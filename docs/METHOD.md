# How Tripline Scope counts the people affected (Module C)

This document explains, in plain language, how Tripline Scope turns rows in hospital and laboratory systems into
a count of **people**, how sure it is about each one, and how the numbers in a scope report can be checked. It is
written for the Information Officer, counsel, the board and the Information Regulator. Technical detail is in
the boxes marked *Technical*.

Method version: `scope-method/0.1.0` (printed in every report).

## 1. What the tool does and does not decide

The tool **proposes and explains**. It never makes the legal decision about who must be notified under section
22 of POPIA; the Information Officer does, with counsel, by releasing a signed report.

Every report keeps four measures apart, because each needs a different level of evidence:

| Measure | What it means | Evidence needed |
|---|---|---|
| **Observed access** | People whose records sit in tables that logs show were accessed during a confirmed window | Access-path analysis (Module B) with a *confirmed* window. Without it the report says "not determinable". |
| **Possible exposure** | Everyone whose records were in any system that may have been exposed | The extracted systems. Missing or uncertain logs never reduce this number. |
| **Confirmed exfiltration** | People whose records are in a copy that is independently known to have left the hospital (for example a leak sample received through lawyers) | An independent copy matched to records — counted only for the categories present in that copy. Mere database access is never treated as proof of theft. |
| **Notification scope** | Who the hospital notifies | Decided by the Information Officer. The tool's proposal is the possible-exposure number. |

## 2. From rows to people

Hospital systems hold the same person many times: in several databases, registered twice in one, with typing
errors, a maiden name in one place and a married name in another, first name and surname swapped, an ID number
missing or mistyped. Children often have no ID number and share a parent's phone. Twins share a birthday,
surname, address and phone. The method is built for exactly these situations.

### 2.1 Which rows can be tied to a person

A row is **usable** when it carries at least two of: a surname, a date of birth, a valid South African ID number
(13 digits, a real date, a valid citizenship digit and a correct Luhn check digit), or a passport number.
Placeholder names such as "UNKNOWN" or "BABY" do not count.

Rows that are not usable — and admissions, bills or results that point to no usable patient record — are
**counted separately as unresolvable rows. They are never forced into people.** The report shows how many there
are per source and table.

### 2.2 Certain links (deterministic)

Two records with the **same valid SA ID number** are the same person when their dates of birth agree with the
date embedded in the ID (or no date of birth is recorded). Because the Luhn check digit catches every single
mistyped digit, two different valid ID numbers are treated as two different people.

### 2.3 Probable links (probabilistic)

Other pairs are scored with the **Fellegi–Sunter** method (implemented with the open-source library Splink): each
field that agrees adds evidence that two records are the same person, each field that disagrees takes evidence
away, and rare values (an uncommon surname) count for more than common ones. The fields compared are: ID number,
passport number, first name (exact, a known variant, similar spelling, swapped with the surname, matching the
other record's middle name, or an initial), surname (exact, swapped, matching a maiden or married surname,
similar spelling), date of birth (exact, a one-character or one-day slip, day and month swapped, a one-year
slip, or the same year), sex, phone (adjusted for how many records share the number), e-mail, medical-aid number,
postal code, middle names (equal, sharing a name, or different) and street address (equal or similar spelling).
Address is shared by a household, so on its own it never links people; it separates unrelated people who happen
to share a common name and birthday, while names, dates of birth and the rules below separate household members.

> *Technical.* Candidate pairs come from these blocking keys (any one suffices): same ID number; same passport;
> soundex of surname + date of birth; soundex of first name + date of birth; sorted soundex of first name and
> surname + date of birth (catches swapped names); maiden surname of one = surname of the other + date of birth;
> same phone; same e-mail; sorted name soundex + birth year; sorted name soundex + birthday. Phone and e-mail
> values shared by more than 50 records (switchboards, placeholders) are not used for blocking. The
> u-probabilities are estimated by deterministic random sampling of record pairs (fixed seed), the
> m-probabilities by expectation maximisation on pairs sharing a date of birth and pairs sharing an ID number,
> and the prior from the ID rule. Training runs single-threaded and parameters are rounded, so the same data
> always gives the same model. The trained parameters (m, u and the resulting weight per level) are printed in
> each report's technical appendix.

The score is turned into a probability and sorted into three **bands** (set in configuration and recorded in
every report):

| Band | Match probability | What happens |
|---|---|---|
| Auto-link | 0.995 or higher | linked |
| Review | 0.80 to 0.995 | a reviewer decides; until then the two records are counted as **two** people |
| Non-link | below 0.80 | not linked |

### 2.4 Guards — rules that override a high score

A score can be misleading when family members share an address, surname and phone. These rules always apply,
whatever the score:

* **First names that contradict** (not equal, not a known variant, not similar, not swapped with the surname, not
  the other's middle name, not an initial) → not linked. *This is what keeps twins apart.*
* **Two different valid ID numbers** → not linked.
* **One record names the other as its guardian** (guardian ID = the other's ID) → not linked.
* **Dates of birth two or more years apart** (and not a slip) → not linked, unless both records carry the same
  valid ID number. *This keeps a parent and child, or two siblings, who share a name apart.*
* **Dates of birth that contradict but are within a year** (and not a slip, and no shared valid ID) → not linked.
  On 10 million synthetic rows 95 % of such pairs were different people — mostly siblings in one household with
  similar first names. Keeping them apart can only count a person twice, never merge two people, so the error goes
  in the direction of notifying more people. A hospital can send them to review instead (`guards.dob_contradiction:
  review` in its profile).

### 2.5 Reviewing uncertain pairs

Uncertain pairs are shown on a review page that runs only on the local machine (127.0.0.1). Reviewers sign in;
each pair shows only what is needed to decide — names, date of birth, sex, the source table, and for ID, passport,
phone and e-mail a masked value with a same/different indicator. Every pair viewed is written to the audit log
(an opaque pair reference and the reviewer's name, no values). Decisions are stored encrypted and **replayed on
every re-run**, so a decision is never lost when new data arrives. Decisions simulated from synthetic ground truth
(drills and demonstrations only) are marked as simulated, and any report that relies on them says so.

### 2.6 Forming people, and the over-merge guard

Linked records are grouped (connected components). Because links chain (A–B and B–C put A and C together), a group
is checked before it is accepted: if it holds **more than one valid ID number, dates of birth that contradict,
more than 25 distinct records, or a pair a reviewer said are different people**, it is **split conservatively**
— only certain links and reviewer-confirmed links are kept — and its probable links go to review. Until then the
group counts as several people (the safer direction for notification).

### 2.7 Confidence for each person

| Confidence | Meaning |
|---|---|
| deterministic | joined only by valid ID numbers (or a single record) |
| auto-linked | at least one automatic probable link |
| reviewed | a reviewer's decision shaped this person |
| probabilistic-unreviewed | an uncertain pair or split group involving this person awaits review |

The report gives the count in each band, and **bounds**: the reported count keeps every pending pair apart (upper);
the lower bound assumes every pending pair is the same person.

## 3. What each person was exposed to

For each person the tool records which **categories** of information appear across their linked rows, **per
source**: ID or passport number, name, date of birth, phone or e-mail, address, medical-aid number, diagnosis
codes, laboratory tests ordered, test results, clinical notes, payment card number and bank account number.
Only the category is recorded — clinical content, card and bank numbers are **never copied**, only flagged as
present.

## 4. Children and contact routes

A person is a **minor** when younger than 18 at the end of the incident window, using the most frequently recorded
date of birth (ties go to the younger date) or, when none is recorded, the date inside the SA ID number. *The ID
number holds a two-digit year; the tool takes the more recent century that is not in the future (so a person born
in 1920 without a recorded date of birth would be read as born in 2020). A recorded date of birth always wins.*

* Minors are routed to a **parent or guardian** when a source records the guardian's phone or e-mail; otherwise
  they are **flagged** for the Information Officer.
* Adults with a usable phone, e-mail or postal address (with postal code) receive individual notices.
* People with **no usable contact details** are counted for the public-notice route that section 22(4) allows
  (website or news media).

The leak sample is evidence, not a contact source: contact details come only from the hospital's own systems.

## 5. Preliminary estimate

`tscope estimate` gives a first count within minutes, labelled **preliminary**: the number of distinct valid ID
numbers, plus distinct phonetic name and date-of-birth keys among rows without an ID that are not already carried
by an ID row. The **upper bound** splits more (exact spelling, no merging of records without an ID), so it
over-counts. The **lower bound** is the point estimate minus 5 % — the accuracy target for the estimate. It is
*calibrated on synthetic data, not guaranteed*: across synthetic estates of 50 000 to 10 million rows the point
estimate was 2.2–2.7 % above the true number of people, so the true number fell inside the range every time. We
tested purely structural lower bounds and rejected them: counting distinct ID numbers can overshoot (one person can
carry two valid ID numbers after a keying error), and merging records transitively on name and date keys chains
unrelated people together in large estates (21–38 % too low at 10 million rows). The refined, person-level count replaces it in a later, signed version.

**Bounded memory.** The estimate does not load the estate at once. It works one *slice* at a time: each source
on its own, split by a hash of the patient key so that no slice holds more than `estimate.rows_per_pass` identity
rows (default 3 million). Dependent rows (admissions, results, billing) join their patient only within the same
source and by the same key, so every join falls inside one slice. Each usable identity row is reduced to five
64-bit values (hashes of the SA ID and of the three keys above, plus the exposure-category mask), and the counts
run over that table, about 40 bytes per row. The result is identical to loading everything at once (tested at
every slicing, and on a 2-million-row estate). Two different keys share a 64-bit hash with probability about
n²/2⁶⁵ (about 10⁻⁵ at 20 million keys). Nothing is spilled to disk. The person-level match still loads the
estate as a whole.

## 6. Module B scope candidates

When access-path analysis supplies scope candidates, each extracted table is classed confirmed, possible, not
assessable, or not covered (matched case-insensitively on database and table name). The report then gives three
scenarios — lower (confirmed tables, records created no later than the end of a confirmed window), candidate
(confirmed and possible) and upper (every table, no time limit) — alongside the full-scope count. **Uncertain or
absent logs never remove anyone from the upper scenario or from the notification proposal.** Each scoping
decision (constrain, widen, clear) is recorded with its reason in the audit log and in the next signed report.
Without Module B input the report states that confidence is degraded and that the whole of every source is
treated as possibly exposed.

## 7. Traceability, versions and integrity

Every report carries: the case id and incident window; the hashes (never the contents) of every source and extract
manifest; rows per source; the method version; the hash of the full matching configuration; the hash of the review
decisions; the model parameters; the scoping decisions; declared evidence gaps; the measured error rates below;
and the hash of the previous version. Each refinement is a **new signed version** linked to the previous one,
with a list of people added and removed per category (counts only). Identical inputs produce a byte-identical
report (canonical JSON, RFC 8785). The Information Officer signs a release with the hospital's key; a provider
key can co-sign; `tscope verify` checks both signatures and the version chain offline.

## 8. Measured error rates

Measured on synthetic laboratory data with ground truth (ten databases with varied layouts; typos, swapped names,
maiden/married surnames, missing IDs, foreign passports, shared family phones, twins, children without IDs linked
to guardians, duplicate registrations, placeholder rows and orphan admissions). The full results, including
hardware and timings, are in `bench/results/`.

| Synthetic admission rows | Auto-link precision (pairs) | Pairwise precision | Pairwise recall | Person-count error | Review band (share of people) | Preliminary estimate vs final |
|---|---|---|---|---|---|---|
| 100 000 | 99.916 % | 99.923 % | 99.891 % | 0.09 % | 0.07 % | 2.7 % |
| 1 000 000 | 99.950 % | 99.965 % | 99.877 % | 0.09 % | 0.15 % | 2.6 % |
| 10 000 000 | 99.912 % | 99.932 % | 99.754 % | 0.15 % | 0.46 % | 2.5 % |

The first 10-million-row run missed the review-band target (0.89 %). Most borderline pairs were unrelated people
sharing a common name and birthday; adding middle-name and street-address evidence and treating conflicting
birth dates as different people brought it to 0.47 % while precision and recall both rose.

Targets: auto-link precision ≥ 99.5 %, person-count error ≤ 1 %, review band ≤ 0.5 % of people, estimate within
5 % of the final count. Real data can differ from synthetic data; the review band and the guards are there to
catch what the model cannot decide.

## 9. Limitations

* Only the extracted sources are counted.
* Two different people with the same name, the same date of birth and no ID number in either record can be
  merged (a true homonym); the model cannot tell them apart without further information.
* Name-variant rules (for example *Sbusiso*/*Sibusiso*) are tuned per hospital with `tscope profile`; the
  defaults are deliberately short so that distinct given names are not treated as variants.
* Error rates are measured on synthetic data shaped like hospital data.
