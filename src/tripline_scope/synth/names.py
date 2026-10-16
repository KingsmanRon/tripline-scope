"""Name, place and code vocabularies for the synthetic generator.

Every value here is generic and invented for test data: common South African given names and surnames by
language group, syllables for a long tail of generated surnames, street names, ICD-10 codes and local test codes.
Nothing is copied from any patient system.
"""

from __future__ import annotations

# Language groups: code -> (share of households, notice language preference code)
GROUPS: dict[str, tuple[float, str]] = {
    "zu": (0.23, "zu"),
    "xh": (0.15, "xh"),
    "st": (0.20, "st"),
    "af": (0.12, "af"),
    "en": (0.10, "en"),
    "in": (0.04, "en"),
    "ts": (0.10, "ts"),
    "fo": (0.06, "en"),  # foreign nationals (passports)
}

MALE: dict[str, list[str]] = {
    "zu": ["Sipho", "Thabo", "Sibusiso", "Bongani", "Mandla", "Themba", "Sandile", "Siyabonga", "Lungelo", "Nkosinathi",
           "Mthokozisi", "Sizwe", "Musa", "Jabulani", "Sabelo", "Mxolisi", "Bheki", "Andile", "Lindani", "Thulani",
           "Njabulo", "Mfundo", "Khulekani", "Zakhele", "Mlungisi", "Nhlanhla", "Sbusiso", "Phumlani", "Vusi", "Mondli",
           "Langa", "Ayanda", "Mzwandile", "Sanele", "Thokozani", "Wandile", "Zola", "Lwazi", "Mpumelelo", "Khaya"],
    "xh": ["Lwando", "Luvo", "Siphamandla", "Anele", "Lukhanyo", "Mzukisi", "Xolani", "Lunga", "Bonga", "Unathi",
           "Akhona", "Lindile", "Sonwabo", "Thembinkosi", "Monde", "Zukile", "Vuyo", "Luthando", "Siyamthanda",
           "Sinethemba", "Masixole", "Ayabonga", "Lulamile", "Mthunzi", "Odwa", "Siseko", "Yonela", "Zimasa", "Asanda",
           "Khanyiso"],
    "st": ["Tshepo", "Katlego", "Kagiso", "Lebogang", "Tumelo", "Thapelo", "Kabelo", "Neo", "Lerato", "Mpho",
           "Teboho", "Tebogo", "Motlatsi", "Refilwe", "Karabo", "Bokang", "Lehlohonolo", "Mothusi", "Itumeleng",
           "Oratile", "Tshiamo", "Boitumelo", "Kamogelo", "Rethabile", "Ofentse", "Omphile", "Pule", "Sello",
           "Tlotlo", "Molefi", "Thato", "Retshepile", "Moeketsi", "Paballo", "Letlotlo"],
    "af": ["Johannes", "Pieter", "Jacobus", "Hendrik", "Gerhard", "Willem", "Francois", "Stefanus", "Christiaan",
           "Andries", "Petrus", "Jan", "Ruan", "Dewald", "Wikus", "Morne", "Riaan", "Schalk", "Danie", "Gideon",
           "Hennie", "Marius", "Theuns", "Werner", "Jaco", "Louis", "Albertus", "Barend", "Cornelius", "Daniel",
           "Eben", "Frikkie", "Gert", "Izak", "Koos"],
    "en": ["David", "Michael", "John", "James", "Robert", "William", "Matthew", "Andrew", "Daniel", "Mark",
           "Richard", "Thomas", "Christopher", "Paul", "Steven", "Brandon", "Ryan", "Jason", "Kevin", "Gareth",
           "Craig", "Dylan", "Liam", "Nathan", "Ethan", "Joshua", "Luke", "Peter", "Simon", "Graham"],
    "in": ["Rajesh", "Pravesh", "Kumar", "Suresh", "Vikash", "Ashwin", "Kevin", "Dinesh", "Nivesh", "Prenesh",
           "Rakesh", "Sanjay", "Yashin", "Kreshen", "Thiresh", "Viren", "Ravi", "Deshan", "Mohammed", "Yusuf"],
    "ts": ["Hlulani", "Tsakani", "Ntsako", "Vutomi", "Rhulani", "Nyiko", "Hlayisani", "Khensani", "Mpho",
           "Rudzani", "Takalani", "Mashudu", "Ndivhuwo", "Livhuwani", "Azwinndini", "Fhatuwani", "Tshilidzi",
           "Murendeni", "Vhutshilo", "Ronewa"],
    "fo": ["Tendai", "Tatenda", "Farai", "Blessing", "Tinashe", "Kudakwashe", "Emmanuel", "Joao", "Carlos",
           "Ibrahim", "Abdul", "Jean", "Patrice", "Godfrey", "Chinedu", "Oluwaseun", "Baraka", "Juma", "Mohamed",
           "Ahmed"],
}

FEMALE: dict[str, list[str]] = {
    "zu": ["Nomvula", "Thandeka", "Nonhlanhla", "Zanele", "Nokuthula", "Lindiwe", "Sibongile", "Ntombi", "Zodwa",
           "Thandiwe", "Nompumelelo", "Hlengiwe", "Busisiwe", "Phumzile", "Nosipho", "Zinhle", "Mbali", "Nandi",
           "Lungile", "Sindisiwe", "Nondumiso", "Khanyisile", "Ayanda", "Andiswa", "Zandile", "Nokwanda", "Thembi",
           "Ntokozo", "Slindile", "Londiwe", "Snenhlanhla", "Nothando", "Bongiwe", "Gugu", "Philile", "Zama",
           "Nomsa", "Nolwazi", "Samkelisiwe", "Qhawekazi"],
    "xh": ["Nomakhaya", "Siphokazi", "Nwabisa", "Ntombizodwa", "Nolitha", "Lulama", "Babalwa", "Ziyanda",
           "Noluthando", "Sinazo", "Yolisa", "Akhona", "Asanda", "Nomonde", "Bulelwa", "Thandokazi", "Lwazikazi",
           "Unathi", "Vuyokazi", "Zukiswa", "Nandipha", "Nosiphiwo", "Phelisa", "Sinovuyo", "Ayakha", "Zintle",
           "Olwethu", "Nokuzola", "Ncumisa", "Anathi"],
    "st": ["Palesa", "Dineo", "Lerato", "Mpho", "Refilwe", "Boitumelo", "Kgomotso", "Naledi", "Masego", "Keabetswe",
           "Lesedi", "Mmathapelo", "Dikeledi", "Puleng", "Tshegofatso", "Reitumetse", "Kelebogile", "Nthabiseng",
           "Matshidiso", "Goitseone", "Onalenna", "Lebohang", "Mamello", "Tebello", "Relebohile", "Bontle", "Kgothatso",
           "Ofentse", "Itumeleng", "Moipone", "Lineo", "Neo", "Seipati", "Tumi", "Karabo"],
    "af": ["Maria", "Anna", "Susanna", "Elizabeth", "Johanna", "Magdalena", "Catharina", "Petronella", "Hester",
           "Aletta", "Elsabe", "Marelize", "Anke", "Liezel", "Carina", "Elmarie", "Annelie", "Ronel", "Sonja",
           "Charlene", "Mariska", "Lizette", "Nadia", "Riana", "Yolandi", "Zelda", "Monique", "Chantel", "Bianca",
           "Wilma", "Retha", "Martie", "Lettie", "Antoinette", "Christelle"],
    "en": ["Sarah", "Jessica", "Emma", "Megan", "Nicole", "Lauren", "Kirsten", "Jennifer", "Michelle", "Samantha",
           "Rebecca", "Claire", "Catherine", "Elizabeth", "Victoria", "Hannah", "Olivia", "Chloe", "Amy", "Kim",
           "Tracey", "Kerry", "Lisa", "Natalie", "Robyn", "Gail", "Julie", "Caroline", "Sharon", "Jacqueline"],
    "in": ["Priya", "Kavitha", "Anusha", "Shereen", "Nirvana", "Thashni", "Reshma", "Kerusha", "Vanitha", "Pooja",
           "Shanaz", "Fathima", "Ayesha", "Kamini", "Pregashnie", "Sharmila", "Nalini", "Yuveshni", "Deshni",
           "Rashida"],
    "ts": ["Hlengani", "Tsakani", "Nyeleti", "Ntsakisi", "Khensani", "Rirhandzu", "Mihloti", "Mixo", "Tintswalo",
           "Masingita", "Rudzani", "Mulalo", "Pfarelo", "Ndivhuwo", "Shonisani", "Lufuno", "Mpfariseni", "Thendo",
           "Vhahangwele", "Azwinndini"],
    "fo": ["Rutendo", "Chipo", "Nyasha", "Tsitsi", "Fadzai", "Ruvimbo", "Maria", "Ana", "Fatima", "Aisha",
           "Grace", "Esther", "Mercy", "Faith", "Ngozi", "Amina", "Zawadi", "Neema", "Halima", "Precious"],
}

SURNAMES: dict[str, list[str]] = {
    "zu": ["Dlamini", "Nkosi", "Ndlovu", "Khumalo", "Sithole", "Zulu", "Ngcobo", "Buthelezi", "Mthembu", "Mkhize",
           "Shabalala", "Zungu", "Cele", "Gumede", "Ntuli", "Majola", "Hadebe", "Mngomezulu", "Xulu", "Mabaso",
           "Nxumalo", "Mbatha", "Ngubane", "Msimang", "Ndaba", "Mhlongo", "Zwane", "Shezi", "Masondo", "Dube",
           "Biyela", "Mazibuko", "Magubane", "Mdletshe", "Khanyile", "Luthuli", "Mchunu", "Mtshali", "Nzimande",
           "Sibiya", "Mahlangu", "Vilakazi", "Msomi", "Ngema", "Gwala", "Mavuso", "Simelane", "Nhlapo", "Maphumulo"],
    "xh": ["Mahlaba", "Ngcukana", "Mbeki", "Sisulu", "Hani", "Mqhayi", "Jonas", "Nqakula", "Madikizela", "Matanzima",
           "Gqola", "Ntshona", "Mzimela", "Qwabe", "Ngxola", "Mdingi", "Bokwe", "Mabandla", "Tshabalala", "Ndamase",
           "Somdaka", "Mlambo", "Mgudlwa", "Nqweniso", "Mxenge", "Kota", "Dyantyi", "Gxowa", "Ntlabati", "Siwisa",
           "Makhubalo", "Mkhwanazi", "Ngqondi", "Fani", "Booi", "Jali", "Nodada", "Mtyobile", "Mapisa", "Xaba"],
    "st": ["Mokoena", "Molefe", "Mofokeng", "Motaung", "Nkosi", "Radebe", "Tau", "Mokwena", "Mahlangu", "Masilo",
           "Sebola", "Maluleke", "Letsoalo", "Modise", "Mothibi", "Mokgadi", "Phiri", "Seleka", "Kekana", "Ramaphosa",
           "Moloi", "Sekgobela", "Lekganyane", "Mabena", "Mashego", "Mosia", "Moletsane", "Ntsoane", "Thobejane",
           "Matlala", "Mphahlele", "Ramokgopa", "Seabi", "Makgoba", "Mogale", "Lebelo", "Tsotetsi", "Sehlako",
           "Motsepe", "Moagi", "Molapo", "Rakgoale", "Mokone", "Setshedi", "Kgosana"],
    "af": ["van der Merwe", "Botha", "Pretorius", "Smit", "Venter", "Nel", "Joubert", "du Plessis", "van Wyk",
           "Fourie", "Coetzee", "Steyn", "Kruger", "Swanepoel", "Erasmus", "Jacobs", "du Toit", "Muller", "Meyer",
           "Visser", "Viljoen", "le Roux", "van Zyl", "Potgieter", "Marais", "Engelbrecht", "Louw", "Bezuidenhout",
           "Olivier", "Theron", "Ferreira", "Hattingh", "van Niekerk", "Badenhorst", "Grobler", "Snyman",
           "Vermeulen", "Kotze", "Lombard", "de Villiers", "Cloete", "Burger", "Strydom", "van Rensburg", "Booysen"],
    "en": ["Smith", "Jones", "Williams", "Brown", "Taylor", "Wilson", "Johnson", "Davies", "Robinson", "Wright",
           "Thompson", "Evans", "Walker", "White", "Roberts", "Green", "Hall", "Wood", "Jackson", "Clarke", "Hughes",
           "Edwards", "Turner", "Martin", "Cooper", "Hill", "Ward", "Morris", "Moore", "Clark", "Lee", "King",
           "Baker", "Harrison", "Morgan", "Allen", "James", "Scott", "Phillips", "Watson", "Davis", "Parker",
           "Price", "Bennett", "Young"],
    "in": ["Naidoo", "Pillay", "Govender", "Reddy", "Moodley", "Chetty", "Singh", "Padayachee", "Maharaj", "Naicker",
           "Moonsamy", "Ramsamy", "Perumal", "Gounden", "Munsamy", "Sewpersad", "Ramlall", "Bhana", "Patel", "Desai",
           "Khan", "Moosa", "Ismail", "Essop", "Dawood", "Pather", "Rajah", "Ramdass", "Sookdeo", "Ganas"],
    "ts": ["Baloyi", "Mathebula", "Maluleke", "Chauke", "Shivambu", "Ngobeni", "Mabunda", "Hlungwani", "Mnisi",
           "Nkuna", "Rikhotso", "Khoza", "Mashaba", "Novela", "Mathonsi", "Netshitenzhe", "Ramabulana", "Mudau",
           "Nemukula", "Tshivhase", "Munyai", "Ndou", "Mukhari", "Nemaungani", "Ravele", "Sikhwari", "Mulaudzi",
           "Netshiavha", "Mashau", "Nethengwe"],
    "fo": ["Moyo", "Ncube", "Sibanda", "Dube", "Mpofu", "Chikwanha", "Mutasa", "Chiweshe", "Banda", "Phiri",
           "Mwale", "Tembo", "Okafor", "Adeyemi", "Okonkwo", "Mensah", "Nkurunziza", "Habimana", "Uwimana",
           "Kabila", "Tshisekedi", "Machel", "Cossa", "Langa", "Mondlane", "Silva", "Santos", "Pereira", "Abdi",
           "Hassan"],
}

# Syllables for a long tail of generated surnames (keeps surname frequencies realistic: a few very common
# names and many rare ones).
SYLL_PREFIX = ["Ma", "Mo", "Ma", "Nko", "Ndla", "Khu", "Sha", "Zwa", "Mthe", "Ngu", "Si", "Mba", "Hla", "Dla", "Mku",
               "Tshe", "Mve", "Gu", "Ntu", "Le", "Se", "Ra", "Mo", "Ke", "Ba", "Ne", "Mu", "Ma", "Tsho", "Mphe",
               "Nga", "Ze", "Lu", "Qwa", "Gxa"]
SYLL_MID = ["ka", "la", "ba", "the", "nga", "ku", "hlo", "si", "tse", "pha", "dla", "ngo", "ma", "lo", "bu", "kwe",
            "tla", "shu", "mbi", "nde", "so", "fa", "go", "tho", "vu"]
SYLL_SUFFIX = ["ne", "ni", "la", "na", "ngo", "le", "ko", "tsi", "bo", "ya", "ni", "wa", "mbe", "he", "ze", "ndo",
               "di", "lo", "se", "kazi", "mbo", "nyane", "si", "ti", "pe"]
EN_PREFIX = ["Ash", "Brad", "Cart", "Dun", "Ell", "Fair", "Glad", "Hart", "Kings", "Lang", "Mar", "North", "Old",
             "Pen", "Red", "Stan", "Thorn", "Wal", "West", "Whit", "Black", "Brook", "Clay", "Ford"]
EN_SUFFIX = ["worth", "ley", "ton", "field", "ford", "wood", "well", "by", "ham", "more", "dale", "son", "er",
             "hurst", "wick", "combe"]
AF_PREFIX = ["van der", "van", "de", "du", "le", "janse van", "van den"]
AF_ROOT = ["Walt", "Westhuizen", "Berg", "Linde", "Spuy", "Bijl", "Heever", "Vyver", "Schyff", "Riet", "Bank",
           "Colff", "Hoven", "Kamp", "Plooy", "Preez", "Randt", "Sandt", "Watt", "Wath", "Rooyen", "Heerden",
           "Vuuren", "Graan", "Jaarsveld", "Huyssteen", "Schalkwyk", "Staden", "Tonder", "Deventer"]

PLACEHOLDER_SURNAMES = ["UNKNOWN", "UNKNOWN", "UNK", "NONAME"]

STREETS = ["Main Road", "Church Street", "Voortrekker Road", "Nelson Mandela Drive", "Jan Smuts Avenue",
           "Oxford Road", "Beyers Naude Drive", "Albertina Sisulu Road", "Rivonia Road", "Long Street", "Victoria Road",
           "Kerk Straat", "Market Street", "Station Road", "Hospital Street", "School Lane", "Protea Avenue",
           "Jacaranda Street", "Acacia Crescent", "Msinga Street", "Vilakazi Street", "Khumalo Street", "Moshoeshoe Road",
           "Dr Pixley Ka Isaka Seme Street", "Govan Mbeki Avenue", "OR Tambo Drive", "Solomon Mahlangu Drive"]
SUBURBS = ["Soweto", "Umlazi", "Khayelitsha", "Soshanguve", "Mamelodi", "Tembisa", "Durban North", "Sandton",
           "Pretoria East", "Bellville", "Mitchells Plain", "Polokwane Central", "Mthatha", "Gqeberha Central",
           "Bloemfontein", "Pietermaritzburg", "Rustenburg", "Mbombela", "Kimberley", "East London", "Chatsworth",
           "Phoenix", "Lenasia", "Alexandra", "Kwamashu"]
EMAIL_DOMAINS = ["example.co.za", "example.com", "mail.example.org", "post.example.net", "inbox.example.co.za"]

ICD10 = ["J45.9", "E11.9", "I10", "J18.9", "A09", "K35.8", "O80", "N39.0", "B20", "A15.0", "R50.9", "S72.0",
         "I21.9", "E86", "K29.7", "M54.5", "J06.9", "Z34.9", "F32.9", "G40.9", "N18.9", "D50.9", "L03.1", "R10.4",
         "O24.4", "P07.3", "Z00.0", "C50.9", "I50.9", "K80.2"]
NOTES = ["Reviewed by attending clinician; stable.", "Admitted for observation.", "Discharged home with follow-up.",
         "Referred to outpatient clinic.", "Pain controlled; plan reviewed.", "Awaiting results.",
         "Transferred to ward.", "Follow-up in two weeks.", "Medication adjusted.", "Seen in casualty; treated.",
         "", "Routine review."]
TEST_CODES = ["FBC", "UE", "LFT", "CRP", "HBA1C", "GLU", "TSH", "LIPID", "INR", "VL", "CD4", "UMCS", "TB-GXP",
              "BHCG", "FERR", "MG", "PSA", "URIC", "TROP", "DDIM"]
RESULT_STATUS = ["final", "final", "final", "final", "preliminary", "pending", "amended", "cancelled"]
WARDS = ["MED1", "MED2", "SURG1", "PAED", "MAT", "ICU", "CAS", "OPD", "ORTH", "ONC"]
