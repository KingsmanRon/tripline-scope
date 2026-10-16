# Tripline Scope: build, test and release targets (build machine). See docs/SUPPLY_CHAIN.md and README.md.
#
#   make lock          regenerate the hashed locks (network)          make lint / test / test-offline
#   make wheelhouse    fetch runtime wheels by hash (network)         make licences / sbom / native-audit
#   make bundle        offline installer in bundle/out/ (+ images)    make bundle-verify / install-test
#   make demo          synthetic lab-breach demo (demo/lab-breach/run.sh)
SHELL := /bin/bash
.SHELLFLAGS := -euo pipefail -c
PYTHON ?= python3
UV ?= uv
# PYTHON as a path that still works after a cd (CI passes the relative .venv/bin/python)
PYTHON_ABS = $(if $(findstring /,$(PYTHON)),$(abspath $(PYTHON)),$(PYTHON))
VERSION := $(shell $(PYTHON) -c 'import tomllib; print(tomllib.load(open("pyproject.toml", "rb"))["project"]["version"])')
BUNDLE ?= bundle/out/tripline-scope-$(VERSION)
WHEELHOUSE ?= build/wheelhouse
PYTEST_ARGS ?= -q -m "not docker and not slow"

.PHONY: help lock check-locks lint test test-offline wheelhouse wheels licences native-audit sbom bundle \
        bundle-verify install-test demo clean

help:
	@sed -n '2,7p' Makefile

lock:                       ## regenerate requirements/{runtime,dev,build}.txt with hashes (keeps pins)
	UV=$(UV) scripts/lock.sh
	$(PYTHON) scripts/check_locks.py

check-locks:                ## every entry pinned with == and SHA-256 hashes; covers both pyprojects
	$(PYTHON) scripts/check_locks.py

lint:
	$(PYTHON) -m ruff check src tests verify scripts

test:                       ## unit, packaging and acceptance tests (Docker-marked tests excluded)
	$(PYTHON) -m pytest $(PYTEST_ARGS)

test-offline:               ## the same tests inside an empty network namespace (root + unshare)
	TSCOPE_OFFLINE_LOOPBACK=1 scripts/run_offline.sh $(PYTHON) -m pytest $(PYTEST_ARGS)

wheelhouse:                 ## runtime wheels for CPython 3.12 / manylinux x86_64, verified against the lock
	UV=$(UV) scripts/fetch_wheels.sh requirements/runtime.txt $(WHEELHOUSE)

wheels:                     ## our two wheels, reproducible (SOURCE_DATE_EPOCH = last commit)
	UV=$(UV) scripts/build_wheels.sh build/dist

licences: wheelhouse        ## licence gate: fails on GPL/AGPL/SSPL/LGPL-without-exception/unknown
	$(PYTHON) scripts/check_licences.py --requirements requirements/runtime.txt --wheels $(WHEELHOUSE) \
	    --native-audit requirements/native-audit.json --json-out build/licences.json

native-audit: wheelhouse    ## refresh requirements/native-audit.json after a re-lock (network: PyPI, crates.io)
	$(PYTHON) scripts/audit_native.py --lock requirements/runtime.txt --wheels $(WHEELHOUSE) \
	    --out requirements/native-audit.json

sbom: wheelhouse wheels     ## CycloneDX SBOM of a clean venv installed offline from the lock -> build/sbom.cdx.json
	rm -rf build/sbom-venv
	$(UV) venv --quiet --python 3.12 build/sbom-venv
	$(UV) pip install --quiet --python build/sbom-venv/bin/python --offline --no-index --require-hashes \
	    --find-links $(WHEELHOUSE) -r requirements/runtime.txt
	$(UV) pip install --quiet --python build/sbom-venv/bin/python --offline --no-index --no-deps build/dist/*.whl
	sh bundle/prune.sh build/sbom-venv/bin/python bundle/prune.list
	$(PYTHON) scripts/sbom.py generate --python build/sbom-venv/bin/python --wheels $(WHEELHOUSE) \
	    --wheels build/dist --lock requirements/runtime.txt --native-audit requirements/native-audit.json \
	    --out build/sbom.cdx.json
	$(PYTHON) scripts/sbom.py check --sbom build/sbom.cdx.json --lock requirements/runtime.txt

bundle:                     ## offline installer; WITH_MSSQL_DEMO=1 adds SQL Server Developer (demo only)
	PYTHON=$(PYTHON) UV=$(UV) scripts/build_bundle.sh

bundle-verify:              ## verify the bundle's signed checksums with the stand-alone verifier
	@echo "release key id: $$(openssl pkey -pubin -in $(BUNDLE)/release.pub -outform DER | tail -c 32 | sha256sum | cut -c1-32)"
	cd $(BUNDLE) && PYTHONPATH=$(CURDIR)/verify/src $(PYTHON_ABS) -m tscope_verify checksums SHA256SUMS \
	    --sig SHA256SUMS.sig --key release.pub

install-test: bundle-verify ## offline install proof: clean --network none container, then compose on an internal network
	scripts/install_test.sh venv $(BUNDLE)
	scripts/install_test.sh container $(BUNDLE)

demo:                       ## synthetic lab-breach demo (written by the integration track)
	@test -x demo/lab-breach/run.sh || { echo "demo/lab-breach/run.sh not present yet" >&2; exit 2; }
	demo/lab-breach/run.sh

clean:
	rm -rf build bundle/out
