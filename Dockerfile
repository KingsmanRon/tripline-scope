# syntax=docker/dockerfile:1
#
# Tripline Scope application image.
#
# Built by scripts/build_bundle.sh with `docker build --network none` from a context that holds only
# wheels/ (every runtime wheel pinned by hash plus our two locally built wheels), requirements.txt (hashed),
# prune.list, prune.sh and smoke-test.sh. Everything installs with --no-index --require-hashes, so the build needs no
# network and the image never reaches one: no telemetry, licence calls or update checks.
#
# The base image is pinned by digest (override with --build-arg PYTHON_IMAGE=... for a hospital mirror).
# Its Debian packages are an aggregated operating-system layer, not linked into the product; see
# docs/SUPPLY_CHAIN.md.
ARG PYTHON_IMAGE=mirror.gcr.io/library/python:3.12-slim@sha256:a6e34c598f2467ed0e9a8d349809fcd8b5c603269512df273a0bb1784edc11b1
FROM ${PYTHON_IMAGE}

ARG TSCOPE_VERSION=0.1.0
LABEL org.opencontainers.image.title="Tripline Scope" \
      org.opencontainers.image.description="Breach scoping for South African hospitals and laboratories (POPIA s22), run on the hospital's own infrastructure" \
      org.opencontainers.image.version="${TSCOPE_VERSION}"

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_NO_INPUT=1 \
    OTEL_SDK_DISABLED=true \
    OTEL_TRACES_EXPORTER=none \
    OTEL_METRICS_EXPORTER=none \
    OTEL_LOGS_EXPORTER=none \
    TSCOPE_HOME=/var/lib/tripline \
    PATH=/opt/tripline/venv/bin:$PATH

COPY wheels/ /tmp/bundle/wheels/
COPY requirements.txt prune.list prune.sh /tmp/bundle/
COPY smoke-test.sh /opt/tripline/share/smoke-test.sh

# Install into a venv without pip (the system pip only installs, then is removed), prune unused font data,
# and drop pip from the image: the running container cannot install anything.
RUN python -m venv --without-pip /opt/tripline/venv \
 && python -m pip --python /opt/tripline/venv/bin/python install --no-index --no-cache-dir --require-hashes \
        --find-links /tmp/bundle/wheels -r /tmp/bundle/requirements.txt \
 && sh /tmp/bundle/prune.sh /opt/tripline/venv/bin/python /tmp/bundle/prune.list \
 && python -m pip uninstall --yes --quiet pip \
 && rm -rf /tmp/bundle /root/.cache \
 && useradd --system --uid 10001 --user-group --home-dir /var/lib/tripline --shell /usr/sbin/nologin tscope \
 && mkdir -p /var/lib/tripline /cases /sources /kek \
 && chown tscope:tscope /var/lib/tripline /cases /kek \
 && chmod 0700 /var/lib/tripline /kek \
 && tscope --version && tscope-verify --help >/dev/null

USER 10001:10001
WORKDIR /cases
ENTRYPOINT ["tscope"]
CMD ["--help"]
