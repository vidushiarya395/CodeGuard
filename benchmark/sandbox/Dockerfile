# Sandbox for running CodeSecEval's own tests against reference and generated code.
# Containers from this image are always started by benchmark/sandbox.py with: no network,
# a read-only file system (only /tmp is writable), memory / CPU / process limits, all Linux
# capabilities dropped, and an unprivileged user. Code comes in on stdin; nothing is mounted.
FROM python:3.11.10-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONHASHSEED=0 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

COPY requirements.txt /sandbox/requirements.txt
RUN python -m pip install -r /sandbox/requirements.txt

COPY runner.py /sandbox/runner.py

USER 65534:65534
WORKDIR /tmp
ENV HOME=/tmp
ENTRYPOINT ["python", "-I", "/sandbox/runner.py"]
