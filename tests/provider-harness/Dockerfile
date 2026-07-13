FROM python:3.12.11-slim-bookworm

WORKDIR /harness
COPY mock_provider.py run_protocols.py ./

RUN useradd --create-home --uid 10001 harness \
 && chown -R harness:harness /harness

USER harness
