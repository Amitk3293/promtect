# NanoClaw

NanoClaw runs on Anthropic's Agents SDK inside per-group containers. The Agents
SDK honors `ANTHROPIC_BASE_URL`, so point it at Promtect in the environment
NanoClaw runs under.

Start Promtect (anthropic mode is the default) where the container can reach it,
and set the base URL in NanoClaw's container/service env:

```sh
promtect        # listens on 127.0.0.1:8790
```

```sh
# in NanoClaw's environment (e.g. its container env / .env)
ANTHROPIC_BASE_URL=http://127.0.0.1:8790
```

## Notes

- Containers don't share the host loopback by default. Keep Promtect on loopback
  and give the container a route to it: run Promtect inside the container's
  network namespace, or reach the host loopback via the container host alias
  (`host.docker.internal` on Docker Desktop, `--network=host` on Linux). Avoid
  binding the proxy to `0.0.0.0` — that exposes your masking proxy to the whole
  network. Confirm the proxy actually sees traffic (`promtect-audit.jsonl`); if
  it sees zero requests, the container couldn't reach Promtect.
- NanoClaw injects credentials at request time; Promtect forwards the auth header
  untouched and only masks the request body.
