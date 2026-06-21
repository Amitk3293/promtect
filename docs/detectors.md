# Detector reference

Promtect ships **71 detectors** covering known credential formats across ~70
providers. Each detector has a `kind` — the label that appears in the sentinel
(`«promtect:aws_key:0001»`), the audit log, and the dashboard breakdown.

Every example below is a **synthetic shape**, not a real secret. Detection is by
format only — Promtect never phones a provider to validate a key.

> This file is kept honest by a test: `detectors.md` must mention every `kind` in
> `src/detect.rs`, or `cargo test` fails. Add a detector → add its row here.

## AI / LLM providers

| Kind | Provider | Shape |
|---|---|---|
| `anthropic_key` | Anthropic | `sk-ant-…` |
| `openai_key` | OpenAI | `sk-…` / `sk-proj-…` |
| `groq_key` | Groq | `gsk_…` |
| `openrouter_key` | OpenRouter | `sk-or-v1-…` |
| `replicate_key` | Replicate | `r8_…` |
| `perplexity_key` | Perplexity | `pplx-…` |
| `fireworks_key` | Fireworks AI | `fw_…` |
| `nvidia_key` | NVIDIA | `nvapi-…` |
| `hf_token` | Hugging Face | `hf_…` |
| `google_api` | Google AI (API key) | `AIza…` |

> Providers with no distinctive prefix (Mistral, Cohere, Together, DeepSeek) are
> still caught in `KEY=value` form by `env_secret`.

## Cloud / infrastructure

| Kind | Provider | Shape |
|---|---|---|
| `aws_key` | AWS access key ID | `AKIA…` / `ASIA…` |
| `aws_secret` | AWS secret access key | `aws_secret_access_key=…` (40-char) |
| `aws_mws` | Amazon MWS auth token | `amzn.mws.<uuid>` |
| `azure_storage_key` | Azure Storage | `AccountKey=…` (88-char base64) |
| `gcp_refresh` | Google Cloud refresh token | `1//…` |
| `google_oauth` | Google OAuth access token | `ya29.…` |
| `digitalocean_token` | DigitalOcean | `dop_v1_…` |
| `doppler_token` | Doppler | `dp.pt.…` |
| `vault_token` | HashiCorp Vault | `hvs.…` / `hvb.…` |
| `terraform_token` | Terraform Cloud | `<14>.atlasv1.…` |
| `databricks_token` | Databricks | `dapi<32 hex>` |
| `planetscale_token` | PlanetScale | `pscale_pw_…` / `pscale_tkn_…` |
| `tailscale_key` | Tailscale | `tskey-auth-…` / `tskey-api-…` |

## Developer tools / platforms

| Kind | Provider | Shape |
|---|---|---|
| `github_token` | GitHub token | `ghp_` / `gho_` / `ghu_` / `ghs_` / `ghr_…` |
| `github_pat` | GitHub fine-grained PAT | `github_pat_…` |
| `gitlab_pat` | GitLab PAT | `glpat-…` |
| `gitlab_trigger` | GitLab pipeline trigger | `glptt-<40 hex>` |
| `npm_token` | npm | `npm_…` |
| `pypi_token` | PyPI | `pypi-AgEIcHlwaS…` |
| `dockerhub_token` | Docker Hub | `dckr_pat_…` |
| `shopify_token` | Shopify | `shpat_` / `shpca_` / `shppa_` / `shpss_…` |
| `linear_key` | Linear | `lin_api_…` |
| `atlassian_token` | Atlassian | `ATATT3…` |
| `figma_token` | Figma | `figd_…` |
| `notion_token` | Notion | `ntn_…` |
| `airtable_pat` | Airtable PAT | `pat<14>.<64 hex>` |
| `rubygems_key` | RubyGems | `rubygems_<48 hex>` |
| `postman_key` | Postman | `PMAK-…` |
| `sonar_token` | SonarQube / SonarCloud | `sqp_` / `sqa_…` |
| `circleci_token` | CircleCI | `CCIPAT_…` |

## SaaS / communication / payment

| Kind | Provider | Shape |
|---|---|---|
| `slack_token` | Slack | `xoxb-` / `xoxp-…` |
| `slack_app` | Slack app-level token | `xapp-…` |
| `slack_webhook` | Slack incoming webhook | `https://hooks.slack.com/services/…` |
| `discord_token` | Discord bot token | `<id>.<6>.<27+>` |
| `discord_webhook` | Discord webhook | `https://discord.com/api/webhooks/…` |
| `telegram_bot` | Telegram bot token | `<digits>:<35-char>` |
| `sendgrid_key` | SendGrid | `SG.<22>.<43>` |
| `mailgun_key` | Mailgun | `key-<32 hex>` (near the word "mailgun") |
| `stripe_key` | Stripe secret / restricted key | `sk_live_…` / `sk_test_…` / `rk_live_…` |
| `stripe_webhook` | Stripe webhook signing secret | `whsec_…` |
| `square_token` | Square | `sq0atp-` / `sq0csp-` / `sq0idp-…` |
| `razorpay_key` | Razorpay | `rzp_live_…` / `rzp_test_…` |

## Vector DB / AI-agent infrastructure

| Kind | Provider | Shape |
|---|---|---|
| `pinecone_key` | Pinecone | `pcsk_…` |
| `langsmith_key` | LangSmith | `lsv2_pt_…` |

## Monitoring / messaging / misc

| Kind | Provider | Shape |
|---|---|---|
| `sentry_user_token` | Sentry user token | `sntryu_<64>` |
| `sentry_org_token` | Sentry org token | `sntrys_…` |
| `sentry_dsn` | Sentry DSN | `https://<32 hex>@…sentry.io/…` |
| `newrelic_key` | New Relic | `NRAK-…` |
| `mapbox_token` | Mapbox | `sk.eyJ…` / `pk.eyJ…` |
| `fcm_token` | Firebase Cloud Messaging | `APA91…` |
| `grafana_cloud` | Grafana Cloud | `glc_…` |
| `grafana_sa` | Grafana service account | `glsa_…` |
| `asana_pat` | Asana PAT | `<0-2>/<digits>:<32 hex>` |
| `dropbox_token` | Dropbox | `sl.…` |
| `age_secret_key` | age encryption secret key | `AGE-SECRET-KEY-1…` |
| `teams_webhook` | Microsoft Teams webhook | `https://….webhook.office.com/webhookb2/…` |

## Structural (format, not provider)

| Kind | What | Shape |
|---|---|---|
| `jwt` | JSON Web Token | `eyJ….eyJ….<sig>` |
| `private_key` | PEM private key block | `-----BEGIN … PRIVATE KEY-----` |
| `pgp_private_key` | PGP private key block | `-----BEGIN PGP PRIVATE KEY BLOCK-----` |
| `db_password` | Database-URL password | `postgres://user:••••@host` (also mysql, mongodb, redis, amqp, mariadb, mssql) |
| `env_secret` | `.env`-style `KEY=value` | `PASSWORD=…`, `API_KEY=…`, `SECRET=…` (unquoted, `"…"`, `'…'`) |

`env_secret` carries a placeholder + code-expression guard: values under 6 chars,
`changeme`, `your_key_here`, `${VAR}`, `{{…}}`, and call expressions like
`getenv("X")` / `os.environ.get("X")` are **not** masked. See `looks_like_placeholder`
in `src/detect.rs`.

## How matches are chosen

When two detectors overlap on the same bytes (e.g. an `anthropic_key` inside an
`API_KEY=` assignment), `dedupe_overlaps` keeps the earliest, longest span and
drops the rest — the bytes are masked once, with the most specific kind. See
[`architecture.md`](architecture.md) for the full pipeline.

Adding a detector is ~one line in `src/detect.rs` — see
[CONTRIBUTING.md](../CONTRIBUTING.md). Don't forget the row in this file.
