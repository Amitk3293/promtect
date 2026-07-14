# Promtect commercial editions

AI tools see what their clients send. Promtect runs as a local proxy and masks
recognized matches in supported request bodies before sending the remaining
prompt upstream. It is not universal DLP; the exact boundary and current edition
states live in [`PRODUCT-CONTRACT.json`](PRODUCT-CONTRACT.json).

The free Core contains 96 public detector kinds for recognized credential formats.
It remains available under the Sustainable Use License.

Pro is the beta paid layer for entropy, personal-data, payment-data, Skills/MCP,
and response scanning. It is not generally available until compatible artifact,
activation, fulfillment, and recovery journeys pass the launch gate.

## What you pay for

The free core catches passwords and API keys it can recognize: known formats from AWS,
OpenAI, Stripe, GitHub, and the rest. Pro adds the things a known-format scanner can't see.

- **Secrets that don't match a known pattern.** Homegrown keys, internal tokens, anything
  random-looking that no signature would catch. Pro spots them by shape, not by name.
- **Your customers' personal and payment details.** Names, emails, phone numbers, addresses,
  card numbers (checked so a random 16-digit string isn't flagged), and government ID numbers.
  This is the data that turns one leak into a GDPR or HIPAA problem, not just a rotated key.
- **A check on the AI tools and plug-ins you install.** Modern AI tools load add-ons (Skills
  and MCP servers) that can quietly read your files or run commands. Before you run them,
  Promtect reads their config files and flags hidden instructions, data theft, and dangerous
  commands. A normal secret scanner is blind to this. (Watching those tools while they run is
  on the roadmap, not here yet.)
- **A check on what the model sends back.** Not just what you send, but the reply too, in case
  a secret comes back the other way.

The free core is the floor. Pro is the ceiling.

## Pricing

These are the locked catalog prices. Checkout is disabled until commercial
readiness is green. Pro is beta; Team and Enterprise are planned products.

|  | Core | Pro (beta) | Team (planned) | Enterprise (planned) |
|---|---|---|---|---|
| Price | $0 | **$12 / dev / month** | **$25 / dev / month** | from quote |
| Billing | forever | annual ($96/yr), or $12 monthly | annual ($240/yr), 3-seat minimum | contact sales |
| 96 known-format detector kinds | available | available through Core | planned bundle | planned bundle |
| Entropy, PII/PHI, and payment detectors | — | beta | beta | beta |
| Skills/MCP static scan and response scan | — | beta | beta | beta |
| Shared rulebook, policy, roles, seats, and SIEM | — | — | beta components; operational product planned | beta components; operational product planned |
| SSO/SAML, fleet UI, central audit, air-gap distribution, compliance mapping, SLA | — | — | — | planned |

Trial, discount, cancellation, and refund terms are not offered until checkout,
served legal terms, fulfillment, and recovery are operational.

## How that compares

Competitor pricing and capability comparisons require dated primary-source
evidence before publication. Promtect runs its proxy locally, but the remaining
prompt still goes to the configured upstream.

Promtect Pro's locked catalog price is $12 monthly or $96 annually per developer.
It is not currently available for purchase.

## Embed / OEM

Want to ship Promtect inside your own product, or white-label it? That is a separate
license. Email sales@promtect.org and tell me what you are building.

## Buy or talk to me

- Pro beta and Team planned status: [promtect.org/pro](https://promtect.org/pro)
- Enterprise and Embed: sales@promtect.org

One person builds and supports this. You talk to me, not a queue.

---

Prices are locked by the product contract and require a reviewed contract change. Promtect is a product
of AK DevOps Solutions SL (ESB26575522), Barcelona, Spain. The commercial editions are
governed by a separate commercial agreement, not the Sustainable Use License.
