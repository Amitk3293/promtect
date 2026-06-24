# Promtect commercial editions

Promtect's core is free and source-available under the [Sustainable Use License](LICENSE):
the loopback proxy and all 71 known-secret detectors. Self-host it, run it at work. That
covers most people, and it stays free.

The paid editions add a different class of detection, plus the controls a team needs to
run Promtect across a fleet.

## What you pay for

The free core catches secrets it can name: 71 known token formats. Pro catches the
secrets it cannot name in advance.

- **Entropy and generic detection.** High-randomness strings and homegrown key formats
  that no signature would match.
- **PII / PHI / PCI detection.** Names, emails, card numbers, and health identifiers,
  for GDPR and HIPAA exposure, not only API keys.
- **LLM response scanning.** Checks what the model sends back, not only what you send.

The free core is the floor. Pro is the ceiling.

## Pricing

Billed annually (two months free versus monthly).

|  | Free | Pro (most popular) | Enterprise |
|---|---|---|---|
| Price | $0 | **$8 / dev / month** | from $19 / dev / month |
| Billing | forever | annual ($96/yr), or $10 monthly | annual, contact sales |
| 71 known-secret detectors | ✅ | ✅ | ✅ |
| Local proxy, no cloud, no CA | ✅ | ✅ | ✅ |
| Entropy + generic detection |  | ✅ | ✅ |
| PII / PHI / PCI detection |  | ✅ | ✅ |
| LLM response scanning |  | ✅ | ✅ |
| Fleet policy + central config |  |  | ✅ |
| SSO / SAML |  |  | ✅ |
| Central audit + multi-env |  |  | ✅ |
| Priority SLA support |  |  | ✅ |

Pro starts with a 14-day trial, no card. Cancel any time. 30-day refund if it does not
earn its keep.

## How that compares

The other tools that catch secrets and PII heading into AI cost far more, and they route
your code through their cloud or a browser plugin to do it.

- GitGuardian: $600 to $800 per developer per year.
- Nightfall AI: $75,000 and up per year at the enterprise tier.
- Prompt Security, WitnessAI, Lasso: roughly $120 to $180 per seat, or $50k flat.

Promtect Pro is $96 per developer per year and never leaves your machine. You pay for
detection, not for someone else to hold your secrets.

## Embed / OEM

Want to ship Promtect inside your own product, or white-label it? That is a separate
license. Email sales@promtect.org and tell me what you are building.

## Buy or talk to me

- Pro: [promtect.org/pro](https://promtect.org/pro)
- Enterprise and Embed: sales@promtect.org

One person builds and supports this. You talk to me, not a queue.

---

Prices are indicative and may change before general availability. Promtect is a product
of AK DevOps Solutions SL (ESB26575522), Barcelona, Spain. The commercial editions are
governed by a separate commercial agreement, not the Sustainable Use License.
