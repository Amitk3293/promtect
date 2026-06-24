# Promtect commercial editions

Promtect's core is free and source-available under the [Sustainable Use License](LICENSE):
the loopback proxy and all 71 known-secret detectors. Self-host it, run it at work. That
covers most people, and it stays free.

The paid editions add a different class of detection, plus the controls a team needs to
run Promtect across many machines. Promtect is a backstop. You still write careful code.
This is the layer that catches what slips through.

## What you pay for

The free core catches secrets it can name: 71 known token formats. Pro catches the
secrets it cannot name in advance, and watches a surface no known-secret scanner sees.

- **Entropy and generic detection.** High-randomness strings and homegrown key formats
  that no signature would match.
- **Structured PII / PCI detection.** Emails, phone numbers, card numbers (validated with
  Luhn), and SSNs, for GDPR and HIPAA exposure, not only API keys.
- **Skills and MCP config scan.** Scans the Skills and MCP server config files your agent
  loads, before they run, for injected instructions, secret exfiltration, and dangerous
  commands. This is the newest attack surface in AI tooling, and a known-secret scanner is
  blind to it. (Runtime MCP tool-call protection is on the roadmap.)
- **LLM response scanning.** Checks what the model sends back, not only what you send.

The free core is the floor. Pro is the ceiling.

## Pricing

Prices below are indicative ahead of GA. Pay annually and get two months free.

|  | Free | Pro | Team (most popular) | Enterprise |
|---|---|---|---|---|
| Price | $0 | **$12 / dev / month** | **$25 / dev / month** | from quote |
| Billing | forever | annual ($96/yr), or $12 monthly | annual ($240/yr), 3-seat minimum | contact sales |
| 71 known-secret detectors | ✅ | ✅ | ✅ | ✅ |
| Local proxy, no cloud, no CA | ✅ | ✅ | ✅ | ✅ |
| Entropy + generic detection |  | ✅ | ✅ | ✅ |
| Structured PII / PCI (email, phone, card+Luhn, SSN) |  | ✅ | ✅ | ✅ |
| Skills / MCP config scan |  | ✅ | ✅ | ✅ |
| LLM response scanning |  | ✅ | ✅ | ✅ |
| Shared policy across the team |  |  | ✅ | ✅ |
| Central value-free audit view |  |  | ✅ | ✅ |
| Priority support |  |  | ✅ | ✅ |
| Fleet enforcement + central plane (self-hosted) |  |  |  | ✅ |
| SSO / SAML, RBAC |  |  |  | ✅ |
| SIEM export |  |  |  | ✅ |
| SOC 2 / HIPAA mapping, SLA |  |  |  | ✅ |

Pro and Team start with a 14-day trial, no card. The first 100 paid customers get a
time-limited year-1 discount (year one only, not a lifetime deal). Cancel any time.
30-day refund if it does not earn its keep.

## How that compares

The other tools that catch secrets and PII heading into AI cost far more, and they route
your code through their cloud or a browser plugin to do it.

- GitGuardian: $600 to $800 per developer per year.
- Nightfall AI: $75,000 and up per year at the enterprise tier.
- Prompt Security, WitnessAI, Lasso: roughly $120 to $180 per seat, or $50k flat.

Promtect Pro is $144 per developer per year ($96 if you pay annually) and never leaves
your machine. You pay for detection, not for someone else to hold your secrets.

## Embed / OEM

Want to ship Promtect inside your own product, or white-label it? That is a separate
license. Email sales@promtect.org and tell me what you are building.

## Buy or talk to me

- Pro and Team: [promtect.org/pro](https://promtect.org/pro)
- Enterprise and Embed: sales@promtect.org

One person builds and supports this. You talk to me, not a queue.

---

Prices are indicative and may change before general availability. Promtect is a product
of AK DevOps Solutions SL (ESB26575522), Barcelona, Spain. The commercial editions are
governed by a separate commercial agreement, not the Sustainable Use License.
