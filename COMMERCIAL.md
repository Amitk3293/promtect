# Promtect commercial editions

AI tools see everything you paste. Promtect runs on your machine and catches the things you
don't want them to see, then sends a cleaned-up request upstream so your real secrets never
leave your laptop. You still get a useful answer back.

The free core catches passwords and API keys, the credentials that get into your servers and
your accounts. That is yours, free, forever.

Pro catches the next layer: your customers' personal and payment details, and the secrets
that don't look like anything Promtect has seen before. One leaked customer record or one
leaked key can mean a breach, a fine, and a week spent rotating every key you own. Pro stops
it at the source, on your machine, for the price of a couple of coffees a month.

## What you pay for

The free core catches passwords and API keys it can recognize: 71 known formats from AWS,
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

Prices below are indicative ahead of launch. Pay annually and get two months free.

|  | Free | Pro | Team (most popular) | Enterprise |
|---|---|---|---|---|
| Price | $0 | **$12 / dev / month** | **$25 / dev / month** | from quote |
| Billing | forever | annual ($96/yr), or $12 monthly | annual ($240/yr), 3-seat minimum | contact sales |
| Catches 71 known passwords and API key formats | ✅ | ✅ | ✅ | ✅ |
| Runs on your machine, no cloud, nothing to install in your browser | ✅ | ✅ | ✅ | ✅ |
| Catches secrets that don't match a known pattern |  | ✅ | ✅ | ✅ |
| Catches customer personal info (names, emails, phones, addresses) and payment details (card numbers, ID numbers) |  | ✅ | ✅ | ✅ |
| Checks the AI tools and plug-ins you install aren't quietly stealing your data |  | ✅ | ✅ | ✅ |
| Checks what the model sends back, not just what you send |  | ✅ | ✅ | ✅ |
| One shared rulebook across the whole team |  |  | ✅ | ✅ |
| One dashboard showing it's working, without ever storing a secret |  |  | ✅ | ✅ |
| Priority support |  |  | ✅ | ✅ |
| Push the rules to every laptop and run the control plane yourself |  |  |  | ✅ |
| Single sign-on (SSO / SAML) and role-based access |  |  |  | ✅ |
| Feeds your security monitoring tools (SIEM) |  |  |  | ✅ |
| SOC 2 / HIPAA mapping, support agreement (SLA) |  |  |  | ✅ |

Pro and Team start with a 14-day trial, no card. The first 100 paid customers get a
time-limited year-1 discount (year one only, not a lifetime deal). Cancel any time.
30-day refund if it does not earn its keep.

## How that compares

The other tools that catch secrets and personal info before they hit an AI cost far more, and
they do it by routing your code through their cloud or a browser plug-in. Promtect never sends
your code anywhere. It runs on your machine.

- GitGuardian: $600 to $800 per developer per year.
- Nightfall AI: $75,000 and up per year at the enterprise tier.
- Prompt Security, WitnessAI, Lasso: roughly $120 to $180 per seat, or $50k flat.

Promtect Pro is $144 per developer per year ($96 if you pay annually) and never leaves your
machine. You pay for the catch, not for someone else to hold your secrets.

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
