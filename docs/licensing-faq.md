# Licensing FAQ

Plain-language answers about what you can and cannot do with Promtect. This page explains
the [Sustainable Use License](../LICENSE) (SUL) in everyday terms. If the FAQ and the LICENSE
ever disagree, the LICENSE text wins. This is not legal advice.

## The short version

Promtect's core is **source-available**, not "open source" in the OSI sense. You can read it,
run it, change it, and self-host it for your own work, for free, forever. What you cannot do
is sell it, or run it as a paid service for other people. The valuable paid detectors are a
separate product under a separate commercial license and are not in this repository.

## What you CAN do (no permission, no payment)

- **Run it for your own work.** Use Promtect inside your company or for personal projects, on
  as many machines as you like, at no cost.
- **Read and study the source.** All of it is in this repository.
- **Modify it.** Patch it, add detectors, wire it into your own tooling for your own internal use.
- **Self-host it.** Run it on your own laptops, servers, or CI for your own team.
- **Share it for free.** Give copies to others as long as you do so free of charge and for
  non-commercial purposes, and you pass along this same license with it.
- **Talk about it.** Blog, compare, benchmark, give talks. (Naming rules live in
  [TRADEMARK.md](../TRADEMARK.md).)

## What you CANNOT do (needs a separate commercial agreement)

- **Resell it.** You cannot sell Promtect, or sell access to it, in any form.
- **Run it as a paid service for others.** You cannot host Promtect (or a fork of it) and
  charge third parties to use it, bundle it into a paid SaaS, or offer it as a managed or
  hosted service. "Internal business purposes" means your own organization, not selling its
  functionality on to customers.
- **Charge for distributing it.** If you hand out copies, they have to be free and
  non-commercial.
- **Strip the notices.** You cannot remove or hide the license, copyright, or other notices.
- **Use the name or logo as your own.** The "Promtect" name and logo are trademarks and are
  not covered by this license. See [TRADEMARK.md](../TRADEMARK.md).

If you want to do any of these, that is a commercial conversation. Email **sales@promtect.org**.

## Common questions

**Can I build on top of Promtect?**
Yes, for your own internal or non-commercial use. The license grants the right to prepare
derivative works, subject to the same limitations above. So you can fork it and extend it for
your team. You cannot take that fork and sell it, or run it as a paid service for others.

**Can my company use it without paying?**
Yes. Internal business use is free. Paying is only for the closed Pro detectors (a separate
product), not for the core.

**Can a consultant use Promtect while doing paid client work?**
Using the tool to do your job is internal business use and is fine. What is not allowed is
selling Promtect itself, or providing its functionality to the client as a paid service or
product. If your offering is "we host and run Promtect for you for a fee," you need a
commercial agreement.

**Can I offer "Promtect-as-a-service" to customers?**
No. That is exactly the case the license blocks. Contact sales@promtect.org for commercial or
OEM terms.

**Is this open source?**
No, and we do not call it that. It is source-available and fair-code. OSI "open source" allows
unrestricted commercial use, including reselling and hosting-as-a-service. The SUL does not.
We chose this so the project can be public, readable, and free for real use after launch while
remaining sustainable. During pre-launch the repository and distribution channels are
intentionally private.

**Which code is actually covered?**
Only the source in this repository, and only on the `main` branch. Content on other branches
is not licensed. The paid Pro detectors (entropy and generic-secret detection, personal and
payment-data detection, response scanning, tool and skill scanning, fleet policy, enterprise
integrations) are not in this repository and are licensed separately. See
[COMMERCIAL.md](../COMMERCIAL.md).

**Can I get different terms?**
Yes. If the SUL does not fit your use case, we offer commercial licensing. Email
sales@promtect.org.

## Why a Sustainable Use License

The same reason n8n and similar projects use it. Fully closed software loses the trust,
transparency, and community that a security tool especially needs. Fully permissive open
source lets a large vendor take the work, host it, and resell it without contributing back.
The SUL is intended to keep Core publicly readable and free for everyone who actually uses it
after launch, while keeping the business viable enough to keep building. The honest deal is:
free for your work, paid only if you want to sell ours.
