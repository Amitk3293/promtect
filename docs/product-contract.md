# Product contract

[`PRODUCT-CONTRACT.json`](../PRODUCT-CONTRACT.json) is the canonical, versioned
contract for Promtect editions, prices, availability, terminology, and public
claims. Other repositories and public surfaces must consume or validate against
that file instead of maintaining independent product truth.

## How to read status

- **Available** means the capability is implemented, deliverable, and proven at
  runtime on a documented supported path.
- **Beta** means some implementation exists, but Promtect does not yet make a
  general-availability promise for it.
- **Planned** means customers cannot rely on or purchase it as a shipped
  capability.

The edition-level status wins over a capability-level status. For example,
implemented Team role or policy components remain non-purchasable while the Team
edition is planned and its full operational journey is unproven.

## Security claim boundary

Promtect is a local proxy, not universal DLP. The bounded promise is to mask
recognized matches in supported, uncompressed UTF-8 request bodies that actually
route through Promtect. Prompts with masked values still go to the configured
upstream. Headers, unsupported formats, bypassing clients, and unrecognized
secret shapes are outside that promise; see the [threat model](../THREAT-MODEL.md).

## Change control

Changing a price, detector count, license term, edition state, or approved claim
requires a reviewed update to the JSON contract first. Site, licensing, Pro,
documentation, and release validation then adopt that contract. A feature moves
to `available` only after its customer delivery path and Docker runtime journey
are both evidenced.

The contract carries prices, never Stripe identifiers. Price, Payment Link, and
product IDs are deployment configuration and live only in the Worker
environments that need them, so this public file stays free of billing-account
detail. Core tests fail if a `price_ids` block reappears.

The public detector count means unique detector kinds. Staging currently has 96
public kinds backed by 99 registry entries because a kind may need more than one
bounded pattern. Both numbers are locked by the Core test suite.

Validate the checked-out staging trees together from the workspace root. The
validator checks Core claims plus Site display prices and checkout URL absence:

```sh
docker run --rm -v "$PWD:/workspace:ro" python:3.13-alpine \
  python /workspace/promtect/scripts/validate-product-contract.py \
  --core /workspace/promtect \
  --site /workspace/promtect-site
```

Run it against isolated worktree paths when validating an unmerged change. The
automated cross-repository launch gate will consume the same validator.
