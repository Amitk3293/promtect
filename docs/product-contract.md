# Product contract

[`PRODUCT-CONTRACT.json`](../PRODUCT-CONTRACT.json) is the canonical, versioned
contract for the Core edition: availability, terminology, and public claims.
Other repositories and public surfaces must consume or validate against that
file instead of maintaining independent product truth. It is schema 2, and
schema 2 publishes Core and nothing else.

## How to read status

- **Available** means the capability is implemented, deliverable, and proven at
  runtime on a documented supported path.
- **Beta** means some implementation exists, but Promtect does not yet make a
  general-availability promise for it.
- **Planned** means customers cannot rely on it.

The edition-level status wins over a capability-level status.

## Security claim boundary

Promtect is a local proxy, not a universal DLP. The bounded promise is to mask
recognized matches in supported, uncompressed UTF-8 request bodies that actually
route through Promtect. Prompts with masked values still go to the configured
upstream. Headers, unsupported formats, bypassing clients, and unrecognized
secret shapes are outside the promise; see the
[threat model](../THREAT-MODEL.md).

## Change control

Changing the detector count, a license term, an edition state, or an approved
claim requires a reviewed update to the JSON contract first. Site, licensing,
documentation, and release validation then adopt the contract. A feature moves
to `available` only after the customer delivery path and the Docker runtime
journey are both evidenced.

The contract carries no commercial detail; anything of that kind lives outside
this repository. Core tests fail if it reappears here.

The public detector count means unique detector kinds. Staging currently has 96
public kinds backed by 99 registry entries, because a kind may need more than one
bounded pattern. Both numbers are locked by the Core test suite.

## Validating

Validate checked-out Core and Site trees together from the workspace root. The
validator checks that Core documents make no prohibited claim and that Site
embeds no Stripe purchase URL and no forbidden distribution term:

```sh
docker run --rm -v "$PWD:/workspace:ro" python:3.13-alpine \
  python /workspace/promtect/scripts/validate-product-contract.py \
  --core /workspace/promtect \
  --site /workspace/promtect-site
```

Run it against isolated worktree paths when validating an unmerged change. The
automated cross-repository launch gate will consume the same validator.
