---
name: New detector request
about: Ask Promtect to recognise a new credential format
title: "[detector] "
labels: detector
---

**Service / provider**
<!-- e.g. Acme Cloud API key -->

**Format**
<!-- Prefix, length, character set. e.g. `acme_` followed by 40 hex chars.
Link to the provider's docs if available. -->

**Synthetic example**
<!-- ⚠️ A FAKE example matching the shape — NEVER a real secret.
e.g. acme_0000000000000000000000000000000000000000 -->

**Where does it appear?**
<!-- Bare token in code/prose, or only as `KEY=value`? Both? -->

**False-positive risk**
<!-- Could this pattern match non-secret text? Anything to guard against? -->

> Want to implement it yourself? It's ~one line plus tests — see CONTRIBUTING.md.
