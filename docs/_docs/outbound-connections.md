---
title: Which external services does Dependency-Track contact?
parent: FAQ
nav_order: 80
---

Dependency-Track periodically calls external APIs to
download vulnerability intelligence and component metadata.
**If your instance is behind a restrictive firewall or proxy,
allow egress to the endpoints listed in _services.bom.json_.**

| Where to find the authoritative list | What it contains |
| ------------------------------------ | ---------------- |
| [`services.bom.json`](https://github.com/DependencyTrack/dependency-track/blob/master/services.bom.json) | Source-of-truth JSON maintained in-repo |
| Release SBOM (e.g. [`bom.json` for v4.12.0](https://github.com/DependencyTrack/dependency-track/releases/download/4.12.0/bom.json)) | `services.bom.json` merged into the full build SBOM |