# vpm index

The package index of [vpm](https://github.com/tibocub/vapor-package-manager): a signed (ed25519) mirror of hashes, dates, file lists and native-build plans for the rocks on luarocks.org,
plus a "works with vlr" result per rock. It is generated, do not edit by hand. Packages themselves still come from luarocks.org (or their git source); every file vpm downloads is checked against the hashes here.

- index URL: `https://tibocub.github.io/vpm-index/index/v1`
- public key (hex): `6b0c70b6b75f606a4a8deb2e19d31d8be9028bd4e6449a65c6d66c5b0c4ff2ca`
- layout: `index/v1/meta.json`, `search.jsonl`, `p/<2 chars>/<name>.json`, each with a `.sig`; `blobs/aa/<sha256>` for small files the index serves itself.

```lua
-- vpm config
return { index = "https://tibocub.github.io/vpm-index/index/v1", keys = { "6b0c70b6b75f606a4a8deb2e19d31d8be9028bd4e6449a65c6d66c5b0c4ff2ca" } }
```
