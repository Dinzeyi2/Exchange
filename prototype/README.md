# Historical prototype

`legacy/` preserves the previous shared application solely so its historical tests
remain reproducible. It is not copied into the distributed node image, is not
exposed by `exchange serve`, and is not an approved deployment path.

The institution runtime is `node/runtime/`; every node requires explicit local
configuration, its own database identity, signer, officer pins and mTLS listeners.
