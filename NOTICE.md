# Provenance & License

This tool is extracted from **AFLNet** (https://github.com/aflnet/aflnet),
which is licensed under the **Apache License 2.0**.

- `opcua-lift.c` and `opcua_state.c` (the lifted `extract_response_codes_opcua`)
  originate from the AFLNet OPCUA extension at commit `212b578`.
- `alloc-shim.h` is a minimal libc-backed reimplementation of the three
  allocator entry points (`ck_alloc`/`ck_realloc`/`ck_free`) used by the lifted
  code; it is written for this standalone package.

If redistributing, retain the AFLNet copyright/notice per Apache-2.0 §4.
The upstream `LICENSE` (Apache-2.0) governs the lifted source.
