# Public signet header fixture

`signet-headers-0-4033.bin` contains 4,034 consecutive 80-byte Bitcoin headers,
including genesis. Bitcoin Core 31.1 downloaded and validated the corresponding
public signet blocks on 2026-09-08. Headers were read through `getblockhash` and
`getblockheader <hash> false`, and each header hash was checked during extraction.

- SHA-256: `4b8175d32f1c04fed00f2c17fc3b449be7f87ea7ba75b2111ef0cd454fecd8b8`.
- Height 4033: `00000032bf07285ff75154d299d94cd1e9fb563f03440c8ad9f25279650bb222`.
- Covers difficulty transitions at heights 2016 and 4032.
- Used for offline SPV regression tests; no Internet access or Bitcoin process required.
