# Nuvoton TPM 2.0 certificate authorities

This bundle has eight legacy roots, one ECC521 root, and four EK-signing
intermediates from
[Nuvoton](https://www.nuvoton.com/export/sites/nuvoton/files/security/Nuvoton_TPM_EK_Certificate_Chain_Rev2.2.pdf).
The first six roots were downloaded on 2026-07-28, and the rest on 2026-07-29.

| Root | SHA-256 (DER) |
| --- | --- |
| Nuvoton TPM Root CA 1110 | `2782e51a95e86d9557fe4204316cf805bd6f5898f81f9732e944d742bcdc5f54` |
| Nuvoton TPM Root CA 1111 | `e38c280f7c0e0b49f31efc7531032bb6a86c3fba4eb89beb1d510eaa4510ae4a` |
| NuvotonTPMRootCA1210 | `ba70a6ea7b77c7fee8947a07b1e70e0b26d39ce5e6307f63d5e4b9507f19a157` |
| Nuvoton TPM Root CA 2110 | `4aebe77a51ed29959a7f9f5e07a24a558dee8167f3985d724995a541c258dfda` |
| Nuvoton TPM Root CA 2111 | `cd8185ff8995ed09811970090a8c36fafab34ef87f47fa51fdb9ecf95c9c2e04` |
| Nuvoton TPM Root CA 2112 | `66e3a1013d4f697700f731e7d68c69b58351f90ec9580d85862d020ab4abf1af` |
| NuvotonTPMRootCA2210 | `fc61abbc18100f460205ebe09d8c3e6995ac2be2234344a7facb62e15f9a7584` |
| NuvotonTPMRootCA2211 | `2bbc5db224b8f28a6d2cf336d4da7ab21c8c490e3d60ef497801dc0b6ac00227` |
| NPCTxxx ECC521 RootCA | `083e7bd13e8fe0bb9b0c64db9e0c8356681df65714d2d5c4925eb98ae1369d40` |

| Intermediate | SHA-256 (DER) |
| --- | --- |
| NPCTxxx ECC384 LeafCA 012110 | `bf4cd3d1224b5d3f954991992ef30f91a34f7a880fabae75ad10184594ddf42b` |
| NPCTxxx ECC384 LeafCA 012111 | `30dd089c936d158c4515fb5cf00e0ee3f8f5ea4bc7d4844d4dec6ef23d040fc8` |
| NPCTxxx ECC384 LeafCA 022110 | `99517a0395f95ea8422abe75997f4be1107c0249749407f4fe1de3c1e5a43dcc` |
| NPCTxxx ECC384 LeafCA 022111 | `aa9a1682088775b6c2558c89a891591713ee0f23adada04e17d001a7fbbd55d0` |

Verification is offline and doesn't check revocation. This bundle can't tell
you whether a certificate has been revoked. A future revocation policy must
authenticate its data and reject required data that's missing or stale.
