# Third-party software

OpenAll itself is MIT-licensed (see `LICENSE`). Two Python packages are shipped unmodified in `vendor/` so the
workflow also runs where the network blocks `pypi.org` (for example some claude.ai chat sessions):

| Package | Version | Licence | Source |
|---|---|---|---|
| capstone (disassembly framework) | 5.0.9 | BSD-style licence by COSEINC / Nguyen Anh Quynh; full text in `LICENSE.TXT` inside each wheel | https://www.capstone-engine.org , PyPI `capstone` |
| pefile | 2024.8.26 | MIT, copyright Ero Carrera; full text in the wheel | https://github.com/erocarrera/pefile , PyPI `pefile` |

SHA-256 of the files in `vendor/` (compare with the files PyPI serves for the same version):

```
273fd8d747d2e35c88f91450be51a603ecfaafb00d96d9f315dcb8689c86193e  capstone-5.0.9-py3-none-manylinux_2_17_x86_64.manylinux2014_x86_64.whl
732cedbbb56d42e723f14d7af6387f1454194a820b4b96b56d1e53f865ef85d0  capstone-5.0.9-py3-none-win_amd64.whl
76f8b485dcd3b1bb8166f1128d395fa3d87af26360c2358fb75b80019b957c6f  pefile-2024.8.26-py3-none-any.whl
```

The Linux and Windows x64 wheels of capstone are included; other platforms install both packages with
`pip install capstone pefile`. Reference sets in `refsets/` contain only hashes of our own small test programs, no
third-party code.
