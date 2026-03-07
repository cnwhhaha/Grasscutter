# RSA Patch for 4.8

This folder provides a `48version.dll` patch file for launchers/tools that expect a dedicated 4.8 RSA patch filename.

- File: `48version.dll` (not tracked in git; generate locally)
- SHA256: see `48version.dll.sha256`
- Source bundle: Cultivation `v1.7.2` patch pack
- Upstream source used for this file: `patch/47version.dll` (fallback when `patch/48version.dll` is unavailable)

You can regenerate it with:

```bash
./scripts/generate_48_rsa_patch.sh
```
