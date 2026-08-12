# Dynamic Libraries

Pre-built shared libraries for the `ibmkmscrypto` native extension, organized by platform.

| Directory        | Platform         | File                          |
|------------------|------------------|-------------------------------|
| `darwin-arm64/`  | macOS (ARM64)    | `ibmkmscrypto.<version>.dylib`    |
| `linux-amd64/`   | Linux (x86-64)   | `ibmkmscrypto.so.<version>`       |
| `windows-amd64/` | Windows (x86-64) | `ibmkmscrypto.dll`            |

The `.gitignore` in this directory overrides the root ignore rules so that the binary library files are committed to version control.

---

## linux-amd64

**Library:** `ibmkmscrypto.so.<version>`  
**Signature:** `ibmkmscrypto.so.<version>.sig`

The `.sig` file is a detached OpenPGP (GPG) signature. To verify the library before use:

```sh
# Import the signer's public key (key ID: 6055714 4A18B07BE)
gpg --keyserver keys.openpgp.org --recv-keys 60557144A18B07BE

# Verify
gpg --verify ibmkmscrypto.so.<version>.sig ibmkmscrypto.so.<version>
```

A `Good signature` result confirms the binary is unmodified and was signed by the expected key. The library is loaded at runtime via [`purego.Dlopen`](https://pkg.go.dev/github.com/ebitengine/purego#Dlopen).

---

## windows-amd64

**Library:** `ibmkmscrypto.dll`

The DLL carries an embedded Authenticode signature and PE version metadata. To verify in Windows Explorer:

1. Right-click `ibmkmscrypto.dll` → **Properties**.
2. **Digital Signatures** tab — confirm a valid signature is listed and click **Details** to inspect the signer and timestamp.
3. **Details** tab — check **File version**, **Product name**, and **Company** fields to confirm the binary matches the expected release.
