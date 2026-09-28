# WipeProof Security Policy & Trust Model (SECURITY.md)

---

## 1. What the Cryptographic Signature Proves (and Does NOT Prove)

A cornerstone of sound security engineering is total honesty regarding the boundary of mathematical assertions. WipeProof explicitly defines what our digital signatures guarantee and where physical/hardware limits lie.

### What the Signature PROVES:
1. **Mathematical Authenticity:** The certificate payload was created and signed by an entity holding the private key associated with `key_id`.
2. **Payload Integrity:** Every field in the certificate (device serial number, method invoked, duration, sector count, Shannon entropy, tool git commit hash) has not been modified by even a single bit since signing. Any modification causes RFC 8785 canonicalization and Ed25519 signature verification to fail.
3. **Audit Log Consistency:** The SHA-256 hash of the execution trace (`execution_log_sha256`) is embedded in the signed payload, proving the execution trace matches the signing session.
4. **Chronological Hash-Chain Sequence:** The certificate embeds `previous_certificate_hash`, forming a tamper-evident ledger that prevents retroactive deletion or substitution of wipe jobs.

### What the Signature DOES NOT PROVE (Explicit Physical Boundaries):
1. **Hardware Integrity / Firmware Placebo Attack:**
   If a physical storage drive contains backdoored, malicious, or buggy firmware that acknowledges an ATA or NVMe Sanitize command (`0x00 SUCCESS`) without actually applying physical flash erase voltages, the software cannot detect this at the bus level. The signature proves the software issued the command and the controller reported success.
2. **Physical Drive Custody & Serial Label Swapping:**
   The signature proves the drive controller reported serial number $S$ over the SATA/NVMe interface. It cannot prove that a rogue actor did not peel the physical adhesive serial label off drive $A$ and paste it onto un-wiped drive $B$. Physical chain-of-custody must be secured with tamper-evident asset seals.
3. **Untrusted / Compromised Host Environment:**
   If the operating system running WipeProof contains a kernel rootkit or hypervisor-level interceptor, hardware discovery and sector reads can be spoofed. WipeProof is designed to run in a measured-boot, minimal live Linux environment to minimize host attack surface.
4. **Post-Sanitization State:**
   The signature certifies the state of the drive at `timestamp_completed`. It does not prove the drive was not subsequently connected to another computer and written to.

---

## 2. Key Management Policy & Operational Security

### Private Key Security
* **Access Permissions:** Private key files (`.pem`) must be stored with strict POSIX permissions `0400` (read-only by the service owner).
* **Isolation:** Private keys must never be committed to source control (enforced via `.gitignore`).
* **Passphrase Protection:** In production environments, private keys must be encrypted with AES-256-GCM using a strong passphrase.

### Hardware Security Module (HSM) / TPM / YubiKey Design Note
For high-assurance enterprise deployments, the private key should never touch host RAM in plaintext:
1. **TPM 2.0 Integration:** Using `tpm2-tools` and TSS2 / PKCS#11 engine, an Ed25519 key can be generated directly inside the motherboard's Trusted Platform Module. Signing operations take place inside the TPM silicon; the private key cannot be extracted.
2. **YubiKey / PIV SmartCard:** The private key can be imported into a YubiKey (PIV Slot 9c - Digital Signature). WipeProof communicates via PKCS#11 (`libykcs11.so`) requiring physical user touch or PIN to authorize each wipe certificate.

### Key Rotation & Revocation
* Every certificate includes a versioned `key_id` (derived from the SHA-256 fingerprint of the 32-byte public key).
* When a technician leaves the organization or a wipe station is decommissioned, the key ID is added to the public `RevocationRegistry` (`revocations.json`) with a UTC timestamp and reason.
* The WipeProof Verifier checks every certificate against this revocation list. If the key was revoked prior to the certificate's `completed_at` timestamp, the certificate status is marked **REVOKED**.

---

## 3. Vulnerability Reporting

If you identify a security vulnerability in WipeProof (e.g. parser bypass, canonicalization collision, safety interlock evasion), please report it responsibly:
* **Email:** security@wipeproof.org (or repository issue marked `[SECURITY]`)
* Please provide a reproducible proof of concept.
