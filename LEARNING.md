# WipeProof Technical Interview & Systems Engineering Guide (LEARNING.md)

This document tracks every major architectural decision, systems/storage concept, cryptographic primitive, and interview question for WipeProof. Use this to prepare for top-tier security engineering, cloud/DevOps, and backend internship interviews.

---

## 1. Storage Media Architecture & Sanitization Physics

### Decision 1: Overwriting vs. Flash Translation Layer (FTL)
* **The Concept:** Traditional Hard Disk Drives (HDDs) map Logical Block Addresses (LBAs) directly to physical magnetic sectors on platters. Solid-State Drives (SSDs) cannot do this because NAND flash cells must be erased in large blocks (e.g. 4 MB) before being rewritten in pages (e.g. 16 KB). The drive controller runs an internal firmware OS called the **Flash Translation Layer (FTL)**.
* **Why Overwrite (`dd if=/dev/zero`) is Insufficient for SSDs:**
  When you write to LBA 100 on an SSD, the FTL does not overwrite the old physical NAND cell. It writes the new data to a fresh erased block in the free pool and marks the old physical cell as "stale" (to be collected later by Garbage Collection). In addition, SSDs feature **overprovisioning** (spare capacity, often 7% to 28% of the drive) and **bad block retirement pools** (blocks with high error rates taken out of service).
  Sequential block overwrites can **only** touch currently mapped LBAs. Residual data remains recoverable from:
  1. Overprovisioned spare blocks.
  2. Blocks waiting for garbage collection.
  3. Wear-leveling pools.
  4. Retired bad blocks.
* **Standards Mapping:**
  * In **NIST SP 800-88 Rev. 2** and **IEEE 2883:2022**, overwriting an SSD is classified at best as **Clear** (logical only), NEVER **Purge**.
  * To achieve **Purge** on an SSD, one must issue native hardware commands (**ATA Sanitize Block Erase** or **NVMe Sanitize Block Erase** / **Crypto Scramble**) that instruct the controller to send high-voltage erase pulses across all physical NAND blocks simultaneously.

---

## 2. Hidden Partitions: HPA & DCO

### Decision 2: Why We Must Audit HPA and DCO Before Sanitization
* **Host Protected Area (HPA):**
  * Created under the ATA specification to hide recovery partitions from the operating system.
  * When HPA is active, the drive's reported maximum addressable LBA (`Read Native Max Address`) is smaller than the true physical maximum sector count.
  * Any standard wipe or partition wipe stops at the reported LBA, leaving the entire HPA area untouched.
* **Device Configuration Overlay (DCO):**
  * Allows OEMs and system vendors to artificially alter the apparent capabilities and size of a drive (e.g. configuring a 120 GB drive to report as an 80 GB drive).
* **The WipeProof Engineering Defense:**
  1. Query `hdparm -N` to inspect visible vs. native maximum sectors.
  2. Query `hdparm --dco-identify` to inspect DCO capabilities.
  3. If HPA/DCO is detected, permanently restore native max sectors (`hdparm -N p<native_max>`, `hdparm --dco-restore`).
  4. Record `native_max_sectors_before` and `native_max_sectors_after` in the signed certificate JSON.

---

## 3. Cryptographic Primitives & Trust Architecture

### Decision 3: RFC 8785 (JSON Canonicalization Scheme - JCS)
* **What it is:** A strict, deterministic algorithm for serializing JSON data into bytes.
* **Why it is necessary:**
  Standard JSON encoders do not guarantee key order, whitespace formatting, or number representations:
  * `{"a": 1, "b": 2}` vs `{"b": 2, "a": 1}` represent the same data, but produce different SHA-256 hashes!
  * Floating-point numbers like `1.0` vs `1e0` serialize differently across Python, Go, and Rust.
* **The Alternative:**
  Signing an arbitrary serialized string (e.g. `json.dumps(obj)`) or signing raw PDF files.
* **The Trade-off:**
  Signing raw string representations makes independent verification fragile; any system parsing and reserializing the JSON breaks the signature. RFC 8785 enables any verifier in any programming language to reconstruct the exact byte sequence and verify the signature.

### Decision 4: RFC 8032 (Ed25519) Signatures
* **What it is:** Edwards-curve Digital Signature Algorithm (EdDSA) over Curve25519 using SHA-512.
* **Why Ed25519 over RSA or ECDSA:**
  1. **Deterministic Nonces:** In standard ECDSA, a random nonce $k$ is generated per signature. If the random number generator repeats or is biased, the private key can be factored in polynomial time (the famous Sony PlayStation 3 security failure). Ed25519 computes the nonce deterministically from the private key and the message: $k = \text{SHA-512}(\text{private\_prefix} \parallel M)$.
  2. **Side-Channel Immunity:** Formulated with complete addition formulas on twisted Edwards curves, allowing constant-time execution without data-dependent branching or cache-line lookups.
  3. **Efficiency:** 32-byte public keys and 64-byte signatures.

### Decision 5: Hash Chaining (`previous_certificate_hash`)
* **The Concept:** Every certificate embeds the SHA-256 hash of the canonical JSON of the previous certificate generated by that workstation.
* **Why it matters for audit:**
  Prevents selective omission or retroactive tampering. If an attacker deletes a certificate for an un-wiped drive, the cryptographic chain breaks at the next issued certificate.

---

## 4. Systems Programming: Language Choice

### Decision 6: Python 3.12+ vs. Rust
* **Why Python 3.12+ was chosen:**
  * Disk sanitization is fundamentally an **I/O-bound** problem. Waiting for a SATA controller or NVMe controller to sanitize flash takes seconds to minutes; the CPU spends >99% of its time sleeping in kernel wait states.
  * Python's standard `cryptography` library binds directly to OpenSSL 3.0 C implementations for Ed25519 and SHA-256, providing native performance and constant-time execution.
  * Rapid integration across CLI, PDF generation (`reportlab`), REST APIs (`FastAPI`), and JSON Schema validation.
* **What the alternative (Rust) offered:**
  * Standalone static binary with zero external dependencies (no Python runtime required on minimal rescue media).
* **Trade-off:**
  Rust produces smaller binaries for live ISOs, but Python provides superior readability, maintainability, and rapid development across the full stack (CLI, engine, verifier service, web UI).

---

## 5. Mock / Loopback Driver Safety Architecture

### Decision 7: Strict Loopback-Only Destructive Testing
* **The Danger:** Automated unit/integration tests running with administrative/root privileges can destroy the developer's workstation if a target path is misconfigured.
* **The Mitigation:**
  WipeProof includes an explicit safety interlock in the engine:
  1. Destructive test suites can only bind to `/dev/loopX` devices or virtual sparse image files.
  2. If any test or mock command attempts to target an actual physical disk (`/dev/sd*`, `/dev/nvme*`), the engine immediately panics and raises `SafetyViolationError`.

---

## 6. Interview Preparation: Questions & Model Answers

### Question 1 (Systems & Storage Architecture)
> *"Explain why running `dd if=/dev/zero of=/dev/nvme0n1` does not achieve a Purge sanitization on an SSD under NIST SP 800-88 Rev. 2."*

**Model Answer:**
> "Under NIST SP 800-88 Rev. 2 and IEEE 2883:2022, an overwrite of user-accessible Logical Block Addresses (LBAs) achieves only a 'Clear' state. On solid-state drives, the Flash Translation Layer (FTL) virtualizes the physical NAND flash cells to implement wear-leveling, bad-block retirement, and overprovisioning.
> When `dd` overwrites LBAs 0 through N sequentially, it only writes to whichever physical pages the FTL allocates. Residual data remains untouched in overprovisioned spare blocks, retired bad blocks, and blocks waiting in garbage collection queues. To achieve a 'Purge' on NVMe, we must issue a hardware controller-level `NVMe Sanitize` (opcode 0x84) or `Format NVM` (opcode 0x80) command, which directs the controller firmware to execute physical block erasures or cryptographic key destruction across all internal flash pools."

### Question 2 (Applied Cryptography & Security Engineering)
> *"Why is JSON Canonicalization (RFC 8785) necessary before signing a JSON object? Why can't we just sign `json.dumps(data)`?"*

**Model Answer:**
> "In JSON, identical semantic objects can have multiple valid serialized representations. Standard `json.dumps()` depends on arbitrary key ordering, whitespace choices, and language-specific floating-point or Unicode escaping rules.
> If a server signs `json.dumps(data)` and sends it to an auditor who parses and reserializes it in Go or Rust, the resulting byte stream will almost certainly differ, causing the SHA-256 hash and Ed25519 signature verification to fail. RFC 8785 (JCS) defines an unambiguous canonical byte representation: keys are sorted lexicographically by UTF-16 code units, insignificant whitespace is stripped, and numbers follow strict ECMAScript formatting. This guarantees that any verifier in any language reproduces the exact byte sequence."

### Question 3 (Threat Modeling & Trust Boundaries)
> *"If a wipe certificate is cryptographically signed with an Ed25519 private key and verified against a trusted public key, what does that signature prove, and what does it NOT prove?"*

**Model Answer:**
> "The signature proves **authenticity and integrity** of the certificate data: it proves that the specific parameters recorded (serial number, sanitize command issued, duration, sampling entropy, tool hash) were signed by the holder of the private key, and that the payload has not been tampered with since signing.
> However, the signature **does NOT prove that the physical data is truly gone** if the underlying hardware is dishonest. For example, if the drive's firmware has a 'firmware placebo' bug or backdoor where it returns a success code for `SANITIZE DEVICE` without actually erasing physical NAND cells, the software has no physical way to detect this at the bus level. Furthermore, the signature does not prove physical chain of custody (e.g., whether someone physically swapped drive chassis labels), nor does it guarantee the host OS wasn't compromised unless verified via measured boot and hardware root of trust (TPM)."

---

## 7. Phase 2: Core Wipe Engine Implementation & Engineering Trade-offs

### Decision 8: Statistical Pseudo-Random Sampling vs. Full Read-Back
* **The Problem:** To be 100% physically certain that an entire 10 TB drive contains zeros, you must read all 10,000,000,000,000 bytes. At SATA-III transfer speeds (~200 MB/s), this takes approximately 14 hours *after* the wipe is already finished.
* **The Solution:** Statistical multi-point sampling:
  1. Mandatory boundary checks: LBA 0 (Master Boot Record / Protective MBR), LBAs 1–33 (Primary GPT header & entries), and the final 33 sectors of the media (Secondary/Backup GPT).
  2. Uniform pseudorandom distribution: Sample 512–2,048 blocks (e.g. 4KB each) scattered across the entire LBA range using a seeded PRNG.
  3. Compute aggregate Shannon entropy and zero-fill ratio.
* **The Trade-off:** We trade microscopic residual detection (e.g., a single isolated block left unmodified in the middle of a 10 TB drive) for exponential performance gains, while guaranteeing that any filesystem, partition structure, or uniform data trace is immediately caught.

### Decision 9: Defense-in-Depth Safety Architecture
* **Why exit code 77 (EBUSY) on Root Mounts:**
  If an automated script or distracted operator passes `--target /dev/sda`, relying solely on a confirmation prompt is insufficient (operators develop "confirmation fatigue"). The engine actively inspects `/proc/mounts`, mount trees, and system device paths. If the target drive or any child partition matches `/`, `/boot`, `/home`, or active swap, the engine halts with `SafetyViolationError` before any write file descriptors are opened.
* **Loopback-Only Invariant in Test Suites:**
  Unit test runners running as root or administrative users could wipe real drives if a test bug passes an unmocked path. `SafetyGatekeeper(test_mode_loopback_only=True)` acts as a circuit breaker, immediately panicking if any path not containing `loop` or `.img` is targeted.

---

## 8. Phase 2 Interview Preparation: Questions & Model Answers

### Question 4 (Systems & Forensic Verification)
> *"How does calculating Shannon Entropy help verify that a disk was wiped, and why is an entropy value close to 8.0 bits/byte either very good or very bad depending on the sanitization method?"*

**Model Answer:**
> "Shannon entropy $H(X) = -\sum P(x_i) \log_2 P(x_i)$ measures the average information density and randomness of byte values in a dataset. For 8-bit bytes, the value ranges strictly from 0.0 (completely uniform/redundant, e.g. all 0x00) to 8.0 (maximum statistical randomness, where every byte value from 0 to 255 appears with equal frequency).
> If the sanitization method was a **Zero-Fill Overwrite or Block Erase**, expected entropy is **0.0000**. Any entropy above zero indicates residual un-wiped data or bad blocks.
> However, if the method was **Cryptographic Erase (erasing the MEK on a Self-Encrypting Drive) or Random Overwrite**, the drive's data remains encrypted ciphertext. True ciphertext is indistinguishable from random noise, meaning the expected post-wipe entropy should be **~8.0000**. If a cryptographically erased drive has low entropy, it implies plaintext or unencrypted regions were exposed."

### Question 5 (Operating Systems & Linux Storage Architecture)
> *"Why are Linux device node names like `/dev/sda` and `/dev/sdb` considered unsafe for scripting automated disk wipes, and how should a production sanitization engine identify target media?"*

**Model Answer:**
> "In the Linux kernel, `/dev/sd*` device names are assigned asynchronously during boot and udev discovery based on whichever drive responds first to the SATA/SCSI bus scan. If a drive experiences a delayed power-on or a SATA cable is moved, what was `/dev/sdb` yesterday can easily become `/dev/sda` today.
> Wiping scripts relying on raw device node letters risk wiping the wrong physical disk. A production sanitization tool must verify immutable hardware identifiers:
> 1. **Serial Number:** Queried directly from drive controller inquiry/identify data via `hdparm -I` or `nvme id-ctrl`.
> 2. **World Wide Name (WWN):** Globally unique 64-bit IEEE identifier for SCSI/SATA drives.
> 3. **Typed / Gated Confirmation:** WipeProof requires the operator to confirm the exact serial number, and verifies it matches the hardware inquiry response before acquiring write handles."

### Question 6 (Firmware & Storage Standards)
> *"What is a Host Protected Area (HPA) in ATA storage, why was it created, and what happens if a data-wiping tool fails to check for it?"*

**Model Answer:**
> "A Host Protected Area (HPA) is an ATA feature defined in the ATA-4 specification allowing a portion of the hard drive to be hidden from the operating system. When enabled, the drive firmware responds to `READ NATIVE MAX ADDRESS` with a sector count lower than its physical capacity. The OS only sees and formats sectors up to the reported boundary.
> OEMs originally used HPA to store recovery partitions and diagnostic software so users wouldn't accidentally delete them. However, malicious actors or previous corporate installations can hide sensitive data partitions inside the HPA.
> If a sanitization tool only overwrites up to the apparent sector count reported by the OS, **100% of the data inside the HPA remains untouched and readable**. A compliant tool must audit HPA using `hdparm -N`, identify the true native max sectors, permanently unhide the area (`hdparm -Np<native_max>`), and log sectors before and after."

---

## 9. Phases 3–5: Cryptographic Trust, Merkle Trees & Verifier Engineering

### Decision 10: RFC 8785 (JCS) vs. Ad-Hoc Normalization
* **Why simple `json.dumps(sort_keys=True)` is not enough:**
  While `sort_keys=True` orders top-level keys, it does not standardize:
  1. Key sorting order for non-ASCII characters: RFC 8785 mandates lexicographical sorting by UTF-16 code units, not Unicode code points.
  2. Floating-point number representations: IEEE-754 numbers like `-0.0` must become `0`, integers represented as floats (e.g. `50.0`) must serialize as `50`, and exponent normalization must follow strict ECMAScript rules.
  3. String escaping: RFC 8785 strictly prohibits escaping forward slashes (`/`), whereas many JSON libraries escape `/` as `\/`.
* **The Security Guarantee:** By implementing RFC 8785, any third-party auditor writing verification tools in Go, Rust, Java, or OpenSSL will compute the exact identical SHA-256 payload digest.

### Decision 11: Append-Only Merkle Transparency Logs
* **Why Hash Chaining Alone is Insufficient at Scale:**
  A single hash chain (`previous_certificate_hash`) proves sequential continuity on a single wipe station. However, in an enterprise data center with 50 wiping stations, cross-station auditing requires a centralized, tamper-evident log.
* **The Merkle Tree Solution (RFC 6962 Model):**
  The verifier service maintains an append-only binary Merkle tree. Every verified certificate hash is inserted as a leaf. The current Merkle Root hash commits to the entire history of all certificates.
  An auditor can verify that their certificate is included in the public log using an $O(\log N)$ **Merkle Inclusion Proof (Audit Path)** without downloading the entire database.

---

## 10. Phases 3–5 Advanced Interview Questions & Model Answers

### Question 7 (Applied Cryptography & Digital Signatures)
> *"Why did you choose RFC 8032 Ed25519 for signing wipe certificates instead of RSA-4096 or ECDSA P-256?"*

**Model Answer:**
> "We chose Ed25519 for three critical security and performance reasons:
> 1. **Deterministic Nonces:** Standard ECDSA relies on a per-signature random nonce $k$. If the random number generator is biased, repeats a nonce, or has weak entropy, the private signing key can be mathematically recovered from two signatures (as occurred in the Sony PS3 master key breach). Ed25519 computes the nonce deterministically via SHA-512 from the private key prefix and message, eliminating nonce reuse vulnerabilities by design.
> 2. **Side-Channel Resilience:** Ed25519 operations are formulated using complete addition laws on twisted Edwards curves, enabling constant-time implementation without secret-dependent branching or memory lookups that leak keys via CPU cache timing attacks.
> 3. **Compact Size & Speed:** Ed25519 produces 64-byte signatures and 32-byte public keys, significantly reducing the JSON certificate footprint and making them easy to encode into high-density 2D QR codes on physical certificates."

### Question 8 (Security Architecture & Audit Ledgers)
> *"How does an append-only Merkle Transparency Log provide tamper-evidence, and how does an auditor verify an inclusion proof?"*

**Model Answer:**
> "An append-only Merkle Transparency Log structures certificate hashes into a binary hash tree, similar to Certificate Transparency (RFC 6962) and Sigstore Rekor. Each leaf is the hash of a certificate's canonical digest. Each parent node is the SHA-256 hash of its two child nodes: $P = \text{SHA-256}(\text{Left} \parallel \text{Right})$. The top node is the Merkle Root.
> If an adversary alters, reorders, or deletes an entry in the log, the change bubbles up the tree and alters the Merkle Root hash.
> To prove that a specific certificate exists in the log of size $N$, the service returns an **Inclusion Proof (Audit Path)** containing only $\lceil \log_2 N \rceil$ sibling hashes. The verifier hashes their leaf with the first sibling, hashes that result with the next sibling, and confirms that the final computed hash equals the published Merkle Root. This allows offline, independent verification in logarithmic time."

### Question 9 (Threat Modeling & Systems Security)
> *"Explain the 'Firmware Placebo Attack' on solid-state drives and how WipeProof mitigates this risk."*

**Model Answer:**
> "The Firmware Placebo Attack occurs when a drive's microcontroller firmware contains bugs, vendor backdoors, or corruption such that when commanded to execute an ATA Sanitize or NVMe Sanitize Block Erase, it immediately returns an exit status of 0 (SUCCESS) without actually sending high-voltage erase pulses to the underlying NAND flash dies. In some vendor drives, the controller merely marks the translation table as empty while the physical voltage charges on the floating gates remain intact, allowing chip-off laboratory recovery.
> Software running on the host OS cannot defy the laws of physics or directly inspect the physical NAND cells through the SATA/PCIe bus.
> WipeProof mitigates this risk by refusing to blindly trust firmware status codes:
> 1. **Statistical Post-Wipe Sampling:** We read thousands of blocks across the logical address space and calculate Shannon entropy $H(X)$. If physical cells still held data or previous patterns, the entropy would be non-zero.
> 2. **Zero-Probe of Partition Boundaries:** We verify that LBA 0 (MBR) and the first and last 34 sectors (GPT headers) are physically zeroed.
> 3. **Honest Security Boundary Disclosure:** Our certificates and SECURITY.md explicitly state that the digital signature attests to the software having issued the command and verified sampled sectors; it does not attest to hardware-level internal transistor truth."
