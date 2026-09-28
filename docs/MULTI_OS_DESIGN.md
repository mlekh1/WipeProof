# Multi-OS Sanitization Architecture & Systems Design Note

**Topic:** How Storage Sanitization Differs Across Linux, Windows, and Android  
**Target Audience:** Security Engineers, Systems Architects, and Technical Interviewers  
**Status:** Architectural Specification (Documentation Only)

---

## 1. Comparative OS Storage Stack Matrix

| Architecture Layer | Linux (WipeProof Implementation) | Windows (Win32 / NT Kernel) | Android (Linux Kernel + AOSP) |
| :--- | :--- | :--- | :--- |
| **Device Abstraction** | Block device nodes (`/dev/sdX`, `/dev/nvmeXnY`) | NT Device Namespaces (`\\.\PhysicalDriveN`, `\Device\HarddiskN`) | Block partitions (`/dev/block/bootdevice/by-name/userdata`) |
| **Hardware Passthrough** | `ioctl()` (`HDIO_DRIVE_CMD`, `NVME_IOCTL_ADMIN_CMD`, `SG_IO`) | Win32 DeviceIoControl (`IOCTL_ATA_PASS_THROUGH`, `IOCTL_STORAGE_MANAGE_DATA_SET_ATTRIBUTES`) | Kernel driver ioctls mediated through SELinux policies |
| **Native Tooling** | `hdparm`, `nvme-cli`, `smartctl`, `lsblk` | `diskpart`, PowerShell `Clear-Disk`, VDS API, vendor tools | Recovery OS daemon (`recovery`, `fastbootd`), `fscrypt` |
| **Cryptographic Erase** | Cryptsetup LUKS key destruction; NVMe Sanitize Crypto | BitLocker FVEK/VMK destruction; TCG Opal SED revert | StrongBox / KeyMint hardware master key eradication |
| **Hardware Erase Type** | ATA Sanitize, ATA Secure Erase, NVMe Sanitize | NVMe Pass-through; vendor firmware utilities | eMMC `SECURE_ERASE` / `SECURE_TRIM`; UFS Purge |

---

## 2. Windows Storage Sanitization Architecture

### 2.1 The Win32 Device Handle Boundary
In Windows, low-level disk access requires opening a handle to the physical drive object:
```c
HANDLE hDevice = CreateFileW(
    L"\\\\.\\PhysicalDrive1",
    GENERIC_READ | GENERIC_WRITE,
    FILE_SHARE_READ | FILE_SHARE_WRITE,
    NULL,
    OPEN_EXISTING,
    FILE_FLAG_NO_BUFFERING | FILE_FLAG_WRITE_THROUGH,
    NULL
);
```

### 2.2 Built-in Commands vs. True Sanitization
* **`diskpart clean`:** Simply zeroes the Master Boot Record (MBR) or GUID Partition Table (GPT) and partition metadata. **Data residual risk is 100%.** Recovery software can reconstruct all files.
* **`diskpart clean all`:** Performs a sequential zero-overwrite across all addressable sectors.
  * On HDDs: Meets NIST SP 800-88 Rev. 2 **Clear**.
  * On SSDs: **Inadequate for Purge.** Flash Translation Layer (FTL) wear leveling and overprovisioned blocks remain un-wiped.
* **Windows IOCTL Hardware Passthrough:**
  To issue ATA Secure Erase or NVMe Sanitize on Windows, an application must use:
  1. `IOCTL_ATA_PASS_THROUGH` (requires `SeManageVolumePrivilege` and administrative tokens).
  2. `NVME_PASS_THROUGH_IOCTL` via the Microsoft inbox NVMe driver (`stornvme.sys`).
  * *Windows Limitation:* The Windows storage filter stack (Volume Manager, Partition Manager) actively locks drives containing mounted NTFS/ReFS volumes. Drives must be offlined (`VDS` / `Set-Disk -IsOffline $true`) before hardware commands can be passed through.

### 2.3 BitLocker Cryptographic Erase
Windows supports rapid cryptographic sanitization on Self-Encrypting Drives (SEDs) compliant with IEEE 1667 / TCG Opal:
* By issuing a TPM or BitLocker command to destroy the Full Volume Encryption Key (FVEK) and Volume Master Key (VMK), the data volume is rendered permanently unreadable ciphertext in milliseconds.

---

## 3. Android & Mobile Storage Sanitization Architecture

Mobile devices (smartphones, tablets, IoT) present a fundamentally different storage architecture from desktop and enterprise servers.

### 3.1 Physical Storage: eMMC and UFS
Android devices do not use SATA or standard PCIe NVMe cards; they use **eMMC (Embedded MultiMediaCard)** or **UFS (Universal Flash Storage)** soldered directly onto the PCB:
* **eMMC Secure Erase vs. Normal Erase:**
  * eMMC specification defines standard `ERASE` (which merely marks blocks for lazy discard / background garbage collection).
  * To securely erase, the kernel must issue `SECURE_ERASE` or `SECURE_TRIM` (opcode `0x80` modifier). This directs the internal eMMC controller to physically erase the NAND flash cells and overwrite all retired copies before returning execution.
* **UFS Purge:**
  * Universal Flash Storage (UFS 2.x, 3.x, 4.x) defines the `PURGE` command, requiring the controller to eliminate all invalid/unmapped data copies from physical flash cells.

### 3.2 File-Based Encryption (FBE) & Instant Cryptographic Erase
Since Android 10, all devices running Google Mobile Services are required to enforce **File-Based Encryption (FBE)**:
1. **Key Hierarchy:**
   * User data partition (`/data`) is encrypted using AES-256-XTS at the filesystem level (`fscrypt`).
   * Two master key categories exist:
     - **Credential Encrypted (CE) storage:** Decrypted only after the user enters their PIN/pattern/passphrase.
     - **Device Encrypted (DE) storage:** Decrypted early during boot before user authentication.
2. **Hardware Security Module (Titan M / StrongBox / TrustZone):**
   * The master keys are never stored in plaintext on flash. They are wrapped by hardware-bound keys generated inside the secure enclave (TEE / StrongBox).
3. **Android Factory Reset (The True Mobile Sanitization):**
   * When an operator triggers a "Factory Reset" on Android, the operating system does not execute a slow, multi-gigabyte block overwrite across the entire flash chip.
   * Instead, the recovery environment sends an authorized command to the Hardware Security Module (KeyMint / Keymaster) to **permanently zero and destroy the hardware Root of Trust and master derivation seeds**.
   * Concurrently, the Replay Protected Memory Block (RPMB)—a hardware-authenticated partition on eMMC/UFS—increments its monotonic counter, permanently invalidating any cached authentication tokens.
   * *Forensic Outcome:* Without the hardware keys destroyed inside the silicon, the entirety of `/data` becomes mathematically indistinguishable from random white noise ($H \approx 8.000000$), satisfying NIST SP 800-88 Rev. 2 **Purge** semantics within seconds.

---

## 4. Key Takeaways for Technical Interviews

1. **Why Overwrite Wiping is Rare on Mobile:**
   Mobile NAND flash has strictly limited write endurance (P/E cycles). Performing sequential multi-pass overwrites damages flash lifespan. Android relies on hardware-bound **Cryptographic Erase** backed by hardware security enclaves.
2. **Windows Storage Locking:**
   Unlike Linux, which permits raw block reads on `/dev/sdX` even if partitions are mounted (though unsafe), Windows actively blocks raw write handles to mounted `PhysicalDrive` devices via the NT kernel I/O manager. Drives must be dismounted and offlined first.
3. **Firmware Placebo Vulnerability Across All OSes:**
   Whether on Linux (`hdparm`), Windows (`IOCTL_ATA_PASS_THROUGH`), or Android (`eMMC SECURE_ERASE`), the host OS is ultimately trusting the storage microcontroller's internal firmware. Independent post-wipe sampling and Shannon entropy calculation remain mandatory.
