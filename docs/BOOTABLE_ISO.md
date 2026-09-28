# WipeProof Bootable Live ISO & Air-Gapped Wipe Station Recipe

**Architecture Note & Deployment Specification**  
**Target Platform:** Debian 12 (Bookworm) / Alpine Linux (x86_64 / UEFI & Legacy BIOS)

---

## 1. Why an Air-Gapped Bootable Live Environment?

In enterprise IT asset disposition (ITAD) and high-security decommission centers, wiping media from within the host operating system has severe flaws:
1. **Self-Wipe Impossibility:** An operating system cannot wipe the storage drive hosting its active kernel, filesystem, and swap.
2. **Untrusted Host Kernel:** If the host machine is suspected of malware or firmware infection, the OS cannot be trusted to discover devices or issue unfiltered SCSI/ATA/NVMe ioctls.
3. **Firmware Freezelock Bypass:** Many desktop and server BIOS/UEFI implementations issue an `ATA SECURITY FREEZE LOCK` command at boot to prevent malicious runtime modifications. An air-gapped live boot sequence enables power cycling or kernel sleep/wake hooks (`rtcwake`) to unfreeze SATA drives for hardware sanitization.

---

## 2. Minimal Live ISO Architecture

```
+---------------------------------------------------------------+
|                      UEFI / GRUB Bootloader                   |
+---------------------------------------------------------------+
                               |
                               v
+---------------------------------------------------------------+
|               Minimal Linux Kernel (No Desktop GUI)          |
|                 - Storage Drivers: ahci, nvme, usb_storage    |
|                 - In-Memory RAM Disk (tmpfs / overlayfs)      |
+---------------------------------------------------------------+
                               |
                               v
+---------------------------------------------------------------+
|                     Air-Gapped WipeProof Station              |
|  - hdparm (ATA Sanitize & HPA/DCO unhide)                     |
|  - nvme-cli (NVMe Sanitize & Format NVM)                      |
|  - smartctl (SMART & Sanitize log query)                      |
|  - Python 3.12+ (WipeProof CLI & Notary)                      |
|  - Ed25519 Private Key (Loaded via USB or TPM 2.0)            |
+---------------------------------------------------------------+
                               |
                               v
+---------------------------------------------------------------+
|           Output Certificates (JSON + PDF) to USB / Serial    |
+---------------------------------------------------------------+
```

---

## 3. Debian `live-build` Implementation Recipe

You can build this reproducible ISO using standard Debian `live-build` tooling:

### Step 1: Install Build Prerequisites
```bash
sudo apt-get update
sudo apt-get install -y live-build debootstrap squashfs-tools xorriso isolinux
```

### Step 2: Configure the Live Build Tree
```bash
mkdir -p wipeproof-live && cd wipeproof-live

lb config \
  --distribution bookworm \
  --architectures amd64 \
  --bootloaders "grub-efi,syslinux" \
  --archive-areas "main contrib non-free-firmware" \
  --binary-images iso-hybrid \
  --memtest none \
  --iso-application "WipeProof Certified Sanitization Station" \
  --iso-publisher "WipeProof Security Engineering"
```

### Step 3: Specify Required System Utilities
Create `config/package-lists/wipeproof.list.chroot`:
```text
linux-image-amd64
live-boot
systemd-sysv
pciutils
usbutils
smartmontools
hdparm
nvme-cli
util-linux
cryptsetup
python3
python3-pip
python3-cryptography
python3-reportlab
python3-qrcode
python3-click
python3-rich
```

### Step 4: Embed the WipeProof Application
Create a chroot hook in `config/hooks/live/01-install-wipeproof.chroot`:
```bash
#!/bin/bash
set -e

# Clone or copy WipeProof into the image
git clone https://github.com/your-username/wipeproof.git /opt/wipeproof
cd /opt/wipeproof
pip3 install --no-cache-dir .

# Create auto-login technician console on tty1
mkdir -p /etc/systemd/system/getty@tty1.service.d
cat <<EOF > /etc/systemd/system/getty@tty1.service.d/autologin.conf
[Service]
ExecStart=
ExecStart=-/sbin/agetty --autologin root --noclear %I \$TERM
EOF

# Launch WipeProof CLI menu automatically on boot
cat <<EOF >> /root/.bashrc
echo "Starting WipeProof Sanitization Console..."
wipeproof scan
EOF
```

### Step 5: Build the Hybrid ISO
```bash
chmod +x config/hooks/live/01-install-wipeproof.chroot
sudo lb build
```
This produces `live-image-amd64.hybrid.iso`.

### Step 6: Burn to Bootable USB
```bash
sudo dd if=live-image-amd64.hybrid.iso of=/dev/sdX bs=4M status=progress conv=fsync
```

---

## 4. Key Management in Air-Gapped Environments

1. **Option A: Sealed USB Token:**
   The private key is stored on a dedicated, encrypted USB flash drive mounted read-only at `/media/keys/station_key.pem`.
2. **Option B: Motherboard TPM 2.0:**
   The live image initializes `tpm2-tss`. The Ed25519 signing key is sealed to PCR 0 (firmware) and PCR 7 (Secure Boot state). If the live environment was tampered with, the TPM refuses to sign.
