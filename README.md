# Folder Audit – V4

**Safe file auditing and duplicate verification for IT professionals**

## Commercial use
This tool is published as a portfolio demonstration of real-world automation and analysis:

If you are interested in:
 * Customisation
 * Integration
 * Commercial Use
 * Support or enhancements

Please contact me via linkedIn or Github.

## Purpose

**Folder Audit** is a read-only filesystem auditing utility designed to scan directories and files, collect metadata, and optionally identify duplicate files using cryptographic hashing (SHA-256).

It is a command-line utility designed for **IT technicians, system administrators, and technical support engineers** who need to audit storage and identify duplicate files **without risking data loss**.

The tool is deliberately non-destructive and performs no write operations on scanned files.

It is intentionally **read-only** and evidence-focused, making it suitable for:

* shared systems
* external drives
* network storage
* customer environments
* regulated or production systems

---

## Typical Use Cases

* Auditing external or legacy drives before cleanup
* Identifying duplicate files on shared storage
* Supporting storage reduction decisions with evidence
* Preparing reports for stakeholders or clients
* Verifying duplicates safely before any manual action

---

## Key Capabilities

* Recursive or targeted folder scanning
* File metadata collection (size, timestamps, paths)
* **TWO-STAGE DUPLICATE DETECTION**:
  * Size-based candidate detection
  * SHA-256 verification for confirmed duplicates
* Grouped duplicate reporting
* Real-time hashing progress with elapsed time and ETA
* CSV output for reports and spreadsheets
* JSON output for automation and tooling
* Zero file modification (read-only operation)

---

## ⚠️ Disk Safety & Filesystem Health Notice (Important)

Folder Audit V4 performs deep, read-only scans of filesystem structures.
When hashing is enabled, it opens and reads the contents of every eligible file.

While the tool **does not modify files or filesystem metadata**, running deep scans on **degraded or unstable storage media** may surface **pre-existing filesystem corruption**, particularly on external or aging NTFS volumes.

**What this means**

* Folder Audit **does not write to disk**

* Folder Audit **does not change permissions or attributes**

* Folder Audit **does not repair or alter filesystem structures**

However, deep traversal and hashing can **stress-test filesystem integrity**, similar to backup verification or forensic scanning tools.

If a volume already contains NTFS inconsistencies, running this tool may cause Windows to detect and report those issues.

---

##Recommended Pre-Flight Checks

Before running Folder Audit V4 — especially with hashing enabled — it is strongly recommended to:

**1. Verify filesystem integrity (read-only)**

chkdsk X: /scan

Safe, non-destructive

Detects NTFS issues without modifying the disk

If errors are reported, resolve them before scanning

---

**2. Ensure backups exist**

Always ensure important data is backed up before performing deep scans on external drives.


---

**3. Use Safe Mode for unknown or external disks**

If you are unsure of a disk’s health:

Run Folder Audit without hashing first

Enable hashing only after a clean metadata scan

---

## Hashing Mode (SHA-256)

Hashing is disabled by default and must be explicitly enabled.

Hashing mode:

* Reads file contents sequentially
* Uses SHA-256 for strong duplicate verification
* May significantly increase scan time on large volumes

Hashing is best suited for:

* Data deduplication planning
* Pre-migration audits
* Identifying exact file duplicates across directories

## How Duplicate Verification Works

1. **Scan Phase**
   Files are scanned and basic metadata collected.

2. **Candidate Identification**
   Files with identical sizes are flagged as possible duplicates.

3. **Verification Phase (Optional)**
   Only candidate files are hashed using SHA-256.

4. **Confirmation**
   Files with matching hashes are marked as confirmed duplicates and grouped.

This approach balances **performance, safety, and accuracy**.

---

## Example Usage

### Safe audit only (no hashing)
python folder_audit_v4.py /data/archive --recursive

### Full verification with hashing
python folder_audit_v4.py /data/archive --recursive --hash

### Generate CSV and JSON evidence
python folder_audit_v4.py /data/archive --hash --json-output audit.json

---

## Output

### CSV Report

Suitable for:

* Flat, spreadsheet friendly format
* Reporting, filtering and manual inspection
* client reports

Includes:

* file paths
* sizes
* timestamps
* duplicate status
* duplicate group ID
* SHA-256 hash (when verified)

### JSON Report

Suitable for:

* automation, pipelines, or further processing
* Structured, machine readable format
* integration with other tools

Includes:

* scan metadata
* summary statistics
* full record set

---

## Limitations

* Folder Audit does not repair filesystem issues
* No filedeletion or movement (by design)
* Hashing large or unstable volumes may surface existing corruption
* External drives with failing hardware should not be scanned deeply
* Performance depends on disk health and filesystem consistency
* Network paths require appropriate permissions
* Hashing largendatasets may take time on slower storage

These limitations were intentional and documented to avoid unsafe behaviour.

---

## Safety

* No files are deleted, moved, or modified
* Hashing is opt-in
* Duplicate confirmation is deterministic
* Designed for cautious, professional use

---

## Design Philosophy

Folder Audit V4 follows an operations-first design:

* Read-only by design
* Explicit opt-in for expensive or risky operations
* Defensive defaults
* Clear separation between metadata inspection and content analysis

This approach mirrors best practices used in production ops and infrastructure tooling.

---

## Disclaimer

Folder Audit V4 is provided as an inspection and reporting tool.
Users are responsible for verifying disk health and maintaining backups before scanning storage volumes.

## Status

**Stable / Frozen**

Verified against real-world datasets.
SHA-256 output validated against external tools.

---

## Future Direction

Planned enhancements (opt-in and controlled):

* Summary-only reporting
* JSON-only mode
* Integration-friendly schemas
* Optional destructive actions with explicit safeguards
* UI wrapper (CLI-first remains the core)

---

## License

This project is provided for evaluation and portfolio demonstration purposes.
Commercial use, redistribution, or resale requires explicit permissions from the author.

## Author

Developed Built as part of an ongoing effort to develop reliable, audit-focused Python utilities,
combining structured programming practices with AI-assisted development.

Darren Williamson
Python Utility Development * Automation * Data Analysis
Uk Citizen / Spain-based / Remote
LinkedIn: https://www.linkedin.com/in/darren-williamson3/
---




