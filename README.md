# Folder Audit – V4

**Safe file auditing and duplicate verification for IT professionals**
(Source code available on request or as part of paid engagements)

## Purpose

**Folder Audit** is a command-line utility designed for **IT technicians, system administrators, and technical support engineers** who need to audit storage and identify duplicate files **without risking data loss**.

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

## Safety Guarantees

* No files are deleted, moved, or modified
* Hashing is opt-in
* Duplicate confirmation is deterministic
* Designed for cautious, professional use

---

## Status

**Stable / Frozen**

Verified against real-world datasets.
SHA-256 output validated against external tools.

---

## Limitations

* No filedeletion or movement (by design)
* Network paths require appropriate permissions
* Hashing largendatasets may take time on slower storage

These limitations were intentional and documented to avoid unsafe behaviour.

## Future Direction

Planned enhancements (opt-in and controlled):

* Summary-only reporting
* JSON-only mode
* Integration-friendly schemas
* Optional destructive actions with explicit safeguards
* UI wrapper (CLI-first remains the core)

---

## License
MIT
Free to use modify and adapt

## Author

Developed Built as part of an ongoing effort to develop reliable, audit-focused Python utilities,
combining structured programming practices with AI-assisted development.

Darren Williamson
Python Utility Development * Automation * Data Analysis
Uk Citizen / Spain-based / Remote
LinkedIn: https://www.linkedin.com/in/darren-williamson3/
---


