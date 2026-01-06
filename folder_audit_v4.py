import argparse
import os
import sys
import hashlib
import csv
import time
import json
from datetime import datetime

def write_json(records, config, output_path):
    data = {
        "scan_metadata": {
            "path": config["path"],
            "recursive": config["recursive"],
            "hashing_enabled": config["hash"],
            "generated_at": datetime.now().isoformat(timespec="seconds"),
        },
        "summary": {
            "files_scanned": len(records),
            "possible_duplicates": sum(
                1 for r in records if r["DuplicateStatus"] == "PossibleDuplicate"
            ),
            "confirmed_duplicates": sum(
                1 for r in records if r["DuplicateStatus"] == "ConfirmedDuplicate"
            ),
        },
        "records": records,
    }

    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)

def parse_args():
    parser = argparse.ArgumentParser(
        description="Folder Audit V4 – Verified duplicate detection and reporting",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter
    )

    # Required positional argument
    parser.add_argument(
        "path",
        help="Folder, drive, or UNC path to scan"
    )

    # Optional flags
    parser.add_argument(
        "--recursive",
        action="store_true",
        help="Scan subdirectories recursively"
    )

    parser.add_argument(
        "--hash",
        action="store_true",
        help="Enable SHA-256 hashing to confirm duplicates"
    )

    parser.add_argument(
        "--min-size",
        type=int,
        default=0,
        metavar="KB",
        help="Ignore files smaller than this size (in kilobytes)"
    )

    parser.add_argument(
        "--output",
        metavar="FILE",
        help="Custom output CSV path"
    )

    parser.add_argument(
        "--quiet",
        action="store_true",
        help="Reduce console output"
    )

    parser.add_argument(
        "--json-output",
        help="Write results to JSON file"
    )

    return parser.parse_args()


def validate_args(args):
    # ---- Validate path ----
    if not os.path.exists(args.path):
        print(f"ERROR: Path does not exist: {args.path}", file=sys.stderr)
        sys.exit(1)

    if not os.path.isdir(args.path):
        print(f"ERROR: Path is not a directory: {args.path}", file=sys.stderr)
        sys.exit(1)

    # ---- Validate min-size ----
    if args.min_size < 0:
        print("ERROR: --min-size must be zero or greater", file=sys.stderr)
        sys.exit(1)

    # ---- Resolve output CSV path ----
    if args.output:
        output_path = args.output
    else:
        timestamp = datetime.now().strftime("%Y-%m-%d_%H%M%S")
        output_path = f"folder_audit_{timestamp}.csv"

    # ---- Basic JSON output validation ----
    if args.json_output:
        if not args.json_output.lower().endswith(".json"):
            print("ERROR: --json-output must end with .json", file=sys.stderr)
            sys.exit(1)

        parent_dir = os.path.dirname(args.json_output)
        if parent_dir and not os.path.isdir(parent_dir):
            print(
                f"ERROR: Directory does not exist for JSON output: {parent_dir}",
                file=sys.stderr
            )
            sys.exit(1)

    # ---- Build final config ----
    return {
        "path": os.path.abspath(args.path),
        "recursive": args.recursive,
        "hash": args.hash,
        "quiet": args.quiet,
        "output": output_path,
        "min_size_bytes": args.min_size * 1024,
        "json_output": args.json_output,
    }



def init_progress(total_bytes: int) -> dict:
    return {
        "total_bytes": total_bytes,
        "bytes_done": 0,
        "start_time": time.time(),
        "last_print": 0.0
    }

def format_hms(seconds: float) -> str:
    seconds = int(seconds)
    h = seconds // 3600
    m = seconds % 3600 // 60
    s = seconds % 60
    return f"{h:02d}:{m:02d}:{s:02d}"


def print_progress(progress: dict):
    now = time.time()

    # throttle updates (twice per second)
    if now - progress["last_print"] < 0.5:
        return
    progress["last_print"] = now

    total = progress["total_bytes"]
    done = progress["bytes_done"]

    if total <= 0:
        return

    percent = (done / total) * 100
    elapsed = now - progress["start_time"]

    rate = done / elapsed if elapsed > 0 else 0
    remaining = (total - done) / rate if rate > 0 else 0

    elapsed_str = format_hms(elapsed)
    eta_str = format_hms(remaining)

    # Move cursor up 3 lines and clear
    print("\033[3F\033[J", end="")

    print(f"Hashing progress: {percent:6.2f}% ({done // (1024*1024)} / {total // (1024*1024)} MB)")
    print(f"Elapsed time:      {elapsed_str}")
    print(f"Estimated remaining: {eta_str}")

def main():
    args = parse_args()
    config = validate_args(args)

    if not config["quiet"]:
        print("Folder Audit V4 – CLI parsed successfully")
        print(f"Path: {config['path']}")
        print(f"Recursive: {config['recursive']}")
        print(f"Hashing enabled: {config['hash']}")
        print(f"Min file size (bytes): {config['min_size_bytes']}")
        print(f"Output CSV: {config['output']}")

    records = scan_files(config)

    if not config["quiet"]:
        print(f"Files scanned: {len(records)}")

    detect_possible_duplicates(records)

    possible_count = sum(
        1 for r in records if r["DuplicateStatus"] == "PossibleDuplicate"
    )

    if not config["quiet"]:
        print(f"Possible duplicates found: {possible_count}")

    if config["hash"]:
        if not config["quiet"]:
            print("Hashing enabled: verifying possible duplicates...")

        # Build candidate list (only possible duplicates)
        candidates = [
            r for r in records
            if r["DuplicateStatus"] == "PossibleDuplicate"
        ]

        total_bytes_to_hash = sum(r["SizeBytes"] for r in candidates)

        progress = init_progress(total_bytes_to_hash)

        print("Hashing progress:   0.00% (0 / 0 MB)")
        print("Elapsed time:      00:00:00")
        print("Estimated remaining: --:--:--")

        detect_confirmed_duplicates(records, progress)

        if not config["quiet"]:
            print()  # newline after progress bar

        confirmed_count = sum(
            1 for r in records if r["DuplicateStatus"] == "ConfirmedDuplicate"
        )

        if not config["quiet"]:
            print(f"Confirmed duplicates: {confirmed_count}")

        write_csv(records, config["output"])

        if not config["quiet"]:
            print(f"Results written to: {config['output']}")

        if config.get("json_output"):
            write_json(records, config, config["json_output"])
            if not config["quiet"]:
                print(f"JSON results written to: {config['json_output']}")

        return 0

from datetime import datetime
from typing import List, Dict


def scan_files(config: Dict) -> List[Dict]:
    """
    Scan files and collect metadata only.
    """
    records = []

    root_path = config["path"]
    recursive = config["recursive"]
    min_size = config["min_size_bytes"]

    if recursive:
        walker = os.walk(root_path)
    else:
        # Non-recursive: only list top-level files
        def single_level_walk(path):
            try:
                yield path, [], os.listdir(path)
            except OSError:
                return
        walker = single_level_walk(root_path)

    for current_path, _, files in walker:
        for name in files:
            full_path = os.path.join(current_path, name)

            try:
                stat = os.stat(full_path)
            except OSError:
                # Permission denied, file vanished, etc.
                continue

            if stat.st_size < min_size:
                continue

            record = {
                "FullPath": full_path,
                "Filename": name,
                "Extension": os.path.splitext(name)[1].lower().lstrip("."),
                "SizeBytes": stat.st_size,
                "LastModified": datetime.fromtimestamp(
                    stat.st_mtime
                ).isoformat(timespec="seconds"),
                "DuplicateGroupID": "",
                "DuplicateStatus": "Unique",
                "HashSHA256": "",
            }

            records.append(record)

    return records

from collections import defaultdict
from typing import List, Dict


def detect_possible_duplicates(records: List[Dict]) -> None:
    """
    Identify possible duplicates using filename + size.
    Modifies records in place.
    """
    groups = defaultdict(list)

    # Group by (Filename, SizeBytes)
    for record in records:
        key = (record["Filename"], record["SizeBytes"])
        groups[key].append(record)

    group_id = 1

    for _, group_records in groups.items():
        if len(group_records) > 1:
            for record in group_records:
                record["DuplicateGroupID"] = group_id
                record["DuplicateStatus"] = "PossibleDuplicate"
            group_id += 1

def compute_sha256(file_path: str, progress: dict) -> str:
    """
    Compute SHA-256 hash of a file.
    Returns empty string if file cannot be read.
    """
    try:
        hash_obj = hashlib.sha256()
        with open(file_path, "rb") as f:
            while chunk := f.read(1024 * 1024):  # 1MB chunks
                hash_obj.update(chunk)
                progress["bytes_done"] += len(chunk)
                print_progress(progress)

        return hash_obj.hexdigest()
    except Exception:
        return ""

def detect_confirmed_duplicates(records, progress: dict):
    """
    Confirm duplicates using SHA-256 hashing.
    Only hashes records already marked as PossibleDuplicate.
    """
    hash_groups = {}

    for record in records:
        if record["DuplicateStatus"] != "PossibleDuplicate":
            continue

        hash_value = compute_sha256(record["FullPath"], progress)

        if not hash_value:
            continue

        record["HashSHA256"] = hash_value

        hash_groups.setdefault(hash_value, []).append(record)

    group_id = 1

    for hash_value, group_records in hash_groups.items():
        if len(group_records) > 1:
            for record in group_records:
                record["DuplicateStatus"] = "ConfirmedDuplicate"
                record["DuplicateGroupID"] = group_id
            group_id += 1

def write_csv(records: list, output_path: str) -> None:
    """
    Write scan results to CSV using the locked V4 schema.
    """
    fieldnames = [
        "FullPath",
        "Filename",
        "Extension",
        "SizeBytes",
        "LastModified",
        "DuplicateGroupID",
        "DuplicateStatus",
        "HashSHA256",
    ]

    try:
        with open(output_path, mode="w", newline="", encoding="utf-8") as csvfile:
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
            writer.writeheader()

            for record in records:
                writer.writerow(record)

    except OSError as e:
        print(f"ERROR: Failed to write CSV: {e}")



if __name__ == "__main__":
    sys.exit(main())
