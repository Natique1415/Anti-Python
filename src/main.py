import sys
import os
import time
from concurrent.futures import ThreadPoolExecutor
import requests
import check_function

import requests


def can_make_api_call():
    # Step 1: Check internet connectivity quickly
    try:
        requests.get("https://www.google.com", timeout=3)
    except requests.RequestException:
        print("No internet connection detected.")
        return False

    # Step 2: Check VirusTotal API availability by querying a known domain
    test_url = "https://www.virustotal.com/api/v3/domains/google.com"
    headers = {"x-apikey": check_function.VIRUSTOTAL_API_KEY}
    try:
        response = requests.get(test_url, headers=headers, timeout=5)
        if response.status_code in {200, 401, 403, 404}:
            return True
        else:
            print(
                f"VirusTotal API returned unexpected status code: {response.status_code}"
            )
            return False
    except requests.RequestException:
        print("Failed to reach VirusTotal API.")
        return False


def list_suspicious_files(base_path):
    suspicious_files = []
    with ThreadPoolExecutor(max_workers=10) as executor:
        futures = []
        for root, _, files in os.walk(base_path):
            # Skip safe directories early
            if check_function.is_path_safe(root):
                print(f"Skipping safe directory: {root}")
                continue

            for file in files:
                file_path = os.path.join(root, file)
                if check_function.is_path_safe(file_path):
                    print(f"Skipping safe file: {file_path}")
                    continue

                futures.append(
                    executor.submit(check_function.local_suspicious_check, root, file)
                )

        for future in futures:
            result = future.result()
            if result and isinstance(result, str) and not result.startswith("[!]"):
                suspicious_files.append(result)
            elif result and result.startswith("[!]"):
                print(result)
    return suspicious_files


def query_virustotal_for_files(files):
    flagged = []
    for file_path in files:
        file_hash = check_function.get_file_hash(file_path)
        vt_data = check_function.query_virustotal(file_hash)
        vt_analysis = check_function.analyze_virustotal_response(vt_data)
        flagged.append(f"[VT] {vt_analysis}: {file_path}")
    return flagged


def main():
    if not (len(sys.argv) == 3 or len(sys.argv) == 2):
        print("Usage: python main.py <directory_path> [--quick/-q | --full/-f]")
        sys.exit(1)

    input_path = sys.argv[1]

    # Windows-only special case for full system scan
    if input_path.lower() == "fs":
        resolved_path = "C:\\"
    else:
        resolved_path = os.path.abspath(os.path.normpath(input_path))

    if not os.path.isdir(resolved_path):
        print(f"Error: '{resolved_path}' is not a valid directory.")
        sys.exit(1)

    # Determine scan mode
    if len(sys.argv) == 3:
        mode_arg = sys.argv[2].lower()
        if mode_arg in ("--quick", "-q"):
            quick_scan = True
        elif mode_arg in ("--full", "-f"):
            quick_scan = False
        else:
            print("Invalid option for scan mode. Use --quick/-q or --full/-f.")
            sys.exit(1)
    else:
        quick_scan = False  # default to full scan

    # Check VirusTotal API connectivity if full scan requested
    if not quick_scan:
        if not can_make_api_call():
            print(
                "Warning: Cannot connect to VirusTotal API, switching to quick scan mode."
            )
            quick_scan = True

    start_time = time.time()

    print(f"Step 1: Running local heuristics scan on {resolved_path}\n")
    suspicious_files = list_suspicious_files(resolved_path)

    if quick_scan:
        if suspicious_files:
            print("\nSuspicious files detected locally (quick scan):")
            for f in suspicious_files:
                print(f)
        else:
            print("No suspicious files found locally.")
        check_function.save_last_scan_time(time.time())
        elapsed = time.time() - start_time
        print(f"\nScan completed in {elapsed:.2f} seconds.")
        return

    # Full scan mode with VirusTotal API
    if not suspicious_files:
        print("No suspicious files found locally. Skipping VirusTotal.")
        check_function.save_last_scan_time(time.time())
        elapsed = time.time() - start_time
        print(f"\nScan completed in {elapsed:.2f} seconds.")
        return

    print(
        f"\nStep 2: Querying VirusTotal API for {len(suspicious_files)} suspicious files...\n"
    )
    flagged_files = query_virustotal_for_files(suspicious_files)

    for line in flagged_files:
        print(line)

    check_function.save_last_scan_time(time.time())

    elapsed = time.time() - start_time
    print(f"\nScan completed in {elapsed:.2f} seconds.")


if __name__ == "__main__":
    main()
