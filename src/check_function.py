import os
import re
import subprocess
import hashlib
import requests
import time
import json
from dotenv import load_dotenv

load_dotenv()

VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY")

CACHE_DIR = "Cache"
os.makedirs(CACHE_DIR, exist_ok=True)

CACHE_FILE = os.path.join(CACHE_DIR, "vt_cache.json")
LAST_SCAN_FILE = os.path.join(CACHE_DIR, "last_scan.json")
SAFE_DIR_FILE = "safe_dir.txt"

API_RATE_LIMIT_PER_MIN = 4
API_INTERVAL = 60 / API_RATE_LIMIT_PER_MIN

MIN_FILE_SIZE = 1024

SUSPICIOUS_EXTENSIONS = {
    ".exe",
    ".bat",
    ".cmd",
    ".scr",
    ".pif",
    ".vbs",
    ".js",
    ".jse",
    ".wsf",
    ".ps1",
    ".msi",
    ".reg",
    ".dll",
    ".hta",
    ".com",
    ".cpl",
    ".lnk",
    ".iso",
}


# Load or initialize caches
if os.path.exists(CACHE_FILE):
    with open(CACHE_FILE, "r") as f:
        vt_cache = json.load(f)
else:
    vt_cache = {}

if os.path.exists(LAST_SCAN_FILE):
    with open(LAST_SCAN_FILE, "r") as f:
        last_scan = json.load(f)
else:
    last_scan = {"last_scan_time": 0}


def save_cache():
    with open(CACHE_FILE, "w") as f:
        json.dump(vt_cache, f, indent=2)


def save_last_scan_time(timestamp):
    with open(LAST_SCAN_FILE, "w") as f:
        json.dump({"last_scan_time": timestamp}, f)


def load_safe_dirs() -> list[str]:
    if not os.path.exists(SAFE_DIR_FILE):
        # create empty file
        with open(SAFE_DIR_FILE, "w") as f:
            pass
        return []

    with open(SAFE_DIR_FILE, "r") as f:
        lines = [line.strip() for line in f]

    safe_dirs = [os.path.abspath(line).lower() for line in lines if line]
    return safe_dirs


SAFE_DIRS = load_safe_dirs()


def is_path_safe(path) -> bool:
    """Returns True if path is inside any safe directory"""
    path = os.path.abspath(path).lower()
    for safe_dir in SAFE_DIRS:
        safe_dir_check = safe_dir if safe_dir.endswith("\\") else safe_dir + "\\"
        path_check = path if path.endswith("\\") else path + "\\"
        if path_check.startswith(safe_dir_check):
            return True
    return False


def is_disguised_executable(file_name) -> bool:
    parts = file_name.lower().split(".")
    if len(parts) >= 3:
        if f".{parts[-1]}" in SUSPICIOUS_EXTENSIONS:
            return True
    return False


def is_suspicious_extension(file_name) -> bool:
    return f'.{file_name.lower().split(".")[-1]}' in SUSPICIOUS_EXTENSIONS


def is_small_file(file_path) -> bool:
    try:
        return os.path.getsize(file_path) < MIN_FILE_SIZE
    except OSError:
        return False


# Checks if the file starts with the 'MZ' header, which indicates a Windows executable (EXE) format.
def is_secretly_exe(file_path) -> bool:
    try:
        with open(file_path, "rb") as f:
            return f.read(2) == b"MZ"
    except Exception:
        return False


# make it more simple ig - to complicated and error prone
def is_signed(file_path):
    try:
        result = subprocess.run(
            [
                "powershell",
                "-Command",
                f"Get-AuthenticodeSignature -FilePath '{file_path}' | Select-Object -ExpandProperty Status",
            ],
            capture_output=True,
            text=True,
        )
        status = result.stdout.strip()
        return status == "Valid"
    except Exception:
        return False


# requires Python 3.11+
def get_file_hash(file_path):
    with open(file_path, "rb") as f:
        return hashlib.file_digest(f, "sha256").hexdigest()


def query_virustotal(file_hash):
    if file_hash in vt_cache:
        return vt_cache[file_hash]

    url = f"https://www.virustotal.com/api/v3/files/{file_hash}"
    headers = {"x-apikey": VIRUSTOTAL_API_KEY}
    response = requests.get(url, headers=headers)
    if response.status_code == 200:
        data = response.json()
        vt_cache[file_hash] = data
        save_cache()
        time.sleep(API_INTERVAL)  # rate limiting
        return data
    elif response.status_code == 404:
        vt_cache[file_hash] = None
        save_cache()
        time.sleep(API_INTERVAL)
        return None
    else:
        print(f"VirusTotal API error {response.status_code}")
        time.sleep(API_INTERVAL)
        return None


def analyze_virustotal_response(data):
    if not data:
        return "Unknown on VirusTotal"
    stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
    malicious = stats.get("malicious", 0)
    suspicious = stats.get("suspicious", 0)
    total = sum(stats.values())
    if malicious > 0 or suspicious > 0:
        return f"Detected by {malicious} engines (suspicious: {suspicious})"
    else:
        return "Clean on VirusTotal"


def is_file_modified_since(file_path, timestamp):
    try:
        mtime = os.path.getmtime(file_path)
        return mtime > timestamp
    except Exception:
        return True  # If in doubt, scan


def local_suspicious_check(root, file):
    full_path = os.path.abspath(os.path.join(root, file))

    # Skip if in safe dir
    if is_path_safe(full_path):
        return None

    # Incremental check: skip if file not modified since last scan
    if not is_file_modified_since(full_path, last_scan.get("last_scan_time", 0)):
        return None

    suspicious_name = is_disguised_executable(file) or is_suspicious_extension(file)
    if not suspicious_name:
        return None

    if is_small_file(full_path):
        if not is_signed(full_path):
            return f"[!] Unsigned suspicious SMALL file: {full_path}"
        else:
            return None

    _, ext = os.path.splitext(file.lower())
    if ext == ".exe" or is_disguised_executable(file):
        if not is_secretly_exe(full_path):
            return (
                f"[!] File pretending to be exe without proper magic bytes: {full_path}"
            )

    # Return full path for VirusTotal check if unsigned suspicious file
    if not is_signed(full_path):
        return full_path

    # Signed files considered safe
    return None
