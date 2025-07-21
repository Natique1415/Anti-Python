# Anti-Python

Scans files and tells you if they’re malicious. (Cue the false positive noise intensifying...)
I built this simply because Windows Defender took way too long for my severely destroyed attention-span brain. So I thought, what better way to cope than to do this in Python (pain).

## How It Works
1. **Local Heuristic Checks**
   - Detects files with suspicious extensions like `.exe`, `.scr`, `.bat`, etc. (I get it — most files with these extensions aren’t malicious. That’s why I also check their digital signatures to be sure. Stop screaming at me through the screen.)
   - Flags disguised filenames (e.g., `report.pdf.exe`) ( I hate these types of attack )
   - Verifies digital signatures where available
   - Skips directories listed in `safe_dir.txt`

2. **Safe Directory Skipping**
   - You can define trusted folders in a `safe_dir.txt` file.
   - Any path listed there (one per line, e.g., `C:\Users`) will be skipped entirely.

3. **VirusTotal Integration**
   - VirusTotal is only queried if a file is flagged locally.
   - Uses file hash to check for known threats.
   - Results are cached to avoid repeated lookups.
   - Adheres to the free API limit (4 requests/min). ( cuz I am broke )
   - Unknown files can optionally be uploaded for scanning.

4. **Result Caching**
   - Stores previous scan results in `Cache/vt_cache.json`.
   - Remembers last scanned files in `Cache/last_scan.json` to skip unmodified files on reruns.

5. **Multithreading for Speed**
   - Uses `ThreadPoolExecutor` to process multiple files in parallel.
   - Much faster than single-threaded scanning and faster than Windows Defender.

6. **Time Tracking**
    - Displays total time taken for each scan. (So I can flex that it runs faster than Windows Defender. Microsoft, if you’re reading this — maybe check the resume I sent two years ago? Seriously, even Bing responded faster.)

## How to Use
1. **Install Requirements**

   ```bash
   pip install -r requirements.txt
   ```


2. **Set VirusTotal API Key**

    Create a **.env** file with:

    ```ini
    VT_API_KEY=your_api_key_here
    ```

3. **Configure Safe Directories**

  Add directories (one per line) in safe_dir.txt that you trust and want to skip during scanning.

4. **Run the Scanner**

   ```bash
   python main.py <directory_path> [--quick/-q | --full/-f]
   ```
   - ``--quick`` or ``-q`` Run a quick scan using only local heuristics (no VirusTotal API calls).
   - ``-full`` or ``-f``: Run a full scan including VirusTotal API checks (this is the default if no option is provided).
 
   - Note: If the program cannot connect to the VirusTotal API when running in full mode, it will automatically fall back to quick scan mode and notify you.

5. **To scan the **entire system drive**: (fs = full system, get it?)**
   ```bash
   python main.py fs
   ```


****Important: This tool is meant to assist, not replace your primary antivirus.
ALWAYS use Windows Defender or another trusted antivirus alongside this program.
(Translation: USE IT AT YOUR OWN RISK!)****
