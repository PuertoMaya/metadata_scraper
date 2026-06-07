import hashlib
import os
import json
import subprocess
import magic
import math
import sys
from pathlib import Path
import concurrent.futures
from datetime import datetime

class ForensicFileAnalyzer:
    """
    A tool designed to scan a directory and look for suspicious files 
    by checking their true MIME type, OS timestamps, and data randomness.
    """
    def __init__(self, exiftool_path="exiftool"):
        self.exiftool_path = exiftool_path

    def get_sha256(self, file_path):
        """Calculates SHA256 hash."""
        sha256_hash = hashlib.sha256()
        try:
            with open(file_path, "rb") as f:
                # We will be using a while loop to read chunks of 4KB 
                while True:
                    chunk = f.read(4096)
                    if not chunk:
                        break
                    sha256_hash.update(chunk)
            return sha256_hash.hexdigest()
        except FileNotFoundError:
            return "ERROR: File disappeared during analysis"
        except PermissionError:
            return "ERROR: Access denied by the operating system"
        except Exception as e:
            return f"ERROR: {str(e)}"

    def get_true_file_type(self, file_path):
        """Uses libmagic to figure out what the file actually is, ignoring its extension."""
        try:
            return magic.from_file(str(file_path), mime=True)
        except Exception as e:
            return f"ERROR: Libmagic failed - {str(e)}"

    def calculate_entropy(self, file_path):
        """
        Calculates Shannon Entropy (0.0 to 8.0).
        High entropy (~7.5+) means the bytes are highly randomized,
        which is a massive red flag for encrypted data, zip bombs, or packed malware.
        """
        try:
            with open(file_path, "rb") as f:
                byte_counts = [0] * 256
                total_bytes = 0
                
                while True:
                    chunk = f.read(4096)
                    if not chunk:
                        break
                    for byte in chunk:
                        byte_counts[byte] += 1
                        total_bytes += 1
            
            if total_bytes == 0:
                return 0.0

            # Apply the standard Shannon Entropy formula
            entropy = 0.0
            for count in byte_counts:
                if count > 0:
                    probability = count / total_bytes
                    entropy -= probability * math.log2(probability)
            
            return round(entropy, 4)
        except Exception as e:
            return f"ERROR: Could not compute entropy - {str(e)}"

    def check_extension_mismatch(self, file_path, mime_type):
        """
        Catches simple spoofing attempts.
        For example: An attacker naming a malicious program 'invoice.pdf'
        when it's actually an executable binary.
        """
        extension = file_path.suffix.lower().replace(".", "")
        if not extension or "ERROR" in mime_type:
            return False
        
        # Mapping common file extensions to libmagic
        common_signatures = {
            "pdf": "application/pdf",
            "png": "image/png",
            "jpg": "image/jpeg",
            "jpeg": "image/jpeg",
            "gif": "image/gif",
            "exe": "application/x-dosexec",
            "zip": "application/zip",
            "txt": "text/plain",
            "html": "text/html",
            "json": "application/json"
        }
        
        expected_mime = common_signatures.get(extension)
        # If we recognize the extension but the actual MIME type is different, flags it
        if expected_mime and expected_mime != mime_type:
            return True
        return False

    def get_mac_times(self, file_path):
        """Gathers basic OS timeline metadata (Modified, Accessed, Created timestamps)."""
        try:
            stat_info = os.stat(file_path)
            # st_ctime is metadata change on Linux, but creation time on Windows.
            # Using st_birthtime if the operating system supports it.
            creation_time = getattr(stat_info, 'st_birthtime', stat_info.st_ctime)
            
            return {
                "created": datetime.fromtimestamp(creation_time).isoformat(),
                "modified": datetime.fromtimestamp(stat_info.st_mtime).isoformat(),
                "accessed": datetime.fromtimestamp(stat_info.st_atime).isoformat()
            }
        except Exception as e:
            return {"error": f"Failed to read OS timestamps: {str(e)}"}

    def get_exiftool_metadata(self, file_path):
        """Runs an external ExifTool process to scrape embedded metadata fields."""
        try:
            # -j gives us structured JSON back, -n forces machine-readable values
            cmd = [self.exiftool_path, "-j", "-n", str(file_path)]
            result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

            if result.returncode == 0:
                parsed_json = json.loads(result.stdout)[0]
                # Strip out the boring ExifTool meta-tags to keep the output clean
                return {k: v for k, v in parsed_json.items() if not k.startswith("ExifTool")}
            else:
                return {"error": result.stderr.strip()}
        except FileNotFoundError:
            return {"error": "ExifTool binary not found. Is it installed in your system PATH?"}
        except Exception as e:
            return {"error": str(e)}

    def analyze_single_file(self, file_path):
        """The main pipeline that gathers all metrics for an individual file."""
        file_path = Path(file_path)
        actual_mime = self.get_true_file_type(file_path)
        
        return {
            "file_name": file_path.name,
            "absolute_path": str(file_path.absolute()),
            "file_size_bytes": file_path.stat().st_size if file_path.exists() else 0,
            "sha256": self.get_sha256(file_path),
            "mime_type": actual_mime,
            "entropy": self.calculate_entropy(file_path),
            "is_spoofed_extension": self.check_extension_mismatch(file_path, actual_mime),
            "os_timestamps": self.get_mac_times(file_path),
            "embedded_metadata": self.get_exiftool_metadata(file_path)
        }


def run_scanner(target_directory, num_workers=4):
    """Dispatches files to a thread pool to accelerate scanning on large folders."""
    analyzer = ForensicFileAnalyzer()
    scan_path = Path(target_directory)
    results = []

    if not scan_path.exists() or not scan_path.is_dir():
        print(f"[-] Error: '{target_directory}' is not a valid directory path.")
        return

    # Gather all items inside the directory recursively, ignoring directory items themselves
    files_found = [item for item in scan_path.rglob("*") if item.is_file()]
    print(f"[+] Found {len(files_found)} files. Analyzing using {num_workers} threads...")

    with concurrent.futures.ThreadPoolExecutor(max_workers=num_workers) as executor:
        # Map our futures to track which file is being processed 
        future_map = {executor.submit(analyzer.analyze_single_file, f): f for f in files_found}

        for future in concurrent.futures.as_completed(future_map):
            associated_file = future_map[future]
            try:
                data = future.result()
                results.append(data)
                print(f"[SUCCESS] Analyzed: {data['file_name']}")
            except Exception as error:
                print(f"[FAILED] Error parsing {associated_file.name}: {error}")

    #Adding it all to a JSON file
    report_filename = "forensic_analysis_output.json"
    with open(report_filename, "w") as out_file:
        json.dump(results, out_file, indent=4)

    print(f"\n[+] Scan finished successfully! Results saved to: {report_filename}")


if __name__ == "__main__":
    #CLI handler 
    if len(sys.argv) < 2:
        print("Usage: python script.py <directory_to_scan>")
        print("Example: python script.py ./my_test_files")
    else:
        user_dir = sys.argv[1]
        run_scanner(user_dir)
