#!/usr/bin/env python3

import argparse
import os
import requests
import zipfile
import json
import shutil
import time
import concurrent.futures
from pathlib import Path
from tqdm import tqdm
from slack_sdk import WebClient
from slack_sdk.errors import SlackApiError
import subprocess
import sys

# ASCII Art for startup banner (using raw string to fix escape sequence warning)
ASCII_BANNER = r"""
 ___````````````````````______```````````````````````````
`.'````.````````````````.'`____`\``````````````````````````
/``.-.``\`_`.--.``.---.`|`(___`\_|_`.--.```,--.``_`.--.```
|`|```|`|[``.-.`|/`/__\\`_.____`.`[``.-.`|``'_\`:[`'/'`\`\`
\```-'``/`|`|`|`||`\__.,|`\____)`|`|`|`|`|`//`|`|,|`\__/`|`
``.___.'`[___||__]'.__.'`\______.'[___||__]\'-;__/|`;.__/``
`````````````````````````````````````````````````[__|``````
"""

# Constants
SCRIPT_NAME = "One Snap: The Universal Bounty Subdomain Harvester"
AUTHOR = "x.com/starkcharry | github.com/7ealvivek | bugcrowd.com/realvivek"
# IMPORTANT: Replace these placeholder values with your actual API keys/tokens.
# DO NOT commit your actual keys to a public repository!
C99_API_KEY = "[YOUR_C99_API_KEY_HERE]"
SLACK_TOKEN = "[YOUR_SLACK_TOKEN_HERE]"
SLACK_CHANNEL = "#all-subdomains" # Customize your Slack channel name here, e.g., "#recon-results"

# Directory and File Names
ZIP_DIR = "chaos_zips"
EXTRACT_DIR = "extracted"
FINAL_ALL = "final_allsubs.txt"
FINAL_ZIP = "final_allsubs.zip"
HTTPX_OUT = "httpx_output.txt"
CHAOS_INDEX = "https://chaos-data.projectdiscovery.io/index.json" # Source of Chaos data and platform info

# Optional GUI imports
try:
    import tkinter as tk
    from tkinter import filedialog, messagebox
    GUI_AVAILABLE = True
except ImportError:
    GUI_AVAILABLE = False

# GUI integration using tkinter
class OneSnapGUI:
    def __init__(self, master):
        self.master = master
        master.title("One Snap GUI")
        master.geometry("500x550") # Set a default window size
        master.resizable(False, False) # Make window non-resizable

        # Styling
        master.tk_setPalette(background='#ececec', foreground='#333333',
                             activeBackground='#c0c0c0', activeForeground='#000000')
        font_label = ('Arial', 10)
        font_button = ('Arial', 10, 'bold')
        font_header = ('Arial', 12, 'bold')

        tk.Label(master, text=SCRIPT_NAME, font=font_header, fg='darkblue').pack(pady=(15, 5))
        tk.Label(master, text=AUTHOR, font=('Arial', 8, 'italic')).pack(pady=(0, 10))

        # Private List Section
        tk.Label(master, text="Private Subdomains List:", font=font_label, anchor="w").pack(fill="x", padx=20, pady=(10, 0))
        self.private_file_path = tk.StringVar()
        self.private_file_path.set("No private list selected.")
        tk.Label(master, textvariable=self.private_file_path, font=font_label, fg='gray').pack(fill="x", padx=20)
        tk.Button(master, text="Select Private List", command=self.ask_private, font=font_button).pack(pady=(5, 15))

        tk.Frame(master, height=1, bg="lightgray").pack(fill="x", padx=15, pady=5) # Separator

        # Action Checkboxes
        tk.Label(master, text="Post-Processing & Output Options:", font=font_label, anchor="w").pack(fill="x", padx=20, pady=(10, 0))
        self.slack_var = tk.BooleanVar()
        tk.Checkbutton(master, text="Upload final ZIP to Slack", variable=self.slack_var, font=font_label).pack(anchor="w", padx=20)

        self.rerun_chaos_var = tk.BooleanVar()
        tk.Checkbutton(master, text="Force full Chaos data download (ignores platform filter)", variable=self.rerun_chaos_var, font=font_label).pack(anchor="w", padx=20)

        self.httpx_var = tk.BooleanVar()
        tk.Checkbutton(master, text="Run httpx after final list", variable=self.httpx_var, font=font_label).pack(anchor="w", padx=20)
        
        tk.Frame(master, height=1, bg="lightgray").pack(fill="x", padx=15, pady=15) # Separator

        # Bounty Platform Checkboxes
        tk.Label(master, text="Filter Chaos Data by Bounty Platform:", font=font_label, anchor="w").pack(fill="x", padx=20, pady=(0, 5))
        tk.Label(master, text="(Select one or more. No selection = full Chaos download)", font=('Arial', 8, 'italic'), fg='gray').pack(fill="x", padx=20)

        self.platform_vars = {
            "bugcrowd": tk.BooleanVar(),
            "hackerone": tk.BooleanVar(),
            "intigriti": tk.BooleanVar(),
            "yeswehack": tk.BooleanVar(),
            "hackenproof": tk.BooleanVar(),
        }
        platform_frame = tk.Frame(master)
        platform_frame.pack(anchor="w", padx=20, pady=5)
        
        row_idx = 0
        col_idx = 0
        for platform_name, var in self.platform_vars.items():
            cb = tk.Checkbutton(platform_frame, text=platform_name.replace("_", " ").title(), variable=var, font=font_label)
            cb.grid(row=row_idx, column=col_idx, sticky="w", padx=5)
            col_idx += 1
            if col_idx > 1: # Change to 1 for a single column, 2 for two columns
                col_idx = 0
                row_idx += 1

        tk.Frame(master, height=1, bg="lightgray").pack(fill="x", padx=15, pady=15) # Separator

        self.run_button = tk.Button(master, text="Run One Snap", command=self.run_script, font=('Arial', 12, 'bold'), bg='darkgreen', fg='white')
        self.run_button.pack(pady=10, ipadx=20, ipady=5)

        self.private_file = None

    def ask_private(self):
        filename = filedialog.askopenfilename(
            title="Select Private Subdomains List",
            filetypes=[("Text files", "*.txt"), ("All files", "*.*")]
        )
        if filename:
            self.private_file = filename
            self.private_file_path.set(f"Private list: {os.path.basename(filename)}")
        else:
            self.private_file_path.set("No private list selected.")

    def run_script(self):
        upload_to_slack = self.slack_var.get()
        rerun_chaos = self.rerun_chaos_var.get()
        run_httpx = self.httpx_var.get()
        
        # Collect selected platforms from checkboxes
        selected_platforms_from_gui = []
        for platform_name, var in self.platform_vars.items():
            if var.get(): # If the checkbox is ticked
                selected_platforms_from_gui.append(platform_name)

        # Disable button during run
        self.run_button.config(state=tk.DISABLED, text="Running...")
        self.master.update_idletasks() # Update GUI immediately

        try:
            run_one_snap(self.private_file, upload_to_slack, rerun_chaos, run_httpx, selected_platforms_from_gui)
            messagebox.showinfo("Success", "One Snap: Done! Final list is ready.")
        except SystemExit as e:
            if e.code != 0:
                messagebox.showerror("Error", f"One Snap encountered an error: {e}")
            else:
                messagebox.showinfo("Finished", "One Snap: No subdomains collected or process exited gracefully.")
        except Exception as e:
            messagebox.showerror("Unexpected Error", f"An unexpected error occurred: {e}")
        finally:
            self.run_button.config(state=tk.NORMAL, text="Run One Snap", bg='darkgreen', fg='white')

# Utility functions

def fetch_chaos_index():
    """Fetches and returns the Chaos Project index.json."""
    try:
        print(f"[*] Fetching Chaos index from: {CHAOS_INDEX}")
        index_response = requests.get(CHAOS_INDEX, timeout=15)
        index_response.raise_for_status() # Raise an HTTPError for bad responses (4xx or 5xx)
        return index_response.json()
    except requests.exceptions.RequestException as e:
        print(f"[!] Error fetching Chaos index: {e}.")
        return None
    except json.JSONDecodeError as e:
        print(f"[!] Error decoding Chaos index JSON: {e}.")
        return None

def download_chaos(chaos_index_data, selected_platforms=None):
    """
    Downloads Chaos Project ZIP files with enhanced retries for network/DNS issues.
    If selected_platforms is provided (a list of platform names), only ZIPs for those platforms are downloaded.
    Otherwise, all Chaos ZIPs are downloaded.
    """
    Path(ZIP_DIR).mkdir(exist_ok=True)
    Path(EXTRACT_DIR).mkdir(exist_ok=True)
    
    if not chaos_index_data:
        print("[!] No Chaos index data available. Skipping Chaos download.")
        return

    urls_to_download = []
    if selected_platforms:
        # Convert selected platforms to lowercase for case-insensitive matching
        platforms_lower = {p.lower() for p in selected_platforms}
        print(f"[*] Filtering Chaos downloads for platforms: {', '.join(platforms_lower)}")
        
        for item in chaos_index_data:
            platform = item.get("platform", "").lower()
            if platform in platforms_lower:
                urls_to_download.append(item["URL"])
        
        if not urls_to_download:
            print("[!] No Chaos ZIPs found for the specified platforms in the Chaos index.")
            return # No matching Chaos data to download
        else:
            print(f"[*] Identified {len(urls_to_download)} Chaos ZIPs matching specified platforms.")
    else:
        print("[*] No specific platforms selected for filtering. Downloading all Chaos Project ZIPs.")
        urls_to_download = [item["URL"] for item in chaos_index_data]

    # Use a requests Session for better connection management and retries
    session = requests.Session()
    # Configure an HTTPAdapter for retries on connection errors (including DNS)
    retries = requests.packages.urllib3.util.retry.Retry(
        total=10,  # Increased total retries (1 initial + 10 retries = 11 attempts)
        backoff_factor=0.7, # Exponential backoff: 0.7s, 1.4s, 2.8s, 5.6s, 11.2s, etc.
        status_forcelist=[429, 500, 502, 503, 504], # Retry on these HTTP status codes (429 = Too Many Requests)
        allowed_methods=frozenset(['GET']), # Only retry GET requests
        respect_retry_after_header=True, # Respect 'Retry-After' header if present
        connect=True, # Enable retries for connection errors (including NameResolutionError, TLS errors)
        read=True, # Enable retries for read timeouts
        redirect=True # Enable retries for redirects
    )
    adapter = requests.adapters.HTTPAdapter(max_retries=retries)
    session.mount('http://', adapter)
    session.mount('https://', adapter)

    failed_downloads = [] # List to store URLs that failed to download even after retries

    for url in tqdm(urls_to_download, desc="[↓] Downloading & Extracting Chaos Zips"):
        zip_path = os.path.join(ZIP_DIR, os.path.basename(url))
        if not os.path.exists(zip_path):
            try:
                # Use the session for the request, timeout for each attempt
                r = session.get(url, stream=True, timeout=30) # Increased individual attempt timeout
                r.raise_for_status() # Raise an exception for bad status codes
                with open(zip_path, 'wb') as f:
                    shutil.copyfileobj(r.raw, f)
            except requests.exceptions.ConnectionError as e:
                # Catches NameResolutionError, Max retries exceeded for connection, etc.
                print(f"\n[!] Connection error for {url} after retries: {e}")
                failed_downloads.append(url)
                time.sleep(2) # Pause for 2 seconds before trying next URL to give network/DNS a break
                continue # Skip to next URL
            except requests.exceptions.RequestException as e:
                # Catches other request-related exceptions (e.g., HTTPError for 404/500, general Timeout)
                print(f"\n[!] Failed to download {url}: {e}")
                failed_downloads.append(url)
                time.sleep(2) # Pause for 2 seconds before trying next URL
                continue
        
        try:
            with zipfile.ZipFile(zip_path, 'r') as zip_ref:
                zip_ref.extractall(EXTRACT_DIR)
        except zipfile.BadZipFile:
            print(f"\n[!] Corrupt zip file detected: {zip_path}. Attempting to remove and continue.")
            try:
                os.remove(zip_path) # Remove corrupt file so it might be re-downloaded later
            except OSError as e:
                print(f"[!] Could not remove corrupt file {zip_path}: {e}")
            failed_downloads.append(url) # Treat as a failure if corrupt
        except Exception as e:
            print(f"\n[!] Error extracting {zip_path}: {e}")
            failed_downloads.append(url) # Treat as a failure if extraction fails

    if failed_downloads:
        print("\n[!] WARNING: The following Chaos ZIPs failed to download or extract after multiple retries:")
        for failed_url in failed_downloads:
            print(f"    - {failed_url}")
        print("[!] This might indicate a persistent network issue, server problem, or corrupt file. Collected data may be incomplete.")

def extract_chaos_subdomains():
    """Extracts all unique subdomains from text files in the Chaos extraction directory."""
    all_subs = set()
    for file in Path(EXTRACT_DIR).rglob("*.txt"):
        try:
            with open(file, 'r', encoding='utf-8', errors='ignore') as f:
                for line in f:
                    sub = line.strip().lstrip("*.") # Remove leading '*.' if present
                    if sub:
                        all_subs.add(sub)
        except Exception as e:
            print(f"[!] Error reading {file}: {e}")
            continue
    return all_subs

def get_root_domains(subdomains):
    """Extracts unique root domains (e.g., example.com from www.example.com) from a list of subdomains."""
    return sorted(set('.'.join(d.split('.')[-2:]) for d in subdomains if len(d.split('.')) >= 2))

def get_platform_roots_from_chaos_index(chaos_index_data, selected_platforms):
    """
    Extracts root domains (names) from the Chaos index data for specified platforms.
    These are the top-level domains that Chaos tracks for those platforms.
    """
    platform_roots = set()
    if not chaos_index_data or not selected_platforms:
        return platform_roots

    platforms_lower = {p.lower() for p in selected_platforms}
    for item in chaos_index_data:
        platform = item.get("platform", "").lower()
        if platform in platforms_lower:
            name = item.get("name") # This is typically the root domain (e.g., "example.com")
            if name:
                platform_roots.add(name.strip().lower())
    print(f"[*] Identified {len(platform_roots)} primary root domains from Chaos index for selected platforms.")
    return platform_roots

def query_c99(domains):
    """Queries the C99.nl API for subdomains given a list of root domains."""
    result = set()
    if not domains:
        return result

    # Validate C99 API key (checks for both empty string and the placeholder)
    if not C99_API_KEY or C99_API_KEY == "[YOUR_C99_API_KEY_HERE]":
        print("[!] C99_API_KEY is not configured. Please set your actual key in the script. Skipping C99 queries.")
        return result

    def query_single_domain(domain):
        try:
            res = requests.get(
                f"https://api.c99.nl/subdomainfinder?key={C99_API_KEY}&domain={domain}&realtime=true&json",
                timeout=10 # Add a timeout for API requests
            ).json()
            if res.get("status") == "success":
                # Ensure 'subdomain' key exists and is not empty before adding
                return {s["subdomain"].strip().lstrip("*.") for s in res.get("subdomains", []) if s.get("subdomain")}
            else:
                error_msg = res.get("error", "Unknown error")
                if "rate limit" in error_msg.lower():
                    print(f"\n[!] C99 API Rate Limit hit for {domain}. Pausing...")
                    return "RATE_LIMITED" # Special signal for rate limit
                print(f"\n[!] C99 API error for {domain}: {error_msg}")
                return set()
        except requests.exceptions.RequestException as e:
            print(f"\n[!] C99 API request failed for {domain}: {e}")
            return set()
        except json.JSONDecodeError:
            print(f"\n[!] C99 API returned invalid JSON for {domain}. Response might not be JSON or empty.")
            return set()
        except Exception as e:
            print(f"\n[!] An unexpected error occurred during C99 query for {domain}: {e}")
            return set()

    # Using conservative C99 query parameters for better resilience against API errors
    chunk_size = 50 # Number of domains per concurrent chunk (reduced from 100)
    domain_chunks = [domains[i:i + chunk_size] for i in range(0, len(domains), chunk_size)]

    for idx, chunk in enumerate(domain_chunks, 1):
        print(f"[C99] Processing chunk {idx}/{len(domain_chunks)} ({len(chunk)} root domains)")
        rate_limit_hit_in_chunk = False
        with concurrent.futures.ThreadPoolExecutor(max_workers=3) as executor: # Reduced from 10 to 3
            futures = {executor.submit(query_single_domain, d): d for d in chunk}
            for f in tqdm(concurrent.futures.as_completed(futures), total=len(chunk), desc=f"[C99 Chunk {idx}]"):
                res = f.result()
                if res == "RATE_LIMITED":
                    rate_limit_hit_in_chunk = True
                    break # Stop processing current chunk on rate limit
                result.update(res)
        
        if rate_limit_hit_in_chunk:
            print("[!] C99 API rate limit hit. Waiting for 60 seconds before resuming (if possible).")
            time.sleep(60) # Longer pause on rate limit
        elif idx < len(domain_chunks):
            print("[*] Waiting 10 seconds before next C99 chunk...") # Increased from 5 to 10
            time.sleep(10)

    return result

def upload_to_slack(filepath):
    """Uploads a file to Slack."""
    if not os.path.exists(filepath):
        print(f"[!] File not found for Slack upload: {filepath}")
        return

    # Validate Slack token
    if not SLACK_TOKEN or SLACK_TOKEN == "[YOUR_SLACK_TOKEN_HERE]":
        print("[!] SLACK_TOKEN is not configured. Please set your actual token in the script. Skipping Slack upload.")
        return

    size = os.path.getsize(filepath) / 1024 / 1024
    if size > 800: # Slack's typical file upload limit for free workspaces is ~800MB
        print(f"[!] File too large ({size:.2f} MB) for Slack upload (max ~800 MB). Skipping.")
        return
    try:
        client = WebClient(token=SLACK_TOKEN)
        with open(filepath, "rb") as f:
            response = client.files_upload(
                channels=SLACK_CHANNEL,
                file=f,
                title="\U0001F4E6 Final All Subdomains ZIP",
                initial_comment=f"Total subs: {sum(1 for _ in open(FINAL_ALL)) if os.path.exists(FINAL_ALL) else 'N/A'}"
            )
            if response["ok"]:
                print("[✓] Uploaded to Slack successfully.")
            else:
                print(f"[!] Slack upload failed: {response['error']}")
    except SlackApiError as e:
        print(f"[!] Slack API error: {e.response['error']}")
    except Exception as e:
        print(f"[!] An unexpected error occurred during Slack upload: {e}")

def save_final_output(subdomains):
    """Saves the unique subdomains to a text file and then zips it."""
    unique_subs = sorted(list(subdomains)) # Convert set to list and sort for consistent output
    print(f"[*] Saving {len(unique_subs)} unique subdomains to {FINAL_ALL} and zipping to {FINAL_ZIP}...")
    try:
        with open(FINAL_ALL, 'w') as f:
            for sub in unique_subs:
                f.write(sub + "\n")
        with zipfile.ZipFile(FINAL_ZIP, 'w', zipfile.ZIP_DEFLATED) as zf:
            zf.write(FINAL_ALL, os.path.basename(FINAL_ALL)) # Save with just filename inside zip
        print(f"[✓] Final list saved: {FINAL_ALL} and {FINAL_ZIP}")
    except Exception as e:
        print(f"[!] Error saving final output: {e}")

def format_time(seconds):
    """Formats seconds into Hh Mm Ss."""
    m, s = divmod(int(seconds), 60)
    h, m = divmod(m, 60)
    return f"{h}h {m}m {s}s" if h else (f"{m}m {s}s" if m else f"{s}s")

def run_httpx_scan(input_file=FINAL_ALL, output_file=HTTPX_OUT):
    """Runs httpx on the final subdomain list with a progress bar and time estimates."""
    if not os.path.exists(input_file) or os.path.getsize(input_file) == 0:
        print(f"[!] httpx input file not found or empty: {input_file}. Skipping httpx scan.")
        return

    try:
        total_lines = 0
        with open(input_file, 'r', encoding='utf-8', errors='ignore') as f:
            for _ in f:
                total_lines += 1
        if total_lines == 0:
            print(f"[!] httpx input file '{input_file}' is empty. Skipping httpx scan.")
            return

    except Exception as e:
        print(f"[!] Could not read input file {input_file} for httpx scan: {e}. Skipping httpx scan.")
        return

    print(f"[*] Running httpx on {total_lines} subdomains. Results will be saved to: {output_file}")
    
    # httpx options:
    # -l <input_file>: input list of subdomains
    # -o <output_file>: output file for results
    # -silent: suppress verbose output on stdout
    # -threads 1000: set high concurrency for speed (from original inspiration script)
    # -timeout 3: set 3 second timeout for HTTP requests (from original inspiration script)
    # Note: -cdn and -resume removed as requested
    httpx_command = [
        "httpx", "-l", input_file, "-o", output_file,
        "-silent", "-threads", "1000", "-timeout", "3"
    ]

    # Validate httpx availability
    try:
        subprocess.run(["httpx", "-h"], check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    except FileNotFoundError:
        print("[!] httpx command not found. Please install httpx (go install github.com/projectdiscovery/httpx/cmd/httpx@latest) and ensure it's in your PATH.")
        return
    except subprocess.CalledProcessError:
        print("[!] httpx command exists but failed to run its help page. Check httpx installation or permissions.")
        return

    # Use a temporary file to capture httpx's stderr for progress parsing
    temp_stderr_file = "httpx_progress_temp.txt"
    with open(temp_stderr_file, "w") as f_err:
        process = subprocess.Popen(httpx_command, stdout=subprocess.DEVNULL, stderr=f_err, text=True)

        start_time = time.time()
        with tqdm(total=total_lines, desc="[HTTPX]", unit="url", leave=True) as pbar:
            while process.poll() is None:
                time.sleep(1)
                f_err.flush()
                try:
                    with open(temp_stderr_file, 'r') as f:
                        lines = f.readlines()
                        if lines:
                            last_line = lines[-1].strip()
                            if "URLs:" in last_line:
                                parts = last_line.split("URLs:")[1].split("|")[0].strip().split("/")
                                if len(parts) == 2:
                                    processed_count = int(parts[0].strip())
                                    current_total = int(parts[1].strip())
                                    
                                    pbar.total = current_total
                                    pbar.n = processed_count
                                    pbar.refresh()

                                    elapsed_time = time.time() - start_time
                                    if processed_count > 0:
                                        urls_per_second = processed_count / elapsed_time
                                        remaining_urls = current_total - processed_count
                                        if urls_per_second > 0:
                                            estimated_remaining_time = remaining_urls / urls_per_second
                                            pbar.set_postfix_str(f"Elapsed: {format_time(elapsed_time)} | ETA: {format_time(estimated_remaining_time)}")
                                        else:
                                            pbar.set_postfix_str(f"Elapsed: {format_time(elapsed_time)}")
                                else:
                                    pbar.set_postfix_str(f"Parsing error: {last_line}")
                            else:
                                pbar.set_postfix_str(f"Waiting for httpx progress... {last_line[:50]}...")

                except Exception:
                    pass

        pbar.close()

    if process.returncode == 0:
        print(f"[✓] HTTPX completed. Results saved to: {output_file}")
    else:
        print(f"[!] HTTPX failed with exit code {process.returncode}.")
        print(f"    Check '{temp_stderr_file}' for more details.")
    
    if os.path.exists(temp_stderr_file):
        os.remove(temp_stderr_file)

# Main logic

def run_one_snap(private_txt=None, upload_slack=False, rerun_chaos=False, run_httpx=False, selected_bounty_platforms=None):
    # Initialize sets to collect all types of subdomains
    chaos_direct_subs = set()         # Subdomains directly extracted from Chaos ZIPs
    c99_public_enriched_subs = set()  # Subdomains from C99, based on public roots (Chaos or Platforms)
    private_subs = set()              # Subdomains from user's private list
    c99_private_enriched_subs = set() # Subdomains from C99, based on private list roots

    # This set will aggregate all public root domains found from any public source
    # to be fed into C99.nl for enrichment.
    public_root_domains_for_c99 = set()

    # --- Phase 1: Determine and process public data source (Bounty Platforms OR Full Chaos) ---

    chaos_index_data = fetch_chaos_index()
    if not chaos_index_data:
        print("[!] Could not retrieve Chaos index. Public data collection from Chaos will be skipped.")
    
    # Decide how to download Chaos: filtered by platform or full
    if rerun_chaos or not selected_bounty_platforms:
        # Scenario 1: Force full Chaos download (due to --rerun-chaos flag)
        # Scenario 2: No specific platforms selected, so default to full Chaos download
        print("[*] Performing full Chaos data collection (no platform filter active or --rerun-chaos used).")
        download_chaos(chaos_index_data, None) # Pass None to indicate no platform filter
    elif selected_bounty_platforms and chaos_index_data:
        # Scenario 3: Specific platforms selected AND Chaos index available. Filter Chaos download.
        print(f"[*] Performing filtered Chaos data collection for platforms: {', '.join(selected_bounty_platforms)}.")
        download_chaos(chaos_index_data, selected_platforms) # Pass selected_platforms for filtering
        
        # Add roots from the selected platforms directly from the Chaos index for C99 enrichment
        # This covers cases where a program's primary domain (name) is relevant but may not appear immediately
        # in the extracted subdomains.
        public_root_domains_for_c99.update(get_platform_roots_from_chaos_index(chaos_index_data, selected_platforms))
    else:
        print("[*] Skipping Chaos data collection (no platforms selected or no index, and no --rerun-chaos).")

    # Extract subdomains from whatever Chaos data was downloaded (could be full or filtered)
    chaos_direct_subs.update(extract_chaos_subdomains())
    if chaos_direct_subs:
        # Also add roots from the actually extracted Chaos subdomains to the C99 query pool.
        # This ensures C99 gets all discovered roots, including those not explicitly listed as 'name' in Chaos index.
        public_root_domains_for_c99.update(get_root_domains(chaos_direct_subs))
    else:
        print("[!] No subdomains extracted from Chaos data.")

    # Perform C99 enrichment on all collected unique public roots (from platforms AND/OR extracted Chaos data)
    if public_root_domains_for_c99:
        print(f"[*] Querying C99.nl with {len(public_root_domains_for_c99)} unique public root domains...")
        c99_public_enriched_subs.update(query_c99(list(public_root_domains_for_c99)))
    else:
        print("[!] No public root domains to query C99.nl with.")


    # --- Phase 2: Process Private List (always runs if private_txt is provided) ---
    if private_txt:
        print(f"[*] Including private subs from '{private_txt}' and C99 enrichment...")
        try:
            with open(private_txt, 'r', encoding='utf-8', errors='ignore') as f:
                for line in f:
                    sub = line.strip().lstrip("*.")
                    if sub:
                        private_subs.add(sub)
            if private_subs:
                private_roots = get_root_domains(private_subs)
                if private_roots:
                    c99_private_enriched_subs = query_c99(private_roots)
                else:
                    print(f"[!] No root domains extracted from private file '{private_txt}' for C99 enrichment.")
            else:
                print(f"[!] Private file '{private_txt}' was empty or contained no valid subdomains.")
        except FileNotFoundError:
            print(f"[!] Error: Private file '{private_txt}' not found.")
            sys.exit(1) # Exit if the specified private file doesn't exist
        except Exception as e:
            print(f"[!] Error processing private file '{private_txt}': {e}")
            sys.exit(1)


    # --- Phase 3: Merge all collected subdomains and Finalize ---
    all_merged = chaos_direct_subs.union(c99_public_enriched_subs).union(private_subs).union(c99_private_enriched_subs)

    if not all_merged:
        print("[!] No subdomains collected from any source. Please check your inputs and flags. Exiting.")
        # Clean up created directories if they are empty
        if Path(ZIP_DIR).exists() and not list(Path(ZIP_DIR).iterdir()): shutil.rmtree(ZIP_DIR, ignore_errors=True)
        if Path(EXTRACT_DIR).exists() and not list(Path(EXTRACT_DIR).iterdir()): shutil.rmtree(EXTRACT_DIR, ignore_errors=True)
        sys.exit(1) # Exit with an error code if no subdomains were found

    print(f"\n[*] Total unique subdomains collected: {len(all_merged)}")
    save_final_output(all_merged)

    if upload_slack:
        upload_to_slack(FINAL_ZIP)

    if run_httpx:
        run_httpx_scan()
    
    # Clean up intermediate directories after successful run
    print("[*] Cleaning up intermediate directories...")
    shutil.rmtree(ZIP_DIR, ignore_errors=True)
    shutil.rmtree(EXTRACT_DIR, ignore_errors=True)
    print("[✓] Cleanup complete.")


# Entry point for CLI/GUI execution
if __name__ == '__main__':
    # Print the ASCII banner at the very start
    print(ASCII_BANNER)
    print(f"       {SCRIPT_NAME}\n") 
    
    # Print Author and Contact details right below the banner
    print("--------------------------------------------------------------------------------")
    print("                                           Developed by:")
    print("                                           X (Twitter): @starkcharry")
    print("                                           Bugcrowd: bugcrowd.com/realvivek")
    print("                                           GitHub: @7ealvivek")
    print("--------------------------------------------------------------------------------\n")


    # Parse arguments for CLI mode
    if GUI_AVAILABLE and os.environ.get('DISPLAY'):
        root = tk.Tk()
        app = OneSnapGUI(root)
        root.mainloop() # GUI mainloop will keep the script running
    else:
        parser = argparse.ArgumentParser(description="One Snap CLI: The Universal Bounty Subdomain Harvester",
                                         formatter_class=argparse.RawTextHelpFormatter)
        
        parser.add_argument("--private", help="Path to a text file containing private subdomains (one per line).\n"
                                               "These will be included and enriched via C99.nl.", required=False)
        parser.add_argument("--slack", action="store_true", help="Upload the final subdomain ZIP to the configured Slack channel.")
        parser.add_argument("--rerun-chaos", action="store_true", 
                            help="Force a full re-download of ALL Chaos Project data.\n"
                                 "This overrides any platform-specific filtering and ensures the freshest, complete Chaos dataset.")
        parser.add_argument("--httpx", action="store_true", 
                            help="Run httpx on the final collected subdomain list.\n"
                                 "Results will be saved to 'httpx_output.txt' to identify live HTTP/S hosts.")

        # Arguments for specific bounty platforms
        platform_group = parser.add_argument_group('Bounty Platforms (Optional)', 
                                                     'Select one or more specific bug bounty platforms to filter public data collection.\n'
                                                     '  - If selected, Chaos downloads will be limited to programs from these platforms.\n'
                                                     '  - If NO platforms are selected, the script defaults to downloading ALL Chaos data.\n'
                                                     '  - Note: `--rerun-chaos` overrides any platform selection, forcing a full Chaos download.')
        platform_group.add_argument("-bugcrowd", action="store_true", help="Include programs from Bugcrowd.")
        platform_group.add_argument("-h1", action="store_true", dest="hackerone", help="Include programs from HackerOne.")
        platform_group.add_argument("-intigriti", action="store_true", help="Include programs from Intigriti.")
        platform_group.add_argument("-yeswehack", action="store_true", help="Include programs from YesWeHack.")
        platform_group.add_argument("-hackandproof", action="store_true", dest="hackenproof", help="Include programs from HackenProof.")

        args = parser.parse_args()

        # Collect selected platforms into a list
        selected_platforms = []
        if args.bugcrowd:
            selected_platforms.append("bugcrowd")
        if args.hackerone:
            selected_platforms.append("hackerone")
        if args.intigriti:
            selected_platforms.append("intigriti")
        if args.yeswehack:
            selected_platforms.append("yeswehack")
        if args.hackenproof:
            selected_platforms.append("hackenproof")

        # Call the main function with all collected arguments
        run_one_snap(args.private, args.slack, args.rerun_chaos, args.httpx, selected_platforms)
