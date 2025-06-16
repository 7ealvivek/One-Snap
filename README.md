
# One Snap: The Universal Bounty Subdomain Harvester

![Python Version](https://img.shields.io/badge/python-3.x-blue.svg)
![License](https://img.shields.io/badge/License-MIT-yellow.svg)
![Dependencies](https://img.shields.io/badge/dependencies-requests%2C%20tqdm%2C%20slack_sdk%2C%20httpx-green.svg)
![GUI Availability](https://img.shields.io/badge/GUI-Tkinter-brightgreen.svg)

---

## Table of Contents

*   [Introduction](#introduction)
*   [Key Features](#key-features)
*   [How It Works (Core Logic)](#how-it-works-core-logic)
*   [Installation](#installation)
    *   [Prerequisites](#prerequisites)
    *   [Setup Steps](#setup-steps)
*   [Configuration (API Keys & Tokens)](#configuration-api-keys--tokens)
*   [Usage](#usage)
    *   [Command Line Interface (CLI)](#command-line-interface-cli)
    *   [Graphical User Interface (GUI)](#graphical-user-interface-gui)
*   [Understanding the Output](#understanding-the-output)
*   [Troubleshooting & Tips](#troubleshooting--tips)
*   [Contributing](#contributing)
*   [License](#license)
*   [Author & Credits](#author--credits)

---

## Introduction

**One Snap** is an all-in-one Python script meticulously crafted to automate and streamline the often tedious process of subdomain collection for bug bounty hunting, penetration testing, and general reconnaissance. It brings together public and private data sources, enriches findings using an external API, probes for live hosts, and can even report results to Slack, all in a single "snap."

Tired of juggling multiple tools and datasets? One Snap simplifies your workflow, offering both a powerful command-line interface and an intuitive graphical user interface to collect comprehensive subdomain lists with unprecedented ease and precision.

---

## Key Features

*   **Flexible Chaos Data Collection:**
    *   **Default:** Downloads and processes the *entire* ProjectDiscovery Chaos dataset for a broad sweep.
    *   **Targeted:** Filter Chaos downloads to include data *only* from specific bug bounty platforms (e.g., HackerOne, Bugcrowd, Intigriti, YesWeHack, HackenProof) if you're focusing on particular programs.
    *   **Force Full:** An explicit option to re-download the *complete* Chaos dataset, overriding any platform filters, ensuring you always have the freshest, most comprehensive public data.
*   **Comprehensive C99.nl Enrichment:** Integrates with the C99.nl subdomain finder API to discover even more subdomains by querying against root domains derived from both public (Chaos/platform-specific) and private sources. Includes built-in rate limit handling.
*   **Private List Integration:** Seamlessly incorporates your own pre-existing lists of subdomains, enriching them with C99.nl queries and merging them with public findings for a truly universal list.
*   **Optional `httpx` Scan with Real-time Progress:** Automatically runs ProjectDiscovery's `httpx` to probe the final list of subdomains, identifying live HTTP/S hosts. Features a real-time progress bar with elapsed time and estimated time remaining.
*   **Optional Slack Integration:** Uploads the final, compressed subdomain list directly to your configured Slack channel for easy sharing and reporting.
*   **Dual Interface:** Offers both a robust Command Line Interface (CLI) for scripting and automation, and a user-friendly Graphical User Interface (GUI) powered by Tkinter for interactive use.
*   **Automated Cleanup:** Automatically removes temporary download and extraction directories after a successful run, keeping your workspace tidy.
*   **Robust Error Handling:** Includes checks and informative messages for network issues, API failures, missing files, and command execution problems.

---

## How It Works (Core Logic)

One Snap operates through a series of intelligent steps to build your comprehensive subdomain list:

1.  **Fetch Chaos Index (`CHAOS_INDEX`):**
    *   The script first connects to `https://chaos-data.projectdiscovery.io/index.json` to retrieve the latest manifest of all available Chaos subdomain `.zip` files. This index also contains metadata, including the `platform` associated with each domain (e.g., "hackerone", "bugcrowd").

2.  **Public Data Acquisition (Conditional Chaos Download):**
    *   **Decision Point:** The script determines which Chaos `.zip` files to download based on your command-line arguments or GUI selections:
        *   If **no specific bounty platforms** (like `-h1`, `-bugcrowd`) are selected, OR if the `--rerun-chaos` flag is present, One Snap proceeds to download **all** `.zip` files listed in the Chaos index.
        *   If **specific bounty platforms ARE selected** (e.g., `-h1 -bugcrowd`), and `--rerun-chaos` is *not* used, the script filters the Chaos index. It identifies and downloads **only** those `.zip` files whose `platform` field matches your selected platforms.
    *   **Download & Extraction:** The selected `.zip` files are downloaded into `chaos_zips/` and then extracted into `extracted/`.

3.  **Subdomain Extraction from Chaos:**
    *   All `.txt` files within the `extracted/` directory (which now contains either filtered or full Chaos data) are read.
    *   Each line is cleaned (removing leading `*.`) and added to the `chaos_direct_subs` set, automatically handling deduplication.

4.  **Root Domain Aggregation for C99.nl Enrichment (Public Sources):**
    *   A comprehensive set of public root domains (`public_root_domains_for_c99`) is built from two sources:
        *   **From Chaos Index (for selected platforms):** If you chose specific bounty platforms, the root `name`s (e.g., "example.com") associated with those platforms directly from the Chaos index are added.
        *   **From Extracted Chaos Subdomains:** The script extracts root domains (e.g., `example.com` from `sub.example.com`) from all subdomains collected in `chaos_direct_subs`. This ensures C99.nl queries are based on all discovered public roots.

5.  **C99.nl Enrichment (Public Data):**
    *   The script takes the `public_root_domains_for_c99` set.
    *   It then queries the C99.nl API for each of these root domains, running queries in parallel batches with built-in pauses to respect API rate limits.
    *   Any new subdomains discovered through C99.nl are added to `c99_public_enriched_subs`.

6.  **Private List Processing (Optional):**
    *   If you provided a private subdomain list via `--private my_targets.txt`:
        *   The script reads all subdomains from this file into the `private_subs` set.
        *   It extracts root domains from your `private_subs`.
        *   These private roots are then used to query C99.nl for further enrichment, adding new findings to `c99_private_enriched_subs`.

7.  **Merge & Deduplicate All Subdomains:**
    *   Finally, all collected subdomains from `chaos_direct_subs`, `c99_public_enriched_subs`, `private_subs`, and `c99_private_enriched_subs` are combined into a single, master set called `all_merged`. Since sets only store unique elements, this step inherently performs deduplication, resulting in a clean, sorted list of unique subdomains.

8.  **Output & Post-Processing:**
    *   The `all_merged` list is saved to `final_allsubs.txt` (one subdomain per line).
    *   This `.txt` file is then compressed into `final_allsubs.zip`.
    *   **Optional Slack Upload:** If `--slack` is used, `final_allsubs.zip` is uploaded to your specified Slack channel.
    *   **Optional `httpx` Scan:** If `--httpx` is used, the script executes `httpx` on `final_allsubs.txt` to find live web servers, saving results to `httpx_output.txt`. A real-time progress bar with time estimates is displayed during this process.

9.  **Cleanup:**
    *   The temporary `chaos_zips/` and `extracted/` directories are automatically removed, keeping your system clean.

---

## Installation

### Prerequisites

Before you can run One Snap, ensure you have the following installed on your system:

*   **Python 3.x**: The script is written in Python 3.
*   **`git`**: For cloning the repository.
*   **Go Language (for `httpx`)**: `httpx` is a Go-based tool. You'll need Go installed to `go install` it.

### Setup Steps

1.  **Clone the Repository:**
    ```bash
    git clone https://github.com/7ealvivek/one-snap.git
    cd one-snap
    ```

2.  **Install Python Dependencies:**
    It's recommended to use a virtual environment.
    ```bash
    python3 -m venv venv
    source venv/bin/activate # On Windows: .\venv\Scripts\activate
    pip install requests tqdm slack_sdk
    ```
    (You may create a `requirements.txt` file with these dependencies and use `pip install -r requirements.txt` instead.)

3.  **Install `httpx`:**
    `httpx` needs to be installed and available in your system's PATH.
    ```bash
    go install github.com/projectdiscovery/httpx/cmd/httpx@latest
    ```
    *   **Important:** After installation, ensure your Go bin directory (e.g., `~/go/bin` on Linux/macOS, `%USERPROFILE%\go\bin` on Windows) is added to your system's `PATH` environment variable. You might need to restart your terminal for changes to take effect.

---

## Configuration (API Keys & Tokens)

**CRITICAL:** You must replace the placeholder values in the `Constants` section of the `one_snap.py` file with your actual API keys and tokens.

Open `one_snap.py` in a text editor and modify these lines:

```python
# Constants
C99_API_KEY = "hehehe" # <-- REPLACE THIS!
SLACK_TOKEN = "hehehehe" # <-- REPLACE THIS!
SLACK_CHANNEL = "#all-subdomains" # <-- REPLACE THIS with your desired channel, e.g., "#recon-results"
```

*   **C99.nl API Key:** Obtain one from [c99.nl](https://c99.nl/). Free tiers often have usage limits.
*   **Slack Token:**
    1.  Create a Slack App at [api.slack.com/apps](https://api.slack.com/apps).
    2.  Go to "Features" -> "OAuth & Permissions".
    3.  Add "Bot Token Scopes": `files:write`.
    4.  Install the app to your workspace.
    5.  Copy your "Bot User OAuth Token" (starts with `xoxb-`).
    6.  **Invite your app's bot** to the `SLACK_CHANNEL` you configure (e.g., `/invite @your_bot_name` in Slack).

---

## Usage

One Snap offers both a powerful Command Line Interface (CLI) and an intuitive Graphical User Interface (GUI).

### Command Line Interface (CLI)

Navigate to the `one-snap` directory in your terminal and activate your virtual environment (if used):

```bash
cd /path/to/one-snap
source venv/bin/activate # On Windows: .\venv\Scripts\activate
```

**Basic Syntax:**

```bash
python3 one_snap.py [OPTIONS] [PLATFORM_FLAGS]
```

**Common Options:**

*   `--private <path_to_file.txt>`: Path to your text file containing subdomains (one per line). These will be included and enriched.
*   `--slack`: Upload the final subdomain ZIP to Slack.
*   `--rerun-chaos`: Force a full re-download of ALL Chaos Project data. This overrides any platform-specific filtering.
*   `--httpx`: Run `httpx` on the final collected subdomain list to identify live hosts.

**Bounty Platform Flags (Optional - filters Chaos downloads):**

Choose one or more to filter the Chaos data to specific platforms. If none are chosen, all Chaos data is downloaded by default (unless `--rerun-chaos` is used).

*   `-bugcrowd`: Include programs from Bugcrowd.
*   `-h1`: Include programs from HackerOne.
*   `-intigriti`: Include programs from Intigriti.
*   `-yeswehack`: Include programs from YesWeHack.
*   `-hackandproof`: Include programs from HackenProof.

---

**CLI Examples:**

1.  **Full Chaos Download & `httpx` Scan:**
    ```bash
    python3 one_snap.py --rerun-chaos --httpx
    ```
    *(This downloads ALL Chaos data, extracts subdomains, enriches with C99.nl, runs `httpx`, and saves outputs. No Slack upload.)*

2.  **Targeted HackerOne & Bugcrowd Programs with Private List, Upload to Slack:**
    ```bash
    python3 one_snap.py -h1 -bugcrowd --private my_targets.txt --slack
    ```
    *(This downloads Chaos data ONLY for H1 & Bugcrowd, merges with `my_targets.txt`, enriches all with C99.nl, and uploads the final ZIP to Slack.)*

3.  **Just Your Private List (No Public Data, No Chaos Download):**
    ```bash
    python3 one_snap.py --private my_company_scope.txt --httpx
    ```
    *(This processes only your private list, enriches it with C99.nl, runs `httpx`, and saves outputs. No Chaos download or Slack upload.)*

4.  **Force Full Chaos + HackerOne (as explicit additional targets) + HTTPX:**
    ```bash
    python3 one_snap.py --rerun-chaos -h1 --httpx
    ```
    *(`--rerun-chaos` forces a full Chaos download. `-h1` ensures HackerOne roots from the Chaos index are definitely included for C99 enrichment, even if they were covered by the full Chaos download.)*

5.  **View all CLI Options:**
    ```bash
    python3 one_snap.py --help
    ```

---

### Graphical User Interface (GUI)

The GUI provides a user-friendly way to interact with One Snap without using the command line.

1.  **Launch the GUI:**
    ```bash
    python3 one_snap.py
    ```
    *(Ensure `tkinter` is installed and you are in a graphical environment.)*

2.  **GUI Window Breakdown:**
    *   **"Select Private List" Button:** Click to open a file dialog and select your private subdomains `.txt` file. The selected path will be displayed.
    *   **"Upload final ZIP to Slack" Checkbox:** Tick this to enable Slack upload.
    *   **"Force full Chaos data download (ignores platform filter)" Checkbox:** Tick this to enable the `--rerun-chaos` behavior.
    *   **"Run httpx after final list" Checkbox:** Tick this to enable the `httpx` scan.
    *   **"Filter Chaos Data by Bounty Platform" Checkboxes:** Tick one or more of these (e.g., `Hackerone`, `Bugcrowd`) to filter Chaos downloads.
    *   **"Run One Snap" Button:** Click this to start the process with your selected options. Progress messages will be displayed in the terminal where you launched the script. A pop-up will confirm completion or indicate errors.

---

## Understanding the Output

After a successful run, One Snap generates the following files in the script's directory:

*   **`final_allsubs.txt`**:
    *   A plain text file containing the **final, unique, and sorted list of all subdomains** collected from all sources (Chaos, C99.nl, and your private list). Each subdomain is on a new line.
*   **`final_allsubs.zip`**:
    *   A compressed `.zip` archive containing `final_allsubs.txt`. This is the file that would be uploaded to Slack.
*   **`httpx_output.txt`** (if `--httpx` was used):
    *   A text file containing the results from the `httpx` scan. This typically lists live HTTP/S hosts along with their status codes, titles, and other relevant information identified by `httpx`.

**Temporary Files (automatically cleaned up):**

*   `chaos_zips/`: Directory where downloaded Chaos `.zip` files are temporarily stored.
*   `extracted/`: Directory where the contents of Chaos `.zip` files are extracted.
*   `httpx_progress_temp.txt`: A temporary file used to parse `httpx`'s real-time progress (removed after `httpx` completes).

---

## Troubleshooting & Tips

*   **API Keys/Tokens:** Double-check that your `C99_API_KEY` and `SLACK_TOKEN` are correctly placed in the `one_snap.py` file and are valid. Invalid keys will cause related features to fail.
*   **Rate Limits:** C99.nl has rate limits. The script includes pauses (`time.sleep`) to mitigate this. If you frequently hit rate limits, consider:
    *   Waiting longer between runs.
    *   Reducing the `chunk_size` or `max_workers` in `query_c99` (though this might slow down the overall process).
    *   Upgrading your C99.nl plan if applicable.
*   **`httpx` Not Found/Fails:**
    *   Ensure `httpx` is installed correctly (use `go install ...`).
    *   Verify that the Go bin directory is in your system's `PATH`. Run `httpx -h` in your terminal to confirm it's accessible.
    *   Check for permissions issues if `httpx` is installed but won't run.
*   **Empty Output:** If `final_allsubs.txt` is empty, check the console output for error messages or warnings.
    *   Perhaps `fetch_chaos_index()` failed.
    *   Maybe no Chaos data matched your platform filters.
    *   Your private file might be empty or improperly formatted.
*   **Slack Upload Issues:**
    *   Confirm `SLACK_TOKEN` is correct and has `files:write` permissions.
    *   Ensure your bot is invited to the `SLACK_CHANNEL`.
    *   Check if the `final_allsubs.zip` file exceeds Slack's maximum file size (~800MB).
*   **GUI Not Launching:**
    *   Ensure `tkinter` is installed for your Python version. On Debian/Ubuntu, it's often `sudo apt-get install python3-tk`.
    *   Verify you're in a graphical desktop environment.

---

## Contributing

Contributions are welcome! If you have suggestions, bug reports, or want to contribute code, please feel free to:

1.  Open an issue on the GitHub repository.
2.  Fork the repository and submit a pull request.

---

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---

## Author & Credits

Developed by **Vivek Kashyap** | [bugcrowd.com/realvivek](https://bugcrowd.com/realvivek)

Special thanks to:
*   [ProjectDiscovery](https://projectdiscovery.io/) for the amazing Chaos Project and `httpx` tool.
*   [C99.nl](https://c99.nl/) for their valuable subdomain discovery API.

---

<p align="left">
  <strong>Connect with the Author:</strong><br>
  X (Twitter): [@starkcharry](https://x.com/starkcharry)<br>
  Bugcrowd: [bugcrowd.com/realvivek](https://bugcrowd.com/realvivek)<br>
  GitHub: [@7ealvivek](https://github.com/7ealvivek)
</p>

