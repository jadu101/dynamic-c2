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

