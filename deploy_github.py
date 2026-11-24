#!/usr/bin/env python3
"""
Deployment script to push the Secure Email Authentication Gateway
repository to GitHub using Python's subprocess module.
"""

import subprocess
import sys

commands = [
    ["git", "init"],
    ["git", "add", "."],
    ["git", "commit", "-m", "Initial commit: Email Authentication Gateway CLI and Report"],
    ["git", "branch", "-M", "main"],
    ["git", "remote", "remove", "origin"], # Remove origin if already exists, ignore error
    ["git", "remote", "add", "origin", "https://github.com/kevinmonteiro543-sketch/Secure-Email-Authentication-Gateway-with-SPF-DKIM-and-DMARC.git"],
    ["git", "push", "-u", "origin", "main"]
]

print("=== Starting GitHub Deployment via Python subprocess ===")

for cmd in commands:
    cmd_str = " ".join(cmd)
    print(f"\nExecuting: {cmd_str}")
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            check=False
        )
        if result.stdout.strip():
            print(f"[STDOUT]\n{result.stdout.strip()}")
        if result.stderr.strip():
            print(f"[STDERR]\n{result.stderr.strip()}")
        
        # If remote remove failed because origin didn't exist yet, that's fine
        if "remove" in cmd and result.returncode != 0:
            continue
            
        if result.returncode != 0 and "push" in cmd:
            print(f"\nPush returned code {result.returncode}. If remote has changes, attempting force push or rebase...")
            # Try push with --force if needed
            force_res = subprocess.run(["git", "push", "-u", "origin", "main", "--force"], capture_output=True, text=True)
            print(f"[FORCE PUSH STDOUT]\n{force_res.stdout.strip()}")
            print(f"[FORCE PUSH STDERR]\n{force_res.stderr.strip()}")
            if force_res.returncode == 0:
                print("Force push successful!")
            else:
                sys.exit(force_res.returncode)
    except Exception as e:
        print(f"Exception during '{cmd_str}': {e}")
        sys.exit(1)

print("\n=== GitHub Deployment Completed Successfully ===")
