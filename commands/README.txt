ANDISCAN JSON Split
-------------------
This folder contains one JSON per category. Each file is a valid payload for --json.

Example usage:
  python3 andiscan.py --json /path/to/one_of_these.json

Or to run ALL categories (bash example):
  for j in /path/to/this/folder/*.json; do
    echo "Running: $j"
    python3 andiscan.py --json "$j" --out android_audit_output
  done
