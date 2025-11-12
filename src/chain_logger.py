import os
import json
import hashlib
from datetime import datetime

CHAIN_LOG_FILE = "logs/chain.log"

def _get_last_hash():
    if not os.path.exists(CHAIN_LOG_FILE):
        return "0" * 64  # genesis hash
    with open(CHAIN_LOG_FILE, "r") as f:
        lines = f.readlines()
        if not lines:
            return "0" * 64
        last_entry = json.loads(lines[-1])
        return last_entry["hash"]

def append_event(level, message):
    os.makedirs("logs", exist_ok=True)
    last_hash = _get_last_hash()
    timestamp = datetime.utcnow().isoformat()
    data = f"{last_hash}|{timestamp}|{level}|{message}"
    new_hash = hashlib.sha256(data.encode()).hexdigest()

    entry = {
        "timestamp": timestamp,
        "level": level,
        "message": message,
        "prev_hash": last_hash,
        "hash": new_hash
    }

    with open(CHAIN_LOG_FILE, "a") as f:
        f.write(json.dumps(entry) + "\n")

def verify_chain():
    """Verify the entire chain log for tampering."""
    if not os.path.exists(CHAIN_LOG_FILE):
        return True, "Chain log file not found (fresh system)."

    with open(CHAIN_LOG_FILE, "r") as f:
        lines = f.readlines()

    prev_hash = "0" * 64
    for i, line in enumerate(lines, start=1):
        try:
            entry = json.loads(line)
        except json.JSONDecodeError:
            return False, f"Corrupted JSON at line {i}"

        data = f"{entry['prev_hash']}|{entry['timestamp']}|{entry['level']}|{entry['message']}"
        expected_hash = hashlib.sha256(data.encode()).hexdigest()

        if entry["prev_hash"] != prev_hash:
            return False, f"Broken chain at entry {i} (prev_hash mismatch)"
        if entry["hash"] != expected_hash:
            return False, f"Tampering detected at entry {i} (hash mismatch)"

        prev_hash = entry["hash"]

    return True, f"Chain verified: {len(lines)} entries, no tampering detected."