import os, json, hashlib, time

CHAIN_FILE = os.path.join("logs", "chain.log")
os.makedirs("logs", exist_ok=True)

def _sha256(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()

def append_event(level: str, message: str):
    """Append a log entry with hash chaining for tamper detection."""
    prev_hash = ""
    if os.path.exists(CHAIN_FILE):
        try:
            with open(CHAIN_FILE, "r") as f:
                lines = [l.strip() for l in f if l.strip()]
                if lines:
                    last = json.loads(lines[-1])
                    prev_hash = last.get("entry_hash", "")
        except Exception:
            prev_hash = ""

    timestamp = time.strftime("%Y-%m-%dT%H:%M:%S%z")
    entry = {"ts": timestamp, "level": level, "msg": message, "prev_hash": prev_hash}
    blob = json.dumps(entry, sort_keys=True).encode()
    entry_hash = _sha256(blob)
    entry["entry_hash"] = entry_hash

    with open(CHAIN_FILE, "a") as fw:
        fw.write(json.dumps(entry) + "\n")

    return entry_hash

def verify_chain() -> bool:
    """Verify all entries form a valid chain."""
    if not os.path.exists(CHAIN_FILE):
        return True
    prev = ""
    with open(CHAIN_FILE, "r") as f:
        for line in f:
            entry = json.loads(line)
            if entry.get("prev_hash") != prev:
                return False
            blob = json.dumps({k: entry[k] for k in entry if k != "entry_hash"}, sort_keys=True).encode()
            if _sha256(blob) != entry["entry_hash"]:
                return False
            prev = entry["entry_hash"]
    return True
