import json

def identify_hash_type(hash_value):
    if len(hash_value) == 32:
        return "MD5"
    elif len(hash_value) == 40:
        return "SHA1"
    elif len(hash_value) == 64:
        return "SHA256"
    else:
        return "Unknown"

def check_hash(hash_value):
    with open("database/malicious_hashes.json") as f:
        db = json.load(f)

    hash_type = identify_hash_type(hash_value)

    if hash_value in db:
        return {
            "indicator": hash_value,
            "indicator_type": "Hash",
            "hash_type": hash_type,
            "status": "Malicious",
            "threat_type": db[hash_value]["type"],
            "risk_score": db[hash_value]["score"]
        }
    else:
        return {
            "indicator": hash_value,
            "indicator_type": "Hash",
            "hash_type": hash_type,
            "status": "Clean",
            "risk_score": 0
        }
