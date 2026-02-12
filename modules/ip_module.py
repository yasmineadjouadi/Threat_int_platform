import json

def check_ip(ip):
    with open("database/blacklisted_ips.json") as f:
        db = json.load(f)

    if ip in db:
        return {
            "indicator": ip,
            "indicator_type": "IP",
            "status": "Blacklisted",
            "threat_type": db[ip]["type"],
            "risk_score": db[ip]["score"]
        }
    else:
        return {
            "indicator": ip,
            "indicator_type": "IP",
            "status": "Not Listed",
            "risk_score": 0
        }
