from flask import Flask, request, jsonify
from modules.hash_module import check_hash
from modules.ip_module import check_ip

app = Flask(__name__)

@app.route("/")
def home():
    return "Threat Intelligence Platform is running 🚀"

def detect_type(indicator):
    if "." in indicator and indicator.count(".") == 3:
        return "IP"
    elif len(indicator) in [32, 40, 64]:
        return "Hash"
    else:
        return "Unknown"

@app.route("/analyze", methods=["POST"])
def analyze():
    data = request.json
    indicator = data.get("indicator")

    indicator_type = detect_type(indicator)

    if indicator_type == "Hash":
        result = check_hash(indicator)
    elif indicator_type == "IP":
        result = check_ip(indicator)
    else:
        return jsonify({"error": "Unsupported indicator type"}), 400

    return jsonify(result)

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
