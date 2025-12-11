from flask import Flask, request, jsonify
import hashlib, requests, math
from flask_cors import CORS

app = Flask(__name__)
CORS(app)

def calculate_entropy(password):
    charset = 0
    if any(c.islower() for c in password): charset += 26
    if any(c.isupper() for c in password): charset += 26
    if any(c.isdigit() for c in password): charset += 10
    if any(c in "!@#$%^&*()-_=+[]{}|;:,.<>/?`~" for c in password): charset += 32
    if charset == 0:
        return 0
    return round(len(password) * math.log2(charset), 2)

def check_breach(password):
    sha1 = hashlib.sha1(password.encode("utf-8")).hexdigest().upper()
    prefix = sha1[:5]
    suffix = sha1[5:]
    url = f"https://api.pwnedpasswords.com/range/{prefix}"
    res = requests.get(url)
    if res.status_code != 200:
        return 0
    for line in res.text.splitlines():
        h, cnt = line.split(":")
        if h == suffix:
            return int(cnt)
    return 0

@app.route("/api/check", methods=["POST"])
def check_password():
    data = request.get_json() or {}
    password = data.get("password", "")

    entropy = calculate_entropy(password)
    breached = check_breach(password)

    if entropy < 28:
        strength = "Very Weak"
    elif entropy < 36:
        strength = "Weak"
    elif entropy < 60:
        strength = "Medium"
    elif entropy < 128:
        strength = "Strong"
    else:
        strength = "Very Strong"

    return jsonify({
        "entropy": entropy,
        "strength": strength,
        "breached": breached
    })

@app.route("/", methods=["GET"])
def home():
    return "Password Security API is running"

if __name__ == "__main__":

    app.run(host="0.0.0.0", port=10000)
