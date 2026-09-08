"""
QRShield - Offline QR Code Safety Scanner
-------------------------------------------
data.py

This single file contains the entire backend:
1. Flask app setup (serves index.html and style.css from this same folder)
2. Offline QR code decoding (OpenCV + pyzbar)
3. Rule-based offline security analysis
4. The /scan route that ties it all together and returns JSON

Everything runs 100% locally. No external API calls are made.
"""

import os
import re

try:
    import cv2  # type: ignore[reportMissingImports]
except ImportError:
    cv2 = None

try:
    from PIL import Image  # type: ignore[reportMissingImports]
except ImportError:
    Image = None

from flask import Flask, render_template, request, jsonify  # type: ignore[reportMissingImports]
from werkzeug.utils import secure_filename  # type: ignore[reportMissingImports]

try:
    from pyzbar.pyzbar import decode as pyzbar_decode  # type: ignore[reportMissingImports]
except Exception:  # pragma: no cover - depends on local environment
    pyzbar_decode = None

# ------------------------------------------------------------------
# Flask app setup
# template_folder="." and static_folder="." let index.html and
# style.css live right next to this file, instead of needing
# separate templates/ and static/ folders.
# ------------------------------------------------------------------
app = Flask(__name__, template_folder=".", static_folder=".", static_url_path="")

# Folder where uploaded QR images are temporarily saved
UPLOAD_FOLDER = "uploads"
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER

# Only these file types are allowed to be uploaded
ALLOWED_EXTENSIONS = {"png", "jpg", "jpeg", "bmp", "webp"}


def allowed_file(filename):
    """Check if the uploaded file has an allowed image extension."""
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS


# ------------------------------------------------------------------
# Lists used for rule-based offline analysis
# (No internet / API lookups - everything is checked against these
# fixed lists using simple Python string logic.)
# ------------------------------------------------------------------

# Common URL shortener domains often abused to hide the real destination
URL_SHORTENERS = [
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "is.gd",
    "cutt.ly", "tiny.one", "rebrandly.com", "shorte.st", "ow.ly"
]

# Words commonly found in phishing / fake login pages
FAKE_LOGIN_KEYWORDS = [
    "login", "signin", "sign-in", "verify", "update", "secure",
    "bank", "account", "wallet", "paypal", "otp", "password",
    "authentication", "confirm", "billing", "unlock"
]

# Dangerous executable / archive file extensions that may indicate malware
EXECUTABLE_EXTENSIONS = [
    ".exe", ".apk", ".bat", ".scr", ".cmd", ".msi", ".zip", ".rar"
]


# ------------------------------------------------------------------
# QR Type Detection
# ------------------------------------------------------------------
def detect_qr_type(data):
    """
    Look at the decoded text and guess what kind of QR code it is.
    This is simple pattern matching - no external services used.
    """
    text = data.strip()
    lower_text = text.lower()

    if lower_text.startswith("wifi:"):
        return "WiFi"
    if lower_text.startswith("mailto:"):
        return "Email"
    if lower_text.startswith("tel:"):
        return "Phone Number"
    if lower_text.startswith("smsto:") or lower_text.startswith("sms:"):
        return "SMS"
    if lower_text.startswith("begin:vcard"):
        return "Contact Card"
    if lower_text.startswith("http://") or lower_text.startswith("https://"):
        return "URL"
    return "Plain Text"


# ------------------------------------------------------------------
# Helper checks used inside the risk analysis
# ------------------------------------------------------------------
def is_ip_address_url(url):
    """Check if the URL's host is a raw IP address instead of a domain name."""
    ip_pattern = r"https?://(\d{1,3}\.){3}\d{1,3}"
    return re.match(ip_pattern, url) is not None


def contains_shortener(url):
    """Check if the URL uses a known link-shortening service."""
    return any(shortener in url.lower() for shortener in URL_SHORTENERS)


def contains_fake_login_keywords(url):
    """Check if the URL text contains common phishing-related keywords."""
    lower_url = url.lower()
    return [word for word in FAKE_LOGIN_KEYWORDS if word in lower_url]


def contains_executable_extension(url):
    """Check if the URL points to a potentially dangerous downloadable file."""
    lower_url = url.lower()
    return [ext for ext in EXECUTABLE_EXTENSIONS if lower_url.endswith(ext)]


def count_special_characters(url):
    """Count unusual special characters that are often used to obfuscate links."""
    special_chars = re.findall(r"[^a-zA-Z0-9:/.\-_]", url)
    return len(special_chars)


def looks_like_random_string(url):
    """
    Roughly guess if the URL path contains a randomly generated string
    (long block of letters/numbers with no vowels or clear words).
    This is a simple heuristic, not a perfect detector.
    """
    match = re.search(r"https?://[^/]+/([^\s?#]+)", url)
    if not match:
        return False
    path = match.group(1)
    chunks = re.split(r"[/\-_.]", path)
    for chunk in chunks:
        if len(chunk) >= 12:
            vowels = sum(1 for c in chunk.lower() if c in "aeiou")
            if vowels / max(len(chunk), 1) < 0.15:
                return True
    return False


# ------------------------------------------------------------------
# Main Risk Analysis Function
# ------------------------------------------------------------------
def analyze_content(data):
    """
    Perform offline, rule-based security analysis on the decoded QR content.
    Returns a dictionary with the score, status, reasons, and recommendation.
    """
    reasons = []
    score = 0
    qr_type = detect_qr_type(data)
    detected_url = None

    if qr_type == "URL":
        detected_url = data.strip()
        url = detected_url

        # 1. HTTP vs HTTPS
        if url.lower().startswith("http://"):
            score += 10
            reasons.append("Link uses insecure HTTP instead of HTTPS (+10)")
        else:
            reasons.append("Link uses secure HTTPS (+0)")

        # 2. URL Shortener
        if contains_shortener(url):
            score += 25
            reasons.append("Link uses a URL shortening service, real destination is hidden (+25)")

        # 3. IP address instead of domain name
        if is_ip_address_url(url):
            score += 30
            reasons.append("Link points directly to an IP address instead of a domain (+30)")

        # 4. Executable / dangerous file download
        exe_hits = contains_executable_extension(url)
        if exe_hits:
            score += 40
            reasons.append(f"Link points to a potentially dangerous file type: {', '.join(exe_hits)} (+40)")

        # 5. Long URL
        if len(url) > 75:
            score += 15
            reasons.append("Link is unusually long (+15)")

        # 6. Too many special characters
        special_count = count_special_characters(url)
        if special_count > 5:
            score += 10
            reasons.append(f"Link contains {special_count} unusual special characters (+10)")

        # 7. Random-looking string in the path
        if looks_like_random_string(url):
            score += 10
            reasons.append("Link contains a random-looking generated string (+10)")

        # 8. Fake login / phishing keywords
        keyword_hits = contains_fake_login_keywords(url)
        if keyword_hits:
            score += 20
            reasons.append(f"Link contains suspicious keywords: {', '.join(keyword_hits)} (+20)")

    else:
        reasons.append(f"QR code contains {qr_type} data, not a direct web link (+0)")

    # ------------------------------------------------------------------
    # Classify the final score into Safe / Suspicious / Malicious
    # ------------------------------------------------------------------
    if score <= 20:
        status = "Safe"
        threat_level = "Low"
        recommendation = "This QR code appears safe."
    elif score <= 50:
        status = "Suspicious"
        threat_level = "Medium"
        recommendation = "Proceed carefully before opening."
    else:
        status = "Malicious"
        threat_level = "High"
        recommendation = "Do NOT open this QR code."

    return {
        "decoded_content": data,
        "detected_url": detected_url,
        "qr_type": qr_type,
        "risk_score": score,
        "status": status,
        "threat_level": threat_level,
        "reasons": reasons,
        "recommendation": recommendation,
    }


# ------------------------------------------------------------------
# Routes
# ------------------------------------------------------------------
@app.route("/")
def home():
    """Render the single-page frontend."""
    return render_template("index.html")


@app.route("/scan", methods=["POST"])
def scan():
    """
    Receive an uploaded QR image, decode it offline, analyze it,
    and return the results as JSON.
    """
    try:
        if "qr_image" not in request.files:
            return jsonify({"error": "No image uploaded."}), 400

        file = request.files["qr_image"]

        if file.filename == "":
            return jsonify({"error": "No image selected."}), 400

        if not allowed_file(file.filename):
            return jsonify({"error": "Unsupported file type. Please upload a PNG or JPG image."}), 400

        filename = secure_filename(file.filename)
        filepath = os.path.join(app.config["UPLOAD_FOLDER"], filename)
        file.save(filepath)

        image = None
        if cv2 is not None:
            image = cv2.imread(filepath)

        if image is None and Image is not None:
            try:
                image = Image.open(filepath)
            except Exception:
                image = None

        if image is None:
            os.remove(filepath)
            if cv2 is None and Image is None:
                return jsonify(
                    {
                        "error": "Server missing image library.",
                        "reason": "Install opencv-python or Pillow.",
                    }
                ), 500
            return jsonify({"error": "Invalid QR Code", "reason": "Cannot decode image."}), 400

        if pyzbar_decode is None:
            os.remove(filepath)
            return jsonify(
                {
                    "error": "QR decoding library unavailable.",
                    "reason": "Install pyzbar and its native libraries to decode uploaded images on the server.",
                }
            ), 500

        decoded_objects = pyzbar_decode(image)

        os.remove(filepath)

        if not decoded_objects:
            return jsonify({"error": "Invalid QR Code", "reason": "Cannot decode image."}), 400

        qr_data = decoded_objects[0].data.decode("utf-8", errors="ignore")

        if not qr_data:
            return jsonify({"error": "Invalid QR Code", "reason": "Cannot decode image."}), 400

        result = analyze_content(qr_data)

        return jsonify(result), 200

    except Exception as e:
        return jsonify({"error": "Something went wrong on the server.", "reason": str(e)}), 500


# ------------------------------------------------------------------
# Run the app
# ------------------------------------------------------------------
if __name__ == "__main__":
    app.run(debug=True)