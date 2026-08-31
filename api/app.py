import os
import re
import traceback
from datetime import datetime

import joblib
from flask import Flask, jsonify, request
from flask_cors import CORS


# ============================================================
# CONFIGURATION
# ============================================================

BASE_DIR = os.path.dirname(
    os.path.dirname(
        os.path.abspath(__file__)
    )
)

MODEL_PATH = os.path.join(
    BASE_DIR,
    "models",
    "logistic_regression_model.pkl"
)

VECTORIZER_PATH = os.path.join(
    BASE_DIR,
    "models",
    "tfidf_vectorizer_final.pkl"
)

URL_MODEL_PATH = os.path.join(
    BASE_DIR,
    "models",
    "url_phishing_model.pkl"
)

URL_FEATURE_NAMES_PATH = os.path.join(
    BASE_DIR,
    "models",
    "url_feature_names.pkl"
)


# ============================================================
# FLASK
# ============================================================

app = Flask(__name__)

CORS(app)


# ============================================================
# MODEL STATE
# ============================================================

model = None
vectorizer = None
url_model = None
url_feature_names = None

MODEL_STATUS = "OFFLINE"
MODEL_ERROR = ""


# ============================================================
# LOAD AI MODELS
# ============================================================

try:

    print("[AI] Loading Logistic Regression...")

    model = joblib.load(
        MODEL_PATH
    )

    print("[AI] Loading TF-IDF...")

    vectorizer = joblib.load(
        VECTORIZER_PATH
    )

    MODEL_STATUS = "ONLINE"

    print("[AI] Main AI engine ONLINE")

except Exception as error:

    MODEL_STATUS = "OFFLINE"

    MODEL_ERROR = (
        f"{type(error).__name__}: {error}"
    )

    print("[AI] MAIN MODEL ERROR")
    print(MODEL_ERROR)

    traceback.print_exc()


# ============================================================
# URL MODEL
# ============================================================

try:

    url_model = joblib.load(
        URL_MODEL_PATH
    )

    print("[AI] URL model loaded")

except Exception as error:

    print("[AI] URL model unavailable:")
    print(error)


try:

    url_feature_names = joblib.load(
        URL_FEATURE_NAMES_PATH
    )

    print("[AI] URL feature names loaded")

except Exception as error:

    print("[AI] URL feature names unavailable:")
    print(error)


# ============================================================
# EMAIL PREDICTION
# ============================================================

def predict_email(text):

    if model is None:

        raise RuntimeError(
            "AI model is not loaded."
        )

    if vectorizer is None:

        raise RuntimeError(
            "TF-IDF vectorizer is not loaded."
        )

    features = vectorizer.transform(
        [text]
    )

    prediction = int(
        model.predict(features)[0]
    )

    confidence = None

    if hasattr(
        model,
        "predict_proba"
    ):

        probabilities = (
            model.predict_proba(features)[0]
        )

        confidence = float(
            max(probabilities) * 100
        )

    if prediction == 1:

        label = "PHISHING"

    else:

        label = "LEGITIMATE"

    return label, confidence


# ============================================================
# THREAT INDICATORS
# ============================================================

URGENT_WORDS = [
    "urgent",
    "immediately",
    "act now",
    "verify now",
    "as soon as possible",
    "account suspended",
    "final warning"
]

CREDENTIAL_WORDS = [
    "password",
    "login",
    "username",
    "otp",
    "one time password",
    "verification code",
    "credential"
]

FINANCIAL_WORDS = [
    "bank",
    "payment",
    "credit card",
    "debit card",
    "invoice",
    "money",
    "transfer",
    "refund"
]

THREAT_WORDS = [
    "suspended",
    "blocked",
    "locked",
    "terminate",
    "security alert",
    "unauthorized"
]


def analyze_threat_indicators(text):

    lower_text = text.lower()

    indicators = []

    risk_score = 0


    if any(
        word in lower_text
        for word in URGENT_WORDS
    ):

        indicators.append({
            "name": "Urgency language",
            "description":
                "The message attempts to create pressure or immediate action.",
            "severity": "MEDIUM"
        })

        risk_score += 1


    if any(
        word in lower_text
        for word in CREDENTIAL_WORDS
    ):

        indicators.append({
            "name": "Credential-related language",
            "description":
                "Login, password, OTP or credential-related terminology was detected.",
            "severity": "HIGH"
        })

        risk_score += 2


    if any(
        word in lower_text
        for word in FINANCIAL_WORDS
    ):

        indicators.append({
            "name": "Financial terminology",
            "description":
                "Banking, payment or financial terminology was detected.",
            "severity": "MEDIUM"
        })

        risk_score += 1


    if any(
        word in lower_text
        for word in THREAT_WORDS
    ):

        indicators.append({
            "name": "Threat language",
            "description":
                "The message contains language associated with account or security threats.",
            "severity": "HIGH"
        })

        risk_score += 2


    urls = re.findall(
        r"https?://[^\s<>\"']+",
        text
    )

    if urls:

        indicators.append({
            "name": "URL detected",
            "description":
                f"{len(urls)} URL(s) detected in the email.",
            "severity": "MEDIUM"
        })

        risk_score += 1


    return indicators, min(
        risk_score,
        7
    )


# ============================================================
# URL ANALYSIS
# ============================================================

def analyze_urls(text):

    urls = re.findall(
        r"https?://[^\s<>\"']+",
        text
    )

    results = []

    for url in urls:

        result = {
            "url": url,
            "risk": "UNKNOWN",
            "score": 0
        }

        # Basic heuristic URL analysis
        lower_url = url.lower()

        score = 0

        if "@" in lower_url:
            score += 2

        if len(url) > 100:
            score += 1

        if "-" in lower_url:
            score += 1

        if any(
            word in lower_url
            for word in [
                "login",
                "verify",
                "secure",
                "account",
                "update",
                "password"
            ]
        ):
            score += 2

        if score >= 4:
            risk = "HIGH"

        elif score >= 2:
            risk = "MEDIUM"

        else:
            risk = "LOW"

        result["score"] = score
        result["risk"] = risk

        results.append(result)


    highest_score = max(
        [item["score"] for item in results],
        default=0
    )

    highest_risk = "NONE"

    if highest_score >= 4:
        highest_risk = "HIGH"

    elif highest_score >= 2:
        highest_risk = "MEDIUM"

    elif highest_score > 0:
        highest_risk = "LOW"


    return {
        "urls": results,
        "total_urls": len(results),
        "highest_score": highest_score,
        "highest_risk": highest_risk
    }


# ============================================================
# HEALTH CHECK
# ============================================================

@app.route(
    "/api/health",
    methods=["GET"]
)
def health():

    return jsonify({
        "status": "OK",
        "service":
            "AI Phishing Detection API",
        "timestamp":
            datetime.now().isoformat(
                timespec="seconds"
            )
    })


# ============================================================
# MODEL STATUS
# ============================================================

@app.route(
    "/api/status",
    methods=["GET"]
)
def status():

    return jsonify({

        "model_status":
            MODEL_STATUS,

        "model_loaded":
            model is not None,

        "vectorizer_loaded":
            vectorizer is not None,

        "url_model_loaded":
            url_model is not None,

        "model_error":
            MODEL_ERROR

    })


# ============================================================
# ANALYZE EMAIL
# ============================================================

@app.route(
    "/api/analyze",
    methods=["POST"]
)
def analyze():

    try:

        data = (
            request.get_json(
                silent=True
            )
            or {}
        )

        text = str(
            data.get(
                "text",
                ""
            )
        ).strip()


        if not text:

            return jsonify({
                "error":
                    "Email text is empty."
            }), 400


        if len(text) > 100000:

            return jsonify({
                "error":
                    "Email is too large."
            }), 400


        # AI prediction

        label, confidence = (
            predict_email(text)
        )


        # Threat indicators

        indicators, risk_score = (
            analyze_threat_indicators(
                text
            )
        )


        # URL analysis

        url_analysis = (
            analyze_urls(text)
        )


        return jsonify({

            "success": True,

            "label":
                label,

            "confidence":
                confidence,

            "indicators":
                indicators,

            "risk_score":
                risk_score,

            "url_analysis":
                url_analysis,

            "character_count":
                len(text),

            "timestamp":
                datetime.now().isoformat(
                    timespec="seconds"
                )

        })


    except Exception as error:

        traceback.print_exc()

        return jsonify({

            "success": False,

            "error":
                str(error),

            "model_status":
                MODEL_STATUS,

            "model_error":
                MODEL_ERROR

        }), 500


# ============================================================
# RUN SERVER
# ============================================================

if __name__ == "__main__":

    print()
    print("=" * 60)
    print("AI PHISHING DETECTION API")
    print("=" * 60)
    print(
        "MODEL STATUS:",
        MODEL_STATUS
    )
    print("=" * 60)
    print()

    app.run(
        host="127.0.0.1",
        port=5000,
        debug=True
    )