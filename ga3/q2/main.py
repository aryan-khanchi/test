import os
import re
import base64
import binascii
import logging

from flask import Flask, request, jsonify
from flask_cors import CORS
from google import genai
from google.genai import types

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = Flask(__name__)
CORS(app)  # allow all origins so the grader's Cloudflare Worker can call this

client = genai.Client(api_key=os.environ.get("GEMINI_API_KEY"))

SYSTEM_PROMPT = (
    "You are a precise document/chart/table reading assistant. "
    "You will be given an image (a scanned document, receipt, invoice, table, "
    "or chart) and a question about it. "
    "Read the image carefully and answer the question. "
    "Rules for your answer:\n"
    "1. Reply with ONLY the answer value, nothing else — no explanation, "
    "no restated question, no extra words.\n"
    "2. If the answer is numeric, return ONLY the number "
    "(e.g. '4089.35'), with no currency symbols, commas, units, or %.\n"
    "3. If the answer is text, return the exact text/label as it appears.\n"
)


def normalize_numeric(text: str) -> str:
    """If the answer is basically a number, strip stray currency/unit junk."""
    stripped = text.strip()
    match = re.fullmatch(r"[^\d\-]*(-?\d[\d,]*\.?\d*)[^\d]*", stripped)
    if match:
        return match.group(1).replace(",", "")
    return stripped


def guess_mime(image_bytes: bytes) -> str:
    if image_bytes[:8] == b"\x89PNG\r\n\x1a\n":
        return "image/png"
    if image_bytes[:3] == b"\xff\xd8\xff":
        return "image/jpeg"
    if image_bytes[:6] in (b"GIF87a", b"GIF89a"):
        return "image/gif"
    if image_bytes[:4] == b"RIFF" and image_bytes[8:12] == b"WEBP":
        return "image/webp"
    return "image/png"  # sane default


@app.route("/answer-image", methods=["POST"])
def answer_image():
    data = request.get_json(silent=True) or {}
    image_b64 = data.get("image_base64")
    question = data.get("question")

    if not image_b64 or not question:
        return jsonify({"answer": ""}), 400

    # Strip a data URL prefix if the client sent one anyway
    if "," in image_b64 and image_b64.strip().lower().startswith("data:"):
        image_b64 = image_b64.split(",", 1)[1]

    try:
        image_bytes = base64.b64decode(image_b64, validate=False)
    except (binascii.Error, ValueError):
        return jsonify({"answer": ""}), 400

    mime = guess_mime(image_bytes)

    try:
        response = client.models.generate_content(
            model="gemini-2.0-flash",
            contents=[
                types.Part.from_bytes(data=image_bytes, mime_type=mime),
                f"{SYSTEM_PROMPT}\n\nQuestion: {question}",
            ],
            config=types.GenerateContentConfig(temperature=0),
        )
        raw_answer = response.text.strip()
    except Exception as e:
        logger.exception("Gemini call failed")
        return jsonify({"answer": "", "error": str(e)}), 500

    final_answer = normalize_numeric(raw_answer)
    return jsonify({"answer": final_answer})


@app.route("/", methods=["GET"])
def health():
    return jsonify({"status": "ok"})


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 5000)))
