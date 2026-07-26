from flask import Flask, request, jsonify

app = Flask(__name__)

@app.route("/prorate", methods=["POST"])
def prorate():
    data = request.get_json()

    old_price = data["old_price"]
    new_price = data["new_price"]
    days_remaining = data["days_remaining"]
    days_in_actual_month = data["days_in_actual_month"]
    spec = data["spec"]  # "v1" or "v2"

    if spec == "v1":
        divisor = 30
    elif spec == "v2":
        divisor = days_in_actual_month
    else:
        return jsonify({"error": "spec must be 'v1' or 'v2'"}), 400

    charge = (new_price - old_price) * (days_remaining / divisor)

    return jsonify({"charge": charge})

if __name__ == "__main__":
    # For local testing only
    app.run(host="0.0.0.0", port=5000, debug=True)
