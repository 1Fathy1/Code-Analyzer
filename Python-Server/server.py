from flask import Flask, request, jsonify
from analyzer import SecurityAnalyzer
import ast
import os

app = Flask(__name__)


# ✅ analyzer function
def analyze_code(code, mode="all"):
    tree = ast.parse(code)
    analyzer = SecurityAnalyzer(mode=mode)
    analyzer.visit(tree)
    return analyzer.vulnerabilities


# ✅ API endpoint
@app.route("/api/v1/py/analyze", methods=["POST"])
def analyze():

    data = request.json

    code = data.get("code", "")
    mode = data.get("mode", "all")

    try:
        result = analyze_code(code, mode)

        return jsonify({
            "status": "success",
            "vulnerabilities": result
        })

    except Exception as e:
        return jsonify({
            "status": "error",
            "message": str(e)
        })

if __name__ == "__main__":
    app.run(
        host="0.0.0.0",
        port=int(os.environ.get("PORT", 5000))
    )
