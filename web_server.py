from flask import Flask, render_template
import json

app = Flask(__name__)

@app.route("/")
def index():
  try:
    with open("lan_snapshot.json") as f:
      data = json.load(f)
  except FileNotFoundError:
    print("❌ lan_snapshot.json not found")
    data = []
  except json.JSONDecodeError as e:
    print("❌ JSON Decode Error:", e)
    data = []
  return render_template("index.html", devices=data)


if __name__ == "__main__":
  app.run(debug=True, port=5000)