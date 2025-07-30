from flask import Flask, render_template
import json

app = Flask(__name__)

@app.route("/")
def index():
  try:
    with open("lan_snapshot.json") as f:
      data = json.load(f)
  except FileNotFoundError:
    data = []
  return render_template("index.html", devices=data)


if __name__ == "__main__":
  app.run(debug=True, post=5000)