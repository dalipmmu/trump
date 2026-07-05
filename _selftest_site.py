"""Local test site + project that intentionally exposes secrets, for self-test."""
import os
from flask import Flask, Response

app = Flask(__name__)

@app.route("/")
def home():
    return Response("""<html><head>
      <script src="/static/app.js"></script>
      <script>var cfg={api_key:"sk-proj-ABCDEFGHIJKLMNOPQRSTUVWX1234567890"};</script>
    </head><body>hello <a href="/page2">page two</a></body></html>""",
    mimetype="text/html")

@app.route("/page2")
def page2():
    return Response("""<html><body>page two
      <script>var stripe="sk_live_aBcDeFgHiJkLmNoPqRsTuVwX";</script>
    </body></html>""", mimetype="text/html")

@app.route("/static/app.js")
def appjs():
    js = ('console.log("app");//# sourceMappingURL=/static/app.js.map')
    return Response(js, mimetype="application/javascript")

@app.route("/static/app.js.map")
def appmap():
    m = ('{"version":3,"sources":["src/config.js"],'
         '"sourcesContent":["const AWS=\\"AKIAIOSFODNN7EXAMPLE\\";'
         'const token=\\"ghp_aBcDeFgHiJkLmNoPqRsTuVwXyZ0123456789\\";"],'
         '"mappings":"AAAA"}')
    return Response(m, mimetype="application/json")

@app.route("/.env")
def env():
    return Response("DB_PASSWORD=supersecret123\nSTRIPE_KEY=sk_live_abcdEFGH1234567890xyz\n",
                    mimetype="text/plain")

if __name__ == "__main__":
    app.run(port=8077)
