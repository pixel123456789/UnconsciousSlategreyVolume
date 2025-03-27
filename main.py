from flask import Flask
from flask import templates
app = Flask(__name__)


@app.route('/')
def index():
    template.render("")

if __name__ == '__main__':
  app.run(host='0.0.0.0', port=5000)
