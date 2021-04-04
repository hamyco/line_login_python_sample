from flask import Flask, render_template
app = Flask(__name__)


@app.route('/')
def homepage():
    name = "Hello World"
    return render_template('index.html', title='flask test', name=name)


@app.route('/gotoauthpage')
def good():
    name = "Good"
    return name


if __name__ == "__main__":
    app.run(debug=True)