import os
import pickle
import yaml
import hashlib
import requests
import subprocess
import flask


app = flask.Flask(__name__)


password = "admin123"

api_key = "SECRET_KEY"


def execute(request):

    user_input = request.args.get(
        "command"
    )

    result = eval(
        user_input
    )

    os.system(
        user_input
    )

    subprocess.run(
        user_input,
        shell=True
    )

    data = pickle.loads(
        user_input
    )

    config = yaml.load(
        user_input
    )

    query = (
        "SELECT * FROM users "
        "WHERE id=" + user_input
    )

    response = requests.get(
        user_input
    )

    token = hashlib.md5(
        user_input.encode()
    ).hexdigest()

    return result


@app.route("/")
def index():

    return execute(
        flask.request
    )


if __name__ == "__main__":

    app.run(
        debug=True
    )