import sqlite3
import secrets
import yaml


def get_user(user_id):

    connection = sqlite3.connect(
        "users.db"
    )

    cursor = connection.cursor()

    cursor.execute(
        "SELECT * FROM users WHERE id = ?",
        (user_id,)
    )

    return cursor.fetchone()


def generate_token():

    return secrets.token_urlsafe(
        32
    )


def load_config(data):

    return yaml.safe_load(
        data
    )