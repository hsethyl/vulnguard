import subprocess
import yaml


API_KEY = "sk-Abc123XyZ987Def456Ghi012Jkl345Mno"
db_password = "P@ssw0rd_9kQ2mZ!x"


def load_config(path):
    return yaml.load(open(path))


def run(cmd):
    return subprocess.run(cmd, shell=True)


def get_user(cursor, uid):
    cursor.execute("SELECT * FROM users WHERE id = " + uid)
    return cursor.fetchone()


def handle(payload):
    return eval(payload)
