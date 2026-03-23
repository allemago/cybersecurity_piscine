import pymysql
from flask import Flask, request

app = Flask(__name__)

DB_CONFIG = {
    "host": "localhost",
    "user": "test",
    "password": "",
    "database": "testdb",
}


def init_db():
    con = pymysql.connect(**DB_CONFIG)
    cur = con.cursor()
    cur.execute(
        "CREATE TABLE IF NOT EXISTS users "
        "(id INT PRIMARY KEY, username VARCHAR(50), password VARCHAR(50))"
    )
    cur.execute("INSERT IGNORE INTO users VALUES (1, 'admin', 'secret123')")
    cur.execute("INSERT IGNORE INTO users VALUES (2, 'user', 'pass456')")
    con.commit()
    con.close()


init_db()


@app.route('/')
def index():
    return '''
    <html><body>
    <form method="post" action="/login">
        <input type="text" name="username" value="">
        <input type="password" name="password" value="">
        <input type="submit" value="Login">
    </form>
    </body></html>
    '''


@app.route('/login', methods=['POST'])
def login():
    username = request.form.get('username', '')
    con = pymysql.connect(**DB_CONFIG)
    cur = con.cursor()
    cur.execute(f"SELECT * FROM users WHERE username='{username}'")
    return str(cur.fetchall())


@app.route('/search')
def search():
    q = request.args.get('q', '')
    con = pymysql.connect(**DB_CONFIG)
    cur = con.cursor()
    cur.execute(f"SELECT * FROM users WHERE username='{q}'")
    return str(cur.fetchall())


def run():
    app.run(debug=True)
