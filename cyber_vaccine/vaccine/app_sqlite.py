import sqlite3

from flask import Flask, request

app = Flask(__name__)


def init_db():
    con = sqlite3.connect('test.db')
    con.execute(
        "CREATE TABLE IF NOT EXISTS users "
        "(id, username, password, email)"
    )
    con.execute(
        "CREATE TABLE IF NOT EXISTS products "
        "(id, name, price, category)"
    )
    con.execute(
        "INSERT OR IGNORE INTO users VALUES "
        "(1, 'admin', 'secret123', 'admin@test.com')"
    )
    con.execute(
        "INSERT OR IGNORE INTO users VALUES "
        "(2, 'user', 'pass456', 'user@test.com')"
    )
    con.execute(
        "INSERT OR IGNORE INTO products VALUES "
        "(1, 'apple', '1.50', 'fruit')"
    )
    con.execute(
        "INSERT OR IGNORE INTO products VALUES "
        "(2, 'banana', '0.99', 'fruit')"
    )
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
    con = sqlite3.connect('test.db')
    cur = con.execute(f"SELECT * FROM users WHERE username='{username}'")
    return str(cur.fetchall())


@app.route('/search')
def search():
    q = request.args.get('q', '')
    con = sqlite3.connect('test.db')
    cur = con.execute(f"SELECT * FROM users WHERE username='{q}'")
    return str(cur.fetchall())


def run():
    app.run(debug=True)
