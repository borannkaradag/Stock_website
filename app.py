import os
from datetime import datetime


from cs50 import SQL
from flask import Flask, flash, redirect, render_template, request, session
from flask_session import Session
from werkzeug.security import check_password_hash, generate_password_hash

from helpers import apology, login_required, lookup, usd

# Configure application
app = Flask(__name__)

# Custom filter
app.jinja_env.filters["usd"] = usd

# Configure session to use filesystem (instead of signed cookies)
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

# Configure CS50 Library to use SQLite database
db = SQL("sqlite:///finance.db")


@app.after_request
def after_request(response):
    """Ensure responses aren't cached"""
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Expires"] = 0
    response.headers["Pragma"] = "no-cache"
    return response


@app.route("/")
@login_required
def index():
    if request.method == 'GET':
        user_portfolio = db.execute('SELECT * from portfolio where Person_ID = ?', session['user_id'])
        prices = {}
        for i in user_portfolio:
            prices[i['Stock']] = lookup(i['Stock'])['price']
        return render_template ('main.html', user_portfolio =  user_portfolio, prices = prices)


@app.route("/buy", methods=["GET", "POST"])
@login_required
def buy():
    if request.method == 'GET':
        return render_template('buy.html')
    """Buy shares of stock"""
    if request.method == 'POST':
        symbol = request.form.get('symbol').upper().strip()
        share = request.form.get('share')
        the_stock_data = lookup(symbol)
        if not the_stock_data:
            return apology("The stock couldn't found")
        if not share.isdigit() or int(share) < 0:
            return apology("Invalid amount")
        share = int(share)
        user = db.execute('SELECT * from users where id = ?', session['user_id'])[0]
        if share * lookup(symbol)['price'] <= user['cash']:
            new_balance = user['cash'] - share * lookup(symbol)['price']
            db.execute ('UPDATE users SET cash = ? where id = ?', new_balance ,session['user_id'])
            user_portfolio = db.execute('SELECT * from portfolio where Person_ID = ? and Stock = ? ', session['user_id'], symbol)
            if not user_portfolio:
                db.execute('INSERT INTO portfolio (Person_ID, Stock, Stock_amount) VALUES (?, ?, ?) ', session['user_id'], symbol, share)
            else:
                db.execute('UPDATE portfolio SET Stock_amount = ? WHERE Person_ID = ? AND Stock = ?', db.execute('SELECT Stock_amount from portfolio where Person_ID = ? and Stock = ? ', session['user_id'], symbol)[0]['Stock_amount'] + share, session['user_id'], symbol)
            db.execute('INSERT INTO stock_transactions (user_id, symbol, quantity, price, timestamp) VALUES (?, ?, ?, ?, ?)', session['user_id'], symbol, share, the_stock_data['price'], datetime.now())
            return apology("Successfully You've purchased the stock")
        else:
            return apology("Insufficient balance")


@app.route("/history")
@login_required
def history():
    if request.method == 'GET':
        data = db.execute('SELECT * FROM stock_transactions where user_id = ?', session['user_id'])
        return render_template('history.html', history = data)
    return apology("TODO")


@app.route("/login", methods=["GET", "POST"])
def login():
    """Log user in"""

    # Forget any user_id
    session.clear()

    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":
        # Ensure username was submitted
        if not request.form.get("username"):
            return apology("must provide username", 403)

        # Ensure password was submitted
        elif not request.form.get("password"):
            return apology("must provide password", 403)

        # Query database for username
        rows = db.execute(
            "SELECT * FROM users WHERE username = ?", request.form.get("username")
        )

        # Ensure username exists and password is correct
        if len(rows) != 1 or not check_password_hash(
            rows[0]["hash"], request.form.get("password")
        ):
            return apology("invalid username and/or password", 403)

        # Remember which user has logged in
        session["user_id"] = rows[0]["id"]

        # Redirect user to home page
        return redirect("/")

    # User reached route via GET (as by clicking a link or via redirect)
    else:
        return render_template("login.html")


@app.route("/logout")
def logout():
    """Log user out"""

    # Forget any user_id
    session.clear()

    # Redirect user to login form
    return redirect("/")


@app.route("/quote", methods=["GET", "POST"])
@login_required
def quote():
    """Get stock quote."""
    if request.method == 'GET':
        return render_template('quote.html')
    if request.method == 'POST':
        data = request.form.get('symbol')
        retrieved_data = lookup(data)
        if not retrieved_data:
            return render_template('quote.html', message = "Stock couldn\'t be found")
        return render_template('quoted.html', data = retrieved_data )



@app.route("/register", methods=["GET", "POST"])
def register():
    """Register user"""
    if request.method == 'POST':

        username = request.form.get("username")
        password = request.form.get("password")
        password_check = request.form.get("password_check")

        if not username:
            return apology("Username is missing")
        if not password:
            return apology("Password is missing")
        if not password_check:
            return apology("Password confirmation is missing")

        existing_in_data = db.execute("SELECT * from users where username = ?", username)
        if existing_in_data:
            return apology("This username has already taken")

        if password != password_check:
            return apology("Passwords do not match.")

        hashed_password = generate_password_hash(password)
        db.execute('INSERT INTO users (username, hash) VALUES (?, ?)', username,hashed_password)


        user_id = db.execute("SELECT id from users where username = ?", username)
        print(user_id)
        print(user_id[0]['id'])
        session['user_id'] = user_id[0]['id']
        return redirect('/')
    else:
        return render_template('register.html')


@app.route("/sell", methods=["GET", "POST"])
@login_required
def sell():
    if request.method == "GET":
        user_portfolio = db.execute('SELECT * from portfolio where Person_ID = ?', session['user_id'])

        return render_template('sell.html', assets = user_portfolio)   # You can increase security by checking whether user gives the correct stock
    if request.method == "POST":
        symbol  = request.form.get('Stock')
        try:
            share = int(request.form.get('share'))
            if share < 0:
                return apology("Invalid Share")
        except:
            return apology("Invalid Share")
        current_stock_amount = db.execute('SELECT Stock_amount from portfolio where Stock = ? and Person_ID = ? ', symbol, session['user_id'])[0]['Stock_amount']
        if share > current_stock_amount:
            return apology("You don't have enought stock")
        else:
            stock_price = lookup(symbol)['price']
            current_cash = db.execute('SELECT cash from users where id = ?', session['user_id'])[0]['cash']
            db.execute('UPDATE portfolio SET stock_amount = ? where Person_ID = ? and Stock = ?' , current_stock_amount - share ,session['user_id'], symbol)
            db.execute('UPDATE users SET cash = ? where id = ?', current_cash + share * stock_price,session['user_id'])
            db.execute('INSERT INTO stock_transactions (user_id, symbol, quantity, price, timestamp) VALUES (?, ?, ?, ?, ?)', session['user_id'],symbol , -share, stock_price, datetime.now())
            return apology ("You've successfully sold your stocks.")
