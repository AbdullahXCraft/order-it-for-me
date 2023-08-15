from flask_mail import Mail
from datetime import datetime, timezone, timedelta
import jwt
from cs50 import SQL
from flask import (
    Flask,
    flash,
    redirect,
    render_template,
    request,
    session,
    url_for,
    get_flashed_messages,
)
from flask_session import Session
from werkzeug.security import check_password_hash, generate_password_hash

from helpers import login_required, sar, had_finished, encode, password_check, email_check, is_valid_url, mail_message

# Configure application
app = Flask(__name__)

# Configure mail settings
app.config["MAIL_SERVER"] = "smtp.gmail.com"
app.config["MAIL_PORT"] = 465
app.config["MAIL_USE_SSL"] = True
app.config["MAIL_USERNAME"] = "orderitformeservice@gmail.com"
app.config["MAIL_PASSWORD"] = "mkilnayyzgvrxtyq"
app.config["MAIL_DEFAULT_SENDER"] = "Order it for me Service"
mail = Mail(app)

# Custom filter
app.jinja_env.filters["sar"] = sar
app.jinja_env.globals.update(encode=encode)
app.jinja_env.globals.update(had_finished=had_finished)

# Configure session to use filesystem (instead of signed cookies)
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

# Configure CS50 Library to use SQLite database
db = SQL("sqlite:///orders.db")

@app.after_request
def after_request(response):
    """Ensure responses aren't cached"""
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Expires"] = 0
    response.headers["Pragma"] = "no-cache"
    return response

@app.route("/", methods=["GET", "POST"])
@login_required
def index():

    available_orders = db.execute("SELECT orders.id, web_url, web_name, username, deadline, closed FROM orders JOIN users ON users.id = orders.owner_id WHERE owner_id != ?", session['user_id'])
    # Provide user with index page
    return render_template("index.html", available_orders=available_orders)

@app.route("/login", methods=["GET", "POST"])
def login():
    """Log user in"""

    # Make sure flashed doesnt get deleted
    get_flashed_messages(with_categories=True)

    # Forget any user_id
    session.clear()

    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":

        # Get user input
        email = request.form.get("email").lower()
        password = request.form.get("password")

        # Ensure email was submitted
        if not email:
            flash("Must provide email", "danger")
            return redirect("/login")

        # Ensure password was submitted
        elif not password:
            flash("Must provide password", "danger")
            return redirect("/login")

        # Query database for email
        rows = db.execute(
            "SELECT * FROM users WHERE email = ?;", email.lower()
        )

        # Ensure email exists and password is correct
        if len(rows) != 1 or not check_password_hash(
            rows[0]["hash"], password
        ):
            flash("Invalid email and/or password", "danger")
            return redirect("/login")

        # Remember which user has logged in
        session["user_username"] = rows[0]["username"]
        session["user_id"] = rows[0]["id"]

        # Redirect user to home page
        flash("Successfully loged in", "success")
        return redirect("/")

    # User reached route via GET (as by clicking a link or via redirect)
    else:
        # Provide user with the log in form
        return render_template("login.html")

@app.route("/logout")
def logout():
    """Log user out"""

    # Make sure flashed doesnt get deleted
    get_flashed_messages(with_categories=True)

    # Forget any user_id
    session.clear()

    # Redirect user to login form
    flash("Successfully loged out", "success")
    return redirect("/")

@app.route("/register", methods=["GET", "POST"])
def register():
    """Register user"""

    # User reached route via POST
    if request.method == "POST":
        # Store form input to their values
        username = request.form.get("username")
        email = request.form.get("email").lower()
        password = request.form.get("password")
        confirmation = request.form.get("confirmation")

        # Ensure username was submitted
        if not username:
            flash("You must provide a username", "danger")
            return redirect("/register")

        # Query database for username
        rows = db.execute("SELECT * FROM users WHERE username = ?;", username)

        # Ensure username is not already used
        if len(rows) != 0:
            flash("This username has already been used", "danger")
            return redirect("/register")

        # Ensure email was submitted
        if not email:
            flash("You must provide an email", "danger")
            return redirect("/register")

        # Ensure email is valid
        if not email_check(email):
            flash("You must provide a valid email", "danger")
            return redirect("/register")

        # Query database for email
        rows = db.execute("SELECT * FROM users WHERE email = ?;", email)

        # Ensure email is not already used
        if len(rows) != 0:
            flash("This email has already been used", "danger")
            return redirect("/register")

        # Ensure password and password confirmation was submitted
        if not password or not confirmation:
            flash("You must provide password and password confirmation", "danger")
            return redirect("/register")

        # Ensure password meets the requirements
        if not password_check(password) == True:
            flash(password_check(password), "danger")
            return redirect("/register")

        # Ensure password and password confirmation match
        if password != confirmation:
            flash("The password and the password confirmation must match", "danger")
            return redirect("/register")

        # Insert user's credentials into the database
        id = db.execute(
            "INSERT INTO users (username, email, hash) VALUES (?, ?, ?);",
            username,
            email,
            generate_password_hash(password),
        )

        # Log In the user
        session["user_id"] = id

        # Redirect user to home page
        flash("Successfully registerd", "success")
        return redirect("/")

    # User reached route via GET
    else:
        # Provide user with register form
        return render_template("register.html")

@app.route("/reset_password", methods=["GET", "POST"])
def reset_password():
    """Reset Password"""

    # User reached route via POST
    if request.method == "POST":
        # Get user's form input
        email = request.form.get("email").lower()

        # Ensure user submited an email
        if not email:
            flash("Must provide an email", "danger")
            return redirect("/reset_password")

        # Query for user's id with this email
        ids = db.execute("SELECT * FROM users WHERE email = ?", email)

        # Ensure email exists
        if len(ids) == 0:
            flash("The email you enterd doesn't exists", "danger")
            return redirect("/reset_password")

        # Create request token with the user's id
        token = jwt.encode(
            {
                "id": ids[0]["id"],
                "exp": datetime.now(tz=timezone.utc) + timedelta(seconds=300),
            },
            "SECRET",
            algorithm="HS256",
        )

        # Send email to user
        mail.send(
            mail_message(
                subject="Password Reset Request",
                recipients=[ids[0]["email"]],
                template=render_template(
                    "emails/reset_request.html",
                    username=ids[0]["username"],
                    reseturl=url_for("reset_token", token=token, _external=True),
                ),
                app_username=app.config["MAIL_USERNAME"]
            )
        )

        # Provide user with sent successfully page
        flash(
            "Request sent, Check your mail you only have 5 minutes to reset your password",
            "success",
        )
        return redirect("/reset_password")

    # User reached route via get
    else:
        # provide user with reset password form
        return render_template("reset_password.html")

@app.route("/reset_password/<token>", methods=["GET", "POST"])
def reset_token(token):
    # User reached route via POST
    if request.method == "POST":
        # Ensure token is a valid and not expired
        try:
            user_id = jwt.decode(token, "SECRET", algorithms="HS256")
        except:
            flash("Invalid token or expired", "danger")
            return redirect("/reset_password")

        # Query for user info
        users = db.execute("SELECT * FROM users WHERE id = ?", user_id["id"])

        # Ensure Valid user id
        if len(users) != 1:
            flash("Invalid user", "danger")
            return redirect("/reset_password")

        # Get user's form input
        password = request.form.get("password")
        confirmation = request.form.get("confirmation")

        # Ensure password and password confirmation was submitted
        if not password or not confirmation:
            flash("You must provide password and password confirmation", "danger")
            return redirect("/reset_password/" + token)

        # Ensure password meets the requirements
        if not password_check(password) == True:
            flash(password_check(password), "danger")
            return redirect("/reset_password/" + token)

        # Ensure password and password confirmation match
        if password != confirmation:
            flash("The password and the password confirmation must match", "danger")
            return redirect("/reset_password/" + token)

        # Ensure old password and new password are not the same
        if generate_password_hash(password) == users[0]["hash"]:
            flash(
                "Your new password mustn't be the same as your old password", "danger"
            )
            return redirect("/reset_password/" + token)

        # Update user's password
        db.execute("UPDATE users SET hash = ? WHERE id = ?", generate_password_hash(password), session["user_id"])

        # Make sure flashed doesnt get deleted
        get_flashed_messages(with_categories=True)

        # Forget any user_id
        session.clear()

        # Redirect user to login form
        flash("Successfully Changed Password", "success")
        return redirect("/login")

    # User reached route via GET
    else:
        # Ensure token is a valid and not expired
        try:
            user_id = jwt.decode(token, "SECRET", algorithms="HS256")
        except:
            flash("Invalid token or expired", "danger")
            return redirect("/reset_password")

        # Query for user info
        users = db.execute("SELECT * FROM users WHERE id = ?", user_id["id"])

        # Ensure Valid user id
        if len(users) != 1:
            flash("Invalid user", "danger")
            return redirect("/reset_password")

        # Provide the user with reset token form
        return render_template("reset_token.html", token=token)

@app.route("/new_order", methods=["GET", "POST"])
@login_required
def new_order():
    # User reached route via POST
    if request.method == "POST":
        # Get form input
        web_name = request.form.get("website_name").lower().capitalize()
        web_url = request.form.get("website_url").lower()
        deadline_date = request.form.get("deadline_date")
        deadline_time = request.form.get("deadline_time")

        # Ensure all fields are inputted
        if not web_name or not web_url or not deadline_date or not deadline_time:
            flash("All fileds must be submitted", "danger")
            return redirect(url_for("new_order"))

        # Ensure valid url
        if not is_valid_url(web_url):
            flash(
                "Invalid url, url must be in this format (https://www.example.com)",
                "danger",
            )
            return redirect(url_for("new_order"))

        # Ensure valid deadline and its atleast in one day
        try:
            deadline = deadline_date + " " + deadline_time
            todeadline = datetime.strptime(deadline, "%Y-%m-%d %H:%M") - datetime.now()
            if todeadline.days < 1:
                flash("Deadline Must be atleast 1 day long", "danger")
                return redirect(url_for("new_order"))
        except:
            flash("Invalid date and/or time", "danger")
            return redirect(url_for("new_order"))

        # Insert data to database
        db.execute(
            "INSERT INTO orders (owner_id, web_name, web_url, deadline) VALUES (?, ?, ?, ?);",
            session["user_id"],
            web_name,
            web_url,
            deadline,
        )

        flash("Successfully added order", "success")
        return redirect(url_for("my_orders"))

    # User reached route via GET
    else:
        # Provide user with index page
        return render_template("new_order.html")

@app.route("/edit_order/<token>", methods=["GET", "POST"])
@login_required
def edit_order(token):

    # User reached route via POST
    if request.method == "POST":

        # Get form input
        web_name = request.form.get("website_name").lower().capitalize()
        web_url = request.form.get("website_url").lower()
        deadline_date = request.form.get("deadline_date")
        deadline_time = request.form.get("deadline_time")

        # Ensure all fields are inputted
        if not web_name or not web_url or not deadline_date or not deadline_time:
            flash("All fileds must be submitted", "danger")
            return redirect("/edit_order/"+token)

        # Ensure valid url
        if not is_valid_url(web_url):
            flash(
                "Invalid url, url must be in this format (https://www.example.com)",
                "danger",
            )
            return redirect("/edit_order/"+token)

        # Ensure valid deadline and its atleast in one day
        try:
            deadline = deadline_date + " " + deadline_time
            todeadline = datetime.strptime(deadline, "%Y-%m-%d %H:%M") - datetime.now()
            if todeadline.days < 1:
                flash("Deadline Must be atleast 1 day long", "danger")
                return redirect("/edit_order/"+token)
        except:
            flash("Invalid date and/or time", "danger")
            return redirect("/edit_order/"+token)

        # Update data database
        db.execute(
            "UPDATE orders SET web_name = ?, web_url = ?, deadline = ? WHERE id = ?",
            web_name,
            web_url,
            deadline,
            jwt.decode(token, "SECRET", algorithms="HS256")['id']
        )

        flash("Changes saved", "success")
        return redirect(url_for("my_orders"))

    else:

        # Get order info
        try:
            order = db.execute('SELECT * FROM orders WHERE id = ?', jwt.decode(token, "SECRET", algorithms="HS256")['id'])[0]
        except:
            flash("Invalid token", "danger")
            return redirect(url_for("my_orders"))
        # Ensure valid token
        if not order:
            flash("This order doesn't exist", "danger")
            return redirect(url_for("my_orders"))
        # Provide user with edit order form
        return render_template("new_order.html", token=token, order=order)

@app.route("/new_request/<token>", methods=["GET", "POST"])
@login_required
def new_request(token):

    # User reached route via POST
    if request.method == "POST":

        # Get form input
        prod_name = request.form.get("prod_name").lower().capitalize()
        prod_url = request.form.get("prod_url").lower()
        prod_price = request.form.get("prod_price")
        prod_amount = request.form.get("prod_amount")

        # Ensure all fields are inputted
        if not prod_name or not prod_url or not prod_price or not prod_amount:
            flash("All fileds must be submitted", "danger")
            return redirect("/new_request/"+token)

        # Ensure valid url
        if not is_valid_url(prod_url):
            flash(
                "Invalid url, url must be in this format (https://www.example.com)",
                "danger",
            )
            return redirect("/new_request/"+token)

        # Ensure valid price
        try:
            prod_price = float(prod_price)
            if not prod_price > 0:
                flash("Price must not be neither negative nor zero", "danger")
                return redirect("/new_request/"+token)
        except ValueError:
            flash("Invalid price", "danger")
            return redirect("/new_request/"+token)

        # Ensure valid amount
        try:
            prod_amount = int(prod_amount)
            if prod_amount < 1:
                flash("Amount must be either one or higher", "danger")
                return redirect("/new_request/"+token)
        except ValueError:
            flash("Invalid amount", "danger")
            return redirect("/new_request/"+token)

        # Insert request into database
        db.execute(
            "INSERT INTO requests (owner_id, order_id, prod_name, prod_url, prod_price, prod_amount, total) VALUES (?, ?, ?, ?, ?, ?, ?);",
            session['user_id'],
            jwt.decode(token, "SECRET", algorithms="HS256")["id"],
            prod_name,
            prod_url,
            prod_price,
            prod_amount,
            prod_amount * prod_price
        )
        # Update order total and count
        db.execute("UPDATE orders SET req_count = req_count + ?, req_total = req_total + ? WHERE id = ?;", 1, prod_amount * prod_price, jwt.decode(token, "SECRET", algorithms="HS256")["id"])


        # Redirect user to index page
        flash("Request succcessfully submited", "success")
        return redirect(url_for("index"))

    # User reached route via GET
    else:

        # Get order info
        order = db.execute("SELECT web_name, username FROM orders JOIN users ON users.id = orders.owner_id WHERE orders.id = ?", jwt.decode(token, "SECRET", algorithms="HS256")["id"])[0]
        # Provide user with new request form
        return render_template("new_request.html", token=token, order=order)

@app.route("/requests/<token>", methods=["GET", "POST"])
@login_required
def requests(token):
    # User reache via POST
    if request.method == "POST":
        try:
            order_id = jwt.decode(token, "SECRET", algorithms="HS256")["id"]
            status = jwt.decode(token, "SECRET", algorithms="HS256")['status']
        except:
            flash("Invalid token", "danger")
            return redirect(url_for("my_orders"))
        # Close order
        db.execute("UPDATE orders SET closed = ? WHERE id = ?", status, order_id)
        # redirect to my orders
        if status:
            flash("Order Closed successfully", "success")
        else:
            flash("Order Reopend successfully", "success")
        return redirect(url_for("my_orders"))

    # User reached route via GET
    else:
        # Provide user with requests page
        try:
            order_id = jwt.decode(token, "SECRET", algorithms="HS256")["id"]
        except:
            flash("Invalid token", "danger")
            return redirect(url_for("my_orders"))
        requests = db.execute("SELECT requests.order_id, requests.id, prod_url, prod_name, prod_price, prod_amount, total, closed, username FROM requests JOIN users ON requests.owner_id = users.id WHERE order_id = ?", order_id)
        order = db.execute("SELECT * FROM orders WHERE id = ?", order_id)[0]
        return render_template('requests.html', requests=requests, order=order, token=token)

@app.route("/my_orders", methods=["GET", "POST"])
@login_required
def my_orders():

    my_orders = db.execute("SELECT * FROM orders WHERE owner_id = ?", session['user_id'])
    # Provide user with index page
    return render_template("my_orders.html", my_orders=my_orders)

@app.route("/my_requests", methods=["GET"])
@login_required
def my_requests():

    my_requests = db.execute("SELECT requests.id, requests.order_id, requests.owner_id, prod_url, prod_name, prod_price, prod_amount, total, requests.closed, web_name, web_url FROM requests JOIN orders ON requests.order_id = orders.id WHERE requests.owner_id = ?", session['user_id'])
    # Provide user with index page
    return render_template("my_requests.html", my_requests=my_requests)

@app.route("/cancel_request/<token>", methods=["GET"])
@login_required
def cancel_request(token):
    try:
        payload = jwt.decode(token, "SECRET", algorithms="HS256")
    except:
        flash("invalid token")
        return redirect(url_for("my_requests"))
    # Cancel request
    db.execute("UPDATE requests SET closed = ? WHERE id = ?", payload["code"], payload["id"])
    # Decrease order count and total
    db.execute("UPDATE orders SET req_count = req_count - ?, req_total = ROUND(req_total - (SELECT total FROM requests WHERE id = ?), 2) WHERE id = ?;", 1, payload["id"], payload["order_id"])
    # Provide user with index page
    if payload["code"] == 1:
        flash("Request succcessfully cancelled", "success")
        return redirect(url_for("my_requests"))
    else:
        flash("Request succcessfully rejected", "success")
        return redirect("/requests/" + payload["token"])

@app.route("/change_password", methods=["GET","POST"])
@login_required
def change_password():

    # User reached route via POST
    if request.method == "POST":
        # Get user info
        users = db.execute("SELECT * FROM users WHERE id = ?", session["user_id"])

        # Get user's form input
        password = request.form.get("password")
        confirmation = request.form.get("confirmation")

        # Ensure password and password confirmation was submitted
        if not password or not confirmation:
            flash("You must provide password and password confirmation", "danger")
            return redirect(url_for("change_password"))

        # Ensure password meets the requirements
        if not password_check(password) == True:
            flash(password_check(password), "danger")
            return redirect(url_for("change_password"))

        # Ensure password and password confirmation match
        if password != confirmation:
            flash("The password and the password confirmation must match", "danger")
            return redirect(url_for("change_password"))

        # Ensure old password and new password are not the same
        if generate_password_hash(password) == users[0]["hash"]:
            flash(
                "Your new password mustn't be the same as your old password", "danger"
            )
            return redirect(url_for("change_password"))

        # Update user's password
        db.execute("UPDATE users SET hash = ? WHERE id = ?", generate_password_hash(password), session["user_id"])

        # Make sure flashed doesnt get deleted
        get_flashed_messages(with_categories=True)

        # Forget any user_id
        session.clear()

        # Redirect user to login form
        flash("Successfully Changed Password", "success")
        return redirect("/login")

    # User reached route via GET
    else:

        # provide user with change password form
        return render_template("change_password.html")

if __name__ == "__main__":
    app.run(debug=False, host="0.0.0.0")
