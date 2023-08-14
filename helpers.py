
from flask import redirect, session
from flask_mail import Message
from functools import wraps
from datetime import datetime
import jwt
import re

def login_required(f):
    """
    Decorate routes to require login.

    http://flask.pocoo.org/docs/0.12/patterns/viewdecorators/
    """
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if session.get("user_id") is None:
            return redirect("/login")
        return f(*args, **kwargs)
    return decorated_function



def sar(value):
    """Format value as SAR."""
    return f"{value:,.2f} SAR"

# encode function
def encode(payload):
    token = jwt.encode(payload, 'SECRET', algorithm='HS256')
    return token

# Check if deadline has passed
def had_finished(deadline):
    totime = datetime.strptime(deadline, "%Y-%m-%d %H:%M") - datetime.now()
    if totime.total_seconds() <= 0:
        return True
    else:
        return False


# Check if url is valid
def is_valid_url(url):
    pattern = re.compile(
        r"^(?:http|ftp)s?://"
        r"(?:(?:[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?\.)+(?:[A-Z]{2,6}\.?|[A-Z0-9-]{2,}\.?)|"
        r"localhost|"
        r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})"
        r"(?::\d+)?"
        r"(?:/?|[/?]\S+)$",
        re.IGNORECASE,
    )
    return bool(pattern.match(url))

# Cheack if the inputed email is valid
def email_check(email):
    # Ensure email is in the form (name@example.com)
    pattern = "^\S+@\S+\.\S+$"
    objs = re.search(pattern, email)
    try:
        if objs.string == email:
            return True
    except:
        return False

# Check if the password is valid
def password_check(password):
    # The accepted symbols
    SpecialSym = "[@#$%&]"

    # Ensure the password is no shorter than 6 characters
    if len(password) < 6:
        return "Password length should be at least 6"

    # Ensure the password is no longer than 20 characters
    if len(password) > 20:
        return "Password length should be not be greater than 8"

    # Ensure password has atleast on numeric
    if not re.search("[0-9]", password):
        return "Password should have at least one numeral"

    # Ensure password has atleast one upper case character
    if not re.search("[A-Z]", password):
        return "Password should have at least one uppercase letter"

    # Ensure password has atleast one lowercase character
    if not re.search("[a-z]", password):
        return "Password should have at least one lowercase letter"

    # Ensure password has atlest one symbol
    if not re.search(SpecialSym, password):
        return "Password should have at least one of the symbols $@#%"

    # Ensure password doesn't have spaces
    if re.search(" ", password):
        return "Password must not include spaces"

    # Return true if password is valid
    return True

# Send email with reset password link
def mail_message(subject, template, recipients, app_username):
    msg = Message(
        subject=subject,
        recipients=recipients,
        sender=("Order it for me Service", app_username),
    )
    msg.html = template
    return msg