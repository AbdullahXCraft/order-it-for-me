# Order it for me
### Video Demo:  <https://youtu.be/dZvHyeHGZg0>
### Description:
### Why this project?
You know when you are going to order from an online website, your family members text you to order something for them, and it kinda gets messy, well this project organizes this for you.
### About this project:
It is a simple web app that organizes orders for you.
### How does it work:
It works using the Flask framework for Python there are multiple routes:
* **Login:**
    Responsible for logging in the user by getting their email and password and checking for them in the database.
* **Logout:**
    Responsible for logging out the user by forgetting the session info.
* **Register:**
    Responsible for registering the user with the needed credentials to the database while ensuring there are no other users with the same info.
* **Change password:**
    Responsible for changing the user's password if he is logged in.
* **Reset password:**
    Responsible for sending a msg to the user's email with a link to reset his password.
* **Index:**
    Responsible for displaying the available order info and letting the user request from any of them.
* **New order**:** Responsible for creating a new order using a form.
* **My orders:**
    Responsible for displaying the orders created by the user.
* **New request:**
    Responsible for creating a new request for a specific order using a form.
* **Requests:**
    Responsible for displaying the requests for each order with its info with the ability to reject requests and close orders so no further requests are possible.
* **My requests:**
    Responsible for displaying all the requests with its info for the loged in user with the abillty to cancel requests.
# Contents:
* ### /static:
    Containing static matireal like css stylecheet and icons.
* ### /templates:
    Containing all html templates.
* ### app.py:
    Containing all flask routes code.
* ### helpers.py:
    Containing functions used in app.py.
* ### orders.db:
    Database containing 3 tables:
    * **users**: stores users credintals.
    * **orders**: stores orders info.
    * **request**: stores requests info.
* ### requirements.txt:
    Containing all the required librarys.
# Used frameworks:
* Flask
* Jinja
* bootstrap 5.1 css/js
* jquery
# Used languages:
* html
* css
* java script
* python
# Used librarys:
* cs50
* Flask
* Flask-Session
* flask_mail
* requests
* datetime
* jwt
* werkzeug.security
* helpers
* re
* functools
### Made by Abdullah Babrahem







# order_it_for_me
# order_it_for_me
# order-it-for-me
