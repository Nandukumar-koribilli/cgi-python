#!C:/Users/katta/AppData/Local/Programs/Python/Python313/python.exe
# -*- coding: UTF-8 -*-

import os
import hashlib
import sys
from urllib.parse import parse_qs
import traceback


# --- Configuration ---
# This file will be created in the cgi-bin directory to store users
USER_DB_FILE = "users.db"

# --- Helper Functions ---

def hash_password(password):
    """Hashes the password using SHA256 for storage and comparison."""
    return hashlib.sha256(password.encode('utf-8')).hexdigest()

def user_exists(username):
    """Checks if a user exists in the database file."""
    if not os.path.exists(USER_DB_FILE):
        return False
    with open(USER_DB_FILE, 'r') as f:
        for line in f:
            # File format is "username:hashed_password"
            stored_user, _ = line.strip().split(':', 1)
            if stored_user == username:
                return True
    return False

def add_user(username, password):
    """Adds a new user to the database file with a hashed password."""
    hashed_pass = hash_password(password)
    with open(USER_DB_FILE, 'a') as f:
        f.write(f"{username}:{hashed_pass}\n")

def verify_user(username, password):
    """Verifies user credentials against the stored hash."""
    if not user_exists(username):
        return False
    hashed_pass_to_check = hash_password(password)
    with open(USER_DB_FILE, 'r') as f:
        for line in f:
            stored_user, stored_pass_hash = line.strip().split(':', 1)
            if stored_user == username and stored_pass_hash == hashed_pass_to_check:
                return True
    return False

# --- HTML Template Functions ---

def print_header(title="Login/Register"):
    """Prints the HTML header and CSS styles."""
    print("Content-Type: text/html")
    print()  # An essential blank line to separate headers from content
    print("<!DOCTYPE html>")
    print("<html lang='en'>")
    print("<head>")
    print(f"<title>{title}</title>")
    print("""
    <style>
        body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif; background-color: #f0f2f5; margin: 40px; display: flex; justify-content: center; align-items: center; }
        .container { max-width: 450px; width: 100%; margin: auto; background: white; padding: 20px 30px; border-radius: 8px; box-shadow: 0 4px 12px rgba(0,0,0,0.1); }
        h1, h2 { text-align: center; color: #333; }
        form { display: flex; flex-direction: column; }
        input[type="text"], input[type="password"] { padding: 12px; margin-bottom: 12px; border: 1px solid #ddd; border-radius: 6px; font-size: 16px; }
        input[type="submit"] { background-color: #007bff; color: white; padding: 12px; border: none; border-radius: 6px; cursor: pointer; font-size: 16px; font-weight: bold; }
        input[type="submit"]:hover { background-color: #0056b3; }
        .register-form input[type="submit"] { background-color: #28a745; }
        .register-form input[type="submit"]:hover { background-color: #218838; }
        .message { text-align: center; padding: 15px; margin-top: 20px; border-radius: 6px; font-size: 16px; }
        .success { background-color: #d4edda; color: #155724; border: 1px solid #c3e6cb; }
        .error { background-color: #f8d7da; color: #721c24; border: 1px solid #f5c6cb; }
        a { color: #007bff; text-decoration: none; }
        a:hover { text-decoration: underline; }
        hr { border: 0; height: 1px; background: #ddd; margin: 20px 0; }
    </style>
    """)
    print("</head>")
    print("<body>")
    print("<div class='container'>")

def print_footer():
    """Prints the HTML footer."""
    print("</div></body></html>")

def show_login_form(message=""):
    """Displays the main page with login and registration forms."""
    print_header("Login & Registration")
    if message:
        print(message)
    
    print("<h2>Register</h2>")
    print("<form action='login.py' method='post' class='register-form'>")
    print("<input type='hidden' name='action' value='register'>")
    print("<input type='text' name='username' placeholder='Choose a Username' required>")
    print("<input type='password' name='password' placeholder='Choose a Password' required>")
    print("<input type='submit' value='Register'>")
    print("</form>")
    
    print("<hr>")
    
    print("<h2>Login</h2>")
    print("<form action='login.py' method='post'>")
    print("<input type='hidden' name='action' value='login'>")
    print("<input type='text' name='username' placeholder='Username' required>")
    print("<input type='password' name='password' placeholder='Password' required>")
    print("<input type='submit' value='Login'>")
    print("</form>")
    print_footer()

def show_message_page(title, message_html):
    """Displays a generic message page (e.g., for success or error)."""
    print_header(title)
    print(message_html)
    print("<p style='text-align:center; margin-top: 20px;'><a href='login.py'>Return to Login Page</a></p>")
    print_footer()

# --- Main Logic ---

def main():
    """Main function to handle CGI requests."""
    # The cgi module was removed in Python 3.13. We manually parse form data.
    form = {}
    if os.environ.get("REQUEST_METHOD") == "POST":
        try:
            content_length = int(os.environ.get("CONTENT_LENGTH", 0))
            post_data = sys.stdin.read(content_length)
            # parse_qs returns values as lists, so we extract the first element.
            form_data = parse_qs(post_data)
            form = {k: v[0] for k, v in form_data.items()}
        except (ValueError, KeyError):
            # Handle potential errors in parsing
            pass

    action = form.get("action")
    username = form.get("username", "").strip()
    password = form.get("password", "")
    if action == "register":
        if not username or not password:
            msg = "<p class='message error'>Username and password are required.</p>"
            show_login_form(msg)
            return

        if user_exists(username):
            msg = f"<h1>Registration Failed</h1><p class='message error'>Username '{username}' is already taken.</p>"
            show_message_page("Error", msg)
        else:
            add_user(username, password)
            msg = f"<h1>Registration Successful</h1><p class='message success'>Welcome, {username}! Your account has been created. You can now log in.</p>"
            show_message_page("Success", msg)

    elif action == "login":
        if not username or not password:
            msg = "<p class='message error'>Username and password are required.</p>"
            show_login_form(msg)
            return

        if verify_user(username, password):
            # Successful login
            print_header(f"Welcome {username}")
            print(f"<h1>Welcome, {username}!</h1>")
            print("<p class='message success'>You have successfully logged in.</p>")
            print("<p style='text-align:center; margin-top: 20px;'><a href='login.py'>Log Out</a></p>")
            print_footer()
        else:
            # Failed login
            msg = "<h1>Login Failed</h1><p class='message error'>Invalid username or password.</p>"
            show_message_page("Error", msg)
    else:
        # No action specified, so show the main login/registration page
        show_login_form()

if __name__ == "__main__":
    # The cgitb module was removed in Python 3.13. We add a basic error handler.
    try:
        main()
    except Exception:
        print("Content-Type: text/html")
        print()
        print("<!DOCTYPE html><html><head><title>CGI Script Error</title></head><body>")
        print("<h1>CGI Script Error</h1>")
        print("<p>The script encountered an error. Traceback is below:</p>")
        print("<pre>")
        traceback.print_exc(file=sys.stdout)
        print("</pre>")
        print("</body></html>")
