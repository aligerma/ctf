from flask import Flask, request, render_template, redirect, url_for, session, send_from_directory
import os

app = Flask(__name__)
app.secret_key = "supersecretkey"  # Secret key for session management

# Simulated database
DATABASE = [
    {"username": "admin", "password": "securepassword"},
    {"username": "guest", "password": "iamguest"}
]

# Directory to store secret files
SECRET_FILES_DIR = "secret_files"
os.makedirs(SECRET_FILES_DIR, exist_ok=True)  # Ensure directory exists


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/login", methods=["POST"])
def login():
    username = request.form.get("username", "")
    password = request.form.get("password", "")

    # Debug output to understand how the payload is processed
    print(f"Received username: {username}, password: {password}")

    # Simulating SQL query evaluation
    for user in DATABASE:
        if (
            (username == user["username"] and password == user["password"])
            or "OR" in username.upper()
            or username == '" or ""="'
            or username == "' OR '1'='1' --"
        ):
            if "admin" in username or username == '" or ""="' or username == "' OR '1'='1' --":
                session["user"] = "admin"  # Mark as logged in
                return redirect(url_for("dashboard"))
            
            if "guest" in username:
                session["user"] = "guest"
                return redirect(url_for("guest_log_in"))

    return "Login failed! Please check your username and password."


@app.route("/dashboard")
def dashboard():
    # Check if the user is logged in as admin
    if session.get("user") == "admin":
        return """
        <style>
            body {
                font-family: Arial, sans-serif;
                background-color: #e9ecef;
                color: #333;
                margin: 0;
                padding: 20px;
            }
            h1 {
                color: #6c757d;
            }
            table {
                width: 80%;
                margin: 20px auto;
                border-collapse: collapse;
                box-shadow: 0 2px 5px rgba(0, 0, 0, 0.1);
            }
            th, td {
                border: 1px solid #ddd;
                padding: 10px;
                text-align: center;
            }
            th {
                background-color: #007bff;
                color: #fff;
            }
            tr:nth-child(even) {
                background-color: #f2f2f2;
            }
        </style>
        <h1>Admin Dashboard</h1>
        <p>Welcome, admin!</p>
        <table>
            <thead>
                <tr>
                    <th>#</th>
                    <th>Username</th>
                    <th>Password</th>
                    <th>Status</th>
                </tr>
            </thead>
            <tbody>
                <tr>
                    <td>1.</td>
                    <td>guest</td>
                    <td>iamguest</td>
                    <td>Active</td>
                </tr>
                <tr>
                    <td>2.</td>
                    <td>paul</td>
                    <td>paulcool</td>
                    <td>Deactive</td>
                </tr>
            </tbody>
        </table>
        <br>
        """
    return "Access denied! You are not authorized to view this page.", 403


@app.route("/guest_log_in")
def guest_log_in():
    # Check if the user is logged in as a guest
    if session.get("user") == "guest":
        return """
        <style>
            body {
                font-family: Arial, sans-serif;
                background-color: #fff3cd;
                color: #856404;
                margin: 0;
                padding: 20px;
                text-align: center;
            }
            img {
                width: 700px;
                height: auto;
                margin-top: 20px;
            }
        </style>
        <h1>Guest Dashboard</h1>
        <p>Welcome, player! You are almost there to find the flag I hid somewhere.</p>
        <p>The picture is where I grew up. It is one of the most famous locations since it is the Capitol Building. 
        The country is located in Central Asia and starts with M.</p>
        <img src="/files/pic.png" alt="Guest Image"/>
        """
    # If not logged in as a guest, redirect to the login page
    return redirect(url_for("index"))


@app.route("/files/<filename>")
def files(filename):
    # Serve files only if the user is logged in
    if session.get("user") in ["admin", "guest"]:  # Allow both admin and guest
        return send_from_directory(SECRET_FILES_DIR, filename)
    return "Access denied! You are not authorized to view this file.", 403


@app.route("/mongolia")
def flag_page():
    # Read the flag content from the file
    return """
    <style>
        body {
            font-family: Arial, sans-serif;
            background-color: #f7f7f7;
            color: #333;
            margin: 0;
            padding: 20px;
            text-align: center;
        }
        h1 {
            color: #4CAF50;
        }
        p {
            font-size: 18px;
            margin: 10px 0;
        }
        pre {
            background-color: #f4f4f4;
            padding: 15px;
            border-radius: 5px;
            font-size: 16px;
            color: #d63384;
        }
        a {
            text-decoration: none;
            color: #fff;
            background-color: #007bff;
            padding: 10px 20px;
            border-radius: 5px;
        }
        a:hover {
            background-color: #0056b3;
        }
    </style>
    <h1>Congratulations</h1>
    <p>You found the flag! But not in the format you wanted. You know what to do:</p>
    <pre>
    69 74 63 31 30 31 7b 67 30 30 64 5f 6a 30 62 5f 68 33 72 33 5f 69 35 5f 66 6c 61 67 7d
    </pre>
    <br>
    <a href="/">Back to Home</a>
    """


@app.route("/logout")
def logout():
    session.clear()  # Clear the session
    return redirect(url_for("index"))


if __name__ == "__main__":
    app.run(debug=True)
