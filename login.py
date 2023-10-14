from flask import Flask, render_template, request, redirect, url_for, session
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.secret_key = 'your_secret_key'  # Replace with a secret key for session management

# Sample user data (in a real system, use a database)
users = {
    'user1': {
        'username': 'user1',
        'password': generate_password_hash('password1'),  # Hashed password
    },
    'user2': {
        'username': 'user2',
        'password': generate_password_hash('password2'),
    }
}

@app.route('/')
def home():
    return 'Welcome to the Home Page'

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        user = users.get(username)
        if user and check_password_hash(user['password'], password):
            session['username'] = username
            return redirect(url_for('secured_page'))
        else:
            return 'Invalid username or password'

    return '''
        <form method="post">
            <p>Username: <input type="text" name="username"></p>
            <p>Password: <input type="password" name="password"></p>
            <p><input type="submit" value="Login"></p>
        </form>
    '''

@app.route('/secured')
def secured_page():
    if 'username' in session:
        return f'Hello, {session["username"]}! This is a secured page. <a href="/logout">Logout</a>'
    else:
        return 'You are not logged in. <a href="/login">Login</a>'

@app.route('/logout')
def logout():
    session.pop('username', None)
    return 'Logged out successfully. <a href="/login">Login</a>'

if __name__ == '__main__':
    app.run(debug=True)
