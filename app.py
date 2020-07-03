from flask import Flask, request, make_response, session, redirect, url_for, escape, render_template
from flask_wtf.csrf import CSRFProtect
from passlib.hash import sha256_crypt
import subprocess, secrets

app = Flask(__name__)
#app.secret_key = 'lkkljafovlnkadflkjweoirls413dkl342'
#app.config["SECRET_KEY"] = "lkkljafovlnkadflkjweoirls413dkl342"
app.config["SECRET_KEY"] = secrets.token_urlsafe(16)


#use built-in CSRF protection from Flask-WTF extention
#reference: https://flask-wtf.readthedocs.io/en/stable/csrf.html
csrf = CSRFProtect(app)

#define a dictionary structure to hold active (registered) users
active_users = {}

@app.after_request
def add_security_headers(response):
#Set content security policy in response headers by using the after_request decorator
#in Flask. Reference: https://pythonise.com/series/learning-flask/python-before-after-request
#and https://stackoverflow.com/questions/29464276/add-response-headers-to-flask-web-app
    response.headers['Content-Security-Policy']='default-src \'self\'; script-src \'self\''
#Set x-frame-options header in the response to prevent 'clickjacking' - a class of attacks where clicks
#in the outer frame can be translated invisibly to clicks on your page’s elements.
# Reference: https://flask.palletsprojects.com/en/1.1.x/security/
    response.headers['X-Frame-Options'] = 'SAMEORIGIN'
#Force the browser to honor the response content type instead of trying to detect it,
#which can be abused to generate a cross-site scripting (XSS) attack.
#Reference: https://flask.palletsprojects.com/en/1.1.x/security/
    response.headers['X-Content-Type-Options'] = 'nosniff'
    return response

@app.route('/')
def index():
    if 'username' in session:
        username = session['username']
        return render_template('loggedin_base.html', username=username)
    else:
        return render_template(('base.html'))

#If a user accesses the /register site (i.e. using the HTTP GET method, he/she will be presented with a webform prompting them to register
#When the user submits the required information (i.e. using the HTTP POST method, the user's username, password
#and 2-factor authentication information will be stored and passed to a function to register the new user
@app.route('/register', methods=['POST', 'GET'])
def register():
    if request.method == 'GET':
        return render_template('register.html')
    elif request.method == 'POST':
        username = str(escape(request.form['uname'])) #Escape username input, because username is later displayed to client in HTML
        #convert the password user submitted into a password hash so that it is not stored in plaintext
        #Reference: https://pythonprogramming.net/password-hashing-flask-tutorial/
        password_hash = sha256_crypt.encrypt(request.form['pword'])
        phone = request.form['2fa']
        return register_user(username, password_hash, phone)

@app.route('/login', methods=['POST', 'GET'])
def login():
    if request.method == 'GET':
        return render_template('login.html')
    elif request.method == 'POST':
        username = request.form['uname']
        password = request.form['pword']
        phone = request.form['2fa']
        return check_auth(username, password, phone)

def register_user(username, password_hash, phone):
    if username in active_users:
        return render_template('username_not_available.html', username = username)
    else:
        active_users[username] = [password_hash, phone]
        return render_template('registration_success.html', username = username)

def check_auth(username, password, phone):
    if username not in active_users:
        #direct user to registration form if username does not exist
        return render_template('auth_failure.html')
    #username exists, which means user registered and password and phone fields are non-empty
    else:
        #Compare the submitted password with the user's stored password hash
        if sha256_crypt.verify(password, active_users[username][0]):
            if phone == active_users[username][1]:
                #reference: https://www.tutorialspoint.com/flask/flask_sessions.htm
                session['username'] = username
                response = make_response('''
                <html>
                <head>
                    <title>Login Success</title>
                    </head>
                    <body>
                    <h1 id="result">Authentication success.</h1>
                    <h2>You can now use the spell check program</h2>
                    <p><a href="/spell_check">Spell check</a></p>
                    <p><a href="/logout">Log out</a></p>
                    </body>
                </html>
                ''')
                return response
            else:
                return render_template('auth_failure.html')
        else:
            return render_template('auth_failure.html')

@app.route('/spell_check', methods=['POST', 'GET'])
def spell_check():
    if 'username' in session:
        if request.method == 'GET':
            return render_template('spellcheck.html')
        elif request.method == 'POST':
            fp = open('text_submission.txt', 'w')
            fp.write(str(escape(request.form['inputtext'])))
            fp.close()
            submitted_text = str(escape(request.form['inputtext'])) #Escaping here is actually unnecessary since the render_template() function does this automatically
            result = subprocess.check_output(["./a.out", "text_submission.txt", "wordlist.txt"]).decode("utf-8").strip().replace('\n', ', ')
            #formatted_result = result.replace('\n', ', ')
            return render_template('response.html', submitted_text = submitted_text, result = result)
    else:
        return render_template('login_failure.html')

#Log out user and delete session cookie
@app.route('/logout')
def logout():
    session.pop('username', None)
    return redirect((url_for('index')))

if __name__ == "__main__":
    app.run(debug=True)


