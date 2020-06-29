from flask import Flask, request, make_response, session, redirect, url_for, escape
from flask_wtf.csrf import CSRFProtect
from passlib.hash import sha256_crypt
import subprocess

app = Flask(__name__)
#app.secret_key = 'lkkljafovlnkadflkjweoirls413dkl342'
app.config["SECRET_KEY"] = "lkkljafovlnkadflkjweoirls413dkl342"


#use built-in CSRF protection from Flask-WTF extention
#reference: https://flask-wtf.readthedocs.io/en/stable/csrf.html
#csrf = CSRFProtect(app)

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
        response = '''
        <html>
                <head>
                    <title>The Spell Check Site</title>
                    </head>
                    <body>
                    <h2>Welcome back, ''' + username + '''!</h2>
                    <p><a href="/spell_check">Spell check</a></p>
                    <p><a href="/logout">Log out</a></p>
                    </body>
                </html>
        '''
        return response
    else:
        return '''
        <html>
                <head>
                    <title>The Spell Check Site</title>
                    </head>
                    <body>
                    <h2>Hello and welcome to the spell check web application!</h2><br>
                    You must log in to use the spell check program.<br>
                    <p><a href="/register">Register</a></p>
                    <p><a href="/login">Log in</a></p>
                    </body>
                </html>
        '''

#If a user accesses the /register site (i.e. using the HTTP GET method, he/she will be presented with a webform prompting them to register
#When the user submits the required information (i.e. using the HTTP POST method, the user's username, password
#and 2-factor authentication information will be stored and passed to a function to register the new user
@app.route('/register', methods=['POST', 'GET'])
def register():
    if request.method == 'GET':
        return present_register_form()
    elif request.method == 'POST':
        username = str(escape(request.form['uname'])) #Escape username input, because username is later displayed to client in HTML
        #Check to make sure password is not empty
        if len(request.form['pword']) == 0:
            return '''
               <html>   
                       <head>
                           <title>Registration Failure</title>
                           </head>
                           <body>
                           <h1>Oops!</h1>
                           <h2 id="success">Failure. The password field cannot be empty</h2>
                           <p><a href="/register">Register</a></p>
                           <p><a href="/login">Log in</a></p>
                           </body>
                       </html>
               '''
        #convert the password user submitted into a password hash so that it is not stored in plaintext
        #Reference: https://pythonprogramming.net/password-hashing-flask-tutorial/
        password_hash = sha256_crypt.encrypt(request.form['pword'])
        phone = request.form['2fa']
        return register_user(username, password_hash, phone)

def present_register_form():
    return '''
        <html>
        <head>
            <title>Registration</title>
            </head>
            <body>
             <h1>User Registration</h1>
             <p/>
                <form name="register" id="register" action="http://127.0.0.1:5000/register" method="post">
                    Username: <INPUT SIZE=32 id="uname" name="uname" TYPE='text'/><p/>
                    Password: <INPUT SIZE=32 id="pword" name="pword" TYPE='text'/><p/>
                    Cell Phone Number: <INPUT SIZE=32 id="2fa" name="2fa" TYPE='text'/><p/>
                    <button id="registerbutton" type="submit">Register</button>
            </body>
        </html>
        '''
#<input type="hidden" name="csrf_token" value="{{ csrf_token() }}"/>

@app.route('/login', methods=['POST', 'GET'])
def login():
    if request.method == 'GET':
        return present_login_form()
    elif request.method == 'POST':
        username = request.form['uname']
        password = request.form['pword']
        phone = request.form['2fa']
        return check_auth(username, password, phone)


def present_login_form():
    return '''
    <html>
        <head>
            <title>Log in</title>
            </head>
            <body>
            <h1>User Login</h1>
             <p/>
                <form name="login" id="login" action="http://127.0.0.1:5000/login" method="post">
                    Username: <INPUT SIZE=32 id="uname" name="uname" TYPE='text'/><p/>
                    Password: <INPUT SIZE=32 id="pword" name="pword" TYPE='text'/><p/>
                    2-fac method: <INPUT SIZE=32 id="2fa" name="2fa" TYPE='text'/><p/>
                    <button id="loginbutton" type="submit">Log in</button>
                    <p><a href="/register">Register</a></p>
                </form>
            </body>
        </html>
    '''

def register_user(username, password_hash, phone):
    if len(username) == 0:
        return '''
        <html>
                <head>
                    <title>Registration Failure</title>
                    </head>
                    <body>
                    <h1>Oops!</h1>
                    <h2 id="success">Failure. The username cannot be empty</h2>
                    <p><a href="/register">Register</a></p>
                    <p><a href="/login">Log in</a></p>
                    </body>
                </html>
        '''
    elif len(phone) == 0:
        return '''
                <html>
                        <head>
                            <title>Registration Failure</title>
                            </head>
                            <body>
                            <h1>Oops!</h1>
                            <h2 id="success">Failure. You must enter a phone number for 2-factor authentication</h2>
                            <p><a href="/register">Register</a></p>
                            <p><a href="/login">Log in</a></p>
                            </body>
                        </html>
                '''
    elif username in active_users:
        return '''
                <html>
                        <head>
                            <title>Registration Failure</title>
                            </head>
                            <body>
                            <h1>Oops!</h1>
                            <h2 id="success">Failure. This username is not available.</h2>
                            <p><a href="/register">Register</a></p>
                            <p><a href="/login">Log in</a></p>
                            </body>
                        </html>
                '''
    else:
        active_users[username] = [password_hash, phone]
        response = '''
            <html>
                <head>
                    <title>Registration Success</title>
                    </head>
                    <body>
                    <h1 id="success">Success!</h1>
                    <p>
                        <a href="/login">Log in</a></p>
                    </body>
                </html>
            '''
        return response

def check_auth(username, password, phone):
    if username not in active_users:
        #direct user to registration form if username does not exist
        return '''
            <html>
                <head>
                    <title>Login Failure</title>
                    </head>
                    <body>
                    <h1 id="result">Incorrect</h1>
                    <p><a href="/register">Register</a></p>
                    <p><a href="/login">Log in</a></p>
                    </body>
                </html>
            '''
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
                    <h1 id="result">Authentication success</h1>
                    <h2>You can now use the spell check program</h2>
                    <p><a href="/spell_check">Spell check</a></p>
                    <p><a href="/logout">Log out</a></p>
                    </body>
                </html>
                ''')
                return response
            else:
                return '''
                <html>
                <head>
                    <title>Login Failure</title>
                    </head>
                    <body>
                    <h1 id="result">Two-factor failure</h1>
                    <p><a href="/register">Register</a></p>
                    <p><a href="/login">Log in</a></p>
                    </body>
                </html>
                '''
        else:
            return '''
            <html>
                <head>
                    <title>Login Failure</title>
                    </head>
                    <body>
                    <h1 id="result">Incorrect</h1>
                    <p><a href="/register">Register</a></p>
                    <p><a href="/login">Log in</a></p>
                    </body>
                </html>
            '''

@app.route('/spell_check', methods=['POST', 'GET'])
def spell_check():
    if 'username' in session:
        if request.method == 'GET':
            return '''
            <html>
            <head>
            <title>Text submission</title>
            </head>
            <body>
             <h1>Submit text to be spell-checked below</h1>
             <p/>
                <form name="text" id="text" action="http://127.0.0.1:5000/spell_check" method="post">
                    Text: <INPUT SIZE=32 id="inputtext" name="inputtext" TYPE='text'/><p/>
                    <button id="submittext" type="submit">Spell check!</button>
                </form>
            <p><a href="/logout">Log out</a></p>
            </body>
            </html>
            '''
        elif request.method == 'POST':
            fp = open('text_submission.txt', 'w')
            fp.write(str(escape(request.form['inputtext'])))
            fp.close()
            result = subprocess.check_output(["./a.out", "text_submission.txt", "wordlist.txt"]).decode("utf-8").strip()
            formatted_result = result.replace('\n', ', ')
            resp = '''
             <html>
            <head>
            <title>Response</title>
            </head>
            <body>
             <h1>Spell check results:</h1><br>
             <p id="textout">Submitted text: ''' + str(escape(request.form['inputtext'])) + '''</p><br> 
             <p id="misspelled">Misspelled words: ''' + formatted_result + '''</p><br><br>
             <p><a href="/spell_check">Try another!</a></p>
             <p><a href="/logout">Log out</a></p>
            </body>
            </html>
            '''
            return resp
    else:
        return '''
            <html>
                <head>
                    <title>Login Failure</title>
                    </head>
                    <body>
                    <h1 id="result">You must log in first</h1>
                    <p><a href="/login">Log in</a></p>
                    <p><a href="/register">Register</a></p>
                    </body>
                </html>
        '''

#Log out user and delete session cookie
@app.route('/logout')
def logout():
    session.pop('username', None)
    return redirect((url_for('index')))

if __name__ == "__main__":
    app.run(debug=True)


