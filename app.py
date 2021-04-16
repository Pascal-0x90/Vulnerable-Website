from flask import Flask, render_template, request, make_response, redirect, url_for, flash
from flask_bcrypt import Bcrypt
from flask_jwt_extended import JWTManager
from flask_mail import Mail

from database.db import initialize_db
from flask_restful import Api
from resources.errors import errors

import json
import requests

app = Flask(__name__)
app.config.from_envvar('ENV_FILE_LOCATION')
app.config['SECRET_KEY'] = 'secret-sneaky-key'
mail = Mail(app)

# imports requiring app and mail
from resources.routes import initialize_routes

api = Api(app, errors=errors)
bcrypt = Bcrypt(app)
jwt = JWTManager(app)

# our main page non-api routes
@app.route("/")
def index():
    return render_template('index.html')

@app.route('/profile')
def profile():
    return render_template('profile.html')

@app.route('/login', methods=['POST', 'GET'])
def login():
    if request.method == 'GET':
        try:
            print(request.cookies.get('token'))
            if not request.cookies.get('token'):
                raise Exception
            return redirect(url_for('profile'))
        except:
            return render_template('login.html')
    else:
        try:
            print(request.cookies.get('token'))
            if not request.cookies.get('token'):
                raise Exception
            return redirect(url_for('profile'))
        except:
            # Caputre request params
            email = request.form.get('email')
            password = request.form.get('password')
            header = dict(request.headers)['Host']
            try:
                xfwdhost = dict(request.headers)['X-Forwarded-Host']
            except:
                xfwdhost = header

            PAYLOAD = json.dumps({
                "email": email,
                "password": password
            })
            HEADERS = {
                "Host": header,
                "Content-Type": "application/json"
            }

            response = requests.post("http://" + header + "/api/auth/login", headers=HEADERS, data=PAYLOAD)

            if response.status_code != 200:
                return json.loads(response.text)['message']
            else:
                token = response.json()['token']
                resp = make_response(render_template('profile.html'))
                resp.set_cookie("token", token)
                return resp

@app.route('/signup', methods=['GET','POST'])
def signup():
    if request.method == 'GET':
        return render_template('signup.html')
    else:
        email = request.form.get('email')
        password = request.form.get('password')
        addr = request.form.get('addr')
        header = dict(request.headers)['Host']

        PAYLOAD = json.dumps({
            'email': email,
            'password': password,
            'address': addr
        })
        HEADERS = {
            "Host": header,
            "Content-Type": "application/json"
        }

        response = requests.post("http://" + header + "/api/auth/signup", headers=HEADERS, data=PAYLOAD)

        if response.status_code != 200:
            return json.loads(response.text)['message']
        else:
            flash("Success!")
            return redirect(url_for('index'))

@app.route('/logout')
def logout():
    resp = make_response(redirect(url_for('login')))
    resp.set_cookie('token', '', expires=0)
    return resp

@app.route('/forgot', methods=['GET', 'POST'] )
def forgot():
    if request.method == 'GET':
        return render_template("forgot.html")
    else:
        email = request.form.get('email')
        hhost = dict(request.headers)['Host']
        try:
            xhost = dict(request.headers)['X-Forwarded-Host']
        except:
            xhost = hhost

        PAYLOAD = json.dumps({
            'email': email
        })

        HEADERS = {
            "Host" : xhost,
            "Content-Type": "application/json"
        }
        print("http://" + hhost + "/api/auth/forgot", HEADERS, PAYLOAD)
        response = requests.post("http://" + hhost + "/api/auth/forgot", headers=HEADERS, data=PAYLOAD)

        if response.status_code != 200:
            return 'Nope', response.status_code
        else:
            flash("Password reset sent!")
            return redirect(url_for('index'))

initialize_db(app)
initialize_routes(api)
