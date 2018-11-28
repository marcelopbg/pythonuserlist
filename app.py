# -*- coding: utf-8 -*-
from flask import Flask, render_template, flash,  request, url_for, redirect, session, logging, make_response, jsonify
from flask_mysqldb import MySQL
from wtforms import Form, HiddenField, StringField, TextAreaField, PasswordField, validators
from passlib.hash import sha256_crypt
from functools import wraps
import json
import csv


app = Flask(__name__)

app.secret_key = 'mysecret'


#config Mysql

app.config['MYSQL_HOST'] = 'marcelopbg.mysql.pythonanywhere-services.com'
app.config['MYSQL_USER'] = 'marcelopbg'
app.config['MYSQL_PASSWORD'] = 'guimaraes1'
app.config['MYSQL_DB'] = 'marcelopbg$myflaskapp'
app.config['MYSQL_CURSORCLASS'] = 'DictCursor'

#init mysql

mysql = MySQL(app)


@app.route('/exportcsv', methods=['POST'])

def export():
    data = request.form['someshit']
   
    myjson = json.loads(data)
    
    return data


@app.route('/')
def index():
    return render_template('home.html')


class RegisterForm(Form):
    name = StringField('Name', [validators.Length(min=1, max=50)])
    username = StringField('Username', [validators.Length(min=4, max=25)])
    email = StringField('Email', [validators.Length(min=6, max=50)])
    password = PasswordField('Password', [
        validators.DataRequired(),
        validators.EqualTo('confirm', message='Passwords do not match')
    ])
    confirm = PasswordField('Confirm Password')

    @app.route('/register', methods=['GET', 'POST'])
    def register():
        form = RegisterForm(request.form)
        if request.method == 'POST' and form.validate():
            name = form.name.data
            email = form.email.data
            username = form.username.data
            password = sha256_crypt.encrypt(str(form.password.data))

            #create cursor
            cur = mysql.connection.cursor()

            cur.execute("INSERT INTO user(name, email, username, password) VALUES (%s, %s, %s, %s)", (name, email, username, password))

            #commit
            mysql.connection.commit()

            #close conn
            cur.close()

            flash('You are now registered and can log in', 'success')

            redirect(url_for('login'))

            return redirect(url_for('login'))
        return render_template('register.html', form=form)

    #User logging
    @app.route('/login', methods=['GET', 'POST'])
    def login():
        if request.method == 'POST':
            # Get Form Fields
            username = request.form['username']
            password_candidate = request.form['password']

            # Create cursor
            cur = mysql.connection.cursor()

            # Get user by username
            result = cur.execute("SELECT * FROM user WHERE username = %s", [username])

            if result > 0:
                # Get stored hash
                data = cur.fetchone()
                password = data['password']

                # Compare Passwords
                if sha256_crypt.verify(password_candidate, password):
                    # Passed
                    session['logged_in'] = True
                    session['username'] = username

                    flash('You are now logged in', 'success')
                    return redirect(url_for('dashboard'))
                else:
                    error = 'Invalid login'
                    return render_template('login.html', error=error)
                # Close connection
                cur.close()
            else:
                error = 'Username not found'
                return render_template('login.html', error=error)

        return render_template('login.html')


        curl.close()



def is_logged_in(f):
    @wraps(f)
    def wrap(*args, **kwargs):
        if 'logged_in' in session:
            return f(*args, **kwargs)
        else:
            flash('Unauthorized, Please login', 'danger')
            return redirect(url_for('login'))
    return wrap

@app.route('/logout')
@is_logged_in

def logout():
        session.clear()
        flash('You are not logged out', 'success')
        return redirect(url_for('login'))

#create cursor




#commit



#close conn


@app.route('/dashboard')

@is_logged_in

def dashboard(**kwargs):
    cur = mysql.connection.cursor()
    result = cur.execute("SELECT  id, name, username, email FROM user where 1=1")
    columns = ('id', 'name', 'username', 'email')
    mysql.connection.commit()
    # app.logger.info(result)
    results = []
    users = cur.fetchall()
    for row in users:
        results.append(dict(zip(columns, row)))

    ajson = json.dumps(users)
  
    return render_template('dashboard.html', data=users, json=ajson)

    cur.close()



    #if __name__ == "__main__":

       # app.secret_key= 'secret123'

       #app.run()
