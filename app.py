# -*- coding: utf-8 -*-
from flask import Flask, render_template, flash,  request, url_for, redirect, session, logging, make_response, jsonify
from data import Articles
from flask_mysqldb import MySQL
from wtforms import Form, HiddenField, StringField, TextAreaField, PasswordField, validators
from passlib.hash import sha256_crypt
from functools import wraps
import pandas as pd
import json
from decimal import Decimal
from datetime import datetime
import csv
from pprint import pprint
import collections
import psycopg2


app = Flask(__name__)

#config Mysql

app.config['MYSQL_HOST'] = 'localhost'
app.config['MYSQL_USER'] = 'marcelopbg'
app.config['MYSQL_PASSWORD'] = '123'
app.config['MYSQL_DB'] = 'myflaskapp'
app.config['MYSQL_CURSORCLASS'] = 'DictCursor'

#init mysql

mysql = MySQL(app)

Articles = Articles()


@app.route('/exportcsv', methods=['POST'])

def export():
    data = request.form['somedata']
    # aobj = json.loads(data)

    # json.dump()
    # f = open(raw)
    # json_raw= data.readlines()
    myjson = json.loads(data)


    app.logger.info('help jesus %s', myjson)
    # csv = 'foo,bar,baz\nhai,bai,crai\n'
    # for (k, v) in myjson.iteritems():
    #    app.loader.info("Key: " + k)
    #    app.loader.info("Value: " + str(v))
    # response = make_response(csv)
    # cd = 'attachment; filename=mycsv.csv'
    # response.headers['Content-Disposition'] = cd
    # response.mimetype='text/csv'

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
    # myjson =
    app.logger.info('log de cristo %s',  json.dumps(result))
    # app.logger.info(results, indent=2)
    # objects_list = []
    # for row in users:
    #     d = collections.OrderedDict()
    #     d['id'] = row.id
    #     d['name'] = row.username
    #     d['username'] = row.email
    #     d['email'] = row.name
    #     objects_list.append(d)
    # j = json.dumps(objects_list)
    # app.logger.info('algo', j)
        # t = (row.name, row.username, row.email)
        # rowarray_list.append(t)

    ajson = json.dumps(users)
    # for user in users:
        # app.logger.info(user)
        # pprint(user['username'])
        # if users:
        #         kwargs.update({'args': users})
        #
        #         ajson =  json.dumps(kwargs,  sort_keys = True, indent = 4,
        #        ensure_ascii = True)

        # astring = print(ajson)
    # app.logger.info(ajson)

        # for user in users:
            # app.logger.info(user)
            # pprint(user['username'])
        # d = json.dumps(users, ensure_ascii=False)
        # asjson = json.load(users)
        # app.logger.info(json)

    return render_template('dashboard.html', data=users, json=ajson)

    # cur.close()



if __name__ == "__main__":

    app.secret_key= 'secret123'

    app.run(debug=True)
