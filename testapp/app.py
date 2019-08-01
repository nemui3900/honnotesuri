from flask import Flask, request, make_response, render_template, session, flash, redirect, url_for
from flask_login import LoginManager, current_user, login_user
import pandas as pd
from flask_sqlalchemy import SQLAlchemy
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, BooleanField, SubmitField
from wtforms.validators import DataRequired
from flask_bootstrap import Bootstrap
from werkzeug.security import generate_password_hash, check_password_hash
import random
from datetime import datetime
app = Flask(__name__)
bootstrap = Bootstrap(app)
login = LoginManager(app)
app.secret_key = 'sssss'
df = pd.read_pickle("./static/mokuji0521")
app.config['DEBUG'] = True
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:////tmp/test.db'
db = SQLAlchemy(app)

class LoginForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    remember_me = BooleanField('Remember Me')
    submit = SubmitField('Sign In')

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(64), index=True, unique=True)
    email = db.Column(db.String(120), index=True, unique=True)
    password_hash = db.Column(db.String(128))

    def __repr__(self):
        return '<User {}>'.format(self.username)

class Post(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    body = db.Column(db.String(140))
    timestamp = db.Column(db.DateTime, index=True, default=datetime.utcnow)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))

    def __repr__(self):
        return '<Post {}>'.format(self.body)
@login.user_loader
def load_user(id):
    return User.query.get(int(id))

@app.route('/')
@app.route('/index')
def index():

    return render_template("index.html")

@app.route('/hon/<book_index>')
def hon(book_index):
    title = df['name'][int(book_index)]
    lines = df['mokuji'][int(book_index)].strip().replace('\n',"").split('\r')
    #nl = [i for i in range(10)]
    return render_template("hon.html",title=title,lines=lines)

@app.route('/ga')
def ga():
    count = 10
    booklist = []
    bookprice = []
    try:
        for i in range(count):
            ra = random.randint(0,len(df))
            booklist.append(df['name'][ra])
            bookprice.append(df['price'][ra])
        sum1 = sum(int (i) for i in bookprice)

        return render_template("ga.html",data=zip(booklist,bookprice),psum=sum1)
    except:
        return render_template('error.html'),500

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user is None or not user.check_password(form.password.data):
            flash('Invalid username or password')
            return redirect(url_for('login'))
        login_user(user, remember=form.remember_me.data)
        return redirect(url_for('index'))
    return render_template('login.html', title='Sign In', form=form)
