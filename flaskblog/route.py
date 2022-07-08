from flaskblog.model import User, Post
from flask import render_template, flash, redirect, url_for, request
from flaskblog.forms import RegistrationForm, LoginForm
from flaskblog import app, bcrypt, db
from flask_login import login_user, current_user, logout_user, login_required

posts = [
    {
        'author': 'zrt',
        'title': 'blog1',
        'content': 'this is my first post',
        'date_posted': '2021-01-10'
    },
    {
        'author': 'sxx',
        'title': 'blog2',
        'content': 'this is my second post',
        'date_posted': '2021-01-11'
    }

]


@app.route('/')
@app.route('/home')
def home():
    return render_template('home.html', posts=posts, title='my_blog')


@app.route('/about')
def about():
    return render_template('about.html')


@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('home'))
    form = RegistrationForm()
    if form.validate_on_submit():
        hashed_pw = bcrypt.generate_password_hash(form.password.data).decode('utf-8')
        user = User(username=form.username.data, email=form.email.data, password=hashed_pw)
        db.session.add(user)
        try:
            db.session.commit()
        except:
            db.session.rollback()
            raise
        finally:
            db.session.close()
        flash('Your account has been created! You are now able to log in', 'success')
        return redirect(url_for('login'))
    return render_template('register.html', title='Register', form=form)


@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('home'))
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user and bcrypt.check_password_hash(user.password, form.password.data):
            login_user(user, remember=form.remember.data)
            next_page = request.args.get('next')
            return redirect(next_page) if next_page else redirect(url_for('home'))
        flash('Login Unsuccessful! Please Have A Check!', 'danger')
    return render_template('login.html', title='Login', form=form)


@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('home'))


@app.route('/account')
@login_required
def account():
    return render_template('account.html', title='Account')
