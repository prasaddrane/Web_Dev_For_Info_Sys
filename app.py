
from flask import Flask, render_template, redirect, url_for,session
from flask_bootstrap import Bootstrap
from flask_wtf import FlaskForm
from wtforms import  StringField, PasswordField, BooleanField
from wtforms.validators import InputRequired, Email, Length
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_session import sessions
from flask_mail import Mail, Message


app=Flask(__name__)
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 465
app.config['MAIL_USE_SSL'] = True
app.config['MAIL_USERNAME'] = 'docmatepro@gmail.com'
app.config['MAIL_PASSWORD'] = 'docmatesecret'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///E:/Web_Development_for_information_Systems/Project/patient.db'
app.config['SECRET_KEY'] = 'Thisissupposedtobesecret'
Bootstrap(app)
mail = Mail(app)
db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.login_view = 'login'

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(15), unique=True)
    email = db.Column(db.String(50), unique=True)
    password = db.Column(db.String(80))

class PatientInformation(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    firstname = db.Column(db.String(30))
    lastname = db.Column(db.String(30))
    password = db.Column(db.String(80))
    email = db.Column(db.String(50), unique=True)
    phone = db.Column(db.String(15), unique=True)
    address = db.Column(db.String(120))
    symptoms = db.Column(db.String(30))


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))



class LoginForm(FlaskForm):
    username = StringField('Username', validators=[InputRequired(), Length(min=4, max=20)])
    password = PasswordField('Password', validators=[InputRequired(), Length(min=8, max=80)])
    remember = BooleanField('Remember me')

class RegisterForm(FlaskForm):
    email = StringField('Email', validators=[InputRequired(), Email(message='Invalid Email'), Length(max=50)])
    username = StringField('Username', validators=[InputRequired(), Length(min=4, max=20)])
    password = PasswordField('Password', validators=[InputRequired(), Length(min=8, max=80)])

class PatientForm(FlaskForm):
    firstname = StringField('First Name', validators=[InputRequired(), Length(min=3, max=20)])
    lastname = StringField('Last Name', validators=[InputRequired(), Length(min=3, max=20)])
    password = PasswordField('Password', validators=[InputRequired(), Length(min=8, max=80)])
    email = StringField('Email', validators=[InputRequired(), Email(message='Invalid Email'), Length(max=50)])
    phone = StringField('Phone', validators=[InputRequired(), Length(min=10, max=11)])
    address = StringField('Address', validators=[InputRequired(), Length(min=10, max=120)])
    symptoms = StringField(validators=[InputRequired(), Length(min=10, max=120)])

@app.route('/login', methods=['GET','POST'])
def login():
    form = LoginForm()

    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user:
            if check_password_hash(user.password, form.password.data):
                return redirect(url_for('patientinfo'))
        
        return '<h1>Invalid username or password</h1>'


    return render_template('login.html', form=form)
    

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    form = RegisterForm()

    if form.validate_on_submit():
        hashed_password = generate_password_hash(form.password.data, method='sha256')
        new_user = User(username=form.username.data, email=form.email.data, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()
        return '<h1>New User has be created!</h1>' 

    return render_template('signup.html', form=form)

@app.route('/patientinfo', methods=['GET', 'POST'])
#@login_required
def patientinfo():
    form = PatientForm()

    if form.validate_on_submit():
        #return '<h1>' + form.firstname.data + ' ' + form.lastname.data + ' ' +form.password.data + ' ' + form.email.data + ' ' + form.phone.data + ' ' + form.address.data + '</h1>'
        hashed_password = generate_password_hash(form.password.data, method='sha256')
        new_patient = PatientInformation(firstname=form.firstname.data, lastname=form.lastname.data, password=hashed_password, email=form.email.data, phone=form.phone.data, address=form.address.data, symptoms=form.symptoms.data)
        db.session.add(new_patient)
        db.session.commit()
        msg = Message(sender='docmatepro@gmail.com', recipients=['prasaddrane@gmail.com', 'farazmohammad341@gmail.com'])
        msg.html = '<h1>' 'First Name :' + ' ' + form.firstname.data + ' ' + 'Last Name: '+ ' ' + form.lastname.data + ' ' + 'Email Address :'+ ' ' + form.email.data + ' '  + 'Contact Details :' + ' ' + form.phone.data + ' ' + 'Address :' + ' ' + form.address.data + ' '  + 'Symptoms :' + ' '+ form.symptoms.data + '</h1>'
        mail.send(msg)
        return redirect('https://www2.hse.ie/coronavirus/')
        #return '<h1> New Patient has been Registered</h1>'

    return render_template('/patientinfo.html', form=form)

@app.route('/about', methods=['GET', 'POST'])
def about():
    return render_template('about.html')

if __name__=='__main__':
    app.run(debug="True")

