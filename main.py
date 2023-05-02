

from flask import Flask, render_template, request, session, redirect, url_for
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import login_user,logout_user,login_manager,LoginManager
from flask_login import login_required, current_user



local_server =True # define the local server
app = Flask(__name__)
app.secret_key = 'Mayuresh'

# getting unique user

login_manager=LoginManager(app)
login_manager.login_view='login'

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql://root:@localhost/wooden'
db = SQLAlchemy(app)

# here we passed the endpoints and run the function

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/products')
def products():
    return render_template('products.html')

class Signup(UserMixin,db.Model):
    id = db.Column(db.Integer, primary_key = True )
    fullname = db.Column(db.String(20))
    mobilenumber = db.Column(db.String(11))
    email = db.Column(db.String(20), unique = True)
    pincode = db.Column(db.Integer())
    password = db.Column(db.String(120),nullable=False)


@app.route('/signup', methods=['POST', 'GET'])
def signup():
    if request.method == "POST":
        fullname = request.form.get('fullname')
        mobilenumber = request.form.get('mobilenumber')
        email = request.form.get('email')
        pincode = request.form.get('pincode')
        password = request.form.get('password')



        encpassword=generate_password_hash(password)

        new_user=Signup(fullname=fullname, mobilenumber=mobilenumber,email=email, pincode=pincode, password=encpassword)
        db.session.add(new_user)
        db.session.commit()
        login_user(new_user)
        return redirect(url_for('login.html'))

    return render_template('signup.html')

@app.route('/login', methods=['POST','GET'])
def login():
    if request.method == "POST":
        email = request.form.get('email')
        password = request.form.get('password')
        user=User.query.filter_by(email=email).first()

        if user and check_password_hash(user.password,password):
            login_user(user)
            return redirect(url_for(''))
        else:
            print("Invalid credentials")

    return render_template('login.html')

@app.route('/logout')
def logout():
    return render_template('login.html')

@app.route('/cart')
def cart():
    return render_template('cart.html')



if __name__ == "__main__":
    app.run(debug=True)