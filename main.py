from flask import Flask, render_template, redirect, flash, session, url_for,request
from flask_sqlalchemy import SQLAlchemy
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import DataRequired, EqualTo
import jwt
from functools import wraps
import requests

app = Flask(__name__)
app.app_context().push()
app.config['SECRET_KEY'] = 'gyjghjhmiyjkhhdlkqwoiekndeuyufwrwe-w3dqwde78123jsdmqn312w'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///todo.db'

db = SQLAlchemy(app)

# Database models
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), unique=True, nullable=False)
    password = db.Column(db.String(80), nullable=False)

class Todo(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    item = db.Column(db.String(200), nullable=False)

# Define WTForms login form
class LoginForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Login')

# Define WTForms registration form
class RegistrationForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    confirm_password = PasswordField('Confirm Password', validators=[DataRequired(), EqualTo('password')])
    submit = SubmitField('Register')

class TodoForm(FlaskForm):
    item = StringField('New Item', validators=[DataRequired()])
    submit = SubmitField('Add Item')


# Decorator for protecting routes with authentication
def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None
        if "user" not in session:
            if "token" in request.args.keys():
                # Extract the token from the Authorization header
                token = request.args.get("token")

            if not token:
                flash('Token is missing!', 'error')
                return redirect(url_for('login'))  # Redirect to login page if token is missing

            try:
                # Verify and decode the token
                data = jwt.decode(token, app.config['SECRET_KEY'],algorithms=["HS256"])
                
                current_user = data['username']

            except jwt.ExpiredSignatureError:
                flash('Token has expired!', 'error')
                return redirect(url_for('login'))

            except jwt.InvalidTokenError:
                flash('Invalid token!', 'error')
                return redirect(url_for('login'))
            # Add the current user to the request object for further use
            session["user"] = current_user

        # Call the protected route function
        return f(*args, **kwargs)

    return decorated

# Routes
@app.route('/')
def index():
    return redirect(url_for('register'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()

    if form.validate_on_submit():
        # Handle the login form submission
        username = form.username.data
        password = form.password.data
        

        user = User.query.filter_by(username=username, password=password).first()

        if user:
            token = jwt.encode({'username': username}, app.config['SECRET_KEY'])

            # Redirect to the todo route
            return redirect(url_for('todo',token = token))
            
        flash('Invalid username or password!', 'error')

    return render_template('login.html', form=form)
@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegistrationForm()

    if form.validate_on_submit():
        # Handle the registration form submission
        username = form.username.data
        password = form.password.data

        existing_user = User.query.filter_by(username=username).first()

        if existing_user:
            flash('Username already exists!', 'error')
        else:
            new_user = User(username=username, password=password)
            db.session.add(new_user)
            db.session.commit()

            flash('Registration successful! Please login.', 'success')
            return redirect(url_for('login'))

    return render_template('register.html', form=form)

@app.route('/todo', methods=['GET', 'POST'])
@token_required
def todo():
    
    form = TodoForm()

    if form.validate_on_submit():
        # Handle the to-do form submission
        item = form.item.data

        user = User.query.filter_by(username=session["user"]).first()
        new_todo = Todo(user_id=user.id, item=item)
        db.session.add(new_todo)
        db.session.commit()

        flash('To-Do item added successfully!', 'success')
        return redirect(url_for('todo', token=request.args.get('token')))

    user = User.query.filter_by(username=session["user"]).first()
    todo_list = Todo.query.filter_by(user_id=user.id).all()

    return render_template('todo.html', form=form, current_user=session["user"], todo_list=todo_list)

@app.route('/todo/delete/<int:todo_id>', methods=['POST'])
@token_required
def delete_todo(todo_id):
    todo = Todo.query.get(todo_id)

    if not todo:
        flash('To-Do item not found!', 'error')
    else:
        db.session.delete(todo)
        db.session.commit()
        flash('To-Do item deleted successfully!', 'success')

    return redirect(url_for('todo', token=request.args.get('token')))

@app.route('/todo/update/<int:todo_id>', methods=['POST'])
@token_required
def update_todo(todo_id):
    todo = Todo.query.get(todo_id)

    if not todo:
        flash('To-Do item not found!', 'error')
    else:
        new_item = request.form['item']
        todo.item = new_item
        db.session.commit()
        flash('To-Do item updated successfully!', 'success')

    return redirect(url_for('todo', token=request.args.get('token')))
@app.route("/logout")
@token_required
def logout():
    session.pop("user")
    return redirect(url_for("login"))
if __name__ == '__main__':
    db.create_all()
    app.run(debug=True)
