from functools import wraps
import os
from flask import Flask, render_template, redirect, url_for, flash, request
from flask_bootstrap import Bootstrap
from datetime import date, datetime
from sqlalchemy.exc import IntegrityError
from werkzeug.exceptions import abort
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import relationship
from flask_login import UserMixin, login_user, LoginManager, login_required, current_user, logout_user
from forms import CreateUser, CreateNewTask

login_manager = LoginManager()
app = Flask(__name__)
login_manager.init_app(app)
# app.config['SECRET_KEY'] = os.environ.get("SECRET_KEY")
app.config['SECRET_KEY'] = "secretkey"
Bootstrap(app)

app.config['SQLALCHEMY_DATABASE_URI'] = "sqlite:///todo.db"
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)


class Task(db.Model):
    __tablename__ = "tasks"
    id = db.Column(db.Integer, primary_key=True)
    author = db.relationship("User", back_populates="all_tasks")
    title = db.Column(db.String, nullable=False)
    start_date = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    end_date = db.Column(db.DateTime, nullable=False)
    priority = db.Column(db.String, nullable=True)
    tag = db.Column(db.String, nullable=True)
    status = db.Column(db.String, nullable=False, default="Not Started")
    author_id = db.Column(db.Integer, db.ForeignKey('users.id'))


class User(UserMixin, db.Model):
    __tablename__ = "users"
    id = db.Column(db.Integer, primary_key=True)
    mail = db.Column(db.String(250), unique=True, nullable=False)
    password = db.Column(db.String(250), nullable=False)
    name = db.Column(db.String(250), nullable=False)
    all_tasks = db.relationship("Task", back_populates="author")


# db.create_all()


# decorator function for admin login
def admin_only(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if current_user.id != 1 or not current_user.is_authenticated:
            return abort(403, description="Forbidden! You do not have access to this page")
        return f(*args, **kwargs)

    return decorated_function


@login_manager.user_loader
def load_user(id):
    return User.query.get(id)


@app.route('/')
def home():
    tasks = Task.query.all()
    task_form = CreateNewTask()
    user_form = CreateUser()
    if task_form.validate_on_submit():
        new_task = Task(
            title=task_form.task.data,
            start_date=task_form.start_date.data,
            end_date=task_form.end_date.data,
            priority=task_form.priority.data,
            tag=task_form.tag.data
        )
    if user_form.validate_on_submit():
        redirect(url_for("register", ))
    return render_template("index.html", all_tasks=tasks, logged_in=current_user.is_authenticated,
                           task_form=task_form, user_form=user_form)

@app.route('/register', methods=["GET", "POST"])
def register():
    form = CreateUserForm()
    if form.validate_on_submit():
        email = form.email.data
        password = form.password.data
        confirm_password =form.confirm_password.data
        if confirm_password==password:

            new_user = User(email=email,
                            password=generate_password_hash(password, method='pbkdf2'
                                                                                       ':sha256',
                                                            salt_length=8),
                            name=form.name.data
                            )
            try:
                db.session.add(new_user)
                db.session.commit()
            except IntegrityError:
                error = "email already exists"
                return redirect(url_for("login", error=error))
            else:

                login_user(new_user, remember=True)
                return redirect(url_for("home"))
        else:
            flash("Passwords do not match, try again")
            return redirect(url_for("register"))
    return render_template("register.html", form=form, logged_in=current_user.is_authenticated)


if __name__ == "__main__":
    app.run(host='0.0.0.0', port=5000, debug=True)
