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
from forms import CreateUser, CreateNewTask, LoginUser, UpdateStatus

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
    email = db.Column(db.String(250), unique=True, nullable=False)
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


@app.route('/', methods=["GET", "POST"])
def home():
    not_started = Task.query.filter_by(status="Not Started").all()
    print(not_started)
    in_progress = Task.query.filter_by(status="In progress").all()
    completed = Task.query.filter_by(status="Completed").all()
    task_form = CreateNewTask()
    user_form = CreateUser()
    login_form = LoginUser()
    update_status = UpdateStatus()


    if task_form.validate_on_submit():

        new_task = Task(
            title=task_form.task.data,
            start_date=task_form.start_date.data,
            end_date=task_form.end_date.data,
            priority=task_form.priority.data,
            tag=task_form.tag.data,
            author=current_user
        )
        db.session.add(new_task)
        db.session.commit()
        return redirect(url_for("home"))
    elif user_form.validate_on_submit():
        name = user_form.name.data
        password = user_form.password.data
        confirm = user_form.confirm_password.data
        email = user_form.mail.data

        if confirm == password:

            new_user = User(email=email,
                            password=generate_password_hash(password, method='pbkdf2'
                                                                             ':sha256',
                                                            salt_length=8),
                            name=name
                            )
            try:
                db.session.add(new_user)
                db.session.commit()
            except IntegrityError:
                error = "email already exists"
                return redirect(url_for("home", error=error))
            else:

                login_user(new_user, remember=True)

                return redirect(url_for("home", logged_in=current_user.is_authenticated))
        else:
            flash("Passwords do not match, try again")
    elif login_form.validate_on_submit():
        email = login_form.mail.data
        password = login_form.password.data
        user_email = email
        user_password = password
        user = User.query.filter_by(email=user_email).first()
        if not user:
            error = "Invalid email"
        else:
            if check_password_hash(pwhash=user.password, password=user_password):
                login_user(user, remember=True)
                return redirect(url_for("home", name=user.name,
                                        logged_in=current_user.is_authenticated))
            else:
                error = "Invalid password"
    elif update_status.validate_on_submit():
        status = update_status.status.data
        task_id = update_status.task_id.data
        task_to_update = Task.query.get(task_id)
        task_to_update.status = status
        print(task_id)
        print(status)
        db.session.commit()
        return redirect(url_for("home"))

    return render_template("index.html", ns=not_started, in_progress=in_progress,
                           completed=completed,
                           logged_in=current_user.is_authenticated,
                           task_form=task_form, user_form=user_form, login_form=login_form,
                           update_form=update_status)


@app.route("/logout")
def logout():
    logout_user()
    return redirect(url_for('home'))


if __name__ == "__main__":
    app.run(host='0.0.0.0', port=5000, debug=True)
