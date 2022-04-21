
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
from flask_gravatar import Gravatar
import os

login_manager = LoginManager()
app = Flask(__name__)
login_manager.init_app(app)
# app.config['SECRET_KEY'] = os.environ.get("SECRET_KEY")
app.config['SECRET_KEY'] = "secretkey"
Bootstrap(app)

app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get("DB_URL", "sqlite:///todo.db")
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)
gravatar = Gravatar(app,
                    size=30,
                    rating='g',
                    default='retro',
                    force_default=False,
                    force_lower=False,
                    use_ssl=False,
                    base_url=None)


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


db.create_all()

@login_manager.user_loader
def load_user(id):
    return User.query.get(id)


@app.route('/', methods=["GET", "POST"])
def home():
    not_started = Task.query.filter_by(status="Not Started").all()
    in_progress = Task.query.filter_by(status="In progress").all()
    completed = Task.query.filter_by(status="Completed").all()
    task_form = CreateNewTask()
    user_form = CreateUser()
    login_form = LoginUser()
    update_status = UpdateStatus()
    error_msg = request.args.get("error_msg")
    if error_msg is None:
        error_msg = ""



    if task_form.validate_on_submit():
        if current_user.is_authenticated:
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
            flash('Task created successfully')
        else:
            error_msg = "Sign up or login to add task"
        return redirect(url_for("home", error_msg=error_msg))
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
                error_msg = "email already exists, Kindly login to continue"
                return redirect(url_for("home", error_msg=error_msg))
            else:
                login_user(new_user, remember=True)
                flash(f'Welcome {current_user.name}')
                return redirect(url_for("home", logged_in=current_user.is_authenticated))
        else:
            error_msg= "Passwords do not match, try again"
            return redirect(url_for("home", error_msg=error_msg))

    elif login_form.validate_on_submit():
        email = login_form.mail.data
        password = login_form.password.data
        user_email = email
        user_password = password
        user = User.query.filter_by(email=user_email).first()
        if not user:
            error_msg = "Invalid email"
            return redirect(url_for("home", error_msg=error_msg))
        else:
            if check_password_hash(pwhash=user.password, password=user_password):
                login_user(user, remember=True)
                flash('You were successfully logged in')
                return redirect(url_for("home", name=user.name,
                                        logged_in=current_user.is_authenticated))
            else:
                error_msg = "Invalid password"
                return redirect(url_for("home", error_msg=error_msg))
    elif update_status.validate_on_submit():
        status = update_status.status.data
        task_id = update_status.task_id.data
        task_to_update = Task.query.get(task_id)
        task_to_update.status = status
        db.session.commit()
        flash('Status updated')
        return redirect(url_for("home"))

    return render_template("index.html", ns=not_started, in_progress=in_progress,
                           completed=completed,
                           logged_in=current_user.is_authenticated,
                           task_form=task_form, user_form=user_form, login_form=login_form,
                           update_form=update_status, error_msg=error_msg)


@app.route("/logout")
def logout():
    logout_user()
    flash('Logged out. log in to see and update your tasks')
    return redirect(url_for('home'))

@app.route("/delete", )
def delete():
    task_id = request.args.get("task_id")
    task_to_delete = Task.query.get(task_id)
    db.session.delete(task_to_delete)
    db.session.commit()
    flash('Task has been deleted')
    return redirect(url_for('home'))


if __name__ == "__main__":
    app.run(host='0.0.0.0', port=5000, debug=True)
