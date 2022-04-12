from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField, PasswordField, EmailField, TextAreaField, BooleanField, DateField, \
    SelectField
from wtforms.validators import DataRequired, URL, Length


class CreateNewTask(FlaskForm):
    task = StringField("Task", validators=[DataRequired()])
    start_date = DateField("Start date", validators=[DataRequired()])
    end_date = DateField("End date", validators=[DataRequired()])
    priority = SelectField("Priority", choices=["High", "Medium", "Low"])
    tag = StringField("tag", validators=[Length(min=3, max=10)])
    submit = SubmitField("Add task")

class CreateUser(FlaskForm):
    mail = EmailField("Email", validators=[DataRequired()])
    password = PasswordField("Password", validators=[DataRequired(), Length(min=6, max=25)], id="password_field")
    # show_password = BooleanField('Show password', id='check')
    confirm_password = PasswordField("confirm password", validators=[DataRequired(), Length(min=6, max=25)])
    name = StringField("Name", validators=[DataRequired(), Length(min=2)])
    submit = SubmitField("Register")

class LoginUser(FlaskForm):
    mail = EmailField("Email", validators=[DataRequired()])
    password = PasswordField("Password", validators=[DataRequired()])
    submit = SubmitField("Sign in")

# class UpdateStatus(FlaskForm):
#     task_id
#     status = SelectField("status", choices=["Not started", "In progress", "Completed"])
