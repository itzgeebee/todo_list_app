from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField, PasswordField, EmailField, TextAreaField, BooleanField, DateField, \
    SelectField
from wtforms.validators import DataRequired, URL, Length


class CreateNewTask(FlaskForm):
    task = StringField("Task", validators=[DataRequired()])
    start_date = DateField("Start date", validators=[DataRequired])
    end_date = DateField("End date", validators=[DataRequired])
    priority = SelectField("Priority", choices=["High", "Medium", "Low"])
    tag = StringField("tag", validators=[Length(min=3, max=10)])

class CreateUser(FlaskForm):
    email = EmailField("Email", validators=[DataRequired()])
    password = PasswordField("Password", validators=[DataRequired()])
    name = StringField("Username", validators=[DataRequired(), Length(min=3, max=20)])
    submit = SubmitField("Sign in")