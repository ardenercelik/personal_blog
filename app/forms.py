from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, BooleanField, SubmitField, TextAreaField
from wtforms.validators import DataRequired, ValidationError, Email, EqualTo, Length
from app.models import User


class LoginForm(FlaskForm):
    username = StringField("Username", validators=[DataRequired()])
    password = PasswordField("Password", validators=[DataRequired()])
    remember_me = BooleanField("Remember me")
    submit = SubmitField("Sign In")


class RegistrationForm(FlaskForm):
    username = StringField("Username", validators=[(DataRequired())])
    email = StringField("email", validators=[DataRequired(), Email()])
    password = PasswordField("Password", validators=[(DataRequired())])
    password2 = PasswordField(
        "Repeat Password",
        validators=[
            DataRequired(),
            EqualTo("password", message="Passwords must match"),
        ],
    )
    submit = SubmitField("Register")

    def validate_username(self, username):
        username = User.query.filter_by(username=username.data).first()
        if username:
            raise ValidationError("Please use a different username.")

    def validate_username(self, email):
        email = User.query.filter_by(email=email.data).first()
        if email:
            raise ValidationError("Please use a different email address.")


class EditProfileForm(FlaskForm):
    username = StringField("Username", validators=[(DataRequired())])
    about_me = TextAreaField("About me", validators=[Length(min=0, max=140)])
    submit = SubmitField("Submit")

    def __init__(self, original_username, *args, **kwargs):
        super(EditProfileForm, self).__init__(*args, **kwargs)
        self.original_username = original_username

    def validate_username(self, username):
        if username.data != self.original_username:
            check = User.query.filter_by(username=username.data)
            if check is not None:
                raise ValidationError("('Please use a different username.')")


class EmptyForm(FlaskForm):
    submit = SubmitField("Submit")


class AddPostForm(FlaskForm):
    body = TextAreaField("Post", validators=[DataRequired(), Length(min=0, max=140)])
    submit = SubmitField("Submit")


class ResetPasswordRequestForm(FlaskForm):
    email = StringField("Email", validators=[DataRequired(), Email()])
    submit = SubmitField("Reset Password")


class ResetPasswordForm(FlaskForm):
    password = PasswordField("Password", validators=[DataRequired()])
    password2 = PasswordField(
        "Repeat Password", validators=[DataRequired(), EqualTo("password")]
    )
    submit = SubmitField("Request Password Reset")

