from flask_wtf import FlaskForm
from wtforms import BooleanField, EmailField, PasswordField, StringField, SubmitField
from wtforms.validators import DataRequired, Email, EqualTo, Length


class RegisterForm(FlaskForm):
    username = StringField(
        "Tên đăng nhập",
        validators=[DataRequired(), Length(min=3, max=80)],
    )
    email = EmailField(
        "Email",
        validators=[DataRequired(), Email(), Length(max=120)],
    )
    password = PasswordField(
        "Mật khẩu",
        validators=[DataRequired(), Length(min=8, max=128)],
    )
    confirm_password = PasswordField(
        "Nhập lại mật khẩu",
        validators=[
            DataRequired(),
            EqualTo("password", message="Mật khẩu nhập lại không khớp."),
        ],
    )
    submit = SubmitField("Đăng ký")


class LoginForm(FlaskForm):
    username = StringField(
        "Tên đăng nhập hoặc email",
        validators=[DataRequired(), Length(max=120)],
    )
    password = PasswordField("Mật khẩu", validators=[DataRequired()])
    remember = BooleanField("Ghi nhớ đăng nhập")
    submit = SubmitField("Đăng nhập")
