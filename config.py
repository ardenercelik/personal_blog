import os

basedir = os.path.abspath(os.path.dirname(__file__))


class Config(object):
    SECRET_KEY = os.environ.get("SECRET_KEY") or "aga bu nedir"
    SQLALCHEMY_DATABASE_URI = os.environ.get(
        "DATABASE_URL"
    ) or "sqlite:///" + os.path.join(basedir, "app.db")
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    MAIL_SERVER = "smtp.googlemail.com"
    MAIL_PORT = 587
    MAIL_USE_TLS = 1
    MAIL_USERNAME = "ardenflaskapp"
    MAIL_PASSWORD = "1905238Dadyan!"
    ADMINS = ["ardenerc@gmail.com"]
    POSTS_PER_PAGE = 3

