from app import app, db
from flask import render_template, flash, redirect, url_for, request
from flask_login import current_user, login_user, logout_user, login_required
from app.forms import (
    LoginForm,
    RegistrationForm,
    EditProfileForm,
    EmptyForm,
    AddPostForm,
    ResetPasswordRequestForm,
    ResetPasswordForm,
)
from app.models import User, Post
from app.email import send_password_reset_email
from werkzeug.urls import url_parse
from flask import request
from datetime import datetime


@app.route("/")
@app.route("/index")
def index():
    form = AddPostForm()

    page = request.args.get("page", 1, type=int)
    if current_user.is_authenticated:
        posts = current_user.followed_posts().paginate(
            page, app.config["POSTS_PER_PAGE"], False
        )
        next_url = url_for("index", page=posts.next_num) if posts.has_next else None
        prev_url = url_for("index", page=posts.prev_num) if posts.has_prev else None
        return render_template(
            "index.html",
            title="Home",
            posts=posts.items,
            form=form,
            next_url=next_url,
            prev_url=prev_url,
        )
    return render_template("index.html", title="Home",)


@app.route("/login", methods=["GET", "POST"])
def login():
    if current_user.is_authenticated:
        return redirect(url_for("index"))
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if not user or not user.check_password(password=form.password.data):
            flash("Invalid username or password")
            return redirect(url_for("login"))
        login_user(user, remember=form.remember_me.data)
        next_page = request.args.get("next")
        if not next_page or url_parse(next_page).netloc != "":
            next_page = url_for("index")
        return redirect(next_page)
    return render_template("login.html", title="Login", form=form)


@app.route("/logout")
def logout():
    logout_user()
    return redirect(url_for("index"))


@app.route("/register", methods=["GET", "POST"])
def register():
    form = RegistrationForm()
    if form.validate_on_submit():
        user = User(username=form.username.data, email=form.email.data)
        user.set_password(form.password.data)
        db.session.add(user)
        db.session.commit()
        flash("Registration Complete")

        return redirect(url_for("login"))

    return render_template("registration.html", title="Register", form=form)


@app.route("/user/<username>")
@login_required
def user(username):
    form = EmptyForm()
    user = User.query.filter_by(username=username).first_or_404()
    posts = Post.query.filter_by(author=current_user).all()
    return render_template("user.html", user=user, posts=posts, form=form)


@app.before_request
def before_request():
    if current_user.is_authenticated:
        current_user.last_seen = datetime.utcnow()
        db.session.commit()


@app.route("/edit_profile", methods=["GET", "POST"])
@login_required
def edit_profile():
    form = EditProfileForm(current_user.username)

    if form.validate_on_submit():
        current_user.username = form.username.data
        current_user.about_me = form.about_me.data
        db.session.commit()
        flash("Your changes has been saved")
        return redirect(url_for("user", username=current_user.username))
    elif request.method == "GET":
        form.username.data = current_user.username
        form.about_me.data = current_user.about_me
        return render_template("edit_profile.html", title="Edit Profile", form=form)


@app.route("/follow/<username>", methods=["GET", "POST"])
@login_required
def follow(username):
    form = EmptyForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=username).first()
        if user is None:
            flash("User {} does not exist.".format(username))
            return redirect(url_for("index"))
        else:
            current_user.follow(user)
            db.session.commit()
            flash("You are following {}.".format(user.username))
            return redirect(url_for("user", username=username))
    else:
        return redirect(url_for("index"))


@app.route("/unfollow/<username>", methods=["GET", "POST"])
@login_required
def unfollow(username):
    form = EmptyForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=username).first()
        if user is None:
            flash("User {} does not exist.".format(username))
            return redirect(url_for("index"))
        else:
            current_user.unfollow(user)
            db.session.commit()
            flash("You are unfollowing {}.".format(username))
            return redirect(url_for("user", username=username))
    else:
        return redirect(url_for("index"))


@app.route("/post", methods=["GET", "POST"])
@login_required
def post():
    form = AddPostForm(request.form)
    if request.method == "POST" and form.validate():
        p1 = Post(body=form.body.data, author=current_user)
        db.session.add(p1)
        db.session.commit()
        flash("You posted something")
    return redirect(url_for("index"))


@app.route("/explore")
@login_required
def explore():
    page = request.args.get("page", 1, type=int)
    posts = Post.query.order_by(Post.timestamp.desc()).paginate(
        page, app.config["POSTS_PER_PAGE"], False
    )
    next_url = url_for("index", page=posts.next_num) if posts.has_next else None
    prev_url = url_for("index", page=posts.prev_num) if posts.has_prev else None
    return render_template(
        "index.html",
        title="Explore",
        posts=posts.items,
        next_url=next_url,
        prev_url=prev_url,
    )


@app.route("/reset_password_request", methods=["POST", "GET"])
def reset_password_request():
    form = ResetPasswordRequestForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user:
            send_password_reset_email(user)
            flash("Check your email for the instructions to reset your password")
            return redirect(url_for("login"))
        else:
            flash("This user does not exist.")
    return render_template("reset_password_request.html", form=form)


@app.route("/reset_password/<token>", methods=["GET", "POST"])
def reset_password(token):
    if current_user.is_authenticated:
        return redirect(url_for("index"))
    user = User.verify_reset_password_token(token)
    if not user:
        return redirect(url_for("index"))
    form = ResetPasswordForm()
    if form.validate_on_submit():
        user.set_password(form.password.data)
        db.session.commit()
        flash("Your password has been reset.")
        return redirect(url_for("login"))
    return render_template("reset_password.html", form=form)

