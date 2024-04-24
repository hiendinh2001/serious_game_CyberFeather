from flask import render_template, request, redirect, url_for, session, jsonify, send_file, Response
from app import app, login
from app import utils
import cloudinary.uploader
from flask_login import login_user, logout_user, current_user
from flask_login import login_required
import os
from datetime import date, datetime, timedelta
import random
from string import ascii_uppercase

@app.route("/")
def index():
    return render_template('index.html')

@app.route("/jouer")
def jouer():
    return render_template('jouer.html')

@app.route("/jouer2")
def jouer2():
    return render_template('jouer_2.html')

@app.route("/contact")
def contact():
    return render_template('contact.html')

@app.route('/register', methods=['get', 'post'])
def user_register():
    err_msg = ""
    if request.method.__eq__('POST'):
        name = request.form.get('name')
        username = request.form.get('username')
        password = request.form.get('password')
        email = request.form.get('email')
        confirm = request.form.get('confirm')
        avatar_path = None

        try:
            if password.strip().__eq__(confirm.strip()):
                avatar = request.files.get('avatar')
                if avatar:
                    res = cloudinary.uploader.upload(avatar)
                    avatar_path = res['secure_url']

                utils.add_user(name=name,
                               username=username,
                               password=password,
                               email=email,
                               avatar=avatar_path)
                return redirect(url_for('user_signin'))
            else:
                err_msg = 'The re-entered password is incorrect'
        except Exception as ex:
            err_msg = 'Your identifier or email already exists'

    return render_template('register.html',
                           err_msg=err_msg)


@app.route('/user-login', methods=['get', 'post'])
def user_signin():
    err_msg = ""
    if request.method.__eq__('POST'):
        username = request.form.get('username')
        password = request.form.get('password')

        user = utils.check_login(username=username,
                                 password=password)
        if user:
            login_user(user=user)

            return redirect(url_for(request.args.get('next', 'index')))
        else:
            err_msg = "Your identifier or password incorrect"

    return render_template('login.html',
                           err_msg=err_msg)


@app.route('/user-logout')
def user_signout():
    logout_user()
    return redirect(url_for('user_signin'))


@login.user_loader
def user_load(user_id):
    return utils.get_user_by_id(user_id=user_id)

@app.route('/info-perso')
@login_required
def info_perso():
    return render_template('info_perso.html', users=utils.load_user())

if __name__ == '__main__':
    app.run(debug=True, host="0.0.0.0")