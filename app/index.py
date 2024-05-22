from flask import render_template, request, redirect, url_for, session, jsonify, send_file, Response, flash
from app import app, login
from app import utils
import cloudinary.uploader
from flask_login import login_user, logout_user, current_user
from flask_login import login_required
from app.models import User, Question,  CHIFFREMENT_CESARQuestion, GameType
import subprocess
import os
from datetime import date, datetime, timedelta
import random
from string import ascii_uppercase
from app import app, db
from random import choice
import random
from sqlalchemy import desc



@app.route("/")
def index():
    top_scores = User.query.order_by(desc(User.score)).limit(10).all()
    return render_template('index.html', top_scores=top_scores)

@app.route("/jouer")
def jouer():
    return render_template('jouer.html')

@app.route("/jouer2")
def jouer2():
    return render_template('indexjeu.html')

@app.route("/Facile")
def Facile():
    return render_template('QCMfacile.html')

@app.route("/Moyen")
def Moyen():
    return render_template('QCMmoyen.html')

@app.route("/Difficile")
def Difficile():
    return render_template('QCMdifficile.html')
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


@app.route('/questions/<level>/<option>/<game>')
@login_required
def get_random_question(level, option, game):
    # Filtrer les questions par niveau, option et jeu
    questions = Question.query.filter_by(level=level, option=option, game=game).all()

    # Vérifier si des questions ont été trouvées
    if questions:
        # Sélectionner une question aléatoire parmi les questions filtrées
        random_question = choice(questions)
        print(game)

        return render_template('questions.html', questions=questions, question=random_question, GameType=GameType, game=game)
    else:
        # Gérer le cas où aucune question n'a été trouvée
        flash("Aucune question disponible pour ce niveau, cette option et ce jeu.", "error")
        return redirect(url_for('jouer2'))



@app.route('/submit_answer', methods=['POST'])
@login_required
def submit_answer():
    question_id = request.form.get('question_id')
    user_answer = request.form.get('answer')
    question = Question.query.get(question_id)
    
    if question:
        correct = user_answer == question.correct_answer
        if correct:
            if question.level == 'Facile':
                score_increase = 1
            elif question.level == 'Moyen':
                score_increase = 2
            elif question.level == 'Difficile':
                score_increase = 3
        else:
            score_increase = 0

        current_user.score += score_increase
        db.session.commit()

    return redirect(url_for('jouer2'))

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True, host="0.0.0.0")