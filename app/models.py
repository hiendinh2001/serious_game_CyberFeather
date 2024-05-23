from sqlalchemy import Column, Integer, Boolean, Float, String, Text, ForeignKey, Enum, DateTime, Enum as PgEnum, Text
from sqlalchemy.orm import relationship, backref
from app import db, app
from datetime import datetime
from flask_login import UserMixin
from enum import Enum as UserEnum
from enum import Enum as PyEnum
from sqlalchemy.types import Enum as PgEnum
import enum
from sqlalchemy.types import Enum as PgEnum


class GameType(enum.Enum):
    CHIFFREMENT_CESAR = 'Chiffrement par décalage (César)'
    MOTUS = 'Motus'
    PENDU = 'Pendu'
    QUESTION_SIMPLE = 'Question simple'
    QCM = 'QCM'

class BaseModel(db.Model):
    __abstract__ = True

    id = Column(Integer, primary_key=True, autoincrement=True)

class User(BaseModel, UserMixin):
    name = Column(String(50), nullable=True)
    username = Column(String(50), nullable=True, unique=True)
    password = Column(String(50), nullable=True)
    avatar = Column(String(100))
    email = Column(String(50), nullable=True, unique=True)
    active = Column(Boolean, default=True)
    joined_date = Column(DateTime, default=datetime.now())
    score = Column(Float, default=0.0)

class QuestionOption(db.Model):
    __tablename__ = 'question_options'

    id = Column(Integer, primary_key=True)
    question_id = Column(Integer, ForeignKey('questions.id'), nullable=False)
    option_text = Column(String(100), nullable=False)

    question = relationship('Question', back_populates='options')

class Question(db.Model):
    __tablename__ = 'questions'

    id = Column(Integer, primary_key=True)
    level = Column(String(50), nullable=False)
    option = Column(String(50), nullable=False)
    game = Column(PgEnum(GameType), nullable=False)
    question_text = Column(Text, nullable=False)
    correct_answer = Column(String(100), nullable=False)

    options = relationship('QuestionOption', back_populates='question')

    def __repr__(self):
        return f'<Question {self.question_text}>'

class CHIFFREMENT_CESARQuestion(db.Model):
    __tablename__ = 'CHIFFREMENT_CESAR_questions'

    id = Column(Integer, primary_key=True)
    question_id = Column(Integer, ForeignKey('questions.id'), nullable=False)
    shift = Column(Integer, nullable=False)

    question = relationship('Question', backref=backref('CHIFFREMENT_CESAR_details', uselist=True))


def add_chiffrement_questions():
    questions = [
        {"level": "Facile", "option": "Chiffrement", "game": GameType.CHIFFREMENT_CESAR,
         "question_text": "Vous devez transmettre un message de manière sécurisée en utilisant le chiffrement de César, une méthode de cryptographie simple et l'une des plus anciennes techniques de chiffrement. Pour assurer la sécurité du message, vous décidez d'utiliser un décalage de 6.",
         "correct_answer": "ngskkuttgmk", "shift": 6},
        {"level": "Facile", "option": "Chiffrement", "game": GameType.CHIFFREMENT_CESAR,
         "question_text": "Vous devez transmettre un message de manière sécurisée en utilisant le chiffrement de César, une méthode de cryptographie simple et l'une des plus anciennes techniques de chiffrement. Pour assurer la sécurité du message, vous décidez d'utiliser un décalage de -8.",
         "correct_answer": "xakzafy", "shift": -8},
        {"level": "Facile", "option": "Chiffrement", "game": GameType.CHIFFREMENT_CESAR,
         "question_text": "Vous devez transmettre un message de manière sécurisée en utilisant le chiffrement de César, une méthode de cryptographie simple et l'une des plus anciennes techniques de chiffrement. Pour assurer la sécurité du message, vous décidez d'utiliser un décalage de 22.",
         "correct_answer": "iwhswna", "shift": 22},
        {"level": "Moyen", "option": "Chiffrement", "game": GameType.CHIFFREMENT_CESAR,
         "question_text": "En utilisant le chiffrement de César, chiffrez le mot avec un décalage de 8.",
         "correct_answer": "xqzibiom", "shift": 8},
        {"level": "Moyen", "option": "Chiffrement", "game": GameType.CHIFFREMENT_CESAR,
         "question_text": "En utilisant le chiffrement de César, chiffrez le mot avec un décalage de 3.",
         "correct_answer": "pdozduh", "shift": 3},
        {"level": "Moyen", "option": "Chiffrement", "game": GameType.CHIFFREMENT_CESAR,
         "question_text": "En utilisant le chiffrement de César, chiffrez le mot avec un décalage de -2.",
         "correct_answer": "nfgqfgle", "shift": -2},
        {"level": "Difficile", "option": "Chiffrement", "game": GameType.CHIFFREMENT_CESAR,
         "question_text": "En utilisant le chiffrement de César, déchiffrez le mot avec un décalage de 7.",
         "correct_answer": "encryption", "shift": 7},
        {"level": "Difficile", "option": "Chiffrement", "game": GameType.CHIFFREMENT_CESAR,
         "question_text": "En utilisant le chiffrement de César, chiffrez le mot avec un décalage de 6.",
         "correct_answer": "ngiqkx", "shift": 6},
        {"level": "Difficile", "option": "Chiffrement", "game": GameType.CHIFFREMENT_CESAR,
         "question_text": "En utilisant le chiffrement de César, chiffrez le mot avec un décalage de -3.",
         "correct_answer": "qolgxk", "shift": -3},
    ]

    for q in questions:
        question = Question(level=q['level'], option=q['option'], game=q['game'].value,
                            question_text=q['question_text'], correct_answer=q['correct_answer'])
        db.session.add(question)
        db.session.commit()

        CHIFFREMENT_CESAR_question = CHIFFREMENT_CESARQuestion(question_id=question.id, shift=q['shift'])
        db.session.add(CHIFFREMENT_CESAR_question)

    db.session.commit()

def add_motus_questions():
    questions = [
        {"level": "Moyen", "option": "Chiffrement", "game": GameType.MOTUS,
         "question_text": "Le but est de trouver le mot sans dépasser 6 tentatives ou la partie est perdue. A chaque tentative, les lettres bien placées sont en rouge et celles mal placées en jaune.",
         "correct_answer": "Déchiffrer"},
        {"level": "Moyen", "option": "Chiffrement", "game": GameType.MOTUS,
         "question_text": "Le but est de trouver le mot sans dépasser 6 tentatives ou la partie est perdue. A chaque tentative, les lettres bien placées sont en rouge et celles mal placées en jaune.",
         "correct_answer": "Encodage"},
        {"level": "Moyen", "option": "Chiffrement", "game": GameType.MOTUS,
         "question_text": "Le but est de trouver le mot sans dépasser 6 tentatives ou la partie est perdue. A chaque tentative, les lettres bien placées sont en rouge et celles mal placées en jaune.",
         "correct_answer": "Sécurité"},
        {"level": "Moyen", "option": "Chiffrement", "game": GameType.MOTUS,
         "question_text": "Le but est de trouver le mot sans dépasser 6 tentatives ou la partie est perdue. A chaque tentative, les lettres bien placées sont en rouge et celles mal placées en jaune.",
         "correct_answer": "Algorithme"},
        {"level": "Difficile", "option": "Chiffrement", "game": GameType.MOTUS,
         "question_text": "Le but est de trouver le mot sans dépasser 6 tentatives ou la partie est perdue. A chaque tentative, les lettres bien placées sont en rouge et celles mal placées en jaune.",
         "correct_answer": "Déchiffrement"},
        {"level": "Difficile", "option": "Chiffrement", "game": GameType.MOTUS,
         "question_text": "Le but est de trouver le mot sans dépasser 6 tentatives ou la partie est perdue. A chaque tentative, les lettres bien placées sont en rouge et celles mal placées en jaune.",
         "correct_answer": "Cryptographie"},
        {"level": "Difficile", "option": "Chiffrement", "game": GameType.MOTUS,
         "question_text": "Le but est de trouver le mot sans dépasser 6 tentatives ou la partie est perdue. A chaque tentative, les lettres bien placées sont en rouge et celles mal placées en jaune.",
         "correct_answer": "Cryptanalyse"},
    ]

    for q in questions:
        question = Question(level=q['level'], option=q['option'], game=q['game'].value,
                            question_text=q['question_text'], correct_answer=q['correct_answer'])
        db.session.add(question)

    db.session.commit()

def add_pendu_questions():
    questions = [
        {"level": "Facile", "option": "Chiffrement", "game": GameType.PENDU,
         "question_text": "Jeu du pendu, vous avez 10 tentatives.", "correct_answer": "Déchiffrer"},
        {"level": "Facile", "option": "Chiffrement", "game": GameType.PENDU,
         "question_text": "Jeu du pendu, vous avez 10 tentatives.", "correct_answer": "Cryptographie"},
        {"level": "Facile", "option": "Chiffrement", "game": GameType.PENDU,
         "question_text": "Jeu du pendu, vous avez 10 tentatives.", "correct_answer": "Cryptanalyse"},
        {"level": "Facile", "option": "Chiffrement", "game": GameType.PENDU,
         "question_text": "Jeu du pendu, vous avez 10 tentatives.", "correct_answer": "Encodage"},
        {"level": "Facile", "option": "Chiffrement", "game": GameType.PENDU,
         "question_text": "Jeu du pendu, vous avez 10 tentatives.", "correct_answer": "Déchiffrement"},
        {"level": "Facile", "option": "Chiffrement", "game": GameType.PENDU,
         "question_text": "Jeu du pendu, vous avez 10 tentatives.", "correct_answer": "Sécurité"},
        {"level": "Facile", "option": "Chiffrement", "game": GameType.PENDU,
         "question_text": "Jeu du pendu, vous avez 10 tentatives.", "correct_answer": "Algorithme"},
    ]

    for q in questions:
        question = Question(level=q['level'], option=q['option'], game=q['game'].value,
                            question_text=q['question_text'], correct_answer=q['correct_answer'])
        db.session.add(question)

    db.session.commit()

def add_chiffrement_question():
    questions = [
        {"level": "Facile", "option": "Chiffrement", "game": GameType.QCM,
         "question_text": "Quel est le principal objectif du chiffrement ?", 
         "correct_answer": "Confidentialité des données",
         "options": "Compression des données|Réplication des données|Confidentialité des données|Sauvegarde des données"},
        
        {"level": "Facile", "option": "Chiffrement", "game": GameType.QCM,
         "question_text": "Quel algorithme est utilisé pour le chiffrement symétrique ?", 
         "correct_answer": "DES",
         "options": "RSA|DES|DSA|ECC"},
        
        {"level": "Facile", "option": "Chiffrement", "game": GameType.QCM,
         "question_text": "Quelle est la taille de clé la plus courante pour le chiffrement AES ?", 
         "correct_answer": "128 bits",
         "options": "64 bits|128 bits|256 bits|512 bits"},
        
        {"level": "Moyen", "option": "Chiffrement", "game": GameType.QCM,
         "question_text": "Quel algorithme utilise une clé publique et une clé privée ?", 
         "correct_answer": "RSA",
         "options": "AES|RSA|SHA-256|MD5"},
        
        {"level": "Moyen", "option": "Chiffrement", "game": GameType.QCM,
         "question_text": "Quelle est la principale caractéristique du chiffrement asymétrique ?", 
         "correct_answer": "Utilise des clés différentes pour le chiffrement et le déchiffrement",
         "options": "Utilise la même clé pour le chiffrement et le déchiffrement|Utilise des clés différentes pour le chiffrement et le déchiffrement|Utilise uniquement une clé privée|Utilise uniquement une clé publique"},
        
        {"level": "Moyen", "option": "Chiffrement", "game": GameType.QCM,
         "question_text": "Quelle taille de clé est recommandée pour AES ?", 
         "correct_answer": "128 bits",
         "options": "56 bits|128 bits|512 bits|1024 bits"},
        
        {"level": "Difficile", "option": "Chiffrement", "game": GameType.QCM,
         "question_text": "Quelle est la différence principale entre le chiffrement symétrique et asymétrique ?", 
         "correct_answer": "Le nombre de clés utilisées",
         "options": "La vitesse de chiffrement|La longueur des clés|Le nombre de clés utilisées|La méthode de déchiffrement"},
        
        {"level": "Difficile", "option": "Chiffrement", "game": GameType.QCM,
         "question_text": "Quel algorithme de chiffrement est considéré comme inviolable en théorie ?", 
         "correct_answer": "One-time pad",
         "options": "Triple DES|One-time pad|Blowfish|Twofish"},
        
        {"level": "Difficile", "option": "Chiffrement", "game": GameType.QCM,
         "question_text": "Quel algorithme est utilisé dans le protocole SSL/TLS pour sécuriser les communications ?", 
         "correct_answer": "Diffie-Hellman",
         "options": "RSA|AES|Diffie-Hellman|MD5"}
    ]

    for q in questions:
        question = Question(
            level=q["level"],
            option=q["option"],
            game=q["game"],
            question_text=q["question_text"],
            correct_answer=q["correct_answer"]
        )

        options_list = q["options"].split("|")
        for option_text in options_list:
            option = QuestionOption(option_text=option_text)
            question.options.append(option)

        db.session.add(question)

    try:
        db.session.commit()
    except Exception as e:
        db.session.rollback()
        print(f"Error: {e}")

def add_simple_encryption_questions():
    questions = [
        # Niveau Facile
        {"level": "Facile", "option": "Chiffrement", "game": GameType.QUESTION_SIMPLE, "question_text": "Quel est le terme utilisé pour désigner la transformation d'un message en un format illisible afin de le rendre secret ?", "correct_answer": "Cryptage"},
        {"level": "Facile", "option": "Chiffrement", "game": GameType.QUESTION_SIMPLE, "question_text": "Quel est le nom de l'algorithme de chiffrement symétrique le plus utilisé ?", "correct_answer": "AES"},
        {"level": "Facile", "option": "Chiffrement", "game": GameType.QUESTION_SIMPLE, "question_text": "Quel est le processus consistant à rendre un message illisible sans avoir besoin d'une clé pour le déchiffrer ?", "correct_answer": "Hachage"},
        
        # Niveau Moyen
        {"level": "Moyen", "option": "Chiffrement", "game": GameType.QUESTION_SIMPLE, "question_text": "Quel est le nom de l'algorithme de chiffrement asymétrique largement utilisé pour le chiffrement des e-mails ?", "correct_answer": "RSA"},
        {"level": "Moyen", "option": "Chiffrement", "game": GameType.QUESTION_SIMPLE, "question_text": "Quel est le nom de l'algorithme de chiffrement utilisé pour sécuriser les transactions en ligne ?", "correct_answer": "SSL/TLS"},
        
        # Niveau Difficile
        {"level": "Difficile", "option": "Chiffrement", "game": GameType.QUESTION_SIMPLE, "question_text": "Quel est le nom de l'algorithme de chiffrement symétrique populaire qui utilise des blocs de données de 128 bits ?", "correct_answer": "DES"},
        {"level": "Difficile", "option": "Chiffrement", "game": GameType.QUESTION_SIMPLE, "question_text": "Quel est le nom de l'algorithme de chiffrement utilisé pour le chiffrement de bout en bout dans l'application de messagerie WhatsApp ?", "correct_answer": "Signal Protocol"}
    ]

    # Ajout des questions à la base de données
    for q in questions:
        question = Question(
            level=q["level"],
            option=q["option"],
            game=q["game"],
            question_text=q["question_text"],
            correct_answer=q["correct_answer"]
        )
        db.session.add(question)

    # Commit des changements
    db.session.commit()


def add_attack_questions():
    questions = [
        {"level": "Facile", "option": "Attaque", "game": GameType.QUESTION_SIMPLE,
         "question_text": "Quel type d'attaque vise à tromper les utilisateurs pour obtenir des informations confidentielles telles que des mots de passe ?",
         "correct_answer": "phishing"},
        {"level": "Facile", "option": "Attaque", "game": GameType.QUESTION_SIMPLE,
         "question_text": "Quel est le terme pour décrire une pièce de logiciel conçue pour se propager et causer des dommages ?",
         "correct_answer": "virus"},
        {"level": "Facile", "option": "Attaque", "game": GameType.QUESTION_SIMPLE,
         "question_text": "Quel terme désigne une tentative d'accès non autorisé à un système informatique ?",
         "correct_answer": "piratage"},
        {"level": "Facile", "option": "Attaque", "game": GameType.QCM,
         "question_text": "Quel type d'attaque consiste à submerger un système avec une grande quantité de trafic pour le rendre indisponible ?",
         "correct_answer": "Attaque par déni de service",
         "options": "Attaque par déni de service|Ransomware|Injection SQL"},
        {"level": "Moyen", "option": "Attaque", "game": GameType.QUESTION_SIMPLE,
         "question_text": "Quel est le nom de l'attaque où un attaquant intercepte et modifie les communications entre deux parties sans leur consentement ?",
         "correct_answer": "man in the middle"},
        {"level": "Moyen", "option": "Attaque", "game": GameType.QUESTION_SIMPLE,
         "question_text": "Quel type d'attaque exploite les failles de sécurité d'un logiciel pour exécuter du code malveillant ?",
         "correct_answer": "exploit"},
        {"level": "Moyen", "option": "Attaque", "game": GameType.QUESTION_SIMPLE,
         "question_text": "Quelle est la pratique consistant à deviner des mots de passe en essayant différentes combinaisons de lettres, chiffres et symboles ?",
         "correct_answer": "brute force"},
        {"level": "Difficile", "option": "Attaque", "game": GameType.QUESTION_SIMPLE,
         "question_text": "Quel est le nom de l'attaque où un attaquant exploite une faiblesse humaine pour obtenir des informations confidentielles, généralement en se faisant passer pour une personne de confiance ?",
         "correct_answer": "ingenierie sociale"},
        {"level": "Difficile", "option": "Attaque", "game": GameType.QCM,
         "question_text": "Quelle est la technique d'attaque qui consiste à cacher du code malveillant dans des fichiers multimédias, tels que des images ou des vidéos ?",
         "correct_answer": "Steganographie",
         "options": "Steganographie|Attaque par pièce jointe malveillante|Empoisonnement du cache DNS"},
        {"level": "Difficile", "option": "Attaque", "game": GameType.QUESTION_SIMPLE,
         "question_text": "Quel est le terme pour une attaque qui cible spécifiquement les bases de données pour extraire des informations sensibles ?",
         "correct_answer": "injection sql"},
        {"level": "Difficile", "option": "Attaque", "game": GameType.QUESTION_SIMPLE,
         "question_text": "Quel type d'attaque utilise des logiciels malveillants pour chiffrer les fichiers d'un utilisateur et demander une rançon en échange de la clé de déchiffrement ?",
         "correct_answer": "ransomware"},
        {"level": "Moyen", "option": "Attaque", "game": GameType.MOTUS,
         "question_text": "Le but est de trouver le mot sans dépasser 6 tentatives ou la partie est perdue. A chaque tentative, les lettres bien placées sont en rouge et celles mal placées en jaune.",
         "correct_answer": "Phishing"},
        {"level": "Moyen", "option": "Attaque", "game": GameType.MOTUS,
         "question_text": "Le but est de trouver le mot sans dépasser 6 tentatives ou la partie est perdue. A chaque tentative, les lettres bien placées sont en rouge et celles mal placées en jaune.",
         "correct_answer": "Malware"},
        {"level": "Facile", "option": "Attaque", "game": GameType.MOTUS,
         "question_text": "Le but est de trouver le mot sans dépasser 6 tentatives ou la partie est perdue. A chaque tentative, les lettres bien placées sont en rouge et celles mal placées en jaune.",
         "correct_answer": "Virus"},
        {"level": "Difficile", "option": "Attaque", "game": GameType.MOTUS,
         "question_text": "Le but est de trouver le mot sans dépasser 6 tentatives ou la partie est perdue. A chaque tentative, les lettres bien placées sont en rouge et celles mal placées en jaune.",
         "correct_answer": "Ransomware"},
        {"level": "Difficile", "option": "Attaque", "game": GameType.MOTUS,
         "question_text": "Le but est de trouver le mot sans dépasser 6 tentatives ou la partie est perdue. A chaque tentative, les lettres bien placées sont en rouge et celles mal placées en jaune.",
         "correct_answer": "Spyware"},
        {"level": "Difficile", "option": "Attaque", "game": GameType.MOTUS,
         "question_text": "Le but est de trouver le mot sans dépasser 6 tentatives ou la partie est perdue. A chaque tentative, les lettres bien placées sont en rouge et celles mal placées en jaune.",
         "correct_answer": "Trojans"},
        {"level": "Moyen", "option": "Attaque", "game": GameType.MOTUS,
         "question_text": "Le but est de trouver le mot sans dépasser 6 tentatives ou la partie est perdue. A chaque tentative, les lettres bien placées sont en rouge et celles mal placées en jaune.",
         "correct_answer": "Worms"},
        {"level": "Moyen", "option": "Attaque", "game": GameType.MOTUS,
         "question_text": "Le but est de trouver le mot sans dépasser 6 tentatives ou la partie est perdue. A chaque tentative, les lettres bien placées sont en rouge et celles mal placées en jaune.",
         "correct_answer": "Botnet"},
        {"level": "Facile", "option": "Attaque", "game": GameType.PENDU,
         "question_text": "Jeu du pendu, vous avez 10 tentatives.", "correct_answer": "Phishing"},
        {"level": "Facile", "option": "Attaque", "game": GameType.PENDU,
         "question_text": "Jeu du pendu, vous avez 10 tentatives.", "correct_answer": "Malware"},
        {"level": "Facile", "option": "Attaque", "game": GameType.PENDU,
         "question_text": "Jeu du pendu, vous avez 10 tentatives.", "correct_answer": "Virus"},
        {"level": "Facile", "option": "Attaque", "game": GameType.PENDU,
         "question_text": "Jeu du pendu, vous avez 10 tentatives.", "correct_answer": "Ransomware"},
        {"level": "Facile", "option": "Attaque", "game": GameType.PENDU,
         "question_text": "Jeu du pendu, vous avez 10 tentatives.", "correct_answer": "Spyware"},
        {"level": "Facile", "option": "Attaque", "game": GameType.PENDU,
         "question_text": "Jeu du pendu, vous avez 10 tentatives.", "correct_answer": "Trojans"},
        {"level": "Facile", "option": "Attaque", "game": GameType.PENDU,
         "question_text": "Jeu du pendu, vous avez 10 tentatives.", "correct_answer": "Worms"},
        {"level": "Facile", "option": "Attaque", "game": GameType.PENDU,
         "question_text": "Jeu du pendu, vous avez 10 tentatives.", "correct_answer": "Botnet"}
    ]

    for q in questions:
        question = Question(
            level=q["level"],
            option=q["option"],
            game=q["game"],
            question_text=q["question_text"],
            correct_answer=q["correct_answer"]
        )

        if "options" in q:
            options_list = q["options"].split("|")
            for option_text in options_list:
                option = QuestionOption(option_text=option_text)
                question.options.append(option)

        db.session.add(question)

    db.session.commit()

def add_attack_question():
    questions = [
        # Niveau Facile
        {"level": "Facile", "option": "Attaque", "game": GameType.QCM,
         "question_text": "Quel type d'attaque consiste à submerger un système avec une grande quantité de trafic pour le rendre indisponible ?",
         "correct_answer": "Attaque par déni de service",
         "options": "Attaque par déni de service|Ransomware|Injection SQL|Phishing"},
        
        {"level": "Facile", "option": "Attaque", "game": GameType.QCM,
         "question_text": "Quel type d'attaque consiste à inciter l'utilisateur à cliquer sur un lien malveillant ?",
         "correct_answer": "Phishing",
         "options": "Phishing|Injection SQL|Attaque par force brute|Spyware"},
        
        {"level": "Facile", "option": "Attaque", "game": GameType.QCM,
         "question_text": "Quel type d'attaque exploite les vulnérabilités d'une application web pour exécuter du code malveillant ?",
         "correct_answer": "Injection SQL",
         "options": "Injection SQL|Ransomware|Attaque par déni de service|Spyware"},
        
        # Niveau Moyen
        {"level": "Moyen", "option": "Attaque", "game": GameType.QCM,
         "question_text": "Quel type d'attaque implique la capture et l'analyse des paquets réseau ?",
         "correct_answer": "Sniffing",
         "options": "Sniffing|Phishing|Ransomware|Injection SQL"},
        
        {"level": "Moyen", "option": "Attaque", "game": GameType.QCM,
         "question_text": "Quel type d'attaque utilise un réseau de machines compromises pour lancer une attaque coordonnée ?",
         "correct_answer": "Botnet",
         "options": "Botnet|Phishing|Spyware|Sniffing"},
        
        {"level": "Moyen", "option": "Attaque", "game": GameType.QCM,
         "question_text": "Quel type d'attaque cible spécifiquement les utilisateurs pour voler leurs informations personnelles ?",
         "correct_answer": "Phishing",
         "options": "Phishing|Injection SQL|Sniffing|Botnet"},
        
        # Niveau Difficile
        {"level": "Difficile", "option": "Attaque", "game": GameType.QCM,
         "question_text": "Quel type d'attaque manipule les requêtes DNS pour rediriger le trafic vers des sites malveillants ?",
         "correct_answer": "Attaque par empoisonnement DNS",
         "options": "Attaque par empoisonnement DNS|Injection SQL|Phishing|Ransomware"},
        
        {"level": "Difficile", "option": "Attaque", "game": GameType.QCM,
         "question_text": "Quel type d'attaque exploite les faiblesses des protocoles de sécurité Wi-Fi pour intercepter les communications ?",
         "correct_answer": "Attaque par KRACK",
         "options": "Attaque par KRACK|Injection SQL|Phishing|Botnet"},
        
        {"level": "Difficile", "option": "Attaque", "game": GameType.QCM,
         "question_text": "Quel type d'attaque consiste à deviner des mots de passe en essayant toutes les combinaisons possibles ?",
         "correct_answer": "Attaque par force brute",
         "options": "Attaque par force brute|Phishing|Sniffing|Botnet"}
    ]

    for q in questions:
        question = Question(
            level=q["level"],
            option=q["option"],
            game=q["game"],
            question_text=q["question_text"],
            correct_answer=q["correct_answer"]
        )

        options_list = q["options"].split("|")
        for option_text in options_list:
            option = QuestionOption(option_text=option_text)
            question.options.append(option)

        db.session.add(question)

    try:
        db.session.commit()
    except Exception as e:
        db.session.rollback()
        print(f"Error: {e}")

def add_linux_questions():
    questions = [
        {"level": "Facile", "option": "Linux", "game": GameType.QUESTION_SIMPLE, "question_text": "Quel est le nom du super-utilisateur sous Linux ?", "correct_answer": "root"},
        {"level": "Facile", "option": "Linux", "game": GameType.QUESTION_SIMPLE, "question_text": "Quel symbole est utilisé pour indiquer le répertoire personnel d'un utilisateur ?", "correct_answer": "~"},
        {"level": "Facile", "option": "Linux", "game": GameType.QUESTION_SIMPLE, "question_text": "Quelle commande permet de changer de répertoire ?", "correct_answer": "cd"},
        {"level": "Facile", "option": "Linux", "game": GameType.QUESTION_SIMPLE, "question_text": "Quelle commande affiche le contenu d'un répertoire ?", "correct_answer": "ls"},
        {"level": "Moyen", "option": "Linux", "game": GameType.QUESTION_SIMPLE, "question_text": "Quelle commande permet de copier des fichiers ou des répertoires ?", "correct_answer": "cp"},
        {"level": "Moyen", "option": "Linux", "game": GameType.QUESTION_SIMPLE, "question_text": "Quel fichier contient les informations sur les utilisateurs du système ?", "correct_answer": "passwd"},
        {"level": "Moyen", "option": "Linux", "game": GameType.QUESTION_SIMPLE, "question_text": "Quel utilitaire est utilisé pour installer des paquets sous Debian et ses dérivés ?", "correct_answer": "apt"},
        {"level": "Moyen", "option": "Linux", "game": GameType.QUESTION_SIMPLE, "question_text": "Quel fichier, avec le chemin, contient les informations de configuration des réseaux sous Linux ? Ecrire la réponse sous la forme abc/defgh/ijklm.", "correct_answer": "etc/network/interfaces"},
        {"level": "Moyen", "option": "Linux", "game": GameType.QUESTION_SIMPLE, "question_text": "Quelle commande permet de modifier les permissions d'un fichier ou d'un répertoire ?", "correct_answer": "chmod"},
        {"level": "Difficile", "option": "Linux", "game": GameType.QUESTION_SIMPLE, "question_text": "Quel gestionnaire de démarrage est couramment utilisé sous Linux ? (réponse en majuscules)", "correct_answer": "GRUB"},
        {"level": "Difficile", "option": "Linux", "game": GameType.QUESTION_SIMPLE, "question_text": "Quelle commande permet de créer une nouvelle partition sur un disque dur ?", "correct_answer": "fdisk"},
        {"level": "Difficile", "option": "Linux", "game": GameType.QUESTION_SIMPLE, "question_text": "Quelle commande permet de trouver des fichiers et des répertoires en fonction de divers critères tels que le nom, la date ou la taille ?", "correct_answer": "find"},
        {"level": "Difficile", "option": "Linux", "game": GameType.QUESTION_SIMPLE, "question_text": "Quel est le nom du système de gestion de versions décentralisé couramment utilisé par les développeurs sous Linux ?", "correct_answer": "git"},
        {"level": "Difficile", "option": "Linux", "game": GameType.QUESTION_SIMPLE, "question_text": "Quelle commande permet de visualiser les journaux du système et des applications sous Linux ?", "correct_answer": "journalctl"},
        {"level": "Facile", "option": "Linux", "game": GameType.MOTUS, "question_text": "Le but est de trouver le mot sans dépasser 6 tentatives ou la partie est perdue. A chaque tentative, les lettres bien placées sont en rouge et celles mal placées en jaune.", "correct_answer": "Terminal"},
        {"level": "Facile", "option": "Linux", "game": GameType.MOTUS, "question_text": "Le but est de trouver le mot sans dépasser 6 tentatives ou la partie est perdue. A chaque tentative, les lettres bien placées sont en rouge et celles mal placées en jaune.", "correct_answer": "Command"},
        {"level": "Facile", "option": "Linux", "game": GameType.MOTUS, "question_text": "Le but est de trouver le mot sans dépasser 6 tentatives ou la partie est perdue. A chaque tentative, les lettres bien placées sont en rouge et celles mal placées en jaune.", "correct_answer": "Kernel"},
        {"level": "Facile", "option": "Linux", "game": GameType.MOTUS, "question_text": "Le but est de trouver le mot sans dépasser 6 tentatives ou la partie est perdue. A chaque tentative, les lettres bien placées sont en rouge et celles mal placées en jaune.", "correct_answer": "Package"},
        {"level": "Facile", "option": "Linux", "game": GameType.MOTUS, "question_text": "Le but est de trouver le mot sans dépasser 6 tentatives ou la partie est perdue. A chaque tentative, les lettres bien placées sont en rouge et celles mal placées en jaune.", "correct_answer": "Desktop"},
        {"level": "Facile", "option": "Linux", "game": GameType.MOTUS, "question_text": "Le but est de trouver le mot sans dépasser 6 tentatives ou la partie est perdue. A chaque tentative, les lettres bien placées sont en rouge et celles mal placées en jaune.", "correct_answer": "Network"},
        {"level": "Moyen", "option": "Linux", "game": GameType.MOTUS, "question_text": "Le but est de trouver le mot sans dépasser 6 tentatives ou la partie est perdue. A chaque tentative, les lettres bien placées sont en rouge et celles mal placées en jaune.", "correct_answer": "Distribution"},
        {"level": "Moyen", "option": "Linux", "game": GameType.MOTUS, "question_text": "Le but est de trouver le mot sans dépasser 6 tentatives ou la partie est perdue. A chaque tentative, les lettres bien placées sont en rouge et celles mal placées en jaune.", "correct_answer": "Filesystem"},
        {"level": "Moyen", "option": "Linux", "game": GameType.MOTUS, "question_text": "Le but est de trouver le mot sans dépasser 6 tentatives ou la partie est perdue. A chaque tentative, les lettres bien placées sont en rouge et celles mal placées en jaune.", "correct_answer": "Compilation"},
        {"level": "Difficile", "option": "Linux", "game": GameType.MOTUS, "question_text": "Le but est de trouver le mot sans dépasser 6 tentatives ou la partie est perdue. A chaque tentative, les lettres bien placées sont en rouge et celles mal placées en jaune.", "correct_answer": "Virtualization"},
        {"level": "Difficile", "option": "Linux", "game": GameType.MOTUS, "question_text": "Le but est de trouver le mot sans dépasser 6 tentatives ou la partie est perdue. A chaque tentative, les lettres bien placées sont en rouge et celles mal placées en jaune.", "correct_answer": "Configuration"},
        {"level": "Difficile", "option": "Linux", "game": GameType.MOTUS, "question_text": "Le but est de trouver le mot sans dépasser 6 tentatives ou la partie est perdue. A chaque tentative, les lettres bien placées sont en rouge et celles mal placées en jaune.", "correct_answer": "Permissions"},
        {"level": "Difficile", "option": "Linux", "game": GameType.MOTUS, "question_text": "Le but est de trouver le mot sans dépasser 6 tentatives ou la partie est perdue. A chaque tentative, les lettres bien placées sont en rouge et celles mal placées en jaune.", "correct_answer": "Environment"},
        {"level": "Difficile", "option": "Linux", "game": GameType.MOTUS, "question_text": "Le but est de trouver le mot sans dépasser 6 tentatives ou la partie est perdue. A chaque tentative, les lettres bien placées sont en rouge et celles mal placées en jaune.", "correct_answer": "Authentication"},
        {"level": "Difficile", "option": "Linux", "game": GameType.MOTUS, "question_text": "Le but est de trouver le mot sans dépasser 6 tentatives ou la partie est perdue. A chaque tentative, les lettres bien placées sont en rouge et celles mal placées en jaune.", "correct_answer": "Superuser"},
        {"level": "Moyen", "option": "Linux", "game": GameType.MOTUS, "question_text": "Le but est de trouver le mot sans dépasser 6 tentatives ou la partie est perdue. A chaque tentative, les lettres bien placées sont en rouge et celles mal placées en jaune.", "correct_answer": "Repository"},
        {"level": "Facile", "option": "Linux", "game": GameType.PENDU, "question_text": "Jeu du pendu, vous avez 10 tentatives.", "correct_answer": "Terminal"},
        {"level": "Facile", "option": "Linux", "game": GameType.PENDU, "question_text": "Jeu du pendu, vous avez 10 tentatives.", "correct_answer": "Command"},
        {"level": "Facile", "option": "Linux", "game": GameType.PENDU, "question_text": "Jeu du pendu, vous avez 10 tentatives.", "correct_answer": "Kernel"},
        {"level": "Facile", "option": "Linux", "game": GameType.PENDU, "question_text": "Jeu du pendu, vous avez 10 tentatives.", "correct_answer": "Package"},
        {"level": "Facile", "option": "Linux", "game": GameType.PENDU, "question_text": "Jeu du pendu, vous avez 10 tentatives.", "correct_answer": "Desktop"},
        {"level": "Facile", "option": "Linux", "game": GameType.PENDU, "question_text": "Jeu du pendu, vous avez 10 tentatives.", "correct_answer": "Network"},
        {"level": "Facile", "option": "Linux", "game": GameType.PENDU, "question_text": "Jeu du pendu, vous avez 10 tentatives.", "correct_answer": "Distribution"},
        {"level": "Facile", "option": "Linux", "game": GameType.PENDU, "question_text": "Jeu du pendu, vous avez 10 tentatives.", "correct_answer": "Filesystem"},
        {"level": "Moyen", "option": "Linux", "game": GameType.PENDU, "question_text": "Jeu du pendu, vous avez 10 tentatives.", "correct_answer": "Compilation"},
        {"level": "Moyen", "option": "Linux", "game": GameType.PENDU, "question_text": "Jeu du pendu, vous avez 10 tentatives.", "correct_answer": "Virtualization"},
        {"level": "Moyen", "option": "Linux", "game": GameType.PENDU, "question_text": "Jeu du pendu, vous avez 10 tentatives.", "correct_answer": "Configuration"},
        {"level": "Moyen", "option": "Linux", "game": GameType.PENDU, "question_text": "Jeu du pendu, vous avez 10 tentatives.", "correct_answer": "Permissions"},
        {"level": "Moyen", "option": "Linux", "game": GameType.PENDU, "question_text": "Jeu du pendu, vous avez 10 tentatives.", "correct_answer": "Environment"},
        {"level": "Moyen", "option": "Linux", "game": GameType.PENDU, "question_text": "Jeu du pendu, vous avez 10 tentatives.", "correct_answer": "Authentication"},
        {"level": "Moyen", "option": "Linux", "game": GameType.PENDU, "question_text": "Jeu du pendu, vous avez 10 tentatives.", "correct_answer": "Superuser"},
        {"level": "Moyen", "option": "Linux", "game": GameType.PENDU, "question_text": "Jeu du pendu, vous avez 10 tentatives.", "correct_answer": "Repository"}
    ]

    for q in questions:
        question = Question(**q)
        db.session.add(question)

    db.session.commit()

def add_linux_question():
    questions = [
        # Niveau Facile
        {"level": "Facile", "option": "Linux", "game": GameType.QCM,
         "question_text": "Quelle commande permet de lister les fichiers et répertoires dans un répertoire sous Linux ?",
         "correct_answer": "ls",
         "options": "ls|cd|rm|touch"},
        
        {"level": "Facile", "option": "Linux", "game": GameType.QCM,
         "question_text": "Quelle commande permet de changer de répertoire sous Linux ?",
         "correct_answer": "cd",
         "options": "cd|ls|rm|touch"},
        
        {"level": "Facile", "option": "Linux", "game": GameType.QCM,
         "question_text": "Quelle commande permet de créer un fichier vide sous Linux ?",
         "correct_answer": "touch",
         "options": "touch|rm|ls|cd"},
        
        # Niveau Moyen
        {"level": "Moyen", "option": "Linux", "game": GameType.QCM,
         "question_text": "Quelle commande permet de copier des fichiers sous Linux ?",
         "correct_answer": "cp",
         "options": "cp|mv|rm|touch"},
        
        {"level": "Moyen", "option": "Linux", "game": GameType.QCM,
         "question_text": "Quelle commande permet de déplacer ou renommer un fichier sous Linux ?",
         "correct_answer": "mv",
         "options": "mv|cp|rm|ls"},
        
        {"level": "Moyen", "option": "Linux", "game": GameType.QCM,
         "question_text": "Quelle commande permet d'afficher le contenu d'un fichier sous Linux ?",
         "correct_answer": "cat",
         "options": "cat|ls|touch|rm"},
        
        # Niveau Difficile
        {"level": "Difficile", "option": "Linux", "game": GameType.QCM,
         "question_text": "Quelle commande permet de modifier les permissions d'un fichier sous Linux ?",
         "correct_answer": "chmod",
         "options": "chmod|chown|chgrp|ls"},
        
        {"level": "Difficile", "option": "Linux", "game": GameType.QCM,
         "question_text": "Quelle commande permet de modifier le propriétaire d'un fichier sous Linux ?",
         "correct_answer": "chown",
         "options": "chown|chmod|chgrp|ls"},
        
        {"level": "Difficile", "option": "Linux", "game": GameType.QCM,
         "question_text": "Quelle commande permet de rechercher des fichiers par nom dans le système de fichiers sous Linux ?",
         "correct_answer": "find",
         "options": "find|grep|locate|which"}
    ]

    for q in questions:
        question = Question(
            level=q["level"],
            option=q["option"],
            game=q["game"],
            question_text=q["question_text"],
            correct_answer=q["correct_answer"]
        )

        options_list = q["options"].split("|")
        for option_text in options_list:
            option = QuestionOption(option_text=option_text)
            question.options.append(option)

        db.session.add(question)

    try:
        db.session.commit()
    except Exception as e:
        db.session.rollback()
        print(f"Error: {e}")

def add_network_security_questions():
    questions = [
        {"level": "Facile", "option": "Securite_des_reseaux", "game": GameType.QUESTION_SIMPLE, "question_text": "La réponse doit être écrite en minuscule, sans accent, sans caractère spécial. Les espaces sont autorisés.", "correct_answer": "cryptographie"},
        {"level": "Facile", "option": "Securite_des_reseaux", "game": GameType.QUESTION_SIMPLE, "question_text": "La réponse doit être écrite en minuscule, sans accent, sans caractère spécial. Les espaces sont autorisés.", "correct_answer": "pare feu"},
        {"level": "Facile", "option": "Securite_des_reseaux", "game": GameType.QUESTION_SIMPLE, "question_text": "La réponse doit être écrite en minuscule, sans accent, sans caractère spécial. Les espaces sont autorisés.", "correct_answer": "https"},
        {"level": "Facile", "option": "Securite_des_reseaux", "game": GameType.QUESTION_SIMPLE, "question_text": "La réponse doit être écrite en minuscule, sans accent, sans caractère spécial. Les espaces sont autorisés.", "correct_answer": "mot de passe"},
        {"level": "Facile", "option": "Securite_des_reseaux", "game": GameType.QCM, "question_text": "Sélectionner une des propositions", "correct_answer": "Authentification", "options": "Chiffrement|Pare-feu"},
        {"level": "Moyen", "option": "Securite_des_reseaux", "game": GameType.QCM, "question_text": "Sélectionner une des propositions", "correct_answer": "IPsec", "options": "FTP|DHCP"},
        {"level": "Moyen", "option": "Securite_des_reseaux", "game": GameType.QCM, "question_text": "Sélectionner une des propositions", "correct_answer": "Hachage", "options": "Chiffrement|Compression"},
        {"level": "Moyen", "option": "Securite_des_reseaux", "game": GameType.QUESTION_SIMPLE, "question_text": "La réponse doit être écrite en minuscule, sans accent, sans caractère spécial. Les espaces sont autorisés.", "correct_answer": "botnet"},
        {"level": "Moyen", "option": "Securite_des_reseaux", "game": GameType.QUESTION_SIMPLE, "question_text": "La réponse doit être écrite en minuscule, sans accent, sans caractère spécial. Les espaces sont autorisés.", "correct_answer": "smtp"},
        {"level": "Difficile", "option": "Securite_des_reseaux", "game": GameType.QUESTION_SIMPLE, "question_text": "La réponse doit être écrite en minuscule, sans accent, sans caractère spécial. Les espaces sont autorisés.", "correct_answer": "sae"},
        {"level": "Difficile", "option": "Securite_des_reseaux", "game": GameType.QUESTION_SIMPLE, "question_text": "La réponse doit être écrite en minuscule, sans accent, sans caractère spécial. Les espaces sont autorisés.", "correct_answer": "zero trust"},
        {"level": "Difficile", "option": "Securite_des_reseaux", "game": GameType.QUESTION_SIMPLE, "question_text": "La réponse doit être écrite en minuscule, sans accent, sans caractère spécial. Les espaces sont autorisés.", "correct_answer": "spoofing"},
        {"level": "Difficile", "option": "Securite_des_reseaux", "game": GameType.QCM, "question_text": "Sélectionner une des propositions", "correct_answer": "SSH", "options": "OAuth|SNMP"},
        {"level": "Facile", "option": "Securite_des_reseaux", "game": GameType.MOTUS, "question_text": "Le but est de trouver le mot sans dépasser 6 tentatives ou la partie est perdue.", "correct_answer": "Sécurité"},
        {"level": "Facile", "option": "Securite_des_reseaux", "game": GameType.MOTUS, "question_text": "Le but est de trouver le mot sans dépasser 6 tentatives ou la partie est perdue.", "correct_answer": "Firewall"},
        {"level": "Moyen", "option": "Securite_des_reseaux", "game": GameType.MOTUS, "question_text": "Le but est de trouver le mot sans dépasser 6 tentatives ou la partie est perdue.", "correct_answer": "Cryptage"},
        {"level": "Facile", "option": "Securite_des_reseaux", "game": GameType.MOTUS, "question_text": "Le but est de trouver le mot sans dépasser 6 tentatives ou la partie est perdue.", "correct_answer": "Intrusif"},
        {"level": "Moyen", "option": "Securite_des_reseaux", "game": GameType.MOTUS, "question_text": "Le but est de trouver le mot sans dépasser 6 tentatives ou la partie est perdue.", "correct_answer": "Vulnérable"},
        {"level": "Difficile", "option": "Securite_des_reseaux", "game": GameType.MOTUS, "question_text": "Le but est de trouver le mot sans dépasser 6 tentatives ou la partie est perdue.", "correct_answer": "Contournement"},
        {"level": "Difficile", "option": "Securite_des_reseaux", "game": GameType.MOTUS, "question_text": "Le but est de trouver le mot sans dépasser 6 tentatives ou la partie est perdue.", "correct_answer": "Authentification"},
        {"level": "Moyen", "option": "Securite_des_reseaux", "game": GameType.MOTUS, "question_text": "Le but est de trouver le mot sans dépasser 6 tentatives ou la partie est perdue.", "correct_answer": "Confidentialité"},
        {"level": "Facile", "option": "Securite_des_reseaux", "game": GameType.PENDU, "question_text": "Jeu du pendu, vous avez 10 tentatives.", "correct_answer": "Sécurité"},
        {"level": "Facile", "option": "Securite_des_reseaux", "game": GameType.PENDU, "question_text": "Jeu du pendu, vous avez 10 tentatives.", "correct_answer": "Firewall"},
        {"level": "Facile", "option": "Securite_des_reseaux", "game": GameType.PENDU, "question_text": "Jeu du pendu, vous avez 10 tentatives.", "correct_answer": "Cryptage"},
        {"level": "Facile", "option": "Securite_des_reseaux", "game": GameType.PENDU, "question_text": "Jeu du pendu, vous avez 10 tentatives.", "correct_answer": "Intrusif"},
        {"level": "Facile", "option": "Securite_des_reseaux", "game": GameType.PENDU, "question_text": "Jeu du pendu, vous avez 10 tentatives.", "correct_answer": "Vulnérable"},
        {"level": "Moyen", "option": "Securite_des_reseaux", "game": GameType.PENDU, "question_text": "Jeu du pendu, vous avez 10 tentatives.", "correct_answer": "Contournement"},
        {"level": "Moyen", "option": "Securite_des_reseaux", "game": GameType.PENDU, "question_text": "Jeu du pendu, vous avez 10 tentatives.", "correct_answer": "Authentification"},
        {"level": "Facile", "option": "Securite_des_reseaux", "game": GameType.PENDU, "question_text": "Jeu du pendu, vous avez 10 tentatives.", "correct_answer": "Confidentialité"}
    ]

    for q in questions:
        question = Question(
            level=q["level"],
            option=q["option"],
            game=q["game"],
            question_text=q["question_text"],
            correct_answer=q["correct_answer"]
        )

        if "options" in q:
            options_list = q["options"].split("|")
            for option_text in options_list:
                option = QuestionOption(option_text=option_text)
                question.options.append(option)

        db.session.add(question)

    db.session.commit()

def add_network_security_question():
    questions = [
        # Niveau Facile
        {"level": "Facile", "option": "Securite_des_reseaux", "game": GameType.QCM,
         "question_text": "Quelle est la principale fonction d'un pare-feu réseau ?",
         "correct_answer": "Filtrer le trafic",
         "options": "Filtrer le trafic|Chiffrer les données|Assurer la connectivité|Fournir du contenu"},
        
        {"level": "Facile", "option": "Securite_des_reseaux", "game": GameType.QCM,
         "question_text": "Quel protocole est couramment utilisé pour sécuriser les communications sur Internet ?",
         "correct_answer": "HTTPS",
         "options": "HTTPS|FTP|Telnet|HTTP"},
        
        {"level": "Facile", "option": "Securite_des_reseaux", "game": GameType.QCM,
         "question_text": "Quelle technique consiste à transformer les données en une forme illisible pour protéger leur confidentialité ?",
         "correct_answer": "Chiffrement",
         "options": "Chiffrement|Compression|Redondance|Segmentation"},
        
        # Niveau Moyen
        {"level": "Moyen", "option": "Securite_des_reseaux", "game": GameType.QCM,
         "question_text": "Quelle est la principale fonction d'un système de détection d'intrusion (IDS) ?",
         "correct_answer": "Surveiller le réseau pour détecter des activités malveillantes",
         "options": "Surveiller le réseau pour détecter des activités malveillantes|Bloquer le trafic indésirable|Gérer les connexions réseau|Fournir des adresses IP"},
        
        {"level": "Moyen", "option": "Securite_des_reseaux", "game": GameType.QCM,
         "question_text": "Quel protocole est utilisé pour sécuriser les communications par courriel ?",
         "correct_answer": "SSL/TLS",
         "options": "SSL/TLS|FTP|SMTP|POP3"},
        
        {"level": "Moyen", "option": "Securite_des_reseaux", "game": GameType.QCM,
         "question_text": "Quel type d'attaque consiste à intercepter les communications entre deux parties sans qu'elles le sachent ?",
         "correct_answer": "Attaque de l'homme du milieu (MITM)",
         "options": "Attaque de l'homme du milieu (MITM)|Phishing|DDoS|Ransomware"},
        
        # Niveau Difficile
        {"level": "Difficile", "option": "Securite_des_reseaux", "game": GameType.QCM,
         "question_text": "Quel est le principal avantage d'utiliser un VPN (réseau privé virtuel) ?",
         "correct_answer": "Sécuriser la communication sur un réseau public",
         "options": "Sécuriser la communication sur un réseau public|Augmenter la vitesse de connexion|Réduire les coûts de bande passante|Fournir un accès sans fil"},
        
        {"level": "Difficile", "option": "Securite_des_reseaux", "game": GameType.QCM,
         "question_text": "Quel protocole de sécurité est souvent utilisé pour créer un tunnel sécurisé entre deux points sur Internet ?",
         "correct_answer": "IPsec",
         "options": "IPsec|HTTP|FTP|ICMP"},
        
        {"level": "Difficile", "option": "Securite_des_reseaux", "game": GameType.QCM,
         "question_text": "Quelle méthode de cryptographie utilise deux clés, une publique et une privée ?",
         "correct_answer": "Cryptographie asymétrique",
         "options": "Cryptographie asymétrique|Cryptographie symétrique|Hachage|Steganographie"}
    ]

    for q in questions:
        question = Question(
            level=q["level"],
            option=q["option"],
            game=q["game"],
            question_text=q["question_text"],
            correct_answer=q["correct_answer"]
        )

        options_list = q["options"].split("|")
        for option_text in options_list:
            option = QuestionOption(option_text=option_text)
            question.options.append(option)

        db.session.add(question)

    try:
        db.session.commit()
    except Exception as e:
        db.session.rollback()
        print(f"Error: {e}")

def add_network_questions():
    questions = [
        # Questions de niveau Facile
        {
            "level": "Facile",
            "option": "Securite_des_reseaux",
            "game": GameType.QUESTION_SIMPLE,
            "question_text": "Quel protocole est utilisé pour sécuriser les communications Web ?",
            "correct_answer": "HTTPS"
        },
        {
            "level": "Facile",
            "option": "Securite_des_reseaux",
            "game": GameType.QUESTION_SIMPLE,
            "question_text": "Quel est le nom du protocole utilisé pour sécuriser l'accès à distance aux systèmes informatiques ?",
            "correct_answer": "SSH"
        },
        {
            "level": "Facile",
            "option": "Securite_des_reseaux",
            "game": GameType.QUESTION_SIMPLE,
            "question_text": "Quel type d'attaque cherche à intercepter les communications entre un client et un serveur pour voler des informations ?",
            "correct_answer": "Man-in-the-middle"
        },
        # Questions de niveau Moyen
        {
            "level": "Moyen",
            "option": "Securite_des_reseaux",
            "game": GameType.QUESTION_SIMPLE,
            "question_text": "Quel protocole est utilisé pour sécuriser les emails ?",
            "correct_answer": "SMTPS"
        },
        {
            "level": "Moyen",
            "option": "Securite_des_reseaux",
            "game": GameType.QUESTION_SIMPLE,
            "question_text": "Quel est le terme utilisé pour désigner un logiciel malveillant capable de se propager à travers un réseau sans intervention humaine ?",
            "correct_answer": "Ver"
        },
        {
            "level": "Moyen",
            "option": "Securite_des_reseaux",
            "game": GameType.QUESTION_SIMPLE,
            "question_text": "Quel protocole est utilisé pour sécuriser les connexions VPN ?",
            "correct_answer": "IPsec"
        },
        # Questions de niveau Difficile
        {
            "level": "Difficile",
            "option": "Securite_des_reseaux",
            "game": GameType.QUESTION_SIMPLE,
            "question_text": "Quel protocole de routage dynamique est sécurisé par défaut avec l'utilisation d'authentification MD5 ?",
            "correct_answer": "BGP"
        },
        {
            "level": "Difficile",
            "option": "Securite_des_reseaux",
            "game": GameType.QUESTION_SIMPLE,
            "question_text": "Quel est le terme utilisé pour désigner un logiciel malveillant qui se cache à l'intérieur d'un autre programme ?",
            "correct_answer": "Troyen"
        },
        {
            "level": "Difficile",
            "option": "Securite_des_reseaux",
            "game": GameType.QUESTION_SIMPLE,
            "question_text": "Quel protocole de chiffrement asymétrique est utilisé pour sécuriser les connexions HTTPS ?",
            "correct_answer": "RSA"
        }
    ]

    # Ajouter les questions à la base de données
    for q in questions:
        question = Question(
            level=q["level"],
            option=q["option"],
            game=q["game"],
            question_text=q["question_text"],
            correct_answer=q["correct_answer"]
        )
        db.session.add(question)

    db.session.commit()


if __name__ == '__main__':
    with app.app_context():
        db.create_all()
        add_chiffrement_questions()
        add_motus_questions()
        add_pendu_questions()
        add_chiffrement_question()
        add_simple_encryption_questions()
        add_attack_questions()
        add_attack_question()
        add_linux_questions()
        add_linux_question()
        add_network_security_questions()
        add_network_security_question()
        add_network_questions()
