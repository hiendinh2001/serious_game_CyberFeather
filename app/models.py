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
    topscore = Column(Float, default=-100.0)
    position = Column(Float, default=0.0)

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
    explanation = Column(Text, nullable=True)

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
         "options": "Compression des données|Réplication des données|Confidentialité des données|Sauvegarde des données",
         "explanation": "Le chiffrement vise à garantir que seules les personnes autorisées peuvent accéder aux données."},

        {"level": "Facile", "option": "Chiffrement", "game": GameType.QCM,
         "question_text": "Quel algorithme est utilisé pour le chiffrement symétrique ?",
         "correct_answer": "DES",
         "options": "RSA|DES|DSA|ECC",
         "explanation": "DES est un algorithme de chiffrement symétrique, ce qui signifie qu'il utilise la même clé pour le chiffrement et le déchiffrement."},

        {"level": "Facile", "option": "Chiffrement", "game": GameType.QCM,
         "question_text": "Quelle est la taille de clé la plus courante pour le chiffrement AES ?",
         "correct_answer": "128 bits",
         "options": "64 bits|128 bits|256 bits|512 bits",
         "explanation": "AES utilise généralement des clés de 128 bits, bien que des tailles de 192 et 256 bits soient également courantes."},

        {"level": "Moyen", "option": "Chiffrement", "game": GameType.QCM,
         "question_text": "Quel algorithme utilise une clé publique et une clé privée ?",
         "correct_answer": "RSA",
         "options": "AES|RSA|SHA-256|MD5",
         "explanation": "RSA est un algorithme de chiffrement asymétrique, utilisant une paire de clés publique et privée pour le chiffrement et le déchiffrement."},

        {"level": "Moyen", "option": "Chiffrement", "game": GameType.QCM,
         "question_text": "Quelle est la principale caractéristique du chiffrement asymétrique ?",
         "correct_answer": "Utilise des clés différentes pour le chiffrement et le déchiffrement",
         "options": "Utilise la même clé pour le chiffrement et le déchiffrement|Utilise des clés différentes pour le chiffrement et le déchiffrement|Utilise uniquement une clé privée|Utilise uniquement une clé publique",
         "explanation": "Le chiffrement asymétrique utilise une clé publique pour chiffrer les données et une clé privée pour les déchiffrer."},

        {"level": "Moyen", "option": "Chiffrement", "game": GameType.QCM,
         "question_text": "Quelle taille de clé est recommandée pour AES ?",
         "correct_answer": "128 bits",
         "options": "56 bits|128 bits|512 bits|1024 bits",
         "explanation": "Pour un bon équilibre entre sécurité et performance, une clé de 128 bits est recommandée pour AES."},

        {"level": "Difficile", "option": "Chiffrement", "game": GameType.QCM,
         "question_text": "Quelle est la différence principale entre le chiffrement symétrique et asymétrique ?",
         "correct_answer": "Le nombre de clés utilisées",
         "options": "La vitesse de chiffrement|La longueur des clés|Le nombre de clés utilisées|La méthode de déchiffrement",
         "explanation": "Le chiffrement symétrique utilise une seule clé, tandis que le chiffrement asymétrique utilise une paire de clés."},

        {"level": "Difficile", "option": "Chiffrement", "game": GameType.QCM,
         "question_text": "Quel algorithme de chiffrement est considéré comme inviolable en théorie ?",
         "correct_answer": "One-time pad",
         "options": "Triple DES|One-time pad|Blowfish|Twofish",
         "explanation": "Le one-time pad est théoriquement inviolable si la clé est aléatoire, aussi longue que le message, et utilisée une seule fois."},

        {"level": "Difficile", "option": "Chiffrement", "game": GameType.QCM,
         "question_text": "Quel algorithme est utilisé dans le protocole SSL/TLS pour sécuriser les communications ?",
         "correct_answer": "Diffie-Hellman",
         "options": "RSA|AES|Diffie-Hellman|MD5",
         "explanation": "Diffie-Hellman est utilisé pour échanger des clés de manière sécurisée dans le protocole SSL/TLS."}
    ]
    for q in questions:
        question = Question(
            level=q["level"],
            option=q["option"],
            game=q["game"],
            question_text=q["question_text"],
            correct_answer=q["correct_answer"],
            explanation=q["explanation"]
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
        {
            "level": "Facile", "option": "Chiffrement", "game": GameType.QUESTION_SIMPLE,
            "question_text": "Quel est le terme utilisé pour désigner la transformation d'un message en un format illisible afin de le rendre secret ?",
            "correct_answer": "Cryptage",
            "explanation": "Le cryptage transforme un message lisible en un format illisible pour protéger son contenu contre les accès non autorisés."
        },
        {
            "level": "Facile", "option": "Chiffrement", "game": GameType.QUESTION_SIMPLE,
            "question_text": "Quel est le nom de l'algorithme de chiffrement symétrique le plus utilisé ?",
            "correct_answer": "AES",
            "explanation": "L'Advanced Encryption Standard (AES) est un algorithme de chiffrement symétrique largement utilisé pour sécuriser les données en utilisant la même clé pour le chiffrement et le déchiffrement."
        },
        {
            "level": "Facile", "option": "Chiffrement", "game": GameType.QUESTION_SIMPLE,
            "question_text": "Quel est le processus consistant à rendre un message illisible sans avoir besoin d'une clé pour le déchiffrer ?",
            "correct_answer": "Hachage",
            "explanation": "Le hachage est une technique qui transforme un message en une valeur fixe unique, rendant le message illisible et irréversible sans clé."
        },

        # Niveau Moyen
        {
            "level": "Moyen", "option": "Chiffrement", "game": GameType.QUESTION_SIMPLE,
            "question_text": "Quel est le nom de l'algorithme de chiffrement asymétrique largement utilisé pour le chiffrement des e-mails ?",
            "correct_answer": "RSA",
            "explanation": "RSA est un algorithme de chiffrement asymétrique utilisé pour sécuriser les communications par e-mail en utilisant une paire de clés, publique et privée."
        },
        {
            "level": "Moyen", "option": "Chiffrement", "game": GameType.QUESTION_SIMPLE,
            "question_text": "Quel est le nom de l'algorithme de chiffrement utilisé pour sécuriser les transactions en ligne ?",
            "correct_answer": "SSL/TLS",
            "explanation": "SSL/TLS (Secure Sockets Layer/Transport Layer Security) est un protocole utilisé pour sécuriser les communications sur Internet, notamment les transactions en ligne."
        },

        # Niveau Difficile
        {
            "level": "Difficile", "option": "Chiffrement", "game": GameType.QUESTION_SIMPLE,
            "question_text": "Quel est le nom de l'algorithme de chiffrement symétrique populaire qui utilise des blocs de données de 128 bits ?",
            "correct_answer": "DES",
            "explanation": "DES (Data Encryption Standard) est un ancien algorithme de chiffrement symétrique qui utilise des blocs de données de 128 bits, bien qu'il soit maintenant considéré comme obsolète et moins sécurisé que AES."
        },
        {
            "level": "Difficile", "option": "Chiffrement", "game": GameType.QUESTION_SIMPLE,
            "question_text": "Quel est le nom de l'algorithme de chiffrement utilisé pour le chiffrement de bout en bout dans l'application de messagerie WhatsApp ?",
            "correct_answer": "Signal Protocol",
            "explanation": "Le Signal Protocol est un protocole de chiffrement de bout en bout utilisé par WhatsApp pour garantir que seuls l'expéditeur et le destinataire puissent lire les messages."
        }
    ]

    # Ajout des questions à la base de données
    for q in questions:
        question = Question(
            level=q["level"],
            option=q["option"],
            game=q["game"],
            question_text=q["question_text"],
            correct_answer=q["correct_answer"],
            explanation=q["explanation"]
        )
        db.session.add(question)

    # Commit des changements
    db.session.commit()


def add_attack_questions():
    questions = [
        # Niveau Facile
        {
            "level": "Facile", "option": "Attaque", "game": GameType.QUESTION_SIMPLE,
            "question_text": "Quel type d'attaque vise à tromper les utilisateurs pour obtenir des informations confidentielles telles que des mots de passe ?",
            "correct_answer": "phishing",
            "explanation": "Le phishing est une méthode d'attaque où les attaquants se font passer pour des entités de confiance pour inciter les utilisateurs à révéler des informations sensibles."
        },
        {
            "level": "Facile", "option": "Attaque", "game": GameType.QUESTION_SIMPLE,
            "question_text": "Quel est le terme pour décrire une pièce de logiciel conçue pour se propager et causer des dommages ?",
            "correct_answer": "virus",
            "explanation": "Un virus est un logiciel malveillant qui peut se répliquer et se propager à d'autres systèmes, souvent endommageant les fichiers et les données."
        },
        {
            "level": "Facile", "option": "Attaque", "game": GameType.QUESTION_SIMPLE,
            "question_text": "Quel terme désigne une tentative d'accès non autorisé à un système informatique ?",
            "correct_answer": "piratage",
            "explanation": "Le piratage est l'acte d'accéder illégalement ou non autorisé à des systèmes informatiques pour voler, modifier ou détruire des informations."
        },
        {
            "level": "Facile", "option": "Attaque", "game": GameType.QCM,
            "question_text": "Quel type d'attaque consiste à submerger un système avec une grande quantité de trafic pour le rendre indisponible ?",
            "correct_answer": "Attaque par déni de service",
            "options": "Attaque par déni de service|Ransomware|Injection SQL",
            "explanation": "Une attaque par déni de service (DoS) submerge un serveur avec du trafic pour le rendre incapable de traiter des demandes légitimes, provoquant une interruption de service."
        },

        # Niveau Moyen
        {
            "level": "Moyen", "option": "Attaque", "game": GameType.QUESTION_SIMPLE,
            "question_text": "Quel est le nom de l'attaque où un attaquant intercepte et modifie les communications entre deux parties sans leur consentement ?",
            "correct_answer": "man in the middle",
            "explanation": "Une attaque Man-in-the-Middle (MITM) consiste à intercepter et potentiellement altérer les communications entre deux parties à leur insu."
        },
        {
            "level": "Moyen", "option": "Attaque", "game": GameType.QUESTION_SIMPLE,
            "question_text": "Quel type d'attaque exploite les failles de sécurité d'un logiciel pour exécuter du code malveillant ?",
            "correct_answer": "exploit",
            "explanation": "Un exploit est une attaque qui utilise une vulnérabilité dans un logiciel pour exécuter du code malveillant et compromettre le système."
        },
        {
            "level": "Moyen", "option": "Attaque", "game": GameType.QUESTION_SIMPLE,
            "question_text": "Quelle est la pratique consistant à deviner des mots de passe en essayant différentes combinaisons de lettres, chiffres et symboles ?",
            "correct_answer": "brute force",
            "explanation": "Une attaque par force brute consiste à essayer systématiquement toutes les combinaisons possibles de mots de passe jusqu'à ce que le bon soit trouvé."
        },

        # Niveau Difficile
        {
            "level": "Difficile", "option": "Attaque", "game": GameType.QUESTION_SIMPLE,
            "question_text": "Quel est le nom de l'attaque où un attaquant exploite une faiblesse humaine pour obtenir des informations confidentielles, généralement en se faisant passer pour une personne de confiance ?",
            "correct_answer": "ingenierie sociale",
            "explanation": "L'ingénierie sociale utilise des manipulations psychologiques pour tromper les individus et les inciter à divulguer des informations confidentielles."
        },
        {
            "level": "Difficile", "option": "Attaque", "game": GameType.QCM,
            "question_text": "Quelle est la technique d'attaque qui consiste à cacher du code malveillant dans des fichiers multimédias, tels que des images ou des vidéos ?",
            "correct_answer": "Steganographie",
            "options": "Steganographie|Attaque par pièce jointe malveillante|Empoisonnement du cache DNS",
            "explanation": "La stéganographie est la technique de dissimulation de messages ou de données dans d'autres fichiers non suspects, comme des images ou des vidéos."
        },
        {
            "level": "Difficile", "option": "Attaque", "game": GameType.QUESTION_SIMPLE,
            "question_text": "Quel est le terme pour une attaque qui cible spécifiquement les bases de données pour extraire des informations sensibles ?",
            "correct_answer": "injection sql",
            "explanation": "L'injection SQL est une technique d'attaque qui permet à un attaquant d'exécuter des commandes SQL malveillantes sur une base de données, souvent pour extraire ou manipuler des données."
        },
        {
            "level": "Difficile", "option": "Attaque", "game": GameType.QUESTION_SIMPLE,
            "question_text": "Quel type d'attaque utilise des logiciels malveillants pour chiffrer les fichiers d'un utilisateur et demander une rançon en échange de la clé de déchiffrement ?",
            "correct_answer": "ransomware",
            "explanation": "Les ransomwares chiffrent les fichiers d'un utilisateur et exigent une rançon pour fournir la clé de déchiffrement, empêchant ainsi l'accès aux données jusqu'au paiement."
        },
    {"level": "Moyen", "option": "Attaque", "game": GameType.MOTUS,
         "question_text": "Le but est de trouver le mot sans dépasser 6 tentatives ou la partie est perdue. A chaque tentative, les lettres bien placées sont en rouge et celles mal placées en jaune.",
         "correct_answer": "Phishing", "explanation": None},
        {"level": "Moyen", "option": "Attaque", "game": GameType.MOTUS,
         "question_text": "Le but est de trouver le mot sans dépasser 6 tentatives ou la partie est perdue. A chaque tentative, les lettres bien placées sont en rouge et celles mal placées en jaune.",
         "correct_answer": "Malware", "explanation": None},
        {"level": "Facile", "option": "Attaque", "game": GameType.MOTUS,
         "question_text": "Le but est de trouver le mot sans dépasser 6 tentatives ou la partie est perdue. A chaque tentative, les lettres bien placées sont en rouge et celles mal placées en jaune.",
         "correct_answer": "Virus", "explanation": None},
        {"level": "Difficile", "option": "Attaque", "game": GameType.MOTUS,
         "question_text": "Le but est de trouver le mot sans dépasser 6 tentatives ou la partie est perdue. A chaque tentative, les lettres bien placées sont en rouge et celles mal placées en jaune.",
         "correct_answer": "Ransomware", "explanation": None},
        {"level": "Difficile", "option": "Attaque", "game": GameType.MOTUS,
         "question_text": "Le but est de trouver le mot sans dépasser 6 tentatives ou la partie est perdue. A chaque tentative, les lettres bien placées sont en rouge et celles mal placées en jaune.",
         "correct_answer": "Spyware", "explanation": None},
        {"level": "Difficile", "option": "Attaque", "game": GameType.MOTUS,
         "question_text": "Le but est de trouver le mot sans dépasser 6 tentatives ou la partie est perdue. A chaque tentative, les lettres bien placées sont en rouge et celles mal placées en jaune.",
         "correct_answer": "Trojans", "explanation": None},
        {"level": "Moyen", "option": "Attaque", "game": GameType.MOTUS,
         "question_text": "Le but est de trouver le mot sans dépasser 6 tentatives ou la partie est perdue. A chaque tentative, les lettres bien placées sont en rouge et celles mal placées en jaune.",
         "correct_answer": "Worms", "explanation": None},
        {"level": "Moyen", "option": "Attaque", "game": GameType.MOTUS,
         "question_text": "Le but est de trouver le mot sans dépasser 6 tentatives ou la partie est perdue. A chaque tentative, les lettres bien placées sont en rouge et celles mal placées en jaune.",
         "correct_answer": "Botnet", "explanation": None},
        {"level": "Facile", "option": "Attaque", "game": GameType.PENDU,
         "question_text": "Jeu du pendu, vous avez 10 tentatives.", "correct_answer": "Phishing", "explanation": None},
        {"level": "Facile", "option": "Attaque", "game": GameType.PENDU,
         "question_text": "Jeu du pendu, vous avez 10 tentatives.", "correct_answer": "Malware", "explanation": None},
        {"level": "Facile", "option": "Attaque", "game": GameType.PENDU,
         "question_text": "Jeu du pendu, vous avez 10 tentatives.", "correct_answer": "Virus", "explanation": None},
        {"level": "Facile", "option": "Attaque", "game": GameType.PENDU,
         "question_text": "Jeu du pendu, vous avez 10 tentatives.", "correct_answer": "Ransomware", "explanation": None},
        {"level": "Facile", "option": "Attaque", "game": GameType.PENDU,
         "question_text": "Jeu du pendu, vous avez 10 tentatives.", "correct_answer": "Spyware", "explanation": None},
        {"level": "Facile", "option": "Attaque", "game": GameType.PENDU,
         "question_text": "Jeu du pendu, vous avez 10 tentatives.", "correct_answer": "Trojans", "explanation": None},
        {"level": "Facile", "option": "Attaque", "game": GameType.PENDU,
         "question_text": "Jeu du pendu, vous avez 10 tentatives.", "correct_answer": "Worms", "explanation": None},
        {"level": "Facile", "option": "Attaque", "game": GameType.PENDU,
         "question_text": "Jeu du pendu, vous avez 10 tentatives.", "correct_answer": "Botnet", "explanation": None},
    ]

    for q in questions:
        question = Question(
            level=q["level"],
            option=q["option"],
            game=q["game"],
            question_text=q["question_text"],
            correct_answer=q["correct_answer"],
            explanation=q["explanation"]
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
        {
            "level": "Facile", "option": "Attaque", "game": GameType.QCM,
            "question_text": "Quel type d'attaque consiste à submerger un système avec une grande quantité de trafic pour le rendre indisponible ?",
            "correct_answer": "Attaque par déni de service",
            "options": "Attaque par déni de service|Ransomware|Injection SQL|Phishing",
            "explanation": "Une attaque par déni de service (DoS) inonde un système de trafic, le rendant incapable de traiter les demandes légitimes et provoquant une interruption de service."
        },
        {
            "level": "Facile", "option": "Attaque", "game": GameType.QCM,
            "question_text": "Quel type d'attaque consiste à inciter l'utilisateur à cliquer sur un lien malveillant ?",
            "correct_answer": "Phishing",
            "options": "Phishing|Injection SQL|Attaque par force brute|Spyware",
            "explanation": "Le phishing est une technique où les attaquants incitent les utilisateurs à cliquer sur des liens malveillants, souvent en se faisant passer pour des entités de confiance."
        },
        {
            "level": "Facile", "option": "Attaque", "game": GameType.QCM,
            "question_text": "Quel type d'attaque exploite les vulnérabilités d'une application web pour exécuter du code malveillant ?",
            "correct_answer": "Injection SQL",
            "options": "Injection SQL|Ransomware|Attaque par déni de service|Spyware",
            "explanation": "L'injection SQL est une technique où des commandes SQL malveillantes sont insérées dans une application web pour exploiter ses vulnérabilités."
        },

        # Niveau Moyen
        {
            "level": "Moyen", "option": "Attaque", "game": GameType.QCM,
            "question_text": "Quel type d'attaque implique la capture et l'analyse des paquets réseau ?",
            "correct_answer": "Sniffing",
            "options": "Sniffing|Phishing|Ransomware|Injection SQL",
            "explanation": "Le sniffing est une technique où un attaquant intercepte et analyse les paquets de données circulant sur un réseau pour en extraire des informations sensibles."
        },
        {
            "level": "Moyen", "option": "Attaque", "game": GameType.QCM,
            "question_text": "Quel type d'attaque utilise un réseau de machines compromises pour lancer une attaque coordonnée ?",
            "correct_answer": "Botnet",
            "options": "Botnet|Phishing|Spyware|Sniffing",
            "explanation": "Un botnet est un réseau de machines infectées par des logiciels malveillants, contrôlé par un attaquant pour lancer des attaques coordonnées telles que des dénis de service."
        },
        {
            "level": "Moyen", "option": "Attaque", "game": GameType.QCM,
            "question_text": "Quel type d'attaque cible spécifiquement les utilisateurs pour voler leurs informations personnelles ?",
            "correct_answer": "Phishing",
            "options": "Phishing|Injection SQL|Sniffing|Botnet",
            "explanation": "Le phishing vise à tromper les utilisateurs en les incitant à divulguer des informations personnelles comme des mots de passe et des numéros de carte de crédit."
        },

        # Niveau Difficile
        {
            "level": "Difficile", "option": "Attaque", "game": GameType.QCM,
            "question_text": "Quel type d'attaque manipule les requêtes DNS pour rediriger le trafic vers des sites malveillants ?",
            "correct_answer": "Attaque par empoisonnement DNS",
            "options": "Attaque par empoisonnement DNS|Injection SQL|Phishing|Ransomware",
            "explanation": "L'attaque par empoisonnement DNS consiste à modifier les enregistrements DNS pour rediriger le trafic internet vers des sites malveillants à l'insu des utilisateurs."
        },
        {
            "level": "Difficile", "option": "Attaque", "game": GameType.QCM,
            "question_text": "Quel type d'attaque exploite les faiblesses des protocoles de sécurité Wi-Fi pour intercepter les communications ?",
            "correct_answer": "Attaque par KRACK",
            "options": "Attaque par KRACK|Injection SQL|Phishing|Botnet",
            "explanation": "L'attaque KRACK (Key Reinstallation Attack) exploite une vulnérabilité dans le protocole de sécurité WPA2 des réseaux Wi-Fi pour intercepter et déchiffrer les données."
        },
        {
            "level": "Difficile", "option": "Attaque", "game": GameType.QCM,
            "question_text": "Quel type d'attaque consiste à deviner des mots de passe en essayant toutes les combinaisons possibles ?",
            "correct_answer": "Attaque par force brute",
            "options": "Attaque par force brute|Phishing|Sniffing|Botnet",
            "explanation": "Une attaque par force brute consiste à tenter systématiquement toutes les combinaisons possibles de mots de passe jusqu'à trouver la bonne."
        }
    ]

    for q in questions:
        question = Question(
            level=q["level"],
            option=q["option"],
            game=q["game"],
            question_text=q["question_text"],
            correct_answer=q["correct_answer"],
            explanation=q["explanation"]
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
        # Niveau Facile
        {
            "level": "Facile", "option": "Linux", "game": GameType.QUESTION_SIMPLE,
            "question_text": "Quel est le nom du super-utilisateur sous Linux ?",
            "correct_answer": "root",
            "explanation": "Le super-utilisateur sous Linux est appelé 'root'. Ce compte possède les privilèges administratifs et peut effectuer toutes les tâches sur le système."
        },
        {
            "level": "Facile", "option": "Linux", "game": GameType.QUESTION_SIMPLE,
            "question_text": "Quel symbole est utilisé pour indiquer le répertoire personnel d'un utilisateur ?",
            "correct_answer": "~",
            "explanation": "Le symbole tilde (~) représente le répertoire personnel de l'utilisateur actuel dans les systèmes Unix et Linux."
        },
        {
            "level": "Facile", "option": "Linux", "game": GameType.QUESTION_SIMPLE,
            "question_text": "Quelle commande permet de changer de répertoire ?",
            "correct_answer": "cd",
            "explanation": "La commande 'cd' (change directory) est utilisée pour naviguer d'un répertoire à un autre dans le système de fichiers."
        },
        {
            "level": "Facile", "option": "Linux", "game": GameType.QUESTION_SIMPLE,
            "question_text": "Quelle commande affiche le contenu d'un répertoire ?",
            "correct_answer": "ls",
            "explanation": "La commande 'ls' (list) affiche la liste des fichiers et sous-répertoires contenus dans un répertoire donné."
        },

        # Niveau Moyen
        {
            "level": "Moyen", "option": "Linux", "game": GameType.QUESTION_SIMPLE,
            "question_text": "Quelle commande permet de copier des fichiers ou des répertoires ?",
            "correct_answer": "cp",
            "explanation": "La commande 'cp' (copy) est utilisée pour copier des fichiers ou des répertoires d'un emplacement à un autre."
        },
        {
            "level": "Moyen", "option": "Linux", "game": GameType.QUESTION_SIMPLE,
            "question_text": "Quel fichier contient les informations sur les utilisateurs du système ?",
            "correct_answer": "passwd",
            "explanation": "Le fichier '/etc/passwd' contient les informations sur les utilisateurs enregistrés sur le système, y compris leur nom d'utilisateur et leur répertoire personnel."
        },
        {
            "level": "Moyen", "option": "Linux", "game": GameType.QUESTION_SIMPLE,
            "question_text": "Quel utilitaire est utilisé pour installer des paquets sous Debian et ses dérivés ?",
            "correct_answer": "apt",
            "explanation": "L'utilitaire 'apt' (Advanced Package Tool) est utilisé pour gérer les paquets logiciels dans les distributions basées sur Debian, telles qu'Ubuntu."
        },
        {
            "level": "Moyen", "option": "Linux", "game": GameType.QUESTION_SIMPLE,
            "question_text": "Quel fichier, avec le chemin, contient les informations de configuration des réseaux sous Linux ? Ecrire la réponse sous la forme abc/defgh/ijklm.",
            "correct_answer": "etc/network/interfaces",
            "explanation": "Le fichier '/etc/network/interfaces' contient la configuration des interfaces réseau pour les systèmes Debian et ses dérivés."
        },
        {
            "level": "Moyen", "option": "Linux", "game": GameType.QUESTION_SIMPLE,
            "question_text": "Quelle commande permet de modifier les permissions d'un fichier ou d'un répertoire ?",
            "correct_answer": "chmod",
            "explanation": "La commande 'chmod' (change mode) est utilisée pour modifier les permissions d'accès des fichiers et répertoires."
        },

        # Niveau Difficile
        {
            "level": "Difficile", "option": "Linux", "game": GameType.QUESTION_SIMPLE,
            "question_text": "Quel gestionnaire de démarrage est couramment utilisé sous Linux ? (réponse en majuscules)",
            "correct_answer": "GRUB",
            "explanation": "Le gestionnaire de démarrage couramment utilisé sous Linux est GRUB (GRand Unified Bootloader)."
        },
        {
            "level": "Difficile", "option": "Linux", "game": GameType.QUESTION_SIMPLE,
            "question_text": "Quelle commande permet de créer une nouvelle partition sur un disque dur ?",
            "correct_answer": "fdisk",
            "explanation": "La commande 'fdisk' est utilisée pour manipuler les tables de partition sur un disque dur, y compris la création de nouvelles partitions."
        },
        {
            "level": "Difficile", "option": "Linux", "game": GameType.QUESTION_SIMPLE,
            "question_text": "Quelle commande permet de trouver des fichiers et des répertoires en fonction de divers critères tels que le nom, la date ou la taille ?",
            "correct_answer": "find",
            "explanation": "La commande 'find' permet de rechercher des fichiers et répertoires en fonction de critères comme le nom, la date de modification ou la taille."
        },
        {
            "level": "Difficile", "option": "Linux", "game": GameType.QUESTION_SIMPLE,
            "question_text": "Quel est le nom du système de gestion de versions décentralisé couramment utilisé par les développeurs sous Linux ?",
            "correct_answer": "git",
            "explanation": "Git est un système de gestion de versions décentralisé très populaire parmi les développeurs pour le suivi des modifications apportées au code source."
        },
        {
            "level": "Difficile", "option": "Linux", "game": GameType.QUESTION_SIMPLE,
            "question_text": "Quelle commande permet de visualiser les journaux du système et des applications sous Linux ?",
            "correct_answer": "journalctl",
            "explanation": "La commande 'journalctl' est utilisée pour afficher les journaux du système et des applications, collectés par le journal systemd."
        },
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
        {
            "level": "Facile", "option": "Linux", "game": GameType.QCM,
            "question_text": "Quelle commande permet de lister les fichiers et répertoires dans un répertoire sous Linux ?",
            "correct_answer": "ls",
            "options": "ls|cd|rm|touch",
            "explanation": "La commande 'ls' permet de lister les fichiers et répertoires dans le répertoire courant."
        },
        {
            "level": "Facile", "option": "Linux", "game": GameType.QCM,
            "question_text": "Quelle commande permet de changer de répertoire sous Linux ?",
            "correct_answer": "cd",
            "options": "cd|ls|rm|touch",
            "explanation": "La commande 'cd' (change directory) est utilisée pour naviguer entre les répertoires."
        },
        {
            "level": "Facile", "option": "Linux", "game": GameType.QCM,
            "question_text": "Quelle commande permet de créer un fichier vide sous Linux ?",
            "correct_answer": "touch",
            "options": "touch|rm|ls|cd",
            "explanation": "La commande 'touch' est utilisée pour créer un fichier vide ou pour mettre à jour les horodatages d'un fichier existant."
        },

        # Niveau Moyen
        {
            "level": "Moyen", "option": "Linux", "game": GameType.QCM,
            "question_text": "Quelle commande permet de copier des fichiers sous Linux ?",
            "correct_answer": "cp",
            "options": "cp|mv|rm|touch",
            "explanation": "La commande 'cp' (copy) est utilisée pour copier des fichiers ou des répertoires d'un emplacement à un autre."
        },
        {
            "level": "Moyen", "option": "Linux", "game": GameType.QCM,
            "question_text": "Quelle commande permet de déplacer ou renommer un fichier sous Linux ?",
            "correct_answer": "mv",
            "options": "mv|cp|rm|ls",
            "explanation": "La commande 'mv' (move) est utilisée pour déplacer des fichiers ou répertoires d'un emplacement à un autre, ou pour les renommer."
        },
        {
            "level": "Moyen", "option": "Linux", "game": GameType.QCM,
            "question_text": "Quelle commande permet d'afficher le contenu d'un fichier sous Linux ?",
            "correct_answer": "cat",
            "options": "cat|ls|touch|rm",
            "explanation": "La commande 'cat' (concatenate) est utilisée pour afficher le contenu d'un ou plusieurs fichiers à l'écran."
        },

        # Niveau Difficile
        {
            "level": "Difficile", "option": "Linux", "game": GameType.QCM,
            "question_text": "Quelle commande permet de modifier les permissions d'un fichier sous Linux ?",
            "correct_answer": "chmod",
            "options": "chmod|chown|chgrp|ls",
            "explanation": "La commande 'chmod' (change mode) est utilisée pour modifier les permissions d'accès des fichiers et répertoires."
        },
        {
            "level": "Difficile", "option": "Linux", "game": GameType.QCM,
            "question_text": "Quelle commande permet de modifier le propriétaire d'un fichier sous Linux ?",
            "correct_answer": "chown",
            "options": "chown|chmod|chgrp|ls",
            "explanation": "La commande 'chown' (change owner) est utilisée pour changer le propriétaire d'un fichier ou d'un répertoire."
        },
        {
            "level": "Difficile", "option": "Linux", "game": GameType.QCM,
            "question_text": "Quelle commande permet de rechercher des fichiers par nom dans le système de fichiers sous Linux ?",
            "correct_answer": "find",
            "options": "find|grep|locate|which",
            "explanation": "La commande 'find' est utilisée pour rechercher des fichiers et répertoires dans le système de fichiers en fonction de différents critères."
        }
    ]

    for q in questions:
        question = Question(
            level=q["level"],
            option=q["option"],
            game=q["game"],
            question_text=q["question_text"],
            correct_answer=q["correct_answer"],
            explanation=q["explanation"]
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
        {"level": "Facile", "option": "Sécurité des réseaux", "game": GameType.MOTUS, "question_text": "Le but est de trouver le mot sans dépasser 6 tentatives ou la partie est perdue.", "correct_answer": "Sécurité"},
        {"level": "Facile", "option": "Sécurité des réseaux", "game": GameType.MOTUS, "question_text": "Le but est de trouver le mot sans dépasser 6 tentatives ou la partie est perdue.", "correct_answer": "Firewall"},
        {"level": "Moyen", "option": "Sécurité des réseaux", "game": GameType.MOTUS, "question_text": "Le but est de trouver le mot sans dépasser 6 tentatives ou la partie est perdue.", "correct_answer": "Cryptage"},
        {"level": "Facile", "option": "Sécurité des réseaux", "game": GameType.MOTUS, "question_text": "Le but est de trouver le mot sans dépasser 6 tentatives ou la partie est perdue.", "correct_answer": "Intrusif"},
        {"level": "Moyen", "option": "Sécurité des réseaux", "game": GameType.MOTUS, "question_text": "Le but est de trouver le mot sans dépasser 6 tentatives ou la partie est perdue.", "correct_answer": "Vulnérable"},
        {"level": "Difficile", "option": "Sécurité des réseaux", "game": GameType.MOTUS, "question_text": "Le but est de trouver le mot sans dépasser 6 tentatives ou la partie est perdue.", "correct_answer": "Contournement"},
        {"level": "Difficile", "option": "Sécurité des réseaux", "game": GameType.MOTUS, "question_text": "Le but est de trouver le mot sans dépasser 6 tentatives ou la partie est perdue.", "correct_answer": "Authentification"},
        {"level": "Moyen", "option": "Sécurité des réseaux", "game": GameType.MOTUS, "question_text": "Le but est de trouver le mot sans dépasser 6 tentatives ou la partie est perdue.", "correct_answer": "Confidentialité"},
        {"level": "Facile", "option": "Sécurité des réseaux", "game": GameType.PENDU, "question_text": "Jeu du pendu, vous avez 10 tentatives.", "correct_answer": "Sécurité"},
        {"level": "Facile", "option": "Sécurité des réseaux", "game": GameType.PENDU, "question_text": "Jeu du pendu, vous avez 10 tentatives.", "correct_answer": "Firewall"},
        {"level": "Facile", "option": "Sécurité des réseaux", "game": GameType.PENDU, "question_text": "Jeu du pendu, vous avez 10 tentatives.", "correct_answer": "Cryptage"},
        {"level": "Facile", "option": "Sécurité des réseaux", "game": GameType.PENDU, "question_text": "Jeu du pendu, vous avez 10 tentatives.", "correct_answer": "Intrusif"},
        {"level": "Facile", "option": "Sécurité des réseaux", "game": GameType.PENDU, "question_text": "Jeu du pendu, vous avez 10 tentatives.", "correct_answer": "Vulnérable"},
        {"level": "Moyen", "option": "Sécurité des réseaux", "game": GameType.PENDU, "question_text": "Jeu du pendu, vous avez 10 tentatives.", "correct_answer": "Contournement"},
        {"level": "Moyen", "option": "Sécurité des réseaux", "game": GameType.PENDU, "question_text": "Jeu du pendu, vous avez 10 tentatives.", "correct_answer": "Authentification"},
        {"level": "Facile", "option": "Sécurité des réseaux", "game": GameType.PENDU, "question_text": "Jeu du pendu, vous avez 10 tentatives.", "correct_answer": "Confidentialité"}
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
        {
            "level": "Facile", "option": "Sécurité des réseaux", "game": GameType.QCM,
            "question_text": "Quelle est la principale fonction d'un pare-feu réseau ?",
            "correct_answer": "Filtrer le trafic",
            "options": "Filtrer le trafic|Chiffrer les données|Assurer la connectivité|Fournir du contenu",
            "explanation": "Un pare-feu réseau filtre le trafic réseau pour permettre ou bloquer certaines communications en fonction de règles de sécurité préétablies."
        },
        {
            "level": "Facile", "option": "Sécurité des réseaux", "game": GameType.QCM,
            "question_text": "Quel protocole est couramment utilisé pour sécuriser les communications sur Internet ?",
            "correct_answer": "HTTPS",
            "options": "HTTPS|FTP|Telnet|HTTP",
            "explanation": "HTTPS (Hypertext Transfer Protocol Secure) est le protocole utilisé pour sécuriser les communications sur Internet, notamment les transactions financières en ligne et l'accès aux pages web sensibles."
        },
        {
            "level": "Facile", "option": "Sécurité des réseaux", "game": GameType.QCM,
            "question_text": "Quelle technique consiste à transformer les données en une forme illisible pour protéger leur confidentialité ?",
            "correct_answer": "Chiffrement",
            "options": "Chiffrement|Compression|Redondance|Segmentation",
            "explanation": "Le chiffrement est une technique de sécurité qui transforme les données en une forme illisible à moins d'avoir la clé de déchiffrement correspondante."
        },

        # Niveau Moyen
        {
            "level": "Moyen", "option": "Sécurité des réseaux", "game": GameType.QCM,
            "question_text": "Quelle est la principale fonction d'un système de détection d'intrusion (IDS) ?",
            "correct_answer": "Surveiller le réseau pour détecter des activités malveillantes",
            "options": "Surveiller le réseau pour détecter des activités malveillantes|Bloquer le trafic indésirable|Gérer les connexions réseau|Fournir des adresses IP",
            "explanation": "Un système de détection d'intrusion surveille le trafic réseau pour détecter les activités malveillantes ou les violations de sécurité."
        },
        {
            "level": "Moyen", "option": "Sécurité des réseaux", "game": GameType.QCM,
            "question_text": "Quel protocole est utilisé pour sécuriser les communications par courriel ?",
            "correct_answer": "SSL/TLS",
            "options": "SSL/TLS|FTP|SMTP|POP3",
            "explanation": "SSL/TLS est utilisé pour sécuriser les communications par courriel en chiffrant les données lors de leur transfert entre les clients de messagerie et les serveurs de messagerie."
        },
        {
            "level": "Moyen", "option": "Sécurité des réseaux", "game": GameType.QCM,
            "question_text": "Quel type d'attaque consiste à intercepter les communications entre deux parties sans qu'elles le sachent ?",
            "correct_answer": "Attaque de l'homme du milieu (MITM)",
            "options": "Attaque de l'homme du milieu (MITM)|Phishing|DDoS|Ransomware",
            "explanation": "Une attaque de l'homme du milieu (MITM) consiste à intercepter les communications entre deux parties sans leur consentement ni leur connaissance."
        },

        # Niveau Difficile
        {
            "level": "Difficile", "option": "Sécurité des réseaux", "game": GameType.QCM,
            "question_text": "Quel est le principal avantage d'utiliser un VPN (réseau privé virtuel) ?",
            "correct_answer": "Sécuriser la communication sur un réseau public",
            "options": "Sécuriser la communication sur un réseau public|Augmenter la vitesse de connexion|Réduire les coûts de bande passante|Fournir un accès sans fil",
            "explanation": "Le principal avantage d'utiliser un VPN est de sécuriser la communication sur un réseau public en cryptant le trafic entre les appareils clients et le serveur VPN."
        },
        {
            "level": "Difficile", "option": "Sécurité des réseaux", "game": GameType.QCM,
            "question_text": "Quel protocole de sécurité est souvent utilisé pour créer un tunnel sécurisé entre deux points sur Internet ?",
            "correct_answer": "IPsec",
            "options": "IPsec|HTTP|FTP|ICMP",
            "explanation": "IPsec (Internet Protocol Security) est un ensemble de protocoles utilisés pour sécuriser les communications IP en fournissant des services d'authentification, d'intégrité des données et de confidentialité."
        },
        {
            "level": "Difficile", "option": "Sécurité des réseaux", "game": GameType.QCM,
            "question_text": "Quelle méthode de cryptographie utilise deux clés, une publique et une privée ?",
            "correct_answer": "Cryptographie asymétrique",
            "options": "Cryptographie asymétrique|Cryptographie symétrique|Hachage|Steganographie",
            "explanation": "La cryptographie asymétrique utilise deux clés distinctes, une publique et une privée, pour le chiffrement et le déchiffrement des données, offrant ainsi un niveau de sécurité plus élevé."
        }
    ]

    for q in questions:
        question = Question(
            level=q["level"],
            option=q["option"],
            game=q["game"],
            question_text=q["question_text"],
            correct_answer=q["correct_answer"],
            explanation=q["explanation"]
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
            "option": "Sécurité des réseaux",
            "game": GameType.QUESTION_SIMPLE,
            "question_text": "Quel protocole est utilisé pour sécuriser les communications Web ?",
            "correct_answer": "HTTPS",
            "explanation": "HTTPS (Hypertext Transfer Protocol Secure) est le protocole utilisé pour sécuriser les communications Web en chiffrant les données échangées entre le client et le serveur."
        },
        {
            "level": "Facile",
            "option": "Sécurité des réseaux",
            "game": GameType.QUESTION_SIMPLE,
            "question_text": "Quel est le nom du protocole utilisé pour sécuriser l'accès à distance aux systèmes informatiques ?",
            "correct_answer": "SSH",
            "explanation": "SSH (Secure Shell) est un protocole de réseau sécurisé utilisé pour sécuriser les connexions à distance aux systèmes informatiques, permettant un accès sécurisé et crypté."
        },
        {
            "level": "Facile",
            "option": "Sécurité des réseaux",
            "game": GameType.QUESTION_SIMPLE,
            "question_text": "Quel type d'attaque cherche à intercepter les communications entre un client et un serveur pour voler des informations ?",
            "correct_answer": "Man-in-the-middle",
            "explanation": "Une attaque de l'homme du milieu (MITM) vise à intercepter les communications entre un client et un serveur pour voler des informations sensibles telles que les identifiants de connexion ou les données confidentielles."
        },
        # Questions de niveau Moyen
        {
            "level": "Moyen",
            "option": "Sécurité des réseaux",
            "game": GameType.QUESTION_SIMPLE,
            "question_text": "Quel protocole est utilisé pour sécuriser les emails ?",
            "correct_answer": "SMTPS",
            "explanation": "SMTPS (Simple Mail Transfer Protocol Secure) est une extension sécurisée du protocole SMTP utilisé pour sécuriser les communications par courrier électronique en chiffrant les données lors de leur transfert."
        },
        {
            "level": "Moyen",
            "option": "Sécurité des réseaux",
            "game": GameType.QUESTION_SIMPLE,
            "question_text": "Quel est le terme utilisé pour désigner un logiciel malveillant capable de se propager à travers un réseau sans intervention humaine ?",
            "correct_answer": "Ver",
            "explanation": "Un ver est un type de logiciel malveillant autonome capable de se propager à travers un réseau informatique sans intervention humaine, infectant les hôtes qu'il rencontre."
        },
        {
            "level": "Moyen",
            "option": "Sécurité des réseaux",
            "game": GameType.QUESTION_SIMPLE,
            "question_text": "Quel protocole est utilisé pour sécuriser les connexions VPN ?",
            "correct_answer": "IPsec",
            "explanation": "IPsec (Internet Protocol Security) est un protocole utilisé pour sécuriser les communications VPN (Virtual Private Network) en fournissant des services de sécurité tels que l'authentification et le chiffrement des données."
        },
        # Questions de niveau Difficile
        {
            "level": "Difficile",
            "option": "Sécurité des réseaux",
            "game": GameType.QUESTION_SIMPLE,
            "question_text": "Quel protocole de routage dynamique est sécurisé par défaut avec l'utilisation d'authentification MD5 ?",
            "correct_answer": "BGP",
            "explanation": "BGP (Border Gateway Protocol) est un protocole de routage dynamique sécurisé par défaut avec l'utilisation d'authentification MD5 (Message Digest Algorithm 5) pour sécuriser les échanges de routeurs entre les systèmes autonomes sur Internet."
        },
        {
            "level": "Difficile",
            "option": "Sécurité des réseaux",
            "game": GameType.QUESTION_SIMPLE,
            "question_text": "Quel est le terme utilisé pour désigner un logiciel malveillant qui se cache à l'intérieur d'un autre programme ?",
            "correct_answer": "Troyen",
            "explanation": "Un troyen est un type de logiciel malveillant qui se cache à l'intérieur d'un programme légitime pour infecter les systèmes informatiques et exécuter des actions malveillantes à l'insu de l'utilisateur."
        },
        {
            "level": "Difficile",
            "option": "Sécurité des réseaux",
            "game": GameType.QUESTION_SIMPLE,
            "question_text": "Quel protocole de chiffrement asymétrique est utilisé pour sécuriser les connexions HTTPS ?",
            "correct_answer": "RSA",
            "explanation": "RSA est un algorithme de chiffrement asymétrique largement utilisé pour sécuriser les connexions HTTPS en fournissant un mécanisme de chiffrement sécurisé basé sur des clés publiques et privées."
        }
    ]

    # Ajouter les questions à la base de données
    for q in questions:
        question = Question(
            level=q["level"],
            option=q["option"],
            game=q["game"],
            question_text=q["question_text"],
            correct_answer=q["correct_answer"],
            explanation=q["explanation"]
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
