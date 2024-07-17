# Imports
import os
import re
from flask import Flask, render_template, request, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user
from werkzeug.security import generate_password_hash, check_password_hash
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, ValidationError
from wtforms.validators import DataRequired, Length, Regexp

# Nome para o aplicativo do Flask de acordo com a própria convenção
app = Flask(__name__)

# Secret Key
app.config['SECRET_KEY'] = os.urandom(24)

# Configurações (Banco de Dados)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///tasks.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

# Configurações (Login)
login_manager = LoginManager(app)
login_manager.login_view = 'login'


# Models
class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), nullable=False, unique=True)
    password = db.Column(db.String(150), nullable=False)


class Task(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    task = db.Column(db.String(200), nullable=False)
    done = db.Column(db.Boolean(200), default=False)


class CompletedTask(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    task = db.Column(db.String(200), nullable=False)
    undo_id = db.Column(db.Integer, db.ForeignKey('task.id'))


class DeletedTask(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    task = db.Column(db.String(200), nullable=False)
    undo_id = db.Column(db.Integer, db.ForeignKey('task.id'))


def create_tables():
    db.create_all()


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


# Validator de senha
def password_validator(form, field):
    password = field.data
    if (len(password) < 8 or
        not re.search(r'[A-Z]', password) or
        not re.search(r'[0-9]', password) or
        not re.search(r'[@$!%*?&]', password)):
        raise ValidationError(
            'A senha deve ter pelo menos 8 caracteres, incluir uma letra maiúscula, um número e um caractere especial.'
        )


# Formulários
class RegistrationForm(FlaskForm):
    username = StringField('Username',
                           validators=[
                               DataRequired(),
                               Length(min=4, max=150),
                               Regexp(r'^[A-Za-z0-9_]+$',
                                      message='O nome de usuário deve conter apenas números ou underscore')
                           ])
    password = PasswordField('Password',
                             validators=[
                                 DataRequired(),
                                 password_validator
                             ])
    submit = SubmitField('Register')


class LoginForm(FlaskForm):
    username = StringField('Username',
                           validators=[
                               DataRequired(),
                               Length(min=4, max=150)
                           ])
    password = PasswordField('Password',
                             validators=[
                                 DataRequired()
                             ])
    submit = SubmitField('Login')


# Rotas
@app.route('/')
@login_required
def index():
    tasks = Task.query.filter_by(done=False).all()
    completed_tasks = CompletedTask.query.all()
    deleted_tasks = DeletedTask.query.all()
    return render_template('index.html', tasks=tasks, completed_tasks=completed_tasks, deleted_tasks=deleted_tasks)


@app.route('/add', methods=['POST'])
@login_required
def add_task():
    task_content = request.form.get('task')
    if task_content:
        new_task = Task(task=task_content)
        db.session.add(new_task)
        db.session.commit()

    return redirect(url_for('index'))


@app.route('/complete/<int:task_id>')
@login_required
def complete_task(task_id):
    task = Task.query.get_or_404(task_id)
    task.done = True
    completed_task = CompletedTask(task=task.task, undo_id=task_id)

    db.session.add(completed_task)
    db.session.delete(task)
    db.session.commit()

    return redirect(url_for('index'))


@app.route('/delete/<int:task_id>')
@login_required
def delete_task(task_id):
    task = Task.query.get_or_404(task_id)
    deleted_task = DeletedTask(task=task.task, undo_id=task_id)

    db.session.add(deleted_task)
    db.session.delete(task)
    db.session.commit()

    return redirect(url_for('index'))


@app.route('/undo_complete/<int:completed_id>')
@login_required
def undo_complete(completed_id):
    completed_task = CompletedTask.query.get_or_404(completed_id)
    new_task = Task(task=completed_task.task, done=False)

    db.session.add(new_task)
    db.session.delete(completed_task)
    db.session.commit()

    return redirect(url_for('index'))


@app.route('/undo_delete/<int:deleted_id>')
@login_required
def undo_delete(deleted_id):
    deleted_task = DeletedTask.query.get_or_404(deleted_id)
    new_task = Task(task=deleted_task.task, done=False)

    db.session.add(new_task)
    db.session.delete(deleted_task)
    db.session.commit()

    return redirect(url_for('index'))


@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegistrationForm()
    if form.validate_on_submit():
        hashed_password = generate_password_hash(form.password.data, method='pbkdf2:sha256')
        new_user = User(username=form.username.data, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()
        return redirect(url_for('login'))
    return render_template('register.html', form=form)


@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user and check_password_hash(user.password, form.password.data):
            login_user(user)
            return redirect(url_for('index'))
        else:
            flash('Falha no login. Verifique o nome de usuário ou senha.', 'danger')
    return render_template('login.html', form=form)


@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))


# Faz com que todas as mudanças que sejam feitas sejam mostradas automaticamente
if __name__ == '__main__':
    with app.app_context():
        create_tables()
    app.run(debug=True)
