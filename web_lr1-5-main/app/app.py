import random
from functools import lru_cache, wraps
from datetime import datetime, timedelta
from flask import request
import re

from flask import (
    Flask, render_template, abort, Response,
    request, make_response, redirect, url_for,
    flash, session
)
from faker import Faker
from flask_login import (
    LoginManager, login_user, logout_user,
    login_required, current_user
)

# === Приложение и конфигурация ===
app = Flask(__name__)
app.config['SECRET_KEY'] = 'your-secret-key'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.permanent_session_lifetime = timedelta(days=7)
import os

basedir = os.path.abspath(os.path.dirname(__file__))

app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + os.path.join(basedir, 'app.db')

print(">>> Using database:", os.path.abspath(
    os.path.join(os.path.dirname(__file__), "app.db")
))

# === Инициализация базы данных ===
from app.models import db, User, Role, VisitLog

db.init_app(app)

# === Настройка Flask-Login ===
login_manager = LoginManager(app)
login_manager.login_view = 'login'
login_manager.login_message = "Пожалуйста, войдите в систему для доступа к этой странице."
login_manager.login_message_category = "warning"

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

    
# === Faker для фейковых постов ===
fake = Faker()
images_ids = [
    '7d4e9175-95ea-4c5f-8be5-92a6b708bb3c',
    '2d2ab7df-cdbc-48a8-a936-35bba702def5',
    '6e12f3de-d5fd-4ebb-855b-8cbc485278b7',
    'afc2cfe7-5cac-4b80-9b9a-d5c65ef0c728',
    'cab5b7f2-774e-4884-a200-0c0180fa777f'
]

def generate_comments(replies=True):
    comments = []
    for _ in range(random.randint(1, 3)):
        c = {'author': fake.name(), 'text': fake.text()}
        if replies:
            c['replies'] = generate_comments(False)
        comments.append(c)
    return comments

def generate_post(i):
    return {
        'title': fake.sentence(),
        'text': fake.paragraph(nb_sentences=100),
        'author': fake.name(),
        'date': fake.date_time_between('-2y', 'now'),
        'image_id': f'{images_ids[i]}.jpg',
        'comments': generate_comments()
    }

def check_rights(allowed_roles, own_allowed=False):

    def decorator(f):
        @wraps(f)
        def wrapper(*args, **kwargs):
            if not current_user.is_authenticated:
                return login_manager.unauthorized()
            role = current_user.role.name if current_user.role else None
            # админ или нужная роль
            if role == 'Administrator' or role in allowed_roles:
                return f(*args, **kwargs)
            # разрешаем над собой
            if own_allowed and kwargs.get('user_id') == current_user.id:
                return f(*args, **kwargs)
            flash("У вас недостаточно прав для доступа к данной странице.", "warning")
            return redirect(url_for('index'))
        return wrapper
    return decorator

@lru_cache
def posts_list():
    return sorted([generate_post(i) for i in range(5)],
                  key=lambda p: p['date'], reverse=True)

# === Роуты ===

with app.app_context():
    db.create_all()



@app.route('/dump')
def dump_db():
    rows = []
    for u in User.query.all():
        rows.append({
            'id': u.id,
            'login': u.login,
            'ФИО': f"{u.surname} {u.name} {u.patronymic}",
            'role': u.role.name if u.role else None,
            'created_at': u.created_at.isoformat()
        })
    return {'users': rows}

@app.route('/')
def index():
    users = User.query.order_by(User.id).all()
    return render_template('index.html', users=users)

@app.route('/view_user/<int:user_id>')
@login_required
@check_rights(['User'], own_allowed=True)
def view_user(user_id):
    user = User.query.get_or_404(user_id)
    return render_template('view_user.html', user=user)

@app.route('/create_user', methods=['GET', 'POST'])
@login_required
@check_rights(['Administrator'])
def create_user():
    roles = Role.query.order_by(Role.name).all()
    errors = {}
    form = {}

    if request.method == 'POST':
        form['login'] = request.form.get('login', '').strip()
        form['password'] = request.form.get('password', '')
        form['surname'] = request.form.get('surname', '').strip()
        form['name'] = request.form.get('name', '').strip()
        form['patronymic'] = request.form.get('patronymic', '').strip()
        form['role_id'] = request.form.get('role_id', '')

        if not form['login']:
            errors['login'] = 'Поле не может быть пустым'
        elif not re.match(r'^[A-Za-z0-9]{5,}$', form['login']):
            errors['login'] = 'Логин должен состоять из латинских букв и цифр, минимум 5 символов'

        pwd = form['password']
        if not pwd:
            errors['password'] = 'Поле не может быть пустым'
        else:
            if len(pwd) < 8 or len(pwd) > 128:
                errors['password'] = 'Пароль должен быть от 8 до 128 символов'
            elif not re.search(r'[A-Z]', pwd) or not re.search(r'[a-z]', pwd):
                errors['password'] = 'Пароль должен содержать и заглавные, и строчные буквы'
            elif not re.search(r'\d', pwd):
                errors['password'] = 'Пароль должен содержать хотя бы одну цифру'
            elif ' ' in pwd:
                errors['password'] = 'Пароль не должен содержать пробелов'
            elif not re.match(r'^[A-Za-zА-Яа-я0-9~!?@#$%^&*_\-+()\[\]{}><\\|"\'.:,]+$', pwd):
                errors['password'] = 'Пароль содержит недопустимые символы'

        if not form['surname']:
            errors['surname'] = 'Поле не может быть пустым'
        if not form['name']:
            errors['name'] = 'Поле не может быть пустым'

        role = None
        if form['role_id']:
            role = Role.query.get(int(form['role_id']))
            if not role:
                errors['role'] = 'Выбранная роль недействительна'

        if errors:
            return render_template('create_user.html', roles=roles, errors=errors, form=form)

        new_user = User(
            login=form['login'], surname=form['surname'],
            name=form['name'], patronymic=form['patronymic'], role=role
        )
        new_user.set_password(form['password'])
        db.session.add(new_user)
        try:
            db.session.commit()
            flash('Пользователь успешно создан', 'success')
            return redirect(url_for('index'))
        except Exception as e:
            db.session.rollback()
            flash('Ошибка при создании пользователя: ' + str(e), 'danger')
            return render_template('create_user.html', roles=roles, errors=errors, form=form)

    return render_template('create_user.html', roles=roles, errors=errors, form=form)

@app.route('/edit_user/<int:user_id>', methods=['GET', 'POST'])
@login_required
@check_rights(['User'], own_allowed=True)
def edit_user(user_id):
    user = User.query.get_or_404(user_id)
    roles = Role.query.order_by(Role.name).all()
    errors = {}
    form = {}

    if request.method == 'POST':
        form['surname'] = request.form.get('surname', '').strip()
        form['name'] = request.form.get('name', '').strip()
        form['patronymic'] = request.form.get('patronymic', '').strip()
        form['role_id'] = request.form.get('role_id', '')

        if not form['surname']:
            errors['surname'] = 'Поле не может быть пустым'
        if not form['name']:
            errors['name'] = 'Поле не может быть пустым'
        role = None
        if form['role_id']:
            role = Role.query.get(int(form['role_id']))
            if not role:
                errors['role'] = 'Выбранная роль недействительна'

        if errors:
            return render_template('edit_user.html', user=user, roles=roles, errors=errors)

        user.surname = form['surname']
        user.name = form['name']
        user.patronymic = form['patronymic']
        user.role = role
        try:
            db.session.commit()
            flash('Пользователь успешно обновлён', 'success')
            return redirect(url_for('index'))
        except Exception as e:
            db.session.rollback()
            flash('Ошибка при обновлении пользователя: ' + str(e), 'danger')
            return render_template('edit_user.html', user=user, roles=roles, errors=errors)

    return render_template('edit_user.html', user=user, roles=roles, errors=errors)

@app.route('/delete_user/<int:user_id>', methods=['POST'])
@login_required
@check_rights(['User'], own_allowed=True)
def delete_user(user_id):
    user = User.query.get_or_404(user_id)
    try:
        db.session.delete(user)
        db.session.commit()
        flash('Пользователь "{} {} {}" успешно удалён'.format(
            user.surname or '', user.name or '', user.patronymic or ''
        ), 'success')
    except Exception as e:
        db.session.rollback()
        flash('Ошибка при удалении пользователя: ' + str(e), 'danger')
    return redirect(url_for('index'))

@app.route('/change_password', methods=['GET', 'POST'])
@login_required
def change_password():
    errors = {}
    if request.method == 'POST':
        old = request.form.get('old_password', '')
        new = request.form.get('new_password', '')
        confirm = request.form.get('confirm_password', '')

        if not current_user.check_password(old):
            errors['old_password'] = 'Неверный старый пароль'

        if not new:
            errors['new_password'] = 'Поле не может быть пустым'
        else:
            if len(new) < 8 or len(new) > 128:
                errors['new_password'] = 'Пароль должен быть от 8 до 128 символов'
            elif not re.search(r'[A-Z]', new) or not re.search(r'[a-z]', new):
                errors['new_password'] = 'Пароль должен содержать и заглавные, и строчные буквы'
            elif not re.search(r'\d', new):
                errors['new_password'] = 'Пароль должен содержать хотя бы одну цифру'
            elif ' ' in new:
                errors['new_password'] = 'Пароль не должен содержать пробелов'
            elif not re.match(r'^[A-Za-zА-Яа-я0-9~!?@#$%^&*\_\-+()\[\]{}><\\|"\'.:,]+$', new):
                errors['new_password'] = 'Пароль содержит недопустимые символы'

        if new != confirm:
            errors['confirm_password'] = 'Пароли не совпадают'

        if errors:
            return render_template('change_password.html', errors=errors)

        current_user.set_password(new)
        try:
            db.session.commit()
            flash('Пароль успешно изменён', 'success')
            return redirect(url_for('index'))
        except Exception as e:
            db.session.rollback()
            flash('Ошибка при смене пароля: ' + str(e), 'danger')
            return render_template('change_password.html', errors=errors)

    return render_template('change_password.html', errors={})

@app.route('/posts')
def posts():
    return render_template('posts.html', title='Посты', posts=posts_list())

@app.route('/posts/<int:index>')
def post(index):
    if index < 0 or index >= len(posts_list()):
        abort(404)
    return render_template('post.html', title=posts_list()[index]['title'],
                           post=posts_list()[index])

@app.route('/about')
def about():
    return render_template('about.html', title='Об авторе')

@app.errorhandler(404)
def page_not_found(e):
    return Response('404 Not Found', status=404)

@app.route('/url-params')
def url_params():
    return render_template('url_params.html', title='Параметры URL',
                           params=request.args)

@app.route('/headers')
def headers():
    return render_template('headers.html', title='Заголовки запроса',
                           headers=dict(request.headers))

@app.route('/cookies', methods=['GET', 'POST'])
def cookies():
    resp = make_response()
    name = 'my_cookie'
    if request.method == 'POST':
        action = request.form.get('action')
        resp = make_response(redirect(url_for('cookies')))
        if action == 'set':
            resp.set_cookie(name, 'cookie_value', max_age=86400)
        else:
            resp.delete_cookie(name)
        return resp
    cookie_set = request.cookies.get(name)
    message = "Cookie установлено." if cookie_set else "Cookie не установлено."
    return render_template('cookies.html', title='Cookie',
                           message=message, cookie_set=cookie_set)

@app.route('/form_params', methods=['GET', 'POST'])
def form_params():
    data = request.form if request.method == 'POST' else {}
    return render_template('form_params.html', title='Параметры формы',
                           form_data=data)

@app.route('/phone_validation', methods=['GET', 'POST'])
def phone_validation():
    error = formatted = None
    if request.method == 'POST':
        phone = request.form.get('phone', '')
        clean = re.sub(r"[^\d]", "", phone)
        if not clean.isdigit():
            error = "Недопустимые символы."
        elif not (10 <= len(clean) <= 11):
            error = "Неверное количество цифр."
        else:
            if clean.startswith(('7','8')):
                clean = '8' + clean[-10:]
            formatted = f"{clean[0]}-{clean[1:4]}-{clean[4:7]}-{clean[7:9]}-{clean[9:11]}"
    return render_template('phone_validation.html', title='Проверка телефона',
                           error=error, formatted_phone=formatted)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        login_ = request.form['username']
        pwd = request.form['password']
        user = User.query.filter_by(login=login_).first()
        if user and user.check_password(pwd):
            login_user(user, remember='remember' in request.form)
            flash("Успешный вход", "success")
            return redirect(request.args.get('next') or url_for('index'))
        flash("Неверный логин или пароль", "danger")
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash("Вы вышли", "info")
    return redirect(url_for('index'))

@app.route('/secret')
@login_required
def secret():
    return render_template('secret.html')

@app.route('/visit_logs')
@login_required
def visit_logs():
    # страница из ?page=
    page = request.args.get('page', 1, type=int)
    per_page = 5

    # общий запрос
    query = VisitLog.query.order_by(VisitLog.created_at.desc())
    # если не админ — только свои логи
    if not (current_user.role and current_user.role.name == 'Administrator'):
        query = query.filter(VisitLog.user_id == current_user.id)

    pagination = query.paginate(page=page, per_page=per_page, error_out=False)
    return render_template('visit_logs.html', pagination=pagination)

user_visits = {}

@app.route('/counter')
def counter():
    if current_user.is_authenticated:
        username = current_user.name
        user_visits[username] = user_visits.get(username, 0) + 1
        visits = user_visits[username]
    else:
        session.permanent = True
        session['visits'] = session.get('visits', 0) + 1
        visits = session['visits']
    return render_template('counter.html', visits=visits)

@app.after_request
def log_visit(response):
    # не логируем статику и сам журнал
    if request.endpoint not in ('static',) and not request.path.startswith('/visit_logs'):
        visit = VisitLog(
            path=request.path,
            user_id=current_user.id if current_user.is_authenticated else None
        )
        db.session.add(visit)
        db.session.commit()
    return response

print(app.url_map)

# === Запуск приложения ===
if __name__ == '__main__':
    with app.app_context():
        db.create_all()
        # Регистрация Blueprint-а делаем здесь, чтобы избежать циклического импорта
        import visit_logs
        app.register_blueprint(visit_logs.visit_logs_bp, url_prefix='/visit_logs')
    app.run(debug=True)
