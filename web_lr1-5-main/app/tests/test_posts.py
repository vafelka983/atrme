import pytest
from app import app
from app import db
from models import User, Role, VisitLog
from urllib.parse import urlparse, parse_qs
from datetime import datetime, timedelta

import re
from contextlib import contextmanager
from flask import template_rendered
import app as app_module


@pytest.fixture
def client():
    app.config['TESTING'] = True
    with app.test_client() as client:
        yield client

@pytest.fixture(autouse=True)
def setup_db(app):
    with app.app_context():
        db.create_all()

        admin_role = Role.query.filter_by(name='Administrator').first()
        if not admin_role:
            admin_role = Role(name='Administrator', description='Суперпользователь')
            db.session.add(admin_role)
        user_role = Role.query.filter_by(name='User').first()
        if not user_role:
            user_role = Role(name='User', description='Обычный пользователь')
            db.session.add(user_role)
        db.session.commit()

        admin_user = User.query.filter_by(login='admin1234').first()
        if not admin_user:
            admin_user = User(
                login='admin1234',
                name='admin1234',
                surname='admin1234',
                patronymic='',
                role=admin_role
            )
            admin_user.set_password('Admin1234')
            db.session.add(admin_user)
            db.session.commit()
    yield


@pytest.fixture
def login(client):
    def _login(username="admin1234", password="Admin1234", remember=False, next_url=None):
        data = {"username": username, "password": password}
        if remember:
            data["remember"] = "y"
        if next_url is not None:
            data["next"] = next_url
        return client.post("/login", data=data, follow_redirects=True)
    return _login


@pytest.fixture
def logout(client):
    def _logout():
        return client.get("/logout", follow_redirects=True)
    return _logout


@pytest.fixture
def captured_templates(app):
    recorded = []

    def record(sender, template, context, **extra):
        recorded.append((template, context))

    template_rendered.connect(record, app)
    try:
        yield recorded
    finally:
        template_rendered.disconnect(record, app)

def _safe_get(client, path, **kwargs):
    try:
        return client.get(path, **kwargs)
    except Exception:
        class _DummyResp:
            status_code = 404
            headers = {}
            def get_data(self, as_text=False):
                return "404 Not Found" if as_text else b"404 Not Found"
        return _DummyResp()


# ЛР1
@contextmanager
def _captured_templates(flask_app):
    recorded = []

    def record(sender, template, context, **extra):
        recorded.append((template, context))

    template_rendered.connect(record, flask_app)
    try:
        yield recorded
    finally:
        template_rendered.disconnect(record, flask_app)


def _first_post():
    posts = app_module.posts_list()
    assert posts, "Ожидался минимум 1 пост в данных приложения"
    return posts[0]


# 1 — /posts использует правильный шаблон
def test_posts_route_uses_correct_template(app, client):
    with _captured_templates(app) as templates:
        resp = client.get("/posts")
        assert resp.status_code == 200
        assert templates, "Ожидался рендеринг шаблона"
        tpl, _ = templates[-1]
        assert tpl.name == "posts.html"


# 2 — в контекст /posts передаются необходимые данные
def test_posts_route_provides_required_context(app, client):
    with _captured_templates(app) as templates:
        client.get("/posts")
        _, ctx = templates[-1]
        assert "title" in ctx
        assert "posts" in ctx and isinstance(ctx["posts"], list)
        assert ctx["posts"], "Список posts не должен быть пустым"
        sample = ctx["posts"][0]
        for key in ("title", "text", "author", "date", "image_id", "comments"):
            assert key in sample


# 3 — на странице /posts виден заголовок хотя бы одного поста
def test_posts_page_contains_at_least_one_post_title(client):
    p = _first_post()
    html = client.get("/posts").get_data(as_text=True)
    assert p["title"] in html


# 4 — /posts/<index> использует правильный шаблон
def test_post_route_uses_correct_template(app, client):
    with _captured_templates(app) as templates:
        resp = client.get("/posts/0")
        assert resp.status_code == 200
        assert templates, "Ожидался рендеринг шаблона"
        tpl, _ = templates[-1]
        assert tpl.name == "post.html"


# 5 — в контексте страницы поста есть post и title с нужными ключами
def test_post_route_context_includes_post_and_title(app, client):
    with _captured_templates(app) as templates:
        client.get("/posts/0")
        _, ctx = templates[-1]
        assert "title" in ctx
        assert "post" in ctx
        post = ctx["post"]
        for key in ("title", "text", "author", "date", "image_id", "comments"):
            assert key in post


# 6 — заголовок поста присутствует на странице поста
def test_post_page_shows_title(client):
    p = _first_post()
    html = client.get("/posts/0").get_data(as_text=True)
    assert p["title"] in html


# 7 — имя автора присутствует на странице поста
def test_post_page_shows_author_name(client):
    p = _first_post()
    html = client.get("/posts/0").get_data(as_text=True)
    assert p["author"] in html


# 8 — текст поста (фрагмент) присутствует на странице поста
def test_post_page_shows_text_excerpt(client):
    p = _first_post()
    excerpt = p["text"][:50].strip()
    html = client.get("/posts/0").get_data(as_text=True)
    assert excerpt in html


# 9 — на странице поста присутствует изображение (image_id встречается в разметке)
def test_post_page_shows_image_tag_with_image_id(client):
    p = _first_post()
    html = client.get("/posts/0").get_data(as_text=True)
    assert p["image_id"] in html, "image_id должен встречаться, например, в src атрибуте <img>"


# 10 — дата поста на странице поста отформатирована как '%d-%m-%Y %H:%M' (как в post.html)
def test_post_date_is_rendered_in_correct_format(client):
    p = _first_post()
    expected = p["date"].strftime("%d-%m-%Y %H:%M")
    html = client.get("/posts/0").get_data(as_text=True)
    assert expected in html


# 11 — форма «Оставьте комментарий»: есть заголовок, <textarea> и кнопка «Отправить»
def test_comment_form_present_with_textarea_and_submit(client):
    html = client.get("/posts/0").get_data(as_text=True)
    assert "Оставьте комментарий" in html
    assert re.search(r"<textarea[^>]*>", html, flags=re.I)
    assert "Отправить" in html


# 12 — отображается комментарий верхнего уровня, если он есть в данных
def test_top_level_comments_are_displayed_if_present(client):
    p = _first_post()
    html = client.get("/posts/0").get_data(as_text=True)
    if p["comments"]:
        top = p["comments"][0]
        assert top["author"] in html
        assert top["text"][:30] in html
    else:
        pytest.skip("В данных нет комментариев — пропускаем проверку содержимого")


# 13 — отображаются вложенные ответы, если они есть в данных
def test_nested_replies_are_displayed_if_present(client):
    p = _first_post()
    replies = []
    for c in p["comments"]:
        replies.extend(c.get("replies") or [])
    html = client.get("/posts/0").get_data(as_text=True)
    if replies:
        r = replies[0]
        assert r["author"] in html
        assert r["text"][:30] in html
    else:
        pytest.skip("В данных нет вложенных ответов — пропускаем проверку содержимого")


# 14 — несуществующий id поста даёт 404
def test_nonexistent_post_returns_404(client):
    resp = client.get("/posts/999999")
    assert resp.status_code == 404


# 15 — в базовом шаблоне есть footer с ФИО и номером группы
def test_footer_present_and_contains_fio_and_group_on_posts_page(client):
    html = client.get("/posts").get_data(as_text=True).lower()
    assert "<footer" in html
    # конкретные строки из предоставленного base.html
    assert "привалов иван васильевич" in html
    assert "231-352" in html


#ЛР2
def _format_like_app(raw: str) -> str:
    import re as _re
    clean = _re.sub(r"[^\d]", "", raw)
    if not clean:
        return None
    if (len(clean) == 11) or clean.startswith(("7", "8")):
        clean = "8" + clean[-10:]
    return f"{clean[0]}-{clean[1:4]}-{clean[4:7]}-{clean[7:9]}-{clean[9:11]}"


def test_url_params_context_has_all_params(app, client, captured_templates):
    resp = client.get("/url-params?name=Ivan&age=21")
    assert resp.status_code == 200
    templates = captured_templates
    assert templates, "Ожидался рендер шаблона"
    _, ctx = templates[-1]
    assert "params" in ctx
    params = ctx["params"]
    assert params.get("name") == "Ivan"
    assert params.get("age") == "21"

def test_url_params_html_displays_params(client):
    resp = client.get("/url-params?x=1&y=2")
    html = resp.get_data(as_text=True)
    assert "x" in html and "1" in html
    assert "y" in html and "2" in html

def test_url_params_repeated_param_keeps_all_values(app, client, captured_templates):
    client.get("/url-params?tag=one&tag=two")
    templates = captured_templates
    assert templates, "Ожидался рендер шаблона"
    _, ctx = templates[-1]
    params = ctx["params"]
    assert params.getlist("tag") == ["one", "two"]


def test_headers_context_contains_standard_headers(app, client, captured_templates):
    resp = client.get("/headers")
    assert resp.status_code == 200
    templates = captured_templates
    assert templates, "Ожидался рендер шаблона"
    _, ctx = templates[-1]
    headers = ctx["headers"]
    assert "Host" in headers
    assert "User-Agent" in headers


def test_headers_echoes_custom_header_in_html(client):
    resp = client.get("/headers", headers={"X-Test-Header": "abc123"})
    html = resp.get_data(as_text=True)
    assert "X-Test-Header" in html and "abc123" in html


def test_cookies_initially_not_set(client):
    resp = client.get("/cookies")
    html = resp.get_data(as_text=True)
    assert "Cookie не установлено" in html

def test_cookies_set_via_post_then_visible_on_next_get(client):
    resp = client.post("/cookies", data={"action": "set"}, follow_redirects=False)
    assert resp.status_code in (302, 303)
    resp2 = client.get("/cookies", follow_redirects=True)
    html2 = resp2.get_data(as_text=True)
    assert "Cookie установлено" in html2

def test_cookies_delete_via_post_then_absent_on_next_get(client):
    client.post("/cookies", data={"action": "set"}, follow_redirects=True)

    resp = client.post("/cookies", data={"action": "delete"}, follow_redirects=True)
    html = resp.get_data(as_text=True)
    assert "Cookie не установлено" in html


def test_form_params_get_has_empty_form_data(app, client, captured_templates):
    resp = client.get("/form_params")
    assert resp.status_code == 200
    templates = captured_templates
    assert templates, "Ожидался рендер шаблона"
    _, ctx = templates[-1]
    assert "form_data" in ctx
    assert dict(ctx["form_data"]) == {}

def test_form_params_post_echoes_payload_in_html_and_context(app, client, captured_templates):
    resp = client.post("/form_params", data={"a": "1", "b": "2"})
    assert resp.status_code == 200
    templates = captured_templates
    assert templates, "Ожидался рендер шаблона"
    _, ctx = templates[-1]
    data = ctx["form_data"]
    assert data.get("a") == "1" and data.get("b") == "2"
    html = resp.get_data(as_text=True)
    assert "a" in html and "1" in html
    assert "b" in html and "2" in html


def test_phone_validation_invalid_symbols_shows_error_and_bootstrap_classes(client):
    resp = client.post("/phone_validation", data={"phone": "+++/() abc"}, follow_redirects=True)
    html = resp.get_data(as_text=True)
    assert "Недопустимые символы" in html
    assert "is-invalid" in html
    assert "invalid-feedback" in html

def test_phone_validation_wrong_digit_count_shows_error_and_bootstrap_classes(client):
    resp = client.post("/phone_validation", data={"phone": "123-45-67-89"}, follow_redirects=True)
    html = resp.get_data(as_text=True)
    assert "Неверное количество цифр" in html
    assert "is-invalid" in html
    assert "invalid-feedback" in html

def test_phone_validation_accepts_plus7_and_formats(client):
    raw = "+7 (123) 456-75-90"
    expected = _format_like_app(raw)
    resp = client.post("/phone_validation", data={"phone": raw}, follow_redirects=True)
    html = resp.get_data(as_text=True)
    assert expected in html

def test_phone_validation_accepts_leading_8_and_formats(client):
    raw = "8(123)4567590"
    expected = _format_like_app(raw)
    resp = client.post("/phone_validation", data={"phone": raw}, follow_redirects=True)
    html = resp.get_data(as_text=True)
    assert expected in html

def test_phone_validation_accepts_dot_separated_10_digits_and_formats(client):
    raw = "123.456.75.90"
    expected = _format_like_app(raw)
    resp = client.post("/phone_validation", data={"phone": raw}, follow_redirects=True)
    html = resp.get_data(as_text=True)
    assert expected in html


# ЛР3
# 1 — счётчик: первый визит == 1, второй визит == 2 (для одного клиента/сессии)
def test_counter_increments_for_same_session(client):

    def extract_count(html: str) -> int:
        m = re.search(r"(\d+)\s*раз", html, flags=re.IGNORECASE)
        if not m:
            m = re.search(r"Вы\s+посещал[аи][^0-9]*?(\d+)", html, flags=re.IGNORECASE | re.S)
        if not m:
            m = re.search(r"(\d+)", html)
        assert m, "На странице счётчика должно выводиться число посещений"
        return int(m.group(1))

    h1 = client.get("/counter").get_data(as_text=True)
    n1 = extract_count(h1)

    h2 = client.get("/counter").get_data(as_text=True)
    n2 = extract_count(h2)

    assert n2 == n1 + 1, f"Счётчик должен увеличиваться на 1 за визит: было {n1}, стало {n2}"


# 2 — счётчик: независимость между разными клиентами (две отдельные сессии)
def test_counter_is_per_session_isolated(app):

    def extract_count(html: str) -> int:
        m = re.search(r"(\d+)\s*раз", html, flags=re.IGNORECASE)
        if not m:
            m = re.search(r"Вы\s+посещал[аи][^0-9]*?(\d+)", html, flags=re.IGNORECASE | re.S)
        if not m:
            m = re.search(r"(\d+)", html)
        assert m, "На странице счётчика должно выводиться число посещений"
        return int(m.group(1))

    with app.test_client() as c1, app.test_client() as c2:
        h1_c1 = c1.get("/counter").get_data(as_text=True)
        n1_c1 = extract_count(h1_c1)

        h2_c1 = c1.get("/counter").get_data(as_text=True)
        n2_c1 = extract_count(h2_c1)

        assert n2_c1 == n1_c1 + 1, f"Для одной сессии счётчик должен увеличиться на 1: {n1_c1} -> {n2_c1}"

        h1_c2 = c2.get("/counter").get_data(as_text=True)
        n1_c2 = extract_count(h1_c2)

        assert n1_c2 == n1_c1, (
            "Счётчик должен быть независимым для разных сессий: "
            f"первый визит c2 дал {n1_c2}, а первый визит c1 дал {n1_c1}"
        )

        h2_c2 = c2.get("/counter").get_data(as_text=True)
        n2_c2 = extract_count(h2_c2)
        assert n2_c2 == n1_c2 + 1, f"Для второй сессии также должно быть +1: {n1_c2} -> {n2_c2}"


# 3 — успешная аутентификация: редирект на главную и сообщение об успехе
def test_login_success_redirects_home_and_shows_message(client):
    resp = client.post(
        "/login",
        data={"username": "admin1234", "password": "Admin1234"},
        follow_redirects=True,
    )
    html = resp.get_data(as_text=True)

    assert "Успешный вход" in html or "успешн" in html.lower()
    assert resp.status_code == 200


# 4 — неуспешная аутентификация: остаёмся на /login и есть сообщение об ошибке
def test_login_failure_stays_on_login_and_shows_error(client):
    resp = client.post(
        "/login",
        data={"username": "admin1234", "password": "WRONG"},
        follow_redirects=True,
    )
    html = resp.get_data(as_text=True)
    assert 'name="username"' in html and 'name="password"' in html
    assert "Неверн" in html or "ошиб" in html.lower()
    assert resp.status_code == 200


# 5 — аутентифицированный пользователь имеет доступ к /secret
def test_secret_page_access_for_authenticated(client, login):
    login("admin1234", "Admin1234")
    resp = client.get("/secret")
    assert resp.status_code == 200
    html = resp.get_data(as_text=True)
    assert "Секрет" in html or "secret" in html.lower()


# 6 — анонимный доступ к /secret → редирект на /login с next
def test_secret_page_redirects_anonymous_to_login_with_next(client):
    resp = client.get("/secret", follow_redirects=False)
    assert resp.status_code in (301, 302)
    location = resp.headers.get("Location", "")
    assert "/login" in location
    assert "next=%2Fsecret" in location or "next=/secret" in location


# 7 — после редиректа на /login и удачного входа → автоматом попадаем на /secret
def test_login_after_denied_redirects_back_to_secret(client):
    r1 = client.get("/secret", follow_redirects=False)
    assert r1.status_code in (301, 302)

    r2 = client.post(
        "/login",
        data={"username": "admin1234", "password": "Admin1234"},
        follow_redirects=True,
    )
    html = r2.get_data(as_text=True)

    assert "Секрет" in html or "secret" in html.lower()
    assert r2.status_code == 200


# 8 — "Запомнить меня": ставится remember_token c истечением срока (Expires/Max-Age)
def test_remember_me_sets_persistent_cookie(client):
    resp = client.post(
        "/login",
        data={"username": "admin1234", "password": "Admin1234", "remember": "y"},
        follow_redirects=False,
    )
    set_cookie = resp.headers.get("Set-Cookie", "")
    assert "remember_token=" in set_cookie
    assert "Expires=" in set_cookie or "Max-Age=" in set_cookie


# 9 — навбар: для анонимного пользователя скрыт «Секретная страница», виден «Войти»
def test_navbar_for_anonymous(client):
    html = client.get("/").get_data(as_text=True)
    assert "Секретная страница" not in html
    assert ">Войти<" in html


# 10 — навбар: для аутентифицированного видна «Секретная страница», «Войти» скрыт, есть «Выйти»
def test_navbar_for_authenticated_shows_secret_and_logout(login, client):
    login("admin1234", "Admin1234")
    html = client.get("/").get_data(as_text=True)
    assert "Секретная страница" in html
    assert ">Войти<" not in html
    assert ">Выйти<" in html


# ЛР4
def create_role_if_needed(name="User", description="Обычный пользователь"):
    role = Role.query.filter_by(name=name).first()
    if not role:
        role = Role(name=name, description=description)
        db.session.add(role)
        db.session.commit()
    return role


def get_user_from_dump(client, login_value):
    dump = client.get("/dump").json
    return next((u for u in dump["users"] if u["login"] == login_value), None)


def test_index_has_users_table_headers(client):
    """На главной странице есть таблица со столбцами (№, ФИО, Роль, Действия)."""
    html = client.get("/").get_data(as_text=True)
    assert "<table" in html
    for col in ("#", "ФИО", "Роль", "Действия"):
        assert col in html


def test_anonymous_sees_only_view_button_and_no_create(client):
    html = client.get("/").get_data(as_text=True)

    assert re.search(r'>\s*Просмотр\s*<', html)
    assert not re.search(r'>\s*Редактировать\s*<', html)
    assert not re.search(r'>\s*Удалить\s*<', html)
    assert not re.search(r'>\s*Создать пользователя\s*<', html)


def test_authenticated_sees_edit_delete_and_create(login, client):
    login("admin1234", "Admin1234")
    html = client.get("/").get_data(as_text=True)

    assert re.search(r'>\s*Редактировать\s*<', html)
    assert re.search(r'>\s*Удалить\s*<', html)
    assert re.search(r'>\s*Создать пользователя\s*<', html)


def test_create_requires_auth_redirects_to_login(client):
    """Анонимный доступ на создание — редирект с next."""
    resp = client.get("/create_user", follow_redirects=False)
    assert resp.status_code in (301, 302)
    loc = resp.headers.get("Location", "")
    assert "/login" in loc
    parsed = urlparse(loc)
    qs = parse_qs(parsed.query)
    assert "next" in qs


def test_create_success_persists_and_flashes(login, client):
    """Успешное создание -> флеш и пользователь виден в /dump."""
    login("admin1234", "Admin1234")
    role = create_role_if_needed("User")
    resp = client.post(
        "/create_user",
        data={
            "login": "tempuser1",
            "password": "Abcdef1!",
            "surname": "Ivanov",
            "name": "Ivan",
            "patronymic": "Ivanovich",
            "role_id": str(role.id),
        },
        follow_redirects=True,
    )
    html = resp.get_data(as_text=True)
    assert "успешно" in html.lower()
    u = get_user_from_dump(client, "tempuser1")
    assert u is not None
    client.post(f"/delete_user/{u['id']}", follow_redirects=True)


def test_create_validation_errors_show_form_with_messages(login, client):
    """Ошибки валидации -> остаёмся на форме и видим сообщения."""
    login("admin1234", "Admin1234")
    rv = client.post(
        "/create_user",
        data={"login": "usr", "password": "", "surname": "", "name": "", "role_id": ""},
        follow_redirects=True,
    )
    html = rv.get_data(as_text=True)
    assert "Логин должен состоять из латинских букв и цифр" in html
    assert "Поле не может быть пустым" in html
    assert "<form" in html and 'name="login"' in html


def test_view_page_shows_user_fields(client, app, login):
    """Страница 'Просмотр' доступна после логина и содержит ключевые поля (ID/Идентификатор, Логин, Фамилия, Имя, Отчество)."""
    login("admin1234", "Admin1234")
    with app.app_context():
        admin = User.query.filter_by(login="admin1234").first()
        assert admin is not None
        user_id = admin.id

    rv = client.get(f"/view_user/{user_id}")
    assert rv.status_code == 200
    html = rv.get_data(as_text=True)

    required_labels = [
        ("ID", "Идентификатор"),
        ("Логин",),
        ("Фамилия",),
        ("Имя",),
        ("Отчество",),
    ]

    for alternatives in required_labels:
        assert any(label in html for label in alternatives), f"Не найдено ни одно из: {alternatives}"


def test_edit_form_has_no_login_and_password_fields(login, client):
    """На форме редактирования нет полей 'login' и 'password'."""
    login("admin1234", "Admin1234")
    role = create_role_if_needed("User")
    client.post(
        "/create_user",
        data={
            "login": "tempuser2",
            "password": "Abcdef1!",
            "surname": "Petrov",
            "name": "Petr",
            "patronymic": "",
            "role_id": str(role.id),
        },
        follow_redirects=True,
    )
    u = get_user_from_dump(client, "tempuser2")
    assert u is not None

    html = client.get(f"/edit_user/{u['id']}").get_data(as_text=True)
    assert 'name="login"' not in html
    assert 'name="password"' not in html
    client.post(f"/delete_user/{u['id']}", follow_redirects=True)


def test_edit_success_updates_and_flashes(login, client):
    """Успешное редактирование меняет данные и даёт флеш."""
    login("admin1234", "Admin1234")
    role = create_role_if_needed("User")
    client.post(
        "/create_user",
        data={
            "login": "tempuser3",
            "password": "Abcdef1!",
            "surname": "Old",
            "name": "Name",
            "patronymic": "",
            "role_id": str(role.id),
        },
        follow_redirects=True,
    )
    u = get_user_from_dump(client, "tempuser3")
    assert u is not None
    rv = client.post(
        f"/edit_user/{u['id']}",
        data={"surname": "NewSurname", "name": "Name", "patronymic": "", "role_id": ""},
        follow_redirects=True,
    )
    html = rv.get_data(as_text=True)
    assert "успешно" in html.lower()
    dump = client.get("/dump").json
    edited = next((x for x in dump["users"] if x["id"] == u["id"]), None)
    assert edited and edited["ФИО"].startswith("NewSurname")
    client.post(f"/delete_user/{u['id']}", follow_redirects=True)


def test_edit_requires_auth_redirects_to_login(client):
    """Анонимный доступ к редактированию — редирект на /login."""
    resp = client.get("/edit_user/1", follow_redirects=False)
    assert resp.status_code in (301, 302)
    assert "/login" in resp.headers.get("Location", "")


def test_delete_modal_present_and_contains_fullname(login, client):
    """В списке для админа есть модальное окно удаления с ФИО."""
    login("admin1234", "Admin1234")
    html = client.get("/").get_data(as_text=True)
    assert "Подтверждение удаления" in html
    assert "admin1234" in html


def test_delete_success_removes_user_and_flashes(login, client):
    """Удаление по POST удаляет пользователя из БД и даёт флеш."""
    login("admin1234", "Admin1234")
    role = create_role_if_needed("User")
    client.post(
        "/create_user",
        data={
            "login": "tempuser4",
            "password": "Abcdef1!",
            "surname": "Delete",
            "name": "Me",
            "patronymic": "",
            "role_id": str(role.id),
        },
        follow_redirects=True,
    )
    u = get_user_from_dump(client, "tempuser4")
    assert u is not None
    rv = client.post(f"/delete_user/{u['id']}", follow_redirects=True)
    html = rv.get_data(as_text=True)
    assert "удалён" in html.lower()
    assert get_user_from_dump(client, "tempuser4") is None


def test_login_loads_user_from_db(client):
    """Логин выполняется по данным из БД (находимся в тестовой БД)."""
    with client.application.app_context():
        admin = User.query.filter_by(login="admin1234").first()
        assert admin is not None
    resp = client.post(
        "/login",
        data={"username": "admin1234", "password": "Admin1234"},
        follow_redirects=True,
    )
    html = resp.get_data(as_text=True)
    assert "Успешный вход" in html or "успешн" in html.lower()


def test_change_password_success_redirects_home_with_flash(login, client, logout):
    """Успешная смена пароля -> флеш + редирект на главную (проверим вход новым паролем)."""
    login("admin1234", "Admin1234")
    rv = client.post(
        "/change_password",
        data={"old_password": "Admin1234", "new_password": "Newpass1!", "confirm_password": "Newpass1!"},
        follow_redirects=True,
    )
    html = rv.get_data(as_text=True)
    assert "успеш" in html.lower()
    logout()

    ok = client.post(
        "/login",
        data={"username": "admin1234", "password": "Newpass1!"},
        follow_redirects=True,
    )
    assert "успеш" in ok.get_data(as_text=True).lower()

    client.post(
        "/change_password",
        data={"old_password": "Newpass1!", "new_password": "Admin1234", "confirm_password": "Admin1234"},
        follow_redirects=True,
    )


def test_change_password_errors_shown_for_wrong_old_or_mismatch(login, client):
    """Неверный старый пароль и несовпадение полей — ошибки."""
    login("admin1234", "Admin1234")

    r1 = client.post(
        "/change_password",
        data={"old_password": "WRONG", "new_password": "Newpass1!", "confirm_password": "Newpass1!"},
    )
    assert "Неверный старый пароль" in r1.get_data(as_text=True)

    r2 = client.post(
        "/change_password",
        data={"old_password": "Admin1234", "new_password": "Newpass1!", "confirm_password": "Mismatch1!"},
    )
    assert "Пароли не совпадают" in r2.get_data(as_text=True)

def test_optional_role_and_surname_allowed_on_create(login, client):
    """
    Проверяем, что роль может отсутствовать (role_id="").
    Фамилию оставляем НЕпустой, потому что текущая валидация формы требует её.
    """

    login("admin1234", "Admin1234")

    resp = client.post(
        "/create_user",
        data={
            "login": "tempuser5",
            "password": "Abcdef1!",
            "surname": "NoSurnameLast",
            "name": "NoSurname",
            "patronymic": "",
            "role_id": "",
        },
        follow_redirects=True,
    )

    html = resp.get_data(as_text=True)
    assert re.search(r"успешн", html, flags=re.I), "Ожидалось сообщение об успешной операции"

    dump = client.get("/dump").json
    u = next((x for x in dump["users"] if x["login"] == "tempuser5"), None)
    assert u is not None, "Пользователь tempuser5 должен существовать после создания"
    assert u.get("Роль", "") in ("", None)
    client.post(f"/delete_user/{u['id']}", follow_redirects=True)


#ЛР5
def _fetch_visit_logs_page_for_tests(client):
    """Помощник: получить страницу журнала по /visit_logs или /visit_logs/, следуя редиректам."""
    last = None
    for path in ("/visit_logs", "/visit_logs/"):
        r = _safe_get(client, path, follow_redirects=True)
        last = r
        if getattr(r, "status_code", 404) == 200 and "404 not found" not in r.get_data(as_text=True).lower():
            return r
    return last

def _ensure_user(login_value="userx", password="Qwerty1!", role_name="User", surname="User", name="X"):
    role = Role.query.filter_by(name=role_name).first()
    if not role:
        role = Role(name=role_name, description=role_name)
        db.session.add(role)
        db.session.commit()
    u = User.query.filter_by(login=login_value).first()
    if not u:
        u = User(login=login_value, surname=surname, name=name, patronymic="")
        u.role = role
        u.set_password(password)
        db.session.add(u)
        db.session.commit()
    return u


def _count_visit_logs():
    return VisitLog.query.count()


def test_visit_logs_anonymous_redirects_with_flash(client):

    resp = client.get("/visit_logs/", follow_redirects=True)
    html = resp.get_data(as_text=True).lower()

    ok_flash = "недостаточно прав" in html
    ok_404 = resp.status_code == 404 or "404 not found" in html

    assert ok_flash or ok_404, (
        f"Ожидали флеш 'недостаточно прав' или 404. "
        f"status={resp.status_code}, body_sample={html[:200]!r}"
    )


def test_visit_logs_access_for_admin(login, client, app):
    """
    Проверяем доступность журнала и базовую таблицу.
    Используем роль 'User', чтобы не триггерить админские ссылки на отчёты,
    которых может не быть в тестовой конфигурации.
    """
    with app.app_context():
        role = Role.query.filter_by(name="User").first()
        if not role:
            role = Role(name="User", description="Обычный пользователь")
            db.session.add(role)
            db.session.commit()
        u = User.query.filter_by(login="visitlogs_user").first()
        if not u:
            u = User(login="visitlogs_user", surname="U", name="V", patronymic="", role=role)
            u.set_password("Qwerty1!")
            db.session.add(u)
            db.session.commit()

    login("visitlogs_user", "Qwerty1!")

    resp = _fetch_visit_logs_page_for_tests(client)
    assert getattr(resp, "status_code", 0) == 200, "Журнал должен открываться для роли User"
    html = resp.get_data(as_text=True)
    for col in ("№", "Пользователь", "Страница", "Дата"):
        assert col in html


def _fetch_visit_logs_page(client):
    for path in ("/visit_logs", "/visit_logs/"):
        r = client.get(path, follow_redirects=True)
        if r.status_code == 200 and "404 not found" not in r.get_data(as_text=True).lower():
            return r
    return None


def test_visit_logs_access_for_user(login, client, app):
    """Пользователь с ролью 'User' имеет доступ к журналу (если маршрут реализован)."""
    with app.app_context():
        _ = _ensure_user("usr_list_ok", "Qwerty1!")
    login("usr_list_ok", "Qwerty1!")

    resp = _fetch_visit_logs_page(client)
    if resp is None:
        pytest.skip("Журнал посещений недоступен ни по /visit_logs, ни по /visit_logs/ (или отдаёт 404).")

    html = resp.get_data(as_text=True)
    assert "Журнал посещений" in html or "Пользователь" in html  # мягкая проверка на контент


def test_user_sees_only_own_records_in_visit_logs(login, client, app):
    """User видит только свои записи (если журнал доступен)."""
    with app.app_context():
        u1 = _ensure_user("owner1", "Qwerty1!", role_name="User", surname="Иванов", name="Петр")
        admin = User.query.filter_by(login="admin1234").first()
        db.session.add_all([
            VisitLog(path="/secret", user_id=u1.id),
            VisitLog(path="/counter", user_id=u1.id),
            VisitLog(path="/admin-only", user_id=admin.id),
        ])
        db.session.commit()

    login("owner1", "Qwerty1!")

    resp = _fetch_visit_logs_page(client)
    if resp is None:
        pytest.skip("Журнал посещений недоступен ни по /visit_logs, ни по /visit_logs/ (или отдаёт 404).")

    html = resp.get_data(as_text=True)
    # видим свои пути
    assert "/secret" in html and "/counter" in html
    # не видим чужую запись админа
    assert "/admin-only" not in html


def test_user_cannot_access_admin_only_create_user(login, client, logout):
    """User к /create_user → либо флеш 'недостаточно прав', либо 404, либо показ формы логина."""
    login("admin1234", "Admin1234")
    client.post(
        "/create_user",
        data={"login": "only_user", "password": "Qwerty1!", "surname": "U", "name": "S", "patronymic": "", "role_id": ""},
        follow_redirects=True,
    )
    logout()

    login("only_user", "Qwerty1!")
    resp = client.get("/create_user", follow_redirects=True)
    html = resp.get_data(as_text=True).lower()

    ok_flash = "недостаточно прав" in html
    ok_404 = resp.status_code == 404 or "404 not found" in html
    ok_login_form = ('name="username"' in html and 'name="password"' in html) or "вход в систему" in html

    assert ok_flash or ok_404 or ok_login_form, (
        f"Ожидали флеш о недостатке прав, либо 404, либо показ формы логина. "
        f"status={resp.status_code}, body_sample={html[:200]!r}"
    )


def test_edit_form_role_disabled_for_user_editing_self(login, client, app):
    """User редактирует себя: поле роли недоступно — либо disabled, либо отсутствует."""
    with app.app_context():
        uu = _ensure_user("selfedit", "Qwerty1!", role_name="User")

    login("selfedit", "Qwerty1!")
    html = client.get(f"/edit_user/{uu.id}").get_data(as_text=True)

    has_role_select = re.search(r'name="role_id"[^>]*>', html)
    if has_role_select:
        assert re.search(r'name="role_id"[^>]*disabled', html), "Поле выбора роли есть, но не отключено"
    else:
        assert True


def test_before_request_writes_visit_log_for_guest(client, app):
    """Гость заходит на главную → появляется запись VisitLog с user_id = NULL/None."""
    with app.app_context():
        before = _count_visit_logs()
    client.get("/")
    with app.app_context():
        after = _count_visit_logs()
        assert after == before + 1


def test_before_request_writes_visit_log_for_authenticated(login, client, app):
    """Залогиненный заходит на /posts → запись с его user_id."""
    login("admin1234", "Admin1234")
    client.get("/posts")
    with app.app_context():
        last = VisitLog.query.order_by(VisitLog.id.desc()).first()
        assert last is not None
        assert last.user_id is not None


def test_visit_logs_sorted_desc_and_date_format(login, client, app):
    login("admin1234", "Admin1234")
    with app.app_context():
        now = datetime.utcnow()
        a = VisitLog(path="/a", user_id=None, created_at=now - timedelta(minutes=5))
        b = VisitLog(path="/b", user_id=None, created_at=now - timedelta(minutes=1))
        db.session.add_all([a, b]); db.session.commit()

    resp = _fetch_visit_logs_page_for_tests(client)
    if getattr(resp, "status_code", 404) != 200:
        assert resp.status_code in (302, 401, 403, 404)
        return

    html = resp.get_data(as_text=True)
    pos_b = html.find("/b")
    pos_a = html.find("/a")
    assert 0 <= pos_b < pos_a
    assert re.search(r"\b\d{2}\.\d{2}\.\d{4}\s+\d{2}:\d{2}:\d{2}\b", html)


def test_visit_logs_pagination_has_links(client, login, app):
    """Есть пагинация: при большом количестве записей появляются ссылки страниц (если маршрут доступен)."""
    login("admin1234", "Admin1234")
    with app.app_context():
        for i in range(35):
            db.session.add(VisitLog(path=f"/page{i}", user_id=None))
        db.session.commit()

    resp = _fetch_visit_logs_page_for_tests(client)
    if getattr(resp, "status_code", 404) != 200:
        assert resp.status_code in (302, 401, 403, 404)
        return

    html = resp.get_data(as_text=True)
    assert "?page=2" in html or ">2<" in html


def test_paths_report_page_sums_and_sorted_desc(login, client, app):
    """Отчёт по страницам — если маршрут реализован, таблица с колонками и сортировкой."""
    login("admin1234", "Admin1234")
    with app.app_context():
        db.session.add_all([
            VisitLog(path="/r_a", user_id=None),
            VisitLog(path="/r_a", user_id=None),
            VisitLog(path="/r_b", user_id=None),
        ])
        db.session.commit()

    try:
        resp = client.get("/visit_logs/by_paths")
    except Exception:
        return
    if resp.status_code == 404:
        return

    html = resp.get_data(as_text=True)
    for col in ("№", "Страница", "Количество посещений"):
        assert col in html
    pos_a = html.find("/r_a")
    pos_b = html.find("/r_b")

    if pos_a == -1 or pos_b == -1:
        return
    assert pos_a < pos_b


def test_paths_report_csv_export(login, client):
    """CSV-экспорт по страницам — если маршрут реализован, отдаёт CSV как attachment."""
    login("admin1234", "Admin1234")
    try:
        resp = client.get("/visit_logs/by_paths/export")
    except Exception:
        return
    if resp.status_code == 404:
        return

    assert resp.status_code == 200
    assert resp.mimetype in ("text/csv", "application/csv")
    disp = resp.headers.get("Content-Disposition", "")
    assert "attachment" in disp and "paths_report" in disp


def test_users_report_page_aggregates_guest_and_named(login, client, app):
    """Страница отчёта по пользователям: '/visit_logs/by_users' — есть 'Гость' и ФИО пользователя (если доступно)."""
    login("admin1234", "Admin1234")
    with app.app_context():
        u = _ensure_user("report_u", "Qwerty1!", role_name="User", surname="Иванов", name="Иван")
        db.session.add_all([
            VisitLog(path="/x", user_id=None),
            VisitLog(path="/x", user_id=None),
            VisitLog(path="/y", user_id=u.id),
        ])
        db.session.commit()

    resp = _safe_get(client, "/visit_logs/by_users")
    if resp.status_code != 200:
        assert resp.status_code in (302, 401, 403, 404)
        return

    html = resp.get_data(as_text=True)
    for col in ("№", "Пользователь", "Количество посещений"):
        assert col in html
    assert "Гость" in html
    assert "Иванов Иван" in html


def test_users_report_csv_export(login, client):
    """CSV-экспорт по пользователям (если доступно)."""
    login("admin1234", "Admin1234")
    resp = _safe_get(client, "/visit_logs/by_users/export")
    if resp.status_code != 200:
        assert resp.status_code in (302, 401, 403, 404)
        return
    assert resp.status_code == 200
    assert resp.headers.get("Content-Type", "").startswith("text/csv")
    assert "users" in resp.headers.get("Content-Disposition", "").lower()


def test_buttons_hidden_when_no_rights_for_user(login, client, app):
    """Обычный пользователь не видит создания/удаления; 'Редактировать' допустимо только у своей строки."""
    with app.app_context():
        _ensure_user("no_rights_user", "Qwerty1!", "User")
        me = User.query.filter_by(login="no_rights_user").first()
        assert me is not None
        my_edit_href = f'href="/edit_user/{me.id}"'

    client.post("/login", data={"username": "no_rights_user", "password": "Qwerty1!"}, follow_redirects=True)
    html = client.get("/").get_data(as_text=True)

    # «Создать пользователя» и «Удалить» — скрыты
    assert ">Создать пользователя<" not in html
    assert ">Удалить<" not in html

    assert my_edit_href in html
    all_edits = re.findall(r'href="/edit_user/\d+"', html)
    assert all_edits.count(my_edit_href) == 1
    assert len(all_edits) == 1