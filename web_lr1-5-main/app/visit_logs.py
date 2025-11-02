from flask import Blueprint, render_template, request, Response
from flask_login import current_user
from .app import db, VisitLog, User, check_rights
from datetime import datetime
import io, csv

visit_logs_bp = Blueprint(
    'visit_logs',
    __name__,
    template_folder='templates/'
)

@visit_logs_bp.route('/')
@check_rights(['Administrator', 'User'])
def index():
    page = request.args.get('page', 1, type=int)
    per_page = 20
    pagination = VisitLog.query \
        .order_by(VisitLog.created_at.desc()) \
        .paginate(page, per_page, False)
    return render_template('visit_logs.html', pagination=pagination)

@visit_logs_bp.route('/logs_pages_report')
@check_rights(['Administrator'])
def pages_report():
    # собираем статистику по пути
    rows = (
        db.session.query(
            VisitLog.path,
            db.func.count(VisitLog.id).label('count')
        )
        .group_by(VisitLog.path)
        .order_by(db.desc('count'))
        .all()
    )
    return render_template('logs_pages_report.html', rows=rows)

@visit_logs_bp.route('/logs_pages_report/export')
@check_rights(['Administrator'])
def pages_report_export():
    rows = (
        db.session.query(
            VisitLog.path,
            db.func.count(VisitLog.id).label('count')
        )
        .group_by(VisitLog.path)
        .order_by(db.desc('count'))
        .all()
    )
    si = io.StringIO()
    w = csv.writer(si)
    w.writerow(['Страница', 'Количество посещений'])
    for path, cnt in rows:
        w.writerow([path, cnt])
    return Response(
        si.getvalue(),
        mimetype='text/csv',
        headers={'Content-Disposition': 'attachment; filename=pages_report.csv'}
    )

@visit_logs_bp.route('/logs_users_report')
@check_rights(['Administrator'])
def users_report():
    # собираем статистику по пользователю
    rows = (
        db.session.query(
            VisitLog.user_id,
            db.func.count(VisitLog.id).label('count')
        )
        .group_by(VisitLog.user_id)
        .order_by(db.desc('count'))
        .all()
    )
    # заменяем user_id на ФИО или "Гость"
    data = []
    for uid, cnt in rows:
        if uid:
            u = User.query.get(uid)
            name = f"{u.surname or ''} {u.name or ''} {u.patronymic or ''}".strip()
        else:
            name = "Гость"
        data.append((name, cnt))
    return render_template('logs_users_report.html', rows=data)

@visit_logs_bp.route('/logs_users_report/export')
@check_rights(['Administrator'])
def users_report_export():
    rows = (
        db.session.query(
            VisitLog.user_id,
            db.func.count(VisitLog.id).label('count')
        )
        .group_by(VisitLog.user_id)
        .order_by(db.desc('count'))
        .all()
    )
    si = io.StringIO()
    w = csv.writer(si)
    w.writerow(['Пользователь', 'Количество посещений'])
    for uid, cnt in rows:
        if uid is not None:
            u = User.query.get(uid)
            name = f"{u.surname or ''} {u.name or ''} {u.patronymic or ''}".strip()
        else:
            name = "Гость"
        w.writerow([name, cnt])
    return Response(
        si.getvalue(),
        mimetype='text/csv',
        headers={'Content-Disposition': 'attachment; filename=users_report.csv'}
    )

