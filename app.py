0"""
ТОГУ — Платформа электронных наградных документов
Flask-приложение для формирования, выдачи, хранения и верификации
электронных благодарностей, грамот, дипломов и сертификатов.

Соответствие ТЗ:
- Роли: суперадмин, админ подразделения, проверяющий, получатель, наблюдатель
- Управление мероприятиями, импорт участников
- Конструктор шаблонов, генерация PDF/PNG
- QR-код, уникальный номер, проверка подлинности
- Личный кабинет получателя
- Журналы событий, согласие на ОПД (152-ФЗ)
"""

import os
import io
import csv
import uuid
import json
import hashlib
import secrets
from datetime import datetime
from functools import wraps

from flask import (
    Flask, render_template, request, redirect, url_for, session,
    flash, send_file, jsonify, abort, send_from_directory
)
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename

# Для генерации PDF — используем reportlab (поставляется со многими дистрибутивами,
# или ставится: pip install reportlab qrcode[pil] Pillow)
from reportlab.lib.pagesizes import A4, A5, landscape, portrait
from reportlab.lib.units import mm
from reportlab.lib.colors import HexColor, white, black
from reportlab.pdfgen import canvas
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont

import qrcode

# ============================================================================
# КОНФИГУРАЦИЯ
# ============================================================================

BASE_DIR = os.path.abspath(os.path.dirname(__file__))
DB_PATH = os.path.join(BASE_DIR, 'instance', 'togu.db')
UPLOAD_FOLDER = os.path.join(BASE_DIR, 'uploads')
GENERATED_FOLDER = os.path.join(BASE_DIR, 'generated')

# Фирменные цвета ТОГУ (из брендбука)
BRAND_COLORS = {
    'primary': '#9B2242',          # Основной бордовый Pantone 7420 C
    'white': '#FFFFFF',
    'iasid': '#FFD72C',            # Институт архитектуры, строительства и дизайна
    'ilmk': '#743A8E',             # Институт лингвистики
    'ispitk': '#B26694',           # Институт соц-полит. технологий
    'ieu': '#175296',              # Институт экономики и управления
    'pedinst': '#8FAD15',          # Педагогический институт
    'polytech': '#007041',         # Политехнический институт
    'ui': '#C7452A',               # Юридический институт
}

# Шрифты брендбука
BRAND_FONTS = {
    'primary': 'Manrope',          # Основной
    'accent': 'Russo One',         # Акцентный
}

ROLES = {
    'superadmin': 'Суперадминистратор',
    'admin': 'Администратор подразделения',
    'reviewer': 'Проверяющий',
    'recipient': 'Получатель',
    'auditor': 'Наблюдатель/аудитор',
}

DOC_TYPES = {
    'diploma_winner': 'Диплом победителя',
    'diploma_participant': 'Диплом участника',
    'gratitude': 'Благодарственное письмо',
    'certificate': 'Сертификат',
    'charter': 'Грамота',
}

# ============================================================================
# Flask app
# ============================================================================

app = Flask(__name__)
app.config['SECRET_KEY'] = secrets.token_hex(32)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['GENERATED_FOLDER'] = GENERATED_FOLDER
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16 МБ

os.makedirs(os.path.join(BASE_DIR, 'instance'), exist_ok=True)
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
os.makedirs(GENERATED_FOLDER, exist_ok=True)

# ============================================================================
# БАЗА ДАННЫХ (SQLite через стандартный sqlite3)
# ============================================================================

import sqlite3


def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON;")
    return conn


def init_db():
    """Инициализация схемы и стартовых данных."""
    conn = get_db()
    cur = conn.cursor()

    cur.executescript("""
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        email TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL,
        full_name TEXT NOT NULL,
        role TEXT NOT NULL,
        department TEXT,
        created_at TEXT DEFAULT CURRENT_TIMESTAMP
    );

    CREATE TABLE IF NOT EXISTS events (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL,
        organizer TEXT,
        date_start TEXT,
        date_end TEXT,
        event_type TEXT,
        description TEXT,
        contact TEXT,
        created_by INTEGER,
        created_at TEXT DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (created_by) REFERENCES users(id)
    );

    CREATE TABLE IF NOT EXISTS templates (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL,
        doc_type TEXT NOT NULL,
        orientation TEXT DEFAULT 'portrait',
        page_size TEXT DEFAULT 'A4',
        institute_color TEXT DEFAULT '#9B2242',
        background_file TEXT,
        is_custom INTEGER DEFAULT 0,
        params_json TEXT,
        version INTEGER DEFAULT 1,
        created_by INTEGER,
        created_at TEXT DEFAULT CURRENT_TIMESTAMP
    );

    CREATE TABLE IF NOT EXISTS recipients (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        event_id INTEGER NOT NULL,
        full_name TEXT NOT NULL,
        email TEXT,
        status TEXT,
        achievement TEXT,
        hours INTEGER,
        position TEXT,
        consent_pd INTEGER DEFAULT 0,
        created_at TEXT DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (event_id) REFERENCES events(id) ON DELETE CASCADE
    );

    CREATE TABLE IF NOT EXISTS documents (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        unique_number TEXT UNIQUE NOT NULL,
        access_token TEXT UNIQUE NOT NULL,
        event_id INTEGER NOT NULL,
        recipient_id INTEGER NOT NULL,
        template_id INTEGER NOT NULL,
        doc_type TEXT NOT NULL,
        status TEXT DEFAULT 'issued',
        signature_hash TEXT,
        signed_by TEXT,
        file_pdf TEXT,
        file_png TEXT,
        issued_at TEXT DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (event_id) REFERENCES events(id),
        FOREIGN KEY (recipient_id) REFERENCES recipients(id),
        FOREIGN KEY (template_id) REFERENCES templates(id)
    );

    CREATE TABLE IF NOT EXISTS event_log (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER,
        action TEXT NOT NULL,
        entity_type TEXT,
        entity_id INTEGER,
        details TEXT,
        ip TEXT,
        created_at TEXT DEFAULT CURRENT_TIMESTAMP
    );
    """)
    conn.commit()

    # Стартовый суперадмин
    cur.execute("SELECT COUNT(*) AS c FROM users")
    if cur.fetchone()['c'] == 0:
        cur.execute(
            "INSERT INTO users (email, password_hash, full_name, role, department) VALUES (?, ?, ?, ?, ?)",
            ('admin@pnu.edu.ru', generate_password_hash('admin123'),
             'Администратор ТОГУ', 'superadmin', 'Управление ИТ')
        )
        # Демо-админ
        cur.execute(
            "INSERT INTO users (email, password_hash, full_name, role, department) VALUES (?, ?, ?, ?, ?)",
            ('iasid@pnu.edu.ru', generate_password_hash('demo123'),
             'Иванов И.И.', 'admin', 'ИАСиД')
        )
        # Демо-получатель
        cur.execute(
            "INSERT INTO users (email, password_hash, full_name, role, department) VALUES (?, ?, ?, ?, ?)",
            ('student@pnu.edu.ru', generate_password_hash('demo123'),
             'Петров П.П.', 'recipient', None)
        )
        conn.commit()

        # Стартовые шаблоны
        templates = [
            ('Диплом победителя (ТОГУ)', 'diploma_winner', 'portrait', 'A4', BRAND_COLORS['primary']),
            ('Диплом участника (ТОГУ)', 'diploma_participant', 'portrait', 'A4', BRAND_COLORS['primary']),
            ('Благодарственное письмо', 'gratitude', 'landscape', 'A4', BRAND_COLORS['primary']),
            ('Грамота', 'charter', 'portrait', 'A4', BRAND_COLORS['primary']),
            ('Сертификат', 'certificate', 'landscape', 'A5', BRAND_COLORS['primary']),
        ]
        for name, dtype, orient, psize, color in templates:
            cur.execute(
                "INSERT INTO templates (name, doc_type, orientation, page_size, institute_color, params_json) "
                "VALUES (?, ?, ?, ?, ?, ?)",
                (name, dtype, orient, psize, color, json.dumps({
                    'title_font': 'Russo One',
                    'body_font': 'Manrope',
                    'show_pattern': True,
                    'show_qr': True,
                }))
            )
        conn.commit()

    conn.close()


def log_event(action, entity_type=None, entity_id=None, details=None):
    """Журналирование действий (для роли наблюдателя/аудитора)."""
    try:
        conn = get_db()
        conn.execute(
            "INSERT INTO event_log (user_id, action, entity_type, entity_id, details, ip) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            (session.get('user_id'), action, entity_type, entity_id,
             json.dumps(details, ensure_ascii=False) if details else None,
             request.remote_addr if request else None)
        )
        conn.commit()
        conn.close()
    except Exception as e:
        print(f"[log_event] error: {e}")


# ============================================================================
# АВТОРИЗАЦИЯ И ДЕКОРАТОРЫ
# ============================================================================

def login_required(f):
    @wraps(f)
    def wrap(*args, **kwargs):
        if 'user_id' not in session:
            flash('Требуется вход в систему', 'warning')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return wrap


def role_required(*allowed_roles):
    def decorator(f):
        @wraps(f)
        def wrap(*args, **kwargs):
            if 'user_id' not in session:
                return redirect(url_for('login'))
            if session.get('role') not in allowed_roles:
                flash('Недостаточно прав доступа', 'error')
                return redirect(url_for('dashboard'))
            return f(*args, **kwargs)
        return wrap
    return decorator


def current_user():
    if 'user_id' not in session:
        return None
    conn = get_db()
    user = conn.execute("SELECT * FROM users WHERE id = ?", (session['user_id'],)).fetchone()
    conn.close()
    return user


# ============================================================================
# КОНТЕКСТ-ПРОЦЕССОР
# ============================================================================

@app.context_processor
def inject_globals():
    return {
        'BRAND_COLORS': BRAND_COLORS,
        'ROLES': ROLES,
        'DOC_TYPES': DOC_TYPES,
        'current_user': current_user(),
    }


@app.template_filter('from_json')
def from_json_filter(s):
    if not s:
        return {}
    try:
        return json.loads(s)
    except Exception:
        return {}


# ============================================================================
# МАРШРУТЫ — ПУБЛИЧНЫЕ
# ============================================================================

@app.route('/')
def index():
    return render_template('index.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email', '').strip().lower()
        password = request.form.get('password', '')

        conn = get_db()
        user = conn.execute("SELECT * FROM users WHERE email = ?", (email,)).fetchone()
        conn.close()

        if user and check_password_hash(user['password_hash'], password):
            session['user_id'] = user['id']
            session['role'] = user['role']
            session['full_name'] = user['full_name']
            log_event('login', 'user', user['id'])
            flash(f'Добро пожаловать, {user["full_name"]}', 'success')
            return redirect(url_for('dashboard'))
        flash('Неверные учётные данные', 'error')

    return render_template('login.html')


@app.route('/logout')
def logout():
    log_event('logout', 'user', session.get('user_id'))
    session.clear()
    flash('Вы вышли из системы', 'info')
    return redirect(url_for('index'))


# ============================================================================
# ПРОВЕРКА ПОДЛИННОСТИ ДОКУМЕНТА (публичная — по QR)
# ============================================================================

@app.route('/verify/<token>')
def verify(token):
    """Лаконичная страница проверки — для QR-сканирования."""
    conn = get_db()
    doc = conn.execute("""
        SELECT d.*, r.full_name AS recipient_name, r.status AS recipient_status,
               e.name AS event_name, e.date_start, e.organizer,
               t.name AS template_name
        FROM documents d
        JOIN recipients r ON r.id = d.recipient_id
        JOIN events e ON e.id = d.event_id
        JOIN templates t ON t.id = d.template_id
        WHERE d.access_token = ?
    """, (token,)).fetchone()
    conn.close()

    if not doc:
        return render_template('verify.html', doc=None)

    log_event('document_verified', 'document', doc['id'], {'token': token})
    return render_template('verify.html', doc=doc)


# ============================================================================
# ЛИЧНЫЙ КАБИНЕТ / DASHBOARD
# ============================================================================

@app.route('/dashboard')
@login_required
def dashboard():
    user = current_user()
    conn = get_db()

    stats = {}
    if user['role'] in ('superadmin', 'admin'):
        stats['events'] = conn.execute("SELECT COUNT(*) AS c FROM events").fetchone()['c']
        stats['documents'] = conn.execute("SELECT COUNT(*) AS c FROM documents").fetchone()['c']
        stats['recipients'] = conn.execute("SELECT COUNT(*) AS c FROM recipients").fetchone()['c']
        stats['templates'] = conn.execute("SELECT COUNT(*) AS c FROM templates").fetchone()['c']
        recent_docs = conn.execute("""
            SELECT d.*, r.full_name AS rname, e.name AS ename
            FROM documents d
            JOIN recipients r ON r.id = d.recipient_id
            JOIN events e ON e.id = d.event_id
            ORDER BY d.issued_at DESC LIMIT 10
        """).fetchall()
    elif user['role'] == 'recipient':
        recent_docs = conn.execute("""
            SELECT d.*, r.full_name AS rname, e.name AS ename
            FROM documents d
            JOIN recipients r ON r.id = d.recipient_id
            JOIN events e ON e.id = d.event_id
            WHERE LOWER(r.email) = LOWER(?)
            ORDER BY d.issued_at DESC
        """, (user['email'],)).fetchall()
        stats['my_documents'] = len(recent_docs)
    else:
        recent_docs = []

    conn.close()
    return render_template('dashboard.html', user=user, stats=stats, recent_docs=recent_docs)


# ============================================================================
# МЕРОПРИЯТИЯ
# ============================================================================

@app.route('/events')
@login_required
@role_required('superadmin', 'admin', 'reviewer', 'auditor')
def events_list():
    conn = get_db()
    events = conn.execute("""
        SELECT e.*, COUNT(r.id) AS recipient_count
        FROM events e LEFT JOIN recipients r ON r.event_id = e.id
        GROUP BY e.id ORDER BY e.created_at DESC
    """).fetchall()
    conn.close()
    return render_template('events_list.html', events=events)


@app.route('/events/new', methods=['GET', 'POST'])
@login_required
@role_required('superadmin', 'admin')
def event_new():
    if request.method == 'POST':
        conn = get_db()
        cur = conn.cursor()
        cur.execute("""
            INSERT INTO events (name, organizer, date_start, date_end, event_type, description, contact, created_by)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            request.form['name'],
            request.form.get('organizer'),
            request.form.get('date_start'),
            request.form.get('date_end'),
            request.form.get('event_type'),
            request.form.get('description'),
            request.form.get('contact'),
            session['user_id'],
        ))
        eid = cur.lastrowid
        conn.commit()
        conn.close()
        log_event('event_created', 'event', eid, {'name': request.form['name']})
        flash('Мероприятие создано', 'success')
        return redirect(url_for('event_detail', event_id=eid))
    return render_template('event_form.html', event=None)


@app.route('/events/<int:event_id>')
@login_required
def event_detail(event_id):
    conn = get_db()
    event = conn.execute("SELECT * FROM events WHERE id = ?", (event_id,)).fetchone()
    if not event:
        conn.close()
        abort(404)
    recipients = conn.execute(
        "SELECT * FROM recipients WHERE event_id = ? ORDER BY full_name", (event_id,)
    ).fetchall()
    documents = conn.execute("""
        SELECT d.*, r.full_name AS rname, t.name AS tname
        FROM documents d
        JOIN recipients r ON r.id = d.recipient_id
        JOIN templates t ON t.id = d.template_id
        WHERE d.event_id = ?
        ORDER BY d.issued_at DESC
    """, (event_id,)).fetchall()
    templates = conn.execute(
        "SELECT * FROM templates WHERE COALESCE(is_custom, 0) != 2 ORDER BY name"
    ).fetchall()
    conn.close()
    return render_template('event_detail.html', event=event, recipients=recipients,
                           documents=documents, templates=templates)


# ============================================================================
# ИМПОРТ УЧАСТНИКОВ (CSV)
# ============================================================================

@app.route('/events/<int:event_id>/import', methods=['POST'])
@login_required
@role_required('superadmin', 'admin')
def event_import(event_id):
    """Импорт CSV: full_name,email,status,achievement,hours,position"""
    file = request.files.get('csv_file')
    if not file or not file.filename:
        flash('Не выбран файл', 'error')
        return redirect(url_for('event_detail', event_id=event_id))

    try:
        stream = io.StringIO(file.stream.read().decode('utf-8-sig'), newline=None)
        reader = csv.DictReader(stream)
        conn = get_db()
        cur = conn.cursor()
        count = 0
        for row in reader:
            cur.execute("""
                INSERT INTO recipients (event_id, full_name, email, status, achievement, hours, position, consent_pd)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                event_id,
                row.get('full_name', '').strip(),
                row.get('email', '').strip(),
                row.get('status', 'участник').strip(),
                row.get('achievement', '').strip(),
                int(row['hours']) if row.get('hours', '').strip().isdigit() else None,
                row.get('position', '').strip(),
                1 if row.get('consent_pd', '').strip().lower() in ('1', 'true', 'да', 'yes') else 0,
            ))
            count += 1
        conn.commit()
        conn.close()
        log_event('recipients_imported', 'event', event_id, {'count': count})
        flash(f'Импортировано записей: {count}', 'success')
    except Exception as e:
        flash(f'Ошибка импорта: {e}', 'error')

    return redirect(url_for('event_detail', event_id=event_id))


@app.route('/events/<int:event_id>/recipient/add', methods=['POST'])
@login_required
@role_required('superadmin', 'admin')
def recipient_add(event_id):
    conn = get_db()
    conn.execute("""
        INSERT INTO recipients (event_id, full_name, email, status, achievement, hours, position, consent_pd)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        event_id,
        request.form['full_name'].strip(),
        request.form.get('email', '').strip(),
        request.form.get('status', 'участник'),
        request.form.get('achievement', ''),
        int(request.form['hours']) if request.form.get('hours', '').strip().isdigit() else None,
        request.form.get('position', ''),
        1 if request.form.get('consent_pd') else 0,
    ))
    conn.commit()
    conn.close()
    flash('Участник добавлен', 'success')
    return redirect(url_for('event_detail', event_id=event_id))


# ============================================================================
# ВЫПУСК ДОКУМЕНТОВ — МАСТЕР (массовая генерация)
# ============================================================================

@app.route('/events/<int:event_id>/issue', methods=['POST'])
@login_required
@role_required('superadmin', 'admin')
def issue_documents(event_id):
    """Массовая генерация документов по выбранному шаблону."""
    template_id = int(request.form['template_id'])
    recipient_ids = request.form.getlist('recipient_ids')
    if not recipient_ids:
        flash('Не выбраны получатели', 'error')
        return redirect(url_for('event_detail', event_id=event_id))

    conn = get_db()
    template = conn.execute("SELECT * FROM templates WHERE id = ?", (template_id,)).fetchone()
    event = conn.execute("SELECT * FROM events WHERE id = ?", (event_id,)).fetchone()
    if not template or not event:
        conn.close()
        abort(404)

    user = current_user()
    issued = 0
    for rid in recipient_ids:
        recipient = conn.execute("SELECT * FROM recipients WHERE id = ?", (rid,)).fetchone()
        if not recipient:
            continue

        unique_number = f"ТОГУ-{datetime.now().year}-{secrets.token_hex(4).upper()}"
        access_token = secrets.token_urlsafe(24)

        # Подпись (упрощённая КЭП-симуляция: SHA-256 от данных + соль)
        sig_payload = f"{unique_number}|{recipient['full_name']}|{event['name']}|{template['name']}"
        signature_hash = hashlib.sha256(
            (sig_payload + app.config['SECRET_KEY']).encode('utf-8')
        ).hexdigest()

        cur = conn.cursor()
        cur.execute("""
            INSERT INTO documents (unique_number, access_token, event_id, recipient_id,
                                    template_id, doc_type, signature_hash, signed_by)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """, (unique_number, access_token, event_id, recipient['id'],
              template_id, template['doc_type'], signature_hash, user['full_name']))
        doc_id = cur.lastrowid

        # Генерация PDF
        pdf_path = generate_document_pdf(
            doc_id=doc_id,
            unique_number=unique_number,
            access_token=access_token,
            template=template,
            event=event,
            recipient=recipient,
            signed_by=user['full_name'],
        )
        cur.execute("UPDATE documents SET file_pdf = ? WHERE id = ?",
                    (os.path.basename(pdf_path), doc_id))
        issued += 1

    conn.commit()
    conn.close()
    log_event('documents_issued', 'event', event_id, {'count': issued})
    flash(f'Выпущено документов: {issued}', 'success')
    return redirect(url_for('event_detail', event_id=event_id))


# ============================================================================
# ГЕНЕРАЦИЯ PDF (по правилам брендбука ТОГУ)
# ============================================================================

# Глобальная карта зарегистрированных шрифтов (имя из брендбука -> имя в reportlab)
FONT_MAP = {
    'body_regular': 'Helvetica',
    'body_bold': 'Helvetica-Bold',
    'display': 'Helvetica-Bold',
}


def _register_fonts():
    """
    Регистрирует шрифты с поддержкой кириллицы.
    Приоритет:
      1) Manrope / Russo One из static/fonts (брендбук)
      2) DejaVu Sans из static/fonts (фолбэк с поддержкой кириллицы)
      3) DejaVu Sans из системы
    """
    global FONT_MAP
    fonts_dir = os.path.join(BASE_DIR, 'static', 'fonts')

    # Кандидаты на основной шрифт (regular)
    regular_candidates = [
        ('Manrope', os.path.join(fonts_dir, 'Manrope-Regular.ttf')),
        ('DejaVuSans', os.path.join(fonts_dir, 'DejaVuSans.ttf')),
        ('DejaVuSans', '/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf'),
        ('LiberationSans', '/usr/share/fonts/truetype/liberation/LiberationSans-Regular.ttf'),
    ]
    bold_candidates = [
        ('Manrope-Bold', os.path.join(fonts_dir, 'Manrope-Bold.ttf')),
        ('DejaVuSans-Bold', os.path.join(fonts_dir, 'DejaVuSans-Bold.ttf')),
        ('DejaVuSans-Bold', '/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf'),
        ('LiberationSans-Bold', '/usr/share/fonts/truetype/liberation/LiberationSans-Bold.ttf'),
    ]
    display_candidates = [
        ('RussoOne', os.path.join(fonts_dir, 'RussoOne-Regular.ttf')),
        # Если Russo One нет — используем жирный кириллический шрифт
        ('DejaVuSans-Bold', os.path.join(fonts_dir, 'DejaVuSans-Bold.ttf')),
        ('DejaVuSans-Bold', '/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf'),
    ]

    def _try_register(candidates, role):
        registered = pdfmetrics.getRegisteredFontNames()
        for name, path in candidates:
            if name in registered:
                FONT_MAP[role] = name
                return
            if os.path.exists(path):
                try:
                    pdfmetrics.registerFont(TTFont(name, path))
                    FONT_MAP[role] = name
                    print(f"[fonts] {role}: {name} ({path})")
                    return
                except Exception as e:
                    print(f"[fonts] failed {path}: {e}")

    _try_register(regular_candidates, 'body_regular')
    _try_register(bold_candidates, 'body_bold')
    _try_register(display_candidates, 'display')

    # Если для display не нашлось — используем body_bold
    if FONT_MAP['display'] == 'Helvetica-Bold' and FONT_MAP['body_bold'] != 'Helvetica-Bold':
        FONT_MAP['display'] = FONT_MAP['body_bold']

    print(f"[fonts] FONT_MAP: {FONT_MAP}")


_register_fonts()


def _font(name, bold=False):
    """
    Безопасный выбор шрифта.
      name='Manrope' (основной) или 'Russo One' (акцентный).
      bold=True переключает на жирное начертание.
    """
    if name == 'Russo One':
        return FONT_MAP.get('display', 'Helvetica-Bold')
    # Manrope (основной)
    if bold:
        return FONT_MAP.get('body_bold', 'Helvetica-Bold')
    return FONT_MAP.get('body_regular', 'Helvetica')


def _draw_pattern(c, w, h, color):
    """Фирменный паттерн ТОГУ — стилизованный знак под углом, бледным цветом."""
    c.saveState()
    c.setFillColor(HexColor(color))
    c.setFillAlpha(0.10)
    c.setStrokeAlpha(0)

    # Сетка стилизованных «иероглифов» (упрощённо — повёрнутые прямоугольники-блоки)
    step_x, step_y = 35 * mm, 28 * mm
    for y in range(0, int(h + step_y), int(step_y)):
        for x in range(0, int(w + step_x), int(step_x)):
            c.saveState()
            c.translate(x, y)
            c.rotate(-25)
            # Условный знак ТОГУ: набор прямоугольников
            c.rect(0, 0, 18 * mm, 3 * mm, fill=1, stroke=0)
            c.rect(0, 4 * mm, 3 * mm, 8 * mm, fill=1, stroke=0)
            c.rect(8 * mm, 4 * mm, 3 * mm, 5 * mm, fill=1, stroke=0)
            c.rect(0, 13 * mm, 12 * mm, 3 * mm, fill=1, stroke=0)
            c.restoreState()
    c.restoreState()


def _draw_qr(c, data, x, y, size_mm=22):
    """Встраивает QR-код в PDF."""
    qr = qrcode.QRCode(version=1, box_size=10, border=1)
    qr.add_data(data)
    qr.make(fit=True)
    img = qr.make_image(fill_color='black', back_color='white').convert('RGB')
    buf = io.BytesIO()
    img.save(buf, format='PNG')
    buf.seek(0)
    from reportlab.lib.utils import ImageReader
    c.drawImage(ImageReader(buf), x, y, size_mm * mm, size_mm * mm)


def _safe_text(s):
    return s if s else ''


def generate_document_pdf(doc_id, unique_number, access_token, template, event, recipient, signed_by):
    """Генерация PDF документа в соответствии с брендбуком ТОГУ.

    template — sqlite3.Row или dict. Если есть background_file — он используется как фон,
    стандартное оформление (рамки/паттерны) пропускается, накладываются только данные + QR.
    """
    filename = f"doc_{doc_id}_{unique_number}.pdf"
    filepath = os.path.join(GENERATED_FOLDER, filename)

    # Универсальный доступ к полям (поддержка dict и sqlite3.Row)
    def tget(key, default=None):
        try:
            return template[key]
        except (KeyError, IndexError):
            return default

    # Размер страницы
    page_size = A4 if tget('page_size', 'A4') == 'A4' else A5
    if tget('orientation', 'portrait') == 'landscape':
        page_size = landscape(page_size)
    else:
        page_size = portrait(page_size)

    c = canvas.Canvas(filepath, pagesize=page_size)
    w, h = page_size

    primary = tget('institute_color') or BRAND_COLORS['primary']
    doc_type = tget('doc_type', 'certificate')

    params_raw = tget('params_json')
    params = json.loads(params_raw) if params_raw else {}

    background_file = tget('background_file')

    # ====== ФОН ИЗ ЗАГРУЖЕННОГО ФАЙЛА (для пользовательских шаблонов) ======
    if background_file:
        bg_path = os.path.join(UPLOAD_FOLDER, background_file)
        if os.path.exists(bg_path):
            from reportlab.lib.utils import ImageReader
            ext = os.path.splitext(background_file)[1].lower()
            try:
                if ext in ('.png', '.jpg', '.jpeg'):
                    c.drawImage(ImageReader(bg_path), 0, 0, w, h, preserveAspectRatio=False, mask='auto')
                elif ext == '.pdf':
                    # Накладываем первую страницу PDF как фон (через pdfrw, если есть)
                    try:
                        from pdfrw import PdfReader
                        from pdfrw.buildxobj import pagexobj
                        from pdfrw.toreportlab import makerl
                        bg_pdf = PdfReader(bg_path)
                        page = pagexobj(bg_pdf.pages[0])
                        c.doForm(makerl(c, page))
                    except ImportError:
                        # Если pdfrw нет — отображаем подсказку, что PDF-фон требует pdfrw
                        c.setFillColor(HexColor('#f0f0f0'))
                        c.rect(0, 0, w, h, fill=1, stroke=0)
                        c.setFillColor(black)
                        c.setFont(_font('Manrope'), 10)
                        c.drawCentredString(w / 2, h - 20 * mm,
                            "Для PDF-фонов установите пакет 'pdfrw'")
            except Exception as e:
                print(f"[bg] error loading {bg_path}: {e}")

        # На пользовательском шаблоне рисуем только текст с данными + QR + номер
        _draw_data_layer(c, w, h, doc_type, unique_number, access_token,
                         event, recipient, signed_by, primary, params,
                         minimal=True)
        c.showPage()
        c.save()
        return filepath

    # ====== СТАНДАРТНОЕ ОФОРМЛЕНИЕ ПО БРЕНДБУКУ ======
    _draw_standard_layout(c, w, h, doc_type, primary, params)

    # ====== ДАННЫЕ + ЛОГОТИП + ЗАГОЛОВОК + QR ======
    _draw_data_layer(c, w, h, doc_type, unique_number, access_token,
                     event, recipient, signed_by, primary, params,
                     minimal=False)

    c.showPage()
    c.save()
    return filepath


def _draw_standard_layout(c, w, h, doc_type, primary, params):
    """Фон и рамки документа по брендбуку (разделы 5.8-5.11). Только декор."""

    if doc_type == 'gratitude':
        # Альбомный А4 с паттерном слева (брендбук 5.8)
        c.saveState()
        c.setFillColor(HexColor(primary))
        c.rect(0, 0, 70 * mm, h, fill=1, stroke=0)
        c.restoreState()
        _draw_pattern(c, 70 * mm, h, '#FFFFFF')

    elif doc_type in ('diploma_winner',):
        # Диплом победителя — полная цветная рамка с узором (брендбук 5.10)
        c.saveState()
        c.setFillColor(HexColor(primary))
        margin = 18 * mm
        c.rect(0, 0, w, h, fill=1, stroke=0)
        c.setFillColor(white)
        c.rect(margin, margin, w - 2 * margin, h - 2 * margin, fill=1, stroke=0)
        c.restoreState()
        _draw_brand_pattern_frame(c, w, h, primary, inset=margin)

    elif doc_type == 'diploma_participant':
        # Диплом участника — контурная рамка с узором
        c.setStrokeColor(HexColor(primary))
        c.setLineWidth(0.6)
        margin = 18 * mm
        c.rect(margin, margin, w - 2 * margin, h - 2 * margin, fill=0, stroke=1)
        _draw_brand_pattern_frame(c, w, h, primary, inset=margin, outline_only=True)

    elif doc_type == 'charter':
        # Грамота — простая геометрическая рамка с уголками (брендбук 5.9)
        margin = 18 * mm
        c.setStrokeColor(HexColor(primary))
        c.setLineWidth(1.0)
        c.rect(margin, margin, w - 2 * margin, h - 2 * margin, fill=0, stroke=1)
        corner = 10 * mm
        for cx, cy in [(margin, margin), (w - margin - corner, margin),
                       (margin, h - margin - corner), (w - margin - corner, h - margin - corner)]:
            c.rect(cx, cy, corner, corner, fill=0, stroke=1)

    elif doc_type == 'certificate':
        # Сертификат — А5 альбомный с фирменной рамкой (брендбук 5.11)
        c.saveState()
        c.setFillColor(HexColor(primary))
        c.rect(0, 0, w, h, fill=1, stroke=0)
        c.setFillColor(white)
        margin = 10 * mm
        c.rect(margin, margin, w - 2 * margin, h - 2 * margin, fill=1, stroke=0)
        c.restoreState()
        _draw_brand_pattern_frame(c, w, h, primary, inset=margin)


def _draw_data_layer(c, w, h, doc_type, unique_number, access_token,
                     event, recipient, signed_by, primary, params, minimal=False):
    """
    Слой данных: логотип, заголовок, тело, подпись, дата, QR, номер.
    Все размеры и отступы вычисляются от размеров страницы — корректно
    работает для A4 и A5, портретной и альбомной ориентации.
    minimal=True — на пользовательском фоне рисуем только данные + QR + номер.
    """

    # Базовый масштаб — относительно меньшей стороны страницы.
    # Для A4 portrait: short=210мм, A5 portrait: short=148мм.
    short_side_mm = min(w, h) / mm
    # Масштабный коэффициент (для A4 = 1.0, для A5 ≈ 0.7)
    k = short_side_mm / 210.0

    # Размеры шрифтов масштабируются от k
    fs_title = max(20, int(42 * k))                # «ДИПЛОМ»
    fs_subtitle = max(10, int(14 * k))             # «ПОБЕДИТЕЛЯ»
    fs_intro = max(9, int(12 * k))                 # «Настоящим удостоверяется...»
    fs_name = max(14, int(20 * k))                 # ФИО
    fs_status = max(9, int(11 * k))                # «является победителем»
    fs_event = max(10, int(13 * k))                # название мероприятия
    fs_small = max(8, int(10 * k))                 # достижения/часы
    fs_sig = max(7, int(9 * k))                    # подпись
    fs_num = max(6, int(8 * k))                    # номер

    # Внешняя цветная рамка (для дипломов/сертификатов) занимает определённый margin
    # Это влияет на положение логотипа и подписи
    has_outer_frame = doc_type in ('diploma_winner', 'certificate')
    outer_margin_mm = 18 if doc_type == 'diploma_winner' else (10 if doc_type == 'certificate' else 0)

    # Отступы (тоже масштабируются, но не меньше outer_margin)
    base_top_mm = max(15 * k, outer_margin_mm + 5)      # от верха до логотипа
    base_bottom_mm = max(18 * k, outer_margin_mm + 6)   # от низа до подписи
    base_side_mm = max(18 * k, outer_margin_mm + 8)     # боковой отступ

    margin_top = base_top_mm * mm
    margin_bottom = base_bottom_mm * mm
    side_margin = base_side_mm * mm

    # ====== ШАПКА: НАЗВАНИЕ УНИВЕРСИТЕТА (текст, без логотипа) ======
    title_y = None

    if not minimal:
        uni_font_size = max(11, int(14 * k))
        if doc_type == 'gratitude':
            # Альбомный — название одной строкой по верху правой колонки
            c.setFont(_font('Manrope', bold=True), uni_font_size)
            c.setFillColor(HexColor(primary))
            title_x_left = max(0.30 * w, 80 * k * mm)
            c.drawString(title_x_left, h - margin_top,
                         "ТИХООКЕАНСКИЙ ГОСУДАРСТВЕННЫЙ УНИВЕРСИТЕТ")
        else:
            # Все остальные — название по центру сверху, в одну строку
            c.setFont(_font('Manrope', bold=True), uni_font_size)
            c.setFillColor(HexColor(primary))
            c.drawCentredString(w / 2, h - margin_top,
                                "ТИХООКЕАНСКИЙ ГОСУДАРСТВЕННЫЙ УНИВЕРСИТЕТ")

        # ====== ЗАГОЛОВОК ДОКУМЕНТА ======
        titles = {
            'diploma_winner': ('ДИПЛОМ', 'ПОБЕДИТЕЛЯ'),
            'diploma_participant': ('ДИПЛОМ', 'УЧАСТНИКА'),
            'gratitude': ('БЛАГОДАРСТВЕННОЕ', 'ПИСЬМО'),
            'charter': ('ГРАМОТА', None),
            'certificate': ('СЕРТИФИКАТ', None),
        }
        big_title, sub_title = titles.get(doc_type, ('ДОКУМЕНТ', None))

        if doc_type == 'gratitude':
            # Шапка одной строкой — заголовок просто ниже
            title_y = h - margin_top - uni_font_size * 2.5
            title_x_left = max(0.30 * w, 80 * k * mm)
            available_w = w - title_x_left - side_margin
            fs_gr_title = fs_title
            font_name = _font('Russo One')
            while fs_gr_title > 14:
                if c.stringWidth(big_title, font_name, fs_gr_title) <= available_w:
                    break
                fs_gr_title -= 1
            c.setFont(font_name, fs_gr_title)
            c.setFillColor(HexColor(primary))
            c.drawString(title_x_left, title_y, big_title)
            if sub_title:
                c.drawString(title_x_left, title_y - fs_gr_title * 1.1, sub_title)
        else:
            title_y = h - margin_top - uni_font_size * 1.5 - 0.06 * h
            c.setFont(_font('Russo One'), fs_title)
            c.setFillColor(HexColor(primary))
            c.drawCentredString(w / 2, title_y, big_title)
            if sub_title:
                c.setFont(_font('Manrope', bold=True), fs_subtitle)
                c.drawCentredString(w / 2, title_y - fs_title * 1.0, sub_title)

    # ====== ОСНОВНОЙ ТЕКСТ ======
    c.setFillColor(black)

    if doc_type == 'gratitude' and not minimal:
        # Альбомный
        body_x = max(0.30 * w, 80 * k * mm)
        # Тело начинается ниже заголовка (учитываем что у благодарности 2 строки заголовка)
        body_y = title_y - fs_title * 2.6
        line_step = max(11, int(14 * k))

        c.setFont(_font('Manrope'), fs_intro)
        c.drawString(body_x, body_y, "Выражаем искреннюю благодарность")
        c.setFont(_font('Manrope', bold=True), fs_name)
        c.setFillColor(HexColor(primary))
        c.drawString(body_x, body_y - line_step * 1.8, _safe_text(recipient['full_name']))
        c.setFillColor(black)
        c.setFont(_font('Manrope'), fs_status)
        c.drawString(body_x, body_y - line_step * 3.5, "за участие в мероприятии:")
        c.setFont(_font('Manrope', bold=True), fs_event)
        _wrap_text(c, body_x, body_y - line_step * 4.6,
                   _safe_text(event['name']),
                   max_width=w - body_x - side_margin,
                   line_height=line_step * 1.2)
        extra_y = body_y - line_step * 6.5
        if recipient['achievement']:
            c.setFont(_font('Manrope'), fs_status)
            c.drawString(body_x, extra_y, f"Достижения: {recipient['achievement']}")
            extra_y -= line_step
        if recipient['hours']:
            c.setFont(_font('Manrope'), fs_status)
            c.drawString(body_x, extra_y, f"Объём участия: {recipient['hours']} ч.")

    elif minimal:
        # На пользовательском фоне — компактный блок данных по центру
        center_y = h / 2
        c.setFont(_font('Manrope', bold=True), fs_name + 2)
        c.setFillColor(HexColor(primary))
        c.drawCentredString(w / 2, center_y + 0.05 * h, _safe_text(recipient['full_name']))
        c.setFillColor(black)
        c.setFont(_font('Manrope'), fs_event)
        _wrap_text_centered(c, w / 2, center_y - 0.02 * h,
                            _safe_text(event['name']),
                            max_width=w - 2 * side_margin,
                            line_height=fs_event * 1.3)
        if recipient['achievement']:
            c.setFont(_font('Manrope'), fs_small)
            c.drawCentredString(w / 2, center_y - 0.10 * h,
                                f"({recipient['achievement']})")

    else:
        # Центральный блок для дипломов / грамот / сертификатов
        # Якорь по центру страницы — все элементы относительно него
        # Сдвигаем слегка вверх, чтобы оставить место под подпись
        anchor_y = h * 0.46

        c.setFont(_font('Manrope'), fs_intro)
        c.drawCentredString(w / 2, anchor_y + fs_name * 1.6,
                            "Настоящим удостоверяется, что")

        c.setFont(_font('Manrope', bold=True), fs_name)
        c.setFillColor(HexColor(primary))
        c.drawCentredString(w / 2, anchor_y, _safe_text(recipient['full_name']))

        c.setFillColor(black)
        c.setFont(_font('Manrope'), fs_status)
        status_line = {
            'diploma_winner': "является победителем",
            'diploma_participant': "является участником",
            'charter': "награждается за",
            'certificate': "успешно прошёл(ла)",
        }.get(doc_type, "")
        c.drawCentredString(w / 2, anchor_y - fs_name * 1.0, status_line)

        c.setFont(_font('Manrope', bold=True), fs_event)
        _wrap_text_centered(c, w / 2, anchor_y - fs_name * 1.0 - fs_event * 1.5,
                            _safe_text(event['name']),
                            max_width=w - 2 * side_margin,
                            line_height=fs_event * 1.3)

        extra_y = anchor_y - fs_name * 1.0 - fs_event * 4.0
        if recipient['achievement']:
            c.setFont(_font('Manrope'), fs_small)
            c.drawCentredString(w / 2, extra_y, f"({recipient['achievement']})")
            extra_y -= fs_small * 1.5
        if recipient['hours']:
            c.setFont(_font('Manrope'), fs_small)
            c.drawCentredString(w / 2, extra_y,
                                f"Объём: {recipient['hours']} академ. часов")

    # ====== ПОДПИСЬ И ДАТА ======
    c.setFont(_font('Manrope'), fs_sig)
    c.setFillColor(black)
    date_str = (event['date_start'] or datetime.now().strftime('%Y-%m-%d'))
    sig_y = margin_bottom + fs_sig * 1.6  # минимум 3 строки от низа
    line_step = fs_sig * 1.5

    if doc_type == 'gratitude' and not minimal:
        sig_x = max(0.30 * w, 80 * k * mm)
        c.drawString(sig_x, sig_y + line_step * 2, f"Дата выдачи: {date_str}")
        c.drawString(sig_x, sig_y + line_step, f"Подписал: {signed_by}")
        c.drawString(sig_x, sig_y, f"Организатор: {_safe_text(event['organizer'])}")
    else:
        c.drawString(side_margin, sig_y + line_step * 2, f"Дата: {date_str}")
        c.drawString(side_margin, sig_y + line_step, f"Подписал (КЭП): {signed_by}")
        c.drawString(side_margin, sig_y, f"Организатор: {_safe_text(event['organizer'])}")

    # ====== QR-КОД ======
    if params.get('show_qr', True):
        verify_url = f"{request.host_url}verify/{access_token}" if request else f"/verify/{access_token}"
        qr_size_mm = max(15, 22 * k)
        qr_x = w - (qr_size_mm + 12 * k) * mm
        qr_y = sig_y - 1 * mm
        _draw_qr(c, verify_url, qr_x, qr_y, size_mm=qr_size_mm)
        c.setFont(_font('Manrope'), max(5, int(7 * k)))
        c.setFillColor(black)
        c.drawCentredString(qr_x + qr_size_mm * mm / 2, qr_y - 3 * mm,
                            "Проверка подлинности")
        c.drawCentredString(qr_x + qr_size_mm * mm / 2, qr_y - 6 * mm, unique_number)

    # ====== НОМЕР ДОКУМЕНТА ======
    c.setFont(_font('Manrope'), fs_num)
    c.setFillColor(black)
    num_y = max(8 * mm, (outer_margin_mm + 2) * mm)
    c.drawString(side_margin, num_y, f"№ {unique_number}")


def _wrap_text(c, x, y, text, max_width, line_height=14):
    """Простой перенос строк."""
    words = text.split()
    line = ""
    for word in words:
        test = (line + " " + word).strip()
        if c.stringWidth(test) < max_width:
            line = test
        else:
            c.drawString(x, y, line)
            y -= line_height
            line = word
    if line:
        c.drawString(x, y, line)


def _wrap_text_centered(c, cx, y, text, max_width, line_height=14):
    words = text.split()
    line = ""
    lines = []
    for word in words:
        test = (line + " " + word).strip()
        if c.stringWidth(test) < max_width:
            line = test
        else:
            lines.append(line)
            line = word
    if line:
        lines.append(line)
    for i, l in enumerate(lines):
        c.drawCentredString(cx, y - i * line_height, l)


def _draw_brand_pattern_frame(c, w, h, color, inset=18 * mm, outline_only=False):
    """Геометрический узор брендбука по периметру (раздел 5.2 — Фирменный узор)."""
    c.saveState()
    c.setStrokeColor(HexColor(color))
    if outline_only:
        c.setLineWidth(0.4)
        # Прямоугольники разного размера по периметру
        step = 18 * mm
        # Сверху
        x = 0
        while x < w:
            sz = (8 + (int(x / step) % 3) * 4) * mm
            c.rect(x, h - inset / 1.5, sz, inset / 2, fill=0, stroke=1)
            x += sz + 4 * mm
        # Снизу
        x = 0
        while x < w:
            sz = (10 + (int(x / step) % 3) * 3) * mm
            c.rect(x, inset / 4, sz, inset / 2, fill=0, stroke=1)
            x += sz + 4 * mm
    c.restoreState()


# ============================================================================
# СКАЧИВАНИЕ И ПРОСМОТР ДОКУМЕНТОВ
# ============================================================================

@app.route('/documents/<int:doc_id>/download')
@login_required
def document_download(doc_id):
    conn = get_db()
    doc = conn.execute("""
        SELECT d.*, r.email AS rec_email FROM documents d
        JOIN recipients r ON r.id = d.recipient_id
        WHERE d.id = ?
    """, (doc_id,)).fetchone()
    conn.close()
    if not doc:
        abort(404)

    user = current_user()
    # Получатель может качать только свой; админы — любые
    if user['role'] == 'recipient':
        if (doc['rec_email'] or '').lower() != user['email'].lower():
            abort(403)

    if not doc['file_pdf']:
        abort(404)
    log_event('document_downloaded', 'document', doc_id)
    return send_from_directory(GENERATED_FOLDER, doc['file_pdf'], as_attachment=True)


@app.route('/documents/<int:doc_id>/preview')
@login_required
def document_preview(doc_id):
    conn = get_db()
    doc = conn.execute("SELECT * FROM documents WHERE id = ?", (doc_id,)).fetchone()
    conn.close()
    if not doc or not doc['file_pdf']:
        abort(404)
    return send_from_directory(GENERATED_FOLDER, doc['file_pdf'])


# ============================================================================
# ШАБЛОНЫ (конструктор — упрощённая версия, выбор цвета института)
# ============================================================================

@app.route('/templates')
@login_required
@role_required('superadmin', 'admin')
def templates_list():
    conn = get_db()
    templates = conn.execute(
        "SELECT * FROM templates WHERE COALESCE(is_custom, 0) != 2 ORDER BY doc_type, name"
    ).fetchall()
    conn.close()
    return render_template('templates_list.html', templates=templates, brand_colors=BRAND_COLORS)


@app.route('/templates/<int:tpl_id>/edit', methods=['GET', 'POST'])
@login_required
@role_required('superadmin', 'admin')
def template_edit(tpl_id):
    conn = get_db()
    if request.method == 'POST':
        params = {
            'title_font': 'Russo One',
            'body_font': 'Manrope',
            'show_pattern': bool(request.form.get('show_pattern')),
            'show_qr': bool(request.form.get('show_qr')),
        }

        # Опциональная замена фона
        bg_filename = None
        bg_file = request.files.get('background_file')
        remove_bg = request.form.get('remove_background')

        existing = conn.execute(
            "SELECT background_file FROM templates WHERE id = ?", (tpl_id,)
        ).fetchone()
        if bg_file and bg_file.filename:
            ext = os.path.splitext(bg_file.filename)[1].lower()
            if ext in ('.png', '.jpg', '.jpeg', '.pdf'):
                safe = f"bg_{secrets.token_hex(6)}{ext}"
                bg_file.save(os.path.join(UPLOAD_FOLDER, safe))
                bg_filename = safe
        elif remove_bg:
            bg_filename = None
        else:
            bg_filename = existing['background_file'] if existing else None

        conn.execute("""
            UPDATE templates SET name = ?, doc_type = ?, orientation = ?, page_size = ?,
                                 institute_color = ?, background_file = ?,
                                 is_custom = ?, params_json = ?, version = version + 1
            WHERE id = ?
        """, (
            request.form['name'],
            request.form['doc_type'],
            request.form['orientation'],
            request.form['page_size'],
            request.form['institute_color'],
            bg_filename,
            1 if bg_filename else 0,
            json.dumps(params),
            tpl_id,
        ))
        conn.commit()
        log_event('template_updated', 'template', tpl_id)
        flash('Шаблон обновлён', 'success')
        return redirect(url_for('templates_list'))

    tpl = conn.execute("SELECT * FROM templates WHERE id = ?", (tpl_id,)).fetchone()
    conn.close()
    if not tpl:
        abort(404)
    return render_template('template_edit.html', tpl=tpl, brand_colors=BRAND_COLORS,
                           doc_types=DOC_TYPES)


# --- Создание нового шаблона с возможностью загрузки фона ---
@app.route('/templates/new', methods=['GET', 'POST'])
@login_required
@role_required('superadmin', 'admin')
def template_new():
    if request.method == 'POST':
        bg_filename = None
        bg_file = request.files.get('background_file')
        if bg_file and bg_file.filename:
            ext = os.path.splitext(bg_file.filename)[1].lower()
            if ext not in ('.png', '.jpg', '.jpeg', '.pdf'):
                flash('Допустимые форматы фона: PNG, JPG, PDF', 'error')
                return redirect(url_for('template_new'))
            safe = f"bg_{secrets.token_hex(6)}{ext}"
            bg_file.save(os.path.join(UPLOAD_FOLDER, safe))
            bg_filename = safe

        params = {
            'title_font': 'Russo One',
            'body_font': 'Manrope',
            'show_pattern': bool(request.form.get('show_pattern')),
            'show_qr': bool(request.form.get('show_qr', '1')),
        }

        conn = get_db()
        cur = conn.cursor()
        cur.execute("""
            INSERT INTO templates (name, doc_type, orientation, page_size,
                                   institute_color, background_file, is_custom,
                                   params_json, created_by)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            request.form['name'],
            request.form['doc_type'],
            request.form['orientation'],
            request.form['page_size'],
            request.form.get('institute_color', BRAND_COLORS['primary']),
            bg_filename,
            1 if bg_filename else 0,
            json.dumps(params),
            session['user_id'],
        ))
        new_id = cur.lastrowid
        conn.commit()
        conn.close()
        log_event('template_created', 'template', new_id, {'name': request.form['name']})
        flash('Шаблон создан', 'success')
        return redirect(url_for('templates_list'))

    return render_template('template_new.html', brand_colors=BRAND_COLORS,
                           doc_types=DOC_TYPES)


# --- Одноразовый выпуск БЕЗ сохранения шаблона ---
@app.route('/events/<int:event_id>/issue-oneoff', methods=['GET', 'POST'])
@login_required
@role_required('superadmin', 'admin')
def issue_oneoff(event_id):
    """
    Выпуск одного или нескольких документов без сохранения шаблона.
    Параметры шаблона задаются прямо в форме; фон можно загрузить как однократный.
    """
    conn = get_db()
    event = conn.execute("SELECT * FROM events WHERE id = ?", (event_id,)).fetchone()
    if not event:
        conn.close()
        abort(404)

    if request.method == 'POST':
        recipient_ids = request.form.getlist('recipient_ids')
        if not recipient_ids:
            flash('Не выбраны получатели', 'error')
            # Возвращаем форму с уже введёнными настройками
            recipients = conn.execute(
                "SELECT * FROM recipients WHERE event_id = ? ORDER BY full_name",
                (event_id,)
            ).fetchall()
            conn.close()
            return render_template(
                'issue_oneoff.html', event=event, recipients=recipients,
                brand_colors=BRAND_COLORS, doc_types=DOC_TYPES,
                form_data=request.form,
                selected_ids=[],
            )

        # Загруженный фон (опционально) — сохраним временно, но в шаблон не запишем
        bg_filename = None
        bg_file = request.files.get('background_file')
        if bg_file and bg_file.filename:
            ext = os.path.splitext(bg_file.filename)[1].lower()
            if ext in ('.png', '.jpg', '.jpeg', '.pdf'):
                safe = f"oneoff_{secrets.token_hex(6)}{ext}"
                bg_file.save(os.path.join(UPLOAD_FOLDER, safe))
                bg_filename = safe

        # Виртуальный шаблон (в памяти, не сохраняем в БД)
        virtual_template = {
            'id': None,
            'name': request.form.get('name', 'Одноразовый шаблон'),
            'doc_type': request.form.get('doc_type', 'certificate'),
            'orientation': request.form.get('orientation', 'portrait'),
            'page_size': request.form.get('page_size', 'A4'),
            'institute_color': request.form.get('institute_color', BRAND_COLORS['primary']),
            'background_file': bg_filename,
            'params_json': json.dumps({
                'show_qr': bool(request.form.get('show_qr', '1')),
                'show_pattern': bool(request.form.get('show_pattern')),
            }),
        }

        user = current_user()
        # Чтобы корректно сохранить документ в БД (FK на templates),
        # создадим временный «системный» шаблон с пометкой и удалим его сразу после выпуска,
        # ИЛИ просто разрешим document.template_id быть NULL.
        # Удобнее: создаём «скрытый» шаблон с пометкой is_custom=2 (одноразовый),
        # но НЕ показываем его в списке. Так мы сохраняем целостность БД.
        cur = conn.cursor()
        cur.execute("""
            INSERT INTO templates (name, doc_type, orientation, page_size, institute_color,
                                   background_file, is_custom, params_json, created_by)
            VALUES (?, ?, ?, ?, ?, ?, 2, ?, ?)
        """, (
            virtual_template['name'] + ' (одноразовый)',
            virtual_template['doc_type'],
            virtual_template['orientation'],
            virtual_template['page_size'],
            virtual_template['institute_color'],
            virtual_template['background_file'],
            virtual_template['params_json'],
            session['user_id'],
        ))
        tmp_tpl_id = cur.lastrowid
        # Получаем как Row для совместимости с generate_document_pdf
        tpl_row = conn.execute("SELECT * FROM templates WHERE id = ?", (tmp_tpl_id,)).fetchone()

        issued = 0
        for rid in recipient_ids:
            recipient = conn.execute("SELECT * FROM recipients WHERE id = ?", (rid,)).fetchone()
            if not recipient:
                continue
            unique_number = f"ТОГУ-{datetime.now().year}-{secrets.token_hex(4).upper()}"
            access_token = secrets.token_urlsafe(24)
            sig_payload = f"{unique_number}|{recipient['full_name']}|{event['name']}|{tpl_row['name']}"
            signature_hash = hashlib.sha256(
                (sig_payload + app.config['SECRET_KEY']).encode('utf-8')
            ).hexdigest()

            cur.execute("""
                INSERT INTO documents (unique_number, access_token, event_id, recipient_id,
                                       template_id, doc_type, signature_hash, signed_by)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """, (unique_number, access_token, event_id, recipient['id'],
                  tmp_tpl_id, tpl_row['doc_type'], signature_hash, user['full_name']))
            doc_id = cur.lastrowid

            pdf_path = generate_document_pdf(
                doc_id=doc_id,
                unique_number=unique_number,
                access_token=access_token,
                template=tpl_row,
                event=event,
                recipient=recipient,
                signed_by=user['full_name'],
            )
            cur.execute("UPDATE documents SET file_pdf = ? WHERE id = ?",
                        (os.path.basename(pdf_path), doc_id))
            issued += 1

        conn.commit()
        conn.close()
        log_event('oneoff_issued', 'event', event_id,
                  {'count': issued, 'doc_type': tpl_row['doc_type']})
        flash(f'Выпущено документов: {issued} (без сохранения шаблона)', 'success')
        return redirect(url_for('event_detail', event_id=event_id))

    recipients = conn.execute(
        "SELECT * FROM recipients WHERE event_id = ? ORDER BY full_name", (event_id,)
    ).fetchall()
    conn.close()
    return render_template('issue_oneoff.html', event=event, recipients=recipients,
                           brand_colors=BRAND_COLORS, doc_types=DOC_TYPES,
                           form_data={}, selected_ids=[])


# ============================================================================
# ЖУРНАЛ СОБЫТИЙ (для роли наблюдателя/аудитора)
# ============================================================================

@app.route('/audit')
@login_required
@role_required('superadmin', 'auditor')
def audit_log():
    conn = get_db()
    events = conn.execute("""
        SELECT el.*, u.full_name AS user_name FROM event_log el
        LEFT JOIN users u ON u.id = el.user_id
        ORDER BY el.created_at DESC LIMIT 200
    """).fetchall()
    conn.close()
    return render_template('audit.html', events=events)


# ============================================================================
# СПРАВОЧНИК ПОЛЬЗОВАТЕЛЕЙ (для суперадмина)
# ============================================================================

@app.route('/users', methods=['GET', 'POST'])
@login_required
@role_required('superadmin')
def users_list():
    conn = get_db()
    if request.method == 'POST':
        try:
            conn.execute("""
                INSERT INTO users (email, password_hash, full_name, role, department)
                VALUES (?, ?, ?, ?, ?)
            """, (
                request.form['email'].strip().lower(),
                generate_password_hash(request.form['password']),
                request.form['full_name'],
                request.form['role'],
                request.form.get('department'),
            ))
            conn.commit()
            log_event('user_created', 'user', None, {'email': request.form['email']})
            flash('Пользователь создан', 'success')
        except sqlite3.IntegrityError:
            flash('Email уже зарегистрирован', 'error')

    users = conn.execute("SELECT * FROM users ORDER BY created_at DESC").fetchall()
    conn.close()
    return render_template('users.html', users=users)


# ============================================================================
# API: проверка подлинности (для интеграций)
# ============================================================================

@app.route('/api/verify/<token>')
def api_verify(token):
    conn = get_db()
    doc = conn.execute("""
        SELECT d.unique_number, d.signature_hash, d.signed_by, d.issued_at, d.status,
               r.full_name AS recipient, e.name AS event
        FROM documents d
        JOIN recipients r ON r.id = d.recipient_id
        JOIN events e ON e.id = d.event_id
        WHERE d.access_token = ?
    """, (token,)).fetchone()
    conn.close()
    if not doc:
        return jsonify({'valid': False, 'error': 'not_found'}), 404
    return jsonify({
        'valid': True,
        'unique_number': doc['unique_number'],
        'recipient': doc['recipient'],
        'event': doc['event'],
        'signed_by': doc['signed_by'],
        'issued_at': doc['issued_at'],
        'status': doc['status'],
    })


# ============================================================================
# ОБРАБОТКА ОШИБОК
# ============================================================================

@app.errorhandler(404)
def not_found(e):
    return render_template('error.html', code=404, msg='Страница не найдена'), 404


@app.errorhandler(403)
def forbidden(e):
    return render_template('error.html', code=403, msg='Доступ запрещён'), 403


# ============================================================================
# ЗАПУСК
# ============================================================================

if __name__ == '__main__':
    init_db()
    print("=" * 60)
    print("ТОГУ — Платформа наградных документов")
    print("=" * 60)
    print(f"  Запуск:  http://127.0.0.1:5000")
    print(f"  Логины:")
    print(f"    admin@pnu.edu.ru / admin123    (суперадмин)")
    print(f"    iasid@pnu.edu.ru / demo123     (админ ИАСиД)")
    print(f"    student@pnu.edu.ru / demo123   (получатель)")
    print("=" * 60)
    app.run(debug=True, host='127.0.0.1', port=5000)
