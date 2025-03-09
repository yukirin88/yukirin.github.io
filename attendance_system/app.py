# app.py の完全修正版

from flask import Flask, render_template, request, redirect, url_for, session, flash
from flask_bootstrap import Bootstrap
from flask_cors import CORS
from datetime import datetime, timedelta
from functools import wraps
import sqlite3
import hashlib
import calendar
import pytz
import os

app = Flask(__name__, template_folder='templates')
Bootstrap(app)
CORS(app)
app.secret_key = os.environ.get('SECRET_KEY', 'your-secret-key-here')
DATABASE_PATH = os.environ.get('DATABASE_URL', 'attendance.db')

def hash_password(password):
    return hashlib.sha256(password.encode('utf-8')).hexdigest()

def get_db_connection():
    conn = sqlite3.connect(DATABASE_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn

def init_db():
    """Initialize database with proper table structure"""
    with get_db_connection() as conn:
        cursor = conn.cursor()
        try:
            # Create users table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS users (
                    id INTEGER PRIMARY KEY,
                    username TEXT UNIQUE NOT NULL,
                    password TEXT NOT NULL,
                    is_admin BOOLEAN DEFAULT 0,
                    is_private BOOLEAN DEFAULT 0,
                    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
                )
            ''')
            # Create records table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS records (
                    id INTEGER PRIMARY KEY,
                    user_id INTEGER NOT NULL,
                    action TEXT NOT NULL,
                    timestamp DATETIME NOT NULL,
                    memo TEXT,
                    is_deleted BOOLEAN DEFAULT 0,
                    likes_count INTEGER DEFAULT 0,
                    is_private BOOLEAN DEFAULT 0,
                    FOREIGN KEY(user_id) REFERENCES users(id)
                )
            ''')
            # Create likes table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS likes (
                    id INTEGER PRIMARY KEY,
                    user_id INTEGER NOT NULL,
                    record_id INTEGER NOT NULL,
                    timestamp DATETIME NOT NULL,
                    FOREIGN KEY(user_id) REFERENCES users(id),
                    FOREIGN KEY(record_id) REFERENCES records(id)
                )
            ''')
            # Add missing columns if needed
            columns = [
                ('users', 'is_private', 'INTEGER DEFAULT 0'),
                ('records', 'likes_count', 'INTEGER DEFAULT 0')
            ]

            for table, column, definition in columns:
                try:
                    cursor.execute(f'ALTER TABLE {table} ADD COLUMN {column} {definition}')
                except sqlite3.OperationalError as e:
                    if 'duplicate column name' not in str(e):
                        raise
            conn.commit()
        except sqlite3.Error as e:
            print(f"Database initialization error: {e}")
            conn.rollback()

def create_admin_user():
    """Create admin user if not exists"""
    with get_db_connection() as conn:
        cursor = conn.cursor()
        try:
            admin = cursor.execute('SELECT * FROM users WHERE username = ?', ('admin',)).fetchone()
            if not admin:
                cursor.execute(
                    'INSERT INTO users (username, password, is_admin) VALUES (?, ?, ?)',
                    ('admin', hash_password('admin'), 1)
                )
            conn.commit()
        except sqlite3.Error as e:
            print(f"Admin user creation error: {e}")
            conn.rollback()

# Initialize app context
with app.app_context():
    init_db()
    create_admin_user()

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash('ログインが必要です。', 'error')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session or not session.get('is_admin'):
            flash('管理者権限が必要です。', 'error')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

def jst_now():
    return datetime.now(pytz.timezone('Asia/Tokyo'))

# ルート定義の例（全てのデータベース操作をwith文でラップ）
@app.route('/')
@login_required
def index():
    with get_db_connection() as conn:
        records = conn.execute('''
            SELECT id, action, 
            strftime('%Y-%m-%d %H:%M:%S', timestamp) as formatted_time,
            memo, likes_count 
            FROM records 
            WHERE user_id = ? AND is_deleted = 0
            ORDER BY timestamp DESC
        ''', (session['user_id'],)).fetchall()
    return render_template("index.html", records=records)

@app.route('/like_record/<int:record_id>', methods=['POST'])
@login_required
def like_record(record_id):
    from_page = request.args.get('from_page', 'index') # クエリパラメータから取得
    try:
        with get_db_connection() as conn:
            # すでにいいね済みか確認
            existing_like = conn.execute(
                'SELECT id FROM likes WHERE user_id = ? AND record_id = ?',
                (session['user_id'], record_id)
            ).fetchone()
            if existing_like:
                flash('すでにいいね済みです。', 'info')
            else:
                # likesテーブルに新しいいいねを追加
                conn.execute(
                    'INSERT INTO likes (user_id, record_id, timestamp) VALUES (?, ?, ?)',
                    (session['user_id'], record_id, jst_now())
                )
                # recordsテーブルのlikes_countを更新
                conn.execute(
                    'UPDATE records SET likes_count = likes_count + 1 WHERE id = ?',
                    (record_id,)
                )
                conn.commit()
                flash('いいねしました！', 'success')
    except sqlite3.Error as e:
        flash(f'エラーが発生しました: {e}', 'error')
    
    # from_pageに基づいてリダイレクト
    if from_page == 'index':
        return redirect(url_for('index'))
    elif from_page == 'all_records':
        return redirect(url_for('all_records'))
    else:
        return redirect(url_for('index'))

@app.route('/calendar', methods=['GET'])
@login_required
def calendar_view():
    year = request.args.get('year', datetime.now(pytz.timezone('Asia/Tokyo')).year, type=int)
    month = request.args.get('month', datetime.now(pytz.timezone('Asia/Tokyo')).month, type=int)
    today = datetime.now(pytz.timezone('Asia/Tokyo'))
    cal = generate_calendar(year, month)
    prev_month = month - 1
    prev_year = year
    if prev_month == 0:
        prev_month = 12
        prev_year -= 1
    next_month = month + 1
    next_year = year
    if next_month == 13:
        next_month = 1
        next_year += 1
    return render_template(
        'calendar.html',
        year=year,
        month=month,
        cal=cal,
        prev_month=prev_month,
        prev_year=prev_year,
        next_month=next_month,
        next_year=next_year,
        today=today
    )

def generate_calendar(year, month):
    cal = calendar.monthcalendar(year, month)
    return cal

@app.route('/login', methods=['GET', 'POST'])
def login():
    is_mobile = request.user_agent.platform in ['iphone', 'android']
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')
        if not username or not password:
            flash('ユーザー名とパスワードを入力してください。', 'error')
            return render_template('login.html', is_mobile=is_mobile)
        with get_db_connection() as conn:
            user = conn.execute('SELECT * FROM users WHERE username = ?', (username,)).fetchone()
            if user and user['password'] == hash_password(password):
                session['user_id'] = user['id']
                session['username'] = user['username']
                session['is_admin'] = user['is_admin']
                return redirect(url_for('admin_dashboard' if user['is_admin'] else 'index'))
            else:
                flash('ユーザー名またはパスワードが間違っています。', 'error')
            return render_template('login.html', is_mobile=is_mobile)
    return render_template('login.html', is_mobile=is_mobile)

@app.route('/admin_dashboard')
@admin_required
def admin_dashboard():
    page = request.args.get('page', 1, type=int)
    per_page = 20
    offset = (page - 1) * per_page
    with get_db_connection() as conn:
        total_records = conn.execute('SELECT COUNT(*) FROM records').fetchone()[0]
        records = conn.execute('''
            SELECT r.*, u.username, u.is_private as user_private
            FROM records r
            JOIN users u ON r.user_id = u.id
            ORDER BY r.timestamp DESC
            LIMIT ? OFFSET ?
        ''', (per_page, offset)).fetchall()
        # タイムスタンプ処理
        for record in records:
            record['timestamp'] = datetime.fromisoformat(record['timestamp'])
        total_pages = (total_records + per_page - 1) // per_page
        return render_template('admin_dashboard.html',
            records=records,
            page=page,
            total_pages=total_pages)

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')
        is_private = request.form.get('is_private') == 'on'
        if not username or not password:
            flash('ユーザー名とパスワードを入力してください。', 'error')
            return render_template('register.html')
        with get_db_connection() as conn:
            existing_user = conn.execute(
                'SELECT * FROM users WHERE username = ?', (username,)
            ).fetchone()
            if existing_user:
                flash('このユーザー名は既に使用されています。', 'error')
                return render_template('register.html')
            conn.execute(
                'INSERT INTO users (username, password, is_private) VALUES (?, ?, ?)',
                (username, hash_password(password), int(is_private))
            )
            conn.commit()
            flash('登録が完了しました。ログインしてください。', 'success')
            return redirect(url_for('login'))
    return render_template('register.html')

@app.route('/reset_password', methods=['GET', 'POST'])
def reset_password():
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        new_password = request.form.get('new_password', '')
        if not username or not new_password:
            flash('ユーザー名と新しいパスワードを入力してください。', 'error')
            return render_template('reset_password.html')
        with get_db_connection() as conn:
            user = conn.execute(
                'SELECT * FROM users WHERE username = ?',
                (username,)
            ).fetchone()
            if user:
                conn.execute(
                    'UPDATE users SET password = ? WHERE username = ?',
                    (hash_password(new_password), username)
                )
                conn.commit()
                flash('パスワードが更新されました。ログインしてください。', 'success')
                return redirect(url_for('login'))
            else:
                flash('指定されたユーザー名が見つかりませんでした。', 'error')
            return render_template('reset_password.html')
    return render_template('reset_password.html')

@app.route('/logout')
@login_required
def logout():
    session.clear()
    flash('ログアウトしました。', 'info')
    return redirect(url_for('login'))

@app.route('/record', methods=['POST'])
@login_required
def record():
    action = request.form.get('action')
    memo = request.form.get('memo', '')
    if not action:
        flash('アクションを選択してください。', 'error')
        return redirect(url_for('index'))

    timestamp = jst_now() # jst_now()でタイムゾーンawareなdatetimeオブジェクトを取得
    with get_db_connection() as conn:
        conn.execute(
            'INSERT INTO records (user_id, action, timestamp, memo) VALUES (?, ?, ?, ?)',
            (session['user_id'], action, timestamp, memo)
        )
        conn.commit()
        flash('記録が保存されました。', 'success')
    return redirect(url_for('index'))

@app.route('/day_records/<date>')
@login_required
def day_records(date):
    with get_db_connection() as conn:
        cursor = conn.cursor()
        try:
            if session.get('is_admin'):
                cursor.execute('''
                    SELECT action, timestamp, memo, username, is_deleted
                    FROM records
                    WHERE DATE(timestamp) = ?
                    ORDER BY timestamp ASC
                ''', (date,))
            else:
                cursor.execute('''
                    SELECT action, timestamp, memo, username
                    FROM records
                    WHERE user_id = ? AND DATE(timestamp) = ? AND is_deleted = 0
                    ORDER BY timestamp ASC
                ''', (session['user_id'], date))
            records = cursor.fetchall()
        except ValueError as ve:
            flash(f'日付形式が無効です: {ve}', 'error')
            records = []
        except sqlite3.Error as e:
            flash(f'データベースエラーが発生しました: {e}', 'error')
            records = []
        return render_template('day_records.html', date=date, records=records, is_admin=session.get('is_admin'))

@app.route('/all_records')
@login_required
def all_records():
    page = request.args.get('page', 1, type=int)
    per_page = 20
    offset = (page - 1) * per_page
    
    with get_db_connection() as conn:
        # 修正点1: JST時間変換とフォーマット処理
        total_records = conn.execute('''
            SELECT COUNT(*) 
            FROM records
            INNER JOIN users ON records.user_id = users.id
            WHERE users.is_private = 0 
            AND records.is_deleted = 0
        ''').fetchone()[0]

        records = conn.execute('''
            SELECT 
                users.username,
                records.id,
                records.action,
                strftime('%Y-%m-%d', 
                datetime(records.timestamp, '+9 hours')) as formatted_date,
                strftime('%H:%M:%S', 
                datetime(records.timestamp, '+9 hours')) as formatted_time,
                records.memo,
                records.likes_count
            FROM records
            INNER JOIN users ON records.user_id = users.id
            WHERE users.is_private = 0
            AND records.is_deleted = 0
            ORDER BY records.timestamp DESC
            LIMIT ? OFFSET ?
        ''', (per_page, offset)).fetchall()

        total_pages = (total_records + per_page - 1) // per_page
        
    return render_template(
        'all_records.html',
        records=records,
        page=page,
        total_pages=total_pages
    )

@app.route('/toggle_privacy', methods=['POST'])
@login_required
def toggle_privacy():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    is_private = request.form.get('is_private') == 'on'
    try:
        with get_db_connection() as conn:
            conn.execute(
                'UPDATE users SET is_private = ? WHERE id = ?',
                (int(is_private), session['user_id'])
            )
            conn.commit()
            session['is_private'] = is_private
            flash('プライバシー設定が更新されました。', 'success')
    except sqlite3.Error as e:
        flash(f'プライバシー設定更新中にエラーが発生しました: {e}', 'error')
    return redirect(url_for('index'))

@app.route('/delete_record/<int:record_id>', methods=['POST'])
@login_required
def delete_record(record_id):
    try:
        with get_db_connection() as conn:
            # 記録を論理削除
            conn.execute('''
                UPDATE records
                SET is_deleted = 1
                WHERE id = ? AND user_id = ?
            ''', (record_id, session['user_id']))
            conn.commit()
            flash('記録が削除されました。', 'success')
    except sqlite3.Error as e:
        flash(f'記録の削除中にエラーが発生しました: {e}', 'error')
    return redirect(url_for('index'))

@app.route('/delete_user/<int:user_id>', methods=['POST'])
@admin_required
def delete_user(user_id):
    if user_id == session.get('user_id'):
        flash('自分自身を削除することはできません。', 'error')
        return redirect(url_for('admin_dashboard'))
    try:
        with get_db_connection() as conn:
            # ユーザーの記録を削除
            conn.execute('DELETE FROM records WHERE user_id = ?', (user_id,))
            # ユーザーを削除
            conn.execute('DELETE FROM users WHERE id = ?', (user_id,))
            conn.commit()
            flash('ユーザーが削除されました。', 'success')
    except sqlite3.Error as e:
        flash(f'ユーザー削除中にエラーが発生しました: {e}', 'error')
    return redirect(url_for('admin_dashboard'))

# その他のルートと関数は変更なし（適切なwith文を使用してデータベース接続を管理）

if __name__ == '__main__':
    app.run(debug=True)
