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

app.config.update(
    SESSION_COOKIE_SECURE=True,
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_REFRESH_EACH_REQUEST=True,
    PERMANENT_SESSION_LIFETIME=timedelta(hours=2)
)

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
        timestamp TEXT NOT NULL,
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

def hash_password(password):
    return hashlib.sha256(password.encode('utf-8')).hexdigest()

# ルート定義の例（全てのデータベース操作をwith文でラップ）
@app.route('/', methods=['GET', 'POST'])
@login_required
def index():
    if request.method == 'POST':
        pass

    with get_db_connection() as conn:
        try:
            # 日付と時間を別々に取得するよう修正
            records = conn.execute('''
                SELECT id, action,
                       strftime('%Y-%m-%d', datetime(timestamp, '+9 hours')) as formatted_date,
                       strftime('%H:%M:%S', datetime(timestamp, '+9 hours')) as formatted_time,
                       memo, likes_count
                FROM records
                WHERE user_id = ? AND is_deleted = 0 AND DATE(timestamp) = DATE('now', '+9 hours')
                ORDER BY timestamp DESC
            ''', (session['user_id'],)).fetchall()
        except sqlite3.Error as e:
            flash(f"データベースエラーが発生しました: {e}", "error")
            records = []

    return render_template("index.html", records=records, is_private=session.get('is_private', False))

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

# app.py カレンダー関連部分修正
@app.route('/calendar', methods=['GET'])
@login_required
def calendar_view():
    # 現在の日本時間を取得
    now = datetime.now(pytz.timezone('Asia/Tokyo'))
    year = request.args.get('year', now.year, type=int)
    month = request.args.get('month', now.month, type=int)
    
    # カレンダー生成
    cal = calendar.monthcalendar(year, month)
    
    # 前月/次月計算
    prev_year, prev_month = (year, month-1) if month > 1 else (year-1, 12)
    next_year, next_month = (year, month+1) if month < 12 else (year+1, 1)
    
    return render_template(
        'calendar.html',
        year=year,
        month=month,
        cal=cal,
        prev_year=prev_year,
        prev_month=prev_month,
        next_year=next_year,
        next_month=next_month,
        today=now.date()
    )

def generate_calendar(year, month):
    cal = calendar.monthcalendar(year, month)
    return cal

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username').strip()
        password = request.form.get('password')

        with get_db_connection() as conn:
            user = conn.execute(
                'SELECT * FROM users WHERE username = ?', (username,)
            ).fetchone()

        if user:
            if user['password'] == hash_password(password):
                session.permanent = True
                session['user_id'] = user['id']
                session['username'] = user['username']
                session['is_admin'] = bool(user['is_admin'])
                flash('ログインしました。', 'success')
                return redirect(url_for('admin_dashboard' if user['is_admin'] else 'index'))
            else:
                flash('ユーザー名またはパスワードが間違っています。', 'error')
        else:
            flash('ユーザーが存在しません。新規登録してください。', 'error')
    return render_template('login.html')

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
            FROM records r JOIN users u ON r.user_id=u.id
            ORDER BY r.timestamp DESC LIMIT ? OFFSET ?
        ''', (per_page, offset)).fetchall()

        # ユーザーリスト取得（追加）
        users = conn.execute('SELECT * FROM users ORDER BY created_at DESC').fetchall()

    total_pages = (total_records + per_page - 1) // per_page
    return render_template('admin_dashboard.html',
                           records=records,
                           users=users,  # ユーザーリストも渡す
                           page=page,
                           total_pages=total_pages)


@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username').strip()
        password = request.form.get('password')
        with get_db_connection() as conn:
            existing_user = conn.execute(
                'SELECT * FROM users WHERE username=?', (username,)
            ).fetchone()
            if existing_user:
                flash('このユーザー名は既に使用されています。', 'error')
                return render_template("register.html")
            
            conn.execute(
                "INSERT INTO users (username, password) VALUES (?, ?)",
                (username, hash_password(password))
            )
            conn.commit()
            flash("登録完了しました。ログインしてください。", "success")
            return redirect(url_for("login"))
    
    return render_template("register.html")

@app.route('/reset_password', methods=['GET', 'POST'])
def reset_password():
    if request.method == 'POST':
        username = request.form.get('username').strip()
        new_password = request.form.get('new_password')
        with get_db_connection() as conn:
            user = conn.execute(
                'SELECT * FROM users WHERE username=?', (username,)
            ).fetchone()
            if user:
                conn.execute(
                    'UPDATE users SET password=? WHERE username=?',
                    (hash_password(new_password), username))
                conn.commit()
                flash('パスワードが更新されました。ログインしてください。', 'success')
                return redirect(url_for('login'))
            else:
                flash('指定されたユーザー名が見つかりませんでした。', 'error')
    return render_template("reset_password.html")

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

    if not action or action not in ['wake_up', 'sleep']:
        flash('有効な行動を選択してください', 'danger')
        return redirect(url_for('index'))

    try:
        # 日本時間のタイムスタンプを明示的に生成
        timestamp = datetime.now(pytz.timezone('Asia/Tokyo'))

        with get_db_connection() as conn:
            conn.execute('BEGIN TRANSACTION')

            # レコード挿入
            conn.execute(
                '''INSERT INTO records 
                (user_id, action, timestamp, memo)
                VALUES (?, ?, ?, ?)''',
                (session['user_id'], action, timestamp.isoformat(), memo)
            )

            # トランザクションコミット
            conn.commit()

        flash('記録が正常に保存されました', 'success')

    except sqlite3.Error as e:
        conn.rollback()
        error_message = f'データベースエラー: {str(e)}'
        app.logger.error(error_message)
        flash(error_message, 'danger')
    except Exception as e:
        error_message = f'予期せぬエラー: {str(e)}'
        app.logger.error(error_message)
        flash(error_message, 'danger')

    return redirect(url_for('index'))

@app.route('/day_records/<date>')
@login_required
def day_records(date):
    try:
        # 日付形式の検証を追加
        parsed_date = datetime.strptime(date, '%Y-%m-%d').date()
    except ValueError:
        flash('無効な日付形式です', 'error')
        return redirect(url_for('calendar_view'))

    with get_db_connection() as conn:
        try:
            if session.get('is_admin'):
                records = conn.execute('''
                    SELECT * FROM records
                    WHERE DATE(timestamp) = ?
                    ORDER BY timestamp ASC
                ''', (parsed_date,)).fetchall()
            else:
                records = conn.execute('''
                    SELECT * FROM records
                    WHERE user_id = ?
                    AND DATE(timestamp) = ?
                    AND is_deleted = 0
                    ORDER BY timestamp ASC
                ''', (session['user_id'], parsed_date)).fetchall()

            return render_template('day_records.html',
                                date=parsed_date.strftime('%Y-%m-%d'),
                                records=records,
                                is_admin=session.get('is_admin'))
        except sqlite3.Error as e:
            flash(f'データベースエラー: {str(e)}', 'error')
            return redirect(url_for('calendar_view'))

@app.route('/all_records')
@login_required
def all_records():
    page = request.args.get("page", 1, type=int)
    per_page = 20
    offset = (page - 1) * per_page

    with get_db_connection() as conn:
        total_records = conn.execute(
            "SELECT COUNT(*) FROM records JOIN users ON records.user_id=users.id WHERE records.is_deleted=0 AND users.is_private=0"
        ).fetchone()[0]

        records = conn.execute(
            '''
            SELECT users.username, records.id, records.action,
                   strftime('%Y-%m-%d', datetime(records.timestamp,'+9 hours')) as formatted_date,
                   strftime('%H:%M:%S', datetime(records.timestamp, '+9 hours')) as formatted_time,
                   records.memo, records.likes_count
              FROM records JOIN users ON records.user_id=users.id 
              WHERE records.is_deleted=0 AND users.is_private=0 
              ORDER BY records.timestamp DESC LIMIT ? OFFSET ?''',
              (per_page, offset)).fetchall()

        liked_ids = [row["record_id"] for row in conn.execute(
          "SELECT record_id FROM likes WHERE user_id=?", 
          (session["user_id"],)).fetchall()]
        
        formatted_records=[]
        for record in records:
          formatted_records.append({
              "username": record["username"],
              "formatted_date": record["formatted_date"],
              "formatted_time": record["formatted_time"],
              "action": record["action"],
              "memo": record["memo"],
              "likes_count": record["likes_count"],
              "id": record["id"],
              "liked": record["id"] in liked_ids})

    total_pages=(total_records+per_page-1)//per_page

    return render_template("all_records.html",records=formatted_records,page=page,total_pages=total_pages)

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
