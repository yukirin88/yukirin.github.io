from flask import Flask, render_template, request, redirect, url_for, session, flash
from flask_wtf import FlaskForm
from flask_bootstrap import Bootstrap
from flask_cors import CORS
from flask_talisman import Talisman
from datetime import datetime, timedelta
from functools import wraps
import sqlite3
import hashlib
import calendar
import pytz
import os  # osモジュールをインポート

app = Flask(__name__, template_folder='templates')
Bootstrap(app)
CORS(app)
# Talisman(app, force_https=True)  # HTTPSを強制する場合はコメントアウトを解除
app.secret_key = 'your_secret_key_here'

# データベースファイルのパス
DATABASE_PATH = os.environ.get('DATABASE_URL', 'attendance.db')  # 環境変数からパスを取得。なければ'attendance.db'を使用

def get_db_connection():
    conn = sqlite3.connect(DATABASE_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def hash_password(password):
    return hashlib.sha256(password.encode('utf-8')).hexdigest()

def jst_now():
    tz = pytz.timezone('Asia/Tokyo')  # タイムゾーンを東京に設定
    return datetime.now(tz)  # 日本標準時で現在の日時を取得

def generate_calendar(year, month):
    cal = calendar.monthcalendar(year, month)
    return cal

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session or not session.get('is_admin'):
            flash('このページにアクセスする権限がありません。', 'error')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    decorated_function.__name__ = f.__name__
    return decorated_function

# データベース初期化関数
def init_db():
    conn = get_db_connection()
    cursor = conn.cursor()

    try:
        # usersテーブルが存在しない場合は作成
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY,
                username TEXT UNIQUE,
                password TEXT,
                is_admin INTEGER DEFAULT 0
            )
        ''')

        # recordsテーブルが存在しない場合は作成
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS records (
                id INTEGER PRIMARY KEY,
                user_id INTEGER,
                action TEXT,
                timestamp DATETIME,
                memo TEXT,
                username TEXT,
                is_deleted INTEGER DEFAULT 0,
                likes_count INTEGER DEFAULT 0  -- likes_countカラムを追加
            )
        ''')

        # user_action_logsテーブルが存在しない場合は作成
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS user_action_logs (
                id INTEGER PRIMARY KEY,
                user_id INTEGER,
                action TEXT,
                timestamp DATETIME
            )
        ''')

        # likesテーブルが存在しない場合は作成
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS likes (
                id INTEGER PRIMARY KEY,
                user_id INTEGER,
                record_id INTEGER,
                timestamp DATETIME,
                FOREIGN KEY(user_id) REFERENCES users(id),
                FOREIGN KEY(record_id) REFERENCES records(id)
            )
        ''')

        # recordsテーブルにlikes_countカラムが存在しない場合は追加
        try:
            cursor.execute("ALTER TABLE records ADD COLUMN likes_count INTEGER DEFAULT 0")
            conn.commit()
            print("likes_count カラムが追加されました。")
        except sqlite3.OperationalError as e:
            if "duplicate column name" in str(e):
                print("likes_count カラムは既に存在します。")
            else:
                print(f"エラー: {e}")

        conn.commit()
        print("データベースの初期化が完了しました。")

    except sqlite3.Error as e:
        print(f"データベースエラー: {e}")
        conn.rollback()  # エラー発生時はロールバック
    finally:
        conn.close()

    # 管理者アカウントが存在しない場合のみ作成
    conn = get_db_connection()
    cursor = conn.cursor()
    try:
        admin_user = cursor.execute('SELECT * FROM users WHERE username = ?', ('ad',)).fetchone()
        if not admin_user:
            admin_password = hash_password('a')
            cursor.execute('INSERT INTO users (username, password, is_admin) VALUES (?, ?, ?)',
                           ('ad', admin_password, 1))
            conn.commit()
            print("管理者アカウントが作成されました。")
    except sqlite3.Error as e:
        print(f"データベースエラー: {e}")
        conn.rollback()  # エラー発生時はロールバック
    finally:
        conn.close()

# アプリケーションの起動前にデータベースを初期化
with app.app_context():
    init_db()

@app.route('/')
def index():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    with get_db_connection() as conn:
        records = conn.execute(
            'SELECT id, action, datetime(timestamp, "localtime") as timestamp, memo, likes_count FROM records WHERE user_id = ? AND is_deleted = 0 ORDER BY timestamp DESC',
            (session['user_id'],)
        ).fetchall()
        # タイムゾーンを考慮して表示
        for record in records:
            record = dict(record)
            record['timestamp'] = datetime.strptime(record['timestamp'], '%Y-%m-%d %H:%M:%S') + timedelta(hours=9)
    return render_template('index.html', records=records)

@app.route('/like//', methods=['POST'])
def like_record(record_id, from_page):
    if 'user_id' not in session:
        return redirect(url_for('login'))
    with get_db_connection() as conn:
        # 既に「いいね」されているか確認
        existing_like = conn.execute('''
            SELECT * FROM likes WHERE user_id = ? AND record_id = ?
        ''', (session['user_id'], record_id)).fetchone()
        if not existing_like:
            # いいねされていない場合は、新規に「いいね」を記録
            conn.execute('''
                INSERT INTO likes (user_id, record_id, timestamp)
                VALUES (?, ?, ?)
            ''', (session['user_id'], record_id, jst_now()))
            # recordsテーブルのlikes_countを増やす
            conn.execute('''
                UPDATE records SET likes_count = likes_count + 1 WHERE id = ?
            ''', (record_id,))
            conn.commit()
            flash('いいねしました！', 'success')
        else:
            flash('すでにいいねしています。', 'info')
    if from_page == 'index':
        return redirect(url_for('index'))
    elif from_page == 'all_records':
        return redirect(url_for('all_records'))
    else:
        return redirect(url_for('index'))  # デフォルトはindexへ

import calendar
from datetime import datetime

@app.route('/calendar')
def calendar_view():
    year = int(request.args.get('year', datetime.now().year))
    month = int(request.args.get('month', datetime.now().month))
    # カレンダーオブジェクトを作成
    cal = calendar.monthcalendar(year, month)
    # 前月と次月の計算
    prev_month = month - 1 if month > 1 else 12
    prev_year = year if month > 1 else year - 1
    next_month = month + 1 if month < 12 else 1
    next_year = year if month < 12 else year + 1
    # 前月と翌月のカレンダーを生成
    prev_cal = calendar.monthcalendar(prev_year, prev_month)
    next_cal = calendar.monthcalendar(next_year, next_month)
    today = datetime.now()
    return render_template('calendar.html', year=year, month=month, cal=cal,
                           prev_cal=prev_cal, prev_month=prev_month, prev_year=prev_year,
                           next_cal=next_cal, next_month=next_month, next_year=next_year,
                           today=today)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')
        if not username or not password:
            flash('ユーザー名とパスワードを入力してください。', 'error')
            return render_template('login.html')
        with get_db_connection() as conn:
            user = conn.execute('SELECT * FROM users WHERE username = ?', (username,)).fetchone()
            if user and 'password' in user.keys() and user['password'] == hash_password(password):
                session['user_id'] = user['id']
                session['username'] = user['username']
                session['is_admin'] = user['is_admin']
                # ログイン時にログを記録
                with get_db_connection() as conn:
                    conn.execute('INSERT INTO user_action_logs (user_id, action, timestamp) VALUES (?, ?, ?)',
                                 (user['id'], 'ログイン', jst_now().strftime('%Y-%m-%d %H:%M:%S')))
                    conn.commit()
                # 管理者なら管理画面へ
                return redirect(url_for('admin_dashboard' if user['is_admin'] else 'index'))
            else:
                flash('ユーザー名またはパスワードが間違っています。', 'error')
        return render_template('login.html')
    return render_template('login.html')

@app.route('/admin_dashboard')
@admin_required
def admin_dashboard():
    with get_db_connection() as conn:
        records = conn.execute('''
            SELECT
                users.username,
                records.action,
                datetime(records.timestamp, "localtime") as timestamp,
                records.memo,
                records.is_deleted
            FROM records
            JOIN users ON records.user_id = users.id
            ORDER BY records.timestamp DESC
        ''').fetchall()
        # タイムゾーンを考慮して表示
        for record in records:
            record = dict(record)
            record['timestamp'] = datetime.strptime(record['timestamp'], '%Y-%m-%d %H:%M:%S') + timedelta(hours=9)
        users = conn.execute('SELECT id, username FROM users WHERE is_admin = 0').fetchall()
        form = FlaskForm()  # CSRFトークン用の空のフォームを作成
    return render_template('admin_dashboard.html', records=records, users=users, all_records=records, form=form)

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')
        if not username or not password:
            flash('ユーザー名とパスワードを入力してください。', 'error')
            return render_template('register.html')
        with get_db_connection() as conn:
            existing_user = conn.execute(
                'SELECT * FROM users WHERE username = ?',
                (username,)
            ).fetchone()
            if existing_user:
                flash('このユーザー名は既に使用されています。', 'error')
                return render_template('register.html')
            try:
                conn.execute(
                    'INSERT INTO users (username, password) VALUES (?, ?)',
                    (username, hash_password(password))
                )
                conn.commit()
                flash('登録が完了しました。ログインしてください。', 'success')
                return redirect(url_for('login'))
            except sqlite3.IntegrityError:
                flash('登録中にエラーが発生しました。', 'error')
        return render_template('register.html')
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
def logout():
    user_id = session.get('user_id')
    session.clear()
    flash('ログアウトしました。', 'info')
    if user_id:
        with get_db_connection() as conn:
            conn.execute('INSERT INTO user_action_logs (user_id, action, timestamp) VALUES (?, ?, ?)',
                         (user_id, 'ログアウト', jst_now().strftime('%Y-%m-%d %H:%M:%S')))
            conn.commit()
    return redirect(url_for('login'))

@app.route('/record', methods=['POST'])
def record():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    action = request.form.get('action')
    memo = request.form.get('memo', '')
    if not action:
        flash('アクションを選択してください。', 'error')
        return redirect(url_for('index'))
    timestamp = jst_now()  # jst_now()でタイムゾーンawareなdatetimeオブジェクトを取得
    with get_db_connection() as conn:
        conn.execute(
            'INSERT INTO records (user_id, action, timestamp, memo, username) VALUES (?, ?, ?, ?, ?)',
            (session['user_id'], action, timestamp, memo, session['username'])
        )
        conn.commit()
        flash('記録が保存されました。', 'success')
        # アクションログを記録
        with get_db_connection() as conn:
            conn.execute(
                'INSERT INTO user_action_logs (user_id, action, timestamp) VALUES (?, ?, ?)',
                (session['user_id'], action, jst_now())
            )
            conn.commit()
    return redirect(url_for('index'))

@app.route('/day_records/<date>')
def day_records(date):
    # 関数の内容
    if 'user_id' not in session:
        return redirect(url_for('login'))
    is_admin = session.get('is_admin', False)
    conn = get_db_connection()
    cursor = conn.cursor()
    try:
        if is_admin:
            # 管理者の場合、全ての記録（削除されたものも含む）を取得
            cursor.execute('''
                SELECT action, timestamp, memo, username, is_deleted
                FROM records
                WHERE DATE(timestamp) = ?
                ORDER BY timestamp ASC
            ''', (date,))
        else:
            # 一般ユーザーの場合、自分の削除されていない記録のみを取得
            cursor.execute('''
                SELECT action, timestamp, memo, username
                FROM records
                WHERE user_id = ? AND DATE(timestamp) = ? AND is_deleted = 0
                ORDER BY timestamp ASC
            ''', (session['user_id'], date))
        records = cursor.fetchall()

        # タイムスタンプをdatetimeオブジェクトに変換
        records = [{
            'action': record['action'],
            'timestamp': datetime.fromisoformat(record['timestamp'].replace(' ', 'T')) + timedelta(hours=9), # 9時間足す
            'memo': record['memo'],
            'username': record['username'],
            'is_deleted': record['is_deleted'] if is_admin else 0
        } for record in records]
    except ValueError as ve:
        flash(f'日付形式が無効です: {ve}', 'error')
        records = []  # エラーが発生した場合、空のリストを返す
    except sqlite3.Error as e:
        flash(f'データベースエラーが発生しました: {e}', 'error')
        records = []  # エラーが発生した場合、空のリストを返す
    finally:
        conn.close()
    return render_template('day_records.html', date=date, records=records, is_admin=is_admin)

@app.route('/all_records')
def all_records():
    page = request.args.get('page', 1, type=int)
    per_page = 20
    offset = (page - 1) * per_page
    with get_db_connection() as conn:
        total_records = conn.execute('SELECT COUNT(*) FROM records WHERE is_deleted = 0').fetchone()[0]
        records = conn.execute('''
            SELECT users.username, records.id, records.action,
                   strftime('%Y/%m/%d %H:%M:%S', records.timestamp) as timestamp,
                   records.memo, records.likes_count
            FROM records
            JOIN users ON records.user_id = users.id
            WHERE records.is_deleted = 0
            ORDER BY records.timestamp DESC
            LIMIT ? OFFSET ?
        ''', (per_page, offset)).fetchall()
    # タイムゾーンを考慮して表示
    for record in records:
        record = dict(record)
        record['timestamp'] = datetime.strptime(record['timestamp'], '%Y-%m-%d %H:%M:%S') + timedelta(hours=9)
    total_pages = (total_records + per_page - 1) // per_page
    return render_template('all_records.html', records=records, page=page, total_pages=total_pages)

@app.route('/delete_record/<int:record_id>', methods=['POST'])
def delete_record(record_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))
    conn = get_db_connection()
    cursor = conn.cursor()
    try:
        # 記録を論理削除
        cursor.execute('''
            UPDATE records
            SET is_deleted = 1
            WHERE id = ? AND user_id = ?
        ''', (record_id, session['user_id']))
        conn.commit()
        flash('記録が削除されました。', 'success')
    except sqlite3.Error as e:
        conn.rollback()
        flash(f'記録の削除中にエラーが発生しました: {e}', 'error')
    finally:
        conn.close()
    return redirect(url_for('index'))

@app.route('/delete_user/<int:user_id>', methods=['POST'])
@admin_required
def delete_user(user_id):
    if user_id == session.get('user_id'):
        flash('自分自身を削除することはできません。', 'error')
        return redirect(url_for('admin_dashboard'))

    conn = get_db_connection()
    cursor = conn.cursor()

    try:
        # ユーザーの記録を削除
        cursor.execute('DELETE FROM records WHERE user_id = ?', (user_id,))

        # ユーザーを削除
        cursor.execute('DELETE FROM users WHERE id = ?', (user_id,))

        conn.commit()
        flash('ユーザーが削除されました。', 'success')

    except sqlite3.Error as e:
        conn.rollback()
        flash(f'ユーザー削除中にエラーが発生しました: {e}', 'error')

    finally:
        conn.close()

    return redirect(url_for('admin_dashboard'))

if __name__ == '__main__':
    # app.run(host='0.0.0.0', port=10000, ssl_context=('mycert.pem', 'key.pem'), debug=True)
    app.run(host='0.0.0.0', port=10000, debug=True)
