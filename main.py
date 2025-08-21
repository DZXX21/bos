from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify, send_file, abort
from werkzeug.security import check_password_hash, generate_password_hash
from werkzeug.utils import secure_filename
from datetime import datetime, timedelta
import sqlite3
import secrets
import re
import json
import logging
from functools import wraps
import os
import mimetypes
from pathlib import Path
import base64
import uuid

app = Flask(__name__)
app.secret_key = os.getenv("SECRET_KEY", secrets.token_hex(16))

# Dosya depolama dizini
STORAGE_PATH = 'db_files'
os.makedirs(STORAGE_PATH, exist_ok=True)

# Dosya upload ayarları
ALLOWED_EXTENSIONS = {'txt', 'pdf', 'png', 'jpg', 'jpeg', 'gif', 'doc', 'docx', 'xls', 'xlsx', 'pptx', 'zip', 'rar'}
MAX_FILE_SIZE = 16 * 1024 * 1024  # 16MB

# Logging yapılandırması
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# ---- DB yardımcıları ---------------------------------------------------------
DB_PATH = 'enterprise_system.db'

def get_conn():
    """Adlarla erişim için Row döndüren bağlantı."""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

# Veritabanı başlatma
def init_db():
    conn = get_conn()
    c = conn.cursor()
    
    # Kullanıcılar tablosu
    c.execute('''CREATE TABLE IF NOT EXISTS users
                 (id INTEGER PRIMARY KEY AUTOINCREMENT,
                  employee_id TEXT UNIQUE NOT NULL,
                  username TEXT UNIQUE NOT NULL,
                  email TEXT UNIQUE NOT NULL,
                  password_hash TEXT NOT NULL,
                  first_name TEXT NOT NULL,
                  last_name TEXT NOT NULL,
                  department TEXT NOT NULL,
                  role TEXT DEFAULT 'employee',
                  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                  last_login TIMESTAMP,
                  is_active INTEGER DEFAULT 1,
                  failed_attempts INTEGER DEFAULT 0,
                  locked_until TIMESTAMP)''')
    
    # Audit log tablosu
    c.execute('''CREATE TABLE IF NOT EXISTS audit_log
                 (id INTEGER PRIMARY KEY AUTOINCREMENT,
                  user_id INTEGER,
                  action TEXT NOT NULL,
                  ip_address TEXT,
                  user_agent TEXT,
                  timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                  details TEXT)''')
    
    # Departmanlar tablosu
    c.execute('''CREATE TABLE IF NOT EXISTS departments
                 (id INTEGER PRIMARY KEY AUTOINCREMENT,
                  name TEXT UNIQUE NOT NULL,
                  description TEXT,
                  manager_id INTEGER)''')
    
    # Görevler tablosu
    c.execute('''CREATE TABLE IF NOT EXISTS tasks
                 (id INTEGER PRIMARY KEY AUTOINCREMENT,
                  user_id INTEGER,
                  title TEXT NOT NULL,
                  description TEXT,
                  priority TEXT DEFAULT 'medium',
                  status TEXT DEFAULT 'pending',
                  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                  due_date TIMESTAMP,
                  completed_at TIMESTAMP)''')
    
    # Dosya kategorileri tablosu
    c.execute('''CREATE TABLE IF NOT EXISTS file_categories
                 (id INTEGER PRIMARY KEY AUTOINCREMENT,
                  name TEXT UNIQUE NOT NULL,
                  description TEXT,
                  access_level TEXT DEFAULT 'employee',
                  icon TEXT DEFAULT 'fa-folder',
                  color TEXT DEFAULT '#3B82F6')''')
    
    # Dosyalar tablosu - VERİTABANI TABANLI
    c.execute('''CREATE TABLE IF NOT EXISTS files
                 (id INTEGER PRIMARY KEY AUTOINCREMENT,
                  title TEXT NOT NULL,
                  filename TEXT NOT NULL,
                  file_path TEXT,
                  file_size INTEGER DEFAULT 0,
                  file_type TEXT NOT NULL,
                  mime_type TEXT,
                  content_preview TEXT,
                  category_id INTEGER,
                  department TEXT,
                  access_level TEXT DEFAULT 'employee',
                  is_active INTEGER DEFAULT 1,
                  version TEXT DEFAULT '1.0',
                  author TEXT,
                  description TEXT,
                  tags TEXT,
                  download_count INTEGER DEFAULT 0,
                  view_count INTEGER DEFAULT 0,
                  created_by INTEGER,
                  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                  updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                  FOREIGN KEY (category_id) REFERENCES file_categories (id),
                  FOREIGN KEY (created_by) REFERENCES users (id))''')
    
    # Dosya erişim log tablosu
    c.execute('''CREATE TABLE IF NOT EXISTS file_access_log
                 (id INTEGER PRIMARY KEY AUTOINCREMENT,
                  user_id INTEGER NOT NULL,
                  file_id INTEGER NOT NULL,
                  action TEXT NOT NULL,
                  ip_address TEXT,
                  timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                  FOREIGN KEY (user_id) REFERENCES users (id),
                  FOREIGN KEY (file_id) REFERENCES files (id))''')
    
    conn.commit()
    conn.close()

# ---- Dosya yardımcı fonksiyonları --------------------------------------------
def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def get_file_icon(file_type):
    """Dosya tipine göre ikon döndürür"""
    icons = {
        'pdf': 'fa-file-pdf',
        'doc': 'fa-file-word', 'docx': 'fa-file-word',
        'xls': 'fa-file-excel', 'xlsx': 'fa-file-excel',
        'pptx': 'fa-file-powerpoint',
        'txt': 'fa-file-text',
        'png': 'fa-file-image', 'jpg': 'fa-file-image', 'jpeg': 'fa-file-image', 'gif': 'fa-file-image',
        'zip': 'fa-file-archive', 'rar': 'fa-file-archive',
        'mp4': 'fa-file-video', 'avi': 'fa-file-video',
        'mp3': 'fa-file-audio', 'wav': 'fa-file-audio'
    }
    return icons.get(file_type.lower(), 'fa-file')

def format_file_size(size_bytes):
    """Dosya boyutunu okunaklı formatta döndürür"""
    if size_bytes == 0:
        return "0B"
    size_names = ["B", "KB", "MB", "GB"]
    i = 0
    while size_bytes >= 1024 and i < len(size_names) - 1:
        size_bytes /= 1024.0
        i += 1
    return f"{size_bytes:.1f}{size_names[i]}"

def can_access_file(file_data, user_role, user_dept):
    """Kullanıcının dosyaya erişip erişemeyeceğini kontrol eder"""
    access_level = file_data.get('access_level', 'employee')
    file_dept = file_data.get('department')
    
    # Admin her şeye erişebilir
    if user_role == 'admin':
        return True
    
    # Access level kontrolü
    if access_level == 'admin' and user_role != 'admin':
        return False
    
    if access_level == 'manager' and user_role not in ['admin', 'manager']:
        return False
    
    # Departman kontrolü (eğer dosya belirli departmana aitsa)
    if file_dept and file_dept != user_dept and access_level not in ['public', 'employee']:
        return False
    
    return True

# ---- Dosya DB işlemleri ------------------------------------------------------
def get_file_categories():
    """Tüm dosya kategorilerini getirir"""
    conn = get_conn()
    c = conn.cursor()
    c.execute("SELECT * FROM file_categories ORDER BY name")
    categories = [dict(r) for r in c.fetchall()]
    conn.close()
    return categories

def get_files_by_category(category_id=None, user_role='employee', user_dept=None):
    """Kategoriye göre dosyaları getirir"""
    conn = get_conn()
    c = conn.cursor()
    
    if category_id:
        c.execute("""SELECT f.*, fc.name as category_name, fc.icon as category_icon, 
                            u.first_name, u.last_name
                     FROM files f 
                     LEFT JOIN file_categories fc ON f.category_id = fc.id
                     LEFT JOIN users u ON f.created_by = u.id
                     WHERE f.category_id = ? AND f.is_active = 1
                     ORDER BY f.created_at DESC""", (category_id,))
    else:
        c.execute("""SELECT f.*, fc.name as category_name, fc.icon as category_icon,
                            u.first_name, u.last_name
                     FROM files f 
                     LEFT JOIN file_categories fc ON f.category_id = fc.id
                     LEFT JOIN users u ON f.created_by = u.id
                     WHERE f.is_active = 1
                     ORDER BY f.created_at DESC""")
    
    all_files = [dict(r) for r in c.fetchall()]
    conn.close()
    
    # Erişim kontrolü uygula
    accessible_files = []
    for file_data in all_files:
        if can_access_file(file_data, user_role, user_dept):
            accessible_files.append(file_data)
    
    return accessible_files

def get_file_by_id(file_id):
    """ID'ye göre dosya getirir"""
    conn = get_conn()
    c = conn.cursor()
    c.execute("""SELECT f.*, fc.name as category_name, fc.icon as category_icon,
                        u.first_name, u.last_name
                 FROM files f 
                 LEFT JOIN file_categories fc ON f.category_id = fc.id
                 LEFT JOIN users u ON f.created_by = u.id
                 WHERE f.id = ? AND f.is_active = 1""", (file_id,))
    file_data = c.fetchone()
    conn.close()
    return dict(file_data) if file_data else None

def search_files(query, user_role='employee', user_dept=None):
    """Dosyalarda arama yapar"""
    conn = get_conn()
    c = conn.cursor()
    c.execute("""SELECT f.*, fc.name as category_name, fc.icon as category_icon,
                        u.first_name, u.last_name
                 FROM files f 
                 LEFT JOIN file_categories fc ON f.category_id = fc.id
                 LEFT JOIN users u ON f.created_by = u.id
                 WHERE f.is_active = 1 AND (
                     f.title LIKE ? OR 
                     f.description LIKE ? OR 
                     f.tags LIKE ? OR
                     f.filename LIKE ?
                 )
                 ORDER BY f.created_at DESC""", 
                 (f'%{query}%', f'%{query}%', f'%{query}%', f'%{query}%'))
    
    all_files = [dict(r) for r in c.fetchall()]
    conn.close()
    
    # Erişim kontrolü uygula
    accessible_files = []
    for file_data in all_files:
        if can_access_file(file_data, user_role, user_dept):
            accessible_files.append(file_data)
    
    return accessible_files

def increment_file_counter(file_id, counter_type='view'):
    """Dosya sayaçlarını artırır (view/download)"""
    conn = get_conn()
    c = conn.cursor()
    
    if counter_type == 'view':
        c.execute("UPDATE files SET view_count = view_count + 1 WHERE id = ?", (file_id,))
    elif counter_type == 'download':
        c.execute("UPDATE files SET download_count = download_count + 1 WHERE id = ?", (file_id,))
    
    conn.commit()
    conn.close()

def log_file_access(user_id, file_id, action, ip_address):
    """Dosya erişimini loglar"""
    conn = get_conn()
    c = conn.cursor()
    c.execute("""INSERT INTO file_access_log (user_id, file_id, action, ip_address) 
                 VALUES (?, ?, ?, ?)""",
             (user_id, file_id, action, ip_address))
    conn.commit()
    conn.close()

# ---- Kullanıcı işlemleri ----------------------------------------------------
def get_user(identifier):
    """username, email veya employee_id ile kullanıcı getirir."""
    conn = get_conn()
    c = conn.cursor()
    c.execute("""
        SELECT u.*, d.name AS department_name
        FROM users u
        LEFT JOIN departments d ON u.department = d.name
        WHERE u.username = ? OR u.email = ? OR u.employee_id = ?
    """, (identifier, identifier, identifier))
    user = c.fetchone()
    conn.close()
    return user

def get_user_by_id(user_id):
    conn = get_conn()
    c = conn.cursor()
    c.execute("""
        SELECT u.*, d.name AS department_name
        FROM users u
        LEFT JOIN departments d ON u.department = d.name
        WHERE u.id = ?
    """, (user_id,))
    user = c.fetchone()
    conn.close()
    return user

def create_user(employee_id, username, email, password, first_name, last_name, department, role='employee'):
    conn = get_conn()
    c = conn.cursor()
    try:
        password_hash = generate_password_hash(password)
        c.execute("""INSERT INTO users 
                     (employee_id, username, email, password_hash, first_name, last_name, department, role) 
                     VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
                 (employee_id, username, email, password_hash, first_name, last_name, department, role))
        conn.commit()
        logger.info(f"New user created: {username} ({employee_id})")
        return True
    except sqlite3.IntegrityError as e:
        logger.warning(f"User creation failed: {e}")
        return False
    finally:
        conn.close()

def log_audit(user_id, action, ip_address, user_agent, details=None):
    conn = get_conn()
    c = conn.cursor()
    c.execute("""INSERT INTO audit_log (user_id, action, ip_address, user_agent, details) 
                 VALUES (?, ?, ?, ?, ?)""",
             (user_id, action, ip_address, user_agent, details))
    conn.commit()
    conn.close()

def update_last_login(user_id):
    conn = get_conn()
    c = conn.cursor()
    c.execute("UPDATE users SET last_login = CURRENT_TIMESTAMP WHERE id = ?", (user_id,))
    conn.commit()
    conn.close()

def get_user_stats(user_id):
    conn = get_conn()
    c = conn.cursor()
    
    # Görev istatistikleri
    c.execute("SELECT COUNT(*) AS cnt FROM tasks WHERE user_id = ? AND status = 'completed'", (user_id,))
    completed_tasks = c.fetchone()["cnt"]
    
    c.execute("SELECT COUNT(*) AS cnt FROM tasks WHERE user_id = ? AND status = 'pending'", (user_id,))
    pending_tasks = c.fetchone()["cnt"]
    
    c.execute("SELECT COUNT(*) AS cnt FROM tasks WHERE user_id = ?", (user_id,))
    total_tasks = c.fetchone()["cnt"]
    
    # Dosya erişim istatistikleri
    c.execute("SELECT COUNT(*) AS cnt FROM file_access_log WHERE user_id = ? AND action = 'DOWNLOAD'", (user_id,))
    downloaded_files = c.fetchone()["cnt"]
    
    c.execute("SELECT COUNT(*) AS cnt FROM file_access_log WHERE user_id = ? AND action = 'VIEW'", (user_id,))
    viewed_files = c.fetchone()["cnt"]
    
    # Bu hafta ki aktivite
    c.execute("""SELECT COUNT(*) AS cnt FROM audit_log 
                 WHERE user_id = ? AND action = 'LOGIN_SUCCESS' 
                 AND timestamp >= date('now', '-6 days')""", (user_id,))
    week_logins = c.fetchone()["cnt"]
    
    conn.close()
    
    completion_rate = round((completed_tasks / total_tasks * 100) if total_tasks > 0 else 0, 1)
    return {
        'completed_tasks': completed_tasks,
        'pending_tasks': pending_tasks,
        'total_tasks': total_tasks,
        'downloaded_files': downloaded_files,
        'viewed_files': viewed_files,
        'week_logins': week_logins,
        'completion_rate': completion_rate
    }

def get_recent_activities(user_id, limit=5):
    conn = get_conn()
    c = conn.cursor()
    c.execute("""SELECT action, timestamp, details FROM audit_log 
                 WHERE user_id = ? ORDER BY timestamp DESC LIMIT ?""", (user_id, limit))
    activities = [dict(action=r["action"], timestamp=r["timestamp"], details=r["details"]) for r in c.fetchall()]
    conn.close()
    return activities

def get_user_tasks(user_id, limit=10):
    conn = get_conn()
    c = conn.cursor()
    c.execute("""SELECT title, priority, status, due_date FROM tasks 
                 WHERE user_id = ? ORDER BY 
                 CASE priority WHEN 'high' THEN 1 WHEN 'medium' THEN 2 ELSE 3 END,
                 created_at DESC LIMIT ?""", (user_id, limit))
    rows = c.fetchall()
    tasks = [dict(title=r["title"], priority=r["priority"], status=r["status"], due_date=r["due_date"]) for r in rows]
    conn.close()
    return tasks

# ---- Hesap kilitleme işlemleri ----------------------------------------------
LOCK_THRESHOLD = 5
LOCK_MINUTES = 15

def increment_failed_attempts(user_id, lock_threshold=LOCK_THRESHOLD, lock_minutes=LOCK_MINUTES):
    conn = get_conn()
    c = conn.cursor()
    c.execute("SELECT failed_attempts FROM users WHERE id = ?", (user_id,))
    row = c.fetchone()
    attempts = (row["failed_attempts"] or 0) + 1

    locked_until = None
    if attempts >= lock_threshold:
        locked_until_dt = datetime.utcnow() + timedelta(minutes=lock_minutes)
        locked_until = locked_until_dt.isoformat(sep=' ', timespec='seconds')
        c.execute("UPDATE users SET failed_attempts = ?, locked_until = ? WHERE id = ?", (attempts, locked_until, user_id))
    else:
        c.execute("UPDATE users SET failed_attempts = ? WHERE id = ?", (attempts, user_id))

    conn.commit()
    conn.close()
    return attempts, locked_until

def reset_failed_attempts(user_id):
    conn = get_conn()
    c = conn.cursor()
    c.execute("UPDATE users SET failed_attempts = 0, locked_until = NULL WHERE id = ?", (user_id,))
    conn.commit()
    conn.close()

def is_account_locked(user):
    """locked_until geçmişte mi? aktif kilit var mı?"""
    lu = user["locked_until"]
    if not lu:
        return False, None
    try:
        locked_until_dt = datetime.fromisoformat(str(lu))
    except ValueError:
        return False, None
    now_utc = datetime.utcnow()
    if locked_until_dt > now_utc:
        remaining = locked_until_dt - now_utc
        remaining_minutes = int(remaining.total_seconds() // 60) + (1 if remaining.total_seconds() % 60 else 0)
        return True, remaining_minutes
    return False, None

# ---- Decorators -------------------------------------------------------------
def require_login(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

def require_role(role):
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if 'user_role' not in session or session['user_role'] != role:
                flash('Bu sayfaya erişim yetkiniz bulunmamaktadır.', 'error')
                return redirect(url_for('dashboard'))
            return f(*args, **kwargs)
        return decorated_function
    return decorator

# ---- Routes ------------------------------------------------------------------
@app.route('/')
@require_login
def dashboard():
    user = get_user(session['username'])
    if not user:
        session.clear()
        return redirect(url_for('login'))
    
    stats = get_user_stats(user["id"])
    recent_activities = get_recent_activities(user["id"])
    user_tasks = get_user_tasks(user["id"])
    
    # Son dosyalar
    recent_files = get_files_by_category(None, user["role"], user["department"])[:5]
    
    return render_template('dashboard.html', 
                           user=user, 
                           stats=stats, 
                           activities=recent_activities, 
                           tasks=user_tasks,
                           recent_files=recent_files,
                           format_file_size=format_file_size,
                           get_file_icon=get_file_icon)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
    
    if request.method == 'POST':
        identifier = request.form.get('identifier', '').strip()
        password = request.form.get('password', '')
        ip_address = request.remote_addr
        user_agent = request.headers.get('User-Agent', '')
        
        user = get_user(identifier)

        if not user:
            log_audit(None, 'LOGIN_FAILED', ip_address, user_agent, f"Unknown user: {identifier}")
            flash('Geçersiz kimlik bilgileri. Lütfen tekrar deneyin.', 'error')
            return render_template('login.html')

        locked, remaining_minutes = is_account_locked(user)
        if locked:
            log_audit(user["id"], 'LOGIN_LOCKED', ip_address, user_agent, f"Locked; {remaining_minutes} dk kaldı")
            flash(f'Hesabınız geçici olarak kilitlendi. {remaining_minutes} dakika sonra tekrar deneyin.', 'error')
            return render_template('login.html')

        if user["is_active"] != 1:
            log_audit(user["id"], 'LOGIN_FAILED', ip_address, user_agent, "Inactive account")
            flash('Hesabınız pasif. Lütfen yöneticiye başvurun.', 'error')
            return render_template('login.html')

        if check_password_hash(user["password_hash"], password):
            session['user_id'] = user["id"]
            session['username'] = user["username"]
            session['user_role'] = user["role"]
            session['full_name'] = f"{user['first_name']} {user['last_name']}"
            session['department'] = user["department"]
            
            reset_failed_attempts(user["id"])
            update_last_login(user["id"])
            log_audit(user["id"], 'LOGIN_SUCCESS', ip_address, user_agent)
            
            logger.info(f"Successful login: {user['username']} from {ip_address}")
            flash(f'Hoş geldiniz, {user["first_name"]} {user["last_name"]}!', 'success')
            return redirect(url_for('dashboard'))
        else:
            attempts, locked_until = increment_failed_attempts(user["id"])
            detail = f"Failed login attempt {attempts} for: {identifier}"
            if locked_until:
                detail += f" | locked_until={locked_until}"
            log_audit(user["id"], 'LOGIN_FAILED', ip_address, user_agent, detail)
            logger.warning(f"Failed login attempt: {identifier} from {ip_address} ({attempts})")
            if locked_until:
                flash('Çok fazla hatalı deneme. Hesabınız 15 dakika kilitlendi.', 'error')
            else:
                remaining = max(0, LOCK_THRESHOLD - attempts)
                flash(f'Geçersiz kimlik bilgileri. Kalan deneme hakkı: {remaining}', 'error')
    
    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        employee_id = request.form['employee_id'].strip()
        username = request.form['username'].strip()
        email = request.form['email'].strip()
        password = request.form['password']
        first_name = request.form['first_name'].strip()
        last_name = request.form['last_name'].strip()
        department = request.form['department']
        
        if len(username) < 3:
            flash('Kullanıcı adı en az 3 karakter olmalıdır!', 'error')
        elif not re.match(r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$', email):
            flash('Geçerli bir e-posta adresi girin!', 'error')
        elif len(password) < 8:
            flash('Şifre en az 8 karakter olmalıdır!', 'error')
        elif create_user(employee_id, username, email, password, first_name, last_name, department):
            flash('Hesabınız başarıyla oluşturuldu! Giriş yapabilirsiniz.', 'success')
            return redirect(url_for('login'))
        else:
            flash('Bu kullanıcı adı veya e-posta zaten kullanılıyor!', 'error')
    
    return render_template('register.html')

# ---- DOSYA YÖNETİMİ ROUTES --------------------------------------------------
@app.route('/files')
@require_login
def files():
    user = get_user_by_id(session['user_id'])
    if not user:
        return redirect(url_for('login'))
    
    # Arama parametresi
    search_query = request.args.get('search', '').strip()
    category_id = request.args.get('category', '')
    
    if search_query:
        files_list = search_files(search_query, user["role"], user["department"])
    elif category_id:
        files_list = get_files_by_category(int(category_id), user["role"], user["department"])
    else:
        files_list = get_files_by_category(None, user["role"], user["department"])
    
    # Kategorileri getir
    categories = get_file_categories()
    
    return render_template('files.html', 
                           files=files_list, 
                           categories=categories,
                           user=user,
                           search_query=search_query,
                           selected_category=category_id,
                           format_file_size=format_file_size,
                           get_file_icon=get_file_icon)

@app.route('/file/<int:file_id>')
@require_login
def file_detail(file_id):
    user = get_user_by_id(session['user_id'])
    if not user:
        return redirect(url_for('login'))
    
    file_data = get_file_by_id(file_id)
    if not file_data:
        flash('Dosya bulunamadı!', 'error')
        return redirect(url_for('files'))
    
    # Erişim kontrolü
    if not can_access_file(file_data, user["role"], user["department"]):
        flash('Bu dosyaya erişim yetkiniz bulunmamaktadır.', 'error')
        return redirect(url_for('files'))
    
    return render_template('file_detail.html', 
                           file=file_data,
                           user=user,
                           format_file_size=format_file_size,
                           get_file_icon=get_file_icon)

@app.route('/download/<int:file_id>')
@require_login
def download_file(file_id):
    user = get_user_by_id(session['user_id'])
    if not user:
        return redirect(url_for('login'))
    
    file_data = get_file_by_id(file_id)
    if not file_data:
        flash('Dosya bulunamadı!', 'error')
        return redirect(url_for('files'))
    
    # Erişim kontrolü
    if not can_access_file(file_data, user["role"], user["department"]):
        flash('Bu dosyaya erişim yetkiniz bulunmamaktadır.', 'error')
        return redirect(url_for('files'))
    
    # Fiziksel dosya var mı kontrol et
    file_path = file_data.get('file_path')
    if file_path and os.path.exists(file_path):
        # Sayaçları artır ve logla
        increment_file_counter(file_id, 'download')
        log_file_access(session['user_id'], file_id, 'DOWNLOAD', request.remote_addr)
        log_audit(session['user_id'], 'FILE_DOWNLOAD', request.remote_addr,
                 request.headers.get('User-Agent'), f"Downloaded: {file_data['title']}")
        
        return send_file(file_path, as_attachment=True, download_name=file_data['filename'])
    else:
        flash('Dosya fiziksel olarak bulunamadı!', 'error')
        return redirect(url_for('files'))

@app.route('/view/<int:file_id>')
@require_login
def view_file(file_id):
    user = get_user_by_id(session['user_id'])
    if not user:
        return redirect(url_for('login'))
    
    file_data = get_file_by_id(file_id)
    if not file_data:
        flash('Dosya bulunamadı!', 'error')
        return redirect(url_for('files'))
    
    # Erişim kontrolü
    if not can_access_file(file_data, user["role"], user["department"]):
        flash('Bu dosyaya erişim yetkiniz bulunmamaktadır.', 'error')
        return redirect(url_for('files'))
    
    # Görüntülenebilir dosya türü kontrolü
    file_type = file_data['file_type'].lower()
    if file_type not in ['pdf', 'png', 'jpg', 'jpeg', 'gif', 'txt']:
        return redirect(url_for('download_file', file_id=file_id))
    
    # Fiziksel dosya var mı kontrol et
    file_path = file_data.get('file_path')
    if file_path and os.path.exists(file_path):
        # Sayaçları artır ve logla
        increment_file_counter(file_id, 'view')
        log_file_access(session['user_id'], file_id, 'VIEW', request.remote_addr)
        log_audit(session['user_id'], 'FILE_VIEW', request.remote_addr,
                 request.headers.get('User-Agent'), f"Viewed: {file_data['title']}")
        
        return send_file(file_path, as_attachment=False, mimetype=file_data['mime_type'])
    else:
        flash('Dosya fiziksel olarak bulunamadı!', 'error')
        return redirect(url_for('files'))

# ---- DOSYA UPLOAD ROUTES ----------------------------------------------------
@app.route('/admin/upload', methods=['GET', 'POST'])
@require_login
@require_role('admin')
def admin_upload():
    if request.method == 'POST':
        # Form verilerini al
        title = request.form.get('title', '').strip()
        description = request.form.get('description', '').strip()
        category_id = request.form.get('category_id')
        access_level = request.form.get('access_level', 'employee')
        department = request.form.get('department', '')
        tags = request.form.get('tags', '').strip()
        author = request.form.get('author', '').strip()
        
        # Dosya kontrolü
        if 'file' not in request.files:
            flash('Dosya seçilmedi!', 'error')
            return redirect(request.url)
        
        file = request.files['file']
        if file.filename == '':
            flash('Dosya seçilmedi!', 'error')
            return redirect(request.url)
        
        if not allowed_file(file.filename):
            flash('Bu dosya türü desteklenmiyor!', 'error')
            return redirect(request.url)
        
        # Dosya boyutu kontrolü
        file.seek(0, os.SEEK_END)
        file_size = file.tell()
        file.seek(0)
        
        if file_size > MAX_FILE_SIZE:
            flash(f'Dosya boyutu çok büyük! Maksimum {format_file_size(MAX_FILE_SIZE)} olmalıdır.', 'error')
            return redirect(request.url)
        
        if not title:
            title = file.filename
        
        try:
            # Güvenli dosya adı
            filename = secure_filename(file.filename)
            file_extension = filename.rsplit('.', 1)[1].lower()
            
            # Benzersiz dosya adı oluştur
            unique_filename = f"{uuid.uuid4().hex}.{file_extension}"
            file_path = os.path.join(STORAGE_PATH, unique_filename)
            
            # Dosyayı kaydet
            file.save(file_path)
            
            # Dosya bilgilerini al
            mime_type = mimetypes.guess_type(file_path)[0] or 'application/octet-stream'
            
            # Veritabanına kaydet
            conn = get_conn()
            c = conn.cursor()
            c.execute("""INSERT INTO files 
                         (title, filename, file_path, file_size, file_type, mime_type,
                          category_id, department, access_level, author, description, tags, created_by) 
                         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                     (title, filename, file_path, file_size, file_extension, mime_type,
                      category_id if category_id else None, department, access_level, 
                      author, description, tags, session['user_id']))
            
            conn.commit()
            conn.close()
            
            # Audit log
            log_audit(session['user_id'], 'FILE_UPLOAD', request.remote_addr,
                     request.headers.get('User-Agent'), f"Uploaded: {title}")
            
            flash(f'Dosya "{title}" başarıyla yüklendi!', 'success')
            return redirect(url_for('files'))
            
        except Exception as e:
            # Hata durumunda dosyayı sil
            if 'file_path' in locals() and os.path.exists(file_path):
                os.remove(file_path)
            flash(f'Dosya yüklenirken hata oluştu: {str(e)}', 'error')
            logger.error(f"File upload error: {e}")
    
    # GET request - upload formunu göster
    categories = get_file_categories()
    departments = ['Bilgi İşlem', 'İnsan Kaynakları', 'Muhasebe', 'Satış', 'Pazarlama']
    
    return render_template('admin_upload.html', categories=categories, departments=departments)

# Dosya silme route'u
@app.route('/admin/delete-file/<int:file_id>', methods=['POST'])
@require_login
@require_role('admin')
def delete_file(file_id):
    try:
        file_data = get_file_by_id(file_id)
        if not file_data:
            flash('Dosya bulunamadı!', 'error')
            return redirect(url_for('files'))
        
        # Fiziksel dosyayı sil
        if file_data['file_path'] and os.path.exists(file_data['file_path']):
            os.remove(file_data['file_path'])
        
        # Veritabanından sil (soft delete)
        conn = get_conn()
        c = conn.cursor()
        c.execute("UPDATE files SET is_active = 0 WHERE id = ?", (file_id,))
        conn.commit()
        conn.close()
        
        log_audit(session['user_id'], 'FILE_DELETE', request.remote_addr,
                 request.headers.get('User-Agent'), f"Deleted: {file_data['title']}")
        
        flash(f'Dosya "{file_data["title"]}" silindi!', 'success')
        
    except Exception as e:
        flash(f'Dosya silinirken hata oluştu: {str(e)}', 'error')
        logger.error(f"File delete error: {e}")
    
    return redirect(url_for('files'))

@app.route('/profile')
@require_login
def profile():
    user = get_user(session['username'])
    if not user:
        return redirect(url_for('login'))
    
    stats = get_user_stats(user["id"])
    return render_template('profile.html', user=user, stats=stats)

@app.route('/logout')
@require_login
def logout():
    user_id = session.get('user_id')
    ip_address = request.remote_addr
    user_agent = request.headers.get('User-Agent', '')
    
    if user_id:
        log_audit(user_id, 'LOGOUT', ip_address, user_agent)
        logger.info(f"User logout: {session.get('username')} from {ip_address}")
    
    session.clear()
    flash('Güvenli çıkış yapıldı. İyi günler!', 'info')
    return redirect(url_for('login'))

@app.route('/admin')
@require_login
@require_role('admin')
def admin_panel():
    conn = get_conn()
    c = conn.cursor()
    
    # İstatistikler
    c.execute("SELECT COUNT(*) AS cnt FROM users WHERE is_active = 1")
    active_users = c.fetchone()["cnt"]
    
    c.execute("SELECT COUNT(*) AS cnt FROM audit_log WHERE action = 'LOGIN_SUCCESS' AND DATE(timestamp) = DATE('now')")
    today_logins = c.fetchone()["cnt"]
    
    c.execute("SELECT COUNT(*) AS cnt FROM audit_log WHERE action = 'LOGIN_FAILED' AND DATE(timestamp) = DATE('now')")
    failed_attempts = c.fetchone()["cnt"]
    
    c.execute("SELECT COUNT(*) AS cnt FROM files WHERE is_active = 1")
    total_files = c.fetchone()["cnt"]
    
    c.execute("SELECT COALESCE(SUM(download_count), 0) AS total_downloads FROM files")
    total_downloads = c.fetchone()["total_downloads"]
    
    c.execute("SELECT COALESCE(SUM(view_count), 0) AS total_views FROM files")
    total_views = c.fetchone()["total_views"]
    
    # En popüler dosyalar
    c.execute("""SELECT f.title, f.download_count, f.view_count, fc.name as category_name
                 FROM files f 
                 LEFT JOIN file_categories fc ON f.category_id = fc.id
                 WHERE f.is_active = 1
                 ORDER BY (f.download_count + f.view_count) DESC LIMIT 10""")
    popular_files = [dict(r) for r in c.fetchall()]
    
    # Son dosya erişimleri
    c.execute("""SELECT f.title, fa.action, u.first_name, u.last_name, fa.timestamp
                 FROM file_access_log fa
                 JOIN files f ON fa.file_id = f.id
                 JOIN users u ON fa.user_id = u.id
                 ORDER BY fa.timestamp DESC LIMIT 10""")
    recent_access = [dict(r) for r in c.fetchall()]
    
    conn.close()
    
    stats = {
        'active_users': active_users,
        'today_logins': today_logins,
        'failed_attempts': failed_attempts,
        'total_files': total_files,
        'total_downloads': total_downloads,
        'total_views': total_views
    }
    
    return render_template('admin.html', 
                           stats=stats, 
                           popular_files=popular_files,
                           recent_access=recent_access)

# ---- API Endpoints -----------------------------------------------------------
@app.route('/api/stats')
@require_login
def api_stats():
    user_id = session['user_id']
    stats = get_user_stats(user_id)
    return jsonify(stats)

@app.route('/api/files')
@require_login
def api_files():
    user = get_user_by_id(session['user_id'])
    files = get_files_by_category(None, user["role"], user["department"])
    
    file_list = []
    for file_data in files:
        file_list.append({
            'id': file_data['id'],
            'title': file_data['title'],
            'filename': file_data['filename'],
            'file_type': file_data['file_type'],
            'file_size': format_file_size(file_data['file_size']),
            'category': file_data.get('category_name', 'Uncategorized'),
            'author': file_data.get('author', 'Unknown'),
            'created_at': file_data['created_at'],
            'download_count': file_data['download_count'],
            'view_count': file_data['view_count'],
            'description': file_data.get('description', ''),
            'icon': get_file_icon(file_data['file_type'])
        })
    
    return jsonify(file_list)

@app.route('/api/categories')
@require_login
def api_categories():
    categories = get_file_categories()
    return jsonify(categories)

@app.route('/api/search')
@require_login
def api_search():
    query = request.args.get('q', '').strip()
    if not query:
        return jsonify([])
    
    user = get_user_by_id(session['user_id'])
    results = search_files(query, user["role"], user["department"])
    
    search_results = []
    for file_data in results:
        search_results.append({
            'id': file_data['id'],
            'title': file_data['title'],
            'filename': file_data['filename'],
            'category': file_data.get('category_name', 'Uncategorized'),
            'description': file_data.get('description', ''),
            'file_type': file_data['file_type'],
            'icon': get_file_icon(file_data['file_type'])
        })
    
    return jsonify(search_results)

# ---- Demo verileri -----------------------------------------------------------
def add_demo_data():
    conn = get_conn()
    c = conn.cursor()
    
    # Departmanlar
    departments = [
        ('Bilgi İşlem', 'IT ve sistem yönetimi'),
        ('İnsan Kaynakları', 'Personel ve bordro işlemleri'),
        ('Muhasebe', 'Mali işler ve raporlama'),
        ('Satış', 'Satış ve müşteri ilişkileri'),
        ('Pazarlama', 'Marka ve dijital pazarlama')
    ]
    
    for dept in departments:
        try:
            c.execute("INSERT INTO departments (name, description) VALUES (?, ?)", dept)
        except sqlite3.IntegrityError:
            pass
    
    # Dosya kategorileri
    categories = [
        ('Politikalar', 'Şirket politikaları ve prosedürler', 'employee', 'fa-shield-alt', '#10B981'),
        ('Raporlar', 'Mali ve operasyonel raporlar', 'manager', 'fa-chart-bar', '#3B82F6'),
        ('Şablonlar', 'Belge şablonları ve formlar', 'employee', 'fa-file-contract', '#8B5CF6'),
        ('Eğitim', 'Eğitim materyalleri ve dokümantasyon', 'employee', 'fa-graduation-cap', '#F59E0B'),
        ('İK Dokümanları', 'İnsan kaynakları belgeleri', 'manager', 'fa-users', '#EF4444'),
        ('Teknik Belgeler', 'Sistem dokümantasyonu', 'admin', 'fa-cogs', '#6B7280')
    ]
    
    for cat in categories:
        try:
            c.execute("INSERT INTO file_categories (name, description, access_level, icon, color) VALUES (?, ?, ?, ?, ?)", cat)
        except sqlite3.IntegrityError:
            pass
    
    conn.commit()
    conn.close()

    # Demo kullanıcıları
    demo_users = [
        ('ADM001', 'admin', 'admin@techcorp.com', 'Admin123!', 'Ahmet', 'Yönetici', 'Bilgi İşlem', 'admin'),
        ('EMP001', 'manager1', 'manager@techcorp.com', 'Manager123!', 'Ayşe', 'Şahin', 'İnsan Kaynakları', 'manager'),
        ('EMP002', 'john.doe', 'john@techcorp.com', 'Employee123!', 'John', 'Doe', 'Satış', 'employee'),
        ('EMP003', 'jane.smith', 'jane@techcorp.com', 'Employee123!', 'Jane', 'Smith', 'Pazarlama', 'employee'),
        ('EMP004', 'mehmet.ak', 'mehmet@techcorp.com', 'Employee123!', 'Mehmet', 'Ak', 'Muhasebe', 'employee')
    ]
    
    for user_data in demo_users:
        try:
            create_user(*user_data)
        except Exception as e:
            logger.debug(f"Demo user create skipped: {e}")
    
    # Demo görevler
    conn = get_conn()
    c = conn.cursor()
    demo_tasks = [
        (3, 'API dokumentasyonu güncelle', 'REST API için güncelleme', 'high', 'completed'),
        (3, 'Bug fix: Login form validation', 'Form validasyon hatası düzelt', 'medium', 'pending'),
        (3, 'Sprint meeting katıl', 'Haftalık sprint toplantısı', 'high', 'pending'),
        (4, 'Pazarlama kampanyası hazırla', 'Yeni ürün lansmanı için kampanya', 'high', 'pending'),
        (5, 'Mali rapor hazırla', 'Aylık finansal rapor', 'high', 'pending')
    ]
    
    for task_data in demo_tasks:
        try:
            c.execute("""INSERT INTO tasks (user_id, title, description, priority, status) 
                         VALUES (?, ?, ?, ?, ?)""", task_data)
        except Exception as e:
            logger.debug(f"Demo task insert skipped: {e}")
    
    # Demo dosyalar - VERİTABANI TABANLI (Metadata only)
    demo_files = [
        # Politikalar (Herkes erişebilir)
        ('Şirket Politikaları', 'company_policy.pdf', None, 2547832, 'pdf', 'application/pdf', 
         'TechCorp şirket politikaları ve kuralları', 1, 'Bilgi İşlem', 'employee', 1, '1.0', 
         'TechCorp İK', 'Şirket çalışanlarının uyması gereken temel politikalar', 'politika,kurallar,şirket', 15, 45, 1),
        
        ('Güvenlik Kuralları', 'security_guidelines.pdf', None, 1876543, 'pdf', 'application/pdf',
         'Bilgi güvenliği kuralları ve prosedürleri', 1, 'Bilgi İşlem', 'employee', 1, '2.1',
         'Güvenlik Ekibi', 'Çalışanlar için güvenlik rehberi', 'güvenlik,siber,koruma', 8, 32, 1),
         
        ('Çalışan El Kitabı', 'employee_handbook.pdf', None, 3456789, 'pdf', 'application/pdf',
         'Yeni çalışanlar için kapsamlı rehber', 1, 'İnsan Kaynakları', 'employee', 1, '3.0',
         'İK Departmanı', 'Çalışan hakları ve sorumlulukları', 'ik,çalışan,rehber', 25, 78, 2),
        
        # Şablonlar (Herkes erişebilir)
        ('Rapor Şablonu', 'report_template.docx', None, 456789, 'docx', 'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
         'Standart rapor düzenleme şablonu', 3, 'Bilgi İşlem', 'employee', 1, '1.5',
         'Template Ekibi', 'Raporlar için standart format', 'şablon,rapor,format', 12, 56, 1),
         
        ('Fatura Şablonu', 'invoice_template.xlsx', None, 234567, 'xlsx', 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
         'Fatura düzenleme için Excel şablonu', 3, 'Muhasebe', 'employee', 1, '2.0',
         'Muhasebe Ekibi', 'Standart fatura formatı', 'fatura,muhasebe,şablon', 18, 94, 5),
        
        # Raporlar (Manager ve Admin)
        ('Aylık Satış Raporu', 'monthly_sales.pdf', None, 987654, 'pdf', 'application/pdf',
         'Ağustos 2024 satış performans raporu', 2, 'Satış', 'manager', 1, '1.0',
         'Satış Analisti', '2024 Ağustos ayı detaylı satış analizi', 'satış,rapor,performans', 6, 23, 3),
         
        ('Mali Durum Raporu', 'financial_report.pdf', None, 1234567, 'pdf', 'application/pdf',
         'Q3 2024 finansal durum analizi', 2, 'Muhasebe', 'manager', 1, '1.2',
         'Mali Müşavir', 'Üçüncü çeyrek mali tablolar', 'finans,mali,analiz', 4, 18, 5),
        
        # Eğitim Materyalleri (Herkes)
        ('Yeni Çalışan Orientasyonu', 'orientation_guide.pdf', None, 4567890, 'pdf', 'application/pdf',
         'İlk gün eğitim materyali', 4, 'İnsan Kaynakları', 'employee', 1, '4.0',
         'Eğitim Koordinatörü', 'Yeni başlayanlar için rehber', 'eğitim,orientasyon,başlangıç', 35, 127, 2),
         
        ('Yazılım Kullanım Kılavuzu', 'software_manual.pdf', None, 2345678, 'pdf', 'application/pdf',
         'CRM sistemi kullanım kılavuzu', 4, 'Bilgi İşlem', 'employee', 1, '1.8',
         'IT Support', 'Adım adım CRM rehberi', 'crm,yazılım,kullanım', 22, 89, 1),
        
        # Teknik Belgeler (Sadece Admin)
        ('Sistem Mimarisi', 'system_architecture.pdf', None, 1876543, 'pdf', 'application/pdf',
         'IT altyapı dokümantasyonu', 6, 'Bilgi İşlem', 'admin', 1, '2.5',
         'Sistem Mimarı', 'Ağ yapısı ve sunucu konfigürasyonu', 'sistem,altyapı,ağ', 3, 12, 1),
         
        ('Veritabanı Şeması', 'database_schema.pdf', None, 876543, 'pdf', 'application/pdf',
         'Ana veritabanı yapısı', 6, 'Bilgi İşlem', 'admin', 1, '1.0',
         'DBA', 'Tablo yapıları ve ilişkiler', 'veritabanı,şema,sql', 2, 8, 1)
    ]
    
    for file_data in demo_files:
        try:
            c.execute("""INSERT INTO files 
                         (title, filename, file_path, file_size, file_type, mime_type, content_preview,
                          category_id, department, access_level, is_active, version, author, 
                          description, tags, download_count, view_count, created_by) 
                         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""", file_data)
        except Exception as e:
            logger.debug(f"Demo file insert skipped: {e}")
    
    conn.commit()
    conn.close()

# ---- Hızlı Dosya Ekleme Fonksiyonu -----------------------------------------
def add_sample_files():
    """Terminal'den çağrılabilir hızlı dosya ekleme"""
    conn = get_conn()
    c = conn.cursor()
    
    sample_files = [
        ('Test PDF Dosyası', 'test_document.pdf', None, 1024000, 'pdf', 'application/pdf', 
         'Test amaçlı PDF dosyası', 1, 'Bilgi İşlem', 'employee', 1, '1.0', 
         'Test User', 'Test için oluşturulmuş örnek PDF dosyası', 'test,pdf,demo', 0, 0, 1),
        
        ('Excel Çalışma Sayfası', 'sample_spreadsheet.xlsx', None, 512000, 'xlsx', 
         'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
         'Örnek Excel çalışma sayfası', 3, 'Muhasebe', 'employee', 1, '1.0',
         'Demo User', 'Excel örnek dosyası', 'excel,spreadsheet,demo', 0, 0, 1),
         
        ('Word Dökümanı', 'sample_document.docx', None, 256000, 'docx',
         'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
         'Örnek Word dökümanı', 3, 'İnsan Kaynakları', 'employee', 1, '1.0',
         'Demo User', 'Word örnek dosyası', 'word,document,demo', 0, 0, 1),
         
        ('PowerPoint Sunumu', 'sample_presentation.pptx', None, 2048000, 'pptx',
         'application/vnd.openxmlformats-officedocument.presentationml.presentation',
         'Örnek PowerPoint sunumu', 4, 'Pazarlama', 'employee', 1, '1.0',
         'Demo User', 'PowerPoint örnek dosyası', 'powerpoint,presentation,demo', 0, 0, 1)
    ]
    
    added_count = 0
    for file_data in sample_files:
        try:
            c.execute("""INSERT INTO files 
                         (title, filename, file_path, file_size, file_type, mime_type, content_preview,
                          category_id, department, access_level, is_active, version, author, 
                          description, tags, download_count, view_count, created_by) 
                         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""", file_data)
            added_count += 1
            print(f"✅ Eklendi: {file_data[0]}")
        except Exception as e:
            print(f"❌ Hata: {file_data[0]} - {e}")
    
    conn.commit()
    conn.close()
    print(f"\n🎉 {added_count} dosya başarıyla eklendi!")
    return added_count

# ---- Main --------------------------------------------------------------------
if __name__ == '__main__':
    init_db()
    add_demo_data()
    
    print("🚀 TechCorp Enterprise File Management System")
    print("=" * 50)
    print("📊 Demo kullanıcıları:")
    print("   - admin / Admin123! (Admin)")
    print("   - manager1 / Manager123! (Manager)")  
    print("   - john.doe / Employee123! (Employee)")
    print("📁 Dosya sistemi hazır!")
    print("🌐 Server: http://localhost:5000")
    print("=" * 50)
    
    app.run(debug=True, host='0.0.0.0', port=5000)