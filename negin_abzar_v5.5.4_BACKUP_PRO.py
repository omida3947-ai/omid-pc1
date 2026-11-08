
# حسابداری OMID PC — نسخه 5.5.4 (اصلاحات امنیتی، یکپارچگی داده و بکاپ رمزنگاری‌شده فلش)
# نیازمندی: Python 3.10+ و PySide6 | نصب: pip install PySide6
# اجرا: python negin_abzar_v5.5.4.py  یا  فایل اجرا.bat
# داده مشتری (دیتابیس و backups) جدا از فایل برنامه ذخیره می‌شود تا آپدیت EXE اطلاعات را پاک نکند.
#
# تغییرات نسخه 5.5.4 نسبت به 5.5.3:
#   - verify_app_password دیگر در صورت خطای دیتابیس به رمز پیش‌فرض کارخانه سقوط نمی‌کند (fail-closed).
#   - محدودیت تلاش ورود (lockout موقت) در LoginDialog اضافه شد.
#   - اگر رمز عبور هنوز همان رمز پیش‌فرض کارخانه باشد، بلافاصله بعد از ورود، تغییر اجباری آن خواسته می‌شود.
#   - باگ خاموش ایندکس یکتای شماره فاکتور رفع شد: فاکتورهای تکراری قدیمی به‌جای نادیده گرفتن، شماره‌گذاری مجدد می‌شوند.
#   - خطاهای مهم که قبلاً کاملاً بلعیده می‌شدند (مهاجرت داده، ارتقای رمز، بازیابی بک‌آپ) اکنون در فایل لاگ ثبت می‌شوند.
#   - دفتر رخداد (audit_log) برای عملیات حساس (ورود، ابطال فاکتور/خرید، حذف کالا، مرجوعی، تغییر رمز، بازیابی بک‌آپ) اضافه شد.
#   - تعریف تکراری جدول instagram_order_items حذف شد.
# -*- coding: utf-8 -*-
import sys, os, sqlite3, csv, subprocess, time, html as html_module, shutil, hashlib, hmac, secrets, tempfile, traceback, base64, json, ctypes, winreg, platform, re
from copy import deepcopy
from datetime import datetime, date, timedelta
from decimal import Decimal, InvalidOperation, ROUND_HALF_UP
from PySide6.QtCore import Qt, Signal, QSizeF, QMarginsF, QTimer, QEvent, QSettings, QUrl, QLockFile, QStandardPaths
from PySide6.QtGui import QFont, QFontDatabase, QTextDocument, QPageSize, QPageLayout, QDesktopServices, QKeySequence, QShortcut
from PySide6.QtPrintSupport import QPrinter, QPrinterInfo, QPrintDialog
try:
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    from cryptography.hazmat.primitives import hashes
except Exception:
    serialization = None
    Ed25519PublicKey = None
    AESGCM = None
    PBKDF2HMAC = None
    hashes = None

from PySide6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QFrame, QLabel, QPushButton, QLineEdit,
    QVBoxLayout, QHBoxLayout, QGridLayout, QTableWidget, QTableWidgetItem,
    QHeaderView, QMessageBox, QComboBox, QSpinBox, QDoubleSpinBox, QScrollArea,
    QStackedWidget, QDialog, QFormLayout, QAbstractItemView, QFileDialog,
    QDialogButtonBox, QTextEdit, QDateEdit, QAbstractSpinBox, QInputDialog, QListWidget,
    QSizePolicy, QCompleter
)

APP_NAME = "حسابداری OMID PC"
APP_VERSION = "5.5.4"
APP_DATA_FOLDER = "OMIDPCAccounting"
# این سه مقدار در init_data_paths() پر می‌شوند تا نصب/آپدیت EXE دیتابیس را پاک نکند.
DATA_DIR = ""
DB_PATH = ""
BACKUP_DIR = ""
LOCK_PATH = ""
DATA_LOCATION_MODE = ""
# رمز اولیه فقط برای نصب اول؛ در نسخه‌های جدید به‌جای یک مقدار ثابت، یک bootstrap امن و تصادفی
# در زمان اجرا تولید می‌شود تا کدمنبع هیچ‌وقت یک رمز پیش‌فرض ثابت و شناخته‌شده نداشته باشد.
# در اولین اجرا اگر هیچ رمز ثبت‌شده‌ای وجود نداشته باشد، این مقدار نمایش داده می‌شود تا کاربر فوراً تغییر دهد.
PASSWORD_HASH_ROUNDS = 120000

def _generate_bootstrap_password(length=18):
    return secrets.token_urlsafe(length)[:length]


def _preferred_default_password():
    env_password = os.environ.get("NEGIN_ABZAR_DEFAULT_PASSWORD", "").strip()
    if env_password:
        return env_password
    return _generate_bootstrap_password()


APP_PASSWORD = _preferred_default_password()
PERSIAN_DIGIT_TABLE = str.maketrans("۰۱۲۳۴۵۶۷۸۹٠١٢٣٤٥٦٧٨٩", "01234567890123456789")
# محدودیت تلاش ناموفق ورود قبل از قفل موقت
LOGIN_MAX_ATTEMPTS_BEFORE_LOCK = 5
LOGIN_LOCK_SECONDS = 30

# سیستم پشتیبان‌گیری حرفه‌ای و مقاوم‌تر در برابر قطع برق
AUTO_BACKUP_INTERVAL_MS = 10 * 60 * 1000       # هر ۱۰ دقیقه
AUTO_BACKUP_RECENT_KEEP = 12                    # ۱۲ نسخه اخیر
DAILY_BACKUP_KEEP = 14                          # ۱۴ روز
WEEKLY_BACKUP_KEEP = 8                          # ۸ هفته
SAFETY_BACKUP_KEEP = 20                         # نسخه‌های ایمنی عملیات حساس

# بکاپ دوم روی فلش/درایو خارجی:
# فایل‌ها در مقصد دوم به‌صورت AES-256-GCM رمزنگاری می‌شوند.
SECONDARY_BACKUP_FOLDER_DEFAULT = ""
SECONDARY_BACKUP_EXTENSION = ".ngbak"
SECONDARY_BACKUP_PBKDF2_ITERATIONS = 600000


def _get_windows_volume_info(path):
    """شناسه پایدار ولوم ویندوز را می‌گیرد تا فلش با حرف درایو اشتباه نشود."""
    if not sys.platform.startswith("win"):
        return {"root": os.path.abspath(path), "serial": "", "label": ""}
    drive=os.path.splitdrive(os.path.abspath(path))[0]
    if not drive:
        raise ValueError("درایو معتبر انتخاب نشده است.")
    root=drive + "\\"
    vol_name=ctypes.create_unicode_buffer(261); fs_name=ctypes.create_unicode_buffer(261)
    serial=ctypes.c_uint32(); max_comp=ctypes.c_uint32(); flags=ctypes.c_uint32()
    ok=ctypes.windll.kernel32.GetVolumeInformationW(root, vol_name, len(vol_name), ctypes.byref(serial), ctypes.byref(max_comp), ctypes.byref(flags), fs_name, len(fs_name))
    if not ok: raise ctypes.WinError()
    return {"root":root, "serial":f"{serial.value:08X}", "label":vol_name.value}


def _find_mounted_volume_by_serial(serial):
    if not serial: return ""
    for code in range(ord("A"), ord("Z")+1):
        try:
            root=chr(code)+":\\"
            if _get_windows_volume_info(root).get("serial") == serial: return root
        except Exception: pass
    return ""


# -------------------- ENCRYPTED SECONDARY BACKUP --------------------
def _dpapi_protect(data):
    """رمزگذاری داده با Windows DPAPI؛ فقط حساب کاربری ویندوز همان دستگاه می‌تواند آن را باز کند."""
    if not sys.platform.startswith("win"):
        raise RuntimeError("رمزنگاری خودکار رمز بکاپ فقط روی ویندوز پشتیبانی می‌شود.")
    class DATA_BLOB(ctypes.Structure):
        _fields_ = [("cbData", ctypes.c_uint32), ("pbData", ctypes.POINTER(ctypes.c_ubyte))]
    raw = bytes(data)
    buf = (ctypes.c_ubyte * len(raw)).from_buffer_copy(raw)
    inp = DATA_BLOB(len(raw), buf)
    out = DATA_BLOB()
    crypt32 = ctypes.windll.crypt32
    kernel32 = ctypes.windll.kernel32
    if not crypt32.CryptProtectData(ctypes.byref(inp), None, None, None, None, 0, ctypes.byref(out)):
        raise ctypes.WinError()
    try:
        return ctypes.string_at(out.pbData, out.cbData)
    finally:
        kernel32.LocalFree(out.pbData)


def _dpapi_unprotect(data):
    if not sys.platform.startswith("win"):
        raise RuntimeError("رمزنگاری خودکار رمز بکاپ فقط روی ویندوز پشتیبانی می‌شود.")
    class DATA_BLOB(ctypes.Structure):
        _fields_ = [("cbData", ctypes.c_uint32), ("pbData", ctypes.POINTER(ctypes.c_ubyte))]
    raw = bytes(data)
    buf = (ctypes.c_ubyte * len(raw)).from_buffer_copy(raw)
    inp = DATA_BLOB(len(raw), buf)
    out = DATA_BLOB()
    crypt32 = ctypes.windll.crypt32
    kernel32 = ctypes.windll.kernel32
    if not crypt32.CryptUnprotectData(ctypes.byref(inp), None, None, None, None, 0, ctypes.byref(out)):
        raise ctypes.WinError()
    try:
        return ctypes.string_at(out.pbData, out.cbData)
    finally:
        kernel32.LocalFree(out.pbData)


def _encrypt_secondary_backup(source_path, target_path, password):
    """رمزنگاری فایل بکاپ با AES-256-GCM و کلید مشتق‌شده با PBKDF2-HMAC-SHA256."""
    if AESGCM is None or PBKDF2HMAC is None or hashes is None:
        raise RuntimeError("کتابخانه cryptography برای بکاپ رمزنگاری‌شده نصب نیست.")
    if not password:
        raise ValueError("رمز بکاپ دوم تنظیم نشده است.")
    with open(source_path, "rb") as f:
        plaintext = f.read()

    salt = secrets.token_bytes(16)
    nonce = secrets.token_bytes(12)
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=SECONDARY_BACKUP_PBKDF2_ITERATIONS,
    )
    key = kdf.derive(password.encode("utf-8"))
    aad = b"NeginAbzar-Encrypted-Backup-v1"
    ciphertext = AESGCM(key).encrypt(nonce, plaintext, aad)

    header = {
        "format": "NeginAbzarEncryptedBackup",
        "version": 1,
        "kdf": "PBKDF2-HMAC-SHA256",
        "iterations": SECONDARY_BACKUP_PBKDF2_ITERATIONS,
        "cipher": "AES-256-GCM",
        "salt": _b64e(salt),
        "nonce": _b64e(nonce),
        "aad": _b64e(aad),
        "original_name": os.path.basename(source_path),
    }
    blob = (
        b"NEGIN-ABZAR-BACKUP-V1\n"
        + json.dumps(header, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
        + b"\n\n"
        + ciphertext
    )
    os.makedirs(os.path.dirname(os.path.abspath(target_path)), exist_ok=True)
    temp = target_path + f".tmp_{os.getpid()}_{time.time_ns()}"
    try:
        with open(temp, "wb") as f:
            f.write(blob)
            f.flush()
            os.fsync(f.fileno())
        os.replace(temp, target_path)
    finally:
        try:
            if os.path.exists(temp):
                os.remove(temp)
        except Exception:
            pass


# -------------------- LICENSE / ANTI-COPY --------------------
# فقط کلید عمومی داخل برنامه قرار می‌گیرد؛ کلید خصوصی هرگز نباید داخل EXE یا فایل نصب باشد.
LICENSE_PUBLIC_KEY_PEM = b"""-----BEGIN PUBLIC KEY-----
MCowBQYDK2VwAyEAxVxt7/LXhRo1tT/E8+L6BAXaSuL18a0AWQ0hkXIWeUs=
-----END PUBLIC KEY-----
"""
LICENSE_FILE_NAME = "negin_license.json"
LICENSE_PRODUCT = "NeginAbzarIsfahan"
LICENSE_SCHEMA = 1


def _b64e(data):
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


def _b64d(text):
    text = str(text or "")
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def _windows_machine_parts():
    parts = []
    if not sys.platform.startswith("win"):
        return parts
    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Cryptography") as key:
            parts.append("machineguid=" + str(winreg.QueryValueEx(key, "MachineGuid")[0]).strip())
    except Exception:
        pass
    try:
        serial = ctypes.c_ulong()
        ctypes.windll.kernel32.GetVolumeInformationW(
            ctypes.c_wchar_p(os.environ.get("SystemDrive", "C:") + "\\"),
            None, 0, ctypes.byref(serial), None, None, None, 0
        )
        parts.append(f"volserial={serial.value:08X}")
    except Exception:
        pass
    try:
        cmd = (
            "$a=Get-CimInstance Win32_ComputerSystemProduct -ErrorAction SilentlyContinue | Select-Object -ExpandProperty UUID;"
            "$b=Get-CimInstance Win32_BIOS -ErrorAction SilentlyContinue | Select-Object -ExpandProperty SerialNumber;"
            "Write-Output (($a -as [string])+'|'+($b -as [string]))"
        )
        out = subprocess.check_output(
            ["powershell", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", cmd],
            stderr=subprocess.DEVNULL, timeout=5, creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0)
        ).decode("utf-8", "ignore").strip()
        if out:
            a, _, b = out.partition("|")
            if a.strip(): parts.append("uuid=" + a.strip())
            if b.strip(): parts.append("bios=" + b.strip())
    except Exception:
        pass
    return parts


def get_machine_id():
    """شناسه دستگاه را از چند شناسه نسبتاً پایدار می‌سازد؛ مقدار خام سخت‌افزار ذخیره نمی‌شود."""
    try:
        parts = _windows_machine_parts()
        if not parts:
            parts = ["fallback=" + str(os.environ.get("COMPUTERNAME") or platform.node() or "unknown-device")]
        raw = "|".join(sorted(set(parts))).encode("utf-8", "ignore")
        digest = hashlib.sha256(raw).hexdigest().upper()
        return "-".join(digest[i:i+4] for i in range(0, len(digest), 4))
    except Exception:
        return "UNKNOWN-DEVICE"


def normalize_machine_id(value):
    """شناسه را برای مقایسه مستقل از خط تیره و فاصله می‌کند."""
    return re.sub(r"[^0-9A-F]", "", str(value or "").upper())


def _license_path():
    return os.path.join(DATA_DIR or program_dir(), LICENSE_FILE_NAME)


def _canonical_license_payload(payload):
    return json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")


def verify_license_file(path=None):
    """اعتبارسنجی امضای دیجیتال + اتصال لایسنس به همین دستگاه."""
    path = path or _license_path()
    try:
        if Ed25519PublicKey is None or serialization is None:
            return False, "کتابخانه cryptography در نسخه نصب‌شده وجود ندارد."
        with open(path, "r", encoding="utf-8") as f:
            doc = json.load(f)
        payload = doc.get("payload")
        signature = doc.get("signature")
        if not payload or not signature:
            return False, "ساختار فایل لایسنس نامعتبر است."
        payload_bytes = _b64d(payload)
        sig_bytes = _b64d(signature)
        public_key = serialization.load_pem_public_key(LICENSE_PUBLIC_KEY_PEM)
        public_key.verify(sig_bytes, payload_bytes)
        data = json.loads(payload_bytes.decode("utf-8"))
        if int(data.get("schema", 0)) != LICENSE_SCHEMA:
            return False, "نسخه ساختار لایسنس با این برنامه سازگار نیست."
        if data.get("product") != LICENSE_PRODUCT:
            return False, "این لایسنس متعلق به حسابداری OMID PC نیست."
        if normalize_machine_id(data.get("machine_id")) != normalize_machine_id(get_machine_id()):
            return False, "این لایسنس برای این سیستم صادر نشده است."
        expires = str(data.get("expires_at") or "").strip()
        if expires:
            try:
                exp = datetime.fromisoformat(expires.replace("Z", "+00:00"))
                now_dt = datetime.now(exp.tzinfo) if exp.tzinfo else datetime.now()
                if now_dt > exp:
                    return False, "اعتبار لایسنس به پایان رسیده است."
            except Exception:
                return False, "تاریخ انقضای لایسنس نامعتبر است."
        return True, data
    except Exception as e:
        _log_error("verify_license_file", e)
        return False, "فایل لایسنس معتبر نیست یا دستکاری شده است."


def install_license_from_file(source_path):
    """فایل امضاشده را فقط پس از اعتبارسنجی روی همین سیستم نصب می‌کند."""
    ok, info = verify_license_file(source_path)
    if not ok:
        return False, info
    try:
        dest = _license_path()
        os.makedirs(os.path.dirname(dest), exist_ok=True)
        tmp = dest + ".tmp"
        shutil.copyfile(source_path, tmp)
        os.replace(tmp, dest)
        return True, info
    except Exception as e:
        _log_error("install_license_from_file", e)
        return False, "ذخیره فایل لایسنس انجام نشد."


class LicenseDialog(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("فعال‌سازی حسابداری OMID PC")
        self.setMinimumWidth(620)
        self.selected_path = ""
        layout = QVBoxLayout(self)
        title = QLabel("🔐 فعال‌سازی نسخه قانونی حسابداری OMID PC")
        title.setStyleSheet("font-size:18px;font-weight:700;")
        layout.addWidget(title)
        info = QLabel("این نسخه به یک سیستم مشخص متصل است. پوشه نصب یا فایل‌های برنامه روی سیستم دیگری بدون لایسنس معتبر اجرا نمی‌شوند.")
        info.setWordWrap(True)
        layout.addWidget(info)
        layout.addWidget(QLabel("شناسه این سیستم:"))
        self.machine = QLineEdit(get_machine_id())
        self.machine.setReadOnly(True)
        self.machine.setToolTip("این شناسه را برای صدور لایسنس به فروشنده/پشتیبانی بدهید.")
        layout.addWidget(self.machine)
        copy_machine_btn = QPushButton("کپی شناسه سیستم")
        copy_machine_btn.clicked.connect(lambda: QApplication.clipboard().setText(self.machine.text()))
        layout.addWidget(copy_machine_btn)
        self.status = QLabel("فایل لایسنس را انتخاب کنید.")
        self.status.setWordWrap(True)
        layout.addWidget(self.status)
        row = QHBoxLayout()
        self.choose_btn = QPushButton("انتخاب فایل لایسنس")
        self.choose_btn.clicked.connect(self.choose_license)
        self.activate_btn = QPushButton("فعال‌سازی")
        self.activate_btn.clicked.connect(self.activate)
        exit_btn = QPushButton("خروج")
        exit_btn.clicked.connect(self.reject)
        row.addWidget(self.choose_btn)
        row.addWidget(self.activate_btn)
        row.addWidget(exit_btn)
        layout.addLayout(row)

    def choose_license(self):
        path, _ = QFileDialog.getOpenFileName(self, "انتخاب فایل لایسنس", "", "License (*.json);;All Files (*.*)")
        if path:
            self.selected_path = path
            self.status.setText("فایل انتخاب شد. برای اعتبارسنجی روی «فعال‌سازی» بزنید.")

    def activate(self):
        if not self.selected_path:
            QMessageBox.warning(self, "لایسنس", "ابتدا فایل لایسنس را انتخاب کنید.")
            return
        ok, info = install_license_from_file(self.selected_path)
        if ok:
            QMessageBox.information(self, "فعال‌سازی موفق", "لایسنس با موفقیت برای این سیستم فعال شد.")
            self.accept()
        else:
            QMessageBox.critical(self, "فعال‌سازی ناموفق", str(info))


def ensure_license():
    """تا قبل از ورود، وجود لایسنس معتبر را اجباری می‌کند."""
    ok, info = verify_license_file()
    if ok:
        return True
    dlg = LicenseDialog()
    if dlg.exec() != QDialog.Accepted:
        return False
    ok, _ = verify_license_file()
    return bool(ok)



def _log_path():
    """مسیر فایل لاگ خطاهای پس‌زمینه؛ کنار پوشه داده کاربر تا فایل برنامه فقط‌خواندنی نماند."""
    base = DATA_DIR or os.path.dirname(os.path.abspath(__file__))
    return os.path.join(base, "negin_abzar_error.log")


def _log_error(context, exc):
    """به‌جای بلعیدن کامل خطاهای مهم، آن‌ها را در یک فایل لاگ محلی ثبت می‌کند.

    این تابع خودش هرگز نباید برنامه را متوقف کند؛ اگر نوشتن لاگ هم شکست بخورد، بی‌صدا رد می‌شویم.
    """
    try:
        path = _log_path()
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "a", encoding="utf-8") as f:
            f.write(f"\n[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] {context}\n")
            f.write("".join(traceback.format_exception(type(exc), exc, exc.__traceback__)))
    except Exception:
        pass


def _audit_connection():
    con = sqlite3.connect(DB_PATH, timeout=30)
    con.execute("""CREATE TABLE IF NOT EXISTS audit_log(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        created_at TEXT NOT NULL,
        action TEXT NOT NULL,
        details TEXT DEFAULT ''
    )""")
    return con


def log_audit(action, details=""):
    """ثبت رخدادهای حساس (ورود، ابطال، حذف، بازیابی بک‌آپ و ...) برای پاسخگویی بعدی.

    این تابع عمداً یک اتصال کوتاه‌عمر جدا باز می‌کند تا وابسته به وجود شیء Database یا
    تراکنش جاری آن نباشد و بتوان آن را حتی قبل از باز شدن پنجره اصلی (مثلاً هنگام ورود) صدا زد.
    """
    con = None
    try:
        con = _audit_connection()
        con.execute(
            "INSERT INTO audit_log(created_at, action, details) VALUES(?,?,?)",
            (now(), action, details),
        )
        con.commit()
    except Exception as e:
        _log_error(f"log_audit:{action}", e)
    finally:
        if con is not None:
            try:
                con.close()
            except Exception:
                pass


def _hash_password(plain, salt=None):
    salt = salt or secrets.token_hex(16)
    dk = hashlib.pbkdf2_hmac(
        "sha256", str(plain or "").encode("utf-8"), salt.encode("utf-8"), PASSWORD_HASH_ROUNDS
    )
    return f"pbkdf2${salt}${dk.hex()}"


def _verify_password(plain, stored):
    stored = str(stored or "")
    entered = str(plain or "")
    if stored.startswith("pbkdf2$"):
        parts = stored.split("$", 2)
        if len(parts) != 3:
            return False
        _, salt, hexhash = parts
        dk = hashlib.pbkdf2_hmac(
            "sha256", entered.encode("utf-8"), salt.encode("utf-8"), PASSWORD_HASH_ROUNDS
        )
        return hmac.compare_digest(dk.hex(), hexhash)
    return hmac.compare_digest(stored, entered)


def _settings_connection():
    con = sqlite3.connect(DB_PATH, timeout=30)
    con.execute("CREATE TABLE IF NOT EXISTS app_settings (key TEXT PRIMARY KEY, value TEXT DEFAULT '')")
    return con


def _read_stored_password(con):
    row = con.execute("SELECT value FROM app_settings WHERE key=?", ("app_password",)).fetchone()
    return str(row[0]).strip() if row and str(row[0]).strip() else ""


def _has_stored_app_password():
    con = None
    try:
        con = _settings_connection()
        return bool(_read_stored_password(con))
    except Exception:
        return False
    finally:
        if con is not None:
            try:
                con.close()
            except Exception:
                pass


def _write_stored_password(con, value):
    con.execute(
        "INSERT INTO app_settings(key,value) VALUES(?,?) "
        "ON CONFLICT(key) DO UPDATE SET value=excluded.value",
        ("app_password", value),
    )
    con.commit()


def verify_app_password(entered):
    """رمز ورود را با مقدار ذخیره‌شده (hash یا نسخه قدیمی متنی) می‌سنجد و در صورت نیاز ارتقا می‌دهد.

    نکته امنیتی: برخلاف نسخه‌های قبلی، اگر خواندن/نوشتن دیتابیس تنظیمات با خطا مواجه شود،
    ورود رد می‌شود (fail-closed) نه اینکه به رمز پیش‌فرض کارخانه سقوط کند؛ وگرنه یک دیتابیس
    تنظیمات قفل‌شده یا خراب می‌توانست به‌صورت ناخواسته درِ ورود با رمز پیش‌فرض را دوباره باز کند.
    """
    con = None
    try:
        con = _settings_connection()
        stored = _read_stored_password(con)
        if not stored:
            if not hmac.compare_digest(str(entered or ""), APP_PASSWORD):
                return False
            _write_stored_password(con, _hash_password(APP_PASSWORD))
            return True
        if not _verify_password(entered, stored):
            return False
        if not stored.startswith("pbkdf2$"):
            _write_stored_password(con, _hash_password(entered))
        return True
    except Exception as e:
        _log_error("verify_app_password", e)
        return False
    finally:
        if con is not None:
            try:
                con.close()
            except Exception:
                pass


def is_using_default_password():
    """True اگر رمز فعال هنوز همان رمز پیش‌فرض کارخانه (APP_PASSWORD) باشد.

    برای اجبار به تغییر رمز بلافاصله بعد از اولین ورود استفاده می‌شود.
    """
    con = None
    try:
        con = _settings_connection()
        stored = _read_stored_password(con)
        if not stored:
            return True
        return _verify_password(APP_PASSWORD, stored)
    except Exception as e:
        _log_error("is_using_default_password", e)
        return False
    finally:
        if con is not None:
            try:
                con.close()
            except Exception:
                pass


def set_app_password(new_plain):
    """رمز عبور برنامه را مستقیماً (مستقل از شیء Database) تنظیم می‌کند."""
    con = None
    try:
        con = _settings_connection()
        _write_stored_password(con, _hash_password(new_plain))
        return True
    except Exception as e:
        _log_error("set_app_password", e)
        return False
    finally:
        if con is not None:
            try:
                con.close()
            except Exception:
                pass


def sqlite_sidecar_paths(path):
    return [path + "-wal", path + "-shm"]


def remove_sqlite_sidecars(path):
    for extra in sqlite_sidecar_paths(path):
        try:
            if os.path.exists(extra):
                os.remove(extra)
        except Exception:
            pass


def program_dir():
    """پوشه فایل برنامه / EXE؛ بعد از Setup ممکن است فقط‌خواندنی باشد."""
    if getattr(sys, "frozen", False):
        return os.path.dirname(os.path.abspath(sys.executable))
    return os.path.dirname(os.path.abspath(__file__))


def _is_protected_install_dir(path):
    p = os.path.normcase(os.path.abspath(path))
    roots = []
    for key in ("ProgramFiles", "ProgramFiles(x86)", "ProgramW6432"):
        value = os.environ.get(key)
        if value:
            roots.append(os.path.normcase(os.path.abspath(value)))
    for root in roots:
        if p == root or p.startswith(root + os.sep):
            return True
    return False


def _dir_is_writable(path):
    try:
        os.makedirs(path, exist_ok=True)
        probe = os.path.join(path, ".negin_write_test")
        with open(probe, "w", encoding="utf-8") as handle:
            handle.write("ok")
        os.remove(probe)
        return True
    except Exception:
        return False


def persistent_data_dir():
    """پوشه پایدار کاربر؛ با تعویض EXE / Setup پاک نمی‌شود."""
    if sys.platform.startswith("win"):
        base = os.environ.get("LOCALAPPDATA") or os.path.expanduser("~")
        return os.path.join(base, APP_DATA_FOLDER)
    xdg = os.environ.get("XDG_DATA_HOME") or os.path.join(os.path.expanduser("~"), ".local", "share")
    return os.path.join(xdg, APP_DATA_FOLDER)


def _migrate_data_bundle(src_dir, dest_dir):
    """انتقال دیتابیس و پشتیبان‌های نسخه قبلی به پوشه پایدار، بدون بازنویسی داده جدید."""
    if not src_dir or not dest_dir:
        return
    if os.path.abspath(src_dir) == os.path.abspath(dest_dir):
        return
    os.makedirs(dest_dir, exist_ok=True)
    src_db = os.path.join(src_dir, "negin_abzar.db")
    dest_db = os.path.join(dest_dir, "negin_abzar.db")
    if os.path.exists(src_db) and not os.path.exists(dest_db):
        shutil.copy2(src_db, dest_db)
        for extra in sqlite_sidecar_paths(src_db):
            if os.path.exists(extra):
                shutil.copy2(extra, dest_db + extra[len(src_db):])
    src_back = os.path.join(src_dir, "backups")
    dest_back = os.path.join(dest_dir, "backups")
    if os.path.isdir(src_back):
        os.makedirs(dest_back, exist_ok=True)
        for name in os.listdir(src_back):
            src = os.path.join(src_back, name)
            dest = os.path.join(dest_back, name)
            if os.path.isfile(src) and not os.path.exists(dest):
                try:
                    shutil.copy2(src, dest)
                except Exception as e:
                    # این یک فایل بک‌آپ خاص است، نه دیتابیس اصلی؛ شکست تک‌فایل نباید
                    # کل مهاجرت را متوقف کند، اما باید جایی ثبت شود تا بی‌سر و صدا گم نشود.
                    _log_error(f"_migrate_data_bundle:copy_backup:{name}", e)


def init_data_paths():
    """جدا کردن فایل برنامه از داده مشتری.

    اولویت:
    1) متغیر محیطی NEGIN_ABZAR_DATA
    2) فایل portable.flag کنار برنامه = حالت قابل‌حمل
    3) اگر negin_abzar.db از قبل کنار برنامه باشد و پوشه قابل‌نوشتن باشد، همان‌جا می‌ماند
       تا نصب ZIP فعلی مشتری خراب نشود
    4) در غیر این صورت %LOCALAPPDATA%\\NeginAbzarIsfahan
       و اگر دیتابیس قدیمی کنار EXE باشد، یک‌بار به آنجا منتقل می‌شود
    """
    global DATA_DIR, DB_PATH, BACKUP_DIR, LOCK_PATH, DATA_LOCATION_MODE
    app_dir = program_dir()
    env = str(os.environ.get("NEGIN_ABZAR_DATA") or "").strip()
    portable_flag = os.path.exists(os.path.join(app_dir, "portable.flag"))
    portable_db = os.path.join(app_dir, "negin_abzar.db")

    if env:
        DATA_DIR = os.path.abspath(env)
        DATA_LOCATION_MODE = "custom"
    elif portable_flag and _dir_is_writable(app_dir) and not _is_protected_install_dir(app_dir):
        DATA_DIR = app_dir
        DATA_LOCATION_MODE = "portable"
    elif (
        os.path.exists(portable_db)
        and _dir_is_writable(app_dir)
        and not _is_protected_install_dir(app_dir)
    ):
        DATA_DIR = app_dir
        DATA_LOCATION_MODE = "portable"
    else:
        DATA_DIR = persistent_data_dir()
        DATA_LOCATION_MODE = "appdata"
        os.makedirs(DATA_DIR, exist_ok=True)
        _migrate_data_bundle(app_dir, DATA_DIR)

    os.makedirs(DATA_DIR, exist_ok=True)
    BACKUP_DIR = os.path.join(DATA_DIR, "backups")
    os.makedirs(BACKUP_DIR, exist_ok=True)
    DB_PATH = os.path.join(DATA_DIR, "negin_abzar.db")
    LOCK_PATH = os.path.join(DATA_DIR, "negin_abzar.lock")
    return DATA_DIR


try:
    init_data_paths()
except Exception as _init_exc:
    # جلوگیری از بسته‌شدن بی‌صدا در سیستم مقصد؛ مسیر AppData همیشه باید قابل استفاده باشد.
    try:
        _fallback = os.path.join(os.environ.get("LOCALAPPDATA") or os.path.expanduser("~"), APP_DATA_FOLDER)
        os.makedirs(_fallback, exist_ok=True)
        DATA_DIR = _fallback
        DATA_LOCATION_MODE = "appdata_fallback"
        BACKUP_DIR = os.path.join(DATA_DIR, "backups")
        os.makedirs(BACKUP_DIR, exist_ok=True)
        DB_PATH = os.path.join(DATA_DIR, "negin_abzar.db")
        LOCK_PATH = os.path.join(DATA_DIR, "negin_abzar.lock")
        with open(os.path.join(DATA_DIR, "negin_abzar_startup.log"), "a", encoding="utf-8") as _lf:
            _lf.write(f"init_data_paths failed: {_init_exc!r}\n")
    except Exception:
        raise


def open_path(path):
    """باز کردن فایل با برنامه پیش‌فرض سیستم‌عامل (ویندوز/لینوکس/مک)."""
    path = os.path.abspath(path)
    try:
        if QDesktopServices.openUrl(QUrl.fromLocalFile(path)):
            return True
    except Exception:
        pass
    try:
        if sys.platform.startswith("win"):
            os.startfile(path)  # type: ignore[attr-defined]
            return True
        if sys.platform == "darwin":
            subprocess.Popen(["open", path])
            return True
        subprocess.Popen(["xdg-open", path])
        return True
    except Exception:
        return False

BG = "#173F43"
PANEL = "#2B6F72"
PANEL_DARK = "#215C60"
PANEL_LIGHT = "#3E8588"
BORDER = "#7BB9BA"
TEXT = "#F4FFFF"
MUTED = "#C5DEDE"
ACCENT = "#70C8C5"
DANGER = "#E98F8F"
GOOD = "#8ED19B"


def to_decimal(v, default="0"):
    """تبدیل امن مقدار عددی به Decimal بدون عبور از float؛ مناسب محاسبات مالی."""
    if v is None or v == "":
        v = default
    if isinstance(v, Decimal):
        return v
    if isinstance(v, bool):
        return Decimal(int(v))
    if isinstance(v, int):
        return Decimal(v)
    try:
        text = str(v).translate(PERSIAN_DIGIT_TABLE)
        text = text.replace("٬", "").replace("،", "").replace(",", "").replace(" ", "").replace("\u00a0", "").strip()
        return Decimal(text)
    except (InvalidOperation, ValueError, TypeError):
        return Decimal(str(default))


def money_decimal(v):
    """مبلغ را به تومان صحیح، با گرد کردن نیم به بالا، تبدیل می‌کند."""
    return to_decimal(v).quantize(Decimal("1"), rounding=ROUND_HALF_UP)


def money(v):
    try:
        return f"{money_decimal(v):,.0f} تومان"
    except Exception:
        return "0 تومان"


def format_qty(v):
    """نمایش امن تعداد با Decimal؛ بدون خطای اعشاری float."""
    try:
        number = to_decimal(v)
        if number == 0:
            return "0"
        text = format(number.quantize(Decimal("0.01"), rounding=ROUND_HALF_UP), "f").rstrip("0").rstrip(".")
        return text
    except Exception:
        return str(v)


class CleanDoubleSpinBox(QDoubleSpinBox):
    """QDoubleSpinBox with compact numeric display.

    Values such as 1.00, 1.50 and 0.00 are shown as 1, 1.5 and 0,
    while real decimal values keep only the necessary decimal digits.
    """
    def textFromValue(self, value):
        try:
            number = float(value)
            if abs(number) < 1e-12:
                return "0"
            decimals = max(0, int(self.decimals()))
            text = f"{number:.{decimals}f}"
            if "." in text:
                text = text.rstrip("0").rstrip(".")
            return text
        except Exception:
            return super().textFromValue(value)


class MoneySpinBox(QDoubleSpinBox):
    """فیلد مبلغ با «تومان» ثابت؛ فقط بخش عددی قابل ویرایش است.

    در حالت راست‌به‌چپ، «تومان» در سمت چپ و عدد در سمت راست دیده می‌شود.
    مکان‌نما همیشه به بخش عددی هدایت می‌شود تا کاربر مجبور نباشد
    دقیقاً روی قسمت خاصی از فیلد کلیک کند.
    """
    SUFFIX = " تومان"

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.setDecimals(0)
        self.setMinimum(0)
        self.setMaximum(999999999999)
        self.setButtonSymbols(QAbstractSpinBox.NoButtons)
        self.setSuffix(self.SUFFIX)
        self.setSpecialValueText("")
        try:
            self.setGroupSeparatorShown(False)
        except Exception:
            pass

        # فیلد عددی همیشه در سمت راستِ «تومان» قابل ویرایش باشد.
        le = self.lineEdit()
        le.setLayoutDirection(Qt.RightToLeft)
        le.setAlignment(Qt.AlignRight | Qt.AlignVCenter)
        le.cursorPositionChanged.connect(self._keep_cursor_in_number)

    def _numeric_length(self):
        text = self.lineEdit().text()
        suffix = self.SUFFIX
        if text.endswith(suffix):
            return len(text) - len(suffix)
        return len(text)

    def _keep_cursor_in_number(self, old_pos, new_pos):
        n = self._numeric_length()
        if new_pos > n:
            self.lineEdit().setCursorPosition(n)

    def focusInEvent(self, event):
        super().focusInEvent(event)
        QTimer.singleShot(0, self._move_cursor_to_number)

    def mousePressEvent(self, event):
        super().mousePressEvent(event)
        QTimer.singleShot(0, self._move_cursor_to_number)

    def _move_cursor_to_number(self):
        le = self.lineEdit()
        n = self._numeric_length()
        le.setCursorPosition(n)

    def textFromValue(self, value):
        # فقط بخش عددی را فرمت می‌کنیم؛ QDoubleSpinBox خودش «تومان» را ثابت اضافه می‌کند.
        if float(value) == 0:
            return ""
        return f"{int(money_decimal(value)):,}"

    def valueFromText(self, text):
        s = str(text).replace("تومان", "").replace(" ", "").strip()
        s = s.replace(".", "").replace(",", "")
        if not s:
            return 0.0
        try:
            return float(s)
        except Exception:
            return 0.0


def now():
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def gregorian_to_jalali(gy, gm, gd):
    """تبدیل میلادی به شمسی بدون نیاز به کتابخانه خارجی."""
    g_days_in_month = [31,28,31,30,31,30,31,31,30,31,30,31]
    j_days_in_month = [31,31,31,31,31,31,30,30,30,30,30,29]
    gy2 = gy - 1600
    gm2 = gm - 1
    gd2 = gd - 1
    g_day_no = 365*gy2 + (gy2+3)//4 - (gy2+99)//100 + (gy2+399)//400
    for i in range(gm2):
        g_day_no += g_days_in_month[i]
    if gm2 > 1 and ((gy % 4 == 0 and gy % 100 != 0) or gy % 400 == 0):
        g_day_no += 1
    g_day_no += gd2
    j_day_no = g_day_no - 79
    j_np = j_day_no // 12053
    j_day_no %= 12053
    jy = 979 + 33*j_np + 4*(j_day_no//1461)
    j_day_no %= 1461
    if j_day_no >= 366:
        jy += (j_day_no-1)//365
        j_day_no = (j_day_no-1)%365
    for i in range(11):
        if j_day_no < j_days_in_month[i]:
            jm = i+1; jd = j_day_no+1; break
        j_day_no -= j_days_in_month[i]
    else:
        jm = 12; jd = j_day_no+1
    return jy, jm, jd


def jalali_today():
    y,m,d = gregorian_to_jalali(date.today().year, date.today().month, date.today().day)
    return f"{y:04d}/{m:02d}/{d:02d}"


def format_jalali_date(value):
    """نمایش تاریخ ذخیره‌شده میلادی به شمسی؛ ورودی خالی/نامعتبر بدون تغییر برمی‌گردد."""
    if not value:
        return "-"
    try:
        raw = str(value).split(" ",1)[0].replace("-","/")
        y,m,d = [int(x) for x in raw.split("/")]
        jy,jm,jd = gregorian_to_jalali(y,m,d)
        return f"{jy:04d}/{jm:02d}/{jd:02d}"
    except Exception:
        return str(value)


def normalize_date_input(value, default_today=True):
    """تاریخ شمسی YYYY/MM/DD یا میلادی YYYY-MM-DD را با اعتبارسنجی کامل به YYYY-MM-DD تبدیل می‌کند."""
    text = str(value or "").translate(PERSIAN_DIGIT_TABLE).strip().replace("-", "/")
    if not text and default_today:
        return date.today().isoformat()
    parts = text.split("/")
    if len(parts) != 3:
        raise ValueError("تاریخ باید به صورت 1405/06/15 یا 2026/09/06 وارد شود.")
    try:
        y, m, d = map(int, parts)
    except ValueError:
        raise ValueError("تاریخ فقط باید شامل عدد و به صورت YYYY/MM/DD باشد.")

    if 1300 <= y <= 1499:
        # جلالی -> میلادی
        if not (1 <= m <= 12):
            raise ValueError("ماه شمسی باید بین 1 تا 12 باشد.")
        max_day = 31 if m <= 6 else (30 if m <= 11 else 30)
        if not (1 <= d <= max_day):
            raise ValueError("روز واردشده برای این ماه شمسی معتبر نیست.")
        jy, jm, jd = y - 979, m, d
        j_day_no = 365 * jy + (jy // 33) * 8 + ((jy % 33) + 3) // 4
        for i in range(jm - 1):
            j_day_no += 31 if i < 6 else 30
        j_day_no += jd - 1
        g_day_no = j_day_no + 79
        gy = 1600 + 400 * (g_day_no // 146097)
        g_day_no %= 146097
        leap = True
        if g_day_no >= 36525:
            g_day_no -= 1
            gy += 100 * (g_day_no // 36524)
            g_day_no %= 36524
            if g_day_no >= 365:
                g_day_no += 1
            else:
                leap = False
        gy += 4 * (g_day_no // 1461)
        g_day_no %= 1461
        if g_day_no >= 366:
            leap = False
            g_day_no -= 1
            gy += g_day_no // 365
            g_day_no %= 365
        gm = 0
        mdays = [31, 29 if leap else 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31]
        while gm < 12 and g_day_no >= mdays[gm]:
            g_day_no -= mdays[gm]
            gm += 1
        gy, gm, gd = gy, gm + 1, g_day_no + 1
        try:
            date(gy, gm, gd)
        except ValueError:
            raise ValueError("تاریخ شمسی واردشده معتبر نیست.")
        # کنترل رفت و برگشت برای تشخیص 30 اسفند نامعتبر و موارد مشابه.
        if gregorian_to_jalali(gy, gm, gd) != (y, m, d):
            raise ValueError("تاریخ شمسی واردشده معتبر نیست.")
        return f"{gy:04d}-{gm:02d}-{gd:02d}"

    # میلادی
    if not (1 <= m <= 12):
        raise ValueError("ماه میلادی باید بین 1 تا 12 باشد.")
    try:
        parsed = date(y, m, d)
    except ValueError:
        raise ValueError("تاریخ میلادی واردشده معتبر نیست.")
    return parsed.isoformat()

def center_item(text):
    item = QTableWidgetItem(str(text))
    item.setTextAlignment(Qt.AlignCenter)
    return item



def save_current_invoice_pdf_and_open(parent=None, invoice_text=""):
    """ذخیره فاکتور به PDF با API سازگار PySide6 و باز کردن فوری فایل."""
    default_dir = QStandardPaths.writableLocation(QStandardPaths.DocumentsLocation)
    path, _ = QFileDialog.getSaveFileName(
        parent,
        "ذخیره فاکتور به PDF",
        os.path.join(default_dir, "فاکتور.pdf"),
        "PDF Files (*.pdf)"
    )
    if not path:
        return False

    if not path.lower().endswith(".pdf"):
        path += ".pdf"

    printer = QPrinter(QPrinter.PrinterMode.HighResolution)
    printer.setOutputFormat(QPrinter.OutputFormat.PdfFormat)
    printer.setOutputFileName(path)
    printer.setPageSize(QPageSize(QPageSize.PageSizeId.A4))
    printer.setPageOrientation(QPageLayout.Orientation.Portrait)
    printer.setPageMargins(QMarginsF(2, 2, 2, 2), QPageLayout.Unit.Millimeter)

    doc = QTextDocument()
    doc.setDefaultFont(QFont("Tahoma", 10))
    doc.setHtml(
        '<div dir="rtl" style="font-family:Tahoma; font-size:12pt;">'
        + html_module.escape(invoice_text).replace("\n", "<br>")
        + "</div>"
    )
    doc.print_(printer)
    open_path(path)
    return True

class Database:
    def __init__(self):
        self.con = sqlite3.connect(DB_PATH, timeout=30)
        self.con.row_factory = sqlite3.Row
        self.con.execute("PRAGMA foreign_keys=ON")
        self.con.execute("PRAGMA journal_mode=WAL")
        # دوام حداکثری تراکنش‌ها در WAL؛ مخصوصاً برای قطع ناگهانی برق/خاموشی.
        self.con.execute("PRAGMA synchronous=FULL")
        self.con.execute("PRAGMA busy_timeout=30000")
        self._fifo_cache = None
        self.create_tables()
        legacy_shop_name = self.get_setting("shop_name", "").strip()
        if legacy_shop_name in {"نگین ابزار اصفهان", "نگین ابزار"}:
            self.set_setting("shop_name", "حسابداری OMID PC")
        self._upgrade_plaintext_password()
        self._normalize_legacy_dates()
        self.seed()
        self.reconcile_all_customer_balances()

    def create_tables(self):
        self._prepare_legacy_recipe_tables()
        self.con.executescript("""
        CREATE TABLE IF NOT EXISTS products(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            category TEXT DEFAULT 'سایر',
            buy_price REAL DEFAULT 0,
            sell_price REAL DEFAULT 0,
            stock REAL DEFAULT 0,
            min_stock REAL DEFAULT 1,
            barcode TEXT DEFAULT '',
            unit TEXT DEFAULT 'عدد'
        );

        CREATE TABLE IF NOT EXISTS customers(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            phone TEXT DEFAULT '',
            address TEXT DEFAULT '',
            balance REAL DEFAULT 0,
            notes TEXT DEFAULT ''
        );

        CREATE TABLE IF NOT EXISTS sales(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            customer_id INTEGER,
            total REAL DEFAULT 0,
            profit REAL DEFAULT 0,
            discount REAL DEFAULT 0,
            payment TEXT DEFAULT 'نقدی',
            created_at TEXT NOT NULL,
            invoice_no INTEGER,
            invoice_date TEXT,
            status TEXT DEFAULT 'فعال',
            voided_at TEXT,
            void_reason TEXT DEFAULT '',
            check_id INTEGER
        );

        CREATE TABLE IF NOT EXISTS sale_items(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            sale_id INTEGER,
            product_id INTEGER,
            qty REAL,
            price REAL,
            buy_price REAL,
            discount REAL DEFAULT 0,
            final_price REAL DEFAULT 0
        );

        CREATE TABLE IF NOT EXISTS purchases(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            supplier TEXT DEFAULT '',
            total REAL DEFAULT 0,
            notes TEXT DEFAULT '',
            created_at TEXT NOT NULL,
            status TEXT DEFAULT 'فعال'
        );

        CREATE TABLE IF NOT EXISTS purchase_items(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            purchase_id INTEGER,
            product_id INTEGER,
            qty REAL,
            price REAL,
            cancelled_qty REAL DEFAULT 0
        );

        CREATE TABLE IF NOT EXISTS expenses(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            title TEXT NOT NULL,
            amount REAL DEFAULT 0,
            notes TEXT DEFAULT '',
            created_at TEXT NOT NULL,
            active INTEGER DEFAULT 1
        );

        CREATE TABLE IF NOT EXISTS instagram_orders(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            customer TEXT,
            phone TEXT,
            total REAL DEFAULT 0,
            status TEXT DEFAULT 'جدید',
            address TEXT DEFAULT '',
            notes TEXT DEFAULT '',
            created_at TEXT NOT NULL,
            customer_id INTEGER,
            sale_id INTEGER,
            payment TEXT DEFAULT '',
            stock_applied INTEGER DEFAULT 0
        );

        CREATE TABLE IF NOT EXISTS instagram_order_items(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            order_id INTEGER NOT NULL,
            product_id INTEGER,
            qty REAL,
            price REAL,
            discount REAL DEFAULT 0,
            final_price REAL DEFAULT 0,
            buy_price REAL DEFAULT 0
        );

        CREATE TABLE IF NOT EXISTS recipes(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            instructions TEXT DEFAULT '',
            created_at TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS recipe_items(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            recipe_id INTEGER NOT NULL,
            product_id INTEGER NOT NULL,
            quantity REAL NOT NULL,
            FOREIGN KEY(recipe_id) REFERENCES recipes(id) ON DELETE CASCADE,
            FOREIGN KEY(product_id) REFERENCES products(id)
        );

        CREATE TABLE IF NOT EXISTS checks(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            person TEXT,
            amount REAL DEFAULT 0,
            due_date TEXT,
            type TEXT DEFAULT 'دریافتی',
            status TEXT DEFAULT 'در انتظار',
            notes TEXT DEFAULT ''
        );

        CREATE TABLE IF NOT EXISTS app_settings(
            key TEXT PRIMARY KEY,
            value TEXT DEFAULT ''
        );

        CREATE TABLE IF NOT EXISTS product_categories(
            name TEXT PRIMARY KEY,
            created_at TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS account_transactions(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            customer_id INTEGER NOT NULL,
            transaction_type TEXT NOT NULL,
            amount REAL DEFAULT 0,
            description TEXT DEFAULT '',
            sale_id INTEGER,
            created_at TEXT NOT NULL
        );
        """)
        self._migrate_legacy_recipe_data()

        # مهاجرت بدون حذف اطلاعات قبلی
        self._ensure_column("products", "active", "INTEGER DEFAULT 1")
        self._ensure_column("sales", "status", "TEXT DEFAULT 'فعال'")
        self._ensure_column("sales", "voided_at", "TEXT")
        self._ensure_column("sales", "void_reason", "TEXT DEFAULT ''")
        self._ensure_column("sales", "check_id", "INTEGER")
        self._ensure_column("purchases", "status", "TEXT DEFAULT 'فعال'" )
        self._ensure_column("checks", "check_no", "TEXT DEFAULT ''")
        self._ensure_column("checks", "bank", "TEXT DEFAULT ''")
        self._ensure_column("checks", "branch", "TEXT DEFAULT ''")
        self._ensure_column("checks", "issue_date", "TEXT DEFAULT ''")
        self._ensure_column("checks", "customer_id", "INTEGER")
        self._ensure_column("checks", "sale_id", "INTEGER")
        self._ensure_column("account_transactions", "check_id", "INTEGER")
        self._ensure_column("sale_items", "discount", "REAL DEFAULT 0")
        self._ensure_column("sale_items", "final_price", "REAL DEFAULT 0")
        self._ensure_column("sale_items", "returned_qty", "REAL DEFAULT 0")
        self.con.execute("UPDATE sale_items SET returned_qty=0 WHERE returned_qty IS NULL")
        self.con.execute("""CREATE TABLE IF NOT EXISTS sale_returns(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            sale_id INTEGER NOT NULL,
            amount REAL DEFAULT 0,
            reason TEXT DEFAULT '',
            created_at TEXT NOT NULL
        )""")
        self.con.execute("""CREATE TABLE IF NOT EXISTS sale_return_items(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            return_id INTEGER NOT NULL,
            sale_item_id INTEGER,
            product_id INTEGER,
            qty REAL,
            amount REAL DEFAULT 0,
            buy_price REAL DEFAULT 0
        )""")
        self.con.execute("CREATE INDEX IF NOT EXISTS idx_sale_returns_sale ON sale_returns(sale_id)")
        self._ensure_column("purchase_items", "cancelled_qty", "REAL DEFAULT 0")
        self._ensure_column("expenses", "active", "INTEGER DEFAULT 1")
        self._ensure_column("instagram_orders", "customer_id", "INTEGER")
        self._ensure_column("instagram_orders", "sale_id", "INTEGER")
        self._ensure_column("instagram_orders", "payment", "TEXT DEFAULT ''")
        self._ensure_column("instagram_orders", "stock_applied", "INTEGER DEFAULT 0")
        # توجه: جدول instagram_order_items همین‌جا در create_tables، در executescript اصلی
        # (چند خط بالاتر) قبلاً ساخته شده؛ تعریف تکراری قبلی این‌جا حذف شد، فقط ایندکس لازم است.
        self.con.execute("CREATE INDEX IF NOT EXISTS idx_ig_items_order ON instagram_order_items(order_id)")
        self.con.execute("CREATE INDEX IF NOT EXISTS idx_ig_orders_sale ON instagram_orders(sale_id)")
        self.con.execute("CREATE INDEX IF NOT EXISTS idx_ig_orders_customer ON instagram_orders(customer_id)")
        self.con.execute("UPDATE sale_items SET discount=0 WHERE discount IS NULL")
        self.con.execute("UPDATE sale_items SET final_price=ROUND(qty*price-discount) WHERE final_price IS NULL OR final_price=0")
        self.con.execute("UPDATE expenses SET active=1 WHERE active IS NULL")
        self.con.execute("UPDATE products SET active=1 WHERE active IS NULL")
        self.con.execute("UPDATE purchases SET status='فعال' WHERE status IS NULL OR status=''")
        self.con.execute("""CREATE TABLE IF NOT EXISTS inventory_movements(
            id INTEGER PRIMARY KEY AUTOINCREMENT, product_id INTEGER NOT NULL,
            movement_type TEXT NOT NULL, qty REAL NOT NULL, reference_id INTEGER,
            description TEXT DEFAULT '', created_at TEXT NOT NULL,
            unit_cost REAL DEFAULT 0
        )""")
        self._ensure_column("inventory_movements", "unit_cost", "REAL DEFAULT 0")
        self._ensure_column("inventory_movements", "reference_item_id", "INTEGER")
        self.con.execute("CREATE INDEX IF NOT EXISTS idx_inventory_product ON inventory_movements(product_id, id)")

        # ستون‌های فاکتور را قبل از ساخت ایندکس ایجاد می‌کنیم تا دیتابیس‌های نسخه‌های قدیمی
        # نیز بدون خطا مهاجرت کنند.
        self._ensure_column("sales", "invoice_no", "INTEGER")
        self._ensure_column("sales", "invoice_date", "TEXT")
        self._ensure_column("sales", "status", "TEXT DEFAULT 'فعال'")
        self._ensure_column("sales", "voided_at", "TEXT")
        self._ensure_column("sales", "void_reason", "TEXT DEFAULT ''")
        self._ensure_column("sales", "check_id", "INTEGER")

        self.con.execute("""
            UPDATE sales SET invoice_date = substr(created_at, 1, 10)
            WHERE invoice_date IS NULL OR invoice_date=''
        """)

        old_dates = self.con.execute("""
            SELECT DISTINCT invoice_date FROM sales
            WHERE invoice_no IS NULL AND invoice_date IS NOT NULL
        """).fetchall()
        for (inv_date,) in old_dates:
            rows = self.con.execute("""
                SELECT id FROM sales WHERE invoice_no IS NULL AND invoice_date=? ORDER BY id
            """, (inv_date,)).fetchall()
            max_no = self.con.execute("""
                SELECT COALESCE(MAX(invoice_no),0) FROM sales WHERE invoice_date=?
            """, (inv_date,)).fetchone()[0] or 0
            for offset, (sid,) in enumerate(rows, 1):
                self.con.execute("UPDATE sales SET invoice_no=? WHERE id=?", (int(max_no)+offset, sid))

        # قبلاً اگر حتی یک جفت (تاریخ فاکتور، شماره فاکتور) تکراری در داده قدیمی پیدا می‌شد،
        # ساخت ایندکس یکتا برای همیشه نادیده گرفته می‌شد (بدون هیچ هشداری) و محافظ یکتایی
        # شماره فاکتور برای کل آینده برنامه غیرفعال می‌ماند. اکنون به‌جای نادیده گرفتن، خود
        # رکوردهای تکراری شماره‌گذاری مجدد می‌شوند و سپس ایندکس یکتا همیشه ساخته می‌شود.
        duplicate_groups = self.con.execute("""
            SELECT invoice_date, invoice_no, COUNT(*) c FROM sales
            WHERE invoice_date IS NOT NULL AND invoice_no IS NOT NULL
            GROUP BY invoice_date, invoice_no HAVING c > 1
        """).fetchall()
        fixed_count = 0
        for grp in duplicate_groups:
            inv_date, inv_no = grp["invoice_date"], grp["invoice_no"]
            rows = self.con.execute(
                "SELECT id FROM sales WHERE invoice_date=? AND invoice_no=? ORDER BY id",
                (inv_date, inv_no)
            ).fetchall()
            # اولین رکورد (کمترین id) شماره فعلی را نگه می‌دارد؛ بقیه به شماره‌های بعدی
            # همان تاریخ منتقل می‌شوند تا هیچ فاکتوری گم یا بازنویسی نشود.
            for extra_row in rows[1:]:
                max_no = self.con.execute(
                    "SELECT COALESCE(MAX(invoice_no),0) FROM sales WHERE invoice_date=?",
                    (inv_date,)
                ).fetchone()[0] or 0
                new_no = int(max_no) + 1
                self.con.execute(
                    "UPDATE sales SET invoice_no=? WHERE id=?",
                    (new_no, extra_row["id"])
                )
                fixed_count += 1
        self._pending_invoice_dedup_count = fixed_count
        self.con.execute("""
            CREATE UNIQUE INDEX IF NOT EXISTS idx_sales_invoice_unique
            ON sales(invoice_date, invoice_no) WHERE invoice_no IS NOT NULL
        """)

        # ایندکس‌های کمکی برای سرعت جستجو و گزارش
        self.con.execute("CREATE INDEX IF NOT EXISTS idx_customers_name ON customers(name)")
        self.con.execute("CREATE INDEX IF NOT EXISTS idx_customers_phone ON customers(phone)")
        self.con.execute("CREATE INDEX IF NOT EXISTS idx_sales_customer ON sales(customer_id)")
        self.con.execute("CREATE INDEX IF NOT EXISTS idx_sales_created ON sales(created_at)")
        self.con.execute("CREATE INDEX IF NOT EXISTS idx_sales_status ON sales(status)")
        self.con.execute("CREATE INDEX IF NOT EXISTS idx_checks_due ON checks(due_date, status, type)")
        self.con.execute("CREATE INDEX IF NOT EXISTS idx_checks_person ON checks(person)")
        self.con.execute("CREATE INDEX IF NOT EXISTS idx_products_barcode ON products(barcode)")
        self.con.execute("CREATE INDEX IF NOT EXISTS idx_account_tx_customer ON account_transactions(customer_id, transaction_type)")

        # دسته‌های موجود در محصولات قدیمی را نیز وارد دفتر دسته‌بندی می‌کنیم.
        self.con.execute("INSERT OR IGNORE INTO product_categories(name, created_at) SELECT DISTINCT TRIM(category), ? FROM products WHERE TRIM(COALESCE(category,'')) <> ''", (now(),))
        for default_category in ("سایر", "PDR", "ابزار", "دستگاه", "مصرفی", "تجهیزات"):
            self.con.execute("INSERT OR IGNORE INTO product_categories(name, created_at) VALUES(?,?)", (default_category, now()))

        self.con.commit()
        # این لاگ عمداً بعد از commit نوشته می‌شود: log_audit یک اتصال جدید به همان فایل
        # باز می‌کند و اگر قبل از commit صدا زده می‌شد، ممکن بود تا رهاشدن قفل نوشتن منتظر بماند.
        fixed_count = getattr(self, "_pending_invoice_dedup_count", 0)
        if fixed_count:
            log_audit(
                "invoice_dedup_migration",
                f"{fixed_count} فاکتور با شماره تکراری قدیمی به‌صورت خودکار شماره‌گذاری مجدد شد."
            )

    def _prepare_legacy_recipe_tables(self):
        tables = {
            row[0] for row in self.con.execute(
                "SELECT name FROM sqlite_master WHERE type='table'"
            ).fetchall()
        }
        if "recipes" in tables:
            columns = {
                row[1] for row in self.con.execute("PRAGMA table_info(recipes)").fetchall()
            }
            if not {"name", "instructions"}.issubset(columns):
                if "recipes_legacy_v1" in tables:
                    raise RuntimeError("ساختار قدیمی رسپی‌ها قبلاً پشتیبان‌گیری شده است.")
                self.con.execute("ALTER TABLE recipes RENAME TO recipes_legacy_v1")
                tables.remove("recipes")
                tables.add("recipes_legacy_v1")
        if "recipe_items" in tables:
            columns = {
                row[1] for row in self.con.execute("PRAGMA table_info(recipe_items)").fetchall()
            }
            if not {"product_id", "quantity"}.issubset(columns):
                if "recipe_items_legacy_v1" in tables:
                    raise RuntimeError("ساختار قدیمی مواد رسپی قبلاً پشتیبان‌گیری شده است.")
                self.con.execute("ALTER TABLE recipe_items RENAME TO recipe_items_legacy_v1")

    def _migrate_legacy_recipe_data(self):
        tables = {
            row[0] for row in self.con.execute(
                "SELECT name FROM sqlite_master WHERE type='table'"
            ).fetchall()
        }
        if "recipes_legacy_v1" not in tables:
            return
        self.con.execute(
            """INSERT OR IGNORE INTO recipes(id, name, instructions, created_at)
               SELECT old.id, COALESCE(NULLIF(TRIM(p.name), ''), 'رسپی ' || old.id),
                      '', COALESCE(NULLIF(old.created_at, ''), ?)
               FROM recipes_legacy_v1 old
               LEFT JOIN products p ON p.id=old.product_id""",
            (now(),)
        )
        if "recipe_items_legacy_v1" in tables:
            self.con.execute(
                """INSERT OR IGNORE INTO recipe_items(id, recipe_id, product_id, quantity)
                   SELECT old_item.id, old_item.recipe_id, old_item.ingredient_id,
                          CAST(old_item.qty AS REAL)
                   FROM recipe_items_legacy_v1 old_item
                   JOIN recipes r ON r.id=old_item.recipe_id
                   JOIN products p ON p.id=old_item.ingredient_id
                   WHERE CAST(old_item.qty AS REAL) > 0"""
            )

    def recipes(self):
        return self.con.execute(
            """SELECT r.id, r.name, r.instructions,
                      COUNT(ri.id) AS ingredient_count,
                      COALESCE(SUM(ri.quantity * p.buy_price), 0) AS total_cost
               FROM recipes r
               LEFT JOIN recipe_items ri ON ri.recipe_id=r.id
               LEFT JOIN products p ON p.id=ri.product_id
               GROUP BY r.id
               ORDER BY r.name COLLATE NOCASE"""
        ).fetchall()

    def recipe_detail(self, recipe_id):
        recipe = self.con.execute(
            "SELECT * FROM recipes WHERE id=?", (int(recipe_id),)
        ).fetchone()
        if not recipe:
            return None, []
        ingredients = self.con.execute(
            """SELECT ri.product_id, ri.quantity, p.name, p.unit, p.buy_price,
                      ri.quantity * p.buy_price AS line_cost
               FROM recipe_items ri
               JOIN products p ON p.id=ri.product_id
               WHERE ri.recipe_id=?
               ORDER BY p.name COLLATE NOCASE""",
            (int(recipe_id),)
        ).fetchall()
        return recipe, ingredients

    def save_recipe(self, name, instructions, ingredients, recipe_id=None):
        name = " ".join(str(name or "").strip().split())
        if not name:
            raise ValueError("نام رسپی را وارد کنید.")
        if not ingredients:
            raise ValueError("حداقل یک ماده اولیه برای رسپی ثبت کنید.")
        prepared = []
        seen = set()
        for product_id, quantity in ingredients:
            product_id = int(product_id)
            quantity = float(quantity)
            if quantity <= 0:
                raise ValueError("مقدار مواد اولیه باید بیشتر از صفر باشد.")
            if product_id in seen:
                raise ValueError("هر ماده اولیه را فقط یک‌بار به رسپی اضافه کنید.")
            seen.add(product_id)
            product = self.con.execute(
                "SELECT id FROM products WHERE id=?", (product_id,)
            ).fetchone()
            if not product:
                raise ValueError("یکی از مواد اولیه دیگر در فهرست محصولات وجود ندارد.")
            prepared.append((product_id, quantity))

        cur = self.con.cursor()
        try:
            cur.execute("BEGIN")
            if recipe_id is None:
                cur.execute(
                    "INSERT INTO recipes(name, instructions, created_at) VALUES(?,?,?)",
                    (name, str(instructions or "").strip(), now())
                )
                recipe_id = int(cur.lastrowid)
            else:
                recipe_id = int(recipe_id)
                cur.execute(
                    "UPDATE recipes SET name=?, instructions=? WHERE id=?",
                    (name, str(instructions or "").strip(), recipe_id)
                )
                if cur.rowcount == 0:
                    raise ValueError("رسپی انتخاب‌شده پیدا نشد.")
                cur.execute("DELETE FROM recipe_items WHERE recipe_id=?", (recipe_id,))
            cur.executemany(
                "INSERT INTO recipe_items(recipe_id, product_id, quantity) VALUES(?,?,?)",
                [(recipe_id, product_id, quantity) for product_id, quantity in prepared]
            )
            self.con.commit()
            return recipe_id
        except Exception:
            self.con.rollback()
            raise

    def delete_recipe(self, recipe_id):
        self.con.execute("DELETE FROM recipes WHERE id=?", (int(recipe_id),))
        self.con.commit()

    def categories(self):
        return [r[0] for r in self.con.execute("SELECT name FROM product_categories ORDER BY name COLLATE NOCASE").fetchall()]

    def add_category(self, name):
        name = " ".join(str(name or "").strip().split())
        if not name:
            raise ValueError("نام دسته‌بندی را وارد کنید.")
        self.con.execute("INSERT OR IGNORE INTO product_categories(name, created_at) VALUES(?,?)", (name, now()))
        self.con.commit()
        return name

    def ensure_category(self, name):
        name = " ".join(str(name or "").strip().split()) or "سایر"
        self.con.execute("INSERT OR IGNORE INTO product_categories(name, created_at) VALUES(?,?)", (name, now()))
        return name

    def delete_category(self, name):
        """حذف دسته‌بندی؛ محصولات آن دسته برای حفظ اطلاعات به «سایر» منتقل می‌شوند."""
        name = " ".join(str(name or "").strip().split())
        if not name:
            raise ValueError("دسته‌بندی نامعتبر است.")
        if name == "سایر":
            raise ValueError("دسته «سایر» قابل حذف نیست؛ چون دسته پیش‌فرض برنامه است.")
        row = self.con.execute("SELECT 1 FROM product_categories WHERE name=?", (name,)).fetchone()
        if not row:
            raise ValueError("دسته‌بندی پیدا نشد.")

        try:
            self.con.execute("BEGIN IMMEDIATE")
            # اگر محصولی در این دسته باشد، با حذف دسته نباید دسته محصول خالی شود.
            moved = self.con.execute(
                "SELECT COUNT(*) FROM products WHERE category=?", (name,)
            ).fetchone()[0]
            self.con.execute("UPDATE products SET category='سایر' WHERE category=?", (name,))
            self.con.execute("DELETE FROM product_categories WHERE name=?", (name,))
            self.con.commit()
            return int(moved or 0)
        except Exception:
            self.con.rollback()
            raise

    def reconcile_all_customer_balances(self):
        rows = self.con.execute("SELECT id FROM customers").fetchall()
        for r in rows:
            self.recompute_customer_balance(int(r[0]))
        self.con.commit()

    def _ensure_column(self, table, column, definition):
        columns = {r[1] for r in self.con.execute(f"PRAGMA table_info({table})").fetchall()}
        if column not in columns:
            self.con.execute(f"ALTER TABLE {table} ADD COLUMN {column} {definition}")

    def _upgrade_plaintext_password(self):
        """رمز قدیمی متنی را به hash ارتقا می‌دهد تا در فایل دیتابیس خوانا نماند."""
        try:
            stored = str(self.get_setting("app_password", "") or "").strip()
            if stored and not stored.startswith("pbkdf2$"):
                self.set_setting("app_password", _hash_password(stored))
        except Exception as e:
            _log_error("_upgrade_plaintext_password", e)

    def _normalize_legacy_dates(self):
        """تاریخ چک‌های قدیمی که شمسی ذخیره شده‌اند را به میلادی ISO تبدیل می‌کند."""
        try:
            rows = self.con.execute("SELECT id, due_date, issue_date FROM checks").fetchall()
            changed = False
            for r in rows:
                for col in ("due_date", "issue_date"):
                    val = r[col]
                    if not val:
                        continue
                    raw = str(val).strip()
                    if len(raw) >= 10 and raw[4] == "-" and raw[7] == "-":
                        continue
                    try:
                        normalized = normalize_date_input(raw, default_today=False)
                    except Exception:
                        continue
                    if normalized != raw:
                        self.con.execute(f"UPDATE checks SET {col}=? WHERE id=?", (normalized, int(r["id"])))
                        changed = True
            if changed:
                self.con.commit()
        except Exception as e:
            _log_error("_normalize_legacy_dates", e)

    def get_setting(self, key, default=""):
        row=self.con.execute("SELECT value FROM app_settings WHERE key=?",(key,)).fetchone()
        return str(row[0]) if row else default

    def set_setting(self, key, value):
        self.con.execute("INSERT INTO app_settings(key,value) VALUES(?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value",(key,str(value)))
        self.con.commit()

    def settings(self):
        return {r["key"]: r["value"] for r in self.con.execute("SELECT key,value FROM app_settings").fetchall()}

    def seed(self):
        """کالای نمونه درج نمی‌شود تا موجودی واقعی فروشگاه در نصب اول خراب نشود."""
        return

    def products(self, search="", category="همه دسته‌ها"):
        sql = "SELECT * FROM products WHERE COALESCE(active,1)=1"
        args = []
        if search:
            sql += " AND (name LIKE ? OR category LIKE ? OR barcode LIKE ?)"
            x = f"%{search}%"
            args += [x, x, x]
        if category != "همه دسته‌ها":
            sql += " AND category=?"
            args.append(category)
        sql += " ORDER BY id DESC"
        return self.con.execute(sql, args).fetchall()

    def product(self, pid):
        return self.con.execute("SELECT * FROM products WHERE id=?", (pid,)).fetchone()

    def _validate_product_data(self, d, pid=None):
        name, category, buy, sell, stock, min_stock, barcode, unit = d
        if not str(name).strip(): raise ValueError("نام محصول الزامی است")
        if any(v < 0 for v in (to_decimal(buy), to_decimal(sell), to_decimal(stock), to_decimal(min_stock))):
            raise ValueError("قیمت‌ها و موجودی نمی‌توانند منفی باشند")
        code = str(barcode or '').strip()
        if code:
            q="SELECT id FROM products WHERE barcode=? AND COALESCE(active,1)=1"
            args=[code]
            if pid is not None: q += " AND id<>?"; args.append(int(pid))
            if self.con.execute(q,args).fetchone(): raise ValueError("این بارکد قبلاً برای یک محصول فعال ثبت شده است")

    def add_product(self, d):
        self._validate_product_data(d)
        name, category, buy, sell, stock, min_stock, barcode, unit = d
        category = self.ensure_category(category)
        self.con.execute("""
        INSERT INTO products(name,category,buy_price,sell_price,stock,min_stock,barcode,unit,active)
        VALUES(?,?,?,?,?,?,?,?,1)
        """, (name,category,int(money_decimal(buy)),int(money_decimal(sell)),str(to_decimal(stock)),str(to_decimal(min_stock)),barcode,unit))
        pid=self.con.execute("SELECT last_insert_rowid()").fetchone()[0]
        if to_decimal(stock) > 0:
            self.con.execute("""INSERT INTO inventory_movements
                (product_id,movement_type,qty,reference_id,description,created_at,unit_cost)
                VALUES(?,?,?,?,?,?,?)""",
                (pid,"ورود اولیه",str(to_decimal(stock)),pid,"موجودی اولیه کالا",now(),int(money_decimal(buy))))
        self.con.commit()

    def update_product(self, pid, d):
        self._validate_product_data(d, pid)
        name, category, buy, sell, stock, min_stock, barcode, unit = d
        category = self.ensure_category(category)
        old=self.product(pid)
        if not old: raise ValueError("محصول پیدا نشد")
        self.con.execute("""
        UPDATE products SET name=?,category=?,sell_price=?,
        min_stock=?,barcode=?,unit=? WHERE id=?
        """, (name,category,int(money_decimal(sell)),str(to_decimal(min_stock)),barcode,unit,pid))
        # بهای خرید از لایه‌های FIFO است؛ فرم ویرایش نباید میانگین را overwrite کند.
        self._rebuild_product_average_cost(self.con.cursor(), int(pid))
        self.con.commit()

    def adjust_stock(self, pid, qty, description="اصلاح موجودی"):
        """
        اصلاح موجودی با حفظ لایه بهای تمام‌شده.
        ورود اصلاحی به عنوان یک لایه FIFO با بهای فعلی کالا ثبت می‌شود؛
        خروج اصلاحی فقط موجودی را کم می‌کند و لایه‌های FIFO را دستکاری نمی‌کند.
        """
        qty_d = to_decimal(qty)
        if qty_d == 0:
            raise ValueError("مقدار اصلاح موجودی نمی‌تواند صفر باشد")
        cur = self.con.cursor()
        try:
            cur.execute("BEGIN IMMEDIATE")
            row = cur.execute("SELECT stock,buy_price FROM products WHERE id=?", (int(pid),)).fetchone()
            if not row:
                raise ValueError("محصول پیدا نشد")
            stock = to_decimal(row["stock"] or 0)
            new_stock = stock + qty_d
            if new_stock < 0:
                raise ValueError("موجودی نمی‌تواند منفی شود")
            unit_cost = money_decimal(row["buy_price"] or 0) if qty_d > 0 else Decimal("0")
            cur.execute("UPDATE products SET stock=? WHERE id=?", (str(new_stock), int(pid)))
            cur.execute(
                """INSERT INTO inventory_movements
                   (product_id,movement_type,qty,reference_id,description,created_at,unit_cost)
                   VALUES(?,?,?,?,?,?,?)""",
                (int(pid), "اصلاح", str(qty_d), int(pid), description, now(), int(unit_cost))
            )
            self._rebuild_product_average_cost(cur, int(pid))
            self.con.commit()
        except Exception:
            self.con.rollback()
            raise

    def delete_product(self, pid):
        self.con.execute("UPDATE products SET active=0 WHERE id=?", (pid,))
        self.con.commit()
        log_audit("delete_product", f"product_id={pid}")

    def restore_product(self, pid):
        row = self.con.execute("SELECT id,barcode FROM products WHERE id=?", (int(pid),)).fetchone()
        if not row:
            raise ValueError("محصول پیدا نشد")
        code = str(row["barcode"] or "").strip()
        if code:
            conflict = self.con.execute(
                "SELECT id,name FROM products WHERE barcode=? AND COALESCE(active,1)=1 AND id<>? LIMIT 1",
                (code, int(pid))
            ).fetchone()
            if conflict:
                raise ValueError(f"بازیابی ممکن نیست؛ بارکد «{code}» در محصول فعال دیگری ثبت شده است.")
        self.con.execute("UPDATE products SET active=1 WHERE id=?", (int(pid),))
        self.con.commit()

    def list_inactive_products(self):
        return self.con.execute("SELECT * FROM products WHERE COALESCE(active,1)=0 ORDER BY id DESC").fetchall()

    def next_invoice_no(self, invoice_date=None):
        invoice_date = invoice_date or date.today().isoformat()
        row=self.con.execute("SELECT COALESCE(MAX(invoice_no),0) FROM sales WHERE invoice_date=?",(invoice_date,)).fetchone()
        return int(row[0] or 0)+1


    def _fifo_cache_begin(self):
        self._fifo_cache = {}

    def _fifo_cache_end(self):
        self._fifo_cache = None

    def _fifo_cache_invalidate(self, product_id=None):
        cache = getattr(self, "_fifo_cache", None)
        if not isinstance(cache, dict):
            return
        if product_id is None:
            cache.clear()
        else:
            cache.pop(int(product_id), None)

    def _build_fifo_layers(self, cur, product_id):
        """ساخت لایه‌های واقعی FIFO از روی گردش انبار، با ترتیب قطعی movement id."""
        pid = int(product_id)
        cache = getattr(self, "_fifo_cache", None)
        if isinstance(cache, dict) and pid in cache:
            return deepcopy(cache[pid])
        layers = []
        legacy_cursor = {}

        movements = cur.execute(
            """SELECT id,movement_type,qty,reference_id,reference_item_id,created_at,
                      COALESCE(unit_cost,0) unit_cost
               FROM inventory_movements
              WHERE product_id=? AND qty<>0
              ORDER BY id""",
            (pid,)
        ).fetchall()

        positive_kinds = {"موجودی اولیه", "ورود اولیه", "ورود خرید", "اصلاح",
                          "اصلاح خرید", "مرجوعی فروش", "مرجوعی اینستاگرام"}
        removal_kinds = {"اصلاح", "اصلاح خرید", "ابطال خرید"}

        def consume_fifo(amount, preferred_item_id=None, newest=False):
            remaining = max(Decimal("0"), to_decimal(amount))
            if remaining <= Decimal("0.000001"):
                return
            if preferred_item_id:
                for layer in layers:
                    if layer.get("item_id") == int(preferred_item_id) and layer["remaining"] > Decimal("0.000001"):
                        take = min(layer["remaining"], remaining)
                        layer["remaining"] -= take
                        remaining -= take
                        break
            if remaining > Decimal("0.000001"):
                seq = reversed(layers) if newest else layers
                for layer in seq:
                    if remaining <= Decimal("0.000001"):
                        break
                    take = min(layer["remaining"], remaining)
                    layer["remaining"] -= take
                    remaining -= take

        for m in movements:
            raw_qty = to_decimal(m["qty"] or 0)
            kind = m["movement_type"]
            ref_item_id = m["reference_item_id"]

            if kind in removal_kinds and raw_qty < -Decimal("0.000001"):
                # ابطال/اصلاح خرید: اگر purchase_item مشخص است، دقیقاً همان لایه را کم کن.
                # اصلاح منفی عمومی موجودی: از جدیدترین لایه‌ها کم می‌کنیم تا سابقه بهای قدیمی حفظ شود.
                consume_fifo(-raw_qty, preferred_item_id=ref_item_id,
                              newest=(ref_item_id is None))
                continue

            if kind in ("خروج فروش", "خروج اینستاگرام"):
                ref_id = int(m["reference_id"] or 0) if m["reference_id"] else 0
                if kind == "خروج فروش":
                    sr = cur.execute(
                        "SELECT status FROM sales WHERE id=?",
                        (ref_id,)
                    ).fetchone()
                    # در بازسازی وضعیت فعلی، فاکتور باطل‌شده نباید نه خروجش
                    # و نه مرجوعی متناظر آن در لایه‌های FIFO اثر داشته باشد.
                    if sr and (sr["status"] or "فعال") == "باطل":
                        continue
                else:
                    orow = cur.execute(
                        "SELECT status FROM instagram_orders WHERE id=?",
                        (ref_id,)
                    ).fetchone()
                    if orow and (orow["status"] or "") == "لغو شد":
                        continue
                consume_fifo(abs(raw_qty), newest=False)
                continue

            if raw_qty <= Decimal("0.000001") or kind not in positive_kinds:
                continue

            qty = raw_qty
            cost = money_decimal(m["unit_cost"] or 0)
            item_id = None
            purchase_id = None

            if kind in ("ورود خرید", "اصلاح خرید"):
                # هم ورود خرید و هم اصلاح مثبت خرید باید به همان purchase_item وصل شوند؛
                # وگرنه ویرایش دوم موجودی را باد می‌کند و ابطال بعد از ویرایش شکست می‌خورد.
                purchase_id = int(m["reference_id"] or 0) if m["reference_id"] else None
                if ref_item_id:
                    item_id = int(ref_item_id)
                    pr = cur.execute(
                        "SELECT id,product_id,qty,price,COALESCE(cancelled_qty,0) cancelled_qty "
                        "FROM purchase_items WHERE id=?",
                        (int(ref_item_id),)
                    ).fetchone()
                    if pr:
                        cost = money_decimal(pr["price"] or 0)
                        # movement qty معیار اصلی است؛ cancelled_qty در گردش‌های جدید
                        # با movement منفی اعمال می‌شود تا دوباره کسر نشود.
                        qty = min(qty, max(Decimal("0"), to_decimal(pr["qty"] or 0)))
                elif kind == "ورود خرید":
                    # سازگاری با دیتابیس‌های قدیمی که reference_item_id ندارند.
                    prs = cur.execute(
                        "SELECT id,qty,price FROM purchase_items "
                        "WHERE purchase_id=? AND product_id=? ORDER BY id",
                        (purchase_id, pid)
                    ).fetchall()
                    idx = legacy_cursor.get(purchase_id, 0)
                    if idx < len(prs):
                        pr = prs[idx]
                        legacy_cursor[purchase_id] = idx + 1
                        item_id = int(pr["id"])
                        qty = min(qty, max(Decimal("0"), to_decimal(pr["qty"] or 0)))
                        cost = money_decimal(pr["price"] or 0)

            elif kind in ("مرجوعی فروش", "مرجوعی اینستاگرام"):
                ref_id = int(m["reference_id"] or 0) if m["reference_id"] else 0
                if kind == "مرجوعی فروش":
                    status_row = cur.execute(
                        "SELECT status FROM sales WHERE id=?",
                        (ref_id,)
                    ).fetchone()
                    # مرجوعیِ فاکتور باطل‌شده در بازسازی فعلی دوباره اضافه نمی‌شود؛
                    # خودِ خروج آن فاکتور نیز در بالا نادیده گرفته شده است.
                    if status_row and (status_row["status"] or "فعال") == "باطل":
                        continue
                    cost = money_decimal(m["unit_cost"] or 0)
                    if cost <= 0:
                        sr = cur.execute(
                            "SELECT buy_price FROM sale_items WHERE sale_id=? AND product_id=? ORDER BY id LIMIT 1",
                            (ref_id, pid)
                        ).fetchone()
                        if sr:
                            cost = money_decimal(sr["buy_price"] or 0)
                else:
                    orow = cur.execute(
                        "SELECT status FROM instagram_orders WHERE id=?",
                        (ref_id,)
                    ).fetchone()
                    if orow and (orow["status"] or "") == "لغو شد":
                        continue
                    cost = money_decimal(m["unit_cost"] or 0)
                    if cost <= 0:
                        sr = cur.execute(
                            "SELECT buy_price FROM instagram_order_items WHERE order_id=? AND product_id=? ORDER BY id LIMIT 1",
                            (ref_id, pid)
                        ).fetchone()
                        if sr:
                            cost = money_decimal(sr["buy_price"] or 0)

            layers.append({
                "kind": kind, "purchase_id": purchase_id, "item_id": item_id,
                "qty": qty, "remaining": qty, "cost": cost,
                "created_at": m["created_at"] or "", "movement_id": int(m["id"])
            })

        cache = getattr(self, "_fifo_cache", None)
        if isinstance(cache, dict):
            cache[pid] = deepcopy(layers)
        return layers


    def _fifo_cost_for_sale(self, cur, product_id, qty):
        """محاسبه بهای تمام‌شده فروش بر مبنای لایه‌های FIFO تاریخی."""
        need = max(Decimal("0"), to_decimal(qty))
        if need <= Decimal("0.000001"):
            return Decimal("0")
        layers = self._build_fifo_layers(cur, int(product_id))
        total_cost = Decimal("0")
        for layer in layers:
            if need <= Decimal("0.000001"):
                break
            take = min(layer["remaining"], need)
            total_cost += take * layer["cost"]
            need -= take
        if need > Decimal("0.000001"):
            row = cur.execute("SELECT buy_price FROM products WHERE id=?", (int(product_id),)).fetchone()
            fallback = money_decimal(row["buy_price"] if row else 0)
            total_cost += need * fallback
        return money_decimal(total_cost)

    def save_sale(self, cart, customer_id, discount, payment, invoice_no=None, invoice_date=None, check_data=None):
        if not cart:
            raise ValueError("فاکتور خالی است")
        invoice_date = normalize_date_input(invoice_date) if invoice_date else date.today().isoformat()
        if payment in ("نسیه", "چک") and not customer_id:
            raise ValueError("برای فروش نسیه یا چکی باید مشتری انتخاب شود.")
        if payment == "چک" and not check_data:
            raise ValueError("اطلاعات چک را وارد کنید.")

        cur = self.con.cursor()
        self._fifo_cache_begin()
        try:
            cur.execute("BEGIN IMMEDIATE")
            if invoice_no is None:
                invoice_no = self.next_invoice_no(invoice_date)
            while cur.execute("SELECT 1 FROM sales WHERE invoice_date=? AND invoice_no=?", (invoice_date, invoice_no)).fetchone():
                invoice_no += 1

            # تجمیع تعداد هر کالا قبل از بررسی موجودی؛ اگر یک کالا چند بار در
            # سبد آمده باشد، کل مقدار آن کالا باید با موجودی مقایسه شود.
            requested_by_pid = {}
            for x in cart:
                pid = int(x["id"])
                qty = to_decimal(x["qty"])
                if qty <= 0:
                    raise ValueError(f"تعداد کالای «{x.get('name', pid)}» نامعتبر است.")
                requested_by_pid[pid] = requested_by_pid.get(pid, Decimal("0")) + qty

            stock_by_pid = {}
            for pid, requested_qty in requested_by_pid.items():
                row = cur.execute(
                    "SELECT name,stock FROM products WHERE id=? AND COALESCE(active,1)=1",
                    (pid,)
                ).fetchone()
                if not row:
                    raise ValueError("یکی از کالاهای فاکتور پیدا نشد یا غیرفعال است.")
                stock = to_decimal(row["stock"] or 0)
                if stock < requested_qty:
                    raise ValueError(
                        f"موجودی کالای «{row['name']}» کافی نیست. "
                        f"موجودی: {format_qty(stock)} | درخواست: {format_qty(requested_qty)}"
                    )
                stock_by_pid[pid] = stock

            prepared = []
            total = Decimal("0")
            discount_total = Decimal("0")
            profit = Decimal("0")
            for x in cart:
                row = cur.execute(
                    "SELECT name,stock,buy_price FROM products WHERE id=? AND COALESCE(active,1)=1",
                    (x["id"],)
                ).fetchone()
                if not row:
                    raise ValueError(f"کالای «{x['name']}» پیدا نشد.")
                qty_d = to_decimal(x["qty"])
                gross = to_decimal(x["price"]) * qty_d
                line_discount = max(Decimal("0"), min(to_decimal(x.get("discount", 0) or 0), gross))
                line_final = max(Decimal("0"), money_decimal(gross - line_discount))
                prepared.append((x, row, line_discount, line_final))
                total += line_final
                discount_total += line_discount

            total = money_decimal(total)
            discount = money_decimal(discount_total)

            # بهای تمام‌شده این فاکتور از لایه‌های FIFO واقعی محاسبه می‌شود.
            fifo_cost_by_pid = {}
            for pid, requested_qty in requested_by_pid.items():
                fifo_cost_by_pid[pid] = self._fifo_cost_for_sale(cur, pid, requested_qty)
            profit = Decimal("0")
            for x, row, line_discount, line_final in prepared:
                pid = int(x["id"])
                total_qty = requested_by_pid[pid]
                unit_fifo = fifo_cost_by_pid[pid] / total_qty if total_qty else Decimal("0")
                profit += line_final - (unit_fifo * to_decimal(x["qty"]))
            profit = money_decimal(profit)

            cur.execute(
                """INSERT INTO sales(customer_id,total,profit,discount,payment,created_at,invoice_no,invoice_date,status)
                   VALUES(?,?,?,?,?,?,?,?,?)""",
                (customer_id, int(total), int(profit), int(discount), payment, now(), invoice_no, invoice_date, "فعال")
            )
            sid = cur.lastrowid

            for x, row, line_discount, line_final in prepared:
                q = to_decimal(x["qty"])
                pid = int(x["id"])
                total_qty = requested_by_pid[pid]
                fifo_unit_cost = fifo_cost_by_pid[pid] / total_qty if total_qty else Decimal("0")
                cur.execute(
                    "INSERT INTO sale_items(sale_id,product_id,qty,price,buy_price,discount,final_price) VALUES(?,?,?,?,?,?,?)",
                    (sid, pid, str(q), int(money_decimal(x["price"])), str(fifo_unit_cost.quantize(Decimal("0.01"), rounding=ROUND_HALF_UP)),
                     int(money_decimal(line_discount)), int(line_final))
                )
                cur.execute("UPDATE products SET stock=stock-? WHERE id=?", (str(q), int(x["id"])))
                cur.execute(
                    """INSERT INTO inventory_movements
                       (product_id,movement_type,qty,reference_id,description,created_at,unit_cost)
                       VALUES(?,?,?,?,?,?,?)""",
                    (int(x["id"]), "خروج فروش", str(-q), sid, f"فروش فاکتور {invoice_no:04d}", now(), int(money_decimal(row["buy_price"] or 0)))
                )

            self._fifo_cache_invalidate()
            for pid in requested_by_pid:
                self._rebuild_product_average_cost(cur, pid)

            if payment == "نسیه":
                cur.execute(
                    "INSERT INTO account_transactions(customer_id,transaction_type,amount,description,sale_id,created_at) VALUES(?,?,?,?,?,?)",
                    (customer_id, "بدهکار", int(total), f"خرید نسیه - فاکتور {invoice_no:04d}", sid, now())
                )

            check_id = None
            if payment == "چک":
                cd = check_data or {}
                cur.execute(
                    """INSERT INTO checks(person,amount,due_date,type,status,notes,check_no,bank,branch,issue_date,customer_id,sale_id)
                       VALUES(?,?,?,?,?,?,?,?,?,?,?,?)""",
                    (cd.get("person", "") or "مشتری", int(money_decimal(total)), cd.get("due_date", invoice_date), "دریافتی", "در انتظار",
                     cd.get("notes", "") or f"چک فاکتور {invoice_no:04d}", cd.get("check_no", ""),
                     cd.get("bank", ""), cd.get("branch", ""), cd.get("issue_date", invoice_date), customer_id, sid)
                )
                check_id = cur.lastrowid
                cur.execute("UPDATE sales SET check_id=? WHERE id=?", (check_id, sid))

            self.con.commit()
        except Exception:
            self.con.rollback()
            raise
        finally:
            self._fifo_cache_end()
        if customer_id:
            self.recompute_customer_balance(customer_id)
        return sid, invoice_no, total, profit

    IG_STOCK_STATUSES = ("در حال آماده‌سازی", "ارسال شد", "تحویل شد")

    def find_or_create_customer(self, name, phone="", address="", cur=None):
        """مشتری را با تلفن یا نام پیدا می‌کند؛ در صورت نبود، مشتری جدید می‌سازد."""
        own = cur is None
        cur = cur or self.con.cursor()
        name = " ".join(str(name or "").strip().split())
        phone = str(phone or "").strip()
        address = str(address or "").strip()
        if not name:
            return None
        row = None
        if phone:
            row = cur.execute(
                "SELECT id FROM customers WHERE phone=? AND TRIM(COALESCE(phone,''))<>'' ORDER BY id LIMIT 1",
                (phone,),
            ).fetchone()
        if not row:
            row = cur.execute(
                "SELECT id FROM customers WHERE name=? ORDER BY id LIMIT 1",
                (name,),
            ).fetchone()
        if row:
            cid = int(row[0])
            if address:
                cur.execute(
                    "UPDATE customers SET address=CASE WHEN TRIM(COALESCE(address,''))='' THEN ? ELSE address END, "
                    "phone=CASE WHEN TRIM(COALESCE(phone,''))='' THEN ? ELSE phone END WHERE id=?",
                    (address, phone, cid),
                )
            if own:
                self.con.commit()
            return cid
        cur.execute(
            "INSERT INTO customers(name,phone,address,balance) VALUES(?,?,?,0)",
            (name, phone, address),
        )
        cid = int(cur.lastrowid)
        if own:
            self.con.commit()
        return cid

    def instagram_order_items(self, order_id):
        return self.con.execute(
            """SELECT i.*, p.name, p.stock, p.unit, p.sell_price
               FROM instagram_order_items i
               LEFT JOIN products p ON p.id=i.product_id
               WHERE i.order_id=?
               ORDER BY i.id""",
            (int(order_id),),
        ).fetchall()

    def instagram_cart(self, order_id):
        cart = []
        for r in self.instagram_order_items(order_id):
            if not r["product_id"]:
                continue
            cart.append({
                "id": int(r["product_id"]),
                "name": r["name"] or "کالا",
                "price": float(r["price"] or 0),
                "qty": float(r["qty"] or 0),
                "discount": float(r["discount"] or 0),
            })
        return cart

    def _prepare_instagram_items(self, items):
        prepared = []
        total = Decimal("0")
        discount_total = Decimal("0")
        for x in items or []:
            pid = int(x["id"])
            qty = to_decimal(x.get("qty", 0))
            if qty <= 0:
                raise ValueError("تعداد کالا باید بیشتر از صفر باشد.")
            price = money_decimal(x.get("price", 0))
            if price < 0:
                raise ValueError("قیمت کالا نمی‌تواند منفی باشد.")
            gross = price * qty
            line_discount = max(Decimal("0"), min(to_decimal(x.get("discount", 0) or 0), gross))
            line_final = max(Decimal("0"), money_decimal(gross - line_discount))
            prepared.append({
                "id": pid,
                "name": x.get("name") or "",
                "qty": qty,
                "price": price,
                "discount": line_discount,
                "final_price": line_final,
            })
            total += line_final
            discount_total += line_discount
        return prepared, money_decimal(total), money_decimal(discount_total)

    def _apply_instagram_stock(self, cur, order_id):
        order = cur.execute("SELECT * FROM instagram_orders WHERE id=?", (int(order_id),)).fetchone()
        if not order or int(order["stock_applied"] or 0):
            return
        items = cur.execute(
            "SELECT * FROM instagram_order_items WHERE order_id=?", (int(order_id),)
        ).fetchall()
        if not items:
            return
        requested = {}
        for it in items:
            pid = int(it["product_id"])
            requested[pid] = requested.get(pid, Decimal("0")) + to_decimal(it["qty"] or 0)
        for pid, qty in requested.items():
            row = cur.execute(
                "SELECT name,stock,buy_price FROM products WHERE id=? AND COALESCE(active,1)=1",
                (pid,),
            ).fetchone()
            if not row:
                raise ValueError("یکی از کالاهای سفارش پیدا نشد یا غیرفعال است.")
            stock = to_decimal(row["stock"] or 0)
            if stock < qty:
                raise ValueError(
                    f"موجودی کالای «{row['name']}» کافی نیست. "
                    f"موجودی: {format_qty(stock)} | سفارش: {format_qty(qty)}"
                )
        fifo_cost = {}
        for pid, qty in requested.items():
            fifo_cost[pid] = self._fifo_cost_for_sale(cur, pid, qty)
        for it in items:
            pid = int(it["product_id"])
            q = to_decimal(it["qty"] or 0)
            total_qty = requested[pid]
            unit_cost = (fifo_cost[pid] / total_qty) if total_qty else Decimal("0")
            cur.execute(
                "UPDATE instagram_order_items SET buy_price=? WHERE id=?",
                (str(unit_cost.quantize(Decimal("0.01"), rounding=ROUND_HALF_UP)), int(it["id"])),
            )
            cur.execute("UPDATE products SET stock=stock-? WHERE id=?", (str(q), pid))
            cur.execute(
                """INSERT INTO inventory_movements
                   (product_id,movement_type,qty,reference_id,description,created_at,unit_cost,reference_item_id)
                   VALUES(?,?,?,?,?,?,?,?)""",
                (pid, "خروج اینستاگرام", str(-q), int(order_id),
                 f"سفارش اینستاگرام {int(order_id)}", now(), int(money_decimal(unit_cost)), int(it["id"])),
            )
        self._fifo_cache_invalidate()
        for pid in requested:
            self._rebuild_product_average_cost(cur, pid)
        cur.execute("UPDATE instagram_orders SET stock_applied=1 WHERE id=?", (int(order_id),))

    def _release_instagram_stock(self, cur, order_id):
        order = cur.execute("SELECT * FROM instagram_orders WHERE id=?", (int(order_id),)).fetchone()
        if not order or not int(order["stock_applied"] or 0):
            return
        items = cur.execute(
            "SELECT * FROM instagram_order_items WHERE order_id=?", (int(order_id),)
        ).fetchall()
        touched = set()
        for it in items:
            pid = int(it["product_id"])
            q = to_decimal(it["qty"] or 0)
            unit_cost = money_decimal(it["buy_price"] or 0)
            cur.execute("UPDATE products SET stock=stock+? WHERE id=?", (str(q), pid))
            cur.execute(
                """INSERT INTO inventory_movements
                   (product_id,movement_type,qty,reference_id,description,created_at,unit_cost,reference_item_id)
                   VALUES(?,?,?,?,?,?,?,?)""",
                (pid, "مرجوعی اینستاگرام", str(q), int(order_id),
                 f"بازگشت سفارش اینستاگرام {int(order_id)}", now(), int(unit_cost), int(it["id"])),
            )
            touched.add(pid)
        self._fifo_cache_invalidate()
        for pid in touched:
            self._rebuild_product_average_cost(cur, pid)
        cur.execute("UPDATE instagram_orders SET stock_applied=0 WHERE id=?", (int(order_id),))

    def _active_sale_for_instagram(self, cur, sale_id):
        if not sale_id:
            return None
        row = cur.execute("SELECT * FROM sales WHERE id=?", (int(sale_id),)).fetchone()
        if row and (row["status"] or "فعال") == "فعال":
            return row
        return None

    def save_instagram_order(self, data, items, order_id=None):
        """ثبت یا ویرایش سفارش اینستاگرام با اقلام واقعی و همگام‌سازی موجودی."""
        name = " ".join(str(data.get("customer") or "").strip().split())
        if not name:
            raise ValueError("نام مشتری سفارش را وارد کنید.")
        status = str(data.get("status") or "جدید").strip() or "جدید"
        prepared, total, _discount = self._prepare_instagram_items(items)
        if status in self.IG_STOCK_STATUSES and not prepared:
            raise ValueError("برای آماده‌سازی، ارسال یا تحویل باید حداقل یک کالا به سفارش اضافه شود.")

        cur = self.con.cursor()
        self._fifo_cache_begin()
        try:
            cur.execute("BEGIN IMMEDIATE")
            customer_id = data.get("customer_id")
            if customer_id:
                customer_id = int(customer_id)
            else:
                customer_id = self.find_or_create_customer(
                    name, data.get("phone", ""), data.get("address", ""), cur=cur
                )

            old = None
            if order_id:
                old = cur.execute(
                    "SELECT * FROM instagram_orders WHERE id=?", (int(order_id),)
                ).fetchone()
                if not old:
                    raise ValueError("سفارش پیدا نشد.")
                active_sale = self._active_sale_for_instagram(cur, old["sale_id"])
                if active_sale and prepared:
                    old_items = cur.execute(
                        "SELECT product_id,qty,price,discount FROM instagram_order_items WHERE order_id=? ORDER BY id",
                        (int(order_id),),
                    ).fetchall()
                    new_sig = [(x["id"], str(x["qty"]), int(x["price"]), int(x["discount"])) for x in prepared]
                    old_sig = [
                        (int(r["product_id"]), str(to_decimal(r["qty"] or 0)),
                         int(money_decimal(r["price"] or 0)), int(money_decimal(r["discount"] or 0)))
                        for r in old_items
                    ]
                    if new_sig != old_sig:
                        raise ValueError(
                            "این سفارش فاکتور فعال دارد. برای تغییر کالاها ابتدا فاکتور را ابطال کنید."
                        )

            if old:
                if int(old["stock_applied"] or 0) and not old["sale_id"]:
                    self._release_instagram_stock(cur, int(order_id))
                if not self._active_sale_for_instagram(cur, old["sale_id"]):
                    cur.execute("DELETE FROM instagram_order_items WHERE order_id=?", (int(order_id),))
                    for x in prepared:
                        cur.execute(
                            """INSERT INTO instagram_order_items
                               (order_id,product_id,qty,price,discount,final_price,buy_price)
                               VALUES(?,?,?,?,?,?,0)""",
                            (int(order_id), x["id"], str(x["qty"]), int(x["price"]),
                             int(x["discount"]), int(x["final_price"])),
                        )
                cur.execute(
                    """UPDATE instagram_orders
                       SET customer=?, phone=?, total=?, status=?, address=?, notes=?,
                           customer_id=?, payment=?
                       WHERE id=?""",
                    (name, str(data.get("phone") or "").strip(), int(total), status,
                     str(data.get("address") or "").strip(), str(data.get("notes") or "").strip(),
                     customer_id, str(data.get("payment") or "").strip(), int(order_id)),
                )
                oid = int(order_id)
            else:
                cur.execute(
                    """INSERT INTO instagram_orders
                       (customer,phone,total,status,address,notes,created_at,customer_id,sale_id,payment,stock_applied)
                       VALUES(?,?,?,?,?,?,?,?,NULL,?,0)""",
                    (name, str(data.get("phone") or "").strip(), int(total), status,
                     str(data.get("address") or "").strip(), str(data.get("notes") or "").strip(),
                     now(), customer_id, str(data.get("payment") or "").strip()),
                )
                oid = int(cur.lastrowid)
                for x in prepared:
                    cur.execute(
                        """INSERT INTO instagram_order_items
                           (order_id,product_id,qty,price,discount,final_price,buy_price)
                           VALUES(?,?,?,?,?,?,0)""",
                        (oid, x["id"], str(x["qty"]), int(x["price"]),
                         int(x["discount"]), int(x["final_price"])),
                    )

            live = cur.execute("SELECT * FROM instagram_orders WHERE id=?", (oid,)).fetchone()
            if status == "لغو شد":
                if self._active_sale_for_instagram(cur, live["sale_id"]):
                    raise ValueError("برای لغو سفارشی که فاکتور فعال دارد، از دکمه «لغو سفارش» استفاده کنید تا فاکتور هم ابطال شود.")
                self._release_instagram_stock(cur, oid)
            elif status in self.IG_STOCK_STATUSES and not self._active_sale_for_instagram(cur, live["sale_id"]):
                self._apply_instagram_stock(cur, oid)

            self.con.commit()
        except Exception:
            self.con.rollback()
            raise
        finally:
            self._fifo_cache_end()
        if customer_id:
            self.recompute_customer_balance(customer_id)
        return oid, total

    def convert_instagram_to_sale(self, order_id, payment, check_data=None, invoice_date=None):
        """از سفارش اینستاگرام فاکتور فروش واقعی صادر می‌کند و به انبار و حساب دفتری وصل می‌شود."""
        order = self.con.execute(
            "SELECT * FROM instagram_orders WHERE id=?", (int(order_id),)
        ).fetchone()
        if not order:
            raise ValueError("سفارش پیدا نشد.")
        if (order["status"] or "") == "لغو شد":
            raise ValueError("سفارش لغوشده قابل تبدیل به فاکتور نیست.")
        if order["sale_id"]:
            sale = self.con.execute("SELECT id,status,invoice_no FROM sales WHERE id=?", (int(order["sale_id"]),)).fetchone()
            if sale and (sale["status"] or "فعال") == "فعال":
                raise ValueError(f"برای این سفارش قبلاً فاکتور {int(sale['invoice_no'] or sale['id']):04d} صادر شده است.")

        cart = self.instagram_cart(order_id)
        if not cart:
            raise ValueError("ابتدا کالاهای سفارش را مشخص کنید.")

        customer_id = order["customer_id"]
        if not customer_id:
            customer_id = self.find_or_create_customer(order["customer"], order["phone"], order["address"])

        if payment in ("نسیه", "چک") and not customer_id:
            raise ValueError("برای فروش نسیه یا چکی باید مشتری سفارش مشخص باشد.")

        # اگر موجودی قبلاً با سفارش رزرو شده، اول آزاد شود تا فاکتور دوباره از FIFO کم کند.
        cur = self.con.cursor()
        self._fifo_cache_begin()
        try:
            cur.execute("BEGIN IMMEDIATE")
            self._release_instagram_stock(cur, int(order_id))
            self.con.commit()
        except Exception:
            self.con.rollback()
            raise
        finally:
            self._fifo_cache_end()

        sid, invoice_no, total, profit = self.save_sale(
            cart, customer_id, 0, payment, None, invoice_date, check_data
        )
        self.con.execute(
            """UPDATE instagram_orders
               SET sale_id=?, payment=?, status='تحویل شد', stock_applied=0, customer_id=?, total=?
               WHERE id=?""",
            (int(sid), payment, customer_id, int(money_decimal(total)), int(order_id)),
        )
        self.con.commit()
        return sid, invoice_no, total, profit

    def cancel_instagram_order(self, order_id, reason="لغو سفارش اینستاگرام"):
        """لغو سفارش؛ فاکتور فعال ابطال و موجودی رزروشده به انبار برمی‌گردد."""
        order = self.con.execute(
            "SELECT * FROM instagram_orders WHERE id=?", (int(order_id),)
        ).fetchone()
        if not order:
            raise ValueError("سفارش پیدا نشد.")
        if (order["status"] or "") == "لغو شد" and not int(order["stock_applied"] or 0):
            return True
        if order["sale_id"]:
            sale = self.con.execute("SELECT status FROM sales WHERE id=?", (int(order["sale_id"]),)).fetchone()
            if sale and (sale["status"] or "فعال") == "فعال":
                self.void_sale(int(order["sale_id"]), reason)
        cur = self.con.cursor()
        self._fifo_cache_begin()
        try:
            cur.execute("BEGIN IMMEDIATE")
            self._release_instagram_stock(cur, int(order_id))
            cur.execute(
                "UPDATE instagram_orders SET status='لغو شد' WHERE id=?",
                (int(order_id),),
            )
            self.con.commit()
        except Exception:
            self.con.rollback()
            raise
        finally:
            self._fifo_cache_end()
        return True

    def delete_instagram_order(self, order_id):
        order = self.con.execute(
            "SELECT * FROM instagram_orders WHERE id=?", (int(order_id),)
        ).fetchone()
        if not order:
            raise ValueError("سفارش پیدا نشد.")
        if order["sale_id"]:
            sale = self.con.execute("SELECT status FROM sales WHERE id=?", (int(order["sale_id"]),)).fetchone()
            if sale and (sale["status"] or "فعال") == "فعال":
                raise ValueError("ابتدا فاکتور این سفارش را ابطال یا سفارش را لغو کنید.")
        if int(order["stock_applied"] or 0):
            raise ValueError("موجودی این سفارش هنوز از انبار کم شده است. ابتدا سفارش را لغو کنید.")
        self.con.execute("DELETE FROM instagram_order_items WHERE order_id=?", (int(order_id),))
        self.con.execute("DELETE FROM instagram_orders WHERE id=?", (int(order_id),))
        self.con.commit()

    def get_due_checks(self):
        """چک‌های دریافتی که سررسیدشان رسیده و هنوز تعیین تکلیف نشده‌اند."""
        today = date.today().isoformat()
        return self.con.execute(
            """SELECT * FROM checks
               WHERE type='دریافتی' AND status='در انتظار'
                 AND due_date IS NOT NULL AND due_date<>'' AND due_date<=?
               ORDER BY due_date, id""", (today,)
        ).fetchall()

    def set_check_status(self, check_id, status):
        """وضعیت چک را تغییر می‌دهد و در صورت برگشت چک دریافتی، بدهی مشتری را ثبت می‌کند."""
        row = self.con.execute("SELECT * FROM checks WHERE id=?", (check_id,)).fetchone()
        if not row:
            raise ValueError("چک پیدا نشد.")
        old_status = row["status"]
        if old_status == status:
            return

        cur = self.con.cursor()
        try:
            cur.execute("BEGIN IMMEDIATE")
            cur.execute("UPDATE checks SET status=? WHERE id=?", (status, check_id))

            # چک برگشتی یعنی مبلغ فروش چکی دیگر پرداخت محسوب نمی‌شود؛
            # بنابراین بدهی مشتری را فقط یک‌بار در دفتر ثبت می‌کنیم.
            # توجه: تطبیق روی check_id انجام می‌شود، نه sale_id — چون چک‌های
            # ثبت‌شده به‌صورت مستقل (بدون اتصال به فاکتور) همگی sale_id=NULL
            # دارند و «sale_id=?» در SQLite هرگز با NULL برابر نمی‌شود؛ این باعث
            # می‌شد بدهیِ برگشت چکِ مستقل هیچ‌وقت پاک نشود و با هر بار برگشت‌خوردن
            # دوباره، یک بدهی تکراری دیگر هم ثبت شود.
            if old_status == "برگشت خورد" and status != "برگشت خورد" and row["customer_id"]:
                cur.execute(
                    "DELETE FROM account_transactions WHERE check_id=? AND transaction_type='بدهکار' AND description LIKE '%برگشت چک%'",
                    (int(check_id),)
                )

            if status == "برگشت خورد" and row["type"] == "دریافتی" and row["customer_id"]:
                already = cur.execute(
                    "SELECT 1 FROM account_transactions WHERE check_id=? AND transaction_type='بدهکار' AND description LIKE '%برگشت چک%' LIMIT 1",
                    (int(check_id),)
                ).fetchone()
                if not already:
                    sale_no = None
                    if row["sale_id"]:
                        sr = cur.execute("SELECT invoice_no FROM sales WHERE id=?", (row["sale_id"],)).fetchone()
                        sale_no = sr["invoice_no"] if sr else None
                    desc = f"برگشت چک شماره {row['check_no'] or '-'}"
                    if sale_no:
                        desc += f" - فاکتور {int(sale_no):04d}"
                    cur.execute(
                        "INSERT INTO account_transactions(customer_id,transaction_type,amount,description,sale_id,check_id,created_at) VALUES(?,?,?,?,?,?,?)",
                        (row["customer_id"], "بدهکار", int(money_decimal(row["amount"] or 0)), desc, row["sale_id"], int(check_id), now())
                    )

            self.con.commit()
        except Exception:
            self.con.rollback()
            raise

        if row["customer_id"]:
            self.recompute_customer_balance(row["customer_id"])

    def add_purchase(self, supplier, items, notes=""):
        if not items: raise ValueError("اقلام خرید خالی است")
        cur=self.con.cursor()
        self._fifo_cache_begin()
        try:
            cur.execute("BEGIN IMMEDIATE")
            total=Decimal("0")
            for pid,qty,price in items:
                row=cur.execute("SELECT id,name FROM products WHERE id=? AND COALESCE(active,1)=1",(pid,)).fetchone()
                if not row: raise ValueError("یکی از کالاهای خرید پیدا نشد")
                if to_decimal(qty)<=0 or to_decimal(price)<0: raise ValueError("تعداد و قیمت خرید نامعتبر است")
                total += to_decimal(qty) * to_decimal(price)
            total = money_decimal(total)
            cur.execute("INSERT INTO purchases(supplier,total,notes,created_at) VALUES(?,?,?,?)",(supplier.strip(),int(total),notes.strip(),now()))
            purchase_id=cur.lastrowid
            touched=set()
            for pid,qty,price in items:
                qty_d = to_decimal(qty)
                price_d = money_decimal(price)
                cur.execute("INSERT INTO purchase_items(purchase_id,product_id,qty,price,cancelled_qty) VALUES(?,?,?,?,0)",(purchase_id,int(pid),str(qty_d),int(price_d)))
                purchase_item_id = cur.lastrowid
                oldp=cur.execute("SELECT stock FROM products WHERE id=?",(pid,)).fetchone()
                old_stock = to_decimal(oldp[0] or 0)
                new_stock = old_stock + qty_d
                cur.execute("UPDATE products SET stock=? WHERE id=?",(str(new_stock),pid))
                cur.execute("""INSERT INTO inventory_movements
                    (product_id,movement_type,qty,reference_id,description,created_at,unit_cost,reference_item_id)
                    VALUES(?,?,?,?,?,?,?,?)""",
                    (pid,"ورود خرید",str(qty_d),purchase_id,f"خرید شماره {purchase_id}",now(),int(price_d),purchase_item_id))
                touched.add(int(pid))
            self._fifo_cache_invalidate()
            for pid in touched:
                self._rebuild_product_average_cost(cur, pid)
            self.con.commit()
        except Exception:
            self.con.rollback(); raise
        finally:
            self._fifo_cache_end()
        return purchase_id,int(total)

    def _set_product_cost_after_stock_change(self, cur, product_id, new_stock, new_cost):
        """به‌روزرسانی موجودی و بهای میانگین فعلی کالا."""
        new_stock = max(Decimal("0"), to_decimal(new_stock))
        new_cost = max(Decimal("0"), to_decimal(new_cost))
        new_buy_price = int(money_decimal(new_cost / new_stock)) if new_stock else 0
        cur.execute(
            "UPDATE products SET stock=?,buy_price=? WHERE id=?",
            (str(new_stock), new_buy_price, int(product_id))
        )


    def _purchase_consumed_quantities(self, cur, product_id):
        """مقدار فروخته‌شده و باقی‌مانده هر purchase_item را از لایه‌های FIFO برمی‌گرداند.

        مقدار باطل‌شده با ویرایش/ابطال خرید (cancelled_qty) فروش محسوب نمی‌شود؛
        وگرنه ویرایش دوباره همان خرید، موجودی را باد می‌کند.
        """
        layers = self._build_fifo_layers(cur, int(product_id))
        consumed, remaining = {}, {}
        for layer in layers:
            iid = layer.get("item_id")
            if iid is None:
                continue
            total = max(Decimal("0"), to_decimal(layer["qty"]))
            rem = max(Decimal("0"), to_decimal(layer["remaining"]))
            consumed[iid] = consumed.get(iid, Decimal("0")) + max(Decimal("0"), total - rem)
            remaining[iid] = remaining.get(iid, Decimal("0")) + rem

        if consumed or remaining:
            ids = tuple(set(consumed) | set(remaining))
            placeholders = ",".join("?" * len(ids))
            rows = cur.execute(
                f"SELECT id, COALESCE(cancelled_qty,0) cancelled_qty FROM purchase_items WHERE id IN ({placeholders})",
                ids,
            ).fetchall()
            for row in rows:
                iid = int(row["id"])
                cancelled = max(Decimal("0"), to_decimal(row["cancelled_qty"] or 0))
                if iid in consumed:
                    consumed[iid] = max(Decimal("0"), consumed[iid] - cancelled)
        return consumed, remaining


    def _rebuild_product_average_cost(self, cur, product_id):
        """با توجه به لایه‌های واقعی FIFO، بهای خرید فعلی باقی‌مانده را بازسازی می‌کند."""
        pid = int(product_id)
        row = cur.execute("SELECT stock FROM products WHERE id=?", (pid,)).fetchone()
        if not row:
            return
        stock = max(Decimal("0"), to_decimal(row["stock"] or 0))
        layers = self._build_fifo_layers(cur, pid)

        remaining_qty = sum((max(Decimal("0"), x["remaining"]) for x in layers), Decimal("0"))
        if remaining_qty > stock + Decimal("0.000001"):
            excess = remaining_qty - stock
            for layer in reversed(layers):
                if excess <= Decimal("0.000001"):
                    break
                take = min(layer["remaining"], excess)
                layer["remaining"] -= take
                excess -= take

        total_cost = sum((x["remaining"] * x["cost"] for x in layers), Decimal("0"))
        avg = money_decimal(total_cost / stock) if stock > Decimal("0.000001") else Decimal("0")
        cur.execute("UPDATE products SET buy_price=? WHERE id=?", (int(avg), pid))

    def _refresh_product_buy_price(self, cur, product_id):
        """سازگاری با کدهای قدیمی؛ بهای خرید باقی‌مانده را بازسازی می‌کند."""
        self._rebuild_product_average_cost(cur, product_id)

    def _get_purchase_unconsumed(self, cur, purchase_id):
        """مقدار باقی‌مانده قابل ابطال از هر قلم خرید را برمی‌گرداند."""
        rows = cur.execute(
            """SELECT id, product_id, qty, price, COALESCE(cancelled_qty,0) cancelled_qty
               FROM purchase_items WHERE purchase_id=? ORDER BY id""",
            (int(purchase_id),)
        ).fetchall()

        result = []
        cache = {}
        for it in rows:
            pid = int(it["product_id"])
            if pid not in cache:
                cache[pid] = self._purchase_consumed_quantities(cur, pid)[1]
            remaining_layer = to_decimal(cache[pid].get(int(it["id"]), Decimal("0")))
            # cancelled_qty قبلی هم باید از مقدار قابل ابطال کم شود.
            original_remaining = max(
                Decimal("0"), to_decimal(it["qty"] or 0) - to_decimal(it["cancelled_qty"] or 0)
            )
            result.append((it, min(original_remaining, remaining_layer)))
        return result

    def void_purchase(self, purchase_id, reason="ابطال خرید"):
        cur = self.con.cursor()
        self._fifo_cache_begin()
        try:
            cur.execute("BEGIN IMMEDIATE")
            p = cur.execute(
                "SELECT * FROM purchases WHERE id=?", (int(purchase_id),)
            ).fetchone()
            if not p:
                raise ValueError("خرید پیدا نشد")
            if (p["status"] or "فعال") != "فعال":
                raise ValueError("این خرید قبلاً تعیین تکلیف شده است")

            rows = self._get_purchase_unconsumed(cur, int(purchase_id))
            if not rows:
                raise ValueError("اقلام خرید پیدا نشد")

            changed = Decimal("0")
            touched = set()

            for it, cancel_q in rows:
                if cancel_q <= Decimal("0.000001"):
                    continue

                pid = int(it["product_id"])
                stock_row = cur.execute(
                    "SELECT stock FROM products WHERE id=?", (pid,)
                ).fetchone()
                current_stock = max(Decimal("0"), to_decimal(stock_row["stock"] if stock_row else 0))
                actual_cancel = min(cancel_q, current_stock)
                if actual_cancel <= Decimal("0.000001"):
                    continue

                new_stock = current_stock - actual_cancel
                cur.execute(
                    "UPDATE products SET stock=? WHERE id=?",
                    (str(new_stock), pid)
                )
                cur.execute(
                    """UPDATE purchase_items
                       SET cancelled_qty=MIN(qty, COALESCE(cancelled_qty,0)+?)
                       WHERE id=?""",
                    (str(actual_cancel), int(it["id"]))
                )
                cur.execute(
                    """INSERT INTO inventory_movements
                       (product_id,movement_type,qty,reference_id,description,created_at,unit_cost,reference_item_id)
                       VALUES(?,?,?,?,?,?,?,?)""",
                    (pid, "ابطال خرید", str(-actual_cancel), int(purchase_id), reason, now(), 0, int(it["id"]))
                )
                touched.add(pid)
                changed += actual_cancel

            if changed <= Decimal("0.000001"):
                raise ValueError(
                    "از این خرید موجودی باقی‌مانده‌ای برای ابطال وجود ندارد؛ "
                    "احتمالاً مقدار باقی‌مانده قبلاً فروخته شده است."
                )

            remaining_total = cur.execute(
                """SELECT COALESCE(SUM(qty-COALESCE(cancelled_qty,0)),0)
                   FROM purchase_items WHERE purchase_id=?""",
                (int(purchase_id),)
            ).fetchone()[0]

            live_total = cur.execute(
                """SELECT COALESCE(SUM((qty-COALESCE(cancelled_qty,0))*price),0)
                   FROM purchase_items WHERE purchase_id=?""",
                (int(purchase_id),)
            ).fetchone()[0]
            status = (
                "باطل"
                if to_decimal(remaining_total) <= Decimal("0.000001")
                else "باطل جزئی"
            )
            cur.execute(
                "UPDATE purchases SET status=?, total=? WHERE id=?",
                (status, int(money_decimal(live_total)), int(purchase_id))
            )

            self._fifo_cache_invalidate()
            for pid in touched:
                self._rebuild_product_average_cost(cur, pid)

            self.con.commit()
        except Exception:
            self.con.rollback()
            raise
        finally:
            self._fifo_cache_end()
        log_audit("void_purchase", f"purchase_id={purchase_id} reason={reason}")
        return True

    def update_purchase(self, purchase_id, supplier, items, notes=""):
        """ویرایش امن خرید بدون بازنویسی بهای تاریخی کالاهای قبلاً فروخته‌شده.

        قلم‌های قدیمی حذف نمی‌شوند. بخش مصرف‌شده همان قلم و همان قیمت تاریخی را
        حفظ می‌کند؛ فقط بخش باقی‌مانده با یک قلم جدید و گردش اصلاحی جایگزین می‌شود.
        """
        if not items:
            raise ValueError("اقلام خرید خالی است")

        new_by_pid = {}
        for pid, qty, price in items:
            pid = int(pid)
            qty_d = to_decimal(qty)
            price_d = money_decimal(price)
            if qty_d <= 0 or price_d < 0:
                raise ValueError("اقلام خرید نامعتبر است")
            prev = new_by_pid.get(pid)
            new_by_pid[pid] = (
                (prev[0] if prev else Decimal("0")) + qty_d,
                price_d
            )

        cur = self.con.cursor()
        self._fifo_cache_begin()
        try:
            cur.execute("BEGIN IMMEDIATE")
            old = cur.execute("SELECT * FROM purchases WHERE id=?", (int(purchase_id),)).fetchone()
            if not old or (old["status"] or "فعال") != "فعال":
                raise ValueError("خرید قابل ویرایش نیست")

            old_rows = cur.execute(
                """SELECT id,product_id,qty,price,COALESCE(cancelled_qty,0) cancelled_qty
                   FROM purchase_items WHERE purchase_id=? ORDER BY id""",
                (int(purchase_id),)
            ).fetchall()
            if not old_rows:
                raise ValueError("اقلام خرید پیدا نشد")

            consumed_by_item = {}
            remaining_by_item = {}
            consumed_by_pid = {}
            cache = {}
            for r in old_rows:
                pid = int(r["product_id"])
                if pid not in cache:
                    consumed, remaining = self._purchase_consumed_quantities(cur, pid)
                    cache[pid] = (consumed, remaining)
                consumed, remaining = cache[pid]
                iid = int(r["id"])
                c = max(Decimal("0"), to_decimal(consumed.get(iid, 0)))
                rem = max(Decimal("0"), to_decimal(remaining.get(iid, 0)))
                consumed_by_item[iid] = c
                remaining_by_item[iid] = rem
                consumed_by_pid[pid] = consumed_by_pid.get(pid, Decimal("0")) + c

            # کالایی که بخشی از آن قبلاً فروخته شده، نمی‌تواند از خرید حذف شود
            # یا تعدادش کمتر از مقدار تاریخی مصرف‌شده شود.
            for pid, consumed_qty in consumed_by_pid.items():
                requested = new_by_pid.get(pid)
                if consumed_qty > Decimal("0.000001"):
                    if requested is None:
                        rowp = self.product(pid)
                        name = rowp["name"] if rowp else str(pid)
                        raise ValueError(
                            f"کالای «{name}» بخشی از این خرید را قبلاً مصرف/فروخته شده و "
                            "برای حفظ تاریخچه نمی‌توان آن را حذف کرد."
                        )
                    if requested[0] + Decimal("0.000001") < consumed_qty:
                        rowp = self.product(pid)
                        name = rowp["name"] if rowp else str(pid)
                        raise ValueError(
                            f"تعداد جدید کالای «{name}» نمی‌تواند کمتر از "
                            f"{format_qty(consumed_qty)} واحد مصرف‌شده تاریخی باشد."
                        )

            affected = set(int(r["product_id"]) for r in old_rows) | set(new_by_pid.keys())
            effective_total = Decimal("0")

            # بخش باقی‌مانده تمام اقلام قدیمی از موجودی خارج می‌شود و همان قلم
            # با cancelled_qty مشخص می‌شود؛ بنابراین movement قدیمی هرگز به قلم جدید
            # نگاشت نمی‌شود و بهای تاریخی آن دست‌نخورده می‌ماند.
            for r in old_rows:
                pid = int(r["product_id"])
                iid = int(r["id"])
                rem = remaining_by_item[iid]
                consumed = consumed_by_item[iid]
                old_price = money_decimal(r["price"] or 0)
                effective_total += consumed * old_price
                if rem <= Decimal("0.000001"):
                    continue

                stock_row = cur.execute("SELECT stock FROM products WHERE id=?", (pid,)).fetchone()
                stock = max(Decimal("0"), to_decimal(stock_row["stock"] if stock_row else 0))
                if stock + Decimal("0.000001") < rem:
                    raise ValueError("موجودی فعلی اجازه ویرایش این خرید را نمی‌دهد.")
                cur.execute("UPDATE products SET stock=stock-? WHERE id=?", (str(rem), pid))
                cur.execute(
                    "UPDATE purchase_items SET cancelled_qty=MIN(qty,COALESCE(cancelled_qty,0)+?) WHERE id=?",
                    (str(rem), iid)
                )
                cur.execute(
                    """INSERT INTO inventory_movements
                       (product_id,movement_type,qty,reference_id,description,created_at,unit_cost,reference_item_id)
                       VALUES(?,?,?,?,?,?,?,?)""",
                    (pid, "اصلاح خرید", str(-rem), int(purchase_id),
                     "کسر بخش قدیمی هنگام ویرایش خرید", now(), 0, iid)
                )

            # برای هر کالای جدید فقط مقدار مازاد بر بخش تاریخی مصرف‌شده به عنوان
            # قلم جدید وارد می‌شود. این قلم قیمت جدید را دارد.
            for pid, (new_qty, new_price) in new_by_pid.items():
                pid = int(pid)
                row = cur.execute(
                    "SELECT id FROM products WHERE id=? AND COALESCE(active,1)=1", (pid,)
                ).fetchone()
                if not row:
                    raise ValueError("یکی از کالاهای خرید پیدا نشد")
                consumed = consumed_by_pid.get(pid, Decimal("0"))
                replacement_qty = max(Decimal("0"), new_qty - consumed)
                if replacement_qty > Decimal("0.000001"):
                    cur.execute(
                        "INSERT INTO purchase_items(purchase_id,product_id,qty,price,cancelled_qty) VALUES(?,?,?,?,0)",
                        (int(purchase_id), pid, str(replacement_qty), int(money_decimal(new_price)))
                    )
                    new_item_id = cur.lastrowid
                    cur.execute("UPDATE products SET stock=stock+? WHERE id=?", (str(replacement_qty), pid))
                    cur.execute(
                        """INSERT INTO inventory_movements
                           (product_id,movement_type,qty,reference_id,description,created_at,unit_cost,reference_item_id)
                           VALUES(?,?,?,?,?,?,?,?)""",
                        (pid, "اصلاح خرید", str(replacement_qty), int(purchase_id),
                         "ورود بخش جدید هنگام ویرایش خرید", now(), int(money_decimal(new_price)), new_item_id)
                    )
                    effective_total += replacement_qty * new_price

            self._fifo_cache_invalidate()
            for pid in affected:
                self._rebuild_product_average_cost(cur, int(pid))

            live_total = cur.execute(
                """SELECT COALESCE(SUM((qty-COALESCE(cancelled_qty,0))*price),0)
                   FROM purchase_items WHERE purchase_id=?""",
                (int(purchase_id),)
            ).fetchone()[0]
            effective_total = money_decimal(live_total)
            cur.execute(
                "UPDATE purchases SET supplier=?,total=?,notes=?,status='فعال' WHERE id=?",
                (supplier.strip(), int(effective_total), notes.strip(), int(purchase_id))
            )
            self.con.commit()
        except Exception:
            self.con.rollback()
            raise
        finally:
            self._fifo_cache_end()
        return int(effective_total)

    def recompute_customer_balance(self, customer_id):
        cid = int(customer_id)
        # فروش نسیه (بدهی اصلی)
        credit = self.con.execute(
            "SELECT COALESCE(SUM(total),0) FROM sales WHERE customer_id=? AND payment='نسیه' AND COALESCE(status,'فعال') IN ('فعال','مرجوع جزئی')",
            (cid,)
        ).fetchone()[0]
        # مانده افتتاحیه و سایر بدهکارهای بدون فاکتور
        opening = self.con.execute(
            "SELECT COALESCE(SUM(amount),0) FROM account_transactions WHERE customer_id=? AND transaction_type='بدهکار' AND sale_id IS NULL",
            (cid,)
        ).fetchone()[0]
        # بدهی ناشی از برگشت چک (تراکنش بدهکار با sale_id که شرح برگشت چک دارد)
        returned_checks = self.con.execute(
            """SELECT COALESCE(SUM(amount),0) FROM account_transactions
               WHERE customer_id=? AND transaction_type='بدهکار'
                 AND sale_id IS NOT NULL AND description LIKE '%برگشت چک%'""",
            (cid,)
        ).fetchone()[0]
        payments = self.con.execute(
            "SELECT COALESCE(SUM(amount),0) FROM account_transactions WHERE customer_id=? AND transaction_type='پرداخت'",
            (cid,)
        ).fetchone()[0]
        adjustments = self.con.execute(
            """SELECT COALESCE(SUM(amount),0) FROM account_transactions
               WHERE customer_id=? AND transaction_type='بستانکار'
                 AND NOT (sale_id IS NOT NULL AND description LIKE 'ابطال فاکتور %')""",
            (cid,)
        ).fetchone()[0]
        raw_balance = money_decimal(
            to_decimal(credit) + to_decimal(opening) + to_decimal(returned_checks)
            - to_decimal(payments) - to_decimal(adjustments)
        )
        # اگر پرداخت‌های قبلی بیش از بدهی فعال باقی مانده باشند (مثلاً پس از
        # ابطال فاکتور نسیه‌ای که قبلاً کامل پرداخت شده)، مبلغ اضافه واقعاً
        # بستانکاری مشتری است و نباید به عنوان بدهی ثبت شود.
        balance_int = int(raw_balance)
        self.con.execute("UPDATE customers SET balance=? WHERE id=?", (balance_int, cid))
        self.con.commit()
        return balance_int

    def format_customer_balance(self, value):
        balance = money_decimal(value)
        if balance > 0:
            return f"بدهکار: {money(balance)}"
        if balance < 0:
            return f"بستانکار: {money(-balance)}"
        return "تسویه: 0 تومان"

    def add_customer_payment(self, customer_id, amount, notes=""):
        amount=int(money_decimal(amount))
        if amount<=0: raise ValueError("مبلغ پرداخت باید بیشتر از صفر باشد.")
        row=self.con.execute("SELECT name FROM customers WHERE id=?",(customer_id,)).fetchone()
        if not row: raise ValueError("مشتری پیدا نشد.")
        balance=self.recompute_customer_balance(customer_id)
        if amount > balance: raise ValueError("مبلغ پرداخت بیشتر از مانده حساب مشتری است.")
        self.con.execute("INSERT INTO account_transactions(customer_id,transaction_type,amount,description,sale_id,created_at) VALUES(?,?,?,?,?,?)",
                         (customer_id,"پرداخت",amount,notes.strip() or "پرداخت حساب دفتری",None,now()))
        self.recompute_customer_balance(customer_id)

    def update_customer(self, customer_id, name, phone, address, balance=None):
        # مانده دیگر مستقیماً از فرم ویرایش نمی‌شود؛ منبع حقیقت دفتر حساب است.
        self.con.execute("UPDATE customers SET name=?, phone=?, address=? WHERE id=?",
                         (name.strip(), phone.strip(), address.strip(), int(customer_id)))
        self.recompute_customer_balance(customer_id)

    def update_account_transaction(self, tx_id, amount, description):
        row=self.con.execute("SELECT customer_id,transaction_type FROM account_transactions WHERE id=?",(int(tx_id),)).fetchone()
        if not row: raise ValueError("تراکنش پیدا نشد")
        if row["transaction_type"]!="پرداخت": raise ValueError("فقط پرداخت‌ها قابل ویرایش هستند")
        amount=int(money_decimal(amount))
        if amount<=0: raise ValueError("مبلغ باید بیشتر از صفر باشد")
        cid=int(row["customer_id"])
        # دقیقاً همان منطق recompute_customer_balance: فقط فروش‌های نسیه فعال
        # در سقف بدهی قابل پرداخت لحاظ می‌شوند.
        credit=self.con.execute("SELECT COALESCE(SUM(total),0) FROM sales WHERE customer_id=? AND payment='نسیه' AND COALESCE(status,'فعال') IN ('فعال','مرجوع جزئی')",(cid,)).fetchone()[0]
        opening=self.con.execute("SELECT COALESCE(SUM(amount),0) FROM account_transactions WHERE customer_id=? AND transaction_type='بدهکار' AND sale_id IS NULL",(cid,)).fetchone()[0]
        returned_checks=self.con.execute("SELECT COALESCE(SUM(amount),0) FROM account_transactions WHERE customer_id=? AND transaction_type='بدهکار' AND sale_id IS NOT NULL AND description LIKE '%برگشت چک%'",(cid,)).fetchone()[0]
        adjustments=self.con.execute("SELECT COALESCE(SUM(amount),0) FROM account_transactions WHERE customer_id=? AND transaction_type='بستانکار' AND NOT (sale_id IS NOT NULL AND description LIKE 'ابطال فاکتور %')",(cid,)).fetchone()[0]
        other_payments=self.con.execute("SELECT COALESCE(SUM(amount),0) FROM account_transactions WHERE customer_id=? AND transaction_type='پرداخت' AND id<>?",(cid,int(tx_id))).fetchone()[0]
        if to_decimal(other_payments) + to_decimal(amount) > to_decimal(credit) + to_decimal(opening) + to_decimal(returned_checks) - to_decimal(adjustments):
            raise ValueError("مبلغ پرداخت از مانده قابل پرداخت بیشتر است")
        self.con.execute("UPDATE account_transactions SET amount=?,description=? WHERE id=?",(amount,description.strip(),int(tx_id)))
        self.con.commit()
        self.recompute_customer_balance(int(row["customer_id"]))

    def _sale_line_live(self, item):
        qty = to_decimal(item["qty"] or 0)
        returned = to_decimal(item["returned_qty"] or 0) if "returned_qty" in item.keys() else Decimal("0")
        live = max(Decimal("0"), qty - returned)
        gross = to_decimal(item["price"] or 0) * qty
        disc = to_decimal(item["discount"] or 0)
        final = to_decimal(item["final_price"] or 0)
        if final <= 0:
            final = max(Decimal("0"), money_decimal(gross - disc))
        if qty <= 0:
            return Decimal("0"), Decimal("0"), Decimal("0")
        live_final = money_decimal(final * live / qty)
        live_disc = money_decimal(disc * live / qty)
        return live, live_final, live_disc

    def _recalc_sale_totals(self, cur, sale_id):
        items = cur.execute("SELECT * FROM sale_items WHERE sale_id=?", (int(sale_id),)).fetchall()
        total = Decimal("0")
        discount = Decimal("0")
        profit = Decimal("0")
        remaining_qty = Decimal("0")
        for it in items:
            live, live_final, live_disc = self._sale_line_live(it)
            remaining_qty += live
            total += live_final
            discount += live_disc
            profit += live_final - (money_decimal(it["buy_price"] or 0) * live)
        return money_decimal(total), money_decimal(discount), money_decimal(profit), remaining_qty

    def partial_return_sale(self, sale_id, returns, reason="مرجوعی جزئی"):
        """مرجوعی تعدادی از اقلام فاکتور بدون ابطال کل فاکتور.

        returns: لیست (sale_item_id, qty)
        """
        if not returns:
            raise ValueError("هیچ کالایی برای مرجوعی انتخاب نشده است.")
        cur = self.con.cursor()
        self._fifo_cache_begin()
        try:
            cur.execute("BEGIN IMMEDIATE")
            sale = cur.execute("SELECT * FROM sales WHERE id=?", (int(sale_id),)).fetchone()
            if not sale:
                raise ValueError("فاکتور پیدا نشد")
            status = sale["status"] or "فعال"
            if status not in ("فعال", "مرجوع جزئی"):
                raise ValueError("این فاکتور قابل مرجوعی نیست.")

            wanted = {}
            for item_id, qty in returns:
                q = to_decimal(qty)
                if q <= 0:
                    continue
                wanted[int(item_id)] = wanted.get(int(item_id), Decimal("0")) + q
            if not wanted:
                raise ValueError("تعداد مرجوعی باید بیشتر از صفر باشد.")

            returned_amount = Decimal("0")
            touched = set()
            prepared = []
            for item_id, qty in wanted.items():
                it = cur.execute(
                    "SELECT * FROM sale_items WHERE id=? AND sale_id=?",
                    (int(item_id), int(sale_id)),
                ).fetchone()
                if not it:
                    raise ValueError("یکی از اقلام فاکتور پیدا نشد.")
                live, live_final, _live_disc = self._sale_line_live(it)
                if qty > live + Decimal("0.000001"):
                    raise ValueError(
                        f"تعداد مرجوعی بیشتر از مانده فاکتور است. مانده: {format_qty(live)}"
                    )
                orig_qty = to_decimal(it["qty"] or 0)
                orig_final = to_decimal(it["final_price"] or 0)
                if orig_final <= 0:
                    orig_final = money_decimal(to_decimal(it["price"] or 0) * orig_qty - to_decimal(it["discount"] or 0))
                line_amount = money_decimal(orig_final * qty / orig_qty) if orig_qty else Decimal("0")
                unit_cost = money_decimal(it["buy_price"] or 0)
                prepared.append((it, qty, line_amount, unit_cost))
                returned_amount += line_amount
                touched.add(int(it["product_id"]))

            cur.execute(
                "INSERT INTO sale_returns(sale_id,amount,reason,created_at) VALUES(?,?,?,?)",
                (int(sale_id), int(money_decimal(returned_amount)), reason.strip() or "مرجوعی جزئی", now()),
            )
            rid = cur.lastrowid
            for it, qty, line_amount, unit_cost in prepared:
                cur.execute(
                    "UPDATE sale_items SET returned_qty=COALESCE(returned_qty,0)+? WHERE id=?",
                    (str(qty), int(it["id"])),
                )
                cur.execute(
                    """INSERT INTO sale_return_items
                       (return_id,sale_item_id,product_id,qty,amount,buy_price)
                       VALUES(?,?,?,?,?,?)""",
                    (rid, int(it["id"]), int(it["product_id"]), str(qty), int(line_amount), int(unit_cost)),
                )
                cur.execute("UPDATE products SET stock=stock+? WHERE id=?", (str(qty), int(it["product_id"])))
                cur.execute(
                    """INSERT INTO inventory_movements
                       (product_id,movement_type,qty,reference_id,description,created_at,unit_cost,reference_item_id)
                       VALUES(?,?,?,?,?,?,?,?)""",
                    (int(it["product_id"]), "مرجوعی فروش", str(qty), int(sale_id),
                     f"مرجوعی جزئی فاکتور {int(sale['invoice_no'] or sale_id):04d}", now(),
                     int(unit_cost), int(it["id"])),
                )

            total, discount, profit, remaining_qty = self._recalc_sale_totals(cur, int(sale_id))
            if remaining_qty <= Decimal("0.000001"):
                new_status = "باطل"
                cur.execute(
                    "UPDATE sales SET total=?,discount=?,profit=?,status=?,voided_at=?,void_reason=? WHERE id=?",
                    (0, 0, 0, new_status, now(), reason.strip() or "مرجوعی کامل", int(sale_id)),
                )
                if sale["payment"] == "چک" and sale["check_id"]:
                    cur.execute(
                        "UPDATE checks SET status='باطل شد',notes=COALESCE(notes,'') || ? WHERE id=?",
                        (f" | مرجوعی کامل: {reason}", int(sale["check_id"])),
                    )
                    cur.execute(
                        "DELETE FROM account_transactions WHERE sale_id=? AND transaction_type='بدهکار' AND description LIKE '%برگشت چک%'",
                        (int(sale_id),),
                    )
                cur.execute(
                    """UPDATE instagram_orders
                       SET sale_id=NULL, stock_applied=0,
                           status=CASE WHEN status='لغو شد' THEN status ELSE 'جدید' END
                       WHERE sale_id=?""",
                    (int(sale_id),),
                )
            else:
                cur.execute(
                    "UPDATE sales SET total=?,discount=?,profit=?,status=? WHERE id=?",
                    (int(total), int(discount), int(profit), "مرجوع جزئی", int(sale_id)),
                )

            self._fifo_cache_invalidate()
            for pid in touched:
                self._rebuild_product_average_cost(cur, pid)
            self.con.commit()
        except Exception:
            self.con.rollback()
            raise
        finally:
            self._fifo_cache_end()
        if sale["customer_id"]:
            self.recompute_customer_balance(int(sale["customer_id"]))
        log_audit("partial_return_sale", f"sale_id={sale_id} amount={money_decimal(returned_amount)} reason={reason.strip()}")
        return money_decimal(returned_amount), remaining_qty

    def void_sale(self, sale_id, reason="ابطال/مرجوعی"):
        cur = self.con.cursor()
        self._fifo_cache_begin()
        try:
            cur.execute("BEGIN IMMEDIATE")
            sale = cur.execute("SELECT * FROM sales WHERE id=?", (int(sale_id),)).fetchone()
            if not sale:
                raise ValueError("فاکتور پیدا نشد")
            if (sale["status"] or "فعال") not in ("فعال", "مرجوع جزئی"):
                raise ValueError("این فاکتور قبلاً ابطال شده است")

            items = cur.execute(
                "SELECT id,product_id,qty,buy_price,COALESCE(returned_qty,0) returned_qty FROM sale_items WHERE sale_id=?",
                (int(sale_id),),
            ).fetchall()
            for it in items:
                remain = max(Decimal("0"), to_decimal(it["qty"] or 0) - to_decimal(it["returned_qty"] or 0))
                if remain <= Decimal("0.000001"):
                    continue
                unit_cost = money_decimal(it["buy_price"] or 0)
                cur.execute("UPDATE products SET stock=stock+? WHERE id=?", (str(remain), int(it["product_id"])))
                cur.execute(
                    "UPDATE sale_items SET returned_qty=? WHERE id=?",
                    (str(to_decimal(it["qty"] or 0)), int(it["id"])),
                )
                cur.execute(
                    """INSERT INTO inventory_movements
                       (product_id,movement_type,qty,reference_id,description,created_at,unit_cost,reference_item_id)
                       VALUES(?,?,?,?,?,?,?,?)""",
                    (int(it["product_id"]), "مرجوعی فروش", str(remain), int(sale_id),
                     f"مرجوعی فاکتور {int(sale['invoice_no'] or sale_id):04d}", now(),
                     int(unit_cost), int(it["id"]))
                )

            # در فاکتور نسیه، خود فروش فعال از محاسبه بدهی حذف می‌شود؛
            # بنابراین نباید یک «بستانکار» اضافی ثبت شود و مانده را دوبار خنثی کند.
            # رکوردهای اشتباه قدیمی همین فاکتور نیز پاک می‌شوند.
            if sale["customer_id"]:
                cur.execute(
                    "DELETE FROM account_transactions WHERE sale_id=? AND transaction_type='بستانکار' AND description LIKE 'ابطال فاکتور %'",
                    (int(sale_id),)
                )

            if sale["payment"] == "چک" and sale["check_id"]:
                cur.execute(
                    "UPDATE checks SET status='باطل شد',notes=COALESCE(notes,'') || ? WHERE id=?",
                    (f" | {reason}", int(sale["check_id"]))
                )
                # اگر چک قبلاً برگشتی بود، بدهی ناشی از برگشت هم با ابطال فاکتور حذف می‌شود.
                cur.execute(
                    "DELETE FROM account_transactions WHERE sale_id=? AND transaction_type='بدهکار' AND description LIKE '%برگشت چک%'",
                    (int(sale_id),)
                )

            cur.execute(
                "UPDATE sales SET total=0,discount=0,profit=0,status='باطل',voided_at=?,void_reason=? WHERE id=?",
                (now(), reason.strip(), int(sale_id))
            )
            # فاکتور اینستاگرام ابطال شد: موجودی با مرجوعی فروش برگشت.
            # سفارش از فاکتور جدا می‌شود تا بتوان دوباره فاکتور گرفت یا لغوش کرد.
            cur.execute(
                """UPDATE instagram_orders
                   SET sale_id=NULL, stock_applied=0,
                       status=CASE WHEN status='لغو شد' THEN status ELSE 'جدید' END
                   WHERE sale_id=?""",
                (int(sale_id),)
            )
            touched = {int(it["product_id"]) for it in items}
            self._fifo_cache_invalidate()
            for pid in touched:
                self._rebuild_product_average_cost(cur, pid)
            self.con.commit()
        except Exception:
            self.con.rollback()
            raise
        finally:
            self._fifo_cache_end()
        if sale["customer_id"]:
            self.recompute_customer_balance(int(sale["customer_id"]))
        log_audit("void_sale", f"sale_id={sale_id} invoice_no={sale['invoice_no']} reason={reason.strip()}")
        return True

    def backup_to(self, path):
        # SQLite Online Backup: امن‌تر از copy2 هنگام باز بودن دیتابیس.
        # در WAL ابتدا checkpoint می‌کنیم تا تغییرات ثبت‌شده در WAL نیز در snapshot
        # قابل اتکا باشند؛ سپس خود backup API یک snapshot سازگار می‌گیرد.
        self.con.execute("PRAGMA wal_checkpoint(FULL)")
        dest=sqlite3.connect(path)
        try:
            with dest:
                self.con.backup(dest)
        finally:
            dest.close()
        return path

    def customer_transactions(self, customer_id):
        return self.con.execute("SELECT at.*,s.invoice_no,s.invoice_date FROM account_transactions at LEFT JOIN sales s ON s.id=at.sale_id WHERE at.customer_id=? ORDER BY at.id DESC",(customer_id,)).fetchall()

    def customer_sales(self, customer_id):
        return self.con.execute("SELECT s.*,COALESCE((SELECT SUM(si.qty-COALESCE(si.returned_qty,0)) FROM sale_items si WHERE si.sale_id=s.id),0) item_count FROM sales s WHERE s.customer_id=? ORDER BY s.id DESC",(customer_id,)).fetchall()

    def stats(self):
        """آمار دوره‌ای بر اساس تاریخ واقعی فاکتور؛ خرید و هزینه بر اساس تاریخ ثبت."""
        today = date.today()
        day = today.isoformat()
        week_start = today.toordinal() - ((today.weekday() - 5) % 7)
        week = date.fromordinal(week_start).isoformat()
        month = today.replace(day=1).isoformat()
        tomorrow = (today + timedelta(days=1)).isoformat()

        def sums(start):
            sales = self.con.execute(
                "SELECT COALESCE(SUM(total),0) FROM sales WHERE invoice_date>=? AND invoice_date<=? AND COALESCE(status,'فعال') IN ('فعال','مرجوع جزئی')",
                (start, day)
            ).fetchone()[0]
            profit = self.con.execute(
                "SELECT COALESCE(SUM(profit),0) FROM sales WHERE invoice_date>=? AND invoice_date<=? AND COALESCE(status,'فعال') IN ('فعال','مرجوع جزئی')",
                (start, day)
            ).fetchone()[0]
            purchases = self.con.execute(
                """SELECT COALESCE(SUM((pi.qty-COALESCE(pi.cancelled_qty,0))*pi.price),0)
                   FROM purchase_items pi
                   JOIN purchases p ON p.id=pi.purchase_id
                   WHERE p.created_at>=? AND p.created_at<?
                     AND COALESCE(p.status,'فعال') IN ('فعال','باطل جزئی')""",
                (start, tomorrow)
            ).fetchone()[0]
            expenses = self.con.execute(
                "SELECT COALESCE(SUM(amount),0) FROM expenses WHERE created_at>=? AND created_at<? AND COALESCE(active,1)=1",
                (start, tomorrow)
            ).fetchone()[0]
            return float(sales or 0), float(profit or 0), float(purchases or 0), float(expenses or 0)

        ds = sums(day)
        ws = sums(week)
        ms = sums(month)
        invoices = self.con.execute(
            "SELECT COUNT(*) FROM sales WHERE invoice_date=? AND COALESCE(status,'فعال') IN ('فعال','مرجوع جزئی')",
            (day,)
        ).fetchone()[0]
        low = self.con.execute("SELECT COUNT(*) FROM products WHERE COALESCE(active,1)=1 AND stock<=min_stock").fetchone()[0]
        inv_value = self.con.execute("SELECT COALESCE(SUM(stock*buy_price),0) FROM products WHERE COALESCE(active,1)=1").fetchone()[0]
        # کلیدهای مورد انتظار بخش گزارش‌ها را برمی‌گردانیم.
        # همچنین نام‌های سازگار با نسخه‌های قبلی حفظ شده‌اند.
        debtors = self.con.execute(
            "SELECT COUNT(*) FROM customers WHERE balance>0"
        ).fetchone()[0]
        due = self.con.execute(
            """SELECT COALESCE(SUM(amount),0) FROM checks
               WHERE type='دریافتی' AND status='در انتظار' AND due_date<=?""",
            (day,)
        ).fetchone()[0]
        return {
            "day": ds,
            "week": ws,
            "month": ms,
            "invoices": invoices,
            "low": low,
            "inventory_value": float(inv_value or 0),
            "debtors": debtors,
            "due_checks": float(due or 0),
        }

    def detailed_reports(self):
        top_products=self.con.execute("""SELECT p.name,
                SUM(si.qty-COALESCE(si.returned_qty,0)) qty,
                SUM(CASE WHEN si.qty>0 THEN COALESCE(si.final_price,si.qty*si.price)*(si.qty-COALESCE(si.returned_qty,0))/si.qty ELSE 0 END) total
            FROM sale_items si JOIN sales s ON s.id=si.sale_id JOIN products p ON p.id=si.product_id
            WHERE COALESCE(s.status,'فعال') IN ('فعال','مرجوع جزئی')
            GROUP BY si.product_id ORDER BY qty DESC LIMIT 10""").fetchall()
        top_customers=self.con.execute("""SELECT c.name, COUNT(s.id) invoices, SUM(s.total) total
            FROM sales s JOIN customers c ON c.id=s.customer_id
            WHERE COALESCE(s.status,'فعال') IN ('فعال','مرجوع جزئی')
            GROUP BY s.customer_id ORDER BY total DESC LIMIT 10""").fetchall()
        return top_products,top_customers

    def export_csv(self, query, path, headers):
        rows = self.con.execute(query).fetchall()
        with open(path, "w", newline="", encoding="utf-8-sig") as f:
            w = csv.writer(f)
            w.writerow(headers)
            for r in rows:
                w.writerow(list(r))


class Card(QFrame):
    def __init__(self, parent=None, bg=PANEL):
        super().__init__(parent)
        self.setObjectName("Card")
        self.setStyleSheet(f"""
        QFrame#Card {{
            background:{bg};
            border:1px solid {BORDER};
            border-radius:18px;
        }}
        """)


class ProductCard(QFrame):
    clicked = Signal(object)

    def __init__(self, p):
        super().__init__()
        self.p = p
        self.setObjectName("ProductCard")
        # کارت‌ها خواناتر و بزرگ‌تر؛ تعداد ستون‌ها متناسب با عرض پنل تنظیم می‌شود.
        self.setMinimumSize(185, 185)
        self.setMaximumSize(300, 195)
        self.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Fixed)
        self.setStyleSheet(f"""
        QFrame#ProductCard {{
            background:{PANEL_LIGHT};
            border:1px solid {BORDER};
            border-radius:16px;
        }}
        QFrame#ProductCard:hover {{ background:#4B9396; }}
        """)
        l = QVBoxLayout(self)
        l.setContentsMargins(10, 8, 10, 8)
        icon = QLabel("🛠️")
        icon.setAlignment(Qt.AlignCenter)
        icon.setStyleSheet("font-size:31px;border:0;")
        l.addWidget(icon)
        n = QLabel(p["name"])
        n.setWordWrap(True)
        n.setAlignment(Qt.AlignCenter)
        n.setStyleSheet("font-size:13px;font-weight:800;border:0;")
        l.addWidget(n)
        s = QLabel(f"{format_qty(p['stock'])}")
        s.setAlignment(Qt.AlignCenter)
        s.setStyleSheet(f"color:{MUTED};font-size:11px;border:0;")
        l.addWidget(s)
        price = QLabel(money(p["sell_price"]))
        price.setAlignment(Qt.AlignCenter)
        price.setStyleSheet("font-weight:800;font-size:12px;border:0;")
        l.addWidget(price)

    def mousePressEvent(self, event):
        self.clicked.emit(self.p)
        super().mousePressEvent(event)


class ProductDialog(QDialog):
    def __init__(self, parent=None, product=None, categories=None):
        super().__init__(parent)
        self.product = product
        self.setWindowTitle("ویرایش محصول" if product else "ثبت محصول جدید")
        self.setMinimumWidth(450)
        self.setLayoutDirection(Qt.RightToLeft)
        f = QFormLayout(self)
        self.name = QLineEdit(product["name"] if product else "")
        self.cat = QComboBox()
        self.cat.setEditable(True)
        self.cat.setInsertPolicy(QComboBox.NoInsert)
        self.cat.addItems(categories or ["سایر", "PDR", "ابزار", "دستگاه", "مصرفی", "تجهیزات"])
        if product:
            self.cat.setCurrentText(product["category"] or "سایر")
        else:
            self.cat.setCurrentText("PDR")
        self.buy = MoneySpinBox(); self.buy.setDecimals(0)
        self.sell = MoneySpinBox(); self.sell.setDecimals(0)
        self.stock = CleanDoubleSpinBox()
        self.minstock = CleanDoubleSpinBox()
        self.barcode = QLineEdit(product["barcode"] if product else "")
        self.unit = QLineEdit(product["unit"] if product else "عدد")
        for x in [self.buy, self.sell]:
            x.setMaximum(999999999999)
            x.setDecimals(0)
        for x in [self.stock, self.minstock]:
            x.setMaximum(999999999999)
            x.setDecimals(2)
        if product:
            self.buy.setValue(product["buy_price"])
            self.buy.setEnabled(False)
            self.buy.setToolTip("بهای خرید از روی لایه‌های FIFO، خرید و اصلاح موجودی محاسبه می‌شود.")
            self.sell.setValue(product["sell_price"])
            self.stock.setValue(product["stock"])
            self.stock.setEnabled(False)
            self.stock.setToolTip("موجودی از طریق خرید، فروش و اصلاح موجودی تغییر می‌کند.")
            self.minstock.setValue(product["min_stock"])
        else:
            self.minstock.setValue(1)
        for x in [self.name,self.cat,self.buy,self.sell,self.stock,self.minstock,self.barcode,self.unit]:
            x.setMinimumHeight(38)
        f.addRow("نام محصول:", self.name)
        f.addRow("دسته‌بندی:", self.cat)
        f.addRow("قیمت خرید:", self.buy)
        f.addRow("قیمت فروش:", self.sell)
        f.addRow("موجودی:", self.stock)
        f.addRow("حداقل موجودی:", self.minstock)
        f.addRow("بارکد:", self.barcode)
        f.addRow("واحد:", self.unit)
        buttons = QDialogButtonBox(QDialogButtonBox.Save | QDialogButtonBox.Cancel)
        buttons.accepted.connect(self.accept)
        buttons.rejected.connect(self.reject)
        f.addRow(buttons)

    def data(self):
        return (
            self.name.text().strip(),
            self.cat.currentText().strip() or "سایر",
            self.buy.value(),
            self.sell.value(),
            self.stock.value(),
            self.minstock.value(),
            self.barcode.text().strip(),
            self.unit.text().strip() or "عدد",
        )


class Main(QMainWindow):
    # --- PDF DIRECT VIEW OPTION ---
    def open_invoice_pdf_direct(self):
        """دکمه «ذخیره به عنوان PDF و نمایش»"""
        try:
            if self.cart:
                self.export_invoice_pdf()
                return
            save_current_invoice_pdf_and_open(self, "فاکتور\n\nسبد فروش خالی است.")
        except Exception as e:
            QMessageBox.critical(self, "خطا", f"ساخت PDF انجام نشد:\n{e}")
    def __init__(self):
        super().__init__()
        self.db = Database()
        self.app_settings = self.db.settings()
        self.cart = []
        self.current_invoice_no = None
        self.current_invoice_date = date.today().isoformat()
        self.active_category = "همه دسته‌ها"
        self.setLayoutDirection(Qt.RightToLeft)
        self.setWindowTitle(f"{APP_NAME} v{APP_VERSION}")
        self.setMinimumSize(900, 550)
        self._restore_window_geometry()
        self.build_style()
        self.build_ui()
        self._setup_shortcuts()
        # بررسی سلامت دیتابیس در اولین فرصت؛ SQLite در صورت وجود WAL ناتمام،
        # هنگام باز شدن اتصال recovery را انجام می‌دهد.
        QTimer.singleShot(1800, self._startup_backup_and_health_check)
        # پشتیبان خودکار هر ۱۰ دقیقه
        self._backup_timer = QTimer(self)
        self._backup_timer.setInterval(AUTO_BACKUP_INTERVAL_MS)
        self._backup_timer.timeout.connect(self._auto_backup_if_needed)
        self._backup_timer.start()
        self._usb_status_timer=QTimer(self)
        self._usb_status_timer.setInterval(3000)
        self._usb_status_timer.timeout.connect(self._refresh_secondary_backup_display)
        self._usb_status_timer.start()

    def _restore_window_geometry(self):
        settings = QSettings("NeginAbzar", "Accounting")
        geo = settings.value("geometry")
        if geo:
            try:
                self.restoreGeometry(geo)
                return
            except Exception:
                pass
        screen = QApplication.primaryScreen()
        if screen:
            area = screen.availableGeometry()
            w = min(1550, max(1000, area.width() - 40))
            h = min(900, max(650, area.height() - 40))
            self.resize(w, h)
        else:
            self.resize(1400, 760)

    def _setup_shortcuts(self):
        QShortcut(QKeySequence("Ctrl+S"), self, activated=self._shortcut_save_sale)
        QShortcut(QKeySequence("Ctrl+P"), self, activated=self._shortcut_print_invoice)
        QShortcut(QKeySequence("Ctrl+N"), self, activated=self._shortcut_clear_cart)
        QShortcut(QKeySequence("Delete"), self, activated=self._shortcut_remove_cart)
        QShortcut(QKeySequence("F5"), self, activated=self.refresh_all)
        QShortcut(QKeySequence("Ctrl+F"), self, activated=self._shortcut_focus_search)

    def _is_sales_page(self):
        return hasattr(self, "stack") and self.stack.currentIndex() == 0

    def _shortcut_save_sale(self):
        if self._is_sales_page():
            self.save_sale()

    def _shortcut_print_invoice(self):
        if self._is_sales_page():
            self.print_invoice()

    def _shortcut_clear_cart(self):
        if self._is_sales_page():
            self.clear_cart()

    def _shortcut_remove_cart(self):
        if not self._is_sales_page():
            return
        w = QApplication.focusWidget()
        if isinstance(w, (QLineEdit, QTextEdit, QComboBox, QAbstractSpinBox)):
            return
        self.remove_cart()

    def _shortcut_focus_search(self):
        if self._is_sales_page() and hasattr(self, "sale_search"):
            self.sale_search.setFocus()
            self.sale_search.selectAll()

    def _verify_backup_file(self, path):
        """بررسی سلامت یک فایل SQLite قبل از اینکه به‌عنوان بک‌آپ معتبر شناخته شود."""
        con = None
        try:
            con = sqlite3.connect(path, timeout=30)
            result = con.execute("PRAGMA integrity_check").fetchone()[0]
            return str(result).lower() == "ok", str(result)
        finally:
            if con is not None:
                con.close()

    def _get_secondary_backup_path(self):
        try:
            serial=str(self.db.get_setting("secondary_backup_volume_serial", "") or "").strip()
            if not serial: return ""
            root=_find_mounted_volume_by_serial(serial)
            if not root: return ""
            sub=str(self.db.get_setting("secondary_backup_subfolder", "NeginBackup") or "NeginBackup").strip()
            return os.path.join(root, sub)
        except Exception: return ""

    def _get_secondary_backup_password(self):
        try:
            blob=self.db.get_setting("secondary_backup_password_dpapi", "")
            if not blob: return ""
            return _dpapi_unprotect(_b64d(blob)).decode("utf-8")
        except Exception as e:
            _log_error("secondary_backup_password_unprotect", e); return ""

    def _copy_to_secondary_backup(self, source_path):
        """فقط روی همان ولوم ثبت‌شده بکاپ رمزنگاری‌شده می‌سازد؛ نبودن فلش برنامه را متوقف نمی‌کند."""
        try:
            folder=self._get_secondary_backup_path()
            if not folder:
                _log_error("secondary_backup", OSError("فلش ثبت‌شده متصل نیست.")); return False
            password=self._get_secondary_backup_password()
            if not password:
                _log_error("secondary_backup", RuntimeError("رمز بکاپ فلش تنظیم نشده است.")); return False
            os.makedirs(folder,exist_ok=True)
            if not _dir_is_writable(folder): raise OSError(f"مسیر فلش قابل نوشتن نیست: {folder}")
            name=os.path.splitext(os.path.basename(source_path))[0]+SECONDARY_BACKUP_EXTENSION
            target=os.path.join(folder,name)
            _encrypt_secondary_backup(source_path,target,password)
            log_audit("secondary_backup",f"encrypted_copy={target}")
            return True
        except Exception as e:
            _log_error("secondary_backup",e); return False

    def _create_backup_snapshot(self, target_path):
        """ساخت snapshot اتمیک: temp -> integrity_check -> os.replace."""
        os.makedirs(os.path.dirname(target_path), exist_ok=True)
        target_path = os.path.abspath(target_path)
        temp_path = target_path + f".tmp_{os.getpid()}_{time.time_ns()}"
        try:
            # Online Backup API از کپی ساده فایل امن‌تر است و snapshot سازگار می‌دهد.
            self.db.backup_to(temp_path)
            ok, detail = self._verify_backup_file(temp_path)
            if not ok:
                raise RuntimeError(f"بررسی سلامت بک‌آپ ناموفق بود: {detail}")
            os.replace(temp_path, target_path)
            # بکاپ دوم بعد از تأیید سلامت و جایگزینی موفق ساخته می‌شود.
            # خطای فلش فقط در لاگ ثبت می‌شود و بکاپ اصلی همچنان موفق محسوب می‌شود.
            self._copy_to_secondary_backup(target_path)
            return target_path
        finally:
            try:
                if os.path.exists(temp_path):
                    os.remove(temp_path)
            except Exception:
                pass

    def _prune_backups(self, folder, prefix, keep):
        try:
            files = sorted(
                [f for f in os.listdir(folder) if f.startswith(prefix) and f.endswith(".db")],
                reverse=True
            )
            for old in files[keep:]:
                try:
                    os.remove(os.path.join(folder, old))
                except Exception as e:
                    _log_error("prune_backup", e)
        except Exception as e:
            _log_error("prune_backup_list", e)

    def _create_safety_backup(self, reason="safety"):
        try:
            safety_dir = os.path.join(BACKUP_DIR, "safety")
            stamp = datetime.now().strftime("%Y%m%d_%H%M%S_%f")[:-3]
            safe_reason = "".join(c if c.isalnum() or c in "-_" else "_" for c in str(reason))[:40]
            path = os.path.join(safety_dir, f"negin_abzar_safety_{stamp}_{safe_reason}.db")
            self._create_backup_snapshot(path)
            self._prune_backups(safety_dir, "negin_abzar_safety_", SAFETY_BACKUP_KEEP)
            log_audit("safety_backup", f"reason={reason} path={path}")
            return path
        except Exception as e:
            _log_error("safety_backup", e)
            return None

    def _startup_backup_and_health_check(self):
        """بررسی سلامت دیتابیس و ساخت snapshot شروع کار."""
        try:
            check = self.db.con.execute("PRAGMA integrity_check").fetchone()[0]
            if str(check).lower() != "ok":
                _log_error("startup_integrity_check", RuntimeError(str(check)))
                QMessageBox.warning(
                    self, "هشدار سلامت دیتابیس",
                    "بررسی سلامت دیتابیس نتیجه عادی نداد.\n"
                    "برنامه اطلاعات را خودکار حذف یا جایگزین نمی‌کند.\n"
                    "لطفاً قبل از ادامه یک نسخه پشتیبان سالم را بررسی کنید."
                )
                return
            self._auto_backup_if_needed(force=True)
        except Exception as e:
            _log_error("startup_backup_and_health_check", e)

    def closeEvent(self, event):
        try:
            settings = QSettings("NeginAbzar", "Accounting")
            settings.setValue("geometry", self.saveGeometry())
        except Exception:
            pass
        try:
            # آخرین snapshot قبل از خروج؛ حتی اگر هنوز ۱۰ دقیقه نگذشته باشد.
            self._auto_backup_if_needed(force=True)
        except Exception as e:
            _log_error("close_backup", e)
        try:
            self.db.con.execute("PRAGMA wal_checkpoint(TRUNCATE)")
        except Exception as e:
            _log_error("close_checkpoint", e)
        super().closeEvent(event)

    def _auto_backup_if_needed(self, force=False):
        """پشتیبان‌گیری دوره‌ای ۱۰ دقیقه‌ای + روزانه + هفتگی با snapshot اتمیک."""
        try:
            now_dt = datetime.now()
            stamp = now_dt.strftime("%Y%m%d_%H%M%S")
            os.makedirs(BACKUP_DIR, exist_ok=True)

            # ۱) نسخه‌های خودکار ۱۰ دقیقه‌ای
            auto_dir = os.path.join(BACKUP_DIR, "auto")
            os.makedirs(auto_dir, exist_ok=True)
            auto_path = os.path.join(auto_dir, f"negin_abzar_auto_{stamp}.db")
            self._create_backup_snapshot(auto_path)
            self._prune_backups(auto_dir, "negin_abzar_auto_", AUTO_BACKUP_RECENT_KEEP)

            # ۲) یک نسخه روزانه
            day_key = now_dt.strftime("%Y-%m-%d")
            daily_dir = os.path.join(BACKUP_DIR, "daily")
            os.makedirs(daily_dir, exist_ok=True)
            daily_path = os.path.join(daily_dir, f"negin_abzar_daily_{day_key}.db")
            if force or not os.path.exists(daily_path):
                self._create_backup_snapshot(daily_path)
            self._prune_backups(daily_dir, "negin_abzar_daily_", DAILY_BACKUP_KEEP)

            # ۳) یک نسخه هفتگی؛ کلید ISO week برای یکنواختی بین سال‌ها
            iso_year, iso_week, _ = now_dt.isocalendar()
            weekly_dir = os.path.join(BACKUP_DIR, "weekly")
            os.makedirs(weekly_dir, exist_ok=True)
            weekly_path = os.path.join(weekly_dir, f"negin_abzar_weekly_{iso_year}-W{iso_week:02d}.db")
            if force or not os.path.exists(weekly_path):
                self._create_backup_snapshot(weekly_path)
            self._prune_backups(weekly_dir, "negin_abzar_weekly_", WEEKLY_BACKUP_KEEP)

        except Exception as e:
            _log_error("auto_backup", e)

    def build_style(self):
        self.setStyleSheet(f"""
        QWidget {{
            background:{BG};
            color:{TEXT};
            font-family:'Tahoma';
            font-size:13px;
        }}
        QLabel {{ background:transparent; }}
        QLineEdit,QComboBox,QSpinBox,QDoubleSpinBox,QDateEdit,QTextEdit {{
            background:{PANEL_LIGHT};
            color:{TEXT};
            border:1px solid {BORDER};
            border-radius:12px;
            padding:8px 11px;
            min-height:28px;
        }}
        QLineEdit:focus,QComboBox:focus,QSpinBox:focus,QDoubleSpinBox:focus {{
            border:2px solid {ACCENT};
        }}
        QPushButton {{
            background:{PANEL_LIGHT};
            color:{TEXT};
            border:1px solid {BORDER};
            border-radius:12px;
            padding:10px 15px;
            font-weight:800;
        }}
        QPushButton:hover {{ background:#4B9396; }}
        QTableWidget {{
            background:{PANEL_DARK};
            color:{TEXT};
            border:1px solid {BORDER};
            border-radius:14px;
            gridline-color:#39797C;
            alternate-background-color:#2C686B;
        }}
        QHeaderView::section {{
            background:{PANEL_LIGHT};
            color:{TEXT};
            border:0;
            padding:10px;
            font-weight:900;
        }}
        QScrollBar:vertical {{
            background:{PANEL_DARK};
            width:10px;
            border-radius:5px;
        }}
        QScrollBar::handle:vertical {{
            background:{BORDER};
            border-radius:5px;
        }}
        """)

    def header(self):
        c = Card(bg="#2D777A")
        c.setMinimumHeight(68)
        c.setMaximumHeight(78)
        l = QHBoxLayout(c)
        l.setContentsMargins(18, 8, 18, 8)
        l.setSpacing(12)

        # سمت راست (در RTL اولین ویجت): عنوان نرم‌افزار
        title = QLabel("حسابداری OMID PC")
        title.setStyleSheet("font-size:22px;font-weight:900;")
        l.addWidget(title)

        l.addStretch()

        # سمت چپ: اطلاعات تماس + نام برند داخل کادر (مشابه نمونه OMID PC)
        # در RTL ترتیب اضافه شدن از راست به چپ است تا در نمای بصری:
        # [تماس] [OMID PC] دیده شود.
        brand = QLabel("OMID PC")
        brand.setAlignment(Qt.AlignCenter)
        brand.setStyleSheet(
            """
            QLabel {
                background: #1F5A5E;
                color: #F4FFFF;
                border: 2px solid #7BB9BA;
                border-radius: 14px;
                padding: 8px 18px;
                font-size: 16px;
                font-weight: 900;
                min-width: 90px;
            }
            """
        )
        contact = QLabel("www.omidpcservice.ir  |  📷 @omidpcservice.ir  |  09929204355")
        contact.setStyleSheet("font-size:13px;font-weight:700;color:#E8FFFF;")
        l.addWidget(brand)
        l.addWidget(contact)
        return c

    def build_ui(self):
        root = QWidget()
        self.setCentralWidget(root)
        outer = QVBoxLayout(root)
        outer.setContentsMargins(14,12,14,12)
        outer.setSpacing(10)
        outer.addWidget(self.header())

        body = QHBoxLayout()
        body.setSpacing(16)
        outer.addLayout(body, 1)

        menu = Card()
        menu.setMinimumWidth(230)
        menu.setMaximumWidth(270)
        ml = QVBoxLayout(menu)
        ml.setContentsMargins(8,8,8,8)
        ml.setSpacing(4)

        menu_scroll = QScrollArea()
        menu_scroll.setWidgetResizable(True)
        menu_scroll.setFrameShape(QFrame.NoFrame)
        menu_scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarAlwaysOff)
        menu_scroll.setVerticalScrollBarPolicy(Qt.ScrollBarAsNeeded)
        menu_content = QWidget()
        menu_content.setStyleSheet("background:transparent;")
        ml_inner = QVBoxLayout(menu_content)
        ml_inner.setContentsMargins(6,8,6,8)
        ml_inner.setSpacing(8)
        t = QLabel("منوی اصلی")
        t.setAlignment(Qt.AlignCenter)
        t.setStyleSheet("font-size:25px;font-weight:900;")
        ml_inner.addWidget(t)
        s = QLabel("انتخاب بخش موردنظر")
        s.setAlignment(Qt.AlignCenter)
        s.setStyleSheet(f"color:{MUTED};")
        ml_inner.addWidget(s)
        ml_inner.addSpacing(8)

        items = [
            ("🧾  فاکتور فروش", 0),
            ("📦  محصولات", 1),
            ("🏭  انبار", 10),
            ("👥  مشتریان", 2),
            ("🛒  خرید و تامین", 3),
            ("📖  رسپی‌ها", 11),
            ("💰  هزینه‌ها", 5),
            ("💳  چک‌ها", 6),
            ("📊  گزارش‌ها", 7),
            ("⚙️  تنظیمات", 8),
            ("📒  حساب دفتری", 9),
        ]
        self.menu_buttons = []
        for text, idx in items:
            b = QPushButton(text)
            b.setMinimumHeight(48)
            b.clicked.connect(lambda _, i=idx: self.stack.setCurrentIndex(i))
            ml_inner.addWidget(b)
            self.menu_buttons.append(b)
        ml_inner.addStretch()
        menu_scroll.setWidget(menu_content)
        ml.addWidget(menu_scroll)
        body.addWidget(menu)

        self.stack = QStackedWidget()
        body.addWidget(self.stack, 1)

        self.make_sales()
        self.make_products()
        self.make_customers()
        self.make_purchases()
        self.make_instagram()
        self.make_expenses()
        self.make_checks()
        self.make_reports()
        self.make_settings()
        self.make_ledger()
        self.make_inventory()
        self.make_recipes()

        self.wrap_all_pages_in_scroll()
        self.refresh_all()
        self.stack.setCurrentIndex(0)
        # بعد از نمایش پنجره، چک‌های سررسیدشده را بررسی می‌کنیم.
        QTimer.singleShot(700, self.check_due_dates_on_startup)

    def title_layout(self, title, subtitle):
        l = QVBoxLayout()
        a = QLabel(title)
        a.setStyleSheet("font-size:27px;font-weight:900;")
        l.addWidget(a)
        b = QLabel(subtitle)
        b.setStyleSheet(f"font-size:13px;color:{MUTED};")
        l.addWidget(b)
        return l

    # ---------- Sales ----------
    def make_sales(self):
        page = QWidget()
        root = QVBoxLayout(page)
        root.setContentsMargins(0,0,0,0)

        top = QHBoxLayout()
        top.addLayout(self.title_layout("فاکتور فروش", "انتخاب سریع کالا و ثبت فروش"))
        top.addStretch()
        self.sale_search = QLineEdit()
        self.sale_search.setPlaceholderText("جستجوی محصول، دسته یا بارکد...")
        self.sale_search.setFixedWidth(340)
        self.sale_search.textChanged.connect(self.refresh_product_cards)
        self.sale_search.returnPressed.connect(self.scan_barcode)
        top.addWidget(self.sale_search)
        root.addLayout(top)

        split = QHBoxLayout()
        split.setSpacing(14)
        root.addLayout(split,1)

        invoice = Card()
        il = QVBoxLayout(invoice)
        it = QLabel("فاکتور فروش")
        it.setAlignment(Qt.AlignCenter)
        it.setStyleSheet("font-size:24px;font-weight:900;")
        il.addWidget(it)

        self.invoice_no_label = QLabel("شماره فاکتور امروز: 0001")
        self.invoice_no_label.setAlignment(Qt.AlignCenter)
        self.invoice_no_label.setStyleSheet("font-size:14px;font-weight:800;")
        il.addWidget(self.invoice_no_label)
        date_row = QHBoxLayout()
        date_row.addWidget(QLabel("تاریخ فاکتور:"))
        self.invoice_date_edit = QLineEdit(jalali_today())
        self.invoice_date_edit.setPlaceholderText("نمونه: 1405/06/18")
        self.invoice_date_edit.setFixedWidth(140)
        self.invoice_date_edit.editingFinished.connect(self._on_invoice_date_changed)
        date_row.addWidget(self.invoice_date_edit)
        date_hint = QLabel("شمسی")
        date_hint.setStyleSheet(f"color:{MUTED};")
        date_row.addWidget(date_hint)
        date_row.addStretch()
        il.addLayout(date_row)
        customer_row=QHBoxLayout(); customer_row.setSpacing(6)
        customer_row.addWidget(QLabel("مشتری:"))
        self.sale_customer=QComboBox(); self.sale_customer.setEditable(True); self.sale_customer.setInsertPolicy(QComboBox.NoInsert); self.sale_customer.addItem("مشتری آزاد / نقدی",None); self.sale_customer.setMinimumHeight(40)
        self.sale_customer.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Fixed)
        customer_row.addWidget(self.sale_customer,1)
        customer_note = QLabel("بعد از ثبت فاکتور خودکار آزاد می‌شود")
        customer_note.setWordWrap(True)
        customer_note.setMinimumWidth(0)
        customer_note.setSizePolicy(QSizePolicy.Preferred, QSizePolicy.Preferred)
        customer_row.addWidget(customer_note,0)
        il.addLayout(customer_row)

        self.cart_table = QTableWidget(0,6)
        self.cart_table.setHorizontalHeaderLabels(
            ["ردیف","محصول","قیمت واحد","تعداد","تخفیف","جمع"])
        self.cart_table.setHorizontalScrollBarPolicy(Qt.ScrollBarAlwaysOff)
        self.cart_table.setVerticalScrollBarPolicy(Qt.ScrollBarAsNeeded)
        self.cart_table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        self.cart_table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.cart_table.cellDoubleClicked.connect(self.edit_cart_discount)
        il.addWidget(self.cart_table,1)

        total = Card(bg="#225D61")
        tv = QVBoxLayout(total)
        pay_row = QHBoxLayout()
        self.total_label = QLabel("0 تومان")
        self.total_label.setStyleSheet("font-size:27px;font-weight:900;")
        pay_row.addWidget(self.total_label)
        self.profit_label = QLabel("سود: 0 تومان")
        self.profit_label.setStyleSheet(f"font-size:14px;font-weight:800;color:{GOOD};")
        pay_row.addWidget(self.profit_label)
        pay_row.addStretch()
        pay_row.addWidget(QLabel("روش پرداخت:"))
        self.payment = QComboBox()
        self.payment.addItems(["نقدی","کارتخوان","واریز بانکی","نسیه","چک"])
        self.payment.setMinimumWidth(110)
        self.payment.setMaximumWidth(150)
        pay_row.addWidget(self.payment)
        tv.addLayout(pay_row)

        # اطلاعات چک در یک ردیف جداگانه قرار گرفته تا در پنجره‌های کوچک بریده نشود.
        self.check_panel = QFrame()
        self.check_panel.setStyleSheet(f"QFrame{{background:{PANEL_DARK};border:1px solid {BORDER};border-radius:10px;}}")
        check_grid = QGridLayout(self.check_panel)
        check_grid.setContentsMargins(10,8,10,8)
        check_grid.setHorizontalSpacing(8)
        check_grid.setVerticalSpacing(6)

        self.check_no = QLineEdit(); self.check_no.setPlaceholderText("شماره چک")
        self.check_bank = QLineEdit(); self.check_bank.setPlaceholderText("نام بانک")
        self.check_branch = QLineEdit(); self.check_branch.setPlaceholderText("شعبه")
        self.check_issue = QLineEdit(jalali_today()); self.check_issue.setPlaceholderText("تاریخ صدور 1405/06/18")
        self.check_due = QLineEdit(jalali_today()); self.check_due.setPlaceholderText("تاریخ سررسید 1405/06/18")
        fields = [
            ("شماره چک:", self.check_no), ("بانک:", self.check_bank),
            ("شعبه:", self.check_branch), ("تاریخ صدور:", self.check_issue),
            ("تاریخ سررسید:", self.check_due)
        ]
        for idx, (label, widget) in enumerate(fields):
            row = idx // 3
            col = idx % 3
            check_grid.addWidget(QLabel(label), row * 2, col, Qt.AlignRight)
            check_grid.addWidget(widget, row * 2 + 1, col)
            widget.setMinimumWidth(120)
        self.check_panel.hide()
        tv.addWidget(self.check_panel)

        def toggle_check_fields(_=None):
            show = self.payment.currentText() == "چک"
            self.check_panel.setVisible(show)
            if show:
                self.check_no.setFocus()
        self.payment.currentIndexChanged.connect(toggle_check_fields)
        il.addWidget(total)

        # دکمه‌های فاکتور در دو ردیف قرار می‌گیرند تا در عرض کمتر هم اسکرول افقی ایجاد نشود.
        actions = QGridLayout()
        actions.setHorizontalSpacing(6)
        actions.setVerticalSpacing(6)
        action_buttons = []

        x = QPushButton("🗑 حذف ردیف")
        x.clicked.connect(self.remove_cart)
        action_buttons.append(x)
        x = QPushButton("🧹 پاک کردن")
        x.clicked.connect(self.clear_cart)
        action_buttons.append(x)
        x = QPushButton("🖨 چاپ فاکتور")
        x.clicked.connect(self.print_invoice)
        action_buttons.append(x)
        x = QPushButton("📚 سوابق فاکتورها")
        x.clicked.connect(self.show_sales_history)
        action_buttons.append(x)
        x = QPushButton("↩️ ابطال کامل فاکتور")
        x.clicked.connect(self.void_sale_dialog)
        action_buttons.append(x)
        x = QPushButton("🔁 مرجوعی جزئی")
        x.clicked.connect(lambda: self.partial_return_dialog())
        action_buttons.append(x)
        x = QPushButton("✓ ثبت فاکتور")
        x.setStyleSheet(f"background:{ACCENT};color:#123638;")
        x.clicked.connect(self.save_sale)
        action_buttons.append(x)

        for i, btn in enumerate(action_buttons):
            btn.setMinimumWidth(0)
            btn.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Fixed)
            actions.addWidget(btn, i // 3, i % 3)
        for col in range(3):
            actions.setColumnStretch(col, 1)
        il.addLayout(actions)
        # فاکتور کمی باریک‌تر باشد تا محصولات فضای کافی برای ۳ ستون داشته باشند.
        invoice.setMinimumWidth(0)
        invoice.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Expanding)
        split.addWidget(invoice,40)

        products = Card()
        # حداقل عرض لازم برای نمایش سه کارت در هر ردیف
        products.setMinimumWidth(560)
        products.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Expanding)
        pl = QVBoxLayout(products)
        pt = QLabel("محصولات")
        pt.setAlignment(Qt.AlignCenter)
        pt.setStyleSheet("font-size:24px;font-weight:900;")
        pl.addWidget(pt)

        cats_widget = QWidget()
        self.cats_layout = QHBoxLayout(cats_widget)
        self.cats_layout.setContentsMargins(2, 2, 2, 2)
        self.cats_layout.setSpacing(7)
        cats_scroll = QScrollArea()
        cats_scroll.setWidgetResizable(True)
        cats_scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarAlwaysOff)
        cats_scroll.setVerticalScrollBarPolicy(Qt.ScrollBarAlwaysOff)
        cats_scroll.setFrameShape(QFrame.NoFrame)
        cats_scroll.setFixedHeight(58)
        cats_scroll.setWidget(cats_widget)
        pl.addWidget(cats_scroll)
        # دسته‌ها را بعد از ساخت product_grid تازه‌سازی می‌کنیم؛
        # چون refresh_product_category_views در نهایت کارت‌های محصولات را رفرش می‌کند.

        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QFrame.NoFrame)
        # فقط اسکرول عمودی؛ محصولات هیچ‌وقت اسکرول افقی نمی‌خواهند.
        scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarAlwaysOff)
        scroll.setVerticalScrollBarPolicy(Qt.ScrollBarAsNeeded)
        self.product_scroll = scroll
        self.product_area = QWidget()
        self.product_area.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Preferred)
        self.product_grid = QGridLayout(self.product_area)
        self.product_grid.setSpacing(12)
        self.product_grid.setContentsMargins(8, 8, 8, 8)
        self.product_grid.setAlignment(Qt.AlignTop | Qt.AlignRight)
        scroll.setWidget(self.product_area)
        pl.addWidget(scroll,1)

        # حالا که product_grid و product_scroll ساخته شده‌اند، دسته‌ها و کارت‌ها را
        # بدون خطای AttributeError تازه‌سازی می‌کنیم.
        self.refresh_product_category_views()

        # فضای بیشتر برای محصولات تا کارت‌ها کوچک نشوند.
        split.addWidget(products,60)
        split.setStretch(0, 40)
        split.setStretch(1, 60)

        self.stack.addWidget(page)

    def set_category(self, c):
        self.active_category = c
        self.refresh_product_cards()

    def refresh_product_cards(self):
        while self.product_grid.count():
            item = self.product_grid.takeAt(0)
            if item.widget():
                item.widget().deleteLater()
        rows = self.db.products(self.sale_search.text().strip(), self.active_category)

        viewport_width = self.product_scroll.viewport().width()
        available = max(220, viewport_width - 32)
        min_card_width = 150
        # با حداقل عرض 620 پیکسل، پنل محصولات در حالت عادی ۳ ستون کامل دارد.
        columns = max(1, min(3, available // min_card_width))

        for i, p in enumerate(rows):
            card = ProductCard(p)
            card.clicked.connect(self.add_to_cart)
            self.product_grid.addWidget(card, i // columns, i % columns)
            self.product_grid.setColumnStretch(i % columns, 1)

        # با تغییر اندازه پنجره، تعداد ستون‌ها خودکار اصلاح می‌شود.
        if not hasattr(self, "_product_resize_connected"):
            self._product_resize_connected = True
            self.product_scroll.viewport().installEventFilter(self)

    def eventFilter(self, obj, event):
        if hasattr(self, "product_scroll") and obj is self.product_scroll.viewport():
            if event.type() == QEvent.Resize:
                if not hasattr(self, "_product_resize_timer"):
                    self._product_resize_timer = QTimer(self)
                    self._product_resize_timer.setSingleShot(True)
                    self._product_resize_timer.timeout.connect(self.refresh_product_cards)
                self._product_resize_timer.start(80)
        return super().eventFilter(obj, event)

    def _sync_invoice_date_from_field(self):
        if not hasattr(self, "invoice_date_edit"):
            self.current_invoice_date = date.today().isoformat()
            return self.current_invoice_date
        try:
            iso = normalize_date_input(self.invoice_date_edit.text().strip())
        except Exception as e:
            raise ValueError(str(e))
        self.current_invoice_date = iso
        self.invoice_date_edit.setText(format_jalali_date(iso))
        return iso

    def _on_invoice_date_changed(self):
        if self.cart:
            QMessageBox.information(self, "تاریخ فاکتور", "برای تغییر تاریخ، ابتدا سبد را خالی کنید.")
            self.invoice_date_edit.setText(format_jalali_date(self.current_invoice_date))
            return
        try:
            iso = self._sync_invoice_date_from_field()
        except Exception as e:
            QMessageBox.warning(self, "تاریخ", str(e))
            self.invoice_date_edit.setText(jalali_today())
            self.current_invoice_date = date.today().isoformat()
            iso = self.current_invoice_date
        self.current_invoice_no = self.db.next_invoice_no(iso)
        if hasattr(self, "invoice_no_label"):
            self.invoice_no_label.setText(
                f"شماره فاکتور {format_jalali_date(iso)}: {self.current_invoice_no:04d}"
            )

    def add_to_cart(self, p):
        if self.current_invoice_no is None:
            try:
                iso = self._sync_invoice_date_from_field()
            except Exception:
                iso = date.today().isoformat()
                self.current_invoice_date = iso
            self.current_invoice_no = self.db.next_invoice_no(iso)
            if hasattr(self, "invoice_no_label"):
                self.invoice_no_label.setText(
                    f"شماره فاکتور {format_jalali_date(iso)}: {self.current_invoice_no:04d}"
                )

        stock = to_decimal(p["stock"])
        if stock <= 0:
            QMessageBox.warning(self,"موجودی","موجودی این کالا تمام شده است.")
            return
        for x in self.cart:
            if x["id"] == p["id"]:
                new_qty = to_decimal(x["qty"]) + 1
                if new_qty > stock:
                    QMessageBox.warning(self,"موجودی","تعداد انتخاب‌شده بیشتر از موجودی است.")
                    return
                x["qty"] = new_qty
                self.refresh_cart()
                return
        self.cart.append({
            "id":p["id"], "name":p["name"], "price":p["sell_price"],
            "buy_price":p["buy_price"], "qty":Decimal("1"), "discount":0
        })
        self.refresh_cart()

    def scan_barcode(self):
        code=self.sale_search.text().strip()
        if not code: return
        row=self.db.con.execute("SELECT * FROM products WHERE barcode=? AND COALESCE(active,1)=1 LIMIT 1",(code,)).fetchone()
        if row:
            self.add_to_cart(row)
            self.sale_search.clear()
        else:
            self.refresh_product_cards()

    def refresh_cart(self):
        self.cart_table.setRowCount(0)
        total = Decimal("0")
        profit = Decimal("0")

        # سود پیش‌نمایش هم باید دقیقاً با همان FIFO مورد استفاده هنگام ثبت فروش
        # محاسبه شود تا عدد قبل و بعد از ثبت فاکتور متفاوت نباشد.
        fifo_cost_by_pid = {}
        qty_by_pid = {}
        for x in self.cart:
            pid = int(x["id"])
            qty_by_pid[pid] = qty_by_pid.get(pid, Decimal("0")) + to_decimal(x["qty"])
        try:
            cur = self.db.con.cursor()
            for pid, qty in qty_by_pid.items():
                fifo_cost_by_pid[pid] = self.db._fifo_cost_for_sale(cur, pid, qty)
        except Exception:
            # پیش‌نمایش نباید در صورت خرابی موقت داده‌های تاریخی، مانع کار صندوق شود.
            fifo_cost_by_pid = {}

        for i, x in enumerate(self.cart, 1):
            self.cart_table.insertRow(i - 1)
            line_gross = to_decimal(x["price"]) * to_decimal(x["qty"])
            line_discount = to_decimal(x.get("discount", 0) or 0)
            line_final = max(Decimal("0"), line_gross - line_discount)
            vals = [
                i, x["name"], money(x["price"]), format_qty(x["qty"]),
                money(line_discount), money(line_final)
            ]
            for j, v in enumerate(vals):
                self.cart_table.setItem(i - 1, j, center_item(v))
            total += line_final
            pid = int(x["id"])
            row_qty = to_decimal(x["qty"])
            total_pid_qty = qty_by_pid.get(pid, row_qty)
            if pid in fifo_cost_by_pid and total_pid_qty > 0:
                # هزینه FIFO کل یک کالا را متناسب با مقدار هر ردیف پخش می‌کنیم.
                row_fifo_cost = fifo_cost_by_pid[pid] * row_qty / total_pid_qty
            else:
                buy = to_decimal(x.get("buy_price", 0) or 0)
                row_fifo_cost = buy * row_qty
            profit += line_final - row_fifo_cost
        self.total_label.setText(money(total))
        if hasattr(self, "profit_label"):
            self.profit_label.setText(f"سود: {money(round(profit))}")

    def edit_cart_discount(self, row, column):
        if row < 0 or row >= len(self.cart): return
        x=self.cart[row]
        p=self.db.product(x["id"])
        stock = to_decimal(p["stock"]) if p else to_decimal(x["qty"])
        dlg=QDialog(self); dlg.setWindowTitle("ویرایش ردیف فاکتور"); dlg.setLayoutDirection(Qt.RightToLeft)
        f=QFormLayout(dlg)
        qty=CleanDoubleSpinBox(); qty.setDecimals(2); qty.setRange(0.01, float(stock) if stock > 0 else 0.01); qty.setValue(float(to_decimal(x["qty"])))
        amount=MoneySpinBox(); amount.setMaximum(999999999999); amount.setValue(float(x.get("discount",0)))
        f.addRow("تعداد:", qty)
        f.addRow("تخفیف:", amount)
        info=QLabel(f"موجودی قابل فروش: {format_qty(stock)}")
        info.setStyleSheet(f"color:{MUTED};")
        f.addRow(info)
        b=QDialogButtonBox(QDialogButtonBox.Save|QDialogButtonBox.Cancel); b.accepted.connect(dlg.accept); b.rejected.connect(dlg.reject); f.addRow(b)
        if dlg.exec():
            new_qty = to_decimal(qty.value())
            if new_qty > stock:
                QMessageBox.warning(self,"موجودی","تعداد نمی‌تواند از موجودی بیشتر باشد."); return
            max_discount=float(to_decimal(x["price"])*new_qty)
            if amount.value()>max_discount:
                QMessageBox.warning(self,"تخفیف","تخفیف نمی‌تواند از مبلغ ردیف بیشتر باشد."); return
            x["qty"]=new_qty
            x["discount"]=int(money_decimal(amount.value()))
            self.refresh_cart()

    def remove_cart(self):
        r = self.cart_table.currentRow()
        if 0 <= r < len(self.cart):
            self.cart.pop(r)
            self.refresh_cart()

    def clear_cart(self):
        self.cart.clear()
        self.current_invoice_no = None
        if hasattr(self, "invoice_date_edit"):
            self.invoice_date_edit.setText(jalali_today())
        self.current_invoice_date = date.today().isoformat()
        if hasattr(self, "invoice_no_label"):
            nxt = self.db.next_invoice_no(self.current_invoice_date)
            self.invoice_no_label.setText(f"شماره فاکتور {jalali_today()}: {nxt:04d}")
        self.refresh_cart()

    def save_sale(self):
        if not self.cart:
            QMessageBox.warning(self,"فاکتور خالی","حداقل یک محصول انتخاب کنید.")
            return
        discount = sum(to_decimal(x.get("discount", 0) or 0) for x in self.cart)
        try:
            self.current_invoice_date = self._sync_invoice_date_from_field()
        except Exception as e:
            QMessageBox.warning(self, "تاریخ فاکتور", str(e))
            return
        self.current_invoice_no = self.db.next_invoice_no(self.current_invoice_date)

        customer_id = self._resolve_combo_customer(self.sale_customer) if hasattr(self,"sale_customer") else None
        if self.payment.currentText() in ("نسیه", "چک") and not customer_id:
            QMessageBox.warning(self,"مشتری","برای فروش نسیه یا چکی ابتدا مشتری را از فهرست انتخاب کنید."); return
        try:
            check_data=None
            if self.payment.currentText()=="چک":
                check_data={
                    "person": self.sale_customer.currentText().split(" | ")[0],
                    "check_no": self.check_no.text().strip(),
                    "bank": self.check_bank.text().strip(),
                    "branch": self.check_branch.text().strip(),
                    "due_date": normalize_date_input(self.check_due.text().strip()),
                    "issue_date": normalize_date_input(self.check_issue.text().strip()),
                    "notes": "چک دریافتی بابت فاکتور"
                }
                if not check_data["check_no"] or not check_data["due_date"]:
                    QMessageBox.warning(self,"چک","شماره چک و تاریخ سررسید را وارد کنید."); return
            sid,invoice_no,total,profit=self.db.save_sale(self.cart,customer_id,discount,self.payment.currentText(),self.current_invoice_no,self.current_invoice_date,check_data)
        except Exception as e:
            QMessageBox.critical(self,"خطای ثبت فاکتور",str(e)); return
        # خروجی فاکتور دقیقاً بر اساس گزینه انتخاب‌شده در تنظیمات چاپگر:
        # PDF => فقط PDF ساخته و روی مانیتور باز شود.
        # چاپگر ویندوز => فقط مستقیم چاپ شود و هیچ PDF/پیش‌نمایشی باز نشود.
        selected_output = ""
        if hasattr(self, "printer_combo"):
            selected_output = str(self.printer_combo.currentData() or "").strip()
        if not selected_output:
            selected_output = str(self.db.get_setting("printer", "") or "").strip()

        output_error = None
        output_message = ""
        try:
            if selected_output == "__PDF__":
                self.create_and_open_invoice_pdf_auto(
                    invoice_no, self.current_invoice_date,
                    self.sale_customer.currentText(), self.payment.currentText()
                )
                output_message = "PDF فاکتور باز شد."
            else:
                self.print_current_invoice_auto(
                    invoice_no, self.current_invoice_date,
                    self.sale_customer.currentText(), self.payment.currentText()
                )
                output_message = "فاکتور مستقیم برای چاپگر ارسال شد."
        except Exception as e:
            output_error = e

        if output_error:
            QMessageBox.warning(
                self, "فاکتور ثبت شد",
                f"شماره فاکتور: {invoice_no:04d}\nمبلغ: {money(total)}\nسود: {money(profit)}\n\nفاکتور ثبت شد، اما خروجی انجام نشد:\n{output_error}"
            )
        else:
            QMessageBox.information(
                self, "فاکتور ثبت شد",
                f"شماره فاکتور: {invoice_no:04d}\nمبلغ: {money(total)}\nسود: {money(profit)}\n\n{output_message}"
            )
        self.clear_cart()
        # بعد از ثبت فاکتور، مشتری قبلی هرگز برای فاکتور بعدی باقی نماند.
        if hasattr(self, "sale_customer"):
            self.sale_customer.blockSignals(True)
            self.sale_customer.setCurrentIndex(0)  # مشتری آزاد / نقدی
            self.sale_customer.blockSignals(False)
        if hasattr(self, "payment"):
            self.payment.setCurrentText("نقدی")
        self.refresh_all()

    def create_and_open_invoice_pdf_auto(self, invoice_no, invoice_date, customer_name, payment_name):
        """ساخت PDF موقت از فاکتور ثبت‌شده و باز کردن فوری آن در PDF Viewer ویندوز."""
        import tempfile, os, subprocess
        folder = os.path.join(tempfile.gettempdir(), "NeginAbzarInvoices")
        os.makedirs(folder, exist_ok=True)
        path = os.path.join(folder, f"فاکتور_{int(invoice_no):04d}_{int(time.time()*1000)}.pdf")

        printer = QPrinter(QPrinter.PrinterMode.HighResolution)
        printer.setOutputFormat(QPrinter.OutputFormat.PdfFormat)
        printer.setOutputFileName(path)
        self.configure_printer_page(printer)

        html = self.invoice_html(
            cart=self.cart,
            invoice_no=int(invoice_no),
            invoice_date=invoice_date,
            customer_name=customer_name,
            payment_name=payment_name
        )
        doc = QTextDocument()
        doc.setDefaultFont(QFont("Tahoma", 9))
        doc.setDocumentMargin(0)
        doc.setHtml(html)
        try:
            doc.setPageSize(printer.pageRect(QPrinter.Unit.Point).size())
        except Exception:
            pass
        doc.print_(printer)

        if not os.path.exists(path) or os.path.getsize(path) < 100:
            raise RuntimeError("فایل PDF فاکتور ساخته نشد.")

        if not open_path(path):
            raise RuntimeError("فایل PDF ساخته شد اما برنامه‌ای برای باز کردن آن پیدا نشد.")

        return path

    def print_current_invoice_auto(self, invoice_no, invoice_date, customer_name, payment_name):
        """چاپ خودکار واقعی فاکتور روی چاپگر ویندوز، بدون QPrintDialog."""
        # چاپگر انتخاب‌شده در تنظیمات را پیدا کن؛ اگر نبود، چاپگر پیش‌فرض ویندوز را بگیر.
        selected = ""
        if hasattr(self, "printer_combo"):
            selected = str(self.printer_combo.currentData() or "").strip()
        if not selected:
            selected = str(self.db.get_setting("printer", "") or "").strip()

        infos = list(QPrinterInfo.availablePrinters())
        default_name = str(QPrinterInfo.defaultPrinterName() or "").strip()
        names = [str(i.printerName()).strip() for i in infos]

        # وقتی کاربر PDF را انتخاب کرده، فقط PDF ساخته و باز می‌شود؛
        # انتخاب PDF نباید ناخواسته به چاپگر پیش‌فرض ویندوز ارسال شود.
        if selected == "__PDF__":
            return
        if selected not in names:
            selected = default_name

        if not selected:
            raise RuntimeError("چاپگر پیش‌فرض ویندوز پیدا نشد. از تنظیمات چاپگر، یک چاپگر واقعی انتخاب کنید.")

        # مهم: چاپگر را با QPrinterInfo می‌سازیم؛ این روش روی نسخه‌های مختلف Qt/PySide6
        # از setPrinterName روی QPrinter پایدارتر است.
        info = next((i for i in infos if str(i.printerName()).strip() == selected), None)
        if info is None:
            raise RuntimeError(f"چاپگر «{selected}» در فهرست چاپگرهای ویندوز پیدا نشد.")

        printer = QPrinter(info, QPrinter.PrinterMode.HighResolution)
        printer.setOutputFormat(QPrinter.OutputFormat.NativeFormat)

        try:
            copies = int(self.db.get_setting("copies", "1") or 1)
        except Exception:
            copies = 1
        printer.setCopyCount(max(1, min(99, copies)))
        self.configure_printer_page(printer)

        html = self.invoice_html(
            cart=self.cart,
            invoice_no=int(invoice_no),
            invoice_date=invoice_date,
            customer_name=customer_name,
            payment_name=payment_name
        )
        doc = QTextDocument()
        doc.setDefaultFont(QFont("Tahoma", 9))
        doc.setDocumentMargin(0)
        doc.setHtml(html)

        try:
            doc.setPageSize(printer.pageRect(QPrinter.Unit.Point).size())
        except Exception:
            pass

        # چاپ مستقیم؛ هیچ دیالوگی باز نمی‌شود.
        doc.print_(printer)

    def show_sales_history(self):
        d=QDialog(self); d.setWindowTitle("📚 سوابق فاکتورها"); d.setLayoutDirection(Qt.RightToLeft); d.resize(1050,620)
        root=QVBoxLayout(d)
        search=QLineEdit(); search.setPlaceholderText("جستجو با شماره فاکتور، نام مشتری یا تلفن..."); root.addWidget(search)
        table=QTableWidget(0,8); table.setHorizontalHeaderLabels(["شناسه","شماره","تاریخ","مشتری","مبلغ","سود","پرداخت","وضعیت"]); table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch); table.setSelectionBehavior(QAbstractItemView.SelectRows); root.addWidget(table)
        buttons=QHBoxLayout(); print_btn=QPushButton("🖨 چاپ مجدد فاکتور انتخاب‌شده"); partial_btn=QPushButton("🔁 مرجوعی جزئی"); void_btn=QPushButton("↩️ ابطال کامل"); close_btn=QPushButton("بستن"); buttons.addWidget(print_btn); buttons.addWidget(partial_btn); buttons.addWidget(void_btn); buttons.addStretch(); buttons.addWidget(close_btn); root.addLayout(buttons)
        def load():
            q=search.text().strip(); like=f"%{q}%"
            rows=self.db.con.execute("""SELECT s.*, COALESCE(c.name,'مشتری آزاد / نقدی') customer, COALESCE(c.phone,'') phone
                FROM sales s LEFT JOIN customers c ON c.id=s.customer_id
                WHERE (?='' OR CAST(s.invoice_no AS TEXT) LIKE ? OR customer LIKE ? OR phone LIKE ?)
                ORDER BY s.id DESC""",(q,like,like,like)).fetchall()
            table.setRowCount(0)
            for r in rows:
                i=table.rowCount(); table.insertRow(i); vals=[r['id'],f"{int(r['invoice_no'] or r['id']):04d}",format_jalali_date(r['invoice_date'] or r['created_at']),r['customer'],money(r['total']),money(r['profit']),r['payment'],r['status'] or 'فعال']
                for j,v in enumerate(vals): table.setItem(i,j,center_item(v))
        def selected_id():
            r=table.currentRow()
            if r<0: return None
            return int(table.item(r,0).text())
        search.textChanged.connect(load)
        print_btn.clicked.connect(lambda: self.print_saved_sale(selected_id()))
        def do_void():
            sid=selected_id()
            if not sid: return
            reason,ok=QInputDialog.getText(self,"ابطال فاکتور","علت:")
            if not ok:
                return
            if QMessageBox.question(d,"تأیید","این فاکتور ابطال و کالاها به انبار برگردانده شوند؟")!=QMessageBox.Yes:
                return
            try: self.db.void_sale(sid,reason.strip() or "ابطال/مرجوعی"); load(); self.refresh_all()
            except Exception as e: QMessageBox.warning(d,"خطا",str(e))
        void_btn.clicked.connect(do_void)
        def do_partial():
            sid=selected_id()
            if not sid:
                QMessageBox.information(d,"مرجوعی","یک فاکتور را انتخاب کنید.")
                return
            self.partial_return_dialog(sid)
            load(); self.refresh_all()
        partial_btn.clicked.connect(do_partial)
        close_btn.clicked.connect(d.accept)
        load(); d.exec()

    def print_saved_sale(self, sale_id):
        if not sale_id:
            QMessageBox.information(self,"چاپ مجدد","یک فاکتور را انتخاب کنید."); return
        sale=self.db.con.execute("SELECT s.*,COALESCE(c.name,'مشتری آزاد / نقدی') customer FROM sales s LEFT JOIN customers c ON c.id=s.customer_id WHERE s.id=?",(int(sale_id),)).fetchone()
        if not sale: return
        if (sale["status"] or "فعال") == "باطل":
            QMessageBox.information(self,"چاپ","این فاکتور ابطال شده است.")
            return
        items=self.db.con.execute("SELECT si.*,p.name FROM sale_items si LEFT JOIN products p ON p.id=si.product_id WHERE si.sale_id=? ORDER BY si.id",(int(sale_id),)).fetchall()
        cart=[]
        for r in items:
            qty=to_decimal(r['qty'] or 0)
            returned=to_decimal(r['returned_qty'] or 0) if 'returned_qty' in r.keys() else Decimal('0')
            live=max(Decimal('0'), qty-returned)
            if live<=0:
                continue
            disc=to_decimal(r['discount'] or 0)
            live_disc=float(disc * live / qty) if qty else 0
            cart.append({"id":r['product_id'],"name":r['name'] or 'کالا حذف/غیرفعال‌شده',"price":float(r['price'] or 0),"qty":float(live),"discount":live_disc})
        # تخفیف هر ردیف از خود فاکتور خوانده می‌شود؛ بازچینی تقریبی دیگر لازم نیست.
        html=self.invoice_html(
            cart=cart,
            invoice_no=int(sale['invoice_no'] or sale['id']),
            invoice_date=sale['invoice_date'] or sale['created_at'],
            customer_name=sale['customer'],
            payment_name=sale['payment']
        )
        selected = self.printer_combo.currentData() if hasattr(self,"printer_combo") else None
        if selected == "__PDF__":
            path,_=QFileDialog.getSaveFileName(self,"ذخیره فاکتور به PDF",f"فاکتور_{int(sale['invoice_no'] or sale['id']):04d}.pdf","PDF (*.pdf)")
            if not path: return
            if not path.lower().endswith(".pdf"): path += ".pdf"
            printer=QPrinter(QPrinter.PrinterMode.HighResolution); printer.setOutputFormat(QPrinter.OutputFormat.PdfFormat); printer.setOutputFileName(path)
            self.configure_printer_page(printer); doc=QTextDocument(); doc.setDefaultFont(QFont("Tahoma",9)); doc.setHtml(html); doc.print_(printer)
            open_path(path)
            return
        printer=QPrinter(QPrinter.PrinterMode.HighResolution); printer.setOutputFormat(QPrinter.OutputFormat.NativeFormat)
        if selected: printer.setPrinterName(selected)
        self.configure_printer_page(printer); dialog=QPrintDialog(printer,self); dialog.setWindowTitle("چاپ مجدد فاکتور")
        if dialog.exec()!=QDialog.DialogCode.Accepted: return
        self.configure_printer_page(printer); doc=QTextDocument(); doc.setDefaultFont(QFont("Tahoma",9)); doc.setHtml(html); doc.print_(printer)

    def void_sale_dialog(self):
        dlg=QDialog(self); dlg.setWindowTitle("ابطال / مرجوعی فاکتور"); dlg.setLayoutDirection(Qt.RightToLeft)
        f=QFormLayout(dlg); day=QLineEdit(jalali_today()); no=QSpinBox(); no.setRange(1,999999999); reason=QLineEdit("مرجوعی کالا / اصلاح فاکتور")
        f.addRow("تاریخ فاکتور:",day); f.addRow("شماره فاکتور:",no); f.addRow("علت:",reason)
        b=QDialogButtonBox(QDialogButtonBox.Save|QDialogButtonBox.Cancel); b.accepted.connect(dlg.accept); b.rejected.connect(dlg.reject); f.addRow(b)
        if dlg.exec():
            try:
                invoice_date = normalize_date_input(day.text().strip())
            except Exception as e:
                QMessageBox.warning(self,"تاریخ",str(e)); return
            row=self.db.con.execute("SELECT id FROM sales WHERE invoice_date=? AND invoice_no=?",(invoice_date,no.value())).fetchone()
            if not row:
                QMessageBox.warning(self,"فاکتور","فاکتور پیدا نشد."); return
            if QMessageBox.question(self,"تأیید",f"فاکتور {no.value():04d} ابطال و کالاها به انبار برگردانده شوند؟")!=QMessageBox.Yes: return
            try:
                self.db.void_sale(row[0],reason.text())
                self.refresh_all(); QMessageBox.information(self,"انجام شد","فاکتور ابطال شد و موجودی/حساب اصلاح گردید.")
            except Exception as e: QMessageBox.critical(self,"خطا",str(e))

    def partial_return_dialog(self, sale_id=None):
        dlg = QDialog(self)
        dlg.setWindowTitle("🔁 مرجوعی جزئی فاکتور")
        dlg.setLayoutDirection(Qt.RightToLeft)
        dlg.resize(820, 560)
        root = QVBoxLayout(dlg)
        pick = QHBoxLayout()
        day = QLineEdit(jalali_today())
        no = QSpinBox(); no.setRange(1, 999999999)
        load_btn = QPushButton("بارگذاری فاکتور")
        pick.addWidget(QLabel("تاریخ:")); pick.addWidget(day)
        pick.addWidget(QLabel("شماره:")); pick.addWidget(no)
        pick.addWidget(load_btn)
        root.addLayout(pick)
        info = QLabel("فاکتور را بارگذاری کنید و تعداد مرجوعی هر کالا را وارد کنید.")
        info.setStyleSheet(f"color:{MUTED};")
        root.addWidget(info)
        table = QTableWidget(0, 6)
        table.setHorizontalHeaderLabels(["کالا", "فروخته", "قبلاً مرجوع", "مانده", "مرجوعی الان", "مبلغ مرجوعی"])
        table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        root.addWidget(table)
        reason = QLineEdit("مرجوعی جزئی کالا")
        form = QFormLayout(); form.addRow("علت:", reason)
        root.addLayout(form)
        total_lbl = QLabel("مبلغ مرجوعی: 0 تومان")
        total_lbl.setStyleSheet("font-size:18px;font-weight:900;")
        root.addWidget(total_lbl)
        buttons = QDialogButtonBox(QDialogButtonBox.Save | QDialogButtonBox.Cancel)
        buttons.accepted.connect(dlg.accept)
        buttons.rejected.connect(dlg.reject)
        root.addWidget(buttons)

        state = {"sale_id": None, "items": []}

        def recalc():
            total = Decimal("0")
            for r, it in enumerate(state["items"]):
                spin = table.cellWidget(r, 4)
                q = to_decimal(spin.value()) if spin else Decimal("0")
                live, live_final, _ = self.db._sale_line_live(it)
                orig_qty = to_decimal(it["qty"] or 0)
                orig_final = to_decimal(it["final_price"] or 0)
                if orig_final <= 0:
                    orig_final = money_decimal(to_decimal(it["price"] or 0) * orig_qty - to_decimal(it["discount"] or 0))
                amt = money_decimal(orig_final * q / orig_qty) if orig_qty and q else Decimal("0")
                total += amt
                table.setItem(r, 5, center_item(money(amt)))
            total_lbl.setText(f"مبلغ مرجوعی: {money(total)}")

        def fill(sid):
            sale = self.db.con.execute(
                "SELECT s.*, COALESCE(c.name,'مشتری آزاد / نقدی') customer FROM sales s LEFT JOIN customers c ON c.id=s.customer_id WHERE s.id=?",
                (int(sid),),
            ).fetchone()
            if not sale:
                QMessageBox.warning(dlg, "فاکتور", "فاکتور پیدا نشد.")
                return
            if (sale["status"] or "فعال") not in ("فعال", "مرجوع جزئی"):
                QMessageBox.warning(dlg, "فاکتور", "این فاکتور ابطال شده و قابل مرجوعی نیست.")
                return
            items = self.db.con.execute(
                """SELECT si.*, p.name FROM sale_items si
                   LEFT JOIN products p ON p.id=si.product_id
                   WHERE si.sale_id=? ORDER BY si.id""",
                (int(sid),),
            ).fetchall()
            state["sale_id"] = int(sid)
            state["items"] = items
            extra = ""
            if sale["payment"] == "چک":
                extra = " | فروش چکی: مبلغ چک دستی در بخش چک‌ها اصلاح شود"
            info.setText(
                f"فاکتور {int(sale['invoice_no'] or sale['id']):04d} | "
                f"{sale['customer']} | {money(sale['total'])} | {sale['status'] or 'فعال'}{extra}"
            )
            table.setRowCount(0)
            for it in items:
                live, _lf, _ld = self.db._sale_line_live(it)
                returned = to_decimal(it["returned_qty"] or 0)
                r = table.rowCount(); table.insertRow(r)
                table.setItem(r, 0, center_item(it["name"] or "کالا"))
                table.setItem(r, 1, center_item(format_qty(it["qty"])))
                table.setItem(r, 2, center_item(format_qty(returned)))
                table.setItem(r, 3, center_item(format_qty(live)))
                spin = CleanDoubleSpinBox()
                spin.setDecimals(2)
                spin.setRange(0, float(live))
                spin.setValue(0)
                spin.valueChanged.connect(lambda _: recalc())
                table.setCellWidget(r, 4, spin)
                table.setItem(r, 5, center_item(money(0)))
            recalc()

        def load_by_number():
            try:
                invoice_date = normalize_date_input(day.text().strip())
            except Exception as e:
                QMessageBox.warning(dlg, "تاریخ", str(e)); return
            row = self.db.con.execute(
                "SELECT id FROM sales WHERE invoice_date=? AND invoice_no=?",
                (invoice_date, no.value()),
            ).fetchone()
            if not row:
                QMessageBox.warning(dlg, "فاکتور", "فاکتور پیدا نشد."); return
            fill(row[0])

        load_btn.clicked.connect(load_by_number)
        if sale_id:
            row = self.db.con.execute(
                "SELECT invoice_date, invoice_no FROM sales WHERE id=?", (int(sale_id),)
            ).fetchone()
            if row:
                day.setText(format_jalali_date(row["invoice_date"]))
                no.setValue(int(row["invoice_no"] or sale_id))
            fill(sale_id)

        if dlg.exec() != QDialog.Accepted:
            return
        if not state["sale_id"]:
            QMessageBox.information(self, "مرجوعی", "ابتدا فاکتور را بارگذاری کنید.")
            return
        returns = []
        for r, it in enumerate(state["items"]):
            spin = table.cellWidget(r, 4)
            q = to_decimal(spin.value()) if spin else Decimal("0")
            if q > 0:
                returns.append((int(it["id"]), str(q)))
        if not returns:
            QMessageBox.information(self, "مرجوعی", "تعداد مرجوعی را وارد کنید.")
            return
        try:
            amount, remaining = self.db.partial_return_sale(
                state["sale_id"], returns, reason.text().strip() or "مرجوعی جزئی"
            )
            self.refresh_all()
            if remaining <= 0:
                QMessageBox.information(self, "انجام شد", "همه اقلام مرجوع شد و فاکتور ابطال گردید.")
            else:
                QMessageBox.information(
                    self, "انجام شد",
                    f"مرجوعی جزئی ثبت شد.\nمبلغ مرجوعی: {money(amount)}\nکالا به انبار برگشت و حساب مشتری اصلاح شد."
                )
        except Exception as e:
            QMessageBox.critical(self, "خطا", str(e))

    def invoice_html(self, cart=None, invoice_no=None, invoice_date=None, customer_name=None, payment_name=None):
        """قالب چاپ A4 تمام‌عرض: فاکتور کل برگه را پر می‌کند."""
        rows = []
        total = Decimal("0")
        subtotal = Decimal("0")
        discount_total = Decimal("0")

        cart = self.cart if cart is None else cart
        invoice_no = invoice_no or self.current_invoice_no or self.db.next_invoice_no(date.today().isoformat())
        invoice_date = invoice_date or now()
        invoice_day = format_jalali_date(str(invoice_date).split(" ", 1)[0])

        customer_name = customer_name if customer_name is not None else (self.sale_customer.currentText() if hasattr(self, "sale_customer") else "مشتری آزاد / نقدی")
        payment_name = payment_name if payment_name is not None else (self.payment.currentText() if hasattr(self, "payment") else "نقدی")

        for i, x in enumerate(cart, 1):
            qty = to_decimal(x.get("qty", 1))
            qty_text = format_qty(qty)
            unit_price = money_decimal(x.get("price", 0))
            line_gross = unit_price * qty
            line_discount = max(Decimal("0"), to_decimal(x.get("discount", 0)))
            line_total = max(Decimal("0"), line_gross - line_discount)

            subtotal += line_gross
            discount_total += line_discount
            total += line_total

            rows.append(f"""
                <tr>
                    <td class="amount">{money_decimal(line_total):,.0f}</td>
                    <td class="discount">{money_decimal(line_discount):,.0f}</td>
                    <td class="price">{money_decimal(unit_price):,.0f}</td>
                    <td class="qty">{qty_text}</td>
                    <td class="name">{html_module.escape(str(x.get('name','')))}</td>
                    <td class="no">{i}</td>
                </tr>
            """)

        # حداقل ۱۲ ردیف تا جدول بلندتر شود و صفحه را پر کند
        target_rows = max(12, len(rows))
        while len(rows) < target_rows:
            rows.append("""
                <tr class="empty-row">
                    <td>&nbsp;</td><td>&nbsp;</td><td>&nbsp;</td>
                    <td>&nbsp;</td><td>&nbsp;</td><td>&nbsp;</td>
                </tr>
            """)

        return f"""
        <html dir="rtl">
        <head>
        <meta charset="utf-8">
        <style>
        @page {{ size: A4; margin: 0; }}
        * {{ box-sizing: border-box; margin: 0; padding: 0; }}

        body {{
            width: 210mm;
            height: 297mm;
            margin: 0;
            padding: 0;
            direction: rtl;
            font-family: Tahoma, "Segoe UI", Arial, sans-serif;
            color: #111;
            background: #fff;
            font-size: 11pt;
        }}

        .page {{
            width: 210mm;
            min-height: 297mm;
            padding: 6mm 8mm 6mm 8mm;
            margin: 0;
        }}

        .header {{
            width: 100%;
            text-align: center;
            margin: 0 0 3mm 0;
            padding: 0;
        }}

        .shop-name {{
            font-size: 32pt;
            font-weight: 900;
            line-height: 1.1;
            text-align: center;
            margin: 0;
            letter-spacing: -0.5px;
        }}

        .invoice-title {{
            font-size: 18pt;
            font-weight: bold;
            text-align: center;
            margin: 2mm 0 1mm 0;
        }}

        .contact {{
            font-size: 11pt;
            line-height: 1.35;
            text-align: center;
            margin-top: 1mm;
        }}

        .divider {{
            border: 0;
            border-top: 2px solid #111;
            margin: 3mm 0 4mm 0;
            width: 100%;
        }}

        .content {{
            width: 100%;
            direction: rtl;
        }}

        /* جدول اطلاعات — تمام عرض */
        .meta {{
            width: 100%;
            border-collapse: collapse;
            table-layout: fixed;
            margin: 0 0 4mm 0;
            direction: ltr;
        }}

        .meta td {{
            border: 1.5px solid #222;
            height: 11mm;
            padding: 2mm 3mm;
            font-size: 12pt;
            font-weight: 400;
            line-height: 1.2;
            vertical-align: middle;
            white-space: nowrap;
            overflow: hidden;
        }}

        .meta .left-cell, .meta .right-cell {{
            width: 50%;
            direction: rtl;
            text-align: right;
        }}

        .meta-label {{
            display: inline-block;
            font-weight: 900;
            direction: rtl;
            margin-left: 4mm;
        }}

        .meta-value {{
            display: inline-block;
            float: left;
            direction: ltr;
            text-align: left;
            font-weight: 600;
        }}

        .meta .customer-value {{
            direction: rtl;
            text-align: left;
            float: left;
        }}

        /* جدول اقلام — تمام عرض A4 */
        .items {{
            width: 100%;
            direction: ltr;
            unicode-bidi: embed;
            border-collapse: collapse;
            table-layout: fixed;
            margin: 0;
        }}

        .items th {{
            border: 1.5px solid #111;
            background: #e8e8e8;
            padding: 2.5mm 1.5mm;
            height: 13mm;
            font-size: 11pt;
            font-weight: 900;
            text-align: center;
            vertical-align: middle;
            line-height: 1.15;
        }}

        .items td {{
            border: 1.2px solid #333;
            padding: 2mm 1.5mm;
            height: 9.5mm;
            font-size: 11pt;
            text-align: center;
            vertical-align: middle;
            line-height: 1.2;
        }}

        /* نسبت ستون‌ها برای عرض کامل */
        .items .amount, .items th.amount {{ width: 17%; direction: ltr; text-align: center; }}
        .items .discount, .items th.discount {{ width: 14%; direction: ltr; text-align: center; }}
        .items .price, .items th.price {{ width: 17%; direction: ltr; text-align: center; }}
        .items .qty, .items th.qty {{ width: 9%; direction: ltr; text-align: center; }}
        .items .name, .items th.name {{
            width: 35%;
            text-align: right !important;
            unicode-bidi: embed;
            padding-right: 3mm !important;
            direction: rtl;
            word-wrap: break-word;
            font-weight: 600;
        }}
        .items .no, .items th.no {{ width: 8%; direction: ltr; text-align: center; }}

        .empty-row td {{ height: 9.5mm; }}

        /* جمع‌ها — تمام عرض */
        .totals {{
            width: 100%;
            border-collapse: collapse;
            table-layout: fixed;
            direction: ltr;
            margin: 5mm 0 0 0;
        }}

        .totals td {{
            border: 1.5px solid #222;
            height: 12mm;
            padding: 2mm 3mm;
            font-size: 13pt;
            font-weight: 700;
            vertical-align: middle;
            line-height: 1.15;
            white-space: nowrap;
        }}

        .totals .discount-number {{ width: 18%; direction: ltr; text-align: center; font-weight: 500; }}
        .totals .discount-caption {{ width: 20%; direction: rtl; text-align: right; font-weight: 900; }}
        .totals .subtotal-number {{ width: 22%; direction: ltr; text-align: center; font-weight: 500; }}
        .totals .subtotal-caption {{ width: 20%; direction: rtl; text-align: right; font-weight: 900; }}
        .totals .final-label {{ width: 30%; direction: rtl; text-align: right; font-size: 14pt; font-weight: 900; }}
        .totals .final-number {{ width: 30%; direction: ltr; text-align: center; font-size: 16pt; font-weight: 900; }}
        .totals .currency {{ width: 20%; direction: rtl; text-align: center; font-size: 14pt; font-weight: 900; }}

        .footer-box {{
            width: 100%;
            border: 0;
            margin-top: 10mm;
            padding: 0;
            text-align: center;
            font-size: 12pt;
            font-weight: 600;
        }}
        </style>
        </head>

        <body>
        <div class="page">
            <div class="header">
                <div class="shop-name">{html_module.escape(self.db.get_setting("shop_name", "حسابداری OMID PC"))}</div>
                <div class="invoice-title">فاکتور فروش</div>
                <div class="contact">
                    تلفن: {html_module.escape(self.db.get_setting("phone", ""))} &nbsp;&nbsp; | &nbsp;&nbsp;
                    اینستاگرام: {html_module.escape(self.db.get_setting("instagram", "@negin_abzar_isfahan"))}
                </div>
                <hr class="divider">
            </div>

            <div class="content">
                <table class="meta">
                    <tr>
                        <td class="left-cell"><span class="meta-label">شماره فاکتور</span><span class="meta-value">{invoice_no:04d}</span></td>
                        <td class="right-cell"><span class="meta-label">تاریخ</span><span class="meta-value">{html_module.escape(invoice_day)}</span></td>
                    </tr>
                    <tr>
                        <td class="left-cell"><span class="meta-value">{html_module.escape(payment_name)}</span></td>
                        <td class="right-cell"><span class="meta-label">وضعیت پرداخت</span></td>
                    </tr>
                    <tr>
                        <td class="left-cell"><span class="meta-value customer-value">{html_module.escape(customer_name)}</span></td>
                        <td class="right-cell"><span class="meta-label">مشتری</span></td>
                    </tr>
                </table>

                <table class="items">
                    <thead>
                        <tr>
                            <th class="amount">مبلغ نهایی<br>(تومان)</th>
                            <th class="discount">تخفیف<br>(تومان)</th>
                            <th class="price">قیمت واحد<br>(تومان)</th>
                            <th class="qty">تعداد</th>
                            <th class="name">شرح کالا</th>
                            <th class="no">ردیف</th>
                        </tr>
                    </thead>
                    <tbody>
                        {''.join(rows)}
                    </tbody>
                </table>

                <table class="totals">
                    <tr>
                        <td class="discount-number">{discount_total:,.0f}</td>
                        <td class="discount-caption">تخفیف کل</td>
                        <td class="subtotal-number">{subtotal:,.0f}</td>
                        <td class="subtotal-caption">جمع کل کالاها</td>
                    </tr>
                    <tr>
                        <td class="currency">تومان</td>
                        <td class="final-number">{total:,.0f}</td>
                        <td class="final-label" colspan="2">مبلغ قابل پرداخت</td>
                    </tr>
                </table>

                <div class="footer-box">از خرید شما سپاسگزاریم</div>
            </div>
        </div>
        </body>
        </html>
        """

    def configure_printer_page(self, printer):
        # حاشیه بسیار کم برای استفاده حداکثری از A4؛
        # چاپ بدون حاشیه واقعی فقط در صورت پشتیبانی خود چاپگر ممکن است.
        printer.setPageSize(QPageSize(QPageSize.PageSizeId.A4))
        printer.setPageOrientation(QPageLayout.Orientation.Portrait)
        printer.setPageMargins(QMarginsF(2, 2, 2, 2), QPageLayout.Unit.Millimeter)
        if hasattr(self, "copies_spin"):
            printer.setCopyCount(self.copies_spin.value())

    def prepare_invoice_document(self, printer):
        """ساخت فاکتور A4 با استفاده حداکثری از محدوده چاپ."""
        doc = QTextDocument()
        font = QFont("Tahoma")
        font.setPointSize(9)
        doc.setDefaultFont(font)
        doc.setDocumentMargin(0)
        doc.setDefaultStyleSheet("body { margin:0; padding:0; font-size:9pt; }")
        doc.setHtml(self.invoice_html())
        try:
            rect = printer.pageRect(QPrinter.Unit.Point)
            doc.setPageSize(rect.size())
        except Exception:
            pass
        return doc

    def print_invoice(self):
        if not self.cart:
            QMessageBox.information(self,"چاپ","ابتدا کالا به فاکتور اضافه کنید.")
            return
        # اگر گزینه PDF انتخاب شده باشد، بدون باز کردن پنجره انتخاب چاپگر،
        # فاکتور ساخته شده و بلافاصله روی مانیتور نمایش داده می‌شود.
        if hasattr(self, "printer_combo") and self.printer_combo.currentData() == "__PDF__":
            import tempfile
            path = os.path.join(tempfile.gettempdir(), "NeginAbzar_Invoice_%d.pdf" % int(time.time()*1000))
            printer = QPrinter(QPrinter.PrinterMode.HighResolution)
            printer.setOutputFormat(QPrinter.OutputFormat.PdfFormat)
            printer.setOutputFileName(path)
            self.configure_printer_page(printer)
            doc = self.prepare_invoice_document(printer)
            doc.print_(printer)
            if not open_path(path):
                QMessageBox.warning(self, "PDF", "PDF ساخته شد اما باز نشد.")
            return

        printer = QPrinter(QPrinter.PrinterMode.HighResolution)
        printer.setOutputFormat(QPrinter.OutputFormat.NativeFormat)
        if hasattr(self, "printer_combo") and self.printer_combo.currentData():
            printer.setPrinterName(self.printer_combo.currentData())
        self.configure_printer_page(printer)
        dialog = QPrintDialog(printer, self)
        dialog.setWindowTitle("انتخاب چاپگر و تنظیمات چاپ فاکتور")
        if dialog.exec() != QDialog.DialogCode.Accepted:
            return
        self.configure_printer_page(printer)
        doc = self.prepare_invoice_document(printer); doc.print_(printer)
        QMessageBox.information(self, "چاپ", "فاکتور با موفقیت برای چاپ ارسال شد.")

    def export_invoice_pdf(self):
        if not self.cart:
            QMessageBox.information(self,"PDF","ابتدا کالا به فاکتور اضافه کنید.")
            return
        path, _ = QFileDialog.getSaveFileName(self, "ذخیره فاکتور PDF", "فاکتور.pdf", "PDF (*.pdf)")
        if not path: return
        if not path.lower().endswith(".pdf"): path += ".pdf"
        printer = QPrinter(QPrinter.PrinterMode.HighResolution)
        printer.setOutputFormat(QPrinter.OutputFormat.PdfFormat)
        printer.setOutputFileName(path)
        self.configure_printer_page(printer)
        doc = self.prepare_invoice_document(printer); doc.print_(printer)
        QMessageBox.information(self, "PDF", f"فاکتور PDF ذخیره شد.\n{path}")

    # ---------- Products ----------
    def add_product_category(self):
        current = self.db.categories()
        name, ok = QInputDialog.getText(
            self,
            "دسته‌بندی جدید",
            "نام دسته‌بندی جدید را وارد کنید.\nمثلاً: لوازم جانبی",
            QLineEdit.Normal,
            ""
        )
        if not ok:
            return
        try:
            name = self.db.add_category(name)
            self.refresh_product_category_views()
            QMessageBox.information(self, "دسته‌بندی", f"دسته «{name}» با موفقیت اضافه شد.")
        except Exception as e:
            QMessageBox.warning(self, "خطا", str(e))

    def manage_product_categories(self):
        d = QDialog(self)
        d.setWindowTitle("مدیریت دسته‌بندی محصولات")
        d.setLayoutDirection(Qt.RightToLeft)
        d.resize(430, 480)
        root = QVBoxLayout(d)

        title = QLabel("دسته‌بندی‌های محصولات")
        title.setStyleSheet("font-size:22px;font-weight:900;")
        title.setAlignment(Qt.AlignCenter)
        root.addWidget(title)

        info = QLabel("از اینجا می‌توانید هر تعداد دسته‌بندی جدید اضافه کنید.")
        info.setStyleSheet(f"color:{MUTED};")
        info.setAlignment(Qt.AlignCenter)
        root.addWidget(info)

        lst = QListWidget()
        for cat in self.db.categories():
            lst.addItem(cat)
        root.addWidget(lst, 1)

        add_row = QHBoxLayout()
        name = QLineEdit()
        name.setPlaceholderText("مثلاً: ابزار برقی")
        add_btn = QPushButton("＋ افزودن دسته")
        add_row.addWidget(name, 1)
        add_row.addWidget(add_btn)
        root.addLayout(add_row)

        action_row = QHBoxLayout()
        delete_btn = QPushButton("🗑 حذف دسته انتخاب‌شده")
        delete_btn.setStyleSheet(f"background:{DANGER};color:#3a1515;")
        action_row.addWidget(delete_btn, 1)
        close_btn = QPushButton("بستن")
        action_row.addWidget(close_btn, 1)
        root.addLayout(action_row)

        def add_now():
            try:
                cat = self.db.add_category(name.text())
                existing = [lst.item(i).text() for i in range(lst.count())]
                if cat not in existing:
                    lst.addItem(cat)
                    lst.sortItems()
                name.clear()
                name.setFocus()
                self.refresh_product_category_views()
            except Exception as e:
                QMessageBox.warning(d, "خطا", str(e))

        def delete_now():
            item = lst.currentItem()
            if item is None:
                QMessageBox.information(d, "حذف دسته", "ابتدا یک دسته‌بندی را انتخاب کنید.")
                return

            cat = item.text().strip()
            if cat == "سایر":
                QMessageBox.warning(d, "حذف دسته", "دسته «سایر» قابل حذف نیست؛ چون دسته پیش‌فرض برنامه است.")
                return

            product_count = self.db.con.execute(
                "SELECT COUNT(*) FROM products WHERE category=?", (cat,)
            ).fetchone()[0] or 0

            if product_count:
                msg = (
                    f"دسته «{cat}» در حال حاضر {int(product_count)} محصول دارد.\n\n"
                    "با حذف دسته، این محصولات برای حفظ اطلاعات به دسته «سایر» منتقل می‌شوند.\n\n"
                    "آیا دسته حذف شود؟"
                )
            else:
                msg = f"دسته «{cat}» حذف شود؟"

            if QMessageBox.question(
                d, "تأیید حذف دسته", msg,
                QMessageBox.Yes | QMessageBox.No, QMessageBox.No
            ) != QMessageBox.Yes:
                return

            try:
                moved = self.db.delete_category(cat)
                if self.active_category == cat:
                    self.active_category = "همه دسته‌ها"
                for i in range(lst.count() - 1, -1, -1):
                    if lst.item(i).text().strip() == cat:
                        lst.takeItem(i)
                        break
                self.refresh_product_category_views()
                self.refresh_products_table()
                if moved:
                    QMessageBox.information(
                        d, "حذف دسته",
                        f"دسته «{cat}» حذف شد و {moved} محصول به «سایر» منتقل شد."
                    )
                else:
                    QMessageBox.information(d, "حذف دسته", f"دسته «{cat}» با موفقیت حذف شد.")
            except Exception as e:
                QMessageBox.warning(d, "خطا", str(e))

        add_btn.clicked.connect(add_now)
        delete_btn.clicked.connect(delete_now)
        name.returnPressed.connect(add_now)
        close_btn.clicked.connect(d.accept)
        d.exec()

    def refresh_product_category_views(self):
        # گزینه‌های دسته‌بندی در بخش فروش را از دیتابیس بازسازی می‌کنیم.
        if hasattr(self, "cats_layout"):
            while self.cats_layout.count():
                item = self.cats_layout.takeAt(0)
                if item.widget():
                    item.widget().deleteLater()
            for c in ["همه دسته‌ها"] + self.db.categories():
                b = QPushButton(c)
                b.setMinimumWidth(105)
                b.clicked.connect(lambda _, x=c: self.set_category(x))
                self.cats_layout.addWidget(b)
            self.cats_layout.addStretch()
            self.refresh_product_cards()

        if hasattr(self, "product_category_button_label"):
            self.product_category_button_label.setText(f"دسته‌ها: {len(self.db.categories())}")

    def make_products(self):
        page = QWidget()
        l = QVBoxLayout(page)
        l.setContentsMargins(0,0,0,0)
        top = QHBoxLayout()
        top.addLayout(self.title_layout("محصولات","نام، دسته، قیمت فروش و بارکد — موجودی در بخش انبار است"))
        top.addStretch()
        add = QPushButton("＋ افزودن محصول")
        add.clicked.connect(self.add_product)
        top.addWidget(add)
        category_btn = QPushButton("＋ افزودن دسته جدید")
        category_btn.clicked.connect(self.add_product_category)
        top.addWidget(category_btn)
        manage_cat = QPushButton("📂 مدیریت دسته‌ها")
        manage_cat.clicked.connect(self.manage_product_categories)
        top.addWidget(manage_cat)
        go_inv = QPushButton("🏭 رفتن به انبار")
        go_inv.clicked.connect(lambda: self.stack.setCurrentIndex(10))
        top.addWidget(go_inv)
        self.product_category_button_label = QLabel()
        self.product_category_button_label.setStyleSheet(f"color:{MUTED};font-weight:700;")
        top.addWidget(self.product_category_button_label)
        l.addLayout(top)

        bar = QHBoxLayout()
        self.product_search = QLineEdit()
        self.product_search.setPlaceholderText("جستجوی محصول...")
        self.product_search.textChanged.connect(self.refresh_products_table)
        bar.addWidget(self.product_search)
        edit = QPushButton("✏ ویرایش")
        edit.clicked.connect(self.edit_product)
        bar.addWidget(edit)
        delete = QPushButton("🗑 حذف")
        delete.clicked.connect(self.delete_product)
        bar.addWidget(delete)
        restore = QPushButton("♻️ بازیابی حذف‌شده")
        restore.clicked.connect(self.restore_product_dialog)
        bar.addWidget(restore)
        export = QPushButton("📤 خروجی CSV")
        export.clicked.connect(self.export_products)
        bar.addWidget(export)
        l.addLayout(bar)

        self.prod_table = QTableWidget(0,9)
        self.prod_table.setHorizontalHeaderLabels(
            ["کد","نام محصول","دسته","قیمت خرید","قیمت فروش","موجودی","حداقل","بارکد","وضعیت"])
        self.prod_table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        self.prod_table.setSelectionBehavior(QAbstractItemView.SelectRows)
        l.addWidget(self.prod_table)
        self.stack.addWidget(page)

    def refresh_products_table(self):
        rows = self.db.products(self.product_search.text().strip())
        self.prod_table.setRowCount(0)
        for r in rows:
            i = self.prod_table.rowCount()
            self.prod_table.insertRow(i)
            status = "⚠️ کمبود" if r["stock"] <= r["min_stock"] else "✓ مناسب"
            vals = [r["id"],r["name"],r["category"],money(r["buy_price"]),
                    money(r["sell_price"]),format_qty(r["stock"]),format_qty(r["min_stock"]),r["barcode"],status]
            for j,v in enumerate(vals):
                self.prod_table.setItem(i,j,center_item(v))

    def add_product(self):
        d = ProductDialog(self, categories=self.db.categories())
        if d.exec() and d.name.text().strip():
            try:
                self.db.add_product(d.data())
                self.refresh_product_category_views()
                self.refresh_all()
            except Exception as e:
                QMessageBox.warning(self, "خطا", str(e))

    def selected_product_id(self):
        r = self.prod_table.currentRow()
        if r < 0:
            return None
        return int(self.prod_table.item(r,0).text())

    def edit_product(self):
        pid = self.selected_product_id()
        if not pid:
            QMessageBox.information(self,"انتخاب","یک محصول را انتخاب کنید.")
            return
        p = self.db.product(pid)
        d = ProductDialog(self,p,self.db.categories())
        if d.exec():
            try:
                self.db.update_product(pid,d.data())
                self.refresh_product_category_views()
                self.refresh_all()
            except Exception as e:
                QMessageBox.warning(self, "خطا", str(e))

    def delete_product(self):
        pid = self.selected_product_id()
        if not pid:
            return
        if QMessageBox.question(self,"حذف","این محصول حذف شود؟") == QMessageBox.Yes:
            self.db.delete_product(pid)
            self.refresh_all()

    def restore_product_dialog(self):
        rows=self.db.list_inactive_products()
        if not rows:
            QMessageBox.information(self,"بازیابی","محصول حذف‌شده‌ای وجود ندارد."); return
        d=QDialog(self); d.setWindowTitle("بازیابی محصول"); d.setLayoutDirection(Qt.RightToLeft); f=QFormLayout(d); combo=QComboBox()
        for r in rows: combo.addItem(f"{r['name']} | کد {r['id']}",int(r['id']))
        f.addRow("محصول:",combo); b=QDialogButtonBox(QDialogButtonBox.Save|QDialogButtonBox.Cancel); b.accepted.connect(d.accept); b.rejected.connect(d.reject); f.addRow(b)
        if d.exec():
            try:
                self.db.restore_product(combo.currentData()); self.refresh_all(); QMessageBox.information(self,"انجام شد","محصول بازیابی شد.")
            except Exception as e:
                QMessageBox.warning(self,"بازیابی","بازیابی محصول انجام نشد:\n" + str(e))

    def adjust_selected_stock(self):
        pid=self.selected_product_id()
        if not pid: QMessageBox.information(self,"انتخاب","یک محصول را انتخاب کنید."); return
        p=self.db.product(pid)
        if not p: return
        dlg=QDialog(self); dlg.setWindowTitle(f"اصلاح موجودی - {p['name']}"); dlg.setLayoutDirection(Qt.RightToLeft); f=QFormLayout(dlg)
        info=QLabel(f"موجودی فعلی: {p['stock']:g} {p['unit']}")
        delta=CleanDoubleSpinBox(); delta.setRange(-999999,999999); delta.setDecimals(2); delta.setValue(0)
        reason=QLineEdit("اصلاح شمارش انبار")
        f.addRow("وضعیت فعلی:",info); f.addRow("تغییر موجودی (+/-):",delta); f.addRow("علت:",reason)
        b=QDialogButtonBox(QDialogButtonBox.Save|QDialogButtonBox.Cancel); b.accepted.connect(dlg.accept); b.rejected.connect(dlg.reject); f.addRow(b)
        if dlg.exec() and abs(delta.value())>0:
            try:
                self.db.adjust_stock(pid,delta.value(),reason.text().strip() or "اصلاح شمارش انبار")
                self.refresh_all(); QMessageBox.information(self,"انجام شد","موجودی اصلاح و در گردش انبار ثبت شد.")
            except Exception as e: QMessageBox.warning(self,"خطا",str(e))

    def export_products(self):
        path,_ = QFileDialog.getSaveFileName(self,"ذخیره محصولات","products.csv","CSV (*.csv)")
        if path:
            try:
                self.db.export_csv(
                    "SELECT id,name,category,buy_price,sell_price,stock,min_stock,barcode,unit FROM products WHERE COALESCE(active,1)=1",
                    path, ["کد","نام","دسته","خرید","فروش","موجودی","حداقل","بارکد","واحد"])
                QMessageBox.information(self,"انجام شد","فایل CSV ذخیره شد.")
            except Exception as e:
                QMessageBox.critical(self,"خطا",str(e))

    def show_inventory_movements(self):
        pid=None
        if hasattr(self, "inventory_table"):
            pid = self.selected_inventory_product_id()
        if not pid and hasattr(self,"prod_table"):
            pid=self.selected_product_id()
        d=QDialog(self); d.setWindowTitle("📜 گردش انبار"); d.setLayoutDirection(Qt.RightToLeft); d.resize(980,560)
        root=QVBoxLayout(d); top=QHBoxLayout(); top.addWidget(QLabel("محصول:")); combo=QComboBox(); combo.addItem("همه محصولات",None)
        for p in self.db.products(): combo.addItem(p["name"],int(p["id"]))
        if pid:
            idx=combo.findData(pid)
            if idx>=0: combo.setCurrentIndex(idx)
        top.addWidget(combo,1); root.addLayout(top)
        table=self.simple_table(["تاریخ","محصول","نوع گردش","تعداد","مرجع","توضیحات"])
        root.addWidget(table)
        def load():
            q="SELECT im.*,p.name FROM inventory_movements im JOIN products p ON p.id=im.product_id"; args=[]
            if combo.currentData(): q+=" WHERE im.product_id=?"; args.append(int(combo.currentData()))
            q+=" ORDER BY im.id DESC"
            rows=self.db.con.execute(q,args).fetchall(); table.setRowCount(0)
            for r in rows:
                i=table.rowCount(); table.insertRow(i)
                vals=[format_jalali_date(r["created_at"]),r["name"],r["movement_type"],format_qty(r["qty"]),r["reference_id"] or "-",r["description"] or ""]
                for j,v in enumerate(vals): table.setItem(i,j,center_item(v))
        combo.currentIndexChanged.connect(load); load(); d.exec()

    def make_inventory(self):
        page = QWidget()
        l = QVBoxLayout(page)
        l.setContentsMargins(0, 0, 0, 0)
        top = QHBoxLayout()
        top.addLayout(self.title_layout(
            "انبار",
            "موجودی، کمبود، گردش کالا و رزرو سفارش اینستاگرام — جدا از صفحه سفارش‌ها"
        ))
        top.addStretch()
        l.addLayout(top)

        kpi = QHBoxLayout()
        self.inv_value_label = QLabel("ارزش موجودی: 0 تومان")
        self.inv_low_label = QLabel("کمبود: 0")
        self.inv_reserved_label = QLabel("رزرو اینستاگرام: 0")
        for w in (self.inv_value_label, self.inv_low_label, self.inv_reserved_label):
            w.setStyleSheet("font-size:16px;font-weight:800;")
            kpi.addWidget(w)
        kpi.addStretch()
        l.addLayout(kpi)

        bar = QHBoxLayout()
        self.inventory_search = QLineEdit()
        self.inventory_search.setPlaceholderText("جستجوی کالا در انبار...")
        self.inventory_search.textChanged.connect(self.refresh_inventory_table)
        bar.addWidget(self.inventory_search)
        only_low = QPushButton("⚠️ فقط کمبود")
        only_low.setCheckable(True)
        only_low.toggled.connect(lambda _: self.refresh_inventory_table())
        self.inventory_only_low = only_low
        bar.addWidget(only_low)
        adjust = QPushButton("⚖️ اصلاح موجودی")
        adjust.clicked.connect(self.adjust_selected_inventory)
        bar.addWidget(adjust)
        movement = QPushButton("📜 گردش کامل")
        movement.clicked.connect(self.show_inventory_movements)
        bar.addWidget(movement)
        export = QPushButton("📤 خروجی انبار")
        export.clicked.connect(self.export_inventory)
        bar.addWidget(export)
        l.addLayout(bar)

        self.inventory_table = QTableWidget(0, 8)
        self.inventory_table.setHorizontalHeaderLabels(
            ["کد", "نام محصول", "موجودی", "حداقل", "رزرو اینستا", "قابل فروش", "ارزش", "وضعیت"]
        )
        self.inventory_table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        self.inventory_table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.inventory_table.itemSelectionChanged.connect(self.refresh_inventory_movements_panel)
        l.addWidget(self.inventory_table, 3)

        mov_card = Card()
        ml = QVBoxLayout(mov_card)
        mh = QLabel("گردش انبار کالاى انتخاب‌شده")
        mh.setStyleSheet("font-size:18px;font-weight:900;")
        ml.addWidget(mh)
        self.inventory_move_table = self.simple_table(
            ["تاریخ", "نوع گردش", "تعداد", "مرجع", "توضیحات"]
        )
        ml.addWidget(self.inventory_move_table)
        l.addWidget(mov_card, 2)
        self.stack.addWidget(page)

    def _instagram_reserved_map(self):
        rows = self.db.con.execute(
            """SELECT i.product_id, SUM(i.qty) qty
               FROM instagram_order_items i
               JOIN instagram_orders o ON o.id=i.order_id
               WHERE COALESCE(o.stock_applied,0)=1
                 AND COALESCE(o.status,'')<>'لغو شد'
                 AND o.sale_id IS NULL
               GROUP BY i.product_id"""
        ).fetchall()
        return {int(r["product_id"]): to_decimal(r["qty"] or 0) for r in rows}

    def refresh_inventory_table(self):
        if not hasattr(self, "inventory_table"):
            return
        q = (self.inventory_search.text().strip() if hasattr(self, "inventory_search") else "")
        rows = self.db.products(q)
        reserved_map = self._instagram_reserved_map()
        only_low = bool(getattr(self, "inventory_only_low", None) and self.inventory_only_low.isChecked())
        total_value = Decimal("0")
        low_count = 0
        reserved_count = Decimal("0")
        self.inventory_table.setRowCount(0)
        for r in rows:
            stock = to_decimal(r["stock"] or 0)
            min_stock = to_decimal(r["min_stock"] or 0)
            reserved = reserved_map.get(int(r["id"]), Decimal("0"))
            available = max(Decimal("0"), stock - reserved)
            value = money_decimal(stock * to_decimal(r["buy_price"] or 0))
            total_value += value
            reserved_count += reserved
            if stock <= min_stock:
                low_count += 1
                status = "⚠️ کمبود"
            else:
                status = "✓ مناسب"
            if only_low and stock > min_stock:
                continue
            i = self.inventory_table.rowCount()
            self.inventory_table.insertRow(i)
            vals = [
                r["id"], r["name"], format_qty(stock), format_qty(min_stock),
                format_qty(reserved), format_qty(available), money(value), status
            ]
            for j, v in enumerate(vals):
                self.inventory_table.setItem(i, j, center_item(v))
        if hasattr(self, "inv_value_label"):
            self.inv_value_label.setText(f"ارزش موجودی: {money(total_value)}")
            self.inv_low_label.setText(f"کمبود: {low_count}")
            self.inv_reserved_label.setText(f"رزرو اینستاگرام: {format_qty(reserved_count)}")
        self.refresh_inventory_movements_panel()

    def refresh_inventory_movements_panel(self):
        if not hasattr(self, "inventory_move_table"):
            return
        self.inventory_move_table.setRowCount(0)
        pid = self.selected_inventory_product_id()
        if not pid:
            return
        rows = self.db.con.execute(
            """SELECT * FROM inventory_movements WHERE product_id=? ORDER BY id DESC LIMIT 80""",
            (int(pid),)
        ).fetchall()
        for r in rows:
            i = self.inventory_move_table.rowCount()
            self.inventory_move_table.insertRow(i)
            vals = [
                format_jalali_date(r["created_at"]), r["movement_type"],
                format_qty(r["qty"]), r["reference_id"] or "-", r["description"] or ""
            ]
            for j, v in enumerate(vals):
                self.inventory_move_table.setItem(i, j, center_item(v))

    def selected_inventory_product_id(self):
        if not hasattr(self, "inventory_table"):
            return None
        r = self.inventory_table.currentRow()
        if r < 0 or not self.inventory_table.item(r, 0):
            return None
        return int(self.inventory_table.item(r, 0).text())

    def adjust_selected_inventory(self):
        pid = self.selected_inventory_product_id() or self.selected_product_id()
        if not pid:
            QMessageBox.information(self, "انبار", "یک کالا را از جدول انبار انتخاب کنید.")
            return
        # reuse the same dialog by temporarily selecting in logic
        p = self.db.product(pid)
        if not p:
            return
        dlg = QDialog(self)
        dlg.setWindowTitle(f"اصلاح موجودی - {p['name']}")
        dlg.setLayoutDirection(Qt.RightToLeft)
        f = QFormLayout(dlg)
        info = QLabel(f"موجودی فعلی: {format_qty(p['stock'])} {p['unit']}")
        delta = CleanDoubleSpinBox()
        delta.setRange(-999999, 999999)
        delta.setDecimals(2)
        delta.setValue(0)
        reason = QLineEdit("اصلاح شمارش انبار")
        f.addRow("وضعیت فعلی:", info)
        f.addRow("تغییر موجودی (+/-):", delta)
        f.addRow("علت:", reason)
        b = QDialogButtonBox(QDialogButtonBox.Save | QDialogButtonBox.Cancel)
        b.accepted.connect(dlg.accept)
        b.rejected.connect(dlg.reject)
        f.addRow(b)
        if dlg.exec() and abs(delta.value()) > 0:
            try:
                self.db.adjust_stock(pid, delta.value(), reason.text().strip() or "اصلاح شمارش انبار")
                self.refresh_all()
                QMessageBox.information(self, "انجام شد", "موجودی اصلاح و در گردش انبار ثبت شد.")
            except Exception as e:
                QMessageBox.warning(self, "خطا", str(e))

    def export_inventory(self):
        path, _ = QFileDialog.getSaveFileName(self, "ذخیره گزارش انبار", "inventory.csv", "CSV (*.csv)")
        if not path:
            return
        try:
            self.db.export_csv(
                "SELECT id,name,category,stock,min_stock,buy_price,sell_price,unit FROM products WHERE COALESCE(active,1)=1",
                path,
                ["کد", "نام", "دسته", "موجودی", "حداقل", "بهای خرید", "قیمت فروش", "واحد"],
            )
            QMessageBox.information(self, "انجام شد", "گزارش انبار ذخیره شد.")
        except Exception as e:
            QMessageBox.critical(self, "خطا", str(e))

    # ---------- generic pages ----------
    def make_customers(self):
        page = QWidget(); l = QVBoxLayout(page); l.setContentsMargins(0,0,0,0)
        top = QHBoxLayout()
        top.addLayout(self.title_layout("مشتریان","دفتر مشتریان و مانده حساب"))
        top.addStretch()
        add = QPushButton("＋ مشتری جدید")
        add.clicked.connect(self.add_customer)
        top.addWidget(add)
        l.addLayout(top)
        search_row = QHBoxLayout()
        self.customer_search = QLineEdit()
        self.customer_search.setPlaceholderText("جستجو با نام، تلفن یا آدرس...")
        self.customer_search.textChanged.connect(self.refresh_customers_table)
        search_row.addWidget(self.customer_search)
        l.addLayout(search_row)
        self.customer_table = QTableWidget(0,5)
        self.customer_table.setHorizontalHeaderLabels(["کد","نام","تلفن","مانده حساب","آدرس"])
        self.customer_table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        self.customer_table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.customer_table.cellDoubleClicked.connect(self.open_customer_ledger_from_table)
        l.addWidget(self.customer_table)
        self.customer_edit_btn = QPushButton("✏️ ویرایش مشتری انتخاب‌شده")
        self.customer_edit_btn.clicked.connect(self.edit_selected_customer)
        l.addWidget(self.customer_edit_btn)
        self.stack.addWidget(page)

    def refresh_customers_table(self):
        q = (self.customer_search.text().strip() if hasattr(self, "customer_search") else "")
        like = f"%{q}%"
        if q:
            rows = self.db.con.execute(
                "SELECT * FROM customers WHERE name LIKE ? OR phone LIKE ? OR address LIKE ? ORDER BY id DESC",
                (like, like, like)
            ).fetchall()
        else:
            rows = self.db.con.execute("SELECT * FROM customers ORDER BY id DESC").fetchall()
        self.customer_table.setRowCount(0)
        for r in rows:
            i = self.customer_table.rowCount()
            self.customer_table.insertRow(i)
            for j, v in enumerate([r["id"], r["name"], r["phone"], self.db.format_customer_balance(r["balance"]), r["address"]]):
                self.customer_table.setItem(i, j, center_item(v))

    def open_customer_ledger_from_table(self,row,column=0):
        item=self.customer_table.item(row,0)
        if not item: return
        cid=int(item.text()); self.stack.setCurrentIndex(9)
        idx=self.ledger_customer.findData(cid) if hasattr(self,"ledger_customer") else -1
        if idx>=0: self.ledger_customer.setCurrentIndex(idx)

    def add_customer(self):
        d = QDialog(self); d.setWindowTitle("ثبت مشتری"); d.setLayoutDirection(Qt.RightToLeft)
        f = QFormLayout(d)
        name=QLineEdit(); phone=QLineEdit(); address=QLineEdit(); balance=MoneySpinBox(); balance.setDecimals(0); balance.setMaximum(999999999999)
        balance.setMaximum(999999999999); balance.setDecimals(0)
        for x in [name,phone,address,balance]: x.setMinimumHeight(38)
        f.addRow("نام:",name); f.addRow("تلفن:",phone); f.addRow("آدرس:",address); f.addRow("مانده:",balance)
        b=QDialogButtonBox(QDialogButtonBox.Save|QDialogButtonBox.Cancel)
        b.accepted.connect(d.accept); b.rejected.connect(d.reject); f.addRow(b)
        if d.exec() and name.text().strip():
            try:
                cur=self.db.con.cursor()
                cur.execute("BEGIN")
                cur.execute("INSERT INTO customers(name,phone,address,balance) VALUES(?,?,?,0)",
                            (name.text().strip(),phone.text().strip(),address.text().strip()))
                cid=cur.lastrowid
                opening=round(balance.value())
                if opening>0:
                    cur.execute("INSERT INTO account_transactions(customer_id,transaction_type,amount,description,sale_id,created_at) VALUES(?,?,?,?,?,?)",
                                (cid,"بدهکار",opening,"مانده افتتاحیه مشتری",None,now()))
                self.db.con.commit()
                self.db.recompute_customer_balance(cid)
                self.refresh_all()
            except Exception as e:
                self.db.con.rollback(); QMessageBox.critical(self,"خطا",str(e))

    def make_purchases(self):
        page=QWidget(); l=QVBoxLayout(page); l.setContentsMargins(0,0,0,0)
        top=QHBoxLayout(); top.addLayout(self.title_layout("خرید و تأمین","ثبت خرید واقعی، اقلام خرید و افزایش خودکار موجودی")); top.addStretch()
        b=QPushButton("＋ ثبت خرید"); b.clicked.connect(self.add_purchase); top.addWidget(b); b=QPushButton("✏️ ویرایش خرید"); b.clicked.connect(self.edit_purchase); top.addWidget(b); b=QPushButton("↩️ ابطال خرید"); b.clicked.connect(self.void_purchase_dialog); top.addWidget(b); l.addLayout(top)
        self.purchase_table=self.simple_table(["شماره","تامین‌کننده","مبلغ","اقلام","توضیحات","تاریخ","وضعیت"])
        l.addWidget(self.purchase_table); self.stack.addWidget(page)

    def add_purchase(self):
        d=QDialog(self); d.setWindowTitle("ثبت خرید کالا"); d.setLayoutDirection(Qt.RightToLeft); d.resize(760,520)
        root=QVBoxLayout(d); f=QFormLayout(); supplier=QLineEdit(); notes=QTextEdit(); f.addRow("تامین‌کننده:",supplier); f.addRow("توضیحات:",notes); root.addLayout(f)
        table=QTableWidget(0,4); table.setHorizontalHeaderLabels(["کالا","تعداد","قیمت خرید واحد","جمع"]); table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch); root.addWidget(table)
        addrow=QPushButton("＋ افزودن قلم خرید"); root.addWidget(addrow)
        total_lbl=QLabel("جمع خرید: 0 تومان"); total_lbl.setStyleSheet("font-size:20px;font-weight:900;"); root.addWidget(total_lbl)
        def recalc():
            total=0
            for r in range(table.rowCount()):
                q=table.cellWidget(r,1); pr=table.cellWidget(r,2)
                if q and pr:
                    v=q.value()*pr.value(); total+=v; table.setItem(r,3,center_item(money(v)))
            total_lbl.setText(f"جمع خرید: {money(total)}")
        def add_row():
            r=table.rowCount(); table.insertRow(r)
            combo=QComboBox(); combo.addItem("انتخاب کالا",None)
            for p in self.db.products(): combo.addItem(f"{p['name']} | موجودی {format_qty(p['stock'])}",int(p['id']))
            q=CleanDoubleSpinBox(); q.setRange(0.01,999999); q.setDecimals(2); q.setValue(1)
            pr=MoneySpinBox(); pr.setValue(0)
            table.setCellWidget(r,0,combo); table.setCellWidget(r,1,q); table.setCellWidget(r,2,pr); table.setItem(r,3,center_item("0 تومان"))
            def changed(i):
                pid=combo.currentData(); row=self.db.product(pid) if pid else None
                if row: pr.setValue(float(row['buy_price']))
                recalc()
            combo.currentIndexChanged.connect(changed); q.valueChanged.connect(lambda _: recalc()); pr.valueChanged.connect(lambda _: recalc())
        addrow.clicked.connect(add_row); add_row()
        buttons=QDialogButtonBox(QDialogButtonBox.Save|QDialogButtonBox.Cancel); buttons.accepted.connect(d.accept); buttons.rejected.connect(d.reject); root.addWidget(buttons)
        if d.exec():
            items=[]
            for r in range(table.rowCount()):
                combo=table.cellWidget(r,0); q=table.cellWidget(r,1); pr=table.cellWidget(r,2); pid=combo.currentData() if combo else None
                if pid and to_decimal(q.value())>0 and pr.value()>=0:
                    items.append((int(pid), str(to_decimal(q.value())), int(money_decimal(pr.value()))))
            if not items:
                QMessageBox.warning(self,"خرید","حداقل یک قلم خرید معتبر وارد کنید."); return
            try:
                self.db.add_purchase(supplier.text(),items,notes.toPlainText())
                self.refresh_all(); QMessageBox.information(self,"ثبت شد","خرید ثبت شد و موجودی کالاها افزایش یافت.")
            except Exception as e: QMessageBox.critical(self,"خطا",str(e))

    def selected_purchase_id(self):
        r=self.purchase_table.currentRow(); return int(self.purchase_table.item(r,0).text()) if r>=0 else None

    def void_purchase_dialog(self):
        pid=self.selected_purchase_id()
        if not pid: QMessageBox.information(self,"خرید","یک خرید را انتخاب کنید."); return
        if QMessageBox.question(self,"ابطال خرید","خرید انتخاب‌شده ابطال و موجودی مربوط به آن کسر شود؟")!=QMessageBox.Yes: return
        try: self.db.void_purchase(pid); self.refresh_all(); QMessageBox.information(self,"انجام شد","خرید ابطال شد.")
        except Exception as e: QMessageBox.warning(self,"خطا",str(e))

    def edit_purchase(self):
        pid=self.selected_purchase_id()
        if not pid: QMessageBox.information(self,"خرید","یک خرید را انتخاب کنید."); return
        old=self.db.con.execute("SELECT * FROM purchases WHERE id=?",(pid,)).fetchone()
        if not old or (old["status"] or "فعال")!="فعال": QMessageBox.warning(self,"خرید","فقط خریدهای فعال قابل ویرایش هستند."); return
        d=QDialog(self); d.setWindowTitle(f"ویرایش خرید {pid}"); d.setLayoutDirection(Qt.RightToLeft); d.resize(760,520); root=QVBoxLayout(d); f=QFormLayout(); supplier=QLineEdit(old["supplier"] or ""); notes=QTextEdit(old["notes"] or ""); f.addRow("تامین‌کننده:",supplier); f.addRow("توضیحات:",notes); root.addLayout(f)
        table=QTableWidget(0,4); table.setHorizontalHeaderLabels(["کالا","تعداد","قیمت خرید واحد","جمع"]); table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch); root.addWidget(table); addrow=QPushButton("＋ افزودن قلم"); root.addWidget(addrow); total_lbl=QLabel("جمع خرید: 0 تومان"); root.addWidget(total_lbl)
        def recalc():
            total=0
            for r in range(table.rowCount()):
                q=table.cellWidget(r,1); pr=table.cellWidget(r,2)
                if q and pr: total+=q.value()*pr.value(); table.setItem(r,3,center_item(money(q.value()*pr.value())))
            total_lbl.setText(f"جمع خرید: {money(total)}")
        def add_row(pid0=None,qty0=1,price0=0):
            r=table.rowCount(); table.insertRow(r); combo=QComboBox(); combo.addItem("انتخاب کالا",None)
            for p in self.db.products(): combo.addItem(f"{p['name']} | موجودی {format_qty(p['stock'])}",int(p['id']))
            if pid0: idx=combo.findData(pid0); combo.setCurrentIndex(idx if idx>=0 else 0)
            q=CleanDoubleSpinBox(); q.setRange(0.01,999999); q.setDecimals(2); q.setValue(qty0); pr=MoneySpinBox(); pr.setValue(price0); table.setCellWidget(r,0,combo); table.setCellWidget(r,1,q); table.setCellWidget(r,2,pr); table.setItem(r,3,center_item("0 تومان")); combo.currentIndexChanged.connect(lambda i: recalc()); q.valueChanged.connect(lambda _:recalc()); pr.valueChanged.connect(lambda _:recalc()); recalc()
        live_rows = self.db.con.execute("""
            SELECT product_id,
                   SUM(qty - COALESCE(cancelled_qty,0)) AS live_qty
            FROM purchase_items
            WHERE purchase_id=?
            GROUP BY product_id
            HAVING SUM(qty - COALESCE(cancelled_qty,0)) > 0.000001
            ORDER BY MIN(id)
        """, (pid,)).fetchall()
        for it in live_rows:
            price_row = self.db.con.execute("""
                SELECT price FROM purchase_items
                WHERE purchase_id=? AND product_id=?
                  AND (qty - COALESCE(cancelled_qty,0)) > 0.000001
                ORDER BY id DESC LIMIT 1
            """, (pid, int(it["product_id"]))).fetchone()
            add_row(
                int(it["product_id"]),
                float(it["live_qty"]),
                float(price_row["price"] if price_row else 0),
            )
        if table.rowCount()==0: add_row()
        addrow.clicked.connect(lambda:add_row())
        buttons=QDialogButtonBox(QDialogButtonBox.Save|QDialogButtonBox.Cancel); buttons.accepted.connect(d.accept); buttons.rejected.connect(d.reject); root.addWidget(buttons)
        if d.exec():
            items=[]
            for r in range(table.rowCount()):
                combo=table.cellWidget(r,0); q=table.cellWidget(r,1); pr=table.cellWidget(r,2); p=combo.currentData() if combo else None
                if p and to_decimal(q.value())>0:
                    items.append((int(p), str(to_decimal(q.value())), int(money_decimal(pr.value()))))
            try: self.db.update_purchase(pid,supplier.text(),items,notes.toPlainText()); self.refresh_all(); QMessageBox.information(self,"انجام شد","خرید و موجودی اصلاح شد.")
            except Exception as e: QMessageBox.critical(self,"خطا",str(e))

    def make_instagram(self):
        page=QWidget(); l=QVBoxLayout(page); l.setContentsMargins(0,0,0,0)
        top=QHBoxLayout()
        top.addLayout(self.title_layout(
            "سفارش‌های اینستاگرام",
            "بخش جدا برای دایرکت اینستا — کالا و مشتری را انتخاب کنید؛ موجودی در بخش انبار دیده می‌شود"
        ))
        top.addStretch()
        for text, slot in (
            ("＋ سفارش جدید", self.add_instagram),
            ("✏️ ویرایش", self.edit_instagram),
            ("🧾 صدور فاکتور", self.convert_instagram_invoice),
            ("🖨 چاپ فاکتور", self.print_instagram_invoice),
            ("↩️ لغو سفارش", self.cancel_instagram),
            ("🗑 حذف", self.delete_instagram),
        ):
            b=QPushButton(text); b.clicked.connect(slot); top.addWidget(b)
        l.addLayout(top)
        search_row=QHBoxLayout()
        self.instagram_search=QLineEdit()
        self.instagram_search.setPlaceholderText("جستجو با مشتری، تلفن، وضعیت یا شماره فاکتور...")
        self.instagram_search.textChanged.connect(self.refresh_instagram_table)
        search_row.addWidget(self.instagram_search)
        hint=QLabel("آماده‌سازی / ارسال / تحویل = کسر از انبار | صدور فاکتور = فروش، سود و حساب دفتری")
        hint.setStyleSheet(f"color:{MUTED};")
        search_row.addWidget(hint)
        l.addLayout(search_row)
        self.instagram_table=self.simple_table(
            ["شماره","مشتری","تلفن","مبلغ","اقلام","وضعیت","فاکتور","پرداخت","آدرس","تاریخ"]
        )
        self.instagram_table.cellDoubleClicked.connect(lambda *_: self.edit_instagram())
        l.addWidget(self.instagram_table); self.stack.addWidget(page)

    def refresh_instagram_table(self):
        if not hasattr(self, "instagram_table"):
            return
        q = (self.instagram_search.text().strip() if hasattr(self, "instagram_search") else "")
        like = f"%{q}%"
        if q:
            rows = self.db.con.execute(
                """SELECT o.*,
                          (SELECT COUNT(*) FROM instagram_order_items i WHERE i.order_id=o.id) item_count,
                          s.invoice_no, s.status sale_status
                   FROM instagram_orders o
                   LEFT JOIN sales s ON s.id=o.sale_id
                   WHERE o.customer LIKE ? OR o.phone LIKE ? OR o.status LIKE ?
                      OR o.address LIKE ? OR CAST(o.id AS TEXT) LIKE ?
                      OR CAST(COALESCE(s.invoice_no,'') AS TEXT) LIKE ?
                   ORDER BY o.id DESC""",
                (like, like, like, like, like, like),
            ).fetchall()
        else:
            rows = self.db.con.execute(
                """SELECT o.*,
                          (SELECT COUNT(*) FROM instagram_order_items i WHERE i.order_id=o.id) item_count,
                          s.invoice_no, s.status sale_status
                   FROM instagram_orders o
                   LEFT JOIN sales s ON s.id=o.sale_id
                   ORDER BY o.id DESC"""
            ).fetchall()
        self.instagram_table.setRowCount(0)
        for r in rows:
            i = self.instagram_table.rowCount()
            self.instagram_table.insertRow(i)
            inv = "-"
            if r["invoice_no"] and (r["sale_status"] or "فعال") == "فعال":
                inv = f"{int(r['invoice_no']):04d}"
            vals = [
                r["id"], r["customer"], r["phone"], money(r["total"]),
                r["item_count"] or 0, r["status"] or "جدید", inv,
                r["payment"] or "-", r["address"] or "", format_jalali_date(r["created_at"]),
            ]
            for j, v in enumerate(vals):
                self.instagram_table.setItem(i, j, center_item(v))

    def selected_instagram_id(self):
        r=self.instagram_table.currentRow(); return int(self.instagram_table.item(r,0).text()) if r>=0 else None

    def _instagram_order_dialog(self, order=None):
        d=QDialog(self)
        d.setWindowTitle("ویرایش سفارش اینستاگرام" if order else "سفارش جدید اینستاگرام")
        d.setLayoutDirection(Qt.RightToLeft)
        d.resize(820, 620)
        root=QVBoxLayout(d)
        f=QFormLayout()
        cust=QComboBox(); cust.addItem("مشتری جدید / وارد کردن دستی", None)
        for r in self.db.con.execute("SELECT id,name,phone FROM customers ORDER BY name COLLATE NOCASE").fetchall():
            cust.addItem(f"{r['name']} | {r['phone'] or '-'}", int(r["id"]))
        self._bind_searchable_combo(cust)
        name=QLineEdit(order["customer"] if order else "")
        phone=QLineEdit(order["phone"] if order else "")
        address=QLineEdit(order["address"] if order else "")
        status=QComboBox(); status.addItems(["جدید","در حال آماده‌سازی","ارسال شد","تحویل شد","لغو شد"])
        if order:
            status.setCurrentText(order["status"] or "جدید")
        payment=QComboBox(); payment.addItems(["نقدی","کارتخوان","واریز بانکی","نسیه","چک"])
        if order and order["payment"]:
            idx=payment.findText(order["payment"])
            if idx>=0: payment.setCurrentIndex(idx)
        notes=QTextEdit(order["notes"] if order else "")
        notes.setMaximumHeight(80)
        if order and order["customer_id"]:
            idx=cust.findData(int(order["customer_id"]))
            if idx>=0: cust.setCurrentIndex(idx)
        def fill_from_customer(_=None):
            cid=self._resolve_combo_customer(cust)
            if not cid:
                return
            row=self.db.con.execute("SELECT name,phone,address FROM customers WHERE id=?",(cid,)).fetchone()
            if not row:
                return
            if not name.text().strip():
                name.setText(row["name"] or "")
            if not phone.text().strip():
                phone.setText(row["phone"] or "")
            if not address.text().strip():
                address.setText(row["address"] or "")
        cust.currentIndexChanged.connect(fill_from_customer)
        for label,w in [
            ("انتخاب مشتری دفتر:",cust),("نام مشتری:",name),("تلفن:",phone),
            ("آدرس ارسال:",address),("وضعیت:",status),("روش پرداخت پیشنهادی:",payment),
            ("توضیحات:",notes)
        ]:
            f.addRow(label,w)
        root.addLayout(f)

        table=QTableWidget(0,5)
        table.setHorizontalHeaderLabels(["کالا","تعداد","قیمت واحد","تخفیف ردیف","جمع"])
        table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        root.addWidget(table)
        addrow=QPushButton("＋ افزودن کالا از انبار")
        root.addWidget(addrow)
        total_lbl=QLabel("جمع سفارش: 0 تومان")
        total_lbl.setStyleSheet("font-size:20px;font-weight:900;")
        root.addWidget(total_lbl)
        info=QLabel("اگر وضعیت «آماده‌سازی / ارسال / تحویل» باشد، موجودی همان لحظه از انبار کم می‌شود.")
        info.setStyleSheet(f"color:{MUTED};")
        info.setWordWrap(True)
        root.addWidget(info)

        def recalc():
            total=Decimal("0")
            for r in range(table.rowCount()):
                q=table.cellWidget(r,1); pr=table.cellWidget(r,2); disc=table.cellWidget(r,3)
                if q and pr and disc:
                    gross=to_decimal(pr.value())*to_decimal(q.value())
                    line=max(Decimal("0"), gross-to_decimal(disc.value()))
                    total += money_decimal(line)
                    table.setItem(r,4,center_item(money(line)))
            total_lbl.setText(f"جمع سفارش: {money(total)}")

        def add_row(pid0=None, qty0=1, price0=0, discount0=0):
            r=table.rowCount(); table.insertRow(r)
            combo=QComboBox(); combo.addItem("انتخاب کالا", None)
            for p in self.db.products():
                combo.addItem(f"{p['name']} | موجودی {format_qty(p['stock'])} | {money(p['sell_price'])}", int(p["id"]))
            if pid0:
                idx=combo.findData(int(pid0))
                combo.setCurrentIndex(idx if idx>=0 else 0)
            q=CleanDoubleSpinBox(); q.setRange(0.01,999999); q.setDecimals(2); q.setValue(float(qty0) or 1)
            pr=MoneySpinBox(); pr.setValue(float(price0) or 0)
            disc=MoneySpinBox(); disc.setValue(float(discount0) or 0)
            table.setCellWidget(r,0,combo); table.setCellWidget(r,1,q)
            table.setCellWidget(r,2,pr); table.setCellWidget(r,3,disc)
            table.setItem(r,4,center_item("0 تومان"))
            def changed(_=None):
                pid=combo.currentData(); rowp=self.db.product(pid) if pid else None
                if rowp and pr.value()<=0:
                    pr.setValue(float(rowp["sell_price"] or 0))
                recalc()
            combo.currentIndexChanged.connect(changed)
            q.valueChanged.connect(lambda _: recalc())
            pr.valueChanged.connect(lambda _: recalc())
            disc.valueChanged.connect(lambda _: recalc())
            changed()

        if order:
            items=self.db.instagram_order_items(order["id"])
            if items:
                for it in items:
                    add_row(it["product_id"], it["qty"] or 1, it["price"] or 0, it["discount"] or 0)
            else:
                add_row()
        else:
            add_row()
        addrow.clicked.connect(lambda: add_row())
        buttons=QDialogButtonBox(QDialogButtonBox.Save|QDialogButtonBox.Cancel)
        buttons.accepted.connect(d.accept); buttons.rejected.connect(d.reject)
        root.addWidget(buttons)

        if d.exec()!=QDialog.Accepted:
            return None
        items=[]
        for r in range(table.rowCount()):
            combo=table.cellWidget(r,0); q=table.cellWidget(r,1)
            pr=table.cellWidget(r,2); disc=table.cellWidget(r,3)
            pid=combo.currentData() if combo else None
            if pid and to_decimal(q.value())>0:
                items.append({
                    "id": int(pid),
                    "name": combo.currentText().split(" | ")[0],
                    "qty": str(to_decimal(q.value())),
                    "price": int(money_decimal(pr.value())),
                    "discount": int(money_decimal(disc.value())),
                })
        customer_id=self._resolve_combo_customer(cust)
        return {
            "customer": name.text().strip() or (cust.currentText().split(" | ")[0] if customer_id else ""),
            "phone": phone.text().strip(),
            "address": address.text().strip(),
            "notes": notes.toPlainText().strip(),
            "status": status.currentText(),
            "payment": payment.currentText(),
            "customer_id": customer_id,
            "items": items,
        }

    def add_instagram(self):
        data=self._instagram_order_dialog()
        if not data:
            return
        try:
            oid, _total = self.db.save_instagram_order(data, data["items"])
            self.refresh_all()
            QMessageBox.information(self,"ثبت شد","سفارش اینستاگرام ثبت شد و به دفتر مشتریان وصل گردید.")
            self._maybe_prompt_instagram_invoice(oid, data)
        except Exception as e:
            QMessageBox.critical(self,"خطا",str(e))

    def edit_instagram(self):
        oid=self.selected_instagram_id()
        if not oid:
            QMessageBox.information(self,"سفارش","یک سفارش را انتخاب کنید.")
            return
        row=self.db.con.execute("SELECT * FROM instagram_orders WHERE id=?",(oid,)).fetchone()
        if not row:
            return
        data=self._instagram_order_dialog(row)
        if not data:
            return
        try:
            self.db.save_instagram_order(data, data["items"], order_id=oid)
            self.refresh_all()
            QMessageBox.information(self,"انجام شد","سفارش به‌روزرسانی شد.")
            self._maybe_prompt_instagram_invoice(oid, data)
        except Exception as e:
            QMessageBox.critical(self,"خطا",str(e))

    def _maybe_prompt_instagram_invoice(self, oid, data):
        if not data or data.get("status") != "تحویل شد" or not data.get("items"):
            return
        row = self.db.con.execute("SELECT sale_id FROM instagram_orders WHERE id=?", (int(oid),)).fetchone()
        if row and row["sale_id"]:
            return
        if QMessageBox.question(self, "صدور فاکتور", "سفارش تحویل شده است. همین حالا فاکتور فروش صادر شود؟") != QMessageBox.Yes:
            return
        for r in range(self.instagram_table.rowCount()):
            item = self.instagram_table.item(r, 0)
            if item and int(item.text()) == int(oid):
                self.instagram_table.selectRow(r)
                break
        self.convert_instagram_invoice()

    def convert_instagram_invoice(self):
        oid=self.selected_instagram_id()
        if not oid:
            QMessageBox.information(self,"فاکتور","یک سفارش را انتخاب کنید.")
            return
        order=self.db.con.execute("SELECT * FROM instagram_orders WHERE id=?",(oid,)).fetchone()
        if not order:
            return
        d=QDialog(self); d.setWindowTitle("صدور فاکتور از سفارش اینستاگرام")
        d.setLayoutDirection(Qt.RightToLeft)
        f=QFormLayout(d)
        f.addRow("مشتری:", QLabel(order["customer"] or "-"))
        f.addRow("مبلغ:", QLabel(money(order["total"])))
        payment=QComboBox(); payment.addItems(["نقدی","کارتخوان","واریز بانکی","نسیه","چک"])
        if order["payment"]:
            idx=payment.findText(order["payment"])
            if idx>=0: payment.setCurrentIndex(idx)
        f.addRow("روش پرداخت:", payment)
        check_no=QLineEdit(); check_bank=QLineEdit(); check_branch=QLineEdit()
        check_issue=QLineEdit(jalali_today()); check_due=QLineEdit(jalali_today())
        check_widgets=[
            ("شماره چک:", check_no), ("بانک:", check_bank), ("شعبه:", check_branch),
            ("تاریخ صدور:", check_issue), ("سررسید:", check_due),
        ]
        check_rows=[]
        for label,w in check_widgets:
            f.addRow(label,w); check_rows.append((label,w))
        def toggle_check(_=None):
            show=payment.currentText()=="چک"
            for lab,w in check_rows:
                w.setVisible(show)
                f.labelForField(w).setVisible(show) if f.labelForField(w) else None
        payment.currentIndexChanged.connect(toggle_check)
        toggle_check()
        b=QDialogButtonBox(QDialogButtonBox.Save|QDialogButtonBox.Cancel)
        b.accepted.connect(d.accept); b.rejected.connect(d.reject); f.addRow(b)
        if d.exec()!=QDialog.Accepted:
            return
        check_data=None
        if payment.currentText()=="چک":
            try:
                check_data={
                    "person": order["customer"] or "مشتری",
                    "check_no": check_no.text().strip(),
                    "bank": check_bank.text().strip(),
                    "branch": check_branch.text().strip(),
                    "due_date": normalize_date_input(check_due.text().strip()),
                    "issue_date": normalize_date_input(check_issue.text().strip()),
                    "notes": f"چک سفارش اینستاگرام {oid}",
                }
            except Exception as e:
                QMessageBox.warning(self,"چک",str(e)); return
            if not check_data["check_no"]:
                QMessageBox.warning(self,"چک","شماره چک را وارد کنید."); return
        try:
            sid, invoice_no, total, profit = self.db.convert_instagram_to_sale(
                oid, payment.currentText(), check_data
            )
            self.refresh_all()
            QMessageBox.information(
                self, "فاکتور صادر شد",
                f"فاکتور {invoice_no:04d} از سفارش اینستاگرام ثبت شد.\n"
                f"مبلغ: {money(total)}\nسود: {money(profit)}\n"
                "موجودی، گزارش فروش و حساب دفتری به‌روز شد."
            )
            try:
                self.print_saved_sale(sid)
            except Exception:
                pass
        except Exception as e:
            QMessageBox.critical(self,"خطا",str(e))

    def print_instagram_invoice(self):
        oid=self.selected_instagram_id()
        if not oid:
            QMessageBox.information(self,"چاپ","یک سفارش را انتخاب کنید.")
            return
        order=self.db.con.execute("SELECT * FROM instagram_orders WHERE id=?",(oid,)).fetchone()
        if not order:
            return
        if order["sale_id"]:
            sale=self.db.con.execute(
                "SELECT id,status FROM sales WHERE id=?", (int(order["sale_id"]),)
            ).fetchone()
            if sale and (sale["status"] or "فعال")=="فعال":
                self.print_saved_sale(int(sale["id"]))
                return
        cart=self.db.instagram_cart(oid)
        if not cart:
            QMessageBox.information(self,"چاپ","این سفارش کالایی برای چاپ ندارد.")
            return
        html=self.invoice_html(
            cart=cart,
            invoice_no=int(order["id"]),
            invoice_date=order["created_at"],
            customer_name=order["customer"] or "مشتری اینستاگرام",
            payment_name=order["payment"] or "سفارش اینستاگرام",
        )
        path=os.path.join(tempfile.gettempdir(), f"NeginAbzar_IG_{int(order['id'])}_{int(time.time()*1000)}.pdf")
        printer=QPrinter(QPrinter.PrinterMode.HighResolution)
        printer.setOutputFormat(QPrinter.OutputFormat.PdfFormat)
        printer.setOutputFileName(path)
        self.configure_printer_page(printer)
        doc=QTextDocument(); doc.setDefaultFont(QFont("Tahoma",9)); doc.setHtml(html); doc.print_(printer)
        open_path(path)

    def cancel_instagram(self):
        oid=self.selected_instagram_id()
        if not oid:
            QMessageBox.information(self,"لغو","یک سفارش را انتخاب کنید.")
            return
        if QMessageBox.question(
            self,"لغو سفارش",
            "سفارش لغو شود؟\nاگر فاکتور فعال داشته باشد ابطال می‌شود و کالا به انبار برمی‌گردد."
        )!=QMessageBox.Yes:
            return
        try:
            self.db.cancel_instagram_order(oid)
            self.refresh_all()
            QMessageBox.information(self,"انجام شد","سفارش لغو شد.")
        except Exception as e:
            QMessageBox.critical(self,"خطا",str(e))

    def delete_instagram(self):
        oid=self.selected_instagram_id()
        if not oid:
            return
        if QMessageBox.question(self,"حذف سفارش","این سفارش حذف شود؟")==QMessageBox.Yes:
            try:
                self.db.delete_instagram_order(oid)
                self.refresh_all()
            except Exception as e:
                QMessageBox.warning(self,"حذف",str(e))

    def make_expenses(self):
        page=QWidget(); l=QVBoxLayout(page); l.setContentsMargins(0,0,0,0)
        top=QHBoxLayout(); top.addLayout(self.title_layout("هزینه‌ها","هزینه‌های جاری، ارسال، اجاره و سایر موارد")); top.addStretch()
        b=QPushButton("＋ ثبت هزینه"); b.clicked.connect(self.add_expense); top.addWidget(b); b=QPushButton("✏️ ویرایش هزینه"); b.clicked.connect(self.edit_expense); top.addWidget(b); b=QPushButton("🗑 حذف هزینه"); b.clicked.connect(self.delete_expense); top.addWidget(b); l.addLayout(top)
        self.expense_table=self.simple_table(["کد","عنوان","مبلغ","توضیحات","تاریخ"]); l.addWidget(self.expense_table); self.stack.addWidget(page)

    def add_expense(self):
        d=QDialog(self); d.setWindowTitle("ثبت هزینه"); d.setLayoutDirection(Qt.RightToLeft); f=QFormLayout(d)
        title=QLineEdit(); amount=MoneySpinBox(); amount.setMaximum(999999999999); amount.setDecimals(0); notes=QTextEdit()
        f.addRow("عنوان:",title); f.addRow("مبلغ:",amount); f.addRow("توضیحات:",notes)
        b=QDialogButtonBox(QDialogButtonBox.Save|QDialogButtonBox.Cancel); b.accepted.connect(d.accept); b.rejected.connect(d.reject); f.addRow(b)
        if d.exec() and title.text().strip():
            self.db.con.execute("INSERT INTO expenses(title,amount,notes,created_at) VALUES(?,?,?,?)",
                                (title.text(),amount.value(),notes.toPlainText(),now()))
            self.db.con.commit(); self.refresh_all()

    def selected_expense_id(self):
        r=self.expense_table.currentRow(); return int(self.expense_table.item(r,0).text()) if r>=0 else None

    def edit_expense(self):
        eid=self.selected_expense_id()
        if not eid: return
        row=self.db.con.execute("SELECT * FROM expenses WHERE id=?",(eid,)).fetchone()
        if not row: return
        d=QDialog(self); d.setWindowTitle("ویرایش هزینه"); d.setLayoutDirection(Qt.RightToLeft); f=QFormLayout(d); title=QLineEdit(row["title"]); amount=MoneySpinBox(); amount.setValue(float(row["amount"])); notes=QTextEdit(row["notes"] or ""); f.addRow("عنوان:",title); f.addRow("مبلغ:",amount); f.addRow("توضیحات:",notes); b=QDialogButtonBox(QDialogButtonBox.Save|QDialogButtonBox.Cancel); b.accepted.connect(d.accept); b.rejected.connect(d.reject); f.addRow(b)
        if d.exec() and title.text().strip(): self.db.con.execute("UPDATE expenses SET title=?,amount=?,notes=? WHERE id=?",(title.text().strip(),round(amount.value()),notes.toPlainText(),eid)); self.db.con.commit(); self.refresh_all()

    def delete_expense(self):
        eid=self.selected_expense_id()
        if not eid: return
        if QMessageBox.question(self,"حذف هزینه","این هزینه حذف شود؟")==QMessageBox.Yes: self.db.con.execute("UPDATE expenses SET active=0 WHERE id=?",(eid,)); self.db.con.commit(); self.refresh_all()

    def check_due_dates_on_startup(self):
        """برای هر چک سررسیدشده از کاربر می‌پرسد پاس شده یا برگشت خورده."""
        try:
            today = date.today().isoformat()
            payables = self.db.con.execute(
                """SELECT * FROM checks
                   WHERE type='پرداختی' AND status='در انتظار'
                     AND due_date IS NOT NULL AND due_date<>'' AND due_date<=?
                   ORDER BY due_date, id""",
                (today,)
            ).fetchall()
            if payables:
                summary = "\n".join([
                    f"• چک {ch['check_no'] or '-'} | {money(ch['amount'])} | سررسید {format_jalali_date(ch['due_date'])} | {ch['person'] or '-'}"
                    for ch in payables[:12]
                ])
                if len(payables) > 12:
                    summary += f"\n... و {len(payables)-12} چک دیگر"
                QMessageBox.information(
                    self, "چک‌های پرداختی سررسیدشده",
                    f"{len(payables)} چک پرداختی به سررسید رسیده است.\n\n{summary}"
                )

            due_checks = self.db.get_due_checks()
            if not due_checks:
                return
            summary = "\n".join([
                f"• چک {ch['check_no'] or '-'} | {money(ch['amount'])} | سررسید {format_jalali_date(ch['due_date'])}"
                for ch in due_checks[:12]
            ])
            if len(due_checks) > 12:
                summary += f"\n... و {len(due_checks)-12} چک دیگر"
            box = QMessageBox(self)
            box.setWindowTitle("🔔 چک‌های سررسیدشده")
            box.setText(
                f"{len(due_checks)} چک سررسید شده است.\n\n{summary}\n\n"
                "اکنون وضعیت هر چک را مشخص کنید."
            )
            box.addButton("شروع بررسی", QMessageBox.AcceptRole)
            box.exec()

            for ch in due_checks:
                due_text = format_jalali_date(ch["due_date"])
                info = (
                    f"چک شماره: {ch['check_no'] or '-'}\n"
                    f"بانک: {ch['bank'] or '-'}\n"
                    f"مبلغ: {money(ch['amount'])}\n"
                    f"سررسید: {due_text}\n"
                    f"شخص: {ch['person'] or '-'}\n\n"
                    "آیا این چک پاس/وصول شده است؟"
                )
                box = QMessageBox(self)
                box.setWindowTitle("🔔 سررسید چک")
                box.setIcon(QMessageBox.Question)
                box.setText(info)
                passed = box.addButton("بله، پاس شد", QMessageBox.AcceptRole)
                returned = box.addButton("خیر، برگشت خورد", QMessageBox.DestructiveRole)
                later = box.addButton("بعداً بررسی می‌کنم", QMessageBox.RejectRole)
                box.exec()
                clicked = box.clickedButton()
                try:
                    if clicked is passed:
                        self.db.set_check_status(int(ch["id"]), "وصول شد")
                    elif clicked is returned:
                        self.db.set_check_status(int(ch["id"]), "برگشت خورد")
                        QMessageBox.warning(
                            self, "چک برگشتی",
                            f"چک شماره {ch['check_no'] or '-'} برگشت خورد.\n"
                            "مبلغ آن به بدهی مشتری در حساب دفتری اضافه شد.\n"
                            "این بدهی فقط یک‌بار ثبت می‌شود."
                        )
                    elif clicked is later:
                        continue
                except Exception as e:
                    QMessageBox.critical(self, "خطا", f"ثبت وضعیت چک انجام نشد:\n{e}")
            self.refresh_all()
        except Exception as e:
            QMessageBox.warning(self, "بررسی چک‌ها", f"بررسی چک‌های سررسیدشده انجام نشد:\n{e}")

    def update_selected_check_status(self):
        row = self.check_table.currentRow()
        if row < 0:
            QMessageBox.information(self, "چک", "ابتدا یک چک را انتخاب کنید.")
            return
        check_id_item = self.check_table.item(row, 0)
        check_id = check_id_item.data(Qt.UserRole) if check_id_item else None
        if not check_id:
            QMessageBox.warning(self, "چک", "شناسه چک پیدا نشد. جدول را دوباره بازخوانی کنید.")
            return
        ch = self.db.con.execute("SELECT * FROM checks WHERE id=?", (int(check_id),)).fetchone()
        if not ch:
            QMessageBox.warning(self, "چک", "چک پیدا نشد.")
            return
        status, ok = self.get_check_status_dialog(ch["status"])
        if ok:
            try:
                self.db.set_check_status(int(check_id), status)
                self.refresh_all()
                QMessageBox.information(self, "چک", "وضعیت چک با موفقیت تغییر کرد.")
            except Exception as e:
                QMessageBox.critical(self, "خطا", str(e))

    def get_check_status_dialog(self, current_status):
        d=QDialog(self); d.setWindowTitle("تغییر وضعیت چک"); d.setLayoutDirection(Qt.RightToLeft)
        f=QFormLayout(d); status=QComboBox(); status.addItems(["در انتظار","وصول شد","برگشت خورد","پرداخت شد","باطل شد"]); status.setCurrentText(current_status)
        f.addRow("وضعیت جدید:",status)
        b=QDialogButtonBox(QDialogButtonBox.Save|QDialogButtonBox.Cancel); b.accepted.connect(d.accept); b.rejected.connect(d.reject); f.addRow(b)
        ok = d.exec() == QDialog.Accepted
        return status.currentText(), ok

    def make_checks(self):
        page = QWidget()
        l = QVBoxLayout(page)
        l.setContentsMargins(0, 0, 0, 0)
        top = QHBoxLayout()
        top.addLayout(self.title_layout("چک‌ها", "مدیریت چک‌های دریافتی/پرداختی و پیگیری سررسید"))
        top.addStretch()
        b = QPushButton("＋ ثبت چک")
        b.clicked.connect(self.add_check)
        top.addWidget(b)
        b = QPushButton("🔄 تغییر وضعیت چک")
        b.clicked.connect(self.update_selected_check_status)
        top.addWidget(b)
        l.addLayout(top)
        search_row = QHBoxLayout()
        self.check_search = QLineEdit()
        self.check_search.setPlaceholderText("جستجو با شخص، شماره چک، بانک یا وضعیت...")
        self.check_search.textChanged.connect(self.refresh_checks_table)
        search_row.addWidget(self.check_search)
        l.addLayout(search_row)
        self.check_table = self.simple_table(
            ["شخص", "شماره چک", "بانک", "شعبه", "مبلغ", "سررسید", "نوع", "وضعیت", "توضیحات"]
        )
        l.addWidget(self.check_table)
        self.stack.addWidget(page)

    def refresh_checks_table(self):
        q = (self.check_search.text().strip() if hasattr(self, "check_search") else "")
        like = f"%{q}%"
        if q:
            rows = self.db.con.execute(
                """SELECT * FROM checks
                   WHERE person LIKE ? OR check_no LIKE ? OR bank LIKE ?
                      OR status LIKE ? OR type LIKE ? OR notes LIKE ?
                   ORDER BY id DESC""",
                (like, like, like, like, like, like)
            ).fetchall()
        else:
            rows = self.db.con.execute("SELECT * FROM checks ORDER BY id DESC").fetchall()
        self.check_table.setRowCount(0)
        for r in rows:
            i = self.check_table.rowCount()
            self.check_table.insertRow(i)
            vals = [
                r["person"], r["check_no"], r["bank"], r["branch"], money(r["amount"]),
                format_jalali_date(r["due_date"]), r["type"], r["status"], r["notes"]
            ]
            for j, v in enumerate(vals):
                self.check_table.setItem(i, j, center_item(v))
            self.check_table.item(i, 0).setData(Qt.UserRole, int(r["id"]))

    def add_check(self):
        d=QDialog(self); d.setWindowTitle("ثبت چک"); d.setLayoutDirection(Qt.RightToLeft); f=QFormLayout(d)
        person=QLineEdit(); check_no=QLineEdit(); bank=QLineEdit(); branch=QLineEdit(); amount=MoneySpinBox(); due=QLineEdit(jalali_today()); issue=QLineEdit(jalali_today()); typ=QComboBox(); typ.addItems(["دریافتی","پرداختی"]); status=QComboBox(); status.addItems(["در انتظار","وصول شد","برگشت خورد","پرداخت شد","باطل شد"]); notes=QLineEdit()
        cust=QComboBox(); cust.addItem("بدون اتصال به مشتری", None)
        for r in self.db.con.execute("SELECT id,name,phone FROM customers ORDER BY name COLLATE NOCASE").fetchall():
            cust.addItem(f"{r['name']} | {r['phone'] or '-'}", int(r["id"]))
        self._bind_searchable_combo(cust)
        for a,w in [("مشتری:",cust),("شخص:",person),("شماره چک:",check_no),("بانک:",bank),("شعبه:",branch),("مبلغ:",amount),("تاریخ صدور:",issue),("سررسید:",due),("نوع:",typ),("وضعیت:",status),("توضیحات:",notes)]: f.addRow(a,w)
        b=QDialogButtonBox(QDialogButtonBox.Save|QDialogButtonBox.Cancel); b.accepted.connect(d.accept); b.rejected.connect(d.reject); f.addRow(b)
        if d.exec():
            if not check_no.text().strip() or amount.value()<=0:
                QMessageBox.warning(self,"چک","شماره چک و مبلغ الزامی است.")
                return
            try:
                due_date = normalize_date_input(due.text().strip())
                issue_date = normalize_date_input(issue.text().strip())
                cid = self._resolve_combo_customer(cust)
                person_name = person.text().strip()
                if not person_name and cid:
                    person_name = cust.currentText().split(" | ")[0].strip()
                self.db.con.execute("""INSERT INTO checks(person,amount,due_date,type,status,notes,check_no,bank,branch,issue_date,customer_id) VALUES(?,?,?,?,?,?,?,?,?,?,?)""",
                                    (person_name, int(money_decimal(amount.value())), due_date, typ.currentText(), "در انتظار", notes.text(), check_no.text().strip(), bank.text().strip(), branch.text().strip(), issue_date, cid))
                new_id = self.db.con.execute("SELECT last_insert_rowid()").fetchone()[0]
                self.db.con.commit()
                wanted = status.currentText()
                if wanted != "در انتظار":
                    self.db.set_check_status(int(new_id), wanted)
                self.refresh_all()
            except Exception as e:
                self.db.con.rollback()
                QMessageBox.warning(self,"خطا در ثبت چک",f"ثبت چک انجام نشد:\n{e}")

    def simple_table(self, headers):
        t=QTableWidget(0,len(headers))
        t.setHorizontalHeaderLabels(headers)
        t.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        t.setAlternatingRowColors(True)
        return t

    # ---------- reports ----------
    def edit_selected_customer(self):
        row = self.customer_table.currentRow()
        if row < 0:
            QMessageBox.warning(self, "ویرایش مشتری", "ابتدا یک مشتری را انتخاب کنید.")
            return
        item = self.customer_table.item(row, 0)
        if not item:
            return
        cid = int(item.text())
        customer = self.db.con.execute("SELECT * FROM customers WHERE id=?", (cid,)).fetchone()
        if not customer:
            return

        dlg = QDialog(self)
        dlg.setWindowTitle("✏️ ویرایش مشتری")
        form = QFormLayout(dlg)
        name = QLineEdit(str(customer["name"] or ""))
        phone = QLineEdit(str(customer["phone"] or ""))
        address = QLineEdit(str(customer["address"] or ""))
        form.addRow("نام مشتری:", name)
        form.addRow("تلفن:", phone)
        form.addRow("آدرس:", address)
        balance_info=QLabel(f"مانده محاسبه‌شده: {self.db.format_customer_balance(self.db.recompute_customer_balance(cid))}")
        form.addRow("مانده حساب:", balance_info)
        buttons = QDialogButtonBox(QDialogButtonBox.Save | QDialogButtonBox.Cancel)
        buttons.accepted.connect(dlg.accept)
        buttons.rejected.connect(dlg.reject)
        form.addRow(buttons)
        if dlg.exec() == QDialog.Accepted:
            if not name.text().strip():
                QMessageBox.warning(self, "خطا", "نام مشتری را وارد کنید.")
                return
            self.db.update_customer(cid, name.text(), phone.text(), address.text())
            self.refresh_all()
            QMessageBox.information(self, "انجام شد", "اطلاعات مشتری ویرایش شد.")

    def make_ledger(self):
        page=QWidget(); root=QVBoxLayout(page); root.setContentsMargins(0,0,0,0)
        top=QHBoxLayout(); top.addLayout(self.title_layout("حساب دفتری","پرونده کامل بدهی، خریدها، پرداخت‌ها و مانده هر مشتری")); top.addStretch()
        top.addWidget(QLabel("مشتری:")); self.ledger_customer=QComboBox(); self.ledger_customer.setEditable(True); self.ledger_customer.setInsertPolicy(QComboBox.NoInsert); self.ledger_customer.setMinimumWidth(330); self.ledger_customer.currentIndexChanged.connect(self.refresh_ledger); top.addWidget(self.ledger_customer)
        b=QPushButton("💵 ثبت پرداخت مشتری"); b.clicked.connect(self.add_customer_payment_dialog); top.addWidget(b); root.addLayout(top)
        edit_pay_btn = QPushButton("✏️ ویرایش پرداخت انتخاب‌شده")
        edit_pay_btn.setToolTip("یک ردیف «پرداخت» را در جدول گردش حساب انتخاب کنید.")
        edit_pay_btn.clicked.connect(self.edit_selected_payment)
        top.addWidget(edit_pay_btn)
        c=Card(bg="#225D61"); cl=QHBoxLayout(c)
        self.ledger_balance=QLabel("مانده: 0 تومان"); self.ledger_balance.setStyleSheet("font-size:25px;font-weight:900;")
        self.ledger_total_debit=QLabel("خرید نسیه: 0 تومان"); self.ledger_total_paid=QLabel("پرداخت/بستانکار: 0 تومان")
        cl.addWidget(self.ledger_balance); cl.addStretch(); cl.addWidget(self.ledger_total_debit); cl.addSpacing(20); cl.addWidget(self.ledger_total_paid); root.addWidget(c)
        sc=Card(); sl=QVBoxLayout(sc); sl.addWidget(QLabel("🧾 فاکتورهای خرید مشتری")); self.ledger_sales=self.simple_table(["فاکتور","تاریخ","مبلغ","سود","پرداخت","وضعیت","تعداد اقلام"]); sl.addWidget(self.ledger_sales); root.addWidget(sc,2)
        tc=Card(); tl=QVBoxLayout(tc); tl.addWidget(QLabel("📒 گردش حساب دفتری")); self.ledger_trans=self.simple_table(["تاریخ","نوع","مبلغ","شرح","شماره فاکتور"]); tl.addWidget(self.ledger_trans); root.addWidget(tc,2)
        self.stack.addWidget(page)

    def _bind_searchable_combo(self, combo):
        combo.setEditable(True)
        combo.setInsertPolicy(QComboBox.NoInsert)
        completer = QCompleter(combo.model(), combo)
        try:
            completer.setCompletionMode(QCompleter.CompletionMode.PopupCompletion)
        except Exception:
            completer.setCompletionMode(QCompleter.PopupCompletion)
        completer.setFilterMode(Qt.MatchContains)
        completer.setCaseSensitivity(Qt.CaseInsensitive)
        combo.setCompleter(completer)
        le = combo.lineEdit()
        if le is not None:
            le.editingFinished.connect(lambda c=combo: self._commit_combo_choice(c))

    def _commit_combo_choice(self, combo):
        text = combo.currentText().strip()
        idx = combo.findText(text)
        if idx >= 0:
            combo.setCurrentIndex(idx)
            return
        name_part = text.split(" | ")[0].strip()
        for i in range(combo.count()):
            if combo.itemText(i).split(" | ")[0].strip() == name_part:
                combo.setCurrentIndex(i)
                return

    def _resolve_combo_customer(self, combo):
        if combo is None:
            return None
        self._commit_combo_choice(combo)
        text = combo.currentText().strip()
        idx = combo.findText(text)
        if idx >= 0:
            return combo.itemData(idx)
        name_part = text.split(" | ")[0].strip()
        matches = []
        for i in range(combo.count()):
            if combo.itemText(i).split(" | ")[0].strip() == name_part:
                matches.append(combo.itemData(i))
        if len(matches) == 1:
            return matches[0]
        data = combo.currentData()
        current_label = combo.itemText(combo.currentIndex()) if combo.currentIndex() >= 0 else ""
        if data is not None and current_label.split(" | ")[0].strip() == name_part:
            return data
        return None

    def refresh_customer_combos(self):
        rows=self.db.con.execute("SELECT id,name,phone,balance FROM customers ORDER BY name COLLATE NOCASE").fetchall()
        for name in ("sale_customer","ledger_customer"):
            combo=getattr(self,name,None)
            if combo is None: continue
            old=combo.currentData(); combo.blockSignals(True); combo.clear()
            if name=="sale_customer": combo.addItem("مشتری آزاد / نقدی",None)
            for r in rows:
                phone = r['phone'] or '-'
                combo.addItem(f"{r['name']} | {phone} | {self.db.format_customer_balance(r['balance'])}", int(r['id']))
            idx=combo.findData(old); combo.setCurrentIndex(idx if idx>=0 else 0); combo.blockSignals(False)
            if combo.property("searchBound") is not True:
                self._bind_searchable_combo(combo)
                combo.setProperty("searchBound", True)
        self.refresh_ledger()

    def refresh_ledger(self):
        if not hasattr(self,"ledger_customer"): return
        cid=self._resolve_combo_customer(self.ledger_customer); self.ledger_sales.setRowCount(0); self.ledger_trans.setRowCount(0)
        if not cid:
            self.ledger_balance.setText("مانده: 0 تومان"); self.ledger_total_debit.setText("خرید نسیه: 0 تومان"); self.ledger_total_paid.setText("پرداخت/بستانکار: 0 تومان"); return
        customer=self.db.con.execute("SELECT name,balance FROM customers WHERE id=?",(cid,)).fetchone();
        if not customer: return
        tx=self.db.customer_transactions(cid)
        # «خرید نسیه» فقط مجموع فاکتورهای نسیه فعال است؛
        # بدهی «برگشت چک» نباید در این شاخص نمایش داده شود.
        debit=sum(
            float(r["total"] or 0) for r in self.db.customer_sales(cid)
            if (r["payment"] or "") == "نسیه" and (r["status"] or "فعال") == "فعال"
        )
        paid=sum(float(r["amount"]) for r in tx if r["transaction_type"] in ("پرداخت","بستانکار"))
        self.ledger_balance.setText(f"{self.db.format_customer_balance(self.db.recompute_customer_balance(cid))}"); self.ledger_total_debit.setText(f"خرید نسیه: {money(debit)}"); self.ledger_total_paid.setText(f"پرداخت/بستانکار: {money(paid)}")
        for r in self.db.customer_sales(cid):
            i=self.ledger_sales.rowCount(); self.ledger_sales.insertRow(i); vals=[f"{int(r['invoice_no'] or r['id']):04d}",format_jalali_date(r["invoice_date"] or r["created_at"]),money(r["total"]),money(r["profit"]),r["payment"],r["status"] or "فعال",format_qty(r["item_count"] or 0)]
            for j,v in enumerate(vals): self.ledger_sales.setItem(i,j,center_item(v))
        for r in tx:
            i=self.ledger_trans.rowCount()
            self.ledger_trans.insertRow(i)
            inv=f"{int(r['invoice_no']):04d}" if r["invoice_no"] else "-"
            vals=[format_jalali_date(r["created_at"]),r["transaction_type"],money(r["amount"]),r["description"],inv]
            for j,v in enumerate(vals):
                self.ledger_trans.setItem(i,j,center_item(v))
            # Keep the real database transaction ID hidden in the date cell.
            self.ledger_trans.item(i, 0).setData(Qt.UserRole, int(r["id"]))


    def edit_selected_payment(self):
        row = self.ledger_trans.currentRow()
        if row < 0:
            QMessageBox.warning(self, "ویرایش پرداخت", "ابتدا یک پرداخت را از جدول «گردش حساب دفتری» انتخاب کنید.")
            return

        date_item = self.ledger_trans.item(row, 0)
        type_item = self.ledger_trans.item(row, 1)
        if not date_item or not type_item:
            QMessageBox.warning(self, "خطا", "اطلاعات پرداخت انتخاب‌شده کامل نیست.")
            return

        if type_item.text().strip() != "پرداخت":
            QMessageBox.warning(self, "ویرایش پرداخت", "فقط ردیف‌های نوع «پرداخت» قابل ویرایش هستند.")
            return

        # Transaction ID is stored invisibly in UserRole of the date cell.
        tx_id = date_item.data(Qt.UserRole)
        try:
            tx_id = int(tx_id)
        except Exception:
            QMessageBox.warning(self, "خطا", "شناسه پرداخت پیدا نشد. لطفاً دوباره جدول را بازخوانی کنید.")
            return

        tx = self.db.con.execute(
            "SELECT * FROM account_transactions WHERE id=?", (tx_id,)
        ).fetchone()
        if not tx:
            QMessageBox.warning(self, "خطا", "پرداخت پیدا نشد.")
            return

        dlg = QDialog(self)
        dlg.setWindowTitle("✏️ ویرایش پرداخت")
        dlg.setLayoutDirection(Qt.RightToLeft)
        form = QFormLayout(dlg)

        amount = MoneySpinBox()
        amount.setDecimals(0)
        amount.setMaximum(999999999999)
        amount.setValue(float(tx["amount"] or 0))

        notes = QLineEdit(str(tx["description"] or ""))

        form.addRow("مبلغ پرداخت:", amount)
        form.addRow("توضیحات:", notes)

        buttons = QDialogButtonBox(QDialogButtonBox.Save | QDialogButtonBox.Cancel)
        buttons.accepted.connect(dlg.accept)
        buttons.rejected.connect(dlg.reject)
        form.addRow(buttons)

        if dlg.exec() == QDialog.Accepted:
            if amount.value() <= 0:
                QMessageBox.warning(self, "خطا", "مبلغ باید بیشتر از صفر باشد.")
                return

            try:
                self.db.update_account_transaction(tx_id, amount.value(), notes.text())
                self.refresh_all()
                self.refresh_ledger()
                QMessageBox.information(self, "انجام شد", "پرداخت با موفقیت ویرایش شد.")
            except Exception as e:
                QMessageBox.critical(self, "خطا", f"ویرایش پرداخت انجام نشد:\n{e}")

    def add_customer_payment_dialog(self):
        cid=self._resolve_combo_customer(self.ledger_customer) if hasattr(self,"ledger_customer") else None
        if not cid: QMessageBox.information(self,"حساب دفتری","ابتدا یک مشتری را انتخاب کنید."); return
        row=self.db.con.execute("SELECT name,balance FROM customers WHERE id=?",(cid,)).fetchone(); d=QDialog(self); d.setWindowTitle(f"ثبت پرداخت - {row['name']}"); d.setLayoutDirection(Qt.RightToLeft); f=QFormLayout(d)
        amount=MoneySpinBox(); amount.setMaximum(999999999999); amount.setDecimals(0); amount.setValue(float(row["balance"] or 0)); notes=QTextEdit(); notes.setPlaceholderText("مثلاً پرداخت نقدی")
        f.addRow("مانده فعلی:",QLabel(self.db.format_customer_balance(row["balance"]))); f.addRow("مبلغ پرداخت:",amount); f.addRow("توضیحات:",notes)
        b=QDialogButtonBox(QDialogButtonBox.Save|QDialogButtonBox.Cancel); b.accepted.connect(d.accept); b.rejected.connect(d.reject); f.addRow(b)
        if d.exec():
            try: self.db.add_customer_payment(cid,amount.value(),notes.toPlainText()); QMessageBox.information(self,"ثبت شد","پرداخت در حساب دفتری ثبت شد."); self.refresh_all()
            except Exception as e: QMessageBox.warning(self,"خطا",str(e))

    def make_reports(self):
        page=QWidget(); l=QVBoxLayout(page); l.setContentsMargins(0,0,0,0)
        l.addLayout(self.title_layout("گزارش‌ها","گزارش روزانه، هفتگی، ماهانه و شاخص‌های مالی"))
        grid=QGridLayout(); grid.setSpacing(10); self.report_values=[]
        titles=["فروش امروز","سود امروز","فاکتور امروز","هزینه امروز","فروش این هفته","سود این هفته","فروش این ماه","سود این ماه","خرید این ماه","هزینه این ماه","سود خالص ماه","ارزش موجودی","بدهکاران","چک سررسیدشده"]
        for i,title in enumerate(titles):
            c=Card(); x=QVBoxLayout(c); x.setContentsMargins(14,12,14,12); a=QLabel(title); a.setStyleSheet(f"color:{MUTED};font-size:13px;"); v=QLabel("0"); v.setStyleSheet("font-size:22px;font-weight:900;"); x.addWidget(a); x.addWidget(v); grid.addWidget(c,i//4,i%4); self.report_values.append(v)
        l.addLayout(grid)
        low=Card(); ll=QVBoxLayout(low); h=QLabel("کالاهای نیازمند شارژ موجودی"); h.setStyleSheet("font-size:21px;font-weight:900;"); ll.addWidget(h); self.low_table=self.simple_table(["محصول","موجودی","حداقل موجودی"]); ll.addWidget(self.low_table); l.addWidget(low)
        split=QHBoxLayout(); cp=Card(); cpl=QVBoxLayout(cp); cpl.addWidget(QLabel("پرفروش‌ترین کالاها")); self.top_product_table=self.simple_table(["کالا","تعداد","فروش"]); cpl.addWidget(self.top_product_table); split.addWidget(cp)
        cc=Card(); ccl=QVBoxLayout(cc); ccl.addWidget(QLabel("بهترین مشتریان")); self.top_customer_table=self.simple_table(["مشتری","فاکتور","فروش"]); ccl.addWidget(self.top_customer_table); split.addWidget(cc); l.addLayout(split)
        export=QPushButton("📤 خروجی گزارش فروش"); export.clicked.connect(self.export_sales); l.addWidget(export); self.stack.addWidget(page)

    def refresh_reports(self):
        st=self.db.stats(); d,w,m=st["day"],st["week"],st["month"]
        net_month=m[1]-m[3]
        vals=[money(d[0]),money(d[1]),str(st["invoices"]),money(d[3]),money(w[0]),money(w[1]),money(m[0]),money(m[1]),money(m[2]),money(m[3]),money(net_month),money(st["inventory_value"]),str(st["debtors"]),money(st["due_checks"])]
        for label,value in zip(self.report_values,vals): label.setText(value)
        rows=self.db.con.execute("SELECT name,stock,min_stock FROM products WHERE COALESCE(active,1)=1 AND stock<=min_stock ORDER BY stock").fetchall(); self.low_table.setRowCount(0)
        for r in rows:
            i=self.low_table.rowCount(); self.low_table.insertRow(i)
            for j,v in enumerate([r["name"],format_qty(r["stock"]),format_qty(r["min_stock"])]): self.low_table.setItem(i,j,center_item(v))
        tp,tc=self.db.detailed_reports(); self.top_product_table.setRowCount(0); self.top_customer_table.setRowCount(0)
        for r in tp:
            i=self.top_product_table.rowCount(); self.top_product_table.insertRow(i)
            for j,v in enumerate([r["name"],format_qty(r["qty"]),money(r["total"])]): self.top_product_table.setItem(i,j,center_item(v))
        for r in tc:
            i=self.top_customer_table.rowCount(); self.top_customer_table.insertRow(i)
            for j,v in enumerate([r["name"],r["invoices"],money(r["total"])]): self.top_customer_table.setItem(i,j,center_item(v))

    def export_sales(self):
        path,_=QFileDialog.getSaveFileName(self,"ذخیره گزارش فروش","sales.csv","CSV (*.csv)")
        if not path: return
        try:
            self.db.export_csv(
                "SELECT id,invoice_no,invoice_date,total,profit,discount,payment,status,created_at FROM sales ORDER BY id DESC",
                path,["شناسه","شماره فاکتور","تاریخ فاکتور","فروش","سود","تخفیف","پرداخت","وضعیت","تاریخ ثبت"])
            QMessageBox.information(self,"انجام شد","گزارش ذخیره شد.")
        except Exception as e:
            QMessageBox.critical(self,"خطا",str(e))

    def make_recipes(self):
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.addLayout(self.title_layout(
            "رسپی‌ها", "ثبت مواد اولیه و محاسبه هزینه هر دستور براساس قیمت خرید فعلی انبار"
        ))

        actions = QHBoxLayout()
        add = QPushButton("＋ رسپی جدید")
        add.clicked.connect(self.add_recipe)
        actions.addWidget(add)
        edit = QPushButton("✏ ویرایش رسپی")
        edit.clicked.connect(self.edit_recipe)
        actions.addWidget(edit)
        delete = QPushButton("🗑 حذف رسپی")
        delete.clicked.connect(self.delete_recipe)
        actions.addWidget(delete)
        actions.addStretch()
        layout.addLayout(actions)

        self.recipe_table = self.simple_table(
            ["نام رسپی", "تعداد مواد", "هزینه مواد (تومان)"]
        )
        self.recipe_table.itemSelectionChanged.connect(self.refresh_recipe_detail)
        layout.addWidget(self.recipe_table)

        ingredients_card = Card()
        ingredients_layout = QVBoxLayout(ingredients_card)
        ingredients_layout.addWidget(QLabel("مواد اولیه رسپی انتخاب‌شده"))
        self.recipe_detail_table = self.simple_table(
            ["ماده اولیه", "مقدار", "واحد", "قیمت خرید واحد", "هزینه"]
        )
        ingredients_layout.addWidget(self.recipe_detail_table)
        self.recipe_instructions_label = QLabel("یک رسپی را انتخاب کنید.")
        self.recipe_instructions_label.setWordWrap(True)
        ingredients_layout.addWidget(self.recipe_instructions_label)
        layout.addWidget(ingredients_card)
        layout.addStretch()
        self.stack.addWidget(page)
        self.refresh_recipes_table()

    def selected_recipe_id(self):
        row = self.recipe_table.currentRow()
        if row < 0:
            return None
        item = self.recipe_table.item(row, 0)
        return int(item.data(Qt.UserRole)) if item and item.data(Qt.UserRole) else None

    def refresh_recipes_table(self):
        if not hasattr(self, "recipe_table"):
            return
        selected_id = self.selected_recipe_id()
        self.recipe_table.setRowCount(0)
        selected_row = -1
        for recipe in self.db.recipes():
            row = self.recipe_table.rowCount()
            self.recipe_table.insertRow(row)
            values = [recipe["name"], recipe["ingredient_count"], money(recipe["total_cost"])]
            for column, value in enumerate(values):
                item = center_item(value)
                if column == 0:
                    item.setData(Qt.UserRole, int(recipe["id"]))
                self.recipe_table.setItem(row, column, item)
            if int(recipe["id"]) == selected_id:
                selected_row = row
        if selected_row >= 0:
            self.recipe_table.selectRow(selected_row)
        elif self.recipe_table.rowCount():
            self.recipe_table.selectRow(0)
        else:
            self.refresh_recipe_detail()

    def refresh_recipe_detail(self):
        if not hasattr(self, "recipe_detail_table"):
            return
        self.recipe_detail_table.setRowCount(0)
        recipe_id = self.selected_recipe_id()
        recipe, ingredients = self.db.recipe_detail(recipe_id) if recipe_id else (None, [])
        if not recipe:
            self.recipe_instructions_label.setText("یک رسپی را انتخاب کنید.")
            return
        for ingredient in ingredients:
            row = self.recipe_detail_table.rowCount()
            self.recipe_detail_table.insertRow(row)
            values = [
                ingredient["name"], format_qty(ingredient["quantity"]), ingredient["unit"],
                money(ingredient["buy_price"]), money(ingredient["line_cost"])
            ]
            for column, value in enumerate(values):
                self.recipe_detail_table.setItem(row, column, center_item(value))
        self.recipe_instructions_label.setText(
            recipe["instructions"] or "برای این رسپی توضیحی ثبت نشده است."
        )

    def open_recipe_dialog(self, recipe_id=None):
        recipe, current_ingredients = self.db.recipe_detail(recipe_id) if recipe_id else (None, [])
        dialog = QDialog(self)
        dialog.setWindowTitle("ویرایش رسپی" if recipe else "ثبت رسپی جدید")
        dialog.setLayoutDirection(Qt.RightToLeft)
        dialog.resize(720, 560)
        layout = QVBoxLayout(dialog)
        form = QFormLayout()
        name = QLineEdit(recipe["name"] if recipe else "")
        instructions = QTextEdit(recipe["instructions"] if recipe else "")
        instructions.setPlaceholderText("روش تهیه یا توضیحات رسپی")
        instructions.setMaximumHeight(100)
        form.addRow("نام رسپی:", name)
        form.addRow("روش تهیه:", instructions)
        layout.addLayout(form)

        ingredient_table = QTableWidget(0, 3)
        ingredient_table.setHorizontalHeaderLabels(["ماده اولیه", "مقدار مصرف", "حذف"])
        ingredient_table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        ingredient_table.setSelectionBehavior(QAbstractItemView.SelectRows)
        layout.addWidget(ingredient_table, 1)

        products = self.db.con.execute(
            """SELECT id, name, unit FROM products
               WHERE COALESCE(active,1)=1 OR id IN (
                   SELECT product_id FROM recipe_items WHERE recipe_id=?
               )
               ORDER BY name COLLATE NOCASE""",
            (int(recipe_id or -1),)
        ).fetchall()

        def remove_ingredient(button):
            for row in range(ingredient_table.rowCount()):
                if ingredient_table.cellWidget(row, 2) is button:
                    ingredient_table.removeRow(row)
                    return

        def add_ingredient(product_id=None, quantity=1):
            row = ingredient_table.rowCount()
            ingredient_table.insertRow(row)
            product_combo = QComboBox()
            for product in products:
                product_combo.addItem(
                    f"{product['name']} ({product['unit']})", int(product["id"])
                )
            if product_id is not None:
                index = product_combo.findData(int(product_id))
                if index >= 0:
                    product_combo.setCurrentIndex(index)
            ingredient_table.setCellWidget(row, 0, product_combo)
            amount = CleanDoubleSpinBox()
            amount.setDecimals(3)
            amount.setRange(0.001, 999999)
            amount.setValue(float(quantity))
            ingredient_table.setCellWidget(row, 1, amount)
            remove = QPushButton("حذف")
            remove.clicked.connect(lambda _, button=remove: remove_ingredient(button))
            ingredient_table.setCellWidget(row, 2, remove)

        add_row = QPushButton("＋ افزودن ماده اولیه")
        add_row.setEnabled(bool(products))
        add_row.clicked.connect(lambda: add_ingredient())
        layout.addWidget(add_row)
        for ingredient in current_ingredients:
            add_ingredient(ingredient["product_id"], ingredient["quantity"])

        buttons = QDialogButtonBox(QDialogButtonBox.Save | QDialogButtonBox.Cancel)
        buttons.accepted.connect(dialog.accept)
        buttons.rejected.connect(dialog.reject)
        layout.addWidget(buttons)
        if dialog.exec() != QDialog.Accepted:
            return

        selected_ingredients = []
        for row in range(ingredient_table.rowCount()):
            product_combo = ingredient_table.cellWidget(row, 0)
            amount = ingredient_table.cellWidget(row, 1)
            if product_combo and product_combo.currentData() is not None:
                selected_ingredients.append((product_combo.currentData(), amount.value()))
        try:
            self.db.save_recipe(
                name.text(), instructions.toPlainText(), selected_ingredients, recipe_id
            )
            self.refresh_recipes_table()
        except Exception as e:
            QMessageBox.warning(self, "ثبت رسپی", str(e))

    def add_recipe(self):
        self.open_recipe_dialog()

    def edit_recipe(self):
        recipe_id = self.selected_recipe_id()
        if not recipe_id:
            QMessageBox.information(self, "انتخاب رسپی", "ابتدا یک رسپی را انتخاب کنید.")
            return
        self.open_recipe_dialog(recipe_id)

    def delete_recipe(self):
        recipe_id = self.selected_recipe_id()
        if not recipe_id:
            QMessageBox.information(self, "انتخاب رسپی", "ابتدا یک رسپی را انتخاب کنید.")
            return
        if QMessageBox.question(self, "حذف رسپی", "رسپی انتخاب‌شده حذف شود؟") == QMessageBox.Yes:
            self.db.delete_recipe(recipe_id)
            self.refresh_recipes_table()

    # ---------- settings ----------
    def make_settings(self):
        page=QWidget(); l=QVBoxLayout(page); l.setContentsMargins(0,0,0,0)
        l.addLayout(self.title_layout("تنظیمات","اطلاعات فروشگاه، مسیر داده پایدار، چاپگر، فاکتور PDF و پشتیبان‌گیری"))
        c=Card(); f=QFormLayout(c)
        self.shop_edit=QLineEdit(self.db.get_setting("shop_name","حسابداری OMID PC")); self.insta_edit=QLineEdit(self.db.get_setting("instagram","@omidpcservice.ir")); self.phone_edit=QLineEdit(self.db.get_setting("phone",""))
        for a,w in [("نام فروشگاه:",self.shop_edit),("اینستاگرام:",self.insta_edit),("تلفن:",self.phone_edit)]: f.addRow(a,w)
        save=QPushButton("💾 ذخیره اطلاعات فروشگاه"); save.clicked.connect(self.save_settings); f.addRow(save); l.addWidget(c)

        # فلش بکاپ اختصاصی رمزنگاری‌شده
        sec=Card(); sf=QFormLayout(sec)
        title=QLabel("🔐 فلش بکاپ اختصاصی OMID PC")
        title.setStyleSheet("font-size:16px; font-weight:700;")
        sf.addRow(title)

        self.secondary_backup_path_edit = QLineEdit()
        self.secondary_backup_path_edit.setReadOnly(True)
        self.secondary_backup_path_edit.setPlaceholderText("هنوز فلشی ثبت نشده است")
        path_row=QHBoxLayout(); path_row.addWidget(self.secondary_backup_path_edit,1)
        browse=QPushButton("🔐 انتخاب و ثبت فلش")
        browse.clicked.connect(self.choose_secondary_backup_path); path_row.addWidget(browse)
        sf.addRow("💾 فلش اختصاصی:",path_row)

        self.secondary_backup_status_label=QLabel("⚪ فلش ثبت نشده")
        self.secondary_backup_status_label.setStyleSheet("font-weight:600;")
        sf.addRow("وضعیت:",self.secondary_backup_status_label)
        self._refresh_secondary_backup_display()

        self.secondary_backup_password_edit=QLineEdit()
        self.secondary_backup_password_edit.setEchoMode(QLineEdit.Password)
        self.secondary_backup_password_edit.setPlaceholderText("رمز قوی اختصاصی شما (حداقل ۱۶ کاراکتر)")
        self.secondary_backup_confirm_edit=QLineEdit()
        self.secondary_backup_confirm_edit.setEchoMode(QLineEdit.Password)
        self.secondary_backup_confirm_edit.setPlaceholderText("تکرار رمز")
        sf.addRow("🔑 رمز بکاپ:", self.secondary_backup_password_edit)
        sf.addRow("تکرار رمز:", self.secondary_backup_confirm_edit)

        sec_hint=QLabel(
            "فلش فقط یک‌بار ثبت می‌شود و برنامه آن را با شناسه ولوم می‌شناسد؛ بنابراین تغییر حرف درایو مشکلی ایجاد نمی‌کند. "
            "از این پس بکاپ‌های خودکار فقط روی همان فلش ثبت‌شده نوشته می‌شوند. فلش دیگری پذیرفته نمی‌شود. "
            "فایل‌های بکاپ روی فلش با AES-256-GCM رمزنگاری می‌شوند و برای بازیابی از داخل برنامه رمز درخواست می‌شود. "
            "اگر فلش جدا باشد، برنامه متوقف نمی‌شود و فقط خطا در لاگ ثبت خواهد شد."
        )
        sec_hint.setWordWrap(True); sec_hint.setStyleSheet(f"color:{MUTED};")
        sf.addRow(sec_hint)
        sec_save=QPushButton("🔐 ذخیره رمز بکاپ")
        sec_save.clicked.connect(self.save_secondary_backup_settings)
        sec_test=QPushButton("🧪 تست فلش ثبت‌شده")
        sec_test.clicked.connect(self.test_secondary_backup)
        sec_actions=QHBoxLayout(); sec_actions.addWidget(sec_save); sec_actions.addWidget(sec_test); sf.addRow(sec_actions)
        l.addWidget(sec)
        data_card=Card(); df=QFormLayout(data_card)
        mode_text = {
            "portable": "قابل‌حمل — داده کنار فایل برنامه است",
            "appdata": "پایدار — داده جدا از برنامه در پوشه کاربر است",
            "custom": "سفارشی — مسیر با NEGIN_ABZAR_DATA تعیین شده",
        }.get(DATA_LOCATION_MODE, DATA_LOCATION_MODE or "-")
        self.data_mode_label=QLabel(mode_text)
        self.data_path_label=QLabel(DATA_DIR)
        self.data_path_label.setWordWrap(True)
        self.data_path_label.setTextInteractionFlags(Qt.TextSelectableByMouse)
        self.db_path_label=QLabel(DB_PATH)
        self.db_path_label.setWordWrap(True)
        self.db_path_label.setTextInteractionFlags(Qt.TextSelectableByMouse)
        df.addRow("نوع ذخیره‌سازی:", self.data_mode_label)
        df.addRow("پوشه اطلاعات:", self.data_path_label)
        df.addRow("فایل دیتابیس:", self.db_path_label)
        hint=QLabel("آپدیت برنامه فقط فایل اجرا را عوض می‌کند. دیتابیس و پوشه backups در این مسیر می‌مانند و پاک نمی‌شوند.")
        hint.setWordWrap(True)
        hint.setStyleSheet(f"color:{MUTED};")
        df.addRow(hint)
        open_data=QPushButton("📂 باز کردن پوشه اطلاعات")
        open_data.clicked.connect(lambda: open_path(DATA_DIR))
        open_back=QPushButton("💾 باز کردن پوشه پشتیبان")
        open_back.clicked.connect(lambda: open_path(BACKUP_DIR))
        row=QHBoxLayout(); row.addWidget(open_data); row.addWidget(open_back)
        df.addRow(row)
        l.addWidget(data_card)
        pc=Card(); pf=QFormLayout(pc)
        self.printer_combo=QComboBox(); self.printer_combo.setMinimumWidth(360)
        self.paper_size=QComboBox(); self.paper_size.addItem("A4 - برگه کامل"); self.paper_size.setEnabled(False)
        self.copies_spin=QSpinBox(); self.copies_spin.setRange(1,99); self.copies_spin.setValue(int(self.db.get_setting("copies","1") or 1)); self.copies_spin.valueChanged.connect(lambda v:self.db.set_setting("copies",v))
        pf.addRow("چاپگر نصب‌شده:",self.printer_combo); pf.addRow("اندازه کاغذ:",self.paper_size); pf.addRow("تعداد نسخه:",self.copies_spin); l.addWidget(pc); self.refresh_printers()
        self.printer_combo.currentIndexChanged.connect(lambda _: self.db.set_setting("printer", self.printer_combo.currentData() or ""))
        actions=QHBoxLayout(); b=QPushButton("🔄 شناسایی چاپگرهای ویندوز"); b.clicked.connect(self.refresh_printers); actions.addWidget(b); b=QPushButton("⚙️ تنظیمات چاپگر ویندوز"); b.clicked.connect(self.open_windows_printers); actions.addWidget(b); b=QPushButton("🧾 چاپ آزمایشی"); b.clicked.connect(self.test_print); actions.addWidget(b); l.addLayout(actions)
        pdf=Card(); pl=QHBoxLayout(pdf); info=QLabel("فاکتور را می‌توانید مستقیم به PDF ذخیره کنید."); info.setWordWrap(True); pl.addWidget(info,1); b=QPushButton("📄 ذخیره فاکتور جاری به PDF"); b.clicked.connect(self.export_invoice_pdf); pl.addWidget(b); l.addWidget(pdf)
        backups=QHBoxLayout(); b=QPushButton("💾 تهیه نسخه پشتیبان"); b.clicked.connect(self.backup); backups.addWidget(b); b=QPushButton("♻️ بازیابی نسخه پشتیبان"); b.clicked.connect(self.restore_backup); backups.addWidget(b); backups.addStretch(); l.addLayout(backups)

        # تغییر رمز ورود برنامه
        password_card=Card(); password_form=QFormLayout(password_card)
        current_password=QLineEdit(); current_password.setEchoMode(QLineEdit.Password); current_password.setPlaceholderText("رمز فعلی")
        new_password=QLineEdit(); new_password.setEchoMode(QLineEdit.Password); new_password.setPlaceholderText("رمز جدید")
        confirm_password=QLineEdit(); confirm_password.setEchoMode(QLineEdit.Password); confirm_password.setPlaceholderText("تکرار رمز جدید")
        self.current_password_edit=current_password
        self.new_password_edit=new_password
        self.confirm_password_edit=confirm_password
        password_form.addRow("🔐 رمز فعلی:", current_password)
        password_form.addRow("رمز جدید:", new_password)
        password_form.addRow("تکرار رمز جدید:", confirm_password)
        change_password=QPushButton("🔑 تغییر رمز ورود")
        change_password.clicked.connect(self.change_app_password)
        password_form.addRow(change_password)
        password_hint=QLabel("رمز در دیتابیس به‌صورت رمزنگاری‌شده ذخیره می‌شود. پس از تغییر، فقط رمز جدید کار می‌کند.")
        password_hint.setStyleSheet(f"color:{MUTED};")
        password_form.addRow(password_hint)
        l.addWidget(password_card)

        l.addStretch(); self.stack.addWidget(page)

    def _refresh_secondary_backup_display(self):
        serial=str(self.db.get_setting("secondary_backup_volume_serial","") or "").strip()
        label=str(self.db.get_setting("secondary_backup_volume_label","") or "").strip()
        root=_find_mounted_volume_by_serial(serial) if serial else ""
        sub=str(self.db.get_setting("secondary_backup_subfolder","NeginBackup") or "NeginBackup")
        if not serial:
            self.secondary_backup_path_edit.setText("")
            self.secondary_backup_status_label.setText("⚪ فلش ثبت نشده")
        elif root:
            self.secondary_backup_path_edit.setText(f"{root}\\{sub} | {label or 'بدون نام'} | شناسه {serial}")
            self.secondary_backup_status_label.setText("🟢 فلش ثبت‌شده متصل است — بکاپ فقط روی همین فلش")
        else:
            self.secondary_backup_path_edit.setText("فلش ثبت‌شده متصل نیست")
            self.secondary_backup_status_label.setText("🔴 فلش ثبت‌شده جداست — بکاپ اصلی ادامه دارد")

    def choose_secondary_backup_path(self):
        path=QFileDialog.getExistingDirectory(self,"فلش موردنظر را انتخاب کنید","")
        if not path: return
        try:
            info=_get_windows_volume_info(path); root=info["root"]
            folder=os.path.join(root,"NeginBackup"); os.makedirs(folder,exist_ok=True)
            if not _dir_is_writable(folder): raise OSError("فلش قابل نوشتن نیست.")
            self.db.set_setting("secondary_backup_volume_serial",info["serial"])
            self.db.set_setting("secondary_backup_volume_label",info["label"])
            self.db.set_setting("secondary_backup_subfolder","NeginBackup")
            self._refresh_secondary_backup_display()
            QMessageBox.information(self,"فلش اختصاصی ثبت شد",
                f"فلش با موفقیت ثبت شد.\n\nشناسه ولوم: {info['serial']}\n\n"
                "از این پس برنامه همین فلش را می‌شناسد و بکاپ‌های خودکار فقط روی همین فلش ذخیره می‌شوند.\n"
                "اگر حرف درایو تغییر کند نیز برنامه فلش را با شناسه آن پیدا می‌کند.")
        except Exception as e:
            _log_error("register_backup_usb",e); QMessageBox.warning(self,"ثبت فلش",f"ثبت فلش انجام نشد:\n{e}")

    def save_secondary_backup_settings(self):
        new_password=self.secondary_backup_password_edit.text(); confirm=self.secondary_backup_confirm_edit.text()
        serial=str(self.db.get_setting("secondary_backup_volume_serial","") or "").strip()
        if not serial:
            QMessageBox.warning(self,"بکاپ فلش","ابتدا فلش را با دکمه «ثبت فلش اختصاصی» انتخاب کنید."); return
        if new_password:
            if len(new_password)<16:
                QMessageBox.warning(self,"امنیت بکاپ","رمز بکاپ را حداقل ۱۶ کاراکتر و ترجیحاً ۲۰ کاراکتر یا بیشتر انتخاب کنید."); return
            if new_password!=confirm:
                QMessageBox.warning(self,"امنیت بکاپ","رمز و تکرار رمز یکسان نیستند."); return
            try: self.db.set_setting("secondary_backup_password_dpapi",_b64e(_dpapi_protect(new_password.encode("utf-8"))))
            except Exception as e:
                _log_error("save_secondary_backup_password",e); QMessageBox.critical(self,"امنیت بکاپ",f"ذخیره امن رمز انجام نشد:\n{e}"); return
        elif not self.db.get_setting("secondary_backup_password_dpapi",""):
            QMessageBox.warning(self,"بکاپ فلش","برای فعال‌سازی بکاپ فلش باید یک رمز قوی تعیین کنید."); return
        self.secondary_backup_password_edit.clear(); self.secondary_backup_confirm_edit.clear(); self._refresh_secondary_backup_display()
        log_audit("secondary_backup_settings",f"volume_serial={serial}")
        QMessageBox.information(self,"بکاپ فلش","تنظیمات بکاپ فلش با موفقیت ذخیره شد.")

    def test_secondary_backup(self):
        if not self.db.get_setting("secondary_backup_volume_serial",""):
            QMessageBox.warning(self,"تست بکاپ","ابتدا فلش بکاپ را ثبت کنید."); return
        if not self._get_secondary_backup_path():
            QMessageBox.warning(self,"تست بکاپ","فلش ثبت‌شده در حال حاضر متصل نیست."); return
        temp=None
        try:
            stamp=datetime.now().strftime("%Y%m%d_%H%M%S"); temp=os.path.join(BACKUP_DIR,f"secondary_test_{stamp}.db")
            self.db.backup_to(temp); ok,_=self._verify_backup_file(temp)
            if not ok: raise RuntimeError("snapshot تست سالم نیست.")
            if not self._copy_to_secondary_backup(temp): raise RuntimeError("کپی رمزنگاری‌شده روی فلش انجام نشد.")
            QMessageBox.information(self,"تست بکاپ","تست موفق بود؛ فایل رمزنگاری‌شده روی فلش اختصاصی ساخته شد.")
        except Exception as e:
            _log_error("test_secondary_backup",e); QMessageBox.warning(self,"تست بکاپ",f"تست بکاپ انجام نشد:\n{e}")
        finally:
            if temp:
                try: os.remove(temp)
                except Exception: pass

    def save_settings(self):
        self.db.set_setting("shop_name",self.shop_edit.text().strip() or "حسابداری OMID PC")
        self.db.set_setting("instagram",self.insta_edit.text().strip())
        self.db.set_setting("phone",self.phone_edit.text().strip())
        self.db.set_setting("copies",self.copies_spin.value())
        self.app_settings=self.db.settings(); self.refresh_all(); QMessageBox.information(self,"تنظیمات","اطلاعات فروشگاه ذخیره شد و در فاکتورهای بعدی استفاده می‌شود.")

    def change_app_password(self):
        current = self.current_password_edit.text().strip()
        new_password = self.new_password_edit.text().strip()
        confirm = self.confirm_password_edit.text().strip()

        if not verify_app_password(current):
            QMessageBox.warning(self, "تغییر رمز", "رمز فعلی اشتباه است.")
            self.current_password_edit.setFocus()
            return
        if len(new_password) < 4:
            QMessageBox.warning(self, "تغییر رمز", "رمز جدید باید حداقل ۴ کاراکتر باشد.")
            self.new_password_edit.setFocus()
            return
        if new_password != confirm:
            QMessageBox.warning(self, "تغییر رمز", "رمز جدید و تکرار آن یکسان نیستند.")
            self.confirm_password_edit.clear()
            self.confirm_password_edit.setFocus()
            return
        try:
            self.db.set_setting("app_password", _hash_password(new_password))
            self.current_password_edit.clear()
            self.new_password_edit.clear()
            self.confirm_password_edit.clear()
            log_audit("change_app_password", "رمز ورود توسط کاربر تغییر کرد.")
            QMessageBox.information(self, "تغییر رمز", "رمز ورود با موفقیت تغییر کرد.")
        except Exception as e:
            _log_error("change_app_password", e)
            QMessageBox.critical(self, "خطا", f"تغییر رمز انجام نشد:\n{e}")

    def _decrypt_secondary_backup(self, path, password):
        with open(path, "rb") as f:
            blob=f.read()
        marker=b"NEGIN-ABZAR-BACKUP-V1\n"
        if not blob.startswith(marker):
            raise ValueError("ساختار فایل بکاپ رمزنگاری‌شده معتبر نیست.")
        rest=blob[len(marker):]
        header_raw, sep, ciphertext=rest.partition(b"\n\n")
        if not sep:
            raise ValueError("هدر فایل بکاپ ناقص است.")
        header=json.loads(header_raw.decode("utf-8"))
        if not password:
            raise ValueError("رمز بکاپ وارد نشده است.")
        salt=_b64d(header["salt"]); nonce=_b64d(header["nonce"]); aad=_b64d(header["aad"])
        kdf=PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt,
                       iterations=int(header.get("iterations", SECONDARY_BACKUP_PBKDF2_ITERATIONS)))
        key=kdf.derive(password.encode("utf-8"))
        return AESGCM(key).decrypt(nonce, ciphertext, aad)

    def restore_backup(self):
        path,_=QFileDialog.getOpenFileName(self,"انتخاب نسخه پشتیبان","","Database (*.db *.ngbak)")
        if not path or os.path.abspath(path)==os.path.abspath(DB_PATH): return
        temp_decrypted=None
        try:
            restore_path=path
            if path.lower().endswith(SECONDARY_BACKUP_EXTENSION):
                password, ok = QInputDialog.getText(self, "رمز بکاپ", "رمز بکاپ فلش را وارد کنید:", QLineEdit.Password)
                if not ok or not password:
                    return
                plaintext=self._decrypt_secondary_backup(path, password)
                fd,temp_decrypted=tempfile.mkstemp(prefix="negin_restore_", suffix=".db")
                os.close(fd)
                with open(temp_decrypted,"wb") as f:
                    f.write(plaintext)
                restore_path=temp_decrypted
            test=sqlite3.connect(restore_path); ok=test.execute("PRAGMA integrity_check").fetchone()[0]; test.close()
            if ok!="ok": raise ValueError("فایل پشتیبان سالم نیست.")
            if QMessageBox.question(self,"تأیید بازیابی","با بازیابی، اطلاعات فعلی برنامه با نسخه پشتیبان جایگزین می‌شود. ادامه می‌دهید؟")!=QMessageBox.Yes: return
            # قبل از جایگزینی دیتابیس فعلی، یک snapshot مستقل و قابل بررسی نگه می‌داریم.
            self._create_safety_backup("before_restore")
            safety = DB_PATH + ".pre_restore"
            try:
                self.db.con.execute("PRAGMA wal_checkpoint(TRUNCATE)")
            except Exception:
                pass
            try:
                self.db.con.close()
            except Exception:
                pass
            if os.path.exists(DB_PATH):
                shutil.copy2(DB_PATH, safety)
            remove_sqlite_sidecars(DB_PATH)
            shutil.copy2(restore_path, DB_PATH)
            remove_sqlite_sidecars(DB_PATH)
            self.db = Database()
            check = self.db.con.execute("PRAGMA integrity_check").fetchone()[0]
            if check != "ok":
                raise ValueError(f"دیتابیس بازیابی‌شده سالم نیست: {check}")
            self.app_settings=self.db.settings(); self.refresh_all()
            try:
                if os.path.exists(safety):
                    os.remove(safety)
            except Exception:
                pass
            log_audit("restore_backup", f"بازیابی موفق از فایل: {path}")
            QMessageBox.information(self,"بازیابی","نسخه پشتیبان با موفقیت بازیابی شد.")
        except Exception as e:
            _log_error("restore_backup", e)
            try:
                safety = DB_PATH + ".pre_restore"
                if os.path.exists(safety):
                    try:
                        self.db.con.close()
                    except Exception:
                        pass
                    remove_sqlite_sidecars(DB_PATH)
                    shutil.copy2(safety, DB_PATH)
                    remove_sqlite_sidecars(DB_PATH)
                    self.db = Database()
                    self.app_settings = self.db.settings()
                    self.refresh_all()
            except Exception as rollback_exc:
                _log_error("restore_backup:rollback_failed", rollback_exc)
            log_audit("restore_backup_failed", f"مسیر انتخابی: {path} | خطا: {e}")
            QMessageBox.critical(self,"خطا در بازیابی",str(e))
        finally:
            if temp_decrypted:
                try:
                    if os.path.exists(temp_decrypted):
                        os.remove(temp_decrypted)
                except Exception:
                    pass

    def refresh_printers(self):
        if not hasattr(self,"printer_combo"): return
        current=self.db.get_setting("printer","") or self.printer_combo.currentData()
        self.printer_combo.blockSignals(True)
        self.printer_combo.clear()
        printers=QPrinterInfo.availablePrinters(); default_name=QPrinterInfo.defaultPrinterName()
        if printers:
            for info in printers:
                name=info.printerName(); label=name+("  ★ پیش‌فرض" if name==default_name else "")
                self.printer_combo.addItem(label,name)
        else:
            self.printer_combo.addItem("هیچ چاپگر نصب‌شده‌ای پیدا نشد","")
        self.printer_combo.insertSeparator(self.printer_combo.count())
        self.printer_combo.addItem("📄 ذخیره به عنوان PDF و نمایش", "__PDF__")
        idx=self.printer_combo.findData(current if current else default_name)
        if idx>=0: self.printer_combo.setCurrentIndex(idx)
        self.printer_combo.blockSignals(False)

    def open_windows_printers(self):
        try: os.startfile("ms-settings:printers")
        except Exception:
            QMessageBox.information(self,"چاپگرها","برای نصب یا به‌روزرسانی درایور، از Settings > Bluetooth & devices > Printers & scanners ویندوز استفاده کنید.")

    def test_print(self):
        html = "<div dir='rtl' style='font-family:Tahoma;text-align:center'><h1>حسابداری OMID PC</h1><h2>چاپ آزمایشی</h2><p>اگر این متن چاپ شد، چاپگر و تنظیمات چاپ درست هستند.</p></div>"
        selected = self.printer_combo.currentData() if hasattr(self, "printer_combo") else None
        if selected == "__PDF__":
            path = os.path.join(tempfile.gettempdir(), "NeginAbzar_Test_%d.pdf" % int(time.time()*1000))
            printer=QPrinter(QPrinter.PrinterMode.HighResolution)
            printer.setOutputFormat(QPrinter.OutputFormat.PdfFormat)
            printer.setOutputFileName(path)
            self.configure_printer_page(printer)
            doc=QTextDocument(); doc.setHtml(html); doc.print_(printer)
            if not open_path(path):
                QMessageBox.warning(self,"PDF","فایل آزمایشی ساخته شد اما باز نشد.")
            else:
                QMessageBox.information(self,"چاپ آزمایشی","PDF آزمایشی باز شد.")
            return
        printer=QPrinter(QPrinter.PrinterMode.HighResolution); printer.setOutputFormat(QPrinter.OutputFormat.NativeFormat)
        if selected: printer.setPrinterName(selected)
        self.configure_printer_page(printer)
        dialog=QPrintDialog(printer,self); dialog.setWindowTitle("چاپ آزمایشی")
        if dialog.exec()!=QDialog.DialogCode.Accepted: return
        doc=QTextDocument(); doc.setHtml(html)
        doc.print_(printer); QMessageBox.information(self,"چاپ آزمایشی","برگه آزمایشی برای چاپگر ارسال شد.")

    def backup(self):
        default=f"negin_abzar_backup_{datetime.now().strftime('%Y%m%d_%H%M%S')}.db"
        path,_=QFileDialog.getSaveFileName(self,"ذخیره نسخه پشتیبان",default,"Database (*.db)")
        if path:
            try:
                if os.path.abspath(path)==os.path.abspath(DB_PATH): raise ValueError("مسیر پشتیبان نباید با دیتابیس اصلی یکی باشد.")
                self.db.backup_to(path)
                # بررسی سلامت فایل پشتیبان
                test=sqlite3.connect(path); ok=test.execute("PRAGMA integrity_check").fetchone()[0]; test.close()
                if ok!="ok": raise ValueError(f"بررسی سلامت پشتیبان ناموفق بود: {ok}")
                QMessageBox.information(self,"انجام شد","نسخه پشتیبان با موفقیت و با بررسی سلامت ذخیره شد.")
            except Exception as e:
                QMessageBox.critical(self,"خطا",str(e))

    def wrap_all_pages_in_scroll(self):
        # Every main section gets its own vertical/horizontal scrollbars.
        for i in range(self.stack.count()):
            page = self.stack.widget(i)
            if isinstance(page, QScrollArea):
                continue
            self.stack.removeWidget(page)
            scroll = QScrollArea()
            scroll.setWidgetResizable(True)
            scroll.setFrameShape(QFrame.NoFrame)
            scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarAlwaysOff)
            scroll.setVerticalScrollBarPolicy(Qt.ScrollBarAsNeeded)
            scroll.setWidget(page)
            self.stack.insertWidget(i, scroll)

    def refresh_all(self):
        if hasattr(self, "invoice_no_label") and not self.cart:
            try:
                iso = self._sync_invoice_date_from_field() if hasattr(self, "invoice_date_edit") else date.today().isoformat()
            except Exception:
                iso = date.today().isoformat()
                self.current_invoice_date = iso
                if hasattr(self, "invoice_date_edit"):
                    self.invoice_date_edit.setText(jalali_today())
            self.current_invoice_no = None
            nxt = self.db.next_invoice_no(iso)
            self.invoice_no_label.setText(f"شماره فاکتور {format_jalali_date(iso)}: {nxt:04d}")
        self.refresh_product_category_views()
        self.refresh_product_cards()
        if hasattr(self, "prod_table"):
            self.refresh_products_table()
        if hasattr(self, "inventory_table"):
            self.refresh_inventory_table()
        if hasattr(self, "customer_table"):
            self.refresh_customers_table()
        self.refresh_customer_combos()

        rows = self.db.con.execute("SELECT * FROM purchases ORDER BY id DESC").fetchall()
        self.purchase_table.setRowCount(0)
        for r in rows:
            i = self.purchase_table.rowCount()
            self.purchase_table.insertRow(i)
            for j, v in enumerate([
                r["id"], r["supplier"], money(r["total"]),
                self.db.con.execute("SELECT COUNT(*) FROM purchase_items WHERE purchase_id=?", (r["id"],)).fetchone()[0],
                r["notes"], format_jalali_date(r["created_at"]), r["status"] or "فعال"
            ]):
                self.purchase_table.setItem(i, j, center_item(v))

        if hasattr(self, "instagram_table"):
            self.refresh_instagram_table()

        rows = self.db.con.execute("SELECT * FROM expenses WHERE COALESCE(active,1)=1 ORDER BY id DESC").fetchall()
        self.expense_table.setRowCount(0)
        for r in rows:
            i = self.expense_table.rowCount()
            self.expense_table.insertRow(i)
            for j, v in enumerate([r["id"], r["title"], money(r["amount"]), r["notes"], format_jalali_date(r["created_at"])]):
                self.expense_table.setItem(i, j, center_item(v))

        if hasattr(self, "check_table"):
            self.refresh_checks_table()

        self.refresh_reports()
        if hasattr(self, "recipe_table"):
            self.refresh_recipes_table()


class LoginDialog(QDialog):
    """صفحه ورود ساده قبل از باز شدن برنامه."""

    def __init__(self):
        super().__init__()
        self.setWindowTitle("ورود به سیستم")
        self.setLayoutDirection(Qt.RightToLeft)
        self.setFixedSize(420, 280)
        self.setModal(True)
        self.setStyleSheet(f"""
            QDialog {{
                background: {BG};
                color: {TEXT};
                font-family: Tahoma;
            }}
            QLabel {{
                background: transparent;
                color: {TEXT};
            }}
            QLineEdit {{
                background: {PANEL_LIGHT};
                color: {TEXT};
                border: 1px solid {BORDER};
                border-radius: 12px;
                padding: 10px 12px;
                min-height: 28px;
                font-size: 15px;
            }}
            QLineEdit:focus {{
                border: 2px solid {ACCENT};
            }}
            QPushButton {{
                background: {PANEL_LIGHT};
                color: {TEXT};
                border: 1px solid {BORDER};
                border-radius: 12px;
                padding: 10px 18px;
                font-weight: 800;
                min-height: 36px;
            }}
            QPushButton:hover {{
                background: #4B9396;
            }}
            QPushButton#loginBtn {{
                background: {ACCENT};
                color: #123638;
            }}
        """)

        root = QVBoxLayout(self)
        root.setContentsMargins(28, 24, 28, 24)
        root.setSpacing(12)

        title = QLabel("🔒 ورود به نرم‌افزار")
        title.setAlignment(Qt.AlignCenter)
        title.setStyleSheet("font-size: 22px; font-weight: 900;")
        root.addWidget(title)

        subtitle = QLabel(APP_NAME)
        subtitle.setAlignment(Qt.AlignCenter)
        subtitle.setStyleSheet(f"color: {MUTED}; font-size: 13px;")
        root.addWidget(subtitle)

        root.addSpacing(8)

        form = QFormLayout()
        form.setSpacing(10)
        self.password_edit = QLineEdit()
        self.password_edit.setEchoMode(QLineEdit.Password)
        self.password_edit.setPlaceholderText("رمز عبور را وارد کنید")
        self.password_edit.returnPressed.connect(self.try_login)
        form.addRow("رمز عبور:", self.password_edit)
        root.addLayout(form)

        self.error_label = QLabel("")
        self.error_label.setAlignment(Qt.AlignCenter)
        self.error_label.setStyleSheet(f"color: {DANGER}; font-weight: 700;")
        if not _has_stored_app_password():
            self.error_label.setText(f"رمز موقت اولیه: {APP_PASSWORD}\nفوراً بعد از ورود آن را تغییر دهید.")
        root.addWidget(self.error_label)

        buttons = QHBoxLayout()
        cancel_btn = QPushButton("خروج")
        cancel_btn.clicked.connect(self.reject)
        login_btn = QPushButton("ورود")
        login_btn.setObjectName("loginBtn")
        login_btn.clicked.connect(self.try_login)
        buttons.addWidget(cancel_btn)
        buttons.addWidget(login_btn)
        root.addLayout(buttons)

        self.password_edit.setFocus()

        # محدودیت تلاش ورود: بعد از چند تلاش ناموفق پیاپی، ورود برای چند ثانیه قفل می‌شود
        # تا حدس‌زدن مکرر رمز عبور (brute-force محلی) سخت‌تر شود.
        self.fail_count = 0
        self._lock_remaining = 0
        self.lock_timer = QTimer(self)
        self.lock_timer.setInterval(1000)
        self.lock_timer.timeout.connect(self._tick_lock)
        self._login_btn = login_btn

    def _tick_lock(self):
        self._lock_remaining -= 1
        if self._lock_remaining <= 0:
            self.lock_timer.stop()
            self.error_label.setText("")
            self.password_edit.setEnabled(True)
            self._login_btn.setEnabled(True)
            self.password_edit.setFocus()
        else:
            self.error_label.setText(f"تلاش‌های ناموفق زیاد؛ {self._lock_remaining} ثانیه صبر کنید.")

    def try_login(self):
        if self._lock_remaining > 0:
            return
        entered = self.password_edit.text().strip()
        if entered and verify_app_password(entered):
            self.fail_count = 0
            log_audit("login_success")
            self.accept()
            return
        self.fail_count += 1
        log_audit("login_failed", f"attempt_no={self.fail_count}")
        self.password_edit.clear()
        if self.fail_count >= LOGIN_MAX_ATTEMPTS_BEFORE_LOCK:
            self._lock_remaining = LOGIN_LOCK_SECONDS
            self.fail_count = 0
            self.password_edit.setEnabled(False)
            self._login_btn.setEnabled(False)
            self.error_label.setText(f"تلاش‌های ناموفق زیاد؛ {self._lock_remaining} ثانیه صبر کنید.")
            self.lock_timer.start()
        else:
            if not _has_stored_app_password():
                self.error_label.setText(
                    f"رمز عبور اشتباه است.\nرمز موقت اولیه: {APP_PASSWORD}\n"
                    "پس از ورود، آن را تغییر دهید."
                )
            else:
                self.error_label.setText("رمز عبور اشتباه است.")
            self.password_edit.setFocus()


class ForceChangePasswordDialog(QDialog):
    """بعد از ورود با رمز پیش‌فرض کارخانه، تغییر رمز را اجباری می‌کند.

    این دیالوگ عمداً راهی برای رد شدن (Cancel/Esc) ندارد تا یک نصب تازه با رمز
    شناخته‌شدهٔ پیش‌فرض در بلندمدت باز نماند.
    """

    def __init__(self):
        super().__init__()
        self.setWindowTitle("تعیین رمز عبور جدید")
        self.setLayoutDirection(Qt.RightToLeft)
        self.setFixedSize(420, 320)
        self.setModal(True)
        self.setStyleSheet(f"""
            QDialog {{ background: {BG}; color: {TEXT}; font-family: Tahoma; }}
            QLabel {{ background: transparent; color: {TEXT}; }}
            QLineEdit {{
                background: {PANEL_LIGHT}; color: {TEXT}; border: 1px solid {BORDER};
                border-radius: 12px; padding: 10px 12px; min-height: 28px; font-size: 15px;
            }}
            QLineEdit:focus {{ border: 2px solid {ACCENT}; }}
            QPushButton {{
                background: {ACCENT}; color: #123638; border: 1px solid {BORDER};
                border-radius: 12px; padding: 10px 18px; font-weight: 800; min-height: 36px;
            }}
            QPushButton:hover {{ background: #4B9396; }}
        """)
        root = QVBoxLayout(self)
        root.setContentsMargins(28, 24, 28, 24)
        root.setSpacing(12)

        title = QLabel("⚠️ رمز عبور هنوز پیش‌فرض کارخانه است")
        title.setAlignment(Qt.AlignCenter)
        title.setWordWrap(True)
        title.setStyleSheet("font-size: 16px; font-weight: 900;")
        root.addWidget(title)

        info = QLabel("برای امنیت برنامه، قبل از ادامه باید یک رمز عبور تازه تعیین کنید.")
        info.setAlignment(Qt.AlignCenter)
        info.setWordWrap(True)
        info.setStyleSheet(f"color: {MUTED}; font-size: 12px;")
        root.addWidget(info)

        form = QFormLayout()
        form.setSpacing(10)
        self.new_edit = QLineEdit(); self.new_edit.setEchoMode(QLineEdit.Password)
        self.confirm_edit = QLineEdit(); self.confirm_edit.setEchoMode(QLineEdit.Password)
        self.confirm_edit.returnPressed.connect(self.try_set)
        form.addRow("رمز جدید:", self.new_edit)
        form.addRow("تکرار رمز:", self.confirm_edit)
        root.addLayout(form)

        self.error_label = QLabel("")
        self.error_label.setAlignment(Qt.AlignCenter)
        self.error_label.setWordWrap(True)
        self.error_label.setStyleSheet(f"color: {DANGER}; font-weight: 700;")
        root.addWidget(self.error_label)

        ok_btn = QPushButton("تنظیم رمز و ادامه")
        ok_btn.clicked.connect(self.try_set)
        root.addWidget(ok_btn)
        self.new_edit.setFocus()

    def try_set(self):
        new_password = self.new_edit.text().strip()
        confirm = self.confirm_edit.text().strip()
        if len(new_password) < 4:
            self.error_label.setText("رمز جدید باید حداقل ۴ کاراکتر باشد.")
            return
        if new_password == APP_PASSWORD:
            self.error_label.setText("رمز جدید نباید همان رمز پیش‌فرض کارخانه باشد.")
            return
        if new_password != confirm:
            self.error_label.setText("رمز جدید و تکرار آن یکسان نیستند.")
            self.confirm_edit.clear()
            return
        if not set_app_password(new_password):
            self.error_label.setText("تغییر رمز ذخیره نشد؛ دوباره تلاش کنید.")
            return
        log_audit("forced_password_change", "رمز پیش‌فرض کارخانه در اولین ورود تغییر کرد.")
        self.accept()

    def closeEvent(self, event):
        # این دیالوگ اجباری است؛ بستن پنجره معادل رد کردن است، نه پذیرفتن.
        event.ignore()
        self.reject()

    def keyPressEvent(self, event):
        if event.key() == Qt.Key_Escape:
            event.ignore()
            return
        super().keyPressEvent(event)


def main():
    try:
        return _main_impl()
    except Exception as exc:
        try:
            _log_error("FATAL_STARTUP", exc)
        except Exception:
            pass
        try:
            QMessageBox.critical(
                None,
                "خطای اجرای حسابداری OMID PC",
                "برنامه نتوانست اجرا شود.\n\n"
                f"جزئیات: {exc}\n\n"
                f"گزارش خطا در پوشه داده برنامه ذخیره شد.\n{DATA_DIR or os.path.expanduser('~')}"
            )
        except Exception:
            pass
        return 1


def _main_impl():
    app = QApplication(sys.argv)
    app.setApplicationName(APP_NAME)
    if not ensure_license():
        sys.exit(0)
    lock = QLockFile(LOCK_PATH or os.path.join(DATA_DIR or program_dir(), "negin_abzar.lock"))
    lock.setStaleLockTime(120000)
    if not lock.tryLock(100):
        QMessageBox.warning(
            None,
            "برنامه باز است",
            "نسخه دیگری از نرم‌افزار در حال اجرا است.\n"
            "برای جلوگیری از ثبت دو فاکتور همزمان، ابتدا پنجره قبلی را ببندید."
        )
        sys.exit(0)
    app._instance_lock = lock
    families = QFontDatabase.families()
    for font in ["Vazirmatn", "IRANSans", "Tahoma"]:
        if font in families:
            app.setFont(QFont(font, 10))
            break

    login = LoginDialog()
    if login.exec() != QDialog.Accepted:
        sys.exit(0)

    # اگر رمز فعال هنوز همان رمز پیش‌فرض کارخانه است، قبل از باز شدن برنامه تغییرش را اجباری می‌کنیم.
    if is_using_default_password():
        force_dlg = ForceChangePasswordDialog()
        while force_dlg.exec() != QDialog.Accepted:
            # کاربر اجازه ندارد این مرحله را رد کند؛ دیالوگ دوباره نمایش داده می‌شود.
            force_dlg = ForceChangePasswordDialog()

    w = Main()
    w.show()
    sys.exit(app.exec())


if __name__ == "__main__":
    sys.exit(main() or 0)