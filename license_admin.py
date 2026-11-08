"""Private license administration tool for OMID PC Accounting.

Keep the generated private key outside this project and never ship it.
Examples:
  python license_admin.py init
  python license_admin.py issue --machine-id XXXX-XXXX --days 365 --output customer_license.json
  python license_admin.py issue --machine-id XXXX-XXXX --perpetual --output customer_license.json
"""
import argparse
import base64
import json
import os
import re
import tkinter as tk
from datetime import datetime, timedelta, timezone
from pathlib import Path
from tkinter import filedialog, messagebox, simpledialog, ttk

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

PRODUCT = "NeginAbzarIsfahan"
SCHEMA = 1
KEY_DIR = Path(os.environ.get("NEGIN_LICENSE_KEY_DIR", Path.home() / "OMIDPCLicenseKeys"))
PRIVATE_KEY_PATH = KEY_DIR / "license_private_key.pem"
PUBLIC_KEY_PATH = KEY_DIR / "license_public_key.pem"


def normalize_machine_id(value):
    """Normalize copied machine IDs so hyphens and spaces do not change the ID."""
    return re.sub(r"[^0-9A-F]", "", str(value or "").upper())


def b64e(value):
    return base64.urlsafe_b64encode(value).decode("ascii").rstrip("=")


def canonical_json(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")


def load_private_key(password=None):
    if not PRIVATE_KEY_PATH.is_file():
        raise SystemExit("Private key not found. Run: python license_admin.py init")
    if password is None:
        password = input("Private key password: ")
    key_data = PRIVATE_KEY_PATH.read_bytes()
    return serialization.load_pem_private_key(key_data, password=password.encode("utf-8"))


def init_keys():
    if PRIVATE_KEY_PATH.exists():
        raise SystemExit(f"Key already exists: {PRIVATE_KEY_PATH}")
    KEY_DIR.mkdir(parents=True, exist_ok=True)
    password = input("Create private key password: ")
    confirm = input("Confirm private key password: ")
    if not password or password != confirm:
        raise SystemExit("Passwords are empty or do not match.")
    private_key = Ed25519PrivateKey.generate()
    PRIVATE_KEY_PATH.write_bytes(
        private_key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.BestAvailableEncryption(password.encode("utf-8")),
        )
    )
    PUBLIC_KEY_PATH.write_bytes(
        private_key.public_key().public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
    )
    try:
        os.chmod(PRIVATE_KEY_PATH, 0o600)
    except OSError:
        pass
    print(f"Private key: {PRIVATE_KEY_PATH}")
    print(f"Public key:  {PUBLIC_KEY_PATH}")
    print("Copy the public PEM into LICENSE_PUBLIC_KEY_PEM in the application source.")


def issue_license(machine_id, output, days=None, perpetual=False, password=None):
    machine_id = normalize_machine_id(machine_id)
    if not machine_id:
        raise SystemExit("machine-id cannot be empty")
    if not perpetual and (days is None or days < 1):
        raise SystemExit("Use --days N or --perpetual")
    private_key = load_private_key(password=password)
    now = datetime.now(timezone.utc).replace(microsecond=0)
    payload = {
        "schema": SCHEMA,
        "product": PRODUCT,
        "machine_id": machine_id,
        "issued_at": now.isoformat().replace("+00:00", "Z"),
        "expires_at": "" if perpetual else (now + timedelta(days=days)).isoformat().replace("+00:00", "Z"),
    }
    payload_bytes = canonical_json(payload)
    document = {"payload": b64e(payload_bytes), "signature": b64e(private_key.sign(payload_bytes))}
    output_path = Path(output).expanduser().resolve()
    output_path.write_text(json.dumps(document, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(f"License written to: {output_path}")
    print(f"Machine ID: {machine_id}")


def open_gui():
    root = tk.Tk()
    root.title("OMID PC • مدیریت لایسنس")
    root.geometry("680x520")
    root.minsize(640, 500)
    root.configure(bg="#24113f")

    icon_path = Path(__file__).resolve().parent / "omidpc.ico"
    if icon_path.exists():
        try:
            root.iconbitmap(str(icon_path))
        except Exception:
            pass

    style = ttk.Style(root)
    style.theme_use("clam")
    style.configure("TFrame", background="#24113f")
    style.configure("Card.TFrame", background="#ffffff", relief="flat")
    style.configure("Subhead.TLabel", background="#ffffff", foreground="#54258a", font=("Tahoma", 11, "bold"))
    style.configure("Field.TLabel", background="#ffffff", foreground="#3b2857", font=("Tahoma", 10))
    style.configure("Info.TLabel", background="#ffffff", foreground="#78658f", font=("Tahoma", 9))
    style.configure("TEntry", fieldbackground="#ffffff", foreground="#1f2d3d", borderwidth=1)
    style.map("TEntry", fieldbackground=[("readonly", "#ffffff")])
    style.configure("Accent.TButton", background="#7b2cbf", foreground="#ffffff", font=("Tahoma", 10, "bold"))
    style.map("Accent.TButton", background=[("active", "#5a189a")], foreground=[("active", "#ffffff")])
    style.configure("Secondary.TButton", background="#f0e6ff", foreground="#54258a", font=("Tahoma", 10, "bold"))
    style.map("Secondary.TButton", background=[("active", "#dfc8ff")], foreground=[("active", "#54258a")])

    header = tk.Frame(root, bg="#3c096c", height=124)
    header.pack(fill="x")
    header.pack_propagate(False)

    logo_badge = tk.Frame(header, bg="#7b2cbf", width=62, height=62)
    logo_badge.place(relx=0.5, rely=0.32, anchor="center")
    logo_badge.pack_propagate(False)
    logo_mark = tk.Label(logo_badge, text="O", bg="#7b2cbf", fg="#ffffff", font=("Tahoma", 31, "bold"))
    logo_mark.place(relx=0.5, rely=0.48, anchor="center")
    logo = tk.Label(header, text="OMID PC", bg="#3c096c", fg="#ffffff", font=("Tahoma", 24, "bold"), justify="center")
    logo.place(relx=0.5, rely=0.62, anchor="center")
    subtitle = tk.Label(header, text="مدیریت و صدور لایسنس", bg="#3c096c", fg="#e9d8ff", font=("Tahoma", 10), justify="center")
    subtitle.place(relx=0.5, rely=0.88, anchor="center")

    def choose_output():
        path = filedialog.asksaveasfilename(
            title="ذخیره فایل لایسنس مشتری",
            defaultextension=".json",
            filetypes=[("فایل‌های JSON", "*.json"), ("همهٔ فایل‌ها", "*.*")],
            initialfile="customer_license.json",
        )
        if path:
            output_var.set(path)

    def paste_machine_id():
        try:
            machine_id_var.set(root.clipboard_get().strip())
            machine_entry.focus_set()
        except tk.TclError:
            messagebox.showwarning("جایگذاری متن", "متنی در کلیپ‌بورد پیدا نشد.")

    def generate():
        machine_id = machine_id_var.get().strip()
        output_path = output_var.get().strip()
        if not machine_id:
            messagebox.showerror("شناسه دستگاه", "لطفاً شناسه دستگاه مشتری را وارد کنید.")
            return
        if not output_path:
            messagebox.showerror("مسیر خروجی", "لطفاً مسیر ذخیره فایل لایسنس را انتخاب کنید.")
            return
        try:
            days = int(days_var.get()) if not perpetual_var.get() else None
            password = simpledialog.askstring("رمز کلید خصوصی", "رمز کلید خصوصی را وارد کنید:", show="*")
            if password is None:
                return
            issue_license(machine_id, output_path, days=days, perpetual=perpetual_var.get(), password=password)
            messagebox.showinfo("ثبت لایسنس", f"فایل لایسنس ذخیره شد:\n{output_path}")
        except Exception as exc:
            messagebox.showerror("خطا در ساخت لایسنس", str(exc))

    main = ttk.Frame(root, padding=20)
    main.pack(fill="both", expand=True)

    card = ttk.Frame(main, padding=18, style="Card.TFrame")
    card.pack(fill="both", expand=True)

    section_title = ttk.Label(card, text="اطلاعات دستگاه مشتری", style="Subhead.TLabel")
    section_title.grid(row=0, column=0, columnspan=3, sticky="w", pady=(0, 10))

    ttk.Label(card, text="شناسه دستگاه مشتری:", style="Field.TLabel").grid(row=1, column=0, sticky="w", padx=(0, 10), pady=8)
    machine_id_var = tk.StringVar()
    machine_entry = ttk.Entry(card, textvariable=machine_id_var, width=36)
    machine_entry.grid(row=1, column=1, sticky="ew", pady=8)
    paste_btn = ttk.Button(card, text="جایگذاری", command=paste_machine_id, style="Secondary.TButton")
    paste_btn.grid(row=1, column=2, sticky="w", padx=(18, 0), pady=8)

    ttk.Label(card, text="تعداد روز اعتبار:", style="Field.TLabel").grid(row=2, column=0, sticky="w", padx=(0, 10), pady=8)
    days_var = tk.StringVar(value="365")
    days_entry = ttk.Entry(card, textvariable=days_var, width=18)
    days_entry.grid(row=2, column=1, sticky="w", pady=8)

    perpetual_var = tk.BooleanVar(value=False)
    perpetual_box = ttk.Checkbutton(card, text="بدون تاریخ انقضا", variable=perpetual_var)
    perpetual_box.grid(row=2, column=2, sticky="w", padx=(18, 0), pady=8)

    ttk.Label(card, text="مسیر خروجی:", style="Field.TLabel").grid(row=3, column=0, sticky="w", padx=(0, 10), pady=8)
    output_var = tk.StringVar(value="customer_license.json")
    output_entry = ttk.Entry(card, textvariable=output_var, width=42)
    output_entry.grid(row=3, column=1, sticky="ew", pady=8)
    browse_btn = ttk.Button(card, text="انتخاب", command=choose_output, style="Secondary.TButton")
    browse_btn.grid(row=3, column=2, sticky="w", padx=(18, 0), pady=8)

    info_line = ttk.Label(card, text="نکته: شناسه دستگاه باید دقیقاً با دستگاه مشتری هماهنگ باشد.", style="Info.TLabel")
    info_line.grid(row=4, column=0, columnspan=3, sticky="w", pady=(12, 0))

    action_row = tk.Frame(card, bg="#ffffff")
    action_row.grid(row=5, column=0, columnspan=3, sticky="ew", pady=(20, 4))
    action_row.columnconfigure(0, weight=1)
    action_row.columnconfigure(1, weight=0)

    spacer = tk.Label(action_row, bg="#ffffff")
    spacer.grid(row=0, column=0, sticky="ew")
    generate_btn = ttk.Button(action_row, text="ایجاد لایسنس", command=generate, style="Accent.TButton", width=18)
    generate_btn.grid(row=0, column=1, sticky="e")

    card.columnconfigure(1, weight=1)

    root.mainloop()


def main():
    parser = argparse.ArgumentParser(description="Issue OMID PC offline licenses")
    sub = parser.add_subparsers(dest="command")
    sub.add_parser("init", help="Create the protected signing key pair")
    issue = sub.add_parser("issue", help="Issue a license for one machine")
    issue.add_argument("--machine-id", required=True)
    issue.add_argument("--output", required=True)
    duration = issue.add_mutually_exclusive_group(required=True)
    duration.add_argument("--days", type=int)
    duration.add_argument("--perpetual", action="store_true")
    args = parser.parse_args()

    if args.command == "init":
        init_keys()
        return
    if args.command == "issue":
        issue_license(args.machine_id, args.output, args.days, args.perpetual)
        return

    open_gui()


if __name__ == "__main__":
    main()
