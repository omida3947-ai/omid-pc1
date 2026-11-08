import os, sys, subprocess

BASE = os.path.dirname(os.path.abspath(sys.argv[0]))
EXE = os.path.join(BASE, 'OMIDPC_Accounting.exe')
if not os.path.isfile(EXE):
    import tkinter as tk
    from tkinter import messagebox
    root = tk.Tk(); root.withdraw()
    messagebox.showerror('OMID PC', 'فایل اصلی برنامه پیدا نشد.\n\n' + EXE)
    raise SystemExit(1)

try:
    subprocess.Popen([EXE], cwd=BASE, creationflags=subprocess.CREATE_NO_WINDOW)
except Exception as exc:
    import tkinter as tk
    from tkinter import messagebox
    root = tk.Tk(); root.withdraw()
    messagebox.showerror('خطای اجرای OMID PC', str(exc))
    raise SystemExit(1)
