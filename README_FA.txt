OMID PC — Accounting / Backup Pro / License Setup

1) فایل build_release.bat را روی سیستم توسعه اجرا کنید. این فایل وابستگی‌های Nuitka، PySide6 و cryptography را نصب می‌کند.
2) بعد از BUILD SUCCESSFUL، فایل NeginAbzar_Setup.iss را با Inno Setup کامپایل کنید.
3) Setup ساخته‌شده را روی سیستم مقصد نصب کنید.
4) دیتابیس داخل Setup نیست؛ سیستم مقصد دیتابیس تازه در %LOCALAPPDATA%\OMIDPCAccounting می‌سازد.
5) در اجرای اول، Machine ID نمایش داده می‌شود. فایل لایسنس امضاشده را از مدیر دریافت و فعال کنید.
6) کلید خصوصی لایسنس هرگز نباید داخل این بسته یا Setup قرار گیرد.
7) اگر برنامه از میانبر اجرا نشد، از Start Menu گزینه «ابزار عیب‌یابی OMID PC» را اجرا کنید.
8) برای ساخت کلید و صدور لایسنس، فایل license_admin.py فقط روی سیستم مدیر اجرا شود.
9) یک‌بار روی سیستم مدیر اجرا کنید: python license_admin.py init. کلید عمومی را در کد اصلی به‌صورت public key قرار دهید.
10) برای اجرای مستقیم سورس اصلی: python negin_abzar_v5.5.4_BACKUP_PRO.py.
11) برای صدور لایسنس: python license_admin.py issue --machine-id MACHINE-ID --days 365 --output negin_license.json.

این بسته شامل نسخه Backup Pro با بکاپ‌های دوره‌ای، بکاپ روزانه/هفتگی و Safety Backup قبل از Restore است.
