@echo off
setlocal
cd /d "%~dp0"

echo ===============================================================
echo OMID PC - License Manager Build
echo ===============================================================
where python >nul 2>&1
if errorlevel 1 (
  echo ERROR: Python not found in PATH.
  pause
  exit /b 1
)

python -m pip install -U nuitka ordered-set zstandard cryptography
if errorlevel 1 (
  echo ERROR: Build requirements failed.
  pause
  exit /b 1
)

if exist "build_license_manager" rmdir /s /q "build_license_manager"
mkdir "build_license_manager"

set ICON_ARG=
if exist "omidpc.ico" set ICON_ARG=--windows-icon-from-ico="omidpc.ico"

python -m nuitka ^
  --standalone ^
  --enable-plugin=tk-inter ^
  --windows-console-mode=disable ^
  %ICON_ARG% ^
  --assume-yes-for-downloads ^
  --output-dir=build_license_manager ^
  --output-filename="OMIDPC_License_Manager.exe" ^
  "license_admin.py"
if errorlevel 1 (
  echo LICENSE MANAGER BUILD FAILED
  pause
  exit /b 1
)

echo.
echo BUILD SUCCESSFUL
echo EXE folder: build_license_manager\license_admin.dist
echo Run OMIDPC_License_Manager.exe in that folder.
pause
