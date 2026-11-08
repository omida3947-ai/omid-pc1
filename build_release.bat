@echo off
setlocal
cd /d "%~dp0"

echo ===============================================================
echo OMID PC - Accounting System - Build
echo ===============================================================
where python >nul 2>&1
if errorlevel 1 (
  echo ERROR: Python not found in PATH.
  pause
  exit /b 1
)
python --version
python -m pip install -U nuitka ordered-set zstandard cryptography pefile PySide6
if errorlevel 1 (
  echo ERROR: Build requirements failed.
  pause
  exit /b 1
)
if exist "build_release" rmdir /s /q "build_release"
mkdir "build_release"

set ICON_ARG=
if exist "omidpc.ico" set ICON_ARG=--windows-icon-from-ico="omidpc.ico"

echo.
echo [1/2] Building app executable...
python -m nuitka ^
  --standalone ^
  --enable-plugin=pyside6 ^
  --experimental=force-dependencies-pefile ^
  --windows-console-mode=force ^
  %ICON_ARG% ^
  --assume-yes-for-downloads ^
  --output-dir=build_release ^
  --output-filename="OMIDPC_Accounting.exe" ^
  "negin_abzar_v5.5.4_BACKUP_PRO.py"
if errorlevel 1 (
  echo ENGINE BUILD FAILED
  pause
  exit /b 1
)

echo.
echo [2/2] Building silent launcher...
python -m nuitka ^
  --onefile ^
  --windows-console-mode=disable ^
  %ICON_ARG% ^
  --assume-yes-for-downloads ^
  --output-dir=build_release ^
  --output-filename="OMIDPCLauncher.exe" ^
  "NeginAbzarLauncher.py"
if errorlevel 1 (
  echo LAUNCHER BUILD FAILED
  pause
  exit /b 1
)

if exist "build_release\negin_abzar_v5.5.4_BACKUP_PRO.dist\OMIDPCLauncher.exe" (
  del /f /q "build_release\negin_abzar_v5.5.4_BACKUP_PRO.dist\OMIDPCLauncher.exe" >nul
)
copy /y "build_release\OMIDPCLauncher.exe" "build_release\negin_abzar_v5.5.4_BACKUP_PRO.dist\OMIDPCLauncher.exe" >nul
if errorlevel 1 (
  echo ERROR: Could not copy launcher.
  pause
  exit /b 1
)

echo.
echo BUILD SUCCESSFUL
echo Test OMIDPCLauncher.exe inside the dist folder.
where ISCC >nul 2>&1
if not errorlevel 1 (
  echo.
  echo Compiling installer with Inno Setup...
  ISCC "NeginAbzar_Setup.iss"
  if errorlevel 1 (
    echo INSTALLER BUILD FAILED
    pause
    exit /b 1
  )
  echo Installer created in the release folder.
) else (
  echo Inno Setup compiler not found. Compile NeginAbzar_Setup.iss after installing Inno Setup.
)

echo.
pause
