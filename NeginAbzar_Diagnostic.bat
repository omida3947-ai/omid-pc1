@echo off
setlocal
cd /d "%~dp0"
title OMID PC - Diagnostic
set PYTHONFAULTHANDLER=1
echo ===============================================
echo OMID PC 5.5.4 - Diagnostic
echo ===============================================
echo.
if not exist "OMIDPC_Accounting.exe" (
  echo ERROR: OMIDPC_Accounting.exe not found in this folder.
  pause
  exit /b 1
)
echo Starting the installed executable...
echo If the program closes, the startup log should be here:
echo %LOCALAPPDATA%\OMIDPCAccounting\negin_abzar_error.log
echo.
"OMIDPC_Accounting.exe"
echo.
echo Process exit code: %ERRORLEVEL%
echo.
echo Check the startup/error log above if the window did not open.
pause
