@echo off
setlocal
set BASE=%~dp0

if exist "%BASE%lockbit-wizard.exe" (
  "%BASE%lockbit-wizard.exe"
  exit /b %errorlevel%
)

if exist "%BASE%lockbit-wizard.py" (
  where py >nul 2>&1
  if %errorlevel%==0 (
    py -3 "%BASE%lockbit-wizard.py"
    exit /b %errorlevel%
  )
  where python >nul 2>&1
  if %errorlevel%==0 (
    python "%BASE%lockbit-wizard.py"
    exit /b %errorlevel%
  )
)

echo [ERROR] lockbit-wizard executable or python script not found.
exit /b 1
