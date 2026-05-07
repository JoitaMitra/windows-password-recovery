@echo off

set curDir=%~dp0
cd /d %curDir%

echo Building installer...
echo.

"C:\Program Files (x86)\Inno Setup 6\ISCC.exe" "%curDir%setup.iss"

echo.
echo Build complete.
pause