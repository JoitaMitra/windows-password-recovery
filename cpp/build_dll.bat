@echo off
REM Change directory to the solution folder
cd /d "%~dp0"

REM Build Release version
echo Building Release version...
msbuild PassRecCredProv.sln /p:Configuration=Release /p:Platform=x64 /m
if errorlevel 1 (
	echo Release build failed!
	exit /b 1
)

REM Build DebugLogging version
echo Building DebugLogging version...
msbuild PassRecCredProv.sln /p:Configuration=DebugLogging /p:Platform=x64 /m
if errorlevel 1 (
	echo DebugLogging build failed!
	exit /b 1
)

echo All builds completed successfully.
pause