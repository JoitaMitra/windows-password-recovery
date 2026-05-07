@echo off
REM Load Visual Studio build environment
call "C:\Program Files\Microsoft Visual Studio\18\Community\Common7\Tools\VsDevCmd.bat"

REM Change directory to the solution folder
cd /d "%~dp0"

REM Build Release version
echo Building Release version...
msbuild PassRecCredProv.sln /p:Configuration=Release /p:Platform=x64 /m
if errorlevel 1 (
	echo Release build failed!
	exit /b 1
)

REM Copy Release DLL to installer payload
echo Copying Release DLL...
copy /Y "x64\Release\PasswordRecovery.dll" "..\installer\payload\PasswordRecovery.dll"

REM Build DebugLogging version
echo Building DebugLogging version...
msbuild PassRecCredProv.sln /p:Configuration=DebugLogging /p:Platform=x64 /m
if errorlevel 1 (
	echo DebugLogging build failed!
	exit /b 1
)

REM Copy DebugLogging DLL to installer payload
echo Copying DebugLogging DLL...
copy /Y "x64\DebugLogging\PasswordRecovery_Debug.dll" "..\installer\payload\PasswordRecovery_Debug.dll"

echo All builds completed successfully.
pause