@echo off
setlocal enabledelayedexpansion

echo ==========================================
echo   Network Scanner Desktop - Build Script
echo ==========================================
echo.

:: Version check
if not exist VERSION (
    echo 1.0.0 > VERSION
)
set /p VERSION=<VERSION
echo Project Version: %VERSION%

:: Check for Go
go version >nul 2>&1
if %errorlevel% neq 0 (
    echo [ERROR] Go is not installed or not in PATH.
    pause
    exit /b 1
)

:: Build commands
echo.
echo [1/2] Tidying dependencies...
go mod tidy

echo [2/2] Compiling Desktop Application...
:: -H windowsgui hides the console window when running the app
go build -ldflags="-H windowsgui -s -w" -o scanner-desktop.exe ./cmd/desktop

if %errorlevel% equ 0 (
    echo.
    echo [SUCCESS] Build completed: scanner-desktop.exe
    echo.
    set /p RUN=Do you want to run it now? (y/n): 
    if /i "!RUN!"=="y" (
        start scanner-desktop.exe
    )
) else (
    echo.
    echo [ERROR] Build failed.
)

pause
