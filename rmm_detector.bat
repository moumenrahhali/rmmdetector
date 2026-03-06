@echo off
setlocal EnableDelayedExpansion

:: ============================================================
::  RMM Detector - Remote Monitoring & Management Scanner
::  Version 1.0
::  Usage:
::    rmm_detector.bat           - Standard scan
::    rmm_detector.bat /silent   - Silent mode (findings only)
::    rmm_detector.bat /json     - JSON output
::    rmm_detector.bat /help     - Show help
:: ============================================================

set "SCRIPT_DIR=%~dp0"
set "PS_SCRIPT=%SCRIPT_DIR%detector.ps1"
set "OUTPUT_FILE=%SCRIPT_DIR%rmm_report.txt"
set "MODE="
set "PS_ARGS="

:: Parse arguments
:parse_args
if "%~1"=="" goto :main
set "ARG=%~1"
if /I "!ARG!"=="/silent" (
    set "MODE=silent"
    set "PS_ARGS=!PS_ARGS! -Silent"
    shift
    goto :parse_args
)
if /I "!ARG!"=="/json" (
    set "MODE=json"
    set "PS_ARGS=!PS_ARGS! -Json"
    shift
    goto :parse_args
)
if /I "!ARG!"=="/output" (
    set "OUTPUT_FILE=%~2"
    set "PS_ARGS=!PS_ARGS! -OutputFile "%~2""
    shift
    shift
    goto :parse_args
)
if /I "!ARG!"=="/help" goto :show_help
shift
goto :parse_args

:show_help
echo.
echo   ██████╗ ███╗   ███╗███╗   ███╗
echo   ██╔══██╗████╗ ████║████╗ ████║
echo   ██████╔╝██╔████╔██║██╔████╔██║
echo   ██╔═══╝ ██║╚██╔╝██║██║╚██╔╝██║
echo   ██║     ██║ ╚═╝ ██║██║ ╚═╝ ██║
echo   ╚═╝     ╚═╝     ╚═╝╚═╝     ╚═╝
echo.
echo   RMM DETECTOR - Remote Monitoring Detection Tool
echo.
echo Usage:
echo   rmm_detector.bat               Standard scan with full output
echo   rmm_detector.bat /silent       Silent mode - only show findings
echo   rmm_detector.bat /json         Output results in JSON format
echo   rmm_detector.bat /output PATH  Save report to custom path
echo   rmm_detector.bat /help         Show this help
echo.
echo The tool scans for:
echo   - Running RMM agent processes
echo   - Installed RMM software (registry)
echo   - RMM-related Windows services
echo   - Startup registry entries
echo   - Scheduled tasks
echo   - Network connections on RMM ports
echo   - Installation directories
echo.
echo Note: Run as Administrator for complete results.
echo This tool is for DETECTION ONLY - it will not remove software.
echo.
goto :eof

:main

:: Check if PowerShell script exists
if not exist "%PS_SCRIPT%" (
    echo [ERROR] detector.ps1 not found at: %PS_SCRIPT%
    echo Please ensure detector.ps1 is in the same directory as rmm_detector.bat
    exit /b 1
)

:: Check PowerShell availability
where powershell.exe >nul 2>&1
if errorlevel 1 (
    echo [ERROR] PowerShell is not available on this system.
    exit /b 1
)

:: Show banner in normal mode
if "!MODE!"=="" (
    echo.
    echo   ██████╗ ███╗   ███╗███╗   ███╗
    echo   ██╔══██╗████╗ ████║████╗ ████║
    echo   ██████╔╝██╔████╔██║██╔████╔██║
    echo   ██╔═══╝ ██║╚██╔╝██║██║╚██╔╝██║
    echo   ██║     ██║ ╚═╝ ██║██║ ╚═╝ ██║
    echo   ╚═╝     ╚═╝     ╚═╝╚═╝     ╚═╝
    echo.
    echo   RMM DETECTOR v1.0
    echo   Remote Monitoring Detection Tool
    echo.
    echo ====================================================
    echo   Starting RMM Security Scan...
    echo ====================================================
    echo.
)

:: Execute PowerShell detector
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%PS_SCRIPT%" -OutputFile "%OUTPUT_FILE%"%PS_ARGS%

set "EXIT_CODE=%errorlevel%"

if "!MODE!"=="" (
    echo.
    if exist "%OUTPUT_FILE%" (
        echo Report saved to: %OUTPUT_FILE%
    )
    echo.
)

exit /b %EXIT_CODE%
