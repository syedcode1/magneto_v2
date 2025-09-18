@echo off
ECHO Starting MAGNETO Stealth Attack Simulator...
ECHO.

:: Change to the directory where this batch file is located
cd /d "%~dp0"

:: Display current directory for debugging
ECHO Current directory: %CD%
ECHO.

:: Check if MAGNETO.ps1 exists in the current directory
IF NOT EXIST "MAGNETO.ps1" (
    ECHO ERROR: MAGNETO.ps1 not found in the current directory.
    ECHO Please ensure MAGNETO.ps1 is in the same folder as this batch file.
    ECHO.
    ECHO Looking in: %CD%
    ECHO.
    DIR *.ps1 2>nul
    PAUSE
    EXIT /B 1
)

:: Run the PowerShell script with bypass execution policy and Cleanup switch
ECHO Executing MAGNETO.ps1 with Cleanup...
powershell.exe -ExecutionPolicy Bypass -File "%~dp0MAGNETO.ps1" -Cleanup
IF %ERRORLEVEL% NEQ 0 (
    ECHO ERROR: Failed to execute MAGNETO.ps1. Check PowerShell permissions or script errors.
    PAUSE
    EXIT /B %ERRORLEVEL%
)

ECHO.
ECHO MAGNETO simulation completed. Check the generated log file for details.
PAUSE
EXIT /B 0