@echo off
chcp 65001 >nul 2>&1
setlocal EnableDelayedExpansion

:: ============================================================
::  DESCUBRIMIENTO DE RED - SIN PRIVILEGIOS ADMIN
::  Ejecuta el script PowerShell desde CMD
::  Busca el .ps1 en la misma carpeta que este .bat
:: ============================================================

set "SCRIPT_DIR=%~dp0"
set "SCRIPT_DIR=%SCRIPT_DIR:~0,-1%"
set "PS1=%SCRIPT_DIR%\Test-red.ps1"

echo.
echo  +======================================================+
echo  ^|  LANZADOR CMD - DESCUBRIMIENTO DE RED              ^|
echo  +======================================================+
echo.

:: Verificar que el script PS1 existe
if not exist "%PS1%" (
    echo  [ERROR] No se encontro el script:
    echo  %PS1%
    echo.
    echo  Asegurate de que Test-red.ps1 este en la misma carpeta que este .bat
    echo.
    pause
    exit /b 1
)

echo  Script  : %PS1%
echo  Carpeta : %SCRIPT_DIR%
echo.

:: Verificar que PowerShell esta disponible
where powershell >nul 2>&1
if errorlevel 1 (
    echo  [ERROR] PowerShell no encontrado en el sistema
    pause
    exit /b 1
)

:: Obtener version de PowerShell
for /f "tokens=*" %%v in ('powershell -NoProfile -Command "$PSVersionTable.PSVersion.Major" 2^>nul') do set "PS_VER=%%v"
echo  PowerShell version: %PS_VER%
echo.

:: Ejecutar el script con bypass de execution policy
:: -OutputPath apunta a la misma carpeta del bat para guardar el reporte ahi
echo  Iniciando...
echo.

powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%PS1%" -OutputPath "%SCRIPT_DIR%"

set "EXIT_CODE=%errorlevel%"

echo.
if %EXIT_CODE% EQU 0 (
    echo  [OK] Script completado correctamente
) else (
    echo  [WARN] Script termino con codigo: %EXIT_CODE%
)

echo.
echo  El reporte HTML se guardo en: %SCRIPT_DIR%
echo.
pause
endlocal