@echo off
:: ================================================================
:: build.bat  -  builds jwt-intruder-all.jar
:: Requirements: JDK 11+, curl (built into Windows 10/11)
:: Usage:  build.bat
:: Output: dist\jwt-intruder-all.jar
:: ================================================================
setlocal enabledelayedexpansion
cd /d "%~dp0"

set DEPS_DIR=%~dp0.build\deps
set COMPILE_DIR=%~dp0.build\compile
set EXTRACT_DIR=%~dp0.build\extract
set DIST_DIR=%~dp0dist
set SRC_DIR=%~dp0src\main\java
set RES_DIR=%~dp0src\main\resources

for %%D in ("%DEPS_DIR%" "%COMPILE_DIR%" "%EXTRACT_DIR%" "%DIST_DIR%") do (
    if not exist "%%~D" mkdir "%%~D"
)

set MAVEN=https://repo1.maven.org/maven2

:: ── Montoya API ──────────────────────────────────────────────────
call :download "%MAVEN%/net/portswigger/burp/extensions/montoya-api/2026.2/montoya-api-2026.2.jar" "%DEPS_DIR%\montoya-api.jar"

:: ── Runtime dependencies ─────────────────────────────────────────
call :download "%MAVEN%/com/nimbusds/nimbus-jose-jwt/9.37.3/nimbus-jose-jwt-9.37.3.jar"           "%DEPS_DIR%\nimbus.jar"
call :download "%MAVEN%/org/bouncycastle/bcprov-jdk18on/1.77/bcprov-jdk18on-1.77.jar"             "%DEPS_DIR%\bcprov.jar"
call :download "%MAVEN%/org/bouncycastle/bcpkix-jdk18on/1.77/bcpkix-jdk18on-1.77.jar"             "%DEPS_DIR%\bcpkix.jar"
call :download "%MAVEN%/org/json/json/20240303/json-20240303.jar"                                  "%DEPS_DIR%\json.jar"
call :download "%MAVEN%/com/nimbusds/content-type/2.3/content-type-2.3.jar"                       "%DEPS_DIR%\content-type.jar"
call :download "%MAVEN%/net/minidev/json-smart/2.5.1/json-smart-2.5.1.jar"                        "%DEPS_DIR%\json-smart.jar"
call :download "%MAVEN%/net/minidev/accessors-smart/2.5.1/accessors-smart-2.5.1.jar"              "%DEPS_DIR%\accessors-smart.jar"
call :download "%MAVEN%/org/ow2/asm/asm/9.6/asm-9.6.jar"                                          "%DEPS_DIR%\asm.jar"

:: ── Collect sources ──────────────────────────────────────────────
set SOURCES=%~dp0.build\sources.txt
if exist "%SOURCES%" del "%SOURCES%"
for /r "%SRC_DIR%" %%F in (*.java) do echo %%F >> "%SOURCES%"

:: ── Compile ──────────────────────────────────────────────────────
echo =^> Compiling sources...
set CP=%DEPS_DIR%\montoya-api.jar;%DEPS_DIR%\nimbus.jar;%DEPS_DIR%\bcprov.jar;%DEPS_DIR%\bcpkix.jar;%DEPS_DIR%\json.jar;%DEPS_DIR%\content-type.jar;%DEPS_DIR%\json-smart.jar;%DEPS_DIR%\accessors-smart.jar;%DEPS_DIR%\asm.jar

javac --release 11 -cp "%CP%" -d "%COMPILE_DIR%" @"%SOURCES%"
if errorlevel 1 ( echo ERROR: Compilation failed & exit /b 1 )
echo    Sources compiled OK.

:: ── Assemble fat JAR ─────────────────────────────────────────────
echo =^> Assembling fat JAR...
pushd "%EXTRACT_DIR%"
for %%J in (nimbus bcprov bcpkix json content-type json-smart accessors-smart asm) do (
    jar xf "%DEPS_DIR%\%%J.jar"
)
popd

for /r "%EXTRACT_DIR%\META-INF" %%F in (*.SF *.DSA *.RSA) do del /q "%%F" 2>nul

xcopy /e /y "%COMPILE_DIR%\*" "%EXTRACT_DIR%\" >nul
xcopy /e /y "%RES_DIR%\*"     "%EXTRACT_DIR%\" >nul

set OUTPUT=%DIST_DIR%\jwt-intruder-all.jar
pushd "%EXTRACT_DIR%"
jar cf "%OUTPUT%" .
popd

echo.
echo Build successful!
echo Load in Burp Suite: %OUTPUT%
goto :eof

:download
if exist "%~2" ( echo   [cached] %~nx2 ) else (
    echo   [download] %~nx2
    curl -fsSL "%~1" -o "%~2"
    if errorlevel 1 ( echo ERROR: Failed to download %~nx2 & exit /b 1 )
)
goto :eof
