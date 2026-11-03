@echo off
setlocal EnableExtensions
title OpenAll setup for Windows
cd /d "%~dp0"

echo ==========================================================
echo  OpenAll setup (Windows)
echo  Checks Python and a C++ compiler, installs two Python
echo  packages, builds three small reference programs and learns
echo  them for your compiler.
echo  Nothing is installed without asking you first.
echo ==========================================================
echo.

rem ---------- 1. Python ----------
set "PY="
py -3 -c "import sys" >nul 2>nul
if not errorlevel 1 set "PY=py -3"
if defined PY goto :python_ok
python -c "import sys" >nul 2>nul
if not errorlevel 1 set "PY=python"
if defined PY goto :python_ok

echo [!] Python 3 was not found.
where winget >nul 2>nul
if errorlevel 1 goto :python_manual
set "ANS="
set /p "ANS=Install Python 3.12 with winget now? [y/n]: "
if /i not "%ANS%"=="y" goto :python_manual
winget install -e --id Python.Python.3.12 --accept-package-agreements --accept-source-agreements
echo.
echo Python was installed. CLOSE this window and run setup_windows.bat again,
echo so that Windows picks up the new Python.
goto :end

:python_manual
echo Install Python 3 from https://www.python.org/downloads/
echo and tick "Add python.exe to PATH" in the installer.
echo Then run this file again.
goto :end

:python_ok
echo [ok] Python found:
%PY% --version

echo.
echo Installing Python packages: capstone and pefile ...
%PY% -m pip install --user --quiet capstone pefile
if not errorlevel 1 goto :pip_ok
echo Internet install failed. Trying the copies shipped in the vendor folder ...
%PY% -m pip install --user --quiet --no-index --find-links "%~dp0vendor" capstone pefile
if errorlevel 1 goto :pip_failed
:pip_ok
echo [ok] capstone and pefile are installed.

rem ---------- 2. C++ compiler ----------
echo.
where g++ >nul 2>nul
if not errorlevel 1 goto :gpp_ok

call :find_gpp
if defined GPPDIR goto :gpp_path

echo [!] No g++ compiler found.
where winget >nul 2>nul
if errorlevel 1 goto :gpp_manual
echo A free compiler is needed to build our own small reference programs.
echo Option: WinLibs GCC (MinGW-w64, 64-bit). It is a large download,
echo hundreds of MB, and is installed for your user only.
set "ANS="
set /p "ANS=Install WinLibs with winget now? [y/n]: "
if /i not "%ANS%"=="y" goto :gpp_manual
winget install -e --id BrechtSanders.WinLibs.POSIX.UCRT --accept-package-agreements --accept-source-agreements
call :find_gpp
if not defined GPPDIR goto :gpp_notfound_after

:gpp_path
set "PATH=%GPPDIR%;%PATH%"

:gpp_ok
echo [ok] Compiler found:
g++ --version
for /f "delims=" %%M in ('g++ -dumpmachine') do set "MACH=%%M"
echo     target: %MACH%
echo %MACH% | findstr /i "x86_64" >nul
if errorlevel 1 echo [!] WARNING: this compiler is not 64-bit. The prototype reads 64-bit programs only.

rem ---------- 3. Reference programs ----------
echo.
set "ANS="
set /p "ANS=Build the three reference programs and learn them for your compiler now? [y/n]: "
if /i not "%ANS%"=="y" goto :finished

set "KIT=%~dp0tests\shelf_demo_cpp"
set "OUT=%~dp0out"
if not exist "%KIT%\ref_empty.cpp" goto :kit_missing
if not exist "%OUT%" mkdir "%OUT%"
echo.
echo Compiling with: g++ -O2 -std=c++17
set "COMPILE_FAILED="
call :compile ref_empty
call :compile ref_stl
call :compile ref_numeric
if defined COMPILE_FAILED goto :compile_failed

echo.
echo Learning the reference programs of this compiler ...
%PY% "%~dp0scripts\build_shelves.py" --learn "%OUT%\ref_empty.exe" "%OUT%\ref_stl.exe" "%OUT%\ref_numeric.exe"
if errorlevel 1 goto :learn_failed

:finished
echo.
echo ==========================================================
echo  Finished.
echo  Next: copy the program you want to study into the input folder,
echo  open this folder in Claude Code and run  /openall-shelves
echo ==========================================================
goto :end

:pip_failed
echo [!] Could not install capstone and pefile.
echo     Copy the text above and send it to Claude.
goto :end

:gpp_manual
echo Install a 64-bit g++ compiler yourself, for example WinLibs from https://winlibs.com/
echo Then run this file again.
goto :end

:gpp_notfound_after
echo [!] WinLibs was installed but g++.exe was not found yet.
echo     Close this window and run setup_windows.bat again.
goto :end

:kit_missing
echo [!] Reference programs not found: %KIT%
echo     Unpack the whole project zip and run this file from inside it.
goto :end

:compile_failed
echo [!] Compilation failed. Copy the text above and send it to Claude.
goto :end

:learn_failed
echo [!] Learning the reference programs stopped with an error.
echo     Copy the text above and send it to Claude.
goto :end

:end
echo.
pause
endlocal
exit /b 0

rem ---------- subroutines ----------
:find_gpp
set "GPPDIR="
for /f "delims=" %%G in ('dir /s /b "%LOCALAPPDATA%\Microsoft\WinGet\Packages\g++.exe" 2^>nul') do if not defined GPPDIR set "GPPDIR=%%~dpG"
if defined GPPDIR exit /b 0
if exist "C:\msys64\ucrt64\bin\g++.exe" set "GPPDIR=C:\msys64\ucrt64\bin\"
if defined GPPDIR exit /b 0
if exist "C:\mingw64\bin\g++.exe" set "GPPDIR=C:\mingw64\bin\"
exit /b 0

:compile
g++ -O2 -std=c++17 -o "%OUT%\%1.exe" "%KIT%\%1.cpp"
if errorlevel 1 goto :compile_err
strip -s "%OUT%\%1.exe" >nul 2>nul
echo [ok] %1.exe
exit /b 0
:compile_err
set "COMPILE_FAILED=1"
echo [!] failed: %1.cpp
exit /b 1
