@echo off
start "" "%SystemRoot%\System32\wscript.exe" //B //Nologo "%~dp0launch_hidden.vbs"
exit /b 0
