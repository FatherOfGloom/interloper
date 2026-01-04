@echo off
@REM TODO: add verbose compiler output flags

if not exist ./bin/ mkdir bin

@echo on
gcc -o bin/interloper.exe src/main.c src/vec.c -lshell32 -lole32 -luuid
@echo off

if %ERRORLEVEL% NEQ 0 exit /b 1
@echo build success