@echo off
call build.bat

if %ERRORLEVEL% NEQ 0 exit /b

pushd bin
interloper.exe %*
popd