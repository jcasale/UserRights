@echo off

setlocal enabledelayedexpansion

set PATH_OUTPUT="%~dp0VersionInfo.cs"

:: Prevent Visual Studio from misbehaving when the file is removed after having been detected.
if exist %PATH_OUTPUT% (
    copy /Y nul: %PATH_OUTPUT%
)

for /F "tokens=*" %%a IN ('git.exe describe HEAD --tags --long') do set GIT=%%a

:: Exit with success to allow msbuild to continue with the empty file.
if "%GIT%" == "" (exit /B)

set INFORMATIONAL_VERSION=%GIT%
set INFORMATIONAL_VERSION=!INFORMATIONAL_VERSION:~1!

for /f "tokens=1 delims=-" %%a IN ("%GIT%") do set GIT=%%a
set VERSION=%GIT%
set VERSION=!VERSION:~1!

(
echo |set /p var="using System.Reflection;"
echo.
echo.
echo |set /p var="[assembly: AssemblyVersion("%VERSION%")]"
echo.
echo |set /p var="[assembly: AssemblyFileVersion("%VERSION%")]"
echo.
echo |set /p var="[assembly: AssemblyInformationalVersion("%INFORMATIONAL_VERSION%")]"
)>%PATH_OUTPUT%