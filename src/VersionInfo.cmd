@echo off

setlocal enabledelayedexpansion

set PATH_OUTPUT="%~dp0version.props"

if exist %PATH_OUTPUT% (
    del /Q %PATH_OUTPUT%
)

for /F "tokens=*" %%a IN ('git.exe describe HEAD --tags --long') do set GIT=%%a
if "%GIT%" == "" (exit /B)

set INFORMATIONAL_VERSION=%GIT%
set INFORMATIONAL_VERSION=!INFORMATIONAL_VERSION:~1!

for /f "tokens=1 delims=-" %%a IN ("%GIT%") do set GIT=%%a
set VERSION=%GIT%
set VERSION=!VERSION:~1!

(
echo ^<Project^>
echo ^ ^ ^<PropertyGroup^>
echo ^ ^ ^ ^ ^<AssemblyVersion^>%VERSION%^</AssemblyVersion^>
echo ^ ^ ^ ^ ^<FileVersion^>%VERSION%^</FileVersion^>
echo ^ ^ ^ ^ ^<Version^>%VERSION%^</Version^>
echo ^ ^ ^ ^ ^<InformationalVersion^>%INFORMATIONAL_VERSION%^</InformationalVersion^>
echo ^ ^ ^</PropertyGroup^>
echo ^</Project^>
)>%PATH_OUTPUT%

echo VersionInfo: Wrote props for %INFORMATIONAL_VERSION%.