@echo off
REM ==== Auto-release ====
REM Get version number from file
setlocal
set /p VERSION=<version.txt

REM Tag name
set TAG=v%VERSION%

REM Executable and version paths
set EXE=dist\SFTPCopy.exe
set VERSION_FILE=version.txt

REM Generate changelog 
git describe --tags --abbrev=0 > prev_tag.tmp 2>nul
set /p PREV_TAG=<prev_tag.tmp

git log %PREV_TAG%..HEAD --pretty=format:"- %%s" > changelog.txt
del prev_tag.tmp

REM Create GitHub release 
gh release create %TAG% %EXE% %VERSION_FILE% changelog.txt ^
    --title "SFTP Copy %VERSION%" ^
    --notes "Auto-release for version %VERSION%"

echo Release %TAG% created successfully!
endlocal
pause
