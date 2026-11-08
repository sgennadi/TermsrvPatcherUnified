@echo off
setlocal
rem Existing repository; this script pushes a prepared checkout, it does not create a new repo.
cd /d "%~dp0.."
git remote get-url origin >nul 2>&1 || git remote add origin https://github.com/sgennadi/TermsrvPatcherUnified.git
for /f %%B in ('git branch --show-current') do set BRANCH=%%B
if not defined BRANCH set BRANCH=main
git push -u origin %BRANCH%
