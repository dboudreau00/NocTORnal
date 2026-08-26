@echo off
rem Double-click launcher. The explicit bypass is required because a
rem default Windows policy of Restricted blocks .ps1 outright, which
rem reads as "PowerShell is broken" to somebody evaluating the install.
powershell -ExecutionPolicy Bypass -File "%~dp0scripts\launch.ps1" %*
