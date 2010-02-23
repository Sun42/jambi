@echo off
copy /Y ..\victim\victim.exe victim.exe
gcc peInfect.c -o infector.exe
infector.exe victim.exe > debug.txt
victim.exe

