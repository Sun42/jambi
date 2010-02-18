@echo off
copy /Y ..\ToInfect\toInfect\a.exe .\toInfect.exe
gcc peInfect.c -o infector.exe
infector.exe toInfect.exe
toInfect.exe

