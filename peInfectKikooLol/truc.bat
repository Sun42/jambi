copy /Y ..\ToInfect\toInfect\bin\Debug\toInfect.exe .\toInfect.exe
gcc peInfect.c -o infector.exe
infector.exe toInfect.exe
toInfect.exe

