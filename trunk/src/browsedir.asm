.486
.model flat, stdcall
option casemap:none

include c:\masm32\include\windows.inc
include c:\masm32\include\kernel32.inc
include c:\masm32\include\user32.inc
include c:\masm32\include\msvcrt.inc

includelib c:\masm32\lib\kernel32.lib
includelib c:\masm32\lib\user32.lib
include c:\masm32\lib\msvcrt.lib

;initialised vars
.data

;FilePattern seeked ;dans un premier temps*.exe mais checker le header serait mieux
lpFileName db	"ToInfect.exe", 0

varTitre db "Title", 0

;uninitialised var
.data?

;
lpFindFileData WIN32_FIND_DATA <>	

hFile dd ?

.code
;offset globale saddr locales
debut: 
lea eax, lpFindFileData
push eax
lea eax, lpFileName
push eax
call FindFirstFile
;invoke FindFirstFile,  offset lpFileName,  offset lpFindFileData
mov   hFile, eax
cmp hFile, 0
je  exit

boucle:
;invoke MessageBox, 0, offset lpFindFileData.cFileName, offset varTitre, MB_OK
invoke crt_printf, offset lpFindFileData.cFileName
invoke FindNextFile,  hFile,  offset lpFindFileData
cmp eax, 0
jne  boucle

exit:
invoke ExitProcess, 0
end debut
