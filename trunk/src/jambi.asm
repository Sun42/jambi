.486
.model flat, stdcall
option casemap:none

include c:\masm32\include\windows.inc
include c:\masm32\include\kernel32.inc
include c:\masm32\include\user32.inc
include  c:\masm32\include\msvcrt.inc

includelib c:\masm32\lib\kernel32.lib
includelib c:\masm32\lib\user32.lib
includelib c:\masm32\lib\msvcrt.lib

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;; TODO
;; tester retour de createfile
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

;initialised vars
.data

;FilePattern seeked ;dans un premier temps*.exe mais checker le header serait mieux
lpFileName db	"*.*", 0

sPutInt db "EAX: %i",13,10, 0
sMsg db "File : %s, size : %i", 13,10,0
varNum dd 45  
varString db "HeyLow World " ,13,10, 0
;uninitialised var
.data?

;
lpFindFileData WIN32_FIND_DATA <>	
iSize DWORD ?
hFile HANDLE ?
hFile2 HANDLE ?

.code
	
;offset globales || addr locales

start: 
;; Recuperation du premier fichier
; hFile = FindFirstFile,  offset lpFileName,  offset lpFindFileData
lea eax, lpFindFileData
push eax
lea eax, lpFileName
push eax
call FindFirstFile

mov   hFile, eax
cmp hFile, 0
je  exit

nextFile:


; open the file RW Mode
; hFile2 = CreateFileA(lpFindFileData.cFileName, GENERIC_READ|GENERIC_WRITE, 0, 0, OPEN_EXISTING, 0, 0)

push	0
push	0
push	OPEN_EXISTING 
push	0
push	0
mov		eax, GENERIC_WRITE
or		eax, GENERIC_READ
lea		eax, lpFindFileData.cFileName
push	eax
call		CreateFile

mov		hFile2, eax

; if (hFile2 == INVALID_HANDLE_VALUE)
; cmp hFile2, INVALID_HANDLE_VALUE
; je exit

; open the file ->penser a close et comparer avec invalide handle

; recup la taille du fichier
; isSize = GetFileSize(hFile2, 0)
push	0
lea		eax, hFile2
push	eax
call		GetFileSize
mov		iSize, eax

;invoke	crt_printf, varString, iSize
push	hFile2
call		CloseHandle

; output FIleName Size
; invoke crt_printf, addr sMsg, addr lpFindFileData.cFileName, iSizert
push	iSize
lea		eax, lpFindFileData.cFileName
push	eax
lea		eax, sMsg
push	eax
call		crt_printf

invoke FindNextFile,  hFile,  offset lpFindFileData
cmp eax, 0
jne  nextFile

exit:
invoke ExitProcess, 1

end start









