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
;; tester retour de createfile+boucle
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

;initialised vars
.data

;FilePattern seeked ;dans un premier temps*.exe mais checker le header serait mieux
lpFileName db	"*.exe", 0

varTitre db "File : %s  -> size : %d", 13,0
varNum dd 45  
varString db "HeyLow World", 0
;uninitialised var
.data?

;
lpFindFileData WIN32_FIND_DATA <>	

hFile dd ?
hFile2 dd ?

.code
	
myputstr: 
push ebp
mov ebp, esp
push [ebp + 8]
call crt_printf
leave
ret
	

;offset globale saddr locales
start: 
;; Recuperation du premier fichier
lea eax, lpFindFileData
push eax
lea eax, lpFileName
push eax
call FindFirstFile
;; ajout du teste de retour

;invoke FindFirstFile,  offset lpFileName,  offset lpFindFileData
mov   hFile, eax
cmp hFile, 0
je  exit

nextFile:
;push 0   ;; 0
;push 0   ;; 0
;push OPEN_EXISTING   ;; OPEN_EXISTING
;push 0   ;; 0
;push 0   ;; 0
;mov ebx, GENERIC_WRITE
;or ebx, GENERIC_READ
;push ebx      ;; GENERIC_READ|GENERIC_WRITE
;lea ebx, lpFindFileData.cFileName
;push ebx      ;; fileName 
;call CreateFileA
;mov hFile, eax
; hFile = CreateFileA(fileName, 
;		      GENERIC_READ|GENERIC_WRITE, 
;		      0, 0, OPEN_EXISTING, 0, 0)

;cmp hFile, INVALID_HANDLE_VALUE
;je exit

mov ebx, GENERIC_WRITE
or ebx, GENERIC_READ
invoke  CreateFile, addr  lpFindFileData.cFileName, ebx, 0, NULL, OPEN_EXISTING, 0, NULL
mov hFile2,eax

;cmp hFile2, INVALID_HANDLE_VALUE
;je exit

push 0
;lea ebx, hFile
;push ebx
push hFile2
call GetFileSize
;d = GetFileSize(hFile,0);


push eax
lea eax, lpFindFileData.cFileName
push eax
lea eax, varTitre
push eax
call crt_printf


invoke FindNextFile,  hFile,  offset lpFindFileData
cmp eax, 0
jne  nextFile
jmp exit


exit:
invoke ExitProcess, 0
end start









