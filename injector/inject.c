#include <stdio.h>
#include <Windows.h>

void hex_dump(void *data, int size)
{
    unsigned char *p = (unsigned char*)data;
    unsigned char c;
    int n;
    char bytestr[4] = {0};
    char addrstr[10] = {0};
    char hexstr[16 * 3 + 5] = {0};
    char charstr[16 * 1 + 5] = {0};

    for(n = 1; n <= size; n++)
    {
        if (n % 16 == 1)
        {
                sprintf_s(addrstr, sizeof(addrstr), "%.4x",
                    (p - (unsigned char*)data));
        }
        c = *p;
        if (isalnum(c) == 0)
        {
            c = '.';
        }
        sprintf_s(bytestr, sizeof(bytestr), "%02X ", *p);
        strncat(hexstr, bytestr, sizeof(hexstr)-strlen(hexstr)-1);
        sprintf_s(bytestr, sizeof(bytestr), "%c", c);
        strncat(charstr, bytestr, sizeof(charstr)-strlen(charstr)-1);
        if (n % 16 == 0)
        {
            printf("[%4.4s]   %-50.50s  %s\n", addrstr, hexstr, charstr);
            hexstr[0] = 0;
            charstr[0] = 0;
        }
        else if (n % 8 == 0)
        {
            strncat(hexstr, "  ", sizeof(hexstr)-strlen(hexstr)-1);
            strncat(charstr, " ", sizeof(charstr)-strlen(charstr)-1);
        }
        p++;
    }
    if (strlen(hexstr) > 0)
    {
        printf("[%4.4s]   %-50.50s  %s\n", addrstr, hexstr, charstr);
    }
}

void create_process(char *name, char *dll_name)
{
        STARTUPINFOA si;
        PROCESS_INFORMATION pi;
        DWORD Addr;
        HANDLE hThread;
        HMODULE hKernel32;

        hKernel32 = GetModuleHandleA("kernel32.dll");
        memset(&si, 0, sizeof(STARTUPINFO));
        si.cb = sizeof(STARTUPINFO);
        memset(&pi, 0, sizeof(PROCESS_INFORMATION));

        if (!CreateProcessA(name, 0, 0, 0, 0, CREATE_SUSPENDED, 0, 0, &si, &pi))
        {
                printf("[-] CreateProcessA() failed : %s is correct ? LastError : %x\n", name, GetLastError());
                exit(EXIT_FAILURE);
        }
        Addr = (DWORD)VirtualAllocEx(pi.hProcess, 0, strlen(dll_name) + 1, MEM_COMMIT, PAGE_READWRITE);
        if ((LPVOID)Addr == NULL)
        {
                printf("[-] VirtualAllocEx failed(), LastError : %x\n", GetLastError());
                TerminateProcess(pi.hProcess, 42);
                exit(EXIT_FAILURE);
        }

        WriteProcessMemory(pi.hProcess, (LPVOID)Addr, (void*)dll_name, strlen(dll_name) + 1, NULL);
        hThread = CreateRemoteThread(pi.hProcess, NULL, 0,
                                (LPTHREAD_START_ROUTINE) GetProcAddress(hKernel32,"LoadLibraryA" ), 
                                (LPVOID)Addr, 0, NULL);
        WaitForSingleObject(hThread, INFINITE);
        ResumeThread(pi.hThread);
        CloseHandle(hThread);
}

int main(int argc, char **argv)
{
        PVOID OldValue = NULL;

        if (argc != 3)
        {
                printf("Usage : %s <target.exe> <dll_name.dll>\n", argv[0]);
                exit(EXIT_FAILURE);
        }
        // TODO CHECK 64 bit
		// Wow64DisableWow64FsRedirection(&OldValue);
        create_process(argv[1], argv[2]);
        return (0);
}