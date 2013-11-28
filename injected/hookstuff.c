#include "hookstuff.h"

BOOL (__stdcall *Resume_VirtualProtect)(LPVOID lpAddress, SIZE_T dwSize, DWORD flNewProtect, PDWORD lpflOldProtect) = NULL;

void setup_hook(char *module, char *name_export, void *Hook_func, void *trampo, DWORD addr)
{
	DWORD OldProtect;
	DWORD len;
	FARPROC Proc;
	
	if (addr != 0)
	{
		Proc = (FARPROC)addr;
	}
	else
	{
		Proc = GetProcAddress(GetModuleHandleA(module), name_export);
		if (!Proc)
			return;
	}
	len = 0;
	while (len < 5)
		len += LDE((BYTE*)Proc + len , LDE_X86);
	memcpy(trampo, Proc, len);
	*(BYTE *)((BYTE*)trampo + len) = 0xE9;
	*(DWORD *)((BYTE*)trampo + len + 1) = (BYTE*)Proc - (BYTE*)trampo - 5;
	VirtualProtect(Proc, len, PAGE_EXECUTE_READWRITE, &OldProtect);
	*(BYTE*)Proc = 0xE9;
	*(DWORD*)((char*)Proc + 1) = (BYTE*)Hook_func - (BYTE*)Proc - 5;
	VirtualProtect(Proc, len, OldProtect, &OldProtect);
}

/* Be careful this DRM calls a lot VirtualProtect */
/* They don't call for example one time VirtualProtect on .txt section, but about (.txt section size / 4) ... */
BOOL __stdcall Hook_VirtualProtect(LPVOID lpAddress, SIZE_T dwSize, DWORD flNewProtect, PDWORD lpflOldProtect)
{
    DWORD return_addr;
	DWORD dwOldProt;

	__asm
	{
		mov eax, [ebp + 4]
		mov return_addr, eax
	}
	//dbg_msg("VirtualProtect(0x%08X, 0x%08X, 0x%08X, 0x%08X) : 0x%08X\n\n", lpAddress, dwSize, flNewProtect, lpflOldProtect, return_addr);
	if (lpAddress >= (LPVOID)dwTxtBase && lpAddress <= (LPVOID)(dwTxtBase + dwTxtSize))
	{
		if (flNewProtect == PAGE_EXECUTE_READ)
		return (Resume_VirtualProtect(lpAddress, dwSize, PAGE_NOACCESS, lpflOldProtect));
	}
	return (Resume_VirtualProtect(lpAddress, dwSize, flNewProtect, lpflOldProtect));
}

void setup_Hook_VirtualProtect(void)
{
	Resume_VirtualProtect = (BOOL(__stdcall *)(LPVOID lpAddress, SIZE_T dwSize, DWORD flNewProtect, PDWORD lpflOldProtect))VirtualAlloc(0, 0x1000, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	memset(Resume_VirtualProtect, 0x90, 0x1000);
	setup_hook("kernel32.dll", "VirtualProtect", &Hook_VirtualProtect, Resume_VirtualProtect, 0);
}

void setup_all_hook(void)
{
	setup_Hook_VirtualProtect();
}