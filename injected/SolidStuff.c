#include "SolidStuff.h"

PVOID protVectoredHandler;
DWORD dwTxtBase;
DWORD dwTxtSize;
DWORD dwRdataBase;
DWORD dwRdataSize;
// Other version 2.XXX ?
DWORD ImportDirectoryRVA;

VOID MakeConsole(VOID)
{
	AllocConsole();
	freopen("CONIN$","rb",stdin);
	freopen("CONOUT$","wb",stdout);
	freopen("CONOUT$","wb",stderr);
}

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpReserved)
{
	HMODULE hModule;
	DWORD dwOldProt;

	if (fdwReason == DLL_PROCESS_ATTACH)
	{
		MakeConsole();
		DisableThreadLibraryCalls(GetModuleHandleA(NULL));
		dbg_msg("[+] DLL_PROCESS_ATTACH\n");
		hModule = GetModuleHandleA(NULL);
		dbg_msg("[+] Base Address = %08X\n", hModule);
		dwTxtBase = GetTextAddress(hModule);
		dbg_msg("[+] .txt Address = %08X\n", dwTxtBase);
		dwTxtSize = GetTextSize(hModule);
		dbg_msg("[+] .txt Size = %08X\n", dwTxtSize);

		dwRdataBase = GetRdataAddress(hModule);
		dwRdataSize = GetRdataSize(hModule);

		// Other version 2.XXX ?
		VirtualProtect((LPVOID)dwRdataBase, dwRdataSize, PAGE_NOACCESS, &dwOldProt);

		setup_all_hook();
		protVectoredHandler = AddVectoredExceptionHandler(0, ProtectionFaultVectoredHandler);
	}
	return TRUE;
}

LONG CALLBACK ProtectionFaultVectoredHandler(PEXCEPTION_POINTERS ExceptionInfo)
{
	DWORD dwOldProtect;
	static BOOL stepInto = FALSE;

    if (ExceptionInfo->ExceptionRecord->ExceptionCode == STATUS_ACCESS_VIOLATION)
    {
		if (ExceptionInfo->ContextRecord->Eip >= dwTxtBase && ExceptionInfo->ContextRecord->Eip <= (dwTxtBase + dwTxtSize))
		{
			RemoveVectoredExceptionHandler(protVectoredHandler);
			dbg_msg("[+] Found OEP : %08X\n", ExceptionInfo->ContextRecord->Eip);

			// Restore Read / write protection on .txt
			VirtualProtect((LPVOID)dwTxtBase, dwTxtSize, PAGE_READWRITE, &dwOldProtect);
			// Other version 2.XXX ?
			dump((DWORD)GetModuleHandleA(NULL), ExceptionInfo->ContextRecord->Eip, ImportDirectoryRVA);
			//dump_other(GetModuleHandleA(NULL), ExceptionInfo->ContextRecord->Eip);
			system("pause");
			TerminateProcess(GetCurrentProcess(), 0);
		}
		else
		{
			if ((ExceptionInfo->ContextRecord->Eip >= (DWORD)GetModuleHandleA(NULL)) && (ExceptionInfo->ContextRecord->Eip <= ((DWORD)GetModuleHandleA(NULL) + 0x02C73000)))
			{
				// Restore Read / write protection on .rdata
				VirtualProtect((LPVOID)dwRdataBase, dwRdataSize, PAGE_READWRITE, &dwOldProtect);
				dbg_msg("[+] ExceptionInfo->ExceptionRecord->ExceptionInformation[1] = %08X\n", ExceptionInfo->ExceptionRecord->ExceptionInformation[1]);
				dbg_msg("[+] ExceptionInfo->ContextRecord->Eip = %08X\n", ExceptionInfo->ContextRecord->Eip);
				//ImportDirectoryRVA = ExceptionInfo->ExceptionRecord->ExceptionInformation[1] - 0x10 - (DWORD)GetModuleHandleA(NULL);
				ImportDirectoryRVA = ExceptionInfo->ExceptionRecord->ExceptionInformation[1] - 0x10 - (DWORD)GetModuleHandleA(NULL);
				dbg_msg("[+] RVA IAT : %08X\n", ImportDirectoryRVA);
			}
			else
			{
				VirtualProtect((LPVOID)dwRdataBase, dwRdataSize, PAGE_READWRITE, &dwOldProtect);
				stepInto = TRUE;
				ExceptionInfo->ContextRecord->EFlags |= 0x100;			
			}
			return EXCEPTION_CONTINUE_EXECUTION;
		}

    }
    else if ((ExceptionInfo->ExceptionRecord->ExceptionCode == EXCEPTION_SINGLE_STEP) && (stepInto))
    {
        VirtualProtect((LPVOID)dwRdataBase, dwRdataSize, PAGE_NOACCESS, &dwOldProtect);
        stepInto = FALSE;
        return EXCEPTION_CONTINUE_EXECUTION;
    }
    return EXCEPTION_CONTINUE_SEARCH;
}