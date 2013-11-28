#include "SolidStuff.h"

PVOID protVectoredHandler;
DWORD dwTxtBase;
DWORD dwTxtSize;
DWORD dwRdataBase;
DWORD dwRdataSize;
DWORD ImportDirectoryRVA;

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpReserved)
{
	HMODULE hModule;
	DWORD dwOldProt;

	if (fdwReason == DLL_PROCESS_ATTACH)
	{
		DisableThreadLibraryCalls(GetModuleHandleA(DLL_NAME));
		dbg_msg("[+] DLL_PROCESS_ATTACH\n");
		hModule = GetModuleHandleA(NULL);
		dbg_msg("[+] Base Address = %08X\n", hModule);
		dwTxtBase = GetTextAddress(hModule);
		dbg_msg("[+] .txt Address = %08X\n", dwTxtBase);
		dwTxtSize = GetTextSize(hModule);
		dbg_msg("[+] .txt Size = %08X\n", dwTxtSize);

		dwRdataBase = GetRdataAddress(hModule);
		dwRdataSize = GetRdataSize(hModule);

		VirtualProtect((LPVOID)dwRdataBase, dwRdataSize, PAGE_NOACCESS, &dwOldProt);

		setup_all_hook();
		protVectoredHandler = AddVectoredExceptionHandler(0, ProtectionFaultVectoredHandler);
	}
	return TRUE;
}

LONG CALLBACK ProtectionFaultVectoredHandler(PEXCEPTION_POINTERS ExceptionInfo)
{
	DWORD dwOldProtect;

    if (ExceptionInfo->ExceptionRecord->ExceptionCode == STATUS_ACCESS_VIOLATION)
    {
		if (ExceptionInfo->ContextRecord->Eip >= dwTxtBase && ExceptionInfo->ContextRecord->Eip <= (dwTxtBase + dwTxtSize))
		{
			RemoveVectoredExceptionHandler(protVectoredHandler);
			dbg_msg("[+] Found OEP : %08X\n", ExceptionInfo->ContextRecord->Eip);

			// Restore Read / write protection on .txt
			VirtualProtect((LPVOID)dwTxtBase, dwTxtSize, PAGE_READWRITE, &dwOldProtect);
			dump(GetModuleHandleA(NULL), ExceptionInfo->ContextRecord->Eip, ImportDirectoryRVA);
			TerminateProcess(GetCurrentProcess(), 0);
		}
		else
		{
			// Restore Read / write protection on .rdata
			VirtualProtect((LPVOID)dwRdataBase, dwRdataSize, PAGE_READWRITE, &dwOldProtect);
			ImportDirectoryRVA = ExceptionInfo->ExceptionRecord->ExceptionInformation[1] - 0x10 - (DWORD)GetModuleHandleA(NULL);
			dbg_msg("[+] RVA IAT : %08X\n", ImportDirectoryRVA);
			return EXCEPTION_CONTINUE_EXECUTION;
		}

    }
    return EXCEPTION_CONTINUE_SEARCH;
}