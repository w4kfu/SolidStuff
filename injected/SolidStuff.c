#include "SolidStuff.h"

PVOID protVectoredHandler;
DWORD dwTxtBase;
DWORD dwTxtSize;

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
		setup_all_hook();
		protVectoredHandler = AddVectoredExceptionHandler(0, ProtectionFaultVectoredHandler);
	}
	return TRUE;
}

LONG CALLBACK ProtectionFaultVectoredHandler(PEXCEPTION_POINTERS ExceptionInfo)
{
    if (ExceptionInfo->ExceptionRecord->ExceptionCode == STATUS_ACCESS_VIOLATION)
    {
		dbg_msg("[+] Found OEP : %08X\n", ExceptionInfo->ContextRecord->Eip);
		dump(GetModuleHandleA(NULL), ExceptionInfo->ContextRecord->Eip);
        TerminateProcess(GetCurrentProcess(), 0);
    }
    return EXCEPTION_CONTINUE_SEARCH;
}