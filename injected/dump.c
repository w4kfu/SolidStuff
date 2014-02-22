#include "dump.h"

DWORD AlignSize(DWORD size, DWORD alignement)
{
    return (size % alignement == 0) ? size : ((size / alignement) + 1 ) * alignement;
}

PBYTE AllocEnough(DWORD dwBase, DWORD *dwAllocSize)
{
    PIMAGE_DOS_HEADER pDosHeader;
    PIMAGE_NT_HEADERS pPE;
    PIMAGE_SECTION_HEADER pSectionHeaders;
    PBYTE pDump = NULL;

    pDosHeader = (PIMAGE_DOS_HEADER)dwBase;
    pPE = (PIMAGE_NT_HEADERS)(dwBase + pDosHeader->e_lfanew);
    pSectionHeaders = (PIMAGE_SECTION_HEADER)((PBYTE)pPE + sizeof(IMAGE_FILE_HEADER) + pPE->FileHeader.SizeOfOptionalHeader + sizeof(DWORD));
    *dwAllocSize = pSectionHeaders[pPE->FileHeader.NumberOfSections - 1].VirtualAddress + pSectionHeaders[pPE->FileHeader.NumberOfSections - 1].Misc.VirtualSize;
    pDump = (PBYTE)VirtualAlloc(NULL, *dwAllocSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!pDump)
        return NULL;
    return pDump;
}

VOID ModifyLastSection(DWORD dwBase)
{
    PIMAGE_DOS_HEADER pDosHeader;
    PIMAGE_NT_HEADERS pPE;
    PIMAGE_SECTION_HEADER pSectionHeaders;
	DWORD OldProtect;

    pDosHeader = (PIMAGE_DOS_HEADER)dwBase;
    pPE = (PIMAGE_NT_HEADERS)(dwBase + pDosHeader->e_lfanew);
    pSectionHeaders = (PIMAGE_SECTION_HEADER)((PBYTE)pPE + sizeof(IMAGE_FILE_HEADER) + pPE->FileHeader.SizeOfOptionalHeader + sizeof(DWORD));
	
	VirtualProtect(pDosHeader, 0x2000, PAGE_EXECUTE_READWRITE, &OldProtect);
	pSectionHeaders[pPE->FileHeader.NumberOfSections - 1].Misc.VirtualSize += 0x1000;
	pSectionHeaders[pPE->FileHeader.NumberOfSections - 1].SizeOfRawData += 0x1000;
	pPE->OptionalHeader.FileAlignment += 0x1000;
	VirtualProtect(pDosHeader, 0x2000, OldProtect, &OldProtect);	
}

BOOL dump_other(DWORD hModule, DWORD dwOEP)
{
	//ModifyLastSection(hModule);
	dump(hModule, dwOEP, 0);
	return TRUE;
}

BOOL dump(DWORD hModule, DWORD dwOEP, DWORD ImportDirectoryRVA)
{
    PIMAGE_DOS_HEADER pDosHeader;
    PIMAGE_NT_HEADERS pPE;
    PIMAGE_SECTION_HEADER pSection;
	PBYTE pDump = NULL;
	PBYTE pAct = NULL;
	DWORD dwAllocSize = 0;
	DWORD dwFinalSize = 0;
	DWORD dwAlign = 0;
	DWORD i;
	HANDLE hFile;
	DWORD dwWritten;

	pDump = AllocEnough((DWORD)hModule, &dwAllocSize);
	if (!pDump)
		return FALSE;
	dbg_msg("[+] Allocated %08X length\n", dwAllocSize);

	PrintNTFileHeader((DWORD)hModule);
	PrintNTOptionalHeader((DWORD)hModule);

    pDosHeader = (PIMAGE_DOS_HEADER)hModule;
    pPE = (PIMAGE_NT_HEADERS)((DWORD)hModule + pDosHeader->e_lfanew);
	pSection = (PIMAGE_SECTION_HEADER)((PCHAR)pPE + sizeof(IMAGE_FILE_HEADER) + pPE->FileHeader.SizeOfOptionalHeader + sizeof(DWORD));

	pAct = pDump;

	/* Copy DOS HEADER */
	memcpy(pAct, (LPVOID)hModule, sizeof (IMAGE_DOS_HEADER));
	dwFinalSize += sizeof (IMAGE_DOS_HEADER);

	/* Copy PADDING */
	memcpy(pAct + dwFinalSize, (LPVOID)(hModule + dwFinalSize), (DWORD)pPE - (DWORD)((DWORD)pDosHeader + sizeof (IMAGE_DOS_HEADER)));
	dwFinalSize += (DWORD)pPE - (DWORD)((DWORD)pDosHeader + sizeof (IMAGE_DOS_HEADER));

	/* Copy NT HEADER */
	memcpy(pAct + dwFinalSize, (LPVOID)pPE, sizeof (IMAGE_FILE_HEADER) + pPE->FileHeader.SizeOfOptionalHeader + sizeof(DWORD));
	dwFinalSize += sizeof (IMAGE_FILE_HEADER) + pPE->FileHeader.SizeOfOptionalHeader + sizeof(DWORD);

	/* Copy Sections */
	memcpy(pAct + dwFinalSize, (LPVOID)pSection, sizeof (IMAGE_SECTION_HEADER) * pPE->FileHeader.NumberOfSections);
	dwFinalSize += sizeof (IMAGE_SECTION_HEADER) * pPE->FileHeader.NumberOfSections;

	dwAlign = AlignSize(dwFinalSize, pPE->OptionalHeader.FileAlignment);
	for (; dwFinalSize < dwAlign; dwFinalSize++)
		*(pAct + dwFinalSize) = 0;

	for (i = 0; i < pPE->FileHeader.NumberOfSections; i++)
	{
		memcpy(pAct + dwFinalSize, (LPVOID)(hModule + pSection[i].VirtualAddress), pSection[i].SizeOfRawData);
		dwFinalSize += pSection[i].SizeOfRawData;
		dwAlign = AlignSize(dwFinalSize, pPE->OptionalHeader.FileAlignment);
		for (; dwFinalSize < dwAlign; dwFinalSize++)
			*(pAct + dwFinalSize) = 0;
	}

    pDosHeader = (PIMAGE_DOS_HEADER)pAct;
    pPE = (PIMAGE_NT_HEADERS)((DWORD)pAct + pDosHeader->e_lfanew);

	// FIX OEP
	pPE->OptionalHeader.AddressOfEntryPoint = dwOEP - hModule;

	// Fix Import

    pPE->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress = ImportDirectoryRVA;
	//pPE->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size = 0;

	// RESET Security
    pPE->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_SECURITY].VirtualAddress = 0;
	pPE->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_SECURITY].Size = 0;

	// RESET Relocation
    pPE->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress = 0;
	pPE->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size = 0;

    if ((hFile = CreateFileA("my_dump.exe", (GENERIC_READ | GENERIC_WRITE),
                             FILE_SHARE_READ | FILE_SHARE_READ,
                             NULL, CREATE_ALWAYS, 0, NULL)) == INVALID_HANDLE_VALUE)
	{
        return FALSE;
	}
    WriteFile(hFile, pAct, dwFinalSize, &dwWritten, NULL);
    if (dwWritten != dwFinalSize)
	{
        return FALSE;
	}
	CloseHandle(hFile);
	VirtualFree(pDump, dwAllocSize, 0);
	return TRUE;
}