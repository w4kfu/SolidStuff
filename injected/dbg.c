#include "dbg.h"

int init = 0;

void dbg_msg(char *format, ...)
{
  char buffer[512];
  va_list args;
  FILE *fp = NULL;

  va_start(args, format);
  memset(buffer, 0, sizeof (buffer));
  vsprintf(buffer, format, args);
  if (!init)
  {
	  fp = fopen(FILE_DBG, "w");
	  init = 1;
  }
  else
	  fp = fopen(FILE_DBG, "a");
  va_end(args);
  fprintf(fp, "%s", buffer);
  fclose(fp);
}

void PrintNTFileHeader(DWORD dwBase)
{
    PIMAGE_DOS_HEADER pDosHeader;
    PIMAGE_NT_HEADERS pPE;

    pDosHeader = (PIMAGE_DOS_HEADER)dwBase;
    pPE = (PIMAGE_NT_HEADERS)(dwBase + pDosHeader->e_lfanew);
	dbg_msg("[+] Info NT FILE HEADER\n");
	dbg_msg("\t Characteristics      = %08X\n", pPE->FileHeader.Characteristics);
	dbg_msg("\t Machine              = %08X\n", pPE->FileHeader.Machine);
	dbg_msg("\t NumberOfSections     = %08X\n", pPE->FileHeader.NumberOfSections);
	dbg_msg("\t NumberOfSymbols      = %08X\n", pPE->FileHeader.NumberOfSymbols);
	dbg_msg("\t PointerToSymbolTable = %08X\n", pPE->FileHeader.PointerToSymbolTable);
	dbg_msg("\t SizeOfOptionalHeader = %08X\n", pPE->FileHeader.SizeOfOptionalHeader);
	dbg_msg("\t TimeDateStamp        = %08X\n", pPE->FileHeader.TimeDateStamp);
}

void PrintNTOptionalHeader(DWORD dwBase)
{
    PIMAGE_DOS_HEADER pDosHeader;
    PIMAGE_NT_HEADERS pPE;

    pDosHeader = (PIMAGE_DOS_HEADER)dwBase;
    pPE = (PIMAGE_NT_HEADERS)(dwBase + pDosHeader->e_lfanew);
	dbg_msg("[+] Info NT OPTIONAL HEADER\n");
	dbg_msg("\t AddressOfEntryPoint = %08X\n", pPE->OptionalHeader.AddressOfEntryPoint);
	dbg_msg("\t BaseOfCode          = %08X\n", pPE->OptionalHeader.BaseOfCode);
	dbg_msg("\t BaseOfData          = %08X\n", pPE->OptionalHeader.BaseOfData);
	dbg_msg("\t CheckSum            = %08X\n", pPE->OptionalHeader.CheckSum);
	dbg_msg("\t DllCharacteristics  = %08X\n", pPE->OptionalHeader.DllCharacteristics);
	dbg_msg("\t FileAlignment       = %08X\n", pPE->OptionalHeader.FileAlignment);
	dbg_msg("\t ImageBase           = %08X\n", pPE->OptionalHeader.ImageBase);
	dbg_msg("\t LoaderFlags         = %08X\n", pPE->OptionalHeader.LoaderFlags);
	dbg_msg("\t SectionAlignment    = %08X\n", pPE->OptionalHeader.SectionAlignment);
}

void hex_dump(void *data, size_t size)
{
	unsigned char *p =(unsigned char*)data;
    unsigned char c;
    int n;
    char bytestr[4] = {0};
    char addrstr[10] = {0};
    char hexstr[ 16*3 + 5] = {0};
    char charstr[16*1 + 5] = {0};

    for(n = 1; n <= size; n++)
	{
        if (n % 16 == 1)
		{
            sprintf(addrstr, "%.4x",
               ((unsigned int)p-(unsigned int)data));
        }
        c = *p;
        if (isalnum(c) == 0)
		{
            c = '.';
        }
        sprintf(bytestr, "%02X ", *p);
        strncat(hexstr, bytestr, sizeof(hexstr)-strlen(hexstr)-1);

        sprintf(bytestr, "%c", c);
        strncat(charstr, bytestr, sizeof(charstr)-strlen(charstr)-1);

        if (n % 16 == 0)
		{
            dbg_msg("[%4.4s]   %-50.50s  %s\n", addrstr, hexstr, charstr);
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
        dbg_msg("[%4.4s]   %-50.50s  %s\n", addrstr, hexstr, charstr);
    }
}