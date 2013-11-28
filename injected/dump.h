#ifndef DUMP_H_
#define DUMP_H_

#include <windows.h>

#include "dbg.h"

BOOL dump(HMODULE hModule, DWORD dwOEP, DWORD ImportDirectoryRVA);

#endif // DUMP_H_