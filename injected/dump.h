#ifndef DUMP_H_
#define DUMP_H_

#include <windows.h>

#include "dbg.h"

BOOL dump(DWORD hModule, DWORD dwOEP, DWORD ImportDirectoryRVA);
BOOL dump_other(DWORD hModule, DWORD dwOEP);

#endif // DUMP_H_