#ifndef _SOLIDSTUFF_H
#define _SOLIDSTUFF_H

#include <Windows.h>

#include "dbg.h"
#include "pestuff.h"
#include "hookstuff.h"
#include "dump.h"

LONG CALLBACK ProtectionFaultVectoredHandler(PEXCEPTION_POINTERS ExceptionInfo);

#endif