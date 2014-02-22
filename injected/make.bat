del SolidStuff.dll

@cl.exe dbg.c /W3 /GF /GS- /GA /MT /nologo /c /TC /D_CRT_SECURE_NO_WARNINGS
@cl.exe dump.c /W3 /GF /GS- /GA /MT /nologo /c /TC /D_CRT_SECURE_NO_WARNINGS
@cl.exe hookstuff.c /W3 /GF /GS- /GA /MT /nologo /c /TC /D_CRT_SECURE_NO_WARNINGS
@cl.exe pestuff.c /W3 /GF /GS- /GA /MT /nologo /c /TC /D_CRT_SECURE_NO_WARNINGS
@cl.exe SolidStuff.c /W3 /GF /GS- /GA /MT /nologo /c /TC /D_CRT_SECURE_NO_WARNINGS

@link dbg.obj dump.obj hookstuff.obj pestuff.obj SolidStuff.obj lib/LDE64.lib /dll /release /subsystem:console /SUBSYSTEM:CONSOLE,5.01 /OSVERSION:5.1 /out:SolidStuff.dll /MACHINE:IX86 /MANIFEST:NO /merge:.rdata=.text

del *.obj
del *.exp

pause