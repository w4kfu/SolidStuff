@cl.exe inject.c /W3 /GF /GS- /GA /MT /nologo /c /TC /D_CRT_SECURE_NO_WARNINGS
@link inject.obj /release /subsystem:console /SUBSYSTEM:CONSOLE,5.01 /OSVERSION:5.1 /out:inject.exe /MACHINE:IX86 /BASE:0x400000 /MANIFEST:NO  /merge:.rdata=.text /DYNAMICBASE:NO

del *.obj
del *.exp

pause