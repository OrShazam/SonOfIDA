# SonOfIDA
reversed malware\
this repository contains both the source exe and dll\
as well as a C code I produced for both\
Anatomy is quite simple:\
exe: add exports for everything kernel32.dll exports in the dll but make it a forward export\
so we won't have to work hard, then replace every file's import from kernel32\
to our crafted kerne132.dll\ 
dll: contains a mini C2 as DllMain - which will now be called whenever a process\
from an infected image attempts to load kernel32.dll


