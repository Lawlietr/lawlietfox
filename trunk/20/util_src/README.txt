HOW TO BUILD portable_src
=================

System requirements
------------------

    - C compiler supporting the C99 standard
	
     mingw64, msys

     MinGW-builds on:
     http://sourceforge.net/projects/mingwbuilds/

     msys project on
     https://sourceforge.net/projects/mingw/files/MSYS/


 Build!
------------------
build x86:

make clean
make

build x64:

make clean
make BITS=64
