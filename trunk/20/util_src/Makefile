CC       = gcc -c 
CFLAGS   = -O3
LD       = gcc -o
BITS	 := 32
LDFLAGS  = -static -Wl,-s
CFLAGS   += -Wall -Wno-unused -Wno-format -msse2 \
	    -fomit-frame-pointer -mthreads
LDLIBS   = -lpsapi -lshlwapi
MD       = mkdir -p
SRC      = src
SUB_DIR  = $(SRC)/mhook-lib
SUBMK    = $(MAKE) -C $(SUB_DIR)
DEP      = .dep
X86FLAG  = -m32
X64FLAG  = -m64
OBJECTS  = $(DEP)/portable.o $(DEP)/inipara.o $(DEP)/ice_error.o \
	   $(DEP)/safe_ex.o $(DEP)/resource.o
DISTDIR  = Release
OUT1     = $(DISTDIR)/libmhook$(BITS).a
OUT2     = $(DISTDIR)/portable$(BITS).dll
RC       = windres
RCFLAGS  = -l "LANGUAGE 4,2" -J rc -O coff
DLLFLAGS += -shared -Wl,--out-implib,$(DISTDIR)/portable$(BITS).lib
MKDLL	 += $(LD) $(DLLFLAGS) -shared -L$(DISTDIR) -lmhook

EXEC     = \
    @echo Starting Compile... \
    $(shell $(MD) $(DISTDIR) 2>/dev/null) \
    $(shell $(MD) $(DEP) 2>/dev/null) \

ifeq ($(BITS),32)
    CFLAGS += $(X86FLAG)
    LDFLAGS += $(X86FLAG)
else
    ifeq ($(BITS),64)
        CFLAGS	+= $(X64FLAG)
        LDFLAGS += $(X64FLAG)
	RCFLAGS += -F pe-x86-64
    endif
endif

all		      : $(OUT1) $(OUT2)
$(OUT1)		      : $(SUB_DIR)/Makefile
	$(call SUBMK)
$(OUT2)		      : $(OBJECTS)
	$(LD) $@ $(OBJECTS) $(DLLFLAGS) $(OUT1) $(LDLIBS) $(LDFLAGS)
$(DEP)/portable.o     : $(SRC)/portable.c $(SRC)/portable.h
	$(call EXEC)
	$(CC) $< $(CFLAGS) -o $@
$(DEP)/inipara.o      : $(SRC)/inipara.c $(SRC)/inipara.h
	$(CC) $< $(CFLAGS) -o $@
$(DEP)/safe_ex.o      : $(SRC)/safe_ex.c $(SRC)/safe_ex.h
	$(CC) $< $(CFLAGS) -o $@
$(DEP)/ice_error.o    : $(SRC)/ice_error.c $(SRC)/ice_error.h
	$(CC) $< $(CFLAGS) -o $@
$(DEP)/resource.o     : $(SRC)/resource.rc
	$(RC) -i $< $(RCFLAGS) -o $@

.PHONY		      : clean
clean                 : 
	-rm -rf $(DISTDIR) $(DEP)


