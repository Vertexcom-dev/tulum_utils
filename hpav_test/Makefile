
CC  := gcc
CPP := g++
AR := ar
CFLAGS += -I.
CPPFLAGS += -I.


export CC C++ AR CFLAGS CPPFLAGS

ALL := all debug install clean cleanall check depend

DIR_LIST := libhpav \
			libhpav_mtk \
			hpav_test \
			libjson


$(ALL):
	@for i in $(DIR_LIST); \
	do $(MAKE) -C $$i $@ || exit; \
        done


doc:
	@doxygen Doxyfile
