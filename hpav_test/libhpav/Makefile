BASE_DIR = ..

OBJ_DIR = .
SRC_DIR = .
INC_DIR = .

SRCS = $(subst $(SRC_DIR)/,,$(wildcard $(SRC_DIR)/*.c))
OBJS = $(addprefix $(OBJ_DIR)/,$(SRCS:.c=.o))

LIB_COMM = libhpav
LIB_MTK_PATH = $(BASE_DIR)/libhpav_mtk

CFLAGS += -I$(INC_DIR) -I$(LIB_MTK_PATH) -fPIC

all: $(LIB_COMM).so $(LIB_COMM).a

debug: CFLAGS += -g
debug: all

$(LIB_COMM).so: $(OBJS)
	$(CC) -shared -fpic -o $@ $(OBJS)

$(LIB_COMM).a: $(OBJS)
	$(AR) -rcv $(LIB_COMM).a $(OBJS)

clean:
	rm -f *.a *.so *.o

cleanall:
	rm -f *.a *.so *.o  .depend

ifeq (.depend, $(wildcard .depend))
include .depend
endif

depend:
	$(CC) -MM $(CFLAGS) $(SRCS) > .depend

install: ;
