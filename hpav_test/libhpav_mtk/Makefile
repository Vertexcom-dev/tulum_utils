BASE_DIR = ..

OBJ_DIR = .
SRC_DIR = .
INC_DIR = .

SRCS = $(subst $(SRC_DIR)/,,$(wildcard $(SRC_DIR)/*.c))
OBJS = $(addprefix $(OBJ_DIR)/,$(SRCS:.c=.o))

LIB_MTK = libhpav_mtk
LIB_COMM_PATH = $(BASE_DIR)/libhpav

CFLAGS += -I$(INC_DIR) -I$(LIB_COMM_PATH) -fPIC

all: $(LIB_MTK).so $(LIB_MTK).a

debug: CFLAGS += -g
debug: all

$(LIB_MTK).so: $(OBJS)
	$(CC) -shared -fpic -o $@ $(OBJS)

$(LIB_MTK).a: $(OBJS)
	$(AR) -rcv $(LIB_MTK).a $(OBJS)

clean:
	rm -f *.a *.so *.o

cleanall:
	rm -f *.a *.so *.o .depend

ifeq (.depend, $(wildcard .depend))
include .depend
endif

depend:
	$(CC) -MM $(CFLAGS) $(SRCS) > .depend

install: ;
