BASE_DIR = ..

OBJ_DIR = .
SRC_DIR = .
INC_DIR = .

SRCS = $(subst $(SRC_DIR)/,,$(wildcard $(SRC_DIR)/*.c))
OBJS = $(addprefix $(OBJ_DIR)/,$(SRCS:.c=.o))

LIB_JSON = libhpav_json
CFLAGS += -I$(INC_DIR) -fPIC

all: $(LIB_JSON).so $(LIB_JSON).a

debug: CFLAGS += -g
debug: all 

$(LIB_JSON).so: $(OBJS)
	$(CC) -shared -fpic -o $@ $(OBJS)

$(LIB_JSON).a: $(OBJS)
	$(AR) -rcv $(LIB_JSON).a $(OBJS)

clean:
	rm -f *.a *.so *.o

cleanall:
	rm -f *.a *.so *.o .depend

ifeq (.depend, $(wildcard .depend))
include .depend
endif

depend:
	$(CC) -MM $(CFLAGS) $(SRCS) > .depend
