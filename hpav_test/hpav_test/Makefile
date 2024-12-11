BASE_DIR = ..

OBJ_DIR = .
SRC_DIR = .
INC_DIR = .

SRCS = $(subst $(SRC_DIR)/,,$(wildcard $(SRC_DIR)/*.c))
OBJS = $(addprefix $(OBJ_DIR)/,$(SRCS:.c=.o))

LIB_COMM_PATH = $(BASE_DIR)/libhpav
LIB_MTK_PATH = $(BASE_DIR)/libhpav_mtk
LIB_JSON_PATH = $(BASE_DIR)/libjson

LIB_COMM = $(LIB_COMM_PATH)/libhpav.a
LIB_MTK = $(LIB_MTK_PATH)/libhpav_mtk.a
VERSION_H = $(LIB_COMM_PATH)/hpav_version.h
LIB_JSON = $(LIB_JSON_PATH)/libhpav_json.a

CFLAGS += -I$(INC_DIR) \
	-I$(LIB_COMM_PATH) -I$(LIB_MTK_PATH) -I$(LIB_JSON_PATH) \
	-Wl,--start-group  -L$(LIB_COMM_PATH) -L$(LIB_MTK_PATH) -L$(LIB_JSON_PATH) -Wl,--end-group

prefix ?= /usr/local
sysconfdir ?= $(prefix)/etc

BIN = hpav_test

all: $(BIN)

debug: CFLAGS += -g
debug: all

$(BIN): $(OBJS) $(LIB_COMM) $(LIB_MTK) $(LIB_JSON)
	$(CC) $(CFLAGS) -o $@ $(OBJS) $(LIB_COMM) $(LIB_MTK) $(LIB_JSON) $(LDFLAGS) -lpcap -lssl -lcrypto -lz -lrt

main.o: $(VERSION_H)

$(LIB_COMM): libhpav.all

$(LIB_MTK): libhpav_mtk.all

$(LIB_JSON): libjson.all
%.all:
	$(MAKE) -C $(BASE_DIR)/$*

%.clean:
	$(MAKE) -C $(BASE_DIR)/$* clean

clean:
	rm -f *.o $(BIN)

cleanall: clean libhpav.clean libhpav_libhpav_libhpav_mtk.clean libjson.clean
	rm -f *.o .depend

ifeq (.depend, $(wildcard .depend))
include .depend
endif

depend:
	$(CC) -MM $(CFLAGS) $(SRCS) > .depend

install: $(BIN)
	[ -d $(prefix)/sbin ] || install -m 0755 -o root -g root -d $(prefix)/sbin
	install -m 0755 -o root -g root $(BIN) $(prefix)/sbin/
	install -d $(sysconfdir)/bash_completion.d
	install -m 644 -o root -g root bash_completion \
	        $(sysconfdir)/bash_completion.d/hpav_test

.PHONY: install
