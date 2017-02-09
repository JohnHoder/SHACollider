BIN = shacollider
DEPS = $(wildcard src/*.h) src/libbloom/bloom.h
SRC = $(wildcard src/*.c)
OBJ = $(patsubst %.c, %.o, $(SRC))
LIBBLOOM = src/libbloom/build/libbloom.a
LIBLEVELDB = src/leveldb/out-static/libleveldb.a
LIBMEMENV = src/leveldb/out-static/libmemenv.a
LIBSNAPPY = src/snappy/.libs/libsnappy.a
LIBS += $(LIBBLOOM) $(LIBLEVELDB) $(LIBMEMENV) $(LIBSNAPPY) -lm -lpthread


CFLAGS += -Wall

### DEBUG ###
ifdef DEBUG
	CFLAGS += -O0 -DDEBUG -pg
else
	CFLAGS += -O2
endif

.c.o:
	$(CC) -c -o $@ $< $(CFLAGS)

$(BIN): $(OBJ) $(LIBBLOOM) $(LIBLEVELDB) $(LIBSNAPPY)
	$(CXX) -o $@ $^ $(CFLAGS) $(LIBS) $(LDFLAGS)

$(LIBBLOOM):
	$(MAKE) -C src/libbloom

$(LIBLEVELDB):
	$(MAKE) -C src/leveldb

$(LIBMEMENV):
	$(MAKE) -C src/leveldb

$(LIBSNAPPY):
	cd src/snappy; ./autogen.sh
	cd src/snappy; ./configure
	$(MAKE) -C src/snappy

.PHONY: clean
clean:
	rm -f $(OBJ) $(BIN) shadb/

.PHONY: distclean
distclean:
	$(MAKE) -C src/libbloom clean
	$(MAKE) -C src/leveldb clean
	$(MAKE) -C src/snappy clean
