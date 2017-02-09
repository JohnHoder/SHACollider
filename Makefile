BIN = shacollider
DEPS = $(wildcard src/*.h) src/libbloom/bloom.h
SRC = $(wildcard src/*.c)
OBJ = $(patsubst %.c, %.o, $(SRC))
LIBBLOOM = src/libbloom/build/libbloom.a
LIBLEVELDB = src/leveldb/out-static/libleveldb.a
LIBMEMENV = src/leveldb/out-static/libmemenv.a
LIBS += $(LIBBLOOM) $(LIBLEVELDB) $(LIBMEMENV) -lm -lpthread -lc++


CFLAGS += -Wall

### DEBUG ###
ifdef DEBUG
	CFLAGS += -O0 -DDEBUG -pg
else
	CFLAGS += -O2
endif

.c.o:
	$(CC) -c -o $@ $< $(CFLAGS)

$(BIN): $(OBJ) $(LIBBLOOM) $(LIBLEVELDB)
	# need to link with C++ linker :-/
	$(CXX) -o $@ $^ $(CFLAGS) $(LIBS) $(LDFLAGS)

$(LIBBLOOM):
	$(MAKE) -C src/libbloom

$(LIBLEVELDB):
	$(MAKE) -C src/leveldb

$(LIBMEMENV):
	$(MAKE) -C src/leveldb

.PHONY: clean
clean:
	rm -f $(OBJ) $(BIN)

.PHONY: distclean
distclean:
	$(MAKE) -C src/libbloom clean
	$(MAKE) -C src/leveldb clean
