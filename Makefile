BIN = shacollider
DEPS = $(wildcard src/*.h) src/libbloom/bloom.h
SRC = $(wildcard src/*.c)
OBJ = $(patsubst %.c, %.o, $(SRC))
LIBBLOOM = src/libbloom/build/libbloom.a
LIBLEVELDB = src/leveldb/out-static/libleveldb.a
LIBMEMENV = src/leveldb/out-static/libmemenv.a
LIBSNAPPY = src/snappy/.libs/libsnappy.a
LIBS += -lm -lpthread

CFLAGS += -Wall -pedantic


.PHONY: all
all: $(BIN)

.PHONY: debug
debug: $(BIN)-debug

.c.o:
	$(CC) -c -o $@ $< $(CFLAGS)

$(BIN): $(OBJ) $(LIBBLOOM) $(LIBLEVELDB) $(LIBMEMENV) $(LIBSNAPPY)
	$(CXX) -o $@ $^ $(CFLAGS) -O3 -march=native $(LIBS) $(LDFLAGS)
	strip $@

$(BIN)-debug: $(OBJ) $(LIBBLOOM) $(LIBLEVELDB) $(LIBMEMENV) $(LIBSNAPPY)
	$(CXX) -o $@ $^ $(CFLAGS) -O0 -DDEBUG -pg -g $(LIBS) $(LDFLAGS)

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

.PHONY: prof
prof: $(BIN)-debug
	./$(BIN)-debug
	gprof $(BIN)-debug gmon.out > perf-analysis.txt

.PHONY: clean
clean:
	rm -f $(OBJ) $(BIN) shadb/

.PHONY: distclean
distclean:
	$(MAKE) -C src/libbloom clean
	$(MAKE) -C src/leveldb clean
	$(MAKE) -C src/snappy clean
