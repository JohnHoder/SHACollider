BIN = shacollider
DEPS = $(wildcard src/*.h) src/libbloom/bloom.h
SRC = $(wildcard src/*.c)
OBJ = $(patsubst %.c, %.o, $(SRC))
LIBBLOOM = src/libbloom/build/libbloom.a
LIBS += $(LIBBLOOM) -lm


CFLAGS += -Wall

DEBUG = 1

### DEBUG ###
ifeq ($(DEBUG), 1)
	CFLAGS += -O0 -DDEBUG
else
	CFLAGS += -O2
endif

.c.o:
	@echo "[+] $(CC) $< -> $@"
	@$(CC) -c -o $@ $< $(CFLAGS)

$(BIN): $(OBJ) $(LIBBLOOM)
	@echo "[+] $(CC) $^ -> $@"
	@$(CC) -o $@ $^ $(CFLAGS) $(LIBS) $(LDFLAGS)

src/libbloom/build/libbloom.a:
	$(MAKE) -C src/libbloom

.PHONY: clean

clean:
	$(MAKE) -C src/libbloom clean
	@rm -f $(OBJ) $(BIN)
	@echo "[+] objects and bins cleaned"
