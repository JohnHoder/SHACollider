BIN = shacollider
DEPS = $(wildcard src/*.h)
SRC = $(wildcard src/*.c)
OBJ = $(patsubst %.c, %.o, $(SRC))

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

$(BIN): $(OBJ)
	@echo "[+] $(CC) $^ -> $@"
	@$(CC) -o $@ $^ $(CFLAGS) $(LIBS) $(LDFLAGS)

.PHONY: clean

clean:
	@echo "[+] objects and bins cleaned"
	@rm -f $(OBJ) $(BIN)