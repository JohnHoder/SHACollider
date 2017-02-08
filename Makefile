PROG = shacollider
DEPS = sha256.h sha_types.h
OBJ = sha256.o main.o

DEBUG = 1

### DEBUG ###
ifeq ($(DEBUG), 1)
	DBGFLAGS = -ggdb -DDEBUG
	CFLAGS += $(DBGFLAGS)
endif

CFLAGS += -02

%.o: %.c $(DEPS)
	@echo "[+] CC $< -> $@"
	@$(CC) -c -o $@ $< $(CFLAGS)

$(PROG): $(OBJ)
	@echo "[+] CC $^ -> $@"
	@$(CC) -o $@ $^ $(CFLAGS) $(LIBS) $(LDFLAGS)

.PHONY: clean

clean:
	@echo "[+] objects and bins cleaned"
	@rm -f *.o $(PROG)
