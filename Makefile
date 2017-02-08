PROG = shacollider
DEPS = sha256.h sha_types.h
OBJ = sha256.o main.o

DEBUG = 1

### DEBUG ###
ifeq ($(DEBUG), 1)
	DBGFLAGS = -O0 -DDEBUG
	CFLAGS += $(DBGFLAGS)
else
	CFLAGS += -O2
endif



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
