CFLAGS := -Wall -Wextra
LDFLAGS := -lpthread

.PHONY: all
all: vulnserver

vulnserver: vulnserver.o
	$(CC) $< -o $@ $(LDFLAGS)

%.o: %.c
	$(CC) -c $(CFLAGS) $< -o $@

.PHONY: clean
clean:
	@rm -f vulnserver vulnserver.o
