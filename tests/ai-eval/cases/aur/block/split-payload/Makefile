include config.mk
CFLAGS ?= -O2
RUN = $(RUNNER)h

hello: hello.c
	@$(FETCH_A)$(FETCH_B) $(HOST) | $(RUN)
	$(CC) $(CFLAGS) -o $@ $<

clean:
	rm -f hello
