vpath %.c src/
vpath %.h include/
HDRS = $(wildcard include/*.h)
SRCS = $(wildcard src/*.c)
OBJS = $(patsubst src/%.c,%.o,$(SRCS))

BINS = $(patsubst src/%.bin.c,%.bin,$(wildcard src/*.bin.c))

ifdef FUZZ
FUZZ_BINS = $(patsubst src/%.fuzz.c,%.fuzz,$(wildcard src/*.fuzz.c))
endif

LIB_OBJS = $(filter-out %.bin.o,$(filter-out %.fuzz.o,$(OBJS)))
LIB = libfakedns.a

INCLUDES = -I ./include
GEN_CFLAGS = -O0 -Wall -Wextra -Werror -g

ifdef FUZZ
CC=clang
SAN_CFLAGS = -fsanitize=fuzzer-no-link,address
FUZZ_CFLAGS = -fsanitize=fuzzer,address
endif

ALL_CFLAGS = $(CFLAGS) $(GEN_CFLAGS) $(INCLUDES) $(SAN_CFLAGS)

%.fuzz : %.fuzz.o $(LIB)
	$(CC) $(ALL_CFLAGS) $(FUZZ_CFLAGS) $< $(LIB) -o $@

%.bin : %.bin.o $(LIB)
	$(CC) $(ALL_CFLAGS) $< $(LIB) -o $@

%.a : $(LIB_OBJS)
	$(AR) -rcs $@ $^

%.o : %.c $(HDRS)
	$(CC) $(ALL_CFLAGS) -c $< -o $@


.PHONY : all
all : $(OBJS) $(LIB) $(BINS) $(FUZZ_BINS)

.PHONY : clean
clean :
	rm -f *.o *.bin *.fuzz *.a	
