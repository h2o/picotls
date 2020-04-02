SRC=$(wildcard *.c)
OBJ=$(SRC:.c=.o)
CLANG?=clang-6.0
LLC?=llc-6.0

all: $(SRC) $(OBJ)

$(OBJ): %.o

%.o: %.c
	$(CLANG) $(CFLAGS) -O2 -fno-gnu-inline-asm -emit-llvm -c $< -o - | $(LLC) -march=bpf -filetype=obj -o $@

clean:
	rm -rf *.o

.PHONY: %.o

