#GCC = arm-hisiv300-linux-gcc
GCC = arm-hisiv100nptl-linux-gcc
#GCC = gcc
SRC = main.c
INCLUDE = 
LIB = 
LDFLAG = -lpthread
EXEC = holepd

all:
	$(GCC) -o $(EXEC) $(SRC) $(INCLUDE) $(LIB) $(LDFLAG)
	@cp -f $(EXEC) ~/i5k/initrd/nfsroot
	@sync

gdb:
	$(GCC) -g -o $(EXEC) $(SRC) $(INCLUDE) $(LIB) $(LDFLAG)
	@cp -f $(EXEC) ~/i5k/initrd/nfsroot
	@sync

clean:
	rm $(EXEC)
