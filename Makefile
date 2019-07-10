CC = gcc
AS = as
LD = ld


default: kern
	@$(CC) -fPIC vm.c -o vm

kern:
	nasm -o kernel.bin kernel/boot.asm
	@#$(AS) --32 -o boot.o kernel/boot.asm
	@#$(LD) $(LDFLAGS) -m elf_i386 --oformat binary -o kernel.bin boot.o

clean:
	rm *.o kernel.bin vm
