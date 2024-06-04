
all: guest.img kvm_zadatak3

kvm_zadatak3: kvm_zadatak3.c
	gcc kvm_zadatak3.c -o kvm_zadatak3

guest.img: guest.o
	ld -T guest.ld guest.o -o guest.img

guest.o: guest.c
	$(CC) -m64 -ffreestanding -fno-pic -c -o $@ $^

clean:
	rm -f kvm_zadatak3 guest.o guest.img