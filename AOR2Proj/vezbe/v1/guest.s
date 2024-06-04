# as guest.s -o guest.o
# ld --oformat binary -N -e _start -o guest guest.o

.globl _start
.code16
_start:
	mov $0x3f8, %dx
    xorw %ax, %ax
loop:
	out %al, (%dx)
	inc %ax
	mov $9, %bx
	cmp %ax, %bx
	jne loop
	hlt
