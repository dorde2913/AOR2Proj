# as guest.s -o guest.o
# ld --oformat binary -N -e _start -o guest guest.o

.globl _start
.code16
_start:
	mov $0x3f8, %dx
    xorw %ax, %ax
loop:
	in (%dx), %al   # al <= input from user, al je sirine 8b, a ax je 16b
	add $1, %al 	# al = al + 1
	out %al, (%dx)  # al => user
	mov $9, %bx		# bx <= 9
	cmp %ax, %bx
	jne loop
	hlt
