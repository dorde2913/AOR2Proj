#include <stddef.h>
#include <stdint.h>


static void outb(uint16_t port, uint8_t value) {
    asm("outb %0,%1" : /* empty */ : "a" (value), "Nd" (port) : "memory");
}
static void inb(uint16_t port,uint8_t *dest){
    asm("inb %1,%0":"=a"(*dest):"d"(port));
}
void
__attribute__((noreturn))
__attribute__((section(".start")))
_start(void) {

	/*
		INSERT CODE BELOW THIS LINE
	*/
    uint8_t input[2];
    const char *p;
    uint16_t port = 0xE9;
    //uint8_t value = 'E';
    inb(0xE9,&input[0]);
    input[1] = '\0';
    outb(0xE9,input[0]);
    outb(0xE9,input[1]);
    //asm("outb %0,%1" : /* empty */ : "a" (value), "Nd" (port) : "memory");
    for (p = "Hello, world!\n"; *p; ++p)
        outb(port, *p);



	/*
		INSERT CODE ABOVE THIS LINE
	*/

	for (;;)
		asm("hlt");
}
