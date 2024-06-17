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

    const char *p;
    uint16_t port = 0xE9;
    uint8_t value = 'E';
    uint8_t input;
    inb(0xE9,&input);
    outb(0xE9,input);
    for (p = "Ovo je kod Guest1!\n"; *p; ++p)
        outb(0xE9, *p);



    /*
        INSERT CODE ABOVE THIS LINE
    */

    for (;;)
        asm("hlt");
}
