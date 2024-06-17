#include <stddef.h>
#include <stdint.h>
#include <string.h>

static void outb(uint16_t port, uint8_t value) {
    asm("outb %0,%1" : /* empty */ : "a" (value), "Nd" (port) : "memory");
}

static void inb(uint16_t port,uint8_t *dest){
    asm("inb %1,%0":"=a"(*dest):"d"(port));
}

static void f_open(char* file_name,char* rw){
    int port = 0x278;

    outb(port,0x01);//signal za open
    for (char* p = file_name;*p!='\0';p++){
        outb(port,*p);
    }
    outb(port,'\0');

    for (char* p = rw;*p!='\0';p++){
        outb(port,*p);
    }
    outb(port,'\0');
    uint8_t ret;
    inb(port,&ret);

    if (ret != 0){
        for (;;)
            asm("hlt");
    }
}
static void f_write(char* file_name, char* line){
    int port = 0x278;

    outb(port,0x04);//signal za write
    for (char* p = file_name;*p!='\0';p++){
        outb(port,*p);
    }
    outb(port,'\0');

    for (char* p = line;*p!='\0';p++){
        outb(port,*p);
    }
    outb(port,'\0');
}

static void f_close(char* file_name){
    int port = 0x278;

    outb(port,0x02);//signal za close
    for (char* p = file_name;*p!='\0';p++){
        outb(port,*p);
    }
    outb(port,'\0');
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
    char* file_name = "test.txt";
    f_open(file_name,"w");

    f_write(file_name,"Ovo je test upisa u fajl\n");
    f_write(file_name,"Ovo je druga linija testa\n");

    f_close(file_name);
    /*
        INSERT CODE ABOVE THIS LINE
    */

    for (;;)
        asm("hlt");
}
