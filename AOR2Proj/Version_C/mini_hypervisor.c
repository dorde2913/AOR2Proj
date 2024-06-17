#include <stdio.h>
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <string.h>
#include <stdint.h>
#include <linux/kvm.h>
#include <stdbool.h>
#include <pthread.h>
#include <semaphore.h>
#define PDE64_PRESENT 1
#define PDE64_RW (1U << 1)
#define PDE64_USER (1U << 2)
#define PDE64_PS (1U << 7)

// CR4
#define CR4_PAE (1U << 5)

// CR0
#define CR0_PE 1u
#define CR0_PG (1U << 31)

#define EFER_LME (1U << 8)
#define EFER_LMA (1U << 10)

struct vm {
    int kvm_fd;
    int vm_fd;
    int vcpu_fd;
    char *mem;
    struct kvm_run *kvm_run;
};

int init_vm(struct vm *vm, size_t mem_size)
{
    struct kvm_userspace_memory_region region;
    int kvm_run_mmap_size;

    vm->kvm_fd = open("/dev/kvm", O_RDWR);
    if (vm->kvm_fd < 0) {
        perror("open /dev/kvm");
        return -1;
    }

    vm->vm_fd = ioctl(vm->kvm_fd, KVM_CREATE_VM, 0);
    if (vm->vm_fd < 0) {
        perror("KVM_CREATE_VM");
        return -1;
    }

    vm->mem = mmap(NULL, mem_size, PROT_READ | PROT_WRITE,
                   MAP_SHARED | MAP_ANONYMOUS, -1, 0);
    if (vm->mem == MAP_FAILED) {
        perror("mmap mem");
        return -1;
    }

    region.slot = 0;
    region.flags = 0;
    region.guest_phys_addr = 0;
    region.memory_size = mem_size;
    region.userspace_addr = (unsigned long)vm->mem;
    if (ioctl(vm->vm_fd, KVM_SET_USER_MEMORY_REGION, &region) < 0) {
        perror("KVM_SET_USER_MEMORY_REGION");
        return -1;
    }

    vm->vcpu_fd = ioctl(vm->vm_fd, KVM_CREATE_VCPU, 0);
    if (vm->vcpu_fd < 0) {
        perror("KVM_CREATE_VCPU");
        return -1;
    }

    kvm_run_mmap_size = ioctl(vm->kvm_fd, KVM_GET_VCPU_MMAP_SIZE, 0);
    if (kvm_run_mmap_size <= 0) {
        perror("KVM_GET_VCPU_MMAP_SIZE");
        return -1;
    }

    vm->kvm_run = mmap(NULL, kvm_run_mmap_size, PROT_READ | PROT_WRITE,
                       MAP_SHARED, vm->vcpu_fd, 0);
    if (vm->kvm_run == MAP_FAILED) {
        perror("mmap kvm_run");
        return -1;
    }

    return 0;
}

static void setup_64bit_code_segment(struct kvm_sregs *sregs)
{
    struct kvm_segment seg = {
            .base = 0,
            .limit = 0xffffffff,
            .present = 1, // Prisutan ili učitan u memoriji
            .type = 11, // Code: execute, read, accessed
            .dpl = 0, // Descriptor Privilage Level: 0 (0, 1, 2, 3)
            .db = 0, // Default size - ima vrednost 0 u long modu
            .s = 1, // Code/data tip segmenta
            .l = 1, // Long mode - 1
            .g = 1, // 4KB granularnost
    };

    sregs->cs = seg;

    seg.type = 3; // Data: read, write, accessed
    sregs->ds = sregs->es = sregs->fs = sregs->gs = sregs->ss = seg;
}

// Omogucavanje long moda.
// Vise od long modu mozete prociati o stranicenju u glavi 5:
// https://www.amd.com/content/dam/amd/en/documents/processor-tech-docs/programmer-references/24593.pdf
// Pogledati figuru 5.1 na stranici 128.
static void setup_long_mode(struct vm *vm, struct kvm_sregs *sregs, int PAGE_SIZE)
{
    // Postavljanje 4 niva ugnjezdavanja.
    // Svaka tabela stranica ima 512 ulaza, a svaki ulaz je veličine 8B.
    // Odatle sledi da je veličina tabela stranica 4KB. Ove tabele moraju da budu poravnate na 4KB.
    uint64_t page = 0;
    uint64_t pml4_addr = 0x1000; // Adrese su proizvoljne.
    uint64_t *pml4 = (void *)(vm->mem + pml4_addr);

    uint64_t pdpt_addr = 0x2000;
    uint64_t *pdpt = (void *)(vm->mem + pdpt_addr);

    uint64_t pd_addr = 0x3000;
    uint64_t *pd = (void *)(vm->mem + pd_addr);

    uint64_t pt_addr = 0x4000;
    uint64_t *pt = (void *)(vm->mem + pt_addr);


    pml4[0] = PDE64_PRESENT | PDE64_RW | PDE64_USER | pdpt_addr;
    pdpt[0] = PDE64_PRESENT | PDE64_RW | PDE64_USER | pd_addr;


    switch(PAGE_SIZE){
        case 0x200000:
            pd[0] = PDE64_PRESENT | PDE64_RW | PDE64_USER | PDE64_PS;
            // PC vrednost se mapira na ovu stranicu.
            pt[0] = page | PDE64_PRESENT | PDE64_RW | PDE64_USER;
            // SP vrednost se mapira na ovu stranicu. Vrednost 0x6000 je proizvoljno tu postavljena.
            pt[511] = 0x6000 | PDE64_PRESENT | PDE64_RW | PDE64_USER;
            break;
        case 0x1000:
            pd[0] = PDE64_PRESENT | PDE64_RW | PDE64_USER | pt_addr;
            // PC vrednost se mapira na ovu stranicu.
            pt[0] = page | PDE64_PRESENT | PDE64_RW | PDE64_USER;
            // SP vrednost se mapira na ovu stranicu. Vrednost 0x6000 je proizvoljno tu postavljena.
            pt[511] = 0x6000 | PDE64_PRESENT | PDE64_RW | PDE64_USER;
            break;
    }

    // 2MB page size
    // pd[0] = PDE64_PRESENT | PDE64_RW | PDE64_USER | PDE64_PS;

    // 4KB page size
    // -----------------------------------------------------
    //pd[0] = PDE64_PRESENT | PDE64_RW | PDE64_USER | pt_addr;
    // PC vrednost se mapira na ovu stranicu.
    //pt[0] = page | PDE64_PRESENT | PDE64_RW | PDE64_USER;
    // SP vrednost se mapira na ovu stranicu. Vrednost 0x6000 je proizvoljno tu postavljena.
    //pt[511] = 0x6000 | PDE64_PRESENT | PDE64_RW | PDE64_USER;

    // FOR petlja služi tome da mapiramo celu memoriju sa stranicama 4KB.
    // Zašti je uslov i < 512? Odgovor: jer je memorija veličine 2MB.
    // for(int i = 0; i < 512; i++) {
    // 	pt[i] = page | PDE64_PRESENT | PDE64_RW | PDE64_USER;
    // 	page += 0x1000;
    // }
    // -----------------------------------------------------

    // Registar koji ukazuje na PML4 tabelu stranica. Odavde kreće mapiranje VA u PA.
    sregs->cr3  = pml4_addr;
    sregs->cr4  = CR4_PAE; // "Physical Address Extension" mora biti 1 za long mode.
    sregs->cr0  = CR0_PE | CR0_PG; // Postavljanje "Protected Mode" i "Paging"
    sregs->efer = EFER_LME | EFER_LMA; // Postavljanje  "Long Mode Active" i "Long Mode Enable"

    // Inicijalizacija segmenata procesora.
    setup_64bit_code_segment(sregs);
}

void printUsage() {
    printf("Usage: program_name [options]\n");
    printf("Options:\n");
    printf("  -m, --memory <2|4|8>   Set memory size (in GB)\n");
    printf("  -p, --page <2|4>       Set page size (in KB)\n");
    printf("  -g, --guest <file.img> Specify guest image file\n");
}

bool check_arguments(int argc, char* argv[],char*** img, int* mem_size, int* page_size,int* num_guests,char*** shared_files, int* num_shared){

    for (int i = 1; i < argc; i++) {

        if (strcmp(argv[i], "--memory") == 0 || strcmp(argv[i], "-m") == 0) {
            if (i + 1 < argc) {
                *mem_size = atoi(argv[i + 1]);
                i++; // Skip the next argument
            } else {
                printf("Error: Missing memory size argument.\n");
                printUsage();
                return false;
            }
        } else if (strcmp(argv[i], "--page") == 0 || strcmp(argv[i], "-p") == 0) {
            if (i + 1 < argc) {
                *page_size = atoi(argv[i + 1]);
                i++; // Skip the next argument
            } else {
                printf("Error: Missing page size argument.\n");
                printUsage();
                return false;
            }
        } else if (strcmp(argv[i], "--guest") == 0 || strcmp(argv[i], "-g") == 0) {
            int c =0;
            if (argc - (i+1) == 0){
                printf("bad args\n");
                return false;
            }
            //*num_guests = argc - (i+1);
            if (img!=NULL){
                *img = (char**)malloc(((argc-(i+1))*sizeof(char*)));
                if (*img == NULL) {
                    printf("BAD ALLOC");
                    return false;
                }
            }
            else return false;
            while (i + 1 < argc && strcmp("--file",argv[i+1])!=0 && strcmp("-f",argv[i+1])!=0) {
                (*img)[c] = (char*) malloc(255*sizeof(char));
                if ((*img)[c]!=NULL){
                    strcpy((*img)[c],argv[i+1]);
                }
                c++;
                i++;
            }
            *num_guests = c;
            if (i+1<argc && c == 0){
                printf("Error: Missing guest image file argument.\n");
                printUsage();
                return false;
            }


        }
        else if(strcmp(argv[i], "--file") == 0 || strcmp(argv[i], "-f") == 0){
            int f = 0;
            if (shared_files != NULL){
                *shared_files = (char**)malloc(((argc-(i+1))*sizeof(char*)));
                if (*shared_files == NULL) {
                    printf("BAD ALLOC");
                    return false;
                }
            }
            else return false;
            while (i + 1 < argc) {
                (*shared_files)[f] = (char*) malloc(255*sizeof(char));
                if ((*shared_files)[f]!=NULL){
                    strcpy((*shared_files)[f],argv[i+1]);
                }
                f++;
                i++;
            }
            *num_shared = f;
            if (i+1<argc && f == 0){
                printf("Error\n");
                printUsage();
                return false;
            }
        }
        else {
            printf("Error: Unknown option '%s'.\n", argv[i]);
            printUsage();
            return false;
        }
    }

    // Validate arguments
    if (*mem_size != 2 && *mem_size  != 4 && *mem_size  != 8) {
        printf("Error: Invalid memory size. Choose 2, 4, or 8 GB.\n");
        return false;
    }
    if (*page_size != 2 && *page_size != 4) {
        printf("Error: Invalid page size. Choose 2 or 4 KB.\n");
        return false;
    }
    if (img == NULL) {
        printf("Error: Guest image file not specified.\n");
        return false;
    }

    // Print parsed values

    // Your logic for handling the arguments goes here

    return true;
}




struct guest_args{
    int mem_size;
    int page_size;
    char* file_name;
    char** shared_files;
    int num_shared;
    int id;
};
sem_t mutex;

typedef struct OpenFiles{
    FILE* file;
    char name[255];
    bool copied;
    struct OpenFiles* next;
}OpenFiles;


char* generateNewName(char* name,char id){
    char* ret = malloc(255);
    strcpy(ret,name);
    printf("%c\n",id);
    bool flag = false;
    char carry;
    char temp;
    int i=0;
    while(ret[i]!='.')i++;
    int index = i;
    temp = ret[i];

    while(ret[i+1]!='\0'){
        carry = ret[i+1];
        ret[i+1] = temp;
        temp = carry;
        i++;
    }
    ret[i+1] = temp;
    ret[i+2] = '\0';
    ret[index] = id;
    printf("%s\n",ret);
    return ret;
    //strcat(name,&carry);
}
void* vm_main(void* args){
    struct guest_args gargs = *((struct guest_args*)args);
    int id;
    struct vm vm;
    struct kvm_sregs sregs;
    struct kvm_regs regs;
    int stop = 0;
    int ret = 0;
    FILE* img;
    int data;

    id = gargs.id;
    char* file_name = gargs.file_name;
    int page_size = gargs.page_size;
    int MEM_SIZE = gargs.mem_size;
    char** shared_files = gargs.shared_files;
    int num_shared = gargs.num_shared;
    int PAGE_SIZE;
    switch(page_size){
        case 2:
            PAGE_SIZE = 0x200000;
            break;
        case 4:
            PAGE_SIZE = 0x1000;
            break;
    }

    if (init_vm(&vm, MEM_SIZE)) {
        printf("Failed to init the VM\n");
        return NULL;
    }

    if (ioctl(vm.vcpu_fd, KVM_GET_SREGS, &sregs) < 0) {
        perror("KVM_GET_SREGS");
        return NULL;
    }

    setup_long_mode(&vm, &sregs,PAGE_SIZE);

    if (ioctl(vm.vcpu_fd, KVM_SET_SREGS, &sregs) < 0) {
        perror("KVM_SET_SREGS");
        return NULL;
    }

    memset(&regs, 0, sizeof(regs));
    regs.rflags = 2;
    regs.rip = 0;
    // SP raste nadole
    regs.rsp = 2 << 20;

    if (ioctl(vm.vcpu_fd, KVM_SET_REGS, &regs) < 0) {
        perror("KVM_SET_REGS");
        return NULL;
    }

    //printf("%s\n",file_name);

    img = fopen(file_name, "r");
    if (img == NULL) {
        printf("Can not open binary file\n");
        return NULL;
    }

    char *p = vm.mem;
    while(feof(img) == 0) {
        int r = fread(p, 1, 1024, img);
        p += r;
    }
    fclose(img);


    bool opening_file = false;
    bool closing_file = false;
    bool writing = false;
    bool reading = false;
    int read_size = 0;

    bool getting_name = false;
    bool getting_mode = false;
    bool getting_size = false;


    char mode[3];
    char name[255];
    char size[255];
    int index =0;
    FILE* current_file;
    OpenFiles *file_list = NULL;

    while(stop == 0) {
        ret = ioctl(vm.vcpu_fd, KVM_RUN, 0);
        if (ret == -1) {
            printf("KVM_RUN failed\n");
            return NULL;
        }

        switch (vm.kvm_run->exit_reason) {
            case KVM_EXIT_IO:
                if (vm.kvm_run->io.direction == KVM_EXIT_IO_OUT && vm.kvm_run->io.port == 0xE9) {
                    sem_wait(&mutex);
                    char *p = (char *)vm.kvm_run;
                    printf("%c", *(p + vm.kvm_run->io.data_offset));
                    sem_post(&mutex);
                }
                else if (vm.kvm_run->io.direction == KVM_EXIT_IO_IN && vm.kvm_run->io.port == 0xE9) {
                    sem_wait(&mutex);
                    printf("Process %d Enter a number between 0 and 8:\n",id);
                    scanf("%d", &data);
                    char *data_in = (((char*)vm.kvm_run)+ vm.kvm_run->io.data_offset);
                    (*data_in) = data;
                    sem_post(&mutex);
                }
                else if (vm.kvm_run->io.direction == KVM_EXIT_IO_IN && vm.kvm_run->io.port == 0x278) {
                    /*
                     * citanje iz fajla
                     */
                    if (reading){
                        if (feof(current_file)){
                            reading = false;
                            char *data_in = (((char*)vm.kvm_run)+ vm.kvm_run->io.data_offset);
                            (*data_in) = '\0';
                        }
                        //printf("reading character from file...\n");
                        char *data_in = (((char*)vm.kvm_run)+ vm.kvm_run->io.data_offset);
                        (*data_in) = fgetc(current_file);

                        if (ferror(current_file))printf("error...\n");
                        //printf("%c\n",*data_in);
                        read_size--;
                        if (read_size == 0) reading = false;
                    }
                    else{
                        char *data_in = (((char*)vm.kvm_run)+ vm.kvm_run->io.data_offset);
                        (*data_in) = '\0';
                    }
                }
                else if (vm.kvm_run->io.direction == KVM_EXIT_IO_OUT && vm.kvm_run->io.port == 0x278) {
                    /*
                     * fopen, fclose, upis u fajl
                     */
                    char *p = (char *)vm.kvm_run;
                    char input = *(p+vm.kvm_run->io.data_offset);//ovo je char koji je poslat
                    /*
                    if (input == '\0') {
                        printf("\n");
                    }
                    printf("%c",input);
                     */
                    switch(input){
                        case 0x01:
                            //signal za pocetak fopen
                            opening_file = true;
                            getting_name = true;
                            index = 0;
                            break;
                        case 0x02:
                            //signal za pocetak fclose
                            closing_file = true;
                            getting_name = true;
                            index = 0;
                            break;
                        case 0x03:
                            //signal za pocetak read
                            reading = true;
                            getting_name = true;
                            index = 0;
                            break;
                        case 0x04:
                            //signal za pocetak write
                            writing = true;
                            getting_name = true;
                            index = 0;
                            break;
                        default:
                            //samo citamo charace test upisa u fajltere, na osnovu flegova odlucujemo sta je
                            if (opening_file && getting_name){
                                name[index] = input;
                                index++;
                                if (input == '\0'){
                                    //imamo name, sada flegovi
                                    getting_name = false;
                                    getting_mode = true;
                                    index = 0;
                                }
                            }
                            else if (opening_file && getting_mode){
                                mode[index] = input;
                                index++;
                                if (input == '\0'){
                                    index = 0;
                                    getting_mode = false;
                                    opening_file = false;
                                    //otvaramo fajl
                                    current_file = fopen(name,mode);
                                    if (!current_file){
                                        printf("COULDNT OPEN FILE %s , in mode %s\n",name,mode);
                                        return false;
                                    }
                                    else{
                                        printf("opened file %s in mode %s\n",name,mode);
                                        //dodaj u listu otvorenih
                                        if (file_list == NULL){
                                            file_list = malloc(sizeof(OpenFiles));
                                            file_list->file = current_file;
                                            strcpy(file_list->name,name);
                                            file_list->next = NULL;
                                            file_list->copied = false;
                                        }
                                        else{
                                            OpenFiles *temp = file_list;
                                            while(temp->next)temp=temp->next;
                                            temp->next = malloc(sizeof(OpenFiles));
                                            temp = temp->next;
                                            temp->file = current_file;
                                            strcpy(temp->name,name);
                                            temp->next = NULL;
                                            temp->copied = false;
                                        }
                                        OpenFiles* temp = file_list;
                                        printf("Open files: ");
                                        while(temp){
                                            printf("%s ",temp->name);
                                            temp = temp->next;
                                        }
                                        printf("\n");
                                    }
                                }
                            }
                            else if (closing_file && getting_name){
                                name[index] = input;
                                index++;
                                if (input == '\0'){
                                    getting_name = false;
                                    closing_file = false;
                                    index = 0;
                                    //nadji fajl koji zatvaramo u listi otvorenih
                                    OpenFiles *temp = file_list;
                                    OpenFiles *prev = NULL;
                                    while(temp && strcmp(temp->name,name)!=0){
                                        prev = temp;
                                        temp=temp->next;
                                    }
                                    if (!temp){
                                        printf("ERROR, attempted close on non-open file\n");
                                        return false;
                                    }
                                    if (prev){
                                        prev->next = temp->next;
                                    }
                                    fclose(temp->file);
                                    printf("Successfully closed file %s\n",temp->name);
                                    free(temp);
                                }
                            }
                            else if (reading && getting_name){
                                name[index] = input;
                                index++;
                                if (input == '\0'){
                                    printf("reading from %s ... \n",name);
                                    getting_name = false;
                                    getting_size = true;
                                    index = 0;
                                    OpenFiles *temp = file_list;
                                    while(temp && strcmp(temp->name,name)!=0)temp=temp->next;
                                    if (!temp){
                                        printf("ERROR, can't read from non-open file\n");
                                        return false;
                                    }
                                    current_file = temp->file;
                                }
                            }
                            else if (reading && getting_size){
                                size[index] = input;
                                index++;
                                if (input == '\0'){
                                    printf("reading %s characters from %s ... \n",size,name);
                                    getting_size = false;
                                    index = 0;
                                    read_size = atoi(size);
                                    fseek(current_file,0,0);
                                }
                            }
                            else if (writing && getting_name){
                                name[index] = input;
                                index++;
                                if (input == '\0'){
                                    getting_name = false;
                                    index = 0;
                                }
                            }
                            else if (writing){
                                if (input == '\0'){
                                    writing = false;
                                    break;
                                }
                                OpenFiles* temp = file_list;

                                while(temp && strcmp(name,temp->name)!=0){
                                    temp=temp->next;
                                }
                                if (!temp) {
                                    printf("ERROR, cant write to non-open file\n");
                                    return false;
                                }
                                //ako je fajl medju deljenim, mora da se napravi nov
                                for (int i=0;i<num_shared;i++){
                                    if (strcmp(temp->name,shared_files[i])==0 && !temp->copied){
                                        //moramo da napravimo nov fajl
                                        printf("pravimo novi fajl\n");
                                        char t = (char)(id+48);
                                        char* h = temp->name;
                                        temp->copied = true;
                                        char* new_name = generateNewName(h,t);
                                        temp->file = fopen(new_name,"w+");
                                        printf("%s\n",new_name);
                                        break;
                                    }
                                }
                                fwrite(&input,1,1,temp->file);
                            }

                            break;
                    }

                }
                continue;
            case KVM_EXIT_HLT:
                printf("KVM_EXIT_HLT\n");
                stop = 1;
                break;
            case KVM_EXIT_INTERNAL_ERROR:
                printf("Internal error: suberror = 0x%x\n", vm.kvm_run->internal.suberror);
                stop = 1;
                break;
            case KVM_EXIT_SHUTDOWN:
                printf("Shutdown\n");
                stop = 1;
                break;
            default:
                printf("Exit reason: %d\n", vm.kvm_run->exit_reason);
                break;
        }

    }
}

int main(int argc, char *argv[])
{
    sem_init(&mutex,0,1);

    int mem_size;// 2,4,8 MB
    int page_size;//2KB ili 2MB
    int MEM_SIZE;
    char** file_names;
    int num_guests;
    char** shared_files;
    int num_shared;



    if (!check_arguments(argc, argv,&file_names,&mem_size,&page_size, &num_guests,&shared_files,&num_shared)) return -1;

    /*
    for (int i=0;i<num_guests;i++){
        printf("%s\n",file_names[i]);
    }


    for (int i=0;i<num_shared;i++){
        printf("%s\n",shared_files[i]);
    }
    */

    pthread_t* threads = malloc(num_guests*sizeof(pthread_t));
    switch(mem_size){
        case 2:
            MEM_SIZE = 0x200000;
            break;
        case 4:
            MEM_SIZE = 0x400000;
            break;
        case 8:
            MEM_SIZE = 0x800000;
            break;
        default:
            break;
    }

    struct guest_args* args = malloc(num_guests*sizeof(struct guest_args));

    for (int i=0;i<num_guests;i++){
        /*
         * za svaki file u file_names treba da se napravi nit
         */
        args[i].id = i;
        args[i].file_name = file_names[i];
        args[i].page_size = page_size;
        args[i].mem_size = MEM_SIZE;
        args[i].shared_files = shared_files;
        args[i].num_shared = num_shared;
        pthread_create(&threads[i],NULL,vm_main,(void*) (&args[i]));
    }

    for (int i=0;i<num_guests;i++){
        pthread_join(threads[i],NULL);
    }
    free(threads);
    free(args);

}
