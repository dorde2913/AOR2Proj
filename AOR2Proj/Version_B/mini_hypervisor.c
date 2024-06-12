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
static void setup_long_mode(struct vm *vm, struct kvm_sregs *sregs)
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
    // 2MB page size
    // pd[0] = PDE64_PRESENT | PDE64_RW | PDE64_USER | PDE64_PS;

    // 4KB page size
    // -----------------------------------------------------
    pd[0] = PDE64_PRESENT | PDE64_RW | PDE64_USER | pt_addr;
    // PC vrednost se mapira na ovu stranicu.
    pt[0] = page | PDE64_PRESENT | PDE64_RW | PDE64_USER;
    // SP vrednost se mapira na ovu stranicu. Vrednost 0x6000 je proizvoljno tu postavljena.
    pt[511] = 0x6000 | PDE64_PRESENT | PDE64_RW | PDE64_USER;

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

bool check_arguments(int argc, char* argv[],char*** img, int* mem_size, int* page_size,int* num_guests){

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
                printUsage();
                return false;
            }
            *num_guests = argc - (i+1);
            if (img!=NULL){
                *img = (char**)malloc(((argc-(i+1))*sizeof(char*)));
                if (*img == NULL) {
                    printf("BAD ALLOC");
                    return false;
                }
            }
            else return false;
            while (i + 1 < argc) {

                (*img)[c] = (char*) malloc(100*sizeof(char));
                if ((*img)[c]!=NULL){
                    strcpy((*img)[c],argv[i+1]);
                }

                c++;
                //printf("%s\n",*img);
                i++; // Skip the next argument
            }
            if (i+1<argc && c == 0){
                printf("Error: Missing guest image file argument.\n");
                printUsage();
                return false;
            }


        } else {
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
};
sem_t mutex;

void* vm_main(void* args){
    struct guest_args gargs = *((struct guest_args*)args);

    struct vm vm;
    struct kvm_sregs sregs;
    struct kvm_regs regs;
    int stop = 0;
    int ret = 0;
    FILE* img;

    char* file_name = gargs.file_name;
    int page_size = gargs.page_size;
    int MEM_SIZE = gargs.mem_size;

    if (init_vm(&vm, MEM_SIZE)) {
        printf("Failed to init the VM\n");
        return NULL;
    }

    if (ioctl(vm.vcpu_fd, KVM_GET_SREGS, &sregs) < 0) {
        perror("KVM_GET_SREGS");
        return NULL;
    }

    setup_long_mode(&vm, &sregs);

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

    while(stop == 0) {
        ret = ioctl(vm.vcpu_fd, KVM_RUN, 0);
        if (ret == -1) {
            printf("KVM_RUN failed\n");
            return NULL;
        }

        switch (vm.kvm_run->exit_reason) {
            case KVM_EXIT_IO:
                if (vm.kvm_run->io.direction == KVM_EXIT_IO_OUT && vm.kvm_run->io.port == 0xE9) {
                    char *p = (char *)vm.kvm_run;
                    sem_wait(&mutex);
                    printf("%c", *(p + vm.kvm_run->io.data_offset));
                    sem_post(&mutex);
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




    if (!check_arguments(argc, argv,&file_names,&mem_size,&page_size, &num_guests)) return -1;
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
        args[i].file_name = file_names[i];
        args[i].page_size = page_size;
        args[i].mem_size = MEM_SIZE;
        pthread_create(&threads[i],NULL,vm_main,(void*) (&args[i]));
    }

    for (int i=0;i<num_guests;i++){
        pthread_join(threads[i],NULL);
    }
    free(threads);
}
