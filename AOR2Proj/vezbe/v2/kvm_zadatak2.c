// Prevođenje:
//    gcc kvm_zadatak2.c -o kvm_zadatak2
// Pokretanje:
//    ./kvm_zadatak2 guest
//
// Koristan link: https://www.kernel.org/doc/html/latest/virt/kvm/api.html
//
// Zadatak: Omogućiti ispravno izvršavanje gost asemblerskog programa. Gost program pristupa serijsom portu 0x3f8 (out i in instrukcija), pa
//          je potrebno emulirati serijski port 0x3f8 i parametar out instrukcije ispisati na standardnom izlazu. 
//          Pristup I/O portovima preko IN/OUT instrukcija izaziva VM izlazak. 
//          Program se završava kada korisnik unese broj 8.
//
#define _GNU_SOURCE
#include <fcntl.h>
#include <linux/kvm.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <unistd.h>

int main(int argc, char *argv[]) {
  uint8_t *mem;
  int kvm_fd;
  int vm_fd;
  int vcpu_fd;
  int ret;
  int stop = 0;
  int data;
  FILE* img;

  if (argc != 2) {
    printf("The program requests an image to run: %s <guest-image>\n", argv[0]);
    return 1;
  }

  // Sistemski poziv za otvaranje /dev/kvm
  // Povratna vrednost je deskriptor fajla
  kvm_fd = open("/dev/kvm", O_RDWR);
  if (kvm_fd == -1) {
    printf("Failed to open /dev/kvm\n");
    return 1;
  }

  // KVM pruža API preko kog može da se komunicira sa njim
  // Komunikacija se vršio preko Input/Outpu sistemskih poziva
  // int ioctl(int fd, unsigned long request, ...);
  //    fd      - fajl deskriptor
  //    request - zahtev
  //    ...     - parametar koji zavisi od zahteva (ovaj parametar će uglavnom biti adresa)
  // 
  // KVM_CREATE_VM - kreira virtuelnu mašinu bez virtuelnog(ih) procesora i memorije
  vm_fd = ioctl(kvm_fd, KVM_CREATE_VM, 0);
  if (vm_fd == -1) {
    printf("Failed to create vm\n");
    return 1;
  }

  mem = mmap(NULL, 1 << 30, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, 0, 0);
  if (mem == NULL) {
    printf("mmap failed\n");
    return 1;
  }

  // Podesavanje regiona memorije koji ce se koristiti za VM
  // slot            - broj mapiranja. Definisanje novog regiona sa istim slot brojem će zameniti ovo mapiranje.
  // guest_phys_addr - Fizicka adresa kako je gost vidi.
  // memory_size     - velicina regiona.
  // userspace_addr  - početna adresa memorije.
  struct kvm_userspace_memory_region region = {
    .slot = 0,
    .guest_phys_addr = 0,
    .memory_size = 1 << 30,
    .userspace_addr = (uintptr_t)mem
  };
  
  // Parametar: region
  ret = ioctl(vm_fd, KVM_SET_USER_MEMORY_REGION, &region);
  if (ret < 0) {
    printf("ioctl KVM_SET_USER_MEMORY_REGION failed\n");
    return 1;
  }

  // Čitanje gost programa.
  img = fopen(argv[1], "r");
  if (img == NULL) {
    printf("Can not open binary file\n");
    return 1;
  }

  // Popunjavanje gost memorije.
  char *p = (char *)mem;
  while(feof(img) == 0) {
    int r = fread(p, 1, 1024, img);
    p += r;
  }
  fclose(img);

  // Kreiranje virtuelnog CPU
  // Parametar: vCPU ID
  vcpu_fd = ioctl(vm_fd, KVM_CREATE_VCPU, 0);
  if (vcpu_fd < 0) {
    printf("Cannot create vCPU\n");
    return 1;
  }

  // Dohvatanje veličine kvm_run strukture
  // Parametar: /
  int kvm_run_mmap_size = ioctl(kvm_fd, KVM_GET_VCPU_MMAP_SIZE);
  if (kvm_run_mmap_size < 0) {
    printf("ioctl KVM_GET_VCPU_MMAP_SIZE failed\n");
    return 1;
  }

  // Mapirati kvm_run strukturu na koju pokazuje lokalna promenljiva kvm_run
  struct kvm_run *run = (struct kvm_run *)mmap(
      NULL, kvm_run_mmap_size, PROT_READ | PROT_WRITE, MAP_SHARED, vcpu_fd, 0);
  if (run == NULL) {
    printf("mmap kvm_run failed\n");
    return 1;
  }

  struct kvm_regs regs;
  struct kvm_sregs sregs;

  // Parametar: struct kvm_sregs
  ret = ioctl(vcpu_fd, KVM_GET_SREGS, &sregs);
  if (ret == -1) {
    printf("Fetching sregs failed\n");
    return 1;
  }

  sregs.cs.selector = 0;
  sregs.cs.base = 0;

  ret = ioctl(vcpu_fd, KVM_SET_SREGS, &sregs);
  if (ret == -1) {
    printf("Seting sregs failed\n");
    return 1;
  }

  regs.rflags = 2;
  regs.rip = 0;
  // regs.rbx = 3;

  // Parametar: struct kvm_regs
  ret = ioctl(vcpu_fd, KVM_SET_REGS, &regs); 
  if (ret == -1) {
    printf("Seting regs failed\n");
    return 1;
  }

  // Pokretanje gosta i obrada izlaza 
  while(stop == 0) {
    // Parametar: /
    ret = ioctl(vcpu_fd, KVM_RUN, 0);
    if (ret == -1) {
      printf("KVM_RUN failed\n");
      return 1;
    }

    switch (run->exit_reason) {
    case KVM_EXIT_IO:
      if (run->io.direction == KVM_EXIT_IO_OUT && run->io.size == 1 && run->io.port == 0x3f8 && run->io.count == 1) {
        printf("IO port: %x, data: %d\n", run->io.port, *(((char*)run)+ run->io.data_offset));
      } else if (run->io.direction == KVM_EXIT_IO_IN && run->io.port == 0x3f8) {
        // Otkomentarisati narednu liniju i pokrenite gost program sa "in (%dx), %al", pa sa "in (%dx), %ax"
        // printf("Count: %d Size: %d Offset: %lld \n", run->io.count, run->io.size, run->io.data_offset); 
        printf("Enter a number between 0 and 8:\n");
        scanf("%d", &data);
        char *data_in = (((char*)run)+ run->io.data_offset);
        // Napomena: U x86 podaci se smeštaju u memoriji po little endian poretku.
        (*data_in) = data;
      }
      break;
    case KVM_EXIT_HLT:
      printf("KVM_EXIT_HLT\n");
      stop = 1;
      break;
    }
  }

  close(kvm_fd);
  return 0;
}
