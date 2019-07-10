#include <err.h>
#include <fcntl.h>
#include <linux/kvm.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

void print_regs(struct kvm_regs *regs) {
#define print_reg(name)            \
  printf("%6.4s: 0x%016lx", #name, \
         *(uint64_t *)(((char *)regs) + offsetof(struct kvm_regs, name)))

  printf("\n\n");

  print_reg(rax);
  print_reg(rbx);
  print_reg(rcx);
  print_reg(rdx);
  printf("\n");
  print_reg(rsi);
  print_reg(rdi);
  print_reg(rsp);
  print_reg(rbp);
  printf("\n");
  print_reg(r8);
  print_reg(r9);
  print_reg(r10);
  print_reg(r11);
  printf("\n");
  print_reg(r12);
  print_reg(r13);
  print_reg(r14);
  print_reg(r15);
  printf("\n");
  print_reg(rip);
  printf("\n");
}

static int run_kernel(unsigned char *code, int len) {
  static int kvm = -1;

  if (kvm == -1) kvm = open("/dev/kvm", O_RDWR | O_CLOEXEC);

  int ret;

  ret = ioctl(kvm, KVM_GET_API_VERSION, NULL);
  if (ret == -1) err(1, "KVM_GET_API_VERSION");
  if (ret != 12) errx(1, "KVM_GET_API_VERSION %d, expected 12", ret);

  ret = ioctl(kvm, KVM_CHECK_EXTENSION, KVM_CAP_USER_MEMORY);
  if (ret == -1) err(1, "KVM_CHECK_EXTENSION");
  if (!ret) errx(1, "Required extension KVM_CAP_USER_MEM not available");

  // Next, we need to create a virtual machine (VM), which represents everything
  // associated with one emulated system, including memory and one or more CPUs.
  // KVM gives us a handle to this VM in the form of a file descriptor:
  int vmfd = ioctl(kvm, KVM_CREATE_VM, (unsigned long)0);

  size_t mem_size = 16 * 1024 * 1024;

  int code_start = 0x1000;

  // For our simple example, we'll allocate a single page of memory to hold our
  // code, using mmap() directly to obtain page-aligned zero-initialized memory:
  char *mem = mmap(NULL, mem_size, PROT_READ | PROT_WRITE,
                   MAP_SHARED | MAP_ANONYMOUS, -1, 0);
  if (mem == NULL) {
    perror("mmap size_of_segment");
    exit(EXIT_FAILURE);
  };

  // We then need to copy our machine code into it:
  memcpy(mem + code_start, code, len);

  // And finally tell the KVM virtual machine about its spacious new 4096-byte
  // memory:
  struct kvm_userspace_memory_region code_region = {
      .slot = 0,
      .guest_phys_addr = 0x0,
      .memory_size = mem_size,
      .userspace_addr = (uint64_t)mem,
  };
  ioctl(vmfd, KVM_SET_USER_MEMORY_REGION, &code_region);

  // Now that we have a VM, with memory containing code to run, we need to
  // create a virtual CPU to run that code. A KVM virtual CPU represents the
  // state of one emulated CPU, including processor registers and other
  // execution state. Again, KVM gives us a handle to this VCPU in the form of a
  // file descriptor:
  int vcpufd = ioctl(vmfd, KVM_CREATE_VCPU, (unsigned long)0);

  // Each virtual CPU has an associated struct kvm_run data structure, used to
  // communicate information about the CPU between the kernel and user space. In
  // particular, whenever hardware virtualization stops (called a "vmexit"),
  // such as to emulate some virtual hardware, the kvm_run structure will
  // contain information about why it stopped. We map this structure into user
  // space using mmap(), but first, we need to know how much memory to map,
  // which KVM tells us with the KVM_GET_VCPU_MMAP_SIZE ioctl():
  int mmap_size = ioctl(kvm, KVM_GET_VCPU_MMAP_SIZE, NULL);

  struct kvm_run *run =
      mmap(NULL, mmap_size, PROT_READ | PROT_WRITE, MAP_SHARED, vcpufd, 0);

  struct kvm_sregs sregs;

  ioctl(vcpufd, KVM_GET_SREGS, &sregs);
  sregs.cs.base = 0;
  ioctl(vcpufd, KVM_SET_SREGS, &sregs);

  struct kvm_regs regs = {
      .rip = code_start,
      .rsp = 0,
      .rax = 0,
      .rbx = 0,
      .rflags = 0x2,
  };
  ioctl(vcpufd, KVM_SET_REGS, &regs);

  int result = 0;

  while (1) {
    ioctl(vcpufd, KVM_RUN, NULL);

    int stat = run->exit_reason;
    if (stat == KVM_EXIT_MMIO) {
      void *addr = (void *)run->mmio.phys_addr;
      if (run->mmio.is_write) {
        printf("mmio write %p\n", addr);
      } else {
        printf("mmio read  %p\n", addr);
      }
      continue;
    }

    if (stat == KVM_EXIT_HLT || stat == KVM_EXIT_SHUTDOWN) {
      // pull the register information
      ioctl(vcpufd, KVM_GET_REGS, &regs);
      result = regs.rax;
      break;
    }

    if (stat == KVM_EXIT_IO) {
      if (run->io.direction == KVM_EXIT_IO_OUT && run->io.port == 0x3f8) {
        ioctl(vcpufd, KVM_GET_REGS, &regs);
        print_regs(&regs);
        continue;
      }

      if (run->io.direction == KVM_EXIT_IO_OUT && run->io.port == 0xfe) {
        ioctl(vcpufd, KVM_GET_REGS, &regs);
        size_t tsc = (regs.rdx << 32) | regs.rax;
        printf("%zu\n", tsc);
        continue;
      }

      continue;
    }

    if (stat == KVM_EXIT_INTERNAL_ERROR) {
      printf("INTERNAL ERROR\n");
      exit(1);
    }

    ioctl(vcpufd, KVM_GET_REGS, &regs);

    printf("unhandled exit: %d at rip = %p\n", run->exit_reason,
           (void *)regs.rip);
    exit(1);
  }

  ioctl(vcpufd, KVM_GET_REGS, &regs);

  // a big ugly hexdump thing. Skips empty lines
  int written = 0;
  int line_len = 16;
  printf("hexdump:\n");
  for (int i = 0; i < mem_size; i++) {
    if (written == 0) {
      // check if we need to skip the line.
      int checksum = 0;  // assume we skip
      for (int o = 0; o < line_len && o + i < mem_size; o++)
        checksum |= mem[i + o];
      if (checksum == 0) {
        i += line_len;
        continue;
      }
      printf("  %06x: ", i);
    }
    unsigned char b = ((unsigned char *)mem)[i];
    printf("%02x ", b);
    written++;
    if (written == line_len) {
      printf("\n");
      written = 0;
    }
  }

  print_regs(&regs);

  close(vmfd);
  close(vcpufd);
  munmap(run, mmap_size);
  munmap(mem, mem_size);

  return result;
}

int main(int argc, char **argv) {
  int fd;
  struct stat sb;

  fd = open(argv[1], O_RDONLY);
  fstat(fd, &sb);

  void *code =
      mmap(NULL, sb.st_size, PROT_WRITE | PROT_EXEC, MAP_PRIVATE, fd, 0);
  if (code == MAP_FAILED) exit(-1);
  int size = sb.st_size;

  run_kernel(code, size);
  return 0;
}
