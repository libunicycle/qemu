#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>
#include "hw/boot/uniboot.h"
#include "hw/boot/bootinfo.h"
#include "standard-headers/linux/qemu_fw_cfg.h"

// meminfo struct, max size is 10K
#define MEMINFO_INFO_ADDR (580 * 1024)
// Top of the stack used by this trampoline and unicycle boot process, size is 80K
#define STACK_ADDR (580 * 1024)
#define BOOTINFO_ADDR (590 * 1024)

#define PAGE_SIZE 4096

#define BIT(x) ((uint64_t)1 << (x))
#define ARRAY_SIZE(x) (sizeof(x) / sizeof((x)[0]))
#define ALIGNED(x) __attribute__((aligned(x)))
#define PACKED __attribute__((packed))
#define NORETURN __attribute__((noreturn))
#define BUILD_ASSERT _Static_assert

NORETURN static inline void x86_stop(void) {
    while (true) {
        __asm__ volatile("cli; hlt");
    }
}

static void print(const char *msg) {
    static volatile uint16_t *cursor = (uint16_t *)0xb8000;

    for (const char *p = msg; *p; p++, cursor++) {
        *cursor = *p | (0x4f << 8);
    }
}

NORETURN static void error(const char *msg) {
    print("Boot error: ");
    print(msg);
    x86_stop();
}

#define CR0_PE BIT(0)  // Protected Mode Enable
#define CR0_MP BIT(1)  // Monitor co-processor
#define CR0_EM BIT(2)  // Emulation
#define CR0_TS BIT(3)  // Task switched
#define CR0_NE BIT(5)  // Native FPU exception handling
#define CR0_PG BIT(31) // Paging

#define CR4_PAE BIT(5)         // Physical Address Extension
#define CR4_OSFXSR BIT(9)      // Operating system support for FXSAVE and FXRSTOR instructions
#define CR4_OSXMMEXCPT BIT(10) // Operating System Support for Unmasked SIMD Floating-Point Exceptions

#define MSR_EXT_FEATURES 0xc0000080

// flags for MSR_EXT_FEATURES
#define MSR_EXT_FEATURES_LONG_MODE BIT(8) // Long mode (64 bits)
#define MSR_EXT_FEATURES_NO_EXECUTE BIT(11) // enables NXE paging bit

static uint64_t x86_rdmsr(uint32_t id) {
    uint32_t eax, edx;
    __asm__ volatile("rdmsr" : "=a"(eax), "=d"(edx) : "c"(id));

    uint64_t ret = edx;
    ret <<= 32;
    ret |= eax;

    return ret;
}

// write model specific register, set value into edx:eax
static void x86_wrmsr(uint32_t id, uint64_t val) {
    uint32_t eax = (uint32_t)val;
    uint32_t edx = (uint32_t)(val >> 32);
    __asm__ volatile("wrmsr" ::"c"(id), "a"(eax), "d"(edx));
}

static uint32_t x86_get_cr0(void) {
    uint32_t val;
    __asm__ volatile("mov %%cr0, %0" : "=r"(val));
    return val;
}

static void x86_set_cr0(uint32_t val) { __asm__ volatile("mov %0, %%cr0" ::"r"(val)); }

static uint32_t x86_get_cr4(void) {
    uint32_t val;
    __asm__ volatile("mov %%cr4, %0" : "=r"(val));
    return val;
}

static void x86_set_cr4(uint32_t val) { __asm__ volatile("mov %0, %%cr4" ::"r"(val)); }

#define NULL_SELECTOR 0x0
#define CODE_SELECTOR 0x8
#define DATA_SELECTOR 0x10

// Top 16 bits is 4K page aligned address, low 16 bits are page flags
typedef uint64_t page_entry;
BUILD_ASSERT(sizeof(page_entry) == 8, "page structure must be 64-bit long");

#define PAGE_PRESENT BIT(0)
#define PAGE_WRITABLE BIT(1)
#define PAGE_USERMODE BIT(2) // if the page flag is set then user-mode allows access this memory
#define PAGE_WRITE_THROUGH BIT(3)
#define PAGE_CACHE_DISABLE BIT(4)
#define PAGE_ACCESSED BIT(5) // system accessed this page
#define PAGE_DIRTY BIT(6)
#define PAGE_LARGE BIT(7) // 1G, 2M or 4K page

page_entry p4_table[PAGE_SIZE / sizeof(page_entry)] ALIGNED(PAGE_SIZE);
page_entry p3_table[PAGE_SIZE / sizeof(page_entry)] ALIGNED(PAGE_SIZE);

static void setup_identity_page_table(void) {
    // setup page table root
    // TODO, make P3 huge pages working both in Qemu and VmWare
    p4_table[0] = (uintptr_t)p3_table | PAGE_WRITABLE | PAGE_PRESENT;
    // initialize p3-level entries
    uint32_t address = PAGE_WRITABLE | PAGE_PRESENT | PAGE_LARGE; // large P3 page is 1G size (1^30)
    for (size_t i = 0; i < ARRAY_SIZE(p3_table); i++) {
        p3_table[i] = address;
        address += (1 << 30);
    }

    __asm__ volatile("mov %0, %%cr3" ::"r"(p4_table));
}

static void fpu_init(void) {
    uint32_t cr0 = x86_get_cr0();
    cr0 &= ~CR0_EM; // clear coprocessor emulation
    cr0 |= CR0_MP;  // set coprocessor monitoring
    cr0 |= CR0_NE;  // set native exceptions
    x86_set_cr0(cr0);

    __asm__ volatile("fninit");
}

static void sse_init(void) {
    uint32_t cr4 = x86_get_cr4();
    cr4 |= (CR4_OSFXSR | CR4_OSXMMEXCPT);
    x86_set_cr4(cr4);
}

#define barrier() __asm__("" : : : "memory")

typedef struct FWCfgDmaAccess {
    uint32_t control;
    uint32_t length;
    uint64_t address;
} __attribute__((packed)) FWCfgDmaAccess;

/* QEMU_CFG_DMA_CONTROL bits */
#define BIOS_CFG_DMA_CTL_ERROR   0x01
#define BIOS_CFG_DMA_CTL_READ    0x02
#define BIOS_CFG_DMA_CTL_SKIP    0x04
#define BIOS_CFG_DMA_CTL_SELECT  0x08

#define BIOS_CFG_DMA_ADDR_HIGH 0x514
#define BIOS_CFG_DMA_ADDR_LOW  0x518

static void outl(uint32_t value, uint16_t port) {
    __asm__("outl %0, %w1" : : "a"(value), "Nd"(port));
}

#define bswap(x) _Generic(x, uint16_t : __builtin_bswap16, uint32_t : __builtin_bswap32, uint64_t : __builtin_bswap64)(x)

#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
#define cpu_to_le(x) (x)
#define le_to_cpu(x) (x)
#define cpu_to_be(x) bswap(x)
#define be_to_cpu(x) bswap(x)
#else
#define cpu_to_le(x) bswap(x)
#define le_to_cpu(x) bswap(x)
#define cpu_to_be(x) (x)
#define be_to_cpu(x) (x)
#endif

static void bios_cfg_read_entry(void *buf, uint16_t entry, uint32_t len) {
    FWCfgDmaAccess access;
    uint32_t control = (entry << 16) | BIOS_CFG_DMA_CTL_SELECT
                        | BIOS_CFG_DMA_CTL_READ;

    access.address = cpu_to_be((uint64_t)(uint32_t)buf);
    access.length = cpu_to_be(len);
    access.control = cpu_to_be(control);

    barrier();

    outl(cpu_to_be((uint32_t)&access), BIOS_CFG_DMA_ADDR_LOW);

    while (be_to_cpu(access.control) & ~BIOS_CFG_DMA_CTL_ERROR) {
        barrier();
    }
}

static uint32_t read_app_entry(void) {
    // application is loaded at this point, we need to read its entry point
    uint32_t app_entry;
    bios_cfg_read_entry(&app_entry, FW_CFG_KERNEL_ENTRY, 4);
    return app_entry;
}

struct PACKED e820_mmap_entry {
    uint64_t base_addr;
    uint64_t length;
    uint32_t type;
};

static void parse_e820_info(void) {
    void *e820_data = (void*)MEMINFO_INFO_ADDR;
    uint32_t size = *(uint32_t*)e820_data;
    size -= 4; // header size

    if (size == 0) {
        error("Empty e820 data");
    }

    if (size % 20 != 0) {
        error("e820 data size is not multiple of 20 bytes");
    }

    size_t in_num = size / 20;
    size_t out_num = in_num - 1; // minus one special case - reserved area around 640K
    size_t mmap_size = sizeof(struct uniboot_memory_map) + out_num * sizeof(struct uniboot_memory_area);

    struct uniboot_entry *entry = bootinfo_alloc(struct uniboot_entry);
    entry->type = UNIBOOT_ENTRY_MEMORY_MAP;
    entry->length = mmap_size;

    struct uniboot_memory_map *mmap = bootinfo_alloc_size(mmap_size);
    mmap->num = out_num;

    struct e820_mmap_entry *in = e820_data + 4;
    struct uniboot_memory_area *out = mmap->areas;
    for (size_t i = 0; i < in_num; i++, in++) {
        uint32_t type = UNIBOOT_MEM_UNUSABLE;
        switch (in->type) {
            case 1: type = UNIBOOT_MEM_RAM; break;
            case 2: type = UNIBOOT_MEM_RESERVED; break;
        }
        uint64_t start = in->base_addr;
        uint64_t length = in->length;

        // handle special case
        // for some reason e820 QEMU gives a non-page aligned reserved address 0x9fc00-0xa0000
        // that's a bit strange and does not look right. Area up to 640K should be usable RAM.
        if (start + length == 0x9fc00) {
            // expand the end the region to 640K
            length = 0xa0000 - start;
        } else if (start == 0x9fc00) {
            continue;
            // both start and end point to 640K and this RESERVED region becomes empty
        }

        out->type = type;
        out->start = start;
        out->length = length;

        out++;
    }
}

struct descriptor_table {
    uint16_t limit;
    uint16_t address;
    uint8_t address_16_23;
    uint8_t access; // access and type
    uint8_t flags;  // limit 16-19 and flags;
    uint8_t address_24_31;
};

#define SEG_NULL \
    { 0, 0, 0, 0, 0, 0 }
#define SEG_CODE_64(dpl) \
    { 0, 0, 0, (((1 /*p*/) << 7) | ((dpl) << 5) | 0x18 | ((0 /*c*/) << 2)), (((0 /*d*/) << 6) | ((1 /*l*/) << 5)), 0 }
#define SEG_DATA_64(dpl) \
    { 0xffff, 0, 0, (0x92 | ((dpl) << 5)), 0x8f, 0 }

const struct descriptor_table gdt64[] ALIGNED(8) = {
    SEG_NULL, SEG_CODE_64(0), SEG_DATA_64(0),
};

struct PACKED gdt64_pointer {
    uint16_t size;
    uint32_t pointer_low;
    uint32_t pointer_high;
};

struct gdt64_pointer gdt64_pointer ALIGNED(8) = {
    .size = sizeof(gdt64) - 1,
    .pointer_low = (uintptr_t)gdt64,
    .pointer_high = 0,
};

void start64(struct uniboot_info *info);

void _start(void) {
    // Qemu initialized and prepopulated part of boot_info
    bootinfo_reinit((void*)BOOTINFO_ADDR, 10240);
    parse_e820_info();
    bootinfo_finalize();

    fpu_init();
    sse_init();

    // enable PAE
    x86_set_cr4(x86_get_cr4() | CR4_PAE);

    // set long mode bit
    uint64_t mode_msr = x86_rdmsr(MSR_EXT_FEATURES);
    mode_msr |= MSR_EXT_FEATURES_LONG_MODE | MSR_EXT_FEATURES_NO_EXECUTE;
    x86_wrmsr(MSR_EXT_FEATURES, mode_msr);

    // enable paging
    setup_identity_page_table();
    x86_set_cr0(x86_get_cr0() | CR0_PG);

        // load global description table
    __asm__ volatile("lgdt %0" ::"m"(gdt64_pointer));

    __asm__ volatile("mov %0, %%esp"::"irm"(STACK_ADDR - 8)); // 8 bytes that x86_64 ABI uses for %eip and %cs values
    __asm__ volatile(""::"D"(BOOTINFO_ADDR));   // first argument in ARM64 calling convention
    // jump to long mode. 'call' does not work in qemu https://bugs.launchpad.net/qemu/+bug/1699867
    __asm__ volatile("push %0; push %1; lret"::"irm"(CODE_SELECTOR), "p"(read_app_entry()));
    __builtin_unreachable();
}
