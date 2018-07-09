#include "qemu/osdep.h"
#include "qemu/option.h"
#include "hw/hw.h"
#include "hw/nvram/fw_cfg.h"
#include "uniboot.h"
#include "load_uniboot.h"
#include "bootinfo.h"
#include "hw/loader.h"
#include "elf.h"
#include "sysemu/sysemu.h"
#include "qemu/error-report.h"
#include "qemu-common.h"

/* Show uniboot debug output */
//#define DEBUG_UNIBOOT

#ifdef DEBUG_UNIBOOT
#define ub_debug(a...) error_report(a)
#else
#define ub_debug(a...)
#endif

/* Memory app for uniboot apps:
 * 600K - 640K  - uniboot 32bit trampoline code
 * 590K - 600K  - bootinfo struct
 * 580K - 590K  - memory map area filled by ROM code (uniboot.S) and consumed by trampoline code
 * 500K - 580K  - stack for uniboot32 tampoline and early unicycle boot
 *
 * Somewhere in BIOS - uniboot.bin code
 */
#define BOOTINFO_ADDR (590 * 1024)

static void populate_segments_entry(struct elf_segments_list *segments) {
    // Init segments info
    ub_debug("Uniboot application conatains %d segments", segments->num);
    size_t segment_list_size = sizeof(struct uniboot_segment_list) + segments->num * sizeof(struct uniboot_segment);

    struct uniboot_entry *entry = bootinfo_alloc(struct uniboot_entry);
    entry->type = UNIBOOT_ENTRY_SEGMENT_LIST;
    entry->length = segment_list_size;

    struct uniboot_segment_list *segs = bootinfo_alloc_size(segment_list_size);
    segs->num = segments->num;

    for (int i = 0; i < segments->num; i++) {
        segs->segments[i].type = segments->segments[i].type;
        segs->segments[i].flags = segments->segments[i].flags;
        segs->segments[i].offset = segments->segments[i].offset;
        segs->segments[i].vaddr = segments->segments[i].vaddr;
        segs->segments[i].paddr = segments->segments[i].paddr;
        segs->segments[i].filesz = segments->segments[i].filesz;
        segs->segments[i].memsz = segments->segments[i].memsz;
        segs->segments[i].align = segments->segments[i].align;
    }
}

static void populate_sectionss_entry(struct elf_sections_list *sections) {
    // Init sections info
    ub_debug("Uniboot application conatains %d sections", sections->num);
    size_t section_list_size = sizeof(struct uniboot_section_list) + sections->num * sizeof(struct uniboot_segment);

    struct uniboot_entry *entry = bootinfo_alloc(struct uniboot_entry);
    entry->type = UNIBOOT_ENTRY_SECTION_LIST;
    entry->length = section_list_size;

    struct uniboot_section_list *secs = bootinfo_alloc_size(section_list_size);
    secs->num = sections->num;

    for (int i = 0; i < sections->num; i++) {
        secs->sections[i].name = sections->sections[i].name;
        secs->sections[i].type = sections->sections[i].type;
        secs->sections[i].flags = sections->sections[i].flags;
        secs->sections[i].addr = sections->sections[i].addr;
        secs->sections[i].size = sections->sections[i].size;
        secs->sections[i].addralign = sections->sections[i].addralign;
        secs->sections[i].entsize = sections->sections[i].entsize;
    }
}

void load_uniboot(FWCfgState *fw_cfg, const char *app_filename) {
    uint64_t elf_low, elf_high;
    uint64_t elf_entry;
    int elf_size;

    struct elf_segments_list segments;
    memset(&segments, 0, sizeof(segments));

    struct elf_sections_list sections;
    memset(&sections, 0, sizeof(sections));

    elf_size = load_elf_ram_sym(app_filename, NULL, NULL, NULL, &elf_entry,
                        &elf_low, &elf_high, NULL, 0, EM_NONE,
                        0, 0, NULL, true, NULL, &segments, &sections);
    if (elf_size < 0) {
        error_report("Error while loading elf kernel");
        exit(1);
    }
    if (segments.num == 0) {
        error_report("Uniboot application contains no ELF segments");
        exit(1);
    }
    if (sections.num == 0) {
        error_report("Uniboot application contains no ELF sections");
        exit(1);
    }
    uint32_t load_addr = elf_low;
    size_t app_size = elf_high - elf_low;
    uint32_t entry_addr = elf_entry;

    ub_debug("qemu: loading uniboot application (%#zx bytes) with entry %#x",
             app_size, entry_addr);

    void *app_buf = g_malloc(app_size);
    if (rom_copy(app_buf, load_addr, app_size) != app_size) {
        error_report("Error while fetching elf kernel from rom");
        exit(1);
    }

    // load application elf binary
    fw_cfg_add_i32(fw_cfg, FW_CFG_KERNEL_ENTRY, entry_addr);
    fw_cfg_add_i32(fw_cfg, FW_CFG_KERNEL_ADDR, load_addr);
    fw_cfg_add_i32(fw_cfg, FW_CFG_KERNEL_SIZE, app_size);
    fw_cfg_add_bytes(fw_cfg, FW_CFG_KERNEL_DATA, app_buf, app_size);

    // Load uniboot 32 bit trampoline
    char *trampoline_file = qemu_find_file(QEMU_FILE_TYPE_BIOS, "uniboot_trampoline32.elf");
    elf_size = load_elf(trampoline_file, NULL, NULL, NULL, &elf_entry,
                           &elf_low, &elf_high, NULL, 0, EM_386,
                           0, 0);
    g_free(trampoline_file);

    if (elf_size < 0) {
        error_report("Error while loading 32bit uniboot trampoline: %d", elf_size);
        exit(1);
    }
    uint32_t tramp_load_addr = elf_low;
    size_t tramp_size = elf_high - elf_low;
    uint32_t tramp_entry_addr = elf_entry;
    ub_debug("qemu: loading uniboot trampoline kernel (%#zx bytes at %#x) with entry %#x",
             tramp_size, tramp_load_addr, tramp_entry_addr);

    void *tramp_buf = g_malloc(tramp_size);
    if (rom_copy(tramp_buf, tramp_load_addr, tramp_size) != tramp_size) {
        error_report("Error while fetching uniboot trampoline from rom");
        exit(1);
    }

    // load uniboot 32bit trampoline
    fw_cfg_add_i32(fw_cfg, FW_CFG_SETUP_ENTRY, tramp_entry_addr);
    fw_cfg_add_i32(fw_cfg, FW_CFG_SETUP_ADDR, tramp_load_addr);
    fw_cfg_add_i32(fw_cfg, FW_CFG_SETUP_SIZE, tramp_size);
    fw_cfg_add_bytes(fw_cfg, FW_CFG_SETUP_DATA, tramp_buf, tramp_size);

    // boot info struct
    uint8_t bootinfo_buffer[10240];
    bootinfo_init(bootinfo_buffer, 10240);

    populate_segments_entry(&segments);
    populate_sectionss_entry(&sections);

    void *boot_info = bootinfo_finalize();
    size_t bootinfo_data_size = bootinfo_size_consumed();
    void *bootinfo_data = g_memdup(boot_info, bootinfo_data_size);

    fw_cfg_add_i32(fw_cfg, FW_CFG_INITRD_ADDR, BOOTINFO_ADDR);
    fw_cfg_add_i32(fw_cfg, FW_CFG_INITRD_SIZE, bootinfo_data_size);
    fw_cfg_add_bytes(fw_cfg, FW_CFG_INITRD_DATA, bootinfo_data, bootinfo_data_size);

    option_rom[nb_option_roms].name = "uniboot.bin";
    option_rom[nb_option_roms].bootindex = 0;
    nb_option_roms++;
}
