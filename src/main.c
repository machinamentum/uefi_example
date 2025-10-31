/*
    Author: Josh Huelsman

    A contrived example of a UEFI bootloader that:
     * Sets up a GOP framebuffer
     * Retrieves a memory map
     * Exits boot services
     * Starts executing kernel code built-in to the bootloader
     * kernel sets up a basic Long Mode GDT and IDT
     * kernel installs an interrupt service routine for int 25, then executes int 25

    This uses the gnu-efi library for EFI bindings and Print().
    One could remove the majority of the library dependency by removing
    Print() calls and setting the entries in LibStubUnicodeInterface in
    gnu-efi/lib/data.c to NULL (thus just needing the headers and data.c).

    A lot of this stuff is based on samples and information from
    wiki.osdev.org

    Some x86 jargon:
    * Real Mode is 16-bit compatibility mode
    * Protected Mode is 32-bit mode
    * Long is 64-bit mode
    * Segment is a region of memory with a set of permissions (ie, read/write/execute) and set usage (code, data, system)
      * Largely vesitgial in Long Mode; paging preferred
    * GDT - Global Descriptor Table - 1 indexed table of descriptors for segments and their permissions
    * IDT - Interrupt Descriptor Table - 0 indexed table of descriptors for interrupt routines

    Many x86 CPU structures have different layouts to accomodate the growing number
    of bits the new versions of the ISA use, primarily around addressing and sizing.
    There are many decisions that seem to have been made to make structures *mostly*
    backwards compatible, such that the CPU can use the older remnants of the structure
    for compatibitly modes.

    There are some MSVC-isms in this code: I am compiling this with clang with
    --target=x86_64-unknown-windows. Doing this requires lld-link which does not seem
    to ship with Xcode.

    In theory, you can just as well compile this using MSVC and cl; you just need to
    specify the subsystem as a UEFI app.
*/

#define EFI_FUNCTION_WRAPPER
#include <efi.h>
#include <efilib.h>

// compiler rt symbol needed for some of the gnu-efi stuff, ugh. Can be removed if not using most of the gnu-efi lib
int _fltused = 0;

struct Framebuffer {
    uint32_t *data;
    int size;
    int width;
    int height;
    int pixels_per_line;
} _framebuffer;

// To make my life easier, I am assuming this is a 64-bit
// UEFI program, so we are already in Long mode on x86_64.
// This is useful because the Base and Limit fields of the GDT
// entry are ignored in Long mode, thus we need only fill the
// access byte and and flag bits. Base and limit are broken up
// into multiple pieces to retain backwards compatiblity.
struct GDTEntry {
    uint16_t limit1;
    uint16_t base1; // bits 15-0
    uint8_t  base2; // bits 23-16

    // The high bits always have the flags:
    // * P DPL S
    // For code/data segments, the low bits have:
    // * E DC RW A
    // For system segments, the low bits have a
    // 4 bit type enumeration
    uint8_t  access;

    // !WARNING! bit fields are not portable *SIRENS*
    uint8_t  limit2 : 4; // in lower 4 bits of this byte
    uint8_t  flags  : 4; // in upper 4 bits of this byte

    uint8_t  base3; // bits 31-24
};

// System segment entry takes up 2 GDT slots (total 16 bytes)
// The first slot is a regular GDT entry but with GDT_ACCESS_CODE_DATA_SEGMENT
// bit set to 0.
// The second slot contains an additional 32 bits to encode
// a full 64-bit Base value accross the two entries.
// Base and Limit are actually used for SS GDT entries.
struct SystemSegmentGDTEntry {
    struct GDTEntry gdt;

    uint32_t base4; // bits 63-32
    uint32_t reserved;
};

// 1 if entry refers to a valid segment
#define GDT_ACCESS_PRESENT (1 << 7)

// level is ring 0 (kernel) - 3 (userspace)
#define GDT_ACCESS_DPL(level) ((level & 3) << 5)

// S flag; 1 if for a code/data segment, 0 for system segment
#define GDT_ACCESS_CODE_DATA_SEGMENT (1 << 4)

// 1 for code segment, 0 for data
#define GDT_ACCESS_EXECUTABLE (1 << 3)

// if code selector: 0 if code may only be executed by the ring level,
//                   1 to allow execution by ring levels >= DPL value
// for data: 0 if segment grows up, 1 if down
#define GDT_ACCESS_DC (1 << 2)

// For code, writing is not allowed. Bit controls read access: 1 allowed
// Conversly, data segments always allow reading. 1 allows write access
#define GDT_ACCESS_RW (1 << 1)

// CPU sets this bit to 1 if it isn't already when a segment is accessed.
// Thus, the GDT needs to be in writable memory unless this is already 1.
#define GDT_ACCESS_ACCESSED (1 << 0)

// Protected mode system segment types
#define GDT_SS_TYPE_TSS16_AVAIL 0x1
#define GDT_SS_TYPE_TSS16_BUSY  0x3
// same as TSS64
#define GDT_SS_TYPE_TSS32_AVAIL 0x9
#define GDT_SS_TYPE_TSS32_BUSY  0xB

// Long mode system segment types
#define GDT_SS_TYPE_TSS64_AVAIL 0x9
#define GDT_SS_TYPE_TSS64_BUSY  0xB

// Protected and Long mode system segment types
#define GDT_SS_TYPE_LDT         0x2

// if 0, limit is in bytes, 1 if limit is in pages (4KB)
#define GDT_FLAG_GRANULARITY(g) (1 << 3)

// 0 for 16-bit mode segment, 1 for 32-bit mode (and 64-bit mode?)
// Must be 0 if GDT_FLAG_LONE is set
#define GDT_FLAG_DB (1 << 2)

// 1 if 64-bit code segment, 0 otherwise
#define GDT_FLAG_LONG (1 << 1)


struct GDTEntry gdt_entries[7] = {
    {0}, // First entry in GDT is ignored, and is recommended to be NULL

    {0}, // Kernel code
    {0}, // Kernel data
    {0}, // User code
    {0}, // User data

    // Two slots for Task State Segment
    {0}, // TSS lo slot
    {0}, // TSS hi slot
};

void encode_gdt_limit20(struct GDTEntry *e, uint32_t limit) {
    e->limit1 = limit & 0xFFFF;
    e->limit2 = (limit >> 16) & 0xF;
}

void encode_gdt_base32(struct GDTEntry *e, uint32_t base) {
    e->base1 = base & 0xFFFF;
    e->base2 = (base >> 16) & 0xFF;
    e->base3 = (base >> 24) & 0xFF;
}

void encode_ssgdt_base64(struct SystemSegmentGDTEntry *e, uint64_t base) {
    encode_gdt_base32(&e->gdt, (uint32_t)base);
    e->base4 = base >> 32;
}

// rpl   - bits 1-0  ; requested ring permission level
// ti    - bit 2     ; 0 if using GDT, 1 if using current LDT
// index - bits 15-3 ; index into GDT/LDT (to get offset into, simply do: index*8)
typedef uint16_t IDTSegmentSelector;

#define IDT_SEGMENT_SELECTOR_RPL(rpl) ((rpl) & 3)
#define IDT_SEGMENT_SELECTOR_TI(ti) (((ti) & 1) << 2)
#define IDT_SEGMENT_SELECTOR_INDEX(index) ((index) << 3)
#define IDT_SEGMENT_SELECTOR(index, rpl, ti) (IDT_SEGMENT_SELECTOR_INDEX(index) | IDT_SEGMENT_SELECTOR_RPL(rpl) | IDT_SEGMENT_SELECTOR_TI(ti))

struct IDTEntry {
    uint16_t offset1;
    IDTSegmentSelector segment_selector;
    uint8_t ist; // offset into interrupt stack table; bits 34-32 are used, upper bits reserved
    uint8_t access; // similar to GDT access byte
    uint16_t offset2;
    uint32_t offset3;
    uint32_t reserved;
};

#define IDT_ACCESS_PRESENT (1 << 7)
#define IDT_ACCESS_DPL(dpl) (((dpl) & 3) << 5)

#define IDT_TYPE_INTERRUPT64 0xE
#define IDT_TYPE_TRAP64      0xF

void encode_idt_offset64(struct IDTEntry *e, uint64_t base) {
    // similar, but not the same as the GDT stuff
    e->offset1 = base & 0xFFFF;
    e->offset2 = (base >> 16) & 0xFFFF;
    e->offset3 = base >> 32;
}

// unlike GDT, slot 0 is usable
// when an interrupt is performed, CPU looks up an entry in IDT
// to see if there is a registered service routine for it.
// ie, `int 3` looks for the entry at 3*8 bytes into the table.
// Since there are going to be many interrupts we want to capture,
// we will want to programmatically fill the table with a default
// service handler, and then write in the individual service entries
// for interrupts we care about.
// There are 256 interrupt vectors, we might as well use them; CPU ignores IDT entries above 255
#define IDT_TABLE_SLOTS 256
struct IDTEntry idt_entries[IDT_TABLE_SLOTS] = {0};

// dpl is the privilege level the caller needs to access the interrupt (`int` instruction).
// rpl is the privilege level the interrupt will execute in.
// rpl must be <= the target segment's dpl (have the same privelege or higher).
// Otherwise, trip GP fault. For example, if target dpl is ring 0, and rpl is ring 2
// We will enter ring 2 but not have permission to actually execute code in
// the segment, thus we fault.
void idt_write_entry(uint8_t slot, void *addr, uint8_t gdt_index, uint8_t dpl, uint8_t type, uint8_t rpl, uint8_t ti, uint8_t ist) {
    struct IDTEntry *e = &idt_entries[slot];

    encode_idt_offset64(e, (uintptr_t)addr);
    e->ist = ist & 7;
    e->access = IDT_ACCESS_PRESENT | IDT_ACCESS_DPL(dpl) | type;
    e->segment_selector = IDT_SEGMENT_SELECTOR(gdt_index, rpl, ti);
}

struct interrupt_frame {
    uintptr_t ip;
    uintptr_t cs;
    uintptr_t flags;
    uintptr_t sp;
    uintptr_t ss;
};

__attribute__ ((interrupt))
void empty_interrupt_handler(struct interrupt_frame *frame) { }

__attribute__ ((interrupt))
void fill_green_interrupt_handler(struct interrupt_frame *frame) {
    struct Framebuffer *fb = &_framebuffer;

    int line_pitch = fb->pixels_per_line;
    for (int y = 0; y < 40; ++y) {
        for (int x = 0; x < 20; ++x) {
            // Byte order B G R 0
            // Since we're presumably on a little endian machine, we shift "up" to set green in bits 15 - 8
            fb->data[y * line_pitch + (x)] = 255 << 8;
        }
    }
}

void idt_fill_table() {
    int gdt_index = 1; // kernel code segment
    for (int i = 0; i < IDT_TABLE_SLOTS; ++i) {
        idt_write_entry(i, empty_interrupt_handler, gdt_index, 0, IDT_TYPE_INTERRUPT64, 0, 0, 0);
        // idt_entries[i].access &= ~IDT_ACCESS_PRESENT;
    }

    idt_write_entry(25, fill_green_interrupt_handler, gdt_index, 0, IDT_TYPE_INTERRUPT64, 0, 0, 0);
}

// In Protected Mode, TSS is used for task switching
// In Long Mode, it is used to store interrupt stack table
struct TaskStateSegmentLong {
    uint32_t reserved0;
    uint32_t rsp0_lo;
    uint32_t rsp0_hi;
    uint32_t rsp1_lo;
    uint32_t rsp1_hi;
    uint32_t rsp2_lo;
    uint32_t rsp2_hi;
    uint32_t reserved1;
    uint32_t reserved2;
    uint32_t ist1_lo;
    uint32_t ist1_hi;
    uint32_t ist2_lo;
    uint32_t ist2_hi;
    uint32_t ist3_lo;
    uint32_t ist3_hi;
    uint32_t ist4_lo;
    uint32_t ist4_hi;
    uint32_t ist5_lo;
    uint32_t ist5_hi;
    uint32_t ist6_lo;
    uint32_t ist6_hi;
    uint32_t ist7_lo;
    uint32_t ist7_hi;
    uint32_t reserved3;
    uint32_t reserved4;
    uint16_t reserved5;
    uint16_t iopb;
} tss;

void write_gdt_entries() {
    // Uses the example GDT table setup from
    // https://wiki.osdev.org/GDT_Tutorial#Flat_/_Long_Mode_Setup
    uint8_t code_segment_access = GDT_ACCESS_PRESENT |
                    GDT_ACCESS_EXECUTABLE |
                    GDT_ACCESS_CODE_DATA_SEGMENT |
                    GDT_ACCESS_RW;
    uint8_t data_segment_access = GDT_ACCESS_PRESENT |
                    GDT_ACCESS_CODE_DATA_SEGMENT |
                    GDT_ACCESS_RW;

    // Set up kernel code segment
    {
        struct GDTEntry *e = &gdt_entries[1];
        e->access = code_segment_access | GDT_ACCESS_DPL(0);
        e->flags = GDT_FLAG_GRANULARITY(1) | GDT_FLAG_LONG;

        // despite osdev wiki stating limit is ignored in Long mode
        // they still seem to recommended specifying the limit as
        // 0xFFFFF (max value).
        encode_gdt_limit20(e, 0xFFFFF);
    }

    // Set up kernel data segment
    {
        struct GDTEntry *e = &gdt_entries[2];
        e->access = data_segment_access | GDT_ACCESS_DPL(0);
        e->flags = GDT_FLAG_GRANULARITY(1) | GDT_FLAG_DB;
        encode_gdt_limit20(e, 0xFFFFF);
    }

    // User mode: copy and pasted from above, but with ring 3
    // Set up user code segment
    if (0) {
        struct GDTEntry *e = &gdt_entries[3];
        e->access = code_segment_access | GDT_ACCESS_DPL(3);
        e->flags = GDT_FLAG_GRANULARITY(1) | GDT_FLAG_DB;
        encode_gdt_limit20(e, 0xFFFFF);
    }

    // Set up user data segment
    {
        struct GDTEntry *e = &gdt_entries[4];
        e->access = data_segment_access | GDT_ACCESS_DPL(3);
        e->flags = GDT_FLAG_GRANULARITY(1) | GDT_FLAG_LONG;
        encode_gdt_limit20(e, 0xFFFFF);
    }

    // Set up task state segment
    {
        struct SystemSegmentGDTEntry *e = (struct SystemSegmentGDTEntry *)&gdt_entries[5];
        e->gdt.access = GDT_ACCESS_PRESENT | GDT_ACCESS_DPL(0) | GDT_SS_TYPE_TSS64_AVAIL;
        encode_ssgdt_base64(e, (uintptr_t)&tss);
        encode_gdt_limit20(&e->gdt, sizeof(struct TaskStateSegmentLong)-1);
        e->gdt.flags = GDT_FLAG_GRANULARITY(0); // bytes
    }
}


#pragma pack(push ,1)

// A descriptor for size/address to feed to lgdt, lidt, lldt
// size is bits 15-0
// ptr is bits 80-16
struct SystemDescriptorTableDescriptor {
    uint16_t size; // size of table-1 (table can be up to 65536 bytes)
    void *ptr; // linear address to table
};

#pragma pack(pop)

struct SystemDescriptorTableDescriptor _gdt_desc;
struct SystemDescriptorTableDescriptor _idt_desc;

// Pretty simple:
// lgdt instruction takes a pointer to a descriptor that has the linear
// address to the GDT and the size-1 of the table
void load_gdt(uint16_t size, void *ptr) {
    _gdt_desc.size = size-1;
    _gdt_desc.ptr = ptr;
    asm __volatile__(
        ".intel_syntax\n"
        "lgdt [_gdt_desc]"
    );
}

void load_idt(uint16_t size, void *ptr) {
    _idt_desc.size = size-1;
    _idt_desc.ptr = ptr;
    asm __volatile__(
        ".intel_syntax\n"
        "lidt [_idt_desc]"
    );
}

// Loads segment registers such as CS, DS, etc.. The value of these registers
// are the offset in bytes from the beginning of the GDT. Since the GDT can
// only be 2^16 in size, the offsets may only be 2^16-1
void reload_segments(uint16_t code_offet, uint16_t data_offset);

void kernel_main(struct Framebuffer *fb) {

    write_gdt_entries();
    load_gdt(sizeof(gdt_entries), &gdt_entries);

    // kernel code segment is in slot 1 at offset 0x08
    // kernel data segment is in slot 2 at offset 0x10
    reload_segments(0x8, 0x10);

    idt_fill_table();
    load_idt(sizeof(idt_entries), &idt_entries);

    asm __volatile__("sti\n"); // enable interrupts

    asm __volatile__(".intel_syntax\nint 25\n"); // call int 25 AKA draw a green square

    // hang
    while (1) { }
}

// Maybe you have a CRT, but I don't
// Mainly just used in this example for "= {0}" initialization
void *memset(void *data, int v, size_t amt) {
    char *d = data;
    for (size_t i = 0; i < amt; ++i) {
        // 0 because this is the only valid use of memset >.>
        d[i] = 0;
    }

    return data;
}

struct Framebuffer *get_gop_framebuffer(EFI_SYSTEM_TABLE *SystemTable) {
    EFI_GUID guid = EFI_GRAPHICS_OUTPUT_PROTOCOL_GUID;
    EFI_GRAPHICS_OUTPUT_PROTOCOL *gop;

    EFI_STATUS status = SystemTable->BootServices->LocateProtocol(&guid, NULL, (void **)&gop);

    if (EFI_ERROR(status)) {
        SystemTable->ConOut->OutputString(ST->ConOut, L"Can't locate GOP\r\n");
        return NULL;
    }

    EFI_GRAPHICS_OUTPUT_MODE_INFORMATION *info;
    UINTN info_size, num_modes, native_mode;
    status = gop->QueryMode(gop, gop->Mode == NULL ? 0 : gop->Mode->Mode, &info_size, &info);

    if (status == EFI_NOT_STARTED)
        status = gop->SetMode(gop, 0);

    if (EFI_ERROR(status)) {
        SystemTable->ConOut->OutputString(ST->ConOut, L"Unable to get native mode\r\n");
    }
    else {
        native_mode = gop->Mode->Mode;
        num_modes = gop->Mode->MaxMode;
    }

    // Pick mode first mode with BGR graphics
    // On QEMU with OVMF, RGB mode seems to be missing
    for (int i = 0; i < num_modes; i++) {
        status = gop->QueryMode(gop, i, &info_size, &info);
        if (info->PixelFormat == PixelBlueGreenRedReserved8BitPerColor) {
            // Note: setting the GOP mod clears the screen, so we will lose
            // any text from previous OutputString/Print calls.
            gop->SetMode(gop, i);
            SystemTable->ConOut->OutputString(ST->ConOut, L"GOP mode set\r\n");
            break;
        }
    }

    _framebuffer.data = (uint32_t *)gop->Mode->FrameBufferBase;
    _framebuffer.size = gop->Mode->FrameBufferSize;
    _framebuffer.width = gop->Mode->Info->HorizontalResolution;
    _framebuffer.height = gop->Mode->Info->VerticalResolution;
    _framebuffer.pixels_per_line = gop->Mode->Info->PixelsPerScanLine;

    return &_framebuffer;
}

EFI_STATUS EFIAPI efi_main(EFI_HANDLE ImageHandle, EFI_SYSTEM_TABLE *SystemTable)
{
    EFI_STATUS Status;
    EFI_INPUT_KEY Key;

    ST = SystemTable;
    Status = ST->ConOut->OutputString(ST->ConOut, L"Hello World\r\n");
    if (EFI_ERROR(Status))
        return Status;

    struct Framebuffer *fb = get_gop_framebuffer(SystemTable);

    if (!fb) {
        Status = ST->ConOut->OutputString(ST->ConOut, L"Could not set up framebuffer\r\n");
        if (EFI_ERROR(Status))
            return Status;

        return Status;
    }

    Status = ST->ConOut->OutputString(ST->ConOut, L"Getting memory map\r\n");

    EFI_MEMORY_DESCRIPTOR *mem_map = NULL;
    UINTN memory_map_size = 0, map_key = 0, descriptor_size = 0;
    UINT32 descriptor_ver;

    // memory_map_size is the size in bytes of our array of EFI_MEMORY_DESCRIPTOR
    // We pass in 0 and NULL so that GetMemoryMap sets memory_map_size to how much memory we need to store the current memory map.
    // The status code returned should be EFI_BUFFER_TO_SMALL ((1LL << 63) | 5)
    Status = SystemTable->BootServices->GetMemoryMap(&memory_map_size, mem_map, &map_key, &descriptor_size, &descriptor_ver);
    Print(L"GetMemoryMap Status: %llX\n", Status);

    Print(L"Memory Descriptor Size: %d\n", sizeof(EFI_MEMORY_DESCRIPTOR));
    Print(L"Map Size: %d\n", memory_map_size);
    Print(L"Map Key: %d\n", map_key);

    // Allocate memory pages to hold the memory descriptors
    int num_pages = (memory_map_size / 0x1000) + 1;

    Status = SystemTable->BootServices->AllocatePages(AllocateAnyPages, EfiLoaderData, num_pages, &mem_map);
    if (EFI_ERROR(Status)) {
        Print(L"Failed to allocate memory %llX\n", Status);
        return Status;
    }

    memory_map_size = num_pages * 0x1000;
    Status = SystemTable->BootServices->GetMemoryMap(&memory_map_size, mem_map, &map_key, &descriptor_size, &descriptor_ver);
    Print(L"GetMemoryMap Status: %llX\n", Status);

    Print(L"Memory Descriptor Size: %d\n", sizeof(EFI_MEMORY_DESCRIPTOR));
    Print(L"Map Size: %d\n", memory_map_size);
    Print(L"Map Key: %d\n", map_key);

    Status = ST->ConOut->OutputString(ST->ConOut, L"Exiting boot services and running kernel\r\n");
    if (EFI_ERROR(Status))
        return Status;

    // We need a map key to exit boot services, which can only be obtained from GetMemoryMap
    // We as far as QEMU+OVMF is concerned, you don't actually need a 0 status code from GetMemoryMap to ExitBootServices,
    // You just need to have called ExitBootServices to get a map key at all. This makes it unnecessary to even retrieve
    // a proper memory map.

    // That being said, we have to be careful: we cannot call any functions (including UEFI firmware functions!)
    // that may allocate memory because that means our memory map is stale, but more importantly that our map key
    // is stale, thus BootServices will not alow us to exit. In this example, I have left in some diagnostics just to
    // illustrate the values retrieved, so we'll have to call GetMemoryMap again for a refresh.

    memory_map_size = num_pages * 0x1000; // memory_map_size will have be written over from the last GetMemoryMap call.
    Status = SystemTable->BootServices->GetMemoryMap(&memory_map_size, mem_map, &map_key, &descriptor_size, &descriptor_ver);
    if (EFI_ERROR(Status)) {
        Print(L"Final GetMemoryMap failed %llX\r\n", Status);
        // return Status;
    }

    // Leave BootServices. After this point, we no longer can call UEFI functions.
    Status = SystemTable->BootServices->ExitBootServices(ImageHandle, map_key);
    if (EFI_ERROR(Status)) {
        Print(L"Failed to leave BootServices %llX\n", Status);
    }

    // On QEMU, this stalls the machine :P
    // Status = ST->ConOut->OutputString(ST->ConOut, L"See! This doesn't work!\r\n");

    // Enter our kernel proper. In this case, our kernel code is in the efi bootloader, but you could just as well use
    // the UEFI firmware to locate a kernel image from disk (before ExitBootServices) and jump to that.
    kernel_main(fb);

    return Status;
}