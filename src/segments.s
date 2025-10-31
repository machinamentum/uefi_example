
// MSVC x64 Calling Convention
// https://learn.microsoft.com/en-us/cpp/build/x64-calling-convention

.intel_syntax

// based on https://wiki.osdev.org/GDT_Tutorial#Long_Mode_2

// Called with
// RCX - code segment offset
// RDX - data segment offset
.global reload_segments
reload_segments:
    push rdx // Push data segment offset to stack
    push rcx // Push code segment offset to stack
    lea rax, [rip + reload_cs_target]
    push rax
    retfq  // "far return" to make CS register reload from GDT table with the offset pushed from cx

reload_cs_target:
    pop rax // load the data segment offset from stack
    // reload the rest of the segment registers
    mov ds, ax
    mov es, ax
    mov fs, ax
    mov gs, ax
    mov ss, ax
    ret
