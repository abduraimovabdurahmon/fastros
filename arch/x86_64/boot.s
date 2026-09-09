; =============================================================
; FastROS — arch/x86_64/boot.s
; LAYER 0: Hardware entry point
;
; Two boot paths:
;   - QEMU -kernel: uses PVH ELF note → _pvh_start (32-bit PM)
;   - GRUB/Multiboot2: uses multiboot2 header → _start (32-bit PM)
; Both paths set up long mode and call kernel_main (Rust).
; =============================================================

; ---- Multiboot2 Header (for GRUB / Multiboot2 bootloaders) ----
section .multiboot_header
align 8
header_start:
    dd 0xe85250d6                               ; Multiboot2 magic
    dd 0                                        ; Architecture: i386 protected mode
    dd header_end - header_start                ; Header length
    dd -(0xe85250d6 + 0 + (header_end - header_start)) ; Checksum
    ; End tag
    dw 0
    dw 0
    dd 8
header_end:

; ---- PVH ELF Note (for QEMU -kernel direct ELF boot) ----
; QEMU scans 64-bit ELFs for this note instead of using multiboot.
; Name: "Xen", Type: 18 (XEN_ELFNOTE_PHYS32_ENTRY), Value: entry addr
section .note.Xen
align 4
    dd 4                    ; namesz: length of "Xen\0"
    dd 4                    ; descsz: 4-byte entry point address
    dd 18                   ; type: XEN_ELFNOTE_PHYS32_ENTRY
    db "Xen", 0             ; name (4 bytes, null-terminated)
    dd _pvh_start           ; 32-bit physical address of PVH entry

; ---- BSS: page tables + kernel stack ----
section .bss
align 4096

p4_table:
    resb 4096       ; Page Map Level 4 (PML4)
p3_table:
    resb 4096       ; Page Directory Pointer Table (PDPT)
p2_table:
    resb 4096       ; Page Directory — 2 MB huge pages

stack_bottom:
    resb 4096 * 16  ; 64 KB kernel stack
stack_top:

; ---- GDT for 64-bit long mode ----
section .rodata
gdt64:
    dq 0                                                    ; Null descriptor
.code: equ $ - gdt64
    dq (1 << 43) | (1 << 44) | (1 << 47) | (1 << 53)     ; Code: 64-bit, execute/read
gdt64_ptr:
    dw $ - gdt64 - 1    ; Limit
    dq gdt64            ; Base

; ---- 32-bit code ----
section .text
bits 32

; PVH entry: called by QEMU -kernel for 64-bit ELF.
; ebx = pointer to hvm_start_info (ignored for now).
; CPU: 32-bit protected mode, flat segments, paging disabled.
global _pvh_start
_pvh_start:
    mov esp, stack_top
    call check_cpuid
    call check_long_mode
    call setup_page_tables
    call enable_paging
    lgdt [gdt64_ptr]
    jmp gdt64.code:long_mode_start

; Multiboot2 entry: called by GRUB / Multiboot2 loaders.
; eax = 0x36d76289 (multiboot2 magic), ebx = multiboot2 info pointer.
global _start
_start:
    mov esp, stack_top
    cmp eax, 0x36d76289
    jne .no_multiboot
    call check_cpuid
    call check_long_mode
    call setup_page_tables
    call enable_paging
    lgdt [gdt64_ptr]
    jmp gdt64.code:long_mode_start
.no_multiboot:
    mov al, 'M'
    jmp error

; ---- CPUID support check ----
check_cpuid:
    pushfd
    pop eax
    mov ecx, eax
    xor eax, 1 << 21
    push eax
    popfd
    pushfd
    pop eax
    push ecx
    popfd
    cmp eax, ecx
    je .no_cpuid
    ret
.no_cpuid:
    mov al, 'C'
    jmp error

; ---- Long mode (64-bit) support check ----
check_long_mode:
    mov eax, 0x80000000
    cpuid
    cmp eax, 0x80000001
    jb .no_long_mode
    mov eax, 0x80000001
    cpuid
    test edx, 1 << 29
    jz .no_long_mode
    ret
.no_long_mode:
    mov al, 'L'
    jmp error

; ---- Identity-map first 1 GB (2 MB huge pages) ----
setup_page_tables:
    mov eax, p3_table
    or eax, 0b11
    mov [p4_table], eax

    mov eax, p2_table
    or eax, 0b11
    mov [p3_table], eax

    mov ecx, 0
.map_p2:
    mov eax, 0x200000
    mul ecx
    or eax, 0b10000011      ; present + writable + huge
    mov [p2_table + ecx * 8], eax
    inc ecx
    cmp ecx, 512
    jne .map_p2
    ret

; ---- Enable PAE + long mode + paging ----
enable_paging:
    mov eax, p4_table
    mov cr3, eax

    mov eax, cr4
    or eax, 1 << 5          ; PAE bit
    mov cr4, eax

    mov ecx, 0xC0000080     ; EFER MSR
    rdmsr
    or eax, 1 << 8          ; LME (long mode enable)
    wrmsr

    mov eax, cr0
    or eax, (1 << 31) | (1 << 16)  ; PG + WP
    mov cr0, eax
    ret

; ---- Error: print "ERR:X" on VGA and halt ----
error:
    mov dword [0xb8000], 0x4f524f45   ; 'ER'
    mov dword [0xb8004], 0x4f3a4f52   ; 'R:'
    mov byte  [0xb8008], 0x4f
    mov byte  [0xb8009], al
    hlt
.hang:
    jmp .hang

; ---- 64-bit long mode start ----
bits 64
long_mode_start:
    mov ax, 0
    mov ss, ax
    mov ds, ax
    mov es, ax
    mov fs, ax
    mov gs, ax

    extern kernel_main
    call kernel_main

    cli
    hlt
.hang:
    jmp .hang
