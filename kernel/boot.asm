global start


bits 16

org 0x1000

start:

	cli ; disable interrupts
	;; clear out the data segments
	xor ax, ax
	mov ds, ax
	mov es, ax
	mov ss, ax


	lgdt [gdtr]    ; load GDT register with start address of Global Descriptor Table
	mov eax, cr0
	or al, 1       ; set PE (Protection Enable) bit in CR0 (Control Register 0)
	mov cr0, eax

	;; Perform a long-jump to the 32 bit protected mode
	jmp (CODE_DESC - NULL_DESC):start32


bits 32
;;  St
start32:


	mov eax, 20
	mov esp, 0x1000
	mov ebp, esp


	sub esp, 16


	mov esi, 0

.TOP:
	mov DWORD [ebp-4], 0xffffff
	jmp .L2
.L3:
	mov eax, DWORD [ebp-4]
	sub DWORD [ebp-4], 1
.L2:
	cmp DWORD [ebp-4], 0
	jne .L3


	add esi, 1


	call print_time
	jmp .TOP

	hlt


print_regs:
	mov dx, 0x3f8
	out dx, eax
	ret


print_time:
	rdtsc
	out 0xfe, eax
	ret



NULL_DESC:
    dd 0            ; null descriptor
    dd 0

CODE_DESC:
    dw 0xFFFF       ; limit low
    dw 0            ; base low
    db 0            ; base middle
    db 10011010b    ; access
    db 11001111b    ; granularity
    db 0            ; base high

DATA_DESC:
    dw 0xFFFF       ; limit low
    dw 0            ; base low
    db 0            ; base middle
    db 10010010b    ; access
    db 11001111b    ; granularity
    db 0            ; base high

gdtr:
    LIMIT dw gdtr - NULL_DESC - 1 ; length of GDT
    BASE  dd NULL_DESC   ; base of GDT

