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
	;; setup the basic stack
	mov esp, 0x1000
	mov ebp, esp


	mov eax, 0
	cpuid
	hlt



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

;; Poke special port to print registers
print_regs:
	mov dx, 0x3f8
	out dx, eax
	ret

;; Poke special port to print the time to the host
print_time:
	rdtsc
	out 0xfe, eax
	ret



check_cpuid:
	pushfd                               ;Save EFLAGS
	pushfd                               ;Store EFLAGS
	xor dword [esp],0x00200000           ;Invert the ID bit in stored EFLAGS
	popfd                                ;Load stored EFLAGS (with ID bit inverted)
	pushfd                               ;Store EFLAGS again (ID bit may or may not be inverted)
	pop eax                              ;eax = modified EFLAGS (ID bit may or may not be inverted)
	xor eax,[esp]                        ;eax = whichever bits were changed
	popfd                                ;Restore original EFLAGS
	and eax,0x00200000                   ;eax = zero if ID bit can't be changed, else non-zero
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


