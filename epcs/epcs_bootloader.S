/**
 * @file epcs_bootloader.S
 * @brief EPCS boot loader for Cyclone III/IV
 */

#define r_zero			r0
#define r_ret			r2
#define r_temp			r4
#define r_byte_count	r5
#define r_read_data		r6
#define r_write_data	r7
#define r_elf_base		r8
#define r_e_entry		r9
#define r_e_phoff		r10
#define r_e_phentsize	r11
#define r_e_phnum		r12
#define r_p_offset		r13
#define r_p_paddr		r14
#define r_p_filesz		r15
#define r_epcs_base		r16
#define r_epcs_cs		r17

#define ELF_HEADER_LE		0x464c457f
#define ET_EXEC				2
#define EM_NIOS2			0x71
#define PT_LOAD				1

#define EPCS_BOOTROM_WORDS	0x100
#define EPCS_ELF_CAPACITY	0x4000

#define EPCS_RXDATA			0x00
#define EPCS_TXDATA			0x04
#define EPCS_STATUS			0x08
#define EPCS_CONTROL		0x0c

#define EPCS_STATUS_RRDY	0x080
#define EPCS_CONTROL_SSO	0x400

#define EPCS_READ_BYTES			0x03
#define EPCS_READ_SILICON_ID	0xab

.macro MOVI32 reg,imm32
	.if (\imm32 & 0xffff0000)
	movhi	\reg, %hi(\imm32)
	.if (\imm32 & 0x0000ffff)
	ori		\reg, \reg, %lo(\imm32)
	.endif
	.else
	movui	\reg, %lo(\imm32)
	.endif
.endm

.macro EPCS_CLOSE
	stwio	r_zero, EPCS_CONTROL(r_epcs_base)
.endm

	.text
	// Clear processor status (Disable interrupts)
	wrctl	status, r_zero

	// Initialize instruction cache
	movhi	r_temp, %hi(0x10000)
1:	initi	r_temp
	addi	r_temp, r_temp, -32
	bne		r_temp, r_zero, 1b
	flushp

	// Get EPCS controllers base address
	nextpc	r_epcs_base
	ori		r_epcs_base, r_epcs_base, (EPCS_BOOTROM_WORDS * 4) - 1
	addi	r_epcs_base, r_epcs_base, 1

	// Initialize some registers
	movui	r_epcs_cs, EPCS_CONTROL_SSO

	// Get EPCS's ID (for EPCS1,4,16,64)
	movhi	r_write_data, %hi(EPCS_READ_SILICON_ID << 24)
	nextpc	r_ret
	br		epcs_txrx32_nostack
	nextpc	r_ret
	br		epcs_txrx32_nostack
	EPCS_CLOSE

	// Calculate EPCS load pointer (EndOfEPCS - EPCS_ELF_CAPACITY)
	movui	r_elf_base, (1 << 1)
	sll		r_elf_base, r_elf_base, r_read_data
	addi	r_elf_base, r_elf_base, -EPCS_ELF_CAPACITY
	orhi	r_elf_base, r_elf_base, %hi(EPCS_READ_BYTES << 24)

	// Check ELF header
	mov		r_write_data, r_elf_base
	nextpc	r_ret
	br		epcs_txrx32_nostack
	nextpc	r_ret
	br		epcs_txrx32_nostack
	EPCS_CLOSE
	MOVI32	r_temp, ELF_HEADER_LE
	bne		r_read_data, r_temp, invalid_elf

	// Check ELF type & machine
	addi	r_write_data, r_elf_base, 16	// offsetof(elf32_ehdr, e_type)
	nextpc	r_ret
	br		epcs_txrx32_nostack
	nextpc	r_ret
	br		epcs_txrx32_nostack
	MOVI32	r_temp, (ET_EXEC | (EM_NIOS2 << 16))
	bne		r_read_data, r_temp, invalid_elf

	// Read e_entry, e_phoff, e_phsize and e_phnum
	nextpc	r_ret
	br		epcs_txrx32_nostack		// skip e_version
	nextpc	r_ret
	br		epcs_txrx32_nostack		// read e_entry
	mov		r_e_entry, r_read_data
	nextpc	r_ret
	br		epcs_txrx32_nostack		// read e_phoff
	add		r_e_phoff, r_elf_base, r_read_data
	nextpc	r_ret
	br		epcs_txrx32_nostack		// skip e_shoff
	nextpc	r_ret
	br		epcs_txrx32_nostack		// skip e_flags
	nextpc	r_ret
	br		epcs_txrx32_nostack		// skip e_ehsize and read e_phentsize
	srli	r_e_phentsize, r_read_data, 16
	nextpc	r_ret
	br		epcs_txrx32_nostack		// read e_phnum
	andi	r_e_phnum, r_read_data, 0xffff
	EPCS_CLOSE

load_program_header:
	// Read p_type
	mov		r_write_data, r_e_phoff
	nextpc	r_ret
	br		epcs_txrx32_nostack
	nextpc	r_ret
	br		epcs_txrx32_nostack
	MOVI32	r_temp, PT_LOAD
	bne		r_read_data, r_temp, next_program_header

	// When p_type == PT_LOAD, read p_offset, p_paddr and p_filesz
	nextpc	r_ret
	br		epcs_txrx32_nostack
	mov		r_p_offset, r_read_data
	nextpc	r_ret
	br		epcs_txrx32_nostack
	nextpc	r_ret
	br		epcs_txrx32_nostack
	mov		r_p_paddr, r_read_data
	nextpc	r_ret
	br		epcs_txrx32_nostack
	mov		r_p_filesz, r_read_data
	EPCS_CLOSE

	// Load section data
	beq		r_p_filesz, r_zero, next_program_header
	add		r_write_data, r_elf_base, r_p_offset
	nextpc	r_ret
	br		epcs_txrx32_nostack
1:	nextpc	r_ret
	br		epcs_txrx32_nostack
	stw		r_read_data, 0(r_p_paddr)
	addi	r_p_paddr, r_p_paddr, 4
	addi	r_p_filesz, r_p_filesz, -4
	blt		r_zero, r_p_filesz, 1b

next_program_header:
	EPCS_CLOSE
	add		r_e_phoff, r_e_phoff, r_e_phentsize
	addi	r_e_phnum, r_e_phnum, -1
	bne		r_e_phnum, r_zero, load_program_header

start_program:
	jmp		r_e_entry

epcs_txrx32_nostack:
// r_write_data => TX data (big endian)
// r_ret => (return address - 4)
// r_read_data <= RX data (little endian)
	stwio	r_epcs_cs, EPCS_CONTROL(r_epcs_base)
	movui	r_byte_count, 4
	mov		r_read_data, r_zero
1:	roli	r_write_data, r_write_data, 8
	stwio	r_write_data, EPCS_TXDATA(r_epcs_base)
2:	ldwio	r_temp, EPCS_STATUS(r_epcs_base)
	andi	r_temp, r_temp, EPCS_STATUS_RRDY
	beq		r_temp, r_zero, 2b
	ldbuio	r_temp, EPCS_RXDATA(r_epcs_base)
	or		r_read_data, r_read_data, r_temp
	roli	r_read_data, r_read_data, 24
	addi	r_byte_count, r_byte_count, -1
	bne		r_byte_count, r_zero, 1b
	addi	r_ret, r_ret, 4
	jmp		r_ret

invalid_elf:
1:	br		1b

