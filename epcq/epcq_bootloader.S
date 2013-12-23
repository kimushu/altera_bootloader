/**
 * @file epcq_bootloader.S
 * @brief EPCQx1 boot loader
 * @author kimu_shu
 */

/*
 * Supported EPCQ devices:
 * | Part#   | Capacity      | Sector size   | DvID |
 * | EPCQ16  |  16Mb (  2MB) | 512kb  (64kB) | 0x15 |
 * | EPCQ32  |  32Mb (  4MB) | 512kb  (64kB) | 0x16 |
 * | EPCQ64  |  64Mb (  8MB) | 512kb  (64kB) | 0x17 |
 * | EPCQ128 | 128Mb ( 16MB) | 512kb  (64kB) | 0x18 |
 * | EPCQ256 | 256Mb ( 32MB) | 512kb  (64kB) | 0x19 |
 */

/*
 * Name of definitions (EPCS_*) are left unchanged for compatibility.
 */

/*
 * Length of EPCS Controller's Boot ROM Memory (in words)
 */
#ifndef EPCS_BOOTROM_WORDS
//# define EPCS_BOOTROM_WORDS	0x080	// Cyclone and Cyclone II
# define EPCS_BOOTROM_WORDS	0x100	// Other device families
#endif
.equ	BOOTROM_WORDS,	EPCS_BOOTROM_WORDS

#if !defined(EPCS_ELF_BYTES) && !defined(EPCS_ELF_SECTORS)
/*
 * Length of ELF area (in bytes)
 * (Comment out if you use EPCS_ELF_SECTORS)
 */
//# define EPCS_ELF_BYTES	0x4000

/*
 * Length of ELF area (in sectors)
 * (Comment out if you use EPCS_ELF_BYTES)
 * (Sector size is automatically detected)
 */
# define EPCS_ELF_SECTORS	1
#endif

/*
 * Register usage
 */
#define r_zero			r0
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
#define r_p_memsz		r17

#define ELF_HEADER_LE		0x464c457f
#define ET_EXEC				2
#define EM_NIOS2			0x71
#define PT_LOAD				1

/*
 * EPCS Serial Flash Controller Registers
 */
#define EPCS_RXDATA				0x00
#define EPCS_TXDATA				0x04
#define EPCS_STATUS				0x08
#define EPCS_CONTROL			0x0c
#define EPCS_STATUS_RRDY		0x080
#define EPCS_CONTROL_SSO		0x400
#define EPCS_READ_BYTES			0x03
#define EPCS_READ_SILICON_ID	0xab
#define EPCS_READ_DEVICE_ID		0x9f

/*
 * Parameter check
 */
#ifdef EPCS_ELF_BYTES
# ifdef EPCS_ELF_SECTORS
	.print "**** Either EPCS_ELF_BYTES or EPCS_ELF_SECTORS must be defined ****"
	.err
# endif
#else
# ifndef EPCS_ELF_SECTORS
	.print "**** Either EPCS_ELF_BYTES or EPCS_ELF_SECTORS must be defined ****"
	.err
# endif
#endif

/*********************************************************************************
 * Macros
 *********************************************************************************/

/*
 * Pseudo move instruction with 32-bit immediate
 *   Operation: rA <- IMM32
 *   Syntax:    MOVI32 rA, IMM32
 */
.macro MOVI32 rA,IMM32
	.if (\IMM32 & 0xffff0000)
		movhi	\rA, %hi(\IMM32)
		.if (\IMM32 & 0x0000ffff)
			ori		\rA, \rA, %lo(\IMM32)
		.endif
	.else
		movui	\rA, %lo(\IMM32)
	.endif
.endm

/*
 * Relative call
 *   Syntax: RCALL label
 */
.macro RCALL label
	nextpc	ra
	br		\label
.endm

/*
 * Return for RCALL
 *   Syntax: RRET
 */
.macro RRET
	addi	ra, ra, 4
	jmp		ra
.endm

/*
 * Close EPCS connection (Stop CS# output)
 */
.macro EPCS_CLOSE
	stwio	r_zero, EPCS_CONTROL(r_epcs_base)
.endm

/*********************************************************************************
 * Code
 *********************************************************************************/

	.text
reset:
	// Clear processor status (Disable interrupts)
	wrctl	status, r_zero

	// Initialize instruction cache
	movhi	r_temp, %hi(0x10000)
1:	initi	r_temp
	addi	r_temp, r_temp, -32
	bne		r_temp, r_zero, 1b
	flushp

	// Get EPCS controller base address
	nextpc	r_epcs_base
	ori		r_epcs_base, r_epcs_base, (EPCS_BOOTROM_WORDS * 4) - 1
	addi	r_epcs_base, r_epcs_base, 1

	// Get EPCQ Device ID
	movhi	r_write_data, %hi(EPCS_READ_DEVICE_ID << 24)
	RCALL	epcs_txrx_word
	EPCS_CLOSE

	// Calculate EPCS capacity
	movui	r_elf_base, 1
	sll		r_elf_base, r_elf_base, r_read_data

#ifdef EPCS_ELF_BYTES
	// Calculate ELF base address (EndOfEPCS - EPCS_ELF_BYTES)
	addi	r_elf_base, r_elf_base, -EPCS_ELF_BYTES
#endif
#ifdef EPCS_ELF_SECTORS
	// Calculate ELF base address (EndOfEPCS - SectorSize*EPCS_ELF_SECTORS)
	MOVI32	r_temp, EPCS_ELF_SECTORS
	slli	r_temp, r_temp, 16
	sub		r_elf_base, r_elf_base, r_temp
#endif

	// Check ELF header
	orhi	r_elf_base, r_elf_base, %hi(EPCS_READ_BYTES << 24)
	mov		r_write_data, r_elf_base
	RCALL	epcs_txrx_word
	RCALL	epcs_txrx_word
	EPCS_CLOSE
	MOVI32	r_temp, ELF_HEADER_LE
	bne		r_read_data, r_temp, halt

	// Check ELF type & machine
	addi	r_write_data, r_elf_base, 16	// offsetof(elf32_ehdr, e_type)
	RCALL	epcs_txrx_word
	RCALL	epcs_txrx_word
	MOVI32	r_temp, (ET_EXEC | (EM_NIOS2 << 16))
	bne		r_read_data, r_temp, halt

	// Read e_entry, e_phoff, e_phsize and e_phnum
	RCALL	epcs_txrx_word			// e_version
	RCALL	epcs_txrx_word			// e_entry
	mov		r_e_entry, r_read_data
	RCALL	epcs_txrx_word			// e_phoff
	add		r_e_phoff, r_elf_base, r_read_data
	RCALL	epcs_txrx_word			// e_shoff
	RCALL	epcs_txrx_word			// e_flags
	RCALL	epcs_txrx_word			// e_ehsize, e_phentsize
	srli	r_e_phentsize, r_read_data, 16
	RCALL	epcs_txrx_word			// e_phnum
	andi	r_e_phnum, r_read_data, 0xffff
	EPCS_CLOSE

load_program_header:
	// Read p_type
	mov		r_write_data, r_e_phoff
	RCALL	epcs_txrx_word			// opcode and address
	RCALL	epcs_txrx_word			// p_type
	MOVI32	r_temp, PT_LOAD
	bne		r_read_data, r_temp, next_program_header

	// When p_type == PT_LOAD, read p_offset, p_paddr and p_filesz
	RCALL	epcs_txrx_word			// p_offset
	mov		r_p_offset, r_read_data
	RCALL	epcs_txrx_word			// p_vaddr
	RCALL	epcs_txrx_word			// p_paddr
	mov		r_p_paddr, r_read_data
	RCALL	epcs_txrx_word			// p_filesz
	mov		r_p_filesz, r_read_data
	RCALL	epcs_txrx_word			// p_memsz
	mov		r_p_memsz, r_read_data
	EPCS_CLOSE

	// Load section data
	beq		r_p_filesz, r_zero, next_program_header
	add		r_write_data, r_elf_base, r_p_offset
	RCALL	epcs_txrx_word			// opcode and address
1:	RCALL	epcs_txrx_word			// section data
	stw		r_read_data, 0(r_p_paddr)
	addi	r_p_paddr, r_p_paddr, 4
	addi	r_p_filesz, r_p_filesz, -4
	addi	r_p_memsz, r_p_memsz, -4
	blt		r_zero, r_p_filesz, 1b

	// Fill remainder area after file image
	bge		r_zero, r_p_memsz, 2f
1:	stw		r_zero, 0(r_p_paddr)
	addi	r_p_paddr, r_p_paddr, 4
	addi	r_p_memsz, r_p_memsz, -4
	blt		r_zero, r_p_memsz, 1b
2:

next_program_header:
	EPCS_CLOSE
	add		r_e_phoff, r_e_phoff, r_e_phentsize
	addi	r_e_phnum, r_e_phnum, -1
	bne		r_e_phnum, r_zero, load_program_header

start_program:
	jmp		r_e_entry

halt:
	br		halt

/*
 * epcs_txrx_word - TX and RX 4 bytes (Must be called by RCALL)
 *   Input:  r_write_data - TX data (MSB first, big-endian)
 *   Output: r_read_data  - RX data (MSB first, little-endian)
 */
epcs_txrx_word:
	MOVI32	r_temp, EPCS_CONTROL_SSO
	stwio	r_temp, EPCS_CONTROL(r_epcs_base)
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
	RRET

