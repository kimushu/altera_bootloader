/**
 * @file epcs_bootloader.S
 * @brief EPCS boot loader
 * @author kimu_shu
 */

/*
 * Supported EPCS devices:
 * | Part#   | Capacity      | Sector size   | SiID |
 * | EPCS1   |   1Mb (128kB) | 256kb  (32kB) | 0x10 |
 * | EPCS4   |   4Mb (512kB) | 512kb  (64kB) | 0x12 |
 * | EPCS16  |  16Mb (  2MB) | 512kb  (64kB) | 0x14 |
 * | EPCS64  |  64Mb (  8MB) | 512kb  (64kB) | 0x16 |
 */

/*
 * Do not use r1 for optimization
 */
.set noat

/*
 * Length of EPCS Controller's Boot ROM Memory (in words)
 */
#ifndef EPCS_BOOTROM_WORDS
//# define EPCS_BOOTROM_WORDS	0x080	// Cyclone and Cyclone II
# define EPCS_BOOTROM_WORDS	0x100	// Other device families
#endif
.equ	BOOTROM_WORDS,	EPCS_BOOTROM_WORDS

#if !defined(EPCS_ELF_BYTES) && !defined(EPCS_ELF_SECTORS) && !defined(EPCS_ELF_AFTER_SOF)
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

/*
 * After SOF mode
 * (Automatically detects the length of configuration data)
 */
//# define EPCS_ELF_AFTER_SOF	1
#endif

/*
 * Register usage
 */
#define r_zero			r0
#define r_temp			r1	/* Temporary */
#define r_return		r2	/* Used in RCALL, RRET */
#define r_epcs_base		r3	/* Base of EPCS controller */
#define r_elf_base		r4	/* Base of ELF data */
#define r_opt_count		r5	/* SOF option bit count */
#define r_e_entry		r5	/* (e_entry) */
#define r_e_phoff		r6	/* (e_phoff) */
#define r_e_phentsize	r7	/* (e_phentsize) */
#define r_e_phnum		r8	/* (e_phnum) */
#define r_p_paddr		r9	/* (p_paddr) */
#define r_paddr_fend	r10	/* (p_paddr + p_filesz) */
#define r_paddr_mend	r11	/* (p_paddr + p_memsz) */
#define r_epcs_count	r12	/* Used in epcs_txrx_word */
#define r_epcs_read		r13	/* Used in epcs_txrx_word */
#define r_epcs_write	r14	/* Used in epcs_txrx_word */
#define r_p_type		r15	/* (p_type) */
/*
 * r15-r31 : Free area for decompressor
 * (If decompressor does not use epcs_txrx_word, r12-r14 are also free)
 */

#define ELF_HEADER_LE		0x464c457f
#define ET_EXEC				2
#define EM_NIOS2			0x71
#define PT_LOAD				1
#define PT_LOPROC			0x70000000
#define PT_LOAD_LZSS		(PT_LOPROC|0x10000)
#define PT_LOAD_LZ4			(PT_LOPROC|0x20000)

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
 * LZSS compression parameters
 */
#define LZSS_REF_BITS	12
#define LZSS_REF_OFFSET	1
#define LZSS_LEN_BITS	4
#define LZSS_LEN_MIN	4
#define LZSS_ESC_CHAR	0xffff
#define LZSS_ESC_END	0xfffe

/*
 * Parameter check
 */
#if (defined(EPCS_ELF_BYTES) && defined(EPCS_ELF_SECTORS)) || \
	(defined(EPCS_ELF_BYTES) && defined(EPCS_ELF_AFTER_SOF)) || \
	(defined(EPCS_ELF_SECTORS) && defined(EPCS_ELF_AFTER_SOF))
	.print "**** One of EPCS_ELF_BYTES, EPCS_ELF_SECTORS or EPCS_ELF_AFTER_SOF must be defined ****"
	.err
#endif

/*********************************************************************************
 * Macros
 *********************************************************************************/

/*
 * Pseudo move instruction with 32-bit immediate
 *   Operation: rA <= IMM32
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
 * Pseudo and instruction with 32-bit immediate
 *   Operation: rB <= rA & IMM32
 *   Syntax:    ANDI32 rB, rA, IMM32
 */
.macro ANDI32 rB,rA,IMM32
	.if (\IMM32 & 0xffff0000)
		.if (\IMM32 & 0x0000ffff)
			MOVI32	\rB, \IMM32
			and		\rB, \rB, \rA
		.else
			andhi	\rB, \rA, %hi(\IMM32)
		.endif
	.else
		andi	\rB, \rA, %lo(\IMM32)
	.endif
.endm

/*
 * Relative call
 *   Syntax: RCALL label
 */
.macro RCALL label
	nextpc	r_return
	br		\label
.endm

/*
 * Return for RCALL
 *   Syntax: RRET
 */
.macro RRET
	addi	r_return, r_return, 4
	jmp		r_return
.endm

/*
 * Open EPCS connection (Start CS# output)
 */
.macro EPCS_OPEN
	MOVI32	r_temp, EPCS_CONTROL_SSO
	stwio	r_temp, EPCS_CONTROL(r_epcs_base)
.endm

/*
 * Send and receive one byte
 */
.macro EPCS_TXRX rTX,rRX
	stwio	\rTX, EPCS_TXDATA(r_epcs_base)
99:	ldwio	r_temp, EPCS_STATUS(r_epcs_base)
	andi	r_temp, r_temp, EPCS_STATUS_RRDY
	beq		r_temp, r_zero, 99b
	ldbuio	\rRX, EPCS_RXDATA(r_epcs_base)
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
	.global _start
_start:
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

#ifndef EPCS_ELF_AFTER_SOF
	// Get EPCS Silicon ID
	movhi	r_epcs_write, %hi(EPCS_READ_SILICON_ID << 24)
	RCALL	epcs_txrx_word
	RCALL	epcs_txrx_word
	EPCS_CLOSE

	// Calculate EPCS capacity
	movui	r_elf_base, (1 << 1)
	sll		r_elf_base, r_elf_base, r_epcs_read

#ifdef EPCS_ELF_BYTES
	// Calculate ELF base address (EndOfEPCS - EPCS_ELF_BYTES)
	addi	r_elf_base, r_elf_base, -EPCS_ELF_BYTES
#endif	/* EPCS_ELF_BYTES */
#ifdef EPCS_ELF_SECTORS
	// Calculate ELF base address (EndOfEPCS - SectorSize*EPCS_ELF_SECTORS)
	addi	r_epcs_read, r_epcs_read, 7
	andi	r_epcs_read, r_epcs_read, 8
	srli	r_epcs_read, r_epcs_read, 3
	addi	r_epcs_read, r_epcs_read, 15
	MOVI32	r_temp, EPCS_ELF_SECTORS
	sll		r_temp, r_temp, r_epcs_read
	sub		r_elf_base, r_elf_base, r_temp
#endif	/* EPCS_ELF_SECTORS */

	// Check ELF header (e_ident)
	orhi	r_elf_base, r_elf_base, %hi(EPCS_READ_BYTES << 24)
	mov		r_epcs_write, r_elf_base
	RCALL	epcs_txrx_word
	RCALL	epcs_txrx_word
	EPCS_CLOSE
	MOVI32	r_temp, ELF_HEADER_LE
	bne		r_epcs_read, r_temp, halt

#else	/* EPCS_ELF_AFTER_SOF */

	// Get configuration data length (only bit[27..0])
	// r_elf_base <= 0b7650_0000_0000_0000_0000_0000_0000_0000 set27_25
	// r_elf_base <= 0b0000_7650_0000_0000_0000_0000_0000_3210 loop[6]
	// r_elf_base <= 0b3210_0000_7650_0000_0000_0000_0000_7654 loop[5]
	// r_elf_base <= 0b7654_3210_0000_7650_0000_0000_0000_1098 loop[4]
	// r_elf_base <= 0b1098_7654_3210_0000_7650_0000_0000_5432 loop[3]
	// r_elf_base <= 0b5432_1098_7654_3210_0000_7650_0000_9876 loop[2]
	// r_elf_base <= 0b9876_5432_1098_7654_3210_0000_7650_3210 loop[1]
	// r_elf_base <= 0b9876_5432_1098_7654_3210_0000_7654_3210 set24
	// r_elf_base <= 0b0000_7654_3210_9876_5432_1098_7654_3210 rotate
	MOVI32	r_epcs_write, ((EPCS_READ_BYTES << 24) + 33)
	RCALL	epcs_txrx_word
	RCALL	epcs_txrx_word
	slli	r_epcs_read, r_epcs_read, 1
	RCALL	extract_bit5s
	slli	r_elf_base, r_epcs_read, 29	// set27_25
	EPCS_CLOSE
	MOVI32	r_epcs_write, ((EPCS_READ_BYTES << 24) + 48)
	RCALL	epcs_txrx_word
	MOVI32	r_opt_count, 6
1:	RCALL	epcs_txrx_word
	RCALL	extract_bit5s
	roli	r_elf_base, r_elf_base, (32-4)
	or		r_elf_base, r_elf_base, r_epcs_read	// loop[r_opt_count]
	subi	r_opt_count, r_opt_count, 1
	bne		r_opt_count, r_zero, 1b
	RCALL	epcs_txrx_word
	EPCS_CLOSE
	srli	r_temp, r_epcs_read, 1
	andi	r_temp, r_temp, 0x0010
	or		r_elf_base, r_elf_base, r_temp	// set24
	roli	r_elf_base, r_elf_base, (32-12)	// rotate

	// Convert bits to bytes
	addi	r_elf_base, r_elf_base, 7
	srli	r_elf_base, r_elf_base, 3

	// Check ELF header (e_ident)
	// If no ELF header found at r_elf_base, retry at r_elf_base+1
	// (This is workaround for difference for compression data)
	orhi	r_elf_base, r_elf_base, %hi(EPCS_READ_BYTES << 24)
	mov		r_epcs_write, r_elf_base
	RCALL	epcs_txrx_word
	RCALL	epcs_txrx_word
	EPCS_CLOSE
	MOVI32	r_temp, ELF_HEADER_LE
	beq		r_epcs_read, r_temp, 1f
	addi	r_elf_base, r_elf_base, 1
	mov		r_epcs_write, r_elf_base
	RCALL	epcs_txrx_word
	RCALL	epcs_txrx_word
	EPCS_CLOSE
	bne		r_epcs_read, r_temp, halt
1:
#endif	/* EPCS_ELF_AFTER_SOF */

	// Check e_type and e_machine
	addi	r_epcs_write, r_elf_base, 16	// offsetof(Elf32_ehdr, e_type)
	RCALL	epcs_txrx_word
	RCALL	epcs_txrx_word
	MOVI32	r_temp, (ET_EXEC | (EM_NIOS2 << 16))
	bne		r_epcs_read, r_temp, halt

	// Read e_entry, e_phoff, e_phentsize and e_phnum
	RCALL	epcs_txrx_word			// e_version
	RCALL	epcs_txrx_word			// e_entry
	mov		r_e_entry, r_epcs_read
	RCALL	epcs_txrx_word			// e_phoff
	add		r_e_phoff, r_elf_base, r_epcs_read
	RCALL	epcs_txrx_word			// e_shoff
	RCALL	epcs_txrx_word			// e_flags
	RCALL	epcs_txrx_word			// lo16:e_ehsize, hi16:e_phentsize
	srli	r_e_phentsize, r_epcs_read, 16
	RCALL	epcs_txrx_word			// lo16:e_phnum, hi16:e_shentsize
	andi	r_e_phnum, r_epcs_read, 0xffff
	EPCS_CLOSE

load_program_header:
	// Read Elf32_phdr fields
	mov		r_epcs_write, r_e_phoff
	RCALL	epcs_txrx_word			// opcode and address
	RCALL	epcs_txrx_word			// p_type
	mov		r_p_type, r_epcs_read
	RCALL	epcs_txrx_word			// p_offset
	add		r_epcs_write, r_elf_base, r_epcs_read
	RCALL	epcs_txrx_word			// p_vaddr
	RCALL	epcs_txrx_word			// p_paddr
	mov		r_p_paddr, r_epcs_read
	RCALL	epcs_txrx_word			// p_filesz
	add		r_paddr_fend, r_p_paddr, r_epcs_read
	RCALL	epcs_txrx_word			// p_memsz
	beq		r_epcs_read, r_zero, next_program_header
	add		r_paddr_mend, r_p_paddr, r_epcs_read
	beq		r_paddr_fend, r_p_paddr, fill_remainder_area
	EPCS_CLOSE

	RCALL	epcs_txrx_word			// opcode and address
#ifdef EPCS_COMPRESS_LZSS
	MOVI32	r_temp, PT_LOAD_LZSS
	beq		r_temp, r_p_type, decompress_lzss
#endif	/* EPCS_COMPRESS_LZSS */
#ifdef EPCS_COMPRESS_LZ4
	MOVI32	r_temp, PT_LOAD_LZ4
	beq		r_temp, r_p_type, decompress_lz4
#endif	/* EPCS_COMPRESS_LZ4 */
	MOVI32	r_temp, PT_LOAD
	bne		r_temp, r_p_type, next_program_header

	// Load uncompressed data (Must be 4-byte aligned)
1:	RCALL	epcs_txrx_word
	stw		r_epcs_read, 0(r_p_paddr)
	addi	r_p_paddr, r_p_paddr, 4
	bltu	r_p_paddr, r_paddr_fend, 1b
	br		fill_remainder_area

	// Fill remainder area (Must be 4-byte aligned)
1:	stw		r_zero, 0(r_p_paddr)
	addi	r_p_paddr, r_p_paddr, 4
fill_remainder_area:
	bltu	r_p_paddr, r_paddr_mend, 1b

next_program_header:
	EPCS_CLOSE
	add		r_e_phoff, r_e_phoff, r_e_phentsize
	addi	r_e_phnum, r_e_phnum, -1
	bne		r_e_phnum, r_zero, load_program_header

start_program:
	jmp		r_e_entry

#ifdef EPCS_COMPRESS_LZSS
#error LZSS decompressor is not implemented
decompress_lzss:
	br		halt
#endif	/* EPCS_COMPRESS_LZSS */

#ifdef EPCS_COMPRESS_LZ4
#define r_lz4_15		r12
#define r_lz4_255		r13
#define r_lz4_lit		r14
#define r_lz4_match		r15
#define r_lz4_window	r16
decompress_lz4:
	// Initialize constants
	MOVI32	r_lz4_255, 255
	MOVI32	r_lz4_15, 15
1:	// Read token
	EPCS_TXRX r_zero, r_temp
	srli	r_lz4_lit, r_temp, 4
	andi	r_lz4_match, r_temp, 15
	bne		r_lz4_lit, r_lz4_15, 4f
2:	// Read additional literal length
	EPCS_TXRX r_zero, r_temp
	add		r_lz4_lit, r_lz4_lit, r_temp
	beq		r_temp, r_lz4_255, 2b
3:	// Read literal
	EPCS_TXRX r_zero, r_temp
	stb		r_temp, 0(r_p_paddr)
	addi	r_p_paddr, r_p_paddr, 1
4:	bgtu	r_lz4_lit, r_zero, 3b
	// Read offset and calc window position
	// (if offset == 0, stop decompressing)
	EPCS_TXRX r_zero, r_temp
	sub		r_lz4_window, r_p_paddr, r_temp
	EPCS_TXRX r_zero, r_temp
	slli	r_temp, r_temp, 8
	sub		r_lz4_window, r_lz4_window, r_temp
	beq		r_lz4_window, r_p_paddr, fill_remainder_area
	addi	r_lz4_match, r_lz4_match, 4
	add		r_lz4_match, r_lz4_match, r_lz4_window
	bne		r_lz4_match, r_lz4_15, 6f
5:	// Read additional match bytes
	EPCS_TXRX r_zero, r_temp
	add		r_lz4_match, r_lz4_match, r_temp
	beq		r_temp, r_lz4_255, 5b
6:	// Output matched data
	ldbu	r_temp, 0(r_lz4_window)
	stb		r_temp, 0(r_p_paddr)
	addi	r_lz4_window, r_lz4_window, 1
	addi	r_p_paddr, r_p_paddr, 1
	bltu	r_lz4_window, r_lz4_match, 6b
	br		1b
#endif	/* EPCS_COMPRESS_LZ4 */

halt:
	br		halt

/*
 * epcs_txrx_word - TX and RX 4 bytes (Must be called by RCALL)
 *   Input:  r_epcs_write - TX data (MSB first, big-endian)
 *   Output: r_epcs_read  - RX data (MSB first, little-endian)
 */
epcs_txrx_word:
	EPCS_OPEN
	MOVI32	r_epcs_count, 4
	mov		r_epcs_read, r_zero
1:	roli	r_epcs_write, r_epcs_write, 8
	EPCS_TXRX r_epcs_write, r_temp
	or		r_epcs_read, r_epcs_read, r_temp
	roli	r_epcs_read, r_epcs_read, 24
	addi	r_epcs_count, r_epcs_count, -1
	bne		r_epcs_count, r_zero, 1b
	RRET

#ifdef EPCS_ELF_AFTER_SOF
/*
 * extract_bit5s - Extract bit5 of each byte (Must be called by RCALL)
 *   Input:  r_epcs_read (0b**A*****_**B*****_**C*****_**D*****)
 *   Output: r_epcs_read (0b00000000_00000000_00000000_0000ABCD)
 */
extract_bit5s:
# xxAxxxxxxxBxxxxxxxCxxxxxxxDxxxxx (r_epcs_read)
	ori		r_epcs_read, r_epcs_read, 0xdfdf
	orhi	r_epcs_read, r_epcs_read, 0xdfdf
# 11A1111111B1111111C1111111D11111 (r_epcs_read)
	srli	r_temp, r_epcs_read, 7
# 000011111A1111111B1111111C111111 (r_temp)
	and		r_temp, r_temp, r_epcs_read
# 000011111AB111111BC111111CD11111 (r_temp)
	srli	r_epcs_read, r_temp, 14
# 00000000000000000011111AB1111111 (r_epcs_read)
	and		r_temp, r_temp, r_epcs_read
# 000000000000000000C1111ABCD11111 (r_temp)
	srli	r_temp, r_temp, 5
	andi	r_epcs_read, r_temp, 0xf
# 0000000000000000000000000000ABCD (r_epcs_read)
	RRET
#endif	/* EPCS_ELF_AFTER_SOF */

