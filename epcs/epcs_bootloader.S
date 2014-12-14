/**
 * @file epcs_bootloader.S
 * @brief EPCS/SPI Flash boot loader
 * @author kimu_shu
 */

/*
 * Supported EPCS devices:
 * (EPCS_BOOTROM_WORDS must be defined)
 * | Part#   | Capacity      | Sector size   | ID*1 |
 * | EPCS1   |   1Mb (128kB) | 256kb  (32kB) | 0x10 |
 * | EPCS4   |   4Mb (512kB) | 512kb  (64kB) | 0x12 |
 * | EPCS16  |  16Mb (  2MB) | 512kb  (64kB) | 0x14 |
 * | EPCS64  |  64Mb (  8MB) | 512kb  (64kB) | 0x16 |
 * (*1: Read by command 0xab)
 *
 * Supported SPI flash devices:
 * (SPI_CONTROLLER_BASE must be defined)
 * | Mfr.   | Part#   | Capacity      | Sector size   | ID *2 |
 * | Micron | M25P20  |   2Mb (256kB) | 512kb  (64kB) | 2012h |
 * | Micron | M25P40  |   4Mb (512kB) | 512kb  (64kB) | 2013h |
 * (*2: Read by command 0x9f)
 */

/*
 * Do not use r1 for optimization
 */
.set noat

/*
 * Register usage
 */
#define r_zero			r0
#define r_temp			r1	/* Temporary */
#define r_return		r2	/* Used in RCALL, RRET */
#define r_spim_base		r3	/* Base of EPCS/SPImaster controller */
#define r_elf_base		r4	/* Base of ELF data */
#define r_opt_count		r5	/* SOF option bit count */
#define r_elf_magic		r5	/* ELF header magic */
#define r_e_entry		r5	/* (e_entry) */
#define r_e_phoff		r6	/* (e_phoff) */
#define r_e_phentsize	r7	/* (e_phentsize) */
#define r_e_phnum		r8	/* (e_phnum) */
#define r_p_paddr		r9	/* (p_paddr) */
#define r_paddr_fend	r10	/* (p_paddr + p_filesz) */
#define r_paddr_mend	r11	/* (p_paddr + p_memsz) */
#define r_spim_count	r12	/* Used in flash_txrx_word */
#define r_spim_read		r13	/* Used in flash_txrx_word */
#define r_spim_write	r14	/* Used in flash_txrx_word */
#define r_p_type		r15	/* (p_type) */
/*
 * r15-r31 : Free area for decompressor
 * (If decompressor does not use flash_txrx_word, r12-r14 are also free)
 */

#define ELF_HEADER_LE		0x464c457f
#define ET_EXEC				2
#define EM_NIOS2			0x71
#define PT_LOAD				1
#define PT_LOPROC			0x70000000
#define PT_LOAD_LZSS		(PT_LOPROC|0x10000)
#define PT_LOAD_LZ4			(PT_LOPROC|0x20000)

/*
 * EPCS controller / SPI controller registers
 */
#define REG_RXDATA			0x00
#define REG_TXDATA			0x04
#define REG_STATUS			0x08
#define REG_CONTROL			0x0c
#define REG_SLAVESELECT		0x14

#define SPI_STATUS_RRDY		0x080
#define SPI_CONTROL_SSO		0x400

#define CMD_READ_BYTES			0x03
#define CMD_READ_SILICON_ID		0xab
#define CMD_READ_DEVICE_ID		0x9f

/*
 * LZSS compression parameters
 */
#define LZSS_REF_BITS	12
#define LZSS_REF_OFFSET	1
#define LZSS_LEN_BITS	4
#define LZSS_LEN_MIN	4
#define LZSS_ESC_CHAR	0xffff
#define LZSS_ESC_END	0xfffe

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
 * Open flash connection (Start CS# output)
 */
.macro FLASH_OPEN
#if defined(SPI_CONTROLLER_BASE)
	MOVI32	r_temp, (1<<0)
	stwio	r_temp, REG_SLAVESELECT(r_spim_base)
#endif
	MOVI32	r_temp, SPI_CONTROL_SSO
	stwio	r_temp, REG_CONTROL(r_spim_base)
	ldwio	r_temp, REG_RXDATA(r_spim_base)
.endm

/*
 * Send and receive one byte
 */
.macro FLASH_TXRX rTX,rRX
	stwio	\rTX, REG_TXDATA(r_spim_base)
99:	ldwio	r_temp, REG_STATUS(r_spim_base)
	andi	r_temp, r_temp, SPI_STATUS_RRDY
	beq		r_temp, r_zero, 99b
	ldwio	\rRX, REG_RXDATA(r_spim_base)
.endm

/*
 * Close flash connection (Stop CS# output)
 */
.macro FLASH_CLOSE
	stwio	r_zero, REG_CONTROL(r_spim_base)
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

#if defined(EPCS_BOOTROM_WORDS)
	// Get EPCS controller base address
	nextpc	r_spim_base
	ori		r_spim_base, r_spim_base, (EPCS_BOOTROM_WORDS * 4) - 1
	addi	r_spim_base, r_spim_base, 1
#elif defined(SPI_CONTROLLER_BASE)
	// Get SPI controller base address
	MOVI32	r_spim_base, SPI_CONTROLLER_BASE
#endif	/* SPI_CONTROLLER_BASE */

	FLASH_CLOSE

#if defined(ELF_AT_HEAD)
	MOVI32	r_elf_base, 0
#elif !defined(ELF_AFTER_SOF)
#if defined(EPCS_BOOTROM_WORDS)
	// Get EPCS Silicon ID
	movhi	r_spim_write, %hi(CMD_READ_SILICON_ID << 24)
	RCALL	flash_txrx_word
	RCALL	flash_txrx_word

	// Calculate capacity (2 << SiliconID)
	movui	r_elf_base, (1 << 1)
	sll		r_elf_base, r_elf_base, r_spim_read
#elif defined(SPI_CONTROLLER_BASE)
	// Get SPI flash device ID
	movhi	r_spim_write, %hi(CMD_READ_DEVICE_ID << 24)
	RCALL	flash_txrx_word
	roli	r_spim_read, r_spim_read, 8

	// Calculate capacity (1 << CapacityID)
	movui	r_elf_base, 1
	sll		r_elf_base, r_elf_base, r_spim_read
#endif	/* SPI_CONTROLLER_BASE */
	FLASH_CLOSE

#if defined(ELF_BYTES_AHEAD)
	// Calculate ELF base address (EndOfFlash - ELF_BYTES_AHEAD)
	addi	r_elf_base, r_elf_base, -ELF_BYTES_AHEAD
#endif	/* ELF_BYTES_AHEAD */
#if defined(ELF_SECTORS_AHEAD)
	// Calculate ELF base address (EndOfFlash - SectorSize*ELF_SECTORS_AHEAD)
	addi	r_spim_read, r_spim_read, 7
	andi	r_spim_read, r_spim_read, 8
	srli	r_spim_read, r_spim_read, 3
	addi	r_spim_read, r_spim_read, 15
	MOVI32	r_temp, ELF_SECTORS_AHEAD
	sll		r_temp, r_temp, r_spim_read
	sub		r_elf_base, r_elf_base, r_temp
#endif	/* ELF_SECTORS_AHEAD */
#endif	/* ELF_AFTER_SOF */

#if !defined(ELF_AFTER_SOF)
	// Check ELF header (e_ident)
	orhi	r_elf_base, r_elf_base, %hi(CMD_READ_BYTES << 24)
	mov		r_spim_write, r_elf_base
	RCALL	flash_txrx_word
	RCALL	flash_txrx_word
	FLASH_CLOSE
	MOVI32	r_elf_magic, ELF_HEADER_LE
	bne		r_spim_read, r_elf_magic, halt

#else	/* ELF_AFTER_SOF */

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
	MOVI32	r_spim_write, ((CMD_READ_BYTES << 24) + 33)
	RCALL	flash_txrx_word
	RCALL	flash_txrx_word
	slli	r_spim_read, r_spim_read, 1
	RCALL	extract_bit5s
	slli	r_elf_base, r_spim_read, 29	// set27_25
	FLASH_CLOSE
	MOVI32	r_spim_write, ((CMD_READ_BYTES << 24) + 48)
	RCALL	flash_txrx_word
	MOVI32	r_opt_count, 6
1:	RCALL	flash_txrx_word
	RCALL	extract_bit5s
	roli	r_elf_base, r_elf_base, (32-4)
	or		r_elf_base, r_elf_base, r_spim_read	// loop[r_opt_count]
	subi	r_opt_count, r_opt_count, 1
	bne		r_opt_count, r_zero, 1b
	RCALL	flash_txrx_word
	FLASH_CLOSE
	srli	r_temp, r_spim_read, 1
	andi	r_temp, r_temp, 0x0010
	or		r_elf_base, r_elf_base, r_temp	// set24
	roli	r_elf_base, r_elf_base, (32-12)	// rotate

	// Convert bits to bytes
	addi	r_elf_base, r_elf_base, 7
	srli	r_elf_base, r_elf_base, 3

	// Check ELF header (e_ident)
	// If no ELF header found at r_elf_base, retry at r_elf_base+1
	// (This is workaround for difference for compression data)
	orhi	r_elf_base, r_elf_base, %hi(CMD_READ_BYTES << 24)
	mov		r_spim_write, r_elf_base
	RCALL	flash_txrx_word
	RCALL	flash_txrx_word
	FLASH_CLOSE
	MOVI32	r_elf_magic, ELF_HEADER_LE
	beq		r_spim_read, r_elf_magic, 1f
	addi	r_elf_base, r_elf_base, 1
	mov		r_spim_write, r_elf_base
	RCALL	flash_txrx_word
	RCALL	flash_txrx_word
	FLASH_CLOSE
	bne		r_spim_read, r_elf_magic, halt
1:
#endif	/* ELF_AFTER_SOF */

	// Check e_type and e_machine
	addi	r_spim_write, r_elf_base, 16	// offsetof(Elf32_ehdr, e_type)
	RCALL	flash_txrx_word
	RCALL	flash_txrx_word
	MOVI32	r_temp, (ET_EXEC | (EM_NIOS2 << 16))
	bne		r_spim_read, r_temp, halt

	// Read e_entry, e_phoff, e_phentsize and e_phnum
	RCALL	flash_txrx_word			// e_version
	RCALL	flash_txrx_word			// e_entry
	mov		r_e_entry, r_spim_read
	RCALL	flash_txrx_word			// e_phoff
	add		r_e_phoff, r_elf_base, r_spim_read
	RCALL	flash_txrx_word			// e_shoff
	RCALL	flash_txrx_word			// e_flags
	RCALL	flash_txrx_word			// lo16:e_ehsize, hi16:e_phentsize
	srli	r_e_phentsize, r_spim_read, 16
	RCALL	flash_txrx_word			// lo16:e_phnum, hi16:e_shentsize
	andi	r_e_phnum, r_spim_read, 0xffff
	FLASH_CLOSE

load_program_header:
	// Read Elf32_phdr fields
	mov		r_spim_write, r_e_phoff
	RCALL	flash_txrx_word			// opcode and address
	RCALL	flash_txrx_word			// p_type
	mov		r_p_type, r_spim_read
	RCALL	flash_txrx_word			// p_offset
	add		r_spim_write, r_elf_base, r_spim_read
	RCALL	flash_txrx_word			// p_vaddr
	RCALL	flash_txrx_word			// p_paddr
	mov		r_p_paddr, r_spim_read
	RCALL	flash_txrx_word			// p_filesz
	add		r_paddr_fend, r_p_paddr, r_spim_read
	RCALL	flash_txrx_word			// p_memsz
	beq		r_spim_read, r_zero, next_program_header
	add		r_paddr_mend, r_p_paddr, r_spim_read
	beq		r_paddr_fend, r_p_paddr, fill_remainder_area
	FLASH_CLOSE

	RCALL	flash_txrx_word			// opcode and address
#if defined(ENABLE_COMPRESS_LZSS)
	MOVI32	r_temp, PT_LOAD_LZSS
	beq		r_temp, r_p_type, decompress_lzss
#endif	/* ENABLE_COMPRESS_LZSS */
#if defined(ENABLE_COMPRESS_LZ4)
	MOVI32	r_temp, PT_LOAD_LZ4
	beq		r_temp, r_p_type, decompress_lz4
#endif	/* ENABLE_COMPRESS_LZ4 */
	MOVI32	r_temp, PT_LOAD
	bne		r_temp, r_p_type, next_program_header

	// Load uncompressed data (Must be 4-byte aligned)
1:	RCALL	flash_txrx_word
	stw		r_spim_read, 0(r_p_paddr)
	addi	r_p_paddr, r_p_paddr, 4
	bltu	r_p_paddr, r_paddr_fend, 1b
	br		fill_remainder_area

	// Fill remainder area (Must be 4-byte aligned)
1:	stw		r_zero, 0(r_p_paddr)
	addi	r_p_paddr, r_p_paddr, 4
fill_remainder_area:
	bltu	r_p_paddr, r_paddr_mend, 1b

next_program_header:
	FLASH_CLOSE
	add		r_e_phoff, r_e_phoff, r_e_phentsize
	addi	r_e_phnum, r_e_phnum, -1
	bne		r_e_phnum, r_zero, load_program_header

start_program:
	jmp		r_e_entry

#if defined(ENABLE_COMPRESS_LZSS)
#error LZSS decompressor is not implemented
decompress_lzss:
	br		halt
#endif	/* ENABLE_COMPRESS_LZSS */

#if defined(ENABLE_COMPRESS_LZ4)
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
	FLASH_TXRX r_zero, r_temp
	srli	r_lz4_lit, r_temp, 4
	andi	r_lz4_match, r_temp, 15
	bne		r_lz4_lit, r_lz4_15, 3f
2:	// Read additional literal length
	FLASH_TXRX r_zero, r_temp
	add		r_lz4_lit, r_lz4_lit, r_temp
	beq		r_temp, r_lz4_255, 2b
3:	// Read literal
	add		r_lz4_lit, r_lz4_lit, r_p_paddr
	beq		r_p_paddr, r_lz4_lit, 5f
4:	FLASH_TXRX r_zero, r_temp
	stb		r_temp, 0(r_p_paddr)
	addi	r_p_paddr, r_p_paddr, 1
	bltu	r_p_paddr, r_lz4_lit, 4b
5:	// Read offset and calc window position
	// (if offset == 0, stop decompressing)
	FLASH_TXRX r_zero, r_temp
	sub		r_lz4_window, r_p_paddr, r_temp
	FLASH_TXRX r_zero, r_temp
	slli	r_temp, r_temp, 8
	sub		r_lz4_window, r_lz4_window, r_temp
	beq		r_lz4_window, r_p_paddr, fill_remainder_area
	bne		r_lz4_match, r_lz4_15, 7f
6:	// Read additional match bytes
	FLASH_TXRX r_zero, r_temp
	add		r_lz4_match, r_lz4_match, r_temp
	beq		r_temp, r_lz4_255, 6b
7:	// Output matched data
	addi	r_lz4_match, r_lz4_match, 4
	add		r_lz4_match, r_lz4_match, r_lz4_window
8:	ldbu	r_temp, 0(r_lz4_window)
	stb		r_temp, 0(r_p_paddr)
	addi	r_lz4_window, r_lz4_window, 1
	addi	r_p_paddr, r_p_paddr, 1
	bltu	r_lz4_window, r_lz4_match, 8b
	br		1b
#endif	/* ENABLE_COMPRESS_LZ4 */

halt:
	br		halt

/*
 * flash_txrx_word - TX and RX 4 bytes (Must be called by RCALL)
 *   Input:  r_spim_write - TX data (MSB first, big-endian)
 *   Output: r_spim_read  - RX data (MSB first, little-endian)
 */
flash_txrx_word:
	FLASH_OPEN
	MOVI32	r_spim_count, 4
	mov		r_spim_read, r_zero
1:	roli	r_spim_write, r_spim_write, 8
	FLASH_TXRX r_spim_write, r_temp
	or		r_spim_read, r_spim_read, r_temp
	roli	r_spim_read, r_spim_read, 24
	addi	r_spim_count, r_spim_count, -1
	bne		r_spim_count, r_zero, 1b
	RRET

#if defined(ELF_AFTER_SOF)
/*
 * extract_bit5s - Extract bit5 of each byte (Must be called by RCALL)
 *   Input:  r_spim_read (0b**A*****_**B*****_**C*****_**D*****)
 *   Output: r_spim_read (0b00000000_00000000_00000000_0000ABCD)
 */
extract_bit5s:
# xxAxxxxxxxBxxxxxxxCxxxxxxxDxxxxx (r_spim_read)
	ori		r_spim_read, r_spim_read, 0xdfdf
	orhi	r_spim_read, r_spim_read, 0xdfdf
# 11A1111111B1111111C1111111D11111 (r_spim_read)
	srli	r_temp, r_spim_read, 7
# 000011111A1111111B1111111C111111 (r_temp)
	and		r_temp, r_temp, r_spim_read
# 000011111AB111111BC111111CD11111 (r_temp)
	srli	r_spim_read, r_temp, 14
# 00000000000000000011111AB1111111 (r_spim_read)
	and		r_temp, r_temp, r_spim_read
# 000000000000000000C1111ABCD11111 (r_temp)
	srli	r_temp, r_temp, 5
	andi	r_spim_read, r_temp, 0xf
# 0000000000000000000000000000ABCD (r_spim_read)
	RRET
#endif	/* ELF_AFTER_SOF */

