#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <error.h>
#include <errno.h>
#include <string.h>
#include <elf.h>
#include <lz4/lz4hc.h>

#define PT_LOAD_LZ4			(PT_LOPROC|0x20000)

static void fsafeclose(FILE **pfp);
static int select_method(const char *name);
static int parse_options(int argc, char *argv[]);
static int read_elf(void);
static int write_elf(void);
static size_t lz4hc_compressor(void *dest, const void *src, size_t srclen, size_t destlen);

static int verbose;
static Elf32_Word method_type;
static size_t (*method_func)(void *, const void *, size_t, size_t);
static const char *method_stopper;
static size_t method_stoplen;
static const char *infile;
static const char *outfile;
static FILE *fp;
static Elf32_Ehdr *ehdr;

int main(int argc, char *argv[])
{
	int result;
	extern char *program_invocation_name;
	extern char *program_invocation_short_name;

	program_invocation_name = program_invocation_short_name;
	select_method("lz4");

	result = parse_options(argc, argv);
	if(result != 0)
	{
		error(EXIT_FAILURE, 0, "parse_options failed (%d)", result);
	}

	result = read_elf();
	fsafeclose(&fp);
	if(result != 0)
	{
		free(ehdr);
		error(EXIT_FAILURE, 0, "read_elf failed (%d)", result);
	}

	result = write_elf();
	fsafeclose(&fp);
	if(result != 0)
	{
		free(ehdr);
		error(EXIT_FAILURE, 0, "write_elf failed (%d)", result);
	}

	free(ehdr);
	return EXIT_SUCCESS;
}

static void fsafeclose(FILE **pfp)
{
	if(*pfp) fclose(*pfp);
	*pfp = NULL;
}

static int select_method(const char *name)
{
	if(strcasecmp(name, "lz4") == 0)
	{
		method_type = PT_LOAD_LZ4;
		method_func = lz4hc_compressor;
		method_stopper = "\x00\x00\x00";
		method_stoplen = 3;
	}
	else
	{
		return EINVAL;
	}

	return 0;
}

static int parse_options(int argc, char *argv[])
{
	int ch;

	optind = 1;
	while((ch = getopt(argc, argv, "m:v")) != -1)
	{
		switch(ch)
		{
		case 'm':
			if(select_method(optarg) != 0)
			{
				error(0, 0, "unknown compress method: `%s'", optarg);
				return EINVAL;
			}
			break;
		case 'v':
			++verbose;
			break;
		default:
			return EINVAL;
		}
	}

	if(optind >= argc)
	{
		error(0, 0, "no input file");
		return EINVAL;
	}

	infile = argv[optind++];

	if(optind < argc)
	{
		outfile = argv[optind++];
	}
	else
	{
		outfile = infile;
	}

	if(optind < argc)
	{
		error(0, 0, "too many options: `%s'", argv[optind]);
		return EINVAL;
	}

	return 0;
}

static int read_elf(void)
{
	int len;

	if(verbose >= 1)
	{
		fprintf(stderr, "infile = \"%s\"\n", infile);
	}

	fp = fopen(infile, "rb");
	if(!fp)
	{
		error(0, 0, "cannot open file: `%s'", infile);
		return ENOENT;
	}

	if(fseek(fp, 0, SEEK_END) < 0 || (len = ftell(fp)) < 0)
	{
		error(0, 0, "cannot get length of input file");
		return EIO;
	}

	ehdr = (Elf32_Ehdr *)malloc(len + 4);
	if(!ehdr)
	{
		error(0, 0, "not enough memory");
		return ENOMEM;
	}

	memset((unsigned char *)ehdr + len, 0, 4);
	if(fseek(fp, 0, SEEK_SET) < 0 || fread(ehdr, 1, len, fp) != len)
	{
		error(0, 0, "cannot read input file");
		return EIO;
	}

	if(memcmp(ehdr->e_ident, ELFMAG, SELFMAG) != 0 ||
		ehdr->e_ident[EI_CLASS] != ELFCLASS32 ||
		ehdr->e_ident[EI_DATA] != ELFDATA2LSB ||
		ehdr->e_ident[EI_VERSION] != EV_CURRENT)
	{
		error(0, 0, "unsupported format");
		return ENOTSUP;
	}

	if(verbose >= 1)
	{
		fprintf(stderr, "e_type = 0x%04x\ne_machine = 0x%04x\n",
			ehdr->e_type, ehdr->e_machine);
	}

	return 0;
}

static int write_elf(void)
{
	int ph_index;
	Elf32_Ehdr new_ehdr;
	Elf32_Phdr new_phdr;
	Elf32_Phdr *phdr;
	unsigned char *src;
	unsigned char *buf;

	memcpy(&new_ehdr, ehdr, sizeof(new_ehdr));
	new_ehdr.e_phoff = sizeof(Elf32_Ehdr);
	new_ehdr.e_shoff = 0;
	new_ehdr.e_ehsize = sizeof(Elf32_Ehdr);
	new_ehdr.e_phentsize = sizeof(Elf32_Phdr);
	new_ehdr.e_phnum = 0;
	new_ehdr.e_shentsize = sizeof(Elf32_Shdr);
	new_ehdr.e_shnum = 0;
	new_ehdr.e_shstrndx = 0;

	phdr = (Elf32_Phdr *)((uintptr_t)ehdr + ehdr->e_phoff);
	for(ph_index = 0;
		ph_index < ehdr->e_phnum;
		++ph_index, phdr = (Elf32_Phdr *)((uintptr_t)phdr + ehdr->e_phentsize))
	{
		if(phdr->p_type == PT_LOAD_LZ4)
		{
			// Already compressed
			error(0, 0, "cannot process already compressed file");
			return ENOTSUP;
		}

		if((phdr->p_type != PT_LOAD) || !(phdr->p_flags & PF_W))
		{
			phdr->p_type = PT_NULL;	// Mark as PT_NULL
			if(verbose >= 1)
			{
				fprintf(stderr, "omit program segment #%d\n", ph_index);
			}
			continue;
		}

		++new_ehdr.e_phnum;
	}

	if(verbose >= 1)
	{
		fprintf(stderr, "outfile = \"%s\"\n", outfile);
	}

	fp = fopen(outfile, "wb");
	if(!fp)
	{
		error(0, 0, "cannot open file for writing: `%s'", outfile);
		return EEXIST;
	}

	if(fwrite(&new_ehdr, 1, sizeof(new_ehdr), fp) != sizeof(new_ehdr))
	{
		error(0, 0, "cannot write Elf32_Ehdr");
		return EIO;
	}

	new_phdr.p_offset = new_ehdr.e_phoff + new_ehdr.e_phentsize * new_ehdr.e_phnum;

	phdr = (Elf32_Phdr *)((uintptr_t)ehdr + ehdr->e_phoff);
	for(ph_index = 0;
		ph_index < new_ehdr.e_phnum;
		phdr = (Elf32_Phdr *)((uintptr_t)phdr + ehdr->e_phentsize))
	{
		if(phdr->p_type == PT_NULL) continue;

		new_phdr.p_vaddr = phdr->p_vaddr;
		new_phdr.p_paddr = phdr->p_paddr;
		new_phdr.p_memsz = phdr->p_memsz;
		new_phdr.p_flags = phdr->p_flags;
		new_phdr.p_align = phdr->p_align;
		if(verbose >= 1)
		{
			fprintf(stderr, "(program segment #%d)\noffset = 0x%08x\n"
				"vaddr = 0x%08x\npaddr = 0x%08x\n"
				"memsz = 0x%08x\nflags = 0x%08x\nalign = 0x%08x\n",
				ph_index, new_phdr.p_offset,
				new_phdr.p_vaddr, new_phdr.p_paddr,
				new_phdr.p_memsz, new_phdr.p_flags, new_phdr.p_align);
		}

		buf = (unsigned char *)malloc(phdr->p_filesz + 4);
		if(!buf)
		{
			error(0, 0, "not enough memory");
			return ENOMEM;
		}

		src = (unsigned char *)ehdr + phdr->p_offset;
		new_phdr.p_filesz = (*method_func)(buf, src, phdr->p_filesz, phdr->p_filesz - method_stoplen);
		if(new_phdr.p_filesz > 0)
		{
			new_phdr.p_type = method_type;
			memcpy(buf + new_phdr.p_filesz, method_stopper, method_stoplen);
			memset(buf + new_phdr.p_filesz + method_stoplen, 0, 4);
			src = buf;
		}
		else
		{
			new_phdr.p_type = PT_LOAD;
			new_phdr.p_filesz = phdr->p_filesz;
		}
		if(verbose >= 1)
		{
			fprintf(stderr, "type = 0x%08x\nfilesz = 0x%08x\n",
				new_phdr.p_type, new_phdr.p_filesz);
		}

		if(fseek(fp, new_ehdr.e_phoff + new_ehdr.e_phentsize * ph_index, SEEK_SET) < 0 ||
			fwrite(&new_phdr, 1, new_ehdr.e_phentsize, fp) != new_ehdr.e_phentsize)
		{
			free(buf);
			error(0, 0, "cannot write Elf32_Phdr");
			return EIO;
		}

		if(new_phdr.p_type != PT_LOAD)
		{
			new_phdr.p_filesz += method_stoplen;
			if(verbose >= 1)
			{
				fprintf(stderr, "ratio = %f\n", (double)new_phdr.p_filesz / phdr->p_filesz);
			}
		}
		new_phdr.p_filesz += 3;
		new_phdr.p_filesz &= ~3u;

		if(fseek(fp, new_phdr.p_offset, SEEK_SET) < 0 ||
			fwrite(src, 1, new_phdr.p_filesz, fp) != new_phdr.p_filesz)
		{
			free(buf);
			error(0, 0, "cannot write contents");
			return EIO;
		}

		free(buf);
		new_phdr.p_offset += new_phdr.p_filesz;
		++ph_index;
	}

	return 0;
}

static size_t lz4hc_compressor(void *dest, const void *src, size_t srclen, size_t destlen)
{
	return LZ4_compressHC2_limitedOutput(src, dest, srclen, srclen, 16);
}

