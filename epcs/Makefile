
Q ?= @

SOURCES = $(wildcard *.S)
BOOTROM_WORDS = $(shell nios2-elf-nm $< | sed -ne "s/\([0-9A-F]\{8\}\) a BOOTROM_WORDS/0x\1/p")

# DEFINES += EPCS_COMPRESS_LZSS
DEFINES += EPCS_COMPRESS_LZ4

all: $(SOURCES:.S=.hex)

clean:
	$(Q)rm -f $(SOURCES:.S=.{elf,hex})

.PRECIOUS: %.hex
%.hex: %.elf
	$(Q)elf2hex --width=32 --input=$< --output=$@ --base=0 --end=$$(($(BOOTROM_WORDS)*4-1))

.PRECIOUS: %.elf
%.elf: %.S $(MAKEFILE_LIST)
	$(Q)nios2-elf-gcc -nostartfiles -o $@ $(addprefix -D,$(DEFINES)) $<
	$(Q)nios2-elf-objcopy --change-section-lma .text=0 $@ || (rm -f $@; false)
	$(Q)nios2-elf-size $@

