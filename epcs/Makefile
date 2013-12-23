
Q ?= @

SOURCES = $(wildcard *.S)
BOOTROM_WORDS = $(shell nios2-elf-nm $< | sed -ne "s/\([0-9A-F]\{8\}\) a BOOTROM_WORDS/0x\1/p")

all: $(SOURCES:.S=.hex)

clean:
	$(Q)rm -f $(SOURCES:.S=.{elf,hex})

.PRECIOUS: %.hex
%.hex: %.elf
	$(Q)nios2-elf-objcopy -O ihex $< $@.2
	$(Q)ruby ../convert_hex.rb -l -d $(BOOTROM_WORDS) < $@.2 > $@ || (rm -f $@.2; test)
	$(Q)rm $@.2

.PRECIOUS: %.elf
%.elf: %.S
	$(Q)nios2-elf-gcc -c -nostartfiles -o $@ $<
	$(Q)nios2-elf-readelf -S $@ | grep -e "Name\\|text"

