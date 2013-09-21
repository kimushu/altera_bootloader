
Q ?= @

SOURCES = $(wildcard *.S)

all: $(SOURCES:.S=.hex)

clean:
	$(Q)rm -f $(SOURCES:.S=.{elf,hex})

.PRECIOUS: %.hex
%.hex: %.elf
	$(Q)nios2-elf-objcopy -O ihex $< $@.2
	$(Q)ruby ../convert_hex.rb < $@.2 > $@ || (rm -f $@.2; test)
	$(Q)rm $@.2

.PRECIOUS: %.elf
%.elf: %.S
	$(Q)nios2-elf-gcc -c -nostartfiles -o $@ $<
	$(Q)nios2-elf-readelf -S $@ | grep -e "Name\\|text"

