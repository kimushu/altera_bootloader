
Q ?= @

SOURCES = $(wildcard *.S)

HEX = [0-9A-F]
HEX2 = $(HEX)\{2\}
HEX8 = $(HEX)\{8\}

all: $(SOURCES:.S=.tcl)

clean:
	$(Q)rm -f $(SOURCES:.S=.{elf,hex})

%.tcl: %.srec Makefile
	$(Q)echo "set m [lindex [get_service_paths master] 0]" > $@
	$(Q)echo "open_service master \$$m" >> $@
	$(Q)echo "master_write_32 \$$m \$$a \\" >> $@
	$(Q)sed -ne "s/^S309$(HEX8)\($(HEX2)\)\($(HEX2)\)\($(HEX2)\)\($(HEX2)\).*/0x\4\3\2\1 \\\\/p" $< >> $@
	$(Q)echo "0xffffffff" >> $@
	$(Q)echo "close_service master \$$m" >> $@

.PRECIOUS: %.srec
%.srec: %.hex
	$(Q)nios2-elf-objcopy -I ihex -O srec --srec-len 4 --srec-forceS3 $< $@

.PRECIOUS: %.hex
%.hex: %.elf
	$(Q)nios2-elf-objcopy -O ihex $< $@.2
	$(Q)ruby ../convert_hex.rb < $@.2 > $@ || (rm -f $@.2; test)
	$(Q)rm $@.2

.PRECIOUS: %.elf
%.elf: %.S
	$(Q)nios2-elf-gcc -c -nostartfiles -o $@ $<
	$(Q)nios2-elf-readelf -S $@ | grep -e "Name\\|text"

