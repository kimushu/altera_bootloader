
TARGET = elfcompress

LZ4_URL = https://github.com/Cyan4973/lz4.git
# LZ4_BRANCH = r122

.PHONY: all
all: $(TARGET)

$(TARGET): elfcompress.c lz4/liblz4.a
	gcc -o $@ -Wall -I. $^

.PHONY: clean
clean:
	rm -f $(TARGET)

.PHONY: clobber
clobber: clean
	rm -rf lz4

lz4/liblz4.a: lz4/Makefile
	make -C $(dir $<)

lz4/Makefile: lz4

lz4:
	git clone $(addprefix -b,$(LZ4_BRANCH)) $(LZ4_URL) $@

