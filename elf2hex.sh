#!/bin/sh
#================================================================================
# ELF to Intel HEX Converter
#
# ** Note **
# This script converts file format with keeping ELF file structure.
#================================================================================

if [[ -z "$1" || -z "$2" ]]; then
  echo "usage: $0 <input-file> <output-file>"
  exit 1
fi
temp=`mktemp`

nios2-elf-objcopy -j.entry -j.text -j.data -j.bss $1 $temp
result=$?
if [[ $result -ne 0 ]]; then
  rm -f $temp
  exit $result
fi

nios2-elf-objcopy -Ibinary -Oihex $temp $2
result=$?
rm -f $temp
exit $result

