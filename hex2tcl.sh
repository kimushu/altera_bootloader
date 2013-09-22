#!/bin/sh
echo "set m [lindex [get_service_paths master] 0]"
echo "open_service master \$m"
echo "master_write_32 \$m $2 \\"
sed -ne "s/^:04....00\([0-9A-F]\{8\}\)..$/0x\1 \\\\/p" $1
echo "0xFFFFFFFF"
echo "close_service master \$m"
