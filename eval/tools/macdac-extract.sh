#!/system/bin/sh
# Supported Phones:
#   - Rooted Pixel 1 8.1.0
#
# Pixel 1 Spurious files
#   - /sbin/.core/* is an artifact from Magisk root
#   - /system_root is just a mirror of /system for Magisk system-less root
#
# /proc is way too crazy
# /sys/* is also way too crazy
# /acct is for cgroups
# /d/ is just debugfs symb link to /sys/kernel/debug

find / \( -path '/proc/*' -o -path '/sys/*' -o -path '/sbin/.core' -o -path '/system_root' -o -path '/acct' -o -path '/d/*' \) -prune -o -print0 |
    while IFS= read -r -d $'\0' line; do
        ls -dlZ "$line"
    done
