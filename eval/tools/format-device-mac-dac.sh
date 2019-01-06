#!/bin/sh
cat $1 |
    sed -E -e 's/,[[:blank:]]+//g' | # remove mknod
    sed -E -e 's/\\ /_/g' | # remove paths with spaces
    awk '{ print $1, $3, $4, $5, $9 }' | # organize
    sort -d -k 5 | # sort by path
    sed -E -e 's/[[:blank:]]+/ /g' | # cannonicalize whitespace
    dos2unix > $2
