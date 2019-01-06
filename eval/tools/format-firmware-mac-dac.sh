#!/bin/sh
cat $1 |
    awk '{ print $1, $3, $4, $5, $6 }' | # organize
    sort -d -k 5 | # sort by path
    sed -E -e 's/[[:blank:]]+/ /g' | # cannonicalize whitespace
    dos2unix > $2
