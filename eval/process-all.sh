#!/bin/bash
rm -rf processed/
mkdir -p processed/recovered/{proc,file}
mkdir -p processed/device/{proc,file}

find raw/device/file -type f -print0 |
    while IFS= read -r -d $'\0' line; do
      fn=$(basename $line)
      of="processed/device/file/$fn"
      echo $fn
      ./tools/format-device-mac-dac.sh "$line" "$of"
    done

find raw/recovered/file -type f -print0 |
    while IFS= read -r -d $'\0' line; do
      fn=$(basename $line)
      of="processed/recovered/file/$fn"
      echo $fn
      ./tools/format-firmware-mac-dac.sh "$line" "$of"
    done
