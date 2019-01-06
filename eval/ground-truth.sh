#!/bin/bash
set -eu

cp_file() {
  cp $1 ./eval/raw/recovered/file/$2
}
cp_proc() {
  cp $1 ./eval/raw/recovered/proc/$2
}

# Android 7.1.2 (NJH47F, Aug 2017) Pixel 1
# Android 8.1.0 (Pixel 1, in lab version)
# Android 9.0.0 (PPR2.181005.003.A1, Nov 2018) Pixel 1
# Android 7.0 (S7 Edge, in lab version)
CODES=(sailfish-njh47f-factory-6fd9b2c4
sailfish-opm1.171019.011-factory-56d15350
sailfish-ppr2.181005.003.a1-factory-dec6298c
G935FXXU1DPLT_G935FOXA1DPLT_BTU)
VENDORS=(aosp aosp aosp samsung)

count=3
while [ "x${VENDORS[count]}" != "x" ]
do
  CODE=${CODES[count]}
  VENDOR=${VENDORS[count]}

  echo "=================== $VENDOR $CODE ====================="

  # With boot
  ./process.py --vendor $VENDOR $CODE --list-objects

  cp_proc $CODE-processes.txt $CODE-withboot-processes.txt
  cp_file $CODE-files.txt $CODE-withboot-files.txt
  rm $CODE-processes.txt $CODE-files.txt

  # Skip boot
  ./process.py --vendor $VENDOR $CODE --list-objects --skip-boot

  cp_proc $CODE-processes.txt $CODE-skipboot-processes.txt
  cp_file $CODE-files.txt $CODE-skipboot-files.txt
  rm $CODE-processes.txt $CODE-files.txt

  count=$(( $count + 1 ))
done
