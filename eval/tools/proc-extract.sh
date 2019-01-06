#!/system/bin/sh
self_pid="$$"
pids=`ls /proc | egrep -o '[0-9]+' | sort -n | grep -v "$self_pid"`

realpath / > /dev/null 2>&1
ret=$?
if [ $ret != 0 ]; then
  >&2 echo "FATAL: could not find realpath"
  exit 1
fi

for pid in $pids; do
  proc_data=`cat /proc/$pid/status | egrep '^(Name|PPid|Pid|Uid|Gid|Groups|Cap)'` > /dev/null 2>&1
  ret=$?

  if [ $ret != 0 ]; then
    >&2 echo "WARN: pid $pid is gone"
    continue
  fi

  sid=`cat /proc/$pid/attr/current`
  ret=$?

  if [ $ret != 0 ]; then
    >&2 echo "WARN: pid $pid SEContext failed"
    continue
  fi

  path=`realpath /proc/$pid/exe` > /dev/null 2>&1
  ret=$?
  echo "$sid" | egrep -q 'u:r:kernel:s0'
  is_kernel=$?

  if [ $ret != 0 ]; then
    if [ $is_kernel != 0 ]; then
      >&2 echo "WARN: dropping pid $pid as realpath failed (this is bad)"
    fi

    continue
  fi

  echo -e "Exe:\t$path"
  echo -e "Sid:\t$sid"
  echo "$proc_data"
  echo
done
