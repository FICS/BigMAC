#!/usr/bin/env python3
from collections import OrderedDict
import argparse
import os
import re

from android.dac import Cred
from android.capabilities import Capabilities
from android.sepolicy import SELinuxContext

from IPython import embed

class Process(object):
    def __init__(self, exe, name, pid, ppid, cred):
        self.exe   = exe
        self.name  = name
        self.pid   = pid
        self.ppid  = ppid
        self.cred  = cred

    def diff(self, other):
        if not isinstance(other, Process):
            raise ValueError("Cannot diff process")

        return self.cred.diff(other.cred)

    def __eq__(self, other):
        if not isinstance(other, Process):
            return False

        return self.pid == other.pid and \
            self.ppid == other.pid and \
            repr(self) == repr(other)

    def __repr__(self):
        return "<Process %s (%s) %s>" % (self.exe, self.name, self.cred)

def read_data(data):
    processes = []

    expect_exe = True

    exe = ""
    name = ""
    pid = ""
    ppid = ""
    cred = Cred()

    has_capamb = data.find("CapAmb:") != -1

    for line_no, line in enumerate(data.split("\n")):
        # Ignore comments and blank lines
        if re.match('^(\s*#)|(\s*$)', line):
            continue

        # greedly replace all whitespace with a single space for splitting
        line = re.sub('\s+', " ", line)

        # split by spaces, while eliminating empty components
        components = list(filter(lambda x: len(x) > 0, line.split(" ")))
        field = components[0][:-1]
        args = components[1:]

        if field == "WARN":
            continue

        if expect_exe and field != "Exe":
            raise ValueError("Expected exe")
        elif not expect_exe and field == "Exe":
            raise ValueError("Unexpected exe")

        if field == "Exe":
            expect_exe = False
            exe = args[0]
        elif field == "Sid":
            cred.sid = SELinuxContext.FromString(args[0])
        elif field == "Name":
            name = args[0]
        elif field == "Pid":
            pid = int(args[0])
        elif field == "PPid":
            ppid = int(args[0])
        elif field == "Uid":
            # ignore other UIDs
            cred.uid = int(args[0])
        elif field == "Gid":
            # ignore other UIDs
            cred.gid = int(args[0])
        elif field == "Groups":
            for g in args:
                cred.add_group(int(g))
        elif "Cap" in field:
            capset = field[3:]
            capv = int(args[0], 16)
            capbits = []

            for i in range(64):
                if capv & (1 << i):
                    capbits += [i]

            capvalues = set(list(map(Capabilities.bit_to_name, capbits)))

            if capset == "Inh":
                cred.cap.inherited = capvalues
            elif capset == "Prm":
                cred.cap.permitted = capvalues
            elif capset == "Eff":
                cred.cap.effective = capvalues
            elif capset == "Bnd":
                if not has_capamb:
                    expect_exe = True
                cred.cap.bounding = capvalues
            elif capset == "Amb":
                cred.cap.ambient = capvalues
                expect_exe = True
            else:
                raise ValueError("unexpected capset")
        else:
            raise ValueError("unk field")

        if expect_exe:
            processes += [Process(exe, name, pid, ppid, cred)]
            exe = ""
            name = ""
            pid = ""
            ppid = ""
            cred = Cred()

    # remove rooting tool processes
    processes = list(filter(lambda x: "magisk" not in (x.exe.lower()+x.name.lower()+str(x.cred.sid).lower()), processes))

    return processes

def fnum(n):
    nn = ""
    n = str(n)
    for i in range(len(n)):
        if i > 0:
            if i % 3 == 0:
                nn += ","

        nn += n[len(n) - i - 1]

    return nn[::-1]

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--debug", action="store_true")
    parser.add_argument("--detailed", action="store_true")
    parser.add_argument("--flatten", action="store_true")
    parser.add_argument("--levels", default=1, type=int)
    parser.add_argument("recovered")
    parser.add_argument("real")

    args = parser.parse_args()

    recovered_data = open(args.recovered).read()
    real_data = open(args.real).read()

    bad_proc = []
    good_proc = []
    extra_proc = []

    recovered_dict = OrderedDict()
    real_dict = OrderedDict()
    real_name_dict = OrderedDict()

    recovered = read_data(recovered_data)
    real = read_data(real_data)

    for p in recovered:
        if p.exe not in recovered_dict:
            recovered_dict[p.exe] = []
        recovered_dict[p.exe] += [p]

    for p in real:
        if p.exe not in real_dict:
            real_dict[p.exe] = []
        real_dict[p.exe] += [p]

    for p in real:
        if p.exe not in real_name_dict:
            real_name_dict[p.name] = []
        real_name_dict[p.name] += [p]

    # Find a process pair
    matching = []

    for exe, proc_list in recovered_dict.items():
        for proc in proc_list:
            matches = []
            if proc.name in real_name_dict:
                for rproc in real_name_dict[proc.name]:
                    if rproc.cred.sid == proc.cred.sid:
                        matches += [[proc, rproc]]
            if exe in real_dict:
                for rproc in real_dict[exe]:
                    if rproc.cred.sid == proc.cred.sid:
                        matches += [[proc, rproc]]

            if len(matches):
                # Just choose the first match
                matching += [matches[0]]
            else:
                extra_proc += [proc]

    print("----- MISSING PROCESS REPORT -----")
    real_paired_procs = [x[1] for x in matching]
    missing_real_procs = list(filter(lambda x: x not in real_paired_procs, real))
    missing_exe_cnt = {}
    missing_sid_cnt = {}

    native_missing = 0
    app_missing = 0

    print("Missing %s processes " % len(missing_real_procs))

    for proc in missing_real_procs:
        exe = proc.exe
        sid = str(proc.cred.sid)

        if exe not in missing_exe_cnt:
            missing_exe_cnt[exe] = 0
        missing_exe_cnt[exe] += 1
        if sid not in missing_sid_cnt:
            missing_sid_cnt[sid] = 0
        missing_sid_cnt[sid] += 1

        if "app" in str(sid) or "app_process" in exe:
            app_missing += 1
        else:
            native_missing += 1

        print(proc)

    print("")
    print("----- PROCESS PAIRING DIFF -----")
    print("Got %s process pairs" % len(matching))
    for lproc, rproc in matching:
        diffr = lproc.diff(rproc)

        if diffr != "":
            print("%-30s %-30s { %s }" % (lproc.exe, lproc.cred.sid, diffr))
            bad_proc += [lproc]
        else:
            good_proc += [lproc]

    print("")
    print("----- STATS -----")
    print("Recovered processes %s, Real processes %s" % (fnum(len(recovered)), fnum(len(real))))
    n = len(good_proc)
    n2 = len(bad_proc)
    print("Good processes %s (%.1f), Bad processes %s (%.1f)" % (fnum(n), float(n)/len(recovered)*100.0,
        fnum(n2), float(n2)/len(recovered)*100.0))
    n = len(recovered) - len(matching)
    print("Extra processes %s (%.1f)" % (fnum(n), float(n)/len(recovered)*100.0))
    print("Missing %d processes (%.1f)" % (len(missing_real_procs), float(len(missing_real_procs))/len(real)*100.0))
    print("Missing %d NATIVE processes (%.1f)" % (native_missing, float(native_missing)/len(real)*100.0))
    print("Missing %d APP processes (%.1f)" % (app_missing, float(app_missing)/len(real)*100.0))
    print("Missing %d unique SIDs " % len(missing_sid_cnt))
    for sid, c in sorted(list(missing_sid_cnt.items()), key=lambda x: x[1], reverse=True):
        if c > 1 or args.detailed:
            print("%s - %d" % (sid, c))

    print("")
    print("Missing %d unique EXEs " % len(missing_exe_cnt))
    for exe, c in sorted(list(missing_exe_cnt.items()), key=lambda x: x[1], reverse=True):
        if c > 1 or args.detailed:
            print("%s - %d" % (exe, c))

    if args.debug:
        embed()

if __name__ == "__main__":
    main()

