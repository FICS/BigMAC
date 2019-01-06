#!/usr/bin/env python
from collections import OrderedDict
import argparse
import os

def read_data(data):
    files = OrderedDict()

    for line in data.split("\n"):
        if line == "":
            continue

        if "Permission denied" in line:
            continue

        components = line.split(" ")

        if len(components) < 5:
            raise ValueError("Invalid line %s" % components)

        dac = components[0]
        user = components[1]
        group = components[2]
        sid = components[3]
        path = components[4]

        if path in files:
            print("WARNDUP: " + path)
            continue

        if path.endswith("/") and path != "/":
            raise ValueError(path)

        # weird crap: some symbolic links on Android have not 777 perms!!!
        # this is messed up and the Linux kernel doesn't seem to care anyways
        if dac.startswith('l'):
            dac = "lrwxrwxrwx"

        # blacklist
        if path.lower().find("magisk") != -1 or path.startswith("/sys/") or path.startswith("/acct/") or path.startswith("/sbin/.core") or \
                path.startswith("/system_root") or path.startswith("/proc/") or path.startswith("/d/") or path.startswith("/dev/__properties__") or \
                path.startswith("/dev/socket/"):
            continue

        files[path] = { "perms" : dac, "user" : user, "group" : group, "selinux" : sid }

    return files

def fnum(n):
    nn = ""
    n = str(n)
    for i in range(len(n)):
        if i > 0:
            if i % 3 == 0:
                nn += ","

        nn += n[len(n) - i - 1]

    return nn[::-1]

def print_prefixes(fps, levels, total=None, detailed=False, flatten=False):
    prefixes = [{}, {}]
    cdfs = [0, 0]

    print("Total: %s" % fnum(len(fps)))

    for level in range(levels):
        fc = prefixes[level]

        for fn in fps:
            parts = fn.split(os.path.sep)
            prefix = parts[1]

            for i in range(level):
                idx = i+2

                if len(parts) > idx:
                    prefix += "/" + parts[idx]

            if prefix not in fc:
                fc[prefix] = 1
            else:
                fc[prefix] += 1


    if flatten:
        cdf = 0
        for f, freq in sorted(prefixes[1].items(), key=lambda x: (x[1]), reverse=True):
            missing = len(fps) if not total else total
            cdf += freq

            if freq > 1 or detailed:
                print("/%-10s - %s (%.1f%%, %.1f%%)" % (f, fnum(freq), float(freq)/missing*100, float(cdf)/missing*100.0))
    else:
        cdf = 0
        for f, freq in sorted(prefixes[0].items(), key=lambda x: (x[1]), reverse=True):
            missing = len(fps) if not total else total
            cdf += freq

            if freq > 1 or detailed:
                print("/%-10s - %s (%.1f%%, %.1f%%)" % (f, fnum(freq), float(freq)/missing*100, float(cdf)/missing*100.0))

            missing = freq
            cdf2 = 0
            for f2, freq2 in filter(lambda x: x[0].startswith(f+"/"), sorted(prefixes[1].items(), key=lambda x: (x[1]), reverse=True)):
                cdf2 += freq2
                if freq2 > 1 or detailed:
                    print("   /%-10s - %s (%.1f%%, %.1f%%)" % (f2, fnum(freq2), float(freq2)/missing*100, float(cdf2)/missing*100.0))

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--detailed", action="store_true")
    parser.add_argument("--flatten", action="store_true")
    parser.add_argument("--levels", default=1, type=int)
    parser.add_argument("recovered")
    parser.add_argument("real")

    args = parser.parse_args()

    recovered_data = open(args.recovered).read()
    real_data = open(args.real).read()

    bad_files = OrderedDict()
    good_files = OrderedDict()
    extra_files = OrderedDict()
    missing_files = OrderedDict()
    wrong_dac = OrderedDict()
    wrong_mac = OrderedDict()

    recovered = read_data(recovered_data)
    real = read_data(real_data)

    for fn, f in recovered.items():
        if fn not in real:
            extra_files.update({ fn : f })
        else:
            of = real[fn]

            bad = False
            if f["user"] != of["user"] or f["group"] != of["group"] or f["perms"] != of["perms"]:
                wrong_dac.update({ fn : { "recovered" : f, "real" : of }})
                bad = True
            if f["selinux"] != of["selinux"]:
                wrong_mac.update({ fn : { "recovered" : f, "real" : of }})
                bad = True

            if not bad:
                good_files.update({ fn : f })
            else:
                bad_files.update({ fn : f })

    for fn, f in real.items():
        if fn not in recovered:
            missing_files.update({ fn : f })

    print("----- DAC LISTING -----")
    for fn, f in wrong_dac.items():
        l = f["recovered"]
        r = f["real"]

        diff = []

        if l["user"] != r["user"]:
            diff += [[l["user"], r["user"]]]
        if l["group"] != r["group"]:
            diff += [[l["group"], r["group"]]]
        if l["perms"] != r["perms"]:
            diff += [[l["perms"], r["perms"]]]

        nd = []
        for d in diff:
            nd += ["%s != %s" % (d[0], d[1])]

        diff = ", ".join(nd)

        print("%s [%s]" % (fn, diff))


    recovered_secontexts = {}
    real_secontexts = {}

    for fn, f in real.items():
        se = f["selinux"]

        if se not in real_secontexts:
            real_secontexts[se] = 0

        real_secontexts[se] += 1

    for fn, f in recovered.items():
        se = str(f["selinux"])

        if se not in recovered_secontexts:
            recovered_secontexts[se] = 0

        recovered_secontexts[se] += 1

    print("")
    print("----- MAC LISTING -----")
    for fn, f in wrong_mac.items():
        print("%s [%s != %s]" % (fn, f["recovered"]["selinux"], f["real"]["selinux"]))

    print("")
    print("----- BAD MAC REPORT -----")
    print_prefixes(wrong_mac, args.levels, total=len(recovered), detailed=args.detailed, flatten=args.flatten)

    print("")
    print("----- BAD DAC REPORT -----")
    print_prefixes(wrong_dac, args.levels, total=len(recovered), detailed=args.detailed, flatten=args.flatten)

    print("")
    print("----- BAD FILES REPORT -----")
    print_prefixes(bad_files, args.levels, total=len(recovered), detailed=args.detailed, flatten=args.flatten)

    print("")
    print("----- GOOD FILES REPORT -----")

    print_prefixes(good_files, args.levels, total=len(recovered), detailed=args.detailed, flatten=args.flatten)

    print("")
    print("----- EXTRA FILES REPORT -----")

    print_prefixes(extra_files, args.levels, total=len(recovered), detailed=args.detailed, flatten=args.flatten)

    print("")
    print("----- MISSING FILES REPORT -----")

    print_prefixes(missing_files, args.levels, total=(len(real)-len(bad_files)-len(good_files)), detailed=args.detailed, flatten=args.flatten)

    print("")
    print("----- MISSING SECONTEXTS -----")

    secontext_diff = set(real_secontexts) - set(recovered_secontexts)
    print(secontext_diff)
    print_prefixes(missing_files, args.levels, total=(len(real)-len(bad_files)-len(good_files)), detailed=args.detailed, flatten=args.flatten)

    print("")
    print("----- STATS -----")
    print("Recovered files %s, Real files %s" % (fnum(len(recovered)), fnum(len(real))))
    print("Extra files %s (in recovered)" % fnum(len(extra_files)))
    print("Missing files %s (from real)" % fnum(len(missing_files)))
    print("Wrong DAC %s" % fnum(len(wrong_dac)))
    print("Wrong MAC %s" % fnum(len(wrong_mac)))
    print("Recovered %s SEContexts, Real SEContexts %s" % (fnum(len(recovered_secontexts)), fnum(len(real_secontexts))))
    print("")
    print("File Contexts Recovery %.2f%%" % (float(len(recovered_secontexts))/(len(real_secontexts))*100.0))
    print("MAC/DAC Accuracy %.2f%%" % (float(len(good_files))/(len(recovered)-len(extra_files))*100.0))
