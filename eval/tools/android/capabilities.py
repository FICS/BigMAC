class Capabilities(object):
    def __init__(self):
        # these are sets of strings, which make them easier to work with
        self.inherited = set()
        self.permitted = set()
        self.effective = set()
        self.bounding = set()
        self.ambient = set()

        # Not a real capset, just here as a guess on capabilities
        # from the SELinux policy
        self.selinux = set()

    def grant_all(self):
        self.inherited = set()
        self.ambient = set()
        self.permitted = set(ALL_CAPABILITIES)
        self.effective = set(ALL_CAPABILITIES)
        self.bounding = set(ALL_CAPABILITIES)

    def bound_default(self):
        self.bounding = set(ALL_CAPABILITIES)

    def bound_none(self):
        self.bounding = set(ALL_CAPABILITIES)

    def drop_all(self):
        self.inherited = set()
        self.ambient = set()
        self.permitted = set()
        self.effective = set()
        self.bounding = set(ALL_CAPABILITIES)

    def diff(self, other):
        if not isinstance(other, Capabilities):
            raise ValueError("Unable to diff non-cap")

        names = ['CapInh', 'CapPrm', 'CapEff', 'CapBnd', 'CapAmb']
        lsets = [self.inherited, self.permitted, self.effective, self.bounding, self.ambient]
        rsets = [other.inherited, other.permitted, other.effective, other.bounding, other.ambient]

        diffs = []
        diffstr = ""
        allc = set(ALL_CAPABILITIES)
        for i in range(len(names)):
            l = lsets[i]
            r = rsets[i]
            name = names[i]

            remove = l - r
            add = r - l

            if len(add):
                if add == allc:
                    diffs += ["%s+[EVERYTHING]" % (name)]
                else:
                    if len(add) > len(allc)/2:
                        add = allc - add
                        diffs += ["%s+[EVERYTHING_NEG %s]" % (name, ",".join(map(str, sorted(list(add)))))]
                    else:
                        diffs += ["%s+[%s]" % (name, ",".join(map(str, sorted(list(add)))))]
            if len(remove):
                if remove == allc:
                    diffs += ["%s-[EVERYTHING]" % (name)]
                else:
                    if len(remove) > len(allc)/2:
                        remove = allc - remove
                        diffs += ["%s-[EVERYTHING_NEG %s]" % (name, ",".join(map(str, sorted(list(remove)))))]
                    else:
                        diffs += ["%s-[%s]" % (name, ",".join(map(str, sorted(list(remove)))))]

        diffstr = " ~ ".join(diffs)

        return diffstr

    def add(self, set_name, cap):
        name_mapping = {
                "selinux": self.selinux,
                "inherited": self.inherited,
                "effective": self.effective,
                "ambient": self.ambient,
                "permitted": self.permitted,
                "bounding": self.bounding
        }

        if set_name not in name_mapping:
            raise ValueError("Capability set '%s' does not exist" % set_name)
        else:
            self._add_cap(cap, name_mapping[set_name])

    def selinux(self, cap):
        self._add_cap(cap, self.selinux)

    def _add_cap(self, cap, capset):
        assert isinstance(cap, str)
        Capabilities.name_to_bit(cap)
        capset |= set([Capabilities._cannonicalize_name(cap)])

    @staticmethod
    def _cannonicalize_name(name):
        if name.lower().startswith("cap_"):
            return name.upper()
        else:
            return ("CAP_"+name).upper()

    @staticmethod
    def name_to_bit(name):
        return CAPABILITIES_INV[Capabilities._cannonicalize_name(name)]

    @staticmethod
    def bit_to_name(bit):
        return CAPABILITIES[bit]

    def __str__(self):
        output = ""

        names = ['CapInh', 'CapPrm', 'CapEff', 'CapBnd', 'CapAmb']
        sets = [self.inherited, self.permitted, self.effective, self.bounding, self.ambient]

        for name, s in zip(names, sets):
            number = 0
            for cap in s:
                number |= 1 << Capabilities.name_to_bit(cap)

            # Just like how Linux outputs
            output += "%s:\t%016x\n" % (name, number)

        return output

CAPABILITIES = {
    0: "CAP_CHOWN",
    1: "CAP_DAC_OVERRIDE",
    2: "CAP_DAC_READ_SEARCH",
    3: "CAP_FOWNER",
    4: "CAP_FSETID",
    5: "CAP_KILL",
    6: "CAP_SETGID",
    7: "CAP_SETUID",
    8: "CAP_SETPCAP",
    9: "CAP_LINUX_IMMUTABLE",
    10: "CAP_NET_BIND_SERVICE",
    11: "CAP_NET_BROADCAST",
    12: "CAP_NET_ADMIN",
    13: "CAP_NET_RAW",
    14: "CAP_IPC_LOCK",
    15: "CAP_IPC_OWNER",
    16: "CAP_SYS_MODULE",
    17: "CAP_SYS_RAWIO",
    18: "CAP_SYS_CHROOT",
    19: "CAP_SYS_PTRACE",
    20: "CAP_SYS_PACCT",
    21: "CAP_SYS_ADMIN",
    22: "CAP_SYS_BOOT",
    23: "CAP_SYS_NICE",
    24: "CAP_SYS_RESOURCE",
    25: "CAP_SYS_TIME",
    26: "CAP_SYS_TTY_CONFIG",
    27: "CAP_MKNOD",
    28: "CAP_LEASE",
    29: "CAP_AUDIT_WRITE",
    30: "CAP_AUDIT_CONTROL",
    31: "CAP_SETFCAP",
    32: "CAP_MAC_OVERRIDE",
    33: "CAP_MAC_ADMIN",
    34: "CAP_SYSLOG",
    35: "CAP_WAKE_ALARM",
    36: "CAP_BLOCK_SUSPEND",
    37: "CAP_AUDIT_READ",
}

CAPABILITIES_INV = dict([[v,k] for k,v in CAPABILITIES.items()])
ALL_CAPABILITIES = list(CAPABILITIES.values())
ALL_CAPABILITY_BITS = list(range(len(CAPABILITIES)))
