import android
from android.capabilities import Capabilities
from android.sepolicy import SELinuxContext

class Cred(object):
    def __init__(self):
        self.uid = None
        self.gid = None
        self.groups = set()
        self.sid = None
        self.cap = Capabilities()

    def clear_groups(self):
        self.groups = set()

    def execve(self, file_obj=None, new_sid=None):
        import copy

        new = Cred()
        new.uid = self.uid
        new.gid = self.gid
        new.groups = copy.deepcopy(self.groups)

        if new_sid:
            assert isinstance(new_sid, SELinuxContext)
            new.sid = copy.deepcopy(new_sid)
        else:
            new.sid = copy.deepcopy(self.sid)

        # TODO: check file if set-user-id and for file capabilities
        # TODO: handle capability(7) assignment semantics
        # TODO: file system capabilities /vendor/bin/pm-service

        # Drop by default, when transitioning to a non-privileged process
        if new.uid != 0:
            new.cap = Capabilities()
        else:
            new.cap = copy.deepcopy(self.cap)

        return new

    def add_group(self, gid):
        if isinstance(gid, int):
            self.groups |= set([gid])
        elif isinstance(gid, str):
            self.groups |= set([AID_MAP_INV[gid]])
        else:
            raise ValueError("Expected type int or str")

    def __eq__(self, other):
        if not isinstance(other, Cred):
            return False

        return self.uid == other.uid and \
            self.gid == other.gid and \
            self.groups == other.groups and \
            self.sid == other.sid and \
            self.cap == other.cap

    def diff(self, other):
        if not isinstance(other, Cred):
            raise ValueError("Cannot diff non-cred")

        cmps = ['uid', 'gid', 'groups', 'sid', 'cap']
        diffs = []

        diffstr = ""
        for c in cmps:
            l = getattr(self, c)
            r = getattr(other, c)

            if l != r:
                if c == "groups":
                    remove = l - r
                    add = r - l

                    if len(add):
                        print(add)
                        diffs += ["Group+[%s]" % ",".join(map(str, map(lambda x: AID_MAP.get(x, str(x)), sorted(list(add)))))]
                    if len(remove):
                        diffs += ["Group-[%s]" % ",".join(map(str, map(lambda x: AID_MAP.get(x, str(x)), sorted(list(remove)))))]
                elif c == "cap":
                    diffs += [l.diff(r)]
                    pass
                elif c in ["uid", "gid"]:
                    diffs += ["%s %s != %s" % (c, AID_MAP.get(l, str(l)), AID_MAP.get(r, str(r)))]
                else:
                    diffs += ["%s %s != %s" % (c, l, r)]

        diffstr = " ~ ".join(diffs)

        return diffstr

    def __str__(self):
        additional_info = [
            "u=%s" % AID_MAP.get(self.uid, str(self.uid)),
            "g=%s" % AID_MAP.get(self.gid, str(self.gid)),
        ]

        if self.sid:
            additional_info += ["sid=" + str(self.sid)]
        if self.groups and len(self.groups):
            additional_info += ["groups=" + ",".join(map(lambda x: AID_MAP.get(x, str(x)), sorted(self.groups)))]

        if len(self.cap.effective):
            if len(self.cap.effective) == len(android.capabilities.ALL_CAPABILITIES):
                additional_info += ["cap=EVERYTHING"]
            else:
                additional_info += ["cap=" + ",".join(list(self.cap.effective))]

        additional_info = " ".join(additional_info)

        return "<Cred %s>" % additional_info

def _parse_aid_file():
    import re
    import os

    # Parse android AID definitions (/system/core/libcutils/include_vndk/cutils/android_filesystem_config.h)
    try:
        fp = open(os.path.join(os.path.dirname(__file__), 'android_fs.h'), 'r')
        data = fp.read()
        fp.close()
    except IOError:
        raise IOError("Unable to find android_fs.h file (uid/gid mapping)")

    mapping = {}
    got_range = False
    range_start = 0

    for line in data.split("\n"):
        # Ignore comments and blank lines
        if re.match(r'^\s*((/\*)|(//)|($))', line):
            continue

        tokens = list(filter(lambda x: x != "", line.split(" ")))
        aid_name = tokens[1]
        aid = int(tokens[2])

        assert aid_name[:4] == "AID_"

        if got_range:
            assert aid_name.endswith("_END")
            got_range = False
            aid_name = aid_name[4:-4].lower()

            for i in range(range_start, aid+1):
                mapping[i] = "%s_%d" % (aid_name, i)
            continue

        if aid_name.endswith("_START"):
            got_range = True
            range_start = aid
            continue

        # XXX: there are some exceptions to this (mediacodec, etc.)
        aid_name = aid_name[4:].lower()

        # Some exceptions to the rule
        if aid_name in ['media_codec', 'media_ex', 'media_drm']:
            aid_name = aid_name.replace('_', '')

        # XXX: not handling ranges
        mapping[aid] = aid_name

    return mapping

# number to name
AID_MAP = _parse_aid_file()
AID_MAP_INV = dict([[v,k] for k,v in AID_MAP.items()])
