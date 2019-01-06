import os
import re
import glob
import logging
import stat

from android.sepolicy import SELinuxContext
from android.property import PROPERTY_KEY, PROPERTY_VALUE
from android.capabilities import Capabilities
from android.dac import Cred, AID_MAP, AID_MAP_INV

log = logging.getLogger(__name__)

# Main reference: https://android.googlesource.com/platform/system/core/+/master/init/README.md

class TriggerCondition(object):
    def __init__(self, props, condition):
        self.props = props
        self.raw_condition = condition
        self.stage_trigger = None
        self.property_conditions = {}

        self._parse_trigger()

    def new_stage(self, stage):
        if self.stage_trigger == stage or (self.stage_trigger is None and stage == "boot"):
            val = True

            for p, v in self.property_conditions.items():
                val = True if p in self.props and (self.props[p] == v or v == "*") else False

                if not val:
                    break

            return val
        else:
            return False

    def setprop(self, new_prop):
        if new_prop not in self.property_conditions:
            return False

        val = True

        for p, v in self.property_conditions.items():
            val = True if p in prop and (prop[p] == v or v == "*") else False

            if not val:
                break

        return val

    def _parse_trigger(self):
        expect_and = False

        for cond in self.raw_condition:
            if cond == "&&" and not expect_and:
                log.error("Trigger condition: unexpected &&")
                return
            elif cond != "&&" and expect_and:
                log.error("Trigger condition: expected &&")
                return

            expect_and = False

            if cond.startswith("property:"):
                cond = cond[len("property:"):]
                match = re.match(r'(%s)=(%s)' % (PROPERTY_KEY.pattern, PROPERTY_VALUE.pattern), cond)

                if not match:
                    log.warning("Trigger condition %s is invalid", cond)
                else:
                    prop, value = match.groups()
                    self.property_conditions[prop] = value

                expect_and = True
            elif cond == "&&":
                pass
            else:
                self.stage_trigger = cond
                expect_and = True

    def __repr__(self):
        triggers = []

        if self.stage_trigger:
            triggers += [str(self.stage_trigger)]

        for k, v in self.property_conditions.items():
            triggers += ["%s=%s" % (k, v)]

        return "<TriggerCondition %s>" % (" && ".join(triggers))

class AndroidInitAction(object):
    def __init__(self, condition):
        self.condition = condition
        self.commands = []

    def add_command(self, cmd, args):
        self.commands += [[cmd] + args]

    def __repr__(self):
        return "<AndroidInitAction %d commands on %s>" % (len(self.commands), repr(self.condition))

class AndroidInitService(object):
    def __init__(self, service_name, service_args):
        self.service_class = "default"
        self.service_groups = []
        self.service_name = service_name
        self.service_args = service_args
        self.options = []

        self.cred = Cred()
        # default uid/gid is root!
        self.cred.uid = 0
        self.cred.gid = 0

        self.disabled = False
        self.oneshot = False

    def add_option(self, option, args):
        if option == "user":
            self.cred.uid = AID_MAP_INV.get(args[0], 9999)
        elif option == "capabilities":
            for cap in args:
                self.cred.cap.add('ambient', cap)
        elif option == "group":
            self.cred.gid = AID_MAP_INV.get(args[0], 9999)

            for group in args[1:]:
                try:
                    self.cred.add_group(group)
                except KeyError:
                    log.warning("Unabled to find AID mapping for group %s", group)
        elif option == "disabled":
            self.disabled = True
        elif option == "class":
            self.service_class = args[0]

            if len(args) > 1:
                self.service_groups = args[1:]
        elif option == "oneshot":
            self.oneshot = True
        elif option == "seclabel":
            self.cred.sid = SELinuxContext.FromString(args[0])
        else:
            self.options += [[option] + args]

    def __str__(self):
        return "<AndroidInitService %s %s>" % (self.service_name, self.cred)

class AndroidInit(object):
    def __init__(self, root_dir, properties, root_fs):
        self.init_dir = os.path.join(root_dir, "init/")
        self.root_fs = root_fs
        self.props = properties
        self.services = {}
        self.actions = []

        # Runtime events
        self.queue = []

        # Stats
        self.stats = {"commands":0}

    def queue_action(self, action):
        # do not double queue actions
        if action in self.queue:
            return

        self.queue += [action]

    def set_prop_trigger(self, prop, value):
        pass

    def new_stage_trigger(self, stage):
        # get set of actions to be triggered
        # queue them

        log.info("Boot %s", stage)

        for action in self.actions:
            if action.condition.new_stage(stage):
                self.queue_action(action)

    def main_loop(self):
        while len(self.queue):
            action = self.queue.pop(0)
            for cmd in action.commands:
                self.execute(cmd[0], cmd[1:])

    def execute(self, cmd, args):
        self.stats["commands"] += 1

        if cmd == "trigger":
            assert len(args) == 1
            self.new_stage_trigger(args[0])
        elif cmd == "mkdir":
            path = args[0]
            user = 0
            group = 0
            perm = 0o755

            if len(args) > 1:
                perm = int(args[1], 8)
            if len(args) > 2:
                user = AID_MAP_INV.get(args[2], 9999)
            if len(args) > 3:
                group = AID_MAP_INV.get(args[3], 9999)

            self.root_fs.mkdir(path, user, group, perm)
        elif cmd == "chown":
            user = AID_MAP_INV.get(args[0], 9999)
            group = AID_MAP_INV.get(args[1], 9999)
            path = args[2]

            if path.startswith("/dev"):
                mode = 0o0400 | stat.S_IFCHR
            elif path.startswith("/sys"):
                mode = 0o0444 | stat.S_IFREG
            else:
                return

            policy = {
                "original_path": None,
                "user": user,
                "group": user,
                "perms": mode,
                "size": 0,
                "link_path": "",
                "capabilities": None,
                "selinux": None,
            }

            if path not in self.root_fs.files:
                self._add_uevent_file(path, policy)

            self.root_fs.chown(path, user, group)
        elif cmd == "chmod":
            mode = int(args[0], 8)
            path = args[1]

            if path.startswith("/dev"):
                mode = mode | stat.S_IFCHR
            elif path.startswith("/sys"):
                mode = mode | stat.S_IFREG
            else:
                return

            policy = {
                "original_path": None,
                "user": AID_MAP_INV.get("root", 9999),
                "group": AID_MAP_INV.get("root", 9999),
                "perms": mode,
                "size": 0,
                "link_path": "",
                "capabilities": None,
                "selinux": None,
            }

            if path not in self.root_fs.files:
                self._add_uevent_file(path, policy)

            self.root_fs.chmod(path, mode)
        elif cmd == "copy":
            pass
        elif cmd == "rm":
            pass
        elif cmd == "rmdir":
            pass
        elif cmd == "setprop":
            pass
        elif cmd == "write":
            pass
        elif cmd == "mount":
            path = args[2]
            fstype = args[0]
            device = args[1]
            options = []
            if len(args) > 3:
                for o in args[3:]:
                    options += o.split(",")

            if path in self.root_fs.mount_points:
                return

            self.root_fs.add_mount_point(path, fstype, device, options)
        elif cmd == "mount_all":
            path = args[0]
            late_mount = "--late" in args

            try:
                with open(self._init_rel_path(self.expand_properties(path)), 'r') as fp:
                    fstab_data = fp.read()
                    entries = self.parse_fstab(fstab_data)
            except IOError:
                log.error("Unable to open fstab file %s", self._init_rel_path(self.expand_properties(path)))#path)
                return

            for entry in entries:
                if late_mount and "latemount" not in entry["fsmgroptions"]:
                    continue
                if not late_mount and "latemount" in entry["fsmgroptions"]:
                    continue

                if entry["path"] in self.root_fs.mount_points:
                    continue

                self.root_fs.add_mount_point(entry["path"], entry["fstype"], entry["device"], entry["options"])

    def parse_fstab(self, data):
        entries = []

        for line_no, line in enumerate(data.split("\n")):
            # ignore blank lines and comments
            if re.match('^(\s*#)|(\s*$)', line):
                continue

            # greedly replace all whitespace with a single space for splitting
            line = re.sub('\s+', " ", line)

            # split by spaces, while eliminating empty components
            components = list(filter(lambda x: len(x) > 0, line.split(" ")))
            device = components[0]
            mount_path = components[1]
            fstype = components[2]
            options = components[3].split(",")

            if len(components) > 4:
                fsmgroptions = components[4].split(",")
            else:
                fsmgroptions = []

            entries += [{"device":device, "path" : mount_path, "fstype" : fstype, "options" : options,
                "fsmgroptions" : fsmgroptions}]

        return entries

    def expand_properties(self, string):
        new_string = string

        for m in re.finditer(r'\$\{' + PROPERTY_KEY.pattern + r'\}', string):
            key = m.group(0)[2:-1]

            # silently fail a property lookup
            if key in self.props:
                value = self.props[key]
            else:
                value = ""

            new_string = new_string.replace(m.group(0), value)

        return new_string

    def read_configs(self, init_rc_base):
        first_init = self.read_init_rc(init_rc_base)

        init_files = self._list_mount_init_files("/system")
        init_files += self._list_mount_init_files("/vendor")
        init_files += self._list_mount_init_files("/odm")

        for init_file in init_files:
            self.read_init_rc(init_file)

    def boot_system(self):
        # this is used to bypass dm-verity/FDE on AOSP
        self.props["vold.decrypt"] = "trigger_post_fs_data"

        self.new_stage_trigger('early-init')
        self.main_loop()

        # TODO: android version check for this
        self.root_fs.add_mount_point("/proc", "proc", "proc", ["rw,relatime,gid=3009,hidepid=2".split(",")])
        self.root_fs.add_mount_point("/sys", "sysfs", "sysfs", ["rw","seclabel","relatime"])

        uevent_files = [
                "/ueventd.rc", "/vendor/ueventd.rc", "/odm/ueventd.rc",
                "/ueventd." + self.props.get_default("ro.hardware") + ".rc"]

        for f in uevent_files:
            try:
                self.read_uevent_rc(f)
                pass
            except IOError:
                pass

        self.new_stage_trigger('init')
        self.new_stage_trigger('late-init')

        # other stages will be handled by internal actions
        self.main_loop()

    def _import(self, path):
        self.read_init_rc(self.expand_properties(path))

    def read_uevent_rc(self, path):
        rc_path = self._init_rel_path(path)

        rc_lines = ""

        with open(rc_path, 'r') as fp:
            rc_lines = fp.read()

        for line_no, line in enumerate(rc_lines.split("\n")):
            # ignore blank lines and comments
            if re.match('^(\s*#)|(\s*$)', line):
                continue

            # greedly replace all whitespace with a single space for splitting
            line = re.sub('\s+', " ", line)

            # split by spaces, while eliminating empty components
            components = list(filter(lambda x: len(x) > 0, line.split(" ")))
            fn = components[0]

            fn_expand = ""

            if fn.startswith("/dev") and len(components) == 4:
                mode = int(components[1], 8) | stat.S_IFCHR
                user = components[2]
                group = components[3]

                fn_expand = fn
            elif fn.startswith("/sys") and len(components) == 5:
                node_name = components[1]
                mode = int(components[2], 8) | stat.S_IFREG
                user = components[3]
                group = components[4]

                fn_expand = fn + "/" + node_name
            else:
                continue

            file_policy = {
                "original_path": None,
                "user": AID_MAP_INV.get(user, 9999),
                "group": AID_MAP_INV.get(group, 9999),
                "perms": mode,
                "size": 0,
                "link_path": "",
                "capabilities": None,
                "selinux": None,
            }

            self._add_uevent_file(fn_expand, file_policy)

        log.info("Loaded %s", path)

    def _expand_kernelfs_dirs(self, path):
        """
        Use the default permissions for creating /sys/* or /dev/* directories
        """
        total_path = "/"

        # Ignore the last, path as we're creating that next
        for component in os.path.normpath(path).split(os.sep)[1:-1]:
            total_path = os.path.join(total_path, component)

            ## Sysfs default permissions
            # directories - 755
            # files - 444 (644 for writeable ones)
            #
            ## Devfs default permissions
            # directories - 755
            # files - 400 (600 for writeable ones)

            if total_path not in self.root_fs.files:
                dir_policy = {
                    "original_path": None,
                    "user": AID_MAP_INV['root'],
                    "group": AID_MAP_INV['root'],
                    "perms": 0o755 | stat.S_IFDIR,
                    "size": 4096,
                    "link_path": "",
                    "capabilities": None,
                    "selinux": None,
                }

                self.root_fs.add_file(total_path, dir_policy)

    def _add_uevent_file(self, path, file_policy):
        import copy

        if not path.startswith("/dev") and not path.startswith("/sys"):
            return

        if '*' in path:
            path = path.replace('*', '0')

        self._expand_kernelfs_dirs(path)

        self.root_fs.add_or_update_file(path, copy.deepcopy(file_policy))

    def read_init_rc(self, path):
        rc_path = self._init_rel_path(path)

        rc_lines = ""

        with open(rc_path, 'r') as fp:
            rc_lines = fp.read()

        pending_imports = []
        sections = []
        current_section = None
        line_continue = False

        for line_no, line in enumerate(rc_lines.split("\n")):
            # ignore blank lines and comments
            if re.match('^(\s*#)|(\s*$)', line):
                continue

            # greedly replace all whitespace with a single space for splitting
            line = re.sub('\s+', " ", line)

            # split by spaces, while eliminating empty components
            components = list(filter(lambda x: len(x) > 0, line.split(" ")))
            action = components[0]

            if action in ['import', 'on', 'service']:
                if current_section is not None and len(current_section):
                    sections += [current_section]

                current_section = []
            elif current_section is None:
                # ignore actions/commands before the first section
                continue

            line_continue_next = components[-1] == "\\"

            # erase trailing slash
            if line_continue_next:
                components = components[:-1]

            if line_continue:
                current_section[-1] += components
            else:
                current_section += [components]

            line_continue = line_continue_next

        # Get trailing section
        if len(current_section):
            sections += [current_section]

        for section in sections:
            action = section[0][0]
            args = section[0][1:]
            body = section[1:]

            if action == "import":
                pending_imports += [args[0]]
            elif action == "service":
                service_name = args[0]
                service_args = args[1:]

                self._add_service(service_name, service_args, body)
            elif action == "on":
                # not handled for now
                condition = args
                commands = body

                self._add_action(condition, commands)
            else:
                raise ValueError("Unknown section type %s" % (action))

        log.info("Loaded %s", path)

        for imp in pending_imports:
            try:
                self._import(imp)
            except IOError:
                log.warn("Unable to import %s", imp)

    def _add_action(self, condition, commands):
        trigger_cond = TriggerCondition(self.props, condition)
        action = AndroidInitAction(trigger_cond)

        for cmd in commands:
            action.add_command(cmd[0], cmd[1:])

        self.actions += [action]

    def _add_service(self, service_name, service_args, service_options):
        # TODO: handle override
        if service_name in self.services:
            log.debug("Not loading service %s. Already exists!", service_name)
            return

        service = AndroidInitService(service_name, service_args)

        for opt in service_options:
            opt_name = opt[0]
            opt_args = opt[1:]
            service.add_option(opt_name, opt_args)

        self.services[service_name] = service

    def _list_mount_init_files(self, mount_point):
        glob_dir = os.path.join(mount_point, "etc/init/*.rc")
        init_files = glob.glob(self._init_rel_path(glob_dir))
        init_files = list(sorted(map(lambda x: x.replace(self.init_dir[:-1], ''), init_files)))
        return init_files

    def _init_rel_path(self, path):
        if os.path.isabs(path):
            path = path[1:]

        return os.path.join(self.init_dir, path)
