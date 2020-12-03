import sys
import os
import logging
import shutil
import time
import errno
import stat
import glob
import pickle
import copy
from fnmatch import fnmatch
from subprocess import Popen

from config import *
from android.property import AndroidPropertyList
from util.file import directories, mkdir_recursive, mkdir
from android.sepolicy import SEPOLICY_FILES, SELinuxContext
from android.file_contexts import convert_file_contexts
from android.dac import AID_MAP

logging.basicConfig(stream=sys.stdout, format="%(levelname)s: %(message)s", level=logging.INFO)
log = logging.getLogger(__name__)

# For now, we only are supporting the system and boot filesystems
# TODO: vendor, userdata, etc.
# TODO: properly handle system_other on AOSP
TARGET_FILESYSTEMS = [
    {
        "name": "boot",
        "pattern": "*boot*",
        "type": "ramdisk",
        "required": True,
    },
    {
        "name": "system",
        "pattern": "*system*",
        "not_pattern": "*system_other*",
        "type": "ext4",
        "required": True,
    },
    {
        "name": "vendor",
        "pattern": "*vendor*",
        "type": "ext4",
        "required": False,
    },
]

def path_to_firmware_name(filepath):
    firmware_name = os.path.basename(filepath)
    firmware_name = firmware_name.split('?')[0] # remove any URL params, if any

    # clip off extension (hack from atextract)
    firmware_name, _ = os.path.splitext(firmware_name)

    return firmware_name

class FilesystemPolicy:
    def __init__(self, fsname, fstype):
        self.fsname = fsname
        self.fstype = fstype
        self.files = {}
        self.mount_points = {}

    def add_file(self, path, policy_info):
        if path != "/" and path.endswith("/"):
            raise ValueError("Paths must be cannonicalized! %s" % path)
        if path in self.files:
            raise ValueError("Cannot re-add existing path '%s' to policy" % path)

        self.files[path] = policy_info

    def add_or_update_file(self, path, policy_info):
        if path != "/" and path.endswith("/"):
            raise ValueError("Paths must be cannonicalized! %s" % path)

        self.files[path] = policy_info

    def find(self, pattern):
        result_set = []
        for fn, v in self.files.items():
            if fnmatch(fn, pattern):
                result_set += [{fn: v}]

        return result_set

    def mkdir(self, path, user=0, group=0, perm=0o755):
        dir_policy = {
            "original_path": None,
            "user": user,
            "group": group,
            "perms": (perm & 0o7777) | stat.S_IFDIR,
            "size": 4096,
            "link_path": "",
            "capabilities": None,
            "selinux": None,
        }

        self.add_or_update_file(path, dir_policy)

    def chown(self, path, user=None, group=None):
        if path not in self.files:
            log.warning("Cannot chown non-existant path %s", path)
            return

        pol = self.files[path]

        if user:
            pol["user"] = user
        if group:
            pol["group"] = group

    def chmod(self, path, perm):
        if path not in self.files:
            log.warning("Cannot chmod non-existant path %s", path)
            return

        pol = self.files[path]
        pol["perms"] = (pol["perms"] & ~0o7777) | (perm & 0o7777)

    def add_mount_point(self, path, fstype, device, options):
        if path in self.mount_points and "remount" not in options:
            raise ValueError("Cannot readd mount-point %s without remount" % (path))

        log.info("Associating mount point %s [fstype=%s, dev=%s, opt=%s]", path, fstype, device, options)

        self.mount_points[path] = {
            "type" : fstype,
            "device" : device,
            "options" : options,
        }

    def mount(self, other_fs, path):
        if not isinstance(other_fs, FilesystemPolicy):
            raise ValueError("Expected to mount other FS policy")

        # transform all paths
        for fn, v in other_fs.files.items():
            # ensure all paths are absolute
            assert fn[0] == "/"

            # remove leading slash, making fn relative
            fn = fn[1:]

            # special case: root of other_fs is now mount point
            if fn == "":
                self.files[path] = v
                continue

            self.add_file(os.path.join(path, fn), v)

        return self

    def realpath(self, path):
        """
        Resolve a path by following symbolic links (if any)
        """
        path = os.path.normpath(path)
        path_components = path.split(os.sep)[1:]
        total_path = "/"

        for component in path_components:
            tpath = os.path.join(total_path, component)

            if tpath in self.files:
                fo = self.files[tpath]

                # got a symbolic link
                if fo["link_path"] != "":
                    link = fo["link_path"]
                    link = os.path.normpath(link)

                    # TODO: this only works for one layer
                    if os.path.isabs(link):
                        total_path = link
                    else:
                        total_path = os.path.join(total_path, link)
                else:
                    total_path = tpath
            else:
                total_path = tpath
                break

        return total_path

    def list_path(self, path, numeric=False, show_links=True):
        output = ""

        # mode     size   user     group    secontext                   name
        # crw-rw----  1 system    camera    u:object_r:video_device:s0  v4l-subdev11
        field_output = []
        field_sizes = [0, 0, 0, 0, 0, 0]

        for f in self.find(path):
            (fn, fo), = f.items()

            size = str(fo["size"])
            user = AID_MAP[fo["user"]]
            group = AID_MAP[fo["group"]]
            secontext = str(fo["selinux"])


            if show_links and stat.S_ISLNK(fo["perms"]):
                name = fn + " -> " + fo["link_path"]
                filemode = stat.filemode(fo["perms"])
            else:
                name = fn
                filemode = stat.filemode(fo["perms"])

            entry = [filemode, size, user, group, secontext, name]

            for i in range(6):
                if len(entry[i]) > field_sizes[i]:
                    field_sizes[i] = len(entry[i])

            field_output += [entry]

        field_output = sorted(field_output, key=lambda x: x[5])

        for entry in field_output:
            for i in range(6):
                if i < 5:
                    output += ("%-" + str(field_sizes[i]+1) + "s") % entry[i]
                else:
                    output += entry[i] + "\n"

        return output

    def _mode_to_string(self, mode):
        return stat.filemode(mode)

class AndroidSecurityPolicy:
    def __init__(self, vendor, firmware_name):
        self.vendor = vendor
        self.firmware_name = firmware_name
        self.fs_policies = []
        self.properties = AndroidPropertyList()
        self.policy_files = {}

    def get_results_dir(self):
        return os.path.join(POLICY_RESULTS_DIR, self.vendor.lower(), self.firmware_name)

    def get_saved_file_path(self, name):
        path = self.policy_files[name]["save_path"]

        # find firmware image name in the saved path for the policy (this can change due to policy path)
        common_path_component_idx = path.split(os.sep).index(self.firmware_name)

        if common_path_component_idx == -1:
            raise ValueError("Unable to determine saved policy file path (did you move or rename policy directory)?")

        # drop the leading N+1 path components
        # example: N = 2, Drop 0, 1, 2
        # from: POLICY_DIR/VENDOR/FIRMWARE/init/system/etc/init/mediaserver.rc
        # to: init/system/etc/init/mediaserver.rc
        return os.path.join(self.get_results_dir(), "/".join(path.split(os.sep)[common_path_component_idx+1:]))

    def get_android_version(self):
        android_version = list(map(int, self.get_properties()['properties']['android_version'].split('.')))

        if len(android_version) < 1 or len(android_version) > 3:
            raise ValueError("Android version %s is malformed" % str(android_version))

        # pad out the version tokens if they dont exist
        android_version = android_version + [0]*(3-len(android_version))
        return android_version

    def get_properties(self):
        props = self.properties
        android_version = props['ro.build.version.release']
        build_id = props['ro.build.id']
        brand = props.get_multi_default(
                ['ro.product.brand', 'ro.product.system.brand'], default="UNKNOWN")

        # Some samsung/lineage prop files don't have a model listed...
        model = props.get_multi_default(
                ['ro.product.model', 'ro.product.base_model', 'ro.product.system.brand'], default="UNKNOWN")

        product_name = props.get_multi_default(['ro.product.name', 'ro.product.system.name'], default="UNKNOWN")
        product_device = props.get_multi_default(['ro.product.device', 'ro.product.system.device'],
                                                 default="UNKNOWN")

        interesting_properties = {
            "brand": brand,
            "model": model,
            "build_id": build_id,
            "android_version": android_version,
            "product_name": product_name,
            "product_device": product_device
        }

        summary_string = "%s - %s (BUILD_ID %s, Android %s)" % \
            (brand, model, build_id, android_version)

        image_data = {
            "summary": summary_string,
            "properties": interesting_properties,
        }

        return image_data

class ExtractionError(ValueError):
    pass

class ASPCodec:
    def __init__(self, asp):
        self.asp = asp
        self.results_dir = self.asp.get_results_dir()
        self.db_dir = os.path.join(self.results_dir, "db/")

    def load(self, quick=False):
        try:
            self.asp.properties.from_file(os.path.join(self.results_dir, "all_properties.prop"))
        except FileNotFoundError:
            raise ValueError("Unable to load properties: file not found")

        if quick:
            return

        self.asp.fs_policies = self._load_db("filesystems.db")
        self.asp.policy_files = self._load_db("policy_files.db")

        return self.asp

    def save(self):
        self.asp.properties.to_file(os.path.join(self.results_dir, "all_properties.prop"))

        mkdir(self.db_dir)

        self._save_db(self.asp.fs_policies, "filesystems.db")
        self._save_db(self.asp.policy_files, "policy_files.db")

    def _load_db(self, name):
        if not os.access(os.path.join(self.db_dir, name), os.R_OK):
            raise ValueError("Unable to open '%s' database for reading" % name)

        with open(os.path.join(self.db_dir, name), 'rb') as fp:
            try:
                obj = pickle.load(fp)
            except TypeError as e:
                raise ValueError("Unable to unpickle '%s'. This is an internal error (code change required): %s" % (name, e))

        log.debug("Loaded '%s' (%s)", name, type(obj))

        return obj

    def _save_db(self, obj, name):
        if not os.access(self.db_dir, os.W_OK):
            raise ValueError("Unable to open '%s' database for writing" % name)

        with open(os.path.join(self.db_dir, name), 'wb') as fp:
            pickle.dump(obj, fp, protocol=pickle.DEFAULT_PROTOCOL)

        log.debug("Saved '%s' (%s)", name, type(obj))

        return 

class ASPExtractor:
    def __init__(self, vendor, firmware_name, job_id="0"):
        self.asp = AndroidSecurityPolicy(vendor, firmware_name)
        self.results_directory = None
        self.saved_files = {}
        self.job_id = job_id

    def save_file(self, source, path, overwrite=False):
        save_path = os.path.join(self.results_directory, path)
        mkdir_recursive(os.path.dirname(save_path))

        if os.path.isfile(save_path) and not overwrite:
            log.warning("Not overwriting saved file '%s': existing file found", path)
            return

        shutil.copyfile(source, save_path)
        self.saved_files[path] = {"save_path": save_path}

    def extract_from_firmware(self, firmware_image_path, skip_extract=False):
        start_time = time.time()
        filesystems = self._firmware_extract_task(firmware_image_path, skip=skip_extract)
        end_time = time.time()
        log.info("Operation took %.2f seconds", end_time - start_time)

        if len(filesystems) == 0:
            log.error("Failed to recover any filesystems")
            sys.exit(1)

        self.results_directory = os.path.join(POLICY_RESULTS_DIR, self.asp.vendor.lower(), self.asp.firmware_name)

        # Create a results directory
        # recursively create directory structure
        mkdir_recursive(self.results_directory)

        # Keep this local until we're done with it
        fs_policies = []

        for fs in TARGET_FILESYSTEMS:
            match = list(filter(lambda x: fnmatch(x["name"], fs["pattern"]), filesystems))

            if "not_pattern" in fs:
                match = list(filter(lambda x: not fnmatch(x["name"], fs["not_pattern"]), match))

            if not len(match):
                if fs["required"]:
                    log.error("Unable to find the %s filesystem. Cannot continue", fs["name"])
                    sys.exit(1)
                else:
                    log.warn("Unable to find the %s filesystem", fs["name"])
                    continue
            elif len(match) > 1:
                log.error("More than one %s filesystem found. Cannot disambiguate", fs["name"])
                sys.exit(1)

            # only one match supported
            match = match[0]

            # Rebuild Android filesystem hierarchy, starting from the top
            log.info("Extracting %s security policy (%s)", fs["name"], match["name"])
            fspolicy = self._walk_filesystem(fs["name"], fs["type"], match["path"])
            fs_policies += [fspolicy]

        # Determine how the firmware is organized
        #    a. Boot is loaded and a system partition is mounted
        #    b. Boot loads initially and then transitions to /system as the rootfs

        # corresponds to system
        # TODO: make robust

        sepolicy_in_system = fs_policies[1].find("/sepolicy")
        treble_enabled = fs_policies[1].find("/system/etc/selinux/plat_sepolicy.cil")

        # Image configurations
        #  1. Legacy two stage boot
        #  2. Single stage boot
        #  3. Single stage boot (treble)

        #from IPython import embed
        #embed()

        # 2 or 3
        if sepolicy_in_system or treble_enabled:
            log.info("Treating firmware image as two-stage boot (system is rootfs)")

            if treble_enabled:
                log.info("Image is Treble enabled")
                # sepolicy binary is in the boot partition. capture it
                pass

            # drop boot partition altogether
            combined_fs = copy.deepcopy(fs_policies[1])

            combined_fs.add_mount_point("/", "rootfs", "rootfs", ["rw"])
            combined_fs.add_mount_point("/system", "ext4", "/dev/block/bootdevice/by-name/system", ["rw"])
        # 1
        else:
            log.info("Treating firmware image as one-stage boot (boot is rootfs)")
            combined_fs = copy.deepcopy(fs_policies[0])
            combined_fs.mount(fs_policies[1], "/system")

            combined_fs.add_mount_point("/", "rootfs", "rootfs", ["rw"])
            combined_fs.add_mount_point("/system", "ext4", "/dev/block/bootdevice/by-name/system", ["rw"])

        if len(fs_policies) > 2:
            log.info("Mounting /vendor partition")
            combined_fs = combined_fs.mount(fs_policies[2], "/vendor")
            combined_fs.fsname = "combined"

            combined_fs.add_mount_point("/vendor", "ext4", "/dev/block/bootdevice/by-name/vendor", ["rw"])

        # Extract out the policy files (from most preferential to least)
        for fn, p in combined_fs.files.items():
            filebase = os.path.basename(fn)

            # extract out sepolicy related files
            if filebase in SEPOLICY_FILES:
                if filebase in self.saved_files:
                    log.warning("Also found '%s' in '%s'. Prefering first seen version", filebase, combined_fs.fsname)
                    continue

                file_name = os.path.basename(p["original_path"])
                self.save_file(p["original_path"], file_name)

                log.info("Saving SELinux policy file '%s' from '%s'",
                         filebase, combined_fs.fsname)

        # TODO: double check that we found a complete SEAndroid policy

        # extract out properties from the filesystems
        self._extract_properties(combined_fs)
        self._extract_init(combined_fs)

        if "file_contexts.bin" in self.saved_files:
            log.info("Converting found file_contexts.bin to file_contexts")

            fc_path = os.path.join(self.results_directory, "file_contexts")
            convert_file_contexts(self.saved_files["file_contexts.bin"]["save_path"], fc_path)

            if "file_contexts" in self.saved_files:
                log.warn("File context conversion from .bin overwrote found file_contexts file")

            # manually save this as it was generated, not copied
            self.saved_files["file_contexts"] = {"save_path": fc_path}

        # Save filesystems
        self.asp.fs_policies = [combined_fs] + fs_policies

        # Save found policy files
        self.asp.policy_files = self.saved_files

        return self.asp

    def _firmware_extract_task(self, filepath, skip=False):
        job_result_dir = os.path.join(os.environ['HOME'], 'atsh_tmp' + self.job_id)

        # Mounted file systems: /home/atsh_tmp0/mnt*
        # Extracted file systems: ./extract/VENDOR/BASENAME/

        # This is an atextract.sh quirk
        vendor_name = self.asp.vendor.lower()

        firmware_name = path_to_firmware_name(filepath)
        vendor_extracted_path = os.path.join("./extract/", vendor_name)
        firmware_extracted_path = os.path.join(vendor_extracted_path, firmware_name)

        if not skip and os.path.isdir(firmware_extracted_path):
            log.warning("Found firmware extracted directory. Removing...")
            shutil.rmtree(firmware_extracted_path)

        log.info("Extracting %s...", firmware_name)

        if not skip:
            p = Popen([AT_EXTRACT_PATH, filepath, vendor_name, self.job_id, '1', '0'])
            p.communicate()
            # TODO: check for error

        if not os.path.isdir(job_result_dir):
            log.error("No filesystem result directory found. Possible extraction error")
            return []

        fs_prefix = "mnt_"
        mounted_filesystems = glob.glob(os.path.join(job_result_dir, fs_prefix + '*'))
        extracted_filesystems = list(directories(os.path.join(firmware_extracted_path)))

        filesystems = []

        for fs in mounted_filesystems:
            name = os.path.basename(fs)
            name = name[len(fs_prefix):]
            log.info('Found filesystem %s', name)
            filesystems += [{"path": fs, "name": name}]

        for fs in extracted_filesystems:
            name = os.path.basename(fs)
            fname, ext = os.path.splitext(name)

            if ext in [".bin", ".img", ".image"]:
                filesystems += [{"path": fs, "name": name}]
                log.info('Found extracted filesystem %s', name)

        return filesystems

    def _extract_properties(self, policy):
        prop_files = []

        # Extract out prop files
        prop_files += policy.find("*.prop")
        prop_files += policy.find("prop.default")

        log.info("Collecting android property metadata from %d prop files",
                len(prop_files))

        props = AndroidPropertyList()

        # TODO: ensure ordering of property files!
        # Ref: https://rxwen.blogspot.com/2010/01/android-property-system.html
        for prop in prop_files:
            (k, v), = prop.items()
            props.from_file(v["original_path"])

            log.debug("Saving .prop file '%s'", k)
            self.save_file(v["original_path"], os.path.join("prop", k[1:]))

        # If we can't find this, we're in trouble
        if 'ro.build.version.release' not in props:
            raise ExtractionError("Invalid firmware image '%s': missing Android version in props files" % self.asp.firmware_name)

        self.asp.properties = props

    def _extract_init(self, policy):
        rc_files = []

        # Extract out prop files
        rc_files = policy.find("*.rc")

        log.info("Found %d init.rc files", len(rc_files))

        for rc_dict in rc_files:
            (rc, v), = rc_dict.items()

            log.debug("Saving init.rc file '%s'", rc)
            self.save_file(v["original_path"], os.path.join("init", rc[1:]))

        fstab_files = policy.find("*fstab*")

        log.info("Found %d fstab files", len(fstab_files))

        for rc_dict in fstab_files:
            (rc, v), = rc_dict.items()

            log.debug("Saving fstab: '%s'", rc)
            self.save_file(v["original_path"], os.path.join("init", rc[1:]))

    def _walk_filesystem(self, fs_name, fs_type, toplevel_path):
        def handle_error(exp):
            if isinstance(exp, OSError):
                if exp.errno == errno.EACCES:
                    log.error("Unable to access file during walk. Make sure you are root!")
                    sys.exit(1)

            raise

        fsp = FilesystemPolicy(fs_name, fs_type)

        includeroot = True
        toplevel_path = os.path.normpath(toplevel_path)
        toplevel_components = toplevel_path.split(os.sep)

        for root, dirs, files in os.walk(toplevel_path, onerror=handle_error, followlinks=False):
            if includeroot:
                objects = ["."] + dirs + files
                includeroot = False
            else:
                objects = dirs + files

            for obj in objects:
                path = os.path.join(root, obj)
                path = os.path.normpath(path)
                path_components = path.split(os.sep)
                # translate the path to absolute relative to the filesystem image base directory
                fs_relative_path = os.path.join("/", *path_components[len(toplevel_components):])

                # get the information of the symbolic link itself, not its target
                st = os.lstat(path)

                # Collect DAC policy
                perms = st[stat.ST_MODE]
                user = st[stat.ST_UID]
                group = st[stat.ST_GID]
                size = st[stat.ST_SIZE]

                if stat.S_ISLNK(perms):
                    link = os.readlink(path)
                else:
                    link = ""

                file_policy = {
                    "original_path": path,
                    "user": user,
                    "group": group,
                    "perms": perms,
                    "size": size,
                    "link_path": link,
                    "capabilities": None,
                    "selinux": None,
                }

                # Collect MAC (SELinux) and other security policies (capabilities)
                xattrs = {}

                # Get all extended attributes
                for xattr in os.listxattr(path, follow_symlinks=False):
                    # These are binary data (SELinux is a C-string, Capabilies is a 64-bit integer)
                    xattrs.update({xattr: os.getxattr(path, xattr, follow_symlinks=False)})

                for k, v in xattrs.items():
                    # pretty-print xattrs
                    if k == "security.selinux":
                        # strip any opening/closing quotes
                        sel = v.strip(b"\x00").decode('ascii')
                        file_policy.update({
                            "selinux": SELinuxContext.FromString(sel)
                        })
                    elif k == "security.capability":
                        # capabilities can vary in size depending on the version
                        # see ./include/uapi/linux/capability.h in the kernel source tree for more information
                        cap = int.from_bytes(v, byteorder='little')
                        file_policy.update({"capabilities": cap})
                    else:
                        log.warn("Unparsed extended attribute key %s", k)

                # store the file metadata in the policy
                fsp.add_file(fs_relative_path, file_policy)

        return fsp

