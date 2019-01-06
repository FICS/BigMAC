# TODO: include seccomp
# plat/nonplat files are only found on Android N (>8.0) as part of the Treble project
# Treble Reference: https://source.android.com/security/selinux/images/SELinux_Treble.pdf
SEPOLICY_FILES = [
        'sepolicy',
        'precompiled_sepolicy', # Treble devices (if it has been compiled)
        'selinux_version', # may or may not be there
        'genfs_contexts', # not sure if this exists - found in binary sepolicy

        # file
        'file_contexts',
        'file_contexts.bin', # found in newer Android versions (>7.0)
        'plat_file_contexts',
        'nonplat_file_contexts',
        'vendor_file_contexts',

        # seapp
        'seapp_contexts',
        'plat_seapp_contexts',
        'nonplat_seapp_contexts',
        'vendor_seapp_contexts',

        # property
        'property_contexts',
        'plat_property_contexts',
        'nonplat_property_contexts',
        'vendor_property_contexts',

        # service
        'service_contexts',
        'plat_service_contexts',
        'nonplat_service_contexts',
        'vndservice_contexts',

        # hwservice
        'hwservice_contexts',
        'plat_hwservice_contexts',
        'nonplat_hwservice_contexts',
        'vendor_hwservice_contexts',

        # TODO: also get fs_config_files and fs_config_dirs

        # Middleware MAC
        'mac_permissions.xml', # TODO: Treble has /vendor and /system versions of this
        'ifw.xml',
        'eops.xml'
]

# Make sure there are no duplicates
assert len(SEPOLICY_FILES) == len(set(SEPOLICY_FILES))

class SELinuxContext:
    def __init__(self, user, role, ty, mls):
        self.user = user
        self.role = role
        self.type = ty
        self.mls = mls

    @staticmethod
    def FromString(context):
        parts = context.split(":")

        if len(parts) < 4:
            raise ValueError("Invalid SELinux label '%s'" % context)

        se_user = parts[0]
        se_role = parts[1]
        se_type = parts[2]
        # MLS is a special case and may also contain ':'
        se_mls = ":".join(parts[3:])

        return SELinuxContext(se_user, se_role, se_type, se_mls)

    def __str__(self):
        return "%s:%s:%s:%s" % (self.user, self.role, self.type, self.mls)

    def __repr__(self):
        return "<SELinuxContext %s>" % (str(self))

    def __eq__(self, rhs):
        if isinstance(rhs, SELinuxContext):
            return str(self) == str(rhs)

        return NotImplemented
