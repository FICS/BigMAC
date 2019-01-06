import logging
import re

PROPERTY_KEY = re.compile(r'[-_.a-zA-Z0-9]+')
PROPERTY_VALUE = re.compile(r'[^#]*')
PROPERTY_KV = re.compile(r'^\s*('+PROPERTY_KEY.pattern+r')\s*=\s*('+
                         PROPERTY_VALUE.pattern+')')

log = logging.getLogger(__name__)

class AndroidPropertyList:
    def __init__(self):
        self.prop = {}

    def set(self, key, value):
        if not PROPERTY_KEY.match(key):
            raise ValueError("Invalid key format")
        if not PROPERTY_VALUE.match(value):
            raise ValueError("Invalid value format")

        self.prop[key] = value

    def __getitem__(self, key):
        return self.get(key)

    def __setitem__(self, key, value):
        self.set(key, value)

    def __contains__(self, key):
        return key in self.prop

    def get(self, key):
        return self.prop[key]

    def get_default(self, key, default=""):
        if key not in self.prop:
            return default
        else:
            return self.prop[key]

    def get_multi_default(self, keys, default=""):
        """ Try multiple keys returning the first found or the default """
        for key in keys:
            if key in self.prop:
                return self.prop[key]

        return default

    def merge(self, rhs):
        """ Merge another property list into this one """
        assert isinstance(rhs, AndroidPropertyList)
        self._merge(rhs.prop)

    def _merge(self, other):
        for k, v in other.items():
            self.prop[k] = v

    def from_file(self, filename):
        prop_raw_data = open(filename, 'r').read()

        properties = {}

        for line_no, line in enumerate(prop_raw_data.split("\n")):
            # Ignore comments and blank lines
            if re.match(r'^(\s*#)|(\s*$)', line):
                continue

            # Ignore import statements
            if re.match('^import', line):
                log.warning("property_from_file: unhandled import statement at line '%d' in '%s'",
                            line_no+1, filename)
                continue

            # Match property assignments (right side can be blank)
            result = PROPERTY_KV.match(line)

            if not result:
                log.warn("property_from_file: failed to match line %d in %s", line_no+1, filename)
                continue

            prop, value = result.groups()
            properties[prop] = value

        # Merge in the final found properties
        self._merge(properties)

    def to_file(self, filename):
        fp = open(filename, 'w')

        for k, v in self.prop.items():
            fp.write("%s=%s\n" % (k, v))

        fp.close()
