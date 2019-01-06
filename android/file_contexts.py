from sefcontext_parser import sefcontext_parser as sefparse
import re
from stat import *

from android.sepolicy import SELinuxContext

F_MODE = {S_IFIFO: '-p',
          S_IFCHR: '-c',
          S_IFDIR: '-d',
          S_IFBLK: '-b',
          S_IFREG: '--',
          S_IFLNK: '-l',
          S_IFSOCK: '-s'}

F_MODE_INV = dict([[v,k] for k,v in F_MODE.items()])

class AndroidFileContext(object):
    def __init__(self, regex, mode, context):
        self.regex = regex
        self.mode = mode
        self.context = context

    def match(self, path, mode=None):
        if self.mode and mode:
            return (self.regex.match(path) is not None) and (mode & self.mode)
        else:
            return self.regex.match(path) is not None

    def __repr__(self):
        return "AndroidFileContext<%s -> %s>" % (self.regex.pattern, self.context)

    def __hash__(self):
        return hash(repr(self))

def convert_file_contexts(source, dest):
    # Based upon https://github.com/jakev/sefcontext-parser for file_contexts.bin
    parser = sefparse.SefContextParser(source)

    with open(dest, 'w') as fp:
        for entry in parser.process_file():
            fp.write("%s\n" % str(entry))

def read_file_contexts(source):
    fp = open(source, 'r')
    data = fp.read()
    fp.close()

    contexts = []

    for line_no, line in enumerate(data.split("\n")):
        # Ignore comments and blank lines
        if re.match('^(\s*#)|(\s*$)', line):
            continue

        # greedly replace all whitespace with a single space for splitting
        line = re.sub('\s+', " ", line)

        # split by spaces, while eliminating empty components
        components = list(filter(lambda x: len(x) > 0, line.split(" ")))

        # regex, mode, context
        if len(components) == 3:
            regex = components[0]
            mode = F_MODE_INV[components[1]]
            context = components[2]
        # regex, context
        elif len(components) == 2:
            regex = components[0]
            context = components[1]
            mode = None
        else:
            raise ValueError("Malformed or unhandled file_contexts syntax at line %d" % (line_no+1))

        try:
            # we assume that the whole path much match (start of line/eol)
            # XXX: this is the right way to do this, but it breaks files which aren't
            # labeled and have no file_context's entry. We'll have to live with it for now
            regex = re.compile(r'^' + regex + r'$')

            #regex = re.compile(regex)
        except re.error:
            log.error("Failed to compile file_contexts regular expression on line %d", (line_no+1))
            continue

        context = SELinuxContext.FromString(context)
        contexts += [AndroidFileContext(regex, mode, context)]

    # ensure that these contexts are sorted by regex
    contexts = sorted(contexts, key=lambda x: x.regex.pattern)

    return contexts
