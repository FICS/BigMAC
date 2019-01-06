import logging
import time
import shlex
import readline
import re
import os
import sys
import networkx as nx
import glob
import pickle
import hashlib
import shutil
import pprint
import overlay

from android.capabilities import Capabilities
from subprocess import Popen, PIPE, STDOUT

log = logging.getLogger(__name__)

HISTORY_FILENAME = ".query_history"
FACTS_OUTPUT_FILE = 'facts.pl'

class Prolog(object):
    def __init__(self, G, save_dir, inst, asp):
        self.graph = G
        self.node_objs = nx.get_node_attributes(G, 'obj')
        self.inst = inst
        self.asp = asp
        self.commands = []
        self.mapping = {}
        self.node_id_map = {}
        self.node_id_map_inv = {}
        self.result = None

        self.db_dir = save_dir
        self.inst_map_path = os.path.join(self.db_dir, 'inst-map')
        self.facts_path = os.path.join(self.db_dir, FACTS_OUTPUT_FILE)
        self.saved_queries_path = os.path.join(self.db_dir, "saved_queries")

        self.mac_only = False
        self.special_file_map = {
            "all": 0,
            "usb": 1,
            "bluetooth": 2,
            "modem": 3,
            "nfc": 4,
        }
        self.special_files = {}
        self.special_files_sorted = {
            "usb": [],
            "bluetooth": [],
            "modem": [],
            "nfc": [],
        }
        self.sub_trusted = []

        self.commands = [
                {'name' : 'query', 'handler': self.query},
                {'name' : 'query_mac', 'handler': self.query_mac_only},
                {'name' : 'print', 'handler': self.print_paths},
                {'name' : 'print_trust', 'handler': self.print_trust_paths},
                {'name' : 'print_special', 'handler' : self.print_special},
                {'name' : 'print_trusted', 'handler' : self.print_trusted},
                {'name' : 'print_strongest', 'handler' : self.print_strongest},
                {'name' : 'diff', 'handler' : self.diff},
                {'name' : 'save', 'handler': self.save},
                {'name' : 'info', 'handler': self.object_info},
                {'name' : 'list_saved', 'handler': self.list_saved},
                {'name' : 'load', 'handler': self.load},
                {'name' : 'debug', 'handler': self.debug},
        ]

    def print_strongest(self, args):
        results = {}
        count = 0
        for pn, p in self.inst.processes.items():
            name = p.get_node_name()
            self.result = []
            self.query([name, "_", "1"])

            if len(self.result) > 0:
                uniq_types = {}
                obj_types = {"ipc": 0, "file": 0}

                for path in self.result:
                    target = path[1]
                    obj = self.node_objs[self.node_id_map_inv[target]]
                    uniq_types[obj.sid.type] = 1

                    if isinstance(obj, overlay.IPCNode):
                        obj_types["ipc"] += 1
                    elif isinstance(obj, overlay.FileNode):
                        obj_types["file"] += 1

                results[name] = [len(uniq_types), len(self.result), obj_types["ipc"],
                        obj_types["file"]]

            count += 1

            if count % 10 == 0:
                print("Progress %d/%d" % (count, len(self.inst.processes)))

        results = sorted(list(results.items()), key=lambda x: x[1][1], reverse=True)

        for i, res in enumerate(results):
            print("%3d: ntype=%-5d nobj=%-5d ipc=%-5d file=%-5d %s" % (i+1,
                res[1][0], res[1][1], res[1][2], res[1][3], res[0]))

    def load_node_map(self):
        with open(self.inst_map_path, 'rb') as fp:
            self.node_id_map = pickle.load(fp)

        self.node_id_map_inv = dict([[v,k] for k,v in self.node_id_map.items()])

    def save_node_map(self):
        with open(self.inst_map_path, 'wb') as fp:
            pickle.dump(self.node_id_map, fp)

    def compile_all(self):
        new_facts = self._emit_facts()

        if not new_facts:
            log.error("Failed to emit facts")
            return False

        try:
            with open(self.facts_path, 'r') as fp:
                old_facts = fp.read()
        except IOError:
            old_facts = ""

        new_facts_sha256 = hashlib.sha256(new_facts.encode('ascii')).digest()
        old_facts_sha256 = hashlib.sha256(old_facts.encode('ascii')).digest()
        recompile = False

        if old_facts_sha256 != new_facts_sha256:
            log.info("Facts have changed! Recompiling prolog helpers...")

            with open(FACTS_OUTPUT_FILE, 'w') as fp:
                fp.write(new_facts)

            # save a copy of the facts to make sure they stay in sync
            shutil.copyfile(FACTS_OUTPUT_FILE, self.facts_path)

            self.save_node_map()
            recompile = True

        # make sure we can load the node map
        try:
            self.load_node_map()
        except (IOError, EOFError, pickle.UnpicklingError) as e:
            log.warning("Failed to load the saved inst-map file: %s", e)

            self.save_node_map()

            # Should always be loadable at this point, unless there is a race condition
            try:
                self.load_node_map()
            except Exception as e:
                log.error("Permanently failed to load the prolog node map file %", e)
                return False

        for q in range(2, 6):
            name = os.path.join(self.db_dir, "inst%d" % q)
            if not self.compile(name, [FACTS_OUTPUT_FILE, 'logic/main%d.pl' % q, 'logic/sea_impl.pl']):
                return False

        return True

    def compile(self, binary, inputs):
        log.info("Compiling prolog %s...", binary)
        cmdline = ["swipl", "--goal=main", "-o", binary, "-c"] + inputs

        start = time.time()
        proc = Popen(cmdline, stdout=PIPE, stderr=STDOUT)
        stdout, _ = proc.communicate()

        error_lines = []
        warning_lines = []
        for line in stdout.decode().split("\n"):
            if "error" in line.lower():
                error_lines += [line[7:]]
            if "warning" in line.lower():
                warning_lines += [line[9:]]

        if len(error_lines):
            log.info("Prolog failed to compile:")

            # remove any binary that failed to compile
            try:
                os.unlink(binary)
            except OSError:
                pass

            for l in error_lines:
                log.error(l)

            return False
        else:
            log.info("Prolog successfully compiled to %s in %.2f seconds",
                    binary, time.time()-start)
            return True

    def object_info(self, args):
        if len(args) < 1:
            print("Object required")
            return

        name = args[0]

        if name not in self.node_objs:
            print("Object not found")
            return

        obj = self.node_objs[name]

        if isinstance(obj, overlay.IPCNode):
            print("IPC %s" % obj.get_node_name())
            if obj.owner:
                print("Owner: %s" % (repr(obj.owner)))
                print("Owner Node Name: %s" % (obj.owner.get_node_name()))
        elif isinstance(obj, overlay.ProcessNode):
            print(repr(obj))
            (fn, fo), = obj.exe.items()
            print("Backing file %s" % fn)
            print(self.inst.filesystem.list_path(fn))
            pprint.pprint(fo)
        else:
            print(repr(obj))
            if len(obj.backing_files):
                (fn, fo), = obj.backing_files.items()
                print("Backing file %s" % fn)
                print(self.inst.filesystem.list_path(fn))
                pprint.pprint(fo)

    def print_paths(self, args):
        if not self.result:
            return

        cutoff = None
        if len(args) > 0:
            try:
                cutoff = int(args[0])
            except ValueError:
                return

        for pathid, path in enumerate(sorted(self.result)):
            if cutoff is not None and (pathid+1 > cutoff):
                break

            pretty_path = self._render_path(path)
            print("%d: %s" % (pathid+1, pretty_path))

    def _render_path(self, path, colorized=False):
        renamed = []

        for component in path:
            name = self.node_id_map_inv[component]
            obj = self.node_objs[name]

            if colorized:
                # TODO: make the coloring be controlled by a lambda
                if obj.trusted:
                    renamed += ["\x1b[32m%s (T)\x1b[0m" % name]
                else:
                    renamed += ["\x1b[31m%s (U)\x1b[0m" % name]
            else:
                renamed += [name]

        return " -> ".join(renamed)

    def print_trust_paths(self, args):
        if not self.result:
            return

        cutoff = None
        if len(args) > 0:
            try:
                cutoff = int(args[0])
            except ValueError:
                return

        for pathid, path in enumerate(sorted(self.result)):
            if cutoff is not None and (pathid+1 > cutoff):
                break

            pretty_path = self._render_path(path, colorized=True)
            print("%d: %s" % (pathid+1, pretty_path))

    def sort_special_files(self):
        if not self.special_files:
            return

        # Obj = (obj, fn, tags)
        for name, obj in self.special_files.items():
            for tag in obj[2]:
                self.special_files_sorted[tag].append((name, obj[1], obj[0]))

    def print_special(self, args):
        pprint.pprint(self.special_files_sorted)

    def print_trusted(self, args):
        pprint.pprint(self.sub_trusted)

    def list_saved(self, args):
        saved_queries = glob.glob(os.path.join(self.saved_queries_path, "*"))

        print("Saved file path %s" % (self.saved_queries_path))
        for i, fn in enumerate(saved_queries):
            print("%d: %s" % (i+1, os.path.basename(fn)))

    def save(self, args):
        if len(args) < 1:
            log.error("Save needs filename")
            return

        if not self.result:
            log.error("No results to save")
            return

        path = os.path.join(self.saved_queries_path, args[0])

        try:
            os.mkdir(self.saved_queries_path)
        except IOError:
            pass

        try:
            with open(path, 'wb') as fp:
                pickle.dump(self.result, fp)
            log.info("Saved %d results to %s", len(self.result), path)
        except IOError as e:
            log.error("Failed to save file: %s", e)

    def diff(self, args):
        import difflib

        filter_param = ""

        if len(args) < 2:
            log.error("Diff needs two arguments")
            return

        if len(args) == 3:
            filter_param = args[2]

        if filter_param != "":
            if filter_param not in ["left", "right", "both"]:
                log.error("Invalid diff filter '%s'", filter_param)
                return

        diff_a = args[0]
        diff_b = args[1]

        diff_a_paths = self._load(diff_a)
        diff_b_paths = self._load(diff_b)

        if len(diff_a_paths) == 0 or len(diff_b_paths) == 0:
            print("Left or right result has no paths")
            return

        d = difflib.Differ()

        diff_a_paths = [(self._render_path(x) + "\n") for x in diff_a_paths]
        diff_b_paths = [(self._render_path(x) + "\n") for x in diff_b_paths]

        print("Diffing %s (%d) -> %s (%d) paths..." % (diff_a, len(diff_a_paths), diff_b, len(diff_b_paths)))
        result = d.compare(diff_a_paths, diff_b_paths)

        if filter_param == "left":
            result = list(filter(lambda x: x.startswith('- '), result))
        elif filter_param == "right":
            result = list(filter(lambda x: x.startswith('+ '), result))
        elif filter_param == "both":
            result = list(filter(lambda x: x.startswith('  '), result))

        for i, line in enumerate(result):
            sys.stdout.write("%d: %s" % (i+1, line))

    def load(self, args):
        if len(args) < 1:
            log.error("Load needs filename")
            return

        self.result = self._load(args[0])

    def _load(self, filename):
        path = os.path.join(self.saved_queries_path, filename)

        try:
            with open(path, 'rb') as fp:
                result = pickle.load(fp)
            log.info("Loaded %d results from %s", len(result), filename)
            return result
        except IOError as e:
            log.error("Failed to load file: %s", e)
            return []

    def debug(self, args):
        from IPython import embed
        embed()

    def interact(self):
        def dispatch_command(user_cmd, args):
            ret = None

            for cmd in self.commands:
                if user_cmd == cmd["name"]:
                    ret = cmd["handler"](args)
                    return 0

            print("Unknown command '%s'" % (user_cmd))
            return 1

        # Non-interactive command dispatch
        #if len(args.command):
        #    return dispatch_command(args.command[0], args.command[1:])

        history_path = os.path.join(self.db_dir, HISTORY_FILENAME)
        try:
            readline.read_history_file(history_path)
        except IOError:
            pass

        readline.parse_and_bind("tab: complete")
        delims = set(readline.get_completer_delims()) - set([":"])
        readline.set_completer_delims("".join(sorted(delims)))
        readline.set_completer(lambda t,s: self.completer(t,s))

        # Interactive command loop
        while True:
            try:
                # Make the prompt stand out a bit
                color_start = "\033[37;1m"
                color_end = "\033[0m"
                action = input('%squery [%s]>%s ' % (color_start, self.asp.get_properties()["summary"], color_end))
            except EOFError:
                sys.stdout.write("\nExiting...\n")
                break
            except KeyboardInterrupt:
                # fake the Ctrl+C display, like a real terminal
                sys.stdout.write("^C\n")
                continue

            try:
                action = action.strip().rstrip()
                args = shlex.split(action)
            except ValueError:
                print("Error parsing arguments")
                continue

            if len(args) > 0:
                user_cmd = args[0]
                args = args[1:]
            # no input? skip
            else:
                continue

            readline.write_history_file(history_path)

            # handle built-in commands
            if user_cmd in ['?', 'help']:
                for cmd in self.commands:
                    print(cmd["name"])
            elif user_cmd == "ipython":
                embed()
            elif user_cmd in ["exit", "quit"]:
                break
            else:
                try:
                    dispatch_command(user_cmd, args)
                except KeyboardInterrupt:
                    print("Command interrupted")

    def completer(self, text, state):
        line_buffer = readline.get_line_buffer()
        tokens = shlex.split(line_buffer)
        start_idx = readline.get_begidx()
        end_idx = readline.get_endidx()
        text = line_buffer[start_idx:end_idx]

        if len(tokens) > 1:
            valid_choices = sorted([i for i in self.node_id_map if i.startswith(text)])
            if state < len(valid_choices) and state < 100:
                return valid_choices[state]
            else:
                return None
        else:
            # commands
            valid_commands = [i["name"] for i in self.commands if i["name"].startswith(text)]
            if state < len(valid_commands):
                return valid_commands[state]
            else:
                return None

    def node_lookup(self, node):
        # pretty -> id
        if node in self.node_id_map:
            pretty = node
            plnode = self.node_id_map[node]
        # maybe id -> pretty
        else:
            if node in self.node_id_map_inv:
                pretty = self.node_id_map_inv[node]
                plnode = node
            else:
                return None, None

        return plnode, pretty

    def query_mac_only(self, args):
        self.mac_only = True
        self.query(args)
        self.mac_only = False

    def query(self, args):
        if len(args) < 3:
            log.error("Query needs 3 arguments")
            return

        if len(args) > 3 and self.mac_only:
            log.error("Incompatible")
            return

        if len(args) >= 4:
            cap = args[3]
        else:
            cap = None
        if len(args) == 5:
            source = args[4]
        else:
            source = None

        if len(args) > 5:
            log.error("Too many args")
            return

        start = args[0]
        end = args[1]
        cutoff = args[2]

        if start in ["_", "*"]:
            plstart, start_pretty = start, start
        else:
            plstart, start_pretty = self.node_lookup(start)

        if end in ["_", "*"]:
            plend, end_pretty = end, end
        else:
            plend, end_pretty = self.node_lookup(end)

        if not plstart:
            log.error("Unable to lookup start node %s", start)
            return

        if not plend:
            log.error("Unable to lookup end node %s", end)
            return

        log.info("Start %f", time.time())
        log.info("Query <%s> -> <%s> (cutoff %s)",
                start_pretty, end_pretty, cutoff)
        cmdline = [plstart, plend, cutoff]

        if self.mac_only:
            binary = "inst2"
        else:
            binary = "inst3"

        if cap:
            cmdline += [cap]
            log.info("Cap %s", cap)
            binary = "inst4"

        if source:
            cmdline += [source]
            log.info("External Source %s", source)
            binary = "inst5"

        log.info("executing '%s' args : %s", binary, cmdline)
        binary_path = os.path.join(self.db_dir, binary)
        proc = Popen([binary_path] + cmdline, stdout=PIPE)

        stime = time.time()
        try:
            stdout, stderr = proc.communicate()
        except KeyboardInterrupt:
            proc.kill()
            print("Query interrupted")
            return

        etime = time.time()

        self.result = self._parse_result(stdout)
        # show the shortest (easiest) paths first
        self.result = sorted(self.result, key=lambda x: len(x))

        if len(self.result) > 0:
            log.info("Got %d paths in %.2f seconds (use `print` or `print_trust` to display)",
                    len(self.result), etime-stime)
        else:
            log.info("No results in %.2f seconds", etime-stime)

    def _parse_result(self, result):
        if len(result) == 0:
            return []

        orig_result = result.decode()
        lines = orig_result.split("\n")

        if len(lines) < 5:
            print("Result was malformed")
            return []

        result = lines[-1]

        # remove all whitespace
        result = re.sub(r'\s+', ' ', result)
        result = re.sub(r'([a-zA-Z0-9]),([a-zA-Z0-9])', "\\1','\\2", result)
        result = re.sub(r'\[([a-zA-Z0-9])', r'[' + r"'\1", result)
        result = re.sub(r'([a-zA-Z0-9])\]', r'\1' + "'" + ']', result)

        try:
            res = eval(result)
        except SyntaxError:
            log.error("Result was malformed")

            with open('bad-result', 'w') as fp:
                fp.write(orig_result)
            return []

        return res

    def _emit_facts(self):
        G = self.graph
        log.info("Emitting prolog facts...")

        node_objs = nx.get_node_attributes(G, 'obj')

        proc_to_drop =[]
        obj_to_drop = []
        total_proc = 0
        total_obj = 0

        # Prune the graph of any nodes we can't get DAC/MAC information for
        for node in list(G.nodes()):
            obj = node_objs[node]
            ty = obj.get_obj_type()

            if ty == "process" or ty == "subject":
                total_proc += 1
                uid = obj.cred.uid
                gid = obj.cred.gid
                groups = obj.cred.groups

                if None in [uid, gid, groups]:
                    log.warning("Dropping Process %s as no cred %s", node, str([uid, gid, groups]))
                    proc_to_drop += [node]
                    continue
            elif ty == "ipc":
                total_obj += 1

                if not obj.owner:
                    log.warning("Dropping IPC %s as no owner", node)
                    obj_to_drop += [node]
                    continue

                if None in [obj.owner.cred.uid, obj.owner.cred.gid]:
                    log.warning("Dropping IPC %s as owner has no cred", node)
                    obj_to_drop += [node]
                    continue
            elif ty == "file":
                total_obj += 1

                uid = obj.uid
                gid = obj.gid

                if None in [uid, gid]:
                    log.warning("Dropping File %s as no DAC info", node)
                    obj_to_drop += [node]
                    continue
            else:
                assert 0

        G.remove_nodes_from(obj_to_drop)
        G.remove_nodes_from(proc_to_drop)

        if len(proc_to_drop) or len(obj_to_drop):
            log.warning("Dropping %d proc (%.1f), %d obj (%.1f)",
                    len(proc_to_drop), len(proc_to_drop)/total_proc*100.0,
                    len(obj_to_drop), len(obj_to_drop)/total_obj*100.0)

        if len(G.nodes()) == 0:
            log.error("Dropped all nodes")
            return False

        node_id = 0

        sub_db = []
        obj_db = []
        self.node_id_map = {}

        facts = ""

        def get_node_type(n):
            return node_objs[n].get_obj_type()

        all_processes = filter(lambda n: get_node_type(n) in ["process", "subject"],
                G.nodes())
        all_objects = filter(lambda n: get_node_type(n) not in ["process", "subject"],
                G.nodes())

        # Sort by PID
        for node in sorted(all_processes, key=lambda n: node_objs[n].pid):
            obj = node_objs[node]
            ty = obj.get_obj_type()

            assert obj not in self.node_id_map
            node_name = "s%d" % node_id

            uid = obj.cred.uid
            gid = obj.cred.gid
            groups = list(obj.cred.groups)

            caps = obj.cred.cap.effective
            caps = [Capabilities.name_to_bit(x) for x in caps]
            caps = sorted(caps)
            caps = str(caps)

            groups = str(sorted([gid] + groups)).replace('\'', '')
            line = "sub(%s, %d, %s, 7, 7, 7, %s)." % (
                    node_name, uid, groups, caps)
            sub_db += [node_name]
            
            if obj.trusted:
                self.sub_trusted.append(node)

            self.node_id_map[node] = node_name
            node_id += 1

            facts += "% " + node + "\n"
            facts += line + "\n"

        node_id = 0

        for node in sorted(all_objects):
            extra_comment = ""
            obj = node_objs[node]
            ty = obj.get_obj_type()

            assert obj not in self.node_id_map
            node_name = "o%d" % node_id

            if ty == "ipc":
                uid = obj.owner.cred.uid
                gid = obj.owner.cred.gid
                # TODO: not really correct for all IPCs
                uperm = 7
                gperm = 7
                operm = 7
                tags = ["all"]
                perty = "[" + ",".join(map(str, map(self.special_file_map.get, tags))) +"]"

                line = "obj(%s, %d, %d, %d, %d, %d, %s)." % (
                        node_name, uid, gid, uperm, gperm, operm, perty)
                obj_db += [node_name]
            elif ty == "file":
                (fn, fo), = obj.backing_files.items()

                uid = obj.uid
                gid = obj.gid
                mode = fo["perms"] & 0o777

                uperm = (mode & 0o700) >> 6
                gperm = (mode & 0o070) >> 3
                operm = (mode & 0o007) >> 0

                tags = sorted(list(fo.get("tags", [])))

                if len(tags):
                    log.info("SPECIAL OBJECT %s %s", fn, tags)
                    self.special_files[node] = (obj, fn, tags)
                    extra_comment = " SPECIAL " + str(tags)

                tags = ["all"] + tags

                perty = "[" + ",".join(map(str, map(self.special_file_map.get, tags))) +"]"

                line = "obj(%s, %d, %d, %d, %d, %d, %s)." % (
                        node_name, uid, gid, uperm, gperm, operm, perty)
                obj_db += [node_name]
            else:
                assert 0

            self.node_id_map[node] = node_name
            node_id += 1

            comment = node + extra_comment
            facts += "% " + comment + "\n"
            facts += line + "\n"

        facts += "\nsub_db(all, %s).\n" % str(sub_db).replace('\'', '')
        obj_db_str = "["
        for i, o in enumerate(obj_db):
            last = i+1 == len(obj_db)
            if last:
                obj_db_str += "%s]" % str(o)
                break

            if i > 0 and i % 10 == 0:
                obj_db_str += "%s,\n" % str(o)
            else:
                obj_db_str += "%s, " % str(o)

        facts += "obj_db(all, %s).\n\n" % obj_db_str

        # Emit edges
        for edge in sorted(list(G.edges())):
            u = self.node_id_map[edge[0]]
            v = self.node_id_map[edge[1]]

            facts += "edge(%s, %s).\n" % (u, v)

        # Sort all special files
        self.sort_special_files()

        log.info("Prolog facts emitted")

        return facts

