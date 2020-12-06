import logging
import os
import networkx as nx
import copy
import re
from enum import Enum
from IPython import embed
from fnmatch import fnmatch

from android.dac import Cred, AID_MAP, AID_MAP_INV
from android.sepolicy import SELinuxContext
from android.capabilities import Capabilities

log = logging.getLogger(__name__)

OBJ_COLOR_MAP = {
        'subject' : '#b7bbff',
        'subject_group' : 'white',
        'file' : 'grey',
        'ipc' : 'pink',
        'socket' : 'orange',
        'unknown' : 'red',
}

class GraphNode(object):
    trusted = False

    def get_node_name():
        raise ValueError("Not implemented")

    def associate_file():
        raise ValueError("Not implemented")

    def get_obj_type(self):
        if isinstance(self, IPCNode):
            obj_type = "ipc"
        elif isinstance(self, SubjectNode):
            obj_type = "subject"
        elif isinstance(self, FileNode):
            obj_type = "file"
        elif isinstance(self, ProcessNode):
            obj_type = "process"
        else:
            raise ValueError("Unhandled generic object type %s" % repr(self))

        return obj_type

    def __repr__(self):
        return "<GraphNode[%s]>" % self.get_obj_type()


class FileNode(GraphNode):
    def __init__(self):
        # files only have these three credentials
        self.uid = None
        self.gid = None
        self.sid = None
        # note that these are stored in xattrs
        self.cap = Capabilities()

        self.backing_files = {}

    def associate_file(self, file_obj):
        self.backing_files.update(file_obj)

    def get_node_name(self):
        return "file:%s" % (str(self.sid.type))

    def __repr__(self):
        return "<FileNode %s>" % self.sid.type

class IPCNode(GraphNode):
    def __init__(self, ipc_type):
        # an SELinux type
        self.sid = None

        # which subject owns this object (used for cred lookup)
        self.owner = None

        self.ipc_type = ipc_type
        self.backing_files = {}

    def associate_file(self, file_obj):
        self.backing_files.update(file_obj)

    @property
    def trusted(self):
        return self.owner.trusted

    @trusted.setter
    def trusted(self, v):
        raise ValueError("Cannot set IPC trust: set it on the owning subject")

    def get_node_name(self):
        return "%s:%s" % (self.ipc_type, self.sid.type)

    def __repr__(self):
        return "<IPCNode %s>" % self.sid.type

class SubjectNode(GraphNode):
    def __init__(self, cred=None):
        self.parents = set()
        self.children = set()

        self.backing_files = {}
        if cred:
            self.cred = cred
        else:
            self.cred = Cred()

    @property
    def sid(self):
        return self.cred.sid

    @sid.setter
    def sid(self, v):
        self.cred.sid = v

    def associate_file(self, file_obj):
        self.backing_files.update(file_obj)

    def get_node_name(self):
        return "subject:%s" % (str(self.sid.type))

    def __repr__(self):
        return "<SubjectNode %s>" % self.sid.type

    def __eq__(self, other):
        return isinstance(other, SubjectNode) and hash(self) == hash(other)

    def __hash__(self):
        return hash(self.cred) + hash(self.get_node_name())

    # __new__ instead of __init__ to establish necessary id invariant
    # You could use both __new__ and __init__, but that's usually more complicated
    # than you really need
    def __new__(cls, cred):
        self = super().__new__(cls)  # Must explicitly create the new object
        # Aside from explicit construction and return, rest of __new__
        # is same as __init__
        self.parents = set()
        self.children = set()

        self.backing_files = {}
        self.cred = cred
        return self  # __new__ returns the new object

    def __getnewargs__(self):
        # Return the arguments that *must* be passed to __new__
        return (self.cred,)

    def __getstate__(self):
        # dump a tuple instead of a set so that the __hash__ function won't be called
        return tuple([self.cred, self.parents, self.children, self.backing_files])

    def __setstate__(self, state):
        self.cred, self.parents, self.children, self.backing_files = state

class ProcessState(Enum):
    RUNNING = 1
    STOPPED = 2

class ProcessNode(GraphNode):
    def __init__(self, subject, parent, exe, pid, cred=None):
        # process state
        self.state = ProcessState.STOPPED
        self.pid = pid

        self.subject = subject

        if self.cred:
            self.cred = cred
        else:
            self.cred = Cred()
        self.parent = parent
        self.exe = exe
        self.children = set()

    @property
    def sid(self):
        return self.cred.sid

    @property
    def trusted(self):
        return self.subject.trusted

    @trusted.setter
    def trusted(self, v):
        raise ValueError("Cannot set process trust: set it on the underlying subject")

    @sid.setter
    def sid(self, v):
        self.cred.sid = v

    def get_node_name(self):
        return "process:%s_%d" % (str(self.subject.sid.type), self.pid)

    def __repr__(self):
        parent_type = self.parent.subject.sid.type if self.parent else "god"

        if self.state == ProcessState.RUNNING:
            return "<ProcessNode %s->%s %s %s RUNNING pid=%d>" % (parent_type, self.subject.sid.type, list(self.exe.keys())[0], self.cred, self.pid)
        else:
            return "<ProcessNode %s->%s %s %s>" % (parent_type, self.subject.sid.type, list(self.exe.keys())[0], self.cred)

    def __eq__(self, other):
        return isinstance(other, ProcessNode) and hash(self) == hash(other)

    def __hash__(self):
        return  hash(self.cred) + hash(self.get_node_name())

    def __new__(cls, subject, parent, exe, pid, cred=None):
        self = super().__new__(cls)  # Must explicitly create the new object
        # process state
        self.state = ProcessState.STOPPED
        self.pid = pid

        self.subject = subject

        self.cred = cred
        self.parent = parent
        self.exe = exe
        self.children = set()

        return self

    def __getnewargs__(self):
        # Return the arguments that *must* be passed to __new__
        return (self.subject, self.parent, self.exe, self.pid, self.cred,)

    #def __getstate__(self):
    #    print("save " + self.cred.sid.type)
    #    # dump a tuple instead of a set so that the __hash__ function won't be called
    #    return tuple([self.cred, self.parents, self.children, self.backing_files])

    #def __setstate__(self, state):
    #    print("load " + state[0].sid.type)
    #    self.cred, self.parents, self.children, self.backing_files = state

class SEPolicyInst(object):
    def __init__(self, filesystem, sepolicy, file_contexts, init, android_version):
        self.android_version = android_version
        self.filesystem = filesystem
        self.sepolicy = sepolicy
        self.file_contexts = file_contexts
        self.init = init
        self.file_mapping = {}

        # Mixed instantiation
        self.subjects = {}
        self.subject_groups = {}
        self.domain_attributes = []
        self.objects = {}

        # Fully instantiated graph
        self.processes = {}

    def instantiate(self, draw_graph=False, expand_obj=False, skip_fileless=False):
        """
        Recreate a running system's state from a combination of MAC and DAC policies.
            * Inflate objects into subjects (processes) if they can be executed
            * Instantiate files, IPC primitives,
            * Link subjects together through objects

        Namespaces:
         - subject
         - process
         - object
            * file
            * ipc
            * socket
        """
        log.info("Applying file contexts to VFS...")
        # All files contain all of the metadata necessary to go forward
        self.apply_file_contexts()

        log.info("Inflating subjects...")
        self.inflate_subjects()

        log.info("Generating subject type hierarchy...")
        self.recover_subject_hierarchy()

        log.info("Inflating subject dataflow graph...")
        self.inflate_graph(expand_all_objects=expand_obj, skip_fileless_subjects=skip_fileless)

        log.info("Extracting policy capability bounds to subjects...")
        self.extract_selinux_capabilities()

        log.info("Assigning conservative trust flag...")
        self.assign_trust()

        log.info("Generating a process tree...")
        self.gen_process_tree()

        #log.info("Simulating subject permissions...")
        #self.simulate_subject_permissions()

        log.info("Simulating process permissions...")
        if not self.simulate_process_permissions():
            return False

        ### Graphing

        if draw_graph:
            log.info("Building subject graph...")
            self.gen_subject_graph()

            log.info("Building process graph...")
            self.gen_process_graph()

            log.info("Creating node labels...")
            self.gen_node_labels()

        self.stats()

        log.info("Finished instantiating SEPolicy")
        return True

    def assign_trust(self):
        for name, subject in self.subjects.items():
            trusted = False
            reason = ""

            ty = subject.sid.type
            if ty in ['init', 'vold', 'ueventd', 'kernel', 'system_server']:
                trusted = True
                # https://source.android.com/security/overview/updates-resources#triaging_bugs
                reason = "in Android's TCB"

            if trusted:
                subject.trusted = True
                log.debug("Subject %s is trusted (reason: %s)", name, reason)

        for name, obj in self.objects.items():
            trusted = False
            reason = ""

            for fn, f in obj.backing_files.items():
                for magic in ['/sys/', '/dev/']:
                    if fn.startswith(magic):
                        trusted = True
                        reason = "backing file %s starts with %s" % (fn, magic)
                        break

            # revoke trust from some externally controlled sources
            for fn, fo in obj.backing_files.items():
                if "tags" not in fo:
                    fo["tags"] = set()

                if fn.startswith('/dev/'):
                    for pattern in ["*usb*", "*GS*", "*serial*"]:
                        if fnmatch(fn, pattern) or fnmatch(obj.sid.type, pattern):
                            fo["tags"] |= set(['usb'])
                            break

                    for pattern in ["*bt_*", "*bluetooth*", "*hci*"]:
                        if fnmatch(fn, pattern) or fnmatch(obj.sid.type, pattern):
                            fo["tags"] |= set(['bluetooth'])
                            break

                    for pattern in ["*nfc*"]:
                        if fnmatch(fn, pattern) or fnmatch(obj.sid.type, pattern):
                            fo["tags"] |= set(['nfc'])
                            break

                    for pattern in ["*at_*", "*atd*", "*modem*", "*mdm*", "*smd*"]:
                        if fnmatch(fn, pattern) or fnmatch(obj.sid.type, pattern):
                            fo["tags"] |= set(['modem'])
                            break

            if trusted:
                obj.trusted = True
                log.debug("Object %s is trusted (reason: %s)", name, reason)

    def get_object_node(self, edge):
        teclass = edge["teclass"]
        cls = self.sepolicy["classes"][teclass]
        node = None

        if cls["parent"]:
            base_object_type = cls["parent"]
            if base_object_type == "file":
                node = FileNode()
            elif base_object_type == "socket":
                node = IPCNode("socket")
            elif base_object_type == "ipc":
                node = IPCNode(teclass)
            elif base_object_type in ["cap", "cap2"]:
                node = SubjectNode(Cred())
        else:
            if teclass in ['drmservice', 'debuggerd', 'property_service', 'service_manager', 'hwservice_manager',
                    'binder', 'key', 'msg', 'system', 'security', 'keystore_key', 'zygote']:
                node = IPCNode(teclass)
            elif teclass in ['netif', 'peer', 'node']:
                node = IPCNode("socket")
            elif teclass in ['filesystem']:
                node = FileNode()
            elif teclass in ["cap_userns", "cap2_userns", "capability", "capability2", "fd"]:
                node = SubjectNode(Cred())
            elif teclass in ["process"]:
                node = IPCNode("process_op")
            # TODO: properly handle BPF
            elif teclass in ["bpf"]:
                node = SubjectNode(Cred())

        if node is None:
            raise ValueError("Unhandled object type %s" % teclass)

        return node

    def get_dataflow_direction(self, edge):
        # We consider binder:call and *:ioctl to be bi-directional

        # ignore fd:use for now
        # we ignore getattr as this is not security sensitive enough
        # ignore DRMservice for now (pread)

        # TODO: handle class key*
        # TODO: handle class security
        # TODO: handle class filesystem
        # TODO: handle class system
        read_types = [
            'read', 'ioctl', 'unix_read', 'search',
            'recv', 'receive', 'recv_msg',  'recvfrom', 'rawip_recv', 'tcp_recv', 'dccp_recv', 'udp_recv',
            'nlmsg_read', 'nlmsg_readpriv',
            # Android specific
            'call', # binder
            'list', # service_manager
            'find', # service_manager
        ]

        # ignore setattr for now. ignore create types
        write_types = [
            'write', 'append',
            #'ioctl',
            'add_name', 'unix_write', 'enqueue',
            'send', 'send_msg',  'sendto', 'rawip_send', 'tcp_send', 'dccp_send', 'udp_send',
            'connectto',
            'nlmsg_write',
            # Android specific
            'call', # binder
            #'transfer', # binder
            'set', # property_service
            'add', # service_manager
            'find', # service_manager - this is not necessarily a write type,
                    #but why bother finding a service if you aren't going to send a message to it?
            'ptrace',
            'transition',
        ]

        # management types
        manage_types = [
            'create', 'open'
        ]

        teclass = edge["teclass"]
        perms = edge["perms"]

        has_read = False
        has_write = False
        has_manage = False

        for perm in perms:
            if perm in write_types:
                has_write = True
            if perm in read_types:
                has_read = True
            if perm in manage_types:
                has_manage = True

        return has_read, has_write, has_manage

    def gen_file_mapping(self):
        """
        Create an index of SELinux types to filesystem objects that we know about
        from our metadata extraction. Note, not all types in the graph will have this
        available. We assume files can only have a single type for their lifetime.
        A different typed file, even with the same path, would be considered a different file.
        """
        G = self.sepolicy["graphs"]["allow"]
        self.file_mapping = {}

        # associate relevant types with known files
        for f, perm in self.filesystem.files.items():
            sid = perm["selinux"]

            # dereference alias as those nodes dont exist
            if sid.type in self.sepolicy["aliases"]:
                ty = self.sepolicy["types"][sid.type]
            else:
                ty = sid.type

            if ty not in G:
                log.warning("Unused type %s in policy", ty)
                continue

            node_ref = G[ty]

            if ty not in self.file_mapping:
                self.file_mapping[ty] = {"files": {}}

            # associate a SID (ty) with a file (f) and its (perm)issions
            self.file_mapping[ty]["files"][f] = perm

    def recover_subject_hierarchy(self):
        G = self.sepolicy["graphs"]["allow"]
        Gt = self.sepolicy["graphs"]["transition"]

        self.gen_file_mapping()

        # Now we have scattered the files to their respective SEPolicy types
        #  * We need to link domains to their underlying executables

        type_transition_classes = nx.get_edge_attributes(Gt, 'teclass')
        domain_transitions = { k:v for k,v in type_transition_classes.items() if v == "process" }

        log.info("Back-propagating %d domain transitions", len(domain_transitions))

        # Used to track which domains didn't even have a process type_transition
        has_backing_file_transition = set([])

        ## Back propagate executable files to domain
        for (parent, child, e) in domain_transitions:
            attrs = Gt[parent][child][e]
            object_type = attrs["through"]

            has_backing_file_transition |= set([child])

            if object_type not in self.file_mapping:
                # This means we didn't find any backing file for this subject on the filesystem image
                # This can mean we're missing files OR that these subjects do not have an explicitly defined
                # domain to executable file transition.
                log.debug('Nothing to back propagate %s', object_type)
                continue

            parent_obj = self.subjects[parent]
            child_obj = self.subjects[child]

            # Build the process hierarchy
            parent_obj.children |= set([child_obj])
            child_obj.parents |= set([parent_obj])

            # Map the found files to the domain
            child_obj.associate_file(self.file_mapping[object_type]["files"])

        ## Recover dyntransitions for the process tree
        for subject_name, subject in self.subjects.items():
            node = G[subject_name]

            for child in node:
                for _, edge in G[subject_name][child].items():
                    if edge["teclass"] == "process" and \
                            ("dyntransition" in edge["perms"] or "transition" in edge["perms"]) and \
                            subject_name != child:

                        # We may have already caught this during the file mapping, but that's why
                        # we're dealing with sets
                        for c in self.expand_attribute(child):
                            child_subject = self.subjects[c]
                            subject.children |= set([child_subject])
                            child_subject.parents |= set([subject])

        ## Special cases
        ##
        ##  1. init - first process created. may not have an explicit transition due to selinux loading time
        init_files = self.subjects["init"].backing_files

        if len(init_files) == 0:
            log.warn("init subject had no associated files")
            self.subjects["init"].associate_file({ "/init" : self.filesystem.files["/init"] })

        ##  2. system_server - forked from zygote, assigned fixed permissions. Runs as a platform app (java based), so no executable
        # Samsung sepolicys may lead to system_server having /system/bin/tima_dump_log as the system_server file. This is an abuse...
        system_server_files = self.subjects["system_server"].backing_files

        for fn, f in system_server_files.items():
            log.warning("system_server already has '%s' associated with it. Odd...", fn)

        # Drop any backing files as we only care about the daemon system_server, not weird dyntransitions
        self.subjects["system_server"].backing_files = {}

        ##  3. zygote - forked from init, assigned fixed permissions
        # zygote children that have no known files are likely app based. Associate app_process files with them
        zygote_files = self.subjects["zygote"].backing_files

        if len(zygote_files) == 0:
            log.error("zygote subject has no associated files")
            raise ValueError("zygote has no associated files")

        # Propagate zygote backed files to its children (zygote just forks, not execs, itself into children)
        # http://androidxref.com/8.1.0_r33/xref/frameworks/base/core/jni/com_android_internal_os_Zygote.cpp#487
        for s in self.subjects["zygote"].children:
            # Don't give zygote files to subjects that already have some
            if len(s.backing_files) == 0:
                for fn, f in zygote_files.items():
                    s.associate_file({fn:f})

        # Special case for system_server which can be transitioned to from system_server_startup
        # https://android.googlesource.com/platform/system/sepolicy/+blame/master/private/system_server_startup.te
        # Mirror backing files from system_server_startup to system_server (if any)
        if "system_server_startup" in self.subjects:
            ss = self.subjects["system_server"]
            for fn, f in self.subjects["system_server_startup"].backing_files.items():
                ss.associate_file({fn:f})

        ##  4. Final chance for file recovery (heuristic)
        no_backing_file_transitions = set(list(self.subjects)) - has_backing_file_transition

        # exclude the obvious app domain
        no_backing_file_transitions -= set(self.expand_attribute('appdomain'))

        # Okay, we have a list of domains that were clearly from dyntransitions
        # We have no mapping from them to their executable. Perform a last ditch search
        for domain in sorted(list(no_backing_file_transitions)):
            # an earlier special case found something
            if len(self.subjects[domain].backing_files) > 0:
                continue

            found_files = self.filesystem.find('*' + domain)

            if len(found_files) == 1:
                (fn, fobj), = found_files[0].items()
                log.warning("Last ditch file mapping recovery for %s found '%s' (this may be incorrect and cause further analysis to fail)", domain, fn)
                self.subjects[domain].associate_file(found_files[0])

    def extract_selinux_capabilities(self):
        G = self.sepolicy["graphs"]["allow"]

        for subject_name, subject in self.subjects.items():
            for obj_name in G[subject_name]:
                for _, edge in G[subject_name][obj_name].items():
                    if edge["teclass"] not in ["capability", "capability2"]:
                        continue

                    # it only makes sense for a domain:self to
                    # have a capability...objects dont have credentials
                    if subject_name != obj_name:
                        log.warn("Bogus SELinux edge %s AVRule (objects don't have CAP). Reason: %s (subject) -[%s]-> %s (object)",
                                edge['teclass'], subject_name, ", ".join(edge["perms"]), obj_name)
                        continue

                    for cap in edge["perms"]:
                        subject.cred.cap.add("selinux", cap)

    def gen_process_tree(self):
        """
        Take the existing subject hierarchy and fully instantiate it.
        This means expand out one of every backing file for a subject into a potential running
        process. Whether or not the process is actually running will be decided during boot
        simulation.
        """
        G = self.sepolicy["graphs"]["allow"]
        self.processes = {}

        # Start from the top of hierarchy
        kernel_subject = self.subjects["kernel"]
        init_subject = self.subjects["init"]

        visited = set()

        # Technically the kernel can have a ton of processes, but we only consider one in our graph
        self.processes["kernel_0"] = ProcessNode(kernel_subject, None, {'/kernel' : {}}, 0)

        # (parent_process, parent_exe, child_subject)
        stack = [(self.processes["kernel_0"], "/kernel", init_subject)]

        ### Propagate subject permissions by simulating fork/exec
        # Depth-first traversal

        pid = 1

        while len(stack):
            parent_process, parent_exe, child_subject = stack.pop()
            # only visit an edge on the subject graph once
            visited |= set([(parent_process.subject, parent_exe, child_subject)])

            # No backing files? Go away
            if len(child_subject.backing_files) == 0:
                continue

            # Resolve symbolic links (should this be done earlier)?
            backing_files_resolved = {}

            for fn, f in sorted(child_subject.backing_files.items()):
                link_path = f["link_path"]
                if link_path != '':
                    resolved = self.filesystem.realpath(link_path)
                    if resolved in self.filesystem.files:
                        target = self.filesystem.files[resolved]
                        backing_files_resolved.update({ link_path : target })
                else:
                    backing_files_resolved.update({ fn : f })

            for fn, f in sorted(backing_files_resolved.items()):
                fc = f["selinux"]
                exec_rule_parent = False
                exec_rule_child = False
                dyntransition = False
                transition = False

                if fc.type in G[parent_process.subject.sid.type]:
                    exec_rule_parent = "execute_no_trans" in G[parent_process.subject.sid.type][fc.type][0]
                if fc.type in G[child_subject.sid.type]:
                    exec_rule_child = "execute_no_trans" in G[child_subject.sid.type][fc.type][0]["perms"]
                if child_subject.sid.type in G[parent_process.subject.sid.type]:
                    parent_child_edge = G[parent_process.subject.sid.type][child_subject.sid.type][0]["perms"]
                    dyntransition = "dyntransition" in parent_child_edge
                    transition = "transition" in parent_child_edge

                # if only dyntransitions, child exe doesn't change, so make sure child processes respect that
                if dyntransition and not transition:
                    (fn_parent, _), = parent_process.exe.items()

                    if fn_parent != fn:
                        continue

                # Conservatively assume the parent
                new_process = ProcessNode(child_subject, parent_process, {fn : f}, pid)
                parent_process.children |= set([new_process])
                proc_id = "%s_%d" % (child_subject.sid.type, pid)

                assert proc_id not in self.processes
                self.processes[proc_id] = new_process

                pid += 1

                for child in sorted(child_subject.children, key=lambda x: str(x.sid.type)):
                    edge = (new_process, fn, child)
                    edge_query = (new_process.subject, fn, child)

                    cycle = new_process.subject == child

                    # TODO: refactor special casing to networkx.algorithms.traversal.edgedfs.edge_dfs
                    # We are _trying_ to avoid cycles while visiting every edge. This needs more work
                    if edge_query not in visited or (child.sid.type == "crash_dump" and not cycle) or child.sid.type.startswith("system_server"):
                        stack += [edge]

    def simulate_process_permissions(self):
        # Special cases for android
        kernel = self.processes["kernel_0"]
        init = self.processes["init_1"]

        ## technically the kernel is a member of all groups, but we dont care for this case
        kernel.cred.uid = kernel.cred.gid = 0
        kernel.cred.clear_groups()
        kernel.cred.cap.grant_all()
        kernel.state = ProcessState.RUNNING
        kernel.cred.sid = kernel.subject.sid

        ## init has everything too
        init.cred.uid = init.cred.gid = 0
        init.cred.sid = init.subject.sid

        # Android 7.0+ - hidepid=2 introduced
        if self.android_version[0] >= 7:
            init.cred.add_group('readproc')
        else:
            init.cred.clear_groups()

        init.cred.cap.grant_all()
        init.state = ProcessState.RUNNING

        system_server_parent = None

        for init_child in sorted(init.children, key=lambda x: x.pid):
            init_child.cred = init.cred.execve(new_sid=init_child.subject.sid)
            # Drop any supplemental groups from init
            init_child.cred.clear_groups()

            found_service = None

            for sname, service in sorted(list(self.init.services.items())):
                (fn, _), = init_child.exe.items()
                cmd = self.filesystem.realpath(service.service_args[0])

                if cmd == fn and not service.oneshot:
                    if found_service:
                        continue

                    found_service = service

            if not found_service:
                log.warn("Could not find a service definition for process %s", init_child)
                continue

            # TODO: handle disabled services
            init_child.state = ProcessState.RUNNING

            service = found_service
            log.debug("Got service definition for %s: %s", init_child, service)

            if service.cred.uid:
                init_child.cred.uid = service.cred.uid

            if service.cred.gid:
                init_child.cred.gid = service.cred.gid

            if service.cred.groups:
                for group in service.cred.groups:
                    init_child.cred.add_group(group)

            if service.cred.sid:
                if init_child.cred.sid != service.cred.sid:
                    log.warning("Service definition for %s has different sid (%s)",
                            init_child.sid.type, service.cred.sid)

            if init_child.cred.uid != 0:
                init_child.cred.cap.drop_all()

            # TODO: FILE SYSTEM CAPABILITIES!

            if len(service.cred.cap.ambient):
                log.info("Service %s has ambient capabilities %s", init_child.sid.type, service.cred.cap.ambient)
                init_child.cred.cap.drop_all()
                init_child.cred.cap.permitted = copy.deepcopy(service.cred.cap.ambient)
                init_child.cred.cap.effective = copy.deepcopy(service.cred.cap.ambient)
                init_child.cred.cap.bounding = copy.deepcopy(service.cred.cap.ambient)
                init_child.cred.cap.inherited = copy.deepcopy(service.cred.cap.ambient)
                init_child.cred.cap.ambient = copy.deepcopy(service.cred.cap.ambient)

            args = service.service_args

            # Zygote special case handling
            if "app_process" in args[0]:
                if "--start-system-server" in args:
                    if system_server_parent is not None:
                        log.error("Found multiple system_server parents!")
                        continue

                    system_server_parent = init_child
                    log.info("Primary system_server parent: %s", init_child)

        # Handle the special case of native daemons spawning additional processes (except for zygote)
        for init_child in sorted(list(init.children), key=lambda x: x.pid):
            if init_child.state == ProcessState.STOPPED and "zygote" not in init_child.subject.sid.type:
                for possible_parent in list(init.children):
                    if possible_parent.state == ProcessState.RUNNING:
                        if possible_parent.subject == init_child.subject:
                            log.warn("Reparenting %s -> %s", init_child, possible_parent)

                            possible_parent.children |= set([init_child])
                            init.children -= set([init_child])
                            init_child.parent = possible_parent

                            # refork from the new parent creds
                            init_child.cred = possible_parent.cred.execve()
                            init_child.state = ProcessState.RUNNING
                            break

        if not system_server_parent:
            log.error("Failed to identify the system_server parent")
            return False

        zygotes = sorted(list(filter(lambda x: "zygote" in x.subject.sid.type, init.children)), key=lambda x: x.pid)
        system_server_startup = list(filter(lambda x: x.subject.sid.type == "system_server_startup", system_server_parent.children))

        if len(zygotes) ==  0:
            log.error("No zygotes! This is bad")
            return False

        if system_server_parent not in zygotes:
            log.error("system_server parent zygote is not in zygote list!")
            return False

        # remove children from all zygotes with differing executables
        for zyg in zygotes:
            (z_fn, _), = zyg.exe.items()

            if system_server_parent != zyg:
                zyg.children = set(filter(lambda x: not x.subject.sid.type.startswith("system_server"), zyg.children))
                log.info("Dropping system_server from %s", zyg)

            for child in list(zyg.children):
                (fn, _), = child.exe.items()

                if fn != z_fn and "crash" not in fn:
                    zyg.children -= set([child])

        if len(system_server_startup) > 0:
            # The parent won't match as the graph looks like zygote -> system_server_startup -> system_server
            # system_server_startup is a temporary state and can be ignored
            system_server = list(filter(lambda x: x.subject.sid.type == "system_server", system_server_startup[0].children))
            log.info("system_server_startup detected, inferring system_server from this label instead of zygote directly");
        else:
            system_server = list(filter(lambda x: x.subject.sid.type == "system_server", system_server_parent.children))

        if len(system_server) == 0:
            log.error("Issue spawning system_server")
            return False
        else:
            system_server = system_server[0]

        ## system_server
        # See system server permissions: http://androidxref.com/8.1.0_r33/xref/frameworks/base/core/java/com/android/internal/os/ZygoteInit.java#646
        system_server.cred.uid = 1000
        system_server.cred.gid = 1000
        system_server.cred.sid = system_server.subject.sid

        system_server.cred.cap.bound_none()

        for cap in ['CAP_IPC_LOCK', 'CAP_KILL', 'CAP_NET_ADMIN', 'CAP_NET_BIND_SERVICE', 'CAP_NET_BROADCAST', 'CAP_NET_RAW',
                'CAP_SYS_MODULE', 'CAP_SYS_NICE', 'CAP_SYS_PTRACE', 'CAP_SYS_TIME', 'CAP_SYS_TTY_CONFIG', 'CAP_WAKE_ALARM']:
            system_server.cred.cap.add('inherited', cap)
            system_server.cred.cap.add('effective', cap)
            system_server.cred.cap.add('permitted', cap)

        for group in [1001,1002,1003,1004,1005,1006,1007,1008,1009,1010,1018,1021,1023,1032,3001,3002,3003,3006,3007,3009,3010]:
            system_server.cred.add_group(group)

        system_server.state = ProcessState.RUNNING

        ## spawn extra applications

        # spawn an untrusted app
        app_parent = system_server_parent
        untrusted_apps = list(filter(lambda x: "untrusted_app" in x.subject.sid.type, app_parent.children))
        crash_dump = list(filter(lambda x: "crash_dump" in x.subject.sid.type, app_parent.children))
        app_id = 0

        for crashes in sorted(crash_dump, key=lambda x: x.subject.sid.type):
            crashes.cred = app_parent.cred.execve(new_sid=crashes.subject.sid)
            crashes.state = ProcessState.RUNNING
            log.info("Spawned crash_dump %s from %s", repr(crashes), repr(app_parent))

        for primary_app in sorted(untrusted_apps, key=lambda x: x.subject.sid.type):
            primary_app.cred = app_parent.cred.execve(new_sid=primary_app.subject.sid)
            # Drop any supplemental groups from init
            primary_app.cred.clear_groups()
            primary_app.cred.cap.drop_all()

            primary_app.cred.uid = 10000+app_id
            primary_app.cred.gid = 10000+app_id
            primary_app.cred.add_group('inet')
            primary_app.cred.add_group('everybody')
            primary_app.cred.add_group(50000+app_id)
            primary_app.state = ProcessState.RUNNING
            log.info("Spawned untrusted_app %s from %s", repr(primary_app), repr(app_parent))
            app_id += 1

        return True

    def list_processes(self):
        proc_output = ""

        for _, proc in sorted(filter(lambda x: x[1].state == ProcessState.RUNNING, self.processes.items()),
                key=lambda x: x[1].pid):

            (exe, _), = proc.exe.items()
            sid = proc.cred.sid
            name = os.path.basename(exe)
            pid = proc.pid

            # skip the kernel contexts
            if proc.parent is None:
                continue

            ppid = proc.parent.pid

            uid = proc.cred.uid
            gid = proc.cred.gid
            groups = " ".join(sorted([str(x) for x in proc.cred.groups]))
            caps = str(proc.cred.cap)

            proc_output += """Exe:\t%s
Sid:\t%s
Name:\t%s
Pid:\t%d
PPid:\t%d
Uid:\t%d\t%d\t%d\t%d
Gid:\t%d\t%d\t%d\t%d
Groups:\t%s
%s
""" % (exe, sid, name, pid, ppid, uid, uid, uid, uid, gid, gid, gid, gid, groups, caps)

        return proc_output



    def simulate_subject_permissions(self):
        # Special cases for android
        kernel = self.subjects["kernel"]
        init = self.subjects["init"]
        system_server = self.subjects["system_server"]
        zygote = self.subjects["zygote"]
        # TODO: handle webview_zygote

        ## technically the kernel is a member of all groups, but we dont care for this case
        kernel.cred.uid = kernel.cred.gid = 0
        kernel.cred.clear_groups()
        kernel.cred.cap.grant_all()

        ## init has everything too
        init.cred.uid = init.cred.gid = 0

        # Android 7.0+ - hidepid=2 introduced
        if self.android_version[0] >= 7:
            #init.cred.add_group('readproc')
            pass
        else:
            init.cred.clear_groups()

        init.cred.cap.grant_all()

        ## system_server
        # See system server permissions: http://androidxref.com/8.1.0_r33/xref/frameworks/base/core/java/com/android/internal/os/ZygoteInit.java#646
        system_server.cred.uid = 1000
        system_server.cred.gid = 1000

        system_server.cred.cap.bound_none()

        for cap in ['CAP_IPC_LOCK', 'CAP_KILL', 'CAP_NET_ADMIN', 'CAP_NET_BIND_SERVICE', 'CAP_NET_BROADCAST', 'CAP_NET_RAW',
                'CAP_SYS_MODULE', 'CAP_SYS_NICE', 'CAP_SYS_PTRACE', 'CAP_SYS_TIME', 'CAP_SYS_TTY_CONFIG', 'CAP_WAKE_ALARM']:
            system_server.cred.cap.add('inherited', cap)
            system_server.cred.cap.add('effective', cap)
            system_server.cred.cap.add('permitted', cap)

        # XXX: this was taken by reading the source / manual extraction
        # system_server groups seem relatively stable, but we should do better here
        for group in [1001,1002,1003,1004,1005,1006,1007,1008,1009,1010,1018,1021,1023,1032,3001,3002,3003,3006,3007,3009,3010]:
            system_server.cred.add_group(group)

        ##################

        visited = set()

        # (parent, child)
        stack = [(kernel, init)]

        ### Propagate subject permissions by simulating fork/exec
        # Depth-first traversal
        while len(stack):
            parent, subject = stack.pop()
            visited |= set([subject])

            # Don't reassign credentials to special cases
            # Start by simulating an execve. Modifications can be made from here
            if subject.cred.uid is None:
                subject.cred = parent.cred.execve(new_sid=subject.sid)

            # perform a service lookup
            if parent == init:
                found_service = None
                for sname, service in self.init.services.items():
                    cmd = service.service_args[0]

                    if cmd in subject.backing_files:
                        if found_service:
                            continue

                        found_service = service

                if found_service:
                    service = found_service
                    log.debug("Got service definition for %s: %s", subject, service)

                    if service.cred.uid:
                        subject.cred.uid = service.cred.uid
                    if service.cred.gid:
                        subject.cred.gid = service.cred.gid
                    if service.cred.groups:
                        for group in service.cred.groups:
                            subject.cred.add_group(group)
                    if service.cred.sid:
                        if subject.cred.sid != service.cred.sid:
                            log.warning("Service definition for %s has different sid (%s)",
                                    subject.sid.type, service.cred.sid)
                    if len(service.cred.cap.ambient):
                        log.info("Service %s has ambient capabilities %s", subject.sid.type, service.cred.cap.ambient)

                else:
                    log.warn("Could not find a service definition for domain %s", subject)
            elif parent == zygote:
                # It depends
                # Don't reassign creds to special cases
                if subject.cred.uid is not None:
                    continue

                if subject.sid.type == "untrusted_app":
                    subject.cred.uid = 10000
                    subject.cred.gid = 10000
                    subject.cred.add_group('inet')

            for child in sorted(subject.children, key=lambda x: str(x.sid.type)):
                if child not in visited:
                    stack += [(subject, child)]

        ### Associate objects with their parent permissions
        for on, o in self.objects.items():
            ty = o.get_obj_type()
            # Nothing here for now
            pass

    def gen_process_graph(self):
        GP = nx.MultiDiGraph()

        self.sepolicy["graphs"]["process"] = GP

        visited = set()
        frontier = [self.processes["kernel_0"]]
        depth = 0

        color_base = '#ff%02x%02x'

        max_cap_count = 0
        for subject_name, subject in self.subjects.items():
            cap_count = len(subject.cred.cap.permitted)

            if cap_count > max_cap_count:
                max_cap_count = cap_count

        if max_cap_count == 0:
            cap_stride = 255
        else:
            cap_stride = 255/max_cap_count

        # BF-traversal
        while len(frontier):
            new_frontier = []

            for proc in frontier:
                visited |= set([proc])

                if proc.state != ProcessState.RUNNING:
                    continue

                node_name = proc.get_node_name()

                cap_count = len(proc.cred.cap.permitted)

                # Color based on depth from kernel
                #calc = int(min(256 - 2**(8-depth), 255))

                # Color based on how many capabilities a process has
                #calc = int(min(256 - cap_count*cap_stride, 255))
                if proc.cred.uid == 0:
                    calc = 0
                else:
                    calc = 255

                color = color_base % (calc, calc)
                GP.add_node(node_name, obj=proc, fillcolor=color)

                for child in proc.children:
                    if child.state != ProcessState.RUNNING:
                        continue

                    GP.add_node(child.get_node_name(), obj=child)
                    GP.add_edge(node_name, child.get_node_name())

                    if child not in visited:
                        new_frontier += [child]

            frontier = new_frontier
            depth += 1

    def gen_subject_graph(self):
        GP = nx.MultiDiGraph()

        self.sepolicy["graphs"]["subject"] = GP

        visited = set()
        frontier = [self.subjects["kernel"]]
        depth = 0

        color_base = '#ff%02x%02x'

        max_cap_count = 0
        for subject_name, subject in self.subjects.items():
            cap_count = len(subject.cred.cap.permitted)

            if cap_count > max_cap_count:
                max_cap_count = cap_count

        if max_cap_count == 0:
            cap_stride = 255
        else:
            cap_stride = 255/max_cap_count

        # BF-traversal
        while len(frontier):
            new_frontier = []

            for subj in frontier:
                visited |= set([subj])

                node_name = subj.get_node_name()

                cap_count = len(subj.cred.cap.permitted)

                # Color based on depth from kernel
                #calc = int(min(256 - 2**(8-depth), 255))

                # Color based on how many capabilities a process has
                #calc = int(min(256 - cap_count*cap_stride, 255))
                if len(subj.backing_files) == 0:
                    calc = 0
                else:
                    calc = 255

                color = color_base % (calc, calc)
                GP.add_node(node_name, obj=subj, fillcolor=color)

                for child in subj.children:
                    GP.add_node(child.get_node_name(), obj=child)
                    GP.add_edge(node_name, child.get_node_name())

                    if child not in visited:
                        new_frontier += [child]

            frontier = new_frontier
            depth += 1

        for _, subject in self.subjects.items():
            if subject not in visited:
                log.warn("Subject %s not in graph!", subject)

    def gen_node_labels(self):
        GS = self.sepolicy["graphs"]["dataflow"]
        GP = self.sepolicy["graphs"]["process"]
        GSUB = self.sepolicy["graphs"]["subject"]

        labels = {}
        node_objs = nx.get_node_attributes(GS, 'obj')

        for n in GS.nodes():
            obj = node_objs[n]
            ty = obj.get_obj_type()
            label = ""

            if ty == "subject":
                files = obj.backing_files

                label = "[%s]\n" % n

                for fn, f in files.items():
                    label += "%s\n" % fn
                label += "%s\n" % obj.cred
            elif ty == "file":
                pass
                #files = obj.backing_files

                #label = "[%s]\n" % n

                #for fn, f in files.items():
                #    label += "%s\n" % fn
                #label += "%s\n" % subject.cred
            elif ty == "ipc":
                label = "[%s]\n" % n
                if obj.owner:
                    label += "%s\n" % obj.owner.cred

            if label != "":
                labels[n] = label

        for n in GS.nodes():
            node_name = n.split(":")[1]

            if node_name not in self.file_mapping:
                continue

            files = self.file_mapping[node_name]["files"]

            for f in files:
                fo = self.file_mapping[node_name]["files"][f]
                cap = 0 if not fo["capabilities"] else fo["capabilities"]
                label = "%s\n%o - %s %s\ncap %016x" % (f, fo["perms"], AID_MAP[fo["user"]], AID_MAP[fo["group"]], cap)
                labels[n] = label

        nx.set_node_attributes(GS, labels, 'label')

        labels = {}
        node_objs = nx.get_node_attributes(GSUB, 'obj')

        for n in GSUB.nodes():
            subject = node_objs[n]
            node_name = n.split(":")[1]

            files = subject.backing_files

            label = "[%s]\n" % n

            for fn, f in files.items():
                label += "%s\n" % fn
                #fo = self.file_mapping[node_name]["files"][f]
                #cap = 0 if not fo["capabilities"] else fo["capabilities"]
                #label = "%s\n%o - %s %s\ncap %016x" % (f, fo["perms"], AID_MAP[fo["user"]], AID_MAP[fo["group"]], cap)
            label += "%s\n" % subject.cred

            labels[n] = label

        nx.set_node_attributes(GSUB, labels, 'label')

        labels = {}
        node_objs = nx.get_node_attributes(GP, 'obj')

        for n in GP.nodes():
            process = node_objs[n]
            node_name = n.split(":")[1]

            (fn, _), = process.exe.items()

            label = "[%s]\n" % n
            label += "%s\n" % fn
                #fo = self.file_mapping[node_name]["files"][f]
                #cap = 0 if not fo["capabilities"] else fo["capabilities"]
                #label = "%s\n%o - %s %s\ncap %016x" % (f, fo["perms"], AID_MAP[fo["user"]], AID_MAP[fo["group"]], cap)
            label += "%s\n" % process.cred

            labels[n] = label

        nx.set_node_attributes(GP, labels, 'label')

    def inflate_subjects(self):
        G = self.sepolicy["graphs"]["allow"]

        self.subjects = {}
        self.subject_groups = {}
        domain_attributes = set()

        for domain in self.sepolicy["attributes"]["domain"]:
            s = SubjectNode(Cred())
            s.sid = SELinuxContext.FromString("u:r:%s:s0" % domain)

            assert domain not in self.subjects
            self.subjects[domain] = s

            attribute_membership = self.sepolicy["types"][domain]
            assert isinstance(attribute_membership, list)

            domain_attributes |= set(attribute_membership)

        domain_attributes = sorted(list(domain_attributes))

        # Make sure not to include any attributes that have objects too!
        good = []
        for attr in domain_attributes:
            bad = False

            for domain in self.expand_attribute(attr):
                if domain not in self.subjects:
                    log.warn("Domain attribute %s is bad (reason: %s != domain)",
                            attr, domain)
                    bad = True
                    # Don't break in order to list all violations

            if attr not in G:
                bad = True
                log.warn("Domain attribute %s is bad (reason: no allow rules)", attr)

            if not bad:
                good += [attr]

        self.domain_attributes = good

        for attr in self.domain_attributes:
            s = SubjectNode(Cred())
            s.sid = SELinuxContext.FromString("u:r:%s:s0" % attr)

            assert attr not in self.subject_groups
            assert attr not in self.subjects

            self.subject_groups[attr] = s

    def flatten_subject_graph(self):
        log.info("Flattening subject graph...")

        GS = self.sepolicy["graphs"]["dataflow"]
        obj_refs = nx.get_node_attributes(GS, 'obj')
        edge_refs = nx.get_edge_attributes(GS, 'ty')

        GS_flat = GS.copy()

        # Flatten all subject groups into each domain member
        for sn, subject in self.subject_groups.items():
            in_edges = GS.in_edges(subject.get_node_name(), keys=True)
            out_edges = GS.out_edges(subject.get_node_name(), keys=True)
            member_domains = []

            for u, v, e in in_edges:
                if obj_refs[u].get_obj_type() == "subject":
                    if obj_refs[u].sid.type in self.subject_groups:
                        raise ValueError("Crap subject groups linked: %s -> %s" % (u, v))
                    member_domains += [u]

            # Copy all edges from subject_group to domain
            for member in member_domains:
                in_edges_member = list(filter(lambda x: not x[0].startswith("subject"), in_edges))
                out_edges_member = list(filter(lambda x: edge_refs[x] == 'write', out_edges))

                in_edges_member = list(map(lambda x: (x[0], member), in_edges_member))
                out_edges_member = list(map(lambda x: (member, x[1]), out_edges_member))
                GS_flat.add_edges_from(in_edges_member)
                GS_flat.add_edges_from(out_edges_member)

        # Finally delete all the subject groups
        GS_flat.remove_nodes_from(list(map(lambda x: x.get_node_name(), self.subject_groups.values())))

        """
              [SubD]                       [SubD] (w.r.t)
                ^     Split IPC Nodes     /     ^
                |     into R/W nodes     /       \
                v                       v         \  
              [IPC]         ----->   [IPCw]     [IPCr]
             ^  |  ^                    \___,----'^ 
            /   |   \                    __/\     |
           /    v    \                  /    v    |
        [SubA][SubB][SubC]           [SubA][SubB][SubC]
        """

        split_ipc_nodes = []

        for on, obj in self.objects.items():
            ot = obj.get_obj_type()
            if ot != "ipc":
                continue
            name = obj.get_node_name()  # [IPC]

            owner = obj.owner

            # nothing can be done here
            if obj.owner is None:
                split_ipc_nodes += [name]
                return

            assert obj.owner.sid is not None

            owner_name = owner.get_node_name()  # [SubD]

            if owner.sid.type in self.subject_groups:
                raise ValueError("IPC %s owner %s is a subject group!" % (obj, owner))

            if owner_name not in GS_flat:
                raise ValueError("IPC %s owner %s is missing from graph!" % (obj, owner))

            # read/write w.r.t to the owner
            self.split_node(GS_flat, name, obj, owner_name)

            split_ipc_nodes += [name]

        owner_name = "subject:kernel"
        GS_flat.add_node("subject:kernel", obj=self.subjects["kernel"])

        for on, obj in self.objects.items():
            ot = obj.get_obj_type()
            if ot != "file":
                continue

            name = obj.get_node_name()

            is_special = False
            for fn, fo in obj.backing_files.items():
                if fn.startswith("/dev/") or fn.startswith("/sys/"):
                    log.info("%s %s is special", obj, fn)
                    is_special = True
                    break

            if is_special:
                GS_flat.add_edge(owner_name, name)
                GS_flat.add_edge(name, owner_name)

                self.split_node(GS_flat, name, obj, owner_name)
                split_ipc_nodes += [name]
                obj.special = True
            else:
                obj.special = False

        # delete unsplit IPC nodes
        GS_flat.remove_nodes_from(split_ipc_nodes)

        num_edges = len(GS_flat.edges())
        edge_inflation = float(num_edges) / len(GS.edges())

        num_nodes = len(GS_flat.nodes())
        node_inflation = float(num_nodes) / len(GS.nodes())

        log.info("Flattened graph now has %d edges (%.2fx increase) and %d nodes (%.1f increase)",
                num_edges, edge_inflation, num_nodes, node_inflation)

        return GS_flat

    def split_node(self, GS_flat, name, obj, owner_name):
        # read/write w.r.t to the owner
        read_edges = GS_flat.in_edges(name)  # ([SubA], [IPC]), ([SubC], [IPC]), ([SubD], [IPC])
        write_edges = GS_flat.out_edges(name)
        r_name = name+"_r"
        w_name = name+"_w"

        GS_flat.add_node(r_name, obj=obj)
        GS_flat.add_node(w_name, obj=obj)

        nbefore = len(GS_flat.nodes())

        GS_flat.add_edge(r_name, owner_name, ty="read")

        for u, v in read_edges:
            if u != owner_name:
                GS_flat.add_edge(u, r_name, ty="write") # w.r.t U

        GS_flat.add_edge(owner_name, w_name, ty="write")

        for u, v in write_edges:
            if v != owner_name:
                GS_flat.add_edge(w_name, v, ty="read") # w.r.t V

        assert len(GS_flat.nodes()) == nbefore

    def fully_instantiate(self):
        FL = self.flatten_subject_graph()

        ### overlay the subject graph to all objects

        running_proc = list(filter(lambda x: x.state == ProcessState.RUNNING, self.processes.values()))
        #running_proc = [self.processes["init_1"]]

        log.info("Using %d/%d processes", len(running_proc), len(self.processes))

        GG = nx.DiGraph()

        obj_inst = {}

        ### fully inflate all objects
        for node in FL.nodes():
            ref = FL.nodes[node]["obj"]
            ty = ref.get_obj_type()
            node_name = node

            if ty == "subject":
                # we do this next
                pass
            elif ty == "file":
                if ref.backing_files == 0:
                    log.warning("Dropping File %s as no backing files", ref)
                    continue

                for fn, f in ref.backing_files.items():
                    if node_name not in obj_inst:
                        obj_inst[node_name] = {}

                    new_fo = FileNode()

                    new_fo.backing_files = { fn: f }
                    new_fo.uid = f["user"]
                    new_fo.gid = f["group"]
                    new_fo.sid = ref.sid

                    # XXX: hack
                    if len(f.get("tags", [])) > 0:
                        new_fo.trusted = False
                    else:
                        new_fo.trusted = ref.trusted

                    # SID is the same
                    name = "%s%s" % (node_name,
                            re.sub(r'[/\\]', '_', fn))

                    if name in obj_inst[node_name]:
                        name += "_alias"

                    assert name not in obj_inst[node_name]
                    assert name not in GG

                    obj_inst[node_name][name] = new_fo
                    GG.add_node(name, obj=new_fo)
            elif ty == "ipc":

                if not ref.owner:
                    log.warning("Dropping IPC %s as no owner at all!", ref)
                    continue

                if ref.owner.sid is None:
                    log.warning("Dropping IPC %s no owner SID!", ref)
                    continue

                # find all owner processes
                owner_proc = list(filter(lambda x: x.sid.type == ref.owner.sid.type, running_proc))

                if len(owner_proc) == 0:
                    log.warning("Dropping IPC %s as no RUNNING owners", ref)
                    continue

                for instid, op in enumerate(owner_proc):
                    if node_name not in obj_inst:
                        obj_inst[node_name] = {}

                    new_ipc = IPCNode(ref.ipc_type)
                    new_ipc.sid = op.sid
                    new_ipc.backing_files = {}
                    new_ipc.owner = op

                    # when splitting subjects, IPCs can have multiple owners
                    name = "%s_%d" % (node_name, instid)

                    assert name not in obj_inst[node_name]
                    assert name not in GG

                    GG.add_node(name, obj=new_ipc)
                    obj_inst[node_name][name] = new_ipc
            else:
                assert 0

        cnt = 0
        dropped = 0

        # okay all objects in graph PERFORM THE JOINING!!!!
        for proc in running_proc:
            node_name = proc.get_node_name()
            assert node_name not in GG
            GG.add_node(node_name, obj=proc)
            subject = proc.subject
            subject_nn = subject.get_node_name()

            if subject_nn == "subject:kernel":
                log.warning("Not fully inst. %s", subject_nn)
                continue
            if subject_nn not in FL:
                log.warning("Not fully inst. %s", subject_nn)
                continue

            FL[subject_nn]
            ie = FL.in_edges(subject_nn) # O -> S (read)
            oe = FL.out_edges(subject_nn) # S -> O (write)

            # in_edges('subject:atfwd') (file:usb_device_w, _)

            nbefore = len(GG.nodes())

            log.info("%s", proc)
            for o, s in ie:
                # object was dropped!
                if o not in obj_inst:
                    dropped += 1
                    #log.warn("%s dropped", o)
                    continue

                for subobname, subob in obj_inst[o].items():
                    cnt += 1
                    GG.add_edge(subobname, node_name, ty="read")

            for s, o in oe:
                # object was dropped!
                if o not in obj_inst:
                    dropped += 1
                    #log.warn("%s dropped", o)
                    continue

                for subobname, subob in obj_inst[o].items():
                    cnt += 1
                    GG.add_edge(node_name, subobname, ty="write")

            assert len(GG.nodes()) == nbefore

        num_edges = len(GG.edges())
        edge_inflation = float(num_edges) / len(FL.edges())

        num_nodes = len(GG.nodes())
        node_inflation = float(num_nodes) / len(FL.nodes())

        log.info("FULLY Instantiated graph now has %d edges (%.2fx increase) and %d nodes (%.1fx increase)",
                num_edges, edge_inflation, num_nodes, node_inflation)
        log.info("Dropped %d edges", dropped)

        return GG

    def inflate_graph(self, expand_all_objects=True, skip_fileless_subjects=True):
        """
        Create all possible subjects and objects from the MAC policy and link
        them in a graph based off of dataflow.
        """
        G = self.sepolicy["graphs"]["allow"]
        Gt = self.sepolicy["graphs"]["transition"]

        # Create our dataflow graph
        GS = self.sepolicy["graphs"]["dataflow"] = nx.MultiDiGraph()

        self.objects = {}

        for _, s in self.subjects.items():
            if skip_fileless_subjects and len(s.backing_files) == 0:
                continue

            GS.add_node(s.get_node_name(), obj=s, fillcolor=OBJ_COLOR_MAP['subject'])

        for attr in self.domain_attributes:
            s = self.subject_groups[attr]

            GS.add_node(s.get_node_name(), obj=s, fillcolor=OBJ_COLOR_MAP['subject_group'])

            for domain in self.expand_attribute(attr):
                if domain not in self.subjects:
                    raise ValueError("Type member %s of attribute %s not a subject!" % (domain, attr))

                if skip_fileless_subjects and len(self.subjects[domain].backing_files) == 0:
                    continue

                # add a is-a edge between the subjects as they are effectively the same
                GS.add_edge(self.subjects[domain].get_node_name(), s.get_node_name())

        # TODO: handle actions applied attributes containing domains
        #for subject_name, subject in self.subjects.items():
        for subject_name in list(self.subjects) + self.domain_attributes:
            if subject_name in self.subjects:
                subject = self.subjects[subject_name]
            else:
                subject = self.subject_groups[subject_name]

            if subject.get_node_name() not in GS:
                log.info("Skipping subject %s as it has no backing files", subject_name)
                continue

            node = G[subject_name]

            # We assume a static graph where all subjects are created already
            # Inflate all possible objects and associate DAC/MAC policies with them
            for obj_name in node:

                for _, edge in G[subject_name][obj_name].items():

                    ###### Create object
                    obj = self.get_object_node(edge)
                    df_r, df_w, df_m = self.get_dataflow_direction(edge)
                    obj_type = obj.get_obj_type()

                    # mostly ignore subject nodes as the target for other subjects
                    if obj_type == "subject":
                        if edge["teclass"] == "fd":
                            continue
                        elif edge["teclass"] == "process":
                            if subject_name != obj_name and \
                                    "ptrace" in edge["perms"]:
                                # TODO: might be interesting to trace which subjects
                                # can ptrace each other
                                pass

                            continue
                        elif edge["teclass"] == "process":
                            if subject_name != obj_name and \
                                    "ptrace" in edge["perms"]:
                                # TODO: might be interesting to trace which subjects
                                # can ptrace each other
                                pass

                            pass
                            #continue
                        # TODO:
                        elif edge["teclass"] == "bpf":
                            continue
                        # handled later
                        elif edge["teclass"] in ["capability", "capability2"]:
                            continue
                        # TODO: Android 9.0
                        elif edge["teclass"] in ["cap_userns", "cap2_userns"]:
                            continue
                        else:
                            raise ValueError("Ignoring MAC edge <%s> -[%s]-> <%s>" % (subject_name, edge["teclass"], obj_name))

                    domain_name = subject.get_node_name()

                    # Object nodes should not be attributes?
                    # Answer: it depends. We don't want edge explosion, but for certain
                    # attributes, we need to see what the deal is
                    if expand_all_objects or self.is_attribute(obj_name) and \
                            obj_type == "ipc" and ( \
                            obj.ipc_type.endswith("service_manager") or obj.ipc_type == "binder"):
                        # to handle cases like `system_server_service`
                        object_expansion = self.expand_attribute(obj_name)
                    else:
                        object_expansion = [obj_name]

                    for ty in object_expansion:
                        new_obj = copy.deepcopy(obj)
                        new_obj.sid = SELinuxContext.FromString("u:object_t:%s:s0" % ty)
                        obj_type = new_obj.get_obj_type()

                        if obj_type == "ipc":
                            if ty in self.subjects:
                                new_obj.owner = self.subjects[ty]
                            else:
                                if new_obj.ipc_type.endswith("service_manager"):
                                    found_ipc_owner = False

                                    # find all vectors to this type
                                    for source, target in G.in_edges(self.actualize(new_obj.sid.type)):
                                        for _, obj_edge in G[source][target].items():
                                            # find any that have the add permission
                                            if "add" in obj_edge["perms"]:
                                                # expand - hal_graphics_allocator_server 9.0
                                                # XXX: just take the first owner we see...
                                                source_type = self.expand_attribute(source)[0]

                                                new_obj.owner = self.subjects[source_type]

                                                found_ipc_owner = True
                                                break

                                        if found_ipc_owner:
                                            break
                                elif new_obj.ipc_type == "property_service":
                                    new_obj.owner = self.subjects["init"]

                                # TODO: handle socket:appdomain
                                # could lead to some interesting vulns

                            # seriously, there is no point in adding this if there is no owner
                            # we'd be yelling to no one
                            if not new_obj.owner:
                                continue

                            if len(new_obj.owner.backing_files) == 0 and skip_fileless_subjects:
                                assert isinstance(new_obj.owner, SubjectNode)
                                continue

                            assert new_obj.owner.sid is not None

                        # no read or write, skip (should be eliminated in pruning step)
                        #if not df_r and not df_w and not df_m:
                        if not df_r and not df_w:
                            continue

                        # associate all relevant files to this object
                        if obj_type == "file":
                            if ty in self.file_mapping:
                                for fn, fo in self.file_mapping[ty]["files"].items():
                                    new_obj.associate_file({ fn : fo })

                        obj_node_name = new_obj.get_node_name()

                        # objects may be seen more than once, hence they need unique names
                        self.objects[obj_node_name] = new_obj

                        # create object
                        GS.add_node(obj_node_name, obj=new_obj, fillcolor=OBJ_COLOR_MAP[obj_type])

                        # We assume there is no way for subjects to talk directly (except shared memory)
                        # data flow: object -> subject (read)
                        if df_r and domain_name not in GS[obj_node_name]:
                            GS.add_edge(obj_node_name, domain_name, ty="read", color='red')

                        # data flow: subject -> object (write)
                        if df_w or df_m:
                            if obj_node_name in GS[domain_name]:
                                edge_types = list(map(lambda x: x[1]['ty'], GS[domain_name][obj_node_name].items()))
                            else:
                                edge_types = []

                            if df_w and 'write' not in edge_types:
                                GS.add_edge(domain_name, obj_node_name, ty="write", color='green')
                            # XXX: disable manage flow for now
                            # if df_m and 'manage' not in edge_types:
                            #     GS.add_edge(domain_name, obj_node_name, ty="manage", color='purple')

    def stats(self):
        log.info("------- STATS --------")
        log.info("---[File Contexts Report]---")
        self.file_contexts_report()

        ############################

        log.info("---[Subject Backing File Report]---")
        subjects_without_backing_files = list(filter(lambda x: len(x[1].backing_files) == 0, self.subjects.items()))
        subjects_with_backing_files = list(filter(lambda x: len(x[1].backing_files) > 0, self.subjects.items()))
        objects_without_backing_files = list(filter(lambda x: len(x[1].backing_files) == 0, self.objects.items()))
        objects_with_backing_files = list(filter(lambda x: len(x[1].backing_files) > 0, self.objects.items()))

        log.info("STAT: Dataflow created %d subjects and %d objects with a total of %d R/W edges",
                len(self.subjects), len(self.objects),
                len(self.sepolicy["graphs"]["dataflow"].edges()))
        log.info("STAT: Recovered subject %d (%.1f%%) file mappings, but unable to do so for %d subjects",
                 len(subjects_with_backing_files),
                 float(len(subjects_with_backing_files))/len(self.subjects)*100.0,
                 len(subjects_without_backing_files))
        log.info("STAT: Recovered object %d (%.1f%%) file mappings, but unable to do so for %d objects",
                 len(objects_with_backing_files),
                 float(len(objects_without_backing_files))/len(self.objects)*100.0,
                 len(objects_without_backing_files))

        ############################

        log.info("---[IPC REPORT]---")

        # IPC Missing owner report
        missing_owner = set()
        got_owner = set()
        missing_ipc_types = {}
        ipc_type_cnt = {}

        for on, o in self.objects.items():
            if isinstance(o, IPCNode):
                ipc_type_cnt[o.ipc_type] = ipc_type_cnt.get(o.ipc_type, 0) + 1

                if not o.owner:
                    missing_owner |= set([o])
                    missing_ipc_types[o.ipc_type] = missing_ipc_types.get(o.ipc_type, 0) + 1
                else:
                    got_owner |= set([o])

        log.info("IPC Freq:")
        for ty, freq in sorted(ipc_type_cnt.items(), key=lambda x: x[1], reverse=True):
            log.info("%s - %d (%.1f%%)", ty, freq, freq/(len(got_owner)+len(missing_owner))*100.0)

        log.info("%d/%d (%.2f%%) IPCNodes are missing their owners!",
                len(missing_owner), len(got_owner), float(len(missing_owner)) / len(got_owner) * 100.0)
        for ty, freq in sorted(missing_ipc_types.items()):
            log.info("IPC type '%s' missing %d owners", ty, freq)

        log.info("------- END STATS --------")

    def path_query(self, source, target, length=None):
        G = self.sepolicy["graphs"]["allow"]

        if source in self.sepolicy["aliases"]:
            source_new = self.sepolicy["types"][source]
            print("%s is an alias of %s" % (source, source_new))
            source = source_new

        if target in self.sepolicy["aliases"]:
            target_new = self.sepolicy["types"][target]
            print("%s is an alias of %s" % (target, target_new))
            target = target_new

        source_nodes = [source]

        if source in self.sepolicy["attributes"]:
            print("%s is an attribute" % source)
        elif source in self.sepolicy["types"]:
            print("%s is a type" % source)

            for attr, types in self.sepolicy["attributes"].items():
                # add all attributes as sources, only if they appear in the access matrix
                if source in types:
                    source_nodes += [attr]
        else:
            print("%s is an invalid type" % source)
            return

        if target in self.sepolicy["attributes"]:
            print("%s is an attribute" % target)
        elif target in self.sepolicy["types"]:
            print("%s is a type" % target)
        else:
            print("%s is an invalid type" % target)
            return

        print("Path query %s -> %s" % (source, target))

        paths = []
        for src in source_nodes:
            if src in G:
                try:
                    paths += list(nx.all_shortest_paths(G, src, target))
                except nx.exception.NetworkXNoPath:
                    pass
            else:
                log.warning("Skipping %s - not used for allows", src)

        paths = sorted(paths, key=lambda x: len(x))

        #paths = nx.all_simple_paths(G, source, target, cutoff=length)
        # file[node] : type -> file_list
        files = nx.get_node_attributes(G, 'files')

        for path in paths:
            path_info = []
            edges = []

            # find all in-edges between components, except last edge, which is target
            for i, _ in enumerate(path[:-1]):
                edges += [G[path[i]][path[i+1]]]

            for c in path:
                types = [c]

                if c in self.sepolicy["attributes"]:
                    types += self.sepolicy["attributes"][c]

                # find all files associated with this type/attribute
                file_list = {}
                for ty in types:
                    if ty in files:
                        file_list.update(files[ty])

                if len(file_list) > 0:
                    if len(file_list) == 1:
                        path_info += ["%s[%s]" % (c, list(file_list)[0])]
                    else:
                        path_info += ["%s[%d]" % (c, len(file_list))]
                else:
                    path_info += ["%s" % c]

            output = ""
            # generate path info string
            for i, _ in enumerate(path[:-1]):
                output += path_info[i]
                e = edges[i]
                edge_classes = list(map(lambda v: v["teclass"], e.values()))
                output += " --[%s]-> " % (" ".join(edge_classes))

            output += path_info[i+1]

            print(output)

    def get_file_context_matches(self, filename):
        matches = []

        for fc in self.file_contexts:
            # TODO: match on directory vs. plain file, etc.
            if fc.match(filename):
                matches += [fc]

        # heuristic: choose longest string as most specific match
        return sorted(matches, reverse=True, key=lambda x: x.regex.pattern)

    def file_contexts_report(self):
        fc_found = set()
        fc_found_types = set()
        fc_missing_types = set()
        fc_prefixes = {}

        # get some qualitative data about the file_contexts in relation to the FS
        for f, perm in self.filesystem.files.items():
            matches = self.get_file_context_matches(f)

            if len(matches) <= 0:
                continue

            ty = perm["selinux"].type
            fc_found |= set(matches)
            fc_found_types |= set([ty])

        # figure out which file contexts are missing from the file system
        missing = set(self.file_contexts) - fc_found

        for fc in missing:
            # which types are missing
            fc_missing_types |= set([fc.context.type])
            prefix = fc.regex.pattern.split(os.path.sep)[1]
            if prefix not in fc_prefixes:
                fc_prefixes[prefix] = 1
            else:
                fc_prefixes[prefix] += 1

        fc_all_types = set(map(lambda x: x.context.type, self.file_contexts))

        log.info("STAT: Filesystem matched %d/%d FCs (%.2f%% are missing)",
                len(fc_found), len(self.file_contexts), len(missing)/len(self.file_contexts)*100.0)
        log.info("Here's a list of the most common filesystem prefixes that were never found")
        for f, freq in sorted(fc_prefixes.items(), key=lambda x: x[1], reverse=True):
            if freq > 1:
                log.info("/%-10s - %d" % (f, freq))

        with open('missing-fc-report.txt', 'w') as report:
            for fc in sorted(missing, key=lambda _: _.regex.pattern):
                report.write(fc.regex.pattern + " " + fc.context.type + "\n")

    def apply_file_contexts(self):
        recovered_labels = 0
        dropped_files = {}
        genfs = self.sepolicy["genfs"]
        fs_use = self.sepolicy["fs_use"]
        match_freq = {}

        # apply file_contexts to combined file system
        for f, perm in self.filesystem.files.items():
            matches = self.get_file_context_matches(f)

            for m in matches:
                if m not in match_freq:
                    match_freq[m] = 0

                match_freq[m] += 1

            # Sort by least used match to most used
            matches = sorted(matches, key=lambda x: match_freq[x])

            # attempt to apply genfs for filesystem
            if len(matches) <= 0 or f in self.filesystem.mount_points:
                import re
                genfs_matches = []

                for path, mount in self.filesystem.mount_points.items():
                    if f.startswith(path):
                        relfs = f[len(path):]
                        fstype = mount["type"]

                        if relfs == "":
                            relfs = "/"

                        if fstype in genfs:
                            fsmap = genfs[fstype]

                            for p, ctx in fsmap:
                                if re.match(r'^' + p + r'.*', relfs):
                                    genfs_matches += [[path, p, ctx]]
                        elif fstype in fs_use:
                            # XXX: hack!
                            if fstype != "tmpfs":
                                continue

                            genfs_matches += [[path, "/", fs_use[fstype]]]

                if len(genfs_matches):
                    genfs_matches = sorted(genfs_matches, reverse=True, key=lambda x: x[0])
                    primary_path = genfs_matches[0][0]
                    genfs_matches = sorted(filter(lambda x: x[0] == primary_path, genfs_matches), reverse=True, key=lambda x: x[1])
                    primary_match = SELinuxContext.FromString(genfs_matches[0][2])
                else:
                    if not perm["selinux"]:
                        log.error("Unable to assign label to %s", f)
                        dropped_files[f] = perm

                    continue
            else:
                # heuristic: choose longest string as most specific match
                primary_match = matches[0].context

            # no SELinux label found? apply one from file_contexts
            if not perm["selinux"]:
                perm["selinux"] = primary_match
                recovered_labels += 1
            else:
                if perm["selinux"] != primary_match:
                    log.warn("Context mismatch between xattr (%s) and file_context (%s) for %s. Preferring latter",
                            perm["selinux"], primary_match, f)
                    recovered_labels += 1
                    # prefer file_contexts as xattrs may be overriden by restorecon on boot
                    perm["selinux"] = primary_match

        for fn in dropped_files:
            del self.filesystem.files[fn]

        if len(dropped_files) > 0:
            log.error("Had to drop %d files due to missing SELinux context",
                   len(dropped_files))

        log.info("Recovered %d labels from file_contexts (out of %d files)",
                recovered_labels, len(self.filesystem.files))

    def expand_attribute(self, attr):
        assert isinstance(attr, str)

        if self.is_attribute(attr):
            return self.sepolicy["attributes"][attr]
        else:
            return [attr]

    def actualize(self, ty):
        """
        Transforms a type into itself and all its attributes
        """
        assert isinstance(ty, str)

        if self.is_attribute(ty):
            raise ValueError("Attributes cannot be actualized!")

        # dereference alias as those nodes dont exist
        if ty in self.sepolicy["aliases"]:
            ty = self.sepolicy["types"][ty]

        return self.sepolicy["types"][ty] + [ty]

    def is_attribute(self, attr):
        assert isinstance(attr, str)

        return attr in self.sepolicy["attributes"]
