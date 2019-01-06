#!/usr/bin/env python3
from __future__ import print_function

import argparse
import sys
import os
import logging
import shutil
import json

import networkx as nx
from prolog import Prolog
from config import *
from security_policy import ASPCodec, AndroidSecurityPolicy
from android.file_contexts import read_file_contexts
from android.initrc import AndroidInit
from segraph import SELinuxPolicyGraph
from sedump import SELinuxPolicyDump
from overlay import SEPolicyInst, ProcessState

logging.basicConfig(stream=sys.stdout, format="%(levelname)s: %(message)s", level=logging.INFO)
log = logging.getLogger(__name__)

def main():
    print("BigMAC Android Policy Processor")
    print(" by Grant Hernandez (https://hernan.de/z)")
    print("")

    parser = argparse.ArgumentParser()
    parser.add_argument('--vendor', required=True)
    parser.add_argument("policy_name")

    parser.add_argument('--debug', action='store_true', help="Enable debug logging.")

    parser.add_argument('--debug-init', action='store_true', help="Drop into an IPython shell after simulating the boot process.")
    parser.add_argument('--skip-boot', action='store_true', help="Don't simulate the boot process.")

    parser.add_argument('--draw-graph', action='store_true')
    parser.add_argument('--focus-set')

    parser.add_argument('--save', action='store_true', help="Save the instantiated policy graph.")
    parser.add_argument('--load', action='store_true', help="Reload the saved instantiated policy graph.")
    parser.add_argument('--save-policy', action='store_true', help="Generate selinux.txt for debugging.")
    parser.add_argument('--list-objects', action='store_true')

    parser.add_argument('--dont-expand-objects', action='store_true')
    parser.add_argument('--prolog', action='store_true', help="Compile Prolog helpers and start the query engine")

    args = parser.parse_args()

    if args.load and args.save:
        log.info("--load and --save are exclusive options")
        return 1

    if args.debug:
        logging.getLogger().setLevel(logging.DEBUG)

    if args.policy_name[-1] == "/":
        args.policy_name = args.policy_name[:-1]
    args.policy_name = os.path.basename(args.policy_name)

    policy_results_dir = os.path.join(POLICY_RESULTS_DIR, args.vendor.lower(), args.policy_name)

    if not os.access(policy_results_dir, os.R_OK):
        log.error("Policy directory does not exist or is not readable")
        return 1

    log.info("Loading android security policy %s (%s)", args.policy_name, args.vendor)

    asp = AndroidSecurityPolicy(args.vendor, args.policy_name)
    aspc = ASPCodec(asp)

    try:
        asp = aspc.load()
    except ValueError as e:
        log.error("Saved policy is corrupt: %s", e)
        return 1

    android_version = asp.get_android_version()
    major, minor, revision = android_version
    log.info("Image summary: %s", asp.get_properties()["summary"])

    # Treble handling
    if major == 8:
        file_contexts = read_file_contexts(asp.get_saved_file_path("plat_file_contexts"))
        file_contexts += read_file_contexts(asp.get_saved_file_path("nonplat_file_contexts"))
    elif major >= 9:
        file_contexts = read_file_contexts(asp.get_saved_file_path("plat_file_contexts"))
        file_contexts += read_file_contexts(asp.get_saved_file_path("vendor_file_contexts"))
    else:
        file_contexts = read_file_contexts(asp.get_saved_file_path("file_contexts"))

    log.info("Loaded %d file contexts", len(file_contexts))
    primary_filesystem = asp.fs_policies[0]

    if args.load:
        try:
            inst = aspc._load_db("inst")
        except ValueError as e:
            log.error("Unable to load saved instantiation: %s", e)
            return 1
    else:
        inst = main_process(args, asp, aspc, file_contexts, primary_filesystem,
                android_version)

    if inst is None:
        return

    if args.debug:
        from IPython import embed
        oldlevel = logging.getLogger().getEffectiveLevel()
        logging.getLogger().setLevel(logging.INFO)
        embed()
        logging.getLogger().setLevel(oldlevel)

    if args.list_objects:
        output_filename = '%s-files.txt' % (args.policy_name.replace("..", "_").replace(os.sep, ""))
        log.info("Saving file list to %s", output_filename)

        with open(output_filename, 'w') as fp:
            fp.write(primary_filesystem.list_path("*"))

        output_filename = '%s-processes.txt' % (args.policy_name.replace("..", "_").replace(os.sep, ""))
        log.info("Saving process list to %s", output_filename)

        with open(output_filename, 'w') as fp:
            fp.write(inst.list_processes())

    if args.prolog:
        G = inst.fully_instantiate()

        pl = Prolog(G, aspc.db_dir, inst, asp)

        if pl.compile_all():
            pl.interact()

    if args.draw_graph:
        GDF = graph["graphs"]["dataflow"]
        GP = graph["graphs"]["process"]
        GSUB = graph["graphs"]["subject"]

        focus_set = set()
        if args.focus_set:
            focus_names = args.focus_set.split(",")
            focus_set = set(focus_names)

        plot(GDF, "dataflow.svg", prune=True, debug=False, focus_set=focus_set)
        plot(GP, "process.svg", debug=False)
        plot(GSUB, "subject.svg", debug=False)

    return 0

def determine_hardware(asp, primary_filesystem, init):
    rohw = 'ro.hardware'
    if rohw not in asp.properties:
        import re
        for pattern, regex in [
                ("*uevent*rc", r'.*ueventd\.([-_a-zA-Z0-9]+)\.rc'),
                ("*fstab.*", r'.*fstab\.([-_a-zA-Z0-9]+)'),]:

            results = primary_filesystem.find(pattern)
            for result in results:
                (fn, _), = result.items()

                match = re.match(regex, fn)

                if match:
                    ro_hardware_guess = match.group(1)
                    asp.properties[rohw] = ro_hardware_guess
                    break

        if not ro_hardware_guess:
            # TODO: we need to get this from the kernel cmdline during extraction
            # For now, take some educated guesses
            # See: https://stackoverflow.com/a/20574345
            for path in ["/init.${ro.hardware}.rc"]:
                for hw in ['qcom', 'msm8996_core', 'h1', asp.properties.get_default('ro.build.product')]:
                    asp.properties[rohw] = hw
                    rc_path = init._init_rel_path(init.expand_properties(path))

                    if os.access(rc_path, os.R_OK):
                        ro_hardware_guess = hw
                        break

                    if not ro_hardware_guess:
                        del asp.properties.prop[rohw]

    ro_hardware_guess = None

    if ro_hardware_guess:
        log.info("Guessing that ro.hardware = %s", asp.properties['ro.hardware'])
        asp.properties[rohw] = ro_hardware_guess

def main_process(args, asp, aspc, file_contexts, primary_filesystem, android_version):
    init = AndroidInit(aspc.results_dir, asp.properties, primary_filesystem)

    determine_hardware(asp, primary_filesystem, init)

    init.read_configs("/init.rc")

    if not args.skip_boot:
        init.boot_system()

    if args.debug_init:
        from IPython import embed
        oldlevel = logging.getLogger().getEffectiveLevel()
        logging.getLogger().setLevel(logging.INFO)
        embed()
        logging.getLogger().setLevel(oldlevel)

    ################################
    # Parse SEPolicy file
    ################################

    try:
        sepolicy = None

        if "sepolicy" in asp.policy_files:
            sepolicy = asp.get_saved_file_path("sepolicy")
        elif "precompiled_sepolicy" in asp.policy_files:
            sepolicy = asp.get_saved_file_path("precompiled_sepolicy")

        if not sepolicy:
            log.error("No compiled sepolicy found. Cannot continue")
            return 1

        if args.save_policy:
            policy = SELinuxPolicyDump(sepolicy)
            log.info("Saving sepolicy.txt")
            policy_fp = open(os.path.join(aspc.results_dir, "sepolicy.txt"), 'w')
            policy_fp.write(str(policy))
            policy_fp.close()

        policy_graph = SELinuxPolicyGraph(sepolicy)
    except OSError:
        log.error("Unable to load SEAndroid policy file. Use --debug for more details")
        return 1

    log.info("Building SEPolicy graph")
    graph = policy_graph.build_graph()

    log.info("Created SEPolicy graph with %d nodes and %d edges",
             len(graph["graphs"]["allow"].nodes()), len(graph["graphs"]["allow"].edges()))

    log.info("Overlaying policy to filesystems")

    # Overlay DAC/filesystem data to the SEAndroid policy
    inst = SEPolicyInst(primary_filesystem, graph, file_contexts, init, android_version)
    result = inst.instantiate(draw_graph=args.draw_graph,
            expand_obj=not args.dont_expand_objects, skip_fileless=True)

    if not result:
        log.error("Unable to instantiate the SEPolicy")
        return None

    if args.save:
        #inst.subjects = None
        #inst.processes = None
        #inst.objects = None
        #inst.subject_groups = None
        #inst.domain_attributes = None
        #inst.android_version = None
        #inst.filesystem = None
        #inst.sepolicy = None
        #inst.file_contexts = None
        #inst.init = None
        #inst.file_mapping = {}
        aspc._save_db(inst, "inst")

    return inst

def make_cute(G, show_labels=True):
    import math
    font_size = 12

    nx.set_node_attributes(G, 'true', 'fixedsize')
    nx.set_node_attributes(G, '0.1', 'width')
    nx.set_node_attributes(G, '0.1', 'height')
    nx.set_node_attributes(G, '%d' % font_size, 'fontsize')

    labels = nx.get_node_attributes(G, 'label')

    widths = {}
    heights = {}
    edge_count = {}
    labels = {}
    fontsizes = {}

    max_edge_count = 0
    max_w = 0.5
    max_h = 0.5
    min_w = 0.1
    min_h = 0.1

    for n in G.nodes():
        count = len(G[n])
        edge_count[n] = count

        if count > max_edge_count:
            max_edge_count = count

    log.info("Cutify - Max edge count: %d", max_edge_count)

    for n, count in edge_count.items():
        w = (max_w-min_w)*(float(count)/max_edge_count) + min_w
        widths[n] = "%.2f" % (w)
        heights[n] = "%.2f" % ((max_h-min_h)*(float(count)/max_edge_count) + min_h)

        node_name = labels[n] if n in labels and n != "" else n
        max_font = 2.0*w/(0.013889*len(node_name))
        math.floor(max_font)

        if max_font < 8.0 or not show_labels:
            labels[n] = ''
        else:
            labels[n] = node_name
            fontsizes[n] = "%.2f" % max_font

    nx.set_node_attributes(G, widths, 'width')
    nx.set_node_attributes(G, heights, 'height')
    nx.set_node_attributes(G, labels, 'label')
    nx.set_node_attributes(G, fontsizes, 'fontsize')

def plot(G, name, prune=False, debug=False, focus_set=set(), edge_limit=None):
    import networkx as nx

    # NetworkX has a relationship with pygraphviz's AGraph
    # This is a wrapper around graphviz (binary/library)
    # The python graphviz library is separate
    import pygraphviz

    remove_edges = False

    nx.set_node_attributes(G, 'filled,solid', 'style')

    if prune:
        while True:
            to_remove = []
            for n in G.nodes():
                if n.startswith("process") or n.startswith("subject"):
                    continue

                ie = set(map(lambda x: x[0], list(G.in_edges(n))))
                oe = set(map(lambda x: x[1], list(G.out_edges(n))))
                total = len(ie | oe)

                if total <= 1:
                    to_remove += [n]

            if len(to_remove) == 0:
                break

            log.info("Removing %d unconnected nodes", len(to_remove))
            list(map(G.remove_node, to_remove))

    if len(focus_set):
        to_keep = []

        for center_node in sorted(list(focus_set)):
            node_focus = set([center_node])
            node_focus |= set(map(lambda x: x[0], list(G.in_edges(center_node))))
            node_focus |= set(map(lambda x: x[1], list(G.out_edges(center_node))))

            for node in list(node_focus):
                if node != center_node and (node.startswith("process") or node.startswith("subject")):
                    node_focus |= set(map(lambda x: x[1], list(G.out_edges(node))))

            to_keep += [node_focus]

        from functools import reduce
        if len(to_keep) == 2:
            nodes_to_keep = (to_keep[0] & to_keep[1]) | focus_set
        else:
            nodes_to_keep = reduce(lambda x,y: x | y, to_keep)

        G = G.subgraph(list(nodes_to_keep))

    log.info("Drawing graph with %d nodes and %d edges" % (len(G.nodes()), len(G.edges())))

    if edge_limit is not None and len(G.edges()) >= edge_limit:
        remove_edges = True

    if remove_edges:
        AG = nx.nx_agraph.to_agraph(nx.create_empty_copy(G))
        log.warning("Way too many edges! Dropping all of them")
    else:
        AG = nx.nx_agraph.to_agraph(G)

    if debug:
        from IPython import embed
        oldlevel = logging.getLogger().getEffectiveLevel()
        logging.getLogger().setLevel(logging.INFO)
        embed()
        logging.getLogger().setLevel(oldlevel)

    log.info("Layout + SVG drawing")

    # The SFDP program is extremely good at large graphs
    AG.layout(prog='sfdp')

    AG.draw(name, prog="sfdp", format='svg', args='-Gsmoothing=rng -Goverlap=prism2000 -Goutputorder=edgesfirst -Gsep=+2')

    #make_cute(G, show_labels=False)
    #AG = nx.nx_agraph.to_agraph(G)
    #AG.layout(prog='sfdp')
    #AG.draw('test2.svg', prog="sfdp", format='svg', args='-Gsmoothing=rng -Goverlap=prism2000 -Goutputorder=edgesfirst -Gsep=+2')

    #open('test.dot', 'w').write(AG.to_string())

    #from subprocess import Popen
    #p = Popen(['mingle', '-v', 'test.dot', '-o', 'wow.dot'])
    #p.communicate()

    #ag2 = pygraphviz.AGraph('wow.dot')
    #ag2.draw('test2.svg', prog='neato', format='svg', args='-Goverlap=false -Goutputorder=edgesfirst -n2')

if __name__ == "__main__":
    sys.exit(main())
