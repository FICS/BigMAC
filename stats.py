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
from process import determine_hardware
from util.file import directories

logging.basicConfig(stream=sys.stdout, format="%(levelname)s: %(message)s", level=logging.INFO)
log = logging.getLogger(__name__)

def main():
    print("Android Policy Inspector")
    print("")

    parser = argparse.ArgumentParser()
    parser.add_argument('--vendor', required=True)
    parser.add_argument('--debug', action='store_true')

    args = parser.parse_args()

    if args.debug:
        logging.getLogger().setLevel(logging.DEBUG)

    #if args.policy_name[-1] == "/":
    #    args.policy_name = args.policy_name[:-1]
    #args.policy_name = os.path.basename(args.policy_name)

    policy_results_dir = os.path.join(POLICY_RESULTS_DIR, args.vendor.lower())

    if not os.access(policy_results_dir, os.R_OK):
        log.error("Policy directory does not exist or is not readable")
        return 1

    policies = list(directories(policy_results_dir))

    models = {}

    log.info("Loading %d %s policies...", len(policies), args.vendor)

    for pol in policies:
        if pol[-1] == "/":
            pol = pol[:-1]
        pol = os.path.basename(pol)

        asp = AndroidSecurityPolicy(args.vendor, pol)
        aspc = ASPCodec(asp)

        try:
            asp = aspc.load(quick=True)
        except ValueError as e:
            log.debug("%s is corrupt: %s", pol, e)
            continue

        image_data = asp.get_properties()
        android_version = asp.get_android_version()
        major, minor, revision = android_version
        model = image_data["properties"]["model"]

        if args.vendor != "aosp":
            model = model[:-1]

        if model not in models:
            models[model] = []

        models[model] += [[asp, aspc, android_version]]

    if args.vendor == "aosp":
        pixel = sorted(models["Pixel"], key=lambda x: x[2][0])

        for asp, aspc, version in pixel:
            asp = aspc.load()
            image_data = asp.get_properties()
            log.info("STAT: Image summary: %s (%s)",
                    image_data["summary"], ".".join(map(str, version)))
            process(args, asp, aspc)
    elif args.vendor == "samsung":
        device = sorted(models["SM-G955"], key=lambda x: x[2][0])
        for asp, aspc, version in device:
            asp = aspc.load()
            image_data = asp.get_properties()
            log.info("STAT: Image summary: %s (%s)",
                    image_data["summary"], ".".join(map(str, version)))
            process(args, asp, aspc)
    else:
        for mn, model in models.items():
            majors = set()
            for _, _, version in model:
                majors |= set([version[0]])

            if len(majors) >= 3:
                print(mn, model)

    if args.debug:
        from IPython import embed
        oldlevel = logging.getLogger().getEffectiveLevel()
        logging.getLogger().setLevel(logging.INFO)
        embed()
        logging.getLogger().setLevel(oldlevel)

    return 0

def process(args, asp, aspc):
    android_version = asp.get_android_version()
    major, minor, revision = android_version

    try:
        # Treble handling
        if major == 8:
            file_contexts = read_file_contexts(asp.get_saved_file_path("plat_file_contexts"))
            file_contexts += read_file_contexts(asp.get_saved_file_path("nonplat_file_contexts"))
        elif major >= 9:
            file_contexts = read_file_contexts(asp.get_saved_file_path("plat_file_contexts"))
            file_contexts += read_file_contexts(asp.get_saved_file_path("vendor_file_contexts"))
        else:
            file_contexts = read_file_contexts(asp.get_saved_file_path("file_contexts"))
    except KeyError:
        return

    log.info("STAT: %d file contexts", len(file_contexts))

    primary_filesystem = asp.fs_policies[0]
    init = AndroidInit(aspc.results_dir, asp.properties, primary_filesystem)

    determine_hardware(asp, primary_filesystem, init)

    init.read_configs("/init.rc")
    init.boot_system()

    log.info("STAT: %d services", len(init.services))

    active_services = 0
    root_services = 0

    for sname, service in sorted(list(init.services.items())):
        if not service.oneshot:
            active_services += 1
            if service.cred.uid is None or service.cred.uid == 0:
                root_services +=1

    log.info("STAT: %d active", active_services)
    log.info("STAT: %d will start as root", root_services)

    log.info("STAT: %d files", len(primary_filesystem.files))

    try:
        sepolicy = None

        if "sepolicy" in asp.policy_files:
            sepolicy = asp.get_saved_file_path("sepolicy")
        elif "precompiled_sepolicy" in asp.policy_files:
            sepolicy = asp.get_saved_file_path("precompiled_sepolicy")

        if not sepolicy:
            log.error("STAT: No compiled sepolicy found. Cannot continue")
            return

        policy_graph = SELinuxPolicyGraph(sepolicy)
    except OSError:
        log.error("STAT: Unable to load SEAndroid policy file. Use --debug for more details")
        return

    log.info("Building SEPolicy graph")
    graph = policy_graph.build_graph()

    log.info("STAT: SEPolicy %d nodes and %d allow edges",
             len(graph["graphs"]["allow"].nodes()), len(graph["graphs"]["allow"].edges()))

    stats = ["attributes", "types", "genfs", "fs_use"]

    for s in stats:
        log.info("STAT: SEPolicy %s %d", s, len(graph[s]))

    log.info("STAT: SEPolicy domains %d", len(graph["attributes"]["domain"]))

    inst = SEPolicyInst(primary_filesystem, graph, file_contexts, init, android_version)
    inst.instantiate(draw_graph=False, expand_obj=True, skip_fileless=True)

    running = sorted(filter(lambda x: x[1].state == ProcessState.RUNNING, inst.processes.items()))
    log.info("STAT: Recovered processes %d", len(inst.processes))
    log.info("STAT: Recovered running processes %d", len(running))

if __name__ == "__main__":
    sys.exit(main())
