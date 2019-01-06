#!/usr/bin/env python3
from __future__ import print_function

import argparse
import sys
import os
import logging
import json

import networkx as nx
from android.sepolicy import SELinuxContext
from networkx.readwrite import json_graph
from config import *

logging.basicConfig(stream=sys.stdout, format="%(levelname)s: %(message)s", level=logging.INFO)
log = logging.getLogger(__name__)

def main():
    print("Policy Graph to Prolog")
    print("")

    parser = argparse.ArgumentParser()
    parser.add_argument('--debug', action='store_true')

    parser.add_argument("graph_saved")
    args = parser.parse_args()

    if args.debug:
        logging.getLogger().setLevel(logging.DEBUG)

    if not os.access(args.graph_saved, os.R_OK):
        log.error("Graph file does not exist or is not readable")
        return 1

    log.info("Loading policy graph %s", args.graph_saved)

    with open(args.graph_saved, 'r') as fp:
        graph_json = json.load(fp)

    G = json_graph.node_link_graph(graph_json)

    files = nx.get_node_attributes(G, 'files')

    # Re-inflate SELinuxContext objects
    for node, attr in files.items():
        for fk, f in attr.items():
            f["selinux"] = SELinuxContext.FromString(f["selinux"])


    focus_types = ['init', 'mediaserver', 'untrusted_app', 'system_server']

    G_subgraph = nx.MultiDiGraph(G.subgraph(focus_types))

    for node in G_subgraph.nodes():
        print(node, " ---- ", G_subgraph[node])

    from IPython import embed
    embed()

    return 0

if __name__ == "__main__":
    sys.exit(main())
