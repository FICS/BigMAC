# Copyright 2015 Fernand Lone Sang (Ge0n0sis)
#
# This file is part of SETools.
#
# SETools is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 2 of the License, or
# (at your option) any later version.
#
# SETools is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with SETools.  If not, see <http://www.gnu.org/licenses/>.
#

import setools
import networkx as nx

from setools.policyrep import terule
from setools.policyrep import exception

class SELinuxPolicyGraph(setools.SELinuxPolicy):
    """Overloaded SELinuxPolicy"""

    def build_graph(self):
        """Create a graph for querying."""
        G_allow = nx.MultiDiGraph()
        G_transition = nx.MultiDiGraph()

        sort = True

        def cond_sort(value):
            """Helper function to sort values according to the sort parameter"""
            return value if not sort else sorted(value)

        # base identifiers
        classes = {}
        attributes = {}
        commons = {}
        types = {}
        aliases = {}
        fs_use = {}
        genfs = {}

        # define type attributes
        for attribute_ in cond_sort(self.typeattributes()):
            attributes[str(attribute_)] = []

        # access vectors
        for common_ in cond_sort(self.commons()):
            commons[str(common_)] = [str(x) for x in common_.perms]

        # security object classes
        for class_ in cond_sort(self.classes()):
            try:
                parent = str(class_.common)
                commons[parent] # just ensure it exists
            except exception.NoCommon:
                parent = None

            perms = [str(x) for x in class_.perms]
            classes[str(class_)] = { "perms" : perms, "parent" : parent }

        # define types, aliases and attributes
        for type_ in cond_sort(self.types()):
            name = str(type_)

            for attr in type_.attributes():
                attributes[str(attr)] += [name]

            for alias in type_.aliases():
                types[str(alias)] = name
                aliases[str(alias)] = True

            types[name] = [str(x) for x in type_.attributes()]

        # define fs_use contexts
        for fs_use_ in cond_sort(self.fs_uses()):
            fs_use[str(fs_use_.fs)] = str(fs_use_.context)

        # define genfs contexts
        for genfscon_ in cond_sort(self.genfscons()):
            fs = genfscon_.fs

            if fs not in genfs:
                genfs[fs] = []

            genfs[fs] += [[str(genfscon_.path), str(genfscon_.context)]]

        edges_to_add = 0

        # define type enforcement rules
        for terule_ in cond_sort(self.terules()):
            # allowxperm rules
            if isinstance(terule_, terule.AVRuleXperm):
                # "{0.ruletype} {0.source} {0.target}:{0.tclass} {0.xperm_type}"
                perms = terule_.perms
            # allow/dontaudit/auditallow/neverallow rules
            elif isinstance(terule_, terule.AVRule):
                # "{0.ruletype} {0.source} {0.target}:{0.tclass}"
                perms = terule_.perms
                assert(type(perms) == set)

                if terule_.ruletype == "allow":
                    u_type = str(terule_.source)
                    v_type = str(terule_.target)


                    # make sure we're not dealing with aliases: only types and attributes
                    assert u_type not in aliases
                    assert v_type not in aliases

                    # Add an individual edge from u -> v for each perm
                    #for x in perms:
                    G_allow.add_edge(u_type, v_type, teclass=str(terule_.tclass), perms=[str(x) for x in perms])

            # type_* type enforcement rules
            elif isinstance(terule_, terule.TERule):
                # "{0.ruletype} {0.source} {0.target}:{0.tclass} {0.default}".format(terule_)
                assert terule_.ruletype == "type_transition"

                u_type = str(terule_.source)
                # technically target is not the target
                # default is the target type, whereas target is the object used to start the transition
                v_type = str(terule_.default)

                assert u_type not in aliases
                assert v_type not in aliases

                file_qualifier = None

                try:
                    file_qualifier = str(terule_.filename)
                except (exception.TERuleNoFilename, exception.RuleUseError):
                    # invalid use for type_change/member
                    pass

                G_transition.add_edge(u_type, v_type,
                                      teclass=str(terule_.tclass),
                                      through=str(terule_.target),
                                      name=file_qualifier)
            else:
                raise RuntimeError("Unhandled TE rule")

            try:
                terule_.conditional
                raise ValueError("Policy has conditional rules. Not supported for SEAndroid graphing")
            except exception.RuleNotConditional:
                pass

        policy = {
            "classes" : classes,
            "attributes" : attributes,
            "types": types,
            "aliases": aliases,
            "genfs": genfs,
            "fs_use": fs_use,
            "graphs" : {
                "allow" : G_allow,
                "transition" : G_transition
            },
        }

        return policy
