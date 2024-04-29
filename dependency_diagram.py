'''
/***
** Script:   dependency_diagram.py
** Desc:     Supporting graph for PCAP_Analyser to define the Digital Network Signature in the terminal itself
** Author:   The Boys 
**              (Pratham Choudhary)
**              (Shourya Gupta)
**              (Swarnadeep Karmarkar)
**              (Aditya Raj Saha)
***/
'''
# suppress PEP8 import errors due to PATH settings
# pylint: disable=E0401
# pylint: disable=E1101
"""Create a dependency diagram for the packet analyser."""
import os

import pyan

OUT = "pcapanalyser/outputs"


def generate_dependency_graph() -> None:
    """Create module dependency graph for pcapanalyser package."""
    # Recursively get all python project files.
    all_py_files = [os.path.join(dp, f) for dp, dn,
                    filenames in os.walk(os.getcwd()) for f in
                    filenames if os.path.splitext(f)[1] == ".py"]
    for file in all_py_files:
        print(f"Analysing {file} to create dependency diagram")
    dependency_graph = pyan.create_callgraph(
                             filenames=all_py_files,
                             colored=True, grouped=True,
                             draw_uses=True, draw_defines=False,
                             annotated=True)

    with open(f"{OUT}/dependencies.dot", "w", encoding="utf-8") as dot_file:
        dot_file.write(dependency_graph)

    os.system(f"dot -Tsvg {OUT}/dependencies.dot > {OUT}/dependencies.svg")
    print(f"Dependency digram written to {OUT}/dependencies.svg")


if __name__ == "__main__":
    generate_dependency_graph()
