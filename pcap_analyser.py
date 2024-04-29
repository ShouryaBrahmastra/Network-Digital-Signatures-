'''
/***
** Script:   pcap_analyser.py
** Desc:     Script to parse a PCAP File and define the Digital Network Signature in the terminal itself
** Author:   The Boys 
**              (Pratham Choudhary) [Backend and module management and bug troubleshooter]
**              (Shourya Gupta) [GUI creator and directory manager]
**              (Swarnadeep Karmarkar) [library manager and module structure creator]
**              (Aditya Raj Saha) [Work flow diagram manager and dependency outliner]
** Note: Run setup.py before use!
***/
'''


# suppress PEP8 import errors due to PATH settings
# pylint: disable=E0401
'''
# Notes
- pcap_analyser.py and all associated scripts MUST be run with python 3.10 as they
  make use of the Type Union operator and the Type Alias annotation which was added
  with 3.10
- pylint: disable=E0401 is commented at the start of each module
  this is due to the installed packages specified in the requirements.txt
  are not always pylint compliant.
'''
"""Master script to run the packet capture analysis program."""
import argparse

from pcapanalyser.captureanalyser import CaptureAnalyser, FUNCTION_MAP
from pcapanalyser.utils import is_valid_pcap_file, create_logger


def parse_args() -> argparse.Namespace:
    """Set up argument parsing."""
    parser = argparse.ArgumentParser()
    parser.add_argument("file", help="The PCAP file to analyse",
                        type=lambda y: is_valid_pcap_file(y, parser))
    parser.add_argument("command", default="all", choices=FUNCTION_MAP.keys())
    parser.add_argument("--out", default="pcapanalyser/outputs/results.txt",
                        help="File path to write the results of the analysis")
    args = parser.parse_args()
    return args


def main(args: argparse.Namespace) -> None:
    """Create a CaptureAnalyser object and handle argument presences."""
    logger = create_logger()
    logger.info("Program Started")
    capture_analyser = CaptureAnalyser(args.file)
    # Use command from CLI input, map it to a python function and execute.
    # CaptureAnalyser.<input_command>()
    print(getattr(capture_analyser,
                  FUNCTION_MAP[args.command])(writefile=args.out))


if __name__ == "__main__":
    arguments = parse_args()
    main(arguments)
