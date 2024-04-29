'''
/***
** Script:   utils.py
** Desc:     Supporting Utils for PCAP_Analyser to define the Digital Network Signature in the terminal itself
** Author:   The Boys 
**              (Pratham Choudhary)
**              (Shourya Gupta)
**              (Swarnadeep Karmarkar)
**              (Aditya Raj Saha)
***/
'''

# suppress PEP8 import errors due to PATH settings
# pylint: disable=E0401
# pylint: disable=R1732
"""Utility methods for packet analyser application."""
import logging
from typing import Any
from argparse import ArgumentParser
from pathlib import Path

import dpkt


def key_from_val(d_dic: dict, value: Any) -> Any:
    """Get key from value."""
    return list(d_dic.keys())[list(d_dic.values()).index(value)]


def create_logger() -> logging.Logger:
    """Create and return a logger object."""
    logging.basicConfig(format="%(levelname)s - %(asctime)s - %(message)s",
                        datefmt="%d-%b-%y %H:%M:%S", filemode="a",
                        filename="pcapanalyser/outputs/results.txt")
    _logger = logging.getLogger(__name__)
    _logger.setLevel(logging.INFO)
    return _logger


def hex_to_ipv4(ip_hex: str) -> str:
    """Convert a string of hex characters into an ipv4 address."""
    hex_octets = [ip_hex[i:i+2] for i in range(0, len(ip_hex), 2)]
    # ['c0', 'a8'...]
    decimal_octets = [int(x, 16) for x in hex_octets]
    # int(x, 16) = base16 = hex = [192, 168...]
    ip_address = ".".join(str(x) for x in decimal_octets)
    # 192.168.....
    return ip_address


def get_src_dst_address(ip_object: dpkt.ip.IP) -> tuple[str, str]:
    """Get the source and destination IP address from a given IP header.

    Arguments
    ip -- the IP object to process
    """
    src_ip_hex, dst_ip_hex = ip_object.src.hex(), ip_object.dst.hex()
    src_ip, dst_ip = hex_to_ipv4(src_ip_hex), hex_to_ipv4(dst_ip_hex)
    return (src_ip, dst_ip)


logger = create_logger()


def validate_filename(filename: str) -> bool:
    """Validate a file name. credit to github:vortexau."""
    pathname_path = Path(filename)
    # UNIX ... and ~
    resolved = pathname_path.expanduser().resolve()
    if not resolved.is_file():
        logger.error("%s does not exist", filename)
        return False
    return True


def validate_file_format(filename: str) -> bool:
    """Validate that the file is a valid PCAP file."""
    try:
        with open(filename, "rb") as pcap_file:
            for timestamp, _ in dpkt.pcap.Reader(pcap_file):
                logger.info("Successfully read PCAP file - TS = %s",
                            timestamp)
                return True
    except ValueError:
        logger.error("Invalid PCAP file supplied")
        return False
    return False


def is_valid_pcap_file(filename: str,
                       parser: ArgumentParser) -> str | None:
    """Check if file exists, and is a valid pcap file."""
    if not validate_filename(filename):
        parser.error(f"The file {filename} does not exist")
    if not validate_file_format(filename):
        parser.error(f"The file {filename} is not a valid PCAP")
    return filename
