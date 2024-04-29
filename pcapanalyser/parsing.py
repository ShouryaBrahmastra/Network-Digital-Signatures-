'''
/***
** Script:   parsing.py
** Desc:     Supporting Parsing for PCAP_Analyser to define the Digital Network Signature in the terminal itself
** Author:   The Boys 
**              (Pratham Choudhary)
**              (Shourya Gupta)
**              (Swarnadeep Karmarkar)
**              (Aditya Raj Saha)
***/
'''

# suppress PEP8 import errors due to PATH settings
# pylint: disable=E0401
"""Methods to handle the parsing of the pcap file."""
import re
from datetime import datetime

import dpkt

from pcapanalyser.utils import (get_src_dst_address, create_logger,
                                key_from_val)
from pcapanalyser.types import Conversations, Emails, Packets

protocol_ids = {}
logger = create_logger()


def parse_packets(filename: str) -> Packets:
    """Parse packets from filename.

    Arguments
    file_buffer -- the file buffer to read and parse
    """
    packets: Packets = {"raw": {}, "count": {}}
    logger.info("Parsing file: %s", filename)
    # Loop through each packet
    with open(filename, "rb") as pcap_file_buffer:
        for timestamp, pkt in dpkt.pcap.Reader(pcap_file_buffer):
            # Store the raw packet with timestamp key
            packets["raw"][timestamp] = pkt
            # Get ethernet frame & IP header
            ethernet = dpkt.ethernet.Ethernet(pkt)
            # If it's IP
            if ethernet.type == dpkt.ethernet.ETH_TYPE_IP:
                # Get header, extract protocol name. Store in protocol_ids
                ip_header = ethernet.data
                protocol_name = dpkt.ip.get_ip_proto_name(ip_header.p)
                protocol_ids[protocol_name] = ip_header.p
                # Add protocol to counter if not already otherwise increment
                if protocol_name not in packets["count"]:
                    packets["count"][protocol_name] = 0
                packets["count"][protocol_name] += 1
            # Anything other than IP (e.g ARP)
            else:
                try:
                    # Try and get the network layer name
                    network_layer_name = ethernet.get_type(
                        ethernet.type).__name__
                except KeyError:
                    # If this fails, just call it unknown
                    logger.error("Unknown or unsupported packet detected")
                    network_layer_name = "Unknown Protocol"
                # Add protocol to counter if not already otherwise increment
                protocol_ids[network_layer_name] = network_layer_name
                if network_layer_name not in packets["count"]:
                    packets["count"][network_layer_name] = 0
                packets["count"][network_layer_name] += 1
        logger.info("Finished parsing. Found %s packets",
                    (sum(packets['count'].values())))
    return packets


def get_first_last_timestamps(packets: Packets,
                              protocol: int) -> tuple[datetime, datetime] | \
                                                tuple[str, str]:
    """Get, format and return first and last timestamps.

    Arguments
    protocol -- the desired protocol
    """
    logger.info("""Finding first and last timestamps for protocol: %s""",
                (key_from_val(protocol_ids, protocol)))
    try:
        timestamps = []
        # Loop through packets, extract ethernet and IP objects
        for timestamp, pkt in packets["raw"].items():
            ethernet = dpkt.ethernet.Ethernet(pkt)
            # IP Objects use different syntax
            if ethernet.type == dpkt.ethernet.ETH_TYPE_IP:
                ip_object = ethernet.data
                if ip_object.p == protocol:
                    timestamps.append(timestamp)
            # Going off frame type
            try:
                if ethernet.get_type(ethernet.type).__name__ == protocol:
                    timestamps.append(timestamp)
            except KeyError:
                continue
        # Select and format the first and last timestamps
        first = datetime.fromtimestamp(min(timestamps)) \
            .strftime("%H:%M:%S.%f")[:-3]
        last = datetime.fromtimestamp(max(timestamps)) \
            .strftime("%H:%M:%S.%f")[:-3]
    except ValueError:
        # This will be hit when there's an unkown protocol (EG ARP)
        return ("Unable to Calculate", "Unable to Calculate")
    return (first, last)


def get_avg_packet_length(packets: Packets, protocol: int) -> float | str:
    """Get the average packet length for a given protocol.

    Arguments
    protocol -- the desired protocol
    """
    logger.info("Finding avg packet length for protocol: %s",
                (key_from_val(protocol_ids, protocol)))
    total_length = 0
    number_of_packets = 0
    # Loop through packets, extract ethernet and IP objects
    for _, pkt in packets["raw"].items():
        ethernet = dpkt.ethernet.Ethernet(pkt)
        # IP has different syntax to non-IP objects (eg ARP)
        if ethernet.type == dpkt.ethernet.ETH_TYPE_IP:
            ip_header = ethernet.data
            if ip_header.p == protocol:
                total_length += len(pkt)
                number_of_packets += 1
        # Going off frame type now (eg ARP)
        try:
            if ethernet.get_type(ethernet.type).__name__ == protocol:
                total_length += len(pkt)
                number_of_packets += 1
        except KeyError:
            continue
    try:
        average_packet_length = round(total_length / number_of_packets, 2)
    except ZeroDivisionError:
        # This will be hit when there's an unkown protocol
        return "Unable to calculate"
    return average_packet_length


def get_filenames_from_uris(packets: Packets) -> list[str]:
    """Get filenames from URI / requests."""
    uris = get_image_uris(packets)
    filenames = []
    for uri in uris:
        # Strip off path and irrelevent HTTP parameters (? mark).
        filenames.append(uri.split("/")[-1].split("?")[0])
    return filenames


def get_image_uris(packets: Packets,
                   file_extensions: list = None) -> list[str]:
    """Find all of the URIs / filenames of image files from the pcap.

    Arguments
    file_extensions -- a list of file extensions to look for.
    """
    if not file_extensions:
        file_extensions = ["jpg", "jpeg", "gif", "png", "ico"]
    logger.info("Finding image URIS with extensions %s",
                (list(file_extensions)))
    uris = []
    for _, pkt in packets["raw"].items():
        ethernet = dpkt.ethernet.Ethernet(pkt)
        if ethernet.type == dpkt.ethernet.ETH_TYPE_IP:
            ip_object = ethernet.data
            if ip_object.p == dpkt.ip.IP_PROTO_TCP:
                try:
                    http = dpkt.http.Request(ip_object.data.data)
                    uri_lower = http.uri.lower()  # Performance
                    # If URI contains extension
                    if any(extension in uri_lower for extension
                            in file_extensions):
                        uris.append(http.uri[0:45])
                except (dpkt.dpkt.NeedData, dpkt.dpkt.UnpackError):
                    # Not valid HTTP request, leave it, move onto the next.
                    pass
    return uris


def get_smtp_emails(packets: Packets, smtp_ports: list = None) -> Emails:
    """Extract emails from SMTP packets.

    Arguments
    smtp_ports -- the ports to filter by
    """
    if not smtp_ports:
        smtp_ports = [25, 465, 2525, 587]
    logger.info("Finding emails via SMTP on ports: %s",
                (list(smtp_ports)))
    emails: Emails = {"From": [], "To": []}
    to_pattern = r"TO: <[\w\._-]+@[\w\._-]+.[\w\._-]+>"
    from_pattern = r"FROM: <[\w\._-]+@[\w\._-]+.[\w\._-]+>"
    for _, pkt in packets["raw"].items():
        ethernet = dpkt.ethernet.Ethernet(pkt)
        if ethernet.type == dpkt.ethernet.ETH_TYPE_IP:
            # SMTP is TCP
            ip_object = ethernet.data
            if ip_object.p == dpkt.ip.IP_PROTO_TCP:
                src_port, dst_port = ip_object.data.sport, ip_object.data.dport
                if src_port in smtp_ports or dst_port in smtp_ports:
                    data = str(ip_object.data.data)
                    emails["From"] += [
                        x[:-1].split("<")[1] for x in re.findall(
                            from_pattern, str(data)
                        )]
                    emails["To"] += [
                        x[:-1].split("<")[1] for x in re.findall(
                            to_pattern, str(data)
                        )]
    # Convert to set and back to list, as to remove any non-unique emails
    # TypedDict in utils.py, this wont change
    emails["From"] = list(set(emails["From"]))
    emails["To"] = list(set(emails["To"]))
    return emails


def get_conversations(packets: Packets) -> Conversations:
    """Find and store unique conversations.

    Arguments
    packets -- the packets to extract conversations from

    Returns
    conversations -- dictionary with keys and values as (src, dst)
    tuple and number of packets sent respectively.
    """
    logger.info("Getting conversations")
    conversations: Conversations = {}
    for _, pkt in packets["raw"].items():
        ethernet = dpkt.ethernet.Ethernet(pkt)
        if ethernet.type == dpkt.ethernet.ETH_TYPE_IP:
            ip_object = ethernet.data
            src_dst = get_src_dst_address(ip_object)
            conversations.setdefault(src_dst, []).append(ip_object)
        else:
            conversations.setdefault(("Unable to", "Calculate"), [])
    return conversations
