'''
/***
** Script:   output.py
** Desc:     Supporting file to open geolocation for PCAP_Analyser to define the Digital Network Signature in Google Earth
** Author:   The Boys 
**              (Pratham Choudhary)
**              (Shourya Gupta)
**              (Swarnadeep Karmarkar)
**              (Aditya Raj Saha)
***/
'''
# suppress PEP8 import errors due to PATH settings
# pylint: disable=E0401
"""Output functionality."""
import simplekml
import dpkt
import geoip2.database

from pcapanalyser.utils import hex_to_ipv4, create_logger
from pcapanalyser.types import Packets

DB_PATH = "pcapanalyser/geolitedatabase/GeoLiteCity.mmdb"

logger = create_logger()


def generate_kml(packets: Packets) -> str:
    """Generate KML file from packets."""
    logger.info("Generating KML file")
    # Find unique destination addresses and how many packets were sent to each
    dst_addresses = set()
    packets_sent_to_address: dict[str, int] = {}
    for _, pkt in packets["raw"].items():
        ethernet = dpkt.ethernet.Ethernet(pkt)
        if ethernet.type == dpkt.ethernet.ETH_TYPE_IP:
            dst_ip = hex_to_ipv4(ethernet.data.dst.hex())
            dst_addresses.add(dst_ip)
            packets_sent_to_address.setdefault(dst_ip, 0)
            packets_sent_to_address[dst_ip] += 1

    # Plot the KML
    kml = simplekml.Kml()
    with geoip2.database.Reader(DB_PATH) as reader:
        for address in dst_addresses:
            try:
                response = reader.city(address)
                country = response.country.name if response.country.name \
                    is not None else "N/A"
                city = response.city.name if response.city.name \
                    is not None else "N/A"
                kml.newpoint(name=address,
                             coords=[(response.location.longitude,
                                      response.location.latitude)],
                             description=f"""Packets Sent : \
                                {packets_sent_to_address[address]}
                                Country : {country}
                                City : {city}""")
            except geoip2.errors.AddressNotFoundError:
                # Address unknown (probably means it's private), just pass
                logger.error("KML - Found unknown address (probably private)")
    kml.save("pcapanalyser/outputs/ip_activity.kml")
    return "KML file saved to pcapanalyser/outputs/ip_activity.kml"


def write_command_output(output: str,
                         writefile: str = "pcapanalyser/outputs/results.txt"
                         ) -> None:
    """Write specified output to a given output file."""
    try:
        logger.info("Writing results to %s", writefile)
        with open(writefile, "a", encoding="utf-8") as out_file:
            out_file.write(f"{output}\n")
    except TypeError:
        logger.error("Malformed data attempted to be written to outfile")
