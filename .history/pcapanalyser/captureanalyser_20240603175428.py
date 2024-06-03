'''
/***
** Script:   utils.py
** Desc:     Definition for CaptureAnalyser object.
*
*               Contains logic for execution of program commands, and formats
*               the results for output. This object calls functions from
*               internal sripts such as parsing and graphing.
** Author:   The Boys 
**              (Pratham Choudhary)
**              (Shourya Gupta)
**              (Swarnadeep Karmarkar)
**              (Aditya Raj Saha)
***/
'''

# suppress PEP8 import errors due to PATH settings
# pylint: disable=E0401
"""
"""
import os

from prettytable import PrettyTable

from pcapanalyser.grapher import Grapher
from pcapanalyser.utils import create_logger, key_from_val
from pcapanalyser.output import write_command_output, generate_kml
from pcapanalyser import parsing

logger = create_logger()
# Specify graph interval here
# If none is specified, a default suitable value will be calculated
GRAPH_INTERVAL = None


FUNCTION_MAP = {
    "summarise": "summarise",
    "uris": "image_uris",
    "filenames": "get_filenames_from_uris",
    "emails": "smtp_emails",
    "conversations": "conversations",
    "plength": "avg_packet_length",
    "timestamps": "first_last_timestamps",
    "kml": "create_kml",
    "graph": "draw_graph",
    "all": "execute_all_commands"
}


class CaptureAnalyser:
    """Capture Analyser object from which all functionality will be called."""

    def __init__(self, filename: str) -> None:
        """Initialise variables."""
        self.packets = parsing.parse_packets(filename)
        self.write_filename = filename
        logger.info("Beginning Analysis for %s", self.write_filename)

    def summarise(self, writefile: str) -> PrettyTable:
        """Print summary of analysis."""
        logger.info("'summary' command executed")
        output = PrettyTable()
        output.field_names = ["Protocol", "Number of Packets",
                              "First timestamp", "Last timestamp",
                              "Avg packet length"]
        total_packets = 0
        for protocol in self.packets["count"]:
            protocol_id = parsing.protocol_ids[protocol]
            number_of_packets = self.packets["count"][protocol]
            total_packets += number_of_packets
            first, last = parsing.get_first_last_timestamps(
                self.packets, protocol_id)
            avg_length = parsing.get_avg_packet_length(
                self.packets, protocol_id)
            output.add_row([protocol, number_of_packets,
                            first, last, avg_length])
        if len(output.rows) < 1:
            output = "No Supported Packets Detected"
        write_command_output(str(output), writefile)
        return output

    def image_uris(self, writefile: str) -> PrettyTable | str:
        """Format and return image URI results."""
        logger.info("'image_uris' command executed")
        image_uris = parsing.get_image_uris(self.packets)
        output = PrettyTable()
        output.field_names = ["URI"]
        for uri in image_uris:
            output.add_row([uri])
        if len(output.rows) < 1:
            output = "No image URIs detected"
        write_command_output(str(output), writefile)
        return output

    def get_filenames_from_uris(self, writefile: str) -> PrettyTable | str:
        """Format and return filenames from URI results."""
        logger.info("'get_filenames_from_uris' command executed")
        filenames = parsing.get_filenames_from_uris(self.packets)
        output = PrettyTable()
        output.field_names = ["Filename"]
        for filename in filenames:
            output.add_row([filename])
        if len(output.rows) < 1:
            output = "No filenames detected"
        write_command_output(str(output), writefile)
        return output

    def smtp_emails(self, writefile: str) -> PrettyTable | str:
        """Format and return email results."""
        logger.info("'smtp_emails' command executed")
        emails = parsing.get_smtp_emails(self.packets)
        output = PrettyTable()
        output.field_names = ["Address", "To/From"]
        for direction, addresses in emails.items():
            # Mypy known bug below, ignore
            for email in addresses:  # type: ignore[attr-defined]
                output.add_row([email, direction])
        if len(output.rows) < 1:
            output = "No emails detected"
        write_command_output(str(output), writefile)
        return output

    def conversations(self, writefile: str) -> PrettyTable:
        """Format and return conversations results."""
        logger.info("'conversations' command executed")
        conversations = parsing.get_conversations(self.packets)
        output = PrettyTable()
        output.field_names = ["Sender", "Recipient", "Packets Sent"]
        for key in sorted(conversations,
                          key=lambda k: len(conversations[k]),
                          reverse=True):
            output.add_row([key[0], key[1], len(conversations[key])])
        write_command_output(str(output), writefile)
        return output

    def avg_packet_length(self, writefile: str) -> PrettyTable:
        """Format and return average packet length for each protocol."""
        logger.info("'avg_packet_length' command executed")
        output = PrettyTable()
        output.field_names = ["Protocol", "Avg Length"]
        for protocol_id in parsing.protocol_ids.values():
            avg_length = parsing.get_avg_packet_length(self.packets,
                                                       protocol_id)
            protocol = key_from_val(parsing.protocol_ids, protocol_id)
            output.add_row([protocol, avg_length])
        write_command_output(str(output), writefile)
        return output

    def first_last_timestamps(self, writefile: str) -> PrettyTable:
        """Format and return first and last timestamps for each protocol."""
        logger.info("'first_last_timestamps' command executed")
        output = PrettyTable()
        output.field_names = ["Protocol", "First Timestamp", "Last Timestamp"]
        for protocol_id in parsing.protocol_ids.values():
            first, last = parsing.get_first_last_timestamps(self.packets,
                                                            protocol_id)
            protocol = key_from_val(parsing.protocol_ids, protocol_id)
            output.add_row([protocol, first, last])
        write_command_output(str(output), writefile)
        return output

    def draw_graph(self, writefile: str,
                   interval: float | None = GRAPH_INTERVAL) -> str:
        """Use Grapher class to plot packet data."""
        logger.info("'draw_graph' command executed")
        directory, _ = os.path.split(writefile)
        writefile = f"{directory}/graph.png"
        grapher = Grapher(self.packets, self.write_filename,
                          interval=interval, writefile=writefile)
        grapher.plot()
        return "Graphing Success"

    def create_kml(self, writefile: str) -> PrettyTable:
        """Create and provide output for KML command."""
        logger.info("'create_kml' command executed")
        result = generate_kml(self.packets)
        write_command_output(str(result), writefile)
        return result

    def execute_all_commands(self, writefile: str) -> str:
        """Execute every command."""
        for mapping in FUNCTION_MAP.values():
            if mapping != "execute_all_commands":
                print(getattr(self, mapping)(writefile))
        return "All commands executed"
