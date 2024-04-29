'''
/***
** Script:   grapher.py
** Desc:     Supporting Graph packet utilities for PCAP_Analyser to define the Digital Network Signature in the terminal itself
*            Grapher object definition.
*
**           Contains logic to plot packet data over time.
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
import statistics
from datetime import datetime
import warnings

import matplotlib.pyplot as plt
import matplotlib.patches as mpatches
from matplotlib.widgets import TextBox

from pcapanalyser.utils import create_logger
from pcapanalyser.types import Packets

logger = create_logger()
warnings.filterwarnings("ignore")


class Grapher:
    """Class to handle all graphical functionality."""

    def __init__(self, packets: Packets, write_filename: str,
                 interval: float = None, writefile: str = None) -> None:
        """Initialise function for Grapher."""
        self.packets = packets
        if not interval:
            self.interval = self.calculate_suitable_interval()
        else:
            self.interval = interval
        self.writefile = writefile
        self.write_filename = write_filename

    @staticmethod
    def calculate_threshold(number_of_packets: list) -> float | bool:
        """Calculate the threshold for 'heavy traffic'.

        The threshold is calculated as the mean number of
        packets per interval + two standard deviations
        number_of_packets -- the data to calculate from
        """
        try:
            mean_per_interval = statistics.mean(number_of_packets)
            st_dev = statistics.stdev(number_of_packets)
            threshold = mean_per_interval + (2 * st_dev)
            return round(threshold, 2)
        # Usually means pcap is over too short of an amount of time
        except statistics.StatisticsError:
            logger.error("Graph - Error calculating threshold")
            return False

    def increment_interval(self,
                           current_interval: tuple) -> tuple[float, float]:
        """Increment the timestamps by the defined interval."""
        next_interval = (current_interval[0]+self.interval,
                         current_interval[1]+self.interval)
        return next_interval

    def get_starting_ending_timestamp(self) -> tuple[float, float]:
        """Extract the timestamp of the first packet."""
        timestamps = []
        for timestamp, _ in self.packets["raw"].items():
            timestamps.append(timestamp)
        return (timestamps[0], timestamps[-1])

    def calculate_suitable_interval(self) -> float:
        """Calculate a suitable interval given first and last timestamp."""
        first, last = self.get_starting_ending_timestamp()
        # "Suitable" should be 17 intervals
        return (last - first) / 17

    def generate_graph_data(self) -> tuple[list[str], list[int]]:
        """Generate the data for the graph.

        Seperates the data into Equal time intervals, and stores the
        number of packets sent during That interval. Returns a tuple
        containing a list of the last timestamps in each interval
        and the number of packets sent in that interval
        """
        logger.info("Generating graph data and plotting")
        timestamp = self.get_starting_ending_timestamp()[0]
        current_interval = (timestamp, timestamp+self.interval)
        packets = {current_interval: 0}
        for timestamp, _ in self.packets["raw"].items():
            # If new interval, increment timestamps, create new entry in dict
            if timestamp - current_interval[0] >= self.interval:
                current_interval = self.increment_interval(current_interval)
                packets.setdefault(current_interval, 0)
            # Increment number of packets sent in dict
            packets[(current_interval[0], current_interval[1])] += 1
        times = [datetime.fromtimestamp(ts[0]).strftime(
                "%H:%M:%S") for ts in packets]
        number_of_packets = list(packets.values())
        return (times, number_of_packets)

    def change_interval(self, value: str) -> None:
        """Handle changing on interval and re-drawing."""
        try:
            self.interval = float(value)
            plt.close()
            self.plot()
        except ValueError:  # User specified something other than a number
            logger.error("Graph - User Input Error")

    def plot(self) -> None:
        """Plot the data after generation."""
        times, number_of_packets = self.generate_graph_data()
        threshold = self.calculate_threshold(number_of_packets)
        if threshold:
            figure = plt.figure(f"{self.write_filename} Analysis")
            axis = figure.add_subplot()
            axis.set(title=f"""Number Of Packets Sent Over Time
                            \n{self.write_filename}""",
                     xlabel="Interval starting time",
                     ylabel="Packets Sent")
            axis.plot(times, number_of_packets, marker="o")
            axis.set_axisbelow(True)
            axis.yaxis.grid(color="gray", linestyle="dashed")
            axis.xaxis.grid(color="gray", linestyle="dashed")
            plt.xticks(rotation=90)
            plt.tick_params(axis="x", which="major", labelsize="small")
            axis.axhline(y=threshold, color="red",
                         label=f"Heavy Traffic Threshold {threshold:.2f}")
            threshold_label = mpatches.Patch(
                color="red",
                label=f"Heavy traffic threshold: {threshold:.2f}")
            interval_label = mpatches.Patch(
                color="blue",
                label=f"Interval: {self.interval:.2f}s")
            axis.legend(handles=[interval_label, threshold_label])
            change_interval_location = plt.axes([0.15, 0.02, 0.8, 0.04])
            change_interval = TextBox(change_interval_location,
                                      "Interval",
                                      initial=round(self.interval, 2))
            change_interval.on_submit(self.change_interval)
            plt.tight_layout()
            if self.writefile:
                try:
                    figure.savefig(self.writefile, bbox_inches="tight")
                except PermissionError:
                    pass
            plt.show()
        else:
            figure = plt.figure(f"{self.write_filename} Analysis Failure")
            axis = figure.add_subplot()
            axis.set(title="""ERROR IN ANALYSIS - \
                     TIME PERIOD OF PCAP FILE TOO SHORT""")
            axis.axhline(y=5, color="red",
                         label="ERROR - COULD NOT CALCULATE")
            plt.legend()
            plt.show(block=False)
