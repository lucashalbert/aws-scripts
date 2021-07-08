#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
Script to aid in validating and formating AWS CLI WAF IPSet updates
"""
__author__ = "Lucas Halbert"
__copyright__ = "Copyright 2021, www.lhalbert.xyz"
__credits__ = ["Lucas Halbert"]
__license__ = "BSD 3-Clause License"
__version__ = "0.0.1"
__maintainer__ = "Lucas Halbert"
__email__ = "contactme@lhalbert.xyz"
__status__ = "Development"
__date__ = "07/06/2021"

import ipaddress
from typing import Tuple
import argparse
import sys
import boto3


class Bcolors:
    """
    Color class for making text pop
    """
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKCYAN = '\033[96m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

# Instantiate arg parser
parser = argparse.ArgumentParser(description='WAF Allowlist Modification Arguments')

# Add arguments to be parsed
parser.add_argument('-f', '--filename',  dest='filename', type=str,
    help='Name of file containing IPs/CIDRs')
parser.add_argument('-l', '--ip-list',  dest='ip_list', type=str,
    help='Comma separated list of IPs/CIDRs')
parser.add_argument('-ii', '--ipset-id', dest='ipset_id', type=str,
    help='IP Set ID of WAF IP list')
parser.add_argument('-r', '--region', dest='region', type=str,
    help='Region that the WAF IPSet resides in')
parser.add_argument('-ct', '--change-token', dest='change_token', type=str,
    help='IPSet change token')
parser.add_argument('-n', '--dry-run', dest='dry_run', action='store_true', default=False,
    help='Toggle dry-run mode')

# Parse Arguments
args = parser.parse_args()

if (args.filename is None and args.ip_list is None) or (args.filename is not None and
    args.ip_list is not None):
    parser.error("ONE of the following arguments is required: -f/--filename or -l/--list")

if (args.ipset_id is not None and args.region is None):
    parser.error("Argument -ii/--ipset-id requires that argument -r/--region be specified")

if (args.change_token is not None and args.region is None):
    parser.error("Argument -ct/--change-token requires that argument -r/--region be specified")

if (args.region is not None and
    (args.ipset_id is None and args.change_token is None)):
    parser.error("Argument -r/--region requires that either argument -ii/--ipset-id or -ct/--change-token be specified")


# Set consume argument variables
filename = args.filename
ip_list = args.ip_list
ipset_id = args.ipset_id
region = args.region
change_token = args.change_token
dry_run = args.dry_run



def format_comma_separated_string_as_list(string: str) -> list:
    """
    Parses a comma separated string and returns a list

    :param string: string representation of a comma separated list
    :return: list of comma separated items
    """
    return "".join(string.split()).split(","), True, "successfully formatted comma separated string"



def validate_ipv4_net(network: str) -> Tuple[bool, str]:
    """
    Checks if string is a valid IPv4 network

    :param network: string representation of IPv4 network
    :return: tuple of (bool, str). (True, msg) if valid; (False, msg) if invalid
    """
    try:
        ipv4_network = ipaddress.IPv4Network(network)
    except (ipaddress.AddressValueError, ipaddress.NetmaskValueError, ValueError) as error:
        valid = False
        msg = "{}Provided string is not a valid IPv4 network: {}.{}".format(Bcolors.FAIL, error, Bcolors.ENDC)
    else:
        valid = True
        msg = "{}String is a valid IPv4 network.{}".format(Bcolors.OKGREEN, Bcolors.ENDC)

    if valid is True and ipv4_network.is_global is False:
        valid = False
        msg = "{}String is not a valid {}global{}{} IPv4 network. This network will be excluded.{}".format(Bcolors.WARNING, Bcolors.UNDERLINE, Bcolors.ENDC, Bcolors.WARNING, Bcolors.ENDC)

    return valid, msg



def validate_ipv6_net(network: str) -> Tuple[bool, str]:
    """
    Checks if string is a valid IPv6 address

    :param network: string representation of IPv6 network
    :return: tuple of (bool, str). (True, msg) if valid; (False, msg) if invalid
    """
    try:
        ipaddress.IPv6Network(network)
    except (ipaddress.AddressValueError, ipaddress.NetmaskValueError, ValueError) as error:
        valid = False
        msg = "Provided string is not a valid IPv6 network: {}.".format(error)
    else:
        valid = True
        msg = "String is a valid IPv6 network."

    return valid, msg



def convert_list_of_ipv4_octets_to_string(octets: list) -> Tuple[str, bool]:
    """
    Converts a list of IPv4 octets into an IPv4 dotted decimal address

    :param octets: list of IPv4 octets
    :return: string twork,...], True, msg) if valid; (False, msg) if invalid
    """
    if len(octets) == 4:
        return (".".join(octets)), True

    return '', False



def format_ipv4_range(network: str) -> Tuple[list, bool, str]:
    """
    Formats an IPv4 range into a list of summarized usable CIDRs

    :param network: string representation of IPv4 network range
    :return: tuple of (list, bool, str). ([IPv4Network, IPv4Network...], True, msg) if valid; ([], False, msg) if invalid
    """
    # Split Range into a starting IP and Ending IP
    ipv4_range = network.split("-")

    # Validate Starting IP in range
    try:
        start = ipaddress.ip_address(ipv4_range[0])
    except (ipaddress.AddressValueError, ipaddress.NetmaskValueError, ValueError) as error:
        msg = "{}Provided IP range starting address is not a valid IPv4 address: {}.{}".format(Bcolors.FAIL, error, Bcolors.ENDC)
        return [], False, msg

    # Validate Ending IP in range
    try:
        end = ipaddress.ip_address(ipv4_range[1])
    except (ipaddress.AddressValueError, ipaddress.NetmaskValueError, ValueError) as error:
        msg = "Provided IP range ending address is not a valid IPv4 address: {}.".format(error)
        return [], False, msg

    # Validate and summarize IP range
    try:
        range_summary = list(ipaddress.summarize_address_range(start, end))
    except (ipaddress.AddressValueError, ipaddress.NetmaskValueError, ValueError) as error:
        valid = False
        msg = "{}Provided IP range is not valid: {}.{}".format(Bcolors.FAIL, error, Bcolors.ENDC)
    else:
        valid = True
        msg = "{}Provided IP range is valid.{}".format(Bcolors.HEADER, Bcolors.ENDC)

    if valid is True:
        return range_summary, valid, msg
    return [], valid, msg



def get_ipset_elements(ipset_id: str, region: str) -> Tuple[list, bool, str]:
    """
    Retrieves all elements of a regional WAF ipset list

    :param ipset_id: string representation of the ipset id
    :param region: string representation of the region that the ipset resides within
    :return: tuple of (list, bool, str). ([IPv4Network, IPv4Network...], True, msg) if valid; ([], False, msg) if invalid
    """
    client = boto3.client('waf-regional', region_name=region)

    try:
        response = client.get_ip_set(IPSetId=ipset_id)
    except (client.exceptions.WAFInternalErrorException, client.exceptions.WAFInvalidAccountException, client.exceptions.WAFNonexistentItemException) as error:
        valid = False
        msg = "Something went wrong while retrieving WAF ipset list: {}.".format(error)
    else:
        valid = True
        msg = "Successfully retrieved WAF ipset list"

    elements = [ x["Value"] for x in response['IPSet']['IPSetDescriptors']]

    return elements, valid, msg


def exists_in_list(search_string: str, list_to_search: list) -> Tuple[bool, str]:
    """
    Tests wheather a search string exists within a specific list of elements

    :param search_string: string to search for within the list of elements
    :param list_to_search: a list of elements to search within
    :return: tuple of (bool, str). (True, msg) if exists; (False, msg) if exists
    """
    #if any(search_string in element for element in list_to_search):
    if search_string in list_to_search:
        exists = True
        msg = "The CIDR '{}' exists within the IPSet list".format(search_string)
    else:
        exists = False
        msg = "The CIDR '{}' does {}NOT{} exist within the IPSet list".format(search_string, Bcolors.WARNING, Bcolors.ENDC)
    return exists, msg



def read_contents_from_file(filename: str) -> Tuple[list, bool, str]:
    """
    Reads the contents line by line of the filename specified

    :param filename: name of file to read
    :return: list of lines read from file
    """
    try:
        # Read contents from filename
        with open(filename, "r") as file:
            contents = file.readlines()
    except EnvironmentError as error:
        status = False
        msg = "There was a problem opening the file '{}': {}".format(filename, error)
        contents = list()
    else:
        # Strip unnecessary leading and trailing whitespace from file contents
        contents = [x.strip() for x in contents]
        status = True
        msg = "Successfully opened the file '{}' for reading".format(filename)
    finally:
        return contents, status, msg



def summarize_waf_updates(entries: list) -> Tuple[str, int]:
    """
    Summarize the necessary WAF updates and generate a CLI update string

    :param entries: list of entries needed to update
    :return: tuple of (str, int). (stringified CLI update phrase, number of updates necessary)
    """
    # Create a list of WAF updates
    updates = list()

    # Generate the CLI update string
    [updates.append("Action=\"INSERT\",IPSetDescriptor=\'{{Type=\"IPV4\",Value=\"{}\"}}\'".format(entry)) for entry in entries]

    # Calculate total number of WAF updates
    num_waf_updates = len(updates)

    # Add a space between each update action phrase
    updates = " ".join(updates)

    return updates, num_waf_updates



def collect_contents():
    """
    Entrypoint for collecting contents from filename or ip-list

    :return: list of contents
    """
    # Check if filename or ip_list is set.
    if filename is None and ip_list is not None:
        contents, status, msg = format_comma_separated_string_as_list(ip_list)
    elif filename is not None and ip_list is None:
        contents, status, msg = read_contents_from_file(filename)

    # If there is a status error returned, print error and exit
    if status is False:
        print("{}".format(msg))
        sys.exit(3)

    return contents




def main():
    """
    Program main
    """
    # Define variables
    ipset_cidrs = None
    valid_entries = list()
    valid = None
    msg = ""
    msg2 = ""

    # Get elements from specific IPSet
    if ipset_id is not None and region is not None and dry_run is False:
        # Get all ipset CIDRs
        ipset_cidrs, ipset_status, msg = get_ipset_elements(ipset_id, region)
        if ipset_status is False:
            print("{}".format(msg))
            sys.exit(3)



    # Get contents from file or ip-list
    contents = collect_contents()

    # Get total number of nets provided
    total_num_nets = len(contents)

    # Loop over contents
    for content in contents:

        # Check for IPv4 Ranges
        if content.find("-") > 0:
            range_summary, range_valid, range_msg = format_ipv4_range(content)
            range_summary = [ str(x) for x in range_summary]
            #print("{0:35}: {1} - Range Summarized to: {2}".format(content, range_msg, ", ".join(range_summary)))
            print("\n{0:31}: {1} - Range Summarized to the following:".format(content, range_msg))

            # Iterate over each network in range summary
            for net in range_summary:
                # Validate network
                valid, msg = validate_ipv4_net(net)

                if valid is True:
                    # convert network string to a ipv4 ip_interface
                    net = ipaddress.ip_interface(net)

                    # If dry-run is false, check if ip exists in IPSet
                    if dry_run is False and ipset_cidrs is not None:
                        # Check if CIDR already exists in ipset
                        exists, msg2 = exists_in_list(str(net), ipset_cidrs)

                        # If the IP does not exist, append it to a list of entries
                        if exists is False:
                            valid_entries.append(str(net))
                else:
                    msg2 = ""

                # Print status of network and any relevent messages
                print("{0:31}: {1} {2}".format(str("    " + str(net)), msg, msg2))

        # Find and ignore IPv6 addresses
        elif content.find(":") > 0:
            print("{0:31}: {1}".format(content, validate_ipv6_net(content)))

        # Find remaining IPv4 addresses
        else:
            # Set net variable equal to content
            net = content

            # Validate network
            valid, msg = validate_ipv4_net(net)

            if valid is True:
                # convert network string to a ipv4 ip_interface
                net = ipaddress.ip_interface(net)

                # If dry-run is false, check if ip exists in IPSet
                if dry_run is False and ipset_cidrs is not None:
                    # Check if CIDR already exists in ipset
                    exists, msg2 = exists_in_list(str(net), ipset_cidrs)

                    # If the IP does not exist, append it to a list of entries
                    if exists is False:
                        valid_entries.append(str(net))
            else:
                msg2 = ""

            # Print status of network and any relevent messages
            #print("{0:35}: {1} {2}".format(str(net), msg, msg2))
            print("{0:31}: {1} {2}".format(str("    " + str(net)), msg, msg2))


    # Summarize all WAF updates into a single usable CLI string
    updates, num_updates = summarize_waf_updates(valid_entries)

    if ipset_cidrs is not None:
        print("\nTotal number of nets in IPSet List: {}".format(len(ipset_cidrs)))

    print("\nTotal number of nets provided: {}".format(total_num_nets))

    if dry_run is False:
        # Check if there are any updates necessary and/or if the script is in dry-run mode
        if num_updates == 0:
            print("\nNo WAF IPSet updates necessary")
            sys.exit(0)
        else:
            print("\nNumber of updates to WAF: {}".format(num_updates))

        # Check if a change-token was provided
        if change_token is None:
            print("\nChange token not specified. Request Change Token by using the following command:")
            print("\033[1;32;47maws waf-regional get-change-token --region {}\x1b[0m".format(region))

        # Print generated AWS CLI WAF update string
        print("\nUpdate WAF IP set list via the following command:")
        print("\033[1;32;47maws waf-regional update-ip-set --region us-west-2 --ip-set-id {} --change-token {} --updates {}\x1b[0m\n".format(ipset_id, change_token, updates))


if __name__ == "__main__":
    main()
