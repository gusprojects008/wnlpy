import socket
import struct
import os
import sys
import random
import time
from parser_netlink_route import parser_rtm_getlink
from parser_nl80211 import (kernel_response_parser, parser_ctrl_attr_mcast_groups, parser_nlattrs_netlink_families)
from linux_subsystems_constants import *
from util_internal_functions import freq_converter

def nlmsghdr_header(nlmsg_len, nlmsg_type, nlmsg_flag, seq, pid, msg):
    nlmsghdr = struct.pack("<IHHII", nlmsg_len, nlmsg_type, nlmsg_flag, seq, pid) + msg
    return nlmsghdr

def genlmsghdr_header(cmd, version, reserved):
    genlmsghdr = struct.pack("<BBH", cmd, version, reserved)
    return genlmsghdr

def netlink_attr(nla_type, nla_data):
    data_length = (len(nla_data) + 3) & ~3 # rounded to multiple of 4.
    padding = b"\x00" * (data_length - len(nla_data)) # gets the padding value needed if the data_length is not yet a multiple of 4 or if there are bytes left over.
    nlattr = struct.pack("<HH", data_length + struct.calcsize("<HH"), nla_type) + nla_data + padding
    return nlattr

def send_nlmsg(sock, nlmsg_type, nlmsg_flag, seq, pid, msg): # Send netlink message
    nlmsg_len = struct.calcsize("<IHHII") + len(msg)
    sock.send(nlmsghdr_header(nlmsg_len, nlmsg_type, nlmsg_flag, seq, pid, msg))


def recv_nlmsg(sock):
    kernel_response = bytearray() # raw data
    while True:
          buf = sock.recv(65536) 
          kernel_response += buf
          offset = 0 
          while offset < len(kernel_response):
                nlmsg_len, nlmsg_type, nlmsg_flags, nlmsg_seq, nlmsg_pid = struct.unpack_from("<IHHII", kernel_response, offset)
                if nlmsg_type == NLMSG_DONE:
                   return kernel_response

                   # nlmsgerr handler
                elif nlmsg_type == NLMSG_ERROR:
                     error, orig_len = struct.unpack_from("<iI", kernel_response, offset + struct.calcsize("<IHHII"))
                     if error == 0:
                        print("Success! Netlink message ACK")
                        sys.exit(0)
                     else:
                         print("NLMSG_ERROR!!! verify permissions or device );")
                         raise OSError(-error, os.strerror(-error))

                         sys.exit(1) 
                offset += (nlmsg_len + 3) & ~3

def rtm_getlink(sock, seq, pid): # Get link informations interfaces
    def rtm_ifinfomsg(ifi_family, ifi_padding, ifi_type, ifi_index, ifi_flags, ifi_change):
        return struct.pack("<BBHiHH", ifi_family, ifi_padding, ifi_type, ifi_index, ifi_flags, ifi_change)

    msg = rtm_ifinfomsg(0, 0, 0, 0, 0, 0)

    send_nlmsg(sock, RTM_GETLINK, NLM_F_REQUEST | NLM_F_DUMP, seq, pid, msg)
    
def get_netlink_families(sock, seq, pid):
    msg = (genlmsghdr_header(CTRL_CMD_GETFAMILY, genlmsghdr_version, genlmsghdr_reserved) + netlink_attr(CTRL_ATTR_FAMILY_NAME, NL80211_GENL_NAME))

    send_nlmsg(sock, NETLINK_GENERIC, NLM_F_REQUEST | NLM_F_DUMP, seq, pid, msg)

    kernel_response = recv_nlmsg(sock)
    kernel_response_parsed = kernel_response_parser(kernel_response, 0)

    return kernel_response_parsed

def nl80211_trigger_scan(sock, NL80211_FAMILY_ID, seq, pid, ifindex):
    msg = (genlmsghdr_header(NL80211_CMD_TRIGGER_SCAN, genlmsghdr_version, genlmsghdr_reserved) + netlink_attr(NL80211_ATTR_IFINDEX, ifindex) + netlink_attr(NL80211_ATTR_SCAN_SSIDS, b"") + netlink_attr(NL80211_ATTR_SCAN_FLAGS, struct.pack("<I", 1 << 1)))
    send_nlmsg(sock, NL80211_FAMILY_ID, NLM_F_REQUEST, seq, pid, msg)

def nl80211_get_scan(sock, NL80211_FAMILY_ID, seq, pid, ifindex):
    msg = (genlmsghdr_header(NL80211_CMD_GET_SCAN, genlmsghdr_version, genlmsghdr_reserved) + netlink_attr(NL80211_ATTR_IFINDEX, ifindex))
    send_nlmsg(sock, NL80211_FAMILY_ID, NLM_F_REQUEST | NLM_F_DUMP, seq, pid, msg) 

def scan_process_analyzer(sock, NL80211_FAMILY_ID, seq, pid, ifindex):
    kernel_response = bytearray()
    offset = 0
    
    while True:
          buffer_data = sock.recv(65536)
          kernel_response += buffer_data
          while offset < len(kernel_response):
                nlmsg_len, nlmsg_type, nlmsg_flags, nlmsg_seq, nlmsg_pid, genlmsg_cmd, genlmsg_version, genlmsg_reserved = struct.unpack_from("<IHHIIBBH", kernel_response, offset)

                if genlmsg_cmd == NL80211_CMD_NEW_SCAN_RESULTS:
                   nl80211_get_scan(sock, NL80211_FAMILY_ID, seq, pid, ifindex)               
                   scan_results = recv_nlmsg(sock)
                   return scan_results
          
                offset += (nlmsg_len + 3) & ~3

def nl80211_get_wiphy(sock, NL80211_FAMILY_ID, seq, pid, iface_index):
    msg = (genlmsghdr_header(NL80211_CMD_GET_WIPHY, genlmsghdr_version, genlmsghdr_reserved) + netlink_attr(NL80211_ATTR_IFINDEX, iface_index) + netlink_attr(NL80211_ATTR_SPLIT_WIPHY_DUMP, b"")) 

    send_nlmsg(sock, NL80211_FAMILY_ID, NLM_F_REQUEST | NLM_F_DUMP, seq, pid, msg)

def nl80211_get_interface(sock, NL80211_FAMILY_ID, seq, pid, ifindex):
    msg = (genlmsghdr_header(NL80211_CMD_GET_INTERFACE, genlmsghdr_version, genlmsghdr_reserved) + netlink_attr(NL80211_ATTR_IFINDEX, ifindex))

    send_nlmsg(sock, NL80211_FAMILY_ID, NLM_F_REQUEST | NLM_F_DUMP,  seq, pid, msg)

def nl80211_set_wiphy_frequency(sock, NL80211_FAMILY_ID, seq, pid, wiphy_index, frequency_mhz):
    msg = (genlmsghdr_header(NL80211_CMD_SET_WIPHY, genlmsghdr_version, genlmsghdr_reserved) + netlink_attr(NL80211_ATTR_WIPHY, wiphy_index) + netlink_attr(NL80211_ATTR_WIPHY_FREQ, frequency_mhz))
    send_nlmsg(sock, NL80211_FAMILY_ID, NLM_F_REQUEST | NLM_F_ACK, seq, pid, msg)

def netlink_RTM_socket(pid):
    # Socket Routing Netlink (RTM)
    sock_rtm = socket.socket(socket.AF_NETLINK, socket.SOCK_RAW, socket.NETLINK_ROUTE)
    sock_rtm.bind((pid, 0))
    return sock_rtm

def netlink_GENL_socket(pid):
    # Socket Generic Netlink (nl80211)
    sock_genl = socket.socket(socket.AF_NETLINK, socket.SOCK_RAW, NETLINK_GENERIC)
    sock_genl.bind((pid, 0))
    return sock_genl
