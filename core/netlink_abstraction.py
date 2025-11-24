import struct
import socket
import os
import sys
import json

from netlink_messages import (get_netlink_families, recv_nlmsg, netlink_RTM_socket, netlink_GENL_socket, rtm_getlink, nl80211_trigger_scan, nl80211_get_scan, scan_process_analyzer, nl80211_get_wiphy, nl80211_get_interface, nl80211_set_wiphy_frequency)
from linux_subsystems_constants import * # ()
from parser_netlink_route import parser_rtm_getlink
from parser_nl80211 import kernel_response_parser, parser_nested_nlattrs, show_ap_info, parser_ctrl_attr_mcast_groups
from util_internal_functions import bytes_for_mac
                               
class NetlinkUser():          
      def __init__(self):      
          self.seq = 1        
          self.pid = os.getpid()
                               
          self.sock_rtm = netlink_RTM_socket(self.pid)
          
          self.sock_genl = netlink_GENL_socket(self.pid)

          self.GET_NETLINK_FAMILIES = get_netlink_families(self.sock_genl, self.seq, self.pid)

          self.NL80211_FAMILY_ID = None
          self.NL80211_SCAN_CTRL_ATTR_MCAST_GRP_ID = None

          for self.dictfamily in self.GET_NETLINK_FAMILIES:
              if "nl80211" in self.dictfamily:
                 self.NL80211_FAMILY_dict = self.dictfamily.get("nl80211")
                 self.NL80211_FAMILY_ID = self.NL80211_FAMILY_dict["CTRL_ATTR_FAMILY_ID"]
                 self.NL80211_SCAN_CTRL_ATTR_MCAST_GRP_ID = parser_ctrl_attr_mcast_groups(self.NL80211_FAMILY_dict["CTRL_ATTR_MCAST_GROUPS"])
          self.bytes_for_mac = bytes_for_mac
          

      def getlink_information(self):
          rtm_getlink(self.sock_rtm, self.seq, self.pid)
          newlink_results = recv_nlmsg(self.sock_rtm)
          nlattrs_newlink_results = parser_rtm_getlink(newlink_results)

          interfaces = {}

          for nlmsg in nlattrs_newlink_results:
              ifindex = None

              if ifindex is None:
                 ifindex = nlmsg.get("ifinfomsg")[3]

              interfaces[ifindex] = {}

              for nla_len, nla_type, nla_data in nlmsg["nlattrs"]:
                  interfaces[ifindex]["IFINDEX"] = ifindex
                  if nla_type == IFLA_IFNAME:
                     interfaces[ifindex]["IFNAME"] = str(nla_data, "utf-8").strip("\x00")
                  if nla_type == IFLA_ADDRESS:
                     interfaces[ifindex]["MAC"] = bytes_for_mac(bytes(nla_data))

                  if nla_type == IFLA_BROADCAST:
                     interfaces[ifindex]["MAC Broadcast"] = bytes_for_mac(bytes(nla_data))

                  if nla_type == IFLA_PROMISCUITY:
                     interfaces[ifindex]["Promiscuity"] = int.from_bytes(bytes(nla_data), "little", signed=False)


          return interfaces

# Get devices wireless physical informations
      def wiphy_information(self, ifindex):
          nl80211_get_wiphy(self.sock_genl, self.NL80211_FAMILY_ID, self.seq, self.pid, ifindex)

          new_wiphy_results = recv_nlmsg(self.sock_genl)

          parsed_msgs = kernel_response_parser(new_wiphy_results, self.NL80211_FAMILY_ID)

          phy_information = {
          }

          wiphy_bands_blob = []
          for nlmsghdr, genlmsg, nlattrs_list in parsed_msgs:
              for nlattr in nlattrs_list:
                  nlattr_index = nlattr[1]

                  if nlattr_index == NL80211_ATTR_WIPHY_NAME:
                     phy_information["Wiphy name"] = nlattr[2].strip(b"\x00").decode()
                  elif nlattr_index == NL80211_ATTR_WIPHY:
                       phy_information["Wiphy index"] = struct.unpack("=I", nlattr[2])[0]
                    
                  elif nlattr_index == NL80211_ATTR_MAC:
                       phy_information["Wiphy MAC"] = self.bytes_for_mac(nlattr[2])
                  elif nlattr_index == NL80211_ATTR_WIPHY_BANDS:
                       wiphy_bands_blob.append(parser_nested_nlattrs(nlattr[2]))


          def parser_wiphy_frequencys(bands_blobs):
              bands_supported = {
                0: "2 Ghz",
                1: "5 Ghz",
                2: "6 Ghz",
                3: "60 Ghz"
              }

              freqs_by_band = {}
              
              for band_name in bands_supported.values():
                  freqs_by_band[band_name] = []
              
              for bands_blob in bands_blobs:
                  for band_id, band_data in bands_blob:
                      if band_id not in bands_supported:
                         continue
  
                      band_name = bands_supported[band_id]

                      parsed_band_data = parser_nested_nlattrs(band_data)
                      for band_data_attr_id, band_data_blob_sub in parsed_band_data:
                          if band_data_attr_id == NL80211_BAND_ATTR_FREQS:
                             band_channel_blob = parser_nested_nlattrs(band_data_blob_sub)
                             for channel_data_id, channel_data in band_channel_blob:
                                 parsed_channel_data = parser_nested_nlattrs(channel_data)
                                 freq_mhz = None
                                 freq_available = True
                                 for channel_data_attr_id, channel_data_attr in parsed_channel_data:
                                     if channel_data_attr_id == NL80211_FREQUENCY_ATTR_FREQ:
                                        freq_mhz = struct.unpack("<I", channel_data_attr)[0] # in mhz
                                     if channel_data_attr_id == NL80211_FREQUENCY_ATTR_DISABLED:
                                        freq_available = False

                                 if freq_mhz is not None:
                                    if freq_available:
                                       freqs_by_band[band_name].append((freq_mhz, True))
                                    else: 
                                        freqs_by_band[band_name].append((freq_mhz, False))
                                        
              return freqs_by_band
                                     

          return phy_information, parser_wiphy_frequencys(wiphy_bands_blob)


      def  get_interface_information(self, ifindex):
           nl80211_get_interface(self.sock_genl, self.NL80211_FAMILY_ID, self.seq, self.pid, ifindex)
           new_interface_results = recv_nlmsg(self.sock_genl)
           new_interface_results_msgs_parsed = kernel_response_parser(new_interface_results, self.NL80211_FAMILY_ID)

           ifindex = None
           get_interface_information_result = {}

           NL80211_IFTYPES = {
             1: "ADHOC",
             2: "STATION",
             3: "AP",
             4: "AP_VLAN",
             5: "WDS",
             6: "MONITOR",
             7: "MESH_POINT",
             8: "P2P_CLIENT",
             9: "P2P_GO",
             10: "P2P_DEVICE",
             11: "OCB",
             12: "NAN",
             13: "MAX"
           }
             
           for nlmsghdr, genlmsg, nlattrs_list in new_interface_results_msgs_parsed:
               for nla_len, nla_type, nla_data in nlattrs_list:
                   if nla_type == NL80211_ATTR_IFINDEX:
                      ifindex = struct.unpack("I", nla_data)[0]
                      get_interface_information_result[ifindex] = {}

               if ifindex:
                   for nla_len, nla_type, nla_data in nlattrs_list:
                       if nla_type == NL80211_ATTR_IFNAME:                          
                          get_interface_information_result[ifindex]["Interface name"] = nla_data.strip(b"\x00").decode() 

                       elif nla_type == NL80211_ATTR_MAC:
                            get_interface_information_result[ifindex]["MAC"] = bytes_for_mac(nla_data)

                       elif nla_type == NL80211_ATTR_WIPHY_FREQ:
                            get_interface_information_result[ifindex]["Frequency"] = struct.unpack("<I", nla_data)[0] # mhz

                       elif nla_type == NL80211_ATTR_IFTYPE:
                            get_interface_information_result[ifindex]["Type"] = NL80211_IFTYPES.get(struct.unpack("<I", nla_data)[0])

                       elif nla_type == NL80211_ATTR_SSID:
                            
                            get_interface_information_result[ifindex]["SSID"] = nla_data.strip(b"\x00").decode()

                       elif nla_type == NL80211_ATTR_WIPHY:
                            get_interface_information_result[ifindex]["Wiphy index"] = struct.unpack("I", nla_data)[0]
                            
                       elif nla_type == NL80211_ATTR_WDEV:
                            get_interface_information_result[ifindex]["WDEV identifier"] = hex(struct.unpack("q", nla_data)[0])

                            
           return get_interface_information_result  
                                 

      def wiphy_frequency(self, wiphy_index, frequency_mhz):
          nl80211_set_wiphy_frequency(self.sock_genl, self.NL80211_FAMILY_ID, self.seq, self.pid, wiphy_index, frequency_mhz)
          set_wiphy_frequency_results = recv_nlmsg(self.sock_genl)
          set_wiphy_frequency_results_msgs_parsed = kernel_response_parser(set_wiphy_frequency_results, self.NL80211_FAMILY_ID)
          return set_wiphy_frequency_results_msgs_parsed

      def trigger_scan(self, ifindex):
          try:
             self.sock_genl.setsockopt(SOL_NETLINK, NETLINK_ADD_MEMBERSHIP, self.NL80211_SCAN_CTRL_ATTR_MCAST_GRP_ID)

             nl80211_trigger_scan(self.sock_genl, self.NL80211_FAMILY_ID, self.seq, self.pid, ifindex)

             scan_results = scan_process_analyzer(self.sock_genl, self.NL80211_FAMILY_ID, self.seq, self.pid, ifindex)

             scan_results_parsed = show_ap_info(scan_results, self.NL80211_FAMILY_ID)
             return scan_results_parsed

          except Exception as error:
                 self.sock_genl.setsockopt(SOL_NETLINK, NETLINK_DROP_MEMBERSHIP, self.NL80211_SCAN_CTRL_ATTR_MCAST_GRP_ID)
                 print(error)

#netlinkuserobj = NetlinkUser()
#ifindex = 3
#wiphy_index = 1
#iface_index_bytes = lambda ifindex: struct.pack("=I", ifindex)
#print(netlinkuserobj.get_interface_information(iface_index_bytes(ifindex)), "\n")
#netlinkuserobj.wiphy_information(iface_index_bytes(ifindex))
#print()
#freq_mhz = struct.pack("=I", int(input("Type it the frequency (mhz): ")))
#print(netlinkuserobj.set_frequency(iface_index_bytes(wiphy_index), freq_mhz))
#print(netlinkuserobj.get_interface_information(iface_index_bytes))
#print(netlinkuserobj.getlink_information())
