import subprocess
from netlink_abstraction import NetlinkUser
from util_internal_functions import index_pack, ifname_to_ifindex
from wifi import l2
netlink_operations = NetlinkUser()

class Operations:
      @staticmethod
      def network_interfaces_list():
          # RTM GETLINK ifinfomsg dump
          getlink_information = netlink_operations.getlink_information()

          for ifindex in getlink_information:
              ifindex_bytes = index_pack(ifindex)
              get_interface_information_dict = netlink_operations.get_interface_information(ifindex_bytes) # GENL nl80211 GET_INTERFACE ifindex information
              wiphy_information_dict = netlink_operations.wiphy_information(ifindex_bytes) # GENL nl80211 GET_WIPHY ifindex information

              get_interface_information = get_interface_information_dict.get(ifindex) if get_interface_information_dict else None
              wiphy_information = wiphy_information_dict[0] if wiphy_information_dict else None

              if get_interface_information and wiphy_information:
                 print(f"(rtnetlink) Link interface (ifinfomsg): {getlink_information.get(ifindex)}\n(nl80211) Get interface information: {get_interface_information}\n(nl80211) Get Wiphy information: {wiphy_information}\n")
              else:
                  print(f"(rtnetlink) Link interface (ifinfomsg): {getlink_information.get(ifindex)}\n")

      def network_interface_list(self, ifname):
          ifindex_bytes = ifname_to_ifindex(ifname)
          ifindex = struct.unpack("<I", ifindex_bytes)[0]

          # RTM GETLINK ifinfomsg dump
          getlink_information = netlink_operations.getlink_information()
          # GENL nl80211 GET_INTERFACE ifindex information
          get_interface_information_dict = netlink_operations.get_interface_information(ifindex_bytes)
          # GENL nl80211 GET_WIPHY ifindex information
          wiphy_information_dict = netlink_operations.wiphy_information(ifindex_bytes)

          get_interface_information = get_interface_information_dict.get(ifindex) if get_interface_information_dict else None
          wiphy_information = wiphy_information_dict if wiphy_information_dict else None

          if get_interface_information and wiphy_information:
             print(f"(rtnetlink) Link interface (ifinfomsg): {getlink_information.get(ifindex)}\n(nl80211) Get interface information: {get_interface_information}\n(nl80211) Get Wiphy information: {wiphy_information}")
          else:
              print(f"(rtnetlink) Link interface (ifinfomsg): {getlink_information.get(ifindex)}")

      def set_monitor(self, ifname):
          try:
             subprocess.run(["sudo", "ip", "link", "set", ifname, "down"], stdout=subprocess.DEVNULL, stderr=subprocess.STDOUT, check=True)
             subprocess.run(["sudo", "iw", "dev", ifname, "set", "type", "monitor"], stdout=subprocess.DEVNULL, stderr=subprocess.STDOUT, check=True)
             subprocess.run(["sudo", "ip", "link", "set", ifname, "up"], stdout=subprocess.DEVNULL, stderr=subprocess.STDOUT, check=True)
             print(f"{ifname} configured for monitor mode!")
          except Exception as error:
                 print(f"error configure {ifname} to monitor mode: {error}")

      def set_station(self, ifname):
          try:
             subprocess.run(["sudo", "ip", "link", "set", ifname, "down"], stdout=subprocess.DEVNULL, stderr=subprocess.STDOUT, check=True)
             subprocess.run(["sudo", "iw", "dev", ifname, "set", "type", "managed"], stdout=subprocess.DEVNULL, stderr=subprocess.STDOUT, check=True)
             subprocess.run(["sudo", "ip", "link", "set", ifname, "up"], stdout=subprocess.DEVNULL, stderr=subprocess.STDOUT, check=True)
             print(f"{ifname} configured for station/management mode!")
          except Exception as error:
                 print(f"error configure {ifname} to monitor mode: {error}")

      def scan_station_mode(self, ifname):
          ifindex = ifname_to_ifindex(ifname)
          print(f"Trigger scan initalized via {ifname} ...")
          scan_results = netlink_operations.trigger_scan(ifindex)
          for ap_result in scan_results:
              print(ap_result)

      def sniff_ieee802_11(self, ifname, promisc, store, show_pattern, filter_pattern, output_path, packets_limit, timeout): # just monitor mode
          l2.ieee802_11.sniff(ifname, promisc, store, show_pattern, filter_pattern, output_path, packets_limit, timeout)

      def set_frequency(self, wiphy_index, frequency_mhz):
          print(f"setting frequency {frequency_mhz} ...")
          wiphy_index = index_pack(wiphy_index)
          frequency_mhz = struct.pack("<I", frequency_mhz)
          print(netlink_operations.wiphy_frequency(wiphy_index, frequency_mhz))

      def channel_hopping(self, wiphy_index):
          wiphy_index = index_pack(wiphy_index)
          wiphy_information = netlink_operations.wiphy_information(wiphy_index)[1]
          print(wiphy_information)
