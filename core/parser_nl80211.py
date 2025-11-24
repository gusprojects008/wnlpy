# Parses the payload (raw data) resulting from the network scanning operation (NLMSG_TRIGGER_SCAN)
import struct
import json
import math
from linux_subsystems_constants import *

def parser_nlattrs_netlink_families(nlattrs):
    bytes_to_hex = lambda nlattr_data: int.from_bytes(nlattr_data[2], byteorder="little")
    offset = 0
    netlink_attrs = {} #[FAMILY_NAME] = {}
    current_family_name = None

    while offset < len(nlattrs):
          nla_len, nla_type = struct.unpack_from("<HH", nlattrs[offset:])
          nla_fmt = f"<HH{nla_len - struct.calcsize('<HH')}s"
          nlattr = struct.unpack_from(nla_fmt, nlattrs, offset)
          offset += (nla_len + 3) & ~3

          if nla_type == CTRL_ATTR_FAMILY_NAME:
             current_family_name = nlattr[2].rstrip(b"\x00").decode(errors="ignore")
             netlink_attrs[current_family_name] = {}
             current_family_name_dict = netlink_attrs[current_family_name]
          elif current_family_name is None:
               continue
          else:
              if nla_type == CTRL_ATTR_FAMILY_ID:
                 current_family_name_dict["CTRL_ATTR_FAMILY_ID"] = bytes_to_hex(nlattr)
              elif nla_type == CTRL_ATTR_VERSION:
                   current_family_name_dict["CTRL_ATTR_VERSION"] = bytes_to_hex(nlattr)
              elif nla_type == CTRL_ATTR_HDRSIZE:
                   current_family_name_dict["CTRL_ATTR_HDRSIZE"] = bytes_to_hex(nlattr)
              elif nla_type == CTRL_ATTR_MAXATTR:
                   current_family_name_dict["CTRL_ATTR_MAXATTR"] = bytes_to_hex(nlattr)
              elif nla_type == CTRL_ATTR_OPS:
                   current_family_name_dict["CTRL_ATTR_OPS"] = nlattr[2].hex()
              elif nla_type == CTRL_ATTR_MCAST_GROUPS:
                   current_family_name_dict["CTRL_ATTR_MCAST_GROUPS"] = nlattr[2].hex()
              else:
                  current_family_name_dict[f"UNKNOWN_ATTR_{nla_type}"] = nlattr

    return netlink_attrs


def kernel_response_parser(kernel_response, NL80211_FAMILY_ID):
    offset = 0 # the offset is the starting point for data parse!
    nlmsg_response = []
    #bytes_to_hex  = lambda nlattr_data: hex(int.from_bytes(nlattr_data[2], byteorder="little"))

    if kernel_response:
       while offset < len(kernel_response):
             nlmsg_len, nlmsg_type, nlmsg_flags, nlmsg_seq, nlmsg_pid, genlmsg_cmd, genlmsg_version, genlmsg_reserved = struct.unpack_from("<IHHIIBBH", kernel_response, offset)

             if nlmsg_type == NETLINK_GENERIC and genlmsg_cmd == 1:
                nlattrs_blob = kernel_response[offset + struct.calcsize("<IHHIIBBH"):offset + nlmsg_len]
                 
                nlmsg_response.append(parser_nlattrs_netlink_families(nlattrs_blob)) # add just attributes
                
             # in a nl80211_cmd_new_scan_results response is returned multiples nlmsgs of each Access Point(AP) network!
             if nlmsg_type == NL80211_FAMILY_ID and genlmsg_cmd == NL80211_CMD_NEW_SCAN_RESULTS:              
                nested_offset = offset + struct.calcsize("<IHHIIBBH")
                nlattrs = [] # new
                while nested_offset < (offset + nlmsg_len):
                      nla_len, nla_type = struct.unpack_from("<HH", kernel_response, nested_offset)
                      nlattr = kernel_response[nested_offset:nested_offset + nla_len]                      
                      nla_format = f"<HH{nla_len - struct.calcsize('<HH')}s"
                      nlattrs.append(struct.unpack(nla_format, nlattr)) # new
                      #nlmsg_response.append(((nlmsg_len, nlmsg_type, nlmsg_flags, nlmsg_seq, nlmsg_pid), (genlmsg_cmd, genlmsg_version, genlmsg_reserved), struct.unpack(nla_format, nlattr))) #to get each nlattr of nlmsg, more verbose!
                      nested_offset += (nla_len + 3) & (~ 3) # round nla_len to a multiple of 4

                nlmsg_response.append({
                  "nlmsghdr": (nlmsg_len, nlmsg_type, nlmsg_flags, nlmsg_seq, nlmsg_pid),
                  "genlmsg": (genlmsg_cmd, genlmsg_version, genlmsg_reserved),
                  "nlattrs": nlattrs
                }) #struct.unpack(nla_format, nlattr)))

             if nlmsg_type == NL80211_FAMILY_ID and genlmsg_cmd == NL80211_CMD_NEW_WIPHY:
                nested_offset = offset + struct.calcsize("<IHHIIBBH")
                nlattrs = []
                while nested_offset < (offset + nlmsg_len):
                      nla_len, nla_type = struct.unpack_from("<HH", kernel_response, nested_offset)
                      nlattr = kernel_response[nested_offset:nested_offset + nla_len]
                      nla_format = f"<HH{nla_len - struct.calcsize('<HH')}s"
                      nlattrs.append(struct.unpack(nla_format, nlattr))
                      #nlmsg_response.append(((nlmsg_len, nlmsg_type, nlmsg_flags, nlmsg_seq, nlmsg_pid), (genlmsg_cmd, genlmsg_version, genlmsg_reserved), struct.unpack(nla_format, nlattr))) #to get each nlattr of nlmsg, more verbose!
                      nested_offset += (nla_len + 3) & (~ 3) # round nla_len to a multiple of 4

                nlmsg_response.append(((nlmsg_len, nlmsg_type, nlmsg_flags, nlmsg_seq, nlmsg_pid), (genlmsg_cmd, genlmsg_version, genlmsg_reserved), nlattrs))


             if nlmsg_type == NL80211_FAMILY_ID and genlmsg_cmd == NL80211_CMD_NEW_INTERFACE:
                nested_offset = offset + struct.calcsize("<IHHIIBBH")
                nlattrs = []
                while nested_offset < (offset + nlmsg_len):
                      nla_len, nla_type = struct.unpack_from("<HH", kernel_response, nested_offset)
                      nlattr = kernel_response[nested_offset:nested_offset + nla_len]
                      nla_format = f"<HH{nla_len - struct.calcsize('<HH')}s"
                      nlattrs.append(struct.unpack(nla_format, nlattr))
                      #nlmsg_response.append(((nlmsg_len, nlmsg_type, nlmsg_flags, nlmsg_seq, nlmsg_pid), (genlmsg_cmd, genlmsg_version, genlmsg_reserved), struct.unpack(nla_format, nlattr))) #to get each nlattr of nlmsg, more verbose!
                      nested_offset += (nla_len + 3) & (~ 3) # round nla_len to a multiple of 4

                nlmsg_response.append(((nlmsg_len, nlmsg_type, nlmsg_flags, nlmsg_seq, nlmsg_pid), (genlmsg_cmd, genlmsg_version, genlmsg_reserved), nlattrs))
             
             #offset += (nlmsg_len + 3) & (~ 3) # nlmsg_len

             
             offset += (nlmsg_len + 3) & (~ 3) # nlmsg_len
          
    return nlmsg_response

def parser_ctrl_attr_mcast_groups(ctrl_attr_mcast_groups):
    data = bytes.fromhex(ctrl_attr_mcast_groups)
    nlattrs = []
    sub_nlattrs = {}
    offset = 0

    while offset < len(data):
          nla_len, nla_type = struct.unpack_from("=HH", data)
          nla_data = data[offset + struct.calcsize("=HH"):offset + nla_len - struct.calcsize("=HH")]

          sub_nlattrs = []
          sub_offset = 0

          while sub_offset < len(nla_data):
                subnla_len, subnla_type = struct.unpack_from("=HH", nla_data, sub_offset)
                subnla_data = nla_data[sub_offset + struct.calcsize("=HH"):sub_offset + subnla_len]

                sub_nlattrs.append(subnla_data)

                sub_offset += (subnla_len + 3) & ~3

          nlattrs.append((nla_data, sub_nlattrs))

          offset += (nla_len + 3) & ~3

    for nlattr, subnla in nlattrs:
        if isinstance(subnla, list):
           if subnla[1] == b"scan":
              return struct.unpack("=I", subnla[0])[0]

"""
def parser_nested_nlattrs(self, blob_data, depth=0):
    attrs = {}
    offset = 0
    while offset < len(blob_data):
        nla_len, nla_type = struct.unpack_from("<HH", blob_data, offset)
        payload = blob_data[offset+4:offset+nla_len]
        
        is_nested = bool(nla_type & NLA_F_NESTED)
        base_type = nla_type & ~NLA_F_NESTED
        
        if is_nested:
            nested = self.parse_nested_attributes(payload, depth+1) if payload else {}
            if base_type not in attrs:
               attrs[base_type] = []
            attrs[base_type].append(nested)
        else:
            attrs[base_type] = (base_type, payload)
        
        offset += (nla_len + 3) & ~3
    return attrs
"""

def parser_nested_nlattrs(blob_data):
    results = []
    offset = 0
    while offset < len(blob_data):
          nla_len, nla_type = struct.unpack_from("<HH", blob_data, offset)
          nla_data = blob_data[offset+4:offset+nla_len]
          results.append((nla_type, nla_data))
          offset += (nla_len + 3) & ~3
    return results

def parser_nl80211_bss(bss_info): # netlink attributes parser NL80211_BSS BSS(Basic Set Service) AP infomations
    offset = 0
    AP_info = [] # contains all netlink attributes of NL80211_BSS and your informations
    while offset < len(bss_info):
          nla_len, nla_type = struct.unpack_from("HH", bss_info, offset)
          nlattr = bss_info[offset:offset + nla_len]
          nla_format = f"HH{nla_len - struct.calcsize('HH')}s"
          AP_info.append(struct.unpack(nla_format, nlattr))
          offset += (nla_len + 3) & (~ 3)
    return AP_info

# Elements Informations(IEs) parser, a attribute between the attributes from nl80211_bss
def parser_IEs(IEs):
    AP_IEs = [] # contains all informations elements from AP
    offset = 0
    while offset < len(IEs):
          ie_id, ie_length = struct.unpack_from("BB", IEs, offset) # ie_id(1 byte), ie_length(1 byte)
          ie_format = f"BB{ie_length}s" # the ie_length is just the length of information 
          ie_element = struct.unpack_from(ie_format, IEs, offset) # ie_element full unpacked 
          AP_IEs.append((ie_element)) # groups each ie_element in a tuple 
          offset += ie_length + struct.calcsize("BB") # go to next ie_element, it is not necessary to line up for a multiple of 4
    return AP_IEs

def mac_converter(mac):
    return ':'.join(f'{byte:02x}' for byte in mac)

# returns the capatibily of rates of transmition from AP router
def calc_rates(rates):
    return [f'{(rate & 0x7f) * 500} Mbps' for rate in rates]

# returns signal quality and the approximate distance in metters between you and the AP router
def signal_analyser(signals):
    # obtains each signal value from the signals dict, and calculates the average of the frame's receive and transmit power signals between the wifi adapter and the AP (Pr and Pt) and with the result of the average of each value (Pr and Pt), subtracts Pr - Pt to obtain the signal attenuation value
    signal_mbm = signals.get("Signal mBm Pr")
    tpc_report = signals.get("TPC report Pt")
    tx_power = signals.get("Tx power enveloped Pt")
    country = signals.get("Country Pt")
    TSF =  signals.get("TSF")
    beacon_interval = signals.get("Beacon interval")
    frequency = signals.get("Frequency")

    Pr = signal_mbm / 100  # Pr received signal strength dBm

    quality = "Good" if Pr > -50 else "Normal" if -70 <= Pr < -50 else "Bad"

    power_transmissions_AP = [tpc_report, tx_power, country]
    Pt_availables = [-abs(Pt) for Pt in power_transmissions_AP if Pt is not None] # the transmit power values of the AP as reported by tpc report are positive and theoretically should be used as positive in operations, but in pratice when tested as negative, more real values are returned than when used as positve.
    #Pt_availables = [(Pt) for Pt in power_transmissions_AP if Pt is not None and Pt > 0]
    #Pt_availables = [Pt for Pt in power_transmissions_AP if Pt is not None and 0 <= Pt <= 30]

    #Pt = min(sum(Pt_availables) / len(Pt_availables), 23) if Pt_availables else 20
    Pt = min(sum(Pt_availables) / len(Pt_availables), -23) if Pt_availables else -20 # average transmitter signal strenght Pt dBm

    # estimates signal loss in an urban area or with a lot of interference, according to frequency
    #possible_loss = 60 if frequency >= 5000 else 45 
    possible_loss = 40 if frequency >= 5000 else 30
    #possible_loss = 15 if frequency >= 5000 else 10

    # Path Loss
    signal_attenuation = Pt - Pr # calculates the loss of signal power when propagating through the air

    #C = 300_000_000
    #frequency_hz = frequency * 1_000_000
    #wavelength = C / frequency_hz
    #FSPL_const = 20 * math.log10(4 * math.pi / wavelength)
    #FSPL = signal_attenuation + FSPL_const 

    # Is the logarithmic base, used to revert the logarithmic value log10 to linear form
    logarithm_base = 10

    # approximate distance with Free Space Path Loss formula 
    approximate_distance = logarithm_base ** (signal_attenuation / possible_loss)

    #approximate_distance = min(approximate_distance, 50)
    approximate_distance = min(approximate_distance, 50)
    #approximate_distance = round(max(approximate_distance, 50), 1)

    return quality, approximate_distance, Pt, Pr, Pt_availables #, FSPL_const, FSPL

def GCS_OUI_identify(GCS):
    GCS_OUI = mac_converter(GCS)
    GCS_OUI_dict = {
        '00:0f:ac:01': 'WEP-40',
        '00:0f:ac:02': 'TKIP',
        '00:0f:ac:04': 'AES_CCMP',
        '00:0f:ac:05': 'WEP-104',
        '00:0f:ac:06': 'BIP',
        '00:0f:ac:07': 'GCMP-128',
        '00:0f:ac:08': 'GCMP-256',
        '00:0f:ac:09': 'CCMP-256',
        '00:0f:ac:0a': 'BIP-GMAC-128',
        '00:0f:ac:0b': 'BIP-GMAC-256',
        '00:50:f2:01': 'Microsoft WEP',
        '00:50:f2:02': 'Microsoft TKIP',
        '00:50:f2:04': 'Microsoft AES-CCMP',
        '00:50:f2:05': 'Microsoft WPA proprietary',
        '00:90:4c:00': 'Broadcom proprietary',
        '00:e0:2f:00': 'Cisco',
        '00:14:a4:00': 'Atheros', 
    }
    return f"{GCS_OUI_dict.get(GCS_OUI, 'Unknown Type')} {GCS_OUI}" 

def AKM_OUI_identify(AKM):
    AKM_OUI = mac_converter(AKM)
    AKM_OUI_dict = {
        '00:0f:ac:01': 'WPA/RSN-PSK',
        '00:0f:ac:02': 'WPA/RSN-EAP',
        '00:0f:ac:03': 'FT-PSK',
        '00:0f:ac:04': 'FT-EAP',
        '00:0f:ac:05': 'WPA/RSN-SHA256-PSK',
        '00:0f:ac:06': 'WPA/RSN-SHA256-EAP',
        '00:0f:ac:07': 'SAE-WPA3',
        '00:0f:ac:08': 'FT-SAE',
        '00:0f:ac:09': 'AP',
        '00:0f:ac:0a': '802.1X',
        '00:0f:ac:0b': '802.1X-192' 
    }
    return f"{AKM_OUI_dict.get(AKM_OUI, 'Unknown Type')} {AKM_OUI}"
    
def mac_oui_vendors_identify(mac_oui):
    with open('./Core/mac-vendors-export.json', 'r', encoding='utf-8') as file:
         data = json.load(file)
         vendors_name = {}
         for line in data:
             vendors_name[line['macPrefix']] = line['vendorName']
         return vendors_name.get(mac_oui.upper()[:8], 'Unknown Vendor Type')

def show_ap_info(kernel_response_scan, NL80211_FAMILY_ID):
    AP_LIST = []
    try:
       kernel_response = kernel_response_parser(kernel_response_scan, NL80211_FAMILY_ID)
       for nlmsg_ap in kernel_response:
           genlcmd = nlmsg_ap["genlmsg"][0]
           #if genlcmd != NL80211_CMD_NEW_SCAN_RESULTS:
              #continue

           for (nla_len, nla_type, nla_data) in nlmsg_ap["nlattrs"]: # attribute from nlmsg_ap
                if nla_type == NL80211_ATTR_BSS:
                   AP_INFO = {}
                   AP_INFO['Vendor specific'] = []

                   for bss_attr in parser_nl80211_bss(nla_data):
                       bss_tag, bss_type, bss_value = bss_attr
                       if bss_type == 1: # NL80211_BSS_BSSID bss attribute
                          bssid = mac_converter(bss_value)
                          AP_INFO['Bssid'] = bssid, mac_oui_vendors_identify(bssid)
                       if bss_type == 2: # NL80211_BSS_FREQUENCY bss attribute
                          AP_INFO['Frequency'] = struct.unpack("<I", bss_value)[0]
                       if bss_type == 3:
                          AP_INFO['TSF'] = struct.unpack("<Q", bss_value)[0] # NL80211_BSS_TSF
                       if bss_type == 4: # NL80211_BSS_BEACON_INTERVAL
                          AP_INFO['Beacon interval'] = struct.unpack("<H", bss_value)[0]
                       if bss_type == 5: # NL80211_BSS_CAPABILITY bss attribute
                             capability = struct.unpack("<H", bss_value)[0] # bitmap informations
                             capabilities = {
                               "ESS is AP": bool(capability & 0x0001),
                               "IBSS is ad-hoc": bool(capability & 0x0002),
                               "Data confidentiality required": bool(capability & 0x0005),
                               "Privacy (WEP Enabled)": bool(capability & 0x0010)
                             }
                             AP_INFO['Capabilities'] = capabilities
                       if bss_type == 6: # NL80211_BSS_INFORMATION_ELEMENTS bss attribute
                          for ie in parser_IEs(bss_value): # loop for IEs attributes per eid
                              if isinstance(ie, tuple):
                                 if ie[0] == 0: # WLAN_EID_SSID eid attribute
                                    AP_INFO['Ssid'] = ie[2].decode('utf-8', errors='ignore') if ie[2].decode('utf-8', errors='ignore') != '' else 'Hidden SSID'
                                 if ie[0] == 1: # WLAN_EID_RATES eid attribute
                                    AP_INFO['Supported rates'] = calc_rates(ie[2])
                                 if ie[0] == 3: # WLAN_EID_DS_PARAMS eid attribute
                                    AP_INFO['Channel'] = struct.unpack('<B', ie[2])[0]
                                 if ie[0] == 7: # WLAN_EID_COUNTRY eid attribute
                                    country_code = ie[2][:3].decode('utf-8', errors='ignore').strip()
                                    channels_info = []
                                    for info in range(3, len(ie[2]), 3):
                                        if len(ie[2][info:info+3]) == 3: # take a info full
                                           first_channel, num_channel, max_power = struct.unpack('<BBb', ie[2][info:info+3])
                                           channels_info.append((first_channel, num_channel, max_power))
                                    AP_INFO['Country'] = country_code, channels_info
                                    # WLAN _EID_QBSS_LOAD
                                 if ie[0] == 35: # WLAN_EID_TPC_REPORT eid attribute tx power signal from device
                                    AP_INFO['TPC report'] = struct.unpack('bb', ie[2])[0]
                                         
                                 if ie[0] == 48: # WLAN_EID_RSN eid attribute
                                    rsn_info = {}
                                    offset = 0
                                    version, GCS, PCSC = struct.unpack_from('H4sH', ie[2], offset) 
                                    rsn_info['Group cipher suite multicast/broadcast'] = GCS_OUI_identify(GCS)
                                    offset += struct.calcsize("HIH")
                                    rsn_info['Pairwise cipher suites unicast'] = []
                                    for _ in range(PCSC):
                                       cipher_suite = struct.unpack_from("4s", ie[2], offset - struct.calcsize('H'))[0]
                                       rsn_info['Pairwise cipher suites unicast'].append(GCS_OUI_identify(cipher_suite))
                                       offset += struct.calcsize("I")
                                    offset -= struct.calcsize("H") # because of the for loop the offset is misaligned
                                    AKM_count = struct.unpack_from("H", ie[2], offset)[0]
                                    offset += struct.calcsize("H")
                                    rsn_info['AKM list'] = []                                      
                                    for _ in range(AKM_count):
                                        AKM = struct.unpack_from("<4s", ie[2], offset)[0]
                                        rsn_info['AKM list'].append(AKM_OUI_identify(AKM))
                                        offset += struct.calcsize("<I")
                                    capability_rsn = struct.unpack_from("<H", ie[2], offset)[0]
                                    rsn_capabilities = {
                                      'Pre-Auth': bool(capability_rsn & 1),
                                      'No pairwise': bool(capability_rsn & 2),
                                      'PTK replay counters': (capability_rsn & 12) >> 2,
                                      'GTK replay counters': (capability_rsn & 48) >> 4,
                                      'Management frame protection required MFPR': bool(capability_rsn & 64),
                                      'Management frame protection capable MFPC': bool(capability_rsn & 128),
                                      'Joint Multi-Band RSNA': bool(capability_rsn & 256),
                                      'PeerKey enable': bool(capability_rsn & 512),
                                      'Extended key ID': bool(capability_rsn & 0x4000),
                                      'OCVC': bool(capability_rsn & 0x8000)
                                    }
                                    rsn_info['RSN capabilities'] = rsn_capabilities              
                                    AP_INFO['RSN'] = rsn_info
                                 if ie[0] == 195: # WLAN_EID_TX_POWER_ENVELOPE eid attribute
                                    offset = 0
                                    AP_INFO['Tx power enveloped'] = []
                                    for _ in range(ie[1]):
                                        tx_power = struct.unpack_from("b", ie[2], offset)[0]
                                        AP_INFO['Tx power enveloped'].append(tx_power)
                                        offset += struct.calcsize("b")

                                 if ie[0] == 221: # WLAN_EID_VENDOR_SPECIFIC eid attribute
                                    vendor_format = f"3sB{ie[1] - struct.calcsize('3sB')}s"
                                    OUI_vendor, OUI_type, vendor_data = struct.unpack(vendor_format, ie[2])
                                    OUI_vendor_mac = mac_converter(OUI_vendor)
                                    AP_INFO['Vendor specific'].append((OUI_vendor_mac, mac_oui_vendors_identify(OUI_vendor_mac), OUI_type, vendor_data))
                       if bss_type == 7: # NL80211_BSS_SIGNAL_MBM bss attribute
                          AP_INFO['Signal mBm'] = struct.unpack("<i", bss_value)[0]
                          signals = {}
                          try:
                             signals["Signal mBm Pr"] = AP_INFO.get("Signal mBm")
                             signals["TPC report Pt"] = AP_INFO.get("TPC report")
                             signals["Tx power enveloped Pt"] = AP_INFO.get("Tx power enveloped")[3] if AP_INFO.get("Tx power enveloped") and len(AP_INFO.get("Tx power enveloped")) > 3 else None
                             signals["Country Pt"] = AP_INFO.get("Country")[1][0][2] if AP_INFO.get("Country") and len(AP_INFO.get("Country")) == 2 else None
                             signals["TSF"] = AP_INFO.get("TSF")
                             signals["Beacon interval"] = AP_INFO.get("Beacon interval")
                             signals["Frequency"] = AP_INFO.get("Frequency")
                             # NL80211_BSS_SIGNAL_UNSPEC
                             # NL80211_BSS_BEACON_TSF
                             signal_results = signal_analyser(signals)
                             AP_INFO["Signal analysis"] = signal_results
                          except Exception as error:
                                 AP_INFO["Signal analysis"] = f"Error: {str(error)}"
                               
                   AP_LIST.append(AP_INFO)
       return AP_LIST
    except Exception as error:
           print(error)

#kernel_response_scan = "Raw data results"

#scan_results = show_ap_info()
#print(scan_results)

#def parser_scan_results(scan_results):
 #   for ap in scan_results:
  #      print(ap)
#parser_scan_results(scan_results)


