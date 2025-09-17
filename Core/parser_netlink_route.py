import struct

def parser_rtm_getlink(data):
    def parser_nlattrs(nlattrs):
        nlattrs_data = []
        offset = 0
        while offset < len(nlattrs):
              nla_len, nla_type = struct.unpack_from("<HH", nlattrs, offset)

              if nla_len < struct.calcsize("<HH") or offset + nla_len > len(nlattrs):
                 break

              nla_data = nlattrs[offset + struct.calcsize('<HH'):offset + nla_len] 
              
              nlattrs_data.append((nla_len, nla_type, nla_data))
              offset += (nla_len + 3) & ~3
              
        return nlattrs_data
      
    offset = 0
    nlmsgs_response = []

    while offset < len(data):
          nlmsg_len, nlmsg_type, nlmsg_flags, nlmsg_seq, nlmsg_pid = struct.unpack_from("<IHHII", data, offset)

          if nlmsg_len < struct.calcsize("<IHHII") or offset + nlmsg_len > len(data):
             break

          if nlmsg_type == 16:
             nested_offset = offset + struct.calcsize("<IHHII")
             if nested_offset + struct.calcsize("<BBHiII") <= offset + nlmsg_len:
                ifi_family, __ifi_pad, ifi_type, ifi_index, ifi_flags, ifi_change = struct.unpack_from("<BBHiII", data, nested_offset)
                 
                nested_offset += struct.calcsize("<BBHiII") + __ifi_pad
                nlattrs = parser_nlattrs(data[nested_offset:offset + nlmsg_len])

                nlmsgs_response.append({
                  "nlmsghdr": (nlmsg_len, nlmsg_type, nlmsg_flags, nlmsg_seq, nlmsg_pid),
                  "ifinfomsg": (ifi_family, __ifi_pad, ifi_type, ifi_index, ifi_flags, ifi_change),
                  "nlattrs": (nlattrs)
                })

          offset += (nlmsg_len + 3) & ~3

    return nlmsgs_response

                   
             
#with open("results.txt", "rb") as file:
 #    data = file.read()
  #   print(parser_rtm_getlink(data))

