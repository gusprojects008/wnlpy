import re
import json

nl80211 = "/usr/include/linux/nl80211.h"

def netlink_values_classes_parser(netlink_file):
    netlink_file_lines = netlink_file.strip().split(',')
    netlink_dictionary = {}
    index = 0

    for line in netlink_file_lines: # Loop for key(cmd or attr) index(Is the value from function enumerate, a number which will be used as index for each key)
        clean_line = re.sub(r'[\n\t]+', '', line.strip())

        if clean_line in netlink_dictionary: # Verify if line already exist
           continue # Skip the iteration index and continue the "for" loop if clean_line already exist

        netlink_dictionary[clean_line] = index

        if '=' in clean_line:
           try:
              key_split = clean_line.strip().split('=')
              key_value = eval(key_split[1].strip(), {}, netlink_dictionary) # evaluate the second value of the key, and solve/interpret it as python code, and if it is an already existing key or variable he solve/interpret by accessing 
              netlink_dictionary.update({key_split[0]: key_value})
           except SyntaxError:
                  try:
                     key_value = eval(key_split[1].strip().replace('U', ''), {}, netlink_dictionary)
                     netlink_dictionary.update({key_split[0]: key_value})
                  except (SyntaxError, NameError):
                         continue
        else:  
            index += 1

    return {key: hex(index) for key, index in netlink_dictionary.items()} # for "key:" the hex() function go iterate over index(iterable) in nl80211_dict.items()

def netlink_file_handler(netlink_file):
    with open(netlink_file, "r") as file_content:
         netlink_content = file_content.read()

    netlink_content = re.sub(r'/\*.*?\*/', '', netlink_content, flags=re.DOTALL) # important explict arg: "flags=" use!

    netlink_content = re.findall(r'nl80211_([^{]+)\s*{([^}]*)};', netlink_content, flags=re.DOTALL) # findall return a list containing all matches, re.DOTALL makes do expression "." include lines

    netlink_dictionary = {}
    for enum_name, enum_values in netlink_content:
        netlink_dictionary[enum_name.strip()] = netlink_values_classes_parser(enum_values.strip())  # netlink_values_class_parser(enum_values)
        
    return netlink_dictionary # re.findall return a tuple(enum name, values_list) if match

# receives a content and creates a txt file or adds it if the file already exist: nl80211_dictionary.txt 
def netlink_file_map(netlink_values_classes):
    with open("netlink_dictionary.txt", "w") as file:
         json.dump(netlink_values_classes, file, indent=1)

netlink_values_classes = netlink_file_map(netlink_file_handler(nl80211))
print(netlink_file_handler(nl80211))
