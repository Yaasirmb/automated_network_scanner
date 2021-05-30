#!/bin/python3.8
import os
import ipaddress
import shutil
import glob
from config import folder,ip_splitter
import logging
import logging.config
from dict_logging import LOGGING_CONFIG
import traceback

sysLog = logging.getLogger('SysLogger')
fileLog = logging.getLogger('timedLogger')

logging.config.dictConfig(LOGGING_CONFIG)

# Path where you want your folders to be created, the Networks folder lives in this directory.
root_path = "/opt/"

#network_path = root_path + "Networks/"
#folder(network_path)

def folder_builder():
    """Code that creates file structure based on subnets found in the text file of the root path."""
    #Creating the root path for where the files will be stored.

    #Looking for all text files in the 'Networks' directory. This is a list object.
    files = glob.glob(root_path + "Networks/*.txt", recursive=False)

    # Each file should contain subnets (make sure to include the cidr block. Ex: 192.168.0.0/24) that you'd like to scan.
    for filename in files:
        root = root_path + "Networks/"
        with open(filename) as f:
            # Getting the name of the text files without the .txt extension from that list.
            org_name =  (os.path.splitext(os.path.basename(f.name))[0])
            org_path = root + org_name

            folder(org_path)
            print('Made org folder' + org_path)
            fileLog.info('The org folder path is ' + org_path)
        
            log_path = root + "Log"
            folder(log_path)
            fileLog.info('The log folder path is ' + log_path)

            # The "line" variable is each line in the file we opened, line is also a subnet
            for line in f:
                line = line.rstrip()
                ip_octets = ip_splitter(line)
                cidr_block = int(ip_octets[4])
                # Handling making folders for subnets bigger than /24s.
                if cidr_block < 24:
                    print(cidr_block)
                    try:
                        # If the subnet is larger than a /24, it gets divided into /24s. 
                        # Ex: if your file contains the subnet 192.168.0.0/23 it will be split into two /24s and become 192.168.0.0/24 and 192.168.1.0/24.
                        subnet_splitter = [ip.with_prefixlen for ip in list(ipaddress.ip_network(line).subnets(new_prefix=24))]
                        subnet_split_set = set(subnet_splitter)

                        for subnet in subnet_split_set:
                            print(subnet)
                            ip_octets = ip_splitter(subnet)
                            site_octet = ip_octets[0] + "-" + ip_octets[1]
                            site_octet_path = org_path + "/" + site_octet
                            folder(site_octet_path)

                            vlan_path = site_octet_path + "/" + ip_octets[2]
                            folder(vlan_path)

                            subfolder_name = "Masscan_Results"
                            subfolder_path = vlan_path + "/" + subfolder_name
                            fileLog.info('The sub folder path is ' + subfolder_path)
                            folder(subfolder_path)

                            completed_folder = "Completed"
                            completed_folder_path = subfolder_path + "/" + completed_folder
                            fileLog.info('The completed folder path is ' + completed_folder_path)
                            folder(completed_folder_path)
                    except:
                        fileLog.error("There was an error: %s", traceback.format_exc())
                        pass

                elif cidr_block == 24:

                    try:
                        ip_octets = ip_splitter(line)
                        if type(ip_octets) != list:
                            fileLog.error('ip_octets is not a list!: '.join(ip_octets))
                    except:
                        fileLog.error("There was an error: %s", traceback.format_exc())
                        pass
                    try:
                        site_octet = ip_octets[0] + "-" + ip_octets[1]
                        site_octet_path = org_path + "/" + site_octet
                        folder(site_octet_path)

                        vlan_path = site_octet_path + "/" + ip_octets[2]
                        folder(vlan_path)

                        subfolder_name = "Masscan_Results"
                        subfolder_path = vlan_path + "/" + subfolder_name
                        fileLog.info('The sub folder path is ' + subfolder_path)
                        folder(subfolder_path)

                        completed_folder = "Completed"
                        completed_folder_path = subfolder_path + "/" + completed_folder
                        fileLog.info('The completed folder path is ' + completed_folder_path)
                        folder(completed_folder_path)
                    except:
                        fileLog.error("There was an error: %s", traceback.format_exc())
                        pass