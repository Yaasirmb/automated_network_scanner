#!/usr/local/bin/python3
import time
import os
import subprocess
import ipaddress
import glob
import copy
import config
from config import ip_splitter, masscan_bin_path
import logging
import traceback
import xml.etree.ElementTree as etree
import argparse
import logging 
import logging.config
from dict_logging import LOGGING_CONFIG
from tenable_asset_importer import tenable_asset_maker

"""
Authors: David F. and Yaasir M.B.
Date: 6/30/2020
This script performs a scan using Masscan and only saves the IP addresses to a text file. That text file is then fed to the Scan_Nmap(Bulk) script.

Parts of this script use code written by Jake Miller's script (@LaconicWolf) https://github.com/laconicwolf/Masscan-to-CSV/blob/master/masscan_xml_parser.py
"""


logging.config.dictConfig(LOGGING_CONFIG)

sysLog = logging.getLogger('SysLogger')
fileLog = logging.getLogger('timedLogger')


def get_host_data(root):
    """Traverses the xml tree and build lists of scan information
    and returns a list of lists.
    """
    host_data = []
    hosts = root.findall('host')
    for host in hosts:
        addr_info = []
        
        # Get address element information
        # <address addr="10.10.10.1" addrtype="ipv4"/>
        ip_address = host.find('address').attrib.get('addr')
        addr_type = host.find('address').attrib.get('addrtype')
        
        # Get ports element information
        # <ports><port protocol="tcp" portid="80">
        # <state state="open" reason="syn-ack" reason_ttl="238"/>
        # </port></ports>
        proto = host.find('ports').find('port').attrib.get('protocol')
        port_id = host.find('ports').find('port').attrib.get('portid')
        port_state = host.find('ports').find('port').find('state').attrib.get('state')
        state_reason = host.find('ports').find('port').find('state').attrib.get('reason')
        reason_ttl = host.find('ports').find('port').find('state').attrib.get('reason_ttl')

        # Get services info if available
        # <service name="ssl" banner="TLS/1.1 cipher:0x01,
        # webservices.example.com"></service>
        try:
            service_name = host.find('ports').find('port').find('service').attrib.get('name')
            banner = host.find('ports').find('port').find('service').attrib.get('banner')
        except AttributeError:
            service_name = banner = ''
            
        addr_info.extend((ip_address, addr_type,
                          proto, port_id, port_state, 
                          state_reason, reason_ttl,
                          service_name, banner))
        
        # Add the data to the host data
        host_data.append(addr_info)

    return host_data


def parse_xml(filename):
    """Given an XML filename, reads and parses the XML file and passes the 
    the root node of type xml.etree.ElementTree.Element to the get_host_data
    function, which will futher parse the data and return a list of lists
    containing the scan data for a host or hosts."""
    try:
        tree = etree.parse(filename)
    except Exception as Malformed_xmlfile:
        print("[-] A an error occurred. The XML may not be well formed. "
              "Please review the error and try again: {}".format(Malformed_xmlfile))
        pass
    root = tree.getroot()
    scan_data = get_host_data(root)
    return scan_data

def list_ip_addresses(data):
    """Parses the input data to return only the IP address information"""
    ip_list = [item[0] for item in data]
    sorted_set = sorted(set(ip_list))
    addr_list = [ip for ip in sorted_set]
    return addr_list

def masscan_main():
    """
    Performs a scan on a network using Masscan, saves the results of the scan to an xml file, 
    parses that xml file for only the IP addresses and saves them to a text file.
    
    """

    root_path = "/opt/"

    # Looking for all text files in the 'Networks' directory. This is a list object.
    files = glob.glob(root_path + "Networks/*.txt" , recursive=False)
    for filename in files:
        text_file = os.path.split(filename)
        text_file_name = text_file[1].rstrip('.txt')
        root = root_path + "Networks/"
        # Opening all text files in the "files" list.
        with open(filename) as networks:
            # Getting the name of the text files without the '.txt' extension from that list.
            org_name =  (os.path.splitext(os.path.basename(networks.name))[0])
            org_path = root + org_name

            # The "line" variable is each line in the file we opened, line is also a subnet.
            for line in networks:
                # line is a raw string that contains the new line character (\n), and the "rstrip" gets rid of the (\n).
                line = line.rstrip()
                
                ip_split = ip_splitter(line)
                cidr_block = ip_split[4]
                #print(ip_split)
                unix_time = int(time.time())

                if ip_split and int(cidr_block) <= 24:

                    # If the subnet is larger than a /24, it gets divided into /24s. 
                    # Ex: if your file contains the subnet 192.168.0.0/23 it will be split into two /24s and become 192.168.0.0/24 and 192.168.1.0/24.
                    subnet_splitter = [ip.with_prefixlen for ip in list(ipaddress.ip_network(line).subnets(new_prefix=24))]
                    fileLog.info('There was a subnet larger than /24, spliiting subnet: ' + line)
                    subnet_split_set = set(subnet_splitter)

                    for subnet in subnet_split_set:
                        #print(subnet)
                        # Path where masscan xml and txt files will be saved.
                        output_path = org_path + '/' + ip_split[0] + '-' + ip_split[1] + '/' + ip_split[2] + '/Masscan_Results/' + "Masscan_" +  str(unix_time)
                        output_path_xml = output_path + '.xml'
                        fileLog.debug('The masscan output path is ' + output_path)
                        # This command can be modified to however you want using any masscan flags.
                        masscan_command = masscan_bin_path + "/masscan " + subnet + " --open --rate 8000 --top-ports 1000 -oX " + output_path_xml
                        #print(masscan_command)
                        fileLog.info(masscan_command)

                        try:  
                            print("Starting Masscan\n")
                            masscan = subprocess.check_output(masscan_command, stderr=subprocess.STDOUT, shell=True)
                            print(masscan)
                            # If the xml file is empty and there were no hosts up in that subnet, the xml file get's deleted.
                            if os.path.getsize(output_path_xml) == 0:
                                os.remove(output_path_xml)
                                fileLog.info('There was an empty file that has been deleted.')
                                print('There was an empty file that has been deleted.')

                            elif os.path.getsize(output_path_xml) > 0:
                                data = parse_xml(output_path_xml)
                                addrs = list_ip_addresses(data)
                                listToStr = ','.join([str(ip) for ip in addrs])
                                # Code for if you want to push the ips directly to tenable.
                                #listToStr = ','.join([str(ip) for ip in addrs])
                                #tenable = tenable_asset_maker(text_file_name,listToStr)
                                print(tenable_asset_maker(text_file_name,listToStr))
                                with open(output_path + '.txt', 'w') as masscan_ips_file:
                                    for addr in addrs:
                                        #print(addr)	
                                        masscan_ips_file.write("%s\n" % addr)
                                os.remove(output_path_xml)
                            print("Finished parsing masscan xml.")
                            fileLog.info(masscan)
                        except:                                                 
                            #sysLog.critical("There was an error in the Scan_Masscan.py script : %s", traceback.format_exc())
                            print('%s', traceback.format_exc())
                            pass


                else:
                    # Same code as above, but this code works for subnets that are /24s 
                    # and smaller (I'm not sure if the smaller works but I think i remember it working, needs testing). 
                    # Will get rid of duplicate code in the future, still works for now.    
                    output_path = org_path + '/' + ip_split[0] + '-' + ip_split[1] + '/' + ip_split[2] + '/Masscan_Results/' + "Masscan_" +  str(unix_time)
                    output_path_xml = output_path + '.xml'
                    fileLog.debug('The masscan output path is ' + output_path)
                    masscan_command = masscan_bin_path + "/masscan " + line + " --open --rate 8000 --top-ports 1000 -oX " + output_path_xml
                    #print(masscan_command)
                    fileLog.info(masscan_command)
                    try:  
                        print("Starting Masscan\n")
                        masscan = subprocess.check_output(masscan_command, stderr=subprocess.STDOUT, shell=True)
                        print(masscan)
                        # If the file is empty and there were no hosts up in that subnet, the xml file get's deleted.
                        if os.path.getsize(output_path_xml) == 0:
                            os.remove(output_path_xml)
                            fileLog.info('There was an empty file that has been deleted.')
                            print('There was an empty file that has been deleted.')
                        elif os.path.getsize(output_path_xml) > 0:
                            data = parse_xml(output_path_xml)
                            addrs = list_ip_addresses(data)
                            listToStr = ','.join([str(ip) for ip in addrs])
                            # Code for if you want to push the ips directly to tenable.
                            #listToStr = ','.join([str(ip) for ip in addrs])
                            #tenable = tenable_asset_maker(text_file_name,listToStr)
                            print(tenable_asset_maker(text_file_name,listToStr))
                            with open(output_path + '.txt', 'w') as masscan_ips_file:
                                for addr in addrs:
                                    #print(addr)	
                                    masscan_ips_file.write("%s\n" % addr)
                            os.remove(output_path_xml)
                        print("Finished parsing masscan xml.")
                        fileLog.info(masscan)
                    except:                                                 
                        sysLog.critical("There was an error in the Scan_Masscan.py script : %s", traceback.format_exc())
                        print("%s", traceback.format_exc())
                        #pass    
                
