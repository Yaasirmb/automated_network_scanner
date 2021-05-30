#!/usr/local/bin/python3
""" This script is designed to take the output of the Masscan.py script and read the text files in order to perform an Nmap scan on each IP address individually. """

import logging
import logging.config
from dict_logging import LOGGING_CONFIG
import subprocess
import shutil
import time
import os
import ipaddress
import glob
import traceback
import copy
from config import ip_splitter, nmap_bin_path, folder, root_path
from Parse_Nmap import parser
from libnmap.parser import NmapParser, NmapParserException
import argparse

"""
Authors: David F. and Yaasir M.B.
Date: 6/30/2020
This is a script that performs an Nmap scan on all hosts based on a scan from the Scan_Masscan.py script and saves the output as an xml file. 
After the scan is complete, it calls the Parse_Nmap.py script to parse the data and pushes the parsed data up to a database.

"""

logging.config.dictConfig(LOGGING_CONFIG)

sysLog = logging.getLogger('SysLogger')
fileLog = logging.getLogger('timedLogger')

def nmap_main():

    # Org_files gets all text files in the root path and places them in a list.
    org_files = glob.glob(root_path + "*.txt")

    # This for loop is looping through all files in the org_files list
    for filename in org_files:
    # Here we're opening the individual files and reading from them
        with open(filename) as f:

            org_name =  (os.path.splitext(os.path.basename(f.name))[0])
            # The path to where the org files live.
            org_path = root_path + org_name

            # In this for loop we're looping through each line in the file we opened in the above loop.
            # The line variable is each line or subnet that's being looped over in the opened file.
            for line in f:
                # Splitting the subnet's octets.
                try:
                    subnet_octets = ip_splitter(line)
                except:
                    fileLog.error("There was an error: %s", traceback.format_exc())
                    continue

                if len(subnet_octets) == 5:
                    # Path to where masscan text files will be saved
                    masscan_path = org_path + '/' + subnet_octets[0] + '-' + subnet_octets[1] + '/' + subnet_octets[2] + "/Masscan_Results/"                    
                else:
                    continue
                
                # If the script finds an 'Unscanned_IPs.txt' file, all the IPs in that file get added to 
                # this list so they can get scanned first during the next round of scanning. 
                ips_from_interrupted_scan = []
                try:
                    with open(masscan_path + 'Unscanned_Ips.txt', 'r') as nmap_unscanned:
                        ips_from_interrupted_scan =  [line.strip() for line in nmap_unscanned]
                        fileLog.debug('Reading the Unscanned Ips file was found.')
                        sysLog.critical('There was an Unscanned_Ips file detected from the last scan in: ' + masscan_path)                           
                    os.remove(masscan_path + 'Unscanned_Ips.txt')
                    fileLog.debug('Deleted the Unscanned Ips file.')

                except FileNotFoundError:
                    fileLog.debug('No Unscanned Ips file was found.')
                    pass
                except:
                    fileLog.error("There was an error: %s", traceback.format_exc())
                    pass

                # masscan_files gets all text files in the masscan path and puts them in a list.
                masscan_files = glob.glob(masscan_path + "Masscan_*.txt")
                
                for file_to_scan in masscan_files:

                    # Opening the text files that will be passed to Nmap for a scan to be performed.
                    with open (file_to_scan) as lines:
                        up_ips = [line.strip() for line in lines]
                    if ips_from_interrupted_scan:
                        up_ips[0:0] = ips_from_interrupted_scan
                    # If the up_ips list is empty, pass
                    if not up_ips:
                        fileLog.debug('There were no up hosts in the subnet: ' + line )
                        continue
                    # Ips that havn't been scanned yet are added to the 'unscanned_ips' list, once they get scanned they are then removed from this list 
                    # and added to the 'scanned_ips' list. We didn't want to edit the up_ips list directly since that could cause potential issues.                   
                    unscanned_ips = copy.copy(up_ips)
                    scanned_ips = []
                    fileLog.info("Nmap will scan "+ str(len(up_ips)) + " IPs.")

                    for ip in up_ips:

                        ip_octets = ip_splitter(ip)

                        vlan_path = org_path + '/' + ip_octets[0] + '-' + ip_octets[1] + '/' + ip_octets[2] + '/'

                        host_octet = ip_octets[3]
                        host_path = vlan_path + host_octet
                        fileLog.debug('Host path for this Ip is ' + host_path)
                        try:
                          folder(host_path)
                        except:
                          fileLog.error('Failed to create host_path: ' + host_path)
                          pass

                        # The unix_time variable is what's being used to name the nmap xml and masscan txt files.
                        unix_time = int(time.time())
                        # Path where the nmap scan will be saved.
                        output_path = host_path + '/' + 'Nmap_' + str(unix_time) + '.xml'
                        fileLog.debug('The Nmap output path for this scan is ' + output_path)
                        
                        try:
                            nmap_command =   "nmap -A -T4 -Pn --disable-arp-ping -iL " + file_to_scan + " -oX " + output_path
                            fileLog.debug('Nmap command: ' + nmap_command)
                            nmap = subprocess.check_output(nmap_command, stderr=subprocess.STDOUT, shell=True)
                            fileLog.info('This IP was scanned successfully: ' + ip)
                            print(nmap)
                            
                            # Define the path to the xml file you want to parse.
                            file_to_parse = output_path
                            parser(file_to_parse)
                            fileLog.info(file_to_parse + 'was parsed and pushed up to the database successfully.')
                            print('The file has been parsed and pushed up to the database successfully.')

                            scanned_ips.append(ip)
                            # Nmap command was successful, so the ip is moved to the scanned_ips list.
                            unscanned_ips.pop(0)
                            with open(masscan_path + 'Unscanned_Ips.txt', 'w') as unscanned_file:
                                unscanned_ips_set = set()
                                unscanned_ips_set.update(unscanned_ips)
                                for item in unscanned_ips_set:
                                    unscanned_file.write("%s\n" % item)
                        except:
                            fileLog.error("There was an error: %s", traceback.format_exc())
                            pass
                    completed_path = masscan_path + 'Completed/'
                    shutil.move(file_to_scan, completed_path)
