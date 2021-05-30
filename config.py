import os
import ipaddress
import logging

# Functions

def folder(path):
    """ Function that checks if a folder exists or not. If it doesn't exist it get's created, if it does exist it doesn't. """
    if not os.path.exists(path):
        os.mkdir(path)
        #print("Directory " , path ,  " Created ")
    else:
        #print("Directory " , path ,  " already exists")
        pass
    return path

def ip_splitter(line):
    """ Function that splits subnets based on their periods '.' """
    ip_octets = []
    ips = line.rstrip()
    try:
        # Here we're using the ipaddress module native to python to check if the subnets provided are real subnets.
        subnet = ipaddress.ip_network(ips)
        split_ips = str(subnet).replace('/' , '.')
        ip_octets = split_ips.split(".")
        return ip_octets

    except (RuntimeError,TypeError,NameError,OSError) as e:
        fileLog.error(e, exc_info = True)
        fileLog.error('There was either an invalid Subnet/IP or some other data was found in the file: ' + ips)
        return ip_octets
        pass

# Access keys
# Create your tenable access keys and put them in between the quotes.
tenable_access_key = ""
tenable_secret_key = ""

# Folder paths
root_path = "/opt/Networks/"
masscan_bin_path = '/opt/masscan/bin/'
nmap_bin_path = '/bin/'
log_folder_path = '/opt/Networks/Log/'
log_file_path = '/opt/Networks/Log/Log_file_rotating.log'


folder(root_path)
folder(log_folder_path)