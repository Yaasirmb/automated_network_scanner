from libnmap.parser import NmapParser, NmapParserException
import argparse
import sys
import pyodbc
import subprocess
from config import connect_string,insert_query
import logging
import traceback
import logging.config
from dict_logging import LOGGING_CONFIG
import time

sysLog = logging.getLogger('SysLogger')
fileLog = logging.getLogger('timedLogger')

logging.config.dictConfig(LOGGING_CONFIG)

"""
 Authors: Yaasir M.B. and David F.
 Date: 4/2/20
 This script parses an Nmap xml file and returns the host name,IP, open ports, state of the ports (only open and filtered), 
 services,products, possible operating systems, 
 and accuracy of the OSes in a list of lists. Once the data is parsed it's then pushed up to a SQL database."""

# file_to_parse is the path to the xml file you want to parse.

def parser(file_to_parse):
   
    # Create the arguments we want this script to be able to take
    argument_parser = argparse.ArgumentParser(description='Parse nmap report data')
    argument_parser.add_argument('--f', dest='file_to_parse', help='Filename to parse')

    try:
         # Parse the report and store it into a variable
         nmap_report = NmapParser.parse_fromfile(file_to_parse)
         #print(nmap_report.hosts)
    except:
        fileLog.error("There was an error: %s", traceback.format_exc())
        print("There was an error: %s", traceback.format_exc())
   
    # A list that's populated with the host_data lists. 
    host_info = []
    #Loop through every host in the nmap_report.
    for host in nmap_report.hosts:

        fileLog.debug(str(len(host.services)) + " services detected for " + str(host.address))
        # Loop through each service in each host.
        for service in host.services:
                
                """ 

                The host_data list contains the host name, IP, open ports, state of ports (only open and filtered), 
                services running on those ports, 
                the product using that service on that port, 
                top 3 OS guesses and how accurate they possibly are, and the start and end time of the scan of the host.
                 
                """
                host_data = []
                host_os = []
                host_accuracy = []
                # If the host has a host name, it append's it to host_data.
                if len(host.hostnames) !=0:
                    host_data.insert(0,host.hostnames[0])
                else:
                    # If the host doesn't have a host name it inserts "No host name" as a place holder.
                    host_data.insert(0,'No host name')
                host_data.insert(1,host.address)
                # Ignore services that are unknown or closed.
                if service.state == 'unknown' or service.state == 'closed':
                    pass
                else:
                    print(service.service)
                    host_data.append(str(service.port))
                    host_data.append(service.state)
                    host_data.append(service.service)
                    host_data.append(service.banner.title())

                host_info.append(host_data)

                # The "i" variable is a counter/iterator for the loop.
                i = 0

                try: 
                    # Loop through the '_extras' dictionary in each host.
                    if host._extras['os']['osmatches']:
                        # The 'item' variable is each dictionary in the 'osmatches' dictionary, which lives inside the 'os' dictionary.
                        for item in host._extras['os']['osmatches']:
                            if i < 3: 
                                # os_name gets the name value from the 'item' variable.
                                os_name = (item['osmatch']['name'])
                                # os_accuracy gets the 'accuracy' value from the 'item' variable.
                                os_accuracy = (item['osmatch']['accuracy'])
                                host_os.append(os_name)
                                host_accuracy.append(os_accuracy)
                                i += 1
                                # The 'os' variable is taking the 'host_os' list and making it a comma separated string.
                                os = ', '.join(host_os)
                                # Same thing is happening with the 'accuracy' variable, except this syntax works for intergers.
                                accuracy = ', '.join(map(str, host_accuracy))          
                except:
                    fileLog.error("There was an error: %s", traceback.format_exc())
                    os = "This host did not come back with any OS guesses."
                    accuracy = "Null"
                host_data.append(os)
                host_data.append(accuracy)
                host_data.append(int(host.starttime))
                host_data.append(int(host.endtime))
                host_info.append(host_data)

        # The last host in the host_info list duplicates for some reason, so this gets rid of duplicate lists.
        data = list()
        for sublist in host_info:
            if sublist not in data:
                data.append(sublist)
        print(data)
            
    try:
        fileLog.debug('Connecting to the database.')
        conn = pyodbc.connect(connect_string)
        fileLog.debug('Connected to the database successfully.')

        # The Cursor object represents a database cursor, which is typically used to manage the context of a fetch operation.
        cursor = conn.cursor()

        for row in data:
            if len(row) == 10:
                values = (str(row[0]),str(row[1]),str(row[2]),str(row[3]),str(row[4]),str(row[5]),str(row[6]),str(row[7]),str(row[8]),str(row[9]))
            
                fileLog.debug('Executing the insert query.')
                fileLog.debug('Insert statement: ' + insert_query)
                fileLog.debug('Values: ' + str(values))

                cursor.execute(insert_query,values)

                fileLog.debug('Insert query was executed succesfully.')
            else:
                sysLog.critical("There was an error with parsing this host: "+ str(row))


        #Commit inserts.
        conn.commit()
        fileLog.debug('The insert query was commited to the database.')
        print('The insert query was commited to the database successfully.')
    except:
        sysLog.critical("There was an error in the Parse_Nmap.py script : %s", traceback.format_exc())
        print(traceback.format_exc())

    # Returns all rows in our database.
    #cursor.execute('SELECT * FROM Nmap_Results ')

    #Prints all those rows we just called for.
    #for row in cursor:
    #    print(row)

    # Ends conenction.
    cursor.close()
    conn.close()


parser('nmap_scan_borking.xml')
