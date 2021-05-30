# Automated Scanning Project README

## Table of Contents

* [What this project does](#Whatthisprojectdoes)

* [How they all work together](#Howtheyworktogether)

* [Config File](#configfile)

* [Folder Builder Script](#folderbuilder)

* [Masscan](#masscan)

* [Nmap](#nmap)

* [Parse Nmap](#parsenmap)

* [Orchestrator](#orchestrator)

* [Tenable](#tenable)

* [How to Use Them](#howto)

* [Dependencies](#dependencies)

## What This Project Does <a name="Whatthisprojectdoes"></a>
This project is a collection of Python scripts that are meant to scan a network using Masscan and/or Nmap in order to inventory a network to give you a better idea of what's on it.

The scripts automate the process of performing a scan, storing the results of the scans, and takes further actions on these results by either performing a deeper scan using Nmap or importing them into Tenable&#46;sc for further investigation.

This project was developed to run on a Linux machine, CentOS7 to be precise. That being said it can work on a Windows machine as well. We've tested the Nmap, Tenable and folder part on Windows, but haven't tested the Masscan part because we weren't able to get Masscan working on Windows.

## How They All Work Together <a name="Howtheyworktogether"></a>

The scripts all work sequentially and feed its results into one another, however they can be modified to work individually since they were made to be modular. So it's possible to just use each portion seperately.  

## Dependencies <a name= "dependencies"> </a>

1. This project was developed using [Python 3.8.2](https://www.python.org/downloads/release/python-382/), however tests have been ran using 3.8.6.
    
    - All the Python packages used in this project are in the "requirements.txt" file, and to install them just type:
    ```
    pip install -r requirements.txt
    ```

2. [MySQL Community Release el7](https://dev.mysql.com/downloads/repo/yum/)

3. [Nmap](https://nmap.org/download.html)

4. [Masscan](https://github.com/robertdavidgraham/masscan)
    
5. A setup file has been included, you'll still need to manually install Nmap and MySQL. *Will add to the file in the future.*
    ```
    ./setup.sh
    ```

## How To Use Them <a name="howto"></a>

- Once you've installed all the dependencies and configured them to your liking, make sure to update the configpy file to match your new configurations where ever necessary.

1. To get started first run the config&#46;py file by typing:
    ```python
    python3 config.py
    ```
    - This will create the "Networks" and "Log" paths.

2. After running the config&#46;py file, navigate to the "Networks" folder and create a text file and populate it with subnets you would like to perform scans on.
    
    Your file should look something like:

    EXAMPLE.txt:

    192.168.0.0/18

    192.188.0.0/24

    192.3.0.0/16

3. Create your MySQL database and make sure to name it "MySQL_Nmap_Results", then follow these instructions to create a table for the Nmap script to write to using the "datbase_schema.sql" file.

![](../../raw/Feature_Testing/import_db_mysql.PNG)

4. Create a cronjob to run the  script(s) you'd like to run.



## The Config File <a name="configfile"></a>

The config&#46;py file is what contains some of the functions used in the scripts, access keys, database credentials and insert querey, and important folder paths.

## Folder Builder Script <a name="folderbuilder"></a>

The Builder_Folder_Structure.py script is the script that handles making the folders for where the scan results files are saved. This script creates folders based on the subnet(s) it found in the "org" file, which is the text file found in the "Networks" folder containing the list of subnet(s) you'd like the scripts to scan. The script first checks to see if the folder already exists, and if it does the folder isn't created, however if it doesn't exist it then creates the folder.

## Masscan Script <a name="masscan"></a>

The Scan_Masscan.py script provides a function that performs a network scan using the [Masscan](https://github.com/robertdavidgraham/masscan) port scanner, to scan the desired subnets of a network to identify live IPs in that subnet. This is to improve the performance of the downstream scripts by reducing the number of IPs to be to only those that respond to network probes. The script first saves the masscan results as an xml file, then the file get's parsed for just the IP addresses and removes any duplicates, then saves those IPs to a text file.

## Nmap Script <a name="nmap"></a>

The Scan_Nmap.py and Scan_Nmap_Bulk.py scripts use the output of the Scan_Masscan script to perform deeper scans on the IPs in the output files created by masscan using [Nmap](https://nmap.org/), saves the results in xml files, then parses those xml files using the Parse_Nmap script for the host name, IP, open ports, state of the ports (only open and filtered), services, products, possible operating systems, and accuracy of the OSes. Once the data is parsed it's inserted into a local MySQL database. The Scan_Namp and Scan_Nmap_Bulk scripts essentially work the same, however the Scan_Namp script performs scans on the IPs individually and if the scan get's interrupted prematurely, it saves the IPs it didn't scan in a text file called "Unscanned_Ips.txt" and on the next round of scanning the script first looks for files with this name and if any are found then those IPs are scanned first. The Scan_Nmap_Bulk script uses Nmaps native ability (-iL) to perform a scan with a text file of IPs as input and we found this to be much faster.

## Parse Nmap <a name="parsenmap"></a>

The Parse_Nmap script uses a python package called [libnmap](https://libnmap.readthedocs.io/en/latest/parser.html) to parse an Nmap xml file and insert the parsed data into a local MySQL database. 


## Tenable Script <a name="tenable"> </a>

This is a script that provides a function that uses the [Tenable.sc](https://docs.tenable.com/tenablesc/api/index.htm) API to import IPs into Tenable&#46;sc as a static asset. The function accepts the name of the asset and Ips you'd like to import (both are strings). If the asset already exists it updates that asset, if not it creates a new one. Returns the status code of the API (200 is success).


# Hope this is useful to someone :)
