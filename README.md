# Sonicwall to Junos Converter

This script converts Sonicwall configuration export to Junos configuration using the set format.

# Installation
1. Install Python3 and pip3. (Installing the python3 MAC OS package should have both the required libraries.) - https://www.python.org/downloads/
2. Install the packages used for the script.
pip3 install -r requirements.txt
 
Run the script:
To get help on the script.
 
root@linux:~/ # ./sonicwall-parser.py -h
usage: sonicwall-parser.py [-h] [-i] [-z] [-a] [-g] [-s] [-sg] [-fp] [-np]
                           [-v] [-A] [-f FILEINPUT]
 
optional arguments:
  -h, --help            show this help message and exit
  -i, --interface       interface
  -z, --zone            zone
  -a, --addresses       addresses
  -g, --addressGroups   addressGroups
  -s, --services        services
  -sg, --servicegroups  servicegroups
  -fp, --fwpolicies     firewallpolicies
  -np, --natpolicies    natpolicies
  -v, --vpn             vpn
  -A, --all             all
  -f FILEINPUT, --fileInput FILEINPUT
                        fileInput
 
 
# To convert Address and Address Groups, run the commands below.
 
### Addresses / Network Subnets / DNS:
./sonicwall-parser.py -a -f <Sonicwall Export File> | tee -a address.txt
 
### Address Groups:
./sonicwall-parser.py -g -f <Sonicwall Export File> | tee -a address-groups.txt
 
 
# To convert Services and Service Groups.
 
### Services:
./sonicwall-parser.py -s -f <Sonicwall Export File> | tee -a services.txt
 
### Service Groups: 
./sonicwall-parser.py -sg -f <Sonicwall Export File> | tee -a service-groups.txt
 
# To convert firewall policies.

### Firewall Policies:
./sonicwall-parser.py -fp -f <Sonicwall Export File> | tee -a firewall-policies.txt
 
