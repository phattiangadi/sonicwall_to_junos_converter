#!/usr/bin/env python3

"""
DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS FILE HEADER
Copyright (c) 2020 Juniper Networks, Inc.
All rights reserved.
"""
__appname__ = "sonicwall-parser.py"
__version__ = "v1"
__license__ = "GNU GPL 3.0 or later"
__developer__ = "Pradeep Hattiangadi"

# Module Declarations
import re
from netaddr import IPAddress
import logging
from argparse import ArgumentParser
from IPy import IP
import xml.etree.ElementTree as ET
import os
import sys
import shlex


# CONSTANTS:
RUNLOG_FILENAME = "runtime-conversion.log"
ERRLOG_FILENAME = "error.log"
DEBUG_FILENAME = "conversion-debug.log"
logging.basicConfig(filename=RUNLOG_FILENAME,level=logging.INFO)
logging.basicConfig(filename=ERRLOG_FILENAME,level=logging.ERROR)
logging.basicConfig(filename=DEBUG_FILENAME, level=logging.DEBUG)

DEBUG = True

# Introduction Banner
banner = """
#############################
#                           #
#  SONICWALL PARSER SCRIPT  #
#                           #
############################# """

### Parsing Functions

# Reset File
def open_reset_files(file):
    if os.path.exists(file):
        os.remove(file)
        file_FD = open(file, "w")
        return(file_FD)
    else:
        file_FD = open(file, "w")
        return(file_FD)
        
# Read File
def read_file(srcFile):
    with open(srcFile) as f:
        f = map(str.rstrip, f)
    return f


def clean_string(record):
    rm_chars = ['.', '(', ')', '"', '*', '/', ' - ', '__', '.', '+', '_-_']
    for char in rm_chars:
        if record.__contains__(' '):
            record = record.replace(' ', '_')
        elif record.__contains__('*'):
            record = record.replace('*', '_')
        elif record.__contains__('/'):
            record = record.replace('/', '-')
        elif record.__contains__(' - '):
            record = record.replace(' - ', '_')
        elif record.__contains__('__'):
            record = record.replace('__', '_')
        elif record.__contains__('+'):
            record = record.replace('+', '_')
        elif record.__contains__('_-_'):
            record = record.replace('_-_', '_')
        else:
            record = record.replace(char, '')
    return record

# PARSE ADDRESS IPv4
def parse_address_v4(fileContent):
    address_list_v4 = []
    address_dict_v4 = {}
    for line in fileContent:
        raw_address = line
        if re.match('^address-object ipv4', line):
            for line in fileContent:
                line=line.strip()
                if 'no host' in line:
                    logging.error('No Host Address Record Found ==> Address Name: %s \n', raw_address)
                    continue
                if 'no network' in line:
                    logging.error('No Network Address Record Found ==> Address Name: %s \n', raw_address)
                    continue
                if 'name' in line:
                    tmp = line.split(maxsplit=1)
                    name = tmp[1].replace(" ", "_").strip('"')
                    address_list_v4.append(name)
                    continue
                if 'zone' in line:
                    tmpzone = line.split()
                    zone = tmpzone[1]
                    address_list_v4.append(zone)
                    continue
                if 'host' in line:
                    tmpIP = line.split()
                    address = tmpIP[1]
                    hostInfo = ("{}-{}".format('host', address))
                    address_list_v4.append(hostInfo)
                    continue
                if 'network' in line:
                    tmpNet = line.split()
                    network = tmpNet[1]
                    subnet = tmpNet[2]
                    netInfo = ("{}-{}-{}".format('network', network, subnet))
                    address_list_v4.append(netInfo)
                    continue
                if 'range' in line:
                    tmpRange = line.split()
                    startIP = tmpRange[1]
                    EndIP = tmpRange[2]
                    netRange = ("{}-{}-{}".format('range', startIP, EndIP))
                    address_list_v4.append(netRange)
                    continue
                if "exit" in line and len(line)==4:
                    logging.info('Address Object %s <==> Converted to <==> Address Name: %s \n', raw_address, address_list_v4)
                    first, rest = address_list_v4[0], address_list_v4[1:]
                    address_dict_v4[first] = rest                    
                    address_list_v4 = []
                    break
    return(address_dict_v4)

# PARSE ADDRESS IPv6
def parse_address_v6(fileContent):
    address_list_v6 = []
    address_dict_v6 = {}
    for line in fileContent:
        raw_address_ipv6 = line
        if re.match('^address-object ipv6', line):
            for line in fileContent:
                line = line.strip()
                if 'no host' in line:
                    logging.error('No IPv6 Host Address Object Data Found ==> Address Name: %s \n', raw_address_ipv6)
                    continue
                if 'no network' in line:
                    logging.error('No IPv6 Network Address Object Data Found ==> Address Name: %s \n', raw_address_ipv6)
                    continue
                if 'name' in line:
                    tmp = line.split(maxsplit=1)
                    name = tmp[1].replace(" ", "_").strip('"')
                    address_list_v6.append(name)
                    continue
                if 'zone' in line:
                    tmpzone = line.split()
                    zone = tmpzone[1]
                    address_list_v6.append(zone)
                    continue
                if 'host' in line:
                    tmpIP = line.split()
                    address = tmpIP[1]
                    hostInfo = ("{}-{}".format('host', address))
                    address_list_v6.append(hostInfo)
                    continue
                if 'network' in line:
                    tmpNet = line.split()
                    network = tmpNet[1]
                    subnet = tmpNet[2]
                    netInfo = ("{}-{}-{}".format('network', network, subnet))
                    address_list_v6.append(netInfo)
                    continue
                if 'range' in line:
                    tmpRange = line.split()
                    startIP = tmpRange[1]
                    EndIP = tmpRange[2]
                    netRange = ("{}-{}-{}".format('range', startIP, EndIP))
                    address_list_v6.append(netRange)
                    continue
                if "exit" in line and len(line) == 4:
                    logging.info('Address Object %s <==> Converted to <==> Address Name: %s \n', raw_address_ipv6, address_list_v6)
                    first, rest = address_list_v6[0], address_list_v6[1:]
                    address_dict_v6[first] = rest
                    address_list_v6 = []
                    break
    return(address_dict_v6)


# PARSE ADDRESS GROUPS IPv4
def parse_address_groups_v4(fileContent):
    addrgrp_list_v4 = []
    addrgrp_dict_v4 = {}
    for line in fileContent:
        raw_address_grp_ipv4 = line
        if re.match('^address-group ipv4', line):
            for line in fileContent:
                line = line.strip()
                if 'name' in line:
                    tmp = line.split(maxsplit=1)
                    name = tmp[1].replace(" ", "_").strip('"')
                    addrgrp_list_v4.append(name)
                    continue
                if 'address-object ipv4' in line:
                    tmpIP = line.split()
                    address = tmpIP[2:]
                    b = ['_'.join(address)]
                    newaddress = clean_string(b[0])
                    hostInfo = ("{}-{}".format('host',newaddress))
                    addrgrp_list_v4.append(hostInfo)
                    continue
                if 'address-group ipv4' in line:
                    tmpIP = line.split()
                    address = tmpIP[2:]
                    b = ['_'.join(address)]
                    newaddress = clean_string(b[0])
                    hostInfo = ("{}-{}".format('group', newaddress))
                    addrgrp_list_v4.append(hostInfo)
                    continue
                if "exit" in line and len(line) == 4:
                    logging.info('Address Group Object %s <==> Converted to <==> Address Name: %s \n', raw_address_grp_ipv4, addrgrp_list_v4)
                    first, rest = addrgrp_list_v4[0], addrgrp_list_v4[1:]
                    addrgrp_dict_v4[first] = rest
                    addrgrp_list_v4 = []
                    break
    return(addrgrp_dict_v4)

# PARSE ADDRESS GROUPS IPv6
def parse_address_groups_v6(fileContent):
    addrgrp_list_v6 = []
    addrgrp_dict_v6 = {}
    for line in fileContent:
        raw_address_grp_ipv6 = line
        if re.match('^address-group ipv6', line):
            for line in f:
                line = line.strip()
                if 'name' in line:
                    tmp = line.split(maxsplit=1)
                    name = tmp[1].replace(" ", "_").strip('"')
                    addrgrp_list_v6.append(name)
                    continue
                if 'address-object ipv4' in line:
                    tmpIP = line.split()
                    address = tmpIP[2:]
                    b = ['_'.join(address)]
                    newaddress = clean_string(b[0])
                    hostInfo = ("{}-{}".format('host', newaddress))
                    addrgrp_list_v6.append(hostInfo)
                    continue
                if 'address-group ipv4' in line:
                    tmpIP = line.split()
                    address = tmpIP[2:]
                    b = ['_'.join(address)]
                    newaddress = clean_string(b[0])
                    hostInfo = ("{}-{}".format('group',newaddress))
                    addrgrp_list_v6.append(hostInfo)
                    continue
                if "exit" in line and len(line) == 4:
                    logging.info('Address Group IPv6 Object %s <==> Converted to <==> Address Name: %s \n', raw_address_grp_ipv6, addrgrp_list_v6)
                    first, rest = addrgrp_list_v6[0], addrgrp_list_v6[1:]
                    addrgrp_dict_v6[first] = rest
                    addrgrp_list_v6 = []
                    break
    return(addrgrp_dict_v6)

# PARSE POLICIES
def parse_policies(fileContent):    
    policy_list = []
    policy_dict = {}
    policyName = 'ACCESS_RULE'
    policyCount = 1
    for line in fileContent:
        if re.match('^access-rule', line):
            raw_policy_info = line
            for line in fileContent:
                line = line.strip()
                if re.match('^no name', line):
                    name = ('{}{}'.format(policyName, policyCount))
                    policyCount += 1
                    policy_list.append(str(name))
                if re.match('^name', line):
                    #print(line)
                    tmp = line.split(maxsplit=1)
                    name = tmp[1].replace(" ", "_").strip('"')
                    policy_list.append(str(name))
                    continue
                if re.match('^from', line):
                    tmpIP = line.split()
                    from_zone = tmpIP[1:]
                    if len(from_zone) > 1:
                        b = ['_'.join(from_zone)]
                        #print(b[0])
                        hostInfo = ("{}-{}".format('from', b[0]))
                    elif len(from_zone) == 1:
                        hostInfo = ("{}-{}".format('from', from_zone[0]))
                        #print(from_zone[0])
                    policy_list.append(hostInfo)
                    continue
                if re.match('^to', line):
                    tmpIP = line.split()
                    to_zone = tmpIP[1:]
                    if len(to_zone) > 1:
                        to_zone_cleaned = ['_'.join(to_zone)]
                        #print(to_zone_cleaned[0])
                        hostInfo = (
                            "{}-{}".format('toZone', to_zone_cleaned[0]))
                    elif len(to_zone) == 1:
                        hostInfo = ("{}-{}".format('toZone', to_zone[0]))
                        #print(to_zone[0])
                    policy_list.append(hostInfo)
                    continue
                if re.match('^source address', line):
                    tmpIP = line.split()
                    if len(tmpIP) == 3:
                        src_addr = tmpIP[2:]
                        if len(src_addr) > 1:
                            src_tmp = ['_'.join(src_addr)]
                            src_cleaned = clean_string(src_tmp[0])
                            #print(src_cleaned)
                            hostInfo = ("{}-{}".format('src', src_cleaned))
                        elif len(src_addr) == 1:
                            #print(src_addr[0])
                            hostInfo = ("{}-{}".format('src', src_addr[0]))
                    else:
                        src_addr = tmpIP[3:]
                        if len(src_addr) > 1:
                            src_tmp = ['_'.join(src_addr)]
                            src_cleaned = clean_string(src_tmp[0])
                            #print(src_cleaned)
                            hostInfo = ("{}-{}".format('src', src_cleaned))
                        elif len(src_addr) == 1:
                            #print(src_addr[0])
                            hostInfo = ("{}-{}".format('src', src_addr[0]))
                    policy_list.append(hostInfo)
                    continue
                if re.match('^destination address', line):
                    tmpIP = line.split()
                    if len(tmpIP) == 3:
                        dest_addr = tmpIP[2:]
                        if len(dest_addr) > 1:
                            dest_tmp = ['_'.join(dest_addr)]
                            dest_cleaned = clean_string(dest_tmp[0])
                            #print(dest_cleaned)
                            hostInfo = ("{}-{}".format('dest', dest_cleaned))
                        elif len(dest_addr) == 1:
                            #print(dest_addr[0])
                            hostInfo = ("{}-{}".format('dest', dest_addr[0]))
                    else:
                        dest_addr = tmpIP[3:]
                        if len(dest_addr) > 1:
                            dest_tmp = ['_'.join(dest_addr)]
                            dest_cleaned = clean_string(dest_tmp[0])
                            #print(dest_cleaned)
                            hostInfo = ("{}-{}".format('dest', dest_cleaned))
                        elif len(dest_addr) == 1:
                            #print(dest_addr[0])
                            hostInfo = ("{}-{}".format('dest', dest_addr[0]))
                    policy_list.append(hostInfo)
                    continue
                if re.match('^service', line):
                    #print(line)
                    tmpIP = line.split()
                    if len(tmpIP) == 2:
                        service = tmpIP[1:]
                        if len(service) > 1:
                            service_tmp = ['_'.join(service)]
                            service_cleaned = clean_string(service_tmp[0])
                            #print(service_cleaned)
                            hostInfo = (
                                "{}-{}".format('appData', service_cleaned))
                        elif len(service) == 1:
                            #print(service[0])
                            hostInfo = ("{}-{}".format('appData', service[0]))
                    else:
                        service = tmpIP[2:]
                        if len(service) > 1:
                            service_tmp = ['_'.join(service)]
                            service_cleaned = clean_string(service_tmp[0])
                            #print(service_cleaned)
                            hostInfo = (
                                "{}-{}".format('appData', service_cleaned))
                        elif len(service) == 1:
                            #print(service[0])
                            hostInfo = ("{}-{}".format('appData', service[0]))
                    policy_list.append(hostInfo)
                    continue
                if re.match('^action', line):
                    tmp = line.split(maxsplit=1)
                    action = tmp[1].replace(" ", "_").strip('"')
                    #print(action)
                    actionInfo = ("{}-{}".format('action', action))
                    policy_list.append(actionInfo)
                    continue
                if re.match('^logging', line) or re.match('^no logging', line):
                    if re.match('^logging', line):
                        logging = 'YES'
                        logInfo = ("{}-{}".format('log', logging))
                    elif re.match('^no logging', line):
                        logging = 'NO'
                        logInfo = ("{}-{}".format('log', logging))
                    policy_list.append(logInfo)
                    continue
                if re.match('^comment', line) or re.match('^no comment', line):
                    if re.match('^comment', line):
                        tmp = line.split(maxsplit=1)
                        comment = tmp[1]
                        descInfo = ("{}-_-{}".format('description', comment))
                    elif re.match('^no comment', line):
                        comment = 'NO'
                        descInfo = ("{}-_-{}".format('description', comment))
                    policy_list.append(descInfo)
                    continue
                if "exit" in line and len(line) == 4:
                    #print(line)
                    first, rest = policy_list[0], policy_list[1:]
                    policy_dict[first] = rest
                    policy_list = []
                    break
    return(policy_dict)

# PARSE ZONE INFO
def parse_zones(fileContent):
    zone_list = []
    for line in fileContent:
        raw_zone = line
        if re.match('^zone', line):
            zone_tmp = line.split(maxsplit=1)
            zone_name = zone_tmp[1]
            zone_list.append(zone_name)
            for line in fileContent:
                line = line.strip()
                if "exit" in line and len(line) == 4:
                    logging.info('Zone name %s <==> Converted to <==> Zone name: %s \n', raw_zone, zone_name)
                    break
    return(zone_list)

# PARSE SERVICES (APPLICATION) INFO
def parse_services(fileContent):
    services_list = []
    services_dict = {}
    for line in fileContent:
        raw_svc_obj = line
        if re.match('^service-object', line):
            line = line.strip()
            svc_tmp_list = shlex.split(line)
            svc_length = len(svc_tmp_list)
            if svc_length == 5:
                for i in svc_tmp_list:
                    service_nametmp = svc_tmp_list[1]
                    service_name = clean_string(service_nametmp)
                    svc_protocol = svc_tmp_list[2]
                    svc_port_low = svc_tmp_list[3]
                    svc_port_high = svc_tmp_list[4]
                    services_dict[service_name] = (
                        "{}-{}-{}".format(svc_protocol, svc_port_low, svc_port_high))
            elif svc_length == 3:
                for i in svc_tmp_list:
                    service_nametmp = svc_tmp_list[1]
                    service_name = clean_string(service_nametmp)
                    svc_protocol = svc_tmp_list[2]
                    services_dict[service_name] = ("{}".format(svc_protocol))
            elif svc_length == 4:
                for i in svc_tmp_list:
                    service_nametmp = svc_tmp_list[1]
                    service_name = clean_string(service_nametmp)
                    svc_protocol = svc_tmp_list[2]
                    svc_type = svc_tmp_list[3]
                    services_dict[service_name] = (
                        "{}-{}".format(svc_protocol, svc_type))
            logging.info('Service name %s <==> Converted to <==> Zone name: %s \n', raw_svc_obj, services_dict)

    return(services_dict)

# PARSE SERVICE GROUP (APPLICATION-SET) INFO
def parse_service_group(fileContent):
    serviceGrp_list = []
    serviceGrp_dict = {}
    for line in fileContent:
        raw_svcgrp_obj = line
        if re.match('^service-group', line):
            nametmp = shlex.split(line)
            name = clean_string(nametmp[1])
            #print(name)
            serviceGrp_list.append(name)
            for line in fileContent:
                line = line.strip()
                if 'service-object' in line:
                    svc_tmp_list = shlex.split(line)
                    service = svc_tmp_list[1]
                    newservice = clean_string(service)
                    #print(newservice)
                    serviceGrpInfo = ("{}::{}".format('app', newservice))
                    serviceGrp_list.append(serviceGrpInfo)
                    continue
                if 'service-group' in line:
                    svc_tmp_list = shlex.split(line)
                    service = svc_tmp_list[1]
                    newservice = clean_string(service)
                    #print(newservice)
                    serviceGrpInfo = ("{}::{}".format('group', newservice))
                    serviceGrp_list.append(serviceGrpInfo)
                    continue
                if "exit" in line and len(line) == 4:
                    if len(serviceGrp_list) != 1:
                        first, rest = serviceGrp_list[0], serviceGrp_list[1:]
                        serviceGrp_dict[first] = rest
                        logging.info('Service name %s <==> Converted to <==> Zone name: %s \n', raw_svcgrp_obj, serviceGrp_list)
                        serviceGrp_list = []
                        break
                    else:
                        logging.error('Service name %s did not have any members:', raw_svcgrp_obj)
                        break
    
    return(serviceGrp_dict)

###############################################################
# Convert to Juniper Configuration
# ADDRESS CLI
def get_address_cli(address_dict):
    for key, value in address_dict.items():
            nametmp = key.replace('(', '')
            name = nametmp.replace(')', '')
            for i in value:
                if len(i) == 1:
                    continue
                if 'host' in i:
                    address = i.split('-')
                    print("set security address-book global address \"{}\" {}".format(name, address[1]))
                if 'network' in i:
                    if not '/' in i:
                        network = i.split('-')
                        subnet = IPAddress(network[2]).netmask_bits()
                        print("set security address-book global address \"{}\" {}/{}".format(name, network[1], subnet))
                    else:
                        network = i.split('-')
                        print("set security address-book global address \"{}\" {}{}".format(name, network[1], network[2]))
                if 'range' in i:
                    range = i.split('-')
                    print("set security address-book global address \"{}\" range-address {} to {}".format(name, range[1], range[2]))                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                        

# ADDRESS GROUP CLI
def get_addrgrp_cli(addrgrp_dict):
    for key, value in addrgrp_dict.items():
        nametmp = key.replace('(', '')
        name = nametmp.replace(')', '')
        for i in value:
            if len(i) == 1:
                continue
            if 'host' in i:
                address = i.split('-')
                print("set security address-book global address-set \"{}\" address {}".format(name, address[1]))
            if 'group' in i:
                address = i.split('-')
                print("set security address-book global address-set \"{}\" address-set {}".format(name, address[1]))

# POLICY CLI
def get_policy_cli(policy_dict):
    for key, value in policy_dict.items():
        policy_nametmp = key.replace('(', '')
        policy_name = policy_nametmp.replace(')', '')
        for i in value:
            if 'from' in i:
                from_tmp = i.split('-')
                from_zone = from_tmp[1]
                continue
            if 'toZone' in i:
                to_tmp = i.split('-')
                to_zone = to_tmp[1]
                continue
            if 'action' in i:
                action_tmp = i.split('-')
                if action_tmp[1] == 'allow':
                    action = 'permit'
                elif action_tmp[1] == 'deny':
                    action = 'deny'
                continue
            if 'src' in i:
                src_tmp = i.split('-')
                src = src_tmp[1]
                continue
            if 'dest' in i:
                dest_tmp = i.split('-')
                dest = dest_tmp[1]
                continue
            if 'appData' in i:
                app_tmp = i.split('-')
                application = app_tmp[1]
                continue
            if 'log' in i:
                log_tmp = i.split('-')
                if log_tmp[1] == 'YES':
                    log_sess_init = 'session-init'
                    log_sess_close = 'session-close'
                    continue
                else:
                    continue
            if 'description' in i:
                desc_tmp = i.split('-_-')
                description = desc_tmp[1]
        
        print("set security policies from-zone {} to-zone {} policy {} match source-address {} destination-address {} application {}".format(from_zone, to_zone, policy_name, src, dest, application))
        if description != 'NO':
            print("set security policies from-zone {} to-zone {} policy {} description {}".format(from_zone, to_zone, policy_name, description))
        print("set security policies from-zone {} to-zone {} policy {} then {}".format(from_zone, to_zone, policy_name, action))
        print("set security policies from-zone {} to-zone {} policy {} then log {} {}".format(from_zone, to_zone, policy_name, log_sess_init, log_sess_close))

# ZONE CLI
def get_zone_cli(zone_list):
    for i in zone_list:
        zone_nametmp = i.replace('(', '')
        zone_name = zone_nametmp.replace(')', '')
        print("set security zones security-zone {}".format(zone_name))

# SERVICES (APPLICATION) CLI
def get_service_cli(services_dict):
    for key, value in services_dict.items():
        svc_nametmp = key.replace('(', '')
        svc_name = svc_nametmp.replace(')', '')
        svc_tmp_list = value.split('-')
        #print(svc_tmp_list)
        if 'ICMP' in svc_tmp_list:
            continue
        if 'ICMPV6' in svc_tmp_list:
            continue
        if 'IGMP' in svc_tmp_list:
            continue
        if len(svc_tmp_list) == 2:
            continue
        if len(svc_tmp_list) == 3:
            svc_protocol = svc_tmp_list[0].lower()
            svc_port_low = svc_tmp_list[1]
            svc_port_high = svc_tmp_list[2]
            print("set applications application {} protocol {} destination-port {}-{}".format(
                svc_name, svc_protocol, svc_port_low, svc_port_high))

# SERVICE GROUP (APPLICATION-SET) CLI
def get_service_group_cli(service_group_dict):
    for key, value in service_group_dict.items():
        if not 'ICMP' in key or 'ICMPV6' in key or 'IGMP' in key:
            svc_nametmp = key.replace('(', '')
            svc_name = svc_nametmp.replace(')', '')
        else:
            continue
        for i in value:
            if 'ICMP' in i:
                continue
            if 'ICMPV6' in i:
                continue
            if 'IGMP' in i:
                continue
            if 'app' in i:
                svctmp_app = i.split('::')
                svc_app = svctmp_app[1]
                print(
                    "set applications application-set {} application {}".format(svc_name, svc_app))
            if 'group' in i:
                svctmp_group = i.split('::')
                svc_group = svctmp_group[1]
                print(
                    "set applications application-set {} application-set {}".format(svc_name, svc_group))

# __main__
##################
# Options Parser #
##################
parser = ArgumentParser()
parser.add_argument("-i", "--interface", help="interface", action='store_true')
parser.add_argument("-z", "--zone", help="zone", action='store_true')
parser.add_argument("-a", "--addresses", help="addresses", action='store_true')
parser.add_argument("-g", "--addressGroups", help="addressGroups", action='store_true')
parser.add_argument("-s", "--services", help="services", action='store_true')
parser.add_argument("-sg", "--servicegroups", help="servicegroups", action='store_true')
parser.add_argument("-fp", "--fwpolicies", help="firewallpolicies", action='store_true')
parser.add_argument("-np", "--natpolicies", help="natpolicies", action='store_true')
parser.add_argument("-v", "--vpn", help="vpn", action='store_true')
parser.add_argument("-A", "--all", help="all", action='store_true')
parser.add_argument("-f", "--fileInput", help="fileInput")

try:
	args = parser.parse_args()
except IOError:
	parser.error("IO ERROR Occurred")
	sys.exit(0)

###################
# MAIN Code Block #
###################
print("{}".format(banner))

if (args.all and args.fileInput):
    pass

if (args.addresses and args.fileInput):
    with open(args.fileInput) as f:
        f1 = map(str.rstrip, f)
        address_data_v4 = parse_address_v4(f1)
        datav4 = get_address_cli(address_data_v4)
    with open(args.fileInput) as f:
        f2 = map(str.rstrip, f)
        address_data_v6 = parse_address_v6(f2)
        datav6 = get_address_cli(address_data_v6)

if (args.addressGroups and args.fileInput):
    with open(args.fileInput) as f:
        f1 = map(str.rstrip, f)
        addressgrp_data_v4 = parse_address_groups_v4(f1)
        datav4 = get_addrgrp_cli(addressgrp_data_v4)
    with open(args.fileInput) as f:
        f2 = map(str.rstrip, f)
        addressgrp_data_v6 = parse_address_groups_v6(f2)
        datav6 = get_addrgrp_cli(addressgrp_data_v6)

if (args.fwpolicies and args.fileInput):
    with open(args.fileInput) as f:
        f1 = map(str.rstrip, f)
        fw_policies = parse_policies(f1)
        datav4 = get_policy_cli(fw_policies)

if (args.services and args.fileInput):
    with open(args.fileInput) as f:
        f1 = map(str.rstrip, f)
        services = parse_services(f1)
        serviceData = get_service_cli(services)

if (args.servicegroups and args.fileInput):
    with open(args.fileInput) as f:
        f1 = map(str.rstrip, f)
        serviceGroup = parse_service_group(f1)
        serviceGrpData = get_service_group_cli(serviceGroup)


if (args.natpolicies and args.fileInput):
    pass

if (args.vpn and args.fileInput):
    pass
