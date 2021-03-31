import re
import getpass

import json
import sys
import requests
import time
import re


def r_write(rule,policyFile):


    line = {}
    placeholder = {}
    catgholder = {}
    temp ={}
    
    # Build dictionary of rule info
    # Start with keys that always exist
    line['ruleNum'] = rule['metadata']['ruleIndex']
    line['name'] = rule['name']
    line['enabled'] = rule['enabled']
    line['action'] = rule['action']
    line['logBegin'] = rule['logBegin']
    line['logEnd'] = rule['logEnd']
    line['sendEventsToFMC'] = rule['sendEventsToFMC']
    line['comment_list'] = []

    #This section will pull the URL details
    #By default if there is nothing present we add Any

    line['URLs'] = []
    placeholder['value'] = []
    catgholder['value'] = []

    if ('commentHistoryList' in rule.keys()):
        comment_list = []
        #print (len(rule['commentHistoryList']))
        #for len(rule['commentHistoryList']):
        temp['comments'] = rule['commentHistoryList']
        #print (line['comments'])
        #print (line['comments']['comment'])
        commLength = len (rule['commentHistoryList'])
        #while (commLength < 1) :
        for obj in temp['comments']:
            comment = obj['comment']
            date = obj['date']
            date = date.split(".")[0]
            if 'name' in obj['user'].keys():
                user = obj['user']['name']
            else:
                user="System"
            fullComment = user + ":" + date + ":" + comment
            comment_list.append(fullComment)
        line['comment_list'] = comment_list
        #print (line['comment_list'])

    #print(rule)
    try:
        #This section picks up the custom url used in the configuration
        #for item in rule['urls']['objects']:
        iterator =len(rule['urls'])
        if iterator == 2 :
            placeholder['value'] = rule['urls']['literals']
            #print(rule['urls'])
            loopvar = placeholder['value']
            #print (placeholder['value'])
            for obj in placeholder['value']:
                if re.search('Url',obj['type']):
                    #print ("matched")
                    line['URLs'].append(obj['url'])
            #print (line['URLs']) 
            #placeholder['value'] = rule['urls']['urlCategoriesWithReputation']
            #loopvar = placeholder['value']
            catgholder['value'] = rule['urls']['urlCategoriesWithReputation'] 
            #print (catgholder['value']['type'])
            for obj in catgholder['value']:
                loopvar = obj['category']['type']
                #print (loopvar)
                #print (obj['category']['name'])
                if re.search('URLCategory', loopvar):
                    line['URLs'].append(obj['category']['name'])
        if iterator == 1:
            try:
                placeholder['value'] = rule['urls']['literals']
                #print(rule['urls'])
                loopvar = placeholder['value']
                #print (placeholder['value'])
                for obj in placeholder['value']:
                    if re.search('Url',obj['type']):
                        #print ("matched")
                        line['URLs'].append(obj['url'])
            except KeyError:
                catgholder['value'] = rule['urls']['urlCategoriesWithReputation'] 
                #print (catgholder['value']['type'])
                for obj in catgholder['value']:
                    loopvar = obj['category']['type']
                    #print (loopvar)
                    #print (obj['category']['name'])
                    if re.search('URLCategory', loopvar):
                        line['URLs'].append(obj['category']['name'])

    except KeyError:
        line['URLs'] = ['any']


    #This section extracts out the usernames and groups that are used in the policy.
    line['users'] = []
    try:
        for item in rule['users']['objects']:
            line['users'].append(item['name']) 

    except KeyError:
        line['users'] = ['any']

    # Then handle getting keys that might not exist
    # Starting with items that may have multiple objects
    # Source Zones
    line['sourceZones'] = []
    #print (rule)
    try:
        #print ("Inside the zone try block")
        for item in rule['sourceZones']['objects']:
            # Put each object in a list, will join to str when printing to CSV
            #print(item['name'])
            line['sourceZones'].append(item['name'])
    except KeyError:
        line['sourceZones'] = ['any']

    # Destination Zones
    line['destZones'] = []
    try:
        for item in rule['destinationZones']['objects']:
            # Put each object in a list, will join to str when printing to CSV
            line['destZones'].append(item['name'])
    except KeyError:
        line['destZones'] = ['any']

    # Source Networks
    line['sourceNetworks'] = []
    placeholder['value'] = []

    try:
        #Inside the rule iteration per rule to look for if the parameter is built in network or manual
        #The loopvar is place holder for storing type of the built in variable used.
        for item in rule['sourceNetworks']:
            #print ("item")
            if re.search('objects',item):
                placeholder['value'] = rule['sourceNetworks']['objects']
                #print (placeholder['value'])
                for obj in placeholder['value']:
                    line['sourceNetworks'].append(obj['name'])
                    #print (line['sourceNetworks'])
            #This section looks for the use of literals in the source networks
            if re.search('literals',item):
                placeholder['value'] = rule['sourceNetworks']['literals']
                for obj in placeholder['value']:
                    line['sourceNetworks'].append(obj['value'])
                    #print (line['sourceNetworks'])

    except KeyError:
        line['sourceNetworks'] = ['any']

    # Destination Networks
    line['destNetworks'] = []
    try:
        #Inside the rule iteration per rule to look for if the parameter is built in network or manual
        #The loopvar is place holder for storing type of the built in variable used.
        for item in rule['destinationNetworks']:
            #print ("item")
            if re.search('objects',item):
                placeholder['value'] = rule['destinationNetworks']['objects']
                #print (placeholder['value'])
                for obj in placeholder['value']:
                    line['destNetworks'].append(obj['name'])
                    #print (line['sourceNetworks'])
            #This section looks for the use of literals in the source networks
            if re.search('literals',item):
                placeholder['value'] = rule['destinationNetworks']['literals']
                for obj in placeholder['value']:
                    line['destNetworks'].append(obj['value'])
                    #print (line['sourceNetworks'])

    except KeyError:
        line['destNetworks'] = ['any']


    # Source Ports
    line['sourcePorts'] = []
    try:
        for item in rule['sourcePorts']:
            loopvar = str(item)
            if re.search('literals',loopvar):
                #print ("inside if")
                item = rule['sourcePorts']['literals']
                for obj in item:
                    line['sourcePorts'].append(obj['port'])
                    #print(line['destPorts'])
            if re.search('objects',loopvar):
                #print ("inside object if")
                item = rule['sourcePorts']['objects']
                for obj in item:
                    line['sourcePorts'].append(obj['name'])
    except KeyError:
        line['sourcePorts'] = ['any']
   


    #conditional switch based on types of objects used in the port configuration
    #This is to ensure we take care of literals and built in objects without override.
    #print (line['ruleNum'])
    line['destPorts'] = []
    #for item in rule['destinationPorts']:
     #   print (item)
    #print (rule)


    try:
        for item in rule['destinationPorts']:
            #print (item)
            #print (rule['destinationPorts'])
            #item = rule['destinationPorts']['literals']
            #line['destports'] = item['port']
            #print (rule[])
            #print (item)
            loopvar = str(item)
            if re.search('literals',loopvar):
                #print ("inside if")
                item = rule['destinationPorts']['literals']
                for obj in item:
                    line['destPorts'].append(obj['port'])
                    #print(line['destPorts'])
            if re.search('objects',loopvar):
                #print ("inside object if")
                item = rule['destinationPorts']['objects']
                for obj in item:
                    line['destPorts'].append(obj['name'])
    except KeyError:
        line['destPorts'] = ['any']

    #print (line['destPorts'])


    #This section will pull the Applications details
    #By default if there is nothing present we add Any

    line['Applications'] = []
    try:
        #print ("Inside application try block")
        for item in rule['applications']:
            #Inserting the values into the list for printing
            #print ("Inside For")
            loopvar = rule['applications']['applications']
            #print (loopvar)
            for obj in loopvar:
                #print (obj['name'])
                line['Applications'].append(obj['name'])
            #line['Applications'].append(item['name'])
    except KeyError:
        line['Applications'] = ['any']

    #This section will pull the VLAN Tags details
    #By default if there is nothing present we add Any

    line['VlanTags'] = []
    try:
        for item in rule['vlanTags']:
            #print ("Inside the VLAN try block")
            #print (item)
            loopvar = str(item)
            #print (loopvar)
            if re.search('objects', item):
                item = rule['vlanTags']['objects']
                #print (item)
                for obj in item:
                    line['VlanTags'].append(obj['name'])

            if re.search("literals", loopvar):
                #print ("Matched with literals")
                #print (rule['vlanTags']['literals'])
                item = rule['vlanTags']['literals']
                for obj in item:
                    temp = str(obj['startTag'])
                    line['VlanTags'].append(temp)

    except KeyError:
        line['VlanTags'] = ['any']

    #print (line['VlanTags'])
    #Converting the indices into the format of string for display purpose.


    # Now get items that may not exist, but can only have one value
    # ipsPolicy
    try:
        line['ipsPolicy'] = rule['ipsPolicy']['name']
    except KeyError:
        line['ipsPolicy'] = 'none'

    # variableSet
    try:
        line['variableSet'] = rule['variableSet']['name']
    except KeyError:
        line['variableSet'] = 'none'

    # filePolicy
    try:
        line['filePolicy'] = rule['filePolicy']['name']
    except KeyError:
        line['filePolicy'] = 'none'

    # syslogConfig
    try:
        line['syslogConfig'] = rule['syslogConfig']['name']
    except KeyError:
        line['syslogConfig'] = 'none'

    # Print status to stdout
    #print (comment_list)
    #print("Writing rule #{0} to CSV...".format(line['ruleNum']))
    #print (line['URLs'])
    # Write rule to line in policyFile
    policyFile.write("{0}, {1}, {2}, {3}, {4}, {5}, {6}, {7}, {8}, {9}, {10}, {11}, {12}, {13}, {14}, {15}, {16}, {17}, {18}, {19}, {20}\n"
                     .format(line['ruleNum'], line['name'], line['enabled'], line['action'], 
                             ';'.join(line['VlanTags']),';'.join(line['sourceZones']), ';'.join(line['destZones']), 
                             ';'.join(line['sourceNetworks']), ';'.join(line['destNetworks']),
                             ';'.join(line['sourcePorts']), ';'.join(line['destPorts']), ':'.join(line['Applications']), ';'.join(line['URLs'],),';'.join(line['users']),';'.join(line['comment_list']),line['ipsPolicy'], 
                             line['variableSet'], line['filePolicy'], line['logBegin'], line['logEnd'],
                             line['sendEventsToFMC'], line['syslogConfig']))
