# Custom Build 1.9
# Sets logBeg to false where rule Action is "ALLOW" when logBeg and logEnd are set to True
# Anupam Pavithran (anpavith@cisco.com) | Cisco Systems India

import re
import getpass
import json
import sys
import requests
import time
import warnings
from sys import getsizeof
from rule_writer import r_write 

#ruledump=open('ruledump.txt','w')

wait_flag=0

warnings.filterwarnings('ignore', message='Unverified HTTPS request')

print('###########################################################')
print('#               ACCESS CONTROL POLICY                     #')
print('###########################################################')
print('#         anpavith              Cisco Systems India       #')
print('###########################################################')

def chunkIt(seq, num):
    avg = len(seq) / float(num)
    out = []
    last = 0.0

    while last < len(seq):
        out.append(seq[int(last):int(last + avg)])
        last += avg

    return out

def get(rules_url,param=dict()):
    
    param['offset']='0'
    param['limit']='1000'
    param['expanded']='true'
    
    responses = list()
    r = get_request(rules_url,param)
    if r.status_code==200 or r.status_code==201:
        responses.append(r)    
        payload = r.json()
    else:
        print('Error occured after get_request in get()')
        print(r.text)
        sys.exit()
    if 'paging' in payload.keys():

        while 'items' in payload.keys() and 'next' in payload['paging']:

            param['offset']=str(int( param['offset'])+1000)
            response_page = get_request(rules_url, param)
            payload=response_page.json()
            responses.append(response_page)
    return responses

def get_request(rules_url,param): 

    r = requests.get(rules_url, headers=headers,params=param, verify=False)
    rj=r.json()
    #ruledump.write(str(rj)+str(r.status_code)+"\n")
    if wait_flag==1:
        print(">", end ="", flush=True)


    if r.status_code == 401:
        if 'Access token invalid' in str(r.json()):
            #print(headers)
            refresh()
            #print(headers)
            r = requests.get(rules_url, headers=headers,params=param, verify=False)
            #print(r.status_code)
            #print(r.text)
            if wait_flag==1:
                print(">", end ="", flush=True) 
    elif bool(re.match(r"Session.*\d+ is invalid",str(rj))) is True:
            print(headers)
            refresh()
            print(headers)
            r = requests.get(rules_url, headers=headers,params=param, verify=False)
            if wait_flag==1:
                print(">", end ="", flush=True) 
    return r


#=================================================================
#Section to take the device details and credentials from the user
#=================================================================


device = input("Enter the device IP address  : ")
username = input("Enter the username of the FMC: ")
password = getpass.getpass("Enter the password of the FMC: ")



#================================================================
# Authenticate and domain selection 
#================================================================

global headers
headers = {'Content-Type': 'application/json'}

    
def authenticate():

    r = None
    api_auth_path = "/api/fmc_platform/v1/auth/generatetoken"
    auth_url = "https://" + device + api_auth_path

    try:

      r = requests.post(auth_url, headers=headers, auth=requests.auth.HTTPBasicAuth(username,password), verify=False)
      auth_headers = r.headers
      auth_token = auth_headers.get('X-auth-access-token', default=None)
      refresh_token=auth_headers.get('X-auth-refresh-token', default=None)
      if auth_token == None:
          print("Authentication not found. Exiting...")
          print(r.reason)
          sys.exit()
      else:
        return(auth_headers,auth_token,refresh_token)
    except Exception as err:
      print ("Error in generating Authentication token --> "+str(err))
      sys.exit()

auth_headers,auth_token,refresh_token=authenticate()

refresh_headers={}
refresh_headers['X-auth-refresh-token']=auth_headers.get('X-auth-refresh-token')
refresh_headers['X-auth-access-token']=auth_headers.get('X-auth-access-token')



def refresh():

    global refresh_counter
    global headers
    refresh_counter=1

    print('\n###########################################################')

   
    refresh_url = "https://" + device + "/api/fmc_platform/v1/auth/refreshtoken"
    if refresh_counter > 3:
        print('Authentication token has already been used 3 times, API re-authentication will be performed')
        authenticate()

    try:
        refresh_counter += 1
        r = requests.post(refresh_url, headers=refresh_headers, verify=False)
        auth_token = r.headers.get('X-auth-access-token', default=None)
        refresh_token = r.headers.get('X-auth-refresh-token', default=None)
        print('auth token-->',auth_token)
        print('refresh token-->',refresh_token)
        if not auth_token or not refresh_token:
            print('Could not refresh tokens')
            sys.exit()

        headers['X-auth-access-token'] = auth_token
        headers['X-auth-refresh-token'] = refresh_token

        refresh_headers['X-auth-access-token']=auth_token
        refresh_headers['X-auth-refresh-token']=refresh_token

    except ConnectionError:
        print('Could not connect. Max retries exceeded with url')
    except Exception as err:
        print ("Refresh Function Error  --> "+str(err))
    print('Successfully refreshed authorization token')


headers['X-auth-access-token']=auth_token
domain=auth_headers['DOMAIN_UUID']

name_list=[]
uuid_list=[]

new_list=json.loads(auth_headers['DOMAINS'])
domain_len=len(new_list)

if domain_len>1:
    for dict_item in new_list:
        name_list.append(dict_item["name"])
        uuid_list.append(dict_item["uuid"])
    i=0
    while i<domain_len:

        print(i+1,name_list[i],uuid_list[i])
        i=i+1
    user_domain = int(input ("Choose the domain from which ACP has to be listed (numeric value):"))
    domain = uuid_list[user_domain-1]

#===============================================================
# Get the list of ACP and ACP selection 
#===============================================================

api_path = "/api/fmc_config/v1/domain/"+ domain+ "/policy/accesspolicies"    # param
url = "https://" + device + api_path
if (url[-1] == '/'):
    url = url[:-1]

allEntries=[]
acp_name =[]
acp_id = []

print('###########################################################')
print('#             ACCESS CONTROL POLICY LIST                  #')
print('###########################################################')

url = "https://" + device + api_path;
r = get(url)

for response in r:
    iterate = 1
    for counter in response.json()['items']:
        acp_name.append(counter['name'])
        acp_id.append(counter['id'])

        print (iterate, counter['name'])
        iterate = iterate + 1

print('###########################################################')
policy_id_1 = input("Choose the ACP Number (integer value):")
policy_id_1 = int(policy_id_1)

ac_policy_1 = acp_name[policy_id_1 - 1]
acp_id_1=acp_id[policy_id_1 - 1]

log=open('ACP_'+acp_name[policy_id_1 - 1]+'_Report_'+str(time.time())+'.csv','w')  #ACP-1
log.write("#, name, enabled, action, VlanTags, sourceZones, destZones, sourceNetworks, destNetworks, sourcePorts, "
                 "destPorts, Applications, URLs, users,comments,ipsPolicy, variableSet, filePolicy, logBegin, logEnd, sendEventsToFMC, syslogConfig\n")


report_flag=0

print('###########################################################')
print('                Available operations on ACP                ')
print('###########################################################')
print('1. Report rules with Action = Allow, LogBeg & LogEnd ')
print('2. Disable logging at Beg if Allow, LogBeg & LogEnd')
print('###########################################################')

report_flag = int(input("Enter your selection (integer value) : "))

print('###########################################################')

rules_url = "https://" + device + "/api/fmc_config/v1/domain/"+domain+"/policy/accesspolicies/"+acp_id[policy_id_1 - 1]+"/accessrules"

wait_flag=1
print('Processing, Please Wait')
r=None
acp_rules = get(rules_url)
wait_flag=0
print('\nRetrived all rules from ',acp_name[policy_id_1 - 1])

bulk_ace_list=[]
rule_counter=0
custom_rule_counter=0

if len(acp_rules)==1 and acp_rules[0].json()['paging'].get('count')==0:
    print('No rules present in ACP')
    sys.exit()
else:

    for response in acp_rules:

        for rule in response.json()['items']:
            rule_counter=rule_counter+1

            if rule['action'] == "ALLOW" or rule['action'] == "TRUST": 
                if 'logBegin' in rule and 'logEnd' in rule:
                    #print (rule['logBegin'], rule['logEnd'])

                    if rule['logBegin'] is True and rule['logEnd'] is True:
                            custom_rule_counter = custom_rule_counter +1
                            if report_flag==1:
                                r_write(rule,log)
                            else:
                                r_write(rule,log)
                                rule['logBegin']='false'
                                rule.pop('metadata')
                                rule.pop('links')
                                #rule.pop('id')
                                bulk_ace_list.append(rule)
                                

print('###########################################################')

print("Total number of rules in Access Control Policy      : ",rule_counter)
print("Number of rules with Allow action & LogBeg & LogEnd : ",custom_rule_counter)

if report_flag==1:
    print("The report has been created with name ",log.name)
    print('###########################################################')

    sys.exit()
if custom_rule_counter==0:
    print("No rules present")
    sys.exit()

refresh()

#=====================================================================================
# Bulk update ACP
#=====================================================================================
print('###########################################################')



post_url ="https://" +  device + "/api/fmc_config/v1/domain/"+domain+"/policy/accesspolicies/"+acp_id[policy_id_1 -1]+"/accessrules?bulk=true"


try:

    print("Processing, Please Wait!")
 

    bulk_ace_list_size=len(bulk_ace_list)

    if bulk_ace_list_size>500:
    
        for not_so_bulk_list in chunkIt(bulk_ace_list,int((bulk_ace_list_size)/500)+1):
            print('\nNumber of rules being posted is ',len(not_so_bulk_list))
    
            print('Size of data being posted ', getsizeof(not_so_bulk_list),' Bytes')
            time.sleep(2)
            print(headers)
            r = requests.put(post_url, data=json.dumps(not_so_bulk_list), headers=headers, verify=False)
            status_code = r.status_code
            reason=r.reason

            if (status_code == 200 or status_code == 201):
                print("Post was successful!")
     
            elif status_code == 401:
                if 'Access token invalid' in str(r.txt):
                    refresh()
          
            else:
                print("Status code : Reason -->",status_code,' : ',reason)
                sys.exit()

    else:                


        r = requests.put(post_url, data=json.dumps(bulk_ace_list), headers=headers, verify=False)
        status_code = r.status_code
        resp = r.text
        reason=r.text
   
        if (status_code == 200 or status_code == 201):
            print("Post was successful!")
     
        elif status_code == 401:
            if 'Access token invalid' in str(resp):
                refresh()
          
        else:
            print("Status code : Reason -->",status_code,' : ',reason)
            sys.exit()

except requests.exceptions.HTTPError as err:
    print ("POST_ACE : Error in connection ")
finally:
    if r: r.close()
print('###########################################################')