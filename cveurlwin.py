#! /usr/bin/python
###############################################################################
# This script is used to create co information database.
# Writen by: Jim Zeng 2015-08-04
###############################################################################
import re
import datetime
import sys
import os
import json
from pprint import pprint
#import urllib
import urllib2

vendorCount = {}
#for root, dirs, files in os.walk("/home/jzeng/projects/cvelist"):
#headers = { 'User-Agent' : 'Mozilla/5.0' }
headers = { 'User-Agent' : 'Googlebot/2.1' }
fileCount = 0
stateStats = {}
failedGoogle = {}
cveVendor = {}
trustedList = ['paloaltonetworks.com/', '.microsoft.com/', 'kb.netapp.com', '.trendmicro.com', 'ipa.go.jp', 'lorexxar.cn/', 'bugzilla.nasm.us', 'gitee.com/', 'kb.netapp.com', 'trendmicro.com/']
for root, dirs, files in os.walk("C:\\Users\\jim\\cvelist\\2017\\1002xxx"):
    #print root
    for file in files:
        #print file
            
        if not file.endswith('.json'):
            continue
        fileCount += 1

        #if fileCount > 50:
        #    break 

        fullName = root + "/" + file 
        with open(fullName) as data_file:    
            data = json.load(data_file)
            vendorName = ''
            state = ''
            url = ''
            try: 
                vendorName =  data['CVE_data_meta']['ASSIGNER'] 
                state = data['CVE_data_meta']['STATE']
                try:
                    stateStats[state] +=1
                except:
                    stateStats[state] = 1
                if state != 'PUBLIC':
                    continue
                #print file
                url =  data['references']['reference_data'][0]['url'] 
                #print url
                
                if file in ['CVE-2017-0040.json', 'CVE-2017-0042.json']:
                    print file, url
                    continue
                    
                checkUrl = 1   
                for trusted in trustedList:
                    if trusted in url:
                        checkUrl = 0
                        break
                if checkUrl == 0:
                    continue
                    
                req = urllib2.Request(url, None, headers)
                status = urllib2.urlopen(req).code
                if status != 200:
                    print status, file, url
             
            except:
                print file, url
                failedGoogle[file] = url
                cveVendor[file] = vendorName
                pass

print ""                
print "======================="
print "Try Mozilla/5..."
headers = { 'User-Agent' : 'Mozilla/5.0' }			
allFiles = failedGoogle.keys()
for file in allFiles:
    url = failedGoogle[file]
    vendorName = cveVendor[file]
    try: 
        req = urllib2.Request(url, None, headers)
        status = urllib2.urlopen(req).code
        if status != 200:
            print status, file, url
        
    except:
        print vendorName, "|", file, "|", url
        pass

print "======================="
print "Total CVEs: ", fileCount 
allStates = stateStats.keys()
for state in allStates:
    print state, ":", stateStats[state]
