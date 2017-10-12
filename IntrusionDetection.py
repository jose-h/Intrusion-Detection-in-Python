"""
Intrusion Detection function for AMIS 

An intrusion detection function capable of detecting scanning, brute force, and compromised IP addresses 
and annotating flow records as such.

Authors:  Jose A. Hernandez & Christopher Mendoza
Version: 2.1
Date:    September 5, 2017

List of features to add & bugs to fix:
1. Improved(alternate) scanning algorithm
2. Fix annotating algorithm
"""

import numpy as np
import pandas as pd
from fractions import Fraction

def detectSSHIntrusions(dataframe, return_var):

    ### Dictonary to hold all the intrusion info
    intrusion_dict = {}

    ssh = dataframe

    #Sort out only SSH connections
    ssh = dataframe[(dataframe.dstport==22)]
    port22 = dataframe[(dataframe.dstport==22) | (dataframe.srcport==22)]
    
    #Set rules for scan phase detection
    scan = port22[(port22.dPkts <= 4)]
    BF = ssh[(ssh.dPkts >= 11) & (ssh.dPkts <= 51)]

    #Sort the dataframe in chronological order
    scansorted = scan.sort_values(['first','dstaddr'])
    totaldst = list(set(scansorted.dstaddr))
    #print(totaldst)
    
    reorder = BF.sort_values(['srcaddr','dstaddr','first'])
    BFsorted = reorder.reset_index(drop = True)

    ### Scan % Rule ###
    scaniplist = []
    for x in range(0,len(totaldst)):
        # make temp flow data where IP is dst 
        tempNFD = scansorted[(scansorted.dstaddr == totaldst[x])]
        # find number of IPs testing IP connects to
        tempsrc_list = len(list(set(tempNFD.srcaddr)))
        #print(tempsrc_list)        
        if (tempsrc_list / len(totaldst)) >= Fraction(1,3):
            scaniplist.append(totaldst[x])
            #print(scaniplist)

    ### Add entry to dictionary
    intrusion_dict['Potential Scan Attackers'] = scaniplist

    #print("IP Addresses that meet initial scan criteria:")
    #print('\n'.join(scaniplist))

    IPNum = len(scaniplist)
    #Go through the list and if there are enough connections, suspect a port scan attack

    ### Scan Algortihm ###
    x=0
    scanattackerlist = []
    for x in range (0,IPNum):
        # This gives me the flow data where the scanner is the dst 
        newNFD = scansorted[(scansorted.dstaddr == scaniplist[x])]
        maxtime = newNFD['first'].max()
        tmin = newNFD['first'].min()
        while (tmin <= maxtime):
            tDF = newNFD[(newNFD['first'] >= (tmin)) & (newNFD['first'] <= (tmin + 60000))]
            tmin = tmin + 60000
            #print("Number of connections between",(tmin-60000),"and",tmin,":",len(tDF))
            if (len(tDF) >= 200):
                if scaniplist[x] not in scanattackerlist:
                    scanattackerlist.append(scaniplist[x])

    #print(scanattackerlist)

    ### Brute-force Algorithm ###
    LoginGraceTime = 200000
    #baseline = BFsorted['dPkts'].value_counts().idmax()

    #Detect Brute Force Attackers
    p = len(BFsorted) - 1
    q = 0
    BruteForceAttackers = []
    for q in range (0,p):
        if ((BFsorted.dPkts[q] == BFsorted.dPkts[q + 1]) & (BFsorted.srcaddr[q] == BFsorted.srcaddr[q + 1]) & (BFsorted.dstaddr[q] == BFsorted.dstaddr[q + 1])):
            if BFsorted.srcaddr[q] not in BruteForceAttackers:
                BruteForceAttackers.append(BFsorted.srcaddr[q])

    k = 0
    BruteForceLength = len(BruteForceAttackers)
    AllCompromises = []
    compromisedIPs = []

    for k in range (0,BruteForceLength):
        tempDF = port22[port22.dstaddr == BruteForceAttackers[k]]
        tempDF = tempDF[tempDF.duration != LoginGraceTime]
        temporary = tempDF.srcaddr.unique()
        tempCompIP = temporary.tolist()
        AllCompromises.extend(tempCompIP)
    AllCompromises.sort()
    for w in AllCompromises:
        if w not in compromisedIPs:
            compromisedIPs.append(w)

    ### Add entry to dictionary
    intrusion_dict['Scan Attackers'] = scanattackerlist
    intrusion_dict['Brute Force Attackers'] = BruteForceAttackers

    ### Potentially Compromised IPs ###
    z = 0
    CompList = list()
    BFLength = len(BruteForceAttackers)
    for z in range (0,BFLength):
        compDF = ssh[(ssh.srcaddr == BruteForceAttackers[z]) | (ssh.dstaddr == BruteForceAttackers[z])]
        compDF = compDF[((compDF.dPkts < 8) | (compDF.dPkts > 14)) & (compDF.duration > 4000)]
        CompList = np.unique(compDF[['srcaddr','dstaddr']])
        NewCompList = CompList.tolist()
        if BruteForceAttackers in NewCompList:          # Added this bit in, else it would fail if BFA list was empty
            NewCompList.remove(BruteForceAttackers[z])
        NewCompList.sort

        ### Add entry to dictionary
        intrusion_dict['Potentially Compromised IPs'] = NewCompList

        #print("Possible compromised IP addresses by IP address",BFattackerlist[z],":")
        #print('\n'.join(NewCompList))


    n = 0
    m = 0
    ScanLength = len(scanattackerlist)
    BF_d = {}
    scan_d = {}
    bf_attackers = list(set(BruteForceAttackers))
    scan_attackers = list(set(scanattackerlist))
    new_netflowData = dataframe
    addr_list = list(new_netflowData['srcaddr'])
    new_netflowData['bf_attkr'] = 0
    new_netflowData['scan_attkr'] = 0

    for n in range (0,BFLength):
        BF_d[bf_attackers[n]] = {}
        dicdf = ssh[ssh.srcaddr == bf_attackers[n]]
        BF_d[bf_attackers[n]]['Organization'] = dicdf.iloc[0]['src_org']
        BF_d[bf_attackers[n]]['City'] = dicdf.iloc[0]['src_city']
        BF_d[bf_attackers[n]]['Country'] = dicdf.iloc[0]['src_country']

        intrusion_dict['Brute Force Attackers'] = BF_d

        #print(addr_list.index(bf_attackers[n]), 'yes\n')

    #print(new_netflowData.index[n])

    #print(bf_attackers)

    for m in range (0, ScanLength):
        scan_d[scan_attackers[m]] = {}
        dicdf = ssh[ssh.srcaddr == scan_attackers[m]]
        scan_d[scan_attackers[m]]['Organization'] = dicdf.iloc[0]['src_org']
        scan_d[scan_attackers[m]]['City'] = dicdf.iloc[0]['src_city']
        scan_d[scan_attackers[m]]['Country'] = dicdf.iloc[0]['src_country']

        intrusion_dict['Scan Attackers'] = scan_d

    #print(scan_attackers)

    if return_var == 0:
        return intrusion_dict

    if return_var == 1:
        return new_netflowData

    #For testing
    if return_var == 2:
        return tempNFD
    else:
        print("Incorrect usage of function 'detectSSHIntrusions'", "\n")
        return -1

### Loads example data frame into detection function, in this case it is an annotated csv file

targetfile = '/home/zero/GoogleDrive/School/Graduate_Work/Thesis/Code/netflow_examples/uky_201702151200_15m_ann.csv'

netflowData = pd.read_csv(targetfile)

### Input to function is a Pandas data frame
### Usage: detectSSHIntrusions(name_of_dataframe, 0 to return intrusion dictionary 1 to return new dataframe)
foo = detectSSHIntrusions(netflowData, 0)
