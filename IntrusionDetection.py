import numpy as np
import pandas as pd

def detectSSHIntrusions(dataframe, return_var):

    ### Dictonary to hold all the intrusion info
    intrusion_dict = {}

    ssh = dataframe
    #Sort out only SSH connections
    ssh = dataframe[(dataframe.dstport==22)]
    port22 = dataframe[(dataframe.dstport==22) | (dataframe.srcport==22)]

    #Set rules for scan phase detection
    scan = port22[(port22.dPkts <= 2)]
    BF = ssh[(ssh.dPkts >= 11) & (ssh.dPkts <= 51)]

    #Sort the dataframe in chronological order
    scansorted = scan.sort_values(['first','dstaddr'])
    reorder = BF.sort_values(['srcaddr','dstaddr','first'])
    BFsorted = reorder.reset_index(drop = True)

    #print(scansorted)

    #Get values for how many times a certain IP address appears as a source
    srccount = scansorted['srcaddr'].value_counts()
    BFsrccount = reorder['srcaddr'].value_counts()

    #print("Source Scan Value Counts:")
    #print(srccount)
    #print("")
    #print("Source BF Value Counts:")
    #print(BFsrccount)
    #print("")

    #Get values for how many times a certain IP address appears as a destination
    dstcount = scansorted['dstaddr'].value_counts()
    BFdstcount = reorder['dstaddr'].value_counts()
    #print("Destination Scan Value Counts:")
    #print(dstcount)
    #print("")
    #print("Destination BF Value Counts:")
    #print(BFdstcount)
    #print("")

    #How many times X amount of dPkts show up
    DPcount = scansorted.dPkts.value_counts()
    DPBFCount = BFsorted.dPkts.value_counts()
    #print(DPcount)
    #print("")
    #print(DPBFCount)
    #print("")

    #Calculate if an IP address appears more than X amount of times
    ScanYN = dstcount + srccount >= 200
    BFYN = BFdstcount + srccount  >= 20
    
    print(ScanYN)    
    
    #List IP addresses that show up more than X amount of times to determine wether to scan or not
    ScanYN = ScanYN[(ScanYN.values) == True]
    BFYN = BFYN[(BFYN.values) == True]

    #List all the IP addresses that meet a criteria
    scaniplist = list(ScanYN.index)

    ### Add entry to dictionary
    intrusion_dict['Potential Scan Attackers'] = scaniplist

    #print("")
    #print("IP Addresses that meet initial scan criteria:")
    #print('\n'.join(scaniplist))
    #print("")
    BFiplist = list(BFYN.index)

    ### Add entry to dictionary
    intrusion_dict['Potential Brute Force Attackers'] = BFiplist

    #print("IP Addresses that meet initial BF criteria:")
    #print('\n'.join(BFiplist))
    #print("")
    IPNum = len(scaniplist)
    BFIPNum = len(BFiplist)

    #Go through the list and find out if there are enough connections to suspect a port scan attack

    x=0
    scanattackerlist = []

    for x in range (0,IPNum):
        newNFD = scansorted[(scansorted.srcaddr == scaniplist[x]) | (scansorted.dstaddr == scaniplist[x])]
        maxtime = newNFD['first'].max()
        mintime = newNFD['first'].min()
        totaltime = (maxtime - mintime)/1000
        average = len(newNFD)/totaltime
        #print("")
        #print("Scan attack data for",scaniplist[x],":")
        #print("")
        #print("Maxtime:",maxtime,"Mintime:",mintime,"Total Time(s):",totaltime,"Average(Connections per second):",average)
        #print("")
        #print("Total amount of connections made by IP Address",scaniplist[x],":",len(newNFD))
        #print("")
        tmin = mintime
        while (tmin <= maxtime):
            tDF = newNFD[(newNFD['first'] >= (tmin)) & (newNFD['first'] <= (tmin + 60000))]
            tmin = tmin + 60000
          #  print("Number of connections between",(tmin-60000),"and",tmin,":",len(tDF))
            if (len(tDF) >= 200):
                if scaniplist[x] not in scanattackerlist:
                    scanattackerlist.append(scaniplist[x])

    #print(scanattackerlist)
    #BruteForce Algorithm

    #Set Variables
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

    #Die off phase with potential compromised IP addresses

    z = 0
    CompList = list()
    BFLength = len(BruteForceAttackers)
    for z in range (0,BFLength):
        compDF = ssh[(ssh.srcaddr == BruteForceAttackers[z]) | (ssh.dstaddr == BruteForceAttackers[z])]
        compDF = compDF[((compDF.dPkts < 8) | (compDF.dPkts > 14)) & (compDF.duration > 4000)]
        CompList = np.unique(compDF[['srcaddr','dstaddr']])
        NewCompList = CompList.tolist()
        if BruteForceAttackers in NewCompList:          # Added this bit in, else it would fail
            NewCompList.remove(BruteForceAttackers[z])
        NewCompList.sort

        ### Add entry to dictionary
        intrusion_dict['Potentially Compromised IPs'] = NewCompList

        #print("")
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
#        BF_d[bf_attackers[n]]['Organization'] = dicdf.iloc[0]['src_org']
#        BF_d[bf_attackers[n]]['City'] = dicdf.iloc[0]['src_city']
#        BF_d[bf_attackers[n]]['Country'] = dicdf.iloc[0]['src_country']

        intrusion_dict['Brute Force Attackers'] = BF_d

        #print(addr_list.index(bf_attackers[n]), 'yes\n')

    #print(new_netflowData.index[n])

    #print(bf_attackers)

    for m in range (0, ScanLength):
        scan_d[scan_attackers[m]] = {}
        dicdf = ssh[ssh.srcaddr == scan_attackers[m]]
#       scan_d[scan_attackers[m]]['Organization'] = dicdf.iloc[0]['src_org']
#        scan_d[scan_attackers[m]]['City'] = dicdf.iloc[0]['src_city']
#        scan_d[scan_attackers[m]]['Country'] = dicdf.iloc[0]['src_country']

        intrusion_dict['Scan Attackers'] = scan_d

    #print(scan_attackers)

    if return_var == 0:
        return intrusion_dict

    if return_var == 1:
        return new_netflowData

    else:
        print("Incorrect usage of function 'detectSSHIntrusions'", "\n")
        return -1

### Loads example data frame into detection function, in this case it is an annotated csv file
### Change hydra_8_hos... to nmap_8_hos... to benchmark nmap
targetfile = '/home/zero/GoogleDrive/School/Graduate_Work/Thesis/hydra_8_hosts_ann.csv'
netflowData = pd.read_csv(targetfile)

### Input to function is a Pandas data frame
### Usage: detectSSHIntrusions(name_of_dataframe, 0 to return intrusion dictionary 1 to return new dataframe)
foo = detectSSHIntrusions(netflowData, 0)
