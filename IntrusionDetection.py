import numpy as np
import pandas as pd

def detectSSHIntrusions(dataframe):
    
    ### Dictonary to hold all the intrusion info
    intrusion_dict = {}    
    
    ssh = dataframe
    #Sort out only SSH connections
    ssh = dataframe[(dataframe.srcport==22) | (dataframe.dstport==22)]

    #Set rules for scan phase detection
    scan = ssh[(ssh.dPkts <= 2)]
    BF = ssh[(ssh.dPkts >= 8) & (ssh.dPkts <= 14)]

    #Sort the dataframe in chronological order
    scansorted = scan.sort_values(['first','dstaddr'])
    BFsorted = BF.sort_values(['first','dstaddr'])

    #Get values for how many times a certain IP address appears as a source
    srccount = scansorted['srcaddr'].value_counts()
    BFsrccount = BFsorted['srcaddr'].value_counts()
    #print("Source Scan Value Counts:")
    #print(srccount)
    #print("")
    #print("Source BF Value Counts:")
    #print(BFsrccount)
    #print("")

    #Get values for how many times a certain IP address appears as a destination
    dstcount = scansorted['dstaddr'].value_counts()
    BFdstcount = BFsorted['dstaddr'].value_counts()
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
                    
                    
    #BruteForce Algorithm

    y=0
    BFattackerlist = list()

    for y in range (0,BFIPNum):
        newNFD = BFsorted[(BFsorted.srcaddr == BFiplist[y]) | (BFsorted.dstaddr == BFiplist[y])]
        maxtime = newNFD['first'].max()
        mintime = newNFD['first'].min()
        totaltime = (maxtime - mintime)/1000
        average = len(newNFD)/totaltime
        #print("")
        #print("Brute force data for",BFiplist[y],":")
        #print("")
        #print("Maxtime:",maxtime,"Mintime:",mintime,"Total Time(s):",totaltime,"Average(Connections per second):",average)
        #print("")
        #print("Total amount of connections made by IP Address",BFiplist[y],":",len(newNFD))
        #print("")
        tmin = mintime
        while (tmin <= maxtime):
            tDF = newNFD[(newNFD['first'] >= (tmin)) & (newNFD['first'] <= (tmin + 60000))]
            tmin = tmin + 60000
           # print("Number of connections between",(tmin-60000),"and",tmin,":",len(tDF))
            if (len(tDF) >= 20):
                if BFiplist[y] not in BFattackerlist:
                    BFattackerlist.append(BFiplist[y])
                    
                    



    ### Add entry to dictionary
    intrusion_dict['Scan Attackers'] = scanattackerlist
    intrusion_dict['Brute Force Attackers'] = BFattackerlist

    #print("")
    #print("IP address of scan attacker(s):",','.join(scanattackerlist))
    #print("")
    #print("IP address of BF attacker(s):",','.join(BFattackerlist))
    
    #Die off phase with potential compromised IP addresses
    
    z = 0
    CompList = list()
    BFLength = len(BFattackerlist)
    for z in range (0,BFLength):
        compDF = ssh[(ssh.srcaddr == BFattackerlist[z]) | (ssh.dstaddr == BFattackerlist[z])]
        compDF = compDF[((compDF.dPkts < 8) | (compDF.dPkts > 14)) & (compDF.duration > 4000)]
        CompList = np.unique(compDF[['srcaddr','dstaddr']])
        NewCompList = CompList.tolist()
        NewCompList.remove(BFattackerlist[z])
        NewCompList.sort
        
        ### Add entry to dictionary       
        intrusion_dict['Potentially Compromised IPs'] = NewCompList
        
        #print("")
        #print("Possible compromised IP addresses by IP address",BFattackerlist[z],":")
        #print('\n'.join(NewCompList))
        
        return intrusion_dict
     
     
### Loads example data frame into detection function, in this case it is an annotated csv file
    
targetfile = "C:/Users/Lulu/Google Drive/School/Graduate_Work/Thesis/Code/uky_201702151500_15m_ann.csv"

netflowData = pd.read_csv(targetfile)

### Input to function is a Pandas data frame
out = detectSSHIntrusions(netflowData)

### Define two vars to itereate over the keys and the values in dictonary, also print a '\n' to look cleaner
for i, j in out.items():
    print(i,j,'\n')
    
#print(list(dictionary.keys()),'\n')
#print(dictionary['Brute Force Attackers'],'\n')
