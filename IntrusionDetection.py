import numpy as np
import pandas as pd

targetfile = 'C:/Users/Owner/Desktop/Definitely Not Research Stuff/netflow_examples/uky_201702151500_15m_ann.csv'

netflowData = pd.read_csv(targetfile)

#Sort out only SSH connections
ssh = netflowData[(netflowData.srcport==22) | (netflowData.dstport==22)]

#Set rules for scan phase detection
scan = ssh[(ssh.duration<=3500) & (ssh.dPkts <=2)]

#Sort the dataframe in chronological order
#scansorted = scan.sort(['first','dstaddr'])

#Get values for how many times a certain IP address appears as a source
srccount = scansorted['srcaddr'].value_counts()
print(srccount)

#Get values for how many times a certain IP address appears as a destination
dstcount = scansorted['dstaddr'].value_counts()
print(dstcount)

#How many times X amount of dPkts show up
DPcount = scansorted.dPkts.value_counts()
print(DPcount)

#Calculate if an IP address appears more than X amount of times
ScanYN = scansorted['srcaddr'].value_counts() + scansorted['dstaddr'].value_counts() >= 150

#List IP addresses that show up more than X amount of times
ScanYN = ScanYN[(ScanYN.values) == True]
print(ScanYN)

#List all the IP addresses that meet a criteria
iplist = list(ScanYN.index)
print(iplist)

IPNum = len(iplist)

#Go through the list and find out if there are enough connections to suspect a port scan attack

x=0

for x in range (0,IPNum):
    newNFD = scansorted[(scansorted.srcaddr == iplist[x]) | (scansorted.dstaddr == iplist[x])]
    maxtime = newNFD['first'].max()
    mintime = newNFD['first'].min()
    totaltime = (maxtime - mintime)/1000
    average = len(newNFD)/totaltime
    print(iplist[x])
    print("")
    print("Maxtime:",maxtime,"Mintime:",mintime,"Total Time(s):",totaltime,"Average(Connections per second):",average)
    print("")
    print("Total amount of connections made by IP Address",iplist[x],":",len(newNFD))
    print("")
    tmin = mintime
    while (tmin <= maxtime):
        tDF = newNFD[(newNFD['first'] >= (tmin)) & (newNFD['first'] <= (tmin + 60000))]
        tmin = tmin + 60000
        print("Number of connections between",(tmin-60000),"and",tmin,":",len(tDF))


