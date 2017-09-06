# Intrusion-Detection-in-Python
Implementing SSHCure in python for AMIS project 

This python function takes in netflow records (annotated by the AMIS module) and determines which flows could be characterized as brute force attempts, scan attacks, or potentially compromised IP addresses. The function returns either a dictionary with IP addresses that fit the aforementioned criteria, or an annotated Pandas dataframe denoting whether that flow contains an IP address that is either a scan or brute force attacker.

This repository and its branches, hold the basis of my research work and any experimental versions of IntrusionDetection.py created during this research.
