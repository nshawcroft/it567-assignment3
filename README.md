# it567-assignment3

This Python script is a simple port scanner that can do a TCP, UDP, or ICMP scan. You can give it one or multiple IP addresses to scan as well as one or multiple ports to scan. It will output the results of the scan on to your desktop. 

How to use the tool:

pythonPortScan.py [ip addresses] [ports] [scan type] 

-[ip addresses]: a list of ip addresses separated by commas. Can be in line or the name of a .txt file containing the list
-[ports]: a list of ports separated by commas
-[scan type]. Which type of scan to do. Can be tcp, udp, or icmp

Requirements met for additional points:
Reading a text file of host IP’s AND reading a range from the command line, 
Allow multiple ports to be specified,
ICMP, TCP, and UDP scans,
Traceroute,
HTML report,
