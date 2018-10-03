#! /usr/bin/env python
from scapy.all import *
import sys, os
from subprocess import check_output

#the ip address(es) to scan. Could be a file path or a comma separated list
hosts = str(sys.argv[1])
#the port(s) to scan.
ports = str(sys.argv[2])
#the type of scan to do (tcp, udp, or icmp)
scan_type = str(sys.argv[3])
#string for building html output
html = "<h1>" + scan_type + " Scan Results</h1>"

#if a text file was provided, read the file for ip addresses and put in a list
ip_list = []
if ".txt" in hosts:
	ip_file = open(hosts)
	hosts = ip_file.read()

ip_list = hosts.replace(" ","").split(",")
	
#put ports in a list
port_list = ports.split(",")


#TCP Scan
if scan_type == "tcp":
	for ip in ip_list:
		html += "<b>" + ip + "</b>"
		#create IP packet to send
		packet = IP()
		packet.dst = ip
		
		html += "<ul style='margin-top: 5px;'>"
		for port in port_list:
			tcp = TCP()
			tcp.dport = int(port)
			answer = sr1(packet/tcp)
			if answer.haslayer(TCP):
				#if response has the SYN/ACK (0x12) flag, it's open and responding
				if answer.getlayer(TCP).flags == 0x12:
					html += "<li>Port " + port + ": Open!</li>"
				else:
					html += "<li>Port " + port + ": Closed</li>"
		html += "</ul>"

		#Do a traceroute
		html += "traceroute:<p>"
		html += str(check_output(["traceroute", ip]))
		html += "</p>"

#UDP Scan
if scan_type == "udp":
	for ip in ip_list:
		html += "<b>" + ip + "</b>"
		#create IP packet
		packet = IP()
		packet.dst = ip

		dns = DNS()
		dns.qd = DNSQR(qname = "8.8.8.8")

		html += "<ul style='margin-top: 5px;'>"
		#send a UDP packet for each port
		for port in port_list:
			udp = UDP()
			udp.dport = int(port)
			answer = sr1(packet/udp/dns,timeout=1)

			#if there's no response, it could be open or filtered
			if (str(type(answer))=="<type 'NoneType'>"):
				html += "<li>Port " + port + ": Open | Filtered</li>"
			#if the response has a udp layer, it's open			
			elif answer.haslayer(UDP):
				html += "<li>Port " + port + ": Open!</li>"
			#if response has ICMP layer but no udp, it's either closed or filtered
			elif answer.haslayer(ICMP):
				if (int(answer.getlayer(ICMP).type)==3 and int(answer.getlayer(ICMP).code)==3):
					html += "<li>Port " + port + ": Closed</li>"
				elif (int(answer.getlayer(ICMP).type)==3 and int(answer.getlayer(ICMP).code) in [1,2,9,10,13]):
					html += "<li>Port " + port + ": Filtered</li>"
		html += "</ul>"
		#Do a traceroute
		html += "traceroute:<p>"
		html += str(check_output(["traceroute", ip]))
		html += "</p>"

#ICMP Scan
if scan_type == "icmp":
	for ip in ip_list:
		#create IP packet
		packet = IP()
		packet.dst = ip
		
		#send the ICMP request
		answer = sr1(packet/ICMP(),timeout=2,verbose=0)
		if answer is None:
			print('not responding')
			html += "<h4>" + ip + ": No Response</h4>"
		elif (int(answer.getlayer(ICMP).type)==3 and int(answer.getlayer(ICMP).code) in [1,2,3,9,10,13]):
			print('ICMP is blocked')
			html += "<h4>" + ip + ": Blocked</h4>"
		else:
			print('response received')
			html += "<h4>" + ip + ": Response Received!</h4>"

		#Do a traceroute
		html += "traceroute:<p>"
		html += str(check_output(["traceroute", ip]))
		html += "</p>"

#Create html file for output
html_file= open("/root/Desktop/scan_results.html","w+")
html_file.write(html)

print("")
print("------SCAN COMPLETE--------")
print('Results written to file /root/Desktop/scan_results.html')

