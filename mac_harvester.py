#!/usr/bin/python2.7
import subprocess
import os
import sys
from BeautifulSoup import BeautifulSoup #Library used for pulling data from html/xml documents

print
print "arugment one [-s,-r,-ra] save,remove,remove_all capture file(s). arugment two [capture file] (xml file format required)"
input_file = sys.argv[2] #the .kismet.netxml file that will be used.
remove = sys.argv[1]
file = open(input_file, "r") #open the specified file.
xmlDom = BeautifulSoup(file) #have Beautiful soup parse the file.
clients = xmlDom.findAll("wireless-client") #find the phrase wireless-client within the file.
output = open("/home/matt/files/AuthMacs1", "a+") #open an output file with APPENDING privledges so we don't overwrite everything else in the file.
count = 1
print
print
print "----------------------------"
print "Mac addresses found in file."
for client in clients: #iterate through every instance of "wireless-client in" the file.
	client = client.find("client-mac").text #within each instance of wireless-client, try to locate the phrase "client-mac" and store it in the client variable.
	print "%d: %s" % (count, client) #print client-mac if found.
	count = count + 1
	output.write(client+"\n") #write client-mac to our previously specified output file.
print "-----------------------------"
output.close()
os.system("cat /home/matt/files/AuthMacs1 | sort -u > /home/matt/files/AuthMacs")
example = os.popen("diff /home/matt/files/AuthMacs /home/matt/files/AuthMacs1").read()

if example != 0:
	print "Duplicate Mac addresses found in AuthMacs1, overwriting AuthMacs1 with AuthMacs."
	os.system("cat /home/matt/files/AuthMacs > /home/matt/files/AuthMacs1")
	print "Duplicate Mac Addresses removed."

if remove == "-r": # if the first arugment is -r then remove the user capture file
	os.system("rm " + sys.argv[2])
	print "%s removed" % (input_file)
elif remove == "-ra": # if the first arugment is -ra then remove all capture files beginning with a matching prefix
	kill = input_file.split(".")
	os.system("rm " + kill[0] + "*")
	print "capture files removed."
elif remove == "-s":
	pass
elif remove != "-r" and remove != "-ra":
	pass
