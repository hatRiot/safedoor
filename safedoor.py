import logging
# don't log the annoying IPv6 warning from scapy
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *
from optparse import OptionParser
import os, sys
import parser

#
# Info in the readme
# Dependencies:
#		Python 2.7
#		Scapy 2.1.0
#

# evil globals
verbose = False
ssl_location = '/etc/ssl/certs'
revocation = None

validated = []
rejected = []

# parse up the packet, if it's worthwhile we'll do stuff with it
def validate(pkt):
	if IP in pkt:
		if pkt[IP].src in rejected:
			return
		if not pkt[IP].src in validated:
			if str(pkt[IP].src) != "192.168.1.51":
				if parser.parse(pkt, verbose, ssl_location, revocation):
					print "[+] Valid certificate from {0}".format(pkt[IP].src)
					validated.append(pkt[IP].src)
				else:
					print "[-] Invalid certificate found from {0}".format(pkt[IP].src)
					rejected.append(pkt[IP].src)
# entry
def main():
	global verbose
	global ssl_location
	global revocation

	if int(os.getuid()) > 0:
		print "[-] You need to be root for this."
		sys.exit(1)

	# command line options
	parser = OptionParser()
	parser.add_option("-a", help="Adapter to sniff on", action="store", default="eth0", dest="adapter")
	parser.add_option('-v', help="Dump certificate information", action="store_true", default=False, dest="verbose")
	parser.add_option('-s', help="Specify a different SSL cert location", action="store", default='/etc/ssl/certs', dest='certFile')
	parser.add_option('-p', help="Specify a port (default: 443)", action="store", default=443, dest="port")
	parser.add_option('-r', help="Specify a CRL file for lookup; give full path", action="store", default=None,
					dest="revocation")

	(options, args) = parser.parse_args()
	adapter = options.adapter
	verbose = options.verbose
	port = options.port
	revocation = options.revocation

	# validate the ssl cert folder
	if os.path.isdir(options.certFile):
		ssl_location = options.certFile
	else:
		ssl_location = '/etc/ssl/certs/'
	
	try:
		print "[+] Beginning sniffer on adapter '{0}' port {1}".format(adapter, port)
		sniff(filter="tcp and port %s"%port, iface=adapter, prn=validate)
	except KeyboardInterrupt, k:
		print "\n[!] Closing down..."
	except TypeError, e:
		print "[-] Type error: ",e
	except Exception, j:
		print j
#	if j.errno is 19:
#			print "[-] Device {0} does not exist.".format(adapter)

if __name__=="__main__":
	main()
