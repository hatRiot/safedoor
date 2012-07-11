safedoor
========

Safedoor is a small Python application for sniffing out invalid/bogus SSL certificates.  A more elaborate discussion of this application and design can be found on my blog, here: forelsec.blogspot.com

Dependencies:
	Python 2.6
	M2Crypto .21.1
	PyOpenSSL .13
	Scapy 2.1.0

drone@devbox:~/safedoor$ sudo python safedoor.py -h
Usage: safedoor.py [options]

Options:
  -h, --help     show this help message and exit
  -a ADAPTER     Adapter to sniff on
  -v             Dump certificate information
  -s CERTFILE    Specify a different SSL cert location
  -p PORT        Specify a port (default: 443)
  -r REVOCATION  Specify a CRL file for lookup; give full path

As of initial commit, Safedoor has no logging mechanisms, but those are currently TODO.  The bulk of this code
was to coincide with the blog post and inquery into SSL verification.  This works very well for discovering 
reverse HTTPS payloads.
