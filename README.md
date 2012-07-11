safedoor
========

Safedoor is a small Python application for sniffing out invalid/bogus SSL certificates.  A more elaborate discussion of this application and design can be found on my blog, here: forelsec.blogspot.com

Dependencies:
	Python 2.6
	M2Crypto .21.1
	PyOpenSSL .13
	Scapy 2.1.0

<pre>
drone@devbox:~/safedoor$ sudo python safedoor.py -h
Usage: safedoor.py [options]

Options:
  -h, --help     show this help message and exit
  -a ADAPTER     Adapter to sniff on
  -v             Dump certificate information
  -s CERTFILE    Specify a different SSL cert location
  -p PORT        Specify a port (default: 443)
  -r REVOCATION  Specify a CRL file for lookup; give full path
</pre>

As of initial commit, Safedoor has no logging mechanisms, but those are currently TODO.  The bulk of this code
was to coincide with the blog post and inquery into SSL verification.  This works very well for discovering 
reverse HTTPS payloads.

Sample verbose run from https://www.google.com.  

<pre>
drone@devbox:~/safedoor$ sudo python safedoor.py -a eth1 -v -r ~/safedoor/client.pem
[+] Beginning sniffer on adapter 'eth1' port 443
[!] Getting SSL certificate...
[+] SSL certificate from 74.125.227.52:443 -> [redacted]
[!] Issuer
[+]		C:		ZA
[+]		CN:		Thawte SGC CA
[+]		O:		Thawte Consulting (Pty) Ltd.
[+]		Hash:	0b4786a34f5ad112b2b7fe5949a2b6bb
[!] Subject
[+]		CN:		www.google.com
[+]		C:		US
[+]		L:		Mountain View
[+]		O:		Google Inc
[+]		ST:		California
[+]	Hash:		a723d34a1e8ecff5165deef984287c82
[!] Public Key
[+]		Bits:	1024
[+]		Type:	6
[+] Version:	2
[+] Serial:		105827261859531100510423749949966875981
[+] Valid:		October 26, 2011 - September 30, 2013
[+] Algorithm:	sha1WithRSAEncryption
[!] x509v3 Extensions:
[+] Extension:  crlDistributionPoints
		URI:http://crl.thawte.com/ThawteSGCCA.crl, 
[+] Extension:  extendedKeyUsage
		TLS Web Server Authentication, TLS Web Client Authentication, Netscape Server Gated Crypto
[+] Extension:  authorityInfoAccess
	OCSP - URI:http://ocsp.thawte.com, CA Issuers - URI:http://www.thawte.com/repository/Thawte_SGC_CA.crt, 
[!] Certificate Dump:
-----BEGIN CERTIFICATE-----
MIIDITCCAoqgAwIBAgIQT52W2WawmStUwpV8tBV9TTANBgkqhkiG9w0BAQUFADBM
MQswCQYDVQQGEwJaQTElMCMGA1UEChMcVGhhd3RlIENvbnN1bHRpbmcgKFB0eSkg
THRkLjEWMBQGA1UEAxMNVGhhd3RlIFNHQyBDQTAeFw0xMTEwMjYwMDAwMDBaFw0x
MzA5MzAyMzU5NTlaMGgxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpDYWxpZm9ybmlh
MRYwFAYDVQQHFA1Nb3VudGFpbiBWaWV3MRMwEQYDVQQKFApHb29nbGUgSW5jMRcw
FQYDVQQDFA53d3cuZ29vZ2xlLmNvbTCBnzANBgkqhkiG9w0BAQEFAAOBjQAwgYkC
gYEA3rcmQ6aZhc04pxUJuc8PycNVjIjujI0oJyRLKl6g2Bb6YRhLz21ggNM1QDJy
wI8S2OVOj7my9tkVXlqGMaO6hqpryNlxjMzNJxMenUJdOPanrO/6YvMYgdQkRn8B
d3zGKokUmbuYOR2oGfs5AER9G5RqeC1prcB6LPrQ2iASmNMCAwEAAaOB5zCB5DAM
BgNVHRMBAf8EAjAAMDYGA1UdHwQvMC0wK6ApoCeGJWh0dHA6Ly9jcmwudGhhd3Rl
LmNvbS9UaGF3dGVTR0NDQS5jcmwwKAYDVR0lBCEwHwYIKwYBBQUHAwEGCCsGAQUF
BwMCBglghkgBhvhCBAEwcgYIKwYBBQUHAQEEZjBkMCIGCCsGAQUFBzABhhZodHRw
Oi8vb2NzcC50aGF3dGUuY29tMD4GCCsGAQUFBzAChjJodHRwOi8vd3d3LnRoYXd0
ZS5jb20vcmVwb3NpdG9yeS9UaGF3dGVfU0dDX0NBLmNydDANBgkqhkiG9w0BAQUF
AAOBgQAhrNWuyjSJWsKrUtKyNGadeqvu5nzVfsJcKLt0AMkQH0IT/GmKHiSgAgDp
ulvKGQSy068Bsn5fFNum21K5mvMSf3yinDtvmX3qUA12IxL/92ZzKbeVCq3Yi7Le
IOkKcGQRCMha8X2e7GmlpdWC1ycenlbN0nbVeSv3JUMcafC4+Q==
-----END CERTIFICATE-----

[+] Cert Digest:	C1956DC8A7DFB2A5A56934DA09778E3A11023358
[!] Testing root certificates:
[+]		Thawte_Premium_Server_CA.pem
[+] Root certificate 'Thawte_Premium_Server_CA.pem' validates this certificate
[+] Valid certificate from 74.125.227.52
</pre>
