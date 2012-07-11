from scapy.all import *
from OpenSSL import SSL, crypto
from crl_lookup import check_crl
import hashlib
import M2Crypto
import ssl
import datetime, os, re, sys
import base64 

#
# Parsing stuff in here.
# Dependencies: 
#		Python 2.7
#		PyOpenSSL .13 
#		Scapy 2.1.0 
#		M2Crypto .21.1
#

ssl_location = '/etc/ssl/certs/'
revocation = None
verbose = False

# when we're here, we've got a packet that's unique and needs it's cert checked out
# return: true if it's valid, false if it's invalid
# @param pkt is the raw packet
# @param verbose is whether we want to dump the cert to console or just validate and return
def parse(pkt, vrb, cert_loc, revoke):
	# set some globals
	global ssl_location
	global verbose
	global revocation
	verbose = vrb
	revocation = revoke
	ssl_location = cert_loc

	cert = ssl.get_server_certificate((pkt[IP].src, 443))
	x509 = crypto.load_certificate(crypto.FILETYPE_PEM, cert)
	# if we're not dumping to console, validate it immediately
	if not verbose:
		return validate(x509)

	print "[!] Getting SSL certificate..."
	print "[+] SSL certificate from {0}:{1} -> {2}:{3}".format(pkt[IP].src, pkt[TCP].sport, pkt[IP].dst, pkt[TCP].dport)


	# issuer info
	issuer = x509.get_issuer().get_components()
	print "[!] Issuer"
	for k, v in dict(issuer).iteritems():
		print "[+]\t{0}:\t{1}".format(k,v)
	print "[+]\tHash:\t",hashlib.md5(x509.get_issuer().der()).hexdigest()

	# subject info
	subject = x509.get_subject().get_components()
	print "[!] Subject"
	for k, v in dict(subject).iteritems():
		print"[+]\t{0}:\t{1}".format(k,v)
	print "[+]\tHash:\t",hashlib.md5(x509.get_subject().der()).hexdigest()
	
	# public key info
	print "[!] Public Key"
	print "[+]\tBits:\t", x509.get_pubkey().bits()
	print "[+]\tType:\t", x509.get_pubkey().type()

	# misc
	print "[+] Version:\t",x509.get_version()
	print "[+] Serial:\t",x509.get_serial_number()
	before = datetime.datetime.strptime(x509.get_notBefore(), "%Y%m%d%H%M%SZ")
	after  = datetime.datetime.strptime(x509.get_notAfter(), "%Y%m%d%H%M%SZ")
	print "[+] Valid:\t{0} - {1}".format(before.strftime('%B %d, %Y'), after.strftime('%B %d, %Y'))
	print "[+] Algorithm:\t",x509.get_signature_algorithm()

	# extensions
	print "[!] x509v3 Extensions:"
	for i in range(1,x509.get_extension_count()):
		ext = x509.get_extension(i)
		print "[+] Extension: ", ext.get_short_name()
		print "\t",str(ext).replace('\n', ', ')

	print "[!] Certificate Dump:"
	print crypto.dump_certificate(crypto.FILETYPE_PEM, x509)
	
	return validate(x509)

# after the cert has been plaintext dumped, validate it.  
# @param cert is an X509 certificate
def validate(cert):
	global verbose

	# easiest check is expiration
	if cert.has_expired():
		print "[-] Certificate has expired."
		return False
	
	# verify the certificates integrity
	try:
		# check() is currently broken in PyOpenSSL .13 and segfaults if a private key isn't
		# found.  I am waiting for the official .14 to include this, but if you pull from
		# repositories or modify it yourself, remove the 'if False' bit to verify keys.
		if False:
			if not cert.get_pubkey().check():
				print "[-] Keys didn't pass integrity check." 
				return False
	except TypeError:
		print "[-] Malformed keypair" 
	
	if verbose:
		hsh = str(cert.digest(cert.get_signature_algorithm())).replace(':', '')
		print "[+] Cert Digest:\t",hsh
	
	# pyopenssl doesn't have any methods for verifying a signature, so i'm just using 
	# m2crypto for now; the implementation is just a call to X509_verify, so perhaps I'll
	# implement it myself at a future date
	m2cert = M2Crypto.X509.load_cert_string(crypto.dump_certificate(crypto.FILETYPE_PEM, cert))
	if m2cert.verify() > 0:
		print "[-] Digital signatures do not match!"
		return False
	
	# verify the certificate SKI if it exists
	try:
		ski = m2cert.get_ext('subjectKeyIdentifier').get_value()
		verify_ski(m2cert, ski)
	except:
		# thrown when no SKI is found
		pass

	# verify the CN exists
	subject = cert.get_subject().get_components()
	if 'CN' in dict(subject):
		cn = dict(subject)['CN']
		rval = subprocess.call("ping -c 1 -w 1 %s"%cn, shell=True, stdout=open('/dev/null', 'w'),
												 stderr=subprocess.STDOUT)
		if rval > 0:
			print "[-] Certificate's CN (%s) does not appear to be active or responding to pings."%cn
			# further, attempt a DNS lookup to see if it resolves
			try:
				rval = socket.gethostbyname(cn)
				if len(rval) > 0:
					print "[+] CN resolved to address {0}; host may be down or rejecting pings.".format(rval)
			except Exception, e:
				print "[-] Cannot resolve CN ({0}).".format(cn)
			
	else:
		print "[!] Certificate does not have a subject common name."

	# verify that the CA is trusted
	issuer_cn = dict(cert.get_issuer().get_components())['CN']
	found = find_root_cert(issuer_cn.split(' ')[0] + '*')
	
	if verbose: print '[+] Testing root certificates'
	# try all relevant certificates 
	status = False
	for i in found:
		if verbose: print "[+]\t", i
		f = file('{0}/{1}'.format(ssl_location, i), 'rb').read()
		# get the root certificate's public key
		root_public = (M2Crypto.X509.load_cert_string(f)).get_pubkey()
		try:
			# validate certificate
			if m2cert.verify(root_public) == 0:
				if verbose: 
					print "[+] Root certificate '{0}' validates this certificate".format(i)
				status = True
				break
		except Exception, j:
			print j

	# if we didn't find a validating root cert, something MIGHT be wrong; they could just not have
	# the root certificate installed on their system 
	if not status:
		print "[-] No installed root certificates validated this certificate."
		return False

	# Finally, if they specified a CRL, check if this cert is present
	if not revocation is None:
		if check_crl(cert, revocation):
			return False
	return True	

# look through the local system for the root certificate
# default location is /etc/ssl/certs/
# param: find is part of the issuer CN
def find_root_cert ( find ):
	global ssl_location

	found = []
	try:
		entries = os.listdir(ssl_location)
		for line in entries: 
			if re.match(find, line):
				found.append(line)	
		return found
	except Exception, e:
		print e

# verify the SKI of the certificate, if it exists
# Right now the main point of this is to test whether or not the certificate is self-signed.  There are
# way too many scenarios where the SKI generation is different, or not applicable.  
def verify_ski(cert, ski): 
	# test if it's self signed
	try:
		aki = ((cert.get_ext('authorityKeyIdentifier')).get_value().replace(':', ''))[5:]
		if ski == aki:
			print '[+] Certificate is self-signed.\n[+] {0} = {1}'.format(aki, ski)
	except:
		pass
	
	# test the SKI
	try:
		digest = hashlib.sha1(cert.get_pubkey().get_rsa().as_pem()).hexdigest().upper()
		if verbose:
			print '[!] Generated SKI: ', ':'.join(digest[pos : pos+2] for pos in range(0, 40, 2))
	except:
		pass
