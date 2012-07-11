from OpenSSL import crypto
import datetime

#
# CRL related stuff in here.  When I get OCSP stuff done, I'll put it here.
# I think as far as that goes, I can just make binary calls to openssl, and 'openssl -oscp' should work
# Dependencies:
#		Python 2.7
#		PyOpenSSL .13
#

# if enabled, lookup the serial in the CRL
# @param location is the location of the CRL 
# if the cert is found on the list, return True, else return False
def check_crl(cert, location):
	f = file(location, 'r').read() 
	revoked_serials = (crypto.load_crl(crypto.FILETYPE_PEM, f)).get_revoked()
	for serial in revoked_serials:
		if serial.get_serial() == cert.get_serial_number():
			print '[!] Certificate found on revocation list:'
			print '[+] Serial:\t\t', serial.get_serial()
			print '[+] Reason:\t\t', serial.get_reason()
			rev_date = datetime.datetime.strptime(serial.get_rev_date(), "%Y%m%d%H%M%SZ")
			print '[+] Date Revoked:\t', rev_date.strftime('%B %d, %Y')
			return True
	return False
