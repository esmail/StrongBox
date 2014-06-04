# By Esmail Fadae.

import os, subprocess, json, urllib2, httplib
import PeerConfiguration

class Communicator():
  
  @staticmethod
  def create_x509_cert(config_directory):
    
    x509_cert_path = os.path.join(config_directory, 'public.x509.pem')
    if not os.path.isfile(x509_cert_path):
      # Use OpenSSL's CLI to generate an X.509 from the existing RSA private key
      # Adapted from http://stackoverflow.com/a/12921889 and http://stackoverflow.com/a/12921889
      subprocess.check_call('openssl req -new -batch -x509 -nodes -days 3650 -key ' \
                            + PeerConfiguration.PeerConfiguration.get_private_key_file(config_directory) \
                            + ' -out ' + x509_cert_path \
                            , shell=True)
  @staticmethod
  def get_public_network_address():
    # TODO: Figure out a fallback for this
    network_address = None
    while not network_address:
      try:
        network_address = json.load(urllib2.urlopen('http://httpbin.org/ip'))['origin']
      except httplib.BadStatusLine:
        pass
      
    return network_address

