# By Esmail Fadae

import os, json, httplib, urllib2
import StoredConfiguration
from Encrypter import Encrypter

class PeerConfiguration(StoredConfiguration):
  """
  The configuration of a StrongBox peer.
  DESIGN TRADEOFF: Choosing to extend the `StoredConfiguration` class, which is
  really a different concept than this rather than introduce the additional
  access indirection of composing with a `StoredConfiguration` object or manually
  creating a facade (which should be the eventual solution).
  """
  
  @classmethod
  def get_private_key_file(cls, config_directory):
    private_key_file = os.path.join(config_directory, 'private_rsa_key.pem')
    return private_key_file
    
  @classmethod
  def get_public_network_address(self):
    # TODO: Figure out a fallback for this
    network_address = None
    while not network_address:
      try:
        network_address = json.load(urllib2.urlopen('http://httpbin.org/ip'))['origin']
      except httplib.BadStatusLine:
        pass
      
    return network_address

  @classmethod
  def get_peer_store_key_file(cls, store_id, config_directory):
    """
    Convenience function to compute the location of a peer's (not our own) 
    store's recorded public key file.
    """
    store_filename = Encrypter.compute_safe_filename(store_id)
    key_path = os.path.join(cls.compute_store_keys_directory(config_directory), store_filename+'.pem')
    return key_path

  @classmethod
  def compute_store_keys_directory(cls, config_directory):
    store_keys_directory = os.path.join(cls.compute_keys_directory(config_directory), 'store_keys')
    return store_keys_directory
  
  @staticmethod
  def compute_keys_directory(cls, config_directory):
    keys_directory = os.path.join(config_directory, 'keys')
    return keys_directory
