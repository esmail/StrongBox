# By Esmail Fadae.

import os, shutil
from StrongBox import PeerData, StoreData
import DirectoryMerkelTree
import StoredConfiguration
import Encrypter
from Logger import NullLogger
import Communicator

class PeerConfiguration():
  """
  The configuration of a StrongBox peer.
  DESIGN TRADEOFF: Introducing an undesired level of access indirection (e.g. 
  `peer_configuration.store_configuration.peer_id` for the time being and putting 
  off creating a more convenient facade (which should be the eventual solution) 
  for the time being.
  """
  
  def compute_config_directory(self):
    config_directory = os.path.join(self.root_directory, '.strongbox_config')
    return config_directory
    
  @classmethod
  def get_private_key_file(cls, config_directory):
    private_key_file = os.path.join(config_directory, 'private_rsa_key.pem')
    return private_key_file
    
  @staticmethod
  def compute_keys_directory(cls, config_directory):
    keys_directory = os.path.join(config_directory, 'keys')
    return keys_directory
  
  @classmethod
  def compute_peer_keys_directory(cls, config_directory):
    peer_keys_directory = os.path.join(cls.compute_keys_directory(config_directory), 'peer_keys')
    return peer_keys_directory
  
  @classmethod
  def compute_store_keys_directory(cls, config_directory):
    store_keys_directory = os.path.join(cls.compute_keys_directory(config_directory), 'store_keys')
    return store_keys_directory
  
  @classmethod
  def get_foreign_peer_key_file(cls, peer_id, config_directory):
    peer_filename = Encrypter.Encrypter.compute_safe_filename(peer_id)
    key_path = os.path.join(cls.compute_peer_keys_directory(config_directory), peer_filename+'.pem')
    return key_path
  
  @classmethod
  def get_foreign_store_key_file(cls, store_id, config_directory):
    """
    Convenience function to compute the location of another (not our own) 
    store's recorded public key file.
    """
    store_filename = Encrypter.Encrypter.compute_safe_filename(store_id)
    key_path = os.path.join(cls.compute_store_keys_directory(config_directory), store_filename+'.pem')
    return key_path
  
  
  def compute_peer_backups_directory(self):
    peer_backups_directory = os.path.join(self.root_directory, '.store_backups')
    return peer_backups_directory


  # TODO: Figure out if there are cases where these directories should/shouldn't be erased.
  def initialize_directory_structure(self):
    peer_backups_directory = self.compute_peer_backups_directory()
    keys_directory = self.compute_keys_directory(self.config_directory)
    store_keys_directory = self.compute_store_keys_directory(self.config_directory)
    peer_keys_directory = self.compute_peer_keys_directory(self.config_directory)
    
    necessary_directories = [peer_backups_directory, keys_directory, store_keys_directory, peer_keys_directory]
    for directory in necessary_directories:
      if not os.path.isdir(directory):
        os.makedirs(directory)

    
  @staticmethod
  def clear_own_store_contents(own_store_directory):
    """
    Remove any pre-existing data within the user's store directory in preparation
    for initiating a new initial configuration and new initial store.
    """
    store_contents = os.listdir(own_store_directory)
    if store_contents:
      # FIXME: It would be safer to just have the user manually delete the files on their own.
      delete_store_contents = raw_input('Store directory \'{}\' must be empty prior to first execution. Okay to delete? [y/n] '.format(own_store_directory))

      if not delete_store_contents == 'y':
        raise IOError()
      else:
        shutil.rmtree(own_store_directory)
        os.makedirs(own_store_directory)


  # FIXME NOW: Loading a previous stored configuration is key. Reformulate this around that activity.
  def __init__(self,
               root_directory = None,
               logger = None,
               encrypter = None,
               stored_configuration = None,
               configuration_file = None,
               own_store_directory = None,
               peer_id = None,
               peer_dict = None,
               store_id = None,
               store_dict = None,
               encryption_key = None, # TODO: Make this an RSA-encrypted file in the store to facilitate updating
               merkel_tree = None
               ):
    
    # Set defaults and overrides.
    if root_directory == None:
      root_directory = os.getcwd()
    self.root_directory = root_directory
    self.config_directory = self.compute_config_directory()
    self.initialize_directory_structure()
    
    if configuration_file == None:
      configuration_file = os.path.join(self.config_directory, 'configuration_file.pickle')
    self.configuration_file = configuration_file
    
    if logger == None:
      logger = NullLogger() # FIXME: Replace once an actual implementation of `Logger` is ready.
    self.logger = logger
    
    if encryption_key is None:
      encryption_key = Encrypter.Encrypter.generate_encryption_key()
      
    # Now that we have our encryption key, instantiate a new `Encrypter` with it or supply it to the one provided.
    if encrypter == None:
      encrypter = Encrypter.Encrypter(self.logger, encryption_key, self.config_directory, peer_id, store_id)
    else:
      encrypter.encryption_key = encryption_key
    self.encrypter = encrypter
      
    if own_store_directory is None:
      own_store_directory = os.path.join(os.getcwd(), 'own_store')
    self.own_store_directory = own_store_directory
    # Since we're doing initialization, make sure the store is empty for the first revision.
    self.clear_own_store_contents(own_store_directory)
    
    if peer_id is None:
      peer_id = encrypter.peer_id
    self.peer_id = peer_id
    
    if store_id is None:
      store_id = encrypter.store_id
    self.store_id = store_id
    
    if merkel_tree is None:
      merkel_tree = DirectoryMerkelTree.make_dmt(own_store_directory, encrypter=encrypter)

    # Prepare and sign the initial revision data.
    revision_number = 1
    store_hash = merkel_tree.dmt_hash
    own_store_revision_data = encrypter.get_signed_revision_data(revision_number, store_hash)
    
    # TODO: Should the network address be overrideable for testing purposes?
    network_address = Communicator.Communicator.get_public_network_address()
    if peer_dict is None:
      peer_dict = {peer_id: PeerData(network_address, {store_id: own_store_revision_data})}
    
    if store_dict is None:
      initial_peers = set([peer_id])
      store_dict = {store_id: StoreData(own_store_revision_data, initial_peers)}
    
    if stored_configuration is None:
      try:
        # FIXME: Will also want to set overridden attributes like `store_dict` given how this interface is shaping up (is that actually necessary)?
        stored_configuration = StoredConfiguration.StoredConfiguration.load_stored_configuration(self.logger, self.encrypter, self.config_directory)
      except EnvironmentError:
        stored_configuration = StoredConfiguration.StoredConfiguration(self.config_directory, logger, encrypter, configuration_file \
                               , own_store_directory, peer_id, peer_dict, store_id \
                               , store_dict, encryption_key, merkel_tree)
    self.stored_configuration = stored_configuration

    # Finally, save the configuration to storage ensuring a backup copy also exists.
    self.stored_configuration.save_to_file()
    backup_configuration_file = configuration_file + '.bak'
    self.stored_configuration.save_to_file(configuration_file=backup_configuration_file)
    
    