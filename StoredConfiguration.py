# By Esmail Fadae with design help from Dmitri Ilushin

import os, shutil, cPickle
from StrongBox import PeerData, StoreData, RevisionData
from Encrypter import Encrypter
import DirectoryMerkelTree

class StoredConfiguration():
  """
  Configuration data which must be preserved across executions of StrongBox, and
  therefore must be saved to storage.
  """
  
  @staticmethod
  def get_configuration_file(config_directory):
    configuration_file = os.path.join(config_directory, 'configuration_file.pickle')
    return configuration_file

  @classmethod
  def get_stored_configuration(cls, logger, encrypter, config_directory):
    """
    Attempt to load a previously stored configuration file, instead trying the 
    backup copy or generating a new configuration as needed.
    """
    configuration = None
    configuration_file = cls.get_configuration_file(config_directory)

    if os.path.isfile(configuration_file):
      logger.debug_print( (1,'Configuration file found, loading.') )
      try:
        configuration = cls.load_configuration_file(logger, encrypter, configuration_file)
      except:
        logger.debug_print( (1, 'Problem loading configuration file.') )

    # If loading the configuration file failed, try the backup
    if configuration is None:
      backup_configuration_file = configuration_file + '.bak'
      if os.path.isfile(backup_configuration_file):
        logger.debug_print( (1, 'Backup configuration file found, loading.') )
        try:
          configuration = cls.load_configuration_file(logger, encrypter, backup_configuration_file)
        except:
          logger.debug_print( (1, 'Problem loading backup configuration file.') )

    # If loading the backup configuration file failed, generate a new configuration.
    if configuration is None:
      logger.debug_print( (1, 'Generating new StrongBox peer configuration.') )
      configuration = cls(logger, encrypter, config_directory)

    return configuration


  @classmethod
  def load_configuration_file(cls, logger, encrypter, configuration_file):
    with open(configuration_file, 'r') as f:
      configuration_data = cPickle.load(f)

    ( own_store_directory,
      peer_id,
      peer_dict,
      store_id,
      store_dict,
      aes_key,
      merkel_tree) = configuration_data

    config_directory = os.path.dirname(configuration_file)
    configuration = cls(logger,
                        encrypter,
                        config_directory,
                        own_store_directory,
                        peer_id,
                        peer_dict,
                        store_id,
                        store_dict,
                        aes_key,
                        merkel_tree)

    return configuration

  def create_configuration_file(self, configuration_data=None, configuration_file_path=None):
    if configuration_data is None:
      configuration_data = (self.own_store_directory,
                            self.peer_id,
                            self.peer_dict,
                            self.store_id,
                            self.store_dict,
                            self.encryption_key,
                            self.merkel_tree)
    
    if configuration_file_path == None:
      configuration_file_path = self.configuration_file
      
    # Store the new configuration data.
    with open(configuration_file_path, 'w') as f:
      cPickle.dump(configuration_data, f)    

  def update_configuration_file(self, configuration_data=None):
    """Back up the previous configuration data and save the current configuration."""
    # Use the current configuration file as the new backup.
    backup_configuration_file = self.configuration_file + '.bak'
    shutil.copyfile(self.configuration_file, backup_configuration_file)

    # Store the new configuration data.
    self.create_configuration_file(self.configuration_file, configuration_data)

  def __init__(self,
               logger,
               encrypter,
               config_directory,
               own_store_directory = None,
               peer_id = None,
               peer_dict = None,
               store_id = None,
               store_dict = None,
               aes_key = None, # TODO: Make this an RSA-encrypted file in the store to facilitate updating
               merkel_tree = None
               ):
    """Initialize the configuration data."""

    # Since we're doing initialization, make sure the store is empty for the first revision.
    self.clear_own_store_contents()

    # Set defaults and incoming overrides.
    self.configuration_file = self.get_configuration_file(config_directory)
    
    if own_store_directory is None:
      own_store_directory = os.path.join(os.getcwd(), 'own_store')
    self.own_store_directory = own_store_directory
    
    if aes_key is None:
      aes_key = Encrypter.generate_encryption_key()
    self.encryption_key = aes_key
    
    # Now that we have our encryption key, instantiate a new `Encrypter` with it or supply it to the provided one.
    if encrypter is None:
      encrypter = Encrypter(logger, aes_key, config_directory)
    else:
      encrypter.encryption_key = aes_key
    self.encrypter = encrypter
    
    if peer_id is None:
      peer_id = Encrypter.peer_id
    else:
      Encrypter.peer_id = peer_id
    self.peer_id = peer_id
    
    # Always ignore the passed in `store_id` since the ID must match the encryption key provided to `encrypter`.
    self.store_id = encrypter.store_id
    
    if merkel_tree is None:
      merkel_tree = DirectoryMerkelTree.make_dmt(self.own_store_directory, encrypter=encrypter)
    self.merkel_tree = merkel_tree
    
    # Prepare and sign the initial revision data.
    revision_number = 1
    store_hash = self.merkel_tree.dmt_hash
    own_store_revision_data = encrypter.get_signed_revision_data(revision_number, store_hash)
    
    # TODO: Should the network address be overrideable for testing purposes?
    network_address = self.get_public_network_address()
    if peer_dict is None:
      peer_dict = {peer_id: PeerData(network_address, {store_id: own_store_revision_data})}
    self.peer_dict = peer_dict
    
    if store_dict is None:
      initial_peers = set([peer_id])
      store_dict = {store_id: StoreData(own_store_revision_data, initial_peers)}
    self.store_dict = store_dict
    
    # Finally, save the configuration to storage ensuring a backup copy also exists.
    self.create_configuration_file()
    backup_configuration_file = self.configuration_file + '.bak'
    self.create_configuration_file(configuration_file_path=backup_configuration_file)

  def clear_own_store_contents(self):
    """
    Remove any pre-existing data within the user's store directory in preparation
    for initiating a new initial configuration and new initial store.
    """
    store_contents = os.listdir(self.own_store_directory)
    if store_contents:
      delete_store_contents = raw_input('Store directory \'{}\' must be empty prior to first execution. Okay to delete? [y/n] '.format(self.own_store_directory))

      if not delete_store_contents == 'y':
        raise IOError()
      else:
        shutil.rmtree(self.own_store_directory)
        os.makedirs(self.own_store_directory)


