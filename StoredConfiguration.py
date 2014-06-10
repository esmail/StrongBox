# By Esmail Fadae with design help from Dmitri Ilushin.

import os, shutil, cPickle, copy
from collections import namedtuple

from StrongBox import PeerData, StoreData, INVALID_REVISION
import Encrypter
import PeerConfiguration
import Communicator
import DirectoryMerkleTree

class StoredConfiguration():
  """
  Contains configuration data which must be preserved across executions of 
  StrongBox, and therefore is saved to storage. To maintain consistency and 
  since such writes to storage can be time consuming, this class's interface 
  promotes batching small mutations together cohesively. Also note that 
  StrongBox is (currently) set up so only one thread accesses this data at a 
  time, therefore no access synchronization is attempted.
  """
  
  def __init__(self,
               config_directory = None,
               logger = None,
               encrypter = None,
               configuration_file = None,
               store_dir = None,
               peer_id = None,
               peer_dict = None,
               store_id = None,
               store_dict = None,
               encryption_key = None, # TODO: Make this an RSA-encrypted file in the store to facilitate updating
               merkle_tree = None
               ):
    """
    A simplistic constructor that just sets the defaults and/or overridden attribute values.
    """
    self.logger = logger
    self.encrypter = encrypter
    self.config_dir = config_directory
    self.configuration_file = configuration_file
    self.store_dir = store_dir
    self.peer_id = peer_id
    self.peer_dict = peer_dict
    self.store_id = store_id
    self.store_dict = store_dict
    self.encryption_key = encryption_key
    self.merkle_tree = merkle_tree

  
  @staticmethod
  def load_stored_configuration(logger, encrypter, config_directory):
    """
    Attempt to load a previously stored configuration file, instead trying the 
    backup copy if necessary.
    
    :returns: A `StoredConfiguration` object or `None` if neither file could be loaded.
    """
    stored_configuration = None
    configuration_file = StoredConfiguration.get_configuration_file(config_directory)

    if os.path.isfile(configuration_file):
      logger.debug_print( (1,'Configuration file found, loading.') )
      try:
        stored_configuration = StoredConfiguration.load_configuration_file(logger, encrypter, configuration_file)
      except:
        logger.debug_print( (1, 'Problem loading configuration file.') )

    # If loading the configuration file failed, try the backup
    if stored_configuration is None:
      backup_configuration_file = configuration_file + '.bak'
      if os.path.isfile(backup_configuration_file):
        logger.debug_print( (1, 'Backup configuration file found, loading.') )
        try:
          stored_configuration = StoredConfiguration.load_configuration_file(logger, encrypter, backup_configuration_file)
        except:
          logger.debug_print( (1, 'Problem loading backup configuration file.') )
    
    if stored_configuration is None:
      raise EnvironmentError('Could not load StrongBox configuration file "{}" or backup configuration file "{}".'.format(configuration_file, backup_configuration_file))

    return stored_configuration


  @staticmethod
  def get_configuration_file(config_directory):
    configuration_file = os.path.join(config_directory, 'configuration_file.pickle')
    return configuration_file

  class StoredConfiguration_NamedTuple(
      namedtuple('_StoredConfiguration_NamedTuple' \
                 , 'store_dir, peer_id, peer_dict, store_id, store_dict, encryption_key, merkle_tree')):
    """
    A class wrapper for `_StoredConfiguration_NamedTuple`. A `_StoredConfiguration_NamedTuple`
    contains only the configuration data from a `StoredConfiguration` object that 
    should actually be saved to storage (e.g. not the `encrypter` attribute). 
    Using a named tuple allows us to pickle/unpickle and save/load the data with 
    explicit constraints on the order and number of attributes expected. This 
    should help catch potential saving and loading errors as we evolve the 
    `StoredConfiguration` class and its attribute list.
    """
    pass

  @staticmethod
  def from_tuple(config_directory, logger, encrypter, stored_configuration_tuple):
    store_dir, peer_id, peer_dict, store_id, store_dict, encryption_key, merkle_tree \
        = stored_configuration_tuple
    stored_configuration = \
        StoredConfiguration(config_directory, logger, encrypter, store_dir, peer_id \
                            , peer_dict, store_id, store_dict, encryption_key, merkle_tree)
    return stored_configuration
  
  def to_tuple(self):
    stored_configuration_tuple = \
        self.StoredConfiguration_NamedTuple(self.config_dir, self.logger, self.encrypter \
                                       , self.store_dir, self.peer_id \
                                       , self.peer_dict, self.store_id, self.store_dict \
                                       , self.encryption_key, self.merkle_tree)
    return stored_configuration_tuple


  @staticmethod
  def load_configuration_file(config_directory, logger, encrypter):
    configuration_file = StoredConfiguration.get_configuration_file(config_directory)
    with open(configuration_file, 'r') as f:
      stored_configuration_tuple = cPickle.load(f)

    stored_configuration = StoredConfiguration.from_tuple(config_directory, logger, encrypter, stored_configuration_tuple)
    return stored_configuration


  def save_to_file(self, configuration_file=None):
    if configuration_file == None:
      configuration_file = self.configuration_file
      
    stored_configuration_tuple = self.to_tuple()
    with open(configuration_file, 'w') as f:
      cPickle.dump(stored_configuration_tuple, f)    


  def _update(self, other, save_to_file=True):
    """
    Selectively update the contents of this object with differences provided in 
    `other` saving the new state to storage by default.
    """
    
    # Selectively enact the updates while accumulating output to report.
    print_tuples = [(2, 'Updating stored configuration.')]

    if (other.store_dir != None) and (other.store_dir != self.store_dir):
      self.store_dir = other.store_dir
      print_tuples.append( (2, 'store_dir = {}'.format([self.store_dir])) )
    if (other.peer_id != None) and (other.peer_id != self.peer_id):
      self.peer_id = other.peer_id
      print_tuples.append( (2, 'peer_id = {}'.format([self.peer_id])) )
    if (other.peer_dict != None) and (other.peer_dict != self.peer_dict):
      self.peer_dict = other.peer_dict
      print_tuples.append( (2, '`peer_dict` updated') )
      print_tuples.append( (3, 'peer_dict = {}'.format(self.peer_dict)) )
    if (other.store_id != None) and (other.store_id != self.store_id):
      self.store_id = other.store_id
      print_tuples.append( (2, 'store_id = {}'.format([self.store_id])) )
    if (other.store_dict != None) and (other.store_dict != self.store_dict):
      self.store_dict = other.store_dict
      print_tuples.append( (2, '`store_dict` updated') )
      print_tuples.append( (3, 'store_dict = {}'.format(self.store_dict)) )
    if (other.encryption_key != None) and (other.encryption_key != self.encryption_key):
      self.encryption_key = other.encryption_key
      print_tuples.append( (2, '`encryption_key` updated') )
      print_tuples.append( (4, '!!!! SOOOoo INSECURE !!!!') )
      print_tuples.append( (4, 'encryption_key = {}'.format([self.encryption_key])) )
      
    # Outputting Merkle trees (currently) requires some special considerations.
    merkle_tree_changed = False
    if (other.merkle_tree != None) and (other.merkle_tree != self.merkle_tree):
      self.merkle_tree = other.merkle_tree
      merkle_tree_changed = True
      print_tuples.append( (2, '`merkle_tree` updated') )
      print_tuples.append( (4, 'merkle_tree:') )
        
    self.logger.debug_print( print_tuples )
    if merkle_tree_changed and (self.logger.verbosity >= 4):
          DirectoryMerkleTree.print_tree(self.merkle_tree)

    if save_to_file:
      # Copy the existing configuration file in place of the old backup.
      backup_configuration_file = self.configuration_file + '.bak'
      shutil.copyfile(self.configuration_file, backup_configuration_file)
  
      # Save the new configuration data in place of the old configuration file.
      self.save_to_file(self.configuration_file, other)
      
 
  def record_peer_data(self, peer_id, peer_data):
    """
    Record data on a new peer or update existing information on a known peer in 
    our stored configuration data. Also, accordingly make any necessary updates 
    to our recorded store-peer associations. 
    """
    
    peer_mutual_stores = set(peer_data.store_revisions.keys()).intersection(set(self.store_dict.keys()))
    
    # TODO: Verify that this check is always redundant and remove (or remove duplicate implementation in `learn...`
    # Only want to track peers that are associated with at least one store we're concerned with.
    if not peer_mutual_stores:
      return
    
    # Only want new data.
    if (peer_id in self.peer_dict.keys()) and (peer_data == self.peer_dict[peer_id]):
      return
    
    # Create copies data for staging changes.
    peer_dict_copy = copy.deepcopy(self.peer_dict)
    store_dict_copy = copy.deepcopy(self.store_dict)
    
    # Record the peer's associations with only the stores we care about.
    peer_mutual_store_revisions = dict()
    for mutual_store_id in peer_mutual_stores:
      # Verify the reported revision data before recording.
      if self.encrypter.verify_revision_data(mutual_store_id, peer_data.store_revisions[mutual_store_id]):
        peer_mutual_store_revisions[mutual_store_id] = peer_data.store_revisions[mutual_store_id]
      else:
        peer_mutual_store_revisions[mutual_store_id] = INVALID_REVISION
      # Simultaneously ensure the store's association with the peer to maintain the bidirectional mapping.
      store_dict_copy[mutual_store_id].peers.add(peer_id) 
    
    network_address = peer_data.network_address
    
    # Enact the update.
    peer_dict_copy[peer_id] = PeerData(network_address, peer_mutual_store_revisions)
    metadata = (self.peer_id, peer_dict_copy, self.store_id, store_dict_copy, self.encryption_key, self.aes_iv, self.merkle_tree)
    self.update_metadata(metadata, True)

  def get_revision_data(self, peer_id, store_id):
    """
    A convenience function for retrieving a given peer's revision data for a 
    given store.
    """
    revision_data = self.peer_dict[peer_id].store_revisions[store_id]
    return revision_data

  def gt_revision_data(self, store_id, revision_data_1, revision_data_2):
    """
    A revision is considered greater than another if its signature is valid and 
    either the other's signature is not, or the other revision is numbered lower.
    """
    if not self.encrypter.verify_revision_data(store_id, revision_data_1):
      return False
    
    if not self.encrypter.verify_revision_data(store_id, revision_data_2):
      return True
    
    return revision_data_1.revision_number > revision_data_2.revision_number


  ############
  # Mutators #
  ############

  
  def learn_peer_gossip(self, gossip_peer_id, gossip_peer_dict):
    """
    Update our knowledge of peers based on gossip from another peer.
    """

    # First consider mutual peers that we have in common (not including ourself and the peer we're communicating with).
    mutual_peers = set(gossip_peer_dict.keys()).intersection(set(self.peer_dict.keys())).difference(set([self.peer_id, gossip_peer_id]))
    
    our_stores = set(self.store_dict.keys())
    for peer_id in mutual_peers:
      # Only update if information about received about a peer is newer than our 
      #  records. Currently, the ways of detecting this are somewhat indirect. 
      
      # TODO: Without signing `PeerData` objects, malicious peers 
      #  can manipulate the state of another peer. (Should there be versioning too?)
      gossip_peer_stores = set(gossip_peer_dict[peer_id].store_revisions.keys())
      recorded_peer_stores = set(self.peer_dict[peer_id].store_revisions.keys())
      peer_mutual_stores = gossip_peer_stores.intersection(our_stores)
      
      # See if the gossip indicates the peer is newly associated with a store we also have.
      peer_new_mutual_stores = peer_mutual_stores.difference(recorded_peer_stores)
      if peer_new_mutual_stores != set():
        self.record_peer_data(peer_id, gossip_peer_dict[peer_id], True)
        break
           
      # Otherwise, see if the gossip reports the peer to be more current with any mutual 
      #  store than we knew about.
      gossip_mutual_store_revisions = {store_id: gossip_peer_dict[peer_id].store_revisions[store_id] for store_id in peer_mutual_stores} # Python 2.7+
      recorded_mutual_store_revisions = {store_id: self.peer_dict[peer_id].store_revisions[store_id] for store_id in peer_mutual_stores} # Python 2.7+
      if any( self.gt_revision_data(store_id, gossip_mutual_store_revisions[store_id], recorded_mutual_store_revisions[store_id]) \
              for store_id in peer_mutual_stores):
        self.record_peer_data(peer_id, gossip_peer_dict[peer_id], True)
        break
    
    # Learn new peers associated with our stores of interest.
    unknown_peers = set(gossip_peer_dict.keys()).difference(set(self.peer_dict.keys()))
    for peer_id in unknown_peers:
      gossip_peer_stores = set(gossip_peer_dict[peer_id].store_revisions.keys())
      if set(gossip_peer_stores).intersection(our_stores):
        self.record_peer_data(peer_id, gossip_peer_dict[peer_id], True)
    
   
  def update_network_address(self):
    """Update this peer's already existing IP address data."""
    
    # Create staging copy of data to be changed.
    peer_dict = copy.deepcopy(self.peer_dict)
    
    # Get and store the IP address
    # FIXME: Would like to sign this data (probably the whole `PeerData` object).
    network_address = Communicator.Communicator.get_public_network_address()
    peer_data = PeerData(network_address, peer_dict[self.peer_id].store_revisions)
    peer_dict[self.peer_id] = peer_data
    
    # Enact the change.
    configuration_updates = StoredConfiguration(peer_dict=peer_dict)
    self._update(configuration_updates)


  # FIXME: Determine exactly where this is being called. I don't believe the docstring accurately represents the uses.
  def update_peer_revision(self, peer_id, store_id, invalid=False):
    """
    After sending a peer synchronization data and verifying their store contents, 
    update our recording of their revision for the store in question to match 
    our own.
    """

    # If the peer had a more recent revision than us, no need to update.
    our_revision = self.get_revision_data(self.peer_id, store_id)
    their_revision = self.get_revision_data(peer_id, store_id)
    if self.gt_revision_data(store_id, their_revision, our_revision):
      return
    
    # Create a copy of the pertinent data in which to stage our changes.
    peer_store_revisions = copy.deepcopy(self.peer_dict[peer_id].store_revisions)
    
    if not invalid:
      # Set the peer's revision for the store to match ours.
      self.logger.debug_print( (1, 'Syncing peer verified to hold revision {}'.format(our_revision.revision_number)) )
      peer_store_revisions[store_id] = our_revision
    else:
      # Record the peer's revision for the store as invalid.
      peer_store_revisions[store_id] = INVALID_REVISION
    
    # Enact the changes
    peer_data = PeerData(self.peer_dict[peer_id].network_address, peer_store_revisions)
    self.record_peer_data(peer_id, peer_data)


  def update_store_revision(self, store_id, revision_data, lock=None):
    """
    Increment the revision number and recalculate the corresponding hash and 
    revision signature for the current state of the user's store.
    """
    # Create a copy of the pertinent data in which to stage our changes.
    store_dict_copy = copy.deepcopy(self.store_dict)
    store_dict_copy[store_id] = StoreData(revision_data=revision_data, peers=store_dict_copy[store_id].peers.union(set([self.peer_id])))
    
    # Also modify our own entry in the peer dictionary so we can gossip to other peers about the new revision.
    network_address_copy = self.peer_dict[self.peer_id].network_address
    store_revisions_copy = copy.deepcopy(self.peer_dict[self.peer_id].store_revisions)
    store_revisions_copy[store_id] = revision_data
    updated_peer_data = PeerData(network_address_copy, store_revisions_copy)
    self.record_peer_data(self.peer_id, updated_peer_data)
    
    # Enact the change
    metadata = (self.peer_id, self.peer_dict, self.store_id, store_dict_copy, self.encryption_key, self.aes_iv, self.merkle_tree)
    self.update_metadata(metadata, True)
    
    
  def _compute_store_item_path(self, store_id, item_relative_path):
    """Compute the absolute path to an item within a particular store."""
    if store_id == self.store_id:
      root_directory = self.store_dir
    else:
      peer_backups_directory = PeerConfiguration.PeerConfiguration.compute_peer_backups_directory(self.config_dir)
      store_dirname = Encrypter.Encrypter.compute_safe_filename(store_id)
      root_directory = os.path.join(peer_backups_directory, store_dirname)
    
    item_absolute_path = os.path.join(root_directory, item_relative_path)
    return item_absolute_path


  def store_put_item(self, store_id, item_relative_path, file_contents=None):
    """
    Save a new directory or file, or update a file within a locally held store 
    (either the user's own store or the backup of another store).
    """ 
    if item_relative_path[-1] == '/':
      is_directory = True
    else:
      is_directory = False
      
    if store_id == self.store_id:
      # Undo the item_absolute_path encryption done while creating our Merkle tree.
      output_tuples = [ (2, 'item_relative_path (encrypted) = {}'.format(item_relative_path)) ]
      item_relative_path = self.encrypter.decrypt_own_store_path(item_relative_path)
      output_tuples.append( (2, 'item_relative_path (decrypted) = {}'.format(item_relative_path)) )
      
      # If a file, decrypt the contents
      if not is_directory:
        file_contents = self.decrypt(file_contents)
        output_tuples.append( (5, 'file_contents (decrypted) = {}'.format(file_contents)) )
      
      self.logger.debug_print(output_tuples)
      
    item_absolute_path = self._compute_store_item_path(store_id, item_relative_path)
    
    if is_directory:
      self.debug_print( [(1, 'Writing directory to store.')] )

      if not os.path.isdir(item_absolute_path):
        os.makedirs(item_absolute_path)
    else:
      # Create subdirectory levels as needed.
      containing_directory = os.path.dirname(item_absolute_path)
      if not os.path.isdir(containing_directory):
        os.makedirs(containing_directory)
      
      self.debug_print( [(1, 'Writing file to store.')] )

      with open(item_absolute_path, 'w') as f:
        f.write(file_contents)


  def store_delete_item(self, store_id, item_relative_path):
    """
    Delete a file or directory from a locally held store (either the user's or 
    a backup of another user's store).
    """
    if store_id == self.store_id:
      # Undo the item_absolute_path encryption done while creating our Merkle tree.
      item_relative_path = self.decrypt_own_store_path(item_relative_path)
      self.debug_print( [(2, 'item_relative_path (decrypted) = {}'.format(item_relative_path))] )
      
    item_absolute_path = self._compute_store_item_path(store_id, item_relative_path)
    
    if os.path.isfile(item_absolute_path):
      self.debug_print( (1, 'Deleting file from store.') )
      os.remove(item_absolute_path)
    elif os.path.isdir(item_absolute_path):
      self.debug_print( (1, 'Deleting directory (and contents) from store.') )
      # Note that this deletes the non-empty directories, so depending on the 
      #  ordering of delete items we might preemptively delete files or folders
      #  that still have pending delete requests.
      shutil.rmtree(item_absolute_path)


  def store_get_item_contents(self, store_id, item_relative_path):
    """
    Get the contents of a file (or return `None` for a directory) in preparation for
    transmission, decrypting on-the-fly if the item originates from the user's store.
    """
    # Directory
    if item_relative_path[-1] == '/':
      return None
    
    if store_id == self.store_id:
      # Undo the item_absolute_path encryption done while creating our Merkle tree.
      item_relative_path = self.encrypter.decrypt_own_store_path(item_relative_path)
    
    item_absolute_path = self._compute_store_item_path(store_id, item_relative_path)
    
    with open(item_absolute_path, 'r') as f:
      file_contents = f.read()
      
    if store_id == self.store_id:
      file_contents = self.encrypt(file_contents)
    
    return file_contents
  
  
  