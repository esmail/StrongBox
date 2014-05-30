# By Esmail Fadae.

import os, hashlib, Crypto.Random, Crypto.PublicKey, Crypto.Cipher.AES, Crypto.Hash.SHA256, Crypto.Signature, cPickle, base64
from PeerConfiguration import PeerConfiguration
from StrongBox import RevisionData, INVALID_REVISION

# FIXME: This is a shitty, shitty name for this class.
class Encrypter():

  def __init__(self,
               logger,
               encryption_key,
               config_directory,
               peer_id=None,
               store_id=None):
    
    self.logger = logger
    self.encryption_key = encryption_key
    self.config_directory = config_directory
    
    # Load or generate the private and public keys.
    self.private_key = self.load_private_key(self.config_directory)
    self.public_key = self.load_public_key(self.config_directory, self.private_key)
    
    # Set defaults and incoming overrides.
    if store_id is None:
      store_id = self.generate_store_id(self.public_key)
    self.store_id = store_id
    
    if peer_id is None:
      peer_id = self.generate_peer_id()
    self.peer_id = peer_id
    

  @staticmethod
  def generate_encryption_key():
    key_size = Crypto.Cipher.AES.key_size[-1] # The maximum `pycrypto` supports (32 bytes a.k.a. 256 bits as of 2014.05.20)
    encryption_key = Crypto.Random.new().read(key_size)
    return encryption_key
    

  def generate_peer_id(self):
    """
    Generate a quasi-unique ID for this peer using a hash (SHA-256, which
    currently has no known collisions) of the owner's public key "salted" with
    32 random bits.
    """
    cipher = hashlib.sha256(self.public_key.exportKey())
    cipher.update(Crypto.Random.new().read(4))
    peer_id = cipher.digest()
    self.logger.debug_print( (2, 'Generated new peer ID: {}'.format([peer_id])) )
    return peer_id
    
    
  def generate_store_id(self, public_key=None):
    """
    Store IDs are meant to uniquely identify a store/user. They are essentially
    the RSA public key, but we use use their SHA-256 hash to "flatten" them to
    a shorter, predictable length.
    """
    # Default to using own public key.
    if public_key is None:
      public_key = self.public_key
    
    store_id = hashlib.sha256(public_key.exportKey()).digest()
    self.logger.debug_print( (2, 'Generated new store ID: {}'.format([store_id])) )
    return store_id
    
  @classmethod
  def load_public_key(cls, config_directory, private_key=None):
    if private_key is None:
      private_key = cls.load_private_key(config_directory)
    
    public_key = private_key.publickey()  
    return public_key
  
  def load_store_key(self, store_id):
    """
    Convenience function to load a store's public key .
    """
    if store_id == self.store_id:
      store_key = self.public_key
    else:
      store_key_file = PeerConfiguration.get_foreign_store_key_file(store_id, self.config_directory)
      with open(store_key_file, 'r') as f:
        store_key = Crypto.PublicKey.RSA.importKey(f.read())
    
    return store_key
  
  def load_peer_key(self, peer_id):
    """
    Convenience function to load a peer's public key.
    """
    if peer_id == self.peer_id:
      public_key = self.public_key
    else:
      peer_key_file = PeerConfiguration.get_foreign_peer_key_file(peer_id, self.config_directory)
      with open(peer_key_file, 'r') as f:
        public_key = Crypto.PublicKey.RSA.importKey(f.read())
    return public_key  
    
  
  @staticmethod
  def load_private_key(config_directory):
    private_key_file = PeerConfiguration.get_private_key_file(config_directory)
    
    # Load from a previously generated file.
    if os.path.isfile(private_key_file):
      with open(private_key_file, 'r') as f:
        private_key = Crypto.PublicKey.RSA.importKey(f.read())
    # Otherwise, generate and save a new private key.
    else:
      private_key = Crypto.PublicKey.RSA.generate(4096)
      with open(private_key_file, 'w') as f:
        f.write(private_key.exportKey())
    
    return private_key
  
  @property
  def store_id(self):
    return self._store_id
  @store_id.setter
  def store_id(self, value):
    # Make sure the store ID and public key match.
    if value != self.generate_store_id(self.public_key):
      raise RuntimeError('Store ID and encryption key do not match.')
    elif value != self.store_id: 
      self._store_id = value
  
  
  def sign(self, payload):
    """
    Convenience primative for computing a signature for any string.
    """
    payload_hash = Crypto.Hash.SHA256.new(payload)
    signature = Crypto.Signature.PKCS1_v1_5.new(self.private_key).sign(payload_hash)
    return signature


  def verify(self, store_id, signature, payload):
    """
    Convenience primative for verifying the signature associated with a string.
    """
    public_key = self.load_store_key(store_id)
    payload_hash = Crypto.Hash.SHA256.new(payload)
    return Crypto.Signature.PKCS1_v1_5.new(public_key).verify(payload_hash, signature)

  
  def get_signed_revision_data(self, revision_number, store_hash):
    """
    A convenience function for adding a signature to generated revision data.
    """
    # Pickle and sign the revision data
    pickled_payload = cPickle.dumps( (revision_number, store_hash) )
    signature = self.sign(pickled_payload)
    signed_revision_data = RevisionData(revision_number=revision_number, store_hash=store_hash, signature=signature)
    return signed_revision_data
  
  def verify_revision_data(self, store_id, revision_data):
    """
    Verify the validity and signature of revision data.
    """
    if (revision_data == INVALID_REVISION) or (not revision_data.signature):
      return False
    
    pickled_payload = cPickle.dumps( (revision_data.revision_number, revision_data.store_hash) )
    return self.verify(store_id, revision_data.signature, pickled_payload)
  
  
  def encrypt(self, plaintext):
    """
    Deterministically encrypt the input string using AES.
    """
    # Deterministically generate the initialization vector in order to facilitate hash-based integrity checks of this
    #  on-the-fly encrypted data. Do so by taking a hash of our private key data "salted" with the unencrypted plaintext.
    # TODO: Have not examined the potential (in)security implications of this scheme for IV generation.
    aes_iv_cipher = hashlib.sha256(self.private_key.exportKey())
    aes_iv_cipher.update(plaintext)
    aes_iv = aes_iv_cipher.digest()[0:Crypto.Cipher.AES.block_size] # Only keep a block worth of bytes and throw out the rest.
    cipher = Crypto.Cipher.AES.new(self.encryption_key, Crypto.Cipher.AES.MODE_CFB, aes_iv)
    ciphertext = aes_iv + cipher.encrypt(plaintext)
    return ciphertext


  def decrypt(self, ciphertext):
    """
    Decrypt AES-encrypted data.
    """
    aes_iv = ciphertext[:Crypto.Cipher.AES.block_size] # Reclaim the IV from the first bytes of the ciphertext.
    cipher = Crypto.Cipher.AES.new(self.encryption_key, Crypto.Cipher.AES.MODE_CFB, aes_iv)
    plaintext = cipher.decrypt(ciphertext)[Crypto.Cipher.AES.block_size:] # Decrypt everything after the IV.
    return plaintext


  def encrypt_filename(self, filename):
    encrypted_filename = self.encrypt(filename)
    return self.compute_safe_filename(encrypted_filename)


  def decrypt_filename(self, safe_encrypted_filename):
    encrypted_filename = base64.urlsafe_b64decode(safe_encrypted_filename)
    filename = self.decrypt(encrypted_filename)
    return filename


  def decrypt_own_store_path(self, encrypted_relative_path):
    """
    Convert an encrypted, store-relative path to its original form.
    """
    print_tuples = [ (1, 'encrypted_relative_path = {}'.format(encrypted_relative_path)) ]
    
    encrypted_path_elements = encrypted_relative_path.split('/')
    decrypted_path_elements = [self.decrypt_filename(e) for e in encrypted_path_elements]
    decrypted_relative_path = '/'.join(decrypted_path_elements)
    
    print_tuples.append( (1, 'decrypted_relative_path = {}'.format(decrypted_relative_path)) )
    self.logger.debug_print(print_tuples)
    
    return decrypted_relative_path


  @staticmethod   
  def compute_safe_filename(input_string):
    """
    Take any string of characters (e.g. the result of a SHA hash) and reversibly 
    convert it to a valid filename.
    """
    return base64.urlsafe_b64encode(input_string)

