# By Esmail Fadae with inspiration from https://github.com/sangeeths/merkle-tree

import os
from os import path
from os import listdir
from os.path import isdir, isfile
from hashlib import sha256
import base64


empty_directory_hash = sha256('empty directory').digest()

def make_dmt(root_directory=os.getcwd(), nonce='', encrypter=None):
  """
  Generate a Merkle tree object for the directory provided. The resulting Merkle 
  tree captures the state of the directory in the form of hierarchically 
  generated hashes of the directories contents. A nonce can optionally be provided 
  to facilitate remote verification of directory contents.
  """
  if not isdir(root_directory):
    raise IOError('The root directory supplied, \'{}\', is not in fact a directory.'.format(root_directory))
  
  directory_contents = listdir(root_directory)
  
  if not directory_contents:
    empty_directory_cipher = sha256('empty_directory')
    
    if nonce:
      empty_directory_cipher.update(nonce)
      
    return DirectoryMerkleTree(dmt_hash=empty_directory_cipher.digest(), children=None)
    
  children = dict()
  
  for filesystem_item in directory_contents:
    item_path = path.join(root_directory, filesystem_item)
    
    if isfile(item_path):
      filename = filesystem_item
      file_path = path.join(root_directory, filename)
      with open(file_path, 'r') as f:
        file_contents = f.read()
      
      if encrypter:
        filename = encrypter.encrypt_filename(filename)
        file_contents = encrypter.encrypt(file_contents)
      
      file_hash = sha256(file_contents)
      file_hash.update(filename) # Obscure the case where files have identical contents.
      
      if nonce:
        file_hash.update(nonce)
        
      dmt_child = DirectoryMerkleTree(dmt_hash=file_hash.digest(), children=None)
      children[filename] = dmt_child
      
    elif isdir(item_path):
      subdir_name = filesystem_item
      subdir_path = path.join(root_directory, subdir_name)
      
      dmt_subtree = make_dmt(subdir_path, nonce, encrypter)
      
      if encrypter:
        subdir_name = encrypter.encrypt_filename(subdir_name)
        
      # Append a slash to facilitate detection of new empty folders upon comparison.
      subdir_name += '/'
      
      children[subdir_name] = dmt_subtree
      
    # Item was neither file nor directory...
    else:
      raise IOError('Item \'{}\' is neither a file nor directory.'.format(item_path))
      
  # Compile all child hashes to compute this tree's hash.
  tree_hash = sha256()
  for child in children.values():
    tree_hash.update(child.dmt_hash)
    
  dmt_tree = DirectoryMerkleTree(dmt_hash=tree_hash.digest(), children=children)
  return dmt_tree

# FIXME: Allow this to optionally accumulate output in a string.
def print_tree(tree):
  """
  Recursively print out the hash of the tree, the tree's contents, and the 
  printed output from those contents.
  """
  if not tree:
    print None
    return
  
  if tree.children:
    print 'Directory hash = {}'.format(base64.urlsafe_b64encode(tree.dmt_hash))
    print 'Contents:'
    for name, subtree in tree.children.iteritems():
      print
      print name
      print_tree(subtree)
  
  else:
    print 'File hash = {}'.format(base64.urlsafe_b64encode(tree.dmt_hash))

def compute_tree_changes(dmt_new, dmt_old, directory_path=''):
  """
  Compare the Merkle trees for two directories and return lists of the items 
  added, updated, and delted.
  """
  updated, new, deleted = set(), set(), set()
  # Base cases:
  # Both files or empty directories
  if (not dmt_new.children) and (not dmt_old.children):
    return updated, new, deleted
  # New directory
  elif not dmt_old.children:
    mutual_filesystem_items = set()
    new_filesystem_items = set(dmt_new.children.keys())
    deleted_filesystem_items = set()
  elif not dmt_new.children:
    mutual_filesystem_items = set()
    new_filesystem_items = set()
    deleted_filesystem_items = set(dmt_old.children.keys())
  else:
    mutual_filesystem_items   = set(dmt_new.children.keys()).intersection(set(dmt_old.children.keys()))
    new_filesystem_items      = set(dmt_new.children.keys()).difference(set(dmt_old.children.keys()))
    deleted_filesystem_items  = set(dmt_old.children.keys()).difference(set(dmt_new.children.keys()))
  
  
  # Compile the set of updated files and directories, as well as any other changes within subdirectories.
  for filesystem_item in mutual_filesystem_items:
    # Always check subdirectories for e.g file renamings.
    if filesystem_item[-1] == '/':
      subdir_name = filesystem_item
      subdir_path = directory_path + subdir_name
      subdir_updated, subdir_new, subdir_deleted = \
          compute_tree_changes(dmt_new.children[subdir_name], dmt_old.children[subdir_name], subdir_path)
      
      # Mark the subdirectory if necessary.
      if (dmt_old.children[subdir_name].dmt_hash != dmt_new.children[subdir_name].dmt_hash) or \
          subdir_updated or subdir_new or subdir_deleted:
        updated.add(subdir_path)
      
      # Incorporate differences from within.
      updated.update(subdir_updated)
      new.update(subdir_new)
      deleted.update(subdir_deleted)
    
    # File with differing hash values.
    elif dmt_old.children[filesystem_item].dmt_hash != dmt_new.children[filesystem_item].dmt_hash:
      filename = filesystem_item
      file_path = directory_path + filename
      updated.add(file_path)
  
  # Compile the set of newly created files.
  for filesystem_item in new_filesystem_items:
    item_path = directory_path + filesystem_item
    new.add(item_path)
    new.update(get_all_paths(dmt_new.children[filesystem_item], item_path))
    
  # Compile the set of deleted files.
  for filesystem_item in deleted_filesystem_items:
    item_path = directory_path + filesystem_item
    deleted.add(item_path)
    deleted.update(get_all_paths(dmt_old.children[filesystem_item], item_path))
  
  return updated, new, deleted

def get_all_paths(dmt, directory_path=''):
  """
  Return the relative paths to all of the contents of a directory Merkle tree.
  """
  # Base case.
  if not dmt.children:
    return set()
  
  filesystem_items = set()
  for item in dmt.children.keys():
    filesystem_items.add(directory_path+item)
    # Also get the paths of subdirectory contents.
    if item[-1] == '/':
      subdir_name = item
      subdir_path = directory_path + subdir_name
      
      filesystem_items.add(subdir_path)
      filesystem_items.update(get_all_paths(dmt.children[subdir_name], subdir_path))
    
  return filesystem_items
  

class DirectoryMerkleTree:
  """
  A simple tree implementation designed to contain Merkle tree information about 
  a directory or file.
  """
  def __init__(self, dmt_hash, children):
    self.dmt_hash = dmt_hash
    self.children = children
  
  def __eq__(self, other):
    if not other:
      return False
    
    if type(other) is not type(self):
      raise TypeError('{} is not equal to {}'.format(type(self), type(other)))
    
    updated, new, deleted = compute_tree_changes(self, other)
    
    if updated or new or deleted:
      return False
    else:
      return True
    
  def __ne__(self, other):
    return not (self == other)
    
  def compare_trees(self):
    None
  
  def get_updated_tree(self):
    None

