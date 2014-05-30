import unittest
import DirectoryMerkelTree
import os, shutil

# These need to be set by the class method `setUpClass` and accessed by the test methods.
updated_dirs = set()
new_dirs = set()
tree_original = None
tree_modified = None


class TestDirectoryMerkelTree(unittest.TestCase):
  test_dir = '.test_temp'
  original_dir = 'original'
  modified_dir = 'modified'
  unmodified_files = {'unmodified_0', 'unmod_0/unmodified_1'}
  updated_files = {'updated_0', 'upd_0/updated_1'}
  updated_empty_dirs = {'upd_1'}
  new_files = {'new_0', 'upd_1/new_1', 'newdir_0/new_2'}
  deleted_files = {'deleted_0', 'upd_2/deleted_1', 'del_0/deleted_2'}
  deleted_dirs = {'del_0/', 'del_1/'}

  @staticmethod
  def get_parent_dirs(path):
    parent_dirs = set()
    p_dir = os.path.dirname(path)
    while p_dir != '':
      parent_dirs.add(p_dir+'/')
      p_dir = os.path.dirname(p_dir)
    return parent_dirs

  # Reusable expensive set up.
  @classmethod
  def setUpClass(cls):
    # Globals that will be mutated.
    global updated_dirs, new_dirs, tree_original, tree_modified

    # Create and enter a temporary directory for test files.
    os.mkdir(cls.test_dir)
    os.chdir(cls.test_dir)

    # The subdirectory 'original' will act as the initial state.
    os.mkdir(cls.original_dir)
    for original_file in cls.unmodified_files.union(cls.updated_files).union(cls.deleted_files):
      relative_dir = os.path.join(cls.original_dir,os.path.dirname(original_file))
      if not os.path.isdir(relative_dir):
        os.makedirs(relative_dir)
      with open(os.path.join(cls.original_dir,original_file), 'w') as f:
        f.write(os.urandom(8)) # Fill each file with 8 bytes of random data.
    # Create empty directories that will be updated with new files.
    for updated_empty_dir in cls.updated_empty_dirs:
      if not os.path.isdir(os.path.join(cls.original_dir, updated_empty_dir)):
        os.mkdir(os.path.join(cls.original_dir, updated_empty_dir))
    # Create any necessary directories that will be deleted.
    for deleted_dir in cls.deleted_dirs:
      if not os.path.isdir(os.path.join(cls.original_dir, deleted_dir)):
        os.mkdir(os.path.join(cls.original_dir, deleted_dir))

    # Copy over the original contents.
    shutil.copytree(cls.original_dir, cls.modified_dir)
    # Update the specified files.
    for updated_file in cls.updated_files:
      with open(os.path.join(cls.modified_dir,updated_file), 'a') as f:
        f.write(os.urandom(8)) # Append in 8 more bytes of random data.
      # Keep track of modified directories, recurring up the tree.
      updated_dirs.update(cls.get_parent_dirs(updated_file))
    # Newly create the specified files.
    for new_file in cls.new_files:
      relative_dir = os.path.join(cls.modified_dir,os.path.dirname(new_file))
      if not os.path.isdir(relative_dir):
        os.mkdir(relative_dir)
        # Keep track of new directories. WARNING: Non-recursive when this is a nested subdirectory.
        new_dirs.add(os.path.dirname(new_file)+'/')
      elif os.path.dirname(new_file):
        updated_dirs.add(os.path.dirname(new_file)+'/')
      with open(os.path.join(cls.modified_dir, new_file), 'w') as f:
        f.write(os.urandom(8)) # Fill each new file with 8 bytes of random data.

    # Delete the specified files.
    for deleted_file in cls.deleted_files:
      os.remove(os.path.join(cls.modified_dir, deleted_file))
      # Keep track of modified directories, recurring up the tree.
      updated_dirs.update(cls.get_parent_dirs(deleted_file))
    # Delete the specified directories
    for deleted_dir in cls.deleted_dirs:
      os.rmdir(os.path.join(cls.modified_dir, deleted_dir))
      if deleted_dir in updated_dirs:
        updated_dirs.remove(deleted_dir)

    # Generate the Merkel trees.
    tree_original = DirectoryMerkelTree.make_dmt(cls.original_dir)
    tree_modified = DirectoryMerkelTree.make_dmt(cls.modified_dir)


  @classmethod
  def tearDownClass(cls):
    os.chdir('..')
    shutil.rmtree(cls.test_dir)

  def test_hash_determinism(self):
    """
    Check that a directory produces the same hash when a Merkel tree is made
    from it twice in a row.
    """
    hash_original = tree_original.dmt_hash
    hash_original_regenerated = DirectoryMerkelTree.make_dmt(self.original_dir).dmt_hash
    self.assertEqual(hash_original, hash_original_regenerated)

  def test_tree_equality(self):
    """Test the implementation of the equality checking for the `DirectoryMerkelTree` class."""
    self.assertEqual(tree_original, tree_original)

  def test_tree_determinism(self):
    """Check that a directory produces the same Merkel tree twice in a row."""
    tree_original_regenerated = DirectoryMerkelTree.make_dmt(self.original_dir)
    self.assertEqual(tree_original, tree_original_regenerated)

  def test_hash_inequality(self):
    hash_original = tree_original.dmt_hash
    hash_modified = tree_modified.dmt_hash
    self.assertNotEqual(hash_original, hash_modified)

  def test_tree_inequality(self):
    self.assertNotEqual(tree_original, tree_modified)

  def test_tree_difference_unmodified(self):
    updated, new, deleted = DirectoryMerkelTree.compute_tree_changes(tree_modified, tree_original)
    modified_items = updated.union(new).union(deleted)
    self.assertTrue(self.unmodified_files.isdisjoint(modified_items))

  def test_tree_difference_updated(self):
    updated, _, _ = DirectoryMerkelTree.compute_tree_changes(tree_modified, tree_original)
    self.assertEqual(updated, self.updated_files.union(updated_dirs), 'Error in calculating updated items.')

  def test_tree_difference_new(self):
    _, new, _ = DirectoryMerkelTree.compute_tree_changes(tree_modified, tree_original)
    self.assertEqual(new, self.new_files.union(new_dirs), 'Error in calculating new items.')

  def test_tree_difference_deleted(self):
    _, _, deleted = DirectoryMerkelTree.compute_tree_changes(tree_modified, tree_original)
    self.assertEqual(deleted, self.deleted_files.union(self.deleted_dirs), 'Error in calculating deleted items.')


