# By Esmail Fadae.

import unittest, os
from StoredConfiguration import StoredConfiguration
from Logger import NullLogger

class TestStoredConfiguration(unittest.TestCase):
  test_dir = '.test_temp'

  def setUp(self):
    # Create and enter temporary directory for test files.
    os.mkdir(self.test_dir)
    os.chdir(self.test_dir)
    
    logger = NullLogger()
    
    