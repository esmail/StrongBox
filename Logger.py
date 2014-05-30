# By Esmail Fadae.

class NullLogger():
  """A "null" logger implementation to facilitate testing of other classes."""
  verbosity=0
  
  @staticmethod
  def debug_print(print_tuples):
    pass
