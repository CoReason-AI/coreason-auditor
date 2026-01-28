import os
import sys

# Add the mock libs directory to sys.path so tests can find coreason_identity
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "libs")))
