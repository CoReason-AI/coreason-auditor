import sys
import os

# Add the mock libs directory to sys.path so tests can find coreason_identity
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "libs")))
