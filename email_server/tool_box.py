"""
Utility functions for the email server.
"""

import os

def ensure_folder_exists(filepath):
    """
    Ensure that the folder for the given filepath exists.
    """
    if filepath.startswith("sqlite:///"):
        filepath = filepath.replace("sqlite:///", "", 1)
    os.makedirs(os.path.dirname(filepath), exist_ok=True)