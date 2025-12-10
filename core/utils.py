import os

def ensure_directory_exists(path):
    # Check if the path has a file extension
    if os.path.splitext(path)[1]:
        directory_path = os.path.dirname(path)
    else:
        directory_path = path
    
    if not os.path.exists(directory_path):
        os.makedirs(directory_path)