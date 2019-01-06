import os

def files(path):
    for file in os.listdir(path):
        if os.path.isfile(os.path.join(path, file)):
            yield os.path.join(path, file)

def directories(path):
    for file in os.listdir(path):
        if os.path.isdir(os.path.join(path, file)):
            yield os.path.join(path, file)

def mkdir(path):
    """Same as os.mkdir but ignores errors due to existing directories"""
    try:
        os.mkdir(path)
    except FileExistsError:
        pass

def mkdir_recursive(path):
    total_path = ""
    for component in os.path.normpath(path).split(os.sep):
        total_path = os.path.join(total_path, component)
        mkdir(total_path)

def chown_parents(path, uid, gid):
    if os.path.isabs(path):
        raise ValueError("Path must not be absolute (this is always an error)")

    total_path = ""
    for component in os.path.normpath(path).split(os.sep):
        total_path = os.path.join(total_path, component)
        os.chown(total_path, uid, gid)

def chown_recursive(path, uid, gid):
    includeroot = True
    for root, dirs, files in os.walk(path, followlinks=False):
        if includeroot:
            objects = ["."] + dirs + files
            includeroot = False
        else:
            objects = dirs + files

        for obj in objects:
            path = os.path.join(root, obj)
            path = os.path.normpath(path)
            os.chown(path, uid, gid)
