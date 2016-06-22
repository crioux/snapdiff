import _winreg
import os
import sys
import zipfile
import tempfile
import argparse
import hashlib
import codecs
import re
import ctypes

wow64key = 0
re_excludedir = []
re_excludereg = []


def Is64Windows():
    return 'PROGRAMFILES(X86)' in os.environ

if Is64Windows():
    wow64key = _winreg.KEY_WOW64_64KEY
    Wow64DisableWow64FsRedirection = ctypes.windll.kernel32.Wow64DisableWow64FsRedirection
    old_value = ctypes.c_long()
    Wow64DisableWow64FsRedirection(ctypes.byref(old_value))


def subkeys(key, numsubkeys):

    i = 0

    while i < numsubkeys:
        try:
            subkey = _winreg.EnumKey(key, i)
            yield subkey
        except WindowsError as e:
            pass
        i += 1


def walk_registry(rootkey, keypath, key=None, full_keypath=None):

    if args.verbose:
        print u"{0}\\{1}".format(reghivestr[rootkey], full_keypath)

    if key is None:
        key = rootkey
    if full_keypath is None:
        full_keypath = keypath

    if keypath:
        keypaths = keypath.split("\\")
        for kp in keypaths:
            try:
                key = _winreg.OpenKey(key, kp, 0, wow64key | _winreg.KEY_READ)
            except WindowsError as e:
                return

    info = _winreg.QueryInfoKey(key)
    modft = info[2]

    yield (full_keypath, key, modft)

    subkeynames = []
    for subkeyname in subkeys(key, info[0]):
        subkeynames.append(subkeyname)

    for subkeyname in subkeynames:

        if full_keypath:
            next_full_keypath = full_keypath + "\\" + subkeyname
        else:
            next_full_keypath = subkeyname

        # Don't do this recursively!
        if keypath.endswith("Wow6432Node") and subkeyname == "Wow6432Node":
            continue

        for x in walk_registry(rootkey,
                               subkeyname,
                               key,
                               (full_keypath + "\\" + subkeyname) if full_keypath else subkeyname):
            yield x

def hash_multi_sz(x):
    if x is None:
        return None
    m = hashlib.md5()
    for s in x:
        m.update(bytearray(s, "utf-16-le"))
    return m.digest()

_valdatahashes={}
_valdatahashes[_winreg.REG_BINARY] = lambda x: None if x is None else hashlib.md5(x).digest()
_valdatahashes[_winreg.REG_DWORD] = lambda x: None if x is None else x
_valdatahashes[_winreg.REG_DWORD_LITTLE_ENDIAN] = lambda x: None if x is None else x
_valdatahashes[_winreg.REG_DWORD_BIG_ENDIAN] = lambda x: None if x is None else x
_valdatahashes[_winreg.REG_EXPAND_SZ] = lambda x: None if x is None else hashlib.md5(bytearray(x, "utf-16-le")).digest()
_valdatahashes[_winreg.REG_LINK] = lambda x: None if x is None else hashlib.md5(x).digest()
_valdatahashes[_winreg.REG_MULTI_SZ] = hash_multi_sz
_valdatahashes[_winreg.REG_NONE] = lambda x: None if x is None else hashlib.md5(x).digest()
_valdatahashes[_winreg.REG_RESOURCE_LIST] = lambda x: None if x is None else hashlib.md5(x).digest()
_valdatahashes[_winreg.REG_FULL_RESOURCE_DESCRIPTOR] = lambda x: None if x is None else hashlib.md5(x).digest()
_valdatahashes[_winreg.REG_RESOURCE_REQUIREMENTS_LIST] = lambda x: None if x is None else hashlib.md5(x).digest()
_valdatahashes[_winreg.REG_SZ] = lambda x: None if x is None else hashlib.md5(bytearray(x, "utf-16-le")).digest()
_valdatahashes[11] = lambda x: None if x is None else x

def valdatahash(data, type):
    if type not in _valdatahashes:
        return None
    return _valdatahashes[type](data)


def key_values(key):
    i = 0
    while True:
        try:
            valtuple = _winreg.EnumValue(key, i)
            yield (valtuple[0], valdatahash(valtuple[1], valtuple[2]), valtuple[2])
            i += 1
        except WindowsError as e:
                break


def snap_directory(dir):
    dir = os.path.abspath(dir)
    print u"Snapping directory '{0}'".format(dir)
    snap = []

    for root, dirs, files in os.walk(dir, topdown=False):
        if args.verbose:
            for d in dirs:
                print u"{0}".format(os.path.join(root, d))
            for f in files:
                print u"{0}".format(os.path.join(root, f))
        snap.append((root, dirs, files))

    return snap

def snap_registry(reg):
    print u"Snapping registry '{0}'".format(reg)

    regparts = reg.split("\\", 1)
    if len(regparts) == 1:
        rootkey = regparts[0]
        rootkeypath = ""
    else:
        rootkey = regparts[0]
        rootkeypath = regparts[1]

    rootkey = reghiveval[rootkey]
    snap = []

    for (keypath, key, modft) in walk_registry(rootkey, rootkeypath):

        values = []
        for (vname, vhash, vtype) in key_values(key):
            values.append((vname, vhash, vtype))

        snap.append((rootkey, keypath, modft, values))

#    print "snap: {}".format(snap)

    return snap

def snap_all():

    dsnap = []
    rsnap = []

    for d in args.dir:
        s = snap_directory(d)
        dsnap.append(s)

    for r in args.reg:
        s = snap_registry(r)
        rsnap.append(s)

    snap = {"dirs": dsnap, "regs": rsnap}

    return snap

def match_excludedir(p):
    for exc in re_excludedir:
        if exc.match(p):
            return True
    return False

def match_excludereg(p):
    for exc in re_excludereg:
        if exc.match(p):
            return True
    return False

def diff_directory(zf, dirs1, dirs2):
    d1set = set()

    # Get all paths from first snap into fast set
    for dir in dirs1:
        for (root, dirs, files) in dir:
            for d in dirs:
                d1path = os.path.join(root, d)
                if not match_excludedir(d1path):
                    d1set.add(d1path)
            for f in files:
                f1path = os.path.join(root, f)
                if not match_excludedir(f1path):
                    d1set.add(f1path)

    # Build list of all paths in the second snap that are not in the first snap
    diffpaths = []
    for dir in dirs2:
        for root, dirs, files in dir:
            for d in dirs:
                dp = os.path.join(root, d)
                if not match_excludedir(dp):
                    if dp not in d1set:
                        diffpaths.append(dp)
            for f in files:
                fp = os.path.join(root, f)
                if not match_excludedir(fp):
                    if fp not in d1set:
                        diffpaths.append(fp)

    for dp in diffpaths:
        try:
            if os.path.isabs(dp):
                # If absolute path c:\foo\bar, then write to location c\foo\bar
                (drive, path) = dp.split(u":", 1)
                if args.includedrive:
                    dpname = u"{0}{1}".format(drive.lower(), path)
                else:
                    dpname = path[1:]
            else:
                dpname = dp

            zf.write(dp, dpname)

            print "Added: " + dp
        except:
            print "Skipped: " + dp

def diff_values(values1, values2):

    vh1set = set()
    diffvalues = []

    for (vname, vhash, vtype) in values1:
        vh1set.add(vhash)

    for (vname, vhash, vtype) in values2:
        if vhash not in vh1set:
            diffvalues.append((vname, vhash, vtype))

    return diffvalues


def diff_registry(zf, regs1, regs2):

    k1set = dict()

    # Get all keys in the first set
    for reglist in regs1:
        for (hkey, keypath, modft, values) in reglist:
            kindex = reghivestr[hkey] + u"\\" + keypath
            if not match_excludereg(kindex):
                k1set[kindex] = (modft, values)

    # Get all keys in the second set
    diffkeys = []
    for reglist in regs2:
        for (hkey, keypath, modft, values) in reglist:
            kindex = reghivestr[hkey] + u"\\" + keypath
            if not match_excludereg(kindex):
                if kindex in k1set:
                    (k1modft, k1values) = k1set[kindex]
                    if modft != k1modft:
                        diffvalues = diff_values(k1values, values)
                        diffkeys.append((hkey, keypath, diffvalues))
                else:
                    diffkeys.append((hkey, keypath, values))

    # Write regfile
    write_regfile(zf, diffkeys)

reghivestr={}
reghivestr[u"HKEY_CLASSES_ROOT"]=u"HKEY_CLASSES_ROOT"
reghivestr[u"HKEY_CURRENT_USER"]=u"HKEY_CURRENT_USER"
reghivestr[u"HKEY_LOCAL_MACHINE"]=u"HKEY_LOCAL_MACHINE"
reghivestr[u"HKEY_USERS"]=u"HKEY_USERS"
reghivestr[u"HKEY_CURRENT_CONFIG"]=u"HKEY_CURRENT_CONFIG"
reghivestr[u"HKCR"]=u"HKEY_CLASSES_ROOT"
reghivestr[u"HKCU"]=u"HKEY_CURRENT_USER"
reghivestr[u"HKLM"]=u"HKEY_LOCAL_MACHINE"
reghivestr[u"HKU"]=u"HKEY_USERS"
reghivestr[u"HKCC"]=u"HKEY_CURRENT_CONFIG"
reghivestr[_winreg.HKEY_CLASSES_ROOT]=u"HKEY_CLASSES_ROOT"
reghivestr[_winreg.HKEY_CURRENT_USER]=u"HKEY_CURRENT_USER"
reghivestr[_winreg.HKEY_LOCAL_MACHINE]=u"HKEY_LOCAL_MACHINE"
reghivestr[_winreg.HKEY_USERS]=u"HKEY_USERS"
reghivestr[_winreg.HKEY_CURRENT_CONFIG]=u"HKEY_CURRENT_CONFIG"

reghiveval={}
reghiveval[u"HKEY_CLASSES_ROOT"]=_winreg.HKEY_CLASSES_ROOT
reghiveval[u"HKEY_CURRENT_USER"]=_winreg.HKEY_CURRENT_USER
reghiveval[u"HKEY_LOCAL_MACHINE"]=_winreg.HKEY_LOCAL_MACHINE
reghiveval[u"HKEY_USERS"]=_winreg.HKEY_USERS
reghiveval[u"HKEY_CURRENT_CONFIG"]=_winreg.HKEY_CURRENT_CONFIG
reghiveval[u"HKCR"]=_winreg.HKEY_CLASSES_ROOT
reghiveval[u"HKCU"]=_winreg.HKEY_CURRENT_USER
reghiveval[u"HKLM"]=_winreg.HKEY_LOCAL_MACHINE
reghiveval[u"HKU"]=_winreg.HKEY_USERS
reghiveval[u"HKCC"]=_winreg.HKEY_CURRENT_CONFIG
reghiveval[_winreg.HKEY_CLASSES_ROOT]=_winreg.HKEY_CLASSES_ROOT
reghiveval[_winreg.HKEY_CURRENT_USER]=_winreg.HKEY_CURRENT_USER
reghiveval[_winreg.HKEY_LOCAL_MACHINE]=_winreg.HKEY_LOCAL_MACHINE
reghiveval[_winreg.HKEY_USERS]=_winreg.HKEY_USERS
reghiveval[_winreg.HKEY_CURRENT_CONFIG]=_winreg.HKEY_CURRENT_CONFIG


def reghexstr(val):
    valstr = u""
    if val:
        first = True
        for x in val:
            if not first:
                valstr += u","
            else:
                first=False
            valstr += u"{0:02x}".format(x)
    return valstr

def regquotestr(s):
    return u"\"" + s.replace(u"\\", u"\\\\").replace(u"\"", u"\\\"") + u"\""


def regvaluestring(val, vtype):

    if not val:
        valstr = u"hex({0:1x}):".format(vtype)
    elif vtype == _winreg.REG_DWORD:
        valstr = u"dword:{0:08x}".format(val)
    elif vtype == _winreg.REG_EXPAND_SZ:
        valstr = reghexstr(bytearray(val, "utf-16-le"))
        if len(valstr) > 0:
            valstr += u","
        valstr += u"00,00"
        valstr = u"hex({0:1x}):".format(vtype) + valstr
    elif vtype == _winreg.REG_SZ:
        isprint = True
        val = unicode(val)
        for x in val:
            if ord(x) < 32:
                isprint = False
                break
        if isprint:
            valstr = regquotestr(val)
        else:
            valstr = reghexstr(bytearray(val, "utf-16-le"))
            if len(valstr) > 0:
                valstr += u","
            valstr += u"00,00"
            valstr = u"hex({0:1x}):".format(vtype) + valstr
    elif vtype == _winreg.REG_MULTI_SZ:
        valstr = u""
        for s in val:
            if len(valstr) > 0:
                valstr += u","
            valstr += reghexstr(bytearray(s, "utf-16-le"))
            if len(valstr) > 0:
                valstr += u","
            valstr += u"00,00"
        if len(valstr) > 0:
            valstr += u","
        valstr = u"hex({0:1x}):".format(vtype) + valstr + u"00,00"
    else:
        valstr = u"hex({0:1x}):".format(vtype) + reghexstr(bytearray(val))

    return valstr


def write_regfile(zf, diffkeys):

    f = tempfile.NamedTemporaryFile(delete=False)

    f.write(codecs.BOM_UTF16_LE)
    f.write(u"Windows Registry Editor Version 5.00\r\n\r\n".encode('utf-16-le'))
    for (hkey, keypath, diffvalues) in diffkeys:
        print u"Writing registry key: {0}\\{1}".format(reghivestr[hkey], keypath)
        try:
            key = _winreg.OpenKey(hkey, keypath, 0, wow64key | _winreg.KEY_READ)
        except:
            print u"Unable to open key"
            continue

        if not keypath:
            f.write(u"[{0}]\r\n".format(reghivestr[hkey]).encode('utf-16-le'))
        else:
            f.write(u"[{0}\\{1}]\r\n".format(reghivestr[hkey], keypath).encode('utf-16-le'))

        for (vname, vhash, vtype) in diffvalues:
            try:
                val = _winreg.QueryValueEx(key, vname)[0]
                if not vname:
                    f.write(u"@={0}\r\n".format(regvaluestring(val, vtype)).encode('utf-16-le'))
                else:
                    f.write(u"{0}={1}\r\n".format(regquotestr(vname), regvaluestring(val, vtype)).encode('utf-16-le'))
            except:
                print u"Unable to query value"
                continue

        f.write(u"\r\n".encode('utf-16-le'))

    f.close()

    print u"Writing registry diff"
    zf.write(f.name, u"snapdiff.reg")

    os.remove(f.name)


def diff_all(zf, snap1, snap2):
    diff_registry(zf, snap1["regs"], snap2["regs"])
    diff_directory(zf, snap1["dirs"], snap2["dirs"])

def main():

    snap1 = snap_all()

    raw_input(u"Press Enter to perform second snapshot...")

    snap2 = snap_all()

    with zipfile.ZipFile(args.out, "w", zipfile.ZIP_DEFLATED, True) as zf:
        print "Zipping diff to: " + args.out
        diff_all(zf, snap1, snap2)

    sys.exit(0)

if __name__=="__main__":

    parser = argparse.ArgumentParser(description=u"SnapDiff (c) 2016 - Christien Rioux")
    parser.add_argument("-d", "--dir", type=unicode, action='append', default=[],
                        help="Select filesystem directories to watch")
    parser.add_argument("-r", "--reg", type=unicode, action='append', default=[],
                        help="Select registry hives/subkeys to watch")
    parser.add_argument("-o", "--out", type=unicode, default=u"snapdiff.zip", help="Name of output zipfile")
    parser.add_argument("-v", "--verbose", action="store_true", default=False, help="Print extra information about the process")
    parser.add_argument("--includedrive", action="store_true", default=False, help="Store drive letter in zipfile paths")
    parser.add_argument("--excludedir", type=unicode, action='append', default=[], help="Exclude regex patterns from filesystem")
    parser.add_argument("--excludereg", type=unicode, action='append', default=[], help="Exclude regex patterns from registry")

    parser.add_help = True
    args = parser.parse_args()

    if len(args.dir) == 0:
        args.dir = [u"C:\\"]
    if len(args.reg) == 0:
        args.reg = [u"HKEY_LOCAL_MACHINE"]
    if len(args.excludedir) == 0:
        args.excludedir = [ur"^C:\\ProgramData\\Package Cache.*",
                           ur"^C:\\System\ Volume\ Information.*",
                           ur"^C:\\Users.*",
                           ur"^C:\\Documents\ and\ Settings.*",
                           ur"^C:\\Windows\\Prefetch.*",
                           ur"^C:\\Windows\\Installer.*",
                           ur"^C:\\Windows\\Logs.*",
                           ur"^C:\\Windows\\Servicing.*",
                           ur"^C:\\Windows\\SoftwareDistribution.*"]
    if len(args.excludereg) == 0:
        args.excludereg = [ur"^HKEY_LOCAL_MACHINE\\COMPONENTS.*",
                           ur"^HKEY_LOCAL_MACHINE\\Schema.*"]

    if len(args.dir) == 1 and (args.dir[0] == u"none" or args.dir[0] == u""):
        args.dir = []
    if len(args.reg) == 1 and (args.reg[0] == u"none" or args.reg[0] == u""):
        args.reg = []
    if len(args.excludedir) == 1 and (args.excludedir[0] == u"none" or args.excludedir[0] == u""):
        args.excludedir = []
    if len(args.excludereg) == 1 and (args.excludereg[0] == u"none" or args.excludereg[0] == u""):
        args.excludereg = []

    for exc in args.excludedir:
        re_excludedir.append(re.compile(exc, re.IGNORECASE))
    for exc in args.excludereg:
        re_excludereg.append(re.compile(exc, re.IGNORECASE))

    main()


