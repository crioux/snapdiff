import _winreg
import os
import sys
import zipfile
import tempfile
import argparse
import hashlib
import codecs
import platform

wow64key = 0

def Is64Windows():
    return 'PROGRAMFILES(X86)' in os.environ

if Is64Windows():
    wow64key = _winreg.KEY_WOW64_64KEY


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
    print "Snapping directory '{0}'".format(dir)
    snap = []

    for root, dirs, files in os.walk(dir, topdown=False):
        snap.append((root, dirs, files))

    return snap

def snap_registry(reg):
    print "Snapping registry '{0}'".format(reg)

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

def diff_directory(dirs1, dirs2):
    d1set = set()

    # Get all paths from first snap into fast set
    for dir in dirs1:
        for (root, dirs, files) in dir:
            for d in dirs:
                d1set.add(os.path.join(root, d))
            for f in files:
                d1set.add(os.path.join(root, f))

    # Build list of all paths in the second snap that are not in the first snap
    diffpaths = []
    for dir in dirs2:
        for root, dirs, files in dir:
            for d in dirs:
                dp = os.path.join(root, d)
                if dp not in d1set:
                    diffpaths.append(dp)
            for f in files:
                fp = os.path.join(root, f)
                if fp not in d1set:
                    diffpaths.append(fp)

    print "Zipping diff to: " + args.out

    with zipfile.ZipFile(args.out, 'w', zipfile.ZIP_DEFLATED, True) as zf:
        for dp in diffpaths:
            try:
                print "Adding: " + dp
                zf.write(dp)
            except:
                print "Skipped file"

def diff_values(values1, values2):

    vh1set = set()
    diffvalues = []

    for (vname, vhash, vtype) in values1:
        vh1set.add(vhash)

    for (vname, vhash, vtype) in values2:
        if vhash not in vh1set:
            diffvalues.append((vname, vhash, vtype))

    return diffvalues


def diff_registry(regs1, regs2):

    k1set = dict()

    # Get all keys in the first set
    for reglist in regs1:
        for (hkey, keypath, modft, values) in reglist:
            kindex = reghivestr[hkey] + "/" + keypath
            k1set[kindex] = (modft, values)

    # Get all keys in the second set
    diffkeys = []
    for reglist in regs2:
        for (hkey, keypath, modft, values) in reglist:
            kindex = reghivestr[hkey] + "/" + keypath
            if kindex in k1set:
                (k1modft, k1values) = k1set[kindex]
                if modft != k1modft:
                    diffvalues = diff_values(k1values, values)
                    diffkeys.append((hkey, keypath, diffvalues))
            else:
                diffkeys.append((hkey, keypath, values))

    # Write regfile
    write_regfile(diffkeys)

reghivestr={}
reghivestr["HKEY_CLASSES_ROOT"]="HKEY_CLASSES_ROOT"
reghivestr["HKEY_CURRENT_USER"]="HKEY_CURRENT_USER"
reghivestr["HKEY_LOCAL_MACHINE"]="HKEY_LOCAL_MACHINE"
reghivestr["HKEY_USERS"]="HKEY_USERS"
reghivestr["HKEY_CURRENT_CONFIG"]="HKEY_CURRENT_CONFIG"
reghivestr["HKCR"]="HKEY_CLASSES_ROOT"
reghivestr["HKCU"]="HKEY_CURRENT_USER"
reghivestr["HKLM"]="HKEY_LOCAL_MACHINE"
reghivestr["HKU"]="HKEY_USERS"
reghivestr["HKCC"]="HKEY_CURRENT_CONFIG"
reghivestr[_winreg.HKEY_CLASSES_ROOT]="HKEY_CLASSES_ROOT"
reghivestr[_winreg.HKEY_CURRENT_USER]="HKEY_CURRENT_USER"
reghivestr[_winreg.HKEY_LOCAL_MACHINE]="HKEY_LOCAL_MACHINE"
reghivestr[_winreg.HKEY_USERS]="HKEY_USERS"
reghivestr[_winreg.HKEY_CURRENT_CONFIG]="HKEY_CURRENT_CONFIG"

reghiveval={}
reghiveval["HKEY_CLASSES_ROOT"]=_winreg.HKEY_CLASSES_ROOT
reghiveval["HKEY_CURRENT_USER"]=_winreg.HKEY_CURRENT_USER
reghiveval["HKEY_LOCAL_MACHINE"]=_winreg.HKEY_LOCAL_MACHINE
reghiveval["HKEY_USERS"]=_winreg.HKEY_USERS
reghiveval["HKEY_CURRENT_CONFIG"]=_winreg.HKEY_CURRENT_CONFIG
reghiveval["HKCR"]=_winreg.HKEY_CLASSES_ROOT
reghiveval["HKCU"]=_winreg.HKEY_CURRENT_USER
reghiveval["HKLM"]=_winreg.HKEY_LOCAL_MACHINE
reghiveval["HKU"]=_winreg.HKEY_USERS
reghiveval["HKCC"]=_winreg.HKEY_CURRENT_CONFIG
reghiveval[_winreg.HKEY_CLASSES_ROOT]=_winreg.HKEY_CLASSES_ROOT
reghiveval[_winreg.HKEY_CURRENT_USER]=_winreg.HKEY_CURRENT_USER
reghiveval[_winreg.HKEY_LOCAL_MACHINE]=_winreg.HKEY_LOCAL_MACHINE
reghiveval[_winreg.HKEY_USERS]=_winreg.HKEY_USERS
reghiveval[_winreg.HKEY_CURRENT_CONFIG]=_winreg.HKEY_CURRENT_CONFIG


def reghexstr(val):
    valstr = u""
    if val:
        first=True
        for x in val:
            if not first:
                valstr += u","
            else:
                first=False
            valstr += u"{0:02x}".format(x)
    return valstr


def regvaluestring(val, vtype):
    if vtype == _winreg.REG_DWORD or vtype == _winreg.REG_DWORD_LITTLE_ENDIAN or vtype == _winreg.REG_DWORD_BIG_ENDIAN:
        valstr = u"{0:08x}".format(val)
    elif vtype == _winreg.REG_EXPAND_SZ:
        valstr = reghexstr(bytearray(val, "utf-16-le"))
        if len(valstr) > 0:
            valstr += u","
        valstr += u"00,00"
        valstr = u"hex({0:1x}):".format(vtype) + valstr
    elif vtype == _winreg.REG_SZ:
        if val:
            isprint = True
            val = unicode(val)
            for x in val:
                if ord(x) < 32:
                    isprint = False
                    break
            if isprint:
                valstr = u"\"" + val.replace(u"\\", u"\\\\").replace(u"\"", u"\\\"") + u"\""
            else:
                valstr = reghexstr(bytearray(val, "utf-16-le"))
                if len(valstr) > 0:
                    valstr += u","
                valstr += u"00,00"
                valstr = u"hex({0:1x}):".format(vtype) + valstr
        else:
            valstr = u"hex({0:1x}):".format(vtype)
    elif vtype == _winreg.REG_MULTI_SZ:
        valstr = u""
        if val:
            for s in val:
                if len(valstr) > 0:
                    valstr += u","
                valstr += reghexstr(bytearray(s, "utf-16-le"))
                if len(valstr) > 0:
                    valstr += u","
                valstr += u"00,00"
            if len(valstr) > 0:
                valstr += u","
            valstr += u"00,00"
        valstr = u"hex({0:1x}):".format(vtype) + valstr
    else:
        valstr = u"hex({0:1x}):".format(vtype) + reghexstr(bytearray(val))
    return valstr


def write_regfile(diffkeys):

    f = tempfile.NamedTemporaryFile(delete=False)

    f.write(codecs.BOM_UTF16_LE)
    f.write(u"Windows Registry Editor Version 5.00\r\n\r\n".encode('utf-16-le'))
    for (hkey, keypath, diffvalues) in diffkeys:
        print "Writing registry key: {0}\\{1}".format(reghivestr[hkey], keypath)
        try:
            key = _winreg.OpenKey(hkey, keypath, 0, wow64key | _winreg.KEY_READ)
        except:
            print "Unable to open key"
            continue

        if not keypath:
            f.write(u"[{0}]\r\n".format(reghivestr[hkey]).encode('utf-16-le'))
        else:
            f.write(u"[{0}\\{1}]\r\n".format(reghivestr[hkey], keypath).encode('utf-16-le'))

        for (vname, vhash, vtype) in diffvalues:
            val = _winreg.QueryValueEx(key, vname)[0]
            f.write(u"\"{0}\"={1}\r\n".format(vname, regvaluestring(val, vtype)).encode('utf-16-le'))

        f.write(u"\r\n".encode('utf-16-le'))

    f.close()

    with zipfile.ZipFile(args.out, 'w', zipfile.ZIP_DEFLATED, True) as zf:
        print "Writing registry diff"
        zf.write(f.name, "snapdiff.reg")

    os.remove(f.name)


def diff_all(snap1, snap2):
    diff_registry(snap1["regs"], snap2["regs"])
    diff_directory(snap1["dirs"], snap2["dirs"])

def main():

    snap1 = snap_all()

    raw_input("Press Enter to perform second snapshot...")

    snap2 = snap_all()

    diff_all(snap1, snap2)

    sys.exit(0)

if __name__=="__main__":

    parser = argparse.ArgumentParser(description="SnapDiff (c) 2016 - Christien Rioux")
    parser.add_argument("-d", "--dir", action='append', default=[],
                        help="Select filesystem directories to watch")
    parser.add_argument("-r", "--reg", action='append', default=[],
                        help="Select registry hives/subkeys to watch")
    parser.add_argument("-o", "--out", type=str, default="snapdiff.zip", help="Name of output zipfile")
    parser.add_help = True
    args = parser.parse_args()

    if len(args.dir) == 0:
        args.dir = ["C:\\"]
    if len(args.reg) == 0:
        args.reg = ["HKLM", "HKCU"]

    main()


