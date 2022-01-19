#!/usr/bin/env python
from passlib.hash import atlassian_pbkdf2_sha1
import passlib.utils.handlers as uh
from passlib.utils.compat import str_to_bascii, u, uascii_to_str, unicode
from passlib.utils import to_unicode
from base64 import b64encode, b64decode
from binascii import hexlify, unhexlify
import sys,getopt
import os


def getHashParam(hash):
    hash = to_unicode(hash, "ascii", "hash")
    ident = u("{PKCS5S2}")
    if not hash.startswith(ident):
        raise uh.exc.InvalidHashError()
    data = b64decode(hash[len(ident):].encode("ascii"))
    salt, chk = data[:16], data[16:]
    salt = hexlify(salt).decode("ascii")
    chk = hexlify(chk).decode("ascii")
    return salt, chk

def verifyPassword(passHash,password):
    salt,chk = getHashParam(passHash)
    s = unhexlify(salt)
    a = atlassian_pbkdf2_sha1.using(salt=s)
    if a.verify(password,passHash):
        print("[+]",password,":",passHash)

def hashBlasting(passwordfile,hashfile):
    with open(passwordfile,'r') as f:
        for clearpass in f.readlines():
            clearpass = clearpass.strip()
            with open(hashfile,'r') as fp:
                for hashline in fp.readlines():
                    hashline = hashline.strip()
                    verifyPassword(hashline,clearpass)
        f.close()
        fp.close()

def parse_arguments(argv):
    passwordfile = ''
    hashfile = ''
    try:
        opts, args = getopt.getopt(argv, "hp:f:", ["help", "passwordfile=","hashfile="])
    except getopt.GetoptError:
        sys.exit(2)

    if len(argv) < 1:
        sys.exit(2)

    for opt, arg in opts:
        if opt in ("-h", "--help"):
            print("python3 atlassian_pbkdf2_dehash.py -p <passwordfile> -f <hashfile>")
            sys.exit()
        elif opt in ("-p", "--passwordfile"):
            passwordfile = arg
            if not os.path.exists(passwordfile):
                print("[-] clear password file does not exists!")
                sys.exit(2)
        elif opt in ("-f", "--hashfile"):
            hashfile = arg
            if not os.path.exists(hashfile):
                print("[-] atlassian pdkdf2 file does not exists!")
                sys.exit(2)
    return passwordfile,hashfile


if __name__ == "__main__":
    passwordfile,hashfile = parse_arguments(sys.argv[1:])
    hashBlasting(passwordfile,hashfile)