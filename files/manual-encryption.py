#!/usr/bin/env python
# -*- coding: utf-8 -*-

""" Manually encrypt a wep message given the WEP key"""

__author__      = "Robin Gaudin & Axel Vallon"
__copyright__   = "Copyright 2022, HEIG-VD"
__license__ 	= "GPL"
__version__ 	= "1.0"
__email__ 	= "robin.gaudin@heig-vd.ch & axel.vallon@heig-vd.ch"
__status__ 	= "Prototype"

from scapy.all import *
from rc4 import RC4
import zlib

# Paramètres (repris de la trame et du script manual-decryption)
message = b'\xaa\xaa\x03\x00\x00\x00\x08\x06\x00\x01\x08\x00\x06\x04\x00\x01\x90\x27\xe4\xea\x61\xf2\xc0\xa8\x01\x64\x00\x00\x00\x00\x00\x00\xc0\xa8\x01\xc8'
key = b'\xaa\xaa\xaa\xaa\xaa'
iv = b'\x0c\x4d\x5c'

# Création du seed pour l'encryption avec RC4
seed = iv + key

# Calcul de l'icv avec crc32, et conversion en bytes
icv = zlib.crc32(message).to_bytes(4, byteorder='little')

# Création du payload
payload = message + icv

# Encryption du message avec son icv en utilisant un cipher généré par RC4
cipher = RC4(seed)
ciphertext = cipher.crypt(payload)

# Création de la trame avec les paramètres générés
arp = rdpcap('arp.cap')[0]
arp.wepdata = ciphertext[:-4]
arp.icv = struct.unpack('!L', ciphertext[-4:])[0]
arp.iv = iv

# Export de la trame dans un fichier pcap
wrpcap('manual-encryption.pcap', arp)
