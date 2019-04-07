#!/usr/bin/env python
# -*- coding: utf-8 -*-

""" Manually encrypt a wep message given the WEP key"""

__author__      = "Guillaume Blanco, Patrick Neto"
__version__ 	= "1.0"
__email__ 		= "guillaume.blanco@heig-vd.ch, patrick.neto@heig-vd.ch"

from scapy.all import *
import os
import rc4
import binascii

# message que l on veut chiffrer
MESSAGE  = "Bonjour Patrick comment tu vas ?"
CAPFILE_CLAIR = "arp.cap"
CAPFILE_CHIFFRE = "arp_chiffre.cap"

#Cle wep AA:AA:AA:AA:AA
key = '\xaa\xaa\xaa\xaa\xaa'

# On recupere un message qui va nous servir de base
arp = rdpcap(CAPFILE_CLAIR)[0]

# On extrait l iv du message et on le concatene avec notre cle pour creer notre seed (pour l algo RC4)
seed = arp.iv + key

crc_msg = binascii.crc32(MESSAGE)

# on concatene le message et l icv pour avoir le message a chiffrer
message_a_chiffrer = MESSAGE + struct.pack('<i', crc_msg)

# on chiffre le message avec rc4
message_chiffre = rc4.rc4crypt(message_a_chiffrer, seed)

# "le ICV est les derniers 4 octets - je le passe en format Long big endian"
icv_chiffre = message_chiffre[-4:]
(icv_numerique,) = struct.unpack('!L', icv_chiffre)

# le message chiffre sans le ICV
text_chiffre = message_chiffre[:-4]

print("Message clair   = " + message_a_chiffrer.encode("hex"))
print("Texte clair     = " + MESSAGE.encode("hex"))
print("Message chiffré = " + message_chiffre.encode("hex")) 
print("Texte chiffré   = " + text_chiffre.encode("hex")) 

arp.wepdata = text_chiffre
arp.icv = icv_numerique

wrpcap(CAPFILE_CHIFFRE,arp)