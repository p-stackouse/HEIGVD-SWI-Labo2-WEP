#!/usr/bin/env python
# -*- coding: utf-8 -*-

""" Manually encrypt a wep message given the WEP key"""

__author__      = "Guillaume Blanco, Patrick Neto"
__version__ 	= "1.0"
__email__ 		= "guillaume.blanco@heig-vd.ch, patrick.neto@heig-vd.ch"

from scapy.all import *
import os
import rc4

#Cle wep AA:AA:AA:AA:AA
key = '\xaa\xaa\xaa\xaa\xaa'

# On recupere un message qui va nous servir de base
arp = rdpcap('arp.cap')[0]

# On extrait l iv du message et on le concatene avec notre cle pour creer notre seed (pour l algo RC4)
seed = arp.iv+key

# message que l on veut chiffrer
message = "Bonjour Patrick comment tu vas ?"

# calcul du crc sur le message
icv= crc32(message)

# on concatene le message et l icv pour avoir le message a chiffrer
message_a_chiffrer = message + str(icv)

# on chiffre le message avec rc4

message_chiffre = rc4.rc4crypt(message_a_chiffrer,seed)

# "le ICV est les derniers 4 octets - je le passe en format Long big endian"
icv_chiffre = message_chiffre[-4:]
(icv_numerique,) = struct.unpack('!L', icv_chiffre)

# le message chiffre sans le ICV
text_chiffre = message_chiffre[:-4]

arp.wepdata = text_chiffre
arp.icv = icv_numerique

wrpcap('arp_chiffre.cap',arp)

'''
IV = os.urandom(4)

print("IV = " + binascii.hexlify(IV))

seed = IV + KEY

#Création du paquet à chiffrer
packet = RadioTap(version=0, pad=0, len=18, 
                  present='Flags+Rate+Channel+dBm_AntSignal+Antenna+b14', 
                  notdecoded='\x00l\x9e\t\xc0\x00\xd7\x01\x00\x00')\
         /Dot11(subtype=0L, type='Data', proto=0L, FCfield='to-DS+wep', ID=10240, addr1='00:1d:7e:bd:9e:a0',
               addr2='90:27:e4:ea:61:f2', addr3='ff:ff:ff:ff:ff:ff', SC=22864, addr4=None)\
         /Dot11WEP(iv=IV, keyid=0, 
                   wepdata='SWI - Labo02 - WEP', 
                   icv=423423)
packet.show()
'''