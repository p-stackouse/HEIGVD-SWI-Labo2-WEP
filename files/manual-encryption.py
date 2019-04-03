#!/usr/bin/env python
# -*- coding: utf-8 -*-

""" Manually decrypt a wep message given the WEP key"""

__author__      = "Guillaume Blanco, Patrick Neto"
__version__ 	= "1.0"
__email__ 		= "guillaume.blanco@heig-vd.ch, patrick.neto@heig-vd.ch"

from scapy.all import *
import binascii
import os
import rc4

#Cle wep AA:AA:AA:AA:AA
KEY = '\xaa\xaa\xaa\xaa\xaa'
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