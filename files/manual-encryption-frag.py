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
MESSAGE  = "Bonjour Patrick comment tu vas ? On va essayer avec un message un peu plus long pour en avoir pour 3 frag"
CAPFILE_CLAIR = "arp.cap"
CAPFILE_CHIFFRE_FRAG = "arp_chiffre_frag.cap"

TAILLE_MESSAGE_MAX = 36

#Cle wep AA:AA:AA:AA:AA
key = '\xaa\xaa\xaa\xaa\xaa'

# on calcul la taille du message et le nombre de fragment qu'il nous faut
long_mes = len(MESSAGE)
nb_frag = int(long_mes/TAILLE_MESSAGE_MAX)

# Si le message n'est pas un multiple de 36 on le pad ( il y a des problèmes si le message est plus grand que 36)
if((long_mes% TAILLE_MESSAGE_MAX) != 0):
    nb_pad = TAILLE_MESSAGE_MAX - long_mes % TAILLE_MESSAGE_MAX
    for i in range(nb_pad):
        MESSAGE += " "
    nb_frag += 1

# on cree un liste pour stocker nos fragments ( pour pouvoir les mettres dans wrpcap ensuite)
fragments = []

# on fait une boucle pour creer nos fragement avec leur numero et le fragment final
for i in range(nb_frag):

    message_a_chiffre = MESSAGE[(i*TAILLE_MESSAGE_MAX):((i+1)*TAILLE_MESSAGE_MAX)]
    chiffrement(message_a_chiffre)
    

def chiffrement(message):
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

    arp.wepdata = text_chiffre
    arp.icv = icv_numerique

'''
wrpcap(CAPFILE_CHIFFRE_FRAG,arp)
'''