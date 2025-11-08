# monitor_ports.sh

Script flexible para monitorizar tráfico de red y capturar paquetes por puerto, interfaz o reglas personalizadas. Incluye filtros de exclusión, guardado en ficheros `pcap` y logs legibles, gestión de procesos en segundo plano y utilidades para detectar actividad sospechosa.

## 🚀 Características principales
- Modos de captura: todo el tráfico (`all`), sólo puertos en escucha (`listening`) o lista personalizada (`custom`).
- Salidas simultáneas en `pcap` (para Wireshark/tcpdump) y `.log` legibles con `tcpdump` (opción `-t`).
- Gestión automática de procesos (`--status`, `--stop`) y seguimiento de PIDs en `/tmp/monitor_ports_pids.lst`.
- Filtros de exclusión por puerto y host/red (`--exclude-port`, `--exclude-host`).
- Compatibilidad con terminal interactiva única (`-T`) o procesos en background.
- Integración con herramientas estándar (`tcpdump`, `ss`, `tshark`, `grep`, `awk`) para análisis posterior.

## 🧩 Requisitos
- GNU/Linux (probado en Fedora Workstation 43).
- Paquetes:
  ```bash
  sudo dnf install -y tcpdump wireshark wireshark-cli nmap-ncat
  ```
  > `nmap-ncat` proporciona `nc`; `wireshark-cli` instala `tshark`.
- Permisos `sudo` para capturar tráfico en interfaces de red.

## 📦 Instalación y configuración
1. Clona o copia el repositorio:
   ```bash
   git clone <URL-del-repo> ~/Documentos/GitHub/monitor_ports.sh
   cd ~/Documentos/GitHub/monitor_ports.sh
   ```
2. Asegúrate de que el script es ejecutable:
   ```bash
   chmod +x monitor_ports.sh
   ```
3. (Opcional) Crea un directorio para almacenar capturas:
   ```bash
   mkdir -p ~/capturas
   ```
4. (Opcional) Añade capacidades a `dumpcap` para usar Wireshark/Tshark sin `sudo`:
   ```bash
   sudo usermod -aG wireshark $USER
   sudo chgrp wireshark /usr/sbin/dumpcap
   sudo chmod 750 /usr/sbin/dumpcap
   sudo setcap 'CAP_NET_RAW+eip CAP_NET_ADMIN+eip' /usr/sbin/dumpcap
   # Cierra sesión y vuelve a entrar para aplicar el grupo
   ```

## ⚙️ Uso básico
```bash
sudo ./monitor_ports.sh -m <modo> -i <interfaz> [opciones]
```
- `-m`: `all`, `listening` o `custom`.
- `-i`: interfaz de red (ej. `wlp3s0`, `eth0`).
- `-o`: directorio de salida (por defecto `./capturas`).
- Añade `-t` para generar también un `.log` legible.

### Ejemplos rápidos
```bash
# Capturar todo el tráfico y guardarlo en ~/capturas
sudo ./monitor_ports.sh -m all -i wlp3s0 -o ~/capturas -t

# Capturar sólo puertos en escucha excluyendo mDNS y WS-Discovery
sudo ./monitor_ports.sh -m listening -i wlp3s0 -o capturas -t \
  --exclude-port 5353,3702

# Monitorear puertos concretos en un único archivo pcap
sudo ./monitor_ports.sh -m custom -p 22,53,80,443 -i wlp3s0 \
  -o capturas -f -t --exclude-host 192.168.1.3
```

## 🛠️ Modos disponibles
| Modo       | Descripción | Notas |
|------------|-------------|-------|
| `all`      | Captura todo el tráfico de la interfaz. | Úsalo con exclusiones para reducir ruido. |
| `listening`| Descubre puertos en escucha vía `ss` y captura cada uno. | Puede generar muchos procesos si hay muchos puertos abiertos. |
| `custom`   | Captura únicamente los puertos especificados con `-p` (lista separada por comas). | Combínalo con `-f` para un único archivo. |

## 🔌 Opciones relevantes
| Opción | Función |
|--------|---------|
| `-o <dir>` | Directorio de salida para `pcap`/`log` (por defecto `./capturas`). |
| `-t` | Crea un proceso adicional con salida legible (`.log`). |
| `-T` | Abre una terminal gráfica única en lugar de procesos en segundo plano. |
| `-f` | Un único fichero `pcap` y `log` para todos los puertos del modo. |
| `--exclude-port 80,5353` | Excluye puertos concretos del filtro final. |
| `--exclude-host 192.168.1.3,10.0.0.0/24` | Excluye hosts/redes (CIDR). |
| `--status` | Muestra PIDs activos, tiempo y comando asociado. |
| `--stop` | Mata todos los procesos tcpdump registrados y borra el archivo de PIDs. |
| `-h` | Ayuda/usage. |

## 👁️ Gestión de capturas
```bash
# Ver capturas activas
sudo ./monitor_ports.sh --status

# Detener todo
sudo ./monitor_ports.sh --stop
```
- Los PIDs se guardan en `/tmp/monitor_ports_pids.lst`.
- Cada modo en background genera al menos un proceso `tcpdump`; con `-t` se generan dos (pcap + log).

## 🔍 Flujos de trabajo recomendados
1. **Radiografía inicial**
   ```bash
   sudo ./monitor_ports.sh -m all -i wlp3s0 -o ~/capturas -t --exclude-host 192.168.1.0/24
   tail -f ~/capturas/captura_all_*.log
   ```
2. **Monitorizar puertos en escucha sin ruido multicast**
   ```bash
   sudo ./monitor_ports.sh -m listening -i wlp3s0 -o capturas -t \
     --exclude-port 5353,3702,1900
   sudo ./monitor_ports.sh --status
   ```
3. **Aislar un host sospechoso**
   ```bash
   sudo ./monitor_ports.sh -m all -i wlp3s0 -o capturas -t \
     --exclude-host 192.168.1.0/24
   tshark -r capturas/captura_all_*.pcap -q -z conv,ip
   ```
4. **Captura ad hoc de un puerto**
   ```bash
   sudo ./monitor_ports.sh -m custom -p 56666 -i wlp3s0 -o capturas -t
   tail -f capturas/port_56666_*.log
   ```

## 🕵️ Guía para identificar tráfico sospechoso
### Revisar los `.log`
- Ver actividad en vivo: `tail -f capturas/*.log`.
- Top IPs externas:
  ```bash
  grep -h ' > ' capturas/*.log | awk '{print $5}' | sed 's/\.[0-9]*$//' \
    | grep -vE '^(192\.168\.|10\.|172\.1[6-9]\.|172\.2[0-9]\.|172\.3[0-1]\.)' \
    | sort | uniq -c | sort -nr | head
  ```
- Detección de solicitudes HTTP sospechosas: `grep -i 'POST' capturas/*.log`.

### Analizar `pcap` con `tshark`
- Conversaciones e IPs principales:
  ```bash
  tshark -r capturas/captura_all_*.pcap -q -z conv,ip
  tshark -r capturas/captura_all_*.pcap -q -z endpoints,ip
  ```
- Escaneos SYN (muchos puertos desde una IP):
  ```bash
  tshark -r capturas/captura_all_*.pcap -Y "tcp.flags.syn == 1 && tcp.flags.ack == 0" \
    -T fields -e ip.src -e tcp.dstport | sort | uniq -c | sort -nr | head
  ```
- DNS con posibles exfiltraciones:
  ```bash
  tshark -r capturas/captura_all_*.pcap -Y "dns.txt.length > 200" \
    -T fields -e frame.time -e ip.src -e dns.qry.name -e dns.txt
  ```
- ARP sospechoso (spoofing):
  ```bash
  tshark -r capturas/captura_all_*.pcap -Y "arp.opcode == 2" \
    -T fields -e arp.src.proto_ipv4 -e eth.src | sort | uniq -c | sort -nr
  ```

### Correlación y respuesta
1. Identifica el host (`ip neigh`, router/AP, MAC → fabricante).
2. Clasifica: ¿dispositivo conocido? ¿aplicación legítima?
3. Investiga IPs/dominios externos en fuentes como VirusTotal o AbuseIPDB.
4. Documenta hallazgos (timestamps, IP, puerto, resumen) y decide acciones: bloqueo de MAC, cambio de credenciales, análisis en endpoint, etc.

## 🧭 Buenas prácticas
- Ejecuta `sudo ./monitor_ports.sh --stop` antes de iniciar nuevas sesiones para evitar procesos huérfanos.
- Usa `--exclude-port`/`--exclude-host` para reducir ruido de broadcast/multicast (mDNS, SSDP, WS-Discovery, etc.).
- Mantén suficiente espacio en disco; los `pcap` pueden crecer rápido (modo `all`).
- Conserva una copia original de los `pcap` para auditorías posteriores.
- Automatiza informes con scripts que procesen los `.log` (ej. `awk`, `python`).

## 🛠️ Solución de problemas
| Síntoma | Posible causa | Solución |
|---------|---------------|----------|
| `command not found` | Ejecutas fuera del directorio del script. | Usa ruta absoluta o crea enlace simbólico. |
| `tcpdump: wlp3s0: You don't have permission to capture` | Falta `sudo` o capacidades. | Ejecuta con `sudo` o aplica capacidades a `dumpcap`. |
| No aparecen `pcap`/`log` | Directorio no existe o sin permisos. | Verifica con `ls -ld <dir>` y usa `mkdir -p`. |
| `--stop` no detiene nada | No hay archivo de PIDs (no se lanzó captura en background). | Comprueba `/tmp/monitor_ports_pids.lst` y la salida de `--status`. |
| Ruido constante de mDNS/WS-Discovery | Servicios broadcast en la LAN. | Excluye puertos 5353, 3702, 1900. |

## 📄 Licencia
Define aquí la licencia del proyecto (MIT, GPL, etc.). Si aún no la has elegido, añade un archivo `LICENSE` con la licencia deseada.

---
¿Ideas para futuras mejoras? Ejemplos: `--summary` para informes automáticos, rotación de ficheros por tamaño/tiempo, modo "focus" para una IP, integración con `fail2ban`. ¡Contribuciones bienvenidas!
