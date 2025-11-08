#!/bin/bash
# Script avanzado para monitorizar puertos y tráfico de red.
# Permite:
#  - Capturar TODO el tráfico (sin filtro de puertos)
#  - Capturar sólo puertos en escucha actualmente
#  - Capturar una lista personalizada de puertos
#  - Guardar salidas en ficheros pcap y/o texto
#  - Lanzar procesos en background y detenerlos fácilmente
#  - Abrir una sola terminal (opcional) o múltiples (desaconsejado para muchos puertos)
#
# Requisitos: tcpdump, ss, awk. Suele requerir permisos de root (sudo).
# Uso básico:
#   sudo ./monitor_ports.sh -m all -i eth0 -o capturas
#   sudo ./monitor_ports.sh -m listening -i wlp3s0
#   sudo ./monitor_ports.sh -m custom -p 22,80,443 -i wlp3s0 -o capturas
#   sudo ./monitor_ports.sh --stop   # Detener procesos previamente lanzados
#
# Variables de control
VERSION="1.0.0"
PID_FILE="/tmp/monitor_ports_pids.lst"
DEFAULT_OUTPUT_DIR="./capturas"

color() { # $1=code $2=text
    local c="$1"; shift
    echo -e "\e[${c}m$*\e[0m"
}

usage() {
    cat <<EOF
Script: monitor_ports.sh v$VERSION
Monitorización flexible de tráfico de red.

Opciones:
  -m <modo>        Modo: all | listening | custom
  -i <interfaz>    Interfaz de red (obligatoria en modos de captura)
  -p <lista>       Lista de puertos (para modo custom) ej: 22,80,443
  -o <dir>         Directorio de salida (por defecto $DEFAULT_OUTPUT_DIR)
  -t               También generar salida legible (tcpdump -n -vv) además de pcap
  -T               Abrir una terminal interactiva única en vez de procesos background
  -f               Un solo fichero pcap para todo (all o listening) en vez de por puerto
    --exclude-port <lista>  Excluir puertos (coma separados) del filtro final
    --exclude-host <lista>  Excluir hosts (IPs, coma separados) o redes CIDR
    --status         Mostrar estado de capturas activas (si existen) y salir
  --stop           Detener todas las capturas previamente lanzadas
  -h               Mostrar ayuda

Ejemplos:
  sudo $0 -m all -i eth0 -o capturas
  sudo $0 -m listening -i wlp3s0 -t
  sudo $0 -m custom -p 53,80,443 -i wlp3s0 -o capturas
  sudo $0 --stop

Notas:
  - Modo 'all' captura todo el tráfico (puede generar volúmenes grandes).
  - Modo 'listening' detecta puertos con servicios activos usando 'ss'.
  - Usa --stop para finalizar procesos anteriores (guarda sus PIDs en $PID_FILE).
EOF
}

# Mostrar estado de capturas activas basándose en el archivo de PIDs
status_show() {
    if [[ ! -f "$PID_FILE" ]]; then
        echo "No hay capturas activas (sin $PID_FILE)"; exit 0
    fi
    echo "Estado de capturas (PID, Tiempo, Comando):"
    while read -r pid; do
        [[ -z "$pid" ]] && continue
        if [[ -d "/proc/$pid" ]]; then
            ps -p "$pid" -o pid,etime,cmd --no-headers
        else
            echo "$pid (finalizado)"
        fi
    done < "$PID_FILE"
    exit 0
}

require_cmd() { # Verificar dependencias
    for c in "$@"; do
        command -v "$c" &>/dev/null || { echo "Falta comando requerido: $c" >&2; exit 1; }
    done
}

stop_all() {
    if [[ -f "$PID_FILE" ]]; then
        echo "Deteniendo procesos..."
        while read -r pid; do
            if [[ -n "$pid" && -d "/proc/$pid" ]]; then
                kill "$pid" 2>/dev/null && echo "  PID $pid detenido" || echo "  PID $pid ya no existe"
            fi
        done <"$PID_FILE"
        rm -f "$PID_FILE"
        echo "Procesos finalizados."
    else
        echo "No hay PID file ($PID_FILE). Nada que detener."
    fi
    exit 0
}

discover_listening_ports() {
    # Devuelve una lista única de puertos en escucha (tcp y udp)
    ss -tuln | awk 'NR>1 {print $5}' | awk -F':' '{p=$NF; if(p ~ /^[0-9]+$/) print p}' | sort -n | uniq
}

build_tcpdump_filter_for_ports() { # $@ = puertos
    local ports=("$@")
    local expr=""
    for p in "${ports[@]}"; do
        if [[ -n "$expr" ]]; then
            expr+=" or "
        fi
        expr+="port $p"
    done
    echo "$expr"
}

start_capture_background() { # $1=interface $2=filter $3=pcap_file $4=text_file(optional)
    local iface="$1"; shift
    local filter="$1"; shift
    local pcap="$1"; shift
    local text_out="$1"
    # Proceso 1: pcap (binario)
    tcpdump -i "$iface" -n -U $filter -w "$pcap" &
    local pid_pcap=$!
    echo "$pid_pcap" >> "$PID_FILE"
    echo "PCAP activo (PID $pid_pcap) -> $pcap"
    # Proceso 2 opcional: salida legible
    if [[ -n "$text_out" ]]; then
        tcpdump -i "$iface" -n -vv -l $filter >> "$text_out" 2>&1 &
        local pid_text=$!
        echo "$pid_text" >> "$PID_FILE"
        echo "Log legible activo (PID $pid_text) -> $text_out"
    fi
}

start_capture_terminal() { # Interactiva en una terminal nueva
    local iface="$1"; shift
    local filter="$1"; shift
    local cmd="sudo tcpdump -i $iface -n -vv $filter"
    if command -v gnome-terminal &>/dev/null; then
        gnome-terminal -- bash -c "$cmd; exec bash"
    elif command -v konsole &>/dev/null; then
        konsole --noclose -e bash -c "$cmd; exec bash"
    else
        echo "No se encontró terminal gráfica compatible. Ejecutando en la actual." >&2
        eval "$cmd"
    fi
}

# Parseo de argumentos
MODE=""
INTERFACE=""
CUSTOM_PORTS=""
OUTPUT_DIR="$DEFAULT_OUTPUT_DIR"
TEXT_OUTPUT=false
SINGLE_TERMINAL=false
SINGLE_FILE=false
EXCLUDE_PORTS=""
EXCLUDE_HOSTS=""
STATUS=false

while [[ $# -gt 0 ]]; do
    case "$1" in
        -m) MODE="$2"; shift 2;;
        -i) INTERFACE="$2"; shift 2;;
        -p) CUSTOM_PORTS="$2"; shift 2;;
        -o) OUTPUT_DIR="$2"; shift 2;;
        -t) TEXT_OUTPUT=true; shift;;
        -T) SINGLE_TERMINAL=true; shift;;
        -f) SINGLE_FILE=true; shift;;
        --exclude-port) EXCLUDE_PORTS="$2"; shift 2;;
        --exclude-host) EXCLUDE_HOSTS="$2"; shift 2;;
        --status) STATUS=true; shift;;
        --stop) stop_all;;
        -h|--help) usage; exit 0;;
        *) echo "Argumento desconocido: $1"; usage; exit 1;;
    esac
done

# Acciones que no requieren parámetros de captura
if $STATUS; then
    status_show
fi

# Validaciones sólo para modos de captura
[[ -z "$MODE" ]] && { echo "Falta -m <modo>" >&2; usage; exit 1; }
[[ -z "$INTERFACE" ]] && { echo "Falta -i <interfaz>" >&2; usage; exit 1; }

require_cmd tcpdump ss awk sort uniq

mkdir -p "$OUTPUT_DIR" || { echo "No se pudo crear directorio $OUTPUT_DIR" >&2; exit 1; }

echo "$(color 36 "Modo:") $MODE"; echo "$(color 36 "Interfaz:") $INTERFACE"; echo "$(color 36 "Dir salida:") $OUTPUT_DIR"

# Aplicar exclusiones si existen (se ejecutan después de construir FILTER inicial)
apply_exclusions() {
    local current_filter="$1"
    local exclude_ports_expr=""
    local exclude_hosts_expr=""
    if [[ -n "$EXCLUDE_PORTS" ]]; then
        IFS=',' read -r -a EX_P_ARR <<< "$EXCLUDE_PORTS"
        for ep in "${EX_P_ARR[@]}"; do
            [[ "$ep" =~ ^[0-9]+$ ]] || { echo "Puerto a excluir inválido: $ep" >&2; exit 1; }
            if [[ -n "$exclude_ports_expr" ]]; then exclude_ports_expr+=" or "; fi
            exclude_ports_expr+="port $ep"
        done
        if [[ -n "$exclude_ports_expr" ]]; then
            if [[ -n "$current_filter" ]]; then
                current_filter="($current_filter) and not ($exclude_ports_expr)"
            else
                current_filter="not ($exclude_ports_expr)"
            fi
        fi
    fi
    if [[ -n "$EXCLUDE_HOSTS" ]]; then
        IFS=',' read -r -a EX_H_ARR <<< "$EXCLUDE_HOSTS"
        for eh in "${EX_H_ARR[@]}"; do
            local term=""
            if [[ "$eh" =~ \/ ]]; then
                # CIDR
                term="net $eh"
            else
                term="host $eh"
            fi
            if [[ -n "$exclude_hosts_expr" ]]; then exclude_hosts_expr+=" or "; fi
            exclude_hosts_expr+="$term"
        done
        if [[ -n "$exclude_hosts_expr" ]]; then
            if [[ -n "$current_filter" ]]; then
                current_filter="($current_filter) and not ($exclude_hosts_expr)"
            else
                current_filter="not ($exclude_hosts_expr)"
            fi
        fi
    fi
    echo "$current_filter"
}

# Helper: comprobar si un puerto está en la lista de exclusión
is_port_excluded() {
    local p_check="$1"
    [[ -z "$EXCLUDE_PORTS" ]] && return 1
    IFS=',' read -r -a EX_P_ARR <<< "$EXCLUDE_PORTS"
    for ep in "${EX_P_ARR[@]}"; do
        [[ "$ep" == "$p_check" ]] && return 0
    done
    return 1
}

if [[ "$MODE" == "all" ]]; then
    FILTER=""
    # Sin filtro captura todo. Para tcpdump, cadena vacía -> todos los paquetes.
    if $SINGLE_TERMINAL; then
        FILTER="$(apply_exclusions "$FILTER")"
        start_capture_terminal "$INTERFACE" "$FILTER"
        exit 0
    fi
    PCAP_FILE="$OUTPUT_DIR/captura_all_$(date +%Y%m%d_%H%M%S).pcap"
    TEXT_FILE=""
    $TEXT_OUTPUT && TEXT_FILE="$OUTPUT_DIR/captura_all_$(date +%Y%m%d_%H%M%S).log"
    FILTER="$(apply_exclusions "$FILTER")"
    start_capture_background "$INTERFACE" "$FILTER" "$PCAP_FILE" "$TEXT_FILE"
    echo "Usa --stop para finalizar. PID(s) en $PID_FILE"
    exit 0
elif [[ "$MODE" == "listening" ]]; then
    mapfile -t PORTS < <(discover_listening_ports)
    if [[ ${#PORTS[@]} -eq 0 ]]; then
        echo "No se encontraron puertos en escucha."; exit 0
    fi
    echo "Puertos detectados: ${PORTS[*]}"
    if $SINGLE_FILE; then
        FILTER="$(build_tcpdump_filter_for_ports "${PORTS[@]}")"
        PCAP_FILE="$OUTPUT_DIR/captura_listening_$(date +%Y%m%d_%H%M%S).pcap"
        TEXT_FILE=""
        $TEXT_OUTPUT && TEXT_FILE="$OUTPUT_DIR/captura_listening_$(date +%Y%m%d_%H%M%S).log"
        if $SINGLE_TERMINAL; then
            FILTER="$(apply_exclusions "$FILTER")"
            start_capture_terminal "$INTERFACE" "$FILTER"
            exit 0
        fi
        FILTER="$(apply_exclusions "$FILTER")"
        start_capture_background "$INTERFACE" "$FILTER" "$PCAP_FILE" "$TEXT_FILE"
    else
        for p in "${PORTS[@]}"; do
            if is_port_excluded "$p"; then
                echo "Omitiendo puerto excluido: $p"
                continue
            fi
            FILTER="port $p"
            FILTER="$(apply_exclusions "$FILTER")"
            PCAP_FILE="$OUTPUT_DIR/port_${p}_$(date +%Y%m%d_%H%M%S).pcap"
            TEXT_FILE=""
            $TEXT_OUTPUT && TEXT_FILE="$OUTPUT_DIR/port_${p}_$(date +%Y%m%d_%H%M%S).log"
            start_capture_background "$INTERFACE" "$FILTER" "$PCAP_FILE" "$TEXT_FILE"
        done
    fi
    echo "Capturas lanzadas. Usa --stop para detener."; exit 0
elif [[ "$MODE" == "custom" ]]; then
    [[ -z "$CUSTOM_PORTS" ]] && { echo "Modo custom requiere -p <lista>" >&2; exit 1; }
    IFS=',' read -r -a PORTS <<< "$CUSTOM_PORTS"
    # Validar números
    for p in "${PORTS[@]}"; do
        [[ "$p" =~ ^[0-9]+$ ]] || { echo "Puerto inválido: $p" >&2; exit 1; }
    done
    if $SINGLE_FILE; then
        FILTER="$(build_tcpdump_filter_for_ports "${PORTS[@]}")"
        PCAP_FILE="$OUTPUT_DIR/custom_$(date +%Y%m%d_%H%M%S).pcap"
        TEXT_FILE=""
        $TEXT_OUTPUT && TEXT_FILE="$OUTPUT_DIR/custom_$(date +%Y%m%d_%H%M%S).log"
        if $SINGLE_TERMINAL; then
            FILTER="$(apply_exclusions "$FILTER")"
            start_capture_terminal "$INTERFACE" "$FILTER"
            exit 0
        fi
        FILTER="$(apply_exclusions "$FILTER")"
        start_capture_background "$INTERFACE" "$FILTER" "$PCAP_FILE" "$TEXT_FILE"
    else
        for p in "${PORTS[@]}"; do
            if is_port_excluded "$p"; then
                echo "Omitiendo puerto excluido: $p"
                continue
            fi
            FILTER="port $p"
            FILTER="$(apply_exclusions "$FILTER")"
            PCAP_FILE="$OUTPUT_DIR/port_${p}_$(date +%Y%m%d_%H%M%S).pcap"
            TEXT_FILE=""
            $TEXT_OUTPUT && TEXT_FILE="$OUTPUT_DIR/port_${p}_$(date +%Y%m%d_%H%M%S).log"
            start_capture_background "$INTERFACE" "$FILTER" "$PCAP_FILE" "$TEXT_FILE"
        done
    fi
    echo "Capturas lanzadas. Usa --stop para detener."; exit 0
else
    echo "Modo desconocido: $MODE" >&2; usage; exit 1
fi

# Recalcular filtros con exclusión antes de lanzar capturas (si no estamos ya en terminal interactiva salida)

# NOTE: Para modo 'all' con exclusiones el filtro final puede ser 'not (...)' evitando capturar esos puertos/hosts.


exit 0