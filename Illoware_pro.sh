#!/usr/bin/env bash
# Illoware_pro.sh - Herramienta unificada de reconocimiento y auditoría mejorada
# Incluye subdominios avanzados, DNS, puertos, HTTP fingerprinting,
# fuzzing de directorios, Nikto, GF patterns, DNSrecon, detección de redirecciones y reporte.
# Capturas de pantalla opcionales.
# Uso: ./Illoware_pro.sh [-S] [-q] -d dominio.com | -i lista_dominios.txt

set -euo pipefail
trap 'error_handler ${LINENO}' ERR
IFS=$'\n\t'

# ---------------------------
# Configuración de entorno Go
export GOPATH="$HOME/go"
export PATH="/usr/local/go/bin:$HOME/go/bin:$PATH"

# ---------------------------
# Configuración general
OUTPUT_BASE="./resultados"
RESOLVERS_FILE="./tools/resolvers.txt"
DEFAULT_RESOLVERS=("8.8.8.8" "1.1.1.1" "9.9.9.9")
GO_PKGS=(
  github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
  github.com/owasp-amass/amass/v4/...@master
  github.com/projectdiscovery/dnsx/cmd/dnsx@latest
  github.com/projectdiscovery/httpx/cmd/httpx@latest
  github.com/sensepost/gowitness@latest
  github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
  github.com/ffuf/ffuf/v2@latest
  github.com/lc/gau/v2/cmd/gau@latest
  github.com/tomnomnom/waybackurls@latest
  github.com/projectdiscovery/dnsgen/cmd/dnsgen@latest
)
APT_PKG=(curl git jq wget figlet dnsutils whois nmap python3 python3-pip gobuster dnsrecon nikto whatweb)
NPM_PKG=(markmap-cli)

# Flags
SKIP_SCREENS=0
QUIET=0

# ---------------------------
# Manejo de errores
error_handler() {
  local exit_code=$?
  local line_no=$1
  echo -e "\n[❌] Error en la línea $line_no. Código de salida: $exit_code" >&2
  exit $exit_code
}

# ---------------------------
# Logging silenciado
log() { [ "$QUIET" -eq 0 ] && echo "$@"; }

# ---------------------------
# Carga de resolvers
load_resolvers() {
  if [[ -s "$RESOLVERS_FILE" ]]; then
    RESOLVERS_SOURCE="$RESOLVERS_FILE"
  else
    log "[WARN] No se encontró resolvers; usando fallback"
    RESOLVERS_SOURCE="/tmp/default_resolvers.txt"
    printf "%s\n" "${DEFAULT_RESOLVERS[@]}" > "$RESOLVERS_SOURCE"
  fi
}

# ---------------------------
# Instalación de dependencias
dependencies_install() {
  log "[+] Actualizando APT y preparando repositorios..."
  sudo apt-get update -y -qq
  sudo apt-get install -y -qq software-properties-common
  log "[+] Instalando paquetes APT..."
  sudo apt-get install -y -qq "${APT_PKG[@]}"
  log "[+] Instalando Go 1.24.3..."
  sudo rm -rf /usr/local/go
  wget -q https://go.dev/dl/go1.24.3.linux-amd64.tar.gz -O /tmp/go.tar.gz
  sudo tar -C /usr/local -xzf /tmp/go.tar.gz
  mkdir -p "$GOPATH/bin"

  # Forzar uso de Go proxy y evitar fallback directo a git
  export GOPROXY=https://proxy.golang.org
  export GOSUMDB=sum.golang.org

  log "[+] Instalando herramientas Go..."
  for pkg in "${GO_PKGS[@]}"; do
    log "  -> $pkg"
    GO111MODULE=on go install "$pkg" || log "[!] Fallo al instalar: $pkg"
  done
  if command -v npm &>/dev/null; then
    log "[+] Instalando herramientas NPM..."
    npm install -g "${NPM_PKG[@]}" >/dev/null
  fi
  load_resolvers
}

# ---------------------------
# Mostrar banner
display_banner() {
  if command -v figlet &>/dev/null; then
    figlet -f slant ILLOWARE_PRO
  fi
}

# ---------------------------
# Parseo de argumentos
parse_args() {
  while getopts ":d:i:qS" opt; do
    case "$opt" in
      d) DOMAIN="$OPTARG" ;;  
      i) INPUT_FILE="$OPTARG" ;;  
      q) QUIET=1 ;;  
      S) SKIP_SCREENS=1 ;;  
      *) echo "Uso: \$0 [-q] [-S] -d dominio.com | -i lista.txt" && exit 1 ;;  
    esac
  done
  if [[ -z "${DOMAIN:-}" && -z "${INPUT_FILE:-}" ]]; then
    echo "Falta -d dominio o -i lista.txt" && exit 1
  fi
}

# ---------------------------
# Preparar directorios
prepare_dirs() {
  local domain="$1"
  BASE="$OUTPUT_BASE/$domain/$(date +%Y%m%d_%H%M%S)"
  mkdir -p "$BASE/raw" "$BASE/clean" "$BASE/screenshots"
}

# ---------------------------
# Verificar protección Cloudflare
check_cloudflare() {
  local ip=$(dig +short "$1" | grep -Eo '([0-9]{1,3}\.){3}[0-9]{1,3}' | head -n1)
  CF_RANGES=("104.16.0.0/12" "172.64.0.0/13" "131.0.72.0/22")
  for r in "${CF_RANGES[@]}"; do
    if ipcalc -nb "$ip" "$r" 2>/dev/null | grep -q NETWORK; then
      echo "$1 redirige a IP $ip (Cloudflare)" > "$BASE/raw/cloudflare.txt"
      return 0
    fi
  done
  return 1
}

# ---------------------------
# Fases de reconocimiento
collect_dns() {
  log "[DNS] Recolección registros..."
  types=(A MX TXT NS SRV AAAA CNAME SOA)
  for t in "${types[@]}"; do
    dig +short "$t" "$DOMAIN" | tee "$BASE/raw/$t"
  done
  dig +short TXT "_dmarc.$DOMAIN" | tee "$BASE/raw/DMARC"
  log "[DNSRECON] Brute-force..."
  dnsrecon -d "$DOMAIN" -t brt -o "$BASE/raw/dnsrecon.txt"
}

run_whois() {
  log "[WHOIS] Ejecutando..."
  whois "$DOMAIN" > "$BASE/raw/whois"
  awk '/inetnum/ {print \\$2"->"\\$3}' "$BASE/raw/whois" | sort -u > "$BASE/clean/rangos"
}

run_nmap() {
  log "[NMAP] Escaneando TCP..."
  nmap -T4 -sS -Pn -sV -sC -O -oA "$BASE/raw/nmap" "$DOMAIN"
  log "[NMAP] Escaneando UDP comunes..."
  udp_ports="53,67,68,69,123,137,138,161,162,500,514,631"
  nmap -sU -Pn -p "$udp_ports" -T4 -oA "$BASE/raw/nmap_udp" "$DOMAIN" || true
}

gather_subdomains() {
  log "[SUB] Subfinder + Amass + DNSGen..."
  subfinder -d "$DOMAIN" -silent >> "$BASE/raw/subs.txt"
  amass enum -passive -d "$DOMAIN" -silent >> "$BASE/raw/subs.txt"
  sort -u "$BASE/raw/subs.txt" | grep "\\.$DOMAIN\$" > "$BASE/clean/subs_base.txt"

  dnsgen "$BASE/clean/subs_base.txt" -o "$BASE/raw/subs_dnsgen.txt"
  grep "\\.$DOMAIN\$" "$BASE/raw/subs_dnsgen.txt" | sort -u > "$BASE/clean/subs_gen.txt"

  cat "$BASE/clean/subs_base.txt" "$BASE/clean/subs_gen.txt" | sort -u > "$BASE/clean/subs_all.txt"
}

resolve_and_filter() {
  log "[RES] dnsx + httpx..."
  dnsx -l "$BASE/clean/subs_all.txt" -silent -r "$RESOLVERS_SOURCE" > "$BASE/raw/resolved.txt"
  httpx -l "$BASE/raw/resolved.txt" -silent -status-code -title -ip -cname -r "$RESOLVERS_SOURCE" > "$BASE/clean/live.txt"
}

detect_technologies() {
  log "[TECH] WhatWeb + Nuclei..."
  whatweb -v $(< "$BASE/clean/live.txt") > "$BASE/raw/whatweb.txt"
  nuclei -l "$BASE/clean/live.txt" -t technologies/tech-detect.yaml -silent > "$BASE/clean/tech.txt"
}

capture_screenshots() {
  if [[ "$SKIP_SCREENS" -eq 0 ]]; then
    log "[SHOT] Gowitness..."
    gowitness file -f "$BASE/clean/live.txt" --destination "$BASE/screenshots" >/dev/null
  else
    log "[SHOT] Omitido (-S)"
  fi
}

discover_endpoints() {
  log "[ENDP] Waybackurls + gau..."
  waybackurls -no-scope-bypass -silent "$DOMAIN" | sort -u > "$BASE/raw/wayback.txt"
  gau "$DOMAIN" | sort -u > "$BASE/raw/gau.txt"
  cat "$BASE/raw/wayback.txt" "$BASE/raw/gau.txt" > "$BASE/raw/all_urls.txt"

  log "[FUZZ] Gobuster..."
  for url in $(cat "$BASE/raw/all_urls.txt"); do
    [[ "$url" =~ ^https?:// ]] && host=$(echo "$url" | awk -F/ '{print \\$3}') || continue
    gobuster dir -u "$url" -w /usr/share/wordlists/directory-list-2.3-medium.txt -q -o "$BASE/raw/gobuster_${host}.txt" &
  done
  wait
}

check_headers() {
  log "[HEAD] httpx headers..."
  httpx -l "$BASE/clean/live.txt" -silent -headers -r "$RESOLVERS_SOURCE" > "$BASE/clean/headers.txt"
}

detect_vulns() {
  log "[VULN] Nuclei CVEs + misconfigs..."
  nuclei -l "$BASE/clean/live.txt" -t cves/ -t security-misconfiguration/ -silent > "$BASE/clean/nuclei.txt"
  log "[NIKTO] Escaneo web..."
  nikto -host "$DOMAIN" -output "$BASE/raw/nikto.txt"
}

gf_patterns() {
  log "[GF] Patrones GF..."
  for p in xss sqli redirect; do
    gf "$p" "$BASE/raw/all_urls.txt" > "$BASE/clean/gf_${p}.txt" || true
  done
}

reverse_dns_lookup() {
  log "[NSLOOKUP] Reverse DNS..."
  awk '{print \\$4}' "$BASE/clean/live.txt" | sort -u | while read -r ip; do
    echo "\n[+] $ip" >> "$BASE/raw/reverse_dns.txt"
    nslookup "$ip" >> "$BASE/raw/reverse_dns.txt" 2>/dev/null
  done
}

generate_report() {
  local md="$BASE/report.md"
  log "[REP] Generando Markdown..."
  {
    echo "# Reporte Illoware_pro - $DOMAIN"
    echo "## DNS"; for f in A MX TXT NS SRV AAAA CNAME SOA DMARC dnsrecon; do echo "### $f"; cat "$BASE/raw/$f" 2>/dev/null; done
    echo "## Subdominios vivos"; cat "$BASE/clean/live.txt"
    echo "## Tecnologías"; cat "$BASE/raw/whatweb.txt"; cat "$BASE/clean/tech.txt"
    echo "## Vulnerabilidades automáticas"; cat "$BASE/clean/nuclei.txt"; echo "Nikto:"; cat "$BASE/raw/nikto.txt"
    echo "## Endpoints (muestra)"; head -n 20 "$BASE/raw/all_urls.txt"
    echo "## Gobuster resultados"; find "$BASE/raw" -name 'gobuster_*.txt' | sort | head -n 10 | while read f; do echo "### $(basename $f)"; head -n 10 "$f"; done
    echo "## Patrones GF"; for p in xss sqli redirect; do echo "### $p"; cat "$BASE/clean/gf_${p}.txt"; done
    echo "## Cabeceras"; head -n 20 "$BASE/clean/headers.txt"
    echo "## Screenshots"; [[ "$SKIP_SCREENS" -eq 1 ]] && echo "(omitido)" || echo "en $BASE/screenshots"
    echo "## Nmap TCP"; ls "$
BASE/raw/nmap.*" 2>/dev/null
    echo "## Nmap UDP"; ls "$BASE/raw/nmap_udp.*" 2>/dev/null
    echo "## Cloudflare"; cat "$BASE/raw/cloudflare.txt" 2>/dev/null || echo "No protegido"
    echo "## Reverse DNS"; cat "$BASE/raw/reverse_dns.txt" 2>/dev/null || echo "Ninguno"
  } > "$md"
  log "[✔] Reporte: $md"
}

# ---------------------------
# Flujo principal
main() {
  parse_args "$@"
  dependencies_install
  display_banner
  load_resolvers

  mapfile -t domains < <([[ -n "${DOMAIN:-}" ]] && printf "%s" "$DOMAIN" || cat "$INPUT_FILE")
  for DOMAIN in "${domains[@]}"; do
    log "\n=== Procesando: $DOMAIN ==="
    prepare_dirs "$DOMAIN"
    collect_dns
    run_whois
    if check_cloudflare "$DOMAIN"; then
      log "[⚠️] $DOMAIN protegido por Cloudflare. Solo pasivo."
      gather_subdomains; resolve_and_filter; capture_screenshots; check_headers; generate_report
      continue
    fi
    run_nmap
    gather_subdomains
    resolve_and_filter
    detect_technologies
    capture_screenshots
    discover_endpoints
    check_headers
    detect_vulns
    gf_patterns
    reverse_dns_lookup
    generate_report
  done
}

main "$@"
