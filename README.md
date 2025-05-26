# Illoware_pro

**Illoware_pro** es una herramienta completa de reconocimiento y auditoría enfocada en bug bounty. Combina técnicas pasivas y activas para recolectar información de DNS, subdominios, puertos, fingerprinting, fuzzing, vulnerabilidades automáticas y generación de reportes.

---

## Tabla de contenidos

* [Requisitos](#requisitos)
* [Instalación](#instalaci%C3%B3n)
* [Uso](#uso)
* [Flags](#flags)
* [Flujo de trabajo](#flujo-de-trabajo)
* [Salida y reportes](#salida-y-reportes)

---

## Requisitos

* **Sistema operativo**: Ubuntu 22.04 (o derivadas Debian)
* **Permisos**: `sudo` para instalar dependencias
* **Dependencias**:

  * APT: `curl`, `git`, `jq`, `wget`, `figlet`, `dnsutils`, `whois`, `nmap`, `python3`, `python3-pip`, `gobuster`, `dnsrecon`, `nikto`, `whatweb`
  * **Go 1.24.3** instalado en `/usr/local/go`
  * **Node.js** (opcional, para NPM: `markmap-cli`)

Todo lo anterior se instala automáticamente con el script.

---

## Instalación

1. **Clona el repositorio** (o descarga `Illoware_pro.sh` directamente):

   ```bash
   git clone https://github.com/Xelofrost/illoware_pro.git
   cd illoware_pro
   ```

2. **Otorga permisos de ejecución**:

   ```bash
   chmod +x Illoware_pro.sh
   ```

3. **Ejecuta el script para instalar dependencias**:

   ```bash
   ./Illoware_pro.sh -d ejemplo.com
   ```

   * Durante la primera ejecución, el script instalará paquetes APT, Go, herramientas Go y NPM.

---

## Uso

```bash
./Illoware_pro.sh [FLAGS] [-d dominio.com | -i lista.txt]
```

* `-d dominio.com`: escanea un solo dominio.
* `-i lista.txt`: escanea varios dominios listados en un archivo (uno por línea).

### Ejemplos

* Escaneo de un dominio:

  ```bash
  ./Illoware_pro.sh -d example.com
  ```

* Escaneo en silencio (solo logs críticos):

  ```bash
  ./Illoware_pro.sh -q -d example.com
  ```

* Escaneo sin capturas de pantalla:

  ```bash
  ./Illoware_pro.sh -S -d example.com
  ```

---

## Flags

* `-d <dominio>`: Dominio objetivo.
* `-i <archivo>`: Archivo con lista de dominios.
* `-q`: Modo silencioso (solo errores y resultados principales).
* `-S`: Omite capturas de pantalla.

---

## Flujo de trabajo

1. **Instalación de dependencias**: APT, Go, herramientas Go, NPM.
2. **Banner**: Muestra `ILLOWARE_PRO` con `figlet`.
3. **Carga de resolvers**: Usa lista externa o fallback.
4. **Fases de reconocimiento**:

   * DNS pasivo y brute-force (`dig`, `dnsrecon`).
   * WHOIS y rangos IP.
   * Detección de protección Cloudflare.
   * Escaneo Nmap TCP/UDP.
   * Subdominios (Subfinder, Amass, DNSGen).
   * Resolución y filtrado (`dnsx`, `httpx`).
   * Fingerprinting de tecnologías (`WhatWeb`, `Nuclei`).
   * Capturas de pantalla opcionales (`Gowitness`).
   * Descubrimiento de endpoints y fuzzing (`Waybackurls`, `gau`, `Gobuster`).
   * Cabeceras HTTP (`httpx`).
   * Vulnerabilidades automáticas (`Nuclei CVEs`, `Nikto`).
   * Patrones GF.
   * Reverse DNS lookup.
5. **Generación de reporte** en Markdown con resultados consolidados.

---

## Salida y reportes

* Cada dominio genera un directorio en `./resultados/<dominio>/<timestamp>/` con subcarpetas:

  * **raw**: Salidas originales de herramientas.
  * **clean**: Resultados filtrados y consolidados.
  * **screenshots**: Imágenes de sitios (opcional).
* Reporte en Markdown: `report.md` con secciones de DNS, subdominios, tecnologías, vulnerabilidades, endpoints, patrones GF, cabeceras, capturas, Nmap TCP/UDP, Cloudflare y reverse DNS.