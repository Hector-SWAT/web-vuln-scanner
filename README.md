# Web Vulnerability Scanner 🔍🛡️

[![Python](https://img.shields.io/badge/python-3.7%2B-blue.svg)](https://python.org)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![Security](https://img.shields.io/badge/security-pentesting-red.svg)](https://github.com/Hector-SWAT)

<div align="center">
  <img src="https://i.imgur.com/TU_IMAGEN_SCANNER.png" alt="Web Vulnerability Scanner Interface" width="800">
  <p><i>Escáner avanzado de vulnerabilidades web para pruebas de penetración</i></p>
</div>

Una herramienta avanzada de pentesting diseñada para identificar vulnerabilidades de seguridad en aplicaciones web. Detecta XSS, SQL Injection, archivos sensibles, directorios expuestos y más.

## ⚠️ **DESCARGO DE RESPONSABILIDAD**

**Esta herramienta está diseñada exclusivamente para fines educativos y pruebas de seguridad autorizadas. El uso no autorizado en sistemas ajenos es ilegal y está prohibido. El autor no se hace responsable del mal uso de esta herramienta.**

## ✨ Características principales

- 🎯 **Detección de vulnerabilidades múltiples**:
  - Cross-Site Scripting (XSS)
  - SQL Injection (SQLi)
  - Local File Inclusion (LFI)
  - Remote Code Execution (RCE)
  
- 🕷️ **Web Crawler integrado** para descubrimiento automático de URLs y formularios
- 📁 **Escaneo de directorios** y archivos sensibles
- 🧵 **Multithreading** para escaneos rápidos y eficientes
- 📊 **Reportes en múltiples formatos**: HTML, JSON, Markdown
- 🔄 **Rotación de User-Agents** para evadir detección
- 📝 **Logging detallado** con diferentes niveles
- ⚙️ **Configuración avanzada** y personalizable

## 🛠️ Vulnerabilidades detectadas

| Tipo | Descripción | Payloads | Estado |
|------|-------------|----------|--------|
| **XSS** | Cross-Site Scripting | 5+ payloads | ✅ Estable |
| **SQLi** | SQL Injection | 7+ payloads | ✅ Estable |
| **LFI** | Local File Inclusion | 3+ payloads | ✅ Estable |
| **RCE** | Remote Code Execution | 4+ payloads | ✅ Estable |
| **Directory Traversal** | Directorios expuestos | 14+ directorios comunes | ✅ Estable |
| **Sensitive Files** | Archivos de configuración | 7+ archivos críticos | ✅ Estable |

## 📋 Requisitos del sistema

- **Python**: 3.7 o superior
- **Sistema Operativo**: Linux, Windows, macOS
- **RAM**: Mínimo 512 MB
- **Conexión a Internet**: Requerida para escaneo
- **Permisos**: Usuario con permisos de escritura

## 🚀 Instalación

### Instalación rápida

```bash
# Clona el repositorio
git clone https://github.com/Hector-SWAT/WebVulnScanner.git
cd WebVulnScanner

# Instala dependencias
pip install -r requirements.txt

# Ejecuta el escáner
python web_scanner.py https://ejemplo.com
```

### Instalación con entorno virtual (Recomendado)

```bash
# Crear entorno virtual
python -m venv venv

# Activar entorno virtual
# En Linux/macOS:
source venv/bin/activate
# En Windows:
venv\Scripts\activate

# Instalar dependencias
pip install -r requirements.txt
```

### Dependencias requeridas

```bash
pip install requests beautifulsoup4 fake-useragent
```

## 💻 Uso básico

### Escaneo simple

```bash
# Escaneo básico de un sitio web
python web_scanner.py https://ejemplo.com

# Escaneo con logging detallado
python web_scanner.py https://ejemplo.com --verbose

# Escaneo con más hilos (más rápido)
python web_scanner.py https://ejemplo.com --threads 20

# Personalizar directorio de reportes
python web_scanner.py https://ejemplo.com --output ./mis_reportes
```

### Opciones avanzadas

| Parámetro | Descripción | Ejemplo |
|-----------|-------------|---------|
| `url` | URL objetivo a escanear | `https://ejemplo.com` |
| `--threads` | Número de hilos (1-50) | `--threads 15` |
| `--output` | Directorio de reportes | `--output ./reportes` |
| `--verbose` | Logging detallado | `--verbose` |

## 📊 Tipos de reportes

El escáner genera reportes en tres formatos:

### 1. Reporte HTML 📄
- Interfaz visual profesional
- Enlaces clickeables
- Categorización por colores
- Ideal para presentaciones

### 2. Reporte JSON 📋
- Formato estructurado para APIs
- Fácil integración con otras herramientas
- Procesamiento automatizado

### 3. Reporte Markdown 📝
- Compatible con GitHub/GitLab
- Fácil lectura en texto plano
- Integración con documentación

## 🔧 Configuración avanzada

El archivo contiene configuraciones personalizables:

```python
CONFIG = {
    "USER_AGENT": "Personalizable",
    "TIMEOUT": 10,                    # Timeout de requests
    "THREADS": 10,                    # Hilos de ejecución
    "PAYLOADS": {                     # Payloads personalizables
        "XSS": [...],
        "SQLi": [...],
        # ... más payloads
    },
    "DIRECTORIES": [...],             # Directorios a escanear
    "FILES": [...],                   # Archivos a buscar
    "REPORT_DIR": "reports"           # Directorio de reportes
}
```

## 📁 Estructura del proyecto

```
WebVulnScanner/
├── web_scanner.py           # Script principal
├── requirements.txt         # Dependencias Python
├── README.md               # Este archivo
├── LICENSE                 # Licencia MIT
├── examples/               # Ejemplos de uso
│   ├── basic_scan.py      # Escaneo básico
│   └── advanced_scan.py   # Escaneo avanzado
├── reports/               # Directorio de reportes (generado)
│   ├── scan_report_*.html # Reportes HTML
│   ├── scan_report_*.json # Reportes JSON
│   └── scan_report_*.md   # Reportes Markdown
├── logs/                  # Logs del sistema
│   └── web_scanner.log    # Log principal
└── docs/                  # Documentación
    ├── SECURITY.md        # Políticas de seguridad
    ├── CONTRIBUTING.md    # Guía de contribución
    └── CHANGELOG.md       # Historial de cambios
```

## 🎯 Ejemplos de uso

### Escaneo de producción
```bash
# Escaneo completo con reportes detallados
python web_scanner.py https://mi-sitio-web.com \
    --threads 5 \
    --output ./auditoria_2024 \
    --verbose
```

### Escaneo rápido para desarrollo
```bash
# Escaneo rápido para desarrollo local
python web_scanner.py http://localhost:8000 \
    --threads 15 \
    --output ./dev_scan
```

### Análisis de múltiples subdominios
```bash
# Script para múltiples objetivos
for subdomain in api admin panel; do
    python web_scanner.py https://${subdomain}.ejemplo.com \
        --output ./scans/${subdomain}
done
```

## 🔍 Interpretación de resultados

### Niveles de severidad

| Nivel | Color | Descripción | Acción recomendada |
|-------|-------|-------------|-------------------|
| 🔴 **Crítico** | Rojo | XSS, SQLi confirmados | **Solución inmediata** |
| 🟡 **Alto** | Amarillo | Archivos sensibles expuestos | **Solución urgente** |
| 🔵 **Medio** | Azul | Directorios accesibles | **Revisar configuración** |
| 🟢 **Info** | Verde | Enlaces y formularios | **Información general** |

### Ejemplo de vulnerabilidad detectada

```json
{
  "XSS": [
    {
      "url": "https://ejemplo.com/search?q=<script>alert(1)</script>",
      "payload": "<script>alert(1)</script>",
      "vulnerable": true
    }
  ]
}
```

## 🛡️ Buenas prácticas de seguridad

### Para auditores
- ✅ Obtener autorización por escrito antes del escaneo
- ✅ Limitar el número de hilos para evitar DoS
- ✅ Realizar escaneos fuera del horario pico
- ✅ Documentar todos los hallazgos

### Para desarrolladores
- ✅ Ejecutar escaneos en entornos de desarrollo
- ✅ Integrar en pipelines CI/CD
- ✅ Revisar reportes regularmente
- ✅ Implementar mitigaciones para vulnerabilidades encontradas

## 🚨 Solución de problemas

### Errores comunes

**Error: "Connection timeout"**
```bash
# Aumentar el timeout en CONFIG
TIMEOUT = 30  # segundos
```

**Error: "Too many requests"**
```bash
# Reducir número de hilos
python web_scanner.py https://ejemplo.com --threads 3
```

**Error: "Permission denied"**
```bash
# Verificar permisos de escritura
chmod 755 ./reports
```

**Error: "Module not found"**
```bash
# Reinstalar dependencias
pip install --upgrade -r requirements.txt
```

### Optimización de rendimiento

```python
# Para sitios lentos
CONFIG["TIMEOUT"] = 30
CONFIG["THREADS"] = 5

# Para sitios rápidos
CONFIG["TIMEOUT"] = 5
CONFIG["THREADS"] = 20
```

## 📈 Métricas y estadísticas

El escáner proporciona métricas detalladas:

- **URLs analizadas**: Total de endpoints probados
- **Vulnerabilidades encontradas**: Desglosadas por tipo
- **Tiempo de ejecución**: Duración total del escaneo
- **Falsos positivos**: Estimación de precisión

## 🤝 Contribuciones

¡Las contribuciones son bienvenidas! Puedes ayudar de varias formas:

### Tipos de contribuciones
- 🐛 **Reportar bugs**: Issues con reproducción
- 💡 **Nuevas vulnerabilidades**: Agregar nuevos tipos de escaneo
- 🔧 **Mejoras de código**: Optimizaciones y refactoring
- 📖 **Documentación**: Mejorar guías y ejemplos
- 🧪 **Testing**: Casos de prueba adicionales

### Proceso de contribución

1. **Fork** el repositorio
2. **Crear rama**: `git checkout -b nueva-vulnerabilidad`
3. **Desarrollar**: Implementar cambios con tests
4. **Commit**: `git commit -am 'Agregar detección de XXE'`
5. **Push**: `git push origin nueva-vulnerabilidad`
6. **Pull Request**: Describir cambios detalladamente

### Guías de desarrollo

```python
# Agregar nueva vulnerabilidad
def scan_xxe(self, url, params=None):
    """Escanea vulnerabilidades XXE"""
    payloads = [
        '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY test SYSTEM "file:///etc/passwd">]><root>&test;</root>',
        # Más payloads...
    ]
    # Implementación...
```

## 📜 Licencia

Este proyecto está bajo la **Licencia MIT**. Consulta el archivo [LICENSE](LICENSE) para más detalles.

```
MIT License

Copyright (c) 2024 Héctor Hernández

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software")...
```

## 👨‍💻 Autor y contacto

**Héctor Hernández** - Security Researcher & Developer

- 📧 **Email**: [hectorhernadez51@gmail.com](mailto:hectorhernadez51@gmail.com)
- 🐙 **GitHub**: [@Hector-SWAT](https://github.com/Hector-SWAT)
- 🔗 **LinkedIn**: [Héctor Hernández](https://linkedin.com/in/hector-swat)
- 🐦 **Twitter**: [@HectorSWAT](https://twitter.com/HectorSWAT)

## 🙏 Reconocimientos

- **OWASP** - Por las guías de vulnerabilidades web
- **PortSwigger** - Inspiración en técnicas de Burp Suite
- **SQLMap Team** - Referencias para detección de SQLi
- **BeautifulSoup** - Excelente librería para parsing HTML
- **Requests** - La mejor librería HTTP para Python

## 🚀 Roadmap

### Versión 2.0 (Próximamente)
- [ ] Interfaz gráfica con PyQt6
- [ ] Soporte para autenticación (Basic, JWT, Cookies)
- [ ] Detección de CSRF y XXE
- [ ] Integración con bases de datos de vulnerabilidades
- [ ] API REST para integración

### Versión 2.5 (Planificado)
- [ ] Machine Learning para reducir falsos positivos
- [ ] Soporte para WebSockets
- [ ] Análisis de código JavaScript
- [ ] Generación de PoC automática

## 📊 Estadísticas del proyecto

- ✅ **Vulnerabilidades detectadas**: 6 tipos
- ✅ **Payloads incluidos**: 25+
- ✅ **Formatos de reporte**: 3
- ✅ **Líneas de código**: 400+
- ✅ **Tests unitarios**: Próximamente

---

<div align="center">

### 🔒 **Recuerda: Usa esta herramienta de forma ética y responsable**

**¿Encontraste una vulnerabilidad? ¡Contribuye al proyecto!**

[🐛 Reportar Bug](https://github.com/Hector-SWAT/WebVulnScanner/issues) • [💡 Solicitar Función](https://github.com/Hector-SWAT/WebVulnScanner/issues) • [📖 Documentación](https://github.com/Hector-SWAT/WebVulnScanner/wiki) • [🛡️ Reporte de Seguridad](mailto:hectorhernadez51@gmail.com)

**⭐ Si esta herramienta te ayudó en tus auditorías, dale una estrella al repositorio**

</div>
