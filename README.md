# CTEA - Cyber Threat Exposure Analyzer 🛡️

**CTEA** es un sistema modular de Detección y Respuesta en Endpoint (EDR) diseñado para monitorear, detectar y responder a amenazas de ciberseguridad en tiempo real.

## 🚀 Características Principales

- **Detección de Procesos**: Identifica procesos sospechosos basados en nombres, rutas y relaciones padre-hijo (ej. Word lanzando PowerShell).
- **Monitor de Red**: Detecta conexiones a puertos inusuales o conocidos por ser usados por malware (Metasploit, Botnets).
- **Integración con VirusTotal**: Escanea hashes de procesos activos contra la base de datos de VirusTotal.
- **Reglas YARA**: Escanea binarios ejecutables en busca de firmas de malware y patrones ocultos.
- **Monitor de Integridad de Archivos (FIM)**: Vigila cambios en directorios críticos del sistema.
- **Honeyfile (Trampa)**: Archivo cebo que dispara una alerta crítica si es accedido o modificado.
- **Persistencia**: Detecta modificaciones en el Registro de Windows (`Run`/`RunOnce`) para identificar malware persistente.
- **Respuesta Automática**: Capacidad de terminar procesos maliciosos de alto riesgo automáticamente.
- **Notificaciones**: Envío de alertas en tiempo real vía Webhook (Discord/Slack).

## 🛠️ Instalación

1.  **Clonar el repositorio**:

    ```bash
    git clone https://github.com/TU_USUARIO/CTEA-EDR.git
    cd CTEA-EDR
    ```

2.  **Instalar dependencias**:
    Asegúrate de tener Python 3.8+ instalado.

    ```bash
    pip install -r requirements.txt
    ```

    _(Si no tienes un archivo requirements.txt, las dependencias principales son: `psutil`, `requests`, `pyyaml`, `watchdog`, `yara-python`)_

3.  **Configuración**:
    Edita el archivo `config/rules.yaml`:
    - Añade tu **API Key de VirusTotal**.
    - Configura la **Webhook URL** para notificaciones.
    - Ajusta los umbrales de riesgo según tus necesidades.

## 💻 Uso

Ejecuta la herramienta desde la terminal:

**Modo Escaneo Rápido**:

```bash
python main.py scan
```

**Modo Demonio (Monitor Continuo)**:

```bash
python main.py daemon
```

## ⚙️ Configuración Avanzada

El comportamiento del EDR se controla a través de `config/rules.yaml`.

### Ejemplo de Configuración de Honeyfile

```yaml
honeyfile:
  enabled: true
  path: "C:\\Users\\Public\\confidential_passwords.txt"
  alert_message: "HONEYFILE ACCESSED!"
```

### Ejemplo de Reglas YARA

Las reglas personalizadas se encuentran en `rules/yara/all_rules.yar`. Puedes añadir tus propias reglas para detectar amenazas específicas.

## ⚠️ Disclaimer

Esta herramienta es para **fines educativos y de investigación**. El autor no se hace responsable del mal uso de este software. Ejecutar siempre en entornos controlados y con autorización.
