# Firewall Detection

🔥 **Firewall Detection** es una herramienta básica de detección de firewalls TCP que permite analizar cómo responde un host ante distintos paquetes TCP y genera recomendaciones para técnicas de evasión.  

---

Esta herramienta se mantiene en fase de desarollo, el objetivo final sera poder reconecer y evadir el firewall usando solo esta herramienta. 

---

## 📌 Descripción

Esta herramienta permite:
- Realizar un escaneo de puertos TCP enviando distintos tipos de paquetes (`SYN`, `ACK`, `FIN`, `NULL`, `XMAS`, `RST`) hacia un objetivo.
- Analizar las respuestas recibidas y generar un **diagnóstico** sobre la presencia y comportamiento de un firewall.
- Generar **recomendaciones automáticas** para posibles técnicas de evasión basadas en el diagnóstico o los resultados crudos.

Está orientada principalmente a pruebas en entornos de laboratorio, para evaluar la protección de sistemas como **Ubuntu con firewalls activos**.  

---

## ⚙️ Funcionamiento interno

1. **Escaneo de paquetes TCP**:
   - Se envían paquetes con diferentes flags TCP al puerto objetivo.
   - Se registra la respuesta: `SA`, `RST`, `No response`, `ICMP unreachable`, etc.
   - Opcionalmente, se puede hacer un escaneo rápido (`--quick`) solo con `SYN` y `ACK`.

2. **Diagnóstico**:
   - Se analiza la respuesta de cada tipo de paquete.
   - Se determina si el puerto está abierto, cerrado, filtrado por firewall o si se encuentra un firewall stateful.

3. **Generación de recomendaciones**:
   - Si `use_raw` está activado, se generan sugerencias directamente desde los resultados crudos.
   - De lo contrario, se utilizan patrones en el diagnóstico para recomendar técnicas de evasión como:
     - Manipulación del puerto de origen.
     - Fragmentación de paquetes.
     - Modificación de la longitud de los paquetes o envío de paquetes NULL, FIN o XMAS para bypass.

4. **Visualización**:
   - Se muestran resultados crudos y diagnóstico con colores diferenciados.
   - Se listan las recomendaciones finales para facilitar la interpretación.

---

## 💻 Instalación

1. Clona el repositorio:
   ```bash
   git clone https://github.com/tu-usuario/FirewallDetection.git
   cd FirewallDetection
