# HTTP Security Analyzer

Aplicación educativa de terminal en Python 3 para comprobar cuatro cabeceras HTTP.
No realiza ataques ni pretende sustituir una auditoría o reproducir la puntuación de Mozilla Observatory.

## Instalación y ejecución

Requiere Python 3.9 o posterior. Solo utiliza la biblioteca estándar: no hay dependencias
externas ni es necesario un archivo requirements.txt.

Desde la carpeta del proyecto:

```sh
python3 analyzer.py
```

Introduce la URL pública que quieras analizar, incluyendo `https://` o `http://`.
También puedes pasarla como argumento: `python3 analyzer.py URL`.
Para consultar la ayuda: `python3 analyzer.py --help`.
Las rutas y consultas deben estar codificadas como URL ASCII (por ejemplo, los espacios como `%20`).
Los nombres de dominio internacionales se convierten mediante IDNA.

## Resultados y puntuación

Se muestran la URL final, el estado HTTP y, para cada cabecera, su valor y una recomendación:

| Cabecera | Comprobación básica |
| --- | --- |
| Content-Security-Policy | Contiene default-src con valor y no contiene comodines, data:, unsafe-inline o unsafe-eval |
| Strict-Transport-Security | Se recibe por HTTPS y tiene un max-age único de al menos 31536000 segundos |
| X-Content-Type-Options | Valor nosniff |
| Referrer-Policy | no-referrer, same-origin, strict-origin o strict-origin-when-cross-origin |

Cada cabecera ausente recibe 0 puntos; presente pero pendiente de revisión, 10;
presente y conforme a las reglas básicas, 25. Total: 0–100.
Las cabeceras duplicadas requieren revisión. Las reglas son heurísticas conservadoras:
no implementan todos los detalles de las políticas ni evalúan el contenido HTML,
recursos, cookies o vulnerabilidades. Incluso 100/100 no garantiza seguridad.
Una política válida puede requerir revisión por estas reglas simplificadas.
La puntuación no equivale a la de Mozilla Observatory. Solo se puntúa la respuesta final;
si es una respuesta HTTP de error, se indica expresamente. HTTP sin cifrado genera un aviso.

## Precauciones de red

- Solo HTTP/HTTPS, puertos 80 y 443; sin credenciales en la URL.
- Espera DNS de 5 segundos y timeout de socket de 5 segundos por operación.
  No es un límite absoluto para la ejecución completa: las operaciones y saltos se acumulan,
  y un servidor que envíe datos lentamente puede prolongar la respuesta.
- Máximo de 5 redirecciones; detección de bucles, rechazo de Location ambiguo
  y bloqueo de degradaciones de HTTPS a HTTP.
- Validación DNS en cada salto: se rechaza todo el destino si alguna IP devuelta
  es privada, local, reservada, multicast o no global, incluidas IPv4 mapeadas en IPv6.
- Conexión directa a una IP ya validada; se conserva el nombre del servidor para Host,
  SNI y la verificación del certificado TLS. No se usan proxies de entorno.
- Una petición GET por salto, sin descargar el cuerpo; las cabeceras se procesan con
  los límites de tamaño y número de la biblioteca http.client.
- Se neutralizan caracteres de control al imprimir datos del servidor.

Estas medidas reducen el riesgo de solicitudes internas, pero no son una frontera
de seguridad frente a redes con enrutamiento especial. Esta aplicación está pensada
para uso local desde terminal; no debe exponerse como servicio público sin controles adicionales.
Solo analiza URLs que tengas autorización para consultar.

## Pruebas

```sh
python3 -m unittest discover -s tests -v
```

Las pruebas simulan DNS, conexiones y respuestas HTTP: no consultan webs reales.
Cubren validación de URL e IP, DNS mixto y fallido, timeout, redirecciones,
bloqueo de destinos internos, fijación de IP y nombre TLS, cierre de conexiones,
evaluación de cabeceras, puntuación y salida de terminal.

El programa devuelve código 0 cuando obtiene y analiza una respuesta (aunque falten
cabeceras) y código 1 ante errores de URL, red o cancelación.
