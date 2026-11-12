# secretscan

Escáner de secretos para usar **antes** de que el código salga de tu máquina.
Está escrito en Python y no tiene dependencias externas.

Dos garantías de diseño:

- **Offline.** No importa ningún módulo de red; un test lo comprueba.
- **Los valores no salen del proceso.** El informe indica archivo, línea, regla
  y longitud, nunca el secreto. `--reveal` los muestra solo si la salida es una
  terminal interactiva; se niega si va a un archivo, una tubería o JSON.

## Uso

```bash
python3 -m secretscan                # repositorio actual (versionado + nuevos no ignorados)
python3 -m secretscan --staged       # solo lo preparado para el próximo commit
python3 -m secretscan --history      # todo lo añadido alguna vez en el historial
python3 -m secretscan src/ config/   # rutas concretas, sin necesidad de git
python3 -m secretscan install-hook   # bloquea los commits que contengan secretos
```

Sale con código 1 si encuentra algo.

## Capas de detección

| Regla | Qué detecta |
| --- | --- |
| `aws-access-key`, `github-token`, `stripe-key`... | Formatos conocidos de proveedores, claves privadas, JWT y contraseñas en URLs |
| `env-value` | Valores de tu `.env` local copiados en cualquier otro archivo, tengan el formato que tengan |
| `secret-assignment` | Valores asignados a variables llamadas `password`, `secret`, `token`, `api_key`... |
| `high-entropy` | Cadenas largas con aspecto aleatorio |
| `dangerous-file` | `.env`, `*.pem`, `id_rsa`, `terraform.tfstate` y similares dentro del repositorio |

Para `env-value` el programa lee los `.env` de la raíz del repositorio
(`--env-file` para indicar otros, `--no-env` para desactivarlo).

## Falsos positivos

- Comentario `secretscan:allow` en la línea.
- Archivo `.secretscanignore` en la raíz, con un patrón glob por línea.
- Opción `--exclude PATRÓN`.

## Tests

```bash
python3 -m unittest discover -s tests
```

## Limitaciones

- Un secreto corto, sin formato y con nombre de variable inocente
  (`x = "perro123"`) no se detecta, salvo que esté en tu `.env`.
- No comprueba si una clave sigue activa: eso exigiría conectarse al proveedor.
- El hook guarda la ruta absoluta de esta carpeta; si la mueves, reinstálalo.
- El programa no puede impedir que otra herramienta lea tu `.env` directamente.
  Si usas un asistente de IA, configura en él que no pueda abrir esos archivos.
