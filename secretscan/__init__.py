"""Escáner de secretos offline y determinista.

Principio de diseño: el valor de un secreto nunca sale del proceso. No hay
llamadas de red y los informes no contienen los valores encontrados.
"""

__version__ = "0.1.0"
