# Introducción

El siguiente informe técnico describe una herramienta desarrollada en PowerShell que permite la gestión avanzada de usuarios en Active Directory , diseñada específicamente para entornos Windows Server con rol de Controlador de Dominio (DC) .

La herramienta está orientada al personal técnico de Telefonica TCCT y cumple con políticas de seguridad estrictas, como:

Comprobación de dominio (vdc.adm)

Validación de autorización RSO

Registros completos de todas las acciones realizadas

---

**Objetivo del Documento**

Este documento tiene como finalidad:

- Documentar el propósito y funcionamiento del script userMgmt.ps1
- Explicar el flujo de cada función disponible
- Detallar cómo se registran las acciones
- Proponer posibles mejoras futuras

1. # <a name="_toc200540733"></a>Requisitos Técnicos


| Componente          | Requerimiento                                                    |
| :-------------------- | :----------------------------------------------------------------- |
| Sistema Operativo   | Windows Server con rol de Controlador de Dominio                 |
| Módulo necesario   | ActiveDirectory (importado automáticamente)                     |
| Dominio requerido   | vdc.adm(en funciones críticas)                                  |
| Permisos            | El usuario debe tener permisos de administrador o delegado en AD |
| Archivos necesarios | userMgmt.log(local y SYSVOL en DCs)                              |
| Entorno             | PowerShell 5.1+ o PowerShell Core                                |

---


# Funciones Disponibles


## Agregar-Usuario

Permite crear manualmente un nuevo usuario en Active Directory.

Se solicita:

- Matrícula (sAMAccountName)
- Nombre y apellidos
- Correo electrónico
- Contraseña (manual o autogenerada)

También permite seleccionar una OU destino y uno o varios grupos a asignar.

Acciones:

- Crea el usuario
- Asigna grupos
- Registra en log y evento

---


## **Ver-EstadoUsuario**


Muestra información detallada de un usuario sin realizar cambios:

- Nombre completo
- Correo
- Estado de cuenta (habilitada/deshabilitada)
- Estado de bloqueo (bloqueado/desbloqueado)
- Último inicio de sesión
- OU actual
- Grupos a los que pertenece

Solo disponible en Controladores de Dominio.

---

1. ## <a name="_toc200540737"></a>**Modificar-Usuario**

Permite modificar datos de un usuario existente:

- Nombre y apellidos
- Correo
- Estado de cuenta
- OU destino
- Asignación/quita de grupos
- El usuario puede elegir qué campos actualizar y si moverlo a otra OU.

Se registra toda acción en logs y eventos.

---

1. ## <a name="_toc200540738"></a>**Eliminar-Usuario**

Ofrece dos opciones:

- Eliminar permanentemente : Se borra el usuario del directorio
- Deshabilitar y mover : Se deshabilita la cuenta y opcionalmente se mueve a una OU de deshabilitados

También permite registrar:

- Motivo del cambio
- Usuario que realiza la acción
- Si fue autorizado por el RSO

---

1. ## <a name="_toc200540739"></a>**Auditar-UsuariosInactivos90Dias**

Busca usuarios habilitados que no han iniciado sesión en más de 90 días.Opciones:

- Deshabilitar y mover todos automáticamente
- Procesar uno a uno
- No hacer nada

Solo funciona en el dominio vdc.adm.


Registra en log local, red (SYSVOL) y evento de sistema.

---

1. ## <a name="_toc200540740"></a>**Auditar-UsuariosDeshabilitados60Dias**

Busca usuarios deshabilitados desde hace más de 60 días.Opciones:

- Eliminar todos
- Seleccionar uno a uno
- No hacer nada

Requiere ser ejecutado en un Controlador de Dominio del dominio vdc.adm.

---

1. ## <a name="_toc200540741"></a>**Desbloquear-UsuarioContraseña**

Función destinada a:

- Desbloquear cuentas bloqueadas
- Habilitar cuentas deshabilitadas (opcional)
- Cambiar contraseña (manual o autogenerada)
- Mover usuarios a OU diferente si están en una OU de deshabilitados

Se muestra estado actual del usuario y se pide confirmación antes de realizar cualquier cambio.

---

1. ## <a name="_toc200540742"></a>**Agregar-ListadoUsuarios**

Importa un archivo CSV con las siguientes columnas:

- matricula
- nombre
- apellidos
- mail

Crea múltiples usuarios en una OU seleccionada.
Asigna automáticamente los grupos disponibles en esa OU.
Muestra resumen antes de aplicar cambios.
También genera contraseñas seguras.

---

1. # <a name="_toc200540743"></a>Registro de Acciones

   1. ## <a name="_toc200540744"></a>**Logs Locales**

Se guardan en:

***C:\Windows\Logs\userMgmt.log***

Formato:

[Fecha] | [TipoEvento] | [Equipo] | [Matrícula] | [Incidencia] | [RSO] | [OU] | [Grupos] | [Descripción] | [Resultado]

1. ## <a name="_toc200540745"></a>**Logs en Red (solo DCs)**

En el servidor compartido:

***\\<dominio>\sysvol\<dominio>\Logs\userMgmt.log***

1. ## <a name="_toc200540746"></a>**Event Viewer**

Registro en canal personalizado:

**RegistroUsuarios**

Con mensajes estructurados y tipo de evento según resultado:

Éxito

Error

Información

Advertencia

Ejemplo de mensaje en evento:

**[2025-04-07 16:00:00] Acción: Éxito.**

**Incidencia: INC-2025-007**

**Usuario que aplica el cambio: admin.jose**

**Usuario afectado: jgonzalez**

**OU destino: OU=Usuarios,DC=vdc,DC=adm**

**Grupos asignados: GrupoTecnico, GrupoTelefonica**

**Descripción: Alta por listado. Incidencia: INC-2025-007. Autorizado por RSO: Autorizada**

**Resultado: Usuario creado correctamente.**

---

1. # <a name="_toc200540747"></a>Seguridad y Trazabilidad

   1. ## <a name="_toc200540748"></a>**Validaciones Automáticas**

Solo se permiten funciones críticas en Controladores de Dominio

Algunas funciones solo se ejecutan en el dominio vdc.adm

En cada función se pregunta si la acción está autorizada por el RSO

1. ## <a name="_toc200540749"></a>**Campos Comunes en Logs**


| Campo             | Descripción                             |
| :------------------ | :----------------------------------------- |
| tipoEvento        | Éxito, Error, Información, Advertencia |
| incidencia        | Motivo del cambio                        |
| usuarioRealizador | Quién hizo la acción                   |
| usuarioAfectado   | Sobre quién se realizó                 |
| ouDestino         | Dónde se movió el usuario              |
| gruposAsignados   | Grupos añadidos o quitados              |
| descripcion       | Descripción del usuario actualizada     |
| autorizadoRSO     | ¿Está autorizado?                      |
| resultado         | Qué se hizo exactamente                 |

---

1. # <a name="_toc200540750"></a>Posibles Extensiones Futuras


| Número | Función                 | Descripción                                                 |
| :-------- | :------------------------- | :------------------------------------------------------------- |
| 9       | Exportar-InformeUsuarios | Generar CSV con usuarios activos, inactivos o deshabilitados |
| 10      | Archivar-Usuarios        | Mover usuarios antiguos a carpeta compartida de archivos     |
| 11      | Crear-NuevosGrupos       | Crear grupos definidos en plantilla                          |
| 12      | Restaurar-Usuarios       | Recuperar usuarios eliminados                                |
| 13      | Reporte-Mensual          | Auditoría automatizada mensual                              |

---

1. # <a name="_toc200540751"></a>Conclusiones

Este script proporciona una solución robusta y profesional para gestionar usuarios en Active Directory dentro del entorno de Telefonica TCCT .

Sus principales ventajas son:

- Interfaz clara con colores diferenciados
- Validación automática del entorno (Dominio, Rol, Fecha/Hora)
- Trazabilidad completa en tres niveles: local, red y evento de sistema
- Integración con políticas de seguridad internas
- Soporte tanto para tareas individuales como masivas

Es ideal para equipos técnicos que requieren realizar cambios auditables y documentados en el directorio activo.
