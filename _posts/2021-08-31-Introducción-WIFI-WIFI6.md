---
layout: single
title: Introducción WIFI/WIFI6
date: 2021-08-31
classes: wide
header:
  teaser: /assets/images/signal.jpg
categories:
  - infosec
tags:
  - WIFI

![](/assets/images/signal.jpg)

---



# Introducción WI-FI, Wi-Fi-6
## ¿Qúe es el Wi-Fi y cómo hemos llegado a la situación actual?
```
Es una tecnología que permite la interconexión inalámbrica de dispositivos electrónicos. 
Los dispositivos habilitados con wifi tales como:
(ordenadores personales, teléfonos, televisores, videoconsolas, reproductores de música, etcétera) pueden conectarse 
entre sí o a Internet a través de un punto de acceso de red inalámbrica.
```
* Tecnología inalámbrica de red local (WLAN), para banda no licenciada (ISM)
* Nace en 1997, pero su uso real inicia en 1999.
* Se basa en contienda (CSMA/CA)
```
(CSMA/CA):
La comunicación sólo se produce cuando un usuario puede transmitir la información sin interferencias.
```
* Propone, originalmente, 2 formas de conexión de los usuarios.
## ¿Qué le pasa al Wi-Fi? 
* Cualquiera lo puede usar.
* No nació pensando en entornos empresariales, industriales o masivos.
* La comunicación la controla el dispositivo cliente.
* IoT, 8K o VR no existían en 2014.
# Otros conceptos básicos
* Beacon Frames: Los puntos de acceso mandan constantemente anuncios de la red, para que los clientes móviles puedan detectar su presencia y conectarse a la red wireless. Estos "anuncios" son conocidos como Beacon Frames,. Si esnifamos las tramas de una wireless podremos ver que normalmente el AP manda el ESSID, de la red en los Beacon Frames, aunque esto se puede deshabilitar por software en la mayoria de los AP que se comercializan actualmente.
* ACL: Significa Access Control List y es el método mediante el cual sólo se permite unirse a la red a aquellas direcciones MAC que estén dadas de alta en una lista de direcciones permitidas.
* CNAC: Significa Closed Network Access Control. Impide que los dispositivos que quieran unirse a la red lo hagan si no conocen previamente el SSID de la misma.
* SSID: (Service Set Identification) y ESSID (Extended Service Set Identification): Este identificador suele emplearse en las redes wireless creadas por infraestructura. Se trata de un conjunto de servicios que agrupan todas las conexiones de los clientes en un sólo canal. Suele denominar de manera familiar el nombre de la red wireless que da servicio o un Punto de Accesso. Cada red wireless tiene un ESSID que la identifica.
## Banda de frencuencia y canales
- Cada país define la posibilidad de utilizar las bandas y canales de manera independiente.
- También las características de uso de las mismas.
![image](https://user-images.githubusercontent.com/64669644/88854922-5f563f00-d1f2-11ea-801a-86166e7aa082.png)
## Método de modulación y acceso
- Puede ser BPSK, QPSK o xx-QAM
- Los métodos de acceso empleados han sido DSSS, OFDM y OFDMA
## Antenas
* Las antenas son elementos que "conectan" con el aire.
* Pueden ser omnidireccionales o directivas.
* Pueden ser discretas (una única antena) o un arreglo de varios elementos (MIMO)
![image](https://user-images.githubusercontent.com/64669644/88858305-15705780-d1f8-11ea-8b27-27b2da276411.png)
## ¿En qué nos puede beneficiar Wi-Fi 6?
* Nuevas aplicaciónes.
* Muchas más conexiones. (IoT) (Hasta 1024 dispositivos por AP)
* Menor Latencia. (Reducción de la latencia hasta 20ms)
* Mayor ancho de banda.
* Menos consumo Energético. (TWT 20MHz Only) (Reducción del consumo hasta en un 30%)
## Mejores prácticas de diseño para redes Wi-Fi
![image](https://user-images.githubusercontent.com/64669644/88859410-fa9ee280-d1f9-11ea-9e86-7c42073750fd.png)
![image](https://user-images.githubusercontent.com/64669644/88859440-08ecfe80-d1fa-11ea-95e0-73307a98fd93.png)

## Elementos de una red Enterprise
* Controlador: Es un elemento que orquesta los parámetros y políticas de un conjunto de AP, de manera que se facilita el ajuste RF, la autenticación de los usuarios o el roaming entre los AP. Puede ser físico o software, estar ubicado en local, en un sitio centrao o en la nube.
* Gestión de infraestructura: Es una suite de software que permite tener una visión global del estado de la red Wi-Fi, permitiendo la visualización de alarmas, topología, reportes, configuración, etc. Suele desplegarse en una ubicación central o en la nube.
* Gestión de Usuarios: Es una suite de software que permite establecer y centralizar políticas relativas a la autenticación y a utorización de los dispositivcos de los clientes que se conectan a la red. Suele desplegarse en una ubicación central o en la nube.
## Factores de un buen diseño
* El espacio físico: donde se pueden instalar los AP, y donde estarán los usuarios en la red, es el primer elemento a controlar. Considerar que es necesario proporcionar conectividad y electricidad al AP. La seguridad de los instaladores también debe ser tomada en cuenta.
* Nivel de señal recibida (RSSI -67 dBm significa señal adecuada): Es la "fuerza" de la señal recibida y que determianra la velocidad de conexión. Es importante saber las aplicaciones que se utilizarán y la distancia a la que estarán de los dispositivos.
* Nivel de ruido (SNR): es la medida de la "limpieza" del medio, simplificando, las interferencias que pueden generarse y afecten la comunicación entre AP y un dispositivo. Es importante saber las aplicaciones que se utilizarán y la densidad de dispositivos en servicio.
## Seguridad
* Separar la comunicación de los distintos grupos de usuarios, cada grupo con sus políticas de seguridad particulares.
* Utilizar mecanismos de autorización basados en el perfil de usuario individual(como 802.1x ó Personal PSK).
* Migrar a mecanismos de cifrado mejorados, como WPA3, lo antes posible.
* Activar mecanismos de monitorización activos en el dominio RF.
* La seguridad debe ser general a toda la red y usuarios, en todo caso añadir políticas adicionales al usuario de acceso inalámbrico, no tratarlo como una isla
## Cifrado
![image](https://user-images.githubusercontent.com/64669644/88910750-31f2ab00-d25d-11ea-8c73-16f140a084bd.png)
![image](https://user-images.githubusercontent.com/64669644/88910787-4040c700-d25d-11ea-8452-6362d6a850a0.png)
## Principales ataques Wi-Fi
* https://github.com/systematicat/hack-captive-portals
* WEP (ChopChop)
* WPA-WPA2 (Kr00k) CVE-2019-15126 - Krack attacks (4-way handshake) - PMKID - Pixie Dust
* WPA3 (Dragonblood)
## Jamming
* Constant jammer
* Deceptive jammer
* Random jammer
* Reactive jammer
## GNSS
* https://es.wikipedia.org/wiki/Sistema_global_de_navegaci%C3%B3n_por_sat%C3%A9lite

# Radio definida por software
- https://es.wikipedia.org/wiki/Radio_definida_por_software
- https://en.wikipedia.org/wiki/List_of_software-defined_radios
## ¿Que es un SDR?
```
Radio en la cual alguna o varias de las funciones de la capa física
son definidas mediante software: filtros, mezcladores, amplificadores, etc.
```
## Orígenes de la tecnología SDR
```
- 1991, programa SPEAKeasy por DARPA.
- Joseph Mitola 90's publicó "Software Radio: Survey, Critical Analysis and future directions".
- Los primeros SDR fueron de uso militar.
- Hardware caro y complejo de usar, anchos muy limitados.
- Después se uso por partes de empresas y radioaficionados. Flex Radio SDR-1000
```
# Introducción RFID (Radio Frequency Identification)
![image](https://user-images.githubusercontent.com/64669644/89021035-2916dd80-d320-11ea-8a83-5111ad40cf51.png)
