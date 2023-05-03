# Covert-storage-channels-in-TLS

A framework for exploring covert storage channels in TLS

Фреймворк, с помощью которого можно исследовать скрытые каналы по памяти в протоколе TLS.

## 1. Stand setup

After installation of Scapy and Suricata (see requirements in **requirements.txt**) move **client.py**, **server.py** and **proxy.py** to the **scapy/test/tls**. As well move the content of folder **pki** to the **scapy/test/tls/pki/**.

После установки Scapy и Suricata (требования указаны в **requirements.txt**) скрипты **client.py**, **server.py** и **proxy.py** необходимо переместить в **scapy/test/tls**. Также содержимое каталога **pki** необходимо переместить в **scapy/test/tls/pki**.

## 2. Suricata module setup

Move the content of folder **filter device** to **suricata/src**. Edit the content of service files as it is shown below.

Содержимое каталога **filter device** необходимо переместить в **suricata/src**. Также нужно отредактировать служебные файлы, как это показано ниже.

**ADD** *#include detect-tls-session-id.h* **TO** *suricata/src/detect-engine-register.c*
**ADD** *DetectTlsSessionIDRegister();* **TO** *suricata/src/detect-engine-register.c*
**ADD** *DETECT_AL_TLS_SESSION_ID,* **TO** *suricata/src/detect-engine-register.h*
**ADD** *detect-tls-session-id.h* **TO** *suricata/src/Makefile.am*
**ADD** *detect-tls-random.c* **TO** *suricata/src/Makefile.am*

After adding changes configure and make as usual in Suricata.

## 3. Usage of framework

Instructions how to run client and server see below. Notice that it is possible to specify server socket (host and port_) by adding arguments to the script running from the console.

Инструкции по запуску клиента и сервера смотрите ниже. Обратите внимание, что сокет сервера (хост и порт) можно задать, добавив аргументы при запуске скрипта из консоли.

*python3 server.py 127.0.0.1 4433*
*python3 client.py 127.0.0.1 4433*

### 3.1 Injecting covert channel

Covert storage channel in Random field of ClientHello replaces the last byte of the Random field in dependence of injected covert message. Covert storage channel in SessionID field of ClientHello places an encrypted covert message (GOST 34.11-2018) in the field.
To activate Random CC add argument *--ccm y* or *--ccm n* with client script.
To activate SessionID CC use another message with key *--ccm* while running client script.

Скрытый канал по памяти, использующий поле Random в сообщении ClientHello, заменяет последний байт поля в зависимости от внедряемого секретного сообщения. Скрытый канал по памяти, использующий поле SessionID, помещает в поле зашифрованное с помощью хэш-функции сообщение (ГОСТ Р 34.11-2018).
Чтобы задейстовать СК с использованием Random, используйте аргумент *--ccm y* или *--ccm n* со скриптом клиентской стороны.
Чтобы задейстовать СК с использованием SessionID, введите иное сообщение с ключом *--ccm* вов ремя запуска скрипта клиентской стороны.

### 3.2 Running proxy

While running proxy it is possible to specify proxy socket by using keys. See example below.
Notice if you use proxy then proxy socket in arguments of client script is needed.

Во время запуска прокси-сервера с помощью ключей возможно задание сокетов прокси-севрера и сервера. Пример приведен ниже.
Важно: при использовании прокси-сервера в аргументах скрипта клиента необходимо указывать сокет прокси.

*python3 server.py --proxy 127.0.0.1 --sport 43433 --server 127.0.0.1 --dport 4433*

### 3.2 Running filter device

Use the Suricata rule below to detect or prevent packets with non-zero (32 bytes) length of SessionID field.

Ниже приведено правило Suricata, с помощью которого можно детектировать или предотвращать передачу пакетов с ненулевой (32 байта) длиной поля SessionID.

*alert tls any any -> any any (msg:"TLS SESSION ID COVERT CHANNEL"; tls.session_id; content:"|20|"; sid: 200076;)*
