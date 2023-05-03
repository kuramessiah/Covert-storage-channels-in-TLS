import os
import socket
import ssl
import sys
from argparse import ArgumentParser
from scapy.utils import inet_aton
from argparse import ArgumentParser

basedir = os.path.abspath(os.path.join(os.path.dirname(__file__),"../../"))

parser = ArgumentParser(description='TLS proxy')
parser.add_argument("--proxy", nargs="?", default="127.0.0.1",
                    help="This proxy")
parser.add_argument("--sport", nargs="?", type=int, default=43433,
                    help="The TCP source port")
parser.add_argument("--server", nargs="?", default="127.0.0.1",
                    help="The server to connect to")
parser.add_argument("--dport", nargs="?", type=int, default=4433,
                    help="The TCP destination port")
args = parser.parse_args()

def proxy_thread(client, data): #client_run
    req = b''

    client.settimeout(0.1)
    while data:
        req += data
        try:
            data = client.recv(1024)
        except socket.error:
            break

    logging.info(req)

    context = ssl.create_default_context()
    context.load_verify_locations(basedir+'/test/tls/pki/ca_cert.pem')
    ssock = socket.create_connection((args.server, args.dport))
    serv = context.wrap_socket(ssock, server_hostname = 'Scapy Test Server')

    serv.send(req)

    resp = b''
    serv.settimeout(1)
    data = serv.recv(1024)
    while data:
        resp += data
        try:
            data = serv.recv(1024)
        except socket.error:
            break

    logging.info(resp)

    client.send(resp)
    

context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
context.load_cert_chain(basedir+'/test/tls/pki/prx_cert.pem', basedir+'/test/tls/pki/prx_key.pem')
ssock = socket.socket()
ssock.bind((args.proxy, args.sport))
ssock.listen(1)
sock = context.wrap_socket(ssock, server_side = True)
print("Running on", args.proxy, ":", args.sport)  
while True:
    conn, addr = sock.accept()
    print("Running on ", args.proxy, ":", args.sport)
    data = conn.recv(4)
    if data == b'STOP':
        break

    proxy_thread(conn, data)
