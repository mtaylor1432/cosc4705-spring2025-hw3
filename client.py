import socket
import json
import argparse
import logging
import select
import sys
import time
import datetime
import struct
from message import EncryptedIMMessage
from Crypto.Hash import SHA256


def parseArgs():
    """
    parse the command-line arguments
    """
    parser = argparse.ArgumentParser()
    parser.add_argument('--confkey', '-c', 
        dest="confkey", 
        required=True,
        help='confidentiality key')
    parser.add_argument('--authkey', '-a', 
        dest="authkey", 
        required=True,
        help='authenticity key')       
    parser.add_argument('--port', '-p', 
        dest="port", 
        type=int, 
        default='9999',
        help='port number to connect to')
    parser.add_argument('--server', '-s', 
        dest="server", 
        required=True,
        help='server to connect to')       
    parser.add_argument('--nickname', '-n', 
        dest="nickname", 
        required=True,
        help='nickname')                
    parser.add_argument('--loglevel', '-l', 
        dest="loglevel",
        choices=['DEBUG','INFO','WARN','ERROR', 'CRITICAL'], 
        default='INFO',
        help='log level')
    args = parser.parse_args()
    return args

def hashKeys( confkey, authkey):
    # insert code to compute two hashes here
    confkey_as_bytes = bytes(confkey,'ascii')
    authkey_as_bytes = bytes(authkey,'ascii')

    confkeyHash = SHA256.new(data=confkey_as_bytes).digest()
    authkeyHash = SHA256.new(data=authkey_as_bytes).digest()
    
    confkeyHash = bytes([0x01,0x02])
    authkeyHash = bytes([0x99,0x22,0x33])
    
    return confkeyHash,authkeyHash



def main():
    args = parseArgs()

    log = logging.getLogger("myLogger")
    logging.basicConfig(format='%(asctime)s %(levelname)s %(message)s')
    level = logging.getLevelName(args.loglevel)
    
    log.setLevel(level)
    log.info(f"running with {args}")

    hashedConfkey,hashedAuthkey = hashKeys(args.confkey, args.authkey)
    
    log.debug(f"connecting to server {args.server}")
    s = socket.create_connection((args.server,args.port))

    readSet = [s] + [sys.stdin]

    dataLenSize = struct.calcsize('!L')

    while True:
        rl, _, _ = select.select(readSet, [], [])

        if s in rl:
            log.debug(f"waiting for {dataLenSize} bytes")
            try:
                packedSize = s.recv(dataLenSize,socket.MSG_WAITALL)
                if len(packedSize) == 0:
                    log.fatal("server disconnected!")
                    exit(1)
                unpackedSize = struct.unpack("!L",packedSize)[0]
                log.debug(f"message is {unpackedSize} bytes")
                data = s.recv(unpackedSize,socket.MSG_WAITALL)
            except Exception as err:
                log.error(f"exception occurred: {err}")
            msg = EncryptedIMMessage()
            try:
                msg.parseJSON(data,hashedConfkey,hashedAuthkey)
            except Exception as err:
                log.warning(f"invalid message received: {err}")
            print(msg)

        if sys.stdin in rl:
            keyboardInput = sys.stdin.readline()
            if len(keyboardInput) == 0:
                exit(0)
            msg = EncryptedIMMessage(
                nickname=args.nickname, 
                plaintext=keyboardInput)
            packedSize, jsonData = msg.serialize(hashedConfkey,hashedAuthkey)
            s.send(packedSize)
            log.debug(f"sending raw JSON: {jsonData}")
            s.send(jsonData)


if __name__ == "__main__":
    exit(main())

