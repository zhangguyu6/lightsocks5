# -*- coding: utf-8 -*-
import asyncio
from enum import Enum
import utli
import struct
import yaml
from exception import AuthenError, UnsupportedMethodsError, VersionError
from log import log
from functools import partial

config = yaml.load(open("test.yaml"))
passw = config["password"]
user = config["username"]
remote_address = config["remoteaddr"]
remote_port = config["remoteport"]


class STAGE_STATE(Enum):
    INIT = 1,
    WAITTING_FOR_CONNECT = 2,
    CONNECTING = 3,
    CONNECTED = 4


class AuthMethod(bytes, Enum):
    none = b'\x00'
    gssapi = b'\x01'
    username_password = b'\x02'
    not_acceptable = b'\xff'


class Command(bytes, Enum):
    connect = b'\x01'
    bind = b'\x02'
    udp_associate = b'\x03'


class Socks5InputProtocol(asyncio.Protocol):
    def __init__(self, remote_address, remote_port):
        log.debug("enter init")
        self.remote_address = remote_address
        self.remote_port = remote_port
        self.connection_state = STAGE_STATE["INIT"]
        self.data = b""
        self.remotedata = b""
        self.transport = None

    def connection_made(self, transport):
        log.debug("make connection")
        self.transport = transport

    def connection_lost(self, exc):
        self.connection_state = STAGE_STATE["CONNECTED"]
        self.transport = None

    async def send_data(self, data):
        print(self.connection_state)
        self.remoteread, self.remotewrite = await asyncio.open_connection(self.remote_address, self.remote_port)
        self.remotewrite.write(data)
        self.remotewrite.drain()
        self.remotedata = await self.remoteread.read()
        print("remotedata is ", self.remotedata)

    def data_received(self, data):
        log.info("data from client is " + str(data))
        log.debug("receiving data")
        self.data = data
        if self.connection_state == STAGE_STATE["INIT"]:
            asyncio.ensure_future(self.handle_init())
        if self.connection_state == STAGE_STATE["WAITTING_FOR_CONNECT"]:
            self.handle_authentication()
        if self.connection_state == STAGE_STATE["CONNECTING"]:
            self.handle_connect()

    async def handle_init(self):
        log.debug("enter handle_init")
        version, numsofmethods = struct.unpack("!BB", self.data[:2])
        if version != 5:
            raise VersionError
        if numsofmethods > len(self.data[2:]):
            raise UnsupportedMethodsError
        client_methods = [bytes([x]) for x in self.data[2:]]
        common_methods = client_methods
        selected = common_methods[0] if common_methods else AuthMethod.not_acceptable

        # 读写远程服务器
        await self.send_data(b'\x05' + selected)

        if selected == AuthMethod.not_acceptable:
            raise AuthenError
        self.connection_state = STAGE_STATE["WAITTING_FOR_CONNECT"]
        print("current state is",self.connection_state)
        await self.handle_authentication()

    async def handle_authentication(self):
        log.debug("handle_authentication")
        remotedata = self.remotedata
        log.debug("remotedata is"+str(remotedata))
        version, status_code = struct.unpack("!BB", remotedata[:2])
        print(version,status_code)
        if status_code == 0:
            self.connection_state = STAGE_STATE["CONNECTING"]
            # self.transport.write(b"\x05" + status_code)
            await self.handle_connect()

        if status_code == 2:
            username = str.encode(user)
            password = str.encode(passw)
            lenusername = str.encode(str(len(username)))
            lenpassword = str.encode(str(len(password)))
            response = b"\01" + lenusername + username + lenpassword + password

            await self.send_data(b'\x05' + response)

            await self.handle_authentication()

        else:
            raise UnsupportedMethodsError

    async def handle_connect(self):
        log.debug("handle_connect")
        data = self.data
        version, requestmode, _, addrtype = data[:4]
        if version != "\x05":
            raise VersionError
        # 只实现tcp stream connection
        if requestmode != "\x01":
            raise UnsupportedMethodsError

        host, post, index = utli.parseaddr(addrtype, data)
        # 加密发至远程
        endata = utli.decript_data(data[index:])
        await self.send_data(data[:index] + endata)
        remotedata = self.remoteread

        version, status, _, addrtype = remotedata[:4]
        host, post, index = utli.parseaddr(addrtype, remotedata)
        # 解密发至本地
        deremotedata = utli.decript_data(remotedata[index:])
        self.transport.write(remotedata[:index] + deremotedata)
        self.connection_state = STAGE_STATE["CONNECTING"]


if __name__ == '__main__':
    loop = asyncio.get_event_loop()
    server = loop.create_server(partial(Socks5InputProtocol, remote_address, remote_port), "localhost", 8091)
    loop.run_until_complete(server)
    log.info("start listening on {}:{}".format("localhost", 8091))
    loop.run_forever()
    loop.close()
