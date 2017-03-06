'''
Argus client script which attaches to the broker and sends
sniffed packets through a pipe to Wireshark.
'''

import threading
import time
import struct
import traceback
import binascii
import json
import subprocess
import os
import platform

import paho.mqtt.client

import ArgusVersion

#============================ helpers =========================================

def isLinux():
    return platform.system() == "Linux"

def isWindows():
    return platform.system() == "Windows"

def currentUtcTime():
    return time.strftime("%a, %d %b %Y %H:%M:%S UTC", time.gmtime())

def logCrash(threadName,err):
    output  = []
    output += ["============================================================="]
    output += [currentUtcTime()]
    output += [""]
    output += ["CRASH in Thread {0}!".format(threadName)]
    output += [""]
    output += ["=== exception type ==="]
    output += [str(type(err))]
    output += [""]
    output += ["=== traceback ==="]
    output += [traceback.format_exc()]
    output  = '\n'.join(output)

    print output

#============================ classes =========================================

class RxMqttThread(threading.Thread):
    '''
    Thread which subscribes to the MQTT broker and pushes
    received frames to he
    '''

    MQTT_BROKER_HOST    = 'argus.paris.inria.fr'
    MQTT_BROKER_PORT    = 1883
    MQTT_BROKER_TOPIC   = 'inria-paris/beamlogic'

    def __init__(self,txWiresharkThread):

        # store params
        self.txWiresharkThread    = txWiresharkThread

        # local variables
        self.mqtt = paho.mqtt.client.Client()
        self.mqtt.on_connect = self._mqtt_on_connect
        self.mqtt.on_message = self._mqtt_on_message

        # start the thread
        threading.Thread.__init__(self)
        self.name            = 'RxMqttThread'
        self.start()

    def run(self):
        try:
            self.mqtt.connect(host=self.MQTT_BROKER_HOST, port=1883, keepalive=60)
            self.mqtt.loop_forever() # handles reconnects
        except Exception as err:
            logCrash(self.name,err)

    #======================== public ==========================================

    #======================== private =========================================

    def _mqtt_on_connect(self,client,userdata,flags,rc):
        assert rc==0
        print("INFO: Connected to {0} MQTT broker".format(self.MQTT_BROKER_HOST))
        self.mqtt.subscribe('argus/{0}'.format(self.MQTT_BROKER_TOPIC))

    def _mqtt_on_message(self,client,userdata,msg):
        self.txWiresharkThread.publish(msg.payload)

class TxWiresharkThread(threading.Thread):
    '''
    Thread which publishes sniffed frames to Wireshark broker.
    '''

    if isWindows():
        PIPE_NAME_WIRESHARK = r'\\.\pipe\argus'
    elif isLinux():
        PIPE_NAME_WIRESHARK = r'/tmp/argus'

    def __init__(self):

        # local variables
        self.dataLock             = threading.Lock()
        self.reconnectToPipeEvent = threading.Event()
        self.reconnectToPipeEvent.clear()
        self.wiresharkConnected   = False

        # start the thread
        threading.Thread.__init__(self)
        self.name                 = 'TxWiresharkThread'
        self.start()

    def run(self):
        try:

            # create pipe
            if isWindows():
                self.pipe = win32pipe.CreateNamedPipe(
                    self.PIPE_NAME_WIRESHARK,
                    win32pipe.PIPE_ACCESS_OUTBOUND,
                    win32pipe.PIPE_TYPE_MESSAGE | win32pipe.PIPE_WAIT,
                    1, 65536, 65536,
                    300,
                    None,
                )
            elif isLinux():
                self.pipe = open(self.PIPE_NAME_WIRESHARK, 'wb')

            while True:

                try:
                    # connect to pipe (blocks until Wireshark appears)
                    if isWindows():
                        win32pipe.ConnectNamedPipe(self.pipe,None)
                    elif isLinux():
                        open(self.PIPE_NAME_WIRESHARK, 'wb')

                    # send PCAP global header to Wireshark
                    ghdr = self._createPcapGlobalHeader()
                    if isWindows():
                        win32file.WriteFile(self.pipe,ghdr)
                    elif isLinux():
                        self.pipe.write(ghdr)
                except:
                    continue
                else:
                    print 'INFO: Wireshark connected'
                    with self.dataLock:
                        self.wiresharkConnected = True

                    # wait until need to reconnect
                    self.reconnectToPipeEvent.wait()
                    self.reconnectToPipeEvent.clear()
                finally:
                    print 'INFO: Wireshark disconnected'
                    with self.dataLock:
                        self.wiresharkConnected = False

                    # disconnect from pipe
                    if isWindows():
                        win32pipe.DisconnectNamedPipe(self.pipe)
                    elif isLinux():
                        self.pipe.close()
        except Exception as err:
            logCrash(self.name,err)

    #======================== public ==========================================

    def publish(self,msg):
        with self.dataLock:
            if not self.wiresharkConnected:
                # no Wireshark listening, dropping.
                return

        zep      = binascii.unhexlify(json.loads(msg)['bytes'])
        udp      = ''.join(
            [
                chr(b) for b in [
                    0x00,0x00,              # source port
                    0x45,0x5a,              # destination port
                    0x00,8+len(zep),        # length
                    0xbc,0x04,              # checksum
                ]
            ]
        )
        ipv6     = ''.join(
            [
                chr(b) for b in [
                    0x60,                   # version
                    0x00,0x00,0x00,         # traffic class
                    0x00,len(udp)+len(zep), # payload length
                    0x11,                   # next header (17==UDP)
                    0x08,                   # HLIM
                    0xbb,0xbb,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x01, # src
                    0xbb,0xbb,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x01, # dest
                ]
            ]
        )
        ethernet = ''.join([chr(b) for b in [
                    0x00,0x00,0x00,0x00,0x00,0x00,    # source
                    0x00,0x00,0x00,0x00,0x00,0x00,    # destination
                    0x86,0xdd,                        # type (IPv6)
                ]
            ]
        )

        frame    = ''.join([ethernet,ipv6,udp,zep])
        pcap     = self._createPcapPacketHeader(len(frame))

        try:
            if isWindows():
                win32file.WriteFile(self.pipe,pcap+frame)
            elif isLinux():
                self.pipe.write(pcap+frame)

        except:
            self.reconnectToPipeEvent.set()

    #======================== private =========================================

    def _createPcapGlobalHeader(self):
        '''
        Create a PCAP global header.

        Per https://wiki.wireshark.org/Development/LibpcapFileFormat:

        typedef struct pcap_hdr_s {
            guint32 magic_number;   /* magic number */
            guint16 version_major;  /* major version number */
            guint16 version_minor;  /* minor version number */
            gint32  thiszone;       /* GMT to local correction */
            guint32 sigfigs;        /* accuracy of timestamps */
            guint32 snaplen;        /* max length of captured packets, in octets */
            guint32 network;        /* data link type */
        } pcap_hdr_t;
        '''

        return struct.pack(
            '<IHHiIII',
            0xa1b2c3d4, # magic_number
            0x0002,     # version_major
            0x0004,     # version_minor
            0,          # thiszone
            0x00000000, # sigfigs
            0x0000ffff, # snaplen
            0x00000001, # network
        )

    def _createPcapPacketHeader(self,length):
        '''
        Create a PCAP global header.

        Per https://wiki.wireshark.org/Development/LibpcapFileFormat:

        typedef struct pcaprec_hdr_s {
            guint32 ts_sec;         /* timestamp seconds */
            guint32 ts_usec;        /* timestamp microseconds */
            guint32 incl_len;       /* number of octets of packet saved in file */
            guint32 orig_len;       /* actual length of packet */
        } pcaprec_hdr_t;
        '''

        return struct.pack(
            '<IIII',
            0x00000000, # ts_sec
            0x00000000, # ts_sec
            length,     # incl_len
            length,     # orig_len
        )

class CliThread(object):
    def __init__(self):
        try:
            print 'ArgusClient {0}.{1}.{2}.{3} - (c) OpenWSN project'.format(
                ArgusVersion.VERSION[0],
                ArgusVersion.VERSION[1],
                ArgusVersion.VERSION[2],
                ArgusVersion.VERSION[3],
            )

            while True:
                input = raw_input('> ')
                print input,
        except Exception as err:
            logCrash('CliThread',err)

#============================ main ============================================

def main():
    # OS dependent imports
    if isWindows():
        import win32pipe
        import win32file
    elif isLinux():
        import serial
    else:
        print("Sorry, we don't currently have support for the " + platform.system() + " OS")
        exit()

    try:
        # parse parameters

        # start Wireshark
        if isWindows():
            wireshark_cmd        = ['C:\Program Files\Wireshark\Wireshark.exe', r'-i\\.\pipe\argus','-k']
        elif isLinux():
            fifo_name = "/tmp/argus"
            if not os.path.exists(fifo_name):
                try:
                    os.mkfifo(fifo_name)
                except OSError, e:
                    print "Failed to create FIFO: {0}".format(e)
                    exit()
            wireshark_cmd        = ["wireshark", "-k", "-i", format(fifo_name)]

        proc                 = subprocess.Popen(wireshark_cmd)

        # start threads
        txWiresharkThread    = TxWiresharkThread()
        rxMqttThread         = RxMqttThread(txWiresharkThread)
        cliThread            = CliThread()
    except Exception as err:
        logCrash('main',err)

if __name__=="__main__":
    main()
