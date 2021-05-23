"""
Argus probe for the Beamlogic Site Analyzer Lite
http://www.beamlogic.com/products/802154-site-analyzer.aspx
"""

import Queue
import argparse
import datetime
import json
import struct
import sys
import threading
import time
import traceback
import abc
import paho.mqtt.publish
import paho.mqtt.client as mqtt
import serial

import ArgusVersion
import openhdlc
from pydispatch import dispatcher 
#============================ helpers =========================================


def currentUtcTime():
    return time.strftime("%a, %d %b %Y %H:%M:%S UTC", time.gmtime())

def logCrash(threadName, err):
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

class BeamLogic_RxSnifferThread(threading.Thread):
    """
    Thread which attaches to the sniffer and parses incoming frames.
    """

    PCAP_GLOBALHEADER_LEN    = 24 # 4+2+2+4+4+4+4
    PCAP_PACKETHEADER_LEN    = 16 # 4+4+4+4
    BEAMLOGIC_HEADER_LEN     = 20 # 1+8+1+1+4+4+1
    PIPE_SNIFFER             = r'\\.\pipe\analyzer'

    def __init__(self, txMqttThread):

        # store params
        self.txMqttThread             = txMqttThread

        # local variables
        self.dataLock                  = threading.Lock()
        self.rxBuffer                  = []
        self.doneReceivingGlobalHeader = False
        self.doneReceivingPacketHeader = False

        # start the thread
        threading.Thread.__init__(self)
        self.name            = 'BeamLogic_RxSnifferThread'
        self.start()

    def run(self):
        try:
            time.sleep(1)  # let the banners print
            while True:
                try:
                    with open(self.PIPE_SNIFFER, 'rb') as sniffer:
                        while True:
                            b = ord(sniffer.read(1))
                            self._newByte(b)
                except IOError:
                    print "WARNING: Could not read from pipe at \"{0}\".".format(
                        self.PIPE_SNIFFER
                    )
                    print "Is SiteAnalyzerAdapter running?"
                    time.sleep(1)
        except Exception as err:
            logCrash(self.name, err)

    #======================== public ==========================================

    #======================== private =========================================

    def _newByte(self, b):
        """
        Just received a byte from the sniffer
        """
        with self.dataLock:
            self.rxBuffer += [b]

            # PCAP global header
            if   not self.doneReceivingGlobalHeader:
                if len(self.rxBuffer) == self.PCAP_GLOBALHEADER_LEN:
                    self.doneReceivingGlobalHeader    = True
                    self.rxBuffer                     = []

            # PCAP packet header
            elif not self.doneReceivingPacketHeader:
                if len(self.rxBuffer) == self.PCAP_PACKETHEADER_LEN:
                    self.doneReceivingPacketHeader    = True
                    self.packetHeader                 = self._parsePcapPacketHeader(self.rxBuffer)
                    assert self.packetHeader['incl_len'] == self.packetHeader['orig_len']
                    self.rxBuffer                     = []

            # PCAP packet bytes
            else:
                if len(self.rxBuffer) == self.packetHeader['incl_len']:
                    self.doneReceivingPacketHeader    = False
                    self._newFrame(self.rxBuffer)
                    self.rxBuffer                     = []

    def _parsePcapPacketHeader(self, header):
        """
        Parse a PCAP packet header

        Per https://wiki.wireshark.org/Development/LibpcapFileFormat:

        typedef struct pcaprec_hdr_s {
            guint32 ts_sec;         /* timestamp seconds */
            guint32 ts_usec;        /* timestamp microseconds */
            guint32 incl_len;       /* number of octets of packet saved in file */
            guint32 orig_len;       /* actual length of packet */
        } pcaprec_hdr_t;
        """

        assert len(header) == self.PCAP_PACKETHEADER_LEN

        returnVal = {}
        (
            returnVal['ts_sec'],
            returnVal['ts_usec'],
            returnVal['incl_len'],
            returnVal['orig_len'],
        ) = struct.unpack('<IIII', ''.join([chr(b) for b in header]))

        return returnVal

    def _newFrame(self, frame):
        """
        Just received a full frame from the sniffer
        """

        # transform frame
        frame = self._transformFrame(frame)

        # publish frame
        self.txMqttThread.publishFrame(frame)

    def _transformFrame(self, frame):
        """
        Replace BeamLogic header by ZEP header.
        """

        beamlogic  = self._parseBeamlogicHeader(frame[:self.BEAMLOGIC_HEADER_LEN])
        ieee154    = frame[self.BEAMLOGIC_HEADER_LEN:beamlogic['Length']+self.BEAMLOGIC_HEADER_LEN]
        zep        = self._formatZep(
            channel         = beamlogic['Channel'],
            timestamp       = beamlogic['TimeStamp'],
            length          = beamlogic['Length'],
            rssi            = beamlogic['RSSI']
        )

        return zep+ieee154

    def _parseBeamlogicHeader(self, header):
        """
        Parse a Beamlogic header

        uint64    TimeStamp
        uint8     Channel
        uint8     RSSI
        uint32    GpsLat
        uint32    GpsLong
        """

        assert len(header) == self.BEAMLOGIC_HEADER_LEN

        returnVal = {}
        (
            returnVal['Reserved'],
            returnVal['TimeStamp'],
            returnVal['Channel'],
            returnVal['RSSI'],
            returnVal['GpsLat'],
            returnVal['GpsLong'],
            returnVal['Length'],
        ) = struct.unpack('<BQBBIIB', ''.join([chr(b) for b in header]))

        return returnVal

    def _formatZep(self, channel, timestamp, length, rssi):
        return [
            0x45, 0x58,     # Preamble
            0x02,           # Version
            0x01,           # Type (Data)
            channel,        # Channel ID
            0x00, 0x01,     # Device ID
            0x01,           # CRC/LQI Mode
            0xff,           # LQI Val
        ] + \
        [   # NTP Timestamp
            ord(b) for b in struct.pack('>Q', self._get_ntp_timestamp())
        ] + \
        [   # Sequence number
            0x02, 0x02, 0x02, 0x02] + \
        [   # Reserved Beam logic Timestamp (1/3 of us)
            ord(b) for b in struct.pack('>Q', timestamp)] + \
        [   # Reserved
            rssi,
            0x00
        ] + \
        [
            length,
        ]

    @staticmethod
    def _get_ntp_timestamp():
        diff = datetime.datetime.utcnow() - datetime.datetime(1900, 1, 1, 0, 0, 0)
        return diff.days * 24 * 60 * 60 + diff.seconds

class Serial_RxSnifferThread(threading.Thread):
    """
    Thread which attaches to the serial and put frames into queue.
    """
    # XOFF            is transmitted as [XONXOFF_ESCAPE, XOFF^XONXOFF_MASK]==[0x12,0x13^0x10]==[0x12,0x03]
    # XON             is transmitted as [XONXOFF_ESCAPE, XON^XONXOFF_MASK]==[0x12,0x11^0x10]==[0x12,0x01]
    # XONXOFF_ESCAPE  is transmitted as [XONXOFF_ESCAPE, XONXOFF_ESCAPE^XONXOFF_MASK]==[0x12,0x12^0x10]==[0x12,0x02]

    XOFF                    = 0x13
    XON                     = 0x11
    XONXOFF_ESCAPE          = 0x12
    XONXOFF_MASK            = 0x10

    FCS16TAB = (0x0000, 0x1021, 0x2042, 0x3063, 0x4084, 0x50a5, 0x60c6, 0x70e7,
    0x8108, 0x9129, 0xa14a, 0xb16b, 0xc18c, 0xd1ad, 0xe1ce, 0xf1ef,
    0x1231, 0x0210, 0x3273, 0x2252, 0x52b5, 0x4294, 0x72f7, 0x62d6,
    0x9339, 0x8318, 0xb37b, 0xa35a, 0xd3bd, 0xc39c, 0xf3ff, 0xe3de,
    0x2462, 0x3443, 0x0420, 0x1401, 0x64e6, 0x74c7, 0x44a4, 0x5485,
    0xa56a, 0xb54b, 0x8528, 0x9509, 0xe5ee, 0xf5cf, 0xc5ac, 0xd58d,
    0x3653, 0x2672, 0x1611, 0x0630, 0x76d7, 0x66f6, 0x5695, 0x46b4,
    0xb75b, 0xa77a, 0x9719, 0x8738, 0xf7df, 0xe7fe, 0xd79d, 0xc7bc,
    0x48c4, 0x58e5, 0x6886, 0x78a7, 0x0840, 0x1861, 0x2802, 0x3823,
    0xc9cc, 0xd9ed, 0xe98e, 0xf9af, 0x8948, 0x9969, 0xa90a, 0xb92b,
    0x5af5, 0x4ad4, 0x7ab7, 0x6a96, 0x1a71, 0x0a50, 0x3a33, 0x2a12,
    0xdbfd, 0xcbdc, 0xfbbf, 0xeb9e, 0x9b79, 0x8b58, 0xbb3b, 0xab1a,
    0x6ca6, 0x7c87, 0x4ce4, 0x5cc5, 0x2c22, 0x3c03, 0x0c60, 0x1c41,
    0xedae, 0xfd8f, 0xcdec, 0xddcd, 0xad2a, 0xbd0b, 0x8d68, 0x9d49,
    0x7e97, 0x6eb6, 0x5ed5, 0x4ef4, 0x3e13, 0x2e32, 0x1e51, 0x0e70,
    0xff9f, 0xefbe, 0xdfdd, 0xcffc, 0xbf1b, 0xaf3a, 0x9f59, 0x8f78,
    0x9188, 0x81a9, 0xb1ca, 0xa1eb, 0xd10c, 0xc12d, 0xf14e, 0xe16f,
    0x1080, 0x00a1, 0x30c2, 0x20e3, 0x5004, 0x4025, 0x7046, 0x6067,
    0x83b9, 0x9398, 0xa3fb, 0xb3da, 0xc33d, 0xd31c, 0xe37f, 0xf35e,
    0x02b1, 0x1290, 0x22f3, 0x32d2, 0x4235, 0x5214, 0x6277, 0x7256,
    0xb5ea, 0xa5cb, 0x95a8, 0x8589, 0xf56e, 0xe54f, 0xd52c, 0xc50d,
    0x34e2, 0x24c3, 0x14a0, 0x0481, 0x7466, 0x6447, 0x5424, 0x4405,
    0xa7db, 0xb7fa, 0x8799, 0x97b8, 0xe75f, 0xf77e, 0xc71d, 0xd73c,
    0x26d3, 0x36f2, 0x0691, 0x16b0, 0x6657, 0x7676, 0x4615, 0x5634,
    0xd94c, 0xc96d, 0xf90e, 0xe92f, 0x99c8, 0x89e9, 0xb98a, 0xa9ab,
    0x5844, 0x4865, 0x7806, 0x6827, 0x18c0, 0x08e1, 0x3882, 0x28a3,
    0xcb7d, 0xdb5c, 0xeb3f, 0xfb1e, 0x8bf9, 0x9bd8, 0xabbb, 0xbb9a,
    0x4a75, 0x5a54, 0x6a37, 0x7a16, 0x0af1, 0x1ad0, 0x2ab3, 0x3a92,
    0xfd2e, 0xed0f, 0xdd6c, 0xcd4d, 0xbdaa, 0xad8b, 0x9de8, 0x8dc9,
    0x7c26, 0x6c07, 0x5c64, 0x4c45, 0x3ca2, 0x2c83, 0x1ce0, 0x0cc1,
    0xef1f, 0xff3e, 0xcf5d, 0xdf7c, 0xaf9b, 0xbfba, 0x8fd9, 0x9ff8,
    0x6e17, 0x7e36, 0x4e55, 0x5e74, 0x2e93, 0x3eb2, 0x0ed1, 0x1ef0,
    )

    def __init__(self, txMqttThread, serialport,baudrate):

        # store params
        self.txMqttThread            = txMqttThread
        self.serialport              = serialport
        self.baudrate                = baudrate

        # local variables
        self.serialHandler           = None
        self.goOn                    = True

        # hdlc frame parser object
        self.hdlc                    = openhdlc.OpenHdlc()
        #frame parsing variables
        self.rxBuffer                = []
        self.hdlc_flag               = False
        self.receiving               = False
        self.xonxoff_escaping        = False

        self.HEADER_LENGTH           = 2

        # to be assigned, callback
        self.send_to_parser          = None

        # connect to dispatcher
        dispatcher.connect(self._send_data, signal='fromMoteConnector@' + self._portname)

        # initialize thread
        super(Serial_RxSnifferThread, self).__init__()
        self.name                    = 'Serial_RxSnifferThread@{0}'.format(self.serialport)
        self.start()

    def run(self):

        time.sleep(1)  # let the banners print
        while self.goOn:
            try:
                # open serial port
                self.serialHandler = serial.Serial(self.serialport, baudrate=self.baudrate)

                # read byte
                while True:
                    waitingbytes   = self.serialHandler.inWaiting()
                    if waitingbytes != 0:
                        c= self.serialHandler.read(waitingbytes)
                        for byte in c:
                            self._newByte(byte)
                    time.sleep(2)

            except serial.SerialException:
                # mote disconnected, or pyserialHandler closed
                # destroy pyserial instance
                print "WARNING: Could not read from serial at \"{0}\".".format(self.serialport)
                self.close()
                self.serialHandler   = None
                time.sleep(1)

            except Exception as err:
                logCrash(self.name, err)
                self.close()

    #======================== public ==========================================

    def close(self):
        print "Is device connected?"
        self.goOn            = False

    #======================== public ==========================================

    #======================== private =========================================
    def _rx_buf_add(self, byte):
        """ Adds byte to buffer and escapes the XONXOFF bytes """

        if byte == chr(self.XONXOFF_ESCAPE):
            self.xonxoff_escaping = True
        else:
            if self.xonxoff_escaping is True:
                self.rxBuffer.append(chr(ord(byte) ^ self.XONXOFF_MASK))
                self.xonxoff_escaping = False
            elif byte != chr(self.XON) and byte != chr(self.XOFF):
                self.rxBuffer.append(byte)

    def _handle_frame(self):
        """ Handles a HDLC frame """
        valid_frame = False
        try:
            self.rxBuffer  = self.hdlc.dehdlcify(self.rxBuffer)

            if self.send_to_parser:
                self.send_to_parser([ord(c) for c in self.rxBuffer])

            if self.rxBuffer[0] == 'P':   #packet from sniffer SERFRAME_MOTE2PC_SNIFFED_PACKET 'P'
                self.rxBuffer = self.rxBuffer[1:] #removing the indicator byte from the packet
                valid_frame   = True

        except openhdlc.HdlcException as err:
            print '{}: Invalid serial frame: {}'.format(self.name,self.rxBuffer)
        return valid_frame

    def parse_input(self, data):

        # ensure data not short longer than header
        if len(data) < self.HEADER_LENGTH:
            raise 'Error packet length'

        _ = data[:2]  # header bytes

        # remove mote id at the beginning.
        data = data[2:]

        return data

    def _newByte(self, b):
        """
        Parses bytes received from serial pipe
        """
        if not self.receiving:
                if self.hdlc_flag and b != self.hdlc.HDLC_FLAG:
                    # start of frame
                    self.receiving        = True
                    # discard received self.hdlc_flag
                    self.hdlc_flag        = False
                    self.xonxoff_escaping = False
                    self.rxBuffer.append(self.hdlc.HDLC_FLAG)
                    self._rx_buf_add(b)
                elif b  == self.hdlc.HDLC_FLAG:
                    # received hdlc flag
                    self.rxBuffer         = [] # Start of the frame, reset
                    self.hdlc_flag        = True
                else:
                    # drop garbage
                    pass
        else:
                if b != self.hdlc.HDLC_FLAG:
                    # middle of frame
                    self._rx_buf_add(b)
                else:
                    # end of frame, received self.hdlc_flag
                    self.hdlc_flag = True
                    self.receiving = False
                    self._rx_buf_add(b)
                    valid_frame    = self._handle_frame()

                    if valid_frame:
                        # discard valid frame self.hdlc_flag
                        self.hdlc_flag  = False
                        self._newFrame(self.rxBuffer)

    def _newFrame(self, frame):
        """
        Just received a full frame from the sniffer
        """
        #Parse incomming frame
        frame = self.parse_input(frame)

        # transform frame
        frame = self._transformFrame(frame)
        # publish frame
        self.txMqttThread.publishFrame(frame)

    def _transformFrame(self, frame):
        """
        Add ZEP header
        """
        body      = frame[0:-3]
        _         = frame[-3:-1]  # crc
        frequency = frame[-1]

        zep   = self._formatZep(body,frequency)
        return zep

    def _formatZep (self, body, frequency):
        # ZEP header
        zep  = [ord('E'), ord('X')]  # Protocol ID String
        zep += [0x02]  # Protocol Version
        zep += [0x01]  # Type
        zep += [ord(frequency)]  # Channel ID int?
        zep += [0x00, 0x01]  # Device ID
        zep += [0x01]  # LQI/CRC mode
        zep += [0xff]
        zep += [0x01] * 8  # timestamp
        zep += [0x02] * 4  # sequence number
        zep += [0x00] * 10  # reserved
        zep += [len(body) + 2]  # length

        # mac frame
        mac  = [ord(i) for i in body]
        mac += self.calculate_fcs(mac)
        return zep + mac

    def calculate_fcs(self,rpayload):
        payload = []
        for b in rpayload:
            payload += [self.byteinverse(b)]
        crc = 0x0000
        for b in payload:
            crc = ((crc << 8) & 0xffff) ^ self.FCS16TAB[((crc >> 8) ^ b) & 0xff]
        return_val = [
            self.byteinverse(crc >> 8),
            self.byteinverse(crc & 0xff),
        ]
        return return_val

    def byteinverse(self,b):
    # TODO: speed up through lookup table

        rb = 0
        for pos in range(8):
            if b & (1 << pos) != 0: #check this out
                bitval = 1
            else:
                bitval = 0
            rb |= bitval << (7 - pos)
        return rb


class MoteProbeNoData(Exception):
    """ No data received from serial pipe """
    pass

class OpenTestBed_RxSnifferThread(threading.Thread):
    """
    Thread which attaches to the OpenTestBed and put frames into queue.
    """

    XOFF                    = 0x13
    XON                     = 0x11
    XONXOFF_ESCAPE          = 0x12
    XONXOFF_MASK            = 0x10

    FCS16TAB = (0x0000, 0x1021, 0x2042, 0x3063, 0x4084, 0x50a5, 0x60c6, 0x70e7,
    0x8108, 0x9129, 0xa14a, 0xb16b, 0xc18c, 0xd1ad, 0xe1ce, 0xf1ef,
    0x1231, 0x0210, 0x3273, 0x2252, 0x52b5, 0x4294, 0x72f7, 0x62d6,
    0x9339, 0x8318, 0xb37b, 0xa35a, 0xd3bd, 0xc39c, 0xf3ff, 0xe3de,
    0x2462, 0x3443, 0x0420, 0x1401, 0x64e6, 0x74c7, 0x44a4, 0x5485,
    0xa56a, 0xb54b, 0x8528, 0x9509, 0xe5ee, 0xf5cf, 0xc5ac, 0xd58d,
    0x3653, 0x2672, 0x1611, 0x0630, 0x76d7, 0x66f6, 0x5695, 0x46b4,
    0xb75b, 0xa77a, 0x9719, 0x8738, 0xf7df, 0xe7fe, 0xd79d, 0xc7bc,
    0x48c4, 0x58e5, 0x6886, 0x78a7, 0x0840, 0x1861, 0x2802, 0x3823,
    0xc9cc, 0xd9ed, 0xe98e, 0xf9af, 0x8948, 0x9969, 0xa90a, 0xb92b,
    0x5af5, 0x4ad4, 0x7ab7, 0x6a96, 0x1a71, 0x0a50, 0x3a33, 0x2a12,
    0xdbfd, 0xcbdc, 0xfbbf, 0xeb9e, 0x9b79, 0x8b58, 0xbb3b, 0xab1a,
    0x6ca6, 0x7c87, 0x4ce4, 0x5cc5, 0x2c22, 0x3c03, 0x0c60, 0x1c41,
    0xedae, 0xfd8f, 0xcdec, 0xddcd, 0xad2a, 0xbd0b, 0x8d68, 0x9d49,
    0x7e97, 0x6eb6, 0x5ed5, 0x4ef4, 0x3e13, 0x2e32, 0x1e51, 0x0e70,
    0xff9f, 0xefbe, 0xdfdd, 0xcffc, 0xbf1b, 0xaf3a, 0x9f59, 0x8f78,
    0x9188, 0x81a9, 0xb1ca, 0xa1eb, 0xd10c, 0xc12d, 0xf14e, 0xe16f,
    0x1080, 0x00a1, 0x30c2, 0x20e3, 0x5004, 0x4025, 0x7046, 0x6067,
    0x83b9, 0x9398, 0xa3fb, 0xb3da, 0xc33d, 0xd31c, 0xe37f, 0xf35e,
    0x02b1, 0x1290, 0x22f3, 0x32d2, 0x4235, 0x5214, 0x6277, 0x7256,
    0xb5ea, 0xa5cb, 0x95a8, 0x8589, 0xf56e, 0xe54f, 0xd52c, 0xc50d,
    0x34e2, 0x24c3, 0x14a0, 0x0481, 0x7466, 0x6447, 0x5424, 0x4405,
    0xa7db, 0xb7fa, 0x8799, 0x97b8, 0xe75f, 0xf77e, 0xc71d, 0xd73c,
    0x26d3, 0x36f2, 0x0691, 0x16b0, 0x6657, 0x7676, 0x4615, 0x5634,
    0xd94c, 0xc96d, 0xf90e, 0xe92f, 0x99c8, 0x89e9, 0xb98a, 0xa9ab,
    0x5844, 0x4865, 0x7806, 0x6827, 0x18c0, 0x08e1, 0x3882, 0x28a3,
    0xcb7d, 0xdb5c, 0xeb3f, 0xfb1e, 0x8bf9, 0x9bd8, 0xabbb, 0xbb9a,
    0x4a75, 0x5a54, 0x6a37, 0x7a16, 0x0af1, 0x1ad0, 0x2ab3, 0x3a92,
    0xfd2e, 0xed0f, 0xdd6c, 0xcd4d, 0xbdaa, 0xad8b, 0x9de8, 0x8dc9,
    0x7c26, 0x6c07, 0x5c64, 0x4c45, 0x3ca2, 0x2c83, 0x1ce0, 0x0cc1,
    0xef1f, 0xff3e, 0xcf5d, 0xdf7c, 0xaf9b, 0xbfba, 0x8fd9, 0x9ff8,
    0x6e17, 0x7e36, 0x4e55, 0x5e74, 0x2e93, 0x3eb2, 0x0ed1, 0x1ef0,
    )
    def __init__(self, txMqttThread,portname):
        __metaclass__ = abc.ABCMeta
        # store params
        self.txMqttThread            = txMqttThread
        self._portname = portname
        # local variables
        self.goOn                    = True

        # hdlc frame parser object
        self.hdlc                    = openhdlc.OpenHdlc()
        #frame parsing variables
        self.rxBuffer                = []
        self.hdlc_flag               = False
        self.receiving               = False
        self.xonxoff_escaping        = False

        self.HEADER_LENGTH           = 2

        # to be assigned, callback
        self.send_to_parser          = None

        # initialize thread
        super(OpenTestBed_RxSnifferThread, self).__init__()
        self.name                    = 'OpenTestBed_RxSnifferThread@{0}'.format(self._portname)
        self.start()

    def run(self):

        time.sleep(1)  # let the banners print
        try:
            self._attach()
            while self.goOn:
                try:
                    rx_bytes = self._rcv_data()
                except MoteProbeNoData:
                    continue
                except Exception as err:
                    logCrash(self.name, err)
                    time.sleep(1)
                    self.close()
                else:
                    #parse incoming bytes
                    self.parse_bytes(rx_bytes)
                    #time.sleep(2)
        except Exception as err:
            logCrash(self.name, err)
            self.close()

    #======================== public ==========================================
    def close(self):
        print "Is device connected?"
        self.goOn            = False

    #======================== private =========================================
    @abc.abstractmethod
    def _rcv_data(self):
        raise NotImplementedError("Should be implemented by child class")

    def _rx_buf_add(self, byte):
        """ Adds byte to buffer and escapes the XONXOFF bytes """

        if byte == chr(self.XONXOFF_ESCAPE):
            self.xonxoff_escaping = True
        else:
            if self.xonxoff_escaping is True:
                self.rxBuffer.append(chr(ord(byte) ^ self.XONXOFF_MASK))
                self.xonxoff_escaping = False
            elif byte != chr(self.XON) and byte != chr(self.XOFF):
                self.rxBuffer.append(byte)

    def _handle_frame(self):
        """ Handles a HDLC frame """
        valid_frame = False
        try:
            self.rxBuffer  = self.hdlc.dehdlcify(self.rxBuffer)

            if self.send_to_parser:
                self.send_to_parser([ord(c) for c in self.rxBuffer])

            if self.rxBuffer[0] == 'P':   #packet from sniffer SERFRAME_MOTE2PC_SNIFFED_PACKET 'P'
                self.rxBuffer = self.rxBuffer[1:] #removing the indicator byte from the packet
                valid_frame   = True

        except openhdlc.HdlcException as err:
            print '{}: Invalid serial frame: {}'.format(self.name,self.rxBuffer)
        return valid_frame

    def parse_input(self, data):

        # ensure data not short longer than header
        if len(data) < self.HEADER_LENGTH:
            raise 'Error packet length'

        _ = data[:2]  # header bytes

        # remove mote id at the beginning.
        data = data[2:]

        return data

    def parse_bytes(self, octets):
        """
        Parses bytes received from serial pipe
        """
        for b in octets:
            if not self.receiving:
                    if self.hdlc_flag and b != self.hdlc.HDLC_FLAG:
                        # start of frame
                        self.receiving        = True
                        # discard received self.hdlc_flag
                        self.hdlc_flag        = False
                        self.xonxoff_escaping = False
                        self.rxBuffer.append(self.hdlc.HDLC_FLAG)
                        self._rx_buf_add(b)
                    elif b  == self.hdlc.HDLC_FLAG:
                        # received hdlc flag
                        self.rxBuffer         = [] # Start of the frame, reset
                        self.hdlc_flag        = True
                    else:
                        # drop garbage
                        pass
            else:
                    if b != self.hdlc.HDLC_FLAG:
                        # middle of frame
                        self._rx_buf_add(b)
                    else:
                        # end of frame, received self.hdlc_flag
                        self.hdlc_flag = True
                        self.receiving = False
                        self._rx_buf_add(b)
                        valid_frame    = self._handle_frame()

                        if valid_frame:
                            # discard valid frame self.hdlc_flag
                            self.hdlc_flag  = False
                            self._newFrame(self.rxBuffer)

    def _newFrame(self, frame):
        """
        Just received a full frame from the sniffer
        """
        #Parse incomming frame
        frame = self.parse_input(frame)
        # transform frame
        frame = self._transformFrame(frame)
        # publish frame
        self.txMqttThread.publishFrame(frame)

    def _transformFrame(self, frame):
        """
        Add ZEP header
        """
        body      = frame[0:-3]
        _         = frame[-3:-1]  # crc
        frequency = frame[-1]

        zep   = self._formatZep(body,frequency)
        #frame = self._dispatch_mesh_debug_packet(zep)
        return zep

    def _formatZep (self, body, frequency):
        # ZEP header
        zep  = [ord('E'), ord('X')]  # Protocol ID String
        zep += [0x02]  # Protocol Version
        zep += [0x01]  # Type
        zep += [ord(frequency)]  # Channel ID #?? Mislim da treba da bude u ovom obliku
        zep += [0x00, 0x01]  # Device ID
        zep += [0x01]  # LQI/CRC mode
        zep += [0xff]
        zep += [0x01] * 8  # timestamp
        zep += [0x02] * 4  # sequence number
        zep += [0x00] * 10  # reserved
        zep += [len(body) + 2]  # length

        # mac frame
        mac  = [ord(i) for i in body]
        mac += self.calculate_fcs(mac)
        return zep + mac

    def calculate_fcs(self,rpayload):
        payload = []
        for b in rpayload:
            payload += [self.byteinverse(b)]
        crc = 0x0000
        for b in payload:
            crc = ((crc << 8) & 0xffff) ^ self.FCS16TAB[((crc >> 8) ^ b) & 0xff]
        return_val = [
            self.byteinverse(crc >> 8),
            self.byteinverse(crc & 0xff),
        ]
        return return_val

    def byteinverse(self,b):
    # TODO: speed up through lookup table

        rb = 0
        for pos in range(8):
            if b & (1 << pos) != 0: #check this out
                bitval = 1
            else:
                bitval = 0
            rb |= bitval << (7 - pos)
        return rb

### child class
class OpentestbedMoteProbe (OpenTestBed_RxSnifferThread):
     BASE_TOPIC = 'opentestbed/deviceType/mote/deviceId'

     def __init__(self,txMqttThread, mqtt_broker, testbedmote_eui64):

        self.mqtt_broker       = mqtt_broker
        self.testbedmote_eui64 = testbedmote_eui64

        # mqtt client
        self.mqtt_client = mqtt.Client()
        self.mqtt_client.on_connect = self._on_mqtt_connect
        self.mqtt_client.on_message = self._on_mqtt_message
        self.mqtt_client.connect(self.mqtt_broker)

        name = 'opentestbed_{0}'.format(testbedmote_eui64)
        # initialize the parent class
        OpenTestBed_RxSnifferThread.__init__(self,txMqttThread, portname=name)

     # ======================== private =================================
     def _rcv_data(self):
        rx_bytes = self.mqtt_serial_queue.get()
        return [chr(i) for i in rx_bytes]

     def _attach(self):
        # create queue for receiving serialbytes messages
        self.serialbytes_queue = Queue.Queue(maxsize=100)
        self.mqtt_client.loop_start()
        self.mqtt_serial_queue = self.serialbytes_queue

     # ==== mqtt callback functions =====================================

     def _on_mqtt_connect(self, client, userdata, flags, rc):
        client.subscribe('{}/{}/notif/frommoteserialbytes'.format(self.BASE_TOPIC, self.testbedmote_eui64))

     def _on_mqtt_message(self, client, userdata, message):
        try:
            serial_bytes = json.loads(message.payload)['serialbytes']
        except json.JSONDecodeError:
            print("failed to parse message payload {}".format(message.payload))
        else:
            try:
                self.serialbytes_queue.put(serial_bytes, block=False)
            except Queue.Full:
                print("queue overflow/full")

class TxMqttThread(threading.Thread):
    """
    Thread which publishes sniffed frames to the MQTT broker.
    """

    MQTT_BROKER_HOST    = 'argus.paris.inria.fr'
    MQTT_BROKER_PORT    = 1883
    MQTT_BROKER_TOPIC   = 'inria-paris/beamlogic'

    def __init__(self):

        # local variables
        self.txQueue         = Queue.Queue(maxsize=100)

        # start the thread
        threading.Thread.__init__(self)
        self.name            = 'TxMqttThread'
        self.start()

    def run(self):
        try:
            while True:
                # wait for first frame
                msgs = [self.txQueue.get(), ]

                # get other frames (if any)
                try:
                    while True:
                        msgs += [self.txQueue.get(block=False)]
                except Queue.Empty:
                    pass

                # add topic
                msgs = [
                    {
                        'topic':       'argus/{0}'.format(self.MQTT_BROKER_TOPIC),
                        'payload':     m,
                    } for m in msgs
                ]

                # publish
                try:
                    paho.mqtt.publish.multiple(
                        msgs,
                        hostname     = self.MQTT_BROKER_HOST,
                        port         = self.MQTT_BROKER_PORT,
                    )
                except Exception as err:
                    print "WARNING publication to {0}:{1} over MQTT failed ({2})".format(
                        self.MQTT_BROKER_HOST,
                        self.MQTT_BROKER_PORT,
                        str(type(err)),
                    )

        except Exception as err:
            logCrash(self.name, err)

    #======================== public ==========================================

    def publishFrame(self, frame):
        msg = {
            'description':   'zep',
            'device':        'Beamlogic',
            'bytes':         ''.join(['{0:02x}'.format(b) for b in frame]),
        }
        try:
            self.txQueue.put(json.dumps(msg), block=False)
        except Queue.Full:
            print "WARNING transmit queue to MQTT broker full. Dropping frame."

    #======================== private =========================================


class CliThread(object):
    def __init__(self):
        try:
            print 'ArgusProbe (for BeamLogic sniffer) {0}.{1}.{2}.{3} - (c) OpenWSN project'.format(
                ArgusVersion.VERSION[0],
                ArgusVersion.VERSION[1],
                ArgusVersion.VERSION[2],
                ArgusVersion.VERSION[3],
            )

            while True:
                user_input = raw_input('>')
                print user_input,
        except Exception as err:
            logCrash('CliThread', err)

#============================ main ============================================

def main():
    parser = argparse.ArgumentParser() #creating an ArgumentParser object
    parser.add_argument("--probetype", nargs="?", default="beamlogic", choices=["beamlogic", "serial","opentestbed"])
    parser.add_argument("--serialport", help= 'Input the serial port for the Serial probe type')
    parser.add_argument("--baudrate",  default= 115200)
    parser.add_argument("--mqtt_broker", default='argus.paris.inria.fr')
    parser.add_argument("--testbedmote")
    args = parser.parse_args()

    # start thread
    txMqttThread         = TxMqttThread()
    if args.probetype   == "beamlogic":
        beamlogic_rxSnifferThread = BeamLogic_RxSnifferThread(txMqttThread)
    elif args.probetype == "serial":
        serial_rxSnifferThread    = Serial_RxSnifferThread(txMqttThread,args.serialport,args.baudrate)
    elif args.probetype == "opentestbed":
        testbed_rxSnifferThread   = OpentestbedMoteProbe(txMqttThread,args.mqtt_broker,args.testbedmote)

    else:
        print('This probe type is not supported!')
        sys.exit()

    cliThread            = CliThread()

if __name__ == "__main__":
    main()
