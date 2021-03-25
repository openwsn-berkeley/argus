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

import paho.mqtt.publish
import serial

import ArgusVersion
import openhdlc


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

    XOFF                    = 0x13
    XON                     = 0x11
    XONXOFF_ESCAPE          = 0x12
    XONXOFF_MASK            = 0x10

    # XOFF            is transmitted as [XONXOFF_ESCAPE,           XOFF^XONXOFF_MASK]==[0x12,0x13^0x10]==[0x12,0x03]
    # XON             is transmitted as [XONXOFF_ESCAPE,            XON^XONXOFF_MASK]==[0x12,0x11^0x10]==[0x12,0x01]
    # XONXOFF_ESCAPE  is transmitted as [XONXOFF_ESCAPE, XONXOFF_ESCAPE^XONXOFF_MASK]==[0x12,0x12^0x10]==[0x12,0x02]

    def __init__(self, txMqttThread, serialport,baudrate):

        # store params
        self.txMqttThread            = txMqttThread
        self.serialport              = serialport
        self.baudrate                = baudrate

        # local variables
        self.serialHandler           = None
        self.goOn                    = True
        self.pleaseConnect           = True
        self.dataLock                = threading.RLock()

        # hdlc frame parser object
        self.hdlc                    = openhdlc.OpenHdlc()
        #frame parsing variables
        self.rxBuffer                = ''
        self.hdlc_flag               = False
        self.receiving               = False
        self.xonxoff_escaping        = False


        # to be assigned, callback
        self.send_to_parser          = None

        # initialize thread
        super(Serial_RxSnifferThread, self).__init__()
        self.name                    = 'Serial_RxSnifferThread@{0}'.format(self.serialport)
        self.start()

    def run(self):

        time.sleep(1)  # let the banners print
        while self.goOn:
            try:
                with self.dataLock:
                    pleaseConnect = self.pleaseConnect

                if pleaseConnect:
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
                print "WARNING: Could not read from serial at \"{0}\".".format(
                       self.serialport)
                print "Is device connected?"
                self.goOn            = False
                self.serialHandler   = None
                time.sleep(1)

            except Exception as err:
                logCrash(self.name, err)

    #======================== public ==========================================

    def connectSerialPort(self):
        with self.dataLock:
            self.pleaseConnect = True

    def disconnectSerialPort(self):
        with self.dataLock:
            self.pleaseConnect = False
        try:
            self.serialHandler.close()
        except:
            pass

    def close(self):
        self.goOn            = False
    #======================== public ==========================================

    #======================== private =========================================
    def _rx_buf_add(self, byte):
        """ Adds byte to buffer and escapes the XONXOFF bytes """

        if byte == chr(self.XONXOFF_ESCAPE):
            self.xonxoff_escaping = True
        else:
            if self.xonxoff_escaping is True:
                self.rxBuffer += chr(ord(byte) ^ self.XONXOFF_MASK)
                self.xonxoff_escaping = False
            elif byte != chr(self.XON) and byte != chr(self.XOFF):
                self.rxBuffer += byte

    def _handle_frame(self):
        """ Handles a HDLC frame """
        valid_frame = False
        try:
            self.rxBuffer  = self.hdlc.dehdlcify(self.rxBuffer)

            if self.send_to_parser:
                self.send_to_parser([ord(c) for c in self.rxBuffer])
            if self.rxBuffer[0] == 'P':   #packet from sniffer SERFRAME_MOTE2PC_SNIFFED_PACKET 'P'
                valid_frame = True

        except openhdlc.HdlcException as err:
            #log.warning('{}: invalid serial frame: {} {}'.format(self.name, format_string_buf(temp_buf), err))
            print 'Err'
        return valid_frame

    def _newByte(self, b):
        """
        Parses bytes received from serial pipe
        """
        if not self.receiving:
                if self.hdlc_flag and b != self.hdlc.HDLC_FLAG:
                    # start of frame
                    #print ('Start of HDLC frame..')
                    self.receiving        = True
                    # discard received self.hdlc_flag
                    self.hdlc_flag        = False
                    self.xonxoff_escaping = False
                    self.rxBuffer         = self.hdlc.HDLC_FLAG
                    self._rx_buf_add(b)
                elif b  == self.hdlc.HDLC_FLAG:
                    # received hdlc flag
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
                    #print ("End of HDLC frame ..")
                    self.hdlc_flag = True
                    self.receiving = False
                    self._rx_buf_add(b)
                    valid_frame    = self._handle_frame()

                    if valid_frame:
                        # discard valid frame self.hdlc_flag
                        self.hdlc_flag  = False
                        self._newFrame(self.rxBuffer)
                        self.rxBuffer           = []

    def _newFrame(self, frame):
        """
        Just received a full frame from the sniffer
        """
        # publish frame
        #self.txMqttThread.publishFrame(frame)
        pass


#########################################################################################
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
    args = parser.parse_args()

    # start thread
    txMqttThread         = TxMqttThread()
    if args.probetype   == "beamlogic":
        beamlogic_rxSnifferThread = BeamLogic_RxSnifferThread(txMqttThread)
    elif args.probetype == "serial":
        serial_rxSnifferThread    = Serial_RxSnifferThread(txMqttThread,args.serialport,args.baudrate)
    elif args.probetype == "opentestbed":
        pass
    else:
        print('This probe type is not supported!')
        sys.exit()

    cliThread            = CliThread()

if __name__ == "__main__":
    main()
