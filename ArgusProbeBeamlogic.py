'''
Argus probe for the Beamlogic Site Analyzer Lite
http://www.beamlogic.com/products/802154-site-analyzer.aspx
'''

import time
import struct
import socket
import threading

import ArgusVersion

class AppData(object):
    pass

class PublishThread(threading.Thread):
    '''
    Thread which publishes sniffed frames to the broker.
    '''
    
    ZEP_UDP_PORT = 17754
    
    def __init__(self):
        self.sock = socket.socket(
            socket.AF_INET,       # IPv4
            socket.SOCK_DGRAM,    # UDP
        )
        '''
        RMQ_EXCHANGE = "beamlogic_sniffer"
        RMQ_ROUTING_KEY = "packet"
        RMQ_HOST = "localhost"

        # In case it complains, you can use
        #subprocess.call(["sudo", "rmmod", "ftdi_sio", "usbserial", "pl2303"])
        proc = subprocess.Popen(['./adaptor', '-i', '4'],
                                stdout=subprocess.PIPE)

        connection = pika.BlockingConnection(pika.ConnectionParameters(host=RMQ_HOST))
        channel = connection.channel()

        channel.exchange_declare(exchange=RMQ_EXCHANGE, type='topic')

        while True:
          line = proc.stdout.readline()
          if line != '':
            #the real code does filtering here
            message =  line.rstrip()
            channel.basic_publish(exchange=RMQ_EXCHANGE,
                                  routing_key=RMQ_ROUTING_KEY,
                                  body=message)
          else:
            break
        '''
    
    #======================== public ==========================================
    
    def publishFrame(self,frame):
        self.sock.sendto(''.join([chr(b) for b in frame]), ('8.8.8.8', self.ZEP_UDP_PORT))
        #raise NotImplementedError()
    
    #======================== private =========================================
    

class SnifferThread(threading.Thread):
    '''
    Thread which attaches to the sniffer and parses incoming frames.
    '''
    
    PCAP_GLOBALHEADER_LEN    = 24 # 4+2+2+4+4+4+4
    PCAP_PACKETHEADER_LEN    = 16 # 4+4+4+4
    BEAMLOGIC_HEADER_LEN     = 18 # 8+1+1+4+4
    PIPE_SNIFFER             = r'\\.\pipe\analyzer'
    
    def __init__(self,publishThread):
        
        # store params
        self.publishThread             = publishThread
        
        # local variables
        self.dataLock                  = threading.Lock()
        self.rxBuffer                  = []
        self.doneReceivingGlobalHeader = False
        self.doneReceivingPacketHeader = False
        
        # start the thread
        threading.Thread.__init__(self)
        self.name            = 'SnifferThread'
        self.start()
    
    def run(self):
        time.sleep(1) # let the banners print
        while True:
            try:
                with open(self.PIPE_SNIFFER, 'rb') as sniffer:
                    while True:
                        b = ord(sniffer.read(1))
                        self._newByte(b)
            except (IOError):
                print "WARNING: Could not read from pipe at \"{0}\".".format(
                    self.PIPE_SNIFFER
                )
                print "Is SiteAnalyzerAdapter running?"
                time.sleep(1)
    
    #======================== public ==========================================
    
    #======================== private =========================================
    
    def _newByte(self,b):
        '''
        Just received a byte from the sniffer
        '''
        with self.dataLock:
            self.rxBuffer += [b]
            
            # global header
            if   not self.doneReceivingGlobalHeader:
                if len(self.rxBuffer)==self.PCAP_GLOBALHEADER_LEN:
                    self.doneReceivingGlobalHeader    = True
                    self.rxBuffer                     = []
            
            # packet header
            elif not self.doneReceivingPacketHeader:
                if len(self.rxBuffer)==self.PCAP_PACKETHEADER_LEN:
                    self.doneReceivingPacketHeader    = True
                    self.packetHeader                 = self._parsePcapPacketHeader(self.rxBuffer)
                    assert self.packetHeader['incl_len']==self.packetHeader['orig_len']
                    self.rxBuffer                     = []
            
            # packet data
            else:
                if len(self.rxBuffer)==self.packetHeader['incl_len']:
                    self.doneReceivingPacketHeader    = False
                    self._newFrame(self.rxBuffer)
                    self.rxBuffer                     = []
    
    def _parsePcapPacketHeader(self,header):
        '''
        Parse a PCAP packet header
        
        Per https://wiki.wireshark.org/Development/LibpcapFileFormat:
        
        typedef struct pcaprec_hdr_s {
            guint32 ts_sec;         /* timestamp seconds */
            guint32 ts_usec;        /* timestamp microseconds */
            guint32 incl_len;       /* number of octets of packet saved in file */
            guint32 orig_len;       /* actual length of packet */
        } pcaprec_hdr_t;
        '''
        
        assert len(header)==self.PCAP_PACKETHEADER_LEN
        
        returnVal = {}
        (
            returnVal['ts_sec'],
            returnVal['ts_usec'],
            returnVal['incl_len'],
            returnVal['orig_len'],
        ) = struct.unpack('<IIII', ''.join([chr(b) for b in header]))
        
        return returnVal
    
    def _newFrame(self,frame):
        '''
        Just received a full frame from the sniffer
        '''
        
        # transform frame
        frame = self._transformFrame(frame)
        
        # publish frame
        self.publishThread.publishFrame(frame)
    
    def _transformFrame(self,frame):
        '''
        Replace BeamLogic header by ZEP header.
        '''
        
        beamlogic  = self._parseBeamlogicHeader(frame[1:1+self.BEAMLOGIC_HEADER_LEN])
        ieee154    = frame[self.BEAMLOGIC_HEADER_LEN+2:]
        ieee154[0] = ieee154[0] | 0x40 # fixing PAN ID compression bit (temporary)
        zep        = self._formatZep(
            channel     = beamlogic['Channel'],
            timestamp   = beamlogic['TimeStamp'],
            length      = len(ieee154),
        )
        
        return zep+ieee154
    
    def _parseBeamlogicHeader(self,header):
        '''
        Parse a Beamlogic packet header
        
        uint64    TimeStamp
        uint8     Channel
        uint8     RSSI
        uint32    GpsLat
        uint32    GpsLong
        '''
        
        assert len(header)==self.BEAMLOGIC_HEADER_LEN
        
        returnVal = {}
        (
            returnVal['TimeStamp'],
            returnVal['Channel'],
            returnVal['RSSI'],
            returnVal['GpsLat'],
            returnVal['GpsLong'],
        ) = struct.unpack('<QBBII', ''.join([chr(b) for b in header]))
        
        return returnVal
    
    def _formatZep(self,channel,timestamp,length):
        return [
            0x45,0x58,
            0x02,
            0x01,
            channel,
            0x00,0x01,
            0x01,
            0xff,
        ]+ \
        [ord(b) for b in struct.pack('>Q',timestamp)]+ \
        [
            0x02,0x02,0x02,0x02,
            0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
            length,
        ]

class CliThread(object):
    def __init__(self):
        print 'ArgusProbeBeamLogic {0}.{1}.{2}.{3} - (c) OpenWSN project'.format(
            ArgusVersion.VERSION[0],
            ArgusVersion.VERSION[1],
            ArgusVersion.VERSION[2],
            ArgusVersion.VERSION[3],
        )
        
        while True:
            input = raw_input('>')
            print input

def main():
    # parse parameters
    
    # start thread
    publishThread = PublishThread()
    snifferThread = SnifferThread(publishThread)
    cliThread     = CliThread()

#============================ main ============================================

if __name__=="__main__":
    main()
