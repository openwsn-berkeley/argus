'''
Argus probe for the Beamlogic Site Analyzer Lite
http://www.beamlogic.com/products/802154-site-analyzer.aspx
'''

import time
import threading

import ArgusVersion

class AppData(object):
    pass

class PublishThread(threading.Thread):
    '''
    Thread which publishes sniffed frames to the broker.
    '''
    def __init__(self):
        pass
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
        raise NotImplementedError()
    
    #======================== private =========================================
    

class SnifferThread(threading.Thread):
    '''
    Thread which attaches to the sniffer and parses incoming frames.
    '''
    
    GLOBAL_HEADER_LEN = 24 # 4+2+2+4+4+4+4
    PACKET_HEADER_LEN = 16 # 4+4+4+4
    PIPE_SNIFFER      = r'\\.\pipe\analyzer'
    
    def __init__(self,publishThread):
        
        # store params
        self.publishThread             = publishThread
        
        # local variables
        self.dataLock                  = threading.Lock()
        self.rxBuffer                  = []
        self.doneReceivingGlobalHeader = False
        self.doneReceivingPacketHeader = False
        self.incl_len                  = None
        
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
                        b = sniffer.read(1)
                        self._newByte(b)
            except (IOError,TypeError):
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
        print '{0:02x}'.format(ord(b)),
        return
        with self.dataLock:
            self.rxBuffer += [b]
            
            # global header
            if   not self.doneReceivingGlobalHeader:
                if len(self.rxBuffer)==self.GLOBAL_HEADER_LEN:
                    self.doneReceivingGlobalHeader    = True
                    self.rxBuffer                     = []
            
            # packet header
            elif not self.doneReceivingGlobalHeader:
                if len(self.rxBuffer)==self.PACKET_HEADER_LEN:
                    self.doneReceivingPacketHeader    = True
                    self.incl_len                     = self._extractInclLen(self.rxBuffer)
                    self.rxBuffer                     = []
            
            # packet data
            else:
                if len(self.rxBuffer)==self.incl_len:
                    self.doneReceivingPacketHeader    = False
                    self._newFrame(self.rxBuffer)
                    self.rxBuffer                     = []
    
    def _extractInclLen(self,header):
        '''
        Extract the incl_len field from a PCAP packet header
        '''
        assert len(header)==self.PACKET_HEADER_LEN
        
        raise NotImplementedError()
    
    def _newFrame(self,frame):
        '''
        Just received a full frame from the sniffer
        '''
        
        # transform frame
        frame = self._transformFrame(frame)
        
        # publish frame
        self.publishThread.publishFrame(self.rxBuffer)
    
    def _transformFrame(self,frame):
        '''
        Replace BeamLogic header by ZEP header.
        '''
        raise NotImplementedError()

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
