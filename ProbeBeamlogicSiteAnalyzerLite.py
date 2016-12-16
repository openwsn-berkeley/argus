'''
Argus probe for the Beamlogic Site Analyzer Lite
http://www.beamlogic.com/products/802154-site-analyzer.aspx
'''

import threading

class AppData(object):
    pass

class PublishThread(threading.Thread):
    '''
    Thread which publishes sniffed frames to the broker
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
    Thread which attaches to the sniffer and parses incoming frames
    '''
    def __init__(self):
        pass
    
    def run(self):
        with open(r'\\.\pipe\analyzer', 'rb') as sniffer:
            while True:
                b = sniffer.read(1)
                self._newByte(b)
    
    #======================== public ==========================================
    
    #======================== private =========================================
    
    def _newByte(self,b):
        '''
        Just received a byte from the sniffer
        '''
        print ' {0:02x}'.format(ord(b)),
    
    def _newFrame(self,b):
        '''
        Just received a full frame from the sniffer
        '''
        raise NotImplementedError()

def main():
    # parse parameters
    
    # start thread
    SnifferThread()

#============================ main ============================================

if __name__=="__main__":
    main():
