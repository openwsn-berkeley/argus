'''
Argus client script which attaches to the broker and sends
sniffed packets through a pipe to Wireshark.
'''

import threading

import paho.mqtt.client

import ArgusVersion

#============================ helpers =========================================

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
    
    MQTT_BROKER_HOST    = 'iot.eclipse.org'
    MQTT_BROKER_PORT    = 1883
    MQTT_BROKER_TOPIC   = 'daumesnil'
    
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
            self.mqtt.loop_forever()
        except Exception as err:
            logCrash(self.name,err)
    
    #======================== public ==========================================
    
    #======================== private =========================================
    
    def _mqtt_on_connect(self,client,userdata,flags,rc):
        print("Connected to {0}, rc={1}".format(self.MQTT_BROKER_HOST,rc))
        self.mqtt.subscribe('argus/{0}'.format(self.MQTT_BROKER_TOPIC))
    
    def _mqtt_on_message(self,client,userdata,msg):
        self.txWiresharkThread.publish(msg.payload)

class TxWiresharkThread(object):
    '''
    Thread which publishes sniffed frames to the MQTT broker.
    '''
    
    PIPE_WIRESHARK      = r'\\.\pipe\argus'
    
    def _init__(self):
        pass
    
    #======================== public ==========================================
    
    def publish(self,frame):
        print frame
    
    #======================== private =========================================

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
    # parse parameters
    
    # start thread
    txWiresharkThread   = TxWiresharkThread()
    rxMqttThread        = RxMqttThread(txWiresharkThread)
    cliThread           = CliThread()

if __name__=="__main__":
    main()
