import dcrypt_hash
import binascii
import os, sys, time, datetime, random

def send(cmd):
    sys.stdout.write(cmd)
    sys.stdout.flush()

def pos(line, column):
    send('\033[%s;%sf' % (line, column))

def hexifynonce(nonce):
    hexnonce=''
    hexnonce = hex(nonce).replace('0x','')
    while(len(hexnonce)<8):
       hexnonce="0"+hexnonce
    return(hexnonce)

def rand64byte():
    buffer = ''
    while (len(buffer) < 64):
     buffer += '0' #should solve at 511a
    return (buffer)

def returnheader():
    header_hex = "02000000" + \
                 rand64byte() + \
                 rand64byte() + \
	         "814cdb52" + \
                 "f0ff0f1e"
    return(header_hex)

# main
nonce = 0
print ''
target = "0000ffff00000000000000000000000000000000000000000000000000000000"

prehash = returnheader()
starthash = time.time()
while True:

  if nonce % 7 == 0:
   header = prehash + hexifynonce(nonce)
   pos(1,1)
   print 'nonce:  ' + hexifynonce(nonce)
   pos(3,1)
   print 'header: ' + header

  # hash fn with timers
  pretimer = datetime.datetime.now()
  hashbin = binascii.unhexlify(header)
  posthash = dcrypt_hash.getPoWHash(hashbin)
  posthashhex = binascii.hexlify(posthash[:32])
  posttimer = datetime.datetime.now()

  hashtime = posttimer - pretimer
  pos(7,1)
  print 'hashed: ' + posthashhex
  pos (10,1)
  print '%d h/s      ' % (1000000/hashtime.microseconds)

  if posthash < binascii.unhexlify(target):
     pos(12,1)
     print posthashhex
     print target
     finishhash = time.time()
     print 'BLOCK (took ' + str(int(finishhash-starthash)) + 's to solve)'
     sys.exit()

  nonce=nonce+1
