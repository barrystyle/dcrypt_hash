import dcrypt_hash, binascii, os, sys, time

print ''

#blockheader as it is read from disk (swapping already done)
header = "01000000c9f65eb5af53b928575a20efc63347e63e094ffa0f763dab948600ba2b000000816478a18edc6a29f865be0b5089abce777011803e157c197f720a833f4d7be40be0df5affff0f1e6fc43380"
print header
hashbin = binascii.unhexlify(header)
posthash = dcrypt_hash.getPoWHash(hashbin)[::-1]

#target and its binary equivalent
target = "00000ffff0000000000000000000000000000000000000000000000000000000"
targetbin = binascii.unhexlify(target)

print ' '
print binascii.hexlify(targetbin)
print binascii.hexlify(posthash)
print ' '

if posthash < target:
   print 'hash is lower than target (good)'
else:
   print 'hash above target (error)'
