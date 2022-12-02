from charm.toolbox.pairinggroup import PairingGroup, ZR, G1, G2, pair
from charm.core.engine.util import objectToBytes
from charm.toolbox.IBSig import *
from BG import BG

debug = False


class BLS01(IBSig):
    def __init__(self, groupObj):
        IBSig.__init__(self)
        global group
        group = groupObj
        
    def dump(self, obj):
        return objectToBytes(obj, group)
            
    def keygen(self, pp):
        x = group.random()
        return (x, pp['G1'] ** x)
        
    def sign(self,pp, x, message):
        #M = self.dump(message)
        return group.hash(objectToBytes(message, group), G2) ** x
        
    def verify(self, pp, vk, sig, message):
        #M = self.dump(message)
        h = group.hash(objectToBytes(message, group), G2)
        if pair(pp['G1'], sig) == pair(vk, h):
            return 1  
        return 0 

'''
def main():
    group = PairingGroup('MNT224')
    g1,g2=group.random(G1),group.random(G2)
    pp= {'G1':g1,'G2':g2,'GT':pair(g1,g2)}
    m = { 'a':"hello world!!!" , 'b':"test message" }
    bls = BLS01(group)
    group.hash(objectToBytes(m, group), G1)
    (pk, sk) = bls.keygen(pp)
    
    sig = bls.sign(pp,sk['x'], m)
    
    if debug: print("Message: '%s'" % m)
    if debug: print("Signature: '%s'" % sig)     
    assert bls.verify(pk, sig, m), "Failure!!!"
    if debug: print('SUCCESS!!!')


if __name__ == "__main__":
    debug = True
    main()
'''