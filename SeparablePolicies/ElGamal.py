from charm.toolbox.PKEnc import PKEnc
from charm.toolbox.pairinggroup import PairingGroup, ZR, G1, G2, GT, pair
from charm.toolbox.eccurve import prime192v2
from charm.toolbox.ecgroup import ECGroup
debug=False
class ElGamal(PKEnc):
    def __init__(self, groupObj, p=0, q=0):
        PKEnc.__init__(self)
        global group
        group = groupObj

    def keygen(self, pp):
        x = group.random(); pk = pp['G1'] ** x
        return x, pk
    def Enc(self,pp, pk, M):
        r = group.random()
        return {'c1':pp['G1'] ** r, 'c2':M * (pk ** r)},r
    def Dec(self, sk, c):
        return c['c2']/(c['c1'] ** sk)

'''
groupObj = PairingGroup('BN254')
G1,G2=groupObj.random(G1),groupObj.random(G2)
pp={'G1':G1,'G2':G2,'GT':pair(G1,G2)}
ENC=ElGamal(groupObj)
(secret_key,public_key) = ENC.keygen(pp)
msg = pp['G1']**2
ciphertext=ENC.encrypt(pp,public_key,msg)
decrypted_msg = ENC.decrypt(secret_key, ciphertext)
print(decrypted_msg==msg)   
'''