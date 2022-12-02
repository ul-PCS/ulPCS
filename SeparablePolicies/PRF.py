from copyreg import pickle
from http.client import PROXY_AUTHENTICATION_REQUIRED
from charm.toolbox.pairinggroup import PairingGroup, ZR, G1, G2, pair


class DY():
    def __init__(self, groupObj):
        global util, group 
        group = groupObj                 
    def Gen(self,pp,seed,k):
        return pp['G']**((seed+k)**(-1))
    

'''
groupObj = PairingGroup('BN254')
G1,G2=groupObj.random(G1),groupObj.random(G2)
pp={'G1':G1,'G2':G2,'GT':pair(G1,G2)}
PRF=DY(groupObj)
seed=groupObj.random()
ID=PRF.Gen(pp,seed,2)
print(ID)
'''