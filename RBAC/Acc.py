from copyreg import pickle
from http.client import PROXY_AUTHENTICATION_REQUIRED
from charm.toolbox.pairinggroup import PairingGroup, ZR, G1, G2, pair
from charm.core.engine.util import objectToBytes
from charm.toolbox.IBSig import *

debug = False


class ACC():
    def __init__(self, groupObj):
        global util, group 
        group = groupObj                 
    def Create(self,pp):
        alpha=group.random()
        A=pp['G2']**alpha
        msk=alpha
        return (A,msk)
    def Add(self,pp,A,msk,x):
        if A==pp['G2']**msk:
            w_x=pp['G1']**((x+msk)**(-1))
        return w_x
    def MemVrf(self, pp, A, x, w_x):
        if pp['GT']==pair(w_x,A*(pp['G2']**group.init(ZR,x))):
            return True
        else: return False

'''
groupObj = PairingGroup('BN254')
G1,G2=groupObj.random(G1),groupObj.random(G2)
pp={'G1':G1,'G2':G2,'GT':pair(G1,G2)}
ACC=ACC(groupObj)
(A,msk)=ACC.Create(pp)
x=groupObj.random()
w_x=ACC.Add(pp,A,msk,x)
out=ACC.MemVrf(pp,A,x,w_x)
print(out)
'''