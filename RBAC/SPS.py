from http.client import PROXY_AUTHENTICATION_REQUIRED
from charm.toolbox.pairinggroup import PairingGroup, ZR, G1, G2, pair
from charm.core.engine.util import objectToBytes
from charm.toolbox.IBSig import *

debug = False


class SPS():
    def __init__(self, groupObj):
        global util, group 
        group = groupObj

    def keygen(self, pp, l):
        sk={}; vk={}
        for i in range(l):
            sk[i]=group.random()
            vk[i]=pp['G2']**sk[i]
        return (sk,vk)
        
    def sign(self, pp, sk, M):
        a= group.random()
        R=1
        for i in range(len(M)):
            R*=M[i]**sk[i]
        sigma={'R':R**a, 'S':pp['G1']**(a**(-1)),'T':pp['G2']**(a**(-1))}
        return sigma
        
    def verify(self, pp, vk, sigma, M):
        LHS=1
        for i in range(len(M)):
            LHS*=pair(vk[i],M[i])
        if LHS==pair(sigma['R'],sigma['T']) and pair(sigma['S'],pp['G2'])==pair(pp['G1'],sigma['T']):
            return 1
        else: return 0
    
'''
groupObj = PairingGroup('BN254')
SPS=SPS(groupObj)

g1, g2 = group.random(G1), group.random(G2)
pp = {'G1':g1, 'G2':g2, 'GT':pair(g1,g2)}

n=10; m=10
(sk,vk)=SPS.keygen(pp,n,m)
M={}; N={}
for i in range(m):
    M[i] = group.random(G1)
for i in range(n):
    N[i] = group.random(G2)
sigma = SPS.sign(pp,sk,M,N)
out=SPS.verify(pp,vk,sigma,M,N)
print(out)
'''