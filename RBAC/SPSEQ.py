from http.client import PROXY_AUTHENTICATION_REQUIRED
from charm.toolbox.pairinggroup import PairingGroup, ZR, G1, G2, pair
from charm.core.engine.util import objectToBytes
from charm.toolbox.IBSig import *

debug = False


class SPSEQ():
    def __init__(self, groupObj):
        global util, group 
        group = groupObj

    def keygen(self, pp, l):
        sk={}; vk={}
        for i in range(l):
            sk[i]=group.random()
            vk[i]=pp['G1']**sk[i]
        return (sk,vk)
        
    def sign(self, pp, sk, M):
        a= group.random()
        R=1
        for i in range(len(M)):
            R*=M[i]**sk[i]
        sigma={'R':R**a, 'S':pp['G2']**(a**(-1)),'T':pp['G1']**(a**(-1))}
        return sigma
        
    def verify(self, pp, vk, sigma, M):
        LHS=1
        for i in range(len(M)):
            LHS*=pair(M[i],vk[i])
        if LHS==pair(sigma['T'],sigma['R']) and pair(pp['G1'],sigma['S'])==pair(sigma['T'],pp['G2']):
            return 1
        else: return 0 
    
    def ChgRep(self, pp, M, sigma, mu):
        M_P={}
        zeta = group.random()
        sigma_P={'R':sigma['R']**(mu * zeta), 'S':sigma['S']**(zeta**(-1)),'T':sigma['T']**(zeta**(-1))}
        for i in range(len(M)):
            M_P[i]=M[i]**mu
        return (M_P,sigma_P)



'''
groupObj = PairingGroup('BN254')
SPSEQ=SPSEQ(groupObj)

g1, g2 = group.random(G1), group.random(G2)
pp = {'G1':g1, 'G2':g2, 'GT':pair(g1,g2)}

l=10
(sk,vk)=SPSEQ.keygen(pp,l)
M={}
for i in range(l):
    M[i]=group.random(G1)
sigma=SPSEQ.sign(pp,M,sk)
mu=group.random()
(sigma_P,M_P)=SPSEQ.ChgRep(pp,M,sigma,vk,mu)
print("re-randomized")
out=SPSEQ.verify(pp,vk,sigma_P,M_P)
print(out)
print("original")
out=SPSEQ.verify(pp,vk,sigma,M)
print(out)
'''