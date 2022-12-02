from charm.toolbox.pairinggroup import ZR,G2
from charm.core.engine.util import objectToBytes
from BLS import BLS01 as DS
from BG import BG
from policy import Policy
from PRF import DY as PRF
from GS import GS as NIZK
from SPS import SPS
from Bulletproof import RangeProof
from Sigma import Sigma
from Pedersen import PedCom as Com

from ElGamal import ElGamal as ENC

class UPCS():
    def __init__(self, groupObj):
        global util, group       
        group = groupObj
        self.DS = DS(groupObj)
        self.BG = BG(groupObj)
        self.F_lambda = Policy()
        self.PRF = PRF(groupObj)
        self.NIZK = NIZK(groupObj)
        self.Sigma= Sigma(groupObj)
        self.SPS = SPS(groupObj)
        self.RangeProof = RangeProof()
        self.Com = Com(groupObj)
        self.Enc = ENC(groupObj)
                        
    def Setup(self):
        pp=BG.Gen(self)
        CRS1 = NIZK.sampleParams(self,pp)
        CRS2 = NIZK.sampleParams(self,pp)
        pp_com = Com.Setup(self)
        (sk_sigAS,vk_sigAS) = SPS.keygen(self,pp,3)
        (sk_sigAR,vk_sigAR) = SPS.keygen(self,pp,3)
        (dk_encA,ek_encA) = ENC.keygen(self,pp)
        msk={'sk_sigAS':sk_sigAS, 'sk_sigAR':sk_sigAR, 'dk_encA': dk_encA}
        mpk={'pp':pp, 'CRS1':CRS1, 'CRS2':CRS2, 'vk_sigAS':vk_sigAS, 'vk_sigAR':vk_sigAR, 'ek_encA':ek_encA, 'pp_com':pp_com}
        return (msk, mpk)

    def KeyGen(self,mpk,msk,x,F):
        seed=group.random()
        if F['R'][x]==1:
            m = group.init(ZR, 1); m_x = mpk['pp']['G1']**m
            sigma_sigR = SPS.sign(self,mpk['pp'],msk['sk_sigAR'],[mpk['pp']['G1']**seed, msk['dk_encA']])
        else:
            m = group.init(ZR, 0); m_x = mpk['pp']['G1']**m
            sigma_sigR = SPS.sign(self,mpk['pp'],msk['sk_sigAR'],[mpk['pp']['G1']**seed, msk['ek_encA']])
        (sk_sig,vk_sig) = DS.keygen(self,mpk['pp'])
        if F['S'][x]==1:
            sigma_sigS = SPS.sign(self,mpk['pp'],msk['sk_sigAS'],[mpk['pp']['G1']**seed, vk_sig, m_x])
            usk = {'seed':seed,'sk_sig':sk_sig,'vk_sig':vk_sig,'sigma_sigS':sigma_sigS,'sigma_sigR':sigma_sigR,'m':m_x,'dk_encA': msk['dk_encA']}
        else:
            usk = {'seed':seed,'sk_sig':sk_sig,'vk_sig':vk_sig,'sigma_sigR':sigma_sigR,'m':m_x}
        sk = [usk,-1,"perp","perp","perp"]
        return UPCS.RandKey(self,mpk,sk)
    

    def RandKey(self,mpk,sk):
        pp=mpk['pp']; pp_com=mpk['pp_com']; GS_instance={}; GS_proof={}; GS_com={}
        #PRF and its proof
        pp=mpk['pp']; X=sk[1]+1
        ID = PRF.Gen(self,pp_com,sk[0]['seed'],X)
        e1, e2, e3 =group.random(), group.random(), group.random()
        cm1 = Com.com(self,pp_com,X,e1)
        cm2 = Com.com(self,pp_com,sk[0]['seed'],e2)
        cm3 = Com.com(self,pp_com,X+sk[0]['seed'],e3)
        w = (X,sk[0]['seed'],e1,e2,e3)
        x = (ID,cm1,cm2,cm3,pp_com['G'],pp_com['H'])
        x_prf, pi_prf = Sigma.PRFprove.Prove(x,w)
        #range_proof
        (v, n, g, h, gs, hs, gamma, u, CURVE, seeds, V)=RangeProof.Setup(self.RangeProof, 2 ** 16 - 1, 16)
        proof = RangeProof.RanProve(self.RangeProof, v, n, g, h, gs, hs, gamma, u, CURVE, seeds[6])
        rp=(V, g, h, gs, hs, u, proof,seeds)

        (sk_sig,vk_sig) = DS.keygen(self,pp)
        sigma_sig = DS.sign(self,pp,sk[0]['sk_sig'],[vk_sig,ID])
        sk[3] = sigma_sig
        ct,r = ENC.Enc(self,pp,mpk['ek_encA'],sk[0]['m']); sk[4]=r
        # Proof of knowledge of encryption
        tau = group.random()
        cm = Com.com(self,pp_com,group.init(ZR, 1),tau)
        x_elgamal = (ct['c1'], ct['c2'],mpk['ek_encA'],cm,pp_com['G'],pp_com['H'])
        w_elgamal = (r,group.init(ZR, 1),tau)
        pi_elgamal = Sigma.ElGamal.Prove(pp,x_elgamal,w_elgamal)
        
        #SPS proof
        x = [pp['G1']**sk[0]['seed'], sk[0]['m'],sk[0]['sigma_sigR']['R'], sk[0]['sigma_sigR']['S'], pp['G1']]
        y = [mpk['vk_sigAR'][0],mpk['vk_sigAR'][1], sk[0]['sigma_sigR']['T']**(-1), pp['G2'], sk[0]['sigma_sigR']['T']**(-1)]
        c_a = [None, None, None, None, pp['G1']]
        c_b = [mpk['vk_sigAR'][0], mpk['vk_sigAR'][1], None, pp['G2'], None]
        (a,b,r,s,t)=NIZK.ParamGen(self,x,y,c_a,c_b)
        GS_instance[1] = {'m':len(x), 'n':len(y), 'a':a, 'b':b}
        GS_com[1] = NIZK.commit(self,GS_instance[1],mpk['CRS1'],x,y,r,s)
        GS_proof[1] = NIZK.prove(self,GS_instance[1],mpk['CRS1'],GS_com[1],x,y,r,s,t)

        x = [sk[0]['vk_sig'], pp['G1']]
        y = [group.hash(objectToBytes([ID,sk[0]['vk_sig']], group), G2), sk[3]**(-1)]
        c_a = [None, pp['G1']]
        c_b = [group.hash(objectToBytes([ID,sk[0]['vk_sig']], group), G2), None]
        (a,b,r,s,t)=NIZK.ParamGen(self,x,y,c_a,c_b)
        GS_instance[2] = {'m':len(x), 'n':len(y), 'a':a, 'b':b}
        GS_com[2] = NIZK.commit(self,GS_instance[2],mpk['CRS1'],x,y,r,s)
        GS_proof[2] = NIZK.prove(self,GS_instance[2],mpk['CRS1'],GS_com[2],x,y,r,s,t)
        
        sk[1] += 1; sk[2] = sk_sig; sk[3] = sigma_sig
        pk = {'ID':ID,'vk_sig':vk_sig,'ct':ct, 'inst':GS_instance, 'com':GS_com,\
                  'pi':GS_proof,'rp':rp, 'x_prf':x_prf, 'pi_prf':pi_prf, 'pi_elgamal':pi_elgamal, 'x_elgamal':x_elgamal}
        return sk,pk


    def Sign(self,mpk,sk,pk_R,m):
        pp=mpk['pp']; pp_com=mpk['pp_com']; (V, g, h, gs, hs, u, proof,seeds)=pk_R['rp']; X=sk[1]+1
        GS_proofs={}; GS_instance={}; GS_com={}
        if 'dk_encA' in sk[0].keys() and \
            NIZK.verifyProof(self,pp,pk_R['inst'][1],mpk['CRS1'],pk_R['com'][1],pk_R['pi'][1])==True and \
            NIZK.verifyProof(self,pp,pk_R['inst'][2],mpk['CRS1'],pk_R['com'][2],pk_R['pi'][2])==True and \
             ENC.Dec(self,sk[0]['dk_encA'],pk_R['ct'])==pp['G1']**group.init(ZR, 1) and \
                RangeProof.RanVerify(self.RangeProof ,V, g, h, gs, hs, u, proof,seeds)==True and \
                    Sigma.PRFprove.Verify(pk_R['x_prf'],pk_R['pi_prf'])==1 and \
                        Sigma.ElGamal.Verify(pp,pk_R['x_elgamal'],pk_R['pi_elgamal'])==1:
                        print('The public key of the reciever is valid\n')
                        # To prove the knowledge of dk^A under the public ek^A
                        ins = (pp['G1'], mpk['ek_encA'])
                        wit= (sk[0]['dk_encA'])
                        x_dk, pi_dk = Sigma.Dlog.Prove(ins,wit)
                        ID_S = PRF.Gen(self,pp_com,sk[0]['seed'],sk[1])
                        #PRF proof
                        e1, e2, e3 =group.random(), group.random(), group.random()
                        cm1 = Com.com(self,pp_com,X,e1)
                        cm2 = Com.com(self,pp_com,sk[0]['seed'],e2)
                        cm3 = Com.com(self,pp_com,X+sk[0]['seed'],e3)
                        w = (X,sk[0]['seed'],e1,e2,e3)
                        x = (ID_S,cm1,cm2,cm3,pp_com['G'],pp_com['H'])
                        x_prf, pi_prf = Sigma.PRFprove.Prove(x,w)
                        #SPS proof
                        sigma = DS.sign(self,pp,sk[2],[m,pk_R['ID']])
                        x = [pp['G1']**sk[0]['seed'],sk[0]['vk_sig'] ,sk[0]['m'],sk[0]['sigma_sigS']['R'], sk[0]['sigma_sigS']['S'], pp['G1']]
                        y = [mpk['vk_sigAS'][0],mpk['vk_sigAS'][1],mpk['vk_sigAS'][2], sk[0]['sigma_sigS']['T']**(-1), pp['G2'], sk[0]['sigma_sigS']['T']**(-1)]
                        c_a = [None, None, None, None, None, pp['G1']]
                        c_b = [mpk['vk_sigAS'][0], mpk['vk_sigAS'][1], mpk['vk_sigAS'][2], None, pp['G2'], None]
                        (a,b,r,s,t)=NIZK.ParamGen(self,x,y,c_a,c_b)
                        GS_instance[1] = {'m':len(x), 'n':len(y), 'a':a, 'b':b}
                        GS_com[1] = NIZK.commit(self,GS_instance[1],mpk['CRS2'],x,y,r,s)
                        GS_proofs[1] = NIZK.prove(self,GS_instance[1],mpk['CRS2'],GS_com[1],x,y,r,s,t)
                        # The second SPS
                        x = [pp['G1']**group.init(ZR, 1), pp['G1']**(-1), pp['G1']**group.init(ZR, 1),pp['G1']**group.init(ZR, 1)]
                        y = [pp['G2'],pp['G2']**group.init(ZR, 1),pp['G2']**group.init(ZR, 1),pp['G2']**(-1)]
                        c_a = [None,pp['G1']**(-1),None,None]
                        c_b = [pp['G2'],None,None,pp['G2']**(-1)]
                        (a,b,r,s,t)=NIZK.ParamGen(self,x,y,c_a,c_b)
                        GS_instance[2] = {'m':len(x), 'n':len(y), 'a':a, 'b':b}
                        GS_com[2] = NIZK.commit(self,GS_instance[2],mpk['CRS2'],x,y,r,s)
                        GS_proofs[2] = NIZK.prove(self,GS_instance[2],mpk['CRS2'],GS_com[2],x,y,r,s,t)

                        pi={'inst':GS_instance, 'pi':GS_proofs, 'com':GS_com, 'x_prf':x_prf, 'pi_prf':pi_prf, "x_dk":x_dk, "pi_dk":pi_dk}
        else:
            print("There is no link")
            sigma="perp"; pi="perp"
        return {'sigma':sigma,'pi':pi}

    def verify(self,mpk,pk_S,pk_R,m,sigma):
        pi_s=sigma['pi']
        if NIZK.verifyProof(self,mpk['pp'],pk_S['inst'][1],mpk['CRS1'],pk_S['com'][1],pk_S['pi'][1])==True and \
            NIZK.verifyProof(self,mpk['pp'],pk_S['inst'][2],mpk['CRS1'],pk_S['com'][2],pk_S['pi'][2])==True and \
            NIZK.verifyProof(self,mpk['pp'],pk_R['inst'][1],mpk['CRS1'],pk_R['com'][1],pk_R['pi'][1])==True and \
                NIZK.verifyProof(self,mpk['pp'],pk_R['inst'][2],mpk['CRS1'],pk_R['com'][2],pk_R['pi'][2])==True and \
                    Sigma.Dlog.Verify(pi_s['x_dk'],pi_s['pi_dk'])==1:
            print("Valid sender's and receiver's public key\n")
            return DS.verify(self,mpk['pp'],pk_S['vk_sig'],sigma['sigma'],[m,pk_R['ID']]) and \
                NIZK.verifyProof(self,mpk['pp'],pi_s['inst'][1],mpk['CRS2'],pi_s['com'][1],pi_s['pi'][1])==True and \
                NIZK.verifyProof(self,mpk['pp'],pi_s['inst'][2],mpk['CRS2'],pi_s['com'][2],pi_s['pi'][2])==True and \
                Sigma.PRFprove.Verify(pk_R['x_prf'],pk_R['pi_prf'])==1

