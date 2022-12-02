from charm.toolbox.pairinggroup import PairingGroup,ZR,G1,G2,GT,pair
from charm.core.engine.util import objectToBytes
from Acc import ACC
from SPSEQ import SPSEQ as SEQ
from BLS import BLS01 as DS
from BG import BG
from policy import Policy
from PRF import DY as PRF
from GS import GS as NIZK
from SPS import SPS
from Bulletproof import RangeProof
from Sigma import Sigma
from Pedersen import PedCom as Com

class UPCS():
    def __init__(self, groupObj):
        global util, group     
        group = groupObj
        self.ACC = ACC(groupObj)
        self.SEQ = SEQ(groupObj)
        self.DS = DS(groupObj)
        self.BG = BG(groupObj)
        self.F_lambda = Policy()
        self.PRF = PRF(groupObj)
        self.NIZK = NIZK(groupObj)
        self.Sigma= Sigma(groupObj)
        self.SPS = SPS(groupObj)
        self.RangeProof = RangeProof()
        self.Com = Com(groupObj)
                        
    def Setup(self,F):
        A={}; alpha={}; W={}
        pp=BG.Gen(self)
        CRS1 = NIZK.sampleParams(self,pp)
        CRS2 = NIZK.sampleParams(self,pp)
        pp_com=Com.Setup(self)
        (sk_sigA,vk_sigA) = SPS.keygen(self,pp,3)
        (sk_seqA,vk_seqA) = SEQ.keygen(self,pp,3)
        for y in range(len(F)):
            S={}
            (A[y],alpha[y]) = ACC.Create(self,pp)
            S[y]=[x for x in range(len(F)) if F[x,y]==1 and x!=y]
            for i in S[y]:
                w_i = ACC.Add(self,pp,A[y],alpha[y],i)
                W[y,i] = w_i
        msk={'sk_sigA':sk_sigA, 'sk_seqA':sk_seqA, 'A': A, 'W':W}
        mpk={'pp':pp, 'CRS1':CRS1, 'CRS2':CRS2, 'vk_sigA':vk_sigA, 'vk_seqA':vk_seqA, 'pp_com':pp_com}
        return (msk, mpk)

    def KeyGen(self,mpk,msk,x):
        W={}
        (A_sd,alpha_sd) = ACC.Create(self,mpk['pp'])
        seed = group.random()
        w_sd = ACC.Add(self,mpk['pp'],A_sd,alpha_sd,seed)
        M = [A_sd,msk['A'][x],mpk['pp']['G2']]
        sigma_SEQ = SEQ.sign(self,mpk['pp'],msk['sk_seqA'],M)
        (sk_sig,vk_sig) = DS.keygen(self,mpk['pp'])
        sigma_sig = SPS.sign(self,mpk['pp'],msk['sk_sigA'],[mpk['pp']['G1']**seed, vk_sig, mpk['pp']['G1']**x])
        for index,w in msk['W'].items():
            if index[1]==x:
                W[index[0]]=[w,SPS.sign(self,mpk['pp'],msk['sk_sigA'],[mpk['pp']['G1']**seed,w])]
        usk={'M':M,'sigma_SEQ':sigma_SEQ,'W':W,'w_sd':w_sd,'seed':seed,'sk_sig':sk_sig,'vk_sig':vk_sig,'sigma_sig':sigma_sig, 'x':x}
        sk=[usk,-1,"perp"]
        return UPCS.RandKey(self,mpk,sk)
    
    

    def RandKey(self,mpk,sk):
        GS_proofs={}; GS_instance={}; GS_com={}
        # PRF evaluation and its proof
        pp=mpk['pp']; pp_com=mpk['pp_com']; X=sk[1]+1
        ID = PRF.Gen(self,pp_com,sk[0]['seed'],X)
        e1, e2, e3 =group.random(), group.random(), group.random()
        cm1 = Com.com(self,pp_com,X,e1)
        cm2 = Com.com(self,pp_com,sk[0]['seed'],e2)
        cm3 = Com.com(self,pp_com,X+sk[0]['seed'],e3)
        w = (X,sk[0]['seed'],e1,e2,e3)
        x = (ID,cm1,cm2,cm3,pp_com['G'],pp_com['H'])
        x_prf, pi_prf = Sigma.PRFprove.Prove(x,w)
        
        # Range_proof for the counter X
        (v, n, g, h, gs, hs, gamma, u, CURVE, seeds, V)=RangeProof.Setup(self.RangeProof,2 ** 16 - 1, 16)
        proof = RangeProof.RanProve(self.RangeProof,v, n, g, h, gs, hs, gamma, u, CURVE, seeds[6])
        rp=(V, g, h, gs, hs, u, proof,seeds)
        (sk_sig,vk_sig) = DS.keygen(self,mpk['pp'])
        sigma_sig = DS.sign(self,mpk['pp'],sk[0]['sk_sig'],[ID,vk_sig])
        mu = group.random()
        (M_P,Sigma_P) = SEQ.ChgRep(self,mpk['pp'],sk[0]['M'],sk[0]['sigma_SEQ'],mu)
        
        # The knowledge of a witness for the Accumulator
        x = [pp['G1']**(-1), sk[0]['w_sd'], sk[0]['w_sd']]
        y = [M_P[2], M_P[0], M_P[2]**sk[0]['x']]
        c_a = [pp['G1']**(-1), None, None]
        c_b = [M_P[2], M_P[0], None]
        (a,b,r,s,t)=NIZK.ParamGen(self, x,y,c_a,c_b)
        GS_instance[1] = {'m':len(x), 'n':len(y), 'a':a, 'b':b}
        GS_com[1] = NIZK.commit(self,GS_instance[1],mpk['CRS1'],x,y,r,s)
        GS_proofs[1] = NIZK.prove(self,GS_instance[1],mpk['CRS1'],GS_com[1],x,y,r,s,t)
        
        # SPS verifrication
        x = [pp['G1']**sk[0]['seed'], sk[0]['vk_sig'], pp['G1']**sk[0]['x'], sk[0]['sigma_sig']['R'], sk[0]['sigma_sig']['S'], pp['G1']]
        y = [mpk['vk_sigA'][0],mpk['vk_sigA'][1], mpk['vk_sigA'][2], sk[0]['sigma_sig']['T']**(-1), pp['G2'], sk[0]['sigma_sig']['T']**(-1)]
        c_a = [None, None, None, None, None, pp['G1']]
        c_b = [mpk['vk_seqA'][0], mpk['vk_seqA'][1], mpk['vk_sigA'][2], None, pp['G2'], None]
        (a,b,r,s,t)=NIZK.ParamGen(self,x,y,c_a,c_b)
        GS_instance[2] = {'m':len(x), 'n':len(y), 'a':a, 'b':b}
        GS_com[2] = NIZK.commit(self,GS_instance[2],mpk['CRS1'],x,y,r,s)
        GS_proofs[2] = NIZK.prove(self,GS_instance[2],mpk['CRS1'],GS_com[2],x,y,r,s,t)

        # BLS signature verifrication
        x = [sk[0]['vk_sig'],pp['G1']]
        y = [group.hash(objectToBytes([ID,vk_sig], group), G2), sigma_sig]
        c_a = [None , pp['G1']]
        c_b = [group.hash(objectToBytes([ID,vk_sig], group)), None]
        (a,b,r,s,t)=NIZK.ParamGen(self,x,y,c_a,c_b)
        GS_instance[3] = {'m':len(x), 'n':len(y), 'a':a, 'b':b}
        GS_com[3] = NIZK.commit(self,GS_instance[3],mpk['CRS1'],x,y,r,s)
        GS_proofs[3] = NIZK.prove(self,GS_instance[3],mpk['CRS1'],GS_com[3],x,y,r,s,t)
        
        sigma_sig = DS.sign(self,mpk['pp'],sk[0]['sk_sig'],[ID,vk_sig])
        sk[1] += 1; sk[2] = sk_sig
        pk={'ID':ID,'vk_sig':vk_sig,'M':M_P,'sigma_SEQ':Sigma_P, 'inst':GS_instance, 'com':GS_com, 'pi':GS_proofs, 'rp':rp, 'x_prf':x_prf, 'pi_prf':pi_prf}
        return sk, pk


    def Sign(self,mpk,sk,pk_R,m,x):
        GS_proofs={}; GS_instance={}; GS_com={}; pp_com=mpk['pp_com']
        pp=mpk['pp']; (V, g, h, gs, hs, u, proof,seeds)=pk_R['rp']
        pp_p={'G1':mpk['pp']['G1'],'G2':pk_R['M'][2],'GT':pair(mpk['pp']['G1'],pk_R['M'][2])}
        if SEQ.verify(self,mpk['pp'],mpk['vk_seqA'],pk_R['sigma_SEQ'],pk_R['M'])==1 and \
            NIZK.verifyProof(self,mpk['pp'],pk_R['inst'][1],mpk['CRS1'],pk_R['com'][1],pk_R['pi'][1])==True and \
                RangeProof.RanVerify(self.RangeProof,V, g, h, gs, hs, u, proof,seeds)==True and \
                    Sigma.PRFprove.Verify(pk_R['x_prf'],pk_R['pi_prf'])==1:
            print("The receiver's public key is valid.\n")
            ID = PRF.Gen(self,mpk['pp_com'],sk[0]['seed'],sk[1])
            e1, e2, e3 =group.random(), group.random(), group.random()
            cm1 = Com.com(self,pp_com,sk[1],e1)
            cm2 = Com.com(self,pp_com,sk[0]['seed'],e2)
            cm3 = Com.com(self,pp_com,sk[1]+sk[0]['seed'],e3)
            w = (sk[1],sk[0]['seed'],e1,e2,e3)
            ins = (ID,cm1,cm2,cm3,pp_com['G'],pp_com['H'])
            x_prf, pi_prf = Sigma.PRFprove.Prove(ins,w)
            search=0
            while search==0:
                for key, value in sk[0]['W'].items():
                    if ACC.MemVrf(self,pp_p,pk_R['M'][1],x,value[0])==True:
                        # The knowledge of a witness for the Accumulator
                        x = [pp['G1']**(-1), value[0], value[0]]
                        y = [pk_R['M'][2], pk_R['M'][0], pk_R['M'][2]**sk[0]['x']]
                        c_a = [pp['G1']**(-1), None, None]
                        c_b = [pk_R['M'][2], pk_R['M'][0], None]
                        (a,b,r,s,t)=NIZK.ParamGen(self,x,y,c_a,c_b)
                        GS_instance[1] = {'m':len(x), 'n':len(y), 'a':a, 'b':b}
                        GS_com[1] = NIZK.commit(self,GS_instance[1],mpk['CRS2'],x,y,r,s)
                        GS_proofs[1] = NIZK.prove(self,GS_instance[1],mpk['CRS2'],GS_com[1],x,y,r,s,t)
                        # SPS proof
                        x = [pp['G1']**sk[0]['seed'], value[0], sk[0]['sigma_sig']['R'], sk[0]['sigma_sig']['S'], pp['G1']]
                        y = [mpk['vk_sigA'][0],mpk['vk_sigA'][1], sk[0]['sigma_sig']['T']**(-1), pp['G2'], sk[0]['sigma_sig']['T']**(-1)]
                        c_a = [None, None, None, None, pp['G1']]
                        c_b = [mpk['vk_seqA'][0], mpk['vk_seqA'][1], None, pp['G2'], None]
                        (a,b,r,s,t)=NIZK.ParamGen(self,x,y,c_a,c_b)
                        GS_instance[2] = {'m':len(x), 'n':len(y), 'a':a, 'b':b}
                        GS_com[2] = NIZK.commit(self,GS_instance[2],mpk['CRS2'],x,y,r,s)
                        GS_proofs[2] = NIZK.prove(self,GS_instance[2],mpk['CRS2'],GS_com[2],x,y,r,s,t)
                        search=1
            sigma = DS.sign(self,mpk['pp'],sk[2],[m,pk_R['ID']])
            pi={'inst':GS_instance, 'pi':GS_proofs, 'com':GS_com, 'x_prf':x_prf, 'pi_prf':pi_prf}
        return {'sigma':sigma,'pi':pi }
    
    def PPSign(self,mpk,sk,pk_R,m,x,value):
        pp=mpk['pp']; (V, g, h, gs, hs, u, proof,seeds)=pk_R['rp']
        if SEQ.verify(self,mpk['pp'],mpk['vk_seqA'],pk_R['sigma_SEQ'],pk_R['M'])==1 and \
            NIZK.verifyProof(self,mpk['pp'],pk_R['inst'][1],mpk['CRS1'],pk_R['com'][1],pk_R['pi'][1])==True and \
                RangeProof.RanVerify(self.RangeProof,V, g, h, gs, hs, u, proof,seeds)==True and \
                    Sigma.PRFprove.Verify(pk_R['x_prf'],pk_R['pi_prf'])==1:
                    print("The receiver's public key is valid.\n")
                    pp=mpk['pp'];pp_com=mpk['pp_com']; GS_proofs={}; GS_instance={}; GS_com={}
                    ID = PRF.Gen(self,mpk['pp_com'],sk[0]['seed'],sk[1])
                    e1, e2, e3 =group.random(), group.random(), group.random()
                    cm1 = Com.com(self,pp_com,sk[1],e1)
                    cm2 = Com.com(self,pp_com,sk[0]['seed'],e2)
                    cm3 = Com.com(self,pp_com,sk[1]+sk[0]['seed'],e3)
                    w = (sk[1],sk[0]['seed'],e1,e2,e3)
                    ins = (ID,cm1,cm2,cm3,pp_com['G'],pp_com['H'])
                    x_prf, pi_prf = Sigma.PRFprove.Prove(ins,w)
                    # The knowledge of a witness for the Accumulator
                    x = [pp['G1']**(-1), value[0], value[0]]
                    y = [pk_R['M'][2], pk_R['M'][0], pk_R['M'][2]**sk[0]['x']]
                    c_a = [pp['G1']**(-1), None, None]
                    c_b = [pk_R['M'][2], pk_R['M'][0], None]
                    (a,b,r,s,t)=NIZK.ParamGen(self,x,y,c_a,c_b)
                    GS_instance[1] = {'m':len(x), 'n':len(y), 'a':a, 'b':b}
                    GS_com[1] = NIZK.commit(self,GS_instance[1],mpk['CRS2'],x,y,r,s)
                    GS_proofs[1] = NIZK.prove(self,GS_instance[1],mpk['CRS2'],GS_com[1],x,y,r,s,t)
                    # SPS proof
                    x = [pp['G1']**sk[0]['seed'],sk[0]['vk_sig'], value[0], sk[0]['sigma_sig']['R'], sk[0]['sigma_sig']['S'], pp['G1']]
                    y = [mpk['vk_sigA'][0],mpk['vk_sigA'][1], mpk['vk_sigA'][2], sk[0]['sigma_sig']['T']**(-1), pp['G2'], sk[0]['sigma_sig']['T']**(-1)]
                    c_a = [None, None, None, None, None, pp['G1']]
                    c_b = [mpk['vk_seqA'][0], mpk['vk_seqA'][1], mpk['vk_sigA'][2], None, pp['G2'], None]
                    (a,b,r,s,t)=NIZK.ParamGen(self,x,y,c_a,c_b)
                    GS_instance[2] = {'m':len(x), 'n':len(y), 'a':a, 'b':b}
                    GS_com[2] = NIZK.commit(self,GS_instance[2],mpk['CRS2'],x,y,r,s)
                    GS_proofs[2] = NIZK.prove(self,GS_instance[2],mpk['CRS2'],GS_com[2],x,y,r,s,t)
                    sigma = DS.sign(self,mpk['pp'],sk[2],[m,pk_R['ID']])
                    pi={'inst':GS_instance, 'pi':GS_proofs, 'com':GS_com, 'x_prf':x_prf, 'pi_prf':pi_prf}
                    return {'sigma':sigma,'pi':pi}
        

    def verify(self,mpk,pk,pk_R,m,sigma):
        pi_s=sigma['pi']
        if SEQ.verify(self,mpk['pp'],mpk['vk_seqA'],pk['sigma_SEQ'],pk['M'])==1 and \
            SEQ.verify(self,mpk['pp'],mpk['vk_seqA'],pk_R['sigma_SEQ'],pk_R['M'])==1 and \
                NIZK.verifyProof(self,mpk['pp'],pk['inst'][1],mpk['CRS1'],pk['com'][1],pk['pi'][1])==True and \
                    NIZK.verifyProof(self,mpk['pp'],pk['inst'][2],mpk['CRS1'],pk['com'][2],pk['pi'][2])==True and \
                        NIZK.verifyProof(self,mpk['pp'],pk['inst'][3],mpk['CRS1'],pk['com'][3],pk['pi'][3])==True and \
                            Sigma.PRFprove.Verify(pi_s['x_prf'],pi_s['pi_prf'])==1:
            return DS.verify(self,mpk['pp'],pk['vk_sig'],sigma['sigma'],[m,pk_R['ID']]) and \
                 NIZK.verifyProof(self,mpk['pp'],pi_s['inst'][1],mpk['CRS2'],pi_s['com'][1],pi_s['pi'][1])==True and \
                 NIZK.verifyProof(self,mpk['pp'],pi_s['inst'][2],mpk['CRS2'],pi_s['com'][2],pi_s['pi'][2])==True
