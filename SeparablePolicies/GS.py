from charm.toolbox.pairinggroup import G1,G2,GT,pair
from charm.toolbox.secretutil import SecretUtil

class GS():
    def __init__(self, groupObj):
        global util, group
        util = SecretUtil(groupObj)
        group = groupObj

    def sampleParams(self,pp):
        par_c = {}; r1={}; r2={}
        for i in range(2):
            for j in range(2):
                for k in range(2):
                    par_c[i,j,k] = group.random()
        assert not (par_c[0,0,0] == 0 and
                    par_c[0,1,0] == 0 and
                    par_c[0,0,1] == par_c[0,1,1])
        assert not (par_c[1,0,0] == 0 and
                    par_c[1,1,0] == 0 and
                    par_c[1,0,1] == par_c[1,1,1])
        for i in range(2):
            for j in range(2):
                r1[i,j] = pp['G1']**par_c[0,i,j]
                r2[i,j] = pp['G2']**par_c[1,i,j]
        return {'u1v1':r1, 'u2v2':r2}
    def ParamGen(self,x,y,c_a,c_b):
        m = len(x); n = len(y)
        a = list(map(lambda c: (None,-1) if c == None else (c,0), c_a))
        b = list(map(lambda c: (None,-1) if c == None else (c,0), c_b))
        r = list(map(lambda i: [0,0] if c_a[i] != None else [group.random(),group.random()], range(m)))
        s = list(map(lambda i: [0,0] if c_b[i] != None else [group.random(),group.random()], range(n)))
        t = [[group.random(),group.random()],[group.random(),group.random()]]
        return (a,b,r,s,t)
    def commit(self,inst,params,x,y,r,s):
        com_c = {}; com_d = {}
        for i in range(inst['m']):
            com_c[i]=group.init(G1, 1)
        for i in range(inst['n']):
            com_d[i]=group.init(G2, 1)

        for i in range(inst['m']):
            for vv in range(2):
                com_c[i,vv] = params['u1v1'][0,vv]**r[i][0] 
            com_c[i,1]*=x[i]

        for i in range(inst['n']):
            for vv in range(2):
                com_d[i,vv] = params['u2v2'][0,vv]**s[i][0] 
            com_d[i,1]*=y[i]
        return {'com_c':com_c,'com_d':com_d}


    def prove(self,inst,params,com,x,y,r,s,ts):
        theta = {}; phi={}
        for i in range(2):
            for vv in range(2):
                theta[i,vv]=group.init(G1,1); phi[i,vv]=group.init(G2,1)
        for i in range(2):
            for vv in range(2):
                for j in range(2):
                    theta[i,vv] *= params['u1v1'][j,vv]**ts[i][j]

            for j in range(inst['n']):
                for k in range(inst['m']):
                    theta[i,1] *= (x[k])**s[j][i]
        for vv in range(2):
            for i in range(2):
                for j in range(inst['m']):
                    for k in range(inst['n']):
                        phi[i,vv] *= (com['com_d'][k,vv])**r[j][i]
                for j in range(2):
                    phi[i,vv] *= (params['u2v2'][j,vv]**ts[j][i])**(-1)
        return {'theta':theta,'phi':phi}

    def verifyProof(self,pp,inst,params,com,proof):
        p1 = {};p2 = {}
        for vv1 in range(2):
            for vv2 in range(2):
                for i in range(inst['m']):
                    p1[i] = com['com_c'][i,vv1]
                    p2[i] = group.init(G2, 1)
                    for j in range(inst['n']):
                        p2[i]*=com['com_d'][j,vv2]

                p1[inst['m']] = params['u1v1'][vv1,vv1]**(-1)
                p2[inst['m']] = proof['phi'][vv1,vv2]
                p1[inst['m']+1] = proof['theta'][vv1,vv1]
                p2[inst['m']+1] = params['u2v2'][vv1,vv2]**(-1)

                pairing_v = group.init(GT,1)
                for i in range(inst['m']+2):
                    pairing_v *= pair(p1[i],p2[i])
                if pairing_v == pp['GT']:
                    return False
        return True
