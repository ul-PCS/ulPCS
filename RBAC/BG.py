from charm.toolbox.pairinggroup import PairingGroup, ZR, G1, G2, pair
from charm.core.engine.util import serializeDict,serializeObject

debug = False


class BG():
    def __init__(self, groupObj):
        global util, group 
        group = groupObj
        
    def Gen(self):
        g1,g2=group.random(G1),group.random(G2)
        return {'G1':g1,'G2':g2,'GT':pair(g1,g2)}

'''
group=PairingGroup('BN254')
BG=BG(group)
pp=BG.Gen()
file = open("Python.txt", "w") 
#convert variable to string
str = repr(serializeObject(pp['G2'],group))
file.write(str)
file.close()
g1=len(serializeObject(pp['G2'],group))
total=sum([len(x) for x in serializeDict(pp, group).values()])
print(total)
print(g1)
'''