# UnLinkable-PCS (ul-PCS)

Our system enables to enforce a pre-determined policy on signatures while removing the links between the users' inititives in the network.

The structure of this repository is as follows:

* `RBAC`: Python code to emulate the proposed Role-based UL-PCS scheme. Please execute test.py for testing.

	- Acc.py: Python code to emulate the Karantaidou and Baldimtsi's accumulator scheme.
	- BG.py: Python code to emulate a bilinear-pairing group.
	- BLS.py: Python code to emulate BLS signatures.
	- Bulletproof.py: Python code to emulate the Range-proof.
	- GS.py: Python code to emulate the Groth-Sahai proof systems.
	- main.py: Python code to emulate the generic construction.
	- Pedersen.py: Python code to emulate a Pedersen Commitment.
	- policy.py: Python code to emulate a role-based policy maker algorithm.
  	- PRF.py: Python code to emulate the Dodis-Yampolskiy PRF.
  	- Sigma.py: Python code to emulate the described Sigma protocols.
	- SPS.py: Python code to emulate Fuchsbauer,Hanser and Slamanig structure-preserving signature.
	- SPSEQ.py: Python code to emulate Fuchsbauer,Hanser and Slamanig structure-preserving signature on equivalence classes.
	- test.py: To test the code.
  
* `SeparablePolicies`: Python code to emulate the proposed UL-PCS scheme with Separable policies. Please execute test.py for testing.
	- BG.py: Python code to emulate a bilinear-pairing group.
	- BLS.py: Python code to emulate BLS signatures.
	- Bulletproof.py: Python code to emulate the Range-proof.
	- ElGamal.py: Python code to emulate the ElGamal encryption.
	- GS.py: Python code to emulate the Groth-Sahai proof systems.
	- main.py: Python code to emulate the generic construction.
	- Pedersen.py: Python code to emulate a Pedersen Commitment.
	- policy.py: Python code to emulate a role-based policy maker algorithm.
  	- PRF.py: Python code to emulate the Dodis-Yampolskiy PRF.
  	- Sigma.py: Python code to emulate the described Sigma protocols.
	- SPS.py: Python code to emulate Fuchsbauer,Hanser and Slamanig structure-preserving signature.
	- test.py: To test the code.
 
## Instruction for Ubuntu 22.04

### Prerequisite Packages:
```
pip3 install -r /path/to/requirements.txt
```

### Install the pbc library:
Install [pbc](https://crypto.stanford.edu/pbc/download.html) library.

```
wget http://crypto.stanford.edu/pbc/files/pbc-0.5.14.tar.gz
tar xf pbc-0.5.14.tar.gz
cd pbc-0.5.14
sudo ./configure.sh
sudo make
sudo make install
sudo make test
```
### Charm-crypto needs to be installed manually.

- Clone charm-crypto from https://github.com/JHUISI/charm.git.
Do not use the releases, they do not work. Install from the repo by running the following commands.
```
git clone https://github.com/JHUISI/charm.git
cd charm
sudo ./configure.sh
sudo make
sudo make install
sudo make test
```

Make sure to set the extra `LDFLAGS` so that charm-crypto finds pbc as shown above.
- Note that python 3.8 and above seems to be broken for charm-crypto, see [this issue](https://github.com/JHUISI/charm/issues/239).
