# HEaaS - HE(homomorphic encryption) as a service
## Quick start
This repo now demostrate how to use HE(homomorphic encryption) for multiparty computation to do financial exchange without unnecessary data reveal 
Ask and Bid will exchange limit price of an order but will keep credit as a encrypted ciphertext during substraction computation, credit will be stored only in Server side, while the exchange only revealing distance of credits with thirdparty bids

Install: 

```
make
export PATH=$PATH:$(pwd)/bin/github.com/LabZion/HEaaS/
```

Run server

```
> server

============================================
Homomorphic computations on batched integers
============================================

Parameters : N=8192, T=65929217, Q = 218 bits, sigma = 3.200000

INFO : 2020/07/20 23:29:14.287851 server.go:342: HEaaS Serve on Port localhost:10000
```

Run client:

```
> client

Saving Ask.
Collecting Bids. Press <Enter> to close and getEligibleBids
```

Run third_party:

```
> third_party

2020/07/20 23:30:51 public key sha256: e662baf058b62db2713c318d2bebf2e7ff431bd39a19eb4af945796dc3153054
```
