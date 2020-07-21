# HEaaS - HE(homomorphic encryption) as a service
## Quick start
This repo now demostrate how to use HE(homomorphic encryption) for multiparty computation to do financial exchange without unnecessary data reveal.

Ask and Bid will exchange limit price of an order as an encrypted ciphertext, credit will be kept as secret in server during substraction computation, credit will be stored only in Server side, while the exchange only revealing distance of credits with thirdparty bids

```
                 {                         {
                   LimitPrice(ciphertext)    LimitPrice(ciphertext)
                 }                           Credit(ciphertext)
   +------------+           +------------+ }         +-------------+
   |            |           |            |           |             |
   |   client   +-- Ask --->+   server   +<-- Bid ---+ third_party |
   |            |           |            |           |             |
   +------------+           +------------+           +-------------+
          ^                     Credit(ciphertext)
          |                        +
          |                        |
          |                        |
          +---- EligibleBid -------+

               {
                LimitPriceDistance = Ask.LimitPrice - Bid.LimitPrice (invisible to server/third_party)
                CreditDistance = Credit - Bid.Credit (invisible to server/third_party)
               }
```


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

Completing bids collection:

```
total bid number: 3
bids: []main.Bid{main.Bid{LimitPriceDistance:-10, CreditDistance:-100}, main.Bid{LimitPriceDistance:0, CreditDistance:100}, main.Bid{LimitPriceDistance:10, CreditDistance:0}}
```
