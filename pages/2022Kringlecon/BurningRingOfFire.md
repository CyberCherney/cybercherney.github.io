---
layout: kringlecon2022
title: "Burning Ring of Fire"
author: "Andrew Cherney"
date: 2023-01-15 19:52:13
tags: 
- kringlecon 
- blockchain 
- smart-contract
---
## Blockchain Divination
___
___
Use the Blockchain Explorer in the Burning Ring of Fire to investigate the contracts and transactions on the chain. At what address is the KringleCoin smart contract deployed? Find hints for this objective hidden throughout the tunnels.

***

The smart contract would be created early in the process, and through some intuition and hints is probably called something like KringleCoin.sol

it's block number 4 that mentions the KringleCoin
check which address it is to

0xc27A2D3DE339Ce353c0eFBa32e948a88F1C86554

***



## Buy a Hat
___
***
Travel to the Burning Ring of Fire and purchase a hat from the vending machine with KringleCoin. Find hints for this objective hidden throughout the tunnels.

***

Need to pre-approve a transfer to a wallet address

To purchase this hat you must:

    Use a KTM to pre-approve a 10 KC transaction to the wallet address: 0x5d3DC98f7515B2042cbEDb667388b0B3689A1554
    Return to this kiosk and use Hat ID: 27 to complete your purchase.

TransactionID: 0x621c2aa6e8f789b482658c6d683f3f8f9064917cd1b4b0c752e9d30a1aa56c9f
Block 102863

***



## Exploit a Smart Contract
***
___
**WalletAddress**: 0xAD40A635C020bA5A6CDc911984e1607552e964B4

**Key**: 0x2da97a65b6d6b26181dc5d39d1293be5e33e07cdc46f87f62007fc85abb85284

Exploit flaws in a smart contract to buy yourself a Bored Sporc NFT. Find hints for this objective hidden throughout the tunnels.

***

Read Merkle Tree and it seemed important, inside of hint as well. Mentions Professor Petabyte. 

Merkle Trees are effectively ways to use a calculated hash to prove a specific input is in the original list of inputs if you have the input you want to check and the root hash. There are no duplicate values for input locations. 

In order to prove that my address is in a presale, I would need that address to eventually calculate the root hash


In inspect element I found me a hard coded root hash of 0x52cfdfdcba8efebabd9ecc2c60e6f482ab30bdc6acf8f9bd0600de83701e15f1

Request sends this data:

```
Proof	"0xa145d7d3f1337f59442cdac387a4c4dc, 0xef65c18b1c3380460e25c13c1fdafe11"
Root	"0x52cfdfdcba8efebabd9ecc2c60e6f482ab30bdc6acf8f9bd0600de83701e15f1"
Session	"d9f8d1f4-1688-413b-9424-2a6a86937943"
Validate	"false"
WalletID	"0xAD40A635C020bA5A6CDc911984e1607552e964B4"
```

That root hash is SHA256  

[https://github.com/QPetabyte/Merkle_Trees](https://github.com/QPetabyte/Merkle_Trees)

the above github lets you make merkle trees
change the allowlist to your wallet address

Root: 0x6c671a2ed92337735a32ed113f7d99171bbd54d9f8a842d5edac0fbbac8969dd
Proof: ['0xcb271ff906bfc290fa01af3d54f5e6eb28f1370b16e6b73522a8915ad231f1e8']

and voila, after changing the root hash in the request we are validated
follow the rest of the guide on the sporc site to buy a jpeg

(100 KC transfer to 0xe8fC6f6a76BE243122E3d01A1c544F87f1264d3a)
then repeat process and grab a sporc

***
Success! You are now the proud owner of BSRS Token #000578. You can find more information at https://boredsporcrowboatsociety.com/TOKENS/BSRS578, or check it out in the gallery!
Transaction: 0x9c6b779ef28e8accda7f3687de3a5a8f43332a7bd23d68bf6c4ad022447e31b9, Block: 103115

Remember: Just like we planned, tell everyone you know to BUY A BoredSporc.
When general sales start, and the humans start buying them up, the prices will skyrocket, and we all sell at once!

The market will tank, but we'll all be rich!!!

***

![BSRS578.png](/pages/2022Kringlecon/BSRS578.png)






