# 什么是元数据？
metadata.json文件包含了关于编译智能合约的信息。（参见Solidity文档）

metadata.json的内容如下：

    {
      "compiler": { "version": "0.8.4+commit.c7e474f2" },
      "language": "Solidity",
      "output": {
        // Application Binary Interface (ABI) describing how to interact with the contract,
        // and what functions and parameters are available.
        "abi": [
          {
            "inputs": [],
            "name": "retrieve",
            "outputs": [
              { "internalType": "uint256", "name": "", "type": "uint256" }
            ],
            "stateMutability": "view",
            "type": "function"
          },
          {
            "inputs": [
              { "internalType": "uint256", "name": "num", "type": "uint256" }
            ],
            "name": "store",
            "outputs": [],
            "stateMutability": "nonpayable",
            "type": "function"
          }
        ],
        // Developer documentation of each function (if available)
        "devdoc": {
          "details": "Store & retrieve value in a variable",
          "kind": "dev",
          "methods": {
            "retrieve()": {
              "details": "Return value ",
              "returns": { "_0": "value of 'number'" }
            },
            "store(uint256)": {
              "details": "Store value in variable",
              "params": { "num": "value to store" }
            }
          },
          "title": "Storage",
          "version": 1
        },
        // User documentation of each function (if available)
        "userdoc": { "kind": "user", "methods": {}, "version": 1 }
      },
      // Compilation settings to allow re-compilation
      "settings": {
        "compilationTarget": { "contracts/1_Storage.sol": "Storage" },
        "evmVersion": "istanbul",
        "libraries": {},
        "metadata": { "bytecodeHash": "ipfs" },
        "optimizer": { "enabled": false, "runs": 200 },
        "remappings": []
      },
      // Source files used 
      "sources": {
        "contracts/1_Storage.sol": {
          // keccak256 hash of the source file at the time of compilation
          "keccak256": "0xb6ee9d528b336942dd70d3b41e2811be10a473776352009fd73f85604f5ed206",
          "license": "GPL-3.0",
          // IPFS and Swarm hashes of the file
          // Calculated deterministically and allows download if published
          "urls": [
            "bzz-raw://fe52c6e3c04ba5d83ede6cc1a43c45fa43caa435b207f64707afb17d3af1bcf1",
            "dweb:/ipfs/QmawU3NM1WNWkBauRudYCiFvuFE1tTLHB98akyBvb9UWwA"
          ]
        }
      },
      "version": 1
    }

当一个智能合约被编译时，它的元数据文件会被生成，并且元数据文件的哈希值会被存储在字节码的末尾。

[0x00878Ac0D6B8d981ae72BA7cDC967eA0Fae69df4](https://goerli.etherscan.io/address/0x00878Ac0D6B8d981ae72BA7cDC967eA0Fae69df4#code) 的字节码（Görli）

    608060405234801561001057600080fd5b5061012f806100206000396000f3fe6080604052348015600f57600080fd5b506004361060325760003560e01c80632e64cec11460375780636057361d146051575b600080fd5b603d6069565b6040516048919060c2565b60405180910390f35b6067600480360381019060639190608f565b6072565b005b60008054905090565b8060008190555050565b60008135905060898160e5565b92915050565b60006020828403121560a057600080fd5b600060ac84828501607c565b91505092915050565b60bc8160db565b82525050565b600060208201905060d5600083018460b5565b92915050565b6000819050919050565b60ec8160db565b811460f657600080fd5b5056fea2646970667358221220c019e4614043d8adc295c3046ba5142c603ab309adeef171f330c51c38f1498964736f6c63430008040033

`a2646970667358221220c019e4614043d8adc295c3046ba5142c603ab309adeef171f330c51c38f1498964736f6c63430008040033` 这些字节是由Solidity编译器添加的。它以CBOR进行编码，默认包含Solidity版本和元数据哈希（取决于编译器版本和编译器偏好）。

让我们解码它：

`0033` = CBOR length: 51 Bytes

a2646970667358221220c019e4614043d8adc295c3046ba5142c603ab309adeef171f330c51c38f1498964736f6c6343000804

    {
      "ipfs": "0x1220c019e4614043d8adc295c3046ba5142c603ab309adeef171f330c51c38f14989",
      "solc": "0x000804"
    }

上述的IPFS哈希是十六进制字节。IPFS使用多基数，允许以不同的字符表示相同的字节集。

字节`0x1220c019e4614043d8adc295c3046ba5142c603ab309adeef171f330c51c38f14989` 将对应于此IPFS cid/hash: [QmbGXtNqvZYEcbjK6xELyBQGEmzqXPDqyJNoQYjJPrST9S](https://cid.ipfs.io/#QmbGXtNqvZYEcbjK6xELyBQGEmzqXPDqyJNoQYjJPrST9S)。

## 好的，那么怎么样呢🤷‍♂️
这个方法允许我们进行源代码验证。

由于源文件的哈希值包含在元数据文件中，所以即使源文件的一个字节发生改变，元数据的哈希值也会改变。这意味着，如果我们能够用给定的源文件编译一个合约，并且字节码+附加的元数据哈希值与链上合约完全相同，我们可以确定这是同一源文件和同一编译设置的字节对字节的匹配。

这就是我们在Sourcify所做的。想了解更多信息，请查看Sourcify文档文章。