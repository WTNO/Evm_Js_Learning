### 代码
```sol
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract Simple {
    uint256 public val1;
    uint256 public val2;

    constructor() {
        val2 = 3;
    }

    function set(uint256 _param) external {
        val1 = _param;
    }
}
```

### 编译
#### 语句
    solc.exe Simple.sol --bin --abi --optimize -o . --overwrite


#### 生成文件
- Simple.bin
  ```
  608060405234801561000f575f80fd5b50600360015560bc806100215f395ff3fe6080604052348015600e575f80fd5b5060043610603a575f3560e01c806360fe47b114603e57806395cacbe014604f578063c82fdf36146069575b5f80fd5b604d60493660046070565b5f55565b005b605760015481565b60405190815260200160405180910390f35b60575f5481565b5f60208284031215607f575f80fd5b503591905056fea26469706673582212208d807bbbc0990d27316ce4f561b1e1430b7e128e9313f2e109eaf6ac78edd70864736f6c63430008150033
  ```
- Simple.abi
    ```json
    [
        {
          "inputs": [

          ],
          "stateMutability": "nonpayable",
          "type": "constructor"
        },
        {
          "inputs": [
            {
              "internalType": "uint256",
              "name": "_param",
              "type": "uint256"
            }
          ],
          "name": "set",
          "outputs": [

          ],
          "stateMutability": "nonpayable",
          "type": "function"
        },
        {
          "inputs": [

          ],
          "name": "val1",
          "outputs": [
            {
              "internalType": "uint256",
              "name": "",
              "type": "uint256"
            }
          ],
          "stateMutability": "view",
          "type": "function"
        },
        {
          "inputs": [

          ],
          "name": "val2",
          "outputs": [
            {
              "internalType": "uint256",
              "name": "",
              "type": "uint256"
            }
          ],
          "stateMutability": "view",
          "type": "function"
        }
    ]
    ```


### 分析
字节码

    608060405234801561000f575f80fd5b50600360015560bc806100215f395ff3fe6080604052348015600e575f80fd5b5060043610603a575f3560e01c806360fe47b114603e57806395cacbe014604f578063c82fdf36146069575b5f80fd5b604d60493660046070565b5f55565b005b605760015481565b60405190815260200160405180910390f35b60575f5481565b5f60208284031215607f575f80fd5b503591905056fea26469706673582212208d807bbbc0990d27316ce4f561b1e1430b7e128e9313f2e109eaf6ac78edd70864736f6c63430008150033

分为两个部分
1. 初始化代码片段

        608060405234801561000f575f80fd5b50600360015560bc806100215f395ff3fe

2. 要部署到区块链的代码

        6080604052348015600e575f80fd5b5060043610603a575f3560e01c806360fe47b114603e57806395cacbe014604f578063c82fdf36146069575b5f80fd5b604d60493660046070565b5f55565b005b605760015481565b60405190815260200160405180910390f35b60575f5481565b5f60208284031215607f575f80fd5b503591905056fea26469706673582212208d807bbbc0990d27316ce4f561b1e1430b7e128e9313f2e109eaf6ac78edd70864736f6c63430008150033


合约通过交易进行部署，在其中：
- 目标地址未指定。
- 数据是初始化代码片段，其中包括合约的二进制代码。这是编译器生成的
*.bin文件中的输出。











