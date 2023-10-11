# 结构与流程
## 2020年版本的evm结构
![image](./img/20200505173119187.png)

## 大致流程
编写合约 > 生成abi > 解析abi得出指令集 > 指令通过opcode来映射成操作码集 > 生成一个operation[256]

## 以太坊虚拟机的工作流程：
由solidity语言编写的智能合约，通过编译器编译成bytecode，之后发到以太坊上，以太坊底层通过evm模块支持合约的执行和调用，调用时根据合约获取代码，即合约的字节码，生成环境后载入到 EVM 执行。

# 源码解析
## opcodes.go
文件`opcodes.go`中定义了所有的OpCode，该值是一个byte，合约编译出来的bytecode中，一个OpCode就是上面的一位。opcodes按功能分为9组，以第一位十六进制数来分类，例如0x1x,0x2x。

例如第一组为 算术 操作
```go
// 0x0 range - arithmetic ops.
const (
	STOP       OpCode = 0x0
	ADD        OpCode = 0x1
	MUL        OpCode = 0x2
	SUB        OpCode = 0x3
	DIV        OpCode = 0x4
	SDIV       OpCode = 0x5
	MOD        OpCode = 0x6
	SMOD       OpCode = 0x7
	ADDMOD     OpCode = 0x8
	MULMOD     OpCode = 0x9
	EXP        OpCode = 0xa
	SIGNEXTEND OpCode = 0xb
)
```




































