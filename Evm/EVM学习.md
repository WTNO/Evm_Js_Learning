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

可以使用表格来总结

|opCodeRange|对应操作|
|---|---|
|0x0	|算术操作|
|0x10	|比较操作|
|0x20	|加密操作|
|0x30	|状态闭包|
|0x40	|区块操作|
|0x50	|存储和执行操作|
|0x60	|压栈操作|
|0x80	|克隆操作|
|0x90	|交换操作|
|0xa0	|日志操作|
|0xf0	|闭包|

实现了判断能否压栈、操作码的byte类型和string类型互相转换的函数或接口。

core/vm/opcodes.go
```go
func StringToOp(str string) OpCode  
func (op OpCode) String() string  
func (op OpCode) IsPush() bool
```

common/types.go
```go
AddressLength = 20
HashLength = 32
type Address [AddressLength]byte
type bitvec [ ]byte
// Hash represents the 32 byte Keccak256 hash of arbitrary data.
type Hash [HashLength]byte
```

## contract.go
### 合约的结构
```go
// Contract代表状态数据库中的以太坊合约。它包含
// 合约代码，调用参数。Contract实现了ContractRef
type Contract struct {
	// CallerAddress是初始化这个
	// 合约的调用者的结果。然而，当"call方法"被委托时，这个值
	// 需要被初始化为调用者的调用者。
	CallerAddress common.Address
	caller        ContractRef
	self          ContractRef

	jumpdests map[common.Hash]bitvec // JUMPDEST分析的汇总结果。
	analysis  bitvec                 // JUMPDEST分析的本地缓存结果

	Code     []byte             // 代码字节数组
	CodeHash common.Hash
	CodeAddr *common.Address
	Input    []byte

	Gas   uint64
	value *big.Int
}
```

### 构造方法
```go
// NewContract 返回一个新的合约环境用于执行 EVM。
func NewContract(caller ContractRef, object ContractRef, value *big.Int, gas uint64) *Contract {
	c := &Contract{CallerAddress: caller.Address(), caller: caller, self: object}

	if parent, ok := caller.(*Contract); ok {
		// 如果可用，从父上下文复用 JUMPDEST 分析。
		c.jumpdests = parent.jumpdests
	} else {
		c.jumpdests = make(map[common.Hash]bitvec)
	}

	// Gas 应该是一个指针，这样它可以在运行中安全地减少
	// 这个指针将会脱离状态转换
	c.Gas = gas
	// 确保设定一个值
	c.value = value

	return c
}
```
该函数构造了新的合约，且如果是被合约调用，则复用该合约的 jumpdests

### validJumpdest
检验代码跳转是否合法
```go
func (c *Contract) validJumpdest(dest *uint256.Int) bool {
    // 返回dest低64位，并返回一个布尔值，表示是否发生了溢出。
	udest, overflow := dest.Uint64WithOverflow()
	// 程序计数器不能超过代码的长度，当然也不能大于63位。
	// 在这种情况下，不需要检查JUMPDEST。
	if overflow || udest >= uint64(len(c.Code)) {
		return false
	}
	// 只允许JUMPDEST作为目的地
	if OpCode(c.Code[udest]) != JUMPDEST {
		return false
	}
	return c.isCode(udest)
}
```

```go
// 如果提供的PC位置是一个实际的操作码，而不是PUSHN操作后的数据段，
// 那么它会返回true。
func (c *Contract) isCode(udest uint64) bool {
	// 我们已经有一个分析了吗？
	if c.analysis != nil {
		return c.analysis.codeSegment(udest)
	}
	// 我们已经有一个合约哈希了吗？
	// 如果我们有哈希，那就意味着它是一个'常规'合约。对于常规
	// 合约（不是临时的initcode），我们在map中存储分析
	if c.CodeHash != (common.Hash{}) {
		// 父上下文是否有分析？
		analysis, exist := c.jumpdests[c.CodeHash]
		if !exist {
			// 进行分析并保存在父上下文中
			// 我们不需要将其存储在c.analysis中
			analysis = codeBitmap(c.Code)
			c.jumpdests[c.CodeHash] = analysis
		}
		// 也把它放在当前合约中以便更快地访问
		c.analysis = analysis
		return analysis.codeSegment(udest)
	}
	// 我们没有代码哈希，很可能是一段尚未在状态trie中的initcode。
	// 在这种情况下，我们进行分析，并本地保存，这样
	// 我们就不必为执行中的每一条JUMP指令重新计算
	// 但是，我们不会把它保存在父上下文中
	if c.analysis == nil {
		c.analysis = codeBitmap(c.Code)
	}
	return c.analysis.codeSegment(udest)
}
```

### AsDelegate
`AsDelegate`将合约设置为委托调用并返回当前合同（用于链式调用）
```go
// AsDelegate 将合约设置为委托调用并返回当前合约（用于链式调用）
func (c *Contract) AsDelegate() *Contract {
	// 注意：调用者必须始终是一个合约。调用者不应该是除合约之外的其他东西。
	parent := c.caller.(*Contract)
	c.CallerAddress = parent.CallerAddress
	c.value = parent.value

	return c
}
```

## stack.go
为了应对高并发情况下的栈资源问题，代码中创建了 栈池 来保存一些被创造但未使用的栈空间。
```go
var stackPool = sync.Pool{
	New: func() interface{} {
		return &Stack{data: make([]uint256.Int, 0, 16)}
	},
}
```

## memory.go
### 数据结构
```go
// Memory 为以太坊虚拟机实现了一个简单的内存模型。
type Memory struct {
	store       []byte // 存储
	lastGasCost uint64 // 上一次的燃气费用
}
```

为以太坊虚拟机提供一个简单存储的模型
```go
func (m *Memory) Set(offset, size uint64, value []byte) 
func (m *Memory) Set32(offset uint64, val *uint256.Int) 
func (m *Memory) Resize(size uint64)
func (m *Memory) GetCopy(offset, size int64) (cpy []byte)  // 截取切片中的一段 (offset,offset+size)
func (m *Memory) GetPtr(offset, size int64)  // 返回切片中的一段的指针
func (m *Memory) Len() int
func (m *Memory) Data() []byte
```

## memory_table.go
衡量一些操作所消耗的内存大小同时判断是否会发生栈溢出，如keccak256、callDataCopy、MStore等

## EVM.go
### EVM结构
evm是以太坊虚拟机基础对象，提供工具处理对应上下文中的交易。运行过程中一旦发生错误，状态会回滚并且不退还gas费用，运行中产生的任务错误都会被归结为代码错误。
```go
// EVM是以太坊虚拟机的基础对象，提供了在给定状态下运行合约所需的工具，
// 并提供了相应的上下文。需要注意的是，任何通过调用生成的错误都应被视为
// 一种回滚状态并消耗所有气体的操作，不应进行任何特定错误的检查。
// 解释器确保任何生成的错误都被视为错误的代码。
//
// EVM永远不应被重用，且不是线程安全的。
type EVM struct {
	// Context提供辅助的区块链相关信息
	Context BlockContext
	TxContext
	// StateDB提供访问底层状态的权限
	StateDB StateDB
	// Depth是当前的调用堆栈
	depth int

	// chainConfig包含了当前链的信息
	chainConfig *params.ChainConfig
	// chain rules包含了当前时代的链规则
	chainRules params.Rules
	// 用于初始化evm的虚拟机配置选项
	Config Config
	// 全局的（在此上下文中）以太坊虚拟机
	// 在整个交易执行过程中使用。
	interpreter *EVMInterpreter
	// abort用于中止EVM调用操作
	abort atomic.Bool
	// callGasTemp保存当前调用可用的gas。这是必要的，因为
	// 可用的gas是按照63/64规则在gasCall*中计算的，然后在opCall*中应用。
	callGasTemp uint64
}
```







