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

#### 区块上下文
前三个变量为函数类型，依次作用为 查询转账者账户是否有充足ether支持转账操作、转账操作、获取第n个区块的hash

其余为一些基础的区块信息，如币基交易地址、Gaslimit、区块高、时间戳、难度值和基础费用

区块一旦创建，区块信息不可以被修改
```go
// BlockContext为EVM提供辅助信息。一旦提供，就不应该修改。
type BlockContext struct {
	// CanTransfer返回账户是否包含足够的以太币进行转账
	CanTransfer CanTransferFunc
	// Transfer从一个账户转移以太币到另一个账户
	Transfer TransferFunc
	// GetHash返回对应于n的哈希
	GetHash GetHashFunc

	// 区块信息
	Coinbase    common.Address // 提供COINBASE的信息
	GasLimit    uint64         // 提供GASLIMIT的信息
	BlockNumber *big.Int       // 提供NUMBER的信息
	Time        uint64         // 提供TIME的信息
	Difficulty  *big.Int       // 提供DIFFICULTY的信息
	BaseFee     *big.Int       // 提供BASEFEE的信息
	Random      *common.Hash   // 提供PREVRANDAO的信息
}
```

#### 交易上下文
```go
// TxContext为EVM提供关于交易的信息。
// 所有字段在交易之间都可能发生变化。
type TxContext struct {
	// 消息信息
	Origin     common.Address // 提供ORIGIN的信息
	GasPrice   *big.Int       // 提供GASPRICE的信息
	BlobHashes []common.Hash  // 提供BLOBHASH的信息
}
```

Origin是什么，就是第一个交易

### evm方法
#### 创建evm
只能用一次
```go
// NewEVM 返回一个新的 EVM。返回的 EVM 不是线程安全的，应该
// 只被使用*一次*。
func NewEVM(blockCtx BlockContext, txCtx TxContext, statedb StateDB, chainConfig *params.ChainConfig, config Config) *EVM {
	evm := &EVM{
		Context:     blockCtx,
		TxContext:   txCtx,
		StateDB:     statedb,
		Config:      config,
		chainConfig: chainConfig,
		chainRules:  chainConfig.Rules(blockCtx.BlockNumber, blockCtx.Random != nil, blockCtx.Time),
	}
	evm.interpreter = NewEVMInterpreter(evm)
	return evm
}
```

#### Reset
```go
// Reset用新的交易上下文重置EVM。这不是线程安全的，应非常谨慎地执行。
func (evm *EVM) Reset(txCtx TxContext, statedb StateDB) {
	evm.TxContext = txCtx
	evm.StateDB = statedb
}
```

#### Cancel & Cancelled
能够通过原子的修改abort使得取消任何evm操作
```go
// Cancel 取消任何正在运行的 EVM 操作。这个方法可以被并发调用，
// 并且多次调用是安全的。
func (evm *EVM) Cancel() {
	evm.abort.Store(true)
}

// Cancelled 如果 Cancel 方法被调用过，那么返回 true
func (evm *EVM) Cancelled() bool {
	return evm.abort.Load()
}
```

## interpreter.go
### 数据结构
#### Config
解释器中会有一个配置结构体，能够选择debug模式，包含追踪操作码的evm日志，一些eip提议的配置，evm跳表
```go
// Config 是解释器的配置选项
type Config struct {
	Tracer                  EVMLogger // 操作码记录器
	NoBaseFee               bool      // 强制将 EIP-1559 的基础费用设为 0 (对于价格为0的调用需要)
	EnablePreimageRecording bool      // 启用 SHA3/keccak 预映像的记录
	ExtraEips               []int     // 需要启用的额外 EIPS
}
```

#### ScopeContext
```go
// ScopeContext 包含每次调用的内容，例如堆栈和内存，
// 但不包含像 pc 和 gas 这样的瞬态变量
type ScopeContext struct {
	Memory   *Memory     // 内存
	Stack    *Stack      // 堆栈
	Contract *Contract   // 合约
}
```

#### EVMInterpreter
解释器结构，包含evm指针，hasher，是否只读，返回数据信息
```go
// EVMInterpreter 代表一个 EVM 解释器
type EVMInterpreter struct {
	evm   *EVM              // EVM 实例
	table *JumpTable        // 跳转表

	hasher    crypto.KeccakState // Keccak256 哈希实例，跨操作码共享
	hasherBuf common.Hash        // Keccak256 哈希结果数组，跨操作码共享

	readOnly   bool   // 是否在状态修改时抛出异常
	returnData []byte // 上一次 CALL 的返回数据，供后续重用
}
```

### 方法
#### 构造方法
传入evm~~和配置信息构建新的解释器，根据配置信息设置该链的规则，如遵循eip158、eip150提议。~~
```go
// NewEVMInterpreter 返回 Interpreter 的一个新实例。
func NewEVMInterpreter(evm *EVM) *EVMInterpreter {
	// 如果跳转表没有初始化，我们设置一个默认的。
	var table *JumpTable
	switch {
	case evm.chainRules.IsCancun:
		table = &cancunInstructionSet
	case evm.chainRules.IsShanghai:
		table = &shanghaiInstructionSet
	case evm.chainRules.IsMerge:
		table = &mergeInstructionSet
	case evm.chainRules.IsLondon:
		table = &londonInstructionSet
	case evm.chainRules.IsBerlin:
		table = &berlinInstructionSet
	case evm.chainRules.IsIstanbul:
		table = &istanbulInstructionSet
	case evm.chainRules.IsConstantinople:
		table = &constantinopleInstructionSet
	case evm.chainRules.IsByzantium:
		table = &byzantiumInstructionSet
	case evm.chainRules.IsEIP158:
		table = &spuriousDragonInstructionSet
	case evm.chainRules.IsEIP150:
		table = &tangerineWhistleInstructionSet
	case evm.chainRules.IsHomestead:
		table = &homesteadInstructionSet
	default:
		table = &frontierInstructionSet
	}
	var extraEips []int
	if len(evm.Config.ExtraEips) > 0 {
		// 对跳转表进行深拷贝以防止在其他表中修改操作码
		table = copyJumpTable(table)
	}
	for _, eip := range evm.Config.ExtraEips {
		if err := EnableEIP(eip, table); err != nil {
			// 禁用它，这样调用者可以检查它是否被激活
			log.Error("EIP激活失败", "eip", eip, "错误", err)
		} else {
			extraEips = append(extraEips, eip)
		}
	}
	evm.Config.ExtraEips = extraEips
	return &EVMInterpreter{evm: evm, table: table}
}
```

#### Run
```go
// 运行循环并使用给定的输入数据评估合约的代码，返回
// 返回的字节切片和一个错误（如果有的话）。
//
// 重要的是注意，解释器返回的任何错误都应该被
// 视为撤销并消耗所有燃气的操作，除非是
// ErrExecutionReverted表示撤销并保留剩余的燃气。
func (in *EVMInterpreter) Run(contract *Contract, input []byte, readOnly bool) (ret []byte, err error) {
	// 增加调用深度，限制为1024
	in.evm.depth++
	defer func() { in.evm.depth-- }()

	// 确保只有在我们还没有处于只读状态时才设置只读。
	// 这也确保了子调用不会删除只读标志。
	if readOnly && !in.readOnly {
		in.readOnly = true
		defer func() { in.readOnly = false }()
	}

	// 重置上一个调用的返回数据。保留旧缓冲区并不重要
	// 因为每个返回调用都会返回新的数据。
	in.returnData = nil

	// 如果没有代码，就不要执行。
	if len(contract.Code) == 0 {
		return nil, nil
	}

	var (
		op          OpCode        // 当前操作码
		mem         = NewMemory() // 绑定内存
		stack       = newstack()  // 本地栈
		callContext = &ScopeContext{
			Memory:   mem,
			Stack:    stack,
			Contract: contract,
		}
		// 出于优化的原因，我们使用uint64作为程序计数器。
		// 理论上可以超过2^64。YP将PC定义为uint256。实际上，这是不可能的。
		pc   = uint64(0) // 程序计数器
		cost uint64
		// 跟踪器使用的副本
		pcCopy  uint64 // 需要延迟的EVMLogger
		gasCopy uint64 // 为EVMLogger记录执行前剩余的燃气
		logged  bool   // 延迟的EVMLogger应忽略已经记录的步骤
		res     []byte // 操作码执行函数的结果
		debug   = in.evm.Config.Tracer != nil
	)
	// 不要移动这个延迟函数，它放在capturestate-deferred方法之前，
	// 所以它在执行之后：capturestate需要在返回到池之前的栈
	defer func() {
		returnStack(stack)
	}()
	contract.Input = input

	if debug {
		defer func() {
			if err != nil {
				if !logged {
					in.evm.Config.Tracer.CaptureState(pcCopy, op, gasCopy, cost, callContext, in.returnData, in.evm.depth, err)
				} else {
					in.evm.Config.Tracer.CaptureFault(pcCopy, op, gasCopy, cost, callContext, in.evm.depth, err)
				}
			}
		}()
	}
	// 解释器主运行循环（上下文）。这个循环运行直到显式的STOP, RETURN或SELFDESTRUCT被执行，
	// 在执行操作过程中出现错误，或者父上下文设置了done标志。
	for {
		if debug {
			// 捕获执行前的值以进行跟踪。
			logged, pcCopy, gasCopy = false, pc, contract.Gas
		}
		// 从跳转表中获取操作，并验证栈以确保有足够的栈项可用来执行操作。
		op = contract.GetOp(pc)
		operation := in.table[op]
		cost = operation.constantGas // 用于跟踪
		// 验证栈
		if sLen := stack.len(); sLen < operation.minStack {
			return nil, &ErrStackUnderflow{stackLen: sLen, required: operation.minStack}
		} else if sLen > operation.maxStack {
			return nil, &ErrStackOverflow{stackLen: sLen, limit: operation.maxStack}
		}
		if !contract.UseGas(cost) {
			return nil, ErrOutOfGas
		}
		if operation.dynamicGas != nil {
			// 所有具有动态内存使用的操作也具有动态燃气成本。
			var memorySize uint64
			// 计算新的内存大小并扩展内存以适应操作
			// 内存检查需要在评估动态燃气部分之前完成，以检测计算溢出
			if operation.memorySize != nil {
				memSize, overflow := operation.memorySize(stack)
				if overflow {
					return nil, ErrGasUintOverflow
				}
				// 内存以32字节的字扩展。燃气也以字计算。
				if memorySize, overflow = math.SafeMul(toWordSize(memSize), 32); overflow {
					return nil, ErrGasUintOverflow
				}
			}
			// 消耗燃气并在没有足够的燃气可用时返回错误。
			// cost被显式设置，以便capture state 延迟方法可以得到适当的成本
			var dynamicCost uint64
			dynamicCost, err = operation.dynamicGas(in.evm, contract, stack, mem, memorySize)
			cost += dynamicCost // 用于跟踪
			if err != nil || !contract.UseGas(dynamicCost) {
				return nil, ErrOutOfGas
			}
			// 在内存扩展之前进行跟踪
			if debug {
				in.evm.Config.Tracer.CaptureState(pc, op, gasCopy, cost, callContext, in.returnData, in.evm.depth, err)
				logged = true
			}
			if memorySize > 0 {
				mem.Resize(memorySize)
			}
		} else if debug {
			in.evm.Config.Tracer.CaptureState(pc, op, gasCopy, cost, callContext, in.returnData, in.evm.depth, err)
			logged = true
		}
		// 执行操作
		res, err = operation.execute(&pc, in, callContext)
		if err != nil {
			break
		}
		pc++
	}

	if err == errStopToken {
		err = nil // 清除停止标记错误
	}

	return res, err
}
```


### 合约预编译的作用
预编译合约是 EVM 中用于提供更复杂库函数(通常用于加密、散列等复杂操作)的一种折衷方法，这些函数不适合编写操作码。 它们适用于简单但经常调用的合约，或逻辑上固定但计算量很大的合约。 预编译合约是在使用节点客户端代码实现的，因为它们不需要 EVM，所以运行速度很快。 与使用直接在 EVM 中运行的函数相比，它对开发人员来说成本也更低。


### evm调用contract的步骤
- 判断调用深度是否大于1024
- 判断是否有充足的余额支持调用
- 进行快照和预编译
- 检查该地址是否在状态数据库中存在
- 若不存在，调用一个不存在的帐户，不要做任何事情，只需ping跟踪程序，检查是否是debug模式，若不是则会创建账户
- 判断是否预编译，若是调用节点客户端代码实现；反之，创建合约对象并加载被调用地址和地址的hash以及代码信息，后用解释器来运行
- 若运行过程中有任何错误，则状态将会回滚到操作前快照处，并消耗gas

> evm调用深度 <= 1024

### 以太坊中的调用call、callcode和delegatecall
|调用方式	|修改的storage	|调用者的msg.sender	|被调用者的msg.sender	|执行的上下文|
|---|---|---|---|---|
|call	|被调用者的storage	|交易发起者的地址	|调用者的地址	|被调用者|
|callcode	|调用者的storage	|调用者的地址	|调用者的地址	|调用者|
|delegatecall	|调用者的storage	|交易发起者的地址	|调用者的地址	|调用者|

还有staticCall调用过程中不允许进行任何修改操作，可以用view来修饰，因此在函数实现中会给解释器的运行函数中的read-only参数传入true值。


















