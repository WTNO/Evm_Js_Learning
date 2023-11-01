# 介绍
### 什么是以太坊虚拟机？
以太坊虚拟机（或EVM）是一个基于栈的计算机，负责执行智能合约指令。所有EVM指令都从栈中获取参数，除了PUSHx，它从代码中获取参数。每条指令都有栈输入，可能需要的参数，以及栈输出（它们的返回值）。这些指令的列表及其操作码可以在我们的参考资料中查看。

### 什么是智能合约？
智能合约是一组指令。每条指令都是一个操作码（它们都有自己方便记忆的助记符，这是它们在0到255之间赋值的文本表示）。当EVM执行智能合约时，它会按顺序读取并执行每条指令，除了`JUMP`和`JUMPI`指令。如果无法执行指令，例如，如果栈上的值不足，或者燃气不足，执行将回滚。交易回滚也可以通过REVERT操作码触发，尽管REVERT操作码会退还未使用的燃气费，而其他导致回滚的原因则会全部消耗掉。在交易回滚的情况下，由交易指令指定的任何状态更改都会恢复到交易之前的状态。

# 执行环境
当EVM执行智能合约时，会为其创建一个上下文。这个上下文由几个具有不同目的的数据区域组成，以及一些变量，如程序计数器，当前的调用者，被调用者和当前代码的地址。

### 代码
代码是存储指令的区域。作为合约帐户状态字段的一部分，代码中存储的指令数据是持久的。外部拥有的帐户（或EOAs）的代码区域是空的。代码是EVM在执行智能合约时读取、解释和执行的字节。代码是不可变的，这意味着它不能被修改，但可以通过`CODESIZE`和`CODECOPY`指令读取。一个合约的代码可以被其他合约通过`EXTCODESIZE`和`EXTCODECOPY`指令读取。

### 程序计数器
程序计数器（PC）编码了应该由EVM下一步读取的存储在代码中的哪条指令。程序计数器通常增加一个字节，指向下一条指令，有些例外。例如，`PUSHx`指令长度超过一个字节，并导致PC跳过它们的参数。`JUMP`指令不增加PC的值，而是将程序计数器修改为栈顶指定的位置。如果`JUMPI`的条件为真（非零代码值），它也会这样做，否则它将像其他指令一样增加PC。

### 栈
栈是一种用来存储智能合约指令输入和输出的32字节元素列表。每个调用上下文创建一个栈，当调用上下文结束时，它会被销毁。当一个新的值被放到栈上时，它会被放在顶部，只有顶部的值才会被指令使用。栈目前最多可以有1024个值。所有的指令都与栈交互，但可以通过`PUSH1`、`POP`、`DUP1`或`SWAP1`等指令直接操作栈。

### 内存
EVM的内存不是持久的，会在调用上下文结束时被销毁。在调用上下文开始时，内存被初始化为0。从内存中读取和写入通常是通过`MLOAD`和`MSTORE`指令完成的，但也可以通过`CREATE`或`EXTCODECOPY`等其他指令访问。我们在本文档后面讨论内存大小计算。

### 存储
存储是32字节插槽到32字节值的映射。存储是智能合约的持久内存：合约写入的每个值在调用完成后都会保留，除非其值被改为0，或者执行了`SELFDESTRUCT`指令。从未写入的键读取存储的字节也返回0。每个合约都有自己的存储，并且不能读取或修改另一个合约的存储。存储是通过`SLOAD`和`SSTORE`指令进行读取和写入的。

### 调用数据
调用数据区域是作为智能合约交易一部分发送的数据。例如，创建合约时，调用数据将是新合约的构造代码。调用数据是不可变的，可以通过`CALLDATALOAD`、`CALLDATASIZE`和`CALLDATACOPY`指令读取。需要注意的是，当合约执行一个xCALL指令时，它也会创建一个内部交易。因此，执行xCALL时，新上下文中会有一个调用数据区域。

### 返回数据
返回数据是智能合约在调用后返回值的方式。它可以通过`RETURN`和`REVERT`指令设置，调用合约可以通过`RETURNDATASIZE`和`RETURNDATACOPY`读取。

# 气体费用
在每笔以太坊区块链上的交易被添加到区块链之前，都会由第三方验证者进行审查。这些验证者通过激励费用进行补偿，以进行这个审查过程，并将交易添加到区块链上。费用因交易而异，取决于不同分叉的不同变量。计算费用的一些变量包括：

- `单个气体单位的当前价格`：Gas，或gwei，是以太坊的一个计量单位，用于支付费用。气体价格随时间变化，基于当前对区块空间的需求，以ETH/gas计价。

- `Calldata size`：每个calldata字节都需要气体，交易数据的大小越大，气体费用越高。Calldata每字节等于0的费用为4个气体，其他的为16个气体（在Istanbul硬分叉之前为64个）。

- `Intrinsic Gas`：每笔交易都有一个内在成本，为21000个气体。创建一个合约需要32000个气体，除了交易成本。同样：calldata每字节等于0的费用为4个气体，其他的为16个气体（在Istanbul硬分叉之前为64个）。这个成本在任何操作码或转账执行之前就已经从交易中支付出去。

- `操作码固定执行成本`：每个操作码在执行时都有一个固定的成本，以气体计价。这个成本对于所有的执行都是相同的，尽管这在新的硬分叉中可能会改变。请参阅我们的参考资料，了解每个操作码和分叉的具体成本。

- `操作码动态执行成本`：一些指令比其他指令做的工作多，这取决于它们的参数。因此，除了固定成本，一些指令还有动态成本。这些动态成本取决于几个因素（这些因素在硬分叉和硬分叉之间有所不同）。请参阅我们的参考资料，了解每个操作码和分叉的具体计算。

要获得您的程序的完整气体成本估计，包括您的编译器选项和特定的状态和输入，可以使用像Remix或Truffle这样的工具。

# 内存扩展
在智能合约执行过程中，可以通过操作码访问内存。当首次访问一个偏移量（读或写）时，内存可能会触发扩展，这会消耗gas。

当访问的字节偏移量（模32）大于之前的偏移量时，可能会触发内存扩展。如果发生了更大的偏移量触发的内存扩展，将计算并从当前调用上下文中的总gas中扣除访问更高偏移量的成本。

给定内存大小的总成本按如下方式计算：

    memory_size_word = (memory_byte_size + 31) / 32
    memory_cost = (memory_size_word ** 2) / 512 + (3 * memory_size_word)

当触发内存扩展时，只需为额外的内存字节付费。因此，特定操作码的内存扩展成本为：

    memory_expansion_cost = new_memory_cost - last_memory_cost

可以用操作码MSIZE获取memory_byte_size。由MSIZE触发的内存扩展的成本呈二次增长，通过提高偏移量的成本来阻止内存的过度使用。任何访问内存的操作码都可能触发扩展（如MLOAD, RETURN 或 CALLDATACOPY）。使用我们的参考资料来查看哪个操作码能够访问内存。注意，字节大小参数为0的操作码不会触发内存扩展，无论它们的偏移参数如何。

# 访问集
访问集是按照外部交易定义的，而不是按照调用定义的。每个交易可能由其发送者、调用数据或被调用者的某种组合定义。交易可以是外部的，也可以是内部的。外部交易发送到以太坊网络。内部交易由执行xCALL指令的外部交易触发。因此，内部交易也被称为调用。访问集可以被视为两种独立类型的列表：接触过的地址和接触过的合约存储槽。

当一个地址被一个交易、指令访问，或者被用作调用者或被调用者时，它会被放入访问集。在一个访问集中不存在的地址上调用操作码BALANCE的成本比该地址已经在集合中的成本更高。其他可以修改访问集的操作码包括`EXTCODESIZE`, `EXTCODECOPY`, `EXTCODEHASH`, `CALL`, `CALLCODE`, `DELEGATECALL`, `STATICCALL`, `CREATE`, `CREATE2` 和 `SELFDESTRUCT`。每个操作码在修改访问集时都有自己的成本。

触摸槽列表是一组由合约地址访问的存储槽键。槽列表初始化为空。当一个操作码访问一个不在集合中的槽时，它会将其添加到集合中。可以修改触摸槽列表的操作码是`SLOAD`和`SSTORE`。同样，这两个操作码在修改访问集时都有自己的成本。

如果一个上下文被回滚，集合会被回滚到该上下文之前的状态。

如果一个地址或存储槽存在于集合中，它被称为'warm'；否则，它是'cold'。在交易中首次触摸的存储槽会在交易的过程中从冷变热。交易可以使用EIP-2930访问列表预先指定合约为热。某些操作码的动态成本取决于一个地址或槽是热还是冷。在hardforkBerlin之后，所有预编译的合约地址总是“热”的。

# Gas退款
一些操作码可以触发gas退款，这会降低交易的gas成本。Gas退款在交易结束时应用。如果交易的gas不足以达到运行的结束，其gas退款不能被触发，交易失败。随着伦敦硬分叉的引入，gas退款的两个方面发生了变化。首先，可以退款的gas上限从总交易成本的一半降低到总交易成本的五分之一。其次，SELFDESTRUCT操作码不能触发gas退款，只有SSTORE可以。









