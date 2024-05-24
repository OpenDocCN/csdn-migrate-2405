# LLVM12 学习手册（四）

> 原文：[`zh.annas-archive.org/md5/96A20F7680F39BBAA9B437BF26B65FE2`](https://zh.annas-archive.org/md5/96A20F7680F39BBAA9B437BF26B65FE2)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第三部分：将 LLVM 提升到下一个级别

在本节中，您将学习 LLVM 中指令选择的实现方式，并通过添加对新机器指令的支持来应用这些知识。LLVM 具有即时编译器（JIT），您将学习如何使用它以及如何根据自己的需求进行定制。您还将尝试各种工具和库，以帮助识别应用程序中的错误。最后，您将使用新的后端扩展 LLVM，这将使您具备利用 LLVM 尚未支持的新架构所需的知识。

本节包括以下章节：

+   第九章，指令选择

+   第十章，JIT 编译

+   第十一章，使用 LLVM 工具进行调试

+   第十二章，创建自己的后端


# 第九章：指令选择

到目前为止使用的 LLVM IR 仍然需要转换为机器指令。这称为**指令选择**，通常缩写为**ISel**。指令选择是目标后端的重要部分，LLVM 有三种不同的选择指令的方法：选择 DAG，快速指令选择和全局指令选择。

在本章中，您将学习以下主题：

+   了解 LLVM 目标后端结构，介绍了目标后端执行的任务，并检查了要运行的机器传递。

+   使用**机器 IR**（**MIR**）来测试和调试后端，这有助于在指定的传递后输出 MIR 并在 MIR 文件上运行传递。

+   指令选择的工作方式，您将了解 LLVM 执行指令选择的不同方式。

+   支持新的机器指令，其中您添加一个新的机器指令并使其可用于指令选择。

通过本章结束时，您将了解目标后端的结构以及指令选择的工作方式。您还将获得向汇编程序和指令选择中添加当前不受支持的机器指令的知识，以及如何测试您的添加。

# 技术要求

要查看图形可视化，您必须安装**Graphviz**软件，可从[`graphviz.org/`](https://graphviz.org/)下载。源代码可在[`gitlab.com/graphviz/graphviz/`](http://gitlab.com/graphviz/graphviz/)上找到。

本章的源代码可在[`github.com/PacktPublishing/Learn-LLVM-12/tree/master/Chapter09`](https://github.com/PacktPublishing/Learn-LLVM-12/tree/master/Chapter09)上找到

您可以在[`bit.ly/3nllhED`](https://bit.ly/3nllhED)上找到代码演示视频

# 了解 LLVM 目标后端结构

在优化了 LLVM IR 之后，选择的 LLVM 目标用于从中生成机器代码。在目标后端中执行以下任务，包括：

1.  用于指令选择的**有向无环图**（**DAG**），通常称为**SelectionDAG**，被构建。

1.  选择与 IR 代码对应的机器指令。

1.  选择的机器指令按最佳顺序排列。

1.  虚拟寄存器被机器寄存器替换。

1.  向函数添加序言和尾声代码。

1.  基本块按最佳顺序排列。

1.  运行特定于目标的传递。

1.  发出目标代码或汇编。

所有这些步骤都被实现为机器函数传递，派生自`MachineFunctionPass`类。这是`FunctionPass`类的子类，是旧的 pass 管理器使用的基类之一。截至 LLVM 12，将机器函数传递转换为新的 pass 管理器仍然是一个正在进行中的工作。

在所有这些步骤中，LLVM 指令都会经历转换。在代码级别，LLVM IR 指令由`Instruction`类的实例表示。在指令选择阶段，它被转换为`MachineInstr`实例。这是一个更接近实际机器级别的表示。它已经包含了对目标有效的指令，但仍然在虚拟寄存器上运行（直到寄存器分配），并且还可以包含某些伪指令。指令选择后的传递会对此进行细化，最终创建一个`MCInstr`实例，这是真实机器指令的表示。`MCInstr`实例可以写入对象文件或打印为汇编代码。

要探索后端传递，您可以创建一个包含以下内容的小型 IR 文件：

```cpp
define i16 @sum(i16 %a, i16 %b) {
  %res = add i16 %a, 3
  ret i16 %res
}
```

将此代码保存为`sum.ll`。使用 LLVM 静态编译器`llc`为 MIPS 架构编译它。这个工具将 LLVM IR 编译成汇编文本或目标文件。可以使用`–mtriple`选项在命令行上覆盖目标平台的编译。使用`–debug-pass=Structure`选项调用`llc`工具：

```cpp
$ llc -mtriple=mips-linux-gnu -debug-pass=Structure < sum.ll
```

除了生成的汇编代码，你还会看到一个要运行的机器 pass 的长列表。其中，`MIPS DAG->DAG Pattern Instruction Selection` pass 执行指令选择，`Mips Delay Slot Filler`是一个特定于目标的 pass，而在清理之前的最后一个 pass，`Mips Assembly Printer`，负责打印汇编代码。在所有这些 pass 中，指令选择 pass 是最有趣的，我们将在下一节详细讨论。

# 使用 MIR 测试和调试后端

你在前面的部分看到目标后端运行了许多 pass。然而，这些 pass 中的大多数并不是在 LLVM IR 上运行的，而是在 MIR 上运行的。这是指令的一个与目标相关的表示，因此比 LLVM IR 更低级。它仍然可以包含对虚拟寄存器的引用，因此它还不是目标 CPU 的纯指令。

要查看 IR 级别的优化，例如，可以告诉`llc`在每个 pass 之后转储 IR。这在后端的机器 pass 中不起作用，因为它们不在 IR 上工作。相反，MIR 起到了类似的作用。

MIR 是当前模块中机器指令当前状态的文本表示。它利用了 YAML 格式，允许序列化和反序列化。基本思想是你可以在某个点停止 pass 管道并以 YAML 格式检查状态。你也可以修改 YAML 文件，或者创建你自己的文件，并传递它，并检查结果。这样可以方便地进行调试和测试。

让我们来看看 MIR。使用`llc`工具和`--stop-after=finalize-isel`选项以及之前使用的测试输入文件运行：

```cpp
$ llc -mtriple=mips-linux-gnu \
        -stop-after=finalize-isel < sum.ll
```

这指示`llc`在指令选择完成后转储 MIR。缩短的输出看起来像这样：

```cpp
---
name:                 sum
body:                  |
  bb.0 (%ir-block.0):
     liveins: $a0, $a1
     %1:gpr32 = COPY $a1
     %0:gpr32 = COPY $a0
     %2:gpr32 = ADDu %0, %1
     $v0 = COPY %2
     RetRA implicit $v0
... 
```

有几个属性你立即注意到。首先，有一些虚拟寄存器，比如`%0`和实际的机器寄存器，比如`$a0`。这是由 ABI 降级引起的。为了在不同的编译器和语言之间具有可移植性，函数遵循调用约定的一部分，这是`$a0`的一部分。因为 MIR 输出是在指令选择之后但是在寄存器分配之前生成的，所以你仍然可以看到虚拟寄存器的使用。

在 LLVM IR 中的`add`指令，MIR 文件中使用的是机器指令`ADDu`。你还可以看到虚拟寄存器有一个寄存器调用附加，这种情况下是`gpr32`。在 MIPS 架构上没有 16 位寄存器，因此必须使用 32 位寄存器。

`bb.0`标签指的是第一个基本块，标签后面的缩进内容是基本块的一部分。第一条语句指定了进入基本块时活跃的寄存器。之后是指令。在这种情况下，只有`$a0`和`$a1`，两个参数，在进入时是活跃的。

MIR 文件中还有很多其他细节。你可以在 LLVM MIR 文档中阅读有关它们的内容[`llvm.org/docs/MIRLangRef.html`](https://llvm.org/docs/MIRLangRef.html)。

你遇到的一个问题是如何找出一个 pass 的名称，特别是如果你只需要检查该 pass 之后的输出而不是积极地在其上工作。当使用`-debug-pass=Structure`选项与`llc`一起时，激活 pass 的选项被打印在顶部。例如，如果你想在`Mips Delay Slot Filler` pass 之前停止，那么你需要查看打印出的列表，并希望找到`-mips-delay-slot-filler`选项，这也会给出 pass 的名称。

MIR 文件格式的主要应用是帮助测试目标后端中的机器传递。使用`llc`和`--stop-after`选项，您可以在指定的传递之后获得 MIR。通常，您将使用这个作为您打算测试用例的基础。您首先注意到的是 MIR 输出非常冗长。例如，许多字段是空的。为了减少这种混乱，您可以在`llc`命令行中添加`-simplify-mir`选项。

您可以根据需要保存和更改 MIR 以进行测试。`llc`工具可以运行单个传递，这非常适合使用 MIR 文件进行测试。假设您想要测试`MIPS Delay Slot Filler`传递。延迟槽是 RISC 架构（如 MIPS 或 SPARC）的一个特殊属性：跳转后的下一条指令总是被执行。因此，编译器必须确保每次跳转后都有一个合适的指令，这个传递就是执行这个任务的。

我们在运行传递之前生成 MIR：

```cpp
$ llc -mtriple=mips-linux-gnu \
        -stop-before=mips-delay-slot-filler -simplify-mir \
        < sum.ll  >delay.mir
```

输出要小得多，因为我们使用了`-simplify-mir`选项。函数的主体现在是以下内容：

```cpp
body:                  |
  bb.0 (%ir-block.0):
     liveins: $a0, $a1
     renamable $v0 = ADDu killed renamable $a0,
                             killed renamable $a1
     PseudoReturn undef $ra, implicit $v0
```

最重要的是，您将看到`ADDu`指令，后面是返回的伪指令。

使用`delay.ll`文件作为输入，我们现在运行延迟槽填充器传递：

```cpp
$ llc -mtriple=mips-linux-gnu \
        -run-pass=mips-delay-slot-filler -o - delay.mir
```

现在将输出中的函数与之前的函数进行比较：

```cpp
body:                  |
  bb.0 (%ir-block.0):
     PseudoReturn undef $ra, implicit $v0 {
        renamable $v0 = ADDu killed renamable $a0,
                                killed renamable $a1
     }
```

您会看到`ADDu`和返回的伪指令的顺序已经改变，`ADDu`指令现在嵌套在返回内部：传递将`ADDu`指令标识为适合延迟槽的指令。

如果延迟槽的概念对您来说是新的，您还会想要查看生成的汇编代码，您可以使用`llc`轻松生成：

```cpp
$ llc -mtriple=mips-linux-gnu < sum.ll
```

输出包含很多细节，但是通过基本块的`bb.0`名称的帮助，您可以轻松地定位生成的汇编代码：

```cpp
# %bb.0:
           jr        $ra
           addu     $2, $4, $5
```

确实，指令的顺序改变了！

掌握了这些知识，我们来看一下目标后端的核心，并检查 LLVM 中如何执行机器指令选择。

# 指令选择的工作原理

LLVM 后端的任务是从 LLVM IR 创建机器指令。这个过程称为**指令选择**或**降低**。受到尽可能自动化这项任务的想法的启发，LLVM 开发人员发明了 TableGen 语言来捕获目标描述的所有细节。我们首先看一下这种语言，然后再深入研究指令选择算法。

## 在 TableGen 语言中指定目标描述

机器指令有很多属性：汇编器和反汇编器使用的助记符、在内存中表示指令的位模式、输入和输出操作数等。LLVM 开发人员决定将所有这些信息都捕获在一个地方，即`.td`后缀。

原则上，TableGen 语言非常简单。您所能做的就是定义记录。`Register`类定义了寄存器的共同属性，您可以为寄存器`R0`定义一个具体的记录：

```cpp
class Register {
  string name;
}
def R0 : Register {
  let name = "R0";
  string altName = "$0";
}
```

您可以使用`let`关键字来覆盖一个值。

TableGen 语言有很多语法糖，使处理记录变得更容易。例如，一个类可以有一个模板参数：

```cpp
class Register<string n> {
  string name = n;
}
def R0 : Register<"R0"> {
  string altName = "$0";
}
```

TableGen 语言是静态类型的，您必须指定每个值的类型。一些支持的类型如下：

+   `位`：一个单独的位

+   `int`：64 位整数值

+   `bits<n>`：由*n*位组成的整数类型

+   `string`：一个字符字符串

+   `list<t>`：类型为`t`的元素列表

+   `dag`：**有向无环图**（**DAG**；指令选择使用）

类的名称也可以用作类型。例如，`list<Register>`指定了`Register`类的元素列表。

该语言允许使用`include`关键字包含其他文件。对于条件编译，支持预处理指令`#define`、`#ifdef`和`#ifndef`。

LLVM 中的 TableGen 库可以解析用 TableGen 语言编写的文件，并创建记录的内存表示。您可以使用这个库来创建自己的生成器。

LLVM 自带了一个名为`llvm-tblgen`的生成器工具和一些`.td`文件。后端的目标描述首先包括`llvm/Target/Target.td`文件。该文件定义了诸如`Register`、`Target`或`Processor`之类的类。`llvm-tblgen`工具了解这些类，并从定义的记录生成 C++代码。

让我们以 MIPS 后端为例来看一下。目标描述在`llvm/lib/Target/Mips`文件夹中的`Mips.td`文件中。该文件包括了最初提到的`Target.td`文件。它还定义了目标特性，例如：

```cpp
def FeatureMips64r2
  : SubtargetFeature<"mips64r2", "MipsArchVersion", 
                     "Mips64r2", "Mips64r2 ISA Support",
                     [FeatureMips64, FeatureMips32r2]>;
```

这些特性后来被用来定义 CPU 模型，例如：

```cpp
def : Proc<"mips64r2", [FeatureMips64r2]>;
```

其他定义寄存器、指令、调度模型等的文件也包括在内。

`llvm-tblgen`工具可以显示由目标描述定义的记录。如果你在`build`目录中，那么以下命令将在控制台上打印记录：

```cpp
$ bin/llvm-tblgen \
  -I../llvm-project/llvm/lib/Target/Mips/ \
  -I../llvm-project/llvm/include \
  ../llvm-project/llvm/lib/Target/Mips/Mips.td
```

与 Clang 一样，`-I`选项会在包含文件时添加一个目录进行搜索。查看记录对于调试很有帮助。该工具的真正目的是从记录生成 C++代码。例如，使用`-gen-subtarget`选项，将向控制台发出解析`llc`的`-mcpu=`和`-mtarget=`选项所需的数据：

```cpp
$ bin/llvm-tblgen \
  -I../llvm-project/llvm/lib/Target/Mips/ \
  -I../llvm-project/llvm/include \
  ../llvm-project/llvm/lib/Target/Mips/Mips.td \
  -gen-subtarget
```

将该命令生成的代码保存到一个文件中，并探索特性和 CPU 在生成的代码中的使用方式！

指令的编码通常遵循一些模式。因此，指令的定义被分成了定义位编码和指令具体定义的类。MIPS 指令的编码在文件`llvm/Target/Mips/MipsInstrFormats.td`中。让我们来看一下`ADD_FM`格式的定义：

```cpp
class ADD_FM<bits<6> op, bits<6> funct> : StdArch {
  bits<5> rd;
  bits<5> rs;
  bits<5> rt;
  bits<32> Inst;
  let Inst{31-26} = op;
  let Inst{25-21} = rs;
  let Inst{20-16} = rt;
  let Inst{15-11} = rd;
  let Inst{10-6}  = 0;
  let Inst{5-0}   = funct;
}
```

在记录主体中，定义了几个新的位字段：`rd`、`rs`等。它们用于覆盖`Inst`字段的部分内容，该字段保存指令的位模式。`rd`、`rs`和`rt`位字段编码了指令操作的寄存器，而`op`和`funct`参数表示操作码和函数编号。`StdArch`超类只添加了一个字段，说明该格式遵循标准编码。

MIPS 目标中的大多数指令编码不涉及 DAG 节点，也不指定汇编助记符。为此定义了一个单独的类。MIPS 架构中的一条指令是`nor`指令，它计算第一个和第二个输入寄存器的按位或，反转结果的位，并将结果赋给输出寄存器。这条指令有几个变体，以下的`LogicNOR`类有助于避免多次重复相同的定义：

```cpp
class LogicNOR<string opstr, RegisterOperand RO>:
  InstSE<(outs RO:$rd), (ins RO:$rs, RO:$rt),
            !strconcat(opstr, "\t$rd, $rs, $rt"),
            [(set RO:$rd, (not (or RO:$rs, RO:$rt)))],
            II_NOR, FrmR, opstr> {
  let isCommutable = 1;
}
```

哇，记录这个简单的概念现在看起来很复杂。让我们剖析一下这个定义。这个类派生自`InstSE`类，这个类总是用于具有标准编码的指令。如果你继续跟踪超类层次结构，你会看到这个类派生自`Instruction`类，这是一个预定义的类，表示目标的指令。`(outs RO:$rd)`参数将最终指令的结果定义为 DAG 节点。`RO`部分是指`LogicNOR`类的同名参数，表示寄存器操作数。`$rd`是要使用的寄存器。这是稍后将放入指令编码中的值，在`rd`字段中。第二个参数定义了指令将操作的值。总之，这个类是用于操作三个寄存器的指令。`!strconcat(opstr, "\t$rd, $rs, $rt")`参数组装了指令的文本表示。`!strconcat`操作符是 TableGen 中预定义的功能，用于连接两个字符串。你可以在 TableGen 程序员指南中查找所有预定义的操作符：[`llvm.org/docs/TableGen/ProgRef.html`](https://llvm.org/docs/TableGen/ProgRef.html)。

它遵循一个模式定义，类似于`nor`指令的文本描述，并描述了这个指令的计算。模式的第一个元素是操作，后面是一个逗号分隔的操作数列表。操作数指的是 DAG 参数中的寄存器名称，并且还指定了 LLVM IR 值类型。LLVM 有一组预定义的操作符，比如`add`和`and`，可以在模式中使用。这些操作符属于`SDNode`类，也可以用作参数。你可以在文件`llvm/Target/TargetSelectionDAG.td`中查找预定义的操作符。

`II_NOR`参数指定了调度模型中使用的行程类别，`FrmR`参数是一个定义的值，用于识别此指令格式。最后，`opstr`助记符被传递给超类。这个类的主体非常简单：它只是指定`nor`操作是可交换的，这意味着操作数的顺序可以交换。

最后，这个类用于定义一个指令的记录，例如，用于 64 位模式下的`nor`指令：

```cpp
def NOR64 : LogicNOR<"nor", GPR64Opnd>, ADD_FM<0, 0x27>,                                    
                              GPR_64;
```

这是最终的定义，可以从`def`关键字中识别出来。它使用`LogicNOR`类来定义 DAG 操作数和模式，使用`ADD_FM`类来指定二进制指令编码。额外的`GPR_64`谓词确保只有在 64 位寄存器可用时才使用这个指令。

开发人员努力避免多次重复定义，一个经常使用的方法是使用`multiclass`类。`multiclass`类可以一次定义多个记录。

例如，MIPS CPU 的浮点单元可以执行单精度或双精度浮点值的加法。这两个指令的定义非常相似，因此定义了一个`multiclass`类，一次创建两个指令：

```cpp
multiclass ADDS_M<…> {
  def _D32 : ADDS_FT<…>, FGR_32;
  def _D64 : ADDS_FT<…>, FGR_64;
}
```

`ADDS_FT`类定义了指令格式，类似于`LogicNOR`类。`FGR_32`和`FGR_64`谓词用于在编译时决定可以使用哪个指令。重要的部分是定义了`_D32`和`_D64`记录。这些是记录的模板。然后使用`defm`关键字定义指令记录：

```cpp
defm FADD : ADDS_M<…>;
```

这一次同时定义了多类中的两个记录，并为它们分配了名称`FADD_D32`和`FADD_D64`。这是避免代码重复的一种非常强大的方式，它经常在目标描述中使用，但结合其他 TableGen 功能，可能会导致非常晦涩的定义。

有了目标描述组织的知识，我们现在可以在下一节中探索指令选择。

## 使用选择 DAG 进行指令选择

LLVM 将 IR 转换为机器指令的标准方式是通过 DAG。使用目标描述中提供的模式匹配和自定义代码，IR 指令被转换为机器指令。这种方法并不像听起来那么简单：IR 大多是与目标无关的，并且可能包含目标不支持的数据类型。例如，代表单个位的`i1`类型在大多数目标上都不是有效的类型。

selectionDAG 由`SDNode`类型的节点组成，在文件`llvm/CodeGen/SelectionDAGNodes.h`中定义。节点表示的操作称为`OpCode`，目标独立代码在文件`llvm/CodeGen/ISDOpcodes.h`中定义。除了操作，节点还存储操作数和它产生的值。

节点的值和操作数形成数据流依赖关系。控制流依赖由链边表示，具有特殊类型`MVT::Other`。这使得可以保持具有副作用的指令的顺序，例如，加载指令。

使用选择 DAG 进行指令选择的步骤如下：

1.  如何跟踪指令选择过程

1.  DAG 被优化了。

1.  DAG 中的类型被合法化了。

1.  指令被选择了。

1.  DAG 中的操作被合法化了。

1.  DAG 被优化了。

1.  指令被排序了。

1.  就像上一节的 MIR 输出中一样，您在这里看到`CopyFromReg`指令，它们将 ABI 使用的寄存器的内容传输到虚拟节点。由于示例使用 16 位值，但 MIPS 架构仅对 32 位值有本机支持，因此需要`truncate`节点。`add`操作是在 16 位虚拟寄存器上执行的，并且结果被扩展并返回给调用者。对于上述每个步骤，都会打印这样的部分。

让我们看看如何跟踪每个步骤对选择 DAG 的更改。

### ![图 9.1 - 为 sum.ll 文件构建的选择 DAG

您可以以两种不同的方式看到指令选择的工作。如果将`-debug-only=isel`选项传递给`llc`工具，则每个步骤的结果将以文本格式打印出来。如果您需要调查为什么选择了机器指令，这将是一个很大的帮助。例如，运行以下命令以查看“Understanding the LLVM target backend structure”部分的`sum.ll`文件的输出：

```cpp
$ llc -mtriple=mips-linux-gnu -debug-only=isel < sum.ll
```

这打印了大量信息。在输出顶部，您可以看到输入的初始创建的 DAG 的描述：

```cpp
Initial selection DAG: %bb.0 'sum:'
SelectionDAG has 12 nodes:
  t0: ch = EntryToken
              t2: i32,ch = CopyFromReg t0, Register:i32 %0
           t5: i16 = truncate t2
              t4: i32,ch = CopyFromReg t0, Register:i32 %1
           t6: i16 = truncate t4
        t7: i16 = add t5, t6
     t8: i32 = any_extend t7
  t10: ch,glue = CopyToReg t0, Register:i32 $v0, t8
  t11: ch = MipsISD::Ret t10, Register:i32 $v0, t10:1 
```

DAG 被构建了。

LLVM 还可以借助*Graphviz*软件生成选择 DAG 的可视化。如果将`–view-dag-combine1-dags`选项传递给`llc`工具，则会打开一个窗口显示构建的 DAG。例如，使用前面的小文件运行`llc`：

```cpp
$ llc -mtriple=mips-linux-gnu  –view-dag-combine1-dags sum.ll
```

DAG 被优化了。

在 Windows PC 上运行，您将看到 DAG：

在 Windows PC 上运行，您将看到 DAG：

图 9.1 - 为 sum.ll 文件构建的选择 DAG

确保文本表示和此图包含相同的信息。`EntryToken`是 DAG 的起点，`GraphRoot`是最终节点。控制流的链用蓝色虚线箭头标记。黑色箭头表示数据流。红色箭头将节点粘合在一起，防止重新排序。即使对于中等大小的函数，图可能会变得非常大。它不包含比带有`-debug-only=isel`选项的文本输出更多或其他信息，只是呈现更加舒适。您还可以在其他时间生成图，例如：

+   将`--view-legalize-types-dags`选项添加到类型合法化之前查看 DAG。

+   添加`–view-isel-dags`选项以查看选择指令。

您可以使用`--help-hidden`选项查看查看 DAG 的所有可用选项。由于 DAG 可能变得庞大和混乱，您可以使用`-filter-view-dags`选项将渲染限制为一个基本块。

### 检查指令选择

了解如何可视化 DAG 后，我们现在可以深入了解细节。选择 DAG 是从 IR 构建的。对于 IR 中的每个函数，`SelectionDAGBuilder`类通过`SelectionDAGBuilder`类填充`SelectionDAG`类的实例。在此步骤中没有进行特殊优化。尽管如此，目标需要提供一些函数来降低调用、参数处理、返回跳转等。为此，目标必须实现`TargetLowering`接口。在目标的文件夹中，源代码通常在`XXXISelLowering.h`和`XXXISelLowering.cpp`文件中。`TargetLowering`接口的实现提供了指令过程所需的所有信息，例如目标上支持的数据类型和操作。

优化步骤会运行多次。优化器执行简单的优化，例如识别支持这些操作的目标上的旋转。这里的原理是产生一个清理过的 DAG，从而简化其他步骤。

在类型合法化步骤中，目标不支持的类型将被替换为支持的类型。例如，如果目标本机只支持 32 位宽整数，则较小的值必须通过符号或零扩展转换为 32 位。这称为`TargetLowering`接口。类型合法化后，选择 DAG 对`sum.ll`文件具有以下文本表示：

```cpp
Optimized type-legalized selection DAG: %bb.0 'sum:'
SelectionDAG has 9 nodes:
  t0: ch = EntryToken
        t2: i32,ch = CopyFromReg t0, Register:i32 %0
        t4: i32,ch = CopyFromReg t0, Register:i32 %1
     t12: i32 = add t2, t4
  t10: ch,glue = CopyToReg t0, Register:i32 $v0, t12
  t11: ch = MipsISD::Ret t10, Register:i32 $v0, t10:1
```

如果将此与最初构建的 DAG 进行比较，那么这里只使用了 32 位寄存器。16 位值被提升，因为本机只支持 32 位值。

操作合法化类似于类型合法化。这一步是必要的，因为并非所有操作都可能被目标支持，或者即使目标本机支持某种类型，也可能并非所有操作都有效。例如，并非所有目标都有用于人口统计的本机指令。在这种情况下，该操作将被一系列操作替换以实现功能。如果类型不适合操作，则可以将类型提升为更大的类型。后端作者还可以提供自定义代码。如果合法化操作设置为`Custom`，则将为这些操作调用`TargetLowering`类中的`LowerOperation()`方法。该方法必须创建操作的合法版本。在`sum.ll`示例中，`add`操作已经是合法的，因为平台支持两个 23 位寄存器的加法，而且没有改变。

在类型和操作被合法化之后，指令选择就会发生。选择的大部分部分是自动化的。请记住前一节中，您在指令描述中提供了一个模式。从这些描述中，`llvm-tblgen`工具生成了一个模式匹配器。基本上，模式匹配器试图找到与当前 DAG 节点匹配的模式。然后选择与该模式相关联的指令。模式匹配器被实现为字节码解释器。解释器的可用代码在`llvm/CodeGen/SelectionDAGISel.h`头文件中定义。`XXXISelDAGToDAG`类实现了目标的指令选择。对于每个 DAG 节点，都会调用`Select()`方法。默认情况下会调用生成的匹配器，但您也可以为它未处理的情况添加代码。

值得注意的是，选择 DAG 节点与所选指令之间没有一对一的关系。DAG 节点可以扩展为多条指令，而多个 DAG 节点可以合并为单条指令。前者的一个例子是合成立即值。特别是在 RISC 架构上，立即值的位长度受限。32 位目标可能仅支持 16 位长度的嵌入式立即值。要执行需要 32 位常量值的操作，通常会将其拆分为两个 16 位值，然后生成使用这两个 16 位值的两个或更多指令。在 MIPS 目标中，您会发现这方面的模式。位域指令是后一种情况的常见例子：`and`，`or`和`shift` DAG 节点的组合通常可以匹配到特殊的位域指令，从而只需一条指令即可处理两个或更多 DAG 节点。

通常，您可以在目标描述中指定一个模式，以组合两个或多个 DAG 节点。对于更复杂的情况，这些情况不容易用模式处理，您可以标记顶部节点的操作，需要特殊的 DAG 组合处理。对于这些节点，在`XXXISelLowering`类中调用`PerformDAGCombine（）`方法。然后，您可以检查任意复杂的模式，如果找到匹配，那么您可以返回表示组合 DAG 节点的操作。在运行 DAG 节点的生成匹配器之前调用此方法。

您可以在`sum.ll`文件的打印输出中跟踪指令选择过程。对于`add`操作，您会在那里找到以下行：

```cpp
ISEL: Starting selection on root node: t12: i32 = add t2, t4
ISEL: Starting pattern match
  Initial Opcode index to 27835
  …
  Morphed node: t12: i32 = ADDu t2, t4
ISEL: Match complete!
```

索引号指向生成匹配器的数组。起始索引为`27835`（一个可以在发布版本之间更改的任意值），经过一些步骤后，选择了`ADDu`指令。

遵循模式匹配

如果遇到模式问题，您还可以通过阅读生成的字节码来追踪匹配过程。您可以在`build`目录中的`lib/Target/XXX/XXXGenDAGIsel.inc`文件中找到源代码。您可以在文本编辑器中打开文件，并在先前的输出中搜索索引。每行都以索引号为前缀，因此您可以轻松找到数组中的正确位置。使用的谓词也会以注释的形式打印出来，因此它们可以帮助您理解为什么某个特定的模式未被选择。

### 将 DAG 转换为指令序列

在指令选择之后，代码仍然是一个图。这种数据结构需要被展平，这意味着指令必须按顺序排列。图包含数据和控制流依赖关系，但总是有几种可能的方式来安排指令，以满足这些依赖关系。我们希望的是一种最大程度利用硬件的顺序。现代硬件可以并行发出多条指令，但总是有限制。这种限制的一个简单例子是一个指令需要另一个指令的结果。在这种情况下，硬件可能无法发出两条指令，而是按顺序执行指令。

您可以向目标描述添加调度模型，描述可用的单元及其属性。例如，如果 CPU 有两个整数算术单元，那么这些信息就被捕捉在模型中。对于每个指令，有必要知道模型的哪个部分被使用。有不同的方法来做到这一点。较新的、推荐的方法是使用所谓的机器指令调度器来定义调度模型。为此，您需要为目标描述中的每个子目标定义一个`SchedMachineModel`记录。基本上，模型由指令和处理器资源的输入和输出操作数的定义组成。然后，这两个定义与延迟值一起关联。您可以在`llvm/Target/TargetSched.td`文件中查找此模型的预定义类型。查看 Lanai 目标以获取一个非常简单的模型，并在 SystemZ 目标中获取一个复杂的调度模型。

还有一个基于所谓行程的较旧模型。使用这个模型，您将处理器单元定义为`FuncUnit`记录。使用这样一个单元的步骤被定义为`InstrStage`记录。每个指令都与一个行程类相关联。对于每个行程类，定义了使用的处理器流水线由`InstrStage`记录组成，以及执行所需的处理器周期数。您可以在`llvm/Target/TargetItinerary.td`文件中找到行程模型的预定义类型。

一些目标同时使用这两种模型。一个原因是由于开发历史。基于行程的模型是最早添加到 LLVM 中的，目标开始使用这个模型。当新的机器指令调度器在 5 年多以后添加时，没有人关心足够迁移已经存在的模型。另一个原因是，使用行程模型不仅可以对使用多个处理器单元的指令进行建模，还可以指定在哪些周期使用这些单元。然而，这种细节级别很少需要，如果需要，那么可以参考机器指令调度器模型来定义行程，基本上将这些信息也引入到新模型中。

如果存在，调度模型用于以最佳方式排序指令。在这一步之后，DAG 不再需要，并被销毁。

使用选择 DAG 进行指令选择几乎可以得到最佳结果，但在运行时和内存使用方面会付出代价。因此，开发了替代方法，我们将在下一节中进行讨论。在下一节中，我们将看一下快速指令选择方法。

## 快速指令选择 - FastISel

使用选择 DAG 进行指令选择会消耗编译时间。如果您正在开发一个应用程序，那么编译器的运行时很重要。您也不太关心生成的代码，因为更重要的是发出完整的调试信息。因此，LLVM 开发人员决定实现一个特殊的指令选择器，它具有快速的运行时，但生成的代码不太优化，并且仅用于`-O0`优化级别。这个组件称为快速指令选择，简称**FastIsel**。

实现在`XXXFastISel`类中。并非每个目标都支持这种指令选择方法，如果是这种情况，选择 DAG 方法也用于`-O0`。实现很简单：从`FastISel`类派生一个特定于目标的类，并实现一些方法。TableGen 工具从目标描述中生成了大部分所需的代码。然而，需要一些工作来实现这个指令选择器。一个根本原因是你需要正确地获取调用约定，这通常是复杂的。

MIPS 目标具有快速指令选择的实现。您可以通过向`llc`工具传递`-fast-isel`选项来启用快速指令选择。使用第一节中的`sum.ll`示例文件，调用如下：

```cpp
$ llc -mtriple=mips-linux-gnu -fast-isel –O0 sum.ll
```

快速指令选择运行非常快，但它是一条完全不同的代码路径。一些 LLVM 开发人员决定寻找一个既能快速运行又能产生良好代码的解决方案，目标是在未来替换选择`dag`和快速指令选择器。我们将在下一节讨论这种方法。

## 新的全局指令选择 - GlobalISel

使用选择 dag，我们可以生成相当不错的机器代码。缺点是它是一个非常复杂的软件。这意味着它很难开发、测试和维护。快速指令选择工作迅速，复杂性较低，但不能产生良好的代码。除了由 TableGen 生成的代码外，这两种方法几乎没有共享代码。

我们能否兼得两全？一种指令选择算法，既快速，易于实现，又能产生良好的代码？这就是向 LLVM 框架添加另一种指令选择算法 - 全局指令选择的动机。短期目标是首先替换 FastISel，长期目标是替换选择 dag。

全局指令选择采用的方法是建立在现有基础设施之上。整个任务被分解为一系列机器函数传递。另一个主要的设计决定是不引入另一种中间表示，而是使用现有的`MachineInstr`类。但是，会添加新的通用操作码。

当前的步骤顺序如下：

1.  `IRTranslator` pass 使用通用操作码构建初始机器指令。

1.  `Legalizer` pass 在一步中使类型和操作合法化。这与选择 dag 不同，后者需要两个不同的步骤。真实的 CPU 架构有时很奇怪，可能只支持某种数据类型的一条指令。选择 dag 处理这种情况不好，但在全局指令选择的组合步骤中很容易处理。

1.  生成的机器指令仍然在虚拟寄存器上操作。在`RegBankSelect` pass 中，选择了一个寄存器组。寄存器组代表 CPU 上的寄存器类型，例如通用寄存器。这比目标描述中的寄存器定义更粗粒度。重要的是它将类型信息与指令关联起来。类型信息基于目标中可用的类型，因此这已经低于 LLVM IR 中的通用类型。

1.  此时，已知类型和操作对于目标是合法的，并且每条指令都与类型信息相关联。接下来的`InstructionSelect` pass 可以轻松地用机器指令替换通用指令。

全局指令选择后，通常会运行后端传递，如指令调度、寄存器分配和基本块放置。

全局指令选择已编译到 LLVM 中，但默认情况下未启用。如果要使用它，需要给`llc`传递`-global-isel`选项，或者给`clang`传递`-mllvm global-isel`选项。您可以控制全局指令选择无法处理 IR 构造时的处理方式。当您给`llc`传递`-global-isel-abort=0`选项时，选择 dag 将作为后备。使用`=1`时，应用程序将终止。为了防止这种情况，您可以给`llc`传递`-global-isel-abort=0`选项。使用`=2`时，选择 dag 将作为后备，并打印诊断消息以通知您有关问题。

要将全局指令选择添加到目标，您只需要重写目标的`TargetPassConfig`类中的相应函数。这个类由`XXXTargetMachine`类实例化，并且实现通常可以在同一个文件中找到。例如，您可以重写`addIRTranslator()`方法，将`IRTranslator` pass 添加到目标的机器 pass 中。

开发主要发生在 AArch64 目标上，目前该目标对全局指令选择有最好的支持。许多其他目标，包括 x86 和 Power，也已经添加了对全局指令选择的支持。一个挑战是从表描述中生成的代码并不多，所以仍然有一定量的手动编码需要完成。另一个挑战是目前不支持大端目标，因此纯大端目标（如 SystemZ）目前无法使用全局指令选择。这两个问题肯定会随着时间的推移得到改善。

Mips 目标具有全局指令选择的实现，但有一个限制，即它只能用于小端目标。您可以通过向`llc`工具传递`–global-isel`选项来启用全局指令选择。使用第一节的`sum.ll`示例文件，调用如下：

```cpp
$ llc -mtriple=mipsel-linux-gnu -global-isel sum.ll
```

请注意，目标`mipsel-linux-gnu`是小端目标。使用大端`mips-linux-gnu`目标会导致错误消息。

全局指令选择器比选择 DAG 快得多，并且已经产生了比快速指令选择更高的代码质量。

# 支持新的机器指令

您的目标 CPU 可能具有 LLVM 尚不支持的机器指令。例如，使用 MIPS 架构的制造商经常向核心 MIPS 指令集添加特殊指令。RISC-V 指令集的规范明确允许制造商添加新指令。或者您正在添加一个全新的后端，那么您必须添加 CPU 的指令。在下一节中，我们将为 LLVM 后端的单个新机器指令添加汇编器支持。

## 添加汇编和代码生成的新指令

新的机器指令通常与特定的 CPU 特性相关联。然后，只有在用户使用`--mattr=`选项选择了该特性时，新指令才会被识别。

例如，我们将在 MIPS 后端添加一个新的机器指令。这个虚构的新机器指令首先将两个输入寄存器`$2`和`$3`的值平方，然后将两个平方的和赋给输出寄存器`$1`：

```cpp
sqsumu $1, $2, $3
```

指令的名称是`sqsumu`，源自平方和求和操作。名称中的最后一个`u`表示该指令适用于无符号整数。

我们首先要添加的 CPU 特性称为`sqsum`。这将允许我们使用`--mattr=+sqsum`选项调用`llc`来启用对新指令的识别。

我们将添加的大部分代码位于`llvm/lib/Target/Mips`文件夹中。顶层文件是`Mips.td`。查看该文件，并找到定义各种特性的部分。在这里，您添加我们新特性的定义：

```cpp
def FeatureSQSum
     : SubtargetFeature<"sqsum", "HasSQSum", "true",
                                 "Use square-sum instruction">;
```

`SubtargetFeature`类有四个模板参数。第一个`sqsum`是特性的名称，用于命令行。第二个参数`HasSQSum`是`Subtarget`类中表示此特性的属性的名称。接下来的参数是特性的默认值和描述，用于在命令行上提供帮助。TableGen 会为`MipsSubtarget`类生成基类，该类在`MipsSubtarget.h`文件中定义。在这个文件中，我们在类的私有部分添加新属性，其中定义了所有其他属性：

```cpp
  // Has square-sum instruction.
  bool HasSQSum = false;
```

在公共部分，我们还添加了一个方法来检索属性的值。我们需要这个方法来进行下一个添加：

```cpp
  bool hasSQSum() const { return HasSQSum; }
```

有了这些添加，我们已经能够在命令行上设置`sqsum`功能，尽管没有效果。

为了将新指令与`sqsum`功能关联起来，我们需要定义一个谓词，指示是否选择了该功能。我们将其添加到`MipsInstrInfo.td`文件中，可以是在定义所有其他谓词的部分，也可以简单地添加到末尾：

```cpp
def HasSQSum : Predicate<"Subtarget->hasSQSum()">,
                     AssemblerPredicate<(all_of FeatureSQSum)>;
```

该谓词使用先前定义的`hasSQSum()`方法。此外，`AssemblerPredicate`模板指定了在为汇编器生成源代码时使用的条件。我们只需引用先前定义的功能。

我们还需要更新调度模型。MIPS 目标使用行程表和机器指令调度器。对于行程表模型，在`MipsSchedule.td`文件中为每条指令定义了一个`InstrItinClass`记录。只需在此文件的所有行程表都被定义的部分添加以下行：

```cpp
def II_SQSUMU : InstrItinClass;
```

我们还需要提供有关指令成本的详细信息。通常，您可以在 CPU 的文档中找到这些信息。对于我们的指令，我们乐观地假设它只需要在 ALU 中一个周期。这些信息被添加到同一文件中的`MipsGenericItineraries`定义中：

```cpp
InstrItinData<II_SQSUMU, [InstrStage<1, [ALU]>]>
```

有了这个，基于行程表的调度模型的更新就完成了。MIPS 目标还在`MipsScheduleGeneric.td`文件中定义了一个基于机器指令调度器模型的通用调度模型。因为这是一个涵盖所有指令的完整模型，我们还需要添加我们的指令。由于它是基于乘法的，我们只需扩展`MULT`和`MULTu`指令的现有定义：

```cpp
def : InstRW<[GenericWriteMul], (instrs MULT, MULTu, SQSUMu)>;
```

MIPS 目标还在`MipsScheduleP5600.td`文件中为 P5600 CPU 定义了一个调度模型。显然，我们的新指令在这个目标上不受支持，所以我们将其添加到不支持的功能列表中：

```cpp
list<Predicate> UnsupportedFeatures = [HasSQSum, HasMips3, … 
```

现在我们准备在`Mips64InstrInfo.td`文件的末尾添加新指令。TableGen 定义总是简洁的，因此我们对其进行分解。该定义使用 MIPS 目标描述中的一些预定义类。我们的新指令是一个算术指令，并且按设计，它适用于`ArithLogicR`类。第一个参数`"sqsumu"`指定了指令的汇编助记符。下一个参数`GPR64Opnd`表示指令使用 64 位寄存器作为操作数，接下来的`1`参数表示操作数是可交换的。最后，为指令给出了一个行程表。`ADD_FM`类用于指定指令的二进制编码。对于真实的指令，必须根据文档选择参数。然后是`ISA_MIPS64`谓词，指示指令适用于哪个指令集。最后，我们的`SQSUM`谓词表示只有在启用我们的功能时指令才有效。完整的定义如下：

```cpp
def SQSUMu  : ArithLogicR<"sqsumu", GPR64Opnd, 1, II_SQSUMU>,
                  ADD_FM<0x1c, 0x28>, ISA_MIPS64, SQSUM
```

如果您只想支持新指令，那么这个定义就足够了。在这种情况下，请确保用 `;` 结束定义。通过添加选择 DAG 模式，您可以使指令可用于代码生成器。该指令使用两个操作寄存器 `$rs` 和 `$rt`，以及目标寄存器 `$rd`，这三个寄存器都由 `ADD_FM` 二进制格式类定义。理论上，要匹配的模式很简单：使用 `mul` 乘法运算符对每个寄存器的值进行平方，然后使用 `add` 运算符将两个乘积相加，并赋值给目标寄存器 `$rd`。模式变得有点复杂，因为在 MIPS 指令集中，乘法的结果存储在一个特殊的寄存器对中。为了可用，结果必须移动到通用寄存器中。在操作合法化期间，通用的 `mul` 运算符被替换为 MIPS 特定的 `MipsMult` 操作进行乘法，以及 `MipsMFLO` 操作将结果的低位部分移动到通用寄存器中。在编写模式时，我们必须考虑到这一点，模式如下所示：

```cpp
{
  let Pattern = [(set GPR64Opnd:$rd,
                              (add (MipsMFLO (MipsMult   
                                GPR64Opnd:$rs, 

                                GPR64Opnd:$rs)),
                                      (MipsMFLO (MipsMult 
                                        GPR64Opnd:$rt, 

                                        GPR64Opnd:$rt)))
                                )];
}
```

如*使用选择 DAG 进行指令选择*部分所述，如果此模式与当前 DAG 节点匹配，则会选择我们的新指令。由于 `SQSUM` 谓词，只有在激活 `sqsum` 功能时才会发生这种情况。让我们用一个测试来检查一下！

## 测试新指令

如果您扩展了 LLVM，那么最好的做法是使用自动化测试来验证。特别是如果您想将您的扩展贡献给 LLVM 项目，那么就需要良好的测试。

在上一节中添加了一个新的机器指令后，我们必须检查两个不同的方面：

+   首先，我们必须验证指令编码是否正确。

+   其次，我们必须确保代码生成按预期工作。

LLVM 项目使用 `llvm-mc` 工具。除了其他任务，此工具可以显示指令的编码。为了进行临时检查，您可以运行以下命令来显示指令的编码：

```cpp
$ echo "sqsumu \$1,\$2,\$3" | \
  llvm-mc --triple=mips64-linux-gnu -mattr=+sqsum \
              --show-encoding
```

这已经显示了部分输入和在自动化测试用例中运行的命令。为了验证结果，您可以使用 `FileCheck` 工具。`llvm-mc` 的输出被传送到这个工具中。此外，`FileCheck` 会读取测试用例文件。测试用例文件包含了以 `CHECK:` 关键字标记的行，之后是预期的输出。`FileCheck` 会尝试将这些行与传送到它的数据进行匹配。如果没有找到匹配项，则会显示错误。将以下内容的 `sqsumu.s` 测试用例文件放入 `llvm/test/MC/Mips` 目录中：

```cpp
# RUN: llvm-mc %s -triple=mips64-linux-gnu -mattr=+sqsum \
# RUN:  --show-encoding | FileCheck %s
# CHECK: sqsumu  $1, $2, $3 # encoding: [0x70,0x43,0x08,0x28]
     sqsumu $1, $2, $3
```

如果您在 `llvm/test/Mips/MC` 文件夹中，可以使用以下命令运行测试，最后会报告成功：

```cpp
$ llvm-lit sqsumu.s
-- Testing: 1 tests, 1 workers --
PASS: LLVM :: MC/Mips/sqsumu.s (1 of 1)
Testing Time: 0.11s
  Passed: 1
```

LIT 工具解释 `RUN:` 行，将 `%s` 替换为当前的文件名。`FileCheck` 工具读取文件，解析 `CHECK:` 行，并尝试匹配来自管道的输入。这是一种非常有效的测试方法。

如果您在 `build` 目录中，可以使用以下命令调用 LLVM 测试：

```cpp
$ ninja check-llvm
```

您还可以运行一个文件夹中包含的测试，只需添加以破折号分隔的文件夹名称。要运行 `llvm/test/Mips/MC` 文件夹中的测试，可以输入以下命令：

```cpp
$ ninja check-llvm-mips-mc
```

要为代码生成构建一个测试用例，您可以遵循相同的策略。以下的 `sqsum.ll` 文件包含了用于计算斜边平方的 LLVM IR 代码：

```cpp
define i64 @hyposquare(i64 %a, i64 %b) {
  %asq = mul i64 %a, %a
  %bsq = mul i64 %b, %b
  %res = add i64 %asq, %bsq
  ret i64 %res
}
```

要查看生成的汇编代码，您可以使用 `llc` 工具：

```cpp
$ llc –mtriple=mips64-linux-gnu –mattr=+sqsum < sqsum.ll
```

确保您在输出中看到我们的新 `sqsum` 指令。还请检查，如果删除 `–mattr=+sqsum` 选项，则不会生成该指令。

掌握了这些知识，您可以构建测试用例。这次，我们使用两个`RUN：`行：一个用于检查我们是否生成了新指令，另一个用于检查是否没有生成。我们可以在一个测试用例文件中执行这两个操作，因为我们可以告诉`FileCheck`工具查找的标签与`CHECK：`不同。将以下内容的测试用例文件`sqsum.ll`放入`llvm/test/CodeGen/Mips`文件夹中：

```cpp
; RUN: llc -mtriple=mips64-linux-gnu -mattr=+sqsum < %s |\
; RUN:  FileCheck -check-prefix=SQSUM %s
; RUN: llc -mtriple=mips64-linux-gnu < %s |\
; RUN:  FileCheck --check-prefix=NOSQSUM %s
define i64 @hyposquare(i64 %a, i64 %b) {
; SQSUM-LABEL: hyposquare:
; SQSUM: sqsumu $2, $4, $5
; NOSQSUM-LABEL: hyposquare:
; NOSQSUM: dmult $5, $5
; NOSQSUM: mflo $1
; NOSQSUM: dmult $4, $4
; NOSQSUM: mflo $2
; NOSQSUM: addu $2, $2, $1
  %asq = mul i64 %a, %a
  %bsq = mul i64 %b, %b
  %res = add i64 %asq, %bsq
  ret i64 %res
}
```

与其他测试一样，您可以使用以下命令在文件夹中单独运行测试：

```cpp
$ llvm-lit squm.ll
```

或者，您可以使用以下命令从构建目录运行它：

```cpp
$ ninja check-llvm-mips-codegen
```

通过这些步骤，您增强了 LLVM 汇编器的功能，使其支持新指令，启用了指令选择以使用这个新指令，并验证了编码是否正确，代码生成是否按预期工作。

# 总结

在本章中，您学习了 LLVM 目标的后端结构。您使用 MIR 来检查通过后的状态，并使用机器 IR 来运行单个通过。有了这些知识，您可以调查后端通过中的问题。

您学习了 LLVM 中如何使用选择 DAG 来实现指令选择，并且还介绍了使用 FastISel 和 GlobalISel 进行指令选择的替代方法，这有助于决定如果您的平台提供所有这些算法，则选择哪种算法。

您扩展了 LLVM 以支持汇编器中的新机器指令和指令选择，帮助您添加对当前不支持的 CPU 功能的支持。为了验证扩展，您为其开发了自动化测试用例。

在下一章中，我们将研究 LLVM 的另一个独特特性：一步生成和执行代码，也称为**即时**（**JIT**）编译。


# 第十章：JIT 编译

LLVM 核心库配备了**ExecutionEngine**组件，允许在内存中编译和执行 IR 代码。使用这个组件，我们可以构建**即时**（**JIT**）编译器，允许直接执行 IR 代码。JIT 编译器更像解释器，因为不需要在辅助存储上存储目标代码。

在本章中，您将了解 JIT 编译器的应用程序，以及 LLVM JIT 编译器的工作原理。您将探索 LLVM 动态编译器和解释器，还将学习如何自己实现 JIT 编译器工具。您还将了解如何在静态编译器中使用 JIT 编译器，以及相关的挑战。

本章将涵盖以下主题：

+   获取 LLVM 的 JIT 实现和用例概述

+   使用 JIT 编译进行直接执行

+   利用 JIT 编译器进行代码评估

在本章结束时，您将了解如何开发 JIT 编译器，无论是使用预配置的类还是符合您需求的定制版本。您还将获得使用静态编译器内部的 JIT 编译器的知识。

# 技术要求

本章的代码文件可以在[`github.com/PacktPublishing/Learn-LLVM-12/tree/master/Chapter10`](https://github.com/PacktPublishing/Learn-LLVM-12/tree/master/Chapter10)找到

您可以在[`bit.ly/3nllhED`](https://bit.ly/3nllhED)找到代码的实际操作视频

# 获取 LLVM 的 JIT 实现和用例概述

到目前为止，我们只看过**提前**（**AOT**）编译器。这些编译器编译整个应用程序。只有在编译完成后，应用程序才能运行。如果在应用程序运行时进行编译，则编译器是 JIT 编译器。JIT 编译器有一些有趣的用例：

+   **虚拟机的实现**：编程语言可以使用 AOT 编译器将其转换为字节码。在运行时，JIT 编译器用于将字节码编译为机器代码。这种方法的优势在于字节码是与硬件无关的，并且由于 JIT 编译器，与 AOT 编译器相比没有性能损失。如今，Java 和 C#使用这种模型，但这个想法实际上很古老：1977 年的 USCD Pascal 编译器已经使用了类似的方法。

+   **表达式评估**：电子表格应用程序可以使用 JIT 编译器编译经常执行的表达式。例如，这可以加速财务模拟。LLVM 调试器 LLDB 使用这种方法在调试时评估源表达式。

+   **数据库查询**：数据库从数据库查询创建执行计划。执行计划描述了对表和列的操作，这导致了查询执行时的结果。JIT 编译器可以用于将执行计划转换为机器代码，从而加速查询的执行。

LLVM 的静态编译模型并不像你想象的那样远离 JIT 模型。LLVM 静态编译器`llc`将 LLVM IR 编译成机器代码，并将结果保存为磁盘上的目标文件。如果目标文件不是存储在磁盘上而是存储在内存中，那么代码是否可以执行？不直接执行，因为对全局函数和全局数据的引用使用重定位而不是绝对地址。

概念上，重定位描述了如何计算地址，例如，作为已知地址的偏移量。如果我们解析重定位为地址，就像链接器和动态加载器所做的那样，那么我们就可以执行目标代码。运行静态编译器将 IR 代码编译成内存中的目标文件，对内存中的目标文件进行链接步骤，然后运行代码，这就给我们了一个 JIT 编译器。LLVM 核心库中的 JIT 实现就是基于这个想法的。

在 LLVM 的开发历史中，有几个不同功能集的 JIT 实现。最新的 JIT API 是**按需编译**（**ORC**）引擎。如果你想知道这个首字母缩略词的含义：这是首席开发人员的意图，在托尔金的宇宙基础上发明另一个首字母缩略词，之前已经有了**ELF**（**可执行和链接格式**）和**DWARF**（**调试标准**）。

ORC 引擎建立在使用静态编译器和动态链接器在内存中的对象文件上的想法之上，并对其进行了扩展。实现采用了*分层*方法。两个基本级别如下：

1.  编译层

1.  链接层

在编译层之上可以放置一个提供对*延迟编译*的支持的层。**转换层**可以堆叠在延迟编译层的上方或下方，允许开发人员添加任意的转换，或者只是在某些事件发生时得到通知。这种分层方法的优势在于 JIT 引擎可以*根据不同的需求进行定制*。例如，高性能虚拟机可能会选择预先编译所有内容，并且不使用延迟编译层。其他虚拟机将强调启动时间和对用户的响应性，并通过延迟编译层的帮助来实现这一点。

较旧的 MCJIT 引擎仍然可用。API 源自一个更早的、已经删除的 JIT 引擎。随着时间的推移，API 变得有点臃肿，并且缺乏 ORC API 的灵活性。目标是删除这个实现，因为 ORC 引擎现在提供了 MCJIT 引擎的所有功能。新的开发应该使用 ORC API。

在下一节中，我们将先看看`lli`，LLVM 解释器和动态编译器，然后再深入实现 JIT 编译器。

# 使用 JIT 编译进行直接执行

直接运行 LLVM IR 是在考虑 JIT 编译器时首先想到的想法。这就是`lli`工具，LLVM 解释器和动态编译器所做的。我们将在下一节中探索`lli`工具，并随后自己实现类似的工具。

## 探索 lli 工具

让我们尝试使用`lli`工具进行一个非常简单的示例。将以下源代码存储为`hello.ll`文件。这相当于一个 C 语言的 hello world 应用程序。它声明了 C 库中`printf()`函数的原型。`hellostr`常量包含要打印的消息。在`main()`函数内部，通过`getelementptr`指令计算出消息的第一个字符的指针，并将该值传递给`printf()`函数。该应用程序始终返回`0`。完整的源代码如下：

```cpp
declare i32 @printf(i8*, ...)
@hellostr = private unnamed_addr constant [13 x i8] c"Hello                                                   world\0A\00"
define i32 @main(i32 %argc, i8** %argv) {
  %res = call i32 (i8*, ...) @printf(                  i8* getelementptr inbounds ([13 x i8],                          [13 x i8]* @hellostr, i64 0, i64 0))
  ret i32 0
}
```

这个 LLVM IR 文件足够通用，适用于所有平台。我们可以直接使用以下命令在`lli`工具中执行 IR：

```cpp
$ lli hello.ll
Hello world
```

这里有趣的一点是如何找到`printf()`函数。IR 代码被编译成机器代码，并触发了对`printf`符号的查找。在 IR 中找不到这个符号，所以当前进程会在其中搜索。`lli`工具动态链接到 C 库，并在那里找到了该符号。

当然，`lli`工具不会链接到您创建的库。为了启用这些函数的使用，`lli`工具支持加载共享库和对象。以下 C 源代码只是打印一个友好的消息：

```cpp
#include <stdio.h>
void greetings() {
  puts("Hi!");
}
```

存储在`greetings.c`文件中，我们将用它来探索使用`lli`工具加载对象。将此源代码编译成共享库。`-fPIC`选项指示 clang 生成位置无关的代码，这对于共享库是必需的。给定`-shared`选项后，编译器将创建`greetings.so`共享库：

```cpp
$ clang –fPIC –shared –o greetings.so greetings.c
```

我们还将文件编译成`greetings.o`对象文件：

```cpp
$ clang –c –o greetings.o greetings.c
```

现在我们有两个文件，`greetings.so`共享库和`greetings.o`对象文件，我们将它们加载到`lli`工具中。

我们还需要一个 LLVM IR 文件，其中调用`greetings()`函数。为此，请创建包含对该函数的单个调用的`main.ll`文件：

```cpp
declare void @greetings(...)
define dso_local i32 @main(i32 %argc, i8** %argv) {
  call void (...) @greetings()
  ret i32 0
}
```

如果尝试像以前一样执行 IR，则`lli`工具无法找到`greetings`符号，将简单崩溃：

```cpp
$ lli main.ll
PLEASE submit a bug report to https://bugs.llvm.org/ and include the crash backtrace.
```

`greetings()`函数在外部文件中定义，为了修复崩溃，我们必须告诉`lli`工具需要加载哪个附加文件。为了使用共享库，您必须使用`–load`选项，该选项以共享库的路径作为参数：

```cpp
$ lli –load ./greetings.so main.ll
Hi!
```

如果包含共享库的目录不在动态加载器的搜索路径中，则重要的是指定共享库的路径。如果省略，则将无法找到库。

或者，我们可以指示`lli`工具使用`–extra-object`选项加载对象文件：

```cpp
$ lli –extra-object greetings.o main.ll
Hi!
```

其他支持的选项是`–extra-archive`，它加载存档，以及`–extra-module`，它加载另一个位代码文件。这两个选项都需要文件的路径作为参数。

现在您知道如何使用`lli`工具直接执行 LLVM IR。在下一节中，我们将实现自己的 JIT 工具。

## 使用 LLJIT 实现我们自己的 JIT 编译器

`lli`工具只是 LLVM API 周围的薄包装器。在第一节中，我们了解到 ORC 引擎使用分层方法。`ExecutionSession`类表示正在运行的 JIT 程序。除其他项目外，此类还保存了使用的`JITDylib`实例。`JITDylib`实例是一个符号表，将符号名称映射到地址。例如，这可以是 LLVM IR 文件中定义的符号，或者是加载的共享库的符号。

要执行 LLVM IR，我们不需要自己创建 JIT 堆栈。实用程序`LLJIT`类提供此功能。当从较旧的 MCJIT 实现迁移时，您也可以使用此类。该类基本上提供了相同的功能。我们将在下一小节中开始实现 JIT 引擎的初始化。

### 初始化用于编译 LLVM IR 的 JIT 引擎

我们首先实现设置 JIT 引擎，编译 LLVM IR 模块并在此模块中执行`main()`函数的函数。稍后，我们将使用此核心功能构建一个小型 JIT 工具。这是`jitmain()`函数：

1.  该函数需要执行 LLVM 模块的 LLVM IR。还需要用于此模块的 LLVM 上下文类，因为上下文类保存重要的类型信息。目标是调用`main()`函数，因此我们还传递通常的`argc`和`argv`参数：

```cpp
Error jitmain(std::unique_ptr<Module> M,
              std::unique_ptr<LLVMContext> Ctx, int 
              argc,
              char *argv[]) {
```

1.  我们使用`LLJITBuilder`类创建`LLJIT`实例。如果发生错误，则返回错误。错误的可能来源是平台尚不支持 JIT 编译：

```cpp
  auto JIT = orc::LLJITBuilder().create();
  if (!JIT)
    return JIT.takeError();
```

1.  然后我们将模块添加到主`JITDylib`实例中。如果配置，则 JIT 编译将利用多个线程。因此，我们需要将模块和上下文包装在`ThreadSafeModule`实例中。如果发生错误，则返回错误：

```cpp
  if (auto Err = (*JIT)->addIRModule(
          orc::ThreadSafeModule(std::move(M),
                                std::move(Ctx))))
    return Err;
```

1.  与`lli`工具一样，我们还支持 C 库中的符号。`DefinitionGenerator`类公开符号，`DynamicLibrarySearchGenerator`子类公开共享库中找到的名称。该类提供了两个工厂方法。`Load()`方法可用于加载共享库，而`GetForCurrentProcess()`方法公开当前进程的符号。我们使用后者功能。符号名称可以具有前缀，取决于平台。我们检索数据布局并将前缀传递给`GetForCurrentprocess()`函数。然后符号名称将以正确的方式处理，我们不需要关心它。通常情况下，如果发生错误，我们会从函数中返回：

```cpp
  const DataLayout &DL = (*JIT)->getDataLayout();
  auto DLSG = orc::DynamicLibrarySearchGenerator::
      GetForCurrentProcess(DL.getGlobalPrefix());
  if (!DLSG)
    return DLSG.takeError();
```

1.  然后我们将生成器添加到主`JITDylib`实例中。如果需要查找符号，则还会搜索加载的共享库中的符号：

```cpp
  (*JIT)->getMainJITDylib().addGenerator(
      std::move(*DLSG));
```

1.  接下来，我们查找`main`符号。该符号必须在命令行给出的 IR 模块中。查找触发了该 IR 模块的编译。如果 IR 模块内引用了其他符号，则使用前一步添加的生成器进行解析。结果是`JITEvaluatedSymbol`类的实例：

```cpp
  auto MainSym = (*JIT)->lookup("main");
  if (!MainSym)
    return MainSym.takeError();
```

1.  我们询问返回的 JIT 符号函数的地址。我们将此地址转换为 C `main()`函数的原型：

```cpp
  auto *Main = (int (*)(
      int, char **))MainSym->getAddress();
```

1.  现在我们可以在 IR 模块中调用`main()`函数，并传递函数期望的`argc`和`argv`参数。我们忽略返回值：

```cpp
  (void)Main(argc, argv);
```

1.  函数执行后报告成功：

```cpp
  return Error::success();
}
```

这演示了使用 JIT 编译是多么容易。除了暴露当前进程或共享库中的符号之外，还有许多其他可能性。`StaticLibraryDefinitionGenerator`类暴露了静态存档中找到的符号，并且可以像`DynamicLibrarySearchGenerator`类一样使用。`LLJIT`类还有一个`addObjectFile()`方法来暴露对象文件的符号。如果现有的实现不符合您的需求，您还可以提供自己的`DefinitionGenerator`实现。在下一小节中，您将把实现扩展为 JIT 编译器。

### 创建 JIT 编译器实用程序

`jitmain()`函数很容易扩展为一个小工具，我们接下来就这样做。源代码保存在`JIT.cpp`文件中，是一个简单的 JIT 编译器：

1.  我们必须包含几个头文件。`LLJIT.h`头文件定义了`LLJIT`类和 ORC API 的核心类。我们包含`IRReader.h`头文件，因为它定义了一个用于读取 LLVM IR 文件的函数。`CommandLine.h`头文件允许我们以 LLVM 风格解析命令行选项。最后，`InitLLVM.h`头文件用于工具的基本初始化，`TargetSelect.h`头文件用于本机目标的初始化：

```cpp
#include "llvm/ExecutionEngine/Orc/LLJIT.h"
#include "llvm/IRReader/IRReader.h"
#include "llvm/Support/CommandLine.h"
#include "llvm/Support/InitLLVM.h"
#include "llvm/Support/TargetSelect.h"
```

1.  我们将`llvm`命名空间添加到当前作用域中：

```cpp
using namespace llvm;
```

1.  我们的 JIT 工具在命令行上期望有一个输入文件，我们使用`cl::opt<>`类声明这个文件：

```cpp
static cl::opt<std::string>
    InputFile(cl::Positional, cl::Required,
              cl::desc("<input-file>"));
```

1.  要读取 IR 文件，我们调用`parseIRFile()`函数。文件可以是文本 IR 表示，也可以是位码文件。该函数返回指向创建的模块的指针。错误处理有点不同，因为可以解析文本 IR 文件，这不一定是语法正确的。`SMDiagnostic`实例在语法错误时保存错误信息。错误消息被打印，应用程序退出：

```cpp
std::unique_ptr<Module>
loadModule(StringRef Filename, LLVMContext &Ctx,
           const char *ProgName) {
  SMDiagnostic Err;
  std::unique_ptr<Module> Mod =
      parseIRFile(Filename, Err, Ctx);
  if (!Mod.get()) {
    Err.print(ProgName, errs());
    exit(-1);
  }
  return std::move(Mod);
}
```

1.  `jitmain()`函数放在这里：

```cpp
Error jitmain(…) { … }
```

1.  然后我们添加`main()`函数，该函数初始化工具和本机目标，并解析命令行：

```cpp
int main(int argc, char *argv[]) {
  InitLLVM X(argc, argv);
  InitializeNativeTarget();
  InitializeNativeTargetAsmPrinter();
  InitializeNativeTargetAsmParser();
  cl::ParseCommandLineOptions(argc, argv,
                              "JIT\n");
```

1.  接下来，初始化 LLVM 上下文类：

```cpp
  auto Ctx = std::make_unique<LLVMContext>();
```

1.  然后我们加载命令行上命名的 IR 模块：

```cpp
  std::unique_ptr<Module> M =
      loadModule(InputFile, *Ctx, argv[0]);
```

1.  然后我们可以调用`jitmain()`函数。为了处理错误，我们使用`ExitOnError`实用类。当发生错误时，该类打印错误消息并退出应用程序。我们还设置了一个横幅，显示应用程序的名称，该横幅会在错误消息之前打印：

```cpp
  ExitOnError ExitOnErr(std::string(argv[0]) + ": ");
  ExitOnErr(jitmain(std::move(M), std::move(Ctx),
                    argc, argv));
```

1.  如果控制流到达这一点，那么 IR 已成功执行。我们返回`0`表示成功：

```cpp
  return 0;
}
```

这已经是完整的实现了！我们只需要添加构建描述，这是下一小节的主题。

### 添加 CMake 构建描述

为了编译这个源文件，我们还需要创建一个`CMakeLists.txt`文件，其中包含构建描述，保存在`JIT.cpp`文件旁边：

1.  我们将最小要求的 CMake 版本设置为 LLVM 所需的版本号，并给项目命名为`jit`：

```cpp
cmake_minimum_required (VERSION 3.13.4)
project ("jit")
```

1.  LLVM 包需要被加载，我们将 LLVM 提供的 CMake 模块目录添加到搜索路径中。然后我们包含`ChooseMSVCCRT`模块，以确保与 LLVM 使用相同的 C 运行时：

```cpp
find_package(LLVM REQUIRED CONFIG)
list(APPEND CMAKE_MODULE_PATH ${LLVM_DIR})
include(ChooseMSVCCRT)
```

1.  我们还需要添加 LLVM 的定义和包含路径。使用的 LLVM 组件通过函数调用映射到库名称：

```cpp
add_definitions(${LLVM_DEFINITIONS})
include_directories(SYSTEM ${LLVM_INCLUDE_DIRS})
llvm_map_components_to_libnames(llvm_libs Core OrcJIT
                                          Support 
                                          native)
```

1.  最后，我们定义可执行文件的名称，要编译的源文件以及要链接的库：

```cpp
add_executable(JIT JIT.cpp)
target_link_libraries(JIT ${llvm_libs})
```

1.  这就是 JIT 工具所需的一切。创建并切换到构建目录，然后运行以下命令来创建和编译应用程序：

```cpp
$ cmake –G Ninja <path to source directory>
$ ninja
```

这将编译`JIT`工具。您可以使用本章开头的`hello.ll`文件检查功能：

```cpp
$ JIT hello.ll
Hello world
```

创建 JIT 编译器非常容易！

示例使用 LLVM IR 作为输入，但这不是必需的。`LLJIT`类使用`IRCompileLayer`类，负责将 IR 编译为机器代码。您可以定义自己的层，接受您需要的输入，例如 Java 字节码。

使用预定义的 LLJIT 类很方便，但限制了我们的灵活性。在下一节中，我们将看看如何使用 ORC API 提供的层来实现 JIT 编译器。

## 从头开始构建 JIT 编译器类

使用 ORC 的分层方法，非常容易构建符合要求的 JIT 编译器。没有一种通用的 JIT 编译器，本章的第一部分给出了一些例子。让我们看看如何设置 JIT 编译器。

ORC API 使用堆叠在一起的层。最低级别是对象链接层，由`llvm::orc::RTDyldObjectLinkingLayer`类表示。它负责链接内存对象并将其转换为可执行代码。此任务所需的内存由`MemoryManager`接口的实例管理。有一个默认实现，但如果需要，我们也可以使用自定义版本。

对象链接层上面是编译层，负责创建内存中的目标文件。`llvm::orc::IRCompileLayer`类以 IR 模块作为输入，并将其编译为目标文件。`IRCompileLayer`类是`IRLayer`类的子类，后者是接受 LLVM IR 的层实现的通用类。

这两个层已经构成了 JIT 编译器的核心。它们将 LLVM IR 模块作为输入，编译并链接到内存中。要添加更多功能，我们可以在这两个层之上添加更多层。例如，`CompileOnDemandLayer`类将模块拆分，以便仅编译请求的函数。这可以用于实现延迟编译。`CompileOnDemandLayer`类也是`IRLayer`类的子类。以非常通用的方式，`IRTransformLayer`类，也是`IRLayer`类的子类，允许我们对模块应用转换。

另一个重要的类是`ExecutionSession`类。这个类表示正在运行的 JIT 程序。基本上，这意味着该类管理`JITDylib`符号表，为符号提供查找功能，并跟踪使用的资源管理器。

JIT 编译器的通用配方如下：

1.  初始化`ExecutionSession`类的一个实例。

1.  初始化层，至少包括`RTDyldObjectLinkingLayer`类和`IRCompileLayer`类。

1.  创建第一个`JITDylib`符号表，通常使用`main`或类似的名称。

使用方法与上一节的`LLJIT`类非常相似：

1.  将 IR 模块添加到符号表中。

1.  查找符号，触发相关函数的编译，可能是整个模块。

1.  执行函数。

在下一小节中，我们将基于通用配方实现一个 JIT 编译器类。

### 创建一个 JIT 编译器类

为了保持 JIT 编译器类的实现简单，我们将所有内容放入`JIT.h`头文件中。类的初始化有点复杂。由于需要处理可能的错误，我们需要一个工厂方法在调用构造函数之前创建一些对象。创建类的步骤如下：

1.  我们首先使用`JIT_H`预处理器定义保护头文件免受多次包含的影响：

```cpp
#ifndef JIT_H
#define JIT_H
```

1.  需要一堆包含文件。其中大多数提供与头文件同名的类。`Core.h`头文件提供了一些基本类，包括`ExecutionSession`类。`ExecutionUtils.h`头文件提供了`DynamicLibrarySearchGenerator`类来搜索库中的符号，我们已经在*使用 LLJIT 实现我们自己的 JIT 编译器*部分中使用过。`CompileUtils.h`头文件提供了`ConcurrentIRCompiler`类：

```cpp
#include "llvm/Analysis/AliasAnalysis.h"
#include "llvm/ExecutionEngine/JITSymbol.h"
#include "llvm/ExecutionEngine/Orc/CompileUtils.h"
#include "llvm/ExecutionEngine/Orc/Core.h"
#include "llvm/ExecutionEngine/Orc/ExecutionUtils.h"
#include "llvm/ExecutionEngine/Orc/IRCompileLayer.h"
#include "llvm/ExecutionEngine/Orc/IRTransformLayer.h"
#include     "llvm/ExecutionEngine/Orc/JITTargetMachineBuilder.h"
#include "llvm/ExecutionEngine/Orc/Mangling.h"
#include     "llvm/ExecutionEngine/Orc/RTDyldObjectLinkingLayer.h"
#include     "llvm/ExecutionEngine/Orc/TargetProcessControl.h"
#include "llvm/ExecutionEngine/SectionMemoryManager.h"
#include "llvm/Passes/PassBuilder.h"
#include "llvm/Support/Error.h"
```

1.  我们的新类是`JIT`类：

```cpp
class JIT {
```

1.  私有数据成员反映了 ORC 层和一个辅助类。 `ExecutionSession`，`ObjectLinkingLayer`，`CompileLayer`，`OptIRLayer`和`MainJITDylib`实例代表了运行中的 JIT 程序，层和符号表，如前所述。 `TargetProcessControl`实例用于与 JIT 目标进程进行交互。这可以是相同的进程，同一台机器上的另一个进程，或者是不同机器上的远程进程，可能具有不同的架构。 `DataLayout`和`MangleAndInterner`类需要以正确的方式操纵符号名称。符号名称是内部化的，这意味着所有相等的名称具有相同的地址。要检查两个符号名称是否相等，只需比较地址，这是一个非常快速的操作：

```cpp
  std::unique_ptr<llvm::orc::TargetProcessControl> 
    TPC;
  std::unique_ptr<llvm::orc::ExecutionSession> ES;
  llvm::DataLayout DL;
  llvm::orc::MangleAndInterner Mangle;
  std::unique_ptr<llvm::orc::RTDyldObjectLinkingLayer>
      ObjectLinkingLayer;
  std::unique_ptr<llvm::orc::IRCompileLayer>
      CompileLayer;
  std::unique_ptr<llvm::orc::IRTransformLayer>
      OptIRLayer;
  llvm::orc::JITDylib &MainJITDylib;
```

1.  初始化分为三个部分。在 C++中，构造函数不能返回错误。简单且推荐的解决方案是创建一个静态工厂方法，在构造对象之前进行错误处理。层的初始化更复杂，因此我们也为它们引入了工厂方法。

在`create()`工厂方法中，我们首先创建一个`SymbolStringPool`实例，用于实现字符串内部化，并由几个类共享。为了控制当前进程，我们创建一个`SelfTargetProcessControl`实例。如果我们想要针对不同的进程，则需要更改此实例。

然后，我们构造了一个`JITTargetMachineBuilder`实例，我们需要知道 JIT 进程的目标三元组。接下来，我们查询目标机器生成器以获取数据布局。如果生成器无法根据提供的三元组实例化目标机器，例如，因为对此目标的支持未编译到 LLVM 库中，这一步可能会失败：

```cpp
public:
  static llvm::Expected<std::unique_ptr<JIT>> create() {
    auto SSP =
        std::make_shared<llvm::orc::SymbolStringPool>();
    auto TPC =
        llvm::orc::SelfTargetProcessControl::Create(SSP);
    if (!TPC)
      return TPC.takeError();
    llvm::orc::JITTargetMachineBuilder JTMB(
        (*TPC)->getTargetTriple());
    auto DL = JTMB.getDefaultDataLayoutForTarget();
    if (!DL)
      return DL.takeError();
```

1.  在这一点上，我们已经处理了所有可能失败的调用。我们现在能够初始化`ExecutionSession`实例。最后，调用`JIT`类的构造函数，并将结果返回给调用者：

```cpp
    auto ES =
        std::make_unique<llvm::orc::ExecutionSession>(
            std::move(SSP));
    return std::make_unique<JIT>(
        std::move(*TPC), std::move(ES), 
        std::move(*DL),
        std::move(JTMB));
  }
```

1.  `JIT`类的构造函数将传递的参数移动到私有数据成员。通过调用带有`create`前缀的静态工厂名称构造层对象。每个`layer`工厂方法都需要引用`ExecutionSession`实例，将层连接到运行中的 JIT 会话。除了对象链接层位于层堆栈的底部之外，每个层还需要引用上一个层，说明了堆叠顺序：

```cpp
  JIT(std::unique_ptr<llvm::orc::TargetProcessControl>
          TPCtrl,
      std::unique_ptr<llvm::orc::ExecutionSession> ExeS,
      llvm::DataLayout DataL,
      llvm::orc::JITTargetMachineBuilder JTMB)
      : TPC(std::move(TPCtrl)), ES(std::move(ExeS)),
        DL(std::move(DataL)), Mangle(*ES, DL),
        ObjectLinkingLayer(std::move(
            createObjectLinkingLayer(*ES, JTMB))),
        CompileLayer(std::move(createCompileLayer(
            *ES, *ObjectLinkingLayer, 
             std::move(JTMB)))),
        OptIRLayer(std::move(
            createOptIRLayer(*ES, *CompileLayer))),
        MainJITDylib(ES->createBareJITDylib("<main>")) {
```

1.  在构造函数的主体中，我们添加了生成器来搜索当前进程的符号。`GetForCurrentProcess()`方法是特殊的，因为返回值包装在`Expected<>`模板中，表示也可以返回`Error`对象。但我们知道不会发生错误-当前进程最终会运行！因此，我们使用`cantFail()`函数解包结果，如果发生错误，它将终止应用程序：

```cpp
    MainJITDylib.addGenerator(llvm::cantFail(
        llvm::orc::DynamicLibrarySearchGenerator::
            GetForCurrentProcess(DL.getGlobalPrefix())));
  }
```

1.  要创建对象链接层，我们需要提供一个内存管理器。我们在这里坚持使用默认的`SectionMemoryManager`类，但如果需要，我们也可以提供不同的实现：

```cpp
  static std::unique_ptr<
      llvm::orc::RTDyldObjectLinkingLayer>
  createObjectLinkingLayer(
      llvm::orc::ExecutionSession &ES,
      llvm::orc::JITTargetMachineBuilder &JTMB) {
    auto GetMemoryManager = []() {
      return std::make_unique<
          llvm::SectionMemoryManager>();
    };
    auto OLLayer = std::make_unique<
        llvm::orc::RTDyldObjectLinkingLayer>(
        ES, GetMemoryManager);
```

1.  对于在 Windows 上使用的 COFF 目标文件格式存在一个小复杂性。这种文件格式不允许将函数标记为导出。这随后导致在对象链接层内部的检查失败：存储在符号中的标志与 IR 中的标志进行比较，由于缺少导出标记而导致不匹配。解决方案是仅针对这种文件格式覆盖标志。这完成了对象层的构建，并将对象返回给调用者：

```cpp
    if (JTMB.getTargetTriple().isOSBinFormatCOFF()) {
      OLLayer
         ->setOverrideObjectFlagsWithResponsibilityFlags(
              true);
      OLLayer
         ->setAutoClaimResponsibilityForObjectSymbols(
              true);
    }
    return std::move(OLLayer);
  }
```

1.  要初始化编译器层，需要一个`IRCompiler`实例。`IRCompiler`实例负责将 IR 模块编译成目标文件。如果我们的 JIT 编译器不使用线程，那么我们可以使用`SimpleCompiler`类，它使用给定的目标机器编译 IR 模块。`TargetMachine`类不是线程安全的，同样`SimpleCompiler`类也不是。为了支持多线程编译，我们使用`ConcurrentIRCompiler`类，它为每个要编译的模块创建一个新的`TargetMachine`实例。这种方法解决了多线程的问题：

```cpp
  static std::unique_ptr<llvm::orc::IRCompileLayer>
  createCompileLayer(
      llvm::orc::ExecutionSession &ES,
      llvm::orc::RTDyldObjectLinkingLayer &OLLayer,
      llvm::orc::JITTargetMachineBuilder JTMB) {
    auto IRCompiler = std::make_unique<
        llvm::orc::ConcurrentIRCompiler>(
        std::move(JTMB));
    auto IRCLayer =
        std::make_unique<llvm::orc::IRCompileLayer>(
            ES, OLLayer, std::move(IRCompiler));
    return std::move(IRCLayer);
  }
```

1.  我们不直接将 IR 模块编译成机器代码，而是安装一个优化 IR 的层。这是一个有意的设计决定：我们将我们的 JIT 编译器转变为一个优化的 JIT 编译器，它产生更快的代码，但需要更长的时间来生成，这对用户来说会有延迟。我们不添加延迟编译，所以当查找一个符号时，整个模块都会被编译。这可能会导致用户在看到代码执行之前花费相当长的时间。

```cpp
  static std::unique_ptr<llvm::orc::IRTransformLayer>
  createOptIRLayer(
      llvm::orc::ExecutionSession &ES,
      llvm::orc::IRCompileLayer &CompileLayer) {
    auto OptIRLayer =
        std::make_unique<llvm::orc::IRTransformLayer>(
            ES, CompileLayer,
            optimizeModule);
    return std::move(OptIRLayer);
  }
```

1.  `optimizeModule()`函数是对 IR 模块进行转换的一个示例。该函数以要转换的模块作为参数，并返回转换后的模块。由于 JIT 可能会使用多个线程，IR 模块被包装在一个`ThreadSafeModule`实例中：

```cpp
  static llvm::Expected<llvm::orc::ThreadSafeModule>
  optimizeModule(
      llvm::orc::ThreadSafeModule TSM,
      const llvm::orc::MaterializationResponsibility
          &R) {
```

1.  为了优化 IR，我们回顾一些来自*第八章*的信息，*优化 IR*，在*向编译器添加优化流水线*部分。我们需要一个`PassBuilder`实例来创建一个优化流水线。首先，我们定义了一些分析管理器，并在通行构建器中注册它们。然后，我们使用默认的优化流水线填充了一个`ModulePassManager`实例，用于`O2`级别。这再次是一个设计决定：`O2`级别已经产生了快速的机器代码，但比`O3`级别更快。之后，我们在模块上运行流水线。最后，优化后的模块返回给调用者：

```cpp
    TSM.withModuleDo([](llvm::Module &M) {
      bool DebugPM = false;
      llvm::PassBuilder PB(DebugPM);
      llvm::LoopAnalysisManager LAM(DebugPM);
      llvm::FunctionAnalysisManager FAM(DebugPM);
      llvm::CGSCCAnalysisManager CGAM(DebugPM);
      llvm::ModuleAnalysisManager MAM(DebugPM);
      FAM.registerPass(
          [&] { return PB.buildDefaultAAPipeline(); });
      PB.registerModuleAnalyses(MAM);
      PB.registerCGSCCAnalyses(CGAM);
      PB.registerFunctionAnalyses(FAM);
      PB.registerLoopAnalyses(LAM);
      PB.crossRegisterProxies(LAM, FAM, CGAM, MAM);
      llvm::ModulePassManager MPM =
          PB.buildPerModuleDefaultPipeline(
              llvm::PassBuilder::OptimizationLevel::O2,
              DebugPM);
      MPM.run(M, MAM);
    });
    return std::move(TSM);
  }
```

1.  `JIT`类的客户端需要一种添加 IR 模块的方法，我们使用`addIRModule()`函数提供这种方法。记住我们创建的层栈：我们必须将 IR 模块添加到顶层，否则我们可能会意外地绕过一些层。这将是一个不容易发现的编程错误：如果`OptIRLayer`成员被`CompileLayer`成员替换，那么我们的`JIT`类仍然可以工作，但不作为一个优化的 JIT，因为我们已经绕过了这一层。这在这个小实现中并不值得担心，但在一个大的 JIT 优化中，我们会引入一个函数来返回顶层层次：

```cpp
  llvm::Error addIRModule(
      llvm::orc::ThreadSafeModule TSM,
      llvm::orc::ResourceTrackerSP RT = nullptr) {
    if (!RT)
      RT = MainJITDylib.getDefaultResourceTracker();
    return OptIRLayer->add(RT, std::move(TSM));
  }
```

1.  同样，我们的 JIT 类的客户端需要一种查找符号的方法。我们将这个任务委托给`ExecutionSession`实例，传入主符号表的引用以及所请求符号的 mangled 和 internalized 名称：

```cpp
  llvm::Expected<llvm::JITEvaluatedSymbol>
  lookup(llvm::StringRef Name) {
    return ES->lookup({&MainJITDylib},
                      Mangle(Name.str()));
  }
```

将 JIT 编译器组合在一起相当容易。初始化这个类有点棘手，因为它涉及到`JIT`类的一个工厂方法和构造函数调用，以及每个层的工厂方法。这种分布是由于 C++的限制，尽管代码本身很简单。

在下一小节中，我们将使用我们的新 JIT 编译器类来实现一个命令行实用程序。

### 使用我们的新 JIT 编译器类

我们的新 JIT 编译器类的接口类似于*使用 LLJIT 实现我们自己的 JIT 编译器*部分中使用的`LLJIT`类。为了测试我们的新实现，我们从上一节中复制`LIT.cpp`类，并进行以下更改：

1.  为了能够使用我们的新类，我们包含`JIT.h`头文件。这取代了`llvm/ExecutionEngine/Orc/LLJIT.h`头文件，因为我们不再使用 LLJIT 类，所以它不再需要。

1.  在`jitmain()`函数中，我们用对我们的新`JIT::create()`方法的调用替换了对`orc::LLJITBuilder().create()`的调用。

1.  同样，在`jitmain()`函数中，我们删除了添加`DynamicLibrarySearchGenerator`类的代码。这个生成器已经集成在 JIT 类中。

这已经是需要改变的一切了！我们可以像在上一节中一样编译和运行更改后的应用程序，得到相同的结果。在底层，新类使用了固定的优化级别，因此对于足够大的模块，我们可以注意到启动和运行时的差异。

拥有 JIT 编译器可以激发新的想法。在下一节中，我们将看看如何将 JIT 编译器作为静态编译器的一部分来评估编译时的代码。

# 利用 JIT 编译器进行代码评估

编译器编写者付出了巨大的努力来生成最佳代码。一个简单而有效的优化是用两个常量替换算术运算的结果值。为了能够执行计算，嵌入了一个常量表达式的解释器。为了得到相同的结果，解释器必须实现与生成的机器代码相同的规则！当然，这可能是微妙错误的源泉。

另一种方法是使用相同的代码生成方法将常量表达式编译为 IR，然后让 JIT 编译和执行 IR。这个想法甚至可以进一步发展。在数学中，函数对于相同的输入总是产生相同的结果。对于计算机语言中的函数，这并不成立。一个很好的例子是`rand()`函数，它每次调用都返回一个随机值。在计算机语言中，具有与数学函数相同特性的函数称为**纯函数**。在表达式优化期间，我们可以 JIT 编译和执行只有常量参数的纯函数，并用 JIT 执行返回的结果替换对函数的调用。实际上，我们将函数的执行从运行时移到了编译时！

考虑交叉编译

在静态编译器中使用 JIT 编译器是一个有趣的选择。然而，如果编译器支持交叉编译，那么这种方法应该经过深思熟虑。通常会引起麻烦的候选者是浮点类型。C 语言中`long double`类型的精度通常取决于硬件和操作系统。一些系统使用 128 位浮点数，而其他系统只使用 64 位浮点数。80 位浮点类型仅在 x86 平台上可用，并且通常仅在 Windows 上使用。使用不同精度进行相同的浮点运算可能会导致巨大差异。在这种情况下，无法使用 JIT 编译进行评估。

很难确定一个函数是否是纯函数。常见的解决方案是应用一种启发式方法。如果一个函数既不通过指针也不通过聚合类型间接地读取或写入堆内存，并且只调用其他纯函数，那么它就是一个纯函数。开发人员可以帮助编译器，例如，用特殊的关键字或符号标记纯函数。在语义分析阶段，编译器可以检查违规情况。

在下一小节中，我们将更仔细地看一下在编译时尝试对函数进行 JIT 执行时对语言语义的影响。

## 识别语言语义

困难的部分确实是在语言语义层面决定哪些语言部分适合在编译时进行评估。排除对堆内存的访问是非常限制性的。一般来说，这排除了字符串处理，例如。当分配的内存的生存周期超过 JIT 执行的函数的生存周期时，使用堆内存就会变得棘手。这是一个程序状态，可能会影响其他结果，因此是危险的。另一方面，如果`malloc()`和`free()`函数有匹配的调用，那么内存只用于内部计算。在这种情况下，使用堆内存是安全的。但要证明这种条件并不容易。

在类似的层面上，JIT 执行函数中的无限循环可能会使编译器冻结。艾伦·图灵在 1936 年表明，没有机器可以决定一个函数是否会产生结果，或者它是否陷入无休止的循环。必须采取一些预防措施来避免这种情况，例如，在 JIT 执行的函数被终止之前设置一个运行时限制。

最后，允许更多功能，就必须更多地考虑安全性，因为编译器现在执行的是其他人编写的代码。想象一下，这段代码从互联网下载并运行文件，或者试图擦除硬盘：如果允许 JIT 执行函数有太多状态，我们也需要考虑这样的情况。

这个想法并不新鲜。D 编程语言有一个名为**编译时函数执行**的功能。参考编译器**dmd**通过在 AST 级别解释函数来实现这一功能。基于 LLVM 的 LDC 编译器具有一个试验性的功能，可以使用 LLVM JIT 引擎。您可以在 https://dlang.org/了解更多关于该语言和编译器的信息。

忽略语义上的挑战，实现并不那么困难。在“从头开始构建 JIT 编译器类”部分，我们使用`JIT`类开发了一个 JIT 编译器。我们在类中输入一个 IR 模块，然后可以查找并执行该模块中的函数。通过查看`tinylang`编译器的实现，我们可以清楚地识别对常量的访问，因为 AST 中有一个`ConstantAccess`节点。例如，有如下代码：

```cpp
  if (auto *Const = llvm::dyn_cast<ConstantAccess>(Expr)) {
    // Do something with the constant.
  }
```

与其解释表达式中的操作以推导常量的值，我们可以做如下操作：

1.  创建一个新的 IR 模块。

1.  在模块中创建一个 IR 函数，返回预期类型的值。

1.  使用现有的`emitExpr()`函数为表达式创建 IR，并使用最后一条指令返回计算出的值。

1.  JIT 执行函数以计算值。

这值得实现吗？LLVM 在优化管道中执行常量传播和函数内联。例如，一个简单的表达式如 4 + 5 在 IR 构造过程中已经被替换为结果。像最大公约数的计算这样的小函数会被内联。如果所有参数都是常量值，那么内联的代码会通过常量传播的计算结果被替换。

基于这一观察，这种方法的实现只有在编译时有足够的语言特性可供执行时才有用。如果是这种情况，那么使用给定的草图实现起来是相当容易的。

了解如何使用 LLVM 的 JIT 编译器组件使您能够以全新的方式使用 LLVM。除了实现类似 Java 虚拟机的 JIT 编译器之外，JIT 编译器还可以嵌入到其他应用程序中。这允许创造性的方法，比如在本节中所看到的将其用于静态编译器。

# 总结

在本章中，您学习了如何开发 JIT 编译器。您从 JIT 编译器的可能应用开始，并探索了 LLVM 动态编译器和解释器`lli`。使用预定义的`LLJIT`类，您自己构建了类似于`lli`的工具。为了能够利用 ORC API 的分层结构，您实现了一个优化的`JIT`类。在获得了所有这些知识之后，您探讨了在静态编译器内部使用 JIT 编译器的可能性，这是一些语言可以受益的特性。

在下一章中，您将学习如何为新的 CPU 架构向 LLVM 添加后端。


# 第十一章：使用 LLVM 工具进行调试

LLVM 带有一套工具，可帮助您识别应用程序中的某些错误。所有这些工具都使用 LLVM 和**Clang**库。

在本章中，您将学习如何使用**消毒剂**为应用程序安装仪器，如何使用最常见的消毒剂来识别各种错误，并如何为应用程序实现模糊测试。这将帮助您识别通常无法通过单元测试找到的错误。您还将学习如何识别应用程序中的性能瓶颈，运行**静态分析器**以识别通常无法通过编译器找到的问题，并创建自己的基于 Clang 的工具，以便您可以扩展 Clang 的新功能。

本章将涵盖以下主题：

+   使用消毒剂为应用程序安装仪器

+   使用**libFuzzer**查找错误

+   使用**XRay**进行性能分析

+   使用**Clang 静态分析器**检查源代码

+   创建自己的基于 Clang 的工具

在本章结束时，您将了解如何使用各种 LLVM 和 Clang 工具来识别应用程序中的大量错误类别。您还将获得扩展 Clang 的知识，例如强制执行命名约定或添加新的源分析功能。

# 技术要求

要在*使用 XRay 进行性能分析*部分创建**火焰图**，您需要从[`github.com/brendangregg/FlameGraph`](https://github.com/brendangregg/FlameGraph)安装脚本。一些系统，如**Fedora**和**FreeBSD**，提供了这些脚本的软件包，您也可以使用它们。

要在同一部分查看**Chrome 可视化**，您需要安装**Chrome**浏览器。您可以从[`www.google.com/chrome/`](https://www.google.com/chrome/)下载浏览器，或者使用系统的软件包管理器安装 Chrome 浏览器。本章的代码文件可在[`github.com/PacktPublishing/Learn-LLVM-12/tree/master/Chapter11`](https://github.com/PacktPublishing/Learn-LLVM-12/tree/master/Chapter11)找到

您可以在[`bit.ly/3nllhED`](https://bit.ly/3nllhED)找到代码的实际操作视频

# 使用消毒剂为应用程序安装仪器

LLVM 带有一些`compiler-rt`项目。消毒剂可以在 Clang 中启用，这使它们非常方便使用。在接下来的章节中，我们将看一下可用的消毒剂，即“地址”，“内存”和“线程”。我们将首先看一下“地址”消毒剂。

## 使用地址消毒剂检测内存访问问题

您可以使用“地址”消毒剂来检测应用程序中的一些内存访问错误。这包括常见错误，如在释放动态分配的内存后继续使用它，或者在分配的内存边界之外写入动态分配的内存。

启用“地址”消毒剂后，它将使用自己的版本替换对`malloc()`和`free()`函数的调用，并使用检查保护仪器化所有内存访问。当然，这会给应用程序增加很多开销，您只会在应用程序的测试阶段使用“地址”消毒剂。如果您对实现细节感兴趣，可以在`llvm/lib/Transforms/Instrumentation/AddressSanitizer.cpp`文件中找到该传递的源代码，以及在[`github.com/google/sanitizers/wiki/AddressSanitizerAlgorithm`](https://github.com/google/sanitizers/wiki/AddressSanitizerAlgorithm)上找到的算法描述。

让我们运行一个简短的示例来演示“地址”消毒剂的功能。以下示例应用程序`outofbounds.c`分配了`12`字节的内存，但初始化了`14`字节：

```cpp
#include <stdlib.h>
#include <string.h>
int main(int argc, char *argv[]) {
  char *p = malloc(12);
  memset(p, 0, 14);
  return (int)*p;
}
```

您可以编译并运行此应用程序，而不会注意到任何问题。这对于这种类型的错误是典型的。即使在更大的应用程序中，这种错误也可能长时间不被注意到。但是，如果您使用`-fsanitize=address`选项启用`address`检测器，那么应用程序在检测到错误后会停止。

启用`-g`选项的调试符号也很有用，因为它有助于确定源代码中错误的位置。以下代码是一个使用`address`检测器和启用调试符号编译源文件的示例：

```cpp
$ clang -fsanitize=address -g outofbounds.c -o outofbounds
```

现在，当运行应用程序时，您会得到一个冗长的错误报告：

```cpp
$ ./outofbounds
=================================================================
==1067==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x60200000001c at pc 0x00000023a6ef bp 0x7fffffffeb10 sp 0x7fffffffe2d8
WRITE of size 14 at 0x60200000001c thread T0
    #0 0x23a6ee in __asan_memset /usr/src/contrib/llvm-project/compiler-rt/lib/asan/asan_interceptors_memintrinsics.cpp:26:3
    #1 0x2b2a03 in main /home/kai/sanitizers/outofbounds.c:6:3
    #2 0x23331f in _start /usr/src/lib/csu/amd64/crt1.c:76:7
```

报告还包含有关内存内容的详细信息。重要信息是错误的类型-`address`检测器拦截应用程序的执行。它显示了`outofbounds.c`文件中的*第 6 行*，其中包含对`memset()`的调用-确实是发生缓冲区溢出的确切位置。

如果您将`outofbounds.c`文件中包含`memset(p, 0, 14);`的行替换为以下代码，则会在释放内存后访问内存。您需要将源代码保存在`useafterfree.c`文件中：

```cpp
  memset(p, 0, 12);
  free(p);
```

再次，如果您编译并运行它，将检测到在释放内存后使用指针：

```cpp
$ clang -fsanitize=address -g useafterfree.c -o useafterfree
$ ./useafterfree
=================================================================
==1118==ERROR: AddressSanitizer: heap-use-after-free on address 0x602000000010 at pc 0x0000002b2a5c bp 0x7fffffffeb00 sp 0x7fffffffeaf8
READ of size 1 at 0x602000000010 thread T0
    #0 0x2b2a5b in main /home/kai/sanitizers/useafterfree.c:8:15
    #1 0x23331f in _start /usr/src/lib/csu/amd64/crt1.c:76:7
```

这次，报告指向包含对`p`指针的解引用的*第 8 行*。

在运行应用程序之前，将`ASAN_OPTIONS`环境变量设置为值`detect_leaks=1`，然后您还会收到有关内存泄漏的报告。在命令行上，您可以这样做：

```cpp
$ ASAN_OPTIONS=detect_leaks=1 ./useafterfree
```

`address`检测器非常有用，因为它捕获了一类难以检测的错误。`memory`检测器执行类似的任务，我们将在下一节中看到。

## 使用`memory`检测器查找未初始化的内存访问

使用未初始化的内存是另一类难以发现的错误。在**C**和**C++**中，一般的内存分配例程不会使用默认值初始化内存缓冲区。对于堆栈上的自动变量也是如此。

存在许多错误的机会，`memory`检测器有助于找到这些错误。如果您对实现细节感兴趣，可以在`llvm/lib/Transforms/Instrumentation/MemorySanitizer.cpp`文件中找到`memory`检测器传递的源代码。文件顶部的注释解释了实现背后的思想。

让我们运行一个小例子，并将以下源代码保存为`memory.c`文件。您应该注意到`x`变量没有初始化，但被用作`return`值：

```cpp
int main(int argc, char *argv[]) {
  int x;
  return x;
}
```

如果没有检测器，应用程序将正常运行。但是，如果使用`-fsanitize=memory`选项，则会收到错误报告：

```cpp
$ clang -fsanitize=memory -g memory.c -o memory
$ ./memory
==1206==WARNING: MemorySanitizer: use-of-uninitialized-value
    #0 0x10a8f49 in main /home/kai/sanitizers/memory.c:3:3
    #1 0x1053481 in _start /usr/src/lib/csu/amd64/crt1.c:76:7
SUMMARY: MemorySanitizer: use-of-uninitialized-value /home/kai/sanitizers/memory.c:3:3 in main
Exiting
```

与`address`检测器一样，`memory`检测器会在发现第一个错误时停止应用程序。

在下一节中，我们将看看如何使用`thread`检测器来检测多线程应用程序中的数据竞争。

## 使用`thread`检测器指出数据竞争

为了利用现代 CPU 的强大功能，应用程序现在使用多个线程。这是一种强大的技术，但也引入了新的错误来源。多线程应用程序中的一个非常常见的问题是对全局数据的访问没有受到保护，例如，`thread`检测器可以在`llvm/lib/Transforms/Instrumentation/ThreadSanitize.cpp`文件中检测到数据竞争。

为了演示`thread`检测器的功能，我们将创建一个非常简单的生产者/消费者风格的应用程序。生产者线程增加全局变量，而消费者线程减少相同的变量。对全局变量的访问没有受到保护，因此这显然是数据竞争。您需要将以下源代码保存在`thread.c`文件中：

```cpp
#include <pthread.h>
int data = 0;
void *producer(void *x) {
  for (int i = 0; i < 10000; ++i) ++data;
  return x;
}
void *consumer(void *x) {
  for (int i = 0; i < 10000; ++i) --data;
  return x;
}
int main() {
  pthread_t t1, t2;
  pthread_create(&t1, NULL, producer, NULL);
  pthread_create(&t2, NULL, consumer, NULL);
  pthread_join(t1, NULL);
  pthread_join(t2, NULL);
  return data;
}
```

从前面的代码中，`data`变量在两个线程之间共享。在这里，它是`int`类型，以使示例简单化。通常情况下，会使用诸如`std::vector`类或类似的数据结构。这两个线程运行`producer()`和`consumer()`函数。

`producer()`函数只增加`data`变量，而`consumer()`函数减少它。未实现访问保护，因此这构成了数据竞争。`main()`函数使用`pthread_create()`函数启动两个线程，使用`pthread_join()`函数等待线程结束，并返回`data`变量的当前值。

如果您编译并运行此应用程序，那么您将注意到没有错误；也就是说，返回值始终为 0。在这种情况下，如果循环执行的次数增加了 100 倍，就会出现错误，即返回值不等于 0。然后，您会看到其他值出现。

您可以使用`thread` sanitizer 来识别数据竞争。要启用带有`thread` sanitizer 的编译，您需要向 Clang 传递`-fsanitize=thread`选项。使用`-g`选项添加调试符号可以在报告中给出行号，这非常有帮助。请注意，您还需要链接`pthread`库：

```cpp
$ clang -fsanitize=thread -g thread.c -o thread -lpthread
$ ./thread
==================
WARNING: ThreadSanitizer: data race (pid=1474)
  Write of size 4 at 0x000000cdf8f8 by thread T2:
    #0 consumer /home/kai/sanitizers/thread.c:11:35 (thread+0x2b0fb2)
  Previous write of size 4 at 0x000000cdf8f8 by thread T1:
    #0 producer /home/kai/sanitizers/thread.c:6:35 (thread+0x2b0f22)
  Location is global 'data' of size 4 at 0x000000cdf8f8 (thread+0x000000cdf8f8)
  Thread T2 (tid=100437, running) created by main thread at:
    #0 pthread_create /usr/src/contrib/llvm-project/compiler-rt/lib/tsan/rtl/tsan_interceptors_posix.cpp:962:3 (thread+0x271703)
    #1 main /home/kai/sanitizers/thread.c:18:3 (thread+0x2b1040)
  Thread T1 (tid=100436, finished) created by main thread at:
    #0 pthread_create /usr/src/contrib/llvm-project/compiler-rt/lib/tsan/rtl/tsan_interceptors_posix.cpp:962:3 (thread+0x271703)
    #1 main /home/kai/sanitizers/thread.c:17:3 (thread+0x2b1021)
SUMMARY: ThreadSanitizer: data race /home/kai/sanitizers/thread.c:11:35 in consumer
==================
ThreadSanitizer: reported 1 warnings
```

报告指出了源文件的*第 6 行*和*第 11 行*，在这里全局变量被访问。它还显示了两个名为*T1*和*T2*的线程访问了该变量，以及各自调用`pthread_create()`函数的文件和行号。

在本节中，我们学习了如何使用三种 sanitizer 来识别应用程序中的常见问题。`address` sanitizer 帮助我们识别常见的内存访问错误，例如越界访问或在释放后使用内存。使用`memory` sanitizer，我们可以找到对未初始化内存的访问，而`thread` sanitizer 则帮助我们识别数据竞争。

在下一节中，我们将尝试通过在随机数据上运行我们的应用程序来触发 sanitizers，称为**模糊测试**。

# 使用 libFuzzer 查找错误

要测试您的应用程序，您需要编写**单元测试**。这是确保软件行为正确的好方法。但是，由于可能输入的数量呈指数增长，您可能会错过某些奇怪的输入，以及一些错误。

**模糊测试**可以在这里帮助。其思想是向应用程序提供随机生成的数据，或者基于有效输入但带有随机更改的数据。这样一遍又一遍地进行，因此您的应用程序将被大量输入进行测试。这是一种非常强大的测试方法。几乎所有浏览器和其他软件中的数百个错误都是通过模糊测试发现的。

LLVM 自带其自己的模糊测试库。最初是 LLVM 核心库的一部分，名为`compiler-rt`。该库旨在测试小型和快速函数。

让我们运行一个小例子。您需要提供`LLVMFuzzerTestOneInput()`函数。该函数由`fuzzer.c`文件调用：

```cpp
#include <stdint.h>
#include <stdlib.h>
int count(const uint8_t *Data, size_t Size) {
  int cnt = 0;
  if (Size)
    while (Data[cnt] >= '0' && Data[cnt] <= '9') ++cnt;
  return cnt;
}
int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t 
                           Size) {
  count(Data, Size);
  return 0;
}
```

从前面的代码中，`count()`函数计算`Data`变量指向的内存中的数字数量。仅检查数据的大小以确定是否有任何可用字节。在`while`循环内，未检查大小。

使用正常的`0`字节。`LLVMFuzzerTestOneInput()`函数是所谓的`0`，目前是唯一允许的值。

要使用 libFuzzer 编译文件，您需要添加`-fsanitize=fuzzer`选项。建议还启用`address` sanitizer 和生成调试符号。使用以下命令编译文件：

```cpp
$ clang -fsanitize=fuzzer,address -g fuzzer.c -o fuzzer
```

运行测试时，会生成一个冗长的报告。该报告包含的信息比堆栈跟踪更多，因此让我们仔细看一下：

1.  第一行告诉您用于初始化随机数生成器的种子。您可以使用`–seed=`选项重复此执行：

```cpp
INFO: Seed: 1297394926
```

1.  默认情况下，libFuzzer 将输入限制为最多 4,096 字节。您可以使用`–max_len=`选项更改默认值：

```cpp
INFO: -max_len is not provided; libFuzzer will not generate inputs larger than 4096 bytes
```

1.  现在，我们在不提供样本输入的情况下运行测试。所有样本输入的集合称为语料库，在此运行中为空：

```cpp
INFO: A corpus is not provided, starting from an empty corpus
```

1.  随后将提供有关生成的测试数据的一些信息。它向您显示尝试了`28`个输入，找到了`6`个输入，总长度为`19`字节，这些输入一共覆盖了`6`个覆盖点或基本块：

```cpp
#28     NEW    cov: 6 ft: 9 corp: 6/19b lim: 4 exec/s: 0 rss: 29Mb L: 4/4 MS: 4 CopyPart-PersAutoDict-CopyPart-ChangeByte- DE: "1\x00"-
```

1.  之后，检测到缓冲区溢出，并且随后是来自`address`消毒剂的信息。最后，报告向您指出导致缓冲区溢出的输入的位置：

```cpp
artifact_prefix='./'; Test unit written to ./crash-17ba0791499db908433b80f37c5fbc89b870084b
```

有了保存的输入，您可以再次执行带有崩溃输入的测试用例：

```cpp
$ ./fuzzer crash-17ba0791499db908433b80f37c5fbc89b870084b
```

这显然对于识别问题非常有帮助。但是，使用随机数据通常并不是非常有用。如果尝试对`tinylang`词法分析器或解析器进行模糊测试，那么纯随机数据会导致立即拒绝输入，因为找不到有效的标记。

在这种情况下，提供一小组有效输入（称为语料库）更有用。然后，语料库的文件将被随机变异并用作输入。您可以将输入视为大多数有效，只是有一些位被翻转。这也适用于其他必须具有特定格式的输入。例如，对于处理**JPEG**和**PNG**文件的库，您将提供一些小的**JPEG**和**PNG**文件作为语料库。

您可以将语料库文件保存在一个或多个目录中，并且可以使用`printf`命令为模糊测试创建一个简单的语料库：

```cpp
$ mkdir corpus
$ printf "012345\0" >corpus/12345.txt
$ printf "987\0" >corpus/987.txt
```

在运行测试时，您将在命令行上提供目录：

```cpp
$ ./fuzzer corpus/
```

然后，语料库被用作生成随机输入的基础，正如报告所告诉您的那样：

```cpp
INFO: seed corpus: files: 2 min: 4b max: 7b total: 11b rss: 29Mb
```

如果要测试的函数处理标记或其他魔术值，比如编程语言，那么可以通过提供包含标记的字典来加快该过程。对于编程语言，字典将包含语言中使用的所有关键字和特殊符号。字典定义遵循简单的键值样式。例如，要在字典中定义`if`关键字，可以添加以下内容：

```cpp
kw1="if"
```

但是，密钥是可选的，可以省略。然后，您可以使用`–dict=`选项在命令行上指定字典文件。在下一节中，我们将了解 libFuzzer 实现的限制和替代方案。

## 限制和替代方案

libFuzzer 实现速度快，但对测试目标有一些限制。它们如下：

+   测试函数必须将输入作为内存中的数组接受。一些库函数需要数据的文件路径，因此无法使用 libFuzzer 进行测试。

+   不应调用`exit()`函数。

+   不应更改全局状态。

+   不应使用硬件随机数生成器。

从上述限制中，前两个限制是 libFuzzer 作为库的实现的含义。后两个限制是为了避免评估算法中的混淆。如果这些限制中的一个未满足，那么对模糊目标的两个相同调用可能会产生不同的结果。

模糊测试的最佳替代工具是**AFL**，位于[`github.com/google/AFL`](https://github.com/google/AFL)。AFL 需要一个被插装的二进制文件（提供了一个用于插装的 LLVM 插件），并要求应用程序在命令行上以文件路径形式接受输入。AFL 和 libFuzzer 可以共享相同的语料库和相同的字典文件。因此，可以使用这两种工具测试应用程序。在 libFuzzer 不适用的情况下，AFL 可能是一个很好的替代方案。

还有许多其他影响 libFuzzer 工作方式的方法。您可以阅读[`llvm.org/docs/LibFuzzer.html`](https://llvm.org/docs/LibFuzzer.html)上的参考页面以获取更多详细信息。

在下一节中，我们将看一个应用程序可能遇到的完全不同的问题；我们尝试识别性能瓶颈。

# 使用 XRay 进行性能分析

如果你的应用程序似乎运行缓慢，那么你可能想知道代码中花费了多少时间。在这种情况下，使用`llvm/lib/XRay/`目录对代码进行仪器化。运行时部分是`compiler-rt`的一部分。

在下面的示例源代码中，通过调用`usleep()`函数来模拟真实工作。`func1()`函数休眠 10 微秒。`func2()`函数根据`n`参数是奇数还是偶数，要么调用`func1()`，要么休眠 100 微秒。在`main()`函数内，这两个函数都在一个循环中被调用。这已经足够获取有趣的信息了。你需要将以下源代码保存在`xraydemo.c`文件中：

```cpp
#include <unistd.h>
void func1() { usleep(10); }
void func2(int n) {
  if (n % 2) func1();
  else usleep(100);
}
int main(int argc, char *argv[]) {
  for (int i = 0; i < 100; i++) { func1(); func2(i); }
  return 0;
}
```

要在编译期间启用 XRay 仪器化，你需要指定`-fxray-instrument`选项。少于 200 条指令的函数不会被仪器化。这是开发人员定义的一个任意阈值，在我们的情况下，这些函数不会被仪器化。阈值可以通过`-fxray-instruction-threshold=`选项指定。另外，我们可以添加一个函数属性来控制是否应该对函数进行仪器化。例如，添加以下原型将导致始终对函数进行仪器化：

```cpp
void func1() __attribute__((xray_always_instrument));
```

同样地，通过使用`xray_never_instrument`属性，你可以关闭对函数的仪器化。

现在我们将使用命令行选项并按以下方式编译`xraydemo.c`文件：

```cpp
$ clang -fxray-instrument -fxray-instruction-threshold=1 -g\
  xraydemo.c -o xraydemo
```

在生成的二进制文件中，默认情况下关闭了仪器。如果你运行这个二进制文件，你会注意到与未经仪器化的二进制文件没有任何区别。`XRAY_OPTIONS`环境变量用于控制运行时数据的记录。要启用数据收集，你需要按照以下方式运行应用程序：

```cpp
$ XRAY_OPTIONS= "patch_premain=true xray_mode=xray-basic "\
  ./xraydemo
```

`xray_mode=xray-basic`选项告诉运行时我们要使用基本模式。在这种模式下，会收集所有运行时数据，这可能会导致巨大的日志文件。当给出`patch_premain=true`选项时，那么在`main()`函数之前运行的函数也会被仪器化。

运行这个命令后，你会在目录中看到一个新文件，其中存储了收集到的数据。你需要使用`llvm-xray`工具从这个文件中提取可读的信息。

`llvm-xray`工具支持各种子命令。你可以使用`account`子命令来提取一些基本统计信息。例如，要获取前 10 个最常调用的函数，你可以添加`-top=10`选项来限制输出，并使用`-sort=count`选项来指定函数调用计数作为排序标准。你可以使用`-sortorder=`选项来影响排序顺序。运行以下命令来获取统计信息：

```cpp
$ llvm-xray account xray-log.xraydemo.xVsWiE -sort=count\
  -sortorder=dsc -instr_map ./xraydemo
Functions with latencies: 3
   funcid      count        sum  function
        1        150   0.166002  demo.c:4:0: func1
        2        100   0.543103  demo.c:9:0: func2
        3          1   0.655643  demo.c:17:0: main
```

你可以看到`func1()`函数被调用最频繁，以及在这个函数中累积的时间。这个示例只有三个函数，所以`-top=`选项在这里没有明显的效果，但对于真实的应用程序来说，它非常有用。

从收集到的数据中，可以重构出运行时发生的所有堆栈帧。你可以使用`stack`子命令来查看前 10 个堆栈。这里显示的输出已经为了简洁起见进行了缩减：

```cpp
$ llvm-xray stack xray-log.xraydemo.xVsWiE -instr_map\
  ./xraydemo
Unique Stacks: 3
Top 10 Stacks by leaf sum:
Sum: 1325516912
lvl   function              count              sum
#0    main                      1       1777862705
#1    func2                    50       1325516912
Top 10 Stacks by leaf count:
Count: 100
lvl   function              count              sum
#0    main                      1       1777862705
#1    func1                   100        303596276
```

`main()`函数调用了`func2()`函数，这是累积时间最长的堆栈帧。深度取决于调用了多少函数，堆栈帧通常很大。

这个子命令也可以用来创建一个`flamegraph.pl`脚本，将数据转换成**可伸缩矢量图形**（**SVG**）文件，你可以在浏览器中查看。

使用以下命令，您可以指示`llvm-xray`使用`-all-stacks`选项输出所有堆栈帧。使用`-stack-format=flame`选项，输出格式符合`flamegraph.pl`脚本的预期格式。使用`-aggregation-type`选项，您可以选择堆栈帧是按总时间还是按调用次数进行聚合。`llvm-xray`的输出被导入`flamegraph.pl`脚本，并将结果输出保存在`flame.svg`文件中：

```cpp
$ llvm-xray stack xray-log.xraydemo.xVsWiE -all-stacks\
  -stack-format=flame --aggregation-type=time\
  -instr_map ./xraydemo | flamegraph.pl >flame.svg
```

在浏览器中打开生成的`flame.svg`文件。图形如下所示：

![图 11.1 - 由 llvm-xray 生成的火焰图](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/lrn-llvm12/img/Figure_11.1_B15647.jpg)

图 11.1 - 由 llvm-xray 生成的火焰图

火焰图乍一看可能会令人困惑，因为*x*轴没有经过的时间的通常含义。相反，函数只是按名称排序。颜色选择是为了具有良好的对比度，并没有其他含义。从前面的图表中，您可以轻松确定调用层次结构和函数中所花费的时间。

关于堆栈帧的信息只有在将鼠标光标移动到表示该帧的矩形上方时才显示。单击帧后，您可以放大此堆栈帧。如果您想要识别值得优化的函数，火焰图非常有帮助。要了解更多关于火焰图的信息，请访问火焰图的发明者 Brendan Gregg 的网站[`www.brendangregg.com/flamegraphs.html`](http://www.brendangregg.com/flamegraphs.html)。

您可以使用`convert`子命令将数据转换为`.yaml`格式或`xray.evt`文件使用的格式，运行以下命令：

```cpp
$ llvm-xray convert -output-format=trace_event\
  -output=xray.evt -symbolize –sort\
  -instr_map=./xraydemo xray-log.xraydemo.xVsWiE
```

如果不指定`-symbolize`选项，则结果图中不会显示函数名称。

完成后，打开 Chrome 浏览器，输入`chrome:///tracing`。然后，单击`xray.evt`文件。您将看到以下数据的可视化：

![图 11.2 - 由 llvm-xray 生成的 Chrome 跟踪查看器可视化](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/lrn-llvm12/img/Figure_11.2_B15647.jpg)

图 11.2 - 由 llvm-xray 生成的 Chrome 跟踪查看器可视化

在此视图中，堆栈帧按函数调用发生的时间进行排序。要进一步解释可视化，请阅读[`www.chromium.org/developers/how-tos/trace-event-profiling-tool`](https://www.chromium.org/developers/how-tos/trace-event-profiling-tool)上的教程。

提示

`llvm-xray`工具具有更多功能。您可以在 LLVM 网站上阅读有关它的信息[`llvm.org/docs/XRay.html`](https://llvm.org/docs/XRay.html)和[`llvm.org/docs/XRayExample.html`](https://llvm.org/docs/XRayExample.html)。

在本节中，我们学习了如何使用 XRay 对应用程序进行工具化，如何收集运行时信息以及如何可视化这些数据。我们可以使用这些知识来找出应用程序中的性能瓶颈。

识别应用程序中的错误的另一种方法是分析源代码，这是由静态分析器完成的。

# 使用 Clang 静态分析器检查源代码

**Clang 静态分析器**是一种在 C、C++和**Objective C**源代码上执行额外检查的工具。静态分析器执行的检查比编译器执行的检查更彻底。它们在时间和所需资源方面也更昂贵。静态分析器具有一组检查器，用于检查特定的错误。

该工具对源代码进行符号解释，从中查看应用程序的所有代码路径，并从中推导出应用程序中使用的值的约束。**符号解释**是编译器中常用的技术，例如用于识别常量值。在静态分析器的上下文中，检查器适用于推导出的值。

例如，如果除法的除数为 0，则静态分析器会发出警告。我们可以通过`div.c`文件中的以下示例进行检查：

```cpp
int divbyzero(int a, int b) { return a / b; }
int bug() { return divbyzero(5, 0); }
```

在示例中，静态分析器将警告除以`0`。但是，在编译时，使用`clang -Wall -c div.c`命令编译的文件不会显示警告。

有两种方法可以从命令行调用静态分析器。较旧的工具是`scan-build`工具是更简单的解决方案。您只需将`compile`命令传递给工具，其他所有操作都会自动完成：

```cpp
$ scan-build clang -c div.c
scan-build: Using '/usr/local/llvm12/bin/clang-12' for static analysis
div.c:2:12: warning: Division by zero [core.DivideZero]
  return a / b;
         ~~^~~
1 warning generated.
scan-build: Analysis run complete.
scan-build: 1 bug found.
scan-build: Run 'scan-view /tmp/scan-build-2021-03-01-023401-8721-1' to examine bug reports.
```

屏幕上的输出已经告诉您发现了问题，即触发了名为`core.DivideZero`的检查器。但这还不是全部。您将在`/tmp`目录的提到的子目录中找到完整的 HTML 报告。您可以使用`scan-view`命令查看报告，或者在浏览器中打开子目录中找到的`index.html`文件。

报告的第一页显示了找到的错误的摘要：

![图 11.3 - 摘要页面](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/lrn-llvm12/img/Figure_11.3_B15647.jpg)

图 11.3 - 摘要页面

对于每个找到的错误，摘要页面显示了错误的类型、源代码中的位置以及分析器发现错误后的路径长度。提供了指向错误详细报告的链接。

以下屏幕截图显示了错误的详细报告：

![图 11.4 - 详细报告](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/lrn-llvm12/img/Figure_11.4_B15647.jpg)

图 11.4 - 详细报告

通过详细报告，您可以通过跟随编号的气泡来验证错误。在我们的简单示例中，它显示了通过将`0`作为参数值传递导致除以零错误的三个步骤。

确实需要通过人来验证。如果派生的约束对于某个检查器不够精确，则可能会出现误报，即对于完全正常的代码报告错误。根据报告，您可以识别出误报。

您不仅限于使用工具提供的检查器。您也可以添加新的检查器。下一节将介绍如何执行此操作。

## 向 Clang 静态分析器添加新的检查器

要向 Clang 静态分析器添加新的检查器，您需要创建`Checker`类的新子类。静态分析器尝试通过代码的所有可能路径。分析引擎在某些点生成事件，例如，在函数调用之前或之后。如果需要处理这些事件，您的类必须为这些事件提供回调。`Checker`类和事件的注册在`clang/include/clang/StaticAnalyzer/Core/Checker.h`头文件中提供。

通常，检查器需要跟踪一些符号。但是检查器无法管理状态，因为它不知道分析引擎当前尝试的代码路径。因此，跟踪的状态必须在引擎中注册，并且只能使用`ProgramStateRef`实例进行更改。

许多库提供必须成对使用的函数。例如，C 标准库提供了`malloc()`和`free()`函数。`malloc()`函数分配的内存必须由`free()`函数精确释放一次。不调用`free()`函数或多次调用它都是编程错误。这种编码模式还有许多其他实例，静态分析器为其中一些提供了检查器。

`iconv`库提供了`iconv_open()`和`iconv_close()`函数，这两个函数必须成对使用。您可以实现一个检查器来检查这一点。

为了检测错误，检查器需要跟踪从`iconv_open()`函数返回的描述符。分析引擎为`iconv_open()`函数的返回值返回一个`SymbolRef`实例。我们将此符号与状态关联起来，以反映是否调用了`iconv_close()`。对于状态，我们创建了`IconvState`类，它封装了一个`bool`值。

新的`IconvChecker`类需要处理四个事件：

+   `PostCall`，在函数调用之后发生。在调用`iconv_open()`函数之后，我们检索返回值的符号，并记住它处于打开状态。

+   `PreCall`，在函数调用之前发生。在调用`iconv_close()`函数之前，我们检查描述符的符号是否处于打开状态。如果不是，则说明已经为描述符调用了`iconv_close()`函数，我们已经检测到对该函数的双重调用。

+   `DeadSymbols`，当未使用的符号被清理时发生。我们检查未使用的符号是否仍处于打开状态。如果是，则我们已经检测到对`iconv_close()`的缺失调用，这是资源泄漏。

+   `PointerEscape`，当符号不再能被分析器跟踪时调用。在这种情况下，我们从状态中移除符号，因为我们无法再推断描述符是否已关闭。

新的检查器是在 Clang 项目内实现的。让我们从将新的检查器添加到所有检查器的集合开始，这是`clang/include/clang/StaticAnalyzer/Checkers/Checkers.td`文件。每个检查器都与软件包相关联。我们的新检查器正在开发中，因此它属于`alpha`软件包。iconv API 是一个 POSIX 标准化的 API，因此它也属于`unix`软件包。在`Checkers.td`文件中找到`UnixAlpha`部分，并添加以下代码以注册新的`IconvChecker`：

```cpp
def IconvChecker : Checker<"Iconv">,
  HelpText<"Check handling of iconv functions">,
  Documentation<NotDocumented>;
```

这将新的检查器添加到已知**检查器**集合中，为命令行选项设置帮助文本，并声明此检查器没有文档。

接下来，我们在`clang/lib/StaticAnalyzer/Checkers/IconvChecker.cpp`文件中实现检查器：

1.  对于实现，我们需要包括几个头文件。`BuiltinCheckerRegistration.h`文件用于注册检查器。`Checker.h`文件提供了`Checker`类的声明和事件的回调。`CallEvent.h`文件声明了用于调用事件的类，`CheckerContext.h`文件用于声明`CheckerContext`类，它是提供对分析器状态访问的中心类：

```cpp
#include "clang/StaticAnalyzer/Checkers/
BuiltinCheckerRegistration.h"
#include "clang/StaticAnalyzer/Core/Checker.h"
#include "clang/StaticAnalyzer/Core/
PathSensitive/CallEvent.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/
CheckerContext.h"
```

1.  为了避免输入命名空间名称，我们使用`clang`和`ento`命名空间：

```cpp
using namespace clang;
using namespace ento;
```

1.  我们将状态与表示 iconv 描述符的每个符号关联起来。状态可以是打开或关闭的，我们使用一个`bool`类型的变量，对于打开状态为`true`。状态值封装在`IconvState`结构中。该结构与`FoldingSet`数据结构一起使用，后者是一个过滤重复条目的哈希集。为了使该数据结构实现可用，这里添加了`Profile()`方法，该方法设置了该结构的唯一位。我们将该结构放入匿名命名空间中，以避免全局命名空间的污染。

```cpp
namespace {
struct IconvState {
  const bool IsOpen;
public:
  IconvState(bool IsOpen) : IsOpen(IsOpen) {}
  bool isOpen() const { return IsOpen; }
  bool operator==(const IconvState &O) const {
    return IsOpen == O.IsOpen;
  }
  void Profile(llvm::FoldingSetNodeID &ID) const {
    ID.AddInteger(IsOpen);
  }
};
}
```

1.  `IconvState`结构表示 iconv 描述符的状态，由`SymbolRef`类的符号表示。这最好通过一个映射来完成，该映射将符号作为键，状态作为值。正如前面所解释的，检查器不能保存状态。相反，状态必须在全局程序状态中注册，这是通过`REGISTER_MAP_WITH_PROGRAMSTATE`宏完成的。此宏引入了`IconvStateMap`名称，我们稍后将使用它来访问映射：

```cpp
REGISTER_MAP_WITH_PROGRAMSTATE(IconvStateMap, SymbolRef,
                               IconvState)
```

1.  我们还在匿名命名空间中实现了`IconvChecker`类。请求的`PostCall`、`PreCall`、`DeadSymbols`和`PointerEscape`事件是`Checker`基类的模板参数：

```cpp
namespace {
class IconvChecker
    : public Checker<check::PostCall, check::PreCall,
                     check::DeadSymbols,
                     check::PointerEscape> {
```

1.  `IconvChecker`类只有`CallDescription`类型的字段，用于识别程序中的`iconv_open()`、`iconv()`和`iconv_close()`函数调用：

```cpp
  CallDescription IconvOpenFn, IconvFn, IconvCloseFn;
```

1.  `report()`方法生成错误报告。该方法的重要参数是符号数组、错误类型和错误描述。在方法内部，为每个符号创建一个错误报告，并将该符号标记为错误的有趣对象。如果提供了源范围作为参数，则也将其添加到报告中。最后，报告被发出：

```cpp
  void
  report(ArrayRef<SymbolRef> Syms, const BugType &Bug,
         StringRef Desc, CheckerContext &C,
         ExplodedNode *ErrNode,
         Optional<SourceRange> Range = None) const {
    for (SymbolRef Sym : Syms) {
      auto R = std::make_unique
              <PathSensitiveBugReport>(
          Bug, Desc, ErrNode);
      R->markInteresting(Sym);
      if (Range)
        R->addRange(*Range);
      C.emitReport(std::move(R));
    }
  }
```

1.  `IconvChecker`类的构造函数只使用函数的名称初始化`CallDescription`字段：

```cpp
public:
  IconvChecker()
      : IconvOpenFn("iconv_open"), IconvFn("iconv"),
        IconvCloseFn("iconv_close", 1) {}
```

1.  当分析器执行函数调用后，会调用`checkPostCall()`方法。如果执行的函数不是全局 C 函数，也不是名为`iconv_open`，那么就没有什么要做的：

```cpp
  void checkPostCall(const CallEvent &Call,
                     CheckerContext &C) const {
    if (!Call.isGlobalCFunction() ||
        !Call.isCalled(IconvOpenFn))
      return;
```

1.  否则，我们尝试将函数的返回值作为符号获取。为了将具有打开状态的符号存储在全局程序状态中，我们需要从`CheckerContext`实例中获取`ProgramStateRef`实例。状态是不可变的，所以将符号添加到状态中会导致新的状态。通过调用`addTransition()`方法，分析器引擎被告知新的状态：

```cpp
    if (SymbolRef Handle =
            Call.getReturnValue().getAsSymbol()) {
      ProgramStateRef State = C.getState();
      State = State->set<IconvStateMap>(
          Handle, IconvState(true));
      C.addTransition(State);
    }
  }
```

1.  同样，当分析器执行函数之前，会调用`checkPreCall()`方法。我们只对名为`iconv_close`的全局 C 函数感兴趣：

```cpp
  void checkPreCall(const CallEvent &Call,
                    CheckerContext &C) const {
    if (!Call.isGlobalCFunction() ||
        !Call.isCalled(IconvCloseFn))
      return;
```

1.  如果函数的第一个参数的符号，也就是 iconv 描述符，是已知的，那么我们从程序状态中检索符号的状态：

```cpp
    if (SymbolRef Handle =
            Call.getArgSVal(0).getAsSymbol()) {
      ProgramStateRef State = C.getState();
      if (const IconvState *St =
              State->get<IconvStateMap>(Handle)) {
```

1.  如果状态表示关闭状态，那么我们已经检测到了双重关闭错误，并为此生成了一个错误报告。调用`generateErrorNode()`可能会返回`nullptr`值，如果已经为这条路径生成了错误报告，所以我们必须检查这种情况：

```cpp
        if (!St->isOpen()) {
          if (ExplodedNode *N = C.generateErrorNode()) {
            BugType DoubleCloseBugType(
                this, "Double iconv_close",
                "iconv API Error");
            report({Handle}, DoubleCloseBugType,
                   "Closing a previous closed iconv "
                   "descriptor",
                   C, N, Call.getSourceRange());
          }
          return;
        }
      }
```

1.  否则，我们将符号的状态设置为关闭：

```cpp
      State = State->set<IconvStateMap>(
          Handle, IconvState(false));
      C.addTransition(State);
    }
  }
```

1.  调用`checkDeadSymbols()`方法来清理未使用的符号。我们遍历我们跟踪的所有符号，并询问`SymbolReaper`实例当前的符号是否已经失效：

```cpp
  void checkDeadSymbols(SymbolReaper &SymReaper,
                        CheckerContext &C) const {
    ProgramStateRef State = C.getState();
    SmallVector<SymbolRef, 8> LeakedSyms;
    for (auto SymbolState :
         State->get<IconvStateMap>()) {
      SymbolRef Sym = SymbolState.first;
      IconvState &St = SymbolState.second;
      if (SymReaper.isDead(Sym)) {
```

1.  如果符号已经失效，那么我们需要检查状态。如果状态仍然是打开的，那么这是一个潜在的资源泄漏。有一个例外：`iconv_open()`在错误的情况下返回`-1`。如果分析器在处理此错误的代码路径中，那么假设存在资源泄漏是错误的，因为函数调用失败了。我们尝试从`ConstraintManager`实例中获取符号的值，如果这个值是`-1`，我们就不认为这个符号是资源泄漏。我们将一个泄漏的符号添加到`SmallVector`实例中，以便稍后生成错误报告。最后，我们从程序状态中删除死亡的符号：

```cpp
        if (St.isOpen()) {
          bool IsLeaked = true;
          if (const llvm::APSInt *Val =
                  State->getConstraintManager()
                      .getSymVal(State, Sym))
            IsLeaked = Val->getExtValue() != -1;
          if (IsLeaked)
            LeakedSyms.push_back(Sym);
        }
        State = State->remove<IconvStateMap>(Sym);
      }
    }
```

1.  循环结束后，我们调用`generateNonFatalErrorNode()`方法。这个方法转换到新的程序状态，并且如果这条路径上还没有错误节点，就返回一个错误节点。`LeakedSyms`容器保存了泄漏符号的（可能为空的）列表，我们调用`report()`方法生成错误报告：

```cpp
    if (ExplodedNode *N =
            C.generateNonFatalErrorNode(State)) {
      BugType LeakBugType(this, "Resource Leak",
                          "iconv API Error", true);
      report(LeakedSyms, LeakBugType,
             "Opened iconv descriptor not closed", C,
             N);
    }
  }
```

1.  当分析器检测到参数无法被跟踪的函数调用时，会调用`checkPointerEscape()`函数。在这种情况下，我们必须假设我们不知道 iconv 描述符是否在函数内部关闭。唯一的例外是对`iconv()`函数的调用，它执行转换并且已知不会调用`iconv_close()`函数。这完成了`IconvChecker`类的实现：

```cpp
  ProgramStateRef
  checkPointerEscape(ProgramStateRef State,
                     const InvalidatedSymbols &Escaped,
                     const CallEvent *Call,
                     PointerEscapeKind Kind) const {
    if (Kind == PSK_DirectEscapeOnCall &&
        Call->isCalled(IconvFn))
      return State;
    for (SymbolRef Sym : Escaped)
      State = State->remove<IconvStateMap>(Sym);
    return State;
  }
};
}
```

1.  最后，新的检查器需要在`CheckerManager`实例中注册。`shouldRegisterIconvChecker()`方法返回`true`，表示`IconvChecker`应该默认注册，`registerIconvChecker()`方法执行注册。这两个方法都是通过从`Checkers.td`文件生成的代码调用的。

```cpp
void ento::registerIconvChecker(CheckerManager &Mgr) {
  Mgr.registerChecker<IconvChecker>();
}
bool ento::shouldRegisterIconvChecker(
    const CheckerManager &Mgr) {
  return true;
}
```

这完成了新检查器的实现。您只需要将文件名添加到`clang/lib/StaticAnalyzer/Checkers/CmakeLists.txt`文件中的源文件名列表中：

```cpp
add_clang_library(clangStaticAnalyzerCheckers
…
  IconvChecker.cpp
…)
```

要编译新的检查器，您需要切换到构建目录并运行`ninja`命令：

```cpp
$ ninja 
```

您可以使用以下保存在`conv.c`文件中的源代码来测试新的检查器，其中包含两个对`iconv_close()`函数的调用：

```cpp
#include <iconv.h>
void doconv() {
  iconv_t id = iconv_open("Latin1", "UTF-16");
  iconv_close(id);
  iconv_close(id);
}
```

你学会了如何用自己的检查器扩展 Clang 静态分析器。你可以利用这些知识来创建新的通用检查器并贡献给社区，或者你可以创建专门为你的需求构建的检查器，提高产品的质量。

静态分析器是建立在 Clang 基础设施之上的，下一节将介绍如何构建自己的插件来扩展 Clang。

# 创建你自己的基于 Clang 的工具

静态分析器是 Clang 基础设施的一个令人印象深刻的例子。你也可以扩展 Clang 的功能，以便向 Clang 添加你自己的功能。这种技术与向 LLVM 添加一个 pass 插件非常相似。

让我们用一个简单的插件来探索功能。LLVM 编码标准要求函数名以小写字母开头。然而，编码标准随着时间的推移而发展，有许多情况下函数以大写字母开头。一个警告违反命名规则的插件可以帮助解决这个问题，所以让我们试一试。

因为你想在`PluginASTAction`类上运行一个用户定义的动作。如果你使用 Clang 库编写自己的工具，那么你为你的动作定义`ASTFrontendAction`类的子类。`PluginASTAction`类是`ASTFrontendAction`类的子类，还具有解析命令行选项的额外能力。

你还需要另一个`ASTConsumer`类的子类。AST 消费者是一个类，你可以在 AST 上运行一个动作，而不管 AST 的来源是什么。我们的第一个插件不需要更多的东西。你可以在`NamingPlugin.cpp`文件中创建实现，如下所示：

1.  首先包括所需的头文件。除了提到的`ASTConsumer`类，你还需要一个编译器实例和插件注册表的实例：

```cpp
#include "clang/AST/ASTConsumer.h"
#include "clang/Frontend/CompilerInstance.h"
#include "clang/Frontend/FrontendPluginRegistry.h"
```

1.  使用`clang`命名空间，并将你的实现放入匿名命名空间中，以避免名称冲突：

```cpp
using namespace clang;
namespace {
```

1.  接下来，定义你的`ASTConsumer`类的子类。稍后，如果检测到命名规则的违反，你将希望发出警告。为此，你需要一个对`DiagnosticsEngine`实例的引用。

1.  你需要在类中存储一个`CompilerInstance`实例，然后你可以要求一个`DiagnosticsEngine`实例：

```cpp
class NamingASTConsumer : public ASTConsumer {
  CompilerInstance &CI;
public:
  NamingASTConsumer(CompilerInstance &CI) : CI(CI) {}
```

1.  `ASTConsumer`实例有几个入口方法。`HandleTopLevelDecl()`方法符合我们的目的。该方法对顶层的每个声明都会被调用。这包括函数以外的内容，例如变量。因此，你将使用 LLVM RTTI `dyn_cast<>()`函数来确定声明是否是函数声明。`HandleTopLevelDecl()`方法有一个声明组作为参数，它可以包含多个声明。这需要对声明进行循环。以下代码展示了`HandleTopLevelDecl()`方法：

```cpp
  bool HandleTopLevelDecl(DeclGroupRef DG) override {
    for (DeclGroupRef::iterator I = DG.begin(),
                                E = DG.end();
         I != E; ++I) {
      const Decl *D = *I;
      if (const FunctionDecl *FD =
              dyn_cast<FunctionDecl>(D)) {
```

1.  在找到函数声明后，你需要检索函数的名称。你还需要确保名称不为空：

```cpp
        std::string Name =
            FD->getNameInfo().getName().getAsString();
        assert(Name.length() > 0 &&
               "Unexpected empty identifier");
```

如果函数名不以小写字母开头，那么你将发现一个违反命名规则的情况：

```cpp
        char &First = Name.at(0);
        if (!(First >= 'a' && First <= 'z')) {
```

1.  要发出警告，你需要一个`DiagnosticsEngine`实例。另外，你需要一个消息 ID。在 Clang 内部，消息 ID 被定义为一个枚举。因为你的插件不是 Clang 的一部分，你需要创建一个自定义 ID，然后用它来发出警告：

```cpp
          DiagnosticsEngine &Diag = 
              CI.getDiagnostics();
          unsigned ID = Diag.getCustomDiagID(
              DiagnosticsEngine::Warning,
              "Function name should start with "
              "lowercase letter");
          Diag.Report(FD->getLocation(), ID);
```

1.  除了关闭所有的大括号，你需要从这个函数中返回`true`来表示处理可以继续进行：

```cpp
        }
      }
    }
    return true;
  }
};
```

1.  接下来，你需要创建`PluginASTAction`子类，该子类实现了 Clang 调用的接口：

```cpp
class PluginNamingAction : public PluginASTAction {
public:
```

你必须实现的第一个方法是`CreateASTConsumer()`方法，它返回你的`NamingASTConsumer`类的一个实例。这个方法是由 Clang 调用的，传递的`CompilerInstance`实例让你可以访问编译器的所有重要类。以下代码演示了这一点：

```cpp
  std::unique_ptr<ASTConsumer>
  CreateASTConsumer(CompilerInstance &CI,
                    StringRef file) override {
    return std::make_unique<NamingASTConsumer>(CI);
  }
```

1.  插件还可以访问命令行选项。您的插件没有命令行参数，只需返回`true`表示成功：

```cpp
  bool ParseArgs(const CompilerInstance &CI,
                 const std::vector<std::string> &args)                                                override {
    return true;
  }
```

1.  插件的操作类型描述了何时调用操作。默认值是`Cmdline`，这意味着必须在命令行上命名插件才能调用。您需要覆盖该方法并将值更改为`AddAfterMainAction`，这将自动运行操作：

```cpp
  PluginASTAction::ActionType getActionType() override {
    return AddAfterMainAction;
  }
```

1.  您的`PluginNamingAction`类的实现已经完成；只缺少类和匿名命名空间的闭合大括号。将它们添加到代码中如下：

```cpp
};
}
```

1.  最后，您需要注册插件。第一个参数是插件的名称，第二个参数是帮助文本：

```cpp
static FrontendPluginRegistry::Add<PluginNamingAction>
    X("naming-plugin", "naming plugin");
```

这完成了插件的实现。要编译插件，在`CMakeLists.txt`文件中创建一个构建描述。插件位于 Clang 源树之外，因此您需要设置一个完整的项目。您可以按照以下步骤进行：

1.  从定义所需的**CMake**版本和项目名称开始：

```cpp
cmake_minimum_required(VERSION 3.13.4)
project(naminglugin)
```

1.  接下来，包括 LLVM 文件。如果 CMake 无法自动找到文件，则必须将`LLVM_DIR`变量设置为指向包含 CMake 文件的 LLVM 目录：

```cpp
find_package(LLVM REQUIRED CONFIG)
```

1.  将包含一些必需模块的 LLVM 目录附加到搜索路径中：

```cpp
list(APPEND CMAKE_MODULE_PATH ${LLVM_DIR})
include(ChooseMSVCCRT)
include(AddLLVM)
include(HandleLLVMOptions)
```

1.  然后，加载 Clang 的 CMake 定义。如果 CMake 无法自动找到文件，则必须将`Clang_DIR`变量设置为指向包含 CMake 文件的 Clang 目录：

```cpp
find_package(Clang REQUIRED)
```

1.  接下来，定义头文件和库文件的位置，以及要使用的定义：

```cpp
include_directories("${LLVM_INCLUDE_DIR}"
                    "${CLANG_INCLUDE_DIRS}")
add_definitions("${LLVM_DEFINITIONS}")
link_directories("${LLVM_LIBRARY_DIR}")
```

1.  前面的定义设置了构建环境。插入以下命令，定义插件的名称、插件的源文件和它是一个 Clang 插件：

```cpp
add_llvm_library(NamingPlugin MODULE NamingPlugin.cpp
                 PLUGIN_TOOL clang)
```

在**Windows**上，插件支持与**Unix**平台不同，必须链接所需的 LLVM 和 Clang 库。以下代码确保了这一点：

```cpp
if(LLVM_ENABLE_PLUGINS AND (WIN32 OR CYGWIN))
  set(LLVM_LINK_COMPONENTS Support)
  clang_target_link_libraries(NamingPlugin PRIVATE
    clangAST clangBasic clangFrontend clangLex)
endif()
```

1.  将这两个文件保存在`NamingPlugin`目录中。在与`NamingPlugin`目录相同级别创建一个`build-naming-plugin`目录，并使用以下命令构建插件：

```cpp
$ mkdir build-naming-plugin
$ cd build-naming-plugin
$ cmake –G Ninja ../NamingPlugin
$ ninja
```

这些步骤在`build`目录中创建了`NamingPlugin.so`共享库。

要测试插件，请将以下源代码保存为`naming.c`文件。`Func1`函数名称违反了命名规则，但`main`名称没有违反：

```cpp
int Func1() { return 0; }
int main() { return Func1(); }
```

要调用插件，您需要指定`-fplugin=`选项：

```cpp
$ clang -fplugin=./NamingPlugin.so  naming.c
naming.c:1:5: warning: Function name should start with lowercase letter
int Func1() { return 0; }
    ^
1 warning generated.
```

这种调用方式要求您覆盖`PluginASTAction`类的`getActionType()`方法，并返回与`Cmdline`默认值不同的值。

如果您没有这样做，例如，因为您希望更多地控制插件操作的调用，那么可以从编译器命令行运行插件：

```cpp
$ clang -cc1 -load ./NamingPlugin.so -plugin naming-plugin\
  naming.c
```

恭喜，您已经构建了您的第一个 Clang 插件！

这种方法的缺点是它有一定的限制。`ASTConsumer`类有不同的入口方法，但它们都是粗粒度的。这可以通过使用`RecursiveASTVisitor`类来解决。这个类遍历所有 AST 节点，您可以重写您感兴趣的`VisitXXX()`方法。您可以按照以下步骤重写插件以使用访问者：

1.  您需要为`RecursiveASTVisitor`类的定义添加额外的`include`。将其插入如下：

```cpp
#include "clang/AST/RecursiveASTVisitor.h"
```

1.  然后，在匿名命名空间中将访问者定义为第一个类。您只需存储对 AST 上下文的引用，这将使您能够访问所有重要的 AST 操作方法，包括发出警告所需的`DiagnosticsEngine`实例：

```cpp
class NamingVisitor
    : public RecursiveASTVisitor<NamingVisitor> {
private:
  ASTContext &ASTCtx;
public:
  explicit NamingVisitor(CompilerInstance &CI)
      : ASTCtx(CI.getASTContext()) {}
```

1.  在遍历期间，每当发现函数声明时，都会调用`VisitFunctionDecl()`方法。将内部循环的主体复制到`HandleTopLevelDecl()`函数中：

```cpp
  virtual bool VisitFunctionDecl(FunctionDecl *FD) {
    std::string Name =
        FD->getNameInfo().getName().getAsString();
    assert(Name.length() > 0 &&
           "Unexpected empty identifier");
    char &First = Name.at(0);
    if (!(First >= 'a' && First <= 'z')) {
      DiagnosticsEngine &Diag = 
          ASTCtx.getDiagnostics();
      unsigned ID = Diag.getCustomDiagID(
          DiagnosticsEngine::Warning,
          "Function name should start with "
          "lowercase letter");
      Diag.Report(FD->getLocation(), ID);
    }
    return true;
  }
};
```

1.  这完成了访问者模式的实现。在你的`NamingASTConsumer`类中，你现在只需要存储一个访问者实例：

```cpp
  std::unique_ptr<NamingVisitor> Visitor;
public:
  NamingASTConsumer(CompilerInstance &CI)
      : Visitor(std::make_unique<NamingVisitor>(CI)) {}
```

1.  你将删除`HandleTopLevelDecl()`方法，因为功能现在在访问者类中，所以你需要重写`HandleTranslationUnit()`方法。这个类对每个翻译单元调用一次，你将从这里开始 AST 遍历：

```cpp
  void
  HandleTranslationUnit(ASTContext &ASTCtx) override {
    Visitor->TraverseDecl(
        ASTCtx.getTranslationUnitDecl());
  }
```

这个新的实现具有完全相同的功能。优点是更容易扩展。例如，如果你想检查变量声明，那么你实现`VisitVarDecl()`方法。或者如果你想处理语句，那么你实现`VisitStmt()`方法。基本上，你对 C、C++和 Objective C 语言的每个实体都有一个访问者方法。

访问 AST 允许你构建执行复杂任务的插件。强制命名约定，如本节所述，是 Clang 的一个有用补充。你可以实现的另一个有用的插件是计算软件度量，比如**圈复杂度**。你还可以添加或替换 AST 节点，允许你例如添加运行时仪表。添加插件允许你按照你的需要扩展 Clang。

# 总结

在本章中，你学会了如何应用各种消毒剂。你使用`address`消毒剂检测指针错误，使用`memory`消毒剂检测未初始化的内存访问，并使用`thread`消毒剂检测数据竞争。应用程序错误通常是由格式不正确的输入触发的，你实现了模糊测试来使用随机数据测试你的应用程序。

你使用 XRay 为你的应用程序添加了仪表，以识别性能瓶颈，并且你也学习了各种可视化数据的方法。在本章中，你还使用了 Clang 静态分析器通过对源代码的解释来查找可能的错误，并学习了如何构建自己的 Clang 插件。

这些技能将帮助你提高构建应用程序的质量。在应用程序用户抱怨之前找到运行时错误肯定是件好事。应用本章中所学的知识，你不仅可以找到各种常见错误，还可以扩展 Clang 的新功能。

在下一章中，你将学习如何向 LLVM 添加新的后端。
