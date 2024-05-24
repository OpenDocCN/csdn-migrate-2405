# LLVM12 学习手册（三）

> 原文：[`zh.annas-archive.org/md5/96A20F7680F39BBAA9B437BF26B65FE2`](https://zh.annas-archive.org/md5/96A20F7680F39BBAA9B437BF26B65FE2)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第六章：高级语言构造的 IR 生成

今天的高级语言通常使用聚合数据类型和**面向对象编程**（**OOP**）构造。**LLVM IR**对聚合数据类型有一定支持，我们必须自行实现类似类的 OOP 构造。添加聚合类型引发了一个问题，即如何传递聚合类型的参数。不同的平台有不同的规则，这也反映在 IR 中。遵守调用约定可确保可以调用系统函数。

在本章中，您将学习如何将聚合数据类型和指针转换为 LLVM IR，以及如何以符合系统的方式传递函数的参数。您还将学习如何在 LLVM IR 中实现类和虚函数。

本章将涵盖以下主题：

+   使用数组、结构和指针

+   正确获取应用程序二进制接口

+   为类和虚函数创建 IR 代码

通过本章结束时，您将掌握创建 LLVM IR 的聚合数据类型和 OOP 的知识。您还将了解如何根据平台规则传递聚合数据类型。

# 技术要求

本章的代码文件可在以下网址找到：[`github.com/PacktPublishing/Learn-LLVM-12/tree/master/Chapter06/tinylang`](https://github.com/PacktPublishing/Learn-LLVM-12/tree/master/Chapter06/tinylang)

您可以在以下网址找到代码的操作视频：[`bit.ly/3nllhED`](https://bit.ly/3nllhED)

# 使用数组、结构和指针

对于几乎所有应用程序，诸如`INTEGER`之类的基本类型是不够的。例如，要表示数学对象，如矩阵或复数，必须基于现有数据类型构造新的数据类型。这些新数据类型通常称为**聚合**或**复合类型**。

`tinylang`类型为`ARRAY [10] OF INTEGER`，或 C 类型为`long[10]`，在 IR 中表示如下：

```cpp
[10 x i64]
```

结构是不同类型的组合。在编程语言中，它们通常用具有命名成员的方式表示。例如，在`tinylang`中，结构写为`RECORD x, y: REAL; color: INTEGER; END;`，在 C 中相同的结构为`struct { float x, y; long color; };`。在 LLVM IR 中，只列出类型名称：

```cpp
{ float, float, i64 }
```

要访问成员，使用数字索引。与数组一样，第一个元素的索引号为`0`。

该结构的成员根据数据布局字符串中的规范在内存中布局。如果需要，将插入未使用的填充字节。如果需要控制内存布局，则可以使用紧凑结构，其中所有元素具有 1 字节对齐。语法略有不同：

```cpp
<{ float, float, i64 }>
```

加载到寄存器中，数组和结构被视为一个单元。例如，不可能将`%x`数组值寄存器的单个元素表示为`%x[3]`。这是因为`%x[i]`和`%x[j]`是否引用相同的元素。相反，我们需要特殊指令来提取和插入单个元素值到数组中。要读取第二个元素，我们使用以下：

```cpp
%el2 = extractvalue [10 x i64] %x, 1
```

我们还可以更新一个元素，例如第一个元素：

```cpp
%xnew = insertvalue [10 x i64] %x, i64 %el2, 0
```

这两个指令也适用于结构。例如，要从`%pt`寄存器中访问`color`成员，可以编写以下内容：

```cpp
%color = extractvalue { float, float, i64 } %pt, 2
```

这两个指令都有一个重要的限制：索引必须是一个常数。对于结构，这很容易解释。索引号只是名称的替代，诸如 C 的语言没有动态计算结构成员名称的概念。对于数组，这只是它无法有效实现。这两个指令在特定情况下具有价值，当元素数量较少且已知时。例如，复数可以建模为两个浮点数的数组。传递这个数组是合理的，并且在计算过程中始终清楚数组的哪一部分必须被访问。

为了在前端通用，我们必须使用指向内存的指针。LLVM 中的所有全局值都表示为指针。让我们声明一个全局变量 `@arr`，作为包含八个 `i64` 元素的数组，相当于 C 声明的 `long arr[8]`：

```cpp
@arr = common global [8 x i64] zeroinitializer
```

要访问数组的第二个元素，必须执行地址计算以确定索引元素的地址。然后，可以从该地址加载值。放入 `@second` 函数中，看起来像这样：

```cpp
define i64 @second() {
  %1 = getelementptr [8 x i64], [8 x i64]* @arr, i64 0, i64 
       1
  %2 = load i64, i64* %1
  ret i64 %2
}
```

`getelementptr` 指令是地址计算的主要工具。因此，它需要更多的解释。第一个操作数 `[8 x i64]` 是指令操作的基本类型。第二个操作数 `[8 x i64]* @arr` 指定了基本指针。请注意这里的细微差别：我们声明了一个包含八个元素的数组，但因为所有的全局值都被视为指针，所以我们有一个指向数组的指针。在 C 语法中，我们使用 `long (*arr)[8]`！这意味着我们首先必须解引用指针，然后才能索引元素，比如在 C 中的 `arr[0][1]`。第三个操作数 `i64 0` 解引用指针，第四个操作数 `i64 1` 是元素索引。这个计算的结果是索引元素的地址。请注意，这个指令不会触及任何内存。

除了结构体，索引参数不需要是常量。因此，`getelementptr` 指令可以在循环中用于检索数组的元素。这里对待结构体的方式不同：只能使用常量，并且类型必须是 `i32`。

有了这些知识，数组很容易从*第五章*，*IR 生成基础* 中集成到代码生成器中。`convertType()` 方法必须扩展以创建类型。如果 `Arr` 变量保存了数组的类型标识符，那么我们可以在方法中添加以下内容：

```cpp
llvm::Type *Component = convertType(Arr->getComponentType());
uint64_t NumElements = Arr->getNumElem();
return llvm::ArrayType::get(Component, NumElements);
```

这种类型可以用来声明全局变量。对于局部变量，我们需要为数组分配内存。我们在过程的第一个基本块中进行这个操作：

```cpp
for (auto *D : Proc->getDecls()) {
  if (auto *Var =
          llvm::dyn_cast<VariableDeclaration>(D)) {
    llvm::Type *Ty = mapType(Var);
    if (Ty->isAggregateType()) {
      llvm::Value *Val = Builder.CreateAlloca(Ty);
      Defs.Defs.insert(
          std::pair<Decl *, llvm::Value *>(Var, Val));
    }
  }
}
```

要读取和写入一个元素，我们必须生成 `getelemtptr` 指令。这被添加到 `emitExpr()`（读取值）和 `emitAssign()`（写入值）方法中。要读取数组的元素，首先读取变量的值。然后处理变量的选择器。对于每个索引，计算表达式并存储值。基于这个列表，计算引用元素的地址并加载值：

```cpp
auto &Selectors = Var->getSelectorList();
for (auto *I = Selectors.begin(),
          *E = Selectors.end();
     I != E;) {
  if (auto *Idx = llvm::dyn_cast<IndexSelector>(*I)) {
    llvm::SmallVector<llvm::Value *, 4> IdxList;
    IdxList.push_back(emitExpr(Idx->getIndex()));
    for (++I; I != E;) {
      if (auto *Idx2 =
              llvm::dyn_cast<IndexSelector>(*I)) {
        IdxList.push_back(emitExpr(Idx2->getIndex()));
        ++I;
      } else
        break;
    }
    Val = Builder.CreateGEP(Val, IdxList);
    Val = Builder.CreateLoad(
        Val->getType()->getPointerElementType(), Val);
  } else {
    llvm::report_fatal_error("Unsupported selector");
  }
}
```

写入数组元素使用相同的代码，唯一的区别是不生成 `load` 指令。而是使用指针作为 `store` 指令的目标。对于记录，使用类似的方法。记录成员的选择器包含常量字段索引，称为 `Idx`。将这个常量转换为常量 LLVM 值，如下所示：

```cpp
llvm::Value *FieldIdx = llvm::ConstantInt::get(Int32Ty, Idx);
```

然后，你可以像数组一样在 `Builder.CreateGEP()` 方法中使用值。

现在你有了将聚合数据类型转换为 LLVM IR 的知识。以系统兼容的方式传递这些类型的值需要一些小心，你将在下一节中学习如何正确实现它。

# 正确理解应用二进制接口

随着数组和记录被添加到代码生成器中，你可能会注意到有时生成的代码并不按预期执行。原因是到目前为止我们忽略了平台的调用约定。每个平台都定义了如何一个函数可以调用同一程序或库中的另一个函数的规则。这些规则在**应用二进制接口**（**ABI**）文档中进行了总结。典型的信息包括以下内容：

+   机器寄存器用于参数传递吗？如果是，使用哪些？

+   如何将数组和结构等聚合类型传递给函数？

+   返回值是如何处理的？

使用的规则种类繁多。在某些平台上，聚合始终以间接方式传递，这意味着在堆栈上放置聚合的副本，然后只传递该副本的指针作为参数。在其他平台上，小型聚合（例如 128 位或 256 位宽）在寄存器中传递，只有超过该阈值才使用间接参数传递。一些平台还使用浮点和矢量寄存器进行参数传递，而其他平台要求浮点值在整数寄存器中传递。

当然，这都是有趣的低级内容。不幸的是，这些内容泄漏到了 LLVM IR 中。起初，这让人感到惊讶。毕竟，我们在 LLVM IR 中定义了函数所有参数的类型！事实证明这是不够的。为了理解这一点，让我们考虑复数。一些语言具有内置的复数数据类型；例如，C99 具有`float _Complex`（等等）。较早版本的 C 没有复数类型，但您可以轻松地定义`struct Complex { float re, im; }`并在此类型上创建算术运算。这两种类型都可以映射到`{ float，float }`LLVM IR 类型。如果 ABI 现在规定内置复数类型的值在两个浮点寄存器中传递，但用户定义的聚合始终以间接方式传递，那么函数提供的信息对于 LLVM 来说不足以决定如何传递此特定参数。不幸的后果是我们需要向 LLVM 提供更多信息，而这些信息是高度特定于 ABI 的。

有两种方法可以向 LLVM 指定此信息：参数属性和类型重写。您需要使用的方法取决于目标平台和代码生成器。最常用的参数属性如下：

+   `inreg`指定参数在寄存器中传递。

+   `byval`指定参数按值传递。参数必须是指针类型。将指向数据的隐藏副本制作，并将此指针传递给被调用的函数。

+   `zeroext`和`signext`指定传递的整数值应该是零扩展或符号扩展。

+   `sret`指定此参数保存一个指向用于从函数返回聚合类型的内存的指针。

虽然所有代码生成器都支持`zeroext`、`signext`和`sret`属性，但只有一些支持`inreg`和`byval`。可以使用`addAttr()`方法将属性添加到函数的参数中。例如，要在`Arg`参数上设置`inreg`属性，可以调用以下方法：

```cpp
Arg->addAttr(llvm::Attribute::InReg);
```

要设置多个属性，可以使用`llvm::AttrBuilder`类。

提供额外信息的另一种方法是使用类型重写。通过这种方法，您可以伪装原始类型。您可以执行以下操作：

+   拆分参数；例如，不要传递一个复数参数，而是传递两个浮点参数。

+   将参数转换为不同的表示形式，例如，将大小为 64 位或更小的结构体转换为`i64`整数。

要在不改变值的位的情况下在类型之间转换，可以使用`bitcast`指令。`bitcast`指令不适用于聚合类型，但这并不是限制，因为您总是可以使用指针。如果将一个点建模为具有两个`int`成员的结构，在 LLVM 中表示为类型`{ i32，i32 }`，那么可以以以下方式将其`bitcast`为`i64`：

```cpp
%intpoint = bitcast { i32, i32}* %point to i64*
```

这将指针转换为结构体的指针，然后可以加载此值并将其作为参数传递。您只需确保两种类型的大小相同即可。

向参数添加属性或更改类型并不复杂。但是你怎么知道你需要实现什么？首先，你应该了解目标平台上使用的调用约定。例如，Linux 上的 ELF ABI 针对每个支持的 CPU 平台都有文档记录。只需查阅文档并熟悉它。有关 LLVM 代码生成器的要求也有文档记录。信息来源是 Clang 实现，在[`github.com/llvm/llvm-project/blob/main/clang/lib/CodeGen/TargetInfo.cpp`](https://github.com/llvm/llvm-project/blob/main/clang/lib/CodeGen/TargetInfo.cpp)文件中。这个单一文件包含了所有支持平台的 ABI 特定操作。这也是所有信息被收集的唯一地方。

在本节中，您学习了如何生成符合平台 ABI 的函数调用的 IR。下一节将介绍为类和虚函数创建 IR 的不同方法。

# 为类和虚函数创建 IR 代码

许多现代编程语言使用类支持面向对象编程。**类**是一个高级语言构造，在本节中，我们将探讨如何将类构造映射到 LLVM IR 中。

## 实现单继承

类是数据和方法的集合。一个类可以继承自另一个类，可能添加更多的数据字段和方法，或者覆盖现有的虚拟方法。让我们用 Oberon-2 中的类来说明这一点，这也是`tinylang`的一个很好的模型。一个`Shape`类定义了一个带有颜色和面积的抽象形状：

```cpp
TYPE Shape = RECORD
               color: INTEGER;
               PROCEDURE (VAR s: Shape) GetColor(): 
                   INTEGER;
               PROCEDURE (VAR s: Shape) Area(): REAL;
             END;
```

`GetColor`方法只返回颜色编号：

```cpp
PROCEDURE (VAR s: Shape) GetColor(): INTEGER;
BEGIN RETURN s.color; END GetColor;
```

抽象形状的面积无法计算，因此这是一个抽象方法：

```cpp
PROCEDURE (VAR s: Shape) Area(): REAL;
BEGIN HALT; END;
```

`Shape`类型可以扩展为表示`Circle`类：

```cpp
TYPE Circle = RECORD (Shape)
                radius: REAL;
                PROCEDURE (VAR s: Circle) Area(): REAL;
              END;
```

对于一个圆，可以计算出面积：

```cpp
PROCEDURE (VAR s: Circle) Area(): REAL;
BEGIN RETURN 2 * radius * radius; END;
```

类型也可以在运行时查询。如果`shape`是`Shape`类型的变量，那么我们可以这样制定类型测试：

```cpp
IF shape IS Circle THEN (* … *) END;
```

除了不同的语法之外，这与 C++中的工作方式非常相似。与 C++的一个显着区别是，Oberon-2 的语法使隐式的`this`指针变得显式，称之为方法的接收者。

要解决的基本问题是如何在内存中布局一个类，以及如何实现方法的动态调用和运行时类型检查。对于内存布局来说，这是相当容易的。`Shape`类只有一个数据成员，我们可以将它映射到相应的 LLVM 结构类型：

```cpp
@Shape = type { i64 }
```

`Circle`类添加了另一个数据成员。解决方案是将新的数据成员追加到末尾：

```cpp
@Circle = type { i64, float }
```

原因是一个类可以有许多子类。采用这种策略，共同基类的数据成员始终具有相同的内存偏移量，并且还使用相同的索引通过`getelementptr`指令访问字段。

要实现方法的动态调用，我们必须进一步扩展 LLVM 结构。如果在`Shape`对象上调用`Area()`函数，那么将调用抽象方法，导致应用程序停止。如果在`Circle`对象上调用它，那么将调用计算圆形面积的相应方法。`GetColor()`函数可以用于两个类的对象。实现这一点的基本思想是为每个对象关联一个带有函数指针的表。在这里，表将有两个条目：一个是`GetColor()`方法，另一个是`Area()`函数。`Shape`类和`Circle`类都有这样的表。这些表在`Area()`函数的条目上有所不同，根据对象的类型调用不同的代码。这个表被称为**虚方法表**，通常缩写为**vtable**。

仅有 vtable 是没有用的。我们必须将其与对象连接起来。为此，我们将一个指向 vtable 的指针始终添加为结构的第一个数据成员。在 LLVM 级别上，`@Shape`类型然后变成了以下形式：

```cpp
@Shape = type { [2 x i8*]*, i64 }
```

`@Circle`类型也类似扩展。结果的内存结构显示在*图 6.1*中：

![图 6.1-类和虚拟方法表的内存布局](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/lrn-llvm12/img/Figure_6.1_B15647.jpg)

图 6.1-类和虚拟方法表的内存布局

LLVM 没有 void 指针，而是使用字节指针。引入隐藏的`vtable`字段后，现在也需要一种初始化它的方法。在 C++中，这是调用构造函数的一部分。在 Oberon-2 中，当分配内存时，该字段会自动初始化。

然后执行动态调用方法的步骤如下：

1.  通过`getelementptr`指令计算 vtable 指针的偏移量。

1.  加载 vtable 的指针。

1.  计算函数在 vtable 中的偏移量。

1.  加载函数指针。

1.  通过`call`指令间接调用函数。

这听起来并不是很高效，但事实上，大多数 CPU 架构可以在只有两条指令的情况下执行这个动态调用。因此，这实际上是 LLVM 级别的冗长。

要将函数转换为方法，需要对象数据的引用。这是通过将数据指针作为方法的第一个参数来实现的。在 Oberon-2 中，这是显式的接收者。在类似于 C++的语言中，这是隐式的`this`指针。

有了 vtable，我们对每个类在内存中都有一个唯一的地址。这对运行时类型测试有帮助吗？答案是只有在有限的范围内有帮助。为了说明问题，让我们通过一个`Ellipse`类扩展类层次结构，它继承自`Circle`类。（这不是数学意义上的经典*is-a*关系。）如果我们有`Shape`类型的`shape`变量，那么我们可以将`shape IS Circle`类型测试实现为将存储在`shape`变量中的 vtable 指针与`Circle`类的 vtable 指针进行比较。只有当`shape`确实具有`Circle`类型时，比较才会返回`true`。但如果`shape`确实是`Ellipse`类型，那么比较会返回`false`，即使`Ellipse`类型的对象可以在只需要`Circle`类型的对象的所有地方使用。

显然，我们需要做更多的工作。解决方案是使用运行时类型信息扩展虚拟方法表。需要存储多少信息取决于源语言。为了支持运行时类型检查，只需存储指向基类 vtable 的指针，然后看起来像*图 6.2*：

![图 6.2-支持简单类型测试的类和 vtable 布局](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/lrn-llvm12/img/Figure_6.2_B15647.jpg)

图 6.2-支持简单类型测试的类和 vtable 布局

如果像之前描述的那样测试失败，那么就会用基类的 vtable 指针重复测试。这将重复进行，直到测试产生`true`，或者如果没有基类，则产生`false`。与调用动态函数不同，类型测试是一个昂贵的操作，因为在最坏的情况下，继承层次结构会一直向上走到根类。

如果你知道整个类层次结构，那么可以采用高效的方法：对类层次结构的每个成员进行深度优先编号。然后，类型测试变成了与数字或区间的比较，可以在常数时间内完成。事实上，这就是 LLVM 自己的运行时类型测试的方法，我们在上一章中了解到了。

将运行时类型信息与 vtable 耦合是一个设计决策，要么是源语言规定的，要么只是一个实现细节。例如，如果你需要详细的运行时类型信息，因为源语言支持运行时反射，并且你有没有 vtable 的数据类型，那么耦合两者并不是一个好主意。在 C++中，耦合导致一个具有虚函数（因此没有 vtable）的类没有附加的运行时类型数据。

通常，编程语言支持接口，它们是一组虚拟方法。接口很重要，因为它们增加了一个有用的抽象。我们将在下一节中看看接口的可能实现。

## 通过接口扩展单一继承

诸如**Java**之类的语言支持接口。接口是一组抽象方法，类似于没有数据成员且只定义了抽象方法的基类。接口提出了一个有趣的问题，因为实现接口的每个类可以在 vtable 中的不同位置具有相应的方法。原因很简单，vtable 中函数指针的顺序是从源语言中类定义中函数的顺序派生的。接口中的定义与此无关，不同的顺序是正常的。

因为接口中定义的方法可以有不同的顺序，我们将每个实现的接口附加到类上。对于接口的每个方法，此表可以指定 vtable 中方法的索引，或者可以是存储在 vtable 中的函数指针的副本。如果在接口上调用方法，那么将搜索接口的相应 vtable，然后获取函数指针并调用方法。将两个接口`I1`和`I2`添加到`Shape`类中会得到以下布局：

![图 6.3 – 接口 vtable 的布局](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/lrn-llvm12/img/Figure_6.3_B15647.jpg)

图 6.3 – 接口 vtable 的布局

警告在于我们必须找到正确的 vtable。我们可以使用类似于*运行时类型测试*的方法：我们可以通过接口 vtable 列表执行线性搜索。我们可以为每个接口分配一个唯一的数字（例如，内存地址），并使用此数字来识别 vtable。这种方案的缺点是显而易见的：通过接口调用方法比在类上调用相同的方法需要更多的时间。对于这个问题并没有简单的缓解方法。

一个好的方法是用哈希表替换线性搜索。在编译时，已知类实现的接口。因此，我们可以构造一个完美的哈希函数，将接口号映射到接口的 vtable。可能需要一个已知的唯一标识接口的数字来进行构造，以便内存不会有帮助。但是还有其他计算唯一数字的方法。如果源中的符号名称是唯一的，那么总是可以计算出诸如`MD5`之类的加密哈希，并将哈希用作数字。计算发生在编译时，因此没有运行时成本。

结果比线性搜索快得多，只需要常数时间。但是，它涉及对数字进行多次算术运算，比类类型的方法调用慢。

通常，接口也参与运行时类型测试，使得搜索列表变得更长。当然，如果实现了哈希表方法，那么它也可以用于运行时类型测试。

一些语言允许有多个父类。这对实现有一些有趣的挑战，我们将在下一节中掌握这些挑战。

## 添加对多重继承的支持

多重继承增加了另一个挑战。如果一个类从两个或更多的基类继承，那么我们需要以这样的方式组合数据成员，以便它们仍然可以从方法中访问。就像单一继承的情况一样，解决方案是追加所有数据成员，包括隐藏的 vtable 指针。`Circle`类不仅是一个几何形状，还是一个图形对象。为了模拟这一点，我们让`Circle`类继承自`Shape`类和`GraphicObj`类。在类布局中，`Shape`类的字段首先出现。然后，我们追加`GraphicObj`类的所有字段，包括隐藏的 vtable 指针。之后，我们添加`Circle`类的新数据成员，得到了*图 6.4*中显示的整体结构：

![图 6.4 - 具有多重继承的类和 vtable 的布局](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/lrn-llvm12/img/Figure_6.4_B15647.jpg)

图 6.4 - 具有多重继承的类和 vtable 的布局

这种方法有几个影响。现在可以有几个指向对象的指针。指向`Shape`或`Circle`类的指针指向对象的顶部，而指向`GraphicObj`类的指针指向对象的内部，指向嵌入的`GraphicObj`对象的开头。在比较指针时必须考虑到这一点。

调用虚方法也会受到影响。如果一个方法在`GraphicObj`类中定义，那么这个方法期望`GraphicObj`类的类布局。如果这个方法在`Circle`类中没有被覆盖，那么有两种可能性。简单的情况是，如果方法调用是通过指向`GraphicObj`实例的指针完成的：在这种情况下，你在`GraphicObj`类的 vtable 中查找方法的地址并调用该函数。更复杂的情况是，如果你用指向`Circle`类的指针调用该方法。同样，你可以在`Circle`类的 vtable 中查找方法的地址。被调用的方法期望一个指向`GraphicObj`类实例的`this`指针，所以我们也必须调整该指针。我们可以做到这一点，因为我们知道`GraphicObj`类在`Circle`类内部的偏移量。

如果`GrapicObj`的方法在`Circle`类中被覆盖，那么如果通过指向`Circle`类的指针调用该方法，则不需要做任何特殊处理。然而，如果通过指向`GraphicObj`实例的指针调用该方法，那么我们需要进行另一个调整，因为该方法需要一个指向`Circle`实例的`this`指针。在编译时，我们无法计算这个调整，因为我们不知道这个`GraphicObj`实例是否是多重继承层次结构的一部分。为了解决这个问题，我们在 vtable 中的每个函数指针一起存储我们需要对`this`指针进行的调整，在*图 6.5*中显示。

![图 6.5 - 具有对 this 指针的调整的 vtable](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/lrn-llvm12/img/Figure_6.5_B15647.jpg)

图 6.5 - 具有对 this 指针的调整的 vtable

现在方法调用变成了以下形式：

1.  在 vtable 中查找函数指针。

1.  调整`this`指针。

1.  调用方法。

这种方法也可以用于实现接口。因为接口只有方法，每个实现的接口都会向对象添加一个新的 vtable 指针。这样做更容易实现，而且很可能更快，但它会给每个对象实例增加开销。在最坏的情况下，如果你的类有一个单独的 64 位数据字段，但实现了 10 个接口，那么你的对象在内存中需要 96 字节：8 字节用于类本身的 vtable 指针，8 字节用于数据成员，以及每个接口的 10 * 8 字节的 vtable 指针。

为了支持与对象的有意义比较并执行运行时类型测试，需要首先将指针规范化为对象。如果我们在 vtable 中添加一个额外的字段，其中包含对象顶部的偏移量，那么我们就可以始终调整指针指向真正的对象。在`Circle`类的 vtable 中，这个偏移量是`0`，但在嵌入的`GraphicObj`类的 vtable 中不是。当然，是否需要实现这一点取决于源语言的语义。

LLVM 本身不偏向于面向对象特性的特殊实现。正如在本节中所看到的，我们可以使用现有的 LLVM 数据类型来实现所有方法。如果你想尝试一种新的方法，那么一个好的方式是先在 C 中做一个原型。所需的指针操作很快就能转换为 LLVM IR，但在高级语言中推理功能更容易。

通过本节学到的知识，你可以在自己的代码生成器中将编程语言中常见的所有面向对象编程构造降低为 LLVM IR。你已经知道了如何表示内存中的单继承、带接口的单继承或多重继承，以及如何实现类型测试和查找虚拟函数，这些都是面向对象语言的核心概念。

# 总结

在本章中，你学会了如何将聚合数据类型和指针转换为 LLVM IR 代码。你还了解了 ABI 的复杂性。最后，你了解了将类和虚拟函数转换为 LLVM IR 的不同方法。有了本章的知识，你将能够为大多数真实编程语言创建一个 LLVM IR 代码生成器。

在下一章中，你将学习一些高级技术。异常处理在现代编程语言中非常常见，LLVM 对此提供了一些支持。将类型信息附加到指针可以帮助进行某些优化，所以我们也会添加这个功能。最后但同样重要的是，调试应用程序的能力对许多开发人员来说是至关重要的，因此我们将为我们的代码生成器添加调试元数据的生成。


# 第七章：高级 IR 生成

在前几章介绍的**中间表示**（**IR**）生成中，您已经可以实现编译器中所需的大部分功能。在本章中，我们将研究一些通常在实际编译器中出现的高级主题。例如，许多现代语言使用异常处理，我们将看看如何将其转换为**低级虚拟机**（**LLVM**）IR。

为了支持 LLVM 优化器在某些情况下生成更好的代码，我们向 IR 代码添加了额外的类型元数据，并附加调试元数据使编译器的用户能够利用源级调试工具。

在本章中，您将学习以下主题：

+   在*抛出和捕获异常*中，您将学习如何在编译器中实现异常处理。

+   在*为基于类型的别名分析生成元数据*中，您将向 LLVM IR 附加额外的元数据，这有助于 LLVM 更好地优化代码。

+   在*添加调试元数据*中，您将实现所需的支持类，以向生成的 IR 代码添加调试信息。

到本章结束时，您将了解有关异常处理和基于类型的别名分析和调试信息的元数据的知识。

# 技术要求

本章的代码文件可在[`github.com/PacktPublishing/Learn-LLVM-12/tree/master/Chapter07`](https://github.com/PacktPublishing/Learn-LLVM-12/tree/master/Chapter07)找到

您可以在[`bit.ly/3nllhED`](https://bit.ly/3nllhED)找到代码演示视频。

# 抛出和捕获异常

LLVM IR 中的异常处理与平台的支持密切相关。在这里，我们将看到使用`libunwind`进行最常见类型的异常处理。它的全部潜力由 C++使用，因此我们将首先看一个 C++的示例，在该示例中，`bar()`函数可以抛出`int`或`double`值，如下所示：

```cpp
int bar(int x) {
  if (x == 1) throw 1;
  if (x == 2) throw 42.0;
  return x;
}
```

`foo()`函数调用`bar()`，但只处理抛出的`int`值。它还声明它只抛出`int`值，如下所示：

```cpp
int foo(int x) throw(int) {
  int y = 0;
  try {
    y = bar(x);
  }
  catch (int e) {
    y = e;
  }
  return y;
}
```

抛出异常需要两次调用运行时库。首先，使用`__cxa_allocate_exception()`调用分配异常的内存。此函数将要分配的字节数作为参数。然后将异常有效负载（例如示例中的`int`或`double`值）复制到分配的内存中。然后使用`__cxa_throw()`调用引发异常。此函数需要三个参数：指向分配的异常的指针；有关有效负载的类型信息；以及指向析构函数的指针，如果异常有效负载有一个的话。`__cxa_throw()`函数启动堆栈展开过程并且永远不会返回。在 LLVM IR 中，这是针对`int`值完成的，如下所示：

```cpp
%eh = tail call i8* @__cxa_allocate_exception(i64 4)
%payload = bitcast i8* %eh to i32*
store i32 1, i32* %payload
tail call void @__cxa_throw(i8* %eh,
                   i8* bitcast (i8** @_ZTIi to i8*), i8* 
                   null)
unreachable
```

`_ZTIi`是描述`int`类型的类型信息。对于 double 类型，它将是`_ZTId`。对`__cxa_throw()`的调用被标记为尾调用，因为它是该函数中的最终调用，可能使当前堆栈帧得以重用。

到目前为止，还没有做任何特定于 LLVM 的工作。这在`foo()`函数中发生了变化，因为对`bar()`的调用可能会引发异常。如果是`int`类型的异常，则必须将控制流转移到`catch`子句的 IR 代码。为了实现这一点，必须使用`invoke`指令而不是`call`指令，如下面的代码片段所示：

```cpp
%y = invoke i32 @_Z3bari(i32 %x) to label %next
                                 unwind label %lpad
```

两个指令之间的区别在于`invoke`有两个关联的标签。第一个标签是如果被调用的函数正常结束，通常是使用`ret`指令。在前面的代码示例中，这个标签称为`%next`。如果发生异常，则执行将继续在所谓的*着陆垫*上，具有`%lpad`标签。

着陆坪是一个基本的块，必须以`landingpad`指令开始。`landingpad`指令为 LLVM 提供了有关处理的异常类型的信息。对于`foo()`函数，它提供了以下信息：

```cpp
lpad:
%exc = landingpad { i8*, i32 }
          cleanup
          catch i8* bitcast (i8** @_ZTIi to i8*)
          filter [1 x i8*] [i8* bitcast (i8** @_ZTIi to 
              i8*)]
```

这里有三种可能的操作类型，如下所述：

+   `cleanup`：这表示存在用于清理当前状态的代码。通常，这用于调用局部对象的析构函数。如果存在此标记，则在堆栈展开期间始终调用着陆坪。

+   `catch`：这是一个类型-值对的列表，表示可以处理的异常类型。如果抛出的异常类型在此列表中找到，则调用着陆坪。对于`foo()`函数，该值是指向`int`类型的 C++运行时类型信息的指针，类似于`__cxa_throw()`函数的参数。

+   `filter`：这指定了一个异常类型数组。如果当前异常的异常类型在数组中找不到，则调用着陆坪。这用于实现`throw()`规范。对于`foo()`函数，该数组只有一个成员——`int`类型的类型信息。

`landingpad`指令的结果类型是一个`{ i8*, i32 }`结构。第一个元素是指向抛出的异常的指针，而第二个元素是类型选择器。让我们从结构中提取这两个元素，如下所示：

```cpp
%exc.ptr = extractvalue { i8*, i32 } %exc, 0
%exc.sel = extractvalue { i8*, i32 } %exc, 1
```

*类型选择器*是一个数字，它帮助我们识别*为什么调用着陆坪*的原因。如果当前异常类型与`landingpad`指令的`catch`部分中给定的异常类型之一匹配，则它具有正值。如果当前异常类型与`filter`部分中给定的任何值都不匹配，则该值为负值，如果应调用清理代码，则为`0`。

基本上，类型选择器是偏移量，指向从`landingpad`指令的`catch`和`filter`部分中给定的值构造的类型信息表。在优化期间，多个着陆坪可以合并为一个，这意味着在 IR 级别不知道此表的结构。要检索给定类型的类型选择器，我们需要调用`@llvm.eh.typeid.for`内部函数。我们需要这样做来检查类型选择器的值是否对应于`int`的类型信息，以便能够执行`catch (int e) {}`块中的代码，如下所示：

```cpp
%tid.int = tail call i32 @llvm.eh.typeid.for(
                             i8* bitcast (i8** @_ZTIi to 
                             i8*))
%tst.int = icmp eq i32 %exc.sel, %tid.int
br i1 % tst.int, label %catchint, label %filterorcleanup
```

异常处理由对`__cxa_begin_catch()`和`__cxa_end_catch()`的调用框定。`__cxa_begin_catch()`函数需要一个参数：当前异常。这是`landingpad`指令返回的值之一。它返回指向异常有效负载的指针——在我们的情况下是一个`int`值。`__cxa_end_catch()`函数标记异常处理的结束，并释放使用`__cxa_allocate_exception()`分配的内存。请注意，如果在`catch`块内抛出另一个异常，则运行时行为要复杂得多。处理异常的方式如下：

```cpp
catchint:
%payload = tail call i8* @__cxa_begin_catch(i8* %exc.ptr)
%payload.int = bitcast i8* %payload to i32*
%retval = load i32, i32* %payload.int
tail call void @__cxa_end_catch()
br label %return
```

如果当前异常的类型与`throws()`声明中的列表不匹配，则调用意外异常处理程序。首先，我们需要再次检查类型选择器，如下所示：

```cpp
filterorcleanup:
%tst.blzero = icmp slt i32 %exc.sel, 0
br i1 %tst.blzero, label %filter, label %cleanup
```

如果类型选择器的值小于`0`，则调用处理程序，如下所示：

```cpp
filter:
tail call void @__cxa_call_unexpected(i8* %exc.ptr) #4
unreachable
```

同样，不希望处理程序返回。

在这种情况下不需要清理工作，因此所有清理代码所做的就是恢复堆栈展开器的执行，如下所示：

```cpp
cleanup:
resume { i8*, i32 } %exc
```

还有一部分缺失：`libunwind`驱动堆栈展开，但它与单一语言无关。语言相关的处理在`personality`函数中完成。对于 Linux 上的 C++，`personality`函数称为`__gxx_personality_v0()`。根据平台或编译器的不同，这个名称可能会有所不同。每个需要参与堆栈展开的函数都附有一个`personality`函数。`personality`函数分析函数是否捕获异常，是否有不匹配的过滤列表，或者是否需要清理调用。它将这些信息返回给展开器，展开器会相应地进行操作。在 LLVM IR 中，`personality`函数的指针作为函数定义的一部分给出，如下面的代码片段所示：

```cpp
define i32 @_Z3fooi(i32) personality i8* bitcast
                     (i32 (...)* @__gxx_personality_v0 to 
                      i8*)
```

有了这些，异常处理功能就完成了。

要在编译器中为您的编程语言使用异常处理，最简单的策略是依附于现有的 C++运行时函数。这样做的优势是您的异常与 C++是可互操作的。缺点是您将一些 C++运行时绑定到您的语言运行时中，尤其是内存管理。如果您想避免这一点，那么您需要创建自己的`_cxa_`函数的等价物。但是，您仍然需要使用提供堆栈展开机制的`libunwind`。

1.  让我们看看如何创建这个 IR。我们在*第三章*中创建了`calc`表达式编译器，*编译器的结构*。现在我们将扩展表达式编译器的代码生成器，以便在执行除以`0`时引发和处理异常。生成的 IR 将检查除法的除数是否为`0`。如果为`true`，则会引发异常。我们还将在函数中添加一个着陆块，用于捕获异常，将`Divide by zero!`打印到控制台，并结束计算。在这种简单情况下，使用异常处理并不是真正必要的，但它允许我们集中精力在代码生成上。我们将所有代码添加到`CodeGenerator.cpp`文件中。我们首先添加所需的新字段和一些辅助方法。我们需要存储`__cxa_allocate_exception()`和`__cxa_throw()`函数的 LLVM 声明，包括函数类型和函数本身。需要一个`GlobalVariable`实例来保存类型信息。我们还需要引用包含着陆块的基本块和只包含`unreachable`指令的基本块，如下面的代码片段所示：

```cpp
  GlobalVariable *TypeInfo = nullptr;
  FunctionType *AllocEHFty = nullptr;
  Function *AllocEHFn = nullptr;
  FunctionType *ThrowEHFty = nullptr;
  Function *ThrowEHFn = nullptr;
  BasicBlock *LPadBB = nullptr;
  BasicBlock *UnreachableBB = nullptr;
```

1.  我们还添加了一个新的辅助函数来创建比较两个值的 IR。`createICmpEq()`函数以`Left`和`Right`值作为参数进行比较。它创建一个`compare`指令，测试值的相等性，并创建一个分支指令到两个基本块，用于相等和不相等的情况。两个基本块通过`TrueDest`和`FalseDest`参数的引用返回。新基本块的标签可以在`TrueLabel`和`FalseLabel`参数中给出。代码如下所示：

```cpp
  void createICmpEq(Value *Left, Value *Right,
                    BasicBlock *&TrueDest,
                    BasicBlock *&FalseDest,
                    const Twine &TrueLabel = "",
                    const Twine &FalseLabel = "") {
    Function *Fn =        Builder.GetInsertBlock()->getParent();
    TrueDest = BasicBlock::Create(M->getContext(),                                  TrueLabel, Fn);
    FalseDest = BasicBlock::Create(M->getContext(),                                   FalseLabel, Fn);
    Value *Cmp = Builder.CreateCmp(CmpInst::ICMP_EQ,                                   Left, Right);
    Builder.CreateCondBr(Cmp, TrueDest, FalseDest);
  }
```

1.  使用运行时的函数，我们需要创建几个函数声明。在 LLVM 中，必须构建给出签名的函数类型以及函数本身。我们使用`createFunc()`方法来创建这两个对象。函数需要引用`FunctionType`和`Function`指针，新声明函数的名称和结果类型。参数类型列表是可选的，并且用来指示可变参数列表的标志设置为`false`，表示参数列表中没有可变部分。代码可以在以下片段中看到：

```cpp
  void createFunc(FunctionType *&Fty, Function *&Fn,
                  const Twine &N, Type *Result,
                  ArrayRef<Type *> Params = None,
                  bool IsVarArgs = false) {
    Fty = FunctionType::get(Result, Params, IsVarArgs);
    Fn = Function::Create(
        Fty, GlobalValue::ExternalLinkage, N, M);
  }
```

准备工作完成后，我们继续生成 IR 来引发异常。

## 引发异常

为了生成引发异常的 IR 代码，我们添加了一个`addThrow()`方法。这个新方法需要初始化新字段，然后通过`__cxa_throw`函数生成引发异常的 IR。引发的异常的有效载荷是`int`类型，并且可以设置为任意值。以下是我们需要编写的代码：

1.  新的`addThrow()`方法首先检查`TypeInfo`字段是否已初始化。如果没有，则创建一个`i8*`类型和`_ZTIi`名称的全局外部常量。这代表描述 C++ `int`类型的 C++元数据。代码如下所示：

```cpp
  void addThrow(int PayloadVal) {
    if (!TypeInfo) {
      TypeInfo = new GlobalVariable(
          *M, Int8PtrTy,
          /*isConstant=*/true,
          GlobalValue::ExternalLinkage,
          /*Initializer=*/nullptr, "_ZTIi");
```

1.  初始化继续创建`__cxa_allocate_exception()`和`__cxa_throw`函数的 IR 声明，使用我们的`createFunc()`辅助方法，如下所示：

```cpp
      createFunc(AllocEHFty, AllocEHFn,
                 "__cxa_allocate_exception", 
                 Int8PtrTy,
                 {Int64Ty});
      createFunc(ThrowEHFty, ThrowEHFn, "__cxa_throw",
                 VoidTy,
                 {Int8PtrTy, Int8PtrTy, Int8PtrTy});
```

1.  使用异常处理的函数需要一个`personality`函数，它有助于堆栈展开。我们添加 IR 代码声明来自 C++库的`__gxx_personality_v0()` `personality`函数，并将其设置为当前函数的`personality`例程。当前函数没有存储为字段，但我们可以使用`Builder`实例查询当前基本块，该基本块将函数存储为`parent`字段，如下面的代码片段所示：

```cpp
      FunctionType *PersFty;
      Function *PersFn;
      createFunc(PersFty, PersFn,                 "__gxx_personality_v0", Int32Ty, None,                 true);
      Function *Fn =          Builder.GetInsertBlock()->getParent();
      Fn->setPersonalityFn(PersFn);
```

1.  接下来，我们创建并填充着陆块的基本块。首先，我们需要保存当前基本块的指针。然后，我们创建一个新的基本块，将其设置在构建器内部用作插入指令的基本块，并调用`addLandingPad()`方法。此方法生成处理异常的 IR 代码，并在下一节“捕获异常”中进行描述。以下代码填充了着陆块的基本块：

```cpp
      BasicBlock *SaveBB = Builder.GetInsertBlock();
      LPadBB = BasicBlock::Create(M->getContext(),                                  "lpad", Fn);
      Builder.SetInsertPoint(LPadBB);
      addLandingPad();
```

1.  初始化部分已经完成，创建了一个包含`unreachable`指令的基本块。然后，我们创建一个基本块，并将其设置为构建器的插入点。然后，我们向其中添加一个`unreachable`指令。最后，我们将构建器的插入点设置回保存的`SaveBB`实例，以便后续的 IR 添加到正确的基本块。代码如下所示：

```cpp
      UnreachableBB = BasicBlock::Create(
          M->getContext(), "unreachable", Fn);
      Builder.SetInsertPoint(UnreachableBB);
      Builder.CreateUnreachable();
      Builder.SetInsertPoint(SaveBB);
    }
```

1.  要引发异常，我们需要通过调用`__cxa_allocate_exception()`函数为异常和有效载荷分配内存。我们的有效载荷是 C++ `int`类型，通常大小为 4 字节。我们为大小创建一个常量无符号值，并调用该函数作为参数。函数类型和函数声明已经初始化，所以我们只需要创建一个`call`指令，如下所示：

```cpp
    Constant *PayloadSz =       ConstantInt::get(Int64Ty, 4, false);
    CallInst *EH = Builder.CreateCall(        AllocEHFty, AllocEHFn, {PayloadSz});
```

1.  接下来，我们将`PayloadVal`值存储到分配的内存中。为此，我们需要使用`ConstantInt::get()`函数创建一个 LLVM IR 常量。分配的内存指针是`i8*`类型，但要存储`i32`类型的值，我们需要创建一个`bitcast`指令来转换类型，如下所示：

```cpp
    Value *PayloadPtr =        Builder.CreateBitCast(EH, Int32PtrTy);
    Builder.CreateStore(        ConstantInt::get(Int32Ty, PayloadVal, true),
        PayloadPtr);
```

1.  最后，我们通过调用`__cxa_throw`函数引发异常。因为这个函数实际上引发的异常也在同一个函数中处理，所以我们需要使用`invoke`指令而不是`call`指令。与`call`指令不同，`invoke`指令结束一个基本块，因为它有两个后继基本块。在这里，它们是`UnreachableBB`和`LPadBB`基本块。如果函数没有引发异常，控制流将转移到`UnreachableBB`基本块。由于`__cxa_throw()`函数的设计，这永远不会发生。控制流将转移到`LPadBB`基本块以处理异常。这完成了`addThrow()`方法的实现，如下面的代码片段所示：

```cpp
    Builder.CreateInvoke(
        ThrowEHFty, ThrowEHFn, UnreachableBB, LPadBB,
        {EH, ConstantExpr::getBitCast(TypeInfo, 
         Int8PtrTy),
         ConstantPointerNull::get(Int8PtrTy)});
  }
```

接下来，我们添加生成处理异常的 IR 代码。

## 捕获异常

为了生成捕获异常的 IR 代码，我们添加了一个`addLandingPad()`方法。生成的 IR 从异常中提取类型信息。如果匹配 C++的`int`类型，那么异常将通过向控制台打印`Divide by zero!`并从函数中返回来处理。如果类型不匹配，我们简单地执行一个`resume`指令，将控制转回运行时。因为在调用层次结构中没有其他函数来处理这个异常，运行时将终止应用程序。这些是我们需要采取的步骤来生成捕获异常的 IR：

1.  在生成的 IR 中，我们需要从 C++运行时库中调用`__cxa_begin_catch()`和`_cxa_end_catch()`函数。为了打印错误消息，我们将从 C 运行时库生成一个调用`puts()`函数的调用，并且为了从异常中获取类型信息，我们必须生成一个调用`llvm.eh.typeid.for`指令。我们需要为所有这些都创建`FunctionType`和`Function`实例，并且利用我们的`createFunc()`方法来创建它们，如下所示：

```cpp
  void addLandingPad() {
    FunctionType *TypeIdFty; Function *TypeIdFn;
    createFunc(TypeIdFty, TypeIdFn,
               "llvm.eh.typeid.for", Int32Ty,
               {Int8PtrTy});
    FunctionType *BeginCatchFty; Function 
        *BeginCatchFn;
    createFunc(BeginCatchFty, BeginCatchFn,
               "__cxa_begin_catch", Int8PtrTy,
               {Int8PtrTy});
    FunctionType *EndCatchFty; Function *EndCatchFn;
    createFunc(EndCatchFty, EndCatchFn,
               "__cxa_end_catch", VoidTy);
    FunctionType *PutsFty; Function *PutsFn;
    createFunc(PutsFty, PutsFn, "puts", Int32Ty,
               {Int8PtrTy});
```

1.  `landingpad`指令是我们生成的第一条指令。结果类型是一个包含`i8*`和`i32`类型字段的结构。通过调用`StructType::get()`函数生成这个结构。我们处理 C++ `int`类型的异常，必须将其作为`landingpad`指令的一个子句添加。子句必须是`i8*`类型的常量，因此我们需要生成一个`bitcast`指令将`TypeInfo`值转换为这种类型。我们将指令返回的值存储在`Exc`变量中，以备后用，如下所示：

```cpp
    LandingPadInst *Exc = Builder.CreateLandingPad(
        StructType::get(Int8PtrTy, Int32Ty), 1, "exc");
    Exc->addClause(ConstantExpr::getBitCast(TypeInfo, 
                   Int8PtrTy));
```

1.  接下来，我们从返回值中提取类型选择器。通过调用`llvm.eh.typeid.for`内部函数，我们检索`TypeInfo`字段的类型 ID，表示 C++的`int`类型。有了这个 IR，我们现在已经生成了我们需要比较的两个值，以决定是否可以处理异常，如下面的代码片段所示：

```cpp
    Value *Sel = Builder.CreateExtractValue(Exc, {1},                  "exc.sel");
    CallInst *Id =
        Builder.CreateCall(TypeIdFty, TypeIdFn,
                           {ConstantExpr::getBitCast(
                               TypeInfo, Int8PtrTy)});
```

1.  为了生成比较的 IR，我们调用我们的`createICmpEq()`函数。这个函数还生成了两个基本块，我们将它们存储在`TrueDest`和`FalseDest`变量中，如下面的代码片段所示：

```cpp
    BasicBlock *TrueDest, *FalseDest;
    createICmpEq(Sel, Id, TrueDest, FalseDest, 
                 "match",
                 "resume");
```

1.  如果两个值不匹配，控制流将在`FalseDest`基本块继续。这个基本块只包含一个`resume`指令，将控制返回给 C++运行时。下面的代码片段中有示例：

```cpp
    Builder.SetInsertPoint(FalseDest);
    Builder.CreateResume(Exc);
```

1.  如果两个值相等，控制流将在`TrueDest`基本块继续。我们首先生成 IR 代码，从`landingpad`指令的返回值中提取指向异常的指针，存储在`Exc`变量中。然后，我们生成一个调用`__cxa_begin_catch()`函数的调用，将指向异常的指针作为参数传递。这表示异常开始被运行时处理，如下面的代码片段所示：

```cpp
    Builder.SetInsertPoint(TrueDest);
    Value *Ptr =
        Builder.CreateExtractValue(Exc, {0}, 
            "exc.ptr");
    Builder.CreateCall(BeginCatchFty, BeginCatchFn,
                       {Ptr});
```

1.  我们通过调用`puts()`函数来处理异常，向控制台打印一条消息。为此，我们首先通过调用`CreateGlobalStringPtr()`函数生成一个指向字符串的指针，然后将这个指针作为参数传递给生成的`puts()`函数调用，如下所示：

```cpp
    Value *MsgPtr = Builder.CreateGlobalStringPtr(
        "Divide by zero!", "msg", 0, M);
    Builder.CreateCall(PutsFty, PutsFn, {MsgPtr});
```

1.  这完成了异常处理，并生成了一个调用`__cxa_end_catch()`函数通知运行时的过程。最后，我们使用`ret`指令从函数中返回，如下所示：

```cpp
    Builder.CreateCall(EndCatchFty, EndCatchFn);
    Builder.CreateRet(Int32Zero);
  }
```

通过`addThrow()`和`addLandingPad()`函数，我们可以生成 IR 来引发异常和处理异常。我们仍然需要添加 IR 来检查除数是否为`0`，这是下一节的主题。

## 将异常处理代码集成到应用程序中

除法的 IR 是在`visit(BinaryOp&)`方法中生成的。我们首先生成 IR 来比较除数和`0`，而不仅仅是生成一个`sdiv`指令。如果除数是`0`，那么控制流将继续在一个基本块中引发异常。否则，控制流将在一个包含`sdiv`指令的基本块中继续。借助`createICmpEq()`和`addThrow()`函数，我们可以很容易地编写这个代码。

```cpp
    case BinaryOp::Div:
      BasicBlock *TrueDest, *FalseDest;
      createICmpEq(Right, Int32Zero, TrueDest,
                   FalseDest, "divbyzero", "notzero");
      Builder.SetInsertPoint(TrueDest);
      addThrow(42); // Arbitrary payload value.
      Builder.SetInsertPoint(FalseDest);
      V = Builder.CreateSDiv(Left, Right);
      break;
```

代码生成部分现在已经完成。要构建应用程序，您需要切换到`build`目录并运行`ninja`工具。

```cpp
$ ninja
```

构建完成后，您可以检查生成的 IR，例如使用`with a: 3/a`表达式。

```cpp
$ src/calc "with a: 3/a"
```

您将看到引发和捕获异常所需的额外 IR。

生成的 IR 现在依赖于 C++运行时。链接所需库的最简单方法是使用 clang++编译器。将用于表达式计算器的运行时函数的`rtcalc.c`文件重命名为`rtcalc.cpp`，并在文件中的每个函数前面添加`extern "C"`。然后我们可以使用`llc`工具将生成的 IR 转换为目标文件，并使用 clang++编译器创建可执行文件。

```cpp
$ src/calc "with a: 3/a" | llc -filetype obj -o exp.o
$ clang++ -o exp exp.o ../rtcalc.cpp
```

然后，我们可以使用不同的值运行生成的应用程序，如下所示：

```cpp
$ ./exp
Enter a value for a: 1
The result is: 3
$ ./exp
Enter a value for a: 0
Divide by zero!
```

在第二次运行中，输入为`0`，这引发了一个异常。这符合预期！

我们已经学会了如何引发和捕获异常。生成 IR 的代码可以用作其他编译器的蓝图。当然，所使用的类型信息和`catch`子句的数量取决于编译器的输入，但我们需要生成的 IR 仍然遵循本节中提出的模式。

添加元数据是向 LLVM 提供更多信息的一种方式。在下一节中，我们将添加类型元数据以支持 LLVM 优化器在某些情况下的使用。

# 为基于类型的别名分析生成元数据

两个指针可能指向同一内存单元，然后它们彼此别名。在 LLVM 模型中，内存没有类型，这使得优化器难以确定两个指针是否彼此别名。如果编译器可以证明两个指针不会别名，那么就有可能进行更多的优化。在下一节中，我们将更仔细地研究这个问题，并探讨如何添加额外的元数据将有所帮助，然后再实施这种方法。

## 理解需要额外元数据的原因

为了演示问题，让我们看一下以下函数：

```cpp
void doSomething(int *p, float *q) {
  *p = 42;
  *q = 3.1425;
} 
```

优化器无法确定`p`和`q`指针是否指向同一内存单元。在优化过程中，这是一个重要的分析，称为`p`和`q`指向同一内存单元，那么它们是别名。如果优化器可以证明这两个指针永远不会别名，这将提供额外的优化机会。例如，在`soSomething()`函数中，存储可以重新排序而不改变结果。

这取决于源语言的定义，一个类型的变量是否可以是不同类型的另一个变量的别名。请注意，语言也可能包含打破基于类型的别名假设的表达式，例如不相关类型之间的类型转换。

LLVM 开发人员选择的解决方案是向`load`和`store`指令添加元数据。元数据有两个目的，如下所述：

+   首先，它基于类型层次结构定义了类型层次结构，其中一个类型可能是另一个类型的别名

+   其次，它描述了`load`或`store`指令中的内存访问

让我们来看看 C 中的类型层次结构。每种类型层次结构都以根节点开头，可以是**命名**或**匿名**。LLVM 假设具有相同名称的根节点描述相同类型的层次结构。您可以在相同的 LLVM 模块中使用不同的类型层次结构，LLVM 会安全地假设这些类型可能会别名。在根节点下面，有标量类型的节点。聚合类型的节点不附加到根节点，但它们引用标量类型和其他聚合类型。Clang 为 C 定义了以下层次结构：

+   根节点称为`Simple C/C++ TBAA`。

+   在根节点下面是`char`类型的节点。这是 C 中的特殊类型，因为所有指针都可以转换为指向`char`的指针。

+   在`char`节点下面是其他标量类型的节点和一个名为`any pointer`的所有指针类型。

聚合类型被定义为一系列成员类型和偏移量。

这些元数据定义用于附加到`load`和`store`指令的访问标签。访问标签由三部分组成：基本类型、访问类型和偏移量。根据基本类型，访问标签描述内存访问的方式有两种可能，如下所述：

1.  如果基本类型是聚合类型，则访问标签描述了`struct`成员的内存访问，具有访问类型，并位于给定偏移量处。

1.  如果基本类型是标量类型，则访问类型必须与基本类型相同，偏移量必须为`0`。

有了这些定义，我们现在可以在访问标签上定义一个关系，用于评估两个指针是否可能别名。元组（基本类型，偏移量）的直接父节点由基本类型和偏移量确定，如下所示：

+   如果基本类型是标量类型且偏移量为 0，则直接父节点是（父类型，0），其中父类型是在类型层次结构中定义的父节点的类型。如果偏移量不为 0，则直接父节点未定义。

+   如果基本类型是聚合类型，则元组（基本类型，偏移量）的直接父节点是元组（新类型，新偏移量），其中新类型是在偏移量处的成员的类型。新偏移量是新类型的偏移量，调整为其新的起始位置。

这个关系的传递闭包是父关系。例如，（基本类型 1，访问类型 1，偏移 1）和（基本类型 2，访问类型 2，偏移 2）这两种内存访问类型可能会别名，如果（基本类型 1，偏移 1）和（基本类型 2，偏移 2）或者反之亦然在父关系中相关联。

让我们通过一个例子来说明：

```cpp
struct Point { float x, y; }
void func(struct Point *p, float *x, int *i, char *c) {
  p->x = 0; p->y = 0; *x = 0.0; *i = 0; *c = 0; 
}
```

使用前面对标量类型的内存访问标签定义，参数`i`的访问标签是（`int`，`int`，`0`），参数`c`的访问标签是（`char`，`char`，`0`）。在类型层次结构中，`int`类型的节点的父节点是`char`节点，因此（`int`，`0`）的直接父节点是（`char`，`0`），两个指针可能会别名。对于参数`x`和参数`c`也是如此。但是参数`x`和`i`没有关联，因此它们不会别名。`struct Point`的`y`成员的访问是（`Point`，`float`，`4`），4 是结构体中`y`成员的偏移量。因此（`Point`，`4`）的直接父节点是（`float`，`0`），因此`p->y`和`x`的访问可能会别名，并且根据相同的推理，也会与参数`c`别名。

要创建元数据，我们使用`llvm::MDBuilder`类，该类在`llvm/IR/MDBuilder.h`头文件中声明。数据本身存储在`llvm::MDNode`和`llvm::MDString`类的实例中。使用构建器类可以保护我们免受构造的内部细节的影响。

通过调用`createTBAARoot()`方法创建根节点，该方法需要类型层次结构的名称作为参数，并返回根节点。可以使用`createAnonymousTBAARoot()`方法创建匿名唯一根节点。

使用`createTBAAScalarTypeNode()`方法将标量类型添加到层次结构中，该方法以类型的名称和父节点作为参数。为聚合类型添加类型节点稍微复杂一些。`createTBAAStructTypeNode()`方法以类型的名称和字段列表作为参数。字段作为`std::pair<llvm::MDNode*, uint64_t>`实例给出。第一个元素表示成员的类型，第二个元素表示`struct`类型中的偏移量。

使用`createTBAAStructTagNode()`方法创建访问标签，该方法以基本类型、访问类型和偏移量作为参数。

最后，元数据必须附加到`load`或`store`指令上。`llvm::Instruction`类有一个`setMetadata()`方法，用于添加各种元数据。第一个参数必须是`llvm::LLVMContext::MD_tbaa`，第二个参数必须是访问标签。

掌握了这些知识，我们将在下一节为`tinylang`添加元数据。

## 为 tinylang 添加 TBAA 元数据

为了支持 TBAA，我们添加了一个新的`CGTBAA`类。这个类负责生成元数据节点。我们将它作为`CGModule`类的成员，称之为`TBAA`。每个`load`和`store`指令都可能被注释，我们也在`CGModule`类中放置了一个新的函数来实现这个目的。该函数尝试创建标签访问信息。如果成功，元数据将附加到指令上。这种设计还允许我们在不需要元数据的情况下关闭元数据生成，例如在关闭优化的构建中。代码如下所示：

```cpp
void CGModule::decorateInst(llvm::Instruction *Inst,
                            TypeDenoter *TyDe) {
  if (auto *N = TBAA.getAccessTagInfo(TyDe))
    Inst->setMetadata(llvm::LLVMContext::MD_tbaa, N);
}
```

我们将新的`CGTBAA`类的声明放入`include/tinylang/CodeGen/CGTBAA.h`头文件中，并将定义放入`lib/CodeGen/CGTBAA.cpp`文件中。除了**抽象语法树**（**AST**）定义之外，头文件还需要包括定义元数据节点和构建器的文件，如下面的代码片段所示：

```cpp
#include "tinylang/AST/AST.h"
#include "llvm/IR/MDBuilder.h"
#include "llvm/IR/Metadata.h"
```

`CGTBAA`类需要存储一些数据成员。因此，让我们逐步看看如何做到这一点，如下所示：

1.  首先，我们需要缓存类型层次结构的根，如下所示：

```cpp
 class CGTBAA {
  llvm::MDNode *Root;
```

1.  为了构造元数据节点，我们需要`MDBuilder`类的一个实例，如下所示：

```cpp
  llvm::MDBuilder MDHelper;
```

1.  最后，我们将为类型生成的元数据存储起来以便重用，如下所示：

```cpp
  llvm::DenseMap<TypeDenoter *, llvm::MDNode *> 
    MetadataCache;
// …
};
```

在定义构造所需的变量之后，我们现在添加了创建元数据所需的方法，如下所示：

1.  构造函数初始化数据成员，如下所示：

```cpp
CGTBAA::CGTBAA(llvm::LLVMContext &Ctx)
      : MDHelper(llvm::MDBuilder(Ctx)), Root(nullptr) {}
```

1.  我们懒惰地实例化类型层次结构的根，我们称之为`Simple tinylang TBAA`，如下面的代码片段所示：

```cpp
llvm::MDNode *CGTBAA::getRoot() {
  if (!Root)
    Root = MDHelper.createTBAARoot("Simple tinylang                                    TBAA");
  return Root;
}
```

1.  对于标量类型，我们使用`MDBuilder`类根据类型的名称创建元数据节点。新的元数据节点存储在缓存中，如下面的代码片段所示：

```cpp
llvm::MDNode *
CGTBAA::createScalarTypeNode(TypeDeclaration *Ty,
                             StringRef Name,
                             llvm::MDNode *Parent) {
  llvm::MDNode *N =
      MDHelper.createTBAAScalarTypeNode(Name, Parent);
  return MetadataCache[Ty] = N;
}
```

1.  创建记录的元数据的方法更加复杂，因为我们必须枚举记录的所有字段。代码如下所示：

```cpp
llvm::MDNode *CGTBAA::createStructTypeNode(
    TypeDeclaration *Ty, StringRef Name,
    llvm::ArrayRef<std::pair<llvm::MDNode *, 
        uint64_t>>
        Fields) {
  llvm::MDNode *N =
      MDHelper.createTBAAStructTypeNode(Name, Fields);
  return MetadataCache[Ty] = N;
}
```

1.  为了返回`tinylang`类型的元数据，我们需要创建类型层次结构。由于`tinylang`的类型系统非常受限，我们可以使用简单的方法。每个标量类型都映射到附加到根节点的唯一类型，我们将所有指针映射到单个类型。结构化类型然后引用这些节点。如果我们无法映射类型，我们将返回`nullptr`，如下所示：

```cpp
llvm::MDNode *CGTBAA::getTypeInfo(TypeDeclaration *Ty) {
  if (llvm::MDNode *N = MetadataCache[Ty])
    return N;
  if (auto *Pervasive =
          llvm::dyn_cast<PervasiveTypeDeclaration>(Ty)) {
    StringRef Name = Pervasive->getName();
    return createScalarTypeNode(Pervasive, Name, 
        getRoot());
  }
  if (auto *Pointer =
          llvm::dyn_cast<PointerTypeDeclaration>(Ty)) {
    StringRef Name = "any pointer";
    return createScalarTypeNode(Pointer, Name, 
        getRoot());
  }
  if (auto *Record =
          llvm::dyn_cast<RecordTypeDeclaration>(Ty)) {
    llvm::SmallVector<std::pair<llvm::MDNode *, 
        uint64_t>,
                      4>
        Fields;
    auto *Rec =
        llvm::cast<llvm::StructType>(              CGM.convertType(Record));
    const llvm::StructLayout *Layout =
        CGM.getModule()->getDataLayout()
            .getStructLayout(Rec);
    unsigned Idx = 0;
    for (const auto &F : Record->getFields()) {
      uint64_t Offset = Layout->getElementOffset(Idx);
      Fields.emplace_back(getTypeInfo(F.getType()), 
          Offset);
      ++Idx;
    }
    StringRef Name = CGM.mangleName(Record);
    return createStructTypeNode(Record, Name, Fields);
  }
  return nullptr;
}
```

1.  获取元数据的通用方法是`getAccessTagInfo()`。因为我们只需要查找指针类型，所以我们进行了检查。否则，我们返回`nullptr`，如下面的代码片段所示：

```cpp
llvm::MDNode *CGTBAA::getAccessTagInfo(TypeDenoter *TyDe) 
{
  if (auto *Pointer = llvm::dyn_cast<PointerType>(TyDe)) 
  {
    return getTypeInfo(Pointer->getTyDen());
  }
  return nullptr;
}
```

为了启用 TBAA 元数据的生成，我们现在只需要将元数据附加到我们生成的`load`和`store`指令上。例如，在`CGProcedure::writeVariable()`中，对全局变量的存储，使用`store`指令，如下所示：

```cpp
      Builder.CreateStore(Val, CGM.getGlobal(D));
```

为了装饰指令，我们需要用以下行替换前一行：

```cpp
      auto *Inst = Builder.CreateStore(Val,
                                       CGM.getGlobal(Decl));
      CGM.decorateInst(Inst, V->getTypeDenoter());
```

有了这些变化，我们已经完成了 TBAA 元数据的生成。

在下一节中，我们将讨论一个非常相似的主题：调试元数据的生成。

# 添加调试元数据

为了允许源级调试，我们必须添加调试信息。LLVM 中的调试信息支持使用调试元数据来描述源语言的类型和其他静态信息，并使用内在函数来跟踪变量值。LLVM 核心库在 Unix 系统上生成 DWARF 格式的调试信息，在 Windows 上生成**蛋白质数据银行**（**PDB**）格式。我们将在下一节中看一下一般的结构。

## 理解调试元数据的一般结构

为了描述静态结构，LLVM 使用元数据类似于基于类型的分析的元数据。静态结构描述文件、编译单元、函数、词法块和使用的数据类型。

我们使用的主要类是`llvm::DIBuilder`，我们需要使用`llvm/IR/DIBuilder`包含文件来获取类声明。这个构建器类提供了一个易于使用的接口来创建调试元数据。稍后，元数据要么添加到 LLVM 对象，比如全局变量，要么在调试内部使用。构建器类可以创建的重要元数据在这里列出：

+   `lvm::DIFile`：使用文件名和包含文件的目录的绝对路径来描述文件。您可以使用`createFile()`方法来创建它。一个文件可以包含主编译单元，也可以包含导入的声明。

+   `llvm::DICompileUnit`：用于描述当前编译单元。除其他内容外，您需要指定源语言、特定于编译器的生产者字符串，是否启用优化，以及编译单元所在的`DIFile`。您可以通过调用`createCompileUnit()`来创建它。

+   `llvm::DISubprogram`：描述一个函数。重要信息是作用域（通常是`DICompileUnit`或嵌套函数的`DISubprogram`）、函数的名称、函数的重整名和函数类型。它是通过调用`createFunction()`来创建的。

+   `llvm::DILexicalBlock`：描述了许多高级语言中找到的块作用域的词法块。您可以通过调用`createLexicalBlock()`来创建它。

LLVM 不对编译器翻译的语言做任何假设。因此，它对语言的数据类型没有任何信息。为了支持源级调试，特别是在调试器中显示变量值，也必须添加类型信息。这里列出了重要的构造：

+   `createBasicType()`函数返回一个指向`llvm::DIBasicType`类的指针，用于创建描述`tinylang`中的`INTEGER`或 C++中的`int`等基本类型的元数据。除了类型的名称，所需的参数是位大小和编码，例如，它是有符号还是无符号类型。

+   有几种方法可以构造复合数据类型的元数据，由`llvm::DIComposite`类表示。您可以使用`createArrayType()`、`createStructType()`、`createUnionType()`和`createVectorType()`函数来实例化`array`、`struct`、`union`和`vector`数据类型的元数据。这些函数需要您期望的参数，例如，数组类型的基本类型和订阅数量，或者`struct`类型的字段成员列表。

+   还有支持枚举、模板、类等的方法。

函数列表显示您必须将源语言的每个细节添加到调试信息中。假设您的`llvm::DIBuilder`类的实例称为`DBuilder`。进一步假设您在名为`File.mod`的文件中有一些`tinylang`源码，位于`/home/llvmuser`文件夹中。文件中有一个在*第 5 行*包含在*第 7 行*包含一个`VAR i:INTEGER`本地声明的`Func():INTEGER`函数。让我们从文件的信息开始创建这些元数据。您需要指定文件名和文件所在文件夹的绝对路径，如下面的代码片段所示：

```cpp
llvm::DIFile *DbgFile = DBuilder.createFile("File.mod",
                                            "/home/llvmuser"); 
```

文件是`tinylang`中的一个模块，因此是 LLVM 的编译单元。这携带了大量信息，如下面的代码片段所示：

```cpp
bool IsOptimized = false;
llvm::StringRef CUFlags;
unsigned ObjCRunTimeVersion = 0;
llvm::StringRef SplitName;
llvm::DICompileUnit::DebugEmissionKind EmissionKind =
      llvm::DICompileUnit::DebugEmissionKind::FullDebug;
llvm::DICompileUnit *DbgCU = DBuilder.createCompileUnit(
      llvm::dwarf::DW_LANG_Modula2, DbgFile, „tinylang",
      IsOptimized, CUFlags, ObjCRunTimeVersion, SplitName,
      EmissionKind);
```

调试器需要知道源语言。DWARF 标准定义了一个包含所有常见值的枚举。一个缺点是您不能简单地添加一个新的源语言。要做到这一点，您必须通过 DWARF 委员会创建一个请求。请注意，调试器和其他调试工具也需要支持新语言，仅仅向枚举添加一个新成员是不够的。

在许多情况下，选择一个接近您源语言的语言就足够了。在`tinylang`的情况下，这是 Modula-2，我们使用`DW_LANG_Modula2`进行语言识别。编译单元位于一个文件中，由我们之前创建的`DbgFile`变量标识。调试信息可以携带有关生产者的信息。这可以是编译器的名称和版本信息。在这里，我们只传递一个`tinylang`字符串。如果您不想添加这些信息，那么您可以简单地将一个空字符串作为参数。

下一组信息包括一个`IsOptimized`标志，应指示编译器是否已经打开了优化。通常，此标志是从`-O`命令行开关派生的。您可以使用`CUFlags`参数向调试器传递附加的参数设置。这里没有使用，我们传递一个空字符串。我们不使用 Objective-C，所以我们将`0`作为 Objective-C 运行时版本传递。通常，调试信息嵌入在我们正在创建的目标文件中。如果我们想要将调试信息写入一个单独的文件中，那么`SplitName`参数必须包含此文件的名称；否则，只需传递一个空字符串。最后，您可以定义应该发出的调试信息级别。默认设置是完整的调试信息，通过使用`FullDebug`枚举值表示。如果您只想发出行号，则可以选择`LineTablesOnly`值，或者选择`NoDebug`值以完全不发出调试信息。对于后者，最好一开始就不创建调试信息。

我们的最小化源码只使用`INTEGER`数据类型，这是一个带符号的 32 位值。为此类型创建元数据是直接的，可以在以下代码片段中看到：

```cpp
llvm::DIBasicType *DbgIntTy =
                       DBuilder.createBasicType("INTEGER", 32,
                                  llvm::dwarf::DW_ATE_signed);
```

要为函数创建调试元数据，我们首先必须为签名创建一个类型，然后为函数本身创建元数据。这类似于为函数创建 IR。函数的签名是一个数组，其中包含源顺序中所有参数的类型以及函数的返回类型作为索引`0`处的第一个元素。通常，此数组是动态构建的。在我们的情况下，我们也可以静态构建元数据。这对于内部函数（例如模块初始化）非常有用。通常，这些函数的参数是已知的，并且编译器编写者可以硬编码它们。代码如下所示：

```cpp
llvm::Metadata *DbgSigTy = {DbgIntTy};
llvm::DITypeRefArray DbgParamsTy =
                      DBuilder.getOrCreateTypeArray(DbgSigTy);
llvm::DISubroutineType *DbgFuncTy =
                   DBuilder.createSubroutineType(DbgParamsTy);
```

我们的函数具有`INTEGER`返回类型和没有其他参数，因此`DbgSigTy`数组仅包含指向此类型元数据的指针。这个静态数组被转换成类型数组，然后用于创建函数的类型。

函数本身需要更多的数据，如下所示：

```cpp
unsigned LineNo = 5;
unsigned ScopeLine = 5;
llvm::DISubprogram *DbgFunc = DBuilder.createFunction(
      DbgCU, "Func", "_t4File4Func", DbgFile, LineNo,
      DbgFuncTy, ScopeLine, 
      llvm::DISubprogram::FlagPrivate,
      llvm::DISubprogram::SPFlagLocalToUnit);
```

函数属于编译单元，在我们的案例中存储在`DbgCU`变量中。我们需要在源文件中指定函数的名称，即`Func`，并且搅乱的名称存储在目标文件中。这些信息帮助调试器在以后定位函数的机器代码。根据`tinylang`的规则，搅乱的名称是`_t4File4Func`。我们还需要指定包含函数的文件。

这一开始可能听起来令人惊讶，但想想 C 和 C++中的包含机制：一个函数可以存储在不同的文件中，然后在主编译单元中用`#include`包含。在这里，情况并非如此，我们使用与编译单元相同的文件。接下来，传递函数的行号和函数类型。函数的行号可能不是函数的词法范围开始的行号。在这种情况下，您可以指定不同的`ScopeLine`。函数还有保护，我们在这里用`FlagPrivate`值指定为私有函数。其他可能的值是`FlagPublic`和`FlagProtected`，分别表示公共和受保护的函数。

除了保护级别，这里还可以指定其他标志。例如，`FlagVirtual`表示虚函数，`FlagNoReturn`表示函数不会返回给调用者。您可以在`llvm/include/llvm/IR/DebugInfoFlags.def`的 LLVM 包含文件中找到所有可能的值的完整列表。最后，还可以指定特定于函数的标志。最常用的是`SPFlagLocalToUnit`值，表示该函数是本编译单元的本地函数。还经常使用的是`MainSubprogram`值，表示该函数是应用程序的主函数。您还可以在前面提到的 LLVM 包含文件中找到所有可能的值。

到目前为止，我们只创建了引用静态数据的元数据。变量是动态的，我们将在下一节中探讨如何将静态元数据附加到 IR 代码以访问变量。

## 跟踪变量及其值

要有用，上一节中描述的类型元数据需要与源程序的变量关联起来。对于全局变量，这相当容易。`llvm::DIBuilder`类的`createGlobalVariableExpression()`函数创建了描述全局变量的元数据。这包括源中变量的名称、搅乱的名称、源文件等。LLVM IR 中的全局变量由`GlobalVariable`类的实例表示。该类有一个`addDebugInfo()`方法，它将从`createGlobalVariableExpression()`返回的元数据节点与全局变量关联起来。

对于局部变量，我们需要采取另一种方法。LLVM IR 不知道表示局部变量的类；它只知道值。LLVM 社区开发的解决方案是在函数的 IR 代码中插入对内部函数的调用。内部函数是 LLVM 知道的函数，因此可以对其进行一些魔术操作。在大多数情况下，内部函数不会导致机器级别的子例程调用。在这里，函数调用是一个方便的工具，用于将元数据与值关联起来。

调试元数据最重要的内部函数是`llvm.dbg.declare`和`llvm.dbg.value`。前者用于声明局部变量的地址，而后者在将局部变量设置为新值时调用。

未来的 LLVM 版本将用 llvm.dbg.addr 内部函数替换 llvm.dbg.declare

`llvm.dbg.declare`内部函数做出了一个非常强烈的假设：调用中描述的变量的地址在函数的整个生命周期内都是有效的。这个假设使得在优化期间保留调试元数据变得非常困难，因为真实的存储地址可能会发生变化。为了解决这个问题，设计了一个名为`llvm.dbg.addr`的新内部函数。这个内部函数接受与`llvm.dbg.declare`相同的参数，但语义不那么严格。它仍然描述了局部变量的地址，前端应该生成对它的调用。

在优化期间，传递可以用（可能是多个）对`llvm.dbg.value`和/或`llvm.dbg.addr`的调用来替换这个内部函数，以保留调试信息。

当`llvm.dbg.addr`的工作完成后，`llvm.dbg.declare`内部函数将被弃用并最终移除。

它是如何工作的？LLVM IR 表示和通过`llvm::DIBuilder`类进行编程创建有些不同，因此我们需要同时看两者。继续上一节的例子，我们使用`alloca`指令在`Func`函数内为`i`变量分配局部存储空间，如下所示：

```cpp
@i = alloca i32
```

之后，我们添加一个对`llvm.dbg.declare`内部函数的调用，如下所示：

```cpp
call void @llvm.dbg.declare(metadata i32* %i,
                        metadata !1, metadata 
                        !DIExpression())
```

第一个参数是局部变量的地址。第二个参数是描述局部变量的元数据，由`llvm::DIBuilder`类的`createAutoVariable()`或`createParameterVariable()`调用创建。第三个参数描述一个地址表达式，稍后我会解释。

让我们实现 IR 创建。您可以使用`llvm::IRBuilder<>`类的`CreateAlloca()`方法为`@i`局部变量分配存储空间，如下所示：

```cpp
llvm::Type *IntTy = llvm::Type::getInt32Ty(LLVMCtx);
llvm::Value *Val = Builder.CreateAlloca(IntTy, nullptr, "i");
```

`LLVMCtx`变量是使用的上下文类，`Builder`是`llvm::IRBuilder<>`类的实例。

局部变量也需要用元数据描述，如下所示：

```cpp
llvm::DILocalVariable *DbgLocalVar =
 DBuilder.createAutoVariable(DbgFunc, "i", DbgFile,
                             7, DbgIntTy);
```

使用上一节中的值，我们指定变量是`DbgFunc`函数的一部分，名称为`i`，在由`DbgFile`命名的文件中定义，位于*第 7 行*，类型为`DbgIntTy`。

最后，我们使用`llvm.dbg.declare`内部函数将调试元数据与变量的地址关联起来。使用`llvm::DIBuilder`可以屏蔽掉添加调用的所有细节。代码如下所示：

```cpp
llvm::DILocation *DbgLoc =
                llvm::DILocation::get(LLVMCtx, 7, 5, 
                                      DbgFunc);
DBuilder.insertDeclare(Val, DbgLocalVar,
                       DBuilder.createExpression(), DbgLoc,
                       Val.getParent());
```

同样，我们需要为变量指定源位置。`llvm::DILocation`的实例是一个容器，用于保存与作用域关联的位置的行和列。`insertDeclare()`方法向 LLVM IR 添加对内部函数的调用。作为参数，它需要变量的地址（存储在`Val`中）和变量的调试元数据（存储在`DbgValVar`中）。我们还传递了一个空地址表达式和之前创建的调试位置。与普通指令一样，我们需要指定将调用插入到哪个基本块中。如果我们指定了一个基本块，那么调用将插入到末尾。或者，我们可以指定一个指令，调用将插入到该指令之前。我们有指向`alloca`指令的指针，这是我们插入到基本块中的最后一个指令。因此，我们使用这个基本块，调用将在`alloca`指令之后追加。

如果局部变量的值发生变化，那么必须在 IR 中添加对`llvm.dbg.value`的调用。您可以使用`llvm::DIBuilder`的`insertValue()`方法来实现。对于`llvm.dbg.addr`也是类似的。不同之处在于，现在指定的是变量的新值，而不是变量的地址。

在我们为函数实现 IR 生成时，我们使用了一种先进的算法，主要使用值并避免为局部变量分配存储空间。为了添加调试信息，这意味着我们在 Clang 生成的 IR 中使用`llvm.dbg.value`的频率要比你看到的要高得多。

如果变量没有专用存储空间，而是属于较大的聚合类型，我们可以怎么办？可能出现这种情况的一种情况是使用嵌套函数。为了实现对调用者堆栈帧的访问，您需要将所有使用的变量收集到一个结构中，并将指向此记录的指针传递给被调用的函数。在被调用的函数内部，您可以将调用者的变量视为函数的本地变量。不同的是，这些变量现在是聚合的一部分。

在调用`llvm.dbg.declare`时，如果调试元数据描述了第一个参数指向的整个内存，则使用空表达式。如果它只描述内存的一部分，则需要添加一个表达式，指示元数据适用于内存的哪一部分。在嵌套帧的情况下，需要计算到帧的偏移量。您需要访问`DataLayout`实例，可以从您正在创建 IR 代码的 LLVM 模块中获取。如果`llvm::Module`实例命名为`Mod`，则包含嵌套帧结构的变量命名为`Frame`，类型为`llvm::StructType`，并且您可以访问帧的第三个成员。然后，您可以得到成员的偏移量，如下面的代码片段所示：

```cpp
const llvm::DataLayout &DL = Mod->getDataLayout();
uint64_t Ofs = DL.getStructLayout(Frame)
               ->getElementOffset(3);
```

表达式是从一系列操作中创建的。为了访问帧的第三个成员，调试器需要将偏移量添加到基指针。您需要创建一个数组和这个信息，例如：

```cpp
llvm::SmallVector<int64_t, 2> AddrOps;
AddrOps.push_back(llvm::dwarf::DW_OP_plus_uconst);
AddrOps.push_back(Offset);
```

从这个数组中，您可以创建一个表达式，然后将其传递给`llvm.dbg.declare`，而不是空表达式，如下所示：

```cpp
llvm::DIExpression *Expr = DBuilder.createExpression(AddrOps);
```

您不仅限于此偏移操作。DWARF 知道许多不同的操作符，您可以创建相当复杂的表达式。您可以在`llvm/include/llvm/BinaryFormat/Dwarf.def` LLVM 包含文件中找到操作符的完整列表。

现在，您可以为变量创建调试信息。为了使调试器能够跟踪源代码中的控制流，您还需要提供行号信息，这是下一节的主题。

## 添加行号

调试器允许程序员逐行浏览应用程序。为此，调试器需要知道哪些机器指令属于源代码中的哪一行。LLVM 允许在每条指令中添加源位置。在上一节中，我们创建了`llvm::DILocation`类型的位置信息。调试位置具有比行、列和作用域更多的信息。如果需要，可以指定此行内联的作用域。还可以指示此调试位置属于隐式代码，即前端生成的但不在源代码中的代码。

在将调试位置附加到指令之前，我们必须将调试位置包装在`llvm::DebugLoc`对象中。为此，您只需将从`llvm::DILocation`类获得的位置信息传递给`llvm::DebugLoc`构造函数。通过这种包装，LLVM 可以跟踪位置信息。虽然源代码中的位置显然不会改变，但是源级语句或表达式的生成机器代码可能会在优化期间被丢弃。封装有助于处理这些可能的更改。

将行号信息添加到生成的指令中主要是从 AST 中检索行号信息，并将其添加到生成的指令中。`llvm::Instruction`类有`setDebugLoc()`方法，它将位置信息附加到指令上。

在下一节中，我们将向我们的`tinylang`编译器添加调试信息的生成。

## 为 tinylang 添加调试支持

我们将调试元数据的生成封装在新的`CGDebugInfo`类中。我们将声明放入`tinylang/CodeGen/CGDebugInfo.h`头文件中，将定义放入`tinylang/CodeGen/CGDebugInfo.cpp`文件中。

`CGDebugInfo`类有五个重要成员。我们需要模块的代码生成器`CGM`的引用，因为我们需要将 AST 表示的类型转换为 LLVM 类型。当然，我们还需要`llvm::DIBuilder`类的实例`DBuilder`，就像前面的部分一样。还需要编译单元的指针，并将其存储在名为`CU`的成员中。

为了避免重复创建类型的调试元数据，我们还添加了一个用于缓存这些信息的映射。成员称为`TypeCache`。最后，我们需要一种管理作用域信息的方法，为此我们基于`llvm::SmallVector<>`类创建了一个名为`ScopeStack`的堆栈。因此，我们有以下代码：

```cpp
  CGModule &CGM;
  llvm::DIBuilder DBuilder;
  llvm::DICompileUnit *CU;
  llvm::DenseMap<TypeDeclaration *, llvm::DIType *>
      TypeCache;
  llvm::SmallVector<llvm::DIScope *, 4> ScopeStack;
```

`CGDebugInfo`类的以下方法都使用了这些成员：

1.  首先，我们需要在构造函数中创建编译单元。我们还在这里创建包含编译单元的文件。稍后，我们可以通过`CU`成员引用该文件。构造函数的代码如下所示：

```cpp
CGDebugInfo::CGDebugInfo(CGModule &CGM)
    : CGM(CGM), DBuilder(*CGM.getModule()) {
  llvm::SmallString<128> Path(
      CGM.getASTCtx().getFilename());
  llvm::sys::fs::make_absolute(Path);
  llvm::DIFile *File = DBuilder.createFile(
      llvm::sys::path::filename(Path),
      llvm::sys::path::parent_path(Path));
  bool IsOptimized = false;
  unsigned ObjCRunTimeVersion = 0;
  llvm::DICompileUnit::DebugEmissionKind EmissionKind =
      llvm::DICompileUnit::DebugEmissionKind::FullDebug;
  CU = DBuilder.createCompileUnit(
      llvm::dwarf::DW_LANG_Modula2, File, "tinylang",
      IsOptimized, StringRef(), ObjCRunTimeVersion,
      StringRef(), EmissionKind);
}
```

1.  我们经常需要提供行号。这可以从源管理器位置派生，大多数 AST 节点都可以使用。源管理器可以将其转换为行号，如下所示：

```cpp
unsigned CGDebugInfo::getLineNumber(SMLoc Loc) {
  return CGM.getASTCtx().getSourceMgr().FindLineNumber(
      Loc);
}
```

1.  作用域的信息保存在堆栈上。我们需要方法来打开和关闭作用域，并检索当前作用域。编译单元是全局作用域，我们会自动添加它，如下所示：

```cpp
llvm::DIScope *CGDebugInfo::getScope() {
  if (ScopeStack.empty())
    openScope(CU->getFile());
  return ScopeStack.back();
}
void CGDebugInfo::openScope(llvm::DIScope *Scope) {
  ScopeStack.push_back(Scope);
}
void CGDebugInfo::closeScope() {
  ScopeStack.pop_back();
}
```

1.  我们为需要转换的类型的每个类别创建一个方法。`getPervasiveType()`方法为基本类型创建调试元数据。请注意以下代码片段中对编码参数的使用，声明`INTEGER`类型为有符号类型，`BOOLEAN`类型编码为布尔类型：

```cpp
llvm::DIType *
CGDebugInfo::getPervasiveType(TypeDeclaration *Ty) {
  if (Ty->getName() == "INTEGER") {
    return DBuilder.createBasicType(
        Ty->getName(), 64, llvm::dwarf::DW_ATE_signed);
  }
  if (Ty->getName() == "BOOLEAN") {
    return DBuilder.createBasicType(
        Ty->getName(), 1, 
            llvm::dwarf::DW_ATE_boolean);
  }
  llvm::report_fatal_error(
      "Unsupported pervasive type");
}
```

1.  如果类型名称只是重命名，那么我们将其映射到类型定义。在这里，我们需要首次使用作用域和行号信息，如下所示：

```cpp
llvm::DIType *
CGDebugInfo::getAliasType(AliasTypeDeclaration *Ty) {
  return DBuilder.createTypedef(
      getType(Ty->getType()), Ty->getName(),
      CU->getFile(), getLineNumber(Ty->getLocation()),
      getScope());
}
```

1.  为数组创建调试信息需要指定大小和对齐方式。我们从`DataLayout`类中检索这些数据。我们还需要指定数组的索引范围。我们可以使用以下代码来实现：

```cpp
llvm::DIType *
CGDebugInfo::getArrayType(ArrayTypeDeclaration *Ty) {
  auto *ATy =
      llvm::cast<llvm::ArrayType>(CGM.convertType(Ty));
  const llvm::DataLayout &DL =
      CGM.getModule()->getDataLayout();
  uint64_t NumElements = Ty->getUpperIndex();
  llvm::SmallVector<llvm::Metadata *, 4> Subscripts;
  Subscripts.push_back(
      DBuilder.getOrCreateSubrange(0, NumElements));
  return DBuilder.createArrayType(
      DL.getTypeSizeInBits(ATy) * 8,
      DL.getABITypeAlignment(ATy),
      getType(Ty->getType()),
      DBuilder.getOrCreateArray(Subscripts));
}
```

1.  使用所有这些单个方法，我们创建一个中心方法来为类型创建元数据。这个元数据还负责缓存数据。代码可以在以下代码片段中看到：

```cpp
llvm::DIType *
CGDebugInfo::getType(TypeDeclaration *Ty) {
  if (llvm::DIType *T = TypeCache[Ty])
    return T;
  if (llvm::isa<PervasiveTypeDeclaration>(Ty))
    return TypeCache[Ty] = getPervasiveType(Ty);
  else if (auto *AliasTy =
               llvm::dyn_cast<AliasTypeDeclaration>(Ty))
    return TypeCache[Ty] = getAliasType(AliasTy);
  else if (auto *ArrayTy =
               llvm::dyn_cast<ArrayTypeDeclaration>(Ty))
    return TypeCache[Ty] = getArrayType(ArrayTy);
  else if (auto *RecordTy =
               llvm ::dyn_cast<RecordTypeDeclaration>(
                   Ty))
    return TypeCache[Ty] = getRecordType(RecordTy);
  llvm::report_fatal_error("Unsupported type");
  return nullptr;
}
```

1.  我们还需要添加一个方法来发出全局变量的元数据，如下所示：

```cpp
void CGDebugInfo::emitGlobalVariable(
    VariableDeclaration *Decl,
    llvm::GlobalVariable *V) {
  llvm::DIGlobalVariableExpression *GV =
      DBuilder.createGlobalVariableExpression(
          getScope(), Decl->getName(), V->getName(),
          CU->getFile(),
          getLineNumber(Decl->getLocation()),
          getType(Decl->getType()), false);
  V->addDebugInfo(GV);
}
```

1.  要为过程发出调试信息，我们首先需要为过程类型创建元数据。为此，我们需要参数类型的列表，返回类型是第一个条目。如果过程没有返回类型，则使用一个称为`void`的未指定类型，就像 C 语言一样。如果参数是引用，则需要添加引用类型；否则，我们将类型添加到列表中。代码如下所示：

```cpp
llvm::DISubroutineType *
CGDebugInfo::getType(ProcedureDeclaration *P) {
  llvm::SmallVector<llvm::Metadata *, 4> Types;
  const llvm::DataLayout &DL =
      CGM.getModule()->getDataLayout();
  // Return type at index 0
  if (P->getRetType())
    Types.push_back(getType(P->getRetType()));
  else
    Types.push_back(
        DBuilder.createUnspecifiedType("void"));
  for (const auto *FP : P->getFormalParams()) {
    llvm::DIType *PT = getType(FP->getType());
    if (FP->isVar()) {
      llvm::Type *PTy = CGM.convertType(FP->getType());
      PT = DBuilder.createReferenceType(
          llvm::dwarf::DW_TAG_reference_type, PT,
          DL.getTypeSizeInBits(PTy) * 8,
          DL.getABITypeAlignment(PTy));
    }
    Types.push_back(PT);
  }
  return DBuilder.createSubroutineType(
      DBuilder.getOrCreateTypeArray(Types));
}
```

1.  对于过程本身，我们现在可以使用上一步创建的过程类型创建调试信息。过程还会打开一个新的作用域，因此我们将该过程推送到作用域堆栈上。我们还将 LLVM 函数对象与新的调试信息关联起来，如下所示：

```cpp
void CGDebugInfo::emitProcedure(
    ProcedureDeclaration *Decl, llvm::Function *Fn) {
  llvm::DISubroutineType *SubT = getType(Decl);
  llvm::DISubprogram *Sub = DBuilder.createFunction(
      getScope(), Decl->getName(), Fn->getName(),
      CU->getFile(), getLineNumber(Decl->getLocation()),
      SubT, getLineNumber(Decl->getLocation()),
      llvm::DINode::FlagPrototyped,
      llvm::DISubprogram::SPFlagDefinition);
  openScope(Sub);
  Fn->setSubprogram(Sub);
}
```

1.  当到达过程的结束时，我们必须通知构建器完成该过程的调试信息的构建。我们还需要从作用域堆栈中移除该过程。我们可以使用以下代码来实现：

```cpp
void CGDebugInfo::emitProcedureEnd(
    ProcedureDeclaration *Decl, llvm::Function *Fn) {
  if (Fn && Fn->getSubprogram())
    DBuilder.finalizeSubprogram(Fn->getSubprogram());
  closeScope();
}
```

1.  最后，当我们完成添加调试信息时，我们需要将`finalize()`方法添加到构建器上。然后验证生成的调试信息。这是开发过程中的重要步骤，因为它可以帮助您找到错误生成的元数据。代码可以在以下代码片段中看到：

```cpp
void CGDebugInfo::finalize() { DBuilder.finalize(); }
```

只有在用户请求时才应生成调试信息。我们将需要一个新的命令行开关来实现这一点。我们将把这个开关添加到`CGModule`类的文件中，并且在这个类内部也会使用它，如下所示：

```cpp
static llvm::cl::opt<bool>
    Debug("g", llvm::cl::desc("Generate debug information"),
          llvm::cl::init(false));
```

`CGModule`类持有`std::unique_ptr<CGDebugInfo>`类的实例。指针在构造函数中初始化，关于命令行开关的设置如下：

```cpp
  if (Debug)
    DebugInfo.reset(new CGDebugInfo(*this));
```

在 getter 方法中，我们返回指针，就像这样：

```cpp
CGDebugInfo *getDbgInfo() {
  return DebugInfo.get();
}
```

生成调试元数据时的常见模式是检索指针并检查其是否有效。例如，在创建全局变量后，我们以这种方式添加调试信息：

```cpp
VariableDeclaration *Var = …;
llvm::GlobalVariable *V = …;
if (CGDebugInfo *Dbg = getDbgInfo())
  Dbg->emitGlobalVariable(Var, V);
```

为了添加行号信息，我们需要在`CGDebugInfo`类中添加一个`getDebugLoc()`转换方法，将 AST 中的位置信息转换为调试元数据，如下所示：

```cpp
llvm::DebugLoc CGDebugInfo::getDebugLoc(SMLoc Loc) {
  std::pair<unsigned, unsigned> LineAndCol =
      CGM.getASTCtx().getSourceMgr().getLineAndColumn(Loc);
  llvm::DILocation *DILoc = llvm::DILocation::get(
      CGM.getLLVMCtx(), LineAndCol.first, LineAndCol.second,
      getCU());
  return llvm::DebugLoc(DILoc);
}
```

然后可以调用`CGModule`类中的实用函数来将行号信息添加到指令中，如下所示：

```cpp
void CGModule::applyLocation(llvm::Instruction *Inst,
                             llvm::SMLoc Loc) {
  if (CGDebugInfo *Dbg = getDbgInfo())
    Inst->setDebugLoc(Dbg->getDebugLoc(Loc));
}
```

通过这种方式，您可以为自己的编译器添加调试信息。

# 总结

在本章中，您了解了在 LLVM 中如何抛出和捕获异常，以及需要生成哪些 IR 代码来利用此功能。为了增强 IR 的范围，您学习了如何将各种元数据附加到指令上。基于类型的别名的元数据为 LLVM 优化器提供了额外的信息，并有助于进行某些优化以生成更好的机器代码。用户总是欣赏使用源级调试器的可能性，通过向 IR 代码添加调试信息，您可以提供编译器的这一重要功能。

优化 IR 代码是 LLVM 的核心任务。在下一章中，我们将学习通道管理器的工作原理以及如何影响通道管理器管理的优化流水线。


# 第八章：优化 IR

LLVM 使用一系列 Passes 来优化**中间表示**（**IR**）。Pass 对 IR 单元执行操作，可以是函数或模块。操作可以是转换，以定义的方式更改 IR，也可以是分析，收集依赖关系等信息。一系列 Passes 称为**Pass 管道**。Pass 管理器在我们的编译器生成的 IR 上执行 Pass 管道。因此，我们需要了解 Pass 管理器的作用以及如何构建 Pass 管道。编程语言的语义可能需要开发新的 Passes，并且我们必须将这些 Passes 添加到管道中。

在本章中，我们将涵盖以下主题：

+   介绍 LLVM Pass 管理器

+   使用新 Pass 管理器实现 Pass

+   为旧 Pass 管理器使用 Pass

+   向您的编译器添加优化管道

在本章结束时，您将了解如何开发新的 Pass 以及如何将其添加到 Pass 管道中。您还将获得设置自己编译器中 Pass 管道所需的知识。

# 技术要求

本章的源代码可在[`github.com/PacktPublishing/Learn-LLVM-12/tree/master/Chapter08`](https://github.com/PacktPublishing/Learn-LLVM-12/tree/master/Chapter08)找到

您可以在[`bit.ly/3nllhED`](https://bit.ly/3nllhED)找到代码的实际应用视频

# 介绍 LLVM Pass 管理器

LLVM 核心库优化编译器创建的 IR 并将其转换为目标代码。这项巨大的任务被分解为称为**Passes**的单独步骤。这些 Passes 需要按正确的顺序执行，这是 Pass 管理器的目标。

但是为什么不硬编码 Passes 的顺序呢？嗯，您的编译器的用户通常期望您的编译器提供不同级别的优化。开发人员更喜欢在开发时间内更快的编译速度而不是优化。最终应用程序应尽可能快地运行，您的编译器应能够执行复杂的优化，接受更长的编译时间。不同级别的优化意味着需要执行不同数量的优化 Passes。作为编译器编写者，您可能希望提供自己的 Passes，以利用您对源语言的了解。例如，您可能希望用内联 IR 或者可能的话用该函数的计算结果替换已知的库函数。对于 C，这样的 Pass 是 LLVM 核心库的一部分，但对于其他语言，您需要自己提供。并且引入自己的 Passes，您可能需要重新排序或添加一些 Passes。例如，如果您知道您的 Pass 的操作使一些 IR 代码不可达，则还应在您自己的 Pass 之后运行死代码删除 Pass。Pass 管理器帮助您组织这些要求。

Pass 通常根据其工作范围进行分类：

+   *函数 Pass*接受单个函数作为输入，并仅对该函数执行其工作。

+   *模块 Pass*接受整个模块作为输入。这样的 Pass 在给定模块上执行其工作，并且可以用于模块内的程序内操作。

+   *调用图* Pass 按自底向上的顺序遍历调用图的函数。

除了 IR 代码之外，Pass 还可能消耗、产生或使一些分析结果无效。进行了许多不同的分析；例如，别名分析或支配树的构建。支配树有助于将不变的代码移出循环，因此只有在支配树创建后才能运行执行此类转换的 Pass。另一个 Pass 可能执行一个转换，这可能会使现有的支配树无效。

在幕后，Pass 管理器确保以下内容：

+   分析结果在 Passes 之间共享。这要求您跟踪哪个 Pass 需要哪个分析，以及每个分析的状态。目标是避免不必要的分析重新计算，并尽快释放分析结果所占用的内存。

+   Pass 以管道方式执行。例如，如果应该按顺序执行多个函数 Pass，那么 Pass 管理器将在第一个函数上运行每个函数 Pass。然后它将在第二个函数上运行所有函数 Pass，依此类推。这里的基本思想是改善缓存行为，因为编译器仅对有限的数据集（即一个 IR 函数）执行转换，然后转移到下一个有限的数据集。

LLVM 中有两个 Pass 管理器，如下：

+   旧的（或传统的）Pass 管理器

+   新的 Pass 管理器

未来属于新的 Pass 管理器，但过渡尚未完成。一些关键的 Pass，如目标代码发射，尚未迁移到新的 Pass 管理器，因此了解两个 Pass 管理器非常重要。

旧的 Pass 管理器需要一个 Pass 从一个基类继承，例如，从`llvm::FunctionPass`类继承一个函数 Pass。相比之下，新的 Pass 管理器依赖于基于概念的方法，只需要从特殊的`llvm::PassInfo<>` mixin 类继承。旧的 Pass 管理器中 Passes 之间的依赖关系没有明确表达。在新的 Pass 管理器中，需要明确编码。新的 Pass 管理器还采用了不同的分析处理方法，并允许通过命令行上的文本表示来指定优化管道。一些 LLVM 用户报告说，仅通过从旧的 Pass 管理器切换到新的 Pass 管理器，编译时间就可以减少高达 10%，这是使用新的 Pass 管理器的非常有说服力的论点。

首先，我们将为新的 Pass 管理器实现一个 Pass，并探索如何将其添加到优化管道中。稍后，我们将看看如何在旧的 Pass 管理器中使用 Pass。

# 使用新的 Pass 管理器实现 Pass

Pass 可以对 LLVM IR 执行任意复杂的转换。为了说明添加新 Pass 的机制，我们的新 Pass 只计算 IR 指令和基本块的数量。我们将 Pass 命名为`countir`。将 Pass 添加到 LLVM 源树或作为独立的 Pass 略有不同，因此我们将在以下部分都进行。

## 将 Pass 添加到 LLVM 源树

让我们从将新 Pass 添加到 LLVM 源开始。如果我们以后想要在 LLVM 树中发布新的 Pass，这是正确的方法。

对 LLVM IR 执行转换的 Pass 的源代码位于`llvm-project/llvm/lib/Transforms`文件夹中，头文件位于`llvm-project/llvm/include/llvm/Transforms`文件夹中。由于 Pass 太多，它们被分类到适合它们的类别的子文件夹中。

对于我们的新 Pass，在两个位置都创建一个名为`CountIR`的新文件夹。首先，让我们实现`CountIR.h`头文件：

1.  像往常一样，我们需要确保文件可以被多次包含。此外，我们需要包含 Pass 管理器的定义：

```cpp
#ifndef LLVM_TRANSFORMS_COUNTIR_COUNTIR_H
#define LLVM_TRANSFORMS_COUNTIR_COUNTIR_H
#include "llvm/IR/PassManager.h"
```

1.  因为我们在 LLVM 源代码中，所以我们将新的`CountIR`类放入`llvm`命名空间中。该类继承自`PassInfoMixin`模板。该模板仅添加了一些样板代码，例如`name()`方法。它不用于确定 Pass 的类型。

```cpp
namespace llvm {
class CountIRPass : public PassInfoMixin<CountIRPass> {
```

1.  在运行时，将调用任务的`run()`方法。`run()`方法的签名确定 Pass 的类型。这里，第一个参数是对`Function`类型的引用，因此这是一个函数 Pass：

```cpp
public:
  PreservedAnalyses run(Function &F,
                        FunctionAnalysisManager &AM);
```

1.  最后，我们需要关闭类、命名空间和头文件保护：

```cpp
};
} // namespace llvm
#endif
```

当然，我们的新 Pass 的定义是如此简单，因为我们只执行了一个微不足道的任务。

让我们继续在`CountIIR.cpp`文件中实现 Pass。LLVM 支持在调试模式下收集有关 Pass 的统计信息。对于我们的 Pass，我们将利用这个基础设施。

1.  我们首先包含我们自己的头文件和所需的 LLVM 头文件：

```cpp
#include "llvm/Transforms/CountIR/CountIR.h"
#include "llvm/ADT/Statistic.h"
#include "llvm/Support/Debug.h"
```

1.  为了缩短源代码，我们告诉编译器我们正在使用`llvm`命名空间：

```cpp
using namespace llvm;
```

1.  LLVM 的内置调试基础设施要求我们定义一个调试类型，即一个字符串。这个字符串稍后将显示在打印的统计信息中：

```cpp
#define DEBUG_TYPE "countir"
```

1.  我们使用`STATISTIC`宏定义了两个计数器变量。第一个参数是计数器变量的名称，第二个参数是将在统计中打印的文本：

```cpp
STATISTIC(NumOfInst, "Number of instructions.");
STATISTIC(NumOfBB, "Number of basic blocks.");
```

1.  在`run()`方法中，我们循环遍历函数的所有基本块，并递增相应的计数器。我们对基本块的所有指令也是一样的。为了防止编译器警告我们关于未使用的变量，我们插入了对`I`变量的无操作使用。因为我们只计数而不改变 IR，我们告诉调用者我们已经保留了所有现有的分析：

```cpp
PreservedAnalyses
CountIRPass::run(Function &F,
                 FunctionAnalysisManager &AM) {
  for (BasicBlock &BB : F) {
    ++NumOfBB;
    for (Instruction &I : BB) {
      (void)I;
      ++NumOfInst;
    }
  }
  return PreservedAnalyses::all();
}
```

到目前为止，我们已经实现了新 Pass 的功能。我们稍后将重用这个实现来进行一个树外的 Pass。对于 LLVM 树内的解决方案，我们必须更改 LLVM 中的几个文件来宣布新 Pass 的存在：

1.  首先，我们需要在源文件夹中添加一个`CMakeLists.txt`文件。这个文件包含了一个新的 LLVM 库名`LLVMCountIR`的构建指令。新库需要链接 LLVM 的`Support`组件，因为我们使用了调试和统计基础设施，以及 LLVM 的`Core`组件，其中包含了 LLVM IR 的定义：

```cpp
add_llvm_component_library(LLVMCountIR
  CountIR.cpp
  LINK_COMPONENTS Core Support )
```

1.  为了使这个新库成为构建的一部分，我们需要将该文件夹添加到父文件夹的`CMakeLists.txt`文件中，即`llvm-project/llvm/lib/Transforms/CMakeList.txt`文件。然后，添加以下行：

```cpp
add_subdirectory(CountIR)
```

1.  `PassBuilder`类需要知道我们的新 Pass。为此，我们在`llvm-project/llvm/lib/Passes/PassBuilder.cpp`文件的`include`部分添加以下行：

```cpp
#include "llvm/Transforms/CountIR/CountIR.h"
```

1.  作为最后一步，我们需要更新 Pass 注册表，这在`llvm-project/llvm/lib/Passes/PassRegistry.def`文件中。查找定义函数 Pass 的部分，例如通过搜索`FUNCTION_PASS`宏。在这个部分中，添加以下行：

```cpp
FUNCTION_PASS("countir", CountIRPass())
```

1.  我们现在已经做出了所有必要的更改。按照*第一章*中的构建说明，*使用 CMake 构建*部分，重新编译 LLVM。要测试新的 Pass，我们将以下 IR 代码存储在我们的`build`文件夹中的`demo.ll`文件中。代码有两个函数，总共三条指令和两个基本块：

```cpp
define internal i32 @func() {
  ret i32 0
}
define dso_local i32 @main() {
  %1 = call i32 @func()
  ret i32 %1
}
```

1.  我们可以使用`opt`实用程序来使用新的 Pass。要运行新的 Pass，我们将利用`--passes="countir"`选项。要获得统计输出，我们需要添加`--stats`选项。因为我们不需要生成的位码，我们还指定了`--disable-output`选项：

```cpp
$ bin/opt --disable-output --passes="countir" –-stats demo.ll
===--------------------------------------------------------===
                   ... Statistics Collected ...
===--------------------------------------------------------===
2 countir - Number of basic blocks.
3 countir - Number of instructions. 
```

1.  我们运行我们的新 Pass，输出符合我们的期望。我们已经成功扩展了 LLVM！

运行单个 Pass 有助于调试。使用`--passes`选项，您不仅可以命名单个 Pass，还可以描述整个流水线。例如，优化级别 2 的默认流水线被命名为`default<O2>`。您可以在默认流水线之前使用`--passes="module(countir),default<O2>"`参数运行`countir` Pass。这样的流水线描述中的 Pass 名称必须是相同类型的。默认流水线是一个模块 Pass，我们的`countir` Pass 是一个函数 Pass。要从这两者创建一个模块流水线，首先我们必须创建一个包含`countir` Pass 的模块 Pass。这是通过`module(countir)`来完成的。您可以通过以逗号分隔的列表指定更多的函数 Passes 添加到这个模块 Pass 中。同样，模块 Passes 也可以组合。为了研究这一点的影响，您可以使用`inline`和`countir` Passes：以不同的顺序运行它们，或者作为模块 Pass，将给出不同的统计输出。

将新的 Pass 添加到 LLVM 源代码树中是有意义的，如果您计划将您的 Pass 作为 LLVM 的一部分发布。如果您不打算这样做，或者希望独立于 LLVM 分发您的 Pass，那么您可以创建一个 Pass 插件。在下一节中，我们将查看如何执行这些步骤。

## 作为插件添加新的 Pass

为了将新的 Pass 作为插件提供，我们将创建一个使用 LLVM 的新项目：

1.  让我们从在我们的源文件夹中创建一个名为`countirpass`的新文件夹开始。该文件夹将具有以下结构和文件：

```cpp
|-- CMakeLists.txt
|-- include
|   `-- CountIR.h
|-- lib
    |-- CMakeLists.txt
    `-- CountIR.cpp
```

1.  请注意，我们已经重用了上一节的功能，只是做了一些小的调整。`CountIR.h`头文件现在位于不同的位置，所以我们改变了用作守卫的符号的名称。我们也不再使用`llvm`命名空间，因为我们现在不在 LLVM 源代码之内。由于这个改变，头文件变成了以下内容：

```cpp
#ifndef COUNTIR_H
#define COUNTIR_H
#include "llvm/IR/PassManager.h"
class CountIRPass
    : public llvm::PassInfoMixin<CountIRPass> {
public:
  llvm::PreservedAnalyses
  run(llvm::Function &F,
      llvm::FunctionAnalysisManager &AM);
};
#endif
```

1.  我们可以从上一节复制`CountIR.cpp`实现文件。这里也需要做一些小的改动。因为我们的头文件路径已经改变，所以我们需要用以下内容替换`include`指令：

```cpp
#include "CountIR.h"
```

1.  我们还需要在 Pass builder 中注册新的 Pass。这是在插件加载时发生的。Pass 插件管理器调用特殊函数`llvmGetPassPluginInfo()`，进行注册。对于这个实现，我们需要两个额外的`include`文件：

```cpp
#include "llvm/Passes/PassBuilder.h"
#include "llvm/Passes/PassPlugin.h"
```

用户可以使用`--passes`选项在命令行上指定要运行的 Passes。`PassBuilder`类从字符串中提取 Pass 名称。为了创建命名 Pass 的实例，`PassBuilder`类维护一个回调函数列表。基本上，回调函数会以 Pass 名称和 Pass 管理器作为参数进行调用。如果回调函数知道 Pass 名称，那么它会将这个 Pass 的实例添加到 Pass 管理器中。对于我们的 Pass，我们需要提供这样一个回调函数：

```cpp
bool PipelineParsingCB(
    StringRef Name, FunctionPassManager &FPM,
    ArrayRef<PassBuilder::PipelineElement>) {
  if (Name == "countir") {
    FPM.addPass(CountIRPass());
    return true;
  }
  return false;
}
```

1.  当然，我们需要将这个函数注册为`PassBuilder`实例。插件加载后，将为此目的调用注册回调。我们的注册函数如下：

```cpp
void RegisterCB(PassBuilder &PB) {
  PB.registerPipelineParsingCallback(PipelineParsingCB);
}
```

1.  最后，每个插件都需要提供上述`llvmGetPassPluginInfo()`函数。这个函数返回一个结构，包含四个元素：我们的插件使用的 LLVM 插件 API 版本、名称、插件的版本号和注册回调。插件 API 要求函数使用`extern "C"`约定。这是为了避免 C++名称混淆的问题。这个函数非常简单：

```cpp
extern "C" ::llvm::PassPluginLibraryInfo LLVM_ATTRIBUTE_WEAK
llvmGetPassPluginInfo() {
  return {LLVM_PLUGIN_API_VERSION, "CountIR", "v0.1",
          RegisterCB};
}
```

为每个回调实现一个单独的函数有助于我们理解正在发生的事情。如果您的插件提供了多个 Passes，那么您可以扩展`RegisterCB`回调函数以注册所有 Passes。通常，您可以找到一个非常紧凑的方法。以下的`llvmGetPassPluginInfo()`函数将`PipelineParsingCB()`、`RegisterCB()`和之前的`llvmGetPassPluginInfo()`合并为一个函数。它通过使用 lambda 函数来实现：

```cpp
extern "C" ::llvm::PassPluginLibraryInfo LLVM_ATTRIBUTE_WEAK
llvmGetPassPluginInfo() {
  return {LLVM_PLUGIN_API_VERSION, "CountIR", "v0.1",
          [](PassBuilder &PB) {
            PB.registerPipelineParsingCallback(
                [](StringRef Name, FunctionPassManager                        &FPM,
                ArrayRef<PassBuilder::PipelineElement>)  
                {
                  if (Name == "countir") {
                    FPM.addPass(CountIRPass());
                    return true;
                  }
                  return false;
                });
          }};
}
```

1.  现在，我们只需要添加构建文件。`lib/CMakeLists.txt`文件只包含一个命令来编译源文件。LLVM 特定的命令`add_llvm_library()`确保使用用于构建 LLVM 的相同编译器标志：

```cpp
add_llvm_library(CountIR MODULE CountIR.cpp)
```

顶层的`CMakeLists.txt`文件更加复杂。

1.  像往常一样，我们设置所需的 CMake 版本和项目名称。此外，我们将`LLVM_EXPORTED_SYMBOL_FILE`变量设置为`ON`。这对于使插件在 Windows 上工作是必要的：

```cpp
cmake_minimum_required(VERSION 3.4.3)
project(countirpass)
set(LLVM_EXPORTED_SYMBOL_FILE ON)
```

1.  接下来，我们寻找 LLVM 安装。我们还将在控制台上打印有关找到的版本的信息：

```cpp
find_package(LLVM REQUIRED CONFIG)
message(STATUS "Found LLVM ${LLVM_PACKAGE_VERSION}")
message(STATUS "Using LLVMConfig.cmake in: ${LLVM_DIR}")
```

1.  现在，我们可以将 LLVM 的`cmake`文件夹添加到搜索路径中。我们包括 LLVM 特定的文件`ChooseMSVCCRT`和`AddLLVM`，它们提供了额外的命令：

```cpp
list(APPEND CMAKE_MODULE_PATH ${LLVM_DIR})
include(ChooseMSVCCRT)
include(AddLLVM)
```

1.  编译器需要了解所需的定义和 LLVM 路径：

```cpp
include_directories("${LLVM_INCLUDE_DIR}")
add_definitions("${LLVM_DEFINITIONS}")
link_directories("${LLVM_LIBRARY_DIR}")
```

1.  最后，我们添加自己的包含和源文件夹：

```cpp
include_directories(BEFORE include)
add_subdirectory(lib)
```

1.  在实现了所有必需的文件之后，我们现在可以在`countirpass`文件夹旁边创建`build`文件夹。首先，切换到构建目录并创建构建文件：

```cpp
$ cmake –G Ninja ../countirpass
```

1.  然后，您可以编译插件，如下所示：

```cpp
$ ninja
```

1.  您可以使用`opt`实用程序使用插件，`opt`实用程序会生成输入文件的优化版本。要使用插件，您需要指定一个额外的参数来加载插件：

```cpp
$ opt --load-pass-plugin=lib/CountIR.so --passes="countir"\
  --disable-output –-stats demo.ll
```

输出与以前版本相同。恭喜，Pass 插件有效！

到目前为止，我们只为新 Pass 管理器创建了一个 Pass。在下一节中，我们还将扩展旧 Pass 管理器的 Pass。

# 调整 Pass 以与旧 Pass 管理器一起使用

未来属于新 Pass 管理器，为旧 Pass 管理器专门开发新 Pass 是没有意义的。然而，在进行过渡阶段期间，如果一个 Pass 可以与两个 Pass 管理器一起工作，那将是有用的，因为 LLVM 中的大多数 Pass 已经这样做了。

旧 Pass 管理器需要一个从特定基类派生的 Pass。例如，函数 Pass 必须从`FunctionPass`基类派生。还有更多的不同之处。Pass 管理器运行的方法被命名为`runOnFunction()`，还必须提供 Pass 的`ID`。我们在这里遵循的策略是创建一个单独的类，可以与旧 Pass 管理器一起使用，并以一种可以与两个 Pass 管理器一起使用的方式重构源代码。

我们将 Pass 插件用作基础。在`include/CountIR.h`头文件中，我们添加一个新的类定义，如下所示：

1.  新类需要从`FunctionPass`类派生，因此我们包含一个额外的头文件来获取类定义：

```cpp
#include "llvm/Pass.h"
```

1.  我们将新类命名为`CountIRLegacyPass`。该类需要内部 LLVM 机制的 ID，并用其初始化父类：

```cpp
class CountIRLegacyPass : public llvm::FunctionPass {
public:
  static char ID;
  CountIRLegacyPass() : llvm::FunctionPass(ID) {}
```

1.  为了实现 Pass 功能，必须重写两个函数。`runOnFunction()`方法用于每个 LLVM IR 函数，并实现我们的计数功能。`getAnalysisUsage()`方法用于宣布所有分析结果都已保存：

```cpp
  bool runOnFunction(llvm::Function &F) override;
  void getAnalysisUsage(llvm::AnalysisUsage &AU) const     override;
};
```

1.  现在头文件的更改已经完成，我们可以增强`lib/CountIR.cpp`文件中的实现。为了重用计数功能，我们将源代码移入一个新的函数：

```cpp
void runCounting(Function &F) {
  for (BasicBlock &BB : F) {
    ++NumOfBB;
    for (Instruction &I : BB) {
      (void)I;
      ++NumOfInst;
    }
  }
}
```

1.  新 Pass 管理器的方法需要更新，以便使用新功能：

```cpp
PreservedAnalyses
CountIRPass::run(Function &F, FunctionAnalysisManager &AM) {
  runCounting(F);
  return PreservedAnalyses::all();
}
```

1.  以同样的方式，我们实现了旧 Pass 管理器的方法。通过返回`false`值，我们表明 IR 没有发生变化：

```cpp
bool CountIRLegacyPass::runOnFunction(Function &F) {
  runCounting(F);
  return false;
}
```

1.  为了保留现有的分析结果，必须以以下方式实现`getAnalysisUsage()`方法。这类似于新 Pass 管理器中`PreservedAnalyses::all()`的返回值。如果不实现此方法，则默认情况下会丢弃所有分析结果：

```cpp
void CountIRLegacyPass::getAnalysisUsage(
    AnalysisUsage &AU) const {
  AU.setPreservesAll();
}
```

1.  `ID`字段可以用任意值初始化，因为 LLVM 使用字段的地址。通常值为`0`，所以我们也使用它：

```cpp
char CountIRLegacyPass::ID = 0;
```

1.  现在只缺少 Pass 注册。要注册新 Pass，我们需要提供`RegisterPass<>`模板的静态实例。第一个参数是调用新 Pass 的命令行选项的名称。第二个参数是 Pass 的名称，用于在调用`-help`选项时向用户提供信息等：

```cpp
static RegisterPass<CountIRLegacyPass>
    X("countir", "CountIR Pass");
```

1.  这些变化足以让我们在旧 Pass 管理器和新 Pass 管理器下调用我们的新 Pass。为了测试这个添加，切换回`build`文件夹并编译 Pass：

```cpp
$ ninja
```

1.  为了在旧 Pass 管理器中加载插件，我们需要使用`--load`选项。我们的新 Pass 是使用`--countir`选项调用的：

```cpp
$ opt --load lib/CountIR.so --countir –-stats\
  --disable-output demo.ll
```

提示

请还要检查，在上一节的命令行中，使用新 Pass 管理器调用我们的 Pass 是否仍然正常工作！

能够使用 LLVM 提供的工具运行我们的新 Pass 是很好的，但最终，我们希望在我们的编译器内运行它。在下一节中，我们将探讨如何设置优化流水线以及如何自定义它。

# 向您的编译器添加优化流水线

我们的`tinylang`编译器，在前几章中开发，对创建的 IR 代码不进行任何优化。在接下来的章节中，我们将向编译器添加一个优化流水线，以实现这一点。

## 使用新 Pass 管理器创建优化流水线

优化流水线设置的核心是`PassBuilder`类。这个类知道所有注册的 Pass，并可以根据文本描述构建 Pass 流水线。我们使用这个类来从命令行给出的描述创建 Pass 流水线，或者使用基于请求的优化级别的默认流水线。我们还支持使用 Pass 插件，例如我们在上一节中讨论的`countir` Pass 插件。通过这样做，我们模仿了`opt`工具的部分功能，并且还使用了类似的命令行选项名称。

`PassBuilder`类填充了一个`ModulePassManager`类的实例，这是用于保存构建的 Pass 流水线并实际运行它的 Pass 管理器。代码生成 Pass 仍然使用旧 Pass 管理器；因此，我们必须保留旧 Pass 管理器以实现这一目的。

对于实现，我们扩展了我们的`tinylang`编译器中的`tools/driver/Driver.cpp`文件：

1.  我们使用新的类，因此我们首先添加新的`include`文件。`llvm/Passes/PassBuilder.h`文件提供了`PassBuilder`类的定义。`llvm/Passes/PassPlugin.h`文件是插件支持所需的。最后，`llvm/Analysis/TargetTransformInfo.h`文件提供了一个将 IR 级别转换与特定目标信息连接起来的 Pass：

```cpp
#include "llvm/Passes/PassBuilder.h"
#include "llvm/Passes/PassPlugin.h"
#include "llvm/Analysis/TargetTransformInfo.h"
```

1.  为了使用新 Pass 管理器的某些功能，我们添加了三个命令行选项，使用与`opt`工具相同的名称。`--passes`选项允许 Pass 流水线的文本规范，`--load-pass-plugin`选项允许使用 Pass 插件。如果给出`--debug-pass-manager`选项，则 Pass 管理器会打印有关执行的 Pass 的信息：

```cpp
static cl::opt<bool>
    DebugPM("debug-pass-manager", cl::Hidden,
            cl::desc("Print PM debugging 
                     information"));
static cl::opt<std::string> PassPipeline(
    "passes",
    cl::desc("A description of the pass pipeline"));
static cl::list<std::string> PassPlugins(
    "load-pass-plugin",
    cl::desc("Load passes from plugin library"));
```

1.  用户通过优化级别影响 Pass 流水线的构建。`PassBuilder`类支持六个不同的优化级别：一个无优化级别，三个用于优化速度的级别，以及两个用于减小大小的级别。我们在一个命令行选项中捕获所有这些级别：

```cpp
static cl::opt<signed char> OptLevel(
    cl::desc("Setting the optimization level:"),
    cl::ZeroOrMore,
    cl::values(
        clEnumValN(3, "O", "Equivalent to -O3"),
        clEnumValN(0, "O0", "Optimization level 0"),
        clEnumValN(1, "O1", "Optimization level 1"),
        clEnumValN(2, "O2", "Optimization level 2"),
        clEnumValN(3, "O3", "Optimization level 3"),
        clEnumValN(-1, "Os",
                   "Like -O2 with extra 
                    optimizations "
                   "for size"),
        clEnumValN(
            -2, "Oz",
            "Like -Os but reduces code size further")),
    cl::init(0));
```

1.  LLVM 的插件机制支持静态插件注册表，在项目配置期间创建。为了利用这个注册表，我们包括`llvm/Support/Extension.def`数据库文件来创建返回插件信息的函数的原型：

```cpp
#define HANDLE_EXTENSION(Ext)                          \
  llvm::PassPluginLibraryInfo get##Ext##PluginInfo();
#include "llvm/Support/Extension.def"
```

1.  我们用新版本替换现有的`emit()`函数。我们在函数顶部声明所需的`PassBuilder`实例：

```cpp
bool emit(StringRef Argv0, llvm::Module *M,
          llvm::TargetMachine *TM,
          StringRef InputFilename) {
  PassBuilder PB(TM);
```

1.  为了实现对命令行上给出的 Pass 插件的支持，我们循环遍历用户给出的插件库列表，并尝试加载插件。如果失败，我们会发出错误消息；否则，我们注册 Passes：

```cpp
  for (auto &PluginFN : PassPlugins) {
    auto PassPlugin = PassPlugin::Load(PluginFN);
    if (!PassPlugin) {
      WithColor::error(errs(), Argv0)
          << "Failed to load passes from '" 
          << PluginFN
          << "'. Request ignored.\n";
      continue;
    }
    PassPlugin->registerPassBuilderCallbacks(PB);
  }
```

1.  静态插件注册表中的信息类似地用于向我们的`PassBuilder`实例注册这些插件：

```cpp
#define HANDLE_EXTENSION(Ext)                          \
  get##Ext##PluginInfo().RegisterPassBuilderCallbacks( \
      PB);
#include "llvm/Support/Extension.def"
```

1.  我们需要声明不同分析管理器的变量。唯一的参数是调试标志：

```cpp
  LoopAnalysisManager LAM(DebugPM);
  FunctionAnalysisManager FAM(DebugPM);
  CGSCCAnalysisManager CGAM(DebugPM);
  ModuleAnalysisManager MAM(DebugPM);
```

1.  接下来，我们通过在`PassBuilder`实例上调用相应的`register`方法来填充分析管理器。通过这个调用，分析管理器填充了默认的分析 Passes，并且还运行注册回调。我们还确保函数分析管理器使用默认的别名分析管道，并且所有分析管理器都知道彼此：

```cpp
  FAM.registerPass(
      [&] { return PB.buildDefaultAAPipeline(); });
  PB.registerModuleAnalyses(MAM);
  PB.registerCGSCCAnalyses(CGAM);
  PB.registerFunctionAnalyses(FAM);
  PB.registerLoopAnalyses(LAM);
  PB.crossRegisterProxies(LAM, FAM, CGAM, MAM);
```

1.  `MPM`模块 Pass 管理器保存我们构建的 Pass 管道。该实例使用调试标志进行初始化：

```cpp
  ModulePassManager MPM(DebugPM);
```

1.  我们实现了两种不同的方法来填充模块 Pass 管理器与 Pass 管道。如果用户在命令行上提供了 Pass 管道，也就是说，他们使用了`--passes`选项，那么我们将使用这个作为 Pass 管道：

```cpp
  if (!PassPipeline.empty()) {
    if (auto Err = PB.parsePassPipeline(
            MPM, PassPipeline)) {
      WithColor::error(errs(), Argv0)
          << toString(std::move(Err)) << "\n";
      return false;
    }
  }
```

1.  否则，我们使用选择的优化级别来确定要构建的 Pass 管道。默认 Pass 管道的名称是`default`，它将优化级别作为参数：

```cpp
  else {
    StringRef DefaultPass;
    switch (OptLevel) {
    case 0: DefaultPass = "default<O0>"; break;
    case 1: DefaultPass = "default<O1>"; break;
    case 2: DefaultPass = "default<O2>"; break;
    case 3: DefaultPass = "default<O3>"; break;
    case -1: DefaultPass = "default<Os>"; break;
    case -2: DefaultPass = "default<Oz>"; break;
    }
    if (auto Err = PB.parsePassPipeline(
            MPM, DefaultPass)) {
      WithColor::error(errs(), Argv0)
          << toString(std::move(Err)) << "\n";
      return false;
    }
  }
```

1.  现在设置了在 IR 代码上运行转换的 Pass 管道。我们需要打开一个文件来写入结果。系统汇编器和 LLVM IR 输出都是基于文本的，因此我们应该为它们都设置`OF_Text`标志：

```cpp
  std::error_code EC;
  sys::fs::OpenFlags OpenFlags = sys::fs::OF_None;
  CodeGenFileType FileType = codegen::getFileType();
  if (FileType == CGFT_AssemblyFile)
    OpenFlags |= sys::fs::OF_Text;
  auto Out = std::make_unique<llvm::ToolOutputFile>(
      outputFilename(InputFilename), EC, OpenFlags);
  if (EC) {
    WithColor::error(errs(), Argv0)
        << EC.message() << '\n';
    return false;
  }
```

1.  对于代码生成，我们必须使用旧的 Pass 管理器。我们只需声明`CodeGenPM`实例并添加使目标特定信息在 IR 转换级别可用的 Pass：

```cpp
  legacy::PassManager CodeGenPM;
  CodeGenPM.add(createTargetTransformInfoWrapperPass(
      TM->getTargetIRAnalysis()));
```

1.  为了输出 LLVM IR，我们添加了一个只打印 IR 到流中的 Pass：

```cpp
  if (FileType == CGFT_AssemblyFile && EmitLLVM) {
    CodeGenPM.add(createPrintModulePass(Out->os()));
  }
```

1.  否则，我们让`TargetMachine`实例添加所需的代码生成 Passes，由我们作为参数传递的`FileType`值指导：

```cpp
  else {
    if (TM->addPassesToEmitFile(CodeGenPM, Out->os(),
                                nullptr, FileType)) {
      WithColor::error()
          << "No support for file type\n";
      return false;
    }
  }
```

1.  经过所有这些准备，我们现在准备执行 Passes。首先，我们在 IR 模块上运行优化管道。接下来，运行代码生成 Passes。当然，在所有这些工作之后，我们希望保留输出文件：

```cpp
  MPM.run(*M, MAM);
  CodeGenPM.run(*M);
  Out->keep();
  return true;
}
```

1.  这是很多代码，但很简单。当然，我们还必须更新`tools/driver/CMakeLists.txt`构建文件中的依赖项。除了添加目标组件外，我们还从 LLVM 中添加所有转换和代码生成组件。名称大致类似于源代码所在的目录名称。在配置过程中，组件名称将被转换为链接库名称：

```cpp
set(LLVM_LINK_COMPONENTS ${LLVM_TARGETS_TO_BUILD}
  AggressiveInstCombine Analysis AsmParser
  BitWriter CodeGen Core Coroutines IPO IRReader
  InstCombine Instrumentation MC ObjCARCOpts Remarks
  ScalarOpts Support Target TransformUtils Vectorize
  Passes)
```

1.  我们的编译器驱动程序支持插件，并宣布以下支持：

```cpp
add_tinylang_tool(tinylang Driver.cpp SUPPORT_PLUGINS)
```

1.  与以前一样，我们必须链接到我们自己的库：

```cpp
target_link_libraries(tinylang
  PRIVATE tinylangBasic tinylangCodeGen
  tinylangLexer tinylangParser tinylangSema)
```

这些是源代码和构建系统的必要补充。

1.  要构建扩展的编译器，请进入您的`build`目录并输入以下内容：

```cpp
$ ninja
```

构建系统的文件更改会自动检测到，并且在编译和链接我们更改的源代码之前运行`cmake`。如果您需要重新运行配置步骤，请按照*第二章*中的说明，*LLVM 源代码漫游*，*编译 tinylang 应用程序*部分中的说明进行操作。

由于我们已经使用`opt`工具的选项作为蓝图，您应该尝试使用加载 Pass 插件并运行 Pass 的选项来运行`tinylang`，就像我们在前面的部分中所做的那样。

通过当前的实现，我们可以运行默认的 Pass 管道或自己构建一个。后者非常灵活，但在几乎所有情况下都是过度的。默认管道非常适用于类似 C 的语言。缺少的是扩展 Pass 管道的方法。在下一节中，我们将解释如何实现这一点。

## 扩展 Pass 管道

在上一节中，我们使用`PassBuilder`类从用户提供的描述或预定义名称创建 Pass 管道。现在，我们将看另一种自定义 Pass 管道的方法：使用**扩展点**。

在构建 Pass 管道期间，Pass 构建器允许您添加用户贡献的 Passes。这些地方被称为扩展点。存在许多扩展点，例如以下：

+   管道开始扩展点允许您在管道开始时添加 Passes。

+   窥孔扩展点允许您在指令组合器 Pass 的每个实例之后添加 Passes。

还存在其他扩展点。要使用扩展点，您需要注册一个回调。在构建 Pass 管道期间，您的回调在定义的扩展点处运行，并可以向给定的 Pass 管理器添加 Pass。

要为管道开始扩展点注册回调，您需要调用`PassBuilder`类的`registerPipelineStartEPCallback()`方法。例如，要将我们的`CountIRPass` Pass 添加到管道的开头，您需要将 Pass 调整为使用`createModuleToFunctionPassAdaptor()`模板函数作为模块 Pass，并将 Pass 添加到模块 Pass 管理器中：

```cpp
PB.registerPipelineStartEPCallback(
    [](ModulePassManager &MPM) {
        MPM.addPass(
             createModuleToFunctionPassAdaptor(
                 CountIRPass());
    });
```

您可以在创建管道之前的任何时间点将此片段添加到 Pass 管道设置代码中，也就是在调用`parsePassPipeline()`方法之前。

在上一节所做的工作的自然扩展是让用户通过命令行传递管道描述。`opt`工具也允许这样做。让我们为管道开始扩展点做这个。首先，我们将以下代码添加到`tools/driver/Driver.cpp`文件中：

1.  我们为用户添加了一个新的命令行，用于指定管道描述。同样，我们从`opt`工具中获取选项名称：

```cpp
static cl::opt<std::string> PipelineStartEPPipeline(
    "passes-ep-pipeline-start",
    cl::desc("Pipeline start extension point));
```

1.  使用 lambda 函数作为回调是最方便的方式。为了解析管道描述，我们调用`PassBuilder`实例的`parsePassPipeline()`方法。Passes 被添加到`PM` Pass 管理器，并作为参数传递给 lambda 函数。如果出现错误，我们会打印错误消息而不会停止应用程序。您可以在调用`crossRegisterProxies()`方法之后添加此片段：

```cpp
  PB.registerPipelineStartEPCallback(
      &PB, Argv0 {
        if (auto Err = PB.parsePassPipeline(
                PM, PipelineStartEPPipeline)) {
          WithColor::error(errs(), Argv0)
              << "Could not parse pipeline "
              << PipelineStartEPPipeline.ArgStr 
              << ": "
              << toString(std::move(Err)) << "\n";
        }
      });
```

提示

为了允许用户在每个扩展点添加 Passes，您需要为每个扩展点添加前面的代码片段。

1.  现在是尝试不同`pass manager`选项的好时机。使用`--debug-pass-manager`选项，您可以跟踪执行 Passes 的顺序。您可以使用`--print-before-all`和`--print-after-all`选项在每次调用 Pass 之前或之后打印 IR。如果您创建自己的 Pass 管道，那么您可以在感兴趣的点插入`print` Pass。例如，尝试`--passes="print,inline,print"`选项。您还可以使用`print` Pass 来探索各种扩展点。

```cpp
    PassBuilder::OptimizationLevel Olevel = …;
    if (OLevel == PassBuilder::OptimizationLevel::O0)
      MPM.addPass(AlwaysInlinerPass());
    else
      MPM = PB.buildPerModuleDefaultPipeline(OLevel,           DebugPM);
```

当然，也可以以这种方式向 Pass 管理器添加多个 Pass。`PassBuilder`类在构建 Pass 管道期间还使用`addPass()`方法。

LLVM 12 中的新功能-运行扩展点回调

因为 Pass 管道在优化级别`O0`下没有填充，所以注册的扩展点不会被调用。如果您使用扩展点来注册应该在`O0`级别运行的 Passes，这将是有问题的。在 LLVM 12 中，可以调用新的`runRegisteredEPCallbacks()`方法来运行已注册的扩展点回调，从而使 Pass 管理器仅填充通过扩展点注册的 Passes。

通过将优化管道添加到`tinylang`中，您可以创建一个类似 clang 的优化编译器。LLVM 社区致力于在每个发布版本中改进优化和优化管道。因此，默认情况下很少不使用默认管道。通常情况下，会添加新的 Passes 来实现编程语言的某些语义。

# 总结

在本章中，您学会了如何为 LLVM 创建新的 Pass。您使用 Pass 管道描述和扩展点运行了 Pass。您通过构建和执行类似 clang 的 Pass 管道来扩展了您的编译器，将`tinylang`变成了一个优化编译器。Pass 管道允许您在扩展点添加 Passes，并且您学会了如何在这些点注册 Passes。这使您能够使用自己开发的 Passes 或现有 Passes 扩展优化管道。

在下一章中，我们将探讨 LLVM 如何从优化的 IR 生成机器指令。
