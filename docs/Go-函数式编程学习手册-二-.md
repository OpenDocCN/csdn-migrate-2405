# Go 函数式编程学习手册（二）

> 原文：[`zh.annas-archive.org/md5/5FC2C8948F5CEA11C4D0D293DBBCA039`](https://zh.annas-archive.org/md5/5FC2C8948F5CEA11C4D0D293DBBCA039)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第三章：使用高阶函数

我们经常遇到诸如“只是好奇，将纯函数式编程概念应用于命令式语言的好处是什么（除了使代码难以阅读）？”这样的问题。

在本章中，我们将使用高阶函数来解决这个常见的误解。

我们在本章的目标是：

+   了解**函数式编程**（**FP**）的特点

+   了解泛型的目的

+   了解 FP 如何提高性能

+   了解柯里化

+   实现`Map`，`Filter`和`Reduce`函数

+   使用 Goroutines 和 Go 通道实现惰性评估

## FP 的特点

让我们首先看看纯 FP 语言的要求。纯 FP 语言必须支持诸如：

+   头等函数

+   **尾递归优化**（**TCO**）

+   高阶函数

+   纯函数

+   不可变数据

为了实现纯 FP，语言必须像对待任何其他变量类型一样对待函数。在不可变的语言中如何有变化的变量？我们以 FP 的方式实现这一点的方法是创建新变量，而不是修改现有变量。我们将在本章后面看到如何实现这一点，当我们看`Map`函数时。

Go 是一种支持命令式、面向对象和 FP 风格的多维语言。我们可以在 Go 中编写纯粹的命令式或函数式程序。这取决于我们选择的编程风格。这是 Go 和 FP 的伟大之处之一。这不是一个全是或全不是的问题。我们可以在合适的时候和地方将我们的代码迁移到 FP。

Go 需要**尾递归优化**（**TCO**）来处理生产性能要求。每次递归函数调用自身时，都会向堆栈帧添加一个新块；我们很快就会感受到这种 Go 编译器遗漏的迟缓效果。当我们实现`Reduce`函数时，我们将看到如何缓解这个问题。

最后一个要求是支持**高阶函数**（**HOF**）。高阶函数将函数作为参数并/或返回函数作为它们的结果。HOF 允许我们以更少的代码以可读的方式链接我们的函数。

HOFs 可以说是任何 FP 语言的焦点，经过对 FP 特性的快速了解后，我们将研究如何在 Go 中利用它们：

| **特点** | **Go 中支持？** | **描述** |
| --- | --- | --- |

| **匿名函数** | 是 | 一个没有名称的函数。例如，这个函数调用一个打印消息的匿名函数。

```go
func anonymousGreeting() func(string) {
   return func(name string) {
      fmt.Printf("Hey %s!n", name)
   } 
}
```

|

| **闭包** | 是 | 闭包是一个内部函数，它关闭（即访问）其外部范围的变量。换句话说，闭包是一个由对该函数的引用保持活动的函数范围。 |
| --- | --- | --- |
| **组合** | 是 | 组合是允许我们将简单函数组合成更复杂函数的方法。柯里化和管道是组合概念的示例实现。 |

| **延续** | 是 | 延续类似于带参数的 GOTO 语句。延续是我们传递给函数（`factorial`）的函数参数（`next`），它指定函数应该返回的位置。阶乘函数不定义返回值。它是一个接受 int 和另一个传递其当前状态的函数。

```go
func factorial(x int, next func(int)) {
   if x == 0 {
      next(1)
   } else {
      factorial(x-1, func(y int) {
         next(x * y)
      })
   }
}
```

调用继续直到满足基本条件（`x == 0`），然后堆栈上的所有部分执行的下一个函数都被弹出并评估。我们可以这样调用`factorial`：

```go
factorial(4, func(result int) {
   fmt.Println("result", result)
})
```

它将打印：**result: 24**使用单子进行编程是**延续传递风格**（**CPS**）的一种形式，它给了我们更多的控制；使用词法工作流解决方案，当遇到错误时，我们可以将执行定向到错误路径（绕过后续的链式函数调用）到我们工作流的单一惯用 Go 错误处理程序。CPS 也可以使用 Goroutines 和通道进行编程。|

| **柯里化** | 是 | 柯里化是指我们得到一个接受 x 个参数的函数，并返回 x 个函数的组合，每个函数接受 1 个参数。在 FP 中，每个函数都是一个参数的函数。 |
| --- | --- | --- |

| **声明式** | 是 | 声明式风格，与命令式风格相对，意味着我们写表达式而不是逐步说明。命令式函数不用作数据；相反，它用于其副作用，即打印“Hello”。

```go
Info.Println("Hello")
```

|

| **Either 数据类型** | 是 | Either 是一个接受两个参数的类型构造函数。它允许我们说一个值是两种类型中的一种。例如，`Either Car Truck`。我们可以使用 Either 来创建一个错误处理系统，如果我们将我们的结果类型定义为`Either Success Failure`。比 Maybe 数据类型稍微复杂一些。

```go
data Either a b = Left a &#124; Right b
```

|

| **一级函数** | 是！ | 一级函数可以作为参数传递并作为值返回。 |
| --- | --- | --- |
| **函数组合** | 是 | 函数组合意味着我们将单片应用程序分解为最小的计算单元。然后，我们可以以新的方式重新组合我们的函数，通过链接我们的函数调用来创建新的功能。 |

| **Hindley-Milner 类型系统** | 否 | HM 推断类型而不需要任何类型定义。HM 类型系统支持多态类型，其中列表可以包含不同类型的项目。如果 Go 使用了 HM，那么 b 的类型将被推断为`float64`（而不是抛出运行时错误，*常量 1.8 被截断为整数*）

```go
a := 1
b := a + 1.8
```

|

| **幂等性** | 是 | 幂等性意味着我们可以重复调用我们的函数，每次都会产生相同的结果。 |
| --- | --- | --- |
| **不可变数据** | 是 | 不可变的数据结构一旦创建就不会改变。数据不能被添加、移除或重新排序。为了进行*更新*，我们需要创建一个带有我们的更改的副本。不可变性是 FP 的核心原则，因为没有它，我们应用程序中的数据流会变得不稳定和不一致。FP 中真正的常数（如生活中）是变化。变异隐藏了变化。更多原因请参见下面的*不可变数据*部分。 |

| **不可变变量** | 是 | Go 有 const 关键字，但只适用于 int 和字符串。为了拥有不可变对象，我们可以这样写：

```go
type Car struct {
   const Make, Model string
}
```

或者只允许通过方法调用访问字段，这可以编码以防止变异。 |

| **Lambda 表达式** | 是 | Lambda 表达式是匿名函数，通常用作数据，作为参数传递，并作为数据返回，并用于调用另一个函数。请注意，lambda 表达式在它们出现的上下文中执行，也就是说，它们只能访问它们的词法范围内的变量，并且只接受一个参数。要查看 lambda 表达式的示例和非 lambda 表达式的示例，请查看：`2-design-patterns/ch04-solid/01_lambda/main.go`**提示 1**：如果我们可以调用一个函数而不使用它的返回值，那么它是不纯的。**提示 2**：如果我们需要传递多个参数，请使用部分应用的函数。**提示 3**：当我们看到像下面这样的代码时，我们可能正在看一个 Lambda 表达式：

```go
return f(func(x int) int {
   return r(r)(x)
})
```

|

| **列表单子** | 是 | 列表单子用于模拟可以返回任意数量结果的非确定性计算。列表单子可以返回零个或多个结果。return 函数将一个值插入到列表中，如下所示：

```go
return a = [a]
```

bind 函数从列表中提取值，对它们应用函数，并生成一个新的列表，如下所示：

```go
[a] -> (a -> [b]) -> [b]
```

给定以下函数定义：

```go
f :: String -> [String]
f a = [a, prevChar a, nextChar a]
```

```go
g :: String -> [String]
g a = [lower a, upper a]
```

列表单子允许我们将**f**和**g**组合如下：

```go
           g   &#124; w
      &#124; W ---> &#124;
      &#124;        &#124; W
      &#124; 
    f &#124;    g   &#124; x
X --> &#124; X ---> &#124;
      &#124;        &#124; X
      &#124; 
      &#124;    g   &#124; y
      &#124; Y ---> &#124;
               &#124; Y
```

f 看起来像这样：`f "X" --> ["W", "X", "Y"]`g 看起来像这样：

`map g (f "X") --> [["w", "W"], ["x", "X"], ["y", "Y"]]`当我们组合 f 和 g 时，我们得到`["w", "W","x", "X","y", "Y"]`使用组合运算符"."，我们可以将 List monad 组合写成如下形式：`f >=> g = concat . map g . f` |

| **Maybe 数据类型** | 是 | Maybe 表示可能不返回结果的计算，即可选值。`Maybe a`是一个值，它要么包含类型为 a 的值（表示为 Just a），要么为空（表示为 Nothing）。以下是 Maybe 的定义：

```go
data Maybe a = Nothing &#124; Just a
```

说，`Maybe` a 要么不存在，要么存在。如果不存在，它是`Nothing`；如果存在，它是 Just a，其中 a 是一个值。Maybe 是一种多态类型，可以用来定义一个可以产生另一种类型的值或根本没有值的函数。

```go
f :: a -> Maybe b
```

|

| **Maybe Monad** | 是 | Maybe Monad 是一种错误单子，其中所有错误都由`Nothing`表示。（Either 类型提供了更多功能。）鉴于`Maybe`的多态性和结合性，我们可以说。

```go
f :: a -> Maybe b 
g :: b -> Maybe c 
h :: a -> Maybe c 
h = f >=> g 
```

**h**是**f**和**g**的单子组合。`Maybe`单子的定义如下：

```go
instance Monad Maybe where
   return x = Just x

   Nothing >>= f = Nothing
   Just x >>= f = f x
```

|

| **单子错误处理** | 是 | `Maybe`帮助我们处理错误。它表示一些预期的东西，而不是意外的错误。Either 就像一个`Maybe`，它还允许我们返回一个任意值而不是`Nothing`。与担心从函数调用中接收到 null 并可能导致空指针异常不同，我们的类型系统将强制以类型安全的方式处理错误条件。使用 Either 作为我们的返回类型，我们可以运行一个任务，获取一个结果，检查该值：

```go
func runTask(success bool) maybe.Either {
```

即使任务失败，我们也会得到一个非空的结果。

```go
func (e either) Succeeded() StringOption {
   if e.err == nil {
      return SomeString(e.val)
   }
   return EmptyString()
}
```

有关详情，请参阅`2-design-patterns/ch04-solid/02_maybe` |

| **无副作用** | 是 | *无副作用*意味着当我们调用纯函数时，唯一发生的事情是：

+   我们传入参数

+   我们得到一个结果；没有其他事情发生。

**提示 1：**如果我们的函数打印输出，那么它是不纯的。**提示 2：**如果在我们系统的任何其他地方调用我们的函数导致任何状态/数据的更改，那么我们的函数是不纯的。**提示 3：**如果我们的函数没有返回值，那么它要么是不纯的，要么是完全无用的。 |

| **运算符重载** | 否 | 运算符重载，也称为*特定多态性*，是多态性的一个特例，其中不同的运算符如+、=或==被视为多态函数，并且根据其参数的类型具有不同的行为。 |
| --- | --- | --- |

| **Option 类型** | 是 | 我们可以在 Go 中创建一个 Option 类型类：

```go
fmt.Println("Has value:", option.SomeString("Hi"))
fmt.Println("Is empty :", option.Empty())
```

以下是输出：

```go
Has value: Hi
Is empty : <EMPTY>
```

|

| **参数多态性** | 否 | 参数多态性意味着**泛型**。这是一种使用非特定数据类型编写函数的数据类型通用编程风格。例如，我们可以实现适用于非特定类型集合的通用算法。泛型提供了代码重用、类型安全和易于阅读的代码。请参阅以下泛型部分以获取一个简单的示例。 |
| --- | --- | --- |
| **部分函数应用** | 是 | 给予一个函数比它所期望的更少的参数被称为部分函数应用。在这里，我们的函数接受一个具有多个参数的函数，并返回一个参数较少的函数。 |

| **纯函数** | 是 | 纯函数将输入映射到输出。给定相同的输入，纯函数将始终返回相同的输出（也称为*确定性*），并且不会有任何可观察的副作用。纯函数的确定性意味着我们的函数式编程程序的正确性可以得到正式证明，这对于关键任务应用程序是一个巨大的好处。就像数学函数一样，我们函数的输出完全取决于其输入，而与其他因素无关。例如，下面的函数的输出将始终比传递给它的值（x）多两个：

```go
func addTwo(x int) int {
   return x + 2
}
```

|

| **模式匹配** | 否 | 模式匹配使编译器能够根据一些模式匹配一个值，以选择代码的一个分支。

```go
type ErrorMessage =
&#124; YourNameInvalid
&#124; YourPhoneInvalid
&#124; NoTicketsMustBeGreaterThan0
&#124; CreditCardNoInvalid
&#124; CreditCardExpDateInvalid
```

在上述代码中，我们的`ErrorMessage`的值将是五种不同的错误选择之一（`YourNameInvalid`、`YourPhoneInvalid`等）在 Go 中，我们可以在运行时使用联合类型来实现这一点。 |

| **管道** | 是 | 管道允许我们将一个函数的输出作为另一个函数的输入。函数调用可以链接在一起以实现工作流程。管道鼓励代码重用和并行执行。 |
| --- | --- | --- |
| **递归** | 是 | 递归在 FP 语言中用于代替循环，其中一个函数调用自身直到达到结束条件。在 Go 中，每次递归调用都会创建一个调用堆栈。TCO 通过使递归中的最后一次调用成为函数本身来避免创建新的堆栈。尽管我们可以在 Go 中使用递归编码而不使用 TCO，但由于性能差，这并不实用。请注意，纯 FP 语言中的递归是通过 HOFs 从视线中抽象出来的。 |

| **引用透明性** | 是 | 引用透明性是纯函数的属性，其中我们的函数总是为相同的输入返回相同的输出。我们的函数表达式 f(x)和评估我们的函数的结果是可以互换的。例如，1 + 1 总是等于 2。正如我们在第二章中看到的，*操作集合*，这意味着我们可以缓存第一次函数调用的结果并提高性能。

**提示：**如果我们可以缓存先前函数调用的结果，那么我们就具有引用完整性。

| **和类型或联合类型** | 是 | 我们可以使用具有`Success()`和`Failure()`方法的接口来实现联合类型，该方法将返回 Success 或 Failure。有关详细信息，请参见`2-design-patterns/ch04-solid/02_maybe`

```go
package maybe

type SuccessOrFailure interface {
   Success() bool
   Failure() bool
}
```

|

| **尾调用优化** | 否 | 尾调用优化使递归函数调用更高效。尾调用发生在一个函数调用另一个函数作为最后一个动作时。TCO 的作用类似于 GOTO 语句。例如：

```go
 func f(x) {// some code;return g(x)}
```

当被调用的函数 g(x)结束时，程序不需要返回到调用函数，因为在最后一行之后没有可执行代码。在尾调用之后，程序不需要关于 g 的任何调用堆栈信息。没有 TCO，程序将为 g 创建一个不必要的调用堆栈；大量递归调用将导致堆栈溢出。有了 TCO，递归程序将更快，消耗的资源也会少得多。

| **类型类** | 是 | 类型类允许我们定义可以在不同类型上使用的函数，每种类型可能有不同的实现。每个类代表一组类型，并与特定的成员函数集相关联。例如，类型类 Eq 表示所有相等类型的集合，这正是可以使用(==)运算符的类型集合。 |
| --- | --- | --- |
| **单元类型** | 是 | 单元类型恰好有一个值。它也被称为身份。乘法的单位是 1，加法的单位是 0，字符串连接的单位是空字符串。定义为 int 类型的元组类型可以包含多少个值？无限。(-∞, …, 0, 1, 2... ∞)定义为空元组的类型可以包含多少个值？单元类型的值在于可以在我们可能返回 nil（或 null）的地方使用它。当我们不关心值是什么时，我们返回一个单元。我们不返回 nil，我们返回一个值；单元值。所有函数都返回值；不再有空指针异常！单元类型在需要空值的地方也很有用。例如，在 F#中，可能会创建副作用但不返回值的异步操作是类型 Async<unit>的实例。 |

这些并非纯 FP 的所有特征，只是其中一些更重要的特征。可能最重要的是对一级函数的支持。

上表介绍了我们将在本书后面更详细地介绍的许多概念。如果你太好奇，可以随意跳过；否则，跟着流程走，我们最终会涉及到它。

在上表中的*Go 支持？*列中：

+   **是！**：表示 FP 特性存在于 Go 中。

+   **是**：表示 Go 中可以通过一些努力实现该特性或要求。

+   **否**：表示缺少此 FP 特性或要求，并且在不进行 Go 编译器的重大升级或在与 Go 并用其他技术的情况下，难以实现或不可能实现。

### 函数组合

函数组合是当我们组合函数时发生的情况。一个函数的输出是下一个函数的输入。我们可以使用范畴论的对象和态射来帮助我们得到正确的顺序。例如，看下面的图表...

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/lrn-fp-go/img/df1c8e59-30fe-4a52-89bc-fe93e0cf3599.png)>

我们看到我们可以组合我们的函数 f 和 g 从 A 到 B 到 C。请注意顺序很重要。我们必须先通过 f 从 A 到 B，然后通过 g 从 B 到 C。

我们用以下符号表示（f.g)(x)。这读作*f-compose-g with input x*。这个表达式等于 g(f(x))，读作*f of x of g*。所以*(f.g)(x) == g(f(x))*。

这是 Go 中`compose`函数的样子：

```go
func Compose(f StrFunc, g StrFunc) StrFunc {
   return func(s string) string {
      return g(f(s))
   }
}
```

其中`StrFunc`的定义如下：

```go
type StrFunc func(string) string
```

在我们的`main.go`中，我们定义了我们的`f`和`g`函数，分别识别和强调：

```go
func main() {
   var recognize = func(name string) string {
         return fmt.Sprintf("Hey %s", name)
      }
   var emphasize = func(statement string) string {
      return fmt.Sprintf(strings.ToUpper(statement) + "!")
      }
```

我们将`f`和`g`组合如下：

```go
var greetFoG = Compose(recognize, emphasize)
fmt.Println(greetFoG("Gopher"))
```

以下是输出：

```go
HEY GOPHER!
```

请注意顺序很重要。如果我们交换`f`和`g`的顺序，然后组合会发生什么？

```go
var greetGoF = Compose(emphasize, recognize)
fmt.Println(greetGoF("Gopher"))
```

以下是输出：

```go
Hey GOPHER!
```

### 单子允许我们链接连续

链接连续意味着我们可以执行一系列函数，其中一个函数的输出是下一个函数的输入。查看以下链接高阶函数的示例：

```go
cars := LoadCars()
for _, car := range cars.Filter(ByHasNumber()).
       Filter(ByForeign()).
       Map(Upgrade()).
       Reduce(JsonReducer(cars), Collection{}) {
       log.Println(car)
}
```

您将看到以下输出：

```go
{"car": {"make": "Honda", "model": " Accord ES2 LX"}}
{"car": {"make": "Lexus", "model": " IS250 LS"}}
{"car": {"make": "Lexus", "model": " SC 430 LS"}}
{"car": {"make": "Toyota", "model": " RAV4 EV"}}
```

如果我们要实现`for`循环、错误检查和其他通常在 Go 中编写典型命令式编程时所需的支撑，需要多少代码？

我们不是告诉 Go 如何过滤、映射和减少我们的集合，而是声明我们想要实现的目标。在本章后面，我们确实实现了`Filter`、`Map`和`Reduce`函数，但如果 Go 标准库已经为我们提供了这些函数呢？

我们如何期望 Go 为汽车提供 HOF 实现？那是不合理的，对吧？缺少什么？答案是*泛型*。

本章中的 ChainLink 实现有点像穷人的单子。我们将在本书的最后一章中探讨一个真正的单子，并发现涉及更多操作（Bind，Return，单子错误处理）。真正的单子也不依赖全局变量。相似的是它们都允许我们按顺序执行操作，其中一个函数的输出是下一个函数的输入。这是一个要记住的关键概念。

### 泛型

参数多态意味着泛型。泛型函数或数据类型可以编写为使用相同逻辑处理任何数据值，而无需将该值转换为特定数据类型。这大大提高了代码的重用性。

以下是一个泛型`IsEqual`实现的 C#代码示例。泛型`IsEqual`函数将接受任何类型（实现`Equals`）。我们通过在运行时简单地指定类型`T`来传递`IsEqual`整数和字符串，在`IsEqual`执行时：

```go
namespace Generics
{
   private static void Main() {
      if(Compute<int>.IsEqual(2, 2)) {
            Console.WriteLine("2 isEqualTo 2");
         }
      if(!Compute<String>.IsEqual("A", "B")) {
            Console.WriteLine("A is_NOT_EqualTo B");
         }
   }
    public class Compute<T> {
        public static bool IsEqual(T Val1, T Val2) {
            return Val1.Equals(Val2);
        }
    }
}
```

目前，在 Go 中，我们将不得不使用空接口并执行类型转换来执行此操作。正是类型转换导致了通常使 Go 中的泛型处理变得不切实际的性能损失。

### 头等函数

头等函数允许我们通过为基本函数提供函数参数来创建新函数。在下面的代码中，我们的基本函数是`Filter`。通过将`ByMake("Toyota")`传递给`Filter`，我们从集合中删除了大多数汽车项目，只留下了丰田汽车：

```go
cars := Filter(ByMake("Toyota"))
```

我们还有能力将作用于单个元素的任何函数转换为作用于列表的函数，方法是用`Map`函数包装它。如果没有我们新的函数式编程风格，我们可能会尝试实现一个`for`循环，并对每辆汽车应用`fmt.Sprintf`转换，如下所示：

```go
// cars: Honda Accord, Honda Accord ES2, Lexus IS250, Honda CR-V, Lexus SC 430,...
for _, car := range cars {
       thisCar := fmt.Sprintf("%s %s", car, map[string]string{
              "Honda": "LX",
              "Lexus": "LS",
              "Toyota": "EV",
              "Ford": "XL",
              "GM": "X",
       }[GetMake(car)])
       // upgrade a car by appending "LX" ... to the end of the model name
       mappedCars = append(mappedCars, thisCar)
}
// mappedCars: Honda Accord LX, Honda Accord ES2 LX, Lexus IS250 LS...
```

相反，我们可以将`Upgrade`函数简单地传递给`Map`，因为我们组合我们的数据转换：

```go
Filter(ByMake("Toyota")).Map(Upgrade())
```

我们不再需要编写操纵数组的`for`循环，因为我们可以直接调用`Map`。

HOFs 可以大大减少开发复杂逻辑所需的时间。我们可以快速将较小的、特定任务的函数组合成更快的复杂业务逻辑解决方案，减少了更少的脚手架代码，这意味着我们将有更少的错误需要修复。我们的函数本质上是可重用的构建模块。

HOFs 是独立的，这使它们易于在我们的代码库中重用、重构和重新组织。这使我们的程序更加灵活，更能抵御未来的代码更改。

更易读的代码，更快的实现，更少的错误。函数式编程的好处正在累积！

### 闭包

闭包是一个在其外部范围内关闭变量的函数。我们真的需要一个例子来理解这个说法！这是一个很好的例子：

```go
func addTwo() func() int {
       sum := 0
 return func() int { // anonymous function
 sum += 2
 return sum
 }
}

func main() {
       twoMore := addTwo()
       fmt.Println(twoMore())
       fmt.Println(twoMore())
}
```

您将看到以下输出：

```go
2
4
```

前面的闭包是由`addTwo`函数形成的。在`addTwo`内部，`sum`和匿名函数都在同一个词法范围内声明。由于`addTwo`闭合了`sum`和匿名函数，并且因为 sum 是在匿名函数之前声明的，匿名函数总是可以访问并修改`sum`变量。一旦`addTwo`被赋值给`twoMore`，`addTwo`函数的匿名函数就可以访问`sum`变量，并在应用程序继续运行时保持对其的控制。

#### 动态作用域

如果我们在外部范围意外地初始化了`sum`，而我们定义了我们的函数呢？请注意，在与我们的匿名函数相同的范围内没有 sum 变量初始化：

```go
func addTwoDynamic() func() int {
    return func() int { 
        sum += 2
 return sum
    }
}
```

当我们在`main()`函数中运行这个时：

```go
twoMoreDynamic := addTwoDynamic()
fmt.Println(twoMoreDynamic())
fmt.Println(twoMoreDynamic())
```

我们的 Go 运行时查找匿名函数被调用的环境，而不是它被定义的地方（这是词法作用域的情况）。如果`addTwoDynamic`嵌套了几个堆栈帧，我们的 Go 运行时会在`addTwoDynamic`被定义的地方查找 sum。如果在那里找不到，它将继续向上查找堆栈，直到找到 sum。因此，我们看到动态作用域增加了复杂性，并可能导致 sum 的值以不可预测的方式改变，或者至少以更难以调试的方式改变。

以下是输出：

```go
7
9
```

发生了什么？由于 sum 没有在我们定义匿名函数的范围内定义，Go 在全局范围内找到了它。它的值是 5。`addTwoDynamic`将 2 加到 5 得到 7。`addTwoDynamic`再次这样做，得到 9。可能不是我们想要的。

能够传递词法上下文是强大的，并且保证我们不会出现动态作用域可能发生的副作用。我们将看一个实际的例子，我们在应用程序启动时创建一个应用程序上下文，例如数据库连接、记录器等，并在整个应用程序中需要时传递该上下文。

### 纯函数

纯函数是指当给定相同的输入时，将始终返回相同的输出，并且不会有任何可观察的副作用。这有什么好处？让我们看看。我们可以并行运行任何纯函数，因为我们的函数不需要访问共享内存。由于纯函数不可能出现由于副作用而导致的竞争条件。在多核上并发运行我们的代码的性能收益是函数式编程的另一个令人惊叹的好处。

### 不可变数据

不可变数据结构：

+   拥有一个状态并且永远不改变

+   更容易构建、调试、测试和推理

+   没有副作用

+   提高性能并且更具可扩展性，因为它们更容易缓存

+   更安全，因为它们防止空指针引用

+   线程安全

+   总是处于稳定状态

由于不可变数据结构永远不会更改，这意味着在数据修改操作期间永远不会发生故障。当初始化不可变数据结构时，它将失败或成功，返回一个永远不会更改的有效数据结构。

为了对不可变数据结构进行更改，我们必须创建一个新的树。假设我们想要更新现有树数据结构（*先前的根*）中 g 的值。首先，我们将创建 g'节点，并通过遍历与 g 连接的节点并仅复制重建树所需的那些值来构建新树。可以创建对其他节点的引用而不创建新节点（这些是白色节点）。有了新的根，新的叶节点被添加到新的树结构中。

一旦创建了新的根，先前/旧的根可以被保留，也可以被标记为删除。

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/lrn-fp-go/img/f1d89ea7-d7eb-4169-8cde-e3bad95d668c.png)

这可能看起来很费力，但最大的好处之一是我们不再需要担心我们的数据意外更改。例如，如果一个 Goroutine 正在循环遍历我们的数据结构，而另一个 Goroutine 正在从中删除元素，我们不再需要担心处理竞争条件并验证我们的前提条件是否仍然有效。当我们使用不可变数据结构时，我们的代码变得更加健壮，更容易理解。

您是否能想到今天使用不可变数据结构的任何解决方案？

曾经想知道 git 是如何工作的吗？

对全栈开发感兴趣吗？ReactJS 如何更新其模型？

在足球比赛中，我们可能输给一个具有特定技能的球员的球队。当我们再次面对这支球队时，我们可能会忘记过去，但这并不会改变历史；改变过去是不可能的。当过去没有被保留时，我们无法从中学习，历史将重演。可变性隐藏了变化。

#### Go 的持久数据结构

查看[`godoc.org/github.com/mndrix/ps`](https://github.com/mndrix/ps)

来自它的文档：

完全持久的数据结构。持久数据结构是一种数据结构，当修改时总是保留其先前版本。这样的数据结构实际上是不可变的，因为它们的操作不会在原地更新结构，而是总是产生一个新的结构。

持久数据结构通常彼此共享结构。这使得操作可以避免复制整个数据结构。

ps 具有用于操作数据列表和映射的小而有效的 API：

```go
type List interface {
   Cons(val interface{}) List
   ForEach(f func(interface{}))
   Head() interface{}
   IsNil() bool
   Reverse() List
   Size() int
   Tail() List
}
func NewList() List
type Map interface {
   Delete(key string) Map
   ForEach(f func(key string, val interface{}))
   IsNil() bool
   Keys() []string
   Lookup(key string) (interface{}, bool)
   Set(key string, value interface{}) Map
   Size() int
   String() string
   UnsafeMutableSet(key string, value interface{}) Map
}
func NewMap() Map
```

有关更多详细信息，请参见[`godoc.org/github.com/mndrix/ps`](https://godoc.org/github.com/mndrix/ps)

### 使用表达式

使用表达式（而不是语句）意味着在 FP 中，我们将一个值传递给一个函数，通常以某种方式对其进行转换，然后返回一个新值。由于 FP 函数没有副作用，一个不返回值的 FP 函数是无用的，也是代码异味的标志。在第一章中，*Go 中的纯函数式编程*，我们看到命令式编程关注程序操作的逐步机制，而在声明式编程中，我们声明了我们希望结果是什么。

这是命令式编程的一个例子：

```go
var found bool
car_to_look_for := "Blazer"
cars := []string{"Accord", "IS250", "Blazer" }

for _, car := range cars {
       if car == car_to_look_for {
              found = true;
       }
}
fmt.Printf("Found? %v", found)
```

这是声明式编程的一个例子：

```go
fmt.Printf("Found? %v", cars.contains("Blazer"))
```

我们有更少、更易于阅读的声明性 FP 代码。

## 样本 HOF 应用程序

让我们构建一个示例应用程序，演示将函数式编程概念应用于 Go 的好处。

我们的应用程序将从以下`cars.csv`文件中读取：

```go
"Honda Accord"
"Honda Accord ES2"
"Lexus IS250"
"Honda CR-V"
"Lexus SC 430"
"Ford F-150"
"Toyota Highlander"
"Toyota RAV4"
"GM Hummer H2"
"GM Hummer H3"
```

我们将应用高阶函数和各种函数式编程构造到汽车列表中，以过滤、映射、减少和转换它。

我们的项目结构如下：

```go
$ tree
.
├── README.md
└── chapter4
 ├── 01_hof
 │ ├── cars.csv
 │ ├── cars.go
 │ ├── generator.go
 │ ├── more_cars.csv
 │ ├── restful.go
 │ ├── types.go
 │ └── utils.go
 └── main.go
```

在`chapter4`目录的根目录是我们的`main.go`文件。由于我们计划从`main.go`构建一个 Go 可执行文件并运行它，我们使用`main`包名并包括一个`main()`函数。

其他文件将位于名为`01_hof`的子目录中，其中`hof`代表高阶函数。

### 第四章应用程序代码

让我们从`main.go`开始检查我们的`chapter4`实现：

```go
package main

import (
       . "github.com/l3x/learn-fp-in-go/chapter4/01_hof"
 "log"
 "os"
 "github.com/julienschmidt/httprouter"
 "net/http"
)
```

在` . "github.com/l3x/learn-fp-in-go/chapter4/01_hof"`导入中的点(`.`)使我们不必在该目录中的函数前加上`hof`，这是该目录中所有 Go 文件使用的包名称：

```go
func init() {
       log.SetFlags(0)
       log.SetOutput(os.Stdout)
}
```

我们将使用`log`包将输出记录到`stdout`。将 0 值传递给`log.SetFlags`告诉记录器在不添加时间戳的情况下打印。我们还告诉记录器打印到`stdout`，而不是默认的`stderr`，因为我们希望所有输出都能一致地显示，以便阅读。对于生产应用程序，我们可能不会将任何信息输出到`stdout`，因为除了命令帮助和使用信息之外，程序没有任何有用的信息要发送到`stdout`。 

`log`函数可以很容易地配置为在时间戳和行号之前添加。`log.SetFlags(log.Lshortfile | log.Ldate)`设置将输出打印到`stdout`：`2017/04/07 utils.go:17: car: Honda Accord`。

#### 构建和运行时指令

在验证我们的 Go 环境是否正确配置之后，我们可以切换到项目目录并使用以下命令启动 RESTful web 服务器：

```go
$ RUN_HTTP_SERVER=TRUE ./chapter4
```

有关我如何管理我的 Go 环境的详细信息，请参阅附录中的*My Go build and runtime process*部分，*Miscellaneous Information and How-Tos*。

我们需要打开另一个终端窗口来运行我们的`chapter4`可执行文件。让我们构建和运行我们的`chapter4`应用程序，以使用以下命令来运行我们的 HOFs：

```go
$ go build && ./chapter4
```

输出的前几行应该如下所示：

```go
ByMake - Honda
-----------------------
car: Honda Accord
car: Honda Accord ES2
. . .
```

#### 更多应用程序代码

在`main()`函数中，我们首先检查`RUN_HTTP_SERVER`环境变量。如果它被设置为`true`，那么程序将设置两个路由。第一个路由`/cars`返回显示从`.csv`文件中加载的所有汽车的索引页面。第二个路由`/cars/:id`检索单个汽车对象并返回其 JSON 表示：

```go
func main() {
       if os.Getenv("RUN_HTTP_SERVER") == "TRUE" {
              router := httprouter.New()
              router.GET("/cars", CarsIndexHandler)
              router.GET("/cars/:id", CarHandler)
              log.Println("Listening on port 8000")
              log.Fatal(http.ListenAndServe(":8000", router))
```

`IndexedCars`变量在`types.go`中定义如下：

```go
IndexedCar struct {
       Index int `json:"index"`
 Car   string` json:"car"`
}
```

在我们查看 else 逻辑之前，让我们来看一下以下`cars.go`文件。我们声明了一个导出的包级变量`CarsDB`，它被赋予了一个`IndexedCars`的切片：

```go
package hof

import (
       "fmt"
 s "strings"
 "regexp"
 "log"
 "encoding/json"
)

var CarsDB = initCarsDB()

func initCarsDB() []IndexedCar {
       var indexedCars []IndexedCar
       for i, car := range LoadCars() {
              indexedCars = append(indexedCars, IndexedCar{i, car})
       }
       lenCars := len(indexedCars)
       for i, car := range LoadMoreCars() {
              indexedCars = append(indexedCars, IndexedCar{i + lenCars, car})
       }
       return indexedCars
}

func LoadCars() Collection {
       return CsvToStruct("cars.csv")
}
```

请注意，我们`01_hof`目录中的每个 Go 源文件都使用包名称`hof`。

我们用`s`来引用`strings`包，这样我们就可以很容易地使用`s`来引用字符串实用函数，比如`s.Contains(car, make)`，而不是`strings.Contains(car, make)`。

由于`var CarsDB = initCarsDB()`是在包级别定义的，所以当我们启动`chapter4`可执行文件时，它将被评估。`initCarsDB()`函数只需要在这个`cars.go`文件中引用，所以我们不需要将其首字母大写。

另一方面，`LoadCars()`函数被主包引用，因此我们需要将其首字母大写以使其可访问。

现在，让我们把注意力转向 else 块中的 FP 好东西。

#### Filter 函数

我们利用的第一个 HOF 是`Filter`函数：

```go
} else {
       cars := LoadCars()

       PrintCars("ByMake - Honda", cars.Filter(ByMake("Honda")))
```

您将看到以下输出：

```go
ByMake - Honda
-----------------------
car: Honda Accord
car: Honda Accord ES2
car: Honda CR-V
```

`Filter`函数在`cars.go`文件中。观察`fn`参数。它被传递到`Filter`函数中，稍后会用`car`参数调用。如果`fn(car)`——也就是`ByMake("Honda")`——返回`true`，那么这辆车就会被添加到集合中：

```go
func (cars Collection) Filter(fn FilterFunc) Collection {
       filteredCars := make(Collection, 0)
       for _, car := range cars {
              if fn(car) {
                     filteredCars = append(filteredCars, car)
              }
       }
       return filteredCars
}
```

当我们在`cars collection`类型上定义`Filter`函数时，它被称为方法。Go 方法是带有特殊接收器参数的函数。在我们的`Filter`函数中，`cars`集合是接收器。请注意，`cars`在第一组参数中，位于`func`关键字和`Filter`名称之间。注意`cars`是具有`Filter`行为的数据结构。`Filter`方法接受`FilterFun`作为其参数，并返回一个过滤后的集合。

##### 现实检查

什么？一个`for`循环？一个可变的`car`变量？怎么回事？我们必须面对现实。Go 编译器不提供 TCO，因此递归实现根本不现实。也许 Go 2.0 将提供一个纯函数库，其中包括我们所有喜爱的高阶函数以及泛型。在那之前，我们将尽可能地使用函数式编程风格，必要时使用一些命令式编程。我们稍后将探讨的另一个选项是一个名为**Gleam**的执行系统，它提供了纯 Go 映射器和减速器，提供了高性能和并发性。

数据转换是如此常见，以至于有一个简写方式是很好的。高阶函数简化了执行数据转换的代码的编写和阅读，这是 FP 最大的好处之一。

#### FilterFunc

在`types.go`文件中，我们看到了它的定义：

```go
FilterFunc func(string) bool
```

回顾一下`main.go`中的那一行，我们看到我们使用了`ByMake`过滤函数：

```go
PrintCars("ByMake - Honda", cars.Filter(ByMake("Honda")))
```

`ByMake`函数在`cars.go`文件中定义：

```go
func ByMake(make string) FilterFunc {
       return func(car string) bool {
 return s.Contains(car, make)
 }
}
```

`ByMake`函数是一个高阶函数，因为它返回一个函数。回想一下，`Filter`是一个高阶函数，因为它接受一个函数。在这种情况下，`ByMake`就是那个函数`fn`，我们将在下一节中看到。

##### 过滤函数

`Filter`函数是一个高阶函数，它接受另一个高阶函数，即`ByMake`，并执行数据转换。

```go
func (cars Collection) Filter(fn FilterFunc) Collection {
   filteredCars := make(Collection, 0)
   for _, car := range cars {
      if fn(car) {
         filteredCars = append(filteredCars, car)
      }
   }
   return filteredCars
}
```

### RESTful 资源

让我们打开`http://localhost:8000/cars`，看看来自`cars.csv`和`more_cars.csv`的所有汽车的完整列表：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/lrn-fp-go/img/fa24237d-e100-487d-9d2c-0edce3dea662.png)

让我们看看`main.go`中下一个`Filter`函数的运行情况：

```go
PrintCars("Numeric", cars.Filter(ByHasNumber()))
```

您将看到以下输出：

```go
Numeric
-----------------------
car: Honda Accord ES2
car: Lexus IS250
car: Lexus SC 430
car: Ford F-150
car: Toyota 86
car: Toyota RAV4
car: GM Hummer H2
car: GM Hummer H3
```

在这种情况下使用的`FilterFunc`方法是`ByHasNumber()`。它的操作方式类似于`ByMake FilterFunc`，并使用 Go 的 regexp `MatchString`函数来返回`true`，如果汽车中有数字的话：

```go
func ByHasNumber() FilterFunc {
       return func(car string) bool {
 match, _ := regexp.MatchString(".+[0-9].*", car)
 return match
 }
}
```

#### 链接函数

既然我们已经掌握了，让我们将几个过滤器链接在一起：

```go
PrintCars("Foreign, Numeric, Toyota",
       cars.Filter(ByForeign()).
              Filter(ByHasNumber()).
              Filter(ByMake("Toyota")))
```

您将看到以下输出：

```go
Foreign, Numeric, Toyota
-----------------------
car: Toyota 86
car: Toyota RAV4
```

#### 更多的汽车

是时候添加更多的汽车了：

```go
moreCars := LoadMoreCars()

PrintCars("More Cars, Domestic, Numeric, GM",
       cars.AddCars(moreCars).
              Filter(ByDomestic()).
              Filter(ByHasNumber()).
              Filter(ByMake("GM")))
```

这是输出：

```go
More Cars, Domestic, Numeric, GM
-----------------------
car: GM Hummer H2
car: GM Hummer H3
car: GM Oldsmobile Delta 88
car: GM Oldsmobile 442
```

等等，什么？ `AddCars`？那怎么成为高阶函数了？ `AddCars`既不接受函数，也不返回函数。更糟糕的是，它改变了`cars`集合。

##### 现实检验

汽车集合保持*纯粹*并不重要；坦率地说，这是不可行的，因为 Go 编译器目前不提供 TCO。重要的是，我们的代码通过使用函数式编程技术得到改进。诚然，这个`AddCars`距离纯粹的函数最远，但它是有用的，它确实提高了我们程序的可读性。当我们使用非纯函数时，尤其是那些改变其状态的函数时，我们需要小心，但对于我们的目的来说，这种用法是完全可以的。

我们在`cars.go`中找到了`AddCars`：

```go
func (cars Collection) AddCars(carsToAdd Collection) Collection {
       return append(cars, carsToAdd...)
}
```

#### Map 函数

回到`main.go`。这一次，您将介绍`Map`高阶函数。而`Filter`的作用是减少结果集合中的项目数量，`Map`将返回与接收到的项目数量相同的项目。`Map`函数将集合转换为一个新的集合，其中每个项目都以某种方式改变：

```go
PrintCars("Numeric, Foreign, Map Upgraded",
       cars.Filter(ByHasNumber()).
              Filter(ByForeign()).
              Map(Upgrade()))
```

这是输出：

```go
Numeric, Foreign, Map Upgraded
-----------------------
car: Honda Accord ES2 LX
car: Lexus IS250 LS
car: Lexus SC 430 LS
car: Toyota 86 EV
car: Toyota RAV4 EV
```

我们将一个名为`Upgrade`的`MapFunc`函数传递给`Map`：

```go
func Upgrade() MapFunc {
       return func(car string) string {
 return fmt.Sprintf("%s %s", car, UpgradeLabel(car))
 }
}
```

`Upgrade`调用`UpgradeLabel`函数，以便在汽车的型号名称末尾添加适当的升级标签：

```go
func UpgradeLabel(car string) string {
       return map[string]string{
 "Honda": "LX",
 "Lexus": "LS",
 "Toyota": "EV",
 "Ford": "XL",
 "GM": "X",
 }[GetMake(car)]
}
```

##### Map 函数的性能提高

FP 的最大好处之一是性能。

如今的程序主要通过使用多个 CPU 核心同时执行多个操作来实现更好的性能。

这意味着并行运行代码，为了做到这一点，我们的代码必须是线程安全的。具有共享可变状态的程序是不安全的。这些程序将在一个核心中成为瓶颈。

FP 通过返回变量的新实例而不是改变原始实例来解决了这个瓶颈/线程安全问题。

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/lrn-fp-go/img/24149bd7-d77b-4308-a2f5-d78e76d0d712.png)

让我们看看`Map`函数，看看我们如何使用 FP 实现这一点：

```go
func (cars Collection) Map(fn MapFunc) Collection {
       mappedCars := make(Collection, 0, len(cars))
       for _, car := range cars {
              mappedCars = append(mappedCars, fn(car))
       }
       return mappedCars
}
```

`Map`不是将内容附加到汽车集合，而是接收一个新变量`mappedCars`。`mappedCars`集合被改变，而不是原始汽车集合。

当我们调用`Map(Upgrade())`时，我们在战术上所做的是将我们的数据更改的时刻推迟到最后一刻--在这个例子中，是在`mappedCars`被填充之后。

我们一直在我们的整个职业生涯中编写 FP 概念。本章的部分内容是识别这些 FP 模式，以及我们应该如何以及为什么要利用它们。

#### Reduce 函数

接下来，让我们看看`Reduce`函数。`Reduce`是 HOF 的瑞士军刀。有了`Reduce`函数，我们可以做任何可以用`Filter`或`Map`完成的事情。

`Reduce`函数，也称为`fold`、`accumulate`、`aggregate`、`compress`或`inject`，接受一个种子值，并将 reducer 函数的逻辑应用于种子，并可能多次调用自身以得到结果。通常，reduce 函数将组合数据元素以返回单个聚合值，因此称为`fold`。因此，我们将所有数据折叠成一个结果。

回到`main.go`，我们应用`ByMake`过滤器来过滤掉所有不是本田产品的汽车。然后，我们调用`Reduce`函数将本田车辆的集合转换为 JSON 字符串的集合：

```go
PrintCars("Filter Honda, Reduce JSON",
       cars.Filter(ByMake("Honda")).
              Reduce(JsonReducer(cars), Collection{}))
```

这将产生以下输出：

```go
Filter Honda, Reduce JSON
-----------------------
car: {"car": {"make": "Honda", "model": " Accord"}}
car: {"car": {"make": "Honda", "model": " Accord ES2"}}
car: {"car": {"make": "Honda", "model": " CR-V"}}
```

`Reduce`函数是汽车集合的一个方法，接受一个`Reducer`函数。再次看到一个`for`循环，并回想起，“没有尾调用优化，没有递归”。没关系。所以，我们的`Reduce`函数的核心部分不是*纯*的。没关系。它仍然是可读的，高效的，安全的；符合 Go 编程的精神，它完成了工作：

```go
func (cars Collection) Reduce(fn ReducerFunc, accumulator Collection) Collection {
       var result = accumulator
       for _, car := range cars {
              result = append(fn(car, result))
       }
       return result
}
```

第二个参数`Collection{}`是累加器，是分配给结果的初始值。`Reducer`函数从累加器值开始，在集合中的每个项目上执行转换，并返回结果。这个`Reduce`函数提供了执行减少的框架，但是真正的工作是由 reducer 函数（`fn`）完成的。请注意，我们可以将任何有效的 reducer 函数（`fn`）传递到`Reduce`框架中，以获得截然不同的结果。

我们的`JsonReducer`函数真正地将汽车集合中的每个项目转换为 JSON 字符串：

```go
func JsonReducer(cars Collection) ReducerFunc  {
       return func(car string, cars Collection) Collection {
 carJson := fmt.Sprintf("{"car": {"make": "%s", "model": "%s"}}", GetMake(car), GetModel(car))
 cars = append(cars, carJson)
 return cars
 }
}
```

Reduce 是一个接受函数的 HOF 函数。`JsonReducer`是一个返回函数的 HOF 函数。

#### 更多高阶函数

现在，让我们返回`main.go`，看看更多 HOF 的实际应用。

我们应用我们的`ByMake`过滤器和一种新类型的 reducer。这个 reducer，`Reducer2`，将返回一个`CarTypes`的切片，而不是 JSON：

```go
PrintCars2("Reduce - Lexus",
       cars.Filter(ByMake("Lexus")).
              Reduce2(CarTypeReducer(cars), []CarType{}))
```

以下是这个的输出：

```go
Reduce - Lexus
-----------------------
car: {Lexus IS250}
car: {Lexus SC 430}
```

以下是另一个示例，展示了链式调用（也称为函数组合）有多么容易：

```go
PrintCars("ByModel - Accord up/downgraded",
       cars.Filter(ByModel("Accord")).
              Map(Upgrade()).
              Map(Downgrade()))
```

以下是这个的输出：

```go
ByModel - Accord up/downgraded
-----------------------
car: Honda Accord 
car: Honda Accord ES2
```

我们看到`Upgrade`映射函数如何在汽车型号末尾添加适当的标签。通过在`Upgrade`之后应用`Downgrade`，我们有效地撤消了`Upgrade`。

#### 生成器

是时候检查生成器了。生成器很有用，因为它们允许我们延迟表达式的评估。我们只在需要时计算我们需要的表达式。生成器还节省内存，因为使用生成器，我们只创建和使用我们需要的，不多不少：

```go
PrintCars("GenerateCars(1, 3)",
       cars.GenerateCars(1, 3))
```

我们将在`generate.go`文件中找到`GenerateCars`的实现：

```go
package hof

import (
       "sync"
 "log"
)

func carGenerator(iterator func(int) int, lower int, upper int) func() (int, bool) {
       return func() (int, bool) {
              lower = iterator(lower)
              return lower, lower > upper
       }
}

func iterator(i int) int {
       i += 1
 return i
}
```

我们定义我们的导入。`sync`导入是一个线索，表明我们需要同步我们的 Goroutines。`iterator`函数将被传递给`carGenerator`函数，并将跟踪我们生成了多少辆汽车。我们将根据需要创建汽车。

#### RESTful 服务器

如果我们的 RESTful 服务器在端口`8000`上运行，我们可以在网页浏览器中打开`http://localhost:8000/cars/1`，看到以下内容：

```go
{
  "index": 1,
  "car": "Honda Accord ES2"
}
```

这是`IndexedCar`结构的表示。它有一个索引和一个汽车制造商和型号字符串。

这是`types.go`中实际的`IndexedCar`结构：

```go
IndexedCar struct {
       Index int `json:"index"`
 Car   string` json:"car"`
}
```

#### 生成汽车函数

以下是实际的生成器函数：

```go
func (cars Collection) GenerateCars(start, limit int) Collection {
       carChannel := make(chan *IndexedCar)
```

`GenerateCars`是`cars`集合中的另一个方法，它使得与其他 HOFs 组合数据变换变得容易。`GenerateCars`接受一个起始索引和限制，即我们想要返回的汽车数量。我们创建指向`IndexedCars`的`carChannel`：

```go
var waitGroup sync.WaitGroup
```

我们使用`sync.WaitGroup`作为计数信号量来等待我们的一系列 Goroutines 完成：

```go
numCarsToGenerate := start + limit - 1
generatedCars := Collection{}
waitGroup.Add(numCarsToGenerate)
```

我们计算要生成的汽车数量，并将该数字传递给`waitGroup.Add`函数：

```go
next := carGenerator(iterator, start -1, numCarsToGenerate)
```

我们的`carGenerator`函数返回一个我们分配给变量`next`的函数：

```go
carIndex, done := next()
```

`next`变量返回两个变量：`carIndex`和`done`。只要还有更多的汽车要生成，`done`就会是`false`。因此，我们可以使用`done`来控制一个`for`循环，为要生成的每辆汽车启动一个 Goroutine：

```go
for !done {
       go func(carIndex int) {
              thisCar, err := GetThisCar(carIndex)
              if err != nil {
                     panic(err)
              }
              carChannel <- thisCar
              generatedCars = append(generatedCars, thisCar.Car)
              waitGroup.Done()
       }(carIndex)

       carIndex, done = next()
}
```

`next`变量在代码块中返回两个变量`GetThisCar(carIndex)`；在此之后，前面的代码调用 RESTful 汽车服务，返回所请求的汽车。

如果遇到错误，我们使用内置函数`panic`来停止当前 Goroutine 的执行。由于我们使用了延迟函数，即`csvfile.Close()`，在调用堆栈中，如果发生 panic，它将被执行。请注意，我们本可以使用内置的 recover 函数更好地控制终止序列。

`thisCar`变量被发送到`carChannel`，并且`Car`字段被附加到`generatedCars`集合中。

##### 柯里化 Goroutine

注意`generatedCars`集合有什么特别之处吗？（提示：我们的 Goroutine 是一个匿名函数）。

没错。我们正在对`generatedCars`集合进行柯里化。我们的 Goroutine 覆盖了`generatedCars`集合。这使我们能够从 Goroutine 中引用并附加到它，而不管它运行在哪个核心上。

我们站在巨人的肩膀上。我们使用 Go 通道和 Goroutines 来模拟 FP 生成器和其他 HOFs。我们的代码可读性强，而且不需要太多的代码就能使其全部工作。

##### 对柯里化的更近距离观察

在我们继续之前，让我们看一下以下柯里化与非柯里化代码示例，以提高我们对柯里化的理解：

```go
package main

import "fmt"

// numberIs numberIs a simple function taking an integer and returning boolean
type numberIs func(int) bool

func lessThanTwo(i int) bool { return i < 2 }

// No curried parameters
func lessThan(x int, y int) (bool) {
   return x < y
}

func main() {
   fmt.Println("NonCurried - lessThan(1,2):", lessThan(1, 2))
   fmt.Println("Curried - LessThanTwo(1):", lessThanTwo(1))
}
```

您会立即看到，柯里化示例只需要一个参数，而非柯里化示例需要两个参数。柯里化的想法是通过部分应用来从更小、更一般的函数中创建新的、更具体的函数。我们将在第八章 *函数参数*中看到更多内容。

另一个收获是函数类型的使用。`numberIs`是一个数据类型，是一个接受 int 并返回 bool 的函数。没错，在 FP 中，我们不害怕函数。我们将它们视为常规的数据类型。在 FP 中，一切都是数据，数据永远不会改变。它只是被传递、创建和返回。

角度*x*的值等于(*A*)邻边的长度除以(*H*)斜边的长度([`www.mathopenref.com/cosine.html`](http://www.mathopenref.com/cosine.html))：

*cos x = A / H*

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/lrn-fp-go/img/842223a2-7e83-48c9-82da-cbe9f193f131.png)

在命令式编程中，我们被引导相信函数和数据是不同的东西。在 FP 中，我们看到函数没有副作用。一个很好的 FP 示例是几何余弦函数。对于直角三角形，如果我们将 15 作为(*A*)邻边和 30 作为(*H*)斜边传递，那么我们得到角 A 的余弦值为 0.5。由于我们可以依赖这个事实——每次传递 15 和 30 都会得到 0.5——即使我们戴着命令式编程的帽子，我们也知道我们可以将这些值放入查找表中。想象一下一个电子表格，其中行号代表 A，列代表 H。在第 15 行，第 30 列的单元格将具有值 0.5。

看，函数就是数据！然而，我们并不总是想要在每种情况下存储每个可能参数组合的每个计算值，只有在有意义的情况下才这样做。

想象一下，每个函数调用都是一个表查找。现在想象一下我们的重用潜力，应用程序的评估部分是通用的。如果你的头脑还完整，等到第九章，*适用的范畴论*，我们将讨论范畴论和类型类的应用。

##### 扩展我们的柯里化示例

但等等，还有更多！让我们在`func main()`上面添加以下内容：

```go
func (f numberIs) apply(s ...int) (ret []bool) {
   for _, i := range s {
      ret = append(ret, f(i))
   }
   return ret
}
```

`apply`函数是绑定到函数类型的方法，即`numberIs`。我们的 apply 函数将`numberIs`函数应用于每个参数。每个计算出的值都附加到新创建的布尔数组中，然后返回给调用者。

接下来，我们将`main()`更新如下：

```go
func main() {
   fmt.Println("NonCurried - lessThan(1,2):", lessThan(1,2))
   fmt.Println("Curried - LessThanTwo(1):", lessThanTwo(1))
   // use anonymous function
 isLessThanOne := numberIs(func(i int) bool { return i < 1 }).apply 
 isLessThanTwo := numberIs(lessThanTwo).apply // use named function
 s := []int{0, 1, 2}
   fmt.Println("Curried, given:", s, "...")
   fmt.Println("isLessThanOne:", isLessThanOne(s...))
   fmt.Println("isLessThanTwo:", isLessThanTwo(s...))
}
```

这是它的输出：

```go
NonCurried - lessThan(1,2): true
Curried - LessThanTwo(1): true
Curried, given: [0 1 2]...
isLessThanOne: [true false false]
isLessThanTwo: [true true false]
```

在纯 FP 中，每个函数都是一个参数的函数。我们可以使用 Go 中的柯里化来实现这一点。

现在，回到汽车。

##### 使用 WaitGroup 变量来管理并发

在将`thisCar`附加到`generatedCars`集合后，我们执行`waitGroup.Done()`。这会减少`WaitGroup`变量的计数。这个计数对应于我们分配给 lower 变量的迭代器值，并应用于分配给 done `return`变量的`lower > upper`表达式：

```go
func carGenerator(iterator func(int) int, lower int, upper int) func() (int, bool) {
       return func() (int, bool) {
 lower = iterator(lower)
 return lower, lower > upper
 }
}
```

我们使用迭代器来知道要启动多少个 Goroutines：

```go
func iterator(i int) int {
       i += 1
 return i
}
```

##### 完成 GenerateCars 函数

在我们的`GenerateCars`函数的末尾，我们执行另一个匿名 Goroutine。这个 Goroutine 的目的是等待所有先前启动的 Goroutine 生成器完成。我们使用`waitGroup.Wait`来知道最后一个生成器何时完成。然后，安全地关闭`carChannel`：

```go
        go func() {
              waitGroup.Wait()
              println("close channel")
              close(carChannel)
       }()

 for thisCar := range carChannel {
              generatedCars = append(generatedCars, thisCar.Car)
       }
       return generatedCars
}
```

`carChannel`将阻塞，直到接收到新的汽车；这是调用`GetThisCar(carIndex)`的结果。回想一下，`WaitGroup.Add(numCarsToGenerate)`告诉`WaitGroup`我们要处理多少辆汽车。`waitGroup.Done()`函数将该数字减少到 0，此时执行`waitGroup.Wait()`，并关闭`carChannel`。

在返回`generatedCars`集合之前，我们等待所有的 Goroutines 从 RESTful HTTP 服务器中获取数据。这是 FP 中的一种常见模式：我们尽可能地消除数据转换操作中的状态更改。我们等到所有的数据收集处理都完成，然后最终返回最终结果。

我们的 FP 工作很像电工的工作。电工关闭电源，连接建筑物中的所有电线，当一切就绪时，他们打开电源开关，所有灯都亮了起来。数据就是力量。不要让你的数据飞出去，直到最后一刻。

在`main.go`文件中，添加以下代码：

```go
PrintCars("GenerateCars(1, 3)",
       cars.GenerateCars(1, 3))
```

以下是它的输出：

```go
GenerateCars(1, 3)
-----------------------
car: Honda CR-V
car: Honda Accord ES2
car: Lexus IS250
```

#### 处理并发

我们通过计算我们启动了多少个`GetThisCar` Goroutines 来管理它们，并利用`WaitGroup`变量在它们完成时递减该计数。虽然我们的许多`GetThisCar` Goroutines 确实并行执行，但重要的是我们处理它们的并发的方式。使用下一个迭代器和`waitGroup`变量，我们能够简单有效地处理它们的生命周期：从每个 Goroutine 开始，接收它们的结果，并在我们的计数表明所有 Goroutines 都完成时关闭`carChannel`。曾经尝试使用 Java 或 C++管理多个操作线程吗？注意我们不必处理管理互斥锁和难以调试的竞争条件？并发实现的便利是 Go 的许多优势之一。

**并发**：系统的属性，其中多个进程同时执行并可能相互交互。并发是处理许多事情的能力。

**并行性**：这是一种计算类型，许多计算同时进行，其原则是大问题通常可以分解为较小的问题，然后并行解决。并行性是同时做很多事情的能力。

请查看 Rob Pike 的史诗级视频，“并发不等于并行”，网址为[`www.youtube.com/watch?v=cN_DpYBzKso`](https://www.youtube.com/watch?v=cN_DpYBzKso)。

#### 最终的 HOF 示例

我们最终的 HOF 示例非常棘手。我们生成了 14 辆汽车，用`ByDomestic`进行筛选，用`Upgrade`函数进行映射，用`ByHasNumber`进行筛选，然后将它们减少为一组 JSON 字符串：

```go
PrintCars("GenerateCars(1, 14), Domestic, Numeric, JSON",
       cars.GenerateCars(1, 14).
              Filter(ByDomestic()).
              Map(Upgrade()).
              Filter(ByHasNumber()).
              Reduce(JsonReducer(cars), Collection{}))
```

其输出如下：

```go
GenerateCars(1, 14), Domestic, Numeric, JSON
-----------------------
car: {"car": {"make": "Ford", "model": " F-150 XL"}}
car: {"car": {"make": "GM", "model": " Hummer H2 X"}}
car: {"car": {"make": "GM", "model": " Hummer H3 X"}}
```

这是六行代码。你认为使用命令式编程风格需要多少行代码来完成这个任务？

“这个程序已经太臃肿了，再多一点臃肿也没关系。” 不，最终会有问题的。然后就来不及修复了。”

- Rob Pike

“问题在于，添加更多的臃肿通常比正确集成要容易得多，后者需要思考、时间和艰难的决定。”

- Roger Peppe

## 总结

FP 是一种声明式的编程风格。它更易读，通常需要比我们的命令式或面向对象的实现选项少得多的代码。

在本章中，我们实现了`Map`，`Filter`和`Reduce`高阶函数。我们研究了闭包，并看了看柯里化如何实现函数组合。

我们的`Reduce`实现演示了如何使用 Goroutines 和 Go 通道执行惰性评估。我们使用`WaitGroup`变量和一些常识来管理其并发性。

在下一章中，我们将考虑 API 软件设计。我们将看看如何使用接口和闭包构建可组合的系统，以强制执行单一责任原则和开闭原则。


# 第四章：Go 中的 SOLID 设计

曾经看到过这样的评论吗：*如果你喜欢设计模式，就用 Java，不要用 Go*？

在本章中，我们将解决关于软件设计模式的常见看法，以及它们如何与开发高质量的 Go 应用程序相适应。

本章的目标是理解以下主题：

+   为什么许多 Gophers 讨厌 Java

+   为什么 Go 不支持继承

+   良好软件设计原则

+   如何在 Go 中应用单一职责原则

+   开闭原则

+   Go 中的鸭子类型

+   如何使用接口在 Go 中建模行为

+   如何使用接口隔离原则来组合软件

+   内部类型提升以及如何嵌入接口

## 为什么许多 Gophers 讨厌 Java

*如果你喜欢设计模式，就用 Java，不要用 Go。*

让我们思考这种思维是从哪里来的。Java（以及 C++）倾向于关注类型层次和类型分类。

以 Spring Framework 中的`ObjectRetrievalFailureException`类为例：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/lrn-fp-go/img/44e29e9c-4a08-41d8-813e-d062e604367b.png)

这看起来太复杂和过于抽象了，对吧？

与 Java 不同，Go 被设计为一种务实的语言，我们不会迷失在无限的继承层次和类型层次中。

当我们在一种非常强调类型层次、抽象层次和类继承的语言中实现解决方案时，我们的代码重构往往需要花费更多的时间。最好在开始编码之前就设计好。在实现 Java 解决方案时，利用设计模式可以节省大量时间。

继承在面向对象编程中创建了高耦合。在前面的例子中，`DataAccessException`类的更改可能会导致其上层的每个类中产生意想不到的副作用。

很容易理解为什么有人会认为在 Go 中没有设计模式的位置。

"如果 C++和 Java 关注类型层次和类型分类，那么 Go 关注组合。"

- Rob Pike

然而，通过谨慎使用抽象，软件设计模式可以完全与 Go 的可组合简单设计理念兼容。

### 讨厌 Java 的更多原因

考虑以下表格：

|  | **Java** | **Golang** |
| --- | --- | --- |
| **语言规范** (PDF) | 788 页 ([`docs.oracle.com/javase/specs/jls/se8/jls8.pdf`](https://docs.oracle.com/javase/specs/jls/se8/jls8.pdf)) | 89 页 ([`golang.org/ref/spec`](https://golang.org/ref/spec)) |
| **Java JDK 与 Go SDK** (压缩) | 279.59 MB ([`jdk.java.net/9/`](http://jdk.java.net/9/)) | 13 MB |
| **并发实现复杂性** | 困难 | 简单 |

以下是一个比较 Java 和 Go 技术栈的高层次图表：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/lrn-fp-go/img/fe227eef-7ff6-4f60-8840-4d1ac45ce65e.png)

Java/JVM 的替代方案占用的空间更大；JVM 做了更多的事情（其中一些是你的应用程序会使用的），并且需要更多的 RAM。此外，由于 Java/JVM 解决方案的原始源代码比 Go 更多，这意味着对黑客进行攻击的攻击面更大。性能？JIT 编译器将应用程序的源代码转换为可执行二进制代码比 Go 需要更多的时间，因为 Go 是本地编译的。

Go 更小更简单。Java 是为了盈利而创建的，并且一直在积极营销。Go 没有市场营销。对于提出对 Go 语言的更改有一个简化的流程。请参见附录中的"How to Propose Changes To Go"。（我没有找到提出对 Java 或 JVM 的更改的流程，但我只能想象这需要更多的时间和精力）。

鉴于前面对 Go 和 Java 的比较，似乎可以归结为简单与复杂。Gophers 倾向于更喜欢简单。

"少即是多。"

- Rob Pike

### 深入挖掘错误处理

在 Java 中，当方法中发生异常时，创建异常对象并将其交给运行时环境的过程称为抛出异常。

当这种情况发生时，程序的正常流程会停止，JRE 会尝试在调用堆栈中找到一个可以处理引发异常的处理程序。

异常对象包含了大量的调试信息，比如异常发生的行号、异常类型、方法层次结构、调用堆栈等等。

由于对 Java 类型层次结构的设计和误解，Java 中存在着许多常见的异常处理反模式。

"不要只是检查错误，要优雅地处理它们。"

- Dave Cheney

与其断言错误是特定类型或值并传递到上一行，我们可以断言错误实现了特定的行为：

```go
type errorBehavior interface {
       Retryable() bool
}

func IsRetryable(err error) bool {
       eb, ok := err.(errorBehavior)
       return ok && eb.Retryable()
}
```

如果发生`IsRetryable`错误，那么调用者会知道他们可以重试生成错误的操作。调用者不需要导入实现抛出错误的库，并尝试理解其类型层次结构的复杂性来正确处理错误。

`github.com/pkg/errors`包允许您使用上下文包装错误，以便以后可以像这样恢复原因：

`func IsRetryable(err error) bool {`

`eb, ok := errors.Cause(err).(errorBehavior)`

`return ok && eb.Retryable()`

} 

一旦检查了错误值，就应该处理一次。在 Go 中，重新打包错误并将其抛出以供另一个处理程序处理并不被认为是最佳实践。

#### 一段对话- Java 开发者，惯用 Go 开发者，FP 开发者

Java 开发者：我讨厌到处写`if err != nil`。

Go 开发者：习惯就好了。

Java 开发者：为什么不直接抛出异常，让调用链上的处理程序处理呢？

Go 开发者：所有优秀的程序员都是懒惰的，那是额外的打字。

| **开发者** | **对话** |
| --- | --- |
| Java | 我讨厌到处写`if err != nil`。 |
| Go | 习惯就好了。 |
| Java | 为什么不直接抛出异常，让调用链上的处理程序处理呢？这样打字更少，所有优秀的程序员都是懒惰的，对吧？ |

| Go | 错误应该立即处理。如果我们的`buggyCode`函数返回错误，但我们继续处理会怎样？你能看出这是多么脆弱和错误吗？

```go
val, err := buggyCode()
// more code
return val, err
```

|

| FP | 关于抛出 Java 异常，最让我困扰的是，当我们将错误抛出给另一个函数处理时，我们刚刚创建了一个副作用。我们的函数不是纯的。我们在应用程序中引入了不确定性。由于调用堆栈中的任何调用者都可以处理异常，我们怎么知道哪个处理程序处理它？由于我们编写了最接近错误的代码，我们应该比任何其他开发人员更了解发生了什么以及如何最好地处理它。 |
| --- | --- |
| Java | 好的。我明白了，但我不仅懒惰，而且所有额外的`if err != nil`代码看起来像是我代码中的脚手架，让我想要呕吐。让我用几张照片澄清我的感受。 |

我们的代码：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/lrn-fp-go/img/4df41f98-3e74-491e-9dc9-156c5f869ff5.png)

| Java | 你能看出区别吗？ |
| --- | --- |
| Go | 理解了！但你需要意识到，我主要对编写后端系统感兴趣，正确性胜过美观。你可以拿你漂亮的 J2EE 企业业务应用程序，然后用尽可能多的异常处理程序包装它们。 |
| Java | 真的吗？你说你喜欢简单，但对我来说，更多的代码看起来更复杂。这意味着更多的代码需要维护。这意味着，我不能在一个地方处理所有的错误处理，而是必须在整个应用程序中插入一小段错误处理代码？该死！我非常喜欢 Go 的快速编译时间，Go 的小占用空间，编写并发应用程序的简易性等等。我非常沮丧。Go 中没有更好的错误处理解决方案吗？ |
| FP | 很高兴你问。根据你想要实现什么，有更好的方法。这种方式不仅可以让您在一个地方处理所有错误，而且还可以以纯 FP 的确定性处理。 |
| Go | 胡说八道。我现在会停止阅读这本书，因为这根本行不通。 |
| Java | 是的！有什么陷阱吗？ |
| FP | 该解决方案需要思考、时间和艰难的决定，但就像学骑自行车一样。一旦你上手了，你就会继续做。这很有趣，可以更有效地带你到达目的地，对你有好处。 |
| Java | 它叫什么？ |
| FP | 词法工作流解决方案 |
| Go | 你抓住我了。我还在阅读。只是足够长的时间来说，这是一个荒谬的说法，名字更是如此。 |
| FP | 我知道这听起来像魔术，而且确实是。它建立在更荒谬的名字上：Y-Combinator 和 Monad。但在讨论细节之前，我们还有很长的路要走。这需要思考、时间和决策能力。 |
| Java | 有什么需要决定的吗？如果它有效，我会使用它。 |
| FP | 词法工作流解决方案的最佳用例是您有要转换的数据。您是否有任何工作流程，其中您输入数据，以某种方式进行转换，然后产生输出？这涵盖了许多业务用例场景，也包括一些系统级别的用例。 |
| Java | 听起来不错。它是做什么的，又不是做什么的？ |
| FP | 它处理您遇到错误时的典型工作流用例，该错误被处理并且在该工作流程中不会发生进一步处理。如果您希望即使出现错误也要继续处理，那么最好使用 applicative functors。如果 Go 支持 TCO，那将为许多 FP 可能性打开大门。目前，我们需要保持现实（不用担心递归的堆栈溢出或性能影响）。如果/当 Go 支持 TCO 时，我们 FP 编码人员将能够释放大量强大、富有表现力和高性能的 FP 解决方案。 |

## 软件设计方法论

软件设计是我们：

+   收集需求

+   从需求创建规格说明

+   根据规格说明实施解决方案

+   审查结果并迭代改进解决方案

传统的瀑布式开发依赖于对产品需求的完美理解以及在每个阶段执行最小的错误。来源：[`scrumreferencecard.com/scrum-reference-card/`](http://scrumreferencecard.com/scrum-reference-card/)

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/lrn-fp-go/img/97dc5d5b-3f70-4b52-9fe5-bd9ca4693237.png)

Scrum 将所有开发活动融合到每个迭代中，以适应在固定间隔内发现的现实情况：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/lrn-fp-go/img/caaf5d0e-29c2-4da5-a658-b3f33f3fd88c.png)

来源：[`scrumreferencecard.com/scrum-reference-card/`](http://scrumreferencecard.com/scrum-reference-card/)

在创建规格说明的过程中，通常会创建诸如**统一标记语言**（**UML**）图表之类的工件，以帮助我们思考问题并制定可行的解决方案。

分析是我们对现实世界操作进行建模，将部分分解为组件。设计是我们根据分析工作、我们的 IT 环境以及我们可以使用的框架/技术堆栈来制定软件解决方案的地方。

我们抽象出所有与问题无关的问题。因此，在分析和设计过程中，我们将问题分解成简单的组件。

实施是当我们将这些简单的事情重新组合在一起时。

### 良好的设计

良好的设计在长期节省资金。

如果我们的项目很小，上市时间的价值很高，那么我们可以跳过设计过程。否则，我们应该努力进行适当的软件设计。这是一个普遍的真理，无论技术如何（Java、Go 等）。

### 糟糕的设计

如果我们的应用架构图看起来像下面的图表，那么我们设计应用程序失败了：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/lrn-fp-go/img/a6e832c2-95c7-4d49-a93f-c7296b14ca4e.png)

简单并不容易，但值得努力。

我们给已经复杂的系统添加功能，它就会变得更加复杂。

在这样的系统中，我们不能一次只考虑一件事；我们必须一起考虑所有可能破坏我们系统的奇怪交互。

#### 随着时间的推移，好的设计与坏的设计

以下图表描述了随着时间的推移，良好设计的价值。与大多数图表一样，*x*轴表示时间的推移。我们在*y*轴上走得越高，我们的应用程序的功能和特性就越丰富。在**设计回报线**以下，没有设计或设计不良的应用程序可以迅速产生结果。

然而，缺乏设计会使应用程序变得脆弱、不可扩展且难以理解：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/lrn-fp-go/img/0fbf42cb-2919-46c8-afbe-022bf32f944c.png)

经过适当设计的应用程序可以轻松扩展，并且从长远来看更易于维护。

“超过 90%的软件成本发生在维护阶段。”

- 弗雷德·布鲁克斯，《神话般的程序员月度》

## SOLID 设计原则

**面向对象编程**（**OOP**）的 SOLID 设计原则适用于设计 Go 软件解决方案。

### 单一职责原则

单一职责原则说，*只做一件事，并且做得很好*。我们在 Go 标准库中看到了 SRP 的运作。以下是一些例子：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/lrn-fp-go/img/9de5a3cb-267f-4651-854b-ec515262c8d6.png)

如果一个拉取请求增强了`aes/crypto`包，你会期望那段代码合并会影响`database/sql/driver`包（或任何包）的功能吗？不会。当然不会。每个包都有明确定义的名称空间和高度内聚；它们执行特定的任务，不会涉及其他问题。

“一个类应该只有一个原因来进行更改。”

- 罗伯特 C·马丁

当马丁先生说一个类只应该有一个更改原因时，显然他是在谈论 OOP 设计，但同样的原则也适用于我们的 Go 应用程序。税收计算更新是否会影响用户界面或任何报告的布局，而不仅仅是显示不同的金额？不会。为什么？因为一个是化妆品的性质，另一个不是。这是两个应该由不同的、松散耦合的类/模块处理的不同责任。

我们的类/模块应该高度内聚，尽可能扮演特定的角色。具有单一职责的代码可以更好地处理变化的需求，而不会对应用程序的其他部分产生不利影响。如果我们有一个更改类/模块的请求，由于它只做一件事情，那么更改的原因只能与它的一个责任有关。

SRP 的应用将使我们的设计朝着越来越小的接口发展。最终，我们将到达最终接口。只有一个方法的接口。例如，在第五章中，*使用装饰添加功能*，我们将看到 Go 的互补 Reader 和 Writer 接口：

```go
type Reader interface {
   Read(p []byte) (n int, err error)
}
type Writer interface {
   Write(p []byte) (n int, err error)
}
```

SRP 对 FP 的意义与 Unix 哲学一致。

“尽管这种哲学无法用一句话写出来，但它的核心思想是系统的力量更多来自程序之间的关系，而不是程序本身。许多 UNIX 程序在孤立状态下做的事情相当琐碎，但与其他程序结合起来，成为通用且有用的工具。”

- 罗布·派克

在λ演算中，每个函数都只有一个参数。它可能看起来像我们的纯函数接受多个参数，但实际上它只是对参数进行柯里化。我们的函数接受列表中的第一个参数，并返回一个接受其余参数的函数；它继续处理每个参数，直到它们全部被消耗。函数组合仅在每个函数只接受一个参数时有效。

```go
three := add(1, 2)
func add1 := + 1
three == add1(2)
```

这是当我们进行柯里化时发生的伪代码。它将一个两个参数的调用转换为一个参数的调用。柯里化存储数据（数字 1）和操作（加法运算符）以供以后使用。这与 OOP 中的对象有什么相似之处？

#### 函数组合

函数组合是将两个较小的函数组合成一个新函数的过程，以实现与两个较小函数相同目标的新函数。两种方式都可以将我们从`a`到`c`。下面，`f[1]`接受`a`并返回`b`。`f[2]`接受`b`并返回`c`。我们可以组合/合并这两个函数，并得到一个接受`a`并返回`c`的单个函数：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/lrn-fp-go/img/bc4b36c4-3ccb-48de-9ded-e28cabbe4bea.png)

函数组合是纯 FP 的基石；它允许我们从较小的抽象中构建更大的抽象。

### 开放/封闭原则

软件应该对扩展开放，但对修改关闭。在结构体中嵌入字段允许我们用另一个类型扩展一个类型。嵌入其他类型（`Car`）的对象（`CarWithSpare`）可以访问其字段和方法。`CarWithSpare`对象可以调用`Car`方法，但不能修改`Car`对象的方法。因此，Go 的类型虽然是*对扩展开放*，但是*对修改关闭*。让我们看一个例子：

```go
package car

import "fmt"

type Car struct {
   Make string
   Model string
}
func (c Car) Tires() int { return 4 }
func (c Car) PrintInfo() {
   fmt.Printf("%v has %d tires\n", c, c.Tires())
}
```

我们定义了我们的`Car`类型和两种方法，`Tires`和`PrintInfo`。接下来，我们将定义我们的`CarWithSpare`类型，并将`Car`类型作为未命名字段嵌入其中：

```go
type CarWithSpare struct {
   Car
}
func (o CarWithSpare) Tires() int { return 5 }
```

在我们的`main.go`文件中，我们创建了一辆本田雅阁，并调用了它的`PrintInfo`方法。预期返回`4`个轮胎。

接下来，我们创建了一辆丰田高地人，但当我们打印它的信息时，它打印出`4`个轮胎，而不是`5`。为什么？

```go
package main

import (
   . "car"
 "fmt"
)

func main() {
   accord := Car{"Honda", "Accord"}
   accord.PrintInfo()
   highlander := CarWithSpare{Car{"Toyota", "Highlander"}}
   highlander.PrintInfo()
   fmt.Printf("%v has %d tires", highlander.Car, highlander.Tires())
}
```

以下是输出：

```go
{Honda Accord} has 4 tires
{Toyota Highlander} has 4 tires
{Toyota Highlander} has 5 tires
```

这是因为`PrintInfo`是`Car`的一个方法，但由于`CarWithSpare`缺少该方法，当我们调用`highlander.PrintInfo`时，实际上执行的是`Car`的方法（而不是`CarWithSpare`）。

为了打印出我们的高地人实际的轮胎数量，我们必须通过在`fmt.Printf`语句中直接执行`highlander.Tires`来手动委托调用。

我们有其他选择吗？有。我们可以覆盖`PrintInfo`方法。换句话说，我们可以为我们的`CarWithSpare`定义一个`PrintInfo`方法，如下所示：

```go
func (c CarWithSpare) PrintInfo() {
   fmt.Printf("%v has %d tires\n", c, c.Tires())
}
```

以下是输出：

```go
{Honda Accord} has 4 tires
{Toyota Highlander} has 5 tires
{Toyota Highlander} has 5 tires
```

如果我们再次调用`accord.PrintInfo()`会发生什么？我们会得到以下输出：

```go
{Honda Accord} has 4 tires
```

因此，Go 允许我们：

+   隐式调用嵌入对象的方法（如果未定义）

+   手动委托调用我们对象的方法

+   覆盖嵌入对象的方法

方法重载呢？

不允许。如果我们尝试创建另一个具有不同参数签名的`PrintInfo`方法，Go 将抛出编译器错误：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/lrn-fp-go/img/c69cfca1-25fd-4055-91dd-7b326f92724b.png)

在下一章中使用装饰器模式，我们将看到如何在不修改现有代码的情况下扩展功能。

#### 函数式编程中的开放/封闭原则

与我们之前的 Go 示例类似，在基本类型（`Car`）中添加了一个新方法（`PrintInfo`），纯函数式编程语言也可以在不重新编译现有代码的情况下向现有数据类型添加新函数，并保持静态类型安全性。

*表达式问题*，也称为*可扩展性问题*，解决了软件语言能够以类型安全的方式向程序添加新方法和类型的能力。有关详细信息，请参见**特征导向软件开发**（**FOSD**）程序立方体，其中基本程序（在称为**软件产品线**的相关程序系列中）（[`softwareproductlines.com/`](http://softwareproductlines.com/)）逐步增加功能，以生成复杂程序。

以下图表显示了如何通过组合特性中的模型，然后将这些模型转换为可执行文件来构建程序：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/lrn-fp-go/img/bce0ef89-a861-4daf-b06f-d0e8e97fe10d.png)

FOSD 方法论主张，复杂系统可以通过逐步添加特性来构建，其中领域模型是函数和常量，程序则表示为表达式，可以生成执行特定任务的程序。

#### FantasyLand JavaScript 规范

`FantasyLand`项目规定了常见代数结构的互操作性：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/lrn-fp-go/img/cbf62a17-f972-4807-9f34-e4d2be56fee9.png)

层次图中的每个数据类型都称为代数数据类型，因为每个都由代数组成，即一组值、一组它所闭合的运算符以及它必须遵守的规则。

让我们来看一个简单的例子，Setoid。

##### Setoid 代数

以下是 Setoid 的规则：

| **规则名称** | **描述** |
| --- | --- |
| 自反性 | `a.equals(a) === true` |
| 对称性 | `a.equals(b) === b.equals(a)` |
| 传递性 | 如果`a.equals(b)`和`b.equals(c)`，那么`a.equals(c)` |
|  | 如果`b`不是相同的`Ord`，`lte`的行为是未指定的（建议返回 false）。`lte`必须返回一个布尔值（`true`或`false`）。 |

规则中使用的值是`a`、`b`和`c`。具有`Ord`的值必须提供一个`lte`方法。equals 方法是这个代数的运算符，它接受一个参数。

就是这样。就是这么简单！

##### Ord 代数

以下是`Ord`的规则：

| **规则名称** | **描述** |
| --- | --- |
| 全面性 | `a.lte(b)`或`b.lte(a)` |
| 反对称性 | 如果`a.lte(b)`和`b.lte(a)`，那么`a.equals(b)` |
| 传递性 | 如果`a.lte(b)`和`b.lte(c)`，那么`a.lte(c)` |
|  | `b`必须是与`a`相同的`Ord`的值。如果`b`不是相同的 Setoid，则 equals 的行为是未指定的（建议返回 false）。`equals`变量必须返回一个布尔值（`true`或`false`）。 |

规则中使用的值是`a`、`b`和`c`。具有 Setoid 的值必须提供一个`lte`方法。`lte`方法是这个代数的运算符，它接受一个参数。

从前面的图表中，我们可以看到`Ord`是一个 Setoid，所以`Ord`有一个`Equals`运算符，`Ord`必须遵守 Setoid 的规则，以及它自己的规则。

在我们的书中，我们将探讨 Haskell 的类型类层次结构，并研究 Functor、Monoid 和 Monad 代数。

#### 表达式问题

不同的语言以不同的方式解决表达式问题：

+   开放类

+   多方法

+   函子的余积

+   类型类

+   对象代数

它们解决的问题与我们在`CarWithSpare`示例中看到的问题相同；它关于如何在不必重新编译现有代码的情况下对现有数据类型添加新函数，并保持静态类型安全。

Go 对表达式问题有基本的支持。类型类、对象代数等不是 Go 标准库的一部分，但我们可以构建任何上述解决方案。这是一个很好的开始：[`github.com/SimonRichardson/wishful`](https://github.com/SimonRichardson/wishful)。

### Liskov 替换原则

用面向对象的术语来说，*Liskov 替换原则*表示相同类型或子类型的对象应该可以被替换，而不影响调用者。换句话说，当我们实现一个接口时，我们的类应该实现接口中定义的所有方法，并满足所有接口要求。简而言之，*满足接口契约*。

编译器将强制执行我们的方法具有正确的签名。LSP 更进一步要求我们的实现也应该具有与超类或接口的文档中陈述或暗示的相同的不变量、后置条件和其他属性。

#### 这个面向对象的方法很糟糕

这就是面向对象编程世界中方法契约的样子：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/lrn-fp-go/img/c5b55bae-d5da-4f4f-9c28-704136cc2e91.png)

我们的方法`m`接收一个`a`，进行一些处理并返回`b`。可能会发生异常，可能会被捕获和处理，也可能会返回错误。此外，为了使方法正确满足其契约，我们需要阅读文档（当然，文档总是完全准确和最新的……不是！）希望我们涵盖所有的前置条件、不变量和后置条件。

**不变量** 是方法的整个生命周期中必须始终为真的东西。例如，如果我们的类有一个持续时间成员变量，那个值必须始终是一个正浮点数。另一个例子可能是，我们的内部纬度和经度值必须始终在北半球。我们可以进一步编写不变量验证器私有方法，以确保我们的不变量符合其可接受值范围。

**前置条件** 是我们的方法在调用时必须为真的东西。例如，在执行我们的 `consummateMarriage` 方法之前，我们应该确保我们选择的 `wouldBeSpouse` 没有已经与他人结婚；否则，我们很可能会违反我们州的反多配偶制度。我们可能会通过执行另一个 `verifyPersonIsSingle` 方法来进行检查。

别忘了 **后置条件**。一个例子可能是：在执行我们的 `consummateMarriage` 方法之后，我们应该确保我们与之完婚的人实际上是我们结婚证书上的同一个人。与错误的人结婚可能会引发各种问题。

最后要处理的问题是 *副作用*。副作用是指当我们的方法改变除了它输出的 **b**（或错误）之外的东西时发生的情况。例如，如果我们的后置条件检查导致了私人调查公司的信用卡扣款，那么这个扣款就是一个副作用。

#### 我们的函数式编程函数闻起来像玫瑰

这是我们在函数式编程世界中的函数契约是什么样子的：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/lrn-fp-go/img/f8c89004-3ce4-4874-a7d3-1c6f8bf1a063.png)

看到区别了吗？我们几乎能闻到区别！嘿，等一下！（面向对象的程序员可能会想...）

这个纯函数缺少一些东西！这是一个不公平的比较！

没错。这不公平，但这是现实。

而使它变得真实的是我们的输入类型。

#### 在函数式编程中，契约不会说谎

让我们看一个命令式代码的例子：

```go
type Dividend struct {
   Val int
}
func (n Dividend) Divide(divisor int) int {
   return n.Val/divisor
}

func main() {
   d := Dividend{2}
   fmt.Printf("%d", d.Divide(0))
}
```

在上述代码中，我们的契约是什么？

契约就是我们方法的签名：`func (n Dividend) Divide(divisor int) int`

我们的契约必须回答哪三个问题？

1.  我们的契约期望什么？

+   答案：它期望以下内容：

+   `Dividend.Val` 要填充一个 `int`

+   被除数是一个 `int`

1.  我们的契约保证了什么？

+   答案：它承诺返回一个整数

1.  契约维护什么？

+   答案：在这种简单情况下不适用

当我们运行上述代码时会发生什么？

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/lrn-fp-go/img/5038ec59-b333-44ea-b460-d7b21aad6d94.jpg)

我们得到了一个运行时恐慌！我们的契约是否成立，还是对我们说谎了？

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/lrn-fp-go/img/cbe891bd-f5ad-4179-bf03-b790f2864753.jpg)

在纯函数式编程中，我们不依赖于像 int、char 或者 string 这样低级的类型。我们利用了一个令人惊叹的类型类系统的全部威力。

在像 Haskell 这样的纯函数式语言中，我们可以定义一个 `PostiveInt` 类型。因此，我们不需要编写一个验证输入参数是否为正数的方法，而是定义一个名为 `PostiveInt` 的类型，它保证只有正整数会被输入：

```go
PositiveInt :: Int -> Maybe Positive
PositiveInt n = if (n < 0) then Nothing else Just (Positive n)
```

在函数式编程术语中，LSP 表示，*契约不会说谎*；

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/lrn-fp-go/img/1918b05d-8512-4ff6-8a1e-24409f2f2c1d.png)

在函数式编程中，我们不必依赖于我们的测试套件来验证我们的应用程序是否正确地执行了它的要求。在函数式编程中，假设我们已经正确地设计了我们的软件，如果它编译通过，那么它就是正确的。我们让我们的类型系统来执行我们的要求。

在面向对象的追求关系中，输入（候选配偶）只被验证为女性。当我们后来发现她不是合适的类型的女人时，也就是说，她已经结婚了，那将使婚姻契约无效。

这就是当我们没有正确地对输入进行类型检查时会发生的情况：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/lrn-fp-go/img/3faef2ce-0e74-4a8d-ac69-6bbd2f383021.png)

这是我们使用纯函数式编程时的情况：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/lrn-fp-go/img/7221c37a-6cd4-4cdc-9b63-b1783c0334d4.png)

看起来很简单，但是外部交互在哪里，比如可能导致离婚的姻亲？孩子呢？他们不就是我们可能称之为婚姻的副作用吗？

单子提供了一种让我们的夫妇与外部世界互动的方式；处理可能有害的影响并产生美丽的副作用。它看起来像这样：

！[](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/lrn-fp-go/img/388f97d1-8e42-4bc1-800d-eaab913cdd74.png)

单子的诀窍在于所有外部交互都被包含在内（在盒子里）。我们将在最后一章深入讨论单子。

这本书是关于在 Go 中学习*函数*编程的。因此，我们将全面理解术语*函数*的含义。函数不仅意味着*纯*。如果我们使用函数，我们就是在进行函数式编程。Go 是一种多范式语言，不强迫我们完全纯粹或完全命令式。如今绝大多数 Go 代码都是命令式的...以标准库为例。实现纯函数式编程技术有其时机和场合。我们越了解 Go 的所有函数能力和纯函数式编程概念，我们就越能够谨慎地应用适当的编码风格来满足我们的应用开发需求。

让我们看看鸭子类型示例中的 LSP 的工作。

#### 鸭子类型

Go 没有继承或子类型，但我们有接口。实现接口方法的函数隐式满足接口合同。

Go 支持所谓的**鸭子类型**。如果它走起来像鸭子，叫起来像鸭子，那么它就是鸭子。换句话说，如果我们有一个具有实现 Duck 接口的方法的 Go 结构体，也就是说，如果它有`Walk()`和`Quack()`方法，那么在所有意图和目的上，我们的结构体就是一只鸭子。

在面向对象的语言中，比如 Java，我们会被诱惑设计我们的鸭子如下。

#### 继承可能出现什么问题？

我们被告知鸭子可以走路和呱呱叫。因此，我们在我们的父类中实现了这些行为，即`Duck`：

！[](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/lrn-fp-go/img/d8043e18-a4e1-416a-99e9-0f5f89fae01a.png)！[](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/lrn-fp-go/img/77ddb2f7-0c9e-41a0-841c-725d1269d4b5.png)

我们从`Mallard`和`BlueBilled`鸭子开始。我们能够通过继承重用`walk()`和`quack()`方法。

接下来，我们听说鸭子可以飞。因此，我们在我们的`Duck`类中实现飞行行为，所有子类都继承了这种新行为：

！[](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/lrn-fp-go/img/66326981-6c3b-4519-8e8a-bf44d140669b.png)

一切都很好，直到我们将`Pekins`鸭子加入我们的群体。

我们在原始设计中没有考虑到的问题是，大多数国内饲养的鸭子不能飞行：

！[](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/lrn-fp-go/img/1035156e-db0e-485e-b1a2-cd2fc956fd05.png)！[](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/lrn-fp-go/img/28bc566a-6b96-490f-8641-8b909a4c9c82.png)

对我们来说，这种设计缺陷甚至在 Go 中都不可能发生！

我们通过使用接口来模拟 Go 中的行为（Go 不支持继承）。

#### 接口隔离原则

最好有很多单一用途的接口，而不是一个通用接口。我们的 API 不应该接受它不需要的结构的引用，反之亦然，我们的客户端实现不应该依赖于它不使用的代码。

我们很快就会在我们的 Viva La Duck 代码示例中看到这一点，以独立的`EatBehavior`和`StrokeBehavior`接口的形式。

当我们严格应用集成隔离原则时，我们最终得到了只有一个方法的接口。这样的对象代表了具有行为的数据，但它也可以被建模为具有数据的行为，这就是 FP 中闭包的作用。

这是另一个地方，如果 Go 支持泛型将会很好。为什么要创建处理`Int`类型、`Customers`或`AvailableWomen`切片的样板代码，当一个`T`的枚举就可以工作（代码更少）？

#### 依赖反转原则

**依赖反转原则**（**DIP**）指出我们应该依赖于抽象，而不是具体实现。DIP 是关于从我们的代码中移除硬编码的依赖关系。

例如，以下代码违反了 DIP：

```go
import "theirpkg"

func MyFunction(t *theirpkg.AType)

func MyOtherFunction(i theirpkg.AnInterface)
```

`MyOtherFunction`函数并不像`MyFunction`函数那样糟糕，但两种实现都将我们的实现与另一个包的类型和接口耦合在一起。

一般来说，良好的软件设计依赖于高内聚性，我们编写的函数只做一件事，并且做得很好，并且松散耦合。

在纯函数式编程中，通过传递部分应用的函数来实现依赖注入。有些人称之为*好莱坞原则*，就像是，“不要打电话给我们，我们会打电话给你”。在 JavaScript 中，这通常是使用回调来实现的。

请注意，回调和继续之间存在微妙的区别。回调函数可能在应用程序的流程中被多次调用，每次它们都会返回一个结果，处理会继续进行。当一个函数调用另一个函数作为其最后一件事时，第二个函数被称为第一个函数的继续。

## 大揭示

单子链继续。

还记得本章前面*Fantasy Land*代数的层次图中的单子吗？

我们将在本书的最后一个单元中更多地讨论单子，但现在让我们来看一下整体情况。

之前我们看到了函数的组合：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/lrn-fp-go/img/ef811db8-5f67-4b7b-a928-1dc30db9cbfe.png)

这实际上是一个问题，因为这不是一个单子。单子看起来像这样：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/lrn-fp-go/img/407d6776-83f1-4461-b0c3-3a57e09c632b.png)

这就是大揭示。单子是紫色的！

哈。抓住你了！

除了颜色，你还能看到单子函数和上面的函数之间的不同之处吗？

那么**a**进入和**a**出来怎么办？这意味着如果单子接受类型为**A**的参数（按照惯例，小写**a**变量是类型 A 的值），那么它将产生另一个**a**值。

猜猜那叫什么？当我们的函数返回与其输入相同的类型时？我们称之为*端态*，其中*en*表示*相同*，*morphism*表示*函数*；因此，它从**a**变为**a**。简单。

在*单子链继续*语句中使用的*链*一词是什么意思？

一个漂亮的单子紫色链函数呢？

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/lrn-fp-go/img/1b5e9082-3668-4085-b455-ccc7c63013fe.png)

这个紫色单子链还有什么其他信息？

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/lrn-fp-go/img/d74237cb-add8-4d04-b161-a28429f5e04a.png)

如果所有函数都是单子，那么我们可以以任何顺序组合它们（结合律规则）。

很好，但是我们可以用单子链做些什么？我们可以并行运行这些进程吗？

并行运行？嗯，这取决于我们正在处理什么。许多事情可以并行运行。

理论上是可以的，但在实践中，我们需要处理与其他 Map/Reduce 解决方案（如 Hadoop）相同的考虑。

### MapReduce

**MapReduce**是一种将大型数据集拆分为许多较小数据集的技术。每个小数据集都在不同的服务器上分别进行处理，然后将结果收集和聚合以产生最终结果。

它是如何工作的？

假设我们有很多网络服务器，我们想要确定它们所有的顶部请求页面。我们可以分析网络服务器访问日志，找到所有请求的 URL，对其进行计数，并对结果进行排序。

以下是 MapReduce 的良好用例：

+   从服务器收集统计信息，例如前 10 个用户，前 10 个请求的 URL

+   计算数据中所有关键字的频率

以下是不适合 MapReduce 的用例：

+   需要共享状态的作业

+   查找单个记录

+   小数据

#### MapReduce 示例

假设我们有一个 Apache 网络服务器访问日志文件，其中的条目看起来像这样：

```go
198.0.200.105 - - [14/Jan/2014:09:36:51 -0800] "GET /example.com/music/js/main.js HTTP/1.1" 200 614 "http://www.example.com/music/" "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_9_1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/31.0.1650.63 Safari/537.36"
```

如果我们想知道前 5 个最常访问的 JSON 文件呢？

我们可以直接从终端使用标准的 Unix 字符串处理命令执行 MapReduce：

```go
$ cat access10k.log | while read line; do echo "$line" | awk '{print $7}' | grep "\.json";done | sort | uniq -c | sort -nr
 234 /example.com/music/data/artist.json
 232 /example.com/music/data/songs.json
 227 /example.com/music/data/influencers.json
  28 /example.com/music-no-links/data/songs.json
  28 /example.com/music-no-links/data/influencers.json
  28 /example.com/music-no-links/data/artist.json
   8 /example.com/music/data/influencers2.json
```

这对几千行来说效果很好。如果我们在最后一个命令前面输入`time`，我们会得到以下类似的结果：

```go
real 1m3.932s
user 0m38.125s
sys 0m42.863s
```

但是如果每个服务器有数百万行代码，而我们有很多服务器呢？

是时候进行 MapReduce 了！

在每个服务器上，我们可以执行我们的映射；将日志文件条目作为输入，产生一组键值对：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/lrn-fp-go/img/ae767c19-be83-409f-883e-8490b2595472.png)

接下来，我们将从每个服务器的每个中间结果中提取数据，并将它们馈送到我们的`reduce`函数中，然后输出结果：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/lrn-fp-go/img/0d6ed4e7-cfdc-45d2-88b8-b811c23bac9c.png)

我们的前 5 个最常请求的 JSON 文件可能是这样的：

```go
85733 /example.com/music/data/artist.json
71938 /example.com/music/data/songs.json
57837 /example.com/music/data/influencers.json
17500 /example.com/music-no-links/data/songs.json
17500 /example.com/music-no-links/data/influencers.json
```

我们可以从这个例子中得到什么？看起来 MapReduce 的好候选包括以下用例：

+   我们有如此多的数据，如果在一个服务器上顺序运行所有数据将花费太长时间

+   我们的输出，来自`map`阶段，包括一系列键值对

+   我们可以独立运行每个`map`或`reduce`函数，知道我们函数的输出仅依赖于其输入

但这里还有什么其他可能不太明显的事情？

还有什么使 Map/Reduce 工作的过程？

FP 模式在阴影中潜伏着什么？（提示：我们已经看到了它，它与数据类型有关。）

### Monad 还能做什么？

Monad 可以用来清晰地传达我们的业务逻辑，并管理我们应用程序的处理流程等。

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/lrn-fp-go/img/68aa7767-20aa-4a2f-8f40-89b44386c2af.jpg)

你知道我在说什么。考虑以下代码片段：

```go
if err != nil {
   return nil, fmt.Errorf("%s:%d: %v", sourceFile, sourceLine, err)
}
```

那些`if err != nil`块遍布我们的代码，并且遮蔽了我们代码的原始意图。如果这是我们的正常路径代码：

```go
happy path code
```

在我们添加错误检查之后，它看起来是这样的：

```go
add error checking
```

猜猜我们的 FP 代码在包含错误处理后会是什么样子？

```go
FP code including error handling
```

这怎么可能？没有内联错误检查？我们将在第九章中涵盖这个主题，*函子、单子和泛型*。

## Viva La Duck

我们的下一个代码示例将说明我们的 Go 实现应用了几个 SOLID 设计原则。

在我们的 Viva La Duck 应用程序中，我们的鸭子必须访问许多池塘寻找要吃的虫子。为了保持简单，我们假设每一次划水都需要鸭子吃一只虫子。每次鸭子划动脚（一次划水），鸭子的划水次数就会减少一次。

我们不关心鸭子如何从一个池塘到另一个池塘，而是鸭子必须划多少次才能穿过池塘的长度。如果池塘有虫子吃，它们将在池塘的另一边找到。如果鸭子耗尽了能量，它就会死去。

我们的程序是一个独立的可运行的 Go 源文件。它的包名是`main`，并且有一个`main()`函数。我们将在以后使用`DASHES`常量，用于打印每个池塘中鸭子遇到的统计信息。

`Pond`结构包含了每个池塘的状态，即鸭子要吃的虫子数量以及穿过池塘所需的划水次数：

```go
package main

import (
       "fmt"
 "errors"
 "log"
)
const DASHES = "----------------------"

type Pond struct {
       BugSupply       int
       StrokesRequired int
}
```

我们应该做的第一件事之一是以简单接口的形式定义我们系统的行为。我们应该考虑如何将我们的接口嵌入到更大的一组接口中，因为我们组合我们系统的行为模式。按照能力对事物进行分类是有意义的，因为事物是由其行为定义的。

由于这是一本关于函数式编程的书，现在是时候提到使用接口的一个主要好处了，那就是它们允许我们将应用程序的函数分组，以模拟现实生活中的行为：

```go
type StrokeBehavior interface {
       PaddleFoot(strokeSupply *int)
}

type EatBehavior interface {
       EatBug(strokeSupply *int)
}
```

每个接口（`StrokeBehavior`和`EatBehavior`）代表了一个细粒度、明确定义的行为。将系统分解成小部分将使我们的应用程序更加灵活和更容易组合：

```go
type SurvivalBehaviors interface {
       StrokeBehavior
       EatBehavior
}
```

通过声明小而单一目的的接口，我们现在可以自由地将它们嵌入到新的、更丰富功能的接口中。

将接口分组是我们可以在 Go 标准库中找到的常见模式。例如，在`httputil`包中，我们找到以下内容：

`type writeFlusher interface {`

`io.Writer`

`http.Flusher`

`}`

接下来，我们定义我们的鸭子。我们的鸭子是无状态的，没有字段：

```go
type Duck struct{}
```

我们为我们的鸭子定义了两种方法。接收器`Duck`必须在与我们的方法`Stroke`相同的包中定义。由于我们只使用了一个主包，这不是问题。

在模拟现实世界之后，我们定义了一个`Foot`结构和一个`PaddleFoot`方法。每当我们的鸭子划动它的脚时，我们都会减少我们鸭子的“划水次数”类型：

```go
type Foot struct{}
func (Foot) PaddleFoot(strokeSupply *int) {
       fmt.Println("- Foot, paddle!")
       *strokeSupply--
}
```

类似地，我们定义了一个`Bill`类型及其`EatBug`方法，它增加了我们鸭子的“划水次数”类型。

```go
type Bill struct{}
func (Bill) EatBug(strokeSupply *int) {
       *strokeSupply++
       fmt.Println("- Bill, eat a bug!")
}
```

对于每一次划水，我们的鸭子都会划动它的脚。

如果鸭子耗尽能量并被困在池塘中，我们的`Stroke`方法将返回一个错误：

```go
func (Duck) Stroke(s StrokeBehavior, strokeSupply *int, p Pond) (err error) {
       for i := 0; i < p.StrokesRequired; i++ {
              if *strokeSupply < p.StrokesRequired - i {
                     err = errors.New("Our duck died!")
              }
              s.PaddleFoot(strokeSupply)
       }
       return err
}
```

现在，我们定义我们鸭子的吃东西行为。当我们的鸭子到达池塘的尽头时，它可以吃掉池塘里的所有虫子：

```go
func (Duck) Eat(e EatBehavior, strokeSupply *int, p Pond) {
       for i := 0; i < p.BugSupply; i++ {
              e.EatBug(strokeSupply)
       }
}
```

`SwimAndEat`方法的签名与`Eat`和`Stroke`方法略有不同。注意到了吗？

所有三种方法都有一个`Duck`作为它们的接收器，但是`SwimAndEat`方法定义了变量`d`。这是因为我们需要在`SwimAndEat`方法中引用`Stroke`和`Eat`方法。

此外，它们都将一个接口作为它们的第一个参数，但是`SwimAndEat`将一个组合的接口集合，即`StrokeAndEatBehaviors`，作为它的第一个参数，它在`Stroke`和`Eat`中使用多态：

```go
func (d Duck) SwimAndEat(se SurvivalBehaviors, strokeSupply *int, ponds []Pond) {
       for i := range ponds {
              pond := &ponds[i]
              err := d.Stroke(se, strokeSupply, *pond)
              if err != nil {
                     log.Fatal(err)  // the duck died!
 }
              d.Eat(se, strokeSupply, *pond)
       }
}
```

### 通过值传递还是引用传递？

这是一个经验法则——如果你想共享一个状态，那么通过引用传递，也就是使用指针类型；否则，通过值传递。由于我们需要在这个“划水”方法中更新我们鸭子的“划水次数”类型，我们将其作为`int`指针（*int）传递。因此，只有在绝对必要时才传递指针参数。我们应该开始进行防御性编码，假设有人可能尝试同时运行我们的代码。当我们通过值传递参数时，可以安全地进行并发使用。当我们通过引用传递时，可能需要添加`sync.mutex`或一些通道来协调并发。

我们的鸭子通过吃更多从池塘中获得的虫子来恢复能量：

```go
func (Duck) Eat(e EatBehavior, strokeSupply *int, p Pond) {
       for i := 0; i < p.BugSupply; i++ {
              e.EatBug(strokeSupply)
       }
}
```

由于我们正在设计我们的软件应用程序来模拟现实世界，鸭脚和鸭嘴等事物是代表真实物体的结构名称的自然候选者。脚用于划水，鸭嘴用于吃虫子。每一次划水，也就是“划”，都会减少我们鸭子的可能划水次数。每只虫子值一次划水。

我们告诉我们鸭子的脚划水。只要鸭子有能量，也就是说，它的“划水次数”类型大于零，鸭子就会服从。但是，如果“划水次数”为零，那么我们的鸭子在到达下一批要吃的虫子之前将被困在池塘中：

```go
type Foot struct{}
func (Foot) PaddleFoot(strokeSupply *int) {
       fmt.Println("- Foot, paddle!")
       *strokeSupply--
}
```

注意，我们正在传递一个指向我们划水次数的指针。这意味着我们的应用程序正在维护一个状态。我们知道纯函数式编程不允许变量突变。这没关系，因为本章是关于使用 Go 进行良好软件设计的。Go 中的纯函数式编程在第一章中有介绍，“Go 中的纯函数式编程”：

```go
type Bill struct{}
func (Bill) EatBug(strokeSupply *int) {
       *strokeSupply++
       fmt.Println("- Bill, eat a bug!")
}
```

对于我们的鸭子遇到的每一个池塘，它都必须游泳并吃虫子才能生存。

由于我们的鸭子的`SwimAndEat`方法需要`StrokeBehavior`和`EatBehavior`，我们将`SurvivalEatBehaviors`接口集合作为它的第一个参数传递：

```go
func (d Duck) SwimAndEat(se SurvivalBehaviors, strokeSupply *int, ponds []Pond) {
       for i := range ponds {
              pond := &ponds[i]
              err := d.Stroke(se, strokeSupply, pond)
              if err != nil {
                     log.Fatal(err)  // the duck died!
 }
              d.Eat(se, strokeSupply, pond)
       }
}
```

回想一下，鸭子的`Stroke`方法接受的是`StrokeBehavior`，而不是`StrokeEatBehavior`！这怎么可能？这是类型嵌入的魔力的一部分。

### 使用 Go 接口进行类型嵌入

Go 允许我们在另一个类型内部声明一个类型。在我们的`SurvivalBehaviors`接口中，我们声明了两个类型接口的字段。通过内部类型提升，Go 编译器执行接口转换，内部接口成为外部接口的一部分。

```go
type SurvivalBehaviors interface {
       StrokeBehavior
       EatBehavior
}
```

`d.Stroke`函数接受`SurvivalBehaviors`类型，就好像它接收了`StrokeBehavior`，`d.Eat`函数接受`SurvivalBehaviors`类型，就好像它接收了`EatBehavior`。

这意味着外部类型`SurvivalBehaviors`现在实现了`StrokeBehavior`和`EatBehavior`的接口。

#### 嵌入接口以添加次要功能

这是另一个使用接口嵌入的例子：

```go
type BytesReadConn struct {
   net.Conn
   BytesRead uint64
}

func (brc *BytesReadConn) Read(p []byte) (int, error) {
   n, err := brc.Conn.Read(p)
   brc.BytesRead += uint64(n)
   return n, err
}
```

通过在我们的`BytesReadConn`中嵌入`net.Conn`，我们能够重写它的`Read`方法，不仅执行`Conn.Read`操作，还能计算读取的字节数。

现在我脑中响起了一首 ELO 的歌。

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/lrn-fp-go/img/2d409a5b-5a74-46ce-89fa-cdd3259201bf.png)

### Go 错误处理习惯

我们的代码中还有另一个常见的 Go 模式：

```go
err := d.Stroke(se, strokeSupply, pond)
if err != nil {
       log.Fatal(err)  // the duck died!
}
```

错误应该尽快处理一次。

有些人认为这是一种在代码中充斥着`if err != nil`块的反模式。我们暂时忽略这种情绪，而更看重它的简单和实用性。

接下来，我们将定义一个`Capabilities`结构，其中嵌入了行为接口和所有重要的力量字段。`Capabilities`类型定义了鸭子能做什么。它有一些力量，可以用来穿过每个池塘，还有两种行为——一种增加它的力量计数，另一种减少计数但帮助它接近下一个食物来源：

```go
type Capabilities struct {
       StrokeBehavior
       EatBehavior
       strokes int
}
```

在 Go 中，嵌入/内部接口的任何方法或字段都可以被外部接口访问。请注意，我们并不是说父类或子类，因为那可能会暗示继承。我们所拥有的是内部类型提升，而不是继承。只要内部字段或方法的名称以大写字母开头，它就可以被外部对象访问。

### 现在是运行我们的程序的时候了

现在，是时候为鸭子提供它的起始资源和一系列要游过的池塘，看看我们的鸭子是否能活下来了。

假设我们的鸭子肚子里有五只虫子，价值五个力量（我们让我们的池塘和虫子非常小，以简化我们的模型）：

```go
func main() {
       var duck Duck
       capabilities := Capabilities{
              StrokeBehavior: Foot{},
              EatBehavior:    Bill{},
              strokes:        5,
       }
```

我们鸭子的第一组池塘将包括两个池塘。每个池塘只提供一种虫子。第一个池塘需要三个力量才能到达另一边。第二个池塘需要两个力量：

```go
ponds := []Pond{
       {BugSupply: 1, StrokesRequired: 3},
       {BugSupply: 1, StrokesRequired: 2},
}
duck.SwimAndEat(&capabilities, &capabilities.strokes, ponds)
displayDuckStats(&capabilities, ponds)
```

对鸭子的`SwimAndEat`方法的调用使用了其能力的地址，因为我们希望在鸭子从一个池塘到另一个池塘时共享鸭子的`Capabilities`对象。

在每天结束时，鸭子穿过每个池塘并吃到它找到的虫子后，我们会显示鸭子的统计数据：

```go
func displayDuckStats(c *Capabilities, ponds []Pond) {
       fmt.Printf("%s\n", DASHES)
       fmt.Printf("Ponds Processed:")
       for _, pond := range ponds {
              fmt.Printf("\n\t%+v", pond)
       }
       fmt.Printf("\nStrokes remaining: %+v\n", c.strokes)
       fmt.Printf("%s\n\n", DASHES)
}
```

这是输出：

```go
- Foot, paddle!
- Foot, paddle!
- Foot, paddle!
- Bill, eat a bug!
- Foot, paddle!
- Foot, paddle!
- Bill, eat a bug!
----------------------
Ponds Processed:
{BugSupply:1 StrokesRequired:3}
{BugSupply:1 StrokesRequired:2}
Strokes remaining: 2
----------------------
```

第一天结束时，鸭子穿过了两个池塘，并有两个力量储备来开始新的一天。

第二天，我们的鸭子只有一个池塘要游过。我们的鸭子肚子里有两只虫子。这个池塘里有两只虫子。让我们看看我们的鸭子是否能到达另一边：

```go
ponds = []Pond{
       {BugSupply: 2, StrokesRequired: 3},
}
duck.SwimAndEat(&capabilities, &capabilities.strokes, ponds)
displayDuckStats(&capabilities, ponds)
```

这是输出：

```go
- Foot, paddle!
- Foot, paddle!
- Foot, paddle!

2017/05/12 19:11:51 Our duck died!
exit status 1
```

不幸的是，我们的鸭子没有足够的力量穿过池塘。真遗憾！

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/lrn-fp-go/img/e5d3a692-3c9e-4e87-b266-f0e6098cf409.png)

我们故事的寓意如下：

+   以有意义的方式（如真实世界）对应用进行建模

+   首先，创建一组行为，作为单一职责接口类型

+   将简单的接口类型组合成更大、更一致的行为集

+   确保每个函数只接受它所需的行为类型

+   不要成为一只鸭子

## 摘要

在本章中，我们看到了如何在 Java 中使用继承的不良设计，并将该解决方案与在 Go 中使用组合进行了对比。

**四人帮**（GoF）的史诗之作，*设计模式：可复用面向对象软件的基本元素*，讨论了解决像 Java 这样的面向对象语言中的设计缺陷的设计模式。例如，在*将重用机制投入实际*一节中，GoF 书中指出，*更偏爱对象组合而不是类继承*。

这个设计原则甚至不适用于 Go。Go 不支持继承。Go 开发人员不需要额外的思考或工作。Go 默认支持组合。

“这些组合技术赋予了 Go 其特色，这与 C++或 Java 程序的特色截然不同。”

- Rob Pike

组合是一种软件设计模式，我们应该用它来构建更好的 API。

我们首先将系统分解为小部分：单一职责接口。然后我们可以将这些部分重新组合在一起。当我们使用组合来设计我们的 API 时，我们的应用程序有更好的机会适应随时间可能发生变化的需求。我们的应用程序变得更容易理解和维护。

在下一章中，我们将坚持追求良好的设计，并将专注于装饰器模式。我们将研究 Go 语言的`Reader`和`Writer`接口，并看到为什么“少即是多”。我们将实现通道以控制并发程序的生命周期等等。
