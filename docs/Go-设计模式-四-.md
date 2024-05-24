# Go 设计模式（四）

> 原文：[`zh.annas-archive.org/md5/8A110D02C69060149D76F09768570714`](https://zh.annas-archive.org/md5/8A110D02C69060149D76F09768570714)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第七章：行为模式 - 访问者，状态，中介者和观察者设计模式

这是关于行为模式的最后一章，也是本书关于 Go 语言中常见的、众所周知的设计模式的部分的结束。

在本章中，我们将研究另外三种设计模式。当您想要从一组对象中抽象出一些功能时，访问者模式非常有用。

状态通常用于构建**有限状态机**（**FSM**），在本节中，我们将开发一个小的*猜数字*游戏。

最后，观察者模式通常用于事件驱动的架构，并且在微服务世界中再次获得了很多关注。

在本章之后，我们需要在深入并发和它带来的设计模式的优势（和复杂性）之前，对常见的设计模式感到非常舒适。

# 访问者设计模式

在下一个设计模式中，我们将把对象类型的一些逻辑委托给一个名为访问者的外部类型，该类型将访问我们的对象以对其执行操作。

## 描述

在访问者设计模式中，我们试图将与特定对象一起工作所需的逻辑与对象本身分离。因此，我们可以有许多不同的访问者对特定类型执行某些操作。

例如，想象一下我们有一个写入控制台的日志记录器。我们可以使记录器“可访问”，以便您可以在每个日志前添加任何文本。我们可以编写一个访问者模式，它将日期、时间和主机名添加到对象中存储的字段。

## 目标

在行为设计模式中，我们主要处理算法。访问者模式也不例外。我们试图实现的目标如下：

+   将某种类型的算法与其在其他类型中的实现分离

+   通过使用一些类型来提高其灵活性，几乎不需要任何逻辑，因此所有新功能都可以添加而不改变对象结构

+   修复会破坏类型中的开闭原则的结构或行为

您可能会想知道开闭原则是什么。在计算机科学中，开闭原则指出：*实体应该对扩展开放，但对修改关闭*。这个简单的状态有很多含义，可以构建更易于维护且不太容易出错的软件。访问者模式帮助我们将一些常常变化的算法从我们需要它“稳定”的类型委托给一个经常变化的外部类型，而不会影响我们的原始类型。

## 日志附加器

我们将开发一个简单的日志附加器作为访问者模式的示例。遵循我们在之前章节中的方法，我们将从一个极其简单的示例开始，以清楚地理解访问者设计模式的工作原理，然后再转向更复杂的示例。我们已经开发了类似的示例，但以稍微不同的方式修改文本。

对于这个特定的例子，我们将创建一个访问者，它会向“访问”的类型附加不同的信息。

## 验收标准

要有效地使用访问者设计模式，我们必须有两个角色--访问者和可访问者。`Visitor`是将在`Visitable`类型内执行的类型。因此，`Visitable`接口实现将算法分离到`Visitor`类型：

1.  我们需要两个消息记录器：`MessageA`和`MessageB`，它们将在消息之前分别打印带有`A：`或`B：`的消息。

1.  我们需要一个访问者能够修改要打印的消息。它将分别将文本“Visited A”或“Visited B”附加到它们。

## 单元测试

正如我们之前提到的，我们将需要`Visitor`和`Visitable`接口的角色。它们将是接口。我们还需要`MessageA`和`MessageB`结构：

```go
package visitor 

import ( 
  "io" 
  "os" 
  "fmt" 
) 

type MessageA struct { 
  Msg string 
  Output io.Writer 
} 

type MessageB struct { 
  Msg string 
  Output io.Writer 
} 

type Visitor interface { 
  VisitA(*MessageA) 
  VisitB(*MessageB) 
} 

type Visitable interface { 
  Accept(Visitor) 
} 

type MessageVisitor struct {} 

```

`MessageA` 和 `MessageB` 结构都有一个 `Msg` 字段来存储它们将要打印的文本。输出 `io.Writer` 将默认实现 `os.Stdout` 接口，或者一个新的 `io.Writer` 接口，就像我们将用来检查内容是否正确的接口一样。

`Visitor` 接口有一个 `Visit` 方法，分别用于 `Visitable` 接口的 `MessageA` 和 `MessageB` 类型。`Visitable` 接口有一个名为 `Accept(Visitor)` 的方法，将执行解耦的算法。

与以前的示例一样，我们将创建一个实现 `io.Writer` 包的类型，以便我们可以在测试中使用它：

```go
package visitor 

import "testing" 

type TestHelper struct { 
  Received string 
} 

func (t *TestHelper) Write(p []byte) (int, error) { 
  t.Received = string(p) 
  return len(p), nil 
} 

```

`TestHelper` 结构实现了 `io.Writer` 接口。它的功能非常简单；它将写入的字节存储在 `Received` 字段上。稍后我们可以检查 `Received` 的内容来测试是否符合我们的预期值。

我们将只编写一个测试，检查代码的整体正确性。在这个测试中，我们将编写两个子测试：一个用于 `MessageA`，一个用于 `MessageB` 类型：

```go
func Test_Overall(t *testing.T) { 
  testHelper := &TestHelper{} 
  visitor := &MessageVisitor{} 
  ... 
} 

```

我们将在每个消息类型的每个测试中使用一个 `TestHelper` 结构和一个 `MessageVisitor` 结构。首先，我们将测试 `MessageA` 类型：

```go
func Test_Overall(t *testing.T) { 
  testHelper := &TestHelper{} 
  visitor := &MessageVisitor{} 

  t.Run("MessageA test", func(t *testing.T){ 
    msg := MessageA{ 
      Msg: "Hello World", 
      Output: testHelper, 
    } 

    msg.Accept(visitor) 
    msg.Print() 

    expected := "A: Hello World (Visited A)" 
    if testHelper.Received !=  expected { 
      t.Errorf("Expected result was incorrect. %s != %s", 
      testHelper.Received, expected) 
    } 
  }) 
  ... 
} 

```

这是完整的第一个测试。我们创建了 `MessageA` 结构，为 `Msg` 字段赋予了值 `Hello World`，并为其传递了在测试开始时创建的 `TestHelper` 的指针。然后，我们执行它的 `Accept` 方法。在 `MessageA` 结构的 `Accept(Visitor)` 方法中，将执行 `VisitA(*MessageA)` 方法来改变 `Msg` 字段的内容（这就是为什么我们传递了 `VisitA` 方法的指针，没有指针内容将不会被持久化）。

为了测试 `Visitor` 类型在 `Accept` 方法中是否完成了其工作，我们必须稍后在 `MessageA` 类型上调用 `Print()` 方法。这样，`MessageA` 结构必须将 `Msg` 的内容写入提供的 `io.Writer` 接口（我们的 `TestHelper`）。

测试的最后一部分是检查。根据*验收标准 2*的描述，`MessageA` 类型的输出文本必须以文本 `A:` 为前缀，存储的消息和文本 `"(Visited)"` 为结尾。因此，对于 `MessageA` 类型，期望的文本必须是 `"A: Hello World (Visited)"`，这是我们在 `if` 部分进行的检查。

`MessageB` 类型有一个非常相似的实现：

```go
  t.Run("MessageB test", func(t *testing.T){ 
    msg := MessageB { 
      Msg: "Hello World", 
      Output: testHelper, 
    } 

    msg.Accept(visitor) 
    msg.Print() 

    expected := "B: Hello World (Visited B)" 
    if testHelper.Received !=  expected { 
      t.Errorf("Expected result was incorrect. %s != %s", 
        testHelper.Received, expected) 
    } 
  }) 
} 

```

实际上，我们刚刚将类型从 `MessageA` 更改为 `MessageB`，现在期望的文本是 `"B: Hello World (Visited B)"`。`Msg` 字段也是 `"Hello World"`，我们还使用了 `TestHelper` 类型。

我们仍然缺少正确的接口实现来编译代码并运行测试。`MessageA` 和 `MessageB` 结构必须实现 `Accept(Visitor)` 方法：

```go
func (m *MessageA) Accept(v Visitor) { 
  //Do nothing 
} 

func (m *MessageB) Accept(v Visitor) { 
  //Do nothing 
} 

```

我们需要实现在 `Visitor` 接口上声明的 `VisitA(*MessageA)` 和 `VisitB(*MessageB)` 方法。`MessageVisitor` 接口是必须实现它们的类型：

```go
func (mf *MessageVisitor) VisitA(m *MessageA){ 
  //Do nothing 
} 
func (mf *MessageVisitor) VisitB(m *MessageB){ 
  //Do nothing 
} 

```

最后，我们将为每种消息类型创建一个 `Print()` 方法。这是我们将用来测试每种类型的 `Msg` 字段内容的方法：

```go
func (m *MessageA) Print(){ 
  //Do nothing 
} 

func (m *MessageB) Print(){ 
  //Do nothing 
} 

```

现在我们可以运行测试，真正检查它们是否已经失败：

```go
go test -v .
=== RUN   Test_Overall
=== RUN   Test_Overall/MessageA_test
=== RUN   Test_Overall/MessageB_test
--- FAIL: Test_Overall (0.00s)
 --- FAIL: Test_Overall/MessageA_test (0.00s)
 visitor_test.go:30: Expected result was incorrect.  != A: Hello World (Visited A)
 --- FAIL: Test_Overall/MessageB_test (0.00s)
 visitor_test.go:46: Expected result was incorrect.  != B: Hello World (Visited B)
FAIL
exit status 1
FAIL

```

测试的输出很清楚。期望的消息是不正确的，因为内容是空的。现在是创建实现的时候了。

## 访问者模式的实现

我们将开始完成 `VisitA(*MessageA)` 和 `VisitB(*MessageB)` 方法的实现：

```go
func (mf *MessageVisitor) VisitA(m *MessageA){ 
  m.Msg = fmt.Sprintf("%s %s", m.Msg, "(Visited A)") 
} 
func (mf *MessageVisitor) VisitB(m *MessageB){ 
  m.Msg = fmt.Sprintf("%s %s", m.Msg, "(Visited B)") 
} 

```

它的功能非常简单- `fmt.Sprintf` 方法返回一个格式化的字符串，其中包含 `m.Msg` 的实际内容、一个空格和消息 `Visited`。这个字符串将被存储在 `Msg` 字段上，覆盖先前的内容。

现在我们将为每种消息类型开发 `Accept` 方法，该方法必须执行相应的 Visitor：

```go
func (m *MessageA) Accept(v Visitor) { 
  v.VisitA(m) 
} 

func (m *MessageB) Accept(v Visitor) { 
  v.VisitB(m) 
} 

```

这段小代码有一些含义。在这两种情况下，我们都使用了一个`Visitor`，在我们的例子中，它与`MessageVisitor`接口完全相同，但它们可以完全不同。关键是要理解访问者模式在其`Visit`方法中执行处理`Visitable`对象的算法。`Visitor`可能在做什么？在这个例子中，它改变了`Visitable`对象，但它也可以简单地从中获取信息。例如，我们可以有一个`Person`类型，有很多字段：姓名、姓氏、年龄、地址、城市、邮政编码等等。我们可以编写一个访问者，仅从一个人中获取姓名和姓氏作为唯一的字符串，一个访问者从应用程序的不同部分获取地址信息，等等。

最后，有一个`Print()`方法，它将帮助我们测试这些类型。我们之前提到它必须默认打印到`Stdout`：

```go
func (m *MessageA) Print() { 
  if m.Output == nil { 
    m.Output = os.Stdout 
  } 

  fmt.Fprintf(m.Output, "A: %s", m.Msg) 
} 

func (m *MessageB) Print() { 
  if m.Output == nil { 
    m.Output = os.Stdout 
  } 
  fmt.Fprintf(m.Output, "B: %s", m.Msg) 
} 

```

首先检查`Output`字段的内容，以便在`os.Stdout`调用的输出为空时将其赋值。在我们的测试中，我们在那里存储了一个指向我们的`TestHelper`类型的指针，因此在我们的测试中永远不会执行这行。最后，每个消息类型都会将存储在`Msg`字段中的完整消息打印到`Output`字段。这是通过使用`Fprintf`方法完成的，该方法将`io.Writer`包作为第一个参数，要格式化的文本作为下一个参数。

我们的实现现在已经完成，我们可以再次运行测试，看看它们是否都通过了：

```go
go test -v .
=== RUN   Test_Overall
=== RUN   Test_Overall/MessageA_test
=== RUN   Test_Overall/MessageB_test
--- PASS: Test_Overall (0.00s)
 --- PASS: Test_Overall/MessageA_test (0.00s)
 --- PASS: Test_Overall/MessageB_test (0.00s)
PASS
ok

```

一切都很好！访问者模式已经完美地完成了它的工作，调用它们的`Visit`方法后，消息内容已经被改变。这里非常重要的一点是，我们可以为这两个结构体添加更多功能，`MessageA`和`MessageB`，而不改变它们的类型。我们只需创建一个新的访问者类型，对`Visitable`上的所有操作进行处理，例如，我们可以创建一个`Visitor`来添加一个打印`Msg`字段内容的方法：

```go
type MsgFieldVisitorPrinter struct {} 

func (mf *MsgFieldVisitorPrinter) VisitA(m *MessageA){ 
  fmt.Printf(m.Msg) 
} 
func (mf *MsgFieldVisitorPrinter) VisitB(m *MessageB){ 
  fmt.Printf(m.Msg) 
} 

```

我们刚刚为这两种类型添加了一些功能，而没有改变它们的内容！这就是访问者设计模式的威力。

## 另一个例子

我们将开发第二个例子，这个例子会更加复杂一些。在这种情况下，我们将模拟一个有几种产品的在线商店。产品将具有简单的类型，只有字段，我们将创建一对访问者来处理它们。

首先，我们将开发接口。`ProductInfoRetriever` 类型有一个方法来获取产品的价格和名称。`Visitor` 接口，就像之前一样，有一个接受 `ProductInfoRetriever` 类型的 `Visit` 方法。最后，`Visitable` 接口完全相同；它有一个接受 `Visitor` 类型作为参数的 `Accept` 方法。

```go
type ProductInfoRetriever interface { 
  GetPrice() float32 
  GetName() string 
} 

type Visitor interface { 
  Visit(ProductInfoRetriever) 
} 

type Visitable interface { 
  Accept(Visitor) 
} 

```

在线商店的所有产品都必须实现`ProductInfoRetriever`类型。此外，大多数产品都将具有一些共同的字段，例如名称或价格（在`ProductInfoRetriever`接口中定义的字段）。我们创建了`Product`类型，实现了`ProductInfoRetriever`和`Visitable`接口，并将其嵌入到每个产品中：

```go
type Product struct { 
  Price float32 
  Name  string 
} 

func (p *Product) GetPrice() float32 { 
  return p.Price 
} 

func (p *Product) Accept(v Visitor) { 
  v.Visit(p) 
} 

func (p *Product) GetName() string { 
  return p.Name 
} 

```

现在我们有一个非常通用的`Product`类型，可以存储商店几乎任何产品的信息。例如，我们可以有一个`Rice`和一个`Pasta`产品：

```go
type Rice struct { 
  Product 
} 

type Pasta struct { 
  Product 
} 

```

每个都嵌入了`Product`类型。现在我们需要创建一对`Visitors`接口，一个用于计算所有产品的价格总和，一个用于打印每个产品的名称：

```go
type PriceVisitor struct { 
  Sum float32 
} 

func (pv *PriceVisitor) Visit(p ProductInfoRetriever) { 
  pv.Sum += p.GetPrice() 
} 

type NamePrinter struct { 
  ProductList string 
} 

func (n *NamePrinter) Visit(p ProductInfoRetriever) { 
  n.Names = fmt.Sprintf("%s\n%s", p.GetName(), n.ProductList) 
} 

```

`PriceVisitor`结构体获取`ProductInfoRetriever`类型的`Price`变量的值，作为参数传递，并将其添加到`Sum`字段。`NamePrinter`结构体存储`ProductInfoRetriever`类型的名称，作为参数传递，并将其附加到`ProductList`字段的新行上。

现在是`main`函数的时间：

```go
func main() { 
  products := make([]Visitable, 2) 
  products[0] = &Rice{ 
    Product: Product{ 
      Price: 32.0, 
      Name:  "Some rice", 
    }, 
  } 
  products[1] = &Pasta{ 
    Product: Product{ 
      Price: 40.0, 
      Name:  "Some pasta", 
    }, 
  } 

  //Print the sum of prices 
  priceVisitor := &PriceVisitor{} 

  for _, p := range products { 
    p.Accept(priceVisitor) 
  } 

  fmt.Printf("Total: %f\n", priceVisitor.Sum) 

  //Print the products list 
  nameVisitor := &NamePrinter{} 

  for _, p := range products { 
    p.Accept(nameVisitor) 
  } 

  fmt.Printf("\nProduct list:\n-------------\n%s",  nameVisitor.ProductList) 
} 

```

我们创建了两个`Visitable`对象的切片：一个`Rice`和一个`Pasta`类型，带有一些任意的名称。然后我们使用`PriceVisitor`实例作为参数对它们进行迭代。在`range for`之后，我们打印总价格。最后，我们使用`NamePrinter`重复这个操作，并打印结果的`ProductList`。这个`main`函数的输出如下：

```go
go run visitor.go
Total: 72.000000
Product list:
-------------
Some pasta
Some rice

```

好的，这是访问者模式的一个很好的例子，但是...如果产品有特殊的考虑呢？例如，如果我们需要在冰箱类型的总价格上加 20 呢？好的，让我们编写`Fridge`结构：

```go
type Fridge struct { 
  Product 
} 

```

这里的想法是只需重写`GetPrice()`方法，以返回产品的价格加 20：

```go
type Fridge struct { 
  Product 
} 

func (f *Fridge) GetPrice() float32 { 
  return f.Product.Price + 20 
} 

```

不幸的是，这对我们的例子来说还不够。`Fridge`结构不是`Visitable`类型。`Product`结构是`Visitable`类型，而`Fridge`结构嵌入了一个`Product`结构，但是正如我们在前几章中提到的，嵌入第二种类型的类型不能被视为后者的类型，即使它具有所有的字段和方法。解决方案是还要实现`Accept(Visitor)`方法，以便它可以被视为`Visitable`：

```go
type Fridge struct { 
  Product 
} 

func (f *Fridge) GetPrice() float32 { 
  return f.Product.Price + 20 
} 

func (f *Fridge) Accept(v Visitor) { 
  v.Visit(f) 
} 

```

让我们重写`main`函数以将这个新的`Fridge`产品添加到切片中：

```go
func main() { 
  products := make([]Visitable, 3) 
  products[0] = &Rice{ 
    Product: Product{ 
      Price: 32.0, 
      Name:  "Some rice", 
    }, 
  } 
  products[1] = &Pasta{ 
    Product: Product{ 
      Price: 40.0, 
      Name:  "Some pasta", 
    }, 
  } 
  products[2] = &Fridge{ 
    Product: Product{ 
      Price: 50, 
      Name:  "A fridge", 
    }, 
  } 
  ... 
} 

```

其他一切都保持不变。运行这个新的`main`函数会产生以下输出：

```go
$ go run visitor.go
Total: 142.000000
Product list:
-------------
A fridge
Some pasta
Some rice

```

如预期的那样，总价格现在更高了，输出了大米（32）、意大利面（40）和冰箱（50 的产品加上 20 的运输，所以是 70）的总和。我们可以不断地为这些产品添加访问者，但是想法很清楚——我们将一些算法解耦到访问者之外。

## 访问者来拯救！

我们已经看到了一个强大的抽象，可以向某些类型添加新的算法。然而，由于 Go 语言中缺乏重载，这种模式在某些方面可能有限（我们在第一个示例中已经看到了这一点，在那里我们不得不创建`VisitA`和`VisitB`的实现）。在第二个示例中，我们没有处理这个限制，因为我们使用了`Visitor`结构的`Visit`方法的接口，但我们只使用了一种类型的访问者（`ProductInfoRetriever`），如果我们为第二种类型实现了`Visit`方法，我们将会遇到相同的问题，这是原始*四人帮*设计模式的目标之一。

# 状态设计模式

状态模式与 FSM 直接相关。FSM，简单来说，是具有一个或多个状态并在它们之间移动以执行某些行为的东西。让我们看看状态模式如何帮助我们定义 FSM。

## 描述

一个灯开关是 FSM 的一个常见例子。它有两种状态——开和关。一种状态可以转移到另一种状态，反之亦然。状态模式的工作方式类似。我们有一个`State`接口和我们想要实现的每个状态的实现。通常还有一个上下文，用于在状态之间保存交叉信息。

通过 FSM，我们可以通过将其范围分割为状态来实现非常复杂的行为。这样我们可以基于任何类型的输入来建模执行管道，或者创建对特定事件以指定方式做出响应的事件驱动软件。

## 目标

状态模式的主要目标是开发 FSM，如下所示：

+   当一些内部事物发生变化时，拥有一种可以改变自身行为的类型

+   可以通过添加更多状态并重新路由它们的输出状态轻松升级模型复杂的图形和管道

## 一个小猜数字游戏

我们将开发一个非常简单的使用 FSM 的游戏。这个游戏是一个猜数字游戏。想法很简单——我们将不得不猜出 0 到 10 之间的某个数字，我们只有几次尝试，否则就会输掉。

我们将让玩家选择难度级别，询问用户在失去之前有多少次尝试。然后，我们将要求玩家输入正确的数字，并在他们猜不中或尝试次数达到零时继续询问。

## 验收标准

对于这个简单的游戏，我们有五个验收标准，基本上描述了游戏的机制：

1.  游戏将询问玩家在失去游戏之前有多少次尝试。

1.  要猜的数字必须在 0 到 10 之间。

1.  每当玩家输入一个要猜的数字时，重试次数就会减少一个。

1.  如果重试次数达到零且数字仍然不正确，游戏结束，玩家输了。

1.  如果玩家猜中数字，玩家获胜。

## 状态模式的实现

单元测试的想法在状态模式中非常简单，因此我们将花更多时间详细解释如何使用它的机制，这比通常更复杂一些。

首先，我们需要一个接口来表示不同的状态和一个游戏上下文来存储状态之间的信息。对于这个游戏，上下文需要存储重试次数，用户是否已经赢得游戏，要猜的秘密数字和当前状态。状态将有一个`executeState`方法，该方法接受这些上下文之一，并在游戏结束时返回`true`，否则返回`false`：

```go
type GameState interface { 
  executeState(*GameContext) bool 
} 

type GameContext struct { 
  SecretNumber int 
  Retries int 
  Won bool 
  Next GameState 
} 

```

如*验收标准 1*中所述，玩家必须能够输入他们想要的重试次数。这将通过一个名为`StartState`的状态来实现。此外，`StartState`结构必须在玩家之前设置上下文的初始值：

```go
type StartState struct{} 
func(s *StartState) executeState(c *GameContext) bool { 
  c.Next = &AskState{} 

  rand.Seed(time.Now().UnixNano()) 
  c.SecretNumber = rand.Intn(10) 

  fmt.Println("Introduce a number a number of retries to set the difficulty:") 
  fmt.Fscanf(os.Stdin, "%d\n", &c.Retries) 

  return true 
} 

```

首先，`StartState`结构实现了`GameState`结构，因为它在其结构上具有`executeState(*Context)`方法，返回布尔类型。在这个状态的开始，它设置了执行完这个状态后唯一可能的状态--`AskState`状态。`AskState`结构尚未声明，但它将是我们询问玩家猜数字的状态。

在接下来的两行中，我们使用 Go 的`Rand`包生成一个随机数。在第一行中，我们用当前时刻返回的`int64`类型数字来喂入随机生成器，因此我们确保每次执行都有一个随机的喂入（如果你在这里放一个常数，随机生成器也会生成相同的数字）。`rand.Intn(int)`方法返回 0 到指定数字之间的整数，因此我们满足了*验收标准 2*。

接下来，我们设置一个消息询问要设置的重试次数，然后使用`fmt.Fscanf`方法，一个强大的函数，您可以向其传递一个`io.Reader`（控制台的标准输入）、一个格式（数字）和一个接口来存储读取器的内容，在这种情况下是上下文的`Retries`字段。

最后，我们返回`true`告诉引擎游戏必须继续。让我们看看我们在函数开头使用的`AskState`结构：

```go
type AskState struct {} 
func (a *AskState) executeState(c *GameContext) bool{ 
  fmt.Printf("Introduce a number between 0 and 10, you have %d tries left\n", c.Retries) 

  var n int 
  fmt.Fscanf(os.Stdin, "%d", &n) 
  c.Retries = c.Retries - 1 

  if n == c.SecretNumber { 
    c.Won = true 
    c.Next = &FinishState{} 
  } 

  if c.Retries == 0 { 
    c.Next = &FinishState{} 
  } 

  return true 
} 

```

`AskState`结构也实现了`GameState`状态，你可能已经猜到了。这个状态从一个向玩家的消息开始，要求他们插入一个新的数字。在接下来的三行中，我们创建一个本地变量来存储玩家将要输入的数字的内容。我们再次使用`fmt.Fscanf`方法，就像我们在`StartState`结构中做的那样，来捕获玩家的输入并将其存储在变量`n`中。然后，我们的计数器中的重试次数减少了一个，所以我们必须在上下文的`Retries`字段中减去一个。

然后，有两个检查：一个检查用户是否输入了正确的数字，如果是，则上下文字段`Won`设置为`true`，下一个状态设置为`FinishState`结构（尚未声明）。

第二个检查是控制重试次数是否已经达到零，如果是，则不会让玩家再次要求输入数字，并直接将玩家发送到`FinishState`结构。毕竟，我们必须再次告诉游戏引擎游戏必须继续，通过在`executeState`方法中返回`true`。

最后，我们定义了`FinishState`结构。它控制游戏的退出状态，检查上下文对象中`Won`字段的内容：

```go
type FinishState struct{} 
func(f *FinishState) executeState(c *GameContext) bool { 
  if c.Won { 
    println("Congrats, you won") 
  }  
  else { 
    println("You lose") 
  } 
  return false 
} 

```

`TheFinishState`结构也通过在其结构中具有`executeState`方法来实现`GameState`状态。这里的想法非常简单——如果玩家赢了（这个字段之前在`AskState`结构中设置），`FinishState`结构将打印消息`恭喜，你赢了`。如果玩家没有赢（记住布尔变量的零值是`false`），`FinishState`将打印消息`你输了`。

在这种情况下，游戏可以被认为已经结束，所以我们返回`false`来表示游戏不应该继续。

我们只需要`main`方法来玩我们的游戏。

```go
func main() { 
  start := StartState{} 
  game := GameContext{ 
    Next:&start, 
  } 
  for game.Next.executeState(&game) {} 
} 

```

嗯，是的，它不能再简单了。游戏必须从`start`方法开始，尽管在未来游戏需要更多初始化的情况下，它可以更抽象地放在外面，但在我们的情况下没问题。然后，我们创建一个上下文，将`Next`状态设置为指向`start`变量的指针。因此，在游戏中将执行的第一个状态将是`StartState`状态。

`main`函数的最后一行有很多东西。我们创建了一个循环，里面没有任何语句。和任何循环一样，在条件不满足后它会继续循环。我们使用的条件是`GameStates`结构的返回值，在游戏未结束时为`true`。

所以，思路很简单：我们在上下文中执行状态，将上下文的指针传递给它。每个状态都返回`true`，直到游戏结束，`FinishState`结构将返回`false`。所以我们的循环将继续循环，等待`FinishState`结构发送的`false`条件来结束应用程序。

让我们再玩一次：

```go
go run state.go
Introduce a number a number of retries to set the difficulty:
5
Introduce a number between 0 and 10, you have 5 tries left
8
Introduce a number between 0 and 10, you have 4 tries left
2
Introduce a number between 0 and 10, you have 3 tries left
1
Introduce a number between 0 and 10, you have 2 tries left
3
Introduce a number between 0 and 10, you have 1 tries left
4
You lose

```

我们输了！我们把重试次数设为 5。然后我们继续插入数字，试图猜出秘密数字。我们输入了 8、2、1、3 和 4，但都不对。我甚至不知道正确的数字是多少；让我们来修复这个！

去到`FinishState`结构的定义并且改变那一行写着`You lose`的地方，用以下内容替换它：

```go
fmt.Printf("You lose. The correct number was: %d\n", c.SecretNumber) 

```

现在它会显示正确的数字。让我们再玩一次：

```go
go run state.go
Introduce a number a number of retries to set the difficulty:
3
Introduce a number between 0 and 10, you have 3 tries left
6
Introduce a number between 0 and 10, you have 2 tries left
2
Introduce a number between 0 and 10, you have 1 tries left
1
You lose. The correct number was: 9

```

这次我们把难度加大了，只设置了三次尝试……但我们又输了。我输入了 6、2 和 1，但正确的数字是 9。最后一次尝试：

```go
go run state.go
Introduce a number a number of retries to set the difficulty:
5
Introduce a number between 0 and 10, you have 5 tries left
3
Introduce a number between 0 and 10, you have 4 tries left
4
Introduce a number between 0 and 10, you have 3 tries left
5
Introduce a number between 0 and 10, you have 2 tries left
6
Congrats, you won

```

太好了！这次我们降低了难度，允许最多五次尝试，我们赢了！我们甚至还有一次尝试剩下，但我们在第四次尝试后猜中了数字，输入了 3、4、5。正确的数字是 6，这是我的第四次尝试。

## 一个赢的状态和一个输的状态

你是否意识到我们可以有一个赢和一个输的状态，而不是直接在`FinishState`结构中打印消息？这样我们可以，例如，在赢的部分检查一些假设的得分板，看看我们是否创造了记录。让我们重构我们的游戏。首先我们需要一个`WinState`和一个`LoseState`结构：

```go
type WinState struct{} 

func (w *WinState) executeState(c *GameContext) bool { 
  println("Congrats, you won") 

  return false 
} 

type LoseState struct{} 

func (l *LoseState) executeState(c *GameContext) bool { 
  fmt.Printf("You lose. The correct number was: %d\n", c.SecretNumber) 
  return false 
} 

```

这两个新状态没有什么新东西。它们包含了之前在`FinishState`状态中的相同消息，顺便说一句，必须修改为使用这些新状态：

```go
func (f *FinishState) executeState(c *GameContext) bool { 
  if c.Won { 
    c.Next = &WinState{} 
  } else { 
    c.Next = &LoseState{} 
  } 
  return true 
} 

```

现在，结束状态不再打印任何东西，而是将其委托给链中的下一个状态——如果用户赢了，则是`WinState`结构，如果没有，则是`LoseState`结构。记住，游戏现在不会在`FinishState`结构上结束，我们必须返回`true`而不是`false`来通知引擎必须继续执行链中的状态。

## 使用状态模式构建的游戏

你现在可能会想，你可以用新状态无限扩展这个游戏，这是真的。状态模式的威力不仅在于创建复杂的有限状态机的能力，还在于通过添加新状态和修改一些旧状态指向新状态而不影响有限状态机的其余部分来改进它的灵活性。

# 中介者设计模式

让我们继续使用中介者模式。顾名思义，它是一种将处于两种类型之间以交换信息的模式。但是，为什么我们会想要这种行为呢？让我们仔细看一下。

## 描述

任何设计模式的关键目标之一是避免对象之间的紧密耦合。这可以通过多种方式实现，正如我们已经看到的。

但是当应用程序增长很多时，特别有效的一种方法是中介者模式。中介者模式是一个很好的例子，它是每个程序员通常在不太考虑的情况下使用的模式。

中介者模式将充当两个对象之间交换通信的类型。这样，通信的对象不需要彼此了解，可以更自由地进行更改。维护对象提供什么信息的模式是中介者。

## 目标

如前所述，中介者模式的主要目标是松散耦合和封装。目标是：

+   为了提供两个必须相互通信的对象之间的松散耦合

+   通过将这些需求传递给中介者模式，减少特定类型的依赖量

## 一个计算器

对于中介者模式，我们将开发一个非常简单的算术计算器。你可能认为计算器如此简单，不需要任何模式。但我们会看到这并不完全正确。

我们的计算器只会执行两个非常简单的操作：求和和减法。

## 验收标准

谈论验收标准来定义一个计算器听起来相当有趣，但无论如何我们都要做：

1.  定义一个名为`Sum`的操作，它接受一个数字并将其加到另一个数字。

1.  定义一个名为`Subtract`的操作，它接受一个数字并将其减去另一个数字。

嗯，我不知道你怎么想，但在这个*复杂*的标准之后，我真的需要休息。那么为什么我们要这么定义呢？耐心点，你很快就会得到答案。

## 实现

我们必须直接跳到实现，因为我们无法测试求和是否正确（嗯，我们可以，但那样就是在测试 Go 是否写得正确！）。我们可以测试是否符合验收标准，但对于我们的例子来说有点过度了。

那么让我们从实现必要的类型开始：

```go
package main 

type One struct{} 
type Two struct{} 
type Three struct{} 
type Four struct{} 
type Five struct{} 
type Six struct{} 
type Seven struct{} 
type Eight struct{} 
type Nine struct{} 
type Zero struct{} 

```

嗯...这看起来相当尴尬。我们在 Go 中已经有数字类型来执行这些操作，我们不需要为每个数字都定义一个类型！

但让我们再继续一下这种疯狂的方法。让我们实现`One`结构：

```go
type One struct{} 

func (o *One) OnePlus(n interface{}) interface{} { 
  switch n.(type) { 
  case One: 
    return &Two{} 
  case Two: 
    return &Three{} 
  case Three: 
    return &Four{} 
  case Four: 
    return &Five{} 
  case Five: 
    return &Six{} 
  case Six: 
    return &Seven{} 
  case Seven: 
    return &Eight{} 
  case Eight: 
    return &Nine{} 
  case Nine: 
    return [2]interface{}{&One{}, &Zero{}} 
  default: 
    return fmt.Errorf("Number not found") 
  } 
} 

```

好吧，我就说到这里。这个实现有什么问题？这完全疯狂！为了进行求和而使每种可能的数字操作都变得太过了！特别是当我们有多于一位数时。

嗯，信不信由你，这就是今天许多软件通常设计的方式。一个对象使用两个或三个对象的小应用程序会增长，最终使用数十个对象。仅仅因为它隐藏在某些疯狂的地方，所以要简单地添加或删除应用程序中的类型变得非常困难。

那么在这个计算器中我们能做什么？使用一个中介者类型来解放所有情况：

```go
func Sum(a, b interface{}) interface{}{ 
  switch a := a.(type) { 
    case One: 
    switch b.(type) { 
      case One: 
        return &Two{} 
      case Two: 
        return &Three{} 
      default: 
        return fmt.Errorf("Number not found") 
    } 
    case Two: 
    switch b.(type) { 
      case One: 
        return &Three{} 
      case Two: 
        return &Four{} 
      default: 
      return fmt.Errorf("Number not found") 

    } 
    case int: 
    switch b := b.(type) { 
      case One: 
        return &Three{} 
      case Two: 
        return &Four{} 
      case int: 
        return a + b 
      default: 
      return fmt.Errorf("Number not found") 

    } 
    default: 
    return fmt.Errorf("Number not found") 
  } 
} 

```

我们只开发了一对数字来简化。`Sum`函数充当两个数字之间的中介者。首先它检查名为`a`的第一个数字的类型。然后，对于第一个数字的每种类型，它检查名为`b`的第二个数字的类型，并返回结果类型。

虽然解决方案现在看起来仍然非常疯狂，但唯一知道计算器中所有可能数字的是`Sum`函数。但仔细看，你会发现我们为`int`类型添加了一个类型情况。我们有`One`、`Two`和`int`情况。在`int`情况下，我们还有另一个`int`情况用于`b`数字。我们在这里做什么？如果两种类型都是`int`情况，我们可以返回它们的和。

你认为这样会有效吗？让我们写一个简单的`main`函数：

```go
func main(){ 
  fmt.Printf("%#v\n", Sum(One{}, Two{})) 
  fmt.Printf("%d\n", Sum(1,2)) 
} 

```

我们打印类型`One`和类型`Two`的总和。通过使用`"%#v"`格式，我们要求打印有关类型的信息。函数中的第二行使用`int`类型，并且我们还打印结果。这在控制台上产生以下输出：

```go
$go run mediator.go
&main.Three{}
7

```

不是很令人印象深刻，对吧？但是让我们思考一下。通过使用中介者模式，我们已经能够重构最初的计算器，在那里我们必须为每种类型定义每个操作，转换为中介者模式的`Sum`函数。

好处在于，由于中介者模式的存在，我们已经能够开始将整数作为计算器的值使用。我们刚刚通过添加两个整数定义了最简单的示例，但我们也可以使用整数和`type`来做同样的事情：

```go
  case One: 
    switch b := b.(type) { 
    case One: 
      return &Two{} 
    case Two: 
      return &Three{} 
    case int: 
      return b+1 
    default: 
      return fmt.Errorf("Number not found") 
    } 

```

通过这个小修改，我们现在可以使用类型`One`和`int`作为数字`b`。如果我们继续在中介者模式上工作，我们可以在类型之间实现很大的灵活性，而无需实现它们之间的每种可能操作，从而产生紧密耦合。

我们将在主函数中添加一个新的`Sum`方法，以查看其运行情况：

```go
func main(){ 
  fmt.Printf("%#v\n", Sum(One{}, Two{})) 
  fmt.Printf("%d\n", Sum(1,2)) 
 fmt.Printf("%d\n", Sum(One{},2)) 
} 
$go run mediator.go&main.Three{}33

```

很好。中介者模式负责了解可能的类型并返回最适合我们情况的类型，即整数。现在我们可以继续扩展这个`Sum`函数，直到完全摆脱使用我们定义的数值类型。

## 使用中介者解耦两种类型

我们进行了一个颠覆性的示例，试图超越传统思维，深入思考中介者模式。应用程序中实体之间的紧密耦合可能在未来变得非常复杂，并且如果需要进行更复杂的重构，则可能更加困难。

只需记住，中介者模式的作用是作为两种不相互了解的类型之间的管理类型，以便您可以获取其中一种类型而不影响另一种类型，并以更轻松和便捷的方式替换类型。

# 观察者设计模式

我们将用我最喜欢的*四人帮*设计模式之一结束，即观察者模式，也称为发布/订阅或发布/监听器。通过状态模式，我们定义了我们的第一个事件驱动架构，但是通过观察者模式，我们将真正达到一个新的抽象层次。

## 描述

观察者模式背后的思想很简单--订阅某个事件，该事件将触发许多订阅类型上的某些行为。为什么这么有趣？因为我们将一个事件与其可能的处理程序解耦。

例如，想象一个登录按钮。我们可以编写代码，当用户点击按钮时，按钮颜色会改变，执行一个操作，并在后台执行表单检查。但是通过观察者模式，更改颜色的类型将订阅按钮点击事件。检查表单的类型和执行操作的类型也将订阅此事件。

## 目标

观察者模式特别有用，可以在一个事件上触发多个操作。当您事先不知道有多少操作会在事件之后执行，或者有可能操作的数量将来会增加时，它也特别有用。总之，执行以下操作：

+   提供一个事件驱动的架构，其中一个事件可以触发一个或多个操作

+   将执行的操作与触发它们的事件解耦

+   提供触发相同操作的多个事件

## 通知者

我们将开发最简单的应用程序，以充分理解观察者模式的根源。我们将创建一个`Publisher`结构，它是触发事件的结构，因此必须接受新的观察者，并在必要时删除它们。当触发`Publisher`结构时，它必须通知所有观察者有关关联数据的新事件。

## 验收标准

需求必须告诉我们有一些类型会触发一个或多个操作的某种方法：

1.  我们必须有一个带有`NotifyObservers`方法的发布者，该方法接受消息作为参数并触发订阅的每个观察者上的`Notify`方法。

1.  我们必须有一个方法向发布者添加新的订阅者。

1.  我们必须有一个方法从发布者中删除新的订阅者。

## 单元测试

也许你已经意识到，我们的要求几乎完全定义了`Publisher`类型。这是因为观察者执行的操作对观察者模式来说是无关紧要的。它应该只执行一个动作，即`Notify`方法，在这种情况下，一个或多个类型将实现。因此，让我们为此模式定义唯一的接口：

```go
type Observer interface { 
  Notify(string) 
} 

```

`Observer`接口有一个`Notify`方法，它接受一个`string`类型，其中包含要传播的消息。它不需要返回任何东西，但是当调用`Publisher`结构的`publish`方法时，我们可以返回一个错误，以便检查是否已经到达了所有观察者。

为了测试所有的验收标准，我们只需要一个名为`Publisher`的结构，其中包含三种方法：

```go
type Publisher struct { 
  ObserversList []Observer 
} 

func (s *Publisher) AddObserver(o Observer) {} 

func (s *Publisher) RemoveObserver(o Observer) {} 

func (s *Publisher) NotifyObservers(m string) {} 

```

`Publisher`结构将订阅的观察者列表存储在名为`ObserversList`的切片字段中。然后它具有接受标准的三种方法--`AddObserver`方法用于向发布者订阅新的观察者，`RemoveObserver`方法用于取消订阅观察者，以及`NotifyObservers`方法，其中包含一个作为我们想要在所有观察者之间传播的消息的字符串。

有了这三种方法，我们必须设置一个根测试来配置`Publisher`和三个子测试来测试每种方法。我们还需要定义一个实现`Observer`接口的测试类型结构。这个结构将被称为`TestObserver`：

```go
type TestObserver struct { 
  ID      int 
  Message string 
} 
func (p *TestObserver) Notify(m string) { 
  fmt.Printf("Observer %d: message '%s' received \n", p.ID, m) 
  p.Message = m 
} 

```

`TestObserver`结构通过在其结构中定义`Notify(string)`方法来实现观察者模式。在这种情况下，它打印接收到的消息以及自己的观察者 ID。然后，它将消息存储在其`Message`字段中。这使我们可以稍后检查`Message`字段的内容是否符合预期。请记住，也可以通过传递`testing.T`指针和预期消息并在`TestObserver`结构内部进行检查来完成。

现在我们可以设置`Publisher`结构来执行这三个测试。我们将创建`TestObserver`结构的三个实例：

```go
func TestSubject(t *testing.T) { 
  testObserver1 := &TestObserver{1, ""} 
  testObserver2 := &TestObserver{2, ""} 
  testObserver3 := &TestObserver{3, ""} 
  publisher := Publisher{} 

```

我们为每个观察者分配了不同的 ID，以便稍后可以看到它们每个人都打印了预期的消息。然后，我们通过在`Publisher`结构上调用`AddObserver`方法来添加观察者。

让我们编写一个`AddObserver`测试，它必须将新的观察者添加到`Publisher`结构的`ObserversList`字段中：

```go
  t.Run("AddObserver", func(t *testing.T) { 
    publisher.AddObserver(testObserver1) 
    publisher.AddObserver(testObserver2) 
    publisher.AddObserver(testObserver3) 

    if len(publisher.ObserversList) != 3 { 
      t.Fail() 
    } 
  }) 

```

我们已经向`Publisher`结构添加了三个观察者，因此切片的长度必须为 3。如果不是 3，测试将失败。

`RemoveObserver`测试将获取 ID 为 2 的观察者并将其从列表中删除：

```go
  t.Run("RemoveObserver", func(t *testing.T) { 
    publisher.RemoveObserver(testObserver2) 

    if len(publisher.ObserversList) != 2 { 
      t.Errorf("The size of the observer list is not the " + 
        "expected. 3 != %d\n", len(publisher.ObserversList)) 
    } 

    for _, observer := range publisher.ObserversList { 
      testObserver, ok := observer.(TestObserver) 
      if !ok {  
        t.Fail() 
      } 

      if testObserver.ID == 2 { 
        t.Fail() 
      } 
    } 
  }) 

```

删除第二个观察者后，`Publisher`结构的长度现在必须为 2。我们还检查剩下的观察者中没有一个的`ID`为 2，因为它必须被移除。

测试的最后一个方法是`Notify`方法。使用`Notify`方法时，所有`TestObserver`结构的实例都必须将它们的`Message`字段从空更改为传递的消息（在本例中为`Hello World!`）。首先，我们将检查在调用`NotifyObservers`测试之前所有的`Message`字段是否实际上都是空的：

```go
t.Run("Notify", func(t *testing.T) { 
    for _, observer := range publisher.ObserversList { 
      printObserver, ok := observer.(*TestObserver) 
      if !ok { 
        t.Fail() 
        break 
      } 

      if printObserver.Message != "" { 
        t.Errorf("The observer's Message field weren't " + "  empty: %s\n", printObserver.Message) 
      } 
    } 

```

使用`for`语句，我们正在迭代`publisher`实例中的`ObserversList`字段。我们需要将指针从观察者转换为`TestObserver`结构的指针，并检查转换是否已正确完成。然后，我们检查`Message`字段实际上是否为空。

下一步是创建要发送的消息--在本例中，它将是`"Hello World!"`，然后将此消息传递给`NotifyObservers`方法，以通知列表上的每个观察者（目前只有观察者 1 和 3）：

```go
    ... 
    message := "Hello World!" 
    publisher.NotifyObservers(message) 

    for _, observer := range publisher.ObserversList { 
      printObserver, ok := observer.(*TestObserver) 
      if !ok { 
        t.Fail() 
        break 
      } 

      if printObserver.Message != message { 
        t.Errorf("Expected message on observer %d was " + 
          "not expected: '%s' != '%s'\n", printObserver.ID, 
          printObserver.Message, message) 
      } 
    } 
  }) 
} 

```

调用`NotifyObservers`方法后，`ObserversList`字段中的每个`TestObserver`测试必须在其`Message`字段中存储`"Hello World!"`消息。同样，我们使用`for`循环来遍历`ObserversList`字段中的每个观察者，并将每个类型转换为`TestObserver`测试（请记住，`TestObserver`结构没有任何字段，因为它是一个接口）。我们可以通过向`Observer`实例添加一个新的`Message()`方法并在`TestObserver`结构中实现它来避免类型转换，以返回`Message`字段的内容。这两种方法都是有效的。一旦我们将类型转换为`TestObserver`方法调用`printObserver`变量作为局部变量，我们检查`ObserversList`结构中的每个实例是否在其`Message`字段中存储了字符串`"Hello World!"`。

是时候运行测试了，必须全部失败以检查它们在后续实现中的有效性：

```go
go test -v  
=== RUN   TestSubject 
=== RUN   TestSubject/AddObserver 
=== RUN   TestSubject/RemoveObserver 
=== RUN   TestSubject/Notify 
--- FAIL: TestSubject (0.00s) 
    --- FAIL: TestSubject/AddObserver (0.00s) 
    --- FAIL: TestSubject/RemoveObserver (0.00s) 
        observer_test.go:40: The size of the observer list is not the expected. 3 != 0 
    --- PASS: TestSubject/Notify (0.00s) 
FAIL 
exit status 1 
FAIL

```

有些地方不如预期。如果我们还没有实现函数，`Notify`方法是如何通过测试的？再看一下`Notify`方法的测试。测试遍历`ObserversList`结构，并且每个`Fail`调用都在此`for`循环内。如果列表为空，它将不会进行迭代，因此不会执行任何`Fail`调用。

让我们通过在`Notify`测试的开头添加一个小的非空列表检查来解决这个问题：

```go
  if len(publisher.ObserversList) == 0 { 
      t.Errorf("The list is empty. Nothing to test\n") 
  } 

```

我们将重新运行测试，看看`TestSubject/Notify`方法是否已经失败：

```go
go test -v
=== RUN   TestSubject
=== RUN   TestSubject/AddObserver
=== RUN   TestSubject/RemoveObserver
=== RUN   TestSubject/Notify
--- FAIL: TestSubject (0.00s)
 --- FAIL: TestSubject/AddObserver (0.00s)
 --- FAIL: TestSubject/RemoveObserver (0.00s)
 observer_test.go:40: The size of the observer list is not the expected. 3 != 0
 --- FAIL: TestSubject/Notify (0.00s)
 observer_test.go:58: The list is empty. Nothing to test
FAIL
exit status 1
FAIL

```

很好，它们全部失败了，现在我们对测试有了一些保证。我们可以继续实现。

## 实施

我们的实现只是定义`AddObserver`、`RemoveObserver`和`NotifyObservers`方法：

```go
func (s *Publisher) AddObserver(o Observer) { 
  s.ObserversList = append(s.ObserversList, o) 
} 

```

`AddObserver`方法通过将指针附加到当前指针列表来将`Observer`实例添加到`ObserversList`结构中。这很容易。`AddObserver`测试现在必须通过（但其他测试不通过，否则我们可能做错了什么）：

```go
go test -v
=== RUN   TestSubject
=== RUN   TestSubject/AddObserver
=== RUN   TestSubject/RemoveObserver
=== RUN   TestSubject/Notify
--- FAIL: TestSubject (0.00s)
 --- PASS: TestSubject/AddObserver (0.00s)
 --- FAIL: TestSubject/RemoveObserver (0.00s)
 observer_test.go:40: The size of the observer list is not the expected. 3 != 3
 --- FAIL: TestSubject/Notify (0.00s)
 observer_test.go:87: Expected message on observer 1 was not expected: 'default' != 'Hello World!'
 observer_test.go:87: Expected message on observer 2 was not expected: 'default' != 'Hello World!'
 observer_test.go:87: Expected message on observer 3 was not expected: 'default' != 'Hello World!'
FAIL
exit status 1
FAIL

```

很好。只有`AddObserver`方法通过了测试，所以我们现在可以继续进行`RemoveObserver`方法：

```go
func (s *Publisher) RemoveObserver(o Observer) { 
  var indexToRemove int 

  for i, observer := range s.ObserversList { 
    if observer == o { 
      indexToRemove = i 
      break 
    } 
  } 

  s.ObserversList = append(s.ObserversList[:indexToRemove], s.ObserversList[indexToRemove+1:]...) 
} 

```

`RemoveObserver`方法将遍历`ObserversList`结构中的每个元素，将`Observer`对象的`o`变量与列表中存储的对象进行比较。如果找到匹配项，它将保存在本地变量`indexToRemove`中，并停止迭代。在 Go 中删除切片的索引有点棘手：

1.  首先，我们需要使用切片索引来返回一个新的切片，其中包含从切片开头到我们想要移除的索引（不包括）的每个对象。

1.  然后，我们从要删除的索引（不包括）到切片中的最后一个对象获取另一个切片

1.  最后，我们将前两个新切片合并成一个新的切片（使用`append`函数）

例如，在一个从 1 到 10 的列表中，我们想要移除数字 5，我们必须创建一个新的切片，将从 1 到 4 的切片和从 6 到 10 的切片连接起来。

这个索引移除是使用`append`函数完成的，因为我们实际上是将两个列表连接在一起。仔细看一下`append`函数第二个参数末尾的三个点。`append`函数将一个元素（第二个参数）添加到一个切片（第一个参数），但我们想要添加整个列表。这可以通过使用三个点来实现，它们的作用类似于*继续添加元素，直到完成第二个数组*。

好的，现在让我们运行这个测试：

```go
go test -v           
=== RUN   TestSubject 
=== RUN   TestSubject/AddObserver 
=== RUN   TestSubject/RemoveObserver 
=== RUN   TestSubject/Notify 
--- FAIL: TestSubject (0.00s) 
    --- PASS: TestSubject/AddObserver (0.00s) 
    --- PASS: TestSubject/RemoveObserver (0.00s) 
    --- FAIL: TestSubject/Notify (0.00s) 
        observer_test.go:87: Expected message on observer 1 was not expected: 'default' != 'Hello World!' 
        observer_test.go:87: Expected message on observer 3 was not expected: 'default' != 'Hello World!' 
FAIL 
exit status 1 
FAIL 

```

我们继续在正确的路径上。`RemoveObserver`测试已经修复，而没有修复其他任何东西。现在我们必须通过定义`NotifyObservers`方法来完成我们的实现：

```go
func (s *Publisher) NotifyObservers(m string) { 
  fmt.Printf("Publisher received message '%s' to notify observers\n", m) 
  for _, observer := range s.ObserversList { 
    observer.Notify(m) 
  } 
} 

```

`NotifyObservers`方法非常简单，因为它在控制台上打印一条消息，宣布特定消息将传递给“观察者”。之后，我们使用 for 循环遍历`ObserversList`结构，并通过传递参数`m`执行每个`Notify(string)`方法。执行完毕后，所有观察者必须在其`Message`字段中存储消息`Hello World!`。让我们通过运行测试来看看这是否成立：

```go
go test -v 
=== RUN   TestSubject 
=== RUN   TestSubject/AddObserver 
=== RUN   TestSubject/RemoveObserver 
=== RUN   TestSubject/Notify 
Publisher received message 'Hello World!' to notify observers 
Observer 1: message 'Hello World!' received  
Observer 3: message 'Hello World!' received  
--- PASS: TestSubject (0.00s) 
    --- PASS: TestSubject/AddObserver (0.00s) 
    --- PASS: TestSubject/RemoveObserver (0.00s) 
    --- PASS: TestSubject/Notify (0.00s) 
PASS 
ok

```

太棒了！我们还可以在控制台上看到“发布者”和“观察者”类型的输出。 “发布者”结构打印以下消息：

```go
hey! I have received the message  'Hello World!' and I'm going to pass the same message to the observers 
```

之后，所有观察者按如下方式打印各自的消息：

```go
hey, I'm observer 1 and I have received the message 'Hello World!'
```

第三个观察者也是如此。

## 总结

我们已经利用状态模式和观察者模式解锁了事件驱动架构的力量。现在，您可以在应用程序中真正执行异步算法和操作，以响应系统中的事件。

观察者模式通常用于 UI。Android 编程中充满了观察者模式，以便 Android SDK 可以将操作委托给创建应用程序的程序员。


# 第八章：Gos 并发简介

我们刚刚完成了在面向对象编程语言中广泛使用的*四人帮*设计模式。在过去的几十年里，它们已经被广泛使用（甚至在它们被明确定义在一本书中之前）。

在本章中，我们将看到 Go 语言中的并发性。我们将学习，通过多个核心和多个进程，应用程序可以帮助我们实现更好的性能和无限的可能性。我们将看看如何以并发安全的方式使用一些已知的模式。

# 一点历史和理论

当我们谈论 Go 的并发性时，不可能不谈论历史。在过去的几十年里，我们看到 CPU 速度的提高，直到我们达到了当前硬件材料、设计和架构所施加的硬件限制。当我们达到这一点时，我们开始尝试第一台多核计算机，第一台双 CPU 主板，然后是心脏中有多个核心的单 CPU。

不幸的是，我们正在使用的语言仍然是在我们拥有单核 CPU 时创建的语言，比如 Java 或 C++。虽然它们是很棒的系统语言，但它们在设计上缺乏适当的并发支持。你可以通过使用第三方工具或开发自己的工具在项目中的这两种语言中开发并发应用（这并不是一件很容易的任务）。

Go 的并发是在考虑到这些警告的情况下设计的。创作者们希望有垃圾回收和程序化语言，对新手来说很熟悉，但同时又可以轻松编写并发应用，而不影响语言的核心。

我们在早期章节中已经经历过这一点。我们开发了 20 多种设计模式，却没有提到并发。这清楚地表明，Go 语言的并发特性完全与核心语言分离，同时又是其一部分，这是抽象和封装的完美例子。

在计算机科学中有许多并发模型，最著名的是出现在诸如**Erlang**或**Scala**等语言中的 actor 模型。另一方面，Go 使用**通信顺序进程**（**CSP**），它对并发有不同的方法。

## 并发与并行

许多人误解了两者之间的区别，甚至认为它们是相同的。Rob Pike，Go 的创始人之一，有一次流行的演讲，*并发不等于并行*，我非常同意。作为这次演讲的快速总结，我们可以得出以下结论：

+   并发是同时处理许多事情的能力

+   并行性是同时做很多事情的能力

通过设计正确的并发工作结构，并发能够实现并行。

例如，我们可以想象一辆自行车的机制。当我们踩踏时，通常是向下踩踏板产生力量（这种推动会使我们的另一条腿上升到相反的踏板）。我们不能同时用两条腿推动，因为曲柄不允许我们这样做。但这种设计允许建造一辆平行自行车，通常称为**串联自行车**。串联自行车是两个人可以同时骑的自行车；他们都踩踏板并施加力量给自行车。

在自行车的例子中，并发是设计一辆自行车，用两条腿（Goroutines）可以自己产生动力来移动自行车。这种设计是并发和正确的。如果我们使用串联自行车和两个人（两个核心），解决方案是并发的、正确的和并行的。但关键是，通过并发设计，我们不必担心并行性；如果我们的并发设计是正确的，我们可以将其视为额外的功能。事实上，我们可以只用一个人使用串联自行车，但自行车的并发设计仍然是正确的。

![并发与并行](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/go-dsn-ptn/img/B05557_08_01-1-300x255.jpg)

在并发方面，左侧有一个由同一 CPU 核心顺序执行的设计和结构。一旦有了这个设计和结构，通过在不同的线程上重复这个结构，就可以实现并行。

这就是 Go 通过简单地不太担心并行执行而更多地关注并发设计和结构来简化关于并发和并行程序的推理。将一个大任务分解成可以并发运行的小任务通常会在单核计算机上提供更好的性能，但如果这种设计也可以并行运行，我们可能会实现更高的吞吐量（或者不会，这取决于设计）。

实际上，我们可以通过将环境变量`GOMAXPROCS`设置为所需的核心数来设置 Go 应用程序中使用的核心数。这不仅在使用调度程序（如**Apache Mesos**）时很有用，而且还可以更好地控制 Go 应用程序的工作和性能。

因此，要总结一下，重要的是要记住，并发是关于结构，而并行是关于执行。我们必须考虑以更好的方式使我们的程序并发，通过将它们分解成更小的工作片段，如果可能且允许的话，Go 的调度器将尝试使它们并行化。

## CSP 与基于 actor 的并发

最常见且可能直观的思考并发的方式接近 actor 模型的工作方式。

![CSP 与基于 actor 的并发](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/go-dsn-ptn/img/B05557_08_02-1-300x164.jpg)

在 actor 模型中，如果**Actor 1**想要与**Actor 2**通信，那么**Actor 1**必须首先了解**Actor 2**；例如，它必须有它的进程 ID，可能是从创建步骤中获得，并将消息放在其收件箱队列中。放置消息后，**Actor 1**可以继续其任务，而不会被阻塞，即使**Actor 2**无法立即处理消息。

另一方面，CSP 引入了一个新的实体-通道。通道是进程之间进行通信的方式，因为它们是完全匿名的（不像 actor，我们需要知道它们的进程 ID）。在 CSP 的情况下，我们没有进程 ID 用于通信。相反，我们必须创建一个通道给进程，以允许传入和传出的通信。在这种情况下，我们知道接收者是它用来接收数据的通道：

![CSP 与基于 actor 的并发](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/go-dsn-ptn/img/B05557_08_03-1-300x37.jpg)

在这个图表中，我们可以看到这些进程是匿名的，但我们有一个 ID 为 1 的通道，即**通道 1**，将它们连接在一起。这种抽象并没有告诉我们每一侧通道上有多少个进程；它只是简单地连接它们，并允许它们通过通道进行通信。

关键在于通道隔离了两个极端，以便进程 A 可以通过一个通道发送数据，这些数据将由潜在的一个或多个对 A 透明的进程处理。它也在相反的情况下起作用；进程 B 可以一次从许多通道接收数据。

# Goroutines

在 Go 中，我们通过使用 Goroutines 来实现并发。它们就像在计算机上同时运行应用程序的进程；实际上，Go 的主循环也可以被认为是一个 Goroutine。Goroutines 在我们使用 actor 的地方使用。它们执行一些逻辑然后消失（或者如果有必要，保持循环）。

但是 Goroutines 不是线程。我们可以启动成千上万甚至百万个并发的 Goroutines。它们非常廉价，堆栈增长很小。我们将使用 Goroutines 来执行我们想要并发工作的代码。例如，通过三个 Goroutines 并行设计三个服务的调用来组成一个响应，可能并行进行服务调用，并且第四个 Goroutine 接收它们并组成响应。这里的重点是什么？如果我们有一台有四个核心的计算机，我们可能可以并行运行这个服务调用，但如果我们使用一台单核心的计算机，设计仍然是正确的，调用将在一个核心中并发执行。通过设计并发应用程序，我们不需要担心并行执行。

回到自行车的比喻，我们用两条腿踩踏自行车踏板。这是两个 Goroutines 同时踩踏踏板。当我们使用双人自行车时，我们总共有四个 Goroutines，可能在并行工作。但我们也有两只手来控制前后刹车。这是我们双人自行车上的八个 Goroutines。实际上，我们刹车时不踩踏板，踩踏板时不刹车；这是一个正确的并发设计。我们的神经系统传输关于何时停止踩踏板和何时开始刹车的信息。在 Go 中，我们的神经系统由通道组成；在玩弄 Goroutines 之后，我们将会看到它们。

## 我们的第一个 Goroutine

现在足够的解释了。让我们动手吧。对于我们的第一个 Goroutine，我们将在一个 Goroutine 中打印消息`Hello World!`。让我们从我们到目前为止一直在做的事情开始：

```go
package main 

func main() { 
  helloWorld() 
} 

func helloWorld(){ 
  println("Hello World!") 
} 

```

运行这段小代码片段将在控制台中简单地输出`Hello World!`：

```go
$ go run main.go
Hello World!

```

一点也不令人印象深刻。要在新的 Goroutine 中运行它，我们只需要在对函数的调用前加上关键字`go`：

```go
package main 

func main() { 
  go helloWorld() 
} 

func helloWorld(){ 
  println("Hello World!") 
} 

```

通过这个简单的词，我们告诉 Go 启动一个新的 Goroutine 来运行`helloWorld`函数的内容。

所以，让我们运行它：

```go
$ go run main.go 
$

```

什么？什么都没打印！为什么？当你开始处理并发应用程序时，事情变得复杂起来。问题在于`main`函数在`helloWorld`函数被执行之前就结束了。让我们一步一步地分析一下。`main`函数开始并安排一个新的 Goroutine 来执行`helloWorld`函数，但当函数结束时，函数并没有被执行——它仍然在调度过程中。

所以，我们`main`函数的问题在于`main`函数必须等待 Goroutine 被执行后才能结束。所以让我们停顿一秒钟，给 Goroutine 一些空间：

```go
package main 
import "time" 

func main() { 
  go helloWorld() 

  time.Sleep(time.Second) 
} 

func helloWorld(){ 
  println("Hello World!") 
} 

```

`time.Sleep`函数有效地使主 Goroutine 在继续（并退出）之前休眠一秒钟。如果我们现在运行这个程序，我们必须得到这个消息：

```go
$ go run main.go
Hello World!

```

我想你现在一定已经注意到了程序在结束之前会有一个小的冻结时间。这是休眠的函数。如果你正在做很多任务，你可能想把等待时间延长到你想要的任何时间。只要记住，在任何应用程序中，`main`函数不能在其他 Goroutines 之前结束。

## 匿名函数作为新的 Goroutines 启动

我们已经定义了`helloWorld`函数，以便可以使用不同的 Goroutine 启动它。这并不是严格必要的，因为你可以直接在函数的作用域中启动代码片段：

```go
package main 
import "time" 

func main() { 
  go func() { 
    println("Hello World") 
  }() 
  time.Sleep(time.Second) 
} 

```

这也是有效的。我们使用了一个匿名函数，并使用`go`关键字在一个新的 Goroutine 中启动它。仔细看函数的闭括号——它们后面跟着开括号和闭括号，表示函数的执行。

我们也可以向匿名函数传递数据：

```go
package main 
import "time" 

func main() { 
  go func(msg string) { 
    println(msg) 
  }("Hello World") 
  time.Sleep(time.Second) 
} 

```

这也是有效的。我们定义了一个接收字符串的匿名函数，然后打印接收到的字符串。当我们在不同的 Goroutine 中调用函数时，我们传递了要打印的消息。在这个意义上，以下示例也是有效的：

```go
package main 
import "time" 

func main() { 
  messagePrinter := func(msg string) { 
    println(msg) 
  } 

  go messagePrinter("Hello World") 
  go messagePrinter("Hello goroutine") 
  time.Sleep(time.Second) 
} 

```

在这种情况下，我们在`main`函数的范围内定义了一个函数，并将其存储在名为`messagePrinter`的变量中。现在我们可以通过使用`messagePrinter（string）`签名并发打印任意数量的消息：

```go
$ go run main.go
Hello World
Hello goroutine

```

我们刚刚触及了 Go 中并发编程的表面，但我们已经可以看到它可以非常强大。但我们绝对必须解决这个休眠期的问题。WaitGroups 可以帮助我们解决这个问题。

## WaitGroups

WaitGroup 位于同步包（`sync`包）中，帮助我们同步许多并发的 Goroutines。它非常容易使用-每当我们必须等待一个 Goroutine 完成时，我们向组中添加`1`，一旦它们全部添加，我们要求组等待。当 Goroutine 完成时，它会说`Done`，WaitGroup 将从组中取出一个：

```go
package main 

import ( 
  "sync" 
  "fmt" 
) 

func main() { 
  var wait sync.WaitGroup 
  wait.Add(1) 

  go func(){ 
    fmt.Println("Hello World!") 
    wait.Done() 
  }() 
  wait.Wait() 
} 

```

这是一个最简单的 WaitGroup 示例。首先，我们创建了一个变量来保存它，称为`wait`变量。接下来，在启动新的 Goroutine 之前，我们告诉 WaitGroup“嘿，你必须等待一件事情完成”，使用`wait.Add（1）`方法。现在我们可以启动 WaitGroup 必须等待的`1`，在这种情况下是打印`Hello World`并在 Goroutine 结束时说`Done`（使用`wait.Done（）`方法）的先前 Goroutine。最后，我们指示 WaitGroup 等待。我们必须记住，函数`wait.Wait（）`可能在 Goroutine 之前执行。

让我们再次运行代码：

```go
$ go run main.go 
Hello World!

```

现在它只等待必要的时间，而不是在退出应用程序之前多等待一毫秒。请记住，当我们使用`Add（value）`方法时，我们向 WaitGroup 添加实体，当我们使用`Done（）`方法时，我们减去一个。

实际上，`Add`函数接受一个增量值，因此以下代码等同于上一个：

```go
package main 

import ( 
  "sync" 
  "fmt" 
) 

func main() { 
  var wait sync.WaitGroup 
  wait.Add(1) 

  go func(){ 
    fmt.Println("Hello World!") 
    wait.Add(-1) 
  }() 
  wait.Wait() 
} 

```

在这种情况下，我们在启动 Goroutine 之前添加了`1`，并在其末尾添加了`-1`（减去 1）。如果我们预先知道要启动多少个 Goroutines，我们也可以只调用一次`Add`方法：

```go
package main 
import ( 
  "fmt" 
  "sync" 
) 

func main() { 
  var wait sync.WaitGroup 

  goRoutines := 5 
  wait.Add(goRoutines) 

  for i := 0; i < goRoutines; i++ { 
    go func(goRoutineID int) { 
      fmt.Printf("ID:%d: Hello goroutines!\n", goRoutineID) 
      wait.Done() 
    }(i) 
  } 
  wait.Wait() 
} 

```

在这个例子中，我们将创建五个 Goroutines（如`goroutines`变量中所述）。我们事先知道这一点，所以我们只需将它们全部添加到 WaitGroup 中。然后，我们将使用`for`循环启动相同数量的`goroutine`变量。每当一个 Goroutine 完成时，它都会调用 WaitGroup 的`Done（）`方法，该方法实际上在主循环的末尾等待。

同样，在这种情况下，代码在启动所有 Goroutines（如果有的话）之前到达`main`函数的末尾，并且 WaitGroup 使主流程的执行等待，直到所有`Done`消息被调用。让我们运行这个小程序：

```go
$ go run main.go 

ID:4: Hello goroutines!
ID:0: Hello goroutines!
ID:1: Hello goroutines!
ID:2: Hello goroutines!
ID:3: Hello goroutines!

```

我们之前没有提到，但我们已将迭代索引作为参数`GoroutineID`传递给每个 Goroutine，以便用消息`Hello goroutines！`打印它。您可能还注意到 Goroutines 不按顺序执行。当然！我们正在处理一个不保证 Goroutines 执行顺序的调度程序。这是编写并发应用程序时要牢记的事情。实际上，如果我们再次执行它，我们不一定会得到相同的输出顺序：

```go
$ go run main.go
ID:4: Hello goroutines!
ID:2: Hello goroutines!
ID:1: Hello goroutines!
ID:3: Hello goroutines!
ID:0: Hello goroutines!

```

# 回调

现在我们知道如何使用 WaitGroups，我们还可以介绍回调的概念。如果您曾经使用过像 JavaScript 这样广泛使用回调的语言，这一部分对您来说将是熟悉的。回调是将在不同函数的上下文中执行的匿名函数。

例如，我们想要编写一个将字符串转换为大写的函数，同时使其异步化。我们如何编写这个函数以便使用回调？有一个小技巧——我们可以有一个接受一个字符串并返回一个字符串的函数：

```go
func toUpperSync(word string) string { 
  //Code will go here 
} 

```

因此，将这个函数的返回类型（一个字符串）作为匿名函数的第二个参数，如下所示：

```go
func toUpperSync(word string, f func(string)) { 
  //Code will go here 
} 

```

现在，`toUpperSync`函数不返回任何内容，但也接受一个函数，巧合的是，这个函数也接受一个字符串。我们可以用通常返回的结果来执行这个函数。

```go
func toUpperSync(word string, f func(string)) { 
  f(strings.ToUpper(word)) 
} 

```

我们用提供的单词调用`strings.ToUpper`方法的结果来执行`f`函数（它返回大写的`parameter`）。我们也写`main`函数：

```go
package main 

import ( 
  "fmt" 
  "strings" 
) 

func main() { 
  toUpperSync("Hello Callbacks!", func(v string) {   
    fmt.Printf("Callback: %s\n", v) }) 
} 

func toUpperSync(word string, f func(string)) { 
  f(strings.ToUpper(word)) 
} 

```

在我们的主要代码中，我们已经定义了我们的回调。正如你所看到的，我们传递了测试`Hello Callbacks!`来将其转换为大写。接下来，我们传递回调以执行将我们的字符串转换为大写的结果。在这种情况下，我们只是在控制台上打印文本，并在其前面加上文本`Callback`。当我们执行这段代码时，我们得到以下结果：

```go
$ go run main.go
Callback: HELLO CALLBACKS!

```

严格来说，这是一个同步回调。要使它异步，我们必须引入一些并发处理：

```go
package main 
import ( 
  "fmt" 
  "strings" 
  "sync" 
) 

var wait sync.WaitGroup 

func main() { 
  wait.Add(1) 

  toUpperAsync("Hello Callbacks!", func(v string) { 
    fmt.Printf("Callback: %s\n", v) 
    wait.Done() 
  }) 

  println("Waiting async response...") 
  wait.Wait() 
} 

func toUpperAsync(word string, f func(string)) { 
  go func(){ 
    f(strings.ToUpper(word)) 
  }() 
} 

```

这是异步执行的相同代码。我们使用 WaitGroups 来处理并发（稍后我们将看到通道也可以用于此）。现在，我们的函数`toUpperAsync`就像其名字所暗示的那样是异步的。我们通过在调用回调时使用关键字`go`在不同的 Goroutine 中启动了回调。我们写了一条小消息来更准确地显示并发执行的顺序性质。我们等待直到回调信号它已经完成，然后我们可以安全地退出程序。当我们执行这个时，我们得到以下结果：

```go
$ go run main.go 

Waiting async response...
Callback: HELLO CALLBACKS!

```

正如你所看到的，程序在执行`toUpperAsync`函数的回调之前就已经到达了`main`函数的末尾。这种模式带来了许多可能性，但也让我们面临一个被称为回调地狱的大问题。

## 回调地狱

术语**回调地狱**通常用来指代当许多回调被堆叠在一起时。当它们增长过多时，这使得它们难以理解和处理。例如，使用与之前相同的代码，我们可以堆叠另一个异步调用与先前打印到控制台的内容：

```go
func main() { 
  wait.Add(1) 

  toUpperAsync("Hello Callbacks!", func(v string) { 
    toUpperAsync(fmt.Sprintf("Callback: %s\n", v), func(v string) { 
      fmt.Printf("Callback within %s", v) 
      wait.Done() 
    }) 
  }) 
  println("Waiting async response...") 
  wait.Wait() 
} 

```

（我们省略了导入、包名和`toUpperAsync`函数，因为它们没有改变。）现在我们在`toUpperAsync`函数中有一个`toUpperAsync`函数，如果我们愿意，我们可以嵌套更多。在这种情况下，我们再次传递我们先前在控制台上打印的文本，以便在下一个回调中使用。内部回调最终在控制台上打印它，得到以下输出：

```go
$ go run main.go 
Waiting async response...
Callback within CALLBACK: HELLO CALLBACKS!

```

在这种情况下，我们可以假设外部回调将在内部回调之前执行。这就是为什么我们不需要在 WaitGroup 中再添加一个。

关键在于我们在使用回调时必须小心。在非常复杂的系统中，太多的回调很难理解和处理。但是经过谨慎和理性的处理，它们是强大的工具。

# 互斥锁

如果你正在处理并发应用程序，你必须处理多个资源可能访问某个内存位置。这通常被称为**竞争条件**。

简单来说，竞争条件类似于两个人同时试图拿到最后一块披萨的时刻——他们的手碰到了一起。用变量替换披萨，用 Goroutines 替换他们的手，我们就有了一个完美的类比。

在这里，有一个人物在晚餐桌上解决这些问题——一个父亲或母亲。他们把披萨放在另一张桌子上，我们必须在拿到我们的披萨之前请求站起来的许可。不管所有的孩子同时问，他们只会允许一个孩子站起来。

好吧，互斥锁就像我们的父母。他们会控制谁可以访问披萨——我的意思是，一个变量——他们不会允许其他人访问它。

要使用互斥锁，我们必须主动锁定它；如果它已经被锁定（另一个 Goroutine 正在使用它），我们必须等待直到它再次解锁。一旦我们获得对互斥锁的访问权，我们可以再次锁定它，进行任何必要的修改，然后再次解锁它。我们将通过一个示例来看看这个过程。

## 使用互斥锁的示例-并发计数器

互斥锁在并发编程中被广泛使用。在 Go 语言中可能没有那么常见，因为它在并发编程中使用通道的更具惯性的方式，但是值得看看它们在通道不太适用的情况下是如何工作的。

对于我们的示例，我们将开发一个小型并发计数器。这个计数器将在`Counter`类型中的整数字段中添加一个。这应该以一种并发安全的方式完成。

我们的`Counter`结构定义如下：

```go
type Counter struct { 
  sync.Mutex 
  value int 
} 

```

`Counter`结构有一个`int`类型的字段，用于存储计数的当前值。它还嵌入了`sync`包中的`Mutex`类型。嵌入这个字段将允许我们锁定和解锁整个结构，而无需主动调用特定字段。

我们的`main`函数启动了 10 个 Goroutines，它们尝试将`Counter`结构的字段值加一。所有这些都是并发完成的。

```go
package main 

import ( 
  "sync" 
  "time" 
) 

func main() { 
  counter := Counter{} 

  for i := 0; i < 10; i++ { 
    go func(i int) { 
      counter.Lock() 
      counter.value++ 
      defer counter.Unlock() 
    }(i) 
  } 
  time.Sleep(time.Second) 

  counter.Lock() 
  defer counter.Unlock() 

  println(counter.value) 
} 

```

我们创建了一个名为`Counter`的类型。使用`for`循环，我们启动了总共 10 个 Goroutines，就像我们在*作为新 Goroutines 启动的匿名函数*部分看到的那样。但是在每个 Goroutine 内部，我们都锁定了计数器，以便没有更多的 Goroutines 可以访问它，将一个添加到字段值中，然后再次解锁，以便其他人可以访问它。

最后，我们将打印计数器持有的值。它必须是 10，因为我们启动了 10 个 Goroutines。

但是，我们如何知道这个程序是线程安全的呢？好吧，Go 自带了一个非常方便的内置功能，叫做“竞争检测器”。

## 介绍竞争检测器

我们已经知道什么是竞争条件。简而言之，当两个进程尝试在同一时间访问同一资源，并且在那一刻涉及一个或多个写操作（两个进程都在写入，或者一个进程在写入而另一个在读取）时，就会使用它。

Go 有一个非常方便的工具来帮助诊断竞争条件，你可以在你的测试或主应用程序中直接运行。所以让我们重用我们刚刚为*互斥锁*部分编写的示例，并使用竞争检测器运行它。这就像在我们的程序的命令执行中添加`-race`命令行标志一样简单：

```go
$ go run -race main.go 
10

```

嗯，这不是很令人印象深刻，是吗？但实际上它告诉我们，在这个程序的代码中没有检测到潜在的竞争条件。让我们通过在修改`counter`之前不锁定它来使`-race`标志的检测器警告我们可能存在竞争条件： 

```go
for i := 0; i < 10; i++ { 
  go func(i int) { 
    //counter.Lock() 
    counter.value++ 
    //counter.Unlock() 
  }(i) 
} 

```

在`for`循环内，在将`1`添加到字段值之前和之后，注释掉`Lock`和`Unlock`调用。这将引入竞争条件。让我们再次运行相同的程序，并激活竞争标志：

```go
$ go run -race main.go 
==================
WARNING: DATA RACE
Read at 0x00c42007a068 by goroutine 6:
 main.main.func1()
 [some_path]/concurrency/locks/main.go:19 +0x44
Previous write at 0x00c42007a068 by goroutine 5:
 main.main.func1()
 [some_path]/concurrency/locks/main.go:19 +0x60
Goroutine 6 (running) created at:
 main.main()
 [some_path]/concurrency/locks/main.go:21 +0xb6
Goroutine 5 (finished) created at:
 main.main()
 [some_path]/concurrency/locks/main.go:21 +0xb6
==================
10
Found 1 data race(s)
exit status 66

```

我已经减少了一些输出，以便更清楚地看到事情。我们可以看到一个大写的警告消息，上面写着“警告：数据竞争”。但这个输出很容易理解。首先，它告诉我们，我们的`main.go`文件上的*第 19 行*代表的某个内存位置正在读取某个变量。但在同一文件的*第 19 行*上也有一个写操作！

这是因为`++`操作需要读取当前值并写入一个值。这就是为什么竞争条件在同一行中，因为每次执行它时，它都会读取并写入`Counter`结构中的字段。

但是让我们记住，竞争检测器是在运行时工作的。它不会静态分析我们的代码！这是什么意思？这意味着我们的设计中可能存在潜在的竞争条件，竞争检测器不会检测到。例如：

```go
package main 

import "sync" 

type Counter struct { 
  sync.Mutex 
  value int 
} 

func main() { 
  counter := Counter{} 

  for i := 0; i < 1; i++ { 
    go func(i int) { 
      counter.value++ 
    }(i) 
  } 
} 

```

我们将保留前面示例中显示的代码。我们将从代码中删除所有锁定和解锁，并启动一个单个 Goroutine 来更新`value`字段：

```go
$ go run -race main.go
$

```

没有警告，所以代码是正确的。好吧，我们知道，按设计，它不是。我们可以将执行的 Goroutines 数量提高到两个，然后看看会发生什么：

```go
for i := 0; i < 2; i++ { 
  go func(i int) { 
    counter.value++ 
  }(i) 
} 

```

让我们再次执行程序：

```go
$ go run -race main.go
WARNING: DATA RACE
Read at 0x00c42007a008 by goroutine 6:
 main.main.func1()
 [some_path]concurrency/race_detector/main.go:15 +0x44
Previous write at 0x00c42007a008 by goroutine 5:
 main.main.func1()
 [some_path]/concurrency/race_detector/main.go:15 +0x60
Goroutine 6 (running) created at:
 main.main()
 [some_path]/concurrency/race_detector/main.go:16 +0xad
Goroutine 5 (finished) created at:
 main.main()
 [some_path]/concurrency/race_detector/main.go:16 +0xad
==================
Found 1 data race(s)
exit status 66

```

现在是的，竞争条件被检测到了。但是如果我们将正在使用的处理器数量减少到只有一个，我们也会有竞争条件吗？

```go
$ GOMAXPROCS=1 go run -race main.go
$

```

似乎没有检测到竞争条件。这是因为调度程序首先执行了一个 Goroutine，然后执行了另一个，所以最终没有发生竞争条件。但是，使用更多的 Goroutines，即使只使用一个核心，它也会警告我们有关竞争条件。

因此，竞争检测器可以帮助我们检测代码中发生的竞争条件，但它不会保护我们免受不立即执行竞争条件的糟糕设计。这是一个非常有用的功能，可以帮我们避免很多麻烦。

# 通道

通道是语言中允许我们编写并发应用程序的第二个原语。我们在*通信顺序进程*部分已经谈到了一些关于通道的内容。

通道是我们在进程之间进行通信的方式。我们可以共享一个内存位置，并使用互斥锁来控制进程的访问。但是通道为我们提供了一种更自然的方式来处理并发应用程序，这也在我们的程序中产生了更好的并发设计。

## 我们的第一个通道

如果我们不能在它们之间创建一些同步，那么使用许多 Goroutines 似乎是相当困难的。只要它们被同步，执行顺序可能就不重要了。通道是在 Go 中编写并发应用程序的第二个关键特性。

现实生活中的电视频道是将一个发射（来自工作室）连接到数百万台电视机（接收器）的东西。Go 中的通道以类似的方式工作。一个或多个 Goroutines 可以作为发射器，一个或多个 Goroutine 可以作为接收器。

还有一件事，通道默认情况下会阻塞 Goroutines 的执行，直到接收到消息。这就好像我们最喜欢的电视节目延迟发射，直到我们打开电视，这样我们就不会错过任何东西。

在 Go 中如何实现这一点？

```go
package main 

import "fmt" 

func main() { 
  channel := make(chan string) 
  go func() { 
    channel <- "Hello World!" 
  }() 

  message := <-channel 
  fmt.Println(message) 
} 

```

在 Go 中创建通道时，我们使用创建切片时使用的相同语法。使用`make`关键字创建通道，我们必须传递关键字`chan`和通道将传输的类型，本例中为字符串。有了这个，我们就有了一个名为`channel`的阻塞通道。接下来，我们启动一个 Goroutines，向通道发送消息`Hello World!`。这由直观的箭头表示，显示了流向--`Hello World!`文本传递给（`<-`）通道。这就像在变量中进行赋值一样，所以我们只能通过先写通道，然后箭头，最后是要传递的值来传递东西给通道。我们不能写`"Hello World!" -> channel`。

正如我们之前提到的，这个通道会阻塞 Goroutines 的执行，直到接收到消息。在这种情况下，`main`函数的执行会在启动的 Goroutines 的消息到达通道的另一端的行`message := <-channel`之前停止。在这种情况下，箭头指向相同的方向，但是放在通道之前，表示数据正在从通道中提取并分配给一个名为`message`的新变量（使用新的赋值"`:=`"运算符）。

在这种情况下，我们不需要使用 WaitGroup 来同步`main`函数和创建的 Goroutines，因为通道的默认性质是阻塞直到接收到数据。但是反过来呢？如果 Goroutine 发送消息时没有接收器，它会继续吗？让我们编辑这个例子来看看：

```go
package main 

import ( 
  "fmt" 
  "time" 
) 

func main() { 
  channel := make(chan string) 

  var waitGroup sync.WaitGroup 

  waitGroup.Add(1) 
  go func() { 
    channel <- "Hello World!" 
    println("Finishing goroutine") 
    waitGroup.Done() 
  }() 

  time.Sleep(time.Second) 
  message := <-channel 
  fmt.Println(message) 
  waitGroup.Wait() 
} 

```

我们将再次使用`Sleep`函数。在这种情况下，我们在 Goroutine 完成时打印一条消息。最大的区别在于`main`函数。现在，在我们监听通道获取数据之前，我们等待一秒钟：

```go
$ go run main.go

Finishing goroutine
Hello World!

```

输出可能会有所不同，因为再次强调，执行顺序没有保证，但现在我们可以看到，直到一秒钟过去之前都没有消息被打印出来。在初始延迟之后，我们开始监听通道，接收数据并打印出来。因此，发射器也必须等待来自通道另一侧的提示才能继续执行。

总之，通道是通过一端发送数据，另一端接收数据的方式，在 Goroutines 之间进行通信（就像管道一样）。在它们的默认状态下，发射器 Goroutine 将阻塞其执行，直到接收器 Goroutine 接收数据。接收器 Goroutine 也是一样，它将阻塞，直到某个发射器通过通道发送数据。因此，你可以有被动的监听器（等待数据）或被动的发射器（等待监听器）。

## 缓冲通道

缓冲通道的工作方式与默认的非缓冲通道类似。你也可以通过使用箭头来传递和获取值，但与非缓冲通道不同的是，发送者不需要等待某个 Goroutine 接收它们发送的数据：

```go
package main 

import ( 
  "fmt" 
  "time" 
) 

func main() { 
  channel := make(chan string, 1) 

  go func() { 
    channel <- "Hello World!" 
    println("Finishing goroutine") 
  }() 

  time.Sleep(time.Second) 

  message := <-channel 
  fmt.Println(message) 
} 

```

这个例子与我们用于通道的第一个例子类似，但现在我们在`make`语句中将通道的容量设置为 1。通过这样做，我们告诉编译器，在被阻塞之前，该通道可以容纳一个字符串。因此，第一个字符串不会阻塞发射器，但第二个会。让我们运行这个例子：

```go
$ go run main.go

Finishing goroutine
Hello World!

```

现在我们可以随意运行这个小程序，输出将始终按照相同的顺序。这一次，我们启动了并发函数并等待了一秒钟。以前，匿名函数在第二秒过去并且有人可以接收到发送的数据之前是不会继续的。在这种情况下，使用缓冲通道，数据被保存在通道中并释放 Goroutine 以继续执行。在这种情况下，Goroutine 总是在等待时间过去之前完成。

这个新通道的大小为 1，因此第二个消息会阻塞 Goroutine 的执行：

```go
package main 

import ( 
  "fmt" 
  "time" 
) 

func main() { 
  channel := make(chan string, 1) 

  go func() { 
    channel <- "Hello World! 1" 
    channel <- "Hello World! 2" 
    println("Finishing goroutine") 
  }() 

  time.Sleep(time.Second) 

  message := <-channel 
  fmt.Println(message) 
} 

```

在这里，我们添加了第二个`Hello world! 2`消息，并为其提供了一个索引。在这种情况下，该程序的输出可能如下所示：

```go
$ go run main.go
Hello World! 1

```

表示我们刚刚从通道缓冲区中取出了一条消息，我们已经打印出来了，并且`main`函数在启动的 Goroutine 完成之前就结束了。当发送第二条消息时，Goroutine 被阻塞，直到另一端接收了第一条消息。然后它打印出来得如此之快，以至于没有时间打印出消息来显示 Goroutine 的结束。如果你在控制台上不断执行程序，sooner or later 调度器会在主线程之前完成 Goroutine 的执行。

## 方向性通道

关于 Go 通道的一个很酷的特性是，当我们将它们用作参数时，我们可以限制它们的方向性，使它们只能用于发送或接收。如果通道在受限方向上被使用，编译器会报错。这个特性为 Go 应用程序应用了新的静态类型级别，并使代码更易理解和更易读。

我们将用通道来举一个简单的例子：

```go
package main 

import ( 
  "fmt" 
  "time" 
) 

func main() { 
  channel := make(chan string, 1) 

 go func(ch chan<- string) { 
    ch <- "Hello World!" 
    println("Finishing goroutine") 
  }(channel) 

  time.Sleep(time.Second) 

  message := <-channel 
  fmt.Println(message) 
} 

```

在我们启动新的 Goroutine `go func(ch chan<- string)`的那一行，声明了传递给这个函数的通道只能用作输入通道，你不能监听它。

我们也可以传递一个只用作接收器通道的通道：

```go
func receivingCh(ch <-chan string) { 
  msg := <-ch 
  println(msg) 
} 

```

正如你所看到的，箭头位于`chan`关键字的相反方向，表示从通道中提取操作。请记住，通道箭头总是指向左边，以指示接收通道，它必须指向左边，以指示插入通道，它必须指向右边。

如果我们试图通过这个*只接收*通道发送一个值，编译器会抱怨：

```go
func receivingCh(ch <-chan string) { 
  msg := <-ch 
  println(msg) 
  ch <- "hello" 
} 

```

这个函数有一个只接收通道，我们将尝试通过它发送消息`hello`。让我们看看编译器说了什么：

```go
$ go run main.go
./main.go:20: invalid operation: ch <- "hello2" (send to receive-only type <-chan string)

```

它不喜欢它，并要求我们纠正它。现在代码更加可读和安全，我们只是在`chan`参数的前面或后面放置了一个箭头。

## 选择语句

`select`语句也是 Go 中的一个关键特性。它用于在一个 Goroutine 中处理多个通道输入。事实上，它打开了许多可能性，在接下来的章节中我们将广泛使用它。

![选择语句](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/go-dsn-ptn/img/B05557_08_04-1.jpg)

在`select`结构中，我们要求程序在一个或多个通道之间选择接收它们的数据。我们可以将这些数据保存在一个变量中，并在完成选择之前对其进行处理。`select`结构只执行一次；不管它是否在监听多个通道，它只会执行一次，代码将继续执行。如果我们希望它多次处理相同的通道，我们必须将其放在一个`for`循环中。

我们将创建一个小应用程序，将消息`hello`和消息`goodbye`发送到同一个 Goroutine 中，该 Goroutine 将打印它们，并在五秒内没有收到其他消息时退出。

首先，我们将创建一个通用函数，用于通过通道发送一个字符串：

```go
func sendString(ch chan<- string, s string) { 
  ch <- s 
} 

```

现在我们可以通过简单调用`sendString`方法向通道发送一个字符串。现在是接收者的时间了。接收者将从两个通道接收消息--一个发送`hello`消息的通道，一个发送`goodbye`消息的通道。你也可以在之前的图表中看到这一点：

```go
func receiver(helloCh, goodbyeCh <-chan string, quitCh chan<- bool) { 
  for { 
    select { 
    case msg := <-helloCh: 
      println(msg) 
    case msg := <-goodbyeCh: 
      println(msg) 
    case <-time.After(time.Second * 2): 
      println("Nothing received in 2 seconds. Exiting") 
      quitCh <- true 
      break 
    } 
  } 
} 

```

让我们从参数开始。这个函数接受三个通道--两个接收通道和一个用于通过它发送东西的通道。然后，它使用`for`关键字开始一个无限循环。这样我们就可以永远保持对两个通道的监听。

在`select`块的范围内，我们必须为我们想要处理的每个通道使用一个 case（你是否意识到它与`switch`语句有多么相似？）。让我们一步一步地看看这三种情况：

+   第一种情况接收来自`helloCh`参数的传入数据，并将其保存在一个名为`msg`的变量中。然后它打印出这个变量的内容。

+   第二种情况接收来自`goodbyeCh`参数的传入数据，并将其保存在一个名为`msg`的变量中。然后它也打印出这个变量的内容。

+   第三种情况非常有趣。它调用`time`函数。之后，如果我们检查它的签名，它接受一个时间和持续时间值，并返回一个接收通道。这个接收通道将在指定的持续时间过去后接收一个时间，`time`的值。在我们的例子中，我们使用它返回的通道作为超时。因为每次处理后`select`都会重新启动，计时器也会重新启动。这是一个非常简单的方法，可以为等待一个或多个通道的响应的 Goroutine 设置一个计时器。

`main`函数准备就绪：

```go
package main 
import "time" 

func main() { 
  helloCh := make(chan string, 1) 
  goodbyeCh := make(chan string, 1) 
  quitCh := make(chan bool) 
  go receiver(helloCh, goodbyeCh, quitCh) 

  go sendString(helloCh, "hello!") 

  time.Sleep(time.Second) 

  go sendString(goodbyeCh, "goodbye!") 
  <-quitCh 
} 

```

再一步一步地，我们创建了这个练习中需要的三个通道。然后，我们在一个不同的 Goroutine 中启动了我们的`receiver`函数。这个 Goroutine 由 Go 的调度程序处理，我们的程序继续执行。我们启动了一个新的 Goroutine，向`helloCh`参数发送消息`hello`。同样，这将在 Go 的调度程序决定时最终发生。

我们的程序再次继续，并等待一秒。在这个间歇中，Go 的调度程序将有时间执行接收者和第一条消息（如果尚未执行），所以`hello!`消息将在间歇期间出现在控制台上。

一个新的消息通过`goodbye`通道以`goodbye!`文本的形式发送到一个新的 Goroutine 中，我们的程序再次继续执行，等待在`quitCh`参数中接收到一条消息的行。

我们已经启动了三个 Goroutine--接收者仍在运行，第一个消息在消息被`select`语句处理时已经完成，第二个消息几乎立即被打印并完成了。所以此刻只有接收者在运行，如果在接下来的两秒内没有收到其他消息，它将处理来自`time`结构的传入消息。在`channel`类型之后，打印一条消息以表明它正在退出，向`quitCh`发送一个`true`，并中断它正在循环的无限循环。

让我们运行这个小应用程序：

```go
$ go run main.go

hello!
goodbye!
Nothing received in 2 seconds. Exiting

```

结果可能并不令人印象深刻，但概念是清晰的。我们可以使用 select 语句在同一个 Goroutine 中处理许多传入的通道。

## 也可以对通道进行范围遍历！

我们将看到关于通道的最后一个特性是对通道进行范围遍历。我们谈论的是范围关键字。我们已经广泛使用它来遍历列表，我们也可以用它来遍历通道：

```go
package main 

import "time" 

func main() { 
  ch := make(chan int) 

  go func() { 
    ch <- 1 
    time.Sleep(time.Second) 

    ch <- 2 

    close(ch) 
  }() 
  for v := range ch { 
    println(v) 
  } 
} 

```

在这种情况下，我们创建了一个非缓冲通道，但它也可以使用缓冲通道。我们在一个新的 Goroutine 中启动一个函数，该函数通过通道发送数字"1"，等待一秒，发送数字"2"，然后关闭通道。

最后一步是对通道进行范围遍历。语法与列表范围非常相似。我们将从通道中存储传入的数据到变量`v`，并将这个变量打印到控制台。范围会一直迭代，直到通道关闭，从通道中获取数据。

你能猜出这个小程序的输出吗？

```go
$ go run main.go

1
2

```

同样，并不令人印象深刻。它打印数字"1"，然后等待一秒，打印数字"2"，然后退出应用程序。

根据这个并发应用程序的设计，范围会迭代可能从通道中传入的数据

通道

直到并发 Goroutine 关闭这个通道。在那一刻，范围结束，应用程序可以退出。

范围在从通道中获取数据时非常有用，并且通常用于多个不同的 Goroutine 向同一个通道发送数据的扇入模式中。

# 使用所有这些-并发单例

既然我们知道如何创建 Goroutines 和通道，我们将把所有的知识放在一个单一的包中。回想一下前几章，当我们解释单例模式时--它是一种只能在我们的代码中存在一次的结构或变量。对这个结构的所有访问都应该使用所描述的模式，但实际上，它并不是并发安全的。

现在我们将考虑并发编写。我们将编写一个并发计数器，就像我们在*互斥*部分中编写的那样，但这次我们将使用通道来解决它。

## 单元测试

为了限制对`singleton`实例的并发访问，只有一个 Goroutine 能够访问它。我们将使用通道访问它--第一个通道用于添加一个，第二个通道用于获取当前计数，第三个通道用于停止 Goroutine。

我们将使用从两个不同的`singleton`实例启动的 10,000 个不同的 Goroutine 添加 10,000 次。然后，我们将引入一个循环来检查`singleton`的计数，直到达到 5,000，但我们将在开始循环之前写下计数是多少。

一旦计数达到 5,000，循环将退出并退出运行的 Goroutine--测试代码看起来像这样：

```go
package channel_singleton 
import ( 
  "testing" 
  "time" 
  "fmt" 
) 

func TestStartInstance(t *testing.T) { 
  singleton := GetInstance() 
  singleton2 := GetInstance() 

  n := 5000 

  for i := 0; i < n; i++ { 
    go singleton.AddOne() 
    go singleton2.AddOne() 
  } 

  fmt.Printf("Before loop, current count is %d\n", singleton.GetCount()) 

  var val int 
  for val != n*2 { 
    val = singleton.GetCount() 
    time.Sleep(10 * time.Millisecond) 
  } 
  singleton.Stop() 
} 

```

在这里，我们可以看到我们将使用的完整测试。在创建两个`singleton`实例之后，我们创建了一个`for`循环，从每个实例中启动`AddOne`方法 5,000 次。这还没有发生；它们正在被调度，最终将被执行。我们打印`singleton`实例的计数，以清楚地看到这种可能性；根据计算机的不同，它将打印出一个大于 0 且小于 10,000 的数字。

在停止持有计数的 Goroutine 之前的最后一步是进入一个循环，检查计数的值，并在值不是预期值（10,000）时等待 10 毫秒。一旦达到这个值，循环将退出，我们可以停止`singleton`实例。

由于要求非常简单，我们将直接跳转到实施。

## 实施

首先，我们将创建将保存计数的 Goroutine：

```go
var addCh chan bool = make(chan bool) 
var getCountCh chan chan int = make(chan chan int) 
var quitCh chan bool = make(chan bool) 

func init() { 
  var count int 

  go func(addCh <-chan bool, getCountCh <-chan chan int, quitCh <-chan bool) { 
    for { 
      select { 
      case <-addCh: 
        count++ 
      case ch := <-getCountCh: 
        ch <- count 
      case <-quitCh: 
        return 
      } 
    } 
  }(addCh, getCountCh, quitCh) 
} 

```

我们创建了三个通道，正如我们之前提到的：

+   `addCh`通道用于与添加一个计数的动作进行通信，并接收一个`bool`类型，只是为了发出“添加一个”的信号（虽然我们可以发送数字，但我们不需要）。

+   `getCountCh`通道将返回一个将接收计数的当前值的通道。花点时间思考一下`getCountCh`通道-它是一个接收整数类型的通道的通道。听起来有点复杂，但当我们完成示例时，它会更有意义，不用担心。

+   `quitCh`通道将通知 Goroutine 应该结束其无限循环并结束自身。

现在我们有了执行我们想要的操作所需的通道。接下来，我们启动 Goroutine，将通道作为参数传递。正如你所看到的，我们正在限制通道的方向，以提供更多的类型安全性。在这个 Goroutine 内部，我们创建了一个无限的`for`循环。这个循环不会停止，直到在其中执行了一个中断。

最后，`select`语句，如果你还记得，是一种同时从不同通道接收数据的方法。我们有三种情况，因此我们监听了作为参数输入的三个传入通道：

+   `addCh`情况将计数增加一。请记住，每次迭代只能执行一个情况，以便没有 Goroutine 可以访问当前计数，直到我们完成添加一个。

+   `getCountCh`通道接收一个接收整数的通道，因此我们捕获了这个新通道，并通过它发送当前值到另一端。

+   `quitCh`通道中断`for`循环，因此 Goroutine 结束。

最后一件事。在任何包中，`init()`函数将在程序执行时执行，因此我们不需要担心从我们的代码中特别执行此函数。

现在，我们将创建测试所期望的类型。我们将看到所有的魔术和逻辑都隐藏在这种类型中，对最终用户来说（正如我们在测试代码中看到的）：

```go
type singleton struct {} 

var instance singleton 
func GetInstance() *singleton { 
  return &instance 
} 

```

`singleton`类型的工作方式类似于第二章中的工作方式，*创建模式-单例，生成器，工厂，原型和抽象工厂*，但这次它不会保存计数值。我们为其创建了一个名为`instance`的本地值，并在调用`GetInstance()`方法时返回指向此实例的指针。这样做并不是严格必要的，但我们不需要在每次访问计数变量时分配`singleton`类型的新实例。

首先，`AddOne()`方法将不得不将当前计数加一。如何？通过向`addCh`通道发送`true`。这很简单：

```go
func (s *singleton) AddOne() { 
  addCh <- true 
} 

```

这个小片段将依次触发我们的 Goroutine 中的`addCh`情况。`addCh`情况只是执行`count++`并完成，让`select`通道控制流执行`init`函数中的下一个指令：

```go
func (s *singleton) GetCount() int { 
  resCh := make(chan int) 
  defer close(resCh) 
  getCountCh <- resCh 
  return <-resCh 
} 

```

`GetCount`方法每次被调用时都会创建一个通道，并推迟在函数结束时关闭它的操作。这个通道是无缓冲的，正如我们在本章中之前看到的那样。无缓冲通道会阻塞执行，直到它接收到一些数据。因此，我们将这个通道发送到`getCountCh`，它也是一个通道，并且有效地期望一个`chan int`类型通过它发送当前计数值。`GetCount()`方法将不会返回，直到`count`变量的值到达`resCh`通道。

你可能会想，为什么我们不在两个方向上使用相同的通道来接收计数的值？这样我们就可以避免分配。如果我们在`GetCount()`方法中使用相同的通道，我们将在这个通道中有两个监听器--一个在`select`语句中，在文件的开头的`init`函数中，一个在那里，所以当发送值时它可以解析到任何一个：

```go
func (s *singleton) Stop() { 
  quitCh <- true 
  close(addCh) 
  close(getCountCh) 
  close(quitCh) 
} 

```

最后，我们必须在某个时刻停止 Goroutine。`Stop`方法向`singleton`类型的 Goroutine 发送值，以触发`quitCh`情况并打破`for`循环。下一步是关闭所有通道，以便不再通过它们发送数据。当你知道你不会再使用一些通道时，这非常方便。

执行测试并查看时间：

```go
$ go test -v .
=== RUN   TestStartInstance
Before loop, current count is 4911
--- PASS: TestStartInstance (0.03s)
PASS
ok

```

输出的代码很少，但一切都按预期工作。在测试中，我们在进入循环之前打印了计数的值，直到达到值 10000。正如我们之前看到的，Go 调度器将尝试使用尽可能多的 OS 线程来运行 Goroutines 的内容，通过使用`GOMAXPROCS`配置来配置。在我的电脑上，它设置为`4`，因为我的电脑有四个核心。但关键是我们可以看到在启动 Goroutine（或 10000 个）和下一个执行行之后会发生很多事情。

但互斥锁的使用呢？

```go
type singleton struct { 
  count int 
  sync.RWMutex 
} 

var instance singleton 

func GetInstance() *singleton { 
  return &instance 
} 

func (s *singleton) AddOne() { 
  s.Lock() 
  defer s.Unlock() 
  s.count++ 
} 

func (s *singleton) GetCount()int { 
  s.RLock() 
  defer s.RUnlock() 
  return s.count 
} 

```

在这种情况下，代码要简洁得多。正如我们之前看到的，我们可以在`singleton`结构中嵌入互斥锁。计数也保存在`count`字段中，`AddOne()`和`GetCount()`方法锁定和解锁值以确保并发安全。

还有一件事。在这个`singleton`实例中，我们使用的是`RWMutex`类型，而不是已知的`sync.Mutex`类型。这里的主要区别在于`RWMutex`类型有两种锁--读锁和写锁。通过调用`RLock`方法执行读锁，只有在当前存在写锁时才会等待。同时，它只会阻止写锁，因此可以并行进行许多读操作。这是有道理的；我们不希望因为另一个 Goroutine 也在读取值（它不会改变）而阻塞想要读取值的 Goroutine。`sync.RWMutex`类型帮助我们在代码中实现这种逻辑。

# 摘要

我们已经看到了如何使用互斥锁和通道编写并发的 Singleton。虽然通道的例子更复杂，但它也展示了 Go 并发的核心力量，因为你可以通过简单地使用通道实现复杂的事件驱动架构。

请记住，如果你以前没有编写过并发代码，开始以舒适的方式并发思考可能需要一些时间。但这并不是练习不能解决的问题。

我们已经看到了设计并发应用程序以实现程序并行性的重要性。我们已经处理了大部分 Go 的原语，编写了并发应用程序，现在我们可以编写常见的并发设计模式。
