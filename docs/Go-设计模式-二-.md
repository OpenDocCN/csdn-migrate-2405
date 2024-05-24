# Go 设计模式（二）

> 原文：[`zh.annas-archive.org/md5/8A110D02C69060149D76F09768570714`](https://zh.annas-archive.org/md5/8A110D02C69060149D76F09768570714)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第三章：结构模式 - 组合，适配器和桥接设计模式

我们将开始我们的结构模式之旅。结构模式，顾名思义，帮助我们用常用的结构和关系来塑造我们的应用程序。

Go 语言本质上鼓励使用组合，几乎完全不使用继承。因此，我们一直在广泛使用**组合**设计模式，所以让我们从定义组合设计模式开始。

# 组合设计模式

组合设计模式倾向于组合（通常定义为*拥有*关系）而不是继承（*是*关系）。自上世纪九十年代以来，*组合优于继承*的方法一直是工程师之间讨论的话题。我们将学习如何使用*拥有*方法创建对象结构。总的来说，Go 没有继承，因为它不需要！

## 描述

在组合设计模式中，您将创建对象的层次结构和树。对象内部有不同的对象，具有它们自己的字段和方法。这种方法非常强大，解决了继承和多重继承的许多问题。例如，典型的继承问题是当您有一个实体从两个完全不同的类继承时，它们之间绝对没有关系。想象一个训练的运动员，和一个游泳的游泳者：

+   `Athlete`类有一个`Train()`方法

+   `Swimmer`类有一个`Swim()`方法

`Swimmer`类继承自`Athlete`类，因此它继承了其`Train`方法并声明了自己的`Swim`方法。您还可以有一个自行车手，也是一名运动员，并声明了一个`Ride`方法。

但现在想象一下，一种会吃东西的动物，比如一只也会叫的狗：

+   `Cyclist`类有一个`Ride()`方法

+   `Animal`类有`Eat()`，`Dog()`和`Bark()`方法

没有花哨的东西。您也可以有一条鱼是一种动物，是的，会游泳！那么，您如何解决呢？鱼不能是一个还会训练的游泳者。鱼不训练（据我所知！）。您可以创建一个带有`Swim`方法的`Swimmer`接口，并使游泳者运动员和鱼实现它。这将是最好的方法，但您仍然必须两次实现`swim`方法，因此代码的可重用性将受到影响。那么三项全能运动员呢？他们是游泳，跑步和骑车的运动员。通过多重继承，您可以有一种解决方案，但这很快就会变得复杂且难以维护。

## 目标

正如您可能已经想象的那样，组合的目标是避免这种层次结构混乱，其中应用程序的复杂性可能会增长太多，代码的清晰度受到影响。

## 游泳者和鱼

我们将以 Go 的方式解决运动员和游泳的鱼的问题。在 Go 中，我们可以使用两种类型的组合--**直接**组合和**嵌入**组合。我们将首先通过使用直接组合来解决这个问题，即在结构体内部拥有所需的一切。

## 需求和验收标准

要求与之前描述的要求相似。我们将有一个运动员和一个游泳者。我们还将有一个动物和一条鱼。`Swimmer`和`Fish`方法必须共享代码。运动员必须训练，动物必须吃：

+   我们必须有一个带有`Train`方法的`Athlete`结构

+   我们必须有一个带有`Swim`方法的`Swimmer`

+   我们必须有一个带有`Eat`方法的`Animal`结构

+   我们必须有一个带有`Swim`方法的`Fish`结构，该方法与`Swimmer`共享，而不会出现继承或层次结构问题

## 创建组合

组合设计模式是一种纯粹的结构模式，除了结构本身之外，没有太多需要测试的地方。在这种情况下，我们不会编写单元测试，而只是描述在 Go 中创建这些组合的方法。

首先，我们将从`Athlete`结构和其`Train`方法开始：

```go
type Athlete struct{} 

func (a *Athlete) Train() { 
  fmt.Println("Training") 
} 

```

前面的代码非常简单。它的`Train`方法打印单词`Training`和一个换行符。我们将创建一个具有`Athlete`结构的复合游泳者：

```go
type CompositeSwimmerA struct{ 
  MyAthlete Athlete 
  MySwim func() 
} 

```

`CompositeSwimmerA`类型有一个`Athlete`类型的`MyAthlete`字段。它还存储一个`func()`类型。请记住，在 Go 中，函数是一等公民，它们可以像任何变量一样作为参数、字段或参数使用。因此，`CompositeSwimmerA`有一个`MySwim`字段，其中存储了一个**闭包**，它不带参数并且不返回任何内容。我如何将函数分配给它呢？好吧，让我们创建一个与`func()`签名匹配的函数（无参数，无返回）：

```go
func Swim(){ 
  fmt.Println("Swimming!") 
} 

```

就是这样！`Swim()`函数不带参数并且不返回任何内容，因此它可以用作`CompositeSwimmerA`结构中的`MySwim`字段：

```go
swimmer := CompositeSwimmerA{ 
  MySwim: Swim, 
} 

swimmer.MyAthlete.Train() 
swimmer.MySwim() 

```

因为我们有一个名为`Swim()`的函数，我们可以将其分配给`MySwim`字段。请注意，`Swim`类型没有括号，这将执行其内容。这样我们就可以将整个函数复制到`MySwim`方法中。

但等等。我们还没有将运动员传递给`MyAthlete`字段，我们正在使用它！这将失败！让我们看看执行此片段时会发生什么：

```go
$ go run main.go
Training
Swimming!

```

这很奇怪，不是吗？实际上并不是，因为 Go 中的零初始化的性质。如果您没有将`Athlete`结构传递给`CompositeSwimmerA`类型，编译器将创建一个其值为零初始化的结构，也就是说，一个`Athlete`结构，其字段的值初始化为零。如果这看起来令人困惑，请查看第一章*准备...开始...跑！*来回顾零初始化。再次考虑`CompositeSwimmerA`结构代码：

```go
type CompositeSwimmerA struct{ 
  MyAthlete Athlete 
  MySwim    func() 
} 

```

现在我们有一个存储在`MySwim`字段中的函数指针。我们可以以相同的方式分配`Swim`函数，但需要多一步：

```go
localSwim := Swim 

swimmer := CompositeSwimmerA{ 
  MySwim: localSwim, 
} 

swimmer.MyAthlete.Train() 
swimmer.MySwim () 

```

首先，我们需要一个包含函数`Swim`的变量。这是因为函数没有地址，无法将其传递给`CompositeSwimmerA`类型。然后，为了在结构体内使用这个函数，我们必须进行两步调用。

那么我们的鱼问题呢？有了我们的`Swim`函数，这不再是问题。首先，我们创建`Animal`结构：

```go
type Animal struct{} 

func (r *Animal)Eat() { 
  println("Eating") 
} 

```

然后我们将创建一个嵌入`Animal`对象的`Shark`对象：

```go
type Shark struct{ 
  Animal 
  Swim func() 
} 

```

等一下！`Animal`类型的字段名在哪里？你有没有意识到我在上一段中使用了*embed*这个词？这是因为在 Go 中，您还可以将对象嵌入到对象中，使其看起来很像继承。也就是说，我们不必显式调用字段名来访问其字段和方法，因为它们将成为我们的一部分。因此，以下代码将是完全正常的：

```go
fish := Shark{ 
  Swim: Swim, 
} 

fish.Eat() 
fish.Swim() 

```

现在我们有一个`Animal`类型，它是零初始化并嵌入的。这就是为什么我可以调用`Animal`结构的`Eat`方法而不创建它或使用中间字段名。此片段的输出如下：

```go
$ go run main.go 
Eating 
Swimming!

```

最后，有第三种使用组合模式的方法。我们可以创建一个带有`Swim`方法的`Swimmer`接口和一个`SwimmerImpl`类型，将其嵌入到运动员游泳者中：

```go
type Swimmer interface { 
  Swim() 
} 
type Trainer interface { 
  Train() 
} 

type SwimmerImpl struct{} 
func (s *SwimmerImpl) Swim(){ 
  println("Swimming!") 
} 

type CompositeSwimmerB struct{ 
  Trainer 
  Swimmer 
} 

```

使用这种方法，您可以更明确地控制对象的创建。`Swimmer`字段被嵌入，但不会被零初始化，因为它是一个指向接口的指针。这种方法的正确使用将是以下方式：

```go
swimmer := CompositeSwimmerB{ 
  &Athlete{}, 
  &SwimmerImpl{}, 
} 

swimmer.Train() 
swimmer.Swim() 

```

`CompositeSwimmerB`的输出如下，如预期的那样：

```go
$ go run main.go
Training
Swimming!

```

哪种方法更好？嗯，我有个人偏好，不应被视为金科玉律。在我看来，*接口*方法是最好的，原因有很多，但主要是因为明确性。首先，您正在使用首选的接口而不是结构。其次，您不会将代码的部分留给编译器的零初始化特性。这是一个非常强大的功能，但必须小心使用，因为它可能导致运行时问题，而在使用接口时，您会在编译时发现这些问题。在不同的情况下，零初始化实际上会在运行时为您节省，事实上！但我尽可能多地使用接口，所以这实际上并不是一个选项。

## 二叉树组合

另一种非常常见的组合模式是在使用二叉树结构时。在二叉树中，您需要在字段中存储自身的实例：

```go
type Tree struct { 
  LeafValue int 
  Right     *Tree 
  Left      *Tree 
} 

```

这是一种递归组合，由于递归的性质，我们必须使用指针，以便编译器知道它必须为此结构保留多少内存。我们的`Tree`结构为每个实例存储了一个`LeafValue`对象，并在其`Right`和`Left`字段中存储了一个新的`Tree`。

有了这个结构，我们可以创建一个对象，就像这样：

```go
root := Tree{ 
  LeafValue: 0, 
  Right:&Tree{ 
    LeafValue: 5, 
    Right: &1Tree{ 6, nil, nil }, 
    Left: nil, 
  }, 
  Left:&Tree{ 4, nil, nil }, 
} 

```

我们可以这样打印其最深层分支的内容：

```go
fmt.Println(root.Right.Right.LeafValue) 

$ go run main.go 
6

```

## 组合模式与继承

在 Go 中使用组合设计模式时，必须非常小心，不要将其与继承混淆。例如，当您在`Son`结构中嵌入`Parent`结构时，就像以下示例中一样：

```go
type Parent struct { 
  SomeField int 
} 

type Son struct { 
  Parent 
} 

```

您不能认为`Son`结构也是`Parent`结构。这意味着您不能将`Son`结构的实例传递给期望`Parent`结构的函数，就像以下示例中一样：

```go
func GetParentField(p *Parent) int{ 
  fmt.Println(p.SomeField) 
} 

```

当您尝试将`Son`实例传递给`GetParentField`方法时，您将收到以下错误消息：

```go
cannot use son (type Son) as type Parent in argument to GetParentField

```

事实上，这是有很多道理的。这个问题的解决方案是什么？嗯，您可以简单地将`Son`结构与父结构组合起来，而不是嵌入，以便稍后可以访问`Parent`实例：

```go
type Son struct { 
  P Parent 
} 

```

所以现在你可以使用`P`字段将其传递给`GetParentField`方法：

```go
son := Son{} 
GetParentField(son.P) 

```

## 关于组合模式的最后几句话

在这一点上，您应该真的很熟悉使用组合设计模式。这是 Go 语言中非常惯用的特性，从纯面向对象的语言切换过来并不是非常痛苦的。组合设计模式使我们的结构可预测，但也允许我们创建大多数设计模式，正如我们将在后面的章节中看到的。

# 适配器设计模式

最常用的结构模式之一是**适配器**模式。就像在现实生活中，您有插头适配器和螺栓适配器一样，在 Go 中，适配器将允许我们使用最初未为特定任务构建的东西。

## 描述

当接口过时且无法轻松或快速替换时，适配器模式非常有用。相反，您可以创建一个新接口来处理应用程序当前需求，该接口在底层使用旧接口的实现。

适配器还帮助我们在应用程序中保持*开闭原则*，使其更可预测。它们还允许我们编写使用一些无法修改的基础的代码。

### 注意

开闭原则首次由 Bertrand Meyer 在他的书《面向对象的软件构造》中提出。他指出代码应该对新功能开放，但对修改关闭。这是什么意思？嗯，这意味着一些事情。一方面，我们应该尝试编写可扩展的代码，而不仅仅是可工作的代码。同时，我们应该尽量不修改源代码（你的或其他人的），因为我们并不总是意识到这种修改的影响。只需记住，代码的可扩展性只能通过设计模式和面向接口的编程来实现。

## 目标

适配器设计模式将帮助您满足最初不兼容的代码部分的需求。这是在决定适配器模式是否适合您的问题时要牢记的关键点——最初不兼容但必须一起工作的两个接口是适配器模式的良好候选对象（但它们也可以使用外观模式，例如）。

## 使用不兼容的接口与适配器对象

对于我们的示例，我们将有一个旧的`Printer`接口和一个新的接口。新接口的用户不希望旧接口的签名，并且我们需要一个适配器，以便用户仍然可以在必要时使用旧的实现（例如与一些旧代码一起工作）。

## 需求和验收标准

有一个名为`LegacyPrinter`的旧接口和一个名为`ModernPrinter`的新接口，创建一个结构来实现`ModernPrinter`接口，并按照以下步骤使用`LegacyPrinter`接口：

1.  创建一个实现`ModernPrinter`接口的适配器对象。

1.  新的适配器对象必须包含`LegacyPrinter`接口的实例。

1.  在使用`ModernPrinter`时，它必须在后台调用`LegacyPrinter`接口，并在前面加上文本`Adapter`。

## 单元测试我们的打印机适配器

我们将首先编写旧代码，但不会测试它，因为我们应该想象它不是我们的代码：

```go
type LegacyPrinter interface { 
  Print(s string) string 
} 
type MyLegacyPrinter struct {} 

func (l *MyLegacyPrinter) Print(s string) (newMsg string) { 
  newMsg = fmt.Sprintf("Legacy Printer: %s\n", s) 
  println(newMsg) 
  return 
} 

```

名为`LegacyPrinter`的旧接口有一个接受字符串并返回消息的`Print`方法。我们的`MyLegacyPrinter`结构实现了`LegacyPrinter`接口，并通过在传递的字符串前加上文本`Legacy Printer:`来修改传递的字符串。在修改文本后，`MyLegacyPrinter`结构将文本打印到控制台，然后返回它。

现在我们将声明我们需要适配的新接口：

```go
type ModernPrinter interface { 
  PrintStored() string 
} 

```

在这种情况下，新的`PrintStored`方法不接受任何字符串作为参数，因为它必须提前存储在实现者中。我们将调用我们的适配器模式的`PrinterAdapter`接口：

```go
type PrinterAdapter struct{ 
  OldPrinter LegacyPrinter 
  Msg        string 
} 
func(p *PrinterAdapter) PrintStored() (newMsg string) { 
  return 
} 

```

如前所述，`PrinterAdapter`适配器必须有一个字段来存储要打印的字符串。它还必须有一个字段来存储`LegacyPrinter`适配器的实例。因此，让我们编写单元测试：

```go
func TestAdapter(t *testing.T){ 
  msg := "Hello World!" 

```

我们将使用消息`Hello World!`作为我们的适配器。当将此消息与`MyLegacyPrinter`结构的实例一起使用时，它会打印文本`Legacy Printer: Hello World!`：

```go
adapter := PrinterAdapter{OldPrinter: &MyLegacyPrinter{}, Msg: msg} 

```

我们创建了一个名为`adapter`的`PrinterAdapter`接口的实例。我们将`MyLegacyPrinter`结构的实例作为`LegacyPrinter`字段传递给`OldPrinter`。此外，我们在`Msg`字段中设置要打印的消息：

```go
returnedMsg := adapter.PrintStored() 

if returnedMsg != "Legacy Printer: Adapter: Hello World!\n" { 
  t.Errorf("Message didn't match: %s\n", returnedMsg) 
} 

```

然后我们使用了`ModernPrinter`接口的`PrintStored`方法；这个方法不接受任何参数，必须返回修改后的字符串。我们知道`MyLegacyPrinter`结构返回传递的字符串，并在前面加上文本`LegacyPrinter:`，适配器将在前面加上文本`Adapter:`。因此，最终我们必须有文本`Legacy Printer: Adapter: Hello World!\n`。

由于我们正在存储接口的实例，因此我们还必须检查我们处理指针为 nil 的情况。这是通过以下测试完成的：

```go
adapter = PrinterAdapter{OldPrinter: nil, Msg: msg} 
returnedMsg = adapter.PrintStored() 

if returnedMsg != "Hello World!" { 
  t.Errorf("Message didn't match: %s\n", returnedMsg) 
} 

```

如果我们没有传递`LegacyPrinter`接口的实例，适配器必须忽略其适配性质，简单地打印并返回原始消息。是时候运行我们的测试了；考虑以下内容：

```go
$ go test -v .
=== RUN   TestAdapter
--- FAIL: TestAdapter (0.00s)
 adapter_test.go:11: Message didn't match: 
 adapter_test.go:17: Message didn't match: 
FAIL
exit status 1
FAIL

```

## 实施

为了使我们的单个测试通过，我们必须重用存储在`PrinterAdapter`结构中的旧`MyLegacyPrinter`：

```go
type PrinterAdapter struct{ 
  OldPrinter LegacyPrinter 
  Msg        string 
} 

func(p *PrinterAdapter) PrintStored() (newMsg string) { 
  if p.OldPrinter != nil { 
    newMsg = fmt.Sprintf("Adapter: %s", p.Msg) 
    newMsg = p.OldPrinter.Print(newMsg) 
  } 
  else { 
    newMsg = p.Msg 
  } 
return 
} 

```

在`PrintStored`方法中，我们检查是否实际上有一个`LegacyPrinter`的实例。在这种情况下，我们将存储的消息和`Adapter`前缀组合成一个新的字符串，以便将其存储在返回变量（称为`newMsg`）中。然后我们使用指向`MyLegacyPrinter`结构的指针来使用`LegacyPrinter`接口打印组合的消息。

如果在`OldPrinter`字段中没有存储`LegacyPrinter`实例，我们只需将存储的消息分配给返回变量`newMsg`并返回该方法。这应该足以通过我们的测试：

```go
$ go test -v .
=== RUN   TestAdapter
Legacy Printer: Adapter: Hello World!
--- PASS: TestAdapter (0.00s)
PASS
ok

```

完美！现在我们可以通过使用这个`Adapter`来继续使用旧的`LegacyPrinter`接口，同时我们可以为将来的实现使用`ModernPrinter`接口。只要记住，适配器模式理想上只提供使用旧的`LegacyPrinter`的方法，而不提供其他任何东西。这样，它的范围将更加封装和在将来更易于维护。

## Go 源代码中适配器模式的示例

您可以在 Go 语言源代码的许多地方找到适配器实现。著名的`http.Handler`接口有一个非常有趣的适配器实现。在 Go 中，一个非常简单的`Hello World`服务器通常是这样做的：

```go
package main 

import ( 
    "fmt" 
    "log" 
    "net/http" 
) 
type MyServer struct{ 
  Msg string 
} 
func (m *MyServer) ServeHTTP(w http.ResponseWriter,r *http.Request){ 
  fmt.Fprintf(w, "Hello, World") 
} 

func main() { 
  server := &MyServer{ 
  Msg:"Hello, World", 
} 

http.Handle("/", server)  
log.Fatal(http.ListenAndServe(":8080", nil)) 
} 

```

HTTP 包有一个名为`Handle`的函数（类似于 Java 中的`static`方法），它接受两个参数--一个表示路由的字符串和一个`Handler`接口。`Handler`接口如下：

```go
type Handler interface { 
  ServeHTTP(ResponseWriter, *Request) 
} 

```

我们需要实现一个`ServeHTTP`方法，HTTP 连接的服务器端将使用它来执行其上下文。但是还有一个`HandlerFunc`函数，允许您定义一些端点行为：

```go
func main() { 
  http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) { 
    fmt.Fprintf(w, "Hello, World") 
  }) 

  log.Fatal(http.ListenAndServe(":8080", nil)) 
} 

```

`HandleFunc`函数实际上是使用函数直接作为`ServeHTTP`实现的适配器的一部分。再慢慢读一遍最后一句--你能猜出它是如何实现的吗？

```go
type HandlerFunc func(ResponseWriter, *Request) 

func (f HandlerFunc) ServeHTTP(w ResponseWriter, r *Request) { 
  f(w, r) 
} 

```

我们可以定义一个与定义结构相同的函数类型。我们使这个函数类型实现`ServeHTTP`方法。最后，从`ServeHTTP`函数中，我们调用接收器本身`f(w, r)`。

你必须考虑 Go 的隐式接口实现。当我们定义一个像`func(ResponseWriter, *Request)`这样的函数时，它会被隐式地识别为`HandlerFunc`。而且因为`HandleFunc`函数实现了`Handler`接口，我们的函数也隐式地实现了`Handler`接口。这听起来很熟悉吗？如果*A = B*，*B = C*，那么*A = C*。隐式实现为 Go 提供了很多灵活性和功能，但你也必须小心，因为你不知道一个方法或函数是否实现了可能引起不良行为的某个接口。

我们可以在 Go 的源代码中找到更多的示例。`io`包使用管道的示例非常有力。在 Linux 中，管道是一种流机制，它将输入的内容输出为输出的其他内容。`io`包有两个接口，它们在 Go 的源代码中随处可见--`io.Reader`和`io.Writer`接口：

```go
type Reader interface { 
  Read(p []byte) (n int, err error) 
} 

type Writer interface { 
  Write(p []byte) (n int, err error) 
} 

```

我们到处都使用`io.Reader`，例如，当您使用`os.OpenFile`打开文件时，它返回一个文件，实际上实现了`io.Reader`接口。这有什么用呢？想象一下，您编写了一个`Counter`结构，从您提供的数字开始计数到零：

```go
type Counter struct {} 
func (f *Counter) Count(n uint64) uint64 { 
  if n == 0 { 
    println(strconv.Itoa(0)) 
    return 0 
  } 

  cur := n 
  println(strconv.FormatUint(cur, 10)) 
  return f.Count(n - 1) 
} 

```

如果您向这个小片段提供数字 3，它将打印以下内容：

```go
3
2
1

```

嗯，不是很令人印象深刻！如果我想要写入文件而不是打印呢？我们也可以实现这种方法。如果我想要打印到文件和控制台呢？嗯，我们也可以实现这种方法。我们必须通过使用`io.Writer`接口将其模块化一些：

```go
type Counter struct { 
  Writer io.Writer 
} 
func (f *Counter) Count(n uint64) uint64 { 
  if n == 0 { 
    f.Writer.Write([]byte(strconv.Itoa(0) + "\n")) 
    return 0 
  } 

  cur := n 
  f.Writer.Write([]byte(strconv.FormatUint(cur, 10) + "\n")) 
  return f.Count(n - 1) 
}

```

现在我们在`Writer`字段中提供了一个`io.Writer`。这样，我们可以像这样创建计数器：`c := Counter{os.Stdout}`，我们将得到一个控制台`Writer`。但等一下，我们还没有解决我们想要将计数带到许多`Writer`控制台的问题。但是我们可以编写一个新的`Adapter`，其中包含一个`io.Writer`，并使用`Pipe()`连接读取器和写入器，我们可以在相反的极端进行读取。这样，您可以解决这两个不兼容的接口`Reader`和`Writer`可以一起使用的问题。

实际上，我们不需要编写适配器--Go 的`io`库在`io.Pipe()`中为我们提供了一个适配器。管道将允许我们将`Reader`转换为`Writer`接口。`io.Pipe()`方法将为我们提供一个`Writer`（管道的入口）和一个`Reader`（出口）供我们使用。因此，让我们创建一个管道，并将提供的写入器分配给前面示例的`Counter`：

```go
pipeReader, pipeWriter := io.Pipe() 
defer pw.Close() 
defer pr.Close() 

counter := Counter{ 
  Writer: pipeWriter, 
} 

```

现在我们有了一个`Reader`接口，之前我们有了一个`Writer`。我们在哪里可以使用`Reader`？`io.TeeReader`函数帮助我们将数据流从`Reader`接口复制到`Writer`接口，并返回一个新的`Reader`，您仍然可以使用它将数据流再次传输到第二个写入器。因此，我们将从相同的读取器流式传输数据到两个写入器--`file`和`Stdout`。

```go
tee := io.TeeReader(pipeReader, file) 

```

现在我们知道我们正在写入一个文件，我们已经传递给`TeeReader`函数。我们仍然需要打印到控制台。`io.Copy`适配器可以像`TeeReader`一样使用--它接受一个读取器并将其内容写入写入器：

```go
go func(){ 
  io.Copy(os.Stdout, tee) 
}() 

```

我们必须在不同的 Go 例程中启动`Copy`函数，以便并发执行写入操作，并且一个读/写不会阻塞另一个读/写。让我们修改`counter`变量，使其再次计数到 5：

```go
counter.Count(5) 

```

通过对代码进行这种修改，我们得到了以下输出：

```go
$ go run counter.go
5
4
3
2
1
0

```

好的，计数已经打印在控制台上。文件呢？

```go
$ cat /tmp/pipe
5
4
3
2
1
0

```

太棒了！通过使用 Go 原生库中提供的`io.Pipe()`适配器，我们已经将计数器与其输出解耦，并将`Writer`接口适配为`Reader`接口。

## Go 源代码告诉我们有关适配器模式的信息

通过适配器设计模式，您已经学会了一种快速实现应用程序中开/闭原则的方法。与其修改旧的源代码（在某些情况下可能不可能），不如创建一种使用新签名的旧功能的方法。

# 桥梁设计模式

**桥梁**模式是从原始*四人帮*书中得到的定义略微神秘的设计。它将抽象与其实现解耦，以便两者可以独立变化。这种神秘的解释只是意味着您甚至可以解耦最基本的功能形式：将对象与其功能解耦。

## 描述

桥梁模式试图像通常的设计模式一样解耦事物。它将抽象（对象）与其实现（对象执行的操作）解耦。这样，我们可以随心所欲地更改对象的操作。它还允许我们更改抽象对象，同时重用相同的实现。

## 目标

桥梁模式的目标是为经常更改的结构带来灵活性。通过了解方法的输入和输出，它允许我们在不太了解代码的情况下进行更改，并为双方留下更容易修改的自由。

## 每个打印机和每种打印方式都有两种。

对于我们的示例，我们将转到控制台打印机抽象以保持简单。我们将有两个实现。第一个将写入控制台。在上一节中了解了`io.Writer`接口后，我们将使第二个写入`io.Writer`接口，以提供更多灵活性。我们还将有两个抽象对象使用这些实现——一个`Normal`对象，它将以直接的方式使用每个实现，以及一个`Packt`实现，它将在打印消息中附加句子`Message from Packt:`。

在本节的结尾，我们将有两个抽象对象，它们有两种不同的功能实现。因此，实际上，我们将有 2²种可能的对象功能组合。

## 要求和验收标准

正如我们之前提到的，我们将有两个对象（`Packt`和`Normal`打印机）和两个实现（`PrinterImpl1`和`PrinterImpl2`），我们将使用桥接设计模式将它们连接起来。更多或更少，我们将有以下要求和验收标准：

+   一个接受要打印的消息的`PrinterAPI`

+   一个简单地将消息打印到控制台的 API 实现

+   一个将消息打印到`io.Writer`接口的 API 实现

+   一个`Printer`抽象，具有实现打印类型的`Print`方法

+   一个`normal`打印机对象，它将实现`Printer`和`PrinterAPI`接口

+   `normal`打印机将直接将消息转发到实现

+   一个`Packt`打印机，它将实现`Printer`抽象和`PrinterAPI`接口

+   `Packt`打印机将在所有打印中附加消息`Message from Packt:`

## 单元测试桥接模式

让我们从*验收标准 1*开始，即`PrinterAPI`接口。该接口的实现者必须提供一个`PrintMessage(string)`方法，该方法将打印作为参数传递的消息：

```go
type PrinterAPI interface { 
  PrintMessage(string) error 
} 

```

我们将通过前一个 API 的实现转到*验收标准 2*：

```go
type PrinterImpl1 struct{} 

func (p *PrinterImpl1) PrintMessage(msg string) error { 
  return errors.New("Not implemented yet") 
} 

```

我们的`PrinterImpl1`是一种通过提供`PrintMessage`方法的实现来实现`PrinterAPI`接口的类型。`PrintMessage`方法尚未实现，并返回错误。这足以编写我们的第一个单元测试来覆盖`PrinterImpl1`：

```go
func TestPrintAPI1(t *testing.T){ 
  api1 := PrinterImpl1{} 

  err := api1.PrintMessage("Hello") 
  if err != nil { 
    t.Errorf("Error trying to use the API1 implementation: Message: %s\n", err.Error()) 
  } 
} 

```

在我们的测试中，我们创建了一个`PrinterImpl1`类型的实例来覆盖`PrintAPI1`。然后我们使用它的`PrintMessage`方法将消息`Hello`打印到控制台。由于我们还没有实现，它必须返回错误字符串`Not implemented yet`：

```go
$ go test -v -run=TestPrintAPI1 . 
=== RUN   TestPrintAPI1 
--- FAIL: TestPrintAPI1 (0.00s) 
        bridge_test.go:14: Error trying to use the API1 implementation: Message: Not implemented yet 
FAIL 
exit status 1 
FAIL    _/C_/Users/mario/Desktop/go-design-patterns/structural/bridge/traditional

```

好的。现在我们必须编写第二个 API 测试，它将使用`io.Writer`接口：

```go
type PrinterImpl2 struct{ 
  Writer io.Writer 
} 

func (d *PrinterImpl2) PrintMessage(msg string) error { 
  return errors.New("Not implemented yet") 
} 

```

正如你所看到的，我们的`PrinterImpl2`结构存储了一个`io.Writer`实现。此外，我们的`PrintMessage`方法遵循了`PrinterAPI`接口。

现在我们熟悉了`io.Writer`接口，我们将创建一个测试对象来实现这个接口，并将写入它的任何内容存储在一个本地字段中。这将帮助我们检查通过写入器发送的内容：

```go
type TestWriter struct { 
  Msg string 
} 

func (t *TestWriter) Write(p []byte) (n int, err error) { 
  n = len(p) 
  if n > 0 { 
    t.Msg = string(p) 
    return n, nil 
  } 
  err = errors.New("Content received on Writer was empty") 
  return 
} 

```

在我们的测试对象中，我们在将其写入本地字段之前检查内容是否为空。如果为空，我们返回错误，如果不为空，我们将`p`的内容写入`Msg`字段。我们将在以下测试中使用这个小结构来测试第二个 API：

```go
func TestPrintAPI2(t *testing.T){ 
  api2 := PrinterImpl2{} 

  err := api2.PrintMessage("Hello") 
  if err != nil { 
    expectedErrorMessage := "You need to pass an io.Writer to PrinterImpl2" 
    if !strings.Contains(err.Error(), expectedErrorMessage) { 
      t.Errorf("Error message was not correct.\n 
      Actual: %s\nExpected: %s\n", err.Error(), expectedErrorMessage) 
    } 
  } 

```

让我们在这里停顿一下。我们在前面的代码的第一行创建了一个名为`api2`的`PrinterImpl2`实例。我们故意没有传递任何`io.Writer`实例，所以我们首先检查我们是否真的收到了错误。然后我们尝试使用它的`PrintMessage`方法，但我们必须得到一个错误，因为它在`Writer`字段中没有存储任何`io.Writer`实例。错误必须是`You need to pass an io.Writer to PrinterImpl2`，我们隐式检查错误的内容。让我们继续测试：

```go
  testWriter := TestWriter{} 
  api2 = PrinterImpl2{ 
    Writer: &testWriter, 
  } 

  expectedMessage := "Hello" 
  err = api2.PrintMessage(expectedMessage) 
  if err != nil { 
    t.Errorf("Error trying to use the API2 implementation: %s\n", err.Error()) 
  } 

  if testWriter.Msg !=  expectedMessage { 
    t.Fatalf("API2 did not write correctly on the io.Writer. \n  Actual: %s\nExpected: %s\n", testWriter.Msg, expectedMessage) 
  } 
} 

```

对于这个单元测试的第二部分，我们使用`TestWriter`对象的一个实例作为`io.Writer`接口，`testWriter`。我们将消息`Hello`传递给`api2`，并检查是否收到任何错误。然后，我们检查`testWriter.Msg`字段的内容--请记住，我们已经编写了一个`io.Writer`接口，它会将传递给其`Write`方法的任何字节存储在`Msg`字段中。如果一切正确，消息应该包含单词`Hello`。

这些就是我们对`PrinterImpl2`的测试。由于我们还没有任何实现，所以在运行这个测试时应该会得到一些错误。

```go
$ go test -v -run=TestPrintAPI2 .
=== RUN   TestPrintAPI2
--- FAIL: TestPrintAPI2 (0.00s)
bridge_test.go:39: Error message was not correct.
Actual: Not implemented yet
Expected: You need to pass an io.Writer to PrinterImpl2
bridge_test.go:52: Error trying to use the API2 implementation: Not 
implemented yet
bridge_test.go:57: API2 did not write correctly on the io.Writer.
Actual:
Expected: Hello
FAIL
exit status 1
FAIL

```

至少有一个测试通过了--检查在使用`PrintMessage`时是否返回了错误消息（任何错误）。其他一切都失败了，这在这个阶段是预期的。

现在我们需要一个打印机抽象，用于可以使用`PrinterAPI`实现者的对象。我们将定义这个为`PrinterAbstraction`接口，其中包含一个`Print`方法。这涵盖了*验收标准 4*：

```go
type PrinterAbstraction interface { 
  Print() error 
} 

```

对于*验收标准 5*，我们需要一个普通打印机。`Printer`抽象将需要一个字段来存储`PrinterAPI`。因此，我们的`NormalPrinter`可能如下所示：

```go
type NormalPrinter struct { 
  Msg     string 
  Printer PrinterAPI 
} 

func (c *NormalPrinter) Print() error { 
  return errors.New("Not implemented yet") 
} 

```

这足以编写`Print（）`方法的单元测试：

```go
func TestNormalPrinter_Print(t *testing.T) { 
  expectedMessage := "Hello io.Writer" 

  normal := NormalPrinter{ 
    Msg:expectedMessage, 
    Printer: &PrinterImpl1{}, 
  } 

  err := normal.Print() 
  if err != nil { 
    t.Errorf(err.Error()) 
  } 
} 

```

测试的第一部分检查了在使用`PrinterImpl1 PrinterAPI`接口时，`Print（）`方法尚未实现。我们将在这个测试中使用的消息是`Hello io.Writer`。使用`PrinterImpl1`时，我们没有简单的方法来检查消息的内容，因为我们直接打印到控制台。在这种情况下，检查是视觉的，所以我们可以检查*验收标准 6*：

```go
  testWriter := TestWriter{} 
  normal = NormalPrinter{ 
    Msg: expectedMessage, 
    Printer: &PrinterImpl2{ 
      Writer:&testWriter, 
    }, 
  } 

  err = normal.Print() 
  if err != nil { 
    t.Error(err.Error()) 
  } 

  if testWriter.Msg != expectedMessage { 
    t.Errorf("The expected message on the io.Writer doesn't match actual.\n  Actual: %s\nExpected: %s\n", testWriter.Msg, expectedMessage) 
  } 
} 

```

`NormalPrinter`测试的第二部分使用`PrinterImpl2`，这需要一个`io.Writer`接口的实现者。我们在这里重用我们的`TestWriter`结构来检查消息的内容。简而言之，我们希望一个接受`string`类型的`Msg`和`PrinterAPI`类型的`Printer`的`NormalPrinter`结构。在这一点上，如果我使用`Print`方法，我不应该收到任何错误，并且`TestWriter`上的`Msg`字段必须包含我们在初始化`NormalPrinter`时传递给它的消息。

让我们运行测试：

```go
$ go test -v -run=TestNormalPrinter_Print .
=== RUN   TestNormalPrinter_Print
--- FAIL: TestNormalPrinter_Print (0.00s)
 bridge_test.go:72: Not implemented yet
 bridge_test.go:85: Not implemented yet
 bridge_test.go:89: The expected message on the io.Writer doesn't match actual.
 Actual:
 Expected: Hello io.Writer
FAIL
exit status 1
FAIL

```

有一个技巧可以快速检查单元测试的有效性--我们调用`t.Error`或`t.Errorf`的次数必须与控制台上的错误消息数量以及它们产生的行数相匹配。在前面的测试结果中，有三个错误分别在*第 72 行*、*第 85 行*和*第 89 行*，这恰好与我们编写的检查相匹配。

我们的`PacktPrinter`结构在这一点上将与`NormalPrinter`的定义非常相似：

```go
type PacktPrinter struct { 
  Msg     string 
  Printer PrinterAPI 
} 

func (c *PacktPrinter) Print() error { 
  return errors.New("Not implemented yet") 
} 

```

这涵盖了*验收标准 7*。我们几乎可以复制并粘贴以前的测试内容，只需做一些更改：

```go
func TestPacktPrinter_Print(t *testing.T) { 
  passedMessage := "Hello io.Writer" 
  expectedMessage := "Message from Packt: Hello io.Writer" 

  packt := PacktPrinter{ 
    Msg:passedMessage, 
    Printer: &PrinterImpl1{}, 
  } 

  err := packt.Print() 
  if err != nil { 
    t.Errorf(err.Error()) 
  } 

  testWriter := TestWriter{} 
  packt = PacktPrinter{ 
    Msg: passedMessage, 
    Printer:&PrinterImpl2{ 
      Writer:&testWriter, 
    }, 
  } 

  err = packt.Print() 
  if err != nil { 
    t.Error(err.Error()) 
  } 

  if testWriter.Msg != expectedMessage { 
    t.Errorf("The expected message on the io.Writer doesn't match actual.\n  Actual: %s\nExpected: %s\n", testWriter.Msg,expectedMessage) 
  } 
} 

```

我们在这里做了什么改变？现在我们有了`passedMessage`，它代表了我们传递给`PackPrinter`的消息。我们还有一个预期的消息，其中包含了来自`Packt`的带前缀的消息。如果您还记得*验收标准 8*，这个抽象必须给传递给它的任何消息加上`Message from Packt：`的前缀，并且同时，它必须能够使用`PrinterAPI`接口的任何实现。

第二个改变是，我们实际上创建了`PacktPrinter`结构，而不是`NormalPrinter`结构；其他一切都是一样的：

```go
$ go test -v -run=TestPacktPrinter_Print .
=== RUN   TestPacktPrinter_Print
--- FAIL: TestPacktPrinter_Print (0.00s)
 bridge_test.go:104: Not implemented yet
 bridge_test.go:117: Not implemented yet
 bridge_test.go:121: The expected message on the io.Writer d
oesn't match actual.
 Actual:
 Expected: Message from Packt: Hello io.Writer
FAIL
exit status 1
FAIL

```

三个检查，三个错误。所有测试都已覆盖，我们终于可以继续实施了。

## 实施

我们将按照创建测试的顺序开始实现，首先是`PrinterImpl1`的定义：

```go
type PrinterImpl1 struct{} 
func (d *PrinterImpl1) PrintMessage(msg string) error { 
  fmt.Printf("%s\n", msg) 
  return nil 
} 

```

我们的第一个 API 接收消息`msg`并将其打印到控制台。在空字符串的情况下，将不会打印任何内容。这足以通过第一个测试：

```go
$ go test -v -run=TestPrintAPI1 .
=== RUN   TestPrintAPI1
Hello
--- PASS: TestPrintAPI1 (0.00s)
PASS
ok

```

您可以在测试输出的第二行中看到`Hello`消息，就在`RUN`消息之后。

`PrinterImpl2`结构也不是很复杂。不同之处在于，我们将在`io.Writer`接口上写入，而不是打印到控制台，这必须存储在结构中。

```go
type PrinterImpl2 struct { 
  Writer io.Writer 
} 

func (d *PrinterImpl2) PrintMessage(msg string) error { 
  if d.Writer == nil { 
    return errors.New("You need to pass an io.Writer to PrinterImpl2") 
  } 

  fmt.Fprintf(d.Writer, "%s", msg) 
  return nil 
} 

```

根据我们的测试，我们首先检查了`Writer`字段的内容，并返回了预期的错误消息`**You need to pass an io.Writer to PrinterImpl2**`，如果没有存储任何内容。这是我们稍后将在测试中检查的消息。然后，`fmt.Fprintf`方法将`io.Writer`接口作为第一个字段，并将格式化的消息作为其余部分，因此我们只需将`msg`参数的内容转发给提供的`io.Writer`：

```go
$ go test -v -run=TestPrintAPI2 .
=== RUN   TestPrintAPI2
--- PASS: TestPrintAPI2 (0.00s)
PASS
ok

```

现在我们将继续使用普通打印机。这个打印机必须简单地将消息转发给存储在`PrinterAPI`接口中的`Printer`，而不做任何修改。在我们的测试中，我们使用了两种`PrinterAPI`的实现--一种打印到控制台，一种写入到`io.Writer`接口：

```go
type NormalPrinter struct { 
  Msg     string 
  Printer PrinterAPI 
} 

func (c *NormalPrinter) Print() error { 
  c.Printer.PrintMessage(c.Msg) 
  return nil 
}
```

我们返回 nil，因为没有发生错误。这应该足以通过单元测试：

```go
$ go test -v -run=TestNormalPrinter_Print . 
=== RUN   TestNormalPrinter_Print 
Hello io.Writer 
--- PASS: TestNormalPrinter_Print (0.00s) 
PASS 
ok

```

在前面的输出中，您可以看到`PrinterImpl1`结构写入`stdout`的`Hello io.Writer`消息。我们可以认为这个检查已经通过了：

最后，`PackPrinter`方法类似于`NormalPrinter`，但只是在每条消息前加上文本`Message from Packt:`：

```go
type PacktPrinter struct { 
  Msg     string 
  Printer PrinterAPI 
} 

func (c *PacktPrinter) Print() error { 
  c.Printer.PrintMessage(fmt.Sprintf("Message from Packt: %s", c.Msg)) 
  return nil 
} 

```

就像`NormalPrinter`方法一样，我们接受了`Msg`字符串和`PrinterAPI`实现，存储在`Printer`字段中。然后，我们使用`fmt.Sprintf`方法来组合一个新的字符串，其中包含文本`Message from Packt:`和提供的消息。我们取得组合的文本，并将其传递给存储在`PacktPrinter`结构的`Printer`字段中的`PrinterAPI`的`PrintMessage`方法：

```go
$ go test -v -run=TestPacktPrinter_Print .
=== RUN   TestPacktPrinter_Print
Message from Packt: Hello io.Writer
--- PASS: TestPacktPrinter_Print (0.00s)
PASS
ok

```

同样，您可以看到使用`PrinterImpl1`写入`stdout`的结果，文本为`Message from Packt: Hello io.Writer`。这最后的测试应该覆盖桥接模式中的所有代码。正如您之前所见，您可以使用`-cover`标志来检查覆盖率：

```go
$ go test -cover .
ok      
2.622s  coverage: 100.0% of statements

```

哇！100%的覆盖率-看起来不错。然而，这并不意味着代码是完美的。我们还没有检查消息的内容是否为空，也许这是应该避免的，但这不是我们的要求的一部分，这也是一个重要的观点。仅仅因为某个功能不在需求或验收标准中，并不意味着它不应该被覆盖。

## 使用桥接模式重用一切

通过桥接模式，我们学会了如何将对象及其实现与`PrintMessage`方法解耦。这样，我们可以重用其抽象以及其实现。我们可以随意交换打印机抽象以及打印机 API，而不影响用户代码。

我们还尽量保持事情尽可能简单，但我相信您已经意识到，所有`PrinterAPI`接口的实现都可以使用工厂来创建。这将是非常自然的，您可能会发现许多实现都遵循了这种方法。然而，我们不应该陷入过度设计，而应该分析每个问题，以精确地设计其需求，并找到创建可重用、可维护和*可读*源代码的最佳方式。可读的代码通常被遗忘，但如果没有人能够理解和维护它，那么强大而不耦合的源代码就是无用的。这就像十世纪的书籍一样--它可能是一部宝贵的故事，但如果我们难以理解它的语法，那就会非常令人沮丧。

# 总结

在本章中，我们已经看到了组合的力量，以及 Go 语言如何利用它的本质。我们已经看到适配器模式可以帮助我们通过在两个不兼容的接口之间使用“适配器”对象来使它们一起工作。同时，我们在 Go 语言的源代码中看到了一些真实的例子，语言的创建者使用了这种设计模式来改进标准库中某个特定部分的可能性。最后，我们已经看到了桥接模式及其可能性，允许我们在对象和它们的实现之间创建可完全重用的交换结构。

此外，在整个章节中，我们一直在使用组合设计模式，不仅仅是在解释它时。我们之前提到过它，但设计模式经常彼此使用。我们使用纯粹的组合而不是嵌入来增加可读性，但是，正如你已经学到的，根据需要可以互换使用两者。在接下来的章节中，我们将继续使用组合模式，因为它是构建 Go 编程语言中关系的基础。


# 第四章：结构模式 - 代理，外观，装饰器和享元设计模式

通过本章，我们将完成结构模式。我们将最复杂的一些模式留到最后，以便您更加熟悉设计模式的机制和 Go 语言的特性。

在本章中，我们将致力于编写一个用于访问数据库的缓存，一个用于收集天气数据的库，一个带有运行时中间件的服务器，并讨论通过在类型值之间保存可共享状态来节省内存的方法。

# 代理设计模式

我们将以代理模式开始最终章节。这是一个简单的模式，可以提供有趣的功能和可能性，而且只需很少的努力。

## 描述

代理模式通常包装一个对象，以隐藏其某些特征。这些特征可能是它是一个远程对象（远程代理），一个非常重的对象，例如非常大的图像或千兆字节数据库的转储（虚拟代理），或者是一个受限制的访问对象（保护代理）。

## 目标

代理模式的可能性很多，但总的来说，它们都试图提供以下相同的功能：

+   隐藏对象在代理后面，以便可以隐藏，限制等功能

+   提供一个易于使用和易于更改的新抽象层

## 示例

对于我们的示例，我们将创建一个远程代理，它将是在访问数据库之前对象的缓存。假设我们有一个包含许多用户的数据库，但是我们不会每次想要获取有关用户的信息时都访问数据库，而是在代理模式下拥有一个用户的**先进先出**（**FIFO**）堆栈（FIFO 是一种说法，当缓存需要清空时，它将删除最先进入的对象）。

## 验收标准

我们将使用代理模式包装一个由切片表示的想象数据库。然后，该模式将必须遵循以下验收标准：

1.  所有对用户数据库的访问都将通过代理类型完成。

1.  代理中将保留`n`个最近用户的堆栈。

1.  如果用户已经存在于堆栈中，则不会查询数据库，并将返回存储的用户

1.  如果查询的用户不在堆栈中，则将查询数据库，如果堆栈已满，则删除堆栈中最旧的用户，存储新用户，并返回它。

## 单元测试

自 Go 的 1.7 版本以来，我们可以通过使用闭包在测试中嵌入测试，以便以更易读的方式对它们进行分组，并减少`Test_`函数的数量。请参阅第一章，*准备...开始...Go！*，了解如何安装新版本的 Go，如果您当前的版本早于 1.7 版本。

此模式的类型将是代理用户和用户列表结构以及`UserFinder`接口，数据库和代理将实现该接口。这很关键，因为代理必须实现与其尝试包装的类型的特性相同的接口：

```go
type UserFinder interface { 
  FindUser(id int32) (User, error) 
} 

```

`UserFinder`是数据库和代理实现的接口。`User`是一种具有名为`ID`的成员的类型，它是`int32`类型：

```go
type User struct { 
  ID int32 
} 

```

最后，`UserList`是用户切片的一种类型。考虑以下语法：

```go
type UserList []User 

```

如果您想知道为什么我们不直接使用用户切片，答案是，通过这种方式声明用户序列，我们可以实现`UserFinder`接口，但是使用切片，我们无法。

最后，代理类型称为`UserListProxy`，将由`UserList`切片组成，这将是我们的数据库表示。`StackCache`成员也将是`UserList`类型，以简化`StackCapacity`，以便给我们的堆栈指定大小。

为了本教程的目的，我们将稍微作弊，声明一个名为`DidDidLastSearchUsedCache`的字段上的布尔状态，该状态将保存上次执行的搜索是否使用了缓存，或者是否访问了数据库。

```go
type UserListProxy struct { 
  SomeDatabase UserList 
  StackCache UserList 
  StackCapacity int 
  DidDidLastSearchUsedCache bool 
} 

func (u *UserListProxy) FindUser(id int32) (User, error) { 
  return User{}, errors.New("Not implemented yet") 
} 

```

`UserListProxy`类型将缓存最多`StackCapacity`个用户，并在达到此限制时旋转缓存。`StackCache`成员将从`SomeDatabase`类型的对象中填充。

第一个测试称为`TestUserListProxy`，并列在下面：

```go
import ( 
   "math/rand" 
   "testing" 
) 

func Test_UserListProxy(t *testing.T) { 
  someDatabase := UserList{} 

  rand.Seed(2342342) 
  for i := 0; i < 1000000; i++ { 
    n := rand.Int31() 
    someDatabase = append(someDatabase, User{ID: n}) 
  } 

```

前面的测试创建了一个包含随机名称的 100 万用户的用户列表。为此，我们通过调用`Seed()`函数使用一些常量种子来为随机数生成器提供输入，以便我们的随机化结果也是常量；用户 ID 是从中生成的。它可能有一些重复，但它满足了我们的目的。

接下来，我们需要一个代理，它引用了刚刚创建的`someDatabase`：

```go
proxy := UserListProxy{ 
  SomeDatabase:  &someDatabase, 
  StackCapacity:  2, 
  StackCache: UserList{}, 
} 

```

此时，我们有一个由 1 百万用户组成的模拟数据库和一个大小为 2 的 FIFO 堆栈实现的缓存的`proxy`对象。现在我们将从`someDatabase`中获取三个随机 ID 来使用我们的堆栈：

```go
knownIDs := [3]int32 {someDatabase[3].ID, someDatabase[4].ID,someDatabase[5].ID} 

```

我们从切片中取出了第四、第五和第六个 ID（请记住，数组和切片从 0 开始，因此索引 3 实际上是切片中的第四个位置）。

这将是我们在启动嵌入式测试之前的起点。要创建嵌入式测试，我们必须调用`testing.T`指针的`Run`方法，其中包括描述和具有`func(t *testing.T)`签名的闭包：

```go
t.Run("FindUser - Empty cache", func(t *testing.T) { 
  user, err := proxy.FindUser(knownIDs[0]) 
  if err != nil { 
    t.Fatal(err) 
  } 

```

例如，在前面的代码片段中，我们给出了描述`FindUser - Empty cache`。然后我们定义我们的闭包。首先它尝试查找具有已知 ID 的用户，并检查错误。由于描述暗示，此时缓存为空，用户将不得不从`someDatabase`数组中检索：

```go
  if user.ID != knownIDs[0] { 
    t.Error("Returned user name doesn't match with expected") 
  } 

  if len(proxy.StackCache) != 1 { 
    t.Error("After one successful search in an empty cache, the size of it must be one") 
  } 

  if proxy.DidLastSearchUsedCache { 
    t.Error("No user can be returned from an empty cache") 
  } 
} 

```

最后，我们检查返回的用户是否具有与`knownIDs`切片的索引 0 处的预期用户相同的 ID，并且代理缓存现在的大小为 1。成员`DidLastSearchUsedCache`的状态代理不能是`true`，否则我们将无法通过测试。请记住，此成员告诉我们上次搜索是从表示数据库的切片中检索的，还是从缓存中检索的。

代理模式的第二个嵌入式测试是要求与之前相同的用户，现在必须从缓存中返回。这与以前的测试非常相似，但现在我们必须检查用户是否从缓存中返回：

```go
t.Run("FindUser - One user, ask for the same user", func(t *testing.T) { 
  user, err := proxy.FindUser(knownIDs[0]) 
  if err != nil { 
    t.Fatal(err) 
  } 

  if user.ID != knownIDs[0] { 
    t.Error("Returned user name doesn't match with expected") 
  } 

  if len(proxy.StackCache) != 1 { 
    t.Error("Cache must not grow if we asked for an object that is stored on it") 
  } 

  if !proxy.DidLastSearchUsedCache { 
    t.Error("The user should have been returned from the cache") 
  } 
}) 

```

因此，我们再次要求第一个已知的 ID。代理缓存在此搜索后必须保持大小为 1，并且这次`DidLastSearchUsedCache`成员必须为 true，否则测试将失败。

最后的测试将使`proxy`类型的`StackCache`数组溢出。我们将搜索两个新用户，我们的`proxy`类型将不得不从数据库中检索这些用户。我们的堆栈大小为 2，因此它将不得不删除第一个用户以为第二个和第三个用户分配空间：

```go
user1, err := proxy.FindUser(knownIDs[0]) 
if err != nil { 
  t.Fatal(err) 
} 

user2, _ := proxy.FindUser(knownIDs[1]) 
if proxy.DidLastSearchUsedCache { 
  t.Error("The user wasn't stored on the proxy cache yet") 
} 

user3, _ := proxy.FindUser(knownIDs[2]) 
if proxy.DidLastSearchUsedCache { 
  t.Error("The user wasn't stored on the proxy cache yet") 
} 

```

我们已经检索到了前三个用户。我们不检查错误，因为这是以前测试的目的。重要的是要记住，没有必要过度测试您的代码。如果这里有任何错误，它将在以前的测试中出现。此外，我们已经检查了`user2`和`user3`查询是否未使用缓存；它们不应该被存储在那里。

现在我们将在代理中查找`user1`查询。它不应该存在，因为堆栈的大小为 2，而`user1`是第一个进入的，因此也是第一个出去的：

```go
for i := 0; i < len(proxy.StackCache); i++ { 
  if proxy.StackCache[i].ID == user1.ID { 
    t.Error("User that should be gone was found") 
  } 
} 

if len(proxy.StackCache) != 2 { 
  t.Error("After inserting 3 users the cache should not grow" + 
" more than to two") 
} 

```

无论我们要求一千个用户，我们的缓存都不能大于我们配置的大小。

最后，我们将再次遍历存储在缓存中的用户，并将它们与我们查询的最后两个用户进行比较。这样，我们将检查只有这些用户存储在缓存中。两者都必须在其中找到：

```go
  for _, v := range proxy.StackCache { 
    if v != user2 && v != user3 { 
      t.Error("A non expected user was found on the cache") 
    } 
  } 
} 

```

现在运行测试应该会出现一些错误，像往常一样。现在让我们运行它们：

```go
$ go test -v .
=== RUN   Test_UserListProxy
=== RUN   Test_UserListProxy/FindUser_-_Empty_cache
=== RUN   Test_UserListProxy/FindUser_-_One_user,_ask_for_the_same_user
=== RUN   Test_UserListProxy/FindUser_-_overflowing_the_stack
--- FAIL: Test_UserListProxy (0.06s)
 --- FAIL: Test_UserListProxy/FindUser_-_Empty_cache (0.00s)
 proxy_test.go:28: Not implemented yet
 --- FAIL: Test_UserListProxy/FindUser_-_One_user,_ask_for_the_same_user (0.00s)
 proxy_test.go:47: Not implemented yet
 --- FAIL: Test_UserListProxy/FindUser_-_overflowing_the_stack (0.00s)
 proxy_test.go:66: Not implemented yet
FAIL
exit status 1
FAIL

```

因此，让我们实现`FindUser`方法以充当我们的代理。

## 实施

在我们的代理中，`FindUser`方法将在缓存列表中搜索指定的 ID。如果找到它，它将返回 ID。如果没有找到，它将在数据库中搜索。最后，如果它不在数据库列表中，它将返回一个错误。

如果您记得，我们的代理模式由两种`UserList`类型组成（其中一种是指针），它们实际上是`User`类型的切片。我们还将在`User`类型中实现一个`FindUser`方法，该方法与`UserFinder`接口具有相同的签名：

```go
type UserList []User 

func (t *UserList) FindUser(id int32) (User, error) { 
  for i := 0; i < len(*t); i++ { 
    if (*t)[i].ID == id { 
      return (*t)[i], nil 
    } 
  } 
  return User{}, fmt.Errorf("User %s could not be found\n", id) 
} 

```

`UserList`切片中的`FindUser`方法将遍历列表，尝试找到与`id`参数相同 ID 的用户，或者如果找不到则返回错误。

您可能想知道为什么指针`t`在括号之间。这是为了在访问其索引之前取消引用底层数组。如果没有它，您将会遇到编译错误，因为编译器会在取消引用指针之前尝试搜索索引。

因此，代理`FindUser`方法的第一部分可以编写如下：

```go
func (u *UserListProxy) FindUser(id int32) (User, error) { 
  user, err := u.StackCache.FindUser(id) 
  if err == nil { 
    fmt.Println("Returning user from cache") 
    u.DidLastSearchUsedCache = true 
    return user, nil 
  } 

```

我们使用上述方法在`StackCache`成员中搜索用户。如果找到用户，错误将为 nil，因此我们检查这一点，以便在控制台打印一条消息，将`DidLastSearchUsedCache`的状态更改为`true`，以便测试可以检查用户是否从缓存中检索，并最终返回用户。

因此，如果错误不是 nil，则意味着它无法在堆栈中找到用户。因此，下一步是在数据库中搜索：

```go
  user, err = u.SomeDatabase.FindUser(id) 
  if err != nil { 
    return User{}, err 
  } 

```

在这种情况下，我们可以重用我们为`UserList`数据库编写的`FindUser`方法，因为在这个例子的目的上，两者具有相同的类型。同样，它在数据库中搜索由`UserList`切片表示的用户，但在这种情况下，如果找不到用户，则返回`UserList`中生成的错误。

当找到用户（`err`为 nil）时，我们必须将用户添加到堆栈中。为此，我们编写了一个专用的私有方法，该方法接收`UserListProxy`类型的指针：

```go
func (u *UserListProxy) addUserToStack(user User) { 
  if len(u.StackCache) >= u.StackCapacity { 
    u.StackCache = append(u.StackCache[1:], user) 
  } 
  else { 
    u.StackCache.addUser(user) 
  } 
} 

func (t *UserList) addUser(newUser User) { 
  *t = append(*t, newUser) 
} 

```

`addUserToStack`方法接受用户参数，并将其放置在堆栈中。如果堆栈已满，则在添加之前删除其中的第一个元素。我们还编写了一个`addUser`方法来帮助我们在`UserList`中。因此，现在在`FindUser`方法中，我们只需添加一行：

```go
u.addUserToStack(user) 

```

这将新用户添加到堆栈中，必要时删除最后一个。

最后，我们只需返回堆栈的新用户，并在`DidLastSearchUsedCache`变量上设置适当的值。我们还向控制台写入一条消息，以帮助测试过程：

```go
  fmt.Println("Returning user from database") 
  u.DidLastSearchUsedCache = false 
  return user, nil 
} 

```

有了这个，我们就有足够的内容来通过我们的测试：

```go
$ go test -v .
=== RUN   Test_UserListProxy
=== RUN   Test_UserListProxy/FindUser_-_Empty_cache
Returning user from database
=== RUN   Test_UserListProxy/FindUser_-_One_user,_ask_for_the_same_user
Returning user from cache
=== RUN   Test_UserListProxy/FindUser_-_overflowing_the_stack
Returning user from cache
Returning user from database
Returning user from database
--- PASS: Test_UserListProxy (0.09s) 
--- PASS: Test_UserListProxy/FindUser_-_Empty_cache (0.00s)
--- PASS: Test_UserListProxy/FindUser_-_One_user,_ask_for_the_same_user (0.00s)
--- PASS: Test_UserListProxy/FindUser_-_overflowing_the_stack (0.00s)
PASS
ok

```

您可以在前面的消息中看到，我们的代理已经完美地工作。它已经从数据库中返回了第一次搜索。然后，当我们再次搜索相同的用户时，它使用了缓存。最后，我们进行了一个新的测试，调用了三个不同的用户，通过查看控制台输出，我们可以观察到只有第一个用户是从缓存中返回的，其他两个是从数据库中获取的。

## 围绕操作进行代理

在需要进行一些中间操作的类型周围包装代理，比如为用户提供授权或提供对数据库的访问，就像我们的示例一样。

我们的示例是将应用程序需求与数据库需求分离的好方法。如果我们的应用程序对数据库的访问过多，解决方案并不在于数据库。请记住，代理使用与其包装的类型相同的接口，对于用户来说，两者之间不应该有任何区别。

# 装饰器设计模式

我们将继续本章，介绍代理模式的大哥，也许是最强大的设计模式之一。**装饰器**模式非常简单，但是在处理旧代码时提供了许多好处。

## 描述

装饰器设计模式允许您在不实际触及它的情况下为已经存在的类型添加更多的功能特性。这是如何可能的呢？嗯，它使用了一种类似于*玛特里奥什卡娃娃*的方法，您可以将一个小娃娃放在一个相同形状但更大的娃娃中，依此类推。

装饰器类型实现了它装饰的类型的相同接口，并在其成员中存储该类型的实例。这样，您可以通过简单地将旧的装饰器存储在新装饰器的字段中来堆叠尽可能多的装饰器（玩偶）。

## 目标

当您考虑扩展旧代码而不会破坏任何东西时，您应该首先考虑装饰器模式。这是一种处理这个特定问题的非常强大的方法。

装饰器非常强大的另一个领域可能并不那么明显，尽管当基于用户输入、偏好或类似输入创建具有许多功能的类型时，它会显现出来。就像瑞士军刀一样，您有一个基本类型（刀的框架），然后您展开其功能。

那么，我们什么时候会使用装饰器模式呢？对这个问题的回答：

+   当您需要向一些无法访问的代码添加功能，或者您不希望修改以避免对代码产生负面影响，并遵循开放/封闭原则（如旧代码）时。

+   当您希望动态创建或更改对象的功能，并且功能数量未知且可能快速增长时

## 示例

在我们的示例中，我们将准备一个`Pizza`类型，其中核心是披萨，配料是装饰类型。我们的披萨上会有一些配料，比如洋葱和肉。

## 验收标准

装饰器模式的验收标准是具有一个公共接口和一个核心类型，所有层都将在其上构建：

+   我们必须有所有装饰器都将实现的主要接口。这个接口将被称为`IngredientAdd`，它将具有`AddIngredient() string`方法。

+   我们必须有一个核心`PizzaDecorator`类型（装饰器），我们将向其添加配料。

+   我们必须有一个实现相同`IngredientAdd`接口的配料`onion`，它将向返回的披萨添加字符串`onion`。

+   我们必须有一个实现`IngredientAdd`接口的配料`meat`，它将向返回的披萨添加字符串`meat`。

+   在顶层对象上调用`AddIngredient`方法时，它必须返回一个带有文本`Pizza with the following ingredients: meat, onion`的完全装饰的`pizza`。

## 单元测试

要启动我们的单元测试，我们必须首先根据验收标准创建基本结构。首先，所有装饰类型必须实现的接口如下：

```go
type IngredientAdd interface { 
  AddIngredient() (string, error) 
} 

```

以下代码定义了`PizzaDecorator`类型，其中必须包含`IngredientAdd`，并且它也实现了`IngredientAdd`：

```go
type PizzaDecorator struct{ 
  Ingredient IngredientAdd 
} 

func (p *PizzaDecorator) AddIngredient() (string, error) { 
  return "", errors.New("Not implemented yet") 
} 

```

`Meat`类型的定义将与`PizzaDecorator`结构的定义非常相似：

```go
type Meat struct { 
  Ingredient IngredientAdd 
} 

func (m *Meat) AddIngredient() (string, error) { 
  return "", errors.New("Not implemented yet") 
} 

```

现在我们以类似的方式定义`Onion`结构体：

```go
type Onion struct { 
  Ingredient IngredientAdd 
} 

func (o *Onion) AddIngredient() (string, error) { 
  return "", errors.New("Not implemented yet") 
}  

```

这已足以实现第一个单元测试，并允许编译器在没有任何编译错误的情况下运行它们：

```go
func TestPizzaDecorator_AddIngredient(t *testing.T) { 
  pizza := &PizzaDecorator{} 
  pizzaResult, _ := pizza.AddIngredient() 
  expectedText := "Pizza with the following ingredients:" 
  if !strings.Contains(pizzaResult, expectedText) { 
    t.Errorf("When calling the add ingredient of the pizza decorator it must return the text %sthe expected text, not '%s'", pizzaResult, expectedText) 
  } 
} 

```

现在它必须能够无问题地编译，这样我们就可以检查测试是否失败：

```go
$ go test -v -run=TestPizzaDecorator .
=== RUN   TestPizzaDecorator_AddIngredient
--- FAIL: TestPizzaDecorator_AddIngredient (0.00s)
decorator_test.go:29: Not implemented yet
decorator_test.go:34: When the the AddIngredient method of the pizza decorator object is called, it must return the text
Pizza with the following ingredients:
FAIL
exit status 1
FAIL 

```

我们的第一个测试已经完成，我们可以看到`PizzaDecorator`结构体还没有返回任何东西，这就是为什么它失败了。现在我们可以继续进行`Onion`类型的测试。`Onion`类型的测试与`Pizza`装饰器的测试非常相似，但我们还必须确保我们实际上将配料添加到`IngredientAdd`方法而不是空指针：

```go
func TestOnion_AddIngredient(t *testing.T) { 
  onion := &Onion{} 
  onionResult, err := onion.AddIngredient() 
  if err == nil { 
    t.Errorf("When calling AddIngredient on the onion decorator without" + "an IngredientAdd on its Ingredient field must return an error, not a string with '%s'", onionResult) 
  } 

```

前面测试的前半部分检查了当没有将`IngredientAdd`方法传递给`Onion`结构体初始化程序时返回错误。由于没有可用的披萨来添加配料，必须返回错误：

```go
  onion = &Onion{&PizzaDecorator{}} 
  onionResult, err = onion.AddIngredient() 

  if err != nil { 
    t.Error(err) 
  } 
  if !strings.Contains(onionResult, "onion") { 
    t.Errorf("When calling the add ingredient of the onion decorator it" + "must return a text with the word 'onion', not '%s'", onionResult) 
  } 
} 

```

`Onion`类型测试的第二部分实际上将`PizzaDecorator`结构传递给初始化程序。然后，我们检查是否没有返回错误，以及返回的字符串是否包含单词`onion`。这样，我们可以确保洋葱已添加到比萨中。

最后对于`Onion`类型，我们当前实现的测试的控制台输出将如下所示：

```go
$ go test -v -run=TestOnion_AddIngredient .
=== RUN   TestOnion_AddIngredient
--- FAIL: TestOnion_AddIngredient (0.00s)
decorator_test.go:48: Not implemented yet
decorator_test.go:52: When calling the add ingredient of the onion decorator it must return a text with the word 'onion', not ''
FAIL
exit status 1
FAIL

```

`meat`成分完全相同，但我们将类型更改为肉而不是洋葱：

```go
func TestMeat_AddIngredient(t *testing.T) { 
  meat := &Meat{} 
  meatResult, err := meat.AddIngredient() 
  if err == nil { 
    t.Errorf("When calling AddIngredient on the meat decorator without" + "an IngredientAdd in its Ingredient field must return an error," + "not a string with '%s'", meatResult) 
  } 

  meat = &Meat{&PizzaDecorator{}} 
  meatResult, err = meat.AddIngredient() 
  if err != nil { 
    t.Error(err) 
  } 

  if !strings.Contains(meatResult, "meat") { 
    t.Errorf("When calling the add ingredient of the meat decorator it" + "must return a text with the word 'meat', not '%s'", meatResult) 
  } 
} 

```

因此，测试的结果将是类似的：

```go
go test -v -run=TestMeat_AddIngredient .
=== RUN   TestMeat_AddIngredient
--- FAIL: TestMeat_AddIngredient (0.00s)
decorator_test.go:68: Not implemented yet
decorator_test.go:72: When calling the add ingredient of the meat decorator it must return a text with the word 'meat', not ''
FAIL
exit status 1
FAIL

```

最后，我们必须检查完整的堆栈测试。创建一个带有洋葱和肉的比萨必须返回文本`带有以下配料的比萨：肉，洋葱`：

```go
func TestPizzaDecorator_FullStack(t *testing.T) { 
  pizza := &Onion{&Meat{&PizzaDecorator{}}} 
  pizzaResult, err := pizza.AddIngredient() 
  if err != nil { 
    t.Error(err) 
  } 

  expectedText := "Pizza with the following ingredients: meat, onion" 
  if !strings.Contains(pizzaResult, expectedText){ 
    t.Errorf("When asking for a pizza with onion and meat the returned " + "string must contain the text '%s' but '%s' didn't have it", expectedText,pizzaResult) 
  } 

  t.Log(pizzaResult) 
} 

```

我们的测试创建了一个名为`pizza`的变量，就像`套娃`玩偶一样，嵌入了多个级别的`IngredientAdd`方法的类型。调用`AddIngredient`方法执行"洋葱"级别的方法，该方法执行"肉"级别的方法，最后执行`PizzaDecorator`结构的方法。在检查是否没有返回错误后，我们检查返回的文本是否符合*验收标准 5*的需求。测试使用以下命令运行：

```go
go test -v -run=TestPizzaDecorator_FullStack .
=== RUN   TestPizzaDecorator_FullStack
--- FAIL: TestPizzaDecorator_FullStack (0.
decorator_test.go:80: Not implemented yet
decorator_test.go:87: When asking for a pizza with onion and meat the returned string must contain the text 'Pizza with the following ingredients: meat, onion' but '' didn't have it
FAIL
exit status 1
FAIL

```

从前面的输出中，我们可以看到测试现在为我们装饰的类型返回一个空字符串。当然，这是因为尚未进行任何实现。这是最后一个测试，用于检查完全装饰的实现。然后让我们仔细看看实现。

## 实施

我们将开始实现`PizzaDecorator`类型。它的作用是提供完整比萨的初始文本：

```go
type PizzaDecorator struct { 
  Ingredient IngredientAdd 
} 

func (p *PizzaDecorator) AddIngredient() (string, error) { 
  return "Pizza with the following ingredients:", nil 
} 

```

在`AddIngredient`方法的返回上进行了一行更改就足以通过测试：

```go
go test -v -run=TestPizzaDecorator_Add .
=== RUN   TestPizzaDecorator_AddIngredient
--- PASS: TestPizzaDecorator_AddIngredient (0.00s)
PASS
ok

```

转到`Onion`结构的实现，我们必须取得我们返回的`IngredientAdd`字符串的开头，并在其末尾添加单词`onion`，以便得到一份组合的比萨：

```go
type Onion struct { 
  Ingredient IngredientAdd 
} 

func (o *Onion) AddIngredient() (string, error) { 
  if o.Ingredient == nil { 
    return "", errors.New("An IngredientAdd is needed in the Ingredient field of the Onion") 
  } 
  s, err := o.Ingredient.AddIngredient() 
  if err != nil { 
    return "", err 
  } 
  return fmt.Sprintf("%s %s,", s, "onion"), nil 
} 

```

首先检查我们是否实际上有一个指向`IngredientAdd`的指针，我们使用内部`IngredientAdd`的内容，并检查是否有错误。如果没有错误发生，我们将收到一个由此内容、一个空格和单词`onion`（没有错误）组成的新字符串。看起来足够好来运行测试：

```go
go test -v -run=TestOnion_AddIngredient .
=== RUN   TestOnion_AddIngredient
--- PASS: TestOnion_AddIngredient (0.00s)
PASS
ok

```

`Meat`结构的实现非常相似：

```go
type Meat struct { 
  Ingredient IngredientAdd 
} 

func (m *Meat) AddIngredient() (string, error) { 
  if m.Ingredient == nil { 
    return "", errors.New("An IngredientAdd is needed in the Ingredient field of the Meat") 
  } 
  s, err := m.Ingredient.AddIngredient() 
  if err != nil { 
    return "", err 
  } 
  return fmt.Sprintf("%s %s,", s, "meat"), nil 
} 

```

他们的测试执行如下：

```go
go test -v -run=TestMeat_AddIngredient .
=== RUN   TestMeat_AddIngredient
--- PASS: TestMeat_AddIngredient (0.00s)
PASS
ok

```

好的。现在所有的部分都要分别测试。如果一切正常，*完全堆叠*解决方案的测试必须顺利通过：

```go
go test -v -run=TestPizzaDecorator_FullStack .
=== RUN   TestPizzaDecorator_FullStack
--- PASS: TestPizzaDecorator_FullStack (0.00s)
decorator_test.go:92: Pizza with the following ingredients: meat, onion,
PASS
ok

```

太棒了！使用装饰器模式，我们可以不断堆叠调用它们内部指针以向`PizzaDecorator`添加功能的`IngredientAdds`。我们也不会触及核心类型，也不会修改或实现新的东西。所有新功能都是由外部类型实现的。

## 一个现实生活的例子-服务器中间件

到目前为止，您应该已经了解了装饰器模式的工作原理。现在我们可以尝试使用我们在适配器模式部分设计的小型 HTTP 服务器的更高级示例。您已经学会了可以使用`http`包创建 HTTP 服务器，并实现`http.Handler`接口。该接口只有一个名为`ServeHTTP(http.ResponseWriter, http.Request)`的方法。我们可以使用装饰器模式为服务器添加更多功能吗？当然可以！

我们将向此服务器添加一些部分。首先，我们将记录对其进行的每个连接到`io.Writer`接口（为简单起见，我们将使用`os.Stdout`接口的`io.Writer`实现，以便将其输出到控制台）。第二部分将在发送到服务器的每个请求上添加基本的 HTTP 身份验证。如果身份验证通过，将出现`Hello Decorator!`消息。最后，用户将能够选择他/她在服务器中想要的装饰项的数量，并且服务器将在运行时进行结构化和创建。

### 从常见接口 http.Handler 开始

我们已经有了我们将使用嵌套类型进行装饰的通用接口。我们首先需要创建我们的核心类型，这将是返回句子`Hello Decorator!`的`Handler`。

```go
type MyServer struct{} 

func (m *MyServer) ServeHTTP(w http.ResponseWriter, r *http.Request) { 
  fmt.Fprintln(w, "Hello Decorator!") 
} 

```

这个处理程序可以归因于`http.Handle`方法，以定义我们的第一个端点。现在让我们通过创建包的`main`函数来检查这一点，并向其发送一个`GET`请求：

```go
func main() { 
  http.Handle("/", &MyServer{}) 

  log.Fatal(http.ListenAndServe(":8080", nil)) 
} 

```

使用终端执行服务器以执行`**go run main.go**`命令。然后，打开一个新的终端进行`GET`请求。我们将使用`curl`命令进行请求：

```go
$ curl http://localhost:8080
Hello Decorator!

```

我们已经跨越了我们装饰服务器的第一个里程碑。下一步是用日志功能装饰它。为此，我们必须实现`http.Handler`接口，以新类型的形式进行如下实现：

```go
type LoggerServer struct { 
  Handler   http.Handler 
  LogWriter io.Writer 
} 

func (s *LoggerServer) ServeHTTP(w http.ResponseWriter, r *http.Request) { 
  fmt.Fprintf(s.LogWriter, "Request URI: %s\n", r.RequestURI) 
  fmt.Fprintf(s.LogWriter, "Host: %s\n", r.Host) 
  fmt.Fprintf(s.LogWriter, "Content Length: %d\n",  
r.ContentLength) 
  fmt.Fprintf(s.LogWriter, "Method: %s\n", r.Method)fmt.Fprintf(s.LogWriter, "--------------------------------\n") 

  s.Handler.ServeHTTP(w, r) 
} 

```

我们称这种类型为`LoggerServer`。正如你所看到的，它不仅存储`Handler`，还存储`io.Writer`以写入日志的输出。我们的`ServeHTTP`方法的实现打印请求 URI、主机、内容长度和使用的方法`io.Writer`。打印完成后，它调用其内部`Handler`字段的`ServeHTTP`函数。

我们可以用`LoggerMiddleware`装饰`MyServer`：

```go
func main() { 
  http.Handle("/", &LoggerServer{ 
    LogWriter:os.Stdout, 
    Handler:&MyServer{}, 
  }) 

  log.Fatal(http.ListenAndServe(":8080", nil)) 
} 

```

现在运行`**curl **`命令：

```go
$ curl http://localhost:8080
Hello Decorator!

```

我们的**curl**命令返回相同的消息，但是如果你查看运行 Go 应用程序的终端，你可以看到日志：

```go
$ go run server_decorator.go
Request URI: /
Host: localhost:8080
Content Length: 0
Method: GET

```

我们已经用日志功能装饰了`MyServer`，而实际上并没有修改它。我们能否用相同的方法进行身份验证？当然可以！在记录请求后，我们将使用**HTTP 基本身份验证**进行身份验证：

```go
type BasicAuthMiddleware struct { 
  Handler  http.Handler 
  User     string 
  Password string 
} 

```

**BasicAuthMiddleware**中间件存储三个字段--一个要装饰的处理程序，就像前面的中间件一样，一个用户和一个密码，这将是访问服务器内容的唯一授权。`decorating`方法的实现将如下进行：

```go
func (s *BasicAuthMiddleware) ServeHTTP(w http.ResponseWriter, r *http.Request) { 
  user, pass, ok := r.BasicAuth() 

  if ok { 
    if user == s.User && pass == s.Password { 
      s.Handler.ServeHTTP(w, r) 
    } 
    else { 
      fmt.Fprintf(w, "User or password incorrect\n") 
    } 
  } 
  else { 
    fmt.Fprintln(w, "Error trying to retrieve data from Basic auth") 
  } 
} 

```

在前面的实现中，我们使用`http.Request`的`BasicAuth`方法自动从请求中检索用户和密码，以及解析操作的`ok/ko`。然后我们检查解析是否正确（如果不正确则向请求者返回消息，并结束请求）。如果在解析过程中没有检测到问题，我们将检查用户名和密码是否与`BasicAuthMiddleware`中存储的用户名和密码匹配。如果凭据有效，我们将调用装饰类型（我们的服务器），但如果凭据无效，我们将收到`用户或密码不正确`的消息，并结束请求。

现在，我们需要为用户提供一种选择不同类型服务器的方式。我们将在主函数中检索用户输入数据。我们将有三个选项可供选择：

+   简单服务器

+   带有日志的服务器

+   带有日志和身份验证的服务器

我们必须使用`Fscanf`函数从用户那里检索输入：

```go
func main() { 
  fmt.Println("Enter the type number of server you want to launch from the  following:") 
  fmt.Println("1.- Plain server") 
  fmt.Println("2.- Server with logging") 
  fmt.Println("3.- Server with logging and authentication") 

  var selection int 
  fmt.Fscanf(os.Stdin, "%d", &selection) 
} 

```

`Fscanf`函数需要一个`io.Reader`实现者作为第一个参数（这将是控制台中的输入），并从中获取用户选择的服务器。我们将传递`os.Stdin`作为`io.Reader`接口来检索用户输入。然后，我们将写入它将要解析的数据类型。`%d`指定符指的是整数。最后，我们将写入存储解析输入的内存地址，即`selection`变量的内存位置。

一旦用户选择了一个选项，我们就可以在运行时获取基本服务器并进行装饰，切换到所选的选项：

```go
   switch selection { 
   case 1: 
     mySuperServer = new(MyServer) 
   case 2: 
     mySuperServer = &LoggerMiddleware{ 
       Handler:   new(MyServer), 
       LogWriter: os.Stdout, 
     } 
   case 3: 
     var user, password string 

     fmt.Println("Enter user and password separated by a space") 
     fmt.Fscanf(os.Stdin, "%s %s", &user, &password) 

     mySuperServer = &LoggerMiddleware{ 
     Handler: &SimpleAuthMiddleware{ 
       Handler:  new(MyServer), 
       User:     user, 
       Password: password, 
     }, 
     LogWriter: os.Stdout, 
   } 
   default: 
   mySuperServer = new(MyServer) 
 } 

```

第一个选项将由默认的`switch`选项处理--一个普通的`MyServer`。在第二个选项的情况下，我们用日志装饰了一个普通服务器。第三个选项更加复杂--我们再次使用`Fscanf`要求用户输入用户名和密码。请注意，您可以扫描多个输入，就像我们正在检索用户和密码一样。然后，我们获取基本服务器，用身份验证进行装饰，最后再加上日志。

如果您遵循第三个选项的嵌套类型的缩进，请求将通过记录器，然后通过身份验证中间件，最后，如果一切正常，将通过`MyServer`参数。请求将遵循相同的路线。

主函数的结尾采用了装饰处理程序，并在`8080`端口上启动服务器：

```go
http.Handle("/", mySuperServer) 
log.Fatal(http.ListenAndServe(":8080", nil)) 

```

因此，让我们使用第三个选项启动服务器：

```go
$go run server_decorator.go 
Enter the server type number you want to launch from the following: 
1.- Plain server 
2.- Server with logging 
3.- Server with logging and authentication 

Enter user and password separated by a space 
mario castro

```

首先，我们将通过选择第一个选项来测试普通服务器。使用命令**go run server_decorator.go**运行服务器，并选择第一个选项。然后，在另一个终端中，使用 curl 运行基本请求，如下所示：

```go
$ curl http://localhost:8080
Error trying to retrieve data from Basic auth

```

哦，不！它没有给我们访问权限。我们没有传递任何用户名和密码，因此它告诉我们我们无法继续。让我们尝试一些随机的用户名和密码：

```go
$ curl -u no:correct http://localhost:8080
User or password incorrect

```

没有访问权限！我们还可以在启动服务器的终端中检查每个请求的记录位置：

```go
Request URI: /
Host: localhost:8080
Content Length: 0
Method: GET

```

最后，输入正确的用户名和密码：

```go
$ curl -u packt:publishing http://localhost:8080
Hello Decorator!

```

我们到这里了！我们的请求也已被记录，服务器已经授予我们访问权限。现在我们可以通过编写更多的中间件来改进服务器的功能。

## 关于 Go 的结构化类型的几句话

Go 有一个大多数人一开始不喜欢的特性 - 结构化类型。这是指您的结构定义了您的类型，而无需明确编写它。例如，当您实现一个接口时，您不必明确地写出您实际上正在实现它，与 Java 等语言相反，在那里您必须写出关键字`implements`。如果您的方法遵循接口的签名，那么您实际上正在实现接口。这也可能导致意外实现接口，这可能引起无法跟踪的错误，但这种情况非常罕见。

然而，结构化类型也允许您在定义实现者之后定义接口。想象一个`MyPrinter`结构如下：

```go
type MyPrinter struct{} 
func(m *MyPrinter)Print(){ 
  println("Hello") 
} 

```

假设我们现在已经使用`MyPrinter`类型工作了几个月，但它没有实现任何接口，因此不能成为装饰器模式的可能候选，或者可能可以？如果几个月后编写了一个与其`Print`方法匹配的接口，会发生什么？考虑以下代码片段：

```go
type Printer interface { 
  Print() 
} 

```

它实际上实现了`Printer`接口，我们可以使用它来创建一个装饰器解决方案。

结构化类型在编写程序时提供了很大的灵活性。如果您不确定类型是否应该是接口的一部分，可以将其留下，并在完全确定后再添加接口。这样，您可以非常轻松地装饰类型，并且在源代码中进行很少的修改。

## 总结装饰器设计模式 - 代理与装饰器

您可能会想知道装饰器模式和代理模式之间有什么区别？在装饰器模式中，我们动态地装饰一个类型。这意味着装饰可能存在也可能不存在，或者可能由一个或多个类型组成。如果您记得，代理模式以类似的方式包装类型，但它是在编译时这样做的，更像是一种访问某种类型的方式。

同时，装饰器可能实现其装饰的类型也实现的整个接口**或者不实现**。因此，您可以拥有一个具有 10 个方法的接口和一个只实现其中一个方法的装饰器，它仍然有效。对装饰器未实现的方法的调用将传递给装饰的类型。这是一个非常强大的功能，但如果您忘记实现任何接口方法，它也很容易出现运行时的不良行为。

在这方面，你可能会认为代理模式不够灵活，确实如此。但装饰器模式更弱，因为你可能会在运行时出现错误，而使用代理模式可以在编译时避免这些错误。只需记住，装饰器通常用于在运行时向对象添加功能，就像我们的 Web 服务器一样。这是你需要的东西和你愿意牺牲以实现它之间的妥协。

# 外观设计模式

在本章中我们将看到的下一个模式是外观模式。当我们讨论代理模式时，你了解到它是一种包装类型以隐藏某些特性或复杂性的方式。想象一下，我们将许多代理组合在一个单一点，比如一个文件或一个库。这就是外观模式。

## 描述

在建筑学中，外观是隐藏建筑物房间和走廊的前墙。它保护居民免受寒冷和雨水的侵袭，并为他们提供隐私。它对住宅进行排序和划分。

外观设计模式在我们的代码中做了相同的事情。它保护代码免受未经授权的访问，对一些调用进行排序，并将复杂性范围隐藏在用户视野之外。

## 目标

当你想要隐藏某些任务的复杂性时，特别是当大多数任务共享实用程序时（例如在 API 中进行身份验证）。库是外观的一种形式，其中某人必须为开发人员提供一些方法，以便以友好的方式执行某些操作。这样，如果开发人员需要使用你的库，他不需要知道检索所需结果的所有内部任务。

因此，在以下情况下使用外观设计模式：

+   当你想要减少我们代码的某些部分的复杂性时。你通过提供更易于使用的方法将复杂性隐藏在外观后面。

+   当你想要将相关的操作分组到一个地方时。

+   当你想要构建一个库，以便其他人可以使用你的产品而不必担心它是如何工作的。

## 例子

举例来说，我们将迈出编写访问`OpenWeatherMaps`服务的自己库的第一步。如果你不熟悉`OpenWeatherMap`服务，它是一个提供实时天气信息以及历史数据的 HTTP 服务。**HTTP REST** API 非常易于使用，并且将是一个很好的例子，说明如何为隐藏 REST 服务背后的网络连接的复杂性创建外观模式。

## 接受标准

`OpenWeatherMap` API 提供了大量信息，因此我们将专注于通过使用其纬度和经度值在某个地理位置获取实时天气数据。以下是此设计模式的要求和接受标准：

1.  提供一个单一类型来访问数据。从`OpenWeatherMap`服务检索到的所有信息都将通过它传递。

1.  创建一种获取某个国家的某个城市的天气数据的方法。

1.  创建一种获取某个纬度和经度位置的天气数据的方法。

1.  只有第二和第三点必须在包外可见；其他所有内容都必须隐藏（包括所有连接相关的数据）。

## 单元测试

为了开始我们的 API 外观，我们需要一个接口，其中包含*接受标准 2*和*接受标准 3*中要求的方法：

```go
type CurrentWeatherDataRetriever interface { 
  GetByCityAndCountryCode(city, countryCode string) (Weather, error) 
  GetByGeoCoordinates(lat, lon float32) (Weather, error) 
} 

```

我们将称*接受标准 2*为`GetByCityAndCountryCode`；我们还需要一个城市名称和一个国家代码，格式为字符串。国家代码是一个两个字符的代码，代表着世界各国的**国际标准化组织**（**ISO**）名称。它返回一个`Weather`值，我们稍后会定义，并且如果出现问题会返回一个错误。

*验收标准 3*将被称为`GetByGeoCoordinates`，并且需要`float32`格式的纬度和经度值。它还将返回`Weather`值和错误。`Weather`值将根据`OpenWeatherMap` API 使用的返回 JSON 进行定义。您可以在网页[`openweathermap.org/current#current_JSON`](http://openweathermap.org/current#current_JSON)上找到此 JSON 的描述。

如果查看 JSON 定义，它具有以下类型：

```go
type Weather struct { 
  ID   int    `json:"id"` 
  Name string `json:"name"` 
  Cod  int    `json:"cod"` 
  Coord struct { 
    Lon float32 `json:"lon"` 
    Lat float32 `json:"lat"` 
  } `json:"coord"`  

  Weather []struct { 
    Id          int    `json:"id"` 
    Main        string `json:"main"` 
    Description string `json:"description"` 
    Icon        string `json:"icon"` 
  } `json:"weather"` 

  Base string `json:"base"` 
  Main struct { 
    Temp     float32 `json:"temp"` 
    Pressure float32 `json:"pressure"` 
    Humidity float32 `json:"humidity"` 
    TempMin  float32 `json:"temp_min"` 
    TempMax  float32 `json:"temp_max"` 
  } `json:"main"` 

  Wind struct { 
    Speed float32 `json:"speed"` 
    Deg   float32 `json:"deg"` 
  } `json:"wind"` 

  Clouds struct { 
    All int `json:"all"` 
  } `json:"clouds"` 

  Rain struct { 
    ThreeHours float32 `json:"3h"` 
  } `json:"rain"` 

  Dt  uint32 `json:"dt"` 
  Sys struct { 
    Type    int     `json:"type"` 
    ID      int     `json:"id"` 
    Message float32 `json:"message"` 
    Country string  `json:"country"` 
    Sunrise int     `json:"sunrise"` 
    Sunset  int     `json:"sunset"` 
  }`json:"sys"` 
} 

```

这是一个相当长的结构，但我们拥有响应可能包含的所有内容。该结构称为`Weather`，因为它由 ID，名称和代码（`Cod`）以及一些匿名结构组成，即`Coord`，`Weather`，`Base`，`Main`，`Wind`，`Clouds`，`Rain`，`Dt`和`Sys`。我们可以通过给它们命名来在`Weather`结构之外编写这些匿名结构，但是只有在我们必须单独使用它们时才有用。

在我们的`Weather`结构中的每个成员和结构之后，您可以找到一个`` `json：`something` ``行。当区分 JSON 键名和成员名时，这非常方便。如果 JSON 键是`something`，我们就不必将我们的成员称为`something`。例如，我们的 ID 成员在 JSON 响应中将被称为`id`。

为什么我们不将 JSON 键的名称给我们的类型？好吧，如果您的类型中的字段是小写的，则`encoding/json`包将无法正确解析它们。此外，最后的注释为我们提供了一定的灵活性，不仅可以更改成员名称，还可以省略一些键（如果我们不需要），具有以下签名：

```go
`json:"something,omitempty"`

```

在末尾使用`omitempty`，如果此键在 JSON 键的字节表示中不存在，则解析不会失败。

好的，我们的验收标准 1 要求对 API 进行单点访问。这将被称为`CurrentWeatherData`：

```go
type CurrentWeatherData struct { 
  APIkey string 
} 

```

`CurrentWeatherData`类型具有 API 密钥作为公共成员以工作。这是因为您必须是`OpenWeatherMap`中的注册用户才能享受其服务。请参阅`OpenWeatherMap` API 的网页，了解如何获取 API 密钥的文档。在我们的示例中，我们不需要它，因为我们不打算进行集成测试。

我们需要模拟数据，以便我们可以编写`mock`函数来检索数据。发送 HTTP 请求时，响应以`io.Reader`的形式包含在名为 body 的成员中。我们已经使用了实现`io.Reader`接口的类型，因此这对您来说应该很熟悉。我们的`mock`函数如下所示：

```go
 func getMockData() io.Reader { 
  response := `{
    "coord":{"lon":-3.7,"lat":40.42},"weather : [{"id":803,"main":"Clouds","description":"broken clouds","icon":"04n"}],"base":"stations","main":{"temp":303.56,"pressure":1016.46,"humidity":26.8,"temp_min":300.95,"temp_max":305.93},"wind":{"speed":3.17,"deg":151.001},"rain":{"3h":0.0075},"clouds":{"all":68},"dt":1471295823,"sys":{"type":3,"id":1442829648,"message":0.0278,"country":"ES","sunrise":1471238808,"sunset":1471288232},"id":3117735,"name":"Madrid","cod":200}` 

  r := bytes.NewReader([]byte(response)) 
  return r 
} 

```

通过对`OpenWeatherMap`使用 API 密钥进行请求生成了前面的模拟数据。`response`变量是包含 JSON 响应的字符串。仔细看一下重音符（`` ` ``）用于打开和关闭字符串。这样，你可以毫无问题地使用任意多的引用。

Further on, we use a special function in the bytes package called `NewReader`, which accepts an slice of bytes (which we create by converting the type from string), and returns an `io.Reader` implementor with the contents of the slice. This is perfect to mimic the `Body` member of an HTTP response.

We will write a test to try `response parser`. Both methods return the same type, so we can use the same `JSON parser` for both:

```go

func TestOpenWeatherMap_responseParser(t *testing.T) { 
  r := getMockData() 
  openWeatherMap := CurrentWeatherData{APIkey: ""} 
 
  weather, err := openWeatherMap.responseParser(r) 
  if err != nil { 
    t.Fatal(err) 
  } 
 
  if weather.ID != 3117735 { 
    t.Errorf("Madrid id is 3117735, not %d\n", weather.ID) 
  } 
} 
```

在前面的测试中，我们首先请求了一些模拟数据，我们将其存储在变量`r`中。稍后，我们创建了一种叫做`openWeatherMap`的`CurrentWeatherData`类型。最后，我们请求为提供的 `io.Reader` 接口的天气值，将其存储在变量`weather`中。在检查错误后，我们确保 ID 与从`getMockData`方法获取的模拟数据中存储的 ID 相同。

我们必须在运行测试之前声明`responseParser`方法，否则代码不会编译：

```go

func (p *CurrentWeatherData) responseParser(body io.Reader) (*Weather, error) { 
  return nil, fmt.Errorf("Not implemented yet") 
} 
```

有了上述所有内容，我们可以运行这个测试：

```go
go test -v -run=responseParser .
=== RUN   TestOpenWeatherMap_responseParser
--- FAIL: TestOpenWeatherMap_responseParser (0.00s)
        facade_test.go:72: Not implemented yet
FAIL
exit status 1
FAIL

```

好的。我们不会写更多的测试，因为其余的仅仅是集成测试，这超出了结构模式解释的范围，并会强制我们拥有一个 API 密钥以及互联网连接。如果您想看看这个示例的集成测试是什么样的，请参考随书附带的代码。

## 实现

首先，我们将实现我们的方法将用于解析`OpenWeatherMap` REST API 的 JSON 响应的解析器：

```go

func (p *CurrentWeatherData) responseParser(body io.Reader) (*Weather, error) { 
  w := new(Weather) 
  err := json.NewDecoder(body).Decode(w) 
  if err != nil { 
    return nil, err 
  } 
 
  return w, nil 
} 
```

现在，这应该足以通过测试了：

```go

go test -v -run=responseParser . 
=== RUN   TestOpenWeatherMap_responseParser 
--- PASS: TestOpenWeatherMap_responseParser (0.00s) 
PASS 
ok

```

至少我们对我们的解析器进行了充分测试。让我们将我们的代码结构化得像一个库。首先，我们将创建通过城市名和国家代码以及通过其纬度和经度来检索城市天气的方法，以及使用其纬度和经度的方法：

```go

func (c *CurrentWeatherData) GetByGeoCoordinates(lat, lon float32) (weather *Weather, err error) { 
  return c.doRequest( 
  fmt.Sprintf("http://api.openweathermap.org/data/2.5/weather q=%s,%s&APPID=%s", lat, lon, c.APIkey)) 
} 
 
func (c *CurrentWeatherData) GetByCityAndCountryCode(city, countryCode string) (weather *Weather, err error) { 
  return c.doRequest(   
  fmt.Sprintf("http://api.openweathermap.org/data/2.5/weather?lat=%f&lon=%f&APPID=%s", city, countryCode, c.APIkey) ) 
} 

```

小菜一碟？当然！一切都必须尽可能简单，并且这是一项出色工作的标志。这个外观中的复杂性在于创建与`OpenWeatherMap` API 的连接，以及控制可能的错误。这个问题在我们的示例中的所有 Facade 方法之间共享，所以我们暂时不需要编写多个 API 调用。

我们所做的是传递 REST API 需要的 URL 以便返回我们想要的信息。这是通过 `fmt.Sprintf` 函数实现的，该函数在每种情况下格式化字符串。例如，为了使用城市名和国家代码获取数据，我们使用以下字符串：

```go

fmt.Sprintf("http://api.openweathermap.org/data/2.5/weather?lat=%f&lon=%f&APPID=%s", city, countryCode, c.APIkey)

```

这需要预先格式化的字符串[`openweathermap.org/api`](https://openweathermap.org/api)，并通过用城市、我们在参数中引入的`countryCode`和`CurrentWeatherData`类型的 API 密钥成员来替换每个 `%s` 指定符来格式化它。

但是，我们还没有设置任何 API 密钥！是的，因为这是一个库，库的用户将必须使用自己的 API 密钥。我们正在隐藏创建 URI 和处理错误的复杂性。

最后，`doRequest`函数是个大问题，所以我们会逐步详细地查看它：

```go

func (o *CurrentWeatherData) doRequest(uri string) (weather *Weather, err error) { 
  client := &http.Client{} 
  req, err := http.NewRequest("GET", uri, nil) 
  if err != nil { 
    return 
  } 
  req.Header.Set("Content-Type", "application/json") 

```

首先，签名告诉我们`doRequest`方法接受一个 URI 字符串，并返回一个指向`Weather`变量和一个错误的指针。我们首先创建一个`http.Client`类，它将发送请求。然后，我们创建一个请求对象，该对象将使用`GET`方法，如`OpenWeatherMap`网页中所述，并传递我们传递的 URI。如果我们要使用不同的方法，或者多个方法，则必须通过签名中的参数来实现。尽管如此，我们只会使用`GET`方法，所以我们可以在那里硬编码它。

然后，我们检查请求对象是否已成功创建，并设置一个标题，说明内容类型是 JSON：

```go

resp, err := client.Do(req) 
if err != nil { 
  return 
} 
 
if resp.StatusCode != 200 { 
  byt, errMsg := ioutil.ReadAll(resp.Body) 
  if errMsg == nil { 
    errMsg = fmt.Errorf("%s", string(byt)) 
  } 
  err = fmt.Errorf("Status code was %d, aborting. Error message was:\n%s\n",resp.StatusCode, errMsg) 
 
  return 
} 
```

然后我们发出请求，并检查错误。因为我们给返回类型命名了，如果发生任何错误，我们只需返回函数，Go 就会返回变量`err`和变量`weather`在那一刻的状态。

我们检查响应的状态码，因为我们只接受 200 作为良好的响应。如果没有返回 200，我们将创建一个包含主体内容和返回的状态码的错误消息：

```go

  weather, err = o.responseParser(resp.Body) 
  resp.Body.Close() 
 
  return 
} 
```

最后，如果一切顺利，我们使用之前编写的`responseParser`函数来解析 Body 的内容，它是一个`io.Reader`接口。也许你想知道为什么我们没有控制`response parser`方法中的`err`。有趣的是，因为我们实际上是在控制它。`responseParser`和`doRequest`具有相同的返回签名。两者都返回一个`Weather`指针和一个错误（如果有的话），所以我们可以直接返回结果。

## 使用外观模式创建的库

我们为使用外观模式的`OpenWeatherMap` API 创建了第一个里程碑。我们在`doRequest`和`responseParser`函数中隐藏了访问`OpenWeatherMap` REST API 的复杂性，而我们库的用户则可以使用易于使用的语法查询 API。例如，要获取西班牙马德里的天气，用户只需在开头输入参数和 API 密钥：

```go

  weatherMap := CurrentWeatherData{*apiKey} 
 
  weather, err := weatherMap.GetByCityAndCountryCode("Madrid", "ES") 
  if err != nil { 
    t.Fatal(err) 
  } 
 
  fmt.Printf("Temperature in Madrid is %f celsius\n", weather.Main.Temp-273.15) 
```

写作本章时，马德里的天气控制台输出如下：

```go

$ Temperature in Madrid is 30.600006 celsius
```

一个典型的夏日！

# [享元模式](https://zh.wikipedia.org/wiki/享元模式)

我们接下来介绍的是**享元**设计模式。它在计算机图形和视频游戏行业中非常常见，但在企业应用中并不常见。

## 描述

享元是一种模式，它允许在某种类型的许多实例之间共享一个重型对象的状态。想象一下，你必须创建和存储太多基本相同的某种重型对象，你会很快耗尽内存。这个问题可以很容易地通过享元模式来解决，还可以额外借助工厂模式的帮助。工厂通常负责封装对象的创建，就像我们之前看到的那样。

## 目标

由于享元模式（**Flyweight pattern**）的存在，我们可以在单个共同对象中共享对象的所有可能状态，从而通过使用指向已创建对象的指针来最小化对象的创建。

## 示例

举个例子，我们将模拟您在赌博网页上找到的一些事情。 想象一下欧洲锦标赛的最后一场比赛，数百万人在整个欧洲观看。 现在想象一下我们拥有一个提供欧洲每支球队历史信息的赌博网页。 这是大量信息，通常存储在一些分布式数据库中，每支球队都有着字面上的兆字节信息，包括球员、比赛、冠军等等。

如果有百万用户访问有关一支球队的信息，并且为每个查询历史数据的用户创建新信息实例，我们将瞬间耗尽内存。 有了我们的代理模式解决方案，我们可以创建一个 *n* 个最近搜索的缓存以加快查询速度，但如果我们为每支球队返回一个克隆，我们仍然会因内存不足而短缺（但由于缓存，速度会更快）。 有趣，是吧？

相反，我们将仅仅存储每支球队的信息一次，并向用户提供对它们的引用。 因此，如果有百万用户尝试访问有关一场比赛的信息，实际上我们将在内存中只有两支球队，并且有百万个指针指向相同的内存地址。

## 验收标准

享元模式的验收标准必须始终减少使用的内存量，并且必须主要专注于这个目标：

1.  我们将创建一个名为`Team`的结构体，其中包含一些基本信息，比如球队的名称、球员、历史成绩以及展示其队徽的图像。

1.  我们必须确保正确的团队创建（注意这里的 *创建* 一词，适合用创建型模式），并且不会出现重复。

1.  当两次创建相同的球队时，我们必须拥有两个指针指向相同的内存地址。

## 基本结构体和测试

我们的`Team`结构体将包含其他结构体，因此将创建总共四个结构体。 `Team` 结构体的签名如下：

```go

type Team struct { 
  ID             uint64 
  Name           string 
  Shield         []byte 
  Players        []Player 
  HistoricalData []HistoricalData 
} 

```

每支球队都有一个 ID、一个名称、表示球队队徽的字节片段图像、一组球员和一组历史数据。 这样，我们将有两支球队的 ID：

```go
const ( 
  TEAM_A = iota 
  TEAM_B 
) 

```

我们通过使用 `const` 和 `iota` 关键字声明两个常量。 `const` 关键字简单地声明接下来的声明为常量。 `iota` 是一个无类型整数，它会自动递增其值，用于每个括号之间的新常量。 当我们声明`TEAM_A`时，`iota`的值开始重置为 0，因此`TEAM_A`等于 0。 在`TEAM_B`变量上，`iota`增加了一个，因此`TEAM_B`等于 1。 `iota` 赋值是在声明不需要特定值的常量值时节约输入的一种优雅方式（就像 `math` 包中的 *Pi* 常量）。

我们的`Player`和`HistoricalData`如下：

```go
type Player struct { 
  Name    string 
  Surname string 
  PreviousTeam uint64 
  Photo   []byte 
} 
 
type HistoricalData struct { 
  Year          uint8 
  LeagueResults []Match 
} 

```

如您所见，我们还需要一个存储在 `HistoricalData` 结构体中的 `Match` 结构体。在这个上下文中，`Match` 结构体表示比赛的历史结果：

```go

type Match struct { 
  Date          time.Time 
  VisitorID     uint64 
  LocalID       uint64 
  LocalScore    byte 
  VisitorScore  byte 
  LocalShoots   uint16 
  VisitorShoots uint16 
} 

```

这足以表示一个团队，并满足 *验收标准 1*。您可能已经猜到每个团队都有很多信息，因为一些欧洲团队已经存在了 100 多年。

对于 *验收标准 2*，单词 *creation* 应该为我们提供一些解决此问题的线索。我们将构建一个工厂来创建和存储我们的团队。我们的工厂将包括一个年份映射，其中包括指向 `Teams` 的指针作为值，以及一个 `GetTeam` 函数。使用映射将会加速团队的搜索，如果我们提前知道它们的名称。我们还将提供一个方法来返回已创建对象的数量，称为 `GetNumberOfObjects` 方法：

```go

type teamFlyweightFactory struct { 
  createdTeams map[string]*Team 
} 
 
func (t *teamFlyweightFactory) GetTeam(name string) *Team { 
  return nil 
} 
 
func (t *teamFlyweightFactory) GetNumberOfObjects() int { 
  return 0 
} 
```

这足以编写我们的第一个单元测试了：

```go

func TestTeamFlyweightFactory_GetTeam(t *testing.T) { 
  factory := teamFlyweightFactory{} 
 
teamA1 := factory.GetTeam(TEAM_A) 
  if teamA1 == nil { 
    t.Error("The pointer to the TEAM_A was nil") 
  } 
 
  teamA2 := factory.GetTeam(TEAM_A) 
  if teamA2 == nil { 
    t.Error("The pointer to the TEAM_A was nil") 
  } 
 
  if teamA1 != teamA2 { 
    t.Error("TEAM_A pointers weren't the same") 
  } 
 
  if factory.GetNumberOfObjects() != 1 { 
    t.Errorf("The number of objects created was not 1: %d\n", factory.GetNumberOfObjects()) 
  } 
} 

```

在我们的测试中，我们验证了所有的验收标准。首先我们创建一个工厂，然后请求 `TEAM_A` 的指针。这个指针不能为 `nil`，否则测试将失败。

然后我们调用第二个指针指向同一支团队。这个指针也不能为 `nil`，并且应该指向与前一个指针相同的内存地址，这样我们就知道它没有分配新的内存。

最后，我们应该检查已创建团队的数量是否只有一个，因为我们已经两次请求了相同的团队。我们有两个指针，但只有一个团队实例。让我们运行测试：

```go

$ go test -v -run=GetTeam .
=== RUN   TestTeamFlyweightFactory_GetTeam
--- FAIL: TestTeamFlyweightFactory_GetTeam (0.00s)
flyweight_test.go:11: The pointer to the TEAM_A was nil
flyweight_test.go:21: The pointer to the TEAM_A was nil
flyweight_test.go:31: The number of objects created was not 1: 0
FAIL
exit status 1
FAIL
```

嗯，失败了。两个指针都是 `nil`，并且没有创建任何对象。有趣的是，比较这两个指针的函数并没有失败；总之，`nil` 等于 `nil`。

## 实现

我们的 `GetTeam` 方法将需要扫描称为 `createdTeams` 的映射字段，以确保查询的团队已经创建，并在返回前存储它。如果团队尚未创建，则必须在返回前创建它并将其存储在映射中：

```go

func (t *teamFlyweightFactory) GetTeam(teamID int) *Team { 
  if t.createdTeams[teamID] != nil { 
    return t.createdTeams[teamID] 
  } 
 
  team := getTeamFactory(teamID) 
  t.createdTeams[teamID] = &team 
 
  return t.createdTeams[teamID] 
} 
```

上述代码非常简单。如果参数名称存在于 `createdTeams` 映射中，则返回指针。否则，调用团队创建工厂。这足够有趣，让我们停下来分析一下。当您使用享元模式时，很常见有一个享元工厂，它使用其他类型的创建模式来检索它所需的对象。

因此，`getTeamFactory` 方法将为我们提供所需的团队，我们将其存储在映射中并返回。团队工厂将能够创建两支团队：`TEAM_A` 和 `TEAM_B`：

```go

func getTeamFactory(team int) Team { 
  switch team { 
    case TEAM_B: 
    return Team{ 
      ID:   2, 
      Name: TEAM_B, 
    } 
    default: 
    return Team{ 
      ID:   1, 
      Name: TEAM_A, 
    } 
  } 
} 
```

我们简化了对象的内容，以便可以专注于享元模式的实现。好的，我们只需定义检索已创建对象数量的函数，如下所示：

```go

func (t *teamFlyweightFactory) GetNumberOfObjects() int { 
  return len(t.createdTeams) 
} 

```

这很简单。`len` 函数返回数组或切片中的元素数量，`string` 中的字符数量等。看起来一切都完成了，我们可以再次运行测试了：

```go

$ go test -v -run=GetTeam . 
=== RUN   TestTeamFlyweightFactory_GetTeam 
--- FAIL: TestTeamFlyweightFactory_GetTeam (0.00s) 
panic: assignment to entry in nil map [recovered] 
        panic: assignment to entry in nil map 
 
goroutine 5 [running]: 
panic(0x530900, 0xc0820025c0) 
        /home/mcastro/Go/src/runtime/panic.go:481 +0x3f4 
testing.tRunner.func1(0xc082068120) 
        /home/mcastro/Go/src/testing/testing.go:467 +0x199 
panic(0x530900, 0xc0820025c0) 
        /home/mcastro/Go/src/runtime/panic.go:443 +0x4f7 
/home/mcastro/go-design-patterns/structural/flyweight.(*teamFlyweightFactory).GetTeam(0xc08202fec0, 0x0, 0x0) 
        /home/mcastro/Desktop/go-design-patterns/structural/flyweight/flyweight.go:71 +0x159 
/home/mcastro/go-design-patterns/structural/flyweight.TestTeamFlyweightFactory_GetTeam(0xc082068120) 
        /home/mcastro/Desktop/go-design-patterns/structural/flyweight/flyweight_test.go:9 +0x61 
testing.tRunner(0xc082068120, 0x666580) 
        /home/mcastro/Go/src/testing/testing.go:473 +0x9f 
created by testing.RunTests 
        /home/mcastro/Go/src/testing/testing.go:582 +0x899 
exit status 2 
FAIL

```

惊慌！我们有什么忘了吗？通过阅读 panic 消息中的堆栈跟踪，我们可以看到一些地址、一些文件，似乎`GetTeam`方法试图在`flyweight.go`文件的*第 71 行*给一个空 map 赋值。让我们仔细看看*第 71 行*（请记住，如果您在按照本教程编写代码，那么错误可能在不同的行，因此请仔细查看您自己的堆栈跟踪）：

```go

t.createdTeams[teamName] = &team

```

好了，这行位于`GetTeam`方法中，当方法通过这里时，意味着它在 map 中没有找到团队-它已经创建了它（变量团队），并尝试将其分配给 map。但 map 是 nil，因为我们在创建工厂时没有初始化它。这有一个快速解决方案。在我们创建工厂的地方，在测试中初始化 map：

```go

factory := teamFlyweightFactory{
    createdTeams: make(map[int]*Team,0),
}

```

我相信你已经看到了这里的问题。如果我们无法访问包，我们可以初始化变量。好吧，我们可以将变量设为公共的，就这样。但这会导致每个实现者必须知道他们必须初始化 map，而且它的签名既不方便也不优雅。相反，我们将创建一个简单的工厂构建器来代替。这在 Go 中是一种非常常见的方法：

```go

func NewTeamFactory() teamFlyweightFactory { 
  return teamFlyweightFactory{ 
    createdTeams: make(map[int]*Team), 
  } 
} 
```

现在，在测试中，我们用对此函数的调用替换了工厂的创建：

```go

func TestTeamFlyweightFactory_GetTeam(t *testing.T) { 
  factory := NewTeamFactory() 
  ... 
} 
```

然后我们再次运行测试：

```go
$ go test -v -run=GetTeam .
=== RUN   TestTeamFlyweightFactory_GetTeam
--- PASS: TestTeamFlyweightFactory_GetTeam (0.00s)
PASS
ok 
```

完美！让我们通过添加第二个测试来改进测试，以确保一切都会按预期运行并具有更多的量。我们将创建一百万次对团队创建的调用，代表一百万个用户的调用。然后，我们只需检查创建的团队数量是否只有两个：

```go

func Test_HighVolume(t *testing.T) { 
  factory := NewTeamFactory() 
 
  teams := make([]*Team, 500000*2) 
  for i := 0; i < 500000; i++ { 
  teams[i] = factory.GetTeam(TEAM_A) 
} 
 
for i := 500000; i < 2*500000; i++ { 
  teams[i] = factory.GetTeam(TEAM_B) 
} 
 
if factory.GetNumberOfObjects() != 2 { 
  t.Errorf("The number of objects created was not 2: %d\n",factory.GetNumberOfObjects()) 
```

在这个测试中，我们分别检索了`TEAM_A`和`TEAM_B`500,000 次，每个检索达到一百万用户。然后，我们确保只创建了两个对象：

```go

$ go test -v -run=Volume . 
=== RUN   Test_HighVolume 
--- PASS: Test_HighVolume (0.04s) 
PASS 
ok
```

完美！我们甚至可以检查指针指向的位置以及它们的位置。我们将以前三个为例进行检查。将以下行添加到最后一个测试的末尾，然后再次运行它：

```go
for i:=0; i<3; i++ { 
  fmt.Printf("Pointer %d points to %p and is located in %p\n", i, teams[i], &teams[i]) 
} 

```

在前面的测试中，我们使用`Printf`方法打印指针的信息。`%p`标志会给出指针指向的对象的内存位置。如果通过传递`&`符号引用指针，它将给出指针本身的方向。

用相同的命令再次运行测试；您将在输出中看到三行新信息，信息类似于以下内容：


```go

Pointer 0 points to 0xc082846000 and is located in 0xc082076000
Pointer 1 points to 0xc082846000 and is located in 0xc082076008
Pointer 2 points to 0xc082846000 and is located in 0xc082076010

```

它告诉我们的是，地图中的前三个位置指向相同的位置，但实际上我们有三个不同的指针，它们实际上比我们的团队对象轻得多。

## 那么单例模式和享元模式有什么区别呢？

嗯，差异微妙，但确实存在。使用单例模式，我们确保只创建一次相同的类型。此外，单例模式是一种创建模式。对于享元模式，它是一种结构模式，我们不关心对象是如何创建的，而是关心如何以轻量的方式构造一个类型来包含重的信息。我们谈论的结构是我们的例子中的`map[int]*Team`结构。在这里，我们真的不关心如何创建对象；我们只是为它编写了一个简单的`getTeamFactory`方法。我们非常重视拥有一个轻量级的结构来容纳可共享的对象（或对象），在这种情况下是地图。

# 总结

我们已经看到了几种组织代码结构的模式。结构模式关心如何创建对象，或者它们如何进行业务（我们将在行为模式中看到这一点）。

不要因为混合了几种模式而感到困惑。如果您严格遵循每种模式的目标，您很容易混合六七种模式。只要记住，过度设计和根本不设计一样糟糕。我记得有一天晚上我做了一个负载均衡器的原型，经过两个小时的疯狂过度设计的代码后，我的脑子里一团糟，我宁愿重新开始。

在下一章中，我们将看到行为模式。它们更加复杂，通常使用结构模式和创建模式来实现它们的目标，但我相信读者会觉得它们非常具有挑战性和有趣。
