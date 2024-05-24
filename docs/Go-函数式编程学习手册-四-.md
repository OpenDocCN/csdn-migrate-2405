# Go 函数式编程学习手册（四）

> 原文：[`zh.annas-archive.org/md5/5FC2C8948F5CEA11C4D0D293DBBCA039`](https://zh.annas-archive.org/md5/5FC2C8948F5CEA11C4D0D293DBBCA039)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第七章：功能参数

在写这一章的时候，我的思绪回到了几年前，当我还在 FoxPro 中编程时。我记得我在 FoxPro 中写了很多函数。我写的函数通常都是单一用途的，很少需要超过四个参数。在微软收购 Fox Software 之后，FoxPro 的新版本开始变得不那么实用。UI 构建器变得更像 Visual Basic。函数开始被类所取代。曾经容易访问的逻辑被隐藏在按钮和 GUI 对象后面。代码行数增加，测试需要更多时间，开发周期变得更长。我感到缺乏生产力，无法充分解释我的感受。

“不理解数学的最高确定性的人陷入了困惑。”

- 莱昂纳多·达·芬奇

当我发现 Go 时，就像天堂重新获得；回归简单，同时具有并发性、网络、出色的开发工具、一流的函数以及面向对象编程的最佳部分。

我们在本章的目标是做以下事情：

+   学习重构长参数列表的更好方法

+   认识死数据对象和功能参数之间的区别

+   学习柯里化和部分应用之间的区别

+   学习如何应用部分应用程序来创建另一个具有较小 arity 的函数

+   使用上下文来优雅地关闭我们的服务器

+   使用上下文来取消和回滚长时间运行的数据库事务

+   实现功能选项以改进我们的 API

如果您认为通过将指针传递给可变数据对象或调用隐藏在函数中的其他函数来简化长参数列表是可以接受的，请以开放的心态阅读本章。

## 重构长参数列表

长参数列表通常被认为是代码异味。

太长了吗？

当我们看着参数列表而无法跟踪它们时，那么它很可能太长了。

**发现大脑的极限 - 一次 4 件事**

工作记忆与我们可以关注和理解的信息有关。保持我们的参数列表简短有助于他人轻松理解我们函数的目的。

[`www.livescience.com/2493-mind-limit-4.html`](https://www.livescience.com/2493-mind-limit-4.html)

四个参数或更少是最佳选择，但七个是最大值。

考虑一下我们的电话号码。有多少位数字？七位。例如：867-5309

你认为为什么七个数字被分成两组数字，其中最大的一组有四个数字？

### 函数签名中超过七个参数有什么问题？

函数签名不应该太长和复杂，以至于我们无法理解。保持简单。使用周到、合理和有意义的参数名称。

是否注意到具有长参数列表的函数通常是某种类型的构造函数？并且这些函数往往会随着时间的推移而获得更多的参数？

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/lrn-fp-go/img/1db4c530-01da-43f2-a7d6-dcf06b6b3101.png)

软件工程师希望减少函数的参数列表是很自然的。这是我们重构应用程序时所做的一部分。只要我们牢记可理解性的目标，我们就会没问题。有时，我们可能有一个具有十个参数的函数签名。如果其他替代方案会使我们的函数签名模糊不清，那就去做吧。清晰胜过模糊。我们应该使用多少参数？这取决于情况。

重构代码是改变代码结构而不改变其行为的过程。我们不是在添加功能。相反，我们是使我们的代码更易读和更易维护。通常，我们会将大型函数（超过 200 行代码）分解为更小、更易理解的代码单元。

有些方法比其他方法更好。

### 重构 - 这本书

读过《重构》这本书吗？它涵盖了重构长参数列表的主题。

提出了以下观点：

+   方法可以在内部查询其他对象的方法以获取做出决策所需的数据

+   方法应该依赖于它们所在的类来获取所需的数据

+   我们应该传递一个或多个对象来简化我们的调用签名

+   我们应该使用一种叫做*用方法替换参数*的技术来减少所需参数的数量

+   传递一个具有所需属性的整个对象以减少所需参数的数量

+   当我们有不相关的数据元素要传递时，请使用参数对象

+   当我们不想在一个更大的参数对象上创建依赖关系时，我们可以发送单独的参数；这是一个例外，我们可能不应该这样做

+   长参数列表会随时间改变，并且本质上很难理解

这个建议与纯面向对象的语言设计方法一致。然而，作为优秀的 Go 程序员，我们应该只同意最后一点。为什么？

为什么会有这样一个几乎持续了 20 年的建议会如此糟糕？

### 艾兹格·W·迪科斯彻说面向对象编程是一个糟糕的想法

荷兰计算机科学家迪科斯彻对面向对象编程提供了以下见解：

“面向对象编程是一个只能在加利福尼亚州产生的极其糟糕的想法。”

- 艾兹格·W·迪科斯彻

什么？面向对象编程是一个*极其糟糕的想法*？为什么？

首先，让我们更多地了解一下艾兹格·W·迪科斯彻。

#### 艾兹格·W·迪科斯彻还说了什么？

迪科斯彻说了一些诸如：

“胜任的程序员完全意识到自己头脑的严格有限大小；因此他怀着完全的谦卑态度对待编程任务，而且他避免像瘟疫一样的聪明技巧。”

- 艾兹格·W·迪科斯彻

他还说了以下的话：

“简单是可靠的前提。”

- 艾兹格·W·迪科斯彻

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/lrn-fp-go/img/3d6b32ec-a539-4e00-9b39-14bcf5e86cea.png)

莫扎特的作曲

“智力的高度或想象力的高度或两者结合在一起并不能造就天才。爱，爱，爱，那是天才的灵魂。”

- 沃尔夫冈·阿马德乌斯·莫扎特

迪科斯彻分享了他对软件开发中不同编程风格的看法。迪科斯彻比较了莫扎特和贝多芬作曲音乐的方式。迪科斯彻解释说，莫扎特开始时就有整个作曲的构思。而贝多芬则会在作曲未完成时写下音乐的部分，并且会用胶水粘贴修正来创作最终的作品。

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/lrn-fp-go/img/57e11402-b3ea-4ef0-8031-458e27b6a63d.png)

贝多芬的作曲

迪科斯彻似乎更喜欢莫扎特的编程风格。他自己的编程方法表明，程序应该被设计和正确组合，而不仅仅是被修改和调试到正确。

莫扎特之所以能在实施之前进行详细设计，是因为他是音乐作曲艺术的大师，并且有丰富的经验。有时，在开发软件时，我们可能没有这样的奢侈条件。当我们无法确定适合我们项目的框架时，将会有更多的试错式编程。

就我个人而言，当我没有严格的截止日期时，我更喜欢贝多芬式的开发。我把它看作是娱乐性编程。它本质上是自我探索的。对我来说，莫扎特式的开发需要更多的纪律。通常，最终结果是一样的。莫扎特式的开发需要更少的时间来完成，但贝多芬式的开发更加愉快。我想这就是为什么开发人员如此喜欢研发项目。 

#### 面向对象编程的根本问题

正如在第四章中所指出的，*Go 中的 SOLID 设计*，你学到了 Java（和面向对象编程语言）如何强调类型层次结构。面向对象编程的设计者关注的是名词而不是动词。一切都是对象。一个对象有属性（数据）并且可以执行动作（方法）。

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/lrn-fp-go/img/66b75afc-8bb8-415f-aada-746631d67ca1.png)

一个不活跃的名词

面向对象编程的一个潜在问题是它促进了在对象的属性/属性中存储和隐藏数据。假设我们的应用程序最终会在执行一个或多个对象的方法时想要访问该对象的数据。

#### OOP 的不一致性

面向对象编程应用可以调用其隐藏的信息并对其进行改变。在应用程序的生命周期内，可以多次调用对象的方法。每次以相同的调用签名调用相同的方法都可能产生不同的结果。其行为特性使得面向对象编程不可靠且难以有效测试。

面向对象编程与基本数学不一致。在面向对象编程中，由于对象的可变状态，我们不能总是以相同的参数调用方法并始终获得相同的结果。面向对象编程没有数学模型。例如，如果我们调用`myMethod(1,2)`，第一次得到 3，下一次得到 4，由于可变状态和对其他对象的内部调用，那么面向对象编程程序的正确性无法定义。

#### 函数式编程和云计算

函数式程序的本质与面向对象编程非常不同。给定相同的输入参数，函数式程序将始终产生相同的结果。我们可以轻松地并行运行它们。我们可以以更快的方式链接/组合它们，这是面向对象编程所不可能的。

我们的部署模型已经从内部服务器改变，管理员会花费大量时间配置和优化它们，以至于给服务器取了宠物名字。我们过去看到的名字遵循了希腊神的模式。有*宙斯*，我们的数据库服务器，还有*阿波罗*，我们的人力资源服务器。

现在我们的服务器部署在云中，我们的管理员可以通过点击按钮添加新服务器或设置自动扩展：如果平均 CPU 超过 80％，则添加新服务器。看起来是这样的：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/lrn-fp-go/img/a52acd9f-b1c4-448a-b051-3d0aa11f467f.png)

上图中的 Pod 代表一个服务器，可能有几个相关的容器。Pod 中的一个容器将运行我们的`f(x)`函数。如果服务器崩溃，我们容器编排器中运行的自动扩展逻辑将被通知，并将自动启动另一台服务器来替换它。Pod 可以根据我们的云部署配置文件和网站的流量模式快速进行配置，并根据需要停用。由于服务器这些天来来去去如此容易和迅速，我们称它们为牲畜而不是宠物。我们更关心我们的服务器群的健康状况，而不是任何一个特定的宠物服务器。

术语*Pod*取自 Kubernetes。请参阅[`kubernetes.io/docs/concepts/workloads/pods/pod-overview/`](https://kubernetes.io/docs/concepts/workloads/pods/pod-overview/)了解更多信息。

Pods 大致相当于 OpenShift v2 的齿轮，并在逻辑上代表一个*逻辑主机*，所有服务容器都可以通过 localhost 相互通信。

其他容器编排器包括 Docker Swarm、Mesos、Marathon 和 Nomad。请参阅[`github.com/KaivoAnastetiks/container-orchestration-comparison`](https://github.com/KaivoAnastetiks/container-orchestration-comparison)。 

具有 FP 特征的应用在我们的云环境中表现可靠；然而，具有可变状态的 OOP 特征的应用则不会如此。

##### 深入了解 f(x)

让我们来看一个基本的函数定义，其中**f**是函数名，**x**是输入值。**x**的另一个名称是输入参数。

整个表达式**f(x)**代表输出值：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/lrn-fp-go/img/533ed4de-b9bc-476d-bba2-516b17d7cca3.png)

如果*f(x) = x + 1*，那么我们知道每次输入值 2 时，输出值总是 3。

这种纯粹和简单的特性是使函数式编程如此强大的原因。

另一方面，如果我们有一个带有`AddOne`方法的对象，有时会在给定值为 2 时返回 3，那么我们如何可靠地扩展我们的`object.AddOne`方法呢？我们不能，这就是为什么在云计算的背景下，以下等式成立的主要原因：*FP > OOP*。

### 重构的更近距离观察

让我们根据函数式编程的观点审视《重构》一书中提出的每一点。

#### 传递函数所需的每个参数并不是一个好主意

为什么我们不希望我们的函数签名指示它需要做出决策的值（参数）？

我们如何减少函数需要的参数？

#### 方法可以在内部查询其他对象的方法以获取做出决策所需的数据

因此，与其调用`GetTravelTime(startLocation, endLocation)`方法，最好调用`GetTravelTime()`？

我们从哪里获取`startLocation`和`endLocation`的值？

我们如何确保没有其他值，比如`modeOfTransportation`，会影响我们的旅行时间结果？

这是否会创建内部的、未记录的依赖关系（假设我们记录了我们的外部 API）？

#### 方法应该依赖于它们所属的类来获取所需的数据

这是否意味着我们依赖于可变数据，这些数据在我们的函数调用之前和期间可能会被更新？

如果我们想要在我们的函数运行时阻止数据更新，我们需要写什么额外的代码来确保数据一致性？我们需要实现什么样的锁定机制？

这会阻止我们编写并行运行的代码吗？

并发编程是否可能？

#### 传递一个带有所需属性的完整对象以减少所需参数的数量

因此，我们的调用应该像这样：`GetTravelTime(info)`，而不是`GetTravelTime(startLocation, endLocation, speed)`。

有时像这样的函数调用`Initialize(Config)`是有意义的，这取决于我们的用例。

然而，也许我们应该努力简化我们的函数，以便自然地需要更少的参数，而不是找到将更多参数值塞入单个输入参数对象的方法。

#### 用方法替换参数技术来减少所需参数的数量

这种技术指导我们删除参数，让接收者调用方法。

##### 在应用*用方法替换参数*技术之前

我们从一个`getDiscountedPrice`函数开始，它需要两个参数：`lineItemPrice`和 discount：

```go
 lineItemPrice := quantity * itemPrice;
 discount := getDiscount();
 totalPrice := getDiscountedPrice(lineItemPrice, discount);
```

*用方法替换参数*积极努力减少参数的数量。

在这种情况下，我们有两个参数。这显然比四个参数少。为什么要减少这么少的参数？

##### 应用*用方法替换参数*技术后

根据我们的指示重构我们的代码后，我们已经删除了一个参数。现在我们只有一个参数：

```go
 lineItemPrice := quantity * itemPrice;
 totalPrice := getDiscountedPrice(lineItemPrice);
```

代码维护者如何知道`totalPrice`可以通过折扣减少？

隐藏折扣参数是否提高了可理解性，还是实际上增加了代码复杂性？

#### 当我们有不相关的数据元素需要传递时，使用参数对象

参数对象只包含字段和用于访问它们的简单方法（getter 和 setter）。它是一个死数据结构，仅用于传输数据。

如果我们将许多不相关的数据项传递到一个函数中，那么我们的函数失败单一职责原则的几率有多大？

如果我们想要添加可以根据我们的运行时上下文修改数据值的逻辑，该怎么办？

然而，如果我们有一组描述新客户的参数，我们可以考虑将它们分组到一个数据对象中。以下内容可能被认为是一个合理的做法：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/lrn-fp-go/img/64bb268c-422e-4620-af03-b3a01bf5bad8.png)

我们将`FullName`属性（称谓，`firstName`，`middleName`，`lastName`，后缀）分组在一起，形成`FullName`数据对象。我们还分组地址属性以创建`Address`数据对象。现在，我们可以调用`CreateCustomer`只传递两个属性：

```go
CreateCustomer(fullName, address)
```

具有两个参数的调用比具有八个参数的调用更好：

```go
CreateCustomer(salutation, firstName, middleName, lastName, suffix, street1, street2, city, state, zip)
```

因此，就像世界上的大多数事情一样，正确的做法取决于我们的情况。

你能想到这种方法的问题吗？

这样做不会在`fullName`和地址对象上创建依赖关系吗？

如果在执行`CreateCustomer`函数之后但在完成之前，要么`fullName`要么地址数据对象发生了变化，那么我们会有什么数据不一致？

#### 长参数列表会随时间改变，并且本质上很难理解

这个陈述很有道理。本章的其余部分将阐述这个陈述。我们将探讨如何管理一个可能随时间变化并且可能需要多个参数来获取完成任务所需信息的 API。

如果我们像贝多芬一样构建我们的应用程序，从我们想要实现的一般想法开始，并将我们的程序打磨成形，那么我们可能一开始不知道 API 将需要什么参数。

！[](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/lrn-fp-go/img/98cbeafd-7c81-410c-8526-bda0051b3f8f.png)

一个动作动词

我们如何设计一个需要多个参数的 API，但具有以下特点？

+   提供合理的默认值

+   指示哪些参数是必需的/可选的

+   提供了语言的全部功能来初始化复杂值，而不是通过死结构传递

+   可以随着时间增长

+   安全

+   可发现

+   自我记录

+   高度可配置

传递配置结构怎么样？

就像我们之前看到的`fullName`和地址数据对象一样，传递配置数据对象会创建一个依赖关系。配置对象由“调用者”和函数“被调用者”保留。

如果我们传递指向我们的配置对象的指针，那么如果发生任何变化，无论是调用者还是被调用者，都会使问题复杂化。

### 解决方案

我们正在寻找的解决方案将允许新的构造函数接受可变数量的参数，并具有以下特点：

+   预定义默认值（在没有为特定设置传递参数的情况下）

+   只传递有意义的值

+   利用 Go 编程语言的强大功能来自定义传递的参数值

这种设计的很多思想来自 Rob Pike 的一篇博客文章。

参考 Rob Pike 在他的博客文章中关于自引用函数和选项设计的内容[`commandcenter.blogspot.com/2014/01/self-referential-functions-and-design.html`](https://commandcenter.blogspot.com/2014/01/self-referential-functions-and-design.html)。

为分享返回函数文字的闭包技术点赞，其中我们设置了服务器设置的值。稍后我们将看到这是如何工作的。

！[](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/lrn-fp-go/img/899209bd-10b1-409e-b6d9-4cef3d91a999.jpg)

#### 传递多个参数的三种方法

让我们记住，有三种方法可以将多个参数传递给函数。我们将在接下来的章节中讨论它们。

##### 简单地传递多个参数

在这里，我们向`InitLog`函数传递了四个参数：

```go
func InitLog (
   traceFileName string,
   debugHandler io.Writer,
   infoHandler io.Writer,
   errorHandler io.Writer,
) {
// . . .
}
```

##### 传递包含多个属性的配置对象/结构

在这里，我们传递了`ClientConfig`配置数据对象并打印其值：

```go
func printClientConfig(config *ClientConfig) {
   Info.Printf(" - security params: %v", config.SecurityParams)
   Info.Printf(" - core limit: %v", config.CoreLimit)
   Info.Printf(" - payload config: %v", config.PayloadConfig)
   Info.Printf(" - channel number: %v", config.ClientChannels)
   Info.Printf(" - load params: %v", config.LoadParams)
   // . . .
```

这种方法的一个缺点是我们在调用者和被调用者之间创建了一个依赖关系。如果调用者或调用者系统的其他部分在我们的函数处理时修改了配置对象会怎么样？

有时，就像前面提供的示例一样，可以相当安全地假设配置对象不会改变。在这种情况下，传递配置对象是正确的做法。这样做简单有效，几乎没有变异导致不一致状态的可能性。

但是，如果由于所调用函数内部的额外复杂性而需要修改参数怎么办？来自死结构的静态值无法帮助。

##### 部分应用

我们的第三个选项称为**部分应用**。我们可以通过柯里化来实现这一点。

柯里化的思想是通过部分应用来从其他更一般的函数创建新的更具体的函数。

考虑一下，我们有一个接受两个数字的`add`函数：

```go
func add(x, y int) int {
   return x + y
}
```

我们可以创建另一个函数，它返回带有一个参数预插入的`add`函数。我们将以将任何其他数字加一的简单示例为例：

```go
func addOnePartialFn() func(int) int {
   return func(y int) int {
      return add(1, y)
   }
}
```

调用`add(1,2)`的结果将与调用`addOne(2)`相同：

```go
func main() {
   fmt.Printf("add(1, 2): %d\n", add(1, 2))
   addOne := addOnePartialFn()
   fmt.Printf("addOne(2): %d\n", addOne(2))
}
```

以下是前面代码的输出：

```go
add(1, 2): 3
addOne(2): 3
```

**柯里化**是函数返回一个新的单参数函数，直到原始函数接收到所有参数的能力。

只使用某些参数调用柯里化函数称为**部分应用**。

函数柯里化是一种技术，我们可以使用它将复杂的功能分解成更容易理解的小部分。逻辑的较小单元也更容易测试。我们的应用程序变成了较小部分的清晰组合。

然而，在本章中我们将追求的解决方案将是第一种，也就是，我们将传递所有必需的参数。但是，我们只需要传递必需的参数，并且我们将为未提供的参数使用合理的默认值。

我们如何实现这一点？通过使用函数参数！

## 函数参数

我们将使用`GetOptions()`实用函数，就像我们在之前的章节中使用的那样，并且我们将在我们的 init 函数中调用`GetOptions`和`InitLog`，以便在运行`main`包中的任何命令之前设置我们的配置值和记录器：

```go
package main

import (
   "server"
 . "utils"
 "context"
 "io/ioutil"
 "net/http"
 "os"
 "os/signal"
 "time"
 "fmt"
)

func init() {
   GetOptions()
   InitLog("trace-log.txt", ioutil.Discard, os.Stdout, os.Stderr)
}
```

让我们使用信号`Notify`订阅`SIGINT`信号。现在，我们可以在程序突然停止之前捕获*Ctrl* + *C*事件。我们将创建一个退出通道来保存我们的信号。它只需要有一个大小为 1 的缓冲区。

当我们的`quit`通道接收到`SIGINT`信号时，我们可以开始我们的优雅、有序的关闭过程：

```go
func main() {
   quit := make(chan os.Signal, 1)
   signal.Notify(quit, os.Interrupt)
```

请仔细注意以下代码。这是我们传递函数参数的地方！

```go
newServer, err := server.New(
   server.MaxConcurrentConnections(4),
   server.MaxNumber(256), // Config.MaxNumber
 server.UseNumberHandler(true),
   server.FormatNumber(func(x int) (string, error) { return fmt.Sprintf("%x", x), nil }), 
 //server.FormatNumber(func(x int) (string, error) { return "", errors.New("FormatNumber error") }), // anonymous fcn
)
```

在我们的示例中，我们选择为服务器的`New`构造函数提供四个参数（`MaxConcurrentConnections`、`MaxNumber`、`FormatNumber`和`UseNumberHandler`）。

请注意，参数名称是不言自明的。我们为前三个参数传递了实际的标量值（4、256、true）。我们可以选择使用配置值（`Config.MaxConcurrentConnections`、`Config.MaxNumber`和`Config.UseNumberHandler`）或使用环境变量。我们也可以使用环境变量。我们可能不会为`UseNumberHandler`使用环境变量。大多数情况下，环境变量用于设置可能会在开发、测试、QA 和生产环境中变化的设置，例如`IPADDRESS`和`PORT`。

这是一个处理 Go 环境变量的方便库：

[`github.com/caarlos0/env`](https://github.com/caarlos0/env)

最后一个参数`FormatNumber`接受一个匿名函数来改变数字的显示格式：

```go
server.FormatNumber(func(x int) (string, error) { return fmt.Sprintf("%x", x), nil }) 
```

`fmt.Sprintf`语句中的`%x`参数指示我们的处理程序以二进制格式显示输入的数字。

当用户在其请求中输入数字**2**时，将显示如下内容：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/lrn-fp-go/img/aa6d94bd-da2b-47aa-b2a3-8a3c215ecc79.png)

如果调用`Server.New`失败，则记录错误并退出程序：

```go
if err != nil {
   Error.Printf("unable to initialize server: %v", err)
   os.Exit(1)
}
```

接下来，我们提供运行 HTTP 服务器所需的参数。`Addr`参数是服务器监听的地址。

与其让`http.Server`默认使用`http.DefaultServeMux`来处理请求，我们将我们的`newServer`函数类型变量传递给接受我们自定义的`ServerOption`函数参数的`http.Server`，以自定义其行为：

```go
srv := &http.Server{
   Addr:    ":"+Config.Port,
   Handler: newServer,
}
```

接下来，我们将为匿名函数调用创建一个 Goroutine。

我们的 Goroutine 将等待，直到用户触发`SIGINT`中断（通过在启动服务器的终端会话中按下*Ctrl* + *C*）。此时，“quit”通道将接收到信号。

尽管“上下文”可以用于传递请求范围的变量，但我们只会用它来传递取消信号。我们将在下一节更详细地介绍“上下文”。

当 2 秒截止日期到期或调用返回的`cancel`函数时，`quit`通道将关闭。只要服务器关闭逻辑花费的时间不超过两秒，延迟`cancel()`将被调用；否则，截止日期将关闭`quit`通道。

```go
go func() {
   <-quit
   ctx, cancel := context.WithDeadline(context.Background(), time.Now().Add(2 * time.Second))
   defer cancel()
   Info.Println("shutting down server...")
   if err := srv.Shutdown( ctx ); err != nil {
      Error.Printf("unable to shutdown server: %v", err)
   }
}()
```

对`Shutdown`的调用将停止服务器而不会中断任何活动连接。首先，`Shutdown`关闭打开的监听器，然后关闭空闲连接。如果没有截止日期，它可能会无限期地等待连接返回到空闲状态，然后再关闭它们。

`ListenAndServe`函数在本地主机端口`Config.Port`上监听，并调用 serve 来处理传入连接的请求：

```go
Error.Println("server started at localhost:"+Config.Port)
err = srv.ListenAndServe()
```

此时，我们的服务器将监听请求，我们的终端将如下所示：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/lrn-fp-go/img/5ad4327e-c548-4b7b-9ea9-4ca0a041af18.png)

请注意，我们可以通过将以下内容插入到我们的`main`函数的第一行来将配置信息打印到我们的终端：

```go
Info.Printf("Config %+v", Config)
```

“％+v”中的`+`告诉`Printf`函数打印字段名称以及值。

当我们按下*Ctrl* + *C*时，以下行中的代码会在`quit`通道上向我们的 Goroutine 发出信号：

```go
signal.Notify(quit, os.Interrupt)
```

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/lrn-fp-go/img/aea8c228-dec8-4f6e-ab7c-2ed1ab712c20.png)

`srv.Shutdown`方法运行，然后`main`中的最后一行执行以打印`server shutdown gracefully`。

在深入了解更多关于我们的`func-param`项目代码之前，让我们更仔细地看看 Go 的`Context`包功能。

## 上下文

上下文主要用于跨多个进程和 API 边界的请求。上下文有助于在对象的不同生命周期阶段穿越各种 API 边界进程时维护有关对象状态的背景信息。

这是一个传递“上下文”参数的示例（来自[`blog.golang.org/context`](https://blog.golang.org/context)）：

```go
func httpDo(ctx context.Context, req *http.Request, f func(*http.Response, error) error) error {
    // Run the HTTP request in a goroutine and pass the response to f.
    tr := &http.Transport{}
    client := &http.Client{Transport: tr}
    c := make(chan error, 1)
    go func() { c <- f(client.Do(req)) }()
    select {
    case <-ctx.Done():
        tr.CancelRequest(req)
        <-c // Wait for f to return.
        return ctx.Err()
    case err := <-c:
        return err
    }
 }
```

将“上下文”参数传递给每个请求中的每个函数可以控制跨 API 和进程边界的请求的超时和取消。此外，它有助于确保诸如安全凭据之类的关键值不会在传输中停留的时间超过必要的时间。

第三方库和框架，例如 Gorilla 的（[`github.com/gorilla/context`](http://github.com/gorilla/context)）包，提供了它们的包和接受上下文请求范围参数的其他包之间的桥梁。这提高了在构建可扩展服务时异构包之间的互操作性。

我们将使用应用程序上下文来控制停止我们的服务器。截止日期确保我们的关闭过程不会超过合理的时间（在我们的示例中为 2 秒）。此外，通过发送取消信号，我们为服务器提供了在关闭之前运行其清理过程的机会。

以下是关于我们的“上下文”参数正在发生的情况的说明：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/lrn-fp-go/img/7aab879a-c096-4374-bf09-00882e2709b0.png)

当管理员用户按下*Ctrl* + *C*时，`os.interrupt`会向`quit`（缓冲）通道发出信号。创建了一个截止日期为 2 秒的上下文（ctx）。该上下文参数被发送到`srv.Shutdown`函数，其中执行服务器的清理代码。如果超过 2 秒，那么我们的 Goroutine 将被取消。结果是我们的服务器会优雅地关闭，我们可以确保它不会花费超过 2 秒的时间。

我们可以构建像这样复杂的“上下文”树：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/lrn-fp-go/img/56df5017-1483-4b5f-8870-c52db31d2b8a.png)

然而，在这样做之前，我们应该意识到我们的`Context`限制，接下来我们将讨论这一点。

### 上下文限制

树可以向上遍历，即从子节点到父节点（而不是相反）。

我们应该只使用建议的值，例如，这个用户的本地名称是`en_US`。`en_US`可以用来增强用户体验，但不能改变应用程序的流程。我们不应该存储可能影响`Context`包中控制流的值。

#### 报告示例

作为在`Context`中存储控制流值所导致的影响的一个例子，让我们考虑以下情况：

```go
func Report(ctx context.Context)  {
   reportName, _ := ctx.Value("reportName").(string)
   filter, _ := ctx.Value("filter").(string)
   RunReport(reportName, filter)
}
```

在前面的例子中，我们只传递了上下文作为参数。在我们的`Report`函数内部，我们提取了修改值`reportName`和 filter 的控制流。现在，我们有了`Report`函数需要完成其工作的格式。

为什么有些人认为在内部查询其他对象的方法以获取做出决策所需的数据或养成传递一个充满数据的大模糊对象的习惯，然后在我们的函数内部提取以知道接下来该做什么是一个好主意？

通常最佳实践是传递函数所需的所有参数。这种编码风格创建了自我说明的 API。如果我们发现我们的参数列表变得很大，即超过六个参数，那么我们应该考虑是否应该重构我们的函数。我们的大函数中是否有可重用的代码？也许我们可以创建一个辅助函数并减少我们的参数印记？

不要忘记我们在第四章中讨论的内容，*Go 中的 SOLID 设计*。*(S)ingle Responsibility principle*表明一个类应该只有一个责任。

如果我们传递了大量参数，我们的函数是否可能执行了多个任务？

### 编写良好的代码与踢好一场足球并无二致

简单地进行。传球要干脆而短。有意识地。控制好球。始终保持对球的关注。

观看业余球员，然后观看一位**精英球员**（**EP**）踢球。主要区别是什么？EP 接球有多好？EP 传球有多好？EP 是否将球传到队友的空间中，还是朝着对手球门的方向踢长传球？

移动（到开放空间），接球，然后传球。做得好的球队一直能赢。我们在谈论什么？接口。能够有效地从一个球员传球到另一个球员的球队赢得更多比赛。

我们可以从中学到东西。如果我们努力编写自我说明的 API（移动到开放空间），那么我们的 API 对我们的客户更加可访问。当我们调用的 API 设计类似（尽可能简单，只需要强制参数，具有合理的默认值）时，我们的系统将具有高度的互操作性和效率。

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/lrn-fp-go/img/dad32d2b-040a-4512-805b-64f2f26016e3.png)

皇家马德里，一个了不起的球队，进行组合和传球。我们的 API 应该像视频中的皇家马德里队一样进行互操作[`www.youtube.com/watch?v=b6_IUVBAJJ0`](https://www.youtube.com/watch?v=b6_IUVBAJJ0)。

这是一个典型的用例吗？假设足球是我们的数据/消息，我们何时想要传递消息，避开对手，将 API 端点移动并将其不变地存入目标？

#### 功能参数 - Rowe

观看罗的掷界外球。Kelyn Rowe 对球的处理就像调用者中的功能参数可以做的事情一样。将这种魔术与我们在业余足球中看到的传球或在`Context`中传递死值进行比较。

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/lrn-fp-go/img/f4944efe-2911-4a8a-9961-48c4a403f2f7.png)

Dom Dwyer 在美国队以 1-0 击败巴拿马；请参考此视频[`www.youtube.com/watch?v=CVXPeGhPXkE`](https://www.youtube.com/watch?v=CVXPeGhPXkE)。

#### 报告示例

`Context`中的值会影响应用程序的控制流。让我们重构一下：

```go
RunReport(reportName, filter)
```

在这种情况下，使用`Context`传递值只会混淆我们的意图，并使我们的代码不太可读。在现实世界的应用程序中，我们很难找到`Context`值的一个好用例。

### 一个更实际的上下文使用案例

一个更实际的`Context`使用案例是向长时间运行的函数发送`Cancel`消息。

在处理数据库事务时，会想到几种用例。

在某些情况下，一个请求可能会生成多个子请求，每个请求运行的时间和消耗的资源各不相同。如果在我们的数据库事务期间，其中一个子请求发生恐慌，我们可以使用`Context`来发出取消所有例程的信号，并释放所有与事务相关的资源：

```go
import (
   "database/sql"
 "github.com/pkg/errors"
)
```

提供对`sql.DB`提交和回滚的访问：

```go
type Transaction interface {
   Commit() error
   Rollback() error
}
```

`TxFunc`参数是提供给`db.WithTransaction`函数的一个功能参数。它将在数据库事务的上下文中执行给定的函数。如果发生错误，则事务将被回滚：

```go
type TxFunc func(tx Transaction) error
```

Db 使用`sql.DB`实现来访问`Begin`和`Commit`事务：

```go
type Dbms struct {
   db *sql.DB
}
```

`WithTransaction`函数是一个提供`Transaction`接口的函数，可以用于在事务中执行 SQL 操作。如果函数返回错误，则事务将被回滚：

```go
func (s Dbms) WithTransaction(fn TxFunc) error {
   var tx         Transaction
   var isCommitted bool
   var err        error
```

开始事务：

```go
tx, err = s.db.Begin()
if err != nil {
   return errors.Wrap(err, "error starting transaction")
}
```

如果事务期间发生错误，则回滚：

```go
defer func() {
   if isCommitted != true {
      tx.Rollback()
   }
}()
```

执行在事务中执行 SQL 操作的函数。

看到`fn(tx)`函数了吗？

这就是我们的函数参数被执行的地方。这就是真正的工作执行的地方。这是执行执行 SQL 查询的逻辑的地方。它在事务的上下文中执行。因此，如果任何查询或子查询失败，整个事务将被回滚：

```go
if err = fn(tx); err != nil {
   return errors.Wrap(err, "error in TxFunc")
}
```

提交事务并将`isCommitted`设置为 true 以指示成功：

```go
    if err = tx.Commit(); err != nil {
      return errors.Wrap(err, "error committing transaction")
   }
   isCommitted = true
 return nil
}
```

我们已经完成了对上下文的查看。现在，回到功能参数解决方案...

#### src/server/server.go

我们可以浏览导入以了解我们将在这个文件中做些什么。我们将处理一些 HTTP 请求，将一些 JSON 转换字符串转换为整数，处理错误，并为我们的服务器实现一个日志记录器：

```go
package server

import (
   "encoding/json"
 "fmt"
 "github.com/pkg/errors"
 "log"
 "net/http"
 "os"
 "strconv"
)
```

我们将定义三个常量，并在定义默认值时使用它们：

```go
const (
   defaultServerMaxMessageSize = 1024 * 1024 * 4
 defaultMaxNumber = 30
 defaultMaxConcurrentConnections = 2
)

var defaultServerOptions = options {
   maxMessageSize:          defaultServerMaxMessageSize,
   maxNumber:               defaultMaxNumber,
   maxConcurrentConnections:  defaultMaxConcurrentConnections,
}
```

我们的`Server`结构有三个字段：

```go
type Server struct {
   logger  Logger
   opts options
   handler http.Handler
}
```

这是`Logger`类型：

```go
type Logger interface {
   Printf(format string, v ...interface{})
}
```

我们使用处理程序提供`ServeHTTP`，这是一个响应 HTTP 请求的`Handler`：

```go
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
   s.handler.ServeHTTP(w, r)
}
```

新的是我们的服务器构造函数。`New`是一个可变函数，接收类型为`ServerOption`的任意数量的功能参数。

请注意，`opt`参数是`ServerOption`类型的可变参数。

我们返回一个指向我们新创建的`Server`对象的指针和惯用的`error`值：

```go
func New(opt ...ServerOption) (*Server, error) {
```

首先，我们使用默认值预填充我们的选项：

```go
   opts := defaultServerOptions
```

然后，我们遍历每个`ServerOption`。以下是`ServerOption`的签名。我们看到我们使用它来定义接受指向选项的函数类型变量：

```go
type ServerOption func(*options) error
```

如果发现错误，我们会将错误包装起来返回并退出这个函数：

```go
   for _, f := range opt {
      err := f(&opts)
      if err != nil {
         return nil, errors.Wrap(err, "error setting option")
      }
   }   
```

在这里，我们创建了我们的`Server`变量，并用功能参数(`opts`)以及一个`logger`填充它：

```go
   s := &Server{
      opts:  opts,
      logger: log.New(os.Stdout, "", 0),
   }
   s.register()
   return s, nil
}
```

在返回调用之前，我们的服务器的`register`方法与我们的 HTTP 多路复用器（mux）一起。mux 将传入的 URL 请求与注册的模式进行匹配，并调用最接近请求的 URL 的模式的处理程序。

这是`register`方法：

```go
func (s *Server) register() {
   mux := http.NewServeMux()
   if s.opts.useNumberHandler {
      mux.Handle("/", http.HandlerFunc(s.displayNumber))
   } else {
      mux.Handle("/", http.FileServer(http.Dir("./")))
   }
   s.handler = mux
}
```

请注意，我们使用`useNumberHandler`选项来确定与我们的根路径"`/`"关联的处理程序。

这是一个虚构的 mux 示例，用于说明服务器选项的用法。在生产中，您可能更好地使用诸如[`github.com/gorilla/mux`](https://github.com/gorilla/mux)和[`github.com/justinas/alice`](https://github.com/justinas/alice)这样的包，以及[`golang.org/pkg/net/http/`](https://golang.org/pkg/net/http/)。

如果`s.opts.useNumberHandler`为`true`，那么 mux 将调用`http.HandlerFunc`函数，并将`displayNumber`函数作为其唯一的函数参数传递。

`displayNumber`函数在一个 HTTP 中使用了一些服务器选项来确定如何处理`request:handler`：

```go
func (s *Server) displayNumber(w http.ResponseWriter, r *http.Request) {
   s.logger.Printf("displayNumber called with number=%s\n", r.URL.Query().Get("number"))
   if numberParam := r.URL.Query().Get("number"); numberParam != "" {
      number, err := strconv.Atoi(numberParam)
      if err != nil {
         writeJSON(w, map[string]interface{}{
            "error": fmt.Sprintf("invalid number (%v)", numberParam),
         }, http.StatusBadRequest)
      }
```

在以下代码块中，我们将用户输入的数字与`maxNumber`服务器选项值进行比较。如果输入值大于最大值，我们显示错误消息；否则，我们继续处理：

```go
      if number > s.opts.maxNumber {
         writeJSON(w, map[string]interface{}{
            "error": fmt.Sprintf("number (%d) too big. Max number: %d", number, s.opts.maxNumber),
         }, http.StatusBadRequest)
      } else {
```

如果没有转换函数（`convertFn`），那么我们将要显示的数字（`displayNumber`）设置为用户输入的值。

但是，如果定义了`convertFn`，我们将数字传递给它，执行它，并将返回值赋给`displayNumber`：

```go
         var displayNumber string
         if s.opts.convertFn == nil {
            displayNumber = numberParam
         } else {
            displayNumber, err = s.opts.convertFn(number)
         }        
```

看看我们如何在`main()`中使用函数文字与`fmt.Sprintf`命令来影响显示的数字？

```go
server.FormatNumber(func(x int) (string, error) { return fmt.Sprintf("%x", x), nil }),
```

要以十六进制格式查看我们的数字，我们将在浏览器中输入以下内容到地址栏：`http://localhost:8080/?number=255`：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/lrn-fp-go/img/48c67ccc-29e5-4d74-ab0e-4a2ae7f3cca9.png)

想以不同的格式看`displayNumber`吗？如果是：在终端控制台中输入*Ctrl* + *C*停止应用程序。在`main.go`中，将`fmt.Sprintf("%x", x)`更改为`fmt.Sprintf("%b", x)`，然后输入`go-run`命令重新启动应用程序。

```go
server.FormatNumber(func(x int) (string, error) { return fmt.Sprintf("%b", x), nil }),
```

当我们回到我们的网络浏览器并刷新时，我们会看到我们的数字 255 以二进制格式显示：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/lrn-fp-go/img/5447be32-88c9-4b52-a5aa-d0c94d05ad63.png)

如果我们注释掉`server.FormatNumber`参数，我们将得到用户输入的未经格式化的数字：

```go
//server.FormatNumber . . .  <= comment out FormatNumber parameter
```

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/lrn-fp-go/img/820bcbad-1664-4d32-b794-b1099e3b13a3.png)

参考以下资源以获取更多的`Sprintf`选项 [`lexsheehan.blogspot.com/search?q=octal+hex+printf`](http://lexsheehan.blogspot.com/2015/02/fmtprintf-format-reference.html)。

如果有错误，我们将显示它。如果没有错误，我们将显示我们的（可能经过格式化的）数字：

```go
         if err != nil {
            writeJSON(w, map[string]interface{}{
               "error": "error running convertFn number",
            }, http.StatusBadRequest)
         } else {
            writeJSON(w, map[string]interface{}{
               "displayNumber": displayNumber,
            })
         }
      }
   } else {
      writeJSON(w, map[string]interface{}{
         "error": "missing number",
      }, http.StatusBadRequest)
   }
}
```

我们将要检查的最后一个项目文件包含我们的`ServerOption`函数。

#### src/server/server_options.go 文件

我们将使用 Go 标准库的 errors 包，因为我们只是想创建一个错误对象：

```go
package server

import (
   . "utils"
 "errors"
)
```

我们定义了一个`ServerOption`类型来简化我们的函数签名：

```go
type ServerOption func(*options) error
```

柯里化允许函数产生新的函数作为它们的返回值。`MaxNumber`正在这样做吗？`MaxNumber`是一个函数，并返回一个`ServerOption`。`SeverOption`是一个函数。所以，是的。我们在这里进行了柯里化。

我们的第一个`ServerOption`函数是`MaxNumber`。它有一个简单的职责：将其参数（`n`）的值分配给我们选项的`maxNumber`字段：

```go
func MaxNumber(n int) ServerOption {
   return func(o *options) error {
      o.maxNumber = n
      return nil
   }
}
```

请注意，`MaxNumber`是一个返回错误的函数。由于在此函数中不可能发生错误，我们只是返回 nil。

其他`ServerOption`函数可能更复杂，我们可能会在其中一些非平凡的函数中遇到错误条件，并且需要返回一个错误。

`MaxConcurrenConnections`函数有一个条件语句，如下所示：

```go
func MaxConcurrentConnections(n int) ServerOption {
   return func(o *options) error {
      if n > Config.MaxConcurrentConnections {
         return errors.New("error setting MaxConcurrentConnections")
      }
      o.maxConcurrentConnections = n
      return nil
   }
}
```

接下来的两个函数提供了格式化我们输入数字的能力。

`convert`类型是一个接受 int 并返回 string 和可能的错误的函数类型：

```go
type convert func(int) (string, error)
```

`FormatNumber`函数是另一个`ServerOption`。与其他接受标量输入值的函数不同，`FormatNumber`接受类型为`convert`的函数参数：

```go
func FormatNumber(fn convert) ServerOption {
   return func(o *options) (err error) {
      o.convertFn = fn
      return
 }
}
```

让我们再看一下`main()`，在那里调用了`FormatNumber`：

```go
server.FormatNumber(func(x int) (string, error) { return fmt.Sprintf("%x", x), nil }),
```

`FormatNumber`函数的参数作为函数参数传递。它是一个满足转换函数类型签名的匿名函数：

```go
type convert func(int) (string, error)
```

该函数接受一个`int`并返回一个字符串和一个错误。

`FormatNumber`只有一个语句——返回语句。它在执行转换函数（fn）后返回一个`ServerOption`函数。

不要被这样一个事实所困惑，即我们知道转换函数接收一个 int，但在匿名返回函数中我们看不到它：`o.convertFn = fn`。

代码行`o.convertFn = fn`由`main()`执行；当它运行时，创建了`newServer`值：

```go
newServer, err := server.New( . . .
```

它所做的是将`fn`函数分配给`convertFn`函数的`SeverOption`值：

```go
func New(opt ...ServerOption) (*Server, error) {
   opts := defaultServerOptions
   for _, f := range opt {
      err := f(&opts)
```

直到用户提交请求并且该请求由`displayNumber`函数处理时，才执行以下行：

```go
displayNumber, err = s.opts.convertFn(number)
```

这就是`int`数字实际传递给`convertFn`函数的地方。

最后一个`ServerOption`函数是`UserNumberHandler`。它很简单，很像`MaxNumber`：

```go
func UseNumberHandler(b bool) ServerOption {
   return func(o *options) error  {
      o.useNumberHandler = b
      return nil
   }
}
```

## 总结

Go 是使用函数式编程和面向对象编程世界中的好思想设计的。例如，Go 从面向对象编程世界借鉴了接口、鸭子类型和组合优于继承的概念，从函数式编程世界借鉴了函数作为一等公民的概念。

Go 是实用主义的完美例子。Go 吸收了面向对象编程和函数式编程范式中更好的原则，同时明显地忽略了许多思想。也许，这种完美平衡的设计是使 Go 如此特别的原因？从这个角度看，Go 是软件语言的完美比例。

有关黄金比例的讨论，请参阅第十一章，*适用的范畴论*。

在下一章中，我们将更深入地探讨纯函数式编程。我们将看到如何利用范畴论和类类型来抽象细节以获得新的见解。我们将研究函子以及稍微更强大和更有用的函子的版本，称为应用函子。您还将学习如何使用单子和幺半群控制副作用世界。


# 第八章：使用管道提高性能

通常，我们感到需要处理一些数据并将其传递到一系列步骤中，在到达目的地之前沿途对其进行转换。我们经常在现实生活场景中遇到这种过程，特别是在工厂装配线环境中。

在本章中，我们将看到如何使用管道模式来构建基于组件的应用程序。我们将看到如何使用函数组合数据流编程技术来创建灵活的解决方案，这些解决方案不仅健壮，而且在当今的分布式处理环境中也具有高性能。

我们在本章的目标是：

+   能够确定何时使用管道模式

+   学习如何构建管道

+   了解如何利用缓冲来增加吞吐量

+   使用 Goroutines 和通道更快地处理数据

+   使用接口提高 API 可读性

+   实现有用的过滤器

+   构建灵活的管道

+   查看更改过滤器顺序并提交无效数据时会发生什么

## 介绍管道模式

管道软件设计模式用于数据流经过一系列阶段的情况，其中前一阶段的输出是下一阶段的输入。每个步骤都可以被视为一种过滤操作，以某种方式转换数据。在过滤器之间经常实现缓冲，以防止死锁或当一个过滤器比连接到它的另一个过滤器运行得更快时发生数据丢失。将过滤器连接到管道中类似于函数组合。

以下图表描述了数据从数据源（例如文件）流过滤器直到最终在控制台上的标准输出中显示的流程：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/lrn-fp-go/img/a8ba339a-0300-4012-8a27-280779c6fc81.png)

### Grep 排序示例

`/etc/group`文件是数据源。Grep 是第一个过滤器，其输入是来自`/etc/group`文件的所有行。`grep`命令删除所有不以`"com"`开头的行，然后将其输出发送到 Unix 管道，该管道将数据发送到`sort`命令：

```go
$ grep "^com" /etc/group | sort com.apple.access_disabled:*:396: com.apple.access_ftp:*:395: com.apple.access_screensharing:*:398: com.apple.access_sessionkey:*:397: com.apple.access_ssh:*:399:
```

让我们明确一点。我们在本章中涵盖的行为类似于 Unix 管道，但我们将研究的是使用 Go 实现的管道，主要使用 Go 通道和 Goroutines。同样，我们不会讨论 Go Pipes（[`golang.org/pkg/os/#Pipe`](https://golang.org/pkg/os/#Pipe)），除了它们是无缓冲的、无结构的字节流。

### 管道特性

管道模式提供了许多有价值的优点，这些优点在正确设计的应用程序中是可取的；这些优点如下：

+   提供了一个处理数据的系统结构

+   将任务分解为顺序步骤

+   封装每个步骤的过滤器

+   独立的过滤器（独立运行）具有一组输入和输出

+   数据通过管道单向传递

+   可配置的模块化（读取、写入、拆分和合并操作）

+   高内聚，过滤器逻辑是自包含的

+   低耦合，过滤器通过连接管道进行通信

+   批处理和在线处理之间的区别消失

管道模式具有许多特点，使其在各种用例中都很有吸引力。我们看到它在技术中的应用范围从持续集成和部署管道到批处理和流数据处理。如果需要以装配线方式处理数据流，那么我们应该考虑使用这种管道模式。

让我们来看看优势：

+   **可扩展性**：向管道添加另一个过滤器

+   **灵活性**：通过连接过滤器进行函数组合

+   **性能**：利用多处理器系统

+   **可测试性**：易于分析、评估和测试管道过滤器系统

与任何模式一样，我们必须考虑其潜在问题。

以下是一些缺点：

+   潜在的数据转换开销

+   潜在的死锁和缓冲区溢出

+   如果基础设施丢失了过滤器之间流动的数据，可能会出现潜在的可靠性问题

+   如果过滤器在向下游发送结果后失败，但在成功完成处理之前指示失败，则可能需要重新处理数据（在管道中设计过滤器为幂等）

+   潜在的大上下文，因为每个过滤器必须提供足够的上下文来执行其工作

以下是一些高级用例，如果适用，使得这种管道模式成为一个有吸引力的设计解决方案候选：

+   处理要求可以分解为一组独立的步骤

+   过滤器操作可以利用多核处理器或分布式计算

+   每个过滤器都有不同的可扩展性要求

+   必须容纳处理步骤的重新排序的系统

### 示例

现在，让我们看一些示例，以帮助理解这种管道模式的价值和适用性。

#### 网站订单处理

以下图示了订单从网站显示订单表单到用户的流程。沿途的过滤器执行各种任务，如解密请求有效载荷，验证用户凭据，向客户信用卡收费，发送确认电子邮件给客户，最后显示感谢页面。

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/lrn-fp-go/img/3164bd3c-f56b-47f9-a36d-43f5ca76cd34.png)

#### 老板工人模式

在老板工人模式中，**老板**过滤器将数据推送到处理数据并将结果合并到**产品**中的工作人员：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/lrn-fp-go/img/4e2256fb-62d4-484e-a677-2699938dbd25.png)

#### 负载均衡器

以下示例显示了一个**负载均衡器**，它接收来自客户端的请求并将其发送到具有最小积压和最可用于处理请求信息包的服务器：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/lrn-fp-go/img/641536af-3cf2-4026-8356-fffa971bad36.png)

#### 数据流类型

数据流类型可以被视为**读取**、**分割**、**合并**和**写入**操作：

| **过滤器类型** | **图像** | **接收** | **发送** | **描述** |
| --- | --- | --- | --- | --- |
| **读取** | ![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/lrn-fp-go/img/581df9d3-ea69-4bba-b5fd-98816201ed16.png) |  | ![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/lrn-fp-go/img/e065c36e-7b8c-472b-b2df-22c69774644d.png) | **读取**过滤器从数据源读取数据并将信息包发送到下游。 |
| **分割** | ![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/lrn-fp-go/img/beb61560-0dff-4ba2-9537-2ed634a6c356.png) | ![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/lrn-fp-go/img/e065c36e-7b8c-472b-b2df-22c69774644d.png) | ![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/lrn-fp-go/img/e065c36e-7b8c-472b-b2df-22c69774644d.png)![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/lrn-fp-go/img/e065c36e-7b8c-472b-b2df-22c69774644d.png) | 多个函数从同一通道读取，直到该通道关闭。通过将工作分配给一组工作人员以并行化 CPU 使用，可以提高性能。 |
| **转换** | ![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/lrn-fp-go/img/906ea89c-b1e8-400a-9abf-f37907bf6d16.png) | ![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/lrn-fp-go/img/e065c36e-7b8c-472b-b2df-22c69774644d.png) | ![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/lrn-fp-go/img/e065c36e-7b8c-472b-b2df-22c69774644d.png) | 这个过滤器从上游接收数据，对其进行转换，然后发送到下游。 |
| **合并** | ![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/lrn-fp-go/img/b3515be9-b909-4b4a-a4bd-f256d0697213.png) | ![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/lrn-fp-go/img/e065c36e-7b8c-472b-b2df-22c69774644d.png)![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/lrn-fp-go/img/e065c36e-7b8c-472b-b2df-22c69774644d.png) | ![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/lrn-fp-go/img/e065c36e-7b8c-472b-b2df-22c69774644d.png) | 这个函数从多个输入通道读取数据，然后将其发送到一个通道，当所有输入都关闭时，该通道也关闭。工作可以分配给多个 Goroutines，它们都从同一个输入通道读取。 |
| **写入** | ![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/lrn-fp-go/img/9f22ce75-8545-450e-a029-0f3e09e1cb25.png) | ![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/lrn-fp-go/img/e065c36e-7b8c-472b-b2df-22c69774644d.png) |  | 这个过滤器从上游接收数据并将其写入到汇聚处。 |

##### 基本构建块

这些是基于流的编程系统的基本构建块。有了这些基本操作，我们可以构建任何基于组件的系统：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/lrn-fp-go/img/8b2a5616-80dd-4653-b1e9-cc4658fbf4c1.png)

基于流的编程是一种组件化的编程模型，它将应用程序定义为一组异步处理操作（又名过滤器）的网络，这些操作交换具有定义的生命周期、命名端口和连接的结构化信息包流（[`en.wikipedia.org/wiki/Stream_(computing)`](https://en.wikipedia.org/wiki/Stream_(computing))）。

#### 通用业务应用程序设计

以下图表描述了一个通用业务应用程序的组件组成图，该应用程序处理输入请求并将请求路由到后端服务器。随后处理、处理和返回服务器的响应。存在一些需要重新路由或重新处理的响应的备用数据流：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/lrn-fp-go/img/74baa648-b3ea-4ec7-9eb3-ac89c57c0342.png)

请注意，只要其输入和输出集相同，每个操作都可以被交换，而不会影响数据流或应用程序的整体操作。

## 示例实现

既然我们看到了管道模式的价值，让我们开始规划一个 Go 实现。

在 Go 中，管道是使用一系列通过 Go 通道连接的阶段实现的。Go 管道以数据源（又名生产者）开始，具有通过通道连接的阶段，并以数据接收端（又名消费者）结束。

数据源可以是一个生成器函数，它将数据发送到第一个阶段，然后关闭初始出站通道。

管道中的每个过滤器（步骤或阶段）：

+   由一个或多个 Goroutines 组成，运行相同的函数（又名过滤器）

+   通过一个或多个入站通道接收上游数据

+   以某种方式转换数据

+   通过一个或多个出站通道向下游发送数据

+   当所有发送操作完成时，关闭其出站通道

+   保持从入站通道接收值，直到这些通道关闭

示例转换函数包括以下内容：

+   累加器

+   聚合器

+   Delta（用于计算资源的两个样本数据点之间的变化）

+   算术

示例数据接收端包括以下内容：

+   文件存储（例如，NFS 和 CIFS/SMB 协议访问 NAS 或 DAS）

+   消息代理（例如，Kafka、NATS 和 RabbitMQ）

+   数据库（例如，PostgreSQL、MongoDB 和 DynamoDB）

+   云存储（例如，S3、OpenStack Swift 和 Ceph）

### 命令式实现

让我们从管道的最简单形式开始我们的编码示例，当然，这是使用命令式编程风格实现的。

#### 解密、认证、收费流程图

我们将基于以下流程图进行编码示例：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/lrn-fp-go/img/ae1c9d2f-d295-494b-8b17-ad4d5d8c8567.png)

我们将从阶段到阶段传递订单数据，直到整个过程完成。订单数据可以在途中进行转换，例如，当**解密**步骤将信用卡号转换为明文时。我们将把每个阶段或步骤称为过滤器。在我们的示例中，每个过滤器将从上游接收一个订单并将一个订单发送到下游。流是单向的。它从数据源开始，经过**解密**过滤器，然后到**认证**过滤器，最后到**收费信用卡**过滤器：

```go
package main

import (
       "fmt"  gc "github.com/go-goodies/go_currency" )
```

我们将导入`go_currency`包，它将帮助我们处理订单行项目中的价格：

```go
type Order struct {
       OrderNumber int
       IsAuthenticated bool
       IsDecrypted bool
       Credentials string
       CCardNumber string
       CCardExpDate string
       LineItems []LineItem
}
type LineItem struct {
       Description string
       Count       int
       PriceUSD    gc.USD
}
```

`GetOrders()`函数将是我们的订单生成数据源。请注意，信用卡号以加密格式存储。我们需要稍后解密它们以便收取信用卡费用：

```go
func GetOrders() []*Order {

       order1 := &Order{
              10001,
              false,
              false,
              "alice,secret",
              "7b/HWvtIB9a16AYk+Yv6WWwer3GFbxpjoR+GO9iHIYY=",
              "0922",
              []LineItem{
              LineItem{"Apples", 1, gc.USD{4, 50}},
              LineItem{"Oranges", 4, gc.USD{12, 00}},
              },
       }
```

请注意，我们的信用卡号已加密，最后一个字段是`LineItem`结构的切片：

```go
        order2 := &Order{
              10002,
              false,
              false,
              "bob,secret",
              "EOc3kF/OmxY+dRCaYRrey8h24QoGzVU0/T2QKVCHb1Q=",
              "0123",
              []LineItem{
                     LineItem{"Milk", 2, gc.USD{8, 00}},
                     LineItem{"Sugar", 1, gc.USD{2, 25}},
                     LineItem{"Salt", 3, gc.USD{3, 75}},
              },
       }
       orders := []*Order{order1, order2}
       return orders
}
```

在我们的示例中，我们只处理两个订单。我们将它们作为`Order`结构的切片从`GetOrders()`函数返回。

我们调用`GetOrder()`函数来生成我们的订单。接下来，我们遍历我们的订单，依次通过我们的订单处理管道运行每个订单：

```go
func main() {
       orders := GetOrders()
       for _, order := range orders {
              fmt.Printf("Processed order: %v\n", Pipeline(*order))
       }
}
```

我们的管道有三个步骤。每个步骤都是一个我们将称之为过滤器的函数。我们的订单通过三个顺序过滤器进行处理：

```go
func Pipeline(o Order) Order {
       o = Authenticate(o)
       o = Decrypt(o)
       o = Charge(o)
       return o
}
```

以下是输出：

```go
Order 10001 is Authenticated
Order 10001 is Decrypted
Order 10001 is Charged
Processed order: {10001 true alice,secret 7b/HWvtIB9a16AYk+Yv6WWwer3GFbxpjoR+GO9iHIYY= 0922 [{Apples 1 4.50} {Oranges 4 12.00}]}
Order 10002 is Authenticated
Order 10002 is Decrypted
Order 10002 is Charged
Processed order: {10002 true bob,secret EOc3kF/OmxY+dRCaYRrey8h24QoGzVU0/T2QKVCHb1Q= 0123 [{Milk 2 8.00} {Sugar 1 2.25} {Salt 3 3.75}]}
```

由于我们从最简单的示例开始，在每个过滤器中都输出了正在发生的过滤器动作，并且我们在这个简单的示例中将订单传递了下去，而没有以任何方式对其进行转换：

```go
func Authenticate(o Order) Order  {
       fmt.Printf("Order %d is Authenticated\n", o.OrderNumber)
       return o
}

func Decrypt(o Order) Order {
       fmt.Printf("Order %d is Decrypted\n", o.OrderNumber)
       return o
}

func Charge(o Order) Order {
       fmt.Printf("Order %d is Charged\n", o.OrderNumber)
       return o
}
```

这是管道的基本思想。我们接收一个数据包，例如一个订单，并将其从一步传递到另一步，其中每一步都是具有特定专业性的过滤器函数。数据可以在途中进行转换，并且沿着一条方向从数据源到终点，即结束处理的地方。

### 并发实现

为了提高性能，我们应该考虑并发运行。Go 语言有一些并发构造，我们可以使用：Goroutines 和 channels。让我们试试：

```go
func main() {
       input := make(chan Order)
       output := make(chan Order)

       go func() {
              for order := range input {
                     output <- Pipeline(order)
              }
       }()

       orders := GetOrders()
       for _, order := range orders {
              fmt.Printf("Processed order: %v\n", Pipeline(*order))
       }
       close(input)
}
```

我们为我们的管道创建了一个输入通道和一个输出通道。

接下来，我们创建了一个立即可执行的 Goroutine 函数。请注意 Goroutine 块末尾的括号：`}()`。直到我们在主函数的最后一行关闭输入通道之前，这个 Goroutine 不会退出。

我们生成一个订单，就像在我们的命令式示例中一样。然后，我们通过将下一个订单传递给管道来处理每个订单。

输出与命令式示例相同，但运行速度较慢。因此，我们降低了性能并增加了代码复杂性。我们可以做得更好。

### 缓冲实现

让我们尝试使用输入/输出缓冲区。

在下图中，管道的每个阶段都从其输入缓冲区读取并写入其输出缓冲区。例如，**解密**过滤器从其输入缓冲区读取，来自数据源，并写入其输出缓冲区：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/lrn-fp-go/img/9ddbc0de-b007-4794-ab6b-88901d9a9605.png)

由于有两个订单，缓冲区大小为两。由于并发队列的缓冲区共享输入和输出，如果有四个订单，那么管道中的所有过滤器都可以同时执行。如果有四个 CPU 核心可用，那么所有过滤器都可以并发运行。

只要其输出缓冲区有空间，管道的一个阶段就可以将其产生的值添加到其输出队列中。如果输出缓冲区已满，新值的生产者将等待直到空间可用。

过滤器可以阻塞，等待订单到达其输入缓冲区，或者直到其输入通道被关闭。

缓冲区可以有效地用于一次容纳多个订单，这可以弥补每个过滤器处理每个订单所需时间的变化。

在最理想的情况下，管道沿线的每个过滤器将以大致相同的时间处理其输入订单。然而，如果**解密**过滤器处理订单的时间远远长于**认证**过滤器，**认证**过滤器将被阻塞，等待**解密**将解密后的订单发送到其输入缓冲区。

以下是我们如何修改我们的程序以包含缓冲通道：

```go
func main() {
       orders := GetOrders()
       numberOfOrders := len(orders)
       input := make(chan Order, numberOfOrders)
       output := make(chan Order, numberOfOrders)
       for i := 0; i < numberOfOrders; i++ {
              go func() {
                     for order := range input {
                            output <- Pipeline(order)
                     }
              }()
       }
       for _, order := range orders {
              input <- *order
       }
       close(input)
       for i := 0; i < numberOfOrders; i++ {
              fmt.Println("The result is:", <-output)
       }
}
```

以下是输出：

```go
Order 10001 is Authenticated
Order 10001 is Decrypted
Order 10001 is Charged
Order 10002 is Authenticated
Order 10002 is Decrypted
Order 10002 is Charged
The result is: {10001 true alice,secret 7b/HWvtIB9a16AYk+Yv6WWwer3GFbxpjoR+GO9iHIYY= 0922 [{Apples 1 4.50} {Oranges 4 12.00}]}
The result is: {10002 true bob,secret EOc3kF/OmxY+dRCaYRrey8h24QoGzVU0/T2QKVCHb1Q= 0123 [{Milk 2 8.00} {Sugar 1 2.25} {Salt 3 3.75}]}
```

这很棒，对吧？通过添加缓冲通道，我们提高了性能。我们的解决方案可以同时在多个核心上并发运行过滤器。

这很好，但如果我们处理大量订单怎么办？

#### 利用所有 CPU 核心

我们可以通过可用的 CPU 核心数量增加缓冲区的数量：

```go
func main() {
       orders := GetOrders()
       numberOfOrders := len(orders)
       cpus := runtime.NumCPU()
       runtime.GOMAXPROCS(cpus)
       input := make(chan Order, cpus)
       output := make(chan Order, cpus)
       for i := 0; i < numberOfOrders; i++ {
              go func() {
                     for order := range input {
                            output <- Pipeline(order)
                     }
              }()
       }
       for _, order := range orders {
              input <- *order
       }
       close(input)
       for i := 0; i < numberOfOrders; i++ {
              fmt.Println("The result is:", <-output)
       }
}
```

使用 I/O 缓冲区是对我们设计的改进，但实际上有更好的解决方案。

### 改进的实现

让我们再次看看我们的订单处理管道：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/lrn-fp-go/img/050180d4-ba4a-40a3-bc59-4d2f2f328d4e.png)

现在，让我们使用更接近实际生活的例子来实现**解密，认证**和**信用卡扣款**过滤器。

`Order`和`LineItem`结构将保持不变，`GetOrders()`生成器也将保持不变。

#### 导入

我们有更多的导入。我们将使用`go_utils`的`Dashes`函数来对信用卡号进行匿名化。此外，我们将导入许多`crypto`包来解密信用卡号：

```go
package main

import (
       "log"  "fmt"  gc "github.com/go-goodies/go_currency"  gu "github.com/go-goodies/go_utils"  "strings"  "crypto/aes"  "crypto/cipher"  "crypto/rand"  "encoding/base64"  "errors"  "io"  "bytes" )
```

#### BuildPipeline

我们有一个新的函数`BuildPipeline()`，它接受一系列过滤器，并使用每个过滤器的输入和输出通道将它们连接起来。`BuildPipeline()`函数铺设了管道，从数据源开始，到终点，也就是`Charge`过滤器：

```go
func main() {
       pipeline := BuildPipeline(Authenticate{}, Decrypt{}, Charge{})
```

#### 立即可执行的 Goroutine

接下来，是立即可执行的 Goroutine，它迭代生成的订单，并将每个订单发送到该过滤器的输入：

```go
go func(){
       orders := GetOrders()
       for _, order := range orders {
              fmt.Printf("order: %v\n", order)
              pipeline.Send(*order)
       }
       log.Println("Close Pipeline")
       pipeline.Close()
}()
```

当所有订单都被发送到管道中时，是时候关闭管道的输入通道了。

#### 接收订单

接下来，我们执行管道的`Receive()`函数，等待订单到达输出通道，然后打印订单：

```go
        pipeline.Receive(func(o Order){
              log.Printf("Received: %v", o)
       })
}
```

以下是输出：

```go
order: &{10001 true alice,secret 7b/HWvtIB9a16AYk+Yv6WWwer3GFbxpjoR+GO9iHIYY= 0922 [{Apples 1 4.50} {Oranges 4 12.00}]}
order: &{10002 true bob,secret EOc3kF/OmxY+dRCaYRrey8h24QoGzVU0/T2QKVCHb1Q= 0123 [{Milk 2 8.00} {Sugar 1 2.25} {Salt 3 3.75}]}
Credit card XXXXXXXXXXXX1111 charged 16.50
Credit card XXXXXXXXXXXX5100 charged 14.00
2017/03/08 03:05:36 Close Pipeline
2017/03/08 03:05:36 Received: {10001 true alice,secret 4111111111111111 0922 [{Apples 1 4.50} {Oranges 4 12.00}]}
2017/03/08 03:05:36 Received: {10002 true bob,secret 5105105105105100 0123 [{Milk 2 8.00} {Sugar 1 2.25} {Salt 3 3.75}]}
```

#### Filterer 接口

我们的管道 API 是围绕`Filterer`接口构建的：

```go
type Filterer interface {
       Filter(input chan Order) chan Order
}
```

#### Filterer 对象

Filterer 对象有一个方法`Filter`，它具有类型为`Order`的输入通道，并返回类型为`Order`的输出通道：

！[](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/lrn-fp-go/img/524bf1d3-8f54-4431-acd1-da49e4472a9b.png)

我们定义类型来充当`Filter`执行的接收器。在管道中遇到的第一个过滤器是 Authenticate 过滤器。以下 Authenticate 过滤器有一个输入参数，类型为`Order`通道，并返回一个类型为`Order`通道的单个值。

#### 认证过滤器

我们的认证逻辑是硬编码的和简单的，即不是我所说的生产就绪。密码`secret`对于任何用户名都有效。如果`Authenticate`在`Credentials`字段中遇到`secret`，订单将不变地流向管道中的下一步。但是，如果密码不是`secret`，那么订单的`isValid`字段将被设置为`false`。管道中后续过滤器的行为可能会受到这个值的影响：

```go
type Authenticate struct {}
func (a Authenticate) Filter(input chan Order) chan Order {
       output := make(chan Order)
       go func(){
              for order := range input {
                     usernamePwd := strings.Split(order.Credentials, ",")
                     if usernamePwd[1] == "secret" {
                            order.IsAuthenticated = true
                            output <- order
                     } else {
                            order.IsAuthenticated = false
                            errMsg := fmt.Sprintf("Error: Invalid password for order Id: %d", order.OrderNumber)
                            log.Println("Error:", errors.New(errMsg))
                            output <- order
                     }
              }
              close(output)
       }()
       return output
}
```

#### 解密过滤器

以下`Decrypt`过滤器有一个输入参数，类型为`Order`通道，并返回一个类型为`Order`通道的单个值：

```go
type Decrypt struct {}
func (d Decrypt) Filter(input chan Order) chan Order {
       output := make(chan Order)
       go func(){
              for order := range input {
                     creditCardNo, err := decrypt(order.CCardNumber)
                     if err != nil {
                            order.IsDecrypted = false
                            log.Println("Error:", err.Error())
                     } else {
                            order.IsDecrypted = true
                            order.CCardNumber = creditCardNo
                            output <- order
                     }
              }
```

请注意，我们通过记录错误来处理错误。即使我们被告知当它从源头到达时，`IsDecrypted`字段值总是 false，如果我们遇到错误，我们也会安全地设置`order.IsDecrypted = false`。

只有在订单有效时我们才处理此订单。如果解密函数失败，订单可能无效，请参考前面的代码。订单也可能在流程的前一步中无效，例如，如果订单的`Authenticate`过滤器失败。

##### 完整处理

当此过滤器的处理完成时，我们关闭其输出通道：

```go
               close(output)
       }()
       return output
}
```

##### ChargeCard 辅助函数

`ChargeCard`函数是`Charge`过滤器使用的辅助函数，用于收取订单中的信用卡号。这个实现只是简单地打印信用卡已经被收取。这是一个真实的信用卡收费逻辑的良好占位符：

```go
func ChargeCard(ccardNo string, amount gc.USD) {
       fmt.Printf("Credit card %v%v charged %v\n", gu.Dashes(len(ccardNo)-4, "X"), ccardNo[len(ccardNo)-4:], amount)
}
```

#### 收费过滤器

与 API 中的所有其他过滤器一样，`Charge`接受类型为`Order`的输入通道，并返回类型为`Order`的输出通道。

如果订单有效，我们使用`total := gc.USD{0, 0}`语句将总额初始化为$0.00，并迭代订单的行项目，执行`Add`函数以得到订单的总金额。然后我们将该金额传递给`ChargeCard`辅助函数来收取我们的钱：

```go
type Charge struct {}
func (c Charge) Filter(input chan Order) chan Order {
       output := make(chan Order)
       go func(){
              for order := range input {
                     if order.IsAuthenticated && order.IsDecrypted {
                            total := gc.USD{0, 0}
                            for _, li := range order.LineItems {
                                   total, _ = total.Add(li.PriceUSD)
                            }
                            ChargeCard(order.CCardNumber, total)
                            output <- order
                     } else {
                            errMsg := fmt.Sprintf("Error: Unable to charge order Id: %d", order.OrderNumber)
                            log.Println("Error:", errors.New(errMsg))
                     }
              }
              close(output)
       }()
       return output
}
```

#### 加密和解密辅助函数

以下代码中的`decrypt`辅助函数被`Decrypt`过滤器使用。我们还有`encrypt`辅助函数，虽然不在我们的管道中，但可以很好地加密纯文本和用于测试目的。

`decrypt`函数接受加密的字符串值。`aes.NewCipher`接受我们的 32 字节长 AES 加密密钥并返回一个 AES-256 密码块，该密码块传递给`NewCBCDecrypter`。`NewCBCDecrypter`函数还接受一个初始化向量（`iv`），它用于在密码块链接模式下解密块。它的`CryptBlocks`函数用于解密值，`RightTrim`用于切掉尾随的`\x00`。哇！我们得到了我们的解密字符串值：

```go
var AESEncryptionKey = "a very very very very secret key"  func encrypt(rawString string) (string, error) {
       rawBytes := []byte(rawString)
       block, err := aes.NewCipher([]byte(AESEncryptionKey))
       if err != nil {
              return "", err
       }
       if len(rawBytes)%aes.BlockSize != 0 {
              padding := aes.BlockSize - len(rawBytes)%aes.BlockSize  padText := bytes.Repeat([]byte{byte(0)}, padding)
              rawBytes = append(rawBytes, padText...)
       }
       ciphertext := make([]byte, aes.BlockSize+len(rawBytes))
       iv := ciphertext[:aes.BlockSize]
       if _, err := io.ReadFull(rand.Reader, iv); err != nil {
              return "", err
       }
       mode := cipher.NewCBCEncrypter(block, iv)
       mode.CryptBlocks(ciphertext[aes.BlockSize:], rawBytes)
       return base64.StdEncoding.EncodeToString(ciphertext), nil
}
func decrypt(encodedValue string) (string, error) {
       block, err := aes.NewCipher([]byte(AESEncryptionKey))
       if err != nil {
              return "", err
       }
       b, err := base64.StdEncoding.DecodeString(encodedValue)
       if err != nil {
              return "", err
       }
       if len(b) < aes.BlockSize {
              return "", errors.New("ciphertext too short")
       }
       iv := b[:aes.BlockSize]
       b = b[aes.BlockSize:]
       if len(b)%aes.BlockSize != 0 {
              return "", errors.New("ciphertext is not a multiple of the block size")
       }
       mode := cipher.NewCBCDecrypter(block, iv)
       mode.CryptBlocks(b, b)
       b = bytes.TrimRight(b, "\x00")
       return string(b), nil
}
```

### 测试应用程序如何处理无效数据

让我们看看我们的应用程序如何处理坏数据。

#### 无效信用卡密文

请注意已附加到加密信用卡号值的 XXX：

```go
func GetOrders() []*Order {

       order1 := &Order{
              10001,
              true,
              "alice,secret",
              "7b/HWvtIB9a16AYk+Yv6WWwer3GFbxpjoR+GO9iHIYY=XXX",
              "0922",
              []LineItem{
                     LineItem{"Apples", 1, gc.USD{4, 50}},
                     LineItem{"Oranges", 4, gc.USD{12, 00}},
              },
       }
```

以下是输出：

```go
2017/03/08 04:23:03 Error: illegal base64 data at input byte 44
2017/03/08 04:23:03 Close Pipeline
2017/03/08 04:23:03 Received: {10002 true bob,secret 5105105105105100 0123 [{Milk 2 8.00} {Sugar 1 2.25} {Salt 3 3.75}]}
order: &{10001 true alice,secret 7b/HWvtIB9a16AYk+Yv6WWwer3GFbxpjoR+GO9iHIYY=XXX 0922 [{Apples 1 4.50} {Oranges 4 12.00}]}
order: &{10002 true bob,secret EOc3kF/OmxY+dRCaYRrey8h24QoGzVU0/T2QKVCHb1Q= 0123 [{Milk 2 8.00} {Sugar 1 2.25} {Salt 3 3.75}]}
Credit card XXXXXXXXXXXX5100 charged 14.00
```

具有无效信用卡号的订单未完全处理。请注意日志中的错误消息。

#### 无效密码

请注意已附加到凭据字段值的 XXX：

```go
func GetOrders() []*Order {

       order1 := &Order{
              10001,
              false,
              "alice,secretXXX",
              "7b/HWvtIB9a16AYk+Yv6WWwer3GFbxpjoR+GO9iHIYY=",
              "0922",
              []LineItem{
                     LineItem{"Apples", 1, gc.USD{4, 50}},
                     LineItem{"Oranges", 4, gc.USD{12, 00}},
              },
       }
```

以下是输出：

```go
order: &{10001 false alice,secretXXX 7b/HWvtIB9a16AYk+Yv6WWwer3GFbxpjoR+GO9iHIYY= 0922 [{Apples 1 4.50} {Oranges 4 12.00}]}
2017/03/08 04:49:30 Close Pipeline
order: &{10002 false bob,secret EOc3kF/OmxY+dRCaYRrey8h24QoGzVU0/T2QKVCHb1Q= 0123 [{Milk 2 8.00} {Sugar 1 2.25} {Salt 3 3.75}]}
2017/03/08 04:49:30 Error: Error: Invalid password for order Id: 10001
Credit card XXXXXXXXXXXX5100 charged 14.00
2017/03/08 04:49:30 Received: {10002 true bob,secret 5105105105105100 0123 [{Milk 2 8.00} {Sugar 1 2.25} {Salt 3 3.75}]}
```

具有无效密码的订单未完全处理。请注意日志中的错误消息。

#### 更改身份验证和解密过滤器的顺序

以前，订单是`Decrypt{}，Authenticate{}，Charge{}`：

```go
func main() {
       pipeline := BuildPipeline(Authenticate{}, Decrypt{}, Charge{})
```

以下是输出：

```go
order: &{10001 false alice,secret 7b/HWvtIB9a16AYk+Yv6WWwer3GFbxpjoR+GO9iHIYY= 0922 [{Apples 1 4.50} {Oranges 4 12.00}]}
2017/03/08 04:52:46 Close Pipeline
order: &{10002 false bob,secret EOc3kF/OmxY+dRCaYRrey8h24QoGzVU0/T2QKVCHb1Q= 0123 [{Milk 2 8.00} {Sugar 1 2.25} {Salt 3 3.75}]}
2017/03/08 04:52:46 Received: {10001 true alice,secret 4111111111111111 0922 [{Apples 1 4.50} {Oranges 4 12.00}]}
Credit card XXXXXXXXXXXX1111 charged 16.50
2017/03/08 04:52:46 Received: {10002 true bob,secret 5105105105105100 0123 [{Milk 2 8.00} {Sugar 1 2.25} {Salt 3 3.75}]}
Credit card XXXXXXXXXXXX5100 charged 14.00
```

有所不同。在这两种情况下，两张发票都已完全处理。

#### 在解密信用卡号和身份验证之前尝试收费

我们首先构建了我们的函数管道：Charge，Decrypt 和 Authenticate。

```go
func main() {
       pipeline := BuildPipeline(Charge{}, Decrypt{}, Authenticate{})
```

以下是输出：

```go
order: &{10001 false alice,secret 7b/HWvtIB9a16AYk+Yv6WWwer3GFbxpjoR+GO9iHIYY= 0922 [{Apples 1 4.50} {Oranges 4 12.00}]}
order: &{10002 false bob,secret EOc3kF/OmxY+dRCaYRrey8h24QoGzVU0/T2QKVCHb1Q= 0123 [{Milk 2 8.00} {Sugar 1 2.25} {Salt 3 3.75}]}
2017/03/08 04:58:27 Error: Error: Unable to charge order Id: 10001
2017/03/08 04:58:27 Error: Error: Unable to charge order Id: 10002
2017/03/08 04:58:27 Close Pipeline
```

#### 在身份验证之前尝试收费

这里也没有什么意外。如果我们在身份验证请求之前尝试收费信用卡，收费将不会被处理：

```go
func main() {
       pipeline := BuildPipeline(Decrypt{}, Charge{}, Authenticate{})
```

以下是输出：

```go
2017/03/08 05:10:32 Close Pipeline
2017/03/08 05:10:32 Error: Error: Unable to charge order Id: 10001
2017/03/08 05:10:32 Error: Error: Unable to charge order Id: 10002
order: &{10001 false false alice,secret 7b/HWvtIB9a16AYk+Yv6WWwer3GFbxpjoR+GO9iHIYY= 0922 [{Apples 1 4.50} {Oranges 4 12.00}]}
order: &{10002 false false bob,secret EOc3kF/OmxY+dRCaYRrey8h24QoGzVU0/T2QKVCHb1Q= 0123 [{Milk 2 8.00} {Sugar 1 2.25} {Salt 3 3.75}]}
```

### 进一步阅读

整本书都可以写关于管道模式的主题。

本章未涵盖的一些主题，但您应该自行研究的包括以下内容：

+   设计和实现`Split`和`Merge`过滤器

+   了解`sync.WaitGroup`类型如何帮助您管理通道通信的同步

+   将分支和条件工作流模式添加到管道中

好的阅读：*Go 并发模式：管道和取消*（[`blog.golang.org/pipelines`](https://blog.golang.org/pipelines)）和*Go 示例：通道*（[`gobyexample.com/channels`](https://gobyexample.com/channels)）

## 总结

构建具有高内聚性和低耦合性的应用程序是软件工程的主要目标。在本章中，我们探讨了管道模式，并学习了如何使用**基于流的编程**（**FPB**）技术构建基于组件的系统。我们研究了适用于应用管道模式的 FPB 模式和用例。

我们研究了一个订单处理流程的示例。我们从命令式实现逐步过渡到使用 Goroutines 和通道的并发实现。我们学习了如何有效地使用 I/O 缓冲区来同时保存多个订单，以及如何弥补每个过滤器处理每个订单所需时间的变化。

我们的最后一个实现是对之前尝试的改进。我们基于`Filterer`接口创建了一个优雅的 API。我们能够使用这个命令定义和控制整个订单处理流程：

```go
pipeline := BuildPipeline(Decrypt{}, Charge{}, Authenticate{})
```

最后，我们实施了各种 FPB 错误处理技术并测试了它们的有效性。

在下一章中，我们将看到另一种用于提高性能的技术：懒惰。


# 第九章：函数对象，幺半群和泛型

"这是我在 Go 中尝试函数式编程。我认为这是一个好主意，但我真的不确定。"

我在超过十几篇博客文章上看到了这样的评论。我希望在阅读完本章并完成示例后，你会对函数式编程（FP）有一种新的热爱。不是因为它是如此纯净，以至于你担心有副作用的编程会把你送到地狱，而是因为你对构成纯 FP 基础的概念感到舒适，并且你看到它的好处超过了学习如何使用它的成本。

本章的目标如下：

+   欣赏 Go 中泛型支持的缺失可能是一件好事

+   学习如何使用泛型代码生成工具来解决样板问题

+   深入理解函数组合是如何工作的

+   构建一些函数对象，并了解如何在不同领域之间进行映射

+   构建一些幺半群，并学习如何编写自己的 reduce 函数

## 理解函数对象

函数对象是范畴之间保持结构的变换。换句话说，函数对象是可映射的类型。让我们通过一个例子来看看这意味着什么。

### 命令式与纯函数式的例子

假设我们从一个 int 切片开始，`ints := []int{1,2,3}`。

在命令式编程中，我们编写所有的脚手架代码来准确实现如何处理这个 int 切片。然而，在纯函数式编程中，我们告诉我们的函数对象我们希望循环做什么：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/lrn-fp-go/img/bb333e07-c020-4551-a72f-6f87db47d65b.jpg)

这是输出：

```go
imperative loop: [2 3 4]
fp map: [2 3 4]
```

让我们看看这是如何工作的。

#### 那个 Map 函数为我们做了什么？

`Map`函数抽象了循环。我们不必再写相同的 range/for 循环代码。我们只需传入我们原始的`ints`列表，并告诉我们的函数对象将该切片映射为一个每个元素比以前大一的切片。这很像 SQL，我们声明我们想要的数据，让数据库引擎去担心如何获取数据。

#### 这能给我们带来什么可能的好处？

我们是否必须更改我们的 SQL 查询代码以从数据库引擎更新中受益，从而提高查询性能？答案是否定的，对于我们的纯函数式编程代码也是一样的。

如果我们只需要编写`Functor(list).Map(add1)`并定义我们自定义的`add1`函数呢？如果`Functor`是 Go 标准库的一部分（或者是另一个非常稳定的第三方包），并且如果 Go 的下一个版本发布了，并且它知道如何根据我们传递的列表的大小来优化性能，那不是仅仅编译使用最新版本的 Go（或者其他非常稳定的第三方包）就能获得的自动的显著的好处吗？

从代码行数或者清晰度来看，这可能并不是一个巨大的胜利。在这种情况下，以及在较小的实用程序或管理程序中，它可能并不会带来很大的好处。在我看来，使用 FP 风格提供最大好处的地方是业务用例逻辑。我们寻找需要小心谨慎地不要用嘈杂的代码（如 for 循环脚手架和错误检查代码块）混淆业务意图的地方。这些都是 FP 风格编程的绝佳场所。其他好的地方是我们希望在不担心竞态条件或副作用的情况下横向扩展我们的应用程序。

### 一个神奇的结构

函数对象可以被看作是一个神奇的结构，可以被映射，其中神奇的结构可以被看作是一个形状，带有一组恒定的元素，并伴随着对每个元素应用变换操作的能力。

让我们看一些例子。

#### 颜色块函数对象

一个函数对象由一个结构组成，通常是 Go 中的一个切片，以及一个变换操作，即映射函数：

| **结构** | 八个块，每个填充有不同的颜色 |
| --- | --- |
| **变换操作** | `f(x) = x - 30`，其中`x`是色调 |

下面是一个函子，它将八个彩色块映射到八个相应的块，其颜色经过上面的转换操作调整色调。

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/lrn-fp-go/img/7001a6f6-694a-4b8b-b94a-8166e7ebf186.png)

前面的图表显示了一个单个**f(x)**箭头，以保持最小的混乱，但更准确的表示应该显示从每个原始元素到其相应的新转换元素的箭头。这实际上是发生的--每个元素在结构内被处理，并转换为一个新值，该值返回到结构内：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/lrn-fp-go/img/cf666dbf-d617-46f4-b833-058bb997d673.png)

#### 手指乘以 10 的函子

如前所述，函子由结构和转换操作组成：

| **结构** | 五个手指，每个手指代表一个整数 |
| --- | --- |
| **转换操作** | `f(x) = x * 10` |

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/lrn-fp-go/img/573afd21-9780-4895-b8d5-926181d3aa15.png)

从上一章我们知道，一个类别包括以下内容：

+   对象的分组

+   **对象**：点/点/没有属性和结构的原始物体

+   **态射（箭头）**：连接两个对象/元素的东西

你能看到对象（每个手指上的数字）吗？

你能看到映射关系吗（1 对应 10，2 对应 20，3 对应 30，依此类推）？

我们的类别在乘法下是封闭的，有一个单位元，并且有一个映射函数（乘以 10），这意味着我们有一个函子。看到了吗？

这是一个保持形状的映射，从一个类别映射到另一个类别；因此，函子被称为类别同态。**f(x)**说明了函子是两个类别之间的函数。

数手指（函子）更多地证明了我们真正需要知道的一切都是在幼儿园里教的！

### Haskell 中函子的定义

在上一章的类型类层次结构图中，我们已经看到了一个**函子**。函子只有一个类型类方法，`fmap`，它的类型是`fmap :: (a -> b) -> f a -> f b`。它说--给我一个接受`a`并返回`b`的函数，一个包含`a`的结构，我会给你一个包含`b`的结构。该函数应用于结构内的每个元素。`fmap`函数转换结构内的值。

我们可以互换使用以下术语：

+   结构

+   容器

+   盒子

要记住的重要一点是，函子作用于结构/容器/盒子内部的元素，并返回具有转换值的结构（而不是原始值）。

### 类型的种类

Haskell 中的函子必须具有 kind `* -> *`。Kinds 是 Haskell 中具体类型之上的另一层类型。Kinds 允许我们定义类型的行为能力，然后将它们与适当的类型类连接起来。例如，一个**Int**可以像可显示的、可读的、有序的或可枚举的东西一样。Haskell 中的值可以根据它们的类型进行分类。让我们使用 Haskell 的简洁语法来看一些例子：

| **类型（类）** | **__ 种 __  ** | **描述** |
| --- | --- | --- |
| **Int** | `*` | `*`代表具体类型（如 Bool、Char 或 Int）。 |
| **Char** | `*` | `*`代表具体类型（如 Bool、Char 或 Int）。 |
| **[]** | `* -> *` | []接受一种类型的 kind `*`，并返回一种新的 kind `*`的类型。 |
| **Maybe** | `* -> *` | 一种高级类型，接受一种 kind `*`的类型，并返回一种新的 kind `*`的类型。 |
| **Either** | `* -> * -> *` | 一种高级类型，接受一种 kind `*`的类型，并返回一种新的 kind `*`的类型，或者返回一种新的 kind `*`的类型。 |
| **函子** | `(* -> *) ->` 约束 | 函子是一个类型类，而不是一种类型。我们定义了作为函子的高阶类型的行为，它接受一种`*`并将其映射到另一种`*`。约束指的是函子必须遵守其代数中定义的规则。约束强制执行某种限制。例如，数值约束可能限制所有数值类型的值都是数值的。123 通过，但"ABC"对于数值约束失败。 |

#### 也许

**Maybe**是一个函子，将每种类型映射到具有额外的`Nothing`值的相同类型。`Maybe`就像一个可选值（注意，类型是我们类别中的对象）：

`data Maybe a = Just a | Nothing`

`Maybe Int`的值可以是一个数字，比如`Just 2`，也可以是`Nothing`。

`Maybe`类型将类型映射到类型。例如，它将**Char**映射到**Maybe Char**。在下面的代码片段中定义的`fmap`显示了每个`a -> b`函数都有一个对应的版本，`Maybe a -> Maybe b`，当给定`Nothing`时只返回`Nothing`，否则正常运行：

```go
instance Functor Maybe where
fmap f Nothing = Nothing
fmap f (Just x) = Just (f x)
```

### 更高级别的多态性

Haskell 丰富的类型特性（类型类、参数化代数数据类型、递归数据类型等）使我们能够在比 Go 当前可能的更高级别上实现多态性。

在 Go 中实现多态行为是可能的。但是，由于语言限制（缺乏泛型），需要额外的代码来指定实现所需行为的每种类型。

有关 Golang 代码示例，演示如何利用结构和方法来获得多态行为，请参阅[`l3x.github.io/golang-code-examples/2014/07/15/polymorphic-shapes.html`](http://l3x.github.io/golang-code-examples/2014/07/15/polymorphic-shapes.html)。

### 没有泛型会导致大量的样板代码

没有泛型的支持，当我们为应用程序需要的每种类型实现列表函数时，我们必须为每种类型都实现它。这是大量重复的样板代码。例如，如果我们必须为`int8`、`int32`、`float64`和`complex128`实现`Sum`函数，它可能看起来像这样：

```go
package main

import (
   "fmt"
)

func int8Sum(list []int8) (int8) {
   var result int8 = 0
 for x := 0; x < len(list); x++ {
      result += list[x]
   }
   return result
}

func int32Sum(list []int32) (int32) {
   var result int32 = 0
 for x := 0; x < len(list); x++ {
      result += list[x]
   }
   return result
}

func float64Sum(list []float64) (float64) {
   var result float64 = 0
 for x := 0; x < len(list); x++ {
      result += list[x]
   }
   return result
}

func complex128Sum(list []complex128) (complex128) {
   var result complex128 = 0
 for x := 0; x < len(list); x++ {
      result += list[x]
   }
   return result
}

func main() {
   fmt.Println("int8Sum:", int8Sum([]int8 {1, 2, 3}))
   fmt.Println("int32Sum:", int32Sum([]int32{1, 2, 3}))
   fmt.Println("float64Sum:", float64Sum([]float64{1, 2, 3}))
   fmt.Println("complex128Sum:", complex128Sum([]complex128{1, 2, 3}))
}
```

以下是输出：

```go
int8Sum: 6
int32Sum: 6
float64Sum: 6
complex128Sum: (6+0i)
```

使用泛型，我们只需要实现一个类似以下的`Sum`函数。`<T>`是我们传递给`Sum`的任何类型的占位符，支持`+`运算符：

```go
func Sum(list []<T>) (<T>) {
   var ret <T> = 0
   for item := range list {
      ret += item
   }
   return ret
}
```

不用编写所有那些重复的样板代码会很好。还有其他选择吗？

是的。我们可以在任何地方使用空的`interface{}`，并执行反射和类型转换来从列表结构中提取数据并将其放回通用的`interface{}`，但这不是高性能的，而且会增加很多额外的代码。

## 用元编程解决泛型缺失问题

**元编程**（**MP**）是关于编写编写代码的代码。在 MP 中，我们编写将程序视为输入数据的程序。我们的 MP 将读取、分析、转换和生成代码。

也许我们可以使用 MP 来修复 Go 中由于不支持泛型而缺失的部分？

也许。首先，让我们更好地了解 MP 是关于什么的。

以下是一些示例：

+   词法分析器、解析器、解释器和编译器

+   **领域特定语言**（**DSL**）

+   **面向方面的编程**（**AOP**）

+   属性（.NET）

+   注解（Java）

+   泛型（.NET，Java）

+   模板（C++）

+   宏（C）

+   method_missing（Ruby）

+   反射（Go，C#，Ruby）

有几种类型的 MP。

支持`eval`函数的程序可以通过连接表示可执行命令的字符串来生成新代码。注意：这可能会带来安全风险，通常不是最佳实践。

一些语言，如 LISP，可以根据状态信息更改其自己的应用程序代码，这提供了在运行时做出新决策的灵活性。

其他静态类型的语言，比如 C++，有能力评估表达式并做出编译时决策，生成可以静态编译到最终可执行文件中的代码。这是我们将在下一节中看到的 MP 类型。

反射是一种 MP 形式，程序可以观察和修改自己的结构和行为，比如确定指针引用的数据类型或返回对象的所有属性列表。

Go 语言不支持宏或泛型，因此看起来我们必须使用反射。反射允许我们的程序操作那些在编译时类型未知的对象。

例如，我们可以使用空的`interface{}`创建一个项目的链表。这将允许我们在列表中放入任何类型的数据。当我们从列表中取出一个项目时，我们必须使用类型断言为其分配一个数据类型以便使用它。问题在于这不是一个类型安全的操作，它使用起来很麻烦，而且速度很慢。使用反射通常不是最佳实践。一些可能的用例包括以下内容（这些都不能帮助我们实现泛型）：

+   调用函数

+   识别接口

+   验证字段

有关 Go 语言中反射的更多信息，请参阅以下信息：

[golang.org/pkg/reflect/](http://golang.org/pkg/reflect/)

[blog.golang.org/laws-of-reflection](http://blog.golang.org/laws-of-reflection)

[blog.ralch.com/tutorial/golang-reflection/](http://blog.ralch.com/tutorial/golang-reflection/)

[blog.gopheracademy.com/birthday-bash-2014/advanced-reflection-with-go-at-hashicorp/](http://blog.gopheracademy.com/birthday-bash-2014/advanced-reflection-with-go-at-hashicorp/)

如果我们不应该使用反射，那么我们如何解决这种重复的样板代码问题呢？

## 泛型代码生成工具

我们如何不写所有那些重复的代码，又不会受到性能损失，也不会失去我们强类型语言的类型安全性呢？

让我们看看使用 Go 工具来为我们生成样板代码。我们将用它来用<T>替换我们代码中的`interface{}`。这里，<T>代表在其被发现的上下文中工作的任何类型。

由于我们将使用真实类型，我们将获得编译时类型安全性。

### clipperhouse/gen 工具

尽管有几种泛型代码生成工具可用，让我们来看看我个人最喜欢的 clipperhouse/gen。

我们可以使用 clipperhouse/gen 工具免费获得以下函数：

| **聚合** | **过滤** | **映射** | **其他** |
| --- | --- | --- | --- |
| [Aggregate[T]](https://clipperhouse.github.io/gen/slice/#aggregatet) | [All](https://clipperhouse.github.io/gen/slice/#all) | [Select[T]](https://clipperhouse.github.io/gen/slice/#selectt) | [List](https://clipperhouse.github.io/gen/optional/#list) |
| [Average](https://clipperhouse.github.io/gen/slice/#average) | [Any](https://clipperhouse.github.io/gen/slice/#any) | [Where](https://clipperhouse.github.io/gen/slice/#where) | [Ring](https://clipperhouse.github.io/gen/optional/#ring) |
| [Average[T]](https://clipperhouse.github.io/gen/slice/#averaget) | [Distinct](https://clipperhouse.github.io/gen/slice/#distinct) |  | [Set](https://clipperhouse.github.io/gen/optional/#set) |
| [Count](https://clipperhouse.github.io/gen/slice/#count) | [DistinctBy](https://clipperhouse.github.io/gen/slice/#distinctby) |  | [stringer](https://clipperhouse.github.io/gen/stringer/#) |
| [Max](https://clipperhouse.github.io/gen/slice/#max) | [First](https://clipperhouse.github.io/gen/slice/#first) |  |  |
| [Max[T]](https://clipperhouse.github.io/gen/slice/#maxt) | [GroupBy[T]](https://clipperhouse.github.io/gen/slice/#groupbyt) |  |  |
| [MaxBy](https://clipperhouse.github.io/gen/slice/#maxby) | [Shuffle](https://clipperhouse.github.io/gen/slice/#shuffle) |  |  |
| [Min](https://clipperhouse.github.io/gen/slice/#min) | [Sort](https://clipperhouse.github.io/gen/slice/#sort) |  |  |
| [Min[T]](https://clipperhouse.github.io/gen/slice/#mint) | [SortBy](https://clipperhouse.github.io/gen/slice/#sortby) |  |  |
| [MinBy](https://clipperhouse.github.io/gen/slice/#minby) |  |  |  |

`gen`是一个用于 Go 的代码生成工具。它旨在为您的类型提供类似泛型的功能。开箱即用，它提供了 LINQ/underscore 风格的方法。

+   [`github.com/clipperhouse/gen`](https://github.com/clipperhouse/gen)

+   [`en.wikipedia.org/wiki/Language_Integrated_Query`](https://en.wikipedia.org/wiki/Language_Integrated_Query)

+   [`en.wikipedia.org/wiki/Underscore.js`](https://en.wikipedia.org/wiki/Underscore.js)

使用 gen 工具，我们将获得大部分泛型的好处，而不会受到反射或类型断言的性能损失。

泛型为我们做的事情很像代码生成。在运行时，当我们将类型为`A`的`a`传递给函数时，我们的函数可以接受`a`并执行正确的操作，这似乎是神奇的。大多数情况下在运行时（由 JIT 或常规 Go 编译器，取决于情况），Go 进行代码生成替换操作。在运行时发生的是我们的`a`在我们的代码中被换入/换出 A 形状的空白。这是我们的泛型代码生成工具将用来为我们生成通用代码的相同模式：

```go
"List <A>".Replace("<A>", a)
```

我们将使用我们的泛型生成工具来替换适合 T 形空白的任何类型：

```go
"List <T>".Replace("<T>", "Foo")
"List <T>".Replace("<T>", "Bar")
```

我们可以使用我们的 gen 工具在开发时生成代码。它为我们生成代码，就像 IDE 可能会做的那样。

我们使用**注释**中的**注释**标记我们的类型，以便我们想要为其生成代码。

让我们通过一个例子来工作。首先，让我们进入正确的目录，并通过源 init 脚本，运行 glide-update，并将 gen 拉入我们的 vendors 目录来初始化我们的 Go 环境。

这是我们使用的命令列表：

```go
cd <DEVDIR>/fp-go/4-purely-functional/ch11-functor-monoid/03_generics_cars
. init
glide-update
go get github.com/clipperhouse/gen
```

这是我们在运行`gen`之前的目录结构：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/lrn-fp-go/img/71ef883b-c503-4457-ae04-1e836013159e.png)

这是我们运行`gen`后的目录结构：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/lrn-fp-go/img/dc46692b-f53c-4fb9-8087-295c00a04762.jpg)

现在，让我们看看我们项目中的代码在`src/car/types.go`中：

```go
package car

// +gen slice:"Where,Sum[Dollars],GroupBy[string],Select[Dollars]"
type Car struct {
   Make string
   Model string
   Price Dollars
}

type Dollars int
```

你看到了`// +gen slice:"Where,Sum[Dollars],GroupBy[string],Select[Dollars]`的注释吗？它告诉我们的 gen 工具生成一个`Car`的切片，并为我们提供以下方法：

+   `CarSlice.Where`

+   `CarSlice.SelectDollars`

+   `CarSlice.SumDollars`

当我们在带有`types.go`的目录中运行 gen 时，gen 将生成一个名为**src/cars/car_slice.go**的文件，其中包含以下内容：

```go
// Generated by: gen
// TypeWriter: slice
// Directive: +gen on Car

package car

// CarSlice is a slice of type Car. Use it where you would use []Car.
type CarSlice []Car

// Where returns a new CarSlice whose elements return true for func. See: http://clipperhouse.github.io/gen/#Where
func (rcv CarSlice) Where(fn func(Car) bool) (result CarSlice) {
   for _, v := range rcv {
      if fn(v) {
         result = append(result, v)
      }
   }
   return result
}

// SumDollars sums Car over elements in CarSlice. See: http://clipperhouse.github.io/gen/#Sum
func (rcv CarSlice) SumDollars(fn func(Car) Dollars) (result Dollars) {
   for _, v := range rcv {
      result += fn(v)
   }
   return
}

// GroupByString groups elements into a map keyed by string. See: http://clipperhouse.github.io/gen/#GroupBy
func (rcv CarSlice) GroupByString(fn func(Car) string) map[string]CarSlice {
   result := make(map[string]CarSlice)
   for _, v := range rcv {
      key := fn(v)
      result[key] = append(result[key], v)
   }
   return result
}

// SelectDollars projects a slice of Dollars from CarSlice, typically called a map in other frameworks. See: http://clipperhouse.github.io/gen/#Select
func (rcv CarSlice) SelectDollars(fn func(Car) Dollars) (result []Dollars) {
   for _, v := range rcv {
      result = append(result, fn(v))
   }
   return
}
```

因此，gen 为我们生成了所有那些样板代码。这使我们的源文件保持整洁。如果 Go 支持泛型，我们的代码将类似于与 gen 一起使用的代码。有多相似？让我们看看。

这是我们的`main.go`文件：

```go
package main

import (
   "fmt"
 . "car"
)

func main() {
   var cars = CarSlice{
      Car{"Honda", "Accord", 3000},
      Car{"Lexus", "IS250", 40000},
      Car{"Toyota", "Highlander", 3500},
      Car{"Honda", "Accord ES", 3500},
   }
   fmt.Println("cars:", cars)
```

以下是输出：

```go
Output:cars: [{honda accord 3000} {lexus is250 40000} {toyota highlander 3500} {honda accord es 3500}]
```

看到`CarSlice`类型了吗？那是 gen 为我们创建的。我们必须键入实际的结构类型，比如`Car`，gen 将为我们创建`CarSlice`类型和我们在注释中告诉它为我们生成的所有方法（就在类型定义的上面）。

#### 如果 Go 支持泛型

如果 Go 支持泛型，同一段代码块可能会如下所示：

```go

   var cars = Slice<Car>{
      Car{"Honda", "Accord", 3000},
      Car{"Lexus", "IS250", 40000},
      Car{"Toyota", "Highlander", 3500},
      Car{"Honda", "Accord ES", 3500},
   }
   fmt.Println("cars:", cars)
```

从懒惰程序员的角度来看，如果 Go 支持泛型，我们将不得不键入两个额外的字符，`<`和`>`。

看起来泛型代码支持的最大特性刚刚被中和了。当我们考虑这些信息以及我们通过 gen 免费获得的函数，以及性能损失保证会在编译时发生（而不是运行时），这使得 Go 对泛型的直接支持看起来像是一个好处，或者至少是一个不那么严重的问题。

##### 添加新方法

如果我们想要为我们的`CarSlice`添加 gen 不提供的方法，我们可以将这些方法放在一个单独的文件中。我们需要记住的是不要将我们的任何源代码键入 gen 生成的文件中。这是因为我们的代码将在下次我们告诉 gen 运行时被覆盖。

##### 定义一个`filter`函数

在我们的`main.go`文件中的几行下面，让我们定义一个`filter`函数，它将返回`Make`为`Honda`的汽车。我们使用我们的新`Where`方法，并将其传递给我们的`honda`文字函数：

```go
honda := func (c Car) bool {
   return c.Make == "Honda"
}
fmt.Println("filter cars by 'Honda':", cars.Where(honda))
```

这是输出：

```go
filter cars by 'honda': [{honda accord 3000} {honda accord es 3500}]
```

很酷。接下来，让我们创建一个映射函数来返回价格字段：

```go
price := func (c Car) Dollars {
   return c.Price
}
fmt.Println("Hondas prices:", cars.Where(honda).SelectDollars(price))
```

这是输出：

```go
hondas prices: [3000 3500]
```

由于我们已经按照本田进行了筛选，结果只包含本田汽车的价格。

聚合？当然，我们可以进行聚合。让我们调用我们在注释中免费获得的`SumDollars`函数：

```go
fmt.Println("Hondas sum(prices):", cars.Where(honda).SumDollars(price))
```

这是输出：

```go
hondas sum(prices): 6500
```

### Nums 重访

还记得我们为四种数字类型实现了`Sum`方法而不使用泛型吗？让我们重新访问一下那段代码，看看我们是否可以改进我们的代码库，现在我们知道了 gen：

```go
cd <DEVDIR>/fp-go/4-purely-functional/ch11-functor-monoid/04_generics_nums
. init
glide-update
```

请注意，我们需要运行 glide-update，以便为我们创建供应商目录。它将首先放在我们的 GOPATH 中，这样当我们运行下一个命令时，gen 包及其依赖项将放在我们的供应商目录中，而不是我们项目的 src 目录中：

```go
go get github.com/clipperhouse/gen
```

现在，让我们 cd 到**~/dev/04_generics_nums/src/num**并运行 gen：

```go
cd src/num;gen;cd -
```

我们可以看到 gen 创建了四个文件，每个文件都有一个切片类型：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/lrn-fp-go/img/e19e1fb0-d162-4e12-b621-5ba5ed88711b.jpg)

我们必须定义每种类型，并注释我们希望 gen 为每个切片创建一个`Sum`方法。请注意，我们从不需要为切片创建类型，只需要类型。Gen 为我们创建每种类型的切片，以及我们在 gen 切片注释中请求的方法。

这是来自`src/num/types.go`的代码：

```go
package num

// +gen slice:"Sum[Int8]"
type Int8 int8

// +gen slice:"Sum[Int32]"
type Int32 int32

// +gen slice:"Sum[Float64]"
type Float64 float64

// +gen slice:"Sum[Complex128]"
type Complex128 complex128
```

这是一个生成的文件（`src/num/int8_slice.go`）的片段，看起来像这样：

```go
// Generated by: gen
// TypeWriter: slice
// Directive: +gen on Int8

package num

// Int8Slice is a slice of type Int8\. Use it where you would use []Int8.
type Int8Slice []Int8

// SumInt8 sums Int8 over elements in Int8Slice. See: http://clipperhouse.github.io/gen/#Sum
func (rcv Int8Slice) SumInt8(fn func(Int8) Int8) (result Int8) {
   for _, v := range rcv {
      result += fn(v)
   }
   return
}
```

还记得我们在之前的汽车示例中将价格函数传递给`Select<T>`函数吗？让我们来看看：

```go
price := func (c Car) Dollars {
   return c.Price
}
fmt.Println("Hondas prices:", cars.Where(honda).SelectDollars(price))
```

这是我们将在`src/num/vars.go`文件中创建的函数类型：

```go
package num

var (
   Int8fn = func (n Int8) Int8 { return n }
   Int32fn = func (n Int32) Int32 { return n }
   Float64fn = func (n Float64) Float64 { return n }
   Complex128fn = func (n Complex128) Complex128 { return n }
)
```

我们将简单地返回传递给我们的文字函数定义的值在我们的`fmt.Println`语句中：

```go
package main

import (
   "fmt"
 . "num"
)

func main() {
   fmt.Println("int8Sum:", Int8Slice{1, 2, 3}.SumInt8(Int8fn))
   fmt.Println("int32Sum:", Int32Slice{1, 2, 3}.SumInt32(Int32fn))
   fmt.Println("float64Sum:", Float64Slice{1, 2, 3}.SumFloat64(Float64fn))
   fmt.Println("complex128Sum:", Complex128Slice{1, 2, 3}.SumComplex128(Complex128fn))
}
```

这是输出：

```go
int8Sum: 6
int32Sum: 6
float64Sum: 6
complex128Sum: (6+0i)
```

即使在这个简单的求和数字示例中，我们也看到我们的 gen 工具使我们免于输入繁琐的循环结构来求和数字。

我们只使用了`Sum`方法，但还有大约两打其他方法可供选择。

可以在[`clipperhouse.github.io/gen/slice/#`](https://clipperhouse.github.io/gen/slice/#)找到描述`Aggregate`方法的文档片段。

#### 切片打字机

切片打字机默认内置到 gen 中。它生成功能便利方法，这些方法对于使用 C#的 LINQ 或 JavaScript 的数组方法的用户来说会很熟悉。它旨在为您节省一些循环，使用传递函数模式。它提供更容易的特定多态排序。

注释看起来像这样：

```go
// +gen slice:"Where,GroupBy[int],Any"
 type Example struct {}
```

在这里，`Example`被用作您的类型的占位符。

生成了一个新类型`ExampleSlice`，并成为以下方法的接收者：

##### 聚合[T]

`AggregateT`遍历切片，将每个元素聚合成单个结果。`AggregateT`类似于 LINQ 的 Aggregate 和下划线 reduce 函数。

这是签名：

```go
func (ExampleSlice) AggregateT(func(T, Example) T) T
```

在下面的示例中，我们在我们的注释注释中指定我们希望 gen 创建一个在字符串切片上操作的`Aggregate`函数。我们定义了一个`join`函数，将其传递给`AggregateString`，执行连接操作：

```go
// +gen slice:"Aggregate[string]"
 type Employee struct{
 Name   string
 Department string
 }

 employees := EmployeeSlice {
 {"Alice", "Accounting"},
 {"Bob", "Back Office"},
 {"Carly", "Containers"},
 }

 join := func(state string, e Employee) string {
    if state != "" {
        state += ", "
    }
    return state + e.Name
 }

 employees.AggregateString(join) // => "Alice, Bob, Carly"
```

## 泛型实现选项

以下是一个决策矩阵，可用于评估哪种泛型实现最好。

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/lrn-fp-go/img/384b20d6-080a-4b7a-8021-792e51da8da6.png)

当我们考虑如何实现泛型时，有许多方面需要考虑。例如，让我们考虑 Haskell 的参数多态性和 C++的特定多态性之间的区别。

在 Haskell 中，多态函数对所有类型都是统一定义的。我们可以称之为编译时多态。

在 C++中，通过替换、虚函数和接口实现动态多态行为，但我们的实现是否适用于任何特定类型是在运行时决定的，当具体类型替换其参数时。

C++模板提供了类似的功能，而没有动态多态性的运行时开销。这种权衡是灵活性在编译时固定的事实。

Haskell 中的类型类允许我们为不同类型的相同函数定义不同的行为。在 C++中，我们使用模板特化和函数重载来实现这一点。

请注意，我们只是触及了问题的表面，并且只讨论了两种语言（C++和 Haskell）。还有很多边缘情况需要考虑。例如，Go 编译器是否应该执行激进的优化？如果是这样，那将意味着为所有使用它们的类型专门化多态函数，这将开启另一层需要管理的复杂性。

如果 Go 添加了泛型支持，将会涉及成本和风险。成本将会在编译时或运行时提前产生。在所有情况下，每种方法的利弊都应该仔细评估，我们应该谨慎地提出要求。我们将在下一章更多地讨论泛型。

有关泛型和 Go 的更多信息，包括像 gen 这样的更多工具，您可以参考[docs.google.com/document/d/1vrAy9gMpMoS3uaVphB32uVXX4pi-HnNjkMEgyAHX4N4](https://docs.google.com/document/d/1vrAy9gMpMoS3uaVphB32uVXX4pi-HnNjkMEgyAHX4N4)。另一个资源是[golang.org/doc/faq#generics.](https://golang.org/doc/faq#generics)

### 我们使用了 gen 工具。

我们使用了 gen 工具，这更符合 C++/模板的方法。虽然使用 gen 导致我们编写了更多的代码，但我们掌控了局面，并且得到了一些类似 LINQ 的功能，这使我们不必为处理切片编写大量样板代码。不错！

那么，Go 支持泛型吗？不支持。但是我们可以使用像 gen 这样的工具来解决重复样板代码的大问题。我们仍然拥有我们的类型安全，并且不需要为使用反射付出性能代价。

## 函子的形状

函子是一种代数类型，它接受一个值（或通常是一系列值），并具有一个 map 函数，该函数应用于列表中的每个元素，以产生相同形状的新函子。形状是什么？

让我们看一个命令式的例子：

```go
ints := []int{1,2,3}
impInts := []int{}
for _, v := range ints {
   impInts = append(impInts, v + 2)
}
fmt.Println("imperative loop:", impInts)
```

这是输出：

```go
imperative loop: [3 4 5]
```

在这个例子中，形状意味着一个包含三个整数的切片。我们从一个包含三个整数的切片开始，运行我们的命令式代码，最终得到一个包含三个整数的切片。

函子得到相同的结果（三个元素进入，三个元素出去），但是函子以不同的方式实现。

我们给我们的函子相同的三个整数切片。函子对每个整数执行`add2`并返回一个包含三个整数的切片（每个整数比以前大两个）：

```go
add2 := func(i int) int { return i + 2 }
fpInts := Functor(ints).Map(add2)
fmt.Println("fp map:", fpInts)
```

这是输出：

```go
fp map: [3 4 5]
```

函子肯定不止这些，对吧？

是的。魔鬼就在细节中。所以，让我们来揭开一些细节。

### 函子实现

让我们来看看我们的 ints 函子实现。

#### ints 函子

作为优秀的程序员，我们在文件顶部声明了我们的接口。我们的接口，也就是我们的契约，只有一个函数`Map`。我们的`IntFunctor`类型接受一个`func(int) int`函数，并返回另一个`IntFunctor`。

什么？它返回一个`IntFunctor`？那是什么，它是如何正确打印的？

让我们来看看`src/functor/ints.go`：

```go
package functor

import (
   "fmt"
)

type IntFunctor interface {
   Map(f func(int) int) IntFunctor
}
```

函子的一个特性是它在其容器内应用`f`函数。那么，什么是容器？

```go
type intBox struct {
   ints []int
}
```

那是我们函子的容器。我们将其称为`box`，因为盒子是一个容器，而且由于我们是优秀的懒惰程序员，我们更喜欢简短的名称。

好的。我看到了盒子。我们的神奇`box`里发生了什么？

```go
func (box intBox) Map(f func(int) int) IntFunctor {
   for i, el := range box.ints {
      box.ints[i] = f(el)
   }
   return box
}
```

首先，我们注意到`Map`是一个方法，`box`是接收者。`Map`接受一个函数并返回另一个`IntFunctor`。啊，所以我们从一个`IntFunctor`映射到另一个`IntFunctor`？是的，确实是这样。

由于一个函数器需要将一个结构映射到另一个结构，并且可能有多个元素需要映射（当我们说映射时，我们指的是逐个元素/三个输入，三个输出的转换）。可以肯定地假设我们将映射元素的列表。

Go 中列表形状通常是如何实现的？用一个切片，对吧？我们不应该感到惊讶，我们的`Map`方法的接收者是一个切片。每个切片都可以使用`range`进行迭代，这就是我们用来迭代我们的元素列表并将我们的函数（`f`）应用于每个元素并返回我们传入的`box`的方法。不同之处在于`box`现在包含了转换后的元素。

等一下，一个带有迭代变量`i`和`el`的`range`是如何在我们纯函数式编程的世界中进行变异的？更令人不安的是我们正在变异我们盒子的内容。没错，变异确实发生了，但只发生在盒子里。这是神奇的，记住吗？在这个盒子里的东西可以改变而不影响我们纯函数式编程的世界。

我们如何区分纯和不纯？这就是我们做的地方：

```go
func Functor(ints []int) IntFunctor {
   return intBox{ints: ints}
}
```

就是这样。这就是我们允许我们的执行降到变异的下水道的地方：

```go
fpInts := Functor(ints).Map(add2)
```

看到前一行的`Functor(ints)`部分了吗？那就是我们将我们的`ints`包装在神奇的盒子里的地方，也是我们允许淘气的`add2`变异函数应用于我们切片中的每个整数的地方。

将元素降低到变异的下水道的这种行为通常被称为 lifting。我认为，根据即将到来的类比，lifting 是一个误称。降低更适合它的名字。更多信息，请参见[`en.wikipedia.org/wiki/Lambda_lifting`](https://en.wikipedia.org/wiki/Lambda_lifting)。

函数器盒子中发生的事情与一个人沉溺于不纯洁的思想时发生的事情并无二致。结构将是在一个人的脑海中穿着圆点连衣裙的三头可爱奶牛的列表。不纯洁的人会让他们的思想降低到一个地方，他们会应用`Undress<T>`的文字函数，其中在这种情况下`T`类型将是一头奶牛：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/lrn-fp-go/img/900ee368-8112-4bb9-ad0a-bbeb777329c2.jpg)

纯函数式编程走向地狱

当一个人知道他们的思想是允许各种不纯的变异的神奇盒子时，他们可能会感到安全。当这种情况发生时，一个人会使用`Undress`函数器，将可爱的、穿着衣服的奶牛从一个世界映射到另一个世界。

当你妈妈说：“别想那些下流的事！”时，这正是她所说的。

在`src/functor.ints.go`中我们做的最后一件事是创建一个`String()`方法：

```go
func (box intBox) String() string {
   return fmt.Sprintf("%+v", box.ints)
}
```

由于我们实现了这个`String()`方法，根据 Go 的鸭子类型规则，我们的`IntFunctor`是一个`Stringer`：

```go
type Stringer interface {
    String() string
}
```

这是一个美丽的、单方法接口。`fmt`寻找这个接口来打印值。

Go 标准库非常易于访问，是了解事物真正工作原理的好地方。在我们的例子中，我们看到我们将`v`作为动词传递（当我们返回`fmt.Sprintf("%+v", box.ints)`时）在`print.go`文件的*第 577 行*。这是`print.go`中从*第 577 行*开始的片段：

```go
// /usr/local/Cellar/go/1.9/libexec/src/fmt/print.go
// If a string is acceptable according to the format, see if
// the value satisfies one of the string-valued interfaces.
// Println etc. set verb to %v, which is "stringable".
switch verb {
case 'v', 's', 'x', 'X', 'q':
   // Is it an error or Stringer?
 // The duplication in the bodies is necessary:
 // setting handled and deferring catchPanic
 // must happen before calling the method.
 switch v := p.arg.(type) {
   case error:
      handled = true
 defer p.catchPanic(p.arg, verb)
      p.fmtString(v.Error(), verb)
      return

 case Stringer:
      handled = true
 defer p.catchPanic(p.arg, verb)
      p.fmtString(v.String(), verb)
      return
 }
}
```

### 函数器定义

函数器([`hackage.haskell.org/package/base-4.8.1.0/docs/Data-Functor.html#t:Functor`](https://hackage.haskell.org/package/base-4.8.1.0/docs/Data-Functor.html#t:Functor))类用于可以进行映射的类型。

我们将使用 Haskell 语法，因为它清晰地定义了 FP 代数数据类型，包括它们的结构、规则和逻辑。`fmap`是映射函数。句号`.`表示`compose`运算符。

函数器的实例应满足以下的身份和结合律：

```go
fmap id  ==  id
fmap (f . g)  ==  fmap f . fmap g
```

我们应该从第十一章中认识到这两条规则，*适用的范畴论*。

#### 身份运算

我们的范畴的恒等律说，**A**的恒等态射是**A**：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/lrn-fp-go/img/45776db5-ff12-437d-b841-76c5c71611b4.png)

如果我们的操作是一个映射，列表中的元素是数字，那么恒等态射是+0。如果我们将 0 添加到输入列表的每个元素，我们的转换列表将由相同的元素组成。

注意！我们将强调组合的概念。您对组合是什么以及它是如何工作的理解对于您能够在纯函数式编程中提高生产力至关重要。如果您只读了本书的几页，那么您的阅读现在就开始吧。

## 组合操作

组合操作**g.f**或**g**在**f**之后，将函数**f**应用于 x（将我们从**A**到**B**），并将结果传递给**g**（将我们从**B**到**C**），这个嵌套的操作等同于**g.f**的组合操作。

在 Haskell 中，我们在第一行定义我们的组合操作，并在第二行请求查看我们组合操作的类型定义。第三行是组合的含义：

```go
> (.) g f = \x -> g (f x)
> :t (.)
(.) :: (b -> c) -> (a -> b) -> a -> c
```

上面的`a`，`b`和`c`对应于以下图表中的**A**，**B**和**C**。

它说，当我们将**A**到**B**函数（**f**）传递给**B**到**C**函数（**g**）时，我们得到**A**到**C**函数（**g.f**）。

这是基本的组合。假设我们从**A**开始，这个图表表示我们可以通过**B**（**A**到**B**到**C**）的方式或者直接从**A**到**C**的方式到达**C**。当我们选择短路线（**A**到**C**）或**g.f**时，我们以嵌套的方式组合**g**和**f**，就像 g(f(x))，其中 x 是我们从**A**得到的值：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/lrn-fp-go/img/85c1f822-890f-4447-b754-920dafc3f1c8.png)

还不太明白？坚持一下。经过几个例子，你就会明白了。

### Go 中的组合示例

我们将创建两个函数，`Humanize`和`Emphasize`（代表 f 和 g），以及`Emphasize(Humanize(true))`的组合函数，以说明从**A**到**B**到**C**的路径：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/lrn-fp-go/img/04e03132-a800-4159-a025-6386d4dd9684.png)

`src/compose/compose.go`文件包含以下代码：

```go
package compose

func Humanize(b bool) string {
   if b { return "yes" } else { return "no" }
}

func Emphasize(s string) string {
   return s + "!!"
}

func EmphasizeHumanize(b bool) string {
   return Emphasize(Humanize(b))
}
```

`main.go`看起来是这样的：

```go
package main

import (
   "fmt"
 . "compose"
)

func main() {
   fmt.Println("A to B - Humanize(true):", Humanize(true))
   fmt.Println("B to C - Emphasize(\"yes\"):", Emphasize("yes"))
   fmt.Println("A to C - EmphasizeHumanizeFG(true)", EmphasizeHumanizeFG(true))
}
```

如果您使用 init 脚本，则您的终端应如下所示：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/lrn-fp-go/img/9b514e34-af68-4690-b047-b3642323ccd0.png)

如果这是一个包括外部包的更复杂的示例，那么您将按照以下顺序运行：

`. init`，`glide-update`和`go-run`

### compose 的 Haskell 版本

我们将介绍组合 Humanize 和 Emphasize 的 Haskell 版本：

```go
humanize b = if b then "yes" else "no"
emphasize str = str ++ "!"
compose g f = \x -> g (f x)
emphasizeHumanize = compose emphasize humanize
emphasizeHumanize True
```

就是这样！这五行等同于 25 行 Go 代码！

我绝不主张任何 Gophers 转换到 Haskell——有太多原因要保持编写和部署 Go 解决方案，这里无法一一列举。我包含 Haskell 代码是出于信息目的。正如本书前面提到的，范畴论直接从数学家的大脑中滴入 Haskell。因此，如果我们想成为优秀的纯函数式编程 Gophers，那么我们应该学习 Haskell。

以下是我们会话的 REPL 终端日志：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/lrn-fp-go/img/a5e2627c-878c-4bcf-b32a-5fd0636440ad.png)

让我们更仔细地看一些行。

我们可以要求 Haskell REPL 告诉我们我们定义的内容的类型使用`:t <symbol>`。

例如，`:t humanize`告诉我们它是一个函数（`->`），它接受一个`Bool`并返回一个字符列表：

```go
:t humanize
humanize :: Bool -> [Char]
```

`\x`告诉 Haskell，compose 是一个 lambda 表达式。我们将我们的 lambda 命名为`compose`，并将`g`和`f`函数作为参数传递。

`g (f x)`表示，应用`f`到`x`，取得结果，并将其传递给`g`：

```go
compose g f = \x -> g (f x)
```

现在，让我们看看 compose 的类型是什么：

```go
:t compose
 compose :: (t2 -> t1) -> (t -> t2) -> t -> t1
```

这有点难以理解。因此，让我们看看 Haskell 如何说它的默认实现的 compose 运算符的类型是什么：

```go
:t (.)
 (.) :: (b -> c) -> (a -> b) -> a -> c
```

我们以前见过这个：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/lrn-fp-go/img/2b57e872-3fab-4a46-b5bf-a87286883296.png)

太棒了！现在我们正在取得进展。是时候定义我们的`emphasizeHumanize`组合 lambda 了：

```go
emphasizeHumanize = compose emphasize humanize
```

`compose`是我们的函数，我们传递了两个参数--`emphasize`和`humanize`。作为优秀、细心的程序员，我们将检查我们函数文字的类型：

```go
:t emphasizeHumanize
 emphasizeHumanize :: Bool -> [Char]
```

非常稳固！它接受一个布尔值并返回一个字符串。

到目前为止，一切都很好。现在是时候运行这个 Haskell 的`compose`函数，看看我们是否得到了与 Go 中相同的结果：

```go
emphasizeHumanize True
 "yes!"
```

哇！

鉴于许多 Haskeller 是数学家，我们知道他们喜欢使用符号而不是单词。此外，我们知道他们喜欢他们的代码看起来像数学方程式。因此，让我们像优秀的、数学思维的程序员一样思考，为语法增添一些调味。

让我们用`.`符号重新定义组合函数名称（注意我们必须将`.`放在括号中；否则，Haskell 会抱怨）：

```go
(.) g f = \x -> g (f x)
```

现在让我们检查它的类型：

```go
:t (.)
(.) :: (t2 -> t1) -> (t -> t2) -> t -> t1
```

好的，现在我们可以理解了...这是基本的组合。我们可以用句号代替 compose：

```go
emphasizeHumanize = (.) emphasize humanize
emphasizeHumanize True
 "yes!" 
```

但这还不够。我们可以做得更好。让我们使用中缀表示法，将（.）放在我们的两个参数之间，就像这样：

```go
emphasizeHumanize = emphasize . humanize
```

让我们验证一下它是否有效：

```go
emphasizeHumanize True
 "yes!"
emphasizeHumanize False
 "no!"
```

### (g.f)(x) = g(f(x)) Go 中的组合

这是我们在 Go 中最终的组合示例的图形表示：

>![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/lrn-fp-go/img/ecafc22b-274b-4a39-8856-eea7314ee282.png)

不要忽视那个图表。仔细研究它。让它深入你的心灵。

这就是组合，函数式编程的基本原则。

那个**(g.f)(x) = g(f(x))**方程非常字面。它说我们可以执行**f**函数，**Humanize(true)**，然后将值**"yes"**传递给**g**...**Emphasize**(**"yes"**)以获得**"yes!!"**。

那个**(g.f)(x) = g(f(x))**方程还说了一件事。它说我们可以嵌套我们的函数，**g(f(x))**，就像从**A**到**B**，然后从**B**到**C**，或者我们可以直接执行**EmphasizeHumanize(true)**从**A**到**C**。

因此，根据左侧图表，**(g.f)(x) == g(f(x))**，同样地，根据右侧图表，**EmphasizeHumanize(true) ==  Emphasize(Humanize(true))**。

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/lrn-fp-go/img/7df60447-1a1e-4479-ac5e-6c7c2fb8d0e6.png)

嘭！

#### (g.f)(x) = g(f(x))的实现

现在让我们来看一下代码。

这是前面图表中的**f**和**g**函数：

```go
package compose

func Humanize(b bool) string {
   if b { return "yes" } else { return "no" }
}

func Emphasize(s string) string {
   return s + "!!"
}

func EmphasizeHumanize(b bool) string {
   return Emphasize(Humanize(b))
}
```

现在是新东西的时间。

我们将创建两种类型。Fbs 代表**f**（或**A**到**B**），它接受一个布尔值（true），并返回一个字符串，`"yes"`。Fss 代表**g**（或**B**到**C**）。`Fss`接受一个字符串，`"yes"`，并返回一个字符串，`"yes!!"`：

```go
type Fbs func(bool) string
type Fss func(string) string
```

这是我们的`Compose`函数：

```go
func Compose(g Fss, f Fbs) Fbs {
   return func(x bool) string {
      return g(f(x))
   }
}
```

在我们的`Compose`函数内部嵌套着一个匿名函数。这是我们的 Lambda。在 Haskell 中，它看起来像`\x -> g (f x)`。

Lambda 是表达式，我们可以在任何地方传递它们。我们需要一个接受布尔值并返回一个`"yes!!"`或`"no!!"`的函数。

最后，我们定义我们的`g.f`函数文字：

```go
var Emphasize_Humanize = Compose(Emphasize, Humanize)
```

#### 关于 Go 中组合命名约定的说明

在 Go 中，我们没有将函数名重命名为`.`符号的奢侈，也没有一种简单地将看起来像**compose(f, g)**的函数调用转换为看起来像**g compose f**，更不用说看起来像**g . f**的方法。但别担心！我们只需使用以下命名约定来表示一个组合函数：`Emphasize_Humanize`（读作`g . f`，其中`g`是`Emphasize`，`f`是`Humanize`）。通常，驼峰式符号看起来像`EmphasizeHumanize`，但用下划线分隔驼峰，很明显这是一个特殊符号。

这是 main.go：

```go
package main

import (
   "fmt"
 . "compose"
)

func main() {
   fmt.Println("A to B - Humanize(true):", Humanize(true))
   fmt.Println("B to C - Emphasize(\"yes\"):", Emphasize("yes"))
   fmt.Println("A to C - EmphasizeHumanize(true):", EmphasizeHumanize(true))
   fmt.Println("A to C - Emphasize_Humanize(true):", Emphasize_Humanize(true))
}
```

这是我们运行它时的样子：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/lrn-fp-go/img/29458000-fc00-4eee-8684-6eaaee0acfbe.png)

### 箭头的方向是重要的

在上一章中，我们使用以下图表来解决*f(x) = x + 2:*

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/lrn-fp-go/img/eb3c1664-0764-49e2-9751-e8222a3db109.png)

还记得我们将*f(x) = x + 2*与*g(x) = x2 + 1*组合时吗？我们解决了**g(f(1)) = 10**：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/lrn-fp-go/img/8b95812f-0f1a-47a6-bf5d-02a5fbaf3658.png)

我们还证明了**f(g(1)) = 4**，显然不是**10**。因此，我们知道函数组合不是可交换的。箭头只能单向移动。

#### 强调人性化排序不正确

当我们尝试颠倒操作顺序时，我们正在尝试做什么：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/lrn-fp-go/img/0499e2cc-9754-426f-8d2f-c0e33c2d6854.png)

这不符合逻辑。

我们首先将布尔值**true**传递给**Emphasize**，但这是什么意思？我们试图做什么？我们没有改变箭头的方向，但我们试图改变调用它们的顺序。鉴于我们从布尔值开始，试图得到一个“是！”或“不是！”的结果，只有在一个方向上应用我们的`Humanize`和`Emphasize`函数才有意义。实际上，我们试图向后组合：

```go
func Compose(f Fss, g Fbs) Fbs {
   return func(n bool) string {
      return g(f(n))
   }
}
```

请注意，其余的代码与以前完全相同。我们只交换了返回语句中**f**和**g**的嵌套顺序。

调用我们的`Compose`函数的函数文字看起来像这样：

```go
var EmphasizeHumanizeFoG = Compose(Emphasize, Humanize)
```

这意味着，“强调真实，然后使结果人性化”，显然行不通（见前面的图表）。

这段代码甚至无法编译：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/lrn-fp-go/img/6d32204b-2ad1-45ba-83f4-3fa6407afc60.png)

### 函数组合是结合的

因此，函数组合不是交换的，但是它是结合的：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/lrn-fp-go/img/0c6f1211-4f95-468c-8aee-f8824c3dd744.png)

该图表表示我们可以通过选择上方（**A****→C**→**D**）路径或下方（**A**→**B**→**D**）路径来组合我们的函数从**A**到**D**。

函子的概念是，它将我们可以在一个范畴中绘制的图表转换为另一个范畴中的图表。这通常让我们将一个范畴中的思想和定理转换为另一个范畴。

让我们看一个特定函子的例子，遗忘函子，以更好地理解将事物从一个范畴转换为另一个范畴的含义。

## 在法律义务的背景下的功能组合

假设拉里同意在 10 月 1 日之前支付给露西 5000 美元，那个日期已经过去了。露西想要得到 5000 美元的报酬，拉里也想支付她，但他没有钱。

露西应该起诉拉里让他付款吗？

以下的范畴图描述了他们的情况：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/lrn-fp-go/img/b6196744-65f1-403c-8569-d9979a00200c.png)

范畴状态如下：

+   **A** = 我们今天的位置（10 月 12 日）

+   **B** = 露西要求提起诉讼

+   **C** = 露西得到报酬

范畴态射如下：

+   **f** = 法律费用（对于两者，2000 美元以上）

+   **g** = 拉里支付露西 5000 美元

+   **h** = 拉里支付露西 5000 美元

### 决定决定状态转换

如果拉里以诚意向露西传达以下内容，露西会选择哪条路？

为了明确，我只是要求更多时间付款，或者你允许我直接向你支付预定的付款，而不需要通过法院系统。

你的想法是什么？

拉里

很明显，这两个路径最终都会从**A**到**C**，但哪条路径最短？哪条路径在时间和财务开支方面更昂贵？

### 范畴论复习

我们连接两个箭头从**A**到**B**和**B**到**C**，以及另一个等价的箭头从**A**到**C**。**A**，**B**和**C**被称为对象。它们可以代表任何东西。在这个例子中，它们代表状态--开始（**A**），中间（**B**）和最终（**C**）状态。在下一个例子中，域和范围代表不同的法院案件，不同的世界。每个案件的事实构成了每个案件的结构，两个世界之间的箭头是律师进行的映射，以证明他们的案件。

#### 范畴规则

只有两条规则必须遵循：

+   身份

+   结合性

#### 结果导向

范畴论是结果导向的。它的重点是从**A**到**C**。箭头是单向的。当我们组合两条路径（**A** → **B**和**B** → **C**）时，我们得到一个等效的路径（**A** → **C**）。这就是我们组合函数时所做的。我们可以调用一个`Compose`函数（如下面的代码片段中所示），而不是两个函数（`f`和`g`）： 

```go
func Compose(g Fss, f Fbs) Fbs {
   return func(x bool) string {
      return g(f(x))
   }
}
```

### 遗忘函子和法律

假设 Lucy 选择了更长的路径；Lucy 的律师们将如何为他们的客户辩护？

让我们假设这个故事还有更多内容。假设 Lucy 在过去某种方式上伤害了 Larry，现在 Lucy 正在强迫 Larry 提起诉讼，他将选择向他的律师传达这些新信息，以提起反诉。

#### 法律规则

他们上法庭时法律将如何运作？律师们研究法律，寻找以前的法院案例，可能会为他们的客户带来有利的结果。然后，他们使用该案例的裁决作为先例来为他们的客户赢得当前的案件。

要证明他们的观点，不可能参考整个案件历史。因此，双方的律师将使用一种修辞手法，范畴论者称之为健忘函子。健忘函子必然会留下一些结构。很难找到一个在每个方面都与手头案件相同的过去案例。

每个律师都会努力说服他人，他们提出的结构，即如果选择的话，将为他们的客户带来最佳结果的一个法院案件，应该被应用。

事实是，过去有很多法院裁决可能适用，但每个律师都会试图说服法官和/或陪审团，他们选择的案件才是实际情况。

获胜的一方将有效地从一个包括不同当事人（原告、被告和案件事实）的世界中映射出先前的法院裁决到当前案件。一些细节会有所不同，但获胜的律师是最好地传达他们已经确定了最相关和适用的案例来在今天的法庭上应用。

每个律师都会确定一个旧案件与最有助于他们客户的现行法庭案件之间的双边对称性，并尽力说服他人应用该案件。我们可能会听到这样的论点开始，*“女士们，先生们，您需要应用的基本结构是这样的**”。*

#### Lucy 的健忘函子

鉴于 G 是他们当前的案件，以及它当前的事实，Lucy 的律师将案件（**E**）中对 Lucy 最有帮助的事实进行映射：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/lrn-fp-go/img/0e32e19a-3dfd-40db-94ea-248a677711f2.png)

**f[Lucy]**是来自案件**E**的事实的映射函数，优先考虑 Lucy。

#### Larry 的健忘函子

Larry 的律师将案件（**F**）中对 Larry 最有帮助的事实进行映射：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/lrn-fp-go/img/2b9faa05-5037-48ac-af96-bd719c58b1d4.png)

由法官和/或陪审团决定哪种映射最适合当前审查的案件。拥有最佳映射的一方获胜。

是时候编写另一个函子了（这是双关语）。

## 构建一个 12 小时时钟函子

我们将构建一个类似这样的 12 小时时钟函子：

| **结构** | 一个有 12 个小时位置的时钟 |
| --- | --- |
| **转换操作** | *f(x) = x + 12*，其中*x*是小时 |

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/lrn-fp-go/img/3da5772f-617f-406d-b8a1-9163d5f7c878.png)

首先，让我们来看一下函子的实现：

```go
// src/functor/clock.go

package functor

import (
   "fmt"
)
```

定义我们的`ClockFunctor`接口以包括一个函数（`Map`）：

```go
type ClockFunctor interface {
   Map(f func(int) int) ClockFunctor
}
```

创建一个容器来保存我们的 12 小时列表：

```go
type hourContainer struct {
   hours []int
}
```

当调用时，`Map`将被执行/应用到容器中的每个元素：

```go
func (box hourContainer) Map(f func(int) int) ClockFunctor {
   for i, el := range box.hours {
      box.hours[i] = f(el)
   }
   return box
}
```

`Map`的实现可以是不纯的，只要副作用限于变量，比如循环变量，作用域在`Map`函数中。注意返回容器，我们称之为`box`，其元素已经以某种方式被映射函数**f**转换。

接下来，我们创建一个名为 Functor 的函数，它将我们的 12 小时列表包装到魔法盒中进行转换。这是我们将价值降低到低谷的地方。有些人称这个过程为 lifting，其中从一个世界到另一个世界的映射转换发生（有关详情，请参见本章前面的*Pure FP goes to Hell*）：

```go
func Functor(hours []int) ClockFunctor {
   return hourContainer{hours: hours}
}
```

### 时钟函子助手

在我们的`clock.go`文件末尾，我们将添加一些辅助函数，如下面的部分所讨论的。

#### 单元函数

我们的`Unit`函数是我们的身份函数。当应用于切片中的元素时，它不会产生任何效果。这很琐碎，但它是满足函子代数法则的要求：

```go
var Unit = func(i int) int {
   return (i)
}
```

#### AmPmMapper 函数

这是我们在想要从上午小时变成下午小时时应用的映射器。它将被传递给`Map`方法，并应用于盒子中包含的每个小时。它将把上午小时（1、2...12）转换为相应的下午小时（13、14..0）。

```go
var AmPmMapper = func(i int) int {
   return (i + 12) % 24
}
```

#### AmHoursFn 辅助函数

我们可以随时调用这个方便的函数，以获取上午小时的列表。请注意，如果我们创建一个`AmHours`变量传递给我们时钟的函子，它的值是可以改变的。因此，这就像是一个上午小时的切片常量：

```go
func AmHoursFn()  []int {
   return []int{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12}
}
```

在现实世界的场景中，我们将按照预期使用函子，也就是说，我们将传入一组初始值的切片，并允许每个函子在调用新的函子的`Map`函数时转换这组值的切片。在我们的`main.go`文件中，我们想要重置学习目的的小时集。

#### 字符串辅助函数

创建一个字符串辅助函数，用于在打印函子内容时使用：

```go
func (box hourContainer) String() string {
   return fmt.Sprintf("%+v", box.hours)
}
```

#### main.go

我们从典型的`package main`和`import`语句以及“main（）”函数开始：

```go
package main

import (
   . "functor"
 "fmt"
)

func main() {
```

请注意，我们在内部的`functor`包（在`src`目录中找到）前面加上一个点。这样可以让我们引用它导出的符号，比如`Functor`和“Map”。

首先，我们调用我们的`Functor`方法，并传入我们的`AmHours`切片。`Functor`将我们的小时结构包装在类型为“ClockFunctor”的函数中：

```go
fmt.Println("initial state :", Functor(AmHoursFn()))
```

这是输出：

```go
initial state : [1 2 3 4 5 6 7 8 9 10 11 12]
```

`Functor`函数是连接我们两个世界的东西：上午小时的世界和下午小时的世界（或者反之亦然）。我们可以说，`Functor`将我们的小时数降低到一个神奇的盒子中，在这个盒子中，变换映射函数`amPmMapper`被应用到每个元素上，将其转换为相应的下午（或上午）小时。

请注意，映射函数必须不产生任何副作用：

```go
fmt.Println("unit application :", Functor(AmHoursFn()).Map(Unit))
```

这是输出：

```go
unit application : [1 2 3 4 5 6 7 8 9 10 11 12]
```

我们可以看到，当我们将我们的函子的身份函数“unit”传递给它的`Map`方法时，它会返回我们传递的内容，也就是上午小时。

现在是有趣的部分。让我们将我们的映射函数传递给我们的函子：

```go
fmt.Println("1st application :", Functor(AmHoursFn()).Map(AmPmMapper))
```

这是输出：

```go
1st application : [13 14 15 16 17 18 19 20 21 22 23 0]
```

太棒了！我们的上午小时列表已经转换为下午小时列表。

现在，让我们炫耀一下，并链接两个`Map`调用：

```go
fmt.Println("chain applications:", Functor(AmHoursFn()).Map(AmPmMapper).Map(AmPmMapper))
```

这是输出：

```go
chain applications: [1 2 3 4 5 6 7 8 9 10 11 12]
```

为什么那样炫耀呢？看起来好像什么都没变。无聊。对吧？

错误。我们正在链接我们的函子。

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/lrn-fp-go/img/2330d241-2d2b-4a81-9b91-50bb0bfad2fb.png)

输出看起来没有改变的原因是因为它从上午小时变成下午小时，然后又变回上午小时。

#### 终端输出日志

这是我们终端上的样子：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/lrn-fp-go/img/243541e1-0f3c-4980-aab4-e6517bfb0c19.png)

#### 函子总结

我们的时钟函子包括一个结构（一个整数切片），其中包含 12 小时和一个`Map`方法，该方法接受一个映射函数，用于将 12 小时中的每个小时转换为随后的 12 小时（上午/下午）。每次执行`Map`方法时，它都会返回一个新的函子；由于这个特性，我们可以链接我们的`Map`方法调用。

换句话说，看看以下示例：

```go
Functor([]int{1, 2, 3}).Map(mapperFn).Map(mapperFn))
```

我们看到，使用函子，我们包装并`Map`（并且可以链接我们的映射）。

## 汽车函子

让我们使用一个函子来升级（和降级）一些汽车！我们将首先打开我们`functor`包中的`car.go`文件。

### 函子包

让我们看看`src/functor/car.go`：

```go
package functor

import (
   "fmt"
 "strings"
)

type (
   Car struct {
      Make string `json:"make"`
 Model string `json:"model"`
 }
)
```

在顶部定义我们的类型是一个好习惯。将它们放在一个类型块中有助于保持我们的代码整洁。另一个好习惯是为结构体的每个字段添加 JSON 注释，以便轻松地将 JSON（解）编组为我们的`Car`结构。

如果您想从结构中省略空字段，可以在字段注释的末尾添加`omitempty`子句。例如，如果`Make`是可选的或有时不包括在内，我们不希望从`Car`结构创建的`json`包含空的`Make`字段，我们的结构定义将如下所示：

`Car struct {`

` Make string `json:"make"``

` Model string `json:"model,omitempty"``

`}`

接下来是我们的接口定义，其中包括单个`Map`方法：

```go
type CarFunctor interface {
   Map(f func(Car) Car) CarFunctor
}
```

这是我们的神奇盒子，其中包含我们将要转换的切片：

```go
type carContainer struct {
   cars []Car
}
```

这是我们的`Map`方法实现，我们在其中遍历我们神奇盒子中的汽车切片的元素，将映射函数`f`应用于每个元素：

```go
func (box carContainer) Map(f func(Car) Car) CarFunctor {
   for i, el := range box.cars {
      box.cars[i] = f(el)
   }
   return box
}
```

这是我们的`Wrap`方法，用于将我们的汽车切片降低到神奇盒子进行转换：

```go
func Wrap(cars []Car) CarFunctor {
   return carContainer{cars: cars}
}
```

在这里，我们定义了我们的辅助函数。`Unit`我们以前见过--它是我们的身份态射。另外两个是`Upgrade`和`Downgrade`。我们将保持简单，当我们升级或删除汽车时，我们将简单地在模型名称的末尾附加“LX”：

```go
var (
   Unit = func(i Car) Car {
      return (i)
   }

   Upgrade = func(car Car) Car {
      if !strings.Contains(car.Model, " LX") {
         car.Model += " LX"
 } else if !strings.Contains(car.Model, " Limited") {
         car.Model += " Limited"
 }
      return car
   }

   Downgrade = func(car Car) Car {
      if strings.Contains(car.Model, " Limited") {
         car.Model = strings.Replace(car.Model, " Limited", "", -1)
      } else if strings.Contains(car.Model, " LX") {
         car.Model = strings.Replace(car.Model, " LX", "", -1)
      }
      return car
   }
)
```

最后，我们包括一个`String`方法，以便我们的`fmt`包知道如何打印我们的汽车：

```go
func (box carContainer) String() string {
   return fmt.Sprintf("%+v", box.cars)
}
```

### main.go

我们将操作字符串和一些 JSON，以及一个`car`函子：

```go
package main

import (
   "encoding/json"
 "fmt"
 "functor"
 "strings"
)
```

创建一个`cars`变量来保存`Car`类型，并用两辆车进行初始化。由于我们用`'json'`注释了我们的`Make`和`Model`字段，我们可以轻松地将`Toyota Highlander`解组为一辆车：

```go
func main() {

   cars := []functor.Car{
      {"Honda", "Accord"},
      {"Lexus", "IS250"}}

   str := `{"make": "Toyota", "model": "Highlander"}`
 highlander := functor.Car{}
   json.Unmarshal([]byte(str), &highlander)
   cars = append(cars, highlander)
```

现在，让我们练习一下我们的`car`函子，并验证它是否正常工作：

```go
fmt.Println("initial state :", functor.Wrap(cars))
fmt.Println("unit application:", functor.Wrap(cars).Map(functor.Unit))
fmt.Println("one upgrade :", functor.Wrap(cars).Map(functor.Upgrade))
fmt.Println("chain upgrades :", functor.Wrap(cars).Map(functor.Upgrade).Map(functor.Upgrade))
fmt.Println("one downgrade :", functor.Wrap([]functor.Car{{"Honda", "Accord"}, {"Lexus", "IS250 LX"}, {"Toyota", "Highlander LX Limited"}}).Map(functor.Downgrade))
```

#### 将 FP 的一行与大量的命令式行进行比较

应用升级和降级到汽车只需要一行 FP 风格的代码。当然，`Upgrade`和`Downgrade`映射函数是在`functor`包中定义的，但这是一个很大的好处。我们可以将循环遍历汽车切片的样板实现与我们的业务用例逻辑分开。

使用命令式实现风格，我们首先将`for...range`迭代块实现到其中，然后插入我们的升级/降级逻辑：

```go
// FUNCTIONAL STYLE
fmt.Println("up and downgrade:", functor.Wrap(cars).Map(functor.Upgrade).Map(functor.Downgrade))

// IMPERATIVE STYLE
cars2 := []functor.Car{}
for _, car := range cars {
   // upgrade
 if !strings.Contains(car.Model, " LX") {
      car.Model += " LX"
 } else if !strings.Contains(car.Model, " Limited") {
      car.Model += " Limited"
 }
   cars2 = append(cars2, car)
}
cars3 := []functor.Car{}
for _, car := range cars2 {
   // downgrade
 if strings.Contains(car.Model, " Limited") {
      car.Model = strings.Replace(car.Model, " Limited", "", -1)
   } else if strings.Contains(car.Model, " LX") {
      car.Model = strings.Replace(car.Model, " LX", "", -1)
   }
   cars3 = append(cars3, car)
}
fmt.Println("up and downgrade:", cars3)
```

看到区别了吗？

哪种编码风格更容易维护？

#### Car 函子终端会话

让我们运行我们的 car 函子示例：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/lrn-fp-go/img/ff3b748b-7219-4d67-a60a-26b586fc36ea.png)

## 幺半群

幺半群是组合任何值的最基本方式。幺半群是代数，它在一个可结合的二元运算下是封闭的，并且具有一个身份元素。

我们可以将幺半群看作是一种设计模式，它允许我们以并行方式快速减少（或折叠）单一类型的集合。

### 幺半群规则

幺半群是满足以下规则的任何东西：

+   闭包规则

+   结合律规则

+   身份规则

让我们简要讨论这些规则。

#### 闭包规则

“如果你组合两个相同类型的值，你会得到另一个相同类型的值。”

给定相同类型的两个输入，幺半群返回相同类型的一个值。

##### 闭包规则示例

1 + 2 = 3，3 是一个整数。

1 + 2 + 3 也等于一个整数。

1 + 2 + 3 + 4 也等于一个整数。

我们的二元运算已经扩展为适用于列表的运算！

##### 闭包公理

如果 a，b ∈ S，则 a + b ∈ S。

这意味着，如果 a 和 b 是整数集合 S 中的任意两个值，并且如果我们将二元运算+应用于任意两个值，那么该加法运算的结果也将是整数集合中的一个值。

#### 结合律规则

“如果你组合了更多的值，组合的顺序并不重要”

```go
( 1 + 2 ) + 3 == 1 + ( 2 + 3 )   // left and right associativity
```

所以，如果我们有 1 + 2 + 3 + 4，我们可以将其转换为（1 + 2）+（3 + 4）。

请注意，结合性适用于加法和乘法以及字符串连接，但不适用于减法和除法。

#### 身份规则

“有一个不做任何事情的身份元素。”

- 身份规则

幺半群将取两个相同类型的值，并返回一个相同类型的值。

##### 身份规则示例

在+运算符下，整数集合的身份是 0。

| 规则 | 示例 |
| --- | --- |
| 左身份 | 0 + 1 == 1 |
| 右单位 | 1 + 0 == 1 |

请注意，运算符是二元的，即它接受两个输入，并且这些输入必须是相同的类型。

将身份元素（有时称为空或零）与 x 组合的结果始终是 x。

##### 0 的身份

在*运算符下，整数集合具有 1 的身份。

```go
1 * 0 == 0
1 * 2 == 2
```

### 编写一个缩减函数

根据前面的三条规则，我们可以编写一个缩减函数。当我们使用加法对整数数组进行缩减时，我们的操作以 0（身份元素）为种子。

当我们使用乘法对整数数组进行缩减时，我们的操作以 1（身份元素）为种子。

这就是想法。以下表格总结了许多可能的缩减：

| **类型** | **操作** | **单位/零/中性值** |
| --- | --- | --- |
| 整数 | + | 0 |
| 整数 | * | 1 |
| 字符串 | +（连接字符串） | “” |
| 布尔 | && | true |
| 布尔 | &#124;&#124; | false |
| 列表 | <<（连接列表） | [] |
|  |  |  |

### 半群是缺少中性值

如果我们缺少单位/零/中性值，那么我们就没有幺半群，而是半群。请注意，半群可以转换为幺半群。

这是一个关于幺半群代数的非常有趣的讨论，但是它们有什么用呢，我们为什么要关心呢？

以下是幺半群的几个很好的用途。

#### 将二进制运算转换为在列表上工作的运算

考虑以下操作：

```go
1 + 2 + 3   ⇒   [1,2,3] |> List.reduce(+)
```

我们不必编写所有那些代码，其中我们输入一个数字，输入一个`+`，再输入另一个数字，我们可以将数字列表输入到我们的缩减函数中，该函数对每个项目应用`+`操作并累积总和。

这是一个字符串附加的例子：

```go
"a" + "b" + "c"   ⇒   ["a", "b", "c] |> List.reduce(+)
```

在前面的例子中，使用了哪个中性/身份元素？

前面的代码是 F#代码。`|>`符号只是一个管道符号，就像我们在 Unix 终端中使用的一样。它允许我们将整数列表`[1,2,3]`或字符串列表`["a", "b", "c"]`传递到`List.reduce(+)`中。大于符号只是数据流的方向指示，即从左到右。

#### 将幺半群与分治算法一起使用

幺半群经常用于解决大型计算问题。幺半群帮助我们将计算分解成片段。我们可以在单独的核心或单独的服务器上运行较小的计算，并将结果重新组合/缩减/折叠成单一结果。我们经常使用并行或并发技术以及递增积累我们的结果。

作为一个非常简单的例子，如果我们需要添加这些数字：1 + 2 + 3 + 4。

我们可以在一个 CPU/核心上添加（1 + 2），在另一个 CPU/核心上添加（3 + 4）：

3 + 7 = 10

当结合律成立时，我们可以并行计算。

### 引用透明性

使用幺半群可以帮助我们做影响性能的设计决策。

在第一天，我们被要求添加 1 + 2 + 3。然后，在第二天，我们被要求再添加 1。我们不必再次添加 1 + 2 + 3。我们只需存储它并将新的 1 加到它上：6 + 1 = 7。

考虑到没有什么是免费的，我们为了获得不必再次添加 1 + 2 + 3 的性能提升付出了什么代价？存储。问题是，哪个更昂贵？这个答案将告诉我们是否利用引用透明性。仅仅因为我们可以做某事，并不意味着我们总是应该这样做。 

### 处理没有数据

如果我们没有数据，但被要求对其进行缩减呢？同样，如果我们没有数据，但被要求逐步添加到它呢？

这就是身份元素派上用场的时候！它可以是缺失数据的初始值。

### 幺半群的更多例子

列表是幺半群。将它们组合的操作只是连接。许多类型的容器也是幺半群，包括单子。

### 什么不是幺半群？

整数不是幺半群，但加法下的整数（一种组合方式）是幺半群。

整数（从 1 开始的整数），甚至加法下的整数都不是幺半群。加法的中性元素是什么？答案是零。

发票不是幂等性：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/lrn-fp-go/img/0b8f0dc3-8f8b-4661-bfbc-136ea1ba44c6.png)

我们如何组合两张发票？

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/lrn-fp-go/img/412e3faf-2ded-4b05-99c7-1c1353b2a4a8.png)

添加发票意味着什么？我们要合并颜色还是以某种方式将它们混合在一起？如果我们堆叠它们，除了从列表中取出顶部的那个之外，我们怎么能对它们做任何事情？我们如何组合客户地址？当然，我们可以添加工作订单号，1,000 + 1,000 = 2,000，但对我们有什么价值呢？

我们怎么可能添加发票？也许如果我们选择一些具有统计性质的字段？

## 幂等性示例

我们将在这里涵盖三种类型的幂等性：

+   名字幂等性

+   Int 切片幂等性

+   行项目幂等性

没错。我们要把那张发票变成一个幂等性！

### 名字幂等性

让我们看看我们可以用一个名字做些什么。首先，我们定义一个具有两种方法`Append`和`Zero`的接口。我们将我们的名字包装在`nameContainer`中。

我们的`nameContainer`是一个结构体，有一个字符串字段`name`。我们的`Append`方法将给定的名字附加到长名字字符串中，该字符串存储在神奇的`nameContainer`中。我们名字的零态射是一个空字符串。

`src/monoid/name_monoid.go`的内容如下：

```go
package monoid

type NameMonoid interface {
   Append(s string) NameMonoid
   Zero() string
}

func WrapName(s string) NameMonoid {
   return nameContainer{name: s}
}

type nameContainer struct {
   name string
}

func (s nameContainer) Append(name string) NameMonoid {
   s.name = s.name + name
   return s
}

func (nameContainer) Zero() string {
   return ""
}

func (s nameContainer) String() string {
   return s.name
}
```

`main.go`看起来是这样的：

```go
package main

import (
   "monoid"
 "fmt"
)

func main() {

   const name = "Alice"
 stringMonoid := monoid.WrapName(name)
   fmt.Println("NameMonoid")
   fmt.Println("Initial state:", stringMonoid)
   fmt.Println("Zero:", stringMonoid.Zero())
   fmt.Println("1st application:", stringMonoid.Append(name))
   fmt.Println("Chain applications:", stringMonoid.Append(name).Append(name))
```

#### 名字幂等性终端会话

让我们运行我们的幂等性：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/lrn-fp-go/img/00863fff-a211-46a6-b700-096d647b1250.png)

在这里，我们运行了我们的应用程序并获得了良好的结果。初始状态是 Alice，**Zero**值是空字符串；在第一次附加后，我们得到**AliceAlice**，当我们再附加一次时，我们得到**AliceAliceAlice**。

##### Int 切片幂等性

让我们看看我们可以用一些整数做些什么。

首先，我们定义一个具有两种方法`Append`和`Zero`的接口。我们将我们的整数包装在`intContainer`中。`intContainer`是一个结构体，有一个整数字段`ints`。我们的`Append`方法将给定的整数切片附加到它正在构建的`ints`切片中，该切片存储在神奇的`intContainer`中。切片的`Zero`态射是`nil`。

以下是`src/monoid/int_monoid.go`的内容：

```go
package monoid

type IntMonoid interface {
   Zero() []int
   Append(i ...int) IntMonoid
   Reduce() int
}

func WrapInt(ints []int) IntMonoid {
return intContainer{ints: ints}
}

type intContainer struct {
   ints []int
}

func (intContainer) Zero() []int {
return nil
}

func (i intContainer) Append(ints ...int) IntMonoid {
   i.ints = append(i.ints, ints...)
return i
}

func (i intContainer) Reduce() int {
   total := 0
 for _, item := range i.ints {
      total += item
   }
return total
}

```

这与名字幂等性的逻辑几乎相同，只是`Reduce`方法不同。`Reduce`方法将允许我们使用我们的二进制运算符，加法，将所有整数与我们的`intMonoid`容器中的所有整数相结合，并得到一个总和。

`main.go`的内容如下：

```go
ints := []int{1, 2, 3}
intMonoid := monoid.WrapInt(ints)
fmt.Println("\nIntMonoid")
fmt.Println("Initial state:", intMonoid)
fmt.Println("Zero:", intMonoid.Zero())
fmt.Println("1st application:", intMonoid.Append(ints...))
fmt.Println("Chain applications:", intMonoid.Append(ints...).Append(ints...))
fmt.Println("Reduce chain:", intMonoid.Append(ints...).Append(ints...).Reduce())
```

我们调用了与`nameMonoid`相同的方法列表，并获得了正确的结果。有趣的一行是最后一行，我们在其中链式调用我们的附加方法，然后调用 Reduce 来总结我们的整数：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/lrn-fp-go/img/4e8a85ac-c638-49da-a812-1693649b8ac4.png)

Int 切片幂等性终端会话

##### 行项目切片幂等性

让我们看看我们可以用一些行项目做些什么。

首先，我们定义一个具有三种方法`Append`，`Zero`和`Reduce`的接口。我们将我们的行项目包装在`lineitemContainer`中。我们的`lineitemContainer`是一个结构体，有三个字段对应于我们发票的行项目：

```go
type Lineitem struct {
   Quantity   int
   Price     int
   ListPrice  int
}
```

我们的`Append`方法将给定的行项目附加到正在构建的行项目切片中，该切片存储在神奇的`lineitemContainer`中。

切片的`Zero`态射是`nil`。

`src/monoid/lineitem_monoid.go`文件将包含以下代码：

```go
package monoid

type LineitemMonoid interface {
   Zero() []int
   Append(i ...int) LineitemMonoid
   Reduce() int
}

func WrapLineitem(lineitems []Lineitem) lineitemContainer {
return lineitemContainer{lineitems: lineitems}
}

type Lineitem struct {
   Quantity   int
   Price     int
   ListPrice  int
}

type lineitemContainer struct {
   lineitems []Lineitem
}

func (lineitemContainer) Zero() []Lineitem {
return nil
}

func (i lineitemContainer) Append(lineitems ...Lineitem) lineitemContainer {
   i.lineitems = append(i.lineitems, lineitems...)
return i
}

func (i lineitemContainer) Reduce() Lineitem {
   totalQuantity := 0
 totalPrice := 0
 totalListPrice := 0
 for _, item := range i.lineitems {
      totalQuantity += item.Quantity
      totalPrice += item.Price
      totalListPrice += item.ListPrice
   }
return Lineitem{totalQuantity, totalPrice, totalListPrice}
}
```

这与`Int`切片幂等性的逻辑几乎相同，只是`Reduce`方法不同。`Reduce`方法将允许我们使用我们的二进制运算符，加法，将所有行项目字段与我们的`lineitemMonoid`容器中的所有行项目相结合，并得到一个总和。

`main.go`文件将包含以下代码：

```go
lineitems := []monoid.Lineitem{
   {1, 12978, 22330},
   {2, 530, 786},
   {5, 270, 507},
}
lineitemMonoid := monoid.WrapLineitem(lineitems)
fmt.Println("\nLineItemMonoid")
fmt.Println("Initial state:", lineitemMonoid)
fmt.Println("Zero:", lineitemMonoid.Zero())
fmt.Println("1st application:", lineitemMonoid.Append(lineitems...))
fmt.Println("Chain applications:", lineitemMonoid.Append(lineitems...).Append(lineitems...))
fmt.Println("Reduce chain:", lineitemMonoid.Append(lineitems...).Append(lineitems...).Reduce())
```

这与我们验证其他幂等性的内容相同。我们的输入值，行项目，是一个包含三个行项目元组的切片。验证`Reduce`的数学是否正确。

##### Int 切片幂等性终端会话

看着输出的最后一行，我们可以看到我们已经调用了我们的`Reduce`函数来求和我们的总数（`totalQuantity`，`totalPrice`和`totalListPrice`）：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/lrn-fp-go/img/43b2d198-4888-4d14-b678-1d996b294807.png)

为了快速手动验证，让我们看一下`totalQuantity`--*1+2+5+1+2+5+1+2+5 = 24*。看起来不错！

## 总结

在这一章中，我们学会了如何使用工具来解决 Go 语言中由于其不支持泛型而引起的问题。我们能够使用这些工具来通过从正确定义的基本类型开始，在我们的 Go 代码中生成类似下划线的特性。不再担心潜在的泛型支持会减慢我们的运行时可执行文件（就像 Java 一样），我们因意外的生产力提升而欢欣鼓舞。

我们继续前进进入纯函数式编程的领域，我们解决了函数组合的概念。有了`g.f(x) == g(f(x))`在我们的工具箱中，我们研究了函子，并学会了如何转换项目列表。我们链接了我们的映射，甚至学会了律师如何使用遗忘函子为他们的客户在法庭上赢得案件。

我们用单子结束了这一章。我们不仅学习了单子的代数定律，还实现了它们。我们链接了`Append`方法，甚至写了一些规约。

在下一章中，我们将继续走向纯粹的启蒙之路，保持对更简单的代码和改进的错误处理的追求。
