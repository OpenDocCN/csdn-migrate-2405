# 精通 Go 并发（一）

> 原文：[`zh.annas-archive.org/md5/5C14031AC553348345D455C9E701A474`](https://zh.annas-archive.org/md5/5C14031AC553348345D455C9E701A474)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 前言

我就是喜欢新的编程语言。也许是因为对现有语言的熟悉和厌倦，对现有工具、语法、编码约定和性能的挫败感。也许我只是在寻找那个“统治它们所有”的语言。无论原因是什么，每当有新的或实验性的语言发布时，我都会迫不及待地去尝试。

这是一个新语言和语言设计的黄金时代。想想看：C 语言是在 20 世纪 70 年代初发布的——那个时候资源是如此稀缺，以至于冗长、清晰和语法逻辑经常被节俭所取代。今天我们使用的大多数语言要么是在这个时代原创写成的，要么直接受到了这些语言的影响。

自 20 世纪 80 年代末和 90 年代初以来，强大的新语言和范式——Perl、Python、Ruby、PHP 和 JavaScript——已经成为了一个不断扩大的用户群体，并成为最受欢迎的语言之一（与 C、C++和 Java 等老牌语言一样）。多线程、内存缓存和 API 使多个进程、不同的语言、应用程序，甚至是不同的操作系统能够协同工作。

虽然这很棒，但直到最近，有一个领域一直未得到很好的满足：强大的、编译的、跨平台的语言，支持并发，面向系统程序员。

很少有语言符合这些参数。当然，已经有一些低级语言满足了其中的一些特征。Erlang 和 Haskell 在功能和语言设计方面都符合要求，但作为函数式语言，对于从 C/Java 背景转向系统程序员来说，它们构成了一个学习障碍。Objective-C 和 C#相对容易、强大，并且支持并发，但它们与特定操作系统绑定，使得为其他平台编程变得困难。我们刚提到的语言（Python、JavaScript 等）虽然非常流行，但它们大多是解释性语言，将性能放在了次要位置。你可以用它们中的大多数来进行系统编程，但在许多方面，这就像是把方形木栓塞进圆孔。因此，当谷歌在 2009 年宣布推出 Go 时，我的兴趣被激起了。当我看到是谁在项目背后（稍后会详细介绍），我感到非常高兴。当我看到这种语言及其设计的实际运行时，我感到非常幸福。

在过去的几年里，我一直在使用 Go 来替换之前用 C、Java、Perl 和 Python 编写的系统应用程序。我对结果非常满意。几乎在每一个实例中，使用 Go 都改进了这些应用程序。它与 C 的良好兼容性是系统程序员寻求尝试 Go 的另一个巨大卖点。

有一些最优秀的语言设计（以及编程一般）的大脑支持，Go 有着光明的未来。

多年来——实际上是几十年来——编写服务器和网络接口的选择一直不多。如果你被要求编写一个，你可能会选择 C、C++或 Java。虽然它们当然可以处理这个任务，而且它们现在都以某种方式支持并发和并行，但它们并不是为此而设计的。

谷歌汇集了一支团队，其中包括一些编程界的巨头——贝尔实验室的 Rob Pike 和 Ken Thompson 以及曾参与谷歌 JavaScript 实现 V8 的 Robert Griesemer——设计了一种现代的、并发的语言，开发便利性是首要考虑的。

为了做到这一点，团队专注于一些替代方案中的一些痛点，具体如下：

+   动态类型的语言在最近几年变得非常流行。Go 避开了 Java 或 C++的显式“繁琐”类型系统。Go 使用类型推断，这节省了开发时间，但仍然是强类型的。

+   并发性、并行性、指针/内存访问和垃圾回收在上述语言中都很难处理。Go 让这些概念可以像你想要或需要的那样简单或复杂。

+   作为一种较新的语言，Go 专注于多核设计，这在 C++等语言中是必要的事后考虑。

+   Go 的编译器速度超快；它的速度非常快，以至于有一些实现将 Go 代码视为解释执行。

+   尽管 Google 设计 Go 是一种系统语言，但它足够多才多艺，可以以多种方式使用。当然，对先进、廉价的并发性的关注使其成为网络和系统编程的理想选择。

+   Go 的语法比较宽松，但使用上比较严格。这意味着 Go 会让你在一些词法标记上有点懒散，但你仍然必须编写基本紧凑的代码。由于 Go 提供了一个格式化工具来尝试澄清你的代码，因此在编码时你也可以花更少的时间来关注可读性问题。

# 本书涵盖的内容

第一章，“Go 中并发的介绍”，介绍了 goroutines 和通道，并将比较 Go 处理并发的方式与其他语言的方法。我们将利用这些新概念构建一些基本的并发应用程序。

第二章，“理解并发模型”，侧重于资源分配、共享内存（以及何时不共享）和数据。我们将研究通道和通道的通道，并解释 Go 内部如何管理并发。

第三章，“开发并发策略”，讨论了设计应用程序以最佳方式利用 Go 中并发工具的方法。我们将看一些可用的第三方包，它们可以在你的策略中发挥作用。

第四章，“应用程序中的数据完整性”，着眼于确保 goroutines 和通道的委托在单线程和多线程应用程序中保持状态。

第五章，“锁、阻塞和更好的通道”，探讨了 Go 如何在开箱即用时避免死锁，以及在哪里以及何时尽管 Go 的语言设计仍然可能发生死锁。

第六章，“C10K – 一个非阻塞的 Go Web 服务器”，解决了互联网上最著名和最受尊敬的挑战之一，并尝试使用核心 Go 包来解决它。然后我们将完善产品，并使用常见的基准测试工具进行测试。

第七章，“性能和可伸缩性”，侧重于挤出并发 Go 代码的最大潜力，最大限度地利用资源，并考虑和减轻第三方软件对自身的影响。我们将为我们的 Web 服务器添加一些额外的功能，并讨论其他可以使用这些包的方式。

第八章，“并发应用程序架构”，侧重于何时何地实施并发模式，何时如何利用并行性来充分利用先进的硬件，以及如何确保数据一致性。

第九章，“在 Go 中记录和测试并发”，侧重于测试和部署应用程序的特定于操作系统的方法。我们还将探讨 Go 与各种代码存储库的关系。

第十章, *高级并发和最佳实践*，探讨了更复杂和先进的技术，包括复制 Go 核心中不可用的并发特性。

# 您需要为本书做好准备

要跟随本书的示例工作，您需要一台运行 Windows、OS X 或支持 Go 的许多 Linux 变体的计算机。对于本书，我们的 Linux 示例和说明参考了 Ubuntu。

如果您尚未安装 Go 1.3 或更新版本，您需要从[`golang.org/`](http://golang.org/)的二进制下载页面或通过操作系统的软件包管理器获取它。

要使用本书中的所有示例，您还需要安装以下软件：

+   MySQL ([`dev.mysql.com/downloads/`](http://dev.mysql.com/downloads/))

+   Couchbase ([`www.couchbase.com/download`](http://www.couchbase.com/download))

您选择的集成开发环境是个人偏好的问题，任何与开发人员合作过的人都可以证明这一点。也就是说，有些 IDE 比其他语言更适合，有些对 Go 的支持更好。本作者使用 Sublime Text，它非常适合 Go，体积轻巧，并允许您直接在 IDE 内构建。您在哪里看到代码截图，都将来自 Sublime Text 内部。

虽然 Go 代码有很好的内置支持，但 Sublime Text 还有一个名为 GoSublime 的不错的插件集，可在[`github.com/DisposaBoy/GoSublime`](https://github.com/DisposaBoy/GoSublime)上获得。

Sublime Text 并非免费，但有免费的评估版本可供使用，没有时间限制。它在 Windows、OS X 和 Linux 变体上都可用，网址是[`www.sublimetext.com/`](http://www.sublimetext.com/)。

# 本书适合的读者是谁

如果您是具有一定 Go 和并发知识的系统或网络程序员，但想了解用 Go 编写的并发系统的实现，那么这本书适合您。本书的目标是使您能够在 Go 中编写高性能、可扩展、资源节约的系统和网络应用。

在本书中，我们将编写一些基本和稍微不那么基本的网络和系统应用程序。假定您以前曾使用过这些类型的应用程序。如果没有，可能需要进行一些课外学习，以便能够充分消化这些内容。

# 惯例

在本书中，您将找到一些区分不同信息类型的文本样式。以下是一些这些样式的示例，以及它们的含义解释。

文本中的代码字，数据库表名，文件夹名，文件名，文件扩展名，路径名，虚拟 URL，用户输入和 Twitter 句柄显示如下："在每个请求之后调用`setProxy`函数，并且您可以将其视为处理程序中的第一行。"

代码块设置如下：

```go
package main

import
(
"net/http"
"html/template"
"time"
"regexp"
"fmt"
"io/ioutil"
"database/sql"
"log"
"runtime"
_ "github.com/go-sql-driver/mysql"
)
```

当我们希望引起您对代码块的特定部分的注意时，相关行或项目将以粗体显示：

```go
package main

import (
  "fmt"
)

func stringReturn(text string) string {
 return text
}

func main() {
 myText := stringReturn("Here be the code")
  fmt.Println(myText)
}
```

任何命令行输入或输出都以以下方式编写：

```go
go get github.com/go-sql-driver/mysql

```

**新术语**和**重要单词**以粗体显示。例如，屏幕上看到的单词，菜单或对话框中的单词等，会在文本中以这种方式出现："如果您通过将文件拖到**拖放文件到此处上传**框中来上传文件，几秒钟后您会看到文件在 Web 界面中被标记为已更改。"

### 注意

警告或重要说明会以以下方式出现在框中。

### 提示

提示和技巧会以这种方式出现。


# 第一章：Go 中并发的介绍

虽然 Go 既是一个很好的通用语言，也是一个低级系统语言，但它的主要优势之一是内置的并发模型和工具。许多其他语言都有第三方库（或扩展），但固有的并发性是现代语言独有的，也是 Go 设计的核心特性。

尽管毫无疑问，Go 在并发方面表现出色——正如我们将在本书中看到的那样——但它具有许多其他语言所缺乏的一套强大的工具来测试和构建并发、并行和分布式代码。

足够谈论 Go 的奇妙并发特性和工具了，让我们开始吧。

# 介绍 goroutines

处理并发的主要方法是通过 goroutine。诚然，我们的第一段并发代码（在前言中提到）并没有做太多事情，只是简单地输出交替的“hello”和“world”，直到整个任务完成。

以下是该代码：

```go
package main

import (
  "fmt"
  "time"
)

type Job struct {
  i int
  max int
  text string
}

func outputText(j *Job) {
  for j.i < j.max {
    time.Sleep(1 * time.Millisecond)
    fmt.Println(j.text)
    j.i++
  }
}

func main() {
  hello := new(Job)
  world := new(Job)

  hello.text = "hello"
  hello.i = 0
  hello.max = 3

  world.text = "world"
  world.i = 0
  world.max = 5

  go outputText(hello)
  outputText(world)

}
```

### 提示

**下载示例代码**

您可以从您在[`www. packtpub.com`](http://www.%20packtpub.com)的帐户中购买的所有 Packt 图书的示例代码文件。如果您在其他地方购买了这本书，您可以访问[`www.packtpub.com/support`](http://www.packtpub.com/support)并注册，以便将文件直接发送到您的邮箱。

但是，如果你回想一下我们为祖母筹划惊喜派对的现实例子，这正是事情通常必须用有限或有限的资源来管理的方式。这种异步行为对于某些应用程序的平稳运行至关重要，尽管我们的例子基本上是在真空中运行的。

您可能已经注意到我们早期例子中的一个怪癖：尽管我们首先在`hello`结构上调用了`outputText()`函数，但我们的输出始于`world`结构的文本值。为什么呢？

作为异步的，当调用 goroutine 时，它会等待阻塞代码完成后再开始并发。您可以通过在下面的代码中用 goroutine 替换`world`结构上的`outputText()`函数调用来测试这一点：

```go
  go outputText(hello)
  go outputText(world)
```

如果你运行这个，你将得不到任何输出，因为主函数结束了，而异步 goroutines 正在运行。有几种方法可以阻止这种情况，在主函数执行完毕并退出程序之前看到输出。经典的方法只是在执行之前要求用户输入，允许您直接控制应用程序何时结束。您还可以在主函数的末尾放置一个无限循环，如下所示：

```go
for {}
```

更好的是，Go 还有一个内置的机制，即`sync`包中的`WaitGroup`类型。

如果您在代码中添加一个`WaitGroup`结构，它可以延迟主函数的执行，直到所有 goroutines 完成。简单来说，它允许您设置所需的迭代次数，以便在允许应用程序继续之前从 goroutines 获得完成的响应。让我们在下一节中看一下对我们“Hello World”应用程序的微小修改。

## 一个耐心的 goroutine

从这里开始，我们将实现一个`WaitGroup`结构，以确保我们的 goroutines 在继续应用程序之前完全运行。在这种情况下，当我们说“patient”时，这与我们在先前的例子中看到的 goroutines 在父方法之外运行的方式形成对比。在下面的代码中，我们将实现我们的第一个`Waitgroup`结构：

```go
package main

import (
  "fmt"
  "sync"
  "time"
)

type Job struct {
  i int
  max int
  text string
}

func outputText(j *Job, goGroup *sync.WaitGroup) {
  for j.i < j.max {
    time.Sleep(1 * time.Millisecond)
    fmt.Println(j.text)
    j.i++
  }
  goGroup.Done()
}

func main() {

  goGroup := new(sync.WaitGroup)
  fmt.Println("Starting")

  hello := new(Job)
  hello.text = "hello"
  hello.i = 0
  hello.max = 2

  world := new(Job)
  world.text = "world"
  world.i = 0
  world.max = 2

  go outputText(hello, goGroup)
  go outputText(world, goGroup)

  goGroup.Add(2)
  goGroup.Wait()

}
```

让我们来看看以下代码的变化：

```go
  goGroup := new(sync.WaitGroup)
```

在这里，我们声明了一个名为`goGroup`的`WaitGroup`结构。这个变量将接收我们的 goroutine 函数在允许程序退出之前完成*x*次的通知。以下是在`WaitGroup`中发送这种期望的一个例子：

```go
  goGroup.Add(2)
```

`Add()`方法指定了`goGroup`在满足等待之前应该接收多少个`Done`消息。在这里，我们指定了`2`，因为我们有两个异步运行的函数。如果你有三个 goroutine 成员，但仍然调用了两个，你可能会看到第三个的输出。如果你向`goGroup`添加了一个大于两的值，例如`goGroup.Add(3)`，那么`WaitGroup`将永远等待并发死锁。

考虑到这一点，你不应该手动设置需要等待的 goroutines 的数量；最好是在范围内进行计算或明确处理。这就是我们告诉`WaitGroup`等待的方式：

```go
  goGroup.Wait()
```

现在，我们等待。这段代码会因为和`goGroup.Add(3)`一样的原因而失败；`goGroup`结构体从未接收到我们的 goroutines 完成的消息。所以，让我们按照下面的代码片段来做：

```go
func outputText(j *Job, goGroup *sync.WaitGroup) {
  for j.i < j.max {
    time.Sleep(1 * time.Millisecond)
    fmt.Println(j.text)
    j.i++
  }
  goGroup.Done()
}
```

我们只对前言中的`outputText()`函数进行了两处更改。首先，我们在第二个函数参数中添加了一个指向我们的`goGroup`的指针。然后，在所有迭代完成后，我们告诉`goGroup`它们都完成了。

# 实现 defer 控制机制

在这里，我们应该花点时间来谈谈 defer。Go 有一个优雅的 defer 控制机制的实现。如果你在其他语言中使用了 defer（或者类似功能），这会看起来很熟悉——这是一种有用的方式，可以延迟执行语句，直到函数的其余部分完成。

在大多数情况下，这只是一种语法糖，允许你将相关操作放在一起，即使它们不会一起执行。如果你曾经写过类似以下伪代码的东西，你会知道我的意思：

```go
x = file.open('test.txt')
int longFunction() {
…
}
x.close();
```

你可能知道由于代码之间的大“距离”而导致的痛苦。在 Go 中，你实际上可以编写类似以下的代码：

```go
package main

import(
"os"
)

func main() {

  file, _ := os.Create("/defer.txt")

  defer file.Close()

  for {

    break

  }

}
```

这并没有任何实际的功能优势，除了使代码更清晰、更易读，但这本身就是一个很大的优点。延迟调用是按照它们定义的顺序的相反顺序执行的，或者说是后进先出。你还应该注意，任何通过引用传递的数据可能处于意外的状态。

例如，参考以下代码片段：

```go
func main() {

  aValue := new(int)

  defer fmt.Println(*aValue)

  for i := 0; i < 100; i++ {
    *aValue++
  }

}
```

这将返回`0`，而不是`100`，因为这是整数的默认值。

### 注意

*Defer*不同于其他语言中的*deferred*（或者 future/promises）。我们将在第二章中讨论 Go 的实现和 future 和 promise 的替代方案，*理解并发模型*。

## 使用 Go 的调度程序

在其他语言中，许多并发和并行应用程序的软线程和硬线程的管理是在操作系统级别处理的。这被认为是固有的低效和昂贵，因为操作系统负责上下文切换，处理多个进程。当应用程序或进程可以管理自己的线程和调度时，它会导致更快的运行时间。授予我们应用程序和 Go 调度程序的线程具有较少的操作系统属性，需要考虑上下文切换，从而减少了开销。

如果你仔细想想，这是不言自明的——你需要处理的东西越多，管理所有的球就越慢。Go 通过使用自己的调度程序消除了这种机制的自然低效性。

这实际上只有一个怪癖，你会很早就学到：如果你从不让出主线程，你的 goroutines 会以意想不到的方式执行（或者根本不执行）。

另一种看待这个问题的方式是，goroutine 必须在并发有效并开始之前被阻塞。让我们修改我们的示例，并包括一些文件 I/O 记录来演示这个怪癖，如下面的代码所示：

```go
package main

import (
  "fmt"
  "time"
  "io/ioutil"
)

type Job struct {
  i int
  max int
  text string
}

func outputText(j *Job) {
  fileName := j.text + ".txt"
  fileContents := ""
  for j.i < j.max {
    time.Sleep(1 * time.Millisecond)
    fileContents += j.text
    fmt.Println(j.text)
    j.i++
  }
  err := ioutil.WriteFile(fileName, []byte(fileContents), 0644)
  if (err != nil) {
    panic("Something went awry")
  }

}

func main() {

  hello := new(Job)
  hello.text = "hello"
  hello.i = 0
  hello.max = 3

  world := new(Job)
  world.text = "world"
  world.i = 0
  world.max = 5

  go outputText(hello)
  go outputText(world)

}
```

从理论上讲，改变的只是我们现在使用文件操作将每个操作记录到不同的文件中（在这种情况下是`hello.txt`和`world.txt`）。然而，如果你运行这个程序，不会创建任何文件。

在我们的最后一个例子中，我们使用了`sync.WaitSync`结构来强制主线程延迟执行，直到异步任务完成。虽然这样可以工作（而且优雅），但它并没有真正解释*为什么*我们的异步任务失败。如前所述，您还可以利用阻塞代码来防止主线程在其异步任务完成之前完成。

由于 Go 调度器管理上下文切换，每个 goroutine 必须将控制权让回主线程，以安排所有这些异步任务。有两种方法可以手动完成这个过程。一种方法，也可能是理想的方法，是`WaitGroup`结构。另一种是 runtime 包中的`GoSched()`函数。

`GoSched()`函数暂时让出处理器，然后返回到当前的 goroutine。考虑以下代码作为一个例子：

```go
package main

import(
  "runtime"
  "fmt"
)

func showNumber(num int) {
  fmt.Println(num)
}

func main() {
  iterations := 10

  for i := 0; i<=iterations; i++ {

    go showNumber(i)

  }
  //runtime.Gosched()
  fmt.Println("Goodbye!")

}
```

在`runtime.Gosched()`被注释掉并且在`"runtime"`之前的下划线被移除的情况下运行这段代码，你将只会看到`Goodbye!`。这是因为在`main()`函数结束之前，没有保证有多少 goroutines 会完成。

正如我们之前学到的，您可以在结束应用程序的执行之前显式等待有限数量的 goroutines。但是，`Gosched()`允许（在大多数情况下）具有相同的基本功能。删除`runtime.Gosched()`之前的注释，您应该在`Goodbye!`之前打印出 0 到 10。

只是为了好玩，尝试在多核服务器上运行此代码，并使用`runtime.GOMAXPROCS()`修改您的最大处理器，如下所示：

```go
func main() {

  runtime.GOMAXPROCS(2)
```

此外，将您的`runtime.Gosched()`推到绝对末尾，以便所有 goroutines 在`main`结束之前有机会运行。

得到了一些意外的东西？这并不意外！您可能会得到完全混乱的 goroutines 执行，如下面的截图所示：

![使用 Go 的调度器](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/ms-cncr-go/img/00002.jpeg)

虽然没有必要完全演示如何在多个核心上处理 goroutines 可能会很棘手，但这是展示为什么在它们之间进行通信（和 Go 调度器）很重要的最简单的方法之一。

您可以使用`GOMAXPROCS > 1`来调试这个，并在您的 goroutine 调用周围加上时间戳显示，如下所示：

```go
  tstamp := strconv.FormatInt(time.Now().UnixNano(), 10)
  fmt.Println(num, tstamp)
```

### 注意

记得在这里导入`time`和`strconv`父包。

这也是一个很好的地方来看并发并将其与并行执行进行比较。首先，在`showNumber()`函数中添加一秒的延迟，如下面的代码片段所示：

```go
func showNumber(num int) {
  tstamp := strconv.FormatInt(time.Now().UnixNano(), 10)
  fmt.Println(num,tstamp)
  time.Sleep(time.Millisecond * 10)
}
```

然后，在`showNumber()`函数之前删除 goroutine 调用，并使用`GOMAXPROCS(0)`，如下面的代码片段所示：

```go
  runtime.GOMAXPROCS(0)
  iterations := 10

  for i := 0; i<=iterations; i++ {
    showNumber(i)
  }
```

正如预期的那样，您会得到 0-10 之间的数字，它们之间有 10 毫秒的延迟，然后输出`Goodbye!`。这是直接的串行计算。

接下来，让我们将`GOMAXPROCS`保持为零以使用单个线程，但是恢复 goroutine 如下：

```go
go showNumber(i)
```

这与之前的过程相同，只是一切都会在相同的时间范围内执行，展示了执行的并发性质。现在，继续将您的`GOMAXPROCS`更改为两个并再次运行。如前所述，只有一个（或可能两个）时间戳，但顺序已经改变，因为一切都在同时运行。

Goroutines 不一定是基于线程的，但它们感觉像是。当 Go 代码被编译时，goroutines 会在可用的线程上进行多路复用。这正是为什么 Go 的调度器需要知道什么正在运行，什么需要在应用程序生命周期结束之前完成等等的原因。如果代码有两个线程可用，那就会使用两个线程。

## 使用系统变量

那么如果您想知道您的代码有多少个线程可用呢？

Go 有一个从 runtime 包函数`GOMAXPROCS`返回的环境变量。要找出可用的内容，您可以编写一个类似以下代码的快速应用程序：

```go
package main

import (
  "fmt"
  "runtime"
)

func listThreads() int {

  threads := runtime.GOMAXPROCS(0)
  return threads
}

func main() {
  runtime.GOMAXPROCS(2)
  fmt.Printf("%d thread(s) available to Go.", listThreads())

}
```

在这个上进行简单的 Go 构建将产生以下输出：

```go
2 thread(s) available to Go.

```

传递给`GOMAXPROCS`的`0`参数（或没有参数）意味着没有进行更改。你可以在那里放入另一个数字，但正如你所想象的那样，它只会返回 Go 实际可用的内容。你不能超过可用的核心，但你可以限制你的应用程序使用少于可用的核心。

`GOMAXPROCS()`调用本身返回一个整数，表示*之前*可用的处理器数量。在这种情况下，我们首先将其设置为两，然后设置为零（没有更改），返回两。

值得注意的是，增加`GOMAXPROCS`有时可能会*降低*应用程序的性能。

在更大的应用程序和操作系统中存在上下文切换的惩罚，增加使用的线程数量意味着 goroutines 可以在多个线程之间共享，并且 goroutines 的轻量级优势可能会被牺牲。

如果你有一个多核系统，你可以很容易地使用 Go 的内部基准测试功能来测试这一点。我们将在第五章*锁、阻塞和更好的通道*和第七章*性能和可伸缩性*中更仔细地研究这个功能。

runtime 包还有一些其他非常有用的环境变量返回函数，比如`NumCPU`、`NumGoroutine`、`CPUProfile`和`BlockProfile`。这些不仅方便调试，也有助于了解如何最好地利用资源。这个包还与 reflect 包很好地配合，reflect 包处理元编程和程序自我分析。我们将在第九章*Go 中的日志记录和测试并发*和第十章*高级并发和最佳实践*中更详细地讨论这一点。

# 理解 goroutines 与 coroutines

在这一点上，你可能会想，“啊，goroutines，我知道这些就是 coroutines。”嗯，是和不是。

coroutine 是一种协作式任务控制机制，但从其最简单的意义上讲，coroutine 并不是并发的。虽然 coroutines 和 goroutines 的使用方式类似，但 Go 对并发的关注提供了远不止状态控制和产出。在我们迄今为止看到的例子中，我们有可以称之为*愚蠢*的 goroutines。虽然它们在同一时间和地址空间中运行，但两者之间没有真正的通信。如果你看看其他语言中的 coroutines，你可能会发现它们通常并不一定是并发的或异步的，而是基于步骤的。它们会向`main()`和彼此产出，但两个 coroutine 之间可能并不一定会进行通信，而是依赖于一个集中的、明确编写的数据管理系统。

### 注意

**原始 coroutine**

coroutines 最初是由 Melvin Conway 为 COBOL 描述的。在他的论文《可分离转换图编译器的设计》中，他建议 coroutine 的目的是将程序分解为子任务，并允许它们独立运行，仅共享少量数据。

Goroutines 有时可能会违反 Conway 的 coroutines 的基本原则。例如，Conway 建议只应该有一个单向的执行路径；换句话说，A 后面是 B，然后是 C，然后是 D，依此类推，其中每个代表 coroutine 中的一个应用程序块。我们知道 goroutines 可以并行运行，并且可以以看似任意的顺序执行（至少没有方向）。到目前为止，我们的 goroutines 也没有共享任何信息；它们只是以共享的模式执行。

# 实现通道

到目前为止，我们已经涉足了能够做很多事情但不能有效地相互通信的并发进程。换句话说，如果你有两个进程占用相同的处理时间并共享相同的内存和数据，你必须知道哪个进程在哪个位置作为更大任务的一部分。

例如，一个应用程序必须循环遍历 Lorem Ipsum 的一个段落，并将每个字母大写，然后将结果写入文件。当然，我们实际上不需要一个并发应用程序来做这个事情（事实上，几乎任何处理字符串的语言都具有这个固有功能），但这是一个快速演示孤立 goroutine 潜在限制的方法。不久，我们将把这个原始示例转化为更实用的东西，但现在，这是我们大写示例的开始：

```go
package main

import (
  "fmt"
  "runtime"
  "strings"
)
var loremIpsum string
var finalIpsum string
var letterSentChan chan string

func deliverToFinal(letter string, finalIpsum *string) {
  *finalIpsum += letter
}

func capitalize(current *int, length int, letters []byte, 
  finalIpsum *string) {
  for *current < length {
    thisLetter := strings.ToUpper(string(letters[*current]))

    deliverToFinal(thisLetter, finalIpsum)
    *current++
  }
}

func main() {

  runtime.GOMAXPROCS(2)

  index := new(int)
  *index = 0
  loremIpsum = "Lorem ipsum dolor sit amet, consectetur adipiscing 
  elit. Vestibulum venenatis magna eget libero tincidunt, ac 
  condimentum enim auctor. Integer mauris arcu, dignissim sit amet 
  convallis vitae, ornare vel odio. Phasellus in lectus risus. Ut 
  sodales vehicula ligula eu ultricies. Fusce vulputate fringilla 
  eros at congue. Nulla tempor neque enim, non malesuada arcu 
  laoreet quis. Aliquam eget magna metus. Vivamus lacinia 
  venenatis dolor, blandit faucibus mi iaculis quis. Vestibulum 
  sit amet feugiat ante, eu porta justo."

  letters := []byte(loremIpsum)
  length := len(letters)

  go capitalize(index, length, letters, &finalIpsum)
  go func() {
    go capitalize(index, length, letters, &finalIpsum)
  }()

  fmt.Println(length, " characters.")
  fmt.Println(loremIpsum)
  fmt.Println(*index)
  fmt.Println(finalIpsum)

}
```

如果我们在这里以某种程度的并行性运行，但我们的 goroutine 之间没有通信，我们最终会得到一团糟的文本，如下面的截图所示：

![实现通道](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/ms-cncr-go/img/00003.jpeg)

由于 Go 中并发调度的不可预测性，可能需要多次迭代才能获得这个确切的输出。事实上，你可能永远也得不到确切的输出。

显然这样行不通。那么我们应该如何最好地构建这个应用程序呢？这里缺少的是同步，但我们也可以用更好的设计模式。

这是另一种将这个问题分解成片段的方法。与其让两个进程并行处理相同的事情，这充满了风险，不如让一个进程从`loremIpsum`字符串中取一个字母并将其大写，然后将其传递给另一个进程将其添加到我们的`finalIpsum`字符串中。

你可以把这想象成两个人坐在两张桌子前，每个人手上都有一叠信件。A 负责拿一封信并将其大写。然后他把信传给 B，然后 B 把它添加到`finalIpsum`堆栈中。为了做到这一点，我们将在我们的代码中实现一个通道，这个应用程序的任务是接收文本（在这种情况下是亚伯拉罕·林肯的葛底斯堡演说的第一行）并将每个字母大写。

## 基于通道的字母大写工厂排序

让我们以最后一个例子为例，通过尝试大写亚伯拉罕·林肯的葛底斯堡演说序言，来做一些（略微）更有意义的事情，同时减轻 Go 中并发的不可预测影响，如下面的代码所示：

```go
package main

import(
  "fmt"
  "sync"
  "runtime"
  "strings"
)

var initialString string
var finalString string

var stringLength int

func addToFinalStack(letterChannel chan string, wg 
  *sync.WaitGroup) {
  letter := <-letterChannel
  finalString += letter
  wg.Done()
}

func capitalize(letterChannel chan string, currentLetter string, 
  wg *sync.WaitGroup) {

  thisLetter := strings.ToUpper(currentLetter)
  wg.Done()
  letterChannel <- thisLetter  
}

func main() {

  runtime.GOMAXPROCS(2)
  var wg sync.WaitGroup

  initialString = "Four score and seven years ago our fathers 
  brought forth on this continent, a new nation, conceived in 
  Liberty, and dedicated to the proposition that all men are 
  created equal."
  initialBytes := []byte(initialString)

  var letterChannel chan string = make(chan string)

  stringLength = len(initialBytes)

  for i := 0; i < stringLength; i++ {
    wg.Add(2)

    go capitalize(letterChannel, string(initialBytes[i]), &wg)
    go addToFinalStack(letterChannel, &wg)

    wg.Wait()
  }

  fmt.Println(finalString)

}
```

你会注意到，我们甚至将这提升到了一个双核处理过程，并得到了以下输出：

```go
go run alpha-channel.go
FOUR SCORE AND SEVEN YEARS AGO OUR FATHERS BROUGHT FORTH ON THIS 
 CONTINENT, A NEW NATION, CONCEIVED IN LIBERTY, AND DEDICATED TO THE 
 PROPOSITION THAT ALL MEN ARE CREATED EQUAL.

```

输出正如我们所预期的那样。值得重申的是，这个例子是极端的过度，但我们很快将把这个功能转化为一个可用的实际应用程序。

所以这里发生了什么？首先，我们重新实现了`sync.WaitGroup`结构，以允许我们所有的并发代码在保持主线程活动的同时执行，如下面的代码片段所示：

```go
var wg sync.WaitGroup
...
for i := 0; i < stringLength; i++ {
  wg.Add(2)

  go capitalize(letterChannel, string(initialBytes[i]), &wg)
  go addToFinalStack(letterChannel, &wg)

  wg.Wait()
}
```

我们允许每个 goroutine 告诉`WaitGroup`结构我们已经完成了这一步。由于我们有两个 goroutine，我们将两个`Add()`方法排入`WaitGroup`结构的队列。每个 goroutine 负责宣布自己已经完成。

接下来，我们创建了我们的第一个通道。我们用以下代码行实例化一个通道：

```go
  var letterChannel chan string = make(chan string)
```

这告诉 Go 我们有一个通道，将向各种程序/ goroutine 发送和接收字符串。这本质上是所有 goroutine 的管理者。它还负责向 goroutine 发送和接收数据，并管理执行顺序。正如我们之前提到的，通道具有在内部上下文切换和无需依赖多线程的能力，使它们能够快速运行。

这个功能有内置的限制。如果你设计非并发或阻塞的代码，你将有效地从 goroutine 中移除并发。我们很快会更多地讨论这个问题。

我们通过`letterChannel`运行两个单独的 goroutine：`capitalize()`和`addToFinalStack()`。第一个简单地从构建的字节数组中获取一个字节并将其大写。然后，它将字节返回到通道，如下一行代码所示：

```go
letterChannel <- thisLetter
```

所有通过通道的通信都是以这种方式进行的。`<-`符号在语法上告诉我们数据将被发送回通道。从来不需要对这些数据做任何处理，但最重要的是要知道通道可以阻塞，至少在每个线程中，直到它接收到数据。您可以通过创建一个通道，然后对其不做任何有价值的事情来测试这一点，如下面的代码片段所示：

```go
package main

func doNothing()(string) {

  return "nothing"
}

func main() {

  var channel chan string = make(chan string)
  channel <- doNothing()

}
```

由于没有沿着通道发送任何东西，也没有实例化 goroutine，这导致了死锁。您可以通过创建一个 goroutine 并将通道带入全局空间来轻松解决这个问题，方法是在`main()`之外创建它。

### 注意

为了清晰起见，我们的示例在这里使用了局部范围的通道。尽可能保持这些全局范围，可以消除很多不必要的东西，特别是如果您有很多 goroutine，因为通道的引用可能会使您的代码变得混乱。

对于我们的整个示例，您可以将其视为下图所示：

![基于通道的字母大写工厂的排序](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/ms-cncr-go/img/00004.jpeg)

## 清理我们的 goroutine

您可能想知道为什么在使用通道时需要`WaitGroup`结构。毕竟，我们不是说过通道会被阻塞，直到它接收到数据吗？这是真的，但它需要另一段语法。

空或未初始化的通道将始终被阻塞。我们将在第七章*性能和可伸缩性*和第十章*高级并发和最佳实践*中讨论这种情况的潜在用途和陷阱。

您可以通过在`make`命令的第二个选项中指定通道缓冲区来决定通道如何阻塞应用程序。

### 缓冲或非缓冲通道

默认情况下，通道是非缓冲的，这意味着如果有一个准备接收的通道，它们将接受任何发送到它们的东西。这也意味着每个通道调用都会阻塞应用程序的执行。通过提供一个缓冲区，只有在发送了许多返回时，通道才会阻塞应用程序。

缓冲通道是同步的。为了保证异步性能，您需要通过提供缓冲区长度来进行实验。我们将在下一章中探讨确保我们的执行符合预期的方法。

### 注意

Go 的通道系统是基于**通信顺序进程**（**CSP**）的，这是一种设计并发模式和多处理的正式语言。当人们描述 goroutine 和通道时，您可能会单独遇到 CSP。

## 使用 select 语句

```go
switch, familiar to Go users and common among other languages:
```

```go
switch {

  case 'x':

  case 'y':

}
```

```go
select statement:
```

```go
select {

  case <- channelA:

  case <- channelB:

}
```

在`switch`语句中，右侧表达式表示一个值；在`select`中，它表示对通道的接收操作。`select`语句将阻塞应用程序，直到有一些信息通过通道发送。如果从未发送任何内容，应用程序将死锁，并且您将收到相应的错误。

如果两个接收操作同时发送（或者满足两个情况），Go 将以不可预测的方式对它们进行评估。

那么，这有什么用呢？让我们看一下字母大写应用程序的主函数的修改版本：

```go
package main

import(
  "fmt"  
  "strings"
)

var initialString string
var initialBytes []byte
var stringLength int
var finalString string
var lettersProcessed int
var applicationStatus bool
var wg sync.WaitGroup

func getLetters(gQ chan string) {

  for i := range initialBytes {
    gQ <- string(initialBytes[i])  

  }

}

func capitalizeLetters(gQ chan string, sQ chan string) {

  for {
    if lettersProcessed >= stringLength {
      applicationStatus = false
      break
    }
    select {
      case letter := <- gQ:
        capitalLetter := strings.ToUpper(letter)
        finalString += capitalLetter
        lettersProcessed++
    }
  }
}

func main() {

  applicationStatus = true;

  getQueue := make(chan string)
  stackQueue := make(chan string)

  initialString = "Four score and seven years ago our fathers brought forth on this continent, a new nation, conceived in Liberty, and dedicated to the proposition that all men are created equal."
  initialBytes = []byte(initialString)
  stringLength = len(initialString)
  lettersProcessed = 0

  fmt.Println("Let's start capitalizing")

  go getLetters(getQueue)
  capitalizeLetters(getQueue,stackQueue)

  close(getQueue)
  close(stackQueue)

  for {

    if applicationStatus == false {
      fmt.Println("Done")
      fmt.Println(finalString)
      break
    }

  }
}
```

这里的主要区别是我们现在有一个通道，它在两个并发运行的函数`getLetters`和`capitalizeLetters`之间监听数据。在底部，您将看到一个`for{}`循环，它会一直保持主动状态，直到`applicationStatus`变量设置为`false`。在下面的代码中，我们将每个字节作为字符串通过 Go 通道传递：

```go
func getLetters(gQ chan string) {

  for i := range initialBytes {
    gQ <- string(initialBytes[i])  

  }

}
```

`getLetters`函数是我们的主要 goroutine，它从构建自 Lincoln's 行的字节数组中获取单个字母。当函数迭代每个字节时，它通过`getQueue`通道发送该字母。

在接收端，我们有`capitalizeLetters`，它接收每个字母并将其大写，然后附加到我们的`finalString`变量上。让我们来看一下这个：

```go
func capitalizeLetters(gQ chan string, sQ chan string) {

  for {
    if lettersProcessed >= stringLength {
      applicationStatus = false
      break
    }
    select {
      case letter := <- gQ:
        capitalLetter := strings.ToUpper(letter)
        finalString += capitalLetter
        lettersProcessed++
    }
  }
}
```

关闭所有通道是至关重要的，否则我们的应用程序将陷入死锁。如果我们在这里永远不打破`for`循环，我们的通道将一直等待从并发进程接收，并且程序将陷入死锁。我们手动检查是否已将所有字母大写，然后才打破循环。

# 闭包和 goroutines

您可能已经注意到 Lorem Ipsum 中的匿名 goroutine：

```go
  go func() {
    go capitalize(index, length, letters, &finalIpsum)
  }()
```

虽然这并不总是理想的，但有很多地方内联函数最适合创建 goroutine。

描述这个最简单的方法是说一个函数不够大或重要，不值得拥有一个命名函数，但事实上，这更多的是关于可读性。如果您在其他语言中使用过 lambda 表达式，这可能不需要太多解释，但请尽量将这些保留给快速的内联函数。

在早期的示例中，闭包主要作为调用`select`语句的包装器或创建匿名 goroutines 来提供`select`语句。

由于函数在 Go 中是一等公民，因此不仅可以直接在代码中使用内联或匿名函数，还可以将它们传递给其他函数并从其他函数返回。

以下是一个示例，它将函数的结果作为返回值传递，使返回的函数之外的状态坚定。在这种情况下，我们将一个函数作为变量返回，并在返回的函数上迭代初始值。初始参数将接受一个字符串，每次调用返回的函数时都会根据单词长度进行修剪。

```go
import(
  "fmt"
  "strings"
)

func shortenString(message string) func() string {

  return func() string {
    messageSlice := strings.Split(message," ")
    wordLength := len(messageSlice)
    if wordLength < 1 {
      return "Nothingn Left!"
    }else {
      messageSlice = messageSlice[:(wordLength-1)]
      message = strings.Join(messageSlice, " ")
      return message
    }
  }
}

func main() {

  myString := shortenString("Welcome to concurrency in Go! ...")

  fmt.Println(myString())
  fmt.Println(myString())  
  fmt.Println(myString())  
  fmt.Println(myString())  
  fmt.Println(myString())  
  fmt.Println(myString())
}
```

一旦初始化并返回，我们设置消息变量，并且返回方法的每次运行都会迭代该值。这种功能允许我们避免在返回值上多次运行函数或不必要地循环，而可以使用闭包来处理这个问题，如上所示。

# 使用 goroutines 和通道构建网络爬虫

让我们拿这个几乎没什么用的大写应用程序，做一些实际的事情。在这里，我们的目标是构建一个基本的爬虫。这样做，我们将完成以下任务：

+   读取五个 URL

+   读取这些 URL 并将内容保存到字符串中

+   当所有 URL 都被扫描和读取时，将该字符串写入文件

这些类型的应用程序每天都在编写，并且它们是最能从并发和非阻塞代码中受益的应用程序之一。

可能不用说，但这并不是一个特别优雅的网络爬虫。首先，它只知道一些起始点——我们提供的五个 URL。此外，它既不是递归的，也不是线程安全的，就数据完整性而言。

也就是说，以下代码有效，并演示了我们如何使用通道和`select`语句：

```go
package main

import(
  "fmt"
  "io/ioutil"
  "net/http"
  "time"
)

var applicationStatus bool
var urls []string
var urlsProcessed int
var foundUrls []string
var fullText string
var totalURLCount int
var wg sync.WaitGroup

var v1 int
```

首先，我们有我们最基本的全局变量，我们将用它们来表示应用程序状态。`applicationStatus`变量告诉我们我们的爬虫进程已经开始，`urls`是我们的简单字符串 URL 的切片。其余的是成语数据存储变量和/或应用程序流程机制。以下代码片段是我们读取 URL 并将它们传递到通道的函数：

```go
func readURLs(statusChannel chan int, textChannel chan string) {

  time.Sleep(time.Millisecond * 1)
  fmt.Println("Grabbing", len(urls), "urls")
  for i := 0; i < totalURLCount; i++ {

    fmt.Println("Url", i, urls[i])
    resp, _ := http.Get(urls[i])
    text, err := ioutil.ReadAll(resp.Body)

    textChannel <- string(text)

    if err != nil {
      fmt.Println("No HTML body")
    }

    statusChannel <- 0

  }

}
```

`readURLs`函数假定`statusChannel`和`textChannel`用于通信，并循环遍历`urls`变量切片，在`textChannel`上返回文本，并在`statusChannel`上返回一个简单的 ping。接下来，让我们看一下将抓取的文本附加到完整文本的函数：

```go
func addToScrapedText(textChannel chan string, processChannel chan bool) {

  for {
    select {
    case pC := <-processChannel:
      if pC == true {
        // hang on
      }
      if pC == false {

        close(textChannel)
        close(processChannel)
      }
    case tC := <-textChannel:
      fullText += tC

    }

  }

}
```

我们使用`addToScrapedText`函数来累积处理过的文本并将其添加到主文本字符串中。当我们在`processChannel`上收到关闭信号时，我们也关闭了我们的两个主要通道。让我们看一下`evaluateStatus()`函数：

```go
func evaluateStatus(statusChannel chan int, textChannel chan string, processChannel chan bool) {

  for {
    select {
    case status := <-statusChannel:

      fmt.Print(urlsProcessed, totalURLCount)
      urlsProcessed++
      if status == 0 {

        fmt.Println("Got url")

      }
      if status == 1 {

        close(statusChannel)
      }
      if urlsProcessed == totalURLCount {
        fmt.Println("Read all top-level URLs")
        processChannel <- false
        applicationStatus = false

      }
    }

  }
}
```

在这个时刻，`evaluateStatus`函数所做的就是确定应用程序的整体范围内发生了什么。当我们通过这个通道发送一个`0`（我们前面提到的 ping）时，我们会增加我们的`urlsProcessed`变量。当我们发送一个`1`时，这是一个消息，我们可以关闭通道。最后，让我们看一下`main`函数：

```go
func main() {
  applicationStatus = true
  statusChannel := make(chan int)
  textChannel := make(chan string)
  processChannel := make(chan bool)
  totalURLCount = 0

  urls = append(urls, "http://www.mastergoco.com/index1.html")
  urls = append(urls, "http://www.mastergoco.com/index2.html")
  urls = append(urls, "http://www.mastergoco.com/index3.html")
  urls = append(urls, "http://www.mastergoco.com/index4.html")
  urls = append(urls, "http://www.mastergoco.com/index5.html")

  fmt.Println("Starting spider")

  urlsProcessed = 0
  totalURLCount = len(urls)

  go evaluateStatus(statusChannel, textChannel, processChannel)

  go readURLs(statusChannel, textChannel)

  go addToScrapedText(textChannel, processChannel)

  for {
    if applicationStatus == false {
      fmt.Println(fullText)
      fmt.Println("Done!")
      break
    }
    select {
    case sC := <-statusChannel:
      fmt.Println("Message on StatusChannel", sC)

    }
  }

}
```

这是我们上一个函数的基本推断，即大写函数。然而，这里的每个部分都负责读取 URL 或将其相应内容附加到较大的变量中。

在下面的代码中，我们创建了一种主循环，让您知道在`statusChannel`上何时抓取了一个 URL：

```go
  for {
    if applicationStatus == false {
      fmt.Println(fullText)
      fmt.Println("Done!")
      break
    }
    select {
      case sC := <- statusChannel:
        fmt.Println("Message on StatusChannel",sC)

    }
  }
```

通常，您会看到这被包装在`go func()`中，作为`WaitGroup`结构的一部分，或者根本没有包装（取决于您需要的反馈类型）。

在这种情况下，控制流是`evaluateStatus`，它作为一个通道监视器，让我们知道数据何时穿过每个通道，并在执行结束时结束。`readURLs`函数立即开始读取我们的 URL，提取底层数据并将其传递给`textChannel`。此时，我们的`addToScrapedText`函数接收每个发送的 HTML 文件并将其附加到`fullText`变量中。当`evaluateStatus`确定所有 URL 已被读取时，它将`applicationStatus`设置为`false`。此时，`main()`底部的无限循环退出。

如前所述，爬虫不能比这更基础，但是看到 goroutines 如何在一起工作的真实例子将为我们在接下来的章节中更安全和更复杂的例子做好准备。

# 总结

在本章中，我们学习了如何从简单的 goroutines 和实例化通道扩展到 goroutines 的基本功能，并允许并发进程内的跨通道、双向通信。我们看了一些创建阻塞代码的新方法，以防止我们的主进程在 goroutines 之前结束。最后，我们学习了使用 select 语句来开发反应式通道，除非沿着通道发送数据，否则它们是静默的。

在我们基本的网络蜘蛛示例中，我们将这些概念结合在一起，创建了一个安全、轻量级的过程，可以从一系列 URL 中提取所有链接，通过 HTTP 获取内容并存储结果响应。

在下一章中，我们将深入了解 Go 的内部调度如何管理并发，并开始使用通道来真正利用 Go 中并发的力量、节俭和速度。


# 第二章：理解并发模型

现在我们已经了解了 Go 的能力以及如何测试一些并发模型，我们需要更深入地了解 Go 最强大的功能，以了解如何最好地利用各种并发工具和模型。

我们玩了一些一般和基本的 goroutines，看看我们如何运行并发进程，但在我们开始通道之间的通信之前，我们需要看看 Go 是如何管理并发调度的。

# 理解 goroutines 的工作方式

到这一点，你应该对 goroutines 做了很好的了解，但值得理解的是它们在 Go 中是如何内部工作的。Go 使用协作调度处理并发，正如我们在前一章中提到的，这在某种程度上严重依赖于某种形式的阻塞代码。

协作调度的最常见替代方案是抢占式调度，其中每个子进程被授予一段时间来完成，然后它的执行被暂停以进行下一个。

没有某种形式的让回到主线程，执行就会遇到问题。这是因为 Go 使用单个进程，作为 goroutines 乐队的指挥。每个子进程负责宣布自己的完成。与其他并发模型相比，其中一些允许直接命名通信，这可能构成一个难点，特别是如果你以前没有使用过通道。

你可能会看到这些事实存在死锁的潜在可能性。在本章中，我们将讨论 Go 的设计允许我们管理这一点的方式，以及在应用程序中解决问题的方法。

# 同步与异步 goroutines

理解并发模型有时是程序员的早期痛点，不仅仅是对于 Go，还有其他使用不同模型的语言。部分原因是由于在*黑盒*中操作（取决于你的终端偏好）；开发人员必须依赖于日志记录或数据一致性错误来辨别异步和/或多核定时问题。

由于同步和异步或并发和非并发任务的概念有时可能有点抽象，我们将在这里尝试以一种视觉方式来演示到目前为止我们所涵盖的所有概念。

当然，有许多方法来处理反馈和日志记录。你可以写入文件`console/terminal/stdout…`，其中大部分本质上是线性的。在日志文件中没有简洁的方式来表示并发。鉴于这一点，以及我们处理着一个专注于服务器的新兴语言，让我们采取不同的角度。

我们将创建一个可视化反馈，显示进程在时间轴上的开始和停止。

## 设计 Web 服务器计划

为了展示不同的方法，我们将创建一个简单的 Web 服务器，循环执行三个微不足道的任务，并在 X 秒时间轴上输出它们的执行标记。我们将使用一个名为`svgo`的第三方库和 Go 的内置`http`包来实现这一点。

首先，让我们通过`go get`获取`svgo`库：

```go
go get github.com/ajstarks/svgo

```

如果你尝试通过`go get`命令安装一个包，并且收到关于未设置`$GOPATH`的错误，那么你需要设置该环境变量。`GOPATH`是 Go 将查找已安装的导入包的位置。

在 Linux（或 Mac）中设置这个，输入以下 bash（或终端）：

```go
export GOPATH=/usr/yourpathhere

```

这条路由取决于你，所以选择一个你最舒适的地方来存储你的 Go 包。

为了确保它是全局可访问的，请将它安装在你的 Go 二进制文件安装的位置。

在 Windows 上，你可以右键单击**我的电脑**，然后导航到**属性** | **高级系统设置** | **环境变量...**，如下面的截图所示：

![设计 Web 服务器计划](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/ms-cncr-go/img/00005.jpeg)

在这里，您需要创建一个名为`GOPATH`的新变量。与 Linux 和 Mac 的说明一样，这可以是您的 Go 语言根目录，也可以是完全不同的地方。在本例中，我们使用了`C:\Go`，如下截图所示：

![设计 Web 服务器计划](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/ms-cncr-go/img/00006.jpeg)

### 注意

请注意，在执行这些步骤后，您可能需要重新打开终端、命令提示符或 bash 会话，以便值被视为有效。在*nix 系统上，您可以登录和注销以启动此操作。

现在我们已经安装了 gosvg，我们可以直观地演示异步和同步进程并排以及多个处理器的外观。

### 注意

**更多库**

为什么使用 SVG？当然，我们不需要使用 SVG 和 Web 服务器，如果您更愿意看到生成的图像并单独打开它，还有其他替代方法可以做到这一点。Go 还有一些其他可用的图形库，如下所示：

+   **draw2d**：顾名思义，这是一个用于进行矢量风格和光栅图形的二维绘图库，可以在[`code.google.com/p/draw2d/`](https://code.google.com/p/draw2d/)找到。

+   **graphics-go**：这个项目涉及 Go 团队的一些成员。它的范围相当有限。您可以在[`code.google.com/p/graphics-go/`](https://code.google.com/p/graphics-go/)找到更多信息。

+   **go:ngine**：这是为 Go 设计的少数 OpenGL 实现之一。对于这个项目来说可能有些过度，但如果您发现自己需要一个三维图形库，可以从[`go-ngine.com/`](http://go-ngine.com/)开始。

+   **Go-SDL**：另一种可能过度的方法，这是一个实现了出色的多媒体库 SDL 的项目。您可以在[`github.com/banthar/Go-SDL`](https://github.com/banthar/Go-SDL)找到更多信息。

还有一些强大的 GUI 工具包可用，但由于它们是作为系统语言设计的，这并不是 Go 的长处。

# 可视化并发

我们对可视化并发的第一次尝试将有两个简单的 goroutines 在循环中运行`drawPoint`函数，循环 100 次。运行后，您可以访问`localhost:1900/visualize`，看看并发 goroutines 的样子。

如果您在端口 1900 上遇到问题（无论是防火墙还是端口冲突），请随意在`main()`函数的第 99 行更改该值。如果您的系统无法解析 localhost，则可能还需要通过`127.0.0.1`访问它。

请注意，我们没有使用`WaitGroup`或任何其他东西来管理 goroutines 的结束，因为我们只想看到我们的代码运行的可视化表示。您也可以使用特定的阻塞代码或`runtime.Gosched()`来处理这个问题，如下所示：

```go
package main

import (
    "github.com/ajstarks/svgo"
    "net/http"
    "fmt"
    "log"
    "time"
    "strconv"
)

var width = 800
var height = 400
var startTime = time.Now().UnixNano()

func drawPoint(osvg *svg.SVG, pnt int, process int) {
  sec := time.Now().UnixNano()
  diff := ( int64(sec) - int64(startTime) ) / 100000

  pointLocation := 0

  pointLocation = int(diff)
  pointLocationV := 0
  color := "#000000"
  switch {
    case process == 1:
      pointLocationV = 60
      color = "#cc6666"
    default:
      pointLocationV = 180
      color = "#66cc66"

  }

  osvg.Rect(pointLocation,pointLocationV,3,5,"fill:"+color+";stroke:
  none;")
  time.Sleep(150 * time.Millisecond)
}

func visualize(rw http.ResponseWriter, req *http.Request) {
  startTime = time.Now().UnixNano()
  fmt.Println("Request to /visualize")
  rw.Header().Set("Content-Type", "image/svg+xml")

  outputSVG := svg.New(rw)

  outputSVG.Start(width, height)
  outputSVG.Rect(10, 10, 780, 100, "fill:#eeeeee;stroke:none")
  outputSVG.Text(20, 30, "Process 1 Timeline", "text-
    anchor:start;font-size:12px;fill:#333333")
  outputSVG.Rect(10, 130, 780, 100, "fill:#eeeeee;stroke:none")    
  outputSVG.Text(20, 150, "Process 2 Timeline", "text-
    anchor:start;font-size:12px;fill:#333333")  

  for i:= 0; i < 801; i++ {
    timeText := strconv.FormatInt(int64(i),10)
    if i % 100 == 0 {
      outputSVG.Text(i,380,timeText,"text-anchor:middle;font-
        size:10px;fill:#000000")      
    }else if i % 4 == 0 {
      outputSVG.Circle(i,377,1,"fill:#cccccc;stroke:none")  
    }

    if i % 10 == 0 {
      outputSVG.Rect(i,0,1,400,"fill:#dddddd")
    }
    if i % 50 == 0 {
      outputSVG.Rect(i,0,1,400,"fill:#cccccc")
    }

  }

  for i := 0; i < 100; i++ {
    go drawPoint(outputSVG,i,1)
    drawPoint(outputSVG,i,2)    
  }

  outputSVG.Text(650, 360, "Run without goroutines", "text-
    anchor:start;font-size:12px;fill:#333333")      
  outputSVG.End()
}

func main() {
  http.Handle("/visualize", http.HandlerFunc(visualize))

    err := http.ListenAndServe(":1900", nil)
    if err != nil {
        log.Fatal("ListenAndServe:", err)
    }  

}
```

当您访问`localhost:1900/visualize`时，您应该看到类似以下截图的内容：

![可视化并发](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/ms-cncr-go/img/00007.jpeg)

正如您所看到的，一切肯定是同时运行的——我们短暂休眠的 goroutines 在同一时刻命中时间轴。通过简单地强制 goroutines 以串行方式运行，您将看到这种行为的可预测变化。如下所示，删除第 73 行的 goroutine 调用：

```go
    drawPoint(outputSVG,i,1)
    drawPoint(outputSVG,i,2)  
```

为了保持我们的演示清晰，将第 77 行更改为指示没有 goroutines，如下所示：

```go
outputSVG.Text(650, 360, "Run with goroutines", "text-
  anchor:start;font-size:12px;fill:#333333")  
```

如果我们停止服务器并使用`go run`重新启动，我们应该看到类似以下截图的内容：

![可视化并发](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/ms-cncr-go/img/00008.jpeg)

现在，每个进程在开始之前都会等待前一个进程完成。如果您在同步数据、通道和进程的同步方面遇到问题，您实际上可以向任何应用程序添加这种反馈。

如果我们愿意，我们可以添加一些通道，并显示它们之间的通信。稍后，我们将设计一个自我诊断服务器，实时提供有关服务器、请求和通道状态的分析。

如果我们重新启动 goroutine 并增加最大可用处理器，我们将看到类似于以下截图的内容，这与我们的第一个截图并不完全相同：

![可视化并发](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/ms-cncr-go/img/00009.jpeg)

显然，您的里程数会根据服务器速度、处理器数量等而有所不同。但在这种情况下，我们的更改导致了两个具有间歇性休眠的进程的更快总执行时间。这应该不足为奇，因为我们基本上有两倍的带宽可用来完成这两个任务。

# RSS 的实际应用

让我们以**Rich Site Summary** / **Really Simple Syndication** (**RSS**)的概念为基础，并注入一些真正的潜在延迟，以确定我们在哪里可以最好地利用 goroutines 来加快执行速度并防止阻塞代码。将真实生活中可能阻塞应用程序元素引入您的代码的一种常见方式是使用涉及网络传输的内容。

这也是一个很好的地方，可以查看超时和关闭通道，以确保我们的程序不会在某些操作花费太长时间时崩溃。

为了满足这两个要求，我们将构建一个非常基本的 RSS 阅读器，它将简单地解析并获取五个 RSS 源的内容。我们将读取每一个源以及每个源上提供的链接，然后我们将通过 HTTP 生成一个 SVG 报告。

### 注意

显然，这是一个最适合作为后台任务的应用程序——您会注意到每个请求可能需要很长时间。但是，为了以图形方式表示与并发和无并发的真实生活过程，它将起作用，特别是对于单个最终用户。我们还将将我们的步骤记录到标准输出中，所以一定要查看您的控制台。

在这个例子中，我们将再次使用第三方库，尽管完全可以使用 Go 的内置 XML 包来解析 RSS。鉴于 XML 的开放性和 RSS 的特定性，我们将绕过它们，使用 Jim Teeuwen 的`go-pkg-rss`，可以通过以下`go get`命令获取：

```go
go get github.com/jteeuwen/go-pkg-rss

```

虽然这个包专门用作 Google Reader 产品的替代品，这意味着它会在一组来源中对新内容进行基于间隔的轮询，但它也有一个相当整洁的 RSS 阅读实现。虽然还有一些其他的 RSS 解析库，但是请随意尝试。

## 带自我诊断功能的 RSS 阅读器

让我们回顾一下我们迄今为止学到的东西，并利用它来同时获取和解析一组 RSS 源，同时在内部 Web 浏览器中返回有关该过程的一些可视化反馈，如下所示的代码：

```go
package main

import(
  "github.com/ajstarks/svgo"
  rss "github.com/jteeuwen/go-pkg-rss"    
  "net/http"
  "log"
  "fmt"
  "strconv"
  "time"
  "os"
  "sync"
  "runtime"
)

type Feed struct {
  url string
  status int
  itemCount int
  complete bool
  itemsComplete bool
  index int
}
```

这是我们源的整体结构的基础：我们有一个代表源位置的`url`变量，一个表示它是否已启动的`status`变量，以及一个表示它是否已完成的`complete`布尔变量。下一个部分是一个单独的`FeedItem`；以下是它的布局方式：

```go
type FeedItem struct {
  feedIndex int
  complete bool
  url string
}
```

与此同时，我们不会对单个项做太多处理；在这一点上，我们只是维护一个 URL，无论它是完整的还是`FeedItem`结构体的索引。

```go
var feeds []Feed
var height int
var width int
var colors []string
var startTime int64
var timeout int
var feedSpace int

var wg sync.WaitGroup

func grabFeed(feed *Feed, feedChan chan bool, osvg *svg.SVG) {

  startGrab := time.Now().Unix()
  startGrabSeconds := startGrab - startTime

  fmt.Println("Grabbing feed",feed.url," 
    at",startGrabSeconds,"second mark")

  if feed.status == 0 {
    fmt.Println("Feed not yet read")
    feed.status = 1

    startX := int(startGrabSeconds * 33);
    startY := feedSpace * (feed.index)

    fmt.Println(startY)
    wg.Add(1)

    rssFeed := rss.New(timeout, true, channelHandler, 
      itemsHandler);

    if err := rssFeed.Fetch(feed.url, nil); err != nil {
      fmt.Fprintf(os.Stderr, "[e] %s: %s", feed.url, err)
      return
    } else {

      endSec := time.Now().Unix()    
      endX := int( (endSec - startGrab) )
      if endX == 0 {
        endX = 1
      }
      fmt.Println("Read feed in",endX,"seconds")
      osvg.Rect(startX,startY,endX,feedSpace,"fill: 
        #000000;opacity:.4")
      wg.Wait()

      endGrab := time.Now().Unix()
      endGrabSeconds := endGrab - startTime
      feedEndX := int(endGrabSeconds * 33);      

      osvg.Rect(feedEndX,startY,1,feedSpace,"fill:#ff0000;opacity:.9")

      feedChan <- true
    }

  }else if feed.status == 1{
    fmt.Println("Feed already in progress")
  }

}
```

`grabFeed()`方法直接控制抓取任何单个源的流程。它还通过`WaitGroup`结构绕过了潜在的并发重复。接下来，让我们看看`itemsHandler`函数：

```go
func channelHandler(feed *rss.Feed, newchannels []*rss.Channel) {

}

func itemsHandler(feed *rss.Feed, ch *rss.Channel, newitems []*rss.Item) {

  fmt.Println("Found",len(newitems),"items in",feed.Url)

  for i := range newitems {
    url := *newitems[i].Guid
    fmt.Println(url)

  }

  wg.Done()
}
```

`itemsHandler`函数目前并没有做太多事情，除了实例化一个新的`FeedItem`结构体——在现实世界中，我们会将这作为下一步，并检索这些项本身的值。我们的下一步是查看抓取单个 feed 并标记每个 feed 所花费的时间的过程，如下所示：

```go
func getRSS(rw http.ResponseWriter, req *http.Request) {
  startTime = time.Now().Unix()  
  rw.Header().Set("Content-Type", "image/svg+xml")
  outputSVG := svg.New(rw)
  outputSVG.Start(width, height)

  feedSpace = (height-20) / len(feeds)

  for i:= 0; i < 30000; i++ {
    timeText := strconv.FormatInt(int64(i/10),10)
    if i % 1000 == 0 {
      outputSVG.Text(i/30,390,timeText,"text-anchor:middle;font-
        size:10px;fill:#000000")      
    }else if i % 4 == 0 {
      outputSVG.Circle(i,377,1,"fill:#cccccc;stroke:none")  
    }

    if i % 10 == 0 {
      outputSVG.Rect(i,0,1,400,"fill:#dddddd")
    }
    if i % 50 == 0 {
      outputSVG.Rect(i,0,1,400,"fill:#cccccc")
    }

  }

  feedChan := make(chan bool, 3)

  for i := range feeds {

    outputSVG.Rect(0, (i*feedSpace), width, feedSpace, 
      "fill:"+colors[i]+";stroke:none;")
    feeds[i].status = 0
    go grabFeed(&feeds[i], feedChan, outputSVG)
    <- feedChan
  }

  outputSVG.End()
}
```

在这里，我们获取 RSS 源并在我们的 SVG 上标记我们的检索和读取事件的状态。我们的`main()`函数主要处理源的设置，如下所示：

```go
func main() {

  runtime.GOMAXPROCS(2)

  timeout = 1000

  width = 1000
  height = 400

  feeds = append(feeds, Feed{index: 0, url: 
    "https://groups.google.com/forum/feed/golang-
    nuts/msgs/rss_v2_0.xml?num=50", status: 0, itemCount: 0, 
    complete: false, itemsComplete: false})
  feeds = append(feeds, Feed{index: 1, url: 
    "http://www.reddit.com/r/golang/.rss", status: 0, itemCount: 
    0, complete: false, itemsComplete: false})
  feeds = append(feeds, Feed{index: 2, url: 
    "https://groups.google.com/forum/feed/golang-
    dev/msgs/rss_v2_0.xml?num=50", status: 0, itemCount: 0, 
    complete: false, itemsComplete: false })
```

这是我们的`FeedItem`结构体的切片：

```go
  colors = append(colors,"#ff9999")
  colors = append(colors,"#99ff99")
  colors = append(colors,"#9999ff")  
```

在打印版本中，这些颜色可能并不特别有用，但在您的系统上测试它将允许您区分应用程序内部的事件。我们需要一个 HTTP 路由作为终点；以下是我们将如何设置它：

```go
  http.Handle("/getrss", http.HandlerFunc(getRSS))
    err := http.ListenAndServe(":1900", nil)
    if err != nil {
        log.Fatal("ListenAndServe:", err)
    }  
}
```

运行时，您应该看到 RSS feed 检索和解析的开始和持续时间，然后是一条细线，表示该 feed 已被解析并且所有项已被读取。

三个块中的每一个都表达了处理每个 feed 的全部时间，展示了这个版本的非并发执行，如下面的屏幕截图所示：

![带有自我诊断功能的 RSS 阅读器](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/ms-cncr-go/img/00010.jpeg)

请注意，我们对 feed 项并没有做任何有趣的事情，我们只是读取 URL。下一步将是通过 HTTP 获取这些项，如下面的代码片段所示：

```go
  url := *newitems[i].Guid
      response, _, err := http.Get(url)
      if err != nil {

      }
```

通过这个例子，我们在每一步都停下来向 SVG 提供某种反馈，告诉它发生了某种事件。我们的通道在这里是有缓冲的，我们明确声明它必须在完成阻塞之前接收三条布尔消息，如下面的代码片段所示：

```go
  feedChan := make(chan bool, 3)

  for i := range feeds {

    outputSVG.Rect(0, (i*feedSpace), width, feedSpace, 
      "fill:"+colors[i]+";stroke:none;")
    feeds[i].status = 0
    go grabFeed(&feeds[i], feedChan, outputSVG)
    <- feedChan
  }

  outputSVG.End()
```

通过在我们的通道调用中给出`3`作为第二个参数，我们告诉 Go 这个通道必须在继续应用程序之前接收三个响应。不过，您应该谨慎使用这个功能，特别是在明确设置事物时。如果其中一个 goroutine 从未通过通道发送布尔值会怎么样？应用程序会崩溃。

请注意，我们在这里还增加了我们的时间轴，从 800 毫秒增加到 60 秒，以便检索所有的 feeds。请记住，如果我们的脚本超过 60 秒，那么超过这个时间的所有操作都将发生在这个可视时间轴表示之外。

通过在读取 feeds 时实现`WaitGroup`结构，我们对应用程序施加了一些串行化和同步。第二个 feed 将在第一个 feed 完成检索所有 URL 之前不会开始。您可能会看到这可能会引入一些错误：

```go
    wg.Add(1)
    rssFeed := rss.New(timeout, true, channelHandler, 
      itemsHandler);
    …
    wg.Wait()
```

这告诉我们的应用程序要等到我们从`itemsHandler()`函数中设置`Done()`命令为止。

那么如果我们完全删除`WaitGroups`会发生什么？考虑到抓取 feed 项的调用是异步的，我们可能看不到所有的 RSS 调用的状态；相反，我们可能只看到一个或两个 feeds，或者根本没有 feed。

## 强加超时

那么如果在我们的时间轴内没有运行任何东西会发生什么？正如您所期望的那样，我们将得到三个没有任何活动的条形图。重要的是要考虑如何终止那些没有按我们期望的方式运行的进程。在这种情况下，最好的方法是超时。`http`包中的`Get`方法并不原生支持超时，因此如果您想要防止这些请求永无止境地进行并杀死您的应用程序，您将不得不自己编写`rssFeed.Fetch`（和底层的`http.Get()`）实现。我们稍后会深入探讨这一点；与此同时，看一下核心`http`包中可用的`Transport`结构，网址为[`golang.org/pkg/net/http/#Transport`](http://golang.org/pkg/net/http/#Transport)。

# 关于 CSP 的一点说明

我们在上一章中简要介绍了 CSP，但在 Go 的并发模型操作方式的背景下，值得更深入地探讨一下。

CSP 在 20 世纪 70 年代末和 80 年代初通过 Tony Hoare 爵士的工作发展起来，至今仍在不断发展中。Go 的实现在很大程度上基于 CSP，但它既不完全遵循初始描述中设定的所有规则和惯例，也不遵循其自那时以来的发展。

Go 与真正的 CSP 不同的一种方式是，根据其定义，Go 中的一个进程只会继续存在，只要存在一个准备好从该进程接收的通道。 我们已经遇到了一些由于监听通道没有接收任何内容而导致的死锁。 反之亦然；死锁也可能是由于通道继续而没有发送任何内容，使其接收通道无限期挂起。

这种行为是 Go 调度程序的典型特征，当您最初使用通道时，它确实只会在您处理通道时造成问题。

### 注意

霍尔的原始作品现在可以从许多机构（大部分）免费获得。 您可以免费阅读，引用，复制和重新分发它（但不能用于商业用途）。 如果您想阅读整个内容，可以在[`www.cs.ucf.edu/courses/cop4020/sum2009/CSP-hoare.pdf`](http://www.cs.ucf.edu/courses/cop4020/sum2009/CSP-hoare.pdf)上获取。

完整的书本本身也可以在[`www.usingcsp.com/cspbook.pdf`](http://www.usingcsp.com/cspbook.pdf)上获得。

截至本出版之时，霍尔正在微软担任研究员。

根据应用程序设计者的说法，Go 实现 CSP 概念的目标是专注于简单性-除非您真的想要或需要，否则您不必担心线程或互斥量。

## 餐桌哲学家问题

您可能已经听说过餐桌哲学家问题，这描述了并发编程旨在解决的问题类型。 餐桌哲学家问题是由伟大的 Edsger Dijkstra 提出的。 问题的关键在于资源-五位哲学家坐在一张桌子旁，有五盘食物和五把叉子，每个人只有在他有两把叉子（一把在左边，另一把在右边）时才能吃饭。 可视化表示如下：

![The dining philosophers problem](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/ms-cncr-go/img/00011.jpeg)

在任一侧只有一把叉子时，任何给定的哲学家只有在双手都拿着叉子时才能吃饭，并且在完成后必须将两者都放回桌子上。 思想是协调餐点，以便所有哲学家都可以永远吃饭而不会挨饿-任何时刻都必须有两位哲学家能够吃饭，而且不能有死锁。 他们是哲学家，因为当他们不吃饭时，他们在思考。 在编程类比中，您可以将其视为等待通道或睡眠进程。

Go 使用 goroutines 相当简洁地处理了这个问题。 给定五位哲学家（例如在一个单独的结构中），您可以让这五位哲学家在思考、在叉子放下时接收通知、抓住叉子、用叉子就餐和放下叉子之间交替。

接收到叉子放下的通知作为监听通道，就餐和思考是独立的过程，放下叉子则是沿通道的公告。

我们可以在以下伪 Go 代码中可视化这个概念：

```go
type Philosopher struct {
  leftHand bool
  rightHand bool
  status int
  name string
}

func main() {

  philosophers := [...]Philospher{"Kant", "Turing", 
    "Descartes","Kierkegaard","Wittgenstein"}

  evaluate := func() {
    for {

      select {
        case <- forkUp:
          // philosophers think!
        case <- forkDown:
          // next philospher eats in round robin
      }

    }

  }

}
```

这个例子被留得非常抽象和非操作性，以便您有机会尝试解决它。 我们将在下一章中为此构建一个功能性解决方案，因此请确保稍后比较您的解决方案。

有数百种处理此问题的方法，我们将看看一些替代方案以及它们在 Go 本身内部如何能够或不能够很好地发挥作用。

# Go 和演员模型

如果您是 Erlang 或 Scala 用户，那么演员模型可能是您非常熟悉的。 CSP 和演员模型之间的区别微不足道但很重要。 使用 CSP，如果另一个通道正在监听并准备好接收消息，那么来自一个通道的消息只能完全发送。 演员模型并不一定需要准备好的通道才能发送。 实际上，它强调直接通信，而不是依赖通道的导管。

这两种系统都可能是不确定的，这在我们之前的 Go/CSP 示例中已经看到了。CSP 和 goroutines 都是匿名的，传输由通道而不是源和目的地指定。在演员模型的伪代码中可视化这一点的简单方法如下：

```go
a = new Actor
b = new Actor
a -> b("message")
```

在 CSP 中，它是这样的：

```go
a = new Actor
b = new Actor
c = new Channel
a -> c("sending something")
b <- c("receiving something")
```

它们都通过稍微不同的方式提供了相同的基本功能。

# 面向对象

当你使用 Go 时，你会注意到一个核心特征经常被提倡，用户可能觉得是错误的。你会听到 Go 不是一种面向对象的语言，然而你有可以有方法的结构体，这些方法反过来又可以有方法，你可以与任何实例进行通信。通道本身可能感觉像原始的对象接口，能够从给定的数据元素中设置和接收值。

Go 的消息传递实现确实是面向对象编程的核心概念。具有接口的结构本质上就像类，Go 支持多态性（尽管不支持参数多态性）。然而，许多使用该语言的人（以及设计它的人）强调它并不是面向对象的。那么是什么原因呢？

这个定义的很大程度上取决于你问的是谁。有些人认为 Go 缺乏面向对象编程的必要特征，而其他人认为它满足了这些特征。最重要的是要记住，你并不受 Go 设计的限制。在*真正*的面向对象语言中可以做的任何事情在 Go 中都可以轻松处理。

## 演示 Go 中简单的多态性

如前所述，如果你期望多态性类似于面向对象编程，这可能不代表一种语法类比。然而，使用接口作为类绑定多态方法的抽象同样干净，并且在许多方面更加明确和可读。让我们看一个 Go 中多态性的非常简单的实现：

```go
type intInterface struct {

}

type stringInterface struct {

}

func (number intInterface) Add (a int, b int) int {
  return a + b;
}

func (text stringInterface) Add (a string, b string) string {
  return a + b
}

func main() {

  number := new (intInterface)
    fmt.Println( number.Add(1,2) )

  text := new (stringInterface)
    fmt.Println( text.Add("this old man"," he played one"))

}
```

正如你所看到的，我们使用接口（或其 Go 模拟）来消除方法的歧义。例如，你不能像在 Java 中那样使用泛型。然而，这归结为最终只是一种风格问题。你既不应该觉得这令人畏惧，也不会给你的代码带来任何混乱或歧义。

# 使用并发

尚未提到的是，我们应该意识到，并发并不总是对应用程序有益的。并没有真正的经验之谈，而且并发很少会给应用程序带来问题；但是如果你真的考虑整个应用程序，不是所有的应用程序都需要并发进程。

那么什么效果最好呢？正如我们在之前的例子中看到的，任何引入潜在延迟或 I/O 阻塞的东西，比如网络调用、磁盘读取、第三方应用程序（主要是数据库）和分布式系统，都可以从并发中受益。如果你有能力在未确定的时间表上进行工作，那么并发策略可以提高应用程序的速度和可靠性。

这里的教训是你不应该感到被迫将并发加入到一个真正不需要它的应用程序中。具有进程间依赖关系（或缺乏阻塞和外部依赖关系）的程序可能很少或根本不会从实现并发结构中获益。

# 管理线程

到目前为止，你可能已经注意到，在 Go 中，线程管理并不是程序员最关心的问题。这是有意设计的。Goroutines 并不绑定到 Go 内部调度程序处理的特定线程或线程。然而，这并不意味着你既不能访问线程，也不能控制单个线程的操作。正如你所知，你已经可以告诉 Go 你有多少线程（或希望使用）通过使用`GOMAXPROCS`。我们也知道，使用这个可能会引入与数据一致性和执行顺序相关的异步问题。

在这一点上，线程的主要问题不是它们如何被访问或利用，而是如何正确地控制执行流程，以确保你的数据是可预测的和同步的。

# 使用 sync 和互斥锁来锁定数据

你可能在前面的例子中遇到的一个问题是原子数据的概念。毕竟，如果你在多个 goroutines 和可能的处理器之间处理变量和结构，你如何确保你的数据在它们之间是安全的？如果这些进程并行运行，协调数据访问有时可能会有问题。

Go 在其`sync`包中提供了大量工具来处理这些类型的问题。你如何优雅地处理它们在很大程度上取决于你的方法，但在这个领域你不应该不得不重新发明轮子。

我们已经看过`WaitGroup`结构，它提供了一种简单的方法，告诉主线程暂停，直到下一个通知说等待的进程已经完成了它应该做的事情。

Go 还提供了对互斥锁的直接抽象。称某物为直接抽象可能看起来矛盾，但事实上你并没有访问 Go 的调度程序，只是一个真正互斥锁的近似。

我们可以使用互斥锁来锁定和解锁数据，并保证数据的原子性。在许多情况下，这可能是不必要的；有很多时候，执行顺序并不影响底层数据的一致性。然而，当我们对这个值有顾虑时，能够显式地调用锁是很有帮助的。让我们看下面的例子：

```go
package main

import(
  "fmt"
  "sync"
)

func main() {
  current := 0
  iterations := 100
  wg := new (sync.WaitGroup);

  for i := 0; i < iterations; i++ {
    wg.Add(1)

    go func() {
      current++
      fmt.Println(current)
      wg.Done()
    }()
    wg.Wait()
  }

}
```

毫不奇怪，在你的终端中提供了 0 到 99 的列表。如果我们将`WaitGroup`更改为知道将调用 100 个`Done()`实例，并将我们的阻塞代码放在循环的末尾，会发生什么？

为了演示为什么以及如何最好地利用`waitGroups`作为并发控制机制的一个简单命题，让我们做一个简单的数字迭代器并查看结果。我们还将看看如何直接调用互斥锁可以增强这种功能，如下所示：

```go
func main() {
  runtime.GOMAXPROCS(2)
  current := 0
  iterations := 100
  wg := new (sync.WaitGroup);
  wg.Add(iterations)
  for i := 0; i < iterations; i++ {
    go func() {
      current++
      fmt.Println(current)
      wg.Done()
    }()

  }
  wg.Wait()

}
```

现在，我们的执行顺序突然错了。你可能会看到类似以下的输出：

```go
95
96
98
99
100
3
4

```

我们有能力随时锁定和解锁当前命令；然而，这不会改变底层的执行顺序，它只会阻止对变量的读取和/或写入，直到调用解锁为止。

让我们尝试使用`mutex`锁定我们输出的变量，如下所示：

```go
  for i := 0; i < iterations; i++ {
    go func() {
      mutex.Lock()
      fmt.Println(current)
      current++
      mutex.Unlock()
      fmt.Println(current)
      wg.Done()
    }()

  }
```

你可能已经看到，在并发应用程序中，互斥控制机制如何重要，以确保数据的完整性。我们将在第四章*应用程序中的数据完整性*中更多地了解互斥锁和锁定和解锁过程。

# 总结

在本章中，我们试图通过给出一些可视化的实时反馈，来消除 Go 并发模式和模型的一些模糊性，包括一个基本的 RSS 聚合器和阅读器。我们研究了餐桌哲学家问题，并探讨了如何使用 Go 并发主题来整洁而简洁地解决问题。我们比较了 CSP 和 actor 模型的相似之处以及它们的不同之处。

在下一章中，我们将把这些概念应用到开发应用程序中维护并发性的过程中。


# 第三章：制定并发策略

在上一章中，我们看到了 Go 依赖的并发模型，以使开发人员的生活更轻松。我们还看到了并行性和并发性的可视化表示。这些帮助我们理解串行、并发和并行应用程序之间的差异和重叠。

然而，任何并发应用程序中最关键的部分不是并发本身，而是并发进程之间的通信和协调。

在本章中，我们将着重考虑创建一个应用程序的计划，该计划严重考虑了进程之间的通信，以及缺乏协调可能导致一致性方面的重大问题。我们将探讨如何在纸上可视化我们的并发策略，以便更好地预见潜在问题。

# 应用复杂并发的效率

在设计应用程序时，我们经常放弃复杂的模式，选择简单性，假设简单的系统通常是最快和最有效的。似乎只有逻辑上，机器的移动部分越少，效率就会比移动部分更多的机器更高。

这里的悖论是，对并发的应用，增加冗余和更多的可移动部分通常会导致更高效的应用。如果我们认为并发方案（如 goroutines）是无限可扩展的资源，那么使用更多的资源应该总是会带来某种形式的效率收益。这不仅适用于并行并发，也适用于单核并发。

如果你发现自己设计的应用程序利用并发，却牺牲了效率、速度和一致性，你应该问问自己这个应用程序是否真的需要并发。

当我们谈论效率时，我们不仅仅是在处理速度。效率还应该考虑 CPU 和内存开销以及确保数据一致性的成本。

例如，如果一个应用程序在一定程度上受益于并发，但需要一个复杂和/或计算昂贵的过程来保证数据一致性，那么重新评估整个策略是值得的。

保持数据的可靠性和最新性应该是最重要的；虽然不可靠的数据可能并不总是会产生灾难性的影响，但它肯定会损害你的应用程序的可靠性。

# 使用竞争检测识别竞争条件

如果你曾经编写过一个依赖于函数或方法的确切时间和顺序来创建期望输出的应用程序，你对竞争条件已经非常熟悉了。

这些在处理并发时特别常见，当引入并行时更加常见。在前几章中，我们确实遇到了一些问题，特别是在我们的递增数字函数中。

竞争条件最常用的教育示例是银行账户。假设你从 1000 美元开始，尝试进行 200 笔 5 美元的交易。每笔交易都需要查询账户的当前余额。如果通过，交易将获批准，从余额中扣除 5 美元。如果失败，交易将被拒绝，余额保持不变。

这一切都很好，直到查询在并发事务中的某个时刻发生（在大多数情况下是在另一个线程中）。例如，一个线程在另一个线程正在移除 5 美元但尚未完成的过程中询问“你的账户里有 5 美元吗？”这样，你最终可能会得到一个本应该被拒绝的交易。

追踪竞争条件的原因可能是一个巨大的头痛。在 Go 的 1.1 版本中，Google 引入了一种竞争检测工具，可以帮助你找到潜在的问题。

让我们以一个具有竞争条件的多线程应用程序的非常基本的例子为例，看看 Golang 如何帮助我们调试它。在这个例子中，我们将建立一个银行账户，初始金额为 1000 美元，进行 100 笔随机金额在 0 到 25 美元之间的交易。

每个交易将在自己的 goroutine 中运行，如下所示：

```go
package main

import(
  "fmt"
  "time"
  "sync"
  "runtime"
  "math/rand"
)  

var balance int
var transactionNo int

func main() {
  rand.Seed(time.Now().Unix())
  runtime.GOMAXPROCS(2)
  var wg sync.WaitGroup

  tranChan := make(chan bool)

  balance = 1000
  transactionNo = 0
  fmt.Println("Starting balance: $",balance)

  wg.Add(1)
  for i := 0; i < 100; i++ {
    go func(ii int, trChan chan(bool)) {
      transactionAmount := rand.Intn(25)
      transaction(transactionAmount)
      if (ii == 99) {
        trChan <- true
      }

    }(i,tranChan)
  }

  go transaction(0)
  select {

    case <- tranChan:
      fmt.Println("Transactions finished")
      wg.Done()

  }

  wg.Wait()
  close(tranChan)
  fmt.Println("Final balance: $",balance)
}

func transaction(amt int) (bool) {

  approved := false  
  if (balance-amt) < 0 {
    approved = false
  }else {
    approved = true
    balance = balance - amt
  }

  approvedText := "declined"
  if (approved == true) {
    approvedText = "approved"
  }else {

  }
  transactionNo = transactionNo + 1
  fmt.Println(transactionNo,"Transaction for $",amt,approvedText)
  fmt.Println("\tRemaining balance $",balance)
  return approved
}
```

根据您的环境（以及是否启用多个处理器），您可能会发现先前的 goroutine 成功地操作了$0 或更多的最终余额。另一方面，您可能最终只会得到超出交易时余额的交易，导致负余额。

那么我们怎么知道呢？

对于大多数应用程序和语言来说，这个过程通常涉及大量的运行、重新运行和日志记录。竞态条件往往会导致令人望而生畏和费力的调试过程。Google 知道这一点，并为我们提供了一个竞态条件检测工具。要测试这一点，只需在测试、构建或运行应用程序时使用`-race`标志，如下所示：

```go
go run -race race-test.go

```

当在先前的代码上运行时，Go 将执行应用程序，然后报告任何可能的竞态条件，如下所示：

```go
>> Final balance: $0
>> Found 2 data race(s)

```

在这里，Go 告诉我们数据存在两种潜在的竞态条件。它并没有告诉我们这些一定会导致数据一致性问题，但如果您遇到这样的问题，这可能会给您一些线索。

如果您查看输出的顶部，您将得到有关导致竞态条件的详细说明。在这个例子中，详细信息如下：

```go
==================
WARNING: DATA RACE
Write by goroutine 5: main.transaction()   /var/go/race.go:75 +0xbd 
 main.func┬╖001()   /var/go/race.go:31 +0x44

Previous write by goroutine 4: main.transaction() 
 /var/go/race.go:75 +0xbd main.func┬╖001()   /var/go/race.go:31 
 +0x44

Goroutine 5 (running) created at: main.main()   /var/go/race.go:36 
 +0x21c

Goroutine 4 (finished) created at: main.main()   /var/go/race.go:36 
 +0x21c

```

我们可以得到详细的、完整的跟踪，了解我们的潜在竞态条件存在的位置。相当有帮助，对吧？

竞态检测器保证不会产生错误的阳性结果，因此您可以将结果视为您的代码中存在潜在问题的有力证据。这里强调潜在性，因为竞态条件在正常情况下很容易被忽略——一个应用程序可能在几天、几个月甚至几年内都能正常工作，然后才会出现竞态条件。

### 提示

我们已经提到了日志记录，如果您对 Go 的核心语言不是非常熟悉，您的想法可能会有很多方向——stdout、文件日志等等。到目前为止，我们一直使用 stdout，但您可以使用标准库来处理这些日志记录。Go 的 log 包允许您按照以下方式写入 io 或 stdout：

```go
  messageOutput := os.Stdout
  logOut := log.New(messageOutput,"Message: ",log.
  Ldate|log.Ltime|log.Llongfile);
  logOut.Println("This is a message from the 
  application!")
```

这将产生以下输出：

```go
Message: 2014/01/21 20:59:11 /var/go/log.go:12: This is a message from the application!

```

那么，log 包相对于自己编写的优势在哪里呢？除了标准化之外，这个包在输出方面也是同步的。

那么现在呢？嗯，有几种选择。您可以利用通道来确保数据的完整性，使用缓冲通道，或者您可以使用`sync.Mutex`结构来锁定您的数据。

## 使用互斥

通常，互斥被认为是在应用程序中实现同步的一种低级和最为人熟知的方法——您应该能够在通道之间的通信中解决数据一致性。然而，在某些情况下，您需要真正地在处理数据时阻止读/写。

在 CPU 级别，互斥表示在寄存器之间交换二进制整数值以获取和释放锁。当然，我们将处理更高级别的东西。

我们已经熟悉了 sync 包，因为我们使用了`WaitGroup`结构，但该包还包含了条件变量`struct Cond`和`Once`，它们将执行一次操作，以及互斥锁`RWMutex`和`Mutex`。正如`RWMutex`的名称所暗示的那样，它对多个读取者和/或写入者进行锁定和解锁；本章后面和第五章中还有更多内容，*锁、块和更好的通道*。

正如包名所暗示的那样，所有这些都赋予您防止可能被任意数量的 goroutines 和/或线程访问的数据发生竞态条件的能力。使用此包中的任何方法都不能确保数据和结构的原子性，但它确实为您提供了有效管理原子性的工具。让我们看看我们可以在并发的、线程安全的应用程序中巩固我们的账户余额的一些方法。

如前所述，我们可以在通道级别协调数据更改，无论该通道是缓冲还是非缓冲。让我们将逻辑和数据操作卸载到通道，并查看`-race`标志呈现了什么。

如果我们修改我们的主循环，如下面的代码所示，以利用通道接收的消息来管理余额值，我们将避免竞态条件：

```go
package main

import(
  "fmt"
  "time"
  "sync"
  "runtime"
  "math/rand"
)  

var balance int
var transactionNo int

func main() {
  rand.Seed(time.Now().Unix())
  runtime.GOMAXPROCS(2)
  var wg sync.WaitGroup
  balanceChan := make(chan int)
  tranChan := make(chan bool)

  balance = 1000
  transactionNo = 0
  fmt.Println("Starting balance: $",balance)

  wg.Add(1)
  for i:= 0; i<100; i++ {

    go func(ii int) {

      transactionAmount := rand.Intn(25)
      balanceChan <- transactionAmount

      if ii == 99 {
        fmt.Println("Should be quittin time")
        tranChan <- true
        close(balanceChan)
        wg.Done()
      }

    }(i)

  }

  go transaction(0)

    breakPoint := false
    for {
      if breakPoint == true {
        break
      }
      select {
        case amt:= <- balanceChan:
          fmt.Println("Transaction for $",amt)
          if (balance - amt) < 0 {
            fmt.Println("Transaction failed!")
          }else {
            balance = balance - amt
            fmt.Println("Transaction succeeded")
          }
          fmt.Println("Balance now $",balance)

        case status := <- tranChan:
          if status == true {
            fmt.Println("Done")
            breakPoint = true
            close(tranChan)

          }
      }
    }

  wg.Wait()

  fmt.Println("Final balance: $",balance)
}

func transaction(amt int) (bool) {

  approved := false  
  if (balance-amt) < 0 {
    approved = false
  }else {
    approved = true
    balance = balance - amt
  }

  approvedText := "declined"
  if (approved == true) {
    approvedText = "approved"
  }else {

  }
  transactionNo = transactionNo + 1
  fmt.Println(transactionNo,"Transaction for $",amt,approvedText)
  fmt.Println("\tRemaining balance $",balance)
  return approved
}
```

这一次，我们让通道完全管理数据。让我们看看我们在做什么：

```go
transactionAmount := rand.Intn(25)
balanceChan <- transactionAmount
```

这仍然会生成 0 到 25 之间的随机整数，但我们不是将其传递给函数，而是通过通道传递数据。通道允许您整洁地控制数据的所有权。然后我们看到选择/监听器，它在很大程度上与本章前面定义的`transaction()`函数相似：

```go
case amt:= <- balanceChan:
fmt.Println("Transaction for $",amt)
if (balance - amt) < 0 {
  fmt.Println("Transaction failed!")
}else {
  balance = balance - amt
  fmt.Println("Transaction succeeded")
}
fmt.Println("Balance now $",balance)
```

为了测试我们是否避免了竞态条件，我们可以再次使用`-race`标志运行`go run`，并且不会收到警告。

通道可以被视为处理同步`dataUse Sync.Mutex()`的官方方式。

如前所述，拥有内置的竞态检测器是大多数语言的开发人员无法享受的奢侈品，拥有它使我们能够测试方法并获得实时反馈。

我们注意到，使用显式互斥锁不鼓励使用 goroutines 的通道。这并不总是完全正确，因为每件事都有正确的时间和地点，互斥锁也不例外。值得注意的是，互斥锁在 Go 中是由通道内部实现的。正如之前提到的，您可以使用显式通道来处理读取和写入，并在它们之间搬移数据。

然而，这并不意味着显式锁没有用处。一个具有许多读取和很少写入的应用程序可能会受益于显式锁定写入；这并不一定意味着读取将是脏读取，但可能会导致更快和/或更多并发的执行。

为了演示起见，让我们使用显式锁来消除我们的竞态条件。我们的`-race`标志告诉我们它在哪里遇到读/写竞态条件，如下所示：

```go
Read by goroutine 5: main.transaction()   /var/go/race.go:62 +0x46

```

前一行只是我们从竞态检测报告中得到的几行中的一行。如果我们查看代码中的第 62 行，我们会找到对`balance`的引用。我们还会找到对`transactionNo`的引用，我们的第二个竞态条件。解决这两个问题最简单的方法是在`transaction`函数的内容周围放置一个互斥锁，因为这是修改`balance`和`transactionNo`变量的函数。`transaction`函数如下所示：

```go
func transaction(amt int) (bool) {
  mutex.Lock()

  approved := false
  if (balance-amt) < 0 {
    approved = false
  }else {
    approved = true
    balance = balance - amt
  }

  approvedText := "declined"
  if (approved == true) {
    approvedText = "approved"
  }else {

  }
  transactionNo = transactionNo + 1
  fmt.Println(transactionNo,"Transaction for $",amt,approvedText)
  fmt.Println("\tRemaining balance $",balance)

  mutex.Unlock()
  return approved
}
```

我们还需要在应用程序顶部将`mutex`定义为全局变量，如下所示：

```go
var mutex sync.Mutex
```

如果我们现在使用`-race`标志运行我们的应用程序，我们将不会收到警告。

`mutex`变量在实际目的上是`WaitGroup`结构的替代品，它作为条件同步机制。这也是通道操作的方式——沿通道移动的数据在 goroutines 之间是受限和隔离的。通过将 goroutine 状态绑定到`WaitGroup`，通道可以有效地作为先进先出工具工作；然后通过低级互斥锁为通道上跨通道访问的数据提供安全性。

另一个值得注意的事情是通道的多功能性——我们有能力在一系列 goroutines 之间共享通道以接收和/或发送数据，并且作为一等公民，我们可以在函数中传递它们。

## 探索超时

我们还可以使用通道显式在指定的时间后终止它们。如果决定手动处理互斥锁，这将是一个更复杂的操作。

通过通道终止长时间运行的例程的能力非常有帮助；考虑一个依赖网络的操作，不仅应该受限于短时间段，而且也不允许长时间运行。换句话说，你想给这个过程几秒钟来完成；但如果它运行超过一分钟，我们的应用程序应该知道出了什么问题，以至于停止尝试在该通道上监听或发送。以下代码演示了在`select`调用中使用超时通道：

```go
func main() {

  ourCh := make(chan string,1)

  go func() {

  }()

  select {
    case <-time.After(10 * time.Second):
      fmt.Println("Enough's enough")
      close(ourCh)
  }

}
```

如果我们运行前面的简单应用程序，我们会看到我们的 goroutine 将被允许在 10 秒钟后什么都不做，之后我们实施一个超时保障，让我们退出。

你可以把这看作在网络应用程序中特别有用；即使在阻塞和依赖线程的服务器时代，像这样的超时也被实施以防止单个行为不端的请求或进程阻塞整个服务器。这正是我们稍后将更详细讨论的经典网络服务器问题的基础。

### 一致性的重要性

在我们的示例中，我们将构建一个事件调度程序。如果我们可以参加会议，并且我们收到两个并发的会议邀请请求，如果存在竞争条件，我们将被重复预订。或者，两个 goroutine 之间的锁定数据可能会导致两个请求都被拒绝，或者导致实际死锁。

我们希望保证任何可用性请求都是一致的——既不应该出现重复预订，也不应该错误地阻止事件请求（因为两个并发或并行例程同时锁定数据）。

# 同步我们的并发操作

同步一词字面上指的是时间存在-事情同时发生。因此，同步性最恰当的演示似乎将涉及时间本身。

当我们考虑时间如何影响我们时，通常涉及安排、截止日期和协调。回到前言中的初步示例，如果有人想要计划他们祖母的生日派对，以下类型的安排任务可以采取多种形式：

+   必须在某个时间之前完成的事情（实际派对）

+   直到另一个任务完成后才能完成的事情（在购买装饰品之前放置装饰品）

+   可以按任何特定顺序完成的事情而不会影响结果（打扫房子）

+   可以按任何顺序完成但可能会影响结果的事情（在弄清楚你祖母最喜欢的蛋糕之前买蛋糕）

有了这些想法，我们将尝试通过设计一个预约日历来处理一些基本的人类安排，该日历可以处理任意数量的人，每个人在上午 9 点到下午 5 点之间有一个小时的时间段。

# 这个项目-多用户预约日历

当你决定写一个程序时，你会做什么？

如果你和很多人一样，你会考虑这个程序；也许你和团队会起草一份规范或需求文档，然后你就开始编码。有时，会有一张图表示应用程序的工作方式的某种类似物。

很多时候，确定应用程序的架构和内部工作方式的最佳方法是拿起铅笔和纸，直观地表示程序的工作方式。对于许多线性或串行应用程序来说，这通常是一个不必要的步骤，因为事情将以可预测的方式进行，不需要在应用程序逻辑内部进行任何特定的协调（尽管协调第三方软件可能会受益于规范）。

你可能熟悉类似以下图表的一些逻辑：

![该项目-多用户预约日历](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/ms-cncr-go/img/00012.jpeg)

这里的逻辑是有道理的。如果您还记得我们的前言，当人类绘制流程时，我们倾向于将它们串行化。从视觉上看，从第一步到第二步，有限数量的流程是容易理解的。

然而，在设计并发应用程序时，至少要考虑无数的并发请求、流程和逻辑，以确保我们的应用程序最终达到我们想要的位置，并获得我们期望的数据和结果。

在上一个例子中，我们完全忽略了“用户是否可用”的可能失败或报告旧或错误数据的可能性。如果我们发现这些问题，是否更有意义去解决它们，或者应该预见它们作为控制流的一部分？向模型添加复杂性可以帮助我们减少未来数据完整性问题的几率。

让我们再次进行可视化，考虑到可用性轮询器将请求用户的可用性与任何给定的时间/用户对。

## 可视化并发模式

正如我们已经讨论过的，我们希望创建一个应用程序应该如何运行的基本蓝图。在这里，我们将实现一些控制流，这与用户活动有关，以帮助我们决定我们需要包含哪些功能。以下图表说明了控制流可能是什么样子：

![可视化并发模式](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/ms-cncr-go/img/00013.jpeg)

在之前的图表中，我们预见到数据可以使用并发和并行流程共享，以找到故障点。如果我们以这种图形方式设计并发应用程序，我们就不太可能在以后发现竞争条件。

虽然我们谈到了 Go 如何帮助您在应用程序完成运行后找到这些问题，但我们理想的开发工作流程是尝试在开始时解决这些问题。

## 开发我们的服务器需求

现在我们已经有了调度过程应该如何工作的想法，我们需要确定应用程序将需要的组件。在这种情况下，组件如下：

+   Web 服务器处理程序

+   输出的模板

+   用于确定日期和时间的系统

### Web 服务器

在我们之前章节的可视化并发示例中，我们使用了 Go 的内置`http`包，我们在这里也会这样做。有许多出色的框架可以实现这一点，但它们主要是扩展核心 Go 功能，而不是重新发明轮子。以下是其中一些功能，从轻到重列出：

+   Web.go：[`webgo.io/`](http://webgo.io/)

Web.go 非常轻量级和精简，并提供了一些在`net`/`http`包中不可用的路由功能。

+   大猩猩：[`www.gorillatoolkit.org/`](http://www.gorillatoolkit.org/)

Gorilla 是一个瑞士军刀，用于增强`net`/`http`包。它并不特别沉重，而且速度快，实用，非常干净。

+   Revel：[`robfig.github.io/revel/`](http://robfig.github.io/revel/)

Revel 是这三者中最沉重的，但它专注于直观的代码、缓存和性能。如果您需要一个成熟的、将面临大量流量的东西，可以考虑它。

在第六章中，*C10K – A Non-blocking Web Server in Go*，我们将自己开发一个旨在实现极高性能的 Web 服务器和框架。

#### 大猩猩工具包

对于这个应用程序，我们将部分使用 Gorilla Web 工具包。 Gorilla 是一个相当成熟的 Web 服务器平台，在这里本地实现了我们的一些需求，即能够在 URL 路由中包含正则表达式的能力。（注意：Web.Go 还扩展了部分功能。）Go 的内部 HTTP 路由处理程序相当简单；当然您可以扩展这个，但在这里我们将走一条经过磨练和可靠的捷径。

我们将仅使用这个包来方便 URL 路由，但 Gorilla Web Toolkit 还包括处理 cookies、会话和请求变量的包。我们将在第六章中更详细地研究这个包，*C10K – 一个 Go 中的非阻塞 Web 服务器*。

### 使用模板

由于 Go 被设计为一种系统语言，而系统语言通常涉及创建服务器和客户端，因此我们在创建 Web 服务器时非常注重使其成为一个功能齐全的替代方案。

任何处理过“网络语言”的人都会知道，除此之外你还需要一个框架，理想情况下是一个处理网络呈现层的框架。虽然如果你接手这样的项目，你可能会寻找或构建自己的框架，但 Go 使得模板方面的事情非常容易。

模板包有两种类型：`text`和`http`。虽然它们都服务于不同的端点，但相同的属性——提供动态性和灵活性——适用于呈现层，而不仅仅是应用层。

### 提示

`text`模板包用于一般纯文本文档，而`http`模板包用于生成 HTML 和相关文档。

这些模板范式在今天太常见了；如果你看一下`http`/`template`包，你会发现它与 Mustache 有很强的相似之处，Mustache 是更受欢迎的变体之一。虽然 Go 中有一个 Mustache 端口，但在模板包中默认处理了所有这些。

### 注意

有关 Mustache 的更多信息，请访问[`mustache.github.io/`](http://mustache.github.io/)。

Mustache 的一个潜在优势是它在其他语言中也是可用的。如果你曾经感到有必要将应用逻辑转移到另一种语言（或将现有模板转移到 Go 中），使用 Mustache 可能是有利的。也就是说，你牺牲了 Go 模板的许多扩展功能，即从编译包中取出 Go 代码并将其直接移入模板控制结构的能力。虽然 Mustache（及其变体）有控制流，但它们可能不会与 Go 的模板系统相匹配。看下面的例子：

```go
<ul>
{{range .Users}}
<li>A User </li>
{{end}}
</ul>
```

鉴于对 Go 逻辑结构的熟悉程度，保持它们在我们的模板语言中保持一致是有意义的。

### 注意

我们不会在这个帖子中展示所有具体的模板，但我们会展示输出。如果你想浏览它们，它们可以在[mastergoco.com/chapters/3/templates](http://mastergoco.com/chapters/3/templates)上找到。

### 时间

我们在这里没有做太多的数学运算；时间将被分成小时块，每个小时块将被设置为占用或可用。目前，Go 中没有太多外部的`date`/`time`包。我们没有进行任何复杂的日期数学运算，但这并不重要，因为即使我们需要，Go 的`time`包也应该足够。

实际上，由于我们从上午 9 点到下午 5 点有文字的时间段，我们只需将它们设置为 9-17 的 24 小时时间值，并调用一个函数将它们转换为语言日期。

## 端点

我们将想要识别 REST 端点（通过`GET`请求）并简要描述它们的工作原理。你可以将它们看作是模型-视图-控制器架构中的模块或方法。以下是我们将使用的端点模式列表：

+   `entrypoint/register/{name}`：这是我们将要去的地方，添加一个名字到用户列表中。如果用户存在，它将失败。

+   `entrypoint/viewusers`：在这里，我们将展示一个用户列表，包括他们的时间段，可用和占用。

+   `entrypoint/schedule/{name}/{time}`：这将初始化一个预约的尝试。

每个都将有一个相应的模板，报告预期动作的状态。

## 自定义结构

我们将处理用户和响应（网页），所以我们需要两个结构来表示每个。一个结构如下：

```go
type User struct {
  Name string
  email string
  times[int] bool
}
```

另一个结构如下：

```go
type Page struct {
  Title string
  Body string
}
```

我们将尽量保持页面尽可能简单。我们将在代码中生成大部分 HTML，而不是进行大量的迭代循环。

我们的请求端点将与我们之前的架构相关联，使用以下代码：

```go
func users(w http.ResponseWriter, r *http.Request) {
}
func register(w http.ResponseWriter, r *http.Request) {
}
func schedule(w http.ResponseWriter, r *http.Request) {
}
```

# 多用户预约日历

在本节中，我们将快速查看我们的样本预约日历应用程序，该应用程序试图控制特定元素的一致性，以避免明显的竞争条件。以下是完整的代码，包括路由和模板：

```go
package main

import(
  "net/http"
  "html/template"
  "fmt"
  "github.com/gorilla/mux"
  "sync"
  "strconv"
)

type User struct {
  Name string
  Times map[int] bool
  DateHTML template.HTML
}

type Page struct {
  Title string
  Body template.HTML
  Users map[string] User
}

var usersInit map[string] bool
var userIndex int
var validTimes []int
var mutex sync.Mutex
var Users map[string]User
var templates = template.Must(template.New("template").ParseFiles("view_users.html", "register.html"))

func register(w http.ResponseWriter, r *http.Request){
  fmt.Println("Request to /register")
  params := mux.Vars(r)
  name := params["name"]

  if _,ok := Users[name]; ok {
    t,_ := template.ParseFiles("generic.txt")
    page := &Page{ Title: "User already exists", Body: 
      template.HTML("User " + name + " already exists")}
    t.Execute(w, page)
  }  else {
          newUser := User { Name: name }
          initUser(&newUser)
          Users[name] = newUser
          t,_ := template.ParseFiles("generic.txt")
          page := &Page{ Title: "User created!", Body: 
            template.HTML("You have created user "+name)}
          t.Execute(w, page)
    }

}

func dismissData(st1 int, st2 bool) {

// Does nothing in particular for now other than avoid Go compiler 
  errors
}

func formatTime(hour int) string {
  hourText := hour
  ampm := "am"
  if (hour > 11) {
    ampm = "pm"
  }
  if (hour > 12) {
    hourText = hour - 12;
  }
fmt.Println(ampm)
  outputString := strconv.FormatInt(int64(hourText),10) + ampm

  return outputString
}

func (u User) FormatAvailableTimes() template.HTML { HTML := "" 
  HTML += "<b>"+u.Name+"</b> - "

  for k,v := range u.Times { dismissData(k,v)

    if (u.Times[k] == true) { formattedTime := formatTime(k) HTML 
      += "<a href='/schedule/"+u.Name+"/"+strconv.FormatInt(int64(k),10)+"' class='button'>"+formattedTime+"</a> "

    } else {

    }

 } return template.HTML(HTML)
}

func users(w http.ResponseWriter, r *http.Request) {
  fmt.Println("Request to /users")

  t,_ := template.ParseFiles("users.txt")
  page := &Page{ Title: "View Users", Users: Users}
  t.Execute(w, page)
}

func schedule(w http.ResponseWriter, r *http.Request) {
  fmt.Println("Request to /schedule")
  params := mux.Vars(r)
  name := params["name"]
  time := params["hour"]
  timeVal,_ := strconv.ParseInt( time, 10, 0 )
  intTimeVal := int(timeVal)

  createURL := "/register/"+name

  if _,ok := Users[name]; ok {
    if Users[name].Times[intTimeVal] == true {
      mutex.Lock()
      Users[name].Times[intTimeVal] = false
      mutex.Unlock()
      fmt.Println("User exists, variable should be modified")
      t,_ := template.ParseFiles("generic.txt")
      page := &Page{ Title: "Successfully Scheduled!", Body: 
        template.HTML("This appointment has been scheduled. <a 
          href='/users'>Back to users</a>")}

      t.Execute(w, page)

    }  else {
            fmt.Println("User exists, spot is taken!")
            t,_ := template.ParseFiles("generic.txt")
            page := &Page{ Title: "Booked!", Body: 
              template.HTML("Sorry, "+name+" is booked for 
              "+time+" <a href='/users'>Back to users</a>")}
      t.Execute(w, page)

    }

  }  else {
          fmt.Println("User does not exist")
          t,_ := template.ParseFiles("generic.txt")
          page := &Page{ Title: "User Does Not Exist!", Body: 
            template.HTML( "Sorry, that user does not exist. Click 
              <a href='"+createURL+"'>here</a> to create it. <a 
                href='/users'>Back to users</a>")}
    t.Execute(w, page)
  }
  fmt.Println(name,time)
}

func defaultPage(w http.ResponseWriter, r *http.Request) {

}

func initUser(user *User) {

  user.Times = make(map[int] bool)
  for i := 9; i < 18; i ++ {
    user.Times[i] = true
  }

}

func main() {
  Users = make(map[string] User)
  userIndex = 0
  bill := User {Name: "Bill"  }
  initUser(&bill)
  Users["Bill"] = bill
  userIndex++

  r := mux.NewRouter()  r.HandleFunc("/", defaultPage)
    r.HandleFunc("/users", users)  
      r.HandleFunc("/register/{name:[A-Za-z]+}", register)
        r.HandleFunc("/schedule/{name:[A-Za-z]+}/{hour:[0-9]+}", 
          schedule)     http.Handle("/", r)

  err := http.ListenAndServe(":1900", nil)  if err != nil {    // 
    log.Fatal("ListenAndServe:", err)    }

}
```

请注意，我们用一个名为 Bill 的用户种子化了我们的应用程序。如果您尝试访问`/register/bill|bill@example.com`，应用程序将报告该用户已存在。

由于我们通过渠道控制了最敏感的数据，我们避免了任何竞争条件。我们可以通过几种方式来测试这一点。第一种最简单的方法是记录成功预约的数量，并以 Bill 作为默认用户运行。

然后我们可以对该操作运行并发负载测试器。有许多这样的测试器可用，包括 Apache 的 ab 和 Siege。为了我们的目的，我们将使用 JMeter，主要是因为它允许我们同时对多个 URL 进行测试。

### 提示

虽然我们并不一定使用 JMeter 进行负载测试（而是用它来运行并发测试），但负载测试工具可以是发现应用程序中尚不存在的规模的瓶颈的非常有价值的方式。

例如，如果您构建了一个具有阻塞元素并且每天有 5,000-10,000 个请求的 Web 应用程序，您可能不会注意到它。但是在每天 500 万-1000 万次请求时，它可能导致应用程序崩溃。

在网络服务器的黎明时代，情况就是这样；服务器扩展到某一天，突然间，它们无法再扩展。负载/压力测试工具允许您模拟流量，以更好地检测这些问题和低效。

鉴于我们有一个用户和一天八个小时，我们应该在脚本结束时最多有八个成功的预约。当然，如果您访问`/register`端点，您将看到比您添加的用户多八倍的用户。以下截图显示了我们在 JMeter 中的基准测试计划：

![多用户预约日历](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/ms-cncr-go/img/00014.jpeg)

当您运行应用程序时，请注意您的控制台；在我们的负载测试结束时，我们应该会看到以下消息：

```go
Total registered appointments: 8

```

如果我们按照本章中最初的图形模拟表示设计我们的应用程序（存在竞争条件），那么我们可能会注册比实际存在的预约要多得多。

通过隔离潜在的竞争条件，我们保证数据一致性，并确保没有人在等待与其他人预约时间冲突的预约。以下截图是我们呈现的所有用户及其可用预约时间的列表：

![多用户预约日历](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/ms-cncr-go/img/00015.jpeg)

上一个截图是我们的初始视图，显示了可用用户及其可用的时间段。通过为用户选择一个时间段，我们将尝试为其预约该特定时间。我们将从下午 5 点开始尝试 Nathan。

以下截图显示了当我们尝试与一个可用用户安排时会发生什么：

![多用户预约日历](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/ms-cncr-go/img/00016.jpeg)

然而，如果我们再次尝试预约（甚至同时），我们将收到一个悲伤的消息，即 Nathan 无法在下午 5 点见我们，如下面的截图所示：

![多用户预约日历](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/ms-cncr-go/img/00017.jpeg)

有了这个，我们有了一个允许创建新用户、安排和阻止重复预约的多用户日历应用程序。

让我们来看看这个应用程序中一些有趣的新点。

首先，您会注意到我们在大部分应用程序中使用了一个名为`generic.txt`的模板。这并不复杂，只有一个页面标题和每个处理程序填写的正文。然而，在`/users`端点上，我们使用`users.txt`如下：

```go
<html>
<head>
  <meta http-equiv="Content-Type" content="text/html; charset=utf-
    8"> 
  <title>{{.Title}}</title>
</head>
<body>

<h1>{{.Title}}</h1>

{{range .Users}}
<div class="user-row">

  {{.FormatAvailableTimes}}

</div>
{{end}}

</body>
</html>
```

我们在模板中提到了基于范围的功能，但是`{{.FormatAvailableTimes}}`是如何工作的呢？在任何给定的上下文中，我们可以有特定于类型的函数，以比模板词法分析器严格可用的更复杂的方式处理数据。

在这种情况下，`User`结构体被传递到以下代码行：

```go
func (u User) FormatAvailableTimes() template.HTML {
```

然后，这行代码执行一些条件分析，并返回一些时间转换的字符串。

在这个例子中，您可以使用一个通道来控制`User.times`的流程，或者像我们这样使用一个显式的互斥锁。除非绝对必要，我们不希望限制所有锁，因此只有在确定请求已经通过必要的测试来修改任何给定用户/时间对的状态时，我们才调用`Lock()`函数。下面的代码显示了我们在互斥锁中设置用户的可用性的地方：

```go
if _,ok := Users[name]; ok {
  if Users[name].Times[intTimeVal] == true {
    mutex.Lock()
    Users[name].Times[intTimeVal] = false
    mutex.Unlock()
```

外部评估检查是否存在具有该名称（键）的用户。第二次评估检查时间可用性是否存在（true）。如果是，我们锁定变量，将其设置为`false`，然后继续输出渲染。

没有`Lock()`函数，许多并发连接可能会损害数据的一致性，并导致用户在特定小时内有多个预约。

# 风格注意事项

请注意，尽管我们更喜欢大多数变量使用驼峰命名法，但在结构体中有一些大写变量。这是一个重要的 Go 约定，值得一提：任何以大写字母开头的结构体变量都是**公共的**。任何以小写字母开头的变量都是**私有的**。

如果您尝试在模板文件中输出私有（或不存在的）变量，模板渲染将失败。

# 关于不可变性的说明

请注意，尽可能避免在模板文件中使用字符串类型进行比较操作，特别是在多线程环境中。在前面的例子中，我们使用整数和布尔值来决定任何给定用户的可用性。在某些语言中，您可能会感到有能力将时间值分配给字符串以便使用。在大多数情况下，这是可以的，即使在 Go 中也是如此；但是假设我们有一个无限可扩展的共享日历应用程序，如果我们以这种方式使用字符串，就会引入内存问题的风险。

在 Go 中，字符串类型是唯一的不可变类型；如果您最终将值分配和重新分配给字符串，这是值得注意的。假设在将字符串转换为副本后释放内存，这不是问题。然而，在 Go（以及其他几种语言）中，完全有可能保留原始值在内存中。我们可以使用以下示例进行测试：

```go
func main() {

  testString := "Watch your top / resource monitor"
  for i:= 0; i < 1000; i++ {

    testString = string(i)

  }
  doNothing(testString)  

  time.Sleep(10 * time.Second)

}
```

在 Ubuntu 中运行时，这大约需要 1.0 MB 的内存；其中一些无疑是开销，但这是一个有用的参考点。让我们稍微加大一点——虽然有 1,000 个相对较小的指针不会产生太大影响——使用以下代码行：

```go
for i:= 0; i < 100000000; i++ {
```

现在，经过 1 亿次内存分配，您可以看到对内存的影响（此时字符串本身比初始值更长并不会占据全部影响）。垃圾回收也会在这里发生，这会影响 CPU。在我们的初始测试中，CPU 和内存都会飙升。如果我们将其替换为整数或布尔值分配，我们会得到更小的印记。

这并不是一个真实的场景，但在并发环境中，垃圾回收必须发生，以便我们可以评估我们的逻辑的属性和类型，这是值得注意的。

根据您当前的 Go 版本、您的机器等情况，这两种情况可能都能够以高效方式运行。虽然这可能看起来不错，但是我们的并发策略规划的一部分应该包括我们的应用程序将在输入、输出、物理资源或所有这些方面扩展的可能性。现在能够很好地工作并不意味着不值得实施效率，以避免在 100 倍规模时引起性能问题。

如果你遇到一个地方，那里一个字符串是合乎逻辑的，但你想要或者可以从可变类型中受益，考虑使用字节切片。

常量当然也是不可变的，但鉴于常量变量的暗含目的，你应该已经知道这一点。可变的常量变量毕竟是一个矛盾。

# 总结

本章希望引导您在深入研究之前探索规划和绘制并发应用程序的方法。通过简要介绍竞争条件和数据一致性，我们试图突出预期设计的重要性。同时，我们利用了一些工具来识别这些问题，如果它们发生的话。

创建一个具有并发进程的健壮脚本流程图将帮助你在创建之前找到可能的陷阱，并且它将让你更好地了解你的应用程序应该如何（以及何时）根据逻辑和数据做出决策。

在下一章中，我们将研究数据一致性问题，并探讨高级通道通信选项，以避免不必要且经常昂贵的缓解功能、互斥锁和外部进程。
