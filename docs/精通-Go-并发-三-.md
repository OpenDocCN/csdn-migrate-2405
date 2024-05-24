# 精通 Go 并发（三）

> 原文：[`zh.annas-archive.org/md5/5C14031AC553348345D455C9E701A474`](https://zh.annas-archive.org/md5/5C14031AC553348345D455C9E701A474)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第七章：性能和可扩展性

只需几百行代码就可以在 Go 中构建一个高性能的 Web 服务器，您应该非常清楚，并发 Go 为我们提供了出色的性能和稳定性工具。

我们在第六章中的示例，*C10K – A Non-blocking Web Server in Go*，也展示了如何在我们的代码中任意或无意地引入阻塞代码会引入严重的瓶颈，并迅速破坏扩展或扩展应用程序的计划。

在本章中，我们将看一些方法，可以更好地准备我们的并发应用程序，确保它能够持续扩展，并且能够在范围、设计和/或容量上进行扩展。

我们将更深入地扩展**pprof**，这是我们在之前章节中简要介绍的 CPU 分析工具，作为阐明我们的 Go 代码是如何编译的，并找出可能的意外瓶颈的方法。

然后我们将扩展到分布式 Go，以及提供一些性能增强的并行计算概念到我们的应用程序中的方法。我们还将看看谷歌应用引擎，以及如何利用它来确保您的基于 Go 的应用程序能够扩展到世界上最可靠的托管基础设施之一。

最后，我们将研究内存利用、保留以及谷歌的垃圾收集器的工作方式（有时也会出现问题）。我们将深入研究如何使用内存缓存来保持数据一致性，以及如何与分布式计算结合，最终也会看到这与分布式计算的关系。

# Go 的高性能

到目前为止，我们已经讨论了一些工具，可以帮助我们发现减速、泄漏和低效的循环。

Go 的编译器和内置的死锁检测器阻止了我们在其他语言中常见且难以检测的错误。

我们基于特定并发模式的时间基准测试，可以帮助我们使用不同的方法设计我们的应用程序，以提高整体执行速度和性能。

## 深入了解 pprof

pprof 工具首次出现在第五章中，*Locks, Blocks, and Better Channels*，如果它仍然感觉有点神秘，那是完全可以理解的。pprof 向您显示的是一个**调用图**，我们可以使用它来帮助识别循环或堆上的昂贵调用的问题。这些包括内存泄漏和可以进行优化的处理器密集型方法。

展示这种工作原理的最好方法之一是构建一些不起作用的东西。或者至少是一些不按照应该的方式工作的东西。

您可能会认为具有垃圾收集的语言可能对这些类型的内存问题免疫，但总是有方法可以隐藏导致内存泄漏的错误。如果 GC 找不到它，有时自己找到它可能会非常痛苦，导致大量——通常是无效的——调试。

公平地说，什么构成内存泄漏有时在计算机科学成员和专家之间存在争议。如果程序不断消耗内存，根据技术定义，如果应用程序本身可以重新访问任何给定的指针，则可能不会泄漏内存。但当你有一个程序在消耗内存后崩溃时，这基本上是无关紧要的，就像大象在自助餐厅消耗内存一样。

在垃圾收集的语言中创建内存泄漏的基本前提是隐藏分配的内存，事实上，在任何可以直接访问和利用内存的语言中，都提供了引入泄漏的机制。

我们将在本章后面再次回顾一些关于垃圾收集和 Go 实现的内容。

那么像 pprof 这样的工具如何帮助呢？非常简单地说，它向您展示了**您的内存和 CPU 利用情况**。

让我们首先设计一个非常明显的 CPU 占用如下，看看 pprof 如何为我们突出显示这一点：

```go
package main

import (
"os"
"flag"
"fmt"
"runtime/pprof"
)

const TESTLENGTH = 100000
type CPUHog struct {
  longByte []byte
}

func makeLongByte() []byte {
  longByte := make([]byte,TESTLENGTH)

  for i:= 0; i < TESTLENGTH; i++ {
    longByte[i] = byte(i)
  }
  return longByte
}

var profile = flag.String("cpuprofile", "", "output pprof data to 
  file")

func main() {
  var CPUHogs []CPUHog

  flag.Parse()
    if *profile != "" {
      flag,err := os.Create(*profile)
      if err != nil {
        fmt.Println("Could not create profile",err)
      }
      pprof.StartCPUProfile(flag)
      defer pprof.StopCPUProfile()

    }

  for i := 0; i < TESTLENGTH; i++ {
    hog := CPUHog{}
    hog.longByte = makeLongByte()
    _ = append(CPUHogs,hog)
  }
}
```

上述代码的输出如下图所示：

![深入了解 pprof](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/ms-cncr-go/img/00039.jpeg)

在这种情况下，我们知道我们的堆栈资源分配去了哪里，因为我们故意引入了循环（以及其中的循环）。

想象一下，我们并没有故意这样做，而是不得不找出资源占用。在这种情况下，pprof 使这变得非常容易，向我们展示了创建和内存分配的简单字符串构成了我们大部分样本。

我们可以稍微修改一下，看看 pprof 输出的变化。为了分配更多的内存，看看我们是否可以改变 pprof 的输出，我们可能会考虑使用更重的类型和更多的内存。

最简单的方法是创建一个新类型的切片，其中包括大量这些较重的类型，如 int64。我们很幸运有 Go：在这方面，我们不容易出现常见的 C 问题，比如缓冲区溢出和内存保护和管理，但是当我们无法故意破坏内存管理系统时，调试就会变得有点棘手。

### 提示

**unsafe 包**

尽管提供了内置的内存保护，但 Go 还提供了另一个有趣的工具：**unsafe**包。根据 Go 的文档：

*包 unsafe 包含绕过 Go 程序类型安全性的操作。*

这可能看起来是一个奇怪的库要包括——确实，虽然许多低级语言允许您自毁，但提供一个分离的语言是相当不寻常的。

在本章的后面，我们将研究`unsafe.Pointer`，它允许您读写任意内存分配的位。这显然是非常危险的（或者有用和邪恶的，这取决于您的目标）功能，您通常会尽量避免在任何开发语言中使用，但它确实允许我们调试和更好地理解我们的程序和 Go 垃圾收集器。

为了增加我们的内存使用量，让我们将我们的字符串分配切换如下，用于随机类型分配，特别是用于我们的新结构`MemoryHog`：

```go
type MemoryHog struct {
  a,b,c,d,e,f,g int64
  h,i,j,k,l,m,n float64
  longByte []byte
}
```

显然，没有什么能阻止我们将其扩展为一组荒谬地大的切片，大量的 int64 数组等等。但我们的主要目标仅仅是改变 pprof 的输出，以便我们可以识别调用图样本中的移动以及它对我们的堆栈/堆配置文件的影响。

我们的任意昂贵的代码如下：

```go
type MemoryHog struct {
  a,b,c,d,e,f,g int64
  h,i,j,k,l,m,n float64
  longByte []byte
}

func makeMemoryHog() []MemoryHog {

  memoryHogs := make([]MemoryHog,TESTLENGTH)

  for i:= 0; i < TESTLENGTH; i++ {
    m := MemoryHog{}
    _ = append(memoryHogs,m)
  }

  return memoryHogs
}

var profile = flag.String("cpuprofile", "", "output pprof data to 
  file")

func main() {
  var CPUHogs []CPUHog

  flag.Parse()
    if *profile != "" {
      flag,err := os.Create(*profile)
      if err != nil {
        fmt.Println("Could not create profile",err)
      }
      pprof.StartCPUProfile(flag)
      defer pprof.StopCPUProfile()

    }

  for i := 0; i < TESTLENGTH; i++ {
    hog := CPUHog{}
    hog.mHog = makeMemoryHog()
    _ = append(CPUHogs,hog)
  }
}
```

有了这个，我们的 CPU 消耗保持大致相同（由于循环机制基本保持不变），但我们的内存分配增加了——毫不奇怪——大约 900%。你可能不会精确复制这些结果，但是一个小改变导致资源分配的重大差异的一般趋势是可以重现的。请注意，内存利用报告可以使用 pprof 进行，但这不是我们在这里所做的；这里的内存利用观察发生在 pprof 之外。

如果我们采取之前建议的极端方法——为我们的结构创建荒谬地大的属性——我们可以进一步进行，但让我们看看这对我们的 CPU 配置文件执行的总体影响。影响如下图所示：

![深入了解 pprof](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/ms-cncr-go/img/00040.jpeg)

在左侧，我们有我们的新分配方法，它调用我们更大的结构，而不是一组字符串。在右侧，我们有我们的初始应用程序。

相当戏剧性的波动，你觉得呢？虽然这两个程序在设计上都没有错，但我们可以轻松地切换我们的方法，看看资源去哪里，以及我们如何减少它们的消耗。

## 并行性和并发对 I/O pprof 的影响

当使用 pprof 时，您可能会很快遇到一个问题，那就是当您编写的脚本或应用程序特别依赖于高效的运行时性能时。当您的程序执行速度过快以至于无法正确进行性能分析时，这种情况最常见。

一个相关的问题涉及到需要连接进行性能分析的网络应用程序；在这种情况下，您可以在程序内部或外部模拟流量，以便进行正确的性能分析。

我们可以通过使用 goroutines 复制类似于前面示例的方式来轻松演示这一点：

```go
const TESTLENGTH = 20000

type DataType struct {
  a,b,c,d,e,f,g int64
  longByte []byte  
}

func (dt DataType) init() {

}

var profile = flag.String("cpuprofile", "", "output pprof data to 
  file")

func main() {

  flag.Parse()
    if *profile != "" {
      flag,err := os.Create(*profile)
      if err != nil {
        fmt.Println("Could not create profile",err)
      }
      pprof.StartCPUProfile(flag)
      defer pprof.StopCPUProfile()
    }
  var wg sync.WaitGroup

  numCPU := runtime.NumCPU()
  runtime.GOMAXPROCS(numCPU)

  wg.Add(TESTLENGTH)

  for i := 0; i < TESTLENGTH; i++ {
    go func() {
      for y := 0; y < TESTLENGTH; y++ {
        dT := DataType{}
        dT.init()
      }
      wg.Done()
    }()
  }

  wg.Wait()

  fmt.Println("Complete.")
}
```

以下图显示了前面代码的 pprof 输出：

![并行性和并发性对 I/O pprof 的影响](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/ms-cncr-go/img/00041.jpeg)

这并不是那么具有信息量，是吗？

如果我们想要获得有关 goroutines 堆栈跟踪的更有价值的信息，Go——像往常一样——提供了一些额外的功能。

在运行时包中，有一个函数和一个方法，允许我们访问和利用 goroutines 的堆栈跟踪：

+   `runtime.Lookup`：此函数根据名称返回一个性能分析

+   `runtime.WriteTo`：此方法将快照发送到 I/O 写入器

如果我们在程序中添加以下行，我们将无法在`pprof` Go 工具中看到输出，但我们可以在控制台中获得对我们的 goroutines 的详细分析。

```go
pprof.Lookup("goroutine").WriteTo(os.Stdout, 1)
```

前一行代码给出了一些抽象 goroutine 内存位置信息和包细节，看起来会像下面的截图：

![并行性和并发性对 I/O pprof 的影响](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/ms-cncr-go/img/00042.jpeg)

但更快的获得这个输出的方法是利用`http`/`pprof`工具，它通过一个单独的服务器保持我们应用程序的结果处于活动状态。我们在这里使用了端口 6000，如下面的代码所示，但您可以根据需要进行修改：

```go
  go func() {
    log.Println(http.ListenAndServe("localhost:6000", nil))
  }()
```

虽然您无法获得 goroutine 堆栈调用的 SVG 输出，但您可以通过访问`http://localhost:6060/debug/pprof/goroutine?debug=1`在浏览器中实时查看。

# 使用 App Engine

虽然并非适用于每个项目，但 Google 的 App Engine 可以在并发应用程序方面提供可扩展性，而无需进行 VM 配置、重启、监控等繁琐操作。

App Engine 与亚马逊网络服务、DigitalOcean 等并没有完全不同，唯一的区别在于您不需要必须参与直接服务器设置和维护的细节。它们都提供了一个单一的地方来获取和利用虚拟计算资源来运行您的应用程序。

相反，它可以成为谷歌架构中更抽象的环境，用于在多种语言中托管和运行您的代码，包括——毫不奇怪的——Go 语言本身。

大型应用程序将会产生费用，但 Google 提供了一个免费的层次，具有合理的试验和小型应用程序的配额。

与可扩展性相关的好处有两个：您无需像在 AWS 或 DigitalOcean 场景中那样负责确保实例的正常运行时间。除了谷歌之外，还有谁不仅拥有支持任何你可以投入其中的架构，而且还拥有 Go 核心本身的最快更新速度？

当然，这里有一些明显的限制与优势相一致，包括您的核心应用程序将仅通过`http`可用（尽管它将可以访问到其他许多服务）。

### 提示

要将应用程序部署到 App Engine，您需要 Go 的 SDK，适用于 Mac OS X、Linux 和 Windows，网址为[`developers.google.com/appengine/downloads#Google_App_Engine_SDK_for_Go`](https://developers.google.com/appengine/downloads#Google_App_Engine_SDK_for_Go)。

安装了 SDK 后，您需要对代码进行一些微小的更改，最值得注意的一点是，在大多数情况下，您的 Go 工具命令将被`goapp`替代，它负责在本地提供您的应用程序，然后部署它。

# 分布式 Go

我们确实涵盖了很多关于并发和并行 Go 的内容，但对于开发人员和系统架构师来说，最大的基础设施挑战之一与协作计算有关。

我们之前提到的一些应用程序和设计从并行扩展到分布式计算。

Memcache(d)是一种内存缓存，可以用作多个系统之间的队列。

我们在第四章中提出的主从和生产者-消费者模型与 Go 中的单机编程相比更多地涉及分布式计算，后者在并发方面具有成语特色。这些模型是许多语言中典型的并发模型，但也可以扩展到帮助我们设计分布式系统，利用不仅是许多核心和丰富的资源，还有冗余。

分布式计算的基本原则是将任何给定应用程序的各种负担分享、分散和最佳吸收到许多系统中。这不仅可以提高总体性能，还可以为系统本身提供一定程度的冗余。

这一切都是有一定成本的，具体如下：

+   网络延迟的潜在可能性

+   导致通信和应用程序执行减速

+   设计和维护上的复杂性整体增加

+   分布式路线上各个节点存在安全问题的潜在可能性

+   由于带宽考虑可能增加成本

这一切都是为了简单地说，虽然构建分布式系统可以为利用并发性和确保数据一致性的大型应用程序提供巨大的好处，但这并不意味着它适用于每个示例。

## 拓扑类型

分布式计算认识到分布式设计的一系列逻辑拓扑结构。拓扑结构是一个恰当的比喻，因为所涉及系统的位置和逻辑通常可以代表物理拓扑。

并非所有被接受的拓扑结构都适用于 Go。当我们使用 Go 设计并发分布式应用程序时，通常会依赖于一些更简单的设计，具体如下。

### 类型 1-星形

星形拓扑结构（或至少是这种特定形式），类似于我们之前概述的主从或生产者-消费者模型。

数据传递的主要方法涉及使用主服务器作为消息传递通道；换句话说，所有请求和命令都由单个实例协调，该实例使用某种路由方法传递消息。以下图显示了星形拓扑结构：

![类型 1-星形](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/ms-cncr-go/img/00043.jpeg)

我们实际上可以非常快速地为此设计一个基于 goroutine 的系统。以下代码仅为主服务器（或分布式目的地）的代码，缺乏任何安全考虑，但显示了我们如何将网络调用转换为 goroutines：

```go
package main

import
(
  "fmt"
  "net"

)
```

我们的标准基本库定义如下：

```go
type Subscriber struct {
  Address net.Addr
  Connection net.Conn
  do chan Task  
}

type Task struct {
  name string
}
```

这是我们将在这里使用的两种自定义类型。`Subscriber`类型是任何进入战场的分布式助手，`Task`类型代表任何给定的可分发任务。我们在这里没有定义它，因为这不是演示的主要目标，但你可以通过在 TCP 连接上通信标准化命令来做任何事情。`Subscriber`类型定义如下：

```go
var SubscriberCount int
var Subscribers []Subscriber
var CurrentSubscriber int
var taskChannel chan Task

func (sb Subscriber) awaitTask() {
  select {
    case t := <-sb.do:
      fmt.Println(t.name,"assigned")

  }
}

func serverListen (listener net.Listener) {
  for {
    conn,_ := listener.Accept()

    SubscriberCount++

    subscriber := Subscriber{ Address: conn.RemoteAddr(), 
      Connection: conn }
    subscriber.do = make(chan Task)
    subscriber.awaitTask()
    _ = append(Subscribers,subscriber)

  }
}

func doTask() {
  for {
    select {
      case task := <-taskChannel:
        fmt.Println(task.name,"invoked")
        Subscribers[CurrentSubscriber].do <- task
        if (CurrentSubscriber+1) > SubscriberCount {
          CurrentSubscriber = 0
        }else {
          CurrentSubscriber++
        }
    }

  }
}

func main() {

  destinationStatus := make(chan int)

  SubscriberCount = 0
  CurrentSubscriber = 0

  taskChannel = make(chan Task)

  listener, err := net.Listen("tcp", ":9000")
  if err != nil {
    fmt.Println ("Could not start server!",err)
  }
  go serverListen(listener)  
  go doTask()

  <-destinationStatus
}
```

这实质上将每个连接视为一个新的`Subscriber`，它根据其索引获得自己的通道。然后，主服务器使用以下非常基本的轮询方法迭代现有的`Subscriber`连接：

```go
if (CurrentSubscriber+1) > SubscriberCount {
  CurrentSubscriber = 0
}else {
  CurrentSubscriber++
}
```

如前所述，这缺乏任何安全模型，这意味着对端口 9000 的任何连接都将成为`Subscriber`，并且可以接收分配给它的网络消息（并且可能还可以调用新消息）。但您可能已经注意到一个更大的遗漏：这个分布式应用程序什么也没做。实际上，这只是一个用于分配和管理订阅者的模型。现在，它没有任何行动路径，但我们将在本章后面更改这一点。

### 类型 2-网格

网格与星型非常相似，但有一个主要区别：每个节点不仅可以通过主节点进行通信，还可以直接与其他节点进行通信。这也被称为**完全图**。以下图显示了网格拓扑结构：

![类型 2-网格](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/ms-cncr-go/img/00044.jpeg)

出于实际目的，主服务器仍然必须处理分配并将连接传递回各个节点。

实际上，通过对我们之前的服务器代码进行以下简单修改，添加这个并不特别困难：

```go
func serverListen (listener net.Listener) {
  for {
    conn,_ := listener.Accept()

    SubscriberCount++

    subscriber := Subscriber{ Address: conn.RemoteAddr(), 
      Connection: conn }
    subscriber.awaitTask()
    _ = append(Subscribers,subscriber)
    broadcast()
  }
}
```

然后，我们添加以下对应的`broadcast`函数，将所有可用的连接共享给所有其他连接：

```go
func broadcast() {
  for i:= range Subscribers {
    for j:= range Subscribers {
      Subscribers[i].Connection.Write
        ([]byte("Subscriber:",Subscriber[j].Address))  
    }
  }
}
```

### 发布和订阅模型

在前面的两种拓扑结构中，我们复制了一个由中央/主服务器处理交付的发布和订阅模型。与单系统并发模式不同，我们缺乏直接在不同计算机之间使用通道的能力（除非我们使用像 Go 的 Circuit 这样的东西，如第四章中所述的那样，*应用程序中的数据完整性*）。

没有直接的编程访问来发送和接收实际命令，我们依赖某种形式的 API。在前面的例子中，没有实际发送或执行的任务，但我们该如何做呢？

显然，要创建可以形式化为非代码传输的任务，我们需要一种 API 形式。我们可以通过两种方式之一来实现这一点：命令序列化，理想情况下通过 JSON 直接传输，以及代码执行。

由于我们将始终处理编译后的代码，因此命令序列化选项可能看起来似乎无法包含 Go 代码本身。这并不完全正确，但是在任何语言中传递完整代码都是安全问题的重要问题。

但让我们看看通过 API 以任务的方式发送数据的两种方法，即通过从 URL 切片中删除一个 URL 以进行检索。我们首先需要在我们的`main`函数中初始化该数组，如下面的代码所示：

```go
type URL struct {
  URI string
  Status int
  Assigned Subscriber
  SubscriberID int
}
```

我们数组中的每个 URL 都将包括 URI、其状态和分配给它的订阅者地址。我们将状态点规范为 0 表示未分配，1 表示已分配并等待，2 表示已分配并完成。

还记得我们的`CurrentSubscriber`迭代器吗？它代表了下一个轮询分配，将为我们的`URL`结构的`SubscriberID`值提供值。

接下来，我们将创建一个任意的 URL 数组，代表我们在这里的整体工作。可能需要一些怀疑来假设检索四个 URL 需要任何分布式系统；实际上，这将通过网络传输引入显著的减速。我们之前在纯粹的单系统并发应用程序中处理过这个问题：

```go
  URLs = []URL{ {Status:0,URL:"http://golang.org/"}, 
    {Status:0,URL:"http://play.golang.org/"}, 
      {Status:0,URL:"http://golang.org/doc/"}, 
        {Status:0,URL:"http://blog.golang.org/"} }
```

### 序列化数据

在 API 的第一个选项中，我们将以 JSON 格式发送和接收序列化数据。我们的主服务器将负责规范其命令和相关数据。在这种情况下，我们希望传输一些内容：要做什么（在这种情况下是检索）与相关数据，当完成时响应应该是什么，以及如何处理错误。

我们可以用自定义结构表示如下：

```go
type Assignment struct {
  command string
  data string
  successResponse string
  errorResponse string
}
...
  asmnt := Assignment{command:"process",
    url:"http://www.golang.org",successResponse:"success",
      errorResponse:"error"}
  json, _ := json.Marshal(asmnt )
  send(string(json))
```

### 远程代码执行

远程代码执行选项并不一定与命令序列化分开，而是结构化和解释格式化响应的替代方案，有效载荷可以是将通过系统命令运行的代码。

例如，任何语言的代码都可以通过网络传递，并且可以从另一种语言的 shell 或 syscall 库中执行，就像以下 Python 示例一样：

```go
from subprocess import call
call([remoteCode])
```

这种方法的缺点很多：它引入了严重的安全问题，并使您几乎无法在客户端内部进行错误检测。

优点是您不需要为响应制定特定的格式和解释器，以及潜在的速度改进。您还可以将响应代码卸载到任意数量的语言的另一个外部进程中。

在大多数情况下，命令的序列化远比远程代码执行选项更可取。

### 其他拓扑

存在许多更复杂的拓扑类型，作为消息队列的一部分更难管理。

以下图表显示了总线拓扑：

![其他拓扑](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/ms-cncr-go/img/00045.jpeg)

总线拓扑网络是一个单向传输系统。对于我们的目的来说，它既不特别有用，也不容易管理，因为每个添加的节点都需要宣布其可用性，接受监听器责任，并准备在新节点加入时放弃该责任。

总线的优势在于快速扩展性。但是，这也带来了严重的缺点：缺乏冗余和单点故障。

即使使用更复杂的拓扑，系统中始终会存在一些可能丢失宝贵齿轮的问题；在这种模块化冗余级别上，将需要一些额外的步骤来实现始终可用的系统，包括自动双重或三重节点复制和故障转移。这比我们在这里讨论的要多一些，但重要的是要注意，无论如何都会存在风险，尽管在总线等拓扑中更容易受到影响。

以下图表显示了环形拓扑：

![其他拓扑](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/ms-cncr-go/img/00046.jpeg)

环形拓扑看起来与我们的网状拓扑类似，但缺少主节点。它基本上需要与总线一样的通信过程（宣布和监听）。请注意一个重要的区别：通信不是在单个监听器之间进行，而是可以在没有主节点的情况下在任何节点之间进行。

这意味着所有节点都必须同时监听并宣布它们的存在给其他节点。

### 消息传递接口

还有一个稍微更正式的版本，称为消息传递接口，它是我们之前构建的更正式的版本。MPI 是从上世纪 90 年代初的学术界诞生的，作为分布式通信的标准。

最初是为 FORTRAN 和 C 而编写的，它仍然是一个协议，因此它基本上与语言无关。

MPI 允许管理高于我们能够为资源管理系统构建的基本拓扑，包括不仅是线性和环形拓扑，还有常见的总线拓扑。

在大多数情况下，MPI 被科学界使用；它是一种高度并发和类似的方法，用于构建大规模分布式系统。点对点操作更严格地定义了错误处理、重试和动态生成进程。

我们之前的基本示例没有为处理器设置优先级，这是 MPI 的核心效果之一。

Go 没有官方的 MPI 实现，但由于 C 和 C++都有官方实现，因此完全可以通过它们进行接口操作。

### 注意

还有一个由 Marcus Thierfelder 用 Go 编写的简单而不完整的绑定，您可以进行实验。它可以在[`github.com/marcusthierfelder/mpi`](https://github.com/marcusthierfelder/mpi)上找到。

您可以从[`www.open-mpi.org/`](http://www.open-mpi.org/)了解更多关于 OpenMPI 的信息并进行安装。

您也可以在[`www.mpich.org/`](http://www.mpich.org/)上阅读更多关于 MPI 和 MPICH 实现的信息。

# 一些有用的库

毫无疑问，Go 语言提供了一些最好的辅助工具，适用于任何编译语言。在许多系统上编译成本地代码，死锁检测，pprof，fmt 等工具不仅可以帮助你构建高性能的应用程序，还可以测试和格式化它们。

这并没有阻止社区开发其他工具，用于调试或帮助并发和/或分布式代码。我们将看看一些很棒的工具，可能值得包含在你的应用程序中，特别是如果它非常显眼或性能关键。

## Nitro 性能分析器

你现在可能已经很清楚，Go 的 pprof 非常强大和有用，尽管不太用户友好。

如果你已经喜欢 pprof，甚至如果你觉得它很繁琐和令人困惑，你可能会更喜欢 Nitro 性能分析器。来自 spf13 的 Steve Francia，Nitro 性能分析器可以让你更清晰地分析你的应用程序及其功能和步骤，同时提供更可用的备选功能的 A/B 测试。

### 提示

在[`spf13.com/project/nitro`](http://spf13.com/project/nitro)上阅读更多关于 Nitro 性能分析器的信息。

你可以通过[github.com/spf13/nitro](http://github.com/spf13/nitro)获取它。

与 pprof 一样，Nitro 会自动将标志注入到你的应用程序中，并且你会在结果中看到它们。

与 pprof 不同，你的应用程序不需要编译就可以从中获取性能分析。相反，你只需在`go run`命令后附加`-stepAnalysis`。

## Heka

Heka 是一个数据管道工具，可用于收集、分析和分发原始数据。Heka 来自 Mozilla，它更像是一个独立的应用程序，而不是一个库，但在获取、分析和分发诸如服务器日志文件之类的数据时，Heka 可以证明自己是有价值的。

Heka 也是用 Go 语言编写的，所以一定要查看源代码，看看 Mozilla 如何在实时数据分析中利用并发和 Go 语言。

### 提示

你可以访问 Heka 主页[`heka-docs.readthedocs.org/en/latest/`](http://heka-docs.readthedocs.org/en/latest/)和 Heka 源页[`github.com/mozilla-services/heka`](https://github.com/mozilla-services/heka)。

## GoFlow

最后，还有 GoFlow，这是一个基于流的编程范式工具，可以将你的应用程序分成不同的组件，每个组件都可以绑定到端口、通道、网络或进程。

虽然 GoFlow 本身不是一个性能工具，但对于一些应用程序来说，GoFlow 可能是扩展并发的合适方法。

### 提示

访问 GoFlow[`github.com/trustmaster/goflow`](https://github.com/trustmaster/goflow)。

# 内存保留

在撰写本文时，Go 1.2.2 的编译器使用了一个天真的标记/清除垃圾收集器，它为对象分配引用等级，并在它们不再使用时清除它们。这值得注意的只是为了指出它被广泛认为是一个相对较差的垃圾收集系统。

那么为什么 Go 要使用它呢？随着 Go 的发展，语言特性和编译速度在很大程度上优先于垃圾收集。虽然 Go 的长期发展时间轴，目前来看，这就是我们的现状。然而，这种权衡是很好的：正如你现在所知道的，编译 Go 代码比编译 C 或 C++代码快得多。目前的垃圾收集系统已经足够好了。但你可以做一些事情来增强和实验垃圾收集系统。

## Go 中的垃圾收集

要了解垃圾收集器在任何时候如何管理堆栈，可以查看`runtime.MemProfileRecord`对象，它跟踪当前活动堆栈跟踪中的对象。

在必要时，你可以调用性能记录，然后利用它来获取一些有趣的数据：

+   `InUseBytes()`: 这个方法根据内存配置文件当前使用的字节数

+   `InUseObjects()`:该方法返回正在使用的活动对象的数量

+   `Stack()`:该方法返回完整的堆栈跟踪

您可以将以下代码放入应用程序的重循环中，以查看所有这些内容：

```go
      var mem runtime.MemProfileRecord
      obj := mem.InUseObjects();
      bytes := mem.InUseBytes();
      stack := mem.Stack();
      fmt.Println(i,obj,bytes)
```

# 总结

现在我们可以构建一些非常高性能的应用程序，然后利用一些 Go 内置工具和第三方包，以在单个实例应用程序以及跨多个分布式系统中寻求最佳性能。

在下一章中，我们将把所有内容整合起来，设计并构建一个并发服务器应用程序，它可以快速独立地工作，并且可以轻松地在性能和范围上进行扩展。


# 第八章：并发应用程序架构

到目前为止，我们已经设计了一些并发程序的小部分，主要是在一个单一的部分中保持并发性。但我们还没有把所有东西联系起来，构建出更强大、更复杂、从管理员的角度来看更具挑战性的东西。

简单的聊天应用程序和 Web 服务器都很好。然而，最终您将需要更多的复杂性，并需要外部软件来满足所有更高级的要求。

在这种情况下，我们将构建一些由几个不协调的服务满足的东西：一个带有修订控制的文件管理器，提供 Web 和 Shell 访问。像 Dropbox 和 Google Drive 这样的服务允许用户在同行之间保留和共享文件。另一方面，GitHub 及其类似的服务允许使用类似的平台，但具有关键的修订控制的额外好处。

许多组织面临以下共享和分发选项的问题：

+   对存储库、存储空间或文件数量的限制

+   如果服务中断，可能导致无法访问

+   安全问题，特别是涉及敏感信息

简单的共享应用程序，如 Dropbox 和 Google Drive，在没有大量修订控制选项的情况下存储数据。GitHub 是一个出色的协作修订控制和分发系统，但伴随着许多成本，开发人员的错误可能导致严重的安全漏洞。

我们将结合版本控制的目标（以及 GitHub 的理想）与 Dropbox/Google Drive 的简单性和开放性。这种类型的应用程序将作为内部网络替代品非常完美——完全隔离并且可通过自定义身份验证访问，不一定依赖于云服务。将所有内容保留在内部消除了任何网络安全问题的潜在可能，并允许管理员设计符合其组织需求的永久备份解决方案。

组织内的文件共享将允许从命令行进行分叉、备份、文件锁定和修订控制，同时也可以通过简单的 Web 界面进行。

# 设计我们的并发应用程序

在设计并发应用程序时，我们将有三个在单独进程中运行的组件。文件监听器将被警报以对指定位置的文件进行更改。Web-CLI 界面将允许用户增加或修改文件，并且备份过程将绑定到监听器，以提供新文件更改的自动副本。考虑到这一点，这三个过程将看起来有点像下图所示的样子：

![设计我们的并发应用程序](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/ms-cncr-go/img/00047.jpeg)

我们的文件监听器进程将执行以下三项任务：

+   密切关注任何文件更改

+   向我们的 Web/CLI 服务器和备份过程进行广播

+   维护我们的数据库/数据存储中任何给定文件的状态

备份过程将接受文件监听器(#2)的任何广播，并以迭代设计创建备份文件。

我们的通用服务器（Web 和 CLI）将报告有关个别文件的详细信息，并允许使用可定制的语法进行前后版本控制。该应用程序的这一部分还必须在提交新文件或请求修订时向文件监听器进行广播。

# 确定我们的需求

我们的架构设计过程中最关键的一步是真正关注我们需要实现的功能、包和技术。对于我们的文件管理和修订控制应用程序，有一些关键点将突出显示：

+   允许文件上传、下载和修订的 Web 界面。

+   允许我们回滚更改并直接修改文件的命令行界面。

+   一个文件系统监听器，用于查找对共享位置所做的更改。

+   一个具有强大的 Go 关联性的数据存储系统，允许我们以基本一致的方式维护有关文件和用户的信息。该系统还将维护用户记录。

+   一个维护和循环更改文件日志的并发日志系统。

我们允许以下三种不同的方式与整个应用程序进行交互，这在某种程度上使事情变得复杂：

+   通过需要用户和登录的 Web。这也允许我们的用户访问和修改文件，即使他们可能在某个地方没有连接到共享驱动器。

+   通过命令行。这是过时的，但对于用户遍历文件系统，特别是不在 GUI 中的高级用户来说，它也是非常有价值的。

+   通过自身改变的文件系统。这是共享驱动机制，我们假设任何有权访问的用户都将对任何文件进行有效修改。

为了处理所有这些，我们可以确定一些关键的技术如下：

+   一个用于管理文件系统修订的数据库或数据存储。在选择事务性、ACID 兼容的 SQL 和 NoSQL 中的快速文档存储时，权衡通常是性能与一致性之间的权衡。然而，由于我们的大部分锁定机制将存在于应用程序中，复制锁定（即使在行级别）将增加潜在的缓慢和不需要的混乱。因此，我们将利用 NoSQL 解决方案。

+   这个解决方案需要很好地处理并发。

+   我们将使用一个 Web 界面，它引入了强大而干净的路由/多路复用，并与 Go 的强大内置模板系统很好地配合。

+   一个文件系统通知库，允许我们监视文件的更改以及备份修订。

我们发现或构建的任何解决方案都需要高度并发和非阻塞。我们要确保不允许对文件进行同时更改，包括对我们内部修订的更改。

考虑到所有这些，让我们逐个识别我们的部分，并决定它们在我们的应用程序中的作用。

我们还将提出一些备选方案，这些选项可以在不损害功能或核心要求的情况下进行交换。这将允许在平台或偏好使我们的主要选项不可取的情况下具有一定的灵活性。每当我们设计一个应用程序时，了解其他可能的选择是个好主意，以防软件（或其使用条款）发生变化，或者在未来的规模上不再满意使用。

让我们从我们的数据存储开始。

# 在 Go 中使用 NoSQL 作为数据存储

使用 NoSQL 的最大让步之一显然是在进行 CRUD 操作（创建、读取、更新和删除）时缺乏标准化。SQL 自 1986 年以来一直是标准化的，并且在许多数据库中非常严密——从 MySQL 到 SQL Server，从微软和甲骨文一直到 PostgreSQL。

### 注意

您可以在[`nosql-database.org/`](http://nosql-database.org/)上阅读更多关于 NoSQL 和各种 NoSQL 平台的信息。

Martin Fowler 在他的书《NoSQL Distilled》中也写了一篇关于这个概念和一些用例的流行介绍，网址为[`martinfowler.com/books/nosql.html`](http://martinfowler.com/books/nosql.html)。

根据 NoSQL 平台的不同，您还可能失去 ACID 兼容性和耐久性。这意味着您的数据不是 100%安全——如果服务器崩溃，如果读取过时或不存在的数据等，可能会有事务丢失。后者被称为脏读。

所有这些都值得注意，因为它适用于我们的应用程序，特别是在并发性方面，因为我们在前几章中已经谈到了其中一个潜在的第三方瓶颈。

对于我们在 Go 中的文件共享应用程序，我们将利用 NoSQL 来存储有关文件的元数据以及修改/交互这些文件的用户。

在选择 NoSQL 数据存储时，我们有很多选择，几乎所有主要的数据存储都在 Go 中有库或接口。虽然我们在这里选择了 Couchbase，但我们也会简要讨论一些其他主要的竞争对手以及每个的优点。

以下各节中的代码片段也应该让你对如何在不太焦虑的情况下将 Couchbase 替换为其他任何一个有一些想法。虽然我们不会深入研究其中任何一个，但为了确保易于交换，用于维护文件和修改信息的代码将尽可能通用。

## MongoDB

MongoDB 是最受欢迎的 NoSQL 平台之一。它是在 2009 年编写的，也是最成熟的平台之一，但也带来了一些权衡，这使得它在近年来有些失宠。

即便如此，Mongo 以可靠的方式完成了它的任务，并且速度非常快。使用索引，就像大多数数据库和数据存储一样，极大地提高了读取的查询速度。

Mongo 还允许对读取、写入和一致性的保证进行非常精细的控制。你可以将其视为对支持语法脏读的任何语言和/或引擎的非常模糊的类比。

最重要的是，Mongo 在 Go 中很容易支持并发，并且隐式地设计用于分布式系统。

### 注意

Mongo 的最大 Go 接口是`mgo`，可以在以下网址找到：[`godoc.org/labix.org/v2/mgo`](http://godoc.org/labix.org/v2/mgo)。

如果你想在 Go 中尝试 Mongo，将数据存储记录注入自定义结构是一个相对简单的过程。以下是一个快速而简单的例子：

```go
import
(
    "labix.org/v2/mgo"
    "labix.org/v2/mgo/bson"
)

type User struct {
  name string
}

func main() {
  servers, err := mgo.Dial("localhost")
  defer servers.Close()
  data := servers.DB("test").C("users")
  result := User{}
  err = c.Find(bson.M{"name": "John"}).One(&result)
}
```

与其他 NoSQL 解决方案相比，Mongo 的一个缺点是它默认没有任何 GUI。这意味着我们要么需要绑定另一个应用程序或 Web 服务，要么坚持使用命令行来管理其数据存储。对于许多应用程序来说，这并不是什么大问题，但我们希望尽可能地将这个项目分隔和局部化，以限制故障点。

Mongo 在容错性和数据丢失方面也有点名声不佳，但这同样适用于许多 NoSQL 解决方案。此外，这在很多方面是一个快速数据存储的特性——因此，灾难恢复往往是以速度和性能为代价的。

可以说这是对 Mongo 及其同行的一种普遍夸大的批评。Mongo 会出现问题吗？当然会。管理的基于 Oracle 的系统也会出现问题吗？当然会。在这个领域减轻大规模故障更多地是系统管理员的责任，而不是软件本身，后者只能提供设计这样的应急计划所需的工具。

尽管如此，我们希望有一个快速和高可用的管理界面，因此 Mongo 不符合我们的要求，但如果这些要求不那么受重视，它可以很容易地插入到这个解决方案中。

## Redis

Redis 是另一个键/值数据存储，最近成为了总使用量和受欢迎程度方面的第一名。在理想的 Redis 世界中，整个数据集都保存在内存中。鉴于许多数据集的大小，这并不总是可能的；然而，结合 Redis 的能力来摒弃持久性，当在并发应用程序中使用时，这可能会产生一些非常高性能的结果。

Redis 的另一个有用的特性是它可以固有地保存不同的数据结构。虽然你可以通过在 Mongo（和其他数据存储）中取消编组 JSON 对象/数组来对这些数据进行抽象，但 Redis 可以处理集合、字符串、数组和哈希。

在 Go 中，有两个主要被接受的 Redis 库：

+   **Radix**：这是一个极简主义的客户端，简洁、快速而简单。要安装 Radix，请运行以下命令：

```go
go get github.com/fzzy/radix/redis

```

+   **Redigo**：这更加强大，稍微复杂一些，但提供了许多更复杂的功能，我们可能在这个项目中不需要。要安装 Redigo，请运行以下命令：

```go
go get github.com/garyburd/redigo/redis

```

现在我们将看一个快速的例子，使用 Redigo 从 Redis 的`Users`数据存储中获取用户的名称：

```go
package main

import
(
    "fmt"
    "github.com/garyburd/redigo/redis"
)

func main() {

  connection,_ := dial()
  defer connection.Close()

  data, err := redis.Values(connection.Do("SORT", "Users", "BY", "User:*->name", 
    "GET", "User:*->name"))

  if (err) {
    fmt.Println("Error getting values", err)
  }

  for i:= range data {
    var Uname string
    data,err := redis.Scan(data, &Uname)
    if (err) {
      fmt.Println("Error getting value",err)
    }else {
      fmt.Println("Name Uname")
    }
  }
}
```

在审查这一点时，您可能会注意到一些非程序访问语法，例如以下内容：

```go
  data, err := redis.Values(connection.Do("SORT", "Users", "BY", "User:*->name", 
    "GET", "User:*->name"))
```

这确实是为什么 Go 中的 Redis 不会成为我们这个项目的选择之一的原因之一——这两个库都提供了对某些功能的几乎 API 级别的访问，还提供了一些更详细的内置功能，用于直接交互。`Do`命令直接将查询传递给 Redis，如果需要使用库，这是可以的，但在整体上是一个不太优雅的解决方案。

这两个库都非常好地与 Go 的并发特性配合，您在通过它们之一进行非阻塞网络调用到 Redis 时不会遇到任何问题。

值得注意的是，Redis 仅支持 Windows 的实验性构建，因此这主要用于*nix 平台。现有的端口来自 Microsoft，可以在[`github.com/MSOpenTech/redis`](https://github.com/MSOpenTech/redis)找到。

## Tiedot

如果您已经大量使用 NoSQL，那么前面提到的引擎对您来说可能都很熟悉。Redis、Couch、Mongo 等在这个相对年轻的技术中都是虚拟的支柱。

另一方面，Tiedot 可能不太熟悉。我们在这里包括它，只是因为文档存储本身是直接用 Go 编写的。文档操作主要通过 Web 界面处理，它是一个像其他几种 NoSQL 解决方案一样的 JSON 文档存储。

由于文档访问和处理是通过 HTTP 进行的，所以工作流程有点违反直觉，如下所示：

![Tiedot](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/ms-cncr-go/img/00048.jpeg)

由于这引入了潜在的延迟或故障点，这使得它不是我们这里的理想解决方案。请记住，这也是之前提到的一些其他解决方案的特点，但由于 Tiedot 是用 Go 编写的，因此连接到它并使用包读取/修改数据将会更容易。在撰写本书时，这是不存在的。

与 CouchDB 等基于 HTTP 或 REST 的替代方案不同，Tiedot 依赖于 URL 端点来指示操作，而不是 HTTP 方法。

您可以在以下代码中看到我们如何通过标准库处理类似的事情：

```go
package main

import
(
  "fmt"
  "json"
  "http"
)

type Collection struct {
  Name string
}
```

简单地说，这是您希望通过数据选择、查询等方式引入到 Go 应用程序中的任何记录的数据结构。您在我们之前使用 SQL 服务器本身时看到了这一点，这并没有什么不同：

```go
func main() {

  Col := Collection{
    Name: ''
  }

  data, err := http.Get("http://localhost:8080/all")
  if (err != nil) {
    fmt.Println("Error accessing tiedot")
  }
  collections,_ = json.Unmarshal(data,&Col)
}
```

尽管不像许多同行那样健壮、强大或可扩展，Tiedot 肯定值得玩耍，或者更好的是，值得贡献。

### 注意

您可以在[`github.com/HouzuoGuo/tiedot`](https://github.com/HouzuoGuo/tiedot)找到 Tiedot。

## CouchDB

Apache 孵化器的 CouchDB 是 NoSQL 大数据中的另一个重要角色。作为一个 JSON 文档存储，CouchDB 在数据存储方法方面提供了很大的灵活性。

CouchDB 支持 ACID 语义，并且可以同时执行，这在某种程度上提供了很大的性能优势。在我们的应用程序中，对 ACID 一致性的依赖性是相对灵活的。从设计上讲，它将是容错和可恢复的，但对于许多人来说，即使是可恢复的数据丢失的可能性仍然被认为是灾难性的。

与 CouchDB 的接口是通过 HTTP 进行的，这意味着不需要直接实现或 Go SQL 数据库钩子来使用它。有趣的是，CouchDB 使用 HTTP 头语法来操作数据，如下所示：

+   **GET**：这代表读取操作

+   **PUT**：这代表创建操作

+   **DELETE**：这代表删除和更新操作

当然，这些最初是在 HTTP 1.1 中的标头方法，但是 Web 的很多部分都集中在 GET/POST 上，这些方法往往会在混乱中失去。

Couch 还配备了一个方便的 Web 界面进行管理。当 CouchDB 运行时，您可以在`http://localhost:5984/_utils/`访问它，如下面的截图所示：

![CouchDB](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/ms-cncr-go/img/00049.jpeg)

也就是说，有一些包装器为一些更复杂和高级的功能提供了一定程度的抽象。

## Cassandra

Cassandra，作为 Apache 基金会的另一个项目，技术上并不是一个 NoSQL 解决方案，而是一个集群（或可集群化）的数据库管理平台。

与许多 NoSQL 应用程序一样，Cassandra 的传统查询方法存在一些限制，例如，通常不支持子查询和连接。

我们在这里提到它主要是因为它专注于分布式计算以及以编程方式调整数据一致性或性能的能力。Couchbase 同样也表达了很多这些内容，但 Cassandra 更加专注于分布式数据存储。

然而，Cassandra 支持一部分 SQL，这将使它对于那些涉足过 MySQL、PostgreSQL 或类似数据库的开发人员来说更加熟悉。Cassandra 对高并发集成的内置处理在很多方面使其对 Go 来说是理想的，尽管对于这个项目来说有些过度。

与 Cassandra 进行接口的最值得注意的库是 gocql，它专注于速度和与 Cassandra 连接的清晰性。如果您选择使用 Cassandra 而不是 Couchbase（或其他 NoSQL），您会发现许多方法可以简单地替换。

以下是连接到集群并编写简单查询的示例：

```go
package main

import
(
    "github.com/gocql/gocql"
    "log"
)

func main() {

  cass := gocql.NewCluster("127.0.0.1")
  cass.Keyspace = "filemaster"
  cass.Consistency = gocql.LocalQuorum

  session, _ := cass.CreateSession()
  defer session.Close()

  var fileTime int;

  if err := session.Query(`SELECT file_modified_time FROM filemaster 
  WHERE filename = ? LIMIT 1`, "test.txt").Consistency(gocql.One).Scan(&fileTime); err != nil {
    log.Fatal(err)
  }
  fmt.Println("Last modified",fileTime)
}
```

如果您计划快速扩展此应用程序、广泛分发它，或者对 SQL 比数据存储/JSON 访问更熟悉，那么 Cassandra 可能是一个理想的解决方案。

对于我们的目的来说，SQL 不是必需的，我们更看重速度，包括耐久性在内。

## Couchbase

Couchbase 是该领域的一个相对新手，但它是由 CouchDB 和 memcached 的开发人员构建的。它是用 Erlang 编写的，与我们期望从我们的许多 Go 应用程序中获得的并发性、速度和非阻塞行为有许多相同的关注点。

Couchbase 还支持我们在前几章中讨论的许多其他功能，包括易于分发的安装、可调的 ACID 兼容性和低资源消耗。

Couchbase 的一个缺点是它在一些资源较低的机器或虚拟机上运行效果不佳（或根本无法运行）。确实，64 位安装至少需要 4GB 内存和四个核心，所以不要指望在小型、中小型实例或旧硬件上启动它。

虽然这里（或其他地方）提出的大多数 NoSQL 解决方案通常比它们的 SQL 对应方案具有性能优势，但 Couchbase 在 NoSQL 领域中表现得非常出色。

Couchbase，如 CouchDB 一样，配备了一个基于 Web 的图形界面，简化了设置和维护的过程。在设置中，您可以使用的高级功能包括基本存储引擎（Couchbase 或 memcached）、自动备份过程（副本）和读写并发级别。

除了配置和管理工具，它还在 Web 仪表板中提供了一些实时监控，如下面的截图所示：

![Couchbase](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/ms-cncr-go/img/00050.jpeg)

虽然不能完全替代完整的服务器管理（当服务器宕机时，你没有洞察力会发生什么），但知道你的资源究竟去了哪里，而不需要命令行方法或外部工具，这非常有帮助。

Couchbase 中的术语略有不同，就像在许多这些解决方案中一样。对稍微将 NoSQL 与古板的旧 SQL 解决方案分开的渴望会不时地显现出来。

在 Couchbase 中，数据库是一个数据存储桶，记录是文档。然而，视图，作为一个旧的事务性 SQL 标准，为表格带来了一些熟悉的东西。这里的重点是，视图允许您使用简单的 JavaScript 创建更复杂的查询，在某些情况下，可以复制否则难以实现的功能，如连接、联合和分页。

在 Couchbase 中创建的每个视图都成为一个 HTTP 访问点。因此，您命名为`select_all_files`的视图将可以通过 URL 访问，例如`http://localhost:8092/file_manager/_design/select_all_files/_view/Select%20All%20Files?connection_timeout=60000&limit=10&skip=0`。

最值得注意的 Couchbase 接口库是 Go Couchbase，如果没有其他选择，它可能会让您免受在代码中进行 HTTP 调用以访问 CouchDB 的冗余之苦。

### 注意

Go Couchbase 可以在[`github.com/couchbaselabs/go-couchbase`](https://github.com/couchbaselabs/go-couchbase)找到。

Go Couchbase 通过 Go 抽象简单而强大地与 Couchbase 进行接口交互。以下代码以精简的方式连接并获取有关各种数据池的信息，感觉自然而简单：

```go
package main

import
(
  "fmt"
  "github.com/couchbaselabs/go-couchbase"
)

func main() {

    conn, err := couchbase.Connect("http://localhost:8091")
    if err != nil {
      fmt.Println("Error:",err)
    }
    for _, pn := range conn.Info.Pools {
        fmt.Printf("Found pool:  %s -> %s\n", pn.Name, pn.URI)
    }
}
```

## 设置我们的数据存储

安装 Couchbase 后，默认情况下可以通过 localhost 和端口 8091 访问其管理面板。

您将有机会设置管理员、其他 IP 连接（如果加入集群）和一般数据存储设计。

之后，您需要设置一个存储桶，这是我们用来存储有关单个文件的所有信息的地方。以下是存储桶设置的界面：

![设置我们的数据存储](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/ms-cncr-go/img/00051.jpeg)

在我们的示例中，我们正在使用单台机器，因此不支持副本（在数据库术语中也称为复制）。我们将其命名为`file_manager`，但这显然可以称为任何有意义的东西。

我们还将保持数据使用量相当低——当我们存储文件操作并记录较旧的操作时，没有必要使用超过 256MB 的内存。换句话说，我们并不一定关心将`test.txt`的修改历史永远保存在内存中。

我们还将使用 Couchbase 作为存储引擎等效，尽管您可以在 memcache(d)之间来回切换而几乎没有注意到的变化。

让我们首先创建一个种子文档：稍后我们将删除的文档，但它将代表我们的数据存储架构。我们可以使用任意的 JSON 结构化对象创建此文档，如下面的屏幕截图所示：

![设置我们的数据存储](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/ms-cncr-go/img/00052.jpeg)

由于存储在此数据存储中的所有内容都应为有效的 JSON，因此我们可以混合和匹配字符串、整数、布尔值、数组和对象。这为我们提供了一些在使用数据时的灵活性。以下是一个示例文档：

```go
{
  "file_name": "test.txt",
  "hash": "",
  "created": 1,
  "created_user": 0,
  "last_modified": "",
  "last_modified_user": "",
  "revisions": [],
  "version": 1
}
```

# 监视文件系统更改

在选择 NoSQL 选项时，我们可以选择各种各样的解决方案。但是当涉及到监视文件系统更改的应用程序时，情况就不一样了。虽然 Linux 版本在 inotify 中有一个相当不错的内置解决方案，但这限制了应用程序的可移植性。

因此，Chris Howey 的 fsnotify 中存在一个处理这个问题的跨平台库非常有帮助。

Fsnotify 在 Linux、OSX 和 Windows 上运行，并允许我们检测任何给定目录中的文件何时被创建、删除、修改或重命名，这对我们的目的来说已经足够了。

实现 fsnotify 也非常容易。最重要的是，它都是非阻塞的，因此，如果我们将监听器放在 goroutine 后面，我们可以将其作为主服务器应用程序代码的一部分运行。

以下代码显示了一个简单的目录监听器：

```go
package main

import (
    "github.com/howeyc/fsnotify""fmt"
  "log""
)

func main() {

    scriptDone := make(chan bool)
    dirSpy, err := fsnotify.NewWatcher()
    if err != nil {
        log.Fatal(err)
    }

    go func() {
        for {
            select {
            case fileChange := <-dirSpy.Event:
                log.Println("Something happened to a file:", 
                  fileChange)
            case err := <-dirSpy.Error:
                log.Println("Error with fsnotify:", err)
            }
        }
    }()

    err = dirSpy.Watch("/mnt/sharedir")
    if err != nil {
      fmt.Println(err)
    }

    <-scriptDone

    dirSpy.Close()
}
```

# 管理日志文件

与许多开发人员工具箱中的基本功能一样，Go 提供了一个相当完整的内置日志记录解决方案。它处理许多基本功能，例如创建时间戳标记的日志项并保存到磁盘或控制台。

基本包遗漏的一件事是内置格式化和日志轮换，这是我们的文件管理器应用程序的关键要求。

请记住，我们的应用程序的关键要求包括能够在并发环境中无缝工作，并且在需要时能够准备好扩展到分布式网络。这就是 fine **log4go**应用程序派上用场的地方。Log4go 允许将日志记录到文件、控制台和内存，并且内在地处理日志轮换。

### 注意

Log4go 可以在[`code.google.com/p/log4go/`](https://code.google.com/p/log4go/)找到。

要安装 Log4go，请运行以下命令：

```go
go get code.google.com/p/log4go

```

创建一个处理警告、通知、调试信息和关键错误的日志文件很简单，并且将日志轮换附加到其中同样简单，如下面的代码所示：

```go
package main

import
(
  logger "code.google.com/p/log4go"
)
func main() {
  logMech := make(logger.Logger);
  logMech.AddFilter("stdout", logger.DEBUG, 
    logger.NewConsoleLogWriter())

  fileLog := logger.NewFileLogWriter("log_manager.log", false)
  fileLog.SetFormat("[%D %T] [%L] (%S) %M")
  fileLog.SetRotate(true)
  fileLog.SetRotateSize(256)
  fileLog.SetRotateLines(20)
  fileLog.SetRotateDaily(true)
  logMech.AddFilter("file", logger.FINE, fileLog)

  logMech.Trace("Received message: %s)", "All is well")
  logMech.Info("Message received: ", "debug!")
  logMech.Error("Oh no!","Something Broke")
}
```

# 处理配置文件

在处理配置文件和解析它们时，您有很多选择，从简单到复杂。

当然，我们可以简单地将所需内容存储为 JSON，但是该格式对于人类来说有点棘手——它需要转义字符等，这使其容易出现错误。

相反，我们将使用 gcfg 中的标准`ini config`文件库来简化事务，该库处理`gitconfig`文件和传统的旧式`.ini`格式，如下面的代码片段所示：

```go
[revisions]
count = 2
revisionsuffix = .rev
lockfiles = false

[logs]
rotatelength = 86400

[alarms]
emails = sysadmin@example.com,ceo@example.com
```

### 注意

您可以在[`code.google.com/p/gcfg/`](https://code.google.com/p/gcfg/)找到 gcfg。

基本上，该库获取配置文件的值并将其推送到 Go 中的结构体中。我们将如何做到这一点的示例如下：

```go
package main

import
(
  "fmt"
  "code.google.com/p/gcfg"
)

type Configuration struct {
  Revisions struct {
    Count int
    Revisionsuffix string
    Lockfiles bool
  }
  Logs struct {
    Rotatelength int
  }
  Alarms struct {
    Emails string
  }
}

func main() {
  configFile := Configuration{}
  err := gcfg.ReadFileInto(&configFile, "example.ini")
  if err != nil {
    fmt.Println("Error",err)
  }
  fmt.Println("Rotation duration:",configFile.Logs.Rotatelength)
}
```

# 检测文件更改

现在我们需要专注于我们的文件监听器。您可能还记得，这是应用程序的一部分，它将接受来自我们的 Web 服务器和备份应用程序的客户端连接，并通知文件的任何更改。

这部分的基本流程如下：

1.  在 goroutine 中监听文件的更改。

1.  在 goroutine 中接受连接并添加到池中。

1.  如果检测到任何更改，则向整个池通知它们。

所有三个操作同时发生，第一个和第三个操作可以在池中没有任何连接的情况下发生，尽管我们假设总会有一个连接始终与我们的 Web 服务器和备份应用程序保持连接。

文件监听器将扮演的另一个关键角色是在首次加载时分析目录并将其与我们在 Couchbase 中的数据存储进行协调。由于 Go Couchbase 库处理获取、更新和添加操作，我们不需要任何自定义视图。在下面的代码中，我们将检查文件监听器进程，并展示如何监听文件夹的更改：

```go
package main

import
(
  "fmt"
  "github.com/howeyc/fsnotify"
  "net"
  "time"
  "io"  
  "io/ioutil"
  "github.com/couchbaselabs/go-couchbase"
  "crypto/md5"
  "encoding/hex"
  "encoding/json"  
  "strings"

)

var listenFolder = "mnt/sharedir"

type Client struct {
  ID int
  Connection *net.Conn  
}
```

在这里，我们声明了我们的共享文件夹以及一个连接的`Client`结构。在这个应用程序中，`Client`可以是 Web 监听器或备份监听器，并且我们将使用以下 JSON 编码结构单向传递消息：

```go
type File struct {
  Hash string "json:hash"
  Name string "json:file_name"
  Created int64 "json:created"
  CreatedUser  int "json:created_user"
  LastModified int64 "json:last_modified"
  LastModifiedUser int "json:last_modified_user"
  Revisions int "json:revisions"
  Version int "json:version"
}
```

如果这看起来很熟悉，那可能是因为这也是我们最初设置的示例文档格式。

### 注意

如果您对之前表达的语法糖不熟悉，这些被称为结构标签。标签只是可以应用于结构字段的附加元数据，以便通过`reflect`包进行键/值查找。在这种情况下，它们用于将我们的结构字段映射到 JSON 字段。

让我们首先看一下我们的整体`Message struct`：

```go
type Message struct {
  Hash string "json:hash"
  Action string "json:action"
  Location string "json:location"  
  Name string "json:name"
  Version int "json:version"
}
```

我们将我们的文件分成一个消息，用于通知我们的其他两个进程发生了更改：

```go
func generateHash(name string) string {

  hash := md5.New()
  io.WriteString(hash,name)
  hashString := hex.EncodeToString(hash.Sum(nil))

  return hashString
}
```

这是一种相对不可靠的方法，用于生成文件的哈希引用，如果文件名更改，它将失败。但是，它允许我们跟踪创建、删除或修改的文件。

## 向客户端发送更改

这是发送到所有现有连接的广播消息。我们传递我们的 JSON 编码的`Message`结构，其中包含当前版本、当前位置和用于参考的哈希。然后我们的其他服务器将相应地做出反应：

```go
func alertServers(hash string, name string, action string, location string, version int) {

  msg := Message{Hash:hash,Action:action,Location:location,Name:name,Version:version}
  msgJSON,_ := json.Marshal(msg)

  fmt.Println(string(msgJSON))

  for i := range Clients {
    fmt.Println("Sending to clients")
    fmt.Fprintln(*Clients[i].Connection,string(msgJSON))
  }
}
```

我们的备份服务器将在备份文件夹中创建带有`.[VERSION]`扩展名的文件副本。

我们的 Web 服务器将通过 Web 界面简单地通知用户文件已更改：

```go
func startServer(listener net.Listener) {
  for {  
    conn,err := listener.Accept()
    if err != nil {

    }
    currentClient := Client{ ID: 1, Connection: &conn}
    Clients = append(Clients,currentClient)
      for i:= range Clients {
        fmt.Println("Client",Clients[i].ID)
      }    
  }  

}
```

这段代码看起来熟悉吗？我们几乎完全复制了我们的聊天服务器`Client`处理程序并将其几乎完整地带到这里：

```go
func removeFile(name string, bucket *couchbase.Bucket) {
  bucket.Delete(generateHash(name))
}
```

`removeFile`函数只做一件事，那就是从我们的 Couchbase 数据存储中删除文件。由于它是反应性的，我们不需要在文件服务器端做任何事情，因为文件已经被删除。此外，没有必要删除任何备份，因为这使我们能够恢复。接下来，让我们看一下我们的更新现有文件的函数：

```go
func updateExistingFile(name string, bucket *couchbase.Bucket) int {
  fmt.Println(name,"updated")
  hashString := generateHash(name)

  thisFile := Files[hashString]
  thisFile.Hash = hashString
  thisFile.Name = name
  thisFile.Version = thisFile.Version + 1
  thisFile.LastModified = time.Now().Unix()
  Files[hashString] = thisFile
  bucket.Set(hashString,0,Files[hashString])
  return thisFile.Version
}
```

这个函数本质上是用新值覆盖 Couchbase 中的任何值，复制现有的`File`结构并更改`LastModified`日期：

```go
func evalFile(event *fsnotify.FileEvent, bucket *couchbase.Bucket) {
  fmt.Println(event.Name,"changed")
  create := event.IsCreate()
  fileComponents := strings.Split(event.Name,"\\")
  fileComponentSize := len(fileComponents)
  trueFileName := fileComponents[fileComponentSize-1]
  hashString := generateHash(trueFileName)

  if create == true {
    updateFile(trueFileName,bucket)
    alertServers(hashString,event.Name,"CREATE",event.Name,0)
  }
  delete := event.IsDelete()
  if delete == true {
    removeFile(trueFileName,bucket)
    alertServers(hashString,event.Name,"DELETE",event.Name,0)    
  }
  modify := event.IsModify()
  if modify == true {
    newVersion := updateExistingFile(trueFileName,bucket)
    fmt.Println(newVersion)
    alertServers(hashString,trueFileName,"MODIFY",event.Name,newVersion)
  }
  rename := event.IsRename()
  if rename == true {

  }
}
```

在这里，我们对我们监视目录中文件系统的任何更改做出反应。我们不会对重命名做出反应，但您也可以处理这些情况。以下是我们处理一般`updateFile`函数的方法：

```go
func updateFile(name string, bucket *couchbase.Bucket) {
  thisFile := File{}
  hashString := generateHash(name)

  thisFile.Hash = hashString
  thisFile.Name = name
  thisFile.Created = time.Now().Unix()
  thisFile.CreatedUser = 0
  thisFile.LastModified = time.Now().Unix()
  thisFile.LastModifiedUser = 0
  thisFile.Revisions = 0
  thisFile.Version = 1

  Files[hashString] = thisFile

  checkFile := File{}
  err := bucket.Get(hashString,&checkFile)
  if err != nil {
    fmt.Println("New File Added",name)
    bucket.Set(hashString,0,thisFile)
  }
}
```

## 检查与 Couchbase 的记录

在检查现有记录与 Couchbase 相对时，我们检查 Couchbase 存储桶中是否存在哈希。如果不存在，我们就创建它。如果存在，我们就什么都不做。为了更可靠地处理关闭，我们还应该将现有记录纳入我们的应用程序。执行此操作的代码如下：

```go
var Clients []Client
var Files map[string] File

func main() {
  Files = make(map[string]File)
  endScript := make(chan bool)

  couchbaseClient, err := couchbase.Connect("http://localhost:8091/")
    if err != nil {
      fmt.Println("Error connecting to Couchbase", err)
    }
  pool, err := couchbaseClient.GetPool("default")
    if err != nil {
      fmt.Println("Error getting pool",err)
    }
  bucket, err := pool.GetBucket("file_manager")
    if err != nil {
      fmt.Println("Error getting bucket",err)
    }  

  files, _ := ioutil.ReadDir(listenFolder)
  for _, file := range files {
    updateFile(file.Name(),bucket)
  }

    dirSpy, err := fsnotify.NewWatcher()
    defer dirSpy.Close()

  listener, err := net.Listen("tcp", ":9000")
  if err != nil {
    fmt.Println ("Could not start server!",err)
  }

  go func() {
        for {
            select {
            case ev := <-dirSpy.Event:
                evalFile(ev,bucket)
            case err := <-dirSpy.Error:
                fmt.Println("error:", err)
            }
        }
    }()
    err = dirSpy.Watch(listenFolder)  
  startServer(listener)

  <-endScript
}
```

最后，`main()`处理设置我们的连接和 goroutines，包括文件监视器、TCP 服务器和连接到 Couchbase。

现在，让我们看一下整个过程中的另一个步骤，我们将自动创建我们修改后的文件的备份。

# 备份我们的文件

由于我们可以说是在网络上发送我们的命令，因此我们的备份过程需要在该网络上侦听并响应任何更改。鉴于修改将通过本地主机发送，我们在网络和文件方面应该有最小的延迟。

我们还将返回一些关于文件发生了什么的信息，尽管在这一点上我们对这些信息并没有做太多处理。这段代码如下：

```go
package main

import
(
  "fmt"
  "net"
  "io"
  "os"
  "strconv"
  "encoding/json"
)

var backupFolder = "mnt/backup/"
```

请注意，我们有一个专门用于备份的文件夹，在这种情况下是在 Windows 机器上。如果我们不小心使用相同的目录，我们就有无限复制和备份文件的风险。在下面的代码片段中，我们将看一下`Message`结构本身和`backup`函数，这是应用程序的这一部分的核心：

```go
type Message struct {
  Hash string "json:hash"
  Action string "json:action"
  Location string "json:location"
  Name string "json:name"  
  Version int "json:version"
}

func backup (location string, name string, version int) {

  newFileName := backupFolder + name + "." + 
    strconv.FormatInt(int64(version),10)
  fmt.Println(newFileName)
  org,_ := os.Open(location)
  defer org.Close()
  cpy,_ := os.Create(newFileName)
  defer cpy.Close()
  io.Copy(cpy,org)
}
```

这是我们的基本文件操作。Go 语言没有一步复制函数；相反，您需要创建一个文件，然后使用`io.Copy`将另一个文件的内容复制到其中：

```go
func listen(conn net.Conn) {
  for {

      messBuff := make([]byte,1024)
    n, err := conn.Read(messBuff)
    if err != nil {

    }

    resultMessage := Message{}
    json.Unmarshal(messBuff[:n],&resultMessage)

    if resultMessage.Action == "MODIFY" {
      fmt.Println("Back up file",resultMessage.Location)
      newVersion := resultMessage.Version + 1
      backup(resultMessage.Location,resultMessage.Name,newVersion)
    }

  }

}
```

这段代码几乎与我们的聊天客户端的`listen()`函数一字不差，只是我们获取了流式 JSON 数据的内容，对其进行解组，并将其转换为`Message{}`结构，然后是`File{}`结构。最后，让我们看一下`main`函数和 TCP 初始化：

```go
func main() {
  endBackup := make(chan bool)
  conn, err := net.Dial("tcp","127.0.0.1:9000")
  if err != nil {
    fmt.Println("Could not connect to File Listener!")
  }
  go listen(conn)

  <- endBackup
}
```

# 设计我们的 Web 界面

为了与文件系统交互，我们需要一个接口，显示所有当前文件的版本、最后修改时间和更改的警报，并允许拖放创建/替换文件。

获取文件列表将很简单，因为我们将直接从我们的`file_manager` Couchbase 存储桶中获取它们。更改将通过我们的文件管理器进程通过 TCP 发送，这将触发 API 调用，为我们的 Web 用户显示文件的更改。

我们在这里使用的一些方法是备份过程中使用的方法的副本，并且肯定可以从一些整合中受益；但以下是 Web 服务器的代码，它允许上传并显示更改的通知：

```go
package main

import
(
  "net"
  "net/http"
  "html/template"
  "log"
  "io"
  "os"
  "io/ioutil"
  "github.com/couchbaselabs/go-couchbase"
  "time"  
  "fmt"
  "crypto/md5"
  "encoding/hex"
  "encoding/json"
)

type File struct {
  Hash string "json:hash"
  Name string "json:file_name"
  Created int64 "json:created"
  CreatedUser  int "json:created_user"
  LastModified int64 "json:last_modified"
  LastModifiedUser int "json:last_modified_user"
  Revisions int "json:revisions"
  Version int "json:version"
}
```

例如，这是我们在文件监听器和备份过程中使用的相同的`File`结构：

```go
type Page struct {
  Title string
  Files map[string] File
}
```

我们的`Page`结构表示通用的 Web 数据，这些数据被转换为我们网页模板的相应变量：

```go
type ItemWrapper struct {

  Items []File
  CurrentTime int64
  PreviousTime int64

}

type Message struct {
  Hash string "json:hash"
  Action string "json:action"
  Location string "json:location"
  Name string "json:name"  
  Version int "json:version"
}
```

我们的`md5`哈希方法在这个应用程序中也是一样的。 值得注意的是，我们从文件监听器接收到信号时，会派生一个`lastChecked`变量，该变量是 Unix 风格的时间戳。 我们使用这个变量来与客户端文件更改进行比较，以便知道是否在 Web 上提醒用户。 现在让我们来看看 Web 界面的`updateFile`函数：

```go
func updateFile(name string, bucket *couchbase.Bucket) {
  thisFile := File{}
  hashString := generateHash(name)

  thisFile.Hash = hashString
  thisFile.Name = name
  thisFile.Created = time.Now().Unix()
  thisFile.CreatedUser = 0
  thisFile.LastModified = time.Now().Unix()
  thisFile.LastModifiedUser = 0
  thisFile.Revisions = 0
  thisFile.Version = 1

  Files[hashString] = thisFile

  checkFile := File{}
  err := bucket.Get(hashString,&checkFile)
  if err != nil {
    fmt.Println("New File Added",name)
    bucket.Set(hashString,0,thisFile)
  }else {
    Files[hashString] = checkFile
  }
}
```

这与我们备份过程中的函数相同，只是不是创建一个重复的文件，而是简单地覆盖我们的内部`File`结构，以便在下次调用`/api`时表示其更新的`LastModified`值。 和我们上一个例子一样，让我们来看看`listen()`函数：

```go
func listen(conn net.Conn) {
  for {

      messBuff := make([]byte,1024)
    n, err := conn.Read(messBuff)
    if err != nil {

    }
    message := string(messBuff[:n])
    message = message[0:]

    resultMessage := Message{}
    json.Unmarshal(messBuff[:n],&resultMessage)

    updateHash := resultMessage.Hash
    tmp := Files[updateHash]
    tmp.LastModified = time.Now().Unix()
    Files[updateHash] = tmp
  }

}
```

在这里，我们读取消息，解组并将其设置为其哈希映射的键。 如果文件不存在，这将创建一个文件，如果存在，则更新我们当前的文件。 接下来，我们将看看`main()`函数，它设置了我们的应用程序和 Web 服务器：

```go
func main() {
  lastChecked := time.Now().Unix()
  Files = make(map[string]File)
  fileChange = make(chan File)
  couchbaseClient, err := couchbase.Connect("http://localhost:8091/")
    if err != nil {
      fmt.Println("Error connecting to Couchbase", err)
    }
  pool, err := couchbaseClient.GetPool("default")
    if err != nil {
      fmt.Println("Error getting pool",err)
    }
  bucket, err := pool.GetBucket("file_manager")
    if err != nil {
      fmt.Println("Error getting bucket",err)
    }    

  files, _ := ioutil.ReadDir(listenFolder)
  for _, file := range files {
    updateFile(file.Name(),bucket)
  }

  conn, err := net.Dial("tcp","127.0.0.1:9000")
  if err != nil {
    fmt.Println("Could not connect to File Listener!")
  }
  go listen(conn)

  http.HandleFunc("/api", func(w http.ResponseWriter, r 
    *http.Request) {
    apiOutput := ItemWrapper{}
    apiOutput.PreviousTime = lastChecked
    lastChecked = time.Now().Unix()
    apiOutput.CurrentTime = lastChecked

    for i:= range Files {
      apiOutput.Items = append(apiOutput.Items,Files[i])
    }
    output,_ := json.Marshal(apiOutput)
    fmt.Fprintln(w,string(output))

  })
  http.HandleFunc("/", func(w http.ResponseWriter, r 
    *http.Request) {
    output := Page{Files:Files,Title:"File Manager"}
    tmp, _ := template.ParseFiles("ch8_html.html")
    tmp.Execute(w, output)
  })
  http.HandleFunc("/upload", func(w http.ResponseWriter, r 
    *http.Request) {
    err := r.ParseMultipartForm(10000000)
    if err != nil {
      return
    }
    form := r.MultipartForm

    files := form.File["file"]
    for i, _ := range files {
      newFileName := listenFolder + files[i].Filename
      org,_:= files[i].Open()
      defer org.Close()
      cpy,_ := os.Create(newFileName)
      defer cpy.Close()
      io.Copy(cpy,org)
    }
  })  

  log.Fatal(http.ListenAndServe(":8080",nil))

}
```

在我们的 Web 服务器组件中，`main()`负责设置与文件监听器和 Couchbase 的连接，并创建一个 Web 服务器（带有相关路由）。

如果您通过将文件拖放到**拖放文件到此处上传**框中上传文件，几秒钟后，您将看到文件在 Web 界面中被标记为已更改，如下面的屏幕截图所示：

![设计我们的 Web 界面](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/ms-cncr-go/img/00053.jpeg)

我们没有包括 Web 界面客户端的代码； 但关键点是通过 API 检索。 我们使用了一个名为`Dropzone.js`的 JavaScript 库，它允许拖放上传，并使用 jQuery 进行 API 访问。

# 恢复文件的历史记录-命令行

我们想要添加到这个应用程序套件中的最后一个组件是一个命令行文件修订过程。 我们可以将这个过程保持相当简单，因为我们知道文件的位置，备份的位置以及如何用后者替换前者。 与以前一样，我们有一些全局配置变量和我们的`generateHash()`函数的复制：

```go
var liveFolder = "/mnt/sharedir "
var backupFolder = "/mnt/backup

func generateHash(name string) string {

  hash := md5.New()
  io.WriteString(hash,name)
  hashString := hex.EncodeToString(hash.Sum(nil))

  return hashString
}

func main() {
  revision := flag.Int("r",0,"Number of versions back")
  fileName := flag.String("f","","File Name")
  flag.Parse()

  if *fileName == "" {

    fmt.Println("Provide a file name to use!")
    os.Exit(0)
  }

  couchbaseClient, err := couchbase.Connect("http://localhost:8091/")
    if err != nil {
      fmt.Println("Error connecting to Couchbase", err)
    }
  pool, err := couchbaseClient.GetPool("default")
    if err != nil {
      fmt.Println("Error getting pool",err)
    }
  bucket, err := pool.GetBucket("file_manager")
    if err != nil {
      fmt.Println("Error getting bucket",err)
    }  

  hashString := generateHash(*fileName)
  checkFile := File{}    
  bucketerr := bucket.Get(hashString,&checkFile)
  if bucketerr != nil {

  }else {
    backupLocation := backupFolder + checkFile.Name + "." + strconv.FormatInt(int64(checkFile.Version-*revision),10)
    newLocation := liveFolder + checkFile.Name
    fmt.Println(backupLocation)
    org,_ := os.Open(backupLocation)
      defer org.Close()
    cpy,_ := os.Create(newLocation)
      defer cpy.Close()
    io.Copy(cpy,org)
    fmt.Println("Revision complete")
  }

}
```

这个应用程序最多接受两个参数：

+   `-f`：这表示文件名

+   `-r`：这表示要恢复的版本数

请注意，这本身会创建一个新版本，因此需要将-2 变为-3，然后为-6，以此类推，以便连续递归备份。

例如，如果您希望将`example.txt`还原为三个版本之前，您可以使用以下命令：

```go
fileversion -f example.txt -r -3

```

## 在守护程序和服务中使用 Go

关于运行这部分应用程序的一点说明——理想情况下，您希望将这些应用程序保持为活动的、可重启的服务，而不是独立的、手动执行的后台进程。 这样做将允许您保持应用程序的活动状态，并从外部或服务器进程管理其生命周期。

这种应用程序套件最适合在 Linux 框（或框）上，并使用像 daemontools 或 Ubuntu 内置的 Upstart 服务这样的守护程序管理器进行管理。 这样做的原因是，任何长期的停机时间都可能导致数据丢失和不一致。 即使在内存中存储文件数据细节（Couchbase 和 memcached）也会对数据丢失构成漏洞。

# 检查我们服务器的健康状况

有许多种方法可以检查一般服务器的健康状况，我们在这里处于一个良好的位置，而无需构建我们自己的系统，这在很大程度上要归功于 Couchbase 本身。 如果您访问 Couchbase Web 管理界面，在您的集群、服务器和存储桶视图下，单击任何一个都会显示一些实时统计信息，如下面的屏幕截图所示：

![检查我们服务器的健康状况](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/ms-cncr-go/img/00054.jpeg)

如果您希望将这些区域包含在应用程序中，以使您的日志记录和错误处理更全面，这些区域也可以通过 REST 访问。

# 总结

我们现在拥有一个从头到尾高度并发的应用程序套件，涉及多个第三方库，并通过记录和灾难恢复来减轻潜在的故障。

到这一点，你应该没有问题构建一个以 Go 语言为重点，专注于维护并发性、可靠性和性能的复杂软件包。我们的文件监控应用程序可以很容易地修改以执行更多操作，使用替代服务，或者扩展到一个强大的分布式环境。

在下一章中，我们将更仔细地测试我们的并发性和吞吐量，探讨 panic 和 recover 的价值，以及在 Go 语言中以安全并发的方式处理记录重要信息和错误。


# 第九章：Go 中的日志记录和测试并发

在这个阶段，你应该对 Go 中的并发感到相当舒适，并且应该能够轻松地实现基本的 goroutines 和并发机制。

我们还涉足了一些分布式并发模式，这些模式不仅通过应用程序本身管理，还通过第三方数据存储管理网络应用程序的并发操作。

在本书的前面，我们研究了一些初步和基本的测试和日志记录。我们研究了 Go 内部测试工具的简单实现，使用 race 工具进行了一些竞争条件测试，并进行了一些基本的负载和性能测试。

然而，这里还有更多需要考虑的地方，特别是与潜在的并发代码黑洞有关——我们已经看到了在 goroutines 中运行的非阻塞代码之间出现了意外行为。

在本章中，我们将进一步研究负载和性能测试，在 Go 中进行单元测试，并尝试更高级的测试和调试。我们还将探讨日志记录和报告的最佳实践，并更仔细地研究 panic 和 recover。

最后，我们将看到所有这些东西不仅可以应用于我们独立的并发代码，还可以应用于分布式系统。

在这个过程中，我们将介绍一些不同风格的单元测试框架。

# 处理错误和日志记录

虽然我们没有明确提到，但 Go 中错误处理的成语性质使得调试自然更容易。

在 Go 代码中，任何大规模函数的一个良好实践是将错误作为返回值返回——对于许多较小的方法和函数来说，这可能是繁琐和不必要的。但是，每当我们构建涉及许多移动部件的东西时，这都是需要考虑的问题。

例如，考虑一个简单的`Add()`函数：

```go
func Add(x int, y int) int {
  return x + y
}
```

如果我们希望遵循“始终返回错误值”的一般规则，我们可能会诱使将这个函数转换为以下代码：

```go
package main
import
(
  "fmt"
  "errors"
  "reflect"
)

func Add(x int, y int) (int, error) {
  var err error

  xType := reflect.TypeOf(x).Kind()
  yType := reflect.TypeOf(y).Kind()
  if xType != reflect.Int || yType != reflect.Int {
    fmt.Println(xType)
    err = errors.New("Incorrect type for integer a or b!")
  }
  return x + y, err
}

func main() {

  sum,err := Add("foo",2)
  if err != nil {
    fmt.Println("Error",err)
  }
  fmt.Println(sum)
}
```

你可以看到我们（非常糟糕地）在重新发明轮子。Go 的内部编译器在我们看到它之前就已经杀死了它。因此，我们应该专注于编译器可能无法捕捉到的事情，这可能会导致我们的应用程序出现意外行为，特别是在涉及通道和监听器时。

要点是让 Go 处理编译器会处理的错误，除非你希望自己处理异常，而不引起编译器特定的困扰。在真正的多态性缺失的情况下，这通常很麻烦，并且需要调用接口，如下面的代码所示：

```go
type Alpha struct {

}

type Numeric struct {

}
```

你可能还记得，创建接口和结构允许我们根据类型分别路由我们的函数调用。这在下面的代码中显示：

```go
func (a Alpha) Add(x string, y string) (string, error) {
  var err error
  xType := reflect.TypeOf(x).Kind()
  yType := reflect.TypeOf(y).Kind()
  if xType != reflect.String || yType != reflect.String {
    err = errors.New("Incorrect type for strings a or b!")
  }
  finalString := x + y
  return finalString, err
}

func (n Numeric) Add(x int, y int) (int, error) {
  var err error

  xType := reflect.TypeOf(x).Kind()
  yType := reflect.TypeOf(y).Kind()
  if xType != reflect.Int || yType != reflect.Int {
    err = errors.New("Incorrect type for integer a or b!")
  }
  return x + y, err
}
func main() {
  n1 := Numeric{}
  a1 := Alpha{}
  z,err := n1.Add(5,2)	
  if err != nil {
    log.Println("Error",err)
  }
  log.Println(z)

  y,err := a1.Add("super","lative")
  if err != nil {
    log.Println("Error",err)
  }
  log.Println(y)
}
```

这仍然报告了最终会被编译器捕获的内容，但也处理了编译器无法看到的某种错误：外部输入。我们通过接口路由我们的`Add()`函数，这通过更明确地指导结构的参数和方法提供了一些额外的标准化。

例如，如果我们为我们的值输入用户输入并需要评估该输入的类型，我们可能希望以这种方式报告错误，因为编译器永远不会知道我们的代码可以接受错误的类型。

## 打破 goroutine 日志

保持关注并发和隔离的消息处理和日志记录的一种方法是用自己的日志记录器束缚我们的 goroutine，这将使一切与其他 goroutines 分开。

在这一点上，我们应该注意到这可能不会扩展——也就是说，创建成千上万个拥有自己日志记录器的 goroutines 可能会变得昂贵，但在最小规模下，这是完全可行和可管理的。

为了单独进行这种日志记录，我们将希望将一个`Logger`实例绑定到每个 goroutine，如下面的代码所示：

```go
package main

import
(
  "log"
  "os"
  "strconv"
)

const totalGoroutines = 5

type Worker struct {
  wLog *log.Logger
  Name string
}
```

我们将创建一个通用的`Worker`结构，讽刺的是它在这个示例中不会做任何工作（至少在这个示例中不会），只是保存它自己的`Logger`对象。代码如下：

```go
func main() {
  done := make(chan bool)

  for i:=0; i< totalGoroutines; i++ {

    myWorker := Worker{}
    myWorker.Name = "Goroutine " + strconv.FormatInt(int64(i),10) + ""
    myWorker.wLog = log.New(os.Stderr, myWorker.Name, 1)
    go func(w *Worker) {

        w.wLog.Print("Hmm")

        done <- true
    }(&myWorker)
  }
```

每个 goroutine 通过`Worker`都负责自己的日志例程。虽然我们直接将输出发送到控制台，但这在很大程度上是不必要的。但是，如果我们想将每个输出到自己的日志文件中，我们可以使用以下代码来实现：

```go
  log.Println("...")

  <- done
}
```

## 使用 LiteIDE 进行更丰富和更容易的调试

在本书的前几章中，我们简要讨论了 IDE，并举了一些与 Go 紧密集成的 IDE 的例子。

在我们审查日志记录和调试时，有一个 IDE 我们之前并没有特别提到，主要是因为它是为一小部分语言——即 Go 和 Lua 而设计的。然而，如果你最终主要或专门使用 Go，你会发现它绝对是必不可少的，特别是因为它与调试、日志记录和反馈功能相关。

**LiteIDE**跨平台，在 OS X、Linux 和 Windows 上运行良好。它以 GUI 形式提供的调试和测试优势是无价的，特别是如果你已经非常熟悉 Go。最后一部分很重要，因为开发人员在深入使用简化编程过程的工具之前，通常会从“学习艰难的方式”中受益最多。在被呈现出漂亮的图标、菜单和弹出窗口之前，了解某件事情的工作原理或不工作原理是几乎总是更好的。话虽如此，LiteIDE 是一款非常棒的免费工具，适用于高级 Go 程序员。

通过从 Go 中形式化许多工具和错误报告，我们可以通过在屏幕上看到它们来轻松地解决一些更棘手的调试任务。

LiteIDE 还带来了上下文感知、代码完成、`go fmt`等功能到我们的工作空间。你可以想象一下，专门针对 Go 调优的 IDE 如何帮助你保持代码的清晰和无错。参考以下截图：

![使用 LiteIDE 进行更丰富和更容易的调试](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/ms-cncr-go/img/00055.jpeg)

LiteIDE 在 Windows 上显示输出和自动代码完成

### 提示

LiteIDE 适用于 Linux、OS X 和 Windows，可以在[`code.google.com/p/liteide/`](https://code.google.com/p/liteide/)找到。

## 将错误发送到屏幕

在本书中，我们通常使用`fmt.Println`语法处理软错误、警告和一般消息，通过向控制台发送消息。

虽然这对于演示目的来说快速简单，但最好使用`log`包来处理这些事情。这是因为我们在`log`包中有更多的灵活性，可以决定消息的最终目的地。

就我们目前的目的而言，这些消息都是虚幻的。将简单的`Println`语句切换到`Logger`非常简单。

我们之前使用以下代码来传递消息：

```go
fmt.Println("Horrible error:",err)
```

你会注意到对`Logger`的更改非常相似：

```go
myLogger.Println("Horrible error:", err)
```

这对于 goroutines 特别有用，因为我们可以创建一个全局的`Logger`接口，可以在任何地方访问，或者将记录器的引用传递给单独的 goroutines，并确保我们的日志记录是并发处理的。

在整个应用程序中使用单个记录器的一个考虑是，我们可能希望单独记录每个过程，以便更清晰地进行分析。我们稍后会在本章中更详细地讨论这一点。

要复制将消息传递给命令行，我们可以简单地使用以下代码：

```go
log.Print("Message")
```

默认情况下，它的`io.writer`是`stdout`——回想一下，我们可以将任何`io.writer`设置为日志的目的地。

然而，我们还希望能够快速轻松地记录到文件中。毕竟，任何在后台运行或作为守护程序运行的应用程序都需要有一些更持久的东西。

## 将错误记录到文件

有很多种方法可以将错误发送到日志文件中——毕竟，我们可以使用内置的文件操作 OS 调用来处理这个问题。事实上，这就是许多人所做的。

然而，`log`包提供了一些标准化和潜在的命令行反馈与错误、警告和一般信息的更持久存储之间的共生关系。

这样做的最简单方法是使用`os.OpenFile()`方法（而不是`os.Open()`方法）打开一个文件，并将该引用传递给我们的日志实例化作为`io.Writer`。

让我们在下面的示例中看看这样的功能：

```go
package main

import (
  "log"
  "os"
)

func main() {
  logFile, _ := os.OpenFile("/var/www/test.log", os.O_RDWR, 0755)

  log.SetOutput(logFile)
  log.Println("Sending an entry to log!")

  logFile.Close()
}
```

在我们之前的 goroutine 包中，我们可以为每个 goroutine 分配一个自己的文件，并将文件引用作为 io Writer 传递（我们需要对目标文件夹具有写访问权限）。代码如下：

```go
  for i:=0; i< totalGoroutines; i++ {

    myWorker := Worker{}
    myWorker.Name = "Goroutine " + strconv.FormatInt(int64(i),10) 
      + ""
    myWorker.FileName = "/var/www/"+strconv.FormatInt(int64(i),10) 
      + ".log"
    tmpFile,_ :=   os.OpenFile(myWorker.FileName, os.O_CREATE, 
      0755)
    myWorker.File = tmpFile
    myWorker.wLog = log.New(myWorker.File, myWorker.Name, 1)
    go func(w *Worker) {

        w.wLog.Print("Hmm")

        done <- true
    }(&myWorker)
  }
```

## 将错误记录到内存

当我们谈论将错误记录到内存时，我们实际上是在谈论数据存储，尽管除了易失性和有限的资源之外，没有理由拒绝将日志记录到内存作为一种可行的选择。

虽然我们将在下一节中看一种更直接的处理网络日志记录的方法，但让我们在一个并发的分布式系统中划分各种应用程序错误而不费太多力气。这个想法是使用共享内存（比如 Memcached 或共享内存数据存储）来传递我们的日志消息。

虽然这些技术上仍然是日志文件（大多数数据存储将单独的记录或文档保存为 JSON 编码的硬文件），但与传统日志记录有着明显不同的感觉。

回到上一章的老朋友 CouchDB，将我们的日志消息传递到中央服务器几乎可以毫不费力地完成，这样我们就可以跟踪不仅是单个机器，还有它们各自的并发 goroutines。代码如下：

```go
package main

import
(
  "github.com/couchbaselabs/go-couchbase"
  "io"
  "time"
  "fmt"
  "os"
  "net/http"
  "crypto/md5"
  "encoding/hex"
)
type LogItem struct {
  ServerID string "json:server_id"
  Goroutine int "json:goroutine"
  Timestamp time.Time "json:time"
  Message string "json:message"
  Page string "json:page"
}
```

这将最终成为我们将发送到 Couchbase 服务器的 JSON 文档。我们将使用`Page`，`Timestamp`和`ServerID`作为组合的哈希键，以允许对同一文档的多个并发请求在不同服务器上分别记录日志，如下面的代码所示：

```go
var currentGoroutine int

func (li LogItem) logRequest(bucket *couchbase.Bucket) {

  hash := md5.New()
  io.WriteString(hash,li.ServerID+li.Page+li.Timestamp.Format("Jan 
    1, 2014 12:00am"))
  hashString := hex.EncodeToString(hash.Sum(nil))
  bucket.Set(hashString,0,li)
  currentGoroutine = 0
}
```

当我们将`currentGoroutine`重置为`0`时，我们使用了一个有意的竞争条件，允许 goroutines 在并发执行时通过数字 ID 报告自己。这使我们能够调试一个看起来正常工作的应用程序，直到它调用某种形式的并发架构。由于 goroutines 将通过 ID 自我识别，这使我们能够更加精细地路由我们的消息。

通过为 goroutine `ID`，`timestamp`和`serverID`指定不同的日志位置，可以快速从日志文件中提取任何并发问题。使用以下代码完成：

```go
func main() {
  hostName, _ := os.Hostname()
  currentGoroutine = 0

  logClient, err := couchbase.Connect("http://localhost:8091/")
    if err != nil {
      fmt.Println("Error connecting to logging client", err)
    }
  logPool, err := logClient.GetPool("default")
    if err != nil {
      fmt.Println("Error getting pool",err)
    }
  logBucket, err := logPool.GetBucket("logs")
    if err != nil {
      fmt.Println("Error getting bucket",err)
    }
  http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
    request := LogItem{}
    request.Goroutine = currentGoroutine
    request.ServerID = hostName
    request.Timestamp = time.Now()
    request.Message = "Request to " + r.URL.Path
    request.Page = r.URL.Path
    go request.logRequest(logBucket)

  })

  http.ListenAndServe(":8080",nil)

}
```

# 使用 log4go 包进行强大的日志记录

与 Go 中的大多数事物一样，在核心页面中有令人满意和可扩展的东西，可以通过第三方（Go 的精彩日志包真正地与**log4go**结合在一起。

使用 log4go 极大地简化了文件记录、控制台记录和通过 TCP/UDP 记录的过程。

### 提示

有关 log4go 的更多信息，请访问[`code.google.com/p/log4go/`](https://code.google.com/p/log4go/)。

每个`log4go Logger`接口的实例都可以通过 XML 配置文件进行配置，并且可以对其应用过滤器以指示消息的去向。让我们看一个简单的 HTTP 服务器，以展示如何将特定的日志定向到位置，如下面的代码所示：

```go
package main

import (
  "code.google.com/p/log4go"
  "net/http"
  "fmt"
  "github.com/gorilla/mux"
)
var errorLog log4go.Logger
var errorLogWriter log4go.FileLogWriter

var accessLog log4go.Logger
var accessLogWriter *log4go.FileLogWriter

var screenLog log4go.Logger

var networkLog log4go.Logger
```

在前面的代码中，我们创建了四个不同的日志对象——一个将错误写入日志文件，一个将访问（页面请求）写入到一个单独的文件，一个直接发送到控制台（用于重要通知），一个将日志消息传递到网络。

最后两个显然不需要`FileLogWriter`，尽管完全可以使用共享驱动器来复制网络记录，如果我们可以减轻并发访问的问题，如下面的代码所示：

```go
func init() {
  fmt.Println("Web Server Starting")
}

func pageHandler(w http.ResponseWriter, r *http.Request) {
  pageFoundMessage := "Page found: " + r.URL.Path
  accessLog.Info(pageFoundMessage)
  networkLog.Info(pageFoundMessage)
  w.Write([]byte("Valid page"))
}
```

任何对有效页面的请求都会发送消息到`web-access.log`文件`accessLog`。

```go
func notFound(w http.ResponseWriter, r *http.Request) {
  pageNotFoundMessage := "Page not found / 404: " + r.URL.Path
  errorLog.Info(pageNotFoundMessage)
  w.Write([]byte("Page not found"))
}
```

与`accessLog`文件一样，我们将接受任何`404 /页面未找到`的请求，并直接将其路由到`notFound()`方法，该方法保存了一个相当通用的错误消息以及无效的`/`丢失的 URL 请求。让我们看看在下面的代码中我们将如何处理非常重要的错误和消息：

```go
func restricted(w http.ResponseWriter, r *http.Request) {
  message := "Restricted directory access attempt!"
  errorLog.Info(message)
  accessLog.Info(message)
  screenLog.Info(message)
  networkLog.Info(message)
  w.Write([]byte("Restricted!"))

}
```

`restricted()`函数和相应的`screenLog`表示我们认为是*关键*的消息，并且值得不仅发送到错误和访问日志，而且还发送到屏幕并作为`networkLog`项目传递。换句话说，这是一个非常重要的消息，每个人都会收到。

在这种情况下，我们正在检测尝试访问我们的`.git`文件夹，这是一个相当常见的意外安全漏洞，人们已知在自动文件上传和更新中犯过这种错误。由于我们在文件中表示明文密码，并且可能将其暴露给外部世界，我们将在请求时捕获这些并传递给我们的关键和非关键日志记录机制。

我们也可以将其视为一个更开放的坏请求通知器-值得网络开发人员立即关注。在下面的代码中，我们将开始创建一些日志记录器：

```go
func main() {

  screenLog = make(log4go.Logger)
  screenLog.AddFilter("stdout", log4go.DEBUG, log4go.NewConsoleLogWriter())

  errorLogWriter := log4go.NewFileLogWriter("web-errors.log", 
    false)
    errorLogWriter.SetFormat("%d %t - %M (%S)")
    errorLogWriter.SetRotate(false)
    errorLogWriter.SetRotateSize(0)
    errorLogWriter.SetRotateLines(0)
    errorLogWriter.SetRotateDaily(true)
```

由于 log4go 提供了许多额外的日志选项，我们可以稍微调整我们的日志轮换和格式，而不必专门使用`Sprintf`或类似的东西来绘制出来。

这里的选项简单而富有表现力：

+   `SetFormat`：这允许我们指定我们的单独日志行的外观。

+   `SetRotate`：这允许根据文件大小和/或`log`中的行数自动旋转。`SetRotateSize()`选项设置消息中的字节旋转，`SetRotateLines()`设置最大的`行数`。`SetRotateDaily()`函数让我们根据前面函数中的设置在每天创建新的日志文件。这是一个相当常见的日志记录技术，通常手工编码会很繁琐。

我们的日志格式的输出最终看起来像以下一行代码：

```go
04/13/14 10:46 - Page found%!(EXTRA string=/valid) (main.pageHandler:24)
```

`%S`部分是源，它为我们提供了调用日志的应用程序部分的行号和方法跟踪：

```go
  errorLog = make(log4go.Logger)
  errorLog.AddFilter("file", log4go.DEBUG, errorLogWriter)

  networkLog = make(log4go.Logger)
  networkLog.AddFilter("network", log4go.DEBUG, log4go.NewSocketLogWriter("tcp", "localhost:3000"))
```

我们的网络日志通过 TCP 发送 JSON 编码的消息到我们提供的地址。我们将在下一节的代码中展示一个非常简单的处理服务器，将日志消息转换为一个集中的日志文件：

```go
  accessLogWriter = log4go.NewFileLogWriter("web-access.log",false)
    accessLogWriter.SetFormat("%d %t - %M (%S)")
    accessLogWriter.SetRotate(true)
    accessLogWriter.SetRotateSize(0)
    accessLogWriter.SetRotateLines(500)
    accessLogWriter.SetRotateDaily(false)
```

我们的`accessLogWriter`与`errorLogWriter`类似，只是它不是每天轮换一次，而是每 500 行轮换一次。这里的想法是访问日志当然会比错误日志更频繁地被访问-希望如此。代码如下：

```go
  accessLog = make(log4go.Logger)
  accessLog.AddFilter("file",log4go.DEBUG,accessLogWriter)

  rtr := mux.NewRouter()
  rtr.HandleFunc("/valid", pageHandler)
  rtr.HandleFunc("/.git/", restricted)
  rtr.NotFoundHandler = http.HandlerFunc(notFound)
```

在前面的代码中，我们使用了 Gorilla Mux 包进行路由。这使我们更容易访问`404`处理程序，在基本的直接内置到 Go 中的`http`包中修改起来不那么简单。代码如下：

```go
  http.Handle("/", rtr)
  http.ListenAndServe(":8080", nil)
}
```

像这样构建网络日志系统的接收端在 Go 中也非常简单，因为我们构建的只是另一个可以处理 JSON 编码消息的 TCP 客户端。

我们可以通过一个接收服务器来做到这一点，这个接收服务器看起来与我们早期章节中的 TCP 聊天服务器非常相似。代码如下：

```go
package main

import
(
  "net"
  "fmt"
)

type Connection struct {

}

func (c Connection) Listen(l net.Listener) {
  for {
    conn,_ := l.Accept()
    go c.logListen(conn)
  }
}
```

与我们的聊天服务器一样，我们将我们的监听器绑定到一个`Connection`结构，如下面的代码所示：

```go
func (c *Connection) logListen(conn net.Conn) {
  for {
    buf := make([]byte, 1024)
    n, _ := conn.Read(buf)
    fmt.Println("Log Message",string(n))
  }
}
```

在前面的代码中，我们通过 JSON 接收日志消息。在这一点上，我们还没有解析 JSON，但我们已经在早期的章节中展示了如何做到这一点。

发送的任何消息都将被推送到缓冲区中-因此，根据信息的详细程度，扩展缓冲区的大小可能是有意义的。

```go
func main() {
  serverClosed := make(chan bool)

  listener, err := net.Listen("tcp", ":3000")
  if err != nil {
    fmt.Println ("Could not start server!",err)
  }

  Conn := Connection{}

  go Conn.Listen(listener)

  <-serverClosed
}
```

你可以想象网络日志记录在哪里会很有用，特别是在服务器集群中，你可能有一系列的，比如，Web 服务器，你不想将单独的日志文件合并成一个日志。

## 恐慌

在讨论捕获错误并记录它们时，我们可能应该考虑 Go 中的`panic()`和`recover()`功能。

正如前面简要讨论的，`panic()`和`recover()`作为一种更基本、即时和明确的错误检测方法，比如`try`/`catch`/`finally`甚至 Go 的内置错误返回值约定。按设计，`panic()`会解开堆栈并导致程序退出，除非调用`recover()`。这意味着除非你明确地恢复，否则你的应用程序将结束。

那么，除了停止执行之外，这有什么用处呢？毕竟，我们可以捕获错误并通过类似以下代码手动结束应用程序：

```go
package main

import
(
  "fmt"
  "os"
)

func processNumber(un int) {

  if un < 1 || un > 4 {
    fmt.Println("Now you've done it!")
    os.Exit(1)
  }else {
    fmt.Println("Good, you can read simple instructions.")
  }
}

func main() {
  userNum := 0
  fmt.Println("Enter a number between 1 and 4.")
  _,err := fmt.Scanf("%d",&userNum)
    if err != nil {}

  processNumber(userNum)
}
```

然而，虽然这个函数进行了健全性检查并执行了永久的、不可逆转的应用程序退出，`panic()`和`recover()`允许我们从特定包和/或方法中反映错误，保存这些错误，然后优雅地恢复。

当我们处理从其他方法调用的方法时，这是非常有用的，这些方法又是从其他方法调用的，依此类推。深度嵌套或递归函数的类型使得很难辨别特定错误，这就是`panic()`和`recover()`最有优势的地方。你也可以想象这种功能与日志记录的结合有多么好。

## 恢复

`panic()`函数本身相当简单，当与`recover()`和`defer()`配对时，它真正变得有用。

举个例子，一个应用程序从命令行返回有关文件的元信息。应用程序的主要部分将监听用户输入，将其传递到一个打开文件的函数中，然后将该文件引用传递给另一个函数，该函数将获取文件的详细信息。

现在，显然我们可以直接通过过程堆叠错误作为返回元素，或者我们可以在途中发生 panic，恢复回到步骤，然后在底部收集我们的错误以进行日志记录和/或直接报告到控制台。

避免意大利面代码是这种方法与前一种方法相比的一个受欢迎的副作用。以一般意义来考虑（这是伪代码）：

```go
func getFileDetails(fileName string) error {
  return err
}

func openFile(fileName string) error {
  details,err := getFileDetails(fileName)
  return err
}

func main() {

  file,err := openFile(fileName)

}
```

有一个错误时，完全可以以这种方式处理我们的应用程序。然而，当每个单独的函数都有一个或多个失败点时，我们将需要更多的返回值以及一种将它们全部整合成单个整体错误消息或多个消息的方法。检查以下代码：

```go
package main

import
(
  "os"
  "fmt"
  "strconv"
)

func gatherPanics() {
  if rec := recover(); rec != nil {
    fmt.Println("Critical Error:", rec)
  }
}
```

这是我们的一般恢复函数，在我们希望捕获任何 panic 之前调用每个方法。让我们看一个推断文件详细信息的函数：

```go
func getFileDetails(fileName string) {
  defer gatherPanics()
  finfo,err := os.Stat(fileName)
  if err != nil {
    panic("Cannot access file")
  }else {
    fmt.Println("Size: ", strconv.FormatInt(finfo.Size(),10))
  }
}

func openFile(fileName string) {
  defer gatherPanics()
  if _, err := os.Stat(fileName); err != nil {
    panic("File does not exist")
  }

}
```

前面代码中的两个函数仅仅是尝试打开一个文件并在文件不存在时发生 panic。第二个方法`getFileDetails()`被从`main()`函数中调用，这样它将始终执行，而不管`openFile()`中是否有阻塞错误。

在现实世界中，我们经常会开发应用程序，其中非致命错误只会导致应用程序的部分功能停止工作，但不会导致整个应用程序崩溃。检查以下代码：

```go
func main() {
  var fileName string
  fmt.Print("Enter filename>")
  _,err := fmt.Scanf("%s",&fileName)
  if err != nil {}
  fmt.Println("Getting info for",fileName)

  openFile(fileName)
  getFileDetails(fileName)

}
```

如果我们从`gatherPanics()`方法中删除`recover()`代码，那么如果/当文件不存在，应用程序将崩溃。

这可能看起来很理想，但想象一下一个用户选择了一个不存在的文件作为他们没有权限查看的目录。当他们解决了第一个问题时，他们将被呈现第二个问题，而不是一次看到所有潜在的问题。

从用户体验的角度来看，表达错误的价值无法被过分强调。通过这种方法，收集和呈现表达性错误变得更加容易——即使`try`/`catch`/`finally`也要求我们（作为开发人员）在 catch 子句中明确地处理返回的错误。

### 记录我们的 panic

在前面的代码中，我们可以很简单地集成一个日志记录机制，除了捕获我们的 panic。

关于日志记录，我们还没有讨论的一个考虑是何时记录。正如我们之前的例子所说明的，有时我们可能遇到应该记录但可能会被未来用户操作所缓解的问题。因此，我们可以选择立即记录错误或将其保存到执行结束或更大的函数结束时再记录。

立即记录日志的主要好处是我们不容易受到实际崩溃的影响，从而无法保存日志。举个例子：

```go
type LogItem struct {
  Message string
  Function string
}

var Logs []LogItem
```

我们使用以下代码创建了一个日志`struct`和一个`LogItems`的切片：

```go
func SaveLogs() {
  logFile := log4go.NewFileLogWriter("errors.log",false)
    logFile.SetFormat("%d %t - %M (%S)")
    logFile.SetRotate(true)
    logFile.SetRotateSize(0)
    logFile.SetRotateLines(500)
    logFile.SetRotateDaily(false)

  errorLog := make(log4go.Logger)
  errorLog.AddFilter("file",log4go.DEBUG,logFile)
  for i:= range Logs {
    errorLog.Info(Logs[i].Message + " in " + Logs[i].Function)
  }

}
```

这里，我们捕获的所有`LogItems`将被转换为日志文件中的一系列好的行项目。然而，如下代码所示，存在问题：

```go
func registerError(block chan bool) {

  Log := LogItem{ Message:"An Error Has Occurred!", Function: "registerError()"}
  Logs = append(Logs,Log)
  block <- true
}
```

在 goroutine 中执行此函数是非阻塞的，并允许主线程的执行继续。问题出在 goroutine 之后运行的以下代码，导致我们根本没有记录任何内容：

```go
func separateFunction() {
  panic("Application quitting!")
}
```

无论是手动调用还是由二进制文件本身调用，应用程序过早退出都会导致我们的日志文件无法写入，因为该方法被延迟到`main()`方法结束。代码如下：

```go
func main() {
  block := make(chan bool)
  defer SaveLogs()
  go func(block chan bool) {

    registerError(block)

  }(block)

  separateFunction()

}
```

然而，这里的权衡是性能。如果我们每次想要记录日志时执行文件操作，就可能在应用程序中引入瓶颈。在前面的代码中，错误是通过 goroutine 发送的，但在阻塞代码中写入——如果我们直接将日志写入`registerError()`中，可能会减慢我们最终应用程序的速度。

如前所述，缓解这些问题并允许应用程序仍然保存所有日志条目的一个机会是利用内存日志或网络日志。

## 捕获并发代码的堆栈跟踪

在早期的 Go 版本中，从源代码正确执行堆栈跟踪是一项艰巨的任务，这体现了用户在 Go 语言早期对一般错误处理的许多抱怨和担忧。

尽管 Go 团队一直对*正确*的方法保持警惕（就像他们对其他一些关键语言特性如泛型的处理一样），但随着语言的发展，堆栈跟踪和堆栈信息已经有所调整。

# 使用 runtime 包进行细粒度堆栈跟踪

为了直接捕获堆栈跟踪，我们可以从内置的 runtime 包中获取一些有用的信息。

具体来说，Go 语言提供了一些工具，可以帮助我们了解 goroutine 的调用和/或断点。以下是 runtime 包中的函数：

+   `runtime.Caller()`: 返回 goroutine 的父函数的信息

+   `runtime.Stack()`: 为堆栈跟踪中的数据分配一个缓冲区，然后填充该缓冲区

+   `runtime.NumGoroutine()`: 返回当前打开的 goroutine 的总数

我们可以利用前面提到的三种工具来更好地描述任何给定 goroutine 的内部工作和相关错误。

使用以下代码，我们将生成一些随机的 goroutine 执行随机的操作，并记录不仅 goroutine 的日志消息，还有堆栈跟踪和 goroutine 的调用者：

```go
package main

import
(
  "os"
  "fmt"
  "runtime"
  "strconv"
  "code.google.com/p/log4go"
)

type LogItem struct {
  Message string
}

var LogItems []LogItem

func saveLogs() {
  logFile := log4go.NewFileLogWriter("stack.log", false)
    logFile.SetFormat("%d %t - %M (%S)")
    logFile.SetRotate(false)
    logFile.SetRotateSize(0)
    logFile.SetRotateLines(0)
    logFile.SetRotateDaily(true)

  logStack := make(log4go.Logger)
  logStack.AddFilter("file", log4go.DEBUG, logFile)
  for i := range LogItems {
    fmt.Println(LogItems[i].Message)
    logStack.Info(LogItems[i].Message)
  }
}
```

`saveLogs()`函数只是将我们的`LogItems`映射到文件中，就像我们在本章前面做的那样。接下来，我们将看一下提供有关我们 goroutines 详细信息的函数：

```go
func goDetails(done chan bool) {
  i := 0
  for {
    var message string
    stackBuf := make([]byte,1024)
    stack := runtime.Stack(stackBuf, false)
    stack++
    _, callerFile, callerLine, ok := runtime.Caller(0)
    message = "Goroutine from " + string(callerLine) + "" + 
      string(callerFile) + " stack:" + 	string(stackBuf)
    openGoroutines := runtime.NumGoroutine()

    if (ok == true) {
      message = message + callerFile
    }

    message = message + strconv.FormatInt(int64(openGoroutines),10) + " goroutines 
        active"

    li := LogItem{ Message: message}

    LogItems = append(LogItems,li)
    if i == 20 {
      done <- true
      break
    }

    i++
  }
}
```

这是我们收集有关 goroutine 的更多细节的地方。`runtime.Caller()`函数提供了一些返回值：指针、调用者的文件名、调用者的行号。最后一个返回值指示是否找到了调用者。

如前所述，`runtime.NumGoroutine()`给出了尚未关闭的现有 goroutine 的数量。

然后，在`runtime.Stack(stackBuf, false)`中，我们用堆栈跟踪填充我们的缓冲区。请注意，我们没有将这个字节数组修剪到指定长度。

所有这三个都被传递到 `LogItem.Message` 中以供以后使用。让我们看看 `main()` 函数中的设置：

```go
func main() {
  done := make(chan bool)

  go goDetails(done)
  for i:= 0; i < 10; i++ {
    go goDetails(done)
  }

  for {
    select {
      case d := <-done:
        if d == true {
          saveLogs()
          os.Exit(1)
        }
    }
  }

}
```

最后，我们循环遍历一些正在执行循环的 goroutines，并在完成后退出。

当我们检查日志文件时，我们得到的关于 goroutines 的详细信息比以前要多得多，如下面的代码所示：

```go
04/16/14 23:25 - Goroutine from + /var/log/go/ch9_11_stacktrace.goch9_11_stacktrace.go stack:goroutine 4 [running]:
main.goDetails(0xc08400b300)
  /var/log/go/ch9_11_stacktrace.goch9_11_stacktrace.go:41 +0x8e
created by main.main
  /var/log/go/ch9_11_stacktrace.goch9_11_stacktrace.go:69 +0x4c

  /var/log/go/ch9_11_stacktrace.goch9_11_stacktrace.go14 goroutines active (main.saveLogs:31)
```

### 提示

有关运行时包的更多信息，请访问 [`golang.org/pkg/runtime/`](http://golang.org/pkg/runtime/)。

# 总结

调试、测试和记录并发代码可能特别麻烦，尤其是当并发的 goroutines 以一种看似无声的方式失败或根本无法执行时。

我们看了各种记录方法，从文件到控制台到内存到网络记录，并研究了并发应用程序组件如何适应这些不同的实现。

到目前为止，您应该已经可以轻松自然地创建健壮且表达力强的日志，这些日志会自动轮换，不会产生延迟或瓶颈，并有助于调试您的应用程序。

您应该对运行时包的基础知识感到满意。随着我们在下一章中深入挖掘，我们将深入探讨测试包、更明确地控制 goroutines 和单元测试。

除了进一步检查测试和运行时包之外，在我们的最后一章中，我们还将涉及更高级的并发主题，以及审查一些与在 Go 语言中编程相关的总体最佳实践。
