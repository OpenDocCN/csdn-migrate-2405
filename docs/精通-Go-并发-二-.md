# 精通 Go 并发（二）

> 原文：[`zh.annas-archive.org/md5/5C14031AC553348345D455C9E701A474`](https://zh.annas-archive.org/md5/5C14031AC553348345D455C9E701A474)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第四章：应用程序中的数据完整性

到目前为止，您应该已经熟悉了 Go 核心中提供的模型和工具，以提供大部分无竞争的并发。

现在我们可以轻松创建 goroutines 和通道，管理通道之间的基本通信，协调数据而不会出现竞争条件，并在出现这些条件时检测到。

然而，我们既不能管理更大的分布式系统，也不能处理潜在的较低级别的一致性问题。我们使用了基本和简单的互斥锁，但我们将要看一种更复杂和富有表现力的处理互斥排他的方法。

在本章结束时，您应该能够将上一章中的并发模式扩展到使用其他语言的多种并发模型和系统构建分布式系统。我们还将从高层次上看一些一致性模型，您可以利用这些模型来进一步表达您的单源和分布式应用程序的预编码策略。

# 深入了解互斥锁和同步

在第二章*理解并发模型*中，我们介绍了`sync.mutex`以及如何在代码中调用互斥锁，但在考虑包和互斥锁类型时还有一些微妙之处。

在理想的世界中，您应该能够仅使用 goroutines 来维护应用程序中的同步。实际上，这可能最好被描述为 Go 中的规范方法，尽管`sync`包提供了一些其他实用程序，包括互斥锁。

在可能的情况下，我们将坚持使用 goroutines 和通道来管理一致性，但互斥锁确实提供了一种更传统和细粒度的方法来锁定和访问数据。如果您曾经管理过另一种并发语言（或语言内的包），很可能您已经使用过互斥锁或类似的东西。在接下来的章节中，我们将探讨如何扩展和利用互斥锁，以便更多地发挥其作用。

如果我们查看`sync`包，我们会看到有几种不同的互斥锁结构。

第一个是`sync.mutex`，我们已经探讨过了，但另一个是`RWMutex`。`RWMutex`结构提供了多读单写锁。如果您希望允许对资源进行读取，但在尝试写入时提供类似互斥锁的锁定，这些锁可能很有用。当您期望函数或子进程频繁读取但很少写入时，它们可以最好地利用，但仍然不能承受脏读。

让我们看一个例子，每隔 10 秒更新一次日期/时间（获取锁定），然后每隔两秒输出当前值，如下面的代码所示：

```go
package main

import (
  "fmt"
  "sync"
  "time"
)

type TimeStruct struct {
  totalChanges int
  currentTime time.Time
  rwLock sync.RWMutex
}

var TimeElement TimeStruct

func updateTime() {
  TimeElement.rwLock.Lock()
  defer TimeElement.rwLock.Unlock()
  TimeElement.currentTime = time.Now()
  TimeElement.totalChanges++
}

func main() {

  var wg sync.WaitGroup

  TimeElement.totalChanges = 0
  TimeElement.currentTime = time.Now()
  timer := time.NewTicker(1 * time.Second)
  writeTimer := time.NewTicker(10 * time.Second)
  endTimer := make(chan bool)

  wg.Add(1)
  go func() {

    for {
      select {
      case <-timer.C:
        fmt.Println(TimeElement.totalChanges, 
          TimeElement.currentTime.String())
      case <-writeTimer.C:
        updateTime()
      case <-endTimer:
        timer.Stop()
        return
      }

    }

  }()

  wg.Wait()
  fmt.Println(TimeElement.currentTime.String())
}
```

### 注意

我们没有在`WaitGroup`结构上显式运行`Done()`，因此这将永久运行。

在`RWMutex`上执行锁定/解锁的两种不同方法：

+   `Lock()`: 这将阻止变量进行读取和写入，直到调用`Unlock()`方法

+   `happenedRlock()`: 这将仅为读取锁定绑定变量

第二种方法是我们用于此示例的方法，因为我们希望模拟真实世界的锁定。净效果是`interval`函数输出当前时间，然后在`rwLock`释放对`currentTime`变量的读取锁之前返回一个脏读。`Sleep()`方法仅用于给我们时间来观察锁定的运动。`RWLock`结构可以被多个读取者或单个写入者获取。

# goroutines 的成本

当你使用 goroutines 时，你可能会到达一个点，你会产生几十甚至几百个 goroutines，并且会想知道这是否会很昂贵。如果你之前的并发和/或并行编程经验主要是基于线程的，这是特别真实的。通常认为，维护线程及其各自的堆栈可能会导致程序性能问题。这有几个原因，如下所示：

+   为线程的创建需要内存

+   在操作系统级别进行上下文切换比进程内上下文切换更复杂和昂贵

+   很多时候，一个线程被创建用于处理本来可以以其他方式处理的非常小的进程

正因为这些原因，许多现代并发语言实现了类似 goroutines 的东西（C#使用 async 和 await 机制，Python 有 greenlets/green threads 等），这些机制使用小规模的上下文切换来模拟线程。

然而，值得知道的是，虽然 goroutines 是（或者可以是）廉价的，比操作系统线程更便宜，但它们并不是免费的。在大规模（也许是巨大规模）下，即使是廉价和轻量级的 goroutines 也会影响性能。这在我们开始研究分布式系统时尤为重要，因为这些系统通常规模更大，速度更快。

直接运行函数和在 goroutine 中运行函数之间的差异当然是可以忽略的。然而，要记住 Go 的文档中指出：

*在同一个地址空间中创建数十万个 goroutines 是实际可行的。*

考虑到每个 goroutine 使用几千字节的堆栈，现代环境中，很容易看出这可能被视为一个不重要的因素。然而，当你开始谈论成千上万（或者百万）个 goroutines 在运行时，它可能会影响任何给定子进程或函数的性能。你可以通过将函数包装在任意数量的 goroutines 中并对平均执行时间和——更重要的是——内存使用进行基准测试来测试这一点。每个 goroutine 大约占用 5KB 的内存，你可能会发现内存可能成为一个因素，特别是在低 RAM 的机器或实例上。如果你有一个在高性能机器上运行的应用程序，想象一下它在一个或多个低功率机器上达到临界点。考虑以下例子：

```go
for i:= 0; i < 1000000000; i++ {
  go someFunction()
}
```

即使 goroutine 的开销很小，但是当有 1 亿个或者——就像我们这里有的——10 亿个 goroutines 在运行时会发生什么？

正如以往一样，在一个利用多个核心的环境中进行这样的操作实际上可能会增加应用程序的开销，因为涉及到操作系统线程和随后的上下文切换的成本。

这些问题几乎总是在应用程序开始扩展之前是看不见的。在你的机器上运行是一回事，但在一个分布式系统中运行，尤其是在低功率应用服务器上运行，就是另一回事了。

性能和数据一致性之间的关系很重要，特别是当你开始使用大量的 goroutines 进行互斥、锁定或通道通信时。

当处理外部、更持久的内存来源时，这就成为一个更大的问题。

# 处理文件

文件是数据一致性问题的一个很好的例子，比如竞争条件可能导致更加持久和灾难性的问题。让我们看一个可能不断尝试更新文件的代码片段，看看我们可能会遇到竞争条件的地方，这反过来可能会导致更大的问题，比如应用程序失败或数据一致性丢失：

```go
package main

import(
  "fmt"
  "io/ioutil"
  "strconv"
  "sync"
)

func writeFile(i int) {

  rwLock.RLock();
  ioutil.WriteFile("test.txt", 
    []byte(strconv.FormatInt(int64(i),10)), 0x777)
  rwLock.RUnlock();

  writer<-true

}

var writer chan bool
var rwLock sync.RWMutex

func main() {

  writer = make(chan bool)

  for i:=0;i<10;i++ {
    go writeFile(i)
  }

  <-writer
  fmt.Println("Done!")
}
```

涉及文件操作的代码很容易出现这种潜在问题，因为错误通常*不是短暂的*，并且可能永远被固定在时间中。

如果我们的 goroutines 在某个关键点阻塞，或者应用程序在中途失败，我们可能会得到一个文件中包含无效数据的结果。在这种情况下，我们只是在一些数字中进行迭代，但您也可以将这种情况应用到涉及数据库或数据存储写入的情况——存在永久性的坏数据而不是临时的坏数据的潜在可能。

这不是仅通过通道或互斥来解决的问题；相反，它需要在每一步进行某种理智检查，以确保数据在执行的每一步中都在您和应用程序期望的位置。任何涉及`io.Writer`的操作都依赖于原语，Go 的文档明确指出我们不应该假设它们对并行执行是安全的。在这种情况下，我们已经在互斥体中包装了文件写入。

# 降低实现 C

在过去的十年或二十年中，语言设计中最有趣的发展之一是希望通过 API 实现低级语言和语言特性。Java 允许您纯粹在外部进行这样的操作，而 Python 提供了一个 C 库，用于在这两种语言之间进行交互。值得一提的是，这样做的原因各不相同——其中包括将 Go 的并发特性作为对遗留 C 代码的包装——您可能需要处理与引入非托管代码到垃圾收集应用程序相关的一些内存管理。

Go 采取了混合方法，允许您通过导入调用 C 接口，这需要一个前端编译器，比如 GCC：

```go
import "C"
```

那么我们为什么要这样做呢？

在你的项目中直接实现 C 有一些好的和坏的原因。一个好的原因可能是直接访问内联汇编，这在 C 中可以做到，但在 Go 中不能直接做到。一个坏的原因可能是任何一个在 Golang 本身中有解决方案的原因。

公平地说，即使是一个坏的原因，如果您构建应用程序可靠，也不是坏事，但它确实给可能使用您的代码的其他人增加了额外的复杂性。如果 Go 能满足技术和性能要求，最好在单个项目中使用单一语言。

C++的创造者 Bjarne Stroustrup 有一句著名的关于 C 和 C++的引语：

*C 使得自己开枪变得容易；C++使得更难，但当你这样做时，它会把你的整条腿都炸掉。*

开玩笑的时候（Stroustrup 有大量这样的笑话和引语），基本的推理是 C 的复杂性经常阻止人们意外地做出灾难性的事情。

正如 Stroustrup 所说，C 使犯大错变得容易，但由于语言设计，后果通常比高级语言要小。处理安全和稳定性问题很容易在任何低级语言中引入。

通过简化语言，C++提供了使低级操作更容易进行的抽象。您可以看到这可能如何应用于在 Go 中直接使用 C，鉴于后者语法上的甜美和程序员友好性。

也就是说，使用 C 可以突出显示关于内存、指针、死锁和一致性的潜在陷阱，所以我们将以一个简单的例子来说明：

```go
package main

// #include <stdio.h>
// #include <string.h>
//  int string_length (char* str) {
//    return strlen(str);
//  }
import "C"
import "fmt"
func main() {
  v := C.CString("Don't Forget My Memory Is Not Visible To Go!")
  x := C.string_length(v)
  fmt.Println("A C function has determined your string 
    is",x,"characters in length")
}
```

## 在 cgo 中触及内存

从前面的例子中最重要的收获是要记住，每当您进入或退出 C 时，您都需要手动管理内存（或者至少比仅使用 Go 更直接地管理）。如果您曾经在 C（或 C++）中工作过，您就会知道没有自动垃圾收集，所以如果您请求内存空间，您也必须释放它。从 Go 调用 C 并不排除这一点。

## cgo 的结构

将 C 导入 Go 将使您走上一个语法侧路，正如您可能在前面的代码中注意到的。最显眼的不同之处是在您的应用程序中实际实现 C 代码。

任何位于`import "C"`指令上方的代码（在注释中阻止 Go 编译器失败）将被解释为 C 代码。以下是一个在我们的 Go 代码上方声明的 C 函数的示例：

```go
/*
  int addition(int a, int b) {
    return a + b;
  }
```

请记住，Go 不会验证这一点，因此如果您在 C 代码中出现错误，可能会导致静默失败。

另一个相关的警告是记住您的语法。虽然 Go 和 C 有很多语法上的重叠，但如果少了一个花括号或一个分号，您很可能会发现自己处于其中一个静默失败的情况。或者，如果您在应用程序的 C 部分工作，然后回到 Go，您肯定会发现自己需要在循环表达式中加上括号，并在行尾加上分号。

还要记住，您经常需要处理 C 和 Go 之间没有一对一对应的类型转换。例如，C 没有内置的字符串类型（当然，您可以包含其他类型的库），因此您可能需要在字符串和 char 数组之间进行转换。同样，`int`和`int64`可能需要一些非隐式转换，而且在编译这些代码时，您可能无法获得您期望的调试反馈。

## 另一种方式

在 Go 中使用 C 显然是一个潜在的强大工具，用于代码迁移，实现低级代码，并吸引其他开发人员，但反过来呢？就像您可以从 Go 中调用 C 一样，您也可以在嵌入的 C 中将 Go 函数作为外部函数调用。

最终目标是能够在同一个应用程序中与 C 和 Go 一起工作。到目前为止，处理这个问题最简单的方法是使用 gccgo，它是 GCC 的前端。这与内置的 Go 编译器不同；当然，可以在 C 和 Go 之间来回切换，但使用 gccgo 可以使这个过程更简单。

**gopart.go**

以下是交互的 Go 部分的代码，C 部分将作为外部函数调用：

```go
package main

func MyGoFunction(num C.int) int {

  squared := num * num
  fmt.Println(num,"squared is",squared)
  return squared
}
```

**cpart.c**

现在是 C 部分的时间，我们在下面的代码片段中调用我们的 Go 应用程序的导出函数`MyGoFunction`。

```go
#include <stdio.h>

extern int square_it(int) __asm__ ("cross.main.MyGoFunction")

int main() {

  int output = square_it(5)
  printf("Output: %d",output)
  return 0;
}
```

**Makefile**

与直接在 Go 中使用 C 不同，目前，对反向操作需要使用 C 编译的 makefile。以下是一个您可以使用的示例，用于从之前的简单示例中获取可执行文件：

```go
all: main

main: cpart.o cpart.c
    gcc cpart.o cpart.c -o main

gopart.o: gopart.go
    gccgo -c gopart.go -o gopart.o -fgo-prefix=cross

clean:
    rm -f main *.o
```

在这里运行 makefile 应该会生成一个可执行文件，该文件调用了 C 中的函数。

然而，更根本的是，cgo 允许您直接将函数定义为 C 的外部函数：

```go
package output

import "C"

//export MyGoFunction
func MyGoFunction(num int) int {

  squared := num * num
  return squared
}
```

接下来，您需要直接使用`cgo`工具为 C 生成头文件，如下面的代码行所示：

```go
go tool cgo goback.go
```

此时，Go 函数可以在您的 C 应用程序中使用：

```go
#include <stdio.h>
#include "_obj/_cgo_export.h"

extern int MyGoFunction(int num);

int main() {

  int result = MyGoFunction(5);
  printf("Output: %d",result);
  return 0;

}
```

请注意，如果导出一个包含多个返回值的 Go 函数，它将在 C 中作为结构体而不是函数可用，因为 C 不提供从函数返回多个变量的功能。

此时，您可能意识到这种功能的真正力量是直接从现有的 C（甚至 C++）应用程序中与 Go 应用程序进行接口交互的能力。

虽然不一定是真正的 API，但现在您可以将 Go 应用程序视为 C 应用程序中的链接库，反之亦然。

关于使用`//export`指令的一个警告：如果这样做，您的 C 代码必须引用这些作为 extern 声明的函数。如您所知，当 C 应用程序需要从另一个链接的 C 文件中调用函数时，会使用 extern。

当以这种方式构建我们的 Go 代码时，cgo 会生成头文件`_cgo_export.h`，就像您之前看到的那样。如果您想查看该代码，它可以帮助您了解 Go 如何将编译的应用程序转换为 C 头文件以供此类用途使用：

```go
/* Created by cgo - DO NOT EDIT. */
#include "_cgo_export.h"

extern void crosscall2(void (*fn)(void *, int), void *, int);

extern void _cgoexp_d133c8d0d35b_MyGoFunction(void *, int);

GoInt64 MyGoFunction(GoInt p0)
{
  struct {
    GoInt p0;
    GoInt64 r0;
  } __attribute__((packed)) a;
  a.p0 = p0;
  crosscall2(_cgoexp_d133c8d0d35b_MyGoFunction, &a, 16);
  return a.r0;
}
```

你可能也会遇到一个罕见的情况，即 C 代码不完全符合你的期望，你无法诱使编译器产生你期望的结果。在这种情况下，你可以在编译 C 应用程序之前自由修改头文件，尽管会有“请勿编辑”的警告。

### 进一步降低 - 在 Go 中进行汇编

如果你可以用 C 射击自己的脚，用 C++炸掉自己的腿，那么想象一下你在 Go 中使用汇编可以做些什么。

在 Go 中直接使用汇编是不可能的，但是由于 Go 直接提供对 C 的访问，而 C 提供了调用内联汇编的能力，你可以间接地在 Go 中使用它。

但同样，仅仅因为某件事是可能的，并不意味着应该这样做——如果你发现自己需要在 Go 中使用汇编，你应该考虑直接使用汇编，并通过 API 连接。

在使用汇编语言（首先是在 C 中，然后是在 Go 中）时，你可能会遇到许多障碍，其中之一就是缺乏可移植性。编写内联 C 是一回事——你的代码应该在处理器指令集和操作系统之间相对可移植——但是汇编显然需要很多具体性。

尽管如此，当你考虑是否需要在 Go 应用程序中直接使用 C 或汇编时，最好还是有自毁的选择，无论你选择射击与否。在考虑是否需要 C 或汇编直接在你的 Go 应用程序中时，一定要非常小心。如果你可以通过 API 或进程间通道在不协调的进程之间进行通信，总是首选这种方式。

在 Go 中（或独立使用或在 C 中）使用汇编的一个非常明显的缺点是，你失去了 Go 提供的交叉编译能力，因此你必须为每个目标 CPU 架构修改你的代码。因此，使用 Go 在 C 中的唯一实际时机是当你的应用程序应该在单个平台上运行时。

这是一个 ASM-in-C-in-Go 应用程序的示例。请记住，我们没有包含 ASM 代码，因为它因处理器类型而异。在以下的`__asm__`部分尝试一些样板汇编：

```go
package main

/*
#include <stdio.h>

void asmCall() {

__asm__( "" );
    printf("I come from a %s","C function with embedded asm\n");

}
*/
import "C"

func main() {

    C.asmCall()

}
```

如果没有其他办法，即使你对汇编和 C 本身都不熟悉，这可能也会为你提供一个深入研究 ASM 的途径。你认为 C 和 Go 越高级，你可能会看到这一点越实际。

对于大多数用途来说，Go（当然还有 C）的层次足够低，可以在不使用汇编的情况下解决任何性能问题。值得再次注意的是，当你调用 C 应用程序时，虽然你失去了对 Go 中内存和指针的一些直接控制，但是在调用汇编时，这个警告适用十倍。Go 提供的所有这些巧妙的工具可能无法可靠地工作，或者根本无法工作。如果你考虑 Go 竞争检测器，可以考虑以下应用程序：

```go
package main

/*
int increment(int i) {
  i++;
  return i;
}
*/
import "C"
import "fmt"

var myNumber int

func main() {
  fmt.Println(myNumber)

  for i:=0;i<100;i++ {
    myNumber = int( C.increment(C.int(myNumber)) )
    fmt.Println(myNumber)
  }

}
```

你可以看到，在 Go 和 C 之间抛来抛去指针可能会让你在程序没有得到你期望的结果时一筹莫展。

请记住，在这里使用 goroutines 与 cgo 有一个有点独特且可能意想不到的地方；它们默认被视为阻塞。这并不是说你不能在 C 中管理并发，但这不会默认发生。相反，Go 可能会启动另一个系统线程。你可以通过利用运行时函数`runtime.LockOSThread()`在一定程度上管理这一点。使用`LockOSThread`告诉 Go 特定的 goroutine 应该留在当前线程中，直到调用`runtime.UnlockOSThread()`之前，没有其他并发的 goroutine 可以使用这个线程。

这取决于直接调用 C 或 C 库的必要性；一些库将愉快地作为新线程被创建，而另一些可能会导致段错误。

### 注意

在你的 Go 代码中，另一个有用的运行时调用是`NumGcoCall()`。它返回当前进程所做的 cgo 调用次数。如果你需要锁定和解锁线程，你也可以使用它来构建一个内部队列报告，以检测和防止死锁。

这并不排除如果您选择在 goroutines 中混合使用 Go 和 C 时可能会发生竞争条件的可能性。

当然，C 本身有一些可用的竞争检测工具。Go 的竞争检测器本身是基于`ThreadSanitizer`库的。毋庸置疑，您可能不希望在单个项目中使用几个完成相同任务的工具。

# 分布式 Go

到目前为止，我们已经谈了很多关于在单个机器内管理数据的内容，尽管有一个或多个核心。这已经足够复杂了。防止竞争条件和死锁本来就很困难，但是当您引入更多的机器（虚拟或真实）时会发生什么？

首先应该想到的是，您可以放弃 Go 提供的许多固有工具，而且在很大程度上是真的。您可以基本上保证 Go 可以处理其自己的、单一的 goroutines 和通道内的数据的内部锁定和解锁，但是如果有一个或多个额外的应用程序实例在运行呢？考虑以下模型：

![分布式 Go](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/ms-cncr-go/img/00018.jpeg)

在这里，我们看到这两个进程中的任何一个线程都可能在任何给定时间点从我们的**关键数据**中读取或写入。考虑到这一点，存在协调对该数据的访问的需要。

在非常高的层面上，有两种直接的策略来处理这个问题，分布式锁或一致性哈希表（一致性哈希）。

第一种策略是互斥的扩展，只是我们没有直接和共享访问相同的地址空间，所以我们需要创建一个抽象。换句话说，我们的工作是设计一个对所有可用的外部实体可见的锁机制。

第二种策略是一种专门设计用于缓存和缓存验证/失效的模式，但它在这里也具有相关性，因为您可以使用它来管理数据在更全局的地址空间中的位置。

然而，当涉及确保这些系统之间的一致性时，我们需要比这种一般的高层方法更深入。

将这个模型一分为二就变得容易了：通道将处理数据和数据结构的并发流动，而在它们不处理的地方，您可以使用互斥锁或低级原子性来添加额外的保障。

然而，看向右边。现在你有另一个 VM/实例或机器试图处理相同的数据。我们如何确保我们不会遇到读者/写者问题？

# 一些常见的一致性模型

幸运的是，我们有一些非核心的 Go 解决方案和策略，可以帮助我们提高控制数据一致性的能力。

让我们简要地看一下我们可以使用的一些一致性模型来管理分布式系统中的数据。

## 分布式共享内存

**分布式共享内存**（**DSM**）系统本身并不固有地防止竞争条件，因为它只是一种多个系统共享实际或分区内存的方法。

实质上，您可以想象两个具有 1GB 内存的系统，每个系统将 500MB 分配给一个可由每个系统访问和写入的共享内存空间。脏读是可能的，竞争条件也是可能的，除非明确设计。以下图表示了两个系统如何使用共享内存进行协调的视觉表示：

![分布式共享内存](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/ms-cncr-go/img/00019.jpeg)

我们很快将看一下 DSM 的一个著名但简单的例子，并使用 Go 可用的库进行测试。

## 先进先出 - PRAM

**流水线 RAM**（**PRAM**）一致性是一种先进先出的方法，其中数据可以按照排队写入的顺序读取。这意味着任何给定的、独立的进程读取的写入可能是不同的。以下图表示了这个概念：

![先进先出 - PRAM](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/ms-cncr-go/img/00020.jpeg)

## 看看主从模型

主从一致性模型与我们即将看到的领导者/追随者模型类似，只是主服务器管理数据和广播的所有操作，而不是从追随者接收写操作。在这种情况下，复制是从主服务器到从服务器传输数据更改的主要方法。在下图中，您将找到一个具有主服务器和四个从服务器的主从模型的表示：

![查看主从模型](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/ms-cncr-go/img/00021.jpeg)

虽然我们可以简单地在 Go 中复制这个模型，但我们有更优雅的解决方案可供选择。

## 生产者-消费者问题

在经典的生产者-消费者问题中，生产者将数据块写入到传送带/缓冲区，而消费者读取数据块。问题出现在缓冲区满时：如果生产者添加到堆栈，读取的数据将不是您想要的。为了避免这种情况，我们使用了带有等待和信号的通道。这个模型看起来有点像下面的图：

![生产者-消费者问题](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/ms-cncr-go/img/00022.jpeg)

如果您正在寻找 Go 中的信号量实现，那么并没有显式使用信号量。但是，想想这里的语言——具有等待和信号的固定大小通道；听起来像是一个缓冲通道。事实上，通过在 Go 中提供一个缓冲通道，您为这里的传送带提供了一个明确的长度；通道机制为您提供了等待和信号的通信。这已经纳入了 Go 的并发模型中。让我们快速看一下下面的代码中所示的生产者-消费者模型。

```go
package main

import(
  "fmt"
)

var comm = make(chan bool)
var done = make(chan bool)

func producer() {
  for i:=0; i< 10; i++ {
    comm <- true
  }
  done <- true
}
func consumer() {
  for {
    communication := <-comm
    fmt.Println("Communication from producer 
      received!",communication)
  }
}

func main() {
  go producer()
  go consumer()
  <- done
  fmt.Println("All Done!")
}
```

## 查看领导者-追随者模型

在领导者/追随者模型中，写操作从单一源广播到任何追随者。写操作可以通过任意数量的追随者传递，也可以限制在单个追随者。任何完成的写操作然后被广播到追随者。这可以在以下图中进行可视化表示：

![查看领导者-追随者模型](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/ms-cncr-go/img/00023.jpeg)

我们在 Go 中也可以看到一个通道的类比。我们可以利用一个单一通道来处理对其他追随者的广播。

## 原子一致性/互斥

我们已经非常详细地研究了原子一致性。它确保任何不是在基本上同时创建和使用的东西都需要串行化，以确保最强形式的一致性。如果一个值或数据集不是原子性的，我们总是可以使用互斥锁来强制对该数据进行线性化。

串行或顺序一致性本质上是强大的，但也可能导致性能问题和并发性的降低。

原子一致性通常被认为是确保一致性的最强形式。

## 发布一致性

发布一致性模型是一种 DSM 变体，可以延迟写操作的修改，直到第一次从读者那里获取。这被称为延迟发布一致性。我们可以在以下序列化模型中可视化延迟发布一致性：

![发布一致性](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/ms-cncr-go/img/00024.jpeg)

这个模型以及急切的发布一致性模型都需要在满足某些条件时宣布发布（正如其名称所示）。在急切模型中，该条件要求写操作将以一致的方式被所有读取进程读取。

在 Go 中，存在替代方案，但如果您有兴趣尝试，也有相关的软件包。

# 使用 memcached

如果您不熟悉 memcache(d)，它是一种管理分布式系统中数据的美妙而显而易见的方式。Go 的内置通道和 goroutines 非常适合管理单台机器进程中的通信和数据完整性，但它们都不是为分布式系统而设计的。

正如其名称所示，Memcached 允许在多个实例或机器之间共享内存数据。最初，memcached 旨在存储数据以便快速检索。这对于具有高周转率的系统（如 Web 应用程序）缓存数据很有用，但也是一种轻松地在多个服务器之间共享数据和利用共享锁机制的好方法。

在我们之前的模型中，memcached 属于 DSM。所有可用和调用的实例在各自的内存中共享一个公共的镜像内存空间。

值得指出的是，memcached 中确实存在竞争条件，你仍然需要一种处理的方法。Memcached 提供了一种在分布式系统中共享数据的方法，但并不保证数据的原子性。相反，memcached 采用以下两种方法之一来使缓存数据失效：

+   数据被明确分配了一个最大年龄（之后，它将从堆栈中删除）

+   或者由于新数据使用了所有可用内存而导致数据从堆栈中被推出

值得注意的是，memcache(d) 中的存储显然是短暂的，而且不具有容错能力，因此它只能在不会导致关键应用程序故障的情况下使用。

在满足这两个条件之一的时候，数据会消失，对该数据的下一次调用将失败，这意味着需要重新生成数据。当然，你可以使用一些复杂的锁生成方法来使 memcached 以一致的方式运行，尽管这不是 memcached 本身的标准内置功能。让我们通过使用 Brad Fitz 的 gomemcache 接口 ([`github.com/bradfitz/gomemcache`](https://github.com/bradfitz/gomemcache)) 在 Go 中快速看一下 memcached 的一个例子：

```go
package main

import (
  "github.com/bradfitz/gomemcache/memcache"
  "fmt"
)

func main() {
     mC := memcache.New("10.0.0.1:11211", "10.0.0.2:11211", 
       "10.0.0.3:11211", "10.0.0.4:11211")
     mC.Set(&memcache.Item{Key: "data", Value: []byte("30") })

     dataItem, err := mc.Get("data")
}
```

正如你可能从前面的例子中注意到的，如果任何这些 memcached 客户端同时写入共享内存，仍然可能存在竞争条件。

关键数据可以存在于任何已连接并同时运行 memcached 的客户端中。

任何客户端也可以在任何时候取消或覆盖数据。

与许多实现不同，你可以通过 memcached 设置一些更复杂的类型，比如结构体，假设它们已经被序列化。这个警告意味着我们在直接共享数据方面受到了一定的限制。显然，我们无法使用指针作为内存位置会因客户端而异。

处理数据一致性的一种方法是设计一个主从系统，其中只有一个节点负责写入，而其他客户端通过键的存在来监听更改。

我们可以利用之前提到的任何其他模型来严格管理这些数据的锁，尽管这可能会变得特别复杂。在下一章中，我们将探讨一些构建分布式互斥系统的方法，但现在，我们简要地看一下另一种选择。

## 电路

最近出现的一个处理分布式并发的第三方库是 Petar Maymounkov 的 Go' circuit。Go' circuit 试图通过为一个或多个远程 goroutine 分配通道来促进分布式协程。

Go' circuit 最酷的部分是，只需包含该包就可以使你的应用程序准备好监听和操作远程 goroutine，并处理与它们相关联的通道。

Go' circuit 在 Tumblr 中使用，这证明它作为一个大规模和相对成熟的解决方案平台具有一定的可行性。

### 注意

Go' circuit 可以在 [`github.com/gocircuit/circuit`](https://github.com/gocircuit/circuit) 找到。

安装 Go' circuit 并不简单——你不能简单地运行 `go get`，它需要 Apache Zookeeper 并且需要从头构建工具包。

一旦完成，就可以相对简单地让两台机器（或者在本地运行时的两个进程）运行 Go 代码来共享一个通道。这个系统中的每个齿轮都属于发送者或监听者类别，就像 goroutines 一样。鉴于我们在这里谈论的是网络资源，语法与一些微小的修改是熟悉的：

```go
homeChannel := make(chan bool)

circuit.Spawn("etphonehome.example.com",func() {
  homeChannel <- true
})

for {
  select {
    case response := <- homeChannel:
      fmt.Print("E.T. has phoned home with:",response)

  }
}
```

您可以看到，这可能会使不同机器之间共享相同数据的通信变得更加清晰，而我们主要使用 memcached 作为网络内存锁定系统。在这里，我们直接处理原生的 Go 代码；我们有能力像在通道中一样使用电路，而不必担心引入新的数据管理或原子性问题。事实上，电路本身就是建立在一个 goroutine 之上的。

当然，这也引入了一些额外的管理问题，主要是关于了解远程机器的情况，它们是否活跃，更新机器的状态等等。这些问题最适合由 Apache Zookeeper 这样的套件来处理分布式资源的协调。值得注意的是，您应该能够从远程机器向主机产生一些反馈：电路通过无密码 SSH 运行。

这也意味着您可能需要确保用户权限被锁定，并且符合您可能已经制定的安全策略。

### 注意

您可以在[`zookeeper.apache.org/`](http://zookeeper.apache.org/)找到 Apache Zookeeper。

# 总结

现在，我们已经掌握了一些方法和模型，不仅可以管理单个或多线程系统中的本地数据，还可以管理分布式系统，您应该开始感到对保护并发和并行进程中数据的有效性相当自信。

我们已经研究了读和读/写锁的两种互斥形式，并开始将其应用于分布式系统，以防止在多个网络系统中出现阻塞和竞争条件。

在下一章中，我们将更深入地探讨这些排除和数据一致性概念，构建非阻塞的网络应用程序，并学习如何处理超时并深入研究通道的并行性。

我们还将更深入地研究 sync 和 OS 包，特别是查看`sync.atomic`操作。


# 第五章：锁，块和更好的通道

现在我们开始对安全和一致地利用 goroutines 有了很好的把握，是时候更深入地了解是什么导致了代码的阻塞和死锁。让我们也探索一下`sync`包，并深入一些分析和分析。

到目前为止，我们已经构建了一些相对基本的 goroutines 和互补的通道，但现在我们需要在 goroutines 之间利用一些更复杂的通信通道。为了做到这一点，我们将实现更多的自定义数据类型，并直接应用它们到通道中。

我们还没有看过 Go 的一些用于同步和分析的低级工具，因此我们将探索`sync.atomic`，这是一个包，它与`sync.Mutex`一起允许更细粒度地控制状态。

最后，我们将深入研究 pprof，这是 Go 提供的一个神奇的工具，它让我们分析我们的二进制文件，以获取有关我们的 goroutines、线程、整体堆和阻塞概况的详细信息。

凭借一些新的工具和方法来测试和分析我们的代码，我们将准备好生成一个强大的，高度可扩展的 Web 服务器，可以安全快速地处理任何数量的流量。

# 了解 Go 中的阻塞方法

到目前为止，通过我们的探索和示例，我们已经遇到了一些阻塞代码的片段，有意的和无意的。在这一点上，看看我们可以引入（或无意中成为）阻塞代码的各种方式是明智的。

通过观察 Go 代码被阻塞的各种方式，我们也可以更好地准备调试并发在我们的应用程序中未按预期运行的情况。

## 阻塞方法 1-一个监听，等待的通道

阻塞代码的最具并发性的方法是通过让一个串行通道监听一个或多个 goroutines。到目前为止，我们已经看到了几次，但基本概念如下代码片段所示：

```go
func thinkAboutKeys() {
  for {
    fmt.Println("Still Thinking")
    time.Sleep(1 * time.Second)
  }
}

func main() {
  fmt.Println("Where did I leave my keys?")

  blockChannel := make(chan int)
  go thinkAboutKeys()

  <-blockChannel

  fmt.Println("OK I found them!")
}
```

尽管我们所有的循环代码都是并发的，但我们正在等待一个信号，以便我们的`blockChannel`继续线性执行。当然，我们可以通过发送通道来看到这一点，从而继续代码执行，如下面的代码片段所示：

```go
func thinkAboutKeys(bC chan int) {
  i := 0
  max := 10
  for {
    if i >= max {
      bC <- 1
    }
    fmt.Println("Still Thinking")
    time.Sleep(1 * time.Second)
    i++
  }
}
```

在这里，我们修改了我们的 goroutine 函数，以接受我们的阻塞通道，并在达到最大值时向其发送结束消息。这些机制对于长时间运行的进程非常重要，因为我们可能需要知道何时以及如何终止它们。

### 通过通道发送更多的数据类型

Go 使用通道（结构和函数）作为一流公民，为我们提供了许多有趣的执行方式，或者至少尝试新的通道之间通信方式的方法。

一个这样的例子是创建一个通过函数本身处理翻译的通道，而不是通过标准语法直接进行通信，通道执行其函数。您甚至可以在单个函数中对它们进行迭代的函数的切片/数组上执行此操作。

#### 创建一个函数通道

到目前为止，我们几乎完全是在单一数据类型和单一值通道中工作。因此，让我们尝试通过通道发送一个函数。有了一流的通道，我们不需要抽象来做到这一点；我们可以直接通过通道发送几乎任何东西，如下面的代码片段所示：

```go
func abstractListener(fxChan chan func() string ) {

  fxChan <- func() string {

    return "Sent!"
  }
}

func main() {

  fxChan := make (chan func() string)
  defer close(fxChan)
  go abstractListener(fxChan)
  select {
    case rfx := <- fxChan:
    msg := rfx()
    fmt.Println(msg)      
    fmt.Println("Received!")

  }

}
```

这就像一个回调函数。然而，它也是本质上不同的，因为它不仅是在函数执行后调用的方法，而且还作为函数之间的通信方式。

请记住，通常有替代方法可以通过通道传递函数，因此这可能是一个非常特定于用例而不是一般实践的东西。

由于通道的类型可以是几乎任何可用类型，这种功能性打开了一系列可能令人困惑的抽象。作为通道类型的结构或接口是相当不言自明的，因为您可以对其定义的任何属性做出与应用程序相关的决策。

让我们在下一节中看一个使用接口的例子。

#### 使用接口通道

与我们的函数通道一样，能够通过通道传递接口（这是一种补充的数据类型）可能非常有用。让我们看一个通过接口发送的例子：

```go
type Messenger interface {
  Relay() string
}

type Message struct {
  status string
}

func (m Message) Relay() string {
  return m.status
}

func alertMessages(v chan Messenger, i int) {
  m := new(Message)
  m.status = "Done with " + strconv.FormatInt(int64(i),10)
  v <- m
}

func main () {

  msg := make(chan Messenger)

  for i:= 0; i < 10; i++ {
    go alertMessages(msg,i)
  }

  select {
    case message := <-msg:
      fmt.Println (message.Relay())
  }
  <- msg
}
```

这是如何利用接口作为通道的一个非常基本的例子；在前面的例子中，接口本身在很大程度上是装饰性的。实际上，我们通过接口的通道传递新创建的消息类型，而不是直接与接口交互。

#### 使用结构体、接口和更复杂的通道

为我们的通道创建一个自定义类型，可以让我们决定我们的通道内部通信的方式，同时让 Go 决定上下文切换和幕后调度。

最终，这主要是一个设计考虑。在前面的例子中，我们使用单独的通道来处理特定的通信片段，而不是使用一个通道来传递大量的数据。然而，您可能还会发现使用单个通道来处理 goroutines 和其他通道之间的大量通信是有利的。

决定是否将通道分隔为单独的通信片段或通信包的主要考虑因素取决于每个通道的总体可变性。

例如，如果您总是想要发送一个计数器以及一个函数或字符串，并且它们在数据一致性方面总是成对出现，这样的方法可能是有意义的。如果其中任何组件在途中失去同步，保持每个片段独立更合乎逻辑。

### 注

**Go 中的映射**

如前所述，Go 中的映射就像其他地方的哈希表，与切片或数组密切相关。

在上一个例子中，我们正在检查用户名/密钥是否已经存在；为此，Go 提供了一个简单的方法。当尝试检索一个不存在的键的哈希时，会返回一个零值，如下面的代码所示：

```go
if Users[user.name] {
  fmt.Fprintln(conn, "Unfortunately, that username is in use!");
}
```

这使得对映射及其键进行语法上的简单和清晰的测试。

Go 中映射的最佳特性之一是能够使用任何可比较类型作为键，包括字符串、整数、布尔值以及任何仅由这些类型组成的映射、结构体、切片或通道。

这种一对多的通道可以作为主从或广播-订阅模型。我们将有一个通道监听消息并将其路由到适当的用户，以及一个通道监听广播消息并将其排队到所有用户。

为了最好地演示这一点，我们将创建一个简单的多用户聊天系统，允许 Twitter 风格的`@user`通信与单个用户，具有向所有用户广播标准消息的能力，并创建一个可以被所有用户阅读的通用广播聊天记录。这两者都将是简单的自定义类型结构体通道，因此我们可以区分各种通信片段。

### 注

**Go 中的结构体**

作为一种一流、匿名和可扩展的类型，结构体是最多才和有用的数据结构之一。它很容易创建类似于数据库和数据存储的模拟，虽然我们不愿称它们为对象，但它们确实可以被视为对象。

就结构体在函数中的使用而言，一个经验法则是，如果结构体特别复杂，应该通过引用而不是值来传递。澄清的两点如下：

+   引用在引号中是因为（这是 Go 的 FAQ 所验证的）从技术上讲，Go 中的一切都是按值传递的。这意味着虽然指针的引用仍然存在，但在过程的某个步骤中，值被复制了。

+   “特别复杂”是可以理解的，所以个人判断可能会起作用。然而，我们可以认为一个简单的结构体最多有五个方法或属性。

你可以把这个想象成一个帮助台系统，虽然在当今，我们不太可能为这样的事情创建一个命令行界面，但是避开 Web 部分让我们忽略了所有与 Go 不相关的客户端代码。

你当然可以拿这样的例子并将其推广到利用一些前端库进行 Web 的异步功能（比如`backbone.js`或`socket.io`）。

为了实现这一点，我们需要创建一个客户端和一个服务器应用程序，并尽量保持每个应用程序尽可能简单。你可以清楚简单地扩展这个功能，包括任何你认为合适的功能，比如进行 Git 评论和更新网站。

我们将从服务器开始，这将是最复杂的部分。客户端应用程序将主要通过套接字接收消息，因此大部分的读取和路由逻辑对于客户端来说是不可见的。

### net 包 - 一个带有接口通道的聊天服务器

在这里，我们需要引入一个相关的包，这个包将被需要来处理我们应用程序的大部分通信。我们在 SVG 输出生成示例中稍微涉及了一下`net`包，以展示并发性 - `net`/`http`只是更广泛、更复杂和更功能丰富的包的一小部分。

我们将使用的基本组件将是 TCP 监听器（服务器）和 TCP 拨号器（客户端）。让我们来看看这些基本设置。

**服务器**

在 TCP 端口上监听不能更简单。只需启动`net.Listen()`方法并处理错误，如下面的代码所示：

```go
  listener, err := net.Listen("tcp", ":9000")
  if err != nil {
    fmt.Println ("Could not start server!")
  }
```

如果启动服务器时出现错误，请检查防火墙或修改端口 - 可能有某些东西正在使用您系统上的端口 9000。

就像这样简单，我们的客户端/拨号器端也是一样简单的。

**客户端**

在这种情况下，我们在 localhost 上运行所有内容，如下面的代码所示。然而，在实际应用中，我们可能会在这里使用一个内部网地址：

```go
  conn, err := net.Dial("tcp","127.0.0.1:9000")
  if err != nil {
    fmt.Println("Could not connect to server!")
  }
```

在这个应用程序中，我们演示了处理未知长度的字节缓冲区的两种不同方法。第一种是使用`strings.TrimRight()`来修剪字符串的相当粗糙的方法。这种方法允许您定义您不感兴趣的字符作为输入的一部分，如下面的代码所示。大多数情况下，这是我们可以假设是缓冲区长度的未使用部分的空白字符。

```go
sendMessage := []byte(cM.name + ": " + 
  strings.TrimRight(string(buf)," \t\r\n"))
```

以这种方式处理字符串通常既不优雅又不可靠。如果我们在这里得到了意料之外的东西会发生什么？字符串将是缓冲区的长度，在这种情况下是 140 个字节。

我们处理这个的另一种方式是直接使用缓冲区的末尾。在这种情况下，我们将`n`变量分配给`conn.Read()`函数，然后可以将其用作字符串到缓冲区转换中的缓冲区长度，如下面的代码所示：

```go
messBuff := make([]byte,1024)
n, err := conn.Read(messBuff)
if err != nil {

}
message := string(messBuff[:n])
```

在这里，我们正在接收消息缓冲区的前`n`个字节。

这更加可靠和高效，但你肯定会遇到文本摄入案例，你会想要删除某些字符以创建更清洁的输入。

这个应用程序中的每个连接都是一个结构，每个用户也是如此。当他们加入时，我们通过将他们推送到`Users`切片来跟踪我们的用户。

所选的用户名是一个命令行参数，如下所示：

```go
./chat-client nathan
chat-client.exe nathan

```

我们不检查以确保只有一个用户使用该名称，因此可能需要该逻辑，特别是如果包含敏感信息的直接消息。

#### 处理直接消息

大多数情况下，这个聊天客户端是一个简单的回声服务器，但正如前面提到的，我们还包括了通过调用 Twitter 风格的`@`语法来进行非全局广播消息的功能。

我们主要通过正则表达式来处理这个问题，如果消息匹配`@user`，那么只有该用户会看到消息；否则，消息将广播给所有人。这有点不够优雅，因为直接消息的发送者如果用户名与用户的预期名称不匹配，将看不到自己的直接消息。

为了做到这一点，我们在广播之前将每条消息都通过`evalMessageRecipient（）`函数。由于这依赖于用户输入来创建正则表达式（以用户名的形式），请注意我们应该使用`regexp.QuoteMeta（）`方法来转义这些内容，以防止正则表达式失败。

让我们首先检查一下我们的聊天服务器，它负责维护所有连接并将它们传递给 goroutine 来监听和接收，如下所示：

```go
chat-server.go
package main

import
(
  "fmt"
  "strings"
  "net"
  "strconv"
  "regexp"
)

var connectionCount int
var messagePool chan(string)

const (
  INPUT_BUFFER_LENGTH = 140
)
```

我们使用了最大字符缓冲区。这将限制我们的聊天消息不超过 140 个字符。让我们看看我们的`User`结构，以了解有关加入用户的信息，如下所示：

```go
type User struct {
  Name string
  ID int
  Initiated bool
```

initiated 变量告诉我们，在连接和公告之后，`User`已连接。让我们检查以下代码，以了解我们如何监听已登录用户的通道：

```go
  UChannel chan []byte
  Connection *net.Conn
}
The User struct contains all of the information we will maintain 
  for each connection. Keep in mind here we don't do any sanity 
  checking to make sure a user doesn't exist – this doesn't 
  necessarily pose a problem in an example, but a real chat client 
  would benefit from a response should a user name already be 
  in use.

func (u *User) Listen() {
  fmt.Println("Listening for",u.Name)
  for {
    select {
      case msg := <- u.UChannel:
        fmt.Println("Sending new message to",u.Name)
        fmt.Fprintln(*u.Connection,string(msg))

    }
  }
}
```

这是我们服务器的核心：每个“用户”都有自己的“Listen（）”方法，该方法维护`User`结构的通道并在其间发送和接收消息。简单地说，每个用户都有自己的并发通道。让我们看一下以下代码中的`ConnectionManager`结构和创建服务器的“Initiate（）”函数：

```go
type ConnectionManager struct {
  name      string
  initiated bool
}

func Initiate() *ConnectionManager {
  cM := &ConnectionManager{
    name:      "Chat Server 1.0",
    initiated: false,
  }

  return cM
}
```

我们的`ConnectionManager`结构只初始化一次。这设置了一些相对装饰的属性，其中一些可以在请求或聊天登录时返回。我们将检查`evalMessageRecipient`函数，该函数试图粗略地确定任何发送的消息的预期接收者，如下所示：

```go
func evalMessageRecipient(msg []byte, uName string) bool {
  eval := true
  expression := "@"
  re, err := regexp.MatchString(expression, string(msg))
  if err != nil {
    fmt.Println("Error:", err)
  }
  if re == true {
    eval = false
    pmExpression := "@" + uName
    pmRe, pmErr := regexp.MatchString(pmExpression, string(msg))
    if pmErr != nil {
      fmt.Println("Regex error", err)
    }
    if pmRe == true {
      eval = true
    }
  }
  return eval
}
```

这是我们的路由器，它从字符串中获取`@`部分，并用它来检测一个预期的接收者，以便隐藏不被公开。如果用户不存在或已离开聊天室，我们不会返回错误。

### 注意

使用`regexp`包的正则表达式格式依赖于`re2`语法，该语法在[`code.google.com/p/re2/wiki/Syntax`](https://code.google.com/p/re2/wiki/Syntax)中有描述。

让我们看一下`ConnectionManager`结构的“Listen（）”方法的代码：

```go
func (cM *ConnectionManager) Listen(listener net.Listener) {
  fmt.Println(cM.name, "Started")
  for {

    conn, err := listener.Accept()
    if err != nil {
      fmt.Println("Connection error", err)
    }
    connectionCount++
    fmt.Println(conn.RemoteAddr(), "connected")
    user := User{Name: "anonymous", ID: 0, Initiated: false}
    Users = append(Users, &user)
    for _, u := range Users {
      fmt.Println("User online", u.Name)
    }
    fmt.Println(connectionCount, "connections active")
    go cM.messageReady(conn, &user)
  }
}

func (cM *ConnectionManager) messageReady(conn net.Conn, user 
  *User) {
  uChan := make(chan []byte)

  for {

    buf := make([]byte, INPUT_BUFFER_LENGTH)
    n, err := conn.Read(buf)
    if err != nil {
      conn.Close()
      conn = nil
    }
    if n == 0 {
      conn.Close()
      conn = nil
    }
    fmt.Println(n, "character message from user", user.Name)
    if user.Initiated == false {
      fmt.Println("New User is", string(buf))
      user.Initiated = true
      user.UChannel = uChan
      user.Name = string(buf[:n])
      user.Connection = &conn
      go user.Listen()

      minusYouCount := strconv.FormatInt(int64(connectionCount-1), 
        10)
      conn.Write([]byte("Welcome to the chat, " + user.Name + ", 
        there are " + minusYouCount + " other users"))

    } else {

      sendMessage := []byte(user.Name + ": " + 
        strings.TrimRight(string(buf), " \t\r\n"))

      for _, u := range Users {
        if evalMessageRecipient(sendMessage, u.Name) == true {
          u.UChannel <- sendMessage
        }

      }

    }

  }
}geReady (per connectionManager) function instantiates new 
  connections into a User struct, utilizing first sent message as 
  the user's name.

var Users []*User
This is our unbuffered array (or slice) of user structs.
func main() {
  connectionCount = 0
  serverClosed := make(chan bool)

  listener, err := net.Listen("tcp", ":9000")
  if err != nil {
    fmt.Println ("Could not start server!",err)
  }

  connManage := Initiate()  
  go connManage.Listen(listener)

  <-serverClosed
}
```

正如预期的那样，`main（）`主要处理连接和错误，并使用`serverClosed`通道保持我们的服务器开放和非阻塞。

我们可以采用许多方法来改进消息路由的方式。第一种方法是调用绑定到用户名的映射（或哈希表）。如果映射的键存在，我们可以返回一些错误功能，如果用户已经存在，如下面的代码片段所示：

```go
type User struct {
  name string
}
var Users map[string] *User

func main() {
  Users := make(map[string] *User)
}
```

## 检查我们的客户端

我们的客户端应用程序相对简单，主要是因为我们不太关心阻塞代码。

虽然我们有两个并发操作（等待消息和等待用户输入以发送消息），但这比我们的服务器要简单得多，后者需要同时监听每个创建的用户并分发发送的消息。

现在让我们将我们的聊天客户端与我们的聊天服务器进行比较。显然，客户端对连接和用户的整体维护要少得多，因此我们不需要使用那么多的通道。让我们看看我们的聊天客户端的代码：

```go
chat-client.go
package main

import
(
  "fmt"
  "net"
  "os"
  "bufio"
  "strings"
)
type Message struct {
  message string
  user string
}

var recvBuffer [140]byte

func listen(conn net.Conn) {
  for {

      messBuff := make([]byte,1024)
      n, err := conn.Read(messBuff)
      if err != nil {
        fmt.Println("Read error",err)
      }
      message := string(messBuff[:n])
      message = message[0:]

      fmt.Println(strings.TrimSpace(message))
      fmt.Print("> ")
  }

}

func talk(conn net.Conn, mS chan Message) {

      for {
      command := bufio.NewReader(os.Stdin)
        fmt.Print("> ")        
                line, err := command.ReadString('\n')

                line = strings.TrimRight(line, " \t\r\n")
        _, err = conn.Write([]byte(line))                       
                if err != nil {
                        conn.Close()
                        break

                }
      doNothing(command)  
        }  

}

func doNothing(bf *bufio.Reader) {
  // A temporary placeholder to address io reader usage

}
func main() {

  messageServer := make(chan Message)

  userName := os.Args[1]

  fmt.Println("Connecting to host as",userName)

  clientClosed := make(chan bool)

  conn, err := net.Dial("tcp","127.0.0.1:9000")
  if err != nil {
    fmt.Println("Could not connect to server!")
  }
  conn.Write([]byte(userName))
  introBuff := make([]byte,1024)    
  n, err := conn.Read(introBuff)
  if err != nil {

  }
  message := string(introBuff[:n])  
  fmt.Println(message)

  go talk(conn,messageServer)
  go listen(conn)

  <- clientClosed
}
```

## 阻塞方法 2-循环中的 select 语句

您是否已经注意到`select`语句本身会阻塞？从根本上讲，`select`语句与开放的监听通道没有什么不同；它只是包装在条件代码中。

`<- myChannel`通道的操作方式与以下代码片段相同：

```go
select {
  case mc := <- myChannel:
    // do something
}
```

开放的监听通道只要没有 goroutine 在睡眠，就不会造成死锁。您会发现这种情况发生在那些正在监听但永远不会接收任何东西的通道上，这是另一种基本上在等待的方法。

这些对于长时间运行的应用程序是有用的快捷方式，你希望保持其活动状态，但你可能不一定需要沿着通道发送任何东西。

# 清理 goroutines

任何等待和/或接收的通道都会导致死锁。幸运的是，Go 在识别这些方面相当擅长，当运行或构建应用程序时，你几乎肯定会陷入恐慌。

到目前为止，我们的许多示例都利用了立即和清晰地将相似的代码组合在一起的延迟`close()`方法，这些代码应该在不同的时间点执行。

尽管垃圾回收处理了大部分的清理工作，但我们大部分时间需要确保关闭通道，以确保我们没有一个等待接收和/或等待发送的进程，两者同时等待对方。幸运的是，我们将无法编译任何具有可检测死锁条件的程序，但我们也需要管理关闭等待的通道。

到目前为止，相当多的示例都以一个通用的整数或布尔通道结束，它只是等待——这几乎完全是为了通道的阻塞效果，这样可以在应用程序仍在运行时演示并发代码的效果和输出。在许多情况下，这种通用通道是不必要的语法垃圾，如下面的代码所示：

```go
<-youMayNotNeedToDoThis
close(youmayNotNeedToDoThis)
```

没有赋值发生的事实是一个很好的指示，表明这是这种语法垃圾的一个例子。如果我们改为包括一个赋值，前面的代码将改为以下代码：

```go
v := <-youMayNotNeedToDoThis
```

这可能表明该值是有用的，而不仅仅是任意的阻塞代码。

## 阻塞方法 3 – 网络连接和读取

如果你在没有启动服务器的情况下运行我们之前的聊天服务器客户端的代码，你会注意到`Dial`函数会阻塞任何后续的 goroutine。我们可以通过在连接上施加比正常更长的超时，或者在登录后简单地关闭客户端应用程序来测试这一点，因为我们没有实现关闭 TCP 连接的方法。

由于我们用于连接的网络读取器是缓冲的，所以在通过 TCP 等待数据时，我们将始终具有阻塞机制。

# 创建通道的通道

管理并发和状态的首选和授权方式是完全通过通道进行。

我们已经演示了一些更复杂类型的通道，但我们还没有看到可能成为令人生畏但强大的实现的东西：通道的通道。这起初可能听起来像一些难以管理的虫洞，但在某些情况下，我们希望一个并发动作生成更多的并发动作；因此，我们的 goroutines 应该能够产生自己的。

一如既往，你通过设计来管理这一切，而实际的代码可能只是一个美学副产品。这种方式构建应用程序应该会使你的代码大部分时间更加简洁和清晰。

让我们重新访问之前的一个 RSS 订阅阅读器的示例，以演示我们如何管理这一点，如下面的代码所示：

```go
package main

import (
 "fmt"
)

type master chan Item

var feedChannel chan master
var done chan bool

type Item struct {
 Url  string
 Data []byte
}
type Feed struct {
 Url   string
 Name  string
 Items []Item
}

var Feeds []Feed

func process(feedChannel *chan master, done *chan bool) {
 for _, i := range Feeds {
  fmt.Println("feed", i)
  item := Item{}
  item.Url = i.Url
  itemChannel := make(chan Item)
  *feedChannel <- itemChannel
  itemChannel <- item
 }
 *done <- true
}
func processItem(url string) {
 // deal with individual feed items here
 fmt.Println("Got url", url)
}

func main() {
 done := make(chan bool)
 Feeds = []Feed{Feed{Name: "New York Times", Url: "http://rss.nytimes.com/services/xml/rss/nyt/HomePage.xml"},
  Feed{Name: "Wall Street Journal", Url: "http://feeds.wsjonline.com/wsj/xml/rss/3_7011.xml"}}
 feedChannel := make(chan master)
 go func(done chan bool, feedChannel chan master) {
  for {
   select {
   case fc := <-feedChannel:
    select {
    case item := <-fc:
     processItem(item.Url)
    }
   default:
   }
  }
 }(done, feedChannel)
 go process(&feedChannel, &done)
 <-done
 fmt.Println("Done!")
}
```

在这里，我们将`feedChannel`管理为一个自定义结构，它本身是我们`Item`类型的通道。这使我们能够完全依赖通道进行同步，通过类似信号量的构造处理。

如果我们想看看另一种处理低级同步的方法，`sync.atomic`提供了一些简单的迭代模式，允许你直接在内存中管理同步。

根据 Go 的文档，这些操作需要非常小心，并且容易出现数据一致性错误，但如果你需要直接操作内存，这就是做到这一点的方法。当我们谈论高级并发特性时，我们将直接使用这个包。

# Pprof – 又一个令人敬畏的工具

就在你以为你已经看到了 Go 令人惊叹的工具集的全部范围时，总会有一个更多的实用程序，一旦你意识到它的存在，你会想知道你以前是如何生存下来的。

Go 格式非常适合清理您的代码；`-race`标志对于检测可能的竞争条件至关重要，但是还存在一个更健壮的、更实用的工具，用于分析您的最终应用程序，那就是 pprof。

Google 最初创建 pprof 来分析 C++应用程序的循环结构和内存分配（以及相关类型）。

如果您认为性能问题没有被 Go 运行时提供的测试工具发现，这将非常有用。这也是生成任何应用程序中数据结构的可视化表示的绝佳方式。

其中一些功能也作为 Go 测试包及其基准测试工具的一部分存在-我们将在第七章中更多地探讨这一点，*性能和可伸缩性*。

使 pprof 运行时版本起作用需要先进行一些设置。我们需要包括`runtime.pprof`包和`flag`包，它允许命令行解析（在这种情况下，用于 pprof 的输出）。

如果我们拿我们的聊天服务器代码来说，我们可以添加几行代码，使应用程序准备好进行性能分析。

让我们确保我们将这两个包与其他包一起包含。我们可以使用下划线语法来告诉编译器我们只对包的副作用感兴趣（这意味着我们获得包的初始化函数和全局变量），如下面的代码所示：

```go
import
(
  "fmt"
...
  _ "runtime/pprof"
)
```

这告诉我们的应用程序生成一个 CPU 分析器（如果不存在），在执行开始时开始分析，并在应用程序成功退出时推迟分析的结束。

有了这个，我们可以使用`cpuprofile`标志运行我们的二进制文件，告诉程序生成一个配置文件，如下所示：

```go
./chat-server -cpuprofile=chat.prof
```

为了多样化（并任意地利用更多资源），我们将暂时放弃聊天服务器，并在退出之前创建一个循环生成大量的 goroutines。这应该给我们一个比简单而长期的聊天服务器更激动人心的性能分析数据演示，尽管我们会简要地回到那个话题：

这是我们的示例代码，它生成了更详细和有趣的性能分析数据：

```go
package main

import (
  "flag"
  "fmt"
  "math/rand"
  "os"
  "runtime"
  "runtime/pprof"
)

const ITERATIONS = 99999
const STRINGLENGTH = 300

var profile = flag.String("cpuprofile", "", "output pprof data to 
  file")

func generateString(length int, seed *rand.Rand, chHater chan 
  string) string {
  bytes := make([]byte, length)
  for i := 0; i < length; i++ {
    bytes[i] = byte(rand.Int())
  }
  chHater <- string(bytes[:length])
  return string(bytes[:length])
}

func generateChannel() <-chan int {
  ch := make(chan int)
  return ch
}

func main() {

  goodbye := make(chan bool, ITERATIONS)
  channelThatHatesLetters := make(chan string)

  runtime.GOMAXPROCS(2)
  flag.Parse()
  if *profile != "" {
    flag, err := os.Create(*profile)
    if err != nil {
      fmt.Println("Could not create profile", err)
    }
    pprof.StartCPUProfile(flag)
    defer pprof.StopCPUProfile()

  }
  seed := rand.New(rand.NewSource(19))

  initString := ""

  for i := 0; i < ITERATIONS; i++ {
    go func() {
      initString = generateString(STRINGLENGTH, seed, 
        channelThatHatesLetters)
      goodbye <- true
    }()

  }
  select {
  case <-channelThatHatesLetters:

  }
  <-goodbye

  fmt.Println(initString)

}
```

当我们从中生成一个配置文件时，我们可以运行以下命令：

```go
go tool pprof chat-server chat-server.prof 

```

这将启动 pprof 应用程序本身。这给了我们一些命令，报告静态生成的文件，如下所示：

+   `topN`：这显示配置文件中的前*N*个样本，其中*N*表示您想要查看的显式数字。

+   `web`：这将创建数据的可视化，将其导出为 SVG，并在 Web 浏览器中打开。要获得 SVG 输出，您还需要安装 Graphviz（[`www.graphviz.org/`](http://www.graphviz.org/)）。

### 注意

您还可以直接运行 pprof 并使用一些标志以多种格式输出，或者启动浏览器，如下所示：

+   `--text`：这将生成文本报告

+   `--web`：这将生成 SVG 并在浏览器中打开

+   `--gv`：这将生成 Ghostview 后置文件

+   `--pdf`：这将生成 PDF 输出

+   `--SVG`：这将生成 SVG 输出

+   `--gif`：这将生成 GIF 输出

命令行结果将足够说明问题，但是以描述性的、可视化的方式呈现应用程序的阻塞配置文件尤其有趣，如下图所示。当您在 pprof 工具中时，只需输入`web`，浏览器将以 SVG 形式显示 CPU 分析的详细信息。 

![Pprof-又一个令人惊叹的工具](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/ms-cncr-go/img/00025.jpeg)

这里的想法不是关于文本，而是关于复杂性

哇，我们突然对程序如何利用 CPU 时间消耗以及我们的应用程序执行、循环和退出的一般视图有了深入了解。

典型的 Go 风格，pprof 工具也存在于`net`/`http`包中，尽管它更注重数据而不是可视化。这意味着，您可以将结果直接输出到 Web 进行分析，而不仅仅是处理命令行工具。

与命令行工具一样，您将看到块、goroutine、堆和线程配置文件，以及通过 localhost 直接查看完整堆栈轮廓，如下面的屏幕截图所示：

![Pprof – yet another awesome tool](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/ms-cncr-go/img/00026.jpeg)

要生成此服务器，您只需在应用程序中包含几行关键代码，构建它，然后运行它。在本例中，我们已经在我们的聊天服务器应用程序中包含了代码，这使我们可以在原本只能在命令行中使用的应用程序中获得 Web 视图。

确保包括`net`/`http`和`log`包。您还需要`http`/`pprof`包。代码片段如下：

```go
import(_(_ 
  "net/http/pprof"
  "log"
  "net/http"
)
```

然后只需在应用程序的某个地方包含此代码，最好是在`main()`函数的顶部附近，如下所示：

```go
  go func() {
    log.Println(http.ListenAndServe("localhost:6060", nil))
  }()
```

与往常一样，端口完全是个人偏好的问题。

然后，您可以在`localhost:6060`找到许多配置工具，包括以下内容：

+   所有工具都可以在`http://localhost:6060/debug/pprof/`找到

+   阻塞配置文件可以在`http://localhost:6060/debug/pprof/block?debug=1`找到

+   所有 goroutine 的配置文件可以在`http://localhost:6060/debug/pprof/goroutine?debug=1`找到

+   堆的详细配置文件可以在`http://localhost:6060/debug/pprof/heap?debug=1`找到

+   线程创建的配置文件可以在`http://localhost:6060/debug/pprof/threadcreate?debug=1`找到

除了阻塞配置文件外，您还可以通过线程创建配置文件找到并发策略中的低效性。如果发现创建的线程数量异常，可以尝试调整同步结构和运行时参数以优化。

请记住，使用 pprof 这种方式也会包括一些分析和配置文件，这些可以归因于`http`或`pprof`包，而不是您的核心代码。您会发现某些明显不属于您应用程序的行；例如，我们的聊天服务器的线程创建分析包括一些显著的行，如下所示：

```go
#       0x7765e         net/http.HandlerFunc.ServeHTTP+0x3e     /usr/local/go/src/pkg/net/http/server.go:1149
#       0x7896d         net/http.(*ServeMux).ServeHTTP+0x11d /usr/local/go/src/pkg/net/http/server.go:1416
```

考虑到我们在这个迭代中明确避免通过 HTTP 或网络套接字传递我们的聊天应用程序，这应该是相当明显的。

除此之外，还有更明显的迹象，如下所示：

```go
#       0x139541        runtime/pprof.writeHeap+0x731           /usr/local/go/src/pkg/runtime/pprof/pprof.go:447
#       0x137aa2        runtime/pprof.(*Profile).WriteTo+0xb2   /usr/local/go/src/pkg/runtime/pprof/pprof.go:229
#       0x9f55f         net/http/pprof.handler.ServeHTTP+0x23f  /usr/local/go/src/pkg/net/http/pprof/pprof.go:165
#       0x9f6a5         net/http/pprof.Index+0x135              /usr/local/go/src/pkg/net/http/pprof/pprof.go:177
```

我们永远无法从最终编译的二进制文件中减少一些系统和 Go 核心机制，如下所示：

```go
#       0x18d96 runtime.starttheworld+0x126 
  /usr/local/go/src/pkg/runtime/proc.c:451
```

### 注意

十六进制值表示运行时函数在内存中的地址。

### 提示

对于 Windows 用户：在*nix 环境中使用 pprof 非常简单，但在 Windows 下可能需要一些更费力的调整。具体来说，您可能需要一个类似 Cygwin 的 bash 替代工具。您可能还需要对 pprof 本身（实际上是一个 Perl 脚本）进行一些必要的调整。对于 64 位 Windows 用户，请确保安装 ActivePerl，并使用 Perl 的 64 位版本直接执行 pprof Perl 脚本。

在发布时，在 64 位 OSX 上也存在一些问题。

# 处理死锁和错误

每当在代码编译时遇到死锁错误时，您将看到熟悉的一串半加密的错误，解释了哪个 goroutine 被留下来处理问题。

但请记住，您始终可以使用 Go 的内置 panic 来触发自己的 panic，这对于构建自己的错误捕获保障以确保数据一致性和理想操作非常有用。代码如下：

```go
package main

import
(
  "os"
)

func main() {
  panic("Oh No, we forgot to write a program!")
  os.Exit(1)
}
```

这可以在任何您希望向开发人员或最终用户提供详细退出信息的地方使用。

# 总结

在探索了一些检查 Go 代码阻塞和死锁的新方法之后，我们现在还有一些工具可供使用，用于检查 CPU 配置文件和资源使用情况。

希望到这一点，你可以用简单的 goroutines 和通道构建一些复杂的并发系统，一直到结构体、接口和其他通道的复用通道。

到目前为止，我们已经构建了一些功能上比较完善的应用程序，但接下来我们将利用我们所做的一切来构建一个可用的 Web 服务器，解决一个经典问题，并可用于设计内部网络、文件存储系统等。

在下一章中，我们将把我们在本章中所做的关于可扩展通道的工作应用到解决互联网所面临的最古老的挑战之一：同时为 10,000（或更多）个连接提供服务。


# 第六章：在 Go 中创建一个非阻塞 Web 服务器

到目前为止，我们已经构建了一些可用的应用程序；我们可以从中开始，并跃入到日常使用的真实系统中。通过这样做，我们能够展示 Go 并发语法和方法中涉及的基本和中级模式。

然而，现在是时候解决一个真实世界的问题了——这个问题困扰了开发人员（以及他们的经理和副总裁）在 Web 的早期历史中很长一段时间。

通过解决这个问题，我们将能够开发一个高性能的 Web 服务器，可以处理大量的实时活跃流量。

多年来，解决这个问题的唯一方法是向问题投入硬件或侵入式缓存系统；因此，用编程方法解决它应该会激发任何程序员的兴趣。

我们将使用到目前为止学到的每一种技术和语言构造，但我们将以比以前更有条理和有意识的方式来做。到目前为止，我们所探讨的一切都将发挥作用，包括以下几点：

+   创建我们并发应用的可视化表示

+   利用 goroutine 来处理请求，以实现可扩展性

+   构建健壮的通道来管理 goroutine 之间的通信和管理它们的循环

+   使用性能分析和基准测试工具（JMeter、ab）来检查我们的事件循环的实际工作方式

+   在必要时设置超时和并发控制，以确保数据和请求的一致性

# 攻克 C10K 问题

C10K 问题的起源根植于串行、阻塞式编程，这使得它成为展示并发编程优势的理想选择，特别是在 Go 语言中。

这个问题的提出者是开发者丹·凯格尔，他曾经问过：

| *是时候让 Web 服务器同时处理一万个客户端了，你不觉得吗？毕竟，现在的网络是一个很大的地方。* | |
| --- | --- |
| --*丹·凯格尔（[`www.kegel.com/c10k.html`](http://www.kegel.com/c10k.html）* |

当他在 1999 年提出这个问题时，对于许多服务器管理员和工程师来说，为 10,000 个并发访问者提供服务是需要通过硬件解决的问题。在常见硬件上，单个服务器能够处理这种类型的 CPU 和网络带宽而不会崩溃的想法对大多数人来说似乎是陌生的。

他提出的解决方案的关键在于生成非阻塞代码。当然，在 1999 年，并发模式和库并不普遍。C++通过一些第三方库和后来通过 Boost 和 C++11 提供的最早的多线程语法的前身，有一些轮询和排队选项。

在接下来的几年里，针对这个问题的解决方案开始涌现，涵盖了各种语言、编程设计和一般方法。在撰写本书时，C10K 问题并非没有解决方案，但它仍然是一个非常适合在高性能 Go 中进行真实世界挑战的平台。

任何性能和可伸缩性问题最终都将受限于底层硬件，因此，结果可能因人而异。在 486 处理器和 500MB RAM 上实现 10,000 个并发连接肯定比在堆满内存和多核的 Linux 服务器上实现更具挑战性。

值得注意的是，一个简单的回显服务器显然能够承担比返回更多数据并接受更复杂请求、会话等的功能性 Web 服务器更多的核心，正如我们将在这里处理的那样。

## 服务器在 10,000 个并发连接时失败

正如你可能还记得的，当我们在第三章中讨论并发策略时，我们谈到了一些关于 Apache 及其负载均衡工具的内容。

当 Web 诞生并且互联网商业化时，互动水平相当低。如果你是一个老手，你可能还记得从 NNTP/IRC 等的转变以及 Web 的极其原始的情况。

为了解决[页面请求]→[HTTP 响应]的基本命题，20 世纪 90 年代早期对 Web 服务器的要求相当宽松。忽略所有的错误响应、头部读取和设置以及其他基本功能（但与输入输出机制无关），早期服务器的本质相当简单，至少与现代 Web 服务器相比是如此。

### 注意

第一个 Web 服务器是由 Web 之父蒂姆·伯纳斯-李开发的。

由 CERN（例如 WWW/HTTP 本身）开发的 CERN httpd 处理了许多你今天在 Web 服务器中所期望的事情——在代码中搜索，你会发现很多注释，这些注释会让你想起 HTTP 协议的核心基本上没有改变。与大多数技术不同，HTTP 的寿命非常长。

1990 年用 C 语言编写的服务器无法利用 Erlang 等语言中可用的许多并发策略。坦率地说，这样做可能是不必要的——大多数的 Web 流量都是基本的文件检索和协议问题。Web 服务器的核心问题不是处理流量，而是处理协议本身的规则。

你仍然可以访问原始的 CERN httpd 网站，并从[`www.w3.org/Daemon/`](http://www.w3.org/Daemon/)下载源代码。我强烈建议你这样做，既可以作为历史课程，也可以看看最早的 Web 服务器是如何解决最早的问题的。

然而，1990 年的 Web 和首次提出 C10K 问题时的 Web 是两个非常不同的环境。

到 1999 年，大多数网站都有一定程度的由第三方软件、CGI、数据库等提供的次要或第三级延迟，所有这些都进一步复杂化了问题。同时并发地提供 10,000 个平面文件的概念本身就是一个挑战，但是如果通过在 Perl 脚本的基础上运行它们来访问 MySQL 数据库而没有任何缓存层，这个挑战就会立即加剧。

到了 20 世纪 90 年代中期，Apache Web 服务器已经占据主导地位，并在很大程度上控制了市场（到 2009 年，它成为第一个为超过 1 亿个网站提供服务的服务器软件）。

Apache 的方法深深扎根于互联网的早期。在推出时，连接最初是先进先出处理的。很快，每个连接都被分配了一个线程池中的线程。Apache 服务器存在两个问题。它们如下：

+   阻塞连接可能导致多米诺效应，其中一个或多个慢速解析的连接可能会导致无法访问

+   Apache 对可以利用的线程/工作者数量有严格的限制，与硬件约束无关

至少从回顾的角度来看，这里很容易看到机会。一个利用 actors（Erlang）、agents（Clojure）或 goroutines（Go）的并发服务器似乎完全符合要求。并发本身并不能解决 C10k 问题，但它绝对提供了一种促进解决的方法。

今天解决 C10K 问题的最显著和可见的例子是 Nginx，它是使用并发模式开发的，到 2002 年在 C 语言中广泛可用，用于解决 C10K 问题。如今，Nginx 代表着世界上第二或第三大的 Web 服务器，这取决于来源。

## 使用并发攻击 C10K

处理大量并发请求的两种主要方法。第一种方法涉及为每个连接分配线程。这就是 Apache（和其他一些服务器）所做的。

一方面，为连接分配一个线程是有很多道理的——它是隔离的，可以通过应用程序和内核的上下文切换进行控制，并且可以随着硬件的增加而扩展。

对于 Linux 服务器来说，这是一个问题——大多数 Web 都是在 Linux 服务器上运行的，每个分配的线程默认保留 8 MB 的内存用于其堆栈。这可以（也应该）重新定义，但这会导致需要大量的内存来处理单个服务器的开销，即使将默认堆栈大小设置为 1 MB，我们也需要至少 10 GB 的内存来处理开销。

这是一个极端的例子，由于几个原因，这不太可能成为一个真正的问题：首先，因为您可以规定每个线程可用的最大资源量，其次，因为您可以很容易地在几台服务器和实例之间进行负载平衡，而不是增加 10 GB 到 80 GB 的 RAM。

即使在一个线程服务器环境中，我们基本上也受到可能导致性能下降（甚至崩溃）的问题的限制。

首先，让我们看一个连接绑定到线程的服务器（如下图所示），并想象一下这如何导致阻塞，最终导致崩溃：

![使用并发攻击 C10K](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/ms-cncr-go/img/00027.jpeg)

这显然是我们要避免的。任何 I/O、网络或外部进程都可能导致一些减速，从而引发我们所说的雪崩效应，使我们可用的线程被占用（或积压），而传入的请求开始堆积起来。

在这种模型中，我们可以生成更多的线程，但正如前面提到的，这里也存在潜在的风险，甚至这也无法减轻潜在的问题。

## 采取另一种方法

为了创建一个可以处理 10,000 个并发连接的网络服务器，我们显然会利用我们的 goroutine/channel 机制，将一个事件循环放在我们的内容交付前面，以保持新通道不断回收或创建。

在这个例子中，我们假设我们正在为一个快速扩张的公司构建企业网站和基础设施。为了做到这一点，我们需要能够提供静态和动态内容。

我们希望引入动态内容的原因不仅仅是为了演示的目的——我们想挑战自己，展示即使在次要进程干扰的情况下，也能展示 10,000 个真正的并发连接。

与往常一样，我们将尝试将我们的并发策略直接映射到 goroutines 和通道。在许多其他语言和应用程序中，这与事件循环直接类似，我们将以此方式处理。在我们的循环中，我们将管理可用的 goroutines，过期或重用已完成的 goroutines，并在必要时生成新的 goroutines。

在这个示例可视化中，我们展示了一个事件循环（和相应的 goroutines）如何使我们能够扩展我们的连接，而不需要使用太多*硬*资源，比如 CPU 线程或 RAM：

![采取另一种方法](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/ms-cncr-go/img/00028.jpeg)

对我们来说，这里最重要的一步是管理事件循环。我们希望创建一个开放的、无限循环来管理我们的 goroutines 和各自的通道的创建和过期。

作为这一过程的一部分，我们还希望对所发生的情况进行一些内部记录，既用于基准测试，也用于调试我们的应用程序。

# 构建我们的 C10K 网络服务器

我们的网络服务器将负责处理请求，路由它们，并提供平面文件或针对几种不同数据源解析模板的动态文件。

正如前面提到的，如果我们只提供平面文件并消除大部分处理和网络延迟，那么处理 10,000 个并发连接将会更容易。

我们的目标是尽可能接近真实世界的情景——很少有网站在一个静态的服务器上运行。大多数网站和应用程序都利用数据库、CDN（内容交付网络）、动态和未缓存的模板解析等。我们需要尽可能地复制它们。

为了简单起见，我们将按类型分隔我们的内容，并通过 URL 路由进行过滤，如下所示：

+   `/static/[request]`：这将直接提供`request.html`

+   `/template/[request]`：这将在通过 Go 解析后提供`request.tpl`

+   `/dynamic/[request][number]`：这也将提供`request.tpl`并对其进行数据库源记录的解析

通过这样做，我们应该能够更好地混合可能阻碍大量用户同时服务能力的 HTTP 请求类型，特别是在阻塞的 Web 服务器环境中。

我们将利用`html/template`包进行解析——我们之前简要地看过语法，深入了解并不一定是本书的目标。但是，如果您打算将这个示例转化为您在环境中使用的内容，或者对构建框架感兴趣，您应该研究一下。

### 提示

您可以在[`golang.org/pkg/html/template/`](http://golang.org/pkg/html/template/)找到 Go 出色的库，用于生成安全的数据驱动模板。

所谓安全，我们主要是指接受数据并将其直接移入模板，而不必担心大量恶意软件和跨站脚本背后的注入问题。

对于数据库源，我们将在这里使用 MySQL，但如果您更熟悉其他数据库，可以随意尝试。与`html/template`包一样，我们不打算花费太多时间来概述 MySQL 和/或其变体。

## 针对阻塞 Web 服务器的基准测试

首先，公平地对阻塞 Web 服务器进行一些起始基准测试，以便我们可以衡量并发与非并发架构的影响。

对于我们的起始基准测试，我们将放弃任何框架，而选择我们的老朋友 Apache。

为了完整起见，我们将使用一台 Intel i5 3GHz 的机器，配备 8GB 的 RAM。虽然我们将在 Ubuntu、Windows 和 OS X 上对我们的最终产品进行基准测试，但我们将以 Ubuntu 为例。

我们的本地域将在`/static`中有三个普通的 HTML 文件，每个文件都被裁剪为 80KB。由于我们不使用框架，我们不需要担心原始动态请求，而只需要关注静态和动态请求，以及数据源请求。

对于所有示例，我们将使用一个名为`master`的 MySQL 数据库，其中包含一个名为`articles`的表，其中将包含 10,000 个重复条目。我们的结构如下：

```go
CREATE TABLE articles (
  article_id INT NOT NULL AUTO_INCREMENT,
  article_title VARCHAR(128) NOT NULL,
  article_text VARCHAR(128) NOT NULL,
  PRIMARY KEY (article_id)
)
```

通过顺序范围从 0 到 10,000 的 ID 索引，我们将能够生成随机数请求，但目前，我们只想看看 Apache 在这台机器上提供静态页面时能得到什么样的基本响应。

对于这个测试，我们将使用 Apache 的 ab 工具，然后使用 gnuplot 来顺序映射请求时间作为并发请求和页面的数量；我们也将为我们的最终产品做同样的测试，但我们还将使用一些其他基准测试工具来获得更好的细节。

### 注意

Apache 的 AB 随 Apache Web 服务器本身提供。您可以在[`httpd.apache.org/docs/2.2/programs/ab.html`](http://httpd.apache.org/docs/2.2/programs/ab.html)了解更多信息。

您可以从[`httpd.apache.org/download.cgi`](http://httpd.apache.org/download.cgi)下载它的 Linux、Windows、OS X 等版本。

gnuplot 实用程序也适用于相同的操作系统，网址是[`www.gnuplot.info/`](http://www.gnuplot.info/)。

所以，让我们看看我们是如何做到的。看一下下面的图表：

![针对阻塞 Web 服务器的基准测试](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/ms-cncr-go/img/00029.jpeg)

哎呀！差距太大了。我们可以调整 Apache 中可用的连接（以及相应的线程/工作者），但这并不是我们的目标。大多数情况下，我们想知道开箱即用的 Apache 服务器会发生什么。在这些基准测试中，我们开始在大约 800 个并发连接时丢弃或拒绝连接。

更令人担忧的是，随着这些请求开始堆积，我们看到一些请求超过 20 秒甚至更长时间。当这种情况发生在阻塞服务器中时，每个请求都会排队；在其后排队的请求也会类似地排队，整个系统开始崩溃。

即使我们无法处理 10,000 个并发连接，仍然有很大的改进空间。虽然单个服务器的容量不再是我们期望设计为 Web 服务器环境的方式，但能够尽可能地从该服务器中挤取性能，基本上是我们并发、事件驱动方法的目标。

## 处理请求

在早期的章节中，我们使用 Gorilla 处理 URL 路由，这是一个紧凑但功能丰富的框架。Gorilla 工具包确实使这变得更容易，但我们也应该知道如何拦截功能以强加我们自己的自定义处理程序。

这是一个简单的 Web 路由器，我们在其中使用自定义的`http.Server`结构处理和指导请求，如下面的代码所示：

```go
var routes []string

type customRouter struct {

}

func (customRouter) ServeHTTP(rw http.ResponseWriter, r 
  *http.Request) {

  fmt.Println(r.URL.Path);
}

func main() {

  var cr customRouter;

  server := &http.Server {
      Addr: ":9000",
      Handler:cr,
      ReadTimeout: 10 * time.Second,
      WriteTimeout: 10 * time.Second,
      MaxHeaderBytes: 1 << 20,
  }

  server.ListenAndServe()
}
```

在这里，我们不是使用内置的 URL 路由 muxer 和分发器，而是创建了一个自定义服务器和自定义处理程序类型来接受 URL 并路由请求。这使我们在处理 URL 时更加强大。

在这种情况下，我们创建了一个名为`customRouter`的基本空结构，并将其传递给我们的自定义服务器创建调用。

我们可以向我们的`customRouter`类型添加更多元素，但是对于这个简单的示例，我们实际上不需要这样做。我们所需要做的就是能够访问 URL 并将它们传递给处理程序函数。我们将有三个：一个用于静态内容，一个用于动态内容，一个用于来自数据库的动态内容。

不过，在我们走得太远之前，我们应该看看我们用 Go 编写的绝对基本的 HTTP 服务器在面对我们向 Apache 发送的相同流量时会做些什么。

老派的意思是服务器只会接受请求并传递静态的平面文件。您可以使用自定义路由器来做到这一点，就像我们之前做的那样，接受请求，打开文件，然后提供它们，但是 Go 提供了一种更简单的方式来处理`http.FileServer`方法中的基本任务。

因此，为了获得 Go 服务器的最基本性能与 Apache 的基准，我们将利用一个简单的 FileServer，并将其与`test.html`页面进行测试（其中包含与 Apache 相同的 80 KB 文件）。

### 注意

由于我们的目标是提高提供平面和动态页面的性能，因此测试套件的实际规格有些不重要。我们期望，尽管度量标准在不同环境中不会匹配，但我们应该看到类似的轨迹。也就是说，我们应该提供这些测试所使用的环境；在这种情况下，我们使用了一台配备 1.4 GHz i5 处理器和 4 GB 内存的 MacBook Air。

首先，我们将使用 Apache 的最佳性能，它具有 850 个并发连接和 900 个总请求。

![处理请求](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/ms-cncr-go/img/00030.jpeg)

与 Apache 相比，结果确实令人鼓舞。我们的两个测试系统都没有进行太多调整（Apache 安装和 Go 中的基本 FileServer），但 Go 的 FileServer 可以处理 1,000 个并发连接，而没有任何问题，最慢的时钟速度为 411 毫秒。

### 提示

在过去的五年中，Apache 在并发性和性能选项方面取得了很大进展，但要达到这一点需要进行一些调整和测试。这个实验的目的并不是贬低经过充分测试和建立的世界第一 Web 服务器 Apache，而是要将其与我们在 Go 中所能做的进行比较。

为了真正了解我们在 Go 中可以实现的基准，让我们看看 Go 的 FileServer 是否可以在单个普通机器上轻松处理 10,000 个连接：

```go
ab -n 10500 -c 10000 -g test.csv http://localhost:8080/a.html
```

我们将得到以下输出：

![处理请求](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/ms-cncr-go/img/00031.jpeg)

成功！Go 的 FileServer 本身将轻松处理 10,000 个并发连接，提供平面的静态内容。

当然，这不是这个特定项目的目标——我们将实现诸如模板解析和数据库访问等真实世界的障碍，但这本身就应该向您展示 Go 为需要处理大量基本网络流量的响应服务器提供的起点。

## 路由请求

因此，让我们退一步，再次看看如何通过传统的 Web 服务器路由我们的流量，不仅包括静态内容，还包括动态内容。

我们将创建三个函数，用于从我们的`customRouter:serveStatic():: read`函数中路由流量并提供一个平面文件`serveRendered():`，解析模板以显示`serveDynamic():`，连接到 MySQL，将数据应用于结构，并解析模板。

为了接受我们的请求并重新路由，我们将更改`customRouter`结构的`ServeHTTP`方法来处理三个正则表达式。

为了简洁和清晰起见，我们只会返回我们三种可能请求的数据。其他任何内容都将被忽略。

在现实世界的场景中，我们可以采取这种方法，积极主动地拒绝我们认为无效的请求连接。这将包括蜘蛛和恶意机器人和进程，它们作为非用户并没有真正价值。

# 提供页面

首先是我们的静态页面。虽然我们之前以成语方式处理了这个问题，但是使用`http.ServeFile`函数可以重写我们的请求，更好地处理特定的 404 错误页面等，如下面的代码所示：

```go
  path := r.URL.Path;

  staticPatternString := "static/(.*)"
  templatePatternString := "template/(.*)"
  dynamicPatternString := "dynamic/(.*)"

  staticPattern := regexp.MustCompile(staticPatternString)
  templatePattern := regexp.MustCompile(templatePatternString)
  dynamicDBPattern := regexp.MustCompile(dynamicPatternString)

  if staticPattern.MatchString(path) {
    page := staticPath + staticPattern.ReplaceAllString(path, 
     "${1}") + ".html"

    http.ServeFile(rw, r, page)
  }
```

在这里，我们只需将所有以`/static/(.*)`开头的请求与`.html`扩展名匹配。在我们的情况下，我们已经将我们的测试文件（80 KB 示例文件）命名为`test.html`，因此所有对它的请求将转到`/static/test`。

我们在这之前加上了`staticPath`，这是一个在代码中定义的常量。在我们的情况下，它是`/var/www/`，但您可能需要根据需要进行修改。

因此，让我们看看引入一些正则表达式所带来的开销，如下图所示：

![提供页面](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/ms-cncr-go/img/00032.jpeg)

怎么样？不仅没有额外的开销，而且似乎`FileServer`功能本身比单独的`FileServe()`调用更重，更慢。为什么呢？除了其他原因，不显式调用文件以打开和提供会导致额外的操作系统调用，这可能会随着请求的增加而成倍增加，从而损害并发性能。

### 提示

**有时候是小事情**

除了严格地提供平面页面之外，我们实际上还在每个请求中执行另一个任务，使用以下代码行：

```go
fmt.Println(r.URL.Path)
```

尽管这最终可能不会对您的最终性能产生影响，但我们应该注意避免不必要的日志记录或相关活动，这可能会给看似微不足道的性能障碍带来更大的问题。

## 解析我们的模板

在我们的下一个阶段，我们将衡量读取和解析模板的影响。为了有效地匹配以前的测试，我们将采用我们的 HTML 静态文件，并对其施加一些变量。

如果您还记得，我们的目标是尽可能模仿真实世界的场景。真实的 Web 服务器肯定会处理大量的静态文件服务，但是今天，动态调用构成了绝大部分的网络流量。

我们的数据结构将类似于最简单的数据表，而没有实际数据库的访问权限：

```go
type WebPage struct {
  Title string
  Contents string
}
```

我们希望采用这种形式的任何数据，并使用模板呈现它。请记住，Go 通过大写（公共）或小写（私有）值的语法糖来创建公共或私有变量的概念。

如果您发现模板无法渲染，但控制台没有明确的错误提示，请检查您的变量命名。从 HTML（或文本）模板调用的私有值将导致渲染在该点停止。

现在，我们将获取这些数据，并将其应用于以`/(.*)`开头的 URL 的模板。我们可以确实使用正则表达式的通配部分做一些更有用的事情，所以让我们使用以下代码将其作为标题的一部分：

```go
  } else if templatePattern.MatchString(path) {

    urlVar := templatePattern.ReplaceAllString(path, "${1}")
    page := WebPage{ Title: "This is our URL: "+urlVar, Contents: 
      "Enjoy our content" }
    tmp, _ := template.ParseFiles(staticPath+"template.html")
    tmp.Execute(rw,page)

  }
```

访问`localhost:9000/template/hello`应该呈现一个主体为以下代码的模板：

```go
<h1>{{.Title}}</h1>
<p>{{.Contents}}</p>
```

我们将得到以下输出：

![解析我们的模板](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/ms-cncr-go/img/00033.jpeg)

关于模板的一点需要注意的是，它们不是编译的；它们保持动态。也就是说，如果您创建了一个可渲染的模板并启动了服务器，那么模板可以被修改，结果会反映出来。

这是一个潜在的性能因素。让我们再次运行我们的基准测试，将模板渲染作为我们应用程序及其架构的附加复杂性：

![解析我们的模板](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/ms-cncr-go/img/00034.jpeg)

天啊！发生了什么？我们从轻松处理 10,000 个并发请求到几乎无法处理 200 个。

公平地说，我们引入了一个故意设置的绊脚石，在任何给定 CMS 的设计中并不罕见。

您会注意到我们在每个请求上调用`template.ParseFiles（）`方法。这是一种看似廉价的调用，但当您开始堆叠请求时，它确实会增加起来。

然后，将文件操作移出请求处理程序可能是有意义的，但我们需要做的不仅仅是这些——为了消除开销和阻塞调用，我们需要为请求设置一个内部缓存。

最重要的是，如果您希望保持服务器的非阻塞、快速和响应性，所有模板的创建和解析都应该发生在实际请求处理程序之外。这里是另一种方法：

```go
var customHTML string
var customTemplate template.Template
var page WebPage
var templateSet bool

func main() {
  var cr customRouter;
  fileName := staticPath + "template.html"
  cH,_ := ioutil.ReadFile(fileName)
  customHTML = string(cH[:])

  page := WebPage{ Title: "This is our URL: ", Contents: "Enjoy 
    our content" }
  cT,_ := template.New("Hey").Parse(customHTML)
  customTemplate = *cT
```

尽管我们在请求之前使用了`Parse（）`函数，但我们仍然可以使用`Execute（）`方法修改我们特定于 URL 的变量，这与`Parse（）`没有相同的开销。

当我们将这个移出`customRouter`结构的`ServeHTTP（）`方法时，我们又回到了正常状态。这是我们将会得到的这些更改的响应：

![解析我们的模板](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/ms-cncr-go/img/00035.jpeg)

## 外部依赖

最后，我们需要解决我们最大的潜在瓶颈，即数据库。正如前面提到的，我们将通过生成 1 到 10,000 之间的随机整数来模拟随机流量，以指定我们想要的文章。

随机化不仅在前端有用——我们将要绕过 MySQL 内部的任何查询缓存，以限制非服务器优化。

### 连接到 MySQL

我们可以通过原生 Go 路由到自定义连接到 MySQL，但通常情况下，有一些第三方包可以使这个过程变得不那么痛苦。鉴于这里的数据库（以及相关库）是主要练习的第三方，我们不会太关心这里的细节。

两个成熟的 MySQL 驱动程序库如下：

+   Go-MySQL-Driver（[`github.com/go-sql-driver/mysql`](https://github.com/go-sql-driver/mysql)）

+   **MyMySQL**（[`github.com/ziutek/mymysql`](https://github.com/ziutek/mymysql)）

在这个例子中，我们将使用 Go-MySQL-Driver。我们将使用以下命令快速安装它：

```go
go get github.com/go-sql-driver/mysql

```

这两个都实现了 Go 中核心的 SQL 数据库连接包，提供了一种标准化的方法来连接到 SQL 源并遍历行。

一个注意事项是，如果你以前从未在 Go 中使用过 SQL 包，但在其他语言中使用过——通常在其他语言中，“Open（）”方法的概念意味着打开连接。在 Go 中，这只是为数据库创建结构和相关实现方法。这意味着仅仅在`sql.database`上调用`Open（）`可能不会给出相关的连接错误，比如用户名/密码问题等。

这种方法的一个优势（或者根据您的观点而定的劣势）是，连接到数据库可能不会在向 Web 服务器发送请求之间保持打开状态。在整体方案中，打开和重新打开连接的影响微乎其微。

由于我们正在利用伪随机文章请求，我们将构建一个 MySQL 附属函数来通过 ID 获取文章，如下面的代码所示：

```go
func getArticle(id int) WebPage {
  Database,err := sql.Open("mysql", "test:test@/master")
  if err != nil {
    fmt.Println("DB error!!!")
  }

  var articleTitle string
  sqlQ := Database.QueryRow("SELECT article_title from articles 
    where article_id=? LIMIT 1", 1).Scan(&articleTitle)
  switch {
    case sqlQ == sql.ErrNoRows:
      fmt.Printf("No rows!")
    case sqlQ != nil:
      fmt.Println(sqlQ)
    default:

  }

  wp := WebPage{}
  wp.Title = articleTitle
  return wp

}
```

然后我们将直接从我们的`ServeHTTP()`方法中调用该函数，如下面的代码所示：

```go
  }else if dynamicDBPattern.MatchString(path) {
    rand.Seed(9)
    id := rand.Intn(10000)
    page = getArticle(id)
    customTemplate.Execute(rw,page)
  }
```

我们在这里做得怎么样？看一下下面的图表：

![连接到 MySQL](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/ms-cncr-go/img/00036.jpeg)

毫无疑问，速度较慢，但我们成功承受了全部 10,000 个并发请求，完全来自未缓存的 MySQL 调用。

鉴于我们无法通过默认安装的 Apache 达到 1,000 个并发请求，这绝非易事。

# 多线程和利用多个核心

您可能想知道在调用额外的处理器核心时性能会如何变化——正如前面提到的，这有时会产生意想不到的效果。

在这种情况下，我们应该期望我们的动态请求和静态请求的性能都会有所提高。任何时候，操作系统中的上下文切换成本可能会超过额外核心的性能优势，我们都会看到矛盾的性能下降。在这种情况下，我们没有看到这种效果，而是看到了一个相对类似的线，如下图所示：

![多线程和利用多个核心](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/ms-cncr-go/img/00037.jpeg)

# 探索我们的 Web 服务器

我们的最终 Web 服务器能够在即使是最适度的硬件上，很好地处理静态、模板渲染和动态内容，符合 10,000 个并发连接的目标。

这段代码——就像本书中的代码一样——可以被视为一个起点，如果投入生产，就需要进行改进。这个服务器缺乏任何形式的错误处理，但可以在没有任何问题的情况下有效地处理有效的请求。让我们看一下以下服务器的代码：

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

我们这里的大部分导入都是相当标准的，但请注意 MySQL 行，它仅仅因为其副作用而被调用作为数据库/SQL 驱动程序：

```go
const staticPath string = "static/"
```

相对的`static/`路径是我们将查找任何文件请求的地方——正如前面提到的，这并不会进行额外的错误处理，但`net/http`包本身会在请求不存在的文件时返回 404 错误：

```go
type WebPage struct {

  Title string
  Contents string
  Connection *sql.DB

}
```

我们的`WebPage`类型表示模板渲染之前的最终输出页面。它可以填充静态内容，也可以由数据源填充，如下面的代码所示：

```go
type customRouter struct {

}

func serveDynamic() {

}

func serveRendered() {

}

func serveStatic() {

}
```

如果您选择扩展 Web 应用程序，请使用这些方法——这样可以使代码更清晰，并删除`ServeHTTP`部分中的大量不必要的内容，如下面的代码所示：

```go
func (customRouter) ServeHTTP(rw http.ResponseWriter, r 
  *http.Request) {
  path := r.URL.Path;

  staticPatternString := "static/(.*)"
  templatePatternString := "template/(.*)"
  dynamicPatternString := "dynamic/(.*)"

  staticPattern := regexp.MustCompile(staticPatternString)
  templatePattern := regexp.MustCompile(templatePatternString)
  dynamicDBPattern := regexp.MustCompile(dynamicPatternString)

  if staticPattern.MatchString(path) {
     serveStatic()
    page := staticPath + staticPattern.ReplaceAllString(path, 
      "${1}") + ".html"
    http.ServeFile(rw, r, page)
  }else if templatePattern.MatchString(path) {

    serveRendered()
    urlVar := templatePattern.ReplaceAllString(path, "${1}")

    page.Title = "This is our URL: " + urlVar
    customTemplate.Execute(rw,page)

  }else if dynamicDBPattern.MatchString(path) {

    serveDynamic()
    page = getArticle(1)
    customTemplate.Execute(rw,page)
  }

}
```

我们所有的路由都是基于正则表达式模式匹配的。有很多方法可以做到这一点，但`regexp`给了我们很大的灵活性。唯一需要考虑简化的时候是，如果您有很多潜在的模式，可能会导致性能损失——这意味着成千上万。流行的 Web 服务器 Nginx 和 Apache 处理他们的可配置路由大部分都是通过正则表达式，所以这是相当安全的领域：

```go
func gobble(s []byte) {

}
```

Go 对于未使用的变量非常挑剔，虽然这并不总是最佳实践，但在某些时候，您会得到一个不对数据进行特定处理但能让编译器满意的函数。对于生产环境，这并不是您想要处理此类数据的方式。

```go
var customHTML string
var customTemplate template.Template
var page WebPage
var templateSet bool
var Database sql.DB

func getArticle(id int) WebPage {
  Database,err := sql.Open("mysql", "test:test@/master")
  if err != nil {
    fmt.Println("DB error!")
  }

  var articleTitle string
  sqlQ := Database.QueryRow("SELECT article_title from articles 
    WHERE article_id=? LIMIT 1", id).Scan(&articleTitle)
  switch {
    case sqlQ == sql.ErrNoRows:
      fmt.Printf("No rows!")
    case sqlQ != nil:
      fmt.Println(sqlQ)
    default:

  }

  wp := WebPage{}
  wp.Title = articleTitle
  return wp

}
```

我们的`getArticle`函数演示了您如何在非常基本的级别上与`database/sql`包进行交互。在这里，我们打开一个连接，并使用`QueryRow()`函数查询一行。还有`Query`命令，通常也是一个`SELECT`命令，但可能返回多行。

```go
func main() {

  runtime.GOMAXPROCS(4)

  var cr customRouter;

  fileName := staticPath + "template.html"
  cH,_ := ioutil.ReadFile(fileName)
  customHTML = string(cH[:])

  page := WebPage{ Title: "This is our URL: ", Contents: "Enjoy 
    our content" }
  cT,_ := template.New("Hey").Parse(customHTML)
  customTemplate = *cT

  gobble(cH)
  log.Println(page)
  fmt.Println(customTemplate)

  server := &http.Server {
      Addr: ":9000",
      Handler:cr,
      ReadTimeout: 10 * time.Second,
      WriteTimeout: 10 * time.Second,
      MaxHeaderBytes: 1 << 20,
  }

  server.ListenAndServe()

}
```

我们的主函数设置服务器，构建默认的`WebPage`和`customRouter`，并开始在端口`9000`上监听。

## 超时并继续

在我们的服务器中，我们没有专注于持续连接的缓解概念。我们之所以不太担心它，是因为我们能够通过利用 Go 语言强大的内置并发特性，在所有三种方法中都能够轻松达到 10,000 个并发连接。

特别是在使用第三方或外部应用程序和服务时，重要的是要知道我们可以并且应该准备在连接中放弃（如果我们的应用程序设计允许的话）。

注意自定义服务器实现和两个特定属性：`ReadTimeout`和`WriteTimeout`。这使我们能够精确处理这种用例。

在我们的示例中，这被设置为一个荒谬地高的 10 秒。要接收、处理和发送一个请求，最多需要 20 秒的时间。在 Web 世界中，这是一个漫长的时间，有可能使我们的应用瘫痪。那么，我们的 C10K 在每端都设置为 1 秒会是什么样子呢？让我们看一下下面的图表：

![超时并继续前进](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/ms-cncr-go/img/00038.jpeg)

在这里，我们几乎在最高并发请求的尾部节省了将近 5 秒的时间，几乎可以肯定是以完整响应为代价。

决定保持运行缓慢连接的时间长度是由你来决定的，但这是保持服务器迅速响应的武器库中的另一个工具。

当你决定终止连接时，总会有一个权衡——太早会导致大量关于不响应或容易出错的服务器的投诉；太晚则无法以编程方式处理连接量。这是需要质量保证和硬数据的考虑之一。

# 总结

C10K 问题今天看起来可能已经过时了，但是呼吁行动是在并发语言和应用程序设计迅速扩展之前主要采用的系统应用的方法的症状。

仅仅 15 年前，这似乎是全球系统和服务器开发人员面临的一个几乎无法克服的问题；现在，通过对服务器设计进行轻微调整和考虑就能够解决。

Go 语言使得实现这一点变得容易（只需付出一点努力），但是达到 10,000（甚至是 100,000 或 1,000,000）并发连接只是一半的战斗。当问题出现时，我们必须知道该怎么做，如何在服务器中寻求最大性能和响应能力，并且如何构建我们的外部依赖，使其不会造成障碍。

在我们的下一章中，我们将通过测试一些分布式计算模式并最大限度地利用内存管理来进一步提高并发应用的性能。
