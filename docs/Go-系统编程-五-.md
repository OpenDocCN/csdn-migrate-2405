# Go 系统编程（五）

> 原文：[`zh.annas-archive.org/md5/2DB8F67A356AEFD794B578E9C4995B3C`](https://zh.annas-archive.org/md5/2DB8F67A356AEFD794B578E9C4995B3C)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第九章：Goroutines - 基本特性

在上一章中，您学习了 Unix 信号处理，以及在 Go 中添加管道支持和创建图形图像。

这个非常重要的章节的主题是 goroutines。Go 使用 goroutines 和**通道**来以自己的方式编写并发应用程序，同时提供对传统并发技术的支持。Go 中的所有内容都使用 goroutines 执行；当程序开始执行时，其单个 goroutine 会自动调用`main()`函数，以开始程序的实际执行。

在本章中，我们将介绍 goroutines 的简单部分，并提供易于遵循的代码示例。然而，在接下来的第十章*，* *Goroutines - 高级特性*中，我们将讨论与 goroutines 和通道相关的更重要和高级的技术，因此，请确保在阅读下一章之前充分理解本章。

因此，本章将告诉您以下内容：

+   创建 goroutines

+   同步 goroutines

+   关于通道以及如何使用它们

+   读取和写入通道

+   创建和使用管道

+   更改`wc.go`实用程序的 Go 代码，以便在新实现中使用 goroutines

+   进一步改进`wc.go`的 goroutine 版本

# 关于 goroutines

**goroutine**是可以并发执行的最小 Go 实体。请注意，这里使用“最小”一词非常重要，因为 goroutines 不是自主实体。Goroutines 存在于 Unix 进程中的线程中。简单来说，进程可以是自主的并独立存在，而 goroutines 和线程都不行。因此，要创建 goroutine，您需要至少有一个带有线程的进程。好处是 goroutines 比线程轻，线程比进程轻。Go 中的所有内容都使用 goroutines 执行，这是合理的，因为 Go 是一种并发编程语言。正如您刚刚了解的那样，当 Go 程序开始执行时，它的单个 goroutine 调用`main()`函数，从而启动实际的程序执行。

您可以使用`go`关键字后跟函数名或匿名函数的完整定义来定义新的 goroutine。`go`关键字在新的 goroutine 中启动函数参数，并允许调用函数自行继续。

然而，正如您将看到的，您无法控制或做出任何关于 goroutines 将以何种顺序执行的假设，因为这取决于操作系统的调度程序以及操作系统的负载。

# 并发和并行

一个非常常见的误解是**并发**和**并行**指的是同一件事，这与事实相去甚远！并行是多个事物同时执行，而并发是一种构造组件的方式，使它们在可能的情况下可以独立执行。

只有在并发构建时，您才能安全地并行执行它们：当且如果您的操作系统和硬件允许。很久以前，Erlang 编程语言就已经做到了这一点，早在 CPU 拥有多个核心和计算机拥有大量 RAM 之前。

在有效的并发设计中，添加并发实体使整个系统运行更快，因为更多的事情可以并行运行。因此，期望的并行性来自于对问题的更好并发表达和实现。开发人员在系统设计阶段负责考虑并发，并从系统组件的潜在并行执行中受益。因此，开发人员不应该考虑并行性，而应该考虑将事物分解为独立组件，这些组件在组合时解决最初的问题。

即使在 Unix 机器上无法并行运行函数，有效的并发设计仍将改善程序的设计和可维护性。换句话说，并发比并行更好！

# 同步 Go 包

`sync` Go 包包含可以帮助您同步 goroutines 的函数；`sync`的最重要的函数是`sync.Add`、`sync.Done`和`sync.Wait`。对于每个程序员来说，同步 goroutines 是一项必不可少的任务。

请注意，goroutines 的同步与共享变量和共享状态无关。共享变量和共享状态与您希望用于执行并发交互的方法有关。

# 一个简单的例子

在这一小节中，我们将介绍一个简单的程序，它创建了两个 goroutines。示例程序的名称将是`aGoroutine.go`，将分为三个部分；第一部分如下：

```go
package main 

import ( 
   "fmt" 
   "time" 
) 

func namedFunction() { 
   time.Sleep(10000 * time.Microsecond) 
   fmt.Println("Printing from namedFunction!") 
} 
```

除了预期的`package`和`import`语句之外，您还可以看到一个名为`namedFunction()`的函数的实现，在打印屏幕上的消息之前会休眠一段时间。

`aGoroutine.go`的第二部分包含以下 Go 代码：

```go
func main() { 
   fmt.Println("Chapter 09 - Goroutines.") 
   go namedFunction() 
```

在这里，您创建了一个执行`namedFunction()`函数的 goroutine。这个天真程序的最后部分如下：

```go
   go func() { 
         fmt.Println("An anonymous function!") 
   }() 

   time.Sleep(10000 * time.Microsecond) 
   fmt.Println("Exiting...") 
} 
```

在这里，您创建了另一个 goroutine，它执行一个包含单个`fmt.Println()`语句的匿名函数。

正如您所看到的，以这种方式运行的 goroutines 是完全隔离的，彼此之间无法交换任何类型的数据，这并不总是所期望的操作风格。

如果您忘记在`main()`函数中调用`time.Sleep()`函数，或者`time.Sleep()`睡眠了很短的时间，那么`main()`将会过早地结束，两个 goroutines 将没有足够的时间开始和完成它们的工作；结果，您将无法在屏幕上看到所有预期的输出！

执行`aGoroutine.go`将生成以下输出：

```go
$ go run aGoroutine.go
Chapter 09 - Goroutines.
Printing from namedFunction!
Exiting... 
```

# 创建多个 goroutines

这一小节将向您展示如何创建许多 goroutines 以及处理更多 goroutines 所带来的问题。程序的名称将是`moreGoroutines.go`，将分为三个部分。

`moreGoroutines.go`的第一部分如下：

```go
package main 

import ( 
   "fmt" 
   "time" 
) 
```

程序的第二部分包含以下 Go 代码：

```go
func main() { 
   fmt.Println("Chapter 09 - Goroutines.") 

   for i := 0; i < 10; i++ { 
         go func(x int) { 
               time.Sleep(10) 
               fmt.Printf("%d ", x) 
         }(i) 
   } 
```

这次，匿名函数接受一个名为`x`的参数，其值为变量`i`。使用变量`i`的`for`循环依次创建十个 goroutines。

程序的最后部分如下：

```go
   time.Sleep(10000) 
   fmt.Println("Exiting...") 
} 
```

再次，如果您将较小的值作为`time.Sleep()`的参数，当您执行程序时将会看到不同的结果。

执行`moreGoroutines.go`将生成一个有些奇怪的输出：

```go
$ go run moreGoroutines.go
Chapter 09 - Goroutines.
1 7 Exiting...
2 3
```

然而，当您多次执行`moreGoroutines.go`时，大惊喜来了：

```go
$ go run moreGoroutines.go
Chapter 09 - Goroutines.
Exiting...
$ go run moreGoroutines.go
Chapter 09 - Goroutines.
3 1 0 9 2 Exiting...
4 5 6 8 7
$ go run moreGoroutines.go
Chapter 09 - Goroutines.
2 0 1 8 7 3 6 5 Exiting...
4
```

正如您所看到的，程序的所有先前输出都与第一个不同！因此，输出不仅不协调，而且并不总是有足够的时间让所有 goroutines 执行；您无法确定 goroutines 将以何种顺序执行。然而，尽管您无法解决后一个问题，因为 goroutines 的执行顺序取决于开发人员无法控制的各种参数，下一小节将教您如何同步 goroutines 并为它们提供足够的时间完成，而无需调用`time.Sleep()`。

# 等待 goroutines 完成它们的工作

这一小节将向您演示正确的方法来创建一个等待其 goroutines 完成工作的调用函数。程序的名称将是`waitGR.go`，将分为四个部分；第一部分如下：

```go
package main 

import ( 
   "fmt" 
   "sync" 
) 
```

除了`time`包的缺失和`sync`包的添加之外，这里没有什么特别的。

第二部分包含以下 Go 代码：

```go
func main() { 
   fmt.Println("Waiting for Goroutines!") 

   var waitGroup sync.WaitGroup 
   waitGroup.Add(10) 
```

在这里，您创建了一个新变量，类型为`sync.WaitGroup`，它等待一组 goroutines 完成。属于该组的 goroutines 的数量由一个或多个对`sync.Add()`函数的调用定义。

在 Go 语句之前调用`sync.Add()`以防止竞争条件是很重要的。

另外，`sync.Add(10)`的调用告诉我们的程序，我们将等待十个 goroutines 完成。

程序的第三部分如下：

```go
   var i int64 
   for i = 0; i < 10; i++ { 

         go func(x int64) { 
               defer waitGroup.Done() 
               fmt.Printf("%d ", x) 
         }(i) 
   } 
```

在这里，您可以使用`for`循环创建所需数量的 goroutines，但也可以使用多个顺序的 Go 语句。当每个 goroutine 完成其工作时，将执行`sync.Done()`函数：在函数定义之后立即使用`defer`关键字告诉匿名函数在完成之前自动调用`sync.Done()`。

`waitGR.go`的最后一部分如下：

```go
   waitGroup.Wait() 
   fmt.Println("\nExiting...") 
} 
```

这里的好处是不需要调用`time.Sleep()`，因为`sync.Wait()`会为我们做必要的等待。

再次应该注意的是，您不应该对 goroutines 的执行顺序做任何假设，这也由以下输出验证：

```go
$ go run waitGR.go
Waiting for Goroutines!
9 0 5 6 7 8 2 1 3 4
Exiting...
$ go run waitGR.go
Waiting for Goroutines!
9 0 5 6 7 8 3 1 2 4
Exiting...
$ go run waitGR.go
Waiting for Goroutines!
9 5 6 7 8 1 0 2 3 4
Exiting...
```

如果您调用`waitGroup.Add()`的次数超过所需次数，当执行`waitGR.go`时，将收到以下错误消息：

```go
Waiting for Goroutines!
fatal error: all goroutines are asleep - deadlock!

goroutine 1 [semacquire]:
sync.runtime_Semacquire(0xc42000e28c)
      /usr/local/Cellar/go/1.8.3/libexec/src/runtime/sema.go:47 +0x34
sync.(*WaitGroup).Wait(0xc42000e280)
      /usr/local/Cellar/go/1.8.3/libexec/src/sync/waitgroup.go:131 +0x7a
main.main()
      /Users/mtsouk/ch/ch9/code/waitGR.go:22 +0x13c
exit status 2
9 0 1 2 6 7 8 3 4 5
```

这是因为当您告诉程序通过调用`sync.Add(1)` n+1 次来等待 n+1 个 goroutines 时，您的程序不能只有 n 个 goroutines（或更少）！简单地说，这将使`sync.Wait()`无限期地等待一个或多个 goroutines 调用`sync.Done()`而没有任何运气，这显然是一个死锁的情况，阻止您的程序完成。

# 创建动态数量的 goroutines

这次，将作为命令行参数给出要创建的 goroutines 的数量：程序的名称将是`dynamicGR.go`，并将分为四个部分。

`dynamicGR.go`的第一部分如下：

```go
package main 

import ( 
   "fmt" 
   "os" 
   "path/filepath" 
   "strconv" 
   "sync" 
) 
```

`dynamicGR.go`的第二部分包含以下 Go 代码：

```go
func main() { 
   if len(os.Args) != 2 { 
         fmt.Printf("usage: %s integer\n",filepath.Base(os.Args[0])) 
         os.Exit(1) 
   } 

   numGR, _ := strconv.ParseInt(os.Args[1], 10, 64) 
   fmt.Printf("Going to create %d goroutines.\n", numGR) 
   var waitGroup sync.WaitGroup 

   var i int64 
   for i = 0; i < numGR; i++ { 
         waitGroup.Add(1) 
```

正如您所看到的，`waitGroup.Add(1)`语句是在创建新的 goroutine 之前调用的。

`dynamicGR.go`的 Go 代码的第三部分如下：

```go
         go func(x int64) { 
               defer waitGroup.Done() 
               fmt.Printf(" %d ", x) 
         }(i) 
   } 
```

在前面的部分中，创建了每个简单的 goroutine。

程序的最后一部分如下：

```go
   waitGroup.Wait() 
   fmt.Println("\nExiting...") 
} 
```

在这里，您只需告诉程序使用`waitGroup.Wait()`语句等待所有 goroutines 完成。

执行`dynamicGR.go`需要一个整数参数，这是您想要创建的 goroutines 的数量：

```go
$ go run dynamicGR.go 15
Going to create 15 goroutines.
 0  2  4  1  3  5  14  10  8  9  12  11  6  13  7
Exiting...
$ go run dynamicGR.go 15
Going to create 15 goroutines.
 5  3  14  4  10  6  7  11  8  9  12  2  13  1  0
Exiting...
$ go run dynamicGR.go 15
Going to create 15 goroutines.
 4  2  3  6  5  10  9  7  0  12  11  1  14  13  8
Exiting...
```

可以想象，您想要创建的 goroutines 越多，输出就会越多样化，因为没有办法控制程序的 goroutines 执行顺序。

# 关于通道

**通道**，简单地说，是一种通信机制，允许 goroutines 交换数据。但是，这里存在一些规则。首先，每个通道允许特定数据类型的交换，这也称为通道的**元素类型**，其次，为了使通道正常运行，您需要使用一些 Go 代码来接收通过通道发送的内容。

您应该使用`chan`关键字声明一个新的通道，并且可以使用`close()`函数关闭一个通道。此外，由于每个通道都有自己的类型，开发人员应该定义它。

最后，一个非常重要的细节：当您将通道用作函数参数时，可以指定其方向，即它将用于写入还是读取。在我看来，如果您事先知道通道的目的，请使用此功能，因为它将使您的程序更健壮，更安全：否则，只需不定义通道函数参数的目的。因此，如果您声明通道函数参数仅用于读取，并尝试向其写入，您将收到一个错误消息，这很可能会使您免受讨厌的错误。

当你尝试从写通道中读取时，你将得到以下类似的错误消息：

```go
# command-line-arguments
./writeChannel.go:13: invalid operation: <-c (receive from send-only type chan<- int)
```

# 向通道写入

在本小节中，你将学习如何向通道写入。所呈现的程序将被称为`writeChannel.go`，并分为三个部分。

第一部分包含了预期的序言：

```go
package main 

import ( 
   "fmt" 
   "time" 
) 
```

正如你所理解的，使用通道不需要任何额外的 Go 包。

`writeChannel.go`的第二部分如下：

```go
func writeChannel(c chan<- int, x int) { 
   fmt.Println(x) 
   c <- x 
   close(c) 
   fmt.Println(x) 
} 
```

尽管`writeChannel()`函数向通道写入数据，但由于当前没有人从程序中读取通道，数据将丢失。

程序的最后一部分包含以下 Go 代码：

```go
func main() { 
   c := make(chan int) 
   go writeChannel(c, 10) 
   time.Sleep(2 * time.Second) 
} 
```

在这里，你可以看到使用`chan`关键字定义了一个名为`c`的通道变量，用于`int`数据。

执行`writeChannel.go`将创建以下输出：

```go
 $ go run writeChannel.go
 10
```

这不是你期望看到的！这个意外的输出的原因是第二个`fmt.Println(x)`语句没有被执行。原因很简单：`c <- x`语句阻塞了`writeChannel()`函数的其余部分的执行，因为没有人从`c`通道中读取。

# 从通道中读取

本小节将通过允许你从通道中读取来改进`writeChannel.go`的 Go 代码。所呈现的程序将被称为`readChannel.go`，并分为四个部分呈现。

第一部分如下：

```go
package main 

import ( 
   "fmt" 
   "time" 
) 
```

`readChannel.go`的第二部分包含以下 Go 代码：

```go
func writeChannel(c chan<- int, x int) { 
   fmt.Println(x) 
   c <- x 
   close(c) 
   fmt.Println(x) 
} 
```

再次注意，如果没有人收集写入通道的数据，发送数据的函数将在等待有人读取其数据时停滞。然而，在第十章*，* *Goroutines - Advanced Features*中，你将看到这个问题的一个非常好的解决方案。

第三部分包含以下 Go 代码：

```go
func main() { 
   c := make(chan int) 
   go writeChannel(c, 10) 
   time.Sleep(2 * time.Second) 
   fmt.Println("Read:", <-c) 
   time.Sleep(2 * time.Second) 
```

在这里，`fmt.Println()`函数中的`<-c`语句用于从通道中读取单个值：相同的语句也可以用于将通道的值存储到变量中。然而，如果你不存储从通道中读取的值，它将会丢失。

`readChannel.go`的最后一部分如下：

```go
   _, ok := <-c 
   if ok { 
         fmt.Println("Channel is open!") 
   } else { 
         fmt.Println("Channel is closed!") 
   } 
} 
```

在这里，你看到了一种技术，可以让你知道你想要从中读取的通道是否已关闭。然而，如果通道是打开的，所呈现的 Go 代码将因为在赋值中使用了`_`字符而丢弃通道的读取值。

执行`readChannel.go`将创建以下输出：

```go
$ go run readChannel.go
10
Read: 10
10
Channel is closed!
$ go run readChannel.go
10
10
Read: 10
Channel is closed!
```

# 解释 h1s.go

在第八章*，* *Processes and Signals*中，你看到了 Go 如何使用许多示例处理 Unix 信号，包括`h1s.go`。然而，现在你更了解 goroutines 和通道，是时候更详细地解释一下`h1s.go`的 Go 代码了。

正如你已经知道的，`h1s.go`使用通道和 goroutines，现在应该清楚了，作为 goroutine 执行的匿名函数使用无限的`for`循环从`sigs`通道读取。这意味着每次有我们感兴趣的信号时，goroutine 都会从`sigs`通道中读取并处理它。

# 管道

Go 程序很少使用单个通道。一个非常常见的使用多个通道的技术称为**pipeline**。因此，pipeline 是一种连接 goroutines 的方法，使得一个 goroutine 的输出成为另一个 goroutine 的输入，借助通道。使用 pipeline 的好处如下：

+   使用 pipeline 的好处之一是程序中有一个恒定的流动，因为没有人等待所有事情都完成才开始执行程序的 goroutines 和通道

+   此外，你使用的变量更少，因此占用的内存空间也更少，因为你不必保存所有东西。

+   最后，使用管道简化了程序的设计并提高了可维护性

`pipelines.go`的代码将以五个部分呈现；第一部分如下：

```go
package main 

import ( 
   "fmt" 
   "os" 
   "path/filepath" 
   "strconv" 
) 
```

第二部分包含以下 Go 代码：

```go
func genNumbers(min, max int64, out chan<- int64) { 

   var i int64 
   for i = min; i <= max; i++ { 
         out <- i 
   } 
   close(out) 
} 
```

在这里，您定义了一个函数，它接受三个参数：两个整数和一个输出通道。输出通道将用于写入将在另一个函数中读取的数据：这就是创建管道的方式。

程序的第三部分如下：

```go
func findSquares(out chan<- int64, in <-chan int64) { 
   for x := range in { 
         out <- x * x 
   } 
   close(out) 
} 
```

这次，函数接受两个都是通道的参数。但是，`out`是一个输出通道，而`in`是一个用于读取数据的输入通道。

第四部分包含另一个函数的定义：

```go
func calcSum(in <-chan int64) { 
   var sum int64 
   sum = 0 
   for x2 := range in { 
         sum = sum + x2 
   } 
   fmt.Printf("The sum of squares is %d\n", sum) 
} 
```

`pipelines.go`的最后一个函数只接受一个用于读取数据的通道作为参数。

`pipelines.go`的最后一部分是`main()`函数的实现：

```go
func main() { 
   if len(os.Args) != 3 { 
         fmt.Printf("usage: %s n1 n2\n", filepath.Base(os.Args[0])) 
         os.Exit(1) 
   } 
   n1, _ := strconv.ParseInt(os.Args[1], 10, 64) 
   n2, _ := strconv.ParseInt(os.Args[2], 10, 64) 

   if n1 > n2 { 
         fmt.Printf("%d should be smaller than %d\n", n1, n2) 
         os.Exit(10) 
   } 

   naturals := make(chan int64) 
   squares := make(chan int64) 
   go genNumbers(n1, n2, naturals) 
   go findSquares(squares, naturals) 
   calcSum(squares) 
} 
```

在这里，`main()`函数首先读取其两个命令行参数并创建必要的通道变量（`naturals`和`squares`）。然后，它调用管道的函数：请注意，通道的最后一个函数不会作为 goroutine 执行。

以下图显示了`pipelines.go`中使用的管道的图形表示，以说明特定管道的工作方式：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/go-sys-prog/img/e6d2874d-12a1-4441-b5a1-f2af5c0056fe.png)

pipelines.go 中使用的管道结构的图形表示

运行`pipelines.go`将生成以下输出：

```go
$ go run pipelines.go
usage: pipelines n1 n2
exit status 1
$ go run pipelines.go 3 2
3 should be smaller than 2
exit status 10
$ go run pipelines.go 3 20
The sum of squares is 2865
$ go run pipelines.go 1 20
The sum of squares is 2870
$ go run pipelines.go 20 20
The sum of squares is 400
```

# wc.go 的更好版本

正如我们在第六章中讨论的，在本章中，您将学习如何创建一个使用 goroutines 的`wc.go`的版本。新实用程序的名称将是`dWC.go`，将分为四个部分。请注意，`dWC.go`的当前版本将每个命令行参数都视为一个文件。

实用程序的第一部分如下：

```go
package main 

import ( 
   "bufio" 
   "fmt" 
   "io" 
   "os" 
   "path/filepath" 
   "regexp" 
   "sync" 
) 
```

第二部分包含以下 Go 代码：

```go
func count(filename string) { 
   var err error 
   var numberOfLines int = 0 
   var numberOfCharacters int = 0 
   var numberOfWords int = 0 

   f, err := os.Open(filename) 
   if err != nil { 
         fmt.Printf("%s\n", err) 
         return 
   } 
   defer f.Close() 

   r := bufio.NewReader(f) 
   for { 
         line, err := r.ReadString('\n') 

         if err == io.EOF { 
               break 
         } else if err != nil { 
               fmt.Printf("error reading file %s\n", err) 
         } 
         numberOfLines++ 
         r := regexp.MustCompile("[^\\s]+") 
         for range r.FindAllString(line, -1) { 
               numberOfWords++ 
         } 
         numberOfCharacters += len(line) 
   } 

   fmt.Printf("\t%d\t", numberOfLines) 
   fmt.Printf("%d\t", numberOfWords) 
   fmt.Printf("%d\t", numberOfCharacters) 
   fmt.Printf("%s\n", filename) 
} 
```

`count()`函数完成所有处理，而不向`main()`函数返回任何信息：它只是打印其输入文件的行数、单词数和字符数，然后退出。尽管`count()`函数的当前实现完成了所需的工作，但这并不是设计程序的正确方式，因为无法控制程序的输出。

实用程序的第三部分如下：

```go
func main() { 
   if len(os.Args) == 1 { 
         fmt.Printf("usage: %s <file1> [<file2> [... <fileN]]\n", 
               filepath.Base(os.Args[0])) 
         os.Exit(1) 
   } 
```

`dWC.go`的最后一部分如下：

```go
   var waitGroup sync.WaitGroup 
   for _, filename := range os.Args[1:] { 
         waitGroup.Add(1) 
         go func(filename string) { 
               count(filename) 
               defer waitGroup.Done() 
         }(filename) 
   } 
   waitGroup.Wait() 
} 
```

正如您所看到的，每个输入文件都由不同的 goroutine 处理。如预期的那样，您无法对输入文件的处理顺序做出任何假设。

执行`dWC.go`将生成以下输出：

```go
$ go run dWC.go /tmp/swtag.log /tmp/swtag.log doesnotExist
open doesnotExist: no such file or directory
          48    275   3571  /tmp/swtag.log
          48    275   3571  /tmp/swtag.log

```

在这里，您可以看到，尽管`doesnotExist`文件名是最后一个命令行参数，但它是`dWC.go`输出中的第一个命令行参数！

尽管`dWC.go`使用了 goroutines，但其中并没有巧妙之处，因为 goroutines 在没有相互通信和执行任何其他任务的情况下运行。此外，输出可能会混乱，因为无法保证`count()`函数的`fmt.Printf()`语句不会被中断。

因此，即将呈现的部分以及将在第十章中呈现的一些技术，即*Goroutines - 高级特性*，将改进`dWC.go`。

# 计算总数

`dWC.go`的当前版本无法计算总数，可以通过使用`awk`处理`dWC.go`的输出来轻松解决：

```go
$ go run dWC.go /tmp/swtag.log /tmp/swtag.log | awk '{sum1+=$1; sum2+=$2; sum3+=$3} END {print "\t", sum1, "\t", sum2, "\t", sum3}'
       96    550   7142

```

然而，这离完美和优雅还有很大差距！

`dWC.go`的当前版本无法计算总数的主要原因是其 goroutines 无法相互通信。这可以通过通道和管道的帮助轻松解决。新版本的`dWC.go`将被称为`dWCtotal.go`，将分为五个部分呈现。

`dWCtotal.go`的第一部分如下：

```go
package main 

import ( 
   "bufio" 
   "fmt" 
   "io" 
   "os" 
   "path/filepath" 
   "regexp" 
) 

type File struct { 
   Filename   string 
   Lines      int 
   Words      int 
   Characters int 
   Error      error 
} 
```

在这里，定义了一个新的`struct`类型。新结构称为`File`，有四个字段和一个额外的字段用于保存错误消息。这是管道循环多个值的正确方式。有人可能会认为`File`结构的更好名称应该是`Counts`、`Results`、`FileCounts`或`FileResults`。

程序的第二部分如下：

```go
func process(files []string, out chan<- File) { 
   for _, filename := range files { 
         var fileToProcess File 
         fileToProcess.Filename = filename 
         fileToProcess.Lines = 0 
         fileToProcess.Words = 0 
         fileToProcess.Characters = 0 
         out <- fileToProcess 
   } 
   close(out) 
} 
```

`process()`函数的更好名称应该是`beginProcess()`或`processResults()`。您可以尝试在整个`dWCtotal.go`程序中自行进行更改。

`dWCtotal.go`的第三部分包含以下 Go 代码：

```go
func count(in <-chan File, out chan<- File) { 
   for y := range in { 
         filename := y.Filename 
         f, err := os.Open(filename) 
         if err != nil { 
               y.Error = err 
               out <- y 
               continue 
         } 
         defer f.Close() 
         r := bufio.NewReader(f) 
         for { 
               line, err := r.ReadString('\n') 
               if err == io.EOF { 
                     break 
               } else if err != nil { 
                     fmt.Printf("error reading file %s", err) 
                     y.Error = err 
                     out <- y 
                     continue 
               } 
               y.Lines = y.Lines + 1 
               r := regexp.MustCompile("[^\\s]+") 
               for range r.FindAllString(line, -1) { 
                     y.Words = y.Words + 1 
               } 
               y.Characters = y.Characters + len(line) 
         } 
         out <- y 
   } 
   close(out) 
} 
```

尽管`count()`函数仍然计算计数，但它不会打印它们。它只是使用`File`类型的`struct`变量将行数、单词数、字符数以及文件名发送到另一个通道。

这里有一个非常重要的细节，就是`count()`函数的最后一条语句：为了正确结束管道，您应该关闭所有涉及的通道，从第一个开始。否则，程序的执行将以类似以下的错误消息失败：

```go
fatal error: all goroutines are asleep - deadlock!
```

然而，就关闭管道的管道而言，您还应该注意不要过早关闭通道，特别是在管道中存在分支时。

程序的第四部分包含以下 Go 代码：

```go
func calculate(in <-chan File) { 
   var totalWords int = 0 
   var totalLines int = 0 
   var totalChars int = 0 
   for x := range in { 
         totalWords = totalWords + x.Words 
         totalLines = totalLines + x.Lines 
         totalChars = totalChars + x.Characters 
         if x.Error == nil { 
               fmt.Printf("\t%d\t", x.Lines) 
               fmt.Printf("%d\t", x.Words) 
               fmt.Printf("%d\t", x.Characters) 
               fmt.Printf("%s\n", x.Filename) 
         } 
   } 

   fmt.Printf("\t%d\t", totalLines) 
   fmt.Printf("%d\t", totalWords) 
   fmt.Printf("%d\ttotal\n", totalChars) 
} 
```

这里没有什么特别的：`calculate()`函数负责打印程序的输出。

`dWCtotal.go`的最后部分如下：

```go
func main() { 
   if len(os.Args) == 1 { 
         fmt.Printf("usage: %s <file1> [<file2> [... <fileN]]\n", 
               filepath.Base(os.Args[0])) 
         os.Exit(1) 
   } 

   files := make(chan File)
   values := make(chan File) 

   go process(os.Args[1:], files) 
   go count(files, values) 
   calculate(values) 
} 
```

由于`files`通道仅用于传递文件名，它本可以是一个`string`通道，而不是一个`File`通道。但是，这样代码更一致。

现在`dWCtotal.go`即使只处理一个文件也会自动生成总数：

```go
$ go run dWCtotal.go /tmp/swtag.log
      48    275   3571  /tmp/swtag.log
      48    275   3571  total
$ go run dWCtotal.go /tmp/swtag.log /tmp/swtag.log doesNotExist
      48    275   3571  /tmp/swtag.log
      48    275   3571  /tmp/swtag.log
      96    550   7142  total
```

请注意，`dWCtotal.go`和`dWC.go`都实现了相同的核心功能，即计算文件的单词、字符和行数：不同之处在于信息处理的方式不同，因为`dWCtotal.go`使用了管道而不是孤立的 goroutines。

第十章*，* *Goroutines - Advanced Features*，将使用其他技术来实现`dWCtotal.go`的功能。

# 进行一些基准测试

在本节中，我们将比较第六章*，* *文件输入和输出*中的`wc.go`与`wc(1)`、`dWC.go`和`dWCtotal.go`的性能。为了使结果更准确，所有三个实用程序将处理相对较大的文件：

```go
$ wc /tmp/*.data
  712804 3564024 9979897 /tmp/connections.data
  285316  855948 4400685 /tmp/diskSpace.data
  712523 1425046 8916670 /tmp/memory.data
 1425500 2851000 5702000 /tmp/pageFaults.data
  285658  840622 4313833 /tmp/uptime.data
 3421801 9536640 33313085 total

```

因此，`time(1)`实用程序将测量以下命令：

```go
$ time wc /tmp/*.data /tmp/*.data
$ time wc /tmp/uptime.data /tmp/pageFaults.data
$ time ./dWC /tmp/*.data /tmp/*.data
$ time ./dWC /tmp/uptime.data /tmp/pageFaults.data
$ time ./dWCtotal /tmp/*.data /tmp/*.data
$ time ./dWCtotal /tmp/uptime.data /tmp/pageFaults.data
$ time ./wc /tmp/uptime.data /tmp/pageFaults.data
$ time ./wc /tmp/*.data /tmp/*.data
```

以下图显示了使用`time(1)`实用程序测量上述命令时的实际领域的图形表示：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/go-sys-prog/img/de995173-8729-4a8b-8960-775d6436074c.png)

绘制`time(1)`实用程序的实际领域

原始的`wc(1)`实用程序是迄今为止最快的。此外，`dWC.go`比`dWCtotal.go`和`wc.go`都要快。除了`dWC.go`，其余两个 Go 版本的性能相同。

# 练习

1.  创建一个管道，读取文本文件，找到给定单词的出现次数，并计算所有文件中该单词的总出现次数。

1.  尝试让`dWCtotal.go`更快。

1.  创建一个简单的 Go 程序，使用通道进行乒乓球比赛。您应该使用命令行参数定义乒乓球的总数。

# 总结

在本章中，我们讨论了创建和同步 goroutines，以及创建和使用管道和通道，以使 goroutines 能够相互通信。此外，我们开发了两个使用 goroutines 处理其输入文件的`wc(1)`实用程序的版本。

在继续下一章之前，请确保您充分理解本章的概念，因为在下一章中，我们将讨论与 goroutines 和通道相关的更高级特性，包括共享内存、缓冲通道、`select`关键字、`GOMAXPROCS`环境变量和信号通道。


# 第十章：Goroutines-高级功能

这是本书的第二章，涉及 goroutines：Go 编程语言的最重要特性，以及大大改进 goroutines 功能的通道，我们将从第九章*,* *Goroutines-基本功能*中停止的地方继续进行。

因此，您将学习如何使用各种类型的通道，包括缓冲通道、信号通道、空通道和通道的通道！此外，您还将学习如何在 goroutines 中利用共享内存和互斥锁，以及如何在程序运行时间过长时设置超时。

具体来说，本章将讨论以下主题：

+   缓冲通道

+   `select`关键字

+   信号通道

+   空通道

+   通道的通道

+   设置程序超时并避免无限等待其结束

+   共享内存和 goroutines

+   使用`sync.Mutex`来保护共享数据

+   使用`sync.RWMutex`来保护您的共享数据

+   更改`dWC.go`代码，以支持缓冲通道和互斥锁

# Go 调度程序

在上一章中，我们说内核调度程序负责执行 goroutines 的顺序，这并不完全准确。内核调度程序负责执行程序的线程。Go 运行时有自己的调度程序，负责使用一种称为**m:n 调度**的技术执行 goroutines，其中*m*个 goroutines 使用*n*个操作系统线程进行多路复用。由于 Go 调度程序必须处理单个程序的 goroutines，其操作比内核调度程序的操作要便宜和快得多。

# sync Go 包

在本章中，我们将再次使用`sync`包中的函数和数据类型。特别是，您将了解`sync.Mutex`和`sync.RWMutex`类型及支持它们的函数的用处。

# select 关键字

在 Go 中，`select`语句类似于通道的`switch`语句，并允许 goroutine 等待多个通信操作。因此，使用`select`关键字的主要优势是，同一个函数可以使用单个`select`语句处理多个通道！此外，您可以在通道上进行非阻塞操作。

用于说明`select`关键字的程序的名称将是`useSelect.go`，并将分为五个部分。`useSelect.go`程序允许您生成您想要的随机数，这是在第一个命令行参数中定义的，直到达到某个限制，这是第二个命令行参数。

`useSelect.go`的第一部分如下：

```go
package main 

import ( 
   "fmt" 
   "math/rand" 
   "os" 
   "path/filepath" 
   "strconv" 
   "time" 
) 
```

`useSelect.go`的第二部分如下：

```go
func createNumber(max int, randomNumberChannel chan<- int, finishedChannel chan bool) { 
   for { 
         select { 
         case randomNumberChannel <- rand.Intn(max): 
         case x := <-finishedChannel: 
               if x { 
                     close(finishedChannel) 
                     close(randomNumberChannel) 
                     return 
               } 
         } 
   } 
}

```

在这里，您可以看到`select`关键字如何允许您同时监听和协调两个通道（`randomNumberChannel`和`finishedChannel`）。`select`语句等待通道解除阻塞，然后在该通道上执行。

`createNumber()`函数的`for`循环将不会自行结束。因此，只要`select`语句的`randomNumberChannel`分支被使用，`createNumber()`将继续生成随机数。当`finishedChannel`通道中获取到布尔值`true`时，`createNumber()`函数将退出。

`finishedChannel`通道的更好名称可能是`done`甚至是`noMoreData`。

程序的第三部分包含以下 Go 代码：

```go
func main() { 
   rand.Seed(time.Now().Unix()) 
   randomNumberChannel := make(chan int) 
   finishedChannel := make(chan bool) 

   if len(os.Args) != 3 { 
         fmt.Printf("usage: %s count max\n", filepath.Base(os.Args[0])) 
         os.Exit(1) 
   } 

   n1, _ := strconv.ParseInt(os.Args[1], 10, 64) 
   count := int(n1) 
   n2, _ := strconv.ParseInt(os.Args[2], 10, 64) 
   max := int(n2) 

   fmt.Printf("Going to create %d random numbers.\n", count) 
```

这里没有什么特别的：你只是在启动所需的 goroutine 之前读取命令行参数。

`useSelect.go`的第四部分是您将启动所需的 goroutine 并创建一个`for`循环以生成所需数量的随机数：

```go
   go createNumber(max, randomNumberChannel, finishedChannel) 
   for i := 0; i < count; i++ { 
         fmt.Printf("%d ", <-randomNumberChannel) 
   } 

   finishedChannel <- false 
   fmt.Println() 
   _, ok := <-randomNumberChannel 
   if ok { 
         fmt.Println("Channel is open!") 
   } else { 
         fmt.Println("Channel is closed!") 
   } 
```

在这里，您还可以向`finishedChannel`发送一条消息，并在向`finishedChannel`发送消息后检查`randomNumberChannel`通道是`open`还是`closed`。由于您向`finishedChannel`发送了`false`，因此`finishedChannel`通道将保持`open`。请注意，向`closed`通道发送消息会导致 panic，而从`closed`通道接收消息会立即返回零值。

请注意，一旦关闭通道，就无法向该通道写入。但是，您仍然可以从该通道读取！

`useSelect.go`的最后一部分包含以下 Go 代码：

```go
   finishedChannel <- true
   _, ok = <-randomNumberChannel 
   if ok { 
         fmt.Println("Channel is open!") 
   } else { 
         fmt.Println("Channel is closed!") 
   } 
} 
```

在这里，您向`finishedChannel`发送了`true`值，因此您的通道将关闭，`createNumber()` goroutine 将退出。

运行`useSelect.go`将创建以下输出：

```go
$ go run useSelect.go 2 100
Going to create 2 random numbers.
19 74
Channel is open!
Channel is closed!
```

正如您将在解释缓冲通道的`bufChannels.go`程序中看到的，`select`语句也可以防止缓冲通道溢出。

# 信号通道

**信号通道**是仅用于发出信号的通道。将使用`signalChannel.go`程序来说明信号通道，该程序将使用一个相当不寻常的示例来呈现五个部分。该程序执行四个 goroutines：当第一个完成时，它通过关闭信号通道向信号通道发送信号，这将解除第二个 goroutine 的阻塞。当第二个 goroutine 完成其工作时，它关闭另一个通道，解除其余两个 goroutine 的阻塞。请注意，信号通道与携带`os.Signal`值的通道不同。

程序的第一部分如下：

```go
package main 

import ( 
   "fmt" 
   "time" 
) 

func A(a, b chan struct{}) { 
   <-a 
   fmt.Println("A!") 
   time.Sleep(time.Second) 
   close(b) 
} 
```

`A()`函数被存储在`a`参数中定义的通道阻塞。这意味着在关闭此通道之前，`A()`函数无法继续执行。函数的最后一条语句关闭了存储在`b`变量中的通道，该通道将用于解除其他 goroutines 的阻塞。

程序的第二部分是`B()`函数的实现：

```go
func B(b, c chan struct{}) { 
   <-b 
   fmt.Println("B!") 
   close(c) 
} 
```

同样，`B()`函数被存储在`b`参数中的通道阻塞，这意味着在关闭`b`通道之前，`B()`函数将在其第一条语句中等待。

`signalChannel.go`的第三部分如下：

```go
func C(a chan struct{}) { 
   <-a 
   fmt.Println("C!") 
} 
```

再次，`C()`函数被存储在其`a`参数中的通道阻塞。

程序的第四部分如下：

```go
func main() { 
   x := make(chan struct{}) 
   y := make(chan struct{}) 
   z := make(chan struct{})

```

将信号通道定义为空`struct`而不带任何字段是一种非常常见的做法，因为空结构不占用内存空间。在这种情况下，您可以使用`bool`通道。

`signalChannel.go`的最后一部分包含以下 Go 代码：

```go
   go A(x, y) 
   go C(z) 
   go B(y, z) 
   go C(z) 

   close(x) 
   time.Sleep(2 * time.Second) 
} 
```

在这里，您启动了四个 goroutines。但是，在关闭`a`通道之前，它们都将被阻塞！此外，`A()`将首先完成并解除`B()`的阻塞，然后解除两个`C()` goroutine 的阻塞。因此，这种技术允许您定义 goroutines 的执行顺序。

如果您执行`signalChannel.go`，您将获得以下输出：

```go
$ go run signalChannel.go
A!
B!
C!
C!
```

正如您所看到的，尽管`A()`函数由于`time.Sleep()`函数调用而花费更多时间来执行，但 goroutines 正在按预期顺序执行。

# 缓冲通道

**缓冲通道**允许 Go 调度程序快速将作业放入队列，以便能够处理更多请求。此外，您可以使用缓冲通道作为**信号量**，以限制吞吐量。该技术的工作原理如下：传入的请求被转发到一个通道，该通道一次处理一个请求。当通道完成时，它向原始调用者发送一条消息，表明它已准备好处理新的请求。因此，通道缓冲区的容量限制了它可以保留和处理的同时请求的数量：这可以很容易地使用`for`循环和在其末尾调用`time.Sleep()`来实现。

缓冲通道将在`bufChannels.go`中进行说明，该程序将分为四个部分。

程序的第一部分如下：

```go
package main 

import ( 
   "fmt" 
) 
```

序言证明了您在 Go 程序中不需要任何额外的包来支持缓冲通道。

程序的第二部分包含以下 Go 代码：

```go
func main() { 
   numbers := make(chan int, 5) 
```

在这里，您创建了一个名为`numbers`的新通道，它有`5`个位置，这由`make`语句的最后一个参数表示。这意味着您可以向该通道写入五个整数，而无需读取其中任何一个以为其他整数腾出空间。但是，您不能将六个整数放在具有五个整数位置的通道上！

`bufChannels.go`的第三部分如下：

```go
   counter := 10 
   for i := 0; i < counter; i++ { 
         select { 
         case numbers <- i: 
         default: 
               fmt.Println("Not enough space for", i) 
         } 
   } 
```

在这里，您尝试将`10`个整数放入具有`5`个位置的缓冲通道。但是，使用`select`语句可以让您知道是否有足够的空间来存储所有整数，并相应地采取行动！

`bufChannels.go`的最后一部分如下：

```go
   for i := 0; i < counter*2; i++ { 
         select { 
         case num := <-numbers: 
               fmt.Println(num) 
         default:
               fmt.Println("Nothing more to be done!")    
               break 
         } 
   } 
} 
```

在这里，您还使用了`select`语句，尝试从一个通道中读取 20 个整数。但是，一旦从通道中读取失败，`for`循环就会使用`break`语句退出。这是因为当从`numbers`通道中没有剩余内容可读时，`num := <-numbers`语句将被阻塞，这使得`case`语句转到`default`分支。

从代码中可以看出，`bufChannels.go`中没有 goroutine，这意味着缓冲通道可以自行工作。

执行`bufChannels.go`将生成以下输出：

```go
$ go run bufChannels.go
Not enough space for 5
Not enough space for 6
Not enough space for 7
Not enough space for 8
Not enough space for 9
0
1
2
3
4
Nothing more to be done!
Nothing more to be done!
Nothing more to be done!
Nothing more to be done!
Nothing more to be done!
Nothing more to be done!
Nothing more to be done!
Nothing more to be done!
Nothing more to be done!
Nothing more to be done!
Nothing more to be done!
Nothing more to be done!
Nothing more to be done!
Nothing more to be done!
Nothing more to be done!
```

# 关于超时

您能想象永远等待某件事执行动作吗？我也不能！因此，在本节中，您将学习如何使用`select`语句在 Go 中实现**超时**。

具有示例代码的程序将被命名为`timeOuts.go`，并将分为四个部分进行介绍；第一部分如下：

```go
package main 

import ( 
   "fmt" 
   "time" 
) 
```

`timeOuts.go`的第二部分如下：

```go
func main() { 
   c1 := make(chan string) 
   go func() { 
         time.Sleep(time.Second * 3) 
         c1 <- "c1 OK" 
   }() 
```

goroutine 中的`time.Sleep()`语句用于模拟 goroutine 执行其真正工作所需的时间。

`timeOuts.go`的第三部分包含以下代码：

```go
   select { 
   case res := <-c1: 
         fmt.Println(res) 
   case <-time.After(time.Second * 1): 
         fmt.Println("timeout c1") 
   } 
```

这次，使用`time.After()`是为了声明您希望在超时之前等待的时间。这里的奇妙之处在于，如果`time.After()`的时间到期，而`select`语句没有从`c1`通道接收到任何数据，那么`time.After()`的`case`分支将被执行。

程序的最后一部分将包含以下 Go 代码：

```go
   c2 := make(chan string) 
   go func() { 
         time.Sleep(time.Second * 3) 
         c2 <- "c2 OK" 
   }() 

   select { 
   case res := <-c2: 
         fmt.Println(res) 
   case <-time.After(time.Second * 4): 
         fmt.Println("timeout c2") 
   } 
} 
```

在前面的代码中，您会看到一个操作，它不会超时，因为它在期望的时间内完成了，这意味着`select`块的第一个分支将被执行，而不是表示超时的第二个分支。

执行`timeOuts.go`将生成以下输出：

```go
$ go run timeOuts.go
timeout c1
c2 OK
```

# 实现超时的另一种方法

本小节的技术将让您不必等待任何顽固的 goroutines 完成它们的工作。因此，本小节将向您展示如何通过`timeoutWait.go`程序来设置 goroutines 的超时，该程序将分为四个部分进行介绍。尽管`timeoutWait.go`和`timeOuts.go`之间存在代码差异，但总体思想是完全相同的。

`timeoutWait.go`的第一部分包含了预期的序言：

```go
package main 

import ( 
   "fmt" 
   "sync" 
   "time" 
) 
```

`timeoutWait.go`的第二部分如下：

```go
func timeout(w *sync.WaitGroup, t time.Duration) bool { 
   temp := make(chan int) 
   go func() { 
         defer close(temp) 
         w.Wait() 
   }() 

   select { 
   case <-temp: 
         return false 
   case <-time.After(t): 
         return true 
   } 
} 
```

在这里，您声明了一个执行整个工作的函数。函数的核心是`select`块，其工作方式与`timeOuts.go`中的相同。`timeout()`的匿名函数将在`w.Wait()`语句返回时成功结束，这将在执行适当数量的`sync.Done()`调用时发生，这意味着所有 goroutines 都将完成。在这种情况下，`select`语句的第一个`case`将被执行。

请注意，`temp`通道在`select`块中是必需的，而在其他地方则不需要。此外，`temp`通道的元素类型可以是任何类型，包括`bool`。

`timeOuts.go`的第三部分包含以下代码：

```go
func main() { 
   var w sync.WaitGroup 
   w.Add(1) 

   t := 2 * time.Second 
   fmt.Printf("Timeout period is %s\n", t) 

   if timeout(&w, t) { 
         fmt.Println("Timed out!") 
   } else { 
         fmt.Println("OK!") 
   } 
```

程序的最后一个片段包含以下 Go 代码：

```go
   w.Done() 
   if timeout(&w, t) { 
         fmt.Println("Timed out!") 
   } else { 
         fmt.Println("OK!") 
   } 
} 
```

在预期的`w.Done（）`调用执行后，`timeout（）`函数将返回`true`，这将防止超时发生。

正如在本小节开头提到的，`timeoutWait.go`实际上可以防止您的程序无限期地等待一个或多个 goroutine 结束。

执行`timeoutWait.go`将生成以下输出：

```go
$ go run timeoutWait.go
Timeout period is 2s
Timed out!
OK!
```

# 通道的通道

在本节中，我们将讨论创建和使用通道的通道。使用这样的通道的两个可能原因如下：

+   用于确认操作已完成其工作

+   用于创建许多由相同通道变量控制的工作进程

在本节中将开发的简单程序的名称是`cOfC.go`，将分为四个部分呈现。

程序的第一部分如下：

```go
package main 

import ( 
   "fmt" 
) 

var numbers = []int{0, -1, 2, 3, -4, 5, 6, -7, 8, 9, 10} 
```

程序的第二部分如下：

```go
func f1(cc chan chan int, finished chan struct{}) { 
   c := make(chan int) 
   cc <- c 
   defer close(c) 

   total := 0 
   i := 0 
   for { 
         select { 
         case c <- numbers[i]: 
               i = i + 1 
               i = i % len(numbers) 
               total = total + 1 
         case <-finished: 
               c <- total 
               return 
         } 
   } 
} 
```

`f1（）`函数返回属于`numbers`变量的整数。当它即将结束时，它还使用`c <- total`语句将发送回到`caller`函数的整数数量。

由于您不能直接使用通道的通道，因此您应该首先从中读取（`cc <- c`）并获取实际可以使用的通道。这里方便的是，尽管您可以关闭`c`通道，但通道的通道（`cc`）仍将保持运行。

`cOfC.go`的第三部分如下：

```go
func main() { 
   c1 := make(chan chan int) 
   f := make(chan struct{}) 

   go f1(c1, f) 
   data := <-c1 
```

在这段 Go 代码中，您可以看到可以使用`chan`关键字连续两次声明通道的通道。

`cOfC.go`的最后一部分包含以下 Go 代码：

```go
   i := 0 
   for integer := range data { 
         fmt.Printf("%d ", integer) 
         i = i + 1 
         if i == 100 { 
               close(f) 
         } 
   } 
   fmt.Println() 
} 
```

在这里，通过关闭`f`通道，您限制了将创建的整数数量，当您拥有所需的整数数量时。

执行`cOfC.go`将生成以下输出：

```go
$ go run cOfC.go
0 -1 2 3 -4 5 6 -7 8 9 10 0 -1 2 3 -4 5 6 -7 8 9 10 0 -1 2 3 -4 5 6 -7 8 9 10 0 -1 2 3 -4 5 6 -7 8 9 10 0 -1 2 3 -4 5 6 -7 8 9 10 0 -1 2 3 -4 5 6 -7 8 9 10 0 -1 2 3 -4 5 6 -7 8 9 10 0 -1 2 3 -4 5 6 -7 8 9 10 0 -1 2 3 -4 5 6 -7 8 9 10 0 100
```

通道的通道是 Go 的高级功能，您可能不需要在系统软件中使用。但是，了解其存在是很好的。

# 空通道

本节将讨论**nil 通道**，这是一种特殊类型的通道，它将始终阻塞。程序的名称将是`nilChannel.go`，将分为四个部分呈现。

程序的第一部分包含了预期的序言：

```go
package main 

import ( 
   "fmt" 
   "math/rand" 
   "time" 
) 
```

第二部分包含`addIntegers（）`函数的实现：

```go
func addIntegers(c chan int) { 
   sum := 0 
   t := time.NewTimer(time.Second) 

   for { 
         select { 
         case input := <-c: 
               sum = sum + input 
         case <-t.C: 
               c = nil 
               fmt.Println(sum) 
         } 
   } 
} 
```

`addIntegers（）`函数在`time.NewTimer（）`函数定义的时间过去后停止，并将转到`case`语句的相关分支。在那里，它将使`c`成为 nil 通道，这意味着通道将停止接收新数据，并且函数将在那里等待。

`nilChannel.go`的第三部分如下：

```go
func sendIntegers(c chan int) { 
   for { 
         c <- rand.Intn(100) 
   } 
} 
```

在这里，`sendIntegers（）`函数会继续生成随机数并将它们发送到`c`通道，只要`c`通道是打开的。但是，这里还有一个永远不会被清理的 goroutine。

程序的最后一部分包含以下 Go 代码：

```go
func main() { 
   c := make(chan int) 
   go addIntegers(c) 
   go sendIntegers(c) 
   time.Sleep(2 * time.Second) 
} 
```

执行`nilChannel.go`将生成以下输出：

```go
$ go run nilChannel.go
162674704
$ go run nilChannel.go
165021841
```

# 共享内存

共享内存是线程之间进行通信的传统方式。Go 具有内置的同步功能，允许单个 goroutine 拥有共享数据的一部分。这意味着其他 goroutine 必须向拥有共享数据的单个 goroutine 发送消息，这可以防止数据的损坏！这样的 goroutine 称为**监视器 goroutine**。在 Go 术语中，这是通过通信进行共享，而不是通过共享进行通信。

这种技术将在`sharedMem.go`程序中进行演示，该程序将分为五个部分呈现。`sharedMem.go`的第一部分包含以下 Go 代码：

```go
package main 

import ( 
   "fmt" 
   "math/rand" 
   "sync" 
   "time" 
) 
```

第二部分如下：

```go
var readValue = make(chan int) 
var writeValue = make(chan int) 

func SetValue(newValue int) { 
   writeValue <- newValue 
} 

func ReadValue() int { 
   return <-readValue 
} 
```

`ReadValue()`函数用于读取共享变量，而`SetValue()`函数用于设置共享变量的值。此外，程序中使用的两个通道需要是全局变量，以避免将它们作为程序所有函数的参数传递。请注意，这些全局变量通常被封装在一个 Go 库或带有方法的`struct`中。

`sharedMem.go`的第三部分如下：

```go
func monitor() { 
   var value int 
   for { 
         select { 
         case newValue := <-writeValue: 
               value = newValue 
               fmt.Printf("%d ", value) 
         case readValue <- value: 
         } 
   } 
} 
```

`sharedMem.go`的逻辑可以在`monitor()`函数的实现中找到。当你有一个读取请求时，`ReadValue()`函数尝试从`readValue`通道读取。然后，`monitor()`函数返回`value`参数中保存的当前值。同样，当你想要改变存储的值时，你调用`SetValue()`，它会写入`writeValue`通道，也由`select`语句处理。再次，`select`块起着关键作用，因为它协调了`monitor()`函数的操作。

程序的第四部分包含以下 Go 代码：

```go
func main() { 
   rand.Seed(time.Now().Unix()) 
   go monitor() 
   var waitGroup sync.WaitGroup 

   for r := 0; r < 20; r++ { 
         waitGroup.Add(1) 
         go func() { 
               defer waitGroup.Done() 
               SetValue(rand.Intn(100)) 
         }() 
   } 
```

程序的最后部分如下：

```go
   waitGroup.Wait() 
   fmt.Printf("\nLast value: %d\n", ReadValue()) 
} 
```

执行`sharedMem.go`将生成以下输出：

```go
$ go run sharedMem.go
33 45 67 93 33 37 23 85 87 23 58 61 9 57 20 61 73 99 42 99
Last value: 99
$ go run sharedMem.go
71 66 58 83 55 30 61 73 94 19 63 97 12 87 59 38 48 81 98 49
Last value: 49
```

如果你想共享更多的值，你可以定义一个新的结构，用来保存所需的变量和你喜欢的数据类型。

# 使用 sync.Mutex

**Mutex**是**mutual exclusion**的缩写；`Mutex`变量主要用于线程同步和保护共享数据，当多个写操作可能同时发生时。互斥锁的工作原理类似于容量为 1 的缓冲通道，最多允许一个 goroutine 同时访问共享变量。这意味着没有两个或更多的 goroutine 可以同时尝试更新该变量。虽然这是一种完全有效的技术，但一般的 Go 社区更倾向于使用前一节介绍的`monitor` goroutine 技术。

为了使用`sync.Mutex`，你必须首先声明一个`sync.Mutex`变量。你可以使用`Lock`方法锁定该变量，并使用`Unlock`方法释放它。`sync.Lock()`方法为你提供了对共享变量的独占访问，这段代码区域在调用`Unlock()`方法时结束，被称为**关键部分**。

程序的每个关键部分在使用`sync.Lock()`进行锁定之前都不能执行。然而，如果锁已经被占用，每个人都应该等待其释放。虽然多个函数可能会等待获取锁，但只有当它被释放时，其中一个函数才会获取到它。

你应该尽量将关键部分设计得尽可能小；换句话说，不要延迟释放锁，因为其他 goroutines 可能想要使用它。此外，忘记解锁`Mutex`很可能会导致死锁。

用于演示`sync.Mutex`的 Go 程序的名称将是`mutexSimple.go`，并将以五个部分呈现。

`mutexSimple.go`的第一部分包含了预期的序言：

```go
package main 

import ( 
   "fmt" 
   "os" 
   "path/filepath" 
   "strconv" 
   "sync" 
) 
```

程序的第二部分如下：

```go
var aMutex sync.Mutex 
var sharedVariable string = "" 

func addDot() { 
   aMutex.Lock() 
   sharedVariable = sharedVariable + "." 
   aMutex.Unlock() 
} 
```

请注意，关键部分并不总是显而易见，你在指定时应该非常小心。还要注意，当两个关键部分使用相同的`Mutex`变量时，一个关键部分不能嵌套在另一个关键部分中！简单地说，几乎要以所有的代价避免在函数之间传递互斥锁，因为这样很难看出你是否嵌套了互斥锁！

在这里，`addDot（）`在`sharedVariable`字符串的末尾添加一个点字符。但是，由于字符串应该同时被多个 goroutine 改变，所以您使用`sync.Mutex`变量来保护它。由于关键部分只包含一个命令，获取对互斥体的访问的等待时间将非常短，甚至是瞬时的。但是，在现实世界的情况下，等待时间可能会更长，特别是在诸如数据库服务器之类的软件上，成千上万的进程同时发生许多事情：您可以通过在关键部分添加对`time.Sleep（）`的调用来模拟这一点。

请注意，将互斥体与一个或多个共享变量相关联是开发人员的责任！

`mutexSimple.go`的第三个代码段是另一个使用互斥体的函数的实现：

```go
func read() string { 
   aMutex.Lock() 
   a := sharedVariable 
   aMutex.Unlock() 
   return a 
} 
```

尽管在读取共享变量时锁定共享变量并不是绝对必要的，但这种锁定可以防止在读取时共享变量发生更改。在这里可能看起来像一个小问题，但想象一下读取您的银行账户余额！

第四部分是您定义要启动的 goroutine 数量的地方：

```go
func main() { 
   if len(os.Args) != 2 { 
         fmt.Printf("usage: %s n\n", filepath.Base(os.Args[0])) 
         os.Exit(1) 
   } 

   numGR, _ := strconv.ParseInt(os.Args[1], 10, 64) 
   var waitGroup sync.WaitGroup 
```

`mutexSimple.go`的最后一部分包含以下 Go 代码：

```go
   var i int64 
   for i = 0; i < numGR; i++ { 
         waitGroup.Add(1) 
         go func() { 
               defer waitGroup.Done() 
               addDot() 
         }() 
   } 
   waitGroup.Wait() 
   fmt.Printf("-> %s\n", read()) 
   fmt.Printf("Length: %d\n", len(read())) 
} 
```

在这里，您启动所需数量的 goroutine。每个 goroutine 调用`addDot（）`函数来访问共享变量：然后等待它们完成，然后使用`read（）`函数读取共享变量的值。

执行`mutexSimple.go`将生成类似以下的输出：

```go
$ go run mutexSimple.go 20
-> ....................
Length: 20
$ go run mutexSimple.go 30
-> ..............................
Length: 30
```

# 使用 sync.RWMutex

Go 提供了另一种类型的互斥体，称为`sync.RWMutex`，它允许多个读取者持有锁，但只允许单个写入者 - `sync.RWMutex`是`sync.Mutex`的扩展，添加了两个名为`sync.RLock`和`sync.RUnlock`的方法，用于读取目的的锁定和解锁。对于独占写入，应分别使用`Lock（）`和`Unlock（）`来锁定和解锁`sync.RWMutex`。

这意味着要么一个写入者可以持有锁，要么多个读取者可以持有锁：不能同时两者都有！当大多数 goroutine 想要读取一个变量而您不希望 goroutine 等待以获取独占锁时，您很可能会使用这样的互斥体。

为了让`sync.RWMutex`变得更加透明，您应该发现`sync.RWMutex`类型是一个 Go 结构，当前定义如下：

```go
type RWMutex struct { 
   w           Mutex 
   writerSem   uint32 
   readerSem   uint32  
   readerCount int32 
   readerWait  int32 
}                
```

所以，这里没有什么可害怕的！现在，是时候看一个使用`sync.RWMutex`的 Go 程序了。该程序将被命名为`mutexRW.go`，并将分为五个部分呈现。

`mutexRW.go`的第一部分包含预期的序言以及全局变量和新的`struct`类型的定义：

```go
package main 

import ( 
   "fmt" 
   "sync" 
   "time" 
) 

var Password = secret{counter: 1, password: "myPassword"} 

type secret struct { 
   sync.RWMutex 
   counter  int 
   password string 
} 
```

`secret`结构嵌入了`sync.RWMutex`，因此它可以调用`sync.RWMutex`的所有方法。

`mutexRW.go`的第二部分包含以下 Go 代码：

```go
func Change(c *secret, pass string) { 
   c.Lock() 
   fmt.Println("LChange") 
   time.Sleep(20 * time.Second) 
   c.counter = c.counter + 1 
   c.password = pass 
   c.Unlock() 
} 
```

此函数对其一个参数进行更改，这意味着它需要一个独占锁，因此使用了`Lock（）`和`Unlock（）`函数。

示例代码的第三部分如下：

```go
func Show(c *secret) string { 
   fmt.Println("LShow") 
   time.Sleep(time.Second)

   c.RLock() 
   defer c.RUnlock() 
   return c.password 
} 

func Counts(c secret) int { 
   c.RLock() 
   defer c.RUnlock() 
   return c.counter 
} 
```

在这里，您可以看到使用`sync.RWMutex`进行读取的两个函数的定义。这意味着它们的多个实例可以获取`sync.RWMutex`锁。

程序的第四部分如下：

```go
func main() { 
   fmt.Println("Pass:", Show(&Password)) 
   for i := 0; i < 5; i++ { 
         go func() { 
               fmt.Println("Go Pass:", Show(&Password)) 
         }() 
   } 
```

在这里，您启动五个 goroutine 以使事情更有趣和随机。

`mutexRW.go`的最后一部分如下：

```go
   go func() { 
         Change(&Password, "123456") 
   }() 

   fmt.Println("Pass:", Show(&Password)) 
   time.Sleep(time.Second) 
   fmt.Println("Counter:", Counts(Password)) 
} 
```

尽管共享内存和使用互斥体仍然是并发编程的有效方法，但使用 goroutine 和通道是一种更现代的方式，符合 Go 的哲学。因此，如果可以使用通道和管道解决问题，您应该优先选择这种方式，而不是使用共享变量。

执行`mutexRW.go`将生成以下输出：

```go
$ go run mutexRW.go
LShow
Pass: myPassword
LShow
LShow
LShow
LShow
LShow
LShow
LChange
Go Pass: 123456
Go Pass: 123456
Pass: 123456
Go Pass: 123456
Go Pass: 123456
Go Pass: 123456
Counter: 2
```

如果`Change()`的实现也使用了`RLock()`调用以及`RUnlock()`调用，那将是完全错误的，那么程序的输出将如下所示：

```go
$ go run mutexRW.go
LShow
Pass: myPassword
LShow
LShow
LShow
LShow
LShow
LShow
LChange
Go Pass: myPassword
Pass: myPassword
Go Pass: myPassword
Go Pass: myPassword
Go Pass: myPassword
Go Pass: myPassword
Counter: 1
```

简而言之，你应该充分了解你正在使用的锁定机制以及它的工作方式。在这种情况下，决定`Counts()`将返回什么的是时间：时间取决于`Change()`函数中的`time.Sleep()`调用，它模拟了实际函数中将发生的处理。问题在于，在`Change()`中使用`RLock()`和`RUnlock()`允许多个 goroutine 读取共享变量，因此从`Counts()`函数中获得错误的输出。

# 重新审视 dWC.go 实用程序

在本节中，我们将改变在上一章中开发的`dWC.go`实用程序的实现。

程序的第一个版本将使用缓冲通道，而程序的第二个版本将使用共享内存来保持你处理的每个文件的计数。

# 使用缓冲通道

这个实现的名称将是`WCbuffered.go`，并将分为五个部分呈现。

实用程序的第一部分如下：

```go
package main 

import ( 
   "bufio" 
   "fmt" 
   "io" 
   "os" 
   "path/filepath" 
   "regexp" 
) 

type File struct { 
   Filename   string 
   Lines      int 
   Words      int 
   Characters int 
   Error      error 
} 
```

`File`结构将为每个输入文件保留计数。`WCbuffered.go`的第二部分包含以下 Go 代码：

```go
func monitor(values <-chan File, count int) { 
   var totalWords int = 0 
   var totalLines int = 0 
   var totalChars int = 0 
   for i := 0; i < count; i++ { 
         x := <-values 
         totalWords = totalWords + x.Words 
         totalLines = totalLines + x.Lines 
         totalChars = totalChars + x.Characters 
         if x.Error == nil { 
               fmt.Printf("\t%d\t", x.Lines) 
               fmt.Printf("%d\t", x.Words) 
               fmt.Printf("%d\t", x.Characters) 
               fmt.Printf("%s\n", x.Filename) 
         } else { 
               fmt.Printf("\t%s\n", x.Error) 
         } 
   } 
   fmt.Printf("\t%d\t", totalLines) 
   fmt.Printf("%d\t", totalWords) 
   fmt.Printf("%d\ttotal\n", totalChars) 
} 
```

`monitor()`函数收集所有信息并打印出来。`monitor()`内部的`for`循环确保它将收集到正确数量的数据。

程序的第三部分包含了`count()`函数的实现：

```go
func count(filename string, out chan<- File) { 
   var err error 
   var nLines int = 0 
   var nChars int = 0 
   var nWords int = 0 

   f, err := os.Open(filename) 
   defer f.Close() 
   if err != nil { 
         newValue := File{ 
Filename: filename, 
Lines: 0, 
Characters: 0, 
Words: 0, 
Error: err } 
         out <- newValue 
         return 
   } 

   r := bufio.NewReader(f) 
   for { 
         line, err := r.ReadString('\n') 

         if err == io.EOF { 
               break 
         } else if err != nil { 
               fmt.Printf("error reading file %s\n", err) 
         } 
         nLines++ 
         r := regexp.MustCompile("[^\\s]+") 
         for range r.FindAllString(line, -1) { 
               nWords++ 
         } 
         nChars += len(line) 
   } 
   newValue := File { 
Filename: filename, 
Lines: nLines, 
Characters: nChars, 
Words: nWords, 
Error: nil }

   out <- newValue

} 
```

当`count()`函数完成时，它会将信息发送到缓冲通道，因此这里没有什么特别的。

`WCbuffered.go`的第四部分如下：

```go
func main() { 
   if len(os.Args) == 1 { 
         fmt.Printf("usage: %s <file1> [<file2> [... <fileN]]\n", 
               filepath.Base(os.Args[0])) 
         os.Exit(1) 
   } 

   values := make(chan File, len(os.Args[1:])) 
```

在这里，你创建了一个名为`values`的缓冲通道，其位置数与你将处理的文件数相同。

实用程序的最后一部分如下：

```go
   for _, filename := range os.Args[1:] {
         go func(filename string) { 
               count(filename, values) 
         }(filename) 
   } 
   monitor(values, len(os.Args[1:])) 
} 
```

# 使用共享内存

共享内存和互斥锁的好处在于，理论上它们通常只占用很小一部分代码，这意味着其余的代码可以在没有其他延迟的情况下并发工作。然而，只有在你实现了某些东西之后，你才能看到真正发生了什么！

这个实现的名称将是`WCshared.go`，并将分为五个部分：实用程序的第一部分如下：

```go
package main 

import ( 
   "bufio" 
   "fmt" 
   "io" 
   "os" 
   "path/filepath" 
   "regexp" 
   "sync" 
) 

type File struct { 
   Filename   string 
   Lines      int 
   Words      int 
   Characters int 
   Error      error 
} 

var aM sync.Mutex 
var values = make([]File, 0) 
```

`values`切片将是程序的共享变量，而互斥变量的名称将是`aM`。

`WCshared.go`的第二部分包含以下 Go 代码：

```go
func count(filename string) { 
   var err error 
   var nLines int = 0 
   var nChars int = 0 
   var nWords int = 0 

   f, err := os.Open(filename) 
   defer f.Close() 
   if err != nil { 
         newValue := File{Filename: filename, Lines: 0, Characters: 0, Words: 0, Error: err} 
         aM.Lock() 
         values = append(values, newValue) 
         aM.Unlock() 
         return 
   } 

   r := bufio.NewReader(f) 
   for { 
         line, err := r.ReadString('\n') 

         if err == io.EOF { 
               break 
         } else if err != nil { 
               fmt.Printf("error reading file %s\n", err) 
         } 
         nLines++ 
         r := regexp.MustCompile("[^\\s]+") 
         for range r.FindAllString(line, -1) { 
               nWords++ 
         } 
         nChars += len(line) 
   } 

   newValue := File{Filename: filename, Lines: nLines, Characters: nChars, Words: nWords, Error: nil} 
   aM.Lock() 
   values = append(values, newValue) 
   aM.Unlock() 
} 
```

因此，在`count()`函数退出之前，它会使用临界区向`values`切片添加一个元素。

`WCshared.go`的第三部分如下：

```go
func main() { 
   if len(os.Args) == 1 { 
         fmt.Printf("usage: %s <file1> [<file2> [... <fileN]]\n", 
               filepath.Base(os.Args[0])) 
         os.Exit(1) 
   } 
```

在这里，你只需要处理实用程序的命令行参数。

`WCshared.go`的第四部分包含以下 Go 代码：

```go
   var waitGroup sync.WaitGroup 
   for _, filename := range os.Args[1:] { 
         waitGroup.Add(1) 
         go func(filename string) { 
               defer waitGroup.Done() 
               count(filename) 
         }(filename) 
   } 

   waitGroup.Wait()
```

在这里，你只需启动所需数量的 goroutine，并等待它们完成工作。

实用程序的最后一部分如下：

```go
   var totalWords int = 0 
   var totalLines int = 0 
   var totalChars int = 0 
   for _, x := range values { 
         totalWords = totalWords + x.Words 
         totalLines = totalLines + x.Lines 
         totalChars = totalChars + x.Characters 
         if x.Error == nil { 
               fmt.Printf("\t%d\t", x.Lines) 
               fmt.Printf("%d\t", x.Words) 
               fmt.Printf("%d\t", x.Characters) 
               fmt.Printf("%s\n", x.Filename) 
         } 
   } 
   fmt.Printf("\t%d\t", totalLines) 
   fmt.Printf("%d\t", totalWords) 
   fmt.Printf("%d\ttotal\n", totalChars) 
}
```

当所有 goroutine 都完成时，就该处理共享变量的内容，计算总数，并打印所需的输出。请注意，在这种情况下，没有任何类型的共享变量，因此不需要互斥锁：你只需等待收集所有结果并打印它们。

# 更多的基准测试

本节将使用方便的`time(1)`实用程序来测量`WCbuffered.go`和`WCshared.go`的性能。然而，这一次，我不会呈现图表，而是会给你`time(1)`实用程序的实际输出：

```go
$ time go run WCshared.go /tmp/*.data /tmp/*.data
real  0m31.836s
user  0m31.659s
sys   0m0.165s
$ time go run WCbuffered.go /tmp/*.data /tmp/*.data
real  0m31.823s
user  0m31.656s
sys   0m0.171s
```

正如你所看到的，这两个实用程序的性能都很好，或者如果你愿意的话，也可以说都很糟糕！然而，除了程序的速度之外，还有其设计的清晰度以及对其进行代码更改的易用性也很重要！此外，所呈现的方式还会计算这两个实用程序的编译时间，这可能会使结果不太准确。

这两个程序之所以能够轻松生成总数，是因为它们都有一个控制点。对于`WCshared.go`实用程序，控制点是共享变量，而对于`WCbuffered.go`，控制点是在`monitor()`函数内收集所需信息的缓冲通道。

# 检测竞争条件

如果在运行或构建 Go 程序时使用`-race`标志，将启用 Go **竞争检测器**，这将使编译器创建典型可执行文件的修改版本。这个修改版本可以记录对共享变量的访问以及发生的所有同步事件，包括对`sync.Mutex`、`sync.WaitGroup`等的调用。在对事件进行一些分析后，竞争检测器会打印一个报告，可以帮助您识别潜在问题，以便您可以纠正它们。

为了展示竞争检测器的操作，我们将使用`rd.go`程序的代码，它将分为四个部分呈现。对于这个特定的程序，**数据竞争**将会发生，因为两个或更多的 goroutine 同时访问同一个变量，并且其中至少一个以某种方式改变了变量的值。

请注意，`main()`程序在 Go 中也是一个 goroutine！

程序的第一部分如下：

```go
package main 

import ( 
   "fmt" 
   "os" 
   "path/filepath" 
   "strconv" 
   "sync" 
) 
```

这里没有什么特别的，所以如果程序有问题，那就不是在前言中。

`rd.go`的第二部分如下：

```go
func main() { 
   arguments := os.Args 
   if len(arguments) != 2 { 
         fmt.Printf("usage: %s number\n", filepath.Base(arguments[0])) 
         os.Exit(1) 
   } 
   numGR, _ := strconv.ParseInt(os.Args[1], 10, 64) 
   var waitGroup sync.WaitGroup 
   var i int64 
```

在这个特定的代码中，没有任何问题。

`rd.go`的第三部分具有以下 Go 代码：

```go
   for i = 0; i < numGR; i++ { 
         waitGroup.Add(1) 
         go func() { 
               defer waitGroup.Done() 
               fmt.Printf("%d ", i) 
         }() 
   } 
```

这段代码非常可疑，因为您试图打印一个由于`for`循环而不断变化的变量的值。

`rd.go`的最后一部分如下：

```go
   waitGroup.Wait() 
   fmt.Println("\nExiting...") 
} 
```

最后一部分代码中没有什么特别的。

为`rd.go`启用 Go 竞争检测器将生成以下输出：

```go
$ go run -race rd.go 10 ================== WARNING: DATA RACE
Read at 0x00c420074168 by goroutine 6:
  main.main.func1()
      /Users/mtsouk/Desktop/goBook/ch/ch10/code/rd.go:25 +0x6c

Previous write at 0x00c420074168 by main goroutine:
  main.main()
      /Users/mtsouk/Desktop/goBook/ch/ch10/code/rd.go:21 +0x30c

Goroutine 6 (running) created at:
  main.main()
      /Users/mtsouk/Desktop/goBook/ch/ch10/code/rd.go:26 +0x2e2
==================
==================
WARNING: DATA RACE
Read at 0x00c420074168 by goroutine 7:
 main.main.func1()
     /Users/mtsouk/Desktop/goBook/ch/ch10/code/rd.go:25 +0x6c

Previous write at 0x00c420074168 by main goroutine:
 main.main()
     /Users/mtsouk/Desktop/goBook/ch/ch10/code/rd.go:21 +0x30c

Goroutine 7 (running) created at:
  main.main()
      /Users/mtsouk/Desktop/goBook/ch/ch10/code/rd.go:26 +0x2e2
==================
2 3 4 4 5 6 7 8 9 10
Exiting...
Found 2 data race(s)
exit status 66 
```

因此，竞争检测器发现了两个数据竞争。第一个发生在数字`1`根本没有被打印出来时，第二个发生在数字`4`被打印两次时。此外，尽管`i`的初始值是数字`0`，但数字`0`并没有被打印出来。最后，你不应该在输出中得到数字`10`，但你确实得到了，因为`i`的最后一个值确实是`10`。请注意，在前面的输出中找到的`main.main.func1()`表示 Go 谈论的是一个匿名函数。

简而言之，前两条消息告诉您的是，`i`变量有问题，因为当程序的 goroutine 尝试读取它时，它一直在变化。此外，您无法确定地告诉会先发生什么。

在没有竞争检测器的情况下运行相同的程序将生成以下输出：

```go
$ go run rd.go 10
10 10 10 10 10 10 10 10 10 10
Exiting...
```

`rd.go`中的问题可以在匿名函数中找到。由于匿名函数不带参数，它使用`i`的当前值，这个值无法确定，因为它取决于操作系统和 Go 调度程序：这就是竞争情况发生的地方！因此，请记住，最容易出现竞争条件的地方之一是在从匿名函数生成的 goroutine 内部！因此，如果您必须解决这种情况，请首先将匿名函数转换为具有定义参数的常规函数！

使用竞争检测器的程序比没有竞争检测器的程序更慢，需要更多的 RAM。最后，如果竞争检测器没有任何报告，它将不会生成任何输出。

# 关于 GOMAXPROCS

`GOMAXPROCS`环境变量（和 Go 函数）允许您限制可以同时执行用户级 Go 代码的操作系统线程的数量。

从 Go 版本 1.5 开始，默认值`GOMAXPROCS`应该是您的 Unix 系统上可用的核心数。

尽管在 Unix 机器上使用小于核心数的`GOMAXPROCS`值可能会影响程序的性能，但指定大于可用核心数的`GOMAXPROCS`值不会使程序运行更快！

`goMaxProcs.go`的代码允许您确定`GOMAXPROCS`的值-它将分为两部分呈现。

第一部分如下：

```go
package main 

import ( 
   "fmt" 
   "runtime" 
) 

func getGOMAXPROCS() int {
   return runtime.GOMAXPROCS(0) 
} 
```

第二部分如下：

```go
func main() { 
   fmt.Printf("GOMAXPROCS: %d\n", getGOMAXPROCS()) 
} 
```

在支持超线程的 Intel i7 机器上执行`goMaxProcs.go`并使用最新的 Go 版本会得到以下输出：

```go
$ go run goMaxProcs.go 
GOMAXPROCS: 8 
```

然而，如果您在运行旧版 Go 的 Debian Linux 机器上执行`goMaxProcs.go`并且有一个旧处理器，它将生成以下输出：

```go
$ go version 
go version go1.3.3 linux/amd64 
$ go run goMaxProcs.go 
GOMAXPROCS: 1 
```

动态更改`GOMAXPROCS`的值的方法如下：

```go
$ export GOMAXPROCS=80; go run goMaxProcs.go 
GOMAXPROCS: 80 
```

但是，设置大于`256`的值将不起作用：

```go
$ export GOMAXPROCS=800; go run goMaxProcs.go 
GOMAXPROCS: 256 
```

最后，请记住，如果您使用单个核心运行诸如`dWC.go`之类的并发程序，则并发版本的程序可能不会比没有 goroutines 的程序版本运行得更快！在某些情况下，这是因为 goroutines 的使用以及对`sync.Add`、`sync.Wait`和`sync.Done`函数的各种调用会减慢程序的性能。可以通过以下输出来验证：

```go
$ export GOMAXPROCS=8; time go run dWC.go /tmp/*.data

real  0m10.826s
user  0m31.542s
sys   0m5.043s
$ export GOMAXPROCS=1; time go run dWC.go /tmp/*.data

real  0m15.362s
user  0m15.253s
sys   0m0.103s
$ time go run wc.go /tmp/*.data

real  0m15.158sexit
user  0m15.023s
sys   0m0.120s
```

# 练习

1.  仔细阅读可以在[`golang.org/pkg/sync/`](https://golang.org/pkg/sync/)找到的`sync`包的文档页面。

1.  尝试使用与本章节中使用的不同的共享内存技术来实现`dWC.go`。

1.  实现一个`struct`数据类型，它保存您的账户余额，并创建读取您拥有的金额并对金额进行更改的函数。创建一个使用`sync.RWMutex`和另一个使用`sync.Mutex`的实现。

1.  如果你在`mutexRW.go`中到处使用`Lock()`和`Unlock()`而不是`RLock()`和`RUnlock()`，会发生什么？

1.  尝试使用 goroutines 从第五章*,* *文件和目录*中实现`traverse.go`。

1.  尝试使用 goroutines 从第五章*,* *文件和目录*中创建`improvedFind.go`的实现。

# 摘要

本章讨论了与 goroutines、通道和并发编程相关的一些高级 Go 特性。然而，本章的教训是通道可以做很多事情，并且可以在许多情况下使用，这意味着开发人员必须能够根据自己的经验选择适当的技术来实现任务。

下一章的主题将是 Go 中的 Web 开发，其中将包含非常有趣的材料，包括发送和接收 JSON 数据，开发 Web 服务器和 Web 客户端，以及从您的 Go 代码与 MongoDB 数据库交互。
