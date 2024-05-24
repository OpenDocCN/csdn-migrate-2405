# Go 编程实用手册（二）

> 原文：[`zh.annas-archive.org/md5/62FC08F1461495F0676A88A03EA0ECBA`](https://zh.annas-archive.org/md5/62FC08F1461495F0676A88A03EA0ECBA)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第八章：并发

Go 最强大的一点是它与 API 的并发。在本章中，你将学习如何在 Go 语言中利用并发构造。本章将涵盖以下主题：

+   并发运行多个函数

+   在并发运行函数之间传递数据

+   等待所有并发函数完成

+   选择并发函数的结果

# 并发运行多个函数

让我们开始并发运行多个函数。

看一下以下代码块中的代码：

```go
import (
  "fmt"
  "time"
)

func main() {

  names := []string{"tarik", "john", "michael", "jessica"}

  for _, name := range names {
   time.Sleep(1 * time.Second)
   fmt.Println(name)
  }
ages := []int{1, 2, 3, 4, 5}
  for _, age:= range ages {
    time.Sleep(1 * time.Second)
    fmt.Println(age)
  }
}
```

从上面的代码可以看出，有两个不同的列表；每个列表都有至少花费一秒钟才能完成的项目，但出于练习目的，我们不会有任何实际的代码，只是`fmt.Println`。我们在每次迭代中都添加了`time.Sleep`一秒钟。如前面的代码所示，我们首先处理名称，然后处理年龄。你可以注意到的一件事是它们实际上并不相互依赖；它们实际上是两项不同的工作。所以，让我们继续运行这个程序，看看在控制台上的效果如何：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/hsn-go-prog/img/721b22d0-b2f7-4f4b-a57f-5a724a78e8cf.png)

如果你观察输出的过程，你会发现每行输出在传递下一个之前等待了一秒钟。你会发现它们实际上是顺序的代码片段，尽管它们并不相互依赖。在继续到第二个`for`循环之前，我们必须等待循环完成。

我们可以通过使用并发模式使这个过程更具可扩展性和效率。为此，我们将在 Go 中使用 Go 例程。Go 例程比线程更轻量级，而且与线程不同，它们是自愿地而不是强制性地交还控制权。随着我们继续前进，你会更多地了解我所说的具体含义。检查以下代码：

```go
package main

import (
  "fmt"
  "time"
)
func main() {

  go func() {
    names := []string{"tarik", "john", "michael", "jessica"}

    for _, name := range names {
      time.Sleep(1 * time.Second)
      fmt.Println(name)
    }
  }()

  go func(){
    ages := []int{1, 2, 3, 4, 5}
    for _, age:= range ages {
      time.Sleep(1 * time.Second)
      fmt.Println(age)
    }
  }()
  time.Sleep(10*time.Second)
}
```

如你所见，我们已经将代码转换为独立的功能片段，使用了 Go 关键字和匿名函数来创建 Go 例程。我们对年龄也做了同样的事情。运行代码时，你将得到以下输出：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/hsn-go-prog/img/5e34080c-da13-44f9-8bae-8c9aefd3ebb9.png)

如你所见，与以前顺序显示输出不同，它是随机显示的。这意味着两个循环是同时进行处理的。

如果我们移除`time.Sleep`（使用`//`注释掉它），我们将在控制台上看不到任何结果。这是因为主应用程序也是在一个 Go 例程下运行的，这意味着我们有三个 Go 例程：我们输入的两个和整个主应用程序。如前所述，问题在于 Go 例程自愿地而不是强制性地将控制权交还给其他 Go 例程。这意味着当你使用`time.Sleep`时，控制权将交给其他 Go 例程，我们的系统将正常工作。

现在，如果我们使用`1`秒而不是上次代码中看到的`10`秒，会发生什么？你将得不到任何输出。这是因为`1`秒对于所有 Go 例程来说不足以完成任务。一旦主 Go 例程完成了它的处理，它就会关闭整个应用程序，并且不会给其他 Go 例程足够的时间来完成。有一种处理这种情况的方法，我们有另一个叫做通道的构造。因此，为了简单起见，我们将删除第二个 Go 例程，现在使用通道。检查以下代码：

```go
package main

import (
    "time"
  "fmt"
)

func main() {

  nameChannel := make(chan string)

  go func() {
    names := []string{"tarik", "john", "michael", "jessica"}

    for _, name := range names {
    time.Sleep(1 * time.Second)
      //fmt.Println(name)
    nameChannel <- name
    }
  }()

  for data:= range nameChannel{
    fmt.Println(data)
  }
}
```

当你运行上面的代码时，你将得到以下异常：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/hsn-go-prog/img/0fac42a1-dd9c-4212-b301-4fe2103f88c3.png)

出现这种异常的原因是，当你完成一个通道时，你需要关闭它，否则`for`循环将一直等待。然而，因为你的 Go 例程已经完成了该通道，循环将陷入死锁并停止你的应用程序。关闭通道的一种方法是添加下面突出显示的代码行：

```go
package main

import (
    "time"
  "fmt"
)

func main() {

  nameChannel := make(chan string)

  go func() {
    names := []string{"tarik", "john", "michael", "jessica"}

    for _, name := range names {
    time.Sleep(1 * time.Second)
      //fmt.Println(name)
    nameChannel <- name
    }
    close(nameChannel)
    //nameChannel <- ""
  }()

  for data:= range nameChannel{
    fmt.Println(data)

    }

  //<-nameChannel
}
```

当一个通道关闭时，循环将终止。所以，让我们继续运行这个程序并检查输出：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/hsn-go-prog/img/6f1d0e64-646b-4cb4-ae45-044c555a6f24.png)

如您所见，这里没有任何异常，一切看起来都很好。如果您不关心结果，并且想要使用我们的第一种方法，可以使用以下代码：

```go
package main

import (
  "fmt"
  "time"
)

func main() {
  nameChannel := make(chan string)
  go func() {
    names := []string{"tarik", "john", "michael", "jessica"}
    for _, name := range names {
      time.Sleep(1 * time.Second)
      fmt.Println(name)
    }
    nameChannel <- ""
  }()
  <-nameChannel
}
```

我们所做的是将所有内容写入控制台，一旦循环结束，就设置了`nameChannel`。此外，在这种情况下，我们会等待直到从名称通道获取一些数据，因此不会终止应用程序。一旦从名称通道获取到一些数据，我们就会读取它，但实际上并不会将其分配给任何变量。当`main` Go 例程继续执行到下一行时，那里没有代码，因此`main`函数退出。因此，我们的应用程序关闭了。您将获得以下输出：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/hsn-go-prog/img/bc660bd9-45d1-4133-9054-387c8f3783c3.png)

这就是您可以使用通道和函数执行并发操作的方法。在结束之前，让我们重申一点关于通道。如果通道为空并且您尝试读取它，它将阻塞其 Go 例程。一旦填充，我们可以从中读取一些东西；我们读取数据并继续。之所以`main` Go 例程无法退出是因为我们之前没有向其发送任何值，这比在我们之前的示例中使用计时器要更有效。

在下一节中，我们将看到如何在并发运行的函数之间传递数据。

# 在并发运行的函数之间传递数据

在本节中，我们将看到如何在 Go 例程之间传递数据。假设我们有两个 Go 例程。第一个 Go 例程对数据执行一些操作，并将数据交给另一个 Go 例程，后者对该数据执行第二个处理阶段。现在，我们需要一种方法在第一个 Go 例程和第二个 Go 例程之间传递数据。正如您所看到的，我们可能需要在两个 Go 例程之间进行一些同步，因为第二个 Go 例程将不得不等待，直到第一个 Go 例程向其提供一些数据。

首先，我们将使用以下代码：

```go
package main
import "fmt"
func main(){
  nameChannel := make(chan string)
  done := make(chan string)
  go func(){
    names := []string {"tarik", "michael", "gopi", "jessica"}
    for _, name := range names {
      // doing some operation
      fmt.Println("Processing the first stage of: " + name)
      nameChannel <- name
    }
    close(nameChannel)
  }()
  go func(){
    for name := range nameChannel{
      fmt.Println("Processing the second stage of: " + name)
    }
    done <- ""
  }()
  <-done
}
```

如果您查看代码，您会看到我们再次使用了通道：`nameChannel`。由于我们需要从两个 Go 例程中访问`nameChannel`，因此我们必须在`main`函数内声明它。在第一个 Go 例程中，我们将向`nameChannel`传递一些数据，即`name`。`name`变量是包含一些数据的字符串数组，来自第一个 Go 例程。在第二个 Go 例程中，我们将使用`nameChannel`并读取它，因为它已经填充。此外，我们还必须使用另一个 Go 例程来向主 Go 例程发出信号，指示所有 Go 例程都已完成（`done := make(chan string)`）。我们还必须终止应用程序以避免任何死锁，使用`close`函数。当通道关闭时，`for`循环将被终止，Go 例程将向`done`变量发送一些数据。然后，我们的主 Go 例程将读取它并继续执行下一行，退出`main`函数，应用程序就完成了。这就是无缓冲通道；也就是说，您可以发送单个数据，必须在发送更多数据之前读取并清空它，否则它将被阻塞。

另一种方法是使用缓冲通道来提高性能。对前面的代码进行轻微修改将有所帮助。我们将添加整数`5`，这意味着您可以在不等待的情况下将五个数据发送到`nameChannel`中。检查修改后的代码：

```go
package main
import "fmt"
func main(){
  nameChannel := make(chan string, 5)
  done := make(chan string)
  go func(){
    names := []string {"tarik", "michael", "gopi", "jessica"}
    for _, name := range names {
      // doing some operation
      fmt.Println("Processing the first stage of: " + name)
      nameChannel <- name
    }
    close(nameChannel)
  }()
  go func(){
    for name := range nameChannel{
      fmt.Println("Processing the second stage of: " + name)
    }
    done <- ""
  }()
  <-done
}
```

例如，它将发送一些数据，但不会等待，因为还有四个位置。因此，它将进入第二次迭代，并将一些数据发送到其中，直到计数达到`5`。好处是，当我们向名称通道发送数据时，我们也从中读取数据。以下将是输出：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/hsn-go-prog/img/36126b7a-c835-4f54-94fe-13a491a92433.png)

这是如何在多个 Go 例程之间传递数据的方法。在下一节中，我们将看到如何等待所有并发函数完成。

# 等待所有并发函数完成

在本节中，我们将看到如何等待所有并发函数完成。假设我们有如下代码片段：

```go
package main

import (
  "fmt"
  )

func main() {
  for i := 0; i < 10; i++ {
    go func(){
      fmt.Println("Hello World")
    }()
  }
}
```

假设我们想在循环中创建多个 Go 例程。在这种情况下，假设我们想要有 10 个 Go 例程加上主 Go 例程，因此总共有 11 个 Go 例程。如果运行前面屏幕截图中显示的代码，将不会有任何输出。

等待所有这些 Go 例程完成，以便我们可以向控制台显示一些内容的一种方法是使用`time.Sleep`，如以下代码所示：

```go
package main

import (
  "fmt"
  "time"
)

func main() {
  for i := 0; i < 10; i++ {
   go func(){
      fmt.Println("Hello World")
    }()
  }

  time.Sleep(10*time.Second)
}

```

运行上述代码后，您将获得以下输出：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/hsn-go-prog/img/8297efd4-819f-4e5c-a987-9c80373f5477.png)

现在，您已经获得了一个输出，但是这种方法的问题是，通常您不知道所有 Go 例程完成需要多长时间；因此，您无法真正预测时间。因此，我们可以使用 Go 库本身提供的`sync.WaitGroup`。顾名思义，它基本上是一组等待，您可以使用它来等待所有 Go 例程完成。检查以下代码：

```go
package main
import (
  "fmt"
  "sync"
)

func main() {
  var wg sync.WaitGroup
  for i := 0; i < 10; i++ {
    wg.Add(1)
    go func(){
      fmt.Println("Hello World")
      wg.Done()
    }()
  }
  wg.Wait()
}
```

因此，在每次迭代中，我们可以向我们的等待组添加一个新项，这在这种情况下将是`1`。因此，我们基本上会将`WaitGroup`中的等待数量增加`1`。当 Go 例程完成时，它将使用`wg.Done()`进行信号传递，这将基本上减少组中的等待数量`1`。此外，`wg.Wait`将阻塞我们的主 Go 例程，直到所有 Go 例程都完成。运行代码后，我们将获得以下输出：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/hsn-go-prog/img/aa31888d-52ee-44f6-91d9-ca023b519084.png)

这是你可以简单等待应用程序中所有 Go 例程完成的方法。在下一节中，我们将看到如何选择并发函数的结果，因为它们被返回。

# 选择并发函数的结果

在本节中，我们将看到如何选择并发排名函数的结果。假设我们的`main`函数中有两个 Go 例程，它们基本上正在设置自己的通道：`channel1`和`channel2`。假设我们想先读取任何内容，然后继续下一行。为此，Go 提供了一个名为`select`的内置结构，`select`基本上等待通道填充并且看起来像`switch`语句。让我们继续看看现在的样子：

```go
package main
import (
  "time"
  "fmt"
)
func main() {
  channel1 := make(chan string)
  channel2 := make(chan string)
  go func(){
    time.Sleep(1*time.Second)
    channel1 <- "Hello from channel1"
  }()
  go func(){
    time.Sleep(1 * time.Second)
    channel2 <- "Hello from channel2"
  }()
  var result string
  select {
  case result = <-channel1:
    fmt.Println(result)
  case result = <-channel2:
    fmt.Println(result)
  }
}
```

因此，您只需说`select`，并且例如说`channel1`，当`channel1`准备就绪时，我们将执行类似创建`string`类型的`result`变量的操作。因此，在这里，我将把`channel1`的值分配给将使用`Println`打印到控制台的`result`变量。在第二种情况下，如果不是`channel1`而是准备好读取的`channel2`，那么我们将将其读取到我们的`result`变量中。`select`语句在这里不会同时使用两种情况；例如，如果`channel1`和`channel2`同时准备就绪，那么`select`语句将随机选择其中一个。

由于`channel1`已准备就绪，我们从`channel1`得到了`Hello`作为输出。如果我们再次运行代码，您将从以下屏幕截图中看到`channel2`：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/hsn-go-prog/img/0b00762b-54ca-44c7-bc7a-1e2acbeeb215.png)

因此，您可以轻松地看到输出中的随机性。这就是它的工作原理。

现在，可能会有一些情况需要多次等待。在这种情况下，您可以使用循环：

```go
package main
import (
 "time"
 "fmt"
)
func main() {
 channel1 := make(chan string)
 channel2 := make(chan string)
go func(){
 time.Sleep(1*time.Second)
 channel1 <- "Hello from channel1"
 }()
go func(){
 time.Sleep(1 * time.Second)
 channel2 <- "Hello from channel2"
 }()
var result string
 for {
 select {
 case result = <-channel1:
 fmt.Println(result)
 case result = <-channel2:
 fmt.Println(result)
 }
 case <-quit:
 return
 }
}
```

想象一下，你正在编写一些必须不断等待某些传入数据的东西，当数据进来时，你希望将其写入控制台。或者你可能想对这些数据进行一些操作。在这种情况下，你可以在一个无限循环中等待它们。如果你想要跳出这个循环，你可以读取另一个通道，比如`quit`。如果`quit`已经存在，那么你可以直接跳出这个循环，或者如果它是一个函数，你可以使用 return，这样也会跳出函数。

所以，这就是你如何可以轻松地在 Go 中读取来自多个函数的数据。这就结束了我们的并发章节。

# 总结

在这一章中，你学会了如何在 Go 语言中利用并发构造。在下一章中，我们将学习系统编程，并将从捕获信号开始。您还将学习如何使用 Go 处理命令行参数。


# 第九章：系统编程

系统编程允许你处理系统消息并运行处理任务。在本章中，你将学习如何使用 Go 处理命令行参数。本章将涵盖以下主题：

+   捕获信号

+   从 Go 应用程序中运行子进程

+   处理命令行参数

# 捕获信号

在我们深入了解如何捕获信号之前，让我们先了解一下信号是什么，以及你如何使用它们。信号是一种有限的进程间通信形式，通常用于 Unix 和类 Unix 操作系统。信号是一种异步通知，发送给同一进程中的特定线程或另一个目标进程，通知它发生了某个事件。你可以捕获信号的原因有很多；例如，你可以捕获来自另一个进程的终止信号，以执行一些终止清理操作。在 Go 中，Go 信号通知通过在我们的通道上发送`os.signal`值来工作。现在，让我们继续看看在我们的 Go 应用程序中是什么样子。

首先，我们将创建一个名为 signals 的新通道，并在这里使用`os.signal`。如果你想捕获多个信号，你可以使用一个带缓冲的通道，并将 3 或 4 作为整数类型。要一次只捕获一个信号，我们可以输入 1，或者你可以只传递这个，那么默认值将自动为 1。我们还需要一些其他通道来通知我们已经完成了信号处理，这样我们就可以终止我们的应用程序或执行其他操作。在我们的`signal`包中，有一个名为`Notify()`的方法，所以让我们继续看看文档，它说*Notify 会导致包信号将传入的信号中继到通道*。因此，Go 将自动监听信号，并将这些信号关联到我们将作为其第一个参数提供的通道上。现在，检查以下代码：

```go
package main
import (
  "os"
  "os/signal"
  "syscall"
  "fmt"
)
func main(){
  signals := make (chan os.Signal, 1)
  done := make(chan bool)
  signal.Notify(signals, syscall.SIGINT, syscall.SIGTERM)
  go func (){
    sig := <- signals
    fmt.Println(sig)
    fmt.Println("Signal captured and processed...")
    done <- true
  }()
  fmt.Println("Waiting for signal")
  <-done
  fmt.Println("Exiting the application...")
}
```

有参数可以过滤你想要监听的信号，即`syscall.SIGINT`和`syscall.SIGTERM`。此外，我们将创建一个 Go 例程，简单地监听这个信号并执行一个操作。此外，我们将读取这个值并将信号的内容写入控制台。我们将添加一个`print`语句，说明`信号已捕获并处理...`。此外，`done <- true`将帮助我们处理信号。最后，我们将输入`print`语句`等待信号`，然后我们完成了信号的捕获和处理。让我们继续运行代码以获得输出。我们现在将运行`main.go`应用程序，它将打印`等待信号`：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/hsn-go-prog/img/0912732c-aef3-4fe4-be62-f53299e646da.png)

现在，我们可以发送一个信号来关闭应用程序，使用*Ctrl* + *C*命令，正如你在下面的截图中所看到的，发生了中断。我们的中断被捕获并处理，现在我们退出应用程序，这也可以在下面的截图中看到：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/hsn-go-prog/img/1464852b-0859-47f3-b5a0-24ec0bcda1cc.png)

这就是你可以简单地捕获进程并在你的 Go 应用程序中使用信号的方法。在下一节中，我们将看到如何从 Go 应用程序中运行子进程。

# 运行子进程

在这个视频中，我们将看到如何在应用程序中运行子进程。在我们的应用程序中，我们将运行一个名为`ls`（在 Linux 中）和`dir`（在 Windows 中）的命令。`ls`和`dir`命令是一个简单地列出给定目录中所有文件的应用程序。因此，从我们当前的目录中，它将给我们返回`hello.txt`和`main.go`文件。我们将在我们的应用程序中运行这个`ls`实用程序应用。因此，我们首先要做的是使用`exec`包，它提供了命令。我们将使用`ls`命令，现在不传递任何参数。这将返回命令本身。你会发现两个函数；一个是`start`，另一个是`run`。

`start`和`r`的区别在于，如果您查看文档，您会发现`run`启动指定的命令并等待其完成。根据您的要求，您可以选择`start`或`run`。

我们还有`PID`，即进程 ID，并且我们将将其输出到控制台。因此，让我们继续运行代码。您会看到以下内容：

```go
package main

import (
  "os/exec"
  "fmt"
  )

func main() {
  lsCommand := exec.Command("ls")
  lsCommand.Start()
  fmt.Println(lsCommand.Process.Pid)
}
```

您将得到以下输出：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/hsn-go-prog/img/eb96b7d3-53e9-45ec-8a16-636df48002eb.png)

如您所见，我们得到了进程 ID，但尚未看到目录中的文件。现在，让我们尝试`run`。我们希望读取来自`ls`命令的任何内容，然后将其打印到控制台上。我们将使用“lsCommand.Output（）”，它返回一个字节数组和一个错误，但我们现在将忽略错误。好了！现在让我们检查上述代码：

```go
package main
import (
  "os/exec"
  "fmt"
)
func main() {
  lsCommand := exec.Command("ls")
  output,_ := lsCommand.Output()
  lsCommand.Run()
  fmt.Println(lsCommand.Process.Pid)
  fmt.Println(string(output))
}
```

我们还将清除终端，然后检查输出：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/hsn-go-prog/img/a05fed55-3db4-4954-b005-49f51cade729.png)

如您所见，它给了我们两个文件名和进程 ID。这就是您可以简单地从 Go 应用程序中运行进程的方法。当然，还有更多的方法。您可以运行其他类型的进程，例如 Google Chrome 或 Firefox，或者您开发的另一个应用程序。因此，当您需要从应用程序内部启动进程时，这是一个非常强大的工具。在下一节中，我们将看到如何处理命令行参数。

# 处理命令行参数

在本节中，我们将看到如何处理命令行参数。命令行参数的典型示例是`ls -a`。在这里，`a`是传递给我们最后一个命令的命令行参数，`ls`是操作系统中的一个程序。根据传递给`ls`命令的参数，它的行为会有所不同。

例如，如果我们键入`ls`，它将显示所有可见文件。如果我们键入`ls -a`，那么它将显示该目录下的所有内容，包括不可见项目，这可以在以下截图中看到：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/hsn-go-prog/img/e35aa49a-a983-4e9e-937a-2c45ee281411.png)

因此，我们将对我们的程序执行相同的操作。您可以使用`os.Args`来读取传递给应用程序的参数。我们将读取并将这些参数写入控制台，然后查看在我们向应用程序传递一些参数后的外观。我们首先需要清除我们的终端并输入`go run main.go`。由于最初我们不会传递任何参数，因此我们可以期望只看到一个参数，那就是我们可执行文件的路径。但是，由于我们使用`go run`，它将为我们创建一个临时可执行文件并运行它，因此那是`temp`位置：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/hsn-go-prog/img/89961188-ade2-488f-a20b-04ac43867414.png)

如果我们键入`go run main.go -someArgument`，我们将得到第二个项目，即`- someArgument`：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/hsn-go-prog/img/3ad043dd-4f1c-4f88-99c4-c5f56bf5da15.png)

如果我们不关心第一个参数，我们可以使用`realArgs`：

```go
package main
import (
  "os"
  "fmt"
)

func main(){
  realArgs := os.Args[1:]
  fmt.Println(realArgs)
}
```

您将得到以下输出：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/hsn-go-prog/img/11f0f182-4278-4a29-b500-9675fb734e87.png)

让我们继续检查一个真实的例子。假设我们只期望传递一个参数。检查以下代码：

```go
package main
import (
  "os"
  "fmt"
)
func main(){
  realArgs := os.Args[1:]
  if len(realArgs) == 0{
    fmt.Println("Please pass an argument.")
    return
  }
  if realArgs[0] == "a"{
    writeHelloWorld()
  }else if realArgs[0] == "b"{
    writeHelloMars()
  }else{
    fmt.Println("Please pass a valid argument.")
  }
}
func writeHelloWorld(){
  fmt.Println("Hello, World")
}
func writeHelloMars(){
  fmt.Println("Hello, Mars")
}
```

正如您在前面的代码中所看到的，我们已经输入了`realArgs[0] == "a"`，这将运行一个名为“writeHelloWorld（）”的函数；如果是`realArgs[0] == "b"`，那么它将运行“writeHelloMars（）”，对于任何默认情况，我们将打印一个警告，“请传递有效的参数”。现在，我们将添加“writeHelloWorld（）”和“writeHelloMars（）”函数。此外，我们将使用内置函数来获取我们的`realArgs`的长度，如果是`0`，我们将打印“请传递参数”。完成后，我们需要添加一个`return`语句并退出。

运行代码后，您将得到以下输出：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/hsn-go-prog/img/450e0c02-df4b-45b7-a076-a604d5590583.png)

正如你所看到的，我们收到了我们的第一条消息。如果我们输入 `go run main.go a`，我们会在控制台上看到 `Hello, World` 的输出，如下面的截图所示：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/hsn-go-prog/img/c1c21852-4c85-4653-8698-8738c4979892.png)

如果我们输入 `go run main.go b`，我们会在控制台上看到 `Hello, Mars` 的输出，如下面的截图所示：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/hsn-go-prog/img/21173ecf-0784-4eba-bd53-f1c2d1239970.png)

这就是你如何在 Go 应用程序中执行命令行参数处理的方法。这就结束了我们的章节。

# 总结

在这一章中，你学会了捕获信号、运行子进程和处理命令行参数。在下一章中，你将学习如何从互联网上下载网页和文件。你还将看到如何创建文件和 Web 服务器，以及处理 HTTP 请求和响应。


# 第十章：Web 编程

在这一章中，我们将看到一些有效的配方，这些配方将涉及与互联网的交互，比如下载网页，创建我们自己的示例网页服务器，以及处理 HTTP 请求。本章将涵盖以下主题：

+   从互联网下载网页

+   从互联网下载文件

+   创建一个简单的网页服务器

+   创建一个简单的文件服务器

# 从互联网下载网页

让我们从如何从互联网下载网页开始。我们将从定义我们的 URL 开始，它将是`golang.org`，然后我们将使用`net/http`包来获取此 URL 的内容。这将返回两个东西：`response`和`error`。

如果您快速查看这里的文档，您会发现它发出了一个`get`请求来指定 URL，并且还根据响应返回了一些 HTTP 代码：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/hsn-go-prog/img/d909cb08-295c-439b-af79-f3866d0cb9ab.png)

检查以下代码：

```go
package main
import (
  "net/http"
  "io/ioutil"
  "fmt"
)
func main(){
  url := "http://golang.org"
  response, err := http.Get(url)
  if err != nil{
   panic(err)
  }
  defer response.Body.Close()
  html, err2 := ioutil.ReadAll(response.Body)
  if err2 != nil{
    panic(err)
  }
  fmt.Println(html)
}
```

如果发生错误，我们将调用`panic`，因此我们输入`panic(err)`，其中我们将`err`作为其参数。当一切都完成时，我们将不得不关闭主体。让我们继续在终端中运行此代码，以获得以下结果：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/hsn-go-prog/img/e8a36631-cf93-440a-8db9-b78e26e097f9.png)

如您所见，它是一个字节数组，我们将把它改为`string`：

```go
package main
import (
  "net/http"
  "io/ioutil"
  "fmt"
)
func main(){
  url := "http://golang.org"
  response, err := http.Get(url)
  if err != nil{
    panic(err)
  }
  defer response.Body.Close()
  html, err2 := ioutil.ReadAll(response.Body)
  if err2 != nil{
    panic(err)
  }
  fmt.Println(string(html))
}
```

如果我们现在运行代码，我们将获得以下输出：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/hsn-go-prog/img/c6ab87be-0d78-4cac-8e38-616190c03278.png)

现在我们在控制台上打印出了这个 HTML 源代码，这就是您可以简单地使用 Go 从互联网下载网页的方法。在下一节中，我们将看到如何从互联网下载文件。

# 从互联网下载文件

在本节中，我们将看到如何从互联网下载文件。为此，我们将以下载图像为例。我们将输入图像的 URL，即 Go 的标志。检查以下代码：

```go
package main
import (
  "net/http"
  "os"
  "io"
  "fmt"
)
func main(){
  imageUrl := "https://golang.org/doc/gopher/doc.png"
  response, err := http.Get(imageUrl)
  if err != nil{
    panic(err)
  }
  defer response.Body.Close()
  file, err2 := os.Create("gopher.png")
  if err2 != nil{
    panic(err2)
  }
  _, err3 := io.Copy(file, response.Body)
  if err3 != nil{
    panic(err3)
  }
  file.Close()
  fmt.Println("Image downloading is successful.")
}
```

如您所见，我们在这里使用了`http.Get()`方法。如果我们的`err`不是`nil`，我们会输入`panic(err)`，然后退出`defer response.Body.Close()`函数。在我们的函数退出之前，我们将关闭`out`响应的主体。因此，我们首先要做的是创建一个新文件，以便我们可以将图像的内容复制到文件中。如果错误再次不是`nil`，我们将会发生 panic，并且将使用`io.Copy()`。我们将简单地写入图像下载成功到控制台。

让我们继续运行代码来检查输出：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/hsn-go-prog/img/94973b74-b647-4d5c-86f1-caf0685edd5e.png)

哇！下载成功了。这就是您可以使用 Golang 从互联网下载图像或任何类型的文件的方法。在下一节中，我们将看到如何创建一个简单的网页服务器。

# 创建一个简单的网页服务器

在本节中，我们将看到如何在 Go 中创建一个简单的网页服务器。由于内置的 API，使用 Go 创建一个简单的网页服务器非常容易。首先，我们将使用`net/http`包。`net/http`包有`HandleFunc()`方法，这意味着它将接受两个参数。第一个是 URL 的路径，第二个是您想要处理传入请求的函数。检查以下代码：

```go
package main
import "net/http"
func sayHello(w http.ResponseWriter, r *http.Request){
  w.Write([]byte("Hello, world"))
}
func main(){
  http.HandleFunc("/", sayHello)
  err := http.ListenAndServe(":5050", nil)
  if(err != nil){
    panic(err)
  }
}
```

只要您的方法签名满足`func sayHello(w http.ResponseWriter, r *http.Request){}`类型的方法，它将被我们的`HandleFunc()`接受。我们将使用`sayHello`作为我们的函数，并且它将返回两件事，首先是`http.ResponseWriter`，而第二件事是请求本身作为指针。由于它将是一个 hello 服务器，我们只需将一些数据写回我们的响应，为此，我们将使用我们的响应写入器。由于我们必须监听特定端口，我们将使用`http.ListenAndServe`。此外，我们使用了`5050`；只要可用，您可以选择任何端口。我们还向函数添加了`nil`，如果发生意外情况，它将返回错误，如果错误不是`nil`，我们将会恐慌。所以让我们继续运行代码，并尝试使用浏览器访问路径。我们必须先运行我们的`main.go`文件并允许它，以便我们可以访问它：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/hsn-go-prog/img/eed6ce6f-ab3a-4e7e-a584-3c92e775e1f3.png)

完成后，我们将不得不打开一个浏览器选项卡，并尝试访问`http://localhost:5050/`：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/hsn-go-prog/img/dc59fd06-831f-46e1-a02a-adf91ec78b5d.png)

您将清楚地看到`Hello, world`。现在，让我们用一个查询字符串或 URL 参数做一个更快的示例。我们将修改方法，以便我们可以决定要对哪个行星说“你好”。检查以下代码：

```go
package main
import "net/http"
func sayHello(w http.ResponseWriter, r *http.Request){
  planet := r.URL.Query().Get("planet")
  w.Write([]byte("Hello, " + planet))
}
func main(){
  http.HandleFunc("/", sayHello)
  err := http.ListenAndServe(":5050", nil)
  if(err != nil){
    panic(err)
  }
}
```

我们有一个具有查询功能的 URL。我们将读取查询字符串，也称为名为`planet`的 URL 参数，并将其值分配给一个变量。我们必须停止当前服务器并再次运行它。打开`http://localhost:5050/`后，我们看不到任何行星的名称：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/hsn-go-prog/img/461d784c-b1ac-4d40-8e1a-0664640afe10.png)

因此，您可以将 URL 更改为`http://localhost:5050/?planet=World`并重试：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/hsn-go-prog/img/67a486bf-1522-4966-b843-27ec0350b526.png)

瞧！现在让我们尝试使用`Jupiter`相同的方法：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/hsn-go-prog/img/27f1716d-9d3e-48be-b596-e38d5c0b9b67.png)

这就是我们如何快速在 Go 中创建自己的 Web 服务器。

在下一节中，我们将看到如何创建一个简单的文件服务器。

# 创建一个简单的文件服务器

在本节中，我们将看到如何创建一个简单的文件服务器。文件服务器背后的主要思想是提供静态文件，例如图像、CSS 文件或 JavaScript 文件，在我们的代码中，我们将看到如何做到这一点。检查以下代码：

```go
package main

import "net/http"

func main() {
  http.Handle("/", http.FileServer(http.Dir("./images")))
  http.ListenAndServe(":5050", nil)
}
```

正如您所看到的，我们已经使用了 HTTP 处理，而这个`Handle`与`handleFunc`不同，并接受处理程序接口作为第二个参数；第一个参数是`pattern`。我们将使用一个名为`FileServer`的特殊 API，在这里它将作为文件服务器工作；我们将在服务器中添加一个位置（图像目录，`./images`）来提供静态文件。

因此，当请求到达路由路径时，文件服务器将服务请求，并且它将在位置`http.Dir("./images")`下提供静态文件。我们将使用`http.ListenAndServe(":5050", nil)`，就像在上一节中一样。此外，如前一节所述，我们将运行服务器，允许权限，并在浏览器中键入`localhost:5050`：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/hsn-go-prog/img/9c575d28-4f9a-40a2-9864-88e9dfd401fa.png)

您可以看到我们位置上的文件列表，如果我们单击 gopher_aviator.png，它会给我们该位置的图像：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/hsn-go-prog/img/c22b7ec3-826f-4255-a72c-9fcfb0f2b318.png)

如果我们返回并单击另一个（gopher.png），它将显示以下图像：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/hsn-go-prog/img/c3328254-7f79-4b7a-bcab-d50ddc07141b.png)

或者，您可以注释掉前面代码中的`http.Handle("/", http.FileServer(http.Dir("./images")))`，并将`nil`替换为位置。如果您按照我们之前所做的相同步骤，并检查浏览器，它仍然会正确地给我们这两个图像，这就是您如何在 Go 中创建一个简单的文件服务器。

# 摘要

在本章中，您学习了如何从互联网上下载网页，如何从互联网上下载文件，如何创建一个简单的 Web 服务器，以及如何创建一个简单的文件服务器。下一章将带您了解如何使用 Go 语言在关系型数据库上读取、更新、删除和创建数据的方法。


# 第十一章：关系数据库

Go 可以与各种关系数据库一起工作，包括 SQL Server、MySQL、Postgres SQL 和 SQLite。在本章中，我们将使用 SQLite。与其他更先进的数据库引擎相比，SQLite 可能稍微受限，但对于我们的示例来说，它基本上是足够的。在本节中，您将学习如何使用 Go 读取、更新、删除和创建关系数据库中的数据。

本章将涵盖以下主题：

+   从数据库中读取数据

+   将数据插入数据库

+   在数据库中更新数据

+   从数据库中删除数据

# 从数据库中读取数据

让我们开始学习如何从 SQL 数据库中读取数据。在开始之前，我们将不得不创建一个名为`personal.db`的数据库。我们将使用一个名为 SQLite 的 DB 浏览器，它允许我们创建新的 SQLite 数据库，编辑它们，添加新记录等。您可以在[`sqlitebrowser.org/`](http://sqlitebrowser.org/)找到有关该工具的更多信息并下载它。这是一个免费工具，它可以在 Windows、macOS 和 Linux 上使用。让我们从一个示例开始。请查看以下屏幕截图：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/hsn-go-prog/img/4804cbdd-9529-4acd-8415-238e5a1e039e.png)

在这里，我们只有一个名为`profile`的表。在这个表上的操作足以让我们学会如何与 SQLite 数据库交互，然后您可以使用相同的技术与 MySQL 或 SQL Server 交互。如果您查看屏幕截图，您会看到我们有三条记录和四列：`ProfileId`，`FirstName`，`LastName`和`Age`。`FirstName`和`LastName`列是字符串或文本，`Age`列是一个数字，`ProfileId`是我们的主键；它也是一个整数列。因此，让我们继续创建我们自己的结构和代码：

```go
package main
import (_ "github.com/mattn/go-sqlite3"
  "database/sql"
  "fmt"
)

type Profile struct{
  ProfileId int
  FirstName string
  LastName string
  Age int
}
func main(){
  db, err := sql.Open("sqlite3", "./personal.db")
  checkError(err)
  var profile Profile
  rows, err := db.Query("select ProfileId, FirstName, LastName, Age from Profile")
  checkError(err)
  for rows.Next(){
    err := rows.Scan(&profile.ProfileId, &profile.FirstName, &profile.LastName, &profile.Age)
    checkError(err)
    fmt.Println(profile)
  }
  rows.Close()
  db.Close()
}
func checkError(err error) {
  if (err != nil) {
    panic(err)
  }
}
```

现在，让我们来解释一下代码。我们使用了结构类型将来自 SQL 数据库的数据映射到我们的内存对象。我们需要导入两个包：第一个是 SQL 数据库，第二个是`go-sqlite3`。我们将进行一个空白导入，这将自动删除 SQL 数据库导入，但这没关系，因为我们稍后会再次导入它。我们之所以进行空白导入，是因为如果此包中有初始化代码，它仍将被执行。这个包将自己注册为底层的 SQL 驱动程序，因此我们仍将使用 SQL 数据库包作为我们的 API，但该 API 将在后台使用`go-sqlite3`包与我们的数据库交互，正如您将看到的，Go 中的数据库交互非常简单。因此，我们要做的第一件事是打开数据库。当我们使用 SQL 包时，您会看到它自动导入我们的 SQL 数据库。

此外，我们将使用 SQLite 版本 3 的 SQLite 驱动程序，并且我们还将指定我们的数据库位于何处。数据源名称可能会根据您使用的数据库类型而更改；它可能是一个 URL，但在我们的情况下，它是一个文件，因为 SQLite 使用数据文件。因此，我们将输入`./personal.db`。我们还添加了错误检查实用程序函数，这样我们就不必一直检查错误。我们只需说`checkError`，错误就会被检查。我们将使用 DB 查询来查询我们的数据库，它返回两件事：一个是行，另一个是错误。数据库查询基本上在这里接受一个 SQL 查询。我们还将使用`for`循环，`rows.next`来迭代每一行和`rows.scan`来获取每一行的值。尊重您的列的顺序很重要，因为它们来自 profile 数据库；如果您需要不同的顺序，您可以在此处指定`*`："select * from Profile"。我通常建议明确指定每一行，而不是使用通配符(`*`)。

当您运行此代码时，您将获得以下输出：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/hsn-go-prog/img/112ced21-a8bd-430d-ba41-14272b0e6d12.png)

如您所见，我们能够在表中捕获我们的数据库记录（`ProfileId`、`FirstName`、`LastName`和`Age`）。

现在，让我们快速看一下如何进行过滤。因此，我们将使用`where`子句，如果您了解 SQL，就会知道`where`子句用于过滤。我们将按`ProfileId`进行过滤。请查看此方法的签名：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/hsn-go-prog/img/f67969c6-7a82-4a01-8f9d-0c64c60dea4d.png)

签名中的第二个参数是占位符的参数，由于它是一个非常古老的函数，只要您有匹配的占位符，就可以提供尽可能多的参数。我们将添加`2`，如您在以下代码片段中所见；您也可以使用变量名：

```go
var profile Profile
rows, err := db.Query("select ProfileId, FirstName, LastName, Age from Profile where ProfileID = ?", 2)
checkError(err)
```

现在，让我们继续运行修改后的代码：

```go
package main
import (_ "github.com/mattn/go-sqlite3"
  "database/sql"
  "fmt"
)
type Profile struct{
  ProfileId int
  FirstName string
  LastName string
  Age int
}
func main(){
  db, err := sql.Open("sqlite3", "./personal.db")
  checkError(err)
  var profile Profile
  rows, err := db.Query("select ProfileId, FirstName, LastName, Age from Profile where ProfileID = ?", 2)
  checkError(err)
  for rows.Next(){
    err := rows.Scan(&profile.ProfileId, &profile.FirstName, &profile.LastName, &profile.Age)
    checkError(err)
    fmt.Println(profile)
  }
  rows.Close()
  db.Close()
}
func checkError(err error) {
  if (err != nil) {
    panic(err)
  }
}
```

运行前述代码后，您将获得以下输出：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/hsn-go-prog/img/a3411988-482a-453b-aa9b-b445f4cc9296.png)

因此，我们从数据库中获取了第二条记录。您还可以使用多个`where`子句，如下面的代码所示：

```go
package main
import (_ "github.com/mattn/go-sqlite3"
  "database/sql"
  "fmt"
)
type Profile struct{
  ProfileId int
  FirstName string
  LastName string
  Age int
}
func main(){
  db, err := sql.Open("sqlite3", "./personal.db")
  checkError(err)
  var profile Profile
  rows, err := db.Query("select ProfileId, FirstName, LastName, Age from Profile where FirstName = ? and LastName = ?","Tarik", "Guney")
  checkError(err)
  for rows.Next(){
    err := rows.Scan(&profile.ProfileId,   &profile.FirstName, &profile.LastName, &profile.Age)
    checkError(err)
    fmt.Println(profile)
  }
  rows.Close()
  db.Close()
}
func checkError(err error) {
  if (err != nil) {
    panic(err)
  }
}
```

您将获得以下输出：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/hsn-go-prog/img/c4af8c54-aa5e-4c4d-80c3-1fd5ed25d560.png)

完美！这就是我们期望的记录。这就是您可以在 Go 中轻松查询 SQL 数据库的方式。

在接下来的部分，我们将看到如何向 SQLite 数据库中插入数据。

# 将数据插入数据库

在本节中，我们将看到如何向数据库中插入数据。我们将使用我们在上一节中开发的代码，并添加一个新的代码片段，将数据插入到我们的`personal.db`数据库中。我们将添加`statement`和`err`，并使用`insert`语句将名称添加到我们的`Profile`表中。我们将指定要将数据插入的列，但我们不会指定`ProfileId`，因为它是表的主键。我们将输入`FirstName`、`LastName`和`Age`，值将只是占位符。我们还将使用`statement.Exec`并为占位符提供值，例如`Jessica`、`McArthur`和`30`。以下是代码：

```go

package main
import (_ "github.com/mattn/go-sqlite3"
  "database/sql"
  "fmt"
)
type Profile struct{
  ProfileId int
  FirstName string
  LastName string
  Age int
}
func main(){
  db, err := sql.Open("sqlite3", "./personal.db")
  checkError(err)
  statement, err := db.Prepare("insert into Profile (FirstName, LastName, Age) values(?,?,?)")
  checkError(err)
  statement.Exec("Jessica", "McArthur", 30)
  var profile Profile
  rows, err := db.Query("select ProfileId, FirstName, LastName, Age from Profile")
  checkError(err)
  for rows.Next(){
    err := rows.Scan(&profile.ProfileId, &profile.FirstName, &profile.LastName, &profile.Age)
    checkError(err)
    fmt.Println(profile)
  }
  rows.Close()
  db.Close()
}

func checkError(err error) {
  if (err != nil) {
    panic(err)
  }
}
```

以下是前述代码的输出：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/hsn-go-prog/img/f0584f29-c29b-4bdc-9d43-c929eae10005.png)

如您所见，我们的 ID 是`5`，名字是`Jessica`，姓氏是`McArthur`，年龄是`30`。这就是您可以简单地使用 Go 向数据库中插入数据的方式。

在我们的下一部分中，我们将看到如何更新数据库中的现有数据。

# 在数据库中更新数据

在本节中，我们将看到如何更新数据库中的现有数据。我们将使用我们在上一节中开发的相同代码，但是我们将更改一些字段。

我们将在 SQL 中使用`update`语句。因此，以下字段将被更改：

```go
statement, err := db.Prepare("update Profile set FirstName = ? where ProfileId = ?")
checkError(err)

statement.Exec("Martha", 5)
```

一旦我们更新了我们的个人资料记录，我们将列出我们`profile`表中的所有记录。如果您还记得我们上一节，最后一条记录的个人资料 ID 是`5`，我们将对其进行更改。上一节输出的最后一行是`{5 Jessica McArthur 30}`，我们现在将更改更新代码的名字：

```go
package main
import (_ "github.com/mattn/go-sqlite3"
  "database/sql"
  "fmt"
)
type Profile struct{
  ProfileId int
  FirstName string
  LastName string
  Age int
}
func main(){
  db, err := sql.Open("sqlite3", "./personal.db")
  checkError(err)
  statement, err := db.Prepare("update Profile set FirstName = ? where ProfileId = ?")
  checkError(err)
  statement.Exec("Martha", 5)
  var profile Profile
  rows, err := db.Query("select ProfileId, FirstName, LastName, Age from Profile")
  checkError(err)
  for rows.Next(){
    err := rows.Scan(&profile.ProfileId, &profile.FirstName, &profile.LastName, &profile.Age)
    checkError(err)
    fmt.Println(profile)
  }
  rows.Close()
  db.Close()
}
func checkError(err error) {
  if (err != nil) {
    panic(err)
  }
}
```

如果运行代码，您将获得以下输出：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/hsn-go-prog/img/b9727fa1-5b6d-4862-a433-6f60dd117e5a.png)

您可以看到，我们已成功将名称`Jessica`更改为`Martha`。这就是您可以在 Go 中简单进行更新的方式。

在我们的下一部分中，我们将看到如何从数据库中删除数据。

# 从数据库中删除数据

在本节中，我们将看到如何从数据库中删除数据。我们仍将使用我们在上一节中开发的旧代码，并对其进行一些小的修改。请查看以下代码：

```go
package main
import (
  _ "github.com/mattn/go-sqlite3"
  "database/sql"
  "fmt"
)
type Profile struct{
  ProfileId int
  FirstName string
  LastName string
  Age int
}
func main(){
  db, err := sql.Open("sqlite3", "./personal.db")
  checkError(err)

  var profile Profile
  rows, err := db.Query("select ProfileId, FirstName, LastName, Age from Profile")
  checkError(err)
  for rows.Next(){
    err := rows.Scan(&profile.ProfileId, &profile.FirstName, &profile.LastName, &profile.Age)
    checkError(err)
    fmt.Println(profile)
  }
  rows.Close()
  db.Close()
}
func checkError(err error) {
  if (err != nil) {
    panic(err)
  }
}
```

前述代码的输出将如下所示：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/hsn-go-prog/img/4237cc24-17c1-4c5e-a800-341420149aca.png)

现在，要删除数据，比如说第 3 行，您将需要对代码进行一些修改。我们将对`statement`、`err`和`statement.Exec`进行一些小的修改。

因此，为了实现我们想要的，我们将使用以下修改后的代码：

```go
package main
import (
  _ "github.com/mattn/go-sqlite3"
  "database/sql"
  "fmt"
)
type Profile struct{
  ProfileId int
  FirstName string
  LastName string
  Age int
}
func main(){
  db, err := sql.Open("sqlite3", "./personal.db")
  checkError(err)
  statement ,err := db.Prepare("delete from Profile where  ProfileId = ?")
  checkError(err)
  statement.Exec(3)

  var profile Profile
  rows, err := db.Query("select ProfileId, FirstName, LastName, Age from Profile")
  checkError(err)
  for rows.Next(){
    err := rows.Scan(&profile.ProfileId, &profile.FirstName, &profile.LastName, &profile.Age)
    checkError(err)
    fmt.Println(profile)
  }
  rows.Close()
  db.Close()
}
func checkError(err error) {
  if (err != nil) {
    panic(err)
  }
}
```

你可以看到我们使用了`db.Prepare`。我们从`profile`中提供了`ProfileId`的引导，其中`ProfileId`是一个占位符。我们还使用了`statement.Exec`，它将使用参数执行；重要的是参数的数量要与你在代码中放置的占位符数量相匹配。让我们运行代码并检查输出：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/hsn-go-prog/img/50f32c0e-51e7-4e18-bfba-d73f8d292e7a.png)

因此，如果你比较两个输出，你会发现我们成功删除了第三个条目，现在我们只有`4`个条目，第三个条目已经被删除。这就是你可以简单地从数据库中删除数据的方法。

# 总结

这基本上结束了我们的书。你将学到很多关于 Go 的知识，现在你可以在各种场景中有效地运用这些知识。你现在可以通过遵循本书中包含的简洁易懂的配方来克服开发者面临的最常见挑战。祝一切顺利！
