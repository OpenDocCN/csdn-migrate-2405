# Go 系统编程（一）

> 原文：[`zh.annas-archive.org/md5/2DB8F67A356AEFD794B578E9C4995B3C`](https://zh.annas-archive.org/md5/2DB8F67A356AEFD794B578E9C4995B3C)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 前言

《Go 系统编程》是一本将帮助您使用 Go 开发系统软件的书，它是一种系统编程语言，最初是作为谷歌内部项目开始的，后来变得很受欢迎。Go 之所以如此受欢迎，是因为它让开发人员感到愉快，易于编写、易于阅读、易于理解，并且有一个编译器可以帮助您。这本书并未涵盖 Go 编程语言的每一个可能方面和特性，只涉及与系统编程相关的内容。如果您希望了解更多关于 Go 编程语言的知识，您可以期待我的下一本书《精通 Go》，它将于 2018 年出版！

你即将阅读的书是一本诚实的书，它将呈现工作中的 Go 代码，而不会忽视其潜在缺陷、限制和逻辑错误，这将使您能够自行改进并在未来创建更好的版本。您将无法改进的是将呈现的基本信息，这是 Unix 系统工作方式的基础。如果这本书能帮助您理解系统编程的重要性以及如何开始使用 Go 开发系统软件，我将认为这本书是成功的。如果 Go 成为您最喜欢的编程语言，我同样会感到高兴！

# 本书涵盖的内容

《第一章》《开始使用 Go 和 Unix 系统编程》首先定义了系统编程是什么，然后讨论了 Go 的优缺点、Go 版本 1.8 的特性，两个方便的 Go 工具`gofmt`和`godoc`，以及 Unix 进程的各种状态。

《第二章》《使用 Go 编写程序》帮助您学习如何编译 Go 代码以及如何使用 Go 支持的环境变量，并了解 Go 如何读取程序的命令行参数。然后，我们将讨论获取用户输入和输出，这是基本任务，向您展示如何在 Go 中定义函数，本书中首次提到`defer`关键字，并继续讨论 Go 提供的数据结构，使用方便的代码示例。在本章的其余部分，我们将讨论 Go 接口和随机数生成。我相信您会喜欢这一章节！

《第三章》《高级 Go 特性》深入探讨了一些高级 Go 特性，包括错误处理，在开发系统软件和错误记录时至关重要。然后介绍了模式匹配和正则表达式、Go 反射，并讨论了不安全的代码。之后，它将 Go 与其他编程语言进行了比较，并介绍了两个实用程序，名为`dtrace(1)`和`strace(1)`，它们可以让您在执行程序时看到幕后发生的事情。最后，它讨论了如何使用`go tool`检测不可达代码以及如何避免一些常见的 Go 错误。

《第四章》《Go 包、算法和数据结构》讨论了 Go 中的算法和排序，以及需要 Go 版本 1.8 或更新版本的`sort.Slice()`函数。然后展示了链表、二叉树和哈希表的 Go 实现。之后，它讨论了 Go 包，并教您如何创建和使用自己的 Go 包。本章的最后部分讨论了 Go 中的垃圾回收。

第五章，“文件和目录”，是本书中首个涉及系统编程主题的章节，涉及文件、符号链接和目录的处理。在本章中，你将找到 Unix 工具的核心功能的 Go 实现，比如`which(1)`、`pwd(1)`和`find(1)`，但首先你将学习如何使用`flag`包来解析 Go 程序的命令行参数和选项。此外，你还将学习如何删除、重命名和移动文件，以及如何以 Go 方式遍历目录结构。本章的最后部分实现了一个实用程序，用于创建目录结构的所有目录的副本！

第六章，“文件输入和输出”，向你展示如何读取文件的内容，如何更改文件内容，以及如何将自己的数据写入文件！在本章中，你将了解`io`包、`io.Writer`和`io.Reader`接口，以及用于缓冲输入和输出的`bufio`包。你还将创建`cp(1)`、`wc(1)`和`dd(1)`实用程序的 Go 版本。最后，你将了解稀疏文件，如何在 Go 中创建稀疏文件，如何从文件中读取和写入记录，以及如何在 Go 中锁定文件。

第七章，“处理系统文件”，教你如何处理 Unix 系统文件，包括向 Unix 日志文件写入数据、向现有文件追加数据以及修改文本文件的数据。在本章中，你还将了解标准的 Go 包`log`和`log/syslog`，Unix 文件权限，以及使用实际示例进一步学习模式匹配和正则表达式知识。你还将了解如何找到用户的用户 ID 以及用户所属的 Unix 组。最后，你将了解如何使用`time`包在 Go 中处理日期和时间，以及如何自己创建和旋转日志文件。

第八章，“进程和信号”，首先讨论了在 Go 中如何处理 Unix 信号，借助`os/signal`包展示了三个 Go 程序。然后展示了一个可以使用信号和信号处理来旋转其日志文件的 Go 程序，以及另一个使用信号来展示文件复制操作进度的 Go 程序。本章还将教你如何在 Go 中绘制数据以及如何在 Go 中实现 Unix 管道。然后将在 Go 中实现`cat(1)`实用程序，然后简要介绍 Unix 套接字客户端的 Go 代码。本章的最后一部分快速讨论了如何在 Go 中编写 Unix shell。

第九章，“Goroutines - 基本特性”，讨论了一个非常重要的 Go 主题，即 goroutines，讨论了如何创建 goroutines 以及如何同步它们并在结束程序之前等待它们完成。然后讨论了通道和管道，这有助于 goroutines 以安全的方式进行通信和交换数据。本章的最后部分呈现了一个使用 goroutines 实现的`wc(1)`实用程序的版本。然而，由于 goroutines 是一个庞大的主题，下一章将继续讨论它们。

第十章，“Goroutines - 高级特性”，讨论了与 goroutines 和通道相关的更高级的主题，包括缓冲通道、信号通道、空通道、通道的通道、超时和`select`关键字。然后讨论了与共享内存和互斥锁相关的问题，然后呈现了两个使用通道和共享内存的`wc(1)`实用程序的更多 Go 版本。最后，本章将讨论竞争条件和`GOMAXPROCS`环境变量。

第十一章，*使用 Go 编写 Web 应用程序*，讨论了在 Go 中开发 Web 应用程序和 Web 服务器以及客户端。此外，它还讨论了使用 Go 代码与 MongoDB 和 MySQL 数据库进行通信。然后，它说明了如何使用`html/template`包，该包是 Go 标准库的一部分，允许您使用 Go HTML 模板文件生成 HTML 输出。最后，它讨论了读取和写入 JSON 数据，然后呈现了一个实用程序，该实用程序读取多个网页并返回在这些网页中找到给定关键字的次数。

第十二章，*网络编程*，讨论了使用`net` Go 标准包涉及的 TCP/IP 及其协议的主题。它向您展示了如何创建 TCP 和 UDP 客户端和服务器，如何执行各种类型的 DNS 查找，以及如何使用 Wireshark 检查网络流量。此外，它还讨论了在 Go 中开发 RPC 客户端和服务器，以及开发 Unix 套接字服务器和 Unix 套接字客户端。

正如您将看到的，每章结束时都有一些练习供您完成，以便获取有关重要 Go 包的更多信息并编写自己的 Go 程序。请尝试完成本书的所有练习。

# 您需要为本书做些什么

这本书需要一台运行 Unix 变种的计算机，其中包括运行 Mac OS X、macOS 或 Linux 的任何机器上都有相对较新的 Go 版本。

苹果过去将其操作系统称为 Mac OS X，后面跟着版本号；然而，在 Mac OS X 10.11（El Capitan）之后，苹果进行了更改，现在 Mac OS X 10.12 被称为 macOS 10.12（Sierra）-在本书中，Mac OS X 和 macOS 这两个术语是可以互换使用的。此外，很有可能在您阅读本书时，最新版本的 macOS 将是 macOS 10.13（High Sierra）。您可以通过访问[`en.wikipedia.org/wiki/MacOS`](https://en.wikipedia.org/wiki/MacOS)了解更多关于各个版本 macOS 的信息。

本书中的所有 Go 代码都经过了在运行 macOS 10.12 Sierra 的 iMac 上运行 Go 1.8.x 以及在运行 Debian Linux 机器上运行 Go 版本 1.3.3 的测试。大部分代码可以在这两个 Go 版本上运行而无需任何代码更改。然而，当使用较新的 Go 功能时，代码将无法在 Go 1.3.3 上编译：本书指出了不会在 Go 版本 1.3.3 上编译或需要 Go 版本 1.8 或更新的 Go 程序。

请注意，在撰写本文时，最新的 Go 版本是 1.9。鉴于 Go 的工作方式，您将能够在更新的 Go 版本中编译本书中的所有 Go 代码而无需任何更改。

# 这本书是为谁准备的

这本书适用于 Unix 用户、高级 Unix 用户、Unix 系统管理员和 Unix 系统开发人员，他们在一个或多个 Unix 变种上使用 Go，并希望开始使用 Go 编程语言开发系统软件。

尽管这本书可能不适合对 Unix 操作系统不太熟悉或没有编程经验的人，但业余程序员将会找到大量关于 Unix 的实用信息，这可能会激发他们开始开发自己的系统实用程序。

# 惯例

在本书中，您会发现一些区分不同类型信息的文本样式。以下是一些这些样式的示例以及它们的含义解释。文本中的代码词、数据库表名、文件夹名、文件名、文件扩展名、路径名、虚拟 URL、用户输入和 Twitter 句柄显示如下：“这是因为`main()`函数是程序执行开始的地方。”

代码块设置如下：

```go
package main 

import "fmt" 
import "os" 

func main() { 
   arguments := os.Args 
   for i := 0; i < len(arguments); i++ { 
         fmt.Println(arguments[i]) 
   } 
} 
```

当我们希望引起您对代码块的特定部分的注意时，相关行或项目将以粗体显示：

```go
package main 

import "fmt" 
import "os" 

func main() { 
   arguments := os.Args 
   for i := 0; i < len(arguments); i++ { 
         fmt.Println(arguments[i]) 
   } 
} 
```

任何命令行输入或输出都以以下形式书写：

```go
$ go run hw.go
Hello World!  
```

**新术语**和**重要单词**以粗体显示。

警告或重要说明会出现在这样的形式。

提示和技巧会出现在这样的形式。


# 第一章：使用 Go 和 Unix 系统编程入门

操作系统是一种允许您与硬件通信的软件，这意味着没有操作系统，您无法使用硬件。Unix 是一种具有许多变体的操作系统，它们有许多共同点，包括它们的编程接口。

Unix 操作系统主要是用 C 语言编程的，而不是完全用汇编语言，这使得它可以在其他计算机架构上移植，而无需从头开始重写所有内容。重要的是要理解，即使您在 Unix 机器上开发 Go 程序，最终您的代码也会被翻译成 C 函数和系统调用，因为这是直接与 Unix 内核通信的唯一方式。与编写 C 代码相比，编写 Go 代码的主要好处是程序更小，bug 更少。您将在第三章中了解更多关于这个的内容，*高级 Go 特性*。

由于本书将使用 Go 语言，您需要在 Unix 机器上安装 Go 的一个版本。好消息是，几乎所有现代 Unix 系统，包括 macOS、Linux 和 FreeBSD 都有 Go 编程语言的端口。Windows 也有一个 Go 端口，但本书不涉及 Microsoft Windows。

尽管您的 Unix 变体很可能有一个 Go 软件包，但您也可以从[`golang.org/dl/`](https://golang.org/dl/)获取 Go。

在本章中，您将学习以下主题：

+   系统编程

+   Go 的优缺点

+   Unix 进程的状态

+   两个 Go 工具：`gofmt`和`godoc`

+   最新 Go 版本（1.8）的特性

# 本书的结构

本书分为三个部分。第一部分，包括本章，是关于 Go 和在开发系统软件时可能有用的 Go 特性：这并不意味着您在开发程序时应该使用所有这些特性。第二部分是关于文件、目录和进程编程，这是最常见的系统软件类型。第三部分探讨了在 Go 中使用 goroutines、Web 应用程序和网络编程，这是最高级的系统软件类型。好消息是，您不需要立即阅读本书的第三部分。

# 什么是系统编程？

系统编程是 Unix 机器上的一个特殊编程领域。请注意，系统编程并不局限于 Unix 机器：本书只涉及 Unix 操作系统。大多数与系统管理任务有关的命令，如磁盘格式化、网络接口配置、模块加载和内核性能跟踪，都是使用系统编程技术实现的。此外，在所有 Unix 系统上都可以找到的`/etc`目录包含处理 Unix 机器及其服务配置的纯文本文件，也是使用系统软件进行操作的。

您可以将系统软件的各个领域和相关系统调用分为以下几类：

+   **文件 I/O**：这个领域涉及文件读写操作，这是操作系统最重要的任务。文件输入和输出必须快速高效，最重要的是可靠。

+   **高级文件 I/O**：除了基本的输入和输出系统调用外，还有更高级的读写文件的方法，包括异步 I/O 和非阻塞 I/O。

+   **系统文件和配置**：这组系统软件包括允许您处理系统文件（如`/etc/passwd`）并获取系统特定信息（如系统时间和 DNS 配置）的函数。

+   **文件和目录**：这个集群包括允许程序员创建和删除目录以及获取文件或目录的所有者和权限等信息的函数和系统调用。

+   **进程控制**：这组软件允许您创建和与 Unix 进程交互。

+   **线程**：当一个进程有多个线程时，它可以执行多个任务。然而，线程必须被创建、终止和同步，这就是这组函数和系统调用的目的。

+   **服务器进程**：这一集合包括允许您开发服务器进程的技术，这些进程可以在后台执行，而无需活动终端。Go 在传统的 Unix 方式下编写服务器进程方面并不那么出色：但让我稍微解释一下。像 Apache 这样的 Unix 服务器使用`fork(2)`来创建一个或多个子进程（这个过程称为**forking**，指的是将父进程克隆成子进程），并继续从同一点执行相同的可执行文件，最重要的是，共享内存。虽然 Go 没有提供与`fork(2)`函数等效的功能，但这并不是问题，因为您可以使用 goroutines 来覆盖大部分`fork(2)`的用途。

+   **进程间通信**：这组函数允许在同一台 Unix 机器上运行的进程使用管道、FIFO、消息队列、信号量和共享内存等特性进行通信。

+   **信号处理**：信号为进程提供了处理异步事件的方法，这可能非常方便。几乎所有服务器进程都有额外的代码，允许它们使用该组的系统调用来处理 Unix 信号。

+   **网络编程**：这是开发利用 TCP/IP 在计算机网络上工作的应用程序的艺术，并不是系统编程本身。然而，大多数 TCP/IP 服务器和客户端都涉及系统资源、用户、文件和目录。因此，大多数情况下，您不能创建网络应用程序而不进行某种形式的系统编程。

系统编程的挑战在于您不能容忍不完整的程序；您要么有一个完全可用、安全的程序，可以在生产系统上使用，要么什么都没有。这主要是因为您不能信任最终用户和黑客。系统编程的关键困难在于错误的系统调用可能会使您的 Unix 机器行为异常，甚至更糟糕的是崩溃！

Unix 系统上的大多数安全问题通常来自错误实现的系统软件，因为系统软件中的错误可能会危及整个系统的安全。最糟糕的是，这可能会在使用某个特定软件多年后发生。

在编写系统软件时，您应该特别注意错误消息和警告，因为它们是帮助您理解发生了什么以及为什么您的程序没有按预期行为的朋友。简而言之，*文件未找到*和*没有足够的权限读取文件*错误消息之间存在着很大的区别。

在 Unix 首次引入时，编写系统软件的唯一方法是使用 C；如今，您可以使用包括 Go 在内的编程语言来编写系统软件，本书将介绍 Go。

您应该明白，使用 C 以外的编程语言开发系统软件的两个主要好处如下：

+   使用现代编程语言及其工具

+   简单性，通常您需要编写、调试和维护更少的代码

除了 Go，用于开发系统工具的其他良好选择包括 Python、Perl、Rust 和 Ruby。

# 学习系统编程

学习系统编程的唯一方法是使用本书作为参考和教程，开发自己的实用程序。起初，你会犯很多荒谬的错误，但随着你的进步，你会犯更少但更聪明和难以调试的错误！然而，在学习时尝试新事物是可以的。事实上，尝试新事物并失败是必要的，因为这意味着你真的在学习新东西。只要确保你不要使用生产 Web 服务器来学习系统编程。

如果你不知道要开发什么，可以从创建自己的版本开始，比如`ls(1)`、`mkdir(1)`、`ln(1)`、`wc(1)`和`which(1)`等现有的 Unix 命令行实用程序。你不必为每个实用程序创建一个功能齐全的版本，支持所有命令行选项；重要的是开发一个稳定和安全的版本，实现主要功能并且没有问题地运行。

能够教你在 C 中进行 Unix 系统编程的最好书籍是*W. Richard Stevens*的*Advanced Unix Programming in the Unix Environment*。它的第三版现在已经可以获取，但所有版本都很有用，包含大量宝贵的细节。

# 关于 Go

Go 是一种现代通用开源编程语言，于 2009 年底正式宣布。它起初是一个谷歌内部项目，受到了包括 C、Pascal、Alef 和 Oberon 在内的许多其他编程语言的启发。它的精神领袖是*Robert Griesemer*、*Ken Thomson*和*Rob Pike*，他们设计 Go 作为专业程序员构建可靠和健壮软件的语言。除了其语法和标准函数外，Go 还配备了一个相当丰富的标准库。

在撰写本书时，最新的稳定 Go 版本是 1.8，其中包括一些方便的新功能，包括以下内容：如果你以前没有使用过 Go，可以跳过这部分。

+   现在存在新的转换规则，允许你在满足一些条件的情况下轻松地在几乎相等的类型之间进行转换。你可以使用`go tool`命令修复`golang.org/x/net/name`形式的导入路径，而无需自己打开源文件。

+   该工具在某些情况下更加严格，在以前会产生误报的情况下更加宽松。

+   当 GOPATH 未定义时，现在有一个 GOPATH 环境变量的默认值。对于 Unix 系统，默认值是$HOME/go。

+   Go 运行时有各种改进，加快了 Go 的速度。

+   有一个`sort.slice()`函数，允许你通过提供比较器回调来对切片进行排序，而不是实现`sort.Interface`。

+   现在`http.Server`有一个`Shutdown`方法。

+   `database/sql`包有各种小改动，让开发人员对查询有更多控制。

+   你可以使用`go bug`命令创建 bug。

# 准备开始 Go

你可以使用这个命令轻松找到你的 Go 版本：

```go
$ go version
go version go1.7.5 darwin/amd64  
```

前面的输出来自 macOS 机器，因此有`darwin`字符串。Linux 机器会给出以下类型的输出：

```go
$ go version
go version go1.3.3 linux/amd64
```

在接下来的章节中，你将学到更多关于`go tool`的知识，你将一直使用它。

我可以想象，你一定迫不及待地想看一些 Go 代码；所以这里是著名的 Hello World 程序的 Go 版本：

```go
package main 

import "fmt" 

// This is a demonstrative comment! 
func main() { 
   fmt.Println("Hello World!") 
} 
```

如果你熟悉 C 或 C++，你会发现 Go 代码非常容易理解。包含 Go 代码的每个文件都以包声明开头，后面是所需的导入声明。包声明显示了该文件所属的包。请注意，除非你想在同一行上放置两个或更多个 Go 语句，否则不需要为成功终止 Go 语句使用分号。

在第二章中，*使用 Go 编写程序*，你将了解如何编译和执行 Go 代码。现在，只需记住 Go 源文件使用`.go`文件扩展名存储：你的任务是选择一个描述性的文件名。

在搜索与 Go 相关的信息时，使用`Golang`或`golang`作为 Go 编程语言的关键词，因为单词 Go 几乎可以在英语中的任何地方找到，这不会帮助你的搜索！

# 两个有用的 Go 工具

Go 发行版附带了大量工具，可以让你作为程序员的生活更轻松。其中最有用的两个是`gofmt`和`godoc`。

请注意，`go tool`本身也可以调用各种工具：你可以通过执行`go tool`来查看它们的列表。

`gofmt`实用程序以给定的方式格式化 Go 程序，这在不同的人要为一个大项目使用相同的代码时非常重要。你可以在[`golang.org/cmd/gofmt/`](https://golang.org/cmd/gofmt/)找到更多关于`gofmt`的信息。

以下是`hw.go`程序的格式不佳的版本，很难阅读和理解：

```go
$ cat unglyHW.go
package main

import
    "fmt"

// This is a demonstrative comment!
        func main() {
  fmt.Println("Hello World!")

}
```

处理前面的代码，保存为`unglyHW.go`并使用`gofmt`，会生成以下易于阅读和理解的输出：

```go
$ gofmt unglyHW.go
package main

import "fmt"

// This is a demonstrative comment!
func main() {
      fmt.Println("Hello World!")

}
```

记住`gofmt`实用程序不会自动保存生成的输出很重要，这意味着你应该使用`-w`选项后跟有效的文件名，或者将`gofmt`的输出重定向到一个新文件。

`godoc`实用程序允许你查看现有 Go 包和函数的文档。你可以在[`godoc.org/golang.org/x/tools/cmd/godoc`](http://godoc.org/golang.org/x/tools/cmd/godoc)找到更多关于`godoc`的信息。

你将经常使用`godoc`，因为它是学习 Go 函数细节的好工具。

以下截图显示了在终端上生成的`godoc`命令的输出，当要求有关`fmt`包的`Println()`函数的信息时：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/go-sys-prog/img/b8c6c34f-8a9b-4b23-9ed3-1e5f5efaa474.png)

godoc 命令的输出

`godoc`的另一个方便功能是它可以启动自己的 web 服务器，并允许你使用 web 浏览器查看它的文档：

```go
$ godoc -http=:8080  
```

以下截图显示了在运行前一个命令时，通过访问`http://localhost:8080/pkg/`在 web 浏览器上获得的输出类型。你可以使用任何你想要的端口号，只要它还没有被使用：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/go-sys-prog/img/180f5a7f-a97c-418e-a357-3b2149951724.png)

使用 web 浏览器中的 godoc 实用程序

程序员最重要的工具是他们用来编写源代码的编辑器。当我在 Mac 上时，我通常使用 TextMate 编辑器，但当我在不同的 Unix 机器上时，我更喜欢 vi。选择编辑器并不是一件容易的事，因为你将花费很多时间在它上面。然而，只要不在源代码文件中放入任何控制字符，任何文本编辑器都可以胜任。以下截图显示了 TextMate 编辑器的操作：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/go-sys-prog/img/5ae80fd5-b3ca-4c88-a509-7f29faae8d5a.png)

TextMate 编辑器显示了一些 Go 代码的外观

# Go 的优缺点

Go 并不完美，但它有一些非常有趣的特性。Go 强大特性的列表包括以下内容：

+   Go 代码易于阅读和理解。

+   Go 希望开发者快乐，因为快乐的开发者写出更好的代码！

+   Go 编译器打印实用的警告和错误消息，帮助你解决实际问题。简而言之，Go 编译器是为了帮助你而不是让你的生活困难！

+   Go 代码是可移植的。

+   Go 是一种现代编程语言。

+   Go 支持过程化、并发和分布式编程。

+   Go 支持**垃圾回收**（**GC**），因此你不必处理内存分配和释放。然而，GC 可能会稍微减慢你的程序。

+   Go 没有预处理器，编译速度很快。因此，Go 可以用作脚本语言。

+   Go 可以构建 Web 应用程序。在 C 中构建 Web 应用程序除非使用非标准的外部库，否则效率不高。此外，Go 为程序员提供了一个简单的 Web 服务器用于测试目的。

+   标准的 Go 库提供了许多简化程序员工作的包。此外，标准的 Go 库中的方法事先经过测试和调试，这意味着它们大多数时间不包含错误。

+   Go 默认使用静态链接，这意味着生成的二进制文件可以轻松地传输到具有相同操作系统的其他计算机上。因此，开发人员不需要担心库、依赖项和不同的库版本。

+   您不需要 GUI 来开发、调试和测试 Go 应用程序，因为可以从命令行中使用 Go。

+   Go 支持 Unicode。这意味着您不需要任何额外的代码来打印多种人类语言的字符。

+   Go 保持概念正交，因为少量正交特性比许多重叠特性更好。

Go 的缺点列表包括以下内容：

+   嗯，Go 不是 C，这意味着您或您的团队应该学习一种新的编程语言来开发系统软件。

+   Go 没有直接支持面向对象的编程，这对于习惯以面向对象方式编写代码的程序员可能是一个问题。尽管如此，您可以在 Go 中使用组合来模拟继承。

+   Unix 首次推出时，C 是编写系统软件的唯一编程语言。如今，您还可以使用 Rust、C++和 Swift 来编写系统软件，这意味着不是每个人都会使用 Go。

+   C 仍然是系统编程中比其他任何编程语言都要快的主要原因是 Unix 是用 C 编写的。

无论编程语言的优点还是缺点，您都可以决定是否喜欢它。重要的是选择一种您喜欢并且能够完成您想要的工作的编程语言！就个人口味而言，我不喜欢 C++，尽管它是一种非常有能力的编程语言，我曾经用 C++编写过 FTP 客户端！此外，我从来不喜欢 Java。在个人口味上没有对错之分，所以不要为自己的选择感到内疚。

# Unix 进程的各种状态

严格来说，进程是一个包含指令、用户数据和系统数据部分以及在运行时获得的其他类型资源的执行环境。程序是一个包含指令和数据的文件，用于初始化进程的指令和用户数据部分。

Unix 操作系统首次推出时，计算机只有单个 CPU，没有多个核心和少量的 RAM。然而，Unix 是一个多用户和多任务操作系统。为了实际上成为一个多用户和多任务系统，它必须能够周期性地运行每个单独的进程，这意味着一个进程应该有多个状态。下图显示了进程的可能状态以及从一个状态到另一个状态的正确路径：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/go-sys-prog/img/2c347cf1-0751-465a-8026-557eabace4a5.png)

Unix 进程的各种状态

有三种进程类别：用户进程、内核进程和守护进程：

+   用户进程在用户空间中运行，通常没有特殊的访问权限

+   内核进程仅在内核空间中执行，并且可以完全访问所有内核数据结构

+   守护进程是可以在用户空间中找到并在后台运行而无需终端的程序

意识到你无法控制进程的状态是非常重要的，因为这是运行在内核中的操作系统的**调度程序**的工作。简单来说，你无法预测进程的状态何时会改变，或者进程何时会进入运行状态，所以你的代码不能依赖任何这样的假设！

创建新进程的 C 方式涉及调用`fork()`系统调用。`fork()`的返回值允许程序员区分父进程和子进程。然而，Go 不支持类似的功能。

# 练习

1.  访问 Go 网站：[`golang.org/`](https://golang.org/)。

1.  在你的系统上安装 Go 并找出它的版本。

1.  自己输入 Hello World 程序的代码并将其保存到文件中。

1.  如果你使用的是 Mac，可以从[`macromates.com/`](http://macromates.com/)下载 TextMate。

1.  如果你使用的是 Mac，可以从[`www.barebones.com/products/TextWrangler/`](http://www.barebones.com/products/TextWrangler/)下载 TextWrangler 编辑器并尝试使用它。

1.  如果你还不熟悉其他 Unix 文本编辑器，可以尝试自己学习 vi 或 Emacs。

1.  查看任何你能找到的 Go 代码，并尝试对其进行小的更改。

# 总结

在本章中，你学会了如何在你的计算机上安装 Go，最新 Go 版本的特性，Go 的优缺点，以及`gofmt`和`godoc` Go 工具，以及关于 Unix 操作系统的一些重要内容。

下一章不仅会告诉你如何编译你的 Go 代码，还会讨论其他重要的 Go 主题，比如读取和使用命令行参数，环境变量，编写函数，数据结构，接口，获取用户输入和打印输出。


# 第二章：在 Go 中编写程序

本章将讨论许多重要、有趣和实用的 Go 主题，这将帮助您更加高效。我认为从编译和运行上一章的`hw.go`程序的 Go 代码开始本章是一个不错的主意。然后，您将学习如何处理 Go 可以使用的环境变量，如何处理 Go 程序的命令行参数，以及如何在屏幕上打印输出并从用户那里获取输入。最后，您将了解如何在 Go 中定义函数，学习极其重要的`defer`关键字，查看 Go 提供的数据结构，并了解 Go 接口，然后再查看生成随机数的代码。

因此，在本章中，您将熟悉许多 Go 概念，包括以下内容：

+   编译您的 Go 程序

+   Go 环境变量

+   使用传递给 Go 程序的命令行参数

+   获取用户输入并在屏幕上打印输出

+   Go 函数和`defer`关键字

+   Go 数据结构和接口

+   生成随机数

# 编译 Go 代码

只要包名是`main`并且其中有`main()`函数，Go 就不在乎一个独立程序的源文件的名称。这是因为`main()`函数是程序执行的起点。这也意味着在单个项目的文件中不能有多个`main()`函数。

有两种运行 Go 程序的方式：

+   第一个是`go run`，只是执行 Go 代码而不生成任何新文件，只会生成一些临时文件，之后会被删除

+   第二种方式，`go build`，编译代码，生成可执行文件，并等待您运行可执行文件

本书是在使用 Homebrew ([`brew.sh/`](https://brew.sh/))版本的 Go 的 Apple Mac OS Sierra 系统上编写的。但是，只要您有一个相对较新的 Go 版本，您应该不会在大多数 Linux 和 FreeBSD 系统上编译和运行所提供的 Go 代码时遇到困难。

因此，第一种方式如下：

```go
$ go run hw.go
Hello World!  
```

上述方式允许 Go 用作脚本语言。以下是第二种方式：

```go
$ go build hw.go
$ file hw
hw: Mach-O 64-bit executable x86_64
```

生成的可执行文件以 Go 源文件的名称命名，这比`a.out`要好得多，后者是 C 编译器生成的可执行文件的默认文件名。

如果您的代码中有错误，比如在调用 Go 函数时拼错了 Go 包名，您将会得到以下类型的错误消息：

```go
$ go run hw.go
# command-line-arguments
./hw.go:3: imported and not used: "fmt"
./hw.go:7: undefined: mt in mt.Println
```

如果您意外地拼错了`main()`函数，您将会得到以下错误消息，因为独立的 Go 程序的执行是从`main()`函数开始的：

```go
$ go run hw.go
# command-line-arguments
runtime.main_main f: relocation target main.main not defined
runtime.main_main f: undefined: "main.main"
```

最后，我想向您展示一个错误消息，它将让您对 Go 的格式规则有一个很好的了解：

```go
$ cat hw.gocat 
package main

import "fmt"

func main()
{
      fmt.Println("Hello World!")
}
$ go run hw.go
# command-line-arguments
./hw.go:6: syntax error: unexpected semicolon or newline before {

```

前面的错误消息告诉我们，Go 更喜欢以一种特定的方式放置大括号，这与大多数编程语言（如 Perl、C 和 C++）不同。这一开始可能看起来令人沮丧，但它可以节省您一行额外的代码，并使您的程序更易读。请注意，前面的代码使用了*Allman 格式样式*，而 Go 不接受这种格式。

对于这个错误的官方解释是，Go 在许多情况下要求使用分号作为语句终止符，并且编译器会在它认为必要时自动插入所需的分号，这种情况是在非空行的末尾。因此，将开括号（`{`）放在自己的一行上会让 Go 编译器在前一行末尾加上一个分号，从而产生错误消息。

如果您认为`gofmt`工具可以帮您避免类似的错误，您将会感到失望：

```go
$ gofmt hw.go
hw.go:6:1: expected declaration, found '{'

```

正如您在以下输出中所看到的，Go 编译器还有另一条规则：

```go
$ go run afile.go
# command-line-arguments
./afile.go:4: imported and not used: "net"
```

这意味着你不应该在程序中导入包而不实际使用它们。虽然这可能是一个无害的警告消息，但你的 Go 程序将无法编译。请记住，类似的警告和错误消息是你遗漏了某些东西的一个很好的指示，你应该尝试纠正它们。如果你对警告和错误采取相同的态度，你将创建更高质量的代码。

# 检查可执行文件的大小

因此，在成功编译`hw.go`之后，你可能想要检查生成的可执行文件的大小：

```go
$ ls -l hw
-rwxr-xr-x  1 mtsouk  staff  1628192 Feb  9 22:29 hw
$ file hw
hw: Mach-O 64-bit executable x86_64  
```

在 Linux 机器上编译相同的 Go 程序将创建以下文件：

```go
$ go versiongo 
go version go1.3.3 linux/amd64
$ go build hw.go
$ ls -l hw
-rwxr-xr-x 1 mtsouk mtsouk 1823712 Feb 18 17:35 hw
$ file hw
hw: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), statically linked, not stripped

```

为了更好地了解 Go 可执行文件的大小，考虑一下，同样的程序用 C 编写的可执行文件大约为 8432 字节！

因此，你可能会问为什么一个如此小的程序会生成一个如此庞大的可执行文件？主要原因是 Go 可执行文件是静态构建的，这意味着它们不需要外部库来运行。使用`strip(1)`命令可以使生成的可执行文件稍微变小，但不要期望奇迹发生：

```go
$ strip hw
$ ls -l hw
-rwxr-xr-x  1 mtsouk  staff  1540096 Feb 18 17:41 hw
```

前面的过程与 Go 本身无关，因为`strip(1)`是一个 Unix 命令，它删除或修改文件的符号表，从而减小它们的大小。Go 可以自行执行`strip(1)`命令的工作并创建更小的可执行文件，但这种方法并不总是有效：

```go
$ ls -l hw
-rwxr-xr-x 1 mtsouk mtsouk 1823712 Feb 18 17:35 hw
$ CGO_ENABLED=0 go build -ldflags "-s" -a hw.go
$ ls -l hw
-rwxr-xr-x 1 mtsouk mtsouk 1328032 Feb 18 17:44 hw
$ file hw
hw: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), statically linked, stripped
```

上述输出来自 Linux 机器；当在 macOS 机器上使用相同的编译命令时，对可执行文件的大小不会有任何影响。

# Go 环境变量

`go tool`可以使用许多专门用于 Go 的 Unix shell 环境变量，包括`GOROOT`、`GOHOME`、`GOBIN`和`GOPATH`。最重要的 Go 环境变量是`GOPATH`，它指定了你的工作空间的位置。通常，这是你在开发 Go 代码时需要定义的唯一环境变量；它与项目文件的组织方式有关。这意味着每个项目将被组织成三个主要目录，名为`src`、`pkg`和`bin`。然而，包括我在内的许多人更喜欢不使用`GOPATH`，而是手动组织他们的项目文件。

因此，如果你是 shell 变量的忠实粉丝，你可以将所有这些定义放在`.bashrc`或`.profile`中，这意味着这些环境变量将在每次登录到 Unix 机器时都处于活动状态。如果你没有使用 Bash shell（默认的 Linux 和 macOS shell），那么你可能需要使用另一个启动文件。查看你喜欢的 Unix shell 的文档，找出要使用哪个文件。

下面的截图显示了以下命令的部分输出，该命令显示了 Go 使用的所有环境变量：

```go
$ go help environment
```

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/go-sys-prog/img/87508a77-cb59-4e6f-ac23-d4a412f73ebc.png)

“go help environment”命令的输出

你可以通过执行下一个命令并将`NAME`替换为你感兴趣的环境变量来找到关于特定环境变量的额外信息：

```go
$ go env NAME  
```

所有这些环境变量与实际的 Go 代码或程序的执行无关，但它们可能会影响开发环境；因此，如果在尝试编译 Go 程序时遇到任何奇怪的行为，检查你正在使用的环境变量。

# 使用命令行参数

命令行参数允许你的程序获取输入，比如你想要处理的文件的名称，而不必编写程序的不同版本。因此，如果你无法处理传递给它的命令行参数，你将无法创建任何有用的系统软件。

这里有一个天真的 Go 程序，名为`cla.go`，它打印出所有的命令行参数，包括可执行文件的名称：

```go
package main 

import "fmt" 
import "os" 

func main() { 
   arguments := os.Args 
   for i := 0; i < len(arguments); i++ { 
         fmt.Println(arguments[i]) 
   } 
} 
```

正如您所看到的，Go 需要一个名为`os`的额外包，以便读取存储在`os.Args`数组中的程序的命令行参数。如果您不喜欢有多个导入语句，您可以将两个导入语句重写如下，我觉得这样更容易阅读：

```go
import ( 
   "fmt" 
   "os" 
)
```

当您使用单个导入块导入所有包时，`gofmt`实用程序会按字母顺序排列包名。

`cla.go`的 Go 代码很简单，它将所有命令行参数存储在一个数组中，并使用`for`循环进行打印。正如您将在接下来的章节中看到的，`os`包可以做更多的事情。如果您熟悉 C 语言，您应该知道在 C 中，命令行参数会自动传递给程序，而您无需包含任何额外的头文件来读取它们。Go 使用了一种不同的方法，这样可以给您更多的控制，但需要稍微更多的代码。

在构建后执行`cla.go`将创建以下类型的输出：

```go
$ ./cla 1 2 three
./cla
1
2
three
```

# 找到命令行参数的总和

现在，让我们尝试一些不同和棘手的事情：您将尝试找到给定给 Go 程序的命令行参数的总和。因此，您将把命令行参数视为数字。尽管主要思想保持不变，但实现完全不同，因为您将不得不将命令行参数转换为数字。Go 程序的名称将是`addCLA.go`，它可以分为两部分。

第一部分是程序的序言：

```go
package main 

import ( 
   "fmt" 
   "os" 
   "strconv" 
) 
```

您需要`fmt`包来打印输出和`os`包来读取命令行参数。由于命令行参数存储为字符串，您还需要`srtconv`包将其转换为整数。

第二部分是`main()`函数的实现：

```go
func main() { 
   arguments := os.Args 
   sum := 0 
   for i := 1; i < len(arguments); i++ { 
         temp, _ := strconv.Atoi(arguments[i]) 
         sum = sum + temp 
   } 
   fmt.Println("Sum:", sum) 
} 
```

`strconv.Atoi()`函数返回两个值：第一个是整数，前提是转换成功，第二个是错误变量。

请注意，大多数 Go 函数都会返回一个错误变量，这个错误变量应该始终被检查，特别是在生产软件中。

如果您不使用`strconv.Atoi()`函数，那么您将会遇到两个问题：

+   第一个问题是程序将尝试使用字符串执行加法，这是数学运算。

+   第二个问题是您将无法判断命令行参数是否是有效的整数，这可以通过检查`strconv.Atoi()`的返回值来完成

因此，`strconv.Atoi()`不仅可以完成所需的工作，而且还可以告诉我们给定参数是否是有效的整数，这同样重要，因为它允许我们以不同的方式处理不合适的参数。

`addCLA.go`中的另一个关键的 Go 代码是忽略`strconv.Atoi()`函数的错误变量的值，使用模式匹配。`_`字符在 Go 模式匹配术语中表示“匹配所有”，但不要将其保存在任何变量中。

Go 支持四种不同大小的有符号和无符号整数，分别命名为 int8、int16、int32、int64、uint8、uint16、uint32 和 uint64。然而，Go 还有`int`和`uint`，它们是当前平台上最有效的有符号和无符号整数。因此，当有疑问时，请使用`int`或`uint`。

使用正确类型的命令行参数执行`addCLA.go`将创建以下输出：

```go
$ go run addCLA.go 1 2 -1 -3
Sum: -1
$ go run addCLA.go
Sum: 0
```

`addCLA.go`的好处是，如果没有参数，它不会崩溃，而无需您担心。然而，看到程序如何处理错误输入会更有趣，因为您永远不能假设会得到正确类型的输入：

```go
$ go run addCLA.go !
Sum: 0
$ go run addCLA.go ! -@
Sum: 0
$ go run addCLA.go ! -@ 1 2
Sum: 3
```

正如您所看到的，如果程序得到错误类型的输入，它不会崩溃，并且不会在其计算中包含错误的输入。这里的一个主要问题是`addCLA.go`不会打印任何警告消息，以让用户知道它们的某些输入被忽略。这种危险的代码会创建不稳定的可执行文件，当给出错误类型的输入时可能会产生安全问题。因此，这里的一般建议是，您永远不应该期望或依赖 Go 编译器，或任何其他编译器或程序，来处理这些事情，因为这是您的工作。

第三章《高级 Go 功能》将更详细地讨论 Go 中的错误处理，并将介绍上一个程序的更好和更安全的版本。目前，我们都应该高兴地证明我们的程序不会因任何输入而崩溃。

尽管这并不是一个完美的情况，但如果您知道您的程序对某些特定类型的输入不起作用，那也不是那么糟糕。糟糕的是，当开发人员不知道存在某些类型的输入可能会导致程序失败时，因为您无法纠正您不相信或认为是错误的东西。

尽管处理命令行参数看起来很容易，但如果您的命令行实用程序支持大量选项和参数，它可能会变得非常复杂。第五章《文件和目录》将更多地讨论使用`flag`标准 Go 包处理命令行选项、参数和参数。

# 用户输入和输出

根据 Unix 哲学，当程序成功完成其工作时，它不会生成任何输出。然而，出于许多原因，并非所有程序都能成功完成，并且它们需要通过打印适当的消息来通知用户其问题。此外，一些系统工具需要从用户那里获取输入，以决定如何处理可能出现的情况。

Go 用户输入和输出的英雄是`fmt`包，本节将向您展示如何通过从最简单的任务开始来执行这两个任务。

了解有关`fmt`包的更多信息的最佳位置是其文档页面，该页面可以在[`golang.org/pkg/fmt/`](https://golang.org/pkg/fmt/)找到。

# 获取用户输入

除了使用命令行参数来获取用户输入（这是系统编程中的首选方法），还有其他方法可以要求用户输入。

当使用`-i`选项时，两个示例是`rm(1)`和`mv(1)`命令：

```go
$ touch aFile
$ rm -i aFile
remove aFile? y
$ touch aFile
$ touch ../aFile
$ mv -i ../aFile .
overwrite ./aFile? (y/n [n]) y
```

因此，本节将向您展示如何在您的 Go 代码中模仿先前的行为，使您的程序能够理解`-i`参数，而不实际实现`rm(1)`或`mv(1)`的功能。

用于获取用户输入的最简单函数称为`fmt.Scanln()`，并读取整行。其他用于获取用户输入的函数包括`fmt.Scan()`、`fmt.Scanf()`、`fmt.Sscanf()`、`fmt.Sscanln()`和`fmt.Sscan()`。

然而，在 Go 中存在一种更高级的方式来从用户那里获取输入；它涉及使用`bufio`包。然而，使用`bufio`包从用户那里获取简单的响应有点过度。

`parameter.go`的 Go 代码如下：

```go
package main 

import ( 
   "fmt" 
   "os" 
   "strings" 
) 

func main() { 
   arguments := os.Args 
   minusI := false 
   for i := 0; i < len(arguments); i++ { 
         if strings.Compare(arguments[i], "-i") == 0 { 
               minusI = true 
               break 
         } 
   } 

   if minusI { 
         fmt.Println("Got the -i parameter!") 
         fmt.Print("y/n: ") 
         var answer string 
         fmt.Scanln(&answer) 
         fmt.Println("You entered:", answer) 
   } else { 
         fmt.Println("The -i parameter is not set") 
   } 
} 
```

所呈现的代码并不特别聪明。它只是使用`for`循环访问所有命令行参数，并检查当前参数是否等于`-i`字符串。一旦它通过`strings.Compare()`函数找到匹配，它就会将`minusI`变量的值从 false 更改为 true。然后，因为它不需要再查找，它使用`break`语句退出`for`循环。如果给出了`-i`参数，带有`if`语句的块将要求用户使用`fmt.Scanln()`函数输入`y`或`n`。

请注意，`fmt.Scanln()` 函数使用了指向 `answer` 变量的指针。由于 Go 通过值传递变量，我们必须在这里使用指针引用，以便将用户输入保存到 `answer` 变量中。一般来说，从用户读取数据的函数往往是这样工作的。

执行 `parameter.go` 会产生以下类型的输出：

```go
$ go run parameter.go
The -i parameter is not set
$ go run parameter.go -i
Got the -i parameter!
y/n: y
You entered: y
```

# 打印输出

在 Go 中打印东西的最简单方法是使用 `fmt.Println()` 和 `fmt.Printf()` 函数。`fmt.Printf()` 函数与 C 的 `printf(3)` 函数有许多相似之处。你也可以使用 `fmt.Print()` 函数来代替 `fmt.Println()`。

`fmt.Print()` 和 `fmt.Println()` 之间的主要区别是，后者每次调用时自动打印一个换行符。`fmt.Println()` 和 `fmt.Printf()` 之间的最大区别是，后者需要为它将打印的每样东西提供一个格式说明符，就像 C 的 `printf(3)` 函数一样。这意味着你可以更好地控制你在做什么，但你需要写更多的代码。Go 将这些说明符称为**动词**，你可以在 [`golang.org/pkg/fmt/`](https://golang.org/pkg/fmt/) 找到更多关于支持的动词的信息。

# Go 函数

函数是每种编程语言的重要元素，因为它们允许你将大型程序分解为更小更易管理的部分，但它们必须尽可能独立，并且只能完成一项任务。因此，如果你发现自己编写了多个任务的函数，可能需要考虑编写多个函数。然而，Go 不会拒绝编译长、复杂或者做多个任务的函数。

一个安全的指示，你需要创建一个新函数的时候是，当你发现自己在程序中多次使用相同的 Go 代码。同样，一个安全的指示，你需要将一些函数放在一个模块中的时候是，当你发现自己在大多数程序中一直使用相同的函数。

最受欢迎的 Go 函数是 `main()`，它可以在每个独立的 Go 程序中找到。如果你看一下 `main()` 函数的定义，你很快就会意识到 Go 中的函数声明以 `func` 关键字开头。

一般来说，你必须尽量编写少于 20-30 行 Go 代码的函数。拥有更小的函数的一个好的副作用是，它们可以更容易地进行优化，因为你可以清楚地找出瓶颈在哪里。

# 给 Go 函数的返回值命名

与 C 不同，Go 允许你给函数的返回值命名。此外，当这样的函数有一个没有参数的返回语句时，函数会自动返回每个命名返回值的当前值。请注意，这样的函数按照它们在函数定义中声明的顺序返回它们的值。

给返回值命名是一个非常方便的 Go 特性，可以帮助你避免各种类型的错误，所以要使用它。

我的个人建议是：给你的函数的返回值命名，除非有非常好的理由不这样做。

# 匿名函数

匿名函数可以在一行内定义，无需名称，它们通常用于实现需要少量代码的事物。在 Go 中，一个函数可以返回一个匿名函数，或者将一个匿名函数作为其参数之一。此外，匿名函数可以附加到 Go 变量上。

对于匿名函数来说，最好的做法是有一个小的实现和局部使用。如果一个匿名函数没有局部使用，那么你可能需要考虑将其变成一个常规函数。

当匿名函数适合一项任务时，它非常方便，可以让你的生活更轻松；只是不要在程序中没有充分理由的情况下使用太多匿名函数。

# 说明 Go 函数

本小节将展示使用`functions.go`程序的 Go 代码来演示前面类型的函数的示例。程序的第一部分包含了预期的序言和`unnamedMinMax()`函数的实现：

```go
package main 

import ( 
   "fmt" 
) 

func unnamedMinMax(x, y int) (int, int) { 
   if x > y { 
         min := y 
         max := x 
         return min, max 
   } else { 
         min := x 
         max := y 
         return min, max 
   } 
} 
```

`unnamedMinMax()`函数是一个常规函数，它以两个整数作为输入，分别命名为`x`和`y`。它使用`return`语句返回两个整数。

`functions.go`的下一部分定义了另一个函数，但这次使用了命名返回值，它们被称为`min`和`max`：

```go
func minMax(x, y int) (min, max int) { 
   if x > y { 
         min = y 
         max = x 
   } else { 
         min = x 
         max = y 
   } 
   return min, max 
} 
```

下一个函数是`minMax()`的改进版本，因为你不必显式定义返回语句的返回变量：

```go
func namedMinMax(x, y int) (min, max int) { 
   if x > y { 
         min = y 
         max = x 
   } else { 
         min = x 
         max = y 
   } 
   return 
} 
```

然而，你可以通过查看`namedMinMax()`函数的定义轻松地发现将返回哪些值。`namedMinMax()`函数将以此顺序返回`min`和`max`的当前值。

下一个函数展示了如何对两个整数进行排序，而不必使用临时变量：

```go
func sort(x, y int) (int, int) { 
   if x > y { 
         return x, y 
   } else { 
         return y, x 
   } 
} 
```

前面的代码还展示了 Go 函数可以返回多个值的便利之处。`functions.go`的最后一部分包含了`main()`函数；这可以分为两部分来解释。

第一部分涉及匿名函数：

```go
 func main() {
   y := 4 
   square := func(s int) int { 
         return s * s 
   } 
   fmt.Println("The square of", y, "is", square(y)) 

   square = func(s int) int { 
         return s + s 
   } 
   fmt.Println("The square of", y, "is", square(y)) 
```

在这里，你定义了两个匿名函数：第一个计算给定整数的平方，而第二个则是给定整数的两倍。重要的是，它们都分配给了同一个变量，这是完全错误的，也是一种危险的做法。因此，不正确使用匿名函数可能会产生严重的错误，所以要格外小心，不要将同一个变量分配给不同的匿名函数。

请注意，即使将函数分配给变量，它仍然被视为匿名函数。

`main()`的第二部分使用了一些已定义的函数：

```go
   fmt.Println(minMax(15, 6)) 
   fmt.Println(namedMinMax(15, 6)) 
   min, max := namedMinMax(12, -1) 
   fmt.Println(min, max) 
} 
```

有趣的是，你可以使用两个变量在一个语句中获取`namedMinMax()`函数的两个返回值。

执行`functions.go`生成以下输出：

```go
$ go run functions.go
The square of 4 is 16
The square of 4 is 8
6 15
6 15
-1 12
```

下一部分展示了更多匿名函数与`defer`关键字结合的例子。

# defer 关键字

`defer`关键字推迟了函数的执行，直到包围函数返回，并且在文件 I/O 操作中被广泛使用。这是因为它可以让你不必记住何时关闭打开的文件。

展示`defer`的 Go 代码文件名为`defer.go`，包含四个主要部分。

第一部分是预期的序言，以及`a1()`函数的定义：

```go
package main 

import ( 
   "fmt" 
) 

func a1() { 
   for i := 0; i < 3; i++ { 
         defer fmt.Print(i, " ") 
   } 
} 
```

在前面的例子中，`defer`关键字与简单的`fmt.Print()`语句一起使用。

第二部分是`a2()`函数的定义：

```go
func a2() { 
   for i := 0; i < 3; i++ { 
         defer func() { fmt.Print(i, " ") }() 
   } 
} 
```

在`defer`关键字之后，有一个未附加到变量的匿名函数，这意味着在`for`循环终止后，匿名函数将自动消失。所呈现的匿名函数不带参数，但在`fmt.Print()`语句中使用了`i`局部变量。

下一部分定义了`a3()`函数，并包含以下 Go 代码：

```go
func a3() { 
   for i := 0; i < 3; i++ { 
         defer func(n int) { fmt.Print(n, " ") }(i) 
   } 
} 
```

这次，匿名函数需要一个名为`n`的整数参数，并从变量`i`中取其值。

`defer.go`的最后一部分是`main()`函数的实现：

```go
func main() { 
   a1() 
   fmt.Println() 
   a2() 
   fmt.Println() 
   a3() 
   fmt.Println() 
} 
```

执行`defer.go`将打印以下内容，这可能会让你感到惊讶：

```go
$ go run defer.go
2 1 0
3 3 3
2 1 0
```

因此，现在是时候通过检查`a1()`、`a2()`和`a3()`执行其代码的方式来解释`defer.go`的输出。输出的第一行验证了在包围函数返回后，延迟函数以**后进先出**（**LIFO**）的顺序执行。`a1()`中的`for`循环延迟了一个使用`i`变量当前值的函数调用。结果，所有数字都以相反的顺序打印，因为`i`的最后使用值是`2`。`a2()`函数比较棘手，因为由于`defer`，函数体在`for`循环结束后被评估，而它仍在引用局部`i`变量，这时对于所有评估的函数体来说，`i`变量的值都等于`3`。结果，`a2()`打印数字`3`三次。简而言之，您有三个使用变量的最后值的函数调用，因为这是传递给函数的内容。但是，`a3()`函数不是这种情况，因为`i`的当前值作为参数传递给延迟的函数，这是由`a3()`函数定义末尾的`(i)`代码决定的。因此，每次执行延迟的函数时，它都有一个不同的`i`值要处理。

由于使用`defer`可能会很复杂，您应该编写自己的示例，并在执行实际的 Go 代码之前尝试猜测它们的输出，以确保您的程序表现如预期。尝试能够判断函数参数何时被评估以及函数体何时实际执行。

您将在第六章 *文件输入和输出*中再次看到`defer`关键字的作用。

# 在函数中使用指针变量

**指针**是内存地址，以提高速度为代价，但代码难以调试且容易出现错误。C 程序员对此了解更多。在 Go 函数中使用指针变量的示例在`pointers.go`文件中进行了说明，可以分为两个主要部分。第一部分包含两个函数的定义和一个名为`complex`的新结构。

```go
func withPointer(x *int) { 
   *x = *x * *x 
} 

type complex struct { 
   x, y int 
} 

func newComplex(x, y int) *complex { 
   return &complex{x, y} 
} 
```

第二部分说明了在`main()`函数中使用先前定义的内容：

```go
func main() { 
   x := -2 
   withPointer(&x) 
   fmt.Println(x) 

   w := newComplex(4, -5) 
   fmt.Println(*w) 
   fmt.Println(w) 
} 
```

由于`withPointer()`函数使用指针变量，您不需要返回任何值，因为对传递给函数的变量的任何更改都会自动存储在传递的变量中。请注意，您需要在变量名前面加上`&`，以便将其作为指针而不是作为值传递。`complex`结构有两个成员，名为`x`和`y`，它们都是整数变量。

另一方面，`newComplex()`函数返回了一个指向先前在`pointers.go`中定义的`complex`结构的指针，需要存储在一个变量中。为了打印`newComplex()`函数返回的复杂变量的内容，您需要在其前面加上一个`*`字符。

执行`pointers.go`会生成以下输出：

```go
$ go run pointers.go
4
{4 -5}
&{4 -5} 
```

我不建议业余程序员在使用库所需之外使用指针，因为它们可能会引起问题。然而，随着经验的增加，您可能希望尝试使用指针，并根据您尝试解决的问题决定是否使用它们。

# Go 数据结构

Go 带有许多方便的**数据结构**，可以帮助您存储自己的数据，包括数组、切片和映射。您应该能够在任何数据结构上执行的最重要的任务是以某种方式访问其所有元素。第二个重要任务是在知道其索引或键后直接访问特定元素。最后两个同样重要的任务是向数据结构中插入元素和删除元素。一旦您知道如何执行这四个任务，您将完全控制数据结构。

# 数组

由于其速度快，并且几乎所有编程语言都支持，数组是最受欢迎的数据结构。您可以在 Go 中声明数组如下：

```go
myArray := [4]int{1, 2, 4, -4} 
```

如果您希望声明具有两个或三个维度的数组，可以使用以下表示法：

```go
twoD := [3][3]int{{1, 2, 3}, {4, 5, 6}, {7, 8, 9}} 
threeD := [2][2][2]int{{{1, 2}, {3, 4}}, {{5, 6}, {7, 8}}} 
```

数组每个维度的第一个元素的索引是 0，每个维度的第二个元素的索引是 1，依此类推。可以轻松地访问、赋值或打印前三个数组中的单个元素。

```go
myArray[0] 
twoD[1][2] = 15 
threeD[0][1][1] = -1

```

访问数组所有元素的最常见方法是使用`len()`函数找到其大小，然后使用`for`循环。然而，还有更酷的方法可以访问数组的所有元素，这涉及在`for`循环中使用`range`关键字，并允许您绕过`len()`函数的使用，当您必须处理两个或更多维数组时，这是非常方便的。

这个小节中的所有代码都保存在`arrays.go`中，你应该自己看一下。运行`arrays.go`会生成以下输出：

```go
$ go run arrays.go
1 2 4 -4
0 2 -2 6 7 8
1 2 3 4 5 15 7 8 9
[[1 2] [3 -1]] [[5 6] [7 8]]
```

现在让我们尝试通过尝试访问一些奇怪的数组元素来破坏事物，比如访问一个不存在的索引号的元素或者访问一个负索引号的元素，使用以下名为`breakMe.go`的 Go 程序：

```go
package main 

import "fmt" 

func main() { 
   myArray := [4]int{1, 2, 4, -4} 
   threeD := [2][2][2]int{{{1, 2}, {3, 4}}, {{5, 6}, {7, 8}}} 
   fmt.Println("myArray[-1]:", myArray[-1])
   fmt.Println("myArray[10]:", myArray[10]) 
   fmt.Println("threeD[-1][20][0]:", threeD[-1][20][0]) 
} 
```

执行`breakMe.go`将生成以下输出：

```go
$ go run breakMe.go
# command-line-arguments
./breakMe.go:8: invalid array index -1 (index must be non-negative)
./breakMe.go:9: invalid array index 10 (out of bounds for 4-element array)
./breakMe.go:10: invalid array index -1 (index must be non-negative)
./breakMe.go:10: invalid array index 20 (out of bounds for 2-element array)
```

Go 认为可以检测到的编译器问题是编译器错误，因为这有助于开发工作流程，这就是为什么要打印`breakMe.go`的所有越界数组访问错误的原因。

尝试破坏事物是一个非常有教育意义的过程，你应该一直尝试。简而言之，知道某些事情不起作用的时候同样有用，就像知道什么时候起作用一样有用。

尽管 Go 数组很简单，但存在许多严重的缺点：

+   首先，一旦定义了数组，就不能改变其大小，这意味着 Go 数组不是动态的。简而言之，如果您想要在没有空间的现有数组中包含额外的元素，您将需要创建一个更大的数组，并将所有元素从旧数组复制到新数组中。

+   其次，当你将数组传递给函数时，实际上是传递了数组的副本，这意味着你在函数内部对数组所做的任何更改在函数结束后都会丢失。

+   最后，将大数组传递给函数可能会非常慢，主要是因为 Go 必须创建数组的第二个副本。解决所有这些问题的方法是使用切片。

# 切片

在许多编程语言中，你不会找到**切片**的概念，尽管它既聪明又方便。切片与数组有许多相似之处，并且允许您克服数组的缺点。

切片有容量和长度属性，它们并不总是相同的。切片的长度与具有相同数量元素的数组的长度相同，并且可以使用`len()`函数找到。切片的容量是为该特定切片分配的当前空间，并可以使用`cap()`函数找到。由于切片的大小是动态的，如果切片的空间不足，Go 会自动将其当前长度加倍以为更多元素腾出空间。

切片作为引用传递给函数，你在函数内部对切片所做的任何修改在函数结束后都不会丢失。此外，将大切片传递给函数比传递相同数组要快得多，因为 Go 不必复制切片，它只会传递切片变量的内存地址。

这个小节的代码保存在`slices.go`中，可以分为三个主要部分。

第一部分是序言以及定义两个以`slice`作为输入的函数：

```go
package main 

import ( 
   "fmt" 
) 

func change(x []int) { 
   x[3] = -2 
} 

func printSlice(x []int) { 
   for _, number := range x {

         fmt.Printf("%d ", number) 
   } 
   fmt.Println() 
} 
```

请注意，当您在切片上使用`range`时，您会在其迭代中得到一对值。第一个是索引号，第二个是元素的值。当您只对存储的元素感兴趣时，您可以忽略索引号，就像`printSlice()`函数一样。

`change()`函数只更改输入切片的第四个元素，而`printSlice()`是一个实用函数，用于打印其切片输入变量的内容。在这里，您还可以看到使用`fmt.Printf()`函数打印整数。

第二部分创建了一个名为`aSlice`的新切片，并使用第一部分中看到的`change()`函数对其进行更改：

```go
func main() { 
   aSlice := []int{-1, 4, 5, 0, 7, 9} 
   fmt.Printf("Before change: ") 
   printSlice(aSlice) 
   change(aSlice) 
   fmt.Printf("After change: ") 
   printSlice(aSlice) 
```

尽管您定义填充切片的方式与定义数组的方式有一些相似之处，但最大的区别在于您不必声明切片将具有的元素数量。

最后一部分说明了 Go 切片的容量属性以及`make()`函数：

```go
   fmt.Printf("Before. Cap: %d, length: %d\n", cap(aSlice), len(aSlice)) 
   aSlice = append(aSlice, -100) 
   fmt.Printf("After. Cap: %d, length: %d\n", cap(aSlice), len(aSlice)) 
   printSlice(aSlice) 
   anotherSlice := make([]int, 4) 
   fmt.Printf("A new slice with 4 elements: ") 
   printSlice(anotherSlice) 
} 
```

`make()`函数会自动将切片的元素初始化为该类型的零值，可以通过`printSlice`（`anotherSlice`）语句的输出进行验证。请注意，使用`make()`函数创建切片时需要指定元素的数量。

执行`slices.go`生成以下输出：

```go
$ go run slices.go 
Before change: -1 4 5 0 7 9 
After change: -1 4 5 -2 7 9 
Before. Cap: 6, length: 6 
After. Cap: 12, length: 7 
-1 4 5 -2 7 9 -100 
A new slice with 4 elements: 0 0 0 0 
```

从输出的第三行可以看出，切片的容量和长度在定义时是相同的。但是，使用`append()`向切片添加新元素后，其长度从`6`变为`7`，但其容量翻倍，从`6`变为`12`。将切片的容量翻倍的主要优势是性能更好，因为 Go 不必一直分配内存空间。

您可以从现有数组的元素创建一个切片，并使用`copy()`函数将现有切片复制到另一个切片。这两个操作都有一些棘手的地方，您应该进行实验。

第六章，*文件输入和输出*，将讨论一种特殊类型的切片，称为字节切片，可用于文件 I/O 操作。

# 映射

Go 中的 Map 数据类型等同于其他编程语言中的哈希表。映射的主要优势是它们可以使用几乎任何数据类型作为其索引，这种情况下称为**key**。要将数据类型用作键，它必须是可比较的。

因此，让我们看一个示例 Go 程序，名为`maps.go`，我们将用它进行说明。`maps.go`的第一部分包含您期望的 Go 代码前言：

```go
package main 

import ( 
   "fmt" 
) 

func main() { 

```

然后，您可以定义一个新的空映射，其中字符串作为键，整数作为值，如下所示：

```go
   aMap := make(map[string]int) 
```

之后，您可以向`aMap`映射添加新的键值对，如下所示：

```go
   aMap["Mon"] = 0 
   aMap["Tue"] = 1 
   aMap["Wed"] = 2 
   aMap["Thu"] = 3 
   aMap["Fri"] = 4 
   aMap["Sat"] = 5 
   aMap["Sun"] = 6 
```

然后，您可以获取现有键的值：

```go
   fmt.Printf("Sunday is the %dth day of the week.\n", aMap["Sun"]) 

```

然而，您可以对现有`map`执行的最重要的操作在以下 Go 代码中进行了说明：

```go
   _, ok := aMap["Tuesday"] 
   if ok { 
         fmt.Printf("The Tuesday key exists!\n") 
   } else { 
         fmt.Printf("The Tuesday key does not exist!\n") 
   } 
```

上述 Go 代码的作用是利用 Go 的错误处理能力，以验证映射的键在尝试获取其值之前是否已存在。这是尝试获取`map`键的值的正确和安全方式，因为要求一个不存在的`key`的值将导致返回零。这样就无法确定结果是零，是因为您请求的`key`不存在，还是因为相应键的元素实际上具有零值。

以下 Go 代码显示了如何遍历现有映射的所有键：

```go
   count := 0 
   for key, _ := range aMap { 
         count++ 
         fmt.Printf("%s ", key) 
   } 
   fmt.Printf("\n") 
   fmt.Printf("The aMap has %d elements\n", count) 
```

如果您对访问映射的键和值没有兴趣，只想计算其对数，那么您可以使用前面`for`循环的下一个更简单的变体：

```go
   count = 0 
   delete(aMap, "Fri") 
   for _, _ = range aMap { 
         count++ 
   } 
   fmt.Printf("The aMap has now %d elements\n", count) 
```

`main()`函数的最后一部分包含以下 Go 代码，用于说明定义和初始化映射的另一种方式：

```go
   anotherMap := map[string]int{ 
         "One":   1, 
         "Two":   2, 
         "Three": 3, 
         "Four":  4, 
   } 
   anotherMap["Five"] = 5 
   count = 0 
   for _, _ = range anotherMap { 
         count++ 
   } 
   fmt.Printf("anotherMap has %d elements\n", count) 
} 
```

但是，除了不同的初始化之外，所有其他`map`操作都完全相同。执行`maps.go`生成以下输出：

```go
$ go run maps.go
Sunday is the 6th day of the week.
The Tuesday key does not exist!
Wed Thu Fri Sat Sun Mon Tue
The aMap has 7 elements
The aMap has now 6 elements
anotherMap has 5 elements
```

映射是一种非常方便的数据结构，当开发系统软件时，您很有可能会需要它们。

# 将数组转换为地图

这个小节将执行一个实际的操作，即在不提前知道`array`大小的情况下将数组转换为地图。`array2map.go`的 Go 代码可以分为三个主要部分。第一部分是标准的 Go 代码，包括所需的包和`main()`函数的开始：

```go
package main 

import ( 
   "fmt" 
   "strconv" 
) 

func main() { 
```

实现核心功能的第二部分如下：

```go
anArray := [4]int{1, -2, 14, 0} 
aMap := make(map[string]int) 

length := len(anArray) 
for i := 0; i < length; i++ { 
   fmt.Printf("%s ", strconv.Itoa(i)) 
   aMap[strconv.Itoa(i)] = anArray[i] 
} 
```

首先定义`array`变量和将要使用的`map`变量。`for`循环用于访问所有数组元素并将它们添加到`map`中。`strconv.Itoa()`函数将`array`的索引号转换为字符串。

请记住，如果你知道地图的所有键都将是连续的正整数，你可能会考虑使用数组或切片而不是地图。实际上，即使键不是连续的，数组和切片也比地图更便宜，所以你最终可能会得到一个稀疏矩阵。

最后一部分仅用于打印生成的地图的内容，使用了`for`循环的预期范围形式：

```go
for key, value := range aMap {
    fmt.Printf("%s: %d\n", key, value) 
   } 
} 
```

正如您可以轻松猜到的那样，开发逆操作并不总是可能的，因为`map`是比`array`更丰富的数据结构。但是，使用更强大的数据结构所付出的代价是时间，因为数组操作通常更快。

# 结构

尽管数组、切片和地图都非常有用，但它们不能在同一个位置保存多个值。当您需要对各种类型的变量进行分组并创建一个新的方便类型时，可以使用结构--结构的各个元素称为字段。

这个小节的代码保存为`dataStructures.go`，可以分为三部分。第一部分包含序言和一个名为`message`的新结构的定义：

```go
package main 

import ( 
   "fmt" 
   "reflect" 
) 

func main() { 

   type message struct {
         X     int 
         Y     int 
         Label string 
   } 
```

消息结构有三个字段，名为`X`、`Y`和`Label`。请注意，结构通常在程序开头和`main()`函数之外定义。

第二部分使用消息结构定义了两个名为`p1`和`p2`的新消息变量，然后使用反射获取有关消息结构的`p1`和`p2`变量的信息：

```go
   p1 := message{23, 12, "A Message"} 
   p2 := message{} 
   p2.Label = "Message 2" 

   s1 := reflect.ValueOf(&p1).Elem() 
   s2 := reflect.ValueOf(&p2).Elem() 
   fmt.Println("S2= ", s2) 
```

最后一部分展示了如何使用`for`循环和`Type()`函数打印结构的所有字段而不知道它们的名称：

```go
   typeOfT := s1.Type() 
   fmt.Println("P1=", p1) 
   fmt.Println("P2=", p2) 

   for i := 0; i < s1.NumField(); i++ {
         f := s1.Field(i)

         fmt.Printf("%d: %s ", i, typeOfT.Field(i).Name) 
         fmt.Printf("%s = %v\n", f.Type(), f.Interface()) 
   } 

} 
```

运行`dataStructures.go`将生成以下类型的输出：

```go
$ go run dataStructures.go
S2=  {0 0 Message 2}
P1= {23 12 A Message}
P2= {0 0 Message 2}
0: X int = 23
1: Y int = 12
2: Label string = A Message
```

如果`struct`定义的字段名称以小写字母开头（`x`而不是`X`），上一个程序将失败，并显示以下错误消息：

```go
panic: reflect.Value.Interface: cannot return value obtained from unexported field or method

```

这是因为小写字段不会被导出；因此，它们不能被`reflect.Value.Interface()`方法使用。您将在下一章中了解更多关于`reflection`的内容。

# 接口

接口是 Go 的高级功能，这意味着如果您对 Go 不太熟悉，可能不希望在程序中使用它们。但是，在开发大型 Go 程序时，接口可能非常实用，这是本书讨论接口的主要原因。

但首先，我将讨论方法，这些是带有特殊接收器参数的函数。您将方法声明为普通函数，并在函数名称之前添加一个额外的参数。这个特殊的参数将函数连接到该额外参数的类型。因此，该参数被称为方法的接收器。您一会儿会看到这样的函数。

简而言之，接口是定义一组需要实现的函数的抽象类型，以便将类型视为接口的实例。当这种情况发生时，我们说该类型满足此接口。因此，接口是两种东西--一组方法和一种类型--它用于定义类型的行为。

让我们用一个例子来描述接口的主要优势。想象一下，你有一个名为 ATYPE 的类型和一个适用于 ATYPE 类型的接口。接受一个 ATYPE 变量的任何函数都可以接受实现了 ATYPE 接口的任何其他变量。

`interfaces.go`的 Go 代码可以分为三部分。第一部分如下所示：

```go
package main 

import ( 
   "fmt" 
) 

type coordinates interface { 
   xaxis() int 
   yaxis() int 
} 

type point2D struct { 
   X int 
   Y int 
} 
```

在这一部分中，你定义了一个名为 coordinates 的接口和一个名为`point2D`的新结构。接口有两个函数，名为`xaxis()`和`yaxis()`。坐标接口的定义表示，如果要转换为坐标接口，必须实现这两个函数。

重要的是注意，接口除了接口本身不声明任何其他特定类型。另一方面，接口的两个函数应声明它们返回值的类型。

第二部分包含以下 Go 代码：

```go
func (s point2D) xaxis() int { 
   return s.X 
} 

func (s point2D) yaxis() int { 
   return s.Y 
} 

func findCoordinates(a coordinates) { 
   fmt.Println("X:", a.xaxis(), "Y:", a.yaxis()) 
} 

type coordinate int 

func (s coordinate) xaxis() int { 
   return int(s) 
} 

func (s coordinate) yaxis() int { 
   return 0 
} 
```

在第二部分中，首先为`point2D`类型实现坐标接口的两个函数。然后开发一个名为`findCoordinates()`的函数，该函数接受一个实现坐标接口的变量。`findCoordinates()`函数只是使用简单的`fmt.Println()`函数调用打印点的两个坐标。然后，定义一个名为 coordinate 的新类型，用于属于*x*轴的点。最后，为 coordinate 类型实现坐标接口。

在编写`interfaces.go`代码时，我认为`coordinates`和`coordinate`这两个名称还不错。在写完上一段之后，我意识到`coordinate`类型本可以改名为`xpoint`以提高可读性。我保留了`coordinates`和`coordinate`这两个名称，以指出每个人都会犯错误，你使用的变量和类型名称必须明智选择。

最后一部分包含以下 Go 代码：

```go
func main() { 

   x := point2D{X: -1, Y: 12}
   fmt.Println(x) 
   findCoordinates(x) 

   y := coordinate(10) 
   findCoordinates(y) 
} 
```

在这一部分中，首先创建一个`point2D`变量，并使用`findCoordinates()`函数打印其坐标，然后创建一个名为`y`的坐标变量，它保存一个单一的坐标值。最后，使用与打印`point2D`变量相同的`findCoordinates()`函数打印`y`变量。

尽管 Go 不是一种面向对象的编程语言，但我将在这里使用一些面向对象的术语。因此，在面向对象的术语中，这意味着`point2D`和`coordinate`类型都是坐标对象。但是，它们都不是*只是*`coordinate`对象。

执行`interfaces.go`会创建以下输出：

```go
$ go run interfaces.go
{-1 12}
X: -1 Y: 12
X: 10 Y: 0
```

我认为在开发系统软件时，Go 接口并不是必需的，但它们是一个方便的 Go 特性，可以使系统应用程序的开发更易读和更简单，所以不要犹豫使用它们。

# 创建随机数

作为一个实际的编程示例，本节将讨论在 Go 中创建随机数。随机数有许多用途，包括生成良好的密码以及创建具有随机数据的文件，这些文件可用于测试其他应用程序。但是，请记住，通常编程语言生成伪随机数，这些数近似于真随机数生成器的属性。

Go 使用`math/rand`包生成随机数，并需要一个种子来开始生成随机数。种子用于初始化整个过程，非常重要，因为如果始终使用相同的种子开始，将始终得到相同的随机数序列。

`random.go`程序有三个主要部分。第一部分是程序的序言：

```go
package main 

import ( 
   "fmt" 
   "math/rand" 
   "os" 
   "strconv" 
   "time" 
) 
```

第二部分是定义`random()`函数，每次调用该函数都会返回一个随机数，使用`rand.Intn()` Go 函数：

```go
func random(min, max int) int { 
   return rand.Intn(max-min) + min 
} 
```

`random()` 函数的两个参数定义了生成的随机数的下限和上限。`random.go` 的最后部分是 `main()` 函数的实现，主要用于调用 `random()` 函数：

```go
func main() { 
   MIN := 0 
   MAX := 0 
   TOTAL := 0 
   if len(os.Args) > 3 { 
         MIN, _ = strconv.Atoi(os.Args[1]) 
         MAX, _ = strconv.Atoi(os.Args[2]) 
         TOTAL, _ = strconv.Atoi(os.Args[3]) 
   } else { 
         fmt.Println("Usage:", os.Args[0], "MIX MAX TOTAL") 
         os.Exit(-1) 
   } 

   rand.Seed(time.Now().Unix()) 
   for i := 0; i < TOTAL; i++ { 
         myrand := random(MIN, MAX) 
         fmt.Print(myrand) 
         fmt.Print(" ") 
   } 
   fmt.Println() 
} 
```

`main()` 函数的一个重要部分涉及处理命令行参数作为整数，并在没有获得正确数量的命令行参数时打印描述性错误消息。这是本书中我们将遵循的标准做法。`random.go` 程序使用 Unix 纪元时间作为随机数生成器的种子，通过调用 `time.Now().Unix()` 函数。要记住的重要事情是，你不必多次调用 `rand.Seed()`。最后，`random.go` 不检查 `strconv.Atoi()` 返回的错误变量以节省书本空间，而不是因为它不必要。

执行 `random.go` 会生成以下类型的输出：

```go
$ go run random.go 12 32 20
29 27 20 23 22 28 13 16 22 26 12 29 22 30 15 19 26 24 20 29

```

如果你希望在 Go 中生成更安全的随机数，你应该使用 `crypto/rand` 包，它实现了一个密码学安全的伪随机数生成器。你可以通过访问其文档页面 [`golang.org/pkg/crypto/rand/`](https://golang.org/pkg/crypto/rand/) 获取有关 `crypto/rand` 包的更多信息。

如果你真的对随机数感兴趣，那么随机数理论的权威参考书是 Donald Knuth 的《计算机编程艺术》第二卷。

# 练习

1.  浏览 Go 文档网站：[`golang.org/doc/`](https://golang.org/doc/)。

1.  编写一个 Go 程序，它会一直读取整数，直到你输入数字 0 为止，然后打印输入中的最小和最大整数。

1.  编写与之前相同的 Go 程序，但这次，你将使用命令行参数获取输入。你认为哪个版本更好？为什么？

1.  编写一个支持两个命令行选项（`-i` 和 `-k`）的 Go 程序，使用 if 语句可以随机顺序。现在将你的程序更改为支持三个命令行参数。正如你将看到的，后一个程序的复杂性太大，无法使用 if 语句处理。

1.  如果映射的索引是自然数，是否有任何情况下使用映射而不是数组是明智且有效的？

1.  尝试将 `array2map.go` 的功能放入一个单独的函数中。

1.  尝试在 Go 中开发自己的随机数生成器，它仍然使用当前时间作为种子，但不使用 `math/rand` 包。

1.  学习如何从现有数组创建切片。当你对切片进行更改时会发生什么？

1.  使用 `copy()` 函数复制现有切片。当目标切片小于源切片时会发生什么？当目标切片大于源切片时会发生什么？

1.  尝试编写一个支持 3D 空间中的点的接口。然后，使用这个接口来支持位于 x 轴上的点。

# 总结

在本章中，你学到了很多东西，包括获取用户输入和处理命令行参数。你熟悉了基本的 Go 结构，并创建了一个生成随机数的 Go 程序。尝试做提供的练习，如果在某些练习中失败，不要灰心。

下一章将讨论许多高级的 Go 特性，包括错误处理、模式匹配、正则表达式、反射、不安全代码、从 Go 调用 C 代码以及 `strace(1)` 命令行实用程序。我将把 Go 与其他编程语言进行比较，并给出实用建议，以避免一些常见的 Go 陷阱。


# 第三章：高级 Go 特性

在上一章中，您学习了如何编译 Go 代码，如何从用户那里获取输入并在屏幕上打印输出，如何创建自己的 Go 函数，Go 支持的数据结构以及如何处理命令行参数。

本章将讨论许多有趣的事情，因此您最好为许多有趣且实用的 Go 代码做好准备，这些代码将帮助您执行许多不同但非常重要的任务，从错误处理开始，以避免一些常见的 Go 错误结束。如果您熟悉 Go，可以跳过您已经知道的内容，但请不要跳过建议的练习。

因此，本章将讨论一些高级的 Go 特性，包括：

+   错误处理

+   错误日志记录

+   模式匹配和正则表达式

+   反射

+   如何使用`strace(1)`和`dtrace(1)`工具来监视 Go 可执行文件的系统调用

+   如何检测不可达的 Go 代码

+   如何避免各种常见的 Go 错误

# Go 中的错误处理

错误经常发生，因此我们的工作是捕捉并处理它们，特别是在编写处理敏感系统信息和文件的代码时。好消息是，Go 有一种特殊的数据类型叫做`error`，可以帮助表示错误状态；如果`error`变量的值为`nil`，则没有错误情况。

正如您在上一章中开发的`addCLA.go`程序中看到的，您可以使用`_`字符忽略大多数 Go 函数返回的`error`变量：

```go
temp, _ := strconv.Atoi(arguments[i]) 
```

然而，这并不被认为是良好的做法，应该避免，特别是在系统软件和其他类型的关键软件（如服务器进程）上。

正如您将在第六章中看到的，*文件输入和输出*，即使是**文件结束**（**EOF**）也是一种错误类型，在从文件中没有剩余内容可读时返回。由于`EOF`在`io`包中定义，您可以按以下方式处理它：

```go
if err == io.EOF {

    // Do something 
} 
```

然而，学习如何开发返回`error`变量的函数以及如何处理它们是最重要的任务，下面将对此进行解释。

# 函数可以返回错误变量

Go 函数可以返回`error`变量，这意味着错误条件可以在函数内部、函数外部或者函数内外都可以处理；后一种情况并不经常发生。因此，本小节将开发一个返回错误消息的函数。相关的 Go 代码可以在`funErr.go`中找到，并将分为三部分呈现。

第一部分包含以下 Go 代码：

```go
package main 

import ( 
   "errors" 
   "fmt" 
   "log" 
) 

func division(x, y int) (int, error, error) { 
   if y == 0 { 
         return 0, nil, errors.New("Cannot divide by zero!") 
   } 
   if x%y != 0 { 
         remainder := errors.New("There is a remainder!") 
         return x / y, remainder, nil 
   } else { 
         return x / y, nil, nil 
   } 

} 
```

除了预期的前言之外，上述代码定义了一个名为`division()`的新函数，该函数返回一个整数和两个`error`变量。如果您还记得您的数学课，当您除两个整数时，除法运算并不总是完美的，这意味着您可能会得到一个不为零的余数。您在`funErr.go`中看到的`errors` Go 包中的`errors.New()`函数创建一个新的`error`变量，使用提供的字符串作为错误消息。

`funErr.go`的第二部分包含以下 Go 代码：

```go
func main() { 
   result, rem, err := division(2, 2) 
   if err != nil { 
         log.Fatal(err) 
   } else { 
         fmt.Println("The result is", result) 
   } 

   if rem != nil { 
         fmt.Println(rem) 
   } 
```

将`error`变量与`nil`进行比较是 Go 中非常常见的做法，可以快速判断是否存在错误条件。

`funErr.go`的最后一部分如下：

```go
   result, rem, err = division(12, 5) 
   if err != nil { 
         log.Fatal(err) 
   } else { 
         fmt.Println("The result is", result) 
   } 

   if rem != nil { 
         fmt.Println(rem) 
   } 

   result, rem, err = division(2, 0) 
   if err != nil { 
         log.Fatal(err) 
   } else { 
         fmt.Println("The result is", result) 
   } 

   if rem != nil { 
         fmt.Println(rem) 
   } 
} 
```

本部分展示了两种错误条件。第一种是具有余数的整数除法，而第二种是无效的除法，因为您不能将一个数除以零。正如名称`log.Fatal()`所暗示的，这个日志函数应该仅用于关键错误，因为当调用时，它会自动终止您的程序。然而，正如您将在下一小节中看到的，存在其他更温和的方式来记录您的错误消息。

执行`funErr.go`会生成以下输出：

```go
$ go run funErr.go
The result is 1
The result is 2
There is a remainder!
2017/03/07 07:39:19 Cannot divide by zero!
exit status 1
```

最后一行是由`log.Fatal()`函数自动生成的，在终止程序之前。重要的是要理解，在调用`log.Fatal()`之后的任何 Go 代码都不会被执行。

# 关于错误记录

Go 提供了可以帮助您以各种方式记录错误消息的函数。您已经在`funErr.go`中看到了`log.Fatal()`，这是一种处理简单错误的相当残酷的方式。简单地说，您应该有充分的理由在代码中使用`log.Fatal()`。一般来说，应该使用`log.Fatal()`而不是`os.Exit()`函数，因为它允许您使用一个函数调用打印错误消息并退出程序。

Go 在`log`标准包中提供了更温和地根据情况行为的附加错误记录函数，包括`log.Printf()`、`log.Print()`、`log.Println()`、`log.Fatalf()`、`log.Fatalln()`、`log.Panic()`、`log.Panicln()`和`log.Panicf()`。请注意，记录函数对于调试目的可能会很有用，因此不要低估它们的作用。

`logging.go`程序使用以下 Go 代码说明了所提到的两个记录函数：

```go
package main 

import ( 
   "log" 
) 

func main() { 
   x := 1 
   log.Printf("log.Print() function: %d", x) 
   x = x + 1 
   log.Printf("log.Print() function: %d", x) 
   x = x + 1 
   log.Panicf("log.Panicf() function: %d", x) 
   x = x + 1 
   log.Printf("log.Print() function: %d", x) 
} 
```

正如您所看到的，`logging.go`不需要`fmt`包，因为它有自己的函数来打印输出。执行`logging.go`将产生以下输出：

```go
$ go run logging.go
2017/03/10 16:51:56 log.Print() function: 1
2017/03/10 16:51:56 log.Print() function: 2
2017/03/10 16:51:56 log.Panicf() function: 3
panic: log.Panicf() function: 3

goroutine 1 [running]:
log.Panicf(0x10b78d0, 0x19, 0xc42003df48, 0x1, 0x1)
      /usr/local/Cellar/go/1.8/libexec/src/log/log.go:329 +0xda
main.main()
      /Users/mtsouk/ch3/code/logging.go:14 +0x1af
exit status 2
```

尽管`log.Printf()`函数的工作方式与`fmt.Printf()`相同，但它会自动打印日志消息打印的日期和时间，就像`funErr.go`中的`log.Fatal()`函数一样。此外，`log.Panicf()`函数的工作方式与`log.Fatal()`类似--它们都会终止当前程序。但是，`log.Panicf()`会打印一些额外的信息，用于调试目的。

Go 还提供了`log/syslog`包，它是 Unix 机器上运行的系统日志服务的简单接口。第七章，*使用系统文件*，将更多地讨论`log/syslog`包。

# 重新审视 addCLA.go 程序

本小节将介绍在前一章中开发的`addCLA.go`程序的改进版本，以使其能够处理任何类型的用户输入。新程序将被称为`addCLAImproved.go`，但是，您将只看到`addCLAImproved.go`和`addCLA.go`之间的差异，使用`diff(1)`命令行实用程序：

```go
$ diff addCLAImproved.go addCLA.go
13,18c13,14
<           temp, err := strconv.Atoi(arguments[i])
<           if err == nil {
<                 sum = sum + temp
<           } else {
<                 fmt.Println("Ignoring", arguments[i])
<           }
---
>           temp, _ := strconv.Atoi(arguments[i])
>           sum = sum + temp
```

这个输出基本上告诉我们的是，在`addCLA.go`中找到的最后两行代码，以`>`字符开头，被`addCLAImproved.go`中以`<`字符开头的代码替换了。两个文件的剩余代码完全相同。

`diff(1)`实用程序逐行比较文本文件，是发现同一文件不同版本之间代码差异的一种方便方法。

执行`addCLAImproved.go`将生成以下类型的输出：

```go
$ go run addCLAImproved.go
Sum: 0
$ go run addCLAImproved.go 1 2 -3
Sum: 0
$ go run addCLAImproved.go 1 a 2 b 3.2 @
Ignoring a
Ignoring b
Ignoring 3.2
Ignoring @
Sum: 3
```

因此，新的改进版本按预期工作，表现可靠，并允许我们区分有效和无效的输入。

# 模式匹配和正则表达式

**模式匹配**在 Go 中扮演着关键角色，它是一种基于**正则表达式**的搜索字符串的技术，用于根据特定的搜索模式搜索一组字符。如果模式匹配成功，它允许您从字符串中提取所需的数据，或者替换或删除它。**语法**是形式语言中字符串的一组生成规则。生成规则描述如何根据语言的语法创建有效的字符串。语法不描述字符串的含义或在任何上下文中可以对其进行的操作，只描述其形式。重要的是要意识到语法是正则表达式的核心，因为没有它，您无法定义或使用正则表达式。

正则表达式和模式匹配并非万能良药，因此不应尝试使用正则表达式解决每个问题，因为它们并不适用于您可能遇到的每种问题。此外，它们可能会给您的软件引入不必要的复杂性。

负责 Go 模式匹配功能的 Go 包称为`regexp`，您可以在`regExp.go`中看到其运行情况。`regExp.go`的代码将分为四部分呈现。

第一部分是预期的序言：

```go
package main 

import ( 
   "fmt" 
   "regexp" 
) 
```

第二部分如下：

```go
func main() { 
match, _ := regexp.MatchString("Mihalis", "Mihalis Tsoukalos") 
   fmt.Println(match) 
   match, _ = regexp.MatchString("Tsoukalos", "Mihalis tsoukalos") 
   fmt.Println(match) 
```

`regexp.MatchString()`的两次调用都尝试在给定的字符串（第二个参数）中查找静态字符串（第一个参数）。

第三部分包含一行 Go 代码，但至关重要：

```go
   parse, err := regexp.Compile("[Mm]ihalis") 
```

`regexp.Compile()`函数读取提供的正则表达式并尝试解析它。如果成功解析正则表达式，则`regexp.Compile()`返回`regexp.Regexp`变量类型的值，您随后可以使用它。`regexp.Compile()`函数中的`[Mm]`表达式表示您要查找的内容可以以大写`M`或小写`m`开头。`[`和`]`都是特殊字符，不是正则表达式的一部分。因此，提供的语法是天真的，只匹配单词`Mihalis`和`mihalis`。

最后一部分使用存储在`parse`变量中的先前正则表达式：

```go
   if err != nil { 
         fmt.Printf("Error compiling RE: %s\n", err) 
   } else { 
         fmt.Println(parse.MatchString("Mihalis Tsoukalos")) 
         fmt.Println(parse.MatchString("mihalis Tsoukalos")) 
         fmt.Println(parse.MatchString("M ihalis Tsoukalos")) 
         fmt.Println(parse.ReplaceAllString("mihalis Mihalis", "MIHALIS")) 
   } 
} 
```

运行`regExp.go`会生成以下输出：

```go
$ go run regExp.go
true
false
true
true
false
MIHALIS MIHALIS
```

因此，对`regexp.MatchString()`的第一次调用是匹配的，但第二次调用不是，因为模式匹配是区分大小写的，`Tsoukalos`与`tsoukalos`不匹配。最后的`parse.ReplaceAllString()`函数搜索给定的字符串（`"mihalis Mihalis"`）并用其第二个参数（`"MIHALIS"`）替换每个匹配项。

本节的其余部分将使用静态文本呈现各种示例，因为您还不知道如何读取文本文件。但是，由于静态文本将存储在数组中并逐行处理，因此所呈现的代码可以轻松修改以支持从外部文本文件获取输入。

# 打印行的给定列的所有值

这是一个非常常见的情景，因为您经常需要从结构化文本文件的给定列中获取所有数据，以便随后进行分析。将呈现`readColumn.go`的代码，该代码将在两部分中呈现，打印第三列中的值。

第一部分如下：

```go
package main 

import ( 
   "fmt" 
   "strings" 
) 

func main() { 
   var s [3]string 
   s[0] = "1 2 3" 
   s[1] = "11 12 13 14 15 16" 
   s[2] = "-1 2 -3 -4 -5 6" 
```

在这里，您导入所需的 Go 包并使用包含三个元素的数组定义了一个包含三行的字符串。

第二部分包含以下 Go 代码：

```go
   column := 2 

   for i := 0; i < len(s); i++ { 
         data := strings.Fields(s[i]) 
         if len(data) >= column { 
               fmt.Println((data[column-1])) 
         } 
   } 
} 
```

首先，您定义您感兴趣的列。然后，您开始迭代存储在数组中的字符串。这类似于逐行读取文本文件。`for`循环内的 Go 代码拆分输入行的字段，将它们存储在`data`数组中，验证所需列的值是否存在，并在屏幕上打印它。所有繁重的工作都由方便的`strings.Fields()`函数完成，该函数根据空格字符拆分字符串，如`unicode.IsSpace()`中定义的，并返回一个字符串切片。虽然`readColumn.go`没有使用`regexp.Compile()`函数，但其实现逻辑仍然基于正则表达式的原则，使用了`strings.Fields()`。

要记住的一件重要的事情是，您永远不应信任您的数据。简而言之，始终验证您期望获取的数据是否存在。

执行`readColumn.go`将生成以下类型的输出：

```go
$ go run readColumn.go
2
12
2
```

第六章，*文件输入和输出*，将展示`readColumn.go`的改进版本，您可以将其用作起点，以便修改所示示例的其余部分。

# 创建摘要

在本节中，我们将开发一个程序，它将添加多行文本中给定列的所有值。为了使事情更有趣，列号将作为程序的参数给出。本小节的程序与上一小节的`readColumn.go`的主要区别在于，您需要将每个值转换为整数。

将开发的程序的名称是`summary.go`，可以分为三部分。

第一部分如下：

```go
package main 

import ( 
   "fmt" 
   "os" 
   "strconv" 
   "strings" 
) 

func main() { 
   var s [3]string 
   s[0] = "1 b 3" 
   s[1] = "11 a 1 14 1 1" 
   s[2] = "-1 2 -3 -4 -5" 
```

第二部分包含以下 Go 代码：

```go
   arguments := os.Args 
   column, err := strconv.Atoi(arguments[1]) 
   if err != nil { 
         fmt.Println("Error reading argument") 
         os.Exit(-1) 
   } 
   if column == 0 { 
         fmt.Println("Invalid column") 
         os.Exit(1) 
   } 
```

前面的代码读取您感兴趣的列的索引。如果要使`summary.go`更好，可以检查`column`变量中的负值，并打印适当的错误消息。

`summary.go`的最后一部分如下：

```go
   sum := 0 
   for i := 0; i < len(s); i++ { 
         data := strings.Fields(s[i]) 
         if len(data) >= column { 
               temp, err := strconv.Atoi(data[column-1]) 
               if err == nil { 
                     sum = sum + temp 
               } else { 
                     fmt.Printf("Invalid argument: %s\n", data[column-1]) 
               } 
         } else { 
               fmt.Println("Invalid column!") 
         } 
   } 
   fmt.Printf("Sum: %d\n", sum) 
} 
```

正如您所看到的，`summary.go`中的大部分 Go 代码都是关于处理异常和潜在错误。`summary.go`的核心功能是用几行 Go 代码实现的。

执行`summary.go`将给出以下输出：

```go
$ go run summary.go 0
Invalid column
exit status 1
$ go run summary.go 2
Invalid argument: b
Invalid argument: a
Sum: 2
$ go run summary.go 1
Sum: 11
```

# 查找出现次数

一个非常常见的编程问题是找出 IP 地址在日志文件中出现的次数。因此，本小节中的示例将向您展示如何使用方便的映射结构来做到这一点。`occurrences.go`程序将分为三部分呈现。

第一部分如下：

```go
package main 

import ( 
   "fmt" 
   "strings" 
) 

func main() { 

   var s [3]string 
   s[0] = "1 b 3 1 a a b" 
   s[1] = "11 a 1 1 1 1 a a" 
   s[2] = "-1 b 1 -4 a 1" 
```

第二部分如下：

```go
   counts := make(map[string]int) 

   for i := 0; i < len(s); i++ { 
         data := strings.Fields(s[i]) 
         for _, word := range data { 
               _, ok := counts[word] 
               if ok { 
                     counts[word] = counts[word] + 1 
               } else { 
                     counts[word] = 1 
               } 
         } 
   } 
```

在这里，我们使用上一章的知识创建了一个名为`counts`的映射，并使用两个`for`循环将所需的数据填充到其中。

最后一部分非常小，因为它只是打印`counts`映射的内容：

```go
   for key, _ := range counts {

         fmt.Printf("%s -> %d \n", key, counts[key]) 
   } 
} 
```

执行`occurrences.go`并使用`sort(1)`命令行实用程序对`occurrences.go`的输出进行排序将生成以下类型的输出：

```go
$ go run occurrences.go | sort -n -r -t\  -k3,3
1 -> 8
a -> 6
b -> 3
3 -> 1
11 -> 1
-4 -> 1
-1 -> 1
```

正如你所看到的，传统的 Unix 工具仍然很有用。

# 查找和替换

本小节中的示例将搜索提供的文本，查找给定字符串的两种变体，并用另一个字符串替换它。程序将被命名为`findReplace.go`，实际上将使用 Go 正则表达式。在这种情况下使用`regexp.Compile()`函数的主要原因是它极大地简化了事情，并允许您只访问文本一次。

`findReplace.go`程序的第一部分如下：

```go
package main 

import ( 
   "fmt" 
   "os" 
   "regexp" 
) 
```

下一部分如下：

```go
func main() { 

   var s [3]string 
   s[0] = "1 b 3" 
   s[1] = "11 a B 14 1 1" 
   s[2] = "b 2 -3 B -5" 

   parse, err := regexp.Compile("[bB]")

   if err != nil { 
         fmt.Printf("Error compiling RE: %s\n", err) 
         os.Exit(-1) 
   } 
```

前面的 Go 代码将找到大写`B`或小写`b`（`[bB]`）的每个出现。请注意，还有`regexp.MustCompile()`，它的工作方式类似于`regexp.Compile()`。但是，`regexp.MustCompile()`不会返回一个`error`变量；如果给定的表达式错误并且无法解析，它会直接 panic。因此，`regexp.Compile()`是一个更好的选择。

最后一部分如下：

```go
   for i := 0; i < len(s); i++ { 
         temp := parse.ReplaceAllString(s[i], "C") 
         fmt.Println(temp) 
   } 
} 
```

在这里，您可以使用`parse.ReplaceAllString()`将每个匹配项替换为大写的 C。

执行`findReplace.go`将生成预期的输出：

```go
$ go run findReplace.go
1 C 3
11 a C 14 1 1
C 2 -3 C -5
```

`awk(1)`和`sed(1)`命令行工具可以更轻松地完成大部分以前的任务，但`sed(1)`和`awk(1)`不是通用的编程语言。

# 反射

反射是 Go 的一个高级特性，它允许您动态了解任意对象的类型以及有关其结构的信息。您应该回忆起第二章中的`dataStructures.go`程序，*在 Go 中编写程序*，它使用反射来查找数据结构的字段以及每个字段的类型。所有这些都是在`reflect` Go 包和`reflect.TypeOf()`函数的帮助下完成的，该函数返回一个`Type`变量。

反射在`reflection.go` Go 程序中得到了展示，将分为四部分呈现。

第一个是 Go 程序的序言，代码如下：

```go
package main 

import ( 
   "fmt" 
   "reflect" 
) 
```

第二部分如下：

```go
func main() { 

   type t1 int 
   type t2 int 

   x1 := t1(1) 
   x2 := t2(1) 
   x3 := 1 
```

在这里，您创建了两种新类型，名为`t1`和`t2`，它们都是`int`，以及三个变量，名为`x1`、`x2`和`x3`。

第三部分包含以下 Go 代码：

```go
   st1 := reflect.ValueOf(&x1).Elem() 
   st2 := reflect.ValueOf(&x2).Elem() 
   st3 := reflect.ValueOf(&x3).Elem() 

   typeOfX1 := st1.Type() 
   typeOfX2 := st2.Type() 
   typeOfX3 := st3.Type() 

   fmt.Printf("X1 Type: %s\n", typeOfX1) 
   fmt.Printf("X2 Type: %s\n", typeOfX2) 
   fmt.Printf("X3 Type: %s\n", typeOfX3) 
```

在这里，您可以使用`reflect.ValueOf()`和`Type()`找到`x1`、`x2`和`x3`变量的类型。

`reflection.go`的最后一部分涉及`struct`变量：

```go
   type aStructure struct { 
         X    uint 
         Y    float64 
         Text string 
   } 

   x4 := aStructure{123, 3.14, "A Structure"} 
   st4 := reflect.ValueOf(&x4).Elem() 
   typeOfX4 := st4.Type() 

   fmt.Printf("X4 Type: %s\n", typeOfX4) 
   fmt.Printf("The fields of %s are:\n", typeOfX4) 

   for i := 0; i < st4.NumField(); i++ { 
         fmt.Printf("%d: Field name: %s ", i, typeOfX4.Field(i).Name) 
         fmt.Printf("Type: %s ", st4.Field(i).Type()) 
         fmt.Printf("and Value: %v\n", st4.Field(i).Interface()) 
   } 
} 
```

Go 中存在一些管理反射的规则，但讨论它们超出了本书的范围。您应该记住的是，您的程序可以使用反射来检查自己的结构，这是一种非常强大的能力。

执行`reflection.go`打印以下输出：

```go
$ go run reflection.go
X1 Type: main.t1
X2 Type: main.t2
X3 Type: int
X4 Type: main.aStructure
The fields of main.aStructure are:
0: Field name: X Type: uint and Value: 123
1: Field name: Y Type: float64 and Value: 3.14
2: Field name: Text Type: string and Value: A Structure
```

输出的前两行显示，Go 不认为类型`t1`和`t2`相等，尽管`t1`和`t2`都是`int`类型的别名。

旧习惯难改！

尽管 Go 试图成为一种安全的编程语言，但有时它被迫忘记安全性，并允许程序员做任何他/她想做的事情。

# 从 Go 调用 C 代码

Go 允许您调用 C 代码，因为有时执行某些任务的唯一方法，例如与硬件设备或数据库服务器通信，是使用 C。然而，如果您发现自己在同一个项目中多次使用此功能，您可能需要重新考虑您的方法和编程语言的选择。

在本书的范围之外更多地讨论 Go 中的这一功能。您应该记住的是，您很可能永远不需要从 Go 程序中调用 C 代码。然而，如果您希望探索这一 Go 功能，可以首先访问[cgo 工具的文档](https://golang.org/cmd/cgo/)，并查看[`github.com/golang/go/blob/master/misc/cgo/gmp/gmp.go`](https://github.com/golang/go/blob/master/misc/cgo/gmp/gmp.go)中的代码。

# 不安全的代码

不安全的代码是绕过 Go 的类型安全和内存安全的 Go 代码，需要使用`unsafe`包。您很可能永远不需要在 Go 程序中使用不安全的代码，但如果出于某种奇怪的原因您确实需要使用它，那可能与指针有关。

对于您的程序来说，使用不安全的代码可能是危险的，因此只有在绝对必要时才使用它。如果您不完全确定需要它，那么就不要使用它。

本小节中的示例代码保存为`unsafe.go`，将分两部分呈现。

第一部分如下：

```go
package main 

import ( 
   "fmt" 
   "unsafe" 
) 

func main() { 
   var value int64 = 5

   var p1 = &value 
   var p2 = (*int32)(unsafe.Pointer(p1)) 
```

首先创建一个名为`value`的新`int64`变量。然后，创建一个指向它的指针命名为`p1`。接下来，创建另一个指针指向`p1`。然而，指向`p1`的`p2`指针是指向`int64`变量的指针，尽管`p1`指向`int64`变量。尽管这违反了 Go 的规则，但`unsafe.Pointer()`函数使这成为可能。

第二部分如下：

```go
   fmt.Println("*p1: ", *p1) 
   fmt.Println("*p2: ", *p2) 
   *p1 = 312121321321213212 
   fmt.Println(value) 
   fmt.Println("*p2: ", *p2) 
   *p1 = 31212132 
   fmt.Println(value) 
   fmt.Println("*p2: ", *p2) 
} 
```

执行`unsafe.go`将创建以下输出：

```go
$ go run unsafe.go
*p1:  5
*p2:  5
312121321321213212
*p2:  606940444
31212132
*p2:  31212132
```

输出显示了不安全指针有多危险。当`value`变量的值适合于`int32`内存空间（`5`和`31212132`）时，`p2`运行正常并显示正确的结果。然而，当`value`变量持有一个不适合`int32`内存空间的值（`312121321321213212`）时，`p2`显示了错误的结果（`606940444`），而没有提供警告或错误消息。

# 将 Go 与其他编程语言进行比较

Go 并不完美，但其他编程语言也不完美。本节将简要讨论其他编程语言，并将它们与 Go 进行比较，以便让您更好地了解您的选择。因此，可以与 Go 进行比较的编程语言列表包括：

+   **C**：C 是开发系统软件最流行的编程语言，因为每个 Unix 操作系统的可移植部分都是用 C 编写的。然而，它也有一些关键缺点，包括 C 指针，它们很棒也很快，但可能导致难以检测的错误和内存泄漏。此外，C 不提供垃圾回收；在 C 创建时，垃圾回收是一种可能会减慢计算机速度的奢侈品。然而，如今的计算机非常快，垃圾回收不再拖慢速度。此外，与其他系统编程语言相比，C 程序需要更多的代码来开发给定的任务。最后，C 是一种不支持现代编程范式的旧编程语言，比如面向对象和函数式编程。

+   **C++**：如前所述，我不再喜欢 C++。如果你认为应该使用 C++，那么你可能想考虑使用 C。然而，C++相对于 Go 的主要优势在于，如果需要，C++可以像 C 一样使用。然而，无论是 C 还是 C++都不支持并发编程。

+   **Rust**：Rust 是一种新的系统编程语言，试图避免由不安全代码引起的不愉快的错误。目前，Rust 的语法变化太快，但这将在不久的将来结束。如果出于某种原因你不喜欢 Go，你应该尝试 Rust。

+   **Swift**：在目前的状态下，Swift 更适合开发 macOS 系统的系统软件。然而，我相信在不久的将来，Swift 将在 Linux 机器上更受欢迎，所以你应该留意它。

+   **Python**：Python 是一种脚本语言，这是它的主要缺点。这是因为通常情况下，你不希望将系统软件的源代码公开给所有人。

+   **Perl**：关于 Python 所说的也适用于 Perl。然而，这两种编程语言都有大量的模块，可以让你的生活变得更轻松，你的代码变得更简洁。

如果你问我的意见，我认为 Go 是一种现代、可移植、成熟和安全的编程语言，用于编写系统软件。在寻找其他选择之前，你应该先尝试 Go。然而，如果你是一名 Go 程序员，想尝试其他东西，我建议你选择 Rust 或 Swift。然而，如果你需要编写可靠的并发程序，Go 应该是你的首选。

如果你无法在 Go 和 Rust 之间做出选择，那就试试 C。学习系统编程的基础知识比你选择的编程语言更重要。

尽管它们有缺点，但请记住，所有脚本编程语言都非常适合编写原型，并且它们的优势在于可以为软件创建图形界面。然而，使用脚本语言交付系统软件很少被接受，除非有一个真正的好理由这样做。

# 分析软件

有时程序因某种未知原因失败或性能不佳，你希望找出原因，而不必重写代码并添加大量的调试语句。因此，本节将讨论`strace(1)`和`dtrace(1)`，它们允许你在 Unix 机器上执行程序时看到幕后发生了什么。虽然这两个工具都可以与`go run`命令一起使用，但如果你首先使用`go build`创建可执行文件并使用该文件，你将获得更少的无关输出。这主要是因为`go run`在实际运行 Go 代码之前会生成临时文件，而你想调试的是实际程序，而不是用于构建程序的编译器。

请记住，尽管`dtrace(1)`比`strace(1)`更强大，并且有自己的编程语言，但`strace(1)`更适用于观察程序所做的系统调用。

# 使用 strace(1)命令行实用程序

`strace(1)`命令行实用程序允许您跟踪系统调用和信号。由于 Mac 机器上没有`strace(1)`，因此本节将使用 Linux 机器来展示`strace(1)`。但是，正如您将在稍后看到的那样，macOS 机器有`dtrace(1)`命令行实用程序，可以做更多的事情。

程序名称后面的数字指的是其页面所属的手册部分。尽管大多数名称只能找到一次，这意味着不必放置部分编号，但是有些名称可能位于多个部分，因为它们具有多重含义，例如`crontab(1)`和`crontab(5)`。因此，如果尝试检索此类页面而没有明确指定部分编号，将会得到手册中具有最小部分编号的条目。

要对`strace(1)`生成的输出有一个良好的感觉，请查看以下图，其中`strace(1)`用于检查`addCLAImproved.go`的可执行文件：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/go-sys-prog/img/6c0c5c81-3946-433a-bc90-4dafd085d3a0.png)

在 Linux 机器上使用 strace(1)命令

`strace(1)`输出的真正有趣的部分是以下行，这在前面的图中看不到：

```go
$ strace ./addCLAImproved 1 2 2>&1 | grep write
write(1, "Sum: 3\n", 7Sum: 3
```

我们使用`grep(1)`命令行实用程序提取包含我们感兴趣的 C 系统调用的行，这种情况下是`write(2)`。这是因为我们已经知道`write(2)`用于打印输出。因此，您了解到在这种情况下，单个`write(2)` C 系统调用用于在屏幕上打印所有输出；它的第一个参数是文件描述符，第二个参数是要打印的文本。

请注意，您可能希望使用`strace(1)`的`-f`选项，以便还跟踪在程序执行期间可能创建的任何子进程。

请记住，还存在`write(2)`的另外两个变体，名为`pwrite(2)`和`writev(2)`，它们提供与`write(2)`相同的核心功能，但方式略有不同。

前一个命令的以下变体需要更多对`write(2)`的调用，因为它生成更多的输出：

```go
$ strace ./addCLAImproved 1 a b 2>&1 | grep write
write(1, "Ignoring a\n", 11Ignoring a
write(1, "Ignoring b\n", 11Ignoring b
write(1, "Sum: 1\n", 7Sum: 1
```

Unix 使用文件描述符作为访问其所有文件的内部表示，这些文件描述符是正整数值。默认情况下，所有 Unix 系统都支持三个特殊和标准的文件名：`/dev/stdin`、`/dev/stdout`和`/dev/stderr`。它们也可以使用文件描述符 0、1 和 2 进行访问。这三个文件描述符也分别称为标准输入、标准输出和标准错误。此外，文件描述符 0 可以在 Mac 机器上作为`/dev/fd/0`进行访问，在 Debian Linux 机器上可以作为`/dev/pts/0`进行访问，因为 Unix 中的一切都是文件。

因此，需要在命令的末尾放置`2>&1`的原因是将所有输出，从标准错误（文件描述符 2）重定向到标准输出（文件描述符 1），以便能够使用`grep(1)`命令进行搜索，该命令仅搜索标准输出。请注意，存在许多`grep(1)`的变体，包括`zegrep(1)`、`fgrep(1)`和`fgrep(1)`，当它们需要处理大型或巨大的文本文件时，可能会更快地工作。

您在这里看到的是，即使您在 Go 中编写，生成的可执行文件也使用 C 系统调用和函数，因为除了使用机器语言外，C 是与 Unix 内核通信的唯一方式。

# DTrace 实用程序

尽管在 FreeBSD 上工作的调试实用程序，如`strace(1)`和`truss(1)`，可以跟踪进程产生的系统调用，但它们可能会很慢，因此不适合解决繁忙的 Unix 系统上的性能问题。另一个名为`dtrace(1)`的工具使用**DTrace**设施，允许您在系统范围内看到幕后发生的事情，而无需修改或重新编译任何内容。它还允许您在生产系统上工作，并动态地观察运行的程序或服务器进程，而不会引入大量开销。

本小节将使用`dtruss(1)`命令行实用程序，它只是一个`dtrace(1)`脚本，显示进程的系统调用。当在 macOS 机器上检查`addCLAImproved.go`可执行文件时，`dtruss(1)`生成的输出看起来与以下截图中看到的类似：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/go-sys-prog/img/f596ddbd-3b87-454d-8eda-478318fd1014.png)

在 macOS 机器上使用 dtruss(1)命令

再次，输出的以下部分验证了在 Unix 机器上，最终一切都被转换成 C 系统调用和函数，因为这是与 Unix 内核通信的唯一方式。您可以显示对`write(2)`系统调用的所有调用如下：

```go
$ sudo dtruss -c ./addCLAImproved 2000 2>&1 | grep write
```

然而，这一次你会得到大量的输出，因为 macOS 可执行文件多次使用`write(2)`而不是只使用一次来打印相同的输出。

开始意识到并非所有的 Unix 系统都以相同的方式工作，尽管它们有许多相似之处，这是很奇妙的。但这也意味着你不应该对 Unix 系统在幕后的工作方式做任何假设。

真正有趣的是以下命令的输出的最后部分：

```go
$ sudo dtruss -c ./addCLAImproved 2000
CALL                                        COUNT
__pthread_sigmask                               1
exit                                            1
getpid                                          1
ioctl                                           1
issetugid                                       1
read                                            1
thread_selfid                                   1
ulock_wake                                      1
bsdthread_register                              2
close                                           2
csops                                           2
open                                            2
select                                          2
sysctl                                          3
mmap                                            7
mprotect                                        8
stat64                                         41
write                                          83
```

你得到这个输出的原因是`-c`选项告诉`dtruss(1)`统计所有系统调用并打印它们的摘要，这种情况下显示`write(2)`被调用了 83 次，`stat64(2)`被调用了 41 次。

`dtrace(1)`实用程序比`strace(1)`更强大，并且有自己的编程语言，但学习起来更困难。此外，尽管有 Linux 版本的`dtrace(1)`，但在 Linux 系统上，`strace(1)`更加成熟，以更简单的方式跟踪系统调用。

您可以通过阅读 Brendan Gregg 和 Jim Mauro 的*DTrace: Dynamic Tracing in Oracle Solaris, Mac OS X, and FreeBSD*以及访问[`dtrace.org/`](http://dtrace.org/)了解更多关于`dtrace(1)`实用程序的信息。

# 在 macOS 上禁用系统完整性保护

第一次尝试在 Mac OS X 机器上运行`dtrace(1)`和`dtruss(1)`可能会遇到麻烦，并收到以下错误消息：

```go
$ sudo dtruss ./addCLAImproved 1 2 2>&1 | grep -i write
dtrace: error on enabled probe ID 2132 (ID 156: syscall::write:return): invalid kernel access in action #12 at DIF offset 92
```

在这种情况下，你可能需要禁用 DTrace 的限制，但仍然保持系统完整性保护对其他所有内容有效。您可以通过访问[`support.apple.com/en-us/HT204899`](https://support.apple.com/en-us/HT204899)了解更多关于系统完整性保护的信息。

# 无法到达的代码

无法到达的代码是永远不会被执行的代码，是一种逻辑错误。由于 Go 编译器本身无法捕捉这种逻辑错误，因此您需要使用`go tool vet`命令来帮助。

你不应该将无法到达的代码与从未被有意执行的代码混淆，比如不需要的函数的代码，因此在程序中从未被调用。

本节的示例代码保存为`cannotReach.go`，可以分为两部分。

第一部分包含以下 Go 代码：

```go
package main 

import ( 
   "fmt" 
) 

func x() int {

   return -1 
   fmt.Println("Exiting x()") 
   return -1 
} 

func y() int { 
   return -1 
   fmt.Println("Exiting y()") 
   return -1 
} 
```

第二部分如下：

```go
func main() { 
   fmt.Println(x()) 
   fmt.Println("Exiting program...") 
} 
```

正如你所看到的，无法到达的代码在第一部分。`x()`和`y()`函数都有无法到达的代码，因为它们的`return`语句放错了位置。然而，我们还没有完成，因为我们将让`go tool vet`工具发现无法到达的代码。这个过程很简单，包括执行以下命令：

```go
$ go tool vet cannotReach.go
cannotReach.go:9: unreachable code
cannotReach.go:14: unreachable code

```

此外，您可以看到`go tool vet`即使周围的函数根本不会被执行，也会检测到无法到达的代码，就像`y()`一样。

# 避免常见的 Go 错误

本节将简要讨论一些常见的 Go 错误，以便您在程序中避免它们：

+   如果在 Go 函数中出现错误，要么记录下来，要么返回错误；除非你有一个非常好的理由，否则不要两者都做。

+   Go 接口定义行为，而不是数据和数据结构。

+   使用`io.Reader`和`io.Writer`接口，因为它们使您的代码更具可扩展性。

+   确保只在需要时将变量的指针传递给函数。其余时间，只传递变量的值。

+   错误变量不是字符串；它们是`error`值。

+   如果你害怕犯错，你很可能最终什么有用的事情都不会做。所以尽量多实验。

以下是可以应用于每种编程语言的一般建议：

+   在小型和独立的 Go 程序中测试您的 Go 代码和函数，以确保它们表现出您认为应该有的行为方式。

+   如果你不太了解 Go 的某个特性，在第一次使用之前先进行测试，特别是如果你正在开发系统实用程序。

+   不要在生产机器上测试系统软件

+   在将系统软件部署到生产机器上时，要在生产机器不忙的时候进行，并确保您有备份计划

# 练习

1.  查找并访问`log`包的文档页面。

1.  使用`strace(1)`来检查上一章中的`hw.go`。

1.  如果您使用 Mac，尝试使用`dtruss(1)`检查`hw.go`可执行文件。

1.  编写一个从用户那里获取输入并使用`strace(1)`或`dtruss(1)`检查其可执行文件的程序。

1.  访问 Rust 的网站[`www.rust-lang.org/`](https://www.rust-lang.org/)。

1.  访问 Swift 的网站[`swift.org/`](https://swift.org/)。

1.  访问`io`包的文档页面[`golang.org/pkg/io/`](https://golang.org/pkg/io/)。

1.  自己使用`diff(1)`命令行实用程序，以便更好地学习如何解释其输出。

1.  访问并阅读`write(2)`的主页。

1.  访问`grep(1)`的主页。

1.  通过检查自己的结构来自己玩反射。

1.  编写一个改进版本的`occurrences.go`，它只会显示高于已知数值阈值的频率，该阈值将作为命令行参数给出。

# 总结

本章教会了您一些高级的 Go 特性，包括错误处理、模式匹配和正则表达式、反射和不安全的代码。还讨论了`strace(1)`和`dtrace(1)`工具。

下一章将涵盖许多有趣的内容，包括使用最新 Go 版本（1.8）中提供的新`sort.slice()` Go 函数，以及大 O 符号、排序算法、Go 包和垃圾回收。
