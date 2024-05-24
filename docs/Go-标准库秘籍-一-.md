# Go 标准库秘籍（一）

> 原文：[`zh.annas-archive.org/md5/F3FFC94069815F41B53B3D7D6E774406`](https://zh.annas-archive.org/md5/F3FFC94069815F41B53B3D7D6E774406)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 前言

感谢您给予本书机会！本书是一本指南，带您了解 Go 标准库的可能性，其中包含了许多开箱即用的功能和解决方案。请注意，本书涵盖的解决方案主要是对标准库实现的简单演示以及其使用方式的说明。这些示例旨在为您提供解决特定问题的起点，而不是完全解决问题。

# 本书适合对象

这本书适用于那些想要加强基础并揭示 Go 标准库隐藏部分的人。本书希望读者具有 Go 的基本知识。对于一些示例，了解 HTML、操作系统和网络将有所帮助。

# 本书内容

第一章，*与环境交互*，探讨了您的代码如何与操作系统环境交互。还涵盖了使用命令行标志和参数、消耗信号以及与子进程一起工作。

第二章，*字符串和其他内容*，介绍了对字符串的常见操作，从简单的子字符串搜索到文本格式化为制表符。

第三章，*处理数字*，介绍了基本转换和数字格式化选项。还涵盖了大数字的操作以及在输出消息中正确使用复数形式。

第四章，*从前从前*，对时间包进行了详细讨论，包括格式化、算术运算以及给定时间段内或延迟一定时间后的代码运行。

第五章，*输入和输出*，涵盖了利用标准 Go 接口进行的 I/O 操作。除了基本的 I/O 外，本章还涵盖了一些有用的序列化格式以及如何处理它们。

第六章，*发现文件系统*，讨论了与文件系统的工作，包括列出文件夹、读取和更改文件属性，以及对比文件。

第七章，*连接网络*，展示了连接 TCP 和 UDP 服务器的客户端实现，以及 SMTP、HTTP 和 JSON-RPC 的使用。

第八章，*与数据库工作*，专注于常见的数据库任务，如数据选择和提取、事务处理和执行，以及存储过程的缺点。

第九章，*来到服务器端*，从服务器的角度提供了对网络的视角。介绍了 TCP、UDP 和 HTTP 服务器的基础知识。

第十章，*并发乐趣*，涉及同步机制和对资源的并发访问。

第十一章，*技巧与窍门*，提供了有用的测试和改进 HTTP 服务器实现的技巧，并展示了 HTTP/2 推送的好处。

# 为了充分利用本书

尽管 Go 编程平台是跨平台的，但本书中的示例通常假定使用基于 Unix 的操作系统，或者至少可以执行一些常见的 Unix 实用程序。对于 Windows 用户，Cygwin 或 GitBash 实用程序可能会有所帮助。示例代码最适合这种设置：

+   基于 Unix 的环境

+   大于或等于 1.9.2 的 Go 版本

+   互联网连接

+   在将创建和执行示例代码的文件夹上具有读取、写入和执行权限

# 下载示例代码文件

您可以从[www.packtpub.com](http://www.packtpub.com)的帐户中下载本书的示例代码文件。如果您在其他地方购买了本书，您可以访问[www.packtpub.com/support](http://www.packtpub.com/support)并注册，以便直接将文件发送到您的邮箱。

您可以按照以下步骤下载代码文件：

1.  登录或注册[www.packtpub.com](http://www.packtpub.com/support)。

1.  选择“支持”选项卡。

1.  单击“代码下载和勘误”。

1.  在搜索框中输入书名，然后按照屏幕上的说明操作。

文件下载完成后，请确保您使用最新版本的解压缩软件解压或提取文件夹：

+   Windows 的 WinRAR/7-Zip

+   Mac 的 Zipeg/iZip/UnRarX

+   Linux 的 7-Zip/PeaZip

本书的代码包也托管在 GitHub 上，网址为[`github.com/PacktPublishing/Go-Standard-Library-Cookbook`](https://github.com/PacktPublishing/Go-Standard-Library-Cookbook)。如果代码有更新，将在现有的 GitHub 存储库上进行更新。

我们还有来自我们丰富书籍和视频目录的其他代码包，可在[`github.com/PacktPublishing/`](https://github.com/PacktPublishing/)上找到！快去看看吧！

# 使用的约定

本书中使用了许多文本约定。

`CodeInText`：指示文本中的代码词、数据库表名、文件夹名、文件名、文件扩展名、路径名、虚拟 URL、用户输入和 Twitter 句柄。这是一个例子：“验证您的`GOPATH`和`GOROOT`环境变量是否设置正确。”

代码块设置如下：

```go
package main
import (
  "log"
  "runtime"
)
```

当我们希望引起您对代码块的特定部分的注意时，相关的行或项目会以粗体显示：

```go
package main
import (
  "log"
  "runtime"
)
```

**粗体**：表示一个新术语、一个重要单词或您在屏幕上看到的单词。例如，菜单或对话框中的单词会以这种方式出现在文本中。

警告或重要说明看起来像这样。

提示和技巧看起来像这样。

# 章节

在本书中，您会经常看到几个标题（*准备工作*、*如何做*、*它是如何工作的*、*还有更多*和*另请参阅*）。

为了清晰地说明如何完成一个食谱，使用以下各节：

# 准备工作

本节告诉您食谱中会有什么，并描述如何设置食谱所需的任何软件或任何初步设置。

# 如何做…

本节包含了遵循食谱所需的步骤。

# 它是如何工作的…

本节通常包括对前一节发生的事情的详细解释。

# 还有更多…

本节包括有关食谱的其他信息，以使您对食谱更加了解。

# 另请参阅

本节为食谱提供了其他有用信息的链接。


# 第一章：与环境交互

在本章中，将涵盖以下配方：

+   检索 Golang 版本

+   访问程序参数

+   使用 flag 包创建程序接口

+   获取并设置带有默认值的环境变量

+   检索当前工作目录

+   获取当前进程 PID

+   处理操作系统信号

+   调用外部进程

+   检索子进程信息

+   从子进程读取/写入

+   优雅地关闭应用程序

+   使用功能选项进行文件配置

# 介绍

每个程序一旦被执行，就存在于操作系统的环境中。程序接收输入并向该环境提供输出。操作系统还需要与程序通信，让程序知道外部发生了什么。最后，程序需要做出适当的响应。

本章将带您了解系统环境的发现基础知识，通过程序参数对程序进行参数化，以及操作系统信号的概念。您还将学习如何执行和与子进程通信。

# 检索 Golang 版本

在构建程序时，最好记录环境设置、构建版本和运行时版本，特别是如果您的应用程序更复杂。这有助于您分析问题，以防出现故障。

除了构建版本和例如环境变量之外，编译二进制文件的 Go 版本可以包含在日志中。以下的步骤将向您展示如何将 Go 运行时版本包含在程序信息中。

# 准备就绪

安装并验证 Go 安装。以下步骤可能有所帮助：

1.  在您的计算机上下载并安装 Go。

1.  验证您的 `GOPATH` 和 `GOROOT` 环境变量是否正确设置。

1.  打开终端并执行 `go version`。如果得到带有版本名称的输出，则 Go 已正确安装。

1.  在 `GOPATH/src` 文件夹中创建存储库。

# 如何做...

以下步骤涵盖了解决方案：

1.  打开控制台并创建文件夹 `chapter01/recipe01`。

1.  导航到目录。

1.  创建 `main.go` 文件，内容如下：

```go
        package main
        import (
          "log"
          "runtime"
        )
        const info = `
          Application %s starting.
          The binary was build by GO: %s`

        func main() {
          log.Printf(info, "Example", runtime.Version())
        }

```

1.  通过执行 `go run main.go` 运行代码。

1.  在终端中查看输出：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/go-stdlib-cb/img/da28c809-195a-49c5-83ad-1c4ef2b86da1.png)

# 它是如何工作的...

`runtime` 包包含许多有用的函数。要找出 Go 运行时版本，可以使用 `Version` 函数。文档说明该函数返回提交的哈希值，以及二进制构建时的日期或标签。

实际上，`Version` 函数返回 `runtime/internal/sys` 的 `Version` 常量。常量本身位于 `$GOROOT/src/runtime/internal/sys/zversion.go` 文件中。

这个 `.go` 文件是由 `go dist` 工具生成的，版本是通过 `go/src/cmd/dist/build.go` 文件中的 `findgoversion` 函数解析的，如下所述。

`$GOROOT/VERSION` 优先级最高。如果文件为空或不存在，则使用 `$GOROOT/VERSION.cache` 文件。如果也找不到 `$GOROOT/VERSION.cache`，则工具会尝试使用 Git 信息来解析版本，但在这种情况下，您需要为 Go 源代码初始化 Git 存储库。

# 访问程序参数

参数化程序运行的最简单方法是使用命令行参数作为程序参数。

简单地说，参数化的程序调用可能如下所示：`./parsecsv user.csv role.csv`。在这种情况下，`parsecsv`是执行二进制文件的名称，`user.csv`和`role.csv`是修改程序调用的参数（在这种情况下是要解析的文件）。

# 如何做...

1.  打开控制台并创建文件夹 `chapter01/recipe02`。

1.  导航到目录。

1.  创建 `main.go` 文件，内容如下：

```go
        package main
        import (
          "fmt"
          "os"
        )

        func main() {

          args := os.Args

          // This call will print
          // all command line arguments.
          fmt.Println(args)

          // The first argument, zero item from slice,
          // is the name of the called binary.
          programName := args[0]
          fmt.Printf("The binary name is: %s \n", programName)

          // The rest of the arguments could be obtained
          // by omitting the first argument.
          otherArgs := args[1:]
          fmt.Println(otherArgs)

          for idx, arg := range otherArgs {
            fmt.Printf("Arg %d = %s \n", idx, arg)
          }
        }
```

1.  通过执行 `go build -o test` 构建二进制文件。

1.  执行命令`./test arg1 arg2`。（Windows 用户可以运行`test.exe arg1 arg2`）。

1.  在终端中查看输出：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/go-stdlib-cb/img/2de10160-aead-4a1d-8f57-1d550b70c651.png)

# 它是如何工作的...

Go 标准库提供了几种访问程序调用参数的方法。最通用的方法是通过 OS 包中的`Args`变量访问参数。

通过这种方式，您可以在字符串切片中获取命令行中的所有参数。这种方法的优点是参数的数量是动态的，这样您可以，例如，将要由程序处理的文件的名称传递给程序。

上面的示例只是回显传递给程序的所有参数。最后，假设二进制文件名为`test`，程序运行由终端命令`./test arg1 arg2`执行。

具体来说，`os.Args[0]`将返回`./test`。`os.Args[1:]`返回不带二进制名称的其余参数。在现实世界中，最好不要依赖于传递给程序的参数数量，而是始终检查参数数组的长度。否则，如果给定索引上的参数不在范围内，程序将自然地发生恐慌。

# 还有更多...

如果参数被定义为标志，`-flag value`，则需要额外的逻辑来将值分配给标志。在这种情况下，使用`flag`包有更好的方法来解析这些标志。这种方法是下一个配方的一部分。

# 使用 flag 包创建程序接口

前面的配方描述了如何通过非常通用的方法访问程序参数。

这个配方将提供一种通过程序标志定义接口的方法。这种方法主导了基于 GNU/Linux、BSD 和 macOS 的系统。程序调用的示例可以是`ls -l`，在*NIX 系统上，它将列出当前目录中的文件。

Go 标志处理包不支持像`ls -ll`这样的标志组合，其中在单个破折号后有多个标志。每个标志必须是单独的。Go 标志包也不区分长选项和短选项。最后，`-flag`和`--flag`是等效的。

# 如何做到...

1.  打开控制台并创建文件夹`chapter01/recipe03`。

1.  导航到目录。

1.  创建带有以下内容的`main.go`文件：

```go
        package main
        import (
          "flag"
          "fmt"
          "log"
          "os"
          "strings"
        )

        // Custom type need to implement
        // flag.Value interface to be able to
        // use it in flag.Var function.
        type ArrayValue []string

        func (s *ArrayValue) String() string {
          return fmt.Sprintf("%v", *s)
        }

        func (a *ArrayValue) Set(s string) error {
          *a = strings.Split(s, ",")
          return nil
        }

        func main() {

          // Extracting flag values with methods returning pointers
          retry := flag.Int("retry", -1, "Defines max retry count")

          // Read the flag using the XXXVar function.
          // In this case the variable must be defined
          // prior to the flag.
          var logPrefix string
          flag.StringVar(&logPrefix, "prefix", "", "Logger prefix")

          var arr ArrayValue
          flag.Var(&arr, "array", "Input array to iterate through.")

          // Execute the flag.Parse function, to
          // read the flags to defined variables.
          // Without this call the flag
          // variables remain empty.
          flag.Parse()

          // Sample logic not related to flags
          logger := log.New(os.Stdout, logPrefix, log.Ldate)

          retryCount := 0
          for retryCount < *retry {
            logger.Println("Retrying connection")
            logger.Printf("Sending array %v\n", arr)
            retryCount++
          }
        }
```

1.  通过执行`go build -o util`来构建二进制文件。

1.  从控制台执行`./util -retry 2 -prefix=example -array=1,2`。

1.  在终端中查看输出：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/go-stdlib-cb/img/24b5846a-4453-4fbc-9301-aa81704939ee.png)

# 它是如何工作的...

对于代码中的标志定义，`flag`包定义了两种类型的函数。

第一种类型是标志类型的简单名称，例如`Int`。这个函数将返回整数变量的指针，解析标志的值将存储在其中。

`XXXVar`函数是第二种类型。它们提供相同的功能，但需要提供变量的指针。解析的标志值将存储在给定的变量中。

Go 库还支持自定义标志类型。自定义类型必须实现`flag`包中的`Value`接口。

例如，假设标志`retry`定义了重新连接到端点的重试限制，标志`prefix`定义了日志中每行的前缀，而`array`是作为有效负载发送到服务器的数组标志。终端中的程序调用将如`./util -retry 2 -prefix=example array=1,2`。

上述代码的重要部分是`Parse()`函数，它从`Args[1:]`中解析定义的标志。在定义所有标志并在访问值之前必须调用该函数。

上面的代码显示了如何从命令行标志中解析一些数据类型。类似地，其他内置类型也可以解析。

最后一个标志`array`演示了自定义类型标志的定义。请注意，`ArrayType`实现了`flag`包中的`Value`接口。

# 还有更多...

`flag`包包含更多函数来设计带有标志的接口。值得阅读`FlagSet`的文档。

通过定义新的`FlagSet`，可以通过调用`myFlagset.Parse(os.Args[2:])`来解析参数。这样你就可以基于第一个标志拥有标志子集。

# 使用默认值获取和设置环境变量

前一个教程，*使用 flag 包创建程序接口*，描述了如何将标志用作程序参数。

特别是对于较大的应用程序，另一种典型的参数化方式是使用环境变量进行配置。环境变量作为配置选项显著简化了应用程序的部署。这在云基础设施中也非常常见。

通常，本地数据库连接和自动构建环境的配置是不同的。

如果配置由环境变量定义，就不需要更改应用程序配置文件甚至应用程序代码。导出的环境变量（例如`DBSTRING`）就是我们所需要的。如果环境变量不存在，将配置默认值也非常实用。这样，应用程序开发人员的生活就轻松多了。

本教程将演示如何读取、设置和取消设置环境变量。它还将向您展示如何在变量未设置时实现默认选项。

# 如何做…

1.  打开控制台并创建文件夹`chapter01/recipe04`。

1.  导航到目录。

1.  创建`get.go`文件，内容如下：

```go
        package main

        import (
          "log"
          "os"
        )

        func main() {
          connStr := os.Getenv("DB_CONN")
          log.Printf("Connection string: %s\n", connStr)
        }
```

1.  通过在终端中调用`DB_CONN=db:/user@example && go run get.go`来执行代码。

1.  在终端中查看输出：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/go-stdlib-cb/img/10deaa7c-c4af-4ceb-b13c-4d3fda3c7bb5.png)

1.  创建`lookup.go`文件，内容如下：

```go
        package main

        import (
          "log"
          "os"
        )

        func main() {

          key := "DB_CONN"

          connStr, ex := os.LookupEnv(key)
          if !ex {
            log.Printf("The env variable %s is not set.\n", key)
          }
          fmt.Println(connStr)
        }
```

1.  在终端中调用`unset DB_CONN && go run lookup.go`来执行代码。

1.  在终端中查看输出：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/go-stdlib-cb/img/aa749e9a-6241-4830-b558-2ff06a7506d5.png)

1.  创建`main.go`文件，内容如下：

```go
        package main
        import (
          "log"
          "os"
        )

        func main() {

          key := "DB_CONN"
          // Set the environmental variable.
          os.Setenv(key, "postgres://as:as@example.com/pg?
                          sslmode=verify-full")
          val := GetEnvDefault(key, "postgres://as:as@localhost/pg?
                                     sslmode=verify-full")
          log.Println("The value is :" + val)

          os.Unsetenv(key)
          val = GetEnvDefault(key, "postgres://as:as@127.0.0.1/pg?
                                    sslmode=verify-full")
          log.Println("The default value is :" + val)

        }

        func GetEnvDefault(key, defVal string) string {
          val, ex := os.LookupEnv(key)
          if !ex {
            return defVal
          }
          return val
        }
```

1.  在终端中执行`go run main.go`来运行代码。

1.  在终端中查看输出：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/go-stdlib-cb/img/20b7ef63-0921-49c4-94f4-3c6f1498de02.png)

# 它是如何工作的…

环境变量可以通过`os`包中的`Getenv`和`Setenv`函数来访问。这些函数的名称不言自明，不需要进一步的描述。

`os`包中还有一个有用的函数。`LookupEnv`函数提供两个值作为结果；变量的值，以及布尔值，定义变量在环境中是否设置。

`os.Getenv`函数的缺点是，即使在环境变量未设置的情况下，它也会返回空字符串。

这个缺点可以通过`os.LookupEnv`函数来克服，该函数返回环境变量的字符串值和一个布尔值，指示变量是否设置。

要实现检索环境变量或默认值，使用`os.LookupEnv`函数。简单地说，如果变量未设置，也就是第二个返回值是`false`，那么就返回默认值。该函数的使用是第 9 步的一部分。

# 检索当前工作目录

应用程序的另一个有用信息来源是目录，程序二进制文件所在的位置。有了这些信息，程序就可以访问与二进制文件一起放置的资源和文件。

自 Go 1.8 版本以来，本教程使用了 Go 的解决方案。这是首选方案。

# 如何做…

1.  打开控制台并创建文件夹`chapter01/recipe05`。

1.  导航到目录。

1.  创建`main.go`文件，内容如下：

```go
        package main

        import (
          "fmt"
          "os"
          "path/filepath"
        )

        func main() {
          ex, err := os.Executable()
          if err != nil {
            panic(err)
          }

          // Path to executable file
          fmt.Println(ex)

          // Resolve the direcotry
          // of the executable
          exPath := filepath.Dir(ex)
          fmt.Println("Executable path :" + exPath)

          // Use EvalSymlinks to get
          // the real path.
          realPath, err := filepath.EvalSymlinks(exPath)
          if err != nil {
            panic(err)
          }
          fmt.Println("Symlink evaluated:" + realPath)
        }
```

1.  通过命令`go build -o binary`构建二进制文件。

1.  通过终端调用`./binary`来执行二进制文件。

1.  查看输出。它应该显示在您的机器上的绝对路径：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/go-stdlib-cb/img/a30ae134-4226-4698-8b10-4b85c626c9a3.png)

# 它是如何工作的…

自 Go 1.8 以来，`os`包中的`Executable`函数是解析可执行文件路径的首选方法。`Executable`函数返回执行的二进制文件的绝对路径（除非返回错误）。

为了解析二进制路径的目录，应用了`filepath`包中的`Dir`。唯一的问题是结果可能是`symlink`或它指向的路径。

为了克服这种不稳定的行为，可以使用`filepath`包中的`EvalSymlinks`来应用到结果路径上。通过这种方法，返回的值将是二进制文件的真实路径。

可以使用`os`库中的`Executable`函数获取二进制文件所在目录的信息。

请注意，如果代码是通过`go run`命令运行的，实际的可执行文件位于临时目录中。

# 获取当前进程 PID

了解正在运行的进程的 PID 是有用的。PID 可以被操作系统实用程序用来查找有关进程本身的信息。在进程失败的情况下，了解 PID 也很有价值，这样您可以在系统日志中跟踪进程行为，例如`/var/log/messages`，`/var/log/syslog`。

本示例向您展示了如何使用`os`包获取执行程序的 PID，并将其与操作系统实用程序一起使用以获取更多信息。

# 如何做…

1.  打开控制台并创建文件夹`chapter01/recipe06`。

1.  导航到目录。

1.  使用以下内容创建`main.go`文件：

```go
        package main

        import (
          "fmt"
          "os"
          "os/exec"
          "strconv"
        )

        func main() {

          pid := os.Getpid()
          fmt.Printf("Process PID: %d \n", pid)

          prc := exec.Command("ps", "-p", strconv.Itoa(pid), "-v")
          out, err := prc.Output()
          if err != nil {
            panic(err)
          }

          fmt.Println(string(out))
        }
```

1.  通过执行`go run main.go`来运行代码。

1.  在终端中查看输出：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/go-stdlib-cb/img/82b6a9e7-9050-4819-b33f-8b74fee5d4fb.png)

# 工作原理…

`os`包中的`Getpid`函数返回进程的 PID。示例代码展示了如何从操作系统实用程序`ps`获取有关进程的更多信息。

在应用程序启动时打印 PID 可能很有用，这样在崩溃时也可以通过检索到的 PID 来调查原因。

# 处理操作系统信号

信号是操作系统与正在运行的进程通信的基本方式。最常见的两个信号是`SIGINT`和`SIGTERM`。这些信号会导致程序终止。

还有一些信号，比如`SIGHUP`。`SIGHUP`表示调用进程的终端已关闭，例如，程序可以决定转移到后台。

Go 提供了一种处理应用程序接收到信号时的行为的方法。本示例将提供一个实现处理的示例。

# 如何做…

1.  打开控制台并创建文件夹`chapter01/recipe07`。

1.  导航到目录。

1.  使用以下内容创建`main.go`文件：

```go
        package main

        import (
          "fmt"
          "os"
          "os/signal"
          "syscall"
        )

        func main() {

          // Create the channel where the received
          // signal would be sent. The Notify
          // will not block when the signal
          // is sent and the channel is not ready.
          // So it is better to
          // create buffered channel.
          sChan := make(chan os.Signal, 1)

          // Notify will catch the
          // given signals and send
          // the os.Signal value
          // through the sChan.
          // If no signal specified in 
          // argument, all signals are matched.
          signal.Notify(sChan,
            syscall.SIGHUP,
            syscall.SIGINT,
            syscall.SIGTERM,
            syscall.SIGQUIT)

          // Create channel to wait till the
          // signal is handled.
          exitChan := make(chan int)
          go func() {
            signal := <-sChan
            switch signal {
              case syscall.SIGHUP:
                fmt.Println("The calling terminal has been closed")
                exitChan <- 0

              case syscall.SIGINT:
                fmt.Println("The process has been interrupted by CTRL+C")
                exitChan <- 1

              case syscall.SIGTERM:
                fmt.Println("kill SIGTERM was executed for process")
                exitChan <- 1

              case syscall.SIGQUIT:
                fmt.Println("kill SIGQUIT was executed for process")
                exitChan <- 1
            }
          }()

          code := <-exitChan
          os.Exit(code)
        }
```

1.  通过执行`go run main.go`来运行代码。

1.  通过按下*CTRL* + *C*发送`SIGINT`信号给应用程序。

1.  查看输出：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/go-stdlib-cb/img/5f5a3b24-e84e-43fc-bc62-33181082f424.png)

# 工作原理…

在资源被获取的应用程序中，如果立即终止可能会发生资源泄漏。最好处理信号并采取一些必要的步骤来释放资源。上述代码展示了如何做到这一点的概念。

`signal`包中的`Notify`函数将帮助我们处理接收到的信号。

如果在`Notify`函数中未指定信号作为参数，函数将捕获所有可能的信号。

请注意，`signal`包的`Notify`函数通过`sChan`通道与`goroutine`通信。`Notify`然后捕获定义的信号并将其发送到`goroutine`进行处理。最后，`exitChan`用于解析进程的退出代码。

重要的信息是，如果分配的通道未准备好，`Notify`函数将不会阻止信号。这样信号可能会被错过。为了避免错过信号，最好创建缓冲通道。

请注意，`SIGKILL`和`SIGSTOP`信号可能无法被`Notify`函数捕获，因此无法处理这些信号。

# 调用外部进程

Go 二进制文件也可以用作各种实用程序的工具，并且可以使用`go run`来替代 bash 脚本。出于这些目的，通常会调用命令行实用程序。

在这个示例中，将提供如何执行和处理子进程的基础知识。

# 准备工作

测试以下命令是否在你的终端中工作：

1.  测试`ls`（Windows 中为`dir`）命令是否存在于你的`$PATH`中。

1.  你应该能够在终端中执行`ls`（Windows 中为`dir`）命令。

# 如何做…

以下步骤涵盖了解决方案：

1.  打开控制台并创建文件夹`chapter01/recipe08`。

1.  导航到目录。

1.  创建`run.go`文件，内容如下：

```go
        package main

        import (
          "bytes"
          "fmt"
          "os/exec"
        )

        func main() {

          prc := exec.Command("ls", "-a")
          out := bytes.NewBuffer([]byte{})
          prc.Stdout = out
          err := prc.Run()
          if err != nil {
            fmt.Println(err)
          }

          if prc.ProcessState.Success() {
            fmt.Println("Process run successfully with output:\n")
            fmt.Println(out.String())
          }
        }
```

1.  通过执行`go run run.go`来运行代码。

1.  在终端中查看输出：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/go-stdlib-cb/img/61af16dc-759a-4ebb-8383-bb6ce2456cc4.png)

1.  创建`start.go`文件，内容如下：

```go
        package main

        import (
          "fmt"
          "os/exec"
        )

        func main() {

          prc := exec.Command("ls", "-a")
          err := prc.Start()
          if err != nil {
            fmt.Println(err)
          }

          prc.Wait()

          if prc.ProcessState.Success() {
            fmt.Println("Process run successfully with output:\n")
            fmt.Println(out.String())
          }
        }
```

1.  通过执行`go run start.go`来运行代码。

1.  在终端中查看输出：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/go-stdlib-cb/img/4d9b6e4d-a10b-477b-9087-74a829c2257c.png)

# 工作原理…

Go 标准库提供了一种简单的调用外部进程的方法。这可以通过`os/exec`包的`Command`函数来实现。

最简单的方法是创建`Cmd`结构并调用`Run`函数。`Run`函数执行进程并等待其完成。如果命令退出时出现错误，`err`值将不为空。

这更适合调用操作系统的实用程序和工具，这样程序不会挂起太久。

进程也可以异步执行。这可以通过调用`Cmd`结构的`Start`方法来实现。在这种情况下，进程被执行，但是主`goroutine`不会等待它结束。`Wait`方法可以用来等待进程结束。`Wait`方法完成后，进程的资源将被释放。

这种方法更适合执行长时间运行的进程和程序依赖的服务。

# 另请参阅

这个示例描述了如何简单地执行子进程。本章还提供了*检索子进程信息*和*从子进程读取/写入*的示例，介绍了如何从子进程读取和写入，并获取有用的进程信息的步骤。

# 检索子进程信息

*调用外部进程*示例描述了如何同步和异步调用子进程。自然地，要处理进程行为，你需要更多地了解进程。这个示例展示了如何在子进程终止后获取 PID 和基本信息。

关于运行进程的信息只能通过`syscall`包获得，而且高度依赖于平台。

# 准备工作

测试`sleep`（Windows 中为`timeout`）命令是否存在于终端中。

# 如何做…

1.  打开控制台并创建文件夹`chapter01/recipe09`。

1.  导航到目录。

1.  创建`main_running.go`文件，内容如下：

```go
        package main

        import (
          "fmt"
          "os/exec"
          "runtime"
        )

        func main() {

          var cmd string
          if runtime.GOOS == "windows" {
            cmd = "timeout"
          } else {
            cmd = "sleep"
          }
          proc := exec.Command(cmd, "1")
          proc.Start()

          // No process state is returned
          // till the process finish.
          fmt.Printf("Process state for running process: %v\n",
                     proc.ProcessState)

          // The PID could be obtain
          // event for the running process
          fmt.Printf("PID of running process: %d\n\n", 
                     proc.Process.Pid)
        }
```

1.  通过执行`go run main_running.go`来运行代码。

1.  在终端中查看输出：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/go-stdlib-cb/img/359c90e1-e52d-49fa-83ca-ace5d98533b1.png)

1.  创建`main.go`文件，内容如下：

```go
        func main() {

          var cmd string
          if runtime.GOOS == "windows" {
            cmd = "timeout"
          } else {
            cmd = "sleep"
          }

          proc := exec.Command(cmd, "1")
          proc.Start()

          // Wait function will
          // wait till the process ends.
          proc.Wait()

          // After the process terminates
          // the *os.ProcessState contains
          // simple information
          // about the process run
          fmt.Printf("PID: %d\n", proc.ProcessState.Pid())
          fmt.Printf("Process took: %dms\n", 
                     proc.ProcessState.SystemTime()/time.Microsecond)
          fmt.Printf("Exited sucessfuly : %t\n",
                     proc.ProcessState.Success())
        }
```

1.  通过执行`go run main.go`来运行代码。

1.  在终端中查看输出：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/go-stdlib-cb/img/2902d443-a9b7-4b4c-89aa-f127f2ea2095.png)

# 工作原理…

`os/exec`标准库提供了执行进程的方法。使用`Command`，将返回`Cmd`结构。`Cmd`提供了对进程表示的访问。当进程正在运行时，你只能找到 PID。

你只能获取有关进程的少量信息。但是通过检索进程的 PID，你可以调用操作系统的实用程序来获取更多信息。

请记住，即使子进程正在运行，也可以获取其 PID。另一方面，只有在进程终止后，`os`包的`ProcessState`结构才可用。

# 另请参阅

本章中有与进程处理相关的*从子进程中读取/写入*和*调用外部进程*的配方。

# 从子进程中读取/写入

每个执行的进程都有标准输出、输入和错误输出。Go 标准库提供了读取和写入这些内容的方法。

本配方将介绍如何读取进程的输出并写入子进程的输入的方法。

# 准备就绪

验证以下命令是否在终端中工作：

1.  测试终端中是否存在`ls`（Windows 中的`dir`）命令。

1.  您应该能够在终端中执行`ls`（Windows 中的`dir`）命令。

# 如何做…

1.  打开控制台并创建文件夹`chapter01/recipe10`。

1.  导航到目录。

1.  创建`main_read_output.go`文件，内容如下：

```go
       package main

       import (
         "fmt"
         "os/exec"
         "runtime"
       )

       func main() {

         var cmd string

         if runtime.GOOS == "windows" {
           cmd = "dir"
         } else {
           cmd = "ls"
         }

         proc := exec.Command(cmd)

         // Output will run the process
         // terminates and returns the standard
         // output in a byte slice.
         buff, err := proc.Output()

         if err != nil {
           panic(err)
         }

         // The output of child
         // process in form
         // of byte slice
         // printed as string
         fmt.Println(string(buff))

       }
```

1.  通过执行`go run main_read_output.go`来运行代码。

1.  在终端中查看输出：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/go-stdlib-cb/img/e44bc828-1856-44f6-9573-0c962c6bf1c7.png)

1.  创建`main_read_stdout.go`文件，内容如下：

```go
        package main

        import (
          "bytes"
          "fmt"
          "os/exec"
          "runtime"
        )

        func main() {

          var cmd string

          if runtime.GOOS == "windows" {
            cmd = "dir"
          } else {
            cmd = "ls"
          }

          proc := exec.Command(cmd)

          buf := bytes.NewBuffer([]byte{})

          // The buffer which implements
          // io.Writer interface is assigned to
          // Stdout of the process
          proc.Stdout = buf

          // To avoid race conditions
          // in this example. We wait till
          // the process exit.
          proc.Run()

          // The process writes the output to
          // to buffer and we use the bytes
          // to print the output.
          fmt.Println(string(buf.Bytes()))

        }
```

1.  通过执行`go run main_read_stdout.go`来运行代码。

1.  在终端中查看输出：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/go-stdlib-cb/img/8ac6c977-1a10-4af7-a567-b2789426c601.png)

1.  创建`main_read_read.go`文件，内容如下：

```go
        package main

        import (
          "bufio"
          "context"
          "fmt"
          "os/exec"
          "time"
        )

        func main() {
          cmd := "ping"
          timeout := 2 * time.Second

          // The command line tool
          // "ping" is executed for
          // 2 seconds
          ctx, _ := context.WithTimeout(context.TODO(), timeout)
          proc := exec.CommandContext(ctx, cmd, "example.com")

          // The process output is obtained
          // in form of io.ReadCloser. The underlying
          // implementation use the os.Pipe
          stdout, _ := proc.StdoutPipe()
          defer stdout.Close()

          // Start the process
          proc.Start()

          // For more comfortable reading the
          // bufio.Scanner is used.
          // The read call is blocking.
          s := bufio.NewScanner(stdout)
          for s.Scan() {
            fmt.Println(s.Text())
          }
        }
```

1.  通过执行`go run main_read.go`来运行代码。

1.  在终端中查看输出：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/go-stdlib-cb/img/ab239155-9b87-489a-a215-258b1dc5f984.png)

1.  创建`sample.go`文件，内容如下：

```go
        package main

        import (
          "bufio"
          "fmt"
          "os"
        )

        func main() {
          sc := bufio.NewScanner(os.Stdin)

          for sc.Scan() {
            fmt.Println(sc.Text())
          }
        }
```

1.  创建`main.go`文件，内容如下：

```go
        package main

        import (
          "bufio"
          "fmt"
          "io"
          "os/exec"
          "time"
        )

        func main() {
          cmd := []string{"go", "run", "sample.go"}

          // The command line tool
          // "ping" is executed for
          // 2 seconds
          proc := exec.Command(cmd[0], cmd[1], cmd[2])

          // The process input is obtained
          // in form of io.WriteCloser. The underlying
          // implementation use the os.Pipe
          stdin, _ := proc.StdinPipe()
          defer stdin.Close()

          // For debugging purposes we watch the
          // output of the executed process
          stdout, _ := proc.StdoutPipe()
          defer stdout.Close()

          go func() {
            s := bufio.NewScanner(stdout)
            for s.Scan() {
              fmt.Println("Program says:" + s.Text())
            }
          }()

          // Start the process
          proc.Start()

          // Now the following lines
          // are written to child
          // process standard input
          fmt.Println("Writing input")
          io.WriteString(stdin, "Hello\n")
          io.WriteString(stdin, "Golang\n")
          io.WriteString(stdin, "is awesome\n")

          time.Sleep(time.Second * 2)

          proc.Process.Kill()

        }
```

1.  通过执行`go run main.go`来运行代码。

1.  在终端中查看输出：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/go-stdlib-cb/img/03b5fa95-0181-4d5e-b404-9f782fbdf5ad.png)

# 工作原理…

`os/exec`包的`Cmd`结构提供了访问进程输出/输入的函数。有几种方法可以读取进程的输出。

读取进程输出的最简单方法之一是使用`Cmd`结构的`Output`或`CombinedOutput`方法（获取`Stderr`和`Stdout`）。在调用此函数时，程序会同步等待子进程终止，然后将输出返回到字节缓冲区。

除了`Output`和`OutputCombined`方法外，`Cmd`结构提供了`Stdout`属性，可以将`io.Writer`分配给它。分配的写入器然后作为进程输出的目的地。它可以是文件、字节缓冲区或任何实现`io.Writer`接口的类型。

读取进程输出的最后一种方法是通过调用`Cmd`结构的`StdoutPipe`方法获取`io.Reader`。`StdoutPipe`方法在`Stdout`之间创建管道，进程在其中写入输出，并提供`Reader`，它作为程序读取进程输出的接口。这样，进程的输出被传送到检索到的`io.Reader`。

向进程的`stdin`写入的方式相同。在所有选项中，将演示使用`io.Writer`的方式。

可以看到，有几种方法可以从子进程中读取和写入。使用`stderr`和`stdin`的方式几乎与步骤 6-7 中描述的方式相同。最后，访问输入/输出的方法可以这样分为：

+   同步（等待进程结束并获取字节）：使用`Cmd`的`Output`和`CombinedOutput`方法。

+   IO：输出或输入以`io.Writer/Reader`的形式提供。`XXXPipe`和`StdXXX`属性是这种方法的正确选择。

IO 类型更加灵活，也可以异步使用。

# 优雅地关闭应用程序

服务器和守护程序是长时间运行的程序（通常是几天甚至几周）。这些长时间运行的程序通常在开始时分配资源（数据库连接，网络套接字），并在资源存在的时间内保持这些资源。如果这样的进程被终止并且关闭未得到适当处理，可能会发生资源泄漏。为了避免这种行为，应该实现所谓的优雅关闭。

在这种情况下，优雅意味着应用程序捕获终止信号（如果可能的话），并在终止之前尝试清理和释放分配的资源。这个食谱将向您展示如何实现优雅关闭。

食谱*处理操作系统信号*描述了捕获操作系统信号。相同的方法将用于实现优雅关闭。在程序终止之前，它将清理并执行一些其他活动。

# 如何做...

1.  打开控制台并创建文件夹`chapter01/recipe11`。

1.  导航到目录。

1.  创建`main.go`文件，内容如下：

```go
        package main

        import (
          "fmt"
          "io"
          "log"
          "os"
          "os/signal"
          "syscall"
          "time"
        )

        var writer *os.File

        func main() {

          // The file is opened as
          // a log file to write into.
          // This way we represent the resources
          // allocation.
          var err error
          writer, err = os.OpenFile(fmt.Sprintf("test_%d.log",
                time.Now().Unix()), os.O_RDWR|os.O_CREATE, os.ModePerm)
          if err != nil {
            panic(err)
          }

          // The code is running in a goroutine
          // independently. So in case the program is
          // terminated from outside, we need to
          // let the goroutine know via the closeChan
          closeChan := make(chan bool)
          go func() {
            for {
              time.Sleep(time.Second)
              select {
                case <-closeChan:
                  log.Println("Goroutine closing")
                  return
                default:
                  log.Println("Writing to log")
                  io.WriteString(writer, fmt.Sprintf("Logging access
                                 %s\n", time.Now().String()))
              }  

            }
          }()

          sigChan := make(chan os.Signal, 1)
          signal.Notify(sigChan,
            syscall.SIGTERM,
            syscall.SIGQUIT,
            syscall.SIGINT)

          // This is blocking read from
          // sigChan where the Notify function sends
          // the signal.
          <-sigChan

          // After the signal is received
          // all the code behind the read from channel could be
          // considered as a cleanup.
          // CLEANUP SECTION
          close(closeChan)
          releaseAllResources()
          fmt.Println("The application shut down gracefully")
        }

        func releaseAllResources() {
          io.WriteString(writer, "Application releasing 
                         all resources\n")
          writer.Close()
        }
```

1.  通过执行`go run main.go`运行代码。

1.  按下*CTRL* + *C*发送`SIGINT`信号。

1.  等待终端输出如下：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/go-stdlib-cb/img/eef690db-8a92-41da-880d-4748b906c175.png)

1.  `recipe11`文件夹还应包含一个名为`test_XXXX.log`的文件，其中包含如下行：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/go-stdlib-cb/img/84079936-5b28-4df9-9622-d0cb003b50dd.png)

# 它是如何工作的...

从`sigChan`读取是阻塞的，因此程序会一直运行，直到通过通道发送信号。`sigChan`是`Notify`函数发送信号的通道。

程序的主要代码在一个新的`goroutine`中运行。这样，当主函数在`sigChan`上被阻塞时，工作将继续。一旦从操作系统发送信号到进程，`sigChan`接收到信号并在从`sigChan`通道读取的行下面的代码执行。这段代码可以被视为清理部分。

请注意，步骤 7 的终端输出包含最终日志`应用程序释放所有资源`，这是清理部分的一部分。

# 另请参阅

有关信号捕获工作原理的详细描述在食谱*处理操作系统信号*中。

# 使用功能选项进行文件配置

这个食谱与 Go 标准库没有直接关系，但包括如何处理应用程序的可选配置。该食谱将在实际情况下使用函数选项模式与文件配置。

# 如何做...

1.  打开控制台并创建文件夹`chapter01/recipe12`。

1.  导航到目录。

1.  创建`main.go`文件，内容如下：

```go
        package main

        import (
          "encoding/json"
          "fmt"
          "os"
        )

        type Client struct {
          consulIP string
          connString string
        }

        func (c *Client) String() string {
          return fmt.Sprintf("ConsulIP: %s , Connection String: %s",
                             c.consulIP, c.connString)
        }

        var defaultClient = Client{
          consulIP: "localhost:9000",
          connString: "postgres://localhost:5432",
        }

        // ConfigFunc works as a type to be used
        // in functional options
        type ConfigFunc func(opt *Client)

        // FromFile func returns the ConfigFunc
        // type. So this way it could read the configuration
        // from the json.
        func FromFile(path string) ConfigFunc {
          return func(opt *Client) {
            f, err := os.Open(path)
            if err != nil {
              panic(err)
            }
            defer f.Close()
            decoder := json.NewDecoder(f)

            fop := struct {
              ConsulIP string `json:"consul_ip"`
            }{}
            err = decoder.Decode(&fop)
            if err != nil {
              panic(err)
            }
            opt.consulIP = fop.ConsulIP
          }
        }

        // FromEnv reads the configuration
        // from the environmental variables
        // and combines them with existing ones.
        func FromEnv() ConfigFunc {
          return func(opt *Client) {
            connStr, exist := os.LookupEnv("CONN_DB")
            if exist {
              opt.connString = connStr
            }
          }
        }

        func NewClient(opts ...ConfigFunc) *Client {
          client := defaultClient
          for _, val := range opts {
            val(&client)
          }
          return &client
        }

        func main() {
          client := NewClient(FromFile("config.json"), FromEnv())
          fmt.Println(client.String())
        }
```

1.  在同一文件夹中，创建名为`config.json`的文件，内容如下：

```go
        {
          "consul_ip":"127.0.0.1"
        }
```

1.  通过命令`CONN_DB=oracle://local:5921 go run main.go`执行代码。

1.  查看输出：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/go-stdlib-cb/img/0bba8cfd-8811-42fc-a255-28160367164c.png)

# 它是如何工作的...

函数选项模式的核心概念是配置 API 包含功能参数。在这种情况下，`NewClient`函数接受各种数量的`ConfigFunc`参数，然后逐个应用于`defaultClient`结构。这样，可以以极大的灵活性修改默认配置。

查看`FromFile`和`FromEnv`函数，它们返回`ConfigFunc`，实际上是访问文件或环境变量。

最后，您可以检查输出，该输出应用了配置选项和结果`Client`结构，其中包含来自文件和环境变量的值。


# 第二章：字符串和其他内容

本章中的配方有：

+   在字符串中查找子字符串

+   将字符串分解为单词

+   使用分隔符连接字符串切片

+   使用 writer 连接字符串

+   使用 tabwriter 对齐文本

+   替换字符串的一部分

+   通过正则表达式模式在文本中查找子字符串

+   从非 Unicode 字符集解码字符串

+   控制大小写

+   解析逗号分隔的数据

+   管理字符串中的空格

+   缩进文本文档

# 介绍

在开发人员的生活中，对字符串和基于字符串的数据进行操作是常见任务。本章介绍如何使用 Go 标准库处理这些任务。毫无疑问，使用标准库可以做很多事情。

检查 Go 是否已正确安装。第一章的*准备就绪*部分，*与环境交互*的*检索 Golang 版本*配方将对您有所帮助。

# 在字符串中查找子字符串

在开发人员中，查找字符串中的子字符串是最常见的任务之一。大多数主流语言都在标准库中实现了这一点。Go 也不例外。本配方描述了 Go 实现这一功能的方式。

# 如何做...

1.  打开控制台并创建文件夹`chapter02/recipe01`。

1.  导航到目录。

1.  创建`contains.go`文件，内容如下：

```go
        package main

        import (
          "fmt"
          "strings"
        )

        const refString = "Mary had a little lamb"

        func main() {

          lookFor := "lamb"
          contain := strings.Contains(refString, lookFor)
          fmt.Printf("The \"%s\" contains \"%s\": %t \n", refString,
                     lookFor, contain)

          lookFor = "wolf"
          contain = strings.Contains(refString, lookFor)
          fmt.Printf("The \"%s\" contains \"%s\": %t \n", refString,
                     lookFor, contain)

          startsWith := "Mary"
          starts := strings.HasPrefix(refString, startsWith)
          fmt.Printf("The \"%s\" starts with \"%s\": %t \n", refString, 
                     startsWith, starts)

          endWith := "lamb"
          ends := strings.HasSuffix(refString, endWith)
          fmt.Printf("The \"%s\" ends with \"%s\": %t \n", refString,
                     endWith, ends)

        }
```

1.  通过执行`go run contains.go`来运行代码。

1.  在终端中查看输出：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/go-stdlib-cb/img/cfdd6ec3-b88c-4c16-b0ea-b27625bd827c.png)

# 它是如何工作的...

Go 库`strings`包含处理字符串操作的函数。这次可以使用`Contains`函数。`Contains`函数只是检查字符串是否包含给定的子字符串。实际上，`Contains`函数中使用了`Index`函数。

要检查字符串是否以子字符串开头，可以使用`HasPrefix`函数。要检查字符串是否以子字符串结尾，可以使用`HasSuffix`函数。

实际上，`Contains`函数是通过使用同一包中的`Index`函数实现的。可以猜到，实际实现方式是这样的：如果给定子字符串的索引大于`-1`，则`Contains`函数返回`true`。

`HasPrefix`和`HasSuffix`函数的工作方式不同：内部实现只是检查字符串和子字符串的长度，如果它们相等或字符串更长，则比较字符串的所需部分。

# 另请参阅

本配方描述了如何匹配精确的子字符串。*通过正则表达式模式在文本中查找子字符串*配方将帮助您了解如何使用正则表达式模式匹配。

# 将字符串分解为单词

将字符串分解为单词可能有些棘手。首先，决定单词是什么，分隔符是什么，是否有任何空格或其他字符。做出这些决定后，可以从`strings`包中选择适当的函数。本配方将描述常见情况。

# 如何做...

1.  打开控制台并创建文件夹`chapter02/recipe02`。

1.  导航到目录。

1.  创建`whitespace.go`文件，内容如下：

```go
        package main

        import (
          "fmt"
          "strings"
        )

        const refString = "Mary had a little lamb"

        func main() {

          words := strings.Fields(refString)
          for idx, word := range words {
            fmt.Printf("Word %d is: %s\n", idx, word)
          }

        }
```

1.  通过执行`go run whitespace.go`来运行代码。

1.  在终端中查看输出：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/go-stdlib-cb/img/aaf4051e-fe24-425c-9f49-cd929cfaed85.png)

1.  创建另一个名为`anyother.go`的文件，内容如下：

```go
        package main

        import (
          "fmt"
          "strings"
        )

        const refString = "Mary_had a little_lamb"

        func main() {

          words := strings.Split(refString, "_")
          for idx, word := range words {
            fmt.Printf("Word %d is: %s\n", idx, word)
          }

        }
```

1.  通过执行`go run anyother.go`来运行代码。

1.  在终端中查看输出：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/go-stdlib-cb/img/c0abf1c1-01cc-4d1a-accd-44894c13b81f.png)

1.  创建另一个名为`specfunction.go`的文件，内容如下：

```go
        package main

        import (
          "fmt"
          "strings"
         )

         const refString = "Mary*had,a%little_lamb"

         func main() {

           // The splitFunc is called for each
           // rune in a string. If the rune
           // equals any of character in a "*%,_"
           // the refString is split.
           splitFunc := func(r rune) bool {
             return strings.ContainsRune("*%,_", r)
           }

           words := strings.FieldsFunc(refString, splitFunc)
           for idx, word := range words {
             fmt.Printf("Word %d is: %s\n", idx, word)
           }

        }
```

1.  通过执行`go run specfunction.go`来运行代码。

1.  在终端中查看输出：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/go-stdlib-cb/img/de72c9b7-3058-4e46-b357-2d46d78961a0.png)

1.  创建另一个名为`regex.go`的文件，内容如下：

```go
        package main

        import (
          "fmt"
          "regexp"
        )

        const refString = "Mary*had,a%little_lamb"

        func main() {

          words := regexp.MustCompile("[*,%_]{1}").Split(refString, -1)
          for idx, word := range words {
            fmt.Printf("Word %d is: %s\n", idx, word)
          }

        }
```

1.  通过执行`go run regex.go`来运行代码。

1.  在终端中查看输出：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/go-stdlib-cb/img/795483fa-ac1f-40af-8bdb-fe4867938c39.png)

# 它是如何工作的...

将字符串拆分为单词的最简单形式考虑任何空白字符作为分隔符。具体来说，空白字符由`unicode`包中的`IsSpace`函数定义：

```go
'\t', '\n', '\v', '\f', '\r', ' ', U+0085 (NEL), U+00A0 (NBSP). 
```

`strings`包的`Fields`函数可以用于按空格字符拆分句子，如前面提到的。步骤**1-5**涵盖了这种简单情况。

如果需要其他分隔符，就需要使用`Split`函数。使用其他分隔符拆分在步骤**6-8**中介绍。只需注意字符串中的空白字符被省略。

如果您需要更复杂的函数来决定是否在给定点拆分字符串，`FieldsFunc`可能适合您。函数的一个参数是消耗给定字符串的符文并在该点返回`true`的函数。这个选项由步骤**9-11**覆盖。

正则表达式是示例中提到的最后一个选项。`regexp`包的`Regexp`结构包含`Split`方法，它的工作方式与您期望的一样。它在匹配组的位置拆分字符串。这种方法在步骤**12-14**中使用。

# 还有更多...

`strings`包还提供了各种`SplitXXX`函数，可以帮助您实现更具体的任务。

# 使用分隔符连接字符串切片

*将字符串拆分为单词*这个教程引导我们完成了根据定义的规则将单个字符串拆分为子字符串的任务。另一方面，本教程描述了如何使用给定的字符串作为分隔符将多个字符串连接成单个字符串。

一个真实的用例可能是动态构建 SQL 选择语句条件的问题。

# 如何做...

1.  打开控制台并创建文件夹`chapter02/recipe03`。

1.  导航到目录。

1.  创建`join.go`文件，内容如下：

```go
        package main

        import (
          "fmt"
          "strings"
        )

        const selectBase = "SELECT * FROM user WHERE %s "

        var refStringSlice = []string{
          " FIRST_NAME = 'Jack' ",
          " INSURANCE_NO = 333444555 ",
          " EFFECTIVE_FROM = SYSDATE "}

        func main() {

          sentence := strings.Join(refStringSlice, "AND")
          fmt.Printf(selectBase+"\n", sentence)

        }
```

1.  通过执行`go run join.go`来运行代码。

1.  在终端中查看输出：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/go-stdlib-cb/img/9a1a1eeb-08a1-483f-a036-383b264ef022.png)

1.  创建`join_manually.go`文件，内容如下：

```go
        package main

        import (
          "fmt"
          "strings"
        )

        const selectBase = "SELECT * FROM user WHERE "

        var refStringSlice = []string{
          " FIRST_NAME = 'Jack' ",
          " INSURANCE_NO = 333444555 ",
          " EFFECTIVE_FROM = SYSDATE "}

        type JoinFunc func(piece string) string

        func main() {

          jF := func(p string) string {
            if strings.Contains(p, "INSURANCE") {
              return "OR"
            }

            return "AND"
          }
          result := JoinWithFunc(refStringSlice, jF)
          fmt.Println(selectBase + result)
        }

         func JoinWithFunc(refStringSlice []string,
                           joinFunc JoinFunc) string {
           concatenate := refStringSlice[0]
           for _, val := range refStringSlice[1:] {
             concatenate = concatenate + joinFunc(val) + val
           }
           return concatenate
        }
```

1.  通过执行`go run join.go`来运行代码。

1.  在终端中查看输出：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/go-stdlib-cb/img/0235e503-6a97-460a-a1cd-f8b35e807aca.png)

# 它是如何工作的...

为了将字符串切片连接成单个字符串，`strings`包的`Join`函数就在那里。简单地说，您需要提供需要连接的字符串切片。这样，您可以舒适地连接字符串切片。步骤**1-5**展示了使用`Join`函数的方法。

当然，可以通过迭代切片来手动实现连接。这样，您可以通过一些更复杂的逻辑自定义分隔符。步骤**6-8**只是表示手动连接如何与更复杂的决策逻辑一起使用，基于当前处理的字符串。

# 还有更多...

`Join`函数由`bytes`包提供，自然用于连接字节切片。

# 使用写入器连接字符串

除了内置的`+`运算符外，还有更多连接字符串的方法。本教程将描述使用`bytes`包和内置的`copy`函数更高效地连接字符串的方法。

# 如何做...

1.  打开控制台并创建文件夹`chapter02/recipe04`。

1.  导航到目录。

1.  创建`concat_buffer.go`文件，内容如下：

```go
       package main

       import (
         "bytes"
         "fmt"
       )

       func main() {
         strings := []string{"This ", "is ", "even ",
                             "more ", "performant "}
          buffer := bytes.Buffer{}
          for _, val := range strings {
            buffer.WriteString(val)
          }

           fmt.Println(buffer.String())
         }
```

1.  通过执行`go run concat_buffer.go`来运行代码。

1.  在终端中查看输出：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/go-stdlib-cb/img/2f4a68c8-c2d3-4636-8bd8-fff4422c4ee9.png)

1.  创建`concat_copy.go`文件，内容如下：

```go
        package main

        import (
          "fmt"
        )

        func main() {

          strings := []string{"This ", "is ", "even ",
                              "more ", "performant "}

          bs := make([]byte, 100)
          bl := 0

          for _, val := range strings {
            bl += copy(bs[bl:], []byte(val))
          }

          fmt.Println(string(bs[:]))

        }
```

1.  在终端中执行`go run concat_copy.go`来运行代码。

1.  在终端中查看输出：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/go-stdlib-cb/img/c256f79f-54e0-4dc9-b44c-67a3e711a549.png)

# 它是如何工作的...

步骤**1-5**涵盖了将`bytes`包`Buffer`作为性能友好的字符串连接解决方案的用法。`Buffer`结构实现了`WriteString`方法，可以用于有效地将字符串连接到底层字节切片中。

在所有情况下都不需要使用这种改进，只需要在程序将要连接大量字符串的情况下考虑一下（例如，在内存中的 CSV 导出和其他情况）。

在步骤**6 - 8**中介绍的内置的`copy`函数可以用于完成`string`的连接。这种方法对最终字符串长度有一些假设，或者可以实时完成。然而，如果结果写入的缓冲区的容量小于已写部分和要附加的字符串的总和，缓冲区必须扩展（通常是通过分配具有更大容量的新切片）。

# 还有更多...

仅供比较，这里有一个基准代码，比较了内置的`+`运算符、`bytes.Buffer`和内置的`copy`的性能：

1.  在其中创建一个`bench`文件夹和文件`bench_test.go`，内容如下：

```go
        package main

        import (
          "bytes"
          "testing"
        )

        const testString = "test"

        func BenchmarkConcat(b *testing.B) {
          var str string
          b.ResetTimer()
          for n := 0; n < b.N; n++ {
            str += testString
          }
          b.StopTimer()
        }

        func BenchmarkBuffer(b *testing.B) {
          var buffer bytes.Buffer

          b.ResetTimer()
          for n := 0; n < b.N; n++ {
            buffer.WriteString(testString)
          }
          b.StopTimer()
        }

        func BenchmarkCopy(b *testing.B) {
          bs := make([]byte, b.N)
          bl := 0

          b.ResetTimer()
          for n := 0; n < b.N; n++ {
            bl += copy(bs[bl:], testString)
          }
          b.StopTimer()
        }
```

1.  查看基准测试的结果：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/go-stdlib-cb/img/c17081b7-fea0-4732-8fe6-817dcef5c142.png)

# 使用 tabwriter 对齐文本

在某些情况下，输出（通常是数据输出）是通过制表文本完成的，这些文本以良好排列的单元格格式化。这种格式可以通过`text/tabwriter`包实现。该包提供了`Writer`过滤器，它将带有制表符的文本转换为格式良好的输出文本。

# 如何做...

1.  打开控制台并创建文件夹`chapter02/recipe05`。

1.  导航到目录。

1.  创建`tabwriter.go`文件，内容如下：

```go
        package main

        import (
          "fmt"
          "os"
          "text/tabwriter"
        )

        func main() {

          w := tabwriter.NewWriter(os.Stdout, 15, 0, 1, ' ',
                                   tabwriter.AlignRight)
          fmt.Fprintln(w, "username\tfirstname\tlastname\t")
          fmt.Fprintln(w, "sohlich\tRadomir\tSohlich\t")
          fmt.Fprintln(w, "novak\tJohn\tSmith\t")
          w.Flush()

        }
```

1.  通过执行`go run tabwriter.go`来运行代码。

1.  在终端中查看输出：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/go-stdlib-cb/img/b82420b6-4610-4dc0-a2c5-c60ce2564e0c.png)

# 它是如何工作的...

通过调用`NewWriter`函数创建具有配置参数的`Writer`过滤器。由此`Writer`写入的所有数据都根据参数进行格式化。这里使用`os.Stdout`仅用于演示目的。

`text/tabwriter`包还提供了一些更多的配置选项，比如`flag`参数。最有用的是`tabwriter.AlignRight`，它配置了写入器在每一列中将内容对齐到右侧。

# 替换字符串的一部分

与字符串处理相关的另一个非常常见的任务是在字符串中替换子字符串。Go 标准库提供了`Replace`函数和`Replacer`类型，用于一次替换多个字符串。

# 如何做...

1.  打开控制台并创建文件夹`chapter02/recipe06`。

1.  导航到目录。

1.  创建`replace.go`文件，内容如下：

```go
        package main

        import (
         "fmt"
         "strings"
        )

        const refString = "Mary had a little lamb"
        const refStringTwo = "lamb lamb lamb lamb"

        func main() {
          out := strings.Replace(refString, "lamb", "wolf", -1)
          fmt.Println(out)

          out = strings.Replace(refStringTwo, "lamb", "wolf", 2)
          fmt.Println(out)
        }
```

1.  通过执行`go run replace.go`来运行代码。

1.  在终端中查看输出：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/go-stdlib-cb/img/76243f61-3968-4c87-81ef-303c328e2f7e.png)

1.  创建`replacer.go`文件，内容如下：

```go
        package main

        import (
          "fmt"
          "strings"
        )

        const refString = "Mary had a little lamb"

        func main() {
          replacer := strings.NewReplacer("lamb", "wolf", "Mary", "Jack")
          out := replacer.Replace(refString)
          fmt.Println(out)
        }
```

1.  通过执行`go run replacer.go`来运行代码。

1.  在终端中查看输出：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/go-stdlib-cb/img/da6e947d-9685-4b0d-871c-d61272db6f04.png)

1.  创建`regexp.go`文件，内容如下：

```go
        package main

        import (
          "fmt"
          "regexp"
        )

        const refString = "Mary had a little lamb"

        func main() {
          regex := regexp.MustCompile("l[a-z]+")
          out := regex.ReplaceAllString(refString, "replacement")
          fmt.Println(out)
        }
```

1.  通过执行`go run regexp.go`来运行代码。

1.  在终端中查看输出：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/go-stdlib-cb/img/9aa3b189-d60a-44e3-8e5e-b8dac48d94e0.png)

# 它是如何工作的...

`strings`包的`Replace`函数被广泛用于简单的替换。最后一个整数参数定义了将进行多少次替换（在`-1`的情况下，所有字符串都被替换。看到`Replace`的第二个用法，只有前两次出现被替换）。`Replace`函数的用法在步骤**1 - 5**中呈现。

除了`Replace`函数，`Replacer`结构也有`WriteString`方法。这个方法将使用`Replacer`中定义的所有替换写入给定的写入器。这种类型的主要目的是可重用性。它可以一次替换多个字符串，并且对并发使用是安全的；参见步骤**6 - 8**。

替换子字符串，甚至匹配模式的更复杂方法，自然是使用正则表达式。`Regex`类型指针方法`ReplaceAllString`可以用于此目的。步骤**9 - 11**说明了`regexp`包的用法。

# 还有更多...

如果需要更复杂的逻辑来进行替换，那么`regexp`包可能是应该使用的包。

# 通过正则表达式模式在文本中查找子字符串

总是有一些任务，比如验证输入、在文档中搜索信息，甚至从给定字符串中清除不需要的转义字符。对于这些情况，通常使用正则表达式。

Go 标准库包含`regexp`包，涵盖了正则表达式的操作。

# 如何做...

1.  打开控制台并创建文件夹`chapter02/recipe07`。

1.  导航到目录。

1.  创建`regexp.go`文件，内容如下：

```go
        package main

        import (
          "fmt"
          "regexp"
        )

        const refString = `[{ \"email\": \"email@example.com\" \
                             "phone\": 555467890},
                            { \"email\": \"other@domain.com\" \
                             "phone\": 555467890}]`

        func main() {

          // This pattern is simplified for brevity
          emailRegexp := regexp.MustCompile("[a-zA-Z0-9]{1,}
                                             @[a-zA-Z0-9]{1,}\\.[a-z]{1,}")
          first := emailRegexp.FindString(refString)
          fmt.Println("First: ")
          fmt.Println(first)

          all := emailRegexp.FindAllString(refString, -1)
          fmt.Println("All: ")
          for _, val := range all {
            fmt.Println(val)
          }

        }
```

1.  通过执行`go run regexp.go`来运行代码。

1.  在终端中查看输出：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/go-stdlib-cb/img/70ccf05e-39f5-4e35-8df8-48c45e48dd9a.png)

# 工作原理...

`FindString`或`FindAllString`函数是在给定字符串中查找匹配模式的最简单方法。唯一的区别是`Regexp`的`FindString`方法只会返回第一个匹配项。另一方面，`FindAllString`会返回一个包含所有匹配项的字符串切片。

`Regexp`类型提供了丰富的`FindXXX`方法。本教程仅描述了通常最有用的`String`变体。请注意，前面的代码使用了`regexp`包的`MustCompile`函数，如果正则表达式的编译失败，它会引发 panic。

# 另请参阅

除了这种复杂的正则表达式模式匹配，还可以仅匹配子字符串。这种方法在本章的*在字符串中查找子字符串*教程中有描述。

# 从非 Unicode 字符集解码字符串

一个鲜为人知的事实是，所有`.go`文件中的内容都是用 UTF-8 编码的。信不信由你，Unicode 并不是世界上唯一的字符集。例如，Windows-1250 编码在 Windows 用户中广泛传播。

在处理非 Unicode 字符串时，需要将内容转换为 Unicode。本教程演示了如何解码和编码非 Unicode 字符串。

# 如何做...

1.  打开控制台并创建文件夹`chapter02/recipe08`。

1.  导航到目录。

1.  创建内容为`Gdańsk`的文件`win1250.txt`。该文件必须以 windows-1250 字符集进行编码。如果不确定如何操作，只需跳到第 6 步，完成第 7 步后，将创建 windows-1250 编码的文件，然后可以将`out.txt`文件重命名并返回第 4 步。

1.  创建`decode.go`文件，内容如下：

```go
        package main

        import (
          "fmt"
          "io/ioutil"
          "os"
          "strings"

          "golang.org/x/text/encoding/charmap"
        )

        func main() {

          // Open windows-1250 file.
          f, err := os.Open("win1250.txt")
          if err != nil {
            panic(err)
          }
          defer f.Close()

          // Read all in raw form.
          b, err := ioutil.ReadAll(f)
          if err != nil {
            panic(err)
          }
          content := string(b)

          fmt.Println("Without decode: " + content)

          // Decode to unicode
          decoder := charmap.Windows1250.NewDecoder()
          reader := decoder.Reader(strings.NewReader(content))
          b, err = ioutil.ReadAll(reader)
          if err != nil {
            panic(err)
          }
          fmt.Println("Decoded: " + string(b))

        }
```

1.  通过执行`go run decode.go`来运行代码。

1.  在终端中查看输出：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/go-stdlib-cb/img/9943be1b-4808-496e-9ebe-90d0947094d0.png)

1.  创建名为`encode.go`的文件，内容如下：

```go
        package main

        import (
          "io"
          "os"

          "golang.org/x/text/encoding/charmap"
        )

        func main() {

          f, err := os.OpenFile("out.txt", os.O_CREATE|os.O_RDWR,
                                os.ModePerm|os.ModeAppend)
          if err != nil {
            panic(err)
          }
          defer f.Close()

          // Decode to unicode
          encoder := charmap.Windows1250.NewEncoder()
          writer := encoder.Writer(f)
          io.WriteString(writer, "Gdańsk")

        }
```

1.  通过执行`go run encode.go`来运行代码。

1.  在 Windows-1250 编码和 UTF-8 编码的文件`out.txt`中查看输出。

# 工作原理...

包`golang.org/x/text/encoding/charmap`包含了简单编码和解码的`Charset`类型。该类型实现了创建`Decoder`结构的`NewDecoder`方法。

步骤**1-5**展示了解码`Reader`的用法。

编码工作类似。创建编码`Writer`，然后由该`Writer`写入的每个字符串都会被编码为 Windows-1250 编码。

请注意，Windows-1250 被选择作为示例。包`golang.org/x/text/encoding/charmap`包含了许多其他字符集选项。

# 控制大小写

有许多实际任务需要修改大小写。让我们挑选其中的一些：

+   不区分大小写的比较

+   自动首字母大写

+   驼峰式转蛇式转换

为此，`strings`包提供了`ToLower`、`ToUpper`、`ToTitle`和`Title`函数。

# 如何做...

1.  打开控制台并创建文件夹`chapter02/recipe09`。

1.  导航到目录。

1.  创建`case.go`文件，内容如下：

```go
        package main

        import (
          "fmt"
          "strings"
          "unicode"
        )

        const email = "ExamPle@domain.com"
        const name = "isaac newton"
        const upc = "upc"
        const i = "i"

        const snakeCase = "first_name"

        func main() {

          // For comparing the user input
          // sometimes it is better to
          // compare the input in a same
          // case.
          input := "Example@domain.com"
          input = strings.ToLower(input)
          emailToCompare := strings.ToLower(email)
          matches := input == emailToCompare
          fmt.Printf("Email matches: %t\n", matches)

          upcCode := strings.ToUpper(upc)
          fmt.Println("UPPER case: " + upcCode)

          // This digraph has different upper case and
          // title case.
          str := "ǳ"
          fmt.Printf("%s in upper: %s and title: %s \n", str,
                     strings.ToUpper(str), strings.ToTitle(str))

          // Use of XXXSpecial function
          title := strings.ToTitle(i)
          titleTurk := strings.ToTitleSpecial(unicode.TurkishCase, i)
          if title != titleTurk {
            fmt.Printf("ToTitle is defferent: %#U vs. %#U \n",
                       title[0], []rune(titleTurk)[0])
          }

          // In some cases the input
          // needs to be corrected in case.
          correctNameCase := strings.Title(name)
          fmt.Println("Corrected name: " + correctNameCase)

          // Converting the snake case
          // to camel case with use of
          // Title and ToLower functions.
          firstNameCamel := toCamelCase(snakeCase)
          fmt.Println("Camel case: " + firstNameCamel)

        }

        func toCamelCase(input string) string {
          titleSpace := strings.Title(strings.Replace(input, "_", " ", -1))
          camel := strings.Replace(titleSpace, " ", "", -1)
          return strings.ToLower(camel[:1]) + camel[1:]
        }
```

1.  通过执行`go run case.go`来运行代码。

1.  在终端中查看输出：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/go-stdlib-cb/img/d144e5ad-7430-44e3-82f1-e18202476c4d.png)

# 它是如何工作的...

请注意，Unicode 中的标题大小写映射与大写映射不同。不同之处在于字符数需要特殊处理。这些主要是连字和双字母，如*fl*，*dz*和*lj*，以及一些多音调希腊字符。例如，*U+01C7 (LJ)*映射到*U+01C8 (Lj)*，而不是*U+01C9 (lj)*。

为了进行适当的不区分大小写比较，应该使用`strings`包中的`EqualFold`函数。该函数使用大小写折叠来规范化字符串并进行比较。

# 解析逗号分隔的数据

有多种表格数据格式。**CSV**（逗号分隔值）是用于数据传输和导出的最基本格式之一。没有定义 CSV 的标准，但格式本身在 RFC 4180 中有描述。

这个示例介绍了如何舒适地解析 CSV 格式的数据。

# 如何做...

1.  打开控制台并创建文件夹`chapter02/recipe10`。

1.  导航到目录。

1.  创建名为`data.csv`的文件，其中包含以下内容：

```go
        "Name","Surname","Age"
        # this is comment in data
        "John","Mnemonic",20
        Maria,Tone,21
```

1.  创建名为`data.go`的文件，其中包含以下内容：

```go
        package main

        import (
          "encoding/csv"
          "fmt"
          "os"
        )

        func main() {

          file, err := os.Open("data.csv")
          if err != nil {
            panic(err)
          }
          defer file.Close()

          reader := csv.NewReader(file)
          reader.FieldsPerRecord = 3
          reader.Comment = '#'

          for {
            record, e := reader.Read()
            if e != nil {
              fmt.Println(e)
              break
            }
            fmt.Println(record)
          }
        }
```

1.  通过执行`go run data.go`来运行代码。

1.  在终端中查看输出：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/go-stdlib-cb/img/788beecb-4faf-49b4-b6ca-21710a3aec1d.png)

1.  创建名为`data_uncommon.csv`的文件，其中包含以下内容：

```go
       Name;Surname;Age
       "John";Mnemonic;20
       "Maria";Tone;21
```

1.  创建名为`data_uncommon.go`的文件，其中包含以下内容：

```go
       package main

       import (
         "encoding/csv"
         "fmt"
         "os"
       )

       func main() {

         file, err := os.Open("data_uncommon.csv")
         if err != nil {
           panic(err)
         }
         defer file.Close()

         reader := csv.NewReader(file)
         reader.Comma = ';'

         for {
           record, e := reader.Read()
           if e != nil {
             fmt.Println(e)
             break
           }
           fmt.Println(record)
         }
       }
```

1.  通过执行`go run data_uncommon.go`来运行代码。

1.  在终端中查看输出：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/go-stdlib-cb/img/f872ac32-9dae-4681-b8a5-7c6fd0f885cb.png)

# 它是如何工作的...

与简单地逐行扫描输入并使用`strings.Split`和其他方法解析 CSV 格式不同，Go 提供了更好的方法。`encoding/csv`包中的`NewReader`函数返回`Reader`结构，该结构提供了读取 CSV 文件的 API。`Reader`结构保留了变量来配置`read`参数，根据您的需求。

`Reader`的`FieldsPerRecord`参数是一个重要的设置。这样可以验证每行的单元格数。默认情况下，当设置为`0`时，它设置为第一行中的记录数。如果设置为正值，则记录数必须匹配。如果设置为负值，则不进行单元格计数验证。

另一个有趣的配置是`Comment`参数，它允许您定义解析数据中的注释字符。在示例中，整行都会被忽略。

Go 1.10 现在禁止使用荒谬的逗号和注释设置。这意味着空值、回车、换行、无效符文和 Unicode 替换字符。还禁止将逗号和注释设置为相等。

# 管理字符串中的空白

字符串输入可能包含过多的空白、过少的空白或不合适的空白字符。本示例包括了如何处理这些并将字符串格式化为所需格式的提示。

# 如何做...

1.  打开控制台并创建文件夹`chapter02/recipe11`。

1.  导航到目录。

1.  创建名为`whitespace.go`的文件，其中包含以下内容：

```go
        package main

        import (
          "fmt"
          "math"
          "regexp"
          "strconv"
          "strings"
        )

        func main() {

          stringToTrim := "\t\t\n Go \tis\t Awesome \t\t"
          trimResult := strings.TrimSpace(stringToTrim)
          fmt.Println(trimResult)

          stringWithSpaces := "\t\t\n Go \tis\n Awesome \t\t"
          r := regexp.MustCompile("\\s+")
          replace := r.ReplaceAllString(stringWithSpaces, " ")
          fmt.Println(replace)

          needSpace := "need space"
          fmt.Println(pad(needSpace, 14, "CENTER"))
          fmt.Println(pad(needSpace, 14, "LEFT"))
        }

        func pad(input string, padLen int, align string) string {
          inputLen := len(input)

          if inputLen >= padLen {
            return input
          }

          repeat := padLen - inputLen
          var output string
          switch align {
            case "RIGHT":
              output = fmt.Sprintf("% "+strconv.Itoa(-padLen)+"s", input)
            case "LEFT":
              output = fmt.Sprintf("% "+strconv.Itoa(padLen)+"s", input)
            case "CENTER":
              bothRepeat := float64(repeat) / float64(2)
              left := int(math.Floor(bothRepeat)) + inputLen
              right := int(math.Ceil(bothRepeat))
              output = fmt.Sprintf("% "+strconv.Itoa(left)+"s% 
                                   "+strconv.Itoa(right)+"s", input, "")
          }
          return output
        }
```

1.  通过执行`go run whitespace.go`来运行代码。

1.  查看输出：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/go-stdlib-cb/img/35175b6c-1e9b-4ddd-97a9-6c86aa8c379d.png)

# 它是如何工作的...

在代码处理之前修剪字符串是非常常见的做法，正如前面的代码所示，标准的 Go 库可以轻松完成这项工作。`strings`库还提供了更多`TrimXXX`函数的变体，也允许修剪字符串中的其他字符。

要修剪前导和结束的空白，可以使用`strings`包的`TrimSpace`函数。这是代码的以下部分的典型示例，这也是之前示例中包含的：

```go
stringToTrim := "\t\t\n Go \tis\t Awesome \t\t"
stringToTrim = strings.TrimSpace(stringToTrim)
```

`regex`包适用于替换多个空格和制表符，可以通过这种方式准备字符串以便进一步处理。请注意，使用此方法时，换行符将被替换为一个空格。

代码的这一部分表示使用正则表达式将所有多个空格替换为单个空格：

```go
r := regexp.MustCompile("\\s+")
replace := r.ReplaceAllString(stringToTrim, " ")
```

填充不是`strings`包的显式函数，但可以通过`fmt`包的`Sprintf`函数实现。代码中的`pad`函数使用格式化模式`% <+/-padding>s`和一些简单的数学运算来找出填充。最后，填充数字前的减号作为右填充，正数作为左填充。

# 另请参阅

有关如何使用正则表达式的更多提示，您可以在本章中查看*通过正则表达式模式在文本中查找子字符串*的示例。

# 对文本文档进行缩进

前面的示例描述了如何进行字符串填充和修剪空白。这个示例将指导您如何对文本文档进行缩进和取消缩进。将使用前面示例中的类似原则。

# 如何做...

1.  打开控制台并创建文件夹`chapter02/recipe12`。

1.  创建名为`main.go`的文件，并包含以下内容：

```go
         package main

         import (
           "fmt"
           "strconv"
           "strings"
           "unicode"
         )

         func main() {

           text := "Hi! Go is awesome."
           text = Indent(text, 6)
           fmt.Println(text)

           text = Unindent(text, 3)
           fmt.Println(text)

           text = Unindent(text, 10)
           fmt.Println(text)

           text = IndentByRune(text, 10, '.')
           fmt.Println(text)

         }

         // Indent indenting the input by given indent and rune
         func IndentByRune(input string, indent int, r rune) string {
           return strings.Repeat(string(r), indent) + input
         }

         // Indent indenting the input by given indent
         func Indent(input string, indent int) string {
           padding := indent + len(input)
           return fmt.Sprintf("% "+strconv.Itoa(padding)+"s", input)
         }

         // Unindent unindenting the input string. In case the
         // input is indented by less than "indent" spaces
         // the min of this both is removed.
         func Unindent(input string, indent int) string {

           count := 0
           for _, val := range input {
             if unicode.IsSpace(val) {
               count++
             }
             if count == indent || !unicode.IsSpace(val) {
               break
             }
           }

           return input[count:]
         }
```

1.  在终端中执行`go run main.go`来运行代码。

1.  查看输出：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/go-stdlib-cb/img/30068e99-b616-4c59-9169-7be545936a62.png)

# 它是如何工作的...

缩进就像填充一样简单。在这种情况下，使用相同的格式选项。`indent`实现的更可读形式可以使用`strings`包的`Repeat`函数。上述代码中的`IndentByRune`函数应用了这种方法。

在这种情况下，取消缩进意味着删除给定数量的前导空格。在上述代码中，`Unindent`的实现会删除最少数量的前导空格或给定的缩进。

# 另请参阅

*管理字符串中的空白*示例也以更宽松的方式处理空格。
