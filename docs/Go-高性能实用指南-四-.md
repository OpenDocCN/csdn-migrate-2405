# Go 高性能实用指南（四）

> 原文：[`zh.annas-archive.org/md5/CBDFC5686A090A4C898F957320E40302`](https://zh.annas-archive.org/md5/CBDFC5686A090A4C898F957320E40302)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第三部分：部署、监控和迭代 Go 程序时考虑性能

在本节中，您将了解编写高性能 Go 代码的各种惯用方法。因此，在本节中，我们将努力在实际场景中编写高性能的 Go 代码。

本节包括以下章节：

+   第十一章，构建和部署 Go 代码

+   第十二章，Go 代码性能分析

+   第十三章，Go 代码追踪

+   第十四章，集群和作业队列

+   第十五章，跨版本比较代码质量


# 第十一章：构建和部署 Go 代码

一旦我们找到了编写高性能 Go 代码的方法，我们需要部署它，验证它，并继续迭代它。这个过程的第一步是部署新的 Go 代码。Go 的代码被编译成二进制文件，这允许我们在代码开发的迭代过程中以模块化的方式部署新的 Go 代码。我们可以将其推送到一个或多个位置，以便针对不同的环境进行测试。这样做将使我们能够优化我们的代码，充分利用系统中将可用的吞吐量。

在本章中，我们将学习有关 Go 构建过程的所有内容。我们将看看 Go 编译器如何构建二进制文件，并利用这些知识为当前平台构建合适大小、优化的二进制文件。我们将涵盖以下主题：

+   构建 Go 二进制文件

+   使用`go clean`来删除对象文件

+   使用`go get`来下载和安装依赖项

+   使用`go mod`进行依赖管理

+   使用`go list`来列出包和模块

+   使用`go run`来执行程序

+   使用`go install`来安装包

这些主题将帮助我们从我们的源代码构建高效的 Go 二进制文件。

# 构建 Go 二进制文件

在第十章中，*Go 中的编译时评估*，我们讨论了一些可能有助于优化我们构建策略的 Go 构建优化。Go 的构建系统有很多选项，可以帮助系统操作员向他们的构建策略添加额外的参数化。

Go 工具有许多不同的方法来构建我们的源代码。让我们先了解每个顶层理解，然后我们将更深入地讨论每个包。了解这些命令之间的关键区别可能会帮助您了解它们如何相互作用，并选择适合工作的正确工具。让我们来看看它们：

+   `go build`：为您的项目构建二进制文件，编译包和依赖项

+   `go clean`：从包源目录中删除对象和缓存文件

+   `go get`：下载并安装包及其依赖项

+   `go mod`：Go 的（相对较新的）内置依赖模块系统

+   `go list`：列出命名的包和模块，并显示有关文件、导入和依赖项的重要构建信息

+   `go run`：运行和编译命名的 Go 程序

+   `go install`：为您的项目构建二进制文件，将二进制文件移动到`$GOPATH/bin`，并缓存所有非主要包

在本章中，我们将调查 Go 构建系统的这些不同部分。随着我们对这些程序如何相互操作的了解越来越多，我们将能够看到如何利用它们来构建适合我们期望的支持架构和操作系统的精简、功能丰富的二进制文件。

在下一节中，我们将通过`go build`来看一下。

# Go build - 构建您的 Go 代码

go build 的调用标准如下：

```go
go build [-o output] [build flags] [packages]
```

使用`-o`定义输出，使用特定命名的文件编译二进制文件。当您有特定的命名约定要保留到您的文件中，或者如果您想根据不同的构建参数（平台/操作系统/git SHA 等）命名二进制文件时，这将非常有帮助。

包可以定义为一组 go 源文件，也可以省略。如果指定了一组 go 源文件的列表，构建程序将使用作为指定单个包的组传递的文件列表。如果未定义任何包，构建程序将验证目录中的包是否可以构建，但将丢弃构建的结果。

# 构建标志

Go 的构建标志被`build`、`clean`、`install`、`list`、`run`和`test`命令共享。以下是一个表格，列出了构建标志及其用法描述：

| **构建标志** | **描述** |
| --- | --- |
| `-a` | 强制重新构建包。如果您想确保所有依赖项都是最新的，这可能特别方便。 |
| `-n` | 打印编译器使用的命令，但不运行命令（类似于其他语言中的干运行）。这对于查看包的编译方式很有用。 |
| `-p n` | 并行化构建命令。默认情况下，此值设置为构建系统可用的 CPU 数量。 |

|`-race` | 启用竞争检测。只有某些架构才能检测到竞争检测：

+   linux/amd64

+   freebsd/amd64

+   darwin/amd64

+   windows/amd64

|

| `-msan` | 检测 C 中未初始化的内存读取。这仅在 Linux 上支持 amd64 或 arm64 架构，并且需要使用 clang/LLVM 编译器进行主机。可以使用`CC=clang go build -msan example.go`进行调用。 |
| --- | --- |
| `-v` | 在编译程序时，构建的包的名称将列在 stdout 中。这有助于验证用于构建的包。 |
| `-work` | 打印 Go 在构建二进制文件时使用的临时工作目录的值。这通常默认存储在`/tmp/`中。 |
| `-x` | 显示构建过程中使用的所有命令。这有助于确定如何构建包。有关更多信息，请参见*构建信息*部分。 |
| `-asmflags '[pattern=]arg list'` | 调用`go tool asm`时要传递的参数列表。 |

|`-buildmode=type` | 这告诉构建命令我们想要构建哪种类型的目标文件。目前，`buildmode`有几种类型选项：

+   `archive`: 将非主包构建为`.a`文件。

+   `c-archive`: 将主包和其所有导入项构建为 C 存档文件。

+   `c-shared`: 将主包和其导入项构建为 C 共享库。

+   `default`: 创建主包列表。

+   `shared`: 将所有非主包合并为单个共享库。

+   `exe`: 将主包和其导入项构建为可执行文件。

+   `pie`: 将主包和其导入项构建为**位置无关可执行文件**（**PIE**）。

+   `plugin`: 将主包和其导入项构建为 Go 插件。

|

| `-compiler name` | 确定要使用的编译器。常见用途是`gccgo`和`gc`。 |
| --- | --- |
| `-gccgoflags` | `gccgo`编译器和链接器调用标志。 |
| `-gcflags` | `gc`编译器和链接器调用标志。有关更多详细信息，请参见*编译器和链接器*部分。 |
| `-installsuffix suffix` | 向包安装目录的名称添加后缀。这是为了使输出与默认构建分开而使用的。 |
| `-ldflags '[pattern=]arg list'` | Go 工具链接调用参数。有关更多详细信息，请参见*编译器和链接器*部分。 |
| `-linkshared` | 在进行`-buildmode=shared`调用后，此标志将链接到新创建的共享库。 |
| `-mod` | 确定要使用的模块下载模式。在撰写本文时，有两个选项：`- readonly`或`vendor`。 |
| `-pkgdir dir` | 利用定义的`dir`来安装和加载所有包。 |
| `-tags tag,list` | 要在构建过程中满足的构建标签列表。此列表以逗号分隔的形式传递。 |

|`-trimpath` | 结果构建的可执行文件将在可执行文件构建期间使用不同的文件系统路径命名方案。这些如下：

+   Go（用于标准库）

+   路径@版本（用于 go 模块）

+   普通导入路径（使用`GOPATH`）

|

| `-toolexec 'cmd args'` | 调用工具链程序，例如调试器或其他交互式程序。这用于诸如 vet 和 asm 的程序。 |
| --- | --- |

有了所有这些信息，您将能够有效地构建正确的链接器标志。

# 构建信息

为了更好地了解构建过程，让我们看一些构建示例，以便更好地了解构建工具是如何协同工作的。

假设我们想要构建一个简单的 HTTP 服务器，其中有一个 Prometheus 导出器。我们可以这样创建一个导出器：

```go
package main
import (
    "fmt"
    "net/http"
    "github.com/prometheus/client_golang/prometheus/promhttp"
)

func main() {
    http.Handle("/", promhttp.Handler())
    port := ":2112"
    fmt.Println("Prometheus Handler listening on port ", port)
    http.ListenAndServe(port, nil)
}                                                                
```

当我们的包准备好后，我们可以使用以下命令构建我们的包：

```go
go build -p 4 -race -x prometheusExporterExample.go
```

当我们构建这个二进制文件时，我们会看到一些东西回到 stdout（因为我们传递了`-x`标志来查看在过程中使用的命令）。让我们来看一下：

1.  我们将截断输出，以便结果更易于阅读。如果你自己测试一下，你会看到更大的构建输出：

```go
WORK=/tmp/go-build924967855
```

为构建设置了一个临时工作目录。正如我们之前提到的，这通常位于`/tmp/`目录中，除非另有规定：

```go
mkdir -p $WORK/b001/
```

1.  编译器还创建了一个子工作目录：

```go
cat >$WORK/b001/importcfg.link << 'EOF' # internal
```

1.  创建并添加了一个链接配置。这会向链接配置添加各种不同的参数：

```go
packagefile command-line-arguments=/home/bob/.cache/go-build/aa/aa63d73351c57a147871fde4964d74c9a39330b467c6d73640815775e6673084-d
```

1.  命令行参数的包是从缓存中引用的：

```go
packagefile fmt=/home/bob/.cache/go-build/74/749e110dc104578def1859fbd4ca5c5546f4032f02ffd5ea4d14c730fbd65b81-d
```

`fmt`是我们用来显示`fmt.Println("Prometheus Handler listening on port ", port)`的打印包。这样引用：

```go
packagefile github.com/prometheus/client_golang/prometheus/promhttp=/home/bob/.cache/go-build/e9/e98940b17504e2f647dccc7832793448aa4e8a64047385341c94c1c4431d59cf-d
```

1.  编译器还为 Prometheus HTTP 客户端库添加了包。之后，还有许多其他引用被添加到构建中。由于篇幅原因，这部分已被截断。

文件末尾用`EOF`表示。

1.  创建一个可执行目录：

```go
mkdir -p $WORK/b001/exe/
```

1.  然后编译器使用之前创建的`importcfg`构建二进制文件：

```go
/usr/lib/golang/pkg/tool/linux_amd64/link -o $WORK/b001/exe/a.out -importcfg $WORK/b001/importcfg.link -installsuffix race -buildmode=exe -buildid=bGYa4XecCYqWj3VjKraU/eHfXIjk2XJ_C2azyW4yU/8YHxpy5Xa69CGQ4FC9Kb/bGYa4XecCYqWj3VjKraU -race -extld=gcc /home/bob/.cache/go-build/aa/aa63d73351c57a147871fde4964d74c9a39330b467c6d73640815775e6673084-
```

1.  然后添加了一个`buildid`：

```go
/usr/lib/golang/pkg/tool/linux_amd64/buildid -w $WORK/b001/exe/a.out # internal
```

1.  接下来，二进制文件被重命名为我们在导出示例中使用的文件名（因为我们没有使用`-o`指定不同的二进制文件名）：

```go
cp $WORK/b001/exe/a.out prometheusExporterExample
```

1.  最后，工作目录被删除：

```go
rm -r $WORK/b001/
```

这个程序的工作输出是一个 Go 二进制文件。在下一节中，我们将讨论编译器和链接器标志。

# 编译器和链接器标志

在构建 Go 二进制文件时，`-gcflags`标志允许您传递可选的编译器参数，而`-ldflags`标志允许您传递可选的链接器参数。可以通过调用以下命令找到编译器和链接器标志的完整列表：

```go
go tool compile -help
go tool link -help
```

让我们看一个利用编译器和链接器标志的例子。我们可以构建一个简单的程序，返回一个未初始化的字符串变量的值。以下程序看起来似乎无害：

```go
package main
import "fmt"

var linkerFlag string
func main() {
    fmt.Println(linkerFlag)
}
```

如果我们使用一些常见的编译器和链接器标志构建这个，我们将看到一些有用的输出：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/hsn-hiperf-go/img/035f3d29-623d-495c-85a2-11918dda45ca.png)

编译器标志我们在这里传递的实现了以下功能：

+   `"-m -m"`：打印有关编译器优化决策的信息。这是我们在构建命令后看到的前面截图中的输出。

+   `"-N"`：禁用 Go 二进制文件中的优化。

+   `"-l"`：禁用内联。

我们传递的链接器标志做了以下事情：

+   `"-X main.linkerFlag=Hi_Gophers"`：为`main`中的`linkerFlag`变量设置一个值。在构建时添加变量是很重要的，因为许多开发人员希望在编译时向他们的代码添加某种构建参数。我们可以使用``date -u +.%Y%m%d%.H%M%S``传递构建日期，也可以使用`git rev-list -1 HEAD`传递 git 提交版本。这些值以后可能对引用构建状态很有帮助。

+   `"-s"`：禁用符号表，这是一种存储源代码中每个标识符的数据结构，以及声明信息。这通常不需要用于生产二进制文件。

+   `"-w"`：禁用 DWARF 生成。由于 Go 二进制文件包括基本类型信息、PC 到行数据和符号表，通常不需要保存 dwarf 表。

如果我们使用标准方法构建二进制文件，然后使用一些可用的编译器和链接器标志，我们将能够看到二进制文件大小的差异：

+   非优化构建：

```go
$ go build -ldflags "-X main.linkerFlag=Hi_Gophers" -o nonOptimized
```

+   优化构建：

```go
$ go build -gcflags="-N -l" -ldflags "-X main.linkerFlag=Hi_Gophers -s -w" -o Optimized
```

正如我们所看到的，`Optimized`二进制文件比`nonOptimized`二进制文件小 28.78%：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/hsn-hiperf-go/img/96137129-bf02-41ac-a309-f719fda97509.png)

这两个二进制文件对最终用户执行相同的功能，因此考虑使用编译器和链接器标志删除一些构建优化，以减少最终生成的二进制文件大小。这在存储和部署这些二进制文件时可能是有益的。

# 构建约束

如果您想要向您的 Go 构建添加构建约束，可以在文件开头添加一行注释，该注释只在空行和其他注释之前。此注释的形式是`// +build darwin,amd64,!cgo, android,386,cgo`。

这对应于`darwin AND amd64 AND (NOT cgo)) OR (android AND 386 AND cgo`的布尔输出。

这需要在包声明之前，构建约束和包初始化之间有一个换行。这采用以下形式：

```go
// +build [OPTIONS]

package main
```

可以在[`golang.org/pkg/go/build/#hdr-Build_Constraints`](https://golang.org/pkg/go/build/#hdr-Build_Constraints)找到完整的构建约束列表。此列表包括以下构建约束：

+   `GOOS`

+   `GOARCH`

+   编译器类型（`gc`或`gccgo`）

+   `cgo`

+   所有 1.x Go 版本（beta 或次要版本没有构建标签）

+   `ctxt.BuildTags`中列出的其他单词

如果您的库中有一个文件，您希望在构建中排除它，您也可以以以下形式添加注释：

```go
// +build ignore
```

相反，您可以使用以下形式的注释将文件构建限制为特定的`GOOS`、`GOARCH`和`cgo`位：

```go
// +build windows, 386, cgo
```

只有在使用`cgo`并在 Windows 操作系统的 386 处理器上构建时才会构建文件。这是 Go 语言中的一个强大构造，因为您可以根据必要的构建参数构建包。

# 文件名约定

如果文件匹配`GOOS`和`GOARCH`模式，并去除任何扩展名和`_test`后缀（用于测试用例），则该文件将为特定的`GOOS`或`GOARCH`模式构建。这样的模式通常被引用如下：

+   `*_GOOS`

+   `*_GOARCH`

+   `*_GOOS_GOARCH`

例如，如果您有一个名为`example_linux_arm.go`的文件，它将只作为 Linux arm 构建的一部分构建。

在下一节中，我们将探讨`go clean`命令。

# Go clean - 清理您的构建目录

Go 命令会在临时目录中构建二进制文件。go clean 命令是为了删除其他工具创建的多余的对象文件或手动调用 go build 时创建的对象文件。Go clean 有一个用法部分`go clean [clean flags] [build flags] [packages]`。

对于 clean 命令，以下标志是可用的：

+   `-cache`标志会删除整个 go 构建缓存。如果您想要比较多个系统上的新构建，或者想要查看新构建所需的时间，这可能会有所帮助。

+   `-i`标志会删除 go install 创建的存档或二进制文件。

+   `-n`标志是一个空操作；打印结果会删除命令，但不执行它们。

+   `-r`标志会递归地应用逻辑到导入路径包的所有依赖项。

+   `-x`标志会打印并执行生成的删除命令。

+   `-cache`标志会删除整个 go 构建缓存。

+   `-testcache`标志会删除构建缓存中的测试结果。

+   `-modcache`标志会删除模块下载缓存。

如果我们想尝试一个没有现有依赖关系的干净构建，我们可以使用一个命令从 go 构建系统的许多重要缓存中删除项目。让我们来看一下：

1.  我们将构建我们的`prometheusExporterExample`以验证构建缓存的大小是否发生变化。我们可以使用 go 环境`GOCACHE`变量找到我们的构建缓存位置：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/hsn-hiperf-go/img/02570ce5-f34e-400f-a39f-184fec134edb.png)

1.  对于我们的验证，我们将连续使用几个命令。首先，我们将使用`rm -rf ~/.cache/go-build/`删除整个缓存目录。

1.  接下来，我们可以通过运行`go build prometheusExporterExample.go`命令来构建我们的 Go 二进制文件。

1.  然后，我们可以通过使用`du -sh ~/.cache/go-build/`检查其大小来验证缓存的大小是否显著增加。

1.  现在，我们可以使用 go clean 程序来清除缓存，即`go clean -cache -modcache -i -r 2&>/dev/null`。

需要注意的是，一些缓存信息存储在主要库中，因此普通用户无法删除。如果需要，我们可以通过以超级用户身份运行 clean 命令来绕过这个问题，但这通常不被推荐。

然后，我们可以验证缓存的大小是否减小。如果我们在清理后查看缓存目录，我们会发现缓存目录中只剩下三个项目：

+   一个解释目录的`README`文件。

+   有一个`log.txt`文件告诉我们有关缓存信息。

+   一个`trim.txt`文件，告诉我们上次完成缓存修剪的时间。在下面的截图中，我们可以看到一个清理后的构建缓存：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/hsn-hiperf-go/img/bd4592fa-bed5-483e-b348-d476141c9533.png)

验证构建的正确缓存将加快构建过程并使开发体验更加轻松。

在下一节中，我们将看一下`go get`和`go mod`命令。

# 使用 go get 和 go mod 检索包依赖项

在构建 Go 程序时，您可能会遇到希望添加依赖项的地方。`go get`下载并安装包及其依赖项。`go get`的调用语法是`go get [-d] [-f] [-t] [-u] [-v] [-fix] [-insecure] [build flags] [packages]`。

Go 1.11 增加了对 Go 模块的初步支持。我们在第六章中学习了如何在*Go 模块*部分中利用 Go 模块。

由于我们可以在我们的 Go 程序中使用打包的依赖项，因此 Go mod vendor 通常作为 Go 构建系统的一部分。在您的代码库中打包依赖项有积极和消极的方面。在构建时本地可用所有必需的依赖项可以加快构建速度。如果您用于构建依赖项的上游存储库发生更改或被删除，您将遇到构建失败。这是因为您的程序将无法满足其上游依赖项。

打包依赖项的消极方面包括，打包依赖项将使程序员负责保持包的最新状态 - 来自上游的更新，如安全更新、性能改进和稳定性增强可能会丢失，如果依赖项被打包而没有更新。

许多企业采用打包的方法，因为他们认为存储所有必需的依赖项的安全性胜过了需要从上游更新打包目录中的新包。

初始化 go 模块后，我们将我们的依赖项打包并使用我们的打包模块构建它们：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/hsn-hiperf-go/img/afb44250-21d2-4722-b549-e2200876aef3.png)

如前面的输出所示，我们有需要满足项目构建约束的依赖项（来自[`github.com/`](https://github.com/)和[`golang.org/`](https://golang.org/)）。我们可以在我们的构建中使用`go mod tidy`来验证`go.mod`是否包含了仓库的所有必要元素。

`go mod tidy`添加丢失的模块并删除未使用的模块，以验证我们的源代码与目录的`go.mod`匹配。

在接下来的部分中，我们将学习`go list`命令。

# Go list

`go list`执行列出命名的包和模块的操作，并显示有关文件、导入和依赖项的重要构建信息。`go list`的调用语法是`usage: go list [-f format] [-json] [-m] [list flags] [build flags] [packages]`。

拥有访问构建过程的主要数据结构的权限是强大的。我们可以使用`go list`来了解我们正在构建的程序的很多信息。例如，考虑以下简单的程序，它打印一条消息并为最终用户计算平方根：

```go
package main

import (
    "fmt"
    "math"
)

func main() {
    fmt.Println("Hello Gophers")
    fmt.Println(math.Sqrt(64))
}
```

如果我们想了解我们特定项目的所有依赖项，我们可以调用`go list -f '{{.Deps}}'`命令。

结果将是我们的存储库包含的所有依赖项的切片：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/hsn-hiperf-go/img/f971b2e1-767a-4219-a5a0-4e9adb984b7c.png)

`go list`数据结构可以在这里找到：[`golang.org/cmd/go/#hdr-List_packages_or_modules`](https://golang.org/cmd/go/#hdr-List_packages_or_modules)。它有许多不同的参数。从 go list 程序中得到的另一个流行输出是 JSON 格式的输出。在下面的截图中，您可以看到执行`go list -json`对我们的`listExample.go`的输出：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/hsn-hiperf-go/img/2057923f-07ed-46e1-8575-eda631d7289c.png)

`go list -m -u all`也会显示您的依赖项。如果它们有可用的升级，结果输出中还会列出第二个版本。如果我们想要密切监视我们的依赖项及其升级，使用`go mod`包可能会有所帮助。

如果我们使用我们的 Prometheus 导出器示例，我们可以看到我们的包是否有需要升级的依赖关系：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/hsn-hiperf-go/img/d12a5df1-df63-46d7-892f-46950cec2002.png)

在这个例子中，我们可以看到有几个包可以升级。如果我们为其中一个依赖项调用 go get，我们将能够有效地升级它们。我们可以使用`go get github.com/pkg/errors@v0.8.1`将前面截图中列出的 errors 包从 v0.8.0 升级到 v0.8.1。

完成这次升级后，我们可以通过运行`go list -m -u github.com/pkg/errors`来验证依赖项是否已经升级。

我们可以在下面的截图中看到这个输出：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/hsn-hiperf-go/img/67ab2f1e-f1ae-4815-81af-79a0079e09d2.png)

在我们之前的输出中，我们可以看到被引用的 errors 包现在是 v0.8.1，而不是我们之前输出中显示的 v0.8.0。

接下来，让我们看看`go run`是什么。

# Go run – 执行您的包

`go run`运行并编译一个命名的 Go 程序。`go run`的调用标准是`go run [build flags] [-exec xprog] package [arguments...]`。

Go run 允许开发人员快速编译和运行一个 go 二进制文件。在这个过程中，`go run`构建可执行文件，运行它，然后删除可执行文件。这在开发环境中特别有帮助。当您快速迭代您的 Go 程序时，`go run`可以用作一个快捷方式，以验证您正在更改的代码是否会产生您认为可以接受的构建产物。正如我们在本章前面学到的，许多这些工具的构建标志是一致的。

`goRun.go`是可能的 go 程序中最简单的一个。它没有参数，只是一个空的`main()`函数调用。我们使用这个作为一个例子，以展示这个过程没有额外的依赖或开销：

```go
package main 
func main() {}
```

我们可以通过执行`go run -x goRun.go`命令来看到与`go run`调用相关的工作输出。

当我们执行此操作时，我们将能够看到作为`go run`程序的一部分调用的构建参数：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/hsn-hiperf-go/img/9d4b103a-02c9-44da-aeeb-7bc01600dfff.png)

这应该看起来非常熟悉，因为输出与我们在 go build 示例中看到的输出非常相似。然后，我们可以看到我们的包被调用。

如果我们对我们的 Prometheus HTTP 服务器执行相同的操作，我们会看到我们的 Prometheus HTTP 服务器是通过执行`go run`程序启动和运行的。在这个 go run 调用期间杀死进程后，我们会注意到我们的本地目录中没有存储任何二进制文件。`go run`调用不会默认保存这些输出。

下一节中的 Go 命令（`go install`）是本章的最后一个命令。让我们看看它是什么。

# Go install – 安装您的二进制文件

`go install`编译并安装一个命名的 Go 程序。`go run`的调用标准是`go install [-i] [build flags] [packages]`。

这些被导入到`$GOPATH/pkg`。如果它们没有被修改，下次编译时将使用缓存的项目。go install 的结果输出是一个可执行文件，与使用 go build 命令编译的文件相同，安装在系统上的`$GOBIN`路径上。例如，如果我们想要在我们的主机上安装我们的 Prometheus HTTP 服务器，我们可以调用 go install 命令，即`GOBIN=~/prod-binaries/ go install -i prometheusExporterExample.go`。

设置我们的`GOBIN`变量告诉编译器在编译完成后安装编译后的二进制文件的位置。go install 程序允许我们将二进制文件安装到我们的`GOBIN`位置。`-i`标志安装命名包的依赖项。我们可以在以下截图中看到这一点：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/hsn-hiperf-go/img/a01089af-4fdb-4474-8777-e0b192bc60dd.png)

完成后，我们可以看到我们在示例中定义的`GOBIN`位置有一个`prometheusExporterExample`二进制文件可用。

在本章的即将到来的最后一节中，我们将看到如何使用 Docker 构建 Go 二进制文件。

# 使用 Docker 构建 Go 二进制文件

根据目标架构的不同，您可能希望使用 Docker 构建您的 Go 二进制文件，以保持可重现的构建，限制构建大小，并最小化服务的攻击向量。使用多阶段 Docker 构建可以帮助我们完成这项任务。

要执行这些操作，您必须安装最新版本的 Docker。我们将要使用的多阶段构建功能要求守护程序和客户端的 Docker 版本都为 17.05 或更高。您可以在[`docs.docker.com/install/`](https://docs.docker.com/install/)找到您的操作系统的最新版本的 Docker，以及安装说明。

考虑以下简单的包，它将一个调试消息记录到屏幕上：

```go
package main
import "go.uber.org/zap"
func main() {
  zapLogger: = zap.NewExample()
  defer zapLogger.Sync()
  zapLogger.Debug("Hi Gophers - from our Zap Logger")
}
```

如果我们想要在 Docker 容器中构建并执行它，同时最小化依赖关系，我们可以使用多阶段 Docker 构建。为此，我们可以执行以下步骤：

1.  通过执行以下操作将当前目录初始化为模块的根：

```go
go mod init github.com/bobstrecansky/HighPerformanceWithGo/11-deploying-go-code/multiStageDockerBuild
```

1.  通过执行以下命令添加`vendor`存储库：

```go
go mod vendor

```

现在我们的存储库中有所有必需的 vendor 包（在我们的情况下是 Zap 记录器）。可以在以下截图中看到：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/hsn-hiperf-go/img/ecffe0fa-4cd9-49b5-9571-2a7bf865bcc8.png)

1.  构建我们的`zapLoggerExample` Docker 容器。我们可以使用以下 Dockerfile 构建我们的容器：

```go
# Builder - stage 1 of 2
FROM golang:alpine as builder
COPY . /src
WORKDIR /src
RUN CGO_ENABLED=0 GOOS=linux go build -mod=vendor -o zapLoggerExample
# Executor - stage 2 of 2
FROM alpine:latest
WORKDIR /src/
COPY --from=builder /src/zapLoggerExample .
CMD ["./zapLoggerExample"]
```

请注意，我们使用`golang:alpine`镜像来构建 Go 二进制文件，因为它是包含成功构建我们的 Go 二进制文件所需的必要元素的最简单的 Docker 镜像之一。我们使用`alpine:latest`镜像来执行 Go 二进制文件，因为它是包含成功运行我们的 Go 二进制文件所需的必要元素的最简单的 Docker 镜像之一。

在这个 Dockerfile 示例中，我们使用多阶段 Docker 构建来构建和执行我们的二进制文件。在第 1 阶段（构建阶段）中，我们使用 golang alpine 镜像作为基础。我们将当前目录中的所有文件复制到 Docker 容器的`/src/`目录中，将`/src/`设置为我们的工作目录，并构建我们的 Go 二进制文件。禁用 cgo，为我们的 Linux 架构构建，并添加我们在*步骤 1*中创建的 vendor 目录都可以帮助减小构建大小和时间。

在第 2 阶段（执行器阶段）中，我们使用基本的 alpine Docker 镜像，将`/src/`设置为我们的工作目录，并将我们在第一阶段构建的二进制文件复制到这个 Docker 容器中。然后我们在这个 Docker 构建中执行我们的记录器作为最后的命令。

1.  在我们收集了必要的依赖项之后，我们可以构建我们的 Docker 容器。我们可以通过执行以下命令来完成这个过程：

```go
docker build -t zaploggerexample .
```

1.  构建完成后，我们可以通过执行以下命令来执行 Docker 容器：

```go
docker run -it --rm zaploggerexample
```

在以下截图中，您可以看到我们的构建和执行步骤已经完成：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/hsn-hiperf-go/img/b0fd4e02-76bb-4058-8114-b3679888ca84.png)

在多阶段 Docker 容器中构建我们的 Go 程序可以帮助我们创建可重复的构建，限制二进制文件大小，并通过仅使用我们需要的部分来最小化我们服务的攻击向量。

# 总结

在本章中，我们学习了如何构建 Go 二进制文件。我们学会了如何有效和永久地做到这一点。我们还学会了如何理解和管理依赖关系，使用`go run`测试 go 代码，并使用 go install 将 go 二进制文件安装到特定位置。了解这些二进制文件的工作原理将帮助您更有效地迭代您的代码。

在下一章中，我们将学习如何分析 Go 代码以找到功能瓶颈。


# 第十二章：Go 代码分析

分析是一种用于测量计算机系统中所使用资源的实践。通常进行分析以了解程序内的 CPU 或内存利用率，以便优化执行时间、大小或可靠性。在本章中，我们将学习以下内容：

+   如何使用`pprof`对 Go 中的请求进行分析

+   如何比较多个分析

+   如何阅读生成的分析和火焰图

进行分析将帮助您推断在函数内部可以进行哪些改进，以及在函数调用中个别部分所需的时间与整个系统相比有多少。

# 了解分析

对 Go 代码进行分析是确定代码基础中瓶颈所在的最佳方法之一。我们的计算机系统有物理限制（CPU 时钟速度、内存大小/速度、I/O 读/写速度和网络吞吐量等），但我们通常可以优化我们的程序，以更有效地利用我们的物理硬件。使用分析器对计算机程序进行分析后，将生成一份报告。这份报告通常称为分析报告，可以告诉您有关您运行的程序的信息。有许多原因可能会让您想了解程序的 CPU 和内存利用率。以下是一些例子：

CPU 性能分析的原因：

+   检查软件新版本的性能改进

+   验证每个任务使用了多少 CPU

+   限制 CPU 利用率以节省成本

+   了解延迟来自何处

内存分析的原因：

+   全局变量的不正确使用

+   未完成的 Goroutines

+   不正确的反射使用

+   大字符串分配

接下来我们将讨论探索仪器方法。

# 探索仪器方法

`pprof`工具有许多不同的方法来将分析纳入您的代码。Go 语言的创建者希望确保它在实现编写高性能程序所需的分析方面简单而有效。我们可以在 Go 软件开发的许多阶段实现分析，包括工程、新功能的创建、测试和生产。

重要的是要记住，分析确实会增加一些性能开销，因为在运行的二进制文件中会持续收集更多的指标。许多公司（包括谷歌）认为这种权衡是可以接受的。为了始终编写高性能代码，增加额外的 5%的 CPU 和内存分析开销是值得的。

# 使用 go test 实施分析

您可以使用`go test`命令创建 CPU 和内存分析。如果您想比较多次测试运行的输出，这可能很有用。这些输出通常会存储在长期存储中，以便在较长的日期范围内进行比较。要执行测试的 CPU 和内存分析，请执行`go test -cpuprofile /tmp/cpu.prof -memprofile /tmp/mem.prof -bench`命令。

这将创建两个输出文件，`cpu.prof`和`mem.prof`，它们都将存储在`/tmp/`文件夹中。稍后在本章的*分析分析*部分中可以使用这些生成的分析。

# 在代码中手动进行仪器分析

如果您想特别对代码中的特定位置进行分析，可以直接在该代码周围实施分析。如果您只想对代码的一小部分进行分析，如果您希望`pprof`输出更小更简洁，或者如果您不想通过在已知的昂贵代码部分周围实施分析来增加额外开销，这可能特别有用。对代码基础的不同部分进行 CPU 和内存分析有不同的方法。

对特定代码块进行 CPU 利用率分析如下：

```go
function foo() {
pprof.StartCPUProfile()
defer pprof.StopCPUProfile()
...
code
...
}
```

对特定代码块进行内存利用率分析如下：

```go
function bar() {
runtime.GC()
defer pprof.WriteHeapProfile()
...
code
...
}
```

希望，如果我们设计有效，迭代有影响，并且使用下一节中的习语实现我们的分析，我们就不必实现代码的各个部分，但知道这始终是分析代码和检索有意义输出的潜在选择是很好的。

# 分析运行服务代码

在 Go 代码中实施分析的最常用方法是在 HTTP 处理程序函数中启用分析器。这对于调试实时生产系统非常有用。能够实时分析生产系统让您能够基于真实的生产数据做出决策，而不是基于您的本地开发环境。

有时，错误只会在特定规模的数据达到特定规模时发生。一个可以有效处理 1,000 个数据点的方法或函数，在其基础硬件上可能无法有效处理 1,000,000 个数据点。这在运行在不断变化的硬件上尤为重要。无论您是在具有嘈杂邻居的 Kubernetes 上运行，还是在具有未知规格的新物理硬件上运行，或者使用代码或第三方库的新版本，了解更改的性能影响对于创建可靠性和弹性至关重要。

能够从生产系统接收数据，其中您的最终用户及其数据的数量级可能大于您在本地使用的数量级，可以帮助您进行性能改进，影响最终用户，这可能是您在本地迭代时从未发现的。 

如果我们想在我们的 HTTP 处理程序中实现`pprof`库，我们可以使用`net/http/pprof`库。这可以通过将`_ "net/http/pprof"`导入到您的主包中来完成。

然后，您的 HTTP 处理程序将为您的分析注册 HTTP 处理程序。确保您不要在公开的 HTTP 服务器上执行此操作；您的程序概要会暴露一些严重的安全漏洞。`pprof`包的索引显示了在使用此包时可用的路径。以下是`pprof`工具索引的屏幕截图：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/hsn-hiperf-go/img/f6f83adb-86ca-49aa-83a5-38ed0d43d3dc.png)

我们可以查看公开的 HTTP `pprof`路径及其描述。路径和相关描述可以在以下表中找到：

| **名称** | **HTTP 路径** | **描述** |
| --- | --- | --- |
| `allocs` | `/debug/pprof/allocs` | 内存分配信息。 |
| `block` | `/debug/pprof/block` | Goroutines 阻塞等待的信息。这通常发生在同步原语上。 |
| `cmdline` | `/debug/pprof/cmdline` | 我们二进制命令行调用的值。 |
| `goroutine` | `/debug/pprof/goroutine` | 当前正在运行的 goroutines 的堆栈跟踪。 |
| `heap` | `/debug/pprof/heap` | 内存分配采样（用于监视内存使用和泄漏）。 |
| `mutex` | `/debug/pprof/mutex` | 有争议的互斥锁堆栈跟踪。 |
| `profile` | `/debug/pprof/profile` | CPU 概要。 |
| `symbol` | `/debug/pprof/symbol` | 请求程序计数器。 |
| `threadcreate` | `/debug/pprof/threadcreate` | 操作系统线程创建堆栈跟踪。 |
| `trace` | `/debug/pprof/trace` | 当前程序跟踪。这将在第十三章中深入讨论，*跟踪 Go 代码*。 |

在下一节中，我们将讨论 CPU 分析。

# CPU 分析简介

让我们对一个简单的 Go 程序执行一些示例分析，以了解分析器的工作原理。我们将创建一个带有一些休眠参数的示例程序，以便查看不同函数调用的时间：

1.  首先，我们实例化我们的包并添加所有导入：

```go
import (
    "fmt"
    "io"
    "net/http"
    _ "net/http/pprof"
    "time"
)
```

1.  接下来，在我们的`main`函数中，我们有一个 HTTP 处理程序，其中包含两个休眠函数，作为处理程序的一部分调用：

```go
func main() {
    Handler := func(w http.ResponseWriter, req *http.Request) {
        sleep(5)
        sleep(10)
        io.WriteString(w, "Memory Management Test")
    }
    http.HandleFunc("/", Handler)
    http.ListenAndServe(":1234", nil)
}
```

我们的`sleep`函数只是睡眠了一段特定的毫秒数，并打印出结果输出：

```go
func sleep(sleepTime int) {
    time.Sleep(time.Duration(sleepTime) * time.Millisecond)
    fmt.Println("Slept for ", sleepTime, " Milliseconds")
}
```

1.  当我们运行我们的程序时，我们看到输出`go run httpProfiling.go`。要从这个特定的代码生成概要文件，我们需要调用`curl -s "localhost:1234/debug/pprof/profile?seconds=10" > out.dump`。这将运行一个 10 秒钟的概要文件，并将结果返回到一个名为`out.dump`的文件中。默认情况下，`pprof`工具将运行 30 秒，并将二进制文件返回到`STDOUT`。我们要确保我们限制这个测试的时间，以便测试持续时间合理，并且我们需要重定向输出，以便能够捕获一些有意义的内容在我们的分析工具中查看。

1.  接下来，我们为我们的函数生成一个测试负载。我们可以使用 Apache Bench 来完成这个任务，生成 5,000 个并发为 10 的请求；我们使用`ab -n 5000 -c 10 http://localhost:1234/`来设置这个。

1.  一旦我们得到了这个测试的输出，我们可以查看我们的`out.dump`文件，`go tool pprof out.dump`。这将带您进入分析器。这是 C++分析器`pprof`的一个轻微变体。这个工具有相当多的功能。

1.  我们可以使用`topN`命令查看概要文件中包含的前*N*个样本，如下图所示：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/hsn-hiperf-go/img/2559344c-6b24-4454-88e5-f3b963485d80.png)

在执行分析器时，Go 程序大约每秒停止 100 次。在此期间，它记录 goroutine 堆栈上的程序计数器。我们还可以使用累积标志`(-cum)`，以便按照我们当前概要文件采样中的累积值进行排序：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/hsn-hiperf-go/img/e0b8c731-8d0f-4b85-ae22-87ef49d77237.png)

1.  我们还可以显示跟踪的可视化图形表示形式。确保安装了`graphviz`包（它应该包含在您的包管理器中，或者可以从[`www.graphviz.org/`](http://www.graphviz.org/)下载，只需键入`web`命令）

这将为我们提供一个从我们的程序内生成的概要文件的可视化表示：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/hsn-hiperf-go/img/f4b4289d-63a6-459f-817e-fd642cceee4c.png)

概要文件中的红色框表示对请求流最有影响的代码路径。我们可以查看这些框，并且正如我们所期望的那样，我们可以看到我们的示例程序中有相当多的时间用于睡眠和向客户端写回响应。我们可以通过传递我们想要查看的函数的名称来以相同的 web 格式查看这些特定函数。例如，如果我们想要查看我们的`sleep`函数的详细视图，我们只需键入`(pprof) web sleep`命令。

1.  然后我们将获得一个以睡眠调用为焦点的 SVG 图像：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/hsn-hiperf-go/img/66241c91-a271-45ea-8575-4766a652208d.png)

1.  在我们得到这个分解之后，我们可能想要查看睡眠函数实际执行了什么。我们可以使用`pprof`中的`list`命令，以便获得对`sleep`命令及其后续调用的调用进行分析的输出。以下屏幕截图显示了这一点；为了简洁起见，代码被缩短了：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/hsn-hiperf-go/img/89c2dac7-abe2-414f-9738-993f76fafc9a.png)

通过对我们正在进行的工作进行分析并将其分解为可分段的块，可以告诉我们很多关于我们需要从利用角度采取的开发方向。

在下一节中，我们将看到内存分析是什么。

# 内存分析简介

我们可以对内存执行与我们在上一节中对 CPU 测试相似的操作。让我们看看另一种处理分析的方法，使用测试功能。让我们使用我们在第二章中创建的例子，*数据结构和算法*中的`o-logn`函数。我们可以使用我们已经为这个特定函数创建的基准，并为这个特定的测试添加一些内存分析。我们可以执行`go test -memprofile=heap.dump -bench`命令。

我们将看到与我们在第二章中看到的类似的输出，*数据结构和算法*：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/hsn-hiperf-go/img/6e4f4592-7126-4df9-9b54-48cc7363664b.png)

唯一的区别是现在我们将从这个测试中得到堆剖析。如果我们用分析器查看它，我们将看到关于堆使用情况的数据，而不是 CPU 使用情况。我们还将能够看到该程序中每个函数的内存分配情况。以下图表说明了这一点：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/hsn-hiperf-go/img/0addac7e-6218-4608-8628-cad13ac28e26.png)

这很有帮助，因为它使我们能够看到代码中每个部分生成的堆大小。我们还可以查看累积内存分配的前几名：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/hsn-hiperf-go/img/df629a1d-7502-4fba-88f8-41e8e3219e28.png)

随着我们的程序变得更加复杂，理解内存利用情况变得越来越重要。在下一节中，我们将讨论如何通过上游`pprof`扩展我们的分析能力。

# 上游 pprof 的扩展功能

如果我们想要默认使用额外的功能，我们可以使用上游的`pprof`二进制文件来扩展我们的分析视图：

1.  我们可以通过调用`go get github.com/google/pprof`来获取这个。`pprof`工具有几种不同的调用方法。我们可以使用报告生成方法来生成所请求格式的文件（目前支持`.dot`、`.svg`、`.web`、`.png`、`.jpg`、`.gif`和`.pdf`格式）。我们还可以像在前几节关于 CPU 和内存分析中所做的那样，使用交互式终端格式。最后，最常用的方法是使用 HTTP 服务器。这种方法涉及在一个易于消化的格式中托管包含大部分相关输出的 HTTP 服务器。

1.  一旦我们通过`go get`获取了二进制文件，我们可以使用 web 界面调用它，查看我们之前生成的输出：`pprof -http=:1234 profile.dump`。

1.  然后我们可以访问新提供的 UI，看看默认的`pprof`工具中没有内置的功能和功能。这个工具提供的一些关键亮点如下：

+   一个正则表达式可搜索的表单字段，以帮助搜索必要的分析元素

+   一个下拉式视图菜单，方便查看不同的分析工具

+   一个样本下拉菜单，显示来自剖析的样本

+   一个细化的过滤器，用于隐藏/显示请求流的不同部分

拥有所有这些工具来进行分析有助于使分析过程更加流畅。如果我们想要查看运行任何带有`fmt`名称的调用所花费的时间，我们可以使用带有正则表达式过滤器的示例视图，它将突出显示`fmt`调用，正如我们在下面的截图中所看到的那样：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/hsn-hiperf-go/img/dd1b454e-ebb1-4ded-aaa4-a57165b00f4a.png)

根据这些值进行过滤可以帮助缩小性能不佳函数的范围。

# 比较多个分析

分析的一个非常好的特性是可以将不同的分析进行比较。如果我们从同一个程序中有两个单独的测量，我们可以确定我们所做的更改是否对系统产生了积极的影响。让我们稍微改进一下我们的 HTTP 睡眠定时函数：

1.  让我们添加一些额外的导入：

```go
package main

import (
  "fmt"
  "net/http"
  _ "net/http/pprof"
  "strconv"
  "time"
)
```

1.  接下来，我们将增强我们的处理程序以接受`time`的查询字符串参数：

```go
func main() { 
    Handler := func(w http.ResponseWriter, r *http.Request) {
        sleepDuration := r.URL.Query().Get("time")
        sleepDurationInt, err := strconv.Atoi(sleepDuration)
        if err != nil {
            fmt.Println("Incorrect value passed as a query string for time")
            return
        }
        sleep(sleepDurationInt)
        fmt.Fprintf(w, "Slept for %v Milliseconds", sleepDuration)
    } 
    http.HandleFunc("/", Handler)
    http.ListenAndServe(":1234", nil)
}
```

1.  我们将保持我们的睡眠函数完全相同：

```go
func sleep(sleepTime int) {
    time.Sleep(time.Duration(sleepTime) * time.Millisecond)
    fmt.Println("Slept for ", sleepTime, " Milliseconds")
}
```

1.  现在我们有了这个额外的功能，我们可以通过向我们的 HTTP 处理程序传递查询参数来使用不同时间进行多个配置文件的采集：

+   我们可以运行我们的新定时配置工具：

```go
go run timedHttpProfiling.go
```

1.  +   在另一个终端中，我们可以启动我们的配置工具：

```go
curl -s "localhost:1234/debug/pprof/profile?seconds=20" > 5-millisecond-profile.dump
```

1.  +   然后我们可以对我们的新资源进行多次请求：

```go
ab -n 10000 -c 10 http://localhost:1234/?time=5
```

1.  +   然后我们可以收集第二个配置文件：

```go
curl -s "localhost:1234/debug/pprof/profile?seconds=20" > 10-millisecond-profile.dump
```

1.  +   然后我们对我们的新资源进行第二次请求，生成第二个配置文件：

```go
ab -n 10000 -c 10 http://localhost:1234/?time=10
```

1.  现在我们有两个单独的配置文件，分别存储在`5-millisecond-profile.dump`和`10-millisecond-profile.dump`中。我们可以使用与之前相同的工具进行比较，设置一个基本配置文件和一个次要配置文件。以下截图说明了这一点：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/hsn-hiperf-go/img/fa125aa7-f40e-4fcc-b0f1-f7de7862cb9b.png)

比较配置文件可以帮助我们了解变化如何影响我们的系统。

让我们继续下一节的火焰图。

# 解释 pprof 中的火焰图

在上游`pprof`包中最有帮助/有用的工具之一是火焰图。火焰图是一种固定速率采样可视化，可以帮助确定配置文件中的热代码路径。随着您的程序变得越来越复杂，配置文件变得越来越大。往往很难知道到底哪段代码路径占用了最多的 CPU，或者我经常称之为*帐篷中的长杆*。

火焰图最初是由 Netflix 的 Brendan Gregg 开发的，用于解决 MySQL 的 CPU 利用率问题。这种可视化的出现帮助许多程序员和系统管理员确定程序中延迟的来源。`pprof`二进制文件生成一个 icicle-style（火焰向下指）火焰图。在火焰图中，我们有特定帧中的数据可视化。

+   *x*轴是我们请求的所有样本的集合

+   y 轴显示了堆栈上的帧数，通常称为堆栈深度

+   方框的宽度显示了特定函数调用使用的总 CPU 时间

这三个东西一起可视化有助于确定程序的哪一部分引入了最多的延迟。您可以访问`pprof`配置文件的火焰图部分，网址为`http://localhost:8080/ui/flamegraph`。以下图片显示了一个火焰图的示例：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/hsn-hiperf-go/img/8be26f48-4577-485d-999c-888ddc547d29.png)

如果我们看看第二章中的`bubbleSort`示例，*数据结构和算法*，我们可以看到在我们的测试中占用 CPU 时间的不同部分。在交互式网络模式中，我们可以悬停在每个样本上，并验证它们的持续时间和百分比执行时间。

在接下来的部分中，我们将看到如何检测 Go 中的内存泄漏。

# 检测 Go 中的内存泄漏

正如第八章中*Go 内存管理*部分所讨论的，我们有很多工具可以查看当前正在执行的程序的内存统计信息。在本章中，我们还将学习使用 pprof 工具进行配置文件。Go 中更常见的内存泄漏之一是无限创建 goroutine。当您过载一个非缓冲通道或者有一个具有大量并发生成新 goroutine 的抽象时，这种情况经常发生。Goroutine 的占用空间非常小，系统通常可以生成大量的 goroutine，但最终会有一个上限，在生产环境中调试程序时很难找到。

在下面的示例中，我们将查看一个有泄漏抽象的非缓冲通道：

1.  我们首先初始化我们的包并导入我们需要的依赖项：

```go
package main

import (
 "fmt"
 "net/http"

 _ "net/http/pprof"                                                                   
 "runtime"
 "time"
)
```

1.  在我们的主函数中，我们处理 HTTP 监听和为`leakyAbstraction`函数提供服务。我们通过 HTTP 提供这个服务，以便简单地看到 goroutines 的数量增长：

```go
func main() {
 http.HandleFunc("/leak", leakyAbstraction)
 http.ListenAndServe("localhost:6060", nil)
}  
```

1.  在我们的`leakyAbstraction`函数中，我们首先初始化一个无缓冲的字符串通道。然后我们通过一个 for 循环无休止地迭代，将 goroutines 的数量写入 HTTP 响应写入器，并将我们的`wait()`函数的结果写入通道：

```go
func leakyAbstraction(w http.ResponseWriter, r *http.Request) {
 ch := make(chan string)                                                                

 for {
   fmt.Fprintln(w, "Number of Goroutines: ", runtime.NumGoroutine())
   go func() { ch <- wait() }()
 }          
}
```

1.  我们的`wait()`函数休眠五微秒并返回一个字符串：

```go
func wait() string {
 time.Sleep(5 * time.Microsecond)
 return "Hello Gophers!"
}
```

这些函数一起将生成 goroutines，直到运行时不再能够这样做并死亡。我们可以通过执行以下命令来测试这一点：

```go
go run memoryLeak.go
```

服务器运行后，在一个单独的终端窗口中，我们可以使用以下命令向服务器发出请求：

```go
curl localhost:6060/leak
```

`curl`命令将打印生成的 goroutines 数量，直到服务器被关闭：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/hsn-hiperf-go/img/e971d565-e6a6-4825-980c-71da2d27ecba.png)

请注意，根据您系统的规格，此请求可能需要一段时间。这没关系——它说明了您的程序可用于使用的 goroutines 数量。

使用我们在本章学到的技术，我们将能够进一步调试类似这样的内存问题，但理解潜在的问题将帮助我们避免内存问题。

这个例子是为了明确展示内存泄漏，但如果我们想要使这个可执行文件不泄漏 goroutines，我们需要修复两件事：

+   我们的无限循环很可能应该有一个限制

+   我们可以添加一个带缓冲的通道，以确保我们有能力处理通过通道进入的所有生成的 goroutines

# 总结

在本章中，我们学习了关于 profiles 的知识——profiles 是什么，以及如何使用`pprof`生成 profiles。您还学会了如何使用不同的方法分析 profiles，如何比较 profiles，以及如何阅读性能的火焰图。能够在生产环境中执行这个操作将帮助您保持稳定，提高性能，并为最终用户提供更好的用户体验。在下一章中，我们将讨论另一种分析代码的方法——跟踪。


# 第十三章：跟踪 Go 代码

跟踪 Go 程序是检查 Go 程序中函数和服务之间的互操作性的一种绝妙方式。跟踪允许您通过系统传递上下文，并评估您被阻止的位置，无论是由第三方 API 调用、缓慢的消息队列还是*O*(*n*²)函数。跟踪将帮助您找到这个瓶颈所在。在本章中，我们将学习以下内容：

+   实施跟踪的过程

+   使用跟踪进行采样的过程

+   解释跟踪的过程

+   比较跟踪的过程

能够实施跟踪并解释结果将帮助开发人员理解和排除故障他们的分布式系统。

# 实施跟踪仪器

Go 的并发模型使用 goroutines，非常强大。高并发的一个缺点是，当您尝试调试高并发模型时，您会遇到困难。为了避免这种困难，语言创建者创建了`go tool trace`。然后他们在 Go 版本 1.5 中分发了这个工具，以便能够调查和解决并发问题。Go 跟踪工具钩入 goroutine 调度程序，以便能够提供有关 goroutines 的有意义信息。您可能希望使用 Go 跟踪调查的一些实现细节包括以下内容：

+   延迟

+   资源争用

+   并行性差

+   与 I/O 相关的事件

+   系统调用

+   通道

+   锁

+   **垃圾收集** (**GC**)

+   Goroutines

解决所有这些问题将帮助您构建一个更具弹性的分布式系统。在下一节中，我们将讨论跟踪格式以及它如何适用于 Go 代码。

# 理解跟踪格式

Go 跟踪可以提供大量信息，并且可以捕获大量请求每秒。因此，跟踪以二进制格式捕获。跟踪输出的结构是静态的。在以下输出中，我们可以看到跟踪遵循特定的模式-它们被定义，并且事件被用十六进制前缀和有关特定跟踪事件的一些信息进行分类。查看这个跟踪格式将帮助我们理解我们的跟踪事件如何存储和如何使用 Go 团队为我们提供的工具检索：

```go
Trace = "gotrace" Version {Event} .

Event = EventProcStart | EventProcStop | EventFreq | EventStack | EventGomaxprocs | EventGCStart | EventGCDone | EventGCScanStart | EventGCScanDone | EventGCSweepStart | EventGCSweepDone | EventGoCreate | EventGoStart | EventGoEnd | EventGoStop | EventGoYield | EventGoPreempt | EventGoSleep | EventGoBlock | EventGoBlockSend | EventGoBlockRecv | EventGoBlockSelect | EventGoBlockSync | EventGoBlockCond | EventGoBlockNet | EventGoUnblock | EventGoSysCall | EventGoSysExit | EventGoSysBlock | EventUser | EventUserStart | EventUserEnd .

EventProcStart = "\x00" ProcID MachineID Timestamp .
EventProcStop = "\x01" TimeDiff .
EventFreq = "\x02" Frequency .
EventStack = "\x03" StackID StackLen {PC} .
EventGomaxprocs = "\x04" TimeDiff Procs .
EventGCStart = "\x05" TimeDiff StackID .
EventGCDone = "\x06" TimeDiff .
EventGCScanStart= "\x07" TimeDiff .
EventGCScanDone = "\x08" TimeDiff .
EventGCSweepStart = "\x09" TimeDiff StackID .
EventGCSweepDone= "\x0a" TimeDiff .
EventGoCreate = "\x0b" TimeDiff GoID PC StackID .
EventGoStart = "\x0c" TimeDiff GoID .
EventGoEnd = "\x0d" TimeDiff .
EventGoStop = "\x0e" TimeDiff StackID .
EventGoYield = "\x0f" TimeDiff StackID .
EventGoPreempt = "\x10" TimeDiff StackID .
EventGoSleep = "\x11" TimeDiff StackID .
EventGoBlock = "\x12" TimeDiff StackID .
EventGoBlockSend= "\x13" TimeDiff StackID .
EventGoBlockRecv= "\x14" TimeDiff StackID .
EventGoBlockSelect = "\x15" TimeDiff StackID .
EventGoBlockSync= "\x16" TimeDiff StackID .
EventGoBlockCond= "\x17" TimeDiff StackID .
EventGoBlockNet = "\x18" TimeDiff StackID .
EventGoUnblock = "\x19" TimeDiff GoID StackID .
EventGoSysCall = "\x1a" TimeDiff StackID .
EventGoSysExit = "\x1b" TimeDiff GoID .
EventGoSysBlock = "\x1c" TimeDiff .
EventUser = "\x1d" TimeDiff StackID MsgLen Msg .
EventUserStart = "\x1e" TimeDiff StackID MsgLen Msg .
EventUserEnd = "\x1f" TimeDiff StackID MsgLen Msg .
```

有关 Go 执行跟踪器的更多信息可以在 Dmitry Vyukov 发布的原始规范文档中找到[`docs.google.com/document/u/1/d/1FP5apqzBgr7ahCCgFO-yoVhk4YZrNIDNf9RybngBc14/pub`](https://docs.google.com/document/u/1/d/1FP5apqzBgr7ahCCgFO-yoVhk4YZrNIDNf9RybngBc14/pub)。

能够看到跟踪的所有这些元素将帮助我们理解如何将跟踪分解为原子块。在下一节中，我们将讨论跟踪收集。

# 理解跟踪收集

能够收集跟踪是实施分布式系统中跟踪的重要部分。如果我们不在某个地方汇总这些跟踪，我们将无法在规模上理解它们。我们可以使用三种方法收集跟踪数据：

+   通过调用`trace.Start`和`trace.Stop`手动调用数据的跟踪

+   使用测试标志`-trace=[OUTPUTFILE]`

+   对`runtime/trace`包进行仪器化

为了了解如何在代码周围实施跟踪，让我们看一个简单的示例程序：

1.  我们首先实例化我们的包并导入必要的包：

```go
package main

import (
    "os"
    "runtime/trace"
)
```

1.  然后我们调用我们的`main`函数。我们将跟踪输出写入一个名为`trace.out`的文件，稍后我们将使用它：

```go
func main() {

    f, err := os.Create("trace.out")
    if err != nil {
        panic(err)
    } 

    defer f.Close()
```

1.  接下来，我们实现我们想要在程序中使用的跟踪，并在函数返回时推迟跟踪的结束：

```go
    err = trace.Start(f)
    if err != nil {
        panic(err)
    } 

    defer trace.Stop()
```

1.  然后我们编写我们想要实现的代码。我们这里的示例只是在匿名函数中通过通道简单地传递字符串`"Hi Gophers"`：

```go
    ch := make(chan string)
    go func() {
        ch <- "Hi Gophers"
    }()
    <-ch
}
```

现在我们已经在我们的（诚然简单的）程序周围实施了跟踪，我们需要执行我们的程序以产生跟踪输出：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/hsn-hiperf-go/img/e1bc51c4-054c-4a88-9e51-22e14d29dcc6.png)

1.  要查看跟踪，您可能需要安装额外的软件包。对于我正在测试的 Fedora 系统，我不得不安装额外的 `golang-misc` 软件包：`sudo dnf install golang-misc`。

1.  创建跟踪后，您可以使用 `go tool trace trace.out` 命令打开您创建的跟踪。

这使您可以启动将提供跟踪输出的 HTTP 服务器。我们可以在下面的截图中看到这个输出：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/hsn-hiperf-go/img/b54e468f-f12c-4783-afa8-7158f541f7e1.png)

我们可以在 Chrome 浏览器中看到生成的跟踪输出。重要的是要提到，我们需要使用兼容的浏览器，即 Chrome。在撰写本书时，Firefox 会产生一个空白页面的跟踪输出。这是在 Chrome 浏览器中的跟踪输出：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/hsn-hiperf-go/img/2cb0717a-8035-40ef-8f40-549a81db2ea7.png)

这个 HTML 页面为您提供了许多不同的有用输出选择。让我们逐个在下表中查看它们：

| 链接 | 描述 |
| --- | --- |
| 查看跟踪 | 查看 GUI 跟踪输出。 |
| Goroutine 分析 | 显示不同的 goroutine 信息。 |
| 网络阻塞概要 | 显示网络阻塞；可以创建单独的概要。 |
| 同步阻塞概要 | 显示同步阻塞；可以创建单独的概要。 |
| 系统调用阻塞概要 | 显示系统调用阻塞；可以创建单独的概要。 |
| 调度器延迟概要 | 显示与调度器相关的所有延迟；可以创建单独的概要。 |
| 用户定义的任务 | 允许查看任务数据类型；用于跟踪用户定义的逻辑操作。这是使用格式 `trace.NewTask()` 调用的。 |
| 用户定义的区域 | 允许查看区域数据类型；用于跟踪代码区域。这是使用格式 `trace.WithRegion()` 调用的。 |
| 最小 mutator 利用率 | 创建一个可视化图表，显示垃圾收集器从程序中窃取工作的位置和时间。这有助于您了解您的生产服务是否受到 GC 的限制。 |

我们可以先在网页浏览器中查看跟踪：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/hsn-hiperf-go/img/edd1f3d9-8df0-4a17-bbe4-f0c54cd30120.png)

当我们查看这些跟踪时，我们可以做的第一件事是查看帮助菜单，它位于屏幕右上角的问号框中。这个信息菜单为我们提供了有关跟踪工具能力的许多描述：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/hsn-hiperf-go/img/8172c4c6-9077-4281-a9a6-f7f0ad7a4991.png)

能够快速有效地在跟踪窗口中移动将帮助您快速查看跟踪。当您试图快速解决生产问题时，这可能非常有帮助。

# 跟踪窗口中的移动

使用经典的 *WASD* 移动键（受到许多第一人称角色扮演视频游戏的启发），我们可以在跟踪中移动。移动键的描述如下：

+   按下 *W* 键，可以放大跟踪的时间窗口。

+   按下 *S* 键缩小。

+   按下 *A* 键向后移动时间。

+   按下 *D* 键向前移动时间。我们也可以通过点击和拖动鼠标向前和向后移动时间。

使用鼠标指针选择器或点击数字键可以操作时间信息。键盘更改列在以下项目符号中：

+   按下 *1* 键让我们选择要检查的跟踪部分

+   按下 *2* 键可以平移

+   按下 *3* 键调用放大功能

+   按下 *4* 键可以选择特定的时间

现在我们可以使用 */* 键搜索跟踪，使用 *Enter* 键浏览结果。

我们还有文件大小统计、指标、帧数据和右侧屏幕上可用的输入延迟窗口。单击这些按钮将打开一个弹出窗口，告诉您有关跟踪中每个特定统计信息的更多细节。

如果我们在跟踪中的 goroutines 行中点击蓝色区域，我们可以查看一些我们的 goroutines 可用统计信息：

+   `GCWaiting`，即正在等待的垃圾收集运行数量（当前值为 0）

+   当前可运行的 goroutines 数量为 1

+   当前正在运行的 goroutines 数量为 1

我们可以在以下截图中看到我们的 goroutines 的可用统计信息：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/hsn-hiperf-go/img/f2a6c91a-b495-44e7-b78c-7bb9c4065b31.png)

goroutine 信息对于最终用户调试程序可能有所帮助。在 Go 跟踪工具中观察 goroutines 可以帮助我们确定 goroutine 何时在争用。它可能正在等待通道清除，可能被系统调用阻塞，或者可能被调度程序阻塞。如果有许多 goroutines 处于等待状态，这意味着程序可能创建了太多的 goroutines。这可能导致调度程序被过度分配。拥有所有这些信息可以帮助我们做出明智的决定，以更有效地编写程序来利用 goroutines。

单击堆行中的橙色条将显示堆信息：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/hsn-hiperf-go/img/04865725-43d9-47f1-86f3-2b84abe7321a.png)

在所选时间（0.137232）时，我们可以看到我们的堆分配了 425984 字节，或大约 425 KB。了解当前分配给堆的内存量可以告诉我们我们的程序是否存在内存争用。剖析（正如我们在第十二章中学到的，*Go 代码的剖析*）通常是查看堆信息的更好方法，但在跟踪上下文中对分配有一个一般的了解通常是有帮助的。

接下来我们可以查看线程信息。单击跟踪中线程行中的活动线程（跟踪的 Threads 行中的洋红色块）将显示处于 InSyscall 和 Running 状态的线程数量：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/hsn-hiperf-go/img/4d9b9579-f430-4d23-a18c-31aa5a04a684.png)

了解正在运行的 OS 线程数量以及当前有多少个线程被系统调用阻塞可能会有所帮助。

接下来，我们可以查看正在运行的每个单独进程。单击进程将显示以下截图中显示的所有详细信息。如果将鼠标悬停在跟踪底部窗格中的事件之一上，您将能够看到进程如何相互关联，如以下截图中的红色箭头所示：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/hsn-hiperf-go/img/f84eef16-2487-4c23-97a0-917f9475ce61.png)

了解您的进程的端到端流程通常可以帮助您诊断问题进程。在下一节中，我们将学习如何探索类似 pprof 的跟踪。

# 探索类似 pprof 的跟踪

Go 工具跟踪也可以生成四种不同类型的跟踪，这可能与您的故障排除需求相关：

+   `net`：一个网络阻塞配置文件

+   `sync`：一个同步阻塞的配置文件

+   `syscall`：一个系统调用阻塞配置文件

+   `sched`：一个调度器延迟配置文件

让我们看看如何在 Web 服务器上使用这些跟踪配置文件的示例：

1.  首先，我们初始化我们的`main`并导入必要的包。请注意，对于`_ "net/http/pprof"`中的显式包名称，使用了空白标识符。这是为了确保我们可以进行跟踪调用：

```go
package main

import (
    "io"
    "net/http"
    _ "net/http/pprof"
    "time"
)

```

1.  接下来，我们设置一个简单的 Web 服务器，等待五秒钟并向最终用户返回一个字符串：

```go
func main() {

   handler := func(w http.ResponseWriter, req *http.Request) {
       time.Sleep(5 * time.Second)
       io.WriteString(w, "Network Trace Profile Test")
    }

    http.HandleFunc("/", handler)
    http.ListenAndServe(":1234", nil)
}
```

1.  在执行`go run netTracePprof.go`后运行服务器后，我们可以进行跟踪：`curl localhost:1234/debug/pprof/trace?seconds=10 > trace.out`。我们可以在以下截图中看到我们的`curl`的输出：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/hsn-hiperf-go/img/fee7866d-9776-4db5-87da-bbd466be6431.png)

1.  同时，在另一个终端中，我们可以对我们示例的 Web 服务器的`/`路径进行请求：`curl localhost:1234/`。然后我们将在运行跟踪的目录中返回一个`trace.out`文件。然后我们可以使用`go tool trace trace.out`打开我们的跟踪。然后我们将看到我们的跟踪结果。在生成的 HTTP 页面中利用网络阻塞配置文件，我们可以看到网络阻塞配置文件的跟踪：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/hsn-hiperf-go/img/57aa695e-104a-4342-b378-462014acf963.png)

正如预期的那样，我们看到了五秒的等待，因为这是我们为这个特定的 web 请求在处理程序函数中添加的等待时间。如果我们愿意，我们可以下载这个配置文件，并在我们在第十二章中讨论的上游`pprof`工具中查看它，*Go 代码性能分析*。在跟踪 HTML 窗口中，有一个下载按钮，旁边是 web 配置文件：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/hsn-hiperf-go/img/7657e853-acb9-4f88-bcf3-f34514fd2bf7.png)

在我们下载了这个配置文件之后，我们可以使用我们在第十二章中安装的上游`pprof`工具来查看它，*Go 代码性能分析*：

```go
$ pprof -http=:1235 ~/Downloads/io.profile
```

然后我们可以看一下火焰图：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/hsn-hiperf-go/img/c94a6a96-e73e-40c0-9336-c38e26c70822.png)

我们可以在以下截图中看到 peek UI：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/hsn-hiperf-go/img/598d77a6-10b2-4875-bd88-1b41b5549789.png)

火焰图和 peek UI 都有助于使这些复杂的调试视图变得更加简洁。在下一节中，我们将看到 Go 中的分布式跟踪是什么。

# Go 分布式跟踪

为 Go 程序实现和调查单个跟踪可能是一项富有成效的工作，可以提供大量关于导致我们程序请求的数据的输出。随着企业拥有越来越多的分布式代码库，以及更多相互操作的复杂调用，追踪单个调用在长期内变得不可行。有两个项目试图帮助 Go 进行分布式跟踪，它们分别是 OpenCensus Go 库和 OpenTelemetry 库：

+   `opencensus-go`: [`github.com/census-instrumentation/opencensus-go`](https://github.com/census-instrumentation/opencensus-go)

+   `opentracing-go`: [`github.com/opentracing/opentracing-go`](https://github.com/opentracing/opentracing-go)

这些项目的维护者已决定将这两个项目合并，并开始在一个名为 OpenTelemetry 的代码库上进行工作。这个新的代码库将允许在许多语言和基础设施中简化集成分布式跟踪。您可以在[`github.com/open-telemetry/opentelemetry-go`](https://github.com/open-telemetry/opentelemetry-go)了解更多关于 OpenTelemetry 的 Go 实现。

在撰写本书时，OpenTelemetry 尚未准备好供生产使用。OpenTelemetry 将向后兼容 OpenCensus 和 OpenTracing，并提供安全补丁。在本书的下一节中，我们将看看如何使用 OpenCensus 实现 Go 程序。将来，使用我们将要讨论的实现 OpenCensus 跟踪的策略，使用 OpenTelemetry 实现您的程序应该是相对简单的。

在接下来的部分，我们将看到如何为我们的应用程序实现 OpenCensus。

# 为您的应用程序实现 OpenCensus

让我们用一个实际的例子来介绍在应用程序中使用 OpenCensus 跟踪。要开始，我们需要确保我们的机器上安装了 Docker。您可以使用[`docs.docker.com/`](https://docs.docker.com/)上的安装文档来确保 Docker 已安装并在您的机器上正确运行。完成后，我们可以开始创建、实现和查看一个示例应用程序。安装了 Docker 后，我们可以拉取我们的仪器的重要镜像。在我们的示例中，我们将使用 Redis（一个键值存储）来存储应用程序中的键值事件，并使用 Zipkin（一个分布式跟踪系统）来查看这些跟踪。

让我们拉取这个项目的依赖项：

1.  Redis 是我们将在示例应用程序中使用的键值存储：

```go
docker pull redis:latest
```

1.  Zipkin 是一个分布式跟踪系统：

```go
docker pull openzipkin/zipkin
```

1.  我们将启动我们的 Redis 服务器，并让它在后台运行：

```go
docker run -it -d -p 6379:6379 redis
```

1.  我们将为我们的 Zipkin 服务器做同样的事情：

```go
docker run -it -d -p 9411:9411 openzipkin/zipkin
```

一旦我们安装并准备好所有依赖项，我们就可以开始编写我们的应用程序：

1.  首先，我们将实例化我们的`main`包并添加必要的导入：

```go
package main

import (

    "context"
    "log"
    "net/http"
    "time"

    "contrib.go.opencensus.io/exporter/zipkin"
    "go.opencensus.io/trace"
    "github.com/go-redis/redis"
    openzipkin "github.com/openzipkin/zipkin-go"
    zipkinHTTP "github.com/openzipkin/zipkin-go/reporter/http"
)

```

1.  我们的`tracingServer`函数定义了一些内容：

+   我们设置了一个新的 Zipkin 端点。

+   我们初始化一个新的 HTTP 报告器，这是我们发送跨度的端点。

+   我们设置了一个新的导出器，它返回一个`trace.Exporter`（这是我们将跨度上传到 Zipkin 服务器的方式）。

+   我们将我们的导出器注册到跟踪处理程序。

+   我们应用了采样率的配置。在这个例子中，我们设置我们的示例始终跟踪，但我们可以将其设置为我们请求的较小百分比：

```go
func tracingServer() {

    l, err := openzipkin.NewEndpoint("oc-zipkin", "192.168.1.5:5454")

    if err != nil {
        log.Fatalf("Failed to create the local zipkinEndpoint: %v", err)

    }

    r := zipkinHTTP.NewReporter("http://localhost:9411/api/v2/spans")
    z := zipkin.NewExporter(r, l)
    trace.RegisterExporter(z)
    trace.ApplyConfig(trace.Config{DefaultSampler: trace.AlwaysSample()})

}
```

1.  在我们的`makeRequest`函数中，我们执行以下操作：

+   创建一个新的`span`

+   向给定的 HTTP URL 发出请求

+   设置睡眠超时以模拟额外的延迟

+   注释我们的跨度

+   返回响应状态

```go
func makeRequest(ctx context.Context, url string) string {
    log.Printf("Retrieving URL")
    _, span := trace.StartSpan(ctx, "httpRequest")
    defer span.End()
    res, _ := http.Get(url)
    defer res.Body.Close()
    time.Sleep(100 * time.Millisecond)
    log.Printf("URL Response : %s", res.Status)
    span.Annotate([]trace.Attribute{
        trace.StringAttribute("URL Response Code", res.Status),
    }, "HTTP Response Status Code:"+res.Status)
    time.Sleep(50 * time.Millisecond)
    return res.Status
}
```

1.  在我们的`writeToRedis`函数中，我们执行以下操作：

+   开始一个新的跨度

+   连接到我们的本地 Redis 服务器

+   设置特定的键值对

```go
func writeToRedis(ctx context.Context, key string, value string) {

    log.Printf("Writing to Redis")
    _, span := trace.StartSpan(ctx, "redisWrite")
    defer span.End()
    client := redis.NewClient(&redis.Options{
        Addr: "localhost:6379",
        Password: "",
        DB: 0,
    })

    err := client.Set(key, value, 0).Err()
    if err != nil {
        panic(err)
    }
}  
```

1.  然后我们使用我们的`main`函数将所有这些内容整合在一起：

```go
func main() {

    tracingServer()
    ctx, span := trace.StartSpan(context.Background(), "main")
    defer span.End()
    for i := 0; i < 10; i++ {
        url := "https://golang.org/"
        respStatus := makeRequest(ctx, url)
        writeToRedis(ctx, url, respStatus)
    }
} 
```

1.  在我们通过执行`go run ocZipkin.go`调用我们的程序之后，我们可以查看我们的 Zipkin 服务器。如果我们选择我们跟踪列表中的一个跟踪，我们可以看到我们创建的跟踪：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/hsn-hiperf-go/img/e4ba0a84-ea05-4651-a52d-9e2f91ffd6fd.png)

如果我们点击一个跨度，我们可以进一步调查它：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/hsn-hiperf-go/img/7b3555a8-7122-4f24-a795-d81fb40a5499.png)

我们可以看到我们代码中的`httprequest`和`rediswrite`函数的调用。随着我们在代码周围实现更多的跨度，我们将获得越来越大的跟踪，这将帮助我们诊断代码的延迟最严重的地方。

如果我们点击跟踪中的一个单独元素，我们可以看到我们在代码中编写的注释：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/hsn-hiperf-go/img/6310d60b-dd08-438f-9de5-66bd074a4783.png)

如果我们试图理解特定用户行为，注释可能会很有用。我们还可以看到`traceId`、`spanId`和`parentId`的详细信息。

# 摘要

在本章中，我们学习了有关跟踪的所有内容。我们学会了如何在特定代码片段上实现单独的跟踪并分析它们以了解它们的行为。我们还学会了如何实现和分析分布式跟踪以了解分布式系统中的问题。能够使用这些技能将帮助您调试分布式系统，并进而帮助降低**平均解决时间**（**MTTR**）。

在第十四章中，*集群和作业队列*，我们将学习如何评估集群和作业队列以进行性能优化。


# 第十四章：簇和作业队列

在 Go 中的聚类和作业队列是使分布式系统同步工作并传递一致消息的好方法。分布式计算很困难，因此在聚类和作业队列中都非常重要地观察潜在的性能优化。

在本章中，我们将学习以下主题：

+   使用分层和质心算法进行聚类

+   Goroutines 作为队列

+   作业队列中的缓冲通道

+   实现第三方排队系统（Kafka 和 RabbitMQ）

了解不同的聚类系统可以帮助您识别数据中的大型群组，以及如何在数据集中准确对其进行分类。了解排队系统将帮助您将大量信息从数据结构传输到特定的排队机制，以便实时将大量数据传递给不同的系统。

# Go 中的聚类

聚类是一种方法，您可以使用它来搜索给定数据集中一致的数据组。使用比较技术，我们可以寻找数据集中包含相似特征的项目组。然后将这些单个数据点划分为簇。聚类通常用于解决多目标问题。

聚类有两种一般分类，都有不同的子分类：

+   **硬聚类**：数据集中的数据点要么明确属于一个簇，要么明确不属于一个簇。硬聚类可以进一步分类如下：

+   **严格分区**：一个对象只能属于一个簇。

+   **带异常值的严格分区**：严格分区，还包括一个对象可以被分类为异常值的概念（意味着它们不属于任何簇）。

+   **重叠聚类**：个体对象可以与一个或多个簇相关联。

+   **软聚类**：根据明确的标准，数据点被分配与特定簇相关联的概率。它们可以进一步分类如下：

1.  +   **子空间**：簇使用二维子空间，以便进一步分类为两个维度。

+   **分层**：使用分层模型进行聚类；与子簇相关联的对象也与父簇相关联。

还有许多不同类型的算法用于聚类。以下表格中显示了一些示例：

| **名称** | **定义** |
| --- | --- |
| 分层 | 用于尝试构建簇的层次结构。通常基于自顶向下或自底向上的方法，试图将数据点分割为一对多个簇（自顶向下）或多对少个簇（自底向上）。 |
| 质心 | 用于找到作为簇中心的特定点位置。 |
| 密度 | 用于寻找数据集中具有数据点密集区域的位置。 |
| 分布 | 用于利用分布模型对簇内的数据点进行排序和分类。 |

在本书中，我们将专注于分层和质心算法，因为它们在计算机科学中（特别是在机器学习中）通常被使用。

# K 最近邻

分层聚类是一种聚类方法，其中与子簇相关联的对象也与父簇相关联。该算法从数据结构中的所有单个数据点开始，分配到单个簇。最近的簇合并。这种模式持续进行，直到所有数据点都与另一个数据点相关联。分层聚类通常使用一种称为**树状图**的图表技术来显示。分层聚类的时间复杂度为*O(n²)*，因此通常不用于大型数据集。

**K 最近邻**（**KNN**）算法是机器学习中经常使用的一种分层算法。在 Go 中查找 KNN 数据的最流行的方法之一是使用`golearn`包。作为机器学习示例经常使用的经典 KNN 示例是鸢尾花的分类，可以在[`github.com/sjwhitworth/golearn/blob/master/examples/knnclassifier/knnclassifier_iris.go`](https://github.com/sjwhitworth/golearn/blob/master/examples/knnclassifier/knnclassifier_iris.go)中看到。

给定一个具有萼片和花瓣长度和宽度的数据集，我们可以看到关于该数据集的计算数据：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/hsn-hiperf-go/img/7fb62e91-76e2-436a-9266-d4a7993c2271.png)

我们可以在此预测模型中看到计算出的准确度。在前面的输出中，我们有以下描述：

| **描述符** | **定义** |
| --- | --- |
| 参考类 | 与输出相关联的标题。 |
| 真阳性 | 模型正确预测了正面响应。 |
| 假阳性 | 模型错误地预测了正面响应。 |
| 真阴性 | 模型正确预测了负面响应。 |
| 精确度 | 不将实际上是负面的实例标记为正面的能力。 |
| 召回率 | *真阳性/（真阳性总和+假阴性）*的比率。 |
| F1 分数 | 精确度和召回率的加权调和平均值。该值介于 0.0 和 1.0 之间，1.0 是该值的最佳可能结果。 |

最后但肯定不是最不重要的，我们有一个总体准确度，告诉我们算法如何准确地预测了我们的结果。

# K-means 聚类

K-means 聚类是机器学习中最常用的聚类算法之一。K-means 试图识别数据集中数据点的潜在模式。在 K-means 中，我们将*k*定义为我们的聚类具有的质心数（具有均匀密度的对象的中心）。然后，我们根据这些质心对不同的数据点进行分类。

我们可以使用 K-means 库，在[`github.com/muesli/kmeans`](https://github.com/muesli/kmeans)中找到，对数据集执行 K-means 聚类。让我们来看一下：

1.  首先，我们实例化`main`包并导入我们所需的包：

```go
package main

import (
  "fmt"
  "log"
  "math/rand"

  "github.com/muesli/clusters"
  "github.com/muesli/kmeans"
)
```

1.  接下来，我们使用`createDataset`函数创建一个随机的二维数据集：

```go
func createDataset(datasetSize int) clusters.Observations {
  var dataset clusters.Observations
  for i := 1; i < datasetSize; i++ {
    dataset = append(dataset, clusters.Coordinates{
      rand.Float64(),
      rand.Float64(),
    })
  }
  return dataset
}
```

1.  接下来，我们创建一个允许我们打印数据以供使用的函数：

```go
func printCluster(clusters clusters.Clusters) {
  for i, c := range clusters {
    fmt.Printf("\nCluster %d center points: x: %.2f y: %.2f\n", i, c.Center[0], c.Center[1])
    fmt.Printf("\nDatapoints assigned to this cluster: : %+v\n\n", c.Observations)
  }
}
```

在我们的`main`函数中，我们定义了我们的聚类大小，数据集大小和阈值大小。

1.  现在，我们可以创建一个新的随机 2D 数据集，并对该数据集执行 K-means 聚类。我们按如下方式绘制结果并打印我们的聚类：

```go
func main() {

  var clusterSize = 3
  var datasetSize = 30
  var thresholdSize = 0.01
  rand.Seed(time.Now().UnixNano())
  dataset := createDataset(datasetSize)
  fmt.Println("Dataset: ", dataset)

  km, err := kmeans.NewWithOptions(thresholdSize, kmeans.SimplePlotter{})
  if err != nil {
    log.Printf("Your K-Means configuration struct was not initialized properly")
  }

  clusters, err := km.Partition(dataset, clusterSize)
  if err != nil {
    log.Printf("There was an error in creating your K-Means relation")
  }

  printCluster(clusters)
}

```

执行此函数后，我们将能够看到我们的数据点分组在各自的聚类中：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/hsn-hiperf-go/img/2569c1a4-10e2-4215-bc8d-1ed8556cbf77.png)

在我们的结果中，我们可以看到以下内容：

+   我们的初始（随机生成的）2D 数据集

+   我们定义的三个聚类

+   分配给每个聚类的相关数据点

该程序还生成了每个聚类步骤的`.png`图像。最后创建的图像是数据点聚类的可视化：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/hsn-hiperf-go/img/7319abcf-10d1-4f28-9995-4ac9319a7783.png)

如果要将大型数据集分组为较小的组，K-means 聚类是一个非常好的算法。它的 O 符号是*O(n)*，因此通常适用于大型数据集。K-means 聚类的实际应用可能包括以下的二维数据集：

+   使用 GPS 坐标在地图上识别犯罪多发区

+   为值班开发人员识别页面聚类

+   根据步数输出与休息天数的比较来识别运动员表现特征

在下一节中，让我们探索 Go 中的作业队列。

# 在 Go 中探索作业队列

作业队列经常用于在计算机系统中处理工作单元。它们通常用于调度同步和异步函数。在处理较大的数据集时，可能会有需要花费相当长时间来处理的数据结构和算法。系统正在处理非常大的数据段，应用于数据集的算法非常复杂，或者两者兼而有之。能够将这些作业添加到作业队列中，并以不同的顺序或不同的时间执行它们，对于维护系统的稳定性并为最终用户提供更好的体验非常有帮助。作业队列也经常用于异步作业，因为作业完成的时间对最终用户来说并不那么重要。如果实现了优先级队列，作业系统还可以对作业进行优先处理。这允许系统首先处理最重要的作业，然后处理没有明确截止日期的作业。

# Goroutines 作为作业队列

也许您的特定任务并不需要作业队列。对于任务，使用 goroutine 通常就足够了。假设我们想在某个特定任务期间异步发送电子邮件。我们可以在我们的函数中使用 goroutine 发送这封电子邮件。

在这个例子中，我将通过 Gmail 发送电子邮件。为了做到这一点，您可能需要允许不太安全的应用程序访问电子邮件验证工作（[`myaccount.google.com/lesssecureapps?pli=1`](https://myaccount.google.com/lesssecureapps?pli=1)）。这并不是长期推荐的做法；这只是一个展示真实世界电子邮件交互的简单方法。如果您有兴趣构建更健壮的电子邮件解决方案，您可以使用 Gmail API（[`developers.google.com/gmail/api/quickstart/go`](https://developers.google.com/gmail/api/quickstart/go)）。让我们开始吧：

1.  首先，我们将实例化我们的`main`包，并将必要的包导入到我们的示例程序中：

```go
package main

import (
  "log"
  "time"

  "gopkg.in/gomail.v2"
)

```

1.  然后，我们将创建我们的`main`函数，它将执行以下操作：

+   记录一个`Doing Work`行（代表在我们的函数中做其他事情）。

+   记录一个`Sending Emails`行（代表电子邮件被添加到 goroutine 的时间）。

+   生成一个 goroutine 来发送电子邮件。

+   确保 goroutine 完成后再休眠（如果需要，我们也可以在这里使用`WaitGroup`）：

```go
func main() {

    log.Printf("Doing Work")
    log.Printf("Sending Emails!")
    go sendMail()
    time.Sleep(time.Second)
    log.Printf("Done Sending Emails!")
}
```

在我们的`sendMail`函数中，我们接收一个收件人，设置我们需要发送电子邮件的正确电子邮件头，并使用`gomail`拨号器发送它。如果您希望看到此程序成功执行，您需要更改`sender`、`recipient`、`username`和`password`变量：

```go
func sendMail() {
    var sender = "USERNAME@gmail.com"
    var recipient = "RECIPIENT@gmail.com"
    var username = "USERNAME@gmail.com"
    var password = "PASSWORD"
    var host = "smtp.gmail.com"
    var port = 587 

    email := gomail.NewMessage()
    email.SetHeader("From", sender)
    email.SetHeader("To", recipient)
    email.SetHeader("Subject", "Test Email From Goroutine")
    email.SetBody("text/plain", "This email is being sent from a Goroutine!")

    dialer := gomail.NewDialer(host, port, username, password)
    err := dialer.DialAndSend(email)
    if err != nil {
        log.Println("Could not send email")
        panic(err)
    }   
}
```

从我们的输出结果中可以看出，我们能够有效地完成一些工作并发送电子邮件：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/hsn-hiperf-go/img/052fc4f2-e76f-42bd-bb2f-a0c295ca6763.png)

本书已经指出，执行任务的最有效方法通常是最简单的方法。如果不需要构建新的作业排队系统来执行简单的任务，就应该避免这样做。在大公司中，通常有专门的团队来维护大规模数据的作业队列系统。从性能和成本的角度来看，它们是昂贵的。它们通常是管理大规模数据系统的重要组成部分，但我觉得如果不提到在将分布式作业队列添加到技术栈之前应该仔细考虑，我会感到遗憾。

# 作业队列作为缓冲通道

Go 的缓冲通道是一个完美的工作队列示例。正如我们在第三章中学到的*理解并发*，缓冲通道是具有有界大小的通道。它们通常比无界通道更高效。它们用于从您启动的显式数量的 goroutine 中检索值。因为它们是**先进先出**（**FIFO**）的排队机制，它们可以有效地用作固定大小的排队机制，我们可以按照它们进来的顺序处理请求。我们可以使用缓冲通道编写一个简单的作业队列。让我们来看一下：

1.  我们首先实例化我们的`main`包，导入所需的库，并设置我们的常量：

```go
package main

import (
  "log"
  "net/http"
)

const queueSize = 50
const workers = 10
const port = "1234"
```

1.  然后，我们创建一个`job`结构。这个结构跟踪作业名称和有效载荷，如下面的代码块所示：

```go
type job struct {
  name string
  payload string
}
```

1.  我们的`runJob`函数只是打印一个成功的消息。如果我们愿意，这里可以添加更多的工作：

```go
func runJob(id int, individualJob job) {
  log.Printf("Worker %d: Completed: %s with payload %s", id, individualJob.name, individualJob.payload)
}

```

我们的主函数创建了一个定义的`queueSize`的`jobQueue`通道。然后，它遍历工作人员并为每个工作人员生成 goroutine。最后，它遍历作业队列并运行必要的作业：

```go
func main() {
  jobQueue := make(chan job, queueSize)
  for i := 1; i <= workers; i++ {
    go func(i int) {
      for j := range jobQueue {
        runJob(i, j)
      }
    }(i)

  }

```

我们还在这里有一个 HTTP 处理函数，用于接收来自外部来源的请求（在我们的情况下，它将是一个简单的 cURL 请求，但您可以从外部系统接收许多不同的请求）：

```go
http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
    submittedJob := job{r.FormValue("name"), r.FormValue("payload")}
    jobQueue <- submittedJob
  })

  http.ListenAndServe(":"+port, nil)
}
```

1.  在此之后，我们启动作业队列并执行请求以测试命令：

```go
for i in {1..15}; do curl localhost:1234/ -d id=$i -d name=job$i -d payload=”Hi from Job $i”; done
```

以下截图显示了一个结果集，显示了不同的工作人员完成了不同的工作：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/hsn-hiperf-go/img/a6a32e02-7046-4aed-be59-9e3a188beb89.png)

请注意，个别的工作人员会根据自己的能力接手工作。这对我们继续发展需要这些工作的系统是有帮助的。

# 集成作业队列

有时我们可能不想使用内置的 Go 队列系统。也许我们已经有一个包含其他消息队列系统的流水线，或者我们知道我们将不得不维护一个非常大的数据输入。用于这项任务的两个常用系统是 Apache Kafka 和 RabbitMQ。让我们快速看一下如何使用 Go 与这两个系统集成。

# Kafka

Apache Kafka 被称为*分布式流系统*，这只是说分布式作业队列的另一种方式。Kafka 是用 Java 编写的，使用发布/订阅模型进行消息队列。它通常用于编写实时流数据管道。

我们假设您已经设置了 Kafka 实例。如果没有，您可以使用以下 bash 脚本快速获取 Kafka 实例：

```go
#!/bin/bash
rm -rf kafka_2.12-2.3.0
wget -c http://apache.cs.utah.edu/kafka/2.3.0/kafka_2.12-2.3.0.tgz
tar xvf kafka_2.12-2.3.0.tgz
./kafka_2.12-2.3.0/bin/zookeeper-server-start.sh kafka_2.12-2.3.0/config/zookeeper.properties &
./kafka_2.12-2.3.0/bin/kafka-server-start.sh kafka_2.12-2.3.0/config/server.properties
wait
```

我们可以执行以下 bash 脚本：

```go
./testKafka.sh
```

在这之后，我们可以运行`kafka`读取和写入 Go 程序来读取和写入 Kafka。让我们分别调查一下。

我们可以使用`writeToKafka.go`程序来写入 Kafka。让我们来看一下：

1.  首先，我们初始化我们的`main`包并导入所需的包：

```go
package main

import (
  "context"
  "fmt"
  "log"
  "time"

  "github.com/segmentio/kafka-go"
)
```

1.  在我们的`main`函数中，我们创建了一个连接到 Kafka，设置了写入截止日期，然后写入了我们的 Kafka 主题/分区的消息。在这种情况下，它只是从 1 到 10 的简单消息计数：

```go
func main() {
    var topic = "go-example"
    var partition = 0 
    var connectionType = "tcp"
    var connectionHost = "0.0.0.0"
    var connectionPort = ":9092"

    connection, err := kafka.DialLeader(context.Background(), connectionType,              
      connectionHost+connectionPort, topic, partition)
    if err != nil {
        log.Fatal(err)
    } 
    connection.SetWriteDeadline(time.Now().Add(10 * time.Second))

    for i := 0; i < 10; i++ {
        connection.WriteMessages(
            kafka.Message{Value: []byte(fmt.Sprintf("Message : %v", i))},
        )
    }

    connection.Close()
} 
```

1.  `readFromKafka.go`程序实例化`main`包并导入所有必要的包，如下所示：

```go
package main
import (
    "context"
    "fmt"
    “log”
    "time"
    "github.com/segmentio/kafka-go"
)

```

1.  我们的`main`函数然后设置了一个 Kafka 主题和分区，然后创建了一个连接，设置了连接截止日期，并设置了批处理大小。

有关 Kafka 主题和分区的更多信息，请访问：[`kafka.apache.org/documentation/#intro_topics`](http://kafka.apache.org/documentation/#intro_topics)。

1.  我们可以看到我们的`topic`和`partition`已经被设置为变量，并且我们的连接已经被实例化：

```go
func main() {

    var topic = "go-example"
    var partition = 0
    var connectionType = "tcp"
    var connectionHost = "0.0.0.0"
    var connectionPort = ":9092"

    connection, err := kafka.DialLeader(context.Background(), connectionType,  
      connectionHost+connectionPort, topic, partition)
    if err != nil {
        log.Fatal("Could not create a Kafka Connection")
    }

```

1.  然后，我们在连接上设置了截止日期并读取我们的批处理。最后，我们关闭我们的连接：

```go
  connection.SetReadDeadline(time.Now().Add(1 * time.Second))
  readBatch := connection.ReadBatch(500, 500000)

  byteString := make([]byte, 500)
  for {
    _, err := readBatch.Read(byteString)
    if err != nil {
        break
    }
    fmt.Println(string(byteString))
  }

  readBatch.Close()
  connection.Close()
}
```

1.  在我们执行`readFromKafka.go`和`writeFromKafka.go`文件之后，我们可以看到生成的输出：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/hsn-hiperf-go/img/35f8e1a7-6cba-4c62-afa4-f1e751bd8cbc.png)

我们的 Kafka 实例现在有了我们从`writeToKafka.go`程序发送的消息，现在可以被我们的`readFromKafka.go`程序消费。

在完成 Kafka 和 zookeeper 服务后，我们可以执行以下命令来停止它们：

```go
./kafka_2.12-2.3.0/bin/kafka-server-stop.sh
./kafka_2.12-2.3.0/bin/zookeeper-server-stop.sh
```

许多企业使用 Kafka 作为消息代理系统，因此能够理解如何在 Go 中从这些系统中读取和写入对于在企业环境中创建规模化的东西是有帮助的。

# RabbitMQ

RabbitMQ 是一个流行的开源消息代理，用 Erlang 编写。它使用一种称为**高级消息队列协议**（**AMQP**）的协议来通过其排队系统传递消息。话不多说，让我们设置一个 RabbitMQ 实例，并使用 Go 来传递消息到它和从它那里接收消息：

1.  首先，我们需要使用 Docker 启动 RabbitMQ 实例：

```go
docker run -d --name rabbitmq -p 5672:5672 -p 15672:15672 rabbitmq:3-management
```

1.  然后，我们在我们的主机上运行了一个带有管理门户的 RabbitMQ 实例。

1.  现在，我们可以使用 Go AMQP 库（[`github.com/streadway/amqp`](https://github.com/streadway/amqp)）来通过 Go 与我们的 RabbitMQ 系统传递消息。

我们将首先创建一个监听器。让我们一步一步地看这个过程：

1.  首先，我们实例化`main`包并导入必要的依赖项，以及设置显式变量：

```go
package main

import (
  "log"

  "github.com/streadway/amqp"
)

func main() {
    var username = "guest"
    var password = "guest"
    var protocol = "amqp://"
    var host = "0.0.0.0"
    var port = ":5672/"
    var queueName = "go-queue"

```

1.  然后，我们创建到`amqp`服务器的连接：

```go
  connectionString := protocol + username + ":" + password + "@" + host + port
  connection, err := amqp.Dial(connectionString)
  if err != nil {
    log.Printf("Could not connect to Local RabbitMQ instance on " + host)
  }
  defer connection.Close()

  ch, err := connection.Channel()
  if err != nil {
    log.Printf("Could not connect to channel")
  }
  defer ch.Close()
```

1.  接下来，我们声明我们正在监听的队列，并从队列中消费消息：

```go
  queue, err := ch.QueueDeclare(queueName, false, false, false, false, nil)
  if err != nil {
    log.Printf("Could not declare queue : " + queueName)
  }

  messages, err := ch.Consume(queue.Name, "", true, false, false, false, nil)
  if err != nil {
    log.Printf("Could not register a consumer")
  }

  listener := make(chan bool)

  go func() {
    for i := range messages {
      log.Printf("Received message: %s", i.Body)
    }
  }()

  log.Printf("Listening for messages on %s:%s on queue %s", host, port, queueName)
  <-listener
}
```

1.  现在，我们可以创建发送函数。同样，我们声明我们的包并导入我们的依赖项，以及设置我们的变量：

```go
package main

import (
  "log"

  "github.com/streadway/amqp"
)

func main() {
  var username = "guest"
  var password = "guest"
  var protocol = "amqp://"
  var host = "0.0.0.0"
  var port = ":5672/"
  var queueName = "go-queue"
```

1.  我们使用了与我们的监听器中使用的相同的连接方法。在生产实例中，我们可能会将其抽象化，但在这里包含它是为了方便理解：

```go
  connectionString := protocol + username + ":" + password + "@" + host + port
  connection, err := amqp.Dial(connectionString)
  if err != nil {
    log.Printf("Could not connect to Local RabbitMQ instance on " + host)
  }
  defer connection.Close()

  ch, err := connection.Channel()
  if err != nil {
    log.Printf("Could not connect to channel")
  }
  defer ch.Close()
```

1.  然后，我们声明我们想要使用的队列并将消息主体发布到该队列：

```go
  queue, err := ch.QueueDeclare(queueName, false, false, false, false, nil)
  if err != nil {
    log.Printf("Could not declare queue : " + queueName)
  }

  messageBody := "Hello Gophers!"
  err = ch.Publish("", queue.Name, false, false,
    amqp.Publishing{
      ContentType: "text/plain",
      Body: []byte(messageBody),
    })
  log.Printf("Message sent on queue %s : %s", queueName, messageBody)
  if err != nil {
    log.Printf("Message not sent successfully on queue %s", queueName, messageBody)
  }
}
```

1.  创建了这两个程序后，我们可以测试它们。我们将使用一个 while true 循环迭代我们的消息发送程序：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/hsn-hiperf-go/img/480ad6b8-ec58-42d6-8666-0a3c28fe1268.png)

在完成这些操作后，我们应该能看到消息进入我们的接收器：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/hsn-hiperf-go/img/ba78ccd7-da8f-4ae6-92ea-a8a17e3cdfc2.png)

我们还可以通过查看位于`http://0.0.0.0:15672`的 RabbitMQ 管理门户的输出来查看此活动的输出，默认情况下使用 guest 作为用户名和密码：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/hsn-hiperf-go/img/6cf9a660-ad49-4116-9877-ff10d226515e.png)

该门户为我们提供了有关 RabbitMQ 作业队列的各种不同信息，从排队的消息数量，发布/订阅模型状态，到有关 RabbitMQ 系统的各个部分（连接、通道、交换和队列）的结果。了解这个排队系统的工作原理将有助于您，如果您将来需要与 RabbitMQ 队列通信的话。

# 总结

在本章中，我们学习了使用分层和质心算法进行集群化，使用 goroutines 作为队列，使用缓冲通道作为作业队列，以及实现第三方排队系统（Kafka 和 RabbitMQ）。

学习所有这些集群和作业队列技术将帮助您更好地使用算法和分布式系统，并解决计算机科学问题。在下一章中，我们将学习如何使用 Prometheus 导出器、APMs、SLIs/SLOs 和日志来衡量和比较不同版本的代码质量。
