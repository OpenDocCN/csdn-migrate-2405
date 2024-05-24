# Go 高性能实用指南（三）

> 原文：[`zh.annas-archive.org/md5/CBDFC5686A090A4C898F957320E40302`](https://zh.annas-archive.org/md5/CBDFC5686A090A4C898F957320E40302)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第七章：Go 中的模板编程

Go 中的模板编程允许最终用户编写生成、操作和运行 Go 程序的 Go 模板。Go 具有清晰的静态依赖关系，这有助于元编程。Go 中的模板编程，包括生成的二进制文件、CLI 工具和模板化库，都是语言的核心原则，帮助我们编写可维护、可扩展、高性能的 Go 代码。

在本章中，我们将涵盖以下主题：

+   Go generate

+   协议缓冲区代码生成

+   链接工具链

+   使用 Cobra 和 Viper 进行配置元编程

+   文本和 HTML 模板

+   Go 模板的 Sprig

所有这些主题都将帮助您更快、更有效地编写 Go 代码。在下一节中，我们将讨论 Go generate 以及它在 Go 编程语言中的用途。

# 理解 Go generate

截至 Go 版本 1.4，该语言包含一个名为 Go generate 的代码生成工具。Go generate 扫描源代码以运行通用命令。这独立于`go build`运行，因此必须在构建代码之前运行。Go generate 由代码作者运行，而不是由编译后的二进制文件的用户运行。这个工具的运行方式类似于通常使用 Makefile 和 shell 脚本的方式，但它是与 Go 工具一起打包的，我们不需要包含任何其他依赖项。

Go generate 将搜索代码库以查找以下模式的行：`//go:generate command argument`。

生成的源文件应该有以下一行，以传达代码是生成的：

```go
^// Code generated .* DO NOT EDIT\.$
```

当生成器运行时，Go generate 利用一组变量：

+   `$GOARCH`：执行平台的架构

+   `$GOOS`：执行平台的操作系统

+   `$GOFILE`：文件名

+   `$GOLINE`：包含指令的源文件的行号

+   `$GOPACKAGE`：包含指令的文件的包名称

+   `$DOLLAR`：一个字面的`$`

我们可以在 Go 中使用这个 Go generate 命令来处理各种不同的用例。它们可以被视为 Go 的内置构建机制。使用 Go generate 执行的操作可以使用其他构建工具，比如 Makefile，但有了 Go generate，您就不需要在构建环境中包含任何其他依赖项。这意味着所有的构建产物都存储在 Go 文件中，以保持项目的一致性。

# 生成 protobufs 的代码

在 Go 中生成代码的一个实际用例是使用 gRPC 生成协议缓冲区。协议缓冲区是一种用于序列化结构化数据的新方法。它通常用于在分布式系统中的服务之间传递数据，因为它往往比其 JSON 或 XML 对应物更有效。协议缓冲区还可以跨多种语言和多个平台进行扩展。它们带有结构化数据定义；一旦您的数据被结构化，就会生成可以从数据源读取和写入的源代码。

首先，我们需要获取最新版本的协议缓冲区：[`github.com/protocolbuffers/protobuf/releases`](https://github.com/protocolbuffers/protobuf/releases)。

在撰写本文时，该软件的稳定版本为 3.8.0。安装此软件包后，我们需要确保使用`go get github.com/golang/protobuf/protoc-gen-go`命令拉取所需的 Go 依赖项。接下来，我们可以生成一个非常通用的协议定义：

```go
syntax = "proto3";
package userinfo;
  service UserInfo {
  rpc PrintUserInfo (UserInfoRequest) returns (UserInfoResponse) {}

} 

message UserInfoRequest {
  string user = 1;
  string email = 2;
} 

message UserInfoResponse {
  string response = 1; 
} 
```

之后，我们可以使用 Go generate 生成我们的 protofile。在与您的`.proto`文件相同的目录中创建一个包含以下内容的文件：

```go
package userinfo
//go:generate protoc -I ../userinfo --go_out=plugins=grpc:../userinfo ../userinfo/userinfo.proto
```

这使我们可以通过使用 Go generate 来生成协议缓冲区定义。在这个目录中执行 Go generate 后，我们会得到一个文件`userinfo.pb.go`，其中包含了所有我们的协议缓冲区定义的 Go 格式。当我们使用 gRPC 生成客户端和服务器架构时，我们可以使用这些信息。

接下来，我们可以创建一个服务器来使用我们之前添加的 gRPC 定义：

```go
package main

import (
    "context"
    "log"
    "net"      
    pb "github.com/HighPerformanceWithGo/7-metaprogramming-in-go/grpcExample/userinfo/userinfo"
    "google.golang.org/grpc"
)      
type userInfoServer struct{}       
func (s *userInfoServer) PrintUserInfo(ctx context.Context, in *pb.UserInfoRequest) (*pb.UserInfoResponse, error) {
    log.Printf("%s %s", in.User, in.Email)
    return &pb.UserInfoResponse{Response: "User Info: User Name: " + in.User + " User Email: " + in.Email}, nil 
} 
```

一旦我们初始化了服务器结构并有一个返回用户信息的函数，我们就可以设置我们的 gRPC 服务器监听我们的标准端口并注册我们的服务器：

```go
func main() {
  l, err := net.Listen("tcp", ":50051")
  if err != nil {
    log.Fatalf("Failed to listen %v", err)
  }
  s := grpc.NewServer()
  pb.RegisterUserInfoServer(s, &userInfoServer{})
  if err := s.Serve(l); err != nil {
    log.Fatalf("Couldn't create Server: %v", err)
  }
}
```

一旦我们设置好服务器定义，我们就可以专注于客户端。我们的客户端具有所有常规的导入，以及一些默认的常量声明，如下所示：

```go
package main

import (
  "context"
  "log"
  "time"

  pb "github.com/HighPerformanceWithGo/7-metaprogramming-in-go/grpcExample/userinfo/userinfo"
  "google.golang.org/grpc"
)

const (
  defaultGrpcAddress = "localhost:50051"
  defaultUser = "Gopher"
  defaultEmail = "Gopher@example.com"
)

```

在我们设置好导入和常量之后，我们可以在主函数中使用它们将这些值发送到我们的服务器。我们设置了一个默认超时为 1 秒的上下文，我们发出了一个`PrintUserInfo`的 protobuf 请求，然后得到了一个响应并记录下来。以下是我们的 protobuf 示例：

```go
func main() {
  conn, err := grpc.Dial(defaultGrpcAddress, grpc.WithInsecure())
  if err != nil {
    log.Fatalf("did not connect: %v", err)
  }
  defer conn.Close()
  c := pb.NewUserInfoClient(conn)

  user := defaultUser
  email := defaultEmail
  ctx, cancel := context.WithTimeout(context.Background(), time.Second)
  defer cancel()
  r, err := c.PrintUserInfo(ctx, &pb.UserInfoRequest{User: user, Email: email})
  if err != nil {
    log.Fatalf("could not greet: %v", err)
  }
  log.Printf("%s", r.Response)
}
```

我们可以在这里看到我们的 protobuf 示例在运行中的情况。Protobuf 是在分布式系统中发送消息的强大方式。Google 经常提到 protobuf 对于他们在规模上的稳定性有多么重要。我们将在下一节讨论我们的 protobuf 代码的结果。

# Protobuf 代码结果

一旦我们有了我们的协议定义、我们的服务器和我们的客户端，我们可以一起执行它们，看到我们的工作在实际中的效果。首先，我们启动服务器：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/hsn-hiperf-go/img/1ef5a6cc-4cae-409b-a20b-820eb05353ba.png)

接下来，我们执行客户端代码。我们可以在我们的客户端代码中看到我们创建的默认用户名和电子邮件地址：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/hsn-hiperf-go/img/d87c1be2-f1c0-4066-8a40-775e4eb0699b.png)

在服务器端，我们可以看到我们发出的请求的日志：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/hsn-hiperf-go/img/d803f44f-6fc8-4629-b664-8c9f5712af69.png)

gRPC 是一个非常高效的协议：它使用 HTTP/2 和协议缓冲区来快速序列化数据。客户端到服务器的单个连接可以进行多次调用，从而减少延迟并增加吞吐量。

在下一节中，我们将讨论链接工具链。

# 链接工具链

Go 语言在其链接工具中有一堆方便的工具，允许我们将相关数据传递给可执行函数。使用这个工具，程序员可以为具有特定名称和值对的字符串设置一个值。在 Go 语言的`cmd`/`link`包中允许您在链接时向 Go 程序传递信息。将此信息从工具链传递到可执行文件的方法是利用构建参数：

```go
go build -ldflags '-X importpath.name=value'
```

例如，如果我们试图从命令行中获取程序的序列号，我们可以做如下操作：

```go
package main

import (
  "fmt"
)

var SerialNumber = "unlicensed"

func main() {
  if SerialNumber == "ABC123" {
    fmt.Println("Valid Serial Number!")
  } else {
    fmt.Println("Invalid Serial Number")
  }
}
```

如前面的输出所示，如果我们尝试在不传入序列号的情况下执行此程序，程序将告诉我们我们的序列号无效：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/hsn-hiperf-go/img/ca2db256-1808-4fce-9f2f-746e956332af.png)

如果我们传入一个不正确的序列号，我们将得到相同的结果：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/hsn-hiperf-go/img/774acde4-4e0e-457c-8513-a7e2db3695cf.png)

如果我们传入正确的序列号，我们的程序将告诉我们我们有一个有效的序列号：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/hsn-hiperf-go/img/9d1f8fef-3f44-475b-88a6-3c2397304178.png)

在链接时将数据传递到程序中的能力在排查大型代码库时非常有用。当您需要部署一个已编译的二进制文件，但稍后可能需要以非确定性方式更新一个常见值时，这也是非常有用的。

在下一节中，我们将讨论两个常用于配置编程的工具——Cobra 和 Viper。

# 介绍 Cobra 和 Viper 用于配置编程

两个常用的 Go 库`spf13/cobra`和`spf13/viper`用于配置编程。这两个库可以一起用于创建具有许多可配置选项的 CLI 二进制文件。Cobra 允许您生成应用程序和命令文件，而 Viper 有助于读取和维护 12 因素 Go 应用程序的完整配置解决方案。Cobra 和 Viper 在一些最常用的 Go 项目中使用，包括 Kubernetes 和 Docker。

要一起使用这两个库制作一个`cmd`库，我们需要确保我们嵌套我们的项目目录，如下所示：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/hsn-hiperf-go/img/2542a06f-7527-477c-9588-b0e63555caa5.png)

一旦我们创建了嵌套的目录结构，我们就可以开始设置我们的主程序。在我们的 `main.go` 文件中，我们已经定义了我们的日期命令 - Cobra 和 Viper 的 `main.go` 函数故意简单，以便我们可以调用在 `cmd` 目录中编写的函数（这是一个常见的 Go 习惯）。我们的 `main` 包如下所示：

```go
package main

import (
    "fmt"
    "os"

    "github.com/HighPerformanceWithGo/7-metaprogramming-in-go/clitooling/cmd"
) 

func main() {

    if err := cmd.DateCommand.Execute(); err != nil { 
        fmt.Println(err)
        os.Exit(1)
    } 
} 
```

一旦我们定义了我们的 `main` 函数，我们就可以开始设置我们的其余命令工具。我们首先导入我们的要求：

```go
package cmd 

import (
    "fmt"
    "time"

    "github.com/spf13/cobra"
    "github.com/spf13/viper"
) 

var verbose bool
```

接下来，我们可以设置我们的根 `date` 命令：

```go
var DateCommand = &cobra.Command{
    Use: "date",
    Aliases: []string{"time"},
    Short: "Return the current date",
    Long: "Returns the current date in a YYYY-MM-DD HH:MM:SS format",
    Run: func(cmd *cobra.Command, args []string) {
        fmt.Println("Current Date :\t", time.Now().Format("2006.01.02 15:04:05"))
        if viper.GetBool("verbose") {
            fmt.Println("Author :\t", viper.GetString("author"))
            fmt.Println("Version :\t", viper.GetString("version"))
        } 
    }, 
} 
```

一旦我们设置了这个，我们还可以设置一个子命令来显示我们的许可信息，如下面的代码示例所示。子命令是 CLI 工具的第二个参数，以便为 `cli` 提供更多信息：

```go
var LicenseCommand = &cobra.Command{
    Use: "license",
    Short: "Print the License",
    Long: "Print the License of this Command",
    Run: func(cmd *cobra.Command, args []string) {
        fmt.Println("License: Apache-2.0")
    }, 
}         
```

最后，我们可以设置我们的 `init()` 函数。Go 中的 `init()` 函数用于一些事情：

+   向用户显示初始信息

+   初始变量声明

+   初始化与外部方的连接（例如 DB 连接池或消息代理初始化）

我们可以在代码的最后部分利用我们新的 `init()` 函数知识来初始化我们之前定义的 `viper` 和 `cobra` 命令：

```go
func init() {
    DateCommand.AddCommand(LicenseCommand) 
    viper.SetDefault("Author", "bob")
    viper.SetDefault("Version", "0.0.1")
    viper.SetDefault("license", "Apache-2.0")
    DateCommand.PersistentFlags().BoolP("verbose", "v", false, "Date 
     Command Verbose")
    DateCommand.PersistentFlags().StringP("author", "a", "bob", "Date 
     Command Author")

    viper.BindPFlag("author",    
     DateCommand.PersistentFlags().Lookup("author"))
    viper.BindPFlag("verbose", 
     DateCommand.PersistentFlags().Lookup("verbose"))

} 
```

前面的代码片段向我们展示了 Viper 中常用的一些默认、持久和绑定标志。

# Cobra/Viper 结果集

现在我们已经实例化了所有的功能，我们可以看到我们的新代码在运行中的情况。

如果我们调用我们的新的 `main.go` 而没有任何可选参数，我们将只看到我们在初始 `DateCommand` 运行块中定义的日期返回，如下面的代码输出所示：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/hsn-hiperf-go/img/573c481a-3822-41c0-9118-936ee34d458e.png)

如果我们向我们的输入添加额外的标志，我们可以收集详细信息并使用命令行标志更改包的作者，如下所示：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/hsn-hiperf-go/img/c2450161-1c4c-4765-8a3b-fb9db3f742f5.png)

我们还可以通过将其作为参数添加来查看我们为许可创建的子命令，如下所示：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/hsn-hiperf-go/img/b0b25dca-8d9d-4d97-8e87-e546ceae13db.png)

我们已经看到了 `spf13` Cobra 和 Viper 包的一小部分功能，但重要的是要理解它们的根本原则 - 它们用于在 Go 中促进可扩展的 CLI 工具。在下一节中，我们将讨论文本模板。

# 文本模板

Go 有一个内置的模板语言 `text/template`，它使用数据实现模板并生成基于文本的输出。我们使用结构来定义我们想要在模板中使用的数据。与所有事物一样，Go 输入文本被定义为 UTF-8，并且可以以任何格式传递。我们使用双大括号 `{{}}` 来表示我们想要在我们的数据上执行的操作。由 `.` 表示的光标允许我们向我们的模板添加数据。这些组合在一起创建了一个强大的模板语言，它将允许我们为许多代码片段重用模板。

首先，我们将初始化我们的包，导入我们需要的依赖项，并为我们想要传递到模板中的数据定义我们的结构：

```go
package main

import (
  "fmt"
  "os"
  "text/template"
)

func main() {
  type ToField struct {
    Date string
    Name string
    Email string
    InOffice bool
  }
```

现在，我们可以使用我们之前提到的 text/template 定义来设置我们的模板和输入结构：

```go
     const note = `
{{/* we can trim whitespace with a {- or a -} respectively */}}
Date: {{- .Date}}
To: {{- .Email | printf "%s"}}
{{.Name}},
{{if .InOffice }}
Thank you for your input yesterday at our meeting.  We are going to go ahead with what you've suggested.
{{- else }}
We were able to get results in our meeting yesterday.  I've emailed them to you.  Enjoy the rest of your time Out of Office!
{{- end}}
Thanks,
Bob
`
    var tofield = []ToField{
        {"07-19-2019", "Mx. Boss", "boss@example.com", true},
        {"07-19-2019", "Mx. Coworker", "coworker@example.com", false},
    }
```

最后，我们可以执行我们的模板并打印它。我们的示例打印到 `Stdout`，但我们也可以打印到文件，写入缓冲区，或自动发送电子邮件：

```go
    t := template.Must(template.New("Email Body").Parse(note))
    for _, k := range tofield {
        err := t.Execute(os.Stdout, k)
        if err != nil {
            fmt.Print(err)
        }
    }
}
```

利用 Go 文本模板系统，我们可以重复使用这些模板来生成一致的高质量内容。由于我们有新的输入，我们可以调整我们的模板并相应地得出结果。在下一节中，我们将讨论 HTML 模板。

# HTML 模板

我们还可以使用 HTML 模板，类似于我们执行文本模板，以便在 Go 中为 HTML 页面生成动态结果。为了做到这一点，我们需要初始化我们的包，导入适当的依赖项，并设置一个数据结构来保存我们计划在 HTML 模板中使用的值，如下所示：

```go
package main

import (
    "html/template"
    "net/http"
)

type UserFields struct {
    Name string
    URL string
    Email string
}
```

接下来，我们创建`userResponse` HTML 模板：

```go
var userResponse = ` 
<html>
<head></head>
<body>
<h1>Hello {{.Name}}</h1>
<p>You visited {{.URL}}</p>
<p>Hope you're enjoying this book!</p> 
<p>We have your email recorded as {{.Email}}</p>
</body>
</html>
`
```

然后，我们创建一个 HTTP 请求处理程序：

```go
func rootHandler(w http.ResponseWriter, r *http.Request) {
    requestedURL := string(r.URL.Path)
    userfields := UserFields{"Bob", requestedURL, "bob@example.com"}
    t := template.Must(template.New("HTML Body").Parse(userResponse))
    t.Execute(w, userfields)
    log.Printf("User " + userfields.Name + " Visited : " + requestedURL)
}
```

之后，我们初始化 HTTP 服务器：

```go
func main() {
 s := http.Server{
 Addr: "127.0.0.1:8080",
 } 
 http.HandleFunc("/", rootHandler)
 s.ListenAndServe()
}
```

然后，我们使用`go run htmlTemplate.go`调用我们的 Web 服务器。当我们在该域上请求页面时，我们将看到以下结果：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/hsn-hiperf-go/img/f036617f-b337-43c3-886c-4366cde1c43f.png)

前面的输出来自于我们的 HTML 模板中的模板化代码。这个例子可以扩展到包括解析通过 X-Forwarded-For 头部的传入 IP 地址请求，基于用户代理字符串的最终用户浏览器信息，或者可以用于向客户端返回丰富响应的任何其他特定请求参数。在下一节中，我们将讨论 Sprig，一个用于 Go 模板函数的库。

# 探索 Sprig

Sprig 是一个用于定义 Go 模板函数的库。该库包括许多函数，扩展了 Go 的模板语言的功能。Sprig 库有一些原则，有助于确定哪些函数可用于驱动增强的模板：

+   只允许简单的数学运算

+   只处理传递给模板的数据；从不从外部来源检索数据

+   利用模板库中的函数构建结果布局

+   永远不会覆盖 Go 核心模板功能

在以下小节中，我们将更详细地了解 Sprig 的功能。

# 字符串函数

Sprig 具有一组字符串函数，可以在模板中操作字符串。

在我们的示例中，我们将采用`"   -  bob smith"`字符串（注意空格和破折号）。然后，我们将执行以下操作：

+   使用`trim()`实用程序修剪空格

+   用单词`smith`替换单词`strecansky`的实例

+   修剪`-`前缀

+   将字符串更改为标题大小写，即从`bob strecansky`更改为`Bob Strecansky`

+   重复字符串 10 次

+   创建一个 14 个字符的单词换行（我的名字的宽度），并用新行分隔每个字符。

Sprig 库可以在一行中执行此操作，类似于 bash shell 可以将函数串联在一起。

我们首先初始化我们的包并导入必要的依赖项：

```go
package main 

import ( 
    "fmt" 
    "os" 
    "text/template" 

    "github.com/Masterminds/sprig" 
) 

```

接下来，我们将我们的字符串映射设置为`interface`，执行我们的转换，并将我们的模板呈现到标准输出：

```go
func main() {
  inStr := map[string]interface{}{"Name": " - bob smith"}
  transform := `{{.Name | trim | replace "smith" "strecansky" | trimPrefix "-" | title | repeat 10 | wrapWith 14 "\n"}}`

  functionMap := sprig.TxtFuncMap()
  t := template.Must(template.New("Name Transformation").Funcs(functionMap).Parse(transform))

  err := t.Execute(os.Stdout, inStr)
  if err != nil {
    fmt.Printf("Couldn't create template: %s", err)
    return
  }
}
```

执行程序后，我们将看到字符串操作发生的方式与我们预期的方式相同：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/hsn-hiperf-go/img/ef77ea5a-0575-420b-af28-f0771b04994f.png)

能够像我们的示例中那样在模板中操作字符串，有助于我们快速纠正可能存在的任何模板问题，并即时操纵它们。

# 字符串切片函数

能够在模板中操作字符串切片是有帮助的，正如我们在之前的章节中所看到的。Sprig 库帮助我们执行一些字符串切片操作。在我们的示例中，我们将根据`.`字符拆分字符串。

首先，我们导入必要的库：

```go
package main

import (
    "fmt"
    "os"
    "text/template"

    "github.com/Masterminds/sprig"
) 

func main() {
```

接下来，我们使用`.`分隔符拆分我们的模板字符串：

```go
    tpl := `{{$v := "Hands.On.High.Performance.In.Go" | splitn "." 5}}{{$v._3}}`

    functionMap := sprig.TxtFuncMap()
    t := template.Must(template.New("String 
     Split").Funcs(functionMap).Parse(tpl))

    fmt.Print("String Split into Dict (word 3): ")
    err := t.Execute(os.Stdout, tpl)
    if err != nil {
        fmt.Printf("Couldn't create template: %s", err)
        return
    } 
```

我们还可以使用`sortAlpha`函数将模板化列表按字母顺序排序：

```go
    alphaSort := `{{ list "Foo" "Bar" "Baz" | sortAlpha}}` 
    s := template.Must(template.New("sortAlpha").
      Funcs(functionMap).Parse(alphaSort))
    fmt.Print("\nAlpha Tuple: ")
    alphaErr := s.Execute(os.Stdout, tpl)
    if alphaErr != nil {
        fmt.Printf("Couldn't create template: %s", err)
        return
    } 

    fmt.Print("\nString Slice Functions Completed\n")
} 
```

这些字符串操作可以帮助我们组织包含在模板化函数中的字符串列表。

# 默认函数

Sprig 的默认函数为模板化函数返回默认值。我们可以检查特定数据结构的默认值以及它们是否为空。对于每种数据类型，都定义了*空*。

| 数字 | `0` |
| --- | --- |
| 字符串 | `""`（空字符串） |
| 列表 | `[]`（空列表） |
| 字典 | `{}`（空字典） |
| 布尔值 | `false` |
| 并且总是 | 空（也称为空） |
| 结构 | 空的定义；永远不会返回默认值 |

我们从导入开始：

```go
package main

import (
    "fmt"
    "os"
    "text/template"

    "github.com/Masterminds/sprig"
) 

```

接下来，我们设置我们的空和非空模板变量：

```go
func main() {

    emptyTemplate := map[string]interface{}{"Name": ""} 
    fullTemplate := map[string]interface{}{"Name": "Bob"}
    tpl := `{{empty .Name}}`
    functionMap := sprig.TxtFuncMap()
    t := template.Must(template.New("Empty 
     String").Funcs(functionMap).Parse(tpl))
```

然后，我们验证我们的空模板和非空模板：

```go
    fmt.Print("empty template: ")
    emptyErr := t.Execute(os.Stdout, emptyTemplate)
    if emptyErr != nil {
        fmt.Printf("Couldn't create template: %s", emptyErr)
        return
    } 

    fmt.Print("\nfull template: ")
    fullErr := t.Execute(os.Stdout, fullTemplate)
    if emptyErr != nil {
        fmt.Printf("Couldn't create template: %s", fullErr)
        return
    } 
    fmt.Print("\nEmpty Check Completed\n") 
}
```

当我们有模板输入需要验证输入不为空时，这是非常有用的。我们的输出结果显示了我们的预期：空模板标记为 true，而完整模板标记为 false：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/hsn-hiperf-go/img/00f6e52b-3879-478f-a61d-e01425972e22.png)

我们还可以将 JSON 文字编码为 JSON 字符串并进行漂亮打印。如果您正在处理需要向最终用户返回 JSON 数组的 HTML 创建的模板，这将特别有帮助。

```go
package main
import (
    "fmt"
    "os"
    "text/template"
    "github.com/Masterminds/sprig"
)
func main() {
    jsonDict := map[string]interface{}{"JSONExamples": map[string]interface{}{"foo": "bar", "bool": false, "integer": 7}} 
    tpl := `{{.JSONExamples | toPrettyJson}}`
    functionMap := sprig.TxtFuncMap()
    t := template.Must(template.New("String Split").Funcs(functionMap).Parse(tpl))
    err := t.Execute(os.Stdout, jsonDict)
    if err != nil {
        fmt.Printf("Couldn't create template: %s", err)
        return
    } 
} 
```

在我们的输出结果中，我们可以看到基于我们的`jsonDict`输入的漂亮打印的 JSON 块：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/hsn-hiperf-go/img/44223726-7492-4c51-8935-b7fa80b99d4d.png)

当与 HTML/template 内置和添加的`content-encoding:json`HTTP 头一起使用时，这非常有用。

Sprig 库有相当多的功能，其中一些我们将在本书的本节中讨论。

可以在[`masterminds.github.io/sprig/`](http://masterminds.github.io/sprig/)找到通过 Sprig 可用的功能的完整列表。

# 总结

在本章中，我们讨论了生成 Go 代码。我们讨论了如何为 Go 代码中最常见的生成部分之一，gRPC protobufs，进行生成。然后，我们讨论了使用链接工具链添加命令行参数和`spf13/cobra`和`spf13/viper`来创建元编程 CLI 工具。最后，我们讨论了使用 text/template、HTML/template 和 Sprig 库进行模板化编程。使用所有这些包将帮助我们编写可读、可重用、高性能的 Go 代码。这些模板也将在长远来看为我们节省大量工作，因为它们往往是可重用和可扩展的。

在下一章中，我们将讨论如何优化内存资源管理。


# 第八章：Go 中的内存管理

内存管理对系统性能至关重要。能够充分利用计算机的内存占用空间，使您能够将高度运行的程序保持在内存中，以便您不经常不得不承受交换到磁盘的巨大性能损失。能够有效地管理内存是编写高性能 Go 代码的核心原则。在本章中，我们将学习以下主题：

+   计算机内存

+   内存如何分配

+   Go 如何有效利用内存

+   内存中如何分配对象

+   有限内存计算设备的策略

了解内存如何被利用可以帮助您学会在程序中有效地利用内存。内存是计算机中存储和操作数据的最快速的地方之一，因此能够高效地管理它将对您的代码质量产生持久的影响。

# 理解现代计算机内存 - 入门

现代计算机具有**随机存取存储器**（**RAM**），用于机器代码和数据存储。 RAM 与 CPU 和硬盘一起用于存储和检索信息。利用 CPU、RAM 和硬盘会有性能折衷。在撰写本文时的现代计算机中，我们对计算机中一些常见操作的一些通用、粗略的时间有以下表述：

| **数据存储类型** | **时间** |
| --- | --- |
| L1（处理器缓存）引用 | 1 ns |
| L2（处理器缓存）引用 | 4 ns |
| 主内存引用 | 100 ns |
| SSD 随机读取 | 16 μs |
| 7200 RPM HDD 磁盘搜索 | 2 ms |

正如您从表中所注意到的，不同的存储类型在现代计算机架构的不同部分具有截然不同的时间。新计算机具有 KB 的 L1 缓存，MB 的 L2 缓存，GB 的主内存和 TB 的 SSD/HDD。由于我们认识到这些不同类型的数据存储在成本和性能方面存在显着差异，我们需要学会如何有效地使用它们，以便编写高性能的代码。

# 分配内存

计算机的主内存用于许多事情。**内存管理单元**（**MMU**）是一种计算机硬件，用于在物理内存地址和虚拟内存地址之间进行转换。当 CPU 执行使用内存地址的指令时，MMU 会获取逻辑内存地址并将其转换为物理内存地址。这些以物理内存地址的分组称为页面。页面通常以 4 kB 段处理，使用称为页表的表。MMU 还具有其他功能，包括使用缓冲区，如**转换旁路缓冲器**（**TLB**），用于保存最近访问的转换。

虚拟内存有助于做到以下几点：

+   允许将硬件设备内存映射到地址空间

+   允许特定内存区域的访问权限（rwx）

+   允许进程具有单独的内存映射

+   允许内存更容易移动

+   允许内存更容易地交换到磁盘

+   允许共享内存，其中物理内存映射到多个进程

当在现代 Linux 操作系统中分配虚拟内存时，内核和用户空间进程都使用虚拟地址。这些虚拟地址通常分为两部分 - 虚拟地址空间中的内存上部分用于内核和内核进程，内存下部分用于用户空间程序。

操作系统利用这些内存。它将进程在内存和磁盘之间移动，以优化我们计算机中可用资源的使用。计算机语言在其运行的底层操作系统中使用**虚拟内存空间**（**VMS**）。 Go 也不例外。如果您在 C 中编程，您会知道 malloc 和 free 的习语。在 Go 中，我们没有`malloc`函数。 Go 也是一种垃圾收集语言，因此我们不必考虑释放内存分配。

我们在用户空间内有两种不同的主要内存度量：VSZ 和 RSS。

# 介绍 VSZ 和 RSS

**VSZ**，**虚拟内存大小**，指的是一个单独进程可以访问的所有内存，包括交换内存。这是在程序初始执行时分配的内存大小。VSZ 以 KiB 为单位报告。

**RSS**，**驻留集大小**，指的是特定进程在 RAM 中分配了多少内存，不包括交换内存。RSS 包括共享库内存，只要该内存目前可用。RSS 还包括堆栈和堆内存。根据这些内存引用通常是共享的事实，RSS 内存可能大于系统中可用的总内存。RSS 以千字节为单位报告。

当我们启动一个简单的 HTTP 服务器时，我们可以看到分配给我们各个进程的 VSZ 和 RSS 如下：

```go
package main
import (
    "io"
    "net/http"
)

func main() {
    Handler := func(w http.ResponseWriter, req *http.Request) {
       io.WriteString(w, "Memory Management Test")
    }
    http.HandleFunc("/", Handler)
    http.ListenAndServe(":1234", nil)
}
```

然后我们可以看一下在调用服务器时生成的进程 ID，如下所示：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/hsn-hiperf-go/img/81bdfc69-6487-4960-8314-6bbc1befb46f.png)

在这里，我们可以看到我们调用的`server.go`进程的 VSZ 和 RSS 值。

如果我们想要减小 Go 二进制文件的构建大小，我们可以使用`build`标志构建我们的二进制文件，而不包括 libc 库，如下所示：

```go
go build -ldflags '-libgcc=none' simpleServer.go
```

如果我们构建二进制文件时不包括 libc 库，我们的示例服务器的内存占用将会小得多，如下所示：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/hsn-hiperf-go/img/9c6365c0-e7b8-4ad6-b012-156776750b96.png)

正如我们所看到的，我们的 VSZ 和 RSS 内存利用率都大大减少了。在实践中，内存是廉价的，我们可以将 libc 库留在我们的 Golang 二进制文件中。Libc 用于许多标准库部分，包括用户和组解析以及主机解析的部分，这就是为什么它在构建时动态链接的原因。

在构建 Go 二进制文件后，它们以容器格式存储。Linux 机器将这个特定的二进制文件存储在一种称为**ELF**（可执行和可链接格式）的格式中。Go 的标准库有一种方法来读取 ELF 文件。我们可以检查之前生成的`simpleServer`二进制文件：

```go
package main
import (
    "debug/elf"
    "fmt"
    "log"
    "os"
)
func main() {
    if len(os.Args) != 2 {
       fmt.Println("Usage: ./elfReader elf_file")
       os.Exit(1)
    }
    elfFile, err := elf.Open(os.Args[1])
    if err != nil {
       log.Fatal(err)
    }
    for _, section := range elfFile.Sections {
       fmt.Println(section)
    }
}
```

我们的`simpleServer`示例的输出结果如下：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/hsn-hiperf-go/img/e368c05e-61a4-4f07-9d92-e6bfca7f7bc0.png)

还有其他 Linux 工具可以用来调查这些 ELF 二进制文件。`readelf`也会以更易读的格式打印 ELF 文件。例如，我们可以这样查看一个 ELF 文件：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/hsn-hiperf-go/img/0fe039dc-bb91-46ab-b5a0-0f9faaa1b30a.png)

ELF 文件有特定的格式。该格式如下：

| **文件布局部分** | **描述** |
| --- | --- |
| 文件头 | **类字段**：定义 32 位和 64 位地址分别为 52 或 64 字节长。**数据**：定义小端或大端。**版本**：存储 ELF 版本（目前只有一个版本，01）。**OS/ABI**：定义操作系统和应用程序二进制接口。**机器**：告诉你机器类型。**类型**：指示这是什么类型的文件；常见类型有 CORE，DYN（用于共享对象），EXEC（用于可执行文件）和 REL（用于可重定位文件）。 |
| 程序头或段 | 包含有关如何在运行时创建进程或内存映像以执行的指令。然后内核使用这些指令通过 mmap 映射到虚拟地址空间。 |
| 部分头或部分 | `.text`：可执行代码（指令，静态常量，文字）`.data`：受控访问的初始化数据`.rodata`：只读数据`.bss`：读/写未初始化数据 |

我们还可以编译这个程序的 32 位版本以查看差异。如第一章中所述，*Go 性能简介*，我们可以为不同的架构构建 Go 二进制文件。我们可以使用以下构建参数为 i386 Linux 系统构建二进制文件：

`env GOOS=linux GOARCH=386 go build -o 386simpleServer simpleServer.go`

完成此构建后，我们可以检查生成的 ELF 文件，并证实生成的 ELF 与之前为我的 x86_64 计算机处理的 ELF 不同。我们将使用`-h`标志仅查看每个文件的头部以简洁起见：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/hsn-hiperf-go/img/642fb06a-a721-41ab-b51d-4db166d02b1d.png)

如您在输出结果中所见，这个特定的二进制文件是为 i386 处理器生成的，而不是最初生成的 x86_64 二进制文件：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/hsn-hiperf-go/img/5f2a3cba-31df-4636-a91e-44c3e442cc8e.png)

了解系统的限制、架构和内存限制可以帮助您构建在主机上有效运行的 Go 程序。在本节中，我们将处理内存利用。

# 理解内存利用

一旦我们有了初始的二进制文件，我们就开始建立对 ELF 格式的了解，以继续理解内存利用。文本、数据和 bss 字段是堆和栈的基础。堆从`.bss`和`.data`位的末尾开始，并持续增长以形成更大的内存地址。

堆栈是连续内存块的分配。这种分配在函数调用堆栈内自动发生。当调用函数时，其变量在堆栈上分配内存。函数调用完成后，变量的内存被释放。堆栈具有固定大小，只能在编译时确定。从分配的角度来看，堆栈分配是廉价的，因为它只需要推送到堆栈和从堆栈中拉取以进行分配。

堆是可用于分配和释放的内存组合。内存是以随机顺序分配的，由程序员手动执行。由于其非连续的块，它在时间上更昂贵，访问速度较慢。然而，堆中的元素可以调整大小。堆分配是昂贵的，因为 malloc 搜索足够的内存来容纳新数据。随着垃圾收集器的工作，它扫描堆中不再被引用的对象，并将它们释放。这两个过程比堆栈分配/释放位要昂贵得多。因此，Go 更喜欢在堆栈上分配而不是在堆上分配。

我们可以使用`-m`的 gcflag 编译程序，以查看 Go 编译器如何使用逃逸分析（编译器确定在运行时初始化变量时是否使用堆栈或堆的过程）。

我们可以创建一个非常简单的程序如下：

```go
package main

import "fmt"

func main() {
    greetingString := "Hello Gophers!"
    fmt.Println(greetingString) 
} 
```

然后，我们可以使用逃逸分析标志编译我们的程序如下：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/hsn-hiperf-go/img/31678bb4-b5a6-4c78-816d-646eeb49a4e3.png)

在我们的输出结果中，我们可以看到我们简单的`greetingString`被分配到了堆上。如果我们想要使用此标志进行更多详细信息，我们可以传递多个`m`值。在撰写本文时，传递多达 5 个`-m`标志会给我们不同级别的详细信息。以下屏幕截图是使用 3 个`-m`标志进行构建的（为简洁起见）：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/hsn-hiperf-go/img/bb8813d9-27e7-4f36-bb82-d4cebcbae446.png)

静态分配的 Go 变量倾向于存在堆栈上。指向内存或接口类型方法的项目倾向于是动态的，因此通常存在堆上。

如果我们想在执行构建时看到更多可用的优化，我们可以使用以下命令查看它们：`go tool compile -help`。

# Go 运行时内存分配

正如我们在第三章中所学的，*理解并发性*，Go 运行时使用`G`结构来表示单个 goroutine 的堆栈参数。`P`结构管理执行的逻辑处理器。作为 Go 运行时的一部分使用的 malloc，在[`golang.org/src/runtime/malloc.g`](https://golang.org/src/runtime/malloc.go)中定义，做了很多工作。Go 使用 mmap 直接向底层操作系统请求内存。小的分配大小（内存分配最多达到 32KB）与大内存分配分开处理。

# 内存分配入门

让我们快速讨论与 Go 的小对象内存分配相关的一些对象。

我们可以在[`golang.org/src/runtime/mheap.go`](https://golang.org/src/runtime/mheap.go)中看到`mheap`和`mspan`结构。

`mheap`是主要的 malloc 堆。它跟踪全局数据，以及许多其他堆细节。一些重要的细节如下：

| **名称** | **描述** |
| --- | --- |
| lock | 互斥锁机制 |
| free | 一个非清除的 mspan 的 mTreap（一种树和堆的混合数据结构） |
| scav | 一个包含空闲和清除的 mspan 的 mTreap |
| sweepgen | 用于跟踪跨度清除状态的整数 |
| sweepdone | 跟踪所有跨度是否都被清除 |
| sweepers | 活动的`sweepone`调用数量 |

`mspan`是主要的跨度 malloc。它跟踪所有可用的跨度。跨度是内存的 8K 或更大的连续区域。它还保留许多其他跨度细节。一些重要的细节如下：

| **名称** | **描述** |
| --- | --- |
| `next` | 列表中的下一个跨度；如果没有则为（nil） |
| `previous` | 列表中的前一个跨度；（nil）如果没有 |
| `list` | 用于调试的跨度列表 |
| `startAddr` | 跨度的第一个字节 |
| `npages` | 跨度中的页面数 |

# 内存对象分配

内存对象有三种分类：

+   微小：小于 16 字节的对象

+   小：大于 16 字节且小于或等于 32KB 的对象

+   大：大于 32KB 的对象

在 Go 中，内存中的微小对象执行以下内存分配过程：

1.  如果`P`的 mcache 有空间，就使用那个空间。

1.  取现有的 mcache 中的子对象，并将其四舍五入为 8、4 或 2 字节。

1.  如果适合分配空间，则将对象放入内存中。

在 Go 中，内存中的小对象遵循特定的内存分配模式：

1.  对象的大小被四舍五入并分类为在[`golang.org/src/runtime/mksizeclasses.go`](https://golang.org/src/runtime/mksizeclasses.go)中生成的小尺寸类之一。在以下输出中，我们可以看到在我的 x86_64 机器上定义的`_NumSizeClasses`和`class_to_size`变量分配。然后使用此值在 P 的 mcache 中找到一个空闲位图，并根据需要进行分配，如果有可用的内存空间。以下截图说明了这一点：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/hsn-hiperf-go/img/d1ab7fe3-9ab0-4a0a-8aca-c6c2e7035bf3.png)

1.  如果 P 的 mspan 没有空闲位置，则从 mcentral 的 mspan 列表中获取一个新的 mspan，该列表有足够的空间来存放新的内存对象。

1.  如果该列表为空，则从 mheap 中执行页面运行，以便为 mspan 找到空间。

1.  如果失败，为空，或者没有足够大的页面来分配，就会从操作系统中分配一组新的页面。这很昂贵，但至少以 1MB 的块来完成，这有助于减少与操作系统通信的成本。

从 mspan 中释放对象遵循类似的过程：

1.  如果 mspan 正在响应分配而被清除，则将其返回到 mcache。

1.  如果 mspan 仍然有分配给它的对象，mcentral 的空闲列表将接收该 mspan 以进行释放。

1.  如果 mspan 处于空闲状态（没有分配的对象），它将被返回到 mheap。

1.  一旦 mspan 在给定的间隔内处于空闲状态，这些页面就会被返回到底层操作系统。

大对象不使用 mcache 或 mcentral；它们直接使用 mheap。

我们可以使用先前创建的 HTTP 服务器来查看一些内存统计信息。使用 runtime 包，我们可以推导出程序从操作系统检索的内存量，以及 Go 程序的堆分配。让我们一步一步地看看这是如何发生的：

1.  首先，我们初始化我们的包，执行我们的导入，并设置我们的第一个处理程序：

```go
package main
import (
    "fmt"
    "io"
    "net/http"
    "runtime"
)

func main() {
    Handler := func(w http.ResponseWriter, req *http.Request) {
       io.WriteString(w, "Memory Management Test")
    }
```

1.  然后我们编写一个匿名函数来捕获我们的运行统计：

```go
  go func() {
       for {
           var r runtime.MemStats
           runtime.ReadMemStats(&r)
           fmt.Println("\nTime: ", time.Now())
           fmt.Println("Runtime MemStats Sys: ", r.Sys)
           fmt.Println("Runtime Heap Allocation: ", r.HeapAlloc)
           fmt.Println("Runtime Heap Idle: ", r.HeapIdle)
           fmt.Println("Runtime Head In Use: ", r.HeapInuse)
           fmt.Println("Runtime Heap HeapObjects: ", r.HeapObjects)
           fmt.Println("Runtime Heap Released: ", r.HeapReleased)
           time.Sleep(5 * time.Second)
       }
    }()
    http.HandleFunc("/", Handler)
    http.ListenAndServe(":1234", nil)
}
```

1.  执行此程序后，我们可以看到我们服务的内存分配。以下结果中的第一个打印输出显示了内存的初始分配：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/hsn-hiperf-go/img/b113544c-1739-46b6-9cca-8d0ea15c940f.png)

第二个打印输出是在对`http://localhost:1234/`发出请求后。您可以看到系统和堆分配大致保持不变，并且空闲堆和正在使用的堆会随着 Web 请求的利用而发生变化。

Go 的内存分配器最初源自 TCMalloc，一个线程缓存的 malloc。有关 TCMalloc 的更多信息可以在[`goog-perftools.sourceforge.net/doc/tcmalloc.html`](http://goog-perftools.sourceforge.net/doc/tcmalloc.html)找到。

Go 分配器，Go 内存分配器，使用线程本地缓存和 8K 或更大的连续内存区域。这些 8K 区域，也称为 span，通常用于以下三种能力之一：

+   空闲：可以重用于堆/栈或返回给操作系统的 span

+   使用中：当前在 Go 运行时中使用的 span

+   堆栈：用于 goroutine 堆栈的 span

如果我们创建一个没有共享库的程序，我们应该看到我们的程序的内存占用要小得多：

1.  首先，我们初始化我们的包并导入所需的库：

```go
package main
import (
    "fmt"
    "runtime"
    "time"
)
```

1.  然后，我们执行与之前的简单 http 服务器相同的操作，但我们只使用`fmt`包来打印一个字符串。然后我们休眠，以便能够看到内存利用输出：

```go
func main() {
    go func() {
       for {
           var r runtime.MemStats
           runtime.ReadMemStats(&r)
           fmt.Println("\nTime: ", time.Now())
           fmt.Println("Runtime MemStats Sys: ", r.Sys)
           fmt.Println("Runtime Heap Allocation: ", r.HeapAlloc)
           fmt.Println("Runtime Heap Idle: ", r.HeapIdle)
           fmt.Println("Runtime Heap In Use: ", r.HeapInuse)
           fmt.Println("Runtime Heap HeapObjects: ", r.HeapObjects)
           fmt.Println("Runtime Heap Released: ", r.HeapReleased)
           time.Sleep(5 * time.Second)
       }
    }()
    fmt.Println("Hello Gophers")
    time.Sleep(11 * time.Second)
}
```

1.  从执行此程序的输出中，我们可以看到此可执行文件的堆分配要比我们的简单 HTTP 服务器小得多：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/hsn-hiperf-go/img/87c357c5-4297-4f02-953d-411fd51fd370.png)

但为什么会这样呢？我们可以使用 goweight 库[[`github.com/jondot/goweight`](https://github.com/jondot/goweight)]来查看程序中依赖项的大小。我们只需要下载这个二进制文件：`go get github.com/jondot/goweight`。

1.  然后我们可以确定我们 Go 程序中的大依赖项是什么：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/hsn-hiperf-go/img/a3278b05-e735-4544-8fac-6ece827fc174.png)

我们可以看到`net/http`库占用了很多空间，runtime 和 net 库也是如此。

相比之下，让我们看一下带有内存统计的简单程序：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/hsn-hiperf-go/img/84587793-0388-4e30-8053-78dd733cfaa8.png)

我们可以看到，没有运行时的下一个最大段要比`net/http`和`net`库小得多。了解资源的确切利用情况总是很重要，以便制作更高效的二进制文件。

如果我们使用 strace 查看操作系统级别的调用，我们接下来可以看到与我们的简单 Web 服务器和简单程序的交互之间的差异。我们简单 Web 服务器的示例如下：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/hsn-hiperf-go/img/15f01d58-f40a-4f5d-80d6-a17a17d9a441.png)

我们简单程序的示例可以在这里看到：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/hsn-hiperf-go/img/a1797f59-dcb9-477d-a3c9-43d4761f5a36.png)

从输出中，我们可以注意到几件事情：

+   我们的`simpleWebServer`的输出比我们的`simpleProgram`要长得多（在截图中已经被截断，但如果生成了，我们可以看到响应长度更长）。

+   `simpleWebServer`加载了更多的 C 库（我们可以在截图中的 strace 捕获中看到`ld.so.preload`、`libpthread.so.0`和`libc.so.6`）。

+   我们的`simpleWebServer`中的内存分配比我们的`simpleProgram`输出要多得多。

我们可以看看这些是从哪里拉取的。`net/http`库没有任何 C 引用，但其父库 net 有。在 net 库中的所有 cgo 包中，我们有文档告诉我们如何跳过使用底层 CGO 解析器的包：[`golang.org/pkg/net/#pkg-overview`](https://golang.org/pkg/net/#pkg-overview)。

这份文档向我们展示了如何使用 Go 和 cgo 解析器：

```go
export GODEBUG=netdns=go    # force pure Go resolver
export GODEBUG=netdns=cgo   # force cgo resolver
```

让我们使用以下命令仅启用 Go 解析器在我们的示例 Web 服务器中：

```go
export CGO_ENABLED=0
go build -tags netgo
```

在下面的屏幕截图中，我们可以看到没有 C 解析器的`simpleServer`正在执行的过程：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/hsn-hiperf-go/img/0c5071fb-8149-4b4a-ba74-c152eff4e528.png)

我们可以看到我们的 VSZ 和 RSS 都很低。将其与使用 C 解析器进行比较，方法是输入以下命令：

```go
 export CGO_ENABLED=1
 go build -tags cgo
```

我们可以看到使用以下 C 解析器的`simpleServer`的输出：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/hsn-hiperf-go/img/456eb523-f097-49dc-9674-28140e57c054.png)

我们的 VSZ 在没有使用 cgo 解析器编译的服务器中显着较低。接下来，我们将讨论有限的内存情况以及如何考虑和构建它们。

# 有限内存情况简介

如果您在嵌入式设备或内存非常受限的设备上运行 Go，有时了解运行时内部的一些基本过程以便就您的进程做出明智的决策是明智的。Go 垃圾收集器*优先考虑低延迟和简单性*。它使用非生成并发三色标记和扫描垃圾收集器。默认情况下，它会自动管理内存分配。

Go 在调试标准库中有一个函数，它将强制进行垃圾收集并将内存返回给操作系统。Go 垃圾收集器在 5 分钟后将未使用的内存返回给操作系统。如果您在内存较低的设备上运行，可以在这里找到此函数`FreeOSMemory()`: [`golang.org/pkg/runtime/debug/#FreeOSMemory`](https://golang.org/pkg/runtime/debug/#FreeOSMemory)。

我们还可以使用`GC()`函数，可以在这里找到：[`golang.org/pkg/runtime/#GC`](https://golang.org/pkg/runtime/#GC)。

`GC()`函数也可能会阻塞整个程序。使用这两个函数要自担风险，因为它们可能导致意想不到的后果。

# 总结

在本章中，我们了解了 Go 如何分配堆和栈。我们还学习了如何有效地监视 VSZ 和 RSS 内存，以及如何优化我们的代码以更好地利用可用内存。能够做到这一点使我们能够有效地利用我们拥有的资源，使用相同数量的硬件为更多的并发请求提供服务。

在下一章中，我们将讨论 Go 中的 GPU 处理。


# 第九章：Go 中的 GPU 并行化

GPU 加速编程在当今的高性能计算堆栈中变得越来越重要。它通常用于**人工智能**（**AI**）和**机器学习**（**ML**）等领域。GPU 通常用于这些任务，因为它们往往非常适合并行计算。

在本章中，我们将学习 Cgo、GPU 加速编程、**CUDA**（**Compute Unified Device Architecture**的缩写）、make 命令、Go 程序的 C 样式链接，以及在 Docker 容器中执行启用 GPU 的进程。学习所有这些单独的东西将帮助我们使用 GPU 来支持 Go 支持的 CUDA 程序。这将帮助我们确定如何有效地使用 GPU 来帮助使用 Go 解决计算问题：

+   Cgo - 在 Go 中编写 C

+   GPU 加速计算-利用硬件

+   GCP 上的 CUDA

+   CUDA-为程序提供动力

# Cgo - 在 Go 中编写 C

Cgo 是 Go 标准库中内置的一个库，允许用户在其 Go 代码中调用底层 C 程序。Cgo 通常用作当前用 C 编写但没有等效 Go 代码的事物的代理。

应该谨慎使用 Cgo，只有在系统中没有等效的 Go 库可用时才使用。Cgo 对您的 Go 程序添加了一些限制：

+   不必要的复杂性

+   困难的故障排除

+   构建和编译 C 代码的复杂性增加

+   Go 的许多工具在 Cgo 程序中不可用

+   交叉编译不像预期的那样有效，或者根本不起作用

+   C 代码的复杂性

+   本机 Go 调用比 Cgo 调用快得多

+   构建时间较慢

如果您可以（或必须）接受所有这些规定，Cgo 可能是您正在开发的项目的必要资源。

有一些情况是适合使用 Cgo 的。主要的两个例子如下：

+   当您必须使用专有的**软件开发工具包**（**SDK**）或专有库时。

+   当您有一个遗留的 C 软件，由于业务逻辑验证的原因，将其移植到 Go 可能会很困难。

+   您已经将 Go 运行时耗尽，并且需要进一步优化。我们很少有机会遇到这种特殊情况。

更多优秀的 cgo 文档可以在以下网址找到：

+   [`golang.org/cmd/cgo/`](https://golang.org/cmd/cgo/)

+   [`blog.golang.org/c-go-cgo`](https://blog.golang.org/c-go-cgo)

在下一节中，我们将看一个简单的 cgo 示例，以便熟悉 Cgo 的工作原理，以及它的一些亮点和缺点。

# 一个简单的 Cgo 示例

让我们来看一个相对简单的 Cgo 示例。在这个例子中，我们将编写一个简单的函数来从 C 绑定打印“Hello Gophers”，然后我们将从我们的 Go 程序中调用该 C 代码。在这个函数中，我们返回一个常量字符字符串。然后我们在 Go 程序中调用`hello_gophers` C 函数。我们还使用`C.GoString`函数将 C 字符串类型转换为 Go 字符串类型：

```go
package main

/*

 #include <stdio.h>
 const char* hello_gophers() {
    return "Hello Gophers!";
 }
*/

import "C"
import "fmt"
func main() {
    fmt.Println(C.GoString(C.hello_gophers()))
}
```

一旦执行了这个程序，我们就可以看到一个简单的“Hello Gophers！”输出：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/hsn-hiperf-go/img/3678c8b4-c73c-4039-b628-2bc85cd3e795.png)

这个例子虽然简单，但向我们展示了如何在我们的 Go 程序中绑定 C 函数。为了进一步强调执行时间的差异，我们可以看一下我们的 Cgo 函数和我们的 Go 函数的基准测试： 

```go
package benchmark

/*
 #include <stdio.h>
 const char* hello_gophers() {
     return "Hello Gophers!";
 }
*/

import "C"
import "fmt"

func CgoPrint(n int) {
    for i := 0; i < n; i++ {
       fmt.Sprintf(C.GoString(C.hello_gophers()))
    }
}

func GoPrint(n int) {
    for i := 0; i < n; i++ {
       fmt.Sprintf("Hello Gophers!")
    }
}
```

然后，我们可以使用这些函数来对我们的绑定 C 函数进行基准测试，以比较普通的`GoPrint`函数：

```go
package benchmark

import "testing"

func BenchmarkCPrint(b *testing.B) {
    CgoPrint(b.N)
}

func BenchmarkGoPrint(b *testing.B) {
    GoPrint(b.N)
}
```

执行完这个之后，我们可以看到以下输出：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/hsn-hiperf-go/img/53f3c348-4a5b-43ea-842a-409ddd9d7a41.png)

请注意，绑定的 Cgo 函数所需的时间大约比本机 Go 功能长一个数量级。在某些情况下这是可以接受的。这个基准测试只是进一步验证了我们只有在有意义的时候才应该使用 Cgo 绑定。重要的是要记住，有特定的时机我们可以证明使用 Cgo 是合理的，比如当我们必须执行本地 Go 功能中不可用的操作时。

在下一节中，我们将学习 GPU 加速编程和 NVIDIA 的 CUDA 平台。

# GPU 加速计算-利用硬件

在今天的现代计算机中，我们有一些硬件部件来完成系统的大部分工作。CPU 执行大部分来自计算机其他部分的指令操作，并传递这些操作的结果。内存是数据存储和处理的快速短期位置。硬盘用于长期数据存储和处理，网络设备用于在网络中的计算设备之间发送这些数据位。现代计算系统中经常使用的设备是独立 GPU。无论是显示具有高保真图形的最新电脑游戏，解码 4K 视频，还是执行金融数字计算，GPU 都成为高速计算的更受欢迎的选择。

GPU 旨在以高效的方式执行特定任务。随着高吞吐量计算的广泛采用，将 GPU 用作通用图形处理单元（GPGPUs）变得更加普遍。

有许多不同的 GPU 编程 API 可供使用，以充分利用 GPU 的性能，包括以下内容：

+   OpenCL：[`www.khronos.org/opencl/`](https://www.khronos.org/opencl/)

+   OpenMP：[`www.openmp.org/`](https://www.openmp.org/)

+   NVIDIA 的 CUDA 平台：[`developer.nvidia.com/cuda-zone`](https://developer.nvidia.com/cuda-zone)

NVIDIA 的 CUDA 库是成熟、高性能且广泛接受的。我们将在本章的示例中使用 CUDA 库。让我们更多地了解 CUDA 平台。

NVIDIA 的 CUDA 平台是由 NVIDIA 团队编写的 API，用于增加并行性并提高具有 CUDA 启用的图形卡的速度。在数据结构上执行并行算法可以严重提高计算时间。许多当前的 ML 和 AI 工具集在内部使用 CUDA，包括但不限于以下内容：

+   TensorFlow：[`www.tensorflow.org/install/gpu`](https://www.tensorflow.org/install/gpu)

+   Numba：[`devblogs.nvidia.com/gpu-accelerated-graph-analytics-python-numba/`](https://devblogs.nvidia.com/gpu-accelerated-graph-analytics-python-numba/)

+   PyTorch：[`pytorch.org/`](https://pytorch.org/)

CUDA 提供了一个用于在 C++中访问这些处理习语的 API。它使用内核的概念，内核是从 C++代码调用的函数，在 GPU 设备上执行。内核是代码的部分，可以并行执行。CUDA 使用 C++语法规则来处理指令。

有许多地方可以使用云中的 GPU 来执行计算任务，例如以下：

+   Google Cloud GPU：[`cloud.google.com/gpu/`](https://cloud.google.com/gpu/)

+   带有 GPU 的 AWS EC2 实例：[`aws.amazon.com/nvidia/`](https://aws.amazon.com/nvidia/)

+   Paperspace：[`www.paperspace.com/`](https://www.paperspace.com/)

+   FloydHub：[`www.floydhub.com/`](https://www.floydhub.com/)

您还可以在本地工作站上运行 CUDA 程序。这样做的要求如下：

+   支持 CUDA 的 GPU（我在示例中使用了 NVIDIA GTX670）

+   具有 GCC 编译器和工具链的操作系统（我在示例中使用了 Fedora 29）

在下一节中，我们将介绍如何设置我们的工作站进行 CUDA 处理：

1.  首先，我们需要为我们的主机安装适当的内核开发工具和内核头文件。我们可以通过执行以下命令在我们的示例 Fedora 主机上执行此操作：

```go
sudo dnf install kernel-devel-$(uname -r) kernel-headers-$(uname -r)
```

1.  我们还需要安装`gcc`和适当的构建工具。我们可以通过以下方式来实现：

```go
sudo dnf groupinstall "Development Tools"
```

1.  安装了先决条件后，我们可以获取 NVIDIA 为 CUDA 提供的本地`.run`文件安装程序。在撰写本文时，`cuda_10.2.89_440.33.01_linux.run`包是最新可用的。您可以从[`developer.nvidia.com/cuda-downloads`](https://developer.nvidia.com/cuda-downloads)下载最新的 CUDA 工具包：

```go
wget http://developer.download.nvidia.com/compute/cuda/10.2/Prod/local_installers/cuda_10.2.89_440.33.01_linux.run
```

1.  然后我们可以使用以下代码安装此软件包：

```go
sudo ./cuda_10.2.89_440.33.01_linux.run
```

这将为我们提供一个安装提示，如下截图所示：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/hsn-hiperf-go/img/0e949b8a-966e-4ceb-b0d4-c9cb23c4e84b.png)

1.  接受最终用户许可协议后，我们可以选择安装所需的依赖项并选择`Install`： 

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/hsn-hiperf-go/img/6b6958e4-be34-4ada-9069-a91439c6b6d8.png)

接受安装提示后，CUDA 安装程序应成功完成安装。如果在安装过程中出现任何错误，请查看以下位置可能会帮助您解决安装问题：

+   `/var/log/cuda-installer.log`

+   `/var/log/nvidia-installer.log`

在下一节中，我们将讨论如何使用主机机器进行 CUDA 进程。

# CUDA - 利用主机进程

安装了 CUDA 后，您需要设置一些环境变量，以便将安装的部分添加到执行路径中。如果您在主机上没有 Docker 访问权限，或者您更愿意使用裸机执行 GPU 密集型操作，此功能将按预期工作。如果您想使用更可重现的构建，可以使用以下*Docker for GPU-enabled programming*部分中定义的 Docker 配置。

我们需要更新我们的`PATH`以包括我们刚刚安装的 CUDA 二进制路径。我们可以通过执行以下命令来实现：`export PATH=$PATH:/usr/local/cuda-10.2/bin:/usr/local/cuda-10.2/NsightCompute-2019.1`。

我们还需要更新我们的`LD_LIBRARY_PATH`变量，这是一个环境变量，您的操作系统在链接动态和共享库时会查找它。我们可以通过执行`export LD_LIBRARY_PATH=:/usr/local/cuda-10.2/lib64`来添加 CUDA 库。

这将把 CUDA 库添加到您的库路径中。我们将在本章的结束部分的 GNU Makefile 中以编程方式将这些添加到我们的路径中。在下一节中，我们将讨论如何使用 Docker 利用 CUDA。

# 用于 GPU 启用编程的 Docker

如果您想在本章中使用 Docker 进行 GPU 启用的编程，可以执行以下步骤，但是为了使用此功能，您必须在计算机上拥有兼容的 NVIDIA CUDA GPU。您可以在[`developer.nvidia.com/cuda-gpus`](https://developer.nvidia.com/cuda-gpus)找到已启用的卡的完整列表。

在生产环境中，我们可能不会以这种方式使用 Docker 进行 GPU 加速计算，因为您很可能希望尽可能接近硬件以进行 GPU 加速编程，但我选择在本章中使用这种方法，以便本书的使用者有一个可重现的构建。大多数情况下，可重现的构建是使用容器化方法略有性能损失的可接受折衷方案。

如果您不确定您的 NVIDIA 启用的 GPU 支持什么，您可以使用`cuda-z`实用程序来查找有关您的显卡的更多信息。该程序的可执行文件可以在[`cuda-z.sourceforge.net/`](http://cuda-z.sourceforge.net/)找到。

下载适用于您特定操作系统的版本后，您应该能够执行以下文件：

```go
./CUDA-Z-0.10.251-64bit.run
```

您将看到一个输出，其中包含有关您当前使用的卡的各种信息：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/hsn-hiperf-go/img/967739f9-a0a3-46c0-8cf1-01bbc0876823.png)

一旦您确定您的卡支持所需的 GPU 处理，我们可以使用 Docker 来连接到您的 GPU 进行处理。为此，我们将按照以下步骤进行：

1.  为您的计算机启用 NVIDIA 容器工具包。对于我的 Fedora 测试系统，我不得不通过将我的发行版更改为``centos7``来进行一些小调整——安装的 RPM 仍然按预期工作：

```go
distribution=$(. /etc/os-release;echo $ID$VERSION_ID)
curl -s -L https://nvidia.github.io/nvidia-docker/$distribution/nvidia-docker.repo | sudo tee /etc/yum.repos.d/nvidia-docker.repo
```

在其他操作系统上安装的完整说明可以在[`github.com/NVIDIA/nvidia-docker#quickstart`](https://github.com/NVIDIA/nvidia-docker#quickstart%7C)找到。

1.  安装`nvidia-container-toolkit`：

```go
sudo yum install -y nvidia-container-toolkit
```

1.  重新启动 Docker 以应用这些新更改：

```go
sudo systemctl restart docker
```

1.  禁用 SELINUX，以便您的计算机能够使用 GPU 进行这些请求：

```go
setenforce 0 #as root
```

1.  执行一个测试`docker run`，以确保您能够在 Docker 中执行 GPU 操作，并检查有关您特定 NVIDIA 卡的信息：

```go
docker run --gpus all tensorflow/tensorflow:latest-gpu nvidia-smi
```

在下一节中，我们将介绍如何在 Google Cloud Platform 上设置支持 CUDA GPU 的机器。

# GCP 上的 CUDA

如果您没有必要的硬件，或者您想在云中运行支持 GPU 的代码，您可能决定您更愿意在共享托管环境中使用 CUDA。在下面的示例中，我们将向您展示如何在 GCP 上使用 GPU。

还有许多其他托管的 GPU 提供商（您可以在本章的*GPU 加速计算-利用硬件*部分中看到所有这些提供商的列表）——我们将在这里以 GCP 的 GPU 实例为例。

您可以在[`cloud.google.com/gpu`](https://cloud.google.com/gpu)了解更多关于 GCP 的 GPU 提供。

# 创建一个带有 GPU 的虚拟机

我们需要创建一个 Google Compute Engine 实例，以便能够在 GCP 上利用 GPU。

您可能需要增加 GPU 配额。要这样做，您可以按照以下网址的步骤进行：

https://cloud.google.com/compute/quotas#requesting_additional_quota

在撰写本文时，NVIDIA P4 GPU 是平台上最便宜的，而且具有足够的性能来展示我们的工作。您可以通过在 IAM 管理员配额页面上检查 NVIDIA P4 GPU 指标来验证您的配额：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/hsn-hiperf-go/img/8736ef6d-39c6-4752-97b7-4652f0ff2bee.png)

为此，我们可以访问 Google Cloud 控制台上的 VM 实例页面。以下是此页面的截图。点击屏幕中央的创建按钮：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/hsn-hiperf-go/img/6a30a93c-431c-4daf-9ac0-95fffc36c1e8.png)

接下来，我们创建一个附加了 GPU 的 Ubuntu 18.04 VM。我们的 VM 实例配置示例如下截图所示：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/hsn-hiperf-go/img/953115ed-637a-4d16-be10-f2a23a328187.png)

我们在这里使用 Ubuntu 18.04 作为示例，而不是 Fedora 29，以展示如何为多种架构设置 CUDA。

我们的操作系统和其他配置参数如下截图所示：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/hsn-hiperf-go/img/ab76ddc8-01ba-4415-b116-41b9acdbab27.png)

点击创建按钮后，我们将返回到 VM 实例页面。等待您的 VM 完全配置好（它的名称左侧会有一个绿色的勾号）：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/hsn-hiperf-go/img/23d21efe-e7d0-4608-bf27-8204a4517118.png)

接下来，我们可以 SSH 到实例，如下截图所示：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/hsn-hiperf-go/img/b333f11f-0d5f-4507-b644-59599f3cf668.png)

在接下来的小节中，我们将安装运行支持 GPU 的 CGo 程序所需的所有依赖项。我还在解释的最后包括了一个执行所有这些操作的脚本，以方便您使用。

# 安装 CUDA 驱动程序

按照[`cloud.google.com/compute/docs/gpus/install-drivers-gpu`](https://cloud.google.com/compute/docs/gpus/install-drivers-gpu)中的说明安装 NVIDIA CUDA 驱动程序：

1.  检索 CUDA 存储库：

```go
curl -O http://developer.download.nvidia.com/compute/cuda/repos/ubuntu1804/x86_64/cuda-repo-ubuntu1804_10.0.130-1_amd64.deb
```

1.  安装`.deb`软件包：

```go
sudo dpkg -i cuda-repo-ubuntu1804_10.0.130-1_amd64.deb
```

1.  将 NVIDIA GPG 密钥添加到 apt 源密钥环：

```go
sudo apt-key adv --fetch-keys http://developer.download.nvidia.com/compute/cuda/repos/ubuntu1804/x86_64/7fa2af80.pub
```

1.  安装 NVIDIA CUDA 驱动程序：

```go
sudo apt-get update && sudo apt-get install cuda
```

1.  现在我们在 GCP VM 上有一个支持 CUDA 的 GPU。我们可以使用`nvidia-smi`命令验证这一点：

```go
nvidia-smi
```

1.  我们将在截图中看到以下输出：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/hsn-hiperf-go/img/94ef6bd0-d6a3-47e2-bcb3-a1afe673d7e0.png)

# 在 GCP 上安装 Docker CE

接下来，我们需要在启用 CUDA 的 GCE VM 上安装 Docker CE。要在我们的 VM 上安装 Docker CE，我们可以按照此页面上的说明进行操作：

[`docs.docker.com/install/linux/docker-ce/ubuntu/`](https://docs.docker.com/install/linux/docker-ce/ubuntu/)

在撰写本书时，以下步骤是必要的：

1.  验证主机上没有其他 docker 版本：

```go
sudo apt-get remove docker docker-engine docker.io containerd runc
```

1.  确保我们的存储库是最新的：

```go
sudo apt-get update
```

1.  安装安装 docker CE 所需的依赖项：

```go
sudo apt-get install apt-transport-https ca-certificates curl gnupg-agent software-properties-common
```

1.  添加 docker CE 存储库：

```go
curl -fsSL https://download.docker.com/linux/ubuntu/gpg | sudo apt-key add -
sudo add-apt-repository "deb [arch=amd64] https://download.docker.com/linux/ubuntu $(lsb_release -cs) stable"
```

1.  运行更新以确保 docker CE 存储库是最新的：

```go
sudo apt-get update
```

1.  安装必要的 docker 依赖项：

```go
sudo apt-get install docker-ce docker-ce-cli containerd.io
```

我们现在在主机上有一个可用的 Docker CE 实例。

# 在 GCP 上安装 NVIDIA Docker

要在我们的 VM 上安装 NVIDIA docker 驱动程序，我们可以按照此页面上的说明进行操作：

[`github.com/NVIDIA/nvidia-docker#ubuntu-16041804-debian-jessiestretchbuster`](https://github.com/NVIDIA/nvidia-docker#ubuntu-16041804-debian-jessiestretchbuster)

1.  设置一个分发变量：

```go
distribution=$(. /etc/os-release;echo $ID$VERSION_ID)
```

1.  添加`nvidia-docker`存储库 gpg 密钥和 apt 存储库：

```go
curl -s -L https://nvidia.github.io/nvidia-docker/gpgkey | sudo apt-key add -
curl -s -L https://nvidia.github.io/nvidia-docker/$distribution/nvidia-docker.list | sudo tee /etc/apt/sources.list.d/nvidia-docker.list
```

1.  安装 nvidia-container-toolkit：

```go
sudo apt-get update && sudo apt-get install -y nvidia-container-toolkit
```

1.  重新启动您的 VM 以使此驱动程序生效。

# 将所有内容脚本化

以下 bash 脚本将所有先前的操作组合在一起。首先，我们安装 CUDA 驱动程序：

```go
#!/bin/bash

# Install the CUDA driver
curl -O http://developer.download.nvidia.com/compute/cuda/repos/ubuntu1804/x86_64/cuda-repo-ubuntu1804_10.0.130-1_amd64.deb
dpkg -i cuda-repo-ubuntu1804_10.0.130-1_amd64.deb
apt-key adv --fetch-keys http://developer.download.nvidia.com/compute/cuda/repos/ubuntu1804/x86_64/7fa2af80.pub
apt-get -y update && sudo apt-get -y install cuda
```

然后我们安装 Docker CE：

```go
# Install Docker CE
apt-get remove docker docker-engine docker.io containerd runc
apt-get update
apt-get -y install apt-transport-https ca-certificates curl gnupg-agent software-properties-common
curl -fsSL https://download.docker.com/linux/ubuntu/gpg | sudo apt-key add -
add-apt-repository "deb [arch=amd64] https://download.docker.com/linux/ubuntu $(lsb_release -cs) stable"
apt-get -y update
apt-get -y install docker-ce docker-ce-cli containerd.io
```

最后我们安装`nvidia-docker`驱动程序：

```go
# Install nvidia-docker
distribution=$(. /etc/os-release;echo $ID$VERSION_ID)
curl -s -L https://nvidia.github.io/nvidia-docker/gpgkey | sudo apt-key add -
curl -s -L https://nvidia.github.io/nvidia-docker/$distribution/nvidia-docker.list | sudo tee /etc/apt/sources.list.d/nvidia-docker.list
apt-get -y update && sudo apt-get -y install nvidia-container-toolkit
usermod -aG docker $USER
systemctl restart docker
```

这包含在[`git/HighPerformanceWithGo/9-gpu-parallelization-in-go/gcp_scripts`](https://github.com/bobstrecansky/HighPerformanceWithGo/blob/master/9-gpu-parallelization-in-go/gcp_scripts/nvidia-cuda-gcp-setup.sh)中的 repo 中，并且可以通过运行以下命令来执行：

```go
sudo bash nvidia-cuda-gcp-setup.sh
```

在目录中。在下一节中，我们将通过一个使用 Cgo 执行的示例 CUDA 程序。

# CUDA-推动程序。

在安装了所有 CUDA 依赖项并运行后，我们可以从一个简单的 CUDA C++程序开始：

1.  首先，我们将包括所有必要的头文件，并定义我们想要处理的元素的数量。`1 << 20`是 1,048,576，这已经足够多的元素来展示一个合适的 GPU 测试。如果您想要查看处理时间的差异，可以进行移位：

```go
#include <cstdlib>
#include <iostream>

const int ELEMENTS = 1 << 20;
```

我们的`multiply`函数被包装在一个`__global__`说明符中。这允许`nvcc`，CUDA 特定的 C++编译器，在 GPU 上运行特定的函数。这个乘法函数相对简单：它使用一些 CUDA 魔法将`a`和`b`数组相乘，并将值返回到`c`数组中：

```go
__global__ void multiply(int j, float * a, float * b, float * c) {

  int index = threadIdx.x * blockDim.x + threadIdx.x;
  int stride = blockDim.x * gridDim.x; 

  for (int i = index; i < j; i += stride)
    c[i] = a[i] * b[i];
}
```

这个 CUDA 魔法是指 GPU 的并行处理功能。变量定义如下：

+   +   `gridDim.x`：处理器上可用的线程块数

+   `blockDim.x`：每个块中的线程数

+   `blockIdx.x`：网格内当前块的索引

+   `threadId.x`：块内当前线程的索引

然后我们需要添加一个`extern "C"`调用，以便为这个特定函数使用 C 风格的链接，这样我们就可以有效地从我们的 Go 代码中调用这个函数。这个`cuda_multiply`函数创建了三个数组：

+   +   `a`和`b`，它们存储 1 到 10 之间的随机数

+   `c`，它存储了`a`和`b`的乘积的结果

```go
extern "C" {

  int cuda_multiply(void) {
    float * a, * b, * c;
    cudaMallocManaged( & a, ELEMENTS * sizeof(float));
    cudaMallocManaged( & b, ELEMENTS * sizeof(float));
    cudaMallocManaged( & c, ELEMENTS * sizeof(float));
```

1.  然后我们创建我们的随机浮点数数组：

```go
    for (int i = 0; i < ELEMENTS; i++) {
      a[i] = rand() % 10;
      b[i] = rand() % 10;
    }
```

然后我们执行我们的乘法函数（我们在文件开头定义的），基于块大小。我们根据数字计算出我们想要使用的块数：

```go
    int blockSize = 256;
    int numBlocks = (ELEMENTS + blockSize - 1) / blockSize;
    multiply << < numBlocks, blockSize >>> (ELEMENTS, a, b, c);
```

完成我们的乘法后，我们将等待 GPU 完成，然后才能访问我们在主机上的信息：`cudaDeviceSynchronize();`。

1.  然后我们可以将我们执行的乘法的值打印到屏幕上，以便让最终用户看到我们正在执行的计算。这在代码中被注释掉了，因为打印到`stdout`对于这段特定的代码来说并不显示很好的性能。如果您想要查看正在发生的计算，可以取消注释：

```go
    //for (int k = 0; k < ELEMENTS; k++) {
      //std::cout << k << ":" << a[k] << "*" << b[k] << "=" << c[k] << "\n";
    //}
```

1.  然后，我们释放为乘法函数分配的 GPU 内存，通过在每个数组指针上调用`cudaFree`，然后返回`0`来完成我们的程序：

```go
    cudaFree(a);
    cudaFree(b);
    cudaFree(c);
    return 0;
  }
}
```

1.  然后，我们将添加我们的头文件`cuda_multiply.h`：

```go
int cuda_multiply(void);
```

本章中，我们的 Go 程序只是围绕我们使用一些语法糖创建的`cuda_multiply.cu`函数的包装器。

1.  我们实例化`main`并导入必要的包：

```go
package main

import (
    "fmt"
    "time"
)
```

1.  然后，我们添加了我们需要的`CFLAGS`和`LDFLAGS`，以便引用我们使用 nvcc make 创建的库，以及系统库。这里需要注意的是，这些注释，在 cgo 代码中称为*preambles*，在编译包的 C 部分时用作头文件。我们可以在这里包含任何必要的 C 代码，以使我们的 Go 代码更易于理解。如果您计划使用以下任何一种风格的标志，它们必须以`#cgo`指令为前缀，以调整底层编译器的行为：

+   +   `CFLAGS`

+   `CPPFLAGS`

+   `CXXFLAGS`

+   `FFLAGS`

+   `LDFLAGS`

1.  然后，我们导入伪包`C`，这使我们能够执行我们编写的 C 代码（回想一下我们在`cuda_multiply.cu`文件中的`extern C`调用）。我们还在这个函数周围添加了一个计时包装器，以便查看执行这个函数需要多长时间：

```go
//#cgo CFLAGS: -I.
//#cgo LDFLAGS: -L. -lmultiply
//#cgo LDFLAGS: -lcudart
//#include <cuda_multiply.h>

import "C"
func main() {
    fmt.Printf("Invoking cuda library...\n")
    start := time.Now()
    C.cuda_multiply()
    elapsed := time.Since(start)
    fmt.Println("\nCuda Execution took", elapsed)
}
```

1.  我们将为接下来要构建的 Docker 容器提供一个 Makefile。我们的 Makefile 定义了一个方法来构建我们的 nvcc 库，运行我们的 Go 代码，并清理我们的 nvcc 库：

```go
//target:
    nvcc -o libmultiply.so --shared -Xcompiler -fPIC cuda_multiply.cu
//go:
    go run cuda_multiply.go
```

```go

//clean:
    rm *.so
```

我们的 Dockerfile 将所有内容整合在一起，以便我们的演示可以非常容易地再现：

```go
FROM tensorflow/tensorflow:latest-gpu
ENV LD_LIBRARY_PATH=/usr/local/cuda-10.1/lib64
RUN ln -s /usr/local/cuda-10.1/lib64/libcudart.so /usr/lib/libcudart.so
RUN apt-get install -y golang
COPY . /tmp
WORKDIR /tmp
RUN make
RUN mv libmultiply.so /usr/lib/libmultiply.so 
ENTRYPOINT ["/usr/bin/go", "run", "cuda_multiply.go"]  
```

1.  接下来，我们将构建和运行我们的 Docker 容器。以下是来自缓存构建的输出，以缩短构建步骤的长度：

```go
$ sudo docker build -t cuda-go .
Sending build context to Docker daemon  8.704kB
Step 1/9 : FROM tensorflow/tensorflow:latest-gpu
 ---> 3c0df9ad26cc
Step 2/9 : ENV LD_LIBRARY_PATH=/usr/local/cuda-10.1/lib64
 ---> Using cache
 ---> 65aba605af5a
Step 3/9 : RUN ln -s /usr/local/cuda-10.1/lib64/libcudart.so /usr/lib/libcudart.so
 ---> Using cache
 ---> a0885eb3c1a8
Step 4/9 : RUN apt-get install -y golang
 ---> Using cache
 ---> bd85bd4a8c5e
Step 5/9 : COPY . /tmp
 ---> 402d800b4708
Step 6/9 : WORKDIR /tmp
 ---> Running in ee3664a4669f
Removing intermediate container ee3664a4669f
 ---> 96ba0678c758
Step 7/9 : RUN make
 ---> Running in 05df1a58cfd9
nvcc -o libmultiply.so --shared -Xcompiler -fPIC cuda_multiply.cu
Removing intermediate container 05df1a58cfd9
 ---> 0095c3bd2f58
Step 8/9 : RUN mv libmultiply.so /usr/lib/libmultiply.so
 ---> Running in 493ab6397c29
Removing intermediate container 493ab6397c29
 ---> 000fcf47898c
Step 9/9 : ENTRYPOINT ["/usr/bin/go", "run", "cuda_multiply.go"]
 ---> Running in 554b8bf32a1e
Removing intermediate container 554b8bf32a1e
 ---> d62266019675
Successfully built d62266019675
Successfully tagged cuda-go:latest 
```

然后，我们可以使用以下命令执行我们的 Docker 容器（根据您的 docker 守护程序配置情况，可能需要使用 sudo）：

```go
sudo docker run --gpus all -it --rm cuda-go
```

接下来是前述命令的输出：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/hsn-hiperf-go/img/eb5b521c-f3a6-443c-9d6e-2d3b125b8663.png)

对于如此大的乘法计算来说，相当令人印象深刻！在高计算工作负载下，GPU 编程通常是非常快速计算的良好解决方案。在同一台机器上，仅使用 CPU 的等效 C++程序大约需要 340 毫秒才能运行。

# 摘要

在本章中，我们学习了 cgo、GPU 加速编程、CUDA、Make 命令、用于 Go 程序的 C 风格链接，以及在 Docker 容器中执行启用 GPU 的进程。学习所有这些单独的元素帮助我们开发了一个性能良好的 GPU 驱动应用程序，可以进行一些非常大的数学计算。这些步骤可以重复进行，以便以高性能的方式进行大规模计算。我们还学会了如何在 GCP 中设置启用 GPU 的 VM，以便我们可以使用云资源来执行 GPU 计算。

在下一章中，我们将讨论 Go 语言中的运行时评估。


# 第十章：Go 中的编译时评估

Go 的作者以一种最小化依赖的方式编写了语言，每个文件都声明了自己的依赖关系。常规的语法和模块支持也有助于开发人员提高编译时间，以及接口满意度。在本章中，我们将看到运行时评估如何帮助加快 Go 编译速度，以及如何使用容器构建 Go 代码和利用 Go 构建缓存。

在本章中，我们将涵盖以下主题：

+   Go 运行时

+   `GCTrace`

+   `GOGC`

+   `GOMAXPROCS`

+   `GOTRACEBACK`

+   Go 构建缓存

+   供应

+   缓存

+   调试

+   `KeepAlive`

+   `NumCPU`

+   `ReadMemStats`

这些都是了解 Go 运行时如何工作以及如何使用它编写高性能代码的宝贵主题。

# 探索 Go 运行时

在 Go 源代码中，我们可以通过查看[`golang.org/src/runtime/`](https://golang.org/src/runtime/)来查看运行时源代码。运行时包含与 Go 运行时交互的操作。该包用于控制诸如 goroutines、垃圾回收、反射和调度等功能，这些功能对语言的运行至关重要。在运行时包中，我们有许多环境变量，可以帮助我们改变 Go 可执行文件的运行时行为。让我们回顾一些关于 Go 运行时的最重要的环境变量。

# GODEBUG

`GODEBUG`是变量的控制器，用于在 Go 运行时进行调试。该变量包含一系列以逗号分隔的`name=val`键值对。这些命名变量用于调整二进制文件返回的调试信息的输出。关于这个变量的一个好处是，运行时允许您直接将其应用于预编译的二进制文件，而不是在构建时调用它。这很好，因为它允许您调试已经构建的二进制文件（并且可能已经在生产环境中造成了损害）。您可以传递给`GODEBUG`的变量如下：

| **GODEBUG 变量** | **启用值** | **描述** |
| --- | --- | --- |
| `allocfreetrace` | 1 | 用于对每个分配进行分析。为每个对象的分配和释放打印堆栈跟踪。每个堆栈跟踪包含内存块、大小、类型、goroutine ID 和单个元素的堆栈跟踪。 |
| `clobberfree` | 1 | 当释放对象时，GC 会用不良内容破坏对象的内容。 |
| `cgocheck` | 0 – 禁用 1（默认）– 廉价检查 2 – 昂贵检查 | 用于检查使用 cgo 的包是否将错误传递给非 Go 代码的 go 指针。设置为 0 表示禁用，1 表示廉价检查可能会错过一些错误（默认），或者 2 表示昂贵检查会减慢程序运行速度。 |
| `efence` | 1 | 分配器将确保每个对象都分配在唯一的页面上，并且内存地址不会被重复使用。 |
| `gccheckmark` | 1 | 通过进行第二次标记传递来验证 GC 的当前标记阶段。在这第二次标记传递期间，世界会停止。如果第二次传递发现了并发标记没有找到的对象，GC 将会发生 panic。 |
| `gcpacertrace` | 1 | 打印有关垃圾收集器的并发 pacer 内部状态的信息。 |
| `gcshrinkstackoff` | 1 | 移动的 goroutines 不能移动到更小的堆栈上。在这种模式下，goroutine 的堆栈只会增长。 |
| `gcstoptheworld` | 1 – 禁用 GC 2 – 禁用 GC 和并发扫描 | 1 禁用并发垃圾回收。这将使每个 GC 事件变成一个全局停止的情况。2 禁用 GC 并在垃圾回收完成后禁用并发扫描。 |
| `gctrace` | 1 | 请参阅下一页的`GCTrace`标题。 |
| `madvdontneed` | 1 | 在 Linux 上使用`MADV_DONTNEED`而不是`MADV_FREE`将内存返回给内核。使用此标志会导致内存利用效率降低，但也会使 RSS 内存值更快地下降。 |
| `memprofilerate` | 0 – 关闭分析 1 – 包括每个分配的块 X – 更新`MemProfileRate`的值 | 控制在内存分析中报告和记录的内存分配分数。更改 X 控制记录的内存分配的分数。 |
| `invalidptr` | 0 – 禁用此检查 1 – 如果发现无效指针，则垃圾收集器和堆栈复制器将崩溃 | 如果在存储指针的地方发现无效指针的值，垃圾收集器和堆栈复制器将崩溃。 |
| `sbrk` | 1 | 从操作系统中交换一个不回收内存的简单分配器，而不是使用默认的内存分配器和垃圾收集器。 |
| `scavenge` | 1 | 启用堆清扫调试模式。 |
| `scheddetail` | 1（与 schedtrace=X 一起使用） | 调度器每 X 毫秒返回与调度器、处理器、线程和 goroutine 进程相关的信息。 |
| `schedtrace` | X | 每 X 毫秒向 STDERR 发出一行调度器状态摘要。 |
| `tracebackancestors` | N | 哪些 goroutine 的回溯与它们关联的堆栈被扩展，报告 N 个祖先 goroutine。如果 N = 0，则不返回祖先信息。 |

其他包还有一些变量可以传递给`GODEBUG`。这些通常是非常知名的包，可能需要运行时性能调整，比如`crypto/tls`和`net/http`。如果包含`GODEBUG`标志在运行时是可用的，包应该包含文档。

# GCTRACE

`GCTRACE`在运行时被使用，以查看已经打印到 stderr 的单行，显示每次收集时总内存和暂停的长度。在撰写本文时，此行组织如下：

```go
gc# @#s #%: #+#+# ms clock, #+#/#/#+# ms cpu, #->#-># MB, # MB goal, #P
```

我们可以为提供一个简单的 HTTP 服务器来提供这个工作原理的示例。首先，我们编写一个简单的 HTTP 服务器，对`localhost:8080`的根目录返回一个简单的`Hello Gophers`响应：

```go

package main
import (
    "fmt"
    "net/http"
)

func hello(w http.ResponseWriter, r *http.Request) {
    fmt.Fprintf(w, "Hello Gophers")
}

func main() {
    http.HandleFunc("/", hello)
    err := http.ListenAndServe(":8080", nil)
    if err != nil {
       fmt.Println(err)
    }
}
```

接下来，我们可以构建并运行这个简单的 Web 服务器，然后我们可以使用 Apache bench ([`httpd.apache.org/docs/2.4/programs/ab.html`](https://httpd.apache.org/docs/2.4/programs/ab.html)) 来模拟对主机的一些负载：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/hsn-hiperf-go/img/4adaae82-8d0b-472f-b9a2-4adba426c69d.png)

当我们从 Apache bench 看到这个输出，显示我们的测试已经完成，我们将在最初实例化我们的简单 HTTP 守护程序的终端上看到一些垃圾回收统计信息：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/hsn-hiperf-go/img/30586da4-f98c-4ad0-ad04-36a39dc1756e.png)

让我们分解一下这个示例的垃圾回收输出：|

| **输出** | **描述** |
| --- | --- |
| gc 1 | 垃圾回收编号。每次垃圾回收时，此编号会递增。 |
| @6.131s | 此垃圾回收发生在程序启动后的 6.131 秒。 |
| 0% | 自程序启动以来在 GC 中花费的时间百分比。 |

| 0.016+2.1+0.023 ms clock | GC 阶段发生的挂钟/CPU 时间。这可以表示为*Tgc = Tseq + Tmark + Tsweep.* **Tseq**: 用户 Go 例程时间停止（停止世界清扫终止）。

**Tmark**: 堆标记时间（并发标记和扫描时间）。

**Tsweep**: 堆清扫时间（清扫世界标记终止）。|

| 4->4->3 MB | GC 开始、GC 结束和活动堆大小。 |
| --- | --- |
| 5 MB goal | 目标堆大小。 |
| 4 P | 使用的处理器数。 |

如果我们等待几分钟，我们的终端应该会产生以下输出：

```go
scvg1: 57 MB released
scvg1: inuse: 1, idle: 61, sys: 63, released: 57, consumed: 5 (MB)
```

这是使用`gctrace > 0`发生的输出。每当 Go 运行时将内存释放回系统时，也称为**清扫**，它会产生一个摘要。在撰写本文时，此输出遵循以下格式：

| **输出** | **描述** |
| --- | --- |
| scvg1: 57 MB released | 垃圾回收周期编号。每次垃圾回收时，此编号会递增。此数据点还让我们知道释放回操作系统的内存块的大小。 |
| inuse: 1 | 程序中使用的内存大小（这也可能表示部分使用的跨度）。 |
| 空闲：61 | 待清理的跨度大小（以 MB 为单位）。 |
| sys: 3 | 从系统映射的内存大小（以 MB 为单位）。 |
| released: 57 | 释放给系统的内存大小（以 MB 为单位）。 |
| consumed: 5 | 从系统分配的内存大小（以 MB 为单位）。 |

垃圾收集和清理输出示例都很重要-它们可以以简单易读的方式告诉我们系统内存利用的当前状态。

# GOGC

`GOGC`变量允许我们调整 Go 垃圾收集系统的强度。垃圾收集器（在[`golang.org/src/runtime/mgc.go`](https://golang.org/src/runtime/mgc.go)实例化）读取`GOGC`变量并确定垃圾收集器的值。值为`off`会关闭垃圾收集器。这在调试时通常很有用，但在长期内不可持续，因为程序需要释放在可执行堆中收集的内存。将此值设置为小于默认值 100 将导致垃圾收集器更频繁地执行。将此值设置为大于默认值 100 将导致垃圾收集器执行更不频繁。对于多核大型机器，垃圾收集经常发生，如果我们减少垃圾收集的频率，可以提高性能。我们可以使用标准库的编译来查看更改垃圾收集如何影响编译时间。在以下代码示例中，我们可以看到标准库的构建及其相应的时间：

```go
#!/bin/bash

export GOGC=off
printf "\nBuild with GOGC=off:"
time go build -a std
printf "\nBuild with GOGC=50:"
export GOGC=50
time go build -a std
for i in 0 500 1000 1500 2000
do
    printf "\nBuild with GOGC = $i:"
    export GOGC=$i
    time go build -a std
done
```

我们的输出显示了 Go 标准库编译时间的相应时间：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/hsn-hiperf-go/img/2e31273d-884b-4f09-93e3-c24e027f8b1a.png)

通过调整垃圾收集，我们可以看到编译时间有很大的差异。这将大大变化，取决于您的架构、系统规格和 Go 版本。重要的是要认识到这是一个我们可以为我们的 Go 程序调整的旋钮。这个旋钮通常用于构建时间或高度监控、对延迟敏感的二进制文件，在执行时间内需要挤出更多的性能。

# GOMAXPROCS

`GOMAXPROCS`是一个可以调整的变量，允许我们控制操作系统为 Go 二进制文件中的 goroutine 分配的线程数。默认情况下，`GOMAXPROCS`等于应用程序可用的核心数。这可以通过运行时包动态配置。重要的是要注意，从 Go 1.10 开始，`GOMAXPROCS`将没有上限限制。

如果我们有一个 CPU 密集型且并行化的函数（例如 goroutine 排序字符串），如果调整我们拥有的`GOMAXPROCS`数量，我们将看到一些严重的改进。在以下代码示例中，我们将测试使用不同数字设置`GOMAXPROCS`来构建标准库：

```go
#!/bin/bash
for i in 1 2 3 4
do
    export GOMAXPROCS=$i
    printf "\nBuild with GOMAXPROCS=$i:"
    time go build -a std
done  
```

在我们的结果中，我们可以看到当我们操纵`GOMAXPROCS`的总数时会发生什么：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/hsn-hiperf-go/img/23351ad2-7dae-4807-a55f-ac54de7cd6fc.png)

实际上，我们不应该手动设置`GOMAXPROCS`。很少有情况下，您可能希望根据系统上可用的资源限制特定二进制文件的 CPU 利用率，或者您可能确实需要根据手头的资源进行优化。然而，在大多数情况下，默认的`GOMAXPROCS`值是合理的。

# GOTRACEBACK

`GOTRACEBACK`允许您控制 Go 程序在出现意外运行时条件或未恢复的恐慌状态时生成的输出。设置`GOTRACEBACK`变量将允许您查看有关为特定错误或恐慌实例化的 goroutine 的更多或更少粒度的信息。来自通道/ goroutine 中断的恐慌示例如下：

```go
package main
import (
    "time"
)

func main() {
    c := make(chan bool, 1)
    go panicRoutine(c)
    for i := 0; i < 2; i++ {
       <-c
    }
}

func panicRoutine(c chan bool) {
    time.Sleep(100 * time.Millisecond)
    panic("Goroutine Panic")
    c <- true
}

```

如果我们在输出中调整`GOTRACEBACK`变量，我们将看到不同级别的堆栈跟踪。设置`GOTRACEBACK=none`或`GOTRACEBACK=0`会给我们关于此恐慌的最少信息：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/hsn-hiperf-go/img/3d1ad4f0-7faa-4444-b8a1-c25fdae2d3df.png)

设置`GOTRACEBACK=single`（Go 运行时的默认选项）将为我们的特定请求发出当前 goroutine 的单个堆栈跟踪，如下所示：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/hsn-hiperf-go/img/454b7684-81a2-4e21-aeaf-d3f083bb190b.png)

设置`GOTRACEBACK=all`或`GOTRACEBACK=1`将为用户创建的所有 goroutine 发送回堆栈跟踪：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/hsn-hiperf-go/img/e56929fc-6e24-45c6-8c70-6cc8df1c46c7.png)

设置`GOTRACEBACK=system`或`GOTRACEBACK=2`将为由运行时创建的函数和 goroutine 添加所有运行时堆栈帧。

最后，我们可以设置`GOTRACEBACK=crash`。这与系统类似，但允许操作系统触发核心转储。

大多数情况下，默认的`GOTRACEBACK=single`为我们提供了关于当前上下文的足够信息，以便就为什么我们的程序以我们没有预期的方式结束做出明智的决定。

# Go 构建缓存

在本章中，我们讨论了优化 Go 构建的几种方法。我们还可以通过一些简单的调整来提高 Go 构建时间的能力。Go 团队一直在优化运行时，而不是构建时间。Go 具有缓存构建时间依赖项的能力，这有助于重用先前构建的常见构件。这些构件保存在`$GOPATH/pkg/`中。我们可以通过在调用 go build 时使用`-i`标志来保留这些中间结果，以便重新利用这些构件。如果我们想调试构建过程中发生了什么，我们可以使用`-x`标志运行我们的构建，以便从 Go 构建系统产生更详细的输出。

# Vendoring 依赖项

Vendoring 也是改善构建一致性和质量的流行选择。在项目结构中，语言的作者们对保持对 vendoring 依赖的支持的反馈持开放态度。将依赖项保留在存储库中会使其非常庞大，但可以帮助在构建时保持本地可用的第三方依赖项。当我们使用 Go 版本 1.11 或更高版本时，我们可以使用 Go 模块标志来允许 vendored 构建。我们可以使用`go mod vendor`来捕获`vendor/`目录中的所有依赖项，然后在构建时使用`go build -mod vendor`。

# 缓存和 vendoring 改进

为了看到我们可以通过构建和缓存资产进行的改进，让我们构建一个具有第三方依赖的项目。Prometheus[[`prometheus.io/`](https://prometheus.io/)]是一个流行的时间序列数据库（也是用 Go 编写的），通常用于指标收集和收集。我们可能希望在我们的任何应用程序中启动一个 Prometheus 指标服务器，以便从系统角度了解我们当前运行的二进制文件。为此，我们可以按如下方式导入 Prometheus 库：

```go
package main
import (
    "net/http"

    "github.com/prometheus/client_golang/prometheus/promhttp"
)

func main() {
    http.Handle("/promMetrics", promhttp.Handler())
    http.ListenAndServe(":1234", nil)
}
```

在我们在基本二进制文件中实例化`prometheus`服务器之后，我们可以构建我们的二进制文件并执行它。要对已经是最新的包执行强制重建，我们可以使用`go build`的`-a`标志。如果你想知道在我们超长的构建时间中到底花了多长时间，你也可以添加`-x`标志——它会给你一个非常详细的输出，说明构建过程中发生了什么。

默认情况下，较新版本的 Golang 将定义一个`GOCACHE`。您可以使用`go env GOCACHE`查看其位置。使用`GOCACHE`和 mod vendor 的组合，我们可以看到我们的构建时间显著提高了。列表中的第一个构建是冷构建，强制重新构建包以使其保持最新。我们的第二个构建，其中一些项目存储在 mod vendor 段中，要快得多。我们的第三个构建，应该有大部分构建元素被缓存，与之相比非常快。以下截图说明了这一点：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/hsn-hiperf-go/img/86acab39-2724-46f6-9fd2-3d35324715af.png)

# 调试

运行时内的调试包为我们提供了许多可用于调试的函数和类型。我们可以做到以下几点：

+   使用`FreeOSMemory()`强制进行垃圾收集。

+   使用`PrintStack()`打印在运行时生成的堆栈跟踪到 stderr。

+   使用`ReadGCStats()`读取我们的垃圾收集统计数据。

+   使用`SetGCPercent()`设置我们的垃圾收集百分比。

+   使用`SetMaxStack()`设置单个 goroutine 的最大堆栈大小。

+   使用`SetMaxThreads()`设置我们的最大 OS 线程数。

+   使用`SetPanicOndefault()`在意外地址故障时控制运行时行为。

+   使用`SetTraceback()`设置回溯的数量。

+   使用`Stack()`返回 goroutine 的堆栈跟踪。

+   使用`WriteHeapDump()`编写堆转储。

# PProf/race/trace

我们将在第十二章 *Go 代码性能分析*和第十三章 *Go 代码追踪*中详细介绍性能分析和追踪 Go 程序的细节。值得注意的是运行时库是这些实用程序的关键驱动程序。能够使用 pprof/race/trace 可以帮助您以有意义的方式调试代码，并能够找到新生错误。在下一节中，我们将学习运行时函数以及它们对 Go 运行时库的重要性。

# 理解函数

Go 运行时库还有一些函数，可以注入到程序的运行时中以发出运行时数据。让我们通过一些主要示例来了解一下。所有可用运行时函数的完整列表可以在[`golang.org/pkg/runtime/#pkg-index`](https://golang.org/pkg/runtime/#pkg-index)找到。这个包中提供的许多函数也包含在`runtime/pprof`包中，我们将在第十二章 *Go 代码性能分析*中更详细地进行调查。

# KeepAlive

`runtime.KeepAlive()`函数期望`interface{}`，并确保传递给它的对象不被释放，并且它的终结器（由`runtime.SetFinalizer`定义）不被运行。这使得传递给`KeepAlive`的参数可达。编译器设置了`OpKeepAlive`，如**静态单赋值**（SSA）包中所定义的（[`golang.org/src/cmd/compile/internal/gc/ssa.go#L2947`](https://golang.org/src/cmd/compile/internal/gc/ssa.go#L2947)）- 这使得编译器能够知道接口的状态作为一个变量，并允许保持保持活动的上下文。

作为一个经验法则，我们不应该在正常的实现中调用`KeepAlive`。它用于确保垃圾收集器不会从函数内部不再被引用的值中回收内存。

# NumCPU

`NumCPU`函数返回当前进程可用的逻辑 CPU 数量。当二进制文件被调用时，运行时会验证启动时可用的 CPU 数量。这个的一个简单示例可以在以下代码片段中找到：

```go
package main

import (
    "fmt"
    "runtime"
)

func main() {
    fmt.Println("Number of CPUs Available: ", runtime.NumCPU())
}
```

现在，我们可以看到当前进程可用的 CPU 数量。在我的情况下，这个值最终是`4`：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/hsn-hiperf-go/img/dc16f4e3-913e-4afb-8526-9aeae8522d04.png)

通过这个，我们可以看到我的计算机有 4 个可用于使用的 CPU。

# ReadMemStats

`ReadMemStats()`函数读取内存分配器统计信息并将其填充到一个变量中，比如`m`。`MemStats`结构体包含了关于内存利用的很多有价值的信息。让我们深入了解一下它可以为我们产生哪些值。一个允许我们查看二进制文件内存利用的 HTTP 处理程序函数可能会有所帮助，因为我们在系统中发出更多请求并希望看到我们的内存分配是在哪里被利用：

1.  首先，我们可以实例化程序和函数：

```go
package main

import (
    "fmt"
    "net/http"
    "runtime"
) 

func memStats(w http.ResponseWriter, r *http.Request) {
    var memStats runtime.MemStats
    runtime.ReadMemStats(&memStats)
```

1.  接下来，我们可以打印运行时提供给我们的各个内存统计值。让我们从`Alloc`、`Mallocs`和`Frees`开始：

```go
    fmt.Fprintln(w, "Alloc:", memStats.Alloc)
    fmt.Fprintln(w, "Total Alloc:", memStats.TotalAlloc)
    fmt.Fprintln(w, "Sys:", memStats.Sys)
    fmt.Fprintln(w, "Lookups:", memStats.Lookups)
    fmt.Fprintln(w, "Mallocs:", memStats.Mallocs)
    fmt.Fprintln(w, "Frees:", memStats.Frees)
```

1.  现在，让我们看一下堆信息：

```go
    fmt.Fprintln(w, "Heap Alloc:", memStats.HeapAlloc)
    fmt.Fprintln(w, "Heap Sys:", memStats.HeapSys)
    fmt.Fprintln(w, "Heap Idle:", memStats.HeapIdle)
    fmt.Fprintln(w, "Heap In Use:", memStats.HeapInuse)
    fmt.Fprintln(w, "Heap Released:", memStats.HeapReleased)
    fmt.Fprintln(w, "Heap Objects:", memStats.HeapObjects)
```

1.  接下来，我们将查看堆栈/跨度/缓存/桶分配：

```go
    fmt.Fprintln(w, "Stack In Use:", memStats.StackInuse)
    fmt.Fprintln(w, "Stack Sys:", memStats.StackSys)
    fmt.Fprintln(w, "MSpanInuse:", memStats.MSpanInuse)
    fmt.Fprintln(w, "MSpan Sys:", memStats.MSpanSys)
    fmt.Fprintln(w, "MCache In Use:", memStats.MCacheInuse)
    fmt.Fprintln(w, "MCache Sys:", memStats.MCacheSys)
    fmt.Fprintln(w, "Buck Hash Sys:", memStats.BuckHashSys)
```

1.  然后，我们查看垃圾收集信息：

```go
    fmt.Fprintln(w, "EnableGC:", memStats.EnableGC)
    fmt.Fprintln(w, "GCSys:", memStats.GCSys)
    fmt.Fprintln(w, "Other Sys:", memStats.OtherSys)
    fmt.Fprintln(w, "Next GC:", memStats.NextGC)
    fmt.Fprintln(w, "Last GC:", memStats.LastGC)
    fmt.Fprintln(w, "Num GC:", memStats.NumGC)
    fmt.Fprintln(w, "Num Forced GC:", memStats.NumForcedGC)
```

1.  现在，让我们看一下垃圾收集中断信息：

```go
    fmt.Fprintln(w, "Pause Total NS:", memStats.PauseTotalNs)
    fmt.Fprintln(w, "Pause Ns:", memStats.PauseNs)
    fmt.Fprintln(w, "Pause End:", memStats.PauseEnd)
    fmt.Fprintln(w, "GCCPUFraction:", memStats.GCCPUFraction)
    fmt.Fprintln(w, "BySize Size:", memStats.BySize)
```

1.  接下来，我们实例化一个简单的 HTTP 服务器：

```go
 func main() {
    http.HandleFunc("/", memStats)
    http.ListenAndServe(":1234", nil)
}
```

在这里，我们可以使用我们的 Apache bench 工具在我们的内存分配器上生成一些负载：

```go
ab -n 1000 -c 1000 http://localhost:1234/
```

最后，我们可以通过向`localhost:1234`发出请求来查看一些活动的 HTTP 服务器信息和响应：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/hsn-hiperf-go/img/b8fd2707-0f29-4394-9e95-fb667b359d75.png)

所有`MemStats`值的定义可以在文档中找到：[`golang.org/pkg/runtime/#MemStats`](https://golang.org/pkg/runtime/#MemStats)。

# 总结

在本章中，我们学习了`GODEBUG`、`GCTRACE`、`GOGC`、`GOMAXPROCS`和`GOTRACEBACK`运行时优化。我们还了解了`GOBUILDCACHE`和 Go 依赖项的供应。最后，我们学习了调试和从代码中调用运行时函数。在排除 Go 代码问题时使用这些技术将帮助您更容易地发现问题和瓶颈。

在下一章中，我们将讨论有效部署 Go 代码的正确方法。
