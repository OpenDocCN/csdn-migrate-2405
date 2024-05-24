# Go 编程蓝图（一）

> 原文：[`zh.annas-archive.org/md5/AC9839247134C458206EE3BE6D404A66`](https://zh.annas-archive.org/md5/AC9839247134C458206EE3BE6D404A66)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 前言

我决定写《Go 编程蓝图》是因为我想驱散一个谣言，即相对年轻的 Go 语言和社区不适合快速编写和迭代软件。我有一个朋友，他可以在一个周末内用 Ruby on Rails 开发完整的应用程序，通过混合现有的宝石和库；Rails 作为一个平台已经以其快速开发而闻名。由于我在 Go 和不断增长的开源软件包中也做到了同样的事情，我想分享一些真实世界的例子，展示我们如何可以快速构建和发布表现出色的软件，从第一天起就准备好扩展，这是 Rails 无法与之竞争的。当然，大多数的可扩展性发生在语言之外，但是像 Go 内置的并发性这样的特性意味着即使在最基本的硬件上，你也可以获得一些非常令人印象深刻的结果，这让你在事情开始变得真实时就能提前开始。

这本书探讨了五个非常不同的项目，其中任何一个都可以成为一个真正的创业基础。无论是低延迟的聊天应用程序、域名建议工具、建立在 Twitter 上的社交投票和选举服务，还是由 Google Places 提供支持的随机夜生活生成器，每一章都涉及大多数使用 Go 编写的产品或服务需要解决的各种问题。我在书中提出的解决方案只是解决每个项目的许多方法之一，我鼓励你自己对我如何解决它们做出自己的判断。概念比代码本身更重要，但你希望能够从中学到一些技巧和窍门，可以加入到你的 Go 工具包中。

我写这本书的过程可能会很有趣，因为它代表了许多敏捷开发者采用的一些哲学。我开始给自己一个挑战，即在深入研究并编写第一个版本之前，先构建一个真正可部署的产品（尽管是一个简单的产品；如果你愿意，可以称之为最小可行产品）。一旦我让它运行起来，我会从头开始重写它。小说家和记者们多次说过写作的艺术就是重写；我发现这对软件也是真实的。第一次我们写代码时，我们真正做的只是了解问题以及可能解决问题的方式，并将一些想法从我们的脑海中记录到纸上（或文本编辑器中）。第二次写代码时，我们将应用我们的新知识来真正解决问题。如果你从未尝试过这样做，试一试吧——你可能会发现，就像我一样，你的代码质量会显著提高。这并不意味着第二次就是最后一次——软件是不断演进的，我们应该尽量保持它的成本低廉和可替换性，这样如果某些部分过时或开始妨碍我们，我们也不介意将其丢弃。

我所有的代码都遵循测试驱动开发（TDD）的实践，其中一些我们将在章节中一起完成，而一些你只会在最终代码中看到结果。即使在印刷版中没有包含，所有的测试代码都可以在本书的 GitHub 存储库中找到。

一旦我完成了我的测试驱动的第二个版本，我会开始撰写描述我做了什么以及为什么这样做的章节。在大多数情况下，我采取的迭代方法被省略在书中，因为这只会增加页面的调整和编辑，这可能会让读者感到沮丧。然而，在一些情况下，我们将一起进行迭代，以了解渐进改进和小迭代的过程（从简单开始，只在绝对必要时引入复杂性）如何应用于编写 Go 软件包和程序。

我在 2012 年从英国搬到美国，但这并不是为什么这些章节以美式英语撰写的原因；这是出版商的要求。我想这本书是针对美国读者的，或者可能是因为美式英语是计算机的标准语言（在英国的代码中，处理颜色的属性是不带 U 拼写的）。无论如何，我提前为任何跨大西洋的差错道歉；我知道程序员有多么苛刻。

任何问题、改进、建议或辩论（我喜欢 Go 社区以及核心团队和语言本身的主张）都是非常欢迎的。这些可能最好在专门设置的书籍 GitHub 问题中进行，网址为[`github.com/matryer/goblueprints`](https://github.com/matryer/goblueprints)，以便每个人都可以参与。

最后，如果有人基于这些项目创建了一家初创公司，或者在其他地方利用了它们，我会感到非常兴奋。我很想听听这方面的消息；你可以在 Twitter 上@matryer 给我发消息，让我知道情况。

# 本书内容包括

第一章 ，*使用 Web 套接字的聊天应用程序*，展示了如何构建一个完整的 Web 应用程序，允许多人在其 Web 浏览器中进行实时对话。我们看到 net/http 包如何让我们提供 HTML 页面，并与客户端的浏览器建立 Web 套接字连接。

第二章 ，*添加身份验证*，展示了如何向我们的聊天应用程序添加 OAuth，以便我们可以跟踪谁说了什么，但让他们可以使用 Google、Facebook 或 GitHub 登录。

第三章 ，*实现个人资料图片的三种方式*，解释了如何向聊天应用程序添加个人资料图片，可以从身份验证服务、[Gravitar.com](http://Gravitar.com)网站获取，或者允许用户从硬盘上传自己的图片。

第四章 ，*用命令行工具查找域名*，探讨了在 Go 中构建命令行工具的简易性，并将这些技能应用于解决为我们的聊天应用程序找到完美域名的问题。它还探讨了 Go 语言如何轻松利用标准输入和标准输出管道来生成一些非常强大的可组合工具。

第五章 ，*构建分布式系统并处理灵活数据*，解释了如何通过 NSQ 和 MongoDB 构建高度可扩展的 Twitter 投票和计票引擎，为民主的未来做准备。

第六章 ，*通过 RESTful 数据 Web 服务 API 公开数据和功能*，介绍了如何通过 JSON Web 服务公开我们在第五章 中构建的功能，具体来说，是如何通过包装 http.HandlerFunc 函数来实现强大的管道模式。

第七章 ，*随机推荐 Web 服务*，展示了如何使用 Google Places API 来生成基于位置的随机推荐 API，这是探索任何地区的一种有趣方式。它还探讨了保持内部数据结构私有的重要性，控制对相同数据的公共视图，以及如何在 Go 中实现枚举器。

第八章，*文件系统备份*，帮助我们构建一个简单但功能强大的文件系统备份工具，用于我们的代码项目，并探索使用 Go 标准库中的 os 包与文件系统进行交互。它还探讨了 Go 的接口如何允许简单的抽象产生强大的结果。

附录，*稳定的 Go 环境的良好实践*，教会我们如何从头开始在新机器上安装 Go，并讨论了我们可能拥有的一些环境选项以及它们将来可能产生的影响。我们还将考虑协作如何影响我们的一些决定，以及开源我们的包可能产生的影响。

# 本书所需内容

要编译和运行本书中的代码，您需要一台能够运行支持 Go 工具集的操作系统的计算机，可以在[`golang.org/doc/install#requirements`](https://golang.org/doc/install#requirements)找到支持的操作系统列表。

附录，*稳定的 Go 环境的良好实践*，提供了一些有用的提示，包括如何安装 Go 并设置开发环境，以及如何使用 GOPATH 环境变量。

# 本书适合对象

本书适用于所有 Go 程序员——从想通过构建真实项目来探索该语言的初学者到对如何以有趣的方式应用该语言感兴趣的专家 gophers。

# 读累了记得休息一会哦~

**公众号：古德猫宁李**

+   电子书搜索下载

+   书单分享

+   书友学习交流

**网站：**[沉金书屋 https://www.chenjin5.com](https://www.chenjin5.com)

+   电子书搜索下载

+   电子书打包资源分享

+   学习资源分享

# 约定

在本书中，您会发现一些文本样式，用于区分不同类型的信息。以下是一些这些样式的示例及其含义的解释。

文本中的代码单词、数据库表名、文件夹名、文件名、文件扩展名、路径名、虚拟 URL、用户输入和 Twitter 用户名显示如下："我们可以使用`import`关键字从其他包中使用功能，之前我们使用`go get`来下载它们。"

代码块设置如下：

```go
package meander
type Cost int8
const (
  _ Cost = iota
  Cost1
  Cost2
  Cost3
  Cost4
  Cost5
)
```

当我们希望引起您对代码块的特定部分的注意时，相关行或项目会以粗体显示：

```go
package meander
type Cost int8
const (

_ Cost = iota

  Cost1
  Cost2
  Cost3
  Cost4
  Cost5
)
```

任何命令行输入或输出都会以以下方式书写：

```go

go build -o project && ./project

```

**新术语**和**重要单词**以粗体显示。您在屏幕上看到的单词，比如菜单或对话框中的单词，会以这样的方式出现在文本中："一旦安装了 Xcode，您就打开**首选项**，然后导航到**下载**部分。

### 注意

警告或重要提示会以这样的方式出现在一个框中。

### 提示

提示和技巧会以这种方式出现。


# 第一章：带有 Web 套接字的聊天应用程序

Go 非常适合编写高性能、并发的服务器应用程序和工具，而 Web 是传递它们的理想媒介。如今很难找到一个不支持 Web 的设备，并且允许我们构建一个针对几乎所有平台和设备的单一应用程序。

我们的第一个项目将是一个基于 Web 的聊天应用程序，允许多个用户在其 Web 浏览器中进行实时对话。成语化的 Go 应用程序通常由许多包组成，这些包通过在不同文件夹中放置代码来组织，Go 标准库也是如此。我们将首先使用`net/http`包构建一个简单的 Web 服务器，该服务器将提供 HTML 文件。然后，我们将继续添加对 Web 套接字的支持，通过它我们的消息将流动。

在诸如 C＃，Java 或 Node.js 之类的语言中，需要使用复杂的线程代码和巧妙地使用锁来保持所有客户端同步。正如我们将看到的，Go 通过其内置的通道和并发范例极大地帮助了我们。

在本章中，您将学习如何：

+   使用`net/http`包来提供 HTTP 请求

+   向用户的浏览器提供基于模板的内容

+   满足 Go 接口以构建我们自己的`http.Handler`类型

+   使用 Go 的 goroutines 允许应用程序同时执行多个任务

+   使用通道在运行的 Go 例程之间共享信息

+   升级 HTTP 请求以使用诸如 Web 套接字之类的现代功能

+   为应用程序添加跟踪，以更好地了解其内部工作原理

+   使用测试驱动开发实践编写完整的 Go 包

+   通过导出的接口返回未导出的类型

### 注意

此项目的完整源代码可以在[`github.com/matryer/goblueprints/tree/master/chapter1/chat`](https://github.com/matryer/goblueprints/tree/master/chapter1/chat)找到。源代码定期提交，因此 GitHub 中的历史实际上也遵循本章的流程。

# 一个简单的 Web 服务器

我们的聊天应用程序首先需要一个具有两个主要职责的 Web 服务器：它必须为在用户浏览器中运行的 HTML 和 JavaScript 聊天客户端提供服务，并接受 Web 套接字连接以允许客户端进行通信。

### 注意

`GOPATH`环境变量在附录中有详细介绍，*稳定的 Go 环境的良好实践*。如果您需要帮助设置，请务必先阅读。

在`GOPATH`中的新文件夹`chat`中创建一个`main.go`文件，并添加以下代码：

```go
package main

import (
  "log"
  "net/http"
)

func main() {

  http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
    w.Write([]byte(`
      <html>
        <head>
          <title>Chat</title>
        </head>
        <body>
          Let's chat!
        </body>
      </html>
    `))
  })
  // start the web server
  if err := http.ListenAndServe(":8080", nil); err != nil {
    log.Fatal("ListenAndServe:", err)
  }
}
```

这是一个完整但简单的 Go 程序，将会：

+   使用`net/http`包监听根路径

+   当请求被发出时，写出硬编码的 HTML

+   使用`ListenAndServe`方法在端口`:8080`上启动 Web 服务器

`http.HandleFunc`函数将路径模式`"/"`映射到我们作为第二个参数传递的函数，因此当用户访问`http://localhost:8080/`时，该函数将被执行。`func(w http.ResponseWriter, r *http.Request)`的函数签名是处理整个 Go 标准库中的 HTTP 请求的常见方式。

### 提示

我们使用`package main`，因为我们希望从命令行构建和运行我们的程序。然而，如果我们正在构建一个可重用的聊天包，我们可能会选择使用不同的东西，比如`package chat`。

在终端中，通过导航到您刚创建的`main.go`文件并执行以下命令来运行程序：

```go

go run main.go

```

打开浏览器到`localhost:8080`，看到**让我们聊天！**消息。

像这样将 HTML 代码嵌入到我们的 Go 代码中是有效的，但它非常丑陋，并且随着我们的项目增长，情况只会变得更糟。接下来，我们将看到模板如何帮助我们清理这些内容。

## 模板

模板允许我们将通用文本与特定文本混合在一起，例如，将用户的姓名注入欢迎消息中。例如，考虑以下模板：

```go
Hello {name}, how are you?
```

我们能够用真实的人名替换前面模板中的`{name}`文本。所以如果 Laurie 登录，她可能会看到：

```go
Hello Laurie, how are you?
```

Go 标准库有两个主要的模板包：一个叫做`text/template`用于文本，另一个叫做`html/template`用于 HTML。`html/template`包与文本版本相同，只是它了解数据将被注入模板的上下文。这很有用，因为它避免了脚本注入攻击，并解决了诸如必须对 URL 编码特殊字符之类的常见问题。

最初，我们只想将 HTML 代码从我们的 Go 代码中移动到自己的文件中，但暂时不混合任何文本。模板包使加载外部文件非常容易，所以这对我们来说是一个不错的选择。

在我们的`chat`文件夹下创建一个名为`templates`的新文件夹，并在其中创建一个名为`chat.html`的文件。我们将 HTML 从`main.go`移动到这个文件中，但我们将进行一些小的更改，以确保我们的更改已生效。

```go
<html>
  <head>
    <title>Chat</title>
  </head>
  <body>
    Let's chat 
(from template)

  </body>
</html>
```

现在，我们已经准备好使用外部 HTML 文件，但我们需要一种方法来编译模板并将其提供给用户的浏览器。

### 提示

编译模板是一个过程，通过这个过程，源模板被解释并准备好与各种数据混合，这必须在模板可以使用之前发生，但只需要发生一次。

我们将编写自己的`struct`类型，负责加载、编译和传递我们的模板。我们将定义一个新类型，它将接受一个`filename`字符串，一次编译模板（使用`sync.Once`类型），保持对编译模板的引用，然后响应 HTTP 请求。您需要导入`text/template`、`path/filepath`和`sync`包来构建您的代码。

在`main.go`中，在`func main()`行上面插入以下代码：

```go
// templ represents a single template
type templateHandler struct {
  once     sync.Once
  filename string
  templ    *template.Template
}
// ServeHTTP handles the HTTP request.
func (t *templateHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
  t.once.Do(func() {
    t.templ = template.Must(template.ParseFiles(filepath.Join("templates", t.filename)))
  })
  t.templ.Execute(w, nil)
}
```

### 提示

您知道您可以自动添加和删除导入的包吗？请参阅附录，*稳定 Go 环境的良好实践*，了解如何做到这一点。

`templateHandler`类型有一个名为`ServeHTTP`的单一方法，其签名看起来很像我们之前传递给`http.HandleFunc`的方法。这个方法将加载源文件，编译模板并执行它，并将输出写入指定的`http.ResponseWriter`对象。因为`ServeHTTP`方法满足`http.Handler`接口，我们实际上可以直接将它传递给`http.Handle`。

### 提示

快速查看位于[`golang.org/pkg/net/http/#Handler`](http://golang.org/pkg/net/http/#Handler)的 Go 标准库源代码，将会发现`http.Handler`的接口定义规定了只有`ServeHTTP`方法需要存在，才能使类型用于通过`net/http`包来提供 HTTP 请求。

### 只做一次的事情

我们只需要一次编译模板，Go 中有几种不同的方法可以实现这一点。最明显的方法是有一个`NewTemplateHandler`函数来创建类型并调用一些初始化代码来编译模板。如果我们确信该函数只会被一个 goroutine 调用（可能是`main`函数中的主要函数），那么这将是一个完全可以接受的方法。另一种方法是在`ServeHTTP`方法内部编译模板一次，这是我们在前面的部分中采用的方法。`sync.Once`类型保证我们传递为参数的函数只会被执行一次，不管有多少 goroutine 在调用`ServeHTTP`。这很有帮助，因为 Go 中的 Web 服务器是自动并发的，一旦我们的聊天应用席卷世界，我们很可能会有许多并发调用`ServeHTTP`方法。

在`ServeHTTP`方法中编译模板还确保我们的代码在绝对需要之前不会浪费时间。这种懒惰的初始化方法在我们目前的情况下并没有节省太多时间，但在设置任务耗时和资源密集的情况下，并且功能使用频率较低的情况下，很容易看出这种方法会派上用场。

### 使用自己的处理程序

为了实现我们的`templateHandler`类型，我们需要更新`main`主体函数，使其看起来像这样：

```go
func main() {
  // root

http.Handle("/", &templateHandler{filename: "chat.html"})

  // start the web server
  if err := http.ListenAndServe(":8080", nil); err != nil {
    log.Fatal("ListenAndServe:", err)
  }
}
```

`templateHandler`结构是有效的`http.Handler`类型，因此我们可以直接将其传递给`http.Handle`函数，并要求它处理与指定模式匹配的请求。在前面的代码中，我们创建了一个`templateHandler`类型的新对象，指定文件名为`chat.html`，然后取其地址（使用`&` **地址**运算符）并将其传递给`http.Handle`函数。我们不存储对新创建的`templateHandler`类型的引用，但这没关系，因为我们不需要再次引用它。

在终端中，按下*Ctrl* + *C*退出程序，然后刷新您的浏览器，注意添加了（来自模板）文本。现在我们的代码比 HTML 代码简单得多，没有那些丑陋的块。

## 正确构建和执行 Go 程序

使用`go run`命令运行 Go 程序时，当我们的代码由单个`main.go`文件组成时非常方便。然而，通常我们可能需要快速添加其他文件。这要求我们在运行之前将整个包正确构建为可执行二进制文件。这很简单，从现在开始，这就是您将在终端中构建和运行程序的方式：

```go

go build -o {name}

./{name}

```

`go build`命令使用指定文件夹中的所有`.go`文件创建输出二进制文件，`-o`标志指示生成的二进制文件的名称。然后，您只需通过名称调用程序直接运行程序。

例如，在我们的聊天应用程序中，我们可以运行：

```go

go build -o chat

./chat

```

由于我们在首次提供页面时编译模板，因此每次发生更改时，我们都需要重新启动您的 Web 服务器程序，以查看更改生效。

# 在服务器上建模聊天室和客户端

我们聊天应用程序的所有用户（客户端）将自动放置在一个大的公共房间中，每个人都可以与其他人聊天。`room`类型将负责管理客户端连接并路由消息进出，而`client`类型表示与单个客户端的连接。

### 提示

Go 将类称为类型，将这些类的实例称为对象。

为了管理我们的网络套接字，我们将使用 Go 社区最强大的一个方面——开源第三方包。每天都会发布解决现实问题的新包，供您在自己的项目中使用，甚至允许您添加功能，报告和修复错误，并获得支持。

### 提示

重新发明轮子通常是不明智的，除非您有非常好的理由。因此，在着手构建新包之前，值得搜索可能已经解决了您的问题的任何现有项目。如果找到一个类似的项目，但不完全满足您的需求，请考虑为该项目添加功能。Go 拥有一个特别活跃的开源社区（请记住 Go 本身也是开源的），随时欢迎新面孔或头像。

我们将使用 Gorilla Project 的`websocket`包来处理我们的服务器端套接字，而不是编写我们自己的。如果您对它的工作原理感到好奇，请转到 GitHub 上的项目主页，[`github.com/gorilla/websocket`](https://github.com/gorilla/websocket)，并浏览开源代码。

## 建模客户端

在`chat`文件夹中的`main.go`旁边创建一个名为`client.go`的新文件，并添加以下代码：

```go
package main
import (
  "github.com/gorilla/websocket"
)
// client represents a single chatting user.
type client struct {
  // socket is the web socket for this client.
  socket *websocket.Conn
  // send is a channel on which messages are sent.
  send chan []byte
  // room is the room this client is chatting in.
  room *room
}
```

在前面的代码中，套接字将保存一个与客户端通信的网络套接字的引用，`send`字段是一个缓冲通道，通过它接收到的消息排队准备转发到用户的浏览器（通过套接字）。`room`字段将保留客户端正在聊天的房间的引用——这是必需的，以便我们可以将消息转发给房间中的其他所有人。

如果您尝试构建此代码，您将注意到一些错误。您必须确保已调用`go get`来检索`websocket`包，这很容易，只需打开终端并输入以下内容：

```go

go get github.com/gorilla/websocket

```

再次构建代码将产生另一个错误：

```go

./client.go:17 undefined: room

```

问题在于我们引用了一个未定义的`room`类型。为了让编译器满意，创建一个名为`room.go`的文件，并插入以下占位符代码：

```go
package main
type room struct {
  // forward is a channel that holds incoming messages
  // that should be forwarded to the other clients.
  forward chan []byte
}
```

一旦我们了解了房间需要做什么，我们将稍后改进这个定义，但现在这将允许我们继续。稍后，`forward`通道将用于将传入的消息发送到所有其他客户端。

### 注意

您可以将通道视为内存中的线程安全消息队列，发送者通过非阻塞的线程安全方式传递数据，接收者读取数据。

为了让客户端执行任何工作，我们必须定义一些方法，这些方法将实际读取和写入到网络套接字。将以下代码添加到`client.go`之外（在`client`结构下方）将向`client`类型添加名为`read`和`write`的两个方法：

```go
func (c *client) read() {
  for {
    if _, msg, err := c.socket.ReadMessage(); err == nil {
      c.room.forward <- msg
    } else {
      break
    }
  }
  c.socket.Close()
}
func (c *client) write() {
  for msg := range c.send {
    if err := c.socket.WriteMessage(websocket.TextMessage, msg); err != nil {
      break
    }
  }
  c.socket.Close()
}
```

`read`方法允许我们的客户端通过`ReadMessage`方法从套接字中读取，不断将接收到的任何消息发送到`room`类型的`forward`通道。如果遇到错误（例如“套接字已断开”），循环将中断并关闭套接字。类似地，`write`方法不断接受`send`通道的消息，通过`WriteMessage`方法将所有内容写入套接字。如果向套接字写入失败，`for`循环将中断并关闭套接字。再次构建包以确保一切都编译。

## 建模一个房间

我们需要一种方法让客户端加入和离开房间，以确保前面部分中的`c.room.forward <- msg`代码实际上将消息转发给所有客户端。为了确保我们不会同时尝试访问相同的数据，一个明智的方法是使用两个通道：一个用于向房间添加客户端，另一个用于将其删除。让我们更新我们的`room.go`代码如下：

```go
package main

type room struct {

  // forward is a channel that holds incoming messages
  // that should be forwarded to the other clients.
  forward chan []byte
  // join is a channel for clients wishing to join the room.
  join chan *client
  // leave is a channel for clients wishing to leave the room.
  leave chan *client
  // clients holds all current clients in this room.
  clients map[*client]bool
}
```

我们添加了三个字段：两个通道和一个映射。`join`和`leave`通道存在的简单目的是允许我们安全地向`clients`映射中添加和删除客户端。如果我们直接访问映射，可能会出现两个同时运行的 Go 例程同时尝试修改映射，导致内存损坏或不可预测的状态。

## 使用符合惯例的 Go 并发编程

现在我们可以使用 Go 并发提供的一个非常强大的功能——`select`语句。我们可以在需要同步或修改共享内存，或根据通道内的各种活动采取不同的操作时使用`select`语句。

在`room`结构下方，添加包含两个`select`子句的`run`方法：

```go
func (r *room) run() {
  for {
    select {
    case client := <-r.join:
      // joining
      r.clients[client] = true
    case client := <-r.leave:
      // leaving
      delete(r.clients, client)
      close(client.send)
    case msg := <-r.forward:
      // forward message to all clients
      for client := range r.clients {
        select {
        case client.send <- msg:
          // send the message
        default:
          // failed to send
          delete(r.clients, client)
          close(client.send)
        }
      }
    }
  }
}
```

尽管这可能看起来是很多代码要消化，但一旦我们稍微分解一下，我们就会发现它其实相当简单，尽管非常强大。顶部的`for`循环表示这个方法将一直运行，直到程序被终止。这可能看起来像是一个错误，但请记住，如果我们将这段代码作为 Go 例程运行，它将在后台运行，不会阻塞我们应用程序的其余部分。前面的代码将一直监视我们房间内的三个通道：`join`，`leave`和`forward`。如果在这些通道中收到消息，`select`语句将运行特定情况的代码块。重要的是要记住，它一次只会运行一个 case 代码块。这就是我们能够同步以确保我们的`r.clients`地图一次只能被一件事情修改的方式。

如果我们在`join`通道上收到消息，我们只需更新`r.clients`地图以保留已加入房间的客户端的引用。请注意，我们将值设置为`true`。我们使用地图更像是一个切片，但不必担心随着时间的推移客户端的增减而收缩切片 - 将值设置为`true`只是一种方便的、低内存的存储引用的方式。

如果我们在`leave`通道上收到消息，我们只需从地图中删除`client`类型，并关闭其`send`通道。关闭通道在 Go 语言中具有特殊的意义，当我们看到最终的`select`语句时，这一点就变得很清楚了。

如果我们在`forward`通道上收到消息，我们会遍历所有客户端，并将消息发送到每个客户端的发送通道。然后，我们的客户端类型的`write`方法将接收并将其发送到浏览器的套接字。如果`send`通道关闭，那么我们知道客户端不再接收任何消息，这就是我们的第二个`select`子句（特别是默认情况）采取的移除客户端并整理事情的操作。

## 将房间转换为 HTTP 处理程序

现在我们将把我们的`room`类型转换为`http.Handler`类型，就像我们之前对模板处理程序所做的那样。您会记得，为了做到这一点，我们只需添加一个名为`ServeHTTP`的方法，具有适当的签名。将以下代码添加到`room.go`文件的底部：

```go
const (
  socketBufferSize  = 1024
  messageBufferSize = 256
)
var upgrader = &websocket.Upgrader{ReadBufferSize: socketBufferSize, WriteBufferSize: socketBufferSize}
func (r *room) ServeHTTP(w http.ResponseWriter, req *http.Request) {
  socket, err := upgrader.Upgrade(w, req, nil)
  if err != nil {
    log.Fatal("ServeHTTP:", err)
    return
  }
  client := &client{
    socket: socket,
    send:   make(chan []byte, messageBufferSize),
    room:   r,
  }
  r.join <- client
  defer func() { r.leave <- client }()
  go client.write()
  client.read()
}
```

`ServeHTTP`方法意味着房间现在可以作为处理程序。我们很快将实现它，但首先让我们看看这段代码中发生了什么。

为了使用 Web 套接字，我们必须使用`websocket.Upgrader`类型升级 HTTP 连接，该类型是可重用的，因此我们只需要创建一个。然后，当请求通过`ServeHTTP`方法进入时，我们通过调用`upgrader.Upgrade`方法获取套接字。一切顺利的话，我们就创建客户端并将其传递到当前房间的`join`通道中。我们还推迟了客户端完成后的离开操作，这将确保用户离开后一切都整理得很好。

然后，客户端的`write`方法被调用为 Go 例程，如行首的三个字符所示`go`（单词`go`后跟一个空格字符）。这告诉 Go 在不同的线程或 goroutine 中运行该方法。

### 注意

比较在其他语言中实现多线程或并发所需的代码量与在 Go 中实现它的三个关键按键，您会发现为什么它已经成为系统开发人员中的最爱。

最后，我们在主线程中调用`read`方法，它将阻塞操作（保持连接活动），直到关闭连接的时候。在代码片段的顶部添加常量是一个很好的做法，用于声明在整个项目中原本将硬编码的值。随着这些值的增加，您可能会考虑将它们放在自己的文件中，或者至少放在各自文件的顶部，以便保持易读易修改。

## 使用辅助函数来减少复杂性

我们的房间几乎可以使用了，尽管为了让它有用，需要创建频道和地图。目前，可以通过要求开发者使用以下代码来实现这一点：

```go
r := &room{
  forward: make(chan []byte),
  join:    make(chan *client),
  leave:   make(chan *client),
  clients: make(map[*client]bool),
}
```

另一个稍微更加优雅的解决方案是提供一个`newRoom`函数来代替。这样就不需要其他人知道确切需要做什么才能让我们的房间有用。在`type room struct`的定义下面，添加这个函数：

```go
// newRoom makes a new room that is ready to go.
func newRoom() *room {
  return &room{
    forward: make(chan []byte),
    join:    make(chan *client),
    leave:   make(chan *client),
    clients: make(map[*client]bool),
  }
}
```

现在，我们的代码用户只需要调用`newRoom`函数，而不是更冗长的六行代码。

## 创建和使用房间

让我们更新`main.go`中的`main`函数，首先创建，然后运行一个房间，让每个人都可以连接到：

```go
func main() {
  r := newRoom()
  http.Handle("/", &templateHandler{filename: "chat.html"})
  http.Handle("/room", r)
  // get the room going
  go r.run()
  // start the web server
  if err := http.ListenAndServe(":8080", nil); err != nil {
    log.Fatal("ListenAndServe:", err)
  }
}
```

我们在一个单独的 Go 例程中运行房间（再次注意`go`关键字），以便聊天操作在后台进行，使我们的主线程运行 Web 服务器。我们的服务器现在已经完成并成功构建，但没有客户端进行交互，它仍然是无用的。

# 构建 HTML 和 JavaScript 聊天客户端

为了让我们的聊天应用程序的用户与服务器以及其他用户进行交互，我们需要编写一些客户端代码，利用现代浏览器中的 Web 套接字。当用户访问我们应用程序的根目录时，我们已经通过模板传递 HTML 内容，所以我们可以增强它。

使用以下标记更新`templates`文件夹中的`chat.html`文件：

```go
<html>
  <head>
    <title>Chat</title>
    <style>
      input { display: block; }
      ul    { list-style: none; }
    </style>
  </head>
  <body>
    <ul id="messages"></ul>
    <form id="chatbox">
      <textarea></textarea>
      <input type="submit" value="Send" />
       </form>  </body>
</html>
```

上述的 HTML 将在页面上呈现一个简单的网络表单，其中包含一个文本区域和一个“发送”按钮——这是我们的用户将消息提交到服务器的方式。上述代码中的`messages`元素将包含聊天消息的文本，以便所有用户都能看到正在说什么。接下来，我们需要添加一些 JavaScript 来为我们的页面添加一些功能。在`form`标签下，在闭合的`</body>`标签上面，插入以下代码：

```go
    <script src="img/jquery.min.js"></script>
    <script>
      $(function(){
        var socket = null;
        var msgBox = $("#chatbox textarea");
        var messages = $("#messages");
        $("#chatbox").submit(function(){
          if (!msgBox.val()) return false;
          if (!socket) {
            alert("Error: There is no socket connection.");
            return false;
          }
          socket.send(msgBox.val());
          msgBox.val("");
          return false;
        });
        if (!window["WebSocket"]) {
          alert("Error: Your browser does not support web sockets.")
        } else {
          socket = new WebSocket("ws://localhost:8080/room");
          socket.onclose = function() {
            alert("Connection has been closed.");
          }
          socket.onmessage = function(e) {
            messages.append($("<li>").text(e.data));
          }
        }
      });
    </script>
```

`socket = new WebSocket("ws://localhost:8080/room")`这一行是我们打开套接字并为两个关键事件`onclose`和`onmessage`添加事件处理程序的地方。当套接字接收到消息时，我们使用 jQuery 将消息附加到列表元素，从而呈现给用户。

提交 HTML 表单触发对`socket.send`的调用，这是我们向服务器发送消息的方式。

再次构建和运行程序，以确保模板重新编译，以便这些更改得到体现。

在两个不同的浏览器（或同一个浏览器的两个标签）中导航到`http://localhost:8080/`并使用应用程序。您会注意到从一个客户端发送的消息立即出现在其他客户端中。

![构建 HTML 和 JavaScript 聊天客户端](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/go-prog-bp/img/Image00001.jpg)

## 更多地利用模板

目前，我们正在使用模板传递静态 HTML，这很好，因为它为我们提供了一种清晰简单的方法来将客户端代码与服务器代码分离。然而，模板实际上更加强大，我们将调整我们的应用程序以更加现实地使用它们。

我们应用程序的主机地址（`:8080`）目前在两个地方都是硬编码的。第一个实例是在`main.go`中启动 Web 服务器的地方：

```go
if err := http.ListenAndServe("
:8080

", nil); err != nil {
  log.Fatal("ListenAndServe:", err)
}
```

第二次是在 JavaScript 中硬编码的，当我们打开套接字时：

```go
socket = new WebSocket("ws://
localhost:8080

/room");
```

我们的聊天应用程序非常固执，坚持只在本地端口`8080`上运行，因此我们将使用命令行标志使其可配置，然后使用模板的注入功能确保我们的 JavaScript 知道正确的主机。

更新`main.go`中的`main`函数：

```go
func main() {  

var addr = flag.String("addr", ":8080", "The addr of the application.")

flag.Parse() // parse the flags

  r := newRoom()
  http.Handle("/", &templateHandler{filename: "chat.html"})
  http.Handle("/room", r)
  // get the room going
  go r.run()
  // start the web server

log.Println("Starting web server on", *addr)

  if err := http.ListenAndServe(
*addr

, nil); err != nil {
    log.Fatal("ListenAndServe:", err)
  }
}
```

为了使此代码构建，您需要导入`flag`包。`addr`变量的定义将我们的标志设置为一个默认为`:8080`的字符串（并简要描述了该值的用途）。我们必须调用`flag.Parse()`来解析参数并提取适当的信息。然后，我们可以通过使用`*addr`引用主机标志的值。

### 注意

对`flag.String`的调用返回`*string`类型，也就是说它返回存储标志值的字符串变量的地址。要获取值本身（而不是值的地址），我们必须使用指针间接操作符`*`。

我们还添加了一个`log.Println`调用，以在终端中输出地址，以确保我们的更改已生效。

我们将修改我们编写的`templateHandler`类型，以便将请求的详细信息作为数据传递到模板的`Execute`方法中。在`main.go`中，更新`ServeHTTP`函数，将请求`r`作为`data`参数传递给`Execute`方法：

```go
func (t *templateHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
  t.once.Do(func() {
    t.templ = template.Must(template.ParseFiles(filepath.Join("templates", t.filename)))
  })

t.templ.Execute(w, r)

}
```

这告诉模板使用可以从`http.Request`中提取的数据进行渲染，其中包括我们需要的主机地址。

要使用`http.Request`的`Host`值，我们可以利用特殊的模板语法来注入数据。更新我们在`chat.html`文件中创建套接字的行：

```go
socket = new WebSocket("ws://{{.Host}}/room");
```

双花括号表示注释，告诉模板源注入数据的方式。`{{.Host}}`本质上等同于告诉它用`request.Host`的值替换注释（因为我们将请求`r`对象作为数据传递）。

### 提示

我们只是初步了解了 Go 标准库中内置模板的强大功能。`text/template`包的文档是了解更多内容的好地方。您可以在[`golang.org/pkg/text/template`](http://golang.org/pkg/text/template)找到更多信息。

重新构建并再次运行聊天程序，但是这次请注意，无论我们指定哪个主机，聊天操作都不再产生错误：

```go
go build -o chat
./chat -addr=":3000"
```

在浏览器中查看页面源代码，注意`{{.Host}}`已被实际应用的主机替换。有效的主机不仅仅是端口号；您还可以指定 IP 地址或其他主机名——只要它们在您的环境中被允许，例如`-addr="192.168.0.1:3000"`。

# 跟踪代码以深入了解内部情况

我们唯一知道我们的应用程序是否工作的方法是打开两个或更多浏览器，并使用我们的 UI 发送消息。换句话说，我们正在手动测试我们的代码。这对于实验性项目（如我们的聊天应用程序）或不希望增长的小项目来说是可以接受的，但是如果我们的代码要有更长的寿命或由多个人共同开发，这种手动测试就成了一种负担。我们不打算为我们的聊天程序解决**测试驱动开发**（**TDD**），但我们应该探索另一种有用的调试技术，称为**跟踪**。

跟踪是一种实践，通过它我们可以记录或打印程序流程中的关键步骤，以使程序内部发生的事情可见。在前一节中，我们添加了一个`log.Println`调用来输出聊天程序绑定到的地址。在本节中，我们将正式化这一过程，并编写我们自己完整的跟踪包。

我们将探索 TDD 实践，因为编写跟踪代码是一个完美的例子，我们很可能会重用、添加、共享，甚至开源。

## 使用 TDD 编写包

Go 中的包被组织到文件夹中，每个文件夹一个包。在同一个文件夹中有不同的包声明会导致构建错误，因为所有同级文件都被期望为单个包做出贡献。Go 没有子包的概念，这意味着嵌套包（在嵌套文件夹中）只存在于美学或信息上的原因，但不会继承任何功能或可见性。在我们的聊天应用中，所有文件都属于`main`包，因为我们想要构建一个可执行工具。我们的追踪包永远不会直接运行，因此可以并且应该使用不同的包名。我们还需要考虑我们包的**应用程序编程接口**（**API**），考虑如何建模一个包，使其对用户来说尽可能具有可扩展性和灵活性。这包括应该导出（对用户可见）的字段、函数、方法和类型，以及为简单起见应该保持隐藏的内容。

### 注意

Go 使用名称的大写来表示哪些项目是导出的，以便以大写字母开头的名称（例如`Tracer`）对包的用户可见，以小写字母开头的名称（例如`templateHandler`）是隐藏或私有的。

在`chat`文件夹旁边创建一个名为`trace`的新文件夹，这将是我们追踪包的名称。

在我们开始编码之前，让我们就我们包的一些设计目标达成一致，以便衡量成功：

+   包应该易于使用

+   单元测试应该覆盖功能

+   用户应该有灵活性来用自己的实现替换追踪器

### 接口

Go 语言中的接口是一种非常强大的语言特性，它允许我们定义一个 API 而不严格或具体地定义实现细节。在可能的情况下，使用接口描述包的基本构建块通常会在未来产生回报，这也是我们追踪包的起点。

在`trace`文件夹内创建一个名为`tracer.go`的新文件，并写入以下代码：

```go
package trace
// Tracer is the interface that describes an object capable of
// tracing events throughout code.
type Tracer interface {
  Trace(...interface{})
}
```

首先要注意的是，我们将包定义为`trace`。

### 注意

虽然将文件夹名称与包名称匹配是一个好习惯，但 Go 工具不强制执行这一点，这意味着如果有意义，你可以自由地给它们命名不同的名称。记住，当人们导入你的包时，他们会输入文件夹的名称，如果突然导入了一个不同名称的包，可能会让人困惑。

我们的`Tracer`类型（大写的`T`表示我们打算将其作为公开可见类型）是一个描述单个名为`Trace`的方法的接口。`...interface{}`参数类型表示我们的`Trace`方法将接受零个或多个任意类型的参数。你可能会认为这是多余的，因为该方法应该只接受一个字符串（我们只想追踪一些字符的字符串，不是吗？）。然而，考虑到`fmt.Sprint`和`log.Fatal`等函数，它们都遵循了 Go 标准库中的一种模式，提供了一个有用的快捷方式，用于一次性传递多个内容。在可能的情况下，我们应该遵循这样的模式和实践，因为我们希望我们自己的 API 对 Go 社区来说是熟悉和清晰的。

### 单元测试

我们答应自己要遵循测试驱动的实践，但接口只是定义，不提供任何实现，因此无法直接进行测试。但我们即将编写一个`Tracer`方法的真正实现，并且我们确实会先编写测试。

在`trace`文件夹中创建一个名为`tracer_test.go`的新文件，并插入以下框架代码：

```go
package trace
import (
  "testing"
)
func TestNew(t *testing.T) {
  t.Error("We haven't written our test yet")
}
```

测试是从一开始就内置在 Go 工具链中的，使得编写可自动化测试成为一等公民。测试代码与生产代码一起存放在以`_test.go`结尾的文件中。Go 工具将把任何以`Test`开头的函数（接受一个`*testing.T`参数）视为单元测试，并在运行测试时执行它们。要为此包运行它们，请在终端中导航到`trace`文件夹并执行以下操作：

```go

go test

```

您会看到我们的测试失败，因为我们在`TestNew`函数的主体中调用了`t.Error`：

```go

--- FAIL: TestNew (0.00 seconds)

 tracer_test.go:8: We haven't written our test yet

FAIL

exit status 1

FAIL  trace        0.011s

```

### 提示

在每次测试运行之前清除终端是一个很好的方法，可以确保您不会将之前的运行与最近的运行混淆。在 Windows 上，您可以使用`cls`命令；在 Unix 机器上，`clear`命令可以做同样的事情。

显然，我们没有正确地编写我们的测试，我们也不希望它通过，所以让我们更新`TestNew`函数：

```go
func TestNew(t *testing.T) {

 var buf bytes.Buffer

 tracer := New(&buf)

 if tracer == nil {

 t.Error("Return from New should not be nil")

 } else {

 tracer.Trace("Hello trace package.")

 if buf.String() != "Hello trace package.\n" {

 t.Errorf("Trace should not write '%s'.", buf.String())

 }

 }

}
```

本书中的大多数包都来自 Go 标准库，因此您可以添加适当的包的`import`语句以访问该包。其他包是外部的，这时您需要使用`go get`来下载它们，然后才能导入。对于这种情况，您需要在文件顶部添加`import "bytes"`。

我们已经开始通过成为第一个用户来设计我们的 API。我们希望能够在`bytes.Buffer`中捕获我们的跟踪器的输出，以便我们可以确保缓冲区中的字符串与预期值匹配。如果不匹配，对` t.Errorf`的调用将使测试失败。在此之前，我们检查一下虚构的`New`函数的返回值是否不是`nil`；同样，如果是，测试将因为对` t.Error`的调用而失败。

### 红绿测试

现在运行`go test`实际上会产生一个错误；它抱怨没有`New`函数。我们没有犯错；我们正在遵循一种被称为红绿测试的实践。红绿测试建议我们首先编写一个单元测试，看到它失败（或产生错误），然后编写尽可能少的代码使该测试通过，并重复这个过程。这里的关键点是我们要确保我们添加的代码实际上正在做一些事情，并确保我们编写的测试代码正在测试一些有意义的东西。

### 注意

考虑一分钟的无意义测试：

```go
if true == true {
  t.Error("True should be true")
}
```

逻辑上不可能让 true 不等于 true（如果 true 等于 false，那么是时候换台新电脑了），因此我们的测试是毫无意义的。如果测试或声明不能失败，那么它就毫无价值。

将`true`替换为一个您希望在特定条件下设置为`true`的变量，这意味着这样的测试确实可能失败（比如在被测试的代码行为不当时）——在这一点上，您有一个值得为代码库做出贡献的有意义的测试。

您可以将`go test`的输出视为待办事项列表，一次只解决一个问题。现在，我们只会解决有关缺少`New`函数的投诉。在`trace.go`文件中，让我们添加尽可能少的代码来继续进行；在接口类型定义下面添加以下代码片段：

```go
func New() {}
```

现在运行`go test`会显示事情确实有所进展，尽管进展不是很大。我们现在有两个错误：

```go

./tracer_test.go:11: too many arguments in call to New

./tracer_test.go:11: New(&buf) used as value

```

第一个错误告诉我们，我们正在向我们的`New`函数传递参数，但`New`函数不接受任何参数。第二个错误说我们正在使用`New`函数的返回值作为值，但`New`函数并不返回任何东西。您可能已经预料到了这一点，确实随着您在编写测试驱动的代码方面获得更多经验，您很可能会跳过这样的琐事。但是，为了正确地说明这种方法，我们将要有一段时间的迂腐。让我们通过更新我们的`New`函数来解决第一个错误：

```go
func New(w io.Writer) {}
```

我们正在接收一个满足`io.Writer`接口的参数，这意味着指定的对象必须有一个合适的`Write`方法。

### 注意

使用现有接口，特别是在 Go 标准库中找到的接口，是确保您的代码尽可能灵活和优雅的一种极其强大且经常必要的方式。

接受`io.Writer`意味着用户可以决定跟踪输出将写入何处。这个输出可以是标准输出，文件，网络套接字，`bytes.Buffer`，甚至是一些自定义对象，只要它实现了`io.Writer`接口的`Write`方法。

再次运行`go test`显示我们已解决第一个错误，我们只需要添加一个返回类型以继续通过第二个错误：

```go
func New(w io.Writer) Tracer {}
```

我们声明我们的`New`函数将返回一个`Tracer`，但我们没有返回任何东西，这让`go test`很高兴地抱怨：

```go

./tracer.go:13: missing return at end of function

```

修复这很容易；我们可以从`New`函数中返回`nil`：

```go
func New(w io.Writer) Tracer {
  return nil
}
```

当然，我们的测试代码已经断言返回值不应该是`nil`，所以`go test`现在给我们一个失败消息：

```go

tracer_test.go:14: Return from New should not be nil

```

### 注意

你可以看到严格遵循红绿原则可能有点乏味，但非常重要的是我们不要跳得太远。如果我们一次写很多实现代码，很可能会有代码没有被单元测试覆盖。

体贴的核心团队甚至通过提供代码覆盖率统计数据来解决了这个问题，我们可以通过运行以下命令生成：

```go
go test -cover
```

只要所有测试通过，添加`-cover`标志将告诉我们在执行测试期间有多少代码被触及。显然，我们越接近 100%越好。

### 实现接口

为了满足这个测试，我们需要一个可以从`New`方法中正确返回的东西，因为`Tracer`只是一个接口，我们必须返回一些真实的东西。让我们在`tracer.go`文件中添加一个 tracer 的实现：

```go
type tracer struct {
  out io.Writer
}

func (t *tracer) Trace(a ...interface{}) {}
```

我们的实现非常简单；`tracer`类型有一个名为`out`的`io.Writer`字段，我们将把跟踪输出写入其中。`Trace`方法与`Tracer`接口所需的方法完全匹配，尽管它目前什么也不做。

现在我们终于可以修复`New`方法了：

```go
func New(w io.Writer) Tracer {
  return &tracer{out: w}
}
```

再次运行`go test`显示我们的期望没有达到，因为在调用`Trace`时没有写入任何内容：

```go

tracer_test.go:18: Trace should not write ''.

```

让我们更新我们的`Trace`方法，将混合参数写入指定的`io.Writer`字段：

```go
func (t *tracer) Trace(a ...interface{}) {
  t.out.Write([]byte(fmt.Sprint(a...)))
  t.out.Write([]byte("\n"))
}
```

当调用`Trace`方法时，我们在`out`字段中存储的`io.Writer`上调用`Write`，并使用`fmt.Sprint`格式化`a`参数。我们将`fmt.Sprint`的字符串返回类型转换为`string`，然后转换为`[]byte`，因为这是`io.Writer`接口所期望的。

我们最终满足了我们的测试吗？

```go

go test -cover

PASS

coverage: 100.0% of statements

ok    trace        0.011s

```

恭喜！我们成功通过了测试，测试覆盖率为`100.0%`。一旦我们喝完香槟，我们可以花一分钟时间考虑一下我们的实现非常有趣的地方。

### 将未导出的类型返回给用户

我们编写的`tracer`结构类型是未导出的，因为它以小写的`t`开头，那么我们如何能够从导出的`New`函数中返回它呢？毕竟，用户会接收到返回的对象吗？这是完全可以接受和有效的 Go 代码；用户只会看到一个满足`Tracer`接口的对象，甚至不会知道我们私有的`tracer`类型。由于他们只与接口交互，我们的`tracer`实现暴露其他方法或字段也无所谓；它们永远不会被看到。这使我们能够保持包的公共 API 清晰简单。

这种隐藏的实现技术在 Go 标准库中被广泛使用，例如，`ioutil.NopCloser`方法是一个将普通的`io.Reader`转换为`io.ReadCloser`的函数，而`Close`方法什么也不做（用于将不需要关闭的`io.Reader`对象传递给需要`io.ReadCloser`类型的函数）。该方法在用户看来返回`io.ReadCloser`，但在底层，有一个秘密的`nopCloser`类型隐藏了实现细节。

### 注意

要亲自看到这一点，请浏览 Go 标准库源代码[`golang.org/src/pkg/io/ioutil/ioutil.go`](http://golang.org/src/pkg/io/ioutil/ioutil.go)，并搜索`nopCloser`结构。

## 使用我们的新的 trace 包

现在我们已经完成了`trace`包的第一个版本，我们可以在聊天应用程序中使用它，以更好地理解用户通过用户界面发送消息时发生了什么。

在`room.go`中，让我们导入我们的新包并对`Trace`方法进行一些调用。我们刚刚编写的`trace`包的路径将取决于您的`GOPATH`环境变量，因为导入路径是相对于`$GOPATH/src`文件夹的。因此，如果您在`$GOPATH/src/mycode/trace`中创建了`trace`包，则需要导入`mycode/trace`。

像这样更新`room`类型和`run()`方法：

```go
type room struct {
  // forward is a channel that holds incoming messages
  // that should be forwarded to the other clients.
  forward chan []byte
  // join is a channel for clients wishing to join the room.
  join chan *client
  // leave is a channel for clients wishing to leave the room.
  leave chan *client
  // clients holds all current clients in this room.
  clients map[*client]bool

// tracer will receive trace information of activity

 // in the room.

 tracer trace.Tracer

}
func (r *room) run() {
  for {
    select {
    case client := <-r.join:
      // joining
      r.clients[client] = true

r.tracer.Trace("New client joined")

    case client := <-r.leave:
      // leaving
      delete(r.clients, client)
      close(client.send)

r.tracer.Trace("Client left")

    case msg := <-r.forward:
      r.tracer.Trace("Message received: ", string(msg))
      // forward message to all clients
      for client := range r.clients {
        select {
        case client.send <- msg:
          // send the message

r.tracer.Trace(" -- sent to client")

        default:
          // failed to send
          delete(r.clients, client)
          close(client.send)

r.tracer.Trace(" -- failed to send, cleaned up client")

        }
      }
    }
  }
}
```

我们在`room`类型中添加了一个`trace.Tracer`字段，然后在整个代码中定期调用`Trace`方法。如果我们运行程序并尝试发送消息，您会注意到应用程序会因为`tracer`字段为`nil`而发生 panic。我们可以通过确保在创建`room`类型时创建并分配一个适当的对象来暂时解决这个问题。更新`main.go`文件以执行此操作：

```go
r := newRoom()
r.tracer = trace.New(os.Stdout)
```

我们使用我们的`New`方法来创建一个对象，该对象将输出发送到`os.Stdout`标准输出管道（这是一种技术方式，表示我们希望它将输出打印到我们的终端）。

现在重新构建并运行程序，并使用两个浏览器玩耍应用程序，注意终端现在有一些有趣的跟踪信息供我们查看：

```go

New client joined

New client joined

Message received: Hello Chat

 -- sent to client

 -- sent to client

Message received: Good morning :)

 -- sent to client

 -- sent to client

Client left

Client left

```

现在我们能够使用调试信息来洞察应用程序的运行情况，这将在开发和支持项目时对我们有所帮助。

## 使跟踪变为可选

一旦应用程序发布，我们生成的跟踪信息将变得非常无用，如果它只是打印到某个终端上，甚至更糟的是，如果它为我们的系统管理员创建了大量噪音。另外，请记住，当我们没有为`room`类型设置跟踪器时，我们的代码会发生 panic，这并不是一个非常用户友好的情况。为了解决这两个问题，我们将增强我们的`trace`包，添加一个`trace.Off()`方法，该方法将返回一个满足`Tracer`接口但在调用`Trace`方法时不执行任何操作的对象。

让我们添加一个测试，调用`Off`函数以获取一个静默的 tracer，然后调用`Trace`以确保代码不会发生 panic。由于跟踪不会发生，这就是我们在测试代码中能做的全部。将以下测试函数添加到`tracer_test.go`文件中：

```go
func TestOff(t *testing.T) {
  var silentTracer Tracer = Off()
  silentTracer.Trace("something")
}
```

为了使其通过，将以下代码添加到`tracer.go`文件中：

```go
type nilTracer struct{}
func (t *nilTracer) Trace(a ...interface{}) {}
// Off creates a Tracer that will ignore calls to Trace.
func Off() Tracer {
  return &nilTracer{}
}
```

我们的`nilTracer`结构定义了一个什么也不做的`Trace`方法，调用`Off()`方法将创建一个新的`nilTracer`结构并返回它。请注意，我们的`nilTracer`结构与我们的`tracer`结构不同，它不需要`io.Writer`；因为它不会写任何东西。

现在让我们通过更新`room.go`文件中的`newRoom`方法来解决我们的第二个问题：

```go
func newRoom() *room {
  return &room{
    forward: make(chan []byte),
    join:    make(chan *client),
    leave:   make(chan *client),
    clients: make(map[*client]bool),
    tracer:  trace.Off(),
  }
}
```

默认情况下，我们的`room`类型将使用`nilTracer`结构创建，并且对`Trace`的任何调用都将被忽略。您可以通过从`main.go`文件中删除`r.tracer = trace.New(os.Stdout)`行来尝试这一点：注意当您使用应用程序时没有任何内容被写入终端，并且没有发生恐慌。

## 清晰的包 API

快速浏览 API（在这种情况下，暴露的变量、方法和类型）我们的`trace`包突出显示了一个简单明显的设计已经出现：

+   `New()`方法

+   `Off()`方法

+   `Tracer`接口

我非常有信心将这个包交给一个没有任何文档或指南的 Go 程序员，我相信他们会知道如何处理它。

### 注意

在 Go 中，添加文档就像在每个项目的前一行添加注释一样简单。关于这个主题的博客文章是值得一读的（[`blog.golang.org/godoc-documenting-go-code`](http://blog.golang.org/godoc-documenting-go-code)），在那里你可以看到`tracer.go`的托管源代码的副本，这是一个你可能如何注释`trace`包的示例。有关更多信息，请参阅[github.com/matryer/goblueprints/blob/master/chapter1/trace/tracer.go](http://github.com/matryer/goblueprints/blob/master/chapter1/trace/tracer.go)。

# 总结

在本章中，我们开发了一个完整的并发聊天应用程序，以及我们自己简单的包来跟踪程序的流程，以帮助我们更好地理解底层发生了什么。

我们使用`net/http`包快速构建了一个非常强大的并发 HTTP Web 服务器。在一个特定的情况下，我们升级了连接以在客户端和服务器之间打开一个 Web 套接字。这意味着我们可以轻松快速地向用户的 Web 浏览器发送消息，而不必编写混乱的轮询代码。我们探讨了模板如何有用地将代码与内容分离，以及允许我们将数据注入到我们的模板源中，这使我们可以使主机地址可配置。命令行标志帮助我们为托管我们的应用程序的人提供简单的配置控制，同时让我们指定合理的默认值。

我们的聊天应用程序利用了 Go 强大的并发能力，使我们能够用几行惯用的 Go 代码编写清晰的*线程化*代码。通过通过通道控制客户端的到来和离开，我们能够在代码中设置同步点，防止我们尝试同时修改相同对象而破坏内存。

我们学习了诸如`http.Handler`和我们自己的`trace.Tracer`这样的接口，使我们能够提供不同的实现，而无需触及使用它们的代码，并且在某些情况下，甚至无需向用户公开实现的名称。我们看到，通过向我们的`room`类型添加`ServeHTTP`方法，我们将我们的自定义房间概念转变为一个有效的 HTTP 处理程序对象，它管理我们的 Web 套接字连接。

实际上，我们离能够正确发布我们的应用程序并不远，除了一个重大的疏忽：你无法看到谁发送了每条消息。我们没有用户的概念，甚至没有用户名，对于一个真正的聊天应用来说，这是不可接受的。

在下一章中，我们将添加回复消息的人的名称，以使他们感觉自己正在与其他人进行真正的对话。


# 第二章：添加身份验证

我们在上一章构建的聊天应用程序侧重于从客户端到服务器再到客户端的消息高性能传输，但我们的用户无法知道他们在和谁交谈。解决这个问题的一个方法是构建某种注册和登录功能，让我们的用户在打开聊天页面之前创建帐户并进行身份验证。

每当我们要从头开始构建东西时，我们必须问自己在此之前其他人是如何解决这个问题的（真正原创的问题极为罕见），以及是否存在任何开放的解决方案或标准可以供我们使用。授权和身份验证并不是新问题，特别是在网络世界中，有许多不同的协议可供选择。那么我们如何决定追求最佳选择？和往常一样，我们必须从用户的角度来看待这个问题。

如今，许多网站允许您使用社交媒体或社区网站上现有的帐户进行登录。这样一来，用户就不必在尝试不同的产品和服务时一遍又一遍地输入所有帐户信息。这也对新站点的转化率产生了积极的影响。

在本章中，我们将增强我们的聊天代码库，添加身份验证，这将允许我们的用户使用 Google、Facebook 或 GitHub 进行登录，您还将看到添加其他登录门户也是多么容易。为了加入聊天，用户必须首先登录。之后，我们将使用授权数据来增强我们的用户体验，以便每个人都知道谁在房间里，以及谁说了什么。

在本章中，您将学习：

+   使用装饰器模式将`http.Handler`类型包装起来，为处理程序添加额外功能

+   使用动态路径提供 HTTP 端点

+   使用 Gomniauth 开源项目访问身份验证服务

+   使用`http`包获取和设置 cookie

+   将对象编码为 Base64，然后再转换为正常状态

+   通过网络套接字发送和接收 JSON 数据

+   向模板提供不同类型的数据

+   使用自己类型的通道进行工作

# 一路处理程序

对于我们的聊天应用程序，我们实现了自己的`http.Handler`类型，以便轻松地编译、执行和向浏览器传递 HTML 内容。由于这是一个非常简单但功能强大的接口，我们将在添加功能到我们的 HTTP 处理时继续使用它。

为了确定用户是否经过身份验证，我们将创建一个身份验证包装处理程序来执行检查，并仅在用户经过身份验证时将执行传递给内部处理程序。

我们的包装处理程序将满足与其内部对象相同的`http.Handler`接口，允许我们包装任何有效的处理程序。实际上，即将编写的身份验证处理程序如果需要的话也可以稍后封装在类似的包装器中。

![一路处理程序](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/go-prog-bp/img/Image00002.jpg)

应用于 HTTP 处理程序的链接模式图

前面的图显示了这种模式如何应用于更复杂的 HTTP 处理程序场景。每个对象都实现了`http.Handler`接口，这意味着对象可以传递到`http.Handle`方法中直接处理请求，或者可以传递给另一个对象，该对象添加了某种额外的功能。`Logging`处理程序可能会在调用内部处理程序的`ServeHTTP`方法之前和之后写入日志文件。由于内部处理程序只是另一个`http.Handler`，任何其他处理程序都可以包装在（或使用）`Logging`处理程序中。

对象通常包含决定执行哪个内部处理程序的逻辑。例如，我们的身份验证处理程序将要么将执行传递给包装处理程序，要么通过向浏览器发出重定向来处理请求。

现在理论已经足够了；让我们写一些代码。在`chat`文件夹中创建一个名为`auth.go`的新文件：

```go
package main
import (
  "net/http"
)
type authHandler struct {
  next http.Handler
}
func (h *authHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
  if _, err := r.Cookie("auth"); err == http.ErrNoCookie {
    // not authenticated
    w.Header().Set("Location", "/login")
    w.WriteHeader(http.StatusTemporaryRedirect)
  } else if err != nil {
    // some other error
    panic(err.Error())
  } else {
    // success - call the next handler
    h.next.ServeHTTP(w, r)
  }
}
func MustAuth(handler http.Handler) http.Handler {
  return &authHandler{next: handler}
}
```

`authHandler`类型不仅实现了`ServeHTTP`方法（满足`http.Handler`接口），还在`next`字段中存储（包装）`http.Handler`。我们的`MustAuth`辅助函数只是创建包装任何其他`http.Handler`的`authHandler`。让我们调整以下根映射行：

```go
http.Handle("/", &templateHandler{filename: "chat.html"})
```

让我们更改第一个参数，以明确指定用于聊天的页面。接下来，让我们使用`MustAuth`函数包装`templateHandler`作为第二个参数：

```go
http.Handle("/chat", MustAuth(&templateHandler{filename: "chat.html"}))
```

使用`MustAuth`函数包装`templateHandler`将导致执行首先通过我们的`authHandler`，仅在请求经过身份验证时才到达`templateHandler`。

我们的`authHandler`中的`ServeHTTP`方法将寻找一个名为`auth`的特殊 cookie，并使用`http.ResponseWriter`上的`Header`和`WriteHeader`方法来重定向用户到登录页面，如果缺少 cookie。

构建并运行聊天应用程序，并尝试访问`http://localhost:8080/chat`：

```go

go build -o chat

./chat -host=":8080"

```

### 提示

您需要删除您的 cookie 以清除先前的 auth 令牌，或者从通过 localhost 提供的其他开发项目中留下的任何其他 cookie。

如果您查看浏览器的地址栏，您会注意到您立即被重定向到`/login`页面。由于我们目前无法处理该路径，您将收到一个**404 页面未找到**错误。

# 创建一个漂亮的社交登录页面

到目前为止，我们并没有太关注使我们的应用程序看起来漂亮，毕竟这本书是关于 Go 而不是用户界面开发。但是，构建丑陋的应用程序是没有借口的，因此我们将构建一个既漂亮又实用的社交登录页面。

Bootstrap 是用于在 Web 上开发响应式项目的前端框架。它提供了解决许多用户界面问题的 CSS 和 JavaScript 代码，以一致和美观的方式。虽然使用 Bootstrap 构建的网站往往看起来都一样（尽管 UI 可以定制的方式有很多），但它是早期应用程序的绝佳选择，或者对于没有设计师访问权限的开发人员。

### 提示

如果您使用 Bootstrap 制定的语义标准构建应用程序，那么为您的站点或应用程序制作 Bootstrap 主题将变得很容易，并且您知道它将完全适合您的代码。

我们将使用托管在 CDN 上的 Bootstrap 版本，因此我们不必担心通过我们的聊天应用程序下载和提供自己的版本。这意味着为了正确呈现我们的页面，我们需要保持活动的互联网连接，即使在开发过程中也是如此。

### 注意

如果您喜欢下载和托管自己的 Bootstrap 副本，可以这样做。将文件保存在`assets`文件夹中，并将以下调用添加到您的`main`函数中（它使用`http.Handle`通过您的应用程序提供资产）：

```go
http.Handle("/assets/", http.StripPrefix("/assets", http.FileServer(http.Dir("/path/to/assets/"))))
```

请注意，`http.StripPrefix`和`http.FileServer`函数返回满足`http.Handler`接口的对象，这是我们使用`MustAuth`辅助函数实现的装饰器模式。

在`main.go`中，让我们为登录页面添加一个端点：

```go
http.Handle("/chat", MustAuth(&templateHandler{filename: "chat.html"}))

http.Handle("/login", &templateHandler{filename: "login.html"})

http.Handle("/room", r)
```

显然，我们不希望在我们的登录页面使用`MustAuth`方法，因为它会导致无限重定向循环。

在我们的`templates`文件夹中创建一个名为`login.html`的新文件，并插入以下 HTML 代码：

```go
<html>
  <head>
    <title>Login</title>
    <link rel="stylesheet"
      href="//netdna.bootstrapcdn.com/bootstrap/3.1.1/css/bootstrap.min.css">
  </head>
  <body>
    <div class="container">
      <div class="page-header">
        <h1>Sign in</h1>
      </div>
      <div class="panel panel-danger">
        <div class="panel-heading">
          <h3 class="panel-title">In order to chat, you must be signed in</h3>
        </div>
        <div class="panel-body">
          <p>Select the service you would like to sign in with:</p>
          <ul>
            <li>
              <a href="/auth/login/facebook">Facebook</a>
            </li>
            <li>
              <a href="/auth/login/github">GitHub</a>
            </li>
            <li>
              <a href="/auth/login/google">Google</a>
            </li>
          </ul>
        </div>
      </div>
    </div>
  </body>
</html>
```

重新启动 Web 服务器并导航到`http://localhost:8080/login`。您会注意到它现在显示我们的登录页面：

![创建漂亮的社交登录页面](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/go-prog-bp/img/Image00003.jpg)

# 具有动态路径的端点

Go 标准库中的`http`包的模式匹配并不是最全面和功能齐全的实现。例如，Ruby on Rails 更容易在路径内部具有动态段。

```go
"auth/:action/:provider_name"
```

然后，这将提供一个数据映射（或字典），其中包含框架自动从匹配的路径中提取的值。因此，如果您访问`auth/login/google`，那么`params[:provider_name]`将等于`google`，而`params[:action]`将等于`login`。

默认情况下，`http`包让我们指定的最多是路径前缀，我们可以通过在模式的末尾留下一个斜杠来实现：

```go
"auth/"
```

然后我们必须手动解析剩余的段，以提取适当的数据。这对于相对简单的情况是可以接受的，因为目前我们只需要处理一些不同的路径，比如：

+   `/auth/login/google`

+   `/auth/login/facebook`

+   `/auth/callback/google`

+   `/auth/callback/facebook`

### 提示

如果您需要处理更复杂的路由情况，您可能希望考虑使用专用包，如 Goweb、Pat、Routes 或 mux。对于像我们这样极其简单的情况，内置的功能就足够了。

我们将创建一个新的处理程序来支持我们的登录流程。在`auth.go`中，添加以下`loginHandler`代码：

```go
// loginHandler handles the third-party login process.
// format: /auth/{action}/{provider}
func loginHandler(w http.ResponseWriter, r *http.Request) {
  segs := strings.Split(r.URL.Path, "/")
  action := segs[2]
  provider := segs[3]
  switch action {
  case "login":
    log.Println("TODO handle login for", provider)
  default:
     w.WriteHeader(http.StatusNotFound)
     fmt.Fprintf(w, "Auth action %s not supported", action)
  }
}
```

在上述代码中，我们使用`strings.Split`将路径分成段，然后提取`action`和`provider`的值。如果已知`action`的值，我们将运行特定的代码；否则，我们将写出错误消息并返回`http.StatusNotFound`状态码（在 HTTP 状态码的语言中，是`404`代码）。

### 注意

我们现在不会让我们的代码完全健壮，但值得注意的是，如果有人使用太少的段访问`loginHandler`，我们的代码将会 panic，因为它期望`segs[2]`和`segs[3]`存在。

额外加分，看看您是否可以防止这种情况，并在有人访问`/auth/nonsense`时返回一个友好的错误消息，而不是一个 panic。

我们的`loginHandler`只是一个函数，而不是实现`http.Handler`接口的对象。这是因为，与其他处理程序不同，我们不需要它来存储任何状态。Go 标准库支持这一点，因此我们可以使用`http.HandleFunc`函数将其映射到与我们之前使用`http.Handle`类似的方式。在`main.go`中更新处理程序：

```go
http.Handle("/chat", MustAuth(&templateHandler{filename: "chat.html"}))
http.Handle("/login", &templateHandler{filename: "login.html"})

http.HandleFunc("/auth/", loginHandler)

http.Handle("/room", r)
```

重新构建并运行聊天应用程序：

```go

go build –o chat

./chat –host=":8080"

```

访问以下 URL 并注意终端中记录的输出：

+   `http://localhost:8080/auth/login/google`输出`TODO handle login for google`

+   `http://localhost:8080/auth/login/facebook`输出`TODO handle login for facebook`

我们已经成功实现了一个动态路径匹配机制，目前只是打印出待办事项消息；接下来，我们需要编写与认证服务集成的代码。

# 读累了记得休息一会哦~

**公众号：古德猫宁李**

+   电子书搜索下载

+   书单分享

+   书友学习交流

**网站：**[沉金书屋 https://www.chenjin5.com](https://www.chenjin5.com)

+   电子书搜索下载

+   电子书打包资源分享

+   学习资源分享

# OAuth2

OAuth2 是一种开放的认证和授权标准，旨在允许资源所有者通过访问令牌交换握手向客户端提供委托访问私人数据（如墙上的帖子或推文）。即使您不希望访问私人数据，OAuth2 也是一个很好的选择，它允许人们使用其现有凭据登录，而不会将这些凭据暴露给第三方网站。在这种情况下，我们是第三方，我们希望允许我们的用户使用支持 OAuth2 的服务进行登录。

从用户的角度来看，OAuth2 流程是：

1.  用户选择希望使用的提供者登录到客户端应用程序。

1.  用户被重定向到提供者的网站（其中包括客户端应用程序 ID 的 URL），并被要求授予客户端应用程序权限。

1.  用户从 OAuth2 服务提供商登录，并接受第三方应用程序请求的权限。

1.  用户被重定向回客户端应用程序，并附带一个请求代码。

1.  在后台，客户端应用程序将授予代码发送给提供者，提供者将返回一个授权令牌。

1.  客户端应用程序使用访问令牌向提供者发出授权请求，例如获取用户信息或墙上的帖子。

为了避免重复造轮子，我们将看一些已经为我们解决了这个问题的开源项目。

## 开源 OAuth2 包

Andrew Gerrand 自 2010 年 2 月以来一直在核心 Go 团队工作，即在 Go 1.0 正式发布两年前。他的`goauth2`包（请参阅[`code.google.com/p/goauth2/`](https://code.google.com/p/goauth2/)）是 OAuth2 协议的优雅实现，完全使用 Go 编写。

Andrew 的项目启发了 Gomniauth（请参阅[`github.com/stretchr/gomniauth`](https://github.com/stretchr/gomniauth)）。作为 Ruby 的`omniauth`项目的开源 Go 替代品，Gomniauth 提供了一个统一的解决方案来访问不同的 OAuth2 服务。在未来，当 OAuth3（或者下一代认证协议）推出时，理论上，Gomniauth 可以承担实现细节的痛苦，使用户代码不受影响。

对于我们的应用程序，我们将使用 Gomniauth 来访问 Google、Facebook 和 GitHub 提供的 OAuth 服务，因此请确保您已通过运行以下命令进行安装：

```go

go get github.com/stretchr/gomniauth

```

### 提示

Gomniauth 的一些项目依赖项存储在 Bazaar 存储库中，因此您需要前往[`wiki.bazaar.canonical.com`](http://wiki.bazaar.canonical.com)下载它们。

# 告诉身份验证提供程序有关您的应用

在我们要求身份验证提供程序帮助我们的用户登录之前，我们必须告诉他们有关我们的应用程序。大多数提供程序都有一种网络工具或控制台，您可以在其中创建应用程序以启动该过程。以下是 Google 的一个示例：

![告诉身份验证提供程序有关您的应用](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/go-prog-bp/img/Image00004.jpg)

为了识别客户端应用程序，我们需要创建客户端 ID 和密钥。尽管 OAuth2 是一个开放标准，但每个提供程序都有自己的语言和机制来设置事物，因此您很可能需要在每种情况下通过用户界面或文档进行尝试来弄清楚。

在撰写本文时，在**Google 开发者控制台**中，您可以导航到**API 和身份验证** | **凭据**，然后单击**创建新的客户端 ID**按钮。

在大多数情况下，为了增加安全性，您必须明确指定请求将来自哪些主机 URL。目前，因为我们将在`localhost:8080`上本地托管我们的应用程序，所以您应该使用该 URL。您还将被要求提供一个重定向 URI，该 URI 是我们聊天应用程序中的端点，并且用户在成功登录后将被重定向到该端点。回调将是我们`loginHandler`上的另一个操作，因此 Google 客户端的重定向 URL 将是`http://localhost:8080/auth/callback/google`。

完成要支持的提供程序的身份验证过程后，您将为每个提供程序获得客户端 ID 和密钥。记下这些信息，因为在设置我们的聊天应用程序中的提供程序时，我们将需要它们。

### 注意

如果我们将我们的应用程序托管在真实域上，我们必须创建新的客户端 ID 和密钥，或者更新我们的身份验证提供程序的适当 URL 字段，以确保它们指向正确的位置。无论哪种方式，为了安全起见，为开发和生产的密钥设置不同的密钥并不是坏习惯。

# 实现外部登录

为了使用我们在身份验证提供程序网站上创建的项目、客户端或帐户，我们必须告诉 Gomniauth 我们想要使用哪些提供程序，以及我们将如何与它们交互。我们通过在主要的 Gomniauth 包上调用`WithProviders`函数来实现这一点。将以下代码片段添加到`main.go`（就在`main`函数顶部的`flag.Parse()`行下面）：

```go
// set up gomniauth
gomniauth.SetSecurityKey("some long key")
gomniauth.WithProviders(
  facebook.New("key", "secret",
    "http://localhost:8080/auth/callback/facebook"),
  github.New("key", "secret",
    "http://localhost:8080/auth/callback/github"),
  google.New("key", "secret",
    "http://localhost:8080/auth/callback/google"),
)
```

您应该用您之前记录的实际值替换`key`和`secret`占位符。第三个参数表示回调 URL，应与您在提供者网站上创建客户端时提供的 URL 匹配。注意第二个路径段是`callback`；虽然我们还没有实现这个，但这是我们处理认证过程的响应的地方。

像往常一样，您需要确保导入了所有适当的包：

```go
import (
  "github.com/stretchr/gomniauth/providers/facebook"
  "github.com/stretchr/gomniauth/providers/github"
  "github.com/stretchr/gomniauth/providers/google"
)
```

### 注意

Gomniauth 需要`SetSecurityKey`调用，因为它在客户端和服务器之间发送状态数据以及签名校验和，以确保状态值在传输过程中没有被篡改。安全密钥在创建哈希时使用，以一种几乎不可能在不知道确切安全密钥的情况下重新创建相同的哈希。您应该用您选择的安全哈希或短语替换`some long key`。

## 登录

现在我们已经配置了 Gomniauth，当用户登陆到我们的`/auth/login/{provider}`路径时，我们需要将用户重定向到提供者的认证页面。我们只需要更新我们在`auth.go`中的`loginHandler`函数：

```go
func loginHandler(w http.ResponseWriter, r *http.Request) {
  segs := strings.Split(r.URL.Path, "/")
  action := segs[2]
  provider := segs[3]
  switch action {
  case "login":
    provider, err := gomniauth.Provider(provider)
    if err != nil {
      log.Fatalln("Error when trying to get provider", provider, "-", err)
    }
    loginUrl, err := provider.GetBeginAuthURL(nil, nil)
    if err != nil {
      log.Fatalln("Error when trying to GetBeginAuthURL for", provider, "-", err)
    }
    w.Header.Set("Location",loginUrl)
    w.WriteHeader(http.StatusTemporaryRedirect)
  default:
    w.WriteHeader(http.StatusNotFound)
    fmt.Fprintf(w, "Auth action %s not supported", action)
  }
}
```

我们在这里做了两件主要的事情。首先，我们使用`gomniauth.Provider`函数来获取与 URL 中指定的对象（如`google`或`github`）匹配的提供者对象。然后我们使用`GetBeginAuthURL`方法获取我们必须发送用户的位置，以开始认证过程。

### 注意

`GetBeginAuthURL(nil, nil)`参数是用于状态和选项的，对于我们的聊天应用程序，我们不打算使用它们。

第一个参数是编码、签名并发送到认证提供者的数据状态映射。提供者不会对状态进行任何操作，只是将其发送回我们的回调端点。例如，如果我们想要将用户重定向回他们在认证过程中尝试访问的原始页面，这是很有用的。对于我们的目的，我们只有`/chat`端点，所以我们不需要担心发送任何状态。

第二个参数是一个附加选项的映射，将被发送到认证提供者，以某种方式修改认证过程的行为。例如，您可以指定自己的`scope`参数，这允许您请求许可以访问提供者的其他信息。有关可用选项的更多信息，请在互联网上搜索 OAuth2 或阅读每个提供者的文档，因为这些值因服务而异。

如果我们的代码从`GetBeginAuthURL`调用中没有错误，我们只需将用户的浏览器重定向到返回的 URL。

重新构建并运行聊天应用程序：

```go

go build -o chat

./chat -host=":8080"

```

通过访问`http://localhost:8080/chat`来打开主要的聊天页面。由于我们还没有登录，我们被重定向到我们的登录页面。点击 Google 选项，使用您的 Google 账户登录，您会注意到您被呈现出一个特定于 Google 的登录页面（如果您还没有登录到 Google）。一旦您登录，您将被呈现一个页面，要求您在查看有关您的账户的基本信息之前，先允许我们的聊天应用程序：

![登录](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/go-prog-bp/img/Image00005.jpg)

这是我们的聊天应用程序用户在登录时会经历的相同流程。

点击**接受**，您会注意到您被重定向回我们的应用程序代码，但是出现了`Auth action callback not supported`错误。这是因为我们还没有在`loginHandler`中实现回调功能。

## 处理来自提供者的响应

一旦用户在提供者的网站上点击**接受**（或者点击相当于**取消**的选项），他们将被重定向回我们应用程序的回调端点。

快速浏览返回的完整 URL，我们可以看到提供者给我们的授权代码。

```go
http://localhost:8080/auth/callback/google?
code=4/Q92xJ-BQfoX6PHhzkjhgtyfLc0Ylm.QqV4u9AbA9sYguyfbjFEsNoJKMOjQI

```

我们不必担心该代码该怎么处理，因为 Gomniauth 将为我们处理 OAuth URL 参数（通过将授权代码发送到 Google 服务器并根据 OAuth 规范将其交换为访问令牌），因此我们可以直接跳转到实现我们的回调处理程序。然而，值得知道的是，这段代码将被身份验证提供程序交换为一个允许我们访问私人用户数据的令牌。为了增加安全性，这个额外的步骤是在后台从服务器到服务器进行的，而不是在浏览器中进行的。

在`auth.go`中，我们准备向我们的动作路径段添加另一个 switch case。在默认情况之前插入以下代码：

```go
case "callback":

  provider, err := gomniauth.Provider(provider)
  if err != nil {
    log.Fatalln("Error when trying to get provider", provider, "-", err)
  }

creds, err := provider.CompleteAuth(objx.MustFromURLQuery(r.URL.RawQuery))

  if err != nil {
    log.Fatalln("Error when trying to complete auth for", provider, "-", err)
  }

user, err := provider.GetUser(creds)

  if err != nil {
    log.Fatalln("Error when trying to get user from", provider, "-", err)
  }

authCookieValue := objx.New(map[string]interface{}{

 "name": user.Name(),

 }).MustBase64()

 http.SetCookie(w, &http.Cookie{

 Name:  "auth",

 Value: authCookieValue,

 Path:  "/"})

  w.Header()["Location"] = []string{"/chat"}
  w.WriteHeader(http.StatusTemporaryRedirect)
```

当身份验证提供程序在用户授予权限后将用户重定向回来时，URL 指定它是一个回调动作。我们像之前一样查找身份验证提供程序，并调用它的`CompleteAuth`方法。我们将`http.Request`（用户浏览器现在正在进行的`GET`请求）中的`RawQuery`解析为`objx.Map`（Gomniauth 使用的多用途映射类型），`CompleteAuth`方法使用 URL 查询参数值来完成与提供程序的身份验证握手。一切顺利的话，我们将获得一些授权凭据，用于访问用户的基本数据。然后我们使用提供程序的`GetUser`方法，Gomniauth 使用指定的凭据访问用户的一些基本信息。

一旦我们有了用户数据，我们将`Name`字段在 JSON 对象中进行 Base64 编码，并将其存储为我们的`auth` cookie 的值，以便以后使用。

### 提示

数据的 Base64 编码确保它不会包含任何特殊或不可预测的字符，就像在 URL 中传递数据或将其存储在 cookie 中一样。请记住，尽管 Base64 编码的数据看起来像是加密的，但实际上并不是——您可以很容易地将 Base64 编码的数据解码回原始文本，而不费吹灰之力。有在线工具可以为您完成这项工作。

设置完 cookie 后，我们将用户重定向到聊天页面，可以安全地假设这是最初的目的地。

再次构建和运行代码，然后访问`/chat`页面，您会注意到注册流程起作用了，我们最终被允许返回到聊天页面。大多数浏览器都有检查器或控制台——一种允许您查看服务器发送给您的 cookie 的工具——您可以使用它来查看`auth` cookie 是否已出现：

```go

go build –o chat

./chat –host=":8080"

```

在我们的情况下，cookie 值是`eyJuYW1lIjoiTWF0IFJ5ZXIifQ==`，这是`{"name":"Mat Ryer"}`的 Base64 编码版本。请记住，我们在聊天应用中从未输入过名字；相反，当我们选择使用 Google 登录时，Gomniauth 会向 Google 请求一个名字。像这样存储非签名的 cookie 对于像用户姓名这样的偶发信息是可以的，但是，您应该避免使用非签名的 cookie 存储任何敏感信息，因为人们可以轻松访问和更改数据。

## 呈现用户数据

将用户数据放在 cookie 中是一个很好的开始，但非技术人员甚至不会知道它的存在，所以我们必须将数据提到前台。我们将通过增强我们的`templateHandler`方法来实现这一点，该方法首先将用户数据传递到模板的`Execute`方法中；这使我们能够在 HTML 中使用模板注释来向用户显示用户数据。

更新`main.go`中我们的`templateHandler`的`ServeHTTP`方法：

```go
func (t *templateHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
  t.once.Do(func() {
    t.templ = template.Must(template.ParseFiles(filepath.Join("templates", t.filename)))
  })

data := map[string]interface{}{

 "Host": r.Host,

 }

 if authCookie, err := r.Cookie("auth"); err == nil {

 data["UserData"] = objx.MustFromBase64(authCookie.Value)

 }

  t.templ.Execute(w, data)
}
```

我们不仅仅将整个`http.Request`对象作为数据传递给我们的模板，而是为一个数据对象创建一个新的`map[string]interface{}`定义，该对象可能有两个字段：`Host`和`UserData`（后者只有在存在`auth` cookie 时才会出现）。通过指定映射类型后跟花括号，我们能够在同一时间添加`Host`条目和创建我们的映射。然后我们将这个新的`data`对象作为第二个参数传递给我们模板的`Execute`方法。

现在我们在模板源中添加一个 HTML 文件来显示名称。更新`chat.html`中的`chatbox`表单：

```go
<form id="chatbox">

{{.UserData.name}}:<br/>

  <textarea></textarea>
  <input type="submit" value="Send" />
</form>
```

`{{.UserData.name}}`注释告诉模板引擎在`textarea`控件之前插入我们用户的名称。

### 提示

由于我们正在使用`objx`包，请不要忘记运行`go get` [`github.com/stretchr/objx`](http://github.com/stretchr/objx)，并导入它。

重新构建并再次运行聊天应用程序，您会注意到在聊天框之前添加了您的名称。

```go

go build -o chat

./chat –host=":8080"

```

## 增加消息的附加数据

到目前为止，我们的聊天应用程序只传输消息作为字节片或`[]byte`类型在客户端和服务器之间；因此，我们的房间的`forward`通道具有`chan []byte`类型。为了发送数据（例如发送者和发送时间）以及消息本身，我们增强了我们的`forward`通道以及我们在两端与 web 套接字交互的方式。

通过在`chat`文件夹中创建一个名为`message.go`的新文件，定义一个将`[]byte`切片替换的新类型：

```go
package main
import (
  "time"
)
// message represents a single message
type message struct {
  Name    string
  Message string
  When    time.Time
}
```

`message`类型将封装消息字符串本身，但我们还添加了分别保存用户名称和消息发送时间戳的`Name`和`When`字段。

由于`client`类型负责与浏览器通信，它需要传输和接收的不仅仅是单个消息字符串。由于我们正在与 JavaScript 应用程序（即在浏览器中运行的聊天客户端）进行交流，并且 Go 标准库具有出色的 JSON 实现，因此这似乎是在消息中编码附加信息的完美选择。我们将更改`client.go`中的`read`和`write`方法，以使用套接字上的`ReadJSON`和`WriteJSON`方法，并对我们的新`message`类型进行编码和解码：

```go
func (c *client) read() {
  for {

var msg *message

 if err := c.socket.ReadJSON(&msg); err == nil {

 msg.When = time.Now()

 msg.Name = c.userData["name"].(string)

 c.room.forward <- msg

    } else {
      break
    }
  }
  c.socket.Close()
}
func (c *client) write() {
  for msg := range c.send {
    if err := 
c.socket.WriteJSON(msg)

; err != nil {
      break
    }
  }
  c.socket.Close()
}
```

当我们从浏览器接收到消息时，我们只期望填充`Message`字段，这就是为什么我们在前面的代码中设置了`When`和`Name`字段。

当您尝试构建前面的代码时，您会注意到它会抱怨一些问题。主要原因是我们试图通过`forward`和`send chan []byte`通道发送`*message`对象。在`room.go`中，将`forward`字段更改为`chan *message`类型，并在`client.go`中对`send chan`类型执行相同操作。

我们必须更新初始化通道的代码，因为类型现在已经改变。或者，您可以等待编译器提出这些问题，并在进行修复时解决它们。在`room.go`中，您需要进行以下更改：

+   将`forward: make(chan []byte)`更改为`forward: make(chan *message)`

+   将`r.tracer.Trace("Message received: ", string(msg))`更改为`r.tracer.Trace("Message received: ", msg.Message)`

+   将`send: make(chan []byte, messageBufferSize)`更改为`send: make(chan *message, messageBufferSize)`

编译器还会抱怨客户端缺少用户数据，这是一个公平的观点，因为`client`类型对我们已添加到 cookie 中的新用户数据一无所知。更新`client`结构以包括一个名为`userData`的新`map[string]interface{}`：

```go
// client represents a single chatting user.
type client struct {
  // socket is the web socket for this client.
  socket *websocket.Conn
  // send is a channel on which messages are sent.
  send chan *message
  // room is the room this client is chatting in.
  room *room
  // userData holds information about the user
  userData map[string]interface{}
}
```

用户数据来自客户端 cookie，我们通过`http.Request`对象的`Cookie`方法访问它。在`room.go`中，使用以下更改更新`ServeHTTP`：

```go
func (r *room) ServeHTTP(w http.ResponseWriter, req *http.Request) {
  socket, err := upgrader.Upgrade(w, req, nil)
  if err != nil {
    log.Fatal("ServeHTTP:", err)
    return
  }

authCookie, err := req.Cookie("auth")

 if err != nil {

 log.Fatal("Failed to get auth cookie:", err)

 return

 }

 client := &client{

 socket:   socket,

 send:     make(chan *message, messageBufferSize),

 room:     r,

 userData: objx.MustFromBase64(authCookie.Value),

 }

  r.join <- client
  defer func() { r.leave <- client }()
  go client.write()
  client.read()
}
```

我们使用`http.Request`类型上的`Cookie`方法来获取用户数据，然后将其传递给客户端。我们使用`objx.MustFromBase64`方法将编码的 cookie 值转换回可用的 map 对象。

现在我们已经将从套接字发送和接收的类型从`[]byte`更改为`*message`，我们必须告诉我们的 JavaScript 客户端，我们正在发送 JSON 而不仅仅是普通字符串。还必须要求在用户提交消息时，它将 JSON 发送回服务器。在`chat.html`中，首先更新`socket.send`调用：

```go
socket.send(JSON.stringify({"Message": msgBox.val()}));
```

我们使用`JSON.stringify`将指定的 JSON 对象（仅包含`Message`字段）序列化为字符串，然后发送到服务器。我们的 Go 代码将把 JSON 字符串解码（或取消编组）为`message`对象，将客户端 JSON 对象的字段名称与我们的`message`类型的字段名称匹配。

最后，更新`socket.onmessage`回调函数以期望 JSON，并在页面上添加发送者的名称：

```go
socket.onmessage = function(e) {
  var msg = eval("("+e.data+")");
  messages.append(
    $("<li>").append(
      $("<strong>").text(msg.Name + ": "),
      $("<span>").text(msg.Message)
    )
  );
}
```

在前面的代码片段中，我们使用了 JavaScript 的`eval`函数将 JSON 字符串转换为 JavaScript 对象，然后访问字段以构建显示它们所需的元素。

构建并运行应用程序，如果可以的话，在两个不同的浏览器中使用两个不同的帐户登录（或者邀请朋友帮助测试）：

```go

go build -o chat

./chat -host=":8080"

```

以下截图显示了聊天应用程序的浏览器聊天界面：

![使用附加数据增强消息](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/go-prog-bp/img/Image00006.jpg)

# 摘要

在本章中，我们通过要求用户使用 OAuth2 服务提供商进行身份验证，然后允许他们加入对话，为我们的聊天应用程序添加了一个有用且必要的功能。我们利用了几个开源包，如`Objx`和`Gomniauth`，大大减少了我们需要处理的多服务器复杂性。

当我们包装`http.Handler`类型时，我们实现了一种模式，以便轻松指定哪些路径需要用户进行身份验证，哪些即使没有`auth` cookie 也是可用的。我们的`MustAuth`辅助函数使我们能够以流畅简单的方式生成包装类型，而不会给我们的代码添加混乱和困惑。

我们看到如何使用 Cookie 和 Base64 编码来安全（虽然不安全）地在用户的浏览器中存储特定用户的状态，并利用该数据通过普通连接和网络套接字。我们更多地控制了模板中可用的数据，以便向 UI 提供用户的名称，并看到如何在特定条件下仅提供某些数据。

由于我们需要通过网络套接字发送和接收附加信息，我们学会了如何轻松地将本机类型的通道更改为适用于我们自己的类型（如我们的`message`类型）的通道。我们还学会了如何通过套接字传输 JSON 对象，而不仅仅是字节片。由于 Go 的类型安全性，以及能够为通道指定类型，编译器有助于确保我们不会通过`chan *message`发送除`message`对象以外的任何东西。尝试这样做将导致编译器错误，立即提醒我们这一事实。

在我们之前构建的应用程序中，看到聊天的人的名字是一个巨大的可用性进步，但它非常正式，可能不会吸引现代 Web 用户，他们习惯于更加视觉化的体验。我们缺少聊天的人的图片，在下一章中，我们将探讨不同的方式，让用户更好地在我们的应用程序中代表自己。

作为额外的任务，看看是否可以利用我们放入`message`类型中的`time.Time`字段，告诉用户消息何时发送。


# 第三章：实现个人资料图片的三种方法

到目前为止，我们的聊天应用程序已经使用了 OAuth2 协议，允许用户登录到我们的应用程序，以便我们知道谁在说什么。在本章中，我们将添加个人资料图片，使聊天体验更加引人入胜。

我们将研究以下几种方法来在我们的应用程序中的消息旁边添加图片或头像：

+   使用认证服务器提供的头像图片

+   使用[Gravatar.com](http://Gravatar.com)网络服务通过用户的电子邮件地址查找图片

+   允许用户上传自己的图片并自行托管

前两个选项允许我们将图片的托管委托给第三方——要么是认证服务，要么是[Gravatar.com](http://Gravatar.com)——这很棒，因为它减少了我们应用程序的托管成本（存储成本和带宽成本，因为用户的浏览器实际上会从认证服务的服务器上下载图片，而不是我们自己的服务器）。第三个选项要求我们在可以通过 web 访问的位置托管图片。

这些选项并不是互斥的；在真实的生产应用程序中，您很可能会使用它们的某种组合。在本章结束时，我们将看到灵活的设计使我们能够依次尝试每种实现，直到找到合适的头像。

在本章中，我们将灵活设计，尽量做到每个里程碑所需的最低工作量。这意味着在每个部分结束时，我们将拥有在浏览器中可演示的工作实现。这也意味着我们将根据需要重构代码，并讨论我们做出的决定背后的原因。

具体来说，在本章中，您将学到以下内容：

+   即使没有标准，也有哪些获取认证服务的额外信息的良好实践

+   何时适合将抽象构建到我们的代码中

+   Go 的零初始化模式如何节省时间和内存

+   如何重用接口使我们能够以与现有接口相同的方式处理集合和单个对象

+   如何使用[Gravatar.com](http://Gravatar.com)网络服务

+   如何在 Go 中进行 MD5 哈希

+   如何通过 HTTP 上传文件并将其存储在服务器上

+   如何通过 Go web 服务器提供静态文件

+   如何使用单元测试指导代码重构

+   何时以及如何将`struct`类型的功能抽象为接口

# 认证服务器的头像

事实证明，大多数认证服务器已经为其用户准备了图片，并通过我们已经知道如何访问的受保护用户资源使其可用。要使用这个头像图片，我们需要从提供者那里获取 URL，将其存储在我们用户的 cookie 中，并通过 web 套接字发送，以便每个客户端可以在相应的消息旁边呈现图片。

## 获取头像 URL

用户或个人资料资源的架构不是 OAuth2 规范的一部分，这意味着每个提供者都负责决定如何表示这些数据。事实上，提供者的做法各不相同，例如，GitHub 用户资源中的头像 URL 存储在名为`avatar_url`的字段中，而在 Google 中，相同的字段称为`picture`。Facebook 甚至通过在名为`picture`的对象内嵌套头像 URL 值的`url`字段来进一步进行。幸运的是，Gomniauth 为我们抽象了这一点；它在提供者上的`GetUser`调用标准化了获取常见字段的接口。

为了使用头像 URL 字段，我们需要回去并将其信息存储在我们的 cookie 中。在`auth.go`中，查看`callback`操作开关情况，并更新创建`authCookieValue`对象的代码如下：

```go
authCookieValue := objx.New(map[string]interface{}{
  "name":       user.Name(),

 "avatar_url": user.AvatarURL(),

}).MustBase64()
```

在前面的代码中调用的`AvatarURL`方法将返回适当的 URL 值，然后我们将其存储在`avatar_url`字段中，该字段将存储在 cookie 中。

### 提示

Gomniauth 定义了一个接口类型的`User`，每个提供者都实现了自己的版本。从认证服务器返回的通用`map[string]interface{}`数据存储在每个对象内，方法调用使用适当的字段名访问相应的值。这种方法描述了访问信息的方式，而不严格关注实现细节，是 Go 中接口的一个很好的用法。

## 传输头像 URL

我们需要更新我们的`message`类型，以便它也可以携带头像 URL。在`message.go`中，添加`AvatarURL`字符串字段：

```go
type message struct {
  Name      string
  Message   string
  When      time.Time

AvatarURL string

}
```

到目前为止，我们实际上还没有为`AvatarURL`分配一个值，就像我们为`Name`字段所做的那样，因此我们必须更新`client.go`中的`read`方法：

```go
func (c *client) read() {
  for {
    var msg *message
    if err := c.socket.ReadJSON(&msg); err == nil {
      msg.When = time.Now()
      msg.Name = c.userData["name"].(string)

if avatarUrl, ok := c.userData["avatar_url"]; ok {

msg.AvatarURL = avatarUrl.(string)

}

      c.room.forward <- msg
    } else {
      break
    }
  }
  c.socket.Close()
}
```

我们在这里所做的一切就是从`userData`字段中取出代表我们放入 cookie 的值，并将其分配给`message`中的适当字段，如果该值在映射中存在的话。我们现在将进一步检查该值是否存在，因为我们不能保证认证服务将为此字段提供一个值。并且由于它可能是`nil`，如果它实际上缺失，将其分配给`string`类型可能会导致恐慌。

## 将头像添加到用户界面

现在，我们的 JavaScript 客户端通过套接字获取了一个头像 URL 值，我们可以使用它来在消息旁边显示图像。我们通过更新`chat.html`中的`socket.onmessage`代码来实现这一点：

```go
socket.onmessage = function(e) {
  var msg = eval("("+e.data+")");
  messages.append(
    $("<li>").append(

$("<img>").css({

width:50,

verticalAlign:"middle"

}).attr("src", msg.AvatarURL),

      $("<strong>").text(msg.Name + ": "),
      $("<span>").text(msg.Message)
    )
  );
}
```

当我们收到一条消息时，我们将插入一个`img`标签，其中源设置为消息的`AvatarURL`字段。我们将使用 jQuery 的`css`方法强制宽度为`50`像素。这可以防止大图片破坏我们的界面，并允许我们将图像对齐到周围文本的中间。

如果我们使用先前版本登录后构建和运行我们的应用程序，你会发现不包含头像 URL 的`auth` cookie 仍然存在。我们不会被要求重新登录（因为我们已经登录了），添加`avatar_url`字段的代码也永远不会运行。我们可以删除 cookie 并刷新页面，但是在开发过程中每次进行更改时都需要这样做。让我们通过添加注销功能来正确解决这个问题。

## 注销

注销用户的最简单方法是删除`auth` cookie 并将用户重定向到聊天页面，这将导致重定向到登录页面，因为我们刚刚删除了 cookie。我们通过在`main.go`中添加一个新的`HandleFunc`调用来实现这一点：

```go
http.HandleFunc("/logout", func(w http.ResponseWriter, r *http.Request) {
  http.SetCookie(w, &http.Cookie{
    Name:   "auth",
    Value:  "",
    Path:   "/",
    MaxAge: -1,
  })
  w.Header()["Location"] = []string{"/chat"}
  w.WriteHeader(http.StatusTemporaryRedirect)
})
```

前面的处理函数使用`http.SetCookie`来更新`MaxAge`设置为`-1`的 cookie 设置，这表示它应该立即被浏览器删除。并非所有浏览器都被强制删除 cookie，这就是为什么我们还提供了一个新的`Value`设置为空字符串的设置，从而删除以前存储的用户数据。

### 提示

作为额外的任务，你可以通过更新`auth.go`中`authHandler`的`ServeHTTP`的第一行来使其适应空值情况以及缺少 cookie 的情况，从而使你的应用程序更加健壮：

```go
if cookie, err := r.Cookie("auth"); err == http.ErrNoCookie || cookie.Value == ""
```

不要忽略`r.Cookie`的返回，我们保留返回的 cookie 的引用（如果实际上有的话），并添加额外的检查，看看 cookie 的`Value`字符串是否为空。

在继续之前，让我们添加一个“登出”链接，以便更轻松地删除 cookie，并允许我们的用户注销。在`chat.html`中，更新`chatbox`表单，插入一个简单的 HTML 链接到新的`/logout`处理程序：

```go
<form id="chatbox">
  {{.UserData.name}}:<br/>
  <textarea></textarea>
  <input type="submit" value="Send" />

or <a href="/logout">sign out</a>

</form>
```

现在构建并运行应用程序，并在浏览器中打开`localhost:8080/chat`：

```go

go build –o chat

./chat –host=:8080

```

如果需要，注销并重新登录。当您点击**发送**时，您将看到您的头像图片出现在您的消息旁边。

![注销](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/go-prog-bp/img/Image00007.jpg)

## 使事情更美观

我们的应用程序开始看起来有点丑陋，是时候做点什么了。在上一章中，我们将 Bootstrap 库引入了我们的登录页面，现在我们将扩展其用途到我们的聊天页面。我们将在`chat.html`中进行三处更改：包括 Bootstrap 并调整页面的 CSS 样式，更改我们表单的标记，并调整我们在页面上呈现消息的方式。

首先，让我们更新页面顶部的`style`标签，并在其上插入一个`link`标签以包含 Bootstrap：

```go
<link rel="stylesheet" href="//netdna.bootstrapcdn.com/bootstrap/3.1.1/css/bootstrap.min.css">
<style>
  ul#messages        { list-style: none; }
  ul#messages li     { margin-bottom: 2px; }
  ul#messages li img { margin-right: 10px; }
</style>
```

接下来，让我们用以下代码替换`body`标签顶部的标记（在`script`标签之前）：

```go
<div class="container">
  <div class="panel panel-default">
    <div class="panel-body">
      <ul id="messages"></ul>
    </div>
  </div>
  <form id="chatbox" role="form">
    <div class="form-group">
      <label for="message">Send a message as {{.UserData.name}}</label> or <a href="/logout">Sign out</a>
      <textarea id="message" class="form-control"></textarea>
    </div>
    <input type="submit" value="Send" class="btn btn-default" />
  </form>
</div>
```

这个标记遵循 Bootstrap 标准，将适当的类应用于各种项目，例如，`form-control`类可以整洁地格式化`form`中的元素（您可以查看 Bootstrap 文档，了解这些类的更多信息）。

最后，让我们更新我们的`socket.onmessage` JavaScript 代码，将发送者的名称作为我们图像的`title`属性。这样，当您将鼠标悬停在图像上时，我们的应用程序将显示图像，而不是在每条消息旁边显示它：

```go
socket.onmessage = function(e) {
  var msg = eval("("+e.data+")");
  messages.append(
    $("<li>").append(
      $("<img>").
attr("title", msg.Name)

.css({
        width:50,
        verticalAlign:"middle"
      }).attr("src", msg.AvatarURL),
      $("<span>").text(msg.Message)
    )
  );
}
```

构建并运行应用程序，刷新浏览器，看看是否出现新的设计：

```go

go build –o chat

./chat –host=:8080

```

上述命令显示以下输出：

![使事情更美观](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/go-prog-bp/img/Image00008.jpg)

通过对代码进行相对较少的更改，我们大大改善了应用程序的外观和感觉。

# 实现 Gravatar

Gravatar 是一个网络服务，允许用户上传单个个人资料图片，并将其与其电子邮件地址关联，以便从任何网站获取。像我们这样的开发人员可以通过在特定 API 端点上执行`GET`操作来访问这些图像，用于我们的应用程序。在本节中，我们将看到如何实现 Gravatar，而不是使用认证服务提供的图片。

## 抽象化头像 URL 过程

由于我们的应用程序有三种不同的获取头像 URL 的方式，我们已经达到了一个合理的学习如何将功能抽象化以清晰地实现这些选项的点。抽象化是指我们将某物的概念与其具体实现分离的过程。`http.Handler`是一个很好的例子，它展示了如何使用处理程序以及其细节，而不具体说明每个处理程序采取的操作。

在 Go 中，我们开始通过定义一个接口来描述获取头像 URL 的想法。让我们创建一个名为`avatar.go`的新文件，并插入以下代码：

```go
package main
import (
  "errors"
)
// ErrNoAvatar is the error that is returned when the
// Avatar instance is unable to provide an avatar URL.
var ErrNoAvatarURL = errors.New("chat: Unable to get an avatar URL.")
// Avatar represents types capable of representing
// user profile pictures.
type Avatar interface {
  // GetAvatarURL gets the avatar URL for the specified client,
  // or returns an error if something goes wrong.
  // ErrNoAvatarURL is returned if the object is unable to get
  // a URL for the specified client.
  GetAvatarURL(c *client) (string, error)
}
```

`Avatar`接口描述了一个类型必须满足的`GetAvatarURL`方法，以便能够获取头像 URL。我们将客户端作为参数，以便知道为哪个用户返回 URL。该方法返回两个参数：一个字符串（如果一切顺利，将是 URL），以及一个错误，以防出现问题。

可能出错的一件事是`Avatar`的特定实现之一无法获取 URL。在这种情况下，`GetAvatarURL`将作为第二个参数返回`ErrNoAvatarURL`错误。因此，`ErrNoAvatarURL`错误成为接口的一部分；它是该方法可能返回的一个可能值，也是我们代码的用户可能需要明确处理的内容。我们在方法的注释部分提到了这一点，这是在 Go 中传达这种设计决策的唯一方式。

### 提示

因为错误是立即使用`errors.New`初始化并存储在`ErrNoAvatarURL`变量中的，所以只会创建一个这样的对象；将错误的指针作为返回传递是非常廉价的。这与 Java 的检查异常不同，后者用作控制流的一部分时会创建并使用昂贵的异常对象。

### 认证服务和头像的实现

我们编写的第一个`Avatar`实现将替换现有的功能，其中我们硬编码了从认证服务获取的头像 URL。让我们使用**测试驱动开发**（**TDD**）的方法，这样我们就可以确保我们的代码可以正常工作，而不必手动测试。让我们在`chat`文件夹中创建一个名为`avatar_test.go`的新文件：

```go
package main
import "testing"
func TestAuthAvatar(t *testing.T) {
  var authAvatar AuthAvatar
  client := new(client)
  url, err := authAvatar.GetAvatarURL(client)
  if err != ErrNoAvatarURL {
    t.Error("AuthAvatar.GetAvatarURL should return ErrNoAvatarURL when no value present")
  }
  // set a value
  testUrl := "http://url-to-gravatar/"
  client.userData = map[string]interface{}{"avatar_url": testUrl}
  url, err = authAvatar.GetAvatarURL(client)
  if err != nil {
    t.Error("AuthAvatar.GetAvatarURL should return no error when value present")
  } else {
    if url != testUrl {
      t.Error("AuthAvatar.GetAvatarURL should return correct URL")
    }
  }
}
```

这个测试文件包含了我们尚不存在的`AuthAvatar`类型的`GetAvatarURL`方法的测试。首先，它使用一个没有用户数据的客户端，并确保返回`ErrNoAvatarURL`错误。在设置合适的值之后，我们的测试再次调用该方法，这次是为了断言它返回正确的值。然而，构建这段代码失败了，因为`AuthAvatar`类型不存在，所以我们将接下来声明`authAvatar`。

在编写我们的实现之前，值得注意的是，我们只声明了`authAvatar`变量作为`AuthAvatar`类型，但实际上从未给它赋值，所以它的值保持为`nil`。这不是一个错误；我们实际上正在利用 Go 的零初始化（或默认初始化）能力。由于我们的对象不需要状态（我们将`client`作为参数传递），因此没有必要在初始化一个实例上浪费时间和内存。在 Go 中，可以在`nil`对象上调用方法，前提是该方法不会尝试访问字段。当我们实际编写我们的实现时，我们将考虑一种方法，以确保这种情况成立。

让我们回到`avatar.go`，让我们的测试通过。在文件底部添加以下代码：

```go
type AuthAvatar struct{}
var UseAuthAvatar AuthAvatar
func (_ AuthAvatar) GetAvatarURL(c *client) (string, error) {
  if url, ok := c.userData["avatar_url"]; ok {
    if urlStr, ok := url.(string); ok {
      return urlStr, nil
    }
  }
  return "", ErrNoAvatarURL
}
```

在这里，我们将我们的`AuthAvatar`类型定义为空结构，并定义`GetAvatarURL`方法的实现。我们还创建了一个方便的变量`UseAuthAvatar`，它具有`AuthAvatar`类型，但其值保持为`nil`。我们以后可以将`UseAuthAvatar`变量分配给任何寻找`Avatar`接口类型的字段。

通常，方法的接收器（在名称之前括号中定义的类型）将被分配给一个变量，以便在方法体中访问它。由于在我们的情况下，我们假设对象可以具有`nil`值，我们可以使用下划线告诉 Go 丢弃引用。这也作为一个额外的提醒，告诉我们自己应该避免使用它。

我们的实现主体在其他方面相对简单：我们安全地寻找`avatar_url`的值，并确保它是一个字符串，然后将其返回。如果沿途出现任何问题，我们将返回接口中定义的`ErrNoAvatarURL`错误。

让我们通过打开终端并导航到`chat`文件夹，然后输入以下内容来运行测试：

```go

go test

```

如果一切顺利，我们的测试将通过，我们将成功创建我们的第一个`Avatar`实现。

### 使用一个实现

当我们使用一个实现时，我们可以直接引用辅助变量，或者在需要功能时创建自己的接口实例。然而，这样做会违背抽象的初衷。相反，我们使用`Avatar`接口类型来指示我们需要的功能的位置。

对于我们的聊天应用程序，我们将有一种方法来获取每个聊天室的头像 URL。所以让我们更新`room`类型，使其可以保存一个`Avatar`对象。在`room.go`中，向`room struct`类型的字段定义中添加以下内容：

```go
// avatar is how avatar information will be obtained.
avatar Avatar
```

更新`newRoom`函数，以便我们可以传入一个`Avatar`实现来使用；当我们创建我们的`room`实例时，我们将简单地将这个实现分配给新字段：

```go
// newRoom makes a new room that is ready to go.
func newRoom(avatar Avatar) *room {
  return &room{
    forward: make(chan *message),
    join:    make(chan *client),
    leave:   make(chan *client),
    clients: make(map[*client]bool),
    tracer:  trace.Off(),
    avatar:  avatar,
  }
}
```

现在构建项目将突出显示`main.go`中对`newRoom`的调用是错误的，因为我们没有提供`Avatar`参数；让我们通过传入我们方便的`UseAuthAvatar`变量来更新它：

```go
r := newRoom(UseAuthAvatar)
```

我们不必创建`AuthAvatar`的实例，因此没有分配内存。在我们的情况下，这并不会带来很大的节省（因为我们的整个应用程序只有一个房间），但是想象一下，如果我们的应用程序有成千上万个房间，潜在的节省规模是多么庞大。我们命名`UseAuthAvatar`变量的方式意味着前面的代码非常容易阅读，也使我们的意图明显。

### 提示

在设计接口时考虑代码的可读性是很重要的。考虑一个接受布尔输入的方法——如果你不知道参数名称，只传递 true 或 false 会隐藏真正的含义。考虑定义一些辅助常量，如以下简短示例中所示：

```go
func move(animated bool) { /* ... */ }
const Animate = true
const DontAnimate = false
```

考虑一下以下对`move`的调用哪一个更容易理解：

```go
move(true)
move(false)
move(Animate)
move(DontAnimate)
```

现在剩下的就是将`client`更改为使用我们的新`Avatar`接口。在`client.go`中，更新`read`方法如下：

```go
func (c *client) read() {
  for {
    var msg *message
    if err := c.socket.ReadJSON(&msg); err == nil {
      msg.When = time.Now()
      msg.Name = c.userData["name"].(string)
      msg.AvatarURL, _ = c.room.avatar.GetAvatarURL(c)
      c.room.forward <- msg
    } else {
      break
    }
  }
  c.socket.Close()
}
```

在这里，我们要求`room`上的`avatar`实例为我们获取头像 URL，而不是从`userData`中提取它。

当构建和运行应用程序时，您会注意到（尽管我们稍微重构了一些东西），行为和用户体验根本没有改变。这是因为我们告诉我们的房间使用`AuthAvatar`实现。

现在让我们向房间添加另一个实现。

### Gravatar 实现

`Avitar`中的 Gravatar 实现将执行与`AuthAvatar`实现相同的工作，只是它将生成托管在[Gravatar.com](http://Gravatar.com)上的个人资料图片的 URL。让我们首先在`avatar_test.go`文件中添加一个测试：

```go
func TestGravatarAvatar(t *testing.T) {
  var gravatarAvitar GravatarAvatar
  client := new(client)
  client.userData = map[string]interface{}{"email": "MyEmailAddress@example.com"}
  url, err := gravatarAvitar.GetAvatarURL(client)
  if err != nil {
    t.Error("GravatarAvitar.GetAvatarURL should not return an error")
  }
  if url != "//www.gravatar.com/avatar/0bc83cb571cd1c50ba6f3e8a78ef1346" {
    t.Errorf("GravatarAvitar.GetAvatarURL wrongly returned %s", url)
  }
}
```

Gravatar 使用电子邮件地址的哈希来生成每个个人资料图片的唯一 ID，因此我们设置一个客户端，并确保`userData`包含一个电子邮件地址。接下来，我们调用相同的`GetAvatarURL`方法，但这次是在具有`GravatarAvatar`类型的对象上。然后我们断言返回了正确的 URL。我们已经知道这是指定电子邮件地址的适当 URL，因为它在 Gravatar 文档中作为示例列出了，这是确保我们的代码正在执行应该执行的工作的一个很好的策略。

### 提示

请记住，本书的所有源代码都可以在 GitHub 上找到。您可以通过从[`github.com/matryer/goblueprints`](https://github.com/matryer/goblueprints)复制和粘贴片段来节省构建前述核心的时间。通常硬编码诸如基本 URL 之类的东西并不是一个好主意；我们在整本书中都进行了硬编码，以使代码片段更容易阅读和更明显，但是如果您愿意，您可以在进行过程中提取它们。

运行这些测试（使用`go test`）显然会导致错误，因为我们还没有定义我们的类型。让我们回到`avatar.go`，并在确保导入`io`包的情况下添加以下代码：

```go
type GravatarAvatar struct{}
var UseGravatar GravatarAvatar
func (_ GravatarAvatar) GetAvatarURL(c *client) (string, error) {
  if email, ok := c.userData["email"]; ok {
    if emailStr, ok := email.(string); ok {
      m := md5.New()
      io.WriteString(m, strings.ToLower(emailStr))
      return fmt.Sprintf("//www.gravatar.com/avatar/%x", m.Sum(nil)), nil
    }
  }
  return "", ErrNoAvatarURL
}
```

我们使用了与`AuthAvatar`相同的模式：一个空的结构体，一个有用的`UseGravatar`变量，以及`GetAvatarURL`方法的实现本身。在这个方法中，我们遵循 Gravatar 的指南，从电子邮件地址生成 MD5 哈希（在确保它是小写之后），并将其附加到硬编码的基本 URL 上。

在 Go 中很容易实现哈希处理，这要归功于 Go 标准库的作者们的辛勤工作。`crypto`包具有令人印象深刻的密码学和哈希处理能力——所有这些都非常容易使用。在我们的情况下，我们创建一个新的`md5`哈希处理器；因为哈希处理器实现了`io.Writer`接口，我们可以使用`io.WriteString`向其中写入一串字节。调用`Sum`返回已写入字节的当前哈希值。

### 提示

您可能已经注意到，每次需要头像 URL 时，我们都会对电子邮件地址进行哈希处理。这在规模上是相当低效的，但我们应该优先考虑完成工作而不是优化。如果需要，我们随时可以回来改变这种工作方式。

现在运行测试会显示我们的代码正在工作，但我们还没有在`auth` cookie 中包含电子邮件地址。我们通过定位在`auth.go`中为`authCookieValue`对象分配值的代码，并更新它以从 Gomniauth 获取`Email`值来实现这一点：

```go
authCookieValue := objx.New(map[string]interface{}{
  "name":       user.Name(),
  "avatar_url": user.AvatarURL(),
  "email":      user.Email(),
}).MustBase64()
```

我们必须做的最后一件事是告诉我们的房间使用 Gravatar 实现而不是`AuthAvatar`实现。我们通过在`main.go`中调用`newRoom`并进行以下更改来实现这一点：

```go
r := newRoom(UseGravatar)
```

再次构建和运行聊天程序，然后转到浏览器。请记住，由于我们已更改 cookie 中存储的信息，我们必须注销并重新登录，以便看到我们的更改生效。

假设您的 Gravatar 帐户有不同的图像，您会注意到系统现在从 Gravatar 而不是认证提供程序中获取图像。使用浏览器的检查器或调试工具将显示`img`标签的`src`属性确实已更改。

![Gravatar implementation](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/go-prog-bp/img/Image00009.jpg)

如果您没有 Gravatar 帐户，您可能会看到一个默认的占位图像代替您的个人资料图片。

# 上传头像图片

在上传图片的第三种方法中，我们将看看如何允许用户从本地硬盘上传图像，以便在聊天时用作他们的个人资料图片。我们需要一种方法来将文件与特定用户关联起来，以确保我们将正确的图片与相应的消息关联起来。

## 用户识别

为了唯一标识我们的用户，我们将复制 Gravatar 的方法，通过对他们的电子邮件地址进行哈希处理，并使用结果字符串作为标识符。我们将用户 ID 与其他用户特定数据一起存储在 cookie 中。这实际上还有一个额外的好处，就是从`GravatarAuth`中删除了与持续哈希处理相关的低效。

在`auth.go`中，用以下代码替换创建`authCookieValue`对象的代码：

```go
m := md5.New()
io.WriteString(m, strings.ToLower(user.Name()))
userId := fmt.Sprintf("%x", m.Sum(nil))
// save some data
authCookieValue := objx.New(map[string]interface{}{
  "userid":     userId,
  "name":       user.Name(),
  "avatar_url": user.AvatarURL(),
  "email":      user.Email(),
}).MustBase64()
```

在用户登录时，我们对电子邮件地址进行了哈希处理，并将结果值存储在`userid`字段中。从此时起，我们可以在我们的 Gravatar 代码中使用这个值，而不是为每条消息对电子邮件地址进行哈希处理。为了做到这一点，首先我们通过从`avatar_test.go`中删除以下行来更新测试：

```go
client.userData = map[string]interface{}{"email": "MyEmailAddress@example.com"}
```

然后用这行替换前面的行：

```go
client.userData = map[string]interface{}{"userid": "0bc83cb571cd1c50ba6f3e8a78ef1346"}
```

我们不再需要设置`email`字段，因为它没有被使用；相反，我们只需要为新的`userid`字段设置一个合适的值。但是，如果您在终端中运行`go test`，您会看到这个测试失败。

为了使测试通过，在`avatar.go`中，更新`GravatarAuth`类型的`GetAvatarURL`方法：

```go
func (_ GravatarAvatar) GetAvatarURL(c *client) (string, error) {
  if userid, ok := c.userData["userid"]; ok {
    if useridStr, ok := userid.(string); ok {
      return "//www.gravatar.com/avatar/" + useridStr, nil
    }
  }
  return "", ErrNoAvatarURL
}
```

这不会改变行为，但它允许我们进行意外的优化，这是一个很好的例子，说明为什么不应该过早优化代码——你早期发现的低效可能不值得修复所需的努力。

## 一个上传表单

如果我们的用户要上传文件作为他们的头像，他们需要一种方法来浏览本地硬盘并将文件提交到服务器。我们通过添加一个新的基于模板的页面来实现这一点。在`chat/templates`文件夹中，创建一个名为`upload.html`的文件：

```go
<html>
  <head>
    <title>Upload</title>
    <link rel="stylesheet" href="//netdna.bootstrapcdn.com/bootstrap/3.1.1/css/bootstrap.min.css">
  </head>
  <body>
    <div class="container">
      <div class="page-header">
        <h1>Upload picture</h1>
      </div>
      <form role="form" action="/uploader" enctype="multipart/form-data" method="post">
        <input type="hidden" name="userid" value="{{.UserData.userid}}" />
        <div class="form-group">
          <label for="message">Select file</label>
          <input type="file" name="avatarFile" />
        </div>
        <input type="submit" value="Upload" class="btn " />
      </form>
    </div>
  </body>
</html>
```

我们再次使用 Bootstrap 使我们的页面看起来漂亮，并且使其与其他页面相匹配。但是，这里需要注意的关键点是 HTML 表单，它将为上传文件提供必要的用户界面。操作指向 `/uploader`，我们尚未实现的处理程序，`enctype` 属性必须是 `multipart/form-data`，以便浏览器可以通过 HTTP 传输二进制数据。然后，有一个 `file` 类型的 `input` 元素，它将包含我们要上传的文件的引用。还要注意，我们已将 `UserData` 映射中的 `userid` 值作为隐藏输入包含在内 —— 这将告诉我们哪个用户正在上传文件。重要的是 `name` 属性是正确的，因为这是我们在服务器上实现处理程序时将引用数据的方式。

现在让我们将新模板映射到 `main.go` 中的 `/upload` 路径：

```go
http.Handle("/upload", &templateHandler{filename: "upload.html"})
```

## 处理上传

当用户在选择文件后点击 **上传** 时，浏览器将发送文件的数据以及用户 ID 到 `/uploader`，但是现在，这些数据实际上并没有去任何地方。我们将实现一个新的 `HandlerFunc`，能够接收文件，读取通过连接流传输的字节，并将其保存为服务器上的新文件。在 `chat` 文件夹中，让我们创建一个名为 `avatars` 的新文件夹 —— 这是我们将保存头像图像文件的地方。

接下来，创建一个名为 `upload.go` 的新文件，并插入以下代码 —— 确保添加适当的包名和导入（即 `ioutils`，`net/http`，`io` 和 `path`）。

```go
func uploaderHandler(w http.ResponseWriter, req *http.Request) {
  userId := req.FormValue("userid")
  file, header, err := req.FormFile("avatarFile")
  if err != nil {
    io.WriteString(w, err.Error())
    return
  }
  data, err := ioutil.ReadAll(file)
  if err != nil {
    io.WriteString(w, err.Error())
    return
  }
  filename := path.Join("avatars", userId+path.Ext(header.Filename))
  err = ioutil.WriteFile(filename, data, 0777)
  if err != nil {
    io.WriteString(w, err.Error())
    return
  }
  io.WriteString(w, "Successful")
}
```

这里，首先 `uploaderHandler` 使用 `http.Request` 上的 `FormValue` 方法来获取我们在 HTML 表单中隐藏输入中放置的用户 ID。然后通过调用 `req.FormFile` 获取一个能够读取上传字节的 `io.Reader` 类型，它返回三个参数。第一个参数表示文件本身，具有 `multipart.File` 接口类型，也是一个 `io.Reader`。第二个是一个包含有关文件的元数据的 `multipart.FileHeader` 对象，例如文件名。最后，第三个参数是一个我们希望具有 `nil` 值的错误。

当我们说 `multipart.File` 接口类型也是 `io.Reader` 时，我们是什么意思呢？嗯，快速浏览一下 [`golang.org/pkg/mime/multipart/#File`](http://golang.org/pkg/mime/multipart/#File) 上的文档，就会清楚地看到该类型实际上只是一些其他更一般接口的包装接口。这意味着 `multipart.File` 类型可以传递给需要 `io.Reader` 的方法，因为任何实现 `multipart.File` 的对象必须实现 `io.Reader`。

### 提示

嵌入标准库接口来描述新概念是确保代码在尽可能多的上下文中工作的好方法。同样，您应该尝试编写使用尽可能简单的接口类型的代码，理想情况下是来自标准库。例如，如果您编写了一个需要读取文件内容的方法，您可以要求用户提供 `multipart.File` 类型的参数。但是，如果您要求使用 `io.Reader`，您的代码将变得更加灵活，因为任何具有适当的 `Read` 方法的类型都可以传递进来，这也包括用户定义的类型。

`ioutil.ReadAll` 方法将继续从指定的 `io.Reader` 读取，直到接收到所有字节，因此这是我们实际从客户端接收字节流的地方。然后我们使用 `path.Join` 和 `path.Ext` 来使用 `userid` 构建一个新的文件名，并从 `multipart.FileHeader` 中获取原始文件名的扩展名。

然后，我们使用`ioutil.WriteFile`方法在`avatars`文件夹中创建一个新文件。我们在文件名中使用`userid`来将图像与正确的用户关联起来，就像 Gravatar 一样。`0777`值指定我们创建的新文件具有完整的文件权限，这是一个很好的默认设置，如果您不确定应设置什么其他权限。

如果在任何阶段发生错误，我们的代码将将其写入响应，这将帮助我们调试它，或者如果一切顺利，它将写入**成功**。

为了将这个新的处理程序函数映射到`/uploader`，我们需要回到`main.go`并在`func main`中添加以下行：

```go
http.HandleFunc("/uploader", uploaderHandler)
```

现在构建并运行应用程序，并记得注销并重新登录，以便我们的代码有机会上传`auth` cookie。

```go

go build -o chat

./chat -host=:8080

```

打开`http://localhost:8080/upload`，单击**选择文件**，然后从硬盘中选择一个文件，然后单击**上传**。转到您的`chat/avatars`文件夹，您会注意到文件确实已上传并重命名为您的`userid`字段的值。

## 提供图像

现在我们有了一个在服务器上保存用户头像图像的地方，我们需要一种方法使它们可以被浏览器访问。我们通过使用`net/http`包的内置文件服务器来实现这一点。在`main.go`中，添加以下代码：

```go
http.Handle("/avatars/",
  http.StripPrefix("/avatars/",
    http.FileServer(http.Dir("./avatars"))))
```

实际上，这实际上是一行代码，已经被分解以提高可读性。`http.Handle`调用应该感觉很熟悉：我们正在指定我们要将`/avatars/`路径与指定的处理程序进行映射-这就是有趣的地方。`http.StripPrefix`和`http.FileServer`都返回`Handler`，它们使用我们在上一章中学到的装饰器模式。`StripPrefix`函数接受`Handler`，通过删除指定的前缀修改路径，并将功能传递给内部处理程序。在我们的情况下，内部处理程序是一个`http.FileServer`处理程序，它将简单地提供静态文件，提供索引列表，并在找不到文件时生成`404 Not Found`错误。`http.Dir`函数允许我们指定要公开的文件夹。

如果我们没有使用`http.StripPrefix`从请求中去掉`/avatars/`前缀，文件服务器将在实际`avatars`文件夹内寻找另一个名为`avatars`的文件夹，即`/avatars/avatars/filename`而不是`/avatars/filename`。

在打开浏览器之前，让我们构建程序并运行它`http://localhost:8080/avatars/`。您会注意到文件服务器已经生成了`avatars`文件夹内文件的列表。单击文件将要么下载文件，要么在图像的情况下简单地显示它。如果您还没有这样做，请转到`http://localhost:8080/upload`并上传一张图片，然后返回到列表页面并单击它以在浏览器中查看它。

## 本地文件的 Avatar 实现

使文件系统头像工作的最后一步是编写我们的`Avatar`接口的实现，生成指向我们在上一节中创建的文件系统端点的 URL。

让我们在我们的`avatar_test.go`文件中添加一个测试函数：

```go
func TestFileSystemAvatar(t *testing.T) {

  // make a test avatar file
  filename := path.Join("avatars", "abc.jpg")
  ioutil.WriteFile(filename, []byte{}, 0777)
  defer func() { os.Remove(filename) }()

  var fileSystemAvatar FileSystemAvatar
  client := new(client)
  client.userData = map[string]interface{}{"userid": "abc"}
  url, err := fileSystemAvatar.GetAvatarURL(client)
  if err != nil {
    t.Error("FileSystemAvatar.GetAvatarURL should not return an error")
  }
  if url != "/avatars/abc.jpg" {
    t.Errorf("FileSystemAvatar.GetAvatarURL wrongly returned %s", url)
  }
}
```

这个测试与`GravatarAvatar`测试类似，但稍微复杂一些，因为我们还在`avatars`文件夹中创建一个测试文件，并在之后将其删除。

### 提示

`defer`关键字是确保代码运行的一个很好的方法，无论在函数的其余部分发生了什么。即使我们的测试代码发生恐慌，延迟函数仍将被调用。

测试的其余部分很简单：我们在`client.userData`中设置了一个`userid`字段，并调用`GetAvatarURL`以确保我们得到正确的值。当然，运行此测试将失败，所以让我们去添加以下代码以使其在`avatar.go`中通过：

```go
type FileSystemAvatar struct{}
var UseFileSystemAvatar FileSystemAvatar
func (_ FileSystemAvatar) GetAvatarURL(c *client) (string, error) {
  if userid, ok := c.userData["userid"]; ok {
    if useridStr, ok := userid.(string); ok {
      return "/avatars/" + useridStr + ".jpg", nil
    }
  }
  return "", ErrNoAvatarURL
}
```

正如我们在这里看到的，为了生成正确的 URL，我们只需获取`userid`的值，并通过将适当的段连接在一起来构建最终的字符串。您可能已经注意到，我们已经将文件扩展名硬编码为`.jpg`，这意味着我们的聊天应用的初始版本只支持 JPEG 格式的图片。

### 提示

只支持 JPEG 可能看起来像是一个半成品的解决方案，但遵循敏捷方法论，这是完全可以的；毕竟，自定义 JPEG 个人资料图片总比没有个人资料图片要好。

通过更新`main.go`来查看我们的新代码的运行情况，以使用我们的新的`Avatar`实现：

```go
r := newRoom(UseFileSystemAvatar)
```

现在像往常一样构建和运行应用程序，然后转到`http://localhost:8080/upload`，使用 Web 表单上传一个 JPEG 图像作为您的个人资料图片。为了确保它正常工作，请选择一个不是您 Gravatar 图片或认证服务图片的独特图片。在点击**上传**后看到成功消息后，转到`http://localhost:8080/chat`并发布一条消息。您会注意到应用程序确实使用了您上传的个人资料图片。

要更改您的个人资料图片，请返回到`/upload`页面并上传不同的图片，然后跳转回`/chat`页面并发布更多消息。

### 支持不同的文件类型

为了支持不同的文件类型，我们必须让我们的`FileSystemAvatar`类型的`GetAvatarURL`方法变得更加智能。

我们将使用非常有用的`ioutil.ReadDir`方法来获取文件列表，而不是盲目地构建字符串。列表还包括目录，因此我们将使用`IsDir`方法来确定我们是否应该跳过它。

然后，我们将检查每个文件是否以`userid`字段开头（记住我们以这种方式命名我们的文件），通过调用`path.Match`来进行检查。如果文件名与`userid`字段匹配，那么我们已经找到了该用户的文件，并返回路径。如果出现任何问题或者我们找不到文件，我们像往常一样返回`ErrNoAvatarURL`错误。

使用以下代码更新`avatar.go`中的适当方法：

```go
func (_ FileSystemAvatar) GetAvatarURL(c *client) (string, error) {
  if userid, ok := c.userData["userid"]; ok {
    if useridStr, ok := userid.(string); ok {
      if files, err := ioutil.ReadDir("avatars"); err == nil {
        for _, file := range files {
          if file.IsDir() {
            continue
          }
          if match, _ := path.Match(useridStr+"*", file.Name()); match {
            return "/avatars/" + file.Name(), nil
          }
        }
      }
    }
  }
  return "", ErrNoAvatarURL
}
```

删除`avatar`文件夹中的所有文件以防混淆，并重新构建程序。这次上传一个不同类型的图像，并注意到我们的应用程序没有任何困难地处理它。

## 重构和优化我们的代码

当我们回顾我们的`Avatar`类型的使用方式时，您会注意到每当有人发送消息时，应用程序都会调用`GetAvatarURL`。在我们最新的实现中，每次调用该方法时，我们都会遍历`avatars`文件夹中的所有文件。对于一个特别健谈的用户，这可能意味着我们会在一分钟内多次重复迭代。这显然是一种资源浪费，并且很快就会成为一个扩展问题。

我们将只在用户首次登录时获取头像 URL 并将其缓存在`auth` cookie 中，而不是为每条消息获取。不幸的是，我们的`Avatar`接口类型要求我们在`GetAvatarURL`方法中传入一个`client`对象，而在我们对用户进行身份验证时并没有这样的对象。

### 提示

那么，当我们设计`Avatar`接口时，我们是否犯了一个错误？虽然这是一个自然的结论，但事实上我们做得很对。我们根据当时可用的最佳信息设计了解决方案，因此比起尝试为每种可能的情况设计，我们更早地拥有了一个可用的聊天应用。软件会在开发过程中演变并几乎总是会发生变化，并且在代码的整个生命周期中肯定会发生变化。

### 用接口替换具体类型

我们得出结论，我们的`GetAvatarURL`方法依赖于我们在需要它的时候无法获得的类型，那么有什么好的替代方案呢？我们可以将每个所需的字段作为单独的参数传递，但这将使我们的接口变得脆弱，因为一旦`Avatar`实现需要新的信息，我们就必须更改方法签名。相反，我们将创建一个新类型，封装我们的`Avatar`实现需要的信息，同时在概念上保持与我们的特定情况解耦。

在`auth.go`中，在页面顶部添加以下代码（当然是在`package`关键字下面）：

```go
import gomniauthcommon "github.com/stretchr/gomniauth/common"
type ChatUser interface {
  UniqueID() string
  AvatarURL() string
}
type chatUser struct {
  gomniauthcommon.User
  uniqueID string
}
func (u chatUser) UniqueID() string {
  return u.uniqueID
}
```

在这里，`import`语句从 Gomniauth 导入了`common`包，并同时为其指定了一个特定的名称，通过该名称可以访问它：`gomniauthcommon`。这并不是完全必要的，因为我们没有包名冲突。但是，这样做可以使代码更容易理解。

在前面的代码片段中，我们还定义了一个名为`ChatUser`的新接口类型，它公开了我们的`Avatar`实现生成正确 URL 所需的信息。然后，我们定义了一个名为`chatUser`的实际实现（注意小写字母开头），它实现了该接口。它还利用了 Go 中一个非常有趣的特性：类型嵌入。我们实际上嵌入了接口类型`gomniauth/common.User`，这意味着我们的`struct`自动实现了该接口。

您可能已经注意到，我们实际上只实现了满足`ChatUser`接口所需的两个方法中的一个。我们之所以能够这样做，是因为 Gomniauth 的`User`接口碰巧定义了相同的`AvatarURL`方法。实际上，当我们实例化我们的`chatUser`结构时——只要我们为暗示的 Gomniauth`User`字段设置适当的值——我们的对象同时实现了 Gomniauth 的`User`接口和我们自己的`ChatUser`接口。

### 以测试驱动的方式更改接口

在我们可以使用新类型之前，我们必须更新`Avatar`接口和适当的实现以利用它。由于我们将遵循 TDD 实践，我们将在测试文件中进行这些更改，看到我们尝试构建代码时的编译器错误，并在最终使测试通过之前看到失败的测试。

打开`avatar_test.go`，并用以下代码替换`TestAuthAvatar`：

```go
func TestAuthAvatar(t *testing.T) {
  var authAvatar AuthAvatar
  testUser := &gomniauthtest.TestUser{}
  testUser.On("AvatarURL").Return("", ErrNoAvatarURL)
  testChatUser := &chatUser{User: testUser}
  url, err := authAvatar.GetAvatarURL(testChatUser)
  if err != ErrNoAvatarURL {
    t.Error("AuthAvatar.GetAvatarURL should return ErrNoAvatarURL when no value present")
  }
  testUrl := "http://url-to-gravatar/"
  testUser = &gomniauthtest.TestUser{}
  testChatUser.User = testUser
  testUser.On("AvatarURL").Return(testUrl, nil)
  url, err = authAvatar.GetAvatarURL(testChatUser)
  if err != nil {
    t.Error("AuthAvatar.GetAvatarURL should return no error when value present")
  } else {
    if url != testUrl {
      t.Error("AuthAvatar.GetAvatarURL should return correct URL")
    }
  }
}
```

### 提示

您还需要像在上一节中那样将`gomniauth/test`包导入为`gomniauthtest`。

在我们定义接口之前就使用我们的新接口是检查我们思路的合理性的好方法，这是练习 TDD 的另一个优势。在这个新测试中，我们创建了 Gomniauth 提供的`TestUser`，并将其嵌入到`chatUser`类型中。然后我们将新的`chatUser`类型传递给我们的`GetAvatarURL`调用，并对输出进行了与以往相同的断言。

### 提示

Gomniauth 的`TestUser`类型很有趣，因为它利用了`Testify`包的模拟能力。有关更多信息，请参阅[`github.com/stretchr/testify`](https://github.com/stretchr/testify)。

`On`和`Return`方法允许我们告诉`TestUser`在调用特定方法时该做什么。在第一种情况下，我们告诉`AvatarURL`方法返回错误，而在第二种情况下，我们要求它返回`testUrl`值，这模拟了我们在这个测试中涵盖的两种可能结果。

更新`TestGravatarAvatar`和`TestFileSystemAvatar`测试要简单得多，因为它们仅依赖于`UniqueID`方法，其值我们可以直接控制。

用以下代码替换`avatar_test.go`中的另外两个测试：

```go
func TestGravatarAvatar(t *testing.T) {
  var gravatarAvitar GravatarAvatar
  user := &chatUser{uniqueID: "abc"}
  url, err := gravatarAvitar.GetAvatarURL(user)
  if err != nil {
    t.Error("GravatarAvitar.GetAvatarURL should not return an error")
  }
  if url != "//www.gravatar.com/avatar/abc" {
    t.Errorf("GravatarAvitar.GetAvatarURL wrongly returned %s", url)
  }
}
func TestFileSystemAvatar(t *testing.T) {
  // make a test avatar file
  filename := path.Join("avatars", "abc.jpg")
  ioutil.WriteFile(filename, []byte{}, 0777)
  defer func() { os.Remove(filename) }()
  var fileSystemAvatar FileSystemAvatar
  user := &chatUser{uniqueID: "abc"}
  url, err := fileSystemAvatar.GetAvatarURL(user)
  if err != nil {
    t.Error("FileSystemAvatar.GetAvatarURL should not return an error")
  }
  if url != "/avatars/abc.jpg" {
    t.Errorf("FileSystemAvatar.GetAvatarURL wrongly returned %s", url)
  }
}
```

当然，这个测试代码甚至不会编译，因为我们还没有更新我们的`Avatar`接口。在`avatar.go`中，更新`Avatar`接口类型中的`GetAvatarURL`签名，以接受`ChatUser`类型而不是`client`类型：

```go
GetAvatarURL(ChatUser) (string, error)
```

### 提示

请注意，我们使用的是`ChatUser`接口（大写字母开头），而不是我们内部的`chatUser`实现结构——毕竟，我们希望对我们的`GetAvatarURL`方法接受的类型保持灵活。

尝试构建将会发现我们现在有破损的实现，因为所有的`GetAvatarURL`方法仍在要求一个`client`对象。

### 修复现有的实现

更改像我们这样的接口是自动查找受影响代码部分的好方法，因为它们会导致编译器错误。当然，如果我们正在编写其他人将使用的包，我们必须对更改接口更加严格。

现在，我们将更新三个实现签名以满足新的接口，并更改方法体以使用新类型。用以下内容替换`FileSystemAvatar`的实现：

```go
func (_ FileSystemAvatar) GetAvatarURL(u ChatUser) (string, error) {
  if files, err := ioutil.ReadDir("avatars"); err == nil {
    for _, file := range files {
      if file.IsDir() {
        continue
      }
      if match, _ := path.Match(u.UniqueID()+"*", file.Name()); match {
        return "/avatars/" + file.Name(), nil
      }
    }
  }
  return "", ErrNoAvatarURL
}
```

这里的关键变化是我们不再访问客户端上的`userData`字段，而是直接在`ChatUser`接口上调用`UniqueID`。

接下来，使用以下代码更新`AuthAvatar`的实现：

```go
func (_ AuthAvatar) GetAvatarURL(u ChatUser) (string, error) {
  url := u.AvatarURL()
  if len(url) > 0 {
    return url, nil
  }
  return "", ErrNoAvatarURL
}
```

我们的新设计正在证明更简单；如果我们能减少所需的代码量，这总是一件好事。上面的代码调用了`AvatarURL`值，并且只要它不为空（或`len(url) > 0`），我们就返回它；否则，我们返回`ErrNoAvatarURL`错误。

最后，更新`GravatarAvatar`的实现：

```go
func (_ GravatarAvatar) GetAvatarURL(u ChatUser) (string, error) {
  return "//www.gravatar.com/avatar/" + u.UniqueID(), nil
}
```

### 全局变量与字段

到目前为止，我们已经将`Avatar`实现分配给了`room`类型，这使我们可以为不同的房间使用不同的头像。然而，这暴露了一个问题：当用户登录时，我们不知道他们要去哪个房间，所以我们无法知道要使用哪种`Avatar`实现。因为我们的应用程序只支持一个房间，我们将考虑另一种选择实现的方法：使用全局变量。

全局变量就是在任何类型定义之外定义的变量，并且可以从包的任何部分访问（如果它被导出，则还可以从包外部访问）。对于简单的配置，比如使用哪种`Avatar`实现，它们是一个简单易行的解决方案。在`main.go`的`import`语句下面，添加以下行：

```go
// set the active Avatar implementation
var avatars Avatar = UseFileSystemAvatar
```

这定义了`avatars`作为一个全局变量，当我们需要获取特定用户的头像 URL 时可以使用它。

### 实现我们的新设计

我们需要更改调用`GetAvatarURL`的代码，以便只访问我们放入`userData`缓存中的值（通过`auth` cookie）。更改分配`msg.AvatarURL`的行，如下所示：

```go
if avatarUrl, ok := c.userData["avatar_url"]; ok {
  msg.AvatarURL = avatarUrl.(string)
}
```

在`auth.go`的`loginHandler`中找到我们调用`provider.GetUser`的代码，并将其替换为设置`authCookieValue`对象的代码：

```go
user, err := provider.GetUser(creds)
if err != nil {
  log.Fatalln("Error when trying to get user from", provider, "-", err)
}
chatUser := &chatUser{User: user}
m := md5.New()
io.WriteString(m, strings.ToLower(user.Name()))
chatUser.uniqueID = fmt.Sprintf("%x", m.Sum(nil))
avatarURL, err := avatars.GetAvatarURL(chatUser)
if err != nil {
  log.Fatalln("Error when trying to GetAvatarURL", "-", err)
}
```

在这里，我们在设置`User`字段（表示嵌入接口）为从 Gomniauth 返回的`User`值时创建了一个新的`chatUser`变量。然后我们将`userid`的 MD5 哈希保存到`uniqueID`字段中。

调用`avatars.GetAvatarURL`是我们辛苦工作的成果，因为现在我们在流程中更早地获取了用户的头像 URL。在`auth.go`中更新`authCookieValue`行，将头像 URL 缓存在 cookie 中，并删除电子邮件地址，因为它不再需要：

```go
authCookieValue := objx.New(map[string]interface{}{
  "userid":     chatUser.uniqueID,
  "name":       user.Name(),
  "avatar_url": avatarURL,
}).MustBase64()
```

无论`Avatar`实现需要做什么工作，比如在文件系统上迭代文件，都会因为实现只在用户首次登录时执行，而不是每次发送消息时执行而得到缓解。

### 整理和测试

最后，我们终于可以剪掉在重构过程中积累的一些废料。

由于我们不再将`Avatar`实现存储在`room`中，让我们从类型中删除该字段以及所有对它的引用。在`room.go`中，从`room`结构中删除`avatar Avatar`的定义，并更新`newRoom`方法：

```go
func newRoom() *room {
  return &room{
    forward: make(chan *message),
    join:    make(chan *client),
    leave:   make(chan *client),
    clients: make(map[*client]bool),
    tracer:  trace.Off(),
  }
}
```

### 提示

记住尽可能使用编译器作为待办事项列表，并跟随错误找出你影响其他代码的地方。

在`main.go`中，删除传递给`newRoom`函数调用的参数，因为我们使用全局变量而不是这个。

在这个练习之后，最终用户体验保持不变。通常，在重构代码时，修改的是内部结构，而公共接口保持稳定和不变。

### 提示

通常，运行诸如`golint`和`go vet`之类的工具对你的代码进行检查是一个好主意，以确保它遵循良好的实践，并且不包含任何 Go 的错误，比如缺少注释或命名不当的函数。

# 合并所有三种实现

为了以一个轰轰烈烈的方式结束这一章，我们将实现一个机制，其中每个`Avatar`实现轮流尝试获取值。如果第一个实现返回`ErrNoAvatarURL`错误，我们将尝试下一个，依此类推，直到找到可用的值。

在`avatar.go`中，在`Avatar`类型下面，添加以下类型定义：

```go
type TryAvatars []Avatar
```

`TryAvatars`类型只是`Avatar`对象的一个切片；因此，我们将添加以下`GetAvatarURL`方法：

```go
func (a TryAvatars) GetAvatarURL(u ChatUser) (string, error) {
  for _, avatar := range a {
    if url, err := avatar.GetAvatarURL(u); err == nil {
      return url, nil
    }
  }
  return "", ErrNoAvatarURL
}
```

这意味着`TryAvatars`现在是一个有效的`Avatar`实现，并且可以用来替代任何特定的实现。在前面的方法中，我们按顺序迭代`Avatar`对象的切片，为每个对象调用`GetAvatarURL`。如果没有返回错误，我们返回 URL；否则，我们继续寻找。最后，如果我们无法找到一个值，我们只需根据接口设计返回`ErrNoAvatarURL`。

在`main.go`中更新`avatars`全局变量以使用我们的新实现：

```go
var avatars Avatar = TryAvatars{
  UseFileSystemAvatar,
  UseAuthAvatar,
  UseGravatar}
```

在这里，我们创建了一个新的`TryAvatars`切片类型的实例，同时将其他`Avatar`实现放在其中。顺序很重要，因为它按照它们在切片中出现的顺序对对象进行迭代。因此，首先我们的代码将检查用户是否上传了图片；如果没有，代码将检查认证服务是否有图片供我们使用。如果这两种方法都失败，将生成一个 Gravatar URL，在最坏的情况下（例如，如果用户没有添加 Gravatar 图片），将呈现一个默认的占位图像。

要查看我们的新功能的运行情况，请执行以下步骤：

1.  构建并重新运行应用程序：

```go

go build –o chat

./chat –host=:8080

```

1.  通过访问`http://localhost:8080/logout`注销。

1.  从`avatars`文件夹中删除所有图片。

1.  通过导航到`http://localhost:8080/chat`重新登录。

1.  发送一些消息并注意你的个人资料图片。

1.  访问`http://localhost:8080/upload`并上传新的个人资料图片。

1.  再次注销，然后像以前一样登录。

1.  发送一些消息并注意你的个人资料图片已更新。

# 摘要

在本章中，我们为我们的聊天应用程序添加了三种不同的个人资料图片实现。首先，我们要求认证服务为我们提供一个 URL 来使用。我们通过使用 Gomniauth 对用户资源数据的抽象来实现这一点，然后将其作为用户界面的一部分包含在每次用户发送消息时。使用 Go 的零（或默认）初始化模式，我们能够引用`Avatar`接口的不同实现而不实际创建任何实例。

我们在用户登录时将数据存储在 cookie 中。因此，还有一个事实是，由于 cookie 在我们的代码构建之间保持持久性，我们添加了一个方便的注销功能来帮助我们验证我们的更改，我们还向用户公开了这个功能，以便他们也可以注销。对代码进行其他小的更改，并在我们的聊天页面上包含 Bootstrap，大大改善了我们应用程序的外观和感觉。

我们在 Go 中使用 MD5 哈希来实现[Gravatar.com](http://Gravatar.com) API，通过对认证服务提供的电子邮件地址进行哈希处理。如果 Gravatar 不知道电子邮件地址，他们会为我们提供一个漂亮的默认占位图像，这意味着我们的用户界面永远不会因缺少图像而出现问题。

然后，我们构建并完成了一个上传表单，并关联了保存上传图片的服务器功能到`avatars`文件夹。我们看到如何通过标准库的`http.FileServer`处理程序向用户公开保存的上传图片。由于这在我们的设计中引入了效率低下的问题，导致了过多的文件系统访问，我们通过单元测试的帮助重构了我们的解决方案。通过将`GetAvatarURL`调用移动到用户登录时而不是每次发送消息时，我们使我们的代码显著提高了可扩展性。

我们特殊的`ErrNoAvatarURL`错误类型被用作接口设计的一部分，以便在无法获取适当的 URL 时通知调用代码——当我们创建`Avatars`切片类型时，这变得特别有用。通过在一系列`Avatar`类型上实现`Avatar`接口，我们能够创建一个新的实现，轮流尝试从每个可用选项中获取有效的 URL，首先是文件系统，然后是认证服务，最后是 Gravatar。我们实现了这一点，而用户与接口交互的方式完全没有受到影响。如果一个实现返回`ErrNoAvatarURL`，我们就尝试下一个。

我们的聊天应用已经准备好上线，这样我们就可以邀请朋友进行真正的对话。但首先，我们需要选择一个域名来托管它，这是我们将在下一章中讨论的事情。
