# 精通 Go Web 服务（一）

> 原文：[`zh.annas-archive.org/md5/2D0D1F51B3626D3F3DD6A0D48080FBC1`](https://zh.annas-archive.org/md5/2D0D1F51B3626D3F3DD6A0D48080FBC1)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 前言

如果有一件事比其他任何事都更多地提到 Go 语言，那就是“Go 是一种服务器语言”。

毫无疑问，Go 被设计为一种理想的服务器语言，是 C、C++和 Java 的下一代迭代版本，旨在避免过度扩展和/或过度工程化。

这种语言已经发展壮大——在狂热的社区支持下——远远超出了服务器的范畴，进入了系统工具、图形甚至是新语言的编译器。然而，Go 的本质是为强大、并发和易于部署的跨平台服务器而设计的。这正是使该语言成为本书主题的理想选择。

《Go 中的 Web 服务精通》旨在成为构建可扩展的、可用于生产的 Web 服务和 API 的指南，重点放在安全性、可扩展性和遵循 RESTful 原则上。

在本书中，我们将为社交网络构建一个基本的 API，这将使我们能够深入了解一些基本概念，如将 Go 连接到其他服务以及保持服务器安全和高可用性。

本书结束时，您应该对构建健壮、可扩展、安全和生产就绪的网络服务的所有相关实例有所经验。

# 本书涵盖的内容

第一章，“Go 中的我们的第一个 API”，快速介绍了或重新介绍了与 Go 设置和使用相关的一些核心概念，以及`http`包。

第二章，“Go 中的 RESTful 服务”，侧重于 REST 架构的指导原则，并将其转化为我们整体 API 设计基础设施。

第三章，“路由和引导”，致力于将前一章的 RESTful 实践应用于我们 API 的内置、第三方和自定义路由器的搭建。

第四章，“在 Go 中设计 API”，探讨了整体 API 设计，同时考察了其他相关概念，如在 REST 架构中利用 Web 套接字和 HTTP 状态代码。

第五章，“Go 中的模板和选项”，涵盖了利用`OPTIONS`请求端点、实现 TLS 和身份验证以及在我们的 API 中标准化响应格式的方法。

第六章，“在 Go 中访问和使用网络服务”，探讨了集成其他网络服务以安全方式进行身份验证和身份识别的方法。

第七章，“使用其他网络技术”，侧重于引入应用架构的其他关键组件，如前端反向代理服务器和解决方案，以将会话数据保留在内存或数据存储中，以便快速访问。

第八章，“Web 的响应式 Go”，着眼于以消费者的方式表达我们 API 的价值，但利用前端、客户端库来解析和呈现我们的响应。

第九章，“部署”，介绍了部署策略，包括利用进程使我们的服务器保持运行、高度可访问，并与相关服务相互连接。

第十章，“性能最大化”，强调了在生产中保持我们的 API 活跃、响应迅速和快速的各种策略。我们将研究保存在磁盘和内存中的缓存机制，以及探索我们如何将这些机制分布到多台机器或镜像中的方法。

第十一章，“安全”，更侧重于确保应用程序和敏感数据受到保护的最佳实践。我们将消除 SQL 注入和跨站脚本攻击。

# 本书所需的内容

要使用本书中的示例，您可以使用 Windows，Linux 或 OS X 计算机中的任何一个，尽管您可能会发现 Windows 在使用一些我们将使用的第三方工具时会有一些限制。

您显然需要安装 Go 语言平台。最简单的方法是通过二进制文件，在 OS X 或 Windows 上可用。 Go 也可以通过多个 Linux 软件包管理器轻松获得，例如 yum 或 aptitude。

IDE 的选择在很大程度上是个人问题，但我们推荐 Sublime Text，它对 Go 有出色的支持，还支持其他语言。我们将花一些时间详细介绍其他常见 IDE 的优缺点，详见第一章，*在 Go 中创建我们的第一个 API*。

我们将利用许多其他平台和服务，如 MySQL，MongoDB，Nginx 等。大多数应该在各个平台上都可用，但如果您使用 Windows，建议您考虑在虚拟机上运行 Linux 平台，最好是 Ubuntu 服务器，以确保最大的兼容性。

# 这本书适合谁

本书适用于那些在 Go 和服务器端 Web 服务和 API 开发方面有经验的开发人员。我们没有花时间介绍 Go 编程的基础知识，所以如果你在这方面感到不稳定，建议您在深入学习之前先进行复习。

目标读者对服务器级别的网络性能感到舒适，对 REST 作为 API 设计指导原则有一定了解，并且至少知道 Go 的本地服务器能力。

我们并不预期您对所有涉及的技术都是专家，但对 Go 的核心库有基本的理解是必要的，并且对网络服务器架构设置和维护有一般的理解是理想的。

# 约定

在本书中，您会发现一些文本样式，用于区分不同类型的信息。以下是一些这些样式的示例，以及它们的含义解释。

文本中的代码词，数据库表名，文件夹名，文件名，文件扩展名，路径名，虚拟 URL，用户输入和 Twitter 用户名显示如下：“现在在临时文件夹中下载`julia-n.m.p-win64.exe`文件。”

代码块设置如下：

```go
package main

import (
  "fmt"
)
func main() {
  fmt.Println("Here be the code")
}
```

当我们希望引起您对代码块的特定部分的注意时，相关行或项目将以粗体显示。

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
curl --head http://localhost:8080/api/user/read/1111
HTTP/1.1 200 OK
Date: Wed, 18 Jun 2014 14:09:30 GMT
Content-Length: 12
Content-Type: text/plain; charset=utf-8

```

**新术语**和**重要单词**以粗体显示。您在屏幕上看到的单词，例如菜单或对话框中的单词，会以这样的方式出现在文本中：“当用户点击**接受**时，我们将返回到我们的重定向 URL，并获得我们正在寻找的代码。”

### 注意

警告或重要说明显示在这样的框中。

### 提示

提示和技巧显示如下。


# 第一章：我们在 Go 中的第一个 API

如果您花费了时间在 Web 上开发应用程序（或者说，不管在哪里），您很快就会发现自己面临与 Web 服务或 API 进行交互的前景。

无论是您需要的库还是必须与之交互的另一个应用程序的沙盒，开发世界在很大程度上依赖于不同应用程序、语言和格式之间的合作。

毕竟，这就是我们拥有 API 的原因——允许任何两个给定平台之间的标准化通信。

如果您在 Web 上花费了很长时间，您会遇到糟糕的 API。所谓的*糟糕*是指不全面、不遵循最佳实践和标准、在语义上令人困惑或缺乏一致性的 API。您会遇到一些 API 在某些地方随意使用 OAuth 或简单的 HTTP 身份验证，而在其他地方则相反，或者更常见的是，API 忽略了 HTTP 动词的规定用途（我们将在本章后面更多地讨论这一点）。

谷歌的 Go 语言特别适用于服务器。具有内置的 HTTP 服务、数据的简单 XML 和 JSON 编码方法、高可用性和并发性，它是您的 API 的理想平台。

在本书中，我们不仅将探讨强大而干净的 API 开发，还将探讨其与其他 API 和数据源的交互，以及此类开发的最佳实践。我们将构建一个大型服务和一堆小型服务，用于个别、独立的课程。

最重要的是，到最后，您应该能够在 Go 中与任何网络 API 进行交互，并能够自己设计和执行一个完善的 API 套件。

本书至少需要对基于 Web 的 API 有一定的了解，并且需要具备初学者水平的 Go 能力，但是当我们讨论新概念时，我们会进行一些非常简要的介绍，并引导您获取更多信息，以便了解 Go 或 API 的这一方面。

我们还将稍微涉及 Go 中的并发性，但我们不会过于详细——如果您希望了解更多，请查看我撰写的书籍*Mastering Concurrency in Go*，*Packt Publishing*。

我们将在本章中涵盖以下主题：

+   了解要求和依赖关系

+   介绍 HTTP 包

+   构建我们的第一个路由

+   通过 HTTP 设置数据

+   从数据存储器向客户端提供数据

# 了解要求和依赖关系

在本书中深入研究之前，我们最好先检查一下您需要安装的东西，以便处理我们开发、测试和部署 API 的所有示例。

## 安装 Go

不用说，我们需要安装 Go 语言。但是，为了完成本书中的所有操作，您还需要安装一些相关项目。

### 注意

Go 适用于 Mac OS X、Windows 和大多数常见的 Linux 变体。您可以在[`golang.org/doc/install`](http://golang.org/doc/install)下载二进制文件。

在 Linux 上，您通常可以通过发行版的软件包管理器获取 Go。例如，您可以通过简单的`apt-get install golang`命令在 Ubuntu 上获取它。大多数发行版都有类似的方法。

除了核心语言外，我们还将与 Google App Engine 一起工作，并且测试 App Engine 的最佳方法是安装**软件开发工具包**（**SDK**）。这将允许我们在部署之前在本地测试我们的应用程序，并模拟 App Engine 上提供的许多功能。

### 注意

App Engine SDK 可以从[`developers.google.com/appengine/downloads`](https://developers.google.com/appengine/downloads)下载。

虽然我们显然最感兴趣的是 Go SDK，但您还应该获取 Python SDK，因为有一些小的依赖关系可能仅在 Go SDK 中不可用。

## 安装和使用 MySQL

我们将使用许多不同的数据库和数据存储来管理我们的测试和真实数据，而 MySQL 将是其中之一。

我们将使用 MySQL 作为我们用户的存储系统；他们的消息和他们的关系将存储在我们的较大的应用程序中（我们稍后会更多地讨论这一点）。

### 注意

MySQL 可以从[`dev.mysql.com/downloads/`](http://dev.mysql.com/downloads/)下载。

您也可以轻松地从 Linux/OS X 的软件包管理器中获取它，方法如下：

+   Ubuntu：`sudo apt-get install mysql-server mysql-client`

+   OS X 与 Homebrew：`brew install mysql`

## Redis

Redis 是我们将用于几种不同演示的两种 NoSQL 数据存储之一，包括从我们的数据库缓存数据以及 API 输出。

如果您对 NoSQL 不熟悉，我们将在示例中使用 Redis 和 Couchbase 进行一些非常简单的结果收集介绍。如果您了解 MySQL，那么 Redis 至少会感觉相似，您不需要完整的知识库来使用我们为我们的目的使用应用程序。

### 注意

Redis 可以从[`redis.io/download`](http://redis.io/download)下载。

Redis 可以在 Linux/OS X 上使用以下方式下载：

+   Ubuntu：`sudo apt-get install redis-server`

+   OS X 与 Homebrew：`brew install redis`

## Couchbase

正如前面提到的，Couchbase 将是我们将在各种产品中使用的第二个 NoSQL 解决方案，主要用于设置短暂或瞬时的键存储查找，以避免瓶颈，并作为内存缓存的实验。

与 Redis 不同，Couchbase 使用简单的 REST 命令来设置和接收数据，而且所有内容都以 JSON 格式存在。

### 注意

Couchbase 可以从[`www.couchbase.com/download`](http://www.couchbase.com/download)下载。

+   对于 Ubuntu（`deb`），请使用以下命令下载 Couchbase：

```go
dpkg -i couchbase-server version.deb

```

+   对于使用 Homebrew 的 OS X，请使用以下命令下载 Couchbase：

```go
brew install https://github.com/couchbase/homebrew/raw/stable/Library/Formula/libcouchbase.rb

```

## Nginx

尽管 Go 自带了运行高并发、高性能 Web 服务器所需的一切，但我们将尝试在我们的结果周围包装一个反向代理。我们主要这样做是为了应对关于可用性和速度的现实问题。*Nginx 在 Windows 上不是原生可用的*。

### 注意

+   对于 Ubuntu，请使用以下命令下载 Nginx：

```go
apt-get install nginx

```

+   对于使用 Homebrew 的 OS X，请使用以下命令下载 Nginx：

```go
brew install nginx

```

## Apache JMeter

我们将利用 JMeter 来对我们的 API 进行基准测试和调优。在这里您有一些选择，因为有几个模拟流量的压力测试应用程序。我们将涉及的两个是**JMeter**和 Apache 内置的**Apache Benchmark**（**AB**）平台。后者在基准测试中是一个坚定不移的选择，但在您可以向 API 发送的内容方面有些受限，因此更倾向于使用 JMeter。

在构建 API 时，我们需要考虑的一件事是其抵御高流量的能力（以及在无法抵御时引入一些缓解措施），因此我们需要知道我们的限制是什么。

### 注意

Apache JMeter 可以从[`jmeter.apache.org/download_jmeter.cgi`](http://jmeter.apache.org/download_jmeter.cgi)下载。

## 使用预定义数据集

在本书的整个过程中，虽然没有必要一直使用我们的虚拟数据集，但是当我们构建社交网络时，将其引入可以节省大量时间，因为它充满了用户、帖子和图片。

通过使用这个数据集，您可以跳过创建这些数据来测试 API 和 API 创建的某些方面。

### 注意

我们的虚拟数据集可以从[`github.com/nkozyra/masteringwebservices`](https://github.com/nkozyra/masteringwebservices)下载。

## 选择 IDE

**集成开发环境**（**IDE**）的选择是开发人员可以做出的最个人化的选择之一，很少有开发人员对自己喜欢的 IDE 不充满激情。

本书中没有任何内容需要特定的 IDE；事实上，Go 在编译、格式化和测试方面的大部分优势都在命令行级别。不过，我们至少想探索一些 Go 的更受欢迎的编辑器和 IDE 选择。

### Eclipse

作为任何语言可用的最受欢迎和最广泛的 IDE 之一，Eclipse 是一个显而易见的首选。大多数语言都通过 Eclipse 插件获得支持，Go 也不例外。

这款庞大的软件也有一些缺点；它在某些语言上偶尔会出现错误，有些自动完成功能的速度明显较慢，并且比大多数其他可用选项更加沉重。

然而，它的优点是多方面的。Eclipse 非常成熟，并且有一个庞大的社区，您可以在出现问题时寻求支持。而且，它是免费的。

### 注意

+   Eclipse 可以从[`eclipse.org/`](http://eclipse.org/)下载

+   在[`goclipse.github.io/`](http://goclipse.github.io/)获取 Goclipse 插件

### Sublime Text

Sublime Text 是我们特别喜欢的，但它有一个很大的警告——它是这里列出的唯一一个不免费的。

这款软件更像是一个完整的代码/文本编辑器，而不是一个沉重的 IDE，但它包括代码完成选项，并且可以直接将 Go 编译器（或其他语言的编译器）集成到界面中。

尽管 Sublime Text 的许可证价格为 70 美元，但许多开发人员发现它的优雅和速度是非常值得的。您可以无限期地尝试该软件，以查看它是否适合您；除非您购买许可证，否则它将作为催告软件运行。

### 注意

Sublime Text 可以从[`www.sublimetext.com/2`](http://www.sublimetext.com/2)下载。

### LiteIDE

LiteIDE 是比其他提到的 IDE 更年轻的一个，但它值得一提，因为它专注于 Go 语言。

它是跨平台的，并且在后台执行了很多 Go 的命令行魔术，使其真正集成。LiteIDE 还可以在 IDE 中直接处理代码自动完成、`go fmt`、构建、运行和测试，以及强大的包浏览器。

它是免费的，如果您想要一个精简且专门针对 Go 语言的工具，那么它绝对值得一试。

### 注意

LiteIDE 可以从[`code.google.com/p/golangide/`](https://code.google.com/p/golangide/)下载。

### IntelliJ IDEA

与 Eclipse 齐名的是 JetBrains 系列的 IDE，它涵盖了大约与 Eclipse 相同数量的语言。最终，两者都主要是以 Java 为主要考虑因素，这意味着有时其他语言的支持可能会次要。

这里的 Go 集成似乎相当强大和完整，因此如果您有许可证，那么它是值得一试的。如果您没有许可证，您可以尝试免费的 Community Edition。

### 注意

+   您可以从[`www.jetbrains.com/idea/download/`](http://www.jetbrains.com/idea/download/)下载 IntelliJ IDEA

+   Go 语言支持插件可在[`plugins.jetbrains.com/plugin/?idea&id=5047`](http://plugins.jetbrains.com/plugin/?idea&id=5047)上获得

### 一些客户端工具

尽管我们将主要关注 Go 和 API 服务，但我们将对客户端与 API 的交互进行一些可视化。

因此，我们将主要关注纯 HTML 和 JavaScript，但对于更多的交互点，我们还将使用 jQuery 和 AngularJS。

### 注意

我们为客户端演示所做的大部分内容都可以在本书的 GitHub 存储库[`github.com/nkozyra/goweb`](https://github.com/nkozyra/goweb)的 client 目录下找到。

jQuery 和 AngularJS 都可以从 Google 的 CDN 动态加载，这样您就不必在本地下载和存储它们。托管在 GitHub 上的示例会动态调用它们。

要动态加载 AngularJS，请使用以下代码：

```go
<script src="img/angular.min.js"></script>
```

要动态加载 jQuery，请使用以下代码：

```go
<script src="img/jquery.min.js"></script>
```

## 查看我们的应用程序

在本书中，我们将构建许多小应用程序来演示要点、函数、库和其他技术。但是，我们也将专注于一个更大的项目，模拟一个社交网络，在其中我们通过 API 创建和返回用户、状态等。

尽管我们将致力于构建一个更大的应用程序来演示每个部分的拼图，但我们也将构建和测试独立的应用程序、API 和接口。

后一组将以快速入门为前缀，以让您知道它不是我们更大应用程序的一部分。

## 设置我们的数据库

如前所述，我们将设计一个几乎完全在 API 级别上运行的社交网络（至少起初是这样），作为本书中的*主要*项目。

当我们想到主要的社交网络（过去和现在），它们中有一些无处不在的概念，如下所示：

+   创建用户并维护用户资料的能力

+   分享消息或状态并基于它们进行对话的能力

+   表达对所述状态/消息的喜好或厌恶，以决定任何给定消息的价值

这里还有一些其他功能，我们将从这里开始构建，但让我们从基础知识开始。让我们按以下方式在 MySQL 中创建我们的数据库：

```go
create database social_network;
```

这将是本书中我们社交网络产品的基础。目前，我们只需要一个`users`表来存储我们的个人用户及其最基本的信息。随着我们的进展，我们将对其进行修改以包括更多功能：

```go
CREATE TABLE users (
  user_id INT(10) UNSIGNED NOT NULL AUTO_INCREMENT,
  user_nickname VARCHAR(32) NOT NULL,
  user_first VARCHAR(32) NOT NULL,
  user_last VARCHAR(32) NOT NULL,
  user_email VARCHAR(128) NOT NULL,
  PRIMARY KEY (user_id),
  UNIQUE INDEX user_nickname (user_nickname)
)
```

在本章中，我们不需要做太多事情，所以这就够了。我们将拥有用户的最基本信息——姓名、昵称和电子邮件，没有太多其他信息。

# 介绍 HTTP 包

我们的大部分 API 工作将通过 REST 处理，因此您应该对 Go 的`http`包非常熟悉。

除了通过 HTTP 提供服务外，`http`包还包括许多其他非常有用的实用程序，我们将详细了解这些实用程序。这些包括 cookie jars、设置客户端、反向代理等。

但目前我们感兴趣的主要实体是`http.Server`结构，它提供了我们服务器所有操作和参数的基础。在服务器内部，我们可以设置 TCP 地址、用于路由特定请求的 HTTP 多路复用、超时和标头信息。

Go 还提供了一些快捷方式来调用服务器，而不是直接初始化结构。例如，如果您有许多默认属性，您可以使用以下代码：

```go
Server := Server {
  Addr: ":8080",
  Handler: urlHandler,
  ReadTimeout: 1000 * time.MicroSecond,
  WriteTimeout: 1000 * time.MicroSecond,
  MaxHeaderBytes: 0,
  TLSConfig: nil
}
```

您可以简单地使用以下代码执行：

```go
http.ListenAndServe(":8080", nil)
```

这将为您调用一个服务器结构并仅设置`Addr`和`Handler`属性。

当然，有时我们会想要更精细地控制我们的服务器，但目前这样就够了。让我们首次将这个概念输出一些 JSON 数据通过 HTTP。

## 快速入门-通过 API 说 Hello, World

正如本章前面提到的，我们将偏离原题，做一些我们将以**快速入门**为前缀的工作，以示它与我们更大的项目无关。

在这种情况下，我们只想激活我们的`http`包并向浏览器传递一些 JSON。毫不奇怪，我们只会向世界输出令人沮丧的`Hello, world`消息。

让我们使用所需的包和导入来设置这个：

```go
package main

import
(
  "net/http"
  "encoding/json"
  "fmt"
)
```

这是我们需要通过 HTTP 输出简单的 JSON 字符串的最低要求。编组 JSON 数据可能比我们在这里看到的要复杂一些，所以如果我们的消息结构不立即让人明白，不要担心。

这是我们的响应结构，包含我们希望从 API 中获取并发送给客户端的所有数据：

```go
type API struct {
  Message string "json:message"
}
```

显然这里还没有太多东西。我们只设置了一个消息字符串，显然命名为`Message`变量。

最后，我们需要设置我们的主要函数（如下所示）来响应路由并提供一个经过编组的 JSON 响应：

```go
func main() {

  http.HandleFunc("/api", func(w http.ResponseWriter, r *http.Request) {

    message := API{"Hello, world!"}

    output, err := json.Marshal(message)

    if err != nil {
      fmt.Println("Something went wrong!")
    }

    fmt.Fprintf(w, string(output))

  })

  http.ListenAndServe(":8080", nil)
}
```

进入`main()`后，我们设置了一个路由处理函数，以响应在`/api`处初始化一个带有`Hello, world!`的 API 结构。然后我们将其编组为 JSON 字节数组`output`，并在将此消息发送到我们的`iowriter`类（在本例中为`http.ResponseWriter`值）后，将其转换为字符串。

最后一步是一种快速而粗糙的方法，通过一个期望字符串的函数发送我们的字节数组，但在这样做时几乎不会出现什么问题。

Go 通过将类型作为环绕目标变量的函数来简单处理类型转换。换句话说，我们可以通过简单地用`int(OurInt64)`函数将`int64`值转换为整数来进行类型转换。当然，也有一些例外情况——一些类型不能直接转换，还有一些其他陷阱，但这是一般的想法。在可能的例外情况中，一些类型不能直接转换为其他类型，有些需要像`strconv`这样的包来管理类型转换。

如果我们在浏览器中输入`localhost:8080/api`（如下截图所示），您应该会得到我们期望的结果，假设一切都正确：

![快速命中-通过 API 说 Hello, World](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/ms-go-websvc/img/1304OS_01_01.jpg)

# 构建我们的第一个路由

当我们谈论 Go 术语中的路由时，我们更准确地讨论的是多路复用器或`mux`。在这种情况下，多路复用器指的是将 URL 或 URL 模式转换为内部函数。

您可以将这看作是从请求到函数（或处理程序）的简单映射。您可能会设计出类似以下的东西：

```go
/api/user  func apiUser
/api/message  func apiMessage
/api/status  func apiStatus
```

`net/http`包提供的内置 mux/router 存在一些限制。例如，您不能为路由提供通配符或正则表达式。

您可能期望能够像下面的代码片段中所讨论的那样做一些事情：

```go
  http.HandleFunc("/api/user/\d+", func(w http.ResponseWriter, r *http.Request) {

    // react dynamically to an ID as supplied in the URL

  })
```

然而，这会导致解析错误。

如果您在任何成熟的 Web API 中花费了一些时间，您会知道这是行不通的。我们需要能够对动态和不可预测的请求做出反应。这意味着无法预料每个数字用户与函数的映射是不可行的。我们需要能够接受和使用模式。

对于这个问题有一些解决方案。第一个是使用具有这种强大路由功能的第三方平台。有一些非常好的平台可供选择，所以我们现在快速看一下这些。

## Gorilla

Gorilla 是一个全面的 Web 框架，我们在本书中会经常使用它。它具有我们需要的精确的 URL 路由包（在其`gorilla/mux`包中），并且还提供一些其他非常有用的工具，如 JSON-RPC、安全 cookie 和全局会话数据。

Gorilla 的`mux`包让我们可以使用正则表达式，但它也有一些简写表达式，让我们定义我们期望的请求字符串类型，而不必写出完整的表达式。

例如，如果我们有一个像`/api/users/309`这样的请求，我们可以在 Gorilla 中简单地路由它如下：

```go
gorillaRoute := mux.NewRouter()
gorillaRoute.HandleFunc("/api/{user}", UserHandler)
```

然而，这样做存在明显的风险——通过让这一切如此开放，我们有可能遇到一些数据验证问题。如果这个函数接受任何参数，而我们只期望数字或文本，这将在我们的基础应用程序中造成问题。

因此，Gorilla 允许我们使用正则表达式来澄清这一点，如下所示：

```go
r := mux.NewRouter()
r.HandleFunc("/products/{user:\d+}", ProductHandler)
```

现在，我们只会得到我们期望的——基于数字的请求参数。让我们修改我们之前的示例，以演示这个概念：

```go
package main

import (
  "encoding/json"
  "fmt"
  "github.com/gorilla/mux"
  "net/http"
)

type API struct {
  Message string "json:message"
}

func Hello(w http.ResponseWriter, r *http.Request) {

  urlParams := mux.Vars(r)
  name := urlParams["user"]
  HelloMessage := "Hello, " + name

  message := API{HelloMessage}
  output, err := json.Marshal(message)

  if err != nil {
    fmt.Println("Something went wrong!")
  }

  fmt.Fprintf(w, string(output))

}

func main() {

  gorillaRoute := mux.NewRouter()
  gorillaRoute.HandleFunc("/api/{user:[0-9]+}", Hello)
  http.Handle("/", gorillaRoute)
  http.ListenAndServe(":8080", nil)
}
```

### 提示

**下载示例代码**

您可以从您在[`www.packtpub.com`](http://www.packtpub.com)的帐户中下载您购买的所有 Packt 图书的示例代码文件。如果您在其他地方购买了这本书，您可以访问[`www.packtpub.com/support`](http://www.packtpub.com/support)并注册，以便直接通过电子邮件接收文件。

通过这段代码，我们在路由级别上进行了一些验证。对`/api/44`的有效请求将给我们一个正确的响应，如下面的屏幕截图所示：

![大猩猩](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/ms-go-websvc/img/1304OS_01_02.jpg)

对`/api/nkozyra`之类的无效请求将给我们一个 404 响应。

### 注意

+   您可以从[`www.gorillatoolkit.org/`](http://www.gorillatoolkit.org/)下载 Gorilla web 工具包

+   其 URL 多路复用器的文档可以在[`www.gorillatoolkit.org/pkg/mux`](http://www.gorillatoolkit.org/pkg/mux)找到

## 路由

来自`drone.io`的 Routes，明确且专门用于 Go 的路由包。这使它比 Gorilla web 工具包更加专注。

在较小的应用程序中，URL 路由大多数情况下不会成为瓶颈，但随着应用程序规模的扩大，这是需要考虑的事情。对于我们的目的，例如 Gorilla 和 Routes 之间的速度差异是可以忽略不计的。

在 routes 中定义您的`mux`包非常干净简单。这是对我们的`Hello world`消息的一个变体，它响应 URL 参数：

```go
func Hello(w http.ResponseWriter, r *http.Request) {

  urlParams := r.URL.Query()
  name := urlParams.Get(":name")
  HelloMessage := "Hello, " + name
  message := API{HelloMessage}
  output, err := json.Marshal(message)

  if err != nil {
    fmt.Println("Something went wrong!")
  }

  fmt.Fprintf(w, string(output))

}

func main() {

  mux := routes.New()
  mux.Get("/api/:name", Hello)
  http.Handle("/", mux)
  http.ListenAndServe(":8080", nil)
}
```

这里的主要区别（与 Gorilla 一样）是我们将我们的`routes`多路复用器传递给`http`，而不是使用内部的多路复用器。与 Gorilla 一样，我们现在可以使用可变的 URL 模式来更改我们的输出，如下所示：

![路由](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/ms-go-websvc/img/1304OS_01_03.jpg)

### 注意

您可以在[`github.com/drone/routes`](https://github.com/drone/routes)了解有关路由及其安装方法的更多信息。

运行以下命令安装路由：

```go
go get github.com/drone/routes

```

# 通过 HTTP 设置数据

现在我们已经研究了如何处理路由，让我们尝试直接从 REST 端点向数据库中注入数据。

在这种情况下，我们将专门查看`POST`请求方法，因为在大多数情况下，当可能传输大量数据时，您希望避免`GET`请求所施加的长度限制。

### 提示

从技术上讲，`PUT`请求是在**创建-读取-更新-删除**（CRUD）概念中用于创建数据的语义上正确的方法，但多年来，`PUT`在很大程度上被边缘化为历史脚注。最近，一些支持将`PUT`（和`DELETE`）恢复到其适当位置的做法已经开始流行。Go（和 Gorilla）将乐意允许您将请求委托给任何一个，并且在我们继续前进时，我们将朝着更符合协议的语义发展。

## 连接到 MySQL

Go 具有一个内置的通用数据库连接设施，大多数第三方数据库连接包都会让步于它。Go 的默认 SQL 包是`database/sql`，它允许更一般的数据库连接，并具有一些标准化。

然而，我们暂时不会自己编写 MySQL 连接，而是使用第三方附加库。有几个可用的库，但我们将选择`Go-MySQL-Driver`。

### 注意

您可以使用以下命令安装`Go-MySQL-Driver`（需要 Git）：

```go
go get github.com/go-sql-driver/mysql

```

在本例中，我们将假设您的 MySQL 在标准端口`3306`上以 localhost 运行。如果它没有运行，请相应地进行必要的调整。这里的示例也将使用无密码的 root 帐户，以便清晰起见。

我们的导入基本上保持不变，但有两个明显的添加：`sql`包（`database/sql`）和前面提到的仅用于副作用的 MySQL 驱动，通过在其前面加下划线导入：

```go
package main

import
(
  "database/sql"
  _ "github.com/go-sql-driver/mysql"
  "encoding/json"
  "fmt"
  "github.com/gorilla/mux"
  "net/http"
)
```

我们将使用 Gorilla 设置一个新的端点。您可能还记得，当我们打算设置或创建数据时，我们通常会推动`PUT`或`POST`动词，但出于演示目的，通过附加 URL 参数是推送数据的最简单方式。以下是我们设置这个新路由的方法：

```go
  routes := mux.NewRouter()
  routes.HandleFunc("/api/user/create", CreateUser).Methods("GET")
```

### 注意

请注意，我们正在指定我们将接受此请求的动词。在实际使用中，这是推荐的`GET`请求。

我们的`CreateUser`函数将接受几个参数——`user`、`email`、`first`和`last`。`User`代表一个简短的用户名，其余的应该是不言自明的。我们将在代码之前定义一个`User`结构体，如下所示：

```go
type User struct {
  ID int "json:id"
  Name  string "json:username"
  Email string "json:email"
  First string "json:first"
  Last  string "json:last"
}
```

现在让我们来看一下`CreateUser`函数本身：

```go
func CreateUser(w http.ResponseWriter, r *http.Request) {

  NewUser := User{}
  NewUser.Name = r.FormValue("user")
  NewUser.Email = r.FormValue("email")
  NewUser.First = r.FormValue("first")
  NewUser.Last = r.FormValue("last")
  output, err := json.Marshal(NewUser)
  fmt.Println(string(output))
  if err != nil {
    fmt.Println("Something went wrong!")
  }

  sql := "INSERT INTO users set user_nickname='" + NewUser.Name + "', user_first='" + NewUser.First + "', user_last='" + NewUser.Last + "', user_email='" + NewUser.Email + "'"
  q, err := database.Exec(sql)
  if err != nil {
    fmt.Println(err)
  }
  fmt.Println(q)
}
```

当我们运行这个时，我们的路由 API 端点应该在`localhost:8080/api/user/create`可用。尽管如果你看一下调用本身，你会注意到我们需要传递 URL 参数来创建一个用户。我们还没有对我们的输入进行任何合理性检查，也没有确保它是干净的/转义的，但我们将按照以下方式访问 URL：`http://localhost:8080/api/user/create?user=nkozyra&first=Nathan&last=Kozyra&email=nathan@nathankozyra.com`。

然后，我们将在我们的`users`表中创建一个用户，如下所示：

![连接到 MySQL](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/ms-go-websvc/img/1304OS_01_04.jpg)

# 从数据存储中向客户端提供数据

显然，如果我们开始通过 API 端点设置数据，尽管很简单，我们也希望通过另一个 API 端点检索数据。我们可以轻松地修改我们当前的调用，使用以下代码包括一个提供数据返回的新路由：

```go
func GetUser(w http.ResponseWriter, r *http.Request) {

  urlParams   := mux.Vars(r)
  id       := urlParams["id"]
  ReadUser := User{}
  err := database.QueryRow("select * from users where user_id=?",id).Scan(&ReadUser.ID, &ReadUser.Name, &ReadUser.First, &ReadUser.Last, &ReadUser.Email )
  switch {
      case err == sql.ErrNoRows:
              fmt.Fprintf(w,"No such user")
      case err != nil:
              log.Fatal(err)
  fmt.Fprintf(w, "Error")
      default:
        output, _ := json.Marshal(ReadUser)
        fmt.Fprintf(w,string(output))
  }
}
```

我们在这里做了一些新的和值得注意的事情。首先，我们使用了`QueryRow()`方法而不是`Exec()`。Go 的默认数据库接口提供了一些稍有不同的查询机制。具体如下：

+   `Exec()`: 该方法用于查询（主要是`INSERT`、`UPDATE`和`DELETE`），不会返回行。

+   `Query()`: 该方法用于返回一个或多个行的查询。这通常用于`SELECT`查询。

+   `QueryRow()`: 该方法类似于`Query()`，但它只期望一个结果。这通常是一个基于行的请求，类似于我们在之前的例子中所做的。然后我们可以在该行上运行`Scan()`方法，将返回的值注入到我们结构体的属性中。

由于我们正在将返回的数据扫描到我们的结构体中，我们不会得到返回值。通过`err`值，我们运行一个开关来确定如何向用户或使用我们的 API 的应用程序传达响应。

如果我们没有行，很可能是请求中存在错误，我们会让接收方知道存在错误。

但是，如果有 SQL 错误，我们现在会保持安静。将内部错误暴露给公众是一种不好的做法。但是，我们应该回应出现了问题，而不要太具体。

最后，如果请求有效并且我们得到一条记录，我们将将其编组为 JSON 响应，并在返回之前将其转换为字符串。我们的下一个结果看起来像我们对有效请求的期望：

![从数据存储中向客户端提供数据](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/ms-go-websvc/img/1304OS_01_05.jpg)

然后，如果我们从我们的用户表中请求一个实际上不存在的特定记录，它将适当地返回错误（如下面的截图所示）：

![从数据存储中向客户端提供数据](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/ms-go-websvc/img/1304OS_01_06.jpg)

## 设置标题以为客户端添加细节

随着我们继续前进，更多地使用 HTTP 头部来传达关于我们通过 API 发送或接受的数据的重要信息的想法将会更加突出。

我们可以通过对其运行`curl`请求来快速查看通过我们的 API 发送的标头。当我们这样做时，我们会看到类似于这样的东西：

```go
curl --head http://localhost:8080/api/user/read/1111
HTTP/1.1 200 OK
Date: Wed, 18 Jun 2014 14:09:30 GMT
Content-Length: 12
Content-Type: text/plain; charset=utf-8

```

这是 Go 默认发送的一个相当小的头部集合。随着我们的前进，我们可能希望附加更多的信息头，告诉接收服务如何处理或缓存数据。

让我们非常简要地尝试设置一些头部，并将它们应用到我们的请求中，使用`http`包。我们将从更基本的响应头开始，并设置一个 Pragma。这是一个`no-cache` Pragma，告诉使用我们的 API 的用户或服务始终从我们的数据库请求最新版本。

最终，鉴于我们正在处理的数据，在这种情况下这是不必要的，但这是演示这种行为的最简单的方法。我们可能会发现，随着前进，端点缓存有助于性能，但它可能不会为我们提供最新的数据。

`http`包本身有一个非常简单的方法，既可以设置响应头，也可以获取请求头。让我们修改我们的`GetUser`函数，告诉其他服务他们不应该缓存这些数据：

```go
func GetUser(w http.ResponseWriter, r *http.Request) {

  w.Header().Set("Pragma","no-cache")
```

`Header()`方法返回`iowriter`的`Header`结构，我们可以直接使用`Set()`添加，或者使用`Get()`获取值。

既然我们已经做到了，让我们看看我们的输出如何改变：

```go
curl --head http://localhost:8080/api/user/read/1111
HTTP/1.1 200 OK
Pragma: no-cache
Date: Wed, 18 Jun 2014 14:15:35 GMT
Content-Length: 12
Content-Type: text/plain; charset=utf-8

```

正如我们所期望的，我们现在直接在 CURL 的头信息中看到我们的值，并且它正确地返回这个结果不应该被缓存。

当然，我们可以发送更有价值的响应头，与 web 服务和 API 一起发送，但这是一个很好的开始。随着我们的前进，我们将利用更多的这些，包括`Content-Encoding`、`Access-Control-Allow-Origin`和更多的头部，允许我们指定我们的数据是什么，谁可以访问它，以及他们应该期望的格式和编码。

# 总结

我们已经涉及了在 Go 中开发简单 web 服务接口的基础知识。诚然，这个特定版本非常有限且容易受攻击，但它展示了我们可以采用的基本机制，以产生可用的、正式的输出，可以被其他服务接收。

在这一点上，你应该已经掌握了开始完善这个过程和我们整个应用所需的基本工具。随着我们的推进，我们将应用更完整的设计到我们的 API 中，因为随机选择的两个 API 端点显然对我们没有太大帮助。

在下一章中，我们将深入研究 API 规划和设计，RESTful 服务的细节，以及如何将逻辑与输出分离。我们将简要涉及一些逻辑/视图分离的概念，并在第三章中向更健壮的端点和方法迈进，*路由和引导*。


# 第二章：Go 中的 RESTful 服务

当人们通常设计 API 和 Web 服务时，他们通常将它们作为事后思考，或者至少作为大型应用程序的最后一步。

这背后有很好的逻辑——应用程序首先出现，当桌子上没有产品时满足开发人员并不太有意义。因此，通常当应用程序或网站创建时，那就是核心产品，任何额外的 API 资源都是其次的。

随着 Web 近年来的变化，这个系统也有了一些变化。现在，写 API 或 Web 服务然后再写应用程序并不是完全不常见。这通常发生在高度响应的单页应用程序或移动应用程序中，其中结构和数据比演示层更重要。

我们的总体项目——一个社交网络——将展示数据和架构优先的应用程序的性质。我们将拥有一个功能齐全的社交网络，可以在 API 端点上进行遍历和操作。然而，在本书的后面，我们将在演示层上玩一些有趣的东西。

尽管这背后的概念可能被视为完全示范性的，但现实是，这种方法是当今许多新兴服务和应用程序的基础。一个新站点或服务通常会使用 API 进行启动，有时甚至只有 API。

在本章中，我们将讨论以下主题：

+   设计我们的应用程序的 API 策略

+   REST 的基础知识

+   其他 Web 服务架构和方法

+   编码数据和选择数据格式

+   REST 动作及其作用

+   使用 Gorilla 的 mux 创建端点

+   应用程序版本控制的方法

# 设计我们的应用程序

当我们着手构建更大的社交网络应用程序时，我们对我们的数据集和关系有一个大致的想法。当我们将这些扩展到 Web 服务时，我们不仅要将数据类型转换为 API 端点，还要转换关系和操作。

例如，如果我们希望找到一个用户，我们会假设数据保存在一个名为`users`的数据库中，并且我们希望能够使用`/api/users`端点检索数据。这是合理的。但是，如果我们希望获取特定用户呢？如果我们希望查看两个用户是否连接？如果我们希望编辑一个用户在另一个用户的照片上的评论？等等。

这些是我们应该考虑的事情，不仅在我们的应用程序中，也在我们围绕它构建的 Web 服务中（或者在这种情况下，反过来，因为我们的 Web 服务首先出现）。

到目前为止，我们的应用程序有一个相对简单的数据集，所以让我们以这样的方式来完善它，以便我们可以创建、检索、更新和删除用户，以及创建、检索、更新和删除用户之间的关系。我们可以把这看作是在传统社交网络上“加为好友”或“关注”某人。

首先，让我们对我们的`users`表进行一些维护。目前，我们只在`user_nickname`变量上有一个唯一索引，但让我们为`user_email`创建一个索引。考虑到理论上一个人只能绑定一个特定的电子邮件地址，这是一个相当常见和合乎逻辑的安全点。将以下内容输入到您的 MySQL 控制台中：

```go
ALTER TABLE `users`
  ADD UNIQUE INDEX `user_email` (`user_email`);
```

现在我们每个电子邮件地址只能有一个用户。这是有道理的，对吧？

接下来，让我们继续创建用户关系的基础。这些将不仅包括加为好友/关注的概念，还包括屏蔽的能力。因此，让我们为这些关系创建一个表。再次，将以下代码输入到您的控制台中：

```go
CREATE TABLE `users_relationships` (
  `users_relationship_id` INT(13) NOT NULL,
  `from_user_id` INT(10) NOT NULL,
  `to_user_id` INT(10) unsigned NOT NULL,
  `users_relationship_type` VARCHAR(10) NOT NULL,
  `users_relationship_timestamp` DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (`users_relationship_id`),
  INDEX `from_user_id` (`from_user_id`),
  INDEX `to_user_id` (`to_user_id`),
  INDEX `from_user_id_to_user_id` (`from_user_id`, `to_user_id`),

  INDEX `from_user_id_to_user_id_users_relationship_type` (`from_user_id`, `to_user_id`, `users_relationship_type`)
)
```

我们在这里做的是为包括各种用户的关系创建了一个表，以及时间戳字段告诉我们关系是何时创建的。

那么，我们现在在哪里？嗯，现在，我们有能力创建、检索、更新和删除用户信息以及用户之间的关系。我们的下一步将是构想一些 API 端点，让我们的网络服务的消费者能够做到这一点。

在上一章中，我们创建了我们的第一个端点，`/api/user/create`和`/api/user/read`。然而，如果我们想要完全控制刚才讨论的数据，我们需要更多。

在那之前，让我们谈谈与网络服务相关的最重要的概念，特别是那些利用 REST 的概念。

# 看看 REST

那么，REST 到底是什么，它从哪里来？首先，REST 代表**表述性状态转移**。这很重要，因为数据（及其元数据）的表述是数据传输的关键部分。

缩写中的**状态**方面有点误导，因为无状态实际上是架构的核心组件。

简而言之，REST 提供了一种简单的、无状态的机制，用于通过 HTTP（以及其他一些协议）呈现数据，这种机制是统一的，并包括缓存指令等控制机制。

这种架构最初是作为罗伊·菲尔丁在加州大学尔湾分校的论文的一部分而产生的。从那时起，它已经被**万维网联盟**（**W3C**）进行了编码和标准化。

一个 RESTful 应用程序或 API 将需要几个重要的组件，我们现在将概述这些组件。

## 在 API 中进行表述

API 最重要的组成部分是我们将作为网络服务一部分传递的数据。通常，它是 JSON、RSS/XML 格式的格式化文本，甚至是二进制数据。

为了设计一个网络服务，确保您的格式与您的数据匹配是一个好习惯。例如，如果您创建了一个用于传递图像数据的网络服务，很容易将这种数据塞进文本格式中。将二进制数据转换为 Base64 编码并通过 JSON 发送并不罕见。

然而，API 的一个重要考虑因素是数据大小的节俭。如果我们以前的例子并将我们的图像数据编码为 Base64，我们最终得到的 API 有效负载将增加近 40%。通过这样做，我们将增加服务的延迟并引入潜在的烦恼。如果我们可以可靠地传输数据，那就没有理由这样做。

模型中的表述也应该起到重要的作用——满足客户端更新、删除或检索特定资源的所有要求。

## 自我描述

当我们说自我描述时，我们也可以将其描述为自包含，以包括 REST 的两个核心组件——响应应该包括客户端每个请求所需的一切，并且应该包括（明确或隐含地）有关如何处理信息的信息。

第二部分涉及缓存规则，我们在第一章中简要提到了*我们在 Go 中的第一个 API*。

提供有关 API 请求中包含的资源的有价值的缓存信息是重要的。这可以消除以后的冗余或不必要的请求。

这也引入了 REST 的无状态性概念。我们的意思是每个请求都是独立存在的。正如前面提到的，任何单个请求都应该包括满足该请求所需的一切。

最重要的是，这意味着放弃普通的 Web 架构的想法，其中您可以设置 cookie 或会话变量。这本质上不是 RESTful。首先，我们的客户端不太可能支持 cookie 或持续会话。但更重要的是，它减少了对任何给定 API 端点所期望的响应的全面和明确的性质。

### 提示

自动化流程和脚本当然可以处理会话，并且它们可以像 REST 的初始提案一样处理它们。这更多是一种演示而不是 REST 拒绝将持久状态作为其精神的一部分的原因。

## URI 的重要性

出于我们稍后将在本章讨论的原因，URI 或 URL 是良好 API 设计中最关键的因素之一。有几个原因：

+   URI 应该是有信息的。我们不仅应该了解数据端点的信息，还应该知道我们可能期望看到的返回数据。其中一些是程序员的习惯用法。例如，`/api/users`会暗示我们正在寻找一组用户，而`/api/users/12345`则表示我们期望获取有关特定用户的信息。

+   URI 不应该在将来中断。很快，我们将讨论版本控制，但这只是一个地方，稳定的资源端点的期望非常重要。如果您的服务的消费者在时间上发现其应用程序中缺少或损坏的链接而没有警告，这将导致非常糟糕的用户体验。

+   无论您在开发 API 或 Web 服务时有多少远见，事情都会发生变化。考虑到这一点，我们应该通过利用 HTTP 状态代码来对现有 URI 指示新位置或错误，而不是允许它们简单地中断。

### HATEOAS

**HATEOAS**代表**超媒体作为应用程序状态的引擎**，是 REST 架构中 URI 的主要约束。其背后的核心原则要求 API 不应引用固定的资源名称或实际的层次结构本身，而应该专注于描述所请求的媒体和/或定义应用程序状态。

### 注意

您可以通过访问 Roy Fielding 的博客[`roy.gbiv.com/untangled/`](http://roy.gbiv.com/untangled/)，阅读有关 REST 及其原始作者定义的要求的更多信息。

# 其他 API 架构

除了 REST，我们还将在本书中查看并实施一些其他常见的 API 和 Web 服务架构。

在大多数情况下，我们将专注于 REST API，但我们还将涉及 SOAP 协议和用于 XML 摄入的 API，以及允许持久性的较新的异步和基于 Web 套接字的服务。

## 远程过程调用

**远程过程调用**，或**RPC**，是一种长期存在的通信方法，构成了后来成为 REST 的基础。虽然仍然有一些使用 RPC 的价值，特别是 JSON-RPC，但我们不会在本书中花太多精力来适应它。

如果您对 RPC 不熟悉，与 REST 相比，其核心区别在于只有一个端点，请求本身定义了 Web 服务的行为。

### 注意

要了解有关 JSON-RPC 的更多信息，请访问[`json-rpc.org/`](http://json-rpc.org/)。

# 选择格式

使用的格式问题曾经是一个比今天更棘手的问题。我们曾经有许多特定于个人语言和开发人员的格式，但 API 世界已经导致这些格式的广度收缩了一些。

Node 和 JavaScript 作为数据传输格式的通用语言的崛起使大多数 API 首先考虑 JSON。 JSON 是一个相对紧凑的格式，现在几乎每种主要语言都有支持，Go 也不例外。

## JSON

以下是一个简单快速的示例，说明 Go 如何使用核心包发送和接收 JSON 数据：

```go
package main

import
(
  "encoding/json"
  "net/http"
  "fmt"
)

type User struct {
  Name string `json:"name"`
  Email string `json:"email"`
  ID int `json:"int"`
}

func userRouter(w http.ResponseWriter, r *http.Request) {
  ourUser := User{}
  ourUser.Name = "Bill Smith"
  ourUser.Email = "bill.smith@example.com"
  ourUser.ID = 100

  output,_ := json.Marshal(&ourUser)
  fmt.Fprintln(w, string(output))
}

func main() {

  fmt.Println("Starting JSON server")
  http.HandleFunc("/user", userRouter)
  http.ListenAndServe(":8080",nil)

}
```

这里需要注意的是`User`结构中变量的 JSON 表示。每当您在重音符号（`` ` ``）字符时，这都代表一个符文。虽然字符串用双引号表示，字符用单引号表示，但重音符号表示应该保持不变的Unicode数据。从技术上讲，该内容保存在`int32`值中。

在一个结构体中，变量/类型声明中的第三个参数被称为标签。这些对于编码是值得注意的，因为它们可以直接翻译为 JSON 变量或 XML 标签。

如果没有标签，我们将直接返回我们的变量名。

## XML

正如前面提到的，XML 曾经是开发者的首选格式。尽管它已经退居幕后，但几乎所有的 API 今天仍然将 XML 作为一个选项呈现出来。当然，RSS 仍然是第一种选择的格式。

正如我们之前在 SOAP 示例中看到的，将数据编组成 XML 是简单的。让我们采用我们在先前 JSON 响应中使用的数据结构，并类似地将其编组成 XML 数据，如下例所示。

我们的 `User` 结构如下所示：

```go

type User struct{
  Name string `xml: "name"`
  Email string `xml: "email"`
  ID int `xml: "id"`
}

```

我们得到的输出如下：

```go

ourUser：= User{}
ourUser.Name = "Bill Smith"
ourUser.Email = "bill.smith@example.com"
ourUser.ID = 100
output，_：= xml.Marshal(&ourUser)
fmt.Fprintln(w, string(output))

```

## YAML

**YAML** 是早期尝试制定的一种类似于 JSON 的人类可读的序列化格式。在名为 `goyaml` 的第三方插件中存在一个友好的 Go 实现。

您可以在 [`godoc.org/launchpad.net/goyaml`](https://godoc.org/launchpad.net/goyaml) 上阅读更多关于 `goyaml` 的信息。要安装 `goyaml`，我们将调用 `go get launchpad.net/goyaml` 命令。

就像在 Go 中内置的默认 XML 和 JSON 方法一样，我们也可以在 YAML 数据上调用 `Marshal` 和 `Unmarshal`。使用我们先前的示例，我们可以相当容易地生成一个 YAML 文档，如下所示：

```go

package main
import (
  "fmt"
  "net/http"
  "launchpad.net/goyaml"
)
type User struct {
  Name string 
  Email string
  ID int
}
func userRouter(w http.ResponseWriter, r *http.Request) {
  ourUser := User{}
  ourUser.Name = "Bill Smith"
  ourUser.Email = "bill.smith@example.com"
  ourUser.ID = 100
  output,_ := goyaml.Marshal(&ourUser)
  fmt.Fprintln(w, string(output))
}
func main() {
  fmt.Println("Starting YAML server")
  http.HandleFunc("/user", userRouter)
  http.ListenAndServe(":8080",nil)
}

```

所获得的输出如下所示：

![YAML](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/ms-go-websvc/img/1304OS_02_02.jpg)

## CSV

**逗号分隔值**（**CSV**）格式是另一种已经不太流行的老牌格式，但它仍然在一些 API 中存在，尤其是旧的 API。

通常，在当今时代我们不建议使用 CSV 格式，但它对业务应用程序可能特别有用。更重要的是，它是内置到 Go 中的另一种编码格式。

强制将数据转换为 CSV 与在 Go 中将其编组成 JSON 或 XML 没有根本上的区别，因为 `encoding/csv` 包使用与这些子包相同的方法。

# 比较 HTTP 动作和方法

REST 的核心思想之一是数据访问和操作应受动词/方法的限制。

例如，`GET` 请求不应允许用户修改、更新或创建其中的数据。这是有道理的。`DELETE` 也是相当直接的。那么，创建和更新呢？然而，在 HTTP 的命名中并不存在这样的直接翻译的动词。

对于处理这个问题存在一些争论，但通常接受的处理方法是使用 `PUT` 来更新资源，使用 `POST` 来创建资源。

### 注意

这是根据 W3C 协议的 HTTP 1.1 的相关信息：

`POST` 和 `PUT` 请求之间的基本区别反映在请求 URI 的不同含义上。`POST` 请求中的 URI 标识将处理封闭实体的资源。该资源可能是一个接受数据的进程、某种其他协议的网关，或者是一个接受注释的独立实体。相比之下，`PUT` 请求中的 URI 标识了请求中封闭的实体——用户代理知道预期使用的 URI，服务器*不得*尝试将请求应用于其他资源。如果服务器希望请求应用于不同的 URI，它*必须*发送 301（永久移动）响应；然后用户代理可以自行决定是否重定向请求。

因此，如果我们遵循这个规则，我们可以假设以下操作将转换为以下 HTTP 动词：

| 操作 | HTTP 动词 |
| --- | --- |
| 检索数据 | `GET` |
| 创建数据 | `POST` |
| 更新数据 | `PUT` |
| 删除数据 | `DELETE` |

因此，对 `/api/users/1234` 的 `PUT` 请求将告诉我们的 Web 服务，我们正在接受将更新或覆盖 ID 为 `1234` 的用户资源数据的数据。

对 `/api/users/1234` 的 `POST` 请求将告诉我们，我们将根据其中的数据创建一个新的用户资源。

### 注意

把更新和创建方法颠倒是非常常见的，比如用`POST`来更新，用`PUT`来创建。一方面，无论哪种方式都不会太复杂。另一方面，W3C 协议相当明确。

## PATCH 方法与 PUT 方法

那么，在经过上一节的学习后，你可能会认为一切都结束了，对吧？一清二楚？然而，一如既往，总会有一些问题、意想不到的行为和相互冲突的规则。

在 2010 年，有一个关于 HTTP 的提议修改，其中包括了一个 `PATCH` 方法。`PATCH` 和 `PUT` 之间的区别有些微妙，但最简单的解释是，`PATCH` 旨在提供对资源的部分更改，而 `PUT` 则预期提供对资源的完整表示。

`PATCH` 方法还提供了潜力，可以将一个资源“复制”到另一个资源中，并提供修改后的数据。

现在，我们只关注`PUT`，但稍后我们将详细讨论 `PATCH`，特别是当我们深入研究 API 服务器端的 `OPTIONS` 方法时。

# 引入 CRUD

缩写**CRUD** 简单地表示**创建、读取（或检索）、更新和删除**。这些动词可能值得注意，因为它们与我们希望在应用程序中使用的 HTTP 动词非常相似。

正如我们在上一节讨论的那样，大多数这些动词似乎都直接对应着 HTTP 方法。我们说“似乎”，因为在 REST 中有一些点使其不能完全类似。我们稍后会在后面的章节中更详细地讨论这一点。

`CREATE`显然承担了`POST`方法的角色，`RETRIEVE`取代了`GET`，`UPDATE`取代了`PUT`/`PATCH`，而`DELETE`则取代了，额，`DELETE`。

如果我们想要对这些翻译非常认真，我们必须澄清`PUT`和`POST`不是`UPDATE`和`CREATE`的直接类比。从某种意义上说，这与`PUT`和`POST`应该提供哪些操作的混淆有关。这一切都取决于幂等性的关键概念，这意味着任何给定操作应在被调用无数次时以同样的方式作出响应。

### 提示

**幂等性**是数学和计算机科学中某些操作的性质，可以多次应用而不会改变结果超出初始应用。

现在，我们将坚持我们之前的翻译，稍后再回到`PUT`与`POST`的细节。

# 添加更多的端点

现在我们已经找到了一个优雅处理 API 版本的方式，让我们退一步重新审视用户创建。在本章的早些时候，我们创建了一些新数据集，并准备创建相应的端点。

现在你了解了 HTTP 动词的知识后，我们应该通过`POST`方法限制用户创建的访问。我们在第一章构建的示例并不完全只与`POST`请求一起使用。良好的 API 设计应规定我们有一个单一的 URI 用于创建、检索、更新和删除任何给定资源。

考虑到这一切，让我们列出我们的端点及它们应该允许用户实现的功能：

| 端点 | 方法 | 目的 |
| --- | --- | --- |
| `/api` | `OPTIONS` | 用来概括 API 中的可用操作 |
| `/api/users` | `GET` | 返回带有可选过滤参数的用户 |
| `/api/users` | `POST` | 创建用户 |
| `/api/user/123` | `PUT` | 用来更新 ID 为`123`的用户 |
| `/api/user/123` | `DELETE` | 删除 ID 为`123`的用户 |

现在，让我们对第一章中的初始 API 进行快速修改，只允许使用`POST`方法进行用户创建。

记住，我们使用了**Gorilla web toolkit**来进行路由。这对于处理请求中的模式和正则表达式非常有帮助，但现在它也很有帮助，因为它允许基于 HTTP 动词/方法进行区分。

在我们的例子中，我们创建了`/api/user/create`和`/api/user/read`端点，但我们现在知道这不是 REST 的最佳实践。因此，我们现在的目标是将任何用户的资源请求更改为`/api/users`，并将创建限制为`POST`请求以及将检索限制为`GET`请求。

在我们的主函数中，我们将改变我们的处理程序来包含一个方法，并更新我们的端点：

```go

routes := mux.NewRouter()
routes.HandleFunc("/api/users", UserCreate).Methods("POST")
routes.HandleFunc("/api/users", UsersRetrieve).Methods("GET")

```

你会注意到我们还将我们的函数名称更改为`UserCreate`和`UsersRetrieve`。随着我们扩展 API，我们需要易于理解并能直接与我们的资源相关联的方法。

让我们看一下我们的应用程序如何变化：

```go

package main
import (
  "database/sql"
  "encoding/json"
  "fmt"
  _ "github.com/go-sql-driver/mysql"
  "github.com/gorilla/mux"
  "net/http"
  "log"
)
var database *sql.DB

```

到目前为止一切都是一样的——我们需要相同的导入和连接到数据库。然而，以下代码是变化的：

```go

type Users struct {
  Users []User `json:"users"`
}

```

我们正在创建一个用于表示我们的通用`GET`请求`/api/users`的用户组的结构。这提供了一个`User{}`结构的切片：

```go

type User struct {
  ID int "json:id"
  Name  string "json:username"
  Email string "json:email"
  First string "json:first"
  Last  string "json:last"
}
func UserCreate(w http.ResponseWriter, r *http.Request) {
  NewUser := User{}
  NewUser.Name = r.FormValue("user")
  NewUser.Email = r.FormValue("email")
  NewUser.First = r.FormValue("first")
  NewUser.Last = r.FormValue("last")
  output, err := json.Marshal(NewUser)
  fmt.Println(string(output))
  if err != nil {
    fmt.Println("Something went wrong!")
  }
  sql := "INSERT INTO users set user_nickname='" + NewUser.Name + "', user_first='" + NewUser.First + "', user_last='" + NewUser.Last + "', user_email='" + NewUser.Email + "'"
  q, err := database.Exec(sql)
  if err != nil {
    fmt.Println(err)
  }
  fmt.Println(q)
}

```

对于我们实际的用户创建函数，实际上没有太多改变，至少目前是这样。接下来，我们将看一下用户数据检索方法。

```go

func UsersRetrieve(w http.ResponseWriter, r *http.Request) {
  w.Header().Set("Pragma","no-cache")
  rows,_ := database.Query("select * from users LIMIT 10")
  Response 	:= Users{}
  for rows.Next() {
    user := User{}
    rows.Scan(&user.ID, &user.Name, &user.First, &user.Last, &user.Email )
    Response.Users = append(Response.Users, user)
  }
  output,_ := json.Marshal(Response)
  fmt.Fprintln(w,string(output))
}

```

在`UsersRetrieve()`函数中，我们现在正在获取一组用户并将它们扫描到我们的`Users{}`结构中。此时，还没有一个标题给出进一步的细节，也没有任何接受起始点或结果计数的方法。我们将在下一章中做这个。

最后，我们在主函数中有我们的基本路由和 MySQL 连接：

```go

func main() {
  db, err := sql.Open("mysql", "root@/social_network")
  if err != nil {}
  database = db
  routes := mux.NewRouter()
  routes.HandleFunc("/api/users", UserCreate).Methods("POST")
  routes.HandleFunc("/api/users", UsersRetrieve).Methods("GET")
  http.Handle("/", routes)
  http.ListenAndServe(":8080", nil)
}

```

正如前面提到的，`main`中最大的区别在于我们重新命名了我们的函数，并且现在正在使用`HTTP`方法将某些操作归类。因此，即使端点是相同的，我们也能够根据我们的请求是使用`POST`还是`GET`动词来指导服务。

当我们访问`http://localhost:8080/api/users`（默认情况下，是`GET`请求）现在在我们的浏览器中，我们将得到一个我们的用户列表（尽管从技术上讲我们仍然只有一个），如下面的截图所示：

![添加更多端点](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/ms-go-websvc/img/1304OS_02_03.jpg)

# 处理 API 版本

在我们继续进行 API 之前，值得注意的是对 API 进行版本控制。

当公司更新 API 并更改版本时，他们面临的一个常见问题是在不破坏先前版本的情况下更改版本。这不仅仅是关于有效的 URL，而且还涉及到 REST 和优雅升级的最佳实践。

以我们当前的 API 为例。我们有一个介绍性的`GET`动词来访问数据，例如`/api/users`端点。然而，这实际上应该是版本化 API 的克隆。换句话说，`/api/users`应该与`/api/{current-version}/users`相同。这样，如果我们转移到另一个版本，我们的旧版本仍然受支持，但不在`{current-version}`地址上。

那么，我们如何告诉用户我们已经升级了呢？一种可能性是通过 HTTP 状态码来规定这些更改。这将允许消费者继续使用旧版本访问我们的 API，例如`/api/2.0/users`。这里的请求还将让消费者知道有一个新版本。

我们将在第三章*路由和引导*中创建我们的 API 的新版本。

# 使用链接头允许分页

这是另一个在无状态性方面有时可能难以处理的 REST 点：如何传递对下一组结果的请求？

你可能认为将其作为数据元素做这件事是有道理的。例如：

```go

{ "payload": [ "item","item 2"], "next": "http://yourdomain.com/api/users?page=2" }

```

虽然这样可能有效，但却违反了 REST 的一些原则。首先，除非我们显式返回超文本，否则我们可能不会提供直接的 URL。因此，我们可能不希望将这个值包含在响应体中。

其次，我们应该能够执行更通用的请求，并获取有关其他操作和可用终端的信息。

换句话说，如果我们仅在`http://localhost:8080/api`请求我们的 API，我们的应用程序应向消费者返回有关可能的下一步和所有可用终端的一些基本信息。

实现这一点的方法之一是使用链接标头。**链接**标头只是你与响应一起设置的另一个标头键/值。

### 提示

因为 JSON 响应通常不被认为是 RESTful，因为它们不是超媒体格式。你会发现一些 API 直接在不可靠的格式中嵌入`self`、`rel`和`next`链接头。

JSON 的主要缺点是其无法原生支持超链接。这个问题由 JSON-LD 解决，其中包括联接文档和无状态上下文。

**超文本应用语言**（**HAL**）试图做同样的事情。前者得到了 W3C 的支持，但两者都有支持者。这两种格式扩展了 JSON，虽然我们不会深入探讨任何一种，但你可以修改响应以产生任一格式。

下面是我们如何在`/api/users`的`GET`请求中实现它的方法：


```go

func UsersRetrieve(w http.ResponseWriter, r *http.Request) {
    log.Println("starting retrieval")
    start := 0
    limit := 10
    next := start + limit
    w.Header().Set("Pragma","no-cache")
    w.Header().Set("Link","<http://localhost:8080/api/users?start="+string(next)+"; rel=\"next\"")
    rows,_ := database.Query("select * from users LIMIT 10")
    Response := Users{}
    for rows.Next() {
        user := User{}
        rows.Scan(&user.ID, &user.Name, &user.First, &user.Last, &user.Email )
        Response.Users = append(Response.Users, user)
    }
    output,_ := json.Marshal(Response)
    fmt.Fprintln(w,string(output))
}

```

这告诉客户端去哪里进行进一步的分页。当我们进一步修改这段代码时，我们将包括向前和向后的分页，并响应用户参数。

# 总结

此时，您不仅应该熟悉在 REST 和其他一些协议中创建 API Web 服务的基本思想，还应该熟悉格式和协议的指导原则。

我们在本章中尝试了一些东西，我们将在接下来的几章中更深入地探讨，特别是在 Go 语言本身的各种模板实现中的 MVC。

在下一章中，我们将构建我们初始端点的其余部分，并探索更高级的路由和 URL muxing。


# 第三章：路由和引导

在过去的两章中，您应该已经熟悉了创建 API 端点、后端数据库来存储最重要信息以及通过 HTTP 请求路由和输出数据所需的机制。

对于最后一点，除了我们最基本的示例之外，我们已经使用了一个库来处理我们的 URL 多路复用器。这就是 Gorilla Web Toolkit。尽管这个库（及其相关框架）非常棒，但了解如何直接在 Go 中处理请求是值得的，特别是为了创建涉及条件和正则表达式的更健壮的 API 端点。

虽然我们简要提到了头信息对于 Web 服务消费者的重要性，包括状态代码，但随着我们继续扩展我们的应用程序，我们将开始深入研究一些重要的内容。

控制和指示状态的重要性对于 Web 服务至关重要，特别是（具有悖论性的）在无状态系统中，如 REST。我们说这是一个悖论，因为虽然服务器应该提供有关应用程序状态和每个请求的少量信息，但重要的是允许客户端根据我们所提供的绝对最小和标准机制来理解这一点。

例如，虽然我们可能在列表或 GET 请求中不提供页码，但我们希望确保消费者知道如何导航以获取更多或以前的结果集。

同样，我们可能不提供硬错误消息，尽管它存在，但我们的 Web 服务应该受到一些标准化的约束，因为它涉及我们可以在标头中提供的反馈。

在本章中，我们将涵盖以下主题：

+   扩展 Go 的多路复用器以处理更复杂的请求

+   查看 Gorilla 中更高级的请求

+   在 Gorilla 中引入 RPC 和 Web 套接字

+   处理应用程序和请求中的错误

+   处理二进制数据

我们还将为我们的 Web 应用程序创建一些消费者友好的接口，这将允许我们与我们的社交网络 API 进行交互，以满足需要`PUT`/`POST`/`DELETE`的请求，以及稍后的`OPTIONS`。

通过本章结束时，您应该已经熟悉了在 Go 中编写路由器以及扩展它们以允许更复杂的请求。

# 在 Go 中编写自定义路由器

如前所述，直到这一点，我们一直专注于使用 Gorilla Web Toolkit 来处理 URL 路由和多路复用器，主要是因为 Go 本身内部的`mux`包的简单性。

通过简单性，我们指的是模式匹配是明确的，不允许使用`http.ServeMux`结构进行通配符或正则表达式。

通过直接查看`http.ServeMux`代码的设置，您可以看到这可以使用更多的细微差别：

```go
// Find a handler on a handler map given a path string
// Most-specific (longest) pattern wins
func (mux *ServeMux) match(path string) (h Handler, pattern string) {
  var n = 0
    for k, v := range mux.m {
      if !pathMatch(k, path) {
        continue
      }
      if h == nil || len(k) > n {
        n = len(k)
        h = v.h
        pattern = v.pattern
      }
    }
    return
}
```

这里的关键部分是`!pathMatch`函数，它调用另一个方法，专门检查路径是否与`muxEntry`映射的成员完全匹配：

```go
func pathMatch(pattern, path string) bool {
  if len(pattern) == 0 {
   // should not happen
    return false
  }

  n := len(pattern)
  if pattern[n-1] != '/' {
   return pattern == path
  }
  return len(path) >= n && path[0:n] == pattern
}
```

当然，访问此代码的最好之处之一是，几乎可以毫不费力地扩展它。

有两种方法可以做到这一点。第一种是编写自己的包，几乎可以像扩展包一样使用。第二种是直接修改您的`src`目录中的代码。这种选择的缺点是在升级时可能会被替换并且随后被破坏。因此，这是一个基本上会破坏 Go 语言的选项。

考虑到这一点，我们将选择第一种选项。那么，我们如何扩展`http`包呢？简短的答案是，您实际上不能在不直接进入代码的情况下进行扩展，因此我们需要创建自己的代码，继承与我们将要处理的各种`http`结构相关的最重要的方法。

要开始这个过程，我们需要创建一个新的包。这应该放在你的 Golang `src`目录下的特定域文件夹中。在这种情况下，我们指的是传统意义上的域，但按照惯例也是指 web 目录的意义。

如果你曾经执行过`go get`命令来获取第三方包，你应该熟悉这些约定。你应该在`src`文件夹中看到类似以下截图的内容：

![在 Go 中编写自定义路由器](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/ms-go-websvc/img/1304OS_03_04.jpg)

在我们的情况下，我们只需创建一个特定于域的文件夹，用于保存我们的包。或者，你可以在你选择的代码存储库中创建项目，比如 GitHub，并直接从那里导入包，通过`go get`。

不过，现在我们只需在该目录下创建一个子文件夹，我的情况下是`nathankozyra.com`，然后一个名为`httpex`（`http`和`regex`的混成词）的文件夹，用于`http`扩展。

根据你的安装和操作系统，你的导入目录可能不会立即显而易见。要快速查看你的导入包应该在哪里，运行`go env`内部工具。你会在`GOPATH`变量下找到目录。

### 提示

如果你发现你的`go get`命令返回`GOPATH not set`错误，你需要导出`GOPATH`变量。要这样做，只需输入`export GOPATH=/your/directory`（对于 Linux 或 OS X）。在 Windows 上，你需要设置一个环境变量。

最后一个警告是，如果你使用的是 OS X，并且在通过`go get`获取包时遇到困难，你可能需要在`sudo`调用之后包含`-E`标志，以确保你使用的是本地用户的变量，而不是 root 的变量。

为了节省空间，我们不会在这里包含所有必要的代码，以便改装允许正则表达式的`http`包。为此，重要的是将所有的`ServeMux`结构、方法和变量复制到你的`httpex.go`文件中。在大多数情况下，我们会复制所有内容。你需要一些重要的导入包；你的文件应该是这样的：

```go
  package httpex

import
(
  "net/http"
  "sync"
  "sync/atomic"
  "net/url"
  "path"
  "regexp"
)

type ServeMux struct {
  mu    sync.RWMutex
  m     map[string]muxEntry
  hosts bool // whether any patterns contain hostnames
}
```

关键的变化发生在`pathMatch()`函数中，以前需要最长可能字符串的字面匹配。现在，我们将任何`==`相等比较改为正则表达式：

```go
// Does path match pattern?
func pathMatch(pattern, path string) bool {
  if len(pattern) == 0 {
    // should not happen
    return false
  }
  n := len(pattern)
  if pattern[n-1] != '/' {
 match,_ := regexp.MatchString(pattern,path)
 return match
  }
 fullMatch,_ := regexp.MatchString(pattern,string(path[0:n]))
  return len(path) >= n && fullMatch
}
```

如果所有这些看起来都像是重复造轮子，重要的是——就像 Go 中的许多东西一样——核心包在大多数情况下提供了一个很好的起点，但当你发现某些功能缺失时，你不应该犹豫去增强它们。

还有另一种快速而简单的方法来创建自己的`ServeMux`路由器，那就是拦截所有请求并对它们进行正则表达式测试。就像上一个例子一样，这并不理想（除非你希望引入一些未解决的效率问题），但在紧急情况下可以使用。以下代码演示了一个非常基本的例子：

```go
package main

import
(
  "fmt"
  "net/http"
  "regexp"
)
```

同样，我们包含了`regexp`包，以便我们可以进行正则表达式测试：

```go
func main() {

    http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {

      path := r.URL.Path
      message := "You have triggered nothing"

      testMatch,_ := regexp.MatchString("/testing[0-9]{3}",path); 

      if (testMatch == true) {
        // helper functions
        message = "You hit the test!"
      }

      fmt.Fprintln(w,message)
    })
```

在这里，我们不是为每个匹配项提供特定的处理程序，而是在单个处理程序中测试`testing[3 digits]`的匹配项，然后根据情况做出反应。

在这种情况下，我们告诉客户端，除非他们匹配模式，否则什么都没有。这个模式显然适用于`/testing123`请求，并且对于任何不匹配这个模式的东西都会失败：

```go
    http.ListenAndServe(":8080", nil)
}
```

最后，我们启动我们的 web 服务器。

# 在 Gorilla 中使用更高级的路由器

现在我们已经玩弄了一下扩展内置包的多路复用，让我们看看 Gorilla 还提供了什么。

除了简单的表达式，我们还可以获取 URL 参数并将其应用到稍后使用的变量中。我们在之前的例子中做到了这一点，但没有提供很多关于我们正在生成的内容的解释。

这是一个示例，我们如何将一个表达式转化为一个变量，用于`httpHandler`函数中：

```go
/api/users/3
/api/users/nkozyra
```

这两种方法都可以作为`GET`请求来处理`users`表中的特定实体。我们可以用以下代码来处理任何一种情况：

```go
mux := mux.NewRouter()
mux.HandleFunc("/api/users/[\w+\d+]", UserRetrieve)
```

然而，我们需要保留最后一个值以供我们的查询使用。为此，Gorilla 允许我们将该表达式设置为映射中的一个键。在这种情况下，我们可以用以下代码来解决这个问题：

```go
mux.HandleFunc("/api/users/{key}", UserRetrieve)
```

这将允许我们通过以下代码从我们的处理程序中提取该值：

```go
variables := mux.Vars(r)
key := variables["key"]
```

你会注意到我们在这里使用了`"key"`而不是一个表达式。你可以在这里都做，这样你就可以将一个正则表达式设置为一个键。例如，如果我们的用户键变量由字母、数字和破折号组成，我们可以这样设置：

```go
r.HandleFunc("/api/users/{key:[A-Za-z0-9\-]}",UserRetrieve
```

而且，在我们的`UserRetrieve`函数中，我们可以直接提取该键（或者我们添加到`mux`包中的任何其他键）：

```go
func UserRetrieve(w http.ResponseWriter, r *http.Request) {
  urlParams := mux.Vars(r)
  key := vars["key"]
}
```

# 使用 Gorilla 进行 JSON-RPC

你可能还记得第二章中我们简要介绍了 RPC，并承诺会回到它。

以 REST 作为我们的主要 Web 服务交付方法，我们将继续限制我们对 RPC 和 JSON-RPC 的了解。然而，现在是一个很好的时机来演示我们如何可以使用 Gorilla 工具包非常快速地创建 RPC 服务。

对于这个例子，我们将接受一个字符串，并通过 RPC 消息返回字符串中的总字符数：

```go
package main

import (
  "github.com/gorilla/rpc"
  "github.com/gorilla/rpc/json"
  "net/http"
  "fmt"
  "strconv"
  "unicode/utf8"
)

type RPCAPIArguments struct {
  Message string
}

type RPCAPIResponse struct {
  Message string
}

type StringService struct{}

func (h *StringService) Length(r *http.Request, arguments *RPCAPIArguments, reply *RPCAPIResponse) error {
  reply.Message = "Your string is " + fmt.Sprintf("Your string is %d chars long", utf8.RuneCountInString(arguments.Message)) + " characters long"
  return nil
}

func main() {
  fmt.Println("Starting service")
  s := rpc.NewServer()
  s.RegisterCodec(json.NewCodec(), "application/json")
  s.RegisterService(new(StringService), "")
  http.Handle("/rpc", s)
  http.ListenAndServe(":10000", nil)
}
```

关于 RPC 方法的一个重要说明是，它需要被导出，这意味着一个函数/方法必须以大写字母开头。这是 Go 对一个概念的处理方式，它在某种程度上类似于`public`/`private`。如果 RPC 方法以大写字母开头，它就会被导出到该包的范围之外，否则它基本上是`private`。

![使用 Gorilla 进行 JSON-RPC](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/ms-go-websvc/img/1304OS_03_06.jpg)

在这种情况下，如果你调用方法`stringService`而不是`StringService`，你会得到响应**找不到服务 stringService**。

# 使用服务进行 API 访问

当涉及构建和测试我们的 Web 服务时，我们将迅速遇到的一个问题是直接处理`POST`/`PUT`/`DELETE`请求，以确保我们的特定于方法的请求能够按我们的预期进行。

有几种方法可以轻松处理这个问题，而不必移动到另一台机器或构建复杂的东西。

第一种方法是我们的老朋友 cURL。迄今为止，cURL 是最受欢迎的一种通过各种协议进行网络请求的方法，它简单易用，并且几乎支持你能想到的任何语言。

### 注意

Go 中没有单独的内置 cURL 组件。然而，这在很大程度上遵循了 Go 开发人员似乎最感兴趣的精简、集成的语言设计理念。

然而，你可以看一下一些第三方解决方案：

+   `go-curl`，由 ShuYu Wang 提供的绑定，可以在[`github.com/andelf/go-curl`](https://github.com/andelf/go-curl)上找到。

+   `go-av`，一种更简单的方法，带有`http`绑定，可以在[`github.com/go-av/curl`](https://github.com/go-av/curl)上找到。

然而，为了测试，我们可以简单直接地从命令行使用 cURL。这很简单，所以构造请求既不难也不费力。

以下是我们可以使用`POST` `http`方法向`/api/users`的创建方法发出的示例调用： 

```go
curl http://localhost:8080/api/users --data "name=nkozyra&email=nkozyra@gmail.com&first=nathan&last=nathan"

```

请记住，我们已经在我们的数据库中有了这个用户，并且它是一个唯一的数据库字段，我们只需修改我们的`UserCreate`函数就可以返回一个错误。请注意，在下面的代码中，我们将我们的响应更改为一个新的`CreateResponse`结构，目前只包括一个错误字符串：

```go
  type CreateResponse struct {
    Error string "json:error"
  }
```

现在，我们来调用它。如果我们从数据库得到一个错误，我们将把它包含在我们的响应中，至少目前是这样；不久之后，我们将研究翻译。否则，它将是空的，我们可以（目前）假设用户已经成功创建。我们说*目前*，因为根据我们的请求成功或失败，我们需要向我们的客户提供更多的信息：

```go
  func UserCreate(w http.ResponseWriter, r *http.Request) {

    NewUser := User{}
    NewUser.Name = r.FormValue("user")
    NewUser.Email = r.FormValue("email")
    NewUser.First = r.FormValue("first")
    NewUser.Last = r.FormValue("last")
    output, err := json.Marshal(NewUser)
    fmt.Println(string(output))
    if err != nil {
      fmt.Println("Something went wrong!")
    }

    Response := CreateResponse{}
    sql := "INSERT INTO users SET user_nickname='" + NewUser.Name + "', user_first='" + NewUser.First + "', user_last='" + NewUser.Last + "', user_email='" + NewUser.Email + "'"
    q, err := database.Exec(sql)
    if err != nil {
      Response.Error = err.Error()
    }
    fmt.Println(q)
    createOutput,_ := json.Marshal(Response)
    fmt.Fprintln(w,string(createOutput))
  }
```

如果我们尝试通过 cURL 请求创建重复的用户，它看起来是这样的：

```go
> curl http://localhost:8080/api/users –data "name=nkozyra&email=nkozyra@gmail.com&first=nathan&last=nathan"
{"Error": "Error 1062: Duplicate entry '' for key 'user nickname'"}

```

# 使用简单的接口访问 API

我们还可以通过一个简单的带有表单的网页迅速实现命中我们的 API 的接口。当然，这是许多 API 被访问的方式——直接由客户端访问而不是由服务器端处理。

尽管我们并不建议这是我们的社交网络应用程序在实践中应该工作的方式，但它为我们提供了一种简单的可视化应用程序的方式：

```go
<!DOCTYPE html>
<html lang="en">
  <head>
    <meta charset="utf-8">
    <title>API Interface</title>
    <script src="img/jquery.min.js"></script>
    <link href="http://maxcdn.bootstrapcdn.com/bootstrap/3.2.0/css/bootstrap.min.css" rel="stylesheet">
    <script src="img/bootstrap.min.js"></xscript>
    <link rel="stylesheet" href="style.css">
    <script src="img/script.js"></script>
  </head>
  <body>

  <div class="container">
      <div class="row">
  <div class="col-12-lg">
        <h1>API Interface</h1>
    <div class="alert alert-warning" id="api-messages" role="alert"></div>

    <ul class="nav nav-tabs" role="tablist">
      <li class="active"><a href="#create" role="tab" data-toggle="tab">Create User</a></li>
    </ul>

    <div class="tab-content">
      <div class="tab-pane active" id="create">

      <div class="form-group">
      <label for="createEmail">Email</label>
      <input type="text" class="form-control" id="createEmail" placeholder="Enter email">
      </div>
      <div class="form-group">
      <label for="createUsername">Username</label>
      <input type="text" class="form-control" id="createUsername" placeholder="Enter username">
      </div>
      <div class="form-group">
            <label for="createFirst">First Name</label>
      <input type="text" class="form-control" id="createFirst" placeholder="First Name">
      </div>
      <div class="form-group">
      <label for="createLast">Last Name</label>
      <input type="text" class="form-control" id="createLast" placeholder="Last Name">
      </div>

      <button type="submit" onclick="userCreate();" class="btn btn-success">Create</button>

      </div>

    </div>
  </div>
  </div>

  </div>

  <script>

  function userCreate() {
    action = "http://localhost:8080/api/users";
    postData = {};
    postData.email  = $('#createEmail').val();
    postData.user  = $('#createUsername').val();
    postData.first  = $('#createFirst').val();
    postData.last = $('#createLast').val();

    $.post(action,postData,function(data) {
      if (data.error) {
        $('.alert').html(data.error);
        $('.alert').alert();
      }
    },'jsonp');
  }

  $(document).ready(function() {
    $('.alert').alert('close');

  });
  </script>
  </body>
</html>
```

当这个被渲染时，我们将有一个快速的基本可视化表单，用于将数据输入到我们的 API 中，以及返回有价值的错误信息和反馈。

### 提示

由于跨域限制，您可能希望从与我们的 API 服务器相同的端口和域运行此文件，或者在服务器文件本身的每个请求中包含此标头：

```go
w.Header().Set("Access-Control-Allow-Origin","http://localhost:9000")
```

这里，`http://localhost:9000`代表请求的来源服务器。

我们渲染的 HTML 演示如下：

使用简单的接口访问 API

# 返回有价值的错误信息

在上次请求中返回错误时，我们只是代理了 MySQL 错误并将其传递。不过这并不总是有帮助，因为似乎至少需要对 MySQL 有一定的了解才能为客户端提供有价值的信息。

当然，MySQL 本身有一个相当清晰和简单的错误消息系统，但关键是它是特定于 MySQL 而不是我们的应用程序。

如果您的客户端不理解“重复条目”是什么意思怎么办？如果他们不会说英语怎么办？您会翻译消息，还是会告诉所有依赖项每个请求返回什么语言？现在您可以看到为什么这可能会变得繁琐。

大多数 API 都有自己的错误报告系统，即使只是为了控制消息。虽然最理想的是根据请求头的语言返回语言，但如果不能，返回错误代码也是有帮助的，这样你（或其他方）可以在以后提供翻译。

然后还有通过 HTTP 状态代码返回的最关键的错误。默认情况下，我们使用 Go 的`http`包生成了一些这样的错误，因为对无效资源的任何请求都会提供一个标准的 404 **未找到**消息。

但是，还有一些特定于 REST 的错误代码，我们很快就会介绍。目前，有一个与我们的错误相关的错误代码：409。

### 注意

根据 W3C 的 RFC 2616 协议规范，我们可以发送一个表示冲突的 409 代码。以下是规范的说明：

由于资源的当前状态与请求的冲突，请求无法完成。此代码仅允许在预期用户可能能够解决冲突并重新提交请求的情况下使用。响应正文应包含足够的信息，以便用户识别冲突的来源。理想情况下，响应实体将包含足够的信息，以便用户或用户代理程序解决问题；但这可能是不可能的，也不是必需的。

冲突最有可能发生在对`PUT`请求的响应中。例如，如果正在使用版本控制，并且`PUT`的实体包含与之前（第三方）请求所做的更改冲突的资源更改，服务器可能使用 409 响应来指示它无法完成请求。在这种情况下，响应实体可能包含两个版本之间差异的列表，格式由响应`Content-Type`定义。

考虑到这一点，让我们首先检测一个指示现有记录并阻止创建新记录的错误。

不幸的是，Go 并没有返回特定的数据库错误代码，但至少对于 MySQL 来说，如果我们知道使用的模式，提取错误就足够简单了。

使用以下代码，我们将构建一个解析器，将 MySQL 错误字符串分割成两个组件并返回一个整数错误代码：

```go
  func dbErrorParse(err string) (string, int64) {
    Parts := strings.Split(err, ":")
    errorMessage := Parts[1]
    Code := strings.Split(Parts[0],"Error ")
    errorCode,_ := strconv.ParseInt(Code[1],10,32)
    return errorMessage, errorCode
  }
```

我们还将用错误状态码来增强我们的`CreateResponse`结构，表示如下：

```go
  type CreateResponse struct {
    Error string "json:error"
    ErrorCode int "json:code"
  }
```

我们还将把 MySQL 的响应和消息转换成一个`CreateResponse`结构，通过改变`UsersCreate`函数中的错误响应行为：

```go
    if err != nil {
      errorMessage, errorCode := dbErrorParse( err.Error() )
      fmt.Println(errorMessage)
      error, httpCode, msg := ErrorMessages(errorCode)
      Response.Error = msg
      Response.ErrorCode = error
      fmt.Println(httpCode)
    }
```

您会注意到我们之前定义的`dbErrorParse`函数。我们将从中获取的结果注入到一个`ErrorMessages`函数中，该函数返回有关任何给定错误的细致信息，而不仅仅是数据库错误：

```go
type ErrMsg struct {
    ErrCode int
    StatusCode int
    Msg string
}
func ErrorMessages(err int64) (ErrMsg) {
    var em ErrMsg{}
    errorMessage := ""
    statusCode := 200;
    errorCode := 0
    switch (err) {
      case 1062:
        errorMessage = "Duplicate entry"
        errorCode = 10
        statusCode = 409
    }

    em.ErrCode = errorCode
    em.StatusCode = statusCode
    em.Msg = errorMsg

    return em

  }
```

目前，这还比较简单，只处理一种类型的错误。随着我们的进展，我们将扩展这一点，并添加更多的错误处理机制和消息（以及尝试翻译表）。

关于 HTTP 状态码，我们还需要做最后一件事。设置 HTTP 状态码的最简单方法是通过`http.Error()`函数：

```go
      http.Error(w, "Conflict", httpCode)
```

如果我们把这放在我们的错误条件块中，我们将返回从`ErrorMessages()`函数接收到的任何状态码：

```go
    if err != nil {
      errorMessage, errorCode := dbErrorParse( err.Error() )
      fmt.Println(errorMessage)
            error, httpCode, msg := ErrorMessages(errorCode)
      Response.Error = msg
      Response.ErrorCode = error
      http.Error(w, "Conflict", httpCode)
    }
```

使用 cURL 和 verbose 标志（`-v`）再次运行这个命令，将会给我们提供关于错误的额外信息，如下面的截图所示：

![返回有价值的错误信息](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/ms-go-websvc/img/1304OS_03_03.jpg)

# 处理二进制数据

首先，我们需要在 MySQL 中创建一个新的字段来容纳图像数据。在这种情况下，我们可以选择`BLOB`数据，它接受大量的任意二进制数据。为此，我们可以假设（或强制）图像不应超过 16MB，因此`MEDIUMBLOB`将处理我们提供的所有数据：

```go
ALTER TABLE `users`
  ADD COLUMN `user_image` MEDIUMBLOB NOT NULL AFTER `user_email`;
```

现在我们的图像列已经就位，我们可以接受数据。在我们的表单中添加另一个字段来存储图像数据：

```go
<div class="form-group">
<label for="createLast">Image</label>
<input type="file" class="form-control" name="image" id="createImage" placeholder="Image">
</div>
```

在我们的服务器中，我们可以进行一些快速的修改来接受这个数据。首先，我们应该从表单中获取文件数据本身，如下所示：

```go
    f, _, err := r.FormFile("image1")
    if err != nil { 
      fmt.Println(err.Error())
    }
```

接下来，我们想要读取整个文件并将其转换为一个字符串：

```go
    fileData,_ := ioutil.ReadAll(f)
```

然后，我们将把它打包成一个`base64`编码的文本表示我们的图像数据：

```go
    fileString := base64.StdEncoding.EncodeToString(fileData)
```

最后，我们在查询中加入新用户图像数据：

```go
sql := "INSERT INTO users set user_image='" + fileString + "',  user_nickname='"
```

### 注

我们将在我们关于安全性的最后一章中回顾一下这里组装的一些 SQL 语句。

# 总结

三章之后，我们已经有了一个简单的社交网络应用程序的框架，我们可以在 REST 和 JSON-RPC 中复制。我们还花了一些时间来正确地将错误传递给 REST 中的客户端。

在我们的下一章中，《在 Go 中设计 API》，我们将真正开始完善我们的社交网络，并探索其他 Go 包，这些包对于拥有一个强大、健壮的 API 是相关的。

此外，我们将引入一些其他库和外部服务，以帮助在用户和他们的关系之间建立连接时提供详细的响应。

最后，我们还将开始尝试使用 Web 套接字，以便在 Web 上为客户端提供更交互式的体验。最后，我们将处理二进制数据，允许我们的客户端通过我们的 API 上传图像。
