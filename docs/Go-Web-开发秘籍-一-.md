# Go Web 开发秘籍（一）

> 原文：[`zh.annas-archive.org/md5/6712F93A50A8E516D2DB7024F42646AC`](https://zh.annas-archive.org/md5/6712F93A50A8E516D2DB7024F42646AC)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 前言

Go 是一种设计用于扩展并支持语言级并发性的开源编程语言，这使得开发人员可以轻松编写大型并发的 Web 应用程序。

从创建 Web 应用程序到在 AWS 上部署，这将是一个学习 Go Web 开发的一站式指南。无论您是新手程序员还是专业开发人员，本书都将帮助您快速掌握 Go Web 开发。

本书将专注于在 Go 中编写模块化代码，并包含深入的信息性配方，逐步构建基础。您将学习如何创建服务器、处理 HTML 表单、会话和错误处理、SQL 和 NoSQL 数据库、Beego、创建和保护 RESTful Web 服务、创建、单元测试和调试 WebSockets，以及创建 Go Docker 容器并在 AWS 上部署它们等概念和配方。

通过本书，您将能够将您在 Go 中学到的新技能应用于在任何领域创建和探索 Web 应用程序。

# 本书适合人群

本书适用于希望使用 Go 编写大型并发 Web 应用程序的开发人员。对 Go 有一定了解的读者会发现本书最有益。

# 本书内容

第一章《在 Go 中创建您的第一个服务器》解释了如何编写和与 HTTP 和 TCP 服务器交互，使用 GZIP 压缩优化服务器响应，并在 Go Web 应用程序中实现路由和日志记录。

第二章《处理模板、静态文件和 HTML 表单》介绍了如何创建 HTML 模板；从文件系统中提供静态资源；创建、读取和验证 HTML 表单；以及为 Go Web 应用程序实现简单的用户身份验证。

第三章《在 Go 中处理会话、错误和缓存》探讨了实现 HTTP 会话、HTTP cookie、错误处理和缓存，以及使用 Redis 管理 HTTP 会话，这对于在多个数据中心部署的 Web 应用程序是必需的。

第四章《在 Go 中编写和消费 RESTful Web 服务》解释了如何编写 RESTful Web 服务、对其进行版本控制，并创建 AngularJS 与 TypeScript 2、ReactJS 和 VueJS 客户端来消费它们。

第五章《使用 SQL 和 NoSQL 数据库》介绍了在 Go Web 应用程序中使用 MySQL 和 MongoDB 数据库实现 CRUD 操作。

第六章《使用微服务工具包 Go 编写微服务》专注于使用协议缓冲区编写和处理微服务，使用微服务发现客户端（如 Consul），使用 Go Micro 编写微服务，并通过命令行和 Web 仪表板与它们进行交互，以及实现 API 网关模式以通过 HTTP 协议访问微服务。

第七章《在 Go 中使用 WebSocket》介绍了如何编写 WebSocket 服务器及其客户端，以及如何使用 GoLand IDE 编写单元测试并进行调试。

第八章《使用 Go Web 应用程序框架-Beego》介绍了设置 Beego 项目架构，编写控制器、视图和过滤器，实现与 Redis 支持的缓存，以及使用 Nginx 监控和部署 Beego 应用程序。

第九章《使用 Go 和 Docker》介绍了如何编写 Docker 镜像、创建 Docker 容器、用户定义的 Docker 网络、使用 Docker Registry，并运行与另一个 Docker 容器链接的 Go Web 应用程序 Docker 容器。

第十章，*保护 Go Web 应用程序*，演示了使用 OpenSSL 创建服务器证书和私钥，将 HTTP 服务器转移到 HTTPS，使用 JSON Web Token（JWT）保护 RESTful API，并防止 Go Web 应用程序中的跨站点请求伪造。

第十一章，*将 Go Web 应用程序和 Docker 容器部署到 AWS*，讨论了设置 EC2 实例，交互以及在其上运行 Go Web 应用程序和 Go Docker 容器。

# 充分利用本书

读者应具备 Go 的基本知识，并在计算机上安装 Go 以执行说明和代码。

# 下载示例代码文件

您可以从[www.packtpub.com](http://www.packtpub.com)的帐户中下载本书的示例代码文件。如果您在其他地方购买了本书，可以访问[www.packtpub.com/support](http://www.packtpub.com/support)并注册，以便将文件直接发送到您的邮箱。

您可以按照以下步骤下载代码文件：

1.  登录或注册[www.packtpub.com](http://www.packtpub.com/support)。

1.  选择“支持”选项卡。

1.  单击“代码下载和勘误”。

1.  在搜索框中输入书名，然后按照屏幕上的说明操作。

下载文件后，请确保使用最新版本的以下软件解压缩或提取文件夹：

+   WinRAR/7-Zip for Windows

+   Zipeg/iZip/UnRarX for Mac

+   7-Zip/PeaZip for Linux

本书的代码包也托管在 GitHub 上，网址为[`github.com/PacktPublishing/Go-Web-Development-Cookbook`](https://github.com/PacktPublishing/Go-Web-Development-Cookbook)。我们还有来自丰富书籍和视频目录的其他代码包，可在**[`github.com/PacktPublishing/`](https://github.com/PacktPublishing/)**上找到。快去看看吧！

# 下载彩色图像

我们还提供了一个 PDF 文件，其中包含本书中使用的屏幕截图/图表的彩色图像。您可以在这里下载：[`www.packtpub.com/sites/default/files/downloads/GoWebDevelopmentCookbook_ColorImages.pdf`](http://www.packtpub.com/sites/default/files/downloads/GoWebDevelopmentCookbook_ColorImages.pdf)。

# 使用的约定

本书中使用了许多文本约定。

`CodeInText`：表示文本中的代码词、数据库表名、文件夹名、文件名、文件扩展名、路径名、虚拟 URL、用户输入和 Twitter 句柄。例如：“GZIP 压缩意味着从服务器以`.gzip`格式向客户端发送响应，而不是发送纯文本响应。”

代码块设置如下：

```go
for 
{
  conn, err := listener.Accept()
  if err != nil 
  {
    log.Fatal("Error accepting: ", err.Error())
  }
  log.Println(conn)
}
```

任何命令行输入或输出都以以下方式编写：

```go
$ go get github.com/gorilla/handlers
$ go get github.com/gorilla/mux
```

**粗体**：表示新术语、重要单词或屏幕上看到的单词。例如，菜单或对话框中的单词会在文本中出现。例如：“AngularJS 客户端页面具有 HTML 表单，其中显示如下的 Id、FirstName 和 LastName 字段。”

警告或重要说明看起来像这样。

提示和技巧看起来像这样。

# 章节

在本书中，您会经常看到几个标题（*准备工作*，*如何做*，*工作原理*，*更多内容*和*另请参阅*）。

为了清晰地说明如何完成配方，使用以下各节：

# 准备工作

本节告诉您该配方中可以期望的内容，并描述了为该配方设置任何软件或任何先决设置所需的步骤。

# 如何做…

本节包含遵循该配方所需的步骤。

# 工作原理…

本节通常包括对前一节发生的事情的详细解释。

# 更多内容…

本节包含有关该配方的其他信息，以使您对该配方更加了解。

# 另请参阅

本节提供了有关该配方的其他有用信息的链接。


# 第一章：在 Go 中创建你的第一个服务器

在本章中，我们将涵盖以下内容：

+   创建一个简单的 HTTP 服务器

+   在一个简单的 HTTP 服务器上实现基本身份验证

+   使用 GZIP 压缩优化 HTTP 服务器响应

+   创建一个简单的 TCP 服务器

+   从 TCP 连接读取数据

+   向 TCP 连接写入数据

+   实现 HTTP 请求路由

+   使用 Gorilla Mux 实现 HTTP 请求路由

+   记录 HTTP 请求

# 介绍

Go 是为了解决多核处理器的新架构带来的问题而创建的，它创建了高性能网络，可以处理数百万个请求和计算密集型任务。Go 的理念是通过实现快速原型设计、减少编译和构建时间以及实现更好的依赖管理来提高生产力。

与大多数其他编程语言不同，Go 提供了`net/http`包，用于创建 HTTP 客户端和服务器。本章将介绍在 Go 中创建 HTTP 和 TCP 服务器。

我们将从一些简单的示例开始，创建一个 HTTP 和 TCP 服务器，并逐渐转向更复杂的示例，其中我们实现基本身份验证、优化服务器响应、定义多个路由和记录 HTTP 请求。我们还将涵盖 Go 处理程序、Goroutines 和 Gorilla 等概念和关键字-Go 的 Web 工具包。

# 创建一个简单的 HTTP 服务器

作为程序员，如果你需要创建一个简单的 HTTP 服务器，那么你可以很容易地使用 Go 的`net/http`包来编写，我们将在这个示例中介绍。

# 如何做…

在这个示例中，我们将创建一个简单的 HTTP 服务器，当我们在浏览器中浏览`http://localhost:8080`或在命令行中执行`curl` `http://localhost:8080`时，它将呈现 Hello World！执行以下步骤：

1.  创建`http-server.go`并复制以下内容：

```go
package main
import 
(
  "fmt"
  "log"
  "net/http"
)
const 
(
  CONN_HOST = "localhost"
  CONN_PORT = "8080"
)
func helloWorld(w http.ResponseWriter, r *http.Request) 
{
  fmt.Fprintf(w, "Hello World!")
}
func main() 
{
  http.HandleFunc("/", helloWorld)
  err := http.ListenAndServe(CONN_HOST+":"+CONN_PORT, nil)
  if err != nil 
  {
    log.Fatal("error starting http server : ", err)
    return
  }
}
```

1.  使用以下命令运行程序：

```go
$ go run http-server.go
```

# 它是如何工作的…

一旦我们运行程序，一个 HTTP 服务器将在本地监听端口`8080`。在浏览器中打开`http://localhost:8080`将显示来自服务器的 Hello World！，如下面的屏幕截图所示：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/go-webdev-cb/img/2cff40e1-a56f-4dbf-bbbd-a61b57ab4600.png)

你好，世界！

让我们理解程序中每一行的含义：

+   `package main`: 这定义了程序的包名称。

+   `import ( "fmt" "log" "net/http" )`: 这是一个预处理命令，告诉 Go 编译器包括`fmt`、`log`和`net/http`包中的所有文件。

+   `const ( CONN_HOST = "localhost" CONN_PORT = "8080" )`: 我们使用`const`关键字在 Go 程序中声明常量。这里我们声明了两个常量-一个是`CONN_HOST`，值为 localhost，另一个是`CONN_PORT`，值为`8080`。

+   `func helloWorld(w http.ResponseWriter, r *http.Request) { fmt.Fprintf(w, "Hello World!") }`: 这是一个 Go 函数，它以`ResponseWriter`和`Request`作为输入，并在 HTTP 响应流上写入`Hello World!`。

接下来，我们声明了`main()`方法，程序执行从这里开始，因为这个方法做了很多事情。让我们逐行理解它：

+   `http.HandleFunc("/", helloWorld)`: 在这里，我们使用`net/http`包的`HandleFunc`注册了`helloWorld`函数与`/`URL 模式，这意味着每当我们访问具有模式`/`的 HTTP URL 时，`helloWorld`会被执行，并将`(http.ResponseWriter`, `*http.Request)`作为参数传递给它。

+   `err := http.ListenAndServe(CONN_HOST+":"+CONN_PORT, nil)`: 在这里，我们调用`http.ListenAndServe`来处理每个传入连接的 HTTP 请求，每个连接在一个单独的 Goroutine 中处理。`ListenAndServe`接受两个参数-服务器地址和处理程序。在这里，我们将服务器地址传递为`localhost:8080`，处理程序为`nil`，这意味着我们要求服务器使用`DefaultServeMux`作为处理程序。

+   `if err != nil { log.Fatal("error starting http server : ", err) return}`：在这里，我们检查是否有问题启动服务器。如果有问题，那么记录错误并以状态码`1`退出。

# 在简单的 HTTP 服务器上实现基本身份验证

一旦创建了 HTTP 服务器，您可能希望限制特定用户访问资源，例如应用程序的管理员。如果是这样，那么您可以在 HTTP 服务器上实现基本身份验证，我们将在这个配方中介绍。

# 准备工作

由于我们已经在上一个配方中创建了一个 HTTP 服务器，我们只需扩展它以包含基本身份验证。

# 如何做…

在这个配方中，我们将通过添加`BasicAuth`函数并修改`HandleFunc`来调用它来更新我们在上一个配方中创建的 HTTP 服务器。执行以下步骤：

1.  创建`http-server-basic-authentication.go`并复制以下内容：

```go
package main
import 
(
  "crypto/subtle"
  "fmt"
  "log"
  "net/http"
)
const 
(
  CONN_HOST = "localhost"
  CONN_PORT = "8080"
  ADMIN_USER = "admin"
  ADMIN_PASSWORD = "admin"
)
func helloWorld(w http.ResponseWriter, r *http.Request) 
{
  fmt.Fprintf(w, "Hello World!")
}
func BasicAuth(handler http.HandlerFunc, realm string) http.HandlerFunc {
  return func(w http.ResponseWriter, r *http.Request) 
  {
    user, pass, ok := r.BasicAuth()
    if !ok || subtle.ConstantTimeCompare([]byte(user),
    []byte(ADMIN_USER)) != 1||subtle.ConstantTimeCompare([]byte(pass), 
    []byte(ADMIN_PASSWORD)) != 1 
    {
      w.Header().Set("WWW-Authenticate", `Basic realm="`+realm+`"`)
      w.WriteHeader(401)
      w.Write([]byte("You are Unauthorized to access the
      application.\n"))
      return
    }
    handler(w, r)
  }
}
func main() 
{
  http.HandleFunc("/", BasicAuth(helloWorld, "Please enter your
  username and password"))
  err := http.ListenAndServe(CONN_HOST+":"+CONN_PORT, nil)
  if err != nil 
  {
    log.Fatal("error starting http server : ", err)
    return
  }
}
```

1.  使用以下命令运行程序：

```go
$ go run http-server-basic-authentication.go
```

# 它是如何工作的…

一旦我们运行程序，HTTP 服务器将在本地监听端口`8080`上启动。

一旦服务器启动，在浏览器中访问`http://localhost:8080`将提示您输入用户名和密码。提供`admin`，`admin`将在屏幕上呈现 Hello World！对于其他用户名和密码的组合，它将呈现您未经授权访问应用程序。

要从命令行访问服务器，我们必须在`curl`命令中提供`--user`标志，如下所示：

```go
$ curl --user admin:admin http://localhost:8080/
Hello World!
```

我们还可以使用`base64`编码的`username:password`令牌访问服务器，我们可以从任何网站（例如`https://www.base64encode.org/`）获取，并将其作为`curl`命令中的授权标头传递，如下所示：

```go
$ curl -i -H 'Authorization:Basic YWRtaW46YWRtaW4=' http://localhost:8080/

HTTP/1.1 200 OK
Date: Sat, 12 Aug 2017 12:02:51 GMT
Content-Length: 12
Content-Type: text/plain; charset=utf-8
Hello World!
```

让我们了解我们引入的更改作为这个配方的一部分：

+   `import`函数添加了一个额外的包，`crypto/subtle`，我们将使用它来比较用户输入凭据中的用户名和密码。

+   使用`const`函数，我们定义了两个额外的常量，`ADMIN_USER`和`ADMIN_PASSWORD`，我们将在验证用户时使用它们。

+   接下来，我们声明了一个`BasicAuth()`方法，它接受两个输入参数——一个处理程序，在用户成功验证后执行，和一个领域，返回`HandlerFunc`，如下所示：

```go
func BasicAuth(handler http.HandlerFunc, realm string) http.HandlerFunc 
{
  return func(w http.ResponseWriter, r *http.Request)
  {
    user, pass, ok := r.BasicAuth()
    if !ok || subtle.ConstantTimeCompare([]byte(user),
    []byte(ADMIN_USER)) != 1||subtle.ConstantTimeCompare
    ([]byte(pass),
    []byte(ADMIN_PASSWORD)) != 1
    {
      w.Header().Set("WWW-Authenticate", `Basic realm="`+realm+`"`)
      w.WriteHeader(401)
      w.Write([]byte("Unauthorized.\n"))
      return
    }
    handler(w, r)
  }
}
```

在前面的处理程序中，我们首先使用`r.BasicAuth()`获取请求的授权标头中提供的用户名和密码，然后将其与程序中声明的常量进行比较。如果凭据匹配，则返回处理程序，否则设置`WWW-Authenticate`以及状态码`401`，并在 HTTP 响应流上写入`You are Unauthorized to access the application`。

最后，我们在`main()`方法中引入了一个更改，以从`HandleFunc`中调用`BasicAuth`，如下所示：

```go
http.HandleFunc("/", BasicAuth(helloWorld, "Please enter your username and password"))
```

我们只需传递一个`BasicAuth`处理程序，而不是`nil`或`DefaultServeMux`来处理所有带有 URL 模式为`/`的传入请求。

# 使用 GZIP 压缩优化 HTTP 服务器响应

GZIP 压缩意味着从服务器以`.gzip`格式向客户端发送响应，而不是发送纯文本响应，如果客户端/浏览器支持的话，发送压缩响应总是一个好习惯。

通过发送压缩响应，我们节省了网络带宽和下载时间，最终使页面加载更快。 GZIP 压缩的原理是浏览器发送一个请求标头，告诉服务器它接受压缩内容（`.gzip`和`.deflate`），如果服务器有能力以压缩形式发送响应，则发送压缩形式的响应。如果服务器支持压缩，则它将设置`Content-Encoding: gzip`作为响应标头，否则它将向客户端发送一个纯文本响应，这清楚地表示要求压缩响应只是浏览器的请求，而不是要求。我们将使用 Gorilla 的 handlers 包在这个配方中实现它。

# 如何做…

在本教程中，我们将创建一个带有单个处理程序的 HTTP 服务器，该处理程序将在 HTTP 响应流上写入 Hello World！并使用 Gorilla `CompressHandler`以`.gzip`格式将所有响应发送回客户端。执行以下步骤：

1.  使用大猩猩处理程序，首先我们需要使用`go get`命令安装包，或者手动将其复制到`$GOPATH/src`或`$GOPATH`，如下所示：

```go
$ go get github.com/gorilla/handlers
```

1.  创建`http-server-mux.go`并复制以下内容：

```go
package main
import 
(
  "io"
  "net/http"
  "github.com/gorilla/handlers"
)
const 
(
  CONN_HOST = "localhost"
  CONN_PORT = "8080"
)
func helloWorld(w http.ResponseWriter, r *http.Request) 
{
  io.WriteString(w, "Hello World!")
}
func main() 
{
  mux := http.NewServeMux()
  mux.HandleFunc("/", helloWorld)
  err := http.ListenAndServe(CONN_HOST+":"+CONN_PORT,
  handlers.CompressHandler(mux))
  if err != nil 
  {
    log.Fatal("error starting http server : ", err)
    return
  }
}
```

1.  使用以下命令运行程序：

```go
$ go run http-server-mux.go
```

# 工作原理…

运行程序后，HTTP 服务器将在本地监听端口`8080`。

在浏览器中打开`http://localhost:8080`将显示来自服务器的 Hello World！并显示 Content-Encoding 响应头值 gzip，如下面的屏幕截图所示：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/go-webdev-cb/img/7dc5f016-1d66-4503-bdeb-752523842b72.png)

你好，世界！

让我们了解程序中每一行的含义：

+   `package main`：这定义了程序的包名称。

+   `import ( "io" "net/http" "github.com/gorilla/handlers" )`: 这是一个预处理命令，告诉 Go 编译器包括来自`io`、`net/http`和`github.com/gorilla/handlers`包的所有文件。

+   `const ( CONN_HOST = "localhost" CONN_PORT = "8080" )`: 我们使用 const 关键字在 Go 程序中声明常量。在这里，我们声明了两个常量，一个是值为 localhost 的`CONN_HOST`，另一个是值为 8080 的`CONN_PORT`。

+   `func helloWorld(w http.ResponseWriter, r *http.Request) { io.WriteString(w, "Hello World!")}`: 这是一个接受`ResponseWriter`和`Request`作为输入参数并在 HTTP 响应流上写入`Hello World!`的 Go 函数。

接下来，我们声明了`main()`方法，程序的执行从这里开始。由于这个方法做了很多事情，让我们逐行理解它：

+   `mux := http.NewServeMux()`: 这将分配并返回一个新的 HTTP 请求多路复用器（`ServeMux`），它将匹配每个传入请求的 URL 与已注册模式列表，并调用最接近 URL 的模式的处理程序。使用它的好处之一是程序完全控制与服务器一起使用的处理程序，尽管任何使用`DefaultServeMux`注册的处理程序都将被忽略。

+   `http.HandleFunc("/", helloWorld)`: 在这里，我们使用`net/http`包的`HandleFunc`将`helloWorld`函数注册到`/`URL 模式，这意味着每当我们访问具有`/`模式的 HTTP URL 时，`helloWorld`将被执行，并将`(http.ResponseWriter`, `*http.Request)`作为参数传递给它。

+   `err := http.ListenAndServe(CONN_HOST+":"+CONN_PORT, handlers.CompressHandler(mux))`: 在这里，我们调用`http.ListenAndServe`来为我们处理每个传入连接的 HTTP 请求。`ListenAndServe`接受两个参数——服务器地址和处理程序。在这里，我们将服务器地址传递为`localhost:8080`，处理程序为`CompressHandler`，它用`.gzip`处理程序包装我们的服务器以将所有响应压缩为`.gzip`格式。

+   `if err != nil { log.Fatal("error starting http server: ", err) return}`: 在这里，我们检查是否有任何启动服务器的问题。如果有问题，记录错误并以状态码 1 退出。

# 创建一个简单的 TCP 服务器

每当你需要构建高性能导向系统时，编写 TCP 服务器总是优于 HTTP 服务器的最佳选择，因为 TCP 套接字比 HTTP 更轻。Go 支持并提供了一种方便的方法来编写使用`net`包的 TCP 服务器，我们将在本教程中介绍。

# 如何做…

在本教程中，我们将创建一个简单的 TCP 服务器，它将在`localhost:8080`上接受连接。执行以下步骤：

1.  创建`tcp-server.go`并复制以下内容：

```go
package main
import 
(
  "log"
  "net"
)
const 
(
  CONN_HOST = "localhost"
  CONN_PORT = "8080"
  CONN_TYPE = "tcp"
)
func main() 
{
  listener, err := net.Listen(CONN_TYPE, CONN_HOST+":"+CONN_PORT)
  if err != nil 
  {
    log.Fatal("Error starting tcp server : ", err)
  }
  defer listener.Close()
  log.Println("Listening on " + CONN_HOST + ":" + CONN_PORT)
  for 
  {
    conn, err := listener.Accept()
    if err != nil 
    {
      log.Fatal("Error accepting: ", err.Error())
    }
    log.Println(conn)
  }
}
```

1.  使用以下命令运行程序：

```go
$ go run tcp-server.go
```

# 工作原理…

运行程序后，TCP 服务器将在本地监听端口`8080`。

让我们理解程序中每一行的含义：

+   `package main`: 这定义了程序的包名称。

+   `import ( "log" "net")`: 这是一个预处理命令，告诉 Go 编译器包括`log`和`net`包中的所有文件。

+   `const ( CONN_HOST = "localhost" CONN_PORT = "8080" CONN_TYPE = "tcp" )`: 我们使用 const 关键字在 Go 程序中声明常量。在这里，我们声明了三个常量——一个是`CONN_HOST`，值为`localhost`，另一个是`CONN_PORT`，值为`8080`，最后一个是`CONN_TYPE`，值为`tcp`。

接下来，我们从`main()`方法中声明了`main()`方法，程序执行从这里开始。由于这个方法做了很多事情，让我们逐行理解它：

+   `listener, err := net.Listen(CONN_TYPE, CONN_HOST+":"+CONN_PORT)`: 这将在本地端口`8080`上创建一个 TCP 服务器。

+   `if err != nil { log.Fatal("Error starting tcp server: ", err) }`: 在这里，我们检查是否有问题启动 TCP 服务器。如果有问题，就记录错误并以状态码 1 退出。

+   `defer listener.Close()`: 这个延迟语句在应用程序关闭时关闭 TCP 套接字监听器。

接下来，我们在一个常量循环中接受 TCP 服务器的传入请求，如果在接受请求时出现任何错误，我们将记录并退出；否则，我们只是在服务器控制台上打印连接对象，如下所示：

```go
for 
{
  conn, err := listener.Accept()
  if err != nil 
  {
    log.Fatal("Error accepting: ", err.Error())
  }
  log.Println(conn)
}
```

# 从 TCP 连接读取数据

在任何应用程序中最常见的情况之一是客户端与服务器进行交互。TCP 是这种交互中最广泛使用的协议之一。Go 提供了一种方便的方式通过实现缓冲的`Input/Output`来读取传入连接数据，我们将在这个示例中介绍。

# 准备就绪…

由于我们已经在之前的示例中创建了一个 TCP 服务器，我们将更新它以从传入连接中读取数据。

# 如何做…

在这个示例中，我们将更新`main()`方法，调用`handleRequest`方法并传递连接对象以读取和打印服务器控制台上的数据。执行以下步骤：

1.  创建`tcp-server-read-data.go`并复制以下内容：

```go
package main
import 
(
  "bufio"
  "fmt"
  "log"
  "net"
)
const 
(
  CONN_HOST = "localhost"
  CONN_PORT = "8080"
  CONN_TYPE = "tcp"
)
func main() 
{
  listener, err := net.Listen(CONN_TYPE, CONN_HOST+":"+CONN_PORT)
  if err != nil 
  {
    log.Fatal("Error starting tcp server : ", err)
  }
  defer listener.Close()
  log.Println("Listening on " + CONN_HOST + ":" + CONN_PORT)
  for 
  {
    conn, err := listener.Accept()
    if err != nil 
    {
      log.Fatal("Error accepting: ", err.Error())
    }
    go handleRequest(conn)
  }
}
func handleRequest(conn net.Conn) 
{
  message, err := bufio.NewReader(conn).ReadString('\n')
  if err != nil 
  {
    fmt.Println("Error reading:", err.Error())
  }
  fmt.Print("Message Received from the client: ", string(message))
  conn.Close()
}
```

1.  使用以下命令运行程序：

```go
$ go run tcp-server-read-data.go
```

# 工作原理…

一旦我们运行程序，TCP 服务器将在本地端口`8080`上开始监听。从命令行执行`echo`命令将向 TCP 服务器发送消息：

```go
$ echo -n "Hello to TCP server\n" | nc localhost 8080
```

这显然会将其记录到服务器控制台，如下面的屏幕截图所示：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/go-webdev-cb/img/e852ce37-88a6-4c6a-97c9-e00988ec7752.png)

让我们理解这个示例中引入的变化：

1.  首先，我们使用`go`关键字从`main()`方法中调用`handleRequest`，这意味着我们在 Goroutine 中调用函数，如下所示：

```go
func main() 
{
  ...
  go handleRequest(conn)
  ...
}
```

1.  接下来，我们定义了`handleRequest`函数，它将传入的连接读入缓冲区，直到第一个`\n`出现，并在控制台上打印消息。如果在读取消息时出现任何错误，则打印错误消息以及错误对象，最后关闭连接，如下所示：

```go
func handleRequest(conn net.Conn) 
{
  message, err := bufio.NewReader(conn).ReadString('\n')
  if err != nil 
  {
    fmt.Println("Error reading:", err.Error())
  }
  fmt.Print("Message Received: ", string(message))
  conn.Close()
}
```

# 向 TCP 连接写入数据

在任何 Web 应用程序中，另一个常见且重要的情况是向客户端发送数据或响应客户端。Go 提供了一种方便的方式，以字节的形式在连接上写入消息，我们将在这个示例中介绍。

# 准备就绪…

由于我们已经在之前的示例中创建了一个 TCP 服务器，用于读取传入连接的数据，所以我们只需更新它以将消息写回客户端。

# 如何做…

在这个示例中，我们将更新程序中的`handleRequest`方法，以便向客户端写入数据。执行以下步骤：

1.  创建`tcp-server-write-data.go`并复制以下内容：

```go
package main
import 
(
  "bufio"
  "fmt"
  "log"
  "net"
)
const 
(
  CONN_HOST = "localhost"
  CONN_PORT = "8080"
  CONN_TYPE = "tcp"
)
func main() 
{
  listener, err := net.Listen(CONN_TYPE, CONN_HOST+":"+CONN_PORT)
  if err != nil 
  {
    log.Fatal("Error starting tcp server : ", err)
  }
  defer listener.Close()
  log.Println("Listening on " + CONN_HOST + ":" + CONN_PORT)
  for 
  {
    conn, err := listener.Accept()
    if err != nil 
    {
      log.Fatal("Error accepting: ", err.Error())
    }
    go handleRequest(conn)
  }
}
func handleRequest(conn net.Conn) 
{
  message, err := bufio.NewReader(conn).ReadString('\n')
  if err != nil 
  {
    fmt.Println("Error reading: ", err.Error())
  }
  fmt.Print("Message Received:", string(message))
  conn.Write([]byte(message + "\n"))
  conn.Close()
}
```

1.  使用以下命令运行程序：

```go
$ go run tcp-server-write-data.go
```

# 工作原理…

一旦我们运行程序，TCP 服务器将在本地端口`8080`上开始监听。从命令行执行`echo`命令，如下所示：

```go
$ echo -n "Hello to TCP server\n" | nc localhost 8080
```

这将为我们提供来自服务器的以下响应：

```go
Hello to TCP server
```

让我们看看我们在这个示例中引入的更改，以便向客户端写入数据。`handleRequest`中的一切都与上一个示例中完全相同，只是我们引入了一行新的代码，将数据作为字节数组写入连接，如下所示：

```go
func handleRequest(conn net.Conn) 
{
  ...
  conn.Write([]byte(message + "\n"))
  ...
}
```

# 实现 HTTP 请求路由

大多数情况下，您必须在 Web 应用程序中定义多个 URL 路由，这涉及将 URL 路径映射到处理程序或资源。在这个示例中，我们将学习如何在 Go 中实现它。

# 如何做…

在这个示例中，我们将定义三个路由，如`/`、`/login`和`/logout`，以及它们的处理程序。执行以下步骤：

1.  创建`http-server-basic-routing.go`并复制以下内容：

```go
package main
import 
(
  "fmt"
  "log"
  "net/http"
)
const 
(
  CONN_HOST = "localhost"
  CONN_PORT = "8080"
)
func helloWorld(w http.ResponseWriter, r *http.Request) 
{
  fmt.Fprintf(w, "Hello World!")
}
func login(w http.ResponseWriter, r *http.Request) 
{
  fmt.Fprintf(w, "Login Page!")
}
func logout(w http.ResponseWriter, r *http.Request) 
{
  fmt.Fprintf(w, "Logout Page!")
}
func main() 
{
  http.HandleFunc("/", helloWorld)
  http.HandleFunc("/login", login)
  http.HandleFunc("/logout", logout)
  err := http.ListenAndServe(CONN_HOST+":"+CONN_PORT, nil)
  if err != nil 
  {
    log.Fatal("error starting http server : ", err)
    return
  }
}
```

1.  使用以下命令运行程序：

```go
$ go run http-server-basic-routing.go
```

# 它是如何工作的…

一旦我们运行程序，HTTP 服务器将在本地监听端口`8080`，并且从浏览器或命令行访问`http://localhost:8080/`、`http://localhost:8080/login`和`http://localhost:8080/logout`将呈现相应处理程序定义中的消息。例如，从命令行执行`http://localhost:8080/`，如下所示：

```go
$ curl -X GET -i http://localhost:8080/
```

这将为我们提供来自服务器的以下响应：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/go-webdev-cb/img/37497746-7f2d-4fe2-89ce-b9fcba58982c.png)

我们也可以从命令行执行`http://localhost:8080/login`，如下所示：

```go
$ curl -X GET -i http://localhost:8080/login
```

这将为我们提供来自服务器的以下响应：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/go-webdev-cb/img/3278b2fb-4f05-4654-9b24-3df2751d2d03.png)

让我们了解我们编写的程序：

1.  我们首先定义了三个处理程序或 Web 资源，如下所示：

```go
func helloWorld(w http.ResponseWriter, r *http.Request) 
{
  fmt.Fprintf(w, "Hello World!")
}
func login(w http.ResponseWriter, r *http.Request) 
{
  fmt.Fprintf(w, "Login Page!")
}
func logout(w http.ResponseWriter, r *http.Request) 
{
  fmt.Fprintf(w, "Logout Page!")
}
```

在这里，`helloWorld`处理程序在 HTTP 响应流上写入`Hello World!`。类似地，登录和注销处理程序在 HTTP 响应流上写入`Login Page!`和`Logout Page!`。

1.  接下来，我们使用`http.HandleFunc()`在`DefaultServeMux`上注册了三个 URL 路径——`/`、`/login`和`/logout`。如果传入的请求 URL 模式与注册的路径之一匹配，那么相应的处理程序将被调用，并将`(http.ResponseWriter`、`*http.Request)`作为参数传递给它，如下所示：

```go
func main() 
{
  http.HandleFunc("/", helloWorld)
  http.HandleFunc("/login", login)
  http.HandleFunc("/logout", logout)
  err := http.ListenAndServe(CONN_HOST+":"+CONN_PORT, nil)
  if err != nil 
  {
    log.Fatal("error starting http server : ", err)
    return
  }
}
```

# 使用 Gorilla Mux 实现 HTTP 请求路由

Go 的`net/http`包为 HTTP 请求的 URL 路由提供了许多功能。它做得不太好的一件事是动态 URL 路由。幸运的是，我们可以通过`gorilla/mux`包实现这一点，我们将在这个示例中介绍。

# 如何做…

在这个示例中，我们将使用`gorilla/mux`来定义一些路由，就像我们在之前的示例中所做的那样，以及它们的处理程序或资源。正如我们在之前的示例中已经看到的，要使用外部包，首先我们必须使用`go get`命令安装包，或者我们必须手动将其复制到`$GOPATH/src`或`$GOPATH`。我们在这个示例中也会这样做。执行以下步骤：

1.  使用`go get`命令安装`github.com/gorilla/mux`，如下所示：

```go
$ go get github.com/gorilla/mux
```

1.  创建`http-server-gorilla-mux-routing.go`并复制以下内容：

```go
package main
import 
(
  "net/http"
  "github.com/gorilla/mux"
)
const 
(
  CONN_HOST = "localhost"
  CONN_PORT = "8080"
)
var GetRequestHandler = http.HandlerFunc
(
  func(w http.ResponseWriter, r *http.Request) 
  {
    w.Write([]byte("Hello World!"))
  }
)
var PostRequestHandler = http.HandlerFunc
(
  func(w http.ResponseWriter, r *http.Request) 
  {
    w.Write([]byte("It's a Post Request!"))
  }
)
var PathVariableHandler = http.HandlerFunc
(
  func(w http.ResponseWriter, r *http.Request) 
  {
    vars := mux.Vars(r)
    name := vars["name"]
    w.Write([]byte("Hi " + name))
  }
)
func main() 
{
  router := mux.NewRouter()
  router.Handle("/", GetRequestHandler).Methods("GET")
  router.Handle("/post", PostRequestHandler).Methods("POST")
  router.Handle("/hello/{name}", 
  PathVariableHandler).Methods("GET", "PUT")
  http.ListenAndServe(CONN_HOST+":"+CONN_PORT, router)
}
```

1.  使用以下命令运行程序：

```go
$ go run http-server-gorilla-mux-routing.go
```

# 它是如何工作…

一旦我们运行程序，HTTP 服务器将在本地监听端口`8080`，并且从浏览器或命令行访问`http://localhost:8080/`、`http://localhost:8080/post`和`http://localhost:8080/hello/foo`将产生相应处理程序定义中的消息。例如，从命令行执行`http://localhost:8080/`，如下所示：

```go
$ curl -X GET -i http://localhost:8080/
```

这将为我们提供来自服务器的以下响应：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/go-webdev-cb/img/5dbedcdd-3be8-4718-af12-a6d8afb02094.png)

我们也可以从命令行执行`http://localhost:8080/hello/foo`，如下所示：

```go
$ curl -X GET -i http://localhost:8080/hello/foo
```

这将为我们提供来自服务器的以下响应：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/go-webdev-cb/img/783a091d-58e2-406d-b4ac-18bb23bc2aed.png)

让我们了解我们在这个示例中所做的代码更改：

1.  首先，我们定义了`GetRequestHandler`和`PostRequestHandler`，它们只是在 HTTP 响应流上写入一条消息，如下所示：

```go
var GetRequestHandler = http.HandlerFunc
(
  func(w http.ResponseWriter, r *http.Request) 
  {
    w.Write([]byte("Hello World!"))
  }
)
var PostRequestHandler = http.HandlerFunc
(
  func(w http.ResponseWriter, r *http.Request) 
  {
    w.Write([]byte("It's a Post Request!"))
  }
)
```

1.  接下来，我们定义了`PathVariableHandler`，它提取请求路径变量，获取值，并将其写入 HTTP 响应流，如下所示：

```go
var PathVariableHandler = http.HandlerFunc
(
  func(w http.ResponseWriter, r *http.Request) 
  {
    vars := mux.Vars(r)
    name := vars["name"]
    w.Write([]byte("Hi " + name))
  }
)
```

1.  然后，我们将所有这些处理程序注册到`gorilla/mux`路由器中，并对其进行实例化，调用 mux 路由器的`NewRouter()`处理程序，如下所示：

```go
func main() 
{
  router := mux.NewRouter()
  router.Handle("/", GetRequestHandler).Methods("GET")
  router.Handle("/post", PostCallHandler).Methods("POST")
  router.Handle("/hello/{name}", PathVariableHandler).
  Methods("GET", "PUT")
  http.ListenAndServe(CONN_HOST+":"+CONN_PORT, router)
}
```

# 记录 HTTP 请求

在故障排除 Web 应用程序时，记录 HTTP 请求总是很有用，因此记录具有适当消息和记录级别的请求/响应是一个好主意。Go 提供了`log`包，可以帮助我们在应用程序中实现日志记录。然而，在这个示例中，我们将使用 Gorilla 日志处理程序来实现它，因为该库提供了更多功能，比如记录 Apache Combined 日志格式和 Apache Common 日志格式，这些功能目前还不受 Go `log`包支持。

# 准备就绪...

由于我们已经在之前的示例中创建了一个 HTTP 服务器并使用 Gorilla Mux 定义了路由，我们将更新它以整合 Gorilla 日志处理程序。

# 如何做...

让我们使用 Gorilla 处理程序实现日志记录。执行以下步骤：

1.  使用`go get`命令安装`github.com/gorilla/handler`和`github.com/gorilla/mux`包，如下所示：

```go
$ go get github.com/gorilla/handlers
$ go get github.com/gorilla/mux
```

1.  创建`http-server-request-logging.go`并复制以下内容：

```go
package main
import 
(
  "net/http"
  "os"
  "github.com/gorilla/handlers"
  "github.com/gorilla/mux"
)
const 
(
  CONN_HOST = "localhost"
  CONN_PORT = "8080"
)
var GetRequestHandler = http.HandlerFunc
(
  func(w http.ResponseWriter, r *http.Request) 
  {
    w.Write([]byte("Hello World!"))
  }
)
var PostRequestHandler = http.HandlerFunc
(
  func(w http.ResponseWriter, r *http.Request) 
  {
    w.Write([]byte("It's a Post Request!"))
  }
)
var PathVariableHandler = http.HandlerFunc
(
  func(w http.ResponseWriter, r *http.Request) 
  {
    vars := mux.Vars(r)
    name := vars["name"]
    w.Write([]byte("Hi " + name))
  }
)
func main() 
{
  router := mux.NewRouter()
  router.Handle("/", handlers.LoggingHandler(os.Stdout,
  http.HandlerFunc(GetRequestHandler))).Methods("GET")
  logFile, err := os.OpenFile("server.log",
  os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0666)
  if err != nil 
  {
    log.Fatal("error starting http server : ", err)
    return
  }
  router.Handle("/post", handlers.LoggingHandler(logFile,
  PostRequestHandler)).Methods("POST")
  router.Handle("/hello/{name}",
  handlers.CombinedLoggingHandler(logFile,
  PathVariableHandler)).Methods("GET")
  http.ListenAndServe(CONN_HOST+":"+CONN_PORT, router)
}
```

1.  运行程序，使用以下命令：

```go
$ go run http-server-request-logging.go
```

# 它是如何工作的...

一旦我们运行程序，HTTP 服务器将在本地监听端口`8080`。

从命令行执行`GET`请求，如下所示：

```go
$ curl -X GET -i http://localhost:8080/
```

这将在 Apache Common 日志格式中记录请求的详细信息，如下面的屏幕截图所示：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/go-webdev-cb/img/d0cddd33-c7b7-4425-b8b9-54c3b29abae8.png)

我们也可以从命令行执行`http://localhost:8080/hello/foo`，如下所示：

```go
$ curl -X GET -i http://localhost:8080/hello/foo
```

这将在`server.log`中以 Apache Combined 日志格式记录请求的详细信息，如下面的屏幕截图所示：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/go-webdev-cb/img/3221304b-510c-4324-98ba-8cda9f8ac737.png)

让我们了解一下在这个示例中我们做了什么：

1.  首先，我们导入了两个额外的包，一个是`os`，我们用它来打开一个文件。另一个是`github.com/gorilla/handlers`，我们用它来导入用于记录 HTTP 请求的日志处理程序，如下所示：

```go
import ( "net/http" "os" "github.com/gorilla/handlers" "github.com/gorilla/mux" )
```

1.  接下来，我们修改了`main()`方法。使用`router.Handle("/", handlers.LoggingHandler(os.Stdout,`

`http.HandlerFunc(GetRequestHandler))).Methods("GET")`，我们用 Gorilla 日志处理程序包装了`GetRequestHandler`，并将标准输出流作为写入器传递给它，这意味着我们只是要求在控制台上以 Apache Common 日志格式记录每个 URL 路径为`/`的请求。

1.  接下来，我们以只写模式创建一个名为`server.log`的新文件，或者如果它已经存在，则打开它。如果有任何错误，那么记录下来并以状态码 1 退出，如下所示：

```go
logFile, err := os.OpenFile("server.log", os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0666)
if err != nil 
{
  log.Fatal("error starting http server : ", err)
  return
}
```

1.  使用`router.Handle("/post", handlers.LoggingHandler(logFile, PostRequestHandler)).Methods("POST")`，我们用 Gorilla 日志处理程序包装了`GetRequestHandler`，并将文件作为写入器传递给它，这意味着我们只是要求在名为`/hello/{name}`的文件中以 Apache Common 日志格式记录每个 URL 路径为`/post`的请求。

1.  使用`router.Handle("/hello/{name}", handlers.CombinedLoggingHandler(logFile, PathVariableHandler)).Methods("GET")`，我们用 Gorilla 日志处理程序包装了`GetRequestHandler`，并将文件作为写入器传递给它，这意味着我们只是要求在名为`server.log`的文件中以 Apache Combined 日志格式记录每个 URL 路径为`/hello/{name}`的请求。


# 第二章：使用模板、静态文件和 HTML 表单

在本章中，我们将涵盖以下内容：

+   创建您的第一个模板

+   通过 HTTP 提供静态文件

+   使用 Gorilla Mux 通过 HTTP 提供静态文件

+   创建您的第一个 HTML 表单

+   阅读您的第一个 HTML 表单

+   验证您的第一个 HTML 表单

+   上传您的第一个文件

# 介绍

我们经常希望创建 HTML 表单，以便以指定的格式从客户端获取信息，将文件或文件夹上传到服务器，并生成通用的 HTML 模板，而不是重复相同的静态文本。有了本章涵盖的概念知识，我们将能够在 Go 中高效地实现所有这些功能。

在本章中，我们将从创建基本模板开始，然后继续从文件系统中提供静态文件，如`.js`、`.css`和`images`，最终创建、读取和验证 HTML 表单，并将文件上传到服务器。

# 创建您的第一个模板

模板允许我们定义动态内容的占位符，可以由模板引擎在运行时替换为值。然后可以将它们转换为 HTML 文件并发送到客户端。在 Go 中创建模板非常容易，使用 Go 的`html/template`包，我们将在本示例中介绍。

# 如何做…

在这个示例中，我们将创建一个`first-template.html`，其中包含一些占位符，其值将在运行时由模板引擎注入。执行以下步骤：

1.  通过执行以下 Unix 命令在`templates`目录中创建`first-template.html`：

```go
$ mkdir templates && cd templates && touch first-template.html
```

1.  将以下内容复制到`first-template.html`中：

```go
<html>
  <head>
    <meta charset="utf-8">
    <title>First Template</title>
    <link rel="stylesheet" href="/static/stylesheets/main.css">
  </head>
  <body>
    <h1>Hello {{.Name}}!</h1>
    Your Id is {{.Id}}
  </body>
</html>
```

上述模板有两个占位符，`{{.Name}}`和`{{.Id}}`，它们的值将由模板引擎在运行时替换或注入。

1.  创建`first-template.go`，在其中我们将为占位符填充值，生成 HTML 输出，并将其写入客户端，如下所示：

```go
import 
(
  "fmt"
  "html/template"
  "log"
  "net/http"
)
const 
(
  CONN_HOST = "localhost"
  CONN_PORT = "8080"
)
type Person struct 
{
  Id   string
  Name string
}
func renderTemplate(w http.ResponseWriter, r *http.Request) 
{
  person := Person{Id: "1", Name: "Foo"}
  parsedTemplate, _ := template.ParseFiles("templates/
  first-template.html")
  err := parsedTemplate.Execute(w, person)
  if err != nil 
  {
    log.Printf("Error occurred while executing the template
    or writing its output : ", err)
    return
  }
}
func main() 
{
  http.HandleFunc("/", renderTemplate)
  err := http.ListenAndServe(CONN_HOST+":"+CONN_PORT, nil)
  if err != nil 
  {
    log.Fatal("error starting http server : ", err)
    return
  }
}
```

一切就绪后，目录结构应如下所示：

！[](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/go-webdev-cb/img/ab60eb27-0295-4b8a-9c7b-9d85f6c65b55.png)

1.  使用以下命令运行程序：

```go
$ go run first-template.go
```

# 它是如何工作的…

一旦我们运行程序，HTTP 服务器将在本地监听端口`8080`上启动。

浏览`http://localhost:8080`将显示模板引擎提供的 Hello Foo！，如下截图所示：

！[](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/go-webdev-cb/img/f54a702f-1181-404b-8c55-f0502b2365fb.png)

从命令行执行`curl -X GET http://localhost:8080`如下：

```go
$ curl -X GET http://localhost:8080
```

这将导致服务器返回以下响应：

！[](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/go-webdev-cb/img/5125ff70-60b0-4b27-a291-1fd30a424f85.png)

让我们了解我们编写的 Go 程序：

+   `type Person struct { Id string Name string }`: 在这里，我们定义了一个`person`结构类型，具有`Id`和`Name`字段。

类型定义中的字段名称应以大写字母开头；否则，将导致错误并且不会在模板中被替换。

接下来，我们定义了一个`renderTemplate()`处理程序，它执行了许多操作。

+   `person := Person{Id: "1", Name: "Foo"}`: 在这里，我们初始化了一个`person`结构类型，其中`Id`为`1`，`Name`为`Foo`。

+   `parsedTemplate, _ := template.ParseFiles("templates/first-template.html")`: 在这里，我们调用`html/template`包的`ParseFiles`，它创建一个新模板并解析我们传入的文件名，即`templates`目录中的`first-template.html`。生成的模板将具有输入文件的名称和内容。

+   `err := parsedTemplate.Execute(w, person)`: 在这里，我们在解析的模板上调用`Execute`处理程序，它将`person`数据注入模板，生成 HTML 输出，并将其写入 HTTP 响应流。

+   `if err != nil {log.Printf("Error occurred while executing the template or writing its output : ", err) return }`: 在这里，我们检查执行模板或将其输出写入响应流时是否出现任何问题。如果有问题，我们将记录错误并以状态码 1 退出。

# 通过 HTTP 提供静态文件

在设计 Web 应用程序时，最好的做法是从文件系统或任何**内容传递网络**（**CDN**）（如 Akamai 或 Amazon CloudFront）提供静态资源，例如`.js`、`.css`和`images`，而不是从 Web 服务器提供。这是因为所有这些类型的文件都是静态的，不需要处理；那么为什么我们要给服务器增加额外的负载呢？此外，它有助于提高应用程序的性能，因为所有对静态文件的请求都将从外部来源提供，并因此减少了对服务器的负载。

Go 的`net/http`包足以通过`FileServer`从文件系统中提供静态资源，我们将在本教程中介绍。

# 准备就绪…

由于我们已经在上一个教程中创建了一个模板，我们将扩展它以从`static/css`目录中提供静态`.css`文件。

# 如何做…

在本教程中，我们将创建一个文件服务器，它将从文件系统中提供静态资源。执行以下步骤：

1.  在`static/css`目录中创建`main.css`，如下所示：

```go
$ mkdir static && cd static && mkdir css && cd css && touch main.css
```

1.  将以下内容复制到`main.css`中：

```go
body {color: #00008B}
```

1.  创建`serve-static-files.go`，在那里我们将创建`FileServer`，它将为所有带有`/static`的 URL 模式从文件系统中的`static/css`目录提供资源，如下所示：

```go
package main
import 
(
  "fmt"
  "html/template"
  "log"
  "net/http"
)
const 
(
  CONN_HOST = "localhost"
  CONN_PORT = "8080"
)
type Person struct 
{
  Name string
  Age string
}
func renderTemplate(w http.ResponseWriter, r *http.Request) 
{
  person := Person{Id: "1", Name: "Foo"}
  parsedTemplate, _ := template.ParseFiles("templates/
  first-template.html")
  err := parsedTemplate.Execute(w, person)
  if err != nil 
  {
    log.Printf("Error occurred while executing the template 
    or writing its output : ", err)
    return
  }
}
func main() 
{
  fileServer := http.FileServer(http.Dir("static"))
  http.Handle("/static/", http.StripPrefix("/static/", fileServer))
  http.HandleFunc("/", renderTemplate)
  err := http.ListenAndServe(CONN_HOST+":"+CONN_PORT, nil)
  if err != nil 
  {
    log.Fatal("error starting http server : ", err)
    return
  }
}
```

1.  更新`first-template.html`（在我们的上一个教程中创建）以包含来自文件系统中的`static/css`目录的`main.css`：

```go
<html>
  <head>
    <meta charset="utf-8">
    <title>First Template</title>
    <link rel="stylesheet" href="/static/css/main.css">
  </head>
  <body>
    <h1>Hello {{.Name}}!</h1>
    Your Id is {{.Id}}
  </body>
</html>
```

一切就绪后，目录结构应如下所示：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/go-webdev-cb/img/94798377-1729-4559-9e5c-6c4ca2fa2f59.png)

1.  使用以下命令运行程序：

```go
$ go run serve-static-files.go
```

# 它是如何工作的…

一旦我们运行程序，HTTP 服务器将在本地监听端口`8080`。浏览`http://localhost:8080`将显示与上一个教程中相同的输出，但是这次文本颜色已从默认的**黑色**更改为**蓝色**，如下图所示：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/go-webdev-cb/img/07fd3f5a-f8c5-4976-98b3-5527c8372755.png)

如果我们查看 Chrome DevTools 的网络选项卡，我们可以看到`main.css`是从文件系统中的`static/css`目录加载的。

让我们了解我们在本教程的`main()`方法中引入的更改：

+   `fileServer := http.FileServer(http.Dir("static"))`：在这里，我们使用`net/http`包的`FileServer`处理程序创建了一个文件服务器，它从文件系统中的`static`目录提供 HTTP 请求。

+   `http.Handle("/static/", http.StripPrefix("/static/", fileServer))`：在这里，我们使用`net/http`包的`HandleFunc`将`http.StripPrefix("/static/", fileServer)`处理程序注册到`/static`URL 模式，这意味着每当我们访问带有`/static`模式的 HTTP URL 时，`http.StripPrefix("/static/", fileServer)`将被执行，并将`(http.ResponseWriter, *http.Request)`作为参数传递给它。

+   `http.StripPrefix("/static/", fileServer)`：这将返回一个处理程序，通过从请求 URL 的路径中删除`/static`来提供 HTTP 请求，并调用文件服务器。`StripPrefix`通过用 HTTP 404 回复处理不以前缀开头的路径的请求。

# 使用 Gorilla Mux 通过 HTTP 提供静态文件

在上一个教程中，我们通过 Go 的 HTTP 文件服务器提供了`static`资源。在本教程中，我们将看看如何通过 Gorilla Mux 路由器提供它，这也是创建 HTTP 路由器的最常见方式之一。

# 准备就绪…

由于我们已经在上一个教程中创建了一个模板，该模板从文件系统中的`static/css`目录中提供`main.css`，因此我们将更新它以使用 Gorilla Mux 路由器。

# 如何做…

1.  使用`go get`命令安装`github.com/gorilla/mux`包，如下所示：

```go
$ go get github.com/gorilla/mux
```

1.  创建`serve-static-files-gorilla-mux.go`，在那里我们将创建一个 Gorilla Mux 路由器，而不是 HTTP`FileServer`，如下所示：

```go
package main
import 
(
  "html/template"
  "log"
  "net/http"
  "github.com/gorilla/mux"
)
const 
(
  CONN_HOST = "localhost"
  CONN_PORT = "8080"
)
type Person struct 
{
  Id string
  Name string
}
func renderTemplate(w http.ResponseWriter, r *http.Request) 
{
  person := Person{Id: "1", Name: "Foo"}
  parsedTemplate, _ := template.ParseFiles("templates/
  first-template.html")
  err := parsedTemplate.Execute(w, person)
  if err != nil 
  {
    log.Printf("Error occurred while executing the template 
    or writing its output : ", err)
    return
  }
}
func main() 
{
  router := mux.NewRouter()
  router.HandleFunc("/", renderTemplate).Methods("GET")
  router.PathPrefix("/").Handler(http.StripPrefix("/static",
  http.FileServer(http.Dir("static/"))))
  err := http.ListenAndServe(CONN_HOST+":"+CONN_PORT, router)
  if err != nil 
  {
    log.Fatal("error starting http server : ", err)
    return
  }
}
```

1.  使用以下命令运行程序：

```go
$ go run serve-static-files-gorilla-mux.go
```

# 它是如何工作的…

一旦我们运行程序，HTTP 服务器将在本地监听端口`8080`上启动。

浏览`http://localhost:8080`将显示与我们上一个示例中看到的相同的输出，如下屏幕截图所示：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/go-webdev-cb/img/f2ba4915-2e5d-4d3e-a893-eab0364df5d8.png)

让我们了解我们在本示例的`main()`方法中引入的更改：

+   `router :=mux.NewRouter()：在这里，我们调用`mux`路由器的`NewRouter()`处理程序实例化了`gorilla/mux`路由器。

+   `router.HandleFunc("/",renderTemplate).Methods("GET")：在这里，我们使用`renderTemplate`处理程序注册了`/` URL 模式。这意味着`renderTemplate`将对每个 URL 模式为`/`的请求执行。

+   `router.PathPrefix("/").Handler(http.StripPrefix("/static", http.FileServer(http.Dir("static/")))：在这里，我们将`/`注册为一个新的路由，并设置处理程序在调用时执行。

+   `http.StripPrefix("/static", http.FileServer(http.Dir("static/")))：这返回一个处理程序，通过从请求 URL 的路径中删除`/static`并调用文件服务器来提供 HTTP 请求。`StripPrefix`通过回复 HTTP 404 来处理不以前缀开头的路径的请求。

# 创建您的第一个 HTML 表单

每当我们想要从客户端收集数据并将其发送到服务器进行处理时，实现 HTML 表单是最佳选择。我们将在本示例中介绍这个。

# 如何做...

在本示例中，我们将创建一个简单的 HTML 表单，其中包含两个输入字段和一个提交表单的按钮。执行以下步骤：

1.  在`templates`目录中创建`login-form.html`，如下所示：

```go
$ mkdir templates && cd templates && touch login-form.html
```

1.  将以下内容复制到`login-form.html`中：

```go
<html>
  <head>
    <title>First Form</title>
  </head>
  <body>
    <h1>Login</h1>
    <form method="post" action="/login">
      <label for="username">Username</label>
      <input type="text" id="username" name="username">
      <label for="password">Password</label>
      <input type="password" id="password" name="password">
      <button type="submit">Login</button>
    </form>
  </body>
</html>
```

上述模板有两个文本框——`用户名`和`密码`——以及一个登录按钮。

单击登录按钮后，客户端将对在 HTML 表单中定义的操作进行`POST`调用，我们的情况下是`/login`。

1.  创建`html-form.go`，在那里我们将解析表单模板并将其写入 HTTP 响应流，如下所示：

```go
package main
import 
(
  "html/template"
  "log"
  "net/http"
)
const 
(
  CONN_HOST = "localhost"
  CONN_PORT = "8080"
)
func login(w http.ResponseWriter, r *http.Request) 
{
  parsedTemplate, _ := template.ParseFiles("templates/
  login-form.html")
  parsedTemplate.Execute(w, nil)
}
func main() 
{
  http.HandleFunc("/", login)
  err := http.ListenAndServe(CONN_HOST+":"+CONN_PORT, nil)
  if err != nil 
  {
    log.Fatal("error starting http server : ", err)
    return
  }
}
```

一切就绪后，目录结构应如下所示：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/go-webdev-cb/img/b9fbfd8c-a74f-4b47-a3b3-4ac7c8ebacf3.png)

1.  使用以下命令运行程序：

```go
$ go run html-form.go
```

# 它是如何工作的...

一旦我们运行程序，HTTP 服务器将在本地监听端口`8080`上启动。浏览`http://localhost:8080`将显示一个 HTML 表单，如下屏幕截图所示：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/go-webdev-cb/img/7d973921-5f28-483f-b58d-77ac105575c0.png)

让我们了解我们编写的程序：

+   `func login(w http.ResponseWriter, r *http.Request) { parsedTemplate, _ := template.ParseFiles("templates/login-form.html") parsedTemplate.Execute(w, nil) }：这是一个接受`ResponseWriter`和`Request`作为输入参数的 Go 函数，解析`login-form.html`并返回一个新模板。

+   `http.HandleFunc("/", login)：在这里，我们使用`net/http`包的`HandleFunc`将登录函数注册到`/` URL 模式，这意味着每次访问`/`模式的 HTTP URL 时，登录函数都会被执行，传递`ResponseWriter`和`Request`作为参数。

+   `err := http.ListenAndServe(CONN_HOST+":"+CONN_PORT, nil)：在这里，我们调用`http.ListenAndServe`来提供处理每个传入连接的 HTTP 请求的服务。`ListenAndServe`接受两个参数——服务器地址和处理程序——其中服务器地址为`localhost:8080`，处理程序为`nil`。

+   `if err != nil { log.Fatal("error starting http server : ", err) return}：在这里，我们检查是否启动服务器时出现问题。如果有问题，记录错误并以状态码`1`退出。

# 阅读您的第一个 HTML 表单

一旦提交 HTML 表单，我们必须在服务器端读取客户端数据以采取适当的操作。我们将在本示例中介绍这个。

# 准备好...

由于我们已经在上一个示例中创建了一个 HTML 表单，我们只需扩展该示例以读取其字段值。

# 如何做...

1.  使用以下命令安装`github.com/gorilla/schema`包：

```go
$ go get github.com/gorilla/schema
```

1.  创建`html-form-read.go`，在这里我们将使用`github.com/gorilla/schema`包解码 HTML 表单字段，并在 HTTP 响应流中写入 Hello，后跟用户名。

```go
package main
import 
(
  "fmt"
  "html/template"
  "log"
  "net/http"
  "github.com/gorilla/schema"
)
const 
(
  CONN_HOST = "localhost"
  CONN_PORT = "8080"
)
type User struct 
{
  Username string
  Password string
}
func readForm(r *http.Request) *User 
{
  r.ParseForm()
  user := new(User)
  decoder := schema.NewDecoder()
  decodeErr := decoder.Decode(user, r.PostForm)
  if decodeErr != nil 
  {
    log.Printf("error mapping parsed form data to struct : ",
    decodeErr)
  }
  return user
}
func login(w http.ResponseWriter, r *http.Request) 
{
  if r.Method == "GET" 
  {
    parsedTemplate, _ := template.ParseFiles("templates/
    login-form.html")
    parsedTemplate.Execute(w, nil)
  } 
  else 
  {
    user := readForm(r)
    fmt.Fprintf(w, "Hello "+user.Username+"!")
  }
}
func main() 
{
  http.HandleFunc("/", login)
  err := http.ListenAndServe(CONN_HOST+":"+CONN_PORT, nil)
  if err != nil 
  {
    log.Fatal("error starting http server : ", err)
    return
  }
}
```

1.  使用以下命令运行程序：

```go
$ go run html-form-read.go
```

# 工作原理...

一旦我们运行程序，HTTP 服务器将在本地监听端口`8080`。浏览`http://localhost:8080`将显示一个 HTML 表单，如下面的屏幕截图所示：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/go-webdev-cb/img/b576b702-a85a-4b85-8f84-6107c72022bb.png)

一旦我们输入用户名和密码并单击登录按钮，我们将在服务器的响应中看到 Hello，后跟用户名，如下面的屏幕截图所示：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/go-webdev-cb/img/f0373bdf-58fd-4108-8adf-24e204ff3006.png)

让我们了解一下我们在这个配方中引入的更改：

1.  使用`import ("fmt" "html/template" "log" "net/http" "github.com/gorilla/schema")`，我们导入了两个额外的包——`fmt`和`github.com/gorilla/schema`——它们有助于将`structs`与`Form`值相互转换。

1.  接下来，我们定义了`User struct`类型，它具有`Username`和`Password`字段，如下所示：

```go
type User struct 
{
  Username string
  Password string
}
```

1.  接下来，我们定义了`readForm`处理程序，它以`HTTP 请求`作为输入参数，并返回`User`，如下所示：

```go
func readForm(r *http.Request) *User {
 r.ParseForm()
 user := new(User)
 decoder := schema.NewDecoder()
 decodeErr := decoder.Decode(user, r.PostForm)
 if decodeErr != nil {
 log.Printf("error mapping parsed form data to struct : ", decodeErr)
 }
 return user
 }
```

让我们详细了解一下这个 Go 函数：

+   `r.ParseForm()`: 在这里，我们将请求体解析为一个表单，并将结果放入`r.PostForm`和`r.Form`中。

+   `user := new(User)`: 在这里，我们创建了一个新的`User struct`类型。

+   `decoder := schema.NewDecoder()`: 在这里，我们正在创建一个解码器，我们将使用它来用`Form`值填充一个用户`struct`。

+   `decodeErr := decoder.Decode(user, r.PostForm)`: 在这里，我们将从`POST`体参数中解码解析的表单数据到一个用户`struct`中。

`r.PostForm`只有在调用`ParseForm`之后才可用。

+   `if decodeErr != nil { log.Printf("error mapping parsed form data to struct : ", decodeErr) }`: 在这里，我们检查是否有任何将表单数据映射到结构体的问题。如果有，就记录下来。

然后，我们定义了一个`login`处理程序，它检查调用处理程序的 HTTP 请求是否是`GET`请求，然后从模板目录中解析`login-form.html`并将其写入 HTTP 响应流；否则，它调用`readForm`处理程序，如下所示：

```go
func login(w http.ResponseWriter, r *http.Request) 
{
  if r.Method == "GET" 
  {
    parsedTemplate, _ := template.ParseFiles("templates/
    login-form.html")
    parsedTemplate.Execute(w, nil)
  } 
  else 
  {
    user := readForm(r)
    fmt.Fprintf(w, "Hello "+user.Username+"!")
  }
}
```

# 验证您的第一个 HTML 表单

大多数情况下，我们在处理客户端输入之前必须对其进行验证，这可以通过 Go 中的许多外部包来实现，例如`gopkg.in/go-playground/validator.v9`、`gopkg.in/validator.v2`和`github.com/asaskevich/govalidator`。

在这个配方中，我们将使用最著名和常用的验证器`github.com/asaskevich/govalidator`来验证我们的 HTML 表单。

# 准备工作...

由于我们已经在上一个配方中创建并读取了一个 HTML 表单，我们只需扩展它以验证其字段值。

# 如何做...

1.  使用以下命令安装`github.com/asaskevich/govalidator`和`github.com/gorilla/schema`包：

```go
$ go get github.com/asaskevich/govalidator
$ go get github.com/gorilla/schema
```

1.  创建`html-form-validation.go`，在这里我们将读取一个 HTML 表单，使用`github.com/gorilla/schema`对其进行解码，并使用`github.com/asaskevich/govalidator`对其每个字段进行验证，验证标签定义在`User struct`中。

```go
package main
import 
(
  "fmt"
  "html/template"
  "log"
  "net/http"
  "github.com/asaskevich/govalidator"
  "github.com/gorilla/schema"
)
const 
(
  CONN_HOST = "localhost"
  CONN_PORT = "8080"
  USERNAME_ERROR_MESSAGE = "Please enter a valid Username"
  PASSWORD_ERROR_MESSAGE = "Please enter a valid Password"
  GENERIC_ERROR_MESSAGE = "Validation Error"
)
type User struct 
{
  Username string `valid:"alpha,required"`
  Password string `valid:"alpha,required"`
}
func readForm(r *http.Request) *User 
{
  r.ParseForm()
  user := new(User)
  decoder := schema.NewDecoder()
  decodeErr := decoder.Decode(user, r.PostForm)
  if decodeErr != nil 
  {
    log.Printf("error mapping parsed form data to struct : ",
    decodeErr)
  }
  return user
}
func validateUser(w http.ResponseWriter, r *http.Request, user *User) (bool, string) 
{
  valid, validationError := govalidator.ValidateStruct(user)
  if !valid 
  {
    usernameError := govalidator.ErrorByField(validationError,
    "Username")
    passwordError := govalidator.ErrorByField(validationError,
    "Password")
    if usernameError != "" 
    {
      log.Printf("username validation error : ", usernameError)
      return valid, USERNAME_ERROR_MESSAGE
    }
    if passwordError != "" 
    {
      log.Printf("password validation error : ", passwordError)
      return valid, PASSWORD_ERROR_MESSAGE
    }
  }
  return valid, GENERIC_ERROR_MESSAGE
}
func login(w http.ResponseWriter, r *http.Request) 
{
  if r.Method == "GET" 
  {
    parsedTemplate, _ := template.ParseFiles("templates/
    login-form.html")
    parsedTemplate.Execute(w, nil)
  } 
  else 
  {
    user := readForm(r)
    valid, validationErrorMessage := validateUser(w, r, user)
    if !valid 
    {
      fmt.Fprintf(w, validationErrorMessage)
      return
    }
    fmt.Fprintf(w, "Hello "+user.Username+"!")
  }
}
func main() 
{
  http.HandleFunc("/", login)
  err := http.ListenAndServe(CONN_HOST+":"+CONN_PORT, nil)
  if err != nil 
  {
    log.Fatal("error starting http server : ", err)
    return
  }
}
```

1.  使用以下命令运行程序：

```go
$ go run html-form-validation.go
```

# 工作原理...

一旦我们运行程序，HTTP 服务器将在本地监听端口`8080`。浏览`http://localhost:8080`将显示一个 HTML 表单，如下面的屏幕截图所示：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/go-webdev-cb/img/348772a2-efa6-4d10-85b0-7c8862333408.png)

然后提交具有有效值的表单：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/go-webdev-cb/img/86cba772-9979-4efc-ace2-bae92d5497be.png)

它将在浏览器屏幕上显示 Hello，后跟用户名，如下面的屏幕截图所示：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/go-webdev-cb/img/12b1c3c6-f8d8-412e-96a3-b29e20e7d229.png)

在任何字段中提交值为非字母的表单将显示错误消息。例如，提交用户名值为`1234`的表单：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/go-webdev-cb/img/11bbc899-37d9-4d63-8edf-d38a2a63de20.png)

它将在浏览器上显示错误消息，如下面的屏幕截图所示：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/go-webdev-cb/img/2e669f3e-942c-42e1-9c2c-d7ee4b674cf6.png)

此外，我们可以从命令行提交 HTML 表单，如下所示：

```go
$ curl --data "username=Foo&password=password" http://localhost:8080/
```

这将给我们在浏览器中得到的相同输出：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/go-webdev-cb/img/2ad63a7c-1b4b-468d-9dea-3fa04157ba04.png)

让我们了解一下我们在这个示例中引入的更改：

1.  使用`import ("fmt", "html/template", "log", "net/http" "github.com/asaskevich/govalidator" "github.com/gorilla/schema" )`，我们导入了一个额外的包——`github.com/asaskevich/govalidator`，它可以帮助我们验证结构。

1.  接下来，我们更新了`User struct`类型，包括一个字符串字面标签，`key`为`valid`，`value`为`alpha, required`，如下所示：

```go
type User struct 
{
  Username string `valid:"alpha,required"`
  Password string 
  valid:"alpha,required"
}
```

1.  接下来，我们定义了一个`validateUser`处理程序，它接受`ResponseWriter`、`Request`和`User`作为输入，并返回`bool`和`string`，分别是结构的有效状态和验证错误消息。在这个处理程序中，我们调用`govalidator`的`ValidateStruct`处理程序来验证结构标签。如果在验证字段时出现错误，我们将调用`govalidator`的`ErrorByField`处理程序来获取错误，并将结果与验证错误消息一起返回。

1.  接下来，我们更新了`login`处理程序，调用`validateUser`并将`(w http.ResponseWriter, r *http.Request, user *User)`作为输入参数传递给它，并检查是否有任何验证错误。如果有错误，我们将在 HTTP 响应流中写入错误消息并返回它。

# 上传您的第一个文件

在任何 Web 应用程序中，最常见的情景之一就是上传文件或文件夹到服务器。例如，如果我们正在开发一个求职门户网站，那么我们可能需要提供一个选项，申请人可以上传他们的个人资料/简历，或者，比如说，我们需要开发一个电子商务网站，其中客户可以使用文件批量上传他们的订单。

在 Go 中实现上传文件的功能非常容易，使用其内置的包，我们将在本示例中进行介绍。

# 如何做…

在这个示例中，我们将创建一个带有`file`类型字段的 HTML 表单，允许用户选择一个或多个文件通过表单提交上传到服务器。执行以下步骤：

1.  在`templates`目录中创建`upload-file.html`，如下所示：

```go
$ mkdir templates && cd templates && touch upload-file.html
```

1.  将以下内容复制到`upload-file.html`中：

```go
<html>
  <head>
    <meta charset="utf-8">
    <title>File Upload</title>
  </head>
  <body>
    <form action="/upload" method="post" enctype="multipart/
    form-data">
      <label for="file">File:</label>
      <input type="file" name="file" id="file">
      <input type="submit" name="submit" value="Submit">
    </form>
  </body>
</html>
```

在前面的模板中，我们定义了一个`file`类型的字段，以及一个`Submit`按钮。

点击“提交”按钮后，客户端将对请求的主体进行编码，并对表单操作进行`POST`调用，这在我们的情况下是`/upload`。

1.  创建`upload-file.go`，在其中我们将定义处理程序来渲染文件上传模板，从请求中获取文件，处理它，并将响应写入 HTTP 响应流，如下所示：

```go
package main
import 
(
  "fmt"
  "html/template"
  "io"
  "log"
  "net/http"
  "os"
)
const 
(
  CONN_HOST = "localhost"
  CONN_PORT = "8080"
)
func fileHandler(w http.ResponseWriter, r *http.Request) 
{
  file, header, err := r.FormFile("file")
  if err != nil 
  {
    log.Printf("error getting a file for the provided form key : ",
    err)
    return
  }
  defer file.Close()
  out, pathError := os.Create("/tmp/uploadedFile")
  if pathError != nil 
  {
    log.Printf("error creating a file for writing : ", pathError)
    return
  }
  defer out.Close()
  _, copyFileError := io.Copy(out, file)
  if copyFileError != nil 
  {
    log.Printf("error occurred while file copy : ", copyFileError)
  }
  fmt.Fprintf(w, "File uploaded successfully : "+header.Filename)
}
func index(w http.ResponseWriter, r *http.Request) 
{
  parsedTemplate, _ := template.ParseFiles("templates/
  upload-file.html")
  parsedTemplate.Execute(w, nil)
}
func main() 
{
  http.HandleFunc("/", index)
  http.HandleFunc("/upload", fileHandler)
  err := http.ListenAndServe(CONN_HOST+":"+CONN_PORT, nil)
  if err != nil 
  {
    log.Fatal("error starting http server : ", err)
    return
  }
}
```

一切就绪后，目录结构应该如下所示：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/go-webdev-cb/img/670f25ff-f46e-4aec-b0b4-c150b76ba734.png)

1.  使用以下命令运行程序：

```go
$ go run upload-file.go
```

# 它是如何工作的…

一旦我们运行程序，HTTP 服务器将在本地监听端口`8080`。浏览`http://localhost:8080`将会显示文件上传表单，如下面的屏幕截图所示：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/go-webdev-cb/img/db929449-393f-4fa5-92ff-368b6c2f5de0.png)

在选择文件后按下“提交”按钮将会在服务器上创建一个名为`uploadedFile`的文件，位于`/tmp`目录中。您可以通过执行以下命令来查看：

**![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/go-webdev-cb/img/438fac80-0552-4137-b28f-d6efe696fbfe.png)**

此外，成功上传将在浏览器上显示消息，如下面的屏幕截图所示：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/go-webdev-cb/img/d430fc2d-02ab-4941-86c2-52dccd992090.png)

让我们了解一下我们编写的 Go 程序：

我们定义了`fileHandler()`处理程序，它从请求中获取文件，读取其内容，最终将其写入服务器上的文件。由于这个处理程序做了很多事情，让我们逐步详细介绍一下：

+   `file, header, err := r.FormFile("file")`: 在这里，我们调用 HTTP 请求的`FormFile`处理程序，以获取提供的表单键对应的文件。

+   `if err != nil { log.Printf("error getting a file for the provided form key : ", err) return }`: 在这里，我们检查是否在从请求中获取文件时出现了任何问题。如果有问题，记录错误并以状态码`1`退出。

+   `defer file.Close()`: `defer`语句会在函数返回时关闭`file`。

+   `out, pathError := os.Create("/tmp/uploadedFile")`: 在这里，我们创建了一个名为`uploadedFile`的文件，放在`/tmp`目录下，权限为`666`，这意味着客户端可以读写但不能执行该文件。

+   `if pathError != nil { log.Printf("error creating a file for writing : ", pathError) return }`: 在这里，我们检查在服务器上创建文件时是否出现了任何问题。如果有问题，记录错误并以状态码`1`退出。

+   `_, copyFileError := io.Copy(out, file)`: 在这里，我们将从接收到的文件中的内容复制到`/tmp`目录下创建的文件中。

+   `fmt.Fprintf(w, "File uploaded successfully : "+header.Filename)`: 在这里，我们向 HTTP 响应流写入一条消息和文件名。
