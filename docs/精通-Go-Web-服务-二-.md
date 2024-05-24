# 精通 Go Web 服务（二）

> 原文：[`zh.annas-archive.org/md5/2D0D1F51B3626D3F3DD6A0D48080FBC1`](https://zh.annas-archive.org/md5/2D0D1F51B3626D3F3DD6A0D48080FBC1)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第四章：在 Go 中设计 API

我们现在已经完成了 REST 的基础知识，处理 URL 路由和在 Go 中进行多路复用，无论是直接还是通过框架。

希望创建我们的 API 的框架已经有所帮助和启发，但是如果我们要设计一个功能齐全的符合 REST 标准的 Web 服务，我们需要填补一些重要的空白。主要是，我们需要处理版本、所有端点和`OPTIONS`头，以及以一种优雅且易于管理的方式处理多种格式。

我们将完善我们想要为基于 API 的应用程序制定的端点，该应用程序允许客户端获取关于我们应用程序的所有信息，以及创建和更新用户，并提供与这些端点相关的有价值的错误信息。

在本章结束时，您还应该能够在 REST 和 WebSocket 应用程序之间切换，因为我们将构建一个非常简单的 WebSocket 示例，并带有内置的客户端测试界面。

在本章中，我们将涵盖以下主题：

+   概述和设计我们完整的社交网络 API

+   处理代码组织和 API 版本控制的基础知识

+   允许我们的 API 使用多种格式（XML 和 JSON）

+   仔细研究 WebSockets 并在 Go 中实现它们

+   创建更健壮和描述性的错误报告

+   通过 API 更新用户记录

在本章结束时，您应该能够优雅地处理 REST Web 服务的多种格式和版本，并更好地理解如何在 Go 中利用 WebSockets。

# 设计我们的社交网络 API

现在我们已经通过让 Go 输出我们 Web 服务中的数据来初步了解了一些，现在要采取的一个重要步骤是充分完善我们希望我们的主要项目的 API 要做什么。

由于我们的应用程序是一个社交网络，我们不仅需要关注用户信息，还需要关注连接和消息传递。我们需要确保新用户可以与某些群体共享信息，建立和修改连接，并处理身份验证。

考虑到这一点，让我们勾画出我们接下来可能的 API 端点，以便我们可以继续构建我们的应用程序：

| 端点 | 方法 | 描述 |
| --- | --- | --- |
| `/api/users` | `GET` | 返回带有可选参数的用户列表 |
| `/api/users` | `POST` | 创建用户 |
| `/api/users/XXX` | `PUT` | 更新用户信息 |
| `/api/users/XXX` | `DELETE` | 删除用户 |
| `/api/connections` | `GET` | 返回基于用户的连接列表 |
| `/api/connections` | `POST` | 创建用户之间的连接 |
| `/api/connections/XXX` | `PUT` | 修改连接 |
| `/api/connections/XXX` | `DELETE` | 删除用户之间的连接 |
| `/api/statuses` | `GET` | 获取状态列表 |
| `/api/statuses` | `POST` | 创建状态 |
| `/api/statuses/XXX` | `PUT` | 更新状态 |
| `/api/statuses/XXX` | `DELETE` | 删除状态 |
| `/api/comments` | `GET` | 获取评论列表 |
| `/api/comments` | `POST` | 创建评论 |
| `/api/comments/XXX` | `PUT` | 更新评论 |
| `/api/comments/XXX` | `DELETE` | 删除评论 |

在这种情况下，`XXX` 存在的任何地方都是我们将作为 URL 端点的一部分提供唯一标识符的地方。

您会注意到我们已经转移到了所有复数端点。这在很大程度上是一种偏好，许多 API 同时使用（或仅使用）单数端点。复数化端点的优势与命名结构的一致性有关，这使开发人员能够进行可预测的调用。使用单数端点可以作为一种简写方式来表达 API 调用只会处理单个记录。

这些端点中的每一个都反映了与数据点的潜在交互。还有一组我们将包括的端点，它们不反映与我们的数据的交互，而是允许我们的 API 客户端通过 OAuth 进行身份验证：

| 端点 | 方法 | 描述 |
| --- | --- | --- |
| `/api/oauth/authorize` | `GET` | 返回带有可选参数的用户列表 |
| `/api/oauth/token` | `POST` | 创建用户 |
| `/api/oauth/revoke` | `PUT` | 更新用户信息 |

如果你对 OAuth 不熟悉，现在不用担心，因为当我们介绍认证方法时，我们将会更深入地了解它。

### 提示

**OAuth**，即**开放认证**，诞生于需要创建一个用于验证 OpenID 用户的系统的需求，OpenID 是一个分散的身份系统。

OAuth2 出现时，系统已经大规模改进，更加安全，并且不再专注于特定的集成。如今，许多 API 依赖并要求 OAuth 来访问并代表用户通过第三方进行更改。

完整的规范文档（RFC6749）可以在互联网工程任务组的网站上找到：[`tools.ietf.org/html/rfc6749`](http://tools.ietf.org/html/rfc6749)。

前面提到的端点代表了我们构建一个完全基于 Web 服务运行的极简社交网络所需的一切。我们也将为此构建一个基本的界面，但主要是专注于在 Web 服务层面构建、测试和调优我们的应用程序。

我们不会在这里讨论`PATCH`请求，正如我们在上一章中提到的，它指的是对数据的部分更新。

在下一章中，我们将增强我们的 Web 服务，允许`PATCH`更新，并且我们将概述我们所有的端点作为我们`OPTIONS`响应的一部分。

# 处理我们的 API 版本

如果你花费了大量时间处理互联网上的 Web 服务和 API，你会发现各种服务处理其 API 版本的方式存在很大的差异。

并非所有这些方法都特别直观，而且通常它们会破坏向前和向后的兼容性。你应该尽量以最简单的方式避免这种情况。

考虑一个默认情况下在 URI 中使用版本控制的 API：`/api/v1.1/users`。

你会发现这是相当常见的；例如，这就是 Twitter 处理 API 请求的方式。

这种方法有一些优点和缺点，因此你应该考虑你的 URI 方法可能存在的缺点。

通过明确定义 API 版本，就没有默认版本，这意味着用户总是拥有他们所请求的版本。好处是你不会通过升级来破坏任何人的 API。坏处是用户可能不知道哪个版本是最新的，除非明确检查或验证描述性的 API 消息。

正如你可能知道的，Go 不允许有条件的导入。虽然这是一个设计决策，使得诸如`go fmt`和`go fix`等工具能够快速而优雅地工作，但有时会妨碍应用程序的设计。

例如，在 Go 中直接实现这样的功能是不可能的：

```go
if version == 1 {
  import "v1"
} else if version == 2 {
  import "v2"
}
```

不过，我们可以在这方面做一些变通。让我们假设我们的应用程序结构如下：

```go
socialnetwork.go
/{GOPATH}/github.com/nkozyra/gowebservice/v1.go
/{GOPATH}/github.com/nkozyra/gowebservice/v2.go

```

然后我们可以按如下方式导入每个版本：

```go
import "github.com/nkozyra/gowebservice/v1"
import "github.com/nkozyra/gowebservice/v2"

```

当然，这也意味着我们需要在我们的应用程序中使用它们，否则 Go 将触发编译错误。

维护多个版本的示例如下所示：

```go
package main

import
(
  "nathankozyra.com/api/v1"
  "nathankozyra.com/api/v2"
)

func main() {

  v := 1

  if v == 1 {
    v1.API()
    // do stuff with API v1
  } else {
    v2.API()
    // do stuff with API v2
  }

}
```

这种设计决定的不幸现实是，你的应用程序将违反编程的基本规则之一：*不要重复代码*。

当然，这不是一个硬性规则，但重复代码会导致功能蔓延、碎片化和其他问题。只要我们在各个版本中做相同的事情，我们就可以在一定程度上缓解这些问题。

在这个例子中，我们的每个 API 版本都将导入我们的标准 API 服务和路由文件，如下面的代码所示：

```go
package v2

import
(
  "nathankozyra.com/api/api"
)

type API struct {

}

func main() {
  api.Version = 1
  api.StartServer()
}
```

当然，我们的 v2 版本将几乎与不同版本相同。基本上，我们使用这些作为包装器，引入我们的重要共享数据，如数据库连接、数据编组等等。

为了演示这一点，我们可以将一些我们的基本变量和函数放入我们的`api.go`文件中：

```go
package api

import (
  "database/sql"
  "encoding/json"
  "fmt"
  _ "github.com/go-sql-driver/mysql"
  "github.com/gorilla/mux"
  "net/http"
  "log"
)

var Database *sql.DB

type Users struct {
  Users []User `json:"users"`
}

type User struct {
  ID int "json:id"
  Name  string "json:username"
  Email string "json:email"
  First string "json:first"
  Last  string "json:last"
}

func StartServer() {

  db, err := sql.Open("mysql", "root@/social_network")
  if err != nil {
  }
  Database = db
  routes := mux.NewRouter()

  http.Handle("/", routes)
  http.ListenAndServe(":8080", nil)
}
```

如果这看起来很熟悉，那是因为它是我们在上一章中尝试 API 时所拥有的核心，这里为了节省空间而剥离了一些路由。

现在也是一个好时机提到一个有趣的第三方包，用于处理基于 JSON 的 REST API——**JSON API Server**（**JAS**）。 JAS 位于 HTTP 之上（就像我们的 API 一样），但通过自动将请求定向到资源来自动化了许多路由。

### 提示

JSON API Server 或 JAS 允许在 HTTP 包之上使用一组简单的特定于 JSON 的 API 工具，以最小的影响增强您的 Web 服务。

您可以在[`github.com/coocood/jas`](https://github.com/coocood/jas)上阅读更多信息。

您可以通过使用以下命令在 Go 中安装它：`go get github.com/coocood/jas`。以多种格式交付我们的 API

在这个阶段，形式化我们处理多种格式的方式是有意义的。在这种情况下，我们处理 JSON、RSS 和通用文本。

我们将在下一章讨论模板时涉及通用文本，但现在我们需要能够分开我们的 JSON 和 RSS 响应。

这样做的最简单方法是将我们的任何资源都视为接口，然后根据请求参数协商数据的编组。

一些 API 直接在 URI 中定义格式。我们也可以在我们的 mux 路由中相当容易地这样做（如下面的示例所示）：

```go
  Routes.HandleFunc("/api.{format:json|xml|txt}/user", UsersRetrieve).Methods("GET")
```

上述代码将允许我们直接从 URL 参数中提取请求的格式。然而，当涉及到 REST 和 URI 时，这也是一个敏感的问题。虽然双方都有一些争论，但出于我们的目的，我们将简单地将格式用作查询参数。

在我们的`api.go`文件中，我们需要创建一个名为`Format`的全局变量：

```go
var Format string
```

以及一个我们可以用来确定每个请求的格式的函数：

```go
func GetFormat(r *http.Request) {

  Format = r.URL.Query()["format"][0]

}
```

我们将在每个请求中调用它。虽然前面的选项自动限制为 JSON、XML 或文本，但我们也可以将其构建到应用逻辑中，并包括对`Format`的回退，如果它不匹配可接受的选项。

我们可以使用通用的`SetFormat`函数来根据当前请求的数据格式进行数据编组：

```go
func SetFormat( data interface{} )  []byte {

  var apiOutput []byte
  if Format == "json" {
    output,_ := json.Marshal(data)
    apiOutput = output
  }else if Format == "xml" {
    output,_ := xml.Marshal(data)
    apiOutput = output
  }
  return apiOutput
}
```

在我们的任何端点函数中，我们可以返回作为接口传递给`SetFormat()`的任何数据资源：

```go
func UsersRetrieve(w http.ResponseWriter, r *http.Request) {
  log.Println("Starting retrieval")
  GetFormat(r)
  start := 0
  limit := 10

  next := start + limit

  w.Header().Set("Pragma","no-cache")
  w.Header().Set("Link","<http://localhost:8080/api/users?start="+string(next)+"; rel=\"next\"")

  rows,_ := Database.Query("SELECT * FROM users LIMIT 10")
  Response:= Users{}

  for rows.Next() {

    user := User{}
    rows.Scan(&user.ID, &user.Name, &user.First, &user.Last, &user.Email )

    Response.Users = append(Response.Users, user)
  }
    output := SetFormat(Response)
  fmt.Fprintln(w,string(output))
}
```

这使我们能够从响应函数中删除编组。现在我们已经相当牢固地掌握了将数据编组为 XML 和 JSON，让我们重新审视另一种用于提供 Web 服务的协议。

# 并发 WebSockets

如前一章所述，WebSocket 是一种保持客户端和服务器之间开放连接的方法，通常用于替代浏览器到客户端的多个 HTTP 调用，也用于两个可能需要保持半可靠恒定连接的服务器之间。

使用 WebSockets 的优势是减少客户端和服务器的延迟，并且对于构建长轮询应用程序的客户端解决方案来说，架构通常更少复杂。

为了概述优势，请考虑以下两种表示形式；第一个是标准 HTTP 请求：

![并发 WebSockets](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/ms-go-websvc/img/1304OS_04_03.jpg)

现在将这与更简化的 WebSocket 请求通过 TCP 进行比较，这消除了多次握手和状态控制的开销：

![并发 WebSockets](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/ms-go-websvc/img/1304OS_04_04.jpg)

您可以看到传统 HTTP 呈现了可以妨碍长期应用的冗余和延迟级别。

可以肯定的是，严格意义上只有 HTTP 1 才有这个问题。HTTP 1.1 引入了保持活动或持久性连接。虽然这在协议方面起作用，但大多数非并发的 Web 服务器在资源分配方面会遇到困难。例如，默认情况下，Apache 会将保持活动超时设置得非常低，因为长时间的连接会占用线程并阻止未来的请求在合理的时间内完成。

HTTP 的现在和未来提供了一些 WebSocket 的替代方案，主要是由 Google 主要开发的 SPDY 协议提出的一些重要选项。

虽然 HTTP 2.0 和 SPDY 提供了在不关闭连接的情况下复用连接的概念，特别是在 HTTP 管线化方法中，但目前还没有广泛的客户端支持。目前，如果我们从 Web 客户端访问 API，WebSockets 提供了更多的客户端可预测性。

应该注意的是，跨 Web 服务器和负载均衡器的 SPDY 支持仍然在很大程度上是实验性的。买方自负。

虽然 REST 仍然是我们 API 和演示的主要目标，但在以下代码中，您会发现一个非常简单的 WebSocket 示例，它接受一条消息并返回该消息在传输过程中的长度：

```go
package main

import (

    "fmt"
    "net/http"
    "code.google.com/p/go.net/websocket"
    "strconv"
)

var addr = ":12345"

func EchoLengthServer(ws *websocket.Conn) {

    var msg string

    for {
      websocket.Message.Receive(ws, &msg)
      fmt.Println("Got message",msg)
      length := len(msg)
      if err := websocket.Message.Send(ws, strconv.FormatInt(int64(length), 10) )  ; err != nil {
          fmt.Println("Can't send message length")
          break
        }
    }
```

请注意这里的循环；在`EchoLengthServer`函数中保持此循环运行非常重要，否则您的 WebSocket 连接将立即在客户端关闭，从而阻止未来的消息。

```go
}

func websocketListen() {

    http.Handle("/length", websocket.Handler(EchoLengthServer))
    err := http.ListenAndServe(addr, nil)
    if err != nil {
        panic("ListenAndServe: " + err.Error())
    }

}
```

这是我们的主要套接字路由器。我们正在监听端口`12345`并评估传入消息的长度，然后返回它。请注意，我们实质上将`http`处理程序*转换*为`websocket`处理程序。这在这里显示：

```go
func main() {

    http.HandleFunc("/websocket", func(w http.ResponseWriter, r *http.Request) {
        http.ServeFile(w, r, "websocket.html")
    })
    websocketListen()

}
```

最后一部分，除了实例化 WebSocket 部分外，还提供了一个平面文件。由于一些跨域策略问题，测试 WebSocket 示例的客户端访问和功能可能会很麻烦，除非两者在同一域和端口上运行。

为了管理跨域请求，必须启动协议握手。这超出了演示的范围，但如果您选择追求它，请知道这个特定的包确实提供了一个`serverHandshaker`接口，引用了`ReadHandshake`和`AcceptHandshake`方法。

### 提示

`websocket.go`的握手机制源代码可以在[`code.google.com/p/go/source/browse/websocket/websocket.go?repo=net`](https://code.google.com/p/go/source/browse/websocket/websocket.go?repo=net)找到。

由于这是一个完全基于 WebSocket 的演示，如果您尝试通过 HTTP 访问`/length`端点，您将收到标准错误，如下截图所示：

![并发 WebSockets](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/ms-go-websvc/img/1304OS_04_01.jpg)

因此，平面文件将返回到相同的域和端口。在前面的代码中，我们只是包括了 jQuery 和以下浏览器中存在的内置 WebSocket 支持：

+   **Chrome**：版本 21 及更高版本

+   **Safari**：版本 6 及更高版本

+   **Firefox**：版本 21 及更高版本

+   **IE**：版本 10 及更高版本

+   **Opera**：版本 22 及更高版本

现代 Android 和 iOS 浏览器现在也处理 WebSockets。

连接到服务器的 WebSocket 端并测试一些消息的代码如下。请注意，我们在这里不测试 WebSocket 支持：

```go
<html>
<head>
  <script src="img/jquery.min.js"></script>
</head>

<body>

<script>
  var socket;

  function update(msg) {

    $('#messageArea').html(msg)

  }
```

这段代码返回我们从 WebSocket 服务器收到的消息：

```go
  function connectWS(){

    var host = "ws://localhost:12345/length";

    socket = new WebSocket(host);
    socket.onopen = function() {
      update("Websocket connected")
    }

    socket.onmessage = function(message){

      update('Websocket counted '+message.data+' characters in your message');
    }

    socket.onclose = function() {
      update('Websocket closed');
    }

  }

  function send() {

    socket.send($('#message').val());

  }

  function closeSocket() {

    socket.close();
  }

  connectWS();
</script>

<div>
  <h2>Your message</h2>
  <textarea style="width:50%;height:300px;font-size:20px;" id="message"></textarea>
  <div><input type="submit" value="Send" onclick="send()" /> <input type="button" onclick="closeSocket();" value="Close" /></div>
</div>

<div id="messageArea"></div>
</body>
</html>
```

当我们在浏览器中访问`/websocket` URL 时，我们将获得文本区域，允许我们从客户端发送消息到 WebSocket 服务器，如下截图所示：

![并发 WebSockets](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/ms-go-websvc/img/1304OS_04_02.jpg)

# 分离我们的 API 逻辑

正如我们之前在版本控制部分提到的，我们实现版本和格式的一致性的最佳方法是将 API 逻辑与整体版本和交付组件分开。

我们在`GetFormat()`和`SetFormat()`函数中看到了一些这种情况，它们涵盖了所有的端点和版本。

# 扩展我们的错误消息

在上一章中，我们简要介绍了通过 HTTP 状态码发送错误消息。在这种情况下，当客户端尝试创建一个已经存在于数据库中的电子邮件地址的用户时，我们传递了一个 409 状态冲突。

`http`包提供了一组非全面的状态代码，您可以用它们来处理标准的 HTTP 问题以及特定于 REST 的消息。这些代码是非全面的，因为其中一些代码还有一些附加消息，但以下列表满足了 RFC 2616 提案：

| Error | Number |
| --- | --- |
| `StatusContinue` | 100 |
| `StatusSwitchingProtocols` | 101 |
| `StatusOK` | 200 |
| `StatusCreated` | 201 |
| `StatusAccepted` | 202 |
| `StatusNonAuthoritativeInfo` | 203 |
| `StatusNoContent` | 204 |
| `StatusResetContent` | 205 |
| `StatusPartialContent` | 206 |
| `StatusMultipleChoices` | 300 |
| `StatusMovedPermanently` | 301 |
| `StatusFound` | 302 |
| `StatusSeeOther` | 303 |
| `StatusNotModified` | 304 |
| `StatusUseProxy` | 305 |
| `StatusTemporaryRedirect` | 307 |
| `StatusBadRequest` | 400 |
| `StatusUnauthorized` | 401 |
| `StatusPaymentRequired` | 402 |
| `StatusForbidden` | 403 |
| `StatusNotFound` | 404 |
| `StatusMethodNotAllowed` | 405 |
| `StatusNotAcceptable` | 406 |
| `StatusProxyAuthRequired` | 407 |
| `StatusRequestTimeout` | 408 |
| `StatusConflict` | 409 |
| `StatusGone` | 410 |
| `StatusLengthRequired` | 411 |
| `StatusPreconditionFailed` | 412 |
| `StatusRequestEntityTooLarge` | 413 |
| `StatusRequestURITooLong` | 414 |
| `StatusUnsupportedMediaType` | 415 |
| `StatusRequestedRangeNotSatisfiable` | 416 |
| `StatusExpectationFailed` | 417 |
| `StatusTeapot` | 418 |
| `StatusInternalServerError` | 500 |
| `StatusNotImplemented` | 501 |
| `StatusBadGateway` | 502 |
| `StatusServiceUnavailable` | 503 |
| `StatusGatewayTimeout` | 504 |
| `StatusHTTPVersionNotSupported` | 505 |

您可能还记得我们之前硬编码了这个错误消息；我们的错误处理仍然应该保持在 API 版本的上下文之上。例如，在我们的`api.go`文件中，我们在`ErrorMessage`函数中有一个 switch 控制，明确定义了我们的 409 HTTP 状态码错误。我们可以通过`http`包本身中定义的常量和全局变量来增强这一点：

```go
func ErrorMessages(err int64) (int, int, string) {
  errorMessage := ""
  statusCode := 200;
  errorCode := 0
  switch (err) {
    case 1062:
      errorMessage = http.StatusText(409)
      errorCode = 10
      statusCode = http.StatusConflict
  }

  return errorCode, statusCode, errorMessage

}
```

您可能还记得这在应用程序的其他组件中进行了一些错误的翻译；在这种情况下，1062 是一个 MySQL 错误。我们还可以直接自动地在 switch 中实现 HTTP 状态码作为默认值：

```go
    default:
      errorMessage = http.StatusText(err)
      errorCode = 0
      statusCode = err
```

# 通过网络服务更新我们的用户

当我们允许用户通过网络服务进行更新时，我们在这里有能力呈现另一个潜在的错误点。

为此，我们将通过添加路由将一个端点添加到/`api/users/XXX`端点：

```go
  Routes.HandleFunc("/api/users/{id:[0-9]+}", UsersUpdate).Methods("PUT")
```

在我们的`UsersUpdate`函数中，我们首先会检查所说的用户 ID 是否存在。如果不存在，我们将返回 404 错误（文档未找到错误），这是资源记录未找到的最接近的近似值。

如果用户存在，我们将尝试通过查询更新他们的电子邮件 ID；如果失败，我们将返回冲突消息（或其他错误）。如果没有失败，我们将返回 200 和 JSON 中的成功消息。这是`UserUpdates`函数的开头：

```go
func UsersUpdate(w http.ResponseWriter, r *http.Request) {
  Response := UpdateResponse{}
  params := mux.Vars(r)
  uid := params["id"]
  email := r.FormValue("email")

  var userCount int
  err := Database.QueryRow("SELECT COUNT(user_id) FROM users WHERE user_id=?", uid).Scan(&userCount)
  if userCount == 0 {

      error, httpCode, msg := ErrorMessages(404)
      log.Println(error)
      log.Println(w, msg, httpCode)
      Response.Error = msg
      Response.ErrorCode = httpCode
      http.Error(w, msg, httpCode)

  }else if err != nil {
    log.Println(error)
  } else {

    _,uperr := Database.Exec("UPDATE users SET user_email=?WHERE user_id=?",email,uid)
    if uperr != nil {
      _, errorCode := dbErrorParse( uperr.Error() )
      _, httpCode, msg := ErrorMessages(errorCode)

      Response.Error = msg
      Response.ErrorCode = httpCode
      http.Error(w, msg, httpCode)
    } else {
      Response.Error = "success"
      Response.ErrorCode = 0
      output := SetFormat(Response)
      fmt.Fprintln(w,string(output))
    }
  }
}
```

我们稍微扩展一下这个，但现在，我们可以创建一个用户，返回用户列表，并更新用户的电子邮件地址。

### 提示

在使用 API 时，现在是一个好时机提到两个基于浏览器的工具：**Postman**和**Poster**，它们让您直接在浏览器中使用 REST 端点。

有关 Chrome 中 Postman 的更多信息，请访问[`chrome.google.com/webstore/detail/postman-rest-client/fdmmgilgnpjigdojojpjoooidkmcomcm?hl=en`](https://chrome.google.com/webstore/detail/postman-rest-client/fdmmgilgnpjigdojojpjoooidkmcomcm?hl=en)。

有关 Firefox 中的 Poster 的更多信息，请访问[`addons.mozilla.org/en-US/firefox/addon/poster/`](https://addons.mozilla.org/en-US/firefox/addon/poster/)。

这两种工具本质上是做同样的事情；它们允许您直接与 API 进行接口，而无需开发特定的基于 HTML 或脚本的工具，也无需直接从命令行使用 cURL。

# 总结

通过本章，我们已经勾勒出了我们的社交网络网络服务的要点，并准备填写。我们已经向您展示了如何创建和概述如何更新我们的用户，以及在无法更新用户时返回有价值的错误信息。

本章在这样的应用程序基础设施——格式和端点——上投入了大量时间。在前者方面，我们主要关注了 XML 和 JSON，但在下一章中，我们将探索模板，以便您可以以您认为必要的任何任意格式返回数据。

我们还将深入探讨身份验证，无论是通过 OAuth 还是简单的 HTTP 基本身份验证，这将允许我们的客户端安全连接到我们的网络服务并发出保护敏感数据的请求。为此，我们还将锁定我们的应用程序以进行一些请求的 HTTPS。

此外，我们将专注于我们仅简要提及的 REST 方面——通过`OPTIONS HTTP`动词概述我们的网络服务的行为。最后，我们将更仔细地研究头部如何用于近似表示网络服务的服务器端和接收端的状态。


# 第五章：Go 中的模板和选项

在我们的社交网络网络服务的基础上，是时候将我们的项目从演示玩具变成实际可用的东西了，也许最终还可以投入生产。

为此，我们需要关注许多事情，其中一些我们将在本章中解决。在上一章中，我们看了一下如何确定我们的社交网络应用程序的主要功能。现在，我们需要确保从 REST 的角度来看，每一件事都是可能的。

为了实现这一点，在本章中，我们将看到：

+   使用`OPTIONS`提供内置文档和我们资源端点目的的 REST 友好解释

+   考虑替代输出格式以及如何实现它们的介绍

+   为我们的 API 实施和强制安全性

+   允许用户注册以使用安全密码

+   允许用户从基于 Web 的界面进行身份验证

+   近似于 OAuth 样式的身份验证系统

+   允许外部应用代表其他用户发出请求

在实施这些事情之后，我们将拥有一个允许用户与之进行接口的服务的基础，无论是通过 API 直接接口还是通过第三方服务。

# 分享我们的选项

我们已经略微提到了`OPTIONS` HTTP 动词的价值和目的，因为它与 HTTP 规范和 REST 的最佳实践有关。

根据 RFC 2616，即 HTTP/1.1 规范，对`OPTIONS`请求的响应应返回有关客户端可以对资源和/或请求的端点进行的操作的信息。

### 注意

您可以在[`www.ietf.org/rfc/rfc2616.txt`](https://www.ietf.org/rfc/rfc2616.txt)找到**HTTP/1.1** **请求注释** (**RFC**)。

换句话说，在我们早期的示例中，对`/api/users`的`OPTIONS`调用应返回一个指示，即`GET`、`POST`、`PUT`和`DELETE`目前是该 REST 资源请求的可用选项。

目前，对于正文内容应该是什么样子或包含什么内容并没有预定义的格式，尽管规范表明这可能会在将来的版本中概述。这给了我们一些灵活性，可以在如何呈现可用操作方面有所作为；在大多数这样的情况下，我们都希望尽可能健壮和信息丰富。

以下代码是我们目前 API 的简单修改，其中包含了我们之前概述的有关`OPTIONS`请求的一些基本信息。首先，我们将在`api.go`文件的导出`Init()`函数中添加请求的特定处理程序：

```go
func Init() {
  Routes = mux.NewRouter()
  Routes.HandleFunc("/api/users", UserCreate).Methods("POST")
  Routes.HandleFunc("/api/users", UsersRetrieve).Methods("GET")	
  Routes.HandleFunc("/api/users/{id:[0-9]+}",UsersUpdate).Methods("PUT")
  Routes.HandleFunc("/api/users", UsersInfo).Methods("OPTIONS")
}
```

然后，我们将添加处理程序：

```go
func UsersInfo(w http.ResponseWriter, r *http.Request) {
  w.Header().Set("Allow","DELETE,GET,HEAD,OPTIONS,POST,PUT")
}
```

直接使用 cURL 调用这个命令会给我们我们所需要的东西。在下面的屏幕截图中，您会注意到响应顶部的`Allow`标头：

![分享我们的选项](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/ms-go-websvc/img/1304OS_05_01.jpg)

这一点单独就足以满足 REST 世界中`OPTIONS`动词的大多数普遍接受的要求，但请记住，正文没有格式，我们希望尽可能地表达。

我们可以通过提供一个特定于文档的包来做到这一点；在这个例子中，它被称为规范。请记住，这是完全可选的，但对于偶然发现它的任何开发人员来说，这是一个不错的礼物。让我们看看如何为自我记录的 API 设置这个：

```go
package specification
type MethodPOST struct {
  POST EndPoint
}
type MethodGET struct {
  GET EndPoint
}
type MethodPUT struct {
  PUT EndPoint
}
type MethodOPTIONS struct {
  OPTIONS EndPoint
}
type EndPoint struct {
  Description string `json:"description"`
  Parameters []Param `json:"parameters"`
}
type Param struct {
  Name string "json:name"
  ParameterDetails Detail `json:"details"`
}
type Detail struct {
  Type string "json:type"
  Description string `json:"description"`
  Required bool "json:required"
}

var UserOPTIONS = MethodOPTIONS{ OPTIONS: EndPoint{ Description: "This page" } }
var UserPostParameters = []Param{ {Name: "Email", ParameterDetails: Detail{Type:"string", Description: "A new user's email address", Required: false} } }

var UserPOST = MethodPOST{ POST: EndPoint{ Description: "Create a user", Parameters: UserPostParameters } }
var UserGET = MethodGET{ GET: EndPoint{ Description: "Access a user" }}
```

然后，您可以直接在我们的`api.go`文件中引用它。首先，我们将创建一个包含所有可用方法的通用接口切片：

```go
type DocMethod interface {
}
```

然后，我们可以在我们的`UsersInfo`方法中编译我们的各种方法：

```go
func UsersInfo(w http.ResponseWriter, r *http.Request) {
  w.Header().Set("Allow","DELETE,GET,HEAD,OPTIONS,POST,PUT")

  UserDocumentation := []DocMethod{}
  UserDocumentation = append(UserDocumentation, Documentation.UserPOST)
  UserDocumentation = append(UserDocumentation, Documentation.UserOPTIONS)
  output := SetFormat(UserDocumentation)
  fmt.Fprintln(w,string(output))
}
```

您的屏幕应该看起来类似于这样：

![分享我们的选项](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/ms-go-websvc/img/1304OS_05_02.jpg)

# 实施替代格式

在查看 API 格式的世界时，您现在知道有两个主要的参与者：**XML**和**JSON**。作为人类可读格式，这两种格式在过去十多年中一直占据着格式世界。

通常情况下，开发人员和技术人员很少会满意地长期使用某种东西。在计算编码和解码的复杂性以及模式的冗长推动许多开发人员转向 JSON 之前，XML 很长一段时间是第一位的。

JSON 也不是没有缺点。没有一些明确的间距，它对人类来说并不那么可读，这会使文档的大小过分增加。它也不能默认处理注释。

还有许多替代格式在一旁。**YAML**，代表**YAML Ain't Markup Language**，是一种使用缩进使其对人类极易阅读的空白分隔格式。一个示例文档可能是这样的：

```go
---
api:
  name: Social Network
  methods:
    - GET
    - POST
    - PUT
    - OPTIONS
    - DELETE
```

缩进系统作为模拟代码块的方法，对于有 Python 经验的人来说会很熟悉。

### 提示

Go 有许多 YAML 实现。最值得注意的是`go-yaml`，可以在[`github.com/go-yaml/yaml`](https://github.com/go-yaml/yaml)找到。

**TOML**，或**Tom's Obvious, Minimal Language**，采用了一种方法，对于任何使用`.ini`风格配置文件的人来说都会非常熟悉。

# 制定我们自己的数据表示格式

TOML 是一个很好的格式，可以用来构建我们自己的数据格式，主要是因为它的简单性使得在这种格式内部实现多种输出成为可能。

当设计像 TOML 这样简单的东西时，你可能会立即想到 Go 的文本模板格式，因为它本质上已经有了呈现它的控制机制。例如，考虑这个结构和循环：

```go
type GenericData struct {
  Name string
  Options GenericDataBlock
}

type GenericDataBlock struct {
  Server string
  Address string
}

func main() {
  Data := GenericData{ Name: "Section", Options: GenericDataBlock{Server: "server01", Address: "127.0.0.1"}}

}
```

当结构被解析为文本模板时，它将精确地生成我们想要的内容:`{{.Name}}`。

```go
{{range $index, $value := Options}}
  $index = $value
{{end}}
```

这种方法的一个大问题是你没有固有的系统来解组数据。换句话说，你可以生成这种格式的数据，但你不能将其解开成 Go 结构的另一种方式。

另一个问题是，随着格式的复杂性增加，使用 Go 模板库中的有限控制结构来满足这种格式的所有复杂性和怪癖变得不太合理。

如果你选择自己的格式，你应该避免文本模板，而是查看编码包，它允许你生成和消费结构化数据格式。

我们将在接下来的章节中仔细研究编码包。

# 引入安全和认证

任何网络服务或 API 的一个关键方面是能够保持信息安全，并且只允许特定用户访问特定的内容。

在历史上，有许多方法可以实现这一点，最早的一种是 HTTP 摘要认证。

另一个常见的方法是包含开发人员凭据，即 API 密钥。这已经不再被推荐，主要是因为 API 的安全性完全依赖于这些凭据的安全性。然而，这在很大程度上是一种明显的允许认证的方法，作为服务提供商，它允许你跟踪谁在做特定的请求，还可以实现请求的限制。

今天的大玩家是 OAuth，我们很快会看一下。然而，首先，我们需要确保我们的 API 只能通过 HTTPS 访问。

## 强制使用 HTTPS

此时，我们的 API 开始使客户和用户能够做一些事情，比如创建用户，更新他们的数据，并为这些用户包含图像数据。我们开始涉足一些在现实环境中不希望公开的事情。

我们可以看一下的第一个安全步骤是强制 API 上的 HTTPS 而不是 HTTP。Go 通过 TLS 实现 HTTPS，而不是 SSL，因为从服务器端来看，TLS 被认为是更安全的协议。其中一个驱动因素是 SSL 3.0 中的漏洞，特别是 2014 年暴露的 Poodlebleed Bug。

### 提示

您可以在[`poodlebleed.com/`](https://poodlebleed.com/)了解更多关于 Poodlebleed 的信息。

让我们看看如何在以下代码中将任何非安全请求重定向到其安全对应项：

```go
package main

import
(
  "fmt"
  "net/http"
  "log"
  "sync"
)

const (
  serverName = "localhost"
  SSLport = ":443"
  HTTPport = ":8080"
  SSLprotocol = "https://"
  HTTPprotocol = "http://"
)

func secureRequest(w http.ResponseWriter, r *http.Request) {
  fmt.Fprintln(w,"You have arrived at port 443, but you are not yet secure.")
}
```

这是我们（暂时）正确的端点。它还不是 TSL（或 SSL），所以我们实际上并没有监听 HTTPS 连接，因此会显示此消息。

```go
func redirectNonSecure(w http.ResponseWriter, r *http.Request) {
  log.Println("Non-secure request initiated, redirecting.")
  redirectURL := SSLprotocol + serverName + r.RequestURI
  http.Redirect(w, r, redirectURL, http.StatusOK)
}
```

这是我们的重定向处理程序。您可能会注意到`http.StatusOK`状态码 - 显然我们希望发送 301 永久移动错误（或`http.StatusMovedPermanently`常量）。但是，如果您正在测试这个，您的浏览器可能会缓存状态并自动尝试重定向您。

```go
func main() {
  wg := sync.WaitGroup{}
  log.Println("Starting redirection server, try to access @ http:")

  wg.Add(1)
  go func() {
    http.ListenAndServe(HTTPport,http.HandlerFunc(redirectNonSecure))
    wg.Done()
  }()
  wg.Add(1)
  go func() {
    http.ListenAndServe(SSLport,http.HandlerFunc(secureRequest))
    wg.Done()
  }()
  wg.Wait()
}
```

那么，为什么我们将这些方法包装在匿名的 goroutines 中呢？好吧，把它们拿出来，您会发现因为`ListenAndServe`函数是阻塞的，我们不能通过简单调用以下语句同时运行这两个方法：

```go
http.ListenAndServe(HTTPport,http.HandlerFunc(redirectNonSecure))
http.ListenAndServe(SSLport,http.HandlerFunc(secureRequest))

```

当然，您在这方面有多种选择。您可以简单地将第一个设置为 goroutine，这将允许程序继续执行第二个服务器。这种方法提供了一些更细粒度的控制，用于演示目的。

## 添加 TLS 支持

在前面的示例中，显然我们并没有监听 HTTPS 连接。Go 使这变得非常容易；但是，像大多数 SSL/TLS 问题一样，处理您的证书时会出现复杂性。

对于这些示例，我们将使用自签名证书，Go 也很容易实现。在`crypto/tls`包中，有一个名为`generate_cert.go`的文件，您可以使用它来生成您的证书密钥。

通过转到您的 Go 二进制目录，然后`src/pkg/crypto/tls`，您可以通过运行以下命令生成一个可以用于测试的密钥对：

```go
go run generate_cert.go --host localhost --ca true

```

然后，您可以将这些文件移动到任何您想要的位置，理想情况下是我们 API 运行的目录。

接下来，让我们删除`http.ListenAndServe`函数，并将其更改为`http.ListenAndServeTLS`。这需要一些额外的参数，包括密钥的位置：

```go
http.ListenAndServeTLS(SSLport, "cert.pem", "key.pem", http.HandlerFunc(secureRequest))
```

为了更加明确，让我们稍微修改我们的`secureRequest`处理程序：

```go
fmt.Fprintln(w,"You have arrived at port 443, and now you are marginally more secure.")
```

如果我们现在运行这个并转到我们的浏览器，希望会看到一个警告，假设我们的浏览器会保护我们：

![添加 TLS 支持](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/ms-go-websvc/img/1304OS_05_03.jpg)

假设我们信任自己，这并不总是明智的，点击通过，我们将看到来自安全处理程序的消息：

![添加 TLS 支持](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/ms-go-websvc/img/1304OS_05_04.jpg)

### 注意

当然，如果我们再次访问`http://localhost:8080`，我们现在应该会自动重定向，并显示 301 状态代码。

当您有访问支持 OpenSSL 的操作系统时，创建自签名证书通常是相当容易的。

如果您想要尝试使用真实证书而不是自签名证书，您可以通过多种服务免费获得一年期的签名（但未经验证）证书。其中比较流行的是 StartSSL（[`www.startssl.com/`](https://www.startssl.com/)），它使得获取免费和付费证书变得简单。

# 让用户注册和认证

您可能还记得，作为我们 API 应用的一部分，我们有一个自包含的接口，允许我们为 API 本身提供 HTML 界面。如果我们不保护我们的用户，任何关于安全性的讨论都将毫无意义。

当然，实现用户身份验证安全的绝对最简单的方法是通过存储和使用带有哈希机制的密码。服务器以明文存储密码是非常常见的，所以我们不会这样做；但是，我们希望至少使用一个额外的安全参数来实现我们的密码。

我们希望不仅存储用户的密码，而且至少存储一个盐。这并不是一个绝对安全的措施，尽管它严重限制了字典和彩虹攻击的威胁。

为此，我们将创建一个名为`password`的新包，作为我们套件的一部分，它允许我们生成随机盐，然后加密该值以及密码。

我们可以使用`GenerateHash()`来创建和验证密码。

## 快速入门-生成盐

获取密码很简单，创建安全哈希也相当容易。为了使我们的身份验证过程更安全，我们缺少的是盐。让我们看看我们如何做到这一点。首先，让我们在我们的数据库中添加一个密码和一个盐字段：

```go
ALTER TABLE `users`
  ADD COLUMN `user_password` VARCHAR(1024) NOT NULL AFTER `user_nickname`,
  ADD COLUMN `user_salt` VARCHAR(128) NOT NULL AFTER `user_password`,
  ADD INDEX `user_password_user_salt` (`user_password`, `user_salt`);
```

有了这个，让我们来看看我们的密码包，其中包含盐和哈希生成函数：

```go
package password

import
(
  "encoding/base64"
  "math/rand"
  "crypto/sha256"
  "time"
)

const randomLength = 16

func GenerateSalt(length int) string {
  var salt []byte
  var asciiPad int64

  if length == 0 {
    length = randomLength
  }

  asciiPad = 32

  for i:= 0; i < length; i++ {
    salt = append(salt, byte(rand.Int63n(94) + asciiPad) )
  }

  return string(salt)
}
```

我们的`GenerateSalt()`函数生成一串特定字符集内的随机字符。在这种情况下，我们希望从 ASCII 表中的 32 开始，一直到 126。

```go
func GenerateHash(salt string, password string) string {
  var hash string
  fullString := salt + password
  sha := sha256.New()
  sha.Write([]byte(fullString))
  hash = base64.URLEncoding.EncodeToString(sha.Sum(nil))

  return hash
}
```

在这里，我们基于密码和盐生成一个哈希。这不仅对于密码的创建有用，还对于验证密码也有用。以下的`ReturnPassword()`函数主要作为其他函数的包装器，允许您创建密码并返回其哈希值：

```go
func ReturnPassword(password string) (string, string) {
  rand.Seed(time.Now().UTC().UnixNano())

  salt := GenerateSalt(0)

  hash := GenerateHash(salt,password)

  return salt, hash
}
```

在我们的客户端，您可能还记得我们通过 jQuery 通过 AJAX 发送了所有数据。我们在一个单独的 Bootstrap 标签上有一个单独的方法，允许我们创建用户。首先，让我们回顾一下标签设置。

现在，`userCreate()`函数中，我们添加了一些东西。首先，有一个密码字段，允许我们在创建用户时发送该密码。在没有安全连接的情况下，我们可能以前对此不太放心：

```go
  function userCreate() {
    action = "https://localhost/api/users";
    postData = {};
    postData.email = $('#createEmail').val();
    postData.user = $('#createUsername').val();
    postData.first = $('#createFirst').val();
    postData.last= $('#createLast').val();
    postData.password = $('#createPassword').val();
```

接下来，我们可以修改我们的`.ajax`响应以对不同的 HTTP 状态代码做出反应。请记住，如果用户名或电子邮件 ID 已经存在，我们已经设置了冲突。因此，让我们也处理这个问题：

```go
var formData = new FormData($('form')[0]);
$.ajax({

    url: action,  //Server script to process data
    dataType: 'json',
    type: 'POST',
    statusCode: {
      409: function() {
        $('#api-messages').html('Email address or nickname already exists!');
        $('#api-messages').removeClass('alert-success').addClass('alert-warning');
        $('#api-messages').show();
        },
      200: function() {
        $('#api-messages').html('User created successfully!');
        $('#api-messages').removeClass('alert-warning').addClass('alert-success');
        $('#api-messages').show();
        }
      },
```

现在，如果我们得到一个 200 的响应，我们知道我们的 API 端已经创建了用户。如果我们得到 409，我们会在警报区域向用户报告电子邮件地址或用户名已被使用。

# 在 Go 中检查 OAuth

正如我们在第四章中简要提到的，*在 Go 中设计 API*，OAuth 是允许应用使用另一个应用的用户身份验证与第三方应用进行交互的一种常见方式。

它在社交媒体服务中非常受欢迎；Facebook、Twitter 和 GitHub 都使用 OAuth 2.0 允许应用代表用户与其 API 进行交互。

这里值得注意的是，虽然有许多 API 调用我们可以放心地不受限制，主要是`GET`请求，但还有一些是特定于用户的，我们需要确保我们的用户授权这些请求。

让我们快速回顾一下我们可以实现的方法，以使我们的服务器类似于 OAuth：

```go
Endpoint
/api/oauth/authorize
/api/oauth/token
/api/oauth/revoke
```

鉴于我们有一个小型的、主要基于演示的服务，我们长时间保持访问令牌活动的风险是很小的。长期有效的访问令牌显然会为客户端开放更多的不受欢迎的访问机会，因为它们可能没有遵守最佳的安全协议。

在正常情况下，我们希望对令牌设置一个到期时间，我们可以通过使用一个带有过期时间的 memcache 系统或密钥库来简单地实现这一点。这样可以使值自然死亡，而无需显式销毁它们。

我们需要做的第一件事是为客户端凭据添加一个表，即`consumer_key`和`consumer_token`：

```go
CREATE TABLE `api_credentials` (
  `user_id` INT(10) UNSIGNED NOT NULL,
  `consumer_key` VARCHAR(128) NOT NULL,
  `consumer_secret` VARCHAR(128) NOT NULL,
  `callback_url` VARCHAR(256) NOT NULL
  CONSTRAINT `FK__users` FOREIGN KEY (`user_id`) REFERENCES `users` (`user_id`) ON UPDATE NO ACTION ON DELETE NO ACTION
)
```

我们将检查详细信息以验证凭据是否正确，并且如果正确，我们将返回一个访问令牌。

访问令牌可以是任何格式；鉴于我们对演示的低安全限制，我们将返回一个随机生成的字符串的 MD5 哈希。在现实世界中，即使对于短期令牌，这可能也不够，但它在这里能够达到目的。

### 提示

请记住，我们在`password`包中实现了一个随机字符串生成器。您可以通过调用以下语句在`api.go`中创建一个快速的密钥和密钥值：

```go
  fmt.Println(Password.GenerateSalt(22))
  fmt.Println(Password.GenerateSalt(41))
```

如果您将此密钥和密钥值输入到先前创建的表中，并将其与现有用户关联，您将拥有一个活动的 API 客户端。请注意，这可能会生成无效的 URL 字符，因此我们将将我们对`/oauth/token`端点的访问限制为`POST`。

我们的伪 OAuth 机制将进入自己的包中，并且它将严格生成我们将在 API 包中的令牌切片中保留的令牌。

在我们的核心 API 包中，我们将添加两个新函数来验证凭据和`pseudoauth`包：

```go
  import(
  Pseudoauth "github.com/nkozyra/gowebservice/pseudoauth" 
  )
```

我们将添加的函数是`CheckCredentials()`和`CheckToken()`。第一个将接受一个密钥、一个一次性号码、一个时间戳和一个加密方法，然后我们将与`consumer_secret`值一起对其进行哈希处理，以查看签名是否匹配。实质上，所有这些请求参数都与双方知道但未广播的秘密结合在一起，以创建一个以双方知道的方式进行哈希处理的签名。如果这些签名对应，应用程序可以发出请求令牌或访问令牌（后者通常用于交换请求令牌，我们将很快讨论更多内容）。

在我们的情况下，我们将接受`consumer_key`值、一次性号码、时间戳和签名，暂时假设 HMAC-SHA1 被用作签名方法。由于 SHA1 发生碰撞的可能性增加，它正在失去一些青睐，但是对于开发应用程序的目的，它将会并且可以在以后简单地替换。Go 还提供了 SHA224、SHA256、SHA384 和 SHA512。

一次性号码和时间戳的目的是专门增加安全性。一次性号码几乎肯定作为请求的唯一标识哈希，时间戳允许我们定期过期数据以保留内存和/或存储。我们这里不会这样做，尽管我们将检查以确保一次性号码以前没有被使用。

要开始验证客户端，我们在数据库中查找共享密钥。

```go
func CheckCredentials(w http.ResponseWriter, r *http.Request)  {
  var Credentials string
  Response := CreateResponse{}
  consumerKey := r.FormValue("consumer_key")
  fmt.Println(consumerKey)
  timestamp := r.FormValue("timestamp")
  signature := r.FormValue("signature")
  nonce := r.FormValue("nonce")
  err := Database.QueryRow("SELECT consumer_secret from api_credentials where consumer_key=?", consumerKey).Scan(&Credentials)
    if err != nil {
    error, httpCode, msg := ErrorMessages(404)
    log.Println(error)	
    log.Println(w, msg, httpCode)
    Response.Error = msg
    Response.ErrorCode = httpCode
    http.Error(w, msg, httpCode)
    return
  }
```

在这里，我们获取`consumer_key`值并查找我们共享的`consumer_secret`令牌，然后将其传递给我们的`ValidateSignature`函数，如下所示：

```go
  token,err := Pseudoauth.ValidateSignature(consumerKey,Credentials,timestamp,nonce,signature,0)
  if err != nil {
    error, httpCode, msg := ErrorMessages(401)
    log.Println(error)	
    log.Println(w, msg, httpCode)
    Response.Error = msg
    Response.ErrorCode = httpCode
    http.Error(w, msg, httpCode)
    return
  }
```

如果我们发现我们的请求无效（要么是因为凭据不正确，要么是因为存在的一次性号码），我们将返回未经授权的错误和 401 状态码：

```go
  AccessRequest := OauthAccessResponse{}
  AccessRequest.AccessToken = token.AccessToken
  output := SetFormat(AccessRequest)
  fmt.Fprintln(w,string(output))
}
```

否则，我们将在 JSON 主体响应中返回访问代码。这是`pseudoauth`包本身的代码：

```go
package pseudoauth
import
(
  "crypto/hmac"
  "crypto/sha1"
  "errors"
  "fmt"
  "math/rand"
  "strings"
  "time"
)
```

这里没有太多令人惊讶的地方！我们需要一些加密包和`math/rand`来允许我们进行种子生成：

```go
type Token struct {
  Valid bool
  Created int64
  Expires int64
  ForUser int
  AccessToken string
}
```

这里比我们目前使用的要多一点，但你可以看到我们可以创建具有特定访问权限的令牌：

```go
var nonces map[string] Token
func init() {
  nonces = make(map[string] Token)
}

func ValidateSignature(consumer_key string, consumer_secret string, timestamp string,  nonce string, signature string, for_user int) (Token, error) {
  var hashKey []byte
  t := Token{}
  t.Created = time.Now().UTC().Unix()
  t.Expires = t.Created + 600
  t.ForUser = for_user

  qualifiedMessage := []string{consumer_key, consumer_secret, timestamp, nonce}
  fullyQualified := strings.Join(qualifiedMessage," ")

  fmt.Println(fullyQualified)
  mac := hmac.New(sha1.New, hashKey)
  mac.Write([]byte(fullyQualified))
  generatedSignature := mac.Sum(nil)

  //nonceExists := nonces[nonce]

  if hmac.Equal([]byte(signature),generatedSignature) == true {

    t.Valid = true
    t.AccessToken = GenerateToken()
    nonces[nonce] = t
    return t, nil
  } else {
    err := errors.New("Unauthorized")
    t.Valid = false
    t.AccessToken = ""
    nonces[nonce] = t
    return t, err
  }

}
```

这是类似于 OAuth 这样的服务尝试验证签名请求的粗略近似；一次性号码、公钥、时间戳和共享私钥使用相同的加密进行评估。如果它们匹配，请求是有效的。如果它们不匹配，应该返回错误。

我们可以稍后使用时间戳为任何给定的请求提供一个短暂的窗口，以便在意外签名泄漏的情况下，可以将损害最小化：

```go
func GenerateToken() string {
  var token []byte
  rand.Seed(time.Now().UTC().UnixNano())
  for i:= 0; i < 32; i++ {
    token = append(token, byte(rand.Int63n(74) + 48) )
  }
  return string(token)
}
```

# 代表用户进行请求

在代表用户进行请求时，OAuth2 过程中涉及一个关键的中间步骤，那就是用户的身份验证。显然，这不能在消费者应用程序中发生，因为这将打开一个安全风险，恶意或不恶意地，用户凭据可能会被泄露。

因此，这个过程需要一些重定向。

首先，需要一个初始请求，将用户重定向到登录位置。如果他们已经登录，他们将有能力授予应用程序访问权限。接下来，我们的服务将接受一个回调 URL 并将用户带回来，同时带上他们的请求令牌。这将使第三方应用程序能够代表用户进行请求，直到用户限制对第三方应用程序的访问为止。

为了存储有效的令牌，这些令牌本质上是用户和第三方开发人员之间的许可连接，我们将为此创建一个数据库：

```go
CREATE TABLE `api_tokens` (
  `api_token_id` INT(10) UNSIGNED NOT NULL AUTO_INCREMENT,
  `application_user_id` INT(10) UNSIGNED NOT NULL,
  `user_id` INT(10) UNSIGNED NOT NULL,
  `api_token_key` VARCHAR(50) NOT NULL,
  PRIMARY KEY (`api_token_id`)
)
```

我们需要一些部件来使其工作，首先是一个登录表单，用于当前未登录的用户，依赖于`sessions`表。让我们现在在 MySQL 中创建一个非常简单的实现：

```go
CREATE TABLE `sessions` (
  `session_id` VARCHAR(128) NOT NULL,
  `user_id` INT(10) NOT NULL,
  UNIQUE INDEX `session_id` (`session_id`)
)
```

接下来，我们需要一个授权表单，用于已登录用户，允许我们为用户和服务创建有效的 API 访问令牌，并将用户重定向到回调地址。

模板可以是一个非常简单的 HTML 模板，可以放置在`/authorize`。因此，我们需要将该路由添加到`api.go`中：

```go
  Routes.HandleFunc("/authorize", ApplicationAuthorize).Methods("POST")
  Routes.HandleFunc("/authorize", ApplicationAuthenticate).Methods("GET")
```

对`POST`的请求将检查确认，如果一切正常，就会传递这个：

```go
<!DOCTYPE html>
<html>
  <head>
    <title>{{.Title}}</title>
  </head>
  <body>
  {{if .Authenticate}}
      <h1>{{.Title}}</h1>
      <form action="{{.Action}}" method="POST">
      <input type="hidden" name="consumer_key" value="{.ConsumerKey}" />
      Log in here
      <div><input name="username" type="text" /></div>
      <div><input name="password" type="password" /></div>
      Allow {{.Application}} to access your data?
      <div><input name="authorize" value="1" type="radio"> Yes</div>
      <div><input name="authorize" value="0" type="radio"> No</div>
      <input type="submit" value="Login" />
  {{end}}
  </form>
  </body>
</html>
```

Go 的模板语言在很大程度上没有逻辑，但并非完全没有逻辑。我们可以使用`if`控制结构将两个页面的 HTML 代码放在一个模板中。为了简洁起见，我们还将创建一个非常简单的`Page`结构，使我们能够构建非常基本的响应页面：

```go
type Page struct {
  Title string
  Authorize bool
  Authenticate bool
  Application string
  Action string
  ConsumerKey string
}
```

目前我们不会维护登录状态，这意味着每个用户都需要在希望授权第三方代表他们进行 API 请求时登录。随着我们的进展，我们将对此进行微调，特别是在使用 Gorilla 工具包中可用的安全会话数据和 cookie 方面。

因此，第一个请求将包括一个带有`consumer_key`值的登录尝试，用于标识应用程序。您也可以在这里包括完整的凭据（nonce 等），但由于这将只允许您的应用程序访问单个用户，这可能是不必要的。

```go
func ApplicationAuthenticate(w http.ResponseWriter, r *http.Request) {
  Authorize := Page{}
  Authorize.Authenticate = true
  Authorize.Title = "Login"
  Authorize.Application = ""
  Authorize.Action = "/authorize"

  tpl := template.Must(template.New("main").ParseFiles("authorize.html"))
  tpl.ExecuteTemplate(w, "authorize.html", Authorize)
}
```

所有请求都将发布到同一个地址，然后我们将验证登录凭据（记住我们`password`包中的`GenerateHash()`），如果它们有效，我们将在`api_connections`中创建连接，然后将用户返回到与 API 凭据关联的回调 URL。

这是一个确定登录凭据是否正确的函数，如果是的话，将使用我们创建的`request_token`值重定向到回调 URL：

```go
func ApplicationAuthorize(w http.ResponseWriter, r *http.Request) {

  username := r.FormValue("username")
  password := r.FormValue("password")
  allow := r.FormValue("authorize")

  var dbPassword string
  var dbSalt string
  var dbUID string

  uerr := Database.QueryRow("SELECT user_password, user_salt, user_id from users where user_nickname=?", username).Scan(&dbPassword, &dbSalt, &dbUID)
  if uerr != nil {

  }
```

通过`user_password`值，`user_salt`值和提交的密码值，我们可以通过使用我们的`GenerateHash()`函数并进行直接比较来验证密码的有效性，因为它们是 Base64 编码的。

```go
  consumerKey := r.FormValue("consumer_key")
  fmt.Println(consumerKey)

  var CallbackURL string
  var appUID string
  err := Database.QueryRow("SELECT user_id,callback_url from api_credentials where consumer_key=?", consumerKey).Scan(&appUID, &CallbackURL)
  if err != nil {

    fmt.Println(err.Error())
    return
  }

  expectedPassword := Password.GenerateHash(dbSalt, password)
  if dbPassword == expectedPassword && allow == "1" {

    requestToken := Pseudoauth.GenerateToken()

    authorizeSQL := "INSERT INTO api_tokens set application_user_id=" + appUID + ", user_id=" + dbUID + ", api_token_key='" + requestToken + "' ON DUPLICATE KEY UPDATE user_id=user_id"

    q, connectErr := Database.Exec(authorizeSQL)
    if connectErr != nil {

    } else {
      fmt.Println(q)
    }
    redirectURL := CallbackURL + "?request_token=" + requestToken
    fmt.Println(redirectURL)
    http.Redirect(w, r, redirectURL, http.StatusAccepted)
```

在将`expectedPassword`与数据库中的密码进行对比后，我们可以判断用户是否成功进行了身份验证。如果是，我们会创建令牌并将用户重定向回回调 URL。然后，其他应用程序有责任存储该令牌以备将来使用。

```go
  } else {

    fmt.Println(dbPassword, expectedPassword)
    http.Redirect(w, r, "/authorize", http.StatusUnauthorized)
  }

}
```

现在我们在第三方端有了令牌，我们可以使用该令牌和我们的`client_token`值进行 API 请求，代表个人用户进行请求，例如创建连接（好友和关注者），发送自动消息或设置状态更新。

# 总结

我们开始本章时，看了一些带来更多 REST 风格选项和功能、更好的安全性以及基于模板的呈现的方法。为了实现这个目标，我们研究了 OAuth 安全模型的基本抽象，这使我们能够使外部客户端在用户的域内工作。

现在，我们的应用程序通过 OAuth 风格的身份验证并通过 HTTPS 进行了安全保护，我们现在可以扩展我们的社交网络应用程序的第三方集成，允许其他开发人员利用和增强我们的服务。

在下一章中，我们将更多地关注我们应用程序的客户端和消费者端，扩展我们的 OAuth 选项，并通过 API 赋予更多的操作，包括创建和删除用户之间的连接，以及创建状态更新。


# 第六章：在 Go 中访问和使用网络服务

在上一章中，我们简要涉及了 OAuth 2.0 过程，并在我们自己的 API 中模拟了这个过程。

我们将通过将我们的用户连接到一些提供 OAuth 2.0 连接的现有普遍服务来进一步探索这个过程，并允许我们的应用程序中的操作在他们的应用程序中创建操作。

一个例子是当您在一个社交网络上发布内容并被给予类似地在另一个社交网络上发布或交叉发布的选项。这正是我们将在这里进行实验的流程类型。

为了真正理解这一点，我们将在我们的应用程序中连接现有用户到另一个使用 OAuth 2.0 的应用程序（如 Facebook、Google+和 LinkedIn），然后在我们的系统和其他系统之间共享资源。

虽然我们无法让这些系统回报，但我们将继续前进，并模拟另一个试图在我们的应用程序基础设施内工作的应用程序。

在本章中，我们将探讨：

+   作为客户端通过 OAuth 2.0 连接到其他服务

+   让我们的用户从我们的应用程序分享信息到另一个网络应用程序

+   允许我们的 API 消费者代表我们的用户发出请求

+   如何确保我们在 OAuth 请求之外建立安全连接

在本章结束时，作为客户端，您应该能够使用 OAuth 将用户帐户连接到其他服务。您还应该能够进行安全请求，创建允许其他服务连接到您的服务的方式，并代表您的用户进行第三方请求。

# 将我们的用户连接到其他服务

为了更好地理解 OAuth 2.0 过程在实践中是如何工作的，让我们连接到一些流行的社交网络，特别是 Facebook 和 Google+。这不仅仅是一个实验项目；这是现代社交网络运作的方式，通过允许服务之间的互联和共享。

这不仅是常见的，而且当您允许不协调的应用程序之间无缝连接时，还往往会引起更高程度的采用。从诸如 Twitter 和 Facebook 之类的服务共享的能力有助于加速它们的流行。

当我们探索客户端方面时，我们将深入了解像我们这样的网络服务如何允许第三方应用程序和供应商在我们的生态系统内工作，并扩大我们应用程序的深度。

要开始这个过程，我们将获取一个现有的 Go OAuth 2.0 客户端。有一些可用的，但要安装 Goauth2，运行`go get`命令如下：

```go
go get code.google.com/p/goauth2/oauth

```

如果我们想将对 OAuth 2.0 服务的访问分隔开，我们可以在我们的导入目录中创建一个独立的文件，让我们创建一个连接到我们的 OAuth 提供者并从中获取相关详细信息。

在这个简短的例子中，我们将连接一个 Facebook 服务，并从 Facebook 请求一个身份验证令牌。之后，我们将返回到我们的网络服务，获取并可能存储令牌：

```go
package main

import (
  "code.google.com/p/goauth2/oauth"
  "fmt"
)
```

这就是我们需要创建一个独立的包，我们可以从其他地方调用。在这种情况下，我们只有一个服务；因此，我们将创建以下变量作为全局变量：

```go
var (
  clientID     = "[Your client ID here]"
  clientSecret = "[Your client secret here]"
  scope        = ""
  redirectURL  = "http://www.mastergoco.com/codepass"
  authURL      = "https://www.facebook.com/dialog/oauth"
  tokenURL     = "https://graph.facebook.com/oauth/access_token"
  requestURL   = "https://graph.facebook.com/me"
  code         = ""
)
```

您将从提供者那里获得这些端点和变量，但它们在这里显然是模糊的。

`redirectURL`变量表示用户登录后您将捕获到的发送令牌的位置。我们将很快仔细研究一般流程。`main`函数编写如下：

```go
func main() {

  oauthConnection := &oauth.Config{
    ClientId:     clientID,
    ClientSecret: clientSecret,
    RedirectURL:  redirectURL,
    Scope:        scope,
    AuthURL:      authURL,
    TokenURL:     tokenURL,
  }

  url := oauthConnection.AuthCodeURL("")
  fmt.Println(url)

}
```

如果我们获取生成的 URL 并直接访问它，它将带我们到类似于我们在上一页上构建的粗略版本的登录页面。这是 Facebook 呈现的身份验证页面：

![将我们的用户连接到其他服务](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/ms-go-websvc/img/1304OS_06_01.jpg)

如果用户（在这种情况下是我）接受此身份验证并点击**好**，页面将重定向回我们的 URL 并传递一个 OAuth 代码，类似于这样：

[`www.mastergoco.com/codepass?code=h9U1_YNL1paTy-IsvQIor6u2jONwtipxqSbFMCo3wzYsSK7BxEVLsJ7ujtoDc`](http://www.mastergoco.com/codepass?code=h9U1_YNL1paTy-IsvQIor6u2jONwtipxqSbFMCo3wzYsSK7BxEVLsJ7ujtoDc)

我们可以将此代码用作将来请求的半永久用户接受代码。如果用户撤销对我们应用程序的访问权限，或者我们选择更改应用程序希望在第三方服务中使用的权限，这将无效。

您可以开始看到一个非常连接的应用程序的可能性，以及为什么第三方身份验证系统，例如通过 Twitter、Facebook、Google+等进行注册和登录的能力，近年来已成为可行和吸引人的前景。

为了将其作为我们 API 的附加部分做任何有用的事情（假设每个社交网络的服务条款允许），我们需要做三件事：

首先，我们需要使其不再仅限于一个服务。为此，我们将创建一个`OauthService`结构的映射：

```go
type OauthService struct {
  clientID string
  clientSecret string
  scope string
  redirectURL string
  authURL string
  tokenURL string
  requestURL string
  code string
}
```

然后，我们可以根据需要添加这个：

```go
  OauthServices := map[string] OauthService{}

  OauthServices["facebook"] = OauthService {
    clientID:  "***",
    clientSecret: "***",
    scope: "",
    redirectURL: "http://www.mastergoco.com/connect/facebook",
    authURL: "https://www.facebook.com/dialog/oauth",
    tokenURL: "https://graph.facebook.com/oauth/access_token",
    requestURL: "https://graph.facebook.com/me",
    code: "",
  }
  OauthServices["google"] = OauthService {
    clientID:  "***.apps.googleusercontent.com",
    clientSecret: "***",
    scope: "https://www.googleapis.com/auth/plus.login",
    redirectURL: "http://www.mastergoco.com/connect/google",
    authURL: "https://accounts.google.com/o/oauth2/auth",
    tokenURL: "https://accounts.google.com/o/oauth2/token",
    requestURL: "https://graph.facebook.com/me",
    code: "",
  }
```

接下来，我们需要做的是将其变成一个实际的重定向，而不是将代码输出到我们的控制台。考虑到这一点，现在是将此代码集成到`api.go`文件中的时候了。这将允许我们注册的用户将他们在我们社交网络上的用户信息连接到其他人，以便他们可以在我们的应用程序上更广泛地广播他们的活动。这将带我们到我们的下一个最后一步，即接受每个相应的网络服务返回的代码：

```go
func Init() {
  Routes = mux.NewRouter()
  Routes.HandleFunc("/interface", APIInterface).Methods("GET", "POST", "PUT", "UPDATE")
  Routes.HandleFunc("/api/users", UserCreate).Methods("POST")
  Routes.HandleFunc("/api/users", UsersRetrieve).Methods("GET")
  Routes.HandleFunc("/api/users/{id:[0-9]+}", UsersUpdate).Methods("PUT")
  Routes.HandleFunc("/api/users", UsersInfo).Methods("OPTIONS")
  Routes.HandleFunc("/authorize", ApplicationAuthorize).Methods("POST")
  Routes.HandleFunc("/authorize", ApplicationAuthenticate).Methods("GET")
  Routes.HandleFunc("/authorize/{service:[a-z]+}", ServiceAuthorize).Methods("GET")
  Routes.HandleFunc("/connect/{service:[a-z]+}", ServiceConnect).Methods("GET")
  Routes.HandleFunc("/oauth/token", CheckCredentials).Methods("POST")
}
```

我们将在`Init()`函数中添加两个端点路由；一个允许服务进行授权（即，发送到该站点的 OAuth 身份验证），另一个允许我们保留以下结果信息：

```go
func ServiceAuthorize(w http.ResponseWriter, r *http.Request) {

  params := mux.Vars(r)
  service := params["service"]
  redURL := OauthServices.GetAccessTokenURL(service, "")
  http.Redirect(w, r, redURL, http.StatusFound)

}
```

在这里，我们将建立一个 Google+认证通道。毋庸置疑，但不要忘记用您的值替换您的`clientID`，`clientSecret`和`redirectURL`变量：

```go
OauthServices["google"] = OauthService {
  clientID:  "***.apps.googleusercontent.com",
  clientSecret: "***",
  scope: "https://www.googleapis.com/auth/plus.login",
  redirectURL: "http://www.mastergoco.com/connect/google",
  authURL: "https://accounts.google.com/o/oauth2/auth",
  tokenURL: "https://accounts.google.com/o/oauth2/token",
  requestURL: "https://accounts.google.com",
  code: "",
}
```

通过访问`http://localhost/authorize/google`，我们将被踢到 Google+的中间身份验证页面。以下是一个基本上与我们之前看到的 Facebook 身份验证基本相似的示例：

![将我们的用户连接到其他服务](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/ms-go-websvc/img/1304OS_06_02.jpg)

当用户点击**接受**时，我们将返回到我们的重定向 URL，并获得我们正在寻找的代码。

### 提示

对于大多数 OAuth 提供商，将从仪表板提供客户端 ID 和客户端密钥。

然而，在 Google+上，您将从他们的开发者控制台中检索您的客户端 ID，这允许您注册新应用程序并请求访问不同的服务。但他们并不公开提供客户端密钥，因此您需要下载一个包含不仅密钥，还包括其他相关数据的 JSON 文件，这些数据可能是您访问服务所需的格式类似于这样：

`{"web":{"auth_uri":"https://accounts.google.com/o/oauth2/auth","client_secret":"***","token_uri":"https://accounts.google.com/o/oauth2/token","client_email":"***@developer.gserviceaccount.com","client_x509_cert_url":"https://www.googleapis.com/robot/v1/metadata/x509/***@developer.gserviceaccount.com","client_id":"***.apps.googleusercontent.com","auth_provider_x509_cert_url":"https://www.googleapis.com/oauth2/v1/certs"}}`

您可以直接从此文件中获取相关详细信息。

当然，为了确保我们知道是谁发出了请求以及如何存储它，我们需要一些状态。

## 使用 Web 服务保存状态

在单个 Web 请求中有很多保存状态的方法。然而，在这种情况下，当我们的客户端发出一个请求，然后被重定向到另一个 URL，然后回到我们的时候，情况往往会变得更加复杂。

我们可以在重定向的 URL 中传递关于用户的一些信息，例如，[`mastergoco.com/connect/google?uid=1`](http://mastergoco.com/connect/google?uid=1)；但这有点不够优雅，并且存在一个小的安全漏洞，中间人攻击者可以了解用户和外部 OAuth 代码。

这里的风险很小，但确实存在；因此，我们应该寻找其他地方。幸运的是，Gorilla 还提供了一个用于安全会话的不错的库。每当我们验证了用户或客户端的身份并将信息存储在 cookie 存储中时，我们可以使用这些。

首先，让我们创建一个`sessions`表：

```go
CREATE TABLE IF NOT EXISTS `sessions` (
  `session_id` varchar(128) NOT NULL,
  `user_id` int(10) NOT NULL,
  `session_start_time` int(11) NOT NULL,
  `session_update_time` int(11) NOT NULL,
  UNIQUE KEY `session_id` (`session_id`)
)
```

接下来，包括`sessions`包：

```go
go get github.com/gorilla/sessions
```

然后，将其移入我们的`api.go`文件的`import`部分：

```go
import (
  ...
  "github.com/gorilla/mux"
  "github.com/gorilla/sessions"

```

现在我们还没有对服务进行身份验证，所以我们将在我们的`ApplicationAuthorize`(`GET`)处理程序上强制执行：

```go
func ServiceAuthorize(w http.ResponseWriter, r *http.Request) {

  params := mux.Vars(r)
  service := params["service"]

  loggedIn := CheckLogin()
 if loggedIn == false {
 redirect = url.QueryEscape("/authorize/" + service)
 http.Redirect(w, r, "/authorize?redirect="+redirect, http.StatusUnauthorized)
 return
 }

  redURL := OauthServices.GetAccessTokenURL(service, "")
  http.Redirect(w, r, redURL, http.StatusFound)

}
```

现在，如果用户尝试连接到一个服务，我们将检查是否存在登录，如果不存在，将用户重定向到我们的登录页面。以下是检查这一点的测试代码：

```go
func CheckLogin(w http.ResponseWriter, r *http.Request) bool {
  cookieSession, err := r.Cookie("sessionid")
  if err != nil {
    fmt.Println("no such cookie")
    Session.Create()
    fmt.Println(Session.ID)
    currTime := time.Now()
    Session.Expire = currTime.Local()
    Session.Expire.Add(time.Hour)

    return false
  } else {
    fmt.Println("found cookki")
    tmpSession := UserSession{UID: 0}
    loggedIn := Database.QueryRow("select user_id from sessions where session_id=?", cookieSession).Scan(&tmpSession.UID)
    if loggedIn != nil {
      return false
    } else {
      if tmpSession.UID == 0 {
        return false
      } else {

        return true
      }
    }
  }
}
```

这是一个相当标准的测试，查找一个 cookie。如果不存在，创建一个`Session`结构并保存一个 cookie，并返回 false。否则，如果在成功登录后 cookie 已保存在数据库中，则返回 true。

这也依赖于一个新的全局变量，`Session`，它是新的结构类型`UserSession`：

```go
var Database *sql.DB
var Routes *mux.Router
var Format string
type UserSession struct {
 ID              string
 GorillaSesssion *sessions.Session
 UID             int
 Expire          time.Time
}

var Session UserSession

func (us *UserSession) Create() {
 us.ID = Password.GenerateSessionID(32)
}
```

目前，我们的登录页面存在问题，这只是为了允许第三方应用程序允许我们的用户授权其使用。我们可以通过简单地根据 URL 中是否看到`consumer_key`或`redirect_url`来设置`auth_type`变量来解决这个问题。在我们的`authorize.html`文件中，进行以下更改：

```go
<input type="hidden" name="auth_type" value="{{.PageType}}" />
```

在我们的`ApplicationAuthenticate()`处理程序中，进行以下更改：

```go
  if len(r.URL.Query()["consumer_key"]) > 0 {
    Authorize.ConsumerKey = r.URL.Query()["consumer_key"][0]
  } else {
    Authorize.ConsumerKey = ""
  }
  if len(r.URL.Query()["redirect"]) > 0 {
    Authorize.Redirect = r.URL.Query()["redirect"][0]
  } else {
    Authorize.Redirect = ""
  }

if Authorize.ConsumerKey == "" && Authorize.Redirect != "" {
  Authorize.PageType = "user"
} else {
  Authorize.PageType = "consumer"
}
```

这还需要修改我们的`Page{}`结构：

```go
type Page struct {
  Title        string
  Authorize    bool
  Authenticate bool
  Application  string
  Action       string
  ConsumerKey  string
  Redirect     string
  PageType     string
}
```

如果我们收到来自`Page`类型用户的授权请求，我们将知道这只是一个登录尝试。如果来自客户端，我们将知道这是另一个应用程序尝试为我们的用户发出请求。

在前一种情况下，我们将利用重定向 URL 在成功认证后将用户带回来，假设登录成功。

Gorilla 提供了一个闪存消息；这本质上是一个一次性的会话变量，一旦被读取就会被删除。你可能能看到这在这里是有价值的。我们将在重定向到我们的连接服务之前设置闪存消息，然后在返回时读取该值，此时它将被处理掉。在我们的`ApplicationAuthorize()`处理程序函数中，我们区分客户端和用户登录。如果用户登录，我们将设置一个可以检索的闪存变量。

```go
  if dbPassword == expectedPassword && allow == "1" && authType == "client" {

    requestToken := Pseudoauth.GenerateToken()

    authorizeSQL := "INSERT INTO api_tokens set application_user_id=" + appUID + ", user_id=" + dbUID + ", api_token_key='" + requestToken + "' ON DUPLICATE KEY UPDATE user_id=user_id"

    q, connectErr := Database.Exec(authorizeSQL)
    if connectErr != nil {

        } else {
      fmt.Println(q)
    }
    redirectURL := CallbackURL + "?request_token=" + requestToken
    fmt.Println(redirectURL)
    http.Redirect(w, r, redirectURL, http.StatusAccepted)

  }else if dbPassword == expectedPassword && authType == "user" {
    UserSession, _ = store.Get(r, "service-session")
        UserSession.AddFlash(dbUID)
    http.Redirect(w, r, redirect, http.StatusAccepted)
  }
```

但这样仅仅不能保持一个持久的会话，所以我们现在要整合这个。当在`ApplicationAuthorize()`方法中发生成功的登录时，我们将在我们的数据库中保存会话，并允许一些持久连接给我们的用户。

# 使用其他 OAuth 服务的数据

成功连接到另一个服务（或多个服务，取决于您引入了哪些 OAuth 提供程序），我们现在可以相互交叉使用多个服务。

例如，在我们的社交网络中发布状态更新也可能需要在 Facebook 上发布状态更新。

为此，让我们首先设置一个状态表：

```go
CREATE TABLE `users_status` (
  `users_status_id` INT NOT NULL AUTO_INCREMENT,
  `user_id` INT(10) UNSIGNED NOT NULL,
  `user_status_timestamp` INT(11) NOT NULL,
  `user_status_text` TEXT NOT NULL,
  PRIMARY KEY (`users_status_id`),
  CONSTRAINT `status_users` FOREIGN KEY (`user_id`) REFERENCES `users` (`user_id`) ON UPDATE NO ACTION ON DELETE NO ACTION
)
```

我们的状态将包括用户的信息、时间戳和状态消息的文本。现在还没有太复杂的东西！

接下来，我们需要为创建、读取、更新和删除状态添加 API 端点。因此，在我们的`api.go`文件中，让我们添加这些：

```go
func Init() {
  Routes = mux.NewRouter()
  Routes.HandleFunc("/interface", APIInterface).Methods("GET", "POST", "PUT", "UPDATE")
  Routes.HandleFunc("/api/users", UserCreate).Methods("POST")
  Routes.HandleFunc("/api/users", UsersRetrieve).Methods("GET")
  Routes.HandleFunc("/api/users/{id:[0-9]+}", UsersUpdate).Methods("PUT")
  Routes.HandleFunc("/api/users", UsersInfo).Methods("OPTIONS")
 Routes.HandleFunc("/api/statuses",StatusCreate).Methods("POST")
 Routes.HandleFunc("/api/statuses",StatusRetrieve).Methods("GET")
 Routes.HandleFunc("/api/statuses/{id:[0-9]+}",StatusUpdate).Methods("PUT")
 Routes.HandleFunc("/api/statuses/{id:[0-9]+}",StatusDelete).Methods("DELETE")
  Routes.HandleFunc("/authorize", ApplicationAuthorize).Methods("POST")
  Routes.HandleFunc("/authorize", ApplicationAuthenticate).Methods("GET")
  Routes.HandleFunc("/authorize/{service:[a-z]+}", ServiceAuthorize).Methods("GET")
  Routes.HandleFunc("/connect/{service:[a-z]+}", ServiceConnect).Methods("GET")
  Routes.HandleFunc("/oauth/token", CheckCredentials).Methods("POST")
}
```

现在，我们将为`PUT`/`Update`和`DELETE`方法创建一些虚拟处理程序：

```go
func StatusDelete(w http.ResponseWriter, r *http.Request) {
  fmt.Fprintln(w, "Nothing to see here")
}

func StatusUpdate(w http.ResponseWriter, r *http.Request) {
  fmt.Fprintln(w, "Coming soon to an API near you!")
}
```

请记住，如果没有这些，我们将无法进行测试，同时还会收到编译器错误。在下面的代码中，您将找到`StatusCreate`方法，该方法允许我们为已授予我们令牌的用户发出请求。由于我们已经有了一个用户，让我们创建一个状态：

```go
func StatusCreate(w http.ResponseWriter, r *http.Request) {

  Response := CreateResponse{}
  UserID := r.FormValue("user")
  Status := r.FormValue("status")
  Token := r.FormValue("token")
  ConsumerKey := r.FormValue("consumer_key")

  vUID := ValidateUserRequest(ConsumerKey,Token)
```

我们将使用密钥和令牌的测试来获取一个有效的用户，该用户被允许进行这些类型的请求：

```go
  if vUID != UserID {
    Response.Error = "Invalid user"
    http.Error(w, Response.Error, 401)
  } else  {
    _,inErr := Database.Exec("INSERT INTO users_status set user_status_text=?, user_id=?", Status, UserID)
    if inErr != nil {
      fmt.Println(inErr.Error())
      Response.Error = "Error creating status"
      http.Error(w, Response.Error, 500)
      fmt.Fprintln(w, Response)
    } else {
      Response.Error = "Status created"
      fmt.Fprintln(w, Response)
    }
  }

}
```

如果用户通过密钥和令牌确认为有效，则将创建状态。

![使用其他 OAuth 服务的数据](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/ms-go-websvc/img/1304OS_06_03.jpg)

通过对 OAuth 的一般工作原理有所了解，并且在我们的 API 中已经有了一个近似的、低门槛版本，我们可以开始允许外部服务请求访问我们的用户帐户，以代表个别用户在我们的服务中执行。

我们在上一章中简要提到了这一点，但让我们用它做一些有用的事情。

我们将允许来自另一个域的另一个应用程序向我们的 API 发出请求，以为我们的用户创建一个状态更新。如果您使用单独的 HTML 界面，类似于我们在早期章节中使用的界面或其他内容，您可以避免返回跨域资源共享头部时遇到的跨域策略问题。

为此，我们可以在我们的`api.go`文件顶部创建一个允许访问我们的 API 的域的切片，并返回`Access-Control-Allow-Origin`头部。

```go
var PermittedDomains []string
```

然后，我们可以在我们的`api.go`文件的`Init()`函数中添加这些：

```go
func Init(allowedDomains []string) {
 for _, domain := range allowedDomains {
 PermittedDomains = append(PermittedDomains,domain)
 }

Routes = mux.NewRouter()
Routes.HandleFunc("/interface", APIInterface).Methods("GET", "POST", "PUT", "UPDATE")
```

然后，我们可以从我们当前的`v1`版本的 API 中调用它们。因此，在`v1.go`中，在调用`api.Init()`时，我们需要调用域列表：

```go
func API() {
  api.Init([]string{"http://www.example.com"})
```

最后，在任何处理程序中，您希望遵守这些域规则，都可以通过循环遍历这些域并设置相关的头部来添加：

```go
func UserCreate(w http.ResponseWriter, r *http.Request) {

...
 for _,domain := range PermittedDomains {
 fmt.Println ("allowing",domain)
 w.Header().Set("Access-Control-Allow-Origin", domain)
  }
```

首先，让我们通过上述任一方法创建一个新用户 Bill Johnson。在这种情况下，我们将回到 Postman，直接向 API 发送请求：

![使用其他 OAuth 服务的数据](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/ms-go-websvc/img/1304OS_06_04.jpg)

创建新用户后，我们可以按照伪 OAuth 流程，允许 Bill Johnson 访问我们的应用程序并生成状态。

首先，我们使用我们的`consumer_key`值将用户传递给`/authorize`。在成功登录并同意允许应用程序访问用户数据后，我们将创建一个`token_key`值并将其传递到重定向 URL。

有了这个密钥，我们可以像以前一样通过向`/api/statuses`端点发布我们的密钥、用户和状态来以编程方式发出状态请求。

# 在 Go 中作为客户端进行安全连接

您可能会遇到这样的情况，即不得不自行进行安全请求，而不是使用 OAuth 客户端。通常，Go 中的`http`包将确保包含的证书是有效的，并且会阻止您进行测试。

```go
package main

import
(
  "net/http"
  "fmt"
)

const (
  URL = "https://localhost/api/users"
)

func main() {

  _, err := http.Get(URL)
  if err != nil {

    fmt.Println(err.Error())
  }

}
type Client struct {
        // Transport specifies the mechanism by which individual
        // HTTP requests are made.
        // If nil, DefaultTransport is used.
        Transport RoundTripper
```

这使我们能够注入自定义的`Transport`客户端，从而覆盖错误处理；在通过浏览器与我们（或任何）API 的交互中，这不建议超出测试，并且可能会引入来自不受信任来源的安全问题。

```go
package main

import
(
  "crypto/tls"
  "net/http"
  "fmt"
)

const (
  URL = "https://localhost/api/users"
)

func main() {

  customTransport := &http.Transport{ TLSClientConfig: &tls.Config{InsecureSkipVerify: true} }
  customClient := &http.Client{ Transport: customTransport }
  response, err := customClient.Get(URL)
  if err != nil {
    fmt.Println(err.Error())
  } else {
    fmt.Println(response)
  }

}
```

然后，我们会得到一个有效的响应（带有头部，在结构体中）：

```go
  &{200 OK 200 HTTP/1.1 1 1 map[Link:[<http://localhost:8080/api/users?start= ; rel="next"] Pragma:[no
  -cache] Date:[Tue, 16 Sep 2014 01:51:50 GMT] Content-Length:[256] Content-Type:[text/plain; charset=
  utf-8] Cache-Control:[no-cache]] 0xc084006800 256 [] false map[] 0xc084021dd0}

```

这只是在测试中最好使用的东西，因为当忽略证书时，连接的安全性显然可能是一个可疑的问题。

# 摘要

在上一章中，我们已经开始了第三方集成应用程序的初始步骤。在本章中，我们稍微看了一下客户端，以了解如何将一个干净简单的流程整合进去。

我们使用其他 OAuth 2.0 服务对用户进行身份验证，这使我们能够与其他社交网络共享信息。这是使社交网络对开发人员友好的基础。允许其他服务使用我们用户和其他用户的数据也为用户创造了更沉浸式的体验。

在下一章中，我们将探讨将 Go 与 Web 服务器和缓存系统集成，构建一个高性能和可扩展架构的平台。

在这个过程中，我们还将推动 API 的功能，这将允许更多的连接和功能。
