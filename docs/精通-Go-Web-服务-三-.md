# 精通 Go Web 服务（三）

> 原文：[`zh.annas-archive.org/md5/2D0D1F51B3626D3F3DD6A0D48080FBC1`](https://zh.annas-archive.org/md5/2D0D1F51B3626D3F3DD6A0D48080FBC1)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第七章：与其他 Web 技术合作

在上一章中，我们看了我们的 Web 服务如何通过 API 或 OAuth 集成与其他 Web 服务良好地配合和集成。

继续这个思路，我们将在开发我们的社交网络服务周围的技术时停下来，看看我们如何还可以独立于其他服务集成其他技术。

很少有应用程序仅在一个语言、一个服务器类型或甚至一个代码集上运行。通常有多种语言、操作系统和多个进程的指定目的。您可能在 Ubuntu 上使用 Go 运行 Web 服务器，这是运行 PostgreSQL 的数据库服务器。

在本章中，我们将讨论以下主题：

+   通过反向代理来提供我们的 Web 流量，以利用成熟的 HTTP 产品提供的更高级功能

+   连接到 NoSQL 或键/值数据存储，我们可以将其用作我们的核心数据提供程序，或者用它来进行辅助工作，如缓存

+   为我们的 API 启用会话，并允许客户和用户在不再指定凭据的情况下发出请求

+   允许用户通过添加其他用户到他们的网络来互相连接

当我们完成所有这些时，您应该对如何将您的 Web 服务与不同于 MySQL 的 NoSQL 和数据库解决方案连接有所了解。我们将在以后利用数据存储来在第十章*最大化性能*中提供性能提升。

您还希望熟悉一些处理 API 的开箱即用解决方案，能够将中间件引入您的 Web 服务，并能够利用消息传递在不和谐或分离的系统之间进行通信。

让我们开始看看我们可以如何连接到其他 Web 服务器，以将一些额外的功能和故障处理引入我们目前仅由 Go 的`net/http`包提供服务的服务中。

# 通过反向代理进行服务

Go 内部 HTTP 服务器最突出的功能之一可能也引发了立即的怀疑回应：如果使用 Go 轻松启动应用程序服务，那么它是否与 Web 服务相关的功能齐全呢？

这是一个可以理解的问题，特别是考虑到 Go 与解释脚本语言的相似性。毕竟，Ruby on Rails、Python、NodeJS，甚至 PHP 都带有开箱即用的简单 Web 服务器。由于它们在功能集、安全更新等方面的限制，很少有人建议将这些简单服务器用作生产级服务器。

话虽如此，Go 的`http`包对于许多生产级项目来说已经足够强大；然而，通过将 Go 与具有更成熟的 Web 服务器的反向代理集成，您可能不仅会发现一些缺失的功能，还会发现一些可靠性。

“反向代理”是一个错误的名称，或者至少是一种笨拙的方式来说明一个内部的、传入的代理，它将客户端请求不透明地通过一个系统路由到另一个服务器，无论是在同一台机器还是网络中。事实上，出于这个原因，它通常被简单地称为网关。

潜在的优势是多方面的。这些包括能够使用一个众所周知、得到充分支持、功能齐全的 Web 服务器（而不仅仅是在 Go 中构建自己的构建块）、拥有庞大的社区支持，以及拥有大量预构建的可用插件和工具。

是否有必要或有利，或者投资回报率如何，这取决于个人偏好和所处情况，但通常可以帮助记录和调试 Web 应用程序。

# 使用 Go 与 Apache

Apache 的 Web 服务器是 Web 服务器中的元老。自 1996 年首次发布以来，它迅速成为了一支坚实的力量，截至 2009 年，它已为超过 1 亿个网站提供服务。自诞生后不久，它一直是世界上最受欢迎的 Web 服务器，尽管一些估计将 Nginx 列为新的第一名（我们将在稍后谈一些关于这个的更多内容）。

将 Go 放在 Apache 后面非常容易，但有一个注意事项；Apache 默认安装时是一个阻塞的、非并发的 Web 服务器。这与 Go 不同，Go 将请求划分为 goroutines 或 NodeJS 甚至 Nginx。其中一些绑定到线程，一些没有。Go 显然没有绑定，这最终影响了服务器的性能。

首先，让我们在 Go 中创建一个简单的`hello world` Web 应用程序，我们将其称为`proxy-me.go`：

```go
package main

import (
        "fmt"
        "log"
        "net/http"
)

func ProxyMe(w http.ResponseWriter, r *http.Request) {

        fmt.Fprintln(w, "hello world")
}

func main() {
        http.HandleFunc("/hello", ProxyMe)
        log.Fatal(http.ListenAndServe(":8080", nil))
}
```

这里没有太复杂的东西。我们在端口 8080 上监听，并且有一个非常简单的路由`/hello`，它只是说`hello world`。要让 Apache 作为透传的反向代理提供此服务，我们编辑我们的默认服务器配置如下：

```go
ProxyRequests Off
ProxyPreserveHost On

<VirtualHost *:80>

        ServerAdmin webmaster@localhost
        DocumentRoot /var/www/html

        ProxyPass /  http://localhost:8080/
        ProxyPassReverse /  http://localhost:8080/

        ErrorLog ${APACHE_LOG_DIR}/error.log
        CustomLog ${APACHE_LOG_DIR}/access.log combined

</VirtualHost>
```

### 提示

默认服务器配置通常存储在 Linux 的`/etc/apache2/sites-enabled/`和 Windows 的`[驱动器]:/[apache 安装目录]/conf/`中。

我们可以通过查看对`/hello`路由的请求的标头来验证我们看到的页面是由 Apache 提供而不是直接通过 Go 提供的。

当我们这样做时，我们不仅会看到服务器是**Apache/2.4.7**，还会看到我们传递的自定义标头。通常，我们会为其他目的使用**X-Forwarded-For**标头，但这足够类似，可以用作演示，如下面的屏幕截图所示：

![使用 Go 与 Apache](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/ms-go-websvc/img/1304OS_07_01.jpg)

# Go 和 NGINX 作为反向代理

尽管 Apache 是 Web 服务器的老大哥，但近年来，它在某些方面的受欢迎程度已被 Nginx 超越。

Nginx 最初是作为解决 C10K 问题的方法编写的——提供 1 万个并发连接。这并不是一个不可能的任务，但以前需要昂贵的解决方案来解决它。

由于 Apache 默认会生成新的线程和/或进程来处理新请求，它经常在重负载下挣扎。

另一方面，Nginx 设计为采用异步事件模型，不会为每个请求生成新进程。在许多方面，这使得它与 Go 在 HTTP 包中的并发工作方式互补。

与 Apache 一样，将 Nginx 放在 Go 之后的好处如下：

+   它有访问和错误日志。这是您需要使用 Go 中的日志包构建的内容。虽然这很容易做到，但这是一个更少的麻烦。

+   它具有非常快的静态文件服务。事实上，Apache 用户经常使用 Nginx 专门用于提供静态文件。

+   它具有 SPDY 支持。SPDY 是一种新的、有些实验性的协议，它操纵 HTTP 协议引入了一些速度和安全功能。有一些尝试实现 Go 的 HTTP 和 TLS 包库用于 SPDY，但还没有在 net/HTTP 包中构建出来。

+   它具有内置的缓存选项和流行缓存引擎的钩子。

+   它具有将一些请求委托给其他进程的灵活性。

我们将在第十章*最大化性能*中直接讨论在 Nginx 和 Go 中使用 SPDY。

值得注意的是，异步、非阻塞和并发的 HTTP 服务几乎总是受到技术外部因素的限制，比如网络延迟、文件和数据库阻塞等。

考虑到这一点，让我们来看一下快速将 Nginx 作为反向代理而不是 Go 的设置。

Nginx 允许通过简单修改默认配置文件进行透传。Nginx 目前还没有对 Windows 的原生支持；因此，在大多数*nix 解决方案中，可以通过导航到`/etc/nginx/sites-enabled`找到该文件。

### 提示

或者，您可以通过在`/etc/nginx/nginx.conf`中的`.conf`文件中进行更改来全局代理。

让我们看一个样本 Nginx 配置操作，让我们代理我们的服务器。

```go
server {
        listen 80 default_server;
        listen [::]:80 default_server ipv6only=on;
        root /usr/share/nginx/html;
        index index.html index.htm;

        # Make site accessible from http://localhost/
        server_name localhost;

        location / {
                proxy_set_header X-Real-IP $remote_addr;
                proxy_set_header X-Forwarded-For $remote_addr;
                proxy_set_header Host $host;
                proxy_pass http://127.0.0.1:8080;
                #       try_files $uri $uri/ =404;

        }
```

有了这个修改，您可以通过运行`/etc/init.d/nginx`来启动 Nginx，然后通过`go run proxy-me.go`来启动 Go 服务器。

如果我们访问本地主机实现，我们将看到与上次请求的标头非常相似，但代理服务器是 Nginx 而不是 Apache：

![Go 和 NGINX 作为反向代理](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/ms-go-websvc/img/1304OS_07_02.jpg)

# 为 API 启用会话

大多数情况下，我们会为机器暴露 API。换句话说，我们期望一些应用程序将直接与我们的网络服务进行交互，而不是用户。

然而，情况并非总是如此。有时，用户直接或通过 JavaScript 与 JSONP 和/或 AJAX 请求等方式使用浏览器与 API 进行交互。

事实上，Web 2.0 美学的基本原则在于为用户提供无缝的、类似桌面的体验。这在今天已经实现，并包括许多处理表示层的 JavaScript MVC 框架。我们将在下一章中解决这个问题。

Web 2.0 这个术语已经基本被取代，现在通常被称为**单页应用**或**SPA**。曾经是一种混合了服务器生成（或提供）HTML 页面和一些通过 XML 和 JavaScript 构建或更新的部分，现在已经让位给了构建整个客户端应用程序的 JavaScript 框架。

这些几乎都依赖于底层 API，通常通过 HTTP/HTTPS 进行无状态请求访问，尽管一些较新的模型使用 Web 套接字来实现服务器和表示模型之间的实时通信。这也是我们将在下一章中看到的内容。

无论模型如何，您都不能简单地将此 API 暴露给世界而不进行一些身份验证。例如，如果 API 可以在没有身份验证的情况下从`/admin`请求访问，那么它很可能也可以从外部访问。您不能依赖用户的信息，比如 HTTP 引用者。

### 提示

语法学家可能会注意到上一句中引用者的拼写错误。然而，这不是一个打字错误。在最初的 HTTP 请求评论提案中，该术语的拼写中没有双* r*，自那时以来它基本上一直保持不变。

然而，当用户在每个页面上进行多次请求时，依赖每个 OAuth 请求就有些过度了。您可以在本地存储或 cookie 中缓存令牌，但前者的浏览器支持仍然有限，后者会限制令牌的撤销。

这方面的一个传统而简单的解决方案是允许基于 cookie 的身份验证会话。您可能仍然希望为主应用程序之外的访问开放 API，以便可以通过 API 密钥或 OAuth 进行身份验证，但它还应该允许用户直接使用客户端工具与其进行交互，以提供清晰的 SPA 体验。

## RESTful 设计中的会话

值得注意的是，因为会话通常强制执行某种状态，它们并不被认为是 RESTful 设计的一部分。然而，也可以说会话仅用于身份验证而不是状态。换句话说，身份验证和会话 cookie 可以被单独用作验证身份的方法。

当然，您也可以通过在每个安全请求中传递用户名和密码来实现这一点。这本身并不是一种不安全的做法，但这意味着用户需要在每个请求中提供这些信息，或者这些信息需要被本地存储。这就是存储在 cookie 中的会话试图解决的问题。

正如前面提到的，这永远不会适用于第三方应用程序，因为它们大部分需要某种易于撤销的密钥来工作，很少有用户名和密码（尽管我们的用户名和密码与用户绑定，所以从技术上讲也有）。

最简单的方法是允许用户名和密码直接进入 URL 请求，有时你可能会看到这种情况。这里的风险是，如果用户意外地分享了完整的 URL，数据将会被泄露。事实上，这在新手 GitHub 用户中经常发生，因为可能会自动推送包含 GitHub 密码的配置文件。

为了减少这种风险，我们应该要求用户名和密码通过标头字段传递，尽管它仍然是明文的。假设一个可靠的 TSL（或 SSL）选项已经就位，请求标头中的明文并不是一个固有的问题，但如果应用程序随时可以切换到（或被访问到）不安全的协议，这可能会成为一个问题。这是一个有时间限制的令牌系统试图解决的问题。

我们可以将会话数据存储在任何地方。我们的应用目前使用的是 MySQL，但会话数据将经常被读取。因此，在数据库中存储几乎没有关系信息的信息并不理想。

记住，我们将存储一个活跃用户，他们会话的开始时间，最后更新时间（每次请求都会更改），以及他们在应用程序中的位置。我们的应用程序可以使用这些信息来告诉用户他们的朋友目前在我们的社交网络中做什么。

考虑到这些条件，依赖我们的主要数据存储并不是一个理想的解决方案。我们想要的是更加短暂、更快速、更具并发性的东西，可以在不影响我们的数据存储的情况下处理许多连续的请求。

如今处理会话的最流行解决方案之一是将关系数据库转移到包括文档和列存储或键值数据存储在内的 NoSQL 解决方案中。

# 在 Go 中使用 NoSQL

很久以前，数据存储和检索的世界几乎完全被限制在关系数据库的领域。在我们的应用程序中，我们使用的是 MySQL，主要是因为它一直是快速应用程序的通用语言，而且 SQL 在类似的数据库（如微软的 SQL Server、PostgreSQL、Oracle 等）之间相对容易转换。

然而，近年来，对 NoSQL 进行了大力推动。更准确地说，推动的是依赖于典型关系数据库结构和模式较少的数据存储解决方案，而更多地依赖于高性能的键值存储。

键值存储正是任何使用关联数组、哈希和映射（在 Go 中）的人所期望的，即与一个键相关联的一些任意数据。许多这些解决方案非常快，因为它们缺乏索引关系、减少了锁定，并且不太强调一致性。事实上，许多解决方案在开箱即用时不保证 ACID 性（但一些提供了可选的使用方法）。

### 注意

**ACID**指的是开发人员在数据库应用程序中期望的属性。在任何给定的 NoSQL 或键值数据存储解决方案中，这些属性可能有一些或全部缺失或是可选参数。**ACID**这个术语可以详细解释如下：

+   **原子性**：这表示事务的所有部分必须成功才能成功

+   **一致性**：这指的是事务完成之前，数据库在事务开始时的状态不会发生变化

+   **隔离性**：这指的是防止访问处于事务状态的数据的表或行锁定机制

+   **持久性**：这确保了成功的事务可以并且将在系统或应用程序故障时幸存

NoSQL 解决方案可以用于许多不同的事情。它们可以直接替代 SQL 服务器。它们可以用一些需要较少一致性的数据来补充数据。它们可以作为快速可访问的、自动过期的缓存结构。我们稍后会看到这一点。

如果您选择在应用程序中引入 NoSQL 解决方案，请考虑这可能给您的应用程序带来的潜在影响。例如，您可以考虑 ACID 属性的潜在权衡是否会被新解决方案提供的性能提升和水平可扩展性所抵消。

虽然几乎所有的 SQL 或传统关系数据库解决方案都与 Go 的`database/sql`包有一些集成，但对于需要某种包装器的键值存储来说，情况并非总是如此。

现在，我们将简要介绍一些最受欢迎的键值存储解决方案，当我们在下一节讨论缓存时，我们将回来使用 NoSQL 作为基本缓存解决方案。

### 注意

尽管最近有所复苏，但 NoSQL 并不是一个新概念。根据定义，任何避开 SQL 或关系数据库概念的东西都可以称为 NoSQL，自上世纪 60 年代以来就有数十种这样的解决方案。可能需要提到的是，我们不会花时间在这些解决方案上——比如 Ken Thompson 的 DBM 或 BerkeleyDB——而是更现代的故事。

在我们开始探索各种 NoSQL 解决方案来处理会话之前，让我们通过提供替代的用户名/密码身份验证来在我们的应用程序中启用它们。

您可能还记得当我们启用了第三方身份验证代理时，我们在`CheckLogin()`函数中启用了会话并将它们存储在我们的 MySQL 数据库中。这个函数只会在对`ApplicationAuthorize`函数的`POST`请求的响应中调用。我们将扩展到更多的方法。首先，让我们创建一个新函数叫做`CheckSession()`，如果它不存在的话，它将验证 cookie 的会话 ID，然后根据我们的会话存储进行验证：

```go
func CheckSession(w http.ResponseWriter, r *http.Request) bool {

}
```

您可能还记得我们在`api.go`中有一个基本的会话结构和一个方法。我们也将把这些移到会话中：

```go
var Session UserSession
```

这个命令变成了以下内容：

```go
var Session Sessions.UserSession
```

为了创建我们的会话存储，我们将在 API 的子目录/会话中创建一个名为`sessions.go`的新包。这是一个没有任何 NoSQL 特定方法的骨架：

```go
package SessionManager

import
(
  "log"
  "time"
  "github.com/gorilla/sessions"
  Password "github.com/nkozyra/api/password"
)

var Session UserSession

type UserSession struct {
  ID              string
  GorillaSesssion *sessions.Session
  UID             int
  Expire          time.Time
}

func (us *UserSession) Create() {
  us.ID = Password.GenerateSessionID(32)
}

type SessionManager struct {

}

func GetSession() {

  log.Println("Getting session")
}

func SetSession() {

  log.Println("Setting session")
}
```

让我们看一些与 Go 有强大第三方集成的简单 NoSQL 模型，以便检查我们如何保持这些会话分离，并以一种使客户端可以安全访问我们的 API 的方式启用它们。

## Memcached

我们将从 Memcached 开始，特别是因为它不像我们的其他选择那样真正是一个数据存储。虽然从某种意义上说它仍然是一个键值存储，但它是一个维护数据仅在内存中的通用缓存系统。

由 Brad Fitzpatrick 为曾经非常流行的 LiveJournal 网站开发，旨在减少对数据库的直接访问量，这是 Web 开发中最常见的瓶颈之一。

Memcached 最初是用 Perl 编写的，但后来被重写为 C，并且已经达到了大规模使用的程度。

这些的优缺点已经显而易见——您可以获得内存的速度，而不会受到磁盘访问的拖累。这显然是巨大的，但它排除了使用应该是一致和容错的数据而不经过一些冗余处理。

因此，它非常适合缓存呈现层和会话的片段。会话本来就是短暂的，而 Memcached 的内置过期功能允许您为任何单个数据设置最大年龄。

也许 Memcached 最大的优势是它的分布式特性。这允许多个服务器在网络中共享内存值的数据。

### 注意

值得注意的是，Memcached 作为先进先出系统运行。过期只是为了编程目的而必要。换句话说，除非您需要在特定时间过期，否则没有必要强制设置最大年龄。

在`api.go`文件中，我们将检查一个 cookie 是否与我们的 Memcached 会话代理匹配，或者我们将创建一个会话：

```go
func CheckSession(w http.ResponseWriter, r *http.Request) bool {
  cookieSession, err := r.Cookie("sessionid")
  if err != nil {
    fmt.Println("Creating Cookie in Memcache")
    Session.Create()
    Session.Expire = time.Now().Local()
    Session.Expire.Add(time.Hour)
    Session.SetSession()
  } else {
    fmt.Println("Found cookie, checking against Memcache")
    ValidSession,err := Session.GetSession(cookieSession.Value)
    fmt.Println(ValidSession)
    if err != nil {
      return false
    } else {
      return true
    }

  }
  return true
}
```

然后，这是我们的`sessions.go`文件：

```go
package SessionManager

import
(
  "encoding/json"
  "errors"
  "time"
  "github.com/bradfitz/gomemcache/memcache"
  "github.com/gorilla/sessions"	
  Password "github.com/nkozyra/api/password"	

)

var Session UserSession

type UserSession struct {
  ID              string `json:"id"`
  GorillaSesssion *sessions.Session `json:"session"`
  SessionStore  *memcache.Client `json:"store"`
  UID             int `json:"uid"`
  Expire          time.Time `json:"expire"`
}

func (us *UserSession) Create() {
  us.SessionStore = memcache.New("127.0.0.1:11211")
  us.ID = Password.GenerateSessionID(32)
}

func (us *UserSession) GetSession(key string) (UserSession, error) {
  session,err := us.SessionStore.Get(us.ID)
  if err != nil {
    return UserSession{},errors.New("No such session")
  } else {
    var tempSession = UserSession{}
    err := json.Unmarshal(session.Value,tempSession)
    if err != nil {

    }
    return tempSession,nil
  }
}
```

`GetSession()`尝试通过键获取会话。如果它存在于内存中，它将直接将其值传递给引用的`UserSession`。请注意，在验证以下代码中的会话时，我们进行了一些微小的更改。我们将 cookie 的到期时间增加了一个小时。这是可选的，但如果用户在最后一次操作后一个小时离开，它允许会话保持活动状态：

```go
func (us *UserSession) SetSession() bool {
  jsonValue,_ := json.Marshal(us)
  us.SessionStore.Set(&memcache.Item{Key: us.ID, Value: []byte(jsonValue)})
  _,err := us.SessionStore.Get(us.ID)
  if err != nil {
      return false
  }
    Session.Expire = time.Now().Local()
    Session.Expire.Add(time.Hour)
    return true
}
```

### 注意

Brad Fitzpatrick 已经加入了 Google 的 Go 团队，因此他在 Go 中编写了一个 Memcached 实现应该不足为奇。同样，这也不足为奇，这是我们在这个示例中将使用的实现。

您可以在[`github.com/bradfitz/gomemcache`](https://github.com/bradfitz/gomemcache)了解更多信息，并使用`go get github.com/bradfitz/gomemcache/memcache`命令进行安装。

## MongoDB

MongoDB 是后来 NoSQL 解决方案中较早的大名鼎鼎的一个；它是一个依赖于具有开放式模式的类 JSON 文档的文档存储。Mongo 的格式称为 BSON，即二进制 JSON。因此，可以想象，这打开了一些不同的数据类型，即 BSON 对象和 BSON 数组，它们都以二进制数据而不是字符串数据存储。

### 注意

您可以在[`bsonspec.org/`](http://bsonspec.org/)了解有关二进制 JSON 格式的更多信息。

作为超集，BSON 不会提供太多的学习曲线，而且我们也不会使用二进制数据进行会话存储，但在某些情况下存储数据是有用且节省的。例如，在 SQL 数据库中的 BLOB 数据。

近年来，随着更新、功能更丰富的 NoSQL 解决方案的出现，MongoDB 已经赢得了一些批评者，但您仍然可以欣赏和利用它提供的简单性。

有一些不错的 MongoDB 和 Go 包，但最成熟的是 mgo。

### 注意

+   有关 MongoDB 的更多信息和下载链接，请访问[`www.mongodb.org/`](http://www.mongodb.org/)

+   mgo 可以在[`labix.org/mgo`](https://labix.org/mgo)找到，并且可以使用`go get gopkg.in/mgo.v2`命令进行安装

MongoDB 没有内置的图形用户界面，但有许多第三方界面，其中很多是基于 HTTP 的。在这里，我会推荐 Genghis ([`genghisapp.com/`](http://genghisapp.com/))，它只使用一个文件，可以用于 PHP 或 Ruby。

让我们看看如何从身份验证跳转到使用 Mongo 进行会话存储和检索。

我们将用另一个示例取代我们之前的示例。创建第二个文件和另一个名为`sessions2.go`的包子目录。

在我们的`api.go`文件中，将导入调用从`Sessions "github.com/nkozyra/api/sessions"`更改为`Sessions "github.com/nkozyra/api/sessionsmongo"`。

我们还需要用 mgo 版本替换`"github.com/bradfitz/gomemcache/memcache"`的导入，但由于我们只是修改存储平台，大部分内容仍然保持不变：

```go
package SessionManager

import
(
  "encoding/json"
  "errors"

  "log"
  "time"
  mgo "gopkg.in/mgo.v2"
  _ "gopkg.in/mgo.v2/bson"
  "github.com/gorilla/sessions"
  Password "github.com/nkozyra/api/password"

)

var Session UserSession

type UserSession struct {
  ID              string `bson:"_id"`
  GorillaSesssion *sessions.Session `bson:"session"`
  SessionStore  *mgo.Collection `bson:"store"`
  UID             int `bson:"uid"`
  Value         []byte `bson:"Valid"`
  Expire          time.Time `bson:"expire"`
}
```

在这种情况下，我们结构的重大变化是将我们的数据设置为 BSON 而不是字符串文字属性中的 JSON。这实际上并不重要，它仍然可以与`json`属性类型一起使用。

```go
func (us *UserSession) Create() {
 s, err := mgo.Dial("127.0.0.1:27017/sessions")
  defer s.Close()
  if err != nil {
    log.Println("Can't connect to MongoDB")
 } else {
 us.SessionStore = s.DB("sessions").C("sessions")
  }
  us.ID = Password.GenerateSessionID(32)
}
```

我们的连接方法显然会发生变化，但我们还需要在一个集合中工作（这类似于数据库术语中的表），因此我们连接到我们的数据库，然后连接到两者都命名为`session`的集合：

```go
func (us *UserSession) GetSession(key string) (UserSession, error) {
  var session UserSession
  err := us.SessionStore.Find(us.ID).One(session)
  if err != nil {
    return UserSession{},errors.New("No such session")
  } 
    var tempSession = UserSession{}
    err := json.Unmarshal(session.Value,tempSession)
    if err != nil {

    }
    return tempSession,nil

}
```

`GetSession()`的工作方式几乎完全相同，除了数据存储方法被切换为`Find()`。`mgo.One()`函数将单个文档（行）的值分配给一个接口。

```go
func (us *UserSession) SetSession() bool {
  jsonValue,_ := json.Marshal(us)
 err := us.SessionStore.Insert(UserSession{ID: us.ID, Value: []byte(jsonValue)})
  if err != nil {
      return false
  } else {
    return true
  }
}
```

# 使用用户名和密码启用连接

为了允许用户输入他们自己的连接的用户名和密码，而不是依赖令牌或者开放 API 端点，我们可以创建一个可以直接调用到任何特定函数中的中间件。

在这种情况下，我们将进行几次身份验证。这是`/api/users` GET 函数中的一个例子，它之前是开放的：

```go
  authenticated := CheckToken(r.FormValue("access_token"))

  loggedIn := CheckLogin(w,r)
  if loggedIn == false {
    authenticated = false
    authenticatedByPassword := MiddlewareAuth(w,r)
    if authenticatedByPassword == true {
        authenticated = true
    }
  } else {
    authenticated = true
  }

  if authenticated == false {
    Response := CreateResponse{}
    _, httpCode, msg := ErrorMessages(401)
    Response.Error = msg
    Response.ErrorCode = httpCode
    http.Error(w, msg, httpCode)
   return 
  }
```

您可以在这里看到我们所做的通行证。首先，我们检查令牌，然后检查现有会话。如果不存在，我们检查登录`用户名`和`密码`并验证它们。

如果这三个都失败了，那么我们返回一个未经授权的错误。

现在，我们在代码的另一个部分中已经有了`MiddlewareAuth()`函数，名为`ApplicationAuthorize()`，所以让我们把它移动一下：

```go
func MiddlewareAuth(w http.ResponseWriter, r *http.Request) (bool, int) {

  username := r.FormValue("username")
  password := r.FormValue("password")

  var dbPassword string
  var dbSalt string
  var dbUID string

  uerr := Database.QueryRow("SELECT user_password, user_salt, user_id from users where user_nickname=?", username).Scan(&dbPassword, &dbSalt, &dbUID)
  if uerr != nil {

  }

  expectedPassword := Password.GenerateHash(dbSalt, password)

  if (dbPassword == expectedPassword) {
    return true, dbUID
  } else {
    return false, 0
  }
}
```

如果用户通过`GET`方法访问`/api/users`端点，现在他们将需要一个`用户名`和`密码`组合，一个`access_token`，或者在 cookie 数据中有一个有效的会话。

在有效的身份验证时，我们还返回预期的`user_id`，否则将返回值为 0。

# 允许我们的用户相互连接

让我们退一步，为我们的应用程序添加一些社交网络特有的功能——创建连接的能力，比如加好友。在大多数社交网络中，这将授予与好友相连的数据的读取权限。

由于我们已经有一个有效的视图来查看用户，我们可以创建一些新的路由来允许用户发起连接。

首先，让我们在`api.go`文件的`Init()`函数中添加一些端点：

```go
for _, domain := range allowedDomains {
  PermittedDomains = append(PermittedDomains, domain)
}
Routes = mux.NewRouter()
Routes.HandleFunc("/interface", APIInterface).Methods("GET", "POST", "PUT", "UPDATE")
Routes.HandleFunc("/api/users", UserCreate).Methods("POST")
Routes.HandleFunc("/api/users", UsersRetrieve).Methods("GET")
Routes.HandleFunc("/api/users/{id:[0-9]+}", UsersUpdate).Methods("PUT")
Routes.HandleFunc("/api/users", UsersInfo).Methods("OPTIONS")
Routes.HandleFunc("/api/statuses", StatusCreate).Methods("POST")
Routes.HandleFunc("/api/statuses", StatusRetrieve).Methods("GET")
Routes.HandleFunc("/api/statuses/{id:[0-9]+}", StatusUpdate).Methods("PUT")
Routes.HandleFunc("/api/statuses/{id:[0-9]+}", StatusDelete).Methods("DELETE")
Routes.HandleFunc("/api/connections", ConnectionsCreate).Methods("POST")
Routes.HandleFunc("/api/connections", ConnectionsDelete).Methods("DELETE")
Routes.HandleFunc("/api/connections", ConnectionsRetrieve).Methods("GET")

```

### 注意

请注意，我们这里没有`PUT`请求方法。由于我们的连接是友谊和二进制的，它们不会被更改，但它们将被创建或删除。例如，如果我们添加一个阻止用户的机制，我们可以将其创建为一个单独的连接类型，并允许对其进行更改。

让我们设置一个数据库表来处理这些：

```go
CREATE TABLE IF NOT EXISTS `users_relationships` (
  `users_relationship_id` int(13) NOT NULL,
  `from_user_id` int(10) NOT NULL,
  `to_user_id` int(10) NOT NULL,
  `users_relationship_type` varchar(10) NOT NULL,
  `users_relationship_timestamp` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP,
  `users_relationship_accepted` tinyint(1) NOT NULL DEFAULT '0',
  PRIMARY KEY (`users_relationship_id`),
  KEY `from_user_id` (`from_user_id`),
  KEY `to_user_id` (`to_user_id`),
  KEY `from_user_id_to_user_id` (`from_user_id`,`to_user_id`),
  KEY `from_user_id_to_user_id_users_relationship_type` (`from_user_id`,`to_user_id`,`users_relationship_type`)
)
```

有了这个设置，我们现在可以复制我们用来确保用户对我们的`/api/connections` `POST`方法进行身份验证的代码，并允许他们发起好友请求。

让我们看一下`ConnectionsCreate()`方法：

```go
func ConnectionsCreate(w http.ResponseWriter, r *http.Request) {
  log.Println("Starting retrieval")
  var uid int
  Response := CreateResponse{}
  authenticated := false
  accessToken := r.FormValue("access_token")
  if accessToken == "" || CheckToken(accessToken) == false {
    authenticated = false
  } else {
    authenticated = true
  }

  loggedIn := CheckLogin(w,r)
  if loggedIn == false {
    authenticated = false
    authenticatedByPassword,uid := MiddlewareAuth(w,r)
    if authenticatedByPassword == true {
        fmt.Println(uid)
        authenticated = true
    }
  } else {
    uid = Session.UID
    authenticated = true
  }

  if authenticated == false {

    _, httpCode, msg := ErrorMessages(401)
    Response.Error = msg
    Response.ErrorCode = httpCode
    http.Error(w, msg, httpCode)
    return
  }
```

这与我们的`/api/users` `GET`函数的代码相同。在查看完整示例之后，我们将回到这里。

```go
  toUID := r.FormValue("recipient")
  var count int
  Database.QueryRow("select count(*) as ucount from users where user_id=?",toUID).Scan(&count)

  if count < 1 {
    fmt.Println("No such user exists")
    _, httpCode, msg := ErrorMessages(410)
    Response.Error = msg
    Response.ErrorCode = httpCode
    http.Error(w, msg, httpCode)
    return
```

在这里，我们检查是否存在用户。如果我们试图连接到一个不存在的用户，我们返回一个 410：Gone 的 HTTP 错误。

```go
  } else {
    var connectionCount int
    Database.QueryRow("select count(*) as ccount from users_relationships where from_user_id=? and to_user_id=?",uid, toUID).Scan(&connectionCount)
    if connectionCount > 0 {
      fmt.Println("Relationship already exists")
      _, httpCode, msg := ErrorMessages(410)
            Response.Error = msg
      Response.ErrorCode = httpCode
      http.Error(w, msg, httpCode)
      return
```

在这里，我们检查是否已经发起了这样的请求。如果是，我们还会传递一个 Gone 引用错误。如果没有满足这些错误条件中的任何一个，那么我们可以创建一个关系：

```go
    } else {
      fmt.Println("Creating relationship")
      rightNow := time.Now().Unix()
      Response.Error = "success"
      Response.ErrorCode = 0
      _,err := Database.Exec("insert into users_relationships set from_user_id=?, to_user_id=?, users_relationship_type=?, users_relationship_timestamp=?",uid, toUID, "friend", rightNow)
      if err != nil {
        fmt.Println(err.Error())
      } else {
        output := SetFormat(Response)
        fmt.Fprintln(w, string(output))
      }
    }
  }
}
```

成功调用后，我们在认证用户和目标用户之间创建一个待处理的用户关系。

您可能已经注意到了这个函数中的代码重复。这通常是通过中间件解决的，Go 有一些可用的选项可以在这个过程中注入。在下一章中，我们将看一些框架和包，它们也可以帮助构建我们自己的中间件。

# 总结

现在我们有了一个功能齐全的社交网络，可以通过强制 TLS 的 Web 服务进行访问，用户可以进行身份验证，并且可以与其他用户进行交互。

在本章中，我们还研究了将会话管理转移到 NoSQL 数据库，并使用其他 Web 服务器代替 Go 来提供额外的功能和故障转移保护。

在下一章中，我们将进一步完善我们的社交网络，尝试从客户端与我们的 API 进行交互。有了这个基础，我们可以让用户直接通过客户端界面进行身份验证和与 API 进行交互，而不需要 API 令牌，同时保留使用第三方令牌的能力。

我们还将研究如何使用 Go 与补充的前端框架，比如 Go 和 Meteor，以提供更具响应性、类似应用的网络界面。


# 第八章：Web 的响应式 Go

如果您花费了任何时间在 Web 上（或者无论如何），开发应用程序，您很快就会发现自己面临从网站内部与 API 进行交互的前景。

在本章中，我们将通过允许浏览器直接通过一些技术作为我们的 Web 服务的传导器来弥合客户端和服务器之间的差距，其中包括谷歌自己的 AngularJS。

在本书的前面，我们为我们的 API 创建了一个临时的客户端接口。这几乎完全是为了通过一个简单的界面查看我们的 Web 服务的细节和输出而存在的。

然而，重要的是要记住，处理 API 的不仅是机器，还有由用户直接发起的客户端接口。因此，我们将考虑以这种格式应用我们自己的 API。我们将通过域名锁定并启用 RESTful 和非 RESTful 属性，使网站能够响应（不一定是移动意义上的响应），并且仅通过使用 HTML5 功能的 API 进行操作。

在本章中，我们将研究：

+   使用像 jQuery 和 AngularJS 这样的客户端框架与我们的服务器端端点相结合

+   使用服务器端框架创建 Web 界面

+   允许我们的用户通过 Web 界面登录，查看其他用户，创建连接并发布消息到我们的 API

+   扩展我们的 Web 服务的功能，并将其扩展为允许通过我们将在 Go 中构建的接口直接访问

+   使用 HTML5 和几个 JavaScript 框架来补充我们的 Go 服务器端框架

# 创建前端界面

在开始之前，我们需要解决浏览器限制客户端到服务器信息流的一些问题。

我们还需要创建一个与我们的 API 一起工作的示例站点。最好在本地主机上的不同端口或另一台机器上进行，因为仅使用`file://`访问就会遇到额外的问题。

### 提示

为了构建 API，与之前的简单演示一样，将接口与 API 捆绑在一起是完全不必要的。

实际上，这可能会在 Web 服务增长时引入混乱。在这个例子中，我们将单独构建我们的界面应用程序，并在端口 444 上运行它。您可以选择任何可用的端口，假设它不会干扰我们的 Web 服务（443）。请注意，在许多系统上，访问端口 1024 及以下需要`root/sudo`。

如果我们尝试在与我们的安全 Web 服务不同的端口上运行接口，我们将遇到跨域资源共享问题。确保我们为客户端和/或 JavaScript 消耗公开的任何端点方法都包括一个`Access-Control-Allow-Origin`头。

### 注意

您可以在[`developer.mozilla.org/en-US/docs/Web/HTTP/Access_control_CORS`](https://developer.mozilla.org/en-US/docs/Web/HTTP/Access_control_CORS)上阅读有关**Access-Control-Allow-Origin**的性质和机制的更多信息。

您可能会诱惑只是使用`*`通配符，但这将导致许多浏览器问题，特别是我们将要研究的前端框架。例如，让我们看看如果我们尝试通过`GET`访问`/api/users`端点会发生什么：

![创建前端界面](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/ms-go-websvc/img/1304OS_08_01.jpg)

结果可能不可靠，一些框架完全拒绝通配符。使用通配符还会禁用一些您可能感兴趣的关键功能，例如 cookies。

您可以看到我们用来尝试访问 Web 服务以引发此错误的以下代码。该代码是用 Angular 构建的，我们将很快更详细地研究它：

```go
<html>
<head>
  <title>CORS Test</title>
  <script src="img/angular.js"></script>
  <script src="img/angular-route.min.js"></script>
  <script>
    var app = angular.module('testCORS', ['ngRoute']);
    app.controller('testWildcard', ['$scope', '$http', '$location', '$routeParams', function($scope,$http,$location,$routeParams) {
      $scope.messageFromAPI = '';
      $scope.users = [];
      $scope.requestAPI = function() {
        $http.get("https://localhost/api/users").success(function(data,status,headers,config) {
          angular.forEach(data.users, function(val,key) {
          $scope.users.push({name: val.Name});
    })
  });
```

在这里，我们正在向我们的 API 端点发出`GET`请求。如果成功，我们将将用户添加到`$scope.users`数组中，该数组将通过 AngularJS 循环进行迭代，如下所示。如果我们的客户端没有域来源允许，由于浏览器中的跨域政策，这将失败：

```go
      };

      $scope.requestAPI();

    }]);
  </script>
</head>
<body ng-app="testCORS">

  <div ng-controller="testWildcard">
    <h1 ng-model="messageFromAPI">Users</h1>
    <div ng-repeat="user in users">
      {{user.name}}
    </div>
```

这是 AngularJS 处理循环的方式，允许您指定一个与特定于 DOM 的变量或循环直接关联的 JavaScript 数组。

```go
  </div>
</body>
</html>
```

在这个例子中，由于权限问题，我们将得到零个用户。

幸运的是，我们之前在应用程序中通过在`v1.go`文件中引入了一个非常高级的配置设置来解决了这个问题：

```go
  api.Init([]string{"http://www.example.com","http://www.mastergoco.com","http://localhost"})
```

您可能还记得`Init()`函数接受一个允许的域名数组，然后我们可以设置`Access-Control-Allow-Origin`头：

```go
func Init(allowedDomains []string) {
  for _, domain := range PermittedDomains {
    fmt.Println("allowing", domain)
    w.Header().Set("Access-Control-Allow-Origin", domain)
  }
```

如前所述，如果我们设置一个`*`通配符域，一些浏览器和库会产生分歧，通配符来源会导致无法设置 cookie 或遵守 SSL 凭证的能力。我们可以更明确地指定域：

```go
requestDomain := r.Header.Get("Origin")
if requestDomain != "" {
  w.Header.Set("Access-Control-Allow-Origin", requestDomain)
}
```

这使您能够保留 cookie 和 SSL 证书的设置，这些设置遵守了非通配符访问控制头的方面。这确实会带来一些与 cookie 相关的安全问题，因此您必须谨慎使用。

如果此循环在通过网络界面可访问的任何函数中被调用，它将防止跨域问题。

# 登录

与以前一样，我们将使用 Twitter 的 Bootstrap 作为基本的 CSS 框架，这使我们能够快速复制一个我们可能在任何地方在线看到的站点结构。

请记住，我们之前的例子打开了一个登录界面，只是将一个令牌传递给第三方，以便允许该应用程序代表我们的用户执行操作。

由于我们现在试图允许用户直接通过我们的 API（通过浏览器通道）进行接口，我们可以改变操作方式，允许会话作为认证方法。

以前，我们是直接通过 JavaScript 将登录请求发布到 API 本身，但现在我们使用完整的网络界面，没有理由这样做；我们可以直接发布到网络界面本身。这主要意味着放弃`onsubmit="return false"`或`onsubmit="userCreate();"`方法，只需将表单数据发送到`/interface/login`：

```go
func Init(allowedDomains []string) {
  for _, domain := range allowedDomains {
   PermittedDomains = append(PermittedDomains, domain)
  }
  Routes = mux.NewRouter()
  Routes.HandleFunc("/interface", APIInterface).Methods("GET", "POST", "PUT", "UPDATE")
  Routes.HandleFunc("/interface/login", APIInterfaceLogin).Methods("GET")
  Routes.HandleFunc("/interface/login", APIInterfaceLoginProcess).Methods("POST")
  Routes.HandleFunc("/interface/register", APIInterfaceRegister).Methods("GET")
  Routes.HandleFunc("/interface/register", APIInterfaceRegisterProcess).Methods("POST")
```

这为我们提供了足够的内容，允许网络界面利用现有代码创建和登录到我们的帐户，同时仍然通过 API 进行。

# 使用 Go 的客户端框架

虽然我们在本书的大部分时间里构建了一个后端 API，但我们也一直在构建一个相对可扩展的基本服务器端框架。

当我们需要从客户端访问 API 时，我们受到 HTML、CSS 和 JavaScript 的限制。或者，我们可以作为消费者在服务器端呈现页面，并且我们也将在本章中展示这一点。

然而，大多数现代网络应用程序在客户端上运行，通常是在**单页应用程序**或**SPA**中。这试图减少用户必须进行的“硬”页面请求的数量，使站点看起来不太像一个应用程序，而更像是一组文档。

这主要是通过异步 JavaScript 数据请求完成的，它允许 SPA 在响应用户操作时*重新绘制*页面。

起初，这种方法有两个主要缺点：

+   首先，应用程序状态没有得到保留，因此如果用户采取行动并尝试重新加载页面，应用程序将重置。

+   其次，基于 JavaScript 的应用在搜索引擎优化方面表现非常糟糕，因为传统的网络爬虫无法渲染 JavaScript 应用程序。它只会渲染原始的 HTML 应用程序。

但最近，一些标准化和技巧已经帮助减轻了这些问题。

在状态上，SPAs 已经开始利用 HTML5 中的一个新功能，使它们能够在浏览器中修改地址栏和/或历史记录，而无需重新加载，通常是通过使用内联锚点。您可以在 Gmail 或 Twitter 的 URL 中看到这一点，它可能看起来像[`mail.google.com/mail/u/0/#inbox/1494392317a0def6`](https://mail.google.com/mail/u/0/#inbox/1494392317a0def6)。

这使用户能够通过 JavaScript 控制器分享或收藏 URL。

在 SEO 方面，这在很大程度上将 SPAs 局限于管理类型的界面或搜索引擎可访问性不是关键因素的领域。然而，随着搜索引擎开始解析 JavaScript，窗口已经打开，可以广泛使用而不会对 SEO 产生负面影响。

# jQuery

如果你做任何前端工作或查看过地球上最流行的网站之一的源代码，那么你一定遇到过 jQuery。

根据 SimilarTech 的数据，jQuery 被大约 6700 万个网站使用。

jQuery 作为一种标准化 API 的方法发展起来，其中一致性曾经是一项几乎不可能的任务。在微软的 Internet Explorer 和各种程度上坚持标准的浏览器之间，编写跨浏览器代码曾经是一件非常复杂的事情。事实上，以前经常会看到这个网站最好使用标签来查看，因为即使使用了任何给定浏览器的最新版本，也无法保证功能。

当 jQuery 开始流行（在 Prototype、Moo Tools 和 Dojo 等其他类似框架之后），Web 开发领域终于找到了一种方法，可以使用单一接口覆盖大多数现有的现代 Web 浏览器。

## 使用 jQuery 消耗 API

使用 jQuery 处理我们的 API 非常简单。当 jQuery 开始出现时，AJAX 的概念真的开始流行起来。**AJAX**或**异步 JavaScript**和**XML**是朝着利用`XMLHttpRequest`对象获取远程数据并将其注入到 DOM 的 Web 技术的第一次迭代。

具有一定讽刺意味的是，微软，通常被认为是最严重违反网络标准的公司，却在 Microsoft Exchange Server 中为`XMLHttpRequest`奠定了基础，从而导致了 AJAX 的出现。

当然，如今 XML 很少成为谜题的一部分，因为这些库中消耗的大部分内容都是 JSON。您仍然可以使用 XML 作为源数据，但您的响应可能会比必要的更冗长。

进行简单的`GET`请求非常简单，因为 jQuery 提供了一个简单的快捷函数，称为`getJSON`，您可以使用它从我们的 API 获取数据。

现在，我们将遍历我们的用户，并创建一些 HTML 数据注入到现有的 DOM 元素中：

```go
<script>

  $(document).ready(function() {
    $.getJSON('/api/users',function() {
        html = '';
      $(data.users).each(function() {
        html += '<div class="row">';
        html += '<div class="col-lg-3">'+ image + '</div>';
        html += '<div class="col-lg-9"><a href="/connect/'+this.ID+'/" >'+ this.first + ' ' + this.last + '</a></div>';
        html += '</div>';
      });
    });
  });
</script>
```

然而，`GET`请求只能让我们走得更远。为了完全符合 RESTful 网络服务，我们需要能够执行`GET`、`POST`、`PUT`、`DELETE`和`OPTIONS`头请求。实际上，最后一种方法将很重要，以允许跨不同域的请求。

正如我们之前提到的，`getJSON`是内置的`ajax()`方法的简写函数，它允许您在请求中更具体。例如，`$.getJSON('/api/users')`转换为以下代码：

```go
$.ajax({
  url: '/api/users',
  cache: false,
  type: 'GET', // or POST, PUT, DELETE
});
```

这意味着我们可以通过直接设置`HTTP`方法来技术上处理 API 中的所有端点和方法。

虽然`XMLHttpRequest`接受所有这些头部，但 HTML 表单（至少通过 HTML 4）只接受`GET`和`POST`请求。尽管如此，如果您打算在客户端 JavaScript 中使用`PUT`、`DELETE`、`OPTIONS`或`TRACE`请求，进行一些跨浏览器测试总是一个好主意。

### 注意

您可以在[`jquery.com/`](http://jquery.com/)下载并阅读 jQuery 提供的非常全面的文档。有一些常见的 CDN 可以让您直接包含库，其中最值得注意的是 Google Hosted Libraries，如下所示：

`<script src="img/jquery.min.js"></script>`

该库的最新版本可在[`developers.google.com/speed/libraries/devguide#jquery`](https://developers.google.com/speed/libraries/devguide#jquery)找到。

## AngularJS

如果我们超越了 jQuery 提供的基本工具集，我们将开始深入研究合法的、完全成型的框架。在过去的五年里，这些框架如雨后春笋般涌现。其中许多是传统的**模型-视图-控制器**（**MVC**）系统，有些是纯模板系统，有些框架同时在客户端和服务器端工作，通过 WebSockets 提供了独特的推送式接口。

与 Go 一样，Angular（或 AngularJS）是由 Google 维护的项目，旨在在客户端提供全功能的 MVC。请注意，随着时间的推移，Angular 已经在设计模式上有所偏离，更多地朝向 MVVM 或 Model View ViewModel，这是一种相关的模式。

Angular 远远超出了 jQuery 提供的基本功能。除了一般的 DOM 操作外，Angular 还提供了真正的控制器作为更大的应用程序的一部分，以及用于强大的单元测试。

除其他功能外，Angular 使得从客户端快速、轻松、愉快地与 API 进行交互成为可能。该框架提供了更多的 MVC 功能，包括能够从`.html`/`template`文件中引入单独的模板的能力。

### 注意

许多人预计实际的推送通知将成为 HTML5 的标准功能，随着规范的成熟。

在撰写本书时，W3C 对推送 API 有一个工作草案。您可以在[`www.w3.org/TR/2014/WD-push-api-20141007/`](http://www.w3.org/TR/2014/WD-push-api-20141007/)了解更多信息。

目前，解决方法包括诸如 Meteor（稍后将讨论）等利用 HTML5 中的 WebSockets 来模拟实时通信，而不受其他浏览器相关限制的束缚，例如在非活动选项卡中的休眠进程等。

## 使用 Angular 消费 API

使 Angular 应用程序能够与 REST API 一起工作，就像 jQuery 一样，直接内置到框架的骨架中。

将此调用与我们刚刚查看的`/api/users`端点进行比较：

```go
$http.$get('/api/users'.
  success(function(data, status, headers, config) {
    html += '<div class="row">';
    html += '<div class="col-lg-3">'+ image + '</div>';
    html += '<div class="col-lg-9"><a href="/connect/'+this.ID+'/" >'+ this.first + ' ' + this.last + '</a></div>';
    html += '</div>';	
  }).
  error(function(data, status, headers, config) {
    alert('error getting API!')
  });
```

除了语法外，Angular 与 jQuery 并没有太大的不同；它也有一个接受回调函数或承诺作为第二参数的方法。但是，与 jQuery 设置方法的属性不同，Angular 为大多数 HTTP 动词提供了简短的方法。

这意味着我们可以直接进行`PUT`或`DELETE`请求：

```go
$http.$delete("/api/statuses/2").success(function(data,headers,config) {
  console.log('Date of response:', headers('Date'))
  console.log(data.message)
}).error(function(data,headers,config) {
  console.log('Something went wrong!');
  console.log('Got this error:', headers('Status'));
});
```

请注意，在前面的示例中，我们正在读取标头值。为了使其跨域工作，您还需要设置一个标头，以便为其他域共享这些标头：

```go
Access-Control-Expose-Headers: [custom values]
```

由于域名在`Access-Control-Allow-Origin`标头中被明确列入白名单，这控制了将可用于客户端而不是域的特定标头键。在我们的情况下，我们将为`Last-Modified`和`Date`值设置一些内容。

### 注意

您可以在[`angularjs.org/`](https://angularjs.org/)阅读更多关于 Angular 并从那里下载它。您还可以直接从 Google Hosted Libraries CDN 包含该库，如下所示：

```go
<script src="img/angular.min.js"></script>

```

您可以在[`developers.google.com/speed/libraries/devguide#angularjs`](https://developers.google.com/speed/libraries/devguide#angularjs)找到该库的最新版本。

# 设置一个消费 API 的前端

为了使用 API，前端将几乎完全不包含内部逻辑。毕竟，整个应用程序都是通过 HTML 调用到 SPA 中的，所以我们除了一个或两个模板之外不需要太多东西。

这是我们的`header.html`文件，其中包含基本的 HTML 代码：

```go
<html>
  <head>Social Network</title>

    <link href="//maxcdn.bootstrapcdn.com/bootstrap/3.3.0/css/bootstrap.min.css" rel="stylesheet">
    <script src="img/jquery.min.js"></script>
    <script src="img/bootstrap.min.js"></script>
    <script src="img/angular.min.js"></script>
    <script src="img/react.min.js"></script>
    <script src="img/application.js"></script>
  </head>

  <body ng-app="SocialNetwork">

    <div ng-view></div>
  </body>
```

带有`application.js`的行很重要，因为那里将存在所有逻辑并利用下面的一个前端框架。

`ng-view`指令只是一个占位符，将根据控制器的路由值替换。我们很快会看到。

请注意，我们在此处调用了 AngularJS、jQuery 和 React。这些都是选项，您不一定需要全部导入。很可能会导致冲突。相反，我们将探讨如何使用它们处理我们的 API。

正如您所期望的，我们的页脚主要是闭合标签：

```go
</body>
</html>
```

我们将利用 Go 的`http`模板系统生成我们的基本模板。这里的示例显示了这一点：

```go
<div ng-controller="webServiceInterface">
  <h1>{{Page.Title}}</h1>
  <div ng-model="webServiceError" style="display:none;"></div>
  <div id="webServiceBody" ng-model="body">
    <!-- nothing here, yet -->

  </div>
</div>
```

这个模板的核心不会是硬编码的，而是由所选择的 JavaScript 框架构建的。

## 为 Web 服务创建客户端 Angular 应用程序

如前所述，`ng-app`元素中的`ng-view`指令是指根据将 URL 与控制器配对的路由动态引入的内容。

更准确地说，它连接了伪 URL 片段（我们之前提到的）构建在`#`锚标签之上。让我们首先通过以下代码片段设置应用程序本身。

```go
var SocialNetworkApp = angular.module('SocialNetwork', ['ngSanitize','ngRoute']);
SocialNetworkApp.config(function($routeProvider) {
  $routeProvider
  .when('/login',
    {
      controller: 'Authentication',
      templateUrl: '/views/auth.html'
    }
  ).when('/users',
    {
      controller: 'Users',
      templateUrl: '/views/users.html'
    }
  ).when('/statuses',
    {
      controller: 'Statuses',
      templateUrl: '/views/statuses.html'
    }
  );
});
```

当访问这些 URL 时，Angular 会告诉它将控制器与模板配对，并将它们放在`ng-view`元素中。这就是允许用户在站点之间导航而不进行硬页面加载的原因。

这是`auth.html`，它位于我们的`/views/`目录中，允许我们登录并执行用户注册：

```go
<div class="container">
  <div class="row">
    <div class="col-lg-5">
      <h2>Login</h2>
      <form>
        <input type="email" name="" class="form-control" placeholder="Email" ng-model="loginEmail" />
        <input type="password" name="" class="form-control" placeholder="Password" ng-model="loginPassword" />
        <input type="submit" value="Login" class="btn" ng-click="login()" />
      </form>
    </div>

    <div class="col-lg-2">
      <h3>- or -</h3>
    </div>

    <div class="col-lg-5">
      <h2>Register</h2>
      <form>
        <input type="email" name="" class="form-control" ng-model="registerEmail" placeholder="Email" ng-keyup="checkRegisteredEmail();" />
        <input type="text" name="" class="form-control" ng-model="registerFirst" placeholder="First Name" />
        <input type="text" name="" class="form-control" ng-model="registerLast" placeholder="Last Name" />
        <input type="password" name="" class="form-control" ng-model="registerPassword" placeholder="Password" ng-keyup="checkPassword();" />
        <input type="submit" value="Register" class="btn" ng-click="register()" />
      </form>
    </div>
  </div>
</div>
```

如前所述，用于控制这一切的 JavaScript 只是我们 API 周围的一个薄包装。这是`Login()`过程：

```go
$scope.login = function() {
  postData = { email: $scope.loginEmail, password: $scope.loginPassword };
  $http.$post('https://localhost/api/users', postData).success(function(data) {

    $location.path('/users');

  }).error(function(data,headers,config) {
    alert ("Error: " + headers('Status'));
  });
};
```

这是`Register()`过程：

```go
$scope.register = function() {
  postData = { user: $scope.registerUser, email: $scope.registerEmail, first: $scope.registerFirst, last: $scope.registerLast, password: $scope.registerPassword };
  $http.$post('https://localhost/api/users', postData).success(function(data) {

    $location.path('/users');

  }).error(function(data,headers,config) {
    alert ("Error: " + headers('Status'));
  });
};
  Routes.HandleFunc("/api/user",UserLogin).Methods("POST","GET")
  Routes.HandleFunc("/api/user",APIDescribe).Methods("OPTIONS")
```

我们想在这里注意`OPTIONS`头。这是 CORS 标准运作的重要部分；基本上，请求通过使用`OPTIONS`动词进行预检调用进行缓冲，返回有关允许的域、资源等信息。在这种情况下，我们在`api.go`中包括一个名为`APIDescribe`的 catchall：

```go
func APIDescribe(w http.ResponseWriter, r *http.Request) {
  w.Header().Set("Access-Control-Allow-Headers", "Origin, X-Requested-With, Content-Type, Accept")
  w.Header().Set("Access-Control-Allow-Origin", "*")
}
```

# 查看其他用户

一旦我们登录，我们应该能够向经过身份验证的用户展示其他用户，以允许他们发起连接。

这是我们如何快速查看我们`users.html` Angular 模板中的其他用户：

```go
<div class="container">
  <div class="row">
    <div ng-repeat="user in users">
      <div class="col-lg-3">{{user.Name}} <a ng-click="createConnection({{user.ID}});">Connect</a></div>
      <div class="col-lg-8">{{user.First}} {{user.Last}}</div>
    </div>

  </div>
</div>
```

我们调用我们的`/api/users`端点，它返回一个已登录用户列表。您可能还记得我们在上一章中将其放在身份验证墙后面。

![查看其他用户](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/ms-go-websvc/img/1304OS_08_02.jpg)

这个视图没有太多的花哨。这只是一种方式，可以看到您可能有兴趣连接或在我们的社交应用中添加好友的人。

# 在 Go 中服务器端呈现框架

为了构建页面，呈现框架在很大程度上是学术性的，它类似于使用 JavaScript 预渲染页面并返回它们。

因此，我们的 API 消费者的总代码非常简单：

```go
package main

import
(
  "github.com/gorilla/mux"
  "fmt"
  "net/http"
  "html/template"
)
var templates = template.Must(template.ParseGlob("templates/*"))
```

在这里，我们指定一个目录用于模板访问，这在这种情况下是惯用的模板。我们不使用`views`，因为我们将用它来放我们的 Angular 模板，那些 HTML 块被`templateUrl`调用。让我们首先定义我们的 SSL 端口并添加一个处理程序。

```go
const SSLport = ":444"

func SocialNetwork(w http.ResponseWriter, r *http.Request) {
  fmt.Println("got a request")
  templates.ExecuteTemplate(w, "socialnetwork.html", nil)
}
```

这就是我们的端点。现在，我们只是显示 HTML 页面。这可以简单地用任何语言完成，并且可以轻松地与我们的 Web 服务进行接口：

```go
func main() {

  Router := mux.NewRouter()
  Router.HandleFunc("/home", SocialNetwork).Methods("GET")
  Router.PathPrefix("/js/").Handler(http.StripPrefix("/js/", http.FileServer(http.Dir("js/"))))
  Router.PathPrefix("/views/").Handler(http.StripPrefix("/views/", http.FileServer(http.Dir("views/"))))
```

最后两行允许从目录中提供文件。如果没有这些，当我们尝试调用 JavaScript 或 HTML 包含文件时，我们将收到 404 错误。让我们接下来添加我们的 SSL 端口和证书。

```go
  http.ListenAndServeTLS(SSLport, "cert.pem", "key.pem", Router)
  }
```

如前所述，端口的选择甚至是 HTTP 还是 HTTPS 都是完全可选的，只要您允许生成的域在`v1.go`中的允许域列表中。

# 创建状态更新

我们的最后一个例子允许用户查看他们的最新状态更新并创建另一个。它略有不同，因为它在单个视图中调用了两个不同的 API 端点——用于最新状态的循环和发布的能力，也就是创建一个新的状态。

`statuses.html`文件看起来有点像这样：

```go
<div class="container">
  <div class="row">
    <div class="col-lg-12">
       <h2>New Status:</h2>
       <textarea class="form-control" rows="10" ng-mode="newStatus"></textarea>
       <a class="btn btn-info" ng-click="createStatus()">Post</a>
```

在这里，我们在控制器中调用`createStatus()`函数来发布到`/api/statuses`端点。这里显示的其余代码通过 ng-repeat 指令显示了先前状态的列表：

```go
    </div>
  </div>
  <div class="row">
    <div class="col-lg-12">
      <h2>Previous Statuses:</h2>
      <div ng-repeat="status in statuses">
        <div>{{status.text}}></div>
      </div>
  </div>
</div>
```

前面的代码只是简单地显示返回的文本。

```go
SocialNetworkApp.controller('Statuses',['$scope', '$http', '$location', '$routeParams', function($scope,$http,$location,$routeParams) {

  $scope.statuses = [];
  $scope.newStatus;

  $scope.getStatuses = function() {
    $http.get('https://www.mastergoco.com/api/statuses').success(function(data) {

    });
  };

  $scope.createStatus = function() {
    $http({
      url: 'https://www.mastergoco.com/api/statuses',
      method: 'POST',
      data: JSON.stringify({ status: $scope.newStatus }),
            headers: {'Content-Type': 'application/json'}

  }).success(function(data) {
      $scope.statuses = [];
      $scope.getStatuses();
    });
  }

  $scope.getStatuses();

}]);
```

![创建状态更新](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/ms-go-websvc/img/1304OS_08_03.jpg)

在这里，我们可以看到一个简单的演示，在添加新状态消息的表单下显示了先前的状态消息。

# 摘要

我们已经简要介绍了在 Go 中开发简单 Web 服务接口的基础知识。诚然，这个特定版本非常有限且容易受攻击，但它展示了我们可以采用的基本机制，以产生可用的、正式的输出，可以被其他服务接收。

在对 Web 的一些主要框架以及诸如 jQuery 之类的通用库进行了初步检查后，您有足够多的选择来测试您的 API 与 Web 界面并创建单页面应用程序。

在这一点上，您应该已经掌握了开始完善这个过程和我们整个应用程序所需的基本工具。我们将继续前进，并在推进过程中对我们的 API 应用更全面的设计。显然，随机选择的两个 API 端点对我们来说并没有太多作用。

在下一章中，我们将深入探讨 API 规划和设计，RESTful 服务的细节，以及如何将逻辑与输出分离。我们将简要涉及一些逻辑/视图分离的概念，并朝着更健壮的端点和方法迈进第三章, *路由和引导*。


# 第九章：部署

说到底，当您准备启动您的 Web 服务或 API 时，总会有一些需要考虑的事项，从代码存储库到分段，到实时环境，到停止、启动和更新策略。

部署编译应用程序总是比部署解释应用程序更加复杂。幸运的是，Go 被设计为一种非常现代的编译语言。这意味着，人们已经付出了大量的思考，以解决传统上困扰 C 或 C++构建的服务器和服务的问题。

考虑到这一点，在本章中，我们将探讨一些可用于轻松部署和更新应用程序的工具和策略，以最小化停机时间。

我们还将研究一些可以减少我们的 Web 服务内部负载的方法，例如将图像存储和消息传递作为部署策略的一部分。

在本章结束时，您应该掌握一些特定于 Go 的和一般的技巧，可以最大限度地减少部署 API 和 Web 服务时常见的烦恼，特别是那些需要频繁更新并需要最少停机时间的服务。

在本章中，我们将探讨：

+   应用程序设计和结构

+   云端部署选项和策略

+   利用消息系统

+   将图像托管与我们的 API 服务器分离，并将其连接到基于云的 CDN

# 项目结构

尽管应用程序的设计和基础设施是机构和个人偏好的问题，但您计划其架构的方式可能会对您用于将应用程序部署到云端或任何生产环境中的方法产生真正的影响。

让我们快速回顾一下我们应用程序的结构，记住除非我们打算为大规模跨平台使用而生产我们的应用程序，否则我们不需要包对象：

```go
bin/
  api # Our API binary

pkg/

src/
  github.com/
    nkozyra/
    api/
      /api/api.go
        /interface/interface.go
        /password/password.go
        /pseudoauth/pseudoauth.go
        /services/services.go
        /specification/specification.go
        /v1/v1.go
        /v2/v2.go
```

我们的应用程序的结构可能会引人注目，具体取决于我们如何将其部署到云端。

如果在部署之前有一个处理构建、依赖管理和推送到实时服务器的传输过程，那么这个结构就不相关了，因为源代码和 Go 包依赖可以被二进制文件所取代。

然而，在整个项目被推送到每个应用服务器或服务器或 NFS/文件服务器的情况下，结构仍然是必不可少的。此外，正如前面所指出的，任何需要考虑跨平台分发的地方，都应该保留 Go 项目的整个结构。

即使这并非至关重要，如果构建机器（或机器）与目标机器不完全相同，这会影响您构建二进制文件的过程，尽管这并不排除仅处理该二进制文件。

在一个示例 GitHub 存储库中，如果存在任何开放目录访问，可能还需要对非二进制代码进行混淆，类似于我们的`interface.go`应用程序。

# 使用进程控制来保持您的 API 运行

处理版本控制和开发流程的方法超出了本书的范围，但在为 Web 构建和部署编译代码时，一个相当常见的问题是安装和重新启动这些进程的过程。

管理更新的方式，同时最大限度地减少或消除停机时间对于实时应用程序至关重要。

对于脚本语言和依赖外部 Web 服务器通过 Web 公开应用程序的语言来说，这个过程很容易。脚本要么监听更改并重新启动其内部 Web 服务，要么在未缓存时进行解释，并且更改立即生效。

对于长时间运行的二进制文件，这个过程变得更加复杂，不仅涉及更新和部署我们的应用程序，还涉及确保我们的应用程序处于活动状态，如果服务停止，不需要手动干预。

幸运的是，有几种简单的方法来处理这个问题。第一种是自动维护的严格进程管理。第二种是一个特定于 Go 的工具。让我们首先看看进程管理器以及它们如何与 Go Web 服务一起工作。

## 使用监督者

对于*nix 服务器来说，这里有几个大的解决方案，从非常简单到更复杂和细粒度的解决方案。它们的操作方式没有太大的区别，因此我们将简要地介绍如何使用 Supervisor 来管理我们的 Web 服务。

### 注意

其他一些值得注意的进程管理器如下：

+   Upstart: [`upstart.ubuntu.com/`](http://upstart.ubuntu.com/)

+   Monit: [`mmonit.com/monit/`](http://mmonit.com/monit/)

+   Runit: [`smarden.org/runit/`](http://smarden.org/runit/)

这些直接监督初始化守护进程监控进程管理器的基本原则是监听运行的应用程序，如果没有根据一组配置的规则尝试重新启动它们。

值得指出的是，这些系统没有真正的分布式方法，允许您以聚合方式管理多个服务器的进程，因此通常需要依靠负载均衡器和网络监控来获取此类反馈。

在 Supervisor 的情况下，安装完成后，我们只需要一个简单的配置文件，通常可以通过导航到*nix 发行版上的`/etc/supervisor/conf.d/`来找到。以下是我们应用程序的一个示例文件：

```go
[program:socialnetwork]
command=/var/app/api
autostart=true
autorestart=true
stderr_logfile=/var/log/api.log
stdout_logfile=/var/log/api.log
```

虽然您可以变得更加复杂，例如，将多个应用程序组合在一起以允许同步重启，这对升级非常有用，但这就是您需要保持我们长时间运行的 API 的全部内容。

当需要更新时，比如从 GIT 到暂存再到线上，可以手动触发一个重新启动服务的进程，也可以通过命令以编程方式触发，比如以下命令：

```go
supervisorctl restart program:socialnetwork
```

这不仅可以使您的应用程序保持运行，还可以强制执行一个完整的更新过程，将您的代码推送到线上并触发进程的重新启动。这确保了最小的停机时间。

## 使用 Manners 创建更加优雅的服务器

虽然替代进程管理器在自己的工作中表现得很好，但它们在应用程序内部缺乏一些控制。例如，简单地杀死或重新启动 Web 服务器几乎肯定会中断任何活动的请求。

单独使用 Manners 时，缺少一些像**goagain**这样的进程的监听控制，它是一个将 TCP 监听器聚合到 goroutines 中，并允许通过 SIGUSR1/SIGUSR2 进程间自定义信号进行外部控制的库。

但是，您可以将两者结合使用来创建这样的进程。或者，您可以直接编写内部监听器，因为对于优雅地重新启动 Web 服务器的目的，goagain 可能会有点过度。

使用 Manners 作为`net/http`的替代/包装器的示例将如下所示：

```go
package main

import
(
  "github.com/braintree/manners"
  "net/http"
  "os"
  "os/signal"
)

var Server *GracefulServer

func SignalListener() {
  sC := make(chan os.signal, 1)
  signal.Notify(sC, syscall.SIGUSR1, syscall.SIGUSR2)
  s := <- sC
  Server.Shutdown <- true
}
```

在 goroutine 中运行并阻塞的通道监听 SIGUSR1 或 SIGUSR2 时，当接收到这样的信号时，我们将布尔值传递给`Server.Shutdown`通道。

```go
func Init(allowedDomains []string) {
  for _, domain := range allowedDomains {
    PermittedDomains = append(PermittedDomains, domain)
  }
  Routes = mux.NewRouter()
  Routes.HandleFunc("/interface", APIInterface).Methods("GET", "POST", "PUT", "UPDATE")
  Routes.HandleFunc("/api/user",UserLogin).Methods("POST","GET")
  ...
}
```

这只是我们在`api.go`中`Init()`函数的重新处理。这注册了我们需要 Manners 包装的 Gorilla 路由器。

```go
func main() {

  go func() {
    SignalListener()
  }()
  Server = manners.NewServer()
  Server.ListenAndServe(HTTPport, Routes)
}
```

在`main()`函数中，我们不仅启动`http.ListenAndServe()`函数，还使用 Manners 服务器。

这将防止在发送关闭信号时断开开放的连接。

### 注意

+   您可以使用`go get github.com/braintree/manners`来安装 Manners。

+   您可以在[`github.com/braintree/manners`](https://github.com/braintree/manners)了解更多关于 Manners 的信息。

+   您可以使用`go get github.com/rcrowley/goagain`来安装 goagain。

+   您可以在[`github.com/rcrowley/goagain`](https://github.com/rcrowley/goagain)了解更多关于 goagain 的信息。

# 使用 Docker 部署

在过去几年里，几乎没有什么服务器端产品能像 Docker 在技术世界中引起如此大的轰动。

Docker 创建了类似于易于部署、预配置的虚拟机，与 VirtualBox、VMWare 等传统虚拟机软件相比，对主机的影响要小得多。

它能够以比虚拟机更少的整体重量来实现这一点，通过利用 Linux 容器，这允许用户空间被包含，同时保留对操作系统本身的许多访问权限。这样一来，每个虚拟机就不需要成为操作系统和应用程序的完整镜像了。

为了在 Go 中使用，这通常是一个很好的选择，特别是如果我们为多个目标处理器创建构建，并希望轻松部署 Docker 容器到任何一个或所有这些处理器。更好的是，现在设置方面基本上是开箱即用的，因为 Docker 已经创建了语言堆栈，并在其中包含了 Go。

尽管在其核心，Docker 本质上只是一个典型 Linux 发行版镜像的抽象，但使用它可以使升级和快速配置变得轻而易举，甚至可能提供额外的安全性好处。最后一点取决于您的应用程序及其依赖关系。

Docker 使用非常简单的配置文件，使用语言堆栈，您可以轻松创建一个容器，可以启动并具有我们 API 所需的一切。

看看这个 Docker 文件示例，看看我们如何为我们的社交网络网络服务获取所有必要的包：

```go
FROM golang:1.3.1-onbuild

RUN go install github.com/go-sql-driver/mysql
RUN go install github.com/gorilla/mux
RUN go install github.com/gorilla/sessions
RUN go install github.com/nkozyra/api/password
RUN go install github.com/nkozyra/api/pseudoauth
RUN go install github.com/nkozyra/api/services
RUN go install github.com/nkozyra/api/specification
RUN go install github.com/nkozyra/api/api

EXPOSE 80 443
```

然后可以使用简单的命令构建和运行该文件：

```go
docker build -t api .
docker run --name api-running api -it --rm
```

您可以看到，至少在最低限度下，这将极大地加快 Go 更新过程，跨多个实例（或在这种情况下是容器）。

完整的 Docker 基础镜像也适用于 Google 云平台。如果您使用或希望测试 Google Cloud，这对于快速部署最新版本的 Go 非常有用。

# 在云环境中部署

对于那些还记得满屋子都是物理单用途服务器、毁灭性的硬件故障和极其缓慢的重建和备份时间的人来说，云托管的出现很可能是一大福音。

如今，一个完整的架构通常可以很快地从模板构建，自动扩展和监控也比以往更容易。现在，市场上也有很多参与者，从谷歌、微软和亚马逊到专注于简单、节俭和易用性的小公司，如 Linode 和 Digital Ocean。

每个网络服务都有自己的功能集和缺点，但大多数都共享一个非常常见的工作流程。为了探索 Golang 本身可能通过 API 提供的其他功能，我们将看看亚马逊云服务。

### 注意

请注意，类似的工具也适用于 Go 的其他云平台。甚至微软的平台 Azure 也有一个专为 Go 编写的客户端库。

## 亚马逊云服务

与前述的许多云服务一样，部署到亚马逊云服务或 AWS 基本上与部署到任何标准物理服务器的基础设施没有太大区别。

不过，AWS 有一些区别。首先是它提供的服务范围。亚马逊不仅仅处理静态虚拟服务器。它还处理一系列支持服务，如 DNS、电子邮件和短信服务（通过他们的 SNS 服务）、长期存储等等。

尽管迄今为止已经说了很多，但请注意，许多备选云服务提供类似的功能，可能与以下示例提供的功能类似。

### 使用 Go 直接与 AWS 进行接口

虽然一些云服务确实提供了某种形式的 API 与其服务配套，但没有一个像亚马逊云服务那样强大。

AWS API 提供了对其环境中的每一个可能操作的直接访问，从添加实例、分配 IP 地址、添加 DNS 条目等等。

正如您所期望的那样，直接与此 API 进行接口可以打开许多可能性，因为它涉及自动化应用程序的健康以及管理更新和错误修复。

要直接与 AWS 进行接口，我们将使用`goamz`包启动我们的应用程序：

```go
package main
import (
    "launchpad.net/goamz/aws"
    "launchpad.net/goamz/ec2"
)
```

### 提示

要获取运行此示例所需的两个依赖项，请运行`go get launchpad.net/goamz/aws`命令和`go get launchpad.net/goamz/ec2`命令。

您可以在[`godoc.org/launchpad.net/goamz`](http://godoc.org/launchpad.net/goamz)找到有关此的其他文档。`goamz`包还包括 Amazon S3 存储服务的包，以及 Amazon 的 SNS 服务和简单数据库服务的一些额外实验性包。

基于镜像启动一个新实例很简单。也许对于习惯于手动部署或通过受控、自动化或自动缩放过程部署的人来说，这太简单了。

```go
    AWSAuth, err := aws.EnvAuth()
    if err != nil {
        fmt.Println(err.Error())
    }
    instance := ec2.New(AWSAuth, aws.USEast)
    instanceOptions := ec2.RunInstances({
        ImageId:      "ami-9eaa1cf6",
        InstanceType: "t2.micro",
    })
```

在这种情况下，`ami-9eaa1cf6`指的是 Ubuntu Server 14.04。

在我们的下一节中，拥有与亚马逊 API 的接口将是重要的，我们将把图像数据从我们的关系数据库中移出，并放入 CDN 中。

# 处理二进制数据和 CDN

您可能还记得在第三章中，*路由和引导*，我们看了如何以 BLOB 格式将二进制数据，特别是图像数据，存储在我们应用程序的数据库中。

当时，我们以一种非常基础的方式处理这个问题，只是简单地将二进制图像数据放入某种存储系统中。

Amazon S3 是 AWS 内容分发/交付网络方面的一部分，它基于桶的概念来收集数据，每个桶都有自己的访问控制权限。需要注意的是，AWS 还提供了一个名为 Cloudfront 的真正 CDN，但 S3 可以用作存储服务。

让我们首先看一下使用`goamz`包在给定存储桶中列出最多 100 个项目：

### 提示

在代码中用您的凭据替换-----------。

```go
package main

import
(
  "fmt"
    "launchpad.net/goamz/aws"
    "launchpad.net/goamz/s3"
)

func main() {
  Auth := aws.Auth { AccessKey: `-----------`, SecretKey: `-----------`, }
  AWSConnection := s3.New(Auth, aws.USEast)

  Bucket := AWSConnection.Bucket("social-images")

    bucketList, err := Bucket.List("", "", "", 100)
    fmt.Println(AWSConnection,Bucket,bucketList,err)  
    if err != nil {
        fmt.Println(err.Error())
    }
    for _, item := range bucketList.Contents {
        fmt.Println(item.Key)
    }
}
```

在我们的社交网络示例中，我们将其作为`/api/user/:id:`端点的一部分处理。

```go
 func UsersUpdate(w http.ResponseWriter, r *http.Request) {
  Response := UpdateResponse{}
  params := mux.Vars(r)
  uid := params["id"]
  email := r.FormValue("email")
  img, _, err := r.FormFile("user_image")
  if err != nil {
    fmt.Println("Image error:")
    fmt.Println(err.Error())
```

返回上传，而不是检查错误并继续尝试处理图像，或者我们继续前进。我们将在这里展示如何处理空值：

```go
  }
  imageData, ierr := ioutil.ReadAll(img)
  if err != nil {
    fmt.Println("Error reading image:")
    fmt.Println(err.Error())
```

在这一点上，我们已经尝试读取图像并提取数据——如果我们不能，我们通过`fmt.Println`或`log.Println`打印响应并跳过剩余的步骤，但不要惊慌，因为我们可以以其他方式继续编辑。

```go
  } else {
    mimeType, _, mimerr := mime.ParseMediaType(string(imageData))
    if mimerr != nil {
      fmt.Println("Error detecting mime:")
      fmt.Println(mimerr.Error())
    } else {
      Auth := aws.Auth { AccessKey: `-----------`, SecretKey: `-----------`, }
      AWSConnection := s3.New(Auth, aws.USEast)
      Bucket := AWSConnection.Bucket("social-images")
      berr := Bucket.Put("FILENAME-HERE", imageData, "", "READ")
      if berr != nil {
        fmt.Println("Error saving to bucket:")
        fmt.Println(berr.Error())
      }
    }
  }
```

在第三章中，*路由和引导*，我们接受了表单中上传的数据，将其转换为 Base64 编码的字符串，并保存在我们的数据库中。

由于我们现在要直接保存图像数据，我们可以跳过这最后一步。我们可以从我们请求中的`FormFile`函数中读取任何内容，并将整个数据发送到我们的 S3 存储桶，如下所示：

```go
    f, _, err := r.FormFile("image1")
    if err != nil {
      fmt.Println(err.Error())
    }
    fileData,_ := ioutil.ReadAll(f)
```

对于这个图像，我们需要确保有一个唯一的标识符，避免竞争条件。

## 检查文件上传的存在

`FormFile()`函数实际上在底层调用`ParseMultipartForm()`，并为文件、文件头和标准错误返回默认值（如果不存在）。

## 使用 net/smtp 发送电子邮件

将我们的 API 和社交网络与辅助工具解耦是一个好主意，可以在我们的系统中创建特定性感，减少这些系统之间的冲突，并为每个系统提供更适当的系统和维护规则。

我们可以很容易地为我们的电子邮件系统配备一个套接字客户端，使系统能够直接监听来自我们 API 的消息。实际上，这只需要几行代码就可以实现：

```go
package main

import
(
  "encoding/json"
  "fmt"
  "net"
)

const
(
  port = ":9000"
)

type Message struct {
  Title string `json:"title"`
  Body string `json:"body"`
  To string `json:"recipient"`
  From string `json:"sender"`
}

func (m Message) Send() {

}
func main() {

  emailQueue,_ := net.Listen("tcp",port)
  for {
    conn, err := emailQueue.Accept()
    if err != nil {

    }
    var message []byte
    var NewEmail Message
    fmt.Fscan(conn,message)
    json.Unmarshal(message,NewEmail)
    NewEmail.Send()
  }

}
```

让我们来看一下实际的发送函数，它将把我们 API 中注册过程中的消息发送到电子邮件服务器：

```go
func (m Message) Send() {
  mailServer := "mail.example.com"
  mailServerQualified := mailServer + ":25"
  mailAuth := smtp.PlainAuth(
        "",
        "[email]",
        "[password]",
        mailServer,
      )
  recip := mail.Address("Nathan Kozyra","nkozyra@gmail.com")
  body := m.Body

  mailHeaders := make(map[string] string)
  mailHeaders["From"] = m.From
  mailHeaders["To"] = recip.toString()
  mailHeaders["Subject"] = m.Title
  mailHeaders["Content-Type"] = "text/plain; charset=\"utf-8\""
  mailHeaders["Content-Transfer-Encoding"] = "base64"
  fullEmailHeader := ""
  for k, v := range mailHeaders {
    fullEmailHeader += base64.StdEncoding.EncodeToString([]byte(body))
  }

  err := smtp.SendMail( mailServerQualified, mailAuth, m.From, m.To, []byte(fullEmailHeader))
  if err != nil {
    fmt.Println("could not send email")
    fmt.Println(err.Error())
  }
}
```

虽然这个系统可以很好地工作，因为我们可以监听 TCP 并接收告诉我们要发送什么和发送到什么地址的消息，但它本身并不特别容错。

我们可以通过使用消息队列系统轻松解决这个问题，接下来我们将使用 RabbitMQ 来看一下。

# RabbitMQ with Go

Web 设计的一个方面，特别与 API 相关，但几乎是任何 Web 堆栈的一部分，是服务器和其他系统之间的消息传递的概念。

它通常被称为**高级消息队列协议**或**AMQP**。它可以成为 API/web 服务的重要组成部分，因为它允许否则分离的服务相互通信，而无需使用另一个 API。

通过消息传递，我们在这里谈论的是可以或应该在发生重要事件时在不同的系统之间共享的通用事物被传递给相关的接收者。

再举个类比，就像手机上的推送通知。当后台应用程序有要通知您的事情时，它会生成警报并通过消息传递系统传递。

以下图表是该系统的基本表示。发送者（S），在我们的情况下是 API，将消息添加到堆栈，然后接收者（R）或电子邮件发送过程将检索这些消息：

![RabbitMQ with Go](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/ms-go-websvc/img/1304OS_09_01.jpg)

我们认为这些过程对 API 特别重要，因为通常有机构希望将 API 与基础设施的其余部分隔离开来。尽管这样做是为了防止 API 资源影响现场站点或允许两个不同的应用程序安全地在相同的数据上运行，但也可以用于允许一个服务接受多个请求，同时允许第二个服务或系统根据资源的允许情况进行处理。

这还为用不同编程语言编写的应用程序提供了非常基本的数据粘合剂。

在我们的 Web 服务中，我们可以使用 AMQP 解决方案告诉我们的电子邮件系统在成功注册后生成欢迎电子邮件。这使我们的核心 API 不必担心这样做，而是可以专注于我们系统的核心。

我们可以通过制定标准消息和标题并将其传递为 JSON 来形式化系统 A 和系统 B 之间的请求的多种方式之一：

```go
type EmailMessage struct {
  Recipient string `json:"to"`
  Sender string `json:"from"`
  Title string `json:"title"`
  Body string `json:"body"`
  SendTime time.Time `json:"sendtime"`
  ContentType string `json:"content-type"`
}
```

以这种方式接收电子邮件，而不是通过开放的 TCP 连接，使我们能够保护消息的完整性。在我们之前的例子中，由于故障、崩溃或关闭而丢失的任何消息将永远丢失。

消息队列，另一方面，就像具有可配置耐久性级别的邮箱一样运作，这使我们能够决定消息应该如何保存，何时过期，以及哪些进程或用户应该访问它们。

在这种情况下，我们使用一个文字消息，作为一个包的一部分交付，将通过队列被我们的邮件服务摄取。在发生灾难性故障的情况下，消息仍将存在，供我们的 SMTP 服务器处理。

另一个重要特性是它能够向消息发起者发送“收据”。在这种情况下，电子邮件系统会告诉 API 或 Web 服务，电子邮件消息已成功从队列中被电子邮件进程取走。

这是在我们简单的 TCP 过程中复制的一些东西。我们必须构建的故障保护和应急措施的数量将使其成为一个非常沉重的独立产品。

幸运的是，在 Go 中集成消息队列是相当简单的：

```go
func Listen() {

  qConn, err := amqp.Dial("amqp://user:pass@domain:port/")
  if err != nil {
    log.Fatal(err)
  }
```

这只是我们与 RabbitMQ 服务器的连接。如果检测到连接出现任何错误，我们将停止该过程。

```go
  qC,err := qConn.Channel()
  if err != nil {
    log.Fatal(err)
  }

  queue, err := qC.QueueDeclare("messages", false, false, false, false, nil)
  if err != nil {
    log.Fatal(err)
  }
```

这里队列的名称有点像 memcache 键或数据库名称一样任意。关键是确保发送和接收机制搜索相同的队列名称：

```go
  messages, err := qC.Consume( queue.Name, "", true, false, false, false, nil)
  waitChan := make(chan int)
  go func() {
    for m := range messages {
      var tmpM Message
      json.Unmarshal(d.Body,tmpM)
      log.Println(tmpM.Title,"message received")
      tmpM.Send()
    }
```

在我们的循环中，我们监听消息并在接收到消息时调用`Send()`方法。在这种情况下，我们传递的是 JSON，然后将其解组为`Message`结构，但这种格式完全取决于您：

```go
  }()

  <- waitChan

}
```

而且，在我们的`main()`函数中，我们需要确保用调用 AMQP 监听器的`Listen()`函数替换我们的无限 TCP 监听器：

```go
func main() {

  Listen()
```

现在，我们有能力从消息队列中接收消息（在电子邮件意义上），这意味着我们只需要在我们的 Web 服务中包含这个功能即可。

在我们讨论的示例用法中，新注册的用户将收到一封电子邮件，提示激活账户。这通常是为了防止使用虚假电子邮件地址进行注册。这并不是一个完全可靠的安全机制，但它确保我们的应用程序可以与拥有真实电子邮件地址的人进行通信。

发送到队列也很容易。

考虑到我们在两个独立应用程序之间共享凭据，将这些内容正式化为一个单独的包是有意义的：

```go
package emailQueue

import
(
  "fmt"
  "log"
  "github.com/streadway/amqp"
)

const
(
  QueueCredentials = "amqp://user:pass@host:port/"
  QueueName = "email"
)

func Listen() {

}

func Send(Recipient string, EmailSubject string, EmailBody string) {

}
```

通过这种方式，我们的 API 和我们的监听器都可以导入我们的`emailQueue`包并共享这些凭据。在我们的`api.go`文件中，添加以下代码：

```go
func UserCreate(w http.ResponseWriter, r *http.Request) {

  ...

  q, err := Database.Exec("INSERT INTO users set user_nickname=?, user_first=?, user_last=?, user_email=?, user_password=?, user_salt=?",NewUser.Name,NewUser.First, NewUser.Last,NewUser.Email,hash,salt)
  if err != nil {
    errorMessage, errorCode := dbErrorParse(err.Error())
    fmt.Println(errorMessage)
    error, httpCode, msg := ErrorMessages(errorCode)
    Response.Error = msg
        Response.ErrorCode = error
    http.Error(w, "Conflict", httpCode)
  } else {

    emailQueue.Send(NewUser.Email,"Welcome to the Social Network","Thanks for joining the Social Network!  Your personal data will help us become billionaires!")

  }
```

在我们的`e-mail.go`进程中：

```go
emailQueue.Listen()
```

### 注意

AMQP 是一个更通用的消息传递接口，具有 RabbitMQ 扩展。您可以在[`github.com/streadway/amqp`](https://github.com/streadway/amqp)上阅读更多信息。

有关 Grab Rabbit Hole 的更多信息，请访问[`github.com/michaelklishin/rabbit-hole`](https://github.com/michaelklishin/rabbit-hole)，或者可以使用`go get github.com/michaelklishin/rabbit-hole`命令进行下载。

# 摘要

通过将 API 的逻辑与我们托管的环境和辅助支持服务分开，我们可以减少功能蔓延和由于非必要功能而导致的崩溃的机会。

在本章中，我们将图像托管从数据库中移到云端，并将原始图像数据和结果引用存储到 S3，这是一个经常用作 CDN 的服务。然后，我们使用 RabbitMQ 演示了如何在部署中利用消息传递。

在这一点上，您应该掌握了将这些服务卸载以及更好地了解部署、更新和优雅重启的可用策略。

在下一章中，我们将开始完成社交网络的最终必要要求，并通过这样做，探索增加我们的 Web 服务的速度、可靠性和整体性能的一些方法。

我们还将引入一个次要服务，允许我们在 SPA 界面内进行社交网络聊天，并扩展我们的图像到 CDN 工作流程，以允许用户创建图库。我们将研究如何通过界面和 API 直接最大化图像呈现和获取的方式。
