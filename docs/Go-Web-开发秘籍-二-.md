# Go Web 开发秘籍（二）

> 原文：[`zh.annas-archive.org/md5/6712F93A50A8E516D2DB7024F42646AC`](https://zh.annas-archive.org/md5/6712F93A50A8E516D2DB7024F42646AC)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第三章：在 Go 中处理会话、错误和缓存

在本章中，我们将涵盖以下示例：

+   创建你的第一个 HTTP 会话

+   使用 Redis 管理你的 HTTP 会话

+   创建你的第一个 HTTP cookie

+   在 Go 中实现缓存

+   在 Go 中实现 HTTP 错误处理

+   在 Web 应用程序中实现登录和注销

# 介绍

有时，我们希望在应用程序级别持久保存用户数据等信息，而不是将其持久保存在数据库中，这可以很容易地通过会话和 cookies 来实现。两者之间的区别在于，会话存储在服务器端，而 cookies 存储在客户端。我们还可能需要缓存静态数据，以避免不必要地调用数据库或 Web 服务，并在开发 Web 应用程序时实现错误处理。通过掌握本章涵盖的概念，我们将能够以相当简单的方式实现所有这些功能。

在本章中，我们将从创建一个 HTTP 会话开始，然后学习如何使用 Redis 进行管理，创建 cookies，缓存 HTTP 响应，实现错误处理，最终以在 Go 中实现登录和注销机制结束。

# 创建你的第一个 HTTP 会话

HTTP 是一个无状态协议，这意味着每次客户端检索网页时，客户端都会打开一个独立的连接到服务器，服务器会对其进行响应，而不保留任何关于先前客户端请求的记录。因此，如果我们想要实现一个机制，让服务器知道客户端发送给它的请求，那么我们可以使用会话来实现。

当我们使用会话时，客户端只需要发送一个 ID，数据就会从服务器加载出来。我们可以在 Web 应用程序中实现这三种方式：

+   Cookies

+   隐藏表单字段

+   URL 重写

在这个示例中，我们将使用 HTTP cookies 来实现一个会话。

# 如何做…

1.  使用`go get`命令安装`github.com/gorilla/sessions`包，如下所示：

```go
$ go get github.com/gorilla/sessions
```

1.  创建`http-session.go`，在其中我们将创建一个 Gorilla cookie 存储来保存和检索会话信息，定义三个处理程序—`/login`、`/home`和`/logout`—在这里我们将创建一个有效的会话 cookie，向 HTTP 响应流写入响应，以及分别使会话 cookie 失效，如下所示：

```go
package main
import 
(
  "fmt"
  "log"
  "net/http"
  "github.com/gorilla/sessions"
)
const 
(
  CONN_HOST = "localhost"
  CONN_PORT = "8080"
)
var store *sessions.CookieStore
func init() 
{
  store = sessions.NewCookieStore([]byte("secret-key"))
}
func home(w http.ResponseWriter, r *http.Request) 
{
  session, _ := store.Get(r, "session-name")
  var authenticated interface{} = session.Values["authenticated"]
  if authenticated != nil 
  {
    isAuthenticated := session.Values["authenticated"].(bool)
    if !isAuthenticated 
    {
      http.Error(w, "You are unauthorized to view the page",
      http.StatusForbidden)
      return
    }
    fmt.Fprintln(w, "Home Page")
  } 
  else 
  {
    http.Error(w, "You are unauthorized to view the page",
    http.StatusForbidden)
    return
  }
}
func login(w http.ResponseWriter, r *http.Request) 
{
  session, _ := store.Get(r, "session-name")
  session.Values["authenticated"] = true
  session.Save(r, w)
  fmt.Fprintln(w, "You have successfully logged in.")
}
func logout(w http.ResponseWriter, r *http.Request) 
{
  session, _ := store.Get(r, "session-name")
  session.Values["authenticated"] = false
  session.Save(r, w)
  fmt.Fprintln(w, "You have successfully logged out.")
}
func main() 
{
  http.HandleFunc("/home", home)
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
$ go run http-session.go
```

# 工作原理…

一旦我们运行程序，HTTP 服务器将在本地监听端口`8080`。

接下来，我们将执行一些命令来看会话是如何工作的。

首先，我们将通过执行以下命令访问`/home`：

```go
$ curl -X GET http://localhost:8080/home
```

这将导致服务器显示未经授权的访问消息，如下面的屏幕截图所示：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/go-webdev-cb/img/90912e34-54a2-44dc-9576-f61fb35e2e58.png)

这是因为我们首先必须登录到一个应用程序，这将创建一个服务器将在提供对任何网页的访问之前验证的会话 ID。所以，让我们登录到应用程序：

```go
$ curl -X GET -i http://localhost:8080/login
```

执行前面的命令将给我们一个`Cookie`，它必须被设置为一个请求头来访问任何网页：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/go-webdev-cb/img/70bc5c54-9374-4701-880e-88cc2d0eb939.png)

接下来，我们将使用提供的`Cookie`来访问`/home`，如下所示：

```go
$ curl --cookie "session-name=MTUyMzEwMTI3NXxEdi1CQkFFQ180SUFBUkFCRUFBQUpmLUNBQUVHYzNSeWFXNW5EQThBRFdGMWRHaGxiblJwWTJGMFpXUUVZbTl2YkFJQ0FBRT18ou7Zxn3qSbqHHiajubn23Eiv8a348AhPl8RN3uTRM4M=;" http://localhost:8080/home
```

这将导致服务器作为响应的主页：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/go-webdev-cb/img/6c042535-965d-417c-910b-2f9b3014aa3b.png)

让我们了解我们编写的 Go 程序：

+   使用`var store *sessions.CookieStore`，我们声明了一个私有的 cookie 存储，用来使用安全的 cookies 来存储会话。

+   使用`func init() { store = sessions.NewCookieStore([]byte("secret-key")) }`，我们定义了一个在`main()`之前运行的`init()`函数，用来创建一个新的 cookie 存储并将其分配给`store`。

`init()`函数总是被调用，无论是否有主函数，所以如果你导入一个包含`init`函数的包，它将被执行。

+   接下来，我们定义了一个`home`处理程序，在那里我们从 cookie 存储中获取一个会话，将其添加到注册表中并使用`store.Get`获取`authenticated`键的值。如果为 true，则我们将`Home Page`写入 HTTP 响应流；否则，我们将写入一个`403`HTTP 代码以及消息 You are unauthorized to view the page.。

+   接下来，我们定义了一个`login`处理程序，在那里我们再次获取一个会话，将`authenticated`键设置为`true`，保存它，最后将 You have successfully logged in.写入 HTTP 响应流。

+   接下来，我们定义了一个`logout`处理程序，在那里我们获取一个会话，将一个`authenticated`键设置为`false`，保存它，最后将 You have successfully logged out.写入 HTTP 响应流。

+   最后，我们定义了`main()`，在那里我们将所有处理程序`home`，`login`和`logout`映射到`/home`，`/login`和`/logout`，并在`localhost:8080`上启动 HTTP 服务器。

# 使用 Redis 管理您的 HTTP 会话

在处理分布式应用程序时，我们可能需要为前端用户实现无状态负载平衡。这样我们就可以将会话信息持久化存储在数据库或文件系统中，以便在服务器关闭或重新启动时识别用户并检索他们的信息。

我们将在这个配方的一部分中使用 Redis 作为持久存储来解决这个问题。

# 准备就绪...

由于我们已经在上一个配方中使用 Gorilla cookie 存储创建了一个会话变量，因此我们只需扩展此配方以将会话信息保存在 Redis 中，而不是在服务器上维护它。

Gorilla 会话存储有多种实现，您可以在`https://github.com/gorilla/sessions#store-implementations`找到。由于我们使用 Redis 作为后端存储，我们将使用`https://github.com/boj/redistore`，它依赖于 Redigo Redis 库来存储会话。

这个配方假设您已经在本地端口`6379`和`4567`上安装并运行了 Redis 和 Redis 浏览器。

# 如何做...

1.  使用`go get`命令安装`gopkg.in/boj/redistore.v1`和`github.com/gorilla/sessions`，如下所示：

```go
$ go get gopkg.in/boj/redistore.v1
$ go get github.com/gorilla/sessions
```

1.  创建`http-session-redis.go`，在那里我们将创建一个`RedisStore`来存储和检索会话变量，如下所示：

```go
package main
import 
(
  "fmt"
  "log"
  "net/http"
  "github.com/gorilla/sessions"
  redisStore "gopkg.in/boj/redistore.v1"
)
const 
(
  CONN_HOST = "localhost"
  CONN_PORT = "8080"
)
var store *redisStore.RediStore
var err error
func init() 
{
  store, err = redisStore.NewRediStore(10, "tcp", ":6379", "",
  []byte("secret-key"))
  if err != nil 
  {
    log.Fatal("error getting redis store : ", err)
  }
}
func home(w http.ResponseWriter, r *http.Request) 
{
  session, _ := store.Get(r, "session-name")
  var authenticated interface{} = session.Values["authenticated"]
  if authenticated != nil 
  {
    isAuthenticated := session.Values["authenticated"].(bool)
    if !isAuthenticated 
    {
      http.Error(w, "You are unauthorized to view the page",
      http.StatusForbidden)
      return
    }
    fmt.Fprintln(w, "Home Page")
  } 
  else 
  {
    http.Error(w, "You are unauthorized to view the page",
    http.StatusForbidden)
    return
  }
}
func login(w http.ResponseWriter, r *http.Request) 
{
  session, _ := store.Get(r, "session-name")
  session.Values["authenticated"] = true
  if err = sessions.Save(r, w); err != nil 
  {
    log.Fatalf("Error saving session: %v", err)
  }
  fmt.Fprintln(w, "You have successfully logged in.")
}
func logout(w http.ResponseWriter, r *http.Request) 
{
  session, _ := store.Get(r, "session-name")
  session.Values["authenticated"] = false
  session.Save(r, w)
  fmt.Fprintln(w, "You have successfully logged out.")
}
func main() 
{
  http.HandleFunc("/home", home)
  http.HandleFunc("/login", login)
  http.HandleFunc("/logout", logout)
  err := http.ListenAndServe(CONN_HOST+":"+CONN_PORT, nil)
  defer store.Close()
  if err != nil 
  {
    log.Fatal("error starting http server : ", err)
    return
  }
}
```

1.  使用以下命令运行程序：

```go
$ go run http-session-redis.go
```

# 它是如何工作的...

运行程序后，HTTP 服务器将在本地端口`8080`上开始监听。

接下来，我们将执行一些命令来看看会话是如何工作的。

首先，我们将通过执行以下命令访问`/home`：

```go
$ curl -X GET http://localhost:8080/home
```

这将导致服务器显示未经授权的访问消息，如下面的屏幕截图所示：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/go-webdev-cb/img/060b9289-61e3-4786-bab8-6be435d42f95.png)

这是因为我们首先必须登录到一个应用程序，这将创建一个服务器将在提供对任何网页的访问之前验证的**会话 ID**。所以，让我们登录到应用程序：

```go
$ curl -X GET -i http://localhost:8080/login
```

执行上一个命令将给我们一个`Cookie`，必须将其设置为请求头以访问任何网页：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/go-webdev-cb/img/75be8a84-1ba2-404b-abb1-3c64d109b0ad.png)

一旦执行了上一个命令，将会创建一个`Cookie`并保存在 Redis 中，您可以通过从`redis-cli`执行命令或在 Redis 浏览器中查看，如下面的屏幕截图所示：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/go-webdev-cb/img/13be0e7f-26c1-42c3-94db-70ae68aa1b54.png)

接下来，我们将使用提供的`Cookie`来访问`/home`，如下所示：

```go
$ curl --cookie "session-name=MTUyMzEwNDUyM3xOd3dBTkV4T1JrdzNURFkyUkVWWlQxWklUekpKVUVOWE1saFRUMHBHVTB4T1RGVXlSRU5RVkZWWk5VeFNWVmRPVVZSQk4wTk1RMUU9fAlGgLGU-OHxoP78xzEHMoiuY0Q4rrbsXfajSS6HiJAm;" http://localhost:8080/home
```

这将导致服务器作为响应的主页：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/go-webdev-cb/img/d723b277-e3d6-463e-95f9-6c8ca2e20624.png)

让我们了解我们在这个配方中引入的更改：

1.  使用`var store *redisStore.RediStore`，我们声明了一个私有的`RediStore`来在 Redis 中存储会话。

1.  接下来，我们更新了`init()`函数，使用大小和最大空闲连接数为`10`创建`NewRediStore`，并将其分配给存储。如果在创建存储时出现错误，我们将记录错误并以状态码`1`退出。

1.  最后，我们更新了`main()`，引入了`defer store.Close()`语句，一旦我们从函数返回，就会关闭 Redis 存储。

# 创建你的第一个 HTTP cookie

在客户端存储信息时，cookie 扮演着重要的角色，我们可以使用它们的值来识别用户。基本上，cookie 是为了解决记住用户信息或持久登录身份验证的问题而发明的，这指的是网站能够在会话之间记住主体的身份。

Cookie 是在互联网上访问网站时 Web 浏览器创建的简单文本文件。您的设备会在本地存储这些文本文件，允许您的浏览器访问 cookie 并将数据传递回原始网站，并以名称-值对的形式保存。

# 如何做到这一点...

1.  使用`go get`命令安装`github.com/gorilla/securecookie`包，如下所示：

```go
$ go get github.com/gorilla/securecookie
```

1.  创建`http-cookie.go`，在其中我们将创建一个 Gorilla 安全 cookie 来存储和检索 cookie，如下所示：

```go
package main
import 
(
  "fmt"
  "log"
  "net/http"
  "github.com/gorilla/securecookie"
)
const 
(
  CONN_HOST = "localhost"
  CONN_PORT = "8080"
)
var cookieHandler *securecookie.SecureCookie
func init() 
{
  cookieHandler = securecookie.New(securecookie.
  GenerateRandomKey(64),
  securecookie.GenerateRandomKey(32))
}
func createCookie(w http.ResponseWriter, r *http.Request) 
{
  value := map[string]string
  {
    "username": "Foo",
  }
  base64Encoded, err := cookieHandler.Encode("key", value)
  if err == nil 
  {
    cookie := &http.Cookie
    {
      Name: "first-cookie",
      Value: base64Encoded,
      Path: "/",
    }
    http.SetCookie(w, cookie)
  }
  w.Write([]byte(fmt.Sprintf("Cookie created.")))
}
func readCookie(w http.ResponseWriter, r *http.Request) 
{
  log.Printf("Reading Cookie..")
  cookie, err := r.Cookie("first-cookie")
  if cookie != nil && err == nil 
  {
    value := make(map[string]string)
    if err = cookieHandler.Decode("key", cookie.Value, &value); 
    err == nil 
    {
      w.Write([]byte(fmt.Sprintf("Hello %v \n", 
      value["username"])))
    }
  } 
  else 
  {
    log.Printf("Cookie not found..")
    w.Write([]byte(fmt.Sprint("Hello")))
  }
}

func main() 
{
  http.HandleFunc("/create", createCookie)
  http.HandleFunc("/read", readCookie)
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
$ go run http-cookie.go
```

# 它是如何工作的...

一旦我们运行程序，HTTP 服务器将在本地监听端口`8080`。

浏览`http://localhost:8080/read`将在浏览器中显示 Hello，如下面的屏幕截图所示：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/go-webdev-cb/img/fa64f000-0212-46be-9698-9aae55c3c804.png)

接下来，我们将访问`http://localhost:8080/create`，这将创建一个名为 first-cookie 的 cookie，并在浏览器中显示 Cookie created 消息：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/go-webdev-cb/img/4f5ab86f-a1ce-4842-b86c-2c57d1906282.png)

现在，随后访问`http://localhost:8080/read`将使用`first-cookie`来显示 Hello，然后是`first-cookie`的值，如下所示：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/go-webdev-cb/img/56a72dba-36a7-48b2-9d0f-bb4f6531db2d.png)

让我们了解我们编写的程序：

+   使用`import ("fmt" "log" "net/http" "github.com/gorilla

/securecookie")`，我们引入了一个额外的包—`github.com/gorilla/securecookie`，我们将使用它来对经过身份验证和加密的 cookie 值进行编码和解码。

+   使用`var cookieHandler *securecookie.SecureCookie`，我们声明了一个私有的安全 cookie。

+   接下来，我们更新了`init()`函数，创建了一个`SecureCookie`，传递了一个 64 字节的哈希密钥，用于使用 HMAC 对值进行身份验证，以及一个 32 字节的块密钥，用于加密值。

+   接下来，我们定义了一个`createCookie`处理程序，在其中使用`gorilla/securecookie`的`Encode`处理程序创建一个以`username`为键，`Foo`为值的`Base64`编码的 cookie。然后，我们向提供的`ResponseWriter`头部添加一个`Set-Cookie`头，并向 HTTP 响应中写入一个`Cookie created.`的消息。

+   接下来，我们定义了一个`readCookie`处理程序，在其中我们从请求中检索一个 cookie，这在我们的代码中是`first-cookie`，为其获取一个值，并将其写入 HTTP 响应。

+   最后，我们定义了`main()`，在其中将所有处理程序—`createCookie`和`readCookie`—映射到`/create`和`/read`，并在`localhost:8080`上启动了 HTTP 服务器。

# 在 Go 中实现缓存

在 Web 应用程序中缓存数据有时是必要的，以避免反复从数据库或外部服务请求静态数据。Go 没有提供任何内置的包来缓存响应，但它通过外部包支持缓存。

有许多包，例如`https://github.com/coocood/freecache`和`https://github.com/patrickmn/go-cache`，可以帮助实现缓存，在本教程中，我们将使用`https://github.com/patrickmn/go-cache`来实现它。

# 如何做到这一点...

1.  使用`go get`命令安装`github.com/patrickmn/go-cache`包，如下所示：

```go
$ go get github.com/patrickmn/go-cache
```

1.  创建`http-caching.go`，在其中我们将在服务器启动时创建一个缓存并填充数据，如下所示：

```go
package main
import 
(
  "fmt"
  "log"
  "net/http"
  "time"
  "github.com/patrickmn/go-cache"
)
const 
(
  CONN_HOST = "localhost"
  CONN_PORT = "8080"
)
var newCache *cache.Cache
func init() 
{
  newCache = cache.New(5*time.Minute, 10*time.Minute)
  newCache.Set("foo", "bar", cache.DefaultExpiration)
}
func getFromCache(w http.ResponseWriter, r *http.Request) 
{
  foo, found := newCache.Get("foo")
  if found 
  {
    log.Print("Key Found in Cache with value as :: ", 
    foo.(string))
    fmt.Fprintf(w, "Hello "+foo.(string))
  } 
  else 
  {
    log.Print("Key Not Found in Cache :: ", "foo")
    fmt.Fprintf(w, "Key Not Found in Cache")
  }
}
func main() 
{
  http.HandleFunc("/", getFromCache)
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
$ go run http-caching.go
```

# 它是如何工作的…

一旦我们运行程序，HTTP 服务器将在本地监听端口`8080`。

在启动时，具有名称`foo`和值为`bar`的键将被添加到缓存中。

浏览`http://localhost:8080/`将从缓存中读取一个键值，并将其附加到 Hello，如下截图所示：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/go-webdev-cb/img/42c7eeff-5a4e-4c2a-bc9a-d125b604ae54.png)

我们在程序中指定了缓存数据的过期时间为五分钟，这意味着我们在服务器启动时在缓存中创建的键在五分钟后将不再存在。因此，五分钟后再次访问相同的 URL 将从服务器返回缓存中找不到键的消息，如下所示：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/go-webdev-cb/img/ced8f589-c0f6-4016-b5a6-0d7e80003110.png)

让我们理解我们编写的程序：

1.  使用`var newCache *cache.Cache`，我们声明了一个私有缓存。

1.  接下来，我们更新了`init()`函数，在其中创建了一个具有五分钟过期时间和十分钟清理间隔的缓存，并向缓存中添加了一个键为`foo`，值为`bar`，过期值为`0`的项目，这意味着我们要使用缓存的默认过期时间。

如果过期持续时间小于一（或`NoExpiration`），则缓存中的项目永远不会过期（默认情况下），必须手动删除。如果清理间隔小于一，则在调用`c.DeleteExpired()`之前不会从缓存中删除过期的项目。

1.  接下来，我们定义了`getFromCache`处理程序，从缓存中检索键的值。如果找到，我们将其写入 HTTP 响应；否则，我们将`Key Not Found in Cache`的消息写入 HTTP 响应。

# 在 Go 中实现 HTTP 错误处理

在任何 Web 应用程序中实现错误处理是主要方面之一，因为它有助于更快地进行故障排除和修复错误。错误处理意味着每当应用程序发生错误时，应该将其记录在某个地方，无论是在文件中还是在数据库中，都应该有适当的错误消息以及堆栈跟踪。

在 Go 中，可以以多种方式实现。一种方法是编写自定义处理程序，我们将在本教程中介绍。

# 如何做…

1.  使用`go get`命令安装`github.com/gorilla/mux`包，如下所示：

```go
$ go get github.com/gorilla/mux
```

1.  创建`http-error-handling.go`，在其中我们将创建一个自定义处理程序，作为处理所有 HTTP 请求的包装器，如下所示：

```go
package main
import 
(
  "errors"
  "fmt"
  "log"
  "net/http"
  "strings"
  "github.com/gorilla/mux"
)
const 
(
  CONN_HOST = "localhost"
  CONN_PORT = "8080"
)
type NameNotFoundError struct 
{
  Code int
  Err error
}
func (nameNotFoundError NameNotFoundError) Error() string 
{
  return nameNotFoundError.Err.Error()
}
type WrapperHandler func(http.ResponseWriter, *http.Request) 
error
func (wrapperHandler WrapperHandler) ServeHTTP(w http.
ResponseWriter, r *http.Request) 
{
  err := wrapperHandler(w, r)
  if err != nil 
  {
    switch e := err.(type) 
    {
      case NameNotFoundError:
      log.Printf("HTTP %s - %d", e.Err, e.Code)
      http.Error(w, e.Err.Error(), e.Code)
      default:
      http.Error(w, http.StatusText(http.
      StatusInternalServerError),
      http.StatusInternalServerError)
    }
  }
}
func getName(w http.ResponseWriter, r *http.Request) error 
{
  vars := mux.Vars(r)
  name := vars["name"]
  if strings.EqualFold(name, "foo") 
  {
    fmt.Fprintf(w, "Hello "+name)
    return nil
  } 
  else 
  {
    return NameNotFoundError{500, errors.New("Name Not Found")}
  }
}
func main() 
{
  router := mux.NewRouter()
  router.Handle("/employee/get/{name}",
  WrapperHandler(getName)).Methods("GET")
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
$ go run http-error-handling.go
```

# 它是如何工作的…

一旦我们运行程序，HTTP 服务器将在本地监听端口`8080`。

接下来，浏览`http://localhost:8080/employee/get/foo`将在浏览器中作为响应给我们 Hello，后跟员工姓名和状态码为`200`：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/go-webdev-cb/img/35f4f25b-54f5-4ab0-9c0f-a4103482a04d.png)

另一方面，访问`http://localhost:8080/employee/get/bar`将返回一个带有消息 Name Not Found 和错误代码`500`的 HTTP 错误：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/go-webdev-cb/img/84a2f72f-5760-4af1-bd09-675a3cc4206b.png)

让我们理解我们编写的程序：

1.  我们定义了一个`NameNotFoundError`结构，它有两个字段——类型为`int`的`Code`和类型为`error`的`Err`，它表示一个带有关联 HTTP 状态码的错误，如下所示：

```go
type NameNotFoundError struct 
{
  Code int
  Err error
}
```

1.  然后，我们允许`NameNotFoundError`满足错误接口，如下所示：

```go
func (nameNotFoundError NameNotFoundError) Error() string 
{
  return nameNotFoundError.Err.Error()
}
```

1.  接下来，我们定义了一个用户定义类型`WrapperHandler`，它是一个接受任何接受`func(http.ResponseWriter, *http.Request)`作为输入参数并返回错误的处理程序的 Go 函数。

1.  然后，我们定义了一个`ServeHTTP`处理程序，它调用我们传递给`WrapperHandler`的处理程序，将`(http.ResponseWriter, *http.Request)`作为参数传递给它，并检查处理程序是否返回任何错误。如果有错误，则使用 switch case 适当处理它们，如下所示：

```go
if err != nil 
{
  switch e := err.(type) 
  {
    case NameNotFoundError:
    log.Printf("HTTP %s - %d", e.Err, e.Code)
    http.Error(w, e.Err.Error(), e.Code)
    default:
    http.Error(w, http.StatusText(http.
    StatusInternalServerError),
    http.StatusInternalServerError)
  }
}
```

1.  接下来，我们定义了`getName`处理程序，它提取请求路径变量，获取`name`变量的值，并检查名称是否匹配`foo`。如果是，则将 Hello，后跟名称，写入 HTTP 响应；否则，它将返回一个`Code`字段值为`500`的`NameNotFoundError`结构和一个`err`字段值为`error`的文本`Name Not Found`。

1.  最后，我们定义了`main()`，在其中将`WrapperHandler`注册为 URL 模式`/get/{name}`的处理程序。

# 在 Web 应用程序中实现登录和注销

每当我们希望应用程序只能被注册用户访问时，我们都必须实现一个机制，在允许他们查看任何网页之前要求用户提供凭据，这将在本示例中进行介绍。

# 准备工作…

由于我们已经在之前的示例中创建了一个 HTML 表单，我们只需更新它以使用`gorilla/securecookie`包实现登录和注销机制。

在第二章的*使用模板、静态文件和 HTML 表单*中查看*在 Web 应用程序中实现登录和注销*的示例。

# 如何做…

1.  使用`go get`命令安装`github.com/gorilla/mux`和`github.com/gorilla/securecookie`，如下所示：

```go
$ go get github.com/gorilla/mux
$ go get github.com/gorilla/securecookie
```

1.  在`templates`目录中创建`home.html`，如下所示：

```go
$ mkdir templates && cd templates && touch home.html
```

1.  将以下内容复制到`home.html`：

```go
<html>
  <head>
    <title></title>
  </head>
  <body>
    <h1>Welcome {{.userName}}!</h1>
    <form method="post" action="/logout">
      <button type="submit">Logout</button>
    </form>
  </body>
</html>
```

在上述模板中，我们定义了一个占位符`{{.userName}}`，其值将在运行时由模板引擎替换，以及一个注销按钮。点击注销按钮后，客户端将对表单动作进行`POST`调用，这在我们的例子中是`/logout`。

1.  创建`html-form-login-logout.go`，在这里我们将解析登录表单，读取用户名字段，并在用户点击登录按钮时设置会话 cookie。用户点击注销按钮后，我们也会清除会话，如下所示：

```go
package main
import 
(
  "html/template"
  "log"
  "net/http"
  "github.com/gorilla/mux"
  "github.com/gorilla/securecookie"
)
const 
(
  CONN_HOST = "localhost"
  CONN_PORT = "8080"
)
var cookieHandler = securecookie.New
(
  securecookie.GenerateRandomKey(64),
  securecookie.GenerateRandomKey(32)
)
func getUserName(request *http.Request) (userName string) 
{
  cookie, err := request.Cookie("session")
  if err == nil 
  {
    cookieValue := make(map[string]string)
    err = cookieHandler.Decode("session", cookie.Value,
    &cookieValue)
    if err == nil 
    {
      userName = cookieValue["username"]
    }
  }
  return userName
}
func setSession(userName string, response http.ResponseWriter) 
{
  value := map[string]string
  {
    "username": userName,
  }
  encoded, err := cookieHandler.Encode("session", value)
  if err == nil 
  {
    cookie := &http.Cookie
    {
      Name: "session",
      Value: encoded,
      Path: "/",
    }
    http.SetCookie(response, cookie)
  }
}
func clearSession(response http.ResponseWriter) 
{
  cookie := &http.Cookie
  {
    Name: "session",
    Value: "",
    Path: "/",
    MaxAge: -1,
  }
  http.SetCookie(response, cookie)
}
func login(response http.ResponseWriter, request *http.Request) 
{
  username := request.FormValue("username")
  password := request.FormValue("password")
  target := "/"
  if username != "" && password != "" 
  {
    setSession(username, response)
    target = "/home"
  }
  http.Redirect(response, request, target, 302)
}
func logout(response http.ResponseWriter, request *http.Request) 
{
  clearSession(response)
  http.Redirect(response, request, "/", 302)
}
func loginPage(w http.ResponseWriter, r *http.Request) 
{
  parsedTemplate, _ := template.ParseFiles("templates/
  login-form.html")
  parsedTemplate.Execute(w, nil)
}
func homePage(response http.ResponseWriter, request *http.Request) 
{
  userName := getUserName(request)
  if userName != "" 
  {
    data := map[string]interface{}
    {
      "userName": userName,
    }
    parsedTemplate, _ := template.ParseFiles("templates/home.html")
    parsedTemplate.Execute(response, data)
  } 
  else 
  {
    http.Redirect(response, request, "/", 302)
  }
}
func main() 
{
  var router = mux.NewRouter()
  router.HandleFunc("/", loginPage)
  router.HandleFunc("/home", homePage)
  router.HandleFunc("/login", login).Methods("POST")
  router.HandleFunc("/logout", logout).Methods("POST")
  http.Handle("/", router)
  err := http.ListenAndServe(CONN_HOST+":"+CONN_PORT, nil)
  if err != nil 
  {
    log.Fatal("error starting http server : ", err)
    return
  }
}
```

一切就绪后，目录结构应如下所示：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/go-webdev-cb/img/ae457fe4-65c1-46ed-ab4e-3998905c80b1.png)

1.  使用以下命令运行程序：

```go
$ go run html-form-login-logout.go
```

# 工作原理…

一旦我们运行程序，HTTP 服务器将在本地的 8080 端口上开始监听。

接下来，浏览`http://localhost:8080`将显示我们的登录表单，如下截图所示：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/go-webdev-cb/img/d3e86f3e-8cee-4306-a391-29d2e021ccfe.png)

在输入用户名`Foo`和随机密码后提交表单将在浏览器中显示欢迎 Foo!消息，并创建一个名为 session 的 cookie，用于管理用户的登录/注销状态：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/go-webdev-cb/img/bdf572bb-d0f3-49b5-95c7-b5cc9f0f43af.png)

现在，直到名为 session 的 cookie 存在，对`http://localhost:8080/home`的每个后续请求都将在浏览器中显示欢迎 Foo!消息。

接下来，清除 cookie 后访问`http://localhost:8080/home`将重定向我们到`http://localhost:8080/`并显示登录表单：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/go-webdev-cb/img/9bb677a6-44ea-4603-a5a6-28590d64ed97.png)

让我们了解我们编写的程序。

1.  使用`var cookieHandler = securecookie.New(securecookie.

使用`GenerateRandomKey(64), securecookie.GenerateRandomKey(32))`，我们创建了一个安全 cookie，将哈希密钥作为第一个参数，块密钥作为第二个参数。哈希密钥用于使用 HMAC 对值进行身份验证，块密钥用于加密值。

1.  接下来，我们定义了`getUserName`处理程序，从 HTTP 请求中获取一个 cookie，初始化一个字符串`键`到字符串`值`的`cookieValue`映射，解码一个 cookie，并获取用户名的值并返回。

1.  接下来，我们定义了`setSession`处理程序，其中我们创建并初始化一个带有`key`和`value`的映射，将其序列化，使用消息认证码对其进行签名，使用`cookieHandler.Encode`处理程序对其进行编码，创建一个新的 HTTP cookie，并将其写入 HTTP 响应流。

1.  接下来，我们定义了`clearSession`，它基本上将 cookie 的值设置为空，并将其写入 HTTP 响应流。

1.  接下来，我们定义了一个`login`处理程序，在这里，我们从 HTTP 表单中获取用户名和密码，检查两者是否都不为空，然后调用`setSession`处理程序并重定向到`/home`，否则重定向到根 URL`/`。

1.  接下来，我们定义了一个`logout`处理程序，在这里，我们调用`clearSession`处理程序清除会话值，并重定向到根 URL。

1.  接下来，我们定义了一个`loginPage`处理程序，在这里，我们解析`login-form.html`，返回一个具有名称和内容的新模板，调用已解析模板上的`Execute`处理程序，生成 HTML 输出，并将其写入 HTTP 响应流。

1.  接下来，我们定义了一个`homePage`处理程序，该处理程序从调用`getUserName`处理程序的 HTTP 请求中获取用户名。然后，我们检查它是否不为空或是否存在 cookie 值。如果用户名不为空，我们解析`home.html`，将用户名注入数据映射，生成 HTML 输出，并将其写入 HTTP 响应流；否则，我们将其重定向到根 URL`/`。

最后，我们定义了`main()`方法，我们在这里启动程序执行。由于这个方法做了很多事情，让我们逐行查看它：

+   `var router = mux.NewRouter()`: 在这里，我们创建了一个新的路由器实例。

+   `router.HandleFunc("/", loginPage)`: 在这里，我们使用`gorilla/mux`包的`HandleFunc`注册了`loginPageHandler`处理程序，并使用`/` URL 模式，这意味着每当我们访问具有`/`模式的 HTTP URL 时，`loginPage`处理程序将通过传递`(http.ResponseWriter, *http.Request)`作为参数来执行。

+   `router.HandleFunc("/home", homePage)`: 在这里，我们使用`gorilla/mux`包的`HandleFunc`注册了`homePageHandler`处理程序，并使用`/home` URL 模式，这意味着每当我们访问具有`/home`模式的 HTTP URL 时，`homePage`处理程序将通过传递`(http.ResponseWriter, *http.Request)`作为参数来执行。

+   `router.HandleFunc("/login", login).Methods("POST")`: 在这里，我们使用`gorilla/mux`包的`HandleFunc`注册了`loginHandler`处理程序，并使用`/login` URL 模式，这意味着每当我们访问具有`/login`模式的 HTTP URL 时，`login`处理程序将通过传递`(http.ResponseWriter, *http.Request)`作为参数来执行。

+   `router.HandleFunc("/logout", logout).Methods("POST")`: 在这里，我们使用`gorilla/mux`包的`HandleFunc`注册了`logoutHandler`处理程序，并使用`/logout` URL 模式，这意味着每当我们访问具有`/logout`模式的 HTTP URL 时，`logout`处理程序将通过传递`(http.ResponseWriter, *http.Request)`作为参数来执行。

+   `http.Handle("/", router)`: 在这里，我们使用`net/http`包的`HandleFunc`为`/` URL 模式注册了路由器，这意味着所有具有`/` URL 模式的请求都由路由器处理。

+   `err := http.ListenAndServe(CONN_HOST+":"+CONN_PORT, nil)`: 在这里，我们调用`http.ListenAndServe`来提供处理每个传入连接的 HTTP 请求的请求。`ListenAndServe`接受两个参数——服务器地址和处理程序，其中服务器地址为`localhost:8080`，处理程序为`nil`，这意味着我们要求服务器使用`DefaultServeMux`作为处理程序。

+   `if err != nil { log.Fatal("error starting http server : ", err) return}`: 在这里，我们检查是否有任何启动服务器的问题。如果有，记录错误并以状态码`1`退出。


# 第四章：在 Go 中编写和使用 RESTful Web 服务

在本章中，我们将涵盖以下内容：

+   创建你的第一个 HTTP GET 方法

+   创建你的第一个 HTTP POST 方法

+   创建你的第一个 HTTP PUT 方法

+   创建你的第一个 HTTP DELETE 方法

+   对你的 REST API 进行版本控制

+   创建你的第一个 REST 客户端

+   创建你的第一个 AngularJS 客户端

+   创建你的第一个 ReactJS 客户端

+   创建你的第一个 VueJS 客户端

# 介绍

每当我们构建一个封装了对其他相关应用有帮助的逻辑的 Web 应用程序时，我们通常也会编写和使用 Web 服务。这是因为它们通过网络公开功能，可以通过 HTTP 协议访问，使应用程序成为唯一的真相来源。

在本章中，我们将编写一个支持`GET`，`POST`，`PUT`和`DELETE` HTTP 方法的 RESTful API，然后我们将学习如何对 REST API 进行版本控制，这在我们创建公开使用的 API 时非常有帮助。最后，我们将编写 REST 客户端来消耗它们。

# 创建你的第一个 HTTP GET 方法

在编写 Web 应用程序时，我们经常需要将我们的服务暴露给客户端或 UI，以便它们可以消耗在不同系统上运行的代码。通过 HTTP 协议方法可以暴露服务。在许多 HTTP 方法中，我们将学习在本教程中实现 HTTP `GET`方法。

# 如何做...

1.  使用`go get`命令安装`github.com/gorilla/mux`包，如下所示：

```go
$ go get github.com/gorilla/mux
```

1.  创建`http-rest-get.go`，在其中我们将定义两个路由—`/employees`和`/employee/{id}`以及它们的处理程序。前者写入员工的静态数组，后者将为提供的 ID 写入相应 ID 的员工详情到 HTTP 响应流，如下所示：

```go
package main
import 
(
  "encoding/json"
  "log"
  "net/http"
  "github.com/gorilla/mux"
)
const 
(
  CONN_HOST = "localhost"
  CONN_PORT = "8080"
)
type Route struct 
{
  Name string
  Method string
  Pattern string
  HandlerFunc http.HandlerFunc
}
type Routes []Route
var routes = Routes
{
  Route
  {
    "getEmployees",
    "GET",
    "/employees",
    getEmployees,
  },
  Route
  {
    "getEmployee",
    "GET",
    "/employee/{id}",
    getEmployee,
  },
}
type Employee struct 
{
  Id string `json:"id"`
  FirstName string `json:"firstName"`
  LastName string `json:"lastName"`
}
type Employees []Employee
var employees []Employee
func init() 
{
  employees = Employees
  {
    Employee{Id: "1", FirstName: "Foo", LastName: "Bar"},
    Employee{Id: "2", FirstName: "Baz", LastName: "Qux"},
  }
}
func getEmployees(w http.ResponseWriter, r *http.Request) 
{
  json.NewEncoder(w).Encode(employees)
}
func getEmployee(w http.ResponseWriter, r *http.Request) 
{
  vars := mux.Vars(r)
  id := vars["id"]
  for _, employee := range employees 
  {
    if employee.Id == id 
    {
      if err := json.NewEncoder(w).Encode(employee); err != nil 
      {
        log.Print("error getting requested employee :: ", err)
      }
    }
  }
}
func AddRoutes(router *mux.Router) *mux.Router 
{
  for _, route := range routes 
  {
    router.
    Methods(route.Method).
    Path(route.Pattern).
    Name(route.Name).
    Handler(route.HandlerFunc)
  }
  return router
}
func main() 
{
  muxRouter := mux.NewRouter().StrictSlash(true)
  router := AddRoutes(muxRouter)
  err := http.ListenAndServe(CONN_HOST+":"+CONN_PORT, router)
  if err != nil 
  {
    log.Fatal("error starting http server :: ", err)
    return
  }
}
```

1.  使用以下命令运行程序：

```go
$ go run http-rest-get.go
```

# 它是如何工作的...

一旦我们运行程序，HTTP 服务器将在本地监听端口`8080`上启动。

接下来，从命令行执行`GET`请求如下将给你一个员工列表：

```go
$ curl -X GET http://localhost:8080/employees
[{"id":"1","firstName":"Foo","lastName":"Bar"},{"id":"2","firstName":"Baz","lastName":"Qux"}]
```

在这里，从命令行执行`GET`请求获取特定员工 ID，将为你提供相应 ID 的员工详情：

```go
$ curl -X GET http://localhost:8080/employee/1
 {"id":"1","firstName":"Foo","lastName":"Bar"}
```

让我们了解我们编写的程序：

1.  我们使用了`import ("encoding/json" "log" "net/http" "strconv" "github.com/gorilla/mux")`。在这里，我们导入了`github.com/gorilla/mux`来创建一个`Gorilla Mux Router`。

1.  接下来，我们声明了`Route`结构类型，具有四个字段—`Name`，`Method`，`Pattern`和`HandlerFunc`，其中`Name`表示 HTTP 方法的名称，`Method`表示 HTTP 方法类型，可以是`GET`，`POST`，`PUT`，`DELETE`等，`Pattern`表示 URL 路径，`HandlerFunc`表示 HTTP 处理程序。

1.  接下来，我们为`GET`请求定义了两个路由，如下：

```go
var routes = Routes
{
  Route
  {
    "getEmployees",
    "GET",
    "/employees",
    getEmployees,
  },
  Route
  {
    "getEmployee",
    "GET",
    "/employee/{id}",
    getEmployee,
  },
}
```

1.  接下来，我们定义了一个静态的`Employees`数组，如下：

```go
func init() 
{
  employees = Employees 
  {
    Employee{Id: "1", FirstName: "Foo", LastName: "Bar"},
    Employee{Id: "2", FirstName: "Baz", LastName: "Qux"},
  }
}
```

1.  然后，我们定义了两个处理程序—`getEmployees`和`getEmployee`，前者只是将员工的静态数组编组并将其写入 HTTP 响应流，后者从 HTTP 请求变量获取员工 ID，从数组中获取相应 ID 的员工，编组对象，并将其写入 HTTP 响应流。

1.  在处理程序之后，我们定义了一个`AddRoutes`函数，它遍历我们定义的路由数组，将其添加到`gorilla/mux`路由器，并返回`Router`对象。

1.  最后，我们定义了`main()`，在其中使用`NewRouter()`处理程序创建了一个`gorilla/mux`路由器实例，对于新路由的尾部斜杠行为为 true，这意味着应用程序将始终将路径视为路由中指定的路径。例如，如果路由路径是`/path/`，访问`/path`将重定向到前者，反之亦然。

# 创建你的第一个 HTTP POST 方法

每当我们需要通过异步调用或 HTML 表单将数据发送到服务器时，我们使用 HTTP `POST`方法的实现，这将在本教程中介绍。

# 如何做...

1.  使用以下命令安装`github.com/gorilla/mux`包，如下所示：

```go
$ go get github.com/gorilla/mux
```

1.  创建`http-rest-post.go`，在其中我们将定义一个支持 HTTP `POST`方法的附加路由和一个处理程序，该处理程序将员工添加到初始静态数组的员工，并将更新后的列表写入 HTTP 响应流，如下所示：

```go
package main
import 
(
  "encoding/json"
  "log"
  "net/http"
  "github.com/gorilla/mux"
)
const 
(
  CONN_HOST = "localhost"
  CONN_PORT = "8080"
)
type Route struct 
{
  Name string
  Method string
  Pattern string
  HandlerFunc http.HandlerFunc
}
type Routes []Route
var routes = Routes
{
  Route
  {
    "getEmployees",
    "GET",
    "/employees",
    getEmployees,
  },
  Route
  {
    "addEmployee",
    "POST",
    "/employee/add",
    addEmployee,
  },
}
type Employee struct 
{
  Id string `json:"id"`
  FirstName string `json:"firstName"`
  LastName string `json:"lastName"`
}
type Employees []Employee
var employees []Employee
func init() 
{
  employees = Employees
  {
    Employee{Id: "1", FirstName: "Foo", LastName: "Bar"},
    Employee{Id: "2", FirstName: "Baz", LastName: "Qux"},
  }
}
func getEmployees(w http.ResponseWriter, r *http.Request) 
{
  json.NewEncoder(w).Encode(employees)
}
func addEmployee(w http.ResponseWriter, r *http.Request) 
{
  employee := Employee{}
  err := json.NewDecoder(r.Body).Decode(&employee)
  if err != nil 
  {
    log.Print("error occurred while decoding employee 
    data :: ", err)
    return
  }
  log.Printf("adding employee id :: %s with firstName 
  as :: %s and lastName as :: %s ", employee.Id, 
  employee.FirstName, employee.LastName)
  employees = append(employees, Employee{Id: employee.Id, 
  FirstName: employee.FirstName, LastName: employee.LastName})
  json.NewEncoder(w).Encode(employees)
}
func AddRoutes(router *mux.Router) *mux.Router 
{
  for _, route := range routes 
  {
    router.
    Methods(route.Method).
    Path(route.Pattern).
    Name(route.Name).
    Handler(route.HandlerFunc)
  }
  return router
}
func main() 
{
  muxRouter := mux.NewRouter().StrictSlash(true)
  router := AddRoutes(muxRouter)
  err := http.ListenAndServe(CONN_HOST+":"+CONN_PORT, router)
  if err != nil 
  {
    log.Fatal("error starting http server :: ", err)
    return
  }
}
```

1.  使用以下命令运行程序：

```go
$ go run http-rest-post.go
```

# 工作原理…

运行程序后，HTTP 服务器将在本地监听端口`8080`。

接下来，使用以下命令从命令行执行`POST`请求将员工添加到具有`ID`为`3`的列表，并将员工列表作为响应返回：

```go
$ curl -H "Content-Type: application/json" -X POST -d '{"Id":"3", "firstName":"Quux", "lastName":"Corge"}' http://localhost:8080/employee/add
```

这可以在以下截图中看到：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/go-webdev-cb/img/50fb9970-5845-4bfe-b5b9-a9145541375d.png)

让我们了解本节中引入的更改：

1.  首先，我们添加了另一个名为`addEmployee`的路由，该路由为 URL 模式`/employee/add`的每个`POST`请求执行`addEmployee`处理程序。

1.  然后，我们定义了一个`addEmployee`处理程序，它基本上解码了作为`POST`请求的一部分传递的员工数据，使用 Go 的内置`encoding/json`包的`NewDecoder`处理程序将其附加到员工的初始静态数组，并将其写入 HTTP 响应流。

# 创建您的第一个 HTTP PUT 方法

每当我们想要更新我们之前创建的记录或者如果记录不存在则创建新记录，通常称为**Upsert**，我们就会使用 HTTP `PUT`方法的实现，我们将在本节中介绍。

# 操作步骤…

1.  使用`go get`命令安装`github.com/gorilla/mux`包，如下所示：

```go
$ go get github.com/gorilla/mux
```

1.  创建`http-rest-put.go`，在其中我们将定义一个支持 HTTP `PUT`方法的附加路由和一个处理程序，该处理程序要么更新提供的 ID 的员工详细信息，要么将员工添加到初始静态数组的员工；如果 ID 不存在，则将其编组为 JSON，并将其写入 HTTP 响应流，如下所示：

```go
package main
import 
(
  "encoding/json"
  "log"
  "net/http"
  "github.com/gorilla/mux"
)
const 
(
  CONN_HOST = "localhost"
  CONN_PORT = "8080"
)
type Route struct 
{
  Name string
  Method string
  Pattern string
  HandlerFunc http.HandlerFunc
}
type Routes []Route
var routes = Routes
{
  Route
  {
    "getEmployees",
    "GET",
    "/employees",
    getEmployees,
  },
  Route
  {
    "addEmployee",
    "POST",
    "/employee/add",
    addEmployee,
  },
  Route
  {
    "updateEmployee",
    "PUT",
    "/employee/update",
    updateEmployee,
  },
}
type Employee struct 
{
  Id string `json:"id"`
  FirstName string `json:"firstName"`
  LastName string `json:"lastName"`
}
type Employees []Employee
var employees []Employee
func init() 
{
  employees = Employees
  {
    Employee{Id: "1", FirstName: "Foo", LastName: "Bar"},
    Employee{Id: "2", FirstName: "Baz", LastName: "Qux"},
  }
}
func getEmployees(w http.ResponseWriter, r *http.Request) 
{
  json.NewEncoder(w).Encode(employees)
}
func updateEmployee(w http.ResponseWriter, r *http.Request) 
{
  employee := Employee{}
  err := json.NewDecoder(r.Body).Decode(&employee)
  if err != nil 
  {
    log.Print("error occurred while decoding employee 
    data :: ", err)
    return
  }
  var isUpsert = true
  for idx, emp := range employees 
  {
    if emp.Id == employee.Id 
    {
      isUpsert = false
      log.Printf("updating employee id :: %s with 
      firstName as :: %s and lastName as:: %s ", 
      employee.Id, employee.FirstName, employee.LastName)
      employees[idx].FirstName = employee.FirstName
      employees[idx].LastName = employee.LastName
      break
    }
  }
  if isUpsert 
  {
    log.Printf("upserting employee id :: %s with 
    firstName as :: %s and lastName as:: %s ", 
    employee.Id, employee.FirstName, employee.LastName)
    employees = append(employees, Employee{Id: employee.Id,
    FirstName: employee.FirstName, LastName: employee.LastName})
  }
  json.NewEncoder(w).Encode(employees)
}
func addEmployee(w http.ResponseWriter, r *http.Request) 
{
  employee := Employee{}
  err := json.NewDecoder(r.Body).Decode(&employee)
  if err != nil 
  {
    log.Print("error occurred while decoding employee 
    data :: ", err)
    return
  }
  log.Printf("adding employee id :: %s with firstName 
  as :: %s and lastName as :: %s ", employee.Id, 
  employee.FirstName, employee.LastName)
  employees = append(employees, Employee{Id: employee.Id, 
  FirstName: employee.FirstName, LastName: employee.LastName})
  json.NewEncoder(w).Encode(employees)
}
func AddRoutes(router *mux.Router) *mux.Router 
{
  for _, route := range routes 
  {
    router.
    Methods(route.Method).
    Path(route.Pattern).
    Name(route.Name).
    Handler(route.HandlerFunc)
  }
  return router
}
func main() 
{
  muxRouter := mux.NewRouter().StrictSlash(true)
  router := AddRoutes(muxRouter)
  err := http.ListenAndServe(CONN_HOST+":"+CONN_PORT, router)
  if err != nil 
  {
    log.Fatal("error starting http server :: ", err)
    return
  }
}
```

1.  使用以下命令运行程序：

```go
$ go run http-rest-put.go
```

# 工作原理…

运行程序后，HTTP 服务器将在本地监听端口`8080`。

接下来，使用以下命令从命令行执行`PUT`请求，将为具有 ID `1`的员工更新`firstName`和`lastName`：

```go
$ curl -H "Content-Type: application/json" -X PUT -d '{"Id":"1", "firstName":"Grault", "lastName":"Garply"}' http://localhost:8080/employee/update
```

这可以在以下截图中看到：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/go-webdev-cb/img/35526607-03fd-4d3b-80a1-77bcdf89de43.png)

如果我们从命令行执行`PUT`请求，为具有 ID `3`的员工添加另一个员工到数组中，因为没有 ID 为 3 的员工，这演示了 upsert 场景：

```go
$ curl -H "Content-Type: application/json" -X PUT -d '{"Id":"3", "firstName":"Quux", "lastName":"Corge"}' http://localhost:8080/employee/update
```

这可以在以下截图中看到：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/go-webdev-cb/img/e7a429b0-4bb7-4fc3-a4f1-ab29b4540853.png)

让我们了解本节中引入的更改：

1.  首先，我们添加了另一个名为`updateEmployee`的路由，该路由为 URL 模式`/employee/update`的每个`PUT`请求执行`updateEmployee`处理程序。

1.  然后，我们定义了一个`updateEmployee`处理程序，它基本上解码了作为`PUT`请求的一部分传递的员工数据，使用 Go 的内置`encoding/json`包的`NewDecoder`处理程序迭代员工数组以了解员工 ID 请求是否存在于员工的初始静态数组中，我们也可以称之为 UPDATE 或 UPSERT 场景，执行所需的操作，并将响应写入 HTTP 响应流。

# 创建您的第一个 HTTP DELETE 方法

每当我们想要删除不再需要的记录时，我们就会使用 HTTP `DELETE`方法的实现，我们将在本节中介绍。

# 工作原理…

1.  使用`go get`命令安装`github.com/gorilla/mux`包，如下所示：

```go
$ go get github.com/gorilla/mux
```

1.  创建`http-rest-delete.go`，在其中我们将定义一个支持 HTTP `DELETE`方法的路由和一个处理程序，该处理程序从员工的静态数组中删除提供的 ID 的员工详细信息，将数组编组为 JSON，并将其写入 HTTP 响应流，如下所示：

```go
package main
import 
(
  "encoding/json"
  "log"
  "net/http"
  "github.com/gorilla/mux"
)
const 
(
  CONN_HOST = "localhost"
  CONN_PORT = "8080"
)
type Route struct 
{
  Name string
  Method string
  Pattern string
  HandlerFunc http.HandlerFunc
}
type Routes []Route
var routes = Routes
{
  Route
  {
    "getEmployees",
    "GET",
    "/employees",
    getEmployees,
  },
  Route
  {
    "addEmployee",
    "POST",
    "/employee/add/",
    addEmployee,
  },
  Route
  {
    "deleteEmployee",
    "DELETE",
    "/employee/delete",
    deleteEmployee,
  },
}
type Employee struct 
{
  Id string `json:"id"`
  FirstName string `json:"firstName"`
  LastName string `json:"lastName"`
}
type Employees []Employee
var employees []Employee
func init() 
{
  employees = Employees
  {
    Employee{Id: "1", FirstName: "Foo", LastName: "Bar"},
    Employee{Id: "2", FirstName: "Baz", LastName: "Qux"},
  }
}
func getEmployees(w http.ResponseWriter, r *http.Request) 
{
  json.NewEncoder(w).Encode(employees)
}
func deleteEmployee(w http.ResponseWriter, r *http.Request) 
{
  employee := Employee{}
  err := json.NewDecoder(r.Body).Decode(&employee)
  if err != nil 
  {
    log.Print("error occurred while decoding employee 
    data :: ", err)
    return
  }
  log.Printf("deleting employee id :: %s with firstName 
  as :: %s and lastName as :: %s ", employee.Id, 
  employee.FirstName, employee.LastName)
  index := GetIndex(employee.Id)
  employees = append(employees[:index], employees[index+1:]...)
  json.NewEncoder(w).Encode(employees)
}
func GetIndex(id string) int 
{
  for i := 0; i < len(employees); i++ 
  {
    if employees[i].Id == id 
    {
      return i
    }
  }
  return -1
}
func addEmployee(w http.ResponseWriter, r *http.Request) 
{
  employee := Employee{}
  err := json.NewDecoder(r.Body).Decode(&employee)
  if err != nil 
  {
    log.Print("error occurred while decoding employee 
    data :: ", err)
    return
  }
  log.Printf("adding employee id :: %s with firstName 
  as :: %s and lastName as :: %s ", employee.Id, 
  employee.FirstName, employee.LastName)
  employees = append(employees, Employee{Id: employee.Id, 
  FirstName: employee.FirstName, LastName: employee.LastName})
  json.NewEncoder(w).Encode(employees)
}
func AddRoutes(router *mux.Router) *mux.Router 
{
  for _, route := range routes 
  {
    router.
    Methods(route.Method).
    Path(route.Pattern).
    Name(route.Name).
    Handler(route.HandlerFunc)
  }
  return router
}
func main() 
{
  muxRouter := mux.NewRouter().StrictSlash(true)
  router := AddRoutes(muxRouter)
  err := http.ListenAndServe(CONN_HOST+":"+CONN_PORT, router)
  if err != nil 
  {
    log.Fatal("error starting http server :: ", err)
    return
  }
}
```

1.  使用以下命令运行程序：

```go
$ go run http-rest-delete.go
```

# 工作原理…

一旦我们运行程序，HTTP 服务器将在本地监听端口`8080`。

接下来，从命令行执行`DELETE`请求，将删除 ID 为 1 的员工，并给我们更新后的员工列表：

```go
$ curl -H "Content-Type: application/json" -X DELETE -d '{"Id":"1", "firstName": "Foo", "lastName": "Bar"}' http://localhost:8080/employee/delete
```

这可以在以下截图中看到：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/go-webdev-cb/img/6b9b0cfe-75e6-46f0-97da-eec53d4eb18f.png)

让我们了解我们在这个示例中引入的更改：

1.  首先，我们添加了另一个名为`deleteEmployee`的路由，它为 URL 模式`/employee/delete`的每个`DELETE`请求执行`deleteEmployee`处理程序。

1.  然后，我们定义了一个`deleteEmployee`处理程序，基本上是使用 Go 内置的`encoding/json`包的`NewDecoder`处理程序解码作为`DELETE`请求的一部分传入的员工数据，使用`GetIndex`辅助函数获取请求的员工的索引，删除员工，并将更新后的数组以 JSON 格式写入 HTTP 响应流。

# 对 REST API 进行版本控制

当您创建一个 RESTful API 来为内部客户端提供服务时，您可能不必担心对 API 进行版本控制。更进一步，如果您可以控制访问您的 API 的所有客户端，情况可能是一样的。

然而，在您有一个公共 API 或者您无法控制每个使用它的客户端的 API 的情况下，可能需要对 API 进行版本控制，因为业务需要不断发展，我们将在这个示例中进行介绍。

# 如何做...

1.  使用`go get`命令安装`github.com/gorilla/mux`包，如下所示：

```go
$ go get github.com/gorilla/mux
```

1.  创建`http-rest-versioning.go`，在其中我们将定义支持 HTTP `GET`方法的相同 URL 路径的两个版本，其中一个具有`v1`作为前缀，另一个具有`v2`作为前缀，如下所示：

```go
package main
import 
(
  "encoding/json"
  "log"
  "net/http"
  "strings"
  "github.com/gorilla/mux"
)
const 
(
  CONN_HOST = "localhost"
  CONN_PORT = "8080"
)
type Route struct 
{
  Name string
  Method string
  Pattern string
  HandlerFunc http.HandlerFunc
}
type Routes []Route
var routes = Routes
{
  Route
  {
    "getEmployees",
    "GET",
    "/employees",
    getEmployees,
  },
}
type Employee struct 
{
  Id string `json:"id"`
  FirstName string `json:"firstName"`
  LastName string `json:"lastName"`
}
type Employees []Employee
var employees []Employee
var employeesV1 []Employee
var employeesV2 []Employee
func init() 
{
  employees = Employees
  {
    Employee{Id: "1", FirstName: "Foo", LastName: "Bar"},
  }
  employeesV1 = Employees
  {
    Employee{Id: "1", FirstName: "Foo", LastName: "Bar"},
    Employee{Id: "2", FirstName: "Baz", LastName: "Qux"},
  }
  employeesV2 = Employees
  {
    Employee{Id: "1", FirstName: "Baz", LastName: "Qux"},
    Employee{Id: "2", FirstName: "Quux", LastName: "Quuz"},
  }
}
func getEmployees(w http.ResponseWriter, r *http.Request) 
{
  if strings.HasPrefix(r.URL.Path, "/v1") 
  {
    json.NewEncoder(w).Encode(employeesV1)
  } 
  else if strings.HasPrefix(r.URL.Path, "/v2") 
  {
    json.NewEncoder(w).Encode(employeesV2)
  } 
  else 
  {
    json.NewEncoder(w).Encode(employees)
  }
}
func AddRoutes(router *mux.Router) *mux.Router 
{
  for _, route := range routes 
  {
    router.
    Methods(route.Method).
    Path(route.Pattern).
    Name(route.Name).
    Handler(route.HandlerFunc)
  }
  return router
}
func main() 
{
  muxRouter := mux.NewRouter().StrictSlash(true)
  router := AddRoutes(muxRouter)
  // v1
  AddRoutes(muxRouter.PathPrefix("/v1").Subrouter())
  // v2
  AddRoutes(muxRouter.PathPrefix("/v2").Subrouter())
  err := http.ListenAndServe(CONN_HOST+":"+CONN_PORT, router)
  if err != nil 
  {
    log.Fatal("error starting http server :: ", err)
    return
  }
}
```

1.  使用以下命令运行程序：

```go
$ go run http-rest-versioning.go
```

# 它是如何工作的...

一旦我们运行程序，HTTP 服务器将在本地监听端口`8080`。

接下来，从命令行执行带有路径前缀为`/v1`的`GET`请求，将给您一个员工列表：

```go
$ curl -X GET http://localhost:8080/v1/employees
[{"id":"1","firstName":"Foo","lastName":"Bar"},{"id":"2","firstName":"Baz","lastName":"Qux"}]
```

在这里，使用路径前缀为`/v2`执行`GET`请求将给您另一组员工的列表，如下所示：

```go
$ curl -X GET http://localhost:8080/v2/employees
 [{"id":"1","firstName":"Baz","lastName":"Qux"},{"id":"2","firstName":"Quux","lastName":"Quuz"}]
```

有时，在设计 REST URL 时，如果客户端在不指定 URL 路径中的版本的情况下查询端点，我们更倾向于返回默认数据。为了实现这一点，我们修改了`getEmployees`处理程序，以检查 URL 中的前缀并相应地采取行动。因此，从命令行执行不带路径前缀的`GET`请求，将给您一个带有单个记录的列表，我们可以称之为 REST 端点的默认或初始响应：

```go
$ curl -X GET http://localhost:8080/employees
 [{"id":"1","firstName":"Foo","lastName":"Bar"}]
```

让我们了解我们在这个示例中引入的更改：

1.  首先，我们定义了一个名为`getEmployees`的单一路由，它为 URL 模式`/employees`的每个`GET`请求执行`getEmployees`处理程序。

1.  然后，我们创建了三个数组，分别是`employees`，`employeesV1`和`employeesV2`，它们作为对 URL 模式`/employees`，`/v1/employees`和`/v2/employees`的 HTTP `GET`调用的响应返回。

1.  接下来，我们定义了一个`getEmployees`处理程序，在其中我们检查 URL 路径中的前缀，并根据其执行操作。

1.  然后，我们定义了一个`AddRoutes`辅助函数，它遍历我们定义的路由数组，将其添加到`gorilla/mux`路由器中，并返回`Router`对象。

1.  最后，我们定义了`main()`，在其中我们使用`NewRouter()`处理程序创建一个带有尾部斜杠行为为 true 的`gorilla/mux`路由器实例，并通过调用`AddRoutes`辅助函数将路由添加到其中，传递默认路由器和两个子路由器，一个带有前缀`v1`，另一个带有前缀`v2`。

# 创建您的第一个 REST 客户端

如今，大多数与服务器通信的应用程序都使用 RESTful 服务。根据我们的需求，我们通过 JavaScript、jQuery 或 REST 客户端来消费这些服务。

在这个食谱中，我们将使用`https://gopkg.in/resty.v1`包编写一个 REST 客户端，该包本身受到 Ruby rest 客户端的启发，用于消耗 RESTful 服务。

# 准备就绪…

在一个单独的终端中运行我们在之前的食谱中创建的`http-rest-get.go`，执行以下命令：

```go
$ go run http-rest-get.go
```

参见*创建您的第一个 HTTP GET 方法*食谱。

通过执行以下命令验证`/employees`服务是否在本地端口`8080`上运行：

```go
$ curl -X GET http://localhost:8080/employees
```

这应该返回以下响应：

```go
[{"id":"1","firstName":"Foo","lastName":"Bar"},{"id":"2","firstName":"Baz","lastName":"Qux"}]
```

# 如何做…

1.  使用`go get`命令安装`github.com/gorilla/mux`和`gopkg.in/resty.v1`包，如下所示：

```go
$ go get github.com/gorilla/mux
$ go get -u gopkg.in/resty.v1
```

1.  创建`http-rest-client.go`，在其中我们将定义调用`resty`处理程序的处理程序，如`GET`、`POST`、`PUT`和`DELETE`，从 REST 服务获取响应，并将其写入 HTTP 响应流，如下所示：

```go
package main
import 
(
  "encoding/json"
  "fmt"
  "log"
  "net/http"
  "github.com/gorilla/mux"
  resty "gopkg.in/resty.v1"
)
const 
(
  CONN_HOST = "localhost"
  CONN_PORT = "8090"
)
const WEB_SERVICE_HOST string = "http://localhost:8080"
type Employee struct 
{
  Id string `json:"id"`
  FirstName string `json:"firstName"`
  LastName string `json:"lastName"`
}
func getEmployees(w http.ResponseWriter, r *http.Request) 
{
  response, err := resty.R().Get(WEB_SERVICE_HOST + 
  "/employees")
  if err != nil 
  {
    log.Print("error getting data from the web service :: ", err)
    return
  }
  printOutput(response, err)
  fmt.Fprintf(w, response.String())
}
func addEmployee(w http.ResponseWriter, r *http.Request) 
{
  employee := Employee{}
  decodingErr := json.NewDecoder(r.Body).Decode(&employee)
  if decodingErr != nil 
  {
    log.Print("error occurred while decoding employee 
    data :: ", decodingErr)
    return
  }
  log.Printf("adding employee id :: %s with firstName 
  as :: %s and lastName as :: %s ", employee.Id, 
  employee.FirstName, employee.LastName)
  response, err := resty.R().
  SetHeader("Content-Type", "application/json").
  SetBody(Employee{Id: employee.Id, FirstName: 
  employee.FirstName, LastName: employee.LastName}).
  Post(WEB_SERVICE_HOST + "/employee/add")
  if err != nil 
  {
    log.Print("error occurred while adding employee :: ", err)
    return
  }
  printOutput(response, err)
  fmt.Fprintf(w, response.String())
}
func updateEmployee(w http.ResponseWriter, r *http.Request) 
{
  employee := Employee{}
  decodingErr := json.NewDecoder(r.Body).Decode(&employee)
  if decodingErr != nil 
  {
    log.Print("error occurred while decoding employee 
    data :: ", decodingErr)
    return
  }
  log.Printf("updating employee id :: %s with firstName 
  as :: %s and lastName as :: %s ", employee.Id, 
  employee.FirstName, employee.LastName)
  response, err := resty.R().
  SetBody(Employee{Id: employee.Id, FirstName: 
  employee.FirstName, LastName: employee.LastName}).
  Put(WEB_SERVICE_HOST + "/employee/update")
  if err != nil 
  {
    log.Print("error occurred while updating employee :: ", err)
    return
  }
  printOutput(response, err)
  fmt.Fprintf(w, response.String())
}
func deleteEmployee(w http.ResponseWriter, r *http.Request) 
{
  employee := Employee{}
  decodingErr := json.NewDecoder(r.Body).Decode(&employee)
  if decodingErr != nil 
  {
    log.Print("error occurred while decoding employee 
    data :: ", decodingErr)
    return
  }
  log.Printf("deleting employee id :: %s with firstName 
  as :: %s and lastName as :: %s ", employee.Id, 
  employee.FirstName, employee.LastName)
  response, err := resty.R().
  SetBody(Employee{Id: employee.Id, FirstName: 
  employee.FirstName, LastName: employee.LastName}).
  Delete(WEB_SERVICE_HOST + "/employee/delete")
  if err != nil 
  {
    log.Print("error occurred while deleting employee :: ", err)
    return
  }
  printOutput(response, err)
  fmt.Fprintf(w, response.String())
}
func printOutput(resp *resty.Response, err error) 
{
  log.Println(resp, err)
}
func main() 
{
  router := mux.NewRouter().StrictSlash(false)
  router.HandleFunc("/employees", getEmployees).Methods("GET")
  employee := router.PathPrefix("/employee").Subrouter()
  employee.HandleFunc("/add", addEmployee).Methods("POST")
  employee.HandleFunc("/update", updateEmployee).Methods("PUT")
  employee.HandleFunc("/delete", deleteEmployee).Methods("DELETE")
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
$ go run http-rest-client.go
```

# 工作原理…

一旦我们运行程序，HTTP 服务器将在本地监听端口`8090`。

接下来，通过执行以下命令向 REST 客户端发送`GET`请求，将会得到来自服务的所有员工的列表：

```go
$ curl -X GET http://localhost:8090/employees
 [{"id":"1","firstName":"Foo","lastName":"Bar"},{"id":"2","firstName":"Baz","lastName":"Qux"}]
```

同样地，在一个单独的终端中运行我们在之前的食谱中创建的`http-rest-post.go`，执行以下命令：

```go
$ go run http-rest-post.go
```

从命令行执行`POST`请求到 REST 客户端，如下所示：

```go
$ curl -H "Content-Type: application/json" -X POST -d '{"Id":"3", "firstName":"Quux", "lastName":"Corge"}' http://localhost:8090/employee/add [{"id":"1","firstName":"Foo","lastName":"Bar"},{"id":"2","firstName":"Baz","lastName":"Qux"},{"id":"3","firstName":"Quux","lastName":"Corge"}]
```

这将向初始静态列表添加一个员工，并返回更新后的员工列表，如下截图所示：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/go-webdev-cb/img/e91da249-f9ae-42b1-ba53-391407df8998.png)

让我们了解我们编写的程序：

1.  使用`import ("encoding/json" "fmt" "log" "net/http" "github.com/gorilla/mux" resty “gopkg.in/resty.v1")`，我们导入了`github.com/gorilla/mux`来创建`Gorilla Mux Router`，并使用包别名`resty`导入了`gopkg.in/resty.v1`，它是 Go 的 REST 客户端，具有各种处理程序来消耗 RESTful web 服务。

1.  使用`const WEB_SERVICE_HOST string = "http://localhost:8080"`，我们声明了 RESTful web 服务主机的完整 URL。

根据项目大小，您可以将`WEB_SERVICE_HOST`字符串移动到常量文件或属性文件中，以帮助您在运行时覆盖其值。

1.  接下来，我们定义了一个`getEmployees`处理程序，在其中我们创建一个新的`resty`请求对象调用其`R()`处理程序，调用`Get`方法，执行 HTTP `GET`请求，获取响应，并将其写入 HTTP 响应。

1.  类似地，我们定义了另外三个处理程序，用于向 RESTful 服务发送`POST`、`PUT`和`DELETE`请求，以及一个`main()`，在其中我们创建了一个`gorilla/mux`路由器实例，并使用`getEmployees`处理程序注册了`/employees` URL 路径，以及使用`addEmployee`、`updateEmployee`和`deleteEmployee`处理程序分别注册了`/employee/add`、`/employee/update`和`/employee/delete`。

# 创建您的第一个 AngularJS 客户端

AngularJS 是一个开源的 JavaScript Model-View-Whatever（MVW）框架，它让我们能够构建结构良好、易于测试和易于维护的基于浏览器的应用程序。

在这个食谱中，我们将学习创建一个 AngularJS 与 TypeScript 2 客户端，向本地运行的 HTTP 服务器发送`POST`请求。

# 准备就绪…

由于我们已经在之前的食谱中创建了一个接受`GET`和`POST`请求的 HTTP 服务器，我们将使用相同的代码库作为我们的 HTTP 服务器。

此外，此处的食谱假设您的机器上已安装了 Angular2 CLI。如果没有，请执行以下命令进行安装：

```go
$ npm install -g @angular/cli
```

参见*创建您的第一个 HTTP POST 方法*食谱。

# 如何做…

1.  通过执行以下命令创建一个新项目和骨架应用程序：

```go
$ ng new angularjs-client
```

1.  移动到`angularjs-client`目录，并通过执行以下命令创建`server.go`：

```go
$ cd angularjs-client && touch server.go
```

1.  将以下代码复制到`server.go`中：

```go
package main
import 
(
  "encoding/json"
  "log"
  "net/http"
  "github.com/gorilla/mux"
)
const 
(
  CONN_HOST = "localhost"
  CONN_PORT = "8080"
)
type Route struct 
{
  Name string
  Method string
  Pattern string
  HandlerFunc http.HandlerFunc
}
type Routes []Route
var routes = Routes
{
  Route
  {
    "getEmployees",
    "GET",
    "/employees",
    getEmployees,
  },
  Route
  {
    "addEmployee",
    "POST",
    "/employee/add",
    addEmployee,
  },
}
type Employee struct 
{
  Id string `json:"id"`
  FirstName string `json:"firstName"`
  LastName string `json:"lastName"`
}
type Employees []Employee
var employees []Employee
func init() 
{
  employees = Employees
  {
    Employee{Id: "1", FirstName: "Foo", LastName: "Bar"},
    Employee{Id: "2", FirstName: "Baz", LastName: "Qux"},
  }
}
func getEmployees(w http.ResponseWriter, r *http.Request) 
{
  json.NewEncoder(w).Encode(employees)
}
func addEmployee(w http.ResponseWriter, r *http.Request) 
{
  employee := Employee{}
  err := json.NewDecoder(r.Body).Decode(&employee)
  if err != nil 
  {
    log.Print("error occurred while decoding employee 
    data :: ", err)
    return
  }
  log.Printf("adding employee id :: %s with firstName 
  as :: %s and lastName as :: %s ", employee.Id, 
  employee.FirstName, employee.LastName)
  employees = append(employees, Employee{Id: employee.Id, 
  FirstName: employee.FirstName, LastName: employee.LastName})
  json.NewEncoder(w).Encode(employees)
}
func AddRoutes(router *mux.Router) *mux.Router 
{
  for _, route := range routes 
  {
    router.
    Methods(route.Method).
    Path(route.Pattern).
    Name(route.Name).
    Handler(route.HandlerFunc)
  }
  return router
}
func main() 
{
  muxRouter := mux.NewRouter().StrictSlash(true)
  router := AddRoutes(muxRouter)
  router.PathPrefix("/").Handler(http.FileServer
  (http.Dir("./dist/")))
  err := http.ListenAndServe(CONN_HOST+":"+CONN_PORT, router)
  if err != nil 
  {
    log.Fatal("error starting http server :: ", err)
    return
  }
}
```

1.  移动到`angularjs-client`目录，并通过执行以下命令创建`models/employee.ts`和`service/employee.service.ts`：

```go
$ cd src/app/ && mkdir models && mkdir services && cd models && touch employee.ts && cd ../services && touch employee.service.ts
```

1.  将以下代码复制到`angularjs-client/src/app/models/employee.ts`中：

```go
export class Employee 
{
  constructor
  (
    public id: string,
    public firstName: string,
    public lastName: string
  ) {}
}
```

1.  将以下代码复制到`angularjs-client/src/app/services`中

/employee.service.ts`:

```go
import { Injectable } from '@angular/core';
import { Http, Response, Headers, RequestOptions } from '@angular/http';
import { Observable } from 'rxjs/Rx';
import { Employee } from "app/models/employee";

@Injectable()
export class EmployeeService 
{
  constructor(private http: Http) { }
  getEmployees(): Observable<Employee[]> 
  {
    return this.http.get("http://localhost:8080/employees")
    .map((res: Response) => res.json())
    .catch((error: any) => Observable.throw(error.json().
    error || 'Server error'));
  }
  addEmployee(employee: Employee): Observable<Employee> 
  {
    let headers = new Headers({ 'Content-Type': 
    'application/json' });
    let options = new RequestOptions({ headers: headers });
    return this.http.post("http://localhost:8080/employee
    /add", employee, options)
    .map(this.extractData)
    .catch(this.handleErrorObservable);
  }
  private extractData(res: Response) 
  {
    let body = res.json();
    return body || {};
  }
  private handleErrorObservable(error: Response | any) 
  {
    console.error(error.message || error);
    return Observable.throw(error.message || error);
  }
}
```

1.  用以下内容替换`angularjs-client/src/app/app.component.html`的代码：

```go
<div class = "container" style="padding:5px">
  <form>
    <div class = "form-group">
      <label for = "id">ID</label>
      <input type = "text" class = "form-control" id = "id" 
      required [(ngModel)] = "employee.id" name = "id">
    </div>
    <div class = "form-group">
      <label for = "firstName">FirstName</label>
      <input type = "text" class = "form-control" id = 
      "firstName" [(ngModel)] = "employee.firstName" name =
      "firstName">
    </div>
    <div class = "form-group">
      <label for = "lastName">LastName</label>
      <input type = "text" class = "form-control" id = 
      "lastName" [(ngModel)] = "employee.lastName" name =
      "lastName">
    </div>
    <div>
      <button (click)="addEmployee()">Add</button>
    </div>
  </form>
</div>
<table>
  <thead>
    <th>ID</th>
    <th>FirstName</th>
    <th>LastName</th>
  </thead>
  <tbody>
    <tr *ngFor="let employee of employees">
      <td>{{employee.id}}</td>
      <td>{{employee.firstName}}</td>
      <td>{{employee.lastName}}</td>
    </tr>
  </tbody>
</table>
```

1.  用以下内容替换`angularjs-client/src/app/app.component.ts`的代码：

```go
import { Component, OnInit } from '@angular/core';
import { EmployeeService } from "app/services/employee.service";
import { Employee } from './models/employee';

@Component
({
  selector: 'app-root',
  templateUrl: './app.component.html',
  styleUrls: ['./app.component.css'],
})
export class AppComponent implements OnInit 
{
  title = 'app';
  employee = new Employee('', '', '');
  employees;
  constructor(private employeeService: EmployeeService) { }
  ngOnInit(): void 
  {
    this.getEmployees();
  }
  getEmployees(): void 
  {
    this.employeeService.getEmployees()
    .subscribe(employees => this.employees = employees);
  }
  addEmployee(): void 
  {
    this.employeeService.addEmployee(this.employee)
    .subscribe
    (
      employee => 
      {
        this.getEmployees();
        this.reset();
      }
    );
  }
  private reset() 
  {
    this.employee.id = null;
    this.employee.firstName = null;
    this.employee.lastName = null;
  }
}
```

1.  用以下内容替换`angularjs-client/src/app/app.module.ts`的代码：

```go
import { BrowserModule } from '@angular/platform-browser';
import { NgModule } from '@angular/core';
import { HttpModule } from '@angular/http';
import { AppComponent } from './app.component';
import { EmployeeService } from "app/services/employee.service";
import { FormsModule } from '@angular/forms';

@NgModule
({
 declarations: 
 [
   AppComponent
 ],
 imports: 
 [
   BrowserModule, HttpModule, FormsModule
 ],
 providers: [EmployeeService],
 bootstrap: [AppComponent]
})
export class AppModule { }
```

一切就绪后，目录结构应如下所示：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/go-webdev-cb/img/b8fa1211-122f-4c01-ae7a-7b7041b79476.png)

1.  移动到`angularjs-client`目录并执行以下命令来构建项目构件并运行程序：

```go
$ ng build
$ go run server.go
```

# 它是如何工作的…

一旦我们运行程序，HTTP 服务器将在本地监听端口`8080`。

浏览到`http://localhost:8080`将显示 AngularJS 客户端页面，其中有一个带有 Id、FirstName 和 LastName 字段的 HTML 表单，如下图所示：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/go-webdev-cb/img/203d5e4b-c4f3-4b47-aac8-31bf7bdeda08.png)

在填写表单后点击“Add”按钮将向运行在端口`8080`上的 HTTP 服务器发送一个`POST`请求。一旦服务器处理了请求，它将返回所有静态员工的列表以及新添加的员工，并在浏览器中显示，如下图所示：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/go-webdev-cb/img/d2c666e9-0b1c-4b91-8376-a454e565541e.png)

所有静态员工的列表以及新添加的员工

# 创建你的第一个 ReactJS 客户端

ReactJS 是一个声明式的 JavaScript 库，有助于高效构建用户界面。因为它基于虚拟 DOM 的概念工作，它提高了应用程序的性能，因为 JavaScript 虚拟 DOM 比常规 DOM 更快。

在这个教程中，我们将学习创建一个 ReactJS 客户端来向本地运行的 HTTP 服务器发送`POST`请求。

# 准备就绪…

由于我们已经在之前的教程中创建了一个接受`GET`和`POST` HTTP 请求的 HTTP 服务器，我们将使用相同的代码库作为我们的 HTTP 服务器。

此外，本教程假设您已在您的机器上安装了`npm`，并且对`npm`和`webpack`有基本的了解，它是一个 JavaScript 模块打包工具。

参见*创建你的第一个 HTTP POST 方法*教程。

# 如何做…

1.  创建一个`reactjs-client`目录，我们将在其中保存所有我们的 ReactJS 源文件和一个 HTTP 服务器，如下所示：

```go
$ mkdir reactjs-client && cd reactjs-client && touch server.go
```

1.  将以下代码复制到`server.go`中：

```go
package main
import 
(
  "encoding/json"
  "log"
  "net/http"
  "github.com/gorilla/mux"
)
const 
(
  CONN_HOST = "localhost"
  CONN_PORT = "8080"
)
type Route struct 
{
  Name string
  Method string
  Pattern string
  HandlerFunc http.HandlerFunc
}
type Routes []Route
var routes = Routes
{
  Route
  {
    "getEmployees",
    "GET",
    "/employees",
    getEmployees,
  },
  Route
  {
    "addEmployee",
    "POST",
    "/employee/add",
    addEmployee,
  },
}
type Employee struct 
{
  Id string `json:"id"`
  FirstName string `json:"firstName"`
  LastName string `json:"lastName"`
}
type Employees []Employee
var employees []Employee
func init() 
{
  employees = Employees
  {
    Employee{Id: "1", FirstName: "Foo", LastName: "Bar"},
    Employee{Id: "2", FirstName: "Baz", LastName: "Qux"},
  }
}
func getEmployees(w http.ResponseWriter, r *http.Request) 
{
  json.NewEncoder(w).Encode(employees)
}
func addEmployee(w http.ResponseWriter, r *http.Request) 
{
  employee := Employee{}
  err := json.NewDecoder(r.Body).Decode(&employee)
  if err != nil 
  {
    log.Print("error occurred while decoding employee 
    data :: ", err)
    return
  }
  log.Printf("adding employee id :: %s with firstName 
  as :: %s and lastName as :: %s ", employee.Id, 
  employee.FirstName, employee.LastName)
  employees = append(employees, Employee{Id: employee.Id, 
  FirstName: employee.FirstName, LastName: employee.LastName})
  json.NewEncoder(w).Encode(employees)
}
func AddRoutes(router *mux.Router) *mux.Router 
{
  for _, route := range routes 
  {
    router.
    Methods(route.Method).
    Path(route.Pattern).
    Name(route.Name).
    Handler(route.HandlerFunc)
  }
  return router
}
func main() 
{
  muxRouter := mux.NewRouter().StrictSlash(true)
  router := AddRoutes(muxRouter)
  router.PathPrefix("/").Handler(http.FileServer
  (http.Dir("./assets/")))
  err := http.ListenAndServe(CONN_HOST+":"+CONN_PORT, router)
  if err != nil 
  {
    log.Fatal("error starting http server :: ", err)
    return
  }
}
```

1.  创建另一个名为`assets`的目录，其中将保存所有我们的前端代码文件，如`.html`、`.js`、`.css`和`images`，如下所示：

```go
$ mkdir assets && cd assets && touch index.html
```

1.  将以下内容复制到`index.html`中：

```go
<html>
  <head lang="en">
    <meta charset="UTF-8" />
    <title>ReactJS Client</title>
  </head> 
  <body>
    <div id="react"></div>
    <script src="img/script.js"></script>
```

```go
  </body>
</html>
```

1.  移动到`reactjs-client`目录并执行`npm init`来创建`package.json`，在其中我们指定构建我们的 react 客户端所需的所有依赖项，如`React`、`React DOM`、`Webpack`、`Babel Loader`、`Babel Core`、`Babel Preset: ES2015`和`Babel Preset: React`，如下所示：

```go
$ cd reactjs-client && touch npm init
```

用以下内容替换`package.json`的内容：

```go
{
  "name": "reactjs-client",
  "version": "1.0.0",
  "description": "ReactJs Client",
  "keywords": 
  [
    "react"
  ],
  "author": "Arpit Aggarwal",
  "dependencies": 
  {
    "axios": "⁰.18.0",
    "react": "¹⁶.2.0",
    "react-dom": "¹⁶.2.0",
    "react-router-dom": "⁴.2.2",
    "webpack": "⁴.2.0",
    "webpack-cli": "².0.9",
    "lodash": "⁴.17.5"
  },
  "scripts": 
  {
    "build": "webpack",
    "watch": "webpack --watch -d"
  },
  "devDependencies": 
  {
    "babel-core": "⁶.18.2",
    "babel-loader": "⁷.1.4",
    "babel-polyfill": "⁶.16.0",
    "babel-preset-es2015": "⁶.18.0",
    "babel-preset-react": "⁶.16.0"
  }
}
```

1.  创建`webpack.config.js`，在其中我们将配置`webpack`，如下所示：

```go
$ cd reactjs-client && touch webpack.config.js
```

将以下内容复制到`webpack.config.js`中：

```go
var path = require('path');
module.exports = 
{
  resolve: 
  {
    extensions: ['.js', '.jsx']
  },
  mode: 'development',
  entry: './app/main.js',
  cache: true,
  output: 
  {
    path: __dirname,
    filename: './assets/script.js'
  },
  module: 
  {
    rules: 
    [
      {
        test: path.join(__dirname, '.'),
        exclude: /(node_modules)/,
        loader: 'babel-loader',
        query: 
        {
          cacheDirectory: true,
          presets: ['es2015', 'react']
        }
      }
    ]
  }
};
```

1.  通过执行以下命令为`webpack`创建入口点，即`reactjs-client/app/main.js`：

```go
$ cd reactjs-client && mkdir app && cd app && touch main.js
```

将以下内容复制到`main.js`中：

```go
'use strict';
const React = require('react');
const ReactDOM = require('react-dom')
import EmployeeApp from './components/employee-app.jsx'
ReactDOM.render
(
  <EmployeeApp />,
  document.getElementById('react')
)
```

1.  通过执行以下命令定义`ReactApp`以及它的子组件：

```go
$ cd reactjs-client && mkdir components && cd components && touch react-app.jsx employee-list.jsx employee.jsx add-employee.jsx
```

将以下内容复制到`reactjs-client/app/components/employee-app.jsx`中：

```go
'use strict';
const React = require('react');
var axios = require('axios');
import EmployeeList from './employee-list.jsx'
import AddEmployee from './add-employee.jsx'
export default class EmployeeApp extends React.Component 
{
  constructor(props) 
  {
    super(props);
    this.state = {employees: []};
    this.addEmployee = this.addEmployee.bind(this);
    this.Axios = axios.create
    (
      {
        headers: {'content-type': 'application/json'}
      }
    );
  }
  componentDidMount() 
  {
    let _this = this;
    this.Axios.get('/employees')
    .then
    (
      function (response) 
      {
        _this.setState({employees: response.data});
      }
    )
    .catch(function (error) { });
  }
  addEmployee(employeeName)
  {
    let _this = this;
    this.Axios.post
    (
      '/employee/add', 
      {
        firstName: employeeName
      }
    )
    .then
    (
      function (response) 
      {
        _this.setState({employees: response.data});
      }
    )
    .catch(function (error) { });
    }
    render() 
    {
      return 
      (
        <div>
          <AddEmployee addEmployee={this.addEmployee}/>
          <EmployeeList employees={this.state.employees}/>
        </div>
      )
   }
}
```

将以下内容复制到`reactjs-client/app/components/employee.jsx`中：

```go
const React = require('react');
export default class Employee extends React.Component
{
  render() 
  {
    return 
    (
      <tr>
        <td>{this.props.employee.firstName}</td>
      </tr>
    )
  }
}

```

将以下内容复制到`reactjs-client/app/components/employee-list.jsx`中：

```go
const React = require('react');
import Employee from './employee.jsx'
export default class EmployeeList extends React.Component
{
  render() 
  {
    var employees = this.props.employees.map
    (
      (employee, i) =>
      <Employee key={i} employee={employee}/>
    );
    return 
    (
      <table>
        <tbody>
          <tr>
            <th>FirstName</th>
          </tr>
          {employees}
        </tbody>
      </table>
    )
  }
}
```

将以下内容复制到`reactjs-client/app/components/add-employee.jsx`中：

```go
import React, { Component, PropTypes } from 'react'
export default class AddEmployee extends React.Component 
{
  render()
  {
    return 
    (
      <div>
        <input type = 'text' ref = 'input' />
        <button onClick = {(e) => this.handleClick(e)}>
          Add
        </button>
      </div>
    )
  }
  handleClick(e) 
  {
    const node = this.refs.input
    const text = node.value.trim()
    this.props.addEmployee(text)
    node.value = ''
  }
}
```

一切就绪后，目录结构应如下所示：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/go-webdev-cb/img/50c0bf0f-cdbe-4833-bf8d-99c9a104973b.png)

目录结构

1.  移动到`reactjs-client`目录并执行以下命令来安装`node modules`和构建`webpack`：

```go
$ npm install
$ npm run build
```

1.  使用以下命令运行程序：

```go
$ go run server.go
```

# 它是如何工作的…

一旦我们运行程序，HTTP 服务器将在本地监听端口`8080`。

浏览到`http://localhost:8080`将会显示我们的 VueJS 客户端页面，如下截图所示：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/go-webdev-cb/img/f00b32c2-acbb-4ab3-a636-89add88479d7.png)

ReactJS 客户端页面

在填写文本框后点击添加按钮将会向运行在端口`8080`上的 HTTP 服务器发送一个`POST`请求：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/go-webdev-cb/img/1584d5e4-c3e7-42e3-a70e-e61ccea90f6e.png)

在填写文本框后点击添加按钮

接下来，从命令行执行一个`GET`请求将会给你一个所有静态员工的列表：

```go
$ curl -X GET http://localhost:8080/employees
```

这将会和新添加的员工一起显示如下：

```go
[{"id":"1","firstName":"Foo","lastName":"Bar"},{"id":"2","firstName":"Baz","lastName":"Qux"},{"id":"","firstName":"Arpit","lastName":""}]
```

# 创建你的第一个 VueJS 客户端

作为开源项目，VueJS 是逐步可采用和渐进式的 JavaScript 框架之一，公司正在采用它来构建他们的前端或面向客户的用户界面。

在这个教程中，我们将学习在 VueJS 中创建一个客户端，通过向本地运行的 HTTP 服务器发送一个 HTTP `POST`请求来添加一个员工。

# 准备好…

由于我们已经在之前的教程中创建了一个接受`GET`和`POST`请求的 HTTP 服务器，我们将使用相同的代码库作为我们的 HTTP 服务器。

参见*创建你的第一个 HTTP POST 方法*教程。

# 如何做…

1.  创建一个`vuejs-client`目录，我们将在其中保存所有 VueJS 源文件和一个 HTTP 服务器，如下所示：

```go
$ mkdir vuejs-client && cd vuejs-client && touch server.go
```

1.  将以下代码复制到`server.go`中：

```go
package main
import 
(
  "encoding/json"
  "log"
  "net/http"
  "github.com/gorilla/mux"
)
const 
(
  CONN_HOST = "localhost"
  CONN_PORT = "8080"
)
type Route struct 
{
  Name string
  Method string
  Pattern string
  HandlerFunc http.HandlerFunc
}
type Routes []Route
var routes = Routes
{
  Route
  {
    "getEmployees",
    "GET",
    "/employees",
    getEmployees,
  },
  Route
  {
    "addEmployee",
    "POST",
    "/employee/add",
    addEmployee,
  },
}
type Employee struct 
{
  Id string `json:"id"`
  FirstName string `json:"firstName"`
  LastName string `json:"lastName"`
}
type Employees []Employee
var employees []Employee
func init() 
{
  employees = Employees
  {
    Employee{Id: "1", FirstName: "Foo", LastName: "Bar"},
    Employee{Id: "2", FirstName: "Baz", LastName: "Qux"},
  }
}
func getEmployees(w http.ResponseWriter, r *http.Request) 
{
  json.NewEncoder(w).Encode(employees)
}
func addEmployee(w http.ResponseWriter, r *http.Request) 
{
  employee := Employee{}
  err := json.NewDecoder(r.Body).Decode(&employee)
  if err != nil 
  {
    log.Print("error occurred while decoding employee 
    data :: ", err)
    return
  }
  log.Printf("adding employee id :: %s with firstName 
  as :: %s and lastName as :: %s ", employee.Id, 
  employee.FirstName, employee.LastName)
  employees = append(employees, Employee{Id: employee.Id, 
  FirstName: employee.FirstName, LastName: employee.LastName})
  json.NewEncoder(w).Encode(employees)
}
func AddRoutes(router *mux.Router) *mux.Router 
{
  for _, route := range routes 
  {
    router.
    Methods(route.Method).
    Path(route.Pattern).
    Name(route.Name).
    Handler(route.HandlerFunc)
  }
  return router
}
func main() 
{
  muxRouter := mux.NewRouter().StrictSlash(true)
  router := AddRoutes(muxRouter)
  router.PathPrefix("/").Handler(http.FileServer
  (http.Dir("./assets/")))
  err := http.ListenAndServe(CONN_HOST+":"+CONN_PORT, router)
  if err != nil 
  {
    log.Fatal("error starting http server :: ", err)
    return
  }
}
```

1.  创建另一个名为`assets`的目录，其中将保存所有我们的前端代码文件，如`.html`、`.js`、`.css`和`images`，如下所示：

```go
$ mkdir assets && cd assets && touch index.html && touch main.js
```

1.  将以下内容复制到`index.html`中：

```go
<html>
  <head>
    <title>VueJs Client</title>
    <script type = "text/javascript" src = "https://cdnjs.
    cloudflare.com/ajax/libs/vue/2.4.0/vue.js"></script>
    <script type = "text/javascript" src="img/vue-resource@1.5.0"></script>
  </head>
  <body>
    <div id = "form">
      <h1>{{ message }}</h1>
      <table>
        <tr>
          <td><label for="id">Id</label></td>
          <td><input type="text" value="" v-model="id"/></td>
        </tr>
        <tr>
          <td><label for="firstName">FirstName</label></td>
          <td><input type="text" value="" v-model="firstName"/>
          <td>
        </tr>
        <tr>
          <td><label for="lastName">LastName</label></td>
          <td> <input type="text" value="" v-model="lastName" />
          </td>
        </tr>
        <tr>
          <td><a href="#" class="btn" @click="addEmployee">Add
          </a></td>
        </tr>
      </table>
    </div>
    <script type = "text/javascript" src = "main.js"></script>
  </body>
</html>
```

1.  将以下内容复制到`main.js`中：

```go
var vue_det = new Vue
({
 el: '#form',
 data: 
 {
   message: 'Employee Dashboard',
   id: '',
   firstName:'',
   lastName:''
 },
 methods: 
 {
   addEmployee: function() 
   {
     this.$http.post
     (
       '/employee/add', 
       {
         id: this.id,
         firstName:this.firstName,
         lastName:this.lastName
       }
     )
     .then
     (
       response => 
       {
         console.log(response);
       }, 
       error => 
       {
         console.error(error);
       }
     );
   }
 }
});
```

一切就绪后，目录结构应该如下所示：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/go-webdev-cb/img/9f55a822-3ed2-4737-9a32-67a78d767f14.png)

目录结构

1.  用以下命令运行程序：

```go
$ go run server.go
```

# 工作原理…

一旦我们运行程序，HTTP 服务器将在本地监听端口`8080`。

浏览到`http://localhost:8080`将会显示我们的 VueJS 客户端页面，其中有一个包含 Id、FirstName 和 LastName 字段的 HTML 表单，如下截图所示：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/go-webdev-cb/img/6ca52730-9d1a-41ab-9232-ce31c5b2b145.png)

VueJS 客户端页面

在填写表单后点击添加按钮将会向运行在端口`8080`上的 HTTP 服务器发送一个`POST`请求，如下截图所示：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/go-webdev-cb/img/2787ecca-7f98-4c93-8b51-27a5ef3a79eb.png)

在填写表单后点击添加按钮

接下来，从命令行执行一个`GET`请求，将会给你一个所有静态员工的列表：

```go
$ curl -X GET http://localhost:8080/employees
```

这将会和新添加的员工一起显示如下：

```go
[{"id":"1","firstName":"Foo","lastName":"Bar"},{"id":"2","firstName":"Baz","lastName":"Qux"},{"id":"5","firstName":"Arpit","lastName":"Aggarwal"}]
```
