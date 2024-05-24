# Go 标准库秘籍（四）

> 原文：[`zh.annas-archive.org/md5/F3FFC94069815F41B53B3D7D6E774406`](https://zh.annas-archive.org/md5/F3FFC94069815F41B53B3D7D6E774406)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第九章：来到服务器端

本章包含以下配方：

+   创建 TCP 服务器

+   创建 UDP 服务器

+   处理多个客户端

+   创建 HTTP 服务器

+   处理 HTTP 请求

+   创建 HTTP 中间件层

+   提供静态文件

+   提供使用模板生成的内容

+   处理重定向

+   处理 cookies

+   优雅地关闭 HTTP 服务器

+   提供安全的 HTTP 内容

+   解析表单变量

# 介绍

本章涵盖了从实现简单的 TCP 和 UDP 服务器到启动 HTTP 服务器的主题。这些配方将引导您从处理 HTTP 请求、提供静态内容，到提供安全的 HTTP 内容。

检查 Go 是否已正确安装。*第一章*的*准备就绪*部分中的*检索 Golang 版本*配方将有所帮助。

确保端口`8080`和`7070`没有被其他应用程序使用。

# 创建 TCP 服务器

在*连接网络*章节中，介绍了 TCP 连接的客户端部分。在本配方中，将描述服务器端。

# 如何做...

1.  打开控制台并创建文件夹`chapter09/recipe01`。

1.  导航到该目录。

1.  创建`servertcp.go`文件，内容如下：

```go
        package main

        import (
          "bufio"
          "fmt"
          "io"
          "net"
        )

        func main() {

          l, err := net.Listen("tcp", ":8080")
          if err != nil {
            panic(err)
          }
          for {
            fmt.Println("Waiting for client...")
            conn, err := l.Accept()
            if err != nil {
              panic(err)
            }

            msg, err := bufio.NewReader(conn).ReadString('\n')
            if err != nil {
              panic(err)
            }
            _, err = io.WriteString(conn, "Received: "+string(msg))
            if err != nil {
              fmt.Println(err)
            }
            conn.Close()
          }
        }
```

1.  通过`go run servertcp.go`执行代码：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/go-stdlib-cb/img/8dfefbc6-9c4b-4e14-b076-71fa553960dd.png)

1.  打开另一个终端并执行`nc localhost 8080`。

1.  写入任何文本，例如`Hello`。

1.  查看输出：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/go-stdlib-cb/img/8ad77c3b-7195-4721-9c59-3c0a7893c688.png)

# 工作原理...

可以使用`net`包创建 TCP 服务器。net 包包含`Listen`函数，用于创建`TCPListener`，可以`Accept`客户端连接。`Accept`方法调用`TCPListener`上的方法，直到接收到客户端连接。如果客户端连接成功，`Accept`方法会返回`TCPConn`连接。`TCPConn`是连接到客户端的连接，用于读取和写入数据。

`TCPConn`实现了`Reader`和`Writer`接口。可以使用所有写入和读取数据的方法。请注意，读取数据时有一个分隔符字符，否则，如果客户端强制关闭连接，则会收到 EOF。

请注意，此实现一次只能处理一个客户端。

# 创建 UDP 服务器

**用户数据报协议**（UDP）是互联网的基本协议之一。本篇将向您展示如何监听 UDP 数据包并读取内容。

# 如何做...

1.  打开控制台并创建文件夹`chapter09/recipe02`。

1.  导航到该目录。

1.  创建`serverudp.go`文件，内容如下：

```go
        package main

        import (
          "fmt"
          "log"
          "net"
        )

        func main() {

          pc, err := net.ListenPacket("udp", ":7070")
          if err != nil {
            log.Fatal(err)
          }
          defer pc.Close()

          buffer := make([]byte, 2048)
          fmt.Println("Waiting for client...")
          for {
            _, addr, err := pc.ReadFrom(buffer)
            if err == nil {
              rcvMsq := string(buffer)
              fmt.Println("Received: " + rcvMsq)
              if _, err := pc.WriteTo([]byte("Received: "+rcvMsq), addr);
              err != nil {
                fmt.Println("error on write: " + err.Error())
              }
            } else {
              fmt.Println("error: " + err.Error())
            }
          }
        }
```

1.  通过`go run serverudp.go`启动服务器：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/go-stdlib-cb/img/f8f78af0-6fb6-4921-a76c-3bc5e8d5e9a0.png)

1.  打开另一个终端并执行`nc -u localhost 7070`。

1.  在终端中写入任何消息，例如`Hello`，然后按*Enter*。

1.  查看输出：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/go-stdlib-cb/img/fd570795-3779-4f90-ad46-33ad28dbabbe.png)

# 工作原理...

与 TCP 服务器一样，可以使用`net`包创建 UDP 服务器。使用`ListenPacket`函数创建`PacketConn`。

`PacketConn`不像`TCPConn`那样实现`Reader`和`Writer`接口。要读取接收到的数据包，应该使用`ReadFrom`方法。`ReadFrom`方法会阻塞，直到接收到数据包。然后返回客户端的`Addr`（记住 UDP 不是基于连接的）。要响应客户端，可以使用`PacketConn`的`WriteTo`方法；这会消耗消息和`Addr`，在这种情况下是客户端的`Addr`。

# 处理多个客户端

前面的配方展示了如何创建 UDP 和 TCP 服务器。示例代码尚未准备好同时处理多个客户端。在本配方中，我们将介绍如何同时处理更多客户端。

# 如何做...

1.  打开控制台并创建文件夹`chapter09/recipe03`。

1.  导航到该目录。

1.  创建`multipletcp.go`文件，内容如下：

```go
        package main

        import (
          "fmt"
          "log"
          "net"
        )

        func main() {

          pc, err := net.ListenPacket("udp", ":7070")
          if err != nil {
            log.Fatal(err)
          }
          defer pc.Close()

          buffer := make([]byte, 2048)
          fmt.Println("Waiting for client...")
          for {

            _, addr, err := pc.ReadFrom(buffer)
            if err == nil {
              rcvMsq := string(buffer)
              fmt.Println("Received: " + rcvMsq)
              if _, err := pc.WriteTo([]byte("Received: "+rcvMsq), addr);
              err != nil {
                fmt.Println("error on write: " + err.Error())
              }
            } else {
              fmt.Println("error: " + err.Error())
            }
          }

        }
```

1.  通过`go run multipletcp.go`执行代码。

1.  打开另外两个终端并执行`nc localhost 8080`。

1.  在两个打开的终端中写入一些内容并查看输出。以下两个图像是连接的客户端。

+   +   终端 1 连接到`localhost:8080`：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/go-stdlib-cb/img/a3ff1b6b-ae4e-43db-8eda-51970a7c9c7e.png)

+   +   终端 2 连接到`localhost:8080`：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/go-stdlib-cb/img/ed6cbf04-737c-4795-8b0d-7121b5c5e134.png)

服务器运行的终端中的输出：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/go-stdlib-cb/img/9fc41327-6ecb-4dd7-a4b4-d4b109e1d948.png)

# 工作原理...

TCP 服务器的实现与本章的前一个配方*创建 TCP 服务器*相同。实现已增强，具有同时处理多个客户端的能力。请注意，我们现在在单独的`goroutine`中处理接受的连接。这意味着服务器可以继续使用`Accept`方法接受客户端连接。

因为 UDP 协议不是有状态的，也不保持任何连接，所以处理多个客户端的工作被移动到应用程序逻辑中，您需要识别客户端和数据包序列。只有向客户端写入响应才能使用 goroutines 并行化。

# 创建 HTTP 服务器

在 Go 中创建 HTTP 服务器非常容易，标准库提供了更多的方法来实现。让我们看看最基本的方法。

# 如何做...

1.  打开控制台并创建文件夹`chapter09/recipe04`。

1.  导航到目录。

1.  创建`httpserver.go`文件，内容如下：

```go
        package main

        import (
          "fmt"
          "net/http"
        )

        type SimpleHTTP struct{}

        func (s SimpleHTTP) ServeHTTP(rw http.ResponseWriter,
                            r *http.Request) {
          fmt.Fprintln(rw, "Hello world")
        }

        func main() {
          fmt.Println("Starting HTTP server on port 8080")
          // Eventually you can use
          // http.ListenAndServe(":8080", SimpleHTTP{})
          s := &http.Server{Addr: ":8080", Handler: SimpleHTTP{}}
          s.ListenAndServe()
        }
```

1.  通过`go run httpserver.go`执行代码。

1.  查看输出：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/go-stdlib-cb/img/d968e06b-4856-4ba6-a454-2da48208c165.png)

1.  在浏览器中访问 URL `http://localhost:8080`，或使用`curl`。应该显示`Hello world`内容：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/go-stdlib-cb/img/013de77f-87a8-4bd4-91e5-f0dc437e913c.png)

# 工作原理...

`net/http`包包含了几种创建 HTTP 服务器的方法。最简单的方法是实现`net/http`包中的`Handler`接口。`Handler`接口要求类型实现`ServeHTTP`方法。这个方法处理请求和响应。

服务器本身以`net/http`包中的`Server`结构的形式创建。`Server`结构需要`Handler`和`Addr`字段。通过调用`ListenAndServe`方法，服务器开始在给定地址上提供内容。

如果使用`Server`的`Serve`方法，则必须提供`Listener`。

`net/http`包还提供了默认服务器，如果从`net/http`包中调用`ListenAndServe`作为函数，则可以使用。它消耗`Handler`和`Addr`，与`Server`结构相同。在内部，创建了`Server`。

# 处理 HTTP 请求

应用程序通常使用 URL 路径和 HTTP 方法来定义应用程序的行为。本配方将说明如何利用标准库来处理不同的 URL 和方法。

# 如何做...

1.  打开控制台并创建文件夹`chapter09/recipe05`。

1.  导航到目录。

1.  创建`handle.go`文件，内容如下：

```go
        package main

        import (
          "fmt"
          "net/http"
        )

        func main() {

          mux := http.NewServeMux()
          mux.HandleFunc("/user", func(w http.ResponseWriter, 
                         r *http.Request) {
            if r.Method == http.MethodGet {
              fmt.Fprintln(w, "User GET")
            }
            if r.Method == http.MethodPost {
              fmt.Fprintln(w, "User POST")
            }
          })

          // separate handler
          itemMux := http.NewServeMux()
          itemMux.HandleFunc("/items/clothes", func(w http.ResponseWriter,
                             r *http.Request) {
            fmt.Fprintln(w, "Clothes")
          })
          mux.Handle("/items/", itemMux)

          // Admin handlers
          adminMux := http.NewServeMux()
          adminMux.HandleFunc("/ports", func(w http.ResponseWriter,
                              r *http.Request) {
            fmt.Fprintln(w, "Ports")
          })

          mux.Handle("/admin/", http.StripPrefix("/admin",
                                adminMux))

          // Default server
          http.ListenAndServe(":8080", mux)

        }
```

1.  通过`go run handle.go`执行代码。

1.  在浏览器中或通过`curl`检查以下 URL：

+   `http://localhost:8080/user`

+   `http://localhost:8080/items/clothes`

+   `http://localhost:8080/admin/ports`

1.  查看输出：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/go-stdlib-cb/img/a51caee0-0d11-49f0-8f5f-c947a53ce435.png)

# 工作原理...

`net/http`包包含`ServeMux`结构，该结构实现了`Handler`接口，可用于`Server`结构，但还包含了如何定义不同路径处理的机制。`ServeMux`指针包含`HandleFunc`和`Handle`方法，接受路径，`HandlerFunc`函数处理给定路径的请求，或者另一个处理程序执行相同的操作。

参见前面的示例，了解如何使用这些。`Handler`接口和`HandlerFunc`需要实现带有请求和响应参数的函数。这样你就可以访问这两个结构。请求本身可以访问`Headers`、HTTP 方法和其他请求参数。

# 创建 HTTP 中间件层

具有 Web UI 或 REST API 的现代应用程序通常使用中间件机制来记录活动或保护给定接口的安全性。在本示例中，将介绍实现这种中间件层。

# 如何做...

1.  打开控制台并创建文件夹`chapter09/recipe06`。

1.  导航到目录。

1.  创建具有以下内容的`middleware.go`文件：

```go
        package main

        import (
          "io"
          "net/http"
        )

        func main() {

          // Secured API
          mux := http.NewServeMux()
          mux.HandleFunc("/api/users", Secure(func(w http.ResponseWriter,
                         r *http.Request) {
            io.WriteString(w,  `[{"id":"1","login":"ffghi"},
                           {"id":"2","login":"ffghj"}]`)
          }))

          http.ListenAndServe(":8080", mux)

        }

        func Secure(h http.HandlerFunc) http.HandlerFunc {
          return func(w http.ResponseWriter, r *http.Request) {
            sec := r.Header.Get("X-Auth")
            if sec != "authenticated" {
              w.WriteHeader(http.StatusUnauthorized)
              return
            }
            h(w, r) // use the handler
          }

        }
```

1.  通过`go run middleware.go`执行代码。

1.  使用`curl`检查 URL`http://localhost:8080/api/users`，通过执行这两个命令（第一个不带`X-Auth`头，第二个带`X-Auth`头）：

+   `curl -X GET -I http://localhost:8080/api/users`

+   `curl -X GET -H "X-Auth: authenticated" -I http://localhost:8080/api/users`

1.  查看输出：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/go-stdlib-cb/img/4689efc2-a6b0-4f6b-916f-60e382705cad.png)

1.  使用`X-User`头测试 URL`http://localhost:8080/api/profile`。

1.  查看输出：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/go-stdlib-cb/img/6508230d-9f72-47ac-8518-6a646364fb91.png)

# 工作原理...

在前面的示例中，中间件的实现利用了 Golang 的*函数作为一等公民*功能。原始的`HandlerFunc`被包装成检查`X-Auth`头的`HandlerFunc`。然后使用`Secure`函数来保护`HandlerFunc`，并在`ServeMux`的`HandleFunc`方法中使用。

请注意，这只是一个简单的示例，但是您可以实现更复杂的解决方案。例如，用户身份可以从`Header`令牌中提取，随后可以定义新类型的处理程序，如`type AuthHandler func(u *User,w http.ResponseWriter, r *http.Request)`。然后，`WithUser`函数为`ServeMux`创建`HandlerFunc`。

# 提供静态文件

几乎任何 Web 应用程序都需要提供静态文件。使用标准库可以轻松实现 JavaScript 文件、静态 HTML 页面或 CSS 样式表的提供。本示例将展示如何实现。

# 如何做...

1.  打开控制台并创建文件夹`chapter09/recipe07`。

1.  导航到目录。

1.  创建具有以下内容的文件`welcome.txt`：

```go
        Hi, Go is awesome!
```

1.  创建文件夹`html`，导航到该文件夹并创建具有以下内容的文件`page.html`：

```go
        <html>
          <body>
            Hi, I'm HTML body for index.html!
          </body>
        </html>
```

1.  创建具有以下内容的`static.go`文件：

```go
        package main

        import (
          "net/http"
        )

        func main() {

          fileSrv := http.FileServer(http.Dir("html"))
          fileSrv = http.StripPrefix("/html", fileSrv)

          http.HandleFunc("/welcome", serveWelcome)
          http.Handle("/html/", fileSrv)
          http.ListenAndServe(":8080", nil)
        }

        func serveWelcome(w http.ResponseWriter, r *http.Request) {
          http.ServeFile(w, r, "welcome.txt")
        }
```

1.  通过`go run static.go`执行代码。

1.  使用浏览器或`curl`实用程序检查以下 URL：

+   `http://localhost:8080/html/page.html`

+   `http://localhost:8080/welcome`

1.  查看输出：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/go-stdlib-cb/img/3f559fb9-21e6-4e04-87cb-e8c704091a71.png)

# 工作原理...

`net/http`包提供了`ServeFile`和`FileServer`函数，用于提供静态文件。`ServeFile`函数只消耗给定文件路径参数的`ResponseWriter`和`Request`，并将文件内容写入响应。

`FileServer`函数创建整个消耗`FileSystem`参数的`Handler`。前面的示例使用了`Dir`类型，它实现了`FileSystem`接口。`FileSystem`接口需要实现`Open`方法，该方法消耗字符串并返回给定路径的实际`File`。

# 使用模板生成的内容

对于某些目的，不需要使用所有 JavaScript 创建高度动态的 Web UI，生成内容的静态内容可能已经足够。Go 标准库提供了一种构建动态生成内容的方法。本示例将引导您进入 Go 标准库模板化。

# 如何做...

1.  打开控制台并创建文件夹`chapter09/recipe08`。

1.  导航到目录。

1.  创建具有以下内容的文件`template.tpl`：

```go
        <html>
          <body>
            Hi, I'm HTML body for index.html!
          </body>
        </html>
```

1.  创建文件`dynamic.go`，内容如下：

```go
        package main

        import "net/http"
        import "html/template"

        func main() {
          tpl, err := template.ParseFiles("template.tpl")
          if err != nil {
            panic(err)
          }

          http.HandleFunc("/",func(w http.ResponseWriter, r *http.Request){
            err := tpl.Execute(w, "John Doe")
            if err != nil {
              panic(err)
            }
          })
          http.ListenAndServe(":8080", nil)
        }
```

1.  通过`go run dynamic.go`执行代码。

1.  检查 URL `http://localhost:8080`并查看输出：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/go-stdlib-cb/img/7ccdc694-3eb4-4c27-a8a7-fdaa4c8a70b2.png)

# 工作原理...

Go 标准库还包含用于模板化内容的包。`html/template`和`text/template`包提供了解析模板和使用它们创建输出的函数。解析是使用`ParseXXX`函数或新创建的`Template`结构指针的方法完成的。前面的示例使用了`html/template`包的`ParseFiles`函数。

模板本身是基于文本的文档或包含动态变量的文本片段。模板的使用基于将模板文本与包含模板中的变量值的结构进行合并。为了将模板与这些结构进行合并，有`Execute`和`ExecuteTemplate`方法。请注意，这些方法使用写入器接口，其中写入输出；在这种情况下使用`ResponseWriter`。

模板语法和特性在文档中有很好的解释。

# 处理重定向

重定向是告诉客户端内容已经移动或需要在其他地方完成请求的常用方式。本教程描述了如何使用标准库实现重定向。

# 如何做...

1.  打开控制台并创建文件夹`chapter09/recipe09`。

1.  导航到目录。

1.  创建文件`redirect.go`，内容如下：

```go
        package main

        import (
          "fmt"
          "log"
          "net/http"
        )

        func main() {
          log.Println("Server is starting...")

          http.Handle("/secured/handle",
               http.RedirectHandler("/login", 
                      http.StatusTemporaryRedirect))
          http.HandleFunc("/secured/hadlefunc", 
               func(w http.ResponseWriter, r *http.Request) {
            http.Redirect(w, r, "/login", http.StatusTemporaryRedirect)
          })
          http.HandleFunc("/login", func(w http.ResponseWriter,
                          r *http.Request) {
            fmt.Fprintf(w, "Welcome user! Please login!\n")
          })
          if err := http.ListenAndServe(":8080", nil); err != nil {
            panic(err)
          }
        }
```

1.  通过`go run redirect.go`执行代码。

1.  使用`curl -v -L http://localhost:8080/s`

`ecured/handle`以查看重定向是否有效：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/go-stdlib-cb/img/9aea8cdd-df60-4b0a-9a56-93249e28c8bd.png)

# 工作原理...

`net/http`包中包含了执行重定向的简单方法。可以利用`RedirectHandler`。该函数接受请求将被重定向的`URL`和将发送给客户端的`状态码`。该函数本身将结果发送给`Handler`，可以在`ServeMux`的`Handle`方法中使用（示例直接使用包中的默认方法）。

第二种方法是使用`Redirect`函数，它可以为您执行重定向。该函数接受`ResponseWriter`、请求指针和与`RequestHandler`相同的 URL 和状态码，这些将发送给客户端。

重定向也可以通过手动设置`Location`头并编写适当的状态码来完成。Go 库使开发人员能够轻松使用这一功能。

# 处理 cookies

Cookies 提供了一种在客户端方便地存储数据的方式。本教程演示了如何使用标准库设置、检索和删除 cookies。

# 如何做...

1.  打开控制台并创建文件夹`chapter09/recipe10`。

1.  导航到目录。

1.  创建文件`cookies.go`，内容如下：

```go
        package main

        import (
          "fmt"
          "log"
          "net/http"
          "time"
        )

        const cookieName = "X-Cookie"

        func main() {
          log.Println("Server is starting...")

          http.HandleFunc("/set", func(w http.ResponseWriter,
                          r *http.Request) {
            c := &http.Cookie{
              Name: cookieName,
              Value: "Go is awesome.",
              Expires: time.Now().Add(time.Hour),
              Domain: "localhost",
            }
            http.SetCookie(w, c)
            fmt.Fprintln(w, "Cookie is set!")
          })
          http.HandleFunc("/get", func(w http.ResponseWriter,
                          r *http.Request) {
            val, err := r.Cookie(cookieName)
            if err != nil {
              fmt.Fprintln(w, "Cookie err: "+err.Error())
              return
            }
            fmt.Fprintf(w, "Cookie is: %s \n", val.Value)
            fmt.Fprintf(w, "Other cookies")
            for _, v := range r.Cookies() {
              fmt.Fprintf(w, "%s => %s \n", v.Name, v.Value)
            }
          })
          http.HandleFunc("/remove", func(w http.ResponseWriter,
                          r *http.Request) {
            val, err := r.Cookie(cookieName)
            if err != nil {
              fmt.Fprintln(w, "Cookie err: "+err.Error())
              return
            }
            val.MaxAge = -1
            http.SetCookie(w, val)
            fmt.Fprintln(w, "Cookie is removed!")
          })
          if err := http.ListenAndServe(":8080", nil); err != nil {
            panic(err)
          }
        }
```

1.  通过`go run cookies.go`执行代码。

1.  按照以下顺序访问 URL 并查看：

+   +   在浏览器中访问 URL `http://localhost:8080/set`的响应：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/go-stdlib-cb/img/94747619-36e0-41ac-80b9-afd0caefacbd.png)

+   +   在浏览器中访问 URL `http://localhost:8080/get`的响应（响应包含可用的 cookies）：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/go-stdlib-cb/img/71f9eafc-cbbe-4c49-a539-d31ba6aa96d2.png)

+   +   在浏览器中访问 URL `http://localhost:8080/remove`的响应（这将删除 cookie）：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/go-stdlib-cb/img/b753a078-b68e-47cf-bb10-7f83a8a5897a.png)

+   +   在浏览器中访问 URL `http://localhost:8080/get`的响应（证明 cookie `X-Cookie`已被移除）：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/go-stdlib-cb/img/50a7c538-9702-4101-883b-9be3d0f5f1a8.png)

# 工作原理...

`net/http`包还提供了操作 cookie 的函数和机制。示例代码介绍了如何设置/获取和删除 cookie。`SetCookie`函数接受代表 cookie 的`Cookie`结构指针，自然也接受`ResponseWriter`。`Name`、`Value`、`Domain`和过期时间直接在`Cookie`结构中设置。在幕后，`SetCookie`函数写入头文件以设置 cookie。

可以从`Request`结构中检索 cookie 值。具有名称参数的`Cookie`方法返回指向`Cookie`的指针，如果请求中存在 cookie。

要列出请求中的所有 cookie，可以调用`Cookies`方法。此方法返回`Cookie`结构指针的切片。

为了让客户端知道应该删除 cookie，可以检索具有给定名称的`Cookie`，并将`MaxAge`字段设置为负值。请注意，这不是 Go 的特性，而是客户端应该工作的方式。

# 优雅关闭 HTTP 服务器

在第一章中，*与环境交互*，介绍了实现优雅关闭的机制。在这个示例中，我们将描述如何关闭 HTTP 服务器并给予它处理现有客户端的时间。

# 操作步骤...

1.  打开控制台并创建文件夹`chapter09/recipe11`。

1.  导航到目录。

1.  创建名为`gracefully.go`的文件，内容如下：

```go
        package main

        import (
          "context"
          "fmt"
          "log"
          "net/http"
          "os"
          "os/signal"
          "time"
        )

        func main() {

          mux := http.NewServeMux()
          mux.HandleFunc("/",func(w http.ResponseWriter, r *http.Request){
            fmt.Fprintln(w, "Hello world!")
          })

          srv := &http.Server{Addr: ":8080", Handler: mux}
          go func() {
            if err := srv.ListenAndServe(); err != nil {
              log.Printf("Server error: %s\n", err)
            }
          }()

          log.Println("Server listening on : " + srv.Addr)

          stopChan := make(chan os.Signal)
          signal.Notify(stopChan, os.Interrupt)

          <-stopChan // wait for SIGINT
          log.Println("Shutting down server...")

          ctx, cancel := context.WithTimeout(
            context.Background(),
            5*time.Second)
          srv.Shutdown(ctx)
          <-ctx.Done()
          cancel()
          log.Println("Server gracefully stopped")
        }
```

1.  通过`go run gracefully.go`执行代码。

1.  等待服务器开始监听：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/go-stdlib-cb/img/77347b25-fda9-49ea-b253-64bcb6839553.png)

1.  使用浏览器连接到`http://localhost:8080`；这将导致浏览器等待 10 秒钟的响应。

1.  在 10 秒的间隔内，按下*Ctrl* + *C*发送`SIGINT`信号。

1.  尝试从另一个标签页重新连接（服务器应该拒绝其他连接）。

1.  在终端中查看输出：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/go-stdlib-cb/img/fe6669e0-c15f-4bae-9492-be6c5636a481.png)

# 工作原理...

`net/http`包中的`Server`提供了优雅关闭连接的方法。前面的代码在一个单独的`goroutine`中启动 HTTP 服务器，并在一个变量中保留对`Server`结构的引用。

通过调用`Shutdown`方法，`Server`开始拒绝新连接并关闭打开的监听器和空闲连接。然后它无限期地等待已经挂起的连接，直到这些连接变为空闲。在所有连接关闭后，服务器关闭。请注意，`Shutdown`方法会消耗`Context`。如果提供的`Context`在关闭之前过期，则会返回来自`Context`的错误，并且`Shutdown`不再阻塞。

# 提供安全的 HTTP 内容

这个示例描述了创建 HTTP 服务器的最简单方式，它通过 TLS/SSL 层提供内容。

# 准备工作

准备私钥和自签名的 X-509 证书。为此，可以使用 OpenSSL 实用程序。通过执行命令`openssl genrsa -out server.key 2048`，使用 RSA 算法生成私钥到文件`server.key`。基于此私钥，可以通过调用`openssl req -new -x509 -sha256 -key server.key -out server.crt -days 365`生成 X-509 证书。创建`server.crt`文件。

# 操作步骤...

1.  打开控制台并创建文件夹`chapter09/recipe12`。

1.  导航到目录。

1.  将创建的`server.key`和`server.crt`文件放入其中。

1.  创建名为`servetls.go`的文件，内容如下：

```go
        package main

        import (
          "fmt"
          "net/http"
        )

        type SimpleHTTP struct{}

          func (s SimpleHTTP) ServeHTTP(rw http.ResponseWriter,
                              r *http.Request) {
            fmt.Fprintln(rw, "Hello world")
          }

          func main() {
            fmt.Println("Starting HTTP server on port 8080")
            // Eventually you can use
            // http.ListenAndServe(":8080", SimpleHTTP{})
            s := &http.Server{Addr: ":8080", Handler: SimpleHTTP{}}
            if err := s.ListenAndServeTLS("server.crt", "server.key");
            err != nil {
              panic(err)
            }
          }
```

1.  通过`go run servetls.go`执行服务器。

1.  访问 URL `https://localhost:8080`（使用 HTTPS 协议）。如果使用`curl`实用程序，则必须使用`--insecure`标志，因为我们的证书是自签名的，不受信任：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/go-stdlib-cb/img/e896790c-9b63-4b81-905f-5ae525a862a9.png)

# 工作原理...

除了`net/http`包中的`ListenAndServe`函数之外，还存在用于通过 SSL/TLS 提供 HTTP 服务的 TLS 变体。通过`Server`的`ListenAndServeTLS`方法，可以提供安全的 HTTP 服务。`ListenAndServeTLS`需要私钥和 X-509 证书的路径。当然，也可以直接使用`net/http`包中的`ListenAndServeTLS`函数。

# 解析表单变量

HTTP 的`POST`表单是向服务器传递信息的一种常见方式，以结构化的方式。这个示例展示了如何在服务器端解析和访问这些信息。

# 如何做...

1.  打开控制台，创建文件夹`chapter09/recipe12`。

1.  导航到目录。

1.  创建名为`form.go`的文件，内容如下：

```go
        package main

        import (
          "fmt"
          "net/http"
        )

        type StringServer string

        func (s StringServer) ServeHTTP(rw http.ResponseWriter,
                              req *http.Request) {
          fmt.Printf("Prior ParseForm: %v\n", req.Form)
          req.ParseForm()
          fmt.Printf("Post ParseForm: %v\n", req.Form)
          fmt.Println("Param1 is : " + req.Form.Get("param1"))
          rw.Write([]byte(string(s)))
        }

        func createServer(addr string) http.Server {
          return http.Server{
            Addr: addr,
            Handler: StringServer("Hello world"),
          }
        }

        func main() {
          s := createServer(":8080")
          fmt.Println("Server is starting...")
          if err := s.ListenAndServe(); err != nil {
            panic(err)
          }
        }
```

1.  通过`go run form.go`执行代码。

1.  打开第二个终端，使用`curl`执行`POST`：

```go
 curl -X POST -H "Content-Type: app
lication/x-www-form-urlencoded" -d "param1=data1&param2=data2" "localhost:8080?
param1=overriden&param3=data3"
```

1.  在运行服务器的第一个终端中查看输出：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/go-stdlib-cb/img/dfb65601-5441-4053-b9e5-01235355f3d3.png)

# 工作原理...

`net/http`包的`Request`结构包含`Form`字段，其中包含了`POST`表单变量和 URL 查询变量的合并。在前面的代码中，重要的一步是在`Request`指针上调用`ParseForm`方法。这个方法调用会将`POST`表单值和查询值解析为一个`Form`变量。请注意，如果在`Form`字段上使用`Get`方法，则会优先考虑参数的`POST`值。`Form`和`PostForm`字段实际上都是`url.Values`类型。

如果只需要访问`POST`表单中的参数，可以使用`Request`的`PostForm`字段。这个字段只保留了`POST`主体中的参数。


# 第十章：并发乐趣

本章包含以下教程：

+   使用 Mutex 同步对资源的访问

+   为并发访问创建 map

+   只运行一次代码块

+   在多个 goroutines 之间池化资源

+   使用 WaitGroup 同步 goroutines

+   从多个来源获取最快的结果

+   使用 errgroup 传播错误

# 介绍

并发行为的编程总是很困难的。Go 具有非常好的机制来管理并发，如通道。除了通道作为同步机制外，Go 标准库还提供了处理更传统核心方式的并发部分的包。本章描述了如何利用 sync 包来实现常见的同步任务。最后一个教程将展示如何简化一组 goroutines 的错误传播。

检查 Go 是否已正确安装。*第一章*的*检索 Golang 版本*教程中的*准备就绪*部分将对你有所帮助。

确保端口`8080`和`7070`没有被其他应用程序使用。

# 使用 Mutex 同步对资源的访问

如果代码使用并发访问被认为对并发使用不安全的任何资源，就需要实现同步机制来保护访问。除了使用通道，还可以利用互斥锁来实现这一目的。这个教程将向你展示如何做到这一点。

# 如何做...

1.  打开控制台并创建文件夹`chapter10/recipe01`。

1.  导航到目录。

1.  创建文件`mutex.go`，内容如下：

```go
        package main

        import (
          "fmt"
          "sync"
        )

        var names = []string{"Alan", "Joe", "Jack", "Ben",
                             "Ellen", "Lisa", "Carl", "Steve",
                             "Anton", "Yo"}

        type SyncList struct {
          m sync.Mutex
          slice []interface{}
        }

        func NewSyncList(cap int) *SyncList {
          return &SyncList{
            sync.Mutex{},
            make([]interface{}, cap),
          }
        }

        func (l *SyncList) Load(i int) interface{} {
          l.m.Lock()
          defer l.m.Unlock()
          return l.slice[i]
        }

        func (l *SyncList) Append(val interface{}) {
          l.m.Lock()
          defer l.m.Unlock()
          l.slice = append(l.slice, val)
        }

        func (l *SyncList) Store(i int, val interface{}) {
          l.m.Lock()
          defer l.m.Unlock()
          l.slice[i] = val
        }

        func main() {

          l := NewSyncList(0)
          wg := &sync.WaitGroup{}
          wg.Add(10)
          for i := 0; i < 10; i++ {
            go func(idx int) {
              l.Append(names[idx])
              wg.Done()
            }(i)
          }
          wg.Wait()

          for i := 0; i < 10; i++ {
            fmt.Printf("Val: %v stored at idx: %d\n", l.Load(i), i)
          }

        }
```

1.  通过`go run mutex.go`执行代码。

1.  查看输出：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/go-stdlib-cb/img/74cd4a32-0ae7-4ae9-a01d-818c46a48289.png)

# 它是如何工作的...

同步原语`Mutex`由`sync`包提供。`Mutex`作为一个锁，用于保护部分或资源。一旦`goroutine`在`Mutex`上调用`Lock`并且`Mutex`处于未锁定状态，`Mutex`就会被锁定，`goroutine`就可以独占地访问临界区。如果`Mutex`处于锁定状态，`goroutine`调用`Lock`方法。这个`goroutine`会被阻塞，需要等待`Mutex`再次解锁。

请注意，在示例中，我们使用`Mutex`来同步对切片原语的访问，这被认为是不安全的并发使用。

重要的事实是`Mutex`在第一次使用后不能被复制。

# 为并发访问创建 map

在 Golang 中，map 原语应被视为不安全的并发访问。在上一个教程中，我们描述了如何使用 Mutex 同步对资源的访问，这也可以用于对 map 原语的访问。但是 Go 标准库还提供了专为并发访问设计的 map 结构。这个教程将说明如何使用它。

# 如何做...

1.  打开控制台并创建文件夹`chapter10/recipe02`。

1.  导航到目录。

1.  创建文件`map.go`，内容如下：

```go
        package main

        import (
          "fmt"
          "sync"
        )

        var names = []string{"Alan", "Joe", "Jack", "Ben",
                             "Ellen", "Lisa", "Carl", "Steve",
                             "Anton", "Yo"}

        func main() {

          m := sync.Map{}
          wg := &sync.WaitGroup{}
          wg.Add(10)
          for i := 0; i < 10; i++ {
            go func(idx int) {
              m.Store(fmt.Sprintf("%d", idx), names[idx])
              wg.Done()
            }(i)
          }
          wg.Wait()

          v, ok := m.Load("1")
          if ok {
            fmt.Printf("For Load key: 1 got %v\n", v)
          }

          v, ok = m.LoadOrStore("11", "Tim")
          if !ok {
            fmt.Printf("Key 11 missing stored val: %v\n", v)
          }

          m.Range(func(k, v interface{}) bool {
            key, _ := k.(string)
            t, _ := v.(string)
            fmt.Printf("For index %v got %v\n", key, t)
            return true
          })

        }
```

1.  通过`go run map.go`执行代码。

1.  查看输出：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/go-stdlib-cb/img/45f734cb-36b0-4b7a-85c7-e88fbef33ba4.png)

# 它是如何工作的...

`sync`包中包含了`Map`结构，该结构被设计用于从多个 Go 例程中并发使用。`Map`结构及其方法模仿了 map 原语的行为。`Store`方法相当于`m[key] = val`语句。`Load`方法相当于`val, ok := m[key]`，`Range`方法提供了遍历 map 的能力。请注意，`Range`函数与`Map`的当前状态一起工作，因此如果在运行`Range`方法期间更改了值，则会反映这些更改，但前提是该键尚未被访问。`Range`函数只会访问其键一次。

# 只运行一次代码块

在多个 goroutine 运行相同代码的情况下，例如，有一个初始化共享资源的代码块，Go 标准库提供了解决方案，将在下文中描述。

# 如何做...

1.  打开控制台并创建文件夹`chapter10/recipe03`。

1.  导航到目录。

1.  创建文件`once.go`，内容如下：

```go
        package main

        import (
          "fmt"
          "sync"
        )

        var names = []interface{}{"Alan", "Joe", "Jack", "Ben",
                                  "Ellen", "Lisa", "Carl", "Steve",
                                  "Anton", "Yo"}

        type Source struct {
          m *sync.Mutex
          o *sync.Once
          data []interface{}
        }

        func (s *Source) Pop() (interface{}, error) {
          s.m.Lock()
          defer s.m.Unlock()
          s.o.Do(func() {
            s.data = names
            fmt.Println("Data has been loaded.")
          })
          if len(s.data) > 0 {
            res := s.data[0]
            s.data = s.data[1:]
            return res, nil
          }
          return nil, fmt.Errorf("No data available")
        }

        func main() {

          s := &Source{&sync.Mutex{}, &sync.Once{}, nil}
          wg := &sync.WaitGroup{}
          wg.Add(10)
          for i := 0; i < 10; i++ {
            go func(idx int) {
              // This code block is done only once
              if val, err := s.Pop(); err == nil {
                fmt.Printf("Pop %d returned: %s\n", idx, val)
              }
              wg.Done()
            }(i)
          }
          wg.Wait()
        }
```

1.  使用`go run once.go`执行代码。

1.  查看输出：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/go-stdlib-cb/img/4e9a0641-c657-405e-9403-e46cea0a4fcd.png)

# 工作原理...

示例代码说明了在访问容器结构时数据的延迟加载。由于数据只应加载一次，因此在`Pop`方法中使用了`sync`包中的`Once`结构。`Once`只实现了一个名为`Do`的方法，该方法消耗了一个无参数的`func`，并且该函数在每个`Once`实例的执行期间只执行一次。

`Do`方法调用会阻塞，直到第一次运行完成。这一事实与`Once`旨在用于初始化的事实相对应。

# 在多个 goroutine 之间池化资源

资源池是提高性能和节省资源的传统方式。通常，值得使用昂贵初始化的资源进行池化。Go 标准库提供了用于资源池的骨架结构，被认为对多个 goroutine 访问是安全的。本示例描述了如何使用它。

# 如何做...

1.  打开控制台并创建文件夹`chapter10/recipe04`。

1.  导航到目录。

1.  创建文件`pool.go`，内容如下：

```go
        package main

        import "sync"
        import "fmt"
        import "time"

        type Worker struct {
          id string
        }

        func (w *Worker) String() string {
          return w.id
        }

        var globalCounter = 0

        var pool = sync.Pool{
          New: func() interface{} {
            res := &Worker{fmt.Sprintf("%d", globalCounter)}
            globalCounter++
            return res
          },
        }

        func main() {
          wg := &sync.WaitGroup{}
          wg.Add(10)
          for i := 0; i < 10; i++ {
            go func(idx int) {
              // This code block is done only once
              w := pool.Get().(*Worker)
              fmt.Println("Got worker ID: " + w.String())
              time.Sleep(time.Second)
              pool.Put(w)
              wg.Done()
            }(i)
          }
          wg.Wait()
        }
```

1.  使用`go run pool.go`执行代码。

1.  查看输出：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/go-stdlib-cb/img/4b1f1b1a-910b-46ea-8e86-82980e37e096.png)

# 工作原理...

`sync`包包含了用于池化资源的结构。`Pool`结构具有`Get`和`Put`方法，用于检索资源并将其放回池中。`Pool`结构被认为对并发访问是安全的。

在创建`Pool`结构时，需要设置`New`字段。`New`字段是一个无参数函数，应该返回指向池化项目的指针。如果需要初始化池中的新对象，则会调用此函数。

从前面示例的日志中可以看出，`Worker`在返回到池中时被重用。重要的事实是，不应该对`Get`检索的项目和`Put`方法返回的项目做任何假设（比如我刚刚把三个对象放到池中，所以至少会有三个可用）。这主要是因为`Pool`中的空闲项目可能随时被自动删除。

如果资源初始化很昂贵，资源池化通常是值得的。然而，资源的管理也带来了一些额外的成本。

# 使用 WaitGroup 同步 goroutine

在处理并发运行的代码分支时，程序在某个时刻需要等待并发运行的代码部分。本示例介绍了如何使用`WaitGroup`等待运行的 goroutine。

# 如何做...

1.  打开控制台并创建文件夹`chapter10/recipe05`。

1.  导航到目录。

1.  创建文件`syncgroup.go`，内容如下：

```go
        package main

        import "sync"
        import "fmt"

        func main() {
          wg := &sync.WaitGroup{}
          for i := 0; i < 10; i++ {
            wg.Add(1)
            go func(idx int) {
              // Do some work
              defer wg.Done()
              fmt.Printf("Exiting %d\n", idx)
            }(i)
          }
          wg.Wait()
          fmt.Println("All done.")
        }
```

1.  使用`go run syncgroup.go`执行代码。

1.  查看输出：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/go-stdlib-cb/img/ecce87d6-6a87-44ff-a4d1-d0fcc182549d.png)

# 工作原理...

通过`sync`包中的`WaitGroup`结构，程序可以等待有限数量的 goroutine 完成运行。`WaitGroup`结构实现了`Add`方法，用于添加要等待的 goroutine 数量。然后在 goroutine 完成后，应调用`Done`方法来减少要等待的 goroutine 数量。`Wait`方法被调用时会阻塞，直到完成给定数量的`Done`调用（通常在`goroutine`结束时）。`WaitGroup`应该与`sync`包中的所有同步原语一样使用。在创建对象后，结构不应被复制。

# 从多个来源获取最快的结果

在某些情况下，例如，在整合来自多个来源的信息检索时，您只需要第一个结果，最快的结果，其他结果在那之后就不相关了。现实世界中的一个例子可能是提取货币汇率以计算价格。您有多个第三方服务，因为您需要尽快显示价格，所以只需要从任何服务接收到的第一个汇率。本教程将展示如何实现这种行为的模式。

# 如何做...

1.  打开控制台并创建文件夹 `chapter10/recipe06`。

1.  导航到目录。

1.  创建文件 `first.go`，内容如下：

```go
        package main

        import (
          "context"
          "fmt"
          "sync"
          "time"
        )

        type SearchSrc struct {
          ID string
          Delay int
        }

        func (s *SearchSrc) Search(ctx context.Context) <-chan string {
          out := make(chan string)
          go func() {
            time.Sleep(time.Duration(s.Delay) * time.Second)
            select {
              case out <- "Result " + s.ID:
              case <-ctx.Done():
              fmt.Println("Search received Done()")
            }
            close(out)
            fmt.Println("Search finished for ID: " + s.ID)
          }()
          return out
        }

        func main() {

          ctx, cancel := context.WithCancel(context.Background())

          src1 := &SearchSrc{"1", 2}
          src2 := &SearchSrc{"2", 6}

          r1 := src1.Search(ctx)
          r2 := src2.Search(ctx)

          out := merge(ctx, r1, r2)

          for firstResult := range out {
            cancel()
            fmt.Println("First result is: " + firstResult)
          }
        }

        func merge(ctx context.Context, results ...<-chan string)
                   <-chan string {
          wg := sync.WaitGroup{}
          out := make(chan string)

          output := func(c <-chan string) {
            defer wg.Done()
            select {
              case <-ctx.Done():
                fmt.Println("Received ctx.Done()")
              case res := <-c:
              out <- res
            }
          }

          wg.Add(len(results))
          for _, c := range results {
            go output(c)
          }

          go func() {
            wg.Wait()
            close(out)
          }()
          return out
        }
```

1.  通过 `go run first.go` 执行代码。

1.  查看输出：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/go-stdlib-cb/img/2011444d-0d1e-4b2b-afb4-2806dc133819.png)

# 它是如何工作的...

上述代码提出了执行多个任务并输出一些结果的解决方案，我们只需要最快的一个。解决方案使用 `Context` 和取消函数来在获得第一个结果后调用取消。`SearchSrc` 结构提供了 `Search` 方法，该方法会导致写入结果的通道。请注意，`Search` 方法使用 `time.Sleep` 函数模拟延迟。对于来自 `Search` 方法的每个通道，合并函数触发写入最终输出通道的 `goroutine`，该通道在 `main` 方法中读取。从 `merge` 函数产生的输出通道接收到第一个结果时，将调用存储在变量 `cancel` 中的 `CancelFunc` 来取消其余处理。

请注意，`Search` 方法仍然需要结束，即使其结果不会被处理；因此，需要处理以避免 `goroutine` 和通道泄漏。

# 使用 errgroup 传播错误

本教程将展示如何轻松使用 errgroup 扩展包来检测 goroutine 组中运行子任务的错误。

# 如何做...

1.  打开控制台并创建文件夹 `chapter10/recipe07`。

1.  导航到目录。

1.  创建文件 `lines.go`，内容如下：

```go
        package main

        import (
          "bufio"
          "context"
          "fmt"
          "log"
          "strings"

          "golang.org/x/sync/errgroup"
        )

        const data = `line one
        line two with more words
        error: This is erroneous line`

        func main() {
          log.Printf("Application %s starting.", "Error Detection")
          scanner := bufio.NewScanner(strings.NewReader(data))
          scanner.Split(bufio.ScanLines)

          // For each line fire a goroutine
          g, _ := errgroup.WithContext(context.Background())
          for scanner.Scan() {
            row := scanner.Text()
            g.Go(func() error {
              return func(s string) error {
                if strings.Contains(s, "error:") {
                  return fmt.Errorf(s)
                }
                return nil
              }(row)
            })
          }

          // Wait until the goroutines finish
          if err := g.Wait(); err != nil {
            fmt.Println("Error while waiting: " + err.Error())
          }

        }
```

1.  通过 `go run lines.go` 执行代码。

1.  查看输出：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/go-stdlib-cb/img/424e9afe-d9e4-4440-ab5a-1eba1b4e7aeb.png)

# 它是如何工作的...

`golang.org/x/sync/errgroup` 包有助于简化 goroutine 组的错误传播和上下文取消。`Group` 包含消耗无参数函数返回 `error` 的 Go 方法。此函数应包含应由执行的 `goroutine` 完成的任务。`errgroup` 的 `Group` 的 `Wait` 方法等待直到 Go 方法中执行的所有任务完成，如果其中任何一个返回 `err`，则返回第一个非空错误。这样，就可以简单地从运行的 goroutine 组中传播错误。

请注意，`Group` 也是使用上下文创建的。`Context` 用作取消其他任务的机制，如果发生错误。在 `goroutine` 函数返回 `error` 后，内部实现会取消上下文，因此正在运行的任务也可能会被取消。


# 第十一章：提示和技巧

本章将涵盖以下示例：

+   日志定制

+   测试代码

+   对代码进行基准测试

+   创建子测试

+   测试 HTTP 处理程序

+   通过反射访问标签

+   对切片进行排序

+   将 HTTP 处理程序分成组

+   利用 HTTP/2 服务器推送

# 介绍

这最后一章添加了一些与测试、设计应用程序接口以及利用`sort`和`reflect`包相关的附加示例。

检查 Go 是否已正确安装。*第一章*中*准备就绪*部分的*检索 Golang 版本*示例，*与环境交互*将帮助您。

确保端口`8080`未被其他应用程序使用。

# 日志定制

除了使用`log`包中的默认记录器进行记录外，标准库还提供了一种根据应用程序或包的需求创建自定义记录器的方法。本示例将简要介绍如何创建自定义记录器。

# 如何做...

1.  打开控制台并创建文件夹`chapter11/recipe01`。

1.  导航到目录。

1.  创建名为`logging.go`的文件，其中包含以下内容：

```go
        package main

        import (
          "log"
          "os"
        )

        func main() {
          custLogger := log.New(os.Stdout, "custom1: ",
                                log.Ldate|log.Ltime)
          custLogger.Println("Hello I'm customized")

          custLoggerEnh := log.New(os.Stdout, "custom2: ",
                                   log.Ldate|log.Lshortfile)
          custLoggerEnh.Println("Hello I'm customized logger 2")

        }
```

1.  通过`go run logging.go`执行代码。

1.  查看输出：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/go-stdlib-cb/img/44cc10f1-f0cf-420c-a81f-be95d1ba11db.png)

# 它是如何工作的...

`log`包提供了`New`函数，简化了自定义记录器的创建。`New`函数接受`Writer`作为参数，该参数可以是实现`Writer`接口的任何对象，以及以字符串形式的前缀和由标志组成的日志消息的形式。最后一个参数是最有趣的，因为通过它，您可以使用动态字段增强日志消息，例如日期和文件名。

请注意，前面的示例中，第一个记录器`custLogger`配置了在日志消息前显示日期和时间的标志。第二个记录器`custLoggerEnh`使用标志`Ldate`和`Lshortfile`来显示文件名和日期。

# 测试代码

测试和基准测试自然属于软件开发。作为一种现代语言，Go 支持从头开始进行这些操作。在这个示例中，将描述测试的基础知识。

# 如何做...

1.  打开控制台并创建文件夹`chapter11/recipe02`。

1.  导航到目录。

1.  创建名为`sample_test.go`的文件，其中包含以下内容：

```go
        package main

        import (
          "strconv"
          "testing"
        )

        func TestSampleOne(t *testing.T) {
          expected := "11"
          result := strconv.Itoa(10)
          compare(expected, result, t)
        }

        func TestSampleTwo(t *testing.T) {
          expected := "11"
          result := strconv.Itoa(10)
          compareWithHelper(expected, result, t)
        }

        func TestSampleThree(t *testing.T) {
          expected := "10"
          result := strconv.Itoa(10)
          compare(expected, result, t)
        }

        func compareWithHelper(expected, result string, t *testing.T) {
          t.Helper()
          if expected != result {
            t.Fatalf("Expected result %v does not match result %v",
                     expected, result)
          }
        }

        func compare(expected, result string, t *testing.T) {
          if expected != result {
            t.Fatalf("Fail: Expected result %v does not match result %v",
                     expected, result)
          }
          t.Logf("OK: Expected result %v = %v",
                 expected, result)
        }
```

1.  通过`go test -v`执行测试。

1.  在终端中查看输出：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/go-stdlib-cb/img/ae338ff0-8ef9-4a6e-9f42-b92be7c20285.png)

# 它是如何工作的...

标准库的`testing`包提供了对代码测试需求的支持。`test`函数需要满足名称模式`TestXXX`。默认情况下，测试工具会查找名为`xxx_test.go`的文件。请注意，每个测试函数都需要接受`T`指针参数，该参数提供了用于测试控制的有用方法。通过`T`结构指针，可以设置测试的状态。例如，`Fail`和`FailNow`方法会导致测试失败。借助`T`结构指针的帮助，可以通过调用`Skip`、`Skipf`或`SkipNow`来跳过测试。

`T`指针的有趣方法是`Helper`方法。通过调用`Helper`方法，当前函数被标记为辅助函数，如果在该函数内调用`FailNow`（`Fatal`），则测试输出将指向测试中调用该函数的代码行，如前面示例代码中所示。

请注意，如果测试工具未以详细模式运行（使用`-v`标志），或者特定测试失败（仅适用于`T`测试），则`Log`方法（及其变体）将不可见。尝试在不使用`-v`标志的情况下运行此示例代码。

# 另请参阅

+   以下示例涵盖了基准测试的基础知识

+   有关测试包的更详细描述，请参阅[`golang.org/pkg/testing`](https://golang.org/pkg/testing)中测试包的丰富文档。

# 对代码进行基准测试

上一个示例介绍了测试包的测试部分，在本示例中将介绍基准测试的基础知识。

# 如何做...

1.  打开控制台并创建文件夹`chapter11/recipe03`。

1.  导航到目录。

1.  创建名为`sample_test.go`的文件，内容如下：

```go
        package main

        import (
          "log"
          "testing"
        )

        func BenchmarkSampleOne(b *testing.B) {
          logger := log.New(devNull{}, "test", log.Llongfile)
          b.ResetTimer()
          b.StartTimer()
          for i := 0; i < b.N; i++ {
            logger.Println("This si awesome")
          }
          b.StopTimer()
        }

        type devNull struct{}

        func (d devNull) Write(b []byte) (int, error) {
          return 0, nil
        }
```

1.  通过`go test -bench=`执行基准测试。

1.  在终端中查看输出：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/go-stdlib-cb/img/ca1e566d-420b-4c88-ae9b-f76989b3ff5c.png)

# 它是如何工作的...

除了纯测试支持外，测试包还提供了用于测量代码性能的机制。为此，使用`B`结构指针作为参数，并且测试文件中的基准测试函数命名为`BenchmarkXXXX`。

基准测试函数的关键部分是操作定时器和使用循环迭代计数器`N`。

如您所见，定时器通过`Reset`/`Start`/`StopTimer`方法进行操作。通过这些方法，基准测试的结果会受到影响。请注意，定时器在基准测试函数开始时开始运行，而`ResetTimer`函数只是重新启动它。

`B`的`N`字段是测量循环中的迭代次数。`N`值设置为足够高的值，以可靠地测量基准测试的结果。基准测试日志中显示迭代次数和每次迭代的测量时间。

# 另请参阅

+   下一个示例将展示如何在测试中创建子测试

+   有关基准测试的更多选项和信息，请查看此处的包文档：[`golang.org/pkg/testing`](https://golang.org/pkg/testing)

# 创建子测试

在某些情况下，有用的是创建一组可能具有类似设置或清理代码的测试。这可以在没有为每个测试创建单独函数的情况下完成。

# 如何做...

1.  打开控制台并创建文件夹`chapter11/recipe04`。

1.  导航到目录。

1.  创建名为`sample_test.go`的文件，内容如下：

```go
        package main

        import (
          "fmt"
          "strconv"
          "testing"
        )

        var testData = []int{10, 11, 017}

        func TestSampleOne(t *testing.T) {
          expected := "10"
          for _, val := range testData {
            tc := val
            t.Run(fmt.Sprintf("input = %d", tc), func(t *testing.T) {
              if expected != strconv.Itoa(tc) {
                t.Fail()
              }
            })
          }
        }
```

1.  通过`go test -v`执行测试。

1.  在终端中查看输出：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/go-stdlib-cb/img/2a644849-82e9-4c74-996f-b54f90f154da.png)

# 它是如何工作的...

`testing`包的`T`结构还提供了`Run`方法，可用于运行嵌套测试。`Run`方法需要子测试的名称和将要执行的测试函数。例如，使用表驱动测试时，这种方法可能很有益。代码示例只是使用`int`值的简单切片作为输入。

基准测试结构`B`也包含相同的方法`Run`，可以提供一种创建复杂基准测试后续步骤的方法。

# 另请参阅

在包文档中仍有很多内容要找出，[`golang.org/pkg/testing`](https://golang.org/pkg/testing)。

# 测试 HTTP 处理程序

测试`HTTP`服务器可能会很复杂。Go 标准库通过一个方便的包`net/http/httptest`简化了这一点。本示例描述了如何利用此包来测试`HTTP`处理程序。

# 如何做...

1.  打开控制台并创建文件夹`chapter11/recipe05`。

1.  导航到目录。

1.  创建名为`sample_test.go`的文件，内容如下：

```go
        package main

        import (
          "fmt"
          "io/ioutil"
          "net/http"
          "net/http/httptest"
          "testing"
          "time"
        )

        const cookieName = "X-Cookie"

        func HandlerUnderTest(w http.ResponseWriter, r *http.Request) {
          http.SetCookie(w, &http.Cookie{
            Domain: "localhost",
            Expires: time.Now().Add(3 * time.Hour),
            Name: cookieName,
          })
          r.ParseForm()
          username := r.FormValue("username")
          fmt.Fprintf(w, "Hello %s!", username)
        }

        func TestHttpRequest(t *testing.T) {

          req := httptest.NewRequest("GET",
                          "http://unknown.io?username=John", nil)
          w := httptest.NewRecorder()
          HandlerUnderTest(w, req)

          var res *http.Cookie
          for _, c := range w.Result().Cookies() {
            if c.Name == cookieName {
              res = c
            }
          }

          if res == nil {
            t.Fatal("Cannot find " + cookieName)
          }

          content, err := ioutil.ReadAll(w.Result().Body)
          if err != nil {
            t.Fatal("Cannot read response body")
          }

          if string(content) != "Hello John!" {
            t.Fatal("Content not matching expected value")
          }
        }
```

1.  通过`go test`执行测试。

1.  在终端中查看输出：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/go-stdlib-cb/img/64b6004e-183e-4200-98d7-91730c66c763.png)

# 它是如何工作的...

对于`Handler`或`HandlerFunc`的测试，可以利用`net/http/httptest`。该包提供了`ResponseRecorder`结构，能够记录响应内容并将其提供回来以断言值。用于组装请求的是`net/http`包的`NewRequest`函数。

`net/http/httptest`包还包含了在本地主机上监听系统选择端口的 HTTP 服务器版本。此实现旨在用于端到端测试。

# 通过反射访问标签

Go 语言允许给结构化字段打标签，附加额外信息。这些信息通常用作编码器的附加信息，或者对结构体进行任何类型的额外处理。这个示例将向你展示如何访问这些信息。

# 如何做...

1.  打开控制台并创建文件夹`chapter11/recipe06`。

1.  导航到目录。

1.  创建文件`structtags.go`，内容如下：

```go
        package main

        import (
          "fmt"
          "reflect"
        )

        type Person struct {
          Name string `json:"p_name" bson:"pName"`
          Age int `json:"p_age" bson:"pAge"`
        }

        func main() {
          f := &Person{"Tom", 30}
          describe(f)
        }

        func describe(f interface{}) {
          val := reflect.TypeOf(f).Elem()
          for i := 0; i < val.NumField(); i++ {
            typeF := val.Field(i)
            fieldName := typeF.Name
            jsonTag := typeF.Tag.Get("json")
            bsonTag := typeF.Tag.Get("bson")
            fmt.Printf("Field : %s jsonTag: %s bsonTag: %s\n",
                       fieldName, jsonTag, bsonTag)
          }
        }
```

1.  通过`go run structtags.go`执行代码。

1.  在终端中查看输出：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/go-stdlib-cb/img/3a755cf6-bb6e-4580-b8d4-883f0275db9f.png)

# 它是如何工作的...

可以使用`reflect`包提取`struct`标签。通过调用`TypeOf`，我们得到了`Person`的指针`Type`，随后通过调用`Elem`，我们得到了指针指向的值的`Type`。

结果的`Type`让我们可以访问`struct`类型`Person`及其字段。通过遍历字段并调用`Field`方法检索字段，我们可以获得`StructField`。`StructField`类型包含`Tag`字段，该字段提供对`struct`标签的访问。然后，`StructTag`字段上的`Get`方法返回特定的标签。

# 对切片进行排序

数据排序是一个非常常见的任务。Go 标准库通过 sort 包简化了排序。这个示例简要介绍了如何使用它。

# 如何做...

1.  打开控制台并创建文件夹`chapter11/recipe07`。

1.  导航到目录。

1.  创建文件`sort.go`，内容如下：

```go
        package main

        import (
          "fmt"
          "sort"
        )

        type Gopher struct {
          Name string
          Age int
        }

        var data = []Gopher{
          {"Daniel", 25},
          {"Tom", 19},
          {"Murthy", 33},
        }

        type Gophers []Gopher

        func (g Gophers) Len() int {
          return len(g)
        }

        func (g Gophers) Less(i, j int) bool {
          return g[i].Age > g[j].Age
        }

        func (g Gophers) Swap(i, j int) {
          tmp := g[j]
          g[j] = g[i]
          g[i] = tmp
        }

        func main() {

          sort.Slice(data, func(i, j int) bool {
            return sort.StringsAreSorted([]string{data[i].Name, 
                                      data[j].Name})
          })

          fmt.Printf("Sorted by name: %v\n", data)

          gophers := Gophers(data)
          sort.Sort(gophers)

          fmt.Printf("Sorted by age: %v\n", data)

        }
```

1.  通过`go run sort.go`执行代码。

1.  在终端中查看输出：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/go-stdlib-cb/img/410f5f55-aca0-4785-a7e3-0f9aedde9643.png)

# 它是如何工作的...

示例代码展示了如何舒适地使用`sort`包对切片进行排序的两种方式。第一种方法更加临时，它使用了`sort`包的`Slice`函数。`Slice`函数消耗要排序的切片和所谓的 less 函数，该函数定义了元素`i`是否应该在元素`j`之前排序。

第二种方法需要更多的代码和提前规划。它利用了`sort`包的`Interface`接口。该接口充当数据的代表，并要求其在排序数据上实现必要的方法：`Len`（定义数据的数量）、`Less`（less 函数）、`Swap`（调用以交换元素）。如果数据值实现了这个接口，那么可以使用`sort`包的`Sort`函数。

原始类型切片`float64`、`int`和`string`在`sort`包中有涵盖。因此，可以使用现有的实现。例如，要对字符串切片进行排序，可以调用`Strings`函数。

# 将 HTTP 处理程序分组

这个示例提供了关于如何将 HTTP 处理程序分离成模块的建议。

# 如何做...

1.  打开控制台并创建文件夹`chapter11/recipe08`。

1.  导航到目录。

1.  创建文件`handlegroups.go`，内容如下：

```go
        package main

        import (
          "fmt"
          "log"
          "net/http"
        )

         func main() {

           log.Println("Staring server...")
           // Adding to mani Mux
           mainMux := http.NewServeMux()
           mainMux.Handle("/api/",
           http.StripPrefix("/api", restModule()))
           mainMux.Handle("/ui/",
           http.StripPrefix("/ui", uiModule()))

           if err := http.ListenAndServe(":8080", mainMux); err != nil {
             panic(err)
           }

         }

         func restModule() http.Handler {
           // Separate Mux for all REST
           restApi := http.NewServeMux()
           restApi.HandleFunc("/users", func(w http.ResponseWriter,
                              r *http.Request) {
             w.Header().Set("Content-Type", "application/json")
             fmt.Fprint(w, `[{"id":1,"name":"John"}]`)
           })
           return restApi
         }

         func uiModule() http.Handler {
           // Separate Mux for all UI
           ui := http.NewServeMux()
           ui.HandleFunc("/users", func(w http.ResponseWriter, 
                         r *http.Request) {
             w.Header().Set("Content-Type", "text/html")
             fmt.Fprint(w, `<html><body>Hello from UI!</body></html>`)
           })

           return ui
         }
```

1.  通过`go run handlegroups.go`执行代码。

1.  查看输出：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/go-stdlib-cb/img/de4c1c5b-e888-4abc-b479-00cbfe6f1e05.png)

1.  访问浏览器 URL`http://localhost:8080/api/users`，输出应该如下所示：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/go-stdlib-cb/img/9a9f2678-99d7-46e6-a522-bfd7c59a1404.png)

1.  同样，您可以测试`http://localhost:8080/ui/users`： 

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/go-stdlib-cb/img/110cb8f2-3bf7-4a57-b911-c8bfb2aa5ec9.png)

# 它是如何工作的...

为了将处理程序分离成模块，代码使用了`ServeMux`来为每个模块（`rest`和`ui`）进行处理。给定模块的 URL 处理是相对定义的。这意味着如果`Handler`的最终 URL 应该是`/api/users`，那么模块内定义的路径将是`/users`。模块本身将设置为`/api/` URL。

通过利用`StripPrefix`函数将模块插入到名为`mainMux`的主`ServeMux`指针中，模块被插入到主`ServeMux`中。例如，通过`StripPrefix("/api",restModule())`将由`restModule`函数创建的 REST 模块插入到主`ServeMux`中。然后模块内的处理 URL 将是`/users`，而不是`/api/users`。

# 利用 HTTP/2 服务器推送

HTTP/2 规范为服务器提供了在被请求之前推送资源的能力。本示例演示了如何实现服务器推送。

# 准备工作

准备私钥和自签名 X-509 证书。为此，可以使用`openssl`实用程序。通过执行命令`openssl genrsa -out server.key 2048`，使用 RSA 算法生成私钥文件`server.key`。基于此私钥，可以通过调用`openssl req -new -x509 -sha256 -key server.key -out server.crt -days 365`生成 X-509 证书。创建了`server.crt`文件。

# 操作步骤...

1.  打开控制台并创建文件夹`chapter11/recipe09`。

1.  导航到目录。

1.  创建文件`push.go`，内容如下：

```go
        package main

        import (
          "io"
          "log"
          "net/http"
        )

        func main() {

          log.Println("Staring server...")
          // Adding to mani Mux
          http.HandleFunc("/",func(w http.ResponseWriter, r *http.Request){
            if p, ok := w.(http.Pusher); ok {
              if err := p.Push("/app.css", nil); err != nil {
                log.Printf("Push err : %v", err)
              }
            }
            io.WriteString(w,
              `<html>
                 <head>
                   <link rel="stylesheet" type="text/css" href="app.css">
                 </head>
                 <body>
                   <p>Hello</p>
                 </body>
               </html>`
             )
           })
           http.HandleFunc("/app.css", func(w http.ResponseWriter,
                           r *http.Request) {
             io.WriteString(w,
               `p {
                 text-align: center;
                 color: red;
               }`)
           })

           if err := http.ListenAndServeTLS(":8080", "server.crt",
                                            "server.key", nil);
           err != nil {
             panic(err)
           }

         }
```

1.  通过`go run push.go`启动服务器。

1.  打开浏览器，在 URL `https://localhost:8080` 中打开开发者工具（查看`Push`作为`app.css`的发起者）：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/go-stdlib-cb/img/a9f38361-8c38-4b77-9ebc-26cc4e533d2e.png)

# 工作原理...

首先，注意 HTTP/2 需要安全连接。服务器推送非常简单实现。自 Go 1.8 以来，HTTP 包提供了`Pusher`接口，可以在资源被请求之前用于`Push`资产。如果客户端（通常是浏览器）支持 HTTP/2 协议并且与服务器的握手成功，`Handler`或`HandlerFunc`中的`ResponseWriter`可以转换为`Pusher`。`Pusher`只提供`Push`方法。`Push`方法消耗目标（可以是绝对路径或绝对 URL）到资源和`PushOptions`，可以提供额外选项（默认情况下可以使用 nil）。

在上面的示例中，查看浏览器中开发者工具的输出。推送的资源在 Initiator 列中具有值`Push`。
