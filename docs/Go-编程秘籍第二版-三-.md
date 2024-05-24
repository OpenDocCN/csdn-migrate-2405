# Go 编程秘籍第二版（三）

> 原文：[`zh.annas-archive.org/md5/6A3DCC49D461FA27A010AAE9FBA229E0`](https://zh.annas-archive.org/md5/6A3DCC49D461FA27A010AAE9FBA229E0)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第五章：网络编程

Go 标准库为网络操作提供了大量支持。它包括允许您使用 TCP/IP、UDP、DNS、邮件和使用 HTTP 的 RPC 的包。第三方包也可以填补标准库中包含的内容的空白，包括`gorilla/websockets` ([`github.com/gorilla/websocket/`](https://github.com/gorilla/websocket/))，用于 WebSocket 实现，可以在普通的 HTTP 处理程序中使用。本章探讨了这些库，并演示了一些简单的用法。这些用法将帮助那些无法使用更高级的抽象，如 REST 或 GRPC，但需要网络连接的开发人员。它对需要执行 DNS 查找或处理原始电子邮件的 DevOps 应用程序也很有用。阅读完本章后，您应该已经掌握了基本的网络编程，并准备深入学习。

在本章中，将涵盖以下用法：

+   编写 TCP/IP 回显服务器和客户端

+   编写 UDP 服务器和客户端

+   处理域名解析

+   使用 WebSockets

+   使用 net/rpc 调用远程方法

+   使用 net/mail 解析电子邮件

# 技术要求

为了继续本章中的所有用法，请按照以下步骤配置您的环境：

1.  从[`golang.org/doc/install`](https://golang.org/doc/install)下载并安装 Go 1.12.6 或更高版本到您的操作系统上。

1.  打开终端或控制台应用程序，然后创建并导航到一个项目目录，例如`~/projects/go-programming-cookbook`。所有代码都将从这个目录运行和修改。

1.  将最新的代码克隆到`~/projects/go-programming-cookbook-original`，您可以选择从该目录工作，而不是手动输入示例：

```go
$ git clone git@github.com:PacktPublishing/Go-Programming-Cookbook-Second-Edition.git go-programming-cookbook-original
```

# 编写 TCP/IP 回显服务器和客户端

TCP/IP 是一种常见的网络协议，HTTP 协议是在其上构建的。TCP 要求客户端连接到服务器以发送和接收数据。这个用法将使用`net`包在客户端和服务器之间建立 TCP 连接。客户端将把用户输入发送到服务器，服务器将用`strings.ToUpper()`的结果将输入的相同字符串转换为大写形式进行响应。客户端将打印从服务器接收到的任何消息，因此它应该输出我们输入的大写版本。

# 如何做...

这些步骤涵盖了编写和运行您的应用程序：

1.  从您的终端或控制台应用程序中，创建一个名为`~/projects/go-programming-cookbook/chapter5/tcp`的新目录，并导航到该目录。

1.  运行以下命令：

```go
$ go mod init github.com/PacktPublishing/Go-Programming-Cookbook-Second-Edition/chapter5/tcp 
```

您应该会看到一个名为`go.mod`的文件，其中包含以下内容：

```go
module github.com/PacktPublishing/Go-Programming-Cookbook-Second-Edition/chapter5/tcp    
```

1.  从`~/projects/go-programming-cookbook-original/chapter5/tcp`复制测试，或者使用这个作为练习编写一些您自己的代码！

1.  创建一个名为`server`的新目录，并导航到该目录。

1.  创建一个名为`main.go`的文件，内容如下：

```go
package main

import (
  "bufio"
  "fmt"
  "net"
  "strings"
)

const addr = "localhost:8888"

func echoBackCapitalized(conn net.Conn) {
  // set up a reader on conn (an io.Reader)
  reader := bufio.NewReader(conn)

  // grab the first line of data encountered
  data, err := reader.ReadString('\n')
  if err != nil {
    fmt.Printf("error reading data: %s\n", err.Error())
    return
  }
  // print then send back the data
  fmt.Printf("Received: %s", data)
  conn.Write([]byte(strings.ToUpper(data)))
  // close up the finished connection
  conn.Close()
}

func main() {
  ln, err := net.Listen("tcp", addr)
  if err != nil {
    panic(err)
  }
  defer ln.Close()
  fmt.Printf("listening on: %s\n", addr)
  for {
    conn, err := ln.Accept()
    if err != nil {
      fmt.Printf("encountered an error accepting connection: %s\n", 
                  err.Error())
      // if there's an error try again
      continue
    }
    // handle this asynchronously
    // potentially a good use-case
    // for a worker pool
    go echoBackCapitalized(conn)
  }
}
```

1.  导航到上一个目录。

1.  创建一个名为`client`的新目录，并导航到该目录。

1.  创建一个名为`main.go`的文件，内容如下：

```go
package main

import (
  "bufio"
  "fmt"
  "net"
  "os"
)

const addr = "localhost:8888"

func main() {
  reader := bufio.NewReader(os.Stdin)
  for {
    // grab a string input from the clie
    fmt.Printf("Enter some text: ")
    data, err := reader.ReadString('\n')
    if err != nil {
      fmt.Printf("encountered an error reading input: %s\n", 
                  err.Error())
      continue
    }
    // connect to the addr
    conn, err := net.Dial("tcp", addr)
    if err != nil {
      fmt.Printf("encountered an error connecting: %s\n", 
                  err.Error())
    }

    // write the data to the connection
    fmt.Fprintf(conn, data)

    // read back the response
    status, err := bufio.NewReader(conn).ReadString('\n')
    if err != nil {
      fmt.Printf("encountered an error reading response: %s\n", 
                  err.Error())
    }
    fmt.Printf("Received back: %s", status)
    // close up the finished connection
    conn.Close()
  }
}
```

1.  导航到上一个目录。

1.  运行`go run ./server`，您将看到以下输出：

```go
$ go run ./server
listening on: localhost:8888
```

1.  在另一个终端中，从`tcp`目录运行`go run ./client`，您将看到以下输出：

```go
$ go run ./client 
Enter some text:
```

1.  输入`this is a test`并按*Enter*。您将看到以下内容：

```go
$ go run ./client 
Enter some text: this is a test
Received back: THIS IS A TEST
Enter some text: 
```

1.  按下*Ctrl* + *C*退出。

1.  如果您复制或编写了自己的测试，请返回上一个目录并运行`go test`。确保所有测试都通过。

# 工作原理...

服务器正在侦听端口`8888`。每当有请求时，服务器必须接收请求并管理客户端连接。在这个程序的情况下，它会派发一个 Goroutine 来从客户端读取请求，将接收到的数据大写，发送回客户端，最后关闭连接。服务器立即再次循环，等待接收新的客户端连接，同时处理先前的连接。

客户端从`STDIN`读取输入，通过 TCP 连接到地址，写入从输入中读取的消息，然后打印服务器的响应。之后，它关闭连接并再次从`STDIN`循环读取。您也可以重新设计此示例，使客户端保持连接，直到程序退出，而不是在每个请求上。

# 编写 UDP 服务器和客户端

UDP 协议通常用于游戏和速度比可靠性更重要的地方。UDP 服务器和客户端不需要相互连接。这个示例将创建一个 UDP 服务器，它将监听来自客户端的消息，将它们的 IP 添加到其列表中，并向先前看到的每个客户端广播消息。

每当客户端连接时，服务器将向`STDOUT`写入一条消息，并将相同的消息广播给所有客户端。这条消息的文本应该是`Sent <count>`，其中`<count>`将在服务器向所有客户端广播时递增。因此，`count`的值可能会有所不同，这取决于您连接到客户端所需的时间，因为服务器将无论发送消息给多少客户端都会广播。

# 如何做...

这些步骤涵盖了编写和运行应用程序的过程：

1.  从您的终端或控制台应用程序中，创建一个名为`~/projects/go-programming-cookbook/chapter5/udp`的新目录，并导航到该目录。

1.  运行以下命令：

```go
$ go mod init github.com/PacktPublishing/Go-Programming-Cookbook-Second-Edition/chapter5/udp 
```

您应该看到一个名为`go.mod`的文件，其中包含以下内容：

```go
module github.com/PacktPublishing/Go-Programming-Cookbook-Second-Edition/chapter5/udp    
```

1.  从`~/projects/go-programming-cookbook-original/chapter5/udp`复制测试，或者将其用作编写自己代码的练习！

1.  创建一个名为`server`的新目录，并导航到该目录。

1.  创建一个名为`broadcast.go`的文件，内容如下：

```go
package main

import (
  "fmt"
  "net"
  "sync"
  "time"
)

type connections struct {
  addrs map[string]*net.UDPAddr
  // lock for modifying the map
  mu sync.Mutex
}

func broadcast(conn *net.UDPConn, conns *connections) {
  count := 0
  for {
    count++
    conns.mu.Lock()
    // loop over known addresses
    for _, retAddr := range conns.addrs {

      // send a message to them all
      msg := fmt.Sprintf("Sent %d", count)
      if _, err := conn.WriteToUDP([]byte(msg), retAddr); err != nil {
        fmt.Printf("error encountered: %s", err.Error())
        continue
      }

    }
    conns.mu.Unlock()
    time.Sleep(1 * time.Second)
  }
}
```

1.  创建一个名为`main.go`的文件，内容如下：

```go
package main

import (
  "fmt"
  "net"
)

const addr = "localhost:8888"

func main() {
  conns := &connections{
    addrs: make(map[string]*net.UDPAddr),
  }

  fmt.Printf("serving on %s\n", addr)

  // construct a udp addr
  addr, err := net.ResolveUDPAddr("udp", addr)
  if err != nil {
    panic(err)
  }

  // listen on our specified addr
  conn, err := net.ListenUDP("udp", addr)
  if err != nil {
    panic(err)
  }
  // cleanup
  defer conn.Close()

  // async send messages to all known clients
  go broadcast(conn, conns)

  msg := make([]byte, 1024)
  for {
    // receive a message to gather the ip address
    // and port to send back to
    _, retAddr, err := conn.ReadFromUDP(msg)
    if err != nil {
      continue
    }

    //store it in a map
    conns.mu.Lock()
    conns.addrs[retAddr.String()] = retAddr
    conns.mu.Unlock()
    fmt.Printf("%s connected\n", retAddr)
  }
}
```

1.  导航到上一个目录。

1.  创建一个名为`client`的新目录，并导航到该目录。

1.  创建一个名为`main.go`的文件，内容如下：

```go
package main

import (
  "fmt"
  "net"
)

const addr = "localhost:8888"

func main() {
  fmt.Printf("client for server url: %s\n", addr)

  addr, err := net.ResolveUDPAddr("udp", addr)
  if err != nil {
    panic(err)
  }

  conn, err := net.DialUDP("udp", nil, addr)
  if err != nil {
    panic(err)
  }
  defer conn.Close()

  msg := make([]byte, 512)
  n, err := conn.Write([]byte("connected"))
  if err != nil {
    panic(err)
  }
  for {
    n, err = conn.Read(msg)
    if err != nil {
      continue
    }
    fmt.Printf("%s\n", string(msg[:n]))
  }
}
```

1.  导航到上一个目录。

1.  运行`go run ./server`，您将看到以下输出：

```go
$ go run ./server
serving on localhost:8888
```

1.  在另一个终端中，从`udp`目录运行`go run ./client`，您将看到以下输出，尽管计数可能有所不同：

```go
$ go run ./client 
client for server url: localhost:8888
Sent 3
Sent 4
Sent 5
```

1.  导航到运行服务器的终端，您应该看到类似以下的内容：

```go
$ go run ./server 
serving on localhost:8888
127.0.0.1:64242 connected
```

1.  按下*Ctrl* + *C*退出服务器和客户端。

1.  如果您复制或编写了自己的测试，请返回上一级目录并运行`go test`。确保所有测试都通过。

# 它是如何工作的...

服务器正在监听端口`8888`，就像在上一个示例中一样。如果客户端启动，它会向服务器发送一条消息，服务器会将其地址添加到地址列表中。因为客户端可以异步连接，所以服务器在修改或读取列表之前必须使用互斥锁。

一个单独的广播 Goroutine 独立运行，并将相同的消息发送到以前发送消息的所有客户端地址。假设它们仍在监听，它们将在大致相同的时间从服务器接收相同的消息。您还可以连接更多的客户端来查看这种效果。

# 使用域名解析

`net`包提供了许多有用的 DNS 查找功能。这些信息与使用 Unix 的`dig`命令获得的信息相似。这些信息对于您实现任何需要动态确定 IP 地址的网络编程非常有用。

本教程将探讨如何收集这些数据。为了演示这一点，我们将实现一个简化的`dig`命令。我们将寻求将 URL 映射到其所有 IPv4 和 IPv6 地址。通过修改`GODEBUG=netdns=`为`go`或`cgo`，它将使用纯 Go DNS 解析器或`cgo`解析器。默认情况下，使用纯 Go DNS 解析器。

# 如何做...

以下步骤涵盖了编写和运行应用程序：

1.  从您的终端或控制台应用程序中，创建一个名为`~/projects/go-programming-cookbook/chapter5/dns`的新目录，并导航到该目录。

1.  运行以下命令：

```go
$ go mod init github.com/PacktPublishing/Go-Programming-Cookbook-Second-Edition/chapter5/dns 
```

您应该看到一个名为`go.mod`的文件，其中包含以下内容：

```go
module github.com/PacktPublishing/Go-Programming-Cookbook-Second-Edition/chapter5/dns
```

1.  从`~/projects/go-programming-cookbook-original/chapter5/dns`复制测试，或者使用此作为练习来编写一些您自己的代码！

1.  创建一个名为`dns.go`的文件，内容如下：

```go
package dns

import (
  "fmt"
  "net"

  "github.com/pkg/errors"
)

// Lookup holds the DNS information we care about
type Lookup struct {
  cname string
  hosts []string
}

// We can use this to print the lookup object
func (d *Lookup) String() string {
  result := ""
  for _, host := range d.hosts {
    result += fmt.Sprintf("%s IN A %s\n", d.cname, host)
  }
  return result
}

// LookupAddress returns a DNSLookup consisting of a cname and host
// for a given address
func LookupAddress(address string) (*Lookup, error) {
  cname, err := net.LookupCNAME(address)
  if err != nil {
    return nil, errors.Wrap(err, "error looking up CNAME")
  }
  hosts, err := net.LookupHost(address)
  if err != nil {
    return nil, errors.Wrap(err, "error looking up HOST")
  }

  return &Lookup{cname: cname, hosts: hosts}, nil
}
```

1.  创建一个名为`example`的新目录，并导航到该目录。

1.  创建一个名为`main.go`的文件，内容如下：

```go
package main

import (
  "fmt"
  "log"
  "os"

  "github.com/PacktPublishing/Go-Programming-Cookbook-Second-Edition/chapter5/dns"
)

func main() {
  if len(os.Args) < 2 {
    fmt.Printf("Usage: %s <address>\n", os.Args[0])
    os.Exit(1)
  }
  address := os.Args[1]
  lookup, err := dns.LookupAddress(address)
  if err != nil {
    log.Panicf("failed to lookup: %s", err.Error())
  }
  fmt.Println(lookup)
}
```

1.  运行`go run main.go golang.org`命令。

1.  您还可以运行以下命令：

```go
$ go build $ ./example golang.org
```

您应该看到以下输出：

```go
$ go run main.go golang.org
golang.org. IN A 172.217.5.17
golang.org. IN A 2607:f8b0:4009:809::2011
```

1.  `go.mod`文件可能已更新，`go.sum`文件现在应该存在于顶级配方目录中。

1.  如果您复制或编写了自己的测试，请返回上一级目录并运行`go test`。确保所有测试都通过。

# 工作原理...

本教程执行了提供的地址的`CNAME`和主机查找。在我们的案例中，我们使用了`golang.org`。我们将结果存储在一个查找结构中，该结构使用`String()`方法打印输出结果。当我们将对象打印为字符串时，将自动调用此方法，或者我们可以直接调用该方法。我们在`main.go`中实现了一些基本的参数检查，以确保在运行程序时提供了地址。

# 使用 WebSockets

WebSockets 允许服务器应用程序连接到用 JavaScript 编写的基于 Web 的客户端。这使您可以创建具有双向通信的 Web 应用程序，并创建更新，例如聊天室等。

本教程将探讨如何在 Go 中编写 WebSocket 服务器，并演示客户端使用 WebSocket 服务器的过程。它使用`github.com/gorilla/websocket`将标准处理程序升级为 WebSocket 处理程序，并创建客户端应用程序。

# 如何做...

这些步骤涵盖了编写和运行应用程序：

1.  从您的终端或控制台应用程序中，创建一个名为`~/projects/go-programming-cookbook/chapter5/websocket`的新目录，并导航到该目录。

1.  运行以下命令：

```go
$ go mod init github.com/PacktPublishing/Go-Programming-Cookbook-Second-Edition/chapter5/websocket 
```

您应该看到一个名为`go.mod`的文件，其中包含以下内容：

```go
module github.com/PacktPublishing/Go-Programming-Cookbook-Second-Edition/chapter5/websocket    
```

1.  从`~/projects/go-programming-cookbook-original/chapter5/websocket`复制测试，或者使用此作为练习来编写一些您自己的代码！

1.  创建一个名为`server`的新目录，并导航到该目录。

1.  创建一个名为`handler.go`的文件，内容如下：

```go
package main

import (
  "log"
  "net/http"

  "github.com/gorilla/websocket"
)

// upgrader takes an http connection and converts it
// to a websocket one, we're using some recommended
// basic buffer sizes
var upgrader = websocket.Upgrader{
  ReadBufferSize: 1024,
  WriteBufferSize: 1024,
}

func wsHandler(w http.ResponseWriter, r *http.Request) {
  // upgrade the connection
  conn, err := upgrader.Upgrade(w, r, nil)
  if err != nil {
    log.Println("failed to upgrade connection: ", err)
    return
  }
  for {
    // read and echo back messages in a loop
    messageType, p, err := conn.ReadMessage()
    if err != nil {
      log.Println("failed to read message: ", err)
      return
    }
    log.Printf("received from client: %#v", string(p))
    if err := conn.WriteMessage(messageType, p); err != nil {
      log.Println("failed to write message: ", err)
      return
    }
  }
}
```

1.  创建一个名为`main.go`的文件，内容如下：

```go
package main

import (
  "fmt"
  "log"
  "net/http"
)

func main() {
  fmt.Println("Listening on port :8000")
 // we mount our single handler on port localhost:8000 to handle all
  // requests
  log.Panic(http.ListenAndServe("localhost:8000", http.HandlerFunc(wsHandler)))
}
```

1.  导航到上一个目录。

1.  创建一个名为`client`的新目录，并导航到该目录。

1.  创建一个名为`process.go`的文件，内容如下：

```go
package main

import (
  "bufio"
  "fmt"
  "log"
  "os"
  "strings"

  "github.com/gorilla/websocket"
)

func process(c *websocket.Conn) {
  reader := bufio.NewReader(os.Stdin)
  for {
    fmt.Printf("Enter some text: ")
    // this will block ctrl-c, to exit press it then hit enter
    // or kill from another location
    data, err := reader.ReadString('\n')
    if err != nil {
      log.Println("failed to read stdin", err)
    }

    // trim off the space from reading the string
    data = strings.TrimSpace(data)

    // write the message as a byte across the websocket
    err = c.WriteMessage(websocket.TextMessage, []byte(data))
    if err != nil {
      log.Println("failed to write message:", err)
      return
    }

    // this is an echo server, so we can always read after the write
    _, message, err := c.ReadMessage()
    if err != nil {
      log.Println("failed to read:", err)
      return
    }
    log.Printf("received back from server: %#v\n", string(message))
  }
}
```

1.  创建一个名为`main.go`的文件，内容如下：

```go
package main

import (
  "log"
  "os"
  "os/signal"

  "github.com/gorilla/websocket"
)

// catchSig cleans up our websocket conenction if we kill the program
// with a ctrl-c
func catchSig(ch chan os.Signal, c *websocket.Conn) {
  // block on waiting for a signal
  <-ch
  err := c.WriteMessage(websocket.CloseMessage, websocket.FormatCloseMessage(websocket.CloseNormalClosure, ""))
  if err != nil {
    log.Println("write close:", err)
  }
  return
}

func main() {
  // connect the os signal to our channel
  interrupt := make(chan os.Signal, 1)
  signal.Notify(interrupt, os.Interrupt)

  // use the ws:// Scheme to connect to the websocket
  u := "ws://localhost:8000/"
  log.Printf("connecting to %s", u)

  c, _, err := websocket.DefaultDialer.Dial(u, nil)
  if err != nil {
    log.Fatal("dial:", err)
  }
  defer c.Close()

  // dispatch our signal catcher
  go catchSig(interrupt, c)

  process(c)
}
```

1.  导航到上一个目录。

1.  运行`go run ./server`，您将看到以下输出：

```go
$ go run ./server
Listening on port :8000
```

1.  在另一个终端中，从`websocket`目录运行`go run ./client`，您将看到以下输出：

```go
$ go run ./client
2019/05/26 11:53:20 connecting to ws://localhost:8000/
Enter some text: 
```

1.  输入`test`字符串，您应该看到以下内容：

```go
$ go run ./client
2019/05/26 11:53:20 connecting to ws://localhost:8000/
Enter some text: test
2019/05/26 11:53:22 received back from server: "test"
Enter some text: 
```

1.  导航到运行服务器的终端，您应该看到类似以下内容的内容：

```go
$ go run ./server
Listening on port :8000
2019/05/26 11:53:22 received from client: "test"
```

1.  按下*Ctrl* + *C*退出服务器和客户端。在按下*Ctrl* + *C*后，您可能还需要按*Enter*。

1.  `go.mod`文件可能已更新，`go.sum`文件现在应该存在于顶级配方目录中。

1.  如果您复制或编写了自己的测试，请返回上一级目录并运行`go test`。确保所有测试都通过。

# 工作原理...

服务器正在端口`8000`上监听 WebSocket 连接。当请求到来时，`github.com/gorilla/websocket`包用于将请求升级为 WebSocket 连接。与先前的回声服务器示例类似，服务器等待在 WebSocket 连接上接收消息，并将相同的消息作为响应发送回客户端。因为它是一个处理程序，所以它可以异步处理许多 WebSocket 连接，并且它们将保持连接，直到客户端终止。

在客户端中，我们添加了一个`catchsig`函数来处理*Ctrl* + *C*事件。这使我们能够在客户端退出时清楚地终止与服务器的连接。否则，客户端只是在`STDIN`上接受用户输入并将其发送到服务器，记录响应，然后重复。

# 使用 net/rpc 调用远程方法

Go 通过`net/rpc`包为您的系统提供基本的 RPC 功能。这是在不依赖于 GRPC 或其他更复杂的 RPC 包的情况下进行 RPC 调用的潜在替代方案。但是，它的功能相当有限，您可能希望导出的任何函数都必须符合非常特定的函数签名。

代码中的注释指出了一些可以远程调用的方法的限制。本配方演示了如何创建一个共享函数，该函数通过结构传递了许多参数，并且可以远程调用。

# 如何做...

这些步骤涵盖了编写和运行应用程序的过程：

1.  从您的终端或控制台应用程序中，创建一个名为`~/projects/go-programming-cookbook/chapter5/rpc`的新目录，并导航到该目录。

1.  运行以下命令：

```go
$ go mod init github.com/PacktPublishing/Go-Programming-Cookbook-Second-Edition/chapter5/rpc 
```

您应该看到一个名为`go.mod`的文件，其中包含以下内容：

```go
module github.com/PacktPublishing/Go-Programming-Cookbook-Second-Edition/chapter5/rpc    
```

1.  从`~/projects/go-programming-cookbook-original/chapter5/rpc`复制测试，或者利用这个机会编写一些您自己的代码！

1.  创建一个名为`tweak`的新目录，并导航到该目录。

1.  创建一个名为`tweak.go`的文件，内容如下：

```go
package tweak

import (
  "strings"
)

// StringTweaker is a type of string
// that can reverse itself
type StringTweaker struct{}

// Args are a list of options for how to tweak
// the string
type Args struct {
  String string
  ToUpper bool
  Reverse bool
}

// Tweak conforms to the RPC library which require:
// - the method's type is exported.
// - the method is exported.
// - the method has two arguments, both exported (or builtin) types.
// - the method's second argument is a pointer.
// - the method has return type error.
func (s StringTweaker) Tweak(args *Args, resp *string) error {

  result := string(args.String)
  if args.ToUpper {
    result = strings.ToUpper(result)
  }
  if args.Reverse {
    runes := []rune(result)
    for i, j := 0, len(runes)-1; i < j; i, j = i+1, j-1 {
      runes[i], runes[j] = runes[j], runes[i]
    }
    result = string(runes)

  }
  *resp = result
  return nil
}
```

1.  导航到上一个目录。

1.  创建一个名为`server`的新目录，并导航到该目录。

1.  创建一个名为`main.go`的文件，内容如下：

```go
package main

import (
  "fmt"
  "log"
  "net"
  "net/http"
  "net/rpc"

  "github.com/PacktPublishing/Go-Programming-Cookbook-Second-Edition/chapter5/rpc/tweak"
)

func main() {
  s := new(tweak.StringTweaker)
  if err := rpc.Register(s); err != nil {
    log.Fatal("failed to register:", err)
  }

  rpc.HandleHTTP()

  l, err := net.Listen("tcp", ":1234")
  if err != nil {
    log.Fatal("listen error:", err)
  }

  fmt.Println("listening on :1234")
  log.Panic(http.Serve(l, nil))
}
```

1.  导航到上一个目录。

1.  创建一个名为`client`的新目录，并导航到该目录。

1.  创建一个名为`main.go`的文件，内容如下：

```go
package main

import (
  "fmt"
  "log"
  "net/rpc"

  "github.com/PacktPublishing/Go-Programming-Cookbook-Second-Edition/chapter5/rpc/tweak"
)

func main() {
  client, err := rpc.DialHTTP("tcp", "localhost:1234")
  if err != nil {
    log.Fatal("error dialing:", err)
  }

  args := tweak.Args{
    String: "this string should be uppercase and reversed",
    ToUpper: true,
    Reverse: true,
  }
  var result string
  err = client.Call("StringTweaker.Tweak", args, &result)
  if err != nil {
    log.Fatal("client call with error:", err)
  }
  fmt.Printf("the result is: %s", result)
}
```

1.  导航到上一个目录。

1.  运行`go run ./server`，您将看到以下输出：

```go
$ go run ./server
Listening on :1234
```

1.  在单独的终端中，从`rpc`目录运行`go run ./client`，您将看到以下输出：

```go
$ go run ./client
the result is: DESREVER DNA ESACREPPU EB DLUOHS GNIRTS SIHT
```

1.  按*Ctrl* + *C*退出服务器。

1.  如果您复制或编写了自己的测试，请返回上一个目录并运行`go test`。确保所有测试都通过。

# 它是如何工作的...

`StringTweaker`结构被放入一个单独的库中，以便客户端（用于设置参数）和服务器（用于注册 RPC 和启动服务器）可以访问其导出类型。它还符合本配方开头提到的规则，以便与`net/rpc`一起使用。

`StringTweaker`可用于接受输入字符串，并根据传递的选项，可选地反转和大写其中包含的所有字符。这种模式可以扩展为创建更复杂的函数，并且您还可以使用额外的函数使代码在增长时更易读。

# 使用 net/mail 解析电子邮件

`net/mail`包提供了许多有用的函数，可在处理电子邮件时帮助您。如果您有电子邮件的原始文本，可以将其解析为提取标题、发送日期信息等。本配方将通过解析硬编码为字符串的原始电子邮件来演示其中的一些功能。

# 如何做...

这些步骤涵盖了编写和运行应用程序的过程：

1.  从您的终端或控制台应用程序中，创建一个名为`~/projects/go-programming-cookbook/chapter5/mail`的新目录，并导航到该目录。

1.  运行以下命令：

```go
$ go mod init github.com/PacktPublishing/Go-Programming-Cookbook-Second-Edition/chapter5/mail 
```

您应该看到一个名为`go.mod`的文件，其中包含以下内容：

```go
module github.com/PacktPublishing/Go-Programming-Cookbook-Second-Edition/chapter5/mail
```

1.  从 `~/projects/go-programming-cookbook-original/chapter5/mail` 复制测试，或者利用这个机会编写一些自己的代码！

1.  创建一个名为 `header.go` 的文件，内容如下：

```go
package main

import (
  "fmt"
  "net/mail"
  "strings"
)

// extract header info and print it nicely
func printHeaderInfo(header mail.Header) {

  // this works because we know it's a single address
  // otherwise use ParseAddressList
  toAddress, err := mail.ParseAddress(header.Get("To"))
  if err == nil {
    fmt.Printf("To: %s <%s>\n", toAddress.Name, toAddress.Address)
  }
  fromAddress, err := mail.ParseAddress(header.Get("From"))
  if err == nil {
    fmt.Printf("From: %s <%s>\n", fromAddress.Name, 
                fromAddress.Address)
  }

  fmt.Println("Subject:", header.Get("Subject"))

  // this works for a valid RFC5322 date
  // it does a header.Get("Date"), then a
  // mail.ParseDate(that_result)
  if date, err := header.Date(); err == nil {
    fmt.Println("Date:", date)
  }

  fmt.Println(strings.Repeat("=", 40))
  fmt.Println()
}
```

1.  创建一个名为 `main.go` 的文件，内容如下：

```go
package main

import (
  "io"
  "log"
  "net/mail"
  "os"
  "strings"
)

// an example email message
const msg string = `Date: Thu, 24 Jul 2019 08:00:00 -0700
From: Aaron <fake_sender@example.com>
To: Reader <fake_receiver@example.com>
Subject: Gophercon 2019 is going to be awesome!

Feel free to share my book with others if you're attending.
This recipe can be used to process and parse email information.
`

func main() {
  r := strings.NewReader(msg)
  m, err := mail.ReadMessage(r)
  if err != nil {
    log.Fatal(err)
  }

  printHeaderInfo(m.Header)

  // after printing the header, dump the body to stdout
  if _, err := io.Copy(os.Stdout, m.Body); err != nil {
    log.Fatal(err)
  }
}
```

1.  运行 `go run .` 命令。

1.  您也可以运行以下内容：

```go
$ go build $ ./mail 
```

您应该看到以下输出：

```go
$ go run .
To: Reader <fake_receiver@example.com>
From: Aaron <fake_sender@example.com>
Subject: Gophercon 2019 is going to be awesome!
Date: 2019-07-24 08:00:00 -0700 -0700
========================================

Feel free to share my book with others if you're attending.
This recipe can be used to process and parse email information. 
```

1.  如果您复制或编写了自己的测试，请返回上一级目录并运行 `go test`。确保所有测试都通过。

# 它是如何工作的...

`printHeaderInfo` 函数为此示例大部分工作。它将地址从标题中解析为 `*mail.Address` 结构，并将日期标题解析为日期对象。然后，它将消息中的所有信息格式化为可读格式。主函数解析初始电子邮件并传递此标题。


# 第六章：关于数据库和存储的一切

Go 应用程序经常需要使用长期存储。这通常以关系和非关系数据库的形式存在，以及键值存储等。在处理这些存储应用程序时，将操作封装在接口中是有帮助的。本章的配方将检查各种存储接口，考虑诸如连接池等并行访问的问题，并查看集成新库的一般提示，这在使用新的存储技术时经常发生。

在本章中，将涵盖以下配方：

+   使用 database/sql 包与 MySQL

+   执行数据库事务接口

+   连接池、速率限制和 SQL 的超时

+   使用 Redis

+   使用 MongoDB 的 NoSQL

+   创建数据可移植性的存储接口

# 使用 database/sql 包与 MySQL

关系数据库是一些最为人熟知和常见的数据库选项。MySQL 和 PostgreSQL 是两种最流行的开源关系数据库。这个配方将演示`database/sql`包，它提供了一些关系数据库的钩子，并自动处理连接池和连接持续时间，并提供了一些基本的数据库操作。

这个配方将使用 MySQL 数据库建立连接，插入一些简单的数据并查询它。它将在使用后通过删除表来清理数据库。

# 准备工作

根据以下步骤配置你的环境：

1.  在你的操作系统上下载并安装 Go 1.12.6 或更高版本，网址为[`golang.org/doc/install`](https://golang.org/doc/install)。

1.  打开一个终端或控制台应用程序，创建一个项目目录，比如`~/projects/go-programming-cookbook`，并导航到该目录。所有的代码都将在这个目录中运行和修改。

1.  将最新的代码克隆到`~/projects/go-programming-cookbook-original`，并选择从该目录工作，而不是手动输入示例。

```go
$ git clone git@github.com:PacktPublishing/Go-Programming-Cookbook-Second-Edition.git go-programming-cookbook-original
```

1.  使用[`dev.mysql.com/doc/mysql-getting-started/en/`](https://dev.mysql.com/doc/mysql-getting-started/en/)安装和配置 MySQL。

1.  运行`export MYSQLUSERNAME=<your mysql username>`命令。

1.  运行`export MYSQLPASSWORD=<your mysql password>`命令。

# 如何做...

这些步骤涵盖了编写和运行应用程序的过程：

1.  从你的终端或控制台应用程序中，创建一个名为`~/projects/go-programming-cookbook/chapter6/database`的新目录，并导航到该目录。

1.  运行以下命令：

```go
$ go mod init github.com/PacktPublishing/Go-Programming-Cookbook-Second-Edition/chapter6/database 
```

你应该看到一个名为`go.mod`的文件，其中包含以下内容：

```go
module github.com/PacktPublishing/Go-Programming-Cookbook-Second-Edition/chapter6/database    
```

1.  从`~/projects/go-programming-cookbook-original/chapter6/database`复制测试，或者利用这个练习编写一些自己的代码！

1.  创建一个名为`config.go`的文件，内容如下：

```go
        package database

        import (
            "database/sql"
            "fmt"
            "os"
            "time"

            _ "github.com/go-sql-driver/mysql" //we import supported 
            libraries for database/sql
        )

        // Example hold the results of our queries
        type Example struct {
            Name string
            Created *time.Time
        }

        // Setup configures and returns our database
        // connection poold
        func Setup() (*sql.DB, error) {
            db, err := sql.Open("mysql", 
            fmt.Sprintf("%s:%s@/gocookbook? 
            parseTime=true", os.Getenv("MYSQLUSERNAME"), 
            os.Getenv("MYSQLPASSWORD")))
            if err != nil {
                return nil, err
            }
            return db, nil
        }
```

1.  创建一个名为`create.go`的文件，内容如下：

```go
        package database

        import (
            "database/sql"

            _ "github.com/go-sql-driver/mysql" //we import supported 
            libraries for database/sql
        )

        // Create makes a table called example
        // and populates it
        func Create(db *sql.DB) error {
            // create the database
            if _, err := db.Exec("CREATE TABLE example (name 
            VARCHAR(20), created DATETIME)"); err != nil {
                return err
            }

            if _, err := db.Exec(`INSERT INTO example (name, created) 
            values ("Aaron", NOW())`); err != nil {
                return err
            }

            return nil
        }
```

1.  创建一个名为`query.go`的文件，内容如下：

```go
        package database

        import (
            "database/sql"
            "fmt"

            _ "github.com/go-sql-driver/mysql" //we import supported 
            libraries for database/sql
        )

        // Query grabs a new connection
        // creates tables, and later drops them
        // and issues some queries
        func Query(db *sql.DB, name string) error {
            name := "Aaron"
            rows, err := db.Query("SELECT name, created FROM example 
            where name=?", name)
            if err != nil {
                return err
            }
            defer rows.Close()
            for rows.Next() {
                var e Example
                if err := rows.Scan(&e.Name, &e.Created); err != nil {
                    return err
                }
                fmt.Printf("Results:\n\tName: %s\n\tCreated: %v\n", 
                e.Name, e.Created)
            }
            return rows.Err()
        }
```

1.  创建一个名为`exec.go`的文件，内容如下：

```go
        package database

        // Exec replaces the Exec from the previous
        // recipe
        func Exec(db DB) error {

            // uncaught error on cleanup, but we always
            // want to cleanup
            defer db.Exec("DROP TABLE example")

            if err := Create(db); err != nil {
                return err
            }

            if err := Query(db, "Aaron"); err != nil {
                return err
            }
            return nil
        }
```

1.  创建并导航到`example`目录。

1.  创建一个名为`main.go`的文件，内容如下：

```go
        package main

        import (
            "PacktPublishing/Go-Programming-Cookbook-Second-Edition/
             go-cookbook/chapter6/database"
            _ "github.com/go-sql-driver/mysql" //we import supported 
            libraries for database/sql
        )

        func main() {
            db, err := database.Setup()
            if err != nil {
                panic(err)
            }

            if err := database.Exec(db); err != nil {
                panic(err)
            }
        }
```

1.  运行`go run main.go`。

1.  你也可以运行以下命令：

```go
$ go build $ ./example
```

你应该看到以下输出：

```go
$ go run main.go
Results:
 Name: Aaron
 Created: 2017-02-16 19:02:36 +0000 UTC
```

1.  `go.mod`文件可能会被更新，顶层配方目录中现在应该存在`go.sum`文件。

1.  如果你复制或编写了自己的测试，返回上一级目录并运行`go test`。确保所有测试都通过。

# 它是如何工作的...

代码中的`_ "github.com/go-sql-driver/mysql"`行是将各种数据库连接器连接到`database/sql`包的方法。还有其他可以以类似方式导入的 MySQL 包，以获得类似的结果。如果你要连接到 PostgreSQL、SQLite 或其他实现了`database/sql`接口的数据库，命令也会类似。

一旦连接，该包将设置一个连接池，该连接池在*SQL 的连接池、速率限制和超时*配方中有所涵盖，您可以直接在连接上执行 SQL，也可以创建可以使用`commit`和`rollback`命令执行所有连接操作的事务对象。

当与数据库通信时，`mysql`包为 Go 时间对象提供了一些便利支持。这个配方还从`MYSQLUSERNAME`和`MYSQLPASSWORD`环境变量中检索用户名和密码。

# 执行数据库事务接口

在与数据库等服务的连接工作时，编写测试可能会很困难。这是因为在 Go 中很难在运行时模拟或鸭子类型化。虽然我建议在处理数据库时使用存储接口，但在这个接口内部模拟数据库事务接口仍然很有用。*为数据可移植性创建存储接口*配方将涵盖存储接口；这个配方将专注于包装数据库连接和事务对象的接口。

为了展示这样一个接口的使用，我们将重写前一个配方中的创建和查询文件以使用我们的接口。最终输出将是相同的，但创建和查询操作将都在一个事务中执行。

# 准备工作

参考*使用 database/sql 包与 MySQL*配方中的*准备工作*部分。

# 如何做...

这些步骤涵盖了编写和运行应用程序：

1.  从您的终端或控制台应用程序中，创建一个名为`~/projects/go-programming-cookbook/chapter6/dbinterface`的新目录，并导航到该目录。

1.  运行以下命令：

```go
$ go mod init github.com/PacktPublishing/Go-Programming-Cookbook-Second-Edition/chapter6/dbinterface 
```

您应该看到一个名为`go.mod`的文件，其中包含以下内容：

```go
module github.com/PacktPublishing/Go-Programming-Cookbook-Second-Edition/chapter6/dbinterface    
```

1.  从`~/projects/go-programming-cookbook-original/chapter6/dbinterface`复制测试，或者利用这个机会编写一些自己的代码！

1.  创建一个名为`transaction.go`的文件，内容如下：

```go
package dbinterface

import "database/sql"

// DB is an interface that is satisfied
// by an sql.DB or an sql.Transaction
type DB interface {
  Exec(query string, args ...interface{}) (sql.Result, error)
  Prepare(query string) (*sql.Stmt, error)
  Query(query string, args ...interface{}) (*sql.Rows, error)
  QueryRow(query string, args ...interface{}) *sql.Row
}

// Transaction can do anything a Query can do
// plus Commit, Rollback, or Stmt
type Transaction interface {
  DB
  Commit() error
  Rollback() error
}
```

1.  创建一个名为`create.go`的文件，内容如下：

```go
package dbinterface

import _ "github.com/go-sql-driver/mysql" //we import supported libraries for database/sql

// Create makes a table called example
// and populates it
func Create(db DB) error {
  // create the database
  if _, err := db.Exec("CREATE TABLE example (name VARCHAR(20), created DATETIME)"); err != nil {
    return err
  }

  if _, err := db.Exec(`INSERT INTO example (name, created) values ("Aaron", NOW())`); err != nil {
    return err
  }

  return nil
}
```

1.  创建一个名为`query.go`的文件，内容如下：

```go
package dbinterface

import (
  "fmt"

  "github.com/PacktPublishing/Go-Programming-Cookbook-Second-Edition/chapter6/database"
)

// Query grabs a new connection
// creates tables, and later drops them
// and issues some queries
func Query(db DB) error {
  name := "Aaron"
  rows, err := db.Query("SELECT name, created FROM example where name=?", name)
  if err != nil {
    return err
  }
  defer rows.Close()
  for rows.Next() {
    var e database.Example
    if err := rows.Scan(&e.Name, &e.Created); err != nil {
      return err
    }
    fmt.Printf("Results:\n\tName: %s\n\tCreated: %v\n", e.Name, 
                e.Created)
  }
  return rows.Err()
}
```

1.  创建一个名为`exec.go`的文件，内容如下：

```go
package dbinterface

// Exec replaces the Exec from the previous
// recipe
func Exec(db DB) error {

  // uncaught error on cleanup, but we always
  // want to cleanup
  defer db.Exec("DROP TABLE example")

  if err := Create(db); err != nil {
    return err
  }

  if err := Query(db); err != nil {
    return err
  }
  return nil
}
```

1.  导航到`example`。

1.  创建一个名为`main.go`的文件，内容如下：

```go
package main

import (
  "github.com/PacktPublishing/Go-Programming-Cookbook-Second-Edition/chapter6/database"
  "github.com/PacktPublishing/Go-Programming-Cookbook-Second-Edition/chapter6/dbinterface"
  _ "github.com/go-sql-driver/mysql" //we import supported libraries for database/sql
)

func main() {
  db, err := database.Setup()
  if err != nil {
    panic(err)
  }

  tx, err := db.Begin()
  if err != nil {
    panic(err)
  }
  // this wont do anything if commit is successful
  defer tx.Rollback()

  if err := dbinterface.Exec(tx); err != nil {
    panic(err)
  }
  if err := tx.Commit(); err != nil {
    panic(err)
```

1.  运行`go run main.go`。

1.  您也可以运行以下命令：

```go
$ go build $ ./example
```

您应该看到以下输出：

```go
$ go run main.go
Results:
 Name: Aaron
 Created: 2017-02-16 20:00:00 +0000 UTC
```

1.  `go.mod`文件可能会被更新，顶级配方目录中现在应该存在`go.sum`文件。

1.  如果您复制或编写了自己的测试，请返回上一级目录并运行`go test`。确保所有测试都通过。

# 它是如何工作的...

这个配方的工作方式与前一个数据库配方*使用 database/sql 包与 MySQL*非常相似。这个配方执行了创建数据和查询数据的相同操作，但也演示了使用事务和创建通用数据库函数，这些函数可以与`sql.DB`连接和`sql.Transaction`对象一起使用。

以这种方式编写的代码允许我们重用执行数据库操作的函数，这些函数可以单独运行或在事务中运行。这样可以实现更多的代码重用，同时仍然将功能隔离到在数据库上操作的函数或方法中。例如，您可以为多个表格编写`Update(db DB)`函数，并将它们全部传递给一个共享的事务，以原子方式执行多个更新。这样也更容易模拟这些接口，正如您将在第九章中看到的，*测试 Go 代码*。

# SQL 的连接池、速率限制和超时

虽然`database/sql`包提供了连接池、速率限制和超时的支持，但通常需要调整默认值以更好地适应数据库配置。当您在微服务上进行水平扩展并且不希望保持太多活动连接到数据库时，这一点就变得很重要。

# 准备工作

参考*使用 database/sql 包与 MySQL*配方中的*准备工作*部分。

# 如何做...

这些步骤涵盖了编写和运行应用程序：

1.  从您的终端或控制台应用程序中，创建一个名为`~/projects/go-programming-cookbook/chapter6/pools`的新目录，并导航到该目录。

1.  运行以下命令：

```go
$ go mod init github.com/PacktPublishing/Go-Programming-Cookbook-Second-Edition/chapter6/pools 
```

您应该看到一个名为`go.mod`的文件，其中包含以下内容：

```go
module github.com/PacktPublishing/Go-Programming-Cookbook-Second-Edition/chapter6/pools    
```

1.  从`~/projects/go-programming-cookbook-original/chapter6/pools`复制测试，或者利用这个练习编写一些自己的代码！

1.  创建一个名为`pools.go`的文件，并包含以下内容：

```go
        package pools

        import (
            "database/sql"
            "fmt"
            "os"

            _ "github.com/go-sql-driver/mysql" //we import supported 
            libraries for database/sql
        )

        // Setup configures the db along with pools
        // number of connections and more
        func Setup() (*sql.DB, error) {
            db, err := sql.Open("mysql", 
            fmt.Sprintf("%s:%s@/gocookbook? 
            parseTime=true", os.Getenv("MYSQLUSERNAME"),         
            os.Getenv("MYSQLPASSWORD")))
            if err != nil {
                return nil, err
            }

            // there will only ever be 24 open connections
            db.SetMaxOpenConns(24)

            // MaxIdleConns can never be less than max open 
            // SetMaxOpenConns otherwise it'll default to that value
            db.SetMaxIdleConns(24)

            return db, nil
        }
```

1.  创建一个名为`timeout.go`的文件，并包含以下内容：

```go
package pools

import (
  "context"
  "time"
)

// ExecWithTimeout will timeout trying
// to get the current time
func ExecWithTimeout() error {
  db, err := Setup()
  if err != nil {
    return err
  }

  ctx := context.Background()

  // we want to timeout immediately
  ctx, cancel := context.WithDeadline(ctx, time.Now())

  // call cancel after we complete
  defer cancel()

  // our transaction is context aware
  _, err = db.BeginTx(ctx, nil)
  return err
}
```

1.  导航到`example`。

1.  创建一个名为`main.go`的文件，并包含以下内容：

```go
        package main

        import "PacktPublishing/
                Go-Programming-Cookbook-Second-Edition/
                go-cookbook/chapter6/pools"

        func main() {
            if err := pools.ExecWithTimeout(); err != nil {
                panic(err)
            }
        }
```

1.  运行`go run main.go`。

1.  您也可以运行以下命令：

```go
$ go build $ ./example
```

您应该看到以下输出：

```go
$ go run main.go
panic: context deadline exceeded

goroutine 1 [running]:
main.main()
/go/src/PacktPublishing/Go-Programming-Cookbook-Second-
Edition/go-cookbook/chapter6/pools/example/main.go:7 +0x4e
exit status 2
```

1.  `go.mod`文件可能会被更新，顶级示例目录中现在应该存在`go.sum`文件。

1.  如果您复制或编写了自己的测试，请返回上一级目录并运行`go test`。确保所有测试都通过。

# 工作原理...

能够控制连接池的深度非常有用。这将防止我们过载数据库，但重要的是要考虑在超时的情况下会发生什么。如果您同时强制执行一组连接和严格基于上下文的超时，就像我们在这个示例中所做的那样，将会有一些情况下，您会发现请求经常在尝试建立太多连接的过载应用程序上超时。

这是因为连接将超时等待连接可用。对于`database/sql`的新添加的上下文功能使得为整个请求设置共享超时变得更加简单，包括执行查询所涉及的步骤。

通过这个和其他的示例，使用一个全局的`config`对象传递给`Setup()`函数是有意义的，尽管这个示例只是使用环境变量。

# 使用 Redis

有时您需要持久存储或第三方库和服务提供的附加功能。这个示例将探讨 Redis 作为非关系型数据存储的形式，并展示 Go 语言如何与这些第三方服务进行交互。

由于 Redis 支持具有简单接口的键值存储，因此它是会话存储或具有持续时间的临时数据的绝佳候选者。在 Redis 中指定数据的超时是非常有价值的。这个示例将探讨从配置到查询再到使用自定义排序的基本 Redis 用法。

# 准备工作

根据以下步骤配置您的环境：

1.  在您的操作系统上下载并安装 Go 1.11.1 或更高版本，网址为[`golang.org/doc/install`](https://golang.org/doc/install)。

1.  从[`www.consul.io/intro/getting-started/install.html`](https://www.consul.io/intro/getting-started/install.html)安装 Consul。

1.  打开一个终端或控制台应用程序，并创建并导航到一个项目目录，例如`~/projects/go-programming-cookbook`。所有的代码都将在这个目录中运行和修改。

1.  将最新的代码克隆到`~/projects/go-programming-cookbook-original`，然后（可选）从该目录中工作，而不是手动输入示例：

```go
$ git clone git@github.com:PacktPublishing/Go-Programming-Cookbook-Second-Edition.git go-programming-cookbook-original
```

1.  使用[`redis.io/topics/quickstart`](https://redis.io/topics/quickstart)安装和配置 Redis。

# 如何做...

这些步骤涵盖了编写和运行应用程序：

1.  从您的终端或控制台应用程序中，创建一个名为`~/projects/go-programming-cookbook/chapter6/redis`的新目录，并导航到该目录。

1.  运行以下命令：

```go
$ go mod init github.com/PacktPublishing/Go-Programming-Cookbook-Second-Edition/chapter6/redis 
```

您应该看到一个名为`go.mod`的文件，其中包含以下内容：

```go
module github.com/PacktPublishing/Go-Programming-Cookbook-Second-Edition/chapter6/redis    
```

1.  从`~/projects/go-programming-cookbook-original/chapter6/redis`复制测试，或者利用这个练习编写一些自己的代码！

1.  创建一个名为`config.go`的文件，并包含以下内容：

```go
        package redis

        import (
            "os"

            redis "gopkg.in/redis.v5"
        )

        // Setup initializes a redis client
        func Setup() (*redis.Client, error) {
            client := redis.NewClient(&redis.Options{
                Addr: "localhost:6379",
                Password: os.Getenv("REDISPASSWORD"),
                DB: 0, // use default DB
         })

         _, err := client.Ping().Result()
         return client, err
        }
```

1.  创建一个名为`exec.go`的文件，并包含以下内容：

```go
        package redis

        import (
            "fmt"
            "time"

            redis "gopkg.in/redis.v5"
        )

        // Exec performs some redis operations
        func Exec() error {
            conn, err := Setup()
            if err != nil {
                return err
            }

            c1 := "value"
            // value is an interface, we can store whatever
            // the last argument is the redis expiration
            conn.Set("key", c1, 5*time.Second)

            var result string
            if err := conn.Get("key").Scan(&result); err != nil {
                switch err {
                // this means the key
                // was not found
                case redis.Nil:
                    return nil
                default:
                    return err
                }
            }

            fmt.Println("result =", result)

            return nil
        }
```

1.  创建一个名为`sort.go`的文件，并包含以下内容：

```go
package redis

import (
  "fmt"

  redis "gopkg.in/redis.v5"
)

// Sort performs a sort redis operations
func Sort() error {
  conn, err := Setup()
  if err != nil {
    return err
  }

  listkey := "list"
  if err := conn.LPush(listkey, 1).Err(); err != nil {
    return err
  }
  // this will clean up the list key if any of the subsequent commands error
  defer conn.Del(listkey)

  if err := conn.LPush(listkey, 3).Err(); err != nil {
    return err
  }
  if err := conn.LPush(listkey, 2).Err(); err != nil {
    return err
  }

  res, err := conn.Sort(listkey, redis.Sort{Order: "ASC"}).Result()
  if err != nil {
    return err
  }
  fmt.Println(res)

  return nil
}
```

1.  导航到`example`。

1.  创建一个名为`main.go`的文件，内容如下：

```go
        package main

        import "PacktPublishing/
                Go-Programming-Cookbook-Second-Edition/
                go-cookbook/chapter6/redis"

        func main() {
            if err := redis.Exec(); err != nil {
                panic(err)
            }

            if err := redis.Sort(); err != nil {
                panic(err)
            }
        }
```

1.  运行`go run main.go`。

1.  您也可以运行以下命令：

```go
$ go build $ ./example
```

您应该看到以下输出：

```go
$ go run main.go
result = value
[1 2 3]
```

1.  `go.mod`文件可能已更新，顶级配方目录中现在应该存在`go.sum`文件。

1.  如果您复制或编写了自己的测试，请返回上一个目录并运行`go test`。确保所有测试都通过。

# 工作原理...

在 Go 中使用 Redis 与使用 MySQL 非常相似。虽然没有标准库，但是许多相同的约定都遵循了，例如使用`Scan()`函数将数据从 Redis 读取到 Go 类型中。在这种情况下，选择最佳库可能会有挑战，我建议定期调查可用的内容，因为事情可能会迅速改变。

这个示例使用`redis`包来进行基本的设置和获取，更复杂的排序功能以及基本的配置。与`database/sql`一样，您可以以写超时、池大小等形式设置额外的配置。Redis 本身还提供了许多额外的功能，包括 Redis 集群支持、Zscore 和计数器对象以及分布式锁。

与前面的示例一样，我建议使用一个`config`对象，它存储您的 Redis 设置和配置详细信息，以便轻松设置和安全性。

# 使用 NoSQL 与 MongoDB

您可能最初认为 Go 更适合关系数据库，因为 Go 结构和 Go 是一种类型化的语言。当使用`github.com/mongodb/mongo-go-driver`包时，Go 可以几乎任意存储和检索结构对象。如果对对象进行版本控制，您的模式可以适应，并且可以提供一个非常灵活的开发环境。

有些库更擅长隐藏或提升这些抽象。`mongo-go-driver`包就是一个很好的例子。下面的示例将以类似的方式创建一个连接，类似于 Redis 和 MySQL，但将存储和检索对象而无需定义具体的模式。

# 准备工作

根据以下步骤配置您的环境：

1.  在您的操作系统上下载并安装 Go 1.11.1 或更高版本，网址为[`golang.org/doc/install`](https://golang.org/doc/install)。

1.  从[`www.consul.io/intro/getting-started/install.html`](https://www.consul.io/intro/getting-started/install.html)安装 Consul。

1.  打开一个终端或控制台应用程序，并创建并导航到一个项目目录，例如`~/projects/go-programming-cookbook`。所有的代码都将在这个目录中运行和修改。

1.  将最新的代码克隆到`~/projects/go-programming-cookbook-original`，（可选）从该目录中工作，而不是手动输入示例：

```go
$ git clone git@github.com:PacktPublishing/Go-Programming-Cookbook-Second-Edition.git go-programming-cookbook-original
```

1.  安装和配置 MongoDB（[`docs.mongodb.com/getting-started/shell/`](https://docs.mongodb.com/getting-started/shell/)）。

# 如何做...

这些步骤涵盖了编写和运行应用程序：

1.  从您的终端或控制台应用程序中，创建一个名为`~/projects/go-programming-cookbook/chapter6/mongodb`的新目录，并导航到该目录。

1.  运行以下命令：

```go
$ go mod init github.com/PacktPublishing/Go-Programming-Cookbook-Second-Edition/chapter6/mongodb 
```

您应该看到一个名为`go.mod`的文件，其中包含以下内容：

```go
module github.com/PacktPublishing/Go-Programming-Cookbook-Second-Edition/chapter6/mongodb    
```

1.  从`~/projects/go-programming-cookbook-original/chapter6/mongodb`复制测试，或者利用这个机会编写一些自己的代码！

1.  创建一个名为`config.go`的文件，内容如下：

```go
package mongodb

import (
  "context"
  "time"

  "github.com/mongodb/mongo-go-driver/mongo"
  "go.mongodb.org/mongo-driver/mongo/options"
)

// Setup initializes a mongo client
func Setup(ctx context.Context, address string) (*mongo.Client, error) {
  ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
  // cancel will be called when setup exits
  defer cancel()

  client, err := mongo.NewClient(options.Client().ApplyURI(address))
  if err != nil {
    return nil, err
  }

  if err := client.Connect(ctx); err != nil {
    return nil, err
  }
  return client, nil
}
```

1.  创建一个名为`exec.go`的文件，内容如下：

```go
package mongodb

import (
  "context"
  "fmt"

  "github.com/mongodb/mongo-go-driver/bson"
)

// State is our data model
type State struct {
  Name string `bson:"name"`
  Population int `bson:"pop"`
}

// Exec creates then queries an Example
func Exec(address string) error {
  ctx := context.Background()
  db, err := Setup(ctx, address)
  if err != nil {
    return err
  }

  coll := db.Database("gocookbook").Collection("example")

  vals := []interface{}{&State{"Washington", 7062000}, &State{"Oregon", 3970000}}

  // we can inserts many rows at once
  if _, err := coll.InsertMany(ctx, vals); err != nil {
    return err
  }

  var s State
  if err := coll.FindOne(ctx, bson.M{"name": "Washington"}).Decode(&s); err != nil {
    return err
  }

  if err := coll.Drop(ctx); err != nil {
    return err
  }

  fmt.Printf("State: %#v\n", s)
  return nil
}
```

1.  导航到`example`。

1.  创建一个名为`main.go`的文件，内容如下：

```go
package main

import "github.com/PacktPublishing/Go-Programming-Cookbook-Second-Edition/chapter6/mongodb"

func main() {
  if err := mongodb.Exec("mongodb://localhost"); err != nil {
    panic(err)
  }
}
```

1.  运行`go run main.go`。

1.  您也可以运行以下命令：

```go
$ go build $ ./example
```

您应该看到以下输出：

```go
$ go run main.go
State: mongodb.State{Name:"Washington", Population:7062000}
```

1.  `go.mod`文件可能已更新，顶级配方目录中现在应该存在`go.sum`文件。

1.  如果您复制或编写了自己的测试，请返回上一个目录并运行`go test`。确保所有测试都通过。

# 工作原理...

`mongo-go-driver`包还提供连接池，并且有许多方法可以调整和配置与`mongodb`数据库的连接。本示例的示例相当基本，但它们说明了理解和查询基于文档的数据库是多么容易。该包实现了 BSON 数据类型，与处理 JSON 非常相似。

`mongodb`的一致性保证和最佳实践超出了本书的范围。然而，在 Go 语言中使用这些功能是一种乐趣。

# 为数据可移植性创建存储接口

在使用外部存储接口时，将操作抽象化到接口后面可能会有所帮助。这是为了方便模拟，如果更改存储后端，则可移植性，以及关注点的隔离。这种方法的缺点可能在于，如果您需要在事务内执行多个操作，那么最好是进行组合操作，或者允许通过上下文对象或附加函数参数传递它们。

此示例将实现一个非常简单的接口，用于在 MongoDB 中处理项目。这些项目将具有名称和价格，我们将使用接口来持久化和检索这些对象。

# 准备工作

请参考*使用 NoSQL 与 MongoDB*中*准备工作*部分中给出的步骤。

# 如何做...

这些步骤涵盖了编写和运行应用程序的过程：

1.  从您的终端或控制台应用程序中，创建一个名为`~/projects/go-programming-cookbook/chapter6/storage`的新目录，并导航到该目录。

1.  运行以下命令：

```go
$ go mod init github.com/PacktPublishing/Go-Programming-Cookbook-Second-Edition/chapter6/storage 
```

您应该会看到一个名为`go.mod`的文件，其中包含以下内容：

```go
module github.com/PacktPublishing/Go-Programming-Cookbook-Second-Edition/chapter6/storage    
```

1.  从`~/projects/go-programming-cookbook-original/chapter6/storage`复制测试，或者利用这个机会编写一些自己的代码！

1.  创建一个名为`storage.go`的文件，内容如下：

```go
        package storage

        import "context"

        // Item represents an item at
        // a shop
        type Item struct {
            Name  string
            Price int64
        }

        // Storage is our storage interface
        // We'll implement it with Mongo
        // storage
        type Storage interface {
            GetByName(context.Context, string) (*Item, error)
            Put(context.Context, *Item) error
        }
```

1.  创建一个名为`mongoconfig.go`的文件，内容如下：

```go
package storage

import (
  "context"
  "time"

  "github.com/mongodb/mongo-go-driver/mongo"
)

// MongoStorage implements our storage interface
type MongoStorage struct {
  *mongo.Client
  DB string
  Collection string
}

// NewMongoStorage initializes a MongoStorage
func NewMongoStorage(ctx context.Context, connection, db, collection string) (*MongoStorage, error) {
  ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
  defer cancel()

  client, err := mongo.Connect(ctx, "mongodb://localhost")
  if err != nil {
    return nil, err
  }

  ms := MongoStorage{
    Client: client,
    DB: db,
    Collection: collection,
  }
  return &ms, nil
}
```

1.  创建一个名为`mongointerface.go`的文件，内容如下：

```go
package storage

import (
  "context"

  "github.com/mongodb/mongo-go-driver/bson"
)

// GetByName queries mongodb for an item with
// the correct name
func (m *MongoStorage) GetByName(ctx context.Context, name string) (*Item, error) {
  c := m.Client.Database(m.DB).Collection(m.Collection)
  var i Item
  if err := c.FindOne(ctx, bson.M{"name": name}).Decode(&i); err != nil {
    return nil, err
  }

  return &i, nil
}

// Put adds an item to our mongo instance
func (m *MongoStorage) Put(ctx context.Context, i *Item) error {
  c := m.Client.Database(m.DB).Collection(m.Collection)
  _, err := c.InsertOne(ctx, i)
  return err
}
```

1.  创建一个名为`exec.go`的文件，内容如下：

```go
package storage

import (
  "context"
  "fmt"
)

// Exec initializes storage, then performs operations
// using the storage interface
func Exec() error {
  ctx := context.Background()
  m, err := NewMongoStorage(ctx, "localhost", "gocookbook", "items")
  if err != nil {
    return err
  }
  if err := PerformOperations(m); err != nil {
    return err
  }

  if err := m.Client.Database(m.DB).Collection(m.Collection).Drop(ctx); err != nil {
    return err
  }

  return nil
}

// PerformOperations creates a candle item
// then gets it
func PerformOperations(s Storage) error {
  ctx := context.Background()
  i := Item{Name: "candles", Price: 100}
  if err := s.Put(ctx, &i); err != nil {
    return err
  }

  candles, err := s.GetByName(ctx, "candles")
  if err != nil {
    return err
  }
  fmt.Printf("Result: %#v\n", candles)
  return nil
}
```

1.  导航到`example`。

1.  创建一个名为`main.go`的文件，内容如下：

```go
        package main

        import "PacktPublishing/Go-Programming-Cookbook-Second-Edition/
                go-cookbook/chapter6/storage"

        func main() {
            if err := storage.Exec(); err != nil {
                panic(err)
            }
        }
```

1.  运行`go run main.go`。

1.  您还可以运行以下命令：

```go
$ go build $ ./example
```

您应该会看到以下输出：

```go
$ go run main.go
Result: &storage.Item{Name:"candles", Price:100}
```

1.  `go.mod`文件可能会被更新，顶级配方目录中现在应该存在`go.sum`文件。

1.  如果您复制或编写了自己的测试，请返回上一级目录并运行`go test`。确保所有测试都通过。

# 它是如何工作的...

演示此示例最重要的函数是`PerformOperations`。此函数将一个`Storage`接口作为参数。这意味着我们可以动态替换底层存储，甚至无需修改此函数。例如，连接存储到单独的 API 以消费和修改它将是很简单的。

我们使用上下文来为这些接口添加额外的灵活性，并允许接口处理超时。将应用程序逻辑与底层存储分离提供了各种好处，但很难选择正确的划界线的位置，这将因应用程序而异。
