# Go 和安全（一）

> 原文：[`zh.annas-archive.org/md5/7656FC72AAECE258C02033B14E33EA12`](https://zh.annas-archive.org/md5/7656FC72AAECE258C02033B14E33EA12)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 前言

本书涵盖了 Go 编程语言，并解释了如何将其应用于网络安全行业。所涵盖的主题对于红队和蓝队都很有用，也适用于希望编写安全代码的开发人员，以及希望保护其网络、主机和知识产权的网络和运维工程师。源代码示例都是完全功能的程序。这些示例旨在成为您可能希望纳入自己工具包的实用应用程序。此外，本书还作为一个构建自定义应用程序的实用菜谱。我还分享了其他我学到的安全最佳实践和技巧。

本书将为您演示在各种计算机安全情况下有用的代码示例。在阅读本书的过程中，您将建立一个实用应用程序和构建模块的菜谱，用于您自己的安全工具，以用于您的组织和工作。它还将涵盖一些关于 Go 编程语言的技巧和趣闻，并提供许多有用的参考程序，以增强您自己的 Go 菜谱。

本书将涵盖几个蓝队和红队使用案例以及其他各种安全相关主题。蓝队主题，即隐写术、取证、数据包捕获、诱饵网站和密码学，以及红队主题，即暴力破解、端口扫描、绑定和反向 shell、SSH 客户端和网页抓取，都将被涵盖。每一章都涉及不同的安全主题，并演示与该主题相关的代码示例。如果您遵循本书，您将拥有一个充满有用安全工具和构建模块的菜谱，以创建您自己的 Go 自定义工具。

本书不是关于使用 Go 语言的深入教程。其中有一章专门解释 Go；然而，与 Alan Donovan 和 Brian Kernighan 的近 400 页的《Go 编程语言》相比，它只是皮毛。幸运的是，Go 是一种非常容易上手的语言，学习曲线很快。提供了一些关于学习 Go 的资源，但如果读者对 Go 不熟悉，可能需要进行一些补充阅读。

本书不会探索尚未有充分记录的尖端安全技术或漏洞。没有零日漏洞或重大技术揭示。每一章都专门讨论一个不同的安全主题。这些主题中的每一个都可以写一本书。有专门研究这些领域的专家，因此本书不会深入研究任何特定主题。读者在完成后将有一个坚实的基础，可以深入探索任何主题。

# 本书适合对象

本书适合已经熟悉 Go 编程语言的程序员。需要一些 Go 的知识，但读者不需要成为 Go 专家。内容面向 Go 的新手，但不会教会您使用 Go 的一切。对 Go 不熟悉的人将有机会探索和尝试 Go 的各个方面，并将其应用于安全实践。我们将从较小和较简单的示例开始，然后再转向使用更高级的 Go 语言特性的示例。

读者不必是高级安全专家，但至少应该对核心安全概念有基本的了解。目标是以经验丰富的开发人员或安全专家的身份，通过安全主题，改进他们的工具集，并建立一个 Go 参考代码库。喜欢构建充满有用工具的菜谱的读者将喜欢阅读这些章节。希望在与安全、网络和其他领域相关的 Go 中构建自定义工具的人将受益于这些示例。开发人员、渗透测试人员、SOC 分析员、DevOps 工程师、社会工程师和网络工程师都可以利用本书的内容。

# 本书涵盖内容

第一章，“使用 Go 进行安全介绍”，涵盖了 Go 的历史，并讨论了为什么 Go 是安全应用的一个不错选择，如何设置开发环境以及运行您的第一个程序。

第二章，“Go 编程语言”，介绍了使用 Go 进行编程的基础知识。它回顾了关键字和数据类型以及 Go 的显著特性。它还包含了获取帮助和阅读文档的信息。

第三章，“文件操作”，帮助您探索使用 Go 操作、读取、写入和压缩文件的各种方法。

第四章，“取证”，讨论了基本的文件取证、隐写术和网络取证技术。

第五章，“数据包捕获和注入”，涵盖了使用`gopacket`包进行数据包捕获的各个方面。主题包括获取网络设备列表、从实时网络设备捕获数据包、过滤数据包、解码数据包层以及发送自定义数据包。

第六章，“密码学”，解释了哈希、对称加密（如 AES）和非对称加密（如 RSA）、数字签名、验证签名、TLS 连接、生成密钥和证书以及其他密码学包。

第七章，“安全外壳（SSH）”，涵盖了 Go SSH 包，如何使用客户端进行密码和密钥对认证。它还涵盖了如何使用 SSH 在远程主机上执行命令和运行交互式外壳。

第八章，“暴力破解”，包括多个暴力破解攻击客户端的示例，包括 HTTP 基本身份验证、HTML 登录表单、SSH、MongoDB、MySQL 和 PostgreSQL。

第九章，“Web 应用程序”，解释了如何构建具有安全 cookie、经过消毒的输出、安全标头、日志记录和其他最佳实践的安全 Web 应用程序。它还涵盖了编写使用客户端证书、HTTP 代理和 Tor 等 SOCKS5 代理的安全 Web 客户端。

第十章，“Web 抓取”，讨论了基本的抓取技术，如字符串匹配、正则表达式和指纹识别。它还涵盖了`goquery`包，这是一个从结构化网页中提取数据的强大工具。

第十一章，“主机发现和枚举”，涵盖了端口扫描、横幅抓取、TCP 代理、简单的套接字服务器和客户端、模糊测试以及扫描具有命名主机的网络。

第十二章，“社会工程学”，提供了通过 JSON REST API（如 Reddit）收集情报的示例，使用 SMTP 发送钓鱼邮件以及生成 QR 码。它还涵盖了蜜罐以及 TCP 和 HTTP 蜜罐的示例。

第十三章，“后渗透”，涵盖了各种后渗透技术，如交叉编译绑定外壳、反向绑定外壳和 Web 外壳。它还提供了搜索可写文件并修改时间戳、所有权和权限的示例。

第十四章，“结论”，是对主题的总结，向您展示您可以从这里走向何方，并且还考虑了应用本书中学到的技术的注意事项。

# 为了充分利用本书

1.  读者应具有基本的编程知识，并且至少了解一种编程语言。

1.  要运行示例，读者需要安装了 Go 的计算机。安装说明在书中有介绍。推荐的操作系统是 Ubuntu Linux，但示例也应该可以在 macOS、Windows 和其他 Linux 发行版上运行。

# 下载示例代码文件

您可以从[www.packtpub.com](http://www.packtpub.com)的帐户中下载本书的示例代码文件。如果您在其他地方购买了本书，您可以访问[www.packtpub.com/support](http://www.packtpub.com/support)并注册，以便直接通过电子邮件接收文件。

您可以按照以下步骤下载代码文件：

1.  登录或注册[www.packtpub.com](http://www.packtpub.com/support)。

1.  选择“支持”选项卡。

1.  点击“代码下载和勘误”。

1.  在搜索框中输入书名，并按照屏幕上的指示操作。

下载文件后，请确保使用以下最新版本之一解压或提取文件夹：

+   WinRAR/7-Zip for Windows

+   Zipeg/iZip/UnRarX for Mac

+   7-Zip/PeaZip for Linux

该书的代码包也托管在 GitHub 上，网址为[`github.com/PacktPublishing/Security-with-Go`](https://github.com/PacktPublishing/Security-with-Go)。我们还有其他书籍和视频的代码包可供下载，网址为**[`github.com/PacktPublishing/`](https://github.com/PacktPublishing/)**。请查看！

# 使用的约定

本书中使用了许多文本约定。

`CodeInText`：表示文本中的代码字词、数据库表名、文件夹名、文件名、文件扩展名、路径名、虚拟 URL、用户输入和 Twitter 句柄。例如：" `make()`函数将创建一个具有特定长度和容量的特定类型的切片。"

代码块设置如下：

```go
package main

import (
    "fmt"
)

func main() {
   // Basic for loop
   for i := 0; i < 3; i++ {
       fmt.Println("i:", i)
   }

   // For used as a while loop
   n := 5
   for n < 10 {
       fmt.Println(n)
       n++
   }
}
```

当我们希望引起您对代码块的特定部分的注意时，相关行或项目将以粗体显示：

```go
package main

import (
    "fmt"
)

func main() {
   // Basic for loop
   for i := 0; i < 3; i++ {
       fmt.Println("i:", i)
   }

   // For used as a while loop
   n := 5
   for n < 10 {
       fmt.Println(n)
       n++
   }
}
```

任何命令行输入或输出都以以下方式编写：

```go
sudo apt-get install golang-go 
```

**粗体**：表示新术语、重要单词或屏幕上看到的单词。例如，菜单或对话框中的单词会在文本中以这种方式出现。例如："在 Windows 10 中，可以通过导航到控制面板|系统|高级系统设置|环境变量来找到。"

高级系统设置|环境变量。"

警告或重要说明看起来像这样。

提示和技巧看起来像这样。


# 第一章：使用 Go 进行安全介绍

安全和隐私作为实际问题，一直在不断引起兴趣，特别是在技术行业。网络安全市场正在蓬勃发展并持续增长。该行业随着创新和研究的不断涌现而发展迅速。安全的兴趣和速度不仅加快了，而且应用程序的规模和风险也成倍增长。该行业需要一种简单易学、跨平台、高效的编程语言。Go 是完美的选择，它拥有非常强大的标准库、学习曲线短、运行速度快。

在本章中，我们将涵盖以下主题：

+   Go 的历史、语言设计、批评、社区和学习技巧

+   为什么使用 Go 进行安全

+   设置开发环境并编写你的第一个程序

+   运行示例程序

# 关于 Go

Go 是由谷歌创建并在 BSD 风格许可下分发的开源编程语言。BSD 许可允许任何人免费使用 Go，只要保留版权声明并且不使用谷歌名称进行认可或推广。Go 受到 C 的重大影响，但语法更简单，内存安全性和垃圾收集更好。有时，Go 被描述为现代的 C++。我认为这太过于简化，但 Go 绝对是一种简单而现代的语言。

# Go 语言设计

Go 的最初目标是创建一种简单、可靠和高效的新语言。正如前面提到的，Go 受到 C 编程语言的重大影响。这种语言本身非常简单，只有 25 个关键字。它被设计成与集成开发环境很好地结合，但并不依赖于它们。根据我的经验，任何尝试过 Go 的人都会发现它非常用户友好，学习曲线很短。

Go 的主要目标之一是解决 C++和 Java 代码的一些负面问题，同时保持性能。这种语言需要简单而一致，以管理非常庞大的开发团队。

变量是静态类型的，应用程序可以快速编译成静态链接的二进制文件。拥有单个静态链接的二进制文件使得创建轻量级容器非常容易。最终的应用程序也运行得很快，接近 C++和 Java 的性能，比 Python 等解释性语言快得多。虽然有指针，但不允许指针算术。Go 并不是自诩为面向对象的编程语言，也没有传统意义上的*类*；然而，它包含了许多与面向对象编程语言非常相似的机制。这将在下一章中更深入地讨论。接口被广泛使用，组合是继承的等价物。

Go 有许多有趣的特性。其中一个突出的特点是内置的并发性。只需在任何函数调用之前加上“go”这个词，它就会生成一个轻量级线程来执行该函数。另一个相当重要的特性是依赖管理，这是非常高效的。依赖管理是 Go 编译速度非常快的原因之一。它不会多次重新包含相同的头文件，就像 C++那样。Go 还具有内置的内存安全性，垃圾收集器处理未使用的内存清理。Go 的标准库也非常令人印象深刻。它是现代的，包含网络、HTTP、TLS、XML、JSON、数据库、图像处理和加密包。Go 还支持 Unicode，允许在源代码中使用各种字符。

Go 工具链是生态系统的核心。它提供了工具来下载和安装远程依赖项，运行单元测试和基准测试，生成代码，并根据 Go 格式标准格式化代码。它还包括编译器、链接器和汇编器，这些工具编译非常快，也允许通过简单地更改`GOOS`和`GOARCH`环境变量来轻松进行交叉编译。

一些功能被排除在 Go 语言之外。泛型、继承、断言、异常、指针算术和隐式类型转换都被排除在 Go 之外。许多功能是有意省略的，特别是泛型、断言和指针算术。作者们故意省略了一些功能，因为他们希望保持性能，尽可能简化语言规范，或者他们无法就最佳实现方式达成一致，或者因为某个功能太有争议。继承也是有意被省略的，而是使用接口和组合。其他一些功能，比如泛型，也是因为关于它们的正确实现存在太多争论而被省略，但它们可能会出现在 Go 2.0 中。作者们认识到，向语言中添加功能要比删除功能容易得多。

# Go 的历史

Go 是一种相对年轻的语言，起源于 2007 年，2009 年开源。它起源于 Google 的*20%项目*，由 Robert Griesemer、Rob Pike 和 Ken Thompson 共同开发。20%项目意味着项目的开发人员将 20%的时间用于作为实验性的副业项目。Go 1.0 于 2012 年 3 月正式发布。从一开始就计划将其作为一种开源语言。直到 Go 1.5 版本，编译器、链接器和汇编器都是用 C 语言编写的。在 1.5 版本之后，一切都是用 Go 语言编写的。

Google 最初为 Linux 和 macOS 推出了 Go，社区推动了其他平台的努力，即 Windows、FreeBSD、OpenBSD、NetBSD 和 Solaris。甚至已经移植到 IBM z 系统主机上。IBM 的 Bill O'Farrell 在 2016 年丹佛的 GopherCon 上做了一个名为*将 Go 移植到 IBM z 架构*的演讲（[`www.youtube.com/watch?v=z0f4Wgi94eo`](https://www.youtube.com/watch?v=z0f4Wgi94eo)）。

谷歌以 Python、Java 和 C++而闻名。他们选择这些语言也是可以理解的。它们各自扮演着特定的角色，有各自的优势和劣势。Go 是为了创建一个符合谷歌需求的新语言。他们需要能够在重负载下表现出色，支持并发，并且易于阅读、编写和快速编译的软件。

启动 Go 项目的触发事件是处理一个庞大的 C++代码库，因为 C++处理依赖关系和重新包含头文件的方式，构建需要花费数小时的时间（[`www.youtube.com/watch?v=bj9T2c2Xk_s`](https://www.youtube.com/watch?v=bj9T2c2Xk_s) (37:15)）。这就是为什么 Go 的主要目标之一是快速编译。Go 帮助将数小时的编译时间缩短到几秒，因为它比 C++更有效地处理依赖关系。

Go 2.0 的讨论已经开始，但仍处于概念阶段。目前没有发布时间表，也没有着急发布新的主要版本。

# 采用和社区

Go 仍然是一种年轻的语言，但它的采用率不断增长，也在人气上持续增长。Go 分别在 2009 年和 2016 年成为 TIOBE 年度语言：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/sec-go/img/3d9b13c6-b329-4bdc-8ebe-4e563bf87d0d.png)

来源：https://www.tiobe.com/tiobe-index/go/

Go 团队表达的期望之一是，他们预期 Go 会吸引大量的 C/C++和 Java 开发人员，但当大量用户来自 Python 和 Ruby 等脚本语言时，他们感到惊讶。其他人，比如我自己，发现 Go 是 Python 的一个自然补充，是一种很棒的语言。然而，当你需要更强大的东西时，你会选择哪种语言呢？一些大公司已经证明了 Go 在大规模生产中是稳定的，包括 Google、Dropbox、Netflix、Uber 和 SoundCloud。

第一个 Go 大会名为 GopherCon，于 2014 年举行。从那时起，GopherCon 每年都会举行。在[`gophercon.com`](https://gophercon.com)上了解更多关于 GopherCon 的信息。我有幸在 2016 年的 GopherCon 上发表了关于数据包捕获的演讲，并有了很棒的经历（[`www.youtube.com/watch?v=APDnbmTKjgM`](https://www.youtube.com/watch?v=APDnbmTKjgM)）。

# 关于 Go 的常见批评

社区中经常出现一些批评。可能最臭名昭著且最受讨论的批评是缺乏泛型。这导致重复的代码来处理不同的数据类型。接口在一定程度上可以缓解这个问题。我们可能会在未来的版本中看到泛型，因为作者已经表现出对泛型的开放态度，但他们并没有匆忙做出重要的设计决定。

接下来经常听到的批评是缺乏异常处理。开发人员必须显式处理或忽略每个错误。就我个人而言，我发现这是一种令人耳目一新的改变。这并不是真的多做工作，而且你可以完全控制代码流程。有时候，使用异常处理时，你并不确定它会在哪里被捕获，因为它会一直冒泡上来。而使用 Go，你可以轻松地跟踪错误处理代码。

Go 有一个处理内存清理的垃圾收集器。垃圾收集器随着时间的推移得到了升级和改进。垃圾收集器确实会对性能产生一些影响，但它节省了开发人员大量的思考和担忧。最初，Go 被描述为一种系统编程语言，对内存的控制能力对于非常低级的应用程序来说是有限制的。自那时起，他们已经转变了对 Go 的称呼，不再称其为系统编程语言。如果你需要对内存进行低级别的控制，那么你将不得不用 C 语言编写部分代码。

# Go 工具链

`go`可执行文件是 Go 工具链的主要应用程序。你可以向`go`传递一个命令，它将采取适当的操作。工具链有工具来运行、编译、格式化源代码，下载依赖项等。让我们看看完整的列表，这是通过`go help`命令或`go`本身获得的输出：

+   `build`: 这个命令编译包和依赖项

+   `clean`: 这个命令移除对象文件

+   `doc`: 这个命令显示包或符号的文档

+   `env`: 这个命令打印 Go 环境信息

+   `generate`: 这是代码生成器

+   `fix`: 这个命令在新版本发布时升级 Go 代码

+   `fmt`: 这个命令在包源代码上运行`gofmt`

+   `get`: 这个命令下载并安装包和依赖项

+   `help`: 这个命令提供特定主题的更多帮助

+   `install`: 这个命令编译并安装包和依赖项

+   `list`: 这个命令列出包

+   `run`: 这个命令编译并运行 Go 程序

+   `test`: 这个命令运行单元测试和基准测试

+   `vet`: 这个命令用于检查源代码中的错误

+   `version`: 这个命令显示 Go 版本

有关这些命令的更多信息，请访问[`golang.org/cmd/`](https://golang.org/cmd/)。

# Go 吉祥物

每个人都知道最好的剑有名字，最好的编程语言有吉祥物。Go 的吉祥物是**gopher**。这只 gopher 没有名字。它有一个豆子形状的身体，微小的四肢，巨大的眼睛和两颗牙齿。它是由 Renee French 设计的，其版权属于*知识共享署名 3.0*许可。这意味着你可以使用这些图片，但必须在使用的地方给予其创作者 Renee French 的信用。

Renee French 在 2016 年的丹佛 GopherCon 上做了一个名为*The Go Gopher: A Character Study*的演讲，解释了 gopher 的由来，它所采取的各种媒介和形式，以及在各种情况下画它的技巧([`www.youtube.com/watch?v=4rw_B4yY69k`](https://www.youtube.com/watch?v=4rw_B4yY69k))。

你可以在[`gopherize.me/`](https://gopherize.me/)生成一个定制的 gopher 头像，并在[`blog.golang.org/gopher`](https://blog.golang.org/gopher)上了解更多关于 Go gopher 的信息。

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/sec-go/img/13098b0b-f4f5-4d83-b780-4a505d29a41b.jpg)

# 学习 Go

如果你以前没有使用过 Go，不要害怕。它有一个温和的学习曲线，只需一两天就可以学会。开始的最佳地点是[`tour.golang.org/`](https://tour.golang.org/)。这是 Go 编程语言的基本教程。如果你已经完成了这个教程，那么你应该已经有了足够的基础来顺利阅读本书。如果你正在阅读本书，但还没有参加过这个教程，你可能会遇到一些你不熟悉的概念，这里没有解释。这个教程是一个学习和练习的好地方。

由于语言规范中只有 25 个保留关键字，它足够简短，可以被“凡人”理解。你可以在[`golang.org/ref/spec`](https://golang.org/ref/spec)上阅读更多关于规范的信息。

你必须已经熟悉了大部分这些关键词。它们包括：`if`，`else`，`goto`，`for`，`import`，`return`，`var`，`continue`，`break`，`range`，`type`，`func`，`interface`，`package`，`const`，`map`，`struct`，`select`，`case`，`switch`，`go`，`defer`，`chan`，`fallthrough`和`default`。

这个教程将帮助你学习关键词、语法和数据结构的基础知识。教程中的游乐场让你可以在浏览器中练习编写和运行代码。

# 为什么使用 Go？

关于 Go，有几个方面吸引了我。并发性，速度和简单性对我来说是最重要的。这种语言非常简单，易于学习。它没有`try`，`catch`和异常流程。尽管有些人批评繁琐的错误处理，但我发现拥有一种简单的语言是令人耳目一新的，它不会在幕后隐藏很多魔法，而是确切地做它所说的。`go fmt`工具标准化了格式，使得阅读他人的代码变得容易，并消除了定义自己的标准的负担。

Go 提供了一种可扩展性和可靠性的感觉，实际上是一种令人愉快的体验。在 Go 之前，快速编译代码的主要选择是 C++，对于不同的平台管理头文件和构建过程并不是一件简单的任务。多年来，C++已经变得非常复杂，对大多数人来说并不像 Go 那样易于接近。

# 为什么在安全领域使用 Go？

我认为我们都明白没有最好的编程语言这回事，但不同的工作有不同的工具。Go 在性能和并发性方面表现出色。它的其他一些优点包括能够编译成单个可执行文件并且容易进行跨平台编译。它还有一个现代化的标准库，非常适合网络应用。

跨编译的便利性在安全领域产生了一些有趣的用例。以下是安全领域中跨编译的一些用例：

+   渗透测试人员可以使用树莓派为 Windows、macOS 和 Linux 编译自定义的 Go 反向外壳，并尝试部署它们。

+   网络防御者可以有一个中央数据库，用来存储所有蜜罐服务器提供的蜜罐信息，然后交叉编译蜜罐服务器。这将使他们能够轻松地在所有平台上部署一致的应用程序，包括 Windows、mac 和 Linux。

+   网络防御者可以在网络中部署非常轻量级的蜜罐，形式为一个 Docker 容器，其中包含一个单一的静态链接二进制文件。容器可以快速创建和销毁，使用最小的带宽和服务器资源。

当你在思考 Go 是否是一个好的语言选择时，将 Go 与其他顶级语言进行比较可能会有所帮助。

# 为什么不使用 Python？

Python 是安全领域中流行的语言。这很可能是因为它的普及性、学习曲线短和大量的库。已经有一些有用的安全工具用 Python 编写，比如用于数据包捕获的 Scapy，用于网页抓取的 Scrapy，用于调试的 Immunity，用于解析 HTML 的 Beautiful Soup，以及用于内存取证的 Volatility。许多供应商和服务提供商也提供了 Python 的 API 示例。

Python 易于学习，并且有大量资源。Go 也易于编写，并且学习曲线平缓。在我看来，学习曲线和编程的简易性并不是 Go 和 Python 之间的主要区别因素。最大的区别，以及 Python 的不足之处，是性能。Python 在性能方面无法与 Go 竞争。部分原因是 Python 的解释性质，但更大的因素是**全局解释器锁**（**GIL**）。GIL 阻止解释器使用超过一个 CPU 的处理能力，即使有多个线程在执行。有一些方法可以绕过这个问题，比如使用多进程，但这也有自己的缺点和限制，因为它实际上是在派生一个新的进程。其他选项是使用 Jython（Python 在 Java 上）或 IronPython（Python 在.NET 上），这些都没有 GIL。

# 为什么不使用 Java？

Java 最大的优势之一是**一次编写，到处运行**（**WORA**）的能力。如果涉及到 GUI、图形或音频等任何事情，这是非常有价值的。Go 在创建 GUI 方面肯定不如 Java，但它是跨平台的，并支持交叉编译。

Java 是成熟且被广泛采用的，有大量可用的资源。与 Go 包相比，Java 库的选择更多。Java 是这两种语言中更冗长的一种。Java 生态系统更加复杂，有几种构建工具和包管理器可供选择。Go 更简单，更标准化。这些差异可能仅仅是由于这两种语言之间的年龄差异，但它可能仍会影响你的语言选择。

在某些情况下，**Java 虚拟机**（**JVM**）在内存或启动时间方面可能过于资源密集。如果需要将几个命令行 Java 应用程序串联在一起，为了运行一系列短暂的程序而启动 JVM 可能会对性能造成显著影响。在内存方面，如果需要运行同一应用程序的多个实例，那么运行每个 JVM 所需的内存可能会累积起来。JVM 也可能会限制，因为它创建了一个沙盒并限制了对主机机器的访问。Go 编译成本机代码，因此不需要虚拟机层。

Go 有很好的文档，并且社区不断增长并提供更多资源。对于有经验的程序员来说，这是一门容易学习的语言。并发性相对简单，并内置于语言中，而不是作为一个库包。

# 为什么不使用 C++？

C++确实提供了更多的控制，因为开发人员负责内存管理，没有垃圾收集器。出于同样的原因，C++的性能会稍微更好。在某些情况下，Go 实际上可以胜过 C++。

C++非常成熟，并拥有大量的第三方库。库并非总是跨平台的，可能具有复杂的 makefile。在 Go 中，交叉编译要简单得多，并且可以使用 Go 工具链完成。

Go 的编译效率更高，因为它具有更好的依赖管理。C++可以多次重新包含相同的头文件，导致编译时间膨胀。Go 中的包系统更一致和标准化。线程和并发在 Go 中是本地的，而在 C++中需要特定于平台的库。

C++的成熟也导致了语言随着时间的推移变得更加复杂。Go 是一种简单而现代的语言，带来了一种清新的变化。对初学者来说，C++不像 Go 那样友好。

# 开发环境

本书中的所有示例都可以在主要平台 Windows、macOS 和 Linux 上运行。话虽如此，这些示例主要是在 Ubuntu Linux 上编写和开发的，这是以下示例的推荐平台。

Ubuntu Linux 可以在[`www.ubuntu.com/download/desktop`](https://www.ubuntu.com/download/desktop)免费下载。下载页面可能会要求捐赠，但您可以选择免费下载。虽然不是必须使用 Ubuntu，但如果您使用相同的环境，阅读本书会更容易。其他 Linux 发行版同样适用，但我强烈建议您使用基于 Debian 的发行版。本书中的大多数 Go 代码示例都可以在 Windows、Linux 和 Mac 上运行，无需任何修改。某些示例可能是特定于 Linux 和 Mac 的，例如文件权限，在 Windows 中处理方式不同。任何特定于平台的示例都会有所提及。

您可以在虚拟机内免费安装 Ubuntu，也可以将其作为主要操作系统。只要您的系统具有足够的 CPU、RAM 和磁盘空间，我建议您使用 Oracle VirtualBox 提供的虚拟机，该虚拟机可在[`www.virtualbox.org/`](https://www.virtualbox.org/)上获得。VMWare Player 是 VirtualBox 的替代品，可在[`www.vmware.com/products/player/playerpro-evaluation.html`](https://www.vmware.com/products/player/playerpro-evaluation.html)上获得。

下载并安装 VirtualBox，然后下载 Ubuntu 桌面 ISO 文件。创建一个虚拟机，让它引导 Ubuntu ISO，并选择安装选项。安装完 Ubuntu 并以您的用户身份登录后，您可以安装 Go 编程语言。Ubuntu 通过提供一个软件包使这变得非常容易。只需打开一个终端窗口，运行以下命令：

```go
sudo apt-get install golang-go
```

使用`sudo`提升您的权限以进行安装，并可能要求您输入密码。如果一切顺利，您现在将可以访问包含整个工具链的`go`可执行文件。您可以运行`go help`或仅运行`go`以获取使用说明。

如果您没有使用 Ubuntu 或想要安装最新版本，您可以从[`golang.org/dl`](https://golang.org/dl/)下载最新版本。Windows 和 Mac 安装程序将负责更新您的`PATH`环境变量，但在 Linux 中，您将不得不将提取的内容移动到所需的位置，例如`/opt/go`，然后手动更新您的`PATH`环境变量以包括该位置。考虑以下示例：

```go
# Extract the downloaded Go tar.gz
tar xzf go1.9.linux-amd64.tar.gz
# Move the extracted directory to /opt
sudo mv go /opt
# Update PATH environment variable to include Go's binaries
echo "export PATH=$PATH:/opt/go/bin" >> ~/.bashrc
```

现在重新启动终端以使更改生效。如果您使用的是 Bash 之外的 shell，您需要更新适合您的 shell 的正确 RC 文件。

# 在其他平台上安装 Go

如果您没有使用 Ubuntu，您仍然可以轻松安装 Go。Go 网站在[`golang.org/dl/`](https://golang.org/dl/)的下载页面提供了多种安装格式。

# 其他 Linux 发行版

第一个选项是使用 Linux 发行版的软件包管理器安装 Go。大多数主要发行版都有 Go 的软件包。名称各不相同，因此可能需要进行网络搜索以获取确切的软件包名称。如果没有可用的软件包，您可以简单地下载预编译的 Linux tarball 并解压缩。将内容解压到`/opt/go`是一个不错的选择。然后，以与上一节中描述的方式相同，将`/opt/go/bin`添加到您的`PATH`环境变量中。

# Windows

官方的 Windows 安装程序可用，安装过程就像运行安装程序一样简单。您可能需要修改环境变量并更新您的`%PATH%`变量。在 Windows 10 中，可以通过导航到控制面板 | 系统 | 高级系统设置 | 环境变量找到。

# Mac

Mac 也有官方的安装程序可用。运行安装程序后，Go 将在您的`PATH`变量中可用。

# 设置 Go

此时，您的环境应该已经安装了 Go，并且您应该能够从终端窗口运行`go`可执行文件。go 程序是您访问 Go 工具链的方式。您可以通过运行以下命令来测试它：

```go
go help
```

现在我们准备编写第一个 Hello World 程序，以确保我们的环境完全正常。不过，在开始编码之前，我们需要创建一个适当的工作区。

# 创建您的工作区

Go 有一个工作区的标准文件夹结构。遵守特定的标准对于 Go 工具链正常工作非常重要。您可以在任何地方创建工作区目录，并且可以随意命名。在实验环境中，我们将简单地使用`Home`目录作为 Go 工作区。这意味着源文件将驻留在`~/src`，包将构建在`~/pkg`，可执行文件将安装到`~/bin`。

# 设置环境变量

为了让大部分 Go 工具链正常工作，必须设置`GOPATH`环境变量。`GOPATH`指定了你将其视为工作区的目录。在构建包之前，必须设置`GOPATH`环境变量。要获取更多帮助和信息，请在终端中运行以下命令调用`go help`命令：

```go
go help gopath
```

我们需要告诉 Go 将我们的`home`目录视为工作区。这是通过设置`GOPATH`环境变量来完成的。您可以通过以下三种方式设置`GOPATH`：

+   第一种方法是每次运行`go`命令时手动设置它。考虑以下示例：

```go
 GOPATH=$HOME go build hello
```

+   您还可以设置`GOPATH`变量，以便在关闭终端时保持设置，环境变量丢失：

```go
 export GOPATH=$HOME
```

+   第三个选项是永久设置`GOPATH`环境变量如下：

1.  1.  将其添加到您的 shell 启动脚本`.bashrc`中。这将在每次启动终端时设置变量。

1.  运行此命令以确保在打开未来的终端/ shell 会话时设置`GOPATH`：

```go
 echo "export GOPATH=$HOME" >> $HOME/.bashrc
```

1.  1.  重新启动终端以使更改生效。如果您使用 Zsh 或其他替代 shell，则需要更新相应的 RC 文件。

请注意，Go 版本 1.8 及更高版本不需要显式设置`GOPATH`环境变量。如果未设置`GOPATH`，它将使用`$HOME/go`作为默认工作区。

# 编辑器

我们将在我们的新`hello`目录中编写我们的第一个程序。您首先需要选择要使用的编辑器。幸运的是，使用 Go 不需要任何特殊的 IDE 或编辑器。Go 工具链可以轻松集成到许多编辑器和 IDE 中。您可以选择使用简单的文本编辑器，如记事本，也可以选择专门用于 Go 的完整的 IDE。

我建议您从一个简单的文本编辑器开始，比如 nano 或 gedit，因为这些都包含在 Ubuntu 中，易于使用，并且支持 Go 的语法高亮。当然，您也可以选择其他编辑器或 IDE。

许多文本编辑器和 IDE 都有 Go 支持的插件。例如，Visual Studio Code、Emacs、Sublime Text、JetBrains IntelliJ、Vim、Atom、NetBeans 和 Eclipse 都有 Go 插件。还有一些专门针对 Go 的 IDE，即 JetBrains GoLand 和 LiteIDE，两者都是跨平台的。

在您熟悉 Go 之后，可以从`nano`或`gedit`命令开始，然后探索其他编辑器和 IDE。本书不会比较编辑器或介绍如何配置它们。

# 创建您的第一个包

在`~/src`目录中，您创建的任何目录都是一个包。您的目录名称成为包或应用程序的名称。我们首先需要确保`src`目录存在。波浪号（`~`）类似于`$HOME`变量，是您的主目录的快捷方式。请参考以下代码块：

```go
mkdir ~/src
```

让我们为我们的第一个应用程序创建一个名为`hello`的新包：

```go
cd ~/src
mkdir hello
```

包只是一个目录。您可以在包中有一个或多个源文件。任何子目录都被视为单独的包。包可以是一个带有`main()`函数（`package main`）的应用程序，也可以是一个只能被其他包导入的库。这个包还没有任何文件，但我们马上就会写第一个文件。现在不要太担心包的结构。您可以在[`golang.org/doc/code.html#PackagePaths`](https://golang.org/doc/code.html#PackagePaths)上阅读有关包路径的更多信息。

# 编写你的第一个程序

您可以在一个目录中拥有的最简单的包是一个目录中的单个文件。创建一个新文件`~/src/hello/hello.go`，并将以下代码放入其中：

```go
package main

import "fmt"

func main() {
   fmt.Println("Hello, world.")
}
```

# 运行可执行文件

执行程序的最简单方法是使用`go run`命令。以下命令将在不留下可执行文件的情况下运行该文件：

```go
go run ~/src/hello/hello.go
```

# 构建可执行文件

要编译和构建可执行文件，请使用`go build`命令。运行`go build`时，必须传递一个包的路径。您提供的包路径是相对于`$GOPATH/src`的。由于我们的包在`~/src/hello`中，我们将运行以下命令：

```go
go build hello
```

只要我们设置了`$GOPATH`，就可以从任何地方调用`go build`。创建的可执行二进制文件将输出到当前工作目录中。然后可以使用以下命令运行它：

```go
./hello
```

# 安装可执行文件

`go build`工具适用于在当前工作目录中生成可执行文件，但有一种方法可以构建和安装您的应用程序，以便将可执行文件收集在同一位置。

当您运行`go install`时，它会将输出文件放在`$GOPATH/bin`的默认位置。在我们的情况下，我们将`$GOPATH`设置为我们的`$HOME`。因此，默认的`bin`目录将是`$HOME/bin`。

如果要将其安装到其他位置，可以通过设置`GOBIN`环境变量来覆盖位置。要安装我们的`hello`程序，我们将运行以下命令：

```go
go install hello
```

这将构建并创建一个可执行文件，`~/bin/hello`。如果`bin`目录尚不存在，它将自动创建。如果多次运行`install`命令，它将重新构建并覆盖`bin`目录中的可执行文件。然后可以使用以下命令运行应用程序：

```go
~/bin/hello
```

为了方便起见，您可以将`~/bin`添加到您的`PATH`环境变量中。这样做将允许您从任何工作目录运行应用程序。要将`bin`目录添加到您的`PATH`中，请在终端中运行以下命令：

```go
echo "export PATH=$PATH:$HOME/gospace/bin" >> ~/.bashrc
```

确保在此之后重新启动您的终端以刷新环境变量。之后，您可以通过在终端中简单地输入以下内容来运行`hello`应用程序：

```go
hello
```

安装应用程序是完全可选的。您不必安装程序来运行或构建它们。在开发时，您可以始终从当前工作目录构建和运行，但安装经常使用的已完成应用程序可能会更方便。

# 使用 go fmt 进行格式化

`go fmt`命令用于格式化源代码文件以符合 Go 格式标准。

这将确保缩进准确，没有过多的空格等。您可以一次格式化单个 Go 源代码文件或整个包。遵循 Go 编码标准并在文件上运行`go fmt`是一个好习惯，这样您就不会怀疑您的代码是否遵循了指南。在[`golang.org/doc/effective_go.html#formatting`](https://golang.org/doc/effective_go.html#formatting)上阅读更多关于格式化的内容。

# 运行 Go 示例

本书提供的示例都是独立的。每个示例都是一个完整的程序，可以运行。大多数示例都很简短，演示了一个特定的主题。虽然这些示例可以作为独立的程序使用，但其中一些可能有限的用途。它们旨在作为参考，并像烹饪书一样用于构建自己的项目。因为每个示例都是一个独立的主包，您可以使用`go build`命令获得可执行文件，并使用`go run`运行文件。以下是有关构建和运行程序的各种选项的更多详细信息。

# 构建单个 Go 文件

如果构建一个文件，它将生成一个以 Go 文件命名的可执行文件。运行以下命令：

```go
go build example.go
```

这将为您生成一个名为 example 的可执行文件，可以像这样执行：

```go
./example
```

# 运行单个 Go 文件

如果您只想运行文件而不生成可执行文件，您不必构建文件。`go run`选项允许您运行`.go`文件，而不会留下可执行文件。您仍然可以传递参数，就像它是一个常规可执行文件一样，如下所示：

```go
go run example.go arg1 arg2
```

# 构建多个 Go 文件

如果一个程序分成多个文件，您可以将它们全部传递给`build`命令。例如，如果您有一个`main.go`文件和一个包含额外函数的`utility.go`文件，您可以通过运行以下命令构建它们：

```go
go build main.go utility.go
```

如果您尝试单独构建`main.go`，它将无法找到`utility.go`中函数的引用。

# 构建文件夹（包）

如果一个包包含多个需要构建的 Go 文件，逐个传递每个文件给`build`命令是很麻烦的。如果在文件夹中不带参数运行`go build`，它将尝试构建目录中的所有`.go`文件。如果其中一个文件在顶部包含`package main`语句，它将生成一个以目录名称命名的可执行文件。如果您编写一个程序，可以编写一个不包含主文件，仅用作库以包含在其他项目中的包。

# 安装程序以供使用

安装程序类似于构建程序，但是，您运行的是`go install`而不是`go build`。您可以在目录中运行它，传递一个绝对目录路径，并传递一个相对于`$GOPATH`环境变量或直接在文件上的目录路径。一旦程序被安装，它将进入您的`$GOBIN`，您应该已经设置好了。您还应该将`$GOBIN`添加到您的`$PATH`中，这样无论您当前在哪个目录，都可以直接从命令行运行已安装的程序。安装是完全可选的，但对于某些程序来说很方便，特别是您想要保存或经常使用的程序。

# 总结

阅读完本章后，您应该对 Go 编程语言及其一些关键特性有一个基本的了解。您还应该在您的机器上安装了 Go 的版本，并设置了环境变量。如果您需要更多关于安装和测试您的环境的说明，请参阅 Go 文档[`golang.org/doc/install`](https://golang.org/doc/install)。

在下一章中，我们将更仔细地了解 Go 编程语言，学习设计、数据类型、关键字、特性、控制结构，以及如何获取帮助和查找文档。如果你已经熟悉 Go，这将是一个很好的复习，以加强你的基础知识。如果你是 Go 的新手，它将作为一个入门指南，为你准备本书的其余部分。


# 第二章：Go 编程语言

在深入研究使用 Go 进行安全性的更复杂示例之前，建立坚实的基础非常重要。本章概述了 Go 编程语言，以便您具备后续示例所需的知识。

本章不是 Go 编程语言的详尽论述，但将为您提供主要功能的扎实概述。本章的目标是为您提供必要的信息，以便在以前从未使用过 Go 的情况下理解和遵循源代码。如果您已经熟悉 Go，本章应该是对您已经知道的内容的快速简单回顾，但也许您会学到一些新的信息。

本章专门涵盖以下主题：

+   Go 语言规范

+   Go 游乐场

+   Go 之旅

+   关键字

+   关于源代码的注释

+   注释

+   类型

+   控制结构

+   延迟

+   包

+   类

+   Goroutines

+   获取帮助和文档

# Go 语言规范

整个 Go 语言规范可以在[`golang.org/ref/spec`](https://golang.org/ref/spec)上找到。本章中的大部分信息来自规范，因为这是语言的真正文档。这里的其他信息是短小的示例、提示、最佳实践和我在使用 Go 期间学到的其他内容。

# Go 游乐场

Go 游乐场是一个网站，您可以在其中编写和执行 Go 代码，而无需安装任何东西。在游乐场中，[`play.golang.org`](https://play.golang.org)，您可以测试代码片段以探索语言，并尝试理解语言的工作原理。它还允许您通过创建存储代码片段的唯一 URL 来分享您的片段。通过游乐场分享代码可能比纯文本片段更有帮助，因为它允许读者实际执行代码并调整源代码，以便在对其工作原理有任何疑问时进行实验：

！[](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/sec-go/img/d5514c8a-7253-4641-8b61-3e02ebcac15e.png)

上面的截图显示了在游乐场中运行的简单程序。顶部有按钮可以运行、格式化、添加导入语句和与他人共享代码。

# Go 之旅

Go 团队提供的另一个资源是*Go 之旅*。这个网站，[`tour.golang.org`](https://tour.golang.org)，建立在前一节提到的游乐场之上。这次旅行是我对这种语言的第一次介绍，当我完成它时，我感到有能力开始处理 Go 项目。它会逐步引导您了解语言，并提供工作代码示例，以便您可以运行和修改代码以熟悉语言。这是向新手介绍 Go 的实用方式。如果您根本没有使用过 Go，我鼓励您去看一看。

！[](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/sec-go/img/155646d8-315b-4b13-aa31-c7be08feb713.png)

上面的截图显示了游览的第一页。在右侧，您将看到一个嵌入式的小游乐场，其中包含左侧显示的短课程相关的代码示例。每节课都有一个简短的代码示例，您可以运行和调整。

# 关键字

为了强调 Go 的简单性，这里列出了其 25 个关键字的详细说明。如果您熟悉其他编程语言，您可能已经了解其中大部分。关键字根据其用途分组在一起进行检查。

**数据类型**：

| `var` | 这定义了一个新变量 |
| --- | --- |
| `const` | 这定义一个不变的常量值 |
| `type` | 这定义了一个新数据类型 |
| `struct` | 这定义了一个包含多个变量的新结构化数据类型 |
| `map` | 这定义了一个新的映射或哈希变量 |
| `interface` | 这定义了一个新接口 |

**函数**：

| `func` | 这定义了一个新函数 |
| --- | --- |
| `return` | 这退出一个函数，可选地返回值 |

**包**：

| `import`  | 这在当前包中导入外部包 |
| --- | --- |
| `package` | 这指定文件属于哪个包 |

**程序流**：

| `if` | 如果条件为真，则使用此分支执行 |
| --- | --- |
| `else` | 如果条件不成立，则使用此分支 |
| `goto` | 这用于直接跳转到标签；它很少使用，也不鼓励使用 |

**Switch 语句**：

| `switch` | 这用于基于条件进行分支 |
| --- | --- |
| `case` | 这定义了`switch`语句的条件 |
| `default` | 这定义了当没有匹配的情况时的默认执行 |
| `fallthrough` | 这用于继续执行下一个 case |

**迭代**：

| `for` | `for`循环可以像在 C 中一样使用，其中提供三个表达式：初始化程序、条件和增量器。在 Go 中，没有`while`循环，`for`关键字承担了`for`和`while`的角色。如果传递一个表达式，条件，`for`循环可以像`while`循环一样使用。 |
| --- | --- |
| `range` | `range`关键字与`for`循环一起用于迭代 map 或 slice。 |
| `continue` | `continue`关键字将跳过当前循环中剩余的任何执行，并直接跳转到下一个迭代。 |
| `break` | `break`关键字将立即完全退出`for`循环，跳过任何剩余的迭代。 |

**并发**：

| `go` | Goroutines 是内置到语言中的轻量级线程。您只需在函数调用前面加上`go`关键字，Go 就会在单独的线程中执行该函数调用。 |
| --- | --- |
| `chan` | 为了在线程之间通信，使用通道。通道用于发送和接收特定数据类型。它们默认是阻塞的。 |
| `select` | `select`语句允许通道以非阻塞方式使用。 |

**便利**：

| `defer` | `defer`关键字是一个相对独特的关键字，在其他语言中我以前没有遇到过。它允许您指定在周围函数返回时稍后调用的函数。当您想要确保当前函数结束时执行某种清理操作，但不确定何时或何地它可能返回时，它非常有用。一个常见的用例是延迟文件关闭。 |
| --- | --- |

# 关于源代码的注释

Go 源代码文件应该有`.go`扩展名。Go 文件的源代码以 UTF-8 Unicode 编码。这意味着您可以在代码中使用任何 Unicode 字符，比如在字符串中硬编码日语字符。

分号在行尾是可选的，通常省略。只有在分隔单行上的多个语句或表达式时才需要分号。

Go 确实有一个代码格式化标准，可以通过在源代码文件上运行`go fmt`来轻松遵守。应该遵循代码格式化，但不像 Python 那样严格由编译器执行确切的格式化以正确执行。

# 注释

注释遵循 C++风格，允许双斜杠和斜杠星号包装样式：

```go
// Line comment, everything after slashes ignored
/* General comment, can be in middle of line or span multiple lines */
```

# 类型

内置数据类型的命名相当直观。Go 带有一组具有不同位长度的整数和无符号整数类型。还有浮点数、布尔值和字符串，这应该不足为奇。

有一些类型，如符文，在其他语言中不常见。本节涵盖了所有不同的类型。

# 布尔

布尔类型表示真或假值。有些语言不提供`bool`类型，您必须使用整数或定义自己的枚举，但 Go 方便地预先声明了`bool`类型。`true`和`false`常量也是预定义的，并且以全小写形式使用。以下是创建布尔值的示例：

```go
var customFlag bool = false  
```

`bool`类型并不是 Go 独有的，但关于布尔类型的一个有趣的小知识是，它是唯一以一个人命名的类型。乔治·布尔生于 1815 年，逝世于 1864 年，写了《思维的法则》，在其中描述了布尔代数，这是所有数字逻辑的基础。`bool`类型在 Go 中非常简单，但其名称背后的历史非常丰富。

# 数字

主要的数字数据类型是整数和浮点数。Go 还提供了复数类型、字节类型和符文。以下是 Go 中可用的数字数据类型。

# 通用数字

这些通用类型可以在您不特别关心数字是 32 位还是 64 位时使用。将自动使用最大可用大小，但将与 32 位和 64 位处理器兼容。

+   `uint`：这是一个 32 位或 64 位的无符号整数

+   `int`：这是一个带有与`uint`相同大小的有符号整数

+   `uintptr`：这是一个无符号整数，用于存储指针值

# 特定数字

这些数字类型指定了位长度以及它是否具有符号位来确定正负值。位长度将确定最大范围。有符号整数的范围会减少一个位，因为最后一位保留给了符号。

# 无符号整数

在没有数字的情况下使用`uint`通常会选择系统的最大大小，通常为 64 位。您还可以指定这四种特定的`uint`大小之一：

+   `uint8`：无符号 8 位整数（0 至 255）

+   `uint16`：无符号 16 位整数（0 至 65535）

+   `uint32`：无符号 32 位整数（0 至 4294967295）

+   `uint64`：无符号 64 位整数（0 至 18446744073709551615）

# 有符号整数

与无符号整数一样，您可以单独使用`int`来选择最佳默认大小，或者指定这四种特定的`int`大小之一：

+   `int8`：8 位整数（-128 至 127）

+   `int16`：16 位整数（-32768 至 32767）

+   `int32`：32 位整数（-2147483648 至 2147483647）

+   `int64`：64 位整数（-9223372036854775808 至 9223372036854775807）

# 浮点数

浮点类型没有通用类型，必须是以下两种选项之一：

+   `float32`：IEEE-754 32 位浮点数

+   `float64`：IEEE-754 64 位浮点数

# 其他数字类型

Go 还为高级数学应用提供了复数类型，以及一些别名以方便使用：

+   `complex64`：具有`float32`实部和虚部的复数

+   `complex128`：具有`float64`实部和虚部的复数

+   `byte`：`uint8`的别名

+   `rune`：`int32`的别名

您可以以十进制、八进制或十六进制格式定义数字。十进制或十进制数字不需要前缀。八进制或八进制数字应以零为前缀。十六进制或十六进制数字应以零和 x 为前缀。

您可以在[`en.wikipedia.org/wiki/Octal`](https://en.wikipedia.org/wiki/Octal)上了解更多八进制数字系统，十进制数字在[`en.wikipedia.org/wiki/Decimal`](https://en.wikipedia.org/wiki/Decimal)，十六进制数字在[`en.wikipedia.org/wiki/Hexadecimal`](https://en.wikipedia.org/wiki/Hexadecimal)。

请注意，数字被存储为整数，它们之间没有区别，除了它们在源代码中的格式化方式。在处理二进制数据时，八进制和十六进制可能很有用。以下是如何定义整数的简短示例：

```go
package main

import "fmt"

func main() {
   // Decimal for 15
   number0 := 15

   // Octal for 15
   number1 := 017 

   // Hexadecimal for 15
   number2 := 0x0F

   fmt.Println(number0, number1, number2)
} 
```

# 字符串

Go 还提供了`string`类型以及一个`strings`包，其中包含一套有用的函数，如`Contains()`，`Join()`，`Replace()`，`Split()`，`Trim()`和`ToUpper()`。此外还有一个专门用于将各种数据类型转换为字符串的`strconv`包。您可以在[`golang.org/pkg/strings/`](https://golang.org/pkg/strings/)上阅读有关`strings`包的更多信息，以及在[`golang.org/pkg/strconv/`](https://golang.org/pkg/strconv/)上阅读有关`strconv`包的更多信息。

双引号用于字符串。单引号仅用于单个字符或符文，而不是字符串。可以使用长形式或使用声明和分配运算符的短形式来定义字符串。您还可以使用`` ` ``（反引号）符号，用于封装跨多行的字符串。以下是字符串用法的简短示例:

```go

package main
import "fmt"
func main() {
   // 长形式分配
   var myText = "test string 1"
   // 短形式分配
   myText2 := "test string 2"
   // 多行字符串
   myText3 := `long string
   spans multiple
   lines`
   fmt.Println(myText)
   fmt.Println(myText2)
   fmt.Println(myText3)
}

```

# 数组

数组由特定类型的序列化元素组成。可以为任何数据类型创建一个数组。数组的长度是不可变的，必须在声明时指定。数组很少直接使用，而是在下一节中介绍的切片类型中大多数使用。数组始终是一维的，但可以创建一个数组的数组来创建多维对象。

要创建一个包含`128`个字节的数组，可以使用以下语法：

```go

var myByteArray [128]byte

```

数组的各个元素可以通过基于`0`的数字索引进行访问。例如，要获取字节数组的第五个元素，语法如下：

```go

singleByte := myByteArray[4]

```

# 切片

切片使用数组作为基础数据类型。主要优点是切片可以调整大小，而数组不行。将切片视为对基础数组的查看窗口。**容量**指的是基础数组的大小，以及切片的最大可能长度。切片的**长度**指当前长度，可以调整大小。

使用`make()`函数创建切片。`make()`函数将创建指定类型、长度和容量的切片。在创建切片时，`make()`函数可以有两种方式。只有两个参数时，长度和容量相同。有三个参数时，可以指定一个比长度大的最大容量。以下是两种`make()`函数声明：

```go

make([]T, lengthAndCapacity)
make([]T, length, capacity)

```

可以创建具有容量和长度为`0`的`nil`切片。`nil`切片没有关联的基础数组。以下是演示如何创建和检查切片的简短示例程序：

```go

package main
import "fmt"
func main() {
   // 创建一个 nil 切片
   var mySlice []byte
   // 创建长度为 8，最大容量为 128 的字节切片
   mySlice = make([]byte, 8, 128)
   // 切片的最大容量
   fmt.Println("Capacity:", cap(mySlice))
   // 切片的当前长度
   fmt.Println("Length:", len(mySlice))
}

```

也可以使用内置`append()`函数向切片追加元素。

`Append`可以一次添加一个或多个元素。必要时，基础数组将调整大小。这意味着切片的最大容量可以增加。当一个切片增加其基础容量时，创建一个更大的基础数组时，将创建具有一些额外空间的数组。这意味着如果超过一个切片的容量，可能会将数组大小增加四倍。这样做是为了使基础数组有空间增长，以减少重新调整大小基础数组的次数，这可能需要移动内存以容纳更大的数组。每次只需添加一个元素就重新调整大小数组可能会很昂贵。切片机制将自动确定最佳的调整大小。

以下代码示例提供了使用切片的各种示例：

```go

package main
import "fmt"
func main() {
   var mySlice []int // nil slice
   // 在 nil 切片上可以使用附加功能。
   // 由于 nil 切片的容量为零，并且具有
   // 没有基础数组，它将创建一个。
   mySlice = append(mySlice, 1, 2, 3, 4, 5)
   // 可以从切片中访问单个元素
   // 就像使用方括号运算符一样，就像数组一样。
   firstElement := mySlice[0]
   fmt.Println("First element:", firstElement)
   // 仅获取第二个和第三个元素，请使用：
   subset := mySlice[1:4]
   fmt.Println(subset)
   // 要获取切片的全部内容，除了
   // 第一个元素，使用：
   subset = mySlice[1:]
   fmt.Println(subset)
   // 要获取切片的全部内容，除了
   // 最后一个元素，使用：
   subset = mySlice[0 : len(mySlice)-1]
   fmt.Println(subset)
   // 要复制切片，请使用 copy()函数。
   // 如果您使用等号将一个切片分配给另一个切片，
   // 切片将指向相同的内存位置，
   // 更改一个会更改两个切片。
   slice1 := []int{1, 2, 3, 4}
   slice2 := make([]int, 4)
   // 在内存中创建一个唯一的副本
   copy(slice2, slice1)
   // 更改一个不应影响另一个
   slice2[3] = 99
   fmt.Println(slice1)
   fmt.Println(slice2)
}

```

# 结构体

在 Go 中，结构体或数据结构是一组变量。变量可以是不同类型的。我们将看一个创建自定义结构体类型的示例。

Go 使用基于大小写的作用域来声明变量为`public`或`private`。大写的变量和方法是公开的，可以从其他包中访问。小写的值是私有的，只能在同一包中访问。

以下示例创建了一个名为`Person`的简单结构体，以及一个名为`Hacker`的结构体。`Hacker`类型在其中嵌入了一个`Person`类型。然后分别创建了每种类型的实例，并将有关它们的信息打印到标准输出：

```go

package main
import "fmt"
func main() {
   // 定义一个 Person 类型。两个字段都是公共的
   type Person struct {
      Name string
      Age  int
   }
   // 创建一个 Person 对象并存储指向它的指针
   nanodano := &Person{Name: "NanoDano", Age: 99}
   fmt.Println(nanodano)
   // 结构也可以嵌入在其他结构中。
   // 这通过简单地存储
   // 另一个变量作为数据类型。
   type Hacker struct {
      Person           Person
      FavoriteLanguage string
   }
   fmt.Println(nanodano)
   hacker := &Hacker{
      Person:           *nanodano,
      FavoriteLanguage: "Go",
   }
   fmt.Println(hacker)
   fmt.Println(hacker.Person.Name)
   fmt.Println(hacker)
}

```

你可以通过将它们的名称以小写字母开头来创建*私有*变量。我用引号是因为私有变量与其他语言中的工作方式略有不同。隐私工作在包级别而不是*类*或类型级别。

# 指针

Go 提供了一个指针类型，用于存储特定类型数据的内存位置。指针可以被用来通过引用传递一个结构体给函数，而不需要创建副本。这也允许函数就地修改对象。

Go 不允许指针算术。指针被认为是*安全*的，因为 Go 甚至不定义指针类型上的加法运算符。它们只能用于引用现有对象。

这个示例演示了基本的指针用法。它首先创建一个整数，然后创建一个指向该整数的指针。然后打印指针的数据类型，指针中存储的地址，以及被指向的数据的值：

```go

package main
import (
   "fmt"
   "reflect"
)
func main() {
   myInt := 42
   intPointer := &myInt
   fmt.Println(reflect.TypeOf(intPointer))
   fmt.Println(intPointer)
   fmt.Println(*intPointer)
}

```

# 函数

使用`func`关键字定义函数。函数可以有多个参数。所有参数都是位置参数，没有命名参数。Go 支持可变参数，允许有未知数量的参数。在 Go 中，函数是一等公民，并且可以匿名使用并作为变量返回。Go 还支持从函数返回多个值。下划线可以用于忽略返回变量。

所有这些示例都在以下代码来源中演示：

```go

package main
import "fmt"
// 没有参数的函数
func sayHello() {
   fmt.Println("Hello.")
}
// 带有一个参数的函数
func greet(name string) {
   fmt.Printf("Hello, %s.\n", name)
}
// 具有相同类型的多个参数的函数
func greetCustom(name, greeting string) {
   fmt.Printf("%s, %s.\n", greeting, name)
}
// 变参参数，无限参数
func addAll(numbers ...int) int {
   sum := 0
   for _, number := range numbers {
      sum += number
   }
   return sum
}
// 具有多个返回值的函数
// 由括号封装的多个值
func checkStatus() (int, error) {
   return 200, nil
}
// 将类型定义为函数，以便可以使用
// 作为返回类型
type greeterFunc func(string)
// 生成并返回一个函数
func generateGreetFunc(greeting string) greeterFunc {
   return func(name string) {
      fmt.Printf("%s, %s.\n", greeting, name)
   }
}
func main() {
   sayHello()
   greet("NanoDano")
   greetCustom("NanoDano", "Hi")
   fmt.Println(addAll(4, 5, 2, 3, 9))
   russianGreet := generateGreetFunc("Привет")
   russianGreet("NanoDano")
   var stringToIntMap map[string]int
   fmt.Println(statusCode, err)
}

```

# 接口

接口是一种特殊类型，它定义了一系列函数签名。你可以把接口看作是在说，“一个类型必须实现函数 X 和函数 Y 来满足这个接口。” 如果你创建了任何类型并实现了满足接口所需的函数，那么你的类型可以在期望接口的任何地方使用。你不必指定你正在尝试满足一个接口，编译器将确定它是否满足要求。

你可以为你的自定义类型添加任意多的其他函数。接口定义了所需的函数，但这并不意味着你的类型仅限于实现这些函数。

最常用的接口是`error`接口。`error`接口只需要实现一个函数，即一个名为`Error()`的函数，该函数返回一个带有错误消息的字符串。以下是接口定义：

```go
type error interface {
   Error() string
} 

```

这使得你很容易实现自己的错误接口。这个示例创建了一个`customError`类型，然后实现了满足接口所需的`Error()`函数。然后，创建了一个示例函数，该函数返回自定义错误：

```go

package main

import "fmt"

// Define a custom type that will
// be used to satisfy the error interface
type customError struct {
   Message string
}

// Satisfy the error interface
// by implementing the Error() function
// which returns a string
func (e *customError) Error() string {
   return e.Message
}

// Sample function to demonstrate
// how to use the custom error
func testFunction() error {
   if true != false { // Mimic an error condition
      return &customError{"Something went wrong."}
   }
   return nil
}

func main() {
   err := testFunction()
   if err != nil {
      fmt.Println(err)
   }
} 
```

其他经常使用的接口是 `Reader` 和 `Writer` 接口。每个接口只需要实现一个函数以满足接口要求。这里的一个重大好处是你可以创建自己的自定义类型，以某种任意的方式读取和写入数据。接口不关心实现细节。接口不会在乎你是在读写硬盘、网络连接、内存中的存储还是 `/dev/null`。只要你实现了所需的函数签名，你就可以在任何使用接口的地方使用你的类型。下面是 `Reader` 和 `Writer` 接口的定义：

```go

type Reader interface {
   Read(p []byte) (n int, err error)
} 
 
type Writer interface {
   Write(p []byte) (n int, err error)
} 

```

# Map

Map 是一个存储键值对的哈希表或字典。键和值可以是任何数据类型，包括映射本身，从而创建多个维度。

顺序不受保证。你可以多次迭代一个映射，并且可能会不同。此外，映射不是并发安全的。如果必须在线程之间共享映射，请使用互斥锁。

这里是一些示例映射用法：

```go

package main

import (
   "fmt"
   "reflect"
)

func main() {
   // Nil maps will cause runtime panic if used 
   // without being initialized with make()
   var intToStringMap map[int]string
   var stringToIntMap map[string]int
   fmt.Println(reflect.TypeOf(intToStringMap))
   fmt.Println(reflect.TypeOf(stringToIntMap))

   // Initialize a map using make
   map1 := make(map[string]string)
   map1["Key Example"] = "Value Example"
   map1["Red"] = "FF0000"
   fmt.Println(map1)

   // Initialize a map with literal values
   map2 := map[int]bool{
      4:  false,
      6:  false,
      42: true,
   }

   // Access individual elements using the key
   fmt.Println(map1["Red"])
   fmt.Println(map2[42])
   // Use range to iterate through maps
   for key, value := range map2 {
      fmt.Printf("%d: %t\n", key, value)
   }

} 
```

# Channel

通道用于线程之间通信。通道是**先进先出**（**FIFO**）队列。你可以将对象推送到队列并异步从前端拉取。每个通道只能支持一个数据类型。通道默认是阻塞的，但可以通过 `select` 语句使其成为非阻塞。像切片和映射一样，通道必须在使用之前用 `make()` 函数初始化。

在 Go 中的格言是 *不要通过共享内存来通信；而是通过通信来共享内存*。在[`blog.golang.org/share-memory-by-communicating`](https://blog.golang.org/share-memory-by-communicating)上阅读更多关于这一哲学的内容。

下面是一个演示基本通道使用的示例程序：

```go

package main

import (
   "log"
   "time"
)

// Do some processing that takes a long time
// in a separate thread and signal when done
func process(doneChannel chan bool) {
   time.Sleep(time.Second * 3)
   doneChannel <- true
}

func main() {
   // Each channel can support one data type.
   // Can also use custom types
   var doneChannel chan bool

   // Channels are nil until initialized with make
   doneChannel = make(chan bool)

   // Kick off a lengthy process that will
   // signal when complete
   go process(doneChannel)

   // Get the first bool available in the channel
   // This is a blocking operation so execution
   // will not progress until value is received
   tempBool := <-doneChannel
   log.Println(tempBool)
   // or to simply ignore the value but still wait
   // <-doneChannel

   // Start another process thread to run in background
   // and signal when done
   go process(doneChannel)

   // Make channel non-blocking with select statement
   // This gives you the ability to continue executing
   // even if no message is waiting in the channel
   var readyToExit = false
   for !readyToExit {
      select {
      case done := <-doneChannel:
         log.Println("Done message received.", done)
         readyToExit = true
      default:
         log.Println("No done signal yet. Waiting.")
         time.Sleep(time.Millisecond * 500)
      }
   }
} 
```

# 控制结构

控制结构用于控制程序执行的流程。最常见的形式是 `if` 语句、`for` 循环和 `switch` 语句。Go 也支持 `goto` 语句，但应保留用于极端性能情况，不应经常使用。让我们简要地看一下这些以了解语法。

# if

`if` 语句有 `if`、`else if` 和 `else` 子句，就像大多数其他语言一样。 Go 的一个有趣特性是能够在条件之前放置语句，创建在 `if` 语句完成后被丢弃的临时变量。

这个示例演示了使用 `if` 语句的各种方式：

```go

package main

import (
   "fmt"
   "math/rand"
)

func main() {
   x := rand.Int()

   if x < 100 {
      fmt.Println("x is less than 100.")
   }

   if x < 1000 {
      fmt.Println("x is less than 1000.")
   } else if x < 10000 {
      fmt.Println("x is less than 10,000.")
   } else {
      fmt.Println("x is greater than 10,000")
   }

   fmt.Println("x:", x)

   // You can put a statement before the condition 
   // The variable scope of n is limited
   if n := rand.Int(); n > 1000 {
      fmt.Println("n is greater than 1000.")
      fmt.Println("n:", n)
   } else {
      fmt.Println("n is not greater than 1000.")
      fmt.Println("n:", n)
   }
   // n is no longer available past the if statement
```

# for

`for` 循环有三个组件，可以像在 C 或 Java 中一样使用 `for` 循环。Go 没有 `while` 循环，因为当与单个条件一起使用时，`for` 循环起到相同的作用。请参考以下示例以获得更多的清晰度：

```go

package main

import (
   "fmt"
)

func main() {
   // Basic for loop
   for i := 0; i < 3; i++ {
      fmt.Println("i:", i)
   }

   // For used as a while loop
   n := 5
   for n < 10 {
      fmt.Println(n)
      n++
   }
} 
```

# range

`range`关键字用于遍历切片、映射或其他数据结构。`range`关键字与`for`循环结合使用，对可迭代的数据结构进行操作。`range`关键字返回键和值变量。以下是使用`range`关键字的一些基本示例：

```go

package main

import "fmt"

func main() {
   intSlice := []int{2, 4, 6, 8}
   for key, value := range intSlice {
      fmt.Println(key, value)
   }

   myMap := map[string]string{
      "d": "Donut",
      "o": "Operator",
   }

   // Iterate over a map
   for key, value := range myMap {
      fmt.Println(key, value)
   }

   // Iterate but only utilize keys
   for key := range myMap {
      fmt.Println(key)
   }

   // Use underscore to ignore keys
   for _, value := range myMap {
      fmt.Println(value)
   }
} 
```

# switch、case、fallthrough 和 default

`switch`语句允许您根据变量的状态分支执行。它类似于 C 和其他语言中的`switch`语句。

默认情况下没有`fallthrough`。这意味着一旦到达一个情况的末尾，代码就会完全退出`switch`语句，除非提供了显式的`fallthrough`命令。如果没有匹配到任何情况，则可以提供一个`default`情况。

您可以在要切换的变量前放置一个语句，例如`if`语句。这会创建一个作用域限于`switch`语句的变量。

此示例演示了两个`switch`语句。第一个使用硬编码的值，并包含一个`default`情况。第二个`switch`语句使用了一种允许在第一行中包含语句的替代语法：

```go

package main

import (
   "fmt"
   "math/rand"
)

func main() {
   x := 42

   switch x {
   case 25:
      fmt.Println("X is 25")
   case 42:
      fmt.Println("X is the magical 42")
      // Fallthrough will continue to next case
      fallthrough
   case 100:
      fmt.Println("X is 100")
   case 1000:
      fmt.Println("X is 1000")
   default:
      fmt.Println("X is something else.")
   }

   // Like the if statement a statement
   // can be put in front of the switched variable
   switch r := rand.Int(); r {
   case r % 2:
      fmt.Println("Random number r is even.")
   default:
      fmt.Println("Random number r is odd.")
   }
   // r is no longer available after the switch statement
} 
```

# 跳转

Go 语言确实有`goto`语句，但很少使用。使用一个名称和一个冒号创建一个标签，然后使用`goto`关键字*跳转*到它。这是一个基本示例：

```go

package main

import "fmt"

func main() {

   goto customLabel

   // Will never get executed because
   // the goto statement will jump right
   // past this line
   fmt.Println("Hello")

   customLabel:
   fmt.Println("World")
} 
```

# 延迟

通过延迟一个函数，它会在当前函数退出时运行。这是一种方便的方式，可以确保一个函数在退出之前被执行，这对于清理或关闭文件很有用。这很方便，因为一个延迟的函数会在周围函数的任何退出处被执行，如果有多个返回位置的话。

常见用例是延迟调用关闭文件或数据库连接。在打开文件后，您可以延迟调用关闭。这将确保文件在函数退出时关闭，即使有多个返回语句，您也不能确定当前函数何时何地退出。

此示例演示了`defer`关键字的一个简单用例。它创建一个文件，然后延迟调用`file.Close()`：

```go

package main

import (
   "log"
   "os"
)

func main() {

   file, err := os.Create("test.txt")
   if err != nil {
      log.Fatal("Error creating file.")
   }
   defer file.Close()
   // It is important to defer after checking the errors.
   // You can't call Close() on a nil object
   // if the open failed.

   // ...perform some other actions here...

   // file.Close() will be called before final exit
} 
```

一定要正确检查和处理错误。如果使用空指针，则`defer`调用会导致恐慌。

还要明白延迟函数是在周围函数退出时运行的。如果在`for`循环中放置一个`defer`调用，它将不会在每个`for`循环迭代结束时被调用。

# 包

包只是目录。每个目录都是一个包。创建子目录会创建一个新包。没有子包会导致一个平坦的层次结构。子目录仅用于组织代码。

包应该存储在您的`$GOPATH`变量的`src`文件夹中。

包名应该与文件夹名匹配，或者命名为`main`。一个`main`包意味着它不打算被导入到另一个应用程序中，而是打算编译并作为程序运行。使用`import`关键字导入包。

你可以单独导入包：

```go

import "fmt"

```

或者，你可以通过用括号包裹多个包来一次性导入多个包：

```go

import (
   "fmt"
   "log"
) 
```

# 类

从技术上讲，Go 并没有类，但有几个微妙的区别使其不被称为面向对象的语言。概念上，我认为它是一种面向对象的编程语言，尽管仅支持最基本的面向对象语言特性。它不具备许多人们对面向对象编程所熟悉的所有特性，比如继承和多态性，而是用其他特性如嵌入类型和接口来替代。也许你可以把它称为一个*微类*系统，因为它是一个最简化实现，没有额外的特性或负担，这取决于你的角度。

本书中，术语*对象*和*类*可能会被用来说明一个概念，使用熟悉的术语，但请注意这些在 Go 中并不是正式术语。类型定义与操作该类型的函数结合起来类似于类，而对象是类型的一个实例。

# 继承

Go 中没有继承，但可以嵌入类型。这里有一个`Person`和`Doctor`类型的示例，`Doctor`类型嵌入了`Person`类型。与直接继承`Person`的行为不同，它将`Person`对象作为变量存储，从而带来了其预期的`Person`方法和属性：  

```go

package main

import (
   "fmt"
   "reflect"
)

type Person struct {
   Name string
   Age  int
} 

type Doctor struct {
   Person         Person
   Specialization string
}

func main() {
   nanodano := Person{
      Name: "NanoDano",
      Age:  99,
   } 

   drDano := Doctor{
      Person:         nanodano,
      Specialization: "Hacking",
   }

   fmt.Println(reflect.TypeOf(nanodano))
   fmt.Println(nanodano)
   fmt.Println(reflect.TypeOf(drDano))
   fmt.Println(drDano)
} 
```

# 多态性

Go 中没有多态性，但可以使用接口创建可以被多个类型使用的通用抽象。接口定义了一个或多个必须满足以兼容接口的方法声明。接口在本章的前面已经介绍过。

# 构造函数

Go 中没有构造函数，但有类似于初始化对象的工厂函数`New()`。你只需创建一个名为`New()`的函数，返回你的数据类型。下面是一个示例：

```go

package main

import "fmt"

type Person struct {
   Name string
}

func NewPerson() Person {
   return Person{
      Name: "Anonymous",
   }
}

func main() {
   p := NewPerson()
   fmt.Println(p)
} 
```

Go 中没有析构函数，因为一切都是由垃圾回收来处理，你不需要手动销毁对象。通过延迟（defer）一个函数调用来在当前函数结束时执行一些清理操作是最接近的方法。

# 方法

方法是属于特定类型的函数，使用点标记法来调用，例如：

```go

myObject.myMethod()

```

点符号标记在 C++和其他面向对象的语言中被广泛使用。 点符号标记和类系统源自于在 C 中使用的一个常见模式。 这个常见模式是定义一组函数，所有这些函数都操作一个特定的数据类型。 所有相关的函数都有相同的第一个参数，即要操作的数据。 由于这是一个如此常见的模式，Go 将其内置到语言中。 在 Go 函数定义中，不是将要操作的对象作为第一个参数传递，而是有一个特殊的位置来指定接收器。 接收器在函数名称之前的一对括号之间指定。 下一个示例演示了如何使用函数接收器。

与其编写一组大型函数，所有这些函数都将指针作为它们的第一个参数，不如编写具有特殊*接收器*的函数。 接收器可以是类型或类型的指针：

```go
package main

import "fmt"

type Person struct {
   Name string
}

// Person function receiver
func (p Person) PrintInfo() {
   fmt.Printf("Name: %s\n", p.Name)
}

// Person pointer receiver
// If you did not use the pointer receivers
// it would not modify the person object
// Try removing the asterisk here and seeing how the
// program changes behavior
func (p *Person) ChangeName(newName string) {
   p.Name = newName
}

func main() {
   nanodano := Person{Name: "NanoDano"}
   nanodano.PrintInfo()
   nanodano.ChangeName("Just Dano")
   nanodano.PrintInfo()
} 
```

在 Go 中，您不会将所有变量和方法封装在一个整体的大括号对中。 您定义一个类型，然后定义操作该类型的方法。 这使您可以在一个地方定义所有的结构体和数据类型，并在包的其他地方定义方法。 您还可以选择在一起定义类型和方法。 这非常简单直接，创建了状态（数据）和逻辑之间稍微清晰的区别。

# 运算符重载

Go 中没有运算符重载，因此您不能使用`+`号将两个结构体相加，但是您可以轻松地在类型上定义一个`Add()`函数，然后调用类似`dataSet1.Add(dataSet2)`的函数。 通过将语言中的操作符重载省略掉，我们可以放心地使用这些操作符，而不必担心由于在代码中的其他地方重载操作符行为而导致的意外行为。

# Goroutines

Goroutines 是内置到语言中的轻量级线程。 您只需在函数调用前加上`go`这个词，就可以让函数在一个线程中执行。 本书中还可以将 goroutines 称为线程。

Go 确实提供了互斥锁，但在大多数情况下可以避免使用，并且本书不会涵盖它们。 您可以在[`golang.org/pkg/sync/`](https://golang.org/pkg/sync/)上阅读有关互斥锁的更多信息。 通道应该用于在线程之间共享数据和通信。 本章前面已经介绍了通道。

注意，`log`包是可以并发安全使用的，但`fmt`包不是。 下面是使用 goroutines 的简短示例：

```go

package main

import (
   "log"
   "time"
)

func countDown() {
   for i := 5; i >= 0; i-- {
      log.Println(i)
      time.Sleep(time.Millisecond * 500)
   }
}

func main() {
   // Kick off a thread
   go countDown()

   // Since functions are first-class
   // you can write an anonymous function
   // for a goroutine
   go func() {
      time.Sleep(time.Second * 2)
      log.Println("Delayed greetings!")
   }()

   // Use channels to signal when complete
   // Or in this case just wait
   time.Sleep(time.Second * 4)
} 
```

# 获取帮助和文档

Go 同时具有在线和离线帮助文档。 离线文档是 Go 内置的，与在线托管的文档相同。 接下来的几节将引导您访问这两种形式的文档。

# 在线 Go 文档

在线文档可在[`golang.org/`](https://golang.org/) 上找到，其中包含所有正式文档、规范和帮助文件。语言文档专门位于[`golang.org/doc/`](https://golang.org/doc/)，标准库信息位于[`golang.org/pkg/`](https://golang.org/pkg/)。

# 离线 Go 文档

Go 还附带了离线文档，使用`godoc`命令行工具即可。您可以在命令行上使用它，或者让它运行一个 Web 服务器，在其中提供与[`golang.org/`](https://golang.org/) 相同的网站。将完整的网站文档本地可用是非常方便的。以下是几个示例，用于获取`fmt`包的文档。将`fmt`替换为您感兴趣的任何包：


```go

# 获取 fmt 包信息
godoc fmt
# 获取 fmt 包的源代码
godoc -src fmt
# 获取特定函数信息
godoc fmt Printf
# 获取函数的源代码
godoc -src fmt Printf
# 运行 HTTP 服务器以查看 HTML 文档
godoc -http = localhost：9999

```

HTTP 选项提供与[`golang.org/`](https://golang.org/)上可用的相同文档。

# 摘要

阅读完本章后，您应该对 Go 基础有基本的了解，例如关键字是什么，它们的作用是什么，以及有哪些基本数据类型可用。您还应该可以轻松创建函数和自定义数据类型。

目标不是记住所有先前的信息，而是了解语言中提供了哪些工具。如有必要，使用本章作为参考。您可以在[`golang.org/ref/spec`](https://golang.org/ref/spec)找到有关 Go 语言规范的更多信息。

在下一章中，我们将讨论在 Go 中处理文件的工作。我们将涵盖基础知识，如获取文件信息，查看文件是否存在，截断文件，检查权限以及创建新文件。我们还将涵盖读取器和写入器接口，以及多种读取和写入数据的方法。除此之外，我们还将涵盖诸如打包到 ZIP 或 TAR 文件以及使用 GZIP 压缩文件等内容。


# 第三章：处理文件

Unix 和 Linux 系统的一个显著特点是将所有内容都视为文件。进程、文件、目录、套接字、设备和管道都被视为文件。鉴于操作系统的这一基本特性，学习如何操作文件是一项关键技能。本章提供了几个不同方式操作文件的示例。

首先，我们将看一下基础知识，即创建、截断、删除、打开、关闭、重命名和移动文件。我们还将看一下如何获取有关文件的详细属性，例如权限和所有权、大小和符号链接信息。

本章的一个专门部分是关于从文件中读取和写入的不同方式。有多个包含有用函数的包；此外，读取器和写入器接口可以实现许多不同的选项，例如缓冲读取器和写入器，直接读取和写入，扫描器，以及用于快速操作的辅助函数。

此外，还提供了用于归档和解档、压缩和解压缩、创建临时文件和目录以及通过 HTTP 下载文件的示例。

具体来说，本章将涵盖以下主题：

+   创建空文件和截断文件

+   获取详细的文件信息

+   重命名、移动和删除文件

+   操作权限、所有权和时间戳

+   符号链接

+   多种读写文件的方式

+   归档

+   压缩

+   临时文件和目录

+   通过 HTTP 下载文件

# 文件基础知识

因为文件是计算生态系统中不可或缺的一部分，了解 Go 中处理文件的选项至关重要。本节涵盖了一些基本操作，如打开、关闭、创建和删除文件。此外，它还涵盖了重命名和移动文件，查看文件是否存在，修改权限、所有权、时间戳以及处理符号链接。这些示例中大多数使用了一个硬编码的文件名`test.txt`。如果要操作不同的文件，请更改此文件名。

# 创建空文件

Linux 中常用的一个工具是**touch**程序。当您需要快速创建具有特定名称的空文件时，它经常被使用。以下示例复制了**touch**的一个常见用例，即创建一个空文件。

创建空文件的用途有限，但让我们考虑一个例子。假设有一个服务将日志写入一组旋转的文件中。每天都会创建一个带有当前日期的新文件，并将当天的日志写入该文件。开发人员可能会聪明地对日志文件设置非常严格的权限，以便只有管理员可以读取它们。但是，如果他们在目录上留下了宽松的权限会怎么样？如果您创建了一个带有下一天日期的空文件会发生什么？服务可能只会在不存在日志文件时创建新的日志文件，但如果存在一个文件，它将在不检查权限的情况下使用它。您可以利用这一点，创建一个您有读取权限的空文件。该文件应该以服务命名日志文件的方式命名。例如，如果服务使用以下格式记录日志：`logs-2018-01-30.txt`，您可以创建一个名为`logs-2018-01-31.txt`的空文件，第二天，服务将写入该文件，因为它已经存在，而您将具有读取权限，而不是服务如果没有文件存在则创建一个具有仅根权限的新文件。

以下是此示例的代码实现：

```go
package main 

import ( 
   "log" 
   "os" 
) 

func main() { 
   newFile, err := os.Create("test.txt") 
   if err != nil { 
      log.Fatal(err) 
   } 
   log.Println(newFile) 
   newFile.Close() 
} 
```

# 截断文件

截断文件是指将文件修剪到最大长度。截断通常用于完全删除文件的所有内容，但也可以用于将文件限制为特定的最大大小。`os.Truncate()`的一个显着特点是，如果文件小于指定的截断限制，它将实际增加文件的长度。它将用空字节填充任何空白空间。

截断文件比创建空文件有更多的实际用途。当日志文件变得太大时，可以截断它们以节省磁盘空间。如果您正在攻击，可能希望截断`.bash_history`和其他日志文件以掩盖您的踪迹。恶意行为者可能仅仅为了破坏数据而截断文件。

```go
package main 

import ( 
   "log" 
   "os" 
) 

func main() { 
   // Truncate a file to 100 bytes. If file 
   // is less than 100 bytes the original contents will remain 
   // at the beginning, and the rest of the space is 
   // filled will null bytes. If it is over 100 bytes, 
   // Everything past 100 bytes will be lost. Either way 
   // we will end up with exactly 100 bytes. 
   // Pass in 0 to truncate to a completely empty file 

   err := os.Truncate("test.txt", 100) 
   if err != nil { 
      log.Fatal(err) 
   } 
} 
```

# 获取文件信息

以下示例将打印有关文件的所有可用元数据。它包括显而易见的属性，即名称、大小、权限、上次修改时间以及它是否是目录。它包含的最后一个数据片段是`FileInfo.Sys()`接口。这包含有关文件底层来源的信息，最常见的是硬盘上的文件系统：

```go
package main 

import ( 
   "fmt" 
   "log" 
   "os" 
) 

func main() { 
   // Stat returns file info. It will return 
   // an error if there is no file. 
   fileInfo, err := os.Stat("test.txt") 
   if err != nil { 
      log.Fatal(err) 
   } 
   fmt.Println("File name:", fileInfo.Name()) 
   fmt.Println("Size in bytes:", fileInfo.Size()) 
   fmt.Println("Permissions:", fileInfo.Mode()) 
   fmt.Println("Last modified:", fileInfo.ModTime()) 
   fmt.Println("Is Directory: ", fileInfo.IsDir()) 
   fmt.Printf("System interface type: %T\n", fileInfo.Sys()) 
   fmt.Printf("System info: %+v\n\n", fileInfo.Sys()) 
} 
```

# 重命名文件

标准库提供了一个方便的函数来移动文件。重命名和移动是同义词；如果要将文件从一个目录移动到另一个目录，请使用`os.Rename()`函数，如下面的代码块所示：

```go
package main 

import ( 
   "log" 
   "os" 
) 

func main() { 
   originalPath := "test.txt" 
   newPath := "test2.txt" 
   err := os.Rename(originalPath, newPath) 
   if err != nil { 
      log.Fatal(err) 
   } 
} 
```

# 删除文件

以下示例很简单，演示了如何删除文件。标准包提供了`os.Remove()`，它需要一个文件路径：

```go
package main 

import ( 
   "log" 
   "os" 
) 

func main() { 
   err := os.Remove("test.txt") 
   if err != nil { 
      log.Fatal(err) 
   } 
} 
```

# 打开和关闭文件

在打开文件时，有几个选项。当调用`os.Open()`时，它只需要一个文件名，并提供一个只读文件。另一个选项是使用`os.OpenFile()`，它需要更多的选项。您可以指定是否要只读或只写文件。您还可以选择在打开时读取和写入、追加、如果不存在则创建，或者截断。将所需的选项与逻辑或运算符结合。通过在文件对象上调用`Close()`来关闭文件。您可以显式关闭文件，也可以推迟调用。有关`defer`关键字的更多详细信息，请参阅第二章，*Go 编程语言*。以下示例不使用`defer`关键字选项，但后续示例将使用：

```go
package main 

import ( 
   "log" 
   "os" 
) 

func main() { 
   // Simple read only open. We will cover actually reading 
   // and writing to files in examples further down the page 
   file, err := os.Open("test.txt") 
   if err != nil { 
      log.Fatal(err) 
   }  
   file.Close() 

   // OpenFile with more options. Last param is the permission mode 
   // Second param is the attributes when opening 
   file, err = os.OpenFile("test.txt", os.O_APPEND, 0666) 
   if err != nil { 
      log.Fatal(err) 
   } 
   file.Close() 

   // Use these attributes individually or combined 
   // with an OR for second arg of OpenFile() 
   // e.g. os.O_CREATE|os.O_APPEND 
   // or os.O_CREATE|os.O_TRUNC|os.O_WRONLY 

   // os.O_RDONLY // Read only 
   // os.O_WRONLY // Write only 
   // os.O_RDWR // Read and write 
   // os.O_APPEND // Append to end of file 
   // os.O_CREATE // Create is none exist 
   // os.O_TRUNC // Truncate file when opening 
} 
```

# 检查文件是否存在

检查文件是否存在是一个两步过程。首先，必须在文件上调用`os.Stat()`以获取`FileInfo`。如果文件不存在，则不会返回`FileInfo`结构，而是返回一个错误。`os.Stat()`可能返回多个错误，因此必须检查错误类型。标准库提供了一个名为`os.IsNotExist()`的函数，它将检查错误，以查看是否是因为文件不存在而引起的。

如果文件不存在，以下示例将调用`log.Fatal()`，但您可以优雅地处理错误，并在需要时继续而不退出：

```go
package main 

import ( 
   "log" 
   "os" 
) 

func main() { 
   // Stat returns file info. It will return 
   // an error if there is no file. 
   fileInfo, err := os.Stat("test.txt") 
   if err != nil { 
      if os.IsNotExist(err) { 
         log.Fatal("File does not exist.") 
      } 
   } 
   log.Println("File does exist. File information:") 
   log.Println(fileInfo) 
} 
```

# 检查读取和写入权限

与前面的示例类似，通过检查错误使用名为`os.IsPermission()`的函数来检查读取和写入权限。如果错误是由于权限问题引起的，该函数将返回 true，如下例所示：

```go
package main 

import ( 
   "log" 
   "os" 
) 

func main() { 
   // Test write permissions. It is possible the file 
   // does not exist and that will return a different 
   // error that can be checked with os.IsNotExist(err) 
   file, err := os.OpenFile("test.txt", os.O_WRONLY, 0666) 
   if err != nil { 
      if os.IsPermission(err) { 
         log.Println("Error: Write permission denied.") 
      } 
   } 
   file.Close() 

   // Test read permissions 
   file, err = os.OpenFile("test.txt", os.O_RDONLY, 0666) 
   if err != nil { 
      if os.IsPermission(err) { 
         log.Println("Error: Read permission denied.") 
      } 
   } 
   file.Close()
} 
```

# 更改权限、所有权和时间戳

如果您拥有文件或有相应的权限，可以更改所有权、时间戳和权限。标准库提供了一组函数。它们在这里给出：

+   `os.Chmod()`

+   `os.Chown()`

+   `os.Chtimes()`

以下示例演示了如何使用这些函数来更改文件的元数据。

```go
package main 

import ( 
   "log" 
   "os" 
   "time" 
) 

func main() { 
   // Change permissions using Linux style 
   err := os.Chmod("test.txt", 0777) 
   if err != nil { 
      log.Println(err) 
   } 

   // Change ownership 
   err = os.Chown("test.txt", os.Getuid(), os.Getgid()) 
   if err != nil { 
      log.Println(err) 
   } 

   // Change timestamps 
   twoDaysFromNow := time.Now().Add(48 * time.Hour) 
   lastAccessTime := twoDaysFromNow 
   lastModifyTime := twoDaysFromNow 
   err = os.Chtimes("test.txt", lastAccessTime, lastModifyTime) 
   if err != nil { 
      log.Println(err) 
   } 
} 
```

# 硬链接和符号链接

典型的文件只是硬盘上的一个指针，称为 inode。硬链接会创建一个指向相同位置的新指针。只有在删除所有指向文件的链接后，文件才会从磁盘中删除。硬链接只能在相同的文件系统上工作。硬链接是您可能认为是“正常”链接的东西。

符号链接或软链接有点不同，它不直接指向磁盘上的位置。符号链接只通过名称引用其他文件。它们可以指向不同文件系统上的文件。但是，并非所有系统都支持符号链接。

在历史上，Windows 对符号链接的支持并不好，但这些示例在 Windows 10 专业版中进行了测试，如果您拥有管理员权限，硬链接和符号链接都可以正常工作。要以管理员身份从命令行执行 Go 程序，首先右键单击命令提示符并选择以管理员身份运行。然后您可以执行程序，符号链接和硬链接将按预期工作。

以下示例演示了如何创建硬链接和符号链接文件，以及如何确定文件是否是符号链接，以及如何修改符号链接文件的元数据而不更改原始文件：

```go
package main 

import ( 
   "fmt" 
   "log" 
   "os" 
) 

func main() { 
   // Create a hard link 
   // You will have two file names that point to the same contents 
   // Changing the contents of one will change the other 
   // Deleting/renaming one will not affect the other 
   err := os.Link("original.txt", "original_also.txt") 
   if err != nil { 
      log.Fatal(err) 
   } 

   fmt.Println("Creating symlink") 
   // Create a symlink 
   err = os.Symlink("original.txt", "original_sym.txt") 
   if err != nil { 
      log.Fatal(err) 
   } 

   // Lstat will return file info, but if it is actually 
   // a symlink, it will return info about the symlink. 
   // It will not follow the link and give information 
   // about the real file 
   // Symlinks do not work in Windows 
   fileInfo, err := os.Lstat("original_sym.txt") 
   if err != nil { 
      log.Fatal(err) 
   } 
   fmt.Printf("Link info: %+v", fileInfo) 

   // Change ownership of a symlink only 
   // and not the file it points to 
   err = os.Lchown("original_sym.txt", os.Getuid(), os.Getgid()) 
   if err != nil { 
      log.Fatal(err) 
   } 
} 
```

# 读写

读写文件可以通过多种方式完成。Go 提供了接口，使得编写自己的函数来处理文件或任何其他读取/写入接口变得容易。

通过`os`、`io`和`ioutil`包，您可以找到适合您需求的正确函数。这些示例涵盖了许多可用选项。

# 复制文件

以下示例使用`io.Copy()`函数将内容从一个读取器复制到另一个写入器：

```go
package main 

import ( 
   "io" 
   "log" 
   "os" 
) 

func main() { 
   // Open original file 
   originalFile, err := os.Open("test.txt") 
   if err != nil { 
      log.Fatal(err) 
   } 
   defer originalFile.Close() 

   // Create new file 
   newFile, err := os.Create("test_copy.txt") 
   if err != nil { 
      log.Fatal(err) 
   } 
   defer newFile.Close() 

   // Copy the bytes to destination from source 
   bytesWritten, err := io.Copy(newFile, originalFile) 
   if err != nil { 
      log.Fatal(err) 
   } 
   log.Printf("Copied %d bytes.", bytesWritten) 

   // Commit the file contents 
   // Flushes memory to disk 
   err = newFile.Sync() 
   if err != nil { 
      log.Fatal(err) 
   }  
} 
```

# 在文件中寻找位置

`Seek()`函数用于将文件光标设置在特定位置。默认情况下，它从偏移量 0 开始，并随着读取字节而向前移动。您可能希望将光标重置到文件的开头，或者直接跳转到特定位置。`Seek()`函数允许您执行此操作。

`Seek()`接受两个参数。第一个是距离，即你想要以字节为单位移动光标。它可以通过正整数向前移动，或者通过提供负数向文件后退。第一个参数，即距离，是一个相对值，而不是文件中的绝对位置。第二个参数指定了相对点的起始位置，称为`whence`。`whence`参数是相对偏移的参考点。它可以是`0`、`1`或`2`，分别表示文件的开头、当前位置和文件的结尾。

例如，如果指定了`Seek(-1, 2)`，它将把文件光标设置在文件末尾的前一个字节。`Seek(2, 0)`将在`file.Seek(5, 1)`的开始处寻找第二个字节，这将使光标从当前位置向前移动 5 个字节：

```go
package main 

import ( 
   "fmt" 
   "log" 
   "os" 
) 

func main() { 
   file, _ := os.Open("test.txt") 
   defer file.Close() 

   // Offset is how many bytes to move 
   // Offset can be positive or negative 
   var offset int64 = 5 

   // Whence is the point of reference for offset 
   // 0 = Beginning of file 
   // 1 = Current position 
   // 2 = End of file 
   var whence int = 0 
   newPosition, err := file.Seek(offset, whence) 
   if err != nil { 
      log.Fatal(err) 
   } 
   fmt.Println("Just moved to 5:", newPosition) 

   // Go back 2 bytes from current position 
   newPosition, err = file.Seek(-2, 1) 
   if err != nil { 
      log.Fatal(err) 
   } 
   fmt.Println("Just moved back two:", newPosition) 

   // Find the current position by getting the 
   // return value from Seek after moving 0 bytes 
   currentPosition, err := file.Seek(0, 1) 
   fmt.Println("Current position:", currentPosition) 

   // Go to beginning of file 
   newPosition, err = file.Seek(0, 0) 
   if err != nil { 
      log.Fatal(err) 
   } 
   fmt.Println("Position after seeking 0,0:", newPosition) 
} 
```

# 向文件写入字节

使用`os`包就可以进行写入操作，因为打开文件时已经需要它。由于所有的 Go 可执行文件都是静态链接的二进制文件，每导入一个包都会增加可执行文件的大小。其他包如`io`、`ioutil`和`bufio`提供了一些帮助，但并非必需品：

```go
package main 

import ( 
   "log" 
   "os" 
) 

func main() { 
   // Open a new file for writing only 
   file, err := os.OpenFile( 
      "test.txt", 
      os.O_WRONLY|os.O_TRUNC|os.O_CREATE, 
      0666, 
   ) 
   if err != nil { 
      log.Fatal(err) 
   } 
   defer file.Close() 

   // Write bytes to file 
   byteSlice := []byte("Bytes!\n") 
   bytesWritten, err := file.Write(byteSlice) 
   if err != nil { 
      log.Fatal(err) 
   } 
   log.Printf("Wrote %d bytes.\n", bytesWritten) 
} 
```

# 快速写入文件

`ioutil`包有一个有用的函数叫做`WriteFile()`，它将处理创建/打开、写入字节片段和关闭。如果您只需要一种快速的方法将字节片段转储到文件中，这将非常有用：

```go
package main 

import ( 
   "io/ioutil" 
   "log" 
) 

func main() { 
   err := ioutil.WriteFile("test.txt", []byte("Hi\n"), 0666) 
   if err != nil { 
      log.Fatal(err) 
   } 
} 
```

# 带缓冲的写入器

`bufio`包允许您创建一个带缓冲的写入器，以便您可以在将其写入磁盘之前在内存中处理缓冲区。如果您需要在将数据写入磁盘之前对数据进行大量操作以节省磁盘 IO 时间，则这是有用的。如果您一次只写入一个字节，并且希望在将其一次性存储到文件之前在内存缓冲区中存储大量数据，否则您将为每个字节执行磁盘 IO。这会对您的磁盘造成磨损，并减慢进程速度。

可以检查缓冲写入器，查看它当前存储了多少未缓冲的数据，以及剩余多少缓冲空间。缓冲区也可以重置以撤消自上次刷新以来的任何更改。缓冲区也可以调整大小。

以下示例打开名为`test.txt`的文件，并创建一个包装文件对象的缓冲写入器。一些字节被写入缓冲区，然后写入一个字符串。然后检查内存缓冲区，然后将缓冲区的内容刷新到磁盘上的文件。它还演示了如何重置缓冲区，撤消尚未刷新的任何更改，以及如何检查缓冲区中剩余的空间。最后，它演示了如何将缓冲区的大小调整为特定大小：

```go
package main 

import ( 
   "bufio" 
   "log" 
   "os" 
) 

func main() { 
   // Open file for writing 
   file, err := os.OpenFile("test.txt", os.O_WRONLY, 0666) 
   if err != nil { 
      log.Fatal(err) 
   } 
   defer file.Close() 

   // Create a buffered writer from the file 
   bufferedWriter := bufio.NewWriter(file) 

   // Write bytes to buffer 
   bytesWritten, err := bufferedWriter.Write( 
      []byte{65, 66, 67}, 
   ) 
   if err != nil { 
      log.Fatal(err) 
   } 
   log.Printf("Bytes written: %d\n", bytesWritten) 

   // Write string to buffer 
   // Also available are WriteRune() and WriteByte() 
   bytesWritten, err = bufferedWriter.WriteString( 
      "Buffered string\n", 
   ) 
   if err != nil { 
      log.Fatal(err) 
   } 
   log.Printf("Bytes written: %d\n", bytesWritten) 

   // Check how much is stored in buffer waiting 
   unflushedBufferSize := bufferedWriter.Buffered() 
   log.Printf("Bytes buffered: %d\n", unflushedBufferSize) 

   // See how much buffer is available 
   bytesAvailable := bufferedWriter.Available() 
   if err != nil { 
      log.Fatal(err) 
   } 
   log.Printf("Available buffer: %d\n", bytesAvailable) 

   // Write memory buffer to disk 
   bufferedWriter.Flush() 

   // Revert any changes done to buffer that have 
   // not yet been written to file with Flush() 
   // We just flushed, so there are no changes to revert 
   // The writer that you pass as an argument 
   // is where the buffer will output to, if you want 
   // to change to a new writer 
   bufferedWriter.Reset(bufferedWriter) 

   // See how much buffer is available 
   bytesAvailable = bufferedWriter.Available() 
   if err != nil { 
      log.Fatal(err) 
   } 
   log.Printf("Available buffer: %d\n", bytesAvailable) 

   // Resize buffer. The first argument is a writer 
   // where the buffer should output to. In this case 
   // we are using the same buffer. If we chose a number 
   // that was smaller than the existing buffer, like 10 
   // we would not get back a buffer of size 10, we will 
   // get back a buffer the size of the original since 
   // it was already large enough (default 4096) 
   bufferedWriter = bufio.NewWriterSize( 
      bufferedWriter, 
      8000, 
   ) 

   // Check available buffer size after resizing 
   bytesAvailable = bufferedWriter.Available() 
   if err != nil { 
      log.Fatal(err) 
   } 
   log.Printf("Available buffer: %d\n", bytesAvailable) 
} 
```

# 从文件中读取最多 n 个字节

`os.File`类型带有一些基本函数。其中之一是`File.Read()`。`Read()`需要传递一个字节切片作为参数。字节从文件中读取并放入字节切片中。`Read()`将尽可能多地读取字节，直到缓冲区填满，然后停止读取。

在调用`Read()`之前，可能需要多次调用`Read()`，具体取决于提供的缓冲区大小和文件的大小。如果在调用`Read()`期间到达文件的末尾，则会返回一个`io.EOF`错误：

```go
package main 

import ( 
   "log" 
   "os" 
) 

func main() { 
   // Open file for reading 
   file, err := os.Open("test.txt") 
   if err != nil { 
      log.Fatal(err) 
   } 
   defer file.Close() 

   // Read up to len(b) bytes from the File 
   // Zero bytes written means end of file 
   // End of file returns error type io.EOF 
   byteSlice := make([]byte, 16) 
   bytesRead, err := file.Read(byteSlice) 
   if err != nil { 
      log.Fatal(err) 
   } 
   log.Printf("Number of bytes read: %d\n", bytesRead) 
   log.Printf("Data read: %s\n", byteSlice) 
} 
```

# 读取确切的 n 个字节

在前面的例子中，如果`File.Read()`只包含 10 个字节的文件，但您提供了一个包含 500 个字节的字节切片缓冲区，它将不会返回错误。有些情况下，您希望确保整个缓冲区都被填满。如果整个缓冲区没有被填满，`io.ReadFull()`函数将返回错误。如果`io.ReadFull()`没有任何数据可读，将返回 EOF 错误。如果它读取了一些数据，然后遇到 EOF，它将返回`ErrUnexpectedEOF`错误：

```go
package main 

import ( 
   "io" 
   "log" 
   "os" 
) 

func main() { 
   // Open file for reading 
   file, err := os.Open("test.txt") 
   if err != nil { 
      log.Fatal(err) 
   } 

   // The file.Read() function will happily read a tiny file in to a    
   // large byte slice, but io.ReadFull() will return an 
   // error if the file is smaller than the byte slice. 
   byteSlice := make([]byte, 2) 
   numBytesRead, err := io.ReadFull(file, byteSlice) 
   if err != nil { 
      log.Fatal(err) 
   } 
   log.Printf("Number of bytes read: %d\n", numBytesRead) 
   log.Printf("Data read: %s\n", byteSlice) 
} 
```

# 至少读取 n 个字节

`io`包提供的另一个有用函数是`io.ReadAtLeast()`。如果至少没有指定数量的字节，则会返回错误。与`io.ReadFull()`类似，如果没有找到数据，则返回`EOF`错误，如果在遇到文件结束之前读取了一些数据，则返回`ErrUnexpectedEOF`错误：

```go
package main 

import ( 
   "io" 
   "log" 
   "os" 
) 

func main() { 
   // Open file for reading 
   file, err := os.Open("test.txt") 
   if err != nil { 
      log.Fatal(err) 
   } 

   byteSlice := make([]byte, 512) 
   minBytes := 8 
   // io.ReadAtLeast() will return an error if it cannot 
   // find at least minBytes to read. It will read as 
   // many bytes as byteSlice can hold. 
   numBytesRead, err := io.ReadAtLeast(file, byteSlice, minBytes) 
   if err != nil { 
      log.Fatal(err) 
   } 
   log.Printf("Number of bytes read: %d\n", numBytesRead) 
   log.Printf("Data read: %s\n", byteSlice) 
} 
```

# 读取文件的所有字节

`ioutil`包提供了一个函数，可以读取文件中的每个字节并将其作为字节切片返回。这个函数很方便，因为在进行读取之前不必定义字节切片。缺点是，一个非常大的文件将返回一个可能比预期更大的大切片。

`io.ReadAll()`函数期望一个已经用`os.Open()`或`Create()`打开的文件：

```go
package main 

import ( 
   "fmt" 
   "io/ioutil" 
   "log" 
   "os" 
) 

func main() { 
   // Open file for reading 
   file, err := os.Open("test.txt") 
   if err != nil { 
      log.Fatal(err) 
   } 

   // os.File.Read(), io.ReadFull(), and 
   // io.ReadAtLeast() all work with a fixed 
   // byte slice that you make before you read 

   // ioutil.ReadAll() will read every byte 
   // from the reader (in this case a file), 
   // and return a slice of unknown slice 
   data, err := ioutil.ReadAll(file) 
   if err != nil { 
      log.Fatal(err) 
   } 

   fmt.Printf("Data as hex: %x\n", data) 
   fmt.Printf("Data as string: %s\n", data) 
   fmt.Println("Number of bytes read:", len(data)) 
} 
```

# 快速将整个文件读取到内存中

与前面示例中的`io.ReadAll()`函数类似，`io.ReadFile()`将读取文件中的所有字节并返回一个字节切片。两者之间的主要区别在于`io.ReadFile()`期望一个文件路径，而不是已经打开的文件对象。`io.ReadFile()`函数将负责打开、读取和关闭文件。您只需提供一个文件名，它就会提供字节。这通常是加载文件数据的最快最简单的方法。

虽然这种方法非常方便，但它有一些限制；因为它直接将整个文件读取到内存中，非常大的文件可能会耗尽系统的内存限制：

```go
package main 

import ( 
   "io/ioutil" 
   "log" 
) 

func main() { 
   // Read file to byte slice 
   data, err := ioutil.ReadFile("test.txt") 
   if err != nil { 
      log.Fatal(err) 
   } 

   log.Printf("Data read: %s\n", data) 
} 
```

# 缓冲读取器

创建一个缓冲读取器将存储一些内容的内存缓冲区。缓冲读取器还提供了一些`os.File`或`io.Reader`类型上不可用的其他函数。默认缓冲区大小为 4096，最小大小为 16。缓冲读取器提供了一组有用的函数。一些可用的函数包括但不限于以下内容：

+   `Read()`: 这是将数据读入字节切片

+   `Peek()`: 这是在不移动文件光标的情况下检查下一个字节

+   `ReadByte()`: 这是读取单个字节

+   `UnreadByte()`: 这会取消上次读取的最后一个字节

+   `ReadBytes()`: 这会读取字节，直到达到指定的分隔符

+   `ReadString()`: 这会读取字符串，直到达到指定的分隔符

以下示例演示了如何使用缓冲读取器从文件获取数据。首先，它打开一个文件，然后创建一个包装文件对象的缓冲读取器。一旦缓冲读取器准备好了，它就展示了如何使用前面的函数：

```go
package main 

import ( 
   "bufio" 
   "fmt" 
   "log" 
   "os" 
) 

func main() { 
   // Open file and create a buffered reader on top 
   file, err := os.Open("test.txt") 
   if err != nil { 
      log.Fatal(err) 
   } 
   bufferedReader := bufio.NewReader(file) 

   // Get bytes without advancing pointer 
   byteSlice := make([]byte, 5) 
   byteSlice, err = bufferedReader.Peek(5) 
   if err != nil { 
      log.Fatal(err) 
   } 
   fmt.Printf("Peeked at 5 bytes: %s\n", byteSlice) 

   // Read and advance pointer 
   numBytesRead, err := bufferedReader.Read(byteSlice) 
   if err != nil { 
      log.Fatal(err) 
   } 
   fmt.Printf("Read %d bytes: %s\n", numBytesRead, byteSlice) 

   // Ready 1 byte. Error if no byte to read 
   myByte, err := bufferedReader.ReadByte() 
   if err != nil { 
      log.Fatal(err) 
   }  
   fmt.Printf("Read 1 byte: %c\n", myByte) 

   // Read up to and including delimiter 
   // Returns byte slice 
   dataBytes, err := bufferedReader.ReadBytes('\n') 
   if err != nil { 
      log.Fatal(err) 
   } 
   fmt.Printf("Read bytes: %s\n", dataBytes) 

   // Read up to and including delimiter 
   // Returns string 
   dataString, err := bufferedReader.ReadString('\n') 
   if err != nil { 
      log.Fatal(err) 
   } 
   fmt.Printf("Read string: %s\n", dataString) 

   // This example reads a few lines so test.txt 
   // should have a few lines of text to work correct 
} 
```

# 使用缓冲读取器读取

Scanner 是`bufio`包的一部分。它对于在特定分隔符处逐步浏览文件很有用。通常，换行符被用作分隔符来按行分割文件。在 CSV 文件中，逗号将是分隔符。`os.File`对象可以像缓冲读取器一样包装在`bufio.Scanner`对象中。我们将调用`Scan()`来读取到下一个分隔符，然后使用`Text()`或`Bytes()`来获取已读取的数据。

分隔符不仅仅是一个简单的字节或字符。实际上有一个特殊的函数，您必须实现它，它将确定下一个分隔符在哪里，向前推进指针的距离以及要返回的数据。如果没有提供自定义的`SplitFunc`类型，则默认为`ScanLines`，它将在每个换行符处分割。`bufio`中包含的其他分割函数有`ScanRunes`和`ScanWords`。

要定义自己的分割函数，请定义一个与此指纹匹配的函数：

```go
type SplitFuncfunc(data []byte, atEOF bool) (advance int, token []byte, 
   err error)
```

返回（`0`，`nil`，`nil`）将告诉扫描器再次扫描，但使用更大的缓冲区，因为没有足够的数据达到分隔符。

在下面的示例中，从文件创建了`bufio.Scanner`，然后逐字扫描文件：

```go
package main 

import ( 
   "bufio" 
   "fmt" 
   "log" 
   "os" 
) 

func main() { 
   // Open file and create scanner on top of it 
   file, err := os.Open("test.txt") 
   if err != nil { 
      log.Fatal(err) 
   } 
   scanner := bufio.NewScanner(file) 

   // Default scanner is bufio.ScanLines. Lets use ScanWords. 
   // Could also use a custom function of SplitFunc type 
   scanner.Split(bufio.ScanWords) 

   // Scan for next token. 
   success := scanner.Scan() 
   if success == false { 
      // False on error or EOF. Check error 
      err = scanner.Err() 
      if err == nil { 
         log.Println("Scan completed and reached EOF") 
      } else { 
         log.Fatal(err) 
      } 
   } 

   // Get data from scan with Bytes() or Text() 
   fmt.Println("First word found:", scanner.Text()) 

   // Call scanner.Scan() manually, or loop with for 
   for scanner.Scan() { 
      fmt.Println(scanner.Text()) 
   } 
} 
```

# 存档

存档是一种存储多个文件的文件格式。最常见的两种存档格式是 tar 文件和 ZIP 存档。Go 标准库有`tar`和`zip`包。这些示例使用 ZIP 格式，但 tar 格式可以很容易地互换。

# 存档（ZIP）文件

以下示例演示了如何创建一个包含多个文件的存档。示例中的文件是硬编码的，只有几个字节，但应该很容易适应其他需求：

```go
// This example uses zip but standard library 
// also supports tar archives 
package main 

import ( 
   "archive/zip" 
   "log" 
   "os" 
) 

func main() { 
   // Create a file to write the archive buffer to 
   // Could also use an in memory buffer. 
   outFile, err := os.Create("test.zip") 
   if err != nil { 
      log.Fatal(err) 
   } 
   defer outFile.Close() 

   // Create a zip writer on top of the file writer 
   zipWriter := zip.NewWriter(outFile) 

   // Add files to archive 
   // We use some hard coded data to demonstrate, 
   // but you could iterate through all the files 
   // in a directory and pass the name and contents 
   // of each file, or you can take data from your 
   // program and write it write in to the archive without 
   var filesToArchive = []struct { 
      Name, Body string 
   }{ 
      {"test.txt", "String contents of file"}, 
      {"test2.txt", "\x61\x62\x63\n"}, 
   } 

   // Create and write files to the archive, which in turn 
   // are getting written to the underlying writer to the 
   // .zip file we created at the beginning 
   for _, file := range filesToArchive { 
      fileWriter, err := zipWriter.Create(file.Name) 
      if err != nil { 
         log.Fatal(err) 
      } 
      _, err = fileWriter.Write([]byte(file.Body)) 
      if err != nil { 
         log.Fatal(err) 
      } 
   } 

   // Clean up 
   err = zipWriter.Close() 
   if err != nil { 
      log.Fatal(err) 
   } 
} 
```

# 提取（解压）存档文件

以下示例演示了如何解压 ZIP 格式文件。它将通过创建必要的目录来复制存档中找到的目录结构：

```go
// This example uses zip but standard library 
// also supports tar archives 
package main 

import ( 
   "archive/zip" 
   "io" 
   "log" 
   "os" 
   "path/filepath" 
) 

func main() { 
   // Create a reader out of the zip archive 
   zipReader, err := zip.OpenReader("test.zip") 
   if err != nil { 
      log.Fatal(err) 
   } 
   defer zipReader.Close() 

   // Iterate through each file/dir found in 
   for _, file := range zipReader.Reader.File { 
      // Open the file inside the zip archive 
      // like a normal file 
      zippedFile, err := file.Open() 
      if err != nil { 
         log.Fatal(err) 
      } 
      defer zippedFile.Close() 

      // Specify what the extracted file name should be. 
      // You can specify a full path or a prefix 
      // to move it to a different directory. 
      // In this case, we will extract the file from 
      // the zip to a file of the same name. 
      targetDir := "./" 
      extractedFilePath := filepath.Join( 
         targetDir, 
         file.Name, 
      ) 

      // Extract the item (or create directory) 
      if file.FileInfo().IsDir() { 
         // Create directories to recreate directory 
         // structure inside the zip archive. Also 
         // preserves permissions 
         log.Println("Creating directory:", extractedFilePath) 
         os.MkdirAll(extractedFilePath, file.Mode()) 
      } else { 
         // Extract regular file since not a directory 
         log.Println("Extracting file:", file.Name) 

         // Open an output file for writing 
         outputFile, err := os.OpenFile( 
            extractedFilePath, 
            os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 
            file.Mode(), 
         ) 
         if err != nil { 
            log.Fatal(err) 
         } 
         defer outputFile.Close() 

         // "Extract" the file by copying zipped file 
         // contents to the output file 
         _, err = io.Copy(outputFile, zippedFile) 
         if err != nil { 
            log.Fatal(err) 
         } 
      }  
   } 
} 
```

# 压缩

Go 标准库还支持压缩，这与存档不同。通常，存档和压缩结合在一起，将大量文件打包成一个紧凑的文件。最常见的格式可能是`.tar.gz`文件，这是一个 gzipped tar 文件。不要混淆 zip 和 gzip，它们是两种不同的东西。

Go 标准库支持多种压缩算法：

+   **bzip2**：bzip2 格式

+   **flate**：DEFLATE（RFC 1951）

+   **gzip**：gzip 格式（RFC 1952）

+   **lzw**：来自《高性能数据压缩技术，计算机，17（6）（1984 年 6 月），第 8-19 页》的 Lempel-Ziv-Welch 格式

+   **zlib**：zlib 格式（RFC 1950）

在[`golang.org/pkg/compress/`](https://golang.org/pkg/compress/)中阅读有关每个包的更多信息。这些示例使用 gzip 压缩，但应该很容易地互换上述任何包。

# 压缩文件

以下示例演示了如何使用`gzip`包压缩文件：

```go
// This example uses gzip but standard library also 
// supports zlib, bz2, flate, and lzw 
package main 

import ( 
   "compress/gzip" 
   "log" 
   "os" 
) 

func main() { 
   // Create .gz file to write to 
   outputFile, err := os.Create("test.txt.gz") 
   if err != nil { 
      log.Fatal(err) 
   } 

   // Create a gzip writer on top of file writer 
   gzipWriter := gzip.NewWriter(outputFile) 
   defer gzipWriter.Close() 

   // When we write to the gzip writer 
   // it will in turn compress the contents 
   // and then write it to the underlying 
   // file writer as well 
   // We don't have to worry about how all 
   // the compression works since we just 
   // use it as a simple writer interface 
   // that we send bytes to 
   _, err = gzipWriter.Write([]byte("Gophers rule!\n")) 
   if err != nil { 
      log.Fatal(err) 
   } 

   log.Println("Compressed data written to file.") 
} 
```

# 解压文件

以下示例演示了如何使用`gzip`算法解压文件：

```go
// This example uses gzip but standard library also 
// supports zlib, bz2, flate, and lzw 
package main 

import ( 
   "compress/gzip" 
   "io" 
   "log" 
   "os" 
) 

func main() { 
   // Open gzip file that we want to uncompress 
   // The file is a reader, but we could use any 
   // data source. It is common for web servers 
   // to return gzipped contents to save bandwidth 
   // and in that case the data is not in a file 
   // on the file system but is in a memory buffer 
   gzipFile, err := os.Open("test.txt.gz") 
   if err != nil { 
      log.Fatal(err) 
   } 

   // Create a gzip reader on top of the file reader 
   // Again, it could be any type reader though 
   gzipReader, err := gzip.NewReader(gzipFile) 
   if err != nil { 
      log.Fatal(err) 
   } 
   defer gzipReader.Close() 

   // Uncompress to a writer. We'll use a file writer 
   outfileWriter, err := os.Create("unzipped.txt") 
   if err != nil { 
      log.Fatal(err) 
   } 
   defer outfileWriter.Close() 

   // Copy contents of gzipped file to output file 
   _, err = io.Copy(outfileWriter, gzipReader) 
   if err != nil { 
      log.Fatal(err) 
   } 
} 
```

在结束关于文件处理的这一章之前，让我们看两个可能有用的实际示例。当您不想创建永久文件但需要一个文件进行操作时，临时文件和目录是有用的。此外，通过互联网下载文件是获取文件的常见方式。下面的示例演示了这些操作。

# 创建临时文件和目录

`ioutil`包提供了两个函数：`TempDir()`和`TempFile()`。调用者有责任在完成后删除临时项目。这些函数提供的唯一好处是，您可以将空字符串传递给目录，它将自动在系统的默认临时文件夹（在 Linux 上为`/tmp`）中创建该项目，因为`os.TempDir()`函数将返回默认的系统临时目录：

```go
package main 

import ( 
   "fmt" 
   "io/ioutil" 
   "log" 
   "os" 
) 

func main() { 
   // Create a temp dir in the system default temp folder 
   tempDirPath, err := ioutil.TempDir("", "myTempDir") 
   if err != nil { 
      log.Fatal(err) 
   } 
   fmt.Println("Temp dir created:", tempDirPath) 

   // Create a file in new temp directory 
   tempFile, err := ioutil.TempFile(tempDirPath, "myTempFile.txt") 
   if err != nil { 
      log.Fatal(err) 
   } 
   fmt.Println("Temp file created:", tempFile.Name()) 

   // ... do something with temp file/dir ... 

   // Close file 
   err = tempFile.Close() 
   if err != nil { 
      log.Fatal(err) 
   } 

   // Delete the resources we created 
   err = os.Remove(tempFile.Name()) 
   if err != nil { 
      log.Fatal(err) 
   } 
   err = os.Remove(tempDirPath) 
   if err != nil { 
      log.Fatal(err) 
   } 
}
```

# 通过 HTTP 下载文件

现代计算中的常见任务是通过 HTTP 协议下载文件。以下示例显示了如何快速将特定 URL 下载到文件中。

其他常见的工具包括`curl`和`wget`：

```go
package main 

import ( 
   "io" 
   "log" 
   "net/http" 
   "os" 
) 

func main() { 
   // Create output file 
   newFile, err := os.Create("devdungeon.html") 
   if err != nil { 
      log.Fatal(err) 
   } 
   defer newFile.Close() 

   // HTTP GET request devdungeon.com 
   url := "http://www.devdungeon.com/archive" 
   response, err := http.Get(url) 
   defer response.Body.Close() 

   // Write bytes from HTTP response to file. 
   // response.Body satisfies the reader interface. 
   // newFile satisfies the writer interface. 
   // That allows us to use io.Copy which accepts 
   // any type that implements reader and writer interface 
   numBytesWritten, err := io.Copy(newFile, response.Body) 
   if err != nil { 
      log.Fatal(err) 
   } 
   log.Printf("Downloaded %d byte file.\n", numBytesWritten) 
} 
```

# 总结

阅读完本章后，您现在应该熟悉了一些与文件交互的不同方式，并且可以轻松执行基本操作。目标不是要记住所有这些函数名，而是要意识到有哪些工具可用。如果您需要示例代码，本章可以用作参考，但我鼓励您创建一个类似这样的代码库。

有用的文件函数分布在多个包中。`os`包仅包含与文件的基本操作，如打开、关闭和简单读取。`io`包提供了可以在读取器和写入器接口上使用的函数，比`os`包更高级。`ioutil`包提供了更高级别的便利函数，用于处理文件。

在下一章中，我们将涵盖取证的主题。它将涵盖诸如寻找异常大或最近修改的文件之类的内容。除了文件取证，我们还将涵盖一些网络取证调查的主题，即查找主机名、IP 和主机的 MX 记录。取证章节还涵盖了隐写术的基本示例，展示了如何在图像中隐藏数据以及如何在图像中查找隐藏的数据。
