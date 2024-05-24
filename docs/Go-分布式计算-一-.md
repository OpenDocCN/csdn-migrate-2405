# Go 分布式计算（一）

> 原文：[`zh.annas-archive.org/md5/BF0BD04A27ACABD0F3CDFCFC72870F45`](https://zh.annas-archive.org/md5/BF0BD04A27ACABD0F3CDFCFC72870F45)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 前言

Go 编程语言是在 Google 开发的，用于解决他们在为其基础设施开发软件时遇到的问题。他们需要一种静态类型的语言，不会减慢开发人员的速度，可以立即编译和执行，利用多核处理器，并使跨分布式系统的工作变得轻松。

《使用 Go 进行分布式计算》的使命是使并发和并行推理变得轻松，并为读者提供设计和实现此类程序的信心。我们将首先深入探讨 goroutines 和 channels 背后的核心概念，这是 Go 语言构建的两个基本概念。接下来，我们将使用 Go 和 Go 标准库设计和构建一个分布式搜索引擎。

## 这本书是为谁准备的

这本书适用于熟悉 Golang 语法并对基本 Go 开发有一定了解的开发人员。如果您经历过 Web 应用程序产品周期，将会更有优势，尽管这并非必需。

## 本书涵盖的内容

第一章《Go 的开发环境》涵盖了开始使用 Go 和本书其余部分所需的一系列主题和概念。其中一些主题包括 Docker 和 Go 中的测试。

第二章《理解 Goroutines》介绍了并发和并行主题，然后深入探讨了 goroutines 的实现细节、Go 的运行时调度器等。

第三章《Channels and Messages》首先解释了控制并行性的复杂性，然后介绍了使用不同类型的通道来控制并行性的策略。

第四章《RESTful Web》提供了开始在 Go 中设计和构建 REST API 所需的所有上下文和知识。我们还将讨论使用不同可用方法与 REST API 服务器进行交互。

第五章《介绍 Goophr》开始讨论分布式搜索引擎的含义，使用 OpenAPI 规范描述 REST API，并描述搜索引擎组件的责任。最后，我们将描述项目结构。

第六章《Goophr Concierge》深入介绍了 Goophr 的第一个组件，详细描述了该组件应该如何工作。借助架构和逻辑流程图，进一步强化了这些概念。最后，我们将看看如何实现和测试该组件。

第七章《Goophr 图书管理员》详细介绍了负责维护搜索词索引的组件。我们还将讨论如何搜索给定的词语以及如何对搜索结果进行排序等。最后，我们将看看如何实现和测试该组件。

第八章《部署 Goophr》将前三章中实现的所有内容汇集起来，并在本地系统上启动应用程序。然后，我们将通过 REST API 添加一些文档并对其进行搜索，以测试我们的设计。

第九章《Web 规模架构的基础》是一个广泛而复杂的主题介绍，讨论如何设计和扩展系统以满足 Web 规模的需求。我们将从单个运行在单个服务器上的单体实例开始，并将其扩展到跨越多个区域，具有冗余保障以确保服务永远不会中断等。

## 充分利用本书

+   本书中的材料旨在实现动手操作。在整本书中，我们都在努力提供所有相关信息，以便读者可以选择自己尝试解决问题，然后再参考书中提供的解决方案。

+   书中的代码除了标准库外没有任何 Go 依赖。这样做是为了确保书中提供的代码示例永远不会改变，也让我们能够探索标准库。

+   书中的源代码应放置在`$GOPATH/src/distributed-go`目录下。给出的示例源代码将位于`$GOPATH/src/distributed-go/chapterX`文件夹中，其中`X`代表章节编号。

+   从[`golang.org/`](https://golang.org/)和[`www.docker.com/community-edition`](https://www.docker.com/community-edition)网站下载并安装 Go 和 Docker

### 下载示例代码文件

您可以从[`www.packtpub.com`](http://www.packtpub.com/)的帐户中下载本书的示例代码文件。如果您在其他地方购买了本书，可以访问[`www.packtpub.com/support`](http://www.packtpub.com/support)并注册，文件将直接发送到您的邮箱。

您可以按照以下步骤下载代码文件：

1.  在[`www.packtpub.com`](http://www.packtpub.com/support)登录或注册。

1.  选择“支持”选项卡。

1.  点击“代码下载和勘误”。

1.  在搜索框中输入书名，然后按照屏幕上的说明操作。

下载文件后，请确保使用以下最新版本解压或提取文件夹：

+   WinRAR / 7-Zip for Windows

+   Zipeg / iZip / UnRarX for Mac

+   7-Zip / PeaZip for Linux

本书的代码包也托管在 GitHub 上，网址为[`github.com/PacktPublishing/Distributed-Computing-with-Go`](https://github.com/PacktPublishing/Distributed-Computing-with-Go)。如果代码有更新，将在现有的 GitHub 存储库中进行更新。

我们还有其他代码包来自我们丰富的图书和视频目录，可在[`github.com/PacktPublishing/`](https://github.com/PacktPublishing/)上找到。快去看看吧！

### 下载彩色图片

我们还提供了一个 PDF 文件，其中包含本书中使用的屏幕截图/图表的彩色图片。您可以在这里下载：[`www.packtpub.com/sites/default/files/downloads/DistributedComputingwithGo_ColorImages.pdf`](https://www.packtpub.com/sites/default/files/downloads/DistributedComputingwithGo_ColorImages.pdf)。

### 使用的约定

本书中使用了许多文本约定。

`CodeInText`：表示文本中的代码单词、数据库表名、文件夹名、文件名、文件扩展名、路径名、虚拟 URL、用户输入和 Twitter 句柄。例如，“现在我们已经准备好所有的代码，让我们使用`Dockerfile`文件构建 Docker 镜像。”

代码块设置如下：

```go
// addInt.go 

package main 

func addInt(numbers ...int) int { 
    sum := 0 
    for _, num := range numbers { 
        sum += num 
    } 
    return sum 
} 
```

当我们希望引起您对代码块的特定部分的注意时，相关行或项目会以粗体显示：

```go
// addInt.go 

package main 

func addInt(numbers ...int) int { 
    sum := 0 
    for _, num := range numbers { 
        sum += num 
    } 
    return sum 
} 
```

任何命令行输入或输出都将按以下方式编写：

```go
$ cd docker
```

**粗体**：表示新术语、重要单词或屏幕上看到的单词，例如在菜单或对话框中，也会在文本中出现。例如，“从**管理**面板中选择**系统信息**。”

警告或重要提示会这样出现。

提示和技巧会这样出现。


# 第一章：Go 的开发环境

Go 是为 21 世纪应用程序开发而构建的现代编程语言。在过去的十年里，硬件和技术有了显著的进步，大多数其他语言没有利用这些技术进步。正如我们将在整本书中看到的，Go 允许我们构建利用多核系统提供的并发性和并行性的网络应用程序。

在本章中，我们将看一些在书的其余部分工作所需的主题，比如：

+   Go 配置——`GOROOT`、`GOPATH`等。

+   Go 包管理

+   整本书中使用的项目结构

+   容器技术以及如何使用 Docker

+   在 Go 中编写测试

## GOROOT

为了运行或构建一个 Go 项目，我们需要访问 Go 二进制文件及其库。在 Unix 系统上，典型的 Go 安装（安装说明可以在[`golang.org/dl/`](https://golang.org/dl/)找到）会将 Go 二进制文件放在`/usr/bin/go`。然而，也可以在不同的路径上安装 Go。在这种情况下，我们需要设置`GOROOT`环境变量指向我们的 Go 安装路径，并将其附加到我们的`PATH`环境变量中。

## GOPATH

程序员倾向于在许多项目上工作，将源代码与非编程相关文件分开是一个好习惯。将源代码放在一个单独的位置或工作空间是一个常见的做法。每种编程语言都有其自己的约定，规定语言相关项目应该如何设置，Go 也不例外。

`GOPATH`是开发人员必须设置的最重要的环境变量。它告诉 Go 编译器在哪里找到项目和其依赖项的源代码。`GOPATH`中有一些需要遵循的约定，它们与文件夹层次结构有关。

### src/

这个目录将包含我们项目和它们依赖项的源代码。一般来说，我们希望我们的源代码有版本控制，并且托管在云上。如果我们或其他人能够轻松地使用我们的项目，那将是很好的。这需要我们做一些额外的设置。

假设我们的项目托管在`http://git-server.com/user-name/my-go-project`。我们想要在本地系统上克隆和构建这个项目。为了使其正常工作，我们需要将其克隆到`$GOPATH/src/git-server.com/user-name/my-go-project`。当我们第一次为 Go 项目构建依赖项时，我们会看到`src/`文件夹中有许多包含我们项目依赖项的目录和子目录。

### pkg/

Go 是一种编译型编程语言；我们有我们想要在项目中使用的源代码和依赖项的代码。一般来说，每次构建一个二进制文件，编译器都必须读取我们项目和依赖项的源代码，然后将其编译成机器代码。每次编译我们的主程序时编译未更改的依赖项会导致非常缓慢的构建过程。这就是**目标文件**存在的原因；它们允许我们将依赖项编译成可重用的机器代码，可以直接包含在我们的 Go 二进制文件中。

这些目标文件存储在`$GOPATH/pkg`中；它们遵循与`src/`类似的目录结构，只是它们位于一个子目录中。这些目录往往遵循`<OS>_<CPU-Architecture>`的命名模式，因为我们可以为多个系统构建可执行二进制文件：

```go
$ tree $GOPATH/pkg
pkg
└── linux_amd64
 ├── github.com
 │ ├── abbot
 │ │ └── go-http-auth.a
 │ ├── dimfeld
 │ │ └── httppath.a
 │ ├── oklog
 │ │ └── ulid.a
 │ ├── rcrowley
 │ │ └── go-metrics.a
 │ ├── sirupsen
 │ │ └── logrus.a
 │ ├── sony
 │ │ └── gobreaker.a
 └── golang.org
 └── x
 ├── crypto
 │ ├── bcrypt.a
 │ ├── blowfish.a
 │ └── ssh
 │ └── terminal.a
 ├── net
 │ └── context.a
 └── sys  
```

### bin/

Go 将我们的项目编译和构建成可执行二进制文件，并将它们放在这个目录中。根据构建规范，它们可能在当前系统或其他系统上可执行。为了使用`bin/`目录中可用的二进制文件，我们需要设置相应的`GOBIN=$GOPATH/bin`环境变量。

## 包管理

在过去，所有程序都是从头开始编写的——每个实用函数和运行代码的库都必须手工编写。现在，我们不希望经常处理低级细节；从头开始编写所有所需的库和实用程序是不可想象的。Go 带有丰富的库，这对于我们大多数需求来说已经足够了。然而，可能我们需要一些标准库提供的额外库或功能。这样的库应该可以在互联网上找到，并且我们可以下载并将它们添加到我们的项目中以开始使用它们。

在前一节*GOPATH*中，我们讨论了所有项目都保存在`$GOPATH/src/git-server.com/user-name/my-go-project`形式的合格路径中。这对于我们可能拥有的任何依赖项都是正确的。在 Go 中处理依赖项有多种方法。让我们看看其中一些。

### go get

`go get`是标准库提供的用于包管理的实用程序。我们可以通过运行以下命令来安装新的包/库：

```go
$ go get git-server.com/user-name/library-we-need
```

这将下载并构建源代码，然后将其安装为二进制可执行文件（如果可以作为独立可执行文件使用）。`go get`实用程序还会安装我们项目所需的所有依赖项。

`go get`实用程序是一个非常简单的工具。它将安装 Git 存储库上的最新主提交。对于简单的项目，这可能足够了。然而，随着项目在大小和复杂性上的增长，跟踪使用的依赖版本可能变得至关重要。不幸的是，`go get`对于这样的项目并不是很好，我们可能需要看看其他包管理工具。

### glide

`glide`是 Go 社区中最广泛使用的包管理工具之一。它解决了`go get`的限制，但需要开发人员手动安装。以下是安装和使用`glide`的简单方法：

```go
$ curl https://glide.sh/get | sh
$ mkdir new-project && cd new-project
$ glide create
$ glide get github.com/last-ent/skelgor # A helper project to generate project skeleton.
$ glide install # In case any dependencies or configuration were manually added.
$ glide up # Update dependencies to latest versions of the package.
$ tree
.
├── glide.lock
├── glide.yaml
└── vendor
 └── github.com
 └── last-ent
 └── skelgor
 ├── LICENSE
 ├── main.go
 └── README.md  
```

如果您不希望通过`curl`和`sh`安装`glide`，还有其他选项可在项目页面上更详细地描述，该页面位于[`github.com/masterminds/glide`](https://github.com/masterminds/glide)。 

### go dep

`go dep`是 Go 社区正在开发的新的依赖管理工具。现在，它需要 Go 1.7 或更新版本进行编译，并且已经准备好供生产使用。然而，它仍在进行更改，并且尚未合并到 Go 的标准库中。

## 项目结构

一个项目可能不仅仅包括项目的源代码，例如配置文件和项目文档。根据偏好，项目的结构方式可能会发生很大变化。然而，最重要的是要记住整个程序的入口是通过`main`函数，这是在`main.go`中作为约定实现的。

本书中将构建的应用程序将具有以下初始结构：

```go
$ tree
.
├── common
│ ├── helpers.go
│ └── test_helpers.go
└── main.go
```

## 使用书中的代码

本书中讨论的源代码可以通过两种方式获得：

+   使用`go get -u github.com/last-ent/distributed-go`

+   从网站下载代码包并将其提取到`$GOPATH/src/github.com/last-ent/distributed-go`

完整书籍的代码现在应该可以在`$GOPATH/src/github.com/last-ent/distributed-go`中找到，每章的特定代码将在该特定章节编号的目录中找到。

例如，

第一章的代码 -> `$GOPATH/src/github.com/last-ent/distributed-go/chapter1`

第二章的代码 -> `$GOPATH/src/github.com/last-ent/distributed-go/chapter2`

等等。

每当我们在任何特定章节中讨论代码时，都意味着我们在相应章节的文件夹中。

## 容器

在整本书中，我们将编写 Go 程序，这些程序将被编译为二进制文件，并直接在我们的系统上运行。然而，在后面的章节中，我们将使用`docker-compose`来构建和运行多个 Go 应用程序。这些应用程序可以在我们的本地系统上运行而没有任何真正的问题；然而，我们的最终目标是能够在服务器上运行这些程序，并能够通过互联网访问它们。

在 20 世纪 90 年代和 21 世纪初，将应用程序部署到互联网的标准方式是获取服务器实例，将代码或二进制文件复制到实例上，然后启动程序。这在一段时间内运行良好，但很快就开始出现了复杂性。以下是其中一些：

+   在开发人员的机器上运行的代码可能在服务器上无法运行。

+   在服务器实例上运行良好的程序可能在将最新补丁应用到服务器操作系统时失败。

+   作为服务的一部分添加每个新实例时，必须运行各种安装脚本，以便我们可以使新实例与所有其他实例保持一致。这可能是一个非常缓慢的过程。

+   必须特别注意确保新实例及其上安装的所有软件版本与我们的程序使用的 API 兼容。

+   还必须确保所有配置文件和重要的环境变量都被复制到新实例；否则，应用程序可能会在没有或几乎没有线索的情况下失败。

+   通常在本地系统上运行的程序版本与测试系统上运行的程序版本与生产系统上运行的程序版本都配置不同，这意味着我们的应用程序可能会在这三种类型的系统中的一种上失败。如果发生这种情况，我们最终将不得不花费额外的时间和精力来尝试弄清楚问题是否特定于某个实例、某个系统等等。

如果我们能以明智的方式避免这种情况发生，那将是很好的。**容器**试图使用操作系统级别的虚拟化来解决这个问题。这是什么意思呢？

所有程序和应用程序都在称为**用户空间**的内存部分中运行。这使操作系统能够确保程序无法引起重大的硬件或软件问题。这使我们能够从用户空间应用程序中可能发生的任何程序崩溃中恢复过来。

容器的真正优势在于它们允许我们在隔离的用户空间中运行应用程序，我们甚至可以自定义用户空间的以下属性：

+   连接的设备，如网络适配器和 TTY

+   CPU 和 RAM 资源

+   主机操作系统可访问的文件和文件夹

然而，这如何帮助我们解决之前提到的问题呢？为此，让我们深入了解一下**Docker**。

### Docker

现代软件开发在产品开发和产品部署到服务器实例中广泛使用容器技术。Docker 是 Docker, Inc（[`www.docker.com`](https://www.docker.com/)）推广的容器技术，截至目前为止，它是最广泛使用的容器技术。另一个主要的替代品是由 CoreOS 开发的**rkt**（[`coreos.com/rkt`](https://coreos.com/rkt)），但在本书中，我们只会关注 Docker。

#### Docker 与虚拟机（VM）相比

迄今为止，看了 Docker 的描述，我们可能会想它是否是另一个虚拟机。然而，这并不是这样，因为虚拟机需要我们在机器或超级用户之上运行完整的客户操作系统，以及所有所需的二进制文件。在 Docker 的情况下，我们使用操作系统级别的虚拟化，这允许我们在隔离的用户空间中运行我们的容器。

VM 的最大优势是我们可以在系统上运行不同类型的操作系统，例如 Windows、FreeBSD 和 Linux。然而，在 Docker 的情况下，我们可以运行任何 Linux 版本，唯一的限制是它必须是 Linux：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/dist-cmp-go/img/c6fa5f9a-7c70-4dd4-99be-a7baebfe3499.png)

Docker 容器与虚拟机

Docker 容器的最大优势是，由于它在 Linux 上作为一个独立的进程运行，因此它轻量级且不知道主机操作系统的所有功能。

#### 理解 Docker

在我们开始使用 Docker 之前，让我们简要了解一下 Docker 的使用方式，结构以及完整系统的主要组件是什么。

以下列表和附带的图片应该有助于理解 Docker 管道的架构：

+   **Dockerfile**：它包含了构建运行我们程序的镜像的指令。

+   **Docker 客户端**：这是用户用来与 Docker 守护程序交互的命令行程序。

+   **Docker 守护程序**：这是一个守护程序应用程序，用于监听管理构建或运行容器以及将容器推送到 Docker 注册表的命令。它还负责配置容器网络、卷等。

+   **Docker 镜像**：Docker 镜像包含构建可在安装了 Docker 的任何 Linux 机器上执行的容器二进制文件所需的所有步骤。

+   **Docker 注册表**：Docker 注册表负责存储和检索 Docker 镜像。我们可以使用公共 Docker 注册表或私有注册表。Docker Hub 被用作默认的 Docker 注册表。

+   **Docker 容器**：Docker 容器与我们迄今讨论的容器不同。Docker 容器是 Docker 镜像的可运行实例。Docker 容器可以被创建、启动、停止等。

+   **Docker API**：我们之前讨论过的 Docker 客户端是与 Docker API 交互的命令行界面。这意味着 Docker 守护程序不需要在与 Docker 客户端相同的机器上运行。本书中将使用的默认设置是使用 UNIX 套接字或网络接口与本地系统上的 Docker 守护程序通信：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/dist-cmp-go/img/142493fb-c42c-4468-994f-7ff76fcd91e4.png)

Docker 架构

#### 测试 Docker 设置

让我们确保我们的 Docker 设置完美运行。对于我们的目的，Docker 社区版应该足够了([`www.docker.com/community-edition`](https://www.docker.com/community-edition))。安装完成后，我们将通过运行一些基本命令来检查它是否正常工作。

让我们首先检查我们安装了什么版本：

```go
$ docker --version
Docker version 17.12.0-ce, build c97c6d6
```

让我们试着深入了解一下我们的 Docker 安装的细节：

```go
$ docker info
Containers: 38
 Running: 0
 Paused: 0
 Stopped: 38
Images: 24
Server Version: 17.12.0-ce 
```

在 Linux 上，当您尝试运行 docker 命令时，可能会出现**Permission denied**错误。为了与 Docker 交互，您可以在命令前加上`sudo`，或者您可以创建一个“docker”用户组并将您的用户添加到该组中。有关更多详细信息，请参阅链接[`docs.docker.com/install/linux/linux-postinstall/.`](https://docs.docker.com/install/linux/linux-postinstall/)

让我们尝试运行一个 Docker 镜像。如果您还记得关于 Docker 注册表的讨论，您就知道我们不需要使用 Dockerfile 构建 Docker 镜像，就可以运行 Docker 容器。我们可以直接从 Docker Hub（默认的 Docker 注册表）拉取它并将镜像作为容器运行：

```go
$ docker run docker/whalesay cowsay Welcome to GopherLand!  

Unable to find image 'docker/whalesay:latest' locally
Trying to pull repository docker.io/docker/whalesay ...
sha256:178598e51a26abbc958b8a2e48825c90bc22e641de3d31e18aaf55f3258ba93b: Pulling from docker.io/docker/whalesay
e190868d63f8: Pull complete
909cd34c6fd7: Pull complete
0b9bfabab7c1: Pull complete
a3ed95caeb02: Pull complete
00bf65475aba: Pull complete
c57b6bcc83e3: Pull complete
8978f6879e2f: Pull complete
8eed3712d2cf: Pull complete
Digest: sha256:178598e51a26abbc958b8a2e48825c90bc22e641de3d31e18aaf55f3258ba93b
Status: Downloaded newer image for docker.io/docker/whalesay:latest
 ________________________
< Welcome to GopherLand! >
 ------------------------
    \
     \
    \ 
     ## .
     ## ## ## ==
     ## ## ## ## ===
     /""""""""""""""""___/ ===
  ~~~ {~~ ~~~~ ~~~ ~~~~ ~~ ~ / ===- ~~~
     \______ o __/
    \ __/
     \__________/

```

前面的命令也可以像这样执行，只需使用`docker run ...`，这更方便：

```go
$ docker pull docker/whalesay & docker run docker/whalesay cowsay Welcome to GopherLand!
```

一旦我们有了一长串构建的镜像，我们可以列出它们所有，同样也适用于 Docker 容器：

```go
$ docker images
REPOSITORY TAG IMAGE ID CREATED SIZE
docker.io/docker/whalesay latest 6b362a9f73eb 2 years ago 247 MB
$ docker container ls --all 
CONTAINER ID IMAGE COMMAND CREATED STATUS PORTS NAMES 
a1b1efb42130 docker/whalesay "cowsay Welcome to..." 5 minutes ago Exited (0) 5 minutes ago frosty_varahamihira 

```

最后，值得注意的是，随着我们不断使用 docker 来构建和运行镜像和容器，我们将开始创建一堆“悬空”的镜像，我们可能不会再真正使用。但是，它们最终会占用存储空间。为了摆脱这样的“悬空”镜像，我们可以使用以下命令：

```go
$ docker rmi --force 'docker images -q -f dangling=true'
# list of hashes for all deleted images.
```

#### Dockerfile

现在我们已经掌握了 Docker 的基础知识，让我们来看看在本书中将用作模板的`Dockerfile`文件。

接下来，让我们看一个例子：

```go
FROM golang:1.10
# The base image we want to use to build our docker image from. 
# Since this image is specialized for golang it will have GOPATH = /go 

ADD . /go/src/hello
# We copy files & folders from our system onto the docker image 

RUN go install hello 
# Next we can create an executable binary for our project with the command,
'go install' ENV NAME Bob
# Environment variable NAME will be picked up by the program 'hello' 
and printed to console.ENTRYPOINT /go/bin/hello
# Command to execute when we start the container # EXPOSE 9000 # Generally used for network applications. Allows us to connect to the
application running inside the container from host system's localhost. 
```

##### main.go

让我们创建一个最基本的 Go 程序，这样我们就可以在 Docker 镜像中使用它。它将获取`NAME`环境变量并打印`<NAME> is your uncle.`然后退出：

```go
package main 

import ( 
    "fmt" 
    "os" 
) 

func main() { 
    fmt.Println(os.Getenv("NAME") + " is your uncle.") 
} 
```

现在我们已经把所有的代码都放好了，让我们使用`Dockerfile`文件构建 Docker 镜像：

```go
$ cd docker
$ tree
.
├── Dockerfile
└── main.go"
0 directories, 2 files $ # -t tag lets us name our docker images so that we can easily refer to them $ docker build . -t hello-uncle Sending build context to Docker daemon 3.072 kB Step 1/5 : FROM golang:1.9.1 ---> 99e596fc807e Step 2/5 : ADD . /go/src/hello ---> Using cache ---> 64d080d7eb39 Step 3/5 : RUN go install hello ---> Using cache ---> 13bd4a1f2a60 Step 4/5 : ENV NAME Bob ---> Using cache ---> cc432fe8ffb4 Step 5/5 : ENTRYPOINT /go/bin/hello ---> Using cache ---> e0bbfb1fe52b Successfully built e0bbfb1fe52b $ # Let's now try to run the docker image. $ docker run hello-uncle Bob is your uncle. $ # We can also change the environment variables on the fly. $ docker run -e NAME=Sam hello-uncle Sam is your uncle. 
```

## 在 Go 中进行测试

测试是编程的重要部分，无论是在 Go 中还是在任何其他语言中。Go 有一种直接的方法来编写测试，在本节中，我们将看一些重要的工具来帮助测试。

我们需要遵循一些规则和约定来测试我们的代码。它们可以列举如下：

+   源文件和相关的测试文件放置在同一个包/文件夹中

+   任何给定源文件的测试文件的名称是`<source-file-name>_test.go`

+   测试函数需要以"Test"前缀开头，并且函数名的下一个字符应该是大写的

在本节的其余部分，我们将查看三个文件及其相关的测试：

+   `variadic.go`和`variadic_test.go`

+   `addInt.go`和`addInt_test.go`

+   `nil_test.go`（这些测试没有任何源文件）

在此过程中，我们将介绍我们可能使用的任何进一步的概念。

### variadic.go

为了理解第一组测试，我们需要了解什么是变参函数以及 Go 如何处理它。让我们从定义开始：

*Variadic 函数是在函数调用期间可以接受任意数量的参数的函数。*

鉴于 Go 是一种静态类型语言，对变参函数的唯一限制是传递给它的不定数量的参数应该是相同的数据类型。但是，这并不限制我们传递其他变量类型。如果传递了参数，则函数将接收到一个元素的切片，否则为`nil`。

让我们看一下代码，以便更好地理解：

```go
// variadic.go 

package main 

func simpleVariadicToSlice(numbers ...int) []int { 
   return numbers 
} 

func mixedVariadicToSlice(name string, numbers ...int) (string, []int) { 
   return name, numbers 
} 

// Does not work. 
// func badVariadic(name ...string, numbers ...int) {} 
```

我们在数据类型之前使用`...`前缀来定义函数作为变参函数。请注意，每个函数只能有一个变参参数，并且它必须是最后一个参数。如果我们取消注释`badVariadic`行并尝试测试代码，我们会看到这个错误。

### variadic_test.go

我们想要测试两个有效的函数，`simpleVariadicToSlice`和`mixedVariadicToSlice`，以验证前一节中定义的各种规则。但是，为了简洁起见，我们将测试这些：

+   `simpleVariadicToSlice`：这是为了没有参数，三个参数，以及查看如何将切片传递给变参函数

+   `mixedVariadicToSlice`：这是为了接受一个简单的参数和一个变参参数

现在让我们看一下测试这两个函数的代码：

```go
// variadic_test.go 
package main 

import "testing" 

func TestSimpleVariadicToSlice(t *testing.T) { 
    // Test for no arguments 
    if val := simpleVariadicToSlice(); val != nil { 
        t.Error("value should be nil", nil) 
    } else { 
        t.Log("simpleVariadicToSlice() -> nil") 
    } 

    // Test for random set of values 
    vals := simpleVariadicToSlice(1, 2, 3) 
    expected := []int{1, 2, 3} 
    isErr := false 
    for i := 0; i < 3; i++ { 
        if vals[i] != expected[i] { 
            isErr = true 
            break 
        } 
    } 
    if isErr { 
        t.Error("value should be []int{1, 2, 3}", vals) 
    } else { 
        t.Log("simpleVariadicToSlice(1, 2, 3) -> []int{1, 2, 3}") 
    } 

    // Test for a slice 
    vals = simpleVariadicToSlice(expected...) 
    isErr = false 
    for i := 0; i < 3; i++ { 
        if vals[i] != expected[i] { 
            isErr = true 
            break 
        } 
    } 
    if isErr { 
        t.Error("value should be []int{1, 2, 3}", vals) 
    } else { 
        t.Log("simpleVariadicToSlice([]int{1, 2, 3}...) -> []int{1, 2, 3}") 
    } 
} 

func TestMixedVariadicToSlice(t *testing.T) { 
    // Test for simple argument & no variadic arguments 
    name, numbers := mixedVariadicToSlice("Bob") 
    if name == "Bob" && numbers == nil { 
        t.Log("Recieved as expected: Bob, <nil slice>") 
    } else { 
        t.Errorf("Received unexpected values: %s, %s", name, numbers) 
    } 
} 
```

### 在`variadic_test.go`中运行测试

让我们运行这些测试并查看输出。在运行测试时，我们将使用`-v`标志来查看每个单独测试的输出：

```go
$ go test -v ./{variadic_test.go,variadic.go} 
=== RUN TestSimpleVariadicToSlice 
--- PASS: TestSimpleVariadicToSlice (0.00s) 
 variadic_test.go:10: simpleVariadicToSlice() -> nil 
 variadic_test.go:26: simpleVariadicToSlice(1, 2, 3) -> []int{1, 2, 3} 
 variadic_test.go:41: simpleVariadicToSlice([]int{1, 2, 3}...) -> []int{1, 2, 3} 
=== RUN TestMixedVariadicToSlice 
--- PASS: TestMixedVariadicToSlice (0.00s) 
 variadic_test.go:49: Received as expected: Bob, <nil slice> 
PASS 
ok command-line-arguments 0.001s   
```

### addInt.go

`variadic_test.go`中的测试详细说明了变参函数的规则。但是，您可能已经注意到`TestSimpleVariadicToSlice`在其函数体中运行了三个测试，但`go test`将其视为单个测试。Go 提供了一种很好的方法来在单个函数内运行多个测试，我们将在`addInt_test.go`中查看它们。

对于这个例子，我们将使用一个非常简单的函数，如下所示：

```go
// addInt.go 

package main 

func addInt(numbers ...int) int { 
    sum := 0 
    for _, num := range numbers { 
        sum += num 
    } 
    return sum 
} 
```

#### addInt_test.go

您可能还注意到在`TestSimpleVariadicToSlice`中，我们重复了很多逻辑，而唯一变化的因素是输入和期望值。一种测试风格，称为**表驱动开发**，定义了运行测试所需的所有数据的表，迭代表的“行”，并对它们运行测试。

让我们看一下我们将要测试的没有参数和变参参数：

```go
// addInt_test.go 

package main 

import ( 
    "testing" 
) 

func TestAddInt(t *testing.T) { 
    testCases := []struct { 
        Name     string 
        Values   []int 
        Expected int 
    }{ 
        {"addInt() -> 0", []int{}, 0}, 
        {"addInt([]int{10, 20, 100}) -> 130", []int{10, 20, 100}, 130}, 
    } 

    for _, tc := range testCases { 
        t.Run(tc.Name, func(t *testing.T) { 
            sum := addInt(tc.Values...) 
            if sum != tc.Expected { 
                t.Errorf("%d != %d", sum, tc.Expected) 
            } else { 
                t.Logf("%d == %d", sum, tc.Expected) 
            } 
        }) 
    } 
} 
```

#### 在 addInt_test.go 中运行测试

现在让我们运行这个文件中的测试，并且我们期望`testCases`表中的每一行被视为一个单独的测试：

```go
$ go test -v ./{addInt.go,addInt_test.go} 
=== RUN TestAddInt 
=== RUN TestAddInt/addInt()_->_0 
=== RUN TestAddInt/addInt([]int{10,_20,_100})_->_130 
--- PASS: TestAddInt (0.00s) 
 --- PASS: TestAddInt/addInt()_->_0 (0.00s) 
 addInt_test.go:23: 0 == 0 
 --- PASS: TestAddInt/addInt([]int{10,_20,_100})_->_130 (0.00s) 
 addInt_test.go:23: 130 == 130 
PASS 
ok command-line-arguments 0.001s   
```

### nil_test.go

我们还可以创建不特定于任何特定源文件的测试；唯一的标准是文件名需要采用`<text>_test.go`的形式。`nil_test.go`中的测试阐明了语言的一些有用特性，开发人员在编写测试时可能会发现有用。它们如下：

+   `httptest.NewServer`*:* 想象一下我们需要针对发送数据的服务器测试我们的代码的情况。启动和协调一个完整的服务器来访问一些数据是困难的。`http.NewServer`为我们解决了这个问题。

+   `t.Helper`：如果我们使用相同的逻辑来通过或失败很多`testCases`，将这个逻辑分离到一个单独的函数中是有意义的。然而，这会扭曲测试运行调用堆栈。我们可以通过注释测试中的`t.Helper()`并重新运行`go test`来看到这一点。

我们还可以格式化我们的命令行输出以打印漂亮的结果。我们将展示一个简单的例子，为通过的案例添加一个勾号，为失败的案例添加一个叉号。

在测试中，我们将运行一个测试服务器，在其上进行 GET 请求，然后测试预期输出与实际输出：

```go
// nil_test.go 

package main 

import ( 
    "fmt" 
    "io/ioutil" 
    "net/http" 
    "net/http/httptest" 
    "testing" 
) 

const passMark = "\u2713" 
const failMark = "\u2717" 

func assertResponseEqual(t *testing.T, expected string, actual string) { 
    t.Helper() // comment this line to see tests fail due to 'if expected != actual' 
    if expected != actual { 
        t.Errorf("%s != %s %s", expected, actual, failMark) 
    } else { 
        t.Logf("%s == %s %s", expected, actual, passMark) 
    } 
} 

func TestServer(t *testing.T) { 
    testServer := httptest.NewServer( 
        http.HandlerFunc( 
            func(w http.ResponseWriter, r *http.Request) { 
                path := r.RequestURI 
                if path == "/1" { 
                    w.Write([]byte("Got 1.")) 
                } else { 
                    w.Write([]byte("Got None.")) 
                } 
            })) 
    defer testServer.Close() 

    for _, testCase := range []struct { 
        Name     string 
        Path     string 
        Expected string 
    }{ 
        {"Request correct URL", "/1", "Got 1."}, 
        {"Request incorrect URL", "/12345", "Got None."}, 
    } { 
        t.Run(testCase.Name, func(t *testing.T) { 
            res, err := http.Get(testServer.URL + testCase.Path) 
            if err != nil { 
                t.Fatal(err) 
            } 

            actual, err := ioutil.ReadAll(res.Body) 
            res.Body.Close() 
            if err != nil { 
                t.Fatal(err) 
            } 
            assertResponseEqual(t, testCase.Expected, fmt.Sprintf("%s", actual)) 
        }) 
    } 
    t.Run("Fail for no reason", func(t *testing.T) {
        assertResponseEqual(t, "+", "-")
    })
} 
```

#### 在 nil_test.go 中运行测试

我们运行了三个测试，其中两个测试案例将通过，一个将失败。这样我们就可以看到勾号和叉号的效果。

```go
$ go test -v ./nil_test.go 
=== RUN TestServer 
=== RUN TestServer/Request_correct_URL 
=== RUN TestServer/Request_incorrect_URL 
=== RUN TestServer/Fail_for_no_reason 
--- FAIL: TestServer (0.00s) 
 --- PASS: TestServer/Request_correct_URL (0.00s) 
 nil_test.go:55: Got 1\. == Got 1\. ![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/dist-cmp-go/img/1a82adfd-2d48-47fe-8d7d-776e1ae5d133.png) 
 --- PASS: TestServer/Request_incorrect_URL (0.00s) 
 nil_test.go:55: Got None. == Got None. ![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/dist-cmp-go/img/1a82adfd-2d48-47fe-8d7d-776e1ae5d133.png)
  --- FAIL: TestServer/Fail_for_no_reason (0.00s)   
 nil_test.go:59: + != - ![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/dist-cmp-go/img/5270c9e7-2a17-4ce4-bdd5-4b72eb407085.jpg)
 FAIL exit status 1 FAIL command-line-arguments 0.003s 
```

## 总结

在本章中，我们首先看了成功运行 Go 项目的基本设置。然后我们看了如何为我们的 Go 项目安装依赖以及如何构建项目结构。我们还研究了容器背后的重要概念，它们解决了什么问题，以及我们将如何在本书中使用它们以及一个示例。接下来，我们看了如何在 Go 中编写测试，并且在这个过程中，我们学到了一些有趣的概念，比如处理可变参数函数和其他有用的测试函数。

在下一章中，我们将开始研究 Go 编程的核心基础之一——goroutines 以及在使用它们时需要牢记的重要细节。


# 第二章：理解 Goroutines

在过去的十年里，软件开发和编程已经取得了相当大的进步。许多以前被认为是学术和低效的概念开始在现代软件解决方案中找到位置。其中两个概念是协程（Go 中的 goroutines）和通道。从概念上讲，它们随着时间的推移而发展，并且它们在每种编程语言中的实现方式也不同。在许多编程语言中，比如 Ruby 或 Clojure，它们被实现为库，但在 Go 中，它们作为一种本地特性在语言中实现。正如我们将看到的，这使得该语言真正现代化，相当高效，并且是一种先进的编程语言。

在本章中，我们将通过查看 goroutines 和以下主题来尝试理解 Go：

+   并发和并行

+   Go 的运行时调度程序

+   在使用 goroutines 时要注意的事项

## 并发和并行

计算机和软件程序很有用，因为它们可以快速完成大量繁重的工作，还可以同时做多件事情。我们希望我们的程序能够同时做多件事情，也就是说，多任务处理，编程语言的成功可能取决于编写和理解多任务处理程序的难易程度。

并发和并行是我们在研究多任务处理时经常遇到的两个术语，它们经常被互换使用。然而，它们意味着两个截然不同的事情。

Go 博客上给出的标准定义（[`blog.golang.org/concurrency-is-not-parallelism`](https://blog.golang.org/concurrency-is-not-parallelism)）如下：

+   **并发性**：*并发性是指同时处理很多事情*。这意味着我们在一段时间内设法同时完成多项任务。但是，我们一次只做一件事。这往往发生在一个任务在等待时，程序决定在空闲时间运行另一个任务。在下图中，这是通过在蓝色任务的空闲时段运行黄色任务来表示的。

+   **并行性**：*并行性是指同时做很多事情*。这意味着即使我们有两个任务，它们也在不间断地工作，没有任何间断。在图中，这表明绿色任务是独立运行的，并且不受红色任务的影响：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/dist-cmp-go/img/66b44862-4bcb-4fcb-a816-4125f4fdf8ca.png)

重要的是要理解这两个术语之间的区别。让我们通过一些具体的例子来进一步阐述两者之间的区别。

### 并发

让我们通过一个简单的例子来看看并发的概念，以及我们如何执行一些日常例行任务。

想象一下你开始一天，需要完成六件事：

+   预订酒店。

+   预订机票

+   订购一件连衣裙

+   支付信用卡账单

+   写电子邮件

+   听有声读物

完成它们的顺序并不重要，对于一些任务，比如写电子邮件或听有声读物，你不需要一次完成它们。以下是完成任务的一种可能方式：

1.  订购一件连衣裙。

1.  写电子邮件的三分之一。

1.  预订酒店。

1.  听 10 分钟的有声读物。

1.  支付信用卡账单。

1.  写电子邮件的另外三分之一。

1.  预订机票。

1.  听 20 分钟的有声读物。

1.  完成写电子邮件。

1.  继续听有声读物直到入睡。

在编程术语中，我们**同时**执行了上述任务。我们度过了一整天，从任务列表中选择了特定的任务，并开始处理它们。对于某些任务，我们甚至决定将它们分成几部分，在其他任务之间处理这些部分。

最终我们将编写一个程序，以并发的方式执行所有前面的步骤，但让我们一步一步来。让我们首先构建一个按顺序执行任务的程序，然后逐渐修改它，直到它成为纯并发代码并使用 goroutines。程序的进展将分为三个步骤：

1.  串行任务执行。

1.  使用 goroutines 的串行任务执行。

1.  并发任务执行。

#### 代码概述

代码将由一组打印出其分配任务的函数组成。在写电子邮件或听有声读物的情况下，我们进一步将任务细分为更多函数。具体如下：

+   `writeMail`，`continueWritingMail1`，`continueWritingMail2`

+   `listenToAudioBook`，`continueListeningToAudioBook`

#### 串行任务执行

让我们首先实现一个以线性方式执行所有任务的程序。根据我们之前讨论的代码概述，以下代码应该很简单：

```go
package main 

import ( 
    "fmt" 
) 

// Simple individual tasks 
func makeHotelReservation() { 
    fmt.Println("Done making hotel reservation.") 
} 
func bookFlightTickets() { 
    fmt.Println("Done booking flight tickets.") 
} 
func orderADress() { 
    fmt.Println("Done ordering a dress.") 
} 
func payCreditCardBills() { 
    fmt.Println("Done paying Credit Card bills.") 
} 

// Tasks that will be executed in parts 

// Writing Mail 
func writeAMail() { 
    fmt.Println("Wrote 1/3rd of the mail.") 
    continueWritingMail1() 
} 
func continueWritingMail1() { 
    fmt.Println("Wrote 2/3rds of the mail.") 
    continueWritingMail2() 
} 
func continueWritingMail2() { 
    fmt.Println("Done writing the mail.") 
} 

// Listening to Audio Book 
func listenToAudioBook() { 
    fmt.Println("Listened to 10 minutes of audio book.") 
    continueListeningToAudioBook() 
} 
func continueListeningToAudioBook() { 
    fmt.Println("Done listening to audio book.") 
} 

// All the tasks we want to complete in the day. 
// Note that we do not include the sub tasks here. 
var listOfTasks = []func(){ 
    makeHotelReservation, bookFlightTickets, orderADress, 
    payCreditCardBills, writeAMail, listenToAudioBook, 
} 

func main() { 
    for _, task := range listOfTasks { 
        task() 
    } 
} 
```

我们接受每个主要任务，并按简单的顺序开始执行它们。执行上述代码应该产生预期之外的输出，如下所示：

```go
Done making hotel reservation.
Done booking flight tickets.
Done ordering a dress.
Done paying Credit Card bills.
Wrote 1/3rd of the mail.
Wrote 2/3rds of the mail.
Done writing the mail.
Listened to 10 minutes of audio book.
Done listening to audio book.
```

#### 使用 goroutines 进行串行任务执行

我们列出了一系列任务，并编写了一个程序以线性和顺序的方式执行它们。但是，我们希望同时执行这些任务！让我们首先为分割任务引入 goroutines，看看效果如何。我们只会展示代码片段，其中代码实际上发生了变化：

```go
/******************************************************************** 
  We start by making Writing Mail & Listening Audio Book concurrent. 
*********************************************************************/ 
// Tasks that will be executed in parts 

// Writing Mail 
func writeAMail() { 
    fmt.Println("Wrote 1/3rd of the mail.") 
    go continueWritingMail1()  // Notice the addition of 'go' keyword. 
} 
func continueWritingMail1() { 
    fmt.Println("Wrote 2/3rds of the mail.") 
    go continueWritingMail2()  // Notice the addition of 'go' keyword. 
} 
func continueWritingMail2() { 
    fmt.Println("Done writing the mail.") 
} 

// Listening to Audio Book 
func listenToAudioBook() { 
    fmt.Println("Listened to 10 minutes of audio book.") 
    go continueListeningToAudioBook()  // Notice the addition of 'go'   keyword. 
} 
func continueListeningToAudioBook() { 
    fmt.Println("Done listening to audio book.") 
} 
```

以下是可能的输出：

```go
Done making hotel reservation.
Done booking flight tickets.
Done ordering a dress.
Done paying Credit Card bills.
Wrote 1/3rd of the mail.
Listened to 10 minutes of audio book.
```

哎呀！这不是我们期望的。`continueWritingMail1`，`continueWritingMail2`和`continueListeningToAudioBook`函数的输出缺失；原因是我们使用了 goroutines。由于 goroutines 没有等待，`main`函数中的代码继续执行，一旦控制流到达`main`函数的末尾，程序就会结束。我们真正想做的是在`main`函数中等待，直到所有 goroutines 都执行完毕。我们可以通过两种方式实现这一点——使用通道或使用`WaitGroup`。由于我们有第三章，*通道和消息*专门讨论通道，让我们在本节中使用`WaitGroup`。

为了使用`WaitGroup`，我们必须记住以下几点：

+   使用`WaitGroup.Add(int)`来计算我们将作为逻辑的一部分运行多少 goroutines。

+   使用`WaitGroup.Done()`来表示 goroutine 完成了其任务。

+   使用`WaitGroup.Wait()`来等待直到所有 goroutines 都完成。

+   将`WaitGroup`实例传递给 goroutines，以便它们可以调用`Done()`方法。

基于这些观点，我们应该能够修改源代码以使用`WaitGroup`。以下是更新后的代码：

```go
package main 

import ( 
    "fmt" 
    "sync" 
) 

// Simple individual tasks 
func makeHotelReservation(wg *sync.WaitGroup) { 
    fmt.Println("Done making hotel reservation.") 
    wg.Done()
} 
func bookFlightTickets(wg *sync.WaitGroup) { 
    fmt.Println("Done booking flight tickets.") 
    wg.Done() 
} 
func orderADress(wg *sync.WaitGroup) { 
    fmt.Println("Done ordering a dress.") 
    wg.Done() 
} 
func payCreditCardBills(wg *sync.WaitGroup) { 
    fmt.Println("Done paying Credit Card bills.") 
    wg.Done() 
} 

// Tasks that will be executed in parts 

// Writing Mail 
func writeAMail(wg *sync.WaitGroup) { 
    fmt.Println("Wrote 1/3rd of the mail.") 
    go continueWritingMail1(wg) 
} 
func continueWritingMail1(wg *sync.WaitGroup) { 
    fmt.Println("Wrote 2/3rds of the mail.") 
    go continueWritingMail2(wg) 
} 
func continueWritingMail2(wg *sync.WaitGroup) { 
    fmt.Println("Done writing the mail.") 
    wg.Done() 
} 

// Listening to Audio Book 
func listenToAudioBook(wg *sync.WaitGroup) { 
    fmt.Println("Listened to 10 minutes of audio book.") 
    go continueListeningToAudioBook(wg) 
} 
func continueListeningToAudioBook(wg *sync.WaitGroup) { 
    fmt.Println("Done listening to audio book.") 
    wg.Done() 
} 

// All the tasks we want to complete in the day. 
// Note that we do not include the sub tasks here. 
var listOfTasks = []func(*sync.WaitGroup){ 
    makeHotelReservation, bookFlightTickets, orderADress, 
    payCreditCardBills, writeAMail, listenToAudioBook, 
} 

func main() { 
    var waitGroup sync.WaitGroup 
    // Set number of effective goroutines we want to wait upon 
    waitGroup.Add(len(listOfTasks)) 

    for _, task := range listOfTasks{ 
        // Pass reference to WaitGroup instance 
        // Each of the tasks should call on WaitGroup.Done() 
        task(&waitGroup) 
    } 
    // Wait until all goroutines have completed execution. 
    waitGroup.Wait() 
}
```

以下是一种可能的输出顺序；请注意`continueWritingMail1`和`continueWritingMail2`在`listenToAudioBook`和`continueListeningToAudioBook`之后执行：

```go
Done making hotel reservation.
Done booking flight tickets.
Done ordering a dress.
Done paying Credit Card bills.
Wrote 1/3rd of the mail.
Listened to 10 minutes of audio book.
Done listening to audio book.
Wrote 2/3rds of the mail.
Done writing the mail.
```

#### 并发任务执行

在上一节的最终输出中，我们可以看到`listOfTasks`中的所有任务都是按顺序执行的，最大并发的最后一步是让顺序由 Go 运行时决定，而不是由`listOfTasks`中的顺序。这听起来可能是一项费力的任务，但实际上这是非常简单实现的。我们只需要在`task(&waitGroup)`前面加上`go`关键字：

```go
func main() { 
    var waitGroup sync.WaitGroup 
    // Set number of effective goroutines we want to wait upon 
    waitGroup.Add(len(listOfTasks)) 

    for _, task := range listOfTasks { 
        // Pass reference to WaitGroup instance 
        // Each of the tasks should call on WaitGroup.Done() 
        go task(&waitGroup) // Achieving maximum concurrency 
    } 

    // Wait until all goroutines have completed execution. 
    waitGroup.Wait() 
```

以下是可能的输出：

```go
Listened to 10 minutes of audio book.
Done listening to audio book.
Done booking flight tickets.
Done ordering a dress.
Done paying Credit Card bills.
Wrote 1/3rd of the mail.
Wrote 2/3rds of the mail.
Done writing the mail.
Done making hotel reservation.
```

如果我们看一下这种可能的输出，任务是按以下顺序执行的：

1.  听有声读物。

1.  预订机票。

1.  订购一件连衣裙。

1.  支付信用卡账单。

1.  写一封电子邮件。

1.  预订酒店。

现在我们对并发是什么以及如何使用`goroutines`和`WaitGroup`编写并发代码有了一个很好的了解，让我们深入了解并行性。

### 并行性

想象一下，你需要写几封电子邮件。它们将会很长、很费力，而让自己保持愉快的最好方法是在写邮件的同时听音乐，也就是说，在“并行”写邮件的同时听音乐。如果我们想编写一个模拟这种情况的程序，以下是一种可能的实现：

```go
package main 

import ( 
    "fmt" 
    "sync" 
    "time" 
) 

func printTime(msg string) { 
    fmt.Println(msg, time.Now().Format("15:04:05")) 
} 

// Task that will be done over time 
func writeMail1(wg *sync.WaitGroup) { 
    printTime("Done writing mail #1.") 
    wg.Done() 
} 
func writeMail2(wg *sync.WaitGroup) { 
    printTime("Done writing mail #2.") 
    wg.Done() 
} 
func writeMail3(wg *sync.WaitGroup) { 
    printTime("Done writing mail #3.") 
    wg.Done() 
} 

// Task done in parallel 
func listenForever() { 
    for { 
        printTime("Listening...") 
    } 
} 

func main() { 
    var waitGroup sync.WaitGroup 
    waitGroup.Add(3) 

    go listenForever() 

    // Give some time for listenForever to start 
    time.Sleep(time.Nanosecond * 10) 

    // Let's start writing the mails 
    go writeMail1(&waitGroup) 
    go writeMail2(&waitGroup) 
    go writeMail3(&waitGroup) 

    waitGroup.Wait() 
} 
```

程序的输出可能如下：

```go
Done writing mail #3\. 19:32:57
Listening... 19:32:57
Listening... 19:32:57
Done writing mail #1\. 19:32:57
Listening... 19:32:57
Listening... 19:32:57
Done writing mail #2\. 19:32:57
```

数字代表时间，以`小时:分钟:秒`表示，可以看到它们是并行执行的。您可能已经注意到，并行代码看起来几乎与最终并发示例的代码相同。然而，在`listenForever`函数中，我们在一个无限循环中打印`Listening...`。如果前面的示例没有使用协程编写，输出将继续打印`Listening...`，永远不会到达`writeMail`函数调用。

现在我们了解了如何使用协程来运行并发程序，让我们看看 Go 是如何允许我们做到这一点的。接下来我们将看一下 Go 运行时使用的调度器。

## Go 的运行时调度器

Go 程序连同运行时在多个 OS 线程上进行管理和执行。运行时使用一种称为**M:N**调度器的调度策略，它将 M 个协程调度到 N 个 OS 线程上。因此，每当我们需要运行或切换到不同的协程时，上下文切换将会很快，这也使我们能够利用 CPU 的多个核进行并行计算。

对 Go 的运行时和调度器有一个扎实的理解会非常有趣和有用，现在是一个详细了解它们的好时机。

从 Go 调度器的角度来看，主要有三个实体：

+   协程（G）

+   OS 线程或机器（M）

+   上下文或处理器（P）

让我们看看它们做了什么。我们还将查看这些实体的部分结构定义，以便更好地了解调度是如何实现和运行的。

### 协程

它是包含程序/函数实际指令的逻辑执行单元。它还包含有关协程的其他重要信息，例如堆栈内存、它正在运行的机器（M）以及调用它的 Go 函数。以下是协程结构中可能有用的一些元素：

```go
// Denoted as G in runtime 
type g struct { 
    stack         stack // offset known to runtime/cgo 
    m               *m    // current m; offset known to arm liblink 
    goid           int64 
    waitsince   int64   // approx time when the g become blocked 
    waitreason string  // if status==Gwaiting 
    gopc          uintptr // pc of go statement that created this goroutine 
    startpc       uintptr // pc of goroutine function 
    timer         *timer  // cached timer for time.Sleep 

    // ... 
} 
```

一个有趣的事情是，当我们的 Go 程序启动时，首先启动一个名为主协程的协程，它负责在启动我们的程序之前设置运行时空间。典型的运行时设置可能包括最大堆栈大小、启用垃圾回收等。

### OS 线程或机器

最初，OS 线程或机器由 OS 创建和管理。随后，调度器可以请求创建或销毁更多的 OS 线程或机器。这是协程将要执行的实际资源。它还维护有关主协程、当前正在其上运行的 G、**线程本地存储**（**tls**）等信息：

```go
// Denoted as M in runtime 
type m struct { 
    g0               *g         // goroutine with scheduling stack 
    tls               [6]uintptr // thread-local storage (for x86 extern register) 
    curg            *g         // current running goroutine 
    p                 puintptr   // attached p for executing go code (nil if not executing go code) 
    id                 int32 
    createstack [32]uintptr // stack that created this thread. 
    spinning      bool        // m is out of work and is actively looking for work 

    // ... 
} 
```

### 上下文或处理器

我们有一个全局调度器负责启动新的 M，注册 G 和处理系统调用。然而，它不处理协程的实际执行。这是由一个名为**处理器**的实体来完成的，它有自己的内部调度器和一个名为运行队列（代码中的`runq`）的队列，其中包含将在当前上下文中执行的协程。它还处理在各种协程之间的切换等：

```go
// Denoted as P in runtime code 
type p struct { 
    id     int32 
    m     muintptr // back-link to associated m (nil if idle) 
    runq [256]guintptr 

    //... 
} 
```

从 Go 1.5 开始，Go 运行时可以在程序生命周期的任何时刻运行最大数量的`GOMAXPROCS` Ps。当然，我们可以通过设置`GOMAXPROCS`环境变量或调用`GOMAXPROCS()`函数来更改这个数字。

### 使用 G、M 和 P 进行调度

当程序准备开始执行时，运行时已经设置好了机器和处理器。运行时会请求操作系统启动足够数量的机器（M），GOMAXPROCS 数量的处理器来执行 goroutine（G）。重要的是要理解 M 是实际的执行单元，G 是逻辑执行单元。然而，它们需要 P 来实际执行 G 对 M。让我们看一个可能的场景来更好地解释调度过程。首先让我们看看我们将在场景中使用的组件：

+   我们有一组准备运行的 M：M1...Mn

+   我们还有两个 P：P1 和 P2，分别带有运行队列—runq1 和 runq2

+   最后但并非最不重要的，我们还有 20 个 goroutine，G1...G20，我们希望作为程序的一部分执行

Go 的运行时和所有组件，M1...Mn，P1 和 P2，以及 G1...G20，如下图所示：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/dist-cmp-go/img/9389276b-2d9b-4ead-9efb-8f28f5ffec93.png)

鉴于我们有两个处理器，全局调度器理想情况下会在两个处理器之间平均分配 goroutine。假设 P1 被分配为处理 G1...G10 并将它们放入其运行队列，同样 P2 将 G11...G20 放入其运行队列。接下来，P1 的调度器从其运行队列中弹出一个 goroutine 来运行，G1，选择一个机器来运行它，M1，同样 P2 在 M2 上运行 G11。这可以通过以下图示进行说明：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/dist-cmp-go/img/a5f54f92-848d-4ee8-bd6b-bb0d8874a3e0.png)

一个进程的内部调度器还负责将当前的 goroutine 与它想要执行的下一个 goroutine 进行切换。如果一切顺利，调度器会出于以下三个可能的原因之一切换当前的 goroutine：

+   当前执行的时间片已经结束：进程将使用**schedtick**（每次调度器调用时递增）来跟踪当前 goroutine 执行了多长时间，一旦达到一定的时间限制，当前 goroutine 将被放回运行队列，下一个 goroutine 将被选中执行。

+   执行完成：简而言之，goroutine 已经执行完所有指令。在这种情况下，它不会被放回运行队列。

+   等待系统调用：在某些情况下，goroutine 可能需要进行系统调用，结果会导致 goroutine 被阻塞。鉴于我们有一些处理器，阻塞这样一个昂贵的资源是没有意义的。好消息是，在 Go 中，处理器不需要等待系统调用；相反，它可以离开等待的 M 和 G 组合，系统调用后会被全局调度器接管。与此同时，处理器可以从可用的机器中选择另一个 M，从其运行队列中选择另一个 goroutine，并开始执行。这可以通过以下图示进行解释：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/dist-cmp-go/img/27d5e056-2609-4609-8d1c-e0c9437d8e90.png)

前面的图解释了处理器 P1 在机器 M1 上运行 goroutine G1。现在 G1 将开始进行系统调用。这可以通过以下图示进行说明：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/dist-cmp-go/img/a1445b62-98e8-44cb-b0f0-74679a42fb4a.png)

前面的图解释了处理器 P1 由于系统调用从机器 M1 和 goroutine G1 中分离。P1 选择一个新的机器 M5，并选择一个新的 goroutine G9 来执行：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/dist-cmp-go/img/d547d370-30c7-4e37-b22a-28b74e49ea40.png)

在前面的图中，G1-M1 系统调用已经完成。现在 G1 被放回 P1 的运行队列，M1 被添加到空闲机器的集合中。

在本节的最后部分，我们将讨论调度器中实施的另一种策略，称为**work-stealing**。

假设处理器 P1 有 10 个 goroutines，P2 有 10 个 goroutines。然而，事实证明 P1 中的 goroutines 很快就完成了，现在 P1 的运行队列中没有 goroutines 了。如果 P1 空闲并等待全局调度器提供更多工作，那将是一场悲剧。通过工作窃取策略的帮助，P1 开始与其他处理器进行检查，如果另一个处理器的运行队列中有 goroutines，它将“窃取”其中一半并开始执行它们。这确保了我们最大程度地利用了程序的 CPU 使用率。让我们提出两个有趣的问题：

+   如果一个处理器意识到它无法再窃取任何任务怎么办？处理器会等待一小段时间，期望有新的 goroutines，如果没有创建，处理器就会被终止。

+   处理器能否窃取超过一半的运行队列？即使我们有很多处理器在工作，工作窃取策略也总是会窃取目标处理器运行队列的一半。

这可以用以下图示说明：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/dist-cmp-go/img/c4bbff37-03f6-4395-a197-b2506b88d511.png)

上图显示了两个处理器 P1 和 P2，在两台机器上执行各自运行队列中的一个 goroutine。假设当 P1 在运行时，处理器 P2 的任务已经完成。如下图所示：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/dist-cmp-go/img/d6b8362d-5400-407c-bfca-f5b4146abd5e.png)

处理器 P2 已经耗尽了它的运行队列，没有更多的 goroutines 可以执行。多亏了工作窃取策略，P2 已经“窃取”了 P1 运行队列中一半的 goroutines，并可以开始执行它们，如下图所示：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/dist-cmp-go/img/5fdef3cb-e16d-4e5c-8e08-ca3fb705debc.png)

## 在使用 goroutines 时要注意的事项

到这个点，我们应该已经对 goroutines 和调度器的工作原理有了很好的理解。现在让我们来看看在使用 goroutines 时可能会让我们感到意外的一些事情。

### 单个 goroutine 使整个程序停止

我们知道 goroutines 在多个线程和多个核心上运行。那么当一个线程发生 panic 时会发生什么？下面是一个可以让我们模拟这种情况的例子。我们将创建许多类似的 goroutines，它们的唯一目的是取一个数字，并在从分母减去 10 后将其除以自身。这对大多数情况都有效，除了当数字是`10`时。以下代码实现了所描述的功能：

```go
package main 

import ( 
    "fmt" 
    "sync" 
) 

func simpleFunc(index int, wg *sync.WaitGroup) { 
    // This line should fail with Divide By Zero when index = 10 
    fmt.Println("Attempting x/(x-10) where x = ", index, " answer is : ", index/(index-10)) 
    wg.Done() 
} 

func main() { 
    var wg sync.WaitGroup 
    wg.Add(40) 
    for i := 0; i < 40; i += 1 { 
        go func(j int) { 
            simpleFunc(j, &wg) 
        }(i) 
    } 

    wg.Wait() 
}
```

先前代码的输出可能如下所示：

```go
Attempting x/(x-10) where x = 39 answer is : 1 Attempting x/(x-10) where x = 20 answer is : 2... Attempting x/(x-10) where x = 37 answer is : 1 Attempting x/(x-10) where x = 11 answer is : 11 panic: runtime error: integer divide by zerogoroutine 15 [running]:main.simpleFunc(0xa, 0xc42000e280) ...exit status 2
```

基本上，许多 goroutines 被放入运行队列中，并以随机顺序执行，它们的输出被打印到控制台。然而，一旦执行了索引==10 的 goroutine，它引发了一个 panic，该 panic 没有被函数处理，导致整个程序停止并以状态码`2`退出。这表明即使一个未被处理的错误或 panic 也会使整个程序停止！

然而，如果因为我们遇到了一个我们本来可以优雅处理的 panic 而导致程序崩溃是没有意义的。Go 允许我们使用一个名为`recover`的适当命名的函数从 panic 中恢复。让我们看看如何在先前的代码示例中使用`recover`：

```go
package main 

import ( 
    "fmt" 
    "sync" 
) 

func simpleFunc(index int, wg *sync.WaitGroup) { 
    // functions with defer keyword are executed at the end of the function 
    // regardless of whether the function was executed successfully or not. 
    defer func() { 
        if r := recover(); r != nil { 
            fmt.Println("Recovered from", r) 
        } 
    }() 

    // We have changed the order of when wg.Done is called because 
    // we should call upon wg.Done even if the following line fails. 
    // Whether a defer function exists or not is dependent on whether it is registered 
    // before or after the failing line of code. 
    defer wg.Done() 
    // This line should fail with Divide By Zero when index = 10 
    fmt.Println("Attempting x/(x-10) where x = ", index, " answer is : ", index/(index-10)) 
} 

func main() { 
    var wg sync.WaitGroup 
    wg.Add(40) 
    for i := 0; i < 40; i += 1 { 
        go func(j int) { 
            simpleFunc(j, &wg) 
        }(i) 
    } 

    wg.Wait() 
}
```

先前代码的输出可能如下所示：

```go
Attempting x/(x-10) where x = 39 answer is : 1 Attempting x/(x-10) where x = 14 answer is : 3 Recovered from runtime error: integer divide by zero Attempting x/(x-10) where x = 3 answer is : 0 ...Attempting x/(x-10) where x = 29 answer is : 1 Attempting x/(x-10) where x = 9 answer is : -9 
```

### Goroutines 是不可预测的

在本章中，我们首先看了 Go 如何使我们能够编写并发的代码，并在一定程度上实现并行。然后我们讨论了 Go 如何在机器和处理器上调度 goroutines。我们可能能够推断 goroutines 将如何分布在机器和处理器上，这反过来可能让我们编写非标准或 hacky 的 Go 代码。

考虑*并行性*部分的代码，我们试图模拟在听音乐的同时写几封电子邮件。以下是代码的输出，供快速参考：

```go
Done writing mail #3\. 19:32:57
Listening... 19:32:57
Listening... 19:32:57
Done writing mail #1\. 19:32:57
Listening... 19:32:57
Listening... 19:32:57
Done writing mail #2\. 19:32:57
```

现在我们可以很容易地推断出至少有两个 P，其中一个被用于打印`Listening...`的 goroutine，而另一个 P 则处理与写邮件相关的 goroutines。

这一切都很好，但考虑一种情况，即`GOMAXPROCS`设置为`1`，或者系统硬件能力较低，可能导致较少的机器。这可能导致 goroutine 打印`Listening...`永远运行，永远不会将控制权交给其他 goroutines。实际上，Go 编译器应该检测到这种情况，并相应地计划 goroutines 的调度。然而，最好是规划我们的代码，这样我们就不必依赖 Go 的调度器及其当前的实现。

## 总结

Goroutines 是并发的，到一定程度上是并行的；然而，我们应该将它们视为并发。Goroutines 的执行顺序是不可预测的，我们不应该依赖它们按任何特定顺序执行。

我们还应该注意处理 goroutines 中的错误和恐慌，因为即使它们在并行执行，一个 goroutine 中的恐慌也会导致整个程序崩溃。最后，goroutines 可能会在系统调用上阻塞，但这不会阻塞程序的执行，也不会减慢整个程序的性能。

我们看了一些 Go 运行时调度器背后的设计概念，以了解为什么会发生所有这些。

也许你会想为什么我们在本章没有讨论通道。原因是，通过不依赖通道，我们能够以它们最基本的形式来看待 goroutines。这使我们能够更深入地了解 goroutines 的概念和实现。

在下一章中，我们将看一下通道以及它们如何进一步增强 goroutines 的功能。


# 第三章：通道和消息

在第二章中，*理解 Goroutines*，我们看到了 goroutines 的工作原理，如何以并发的方式使用它们，以及可能发生的一些常见错误。它们简单易用，但受限于它们只能生成其他 goroutines 并等待系统调用。实际上，goroutines 比前一章展示的更有能力，为了发挥它们的全部潜力，我们需要了解如何使用通道，这是本章的目标。在这里，我们将讨论以下主题：

+   控制并行性

+   通道和数据通信

+   通道的类型

+   关闭和复用通道

## 控制并行性

我们知道，生成的 goroutines 将尽快开始执行，并以同时的方式执行。然而，当这些 goroutines 需要在一个具有较低限制的共同源上工作时，就会存在固有的风险。这可能导致共同源明显减慢或在某些情况下甚至失败。正如你可能猜到的那样，这在计算机科学领域并不是一个新问题，有许多处理它的方法。正如我们将在整个章节中看到的，Go 提供了一些机制来以简单直观的方式控制并行性。让我们从一个模拟负担共同源问题的例子开始，然后继续解决它。

想象一个收银员需要处理订单，但一天只能处理 10 个订单。让我们看看如何将其作为一个程序来呈现：

```go
// cashier.go 
package main 

import ( 
    "fmt" 
    "sync" 
) 

func main() { 
    var wg sync.WaitGroup 
    // ordersProcessed & cashier are declared in main function 
    // so that cashier has access to shared state variable 'ordersProcessed'. 
    // If we were to declare the variable inside the 'cashier' function, 
    // then it's value would be set to zero with every function call. 
    ordersProcessed := 0 
    cashier := func(orderNum int) { 
        if ordersProcessed < 10 { 
            // Cashier is ready to serve! 
            fmt.Println("Processing order", orderNum) 
            ordersProcessed++ 
        } else { 
            // Cashier has reached the max capacity of processing orders. 
            fmt.Println("I am tired! I want to take rest!", orderNum) 
        } 
        wg.Done() 
    } 

    for i := 0; i < 30; i++ { 
        // Note that instead of wg.Add(60), we are instead adding 1 
        // per each loop iteration. Both are valid ways to add to WaitGroup as long as we can ensure the right number of calls. 
        wg.Add(1) 
        go func(orderNum int) { 
            // Making an order 
            cashier(orderNum) 
        }(i) 

    } 
    wg.Wait() 
} 
```

程序的可能输出如下：

```go
Processing order 29
Processing order 22
Processing order 23
Processing order 13
Processing order 24
Processing order 25
Processing order 21
Processing order 26
Processing order 0
Processing order 27
Processing order 14
I am tired! I want to take rest! 28
I am tired! I want to take rest! 1
I am tired! I want to take rest! 7
I am tired! I want to take rest! 8
I am tired! I want to take rest! 2
I am tired! I want to take rest! 15
...
```

前面的输出显示了一个收银员在接受 10 个订单后不堪重负。然而，值得注意的是，如果你多次运行前面的代码，你可能会得到不同的输出。例如，在某些运行中，所有 30 个订单可能会被处理！

这是因为所谓的**竞争条件**。数据竞争（或竞争条件）发生在多个参与者（在我们的情况下是 goroutines）试图访问和修改一个共享状态时，这会导致 goroutines 的读写不正确。

我们可以尝试以两种方式解决这个问题：

+   增加订单处理限制

+   增加收银员的数量

增加限制只有在一定程度上是可行的，超过这个限制将会开始降低系统的性能，或者在收银员的情况下，工作既不高效也不 100%准确。相反，通过增加收银员的数量，我们可以开始连续处理更多订单，而不改变限制。有两种方法：

+   没有通道的分布式工作

+   使用通道的分布式工作

### 没有通道的分布式工作

为了在收银员之间平均分配工作，我们需要预先知道订单的数量，并确保每个收银员接收的工作都在他/她的限制范围内。这不是最实际的解决方案，因为在现实世界的情况下，我们需要跟踪每个收银员处理了多少订单，并将剩余的订单转给其他收银员。然而，在我们寻找正确解决方法之前，让我们花时间更好地理解无控制并行性的问题，并尝试解决它。以下代码尝试以天真的方式解决它，这应该为我们提供一个良好的开始：

```go
// wochan.go 

package main 

import ( 
   "fmt" 
   "sync" 
) 

func createCashier(cashierID int, wg *sync.WaitGroup) func(int) { 
   ordersProcessed := 0 
   return func(orderNum int) { 
         if ordersProcessed < 10 { 
               // Cashier is ready to serve! 
               //fmt.Println("Cashier ", cashierID, "Processing order", orderNum, "Orders Processed", ordersProcessed) 
               fmt.Println(cashierID, "->", ordersProcessed) 
               ordersProcessed++ 
         } else { 
               // Cashier has reached the max capacity of processing orders. 
               fmt.Println("Cashier ", cashierID, "I am tired! I want to take rest!", orderNum) 
         } 
         wg.Done() 
   } 
} 

func main() { 
   cashierIndex := 0 
   var wg sync.WaitGroup 

   // cashier{1,2,3} 
   cashiers := []func(int){} 
   for i := 1; i <= 3; i++ { 
         cashiers = append(cashiers, createCashier(i, &wg)) 
   } 

   for i := 0; i < 30; i++ { 
         wg.Add(1) 

         cashierIndex = cashierIndex % 3 

         func(cashier func(int), i int) { 
               // Making an order 
               go cashier(i) 
         }(cashiers[cashierIndex], i) 

         cashierIndex++ 
   } 
   wg.Wait() 
} 
```

以下是可能的一个输出：

```go
Cashier 2 Processing order 7
Cashier 1 Processing order 6
Cashier 3 Processing order 8
Cashier 3 Processing order 29
Cashier 1 Processing order 9
Cashier 3 Processing order 2
Cashier 2 Processing order 10
Cashier 1 Processing order 3
...
```

我们将 30 个可用订单分配给收银员`1`、`2`和`3`，所有订单都成功处理，没有人抱怨累了。但是，请注意，使这项工作需要我们付出很多努力。我们必须创建一个函数生成器来创建收银员，通过`cashierIndex`跟踪要使用哪个收银员等等。最糟糕的部分是前面的代码是不正确的！从逻辑上看，它可能看起来是在做我们想要的事情；但是，请注意，我们正在生成多个 goroutine，它们正在处理具有共享状态`ordersProcessed`的变量！这就是我们之前讨论的数据竞争。好消息是我们可以在`wochan.go`中以两种方式检测到它：

+   在`createCashier`函数中，用`fmt.Println(cashierID, "->", ordersProcessed)`替换`fmt.Println("Cashier ", cashierID, "Processing order", orderNum)`。以下是一个可能的输出：

```go
     3 -> 0
     3 -> 1
     1 -> 0
     ...
     2 -> 3
     3 -> 1 # Cashier 3 sees ordersProcessed as 1 but three lines above, Cashier 3 
 was at ordersProcessed == 4!
     3 -> 5
     1 -> 4
     1 -> 4 # Cashier 1 sees ordersProcessed == 4 twice.
     2 -> 4
     2 -> 4 # Cashier 2 sees ordersProcessed == 4 twice.
     ...
```

+   前面的观点证明了代码是不正确的；然而，我们不得不猜测代码中可能存在的问题，然后进行验证。Go 为我们提供了工具来检测数据竞争，这样我们就不必担心这类问题。我们只需使用`-race`标志测试、运行、构建或安装包（在运行的情况下是文件）。让我们在我们的程序上运行它并查看输出：

```go
      $ go run -race wochan.go 
      Cashier 1 Processing order 0
      Cashier 2 Processing order 1
      ==================
      WARNING: DATA RACE
      Cashier 3 Processing order 2
      Read at 0x00c4200721a0 by goroutine 10:
      main.createCashier.func1()
     wochan.go:11 +0x73

      Previous write at 0x00c4200721a0 by goroutine 7:
      main.createCashier.func1()
     wochan.go:14 +0x2a7

      Goroutine 10 (running) created at:
      main.main.func1()
     wochan.go:40 +0x4a
      main.main()
     wochan.go:41 +0x26e

      Goroutine 7 (finished) created at:
      main.main.func1()
     wochan.go:40 +0x4a
      main.main()
     wochan.go:41 +0x26e
      ==================
      Cashier 2 Processing order 4
      Cashier 3 Processing order 5
      ==================
      WARNING: DATA RACE
      Read at 0x00c420072168 by goroutine 9:
      main.createCashier.func1()
     wochan.go:11 +0x73

      Previous write at 0x00c420072168 by goroutine 6:
      main.createCashier.func1()
     wochan.go:14 +0x2a7

      Goroutine 9 (running) created at:
      main.main.func1()
     wochan.go:40 +0x4a
      main.main()
     wochan.go:41 +0x26e

      Goroutine 6 (finished) created at:
      main.main.func1()
     wochan.go:40 +0x4a
      main.main()
     wochan.go:41 +0x26e
      ==================
      Cashier 1 Processing order 3
      Cashier 1 Processing order 6
      Cashier 2 Processing order 7
      Cashier 3 Processing order 8
      ...
      Found 2 data race(s)
      exit status 66
```

如图所示，`-race`标志帮助我们检测数据竞争。

这是否意味着当我们有共享状态时我们无法分配我们的任务？当然可以！但是我们需要使用 Go 提供的机制来实现这一目的：

+   互斥锁、信号量和锁

+   通道

互斥锁是一种互斥锁，它为我们提供了一种同步机制，允许只有一个 goroutine 在任何给定时间访问特定的代码或共享状态。正如已经说明的，对于同步问题，我们可以使用互斥锁或通道，Go 建议使用正确的构造来解决正确的问题。然而，在实践中，使用通道为我们提供了更高级的抽象和更大的灵活性，尽管互斥锁也有其用途。因此，在本章和本书中，我们将使用通道。

### 使用通道进行分布式工作

现在我们对三件事情很确定：我们想要正确地将订单分配给收银员，我们想要确保每个收银员处理正确数量的订单，我们想要使用通道来解决这个问题。在解决使用通道解决收银员问题之前，让我们先看一下通道的基本语法和用法。

#### 什么是通道？

通道是一种通信机制，允许我们在 goroutine 之间传递数据。它是 Go 中的内置数据类型。数据可以使用原始数据类型之一传递，或者我们可以使用结构创建自己的复杂数据类型。

以下是一个简单的示例，演示如何使用通道：

```go
// simchan.go 
package main 

import "fmt" 

// helloChan waits on a channel until it gets some data and then prints the value. 
func helloChan(ch <- chan string) { 
    val := <- ch 
    fmt.Println("Hello, ", val) 
} 

func main() { 
    // Creating a channel 
    ch := make(chan string) 

    // A Goroutine that receives data from a channel 
    go helloChan(ch) 

    // Sending data to a channel. 
    ch <- "Bob" 
} 
```

如果我们运行前面的代码，它将打印以下输出：

```go
Hello, Bob
```

使用通道的基本模式可以通过以下步骤来解释：

1.  创建通道以接受要处理的数据。

1.  启动等待通道数据的 goroutine。

1.  然后，我们可以使用`main`函数或其他 goroutine 将数据传递到通道中。

1.  监听通道的 goroutine 可以接受数据并处理它们。

使用通道的优势在于多个 goroutine 可以在同一个通道上等待并同时执行任务。

#### 使用 goroutine 解决收银员问题

在尝试解决问题之前，让我们首先制定我们想要实现的目标：

1.  创建一个接受所有订单的通道`orderChannel`。

1.  启动所需数量的收银员 goroutine，从`orderChannel`接受有限数量的订单。

1.  开始将所有订单放入`orderChannel`。

让我们看一个可能的解决方案，试图使用前面的步骤解决收银员问题：

```go
// wichan.go 
package main 

import ( 
    "fmt" 
    "sync" 
) 

func cashier(cashierID int, orderChannel <-chan int, wg *sync.WaitGroup) { 
    // Process orders upto limit. 
    for ordersProcessed := 0; ordersProcessed < 10; ordersProcessed++ { 
        // Retrieve order from orderChannel 
        orderNum := <-orderChannel 

        // Cashier is ready to serve! 
        fmt.Println("Cashier ", cashierID, "Processing order", orderNum, "Orders Processed", ordersProcessed) 
        wg.Done() 
    } 
} 

func main() { 
    var wg sync.WaitGroup 
    wg.Add(30) 
    ordersChannel := make(chan int) 

    for i := 0; i < 3; i++ { 
        // Start the three cashiers 
        func(i int) { 
            go cashier(i, ordersChannel, &wg) 
        }(i) 
    } 

    // Start adding orders to be processed. 
    for i := 0; i < 30; i++ { 
        ordersChannel <- i 
    } 
    wg.Wait() 
} 
```

通过使用`-race`标志运行前面的代码，我们可以看到代码在没有任何数据竞争的情况下运行：

```go
$ go run -race wichan.go 
Cashier 2 Processing order 2 Orders Processed 0
Cashier 2 Processing order 3 Orders Processed 1
Cashier 0 Processing order 0 Orders Processed 0
Cashier 1 Processing order 1 Orders Processed 0
...
Cashier 0 Processing order 27 Orders Processed 9
```

代码非常简单，易于并行化，并且在不引起任何数据竞争的情况下运行良好。

## 通道和数据通信

Go 是一种静态类型的语言，这意味着给定的通道只能发送或接收单一数据类型的数据。在 Go 的术语中，这被称为通道的**元素类型**。Go 通道将接受任何有效的 Go 数据类型，包括函数。以下是一个接受和调用函数的简单程序的示例：

```go
// elems.go 
package main 

import "fmt" 

func main() { 
    // Let's create three simple functions that take an int argument 
    fcn1 := func(i int) { 
        fmt.Println("fcn1", i) 
    } 
    fcn2 := func(i int) { 
        fmt.Println("fcn2", i*2) 
    } 
    fcn3 := func(i int) { 
        fmt.Println("fcn3", i*3) 
    } 

    ch := make(chan func(int)) // Channel that sends & receives functions that take an int argument 
    done := make(chan bool)    // A Channel whose element type is a boolean value. 

    // Launch a goroutine to work with the channels ch & done. 
    go func() { 
        // We accept all incoming functions on Channel ch and call the functions with value 10\. 
        for fcn := range ch { 
            fcn(10) 
        } 
        // Once the loop terminates, we print Exiting and send true to done Channel. 
        fmt.Println("Exiting") 
        done <- true 
    }() 

    // Sending functions to channel ch 
    ch <- fcn1 
    ch <- fcn2 
    ch <- fcn3 

    // Close the channel once we are done sending it data. 
    close(ch) 

    // Wait on the launched goroutine to end. 
    <-done 
} 
```

前面的代码的输出如下：

```go
fcn1 10
fcn2 20
fcn3 30
Exiting
```

在前面的代码示例中，我们说通道`ch`的元素类型为`func(int)`，通道`done`的元素类型为`bool`。代码中还有很多有趣的细节，但我们将在接下来的部分讨论它们。

### 消息和事件

到目前为止，我们一直在使用术语*数据*来指代从通道发送和接收的值。虽然到目前为止这可能很容易理解，但 Go 使用两个特定的术语来描述通过通道进行通信的数据类型。它们被称为**消息**和**事件**。在代码方面它们是相同的，但这些术语用于帮助我们理解被发送的数据的*类型*。简而言之：

+   消息通常是我们希望 goroutine 处理并在需要时对其进行操作的值。

+   事件用于表示某个*事件*已发生。接收到的实际值可能并不像接收值的行为那样重要。请注意，尽管我们使用术语*事件*，它们仍然是一种*消息*类型。

在前面的代码示例中，发送到`ch`的值是消息，而发送到`done`的值是事件。需要注意的重要一点是，事件通道的元素类型往往是`struct{}{}`、`bool`或`int`。

现在我们了解了通道元素类型、消息和事件是什么，让我们来看看不同类型的通道。

## 通道的类型

Go 为我们提供了三种主要的通道类型变体。它们可以被广泛地分类为：

+   无缓冲

+   缓冲

+   单向（只发送和只接收类型的通道）

### 无缓冲通道

这是 Go 中可用的基本通道类型。使用起来非常简单——我们将数据发送到通道，然后在另一端接收数据。有趣的部分是，任何在无缓冲通道上操作的 goroutine 都将被阻塞，直到发送方和接收方的 goroutine 都可用。例如，考虑以下代码片段：

```go
ch := make(chan int) 
go func() {ch <- 100}     // Send 100 into channel.                
                             Channel: send100          
go func() {val := <- ch}  // Goroutine waiting on channel.        
                             Channel: recv1         
go func() {val := <- ch}  // Another goroutine waiting on channel.
                             Channel: recv2
```

我们有一个元素类型为`int`的通道`ch`。我们启动了三个 goroutine；一个将消息`100`发送到通道（`send100`），另外两个 goroutine（`recv1`和`recv2`）在通道上等待。`send100`被阻塞，直到`recv1`或`recv2`中的任一个开始监听通道以接收消息。如果我们假设`recv2`接收了由`send100`发送到通道的消息，那么`recv1`将等待，直到在通道上发送另一条消息。如果前面的四行是通道上的唯一通信，那么`recv1`将等待直到程序结束，然后将被 Go 运行时突然终止。

### 缓冲通道

考虑这样一种情况，我们能够向通道发送的消息比接收消息的 goroutine 处理的消息多。如果我们使用无缓冲通道，程序将显著减慢，因为我们必须等待每条消息被处理后才能放入另一条消息。如果通道能够存储这些额外的消息或“缓冲”消息，那将是理想的。这正是缓冲通道所做的。它维护一个消息队列，goroutine 将以自己的速度消耗它。然而，即使缓冲通道也有限制容量；我们需要在通道创建时定义队列的容量。

那么，我们如何使用带缓冲的通道呢？从语法上讲，它与使用无缓冲通道是相同的。带缓冲通道的行为可以解释如下：

+   **如果带缓冲通道为空**：在通道上接收消息将被阻塞，直到通过通道发送消息

+   **如果带缓冲通道已满**：在通道上发送消息将被阻塞，直到至少从通道接收到一条消息，从而为新消息腾出空间放在通道的缓冲区或队列中

+   **如果带缓冲通道部分填充，即既不满也不空**：在通道上发送或接收消息都不会被阻塞，通信是瞬时的

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/dist-cmp-go/img/c3be325a-235f-4cb6-9c5e-61393adb9827.png)

通过带缓冲通道进行通信

### 单向缓冲

消息可以从通道发送和接收。然而，当 goroutine 使用通道进行通信时，它们通常只用于单一目的：要么从通道发送，要么接收。Go 允许我们指定 goroutine 使用的通道是用于发送还是接收消息。它通过单向通道的帮助来实现这一点。一旦通道被标识为单向，我们就不能对其执行其他操作。这意味着单向发送通道不能用于接收消息，单向接收通道不能用于发送消息。任何尝试这样做的行为都将被 Go 编译器识别为编译时错误。

以下是正确使用单向通道的示例：

```go
// unichans.go 
package main 

import ( 
    "fmt" 
    "sync" 
) 

func recv(ch <-chan int, wg *sync.WaitGroup) { 
    fmt.Println("Receiving", <-ch) 
    wg.Done() 
} 

func send(ch chan<- int, wg *sync.WaitGroup) { 
    fmt.Println("Sending...") 
    ch <- 100 
    fmt.Println("Sent") 
    wg.Done() 
} 

func main() { 
    var wg sync.WaitGroup 
    wg.Add(2) 

    ch := make(chan int) 
    go recv(ch, &wg) 
    go send(ch, &wg) 

    wg.Wait() 
} 
```

预期输出将如下所示：

```go
Sending...
Receiving 100 # (or) Sent
Sent # (or) Receiving 100  
```

现在，让我们尝试在接收通道上发送消息并看看会发生什么。我们只会在前面的示例中看到更改的函数：

```go
// unichans2.go 
// ... 
// Changed function 
func recv(ch <-chan int, wg *sync.WaitGroup) { 
    fmt.Println("Receiving", <-ch) 
    fmt.Println("Trying to send") // signalling that we are going to send over channel. 
    ch <- 13                      // Sending over channel 
    wg.Done() 
} 
```

现在，如果我们尝试运行或构建更新后的程序，我们将会得到以下错误：

```go
$ go run unichans.go 
# command-line-arguments
unichans.go:11: invalid operation: ch <- 13 (send to receive-only type <-chan int)  
```

那么，如果我们使用带缓冲的通道，程序会如何行为？由于未填充的通道不会阻塞，`send` 协程将消息发送到通道，然后继续执行。`recv` 协程在开始执行时从通道中读取，然后打印它：

```go
// buffchan.go 
package main 

import ( 
    "fmt" 
    "sync" 
) 

func recv(ch <-chan int, wg *sync.WaitGroup) { 
    fmt.Println("Receiving", <-ch) 
    wg.Done() 
} 

func send(ch chan<- int, wg *sync.WaitGroup) { 
    fmt.Println("Sending...") 
    ch <- 100 
    fmt.Println("Sent") 
    wg.Done() 
} 

func main() { 
    var wg sync.WaitGroup 
    wg.Add(2) 

    // Using a buffered channel. 
    ch := make(chan int, 10) 
    go recv(ch, &wg) 
    go send(ch, &wg) 

    wg.Wait() 
} 
```

输出将如下所示：

```go
Sending...
Sent
Receiving 100
```

## 关闭通道

在前面的部分中，我们已经看过三种类型的通道以及如何创建它们。在本节中，让我们看看如何关闭通道以及这可能会影响在这些通道上发送和接收消息。当我们不再想在通道上发送任何消息时，我们关闭通道。通道关闭后的行为对于每种类型的通道都是不同的。让我们深入了解一下：

+   **无缓冲关闭通道**：发送消息将导致恐慌，接收消息将立即产生通道元素类型的零值。

+   **带缓冲关闭通道**：发送消息将导致恐慌，但在通道的队列中首先产生所有值。一旦队列耗尽，通道将开始产生通道元素类型的零值。

以下是一个阐述前两点的程序：

```go
// closed.go 
package main 

import "fmt" 

type msg struct { 
    ID    int 
    value string 
} 

func handleIntChan(intChan <-chan int, done chan<- int) { 
    // Even though there are only 4 elements being sent via channel, we retrieve 6 values. 
    for i := 0; i < 6; i++ { 
        fmt.Println(<-intChan) 
    } 
    done <- 0 
} 

func handleMsgChan(msgChan <-chan msg, done chan<- int) { 
    // We retrieve 6 values of element type struct 'msg'. 
    // Given that there are only 4 values in the buffered channel, 
    // the rest should be zero value of struct 'msg'. 
    for i := 0; i < 6; i++ { 
        fmt.Println(fmt.Sprintf("%#v", <-msgChan)) 
    } 
    done <- 0 
} 

func main() { 
    intChan := make(chan int) 
    done := make(chan int) 

    go func() { 
        intChan <- 9 
        intChan <- 2 
        intChan <- 3 
        intChan <- 7 
        close(intChan) 
    }() 
    go handleIntChan(intChan, done) 

    msgChan := make(chan msg, 5) 
    go func() { 
        for i := 1; i < 5; i++ { 
            msgChan <- msg{ 
                ID:    i, 
                value: fmt.Sprintf("VALUE-%v", i), 
            } 
        } 
        close(msgChan) 
    }() 
    go handleMsgChan(msgChan, done) 

    // We wait on the two channel handler goroutines to complete. 
    <-done 
    <-done 

    // Since intChan is closed, this will cause a panic to occur. 
    intChan <- 100 
} 
```

程序的一个可能输出如下：

```go
9
2
3
7
0
0
main.msg{ID:1, value:"VALUE-1"}
main.msg{ID:2, value:"VALUE-2"}
main.msg{ID:3, value:"VALUE-3"}
main.msg{ID:4, value:"VALUE-4"}
main.msg{ID:0, value:""}
main.msg{ID:0, value:""}
panic: send on closed channel

goroutine 1 [running]:
main.main()
     closed.go:58 +0x194

    Process finished with exit code 2

```

最后，以下是一些有关关闭通道和已关闭通道的进一步有用的要点：

+   无法确定通道是否已关闭。我们能做的最好的事情是检查我们是否能够成功地从通道中检索到消息。我们知道检索通道的默认语法是 `msg := <- ch`。然而，还有一种检索的变体：`msg, ok := <-ch`。第二个参数告诉我们检索是否成功。如果通道关闭，`ok` 将为 `false`。这可以用来告诉通道何时已关闭。

+   `msg, ok := <-ch` 是在迭代通道时的常见模式。因此，Go 允许我们对通道进行`range`。当通道关闭时，`range`循环结束。

+   关闭已关闭的通道、空通道或只接收通道将导致恐慌。只有双向通道或只发送通道可以关闭。

+   关闭通道并不是强制性的，对于垃圾收集器（GC）也是无关紧要的。如果 GC 确定通道不可达，无论通道是打开的还是关闭的，通道都将被垃圾回收。

## 多路复用通道

多路复用描述了我们使用单一资源来对多个信号或操作进行操作的方法。这种方法在电信和计算机网络中被广泛使用。我们可能会发现自己处于这样一种情况：我们有多种类型的任务需要执行。但是，它们只能在互斥状态下执行，或者它们需要在共享资源上工作。为此，我们使用 Go 中称为通道多路复用的模式。在深入讨论如何实际多路复用通道之前，让我们尝试自己实现它。

假设我们有一组通道，并且我们希望在数据发送到通道时立即对其进行操作。以下是我们希望这样做的一种天真的方法：

```go
// naiveMultiplexing.go 
package main 

import "fmt" 

func main() { 
    channels := 5{ 
        make(chan int), 
        make(chan int), 
        make(chan int), 
        make(chan int), 
        make(chan int), 
    } 

    go func() { 
        // Starting to wait on channels 
        for _, chX := range channels { 
            fmt.Println("Receiving from", <- chX) 
        } 
    }() 

    for i := 1; i < 6; i++ { 
        fmt.Println("Sending on channel:", i) 
        channels[i] <- 1 
    } 
} 
```

前面程序的输出如下：

```go
Sending on channel: 1
fatal error: all goroutines are asleep - deadlock!

goroutine 1 [chan send]:
main.main()
 /home/entux/Documents/Code/GO-WORKSPACE/src/distributed-go/ch3/naiveSwitch.go:23 +0x2b1

goroutine 5 [chan receive]:
main.main.func1(0xc4200160c0, 0xc420016120, 0xc420016180, 0xc4200161e0, 0xc420016240)
 GO-WORKSPACE/src/distributed-go/ch3/naiveSwitch.go:17 +0xba
created by main.main
 GO-WORKSPACE/src/distributed-go/ch3/naiveSwitch.go:19 +0x18b

```

在 goroutine 中的循环中，第一个通道从未被等待，这导致了 goroutine 中的死锁。多路复用帮助我们在多个通道上等待，而不会在任何通道上阻塞，同时在通道上有消息时对其进行操作。

在多路复用通道时，有一些重要的要点需要记住：

+   **语法**：

```go
      select { 
      case <- ch1: 
        // Statements to execute if ch1 receives a message 
      case val := <- ch2: 
        // Save message received from ch2 into a variable and
        execute statements for ch2 
      }
```

+   在执行`select`时，可能会有多个`case`准备好接收消息。在这种情况下，`select`不会执行所有`case`，而是随机选择一个执行，然后退出`select`语句。

+   然而，如果我们希望在`select`语句的`case`中对发送到所有通道的消息做出反应，前面的观点可能会受到限制。然后我们可以将`select`语句放在`for`循环中，它将确保处理所有消息。

+   尽管`for`循环将处理发送到所有通道的消息，但循环仍会被阻塞，直到有消息可用。可能存在我们不希望阻塞循环迭代，而是执行一些“默认”操作的情况。这可以通过`select`语句中的`default` case 来实现。

+   基于前面两点的更新语法是：

```go
      for { 
        select { 
            case <- ch1: 
            // Statements to execute if ch1 receives a message 
            case val := <- ch2: 
            // Save message received from ch2 into a variable and
            execute statements for ch2 
            default: 
            // Statements to execute if none of the channels has yet
            received a message. 
        } 
      } 
```

+   对于缓冲通道，接收消息的顺序不是保证的。

以下是在不被任何通道阻塞的情况下对所有所需通道进行多路复用的正确方法，并继续处理发送的所有消息：

```go
// multiplexing.go 

package main 

import ( 
    "fmt" 
) 

func main() { 
    ch1 := make(chan int) 
    ch2 := make(chan string) 
    ch3 := make(chan int, 3) 
    done := make(chan bool) 
    completed := make(chan bool) 

    ch3 <- 1 
    ch3 <- 2 
    ch3 <- 3 
    go func() { 
        for { 

            select { 
                case <-ch1: 
                      fmt.Println("Received data from ch1") 
                case val := <-ch2: 
                      fmt.Println(val) 
                case c := <-ch3: 
                      fmt.Println(c) 
                case <-done: 
                      fmt.Println("exiting...") 
                      completed <- true 
                      return 
            } 
        } 
    }() 

    ch1 <- 100 
    ch2 <- "ch2 msg" 
    // Uncomment us to avoid leaking the 'select' goroutine! 
    //close(done) 
    //<-completed 
} 
```

以下是前面程序的输出：

```go
1
Received data from ch1
2
3
```

不幸的是，该程序存在一个缺陷：它泄漏了处理`select`的 goroutine。这也在`main`函数末尾附近的注释中指出。当我们有一个正在运行但无法直接访问的 goroutine 时，通常会发生这种情况。即使 goroutine 的引用未被存储，GC 也不会对其进行垃圾回收。因此，我们需要一种机制来停止并从这样的 goroutine 返回。通常，这可以通过创建一个专门用于从 goroutine 返回的通道来实现。

在前面的代码中，我们通过`done`通道发送信号。如果我们取消注释这些行然后运行程序，输出将如下：

```go
1
2
3
Received data from ch1
ch2 msg
exiting...
```

## 总结

在本章中，我们探讨了控制并行性的原因，并对涉及共享状态的任务的复杂性有了更深入的了解。我们以一个超负荷的收银员的例子作为一个需要解决的编程问题，并通过通道进行实验，并进一步探讨了不同类型的通道以及使用它们涉及的微妙之处。例如，我们看到关闭的缓冲通道和非缓冲通道都会在我们尝试向它们发送消息时引发恐慌，并且从它们接收消息会根据通道是缓冲的以及通道是空的还是满的而导致不同的结果。我们还看到了如何在不阻塞任何通道的情况下等待多个通道上的消息的方法。

在后面的章节中，从第五章 *介绍 Goophr* 到第八章 *部署 Goophr*，我们将开发一个分布式网络应用。这需要我们具备基本的知识，如何使用 HTTP 协议与网络服务器进行交互，而不是使用网络浏览器。这些知识不仅在与我们的应用程序交互时会派上用场，而且在作为开发人员与标准网络交互时也会派上用场。这将是下一章第四章 *RESTful 网络* 的主题，我们将看看我们将使用的工具和协议来与我们的网络应用程序进行交互。
