# Docker Windows 教程（一）

> 原文：[`zh.annas-archive.org/md5/51C8B846C280D9811810C638FA10FD64`](https://zh.annas-archive.org/md5/51C8B846C280D9811810C638FA10FD64)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 前言

容器是运行软件的新方式。它们高效、安全、可移植，您可以在 Docker 中运行 Windows 应用程序而无需进行代码更改。Docker 帮助您应对 IT 中的最大挑战：现代化传统应用程序、构建新应用程序、迁移到云端、采用 DevOps 并保持创新。

本书将教会您有关 Windows 上 Docker 的一切，从基础知识到在生产环境中运行高可用负载。您将通过一个 Docker 之旅，从关键概念和在 Windows 上的.NET Framework 和.NET Core 应用程序的简单示例开始。然后，您将学习如何使用 Docker 来现代化传统的 ASP.NET 和 SQL Server 应用程序的架构和开发。

这些示例向您展示了如何将传统的单片应用程序拆分为分布式应用程序，并将它们部署到云端的集群环境中，使用与本地运行时完全相同的构件。您将了解如何构建使用 Docker 来编译、打包、测试和部署应用程序的 CI/CD 流水线。为了帮助您自信地进入生产环境，您将学习有关 Docker 安全性、管理和支持选项的知识。

本书最后将指导您如何在自己的项目中开始使用 Docker。您将学习一些 Docker 实施的真实案例，从小规模的本地应用到在 Azure 上运行的大规模应用。

# 本书适合对象

如果您想要现代化旧的单片应用程序而不必重写它，平稳地部署到生产环境，或者迁移到 DevOps 或云端，那么 Docker 就是您的实现者。本书将为您提供 Docker 的扎实基础，让您能够自信地应对所有这些情况。

# 要充分利用本书

本书附带了大量代码，存储在 GitHub 的`sixeyed/docker-on-windows`仓库中。要使用这些示例，您需要：

+   Windows 10 与 1809 更新，或 Windows Server 2019

+   Docker 版本 18.09 或更高

# 下载示例代码文件

您可以从您在[www.packt.com](http://www.packt.com)的账户中下载本书的示例代码文件。如果您在其他地方购买了本书，您可以访问[www.packt.com/support](http://www.packt.com/support)并注册，文件将直接通过电子邮件发送给您。

您可以按照以下步骤下载代码文件：

1.  在[www.packt.com](http://www.packt.com)上登录或注册。

1.  选择“支持”选项卡。

1.  点击“代码下载和勘误”。

1.  在搜索框中输入书名，然后按照屏幕上的说明操作。

下载文件后，请确保使用最新版本的解压或提取文件夹：

+   WinRAR/7-Zip for Windows

+   Zipeg/iZip/UnRarX for Mac

+   7-Zip/PeaZip for Linux

该书的代码包也托管在 GitHub 上：[`github.com/PacktPublishing/Docker-on-Windows-Second-Edition`](https://github.com/PacktPublishing/Docker-on-Windows-Second-Edition)。如果代码有更新，将在现有的 GitHub 存储库中更新。

我们还有来自我们丰富书籍和视频目录的其他代码包，可在**[`github.com/PacktPublishing/`](https://github.com/PacktPublishing/)**上找到。去看看吧！

代码包也可以在作者的 GitHub 存储库中找到：[`github.com/sixeyed/docker-on-windows/tree/second-edition`](https://github.com/sixeyed/docker-on-windows/tree/second-edition)。

# 下载彩色图像

我们还提供了一个 PDF 文件，其中包含本书中使用的屏幕截图/图表的彩色图像。你可以在这里下载：`www.packtpub.com/sites/default/files/downloads/9781789617375_ColorImages.pdf`。

# 使用的约定

本书中使用了许多文本约定。

`CodeInText`：表示文本中的代码词，数据库表名，文件夹名，文件名，文件扩展名，路径名，虚拟 URL，用户输入和 Twitter 句柄。这是一个例子：“作为 Azure 门户的替代方案，你可以使用`az`命令行来管理 DevTest 实验室。”

代码块设置如下：

```
<?xml version="1.0" encoding="utf-8"?> <configuration>
  <appSettings  configSource="config\appSettings.config"  />
  <connectionStrings  configSource="config\connectionStrings.config"  /> </configuration>
```

任何命令行输入或输出都以以下方式编写：

```
> docker version
```

**粗体**：表示一个新术语，一个重要的词，或者你在屏幕上看到的词。例如，菜单或对话框中的单词会以这种方式出现在文本中。这是一个例子：“在你做任何其他事情之前，你需要选择切换到 Windows 容器…”

警告或重要提示会以这种方式出现。提示和技巧会以这种方式出现。


# 第一部分：理解 Docker 和 Windows 容器

本节向读者介绍了 Docker 中的所有关键概念——容器、镜像、注册表和集群。读者将学习应用程序如何在容器中运行，以及如何为 Docker 打包他们自己的应用程序。

本节包括以下章节：

+   第一章，*在 Windows 上开始使用 Docker*

+   第二章，*在 Docker 容器中打包和运行应用程序*

+   第三章，*开发 Docker 化的.NET Framework 和.NET Core 应用程序*

+   第四章，*与 Docker 注册表共享镜像*


# 第一章：在 Windows 上使用 Docker 入门

Docker 是一个应用平台。这是一种在隔离的轻量级单元中运行应用程序的新方法，称为**容器**。容器是运行应用程序的一种非常高效的方式 - 比**虚拟机**（**VMs**）或裸机服务器要高效得多。容器在几秒钟内启动，并且不会增加应用程序的内存和计算需求。Docker 对其可以运行的应用程序类型完全不可知。您可以在一个容器中运行全新的.NET Core 应用程序，在另一个容器中运行 10 年前的 ASP.NET 2.0 WebForms 应用程序，这两个容器可以在同一台服务器上。

容器是隔离的单元，但它们可以与其他组件集成。您的 WebForms 容器可以访问托管在.NET Core 容器中的 REST API。您的.NET Core 容器可以访问在容器中运行的 SQL Server 数据库，或者在单独的机器上运行的 SQL Server 实例。您甚至可以设置一个混合 Linux 和 Windows 机器的集群，所有这些机器都运行 Docker，并且 Windows 容器可以透明地与 Linux 容器通信。

无论大小，公司都在转向 Docker 以利用这种灵活性和效率。Docker，Inc. - Docker 平台背后的公司 - 的案例研究显示，通过转向 Docker，您可以减少 50%的硬件需求，并将发布时间缩短 90%，同时仍然保持应用程序的高可用性。这种显著的减少同样适用于本地数据中心和云。

效率并不是唯一的收获。当您将应用程序打包到 Docker 中运行时，您会获得可移植性。您可以在笔记本电脑上的 Docker 容器中运行应用程序，并且它将在数据中心的服务器和任何云中的 VM 上表现完全相同。这意味着您的部署过程简单且无风险，因为您正在部署您已经测试过的完全相同的构件，并且您还可以自由选择硬件供应商和云提供商。

另一个重要的动机是安全性。容器在应用程序之间提供了安全隔离，因此您可以放心，如果一个应用程序受到攻击，攻击者无法继续攻击同一主机上的其他应用程序。平台还有更广泛的安全性好处。Docker 可以扫描打包应用程序的内容，并提醒您应用程序堆栈中的安全漏洞。您还可以对容器映像进行数字签名，并配置 Docker 仅从您信任的映像作者运行容器。

Docker 是由开源组件构建的，并作为**Docker 社区版**（**Docker CE**）和**Docker 企业版**提供。Docker CE 是免费使用的，并且每月发布。Docker 企业版是付费订阅；它具有扩展功能和支持，并且每季度发布。Docker CE 和 Docker 企业版都可在 Windows 上使用，并且两个版本使用相同的基础平台，因此您可以以相同的方式在 Docker CE 和 Docker 企业版上运行应用程序容器。

本章让您快速上手 Docker 容器。它涵盖了：

+   Docker 和 Windows 容器

+   理解关键的 Docker 概念

+   在 Windows 上运行 Docker

+   通过本书了解 Docker

# 技术要求

您可以使用 GitHub 存储库[`github.com/sixeyed/docker-on-windows/tree/second-edition/ch01`](https://github.com/sixeyed/docker-on-windows/tree/second-edition/ch01)中的代码示例来跟随本书。您将在本章中学习如何安装 Docker - 唯一的先决条件是 Windows 10 并安装了 1809 微软更新，或者 Windows Server 2019。

# Docker 和 Windows 容器

Docker 最初是在 Linux 上开发的，利用了核心 Linux 功能，但使得在应用工作负载中使用容器变得简单高效。微软看到了潜力，并与 Docker 工程团队密切合作，将相同的功能带到了 Windows 上。

Windows Server 2016 是第一个可以运行 Docker 容器的 Windows 版本；Windows Server 2019 通过显著改进的功能和性能继续创新 Windows 容器。您可以在 Windows 10 上运行相同的 Docker 容器进行开发和测试，就像在生产环境中在 Windows Server 上运行一样。目前，您只能在 Windows 上运行 Windows 应用程序容器，但微软正在增加对在 Windows 上运行 Linux 应用程序容器的支持。

首先，您需要知道的是容器与 Windows UI 之间没有集成。容器仅用于服务器端应用工作负载，如网站、API、数据库、消息队列、消息处理程序和控制台应用程序。您不能使用 Docker 来运行客户端应用程序，比如.NET WinForms 或 WPF 应用程序，但您可以使用 Docker 来打包和分发应用程序，这将为您所有的应用程序提供一致的构建和发布流程。

在 Windows Server 2019 和 Windows 10 上运行容器的方式也有所不同。使用 Docker 的用户体验是相同的，但容器托管的方式不同。在 Windows Server 上，服务应用程序的进程实际上在服务器上运行，并且容器和主机之间没有层。在容器中，您可能会看到`w3wp.exe`运行以提供网站服务，但该进程实际上在服务器上运行 - 如果您运行了 10 个 Web 容器，您将在服务器的任务管理器中看到 10 个`w3wp.exe`实例。

Windows 10 与 Windows Server 2019 没有相同的操作系统内核，因此为了为容器提供 Windows Server 内核，Windows 10 在一个非常轻量的虚拟机中运行每个容器。这些被称为**Hyper-V 容器**，如果您在 Windows 10 上的容器中运行 Web 应用程序，您将看不到`w3wp.exe`在主机上运行 - 它实际上在 Hyper-V 容器中的专用 Windows Server 内核中运行。

这是默认行为，但在最新版本的 Windows 和 Docker 中，您可以在 Windows 10 上运行 Windows Server 容器，因此您可以跳过为每个容器运行 VM 的额外开销。

了解 Windows Server 容器和 Hyper-V 容器之间的区别是很重要的。您可以为两者使用相同的 Docker 工件和相同的 Docker 命令，因此流程是相同的，但使用 Hyper-V 容器会有轻微的性能损失。在本章的后面，我将向您展示在 Windows 上运行 Docker 的选项，您可以选择最适合您的方法。

# Windows 版本

Windows Server 容器中的应用程序直接在主机上运行进程，并且服务器上的 Windows 版本需要与容器内的 Windows 版本匹配。本书中的所有示例都基于使用 Windows Server 2019 的容器，这意味着您需要一台 Windows Server 2019 机器来运行它们，或者使用安装了 1809 更新的 Windows 10（`winver`命令将告诉您您的更新版本）。

您可以将为不同版本的 Windows 构建的容器作为 Hyper-V 容器运行。这样可以实现向后兼容性，因此您可以在运行 Windows Server 2019 的计算机上运行为 Windows Server 2016 构建的容器。

# Windows 许可

Windows 容器与运行 Windows 的服务器或虚拟机没有相同的许可要求。Windows 的许可是在主机级别而不是容器级别。如果在一台服务器上运行了 100 个 Windows 容器，您只需要为服务器购买一个许可证。如果您目前使用虚拟机来隔离应用程序工作负载，那么可以节省相当多的费用。去除虚拟机层并直接在服务器上运行应用程序容器可以消除所有虚拟机的许可要求，并减少所有这些机器的管理开销。

Hyper-V 容器有单独的许可。在 Windows 10 上，您可以运行多个容器，但不能用于生产部署。在 Windows Server 上，您还可以以 Hyper-V 模式运行容器以增加隔离性。这在多租户场景中很有用，其中您需要预期和减轻敌对工作负载。Hyper-V 容器是单独许可的，在高容量环境中，您需要 Windows Server 数据中心许可证才能运行 Hyper-V 容器而不需要单独的许可证。

微软和 Docker 公司合作，为 Windows Server 2016 和 Windows Server 2019 提供免费的 Docker Enterprise。Windows Server 许可证的价格包括 Docker Enterprise Engine，这使您可以获得在容器中运行应用程序的支持。如果您在容器或 Docker 服务方面遇到问题，可以向微软提出，并且他们可以将问题升级给 Docker 的工程师。

# 理解关键的 Docker 概念

Docker 是一个非常强大但非常简单的应用程序平台。你可以在短短几天内开始在 Docker 中运行你现有的应用程序，并在另外几天内准备好投入生产。本书将带你通过许多.NET Framework 和.NET Core 应用程序在 Docker 中运行的示例。你将学习如何在 Docker 中构建、部署和运行应用程序，并进入高级主题，如解决方案设计、安全性、管理、仪表板和持续集成和持续交付（CI/CD）。

首先，你需要了解核心的 Docker 概念：镜像、注册表、容器和编排器 - 以及了解 Docker 的实际运行方式。

# Docker 引擎和 Docker 命令行

Docker 作为后台 Windows 服务运行。这个服务管理每个正在运行的容器 - 它被称为 Docker 引擎。引擎为消费者提供了一个 REST API，用于处理容器和其他 Docker 资源。这个 API 的主要消费者是 Docker 命令行工具（CLI），这是我在本书中大部分代码示例中使用的工具。

Docker REST API 是公开的，有一些由 API 驱动的替代管理工具，包括像 Portainer（开源）和 Docker Universal Control Plane（UCP）（商业产品）这样的 Web UI。Docker CLI 非常简单易用 - 你可以使用像`docker container run`这样的命令来在容器中运行应用程序，使用`docker container rm`来删除容器。

你还可以配置 Docker API 以实现远程访问，并配置你的 Docker CLI 以连接到远程服务。这意味着你可以使用笔记本电脑上的 Docker 命令管理在云中运行的 Docker 主机。允许远程访问的设置也可以包括加密，因此你的连接是安全的 - 在本章中，我将向你展示一种简单的配置方法。

一旦你运行了 Docker，你将开始从镜像中运行容器。

# Docker 镜像

Docker 镜像是一个完整的应用程序包。它包含一个应用程序及其所有的依赖项：语言运行时、应用程序主机和底层操作系统。从逻辑上讲，镜像是一个单一的文件，它是一个可移植的单元 - 你可以通过将你的镜像推送到 Docker 注册表来分享你的应用程序。任何有权限的人都可以拉取镜像并在容器中运行你的应用程序；它对他们来说的行为方式与对你来说完全一样。

这里有一个具体的例子。一个 ASP.NET WebForms 应用程序将在 Windows Server 上的**Internet Information Services**（**IIS**）上运行。为了将应用程序打包到 Docker 中，您构建一个基于 Windows Server Core 的镜像，添加 IIS，然后添加 ASP.NET，复制您的应用程序，并在 IIS 中配置它作为一个网站。您可以在一个称为**Dockerfile**的简单脚本中描述所有这些步骤，并且您可以使用 PowerShell 或批处理文件来执行每个步骤。

通过运行`docker image build`来构建镜像。输入是 Dockerfile 和需要打包到镜像中的任何资源（如 Web 应用程序内容）。输出是一个 Docker 镜像。在这种情况下，镜像的逻辑大小约为 5GB，但其中 4GB 将是您用作基础的 Windows Server Core 镜像，并且该镜像可以作为基础共享给许多其他镜像。（我将在第四章中更详细地介绍镜像层和缓存，*使用 Docker 注册表共享镜像*。）

Docker 镜像就像是您的应用程序一个版本的文件系统快照。镜像是静态的，并且您可以使用镜像注册表来分发它们。

# 镜像注册表

注册表是 Docker 镜像的存储服务器。注册表可以是公共的或私有的，有免费的公共注册表和商业注册表服务器，可以对镜像进行细粒度的访问控制。镜像以唯一的名称存储在注册表中。任何有权限的人都可以通过运行`docker image push`来上传镜像，并通过运行`docker image pull`来下载镜像。

最受欢迎的注册表是**Docker Hub**，这是由 Docker 托管的公共注册表，但其他公司也托管自己的注册表来分发他们自己的软件：

+   Docker Hub 是默认的注册表，它已经变得非常受欢迎，用于开源项目、商业软件以及团队开发的私有项目。在 Docker Hub 上存储了数十万个镜像，每年提供数十亿次的拉取请求。您可以将 Docker Hub 镜像配置为公共或私有。它适用于内部产品，您可以限制对镜像的访问。您可以设置 Docker Hub 自动从存储在 GitHub 中的 Dockerfile 构建镜像-目前，这仅支持基于 Linux 的镜像，但 Windows 支持应该很快就会到来。

+   **Microsoft 容器注册表**（**MCR**）是微软托管其自己的 Windows Server Core 和 Nano Server 的 Docker 图像的地方，以及预先配置了.NET Framework 的图像。微软的 Docker 图像可以免费下载和使用。它们只能在 Windows 机器上运行，这是 Windows 许可证适用的地方。

在典型的工作流程中，您可能会在 CI 管道的一部分构建图像，并在所有测试通过时将它们推送到注册表。您可以使用 Docker Hub，也可以运行自己的私有注册表。然后，该图像可供其他用户在容器中运行您的应用程序。

# Docker 容器

容器是从图像创建的应用程序实例。图像包含整个应用程序堆栈，并且还指定了启动应用程序的进程，因此 Docker 知道在运行容器时该做什么。您可以从同一图像运行多个容器，并且可以以不同的方式运行容器。（我将在下一章中描述它们。）

您可以使用`docker container run`启动应用程序，指定图像的名称和配置选项。分发内置到 Docker 平台中，因此如果您在尝试运行容器的主机上没有图像的副本，Docker 将首先拉取图像。然后它启动指定的进程，您的应用程序就在容器中运行了。

容器不需要固定的 CPU 或内存分配，应用程序的进程可以使用主机的计算能力。您可以在一台普通硬件上运行数十个容器，除非所有应用程序都尝试同时使用大量 CPU，它们将愉快地并发运行。您还可以启动具有资源限制的容器，以限制它们可以访问多少 CPU 和内存。

Docker 提供容器运行时，以及图像打包和分发。在小型环境和开发中，您将在单个 Docker 主机上管理单个容器，这可以是您的笔记本电脑或测试服务器。当您转移到生产环境时，您将需要高可用性和扩展选项，这需要像 Docker Swarm 这样的编排器。

# Docker Swarm

Docker 有能力在单台机器上运行，也可以作为运行 Docker 的一组机器中的一个节点。这个集群被称为**Swarm**，你不需要安装任何额外的东西来在 swarm 模式下运行。你在一组机器上安装 Docker - 在第一台机器上，你运行`docker swarm init`来初始化 swarm，在其他机器上，你运行`docker swarm join`来加入 swarm。

我将在第七章中深入介绍 swarm 模式，*使用 Docker Swarm 编排分布式解决方案*，但在你继续深入之前，重要的是要知道 Docker 平台具有高可用性、安全性、规模和弹性。希望你的 Docker 之旅最终会让你受益于所有这些特性。

在 swarm 模式下，Docker 使用完全相同的构件，因此你可以在一个 20 节点的 swarm 中运行 50 个容器的应用，其功能与在笔记本上的单个容器中运行时相同。在 swarm 中，你的应用性能更高，更容忍故障，并且你将能够对新版本执行自动滚动更新。

在 swarm 中，节点使用安全加密进行所有通信，为每个节点使用受信任的证书。你也可以将应用程序秘密作为加密数据存储在 swarm 中，因此数据库连接字符串和 API 密钥可以被安全保存，并且 swarm 只会将它们传递给需要它们的容器。

Docker 是一个成熟的平台。它在 2016 年才新加入 Windows Server，但在 Linux 上发布了四年后才进入 Windows。Docker 是用 Go 语言编写的，这是一种跨平台语言，只有少部分代码是特定于 Windows 的。当你在 Windows 上运行 Docker 时，你正在运行一个经过多年成功生产使用的应用平台。

# 关于 Kubernetes 的说明

Docker Swarm 是一个非常流行的容器编排器，但并不是唯一的选择。Kubernetes 是另一个选择，它已经取得了巨大的增长，大多数公共云现在都提供托管的 Kubernetes 服务。在撰写本书时，Kubernetes 是一个仅限于 Linux 的编排器，Windows 支持仍处于测试阶段。在你的容器之旅中，你可能会听到很多关于 Kubernetes 的内容，因此了解它与 Docker Swarm 的比较是值得的。

首先，相似之处 - 它们都是容器编排器，这意味着它们都是负责在生产环境中以规模运行容器的机器集群。它们都可以运行 Docker 容器，并且您可以在 Docker Swarm 和 Kubernetes 中使用相同的 Docker 镜像。它们都是基于开源项目构建的，并符合**Open Container Initiative**（**OCI**）的标准，因此不必担心供应商锁定问题。您可以从 Docker Swarm 开始，然后转移到 Kubernetes，反之亦然，而无需更改您的应用程序。

现在，不同之处。Docker Swarm 非常简单；您只需几行标记就可以描述要在 swarm 中以容器运行的分布式应用程序。要在 Kubernetes 上运行相同的应用程序，您的应用程序描述将是四倍甚至更多的标记。Kubernetes 比 swarm 具有更多的抽象和配置选项，因此有一些您可以在 Kubernetes 中做但在 swarm 中做不了的事情。这种灵活性的代价是复杂性，而且学习 Kubernetes 的学习曲线比学习 swarm 要陡峭得多。

Kubernetes 很快将支持 Windows，但在一段时间内不太可能在 Linux 服务器和 Windows 服务器之间提供完全的功能兼容性。在那之前，使用 Docker Swarm 是可以的 - Docker 有数百家企业客户在 Docker Swarm 上运行他们的生产集群。如果您发现 Kubernetes 具有一些额外的功能，那么一旦您对 swarm 有了很好的理解，学习 Kubernetes 将会更容易。

# 在 Windows 上运行 Docker

在 Windows 10 上安装 Docker 很容易，使用*Docker Desktop* - 这是一个设置所有先决条件、部署最新版本的 Docker Community Engine 并为您提供一些有用选项来管理镜像存储库和远程集群的 Windows 软件包。

在生产环境中，您应该理想地使用 Windows Server 2019 Core，即没有 UI 的安装版本。这样可以减少攻击面和服务器所需的 Windows 更新数量。如果将所有应用程序迁移到 Docker，您将不需要安装任何其他 Windows 功能；您只需将 Docker Engine 作为 Windows 服务运行。

我将介绍这两种安装选项，并向您展示第三种选项，即在 Azure 中使用 VM，如果您想尝试 Docker 但无法访问 Windows 10 或 Windows Server 2019，则这种选项非常有用。

有一个名为 Play with Docker 的在线 Docker 游乐场，网址是[`dockr.ly/play-with-docker`](https://dockr.ly/play-with-docker)。Windows 支持预计很快就会到来，这是一个很好的尝试 Docker 的方式，而不需要进行任何投资 - 你只需浏览该网站并开始使用。

# Docker Desktop

Docker Desktop 可以从 Docker Hub 获取 - 你可以通过导航到[`dockr.ly/docker-for-windows`](https://dockr.ly/docker-for-windows)找到它。你可以在**稳定通道**和**Edge 通道**之间进行选择。两个通道都提供社区 Docker Engine，但 Edge 通道遵循每月发布周期，并且你将获得实验性功能。稳定通道跟踪 Docker Engine 的发布周期，每季度更新一次。

如果你想使用最新功能进行开发，应该使用 Edge 通道。在测试和生产中，你将使用 Docker Enterprise，因此需要小心，不要使用开发中尚未在 Enterprise 中可用的功能。Docker 最近宣布了**Docker Desktop Enterprise**，让开发人员可以在本地运行与其组织在生产中运行的完全相同的引擎。

你需要下载并运行安装程序。安装程序将验证你的设置是否可以运行 Docker，并配置支持 Docker 所需的 Windows 功能。当 Docker 运行时，你会在通知栏看到一个鲸鱼图标，你可以右键单击以获取选项：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-win/img/3b868f4a-752c-4445-94c1-93403f042d4a.png)

在做任何其他操作之前，你需要选择切换到 Windows 容器...。Windows 上的 Docker Desktop 可以通过在你的机器上运行 Linux VM 中的 Docker 来运行 Linux 容器。这对于测试 Linux 应用程序以查看它们在容器中的运行方式非常有用，但本书关注的是 Windows 容器 - 所以切换过去，Docker 将在未来记住这个设置。

在 Windows 上运行 Docker 时，你可以打开命令提示符或 PowerShell 会话并开始使用容器。首先，通过运行`docker version`来验证一切是否按预期工作。你应该看到类似于这段代码片段的输出：

```
> docker version

Client: Docker Engine - Community
 Version:           18.09.2
 API version:       1.39
 Go version:        go1.10.8
 Git commit:        6247962
 Built:             Sun Feb 10 04:12:31 2019
 OS/Arch:           windows/amd64
 Experimental:      false

Server: Docker Engine - Community
 Engine:
  Version:          18.09.2
  API version:      1.39 (minimum version 1.24)
  Go version:       go1.10.6
  Git commit:       6247962
  Built:            Sun Feb 10 04:28:48 2019
  OS/Arch:          windows/amd64
  Experimental:     true
```

输出会告诉你命令行客户端和 Docker Engine 的版本。操作系统字段应该都是*Windows*；如果不是，那么你可能仍然处于 Linux 模式，需要切换到 Windows 容器。

现在使用 Docker CLI 运行一个简单的容器：

```
docker container run dockeronwindows/ch01-whale:2e
```

这使用了 Docker Hub 上的公共镜像 - 本书的示例镜像之一，Docker 在您第一次使用时会拉取。如果您没有其他镜像，这将需要几分钟，因为它还会下载我镜像所使用的 Microsoft Nano Server 镜像。当容器运行时，它会显示一些 ASCII 艺术然后退出。再次运行相同的命令，您会发现它执行得更快，因为镜像现在已经在本地缓存中。

Docker Desktop 在启动时会检查更新，并在准备好时提示您下载新版本。只需在发布新版本时安装新版本，即可使您的 Docker 工具保持最新。您可以通过从任务栏菜单中选择 **关于 Docker Desktop** 来检查您已安装的当前版本：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-win/img/fdd0cd57-b688-4ead-9e85-e97216e4d720.png)

这就是您需要的所有设置。Docker Desktop 还包含了我将在本书中稍后使用的 Docker Compose 工具，因此您已准备好跟着代码示例进行操作。

# Docker 引擎

Docker Desktop 在 Windows 10 上使用容器进行开发非常方便。对于没有 UI 的生产环境中，您可以安装 Docker 引擎以作为后台 Windows 服务运行，使用 PowerShell 模块进行安装。

在新安装的 Windows Server 2019 Core 上，使用 `sconfig` 工具安装所有最新的 Windows 更新，然后运行这些 PowerShell 命令来安装 Docker 引擎和 Docker CLI：

```
Install-Module -Name DockerMsftProvider -Repository PSGallery -Force
Install-Package -Name docker -ProviderName DockerMsftProvider
```

这将配置服务器所需的 Windows 功能，安装 Docker，并设置其作为 Windows 服务运行。根据安装了多少 Windows 更新，您可能需要重新启动服务器：

```
Restart-Computer -Force
```

当服务器在线时，请确认 Docker 是否正在运行 `docker version`，然后从本章的示例镜像中运行一个容器：

```
docker container run dockeronwindows/ch01-whale:2e
```

当发布新版本的 Docker Engine 时，您可以通过重复 `Install` 命令并添加 `-Update` 标志来更新服务器：

```
Install-Package -Name docker -ProviderName DockerMsftProvider -Update 
```

我在一些环境中使用这个配置 - 在轻量级虚拟机中运行 Windows Server 2019 Core，只安装了 Docker。您可以通过远程桌面连接在服务器上使用 Docker，或者您可以配置 Docker 引擎以允许远程连接，这样您就可以使用笔记本电脑上的 `docker` 命令管理服务器上的 Docker 容器。这是一个更高级的设置，但它确实为您提供了安全的远程访问。

最好设置 Docker 引擎，以便使用 TLS 对客户端进行安全通信，这与 HTTPS 使用的加密技术相同。只有具有正确 TLS 证书的客户端才能连接到服务。您可以通过在 VM 内运行以下 PowerShell 命令来设置这一点，提供 VM 的外部 IP 地址：

```
$ipAddress = '<vm-ip-address>'

mkdir -p C:\certs\client

docker container run --rm `
 --env SERVER_NAME=$(hostname) `
 --env IP_ADDRESSES=127.0.0.1,$ipAddress `
 --volume 'C:\ProgramData\docker:C:\ProgramData\docker' `
 --volume 'C:\certs\client:C:\Users\ContainerAdministrator\.docker' `
 dockeronwindows/ch01-dockertls:2e

Restart-Service docker
```

不要太担心这个命令在做什么。在接下来的几章中，您将对所有这些 Docker 选项有一个很好的理解。我正在使用一个基于 Stefan Scherer 的 Docker 镜像，他是微软 MVP 和 Docker Captain。该镜像有一个脚本，用 TLS 证书保护 Docker 引擎。您可以在 Stefan 的博客上阅读更多详细信息[`stefanscherer.github.io`](https://stefanscherer.github.io)。

当这个命令完成时，它将配置 Docker 引擎 API，只允许安全的远程连接，并且还将创建客户端需要使用的证书。从 VM 上的`C:\certs\client`目录中复制这些证书到您想要使用 Docker 客户端的机器上。

在客户端机器上，您可以设置环境变量，指向 Docker 客户端使用远程 Docker 服务。这些命令将建立与 VM 的远程连接（假设您在客户端上使用了相同的证书文件路径），如下所示：

```
$ipAddress = '<vm-ip-address>'

$env:DOCKER_HOST='tcp://$($ipAddress):2376'
$env:DOCKER_TLS_VERIFY='1'
$env:DOCKER_CERT_PATH='C:\certs\client'
```

您可以使用这种方法安全地连接到任何远程 Docker 引擎。如果您没有 Windows 10 或 Windows Server 2019 的访问权限，您可以在云上创建一个 VM，并使用相同的命令连接到它。

# Azure VM 中的 Docker

微软让在 Azure 中运行 Docker 变得很容易。他们提供了一个带有 Docker 安装和配置的 VM 映像，并且已经拉取了基本的 Windows 映像，这样您就可以快速开始使用。

用于测试和探索，我总是在 Azure 中使用 DevTest 实验室。这是一个非生产环境的很棒的功能。默认情况下，在 DevTest 实验室中创建的任何虚拟机每天晚上都会被关闭，这样你就不会因为使用了几个小时并忘记关闭的虚拟机而产生大量的 Azure 账单。

您可以通过 Azure 门户创建一个 DevTest 实验室，然后从 Microsoft 的 VM 映像**Windows Server 2019 Datacenter with Containers**创建一个 VM。作为 Azure 门户的替代方案，您可以使用`az`命令行来管理 DevTest 实验室。我已经将`az`打包到一个 Docker 镜像中，您可以在 Windows 容器中运行它：

```
docker container run -it dockeronwindows/ch01-az:2e
```

这将运行一个交互式的 Docker 容器，其中包含打包好并准备好使用的`az`命令。运行`az login`，然后你需要打开浏览器并对 Azure CLI 进行身份验证。然后，你可以在容器中运行以下命令来创建一个 VM：

```
az lab vm create `
 --lab-name docker-on-win --resource-group docker-on-win `
 --name dow-vm-01 `
 --image "Windows Server 2019 Datacenter with Containers" `
 --image-type gallery --size Standard_DS2_v2 `
 --admin-username "elton" --admin-password "S3crett20!9"
```

该 VM 使用带有 UI 的完整 Windows Server 2019 安装，因此你可以使用远程桌面连接到该机器，打开 PowerShell 会话，并立即开始使用 Docker。与其他选项一样，你可以使用`docker version`检查 Docker 是否正在运行，然后从本章的示例镜像中运行一个容器：

```
docker container run dockeronwindows/ch01-whale:2e
```

如果 Azure VM 是你首选的选项，你可以按照上一节的步骤来保护远程访问的 Docker API。这样你就可以在笔记本电脑上运行 Docker 命令行来管理云上的容器。Azure VM 使用 PowerShell 部署 Docker，因此你可以使用上一节中的`InstallPackage ... -Update`命令来更新 VM 上的 Docker Engine。

所有这些选项 - Windows 10、Windows Server 2019 和 Azure VM - 都可以运行相同的 Docker 镜像，并产生相同的结果。Docker 镜像中的示例应用程序`dockeronwindows/ch01-whale:2e`在每个环境中的行为都是相同的。

# 通过本书学习 Docker

本书中的每个代码清单都附有我 GitHub 存储库中的完整代码示例，网址为[`github.com/sixeyed/docker-on-windows`](https://github.com/sixeyed/docker-on-windows)。书中有一个名为`second-edition`的分支。源代码树按章节组织，每个章节都有一个用于每个代码示例的文件夹。在本章中，我使用了三个示例来创建 Docker 镜像，你可以在`ch01\ch01-whale`、`ch01\ch01-az`和`ch01\ch01-dockertls`中找到它们。

本书中的代码清单可能会被压缩，但完整的代码始终可以在 GitHub 存储库中找到。

我在学习新技术时更喜欢跟着代码示例走，但如果你想使用演示应用程序的工作版本，每个示例也可以作为公共 Docker 镜像在 Docker Hub 上找到。无论何时看到`docker container run`命令，该镜像已经存在于 Docker Hub 上，因此如果愿意，你可以使用我的镜像而不是构建自己的。`dockeronwindows`组织中的所有镜像，比如本章的`dockeronwindows/ch01-whale:2e`，都是从 GitHub 存储库中相关的 Dockerfile 构建的。

我的开发环境分为 Windows 10 和 Windows Server 2019，我在 Windows 10 上使用 Docker Desktop，在 Windows Server 2019 上运行 Docker Enterprise Engine。我的测试环境基于 Windows Server 2019 Core，我也在那里运行 Docker Enterprise Engine。我已在所有这些环境中验证了本书中的所有代码示例。

我正在使用 Docker 的 18.09 版本，这是我写作时的最新版本。Docker 一直向后兼容，所以如果你在 Windows 10 或 Windows Server 2019 上使用的版本晚于 18.09，那么示例 Dockerfiles 和镜像应该以相同的方式工作。

我的目标是让这本书成为关于 Windows 上 Docker 的权威之作，所以我涵盖了从容器的基础知识，到使用 Docker 现代化.NET 应用程序以及容器的安全性影响，再到 CI/CD 和生产管理的所有内容。这本书以指导如何在自己的项目中继续使用 Docker 结束。

如果你想讨论这本书或者你自己的 Docker 之旅，欢迎在 Twitter 上@EltonStoneman 找我。

# 总结

在本章中，我介绍了 Docker，这是一个可以在轻量级计算单元容器中运行新旧应用程序的应用平台。公司正在转向 Docker 以提高效率、安全性和可移植性。我涵盖了以下主题：

+   Docker 在 Windows 上的工作原理以及容器的许可。

+   Docker 的关键概念：镜像、注册表、容器和编排器。

+   在 Windows 10、Windows Server 2019 或 Azure 上运行 Docker 的选项。

如果你打算在本书的其余部分跟着代码示例一起工作，那么你现在应该有一个可用的 Docker 环境了。在第二章中，*将应用程序打包并作为 Docker 容器运行*，我将继续讨论如何将更复杂的应用程序打包为 Docker 镜像，并展示如何使用 Docker 卷在容器中管理状态。


# 第二章：打包和运行应用程序作为 Docker 容器

Docker 将基础设施的逻辑视图简化为三个核心组件：主机、容器和图像。主机是运行容器的服务器，每个容器都是应用程序的隔离实例。容器是从图像创建的，图像是打包的应用程序。Docker 容器图像在概念上非常简单：它是一个包含完整、自包含应用程序的单个单元。图像格式非常高效，图像和容器运行时之间的集成非常智能，因此掌握图像是有效使用 Docker 的第一步。

在第一章中，您已经通过运行一些基本容器来检查 Docker 安装是否正常工作，但我没有仔细检查图像或 Docker 如何使用它。在本章中，您将彻底了解 Docker 图像，了解它们的结构，了解 Docker 如何使用它们，并了解如何将自己的应用程序打包为 Docker 图像。

首先要理解的是图像和容器之间的区别，通过从相同的图像运行不同类型的容器，您可以非常清楚地看到这一点。

在本章中，您将更多地了解 Docker 的基础知识，包括：

+   从图像运行容器

+   从 Dockerfile 构建图像

+   将自己的应用程序打包为 Docker 图像

+   在图像和容器中处理数据

+   将传统的 ASP.NET Web 应用程序打包为 Docker 图像

# 技术要求

要跟随示例，您需要在 Windows 10 上运行 Docker，并更新到 18.09 版，或者在 Windows Server 2019 上运行。本章的代码可在[`github.com/sixeyed/docker-on-windows/tree/second-edition/ch02`](https://github.com/sixeyed/docker-on-windows/tree/second-edition/ch02)上找到。

# 从图像运行容器

`docker container run`命令从图像创建一个容器，并在容器内启动应用程序。实际上，这相当于运行两个单独的命令，`docker container create`和`docker container start`，这表明容器可以具有不同的状态。您可以创建一个容器而不启动它，并且可以暂停、停止和重新启动运行中的容器。容器可以处于不同的状态，并且可以以不同的方式使用它们。

# 使用任务容器执行一个任务

`dockeronwindows/ch02-powershell-env:2e`镜像是一个打包的应用程序的示例，旨在在容器中运行并执行单个任务。该镜像基于 Microsoft Windows Server Core，并设置为在启动时运行一个简单的 PowerShell 脚本，打印有关当前环境的详细信息。让我们看看当我直接从镜像运行容器时会发生什么：

```
> docker container run dockeronwindows/ch02-powershell-env:2e

Name                           Value
----                           -----
ALLUSERSPROFILE                C:\ProgramData
APPDATA                        C:\Users\ContainerAdministrator\AppData\Roaming
CommonProgramFiles             C:\Program Files\Common Files
CommonProgramFiles(x86)        C:\Program Files (x86)\Common Files
CommonProgramW6432             C:\Program Files\Common Files
COMPUTERNAME                   8A7D5B9A4021
...
```

没有任何选项，容器将运行内置于镜像中的 PowerShell 脚本，并且脚本将打印有关操作系统环境的一些基本信息。我将其称为**任务容器**，因为容器执行一个任务然后退出。

如果运行`docker container ls`，列出所有活动容器，您将看不到此容器。但如果运行`docker container ls --all`，显示所有状态的容器，您将在`Exited`状态中看到它：

```
> docker container ls --all
CONTAINER ID  IMAGE       COMMAND    CREATED          STATUS
8a7d5b9a4021 dockeronwindows/ch02-powershell-env:2e "powershell.exe C:..."  30 seconds ago   Exited
```

任务容器在自动化重复任务方面非常有用，比如运行脚本来设置环境、备份数据或收集日志文件。您的容器镜像打包了要运行的脚本，以及脚本所需的所有要求的确切版本，因此安装了 Docker 的任何人都可以运行脚本，而无需安装先决条件。

这对于 PowerShell 特别有用，因为脚本可能依赖于几个 PowerShell 模块。这些模块可能是公开可用的，但您的脚本可能依赖于特定版本。您可以构建一个已安装了模块的镜像，而不是共享一个需要用户安装许多不同模块的正确版本的脚本。然后，您只需要 Docker 来运行脚本任务。

镜像是自包含的单位，但您也可以将其用作模板。一个镜像可能配置为执行一项任务，但您可以以不同的方式从镜像运行容器以执行不同的任务。

# 连接到交互式容器

**交互式容器**是指与 Docker 命令行保持开放连接的容器，因此您可以像连接到远程机器一样使用容器。您可以通过指定交互式选项和容器启动时要运行的命令来从相同的 Windows Server Core 镜像运行交互式容器：

```
> docker container run --interactive --tty dockeronwindows/ch02-powershell-env:2e `
 powershell

Windows PowerShell
Copyright (C) Microsoft Corporation. All rights reserved.

PS C:\> Write-Output 'This is an interactive container'
This is an interactive container
PS C:\> exit
```

`--interactive`选项运行交互式容器，`--tty`标志将终端连接附加到容器。在容器映像名称后的`powershell`语句是容器启动时要运行的命令。通过指定命令，您可以替换映像中设置的启动命令。在这种情况下，我启动了一个 PowerShell 会话，它代替了配置的命令，因此环境打印脚本不会运行。

交互式容器会持续运行，只要其中的命令在运行。当您连接到 PowerShell 时，在主机的另一个窗口中运行`docker container ls`，会显示容器仍在运行。当您在容器中键入`exit`时，PowerShell 会话结束，因此没有进程在运行，容器也会退出。

交互式容器在构建自己的容器映像时非常有用，它们可以让您首先以交互方式进行步骤，并验证一切是否按您的预期工作。它们也是很好的探索工具。您可以从 Docker 注册表中拉取别人的映像，并在运行应用程序之前探索其内容。

阅读本书时，您会发现 Docker 可以在虚拟网络中托管复杂的分布式系统，每个组件都在自己的容器中运行。如果您想检查系统的某些部分，可以在网络内部运行交互式容器，并检查各个组件，而无需使部分公开可访问。

# 在后台容器中保持进程运行

最后一种类型的容器是您在生产中最常使用的，即后台容器，它在后台保持长时间运行的进程。它是一个行为类似于 Windows 服务的容器。在 Docker 术语中，它被称为**分离容器**，Docker 引擎会在后台保持其运行。在容器内部，进程在前台运行。该进程可能是一个 Web 服务器或一个轮询消息队列以获取工作的控制台应用程序，但只要进程保持运行，Docker 就会保持容器保持活动状态。

我可以再次从相同的映像运行后台容器，指定`detach`选项和运行一些分钟的命令：

```
> docker container run --detach dockeronwindows/ch02-powershell-env:2e `
 powershell Test-Connection 'localhost' -Count 100

bb326e5796bf48199a9a6c4569140e9ca989d7d8f77988de7a96ce0a616c88e9
```

在这种情况下，当容器启动后，控制返回到终端；长随机字符串是新容器的 ID。您可以运行`docker container ls`并查看正在运行的容器，`docker container logs`命令会显示容器的控制台输出。对于操作特定容器的命令，您可以通过容器名称或容器 ID 的一部分来引用它们 - ID 是随机的，在我的情况下，这个容器 ID 以`bb3`开头：

```
> docker container logs bb3

Source        Destination     IPV4Address      IPV6Address
------        -----------     -----------      -----------
BB326E5796BF  localhost       127.0.0.1        ::1
BB326E5796BF  localhost       127.0.0.1        ::1
```

`--detach`标志将容器分离，使其进入后台，而在这种情况下，命令只是重复一百次对`localhost`的 ping。几分钟后，PowerShell 命令完成，因此没有正在运行的进程，容器退出。

这是一个需要记住的关键事情：如果您想要在后台保持容器运行，那么 Docker 在运行容器时启动的进程必须保持运行。

现在您已经看到容器是从镜像创建的，但它可以以不同的方式运行。因此，您可以完全按照准备好的镜像使用，或者将镜像视为内置默认启动模式的模板。接下来，我将向您展示如何构建该镜像。

# 构建 Docker 镜像

Docker 镜像是分层的。底层是操作系统，可以是完整的操作系统，如 Windows Server Core，也可以是微软 Nano Server 等最小的操作系统。在此之上是每次构建镜像时对基本操作系统所做更改的层，通过安装软件、复制文件和运行命令。从逻辑上讲，Docker 将镜像视为单个单位，但从物理上讲，每个层都存储为 Docker 缓存中的单独文件，因此具有许多共同特征的镜像可以共享缓存中的层。

镜像是使用 Dockerfile 语言的文本文件构建的 - 指定要从哪个基本操作系统镜像开始以及添加的所有步骤。这种语言非常简单，您只需要掌握几个命令就可以构建生产级别的镜像。我将从查看到目前为止在本章中一直在使用的基本 PowerShell 镜像开始。

# 理解 Dockerfile

Dockerfile 只是一个将软件打包到 Docker 镜像中的部署脚本。PowerShell 镜像的完整代码只有三行：

```
FROM mcr.microsoft.com/windows/servercore:ltsc2019  COPY scripts/print-env-details.ps1 C:\\print-env.ps1 CMD ["powershell.exe", "C:\\print-env.ps1"]
```

即使你以前从未见过 Dockerfile，也很容易猜到发生了什么。按照惯例，指令（`FROM`、`COPY`和`CMD`）是大写的，参数是小写的，但这不是强制的。同样按照惯例，你保存文本在一个名为`Dockerfile`的文件中，但这也不是强制的（在 Windows 中，没有扩展名的文件看起来很奇怪，但请记住 Docker 的传统是在 Linux 中）。

让我们逐行查看 Dockerfile 中的指令：

+   `FROM mcr.microsoft.com/windows/servercore:ltsc2019`使用名为`windows/servercore`的镜像作为此镜像的起点，指定了镜像的`ltsc2019`版本和其托管的注册表。

+   `COPY scripts/print-env-details.ps1 C:\\print-env.ps1`将 PowerShell 脚本从本地计算机复制到镜像中的特定位置。

+   `CMD ["powershell.exe", "C:\\print-env.ps1"]`指定了容器运行时的启动命令，在这种情况下是运行 PowerShell 脚本。

这里有一些明显的问题。基础镜像是从哪里来的？Docker 内置了镜像注册表的概念，这是一个容器镜像的存储库。默认注册表是一个名为**Docker Hub**的免费公共服务。微软在 Docker Hub 上发布了一些镜像，但 Windows 基础镜像托管在**Microsoft Container Registry**（**MCR**）上。

Windows Server Core 镜像的 2019 版本被称为`windows/servercore:ltsc2019`。第一次使用该镜像时，Docker 会从 MCR 下载到本地计算机，然后缓存以供进一步使用。

Docker Hub 是 Microsoft 所有镜像的发现列表，因为 MCR 没有 Web UI。即使镜像托管在 MCR 上，它们也会在 Docker Hub 上列出，所以当你在寻找镜像时，那就是去的地方。

PowerShell 脚本是从哪里复制过来的？构建镜像时，包含 Dockerfile 的目录被用作构建的上下文。从这个 Dockerfile 构建镜像时，Docker 会期望在上下文目录中找到一个名为`scripts`的文件夹，其中包含一个名为`print-env-details.ps1`的文件。如果找不到该文件，构建将失败。

Dockerfile 使用反斜杠作为转义字符，以便将指令继续到新的一行。这与 Windows 文件路径冲突，所以你必须将`C:\print.ps1`写成`C:\\print.ps1`或`C:/print.ps1`。有一个很好的方法来解决这个问题，在 Dockerfile 开头使用处理器指令，我将在本章后面进行演示。

你如何知道 PowerShell 可以使用？它是 Windows Server Core 基础镜像的一部分，所以你可以依赖它。你可以使用额外的 Dockerfile 指令安装任何不在基础镜像中的软件。你可以添加 Windows 功能，设置注册表值，将文件复制或下载到镜像中，解压 ZIP 文件，部署 MSI 文件，以及其他任何你需要的操作。

这是一个非常简单的 Dockerfile，但即使如此，其中两条指令是可选的。只有`FROM`指令是必需的，所以如果你想构建一个微软的 Windows Server Core 镜像的精确克隆，你可以在 Dockerfile 中只使用一个`FROM`语句，并且随意命名克隆的镜像。

# 从 Dockerfile 构建镜像

现在你有了一个 Dockerfile，你可以使用`docker`命令行将其构建成一个镜像。像大多数 Docker 命令一样，`image build`命令很简单，只有很少的必需选项，更倾向于使用约定而不是命令。

要构建一个镜像，打开命令行并导航到 Dockerfile 所在的目录。然后运行`docker image build`并给你的镜像打上一个标签，这个标签就是将来用来识别镜像的名称。

```
docker image build --tag dockeronwindows/ch02-powershell-env:2e .
```

每个镜像都需要一个标签，使用`--tag`选项指定，这是本地镜像缓存和镜像注册表中镜像的唯一标识符。标签是你在运行容器时将引用镜像的方式。完整的标签指定要使用的注册表：存储库名称，这是应用程序的标识符，以及后缀，这是镜像的版本标识符。

当你为自己构建一个镜像时，你可以随意命名，但约定是将你的存储库命名为你的注册表用户名，后面跟上应用程序名称：`{user}/{app}`。你还可以使用标签来标识应用程序的版本或变体，比如`sixeyed/git`和`sixeyed/git:2.17.1-windowsservercore-ltsc2019`，这是 Docker Hub 上我的两个镜像。

`image build`命令末尾的句点告诉 Docker 要使用的上下文的位置。`.`是当前目录。Docker 将目录树的内容复制到一个临时文件夹进行构建，因此上下文需要包含 Dockerfile 中引用的任何文件。复制上下文后，Docker 开始执行 Dockerfile 中的指令。

# 检查 Docker 构建镜像的过程

理解 Docker 镜像是如何构建的将有助于您构建高效的镜像。`image build`命令会产生大量输出，告诉您 Docker 在构建的每个步骤中做了什么。Dockerfile 中的每个指令都会作为一个单独的步骤执行，产生一个新的镜像层，最终镜像将是所有层的组合堆栈。以下代码片段是构建我的镜像的输出：

```
> docker image build --tag dockeronwindows/ch02-powershell-env:2e .

Sending build context to Docker daemon  4.608kB
Step 1/3 : FROM mcr.microsoft.com/windows/servercore:ltsc2019
 ---> 8b79386f6e3b
Step 2/3 : COPY scripts/print-env-details.ps1 C:\\print-env.ps1
 ---> 5e9ed4527b3f
Step 3/3 : CMD ["powershell.exe", "C:\\print-env.ps1"]
 ---> Running in c14c8aef5dc5
Removing intermediate container c14c8aef5dc5
 ---> 5f272fb2c190
Successfully built 5f272fb2c190
Successfully tagged dockeronwindows/ch02-powershell-env:2e
```

这就是 Docker 构建镜像时发生的事情：

1.  `FROM`镜像已经存在于我的本地缓存中，因此 Docker 不需要下载它。输出是 Microsoft 的 Windows Server Core 镜像的 ID（以`8b79`开头）。

1.  Docker 将脚本文件从构建上下文复制到一个新的镜像层（ID `5e9e`）。

1.  Docker 配置了当从镜像运行容器时要执行的命令。它从*步骤 2*镜像创建一个临时容器，配置启动命令，将容器保存为一个新的镜像层（ID `5f27`），并删除中间容器（ID `c14c`）。

最终层被标记为镜像名称，但所有中间层也被添加到本地缓存中。这种分层的方法意味着 Docker 在构建镜像和运行容器时可以非常高效。最新的 Windows Server Core 镜像未经压缩超过 4GB，但当您运行基于 Windows Server Core 的多个容器时，它们将都使用相同的基础镜像层，因此您不会得到多个 4GB 镜像的副本。

您将在本章后面更多地了解镜像层和存储，但首先我将看一些更复杂的 Dockerfile，其中打包了.NET 和.NET Core 应用程序。

# 打包您自己的应用程序

构建镜像的目标是将您的应用程序打包成一个便携、自包含的单元。镜像应尽可能小，这样在运行应用程序时移动起来更容易，并且应尽可能少地包含操作系统功能，这样启动时间快，攻击面小。

Docker 不对图像大小施加限制。你的长期目标可能是构建在 Linux 或 Nano Server 上运行轻量级.NET Core 应用程序的最小图像。但你可以先将现有的 ASP.NET 应用程序作为 Docker 图像的全部内容打包，以在 Windows Server Core 上运行。Docker 也不对如何打包应用程序施加限制，因此你可以选择不同的方法。

# 在构建过程中编译应用程序

在 Docker 图像中打包自己的应用程序有两种常见的方法。第一种是使用包含应用程序平台和构建工具的基础图像。因此，在你的 Dockerfile 中，你将源代码复制到图像中，并在图像构建过程中编译应用程序。

这是一个受欢迎的公共图像的方法，因为这意味着任何人都可以构建图像，而无需在本地安装应用程序平台。这也意味着应用程序的工具与图像捆绑在一起，因此可以使在容器中运行的应用程序的调试和故障排除成为可能。

这是一个简单的.NET Core 应用程序的示例。这个 Dockerfile 是为`dockeronwindows/ch02-dotnet-helloworld:2e`图像而设计的：

```
FROM microsoft/dotnet:2.2-sdk-nanoserver-1809 WORKDIR /src COPY src/ . USER ContainerAdministrator RUN dotnet restore && dotnet build CMD ["dotnet", "run"]
```

Dockerfile 使用了来自 Docker Hub 的 Microsoft 的.NET Core 图像作为基础图像。这是图像的一个特定变体，它基于 Nano Server 1809 版本，并安装了.NET Core 2.2 SDK。构建将应用程序源代码从上下文中复制进来，并在容器构建过程中编译应用程序。

这个 Dockerfile 中有三个你以前没有见过的新指令：

1.  `WORKDIR`指定当前工作目录。如果目录在中间容器中不存在，Docker 会创建该目录，并将其设置为当前目录。它将保持为 Dockerfile 中的后续指令以及从图像运行的容器的工作目录。

1.  `USER`更改构建中的当前用户。Nano Server 默认使用最低特权用户。这将切换到容器图像中的内置帐户，该帐户具有管理权限。

1.  `RUN`在中间容器中执行命令，并在命令完成后保存容器的状态，创建一个新的图像层。

当我构建这个图像时，你会看到`dotnet`命令的输出，这是应用程序从图像构建中的`RUN`指令中编译出来的：

```
> docker image build --tag dockeronwindows/ch02-dotnet-helloworld:2e . 
Sending build context to Docker daemon  192.5kB
Step 1/6 : FROM microsoft/dotnet:2.2-sdk-nanoserver-1809
 ---> 90724d8d2438
Step 2/6 : WORKDIR /src
 ---> Running in f911e313b262
Removing intermediate container f911e313b262
 ---> 2e2f7deb64ac
Step 3/6 : COPY src/ .
 ---> 391c7d8f4bcc
Step 4/6 : USER ContainerAdministrator
 ---> Running in f08f860dd299
Removing intermediate container f08f860dd299
 ---> 6840a2a2f23b
Step 5/6 : RUN dotnet restore && dotnet build
 ---> Running in d7d61372a57b

Welcome to .NET Core!
...
```

你会在 Docker Hub 上经常看到这种方法，用于使用.NET Core、Go 和 Node.js 等语言构建的应用程序，其中工具很容易添加到基础镜像中。这意味着你可以在 Docker Hub 上设置自动构建，这样当你将代码更改推送到 GitHub 时，Docker 的服务器就会根据 Dockerfile 构建你的镜像。服务器可以在没有安装.NET Core、Go 或 Node.js 的情况下执行此操作，因为所有构建依赖项都在基础镜像中。

这种选项意味着最终镜像将比生产应用程序所需的要大得多。语言 SDK 和工具可能会占用比应用程序本身更多的磁盘空间，但你的最终结果应该是应用程序；当容器在生产环境运行时，镜像中占用空间的所有构建工具都不会被使用。另一种选择是首先构建应用程序，然后将编译的二进制文件打包到你的容器镜像中。

# 在构建之前编译应用程序

首先构建应用程序与现有的构建流水线完美契合。你的构建服务器需要安装所有的应用程序平台和构建工具来编译应用程序，但你的最终容器镜像只包含运行应用程序所需的最小内容。采用这种方法，我的.NET Core 应用程序的 Dockerfile 变得更加简单：

```
FROM  microsoft/dotnet:2.2-runtime-nanoserver-1809

WORKDIR /dotnetapp
COPY ./src/bin/Debug/netcoreapp2.2/publish .

CMD ["dotnet", "HelloWorld.NetCore.dll"]
```

这个 Dockerfile 使用了一个不同的`FROM`镜像，其中只包含.NET Core 2.2 运行时，而不包含工具（因此它可以运行已编译的应用程序，但无法从源代码编译）。你不能在构建应用程序之前构建这个镜像，所以你需要在构建脚本中包装`docker image build`命令，该脚本还运行`dotnet publish`命令来编译二进制文件。

一个简单的构建脚本，用于编译应用程序并构建 Docker 镜像，看起来像这样：

```
dotnet restore src; dotnet publish src

docker image build --file Dockerfile.slim --tag dockeronwindows/ch02-dotnet-helloworld:2e-slim .
```

如果你把 Dockerfile 指令放在一个名为**Dockerfile**之外的文件中，你需要使用`--file`选项指定文件名：`docker image build --file Dockerfile.slim`。

我把平台工具的要求从镜像移到了构建服务器上，这导致最终镜像变得更小：与之前版本相比，这个版本的大小为 410 MB，而之前的版本为 1.75 GB。你可以通过列出镜像并按照镜像仓库名称进行过滤来看到大小的差异：

```
> docker image ls --filter reference=dockeronwindows/ch02-dotnet-helloworld

REPOSITORY                               TAG     IMAGE ID       CREATED              SIZE
dockeronwindows/ch02-dotnet-helloworld   2e-slim b6e7dca114a4   About a minute ago   410MB
dockeronwindows/ch02-dotnet-helloworld   2e      bf895a7452a2   7 minutes ago        1.75GB
```

这个新版本也是一个更受限制的镜像。源代码和.NET Core SDK 没有打包在镜像中，所以你不能连接到正在运行的容器并检查应用程序代码，或者对代码进行更改并重新编译应用程序。

对于企业环境或商业应用程序，你可能已经有一个设备齐全的构建服务器，并且打包构建的应用程序可以成为更全面工作流的一部分：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-win/img/d09a1ae3-e97a-4318-8118-f2d2a39c5828.png)

在这个流水线中，开发人员将他们的更改推送到中央源代码仓库（**1**）。构建服务器编译应用程序并运行单元测试；如果测试通过，那么容器镜像将在暂存环境中构建和部署（2）。集成测试和端到端测试在暂存环境中运行，如果测试通过，那么你的容器镜像版本是一个好的发布候选，供测试人员验证（3）。

通过在生产环境中从镜像运行容器来部署新版本，并且你知道你的整个应用程序堆栈是通过了所有测试的相同的一组二进制文件。

这种方法的缺点是你需要在所有构建代理上安装应用程序 SDK，并且 SDK 及其所有依赖项的版本需要与开发人员使用的相匹配。通常在 Windows 项目中，你会发现安装了 Visual Studio 的 CI 服务器，以确保服务器具有与开发人员相同的工具。这使得构建服务器非常庞大，需要大量的努力来委托和维护。

这也意味着，除非你在你的机器上安装了.NET Core 2.2 SDK，否则你无法从本章的源代码构建这个 Docker 镜像。

通过使用多阶段构建，你可以兼顾两种选择，其中你的 Dockerfile 定义了一个步骤来编译你的应用程序，另一个步骤将其打包到最终镜像中。多阶段 Dockerfile 是可移植的，因此任何人都可以在没有先决条件的情况下构建镜像，但最终镜像只包含了应用程序所需的最小内容。

# 使用多阶段构建编译

在多阶段构建中，你的 Dockerfile 中有多个`FROM`指令，每个`FROM`指令在构建中启动一个新阶段。Docker 在构建镜像时执行所有指令，后续阶段可以访问前期阶段的输出，但只有最终阶段用于完成的镜像。

我可以通过将前两个 Dockerfile 合并成一个，为.NET Core 控制台应用程序编写一个多阶段的 Dockerfile：

```
# build stage
FROM microsoft/dotnet:2.2-sdk-nanoserver-1809 AS builder

WORKDIR /src
COPY src/ .

USER ContainerAdministrator
RUN dotnet restore && dotnet publish

# final image stage
FROM microsoft/dotnet:2.2-runtime-nanoserver-1809

WORKDIR /dotnetapp
COPY --from=builder /src/bin/Debug/netcoreapp2.2/publish .

CMD ["dotnet", "HelloWorld.NetCore.dll"]
```

这里有一些新的东西。第一阶段使用了一个大的基础镜像，安装了.NET Core SDK。我使用`FROM`指令中的`AS`选项将这个阶段命名为`builder`。阶段的其余部分继续复制源代码并发布应用程序。当构建器阶段完成时，发布的应用程序将存储在一个中间容器中。

第二阶段使用了运行时.NET Core 镜像，其中没有安装 SDK。在这个阶段，我将从上一个阶段复制已发布的输出，在`COPY`指令中指定`--from=builder`。任何人都可以使用 Docker 从源代码编译这个应用程序，而不需要在他们的机器上安装.NET Core。

用于 Windows 应用程序的多阶段 Dockerfile 是完全可移植的。要编译应用程序并构建镜像，唯一的前提是要有一个安装了 Docker 的 Windows 机器和代码的副本。构建器阶段包含了 SDK 和所有编译器工具，但最终镜像只包含运行应用程序所需的最小内容。

这种方法不仅适用于.NET Core。你可以为.NET Framework 应用程序编写一个多阶段的 Dockerfile，其中第一阶段使用安装了 MSBuild 的镜像，用于编译你的应用程序。书中后面有很多这样的例子。

无论你采取哪种方法，都只需要理解几个 Dockerfile 指令，就可以构建更复杂的应用程序镜像，用于与其他系统集成的软件。

# 使用主要的 Dockerfile 指令

Dockerfile 语法非常简单。你已经看到了`FROM`、`COPY`、`USER`、`RUN`和`CMD`，这已经足够打包一个基本的应用程序以在容器中运行。对于真实世界的镜像，你需要做更多的工作，还有三个关键指令需要理解。

这是一个简单静态网站的 Dockerfile；它使用**Internet Information Services**（**IIS**）并在默认网站上提供一个 HTML 页面，显示一些基本细节：

```
# escape=` FROM mcr.microsoft.com/windows/servercore/iis:windowsservercore-ltsc2019
SHELL ["powershell"]

ARG ENV_NAME=DEV

EXPOSE 80

COPY template.html C:\template.html
RUN (Get-Content -Raw -Path C:\template.html) `
 -replace '{hostname}', [Environment]::MachineName `
 -replace '{environment}', [Environment]::GetEnvironmentVariable('ENV_NAME') `
 | Set-Content -Path C:\inetpub\wwwroot\index.html
```

这个 Dockerfile 的开始方式不同，使用了`escape`指令。这告诉 Docker 使用反引号``` option for the escape character, to split commands over multiple lines, rather than the default backslash `\` option. With this escape directive I can use backslashes in file paths, and backticks to split long PowerShell commands, which is more natural to Windows users.

The base image is `microsoft/iis`, which is a Microsoft Windows Server Core image with IIS already set up. I copy an HTML template file from the Docker build context into the root folder. Then I run a PowerShell command to update the content of the template file and save it in the default website location for IIS.

In this Dockerfile, I use three new instructions:

*   `SHELL` specifies the command line to use in `RUN` commands. The default is `cmd`, and this switches to `powershell`.
*   `ARG` specifies a build argument to use in the image with a default value.
*   `EXPOSE` will make a port available in the image, so that containers from the image can have traffic sent in from the host.

This static website has a single home page, which tells you the name of the server that sent the response, with the name of the environment in the page title. The HTML template file has placeholders for the hostname and the environment name. The `RUN` command executes a PowerShell script to read the file contents, replace the placeholders with the actual hostname and environment value, and then write the contents out.

Containers run in an isolated space, and the host can only send network traffic into the container if the image has explicitly made the port available for use. That's the `EXPOSE` instruction, which is like a very simple firewall; you use it to expose the ports that your application is listening on. When you run a container from this image, port `80` is available to be published so Docker can serve web traffic from the container.

I can build this image in the usual way, and make use of the `ARG` command specified in the Dockerfile to override the default value at build time with the `--build-arg` option:

```

docker image build --build-arg ENV_NAME=TEST --tag dockeronwindows/ch02-static-website:2e .

```

Docker processes the new instructions in the same way as those you've already seen: it creates a new, intermediate container from the previous image in the stack, executes the instruction, and extracts a new image layer from the container. After the build, I have a new image which I can run to start the static web server:

```

> docker container run --detach --publish 8081:80 dockeronwindows/ch02-static-website:2e

6e3df776cb0c644d0a8965eaef86e377f8ebe036e99961a0621dcb7912d96980

```

This is a detached container so it runs in the background, and the `--publish` option makes port `80` in the container available to the host. Published ports mean that the traffic coming into the host can be directed into containers by Docker. I've specified that port `8081` on the host should map to port `80` on the container.

You can also let Docker choose a random port on the host, and use the `port` command to list which ports the container exposes, and where they are published on the host:

```

> docker container port 6e

80/tcp -> 0.0.0.0:8081

```

Now I can browse to port `8081` on my machine and see the response from IIS running inside the container, showing me the hostname, which is actually the container ID, and in the title bar is the name of the environment:

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-win/img/76a58414-9209-4783-a22d-ef44c904ef3b.png)

The environment name is just a text description, but the value came from the argument is passed to the `docker image build` command, which overrides the default value from the `ARG` instruction in the Dockerfile. The hostname should show the container ID, but there's a problem with the current implementation.

On the web page the hostname starts with `bf37`, but my container ID actually starts with `6e3d`. To understand why the ID displayed isn't the actual ID of the running container, I'll look again at the temporary containers used during image builds.

# Understanding temporary containers and image state

My website container has an ID that starts with `6e3d`, which is the hostname that the application inside the container should see, but that's not what the website claims. So, what went wrong? Remember that Docker executes every build instruction inside a temporary, intermediate container.

The `RUN` instruction to generate the HTML ran in a temporary container, so the PowerShell script wrote *that* container's ID as the hostname in the HTML file; this is where the container ID starting with `bf37` came from. The intermediate container gets removed by Docker, but the HTML file it created persists within the image.

This is an important concept: when you build a Docker image, the instructions execute inside temporary containers. The containers are removed, but the state they write persists within the final image and will be present in any containers you run from that image. If I run multiple containers from my website image, they will all show the same hostname from the HTML file, because that's saved inside the image, which is shared by all containers.

Of course, you can also store the state in individual containers, which is not part of the image, so it's not shared between containers. I'll look at how to work with data in Docker now and then finish the chapter with a real-world Dockerfile example.

# Working with data in Docker images and containers

Applications running in a Docker container see a single filesystem which they can read from and write to in the usual way for the operating system. The container sees a single filesystem drive but it's actually a virtual filesystem, and the underlying data can be in many different physical locations.

Files which a container can access on its `C` drive could actually be stored in an image layer, in the container's own storage layer, or in a volume that is mapped to a location on the host. Docker merges all of these locations into a single virtual filesystem.

# Data in layers and the virtual C drive

The virtual filesystem is how Docker can take a set of physical image layers and treat them as one logical container image. Image layers are mounted as read-only parts of the filesystem in a container, so they can't be altered, and that's how they can be safely shared by many containers.

Each container has its own writeable layer on top of all of the read-only layers, so every container can modify its own data without affecting any other containers:

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-win/img/e5203dc0-e4fa-4e26-a79f-6665788e9d60.png)

This diagram shows two containers running from the same image. The image (1) is physically composed of many layers: one built from each instruction in the Dockerfile. The two containers (2 and 3) use the same layers from the image when they run, but they each have their own isolated, writeable layers.

Docker presents a single filesystem to the container. The concept of layers and read-only base layers is hidden, and your container just reads and writes data as if it had a full native filesystem, with a single drive. If you create a file when you build a Docker image and then edit the file inside a container, Docker actually creates a copy of the changed file in the container's writeable layer and hides the original read-only file. So the container has an edited copy of the file, but the original file in the image is unchanged.

You can see this by creating some simple images with data in different layers. The Dockerfile for the `dockeronwindows/ch02-fs-1:2e` image uses Nano Server as the base image, creates a directory, and writes a file into it:

```

# escape=` FROM mcr.microsoft.com/windows/nanoserver:1809 RUN md c:\data & `echo 'from image 1' > c:\data\file1.txt

```

The Dockerfile for the `dockeronwindows/ch02-fs-2:2e` image creates an image based on that image, and adds a second file to the data directory:

```

FROM dockeronwindows/ch02-fs-1:2e RUN echo 'from image 2' > c:\data\file2.txt

```

There's nothing special about *base* images; any image can be used in the `FROM` instruction for a new image. It can be an official image curated on Docker Hub, a commercial image from a private registry, a local image built from scratch, or an image that is many levels deep in a hierarchy.

I'll build both images and run an interactive container from `dockeronwindows/ch02-fs-2:2e`, so I can take a look at the files on the `C` drive. This command starts a container and gives it an explicit name, `c1`, so I can work with it without using the random container ID:

```

docker container run -it --name c1 dockeronwindows/ch02-fs-2:2e

```

Many options in the Docker commands have short and long forms. The long form starts with two dashes, like `--interactive`. The short form is a single letter and starts with a single dash, like `-i`. Short tags can be combined, so `-it` is equivalent to `-i -t`, which is equivalent to `--interactive --tty`. Run `docker --help` to navigate the commands and their options.

Nano Server is a minimal operating system, built for running apps in containers. It is not a full version of Windows, you can't run Nano Server as the OS on a VM or a physical machine, and you can't run all Windows apps in a Nano Server container. The base image is deliberately small, and even PowerShell is not included to keep the surface area down, meaning you need fewer updates and there are fewer potential attack vectors.

You need to brush off your old DOS commands to work with Nano Server containers. `dir` lists the directory contents inside the container:

```

C:\>dir C:\data

C 驱动器中的卷没有标签。

卷序列号为 BC8F-B36C

目录：C:\data

02/06/2019  11:00 AM    <DIR>          .

02/06/2019  11:00 AM    <DIR>          ..

02/06/2019  11:00 AM                17 file1.txt

02/06/2019  11:00 AM                17 file2.txt

```

Both of the files are there for the container to use in the `C:\data` directory; the first file is in a layer from the `ch02-fs-1:2e` image, and the second file is in a layer from the `ch02-fs-2:2e` image. The `dir` executable is available from another layer in the base Nano Server image, and the container sees them all in the same way.

I'll append some more text to one of the existing files and create a new file in the `c1` container:

```

C:\>echo ' * ADDITIONAL * ' >> c:\data\file2.txt

C:\>echo 'New!' > c:\data\file3.txt

C:\>dir C:\data

C 驱动器中的卷没有标签。

卷序列号为 BC8F-B36C

目录：C:\data

02/06/2019  01:10 PM    <DIR>          .

02/06/2019  01:10 PM    <DIR>          ..

02/06/2019  11:00 AM                17 file1.txt

02/06/2019  01:10 PM                38 file2.txt

02/06/2019  01:10 PM                 9 file3.txt

```

From the file listing you can see that `file2.txt` from the image layer has been modified and there is a new file, `file3.txt`. Now I'll exit this container and create a new one using the same image:

```

C:\> 退出

PS> docker container run -it --name c2 dockeronwindows/ch02-fs-2:2e

```

What are you expecting to see in the `C:\data` directory in this new container? Let's take a look:

```

C:\>dir C:\data

C 驱动器中的卷没有标签。

卷序列号为 BC8F-B36C

目录：C:\data

02/06/2019  11:00 AM    <DIR>          .

02/06/2019  11:00 AM    <DIR>          ..

02/06/2019  11:00 AM                17 file1.txt

02/06/2019  11:00 AM                17 file2.txt

```

You know that image layers are read-only and every container has its own writeable layer, so the results should make sense. The new container, `c2`, has the original files from the image without the changes from the first container, `c1`, which are stored in the writeable layer for `c1`. Each container's filesystem is isolated, so one container doesn't see any changes made by another container.

If you want to share data between containers, or between containers and the host, you can use Docker volumes.

# Sharing data between containers with volumes

Volumes are units of storage. They have a separate life cycle to containers, so they can be created independently and then mounted inside one or more containers. You can ensure containers are always created with volume storage using the `VOLUME` instruction in the Dockerfile.

You specify volumes with a target directory, which is the location inside the container where the volume is surfaced. When you run a container with a volume defined in the image, the volume is mapped to a physical location on the host, which is specific to that one container. More containers running from the same image will have their volumes mapped to a different host location.

In Windows, volume directories need to be empty. In your Dockerfile, you can't create files in a directory and then expose it as a volume. Volumes also need to be defined on a disk that exists in the image. In the Windows base images, there is only a `C` drive available, so volumes need to be created on the `C` drive.

The Dockerfile for `dockeronwindows/ch02-volumes:2e` creates an image with two volumes, and explicitly specifies the `cmd` shell as the `ENTRYPOINT` when containers are run from the image:

```

# escape=`

FROM mcr.microsoft.com/windows/nanoserver:1809 VOLUME C:\app\config VOLUME C:\app\logs USER ContainerAdministrator ENTRYPOINT cmd /S /C

```

Remember the Nano Server image uses a least-privilege user by default. Volumes are not accessible by that user, so this Dockerfile switches to the administrative account, and when you run a container from the image you can access volume directories.

When I run a container from that image, Docker creates a virtual filesystem from three sources. The image layers are read-only, the container's layer is writeable, and the volumes can be set to read-only or writeable:

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-win/img/f630b9fe-5ce9-44cb-b8ac-9f76da4fb8ab.png)

Because volumes are separate from the container, they can be shared with other containers even if the source container isn't running. I can run a task container from this image, with a command to create a new file in the volume:

```

docker container run --name source dockeronwindows/ch02-volumes:2e "echo 'start' > c:\app\logs\log-1.txt"

```

Docker starts the container, which writes the file, and then exits. The container and its volumes haven't been deleted, so I can connect to the volumes in another container using the `--volumes-from` option and by specifying my first container's name:

```

docker container run -it --volumes-from source dockeronwindows/ch02-volumes:2e cmd

```

This is an interactive container, and when I list the contents of the `C:\app` directory, I'll see the two directories, `logs` and `config`, which are volumes from the first container:

```

> ls C:\app

目录：C:\app

模式     最后写入时间      长度  名称

----     -------------      ------  ----

d----l   6/22/2017 8:11 AM          config

d----l   6/22/2017 8:11 AM          logs

```

The shared volume has read and write access, so I can see the file created in the first container and append to it:

```

C:\>type C:\app\logs\log-1.txt

开始

C:\>echo 'more' >> C:\app\logs\log-1.txt

C:\>type C:\app\logs\log-1.txt

开始

更多

```

Sharing data between containers like this is very useful; you can run a task container that takes a backup of data or log files from a long-running background container. The default access is for volumes to be writeable, but that's something to be wary of, as you could edit data and break the application running in the source container.

Docker lets you mount volumes from another container in read-only mode instead, by adding the `:ro` flag to the name of the container in the `--volumes-from` option. This is a safer way to access data if you want to read it without making changes. I'll run a new container, sharing the same volumes from the original container in read-only mode:

```

> docker container run -it --volumes-from source:ro dockeronwindows/ch02-volumes:2e cmd

C:\>type C:\app\logs\log-1.txt

开始

更多

C:\>echo 'more' >> C:\app\logs\log-1.txt

拒绝访问。

C:\>echo 'new' >> C:\app\logs\log-2.txt

拒绝访问。

```

In the new container I can't create a new file or write to the existing log file, but I can see the content in the log file from the original container, and the line appended by the second container.

# Sharing data between the container and host with volumes

Container volumes are stored on the host, so you can access them directly from the machine running Docker, but they'll be in a nested directory somewhere in Docker's program data directory. The `docker container inspect` command tells you the physical location for a container's volumes, along with a lot more information, including the container's ID, name, and the virtual IP address of the container in the Docker network.

I can use JSON formatting in the `container inspect` command, passing a query to extract just the volume information in the `Mounts` field. This command pipes the Docker output into a PowerShell cmdlet, to show the JSON in a friendly format:

```

> docker container inspect --format '{{ json .Mounts }}' source | ConvertFrom-Json

类型        : 卷

名称：65ab1b420a27bfd79d31d0d325622d0868e6b3f353c74ce3133888fafce972d9

来源：C：\ ProgramData \ docker \ volumes \ 65ab1b42 ... \ _data

目的地：c：\ app \ config

驱动程序：本地

RW：TruePropagation：

类型：卷

名称：b1451fde3e222adbe7f0f058a461459e243ac15af8770a2f7a4aefa7516e0761

来源：C：\ ProgramData \ docker \ volumes \ b1451fde ... \ _data

目的地：c：\ app \ logs

驱动程序：本地

RW：True

```

I've abbreviated the output, but in the `Source` field you can see the full path where the volume data is stored on the host. I can access the container's files directly from the host, using that source directory. When I run this command on my Windows machine, I'll see the file created inside the container volume:

```

> ls C：\ ProgramData \ docker \ volumes \ b1451fde ... \ _data

目录：C：\ ProgramData \ docker \ volumes \ b1451fde3e222adbe7f0f058a461459e243ac15af8770a2f7a4aefa7516e0761 \ _data

模式 LastWriteTime 长度名称

---- ------------- ------

-a---- 06/02/2019 13:33 19 log-1.txt

```

Accessing the files on the host is possible this way, but it's awkward to use the nested directory location with the volume ID. Instead you can mount a volume from a specific location on the host when you create a container.

# Mounting volumes from host directories

You use the `--volume` option to explicitly map a directory in a container from a known location on the host. The target location in the container can be a directory created with the `VOLUME` command, or any directory in the container's filesystem. If the target location already exists in the Docker image, it is hidden by the volume mount, so you won't see any of the image files.

I'll create a dummy configuration file for my app in a directory on the `C` drive on my Windows machine:

```

PS> mkdir C：\ app-config | Out-Null

PS> echo 'VERSION = 18.09' > C：\ app-config \ version.txt

```

Now I'll run a container which maps a volume from the host, and read the configuration file which is actually stored on the host:

```

> docker 容器运行`

--volume C：\ app-config：C：\ app \ config `

dockeronwindows / ch02-volumes：2e `

类型 C：\ app \ config \ version.txt

VERSION = 18.09

```

The `--volume` option specifies the mount in the format `{source}:{target}`. The source is the host location, which needs to exist. The target is the container location, which doesn't need to exist, but the existing contents will be hidden if it does exist.

Volume mounts are different in Windows and Linux containers. In Linux containers, Docker merges the contents from the source into the target, so if files exist in the image, you see them as well as the contents of the volume source. Docker on Linux also lets you mount a single file location, but on Windows you can only mount whole directories.

Volume mounts are useful for running stateful applications in containers, like databases. You can run SQL Server in a container, and have the database files stored in a location on the host, which could be a RAID array on the server. When you have schema updates, you remove the old container and start a new container from the updated Docker image. You use the same volume mount for the new container, so that the data is preserved from the old container.

# Using volumes for configuration and state

Application state is an important consideration when you're running applications in containers. Containers can be long-running, but they are not intended to be permanent. One of the biggest advantages with containers over traditional compute models is that you can easily replace them, and it only takes a few seconds to do so. When you have a new feature to deploy, or a security vulnerability to patch, you just build and test an upgraded image, stop the old container, and start a replacement from the new image.

Volumes let you manage that upgrade process by keeping your data separate from your application container. I'll demonstrate this with a simple web application that stores the hit count for a page in a text file; each time you browse to the page, the site increments the count.

The Dockerfile for the `dockeronwindows/ch02-hitcount-website` image uses multi-stage builds, compiling the application using the `microsoft/dotnet` image, and packaging the final app using `microsoft/aspnetcore` as the base:

```

# escape = `从 microsoft / dotnet：2.2-sdk-nanoserver-1809 AS 构建者的工作目录 C：\ src 复制 src。用户 ContainerAdministrator 运行 dotnet restore && dotnet publish # app image FROM microsoft / dotnet：2.2-aspnetcore-runtime-nanoserver-1809

EXPOSE 80 WORKDIR C：\ dotnetapp RUN mkdir app-state CMD ["dotnet", "HitCountWebApp.dll"] COPY --from=builder C：\ src \ bin \ Debug \ netcoreapp2.2 \ publish。

```

In the Dockerfile I create an empty directory at `C:\dotnetapp\app-state`, which is where the application will store the hit count in a text file. I've built the first version of the app into an image with the `2e-v1` tag:

```

docker image build --tag dockeronwindows / ch02-hitcount-website：2e-v1。

```

I'll create a directory on the host to use for the container's state, and run a container that mounts the application state directory from a directory on the host:

```

mkdir C：\ app-state

docker 容器运行-d --publish-all`

-v C：\ app-state：C：\ dotnetapp \ app-state `

--name appv1 `

dockeronwindows / ch02-hitcount-website：2e-v1

```

The `publish-all` option tells Docker to publish all the exposed ports from the container image to random ports on the host. This is a quick option for testing containers in a local environment, as Docker will assign a free port from the host and you don't need to worry about which ports are already in use by other containers. You find out the ports a container has published with the `container port` command:

```

> docker 容器端口 appv1

80 / tcp-> 0.0.0.0：51377

```

I can browse to the site at `http://localhost:51377`. When I refresh the page a few times, I'll see the hit count increasing:

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-win/img/47bcf624-7bdc-478d-a735-0edc36d20e14.png)

Now, when I have an upgraded version of the app to deploy, I can package it into a new image tagged with `2e-v2`. When the image is ready, I can stop the old container and start a new one using the same volume mapping:

```

PS> docker 容器停止 appv1

appv1

PS> docker 容器运行-d --publish-all `

-v C：\ app-state：C：\ dotnetapp \ app-state `

--name appv2 `

dockeronwindows / ch02-hitcount-website：2e-v2

db8a39ba7af43be04b02d4ea5d9e646c87902594c26a62168c9f8bf912188b62

```

The volume containing the application state gets reused, so the new version will continue using the saved state from the old version. I have a new container with a new published port. When I fetch the port and browse to it for the first time, I see the updated UI with an attractive icon, but the hit count is carried forward from version 1:

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-win/img/6d464a9f-b169-4970-9b8b-cc01198853c4.png)

Application state can have structural changes between versions, which is something you will need to manage yourself. The Docker image for the open source Git server, GitLab, is a good example of this. The state is stored in a database on a volume, and when you upgrade to a new version, the app checks the database and runs upgrade scripts if needed.

Application configuration is another way to make use of volume mounts. You can ship your application with a default configuration set built into the image, but users can override the base configuration with their own files using a mount.

You'll see these techniques put to good use in the next chapter.

# Packaging a traditional ASP.NET web app as a Docker image

Microsoft has made the Windows Server Core base image available on MCR, and that's a version of Windows Server 2019 which has much of the functionality of the full server edition, but without the UI. As base images go, it's very large: 2 GB compressed on Docker Hub, compared to 100 MB for Nano Server, and 2 MB for the tiny Alpine Linux image. But it means you can Dockerize pretty much any existing Windows app, and that's a great way to start migrating your systems to Docker.

Remember NerdDinner? It was an open source ASP.NET MVC showcase app, originally written by Scott Hanselman and Scott Guthrie among others at Microsoft. You can still get the code at CodePlex, but there hasn't been a change made since 2013, so it's an ideal candidate for proving that old .NET Framework apps can be migrated to Docker Windows containers, and this can be the first step in modernizing them.

# Writing a Dockerfile for NerdDinner

I'll follow the multi-stage build approach for NerdDinner, so the Dockerfile for the `dockeronwindows/ch-02-nerd-dinner:2e` images starts with a builder stage:

```

# escape = `从 microsoft / dotnet-framework：4.7.2-sdk-windowsservercore-ltsc2019 AS 构建者的工作目录 C：\ src \ NerdDinner 复制 src \ NerdDinner \ packages.config。运行 nuget restore packages.config -PackagesDirectory .. \ packages COPY src C：\ src RUN msbuild NerdDinner.csproj / p：OutputPath = c：\ out / p：Configuration = Release

```

The stage uses `microsoft/dotnet-framework` as the base image for compiling the application. This is an image which Microsoft maintains on Docker Hub. It's built on top of the Windows Server Core image, and it has everything you need to compile .NET Framework applications, including NuGet and MSBuild. The build stage happens in two parts:

1.  Copy the NuGet `packages.config` file into the image, and then run `nuget restore`.
2.  Copy the rest of the source tree and run `msbuild`.

Separating these parts means Docker will use multiple image layers: the first layer will contain all the restored NuGet packages, and the second layer will contain the compiled web app. This means I can take advantage of Docker's layer caching. Unless I change my NuGet references, the packages will be loaded from the cached layer and Docker won't run the restore part, which is an expensive operation. The MSBuild step will run every time any source files change.

If I had a deployment guide for NerdDinner, before the move to Docker, it would look something like this:

1.  Install Windows on a clean server.
2.  Run all Windows updates.
3.  Install IIS.
4.  Install .NET.
5.  Set up ASP.NET.
6.  Copy the web app into the `C` drive.
7.  Create an application pool in IIS.
8.  Create the website in IIS using the application pool.
9.  Delete the default website.

This will be the basis for the second stage of the Dockerfile, but I will be able to simplify all the steps. I can use Microsoft's ASP.NET Docker image as the `FROM` image, which will give me a clean install of Windows with IIS and ASP.NET installed. That takes care of the first five steps in one instruction. This is the rest of the Dockerfile for `dockeronwindows/ch-02-nerd-dinner:2e`:

```

FROM mcr.microsoft.com / dotnet / framework / aspnet：4.7.2-windowsservercore-ltsc2019 SHELL ["powershell", "-Command", "$ErrorActionPreference = 'Stop'] ENV BING_MAPS_KEY bing_maps_key WORKDIR C：\ nerd-dinner RUN Remove-Website -Name 'Default Web Site'; `

New-Website -Name 'nerd-dinner' ` -Port 80 -PhysicalPath 'c:\nerd-dinner' `-ApplicationPool '.NET v4.5' RUN & c:\windows\system32\inetsrv\appcmd.exe ` unlock config /section:system.webServer/handlers COPY --from=builder C:\out\_PublishedWebsites\NerdDinner C:\nerd-dinner

```

Microsoft uses both Docker Hub and MCR to store their Docker images. The .NET Framework SDK is on Docker Hub, but the ASP.NET runtime image is on MCR. You can always find where an image is hosted by checking on Docker Hub.

Using the `escape` directive and `SHELL` instruction lets me use normal Windows file paths without double backslashes, and PowerShell-style backticks to separate commands over many lines. Removing the default website and creating a new website in IIS is simple with PowerShell, and the Dockerfile clearly shows me the port the app is using and the path of the content.

I'm using the built-in .NET 4.5 application pool, which is a simplification from the original deployment process. In IIS on a VM you'd normally have a dedicated application pool for each website in order to isolate processes from each other. But in the containerized app, there will be only one website running. Any other websites will be running in other containers, so we already have isolation, and each container can use the default application pool without worrying about interference.

The final `COPY` instruction copies the published web application from the builder stage into the application image. It's the last line in the Dockerfile to take advantage of Docker's caching again. When I'm working on the app, the source code will be the thing I change most frequently. The Dockerfile is structured so that when I change code and run `docker image build`, the only instructions that run are MSBuild in the first stage and the copy in the second stage, so the build is very fast.

This could be all you need for a fully functioning Dockerized ASP.NET website, but in the case of NerdDinner there is one more instruction, which proves that you can cope with awkward, unexpected details when you containerize your application. The NerdDinner app has some custom configuration settings in the `system.webServer` section of its `Web.config` file, and by default the section is locked by IIS. I need to unlock the section, which I do with `appcmd` in the second `RUN` instruction.

Now I can build the image and run a legacy ASP.NET app in a Windows container:

```

docker container run -d -P dockeronwindows/ch02-nerd-dinner:2e

```

我可以使用`docker container port`来获取容器的发布端口，并浏览到 NerdDinner 的主页：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-win/img/2e704bc2-8b9b-4e32-a63d-4207c87a2d38.png)

这是一个六年前的应用程序，在 Docker 容器中运行，没有代码更改。Docker 是一个很好的平台，可以用来构建新的应用程序和现代化旧的应用程序，但它也是一个很好的方式，可以将现有的应用程序从数据中心移到云端，或者将它们从不再支持的旧版本的 Windows 中移出，比如 Windows Server 2003 和（很快）Windows Server 2008。

在这一点上，这个应用程序还没有完全功能，我只是运行了一个基本版本。Bing Maps 对象没有显示真实的地图，因为我还没有提供 API 密钥。API 密钥是每个环境（每个开发人员、测试环境和生产环境）都会改变的东西。

在 Docker 中，你可以使用环境变量和配置对象来管理环境配置，我将在第三章中使用这些内容来进行 Dockerfile 的下一个迭代，*开发 Docker 化的.NET Framework 和.NET Core 应用程序*。

如果你在这个版本的 NerdDinner 中浏览并尝试注册一个新用户或搜索一个晚餐，你会看到一个黄色的崩溃页面告诉你数据库不可用。在其原始形式中，NerdDinner 使用 SQL Server LocalDB 作为轻量级数据库，并将数据库文件存储在应用程序目录中。我可以将 LocalDB 运行时安装到容器映像中，但这与 Docker 的哲学不符，即一个容器只运行一个应用程序。相反，我将为数据库构建一个单独的映像，这样我就可以在它自己的容器中运行它。

在下一章中，我将对 NerdDinner 示例进行迭代，添加配置管理，将 SQL Server 作为一个独立组件在自己的容器中运行，并演示如何通过使用 Docker 平台来开始现代化传统的 ASP.NET 应用程序。

# 总结

在本章中，我更仔细地看了 Docker 镜像和容器。镜像是应用程序的打包版本，容器是从镜像运行的应用程序的实例。您可以使用容器来执行简单的一次性任务，与它们进行交互，或者让它们在后台运行。随着您对 Docker 的使用越来越多，您会发现自己会做这三种事情。

Dockerfile 是构建镜像的源脚本。它是一个简单的文本文件，包含少量指令来指定基础镜像，复制文件和运行命令。您可以使用 Docker 命令行来构建镜像，这非常容易添加到您的 CI 构建步骤中。当开发人员推送通过所有测试的代码时，构建的输出将是一个有版本的 Docker 镜像，您可以将其部署到任何主机，知道它将始终以相同的方式运行。

在本章中，我看了一些简单的 Dockerfile，并以一个真实的应用程序结束了。NerdDinner 是一个传统的 ASP.NET MVC 应用程序，它是为在 Windows Server 和 IIS 上运行而构建的。使用多阶段构建，我将这个传统的应用程序打包成一个 Docker 镜像，并在容器中运行它。这表明 Docker 提供的新的计算模型不仅适用于使用.NET Core 和 Nano Server 的新项目，您还可以将现有的应用程序迁移到 Docker，并使自己处于一个良好的现代化起步位置。

在下一章中，我将使用 Docker 来现代化 NerdDinner 的架构，将功能分解为单独的组件，并使用 Docker 将它们全部连接在一起。


# 第三章：开发 Docker 化的.NET Framework 和.NET Core 应用程序

Docker 是一个用于打包、分发、运行和管理应用程序的平台。当您将应用程序打包为 Docker 镜像时，它们都具有相同的形状。您可以以相同的方式部署、管理、保护和升级它们。所有 Docker 化的应用程序在运行时都具有相同的要求：在兼容的操作系统上运行 Docker 引擎。应用程序在隔离的环境中运行，因此您可以在同一台机器上托管不同的应用程序平台和不同的平台版本而不会发生干扰。

在.NET 世界中，这意味着您可以在单个 Windows 机器上运行多个工作负载。它们可以是 ASP.NET 网站，也可以是作为.NET 控制台应用程序或.NET Windows 服务运行的**Windows Communication Foundation**（**WCF**）应用程序。在上一章中，我们讨论了如何在不进行任何代码更改的情况下将传统的.NET 应用程序 Docker 化，但是 Docker 对容器内运行的应用程序应该如何行为有一些简单的期望，以便它们可以充分利用该平台的全部优势。

在本章中，我们将探讨如何构建应用程序，以便它们可以充分利用 Docker 平台，包括：

+   Docker 与您的应用程序之间的集成点

+   使用配置文件和环境变量配置您的应用程序

+   使用健康检查监视应用程序

+   在不同容器中运行分布式解决方案的组件

这将帮助您开发符合 Docker 期望的.NET 和.NET Core 应用程序，以便您可以完全使用 Docker 进行管理。

我们将在本章中涵盖以下主题：

+   为 Docker 构建良好的应用程序

+   分离依赖项

+   拆分单片应用程序

# 为 Docker 构建良好的应用程序

Docker 平台对使用它的应用程序几乎没有要求。您不受限于特定的语言或框架，您不需要使用特殊的库来在应用程序和容器之间进行通信，也不需要以特定的方式构建您的应用程序。

为了支持尽可能广泛的应用程序范围，Docker 使用控制台在应用程序和容器运行时之间进行通信。应用程序日志和错误消息预期出现在控制台输出和错误流中。由 Docker 管理的存储被呈现为操作系统的普通磁盘，Docker 的网络堆栈是透明的。应用程序将看起来像是在自己的机器上运行，通过普通的 TCP/IP 网络连接到其他机器。

Docker 中的一个良好应用是一个对其运行的系统几乎没有假设，并且使用所有操作系统支持的基本机制：文件系统、环境变量、网络和控制台。最重要的是，应用程序应该只做一件事。正如你所看到的，当 Docker 运行一个容器时，它启动 Dockerfile 或命令行中指定的进程，并监视该进程。当进程结束时，容器退出。因此，理想情况下，你应该构建你的应用程序只有一个进程，这样可以确保 Docker 监视重要的进程。

这些只是建议，而不是要求。当容器启动时，你可以在引导脚本中启动多个进程，Docker 会愉快地运行它，但它只会监视最后启动的进程。你的应用程序可以将日志条目写入本地文件，而不是控制台，Docker 仍然会运行它们，但如果你使用 Docker 来检查容器日志，你将看不到任何输出。

在.NET 中，你可以通过运行控制台应用程序轻松满足建议，这提供了应用程序和主机之间的简化集成，这也是为什么所有.NET Core 应用程序（包括网站和 Web API）都作为控制台应用程序运行的一个原因。对于传统的.NET 应用程序，你可能无法使它们成为完美的应用程序，但你可以注意打包它们，以便它们充分利用 Docker 平台。

# 在 Docker 中托管 Internet 信息服务（IIS）应用程序

完整的.NET Framework 应用程序可以轻松打包成 Docker 镜像，但你需要注意一些限制。微软为 Docker 提供了 Nano Server 和 Windows Server Core 基础镜像。完整的.NET Framework 无法在 Nano Server 上运行，因此要在 Docker 中托管现有的.NET 应用程序，你需要使用 Windows Server Core 基础镜像。

从 Windows Server Core 运行意味着您的应用程序镜像大小约为 4 GB，其中大部分在基础镜像中。您拥有完整的 Windows Server 操作系统，所有软件包都可用于启用 Windows Server 功能，如域名系统（DNS）和动态主机配置协议（DHCP），即使您只想将其用于单个应用程序角色。从 Windows Server Core 运行容器是完全合理的，但您需要了解其影响：

+   基础镜像具有大量安装的软件，这意味着它可能会有更频繁的安全和功能补丁。

+   操作系统除了您的应用程序进程外，还运行了许多自己的进程，因为 Windows 的几个核心部分作为后台 Windows 服务运行。

+   Windows 拥有自己的应用程序平台，具有高价值的特性集，用于托管和管理，这些特性与 Docker 方法不会自然集成。

您可以将 ASP.NET Web 应用程序 Docker 化几个小时。它将构建为一个大型 Docker 镜像，比基于轻量级现代应用程序堆栈构建的应用程序需要更长的时间来分发和启动。但您仍将拥有一个部署、配置和准备运行的整个应用程序的单一软件包。这是提高质量和减少部署时间的重要一步，也可以是现代化传统应用程序计划的第一部分。

将 ASP.NET 应用程序与 Docker 更紧密地集成，可以修改 IIS 日志的编写方式，指定 Docker 如何检查容器是否健康，并向容器注入配置，而无需对应用程序代码进行任何更改。如果更改代码是现代化计划的一部分，那么只需进行最小的更改，就可以使用容器的环境变量和文件系统进行应用程序配置。

# 为 Docker 友好的日志记录配置 IIS

IIS 将日志条目写入文本文件，记录 HTTP 请求和响应。您可以精确配置要写入的字段，但默认安装记录了诸如 HTTP 请求的路由、响应状态代码和 IIS 响应所需的时间等有用信息。将这些日志条目呈现给 Docker 是很好的，但 IIS 管理自己的日志文件，将条目缓冲到磁盘之前，并旋转日志文件以管理磁盘空间。

日志管理是应用程序平台的基本组成部分，这就是为什么 IIS 为 Web 应用程序负责，但 Docker 有自己的日志记录系统。Docker 日志记录比 IIS 使用的文本文件系统更强大和可插拔，但它只从容器的控制台输出流中读取日志条目。您不能让 IIS 将日志写入控制台，因为它在后台作为 Windows 服务运行，没有连接到控制台，所以您需要另一种方法。

有两种选择。第一种是构建一个 HTTP 模块，它插入到 IIS 平台中，具有一个事件处理程序，从 IIS 接收日志。此处理程序可以将所有消息发布到队列或 Windows 管道，因此您不会改变 IIS 日志的方式；您只是添加了另一个日志接收端。然后，您会将您的 Web 应用程序与一个监听已发布的日志条目并将其中继到控制台的控制台应用程序打包在一起。控制台应用程序将是容器启动时的入口点，因此每个 IIS 日志条目都会被路由到控制台供 Docker 读取。

HTTP 模块方法是强大且可扩展的，但在我们刚开始时，它增加了比我们需要的更多复杂性。第二个选项更简单 - 配置 IIS 将所有日志条目写入单个文本文件，并在容器的启动命令中运行一个 PowerShell 脚本来监视该文件，并将新的日志条目回显到控制台。当容器运行时，所有 IIS 日志条目都会回显到控制台，从而将它们呈现给 Docker。

在 Docker 镜像中设置这一点，首先需要配置 IIS，使其将任何站点的所有日志条目写入单个文件，并允许文件增长而不进行旋转。您可以在 Dockerfile 中使用 PowerShell 来完成这一点，使用`Set-WebConfigurationProperty` cmdlet 来修改应用程序主机级别的中央日志属性。我在`dockeronwindows/ch03-iis-log-watcher`镜像的 Dockerfile 中使用了这个 cmdlet：

```
RUN Set-WebConfigurationProperty -p 'MACHINE/WEBROOT/APPHOST' -fi 'system.applicationHost/log' -n 'centralLogFileMode' -v 'CentralW3C'; `
    Set-WebConfigurationProperty -p 'MACHINE/WEBROOT/APPHOST' -fi 'system.applicationHost/log/centralW3CLogFile' -n 'truncateSize' -v 4294967295; `
    Set-WebConfigurationProperty -p 'MACHINE/WEBROOT/APPHOST' -fi 'system.applicationHost/log/centralW3CLogFile' -n 'period' -v 'MaxSize'; `
    Set-WebConfigurationProperty -p 'MACHINE/WEBROOT/APPHOST' -fi 'system.applicationHost/log/centralW3CLogFile' -n 'directory' -v 'C:\iislog'
```

这是丑陋的代码，但它表明你可以在 Dockerfile 中编写任何你需要设置应用程序的内容。它配置 IIS 将所有条目记录到`C:\iislog`中的文件，并设置日志轮换的最大文件大小，让日志文件增长到 4GB。这足够的空间来使用 - 记住，容器不应该长时间存在，所以我们不应该在单个容器中有几 GB 的日志条目。IIS 仍然使用子目录格式来记录日志文件，所以实际的日志文件路径将是`C:\iislog\W3SVC\u_extend1.log`。现在我有了一个已知的日志文件位置，我可以使用 PowerShell 来回显日志条目到控制台。

我在`CMD`指令中执行这个操作，所以 Docker 运行和监控的最终命令是 PowerShell 的 cmdlet 来回显日志条目。当新条目被写入控制台时，它们会被 Docker 捕捉到。PowerShell 可以很容易地监视文件，但是有一个复杂的地方，因为文件需要在 PowerShell 监视之前存在。在 Dockerfile 中，我在启动时按顺序运行多个命令：

```
 CMD Start-Service W3SVC; `
     Invoke-WebRequest http://localhost -UseBasicParsing | Out-Null; `
     netsh http flush logbuffer | Out-Null; `
     Get-Content -path 'c:\iislog\W3SVC\u_extend1.log' -Tail 1 -Wait
```

容器启动时会发生四件事情：

1.  启动 IIS Windows 服务（W3SVC）。

1.  发出 HTTP `GET`请求到本地主机，启动 IIS 工作进程并写入第一个日志条目。

1.  刷新 HTTP 日志缓冲区，这样日志文件就会被写入磁盘并存在于 PowerShell 监视之中。

1.  以尾部模式读取日志文件的内容，这样文件中写入的任何新行都会显示在控制台上。

我可以以通常的方式从这个镜像中运行一个容器：

```
 docker container run -d -P --name log-watcher dockeronwindows/ch03-iis-log-watcher:2e
```

当我通过浏览到容器的 IP 地址（或在 PowerShell 中使用`Invoke-WebRequest`）发送一些流量到站点时，我可以看到从`Get-Content` cmdlet 使用`docker container logs`中中继到 Docker 的 IIS 日志条目：

```
> docker container logs log-watcher
2019-02-06 20:21:30 W3SVC1 172.27.97.43 GET / - 80 - 192.168.2.214 Mozilla/5.0+(Windows+NT+10.0;+Win64;+x64;+rv:64.0)+Gecko/20100101+Firefox/64.0 - 200 0 0 7
2019-02-06 20:21:30 W3SVC1 172.27.97.43 GET /iisstart.png - 80 - 192.168.2.214 Mozilla/5.0+(Windows+NT+10.0;+Win64;+x64;+rv:64.0)+Gecko/20100101+Firefox/64.0 http://localhost:51959/ 200 0 0 17
2019-02-06 20:21:30 W3SVC1 172.27.97.43 GET /favicon.ico - 80 - 192.168.2.214 Mozilla/5.0+(Windows+NT+10.0;+Win64;+x64;+rv:64.0)+Gecko/20100101+Firefox/64.0 - 404 0 2 23
```

IIS 始终在将日志条目写入磁盘之前在内存中缓冲日志条目，以提高性能进行微批量写入。刷新每 60 秒进行一次，或者当缓冲区大小为 64KB 时。如果你想强制容器中的 IIS 日志刷新，可以使用与我在 Dockerfile 中使用的相同的`netsh`命令：`docker container exec log-watcher netsh http flush logbuffer`。你会看到一个`Ok`输出，并且新的条目将在`docker container logs`中。

我已将配置添加到映像中的 IIS 和一个新命令，这意味着所有 IIS 日志条目都会被回显到控制台。这将适用于托管在 IIS 中的任何应用程序，因此我可以在不更改应用程序或站点内容的情况下回显 ASP.NET 应用程序和静态网站的 HTTP 日志。控制台输出是 Docker 查找日志条目的地方，因此这个简单的扩展将现有应用程序的日志集成到新平台中。

# 管理应用程序配置

在 Docker 映像中打包应用程序的目标是在每个环境中使用相同的映像。您不会为测试和生产构建单独的映像，因为这将使它们成为单独的应用程序，并且可能存在不一致性。您应该从用户测试的完全相同的 Docker 映像部署生产应用程序，这是生成过程生成的完全相同的映像，并用于所有自动集成测试的映像。

当然，一些东西需要在环境之间进行更改 - 数据库的连接字符串，日志级别和功能开关。这是应用程序配置，在 Docker 世界中，您使用默认配置构建应用程序映像，通常用于开发环境。在运行时，您将当前环境的正确配置注入到容器中，并覆盖默认配置。

有不同的方法来注入此配置。在本章中，我将向您展示如何使用卷挂载和环境变量。在生产中，您将运行运行 Docker 的机器集群，并且可以将配置数据存储在集群的安全数据库中，作为 Docker 配置对象或 Docker 秘密。我将在第七章中介绍这一点，*使用 Docker Swarm 编排分布式解决方案*。

# 在 Docker 卷中挂载配置文件

传统的应用程序平台使用配置文件在环境之间更改行为。 .NET Framework 应用程序具有丰富的基于 XML 的配置框架，而 Java 应用程序通常在属性文件中使用键值对。您可以在 Dockerfile 中向应用程序映像添加这些配置文件，并且当您从映像运行容器时，它将使用此默认配置。

您的应用程序设置应该使用一个特定的目录来存储配置文件，这样可以通过挂载 Docker 卷在运行时覆盖它们。我已经在`dockeronwindows/ch03-aspnet-config:2e`中使用了一个简单的 ASP.NET WebForms 应用程序。Dockerfile 只使用了您已经看到的命令：

```
# escape=` FROM mcr.microsoft.com/dotnet/framework/aspnet COPY Web.config C:\inetpub\wwwroot COPY config\*.config C:\inetpub\wwwroot\config\ COPY default.aspx C:\inetpub\wwwroot
```

这使用了微软的 ASP.NET 镜像作为基础，并复制了我的应用程序文件 - 一个 ASPX 页面和一些配置文件。在这个例子中，我正在使用默认的 IIS 网站，它从`C:\inetpub\wwwroot`加载内容，所以我只需要在 Dockerfile 中使用`COPY`指令，而不需要运行任何 PowerShell 脚本。

ASP.NET 期望在应用程序目录中找到`Web.config`文件，但您可以将配置的部分拆分成单独的文件。我已经在一个子目录中的文件中做到了这一点，这些文件是从`appSettings`和`connectionStrings`部分加载的：

```
<?xml version="1.0" encoding="utf-8"?> <configuration>
  <appSettings  configSource="config\appSettings.config"  />
  <connectionStrings  configSource="config\connectionStrings.config"  /> </configuration>
```

`config`目录填充了默认配置文件，所以我可以从镜像中运行容器，而不需要指定任何额外的设置：

```
docker container run -d -P dockeronwindows/ch03-aspnet-config:2e
```

当我获取容器的端口并浏览到它时，我看到网页显示来自默认配置文件的值：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-win/img/c2ba482d-3bc5-451f-af92-3f10af0aebb4.png)

我可以通过从主机上的目录加载配置文件，将本地目录挂载为一个卷，以`C:\inetpub\wwwroot\config`为目标，来为不同的环境运行应用程序。当容器运行时，该目录的内容将从主机上的目录加载：

```
docker container run -d -P `
 -v $pwd\prod-config:C:\inetpub\wwwroot\config `
 dockeronwindows/ch03-aspnet-config:2e
```

我正在使用 PowerShell 来运行这个命令，它会将`$pwd`扩展到当前目录的完整值，所以我在说当前路径中的`prod-config`目录应该被挂载为容器中的`C:\inetpub\wwwroot\config`。您也可以使用完全限定的路径。

当我浏览到这个容器的端口时，我看到不同的配置值显示出来：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-win/img/a42dd810-c2c0-4f38-9f3b-455b9164f98d.png)

这里重要的是，我在每个环境中使用完全相同的 Docker 镜像，具有相同的设置和相同的二进制文件。只有配置文件会改变，Docker 提供了一种优雅的方法来做到这一点。

# 推广环境变量

现代应用程序越来越多地使用环境变量作为配置设置，因为它们几乎被每个平台支持，从物理机器到 PaaS，再到无服务器函数。所有平台都以相同的方式使用环境变量 - 作为键值对的存储，因此通过使用环境变量进行配置，可以使您的应用程序具有高度的可移植性。

ASP.NET 应用程序已经在`Web.config`中具有丰富的配置框架，但通过一些小的代码更改，您可以将关键设置移动到环境变量中。这样，您可以为应用程序构建一个 Docker 镜像，在不同的平台上运行，并在容器中设置环境变量以更改配置。

Docker 允许您在 Dockerfile 中指定环境变量并给出初始默认值。`ENV`指令设置环境变量，您可以在每个`ENV`指令中设置一个或多个变量。以下示例来自于`dockeronwindows/ch03-iis-environment-variables:2e`的 Dockerfile。

```
 ENV A01_KEY A01 value
 ENV A02_KEY="A02 value" `
     A03_KEY="A03 value"
```

使用`ENV`在 Dockerfile 中添加的设置将成为镜像的一部分，因此您从该镜像运行的每个容器都将具有这些值。运行容器时，您可以使用`--env`或`-e`选项添加新的环境变量或替换现有镜像变量的值。您可以通过一个简单的 Nano Server 容器看到环境变量是如何工作的。

```
> docker container run `
  --env ENV_01='Hello' --env ENV_02='World' `
  mcr.microsoft.com/windows/nanoserver:1809 `
  cmd /s /c echo %ENV_01% %ENV_02%

Hello World
```

在 IIS 中托管的应用程序使用 Docker 中的环境变量存在一个复杂性。当 IIS 启动时，它会从系统中读取所有环境变量并对其进行缓存。当 Docker 运行具有设置的环境变量的容器时，它会将它们写入进程级别，但这发生在 IIS 缓存了原始值之后，因此它们不会被更新，IIS 应用程序将无法看到新值。然而，IIS 并不以相同的方式缓存机器级别的环境变量，因此我们可以将 Docker 设置的值提升为机器级别的环境变量，这样 IIS 应用程序就能够读取它们。

推广环境变量可以通过将它们从进程级别复制到机器级别来实现。您可以在容器启动命令中使用 PowerShell 脚本，通过循环遍历所有进程级别变量并将它们复制到机器级别，除非机器级别键已经存在。

```
 foreach($key in [System.Environment]::GetEnvironmentVariables('Process').Keys) {
     if ([System.Environment]::GetEnvironmentVariable($key, 'Machine') -eq $null) {
         $value = [System.Environment]::GetEnvironmentVariable($key, 'Process')
         [System.Environment]::SetEnvironmentVariable($key, $value, 'Machine')
     }
 }
```

如果您使用的是基于 Microsoft 的 IIS 镜像的图像，则无需执行此操作，因为它会为您使用一个名为`ServiceMonitor.exe`的实用程序，该实用程序已打包在 IIS 镜像中。ServiceMonitor 执行三件事——它使进程级环境变量可用，启动后台 Windows 服务，然后监视服务以确保其保持运行。这意味着您可以使用 ServiceMonitor 作为容器的启动进程，如果 IIS Windows 服务失败，ServiceMonitor 将退出，Docker 将看到您的应用程序已停止。

`ServiceMonitor.exe`可以在 GitHub 上作为二进制文件使用，但它不是开源的，并且并非所有行为都有文档记录（它似乎只适用于默认的 IIS 应用程序池）。它被复制到 Microsoft 的 IIS 镜像中，并设置为容器的`ENTRYPOINT`。ASP.NET 镜像是基于 IIS 镜像构建的，因此它也配置了 ServiceMonitor。

如果您想要在自己的逻辑中使用 ServiceMonitor 来回显 IIS 日志，您需要在后台启动 ServiceMonitor，并在 Dockerfile 中的启动命令中完成日志读取。我在`dockeronwindows/ch03-iis-environment-variables:2e`中使用 PowerShell 的`Start-Process`命令运行 ServiceMonitor：

```
ENTRYPOINT ["powershell"] CMD Start-Process -NoNewWindow -FilePath C:\ServiceMonitor.exe -ArgumentList w3svc; ` Invoke-WebRequest http://localhost -UseBasicParsing | Out-Null; `
    netsh http flush logbuffer | Out-Null; `
   Get-Content -path 'C:\iislog\W3SVC\u_extend1.log' -Tail 1 -Wait 
```

`ENTRYPOINT`和`CMD`指令都告诉 Docker 如何运行您的应用程序。您可以将它们组合在一起，以指定默认的入口点，并允许您的镜像用户在启动容器时覆盖命令。

图像中的应用程序是一个简单的 ASP.NET Web Forms 页面，列出了环境变量。我可以以通常的方式在容器中运行这个应用程序：

```
docker container run -d -P --name iis-env dockeronwindows/ch03-iis-environment-variables:2e
```

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-win/img/2e618d29-6ac9-4bbd-9146-05ec35667a31.png)

```
$port = $(docker container port iis-env).Split(':')[1]
start "http://localhost:$port"
```

网站显示了来自 Docker 镜像的默认环境变量值，这些值被列为进程级变量：

当容器启动时，我可以获取容器的端口，并在 ASP.NET Web Forms 页面上打开浏览器，使用一些简单的 PowerShell 脚本：

您可以使用不同的环境变量运行相同的镜像，覆盖其中一个镜像变量并添加一个新变量：

```
docker container run -d -P --name iis-env2 ` 
 -e A01_KEY='NEW VALUE!' ` 
 -e B01_KEY='NEW KEY!' `
 dockeronwindows/ch03-iis-environment-variables:2e
```

浏览新容器的端口，您将看到 ASP.NET 页面写出的新值：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-win/img/ef181092-bc3c-4348-8c38-689692850087.png)

我现在已经将对 Docker 环境变量管理的支持添加到了 IIS 镜像中，因此 ASP.NET 应用程序可以使用`System.Environment`类来读取配置设置。我在这个新镜像中保留了 IIS 日志回显，因此这是一个良好的 Docker 公民，现在您可以通过 Docker 配置应用程序并检查日志。

我可以做的最后一个改进是告诉 Docker 如何监视容器内运行的应用程序，以便 Docker 可以确定应用程序是否健康，并在其变得不健康时采取行动。

# 构建监视应用程序的 Docker 镜像

当我将这些新功能添加到 NerdDinner Dockerfile 并从镜像运行容器时，我将能够使用`docker container logs`命令查看 Web 请求和响应日志，该命令中继了 Docker 捕获的所有 IIS 日志条目，并且我可以使用环境变量和配置文件来指定 API 密钥和数据库用户凭据。这使得运行和管理传统的 ASP.NET 应用程序与我在 Docker 上运行的任何其他容器化应用程序的方式一致。我还可以配置 Docker 来监视容器，以便我可以管理任何意外故障。

Docker 提供了监视应用程序健康状况的能力，而不仅仅是检查应用程序进程是否仍在运行，使用 Dockerfile 中的`HEALTHCHECK`指令。使用`HEALTHCHECK`告诉 Docker 如何测试应用程序是否仍然健康。语法类似于`RUN`和`CMD`指令。您传递一个要执行的 shell 命令，如果应用程序健康，则应该返回`0`，如果不健康，则返回`1`。Docker 在容器运行时定期运行健康检查，并在容器的健康状况发生变化时发出状态事件。

Web 应用程序的*健康*的简单定义是能够正常响应 HTTP 请求。您进行的请求取决于您希望检查的彻底程度。理想情况下，请求应该执行应用程序的关键部分，以便您确信它全部正常工作。但同样，请求应该快速完成并且对计算影响最小，因此处理大量的健康检查不会影响消费者请求。

对于任何 Web 应用程序的简单健康检查只需使用`Invoke-WebRequest` PowerShell 命令来获取主页并检查 HTTP 响应代码是否为`200`，这意味着成功接收到响应：

```
try { 
    $response = iwr http://localhost/ -UseBasicParsing
    if ($response.StatusCode -eq 200) { 
        return 0
    } else {
        return 1
    } 
catch { return 1 }
```

对于更复杂的 Web 应用程序，添加一个专门用于健康检查的新端点可能很有用。您可以向 API 和网站添加一个诊断端点，该端点执行应用程序的一些核心逻辑并返回一个布尔结果，指示应用程序是否健康。您可以在 Docker 健康检查中调用此端点，并检查响应内容以及状态码，以便更有信心地确认应用程序是否正常工作。

Dockerfile 中的`HEALTHCHECK`指令非常简单。您可以配置检查之间的间隔和容器被视为不健康之前可以失败的检查次数，但是要使用默认值，只需在`HEALTHCHECK CMD`中指定测试脚本。以下是来自`dockeronwindows/ch03-iis-healthcheck:2e`镜像的 Dockerfile 的示例，它使用 PowerShell 向诊断 URL 发出`GET`请求并检查响应状态码：

```
HEALTHCHECK --interval=5s `
 CMD powershell -command `
    try { `
     $response = iwr http://localhost/diagnostics -UseBasicParsing; `
     if ($response.StatusCode -eq 200) { return 0} `
     else {return 1}; `
    } catch { return 1 }
```

我已经为健康检查指定了一个间隔，因此 Docker 将每 5 秒在容器内执行此命令（如果您不指定间隔，则默认间隔为 30 秒）。健康检查非常便宜，因为它是本地容器的，所以您可以设置这样的短间隔，并快速捕捉任何问题。

此 Docker 镜像中的应用程序是一个 ASP.NET Web API 应用程序，其中有一个诊断端点和一个控制器，您可以使用该控制器来切换应用程序的健康状态。Dockerfile 包含一个健康检查，当您从该镜像运行容器时，您可以看到 Docker 如何使用它：

```
docker container run -d -P --name healthcheck dockeronwindows/ch03-iis-healthcheck:2e
```

如果您在启动该容器后运行`docker container ls`，您会看到状态字段中稍有不同的输出，类似于`Up 3 seconds (health: starting)`。Docker 每 5 秒运行一次此容器的健康检查，所以在这一点上，检查尚未运行。稍等一会儿，然后状态将变为类似于`Up 46 seconds (healthy)`。

您可以通过查询“诊断”端点来检查 API 的当前健康状况：

```
$port = $(docker container port healthcheck).Split(':')[1]
iwr "http://localhost:$port/diagnostics"
```

在返回的内容中，您会看到`"Status":"GREEN"`，这意味着 API 是健康的。直到我调用控制器来切换健康状态之前，这个容器将保持健康。我可以通过一个`POST`请求来做到这一点，该请求将 API 设置为对所有后续请求返回 HTTP 状态`500`：

```
iwr "http://localhost:$port/toggle/unhealthy" -Method Post
```

现在，应用程序将对 Docker 平台发出的所有`GET`请求响应 500，这将导致健康检查失败。Docker 会继续尝试健康检查，如果连续三次失败，则认为容器不健康。此时，容器列表中的状态字段显示`Up 3 minutes (unhealthy)`。Docker 不会对不健康的单个容器采取自动操作，因此此容器仍在运行，您仍然可以访问 API。

在集群化的 Docker 环境中运行容器时，健康检查非常重要（我在第七章中介绍了*使用 Docker Swarm 编排分布式解决方案*），并且在所有 Dockerfile 中包含它们是一个良好的实践。能够打包一个平台可以测试健康状况的应用程序是一个非常有用的功能 - 这意味着无论在哪里运行应用程序，Docker 都可以对其进行检查。

现在，您拥有了所有工具，可以将 ASP.NET 应用程序容器化，并使其成为 Docker 的良好组成部分，与平台集成，以便可以像其他容器一样进行监视和管理。在 Windows Server Core 上运行的完整.NET Framework 应用程序无法满足运行单个进程的期望，因为所有必要的后台 Windows 服务，但您仍应构建容器映像，以便它们仅运行一个逻辑功能并分离任何依赖项。

# 分离依赖项

在上一章中，我将传统的 NerdDinner 应用程序 Docker 化并使其运行起来，但没有数据库。原始应用程序期望在与应用程序运行的同一主机上使用 SQL Server LocalDB。LocalDB 是基于 MSI 的安装，我可以通过下载 MSI 并在 Dockerfile 中使用`RUN`命令安装它来将其添加到 Docker 镜像中。但这意味着当我从镜像启动容器时，它具有两个功能：托管 Web 应用程序和运行数据库。

在一个容器中具有两个功能并不是一个好主意。如果您想要升级网站而不更改数据库会发生什么？或者如果您需要对数据库进行一些维护，而这不会影响网站会发生什么？如果您需要扩展网站呢？通过将这两个功能耦合在一起，您增加了部署风险、测试工作量和管理复杂性，并减少了操作灵活性。

相反，我将把数据库打包到一个新的 Docker 镜像中，在一个单独的容器中运行它，并使用 Docker 的网络层从网站容器访问数据库容器。SQL Server 是一个有许可的产品，但免费的变体是 SQL Server Express，它可以从 Docker Hub 上的微软镜像中获得，并带有生产许可证。我可以将其用作我的镜像的基础，构建它以准备一个预配置的数据库实例，其中架构已部署并准备连接到 Web 应用程序。

# 为 SQL Server 数据库创建 Docker 镜像

设置数据库镜像就像设置任何其他 Docker 镜像一样。我将把设置任务封装在一个 Dockerfile 中。总的来说，对于一个新的数据库，步骤将是：

1.  安装 SQL Server

1.  配置 SQL Server

1.  运行 DDL 脚本来创建数据库架构

1.  运行 DML 脚本来填充静态数据

这非常适合使用 Visual Studio 的 SQL 数据库项目类型和 Dacpac 部署模型的典型构建过程。从发布项目的输出是一个包含数据库架构和任何自定义 SQL 脚本的`.dacpac`文件。使用`SqlPackage`工具，您可以将 Dacpac 文件部署到 SQL Server 实例，它将创建一个新的数据库（如果不存在），或者升级现有的数据库，使架构与 Dacpac 匹配。

这种方法非常适合自定义 SQL Server Docker 镜像。我可以再次使用多阶段构建来为 Dockerfile 构建，这样其他用户就不需要安装 Visual Studio 来从源代码打包数据库。这是`dockeronwindows/ch03-nerd-dinner-db:2e`镜像的 Dockerfile 的第一阶段：

```
# escape=` FROM microsoft/dotnet-framework:4.7.2-sdk-windowsservercore-ltsc2019 AS builder SHELL ["powershell", "-Command", "$ErrorActionPreference = 'Stop';"] # add SSDT build tools RUN nuget install Microsoft.Data.Tools.Msbuild -Version 10.0.61804.210 # add SqlPackage tool ENV download_url="https://download.microsoft.com/download/6/E/4/6E406.../EN/x64/DacFramework.msi" RUN Invoke-WebRequest -Uri $env:download_url -OutFile DacFramework.msi ; `Start-Process msiexec.exe -ArgumentList '/i', 'DacFramework.msi', '/quiet', '/norestart' -NoNewWindow -Wait; `Remove-Item -Force DacFramework.msi WORKDIR C:\src\NerdDinner.Database COPY src\NerdDinner.Database . RUN msbuild NerdDinner.Database.sqlproj ` /p:SQLDBExtensionsRefPath="C:\Microsoft.Data.Tools.Msbuild.10.0.61804.210\lib\net46" ` /p:SqlServerRedistPath="C:\Microsoft.Data.Tools.Msbuild.10.0.61804.210\lib\net46" 
```

这里有很多内容，但都很简单。`builder`阶段从微软的.NET Framework SDK 镜像开始。这给了我`NuGet`和`MSBuild`，但没有我构建 SQL Server Dacpac 所需的依赖项。前两个`RUN`指令安装了 SQL Server 数据工具和`SqlPackage`工具。如果我有很多数据库项目要容器化，我可以将其打包为一个单独的 SQL Server SDK 镜像。

阶段的其余部分只是复制 SQL 项目源代码并运行`MSBuild`来生成 Dacpac。

这是 Dockerfile 的第二阶段，它打包了 NerdDinner Dacpac 以在 SQL Server Express 中运行：

```
FROM dockeronwindows/ch03-sql-server:2e ENV DATA_PATH="C:\data" ` sa_password="N3rdD!Nne720⁶" VOLUME ${DATA_PATH} WORKDIR C:\init COPY Initialize-Database.ps1 . CMD powershell ./Initialize-Database.ps1 -sa_password $env:sa_password -data_path $env:data_path -Verbose COPY --from=builder ["C:\\Program Files...\\DAC", "C:\\Program Files...\\DAC"] COPY --from=builder C:\docker\NerdDinner.Database.dacpac . 
```

我正在使用我自己的 Docker 镜像，其中安装了 SQL Server Express 2017。微软在 Docker Hub 上发布了用于 Windows 和 Linux 的 SQL Server 镜像，但 Windows 版本并没有定期维护。SQL Server Express 是免费分发的，所以你可以将其打包到自己的 Docker 镜像中（`dockeronwindows/ch03-sql-server`的 Dockerfile 在 GitHub 的`sixeyed/docker-on-windows`存储库中）。

除了您迄今为止看到的内容之外，这里没有新的说明。为 SQL Server 数据文件设置了一个卷，并设置了一个环境变量来将默认数据文件路径设置为`C:\data`。您会看到没有`RUN`命令，所以当我构建镜像时，我实际上并没有设置数据库架构；我只是将 Dacpac 文件打包到镜像中，这样我就有了创建或升级数据库所需的一切。

在`CMD`指令中，我运行一个设置数据库的 PowerShell 脚本。有时将所有启动细节隐藏在一个单独的脚本中并不是一个好主意，因为这意味着仅凭 Dockerfile 就无法看到容器运行时会发生什么。但在这种情况下，启动过程有很多功能，如果我们把它们都放在那里，Dockerfile 会变得非常庞大。

基本的 SQL Server Express 镜像定义了一个名为`sa_password`的环境变量来设置管理员密码。我扩展了这个镜像并为该变量设置了默认值。我将以相同的方式使用该变量，以便允许用户在运行容器时指定管理员密码。启动脚本的其余部分处理了在 Docker 卷中存储数据库状态的问题。

# 管理 SQL Server 容器的数据库文件

数据库容器与任何其他 Docker 容器一样，但侧重于状态。您需要确保数据库文件存储在容器之外，这样您就可以替换数据库容器而不会丢失任何数据。您可以像我们在上一章中看到的那样轻松地使用卷来实现这一点，但有一个问题。

如果您构建了一个带有部署的数据库架构的自定义 SQL Server 镜像，那么您的数据库文件将位于已知位置的镜像中。您可以从该镜像运行一个容器，而无需挂载卷，它将正常工作，但数据将存储在容器的可写层中。如果您在需要执行数据库升级时替换容器，那么您将丢失所有数据。

相反，您可以使用从主机挂载的卷来运行容器，将预期的 SQL Server 数据目录从主机目录映射到一个已知位置的主机上，这样，您的文件就可以存放在容器之外的主机上。这样，您可以确保您的数据文件存储在可靠的地方，比如在服务器上的 RAID 阵列中。但这意味着您不能在 Dockerfile 中部署数据库，因为数据目录将在镜像中存储数据文件，如果您在目录上挂载卷，这些文件将被隐藏。

微软的 SQL Server 镜像通过在运行时附加数据库和日志文件来处理这个问题，因此它的工作原理是您已经在主机上拥有数据库文件。在这种情况下，您可以直接使用该镜像，挂载您的数据文件夹，并使用参数运行 SQL Server 容器，告诉它要附加哪个数据库。这是一个非常有限的方法 - 这意味着您需要首先在不同的 SQL Server 实例上创建数据库，然后在运行容器时附加它。这与自动化发布流程不符。

对于我的自定义镜像，我想做一些不同的事情。镜像包含了 Dacpac，因此它具有部署数据库所需的一切。当容器启动时，我希望它检查数据目录，如果它是空的，那么我通过部署 Dacpac 模型来创建一个新的数据库。如果在容器启动时数据库文件已经存在，则首先附加数据库文件，然后使用 Dacpac 模型升级数据库。

这种方法意味着您可以使用相同的镜像在新环境中运行一个新的数据库容器，或者升级现有的数据库容器而不丢失任何数据。无论您是否从主机挂载数据库目录，这都能很好地工作，因此您可以让用户选择如何管理容器存储，因此该镜像支持许多不同的场景。

执行此操作的逻辑都在`Initialize-Database.ps1` PowerShell 脚本中，Dockerfile 将其设置为容器的入口点。在 Dockerfile 中，我将数据目录传递给 PowerShell 脚本中的`data_path`变量，并且脚本检查该目录中是否存在 NerdDinner 数据（`mdf`）和日志（`ldf`）文件：

```
$mdfPath  =  "$data_path\NerdDinner_Primary.mdf" $ldfPath  =  "$data_path\NerdDinner_Primary.ldf" # attach data files if they exist: if  ((Test-Path  $mdfPath)  -eq  $true) {  $sqlcmd  =  "IF DB_ID('NerdDinner') IS NULL BEGIN CREATE DATABASE NerdDinner ON (FILENAME = N'$mdfPath')"    if  ((Test-Path  $ldfPath)  -eq  $true) {   $sqlcmd  =  "$sqlcmd, (FILENAME = N'$ldfPath')"
 }  $sqlcmd  =  "$sqlcmd FOR ATTACH; END"  Invoke-Sqlcmd  -Query $sqlcmd  -ServerInstance ".\SQLEXPRESS" }
```

这个脚本看起来很复杂，但实际上，它只是构建了一个`CREATE DATABASE...FOR ATTACH`语句，如果 MDF 数据文件和 LDF 日志文件存在，则填写路径。然后它调用 SQL 语句，将外部卷中的数据库文件作为 SQL Server 容器中的新数据库附加。

这涵盖了用户使用卷挂载运行容器的情况，主机目录已经包含来自先前容器的数据文件。这些文件被附加，数据库在新容器中可用。接下来，脚本使用`SqlPackage`工具从 Dacpac 生成部署脚本。我知道`SqlPackage`工具存在，也知道它的路径，因为它是从构建阶段打包到我的镜像中的：

```
$SqlPackagePath  =  'C:\Program Files\Microsoft SQL Server\140\DAC\bin\SqlPackage.exe' &  $SqlPackagePath  `
  /sf:NerdDinner.Database.dacpac `
  /a:Script /op:deploy.sql /p:CommentOutSetVarDeclarations=true `
  /tsn:.\SQLEXPRESS /tdn:NerdDinner /tu:sa /tp:$sa_password  
```

如果容器启动时数据库目录为空，则容器中没有`NerdDinner`数据库，并且`SqlPackage`将生成一个包含一组`CREATE`语句的脚本来部署新数据库。如果数据库目录包含文件，则现有数据库将被附加。在这种情况下，`SqlPackage`将生成一个包含一组`ALTER`和`CREATE`语句的脚本，以使数据库与 Dacpac 保持一致。

在这一步生成的`deploy.sql`脚本将创建新模式，或者对旧模式进行更改以升级它。最终数据库模式在两种情况下都将是相同的。

最后，PowerShell 脚本执行 SQL 脚本，传入数据库名称、文件前缀和数据路径的变量：

```
$SqlCmdVars  =  "DatabaseName=NerdDinner",  "DefaultFilePrefix=NerdDinner"...  Invoke-Sqlcmd  -InputFile deploy.sql -Variable $SqlCmdVars  -Verbose
```

SQL 脚本运行后，数据库在容器中存在，并且其模式与 Dacpac 中建模的模式相同，Dacpac 是从 Dockerfile 的构建阶段中的 SQL 项目构建的。数据库文件位于预期位置，并具有预期名称，因此如果用相同镜像的另一个容器替换此容器，新容器将找到现有数据库并附加它。

# 在容器中运行数据库

现在我有一个数据库镜像，可以用于新部署和升级。开发人员可以使用该镜像，在他们开发功能时运行它而不挂载卷，这样他们每次运行容器时都可以从一个新的数据库开始。同样的镜像也可以在需要保留现有数据库的环境中使用，通过使用包含数据库文件的卷来运行容器。

这就是您在 Docker 中运行 NerdDinner 数据库的方式，使用默认管理员密码，带有数据库文件的主机目录，并命名容器，以便我可以从其他容器中访问它：

```
mkdir -p C:\databases\nd

docker container run -d -p 1433:1433 ` --name nerd-dinner-db ` -v C:\databases\nd:C:\data ` dockeronwindows/ch03-nerd-dinner-db:2e
```

第一次运行此容器时，Dacpac 将运行以创建数据库，并将数据和日志文件保存在主机上的挂载目录中。您可以使用`ls`检查主机上是否存在文件，并且`docker container logs`的输出显示生成的 SQL 脚本正在运行，并创建资源：

```
> docker container logs nerd-dinner-db
VERBOSE: Starting SQL Server
VERBOSE: Changing SA login credentials
VERBOSE: No data files - will create new database
Generating publish script for database 'NerdDinner' on server '.\SQLEXPRESS'.
Successfully generated script to file C:\init\deploy.sql.
VERBOSE: Changed database context to 'master'.
VERBOSE: Creating NerdDinner...
VERBOSE: Changed database context to 'NerdDinner'.
VERBOSE: Creating [dbo].[Dinners]...
...
VERBOSE: Deployed NerdDinner database, data files at: C:\data
```

我使用的`docker container run`命令还发布了标准的 SQL Server 端口`1433`，因此您可以通过.NET 连接或**SQL Server Management Studio**（**SSMS**）远程连接到容器内运行的数据库。如果您的主机上已经运行了 SQL Server 实例，您可以将容器的端口`1433`映射到主机上的不同端口。

要使用 SSMS、Visual Studio 或 Visual Studio Code 连接到运行在容器中的 SQL Server 实例，请使用`localhost`作为服务器名称，选择 SQL Server 身份验证，并使用`sa`凭据。我使用的是**SqlElectron**，这是一个非常轻量级的 SQL 数据库客户端：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-win/img/6fb1e102-ad53-4aca-a138-a1de00d35260.png)

然后，您可以像处理任何其他 SQL Server 数据库一样处理 Docker 化的数据库，查询表并插入数据。从 Docker 主机机器上，您可以使用`localhost`作为数据库服务器名称。通过发布端口，您可以在主机之外访问容器化的数据库，使用主机机器名称作为服务器名称。Docker 将端口`1433`上的任何流量路由到运行在容器上的 SQL Server。

# 从应用程序容器连接到数据库容器

Docker 平台内置了一个 DNS 服务器，容器用它来进行服务发现。我使用了一个显式名称启动了 NerdDinner 数据库容器，同一 Docker 网络中运行的任何其他容器都可以通过名称访问该容器，就像 Web 服务器通过其 DNS 主机名访问远程数据库服务器一样：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-win/img/57115c85-6752-43a3-9e3e-9f7c07780995.png)

这使得应用程序配置比传统的分布式解决方案简单得多。每个环境看起来都是一样的。在开发、集成测试、QA 和生产中，Web 容器将始终使用`nerd-dinner-db`主机名连接到实际运行在容器内的数据库。容器可以在同一台 Docker 主机上，也可以在 Docker Swarm 集群中的另一台独立机器上，对应用程序来说是透明的。

Docker 中的服务发现不仅适用于容器。容器可以使用其主机名访问网络上的另一台服务器。您可以在容器中运行 Web 应用程序，但仍然让它连接到物理机上运行的 SQL Server，而不是使用数据库容器。

每个环境可能有一个不同的配置，那就是 SQL Server 的登录凭据。在 NerdDinner 数据库镜像中，我使用了与本章前面的`dockeronwindows/ch03-aspnet-config`相同的配置方法。我已经将`Web.config`中的`appSettings`和`connectionStrings`部分拆分成单独的文件，并且 Docker 镜像将这些配置文件与默认值捆绑在一起。

开发人员可以直接从镜像中运行容器，并且它将使用默认的数据库凭据，这些凭据与 NerdDinner 数据库 Docker 镜像中内置的默认凭据相匹配。在其他环境中，可以通过在主机服务器上使用配置文件进行卷挂载来运行容器，这些配置文件指定了不同的应用程序设置和数据库连接字符串。

这是一个简化的安全凭据方法，我用它来展示如何使我们的应用更加适合 Docker，而不改变代码。将凭据保存在服务器上的纯文本文件中并不是管理机密信息的好方法，我将在第九章*了解 Docker 的安全风险和好处*中再次讨论这个问题，当时我会介绍 Docker 中的安全性。

本章对 NerdDinner 的 Dockerfile 进行了一些更新。我添加了健康检查和从 IIS 中输出日志的设置。我仍然没有对 NerdDinner 代码库进行任何功能性更改，只是将`Web.config`文件拆分，并将默认数据库连接字符串设置为使用运行在 Docker 中的 SQL Server 数据库容器。现在运行 Web 应用程序容器时，它将能够通过名称连接到数据库容器，并使用在 Docker 中运行的 SQL Server Express 数据库：

```
docker container run -d -P dockeronwindows/ch03-nerd-dinner-web:2e
```

您可以在创建容器时明确指定 Docker 网络应加入的容器，但在 Windows 上，所有容器默认加入名为`nat`的系统创建的 Docker 网络。数据库容器和 Web 容器都连接到`nat`网络，因此它们可以通过容器名称相互访问。

当容器启动时，我现在可以使用容器的端口打开网站，点击注册链接并创建一个账户：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-win/img/3a32ee44-2cc1-4d04-9244-6d2dd9139dad.png)

注册页面查询运行在 SQL Server 容器中的 ASP.NET 成员数据库。如果注册页面正常运行，则 Web 应用程序与数据库之间存在有效的连接。我可以在 Sqlectron 中验证这一点，查询`UserProfile`表并查看新用户行：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-win/img/d293f55f-0ad4-4806-b9a6-f5e771799b2e.png)

我现在已将 SQL Server 数据库与 Web 应用程序分离，每个组件都在一个轻量级的 Docker 容器中运行。在我的开发笔记本上，每个容器在空闲时使用的主机 CPU 不到 1%，数据库使用 250MB 内存，Web 服务器使用 70MB。

`docker container top`可以显示容器内运行的进程信息，包括内存和 CPU。

容器资源占用较少，因此将功能单元拆分为不同的容器没有任何惩罚，然后可以单独扩展、部署和升级这些组件。

# 拆分单片应用程序

传统的依赖于 SQL Server 数据库的.NET Web 应用程序可以以最小的工作量迁移到 Docker，而无需重写任何应用程序代码。在我的 NerdDinner 迁移的这个阶段，我有一个应用程序 Docker 镜像和一个数据库 Docker 镜像，我可以可靠地和重复地部署和维护。我还有一些有益的副作用。

在 Visual Studio 项目中封装数据库定义可能是一种新的方法，但它可以为数据库脚本添加质量保证，并将模式引入代码库，因此可以与系统的其余部分一起进行源代码控制和管理。Dacpacs、PowerShell 脚本和 Dockerfiles 为不同的 IT 功能提供了一个新的共同基础。开发、运维和数据库管理团队可以共同使用相同的语言在相同的工件上进行工作。

Docker 是 DevOps 转型的推动者，但无论您的路线图上是否有 DevOps，Docker 都为快速、可靠的发布提供了基础。为了最大限度地利用这一点，您需要考虑将单片应用程序分解为更小的部分，这样您就可以频繁发布高价值组件，而无需对整个大型应用程序进行回归测试。

从现有应用程序中提取核心组件可以在不进行大规模、复杂的重写的情况下将现代、轻量级技术引入您的系统。您可以将微服务架构原则应用于现有解决方案，其中您已经了解了值得提取到自己服务中的领域。

# 从单体中提取高价值组件

Docker 平台为现代化传统应用程序提供了巨大的机会，使您可以将特性从单体中取出并在单独的容器中运行。如果您可以隔离特性中的逻辑，这也是将其迁移到.NET Core 的机会，这样您可以将其打包成更小的 Docker 镜像。

微软的.NET Core 路线图已经看到它采用了更多的完整.NET Framework 功能，但将传统.NET 应用程序的部分移植到.NET Core 仍然可能是一项艰巨的任务。这是一个值得评估的选项，但它不必成为您现代化方法的一部分。分解单体的价值在于拥有可以独立开发、部署和维护的功能。如果这些组件正在使用完整的.NET Framework，您仍然可以获得这些好处。

当您现代化传统应用程序时的优势在于您已经了解了功能集。您可以识别系统中的高价值功能，并从中提取这些功能到它们自己的组件中。优秀的候选对象将是那些如果频繁更改就能为业务提供价值的功能，因此新的功能请求可以快速构建和部署，而无需修改和测试整个应用程序。

同样优秀的候选特性是那些如果保持不变就能为 IT 提供价值的特性-具有许多依赖关系的复杂组件，业务很少改变。将这样的特性提取到一个单独的组件中意味着您可以部署主应用程序的升级，而无需测试复杂组件，因为它保持不变。像这样分解单体应用程序会给您一组具有自己交付节奏的组件。

在 NerdDinner 中，有一些很适合分离成自己的服务的候选项。在本章的其余部分，我将专注于其中之一：主页。主页是渲染应用程序第一页的 HTML 的功能。在生产环境中快速而安全地部署主页更改的过程将让业务能够尝试新的外观和感觉，评估新版本的影响，并决定是否继续使用它。

当前应用程序分布在两个容器之间。在本章的这一部分，我将把主页分离成自己的组件，这样整个 NerdDinner 应用程序将在三个容器中运行：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-win/img/d7df03c2-ff8d-42c1-ae41-cda4c2ad0df0.png)

我不会改变应用程序的路由。用户仍然会首先进入 NerdDinner 应用程序，然后应用程序容器将调用新的主页服务容器以获取内容显示。这样我就不需要公开新的容器。更改只有一个技术要求：主应用程序需要能够与新的主页服务组件通信。

您可以自由选择容器中应用程序的通信方式。Docker 网络为 TCP/IP 和 UDP 提供了完整的协议支持。您可以使整个过程异步运行，将消息队列放在另一个容器中，并在其他容器中监听消息处理程序。但是在本章中，我将从更简单的方式开始。

# 在 ASP.NET Core 应用程序中托管 UI 组件

ASP.NET Core 是一个现代的应用程序堆栈，它在快速而轻量的运行时中提供了 ASP.NET MVC 和 Web API 的最佳功能。ASP.NET Core 网站作为控制台应用程序运行，它们将日志写入控制台输出流，并且它们可以使用环境变量和文件进行配置。这种架构使它们成为优秀的 Docker 公民。

将 NerdDinner 主页提取为一个新的服务的最简单方法是将其编写为一个 ASP.NET Core 网站，具有单个页面，并从现有应用程序中中继新应用程序的输出。以下屏幕截图显示了我在 Docker 中使用 ASP.NET Core Razor Pages 运行的时尚、现代化的主页重新设计：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-win/img/76fda9ae-bd4e-4b22-894c-26fef2521d7a.png)

为了将主页应用程序打包为 Docker 镜像，我正在使用与主应用程序和数据库镜像相同的多阶段构建方法。在第十章中，*使用 Docker 支持持续部署流水线*，您将看到如何使用 Docker 来支持 CI/CD 构建流水线，并将整个自动化部署过程联系在一起。

`dockeronwindows/ch03-nerd-dinner-homepage:2e`镜像的 Dockerfile 使用了与完整 ASP.NET 应用程序相同的模式。构建器阶段使用 SDK 镜像并分离包恢复和编译步骤：

```
# escape=` FROM microsoft/dotnet:2.2-sdk-nanoserver-1809 AS builder WORKDIR C:\src\NerdDinner.Homepage COPY src\NerdDinner.Homepage\NerdDinner.Homepage.csproj . RUN dotnet restore COPY src\NerdDinner.Homepage . RUN dotnet publish  
```

Dockerfile 的最后阶段为`NERD_DINNER_URL`环境变量提供了默认值。应用程序将其用作主页上链接的目标。 Dockerfile 的其余指令只是复制已发布的应用程序并设置入口点：

```
FROM microsoft/dotnet:2.2-aspnetcore-runtime-nanoserver-1809 WORKDIR C:\dotnetapp ENV NERD_DINNER_URL="/home/find" EXPOSE 80 CMD ["dotnet", "NerdDinner.Homepage.dll"] COPY --from=builder C:\src\NerdDinner.Homepage\bin\Debug\netcoreapp2.2\publish .
```

我可以在单独的容器中运行主页组件，但它尚未连接到主 NerdDinner 应用程序。使用本章中采用的方法，我需要对原始应用程序进行代码更改，以便集成新的主页服务。

# 从其他应用程序容器连接到应用程序容器

从主应用程序容器调用新主页服务基本上与连接到数据库相同：我将使用已知名称运行主页容器，并且可以使用其名称和 Docker 内置服务发现在其他容器中访问服务。

在主 NerdDinner 应用程序的`HomeController`类中进行简单更改，将从新主页服务中继承响应，而不是从主应用程序呈现页面：

```
static  HomeController() {
  var  homepageUrl  =  Environment.GetEnvironmentVariable("HOMEPAGE_URL", EnvironmentVariableTarget.Machine); if (!string.IsNullOrEmpty(homepageUrl))
  {
    var  request  =  WebRequest.Create(homepageUrl); using (var  response  =  request.GetResponse())
    using (var  responseStream  =  new  StreamReader(response.GetResponseStream()))
    {
      _NewHomePageHtml  =  responseStream.ReadToEnd();
    }
 } } public  ActionResult  Index() { if (!string.IsNullOrEmpty(_NewHomePageHtml)) { return  Content(_NewHomePageHtml);
  }
  else
  {
    return  Find();
 } }
```

在新代码中，我从环境变量中获取主页服务的 URL。与数据库连接一样，我可以在 Dockerfile 中为其设置默认值。在分布式应用程序中，这将是不好的做法，因为我们无法保证组件在何处运行，但是在 Docker 化应用程序中，我可以安全地这样做，因为我将控制容器的名称，因此在部署它们时，我可以确保服务名称是正确的。

我已将此更新的镜像标记为`dockeronwindows/ch03-nerd-dinner-web:2e-v2`。现在，要启动整个解决方案，我需要运行三个容器：

```
docker container run -d -p 1433:1433 `
 --name nerd-dinner-db ` 
 -v C:\databases\nd:C:\data `
 dockeronwindows/ch03-nerd-dinner-db:2e

docker container run -d -P `
 --name nerd-dinner-homepage `
 dockeronwindows/ch03-nerd-dinner-homepage:2e

docker container run -d -P dockeronwindows/ch03-nerd-dinner-web:2e-v2
```

当容器正在运行时，我浏览到 NerdDinner 容器的发布端口，我可以看到来自新组件的主页：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-win/img/f9efcc3f-8948-422d-84bb-56c6411792bb.png)

“找晚餐”链接将我带回原始的 Web 应用程序，现在我可以在主页上迭代并通过替换该容器发布新的用户界面 - 而无需发布或测试应用程序的其余部分。

新的用户界面发生了什么？在这个简单的例子中，集成的主页没有新的 ASP.NET Core 版本的样式，因为主应用程序只读取页面的 HTML，而不是 CSS 文件或其他资产。更好的方法是在容器中运行反向代理，并将其用作其他容器的入口点，这样每个容器都可以提供所有资产。我会在书中稍后做到这一点。

现在，我的解决方案分布在三个容器中，我大大提高了灵活性。在构建时，我可以专注于提供最高价值的功能，而不必费力测试未更改的组件。在部署时，我可以快速而自信地发布，知道我们推送到生产环境的新镜像将与测试的内容完全相同。然后在运行时，我可以根据其要求独立地扩展组件。

我确实有一个新的非功能性要求，那就是确保所有容器都具有预期的名称，按正确的顺序启动，并且在同一个 Docker 网络中，以便整个解决方案正常工作。Docker 对此提供了支持，重点是使用 Docker Compose 组织分布式系统。我会在第六章中向您展示这一点，*使用 Docker Compose 组织分布式解决方案*。

# 总结

在本章中，我们涵盖了三个主要主题。首先，我们介绍了将传统的.NET Framework 应用程序容器化，使其成为良好的 Docker 公民，并与平台集成以进行配置、日志记录和监视。

然后，我们介绍了如何使用 SQL Server Express 和 Dacpac 部署模型将数据库工作负载容器化，构建一个版本化的 Docker 镜像，可以将容器作为新数据库运行，或升级现有数据库。

最后，我们展示了如何将单片应用程序的功能提取到单独的容器中，使用 ASP.NET Core 和 Windows Nano Server 打包一个快速、轻量级的服务，主应用程序可以使用。

您已经学会了如何在 Docker Hub 上使用来自 Microsoft 的更多图像，以及如何为完整的.NET 应用程序使用 Windows Server Core，为数据库使用 SQL Server Express，以及.NET Core 图像的 Nano Server 版本。

在后面的章节中，我会回到 NerdDinner，并继续通过将功能提取到专用服务中来使其现代化。在那之前，在下一章中，我会更仔细地研究如何使用 Docker Hub 和其他注册表来存储镜像。


# 第四章：使用 Docker 注册表共享镜像

发布应用程序是 Docker 平台的一个重要部分。Docker 引擎可以从中央位置下载镜像以从中运行容器，并且还可以上传本地构建的镜像到中央位置。这些共享的镜像存储被称为**注册表**，在本章中，我们将更仔细地看一下镜像注册表的工作原理以及可用于您的注册表的类型。

主要的镜像注册表是 Docker Hub，这是一个免费的在线服务，也是 Docker 服务默认的工作位置。Docker Hub 是一个很好的地方，社区可以分享构建的用于打包开源软件并且可以自由重新分发的镜像。Docker Hub 取得了巨大的成功。在撰写本书时，上面有数十万个可用的镜像，每年下载量达数十亿次。

公共注册表可能不适合您自己的应用程序。Docker Hub 还提供商业计划，以便您可以托管私有镜像（类似于 GitHub 允许您托管公共和私有源代码仓库的方式），还有其他商业注册表添加了诸如安全扫描之类的功能。您还可以通过使用免费提供的开源注册表实现在您的环境中运行自己的注册表服务器。

在本章中，我将向您展示如何使用这些注册表，并且我将介绍标记镜像的细节 - 这是您可以对 Docker 镜像进行版本控制的方法 - 以及如何使用来自不同注册表的镜像。我们将涵盖：

+   理解注册表和仓库

+   运行本地镜像注册表

+   使用本地注册表推送和拉取镜像

+   使用商业注册表

# 理解注册表和仓库

您可以使用`docker image pull`命令从注册表下载镜像。运行该命令时，Docker 引擎连接到注册表，进行身份验证 - 如果需要的话 - 并下载镜像。拉取过程会下载所有镜像层并将它们存储在本地镜像缓存中。容器只能从本地镜像缓存中可用的镜像运行，因此除非它们是本地构建的，否则需要先拉取。

在 Windows 上开始使用 Docker 时，您运行的最早的命令之一可能是一些简单的命令，就像来自第二章的这个例子，*将应用程序打包并作为 Docker 容器运行*。

```
> docker container run dockeronwindows/ch02-powershell-env:2e

Name                           Value
----                           -----
ALLUSERSPROFILE                C:\ProgramData
APPDATA                        C:\Users\ContainerAdministrator\AppData\Roaming
...
```

这将起作用，即使您在本地缓存中没有该镜像，因为 Docker 可以从默认注册表 Docker Hub 中拉取它。如果您尝试从本地没有存储的镜像运行容器，Docker 将在创建容器之前自动拉取它。

在这个例子中，我没有给 Docker 太多信息——只是镜像名称，`dockeronwindows/ch02-powershell-env:2e`。这个细节足以让 Docker 在注册表中找到正确的镜像，因为 Docker 会用默认值填充一些缺失的细节。仓库的名称是`dockeronwindows/ch02-powershell-env`，仓库是一个可以包含多个 Docker 镜像版本的存储单元。

# 检查镜像仓库名称

仓库有一个固定的命名方案：`{registry-domain}/{account-id}/{repository-name}:{tag}`。所有部分都是必需的，但 Docker 会假设一些值的默认值。所以`dockeronwindows/ch02-powershell-env:2e`实际上是完整仓库名称的简写形式，即`docker.io/dockeronwindows/ch02-powershell-env:2e`：

+   `registry-domain`是存储镜像的注册表的域名或 IP 地址。Docker Hub 是默认的注册表，所以在使用来自 Hub 的镜像时，可以省略注册表域。如果不指定注册表，Docker 将使用`docker.io`作为注册表。

+   `account-id`是在注册表上拥有镜像的帐户或组织的名称。在 Docker Hub 上，帐户名称是强制的。我的帐户 ID 是`sixeyed`，伴随本书的图像的组织帐户 ID 是`dockeronwindows`。在其他注册表上，可能不需要帐户 ID。

+   `repository-name`是您想要为镜像指定的名称，以在注册表上的您的所有仓库中唯一标识应用程序。

+   `tag`是用来区分仓库中不同镜像变体的方式。

您可以使用标签对应用程序进行版本控制或识别变体。如果在构建或拉取镜像时未指定标签，Docker 将使用默认标签`latest`。当您开始使用 Docker 时，您将使用 Docker Hub 和`latest`标签，这是 Docker 提供的默认值，以隐藏一些复杂性，直到您准备深入挖掘。随着您继续使用 Docker，您将使用标签来清楚地区分应用程序包的不同版本。

一个很好的例子是微软的.NET Core 基础图像，它位于 Docker Hub 的`microsoft/dotnet`存储库中。 .NET Core 是一个在 Linux 和 Windows 上运行的跨平台应用程序堆栈。您只能在基于 Linux 的 Docker 主机上运行 Linux 容器，并且只能在基于 Windows 的 Docker 主机上运行 Windows 容器，因此 Microsoft 在标签名称中包含了操作系统。

在撰写本文时，Microsoft 在`microsoft/dotnet`存储库中提供了数十个版本的.NET Core 图像可供使用，并使用不同的标签进行标识。以下只是一些标签：

+   `2.2-runtime-bionic`是基于 Ubuntu 18.04 版本的 Linux 图像，其中安装了.NET Core 2.2 运行时

+   `2.2-runtime-nanoserver-1809`是一个 Nano Server 1809 版本的图像，其中安装了.NET Core 2.2 运行时

+   `2.2-sdk-bionic`是基于 Debian 的 Linux 图像，其中安装了.NET Core 2.2 运行时和 SDK

+   `2.2-sdk-nanoserver-1809`是一个 Nano Server 图像，其中安装了.NET Core 2.2 运行时和 SDK

这些标签清楚地表明了每个图像包含的内容，但它们在根本上都是相似的 - 它们都是`microsoft/dotnet`的变体。

Docker 还支持多架构图像，其中单个图像标签用作许多变体的总称。可以基于 Linux 和 Windows 操作系统，或英特尔和**高级 RISC 机器**（**ARM**）处理器的图像变体。它们都使用相同的图像名称，当您运行`docker image pull`时，Docker 会为您的主机操作系统和 CPU 架构拉取匹配的图像。 .NET Core 图像可以做到这一点 - `docker image pull microsoft/dotnet:2.2-sdk`将在 Linux 机器上下载 Linux 图像，在 Windows 机器上下载 Windows 图像。

如果您将跨平台应用程序发布到 Docker Hub，并且希望尽可能地让消费者使用它，您应该将其发布为多架构图像。在您自己的开发中，最好是明确地在 Dockerfiles 中指定确切的`FROM`图像，否则您的应用程序将在不同的操作系统上构建不同。

# 构建、标记和版本化图像

当您首次构建图像时，您会对图像进行标记，但您也可以使用`docker image tag`命令显式地向图像添加标签。这在对成熟应用程序进行版本控制时非常有用，因此用户可以选择要使用的版本级别。如果您运行以下命令，您将构建一个具有五个标签的图像，其中包含应用程序版本的不同精度级别：

```
docker image build -t myapp .
docker image tag myapp:latest myapp:5
docker image tag myapp:latest myapp:5.1
docker image tag myapp:latest myapp:5.1.6
docker image tag myapp:latest myapp:bc90e9
```

最初的 `docker image build` 命令没有指定标记，因此新图像将默认为 `myapp:latest`。每个后续的 `docker image tag` 命令都会向同一图像添加一个新标记。标记不会复制图像，因此没有数据重复 - 您只有一个图像，可以用多个标记引用。通过添加所有这些标记，您为消费者提供了选择使用哪个图像，或者以其为基础构建自己的图像。

此示例应用程序使用语义化版本。最终标记可以是触发构建的源代码提交的 ID；这可能在内部使用，但不公开。`5.1.6` 是补丁版本，`5.1` 是次要版本号，`5` 是主要版本号。

用户可以明确使用 `myapp:5.1.6`，这是最具体的版本号，知道该标记不会在该级别更改，图像将始终相同。下一个发布将具有标记 `5.1.7`，但那将是一个具有不同应用程序版本的不同图像。

`myapp:5.1` 将随着每个补丁版本的发布而更改 - 下一个构建，`5.1` 将是 `5.1.7` 的标记别名 - 但用户可以放心，不会有任何破坏性的更改。`myapp:5` 将随着每个次要版本的发布而更改 - 下个月，它可能是 `myapp:5.2` 的别名。用户可以选择主要版本，如果他们总是想要版本 5 的最新发布，或者他们可以使用最新版本，可以接受可能的破坏性更改。

作为图像的生产者，您可以决定如何支持图像标记中的版本控制。作为消费者，您应该更加具体 - 尤其是对于您用作自己构建的 `FROM` 图像。如果您正在打包 .NET Core 应用程序，如果您的 Dockerfile 像这样开始：

```
FROM microsoft/dotnet:sdk
```

在撰写本文时，此图像已安装了 .NET Core SDK 的 2.2.103 版本。如果您的应用程序针对 2.2 版本，那就没问题；图像将构建，您的应用程序将在容器中正确运行。但是，当 .NET Core 2.3 或 3.0 发布时，新图像将应用通用的 `:sdk` 标记，这可能不支持针对 2.2 应用程序的目标。在该发布之后使用完全相同的 Dockerfile 时，它将使用不同的基础图像 - 您的图像构建可能会失败，或者它可能仅在应用程序运行时失败，如果 .NET Core 更新中存在破坏性更改。

相反，您应该考虑使用应用程序框架的次要版本的标签，并明确说明操作系统和 CPU 架构（如果是多架构图片）：

```
FROM microsoft/dotnet:2.2-sdk-nanoserver-1809
```

这样，您将受益于图像的任何补丁版本，但您将始终使用.NET Core 的 2.2 版本，因此您的应用程序将始终在基础图像中具有匹配的主机平台。

您可以标记您本地缓存中的任何图像，而不仅仅是您自己构建的图像。如果您想要重新标记一个公共图像并将其添加到本地私有注册表中的批准基础图像集中，这将非常有用。

# 将图像推送到注册表

构建和标记图像是本地操作。`docker image build`和`docker image tag`的最终结果是对您运行命令的 Docker Engine 上的图像缓存的更改。需要使用`docker image push`命令将图像明确共享到注册表中。

Docker Hub 可供使用，无需进行身份验证即可拉取公共图像，但是要上传图像（或拉取私有图像），您需要注册一个账户。您可以在[`hub.docker.com/`](https://hub.docker.com/)免费注册，这是您可以在 Docker Hub 和其他 Docker 服务上使用的 Docker ID 的地方。您的 Docker ID 是您用来验证访问 Docker Hub 的 Docker 服务的方式。这是通过`docker login`命令完成的：

```
> docker login
Login with your Docker ID to push and pull images from Docker Hub. If you don't have a Docker ID, head over to https://hub.docker.com to create one.
Username: sixeyed
Password:
Login Succeeded
```

要将图片推送到 Docker Hub，仓库名称必须包含您的 Docker ID 作为账户 ID。您可以使用任何账户 ID 在本地标记一个图片，比如`microsoft/my-app`，但是您不能将其推送到注册表上的 Microsoft 组织。您登录的 Docker ID 需要有权限将图片推送到注册表上的账户。

当我发布图片以配合这本书时，我会使用`dockeronwindows`作为仓库中的账户名来构建它们。这是 Docker Hub 上的一个组织，而我的用户账户`sixeyed`有权限将图片推送到该组织。当我以`sixeyed`登录时，我可以将图片推送到属于`sixeyed`或`dockeronwindows`的仓库：

```
docker image push sixeyed/git:2.17.1-windowsservercore-ltsc2019 docker image push dockeronwindows/ch03-iis-healthcheck:2e 
```

Docker CLI 的输出显示了图像如何分成层，并告诉您每个层的上传状态：

```
The push refers to repository [docker.io/dockeronwindows/ch03-iis-healthcheck]
55e5e4877d55: Layer already exists
b062c01c8395: Layer already exists
7927569daca5: Layer already exists
...
8df29e538807: Layer already exists
b42b16f07f81: Layer already exists
6afa5894851e: Layer already exists
4dbfee563a7a: Skipped foreign layer
c4d02418787d: Skipped foreign layer
2e: digest: sha256:ffbfb90911efb282549d91a81698498265f08b738ae417bc2ebeebfb12cbd7d6 size: 4291
```

该图像使用 Windows Server Core 作为基本图像。该图像不是公开可再分发的 - 它在 Docker Hub 上列出，并且可以从 Microsoft 容器注册表免费下载，但未经许可不得存储在其他公共图像注册表上。这就是为什么我们可以看到标有*跳过外部层*的行 - Docker 不会将包含 Windows OS 的层推送到 Docker Hub。

您无法发布到另一个用户的帐户，但可以使用您自己的帐户名称标记另一个用户的图像。这是一组完全有效的命令，如果我想要下载特定版本的 Windows Server Core 图像，给它一个更友好的名称，并在我的帐户下使用该新名称在 Hub 上提供它，我可以运行这些命令：

```
docker image pull mcr.microsoft.com/windows/servercore:1809_KB4480116_amd64
docker image tag mcr.microsoft.com/windows/servercore:1809_KB4480116_amd64 `
  sixeyed/windowsservercore:2019-1811
docker image push sixeyed/windowsservercore:2019-1811
```

Microsoft 在不同的时间使用了不同的标记方案来标记他们的图像。Windows Server 2016 图像使用完整的 Windows 版本号，如`10.0.14393.2608`。Windows Server 2019 图像使用发布名称，后跟图像中包含的最新 Windows 更新的 KB 标识符，如`1809_KB4480116`。

对于用户来说，将图像推送到注册表并不比这更复杂，尽管在幕后，Docker 运行一些智能逻辑。图像分层也适用于注册表，就像适用于 Docker 主机上的本地图像缓存一样。当您将基于 Windows Server Core 的图像推送到 Hub 时，Docker 不会上传 4GB 的基本图像 - 它知道基本层已经存在于 MCR 上，并且只会上传目标注册表上缺少的层。

将公共图像标记并推送到公共 Hub 的最后一个示例是有效的，但不太可能发生 - 您更有可能将图像标记并推送到您自己的私有注册表。

# 运行本地图像注册表

Docker 平台是可移植的，因为它是用 Go 语言编写的，这是一种跨平台语言。Go 应用程序可以编译成本地二进制文件，因此 Docker 可以在 Linux 或 Windows 上运行，而无需用户安装 Go。在 Docker Hub 上有一个包含用 Go 编写的注册表服务器的官方图像，因此您可以通过从该图像运行 Docker 容器来托管自己的图像注册表。

`registry`是由 Docker 团队维护的官方存储库，但在撰写本文时，它只有适用于 Linux 的图像。很可能很快就会发布注册表的 Windows 版本，但在本章中，我将向您介绍如何构建自己的注册表图像，因为它展示了一些常见的 Docker 使用模式。

*官方存储库*就像其他公共镜像一样在 Docker Hub 上可用，但它们经过 Docker, Inc.的策划，并由 Docker 自己或应用程序所有者维护。您可以依赖它们包含正确打包和最新软件。大多数官方镜像都有 Linux 变体，但 Windows 官方镜像的数量正在增加。

# 构建注册表镜像

Docker 的注册服务器是一个完全功能的镜像注册表，但它只是 API 服务器 - 它没有像 Docker Hub 那样的 Web UI。它是一个开源应用程序，托管在 GitHub 的`docker/distribution`存储库中。要在本地构建该应用程序，您首先需要安装 Go SDK。如果您已经这样做了，可以运行一个简单的命令来编译该应用程序：

```
go get github.com/docker/distribution/cmd/registry
```

但是，如果您不是经常使用 Go 开发人员，您不希望在本地机器上安装和维护 Go 工具的开销，只是为了在需要更新时构建注册服务器。最好将 Go 工具打包到一个 Docker 镜像中，并设置该镜像，以便在运行容器时为您构建注册服务器。您可以使用我在第三章中演示的相同的多阶段构建方法，*开发 Docker 化的.NET Framework 和.NET Core 应用程序*。

多阶段模式有很多优势。首先，这意味着您的应用程序镜像可以尽可能地保持轻量级 - 您不需要将构建工具与运行时一起打包。其次，这意味着您的构建代理被封装在一个 Docker 镜像中，因此您不需要在构建服务器上安装这些工具。第三，这意味着开发人员可以使用与构建服务器相同的构建过程，因此您避免了开发人员机器和构建服务器安装了不同的工具集的情况，这可能导致构建问题。

`dockeronwindows/ch04-registry:2e`的 Dockerfile 使用官方的 Go 镜像，在 Docker Hub 上有一个 Windows Server Core 变体。构建阶段使用该镜像来编译注册表应用程序：

```
# escape=` FROM golang:1.11-windowsservercore-1809 AS builder ARG REGISTRY_VERSION="v2.6.2" WORKDIR C:\gopath\src\github.com\docker RUN git clone https://github.com/docker/distribution.git; ` cd distribution; `
    git checkout $env:REGISTRY_VERSION; `
    go build -o C:\out\registry.exe .\cmd\registry  
```

我使用`ARG`指令来指定要构建的源代码版本——GitHub 存储库为每个发布的版本都有标签，我默认使用版本 2.6.2。然后我使用`git`来克隆源代码并切换到标记版本的代码，并使用`go build`来编译应用程序。Git 客户端和 Go 工具都在基本的`golang`映像中。输出将是`registry.exe`，这是一个本地的 Windows 可执行文件，不需要安装 Go 就可以运行。

Dockerfile 的最后阶段使用 Nano Server 作为基础，可以很好地运行 Go 应用程序。以下是整个应用程序阶段：

```
FROM mcr.microsoft.com/windows/nanoserver:1809 ENV REGISTRY_STORAGE_FILESYSTEM_ROOTDIRECTORY="C:\data"  VOLUME ${REGISTRY_STORAGE_FILESYSTEM_ROOTDIRECTORY} EXPOSE 5000 WORKDIR C:\registry CMD ["registry", "serve", "config.yml"] COPY --from=builder C:\out\registry.exe . COPY --from=builder C:\gopath\src\github.com\docker\...\config-example.yml .\config.yml
```

这个阶段没有什么复杂的。它从设置图像开始：

1.  `REGISTRY_STORAGE_FILESYSTEM_ROOTDIRECTORY`是注册表使用的环境变量，作为存储数据的基本路径。

1.  通过使用环境变量中捕获的路径创建了一个`VOLUME`，用于注册表数据。

1.  暴露端口`5000`，这是 Docker 注册表的常规端口。

Dockerfile 的其余部分设置了容器的入口点，并从构建阶段复制了编译的二进制文件和默认配置文件。

Windows Server 2016 中的 Docker 容器有一个不同的卷实现——容器内的目标目录实际上是一个符号链接，而不是一个普通目录。这导致了 Go、Java 和其他语言的问题。通过使用映射驱动器，可以实现一种解决方法，但现在不再需要。如果您看到任何使用 G:驱动器的 Dockerfile，它们是基于 Windows Server 2016 的，可以通过使用 C:驱动器简化为 Windows Server 2019。

构建注册表映像与构建任何其他映像相同，但当您使用它来运行自己的注册表时，有一些重要因素需要考虑。

# 运行注册表容器

运行自己的注册表可以让您在团队成员之间共享图像，并使用快速本地网络而不是互联网连接存储所有应用程序构建的输出。您通常会在可以广泛访问的服务器上运行注册表容器，配置如下：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-win/img/7c1703fa-380c-4361-949b-90883f08e110.png)

注册表在服务器上的容器（1）上运行。客户端机器（3）连接到服务器，以便它们可以使用本地网络上的注册表来推送和拉取私有图像。

为了使注册表容器可访问，您需要将容器的端口`5000`发布到主机上的端口`5000`。注册表用户可以使用主机服务器的 IP 地址或主机名访问容器，这将是您在镜像名称中使用的注册表域。您还需要挂载一个卷从主机存储图像数据在一个已知的位置。当您用新版本替换容器时，它仍然可以使用主机的域名，并且仍然具有之前容器存储的所有图像层。

在我的主机服务器上，我配置了一个作为磁盘`E:`的 RAID 阵列，我用它来存储我的注册表数据，以便我可以运行我的注册表容器挂载该卷作为数据路径：

```
mkdir E:\registry-data
docker container run -d -p 5000:5000 -v E:\registry-data:C:\data dockeronwindows/ch04-registry:2e
```

在我的网络中，我将在具有 IP 地址`192.168.2.146`的物理机器上运行容器。我可以使用`192.168.2.146:5000`作为注册表域来标记图像，但这并不是很灵活。最好使用主机的域名，这样我可以在需要时将其指向不同的物理服务器，而无需重新标记所有图像。

对于主机名，您可以使用您网络的**域名系统**（**DNS**）服务，或者如果您运行公共服务器，可以使用**规范名称**（**CNAME**）。或者，您可以在客户机上的 hosts 文件中添加一个条目，并使用自定义域名。这是我用来为`registry.local`添加指向我的 Docker 服务器的主机名条目的 PowerShell 命令：

```
Add-Content -Path 'C:\Windows\System32\drivers\etc\hosts' -Value "`r`n192.168.2.146 registry.local"
```

现在我的服务器正在运行一个具有可靠存储的容器中的注册表服务器，并且我的客户端已设置好以使用友好的域名访问注册表主机。我可以开始从自己的注册表推送和拉取私有镜像，这仅对我的网络上的用户可用。

# 使用本地注册表推送和拉取镜像

只有当镜像标签与注册表域匹配时，才能将镜像推送到注册表。标记和推送的过程与 Docker Hub 相同，但您需要明确包含本地注册表域在新标记中。这些命令从 Docker Hub 拉取我的注册表服务器镜像，并添加一个新标记，使其适合推送到本地注册表：

```
docker image pull dockeronwindows/ch04-registry:2e

docker image tag dockeronwindows/ch04-registry:2e registry.local:5000/infrastructure/registry:v2.6.2
```

`docker image tag`命令首先指定源标记，然后指定目标标记。您可以更改新目标标记的镜像名称的每个部分。我使用了以下内容：

+   `registry.local:5000`是注册表域。原始镜像名称隐含的域为`docker.io`。

+   `infrastructure`是帐户名称。原始帐户名称是`dockeronwindows`。

+   `registry`是存储库名称。原始名称是`ch04-registry`。

+   `v2.6.2`是图像标记。原始标记是`2e`。

如果您想知道为什么本书的所有图像都有`2e`标记，那是因为我用它来标识它们与本书的第二版一起使用。我没有在第一版中为图像使用标记，因此它们都具有隐含的`latest`标记。它们仍然存在于 Docker Hub 上，但通过将新版本标记为`2e`，我可以将图像发布到相同的存储库，而不会破坏第一版读者的代码示例。

我可以尝试将新标记的映像推送到本地注册表，但 Docker 还不允许我使用注册表：

```
> docker image push registry.local:5000/infrastructure/registry:v2.6.2

The push refers to a repository [registry.local:5000/infrastructure/registry]
Get https://registry.local:5000/v2/: http: server gave HTTP response to HTTPS client
```

Docker 平台默认是安全的，相同的原则也适用于映像注册表。Docker 引擎期望使用 HTTPS 与注册表通信，以便流量被加密。我的简单注册表安装使用明文 HTTP，因此我收到了一个错误，说 Docker 尝试使用加密传输进行注册表，但只有未加密传输可用。

设置 Docker 使用本地注册表有两个选项。第一个是扩展注册表服务器以保护通信-如果您提供 SSL 证书，注册表服务器映像可以在 HTTPS 上运行。这是我在生产环境中会做的事情，但是为了开始，我可以使用另一个选项并在 Docker 配置中做一个例外。如果在允许的不安全注册表列表中明确命名，Docker 引擎将允许使用 HTTP 注册表。

您可以使用公司的 SSL 证书或自签名证书在 HTTPS 下运行注册表映像，这意味着您无需配置 Docker 引擎以允许不安全的注册表。GitHub 上的 Docker 实验室存储库`docker/labs`中有一个 Windows 注册表演练，解释了如何做到这一点。

# 配置 Docker 以允许不安全的注册表

Docker 引擎可以使用 JSON 配置文件来更改设置，包括引擎允许的不安全注册表列表。该列表中的任何注册表域都可以使用 HTTP 而不是 HTTPS，因此这不是您应该为托管在公共网络上的注册表执行的操作。

Docker 的配置文件位于`％programdata％\docker\config\daemon.json`（**daemon**是 Linux 术语，表示后台服务，因此这是 Docker 引擎配置文件的名称）。您可以手动编辑它，将本地注册表添加为安全选项，然后重新启动 Docker Windows 服务。此配置允许 Docker 使用 HTTP 访问本地注册表：

```
{  
    "insecure-registries": [    
         "registry.local:5000"  
    ]
}
```

如果您在 Windows 10 上使用 Docker Desktop，则 UI 具有一个很好的配置窗口，可以为您处理这些问题。只需右键单击状态栏中的 Docker 标志，选择“设置”，导航到“守护程序”页面，并将条目添加到不安全的注册表列表中：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-win/img/500523ff-3838-4543-8104-c4342100969a.png)

将本地注册表域添加到我的不安全列表后，我可以使用它来推送和拉取镜像：

```
> docker image push registry.local:5000/infrastructure/registry:v2.6.2

The push refers to repository [registry.2019:5000/infrastructure/registry]
dab5f9f9b952: Pushed
9ab5db0fd189: Pushed
c53fe60c877c: Pushed
ccc905d24a7d: Pushed
470656dd7daa: Pushed
f32c8541ff24: Pushed
3ad7de2744af: Pushed
b9fa4df06e58: Skipped foreign layer
37c182b75172: Skipped foreign layer
v2.6.2: digest: sha256:d7e87b1d094d96569b346199c4d3dd5ec1d5d5f8fb9ea4029e4a4aa9286e7aac size: 2398 
```

任何具有对我的 Docker 服务器的网络访问权限的用户都可以使用存储在本地注册表中的镜像，使用`docker image pull`或`docker container run`命令。您还可以通过在`FROM`指令中指定名称与注册表域、存储库名称和标签，将本地镜像用作其他 Dockerfile 中的基本镜像：

```
FROM registry.local:5000/infrastructure/registry:v2.6.2
CMD ["cmd /s /c", "echo", "Hello from Chapter 4."]
```

没有办法覆盖默认注册表，因此当未指定域时，无法将本地注册表设置为默认值 - 默认值始终为 Docker Hub。如果要为镜像使用不同的注册表，注册表域必须始终在镜像名称中指定。任何不带注册表地址的镜像名称都将被假定为指向`docker.io`的镜像。

# 将 Windows 镜像层存储在本地注册表中

不允许公开重新分发 Microsoft 镜像的基本层，但允许将它们存储在私有注册表中。这对于 Windows Server Core 镜像特别有用。该镜像的压缩大小为 2GB，Microsoft 每个月在 Docker Hub 上发布一个新版本的镜像，带有最新的安全补丁。

更新通常只会向镜像添加一个新层，但该层可能是 300MB 的下载。如果有许多用户使用 Windows 镜像，他们都需要下载这些层，这需要大量的带宽和时间。如果运行本地注册表服务器，可以从 Docker Hub 一次拉取这些层，并将它们推送到本地注册表。然后，其他用户从本地注册表中拉取，从快速本地网络而不是从互联网上下载。

您需要在 Docker 配置文件中为特定注册表启用此功能，使用`allow-nondistributable-artifacts`字段：

```
{
  "insecure-registries": [
    "registry.local:5000"
  ],
 "allow-nondistributable-artifacts": [
    "registry.local:5000"
  ]
}
```

这个设置在 Docker for Windows UI 中没有直接暴露，但你可以在设置屏幕的高级模式中设置它：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-win/img/7fe10262-09e8-4ea1-90b6-01d668a719bf.png)

现在，我可以将 Windows *foreign layers*推送到我的本地注册表。我可以使用自己的注册表域标记最新的 Nano Server 图像，并将图像推送到那里：

```
PS> docker image tag mcr.microsoft.com/windows/nanoserver:1809 `
     registry.local:5000/microsoft/nanoserver:1809

PS> docker image push registry.local:5000/microsoft/nanoserver:1809
The push refers to repository [registry.2019:5000/microsoft/nanoserver]
75ddd2c5f09c: Pushed
37c182b75172: Pushing  104.8MB/243.8MB
```

当您将 Windows 基础镜像层存储在自己的注册表中时，层 ID 将与 MCR 上的原始层 ID 不同。这对 Docker 的图像缓存产生影响。您可以使用完整标签`registry.local:5000/microsoft/nanoserver:1809`在干净的机器上拉取自己的 Nano Server 图像。然后，如果您拉取官方的 Microsoft 图像，层将再次被下载。它们具有相同的内容但不同的 ID，因此 Docker 不会将它们识别为缓存命中。

如果您要存储 Windows 的基础图像的自己的版本，请确保您是一致的，并且只在您的 Dockerfile 中使用这些图像。这也适用于从 Windows 图像构建的图像-因此，如果您想要使用.NET，您需要使用您的 Windows 图像作为基础构建自己的 SDK 图像。这会增加一些额外的开销，但许多大型组织更喜欢这种方法，因为它可以让他们对基础图像有更好的控制。

# 使用商业注册表

运行自己的注册表不是拥有安全的私有图像存储库的唯一方法-您可以使用几种第三方提供的选择。在实践中，它们都以相同的方式工作-您需要使用注册表域标记您的图像，并与注册表服务器进行身份验证。有几种可用的选项，最全面的选项来自 Docker，Inc.，他们为不同的服务级别提供了不同的产品。

# Docker Hub

Docker Hub 是最广泛使用的公共容器注册表，在撰写本文时，平均每月超过 10 亿次图像拉取。您可以在 Hub 上托管无限数量的公共存储库，并支付订阅费以托管多个私有存储库。

Docker Hub 具有自动构建系统，因此您可以将镜像存储库链接到 GitHub 或 Bitbucket 中的源代码存储库，Docker 的服务器将根据存储库中的 Dockerfile 构建镜像，每当您推送更改时 - 这是一个简单而有效的托管**持续集成**（**CI**）解决方案，特别是如果您使用可移植的多阶段 Dockerfile。

Hub 订阅适用于较小的项目或多个用户共同开发同一应用程序的团队。它具有授权框架，用户可以创建一个组织，该组织成为存储库中的帐户名，而不是个人用户的帐户名。可以授予多个用户对组织存储库的访问权限，这允许多个用户推送镜像。

Docker Hub 也是用于商业软件分发的注册表。它就像是面向服务器端应用程序的应用商店。如果您的公司生产商业软件，Docker Hub 可能是分发的一个不错选择。您可以以完全相同的方式构建和推送镜像，但您的源代码可以保持私有 - 只有打包的应用程序是公开可用的。

您可以在 Docker 上注册为已验证的发布者，以确定有一个商业实体在维护这些镜像。Docker Hub 允许您筛选已验证的发布者，因此这是一个让您的应用程序获得可见性的好方法：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-win/img/d6a7c495-7147-4b6d-86cd-3c79835f0983.png)

Docker Hub 还有一个认证流程，适用于托管在 Docker Hub 上的镜像。Docker 认证适用于软件镜像和硬件堆栈。如果您的镜像经过认证，它将保证在任何经过认证的硬件上都可以在 Docker Enterprise 上运行。Docker 在认证过程中测试所有这些组合，这种端到端的保证对大型企业非常有吸引力。

# Docker Trusted Registry

**Docker Trusted Registry**（**DTR**）是 Docker Enterprise 套件的一部分，这是 Docker 公司提供的企业级**容器即服务**（**CaaS**）平台。它旨在为在其自己的数据中心或任何云中运行 Docker 主机集群的企业提供服务。Docker Enterprise 配备了一个名为**Universal Control Plane**（**UCP**）的全面管理套件，该套件提供了一个界面，用于管理 Docker 集群中的所有资源 - 主机服务器、镜像、容器、网络、卷以及其他所有内容。Docker Enterprise 还提供了 DTR，这是一个安全、可扩展的镜像注册表。

DTR 通过 HTTPS 运行，并且是一个集群化服务，因此您可以在集群中部署多个注册表服务器以实现可伸缩性和故障转移。您可以使用本地存储或云存储来存储 DTR，因此如果在 Azure 中运行，则可以将图像持久保存在具有实际无限容量的 Azure 存储中。与 Docker Hub 一样，您可以为共享存储库创建组织，但是使用 DTR，您可以通过创建自己的用户帐户或插入到**轻量级目录访问协议**（**LDAP**）服务（如 Active Directory）来管理身份验证。然后，您可以为细粒度权限配置基于角色的访问控制。

DTR 还提供安全扫描功能，该功能扫描图像内部的二进制文件，以检查已知的漏洞。您可以配置扫描以在推送图像时运行，或构建一个计划。计划扫描可以在发现旧图像的依赖项中发现新漏洞时向您发出警报。DTR UI 允许您深入了解漏洞的详细信息，并查看确切的文件和确切的利用方式。

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-win/img/57b74dfa-9361-4b46-ac45-baa91cefca64.png)

Docker Enterprise 还有一个主要的安全功能，**内容信任**，这仅在 Docker Enterprise 中可用。Docker 内容信任允许用户对图像进行数字签名，以捕获批准工作流程 - 因此 QA 和安全团队可以通过他们的测试套件运行图像版本并对其进行签名，以确认他们批准了用于生产的发布候选版本。这些签名存储在 DTR 中。UCP 可以配置为仅运行由某些团队签名的图像，因此您可以对集群将运行的软件进行严格控制，并提供证明谁构建和批准软件的审计跟踪。

Docker Enterprise 具有丰富的功能套件，可以通过友好的 Web UI 以及通常的 Docker 命令行访问。安全性，可靠性和可扩展性是功能集中的主要因素，这使其成为企业用户寻找管理图像，容器和 Docker 主机的标准方式的不错选择。我将在第八章中介绍 UCP，*管理和监控 Docker 化解决方案*，以及在第九章中介绍 DTR，*了解 Docker 的安全风险和好处*。

如果您想在无需设置要求的沙箱环境中尝试 Docker Enterprise，请浏览[`trial.docker.com`](http://trial.docker.com)以获取一个可用于 12 小时的托管试用版。

# 其他注册表

Docker 现在非常受欢迎，许多第三方服务已经将图像注册表添加到其现有的服务中。在云端，您可以使用来自亚马逊网络服务（AWS）的 EC2 容器注册表（ECR），微软的 Azure 容器注册表，以及谷歌云平台上的容器注册表。所有这些服务都与标准的 Docker 命令行和各自平台的其他产品集成，因此如果您在某个云服务提供商中有大量投资，它们可能是很好的选择。

还有一些独立的注册表服务，包括 JFrog 的 Artifactory 和 Quay.io，这些都是托管服务。使用托管注册表可以减少运行自己的注册表服务器的管理开销，如果您已经在使用来自提供商的服务，并且该提供商还提供注册表，则评估该选项是有意义的。

所有的注册表提供商都有不同的功能集和服务水平 - 您应该比较它们的服务，并且最重要的是，检查 Windows 支持的水平。大多数现有的平台最初是为了支持 Linux 图像和 Linux 客户端而构建的，对于 Windows 可能没有功能平衡。

# 总结

在本章中，您已经了解了图像注册表的功能以及如何使用 Docker 与之配合工作。我介绍了仓库名称和图像标记，以识别应用程序版本或平台变化，以及如何运行和使用本地注册表服务器 - 通过在容器中运行一个。

在 Docker 的旅程中，您很可能会很早就开始使用私有注册表。当您开始将现有应用程序 Docker 化并尝试新的软件堆栈时，通过快速的本地网络推送和拉取图像可能会很有用 - 或者如果本地存储空间有问题，可以使用云服务。随着您对 Docker 的使用越来越多，并逐步实施生产，您可能会计划升级到具有丰富安全功能的受支持的注册表 DTR。

现在您已经很好地了解了如何共享图像并使用其他人共享的图像，您可以考虑使用容器优先的解决方案设计，将经过验证和可信赖的软件组件引入我们自己的应用程序中。
