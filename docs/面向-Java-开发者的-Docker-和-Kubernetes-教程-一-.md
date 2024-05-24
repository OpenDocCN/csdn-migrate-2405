# 面向 Java 开发者的 Docker 和 Kubernetes 教程（一）

> 原文：[`zh.annas-archive.org/md5/232C7A0FCE93C7B650611F281F88F33B`](https://zh.annas-archive.org/md5/232C7A0FCE93C7B650611F281F88F33B)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 前言

想象一下，在几分钟内在 Apache Tomcat 或 Wildfly 上创建和测试 Java EE 应用程序，以及迅速部署和管理 Java 应用程序。听起来太好了吧？您有理由欢呼，因为通过利用 Docker 和 Kubernetes，这样的场景是可能的。

本书将首先介绍 Docker，并深入探讨其网络和持久存储概念。然后，您将了解微服务的概念，以及如何将 Java 微服务部署和运行为 Docker 容器。接下来，本书将专注于 Kubernetes 及其特性。您将首先使用 Minikube 运行本地集群。下一步将是在亚马逊 AWS 上运行的 Kubernetes 上部署您的 Java 服务。在本书的最后，您将亲身体验一些更高级的主题，以进一步扩展您对 Docker 和 Kubernetes 的知识。

# 本书涵盖的内容

第一章，*Docker 简介*，介绍了 Docker 背后的原因，并介绍了 Docker 与传统虚拟化之间的区别。该章还解释了基本的 Docker 概念，如镜像、容器和 Dockerfile。

第二章，*网络和持久存储*，解释了 Docker 容器中网络和持久存储的工作原理。

第三章，*使用微服务*，概述了微服务的概念，并解释了它们与单片架构相比的优势。

第四章，*创建 Java 微服务*，探讨了通过使用 Java EE7 或 Spring Boot 快速构建 Java 微服务的方法。

第五章，*使用 Java 应用程序创建镜像*，教授如何将 Java 微服务打包成 Docker 镜像，无论是手动还是从 Maven 构建文件中。

第六章，*运行带有 Java 应用程序的容器*，展示了如何使用 Docker 运行容器化的 Java 应用程序。

第七章，*Kubernetes 简介*，介绍了 Kubernetes 的核心概念，如 Pod、节点、服务和部署。

第八章，*使用 Java 与 Kubernetes*，展示了如何在本地 Kubernetes 集群上部署打包为 Docker 镜像的 Java 微服务。

第九章，*使用 Kubernetes API*，展示了如何使用 Kubernetes API 来自动创建 Kubernetes 对象，如服务或部署。本章提供了如何使用 API 获取有关集群状态的信息的示例。

第十章，*在云中部署 Java 到 Kubernetes*，向读者展示了如何配置 Amazon AWS EC2 实例，使其适合运行 Kubernetes 集群。本章还详细说明了如何在 Amazon AWS 云上创建 Kubernetes 集群的方法。

第十一章，*更多资源*，探讨了 Java 和 Kubernetes 如何指向互联网上其他高质量的可用资源，以进一步扩展有关 Docker 和 Kubernetes 的知识。

# 本书所需内容

对于本书，您将需要任何一台能够运行现代版本的 Linux、Windows 10 64 位或 macOS 的体面 PC 或 Mac。

# 本书适合对象

本书适用于希望进入容器化世界的 Java 开发人员。读者将学习 Docker 和 Kubernetes 如何帮助在集群上部署和管理 Java 应用程序，无论是在自己的基础设施上还是在云中。

# 约定

在本书中，您将找到许多文本样式，用于区分不同类型的信息。以下是一些这些样式的示例及其含义的解释。文本中的代码单词、数据库表名、文件夹名、文件名、文件扩展名、路径名、虚拟 URL、用户输入和 Twitter 句柄显示如下：“当您运行`docker build`命令时，Dockerfile 用于创建图像。”代码块设置如下：

```
{

"apiVersion": "v1",

"kind": "Pod",

"metadata":{

"name": ”rest_service”,

"labels": {

"name": "rest_service"

}

},

"spec": {

"containers": [{

"name": "rest_service",

"image": "rest_service",

"ports": [{"containerPort": 8080}],

}]

}

}
```

任何命令行输入或输出都以以下方式编写：

```
docker rm $(docker ps -a -q -f status=exited)

```

**新术语**和**重要单词**以粗体显示。屏幕上看到的单词，例如菜单或对话框中的单词，会在文本中出现，如：“点击“暂时跳过”将使您在不登录 Docker Hub 的情况下转到图像列表。”

警告或重要说明会出现在这样的框中。提示和技巧会出现在这样。


# 第一章：Docker 简介

本章我们将首先解释 Docker 及其架构背后的推理。我们将涵盖 Docker 概念，如镜像、层和容器。接下来，我们将安装 Docker，并学习如何从“远程”注册表中拉取一个示例基本的 Java 应用程序镜像，并在本地机器上运行它。

Docker 是作为平台即服务公司 dotCloud 的内部工具创建的。 2013 年 3 月，它作为开源软件向公众发布。 它的源代码可以在 GitHub 上免费获得：[h](https://github.com/docker/docker) [t](https://github.com/docker/docker) [t](https://github.com/docker/docker) [p](https://github.com/docker/docker) [s](https://github.com/docker/docker) [://g](https://github.com/docker/docker) [i](https://github.com/docker/docker) [t](https://github.com/docker/docker) [h](https://github.com/docker/docker) [u](https://github.com/docker/docker) [b](https://github.com/docker/docker) [.](https://github.com/docker/docker) [c](https://github.com/docker/docker) [o](https://github.com/docker/docker) [m](https://github.com/docker/docker) [/d](https://github.com/docker/docker) [o](https://github.com/docker/docker) [c](https://github.com/docker/docker) [k](https://github.com/docker/docker) [e](https://github.com/docker/docker) [r](https://github.com/docker/docker) [/d](https://github.com/docker/docker) [o](https://github.com/docker/docker) [c](https://github.com/docker/docker) [k](https://github.com/docker/docker) [e](https://github.com/docker/docker) [r](https://github.com/docker/docker) 。不仅 Docker Inc.的核心团队致力于 Docker 的开发，还有许多大公司赞助他们的时间和精力来增强和贡献 Docker，如谷歌、微软、IBM、红帽、思科系统等。 Kubernetes 是谷歌开发的一个工具，用于根据他们在 Borg（谷歌自制的容器系统）上学到的最佳实践在计算机集群上部署容器。 在编排、自动化部署、管理和扩展容器方面，它与 Docker 相辅相成；它通过在集群中保持容器部署的平衡来管理 Docker 节点的工作负载。 Kubernetes 还提供了容器之间通信的方式，无需打开网络端口。 Kubernetes 也是一个开源项目，存放在 GitHub 上[h](https://github.com/kubernetes/kubernetes) [t](https://github.com/kubernetes/kubernetes) [t](https://github.com/kubernetes/kubernetes) [p](https://github.com/kubernetes/kubernetes) [s](https://github.com/kubernetes/kubernetes) [://g](https://github.com/kubernetes/kubernetes) [i](https://github.com/kubernetes/kubernetes) [t](https://github.com/kubernetes/kubernetes) [h](https://github.com/kubernetes/kubernetes) [u](https://github.com/kubernetes/kubernetes) [b](https://github.com/kubernetes/kubernetes) [.](https://github.com/kubernetes/kubernetes) [c](https://github.com/kubernetes/kubernetes) [o](https://github.com/kubernetes/kubernetes) [m](https://github.com/kubernetes/kubernetes) [/k](https://github.com/kubernetes/kubernetes) [u](https://github.com/kubernetes/kubernetes) [b](https://github.com/kubernetes/kubernetes) [e](https://github.com/kubernetes/kubernetes) [r](https://github.com/kubernetes/kubernetes) [n](https://github.com/kubernetes/kubernetes) [e](https://github.com/kubernetes/kubernetes) [t](https://github.com/kubernetes/kubernetes) [e](https://github.com/kubernetes/kubernetes) [s](https://github.com/kubernetes/kubernetes) [/k](https://github.com/kubernetes/kubernetes) [u](https://github.com/kubernetes/kubernetes) [b](https://github.com/kubernetes/kubernetes) [e](https://github.com/kubernetes/kubernetes) [r](https://github.com/kubernetes/kubernetes) [n](https://github.com/kubernetes/kubernetes) [e](https://github.com/kubernetes/kubernetes) [t](https://github.com/kubernetes/kubernetes) [e](https://github.com/kubernetes/kubernetes) [s](https://github.com/kubernetes/kubernetes) 。每个人都可以贡献。 让我们首先从 Docker 开始我们的旅程。 以下内容将被覆盖：

+   我们将从这个神奇工具背后的基本理念开始，并展示使用它所获得的好处，与传统虚拟化相比。

+   我们将在三个主要平台上安装 Docker：macOS、Linux 和 Windows

# Docker 的理念

Docker 的理念是将应用程序及其所有依赖项打包成一个单一的标准化部署单元。这些依赖项可以是二进制文件、库文件、JAR 文件、配置文件、脚本等。Docker 将所有这些内容打包成一个完整的文件系统，其中包含了 Java 应用程序运行所需的一切，包括虚拟机本身、诸如 Wildfly 或 Tomcat 之类的应用服务器、应用程序代码和运行时库，以及服务器上安装和部署的一切内容，以使应用程序运行。将所有这些内容打包成一个完整的镜像可以保证其可移植性；无论部署在何种环境中，它都将始终以相同的方式运行。使用 Docker，您可以在主机上运行 Java 应用程序，而无需安装 Java 运行时。与不兼容的 JDK 或 JRE、应用服务器的错误版本等相关的所有问题都将消失。升级也变得简单而轻松；您只需在主机上运行容器的新版本。

如果需要进行一些清理，您只需销毁 Docker 镜像，就好像什么都没有发生过一样。不要将 Docker 视为一种编程语言或框架，而应将其视为一种有助于解决安装、分发和管理软件等常见问题的工具。它允许开发人员和 DevOps 在任何地方构建、发布和运行其代码。任何地方也包括在多台机器上，这就是 Kubernetes 派上用场的地方；我们很快将回到这一点。

将所有应用程序代码和运行时依赖项打包为单个完整的软件单元可能看起来与虚拟化引擎相同，但实际上远非如此，我们将在下面解释。要完全了解 Docker 的真正含义，首先我们需要了解传统虚拟化和容器化之间的区别。现在让我们比较这两种技术。

# 虚拟化和容器化的比较

传统虚拟机代表硬件级虚拟化。实质上，它是一个完整的、虚拟化的物理机器，具有 BIOS 和安装了操作系统。它运行在主机操作系统之上。您的 Java 应用程序在虚拟化环境中运行，就像在您自己的机器上一样。使用虚拟机为您的应用程序带来了许多优势。每个虚拟机可以拥有完全不同的操作系统；例如，这些可以是不同的 Linux 版本、Solaris 或 Windows。虚拟机也是非常安全的；它们是完全隔离的、完整的操作系统。

然而，没有什么是不需要付出代价的。虚拟机包含操作系统运行所需的所有功能：核心系统库、设备驱动程序等。有时它们可能会占用资源并且很重。虚拟机需要完整安装，有时可能会很繁琐，设置起来也不那么容易。最后但并非最不重要的是，您需要更多的计算能力和资源来在虚拟机中执行您的应用程序，虚拟机监视程序需要首先导入虚拟机，然后启动它，这需要时间。然而，我相信，当涉及到运行 Java 应用程序时，拥有完整的虚拟化环境并不是我们经常想要的。Docker 通过容器化的概念来拯救。Java 应用程序（当然，不仅限于 Java）在 Docker 上运行在一个被称为容器的隔离环境中。容器在流行意义上不是虚拟机。它表现为一种操作系统虚拟化，但根本没有仿真。主要区别在于，每个传统虚拟机镜像都在独立的客户操作系统上运行，而 Docker 容器在主机上运行的相同内核内部运行。容器是自给自足的，不仅与底层操作系统隔离，而且与其他容器隔离。它有自己独立的文件系统和环境变量。当然，容器可以相互通信（例如应用程序和数据库容器），也可以共享磁盘上的文件。与传统虚拟化相比的主要区别在于，由于容器在相同的内核内部运行，它们利用更少的系统资源。所有操作系统核心软件都从 Docker 镜像中删除。基础容器通常非常轻量级。与经典虚拟化监视程序和客户操作系统相关的开销都没有了。这样，您可以为 Java 应用程序实现几乎裸金属的核心性能。此外，由于容器的最小开销，容器化 Java 应用程序的启动时间通常非常短。您还可以在几秒钟内部署数百个应用程序容器，以减少软件配置所需的时间。我们将在接下来的章节中使用 Kubernetes 来实现这一点。尽管 Docker 与传统虚拟化引擎有很大不同。请注意，容器不能替代所有用例的虚拟机；仍然需要深思熟虑的评估来确定对您的应用程序最好的是什么。两种解决方案都有其优势。一方面，我们有性能一般的完全隔离安全的虚拟机。另一方面，我们有一些关键功能缺失的容器，但配备了可以非常快速配置的高性能。让我们看看在使用 Docker 容器化时您将获得的其他好处。

# 使用 Docker 的好处

正如我们之前所说，使用 Docker 的主要可见好处将是非常快的性能和短的配置时间。您可以快速轻松地创建或销毁容器。容器与其他 Docker 容器有效地共享操作系统的内核和所需的库等资源。因此，在容器中运行的应用程序的多个版本将非常轻量级。结果是更快的部署、更容易的迁移和启动时间。

在部署 Java 微服务时，Docker 尤其有用。我们将在接下来的章节中详细讨论微服务。微服务应用由一系列离散的服务组成，通过 API 与其他服务通信。微服务将应用程序分解为大量的小进程。它们与单体应用相反，单体应用将所有操作作为单个进程或一组大进程运行。

使用 Docker 容器可以让您部署即插即用的软件，具有可移植性和极易分发的特点。您的容器化应用程序只需在其容器中运行；无需安装。无需安装过程具有巨大的优势；它消除了诸如软件和库冲突甚至驱动兼容性问题等问题。Docker 容器是可移植的；它们可以从任何地方运行：您的本地机器、远程服务器以及私有或公共云。所有主要的云计算提供商，如亚马逊网络服务（AWS）和谷歌的计算平台现在都支持 Docker。在亚马逊 EC2 实例上运行的容器可以轻松转移到其他环境，实现完全相同的一致性和功能。Docker 在基础架构层之上提供的额外抽象层是一个不可或缺的特性。开发人员可以创建软件而不必担心它将在哪个平台上运行。Docker 与 Java 有着相同的承诺；一次编写，到处运行；只是不是代码，而是配置您想要的服务器的方式（选择操作系统，调整配置文件，安装依赖项），您可以确信您的服务器模板将在运行 Docker 的任何主机上完全相同。

由于 Docker 的可重复构建环境，它特别适用于测试，特别是在持续集成或持续交付流程中。您可以快速启动相同的环境来运行测试。而且由于容器镜像每次都是相同的，您可以分发工作负载并并行运行测试而不会出现问题。开发人员可以在他们的机器上运行与后来在生产中运行的相同的镜像，这在测试中又有巨大的优势。

使用 Docker 容器可以加快持续集成的速度。不再有无休止的构建-测试-部署循环；Docker 容器确保应用程序在开发、测试和生产环境中运行完全相同。随着时间的推移，代码变得越来越麻烦。这就是为什么不可变基础设施的概念如今变得越来越受欢迎，容器化的概念也变得如此流行。通过将 Java 应用程序放入容器中，您可以简化部署和扩展的过程。通过拥有一个几乎不需要配置管理的轻量级 Docker 主机，您可以通过部署和重新部署容器来简单地管理应用程序。而且，由于容器非常轻量级，所以只需要几秒钟。

我们一直在谈论镜像和容器，但没有深入了解细节。现在让我们来看看 Docker 镜像和容器是什么。

# Docker 概念-镜像和容器

在处理 Kubernetes 时，我们将使用 Docker 容器；它是一个开源的容器集群管理器。要运行我们自己的 Java 应用程序，我们首先需要创建一个镜像。让我们从 Docker 镜像的概念开始。

# 镜像

将图像视为只读模板，它是创建容器的基础。这就像一个包含应用程序运行所需的所有定义的食谱。它可以是带有应用服务器（例如 Tomcat 或 Wildfly）和 Java 应用程序本身的 Linux。每个图像都是从基本图像开始的；例如 Ubuntu；一个 Linux 图像。虽然您可以从简单的图像开始，并在其上构建应用程序堆栈，但您也可以从互联网上提供的数百个图像中选择一个已经准备好的图像。有许多图像对于 Java 开发人员特别有用：`openjdk`，`tomcat`，`wildfly`等等。我们稍后将使用它们作为我们自己图像的基础。拥有，比如说，已经安装和配置正确的 Wildfly 作为您自己图像的起点要容易得多。然后您只需专注于您的 Java 应用程序。如果您是构建图像的新手，下载一个专门的基础图像是与自己开发相比获得严重速度提升的好方法。

图像是使用一系列命令创建的，称为指令。指令被放置在 Dockerfile 中。Dockerfile 只是一个普通的文本文件，包含一个有序的`root`文件系统更改的集合（与运行启动应用程序服务器的命令相同，添加文件或目录，创建环境变量等），以及稍后在容器运行时使用的相应执行参数。当您开始构建图像的过程时，Docker 将读取 Dockerfile 并逐个执行指令。结果将是最终图像。每个指令在图像中创建一个新的层。然后该图像层成为下一个指令创建的层的父层。Docker 图像在主机和操作系统之间具有高度的可移植性；可以在运行 Docker 的任何主机上的 Docker 容器中运行图像。Docker 在 Linux 中具有本地支持，但在 Windows 和 macOS 上必须在虚拟机中运行。重要的是要知道，Docker 使用图像来运行您的代码，而不是 Dockerfile。Dockerfile 用于在运行`docker build`命令时创建图像。此外，如果您将图像发布到 Docker Hub，您将发布一个带有其层的结果图像，而不是源 Dockerfile 本身。

我们之前说过，Dockerfile 中的每个指令都会创建一个新的层。层是图像的内在特性；Docker 图像是由它们组成的。现在让我们解释一下它们是什么，以及它们的特点是什么。

# 层

每个图像由一系列堆叠在一起的层组成。实际上，每一层都是一个中间图像。通过使用**联合文件系统**，Docker 将所有这些层组合成单个图像实体。联合文件系统允许透明地覆盖单独文件系统的文件和目录，从而产生一个统一的文件系统，如下图所示：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-k8s-java-dev/img/Image00004.jpg)

具有相同路径的目录的内容和结构在这些单独的文件系统中将在一个合并的目录中一起显示，在新的虚拟文件系统中。换句话说，顶层的文件系统结构将与下面的层的结构合并。具有与上一层相同路径的文件和目录将覆盖下面的文件和目录。删除上层将再次显示和暴露出先前的目录内容。正如我们之前提到的，层被堆叠放置，一层叠在另一层之上。为了保持层的顺序，Docker 利用了层 ID 和指针的概念。每个层包含 ID 和指向其父层的指针。没有指向父层的指针的层是堆栈中的第一层，即基础层。您可以在下图中看到这种关系：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-k8s-java-dev/img/Image00005.jpg)

图层具有一些有趣的特性。首先，它们是可重用和可缓存的。你可以在前面的图表中看到指向父图层的指针是很重要的。当 Docker 处理 Dockerfile 时，它会查看两件事：正在执行的 Dockerfile 指令和父映像。Docker 将扫描父图层的所有子图层，并寻找其命令与当前指令匹配的图层。如果找到匹配的图层，Docker 将跳过下一个 Dockerfile 指令并重复该过程。如果在缓存中找不到匹配的图层，则会创建一个新的图层。对于向图像添加文件的指令（我们稍后将详细了解它们），Docker 为每个文件内容创建一个校验和。在构建过程中，将此校验和与现有图像的校验和进行比较，以检查是否可以从缓存中重用该图层。如果两个不同的图像有一个共同的部分，比如 Linux shell 或 Java 运行时，Docker 将在这两个图像中重用 shell 图层，Docker 跟踪所有已拉取的图层，这是一个安全的操作；正如你已经知道的，图层是只读的。当下载另一个图像时，将重用该图层，只有差异将从 Docker Hub 中拉取。这当然节省了时间、带宽和磁盘空间，但它还有另一个巨大的优势。如果修改了 Docker 图像，例如通过修改容器化的 Java 应用程序，只有应用程序图层会被修改。当你成功从 Dockerfile 构建了一个图像后，你会注意到同一 Dockerfile 的后续构建会快得多。一旦 Docker 为一条指令缓存了一个图像图层，它就不需要重新构建。后来，你只需推送更新的部分，而不是整个图像。这使得流程更简单、更快速。如果你在持续部署流程中使用 Docker，这将特别有用：推送一个 Git 分支将触发构建一个图像，然后发布应用程序给用户。由于图层重用的特性，整个流程会快得多。

可重用层的概念也是 Docker 比完整虚拟机轻量的原因之一，虚拟机不共享任何内容。多亏了层，当你拉取一个图像时，最终你不必下载其整个文件系统。如果你已经有另一个图像包含了你拉取的图像的一些层，那么只有缺失的层会被实际下载。不过，需要注意的是，层的另一个特性：除了可重用，层也是可加的。如果在容器中创建了一个大文件，然后进行提交（我们稍后会讲到），然后删除该文件，再进行另一个提交；这个文件仍然会存在于层历史中。想象一下这种情况：你拉取了基础的 Ubuntu 图像，并安装了 Wildfly 应用服务器。然后你改变主意，卸载了 Wildfly 并安装了 Tomcat。所有从 Wildfly 安装中删除的文件仍然会存在于图像中，尽管它们已经被删除。图像大小会迅速增长。理解 Docker 的分层文件系统可以在图像大小上产生很大的差异。当你将图像发布到注册表时，大小可能会成为一个问题；它需要更多的请求和更长的传输时间。

当需要在集群中部署数千个容器时，大型图像就会成为一个问题。例如，你应该始终意识到层的可加性，并尝试在 Dockerfile 的每一步优化图像，就像使用命令链接一样。在创建 Java 应用程序图像时，我们将使用命令链接技术。

因为层是可加的，它们提供了特定图像是如何构建的完整历史记录。这给了你另一个很棒的功能：可以回滚到图像历史中的某个特定点。由于每个图像包含了所有构建步骤，我们可以很容易地回到以前的步骤。这可以通过给某个层打标签来实现。我们将在本书的后面介绍图像标记。

层和镜像是密切相关的。正如我们之前所说，Docker 镜像被存储为一系列只读层。这意味着一旦容器镜像被创建，它就不会改变。但是，如果整个文件系统都是只读的，这就没有太多意义了。那么如何修改一个镜像？或者将您的软件添加到基本 Web 服务器镜像中？嗯，当我们启动一个容器时，Docker 实际上会取出只读镜像（以及所有只读层），并在层堆栈顶部添加一个可写层。现在让我们专注于容器。

# 容器

镜像的运行实例称为容器。Docker 使用 Docker 镜像作为只读模板来启动它们。如果您启动一个镜像，您将得到这个镜像的一个运行中的容器。当然，您可以有许多相同镜像的运行容器。实际上，我们将经常使用 Kubernetes 稍后做这件事。

要运行一个容器，我们使用`docker run`命令：

```
docker run [OPTIONS] IMAGE [COMMAND] [ARG...]

```

有很多可以使用的`run`命令选项和开关；我们稍后会了解它们。一些选项包括网络配置，例如（我们将在第二章 *Networking and Persistent Storage*中解释 Docker 的网络概念）。其他选项，比如`-it`（来自交互式），告诉 Docker 引擎以不同的方式运行；在这种情况下，使容器变得交互，并附加一个终端到其输出和输入。让我们专注于容器的概念，以更好地理解整个情况。我们将很快使用`docker run`命令来测试我们的设置。

那么，当我们运行`docker run`命令时，在幕后会发生什么呢？Docker 将检查您想要运行的镜像是否在本地计算机上可用。如果没有，它将从“远程”存储库中拉取下来。Docker 引擎会获取镜像并在镜像的层堆栈顶部添加一个可写层。接下来，它会初始化镜像的名称、ID 和资源限制，如 CPU 和内存。在这个阶段，Docker 还将通过从池中找到并附加一个可用的 IP 地址来设置容器的 IP 地址。执行的最后一步将是实际的命令，作为`docker run`命令的最后一个参数传递。如果使用了`it`选项，Docker 将捕获并提供容器输出，它将显示在控制台上。现在，您可以做一些通常在准备操作系统运行应用程序时会做的事情。这可以是安装软件包（例如通过`apt-get`），使用 Git 拉取源代码，使用 Maven 构建您的 Java 应用程序等。所有这些操作都将修改顶部可写层中的文件系统。然后，如果执行`commit`命令，将创建一个包含所有更改的新镜像，类似于冻结，并准备随后运行。要停止容器，请使用`docker stop`命令：

```
docker stop

```

停止容器时，将保留所有设置和文件系统更改（在可写的顶层）。在容器中运行的所有进程都将停止，并且内存中的所有内容都将丢失。这就是停止容器与 Docker 镜像的区别。

要列出系统上所有容器，无论是运行还是停止的，执行`docker ps`命令：

```
docker ps -a

```

结果，Docker 客户端将列出一个包含容器 ID（您可以用来在其他命令中引用容器的唯一标识符）、创建日期、用于启动容器的命令、状态、暴露端口和名称的表格，可以是您分配的名称，也可以是 Docker 为您选择的有趣的名称。要删除容器，只需使用`docker rm`命令。如果要一次删除多个容器，可以使用容器列表（由`docker ps`命令给出）和一个过滤器：

```
docker rm $(docker ps -a -q -f status=exited)

```

我们已经说过，Docker 图像始终是只读且不可变的。如果它没有改变图像的可能性，那么它就不会很有用。那么除了通过修改 Dockerfile 并进行重建之外，图像修改如何可能呢？当容器启动时，层堆栈顶部的可写层就可以使用了。我们实际上可以对运行中的容器进行更改；这可以是添加或修改文件，就像安装软件包、配置操作系统等一样。如果在运行的容器中修改文件，则该文件将从底层（父级）只读层中取出，并放置在顶部的可写层中。我们的更改只可能存在于顶层。联合文件系统将覆盖底层文件。原始的底层文件不会被修改；它仍然安全地存在于底层的只读层中。通过发出`docker commit`命令，您可以从运行中的容器（以及可写层中的所有更改）创建一个新的只读图像。

```
docker commit <container-id> <image-name>

```

`docker commit`命令会将您对容器所做的更改保存在可写层中。为了避免数据损坏或不一致，Docker 将暂停您要提交更改的容器。`docker commit`命令的结果是一个全新的只读图像，您可以从中创建新的容器：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-k8s-java-dev/img/Image00006.jpg)

作为对成功提交的回应，Docker 将输出新生成图像的完整 ID。如果您在没有首先发出`commit`的情况下删除容器，然后再次启动相同的图像，Docker 将启动一个全新的容器，而不会保留先前运行容器中所做的任何更改。无论哪种情况，无论是否有`commit`，对文件系统的更改都不会影响基本图像。通过更改容器中的顶部可写层来创建图像在调试和实验时很有用，但通常最好使用 Dockerfile 以文档化和可维护的方式管理图像。

我们现在已经了解了容器化世界中构建（Dockerfile 和图像）和运行时（容器）部分。我们还缺少最后一个元素，即分发组件。Docker 的分发组件包括 Docker 注册表、索引和存储库。现在让我们专注于它们，以便有一个完整的图片。

# Docker 注册表、存储库和索引

Docker 分发系统中的第一个组件是注册表。Docker 利用分层系统存储图像，如下面的屏幕截图所示：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-k8s-java-dev/img/Image00007.jpg)

您构建的图像可以存储在`远程`注册表中供他人使用。`Docker`注册表是一个存储 Docker 图像的服务（实际上是一个应用程序）。Docker Hub 是公开可用注册表的一个例子；它是免费的，并提供不断增长的现有图像的庞大集合。而存储库则是相关图像的集合（命名空间），通常提供相同应用程序或服务的不同版本。它是具有相同名称和不同标记的不同 Docker 图像的集合。

如果您的应用程序命名为`hello-world-java`，并且您的注册表的用户名（或命名空间）为`dockerJavaDeveloper`，那么您的图像将放在`dockerJavaDeveloper/hello-world-java`存储库中。您可以给图像打标签，并在单个命名存储库中存储具有不同 ID 的多个版本的图像，并使用特殊语法访问图像的不同标记版本，例如`username/image_name:tag`。`Docker`存储库与 Git 存储库非常相似。例如，`Git`，`Docker`存储库由 URI 标识，并且可以是公共的或私有的。URI 看起来与以下内容相同：

```
{registryAddress}/{namespace}/{repositoryName}:{tag}

```

Docker Hub 是默认注册表，如果不指定注册表地址，Docker 将从 Docker Hub 拉取图像。要在注册表中搜索图像，请执行`docker search`命令；例如：

```
$ docker search hello-java-world

```

如果不指定`远程`注册表，Docker 将在 Docker Hub 上进行搜索，并输出与您的搜索条件匹配的图像列表：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-k8s-java-dev/img/Image00008.jpg)

注册表和存储库之间的区别可能在开始时令人困惑，因此让我们描述一下如果执行以下命令会发生什么：

```
$ docker pull ubuntu:16.04

```

该命令从 Docker Hub 注册表中的`ubuntu`存储库中下载标记为`16.04`的镜像。官方的`ubuntu`存储库不使用用户名，因此在这个例子中省略了命名空间部分。

尽管 Docker Hub 是公开的，但您可以通过 Docker Hub 用户帐户免费获得一个私有仓库。最后，但并非最不重要的是，您应该了解的组件是索引。索引管理搜索和标记，还管理用户帐户和权限。实际上，注册表将身份验证委托给索引。在执行远程命令，如“推送”或“拉取”时，索引首先会查看图像的名称，然后检查是否有相应的仓库。如果有，索引会验证您是否被允许访问或修改图像。如果允许，操作将获得批准，注册表将获取或发送图像。

让我们总结一下我们到目前为止学到的东西：

+   Dockerfile 是构建图像的配方。它是一个包含有序指令的文本文件。每个 Dockerfile 都有一个基本图像，您可以在其上构建

+   图像是文件系统的特定状态：一个只读的、冻结的不可变的快照

+   图像由代表文件系统在不同时间点的更改的层组成；层与 Git 仓库的提交历史有些相似。Docker 使用层缓存

+   容器是图像的运行时实例。它们可以运行或停止。您可以运行多个相同图像的容器

+   您可以对容器上的文件系统进行更改并提交以使其持久化。提交总是会创建一个新的图像

+   只有文件系统更改可以提交，内存更改将丢失

+   注册表保存了一系列命名的仓库，这些仓库本身是由它们的 ID 跟踪的图像的集合。注册表与 Git 仓库相同：您可以“推送”和“拉取”图像

现在您应该对具有层和容器的图像的性质有所了解。但 Docker 不仅仅是一个 Dockerfile 处理器和运行时引擎。让我们看看还有什么其他可用的东西。

# 附加工具

这是一个完整的软件包，其中包含了许多有用的工具和 API，可以帮助开发人员和 DevOp 在日常工作中使用。例如，有一个 Kinematic，它是一个用于在 Windows 和 macOS X 上使用 Docker 的桌面开发环境。

从 Java 开发者的角度来看，有一些工具特别适用于程序员日常工作，比如 IntelliJ IDEA 的 Docker 集成插件（我们将在接下来的章节中大量使用这个插件）。Eclipse 的粉丝可以使用 Eclipse 的 Docker 工具，该工具从 Eclipse Mars 版本开始可用。NetBeans 也支持 Docker 命令。无论您选择哪种开发环境，这些插件都可以让您从您喜爱的 IDE 直接下载和构建 Docker 镜像，创建和启动容器，以及执行其他相关任务。

Docker 如今非常流行，难怪会有数百种第三方工具被开发出来，以使 Docker 变得更加有用。其中最突出的是 Kubernetes，这是我们在本书中将要重点关注的。但除了 Kubernetes，还有许多其他工具。它们将支持您进行与 Docker 相关的操作，如持续集成/持续交付、部署和基础设施，或者优化镜像。数十个托管服务现在支持运行和管理 Docker 容器。

随着 Docker 越来越受到关注，几乎每个月都会涌现出更多与 Docker 相关的工具。您可以在 GitHub 的 awesome Docker 列表上找到一个非常精心制作的 Docker 相关工具和服务列表，网址为 https://github.com/veggiemonk/awesome-docker。

但不仅有可用的工具。此外，Docker 提供了一组非常方便的 API。其中之一是用于管理图像和容器的远程 API。使用此 API，您将能够将图像分发到运行时 Docker 引擎。还有统计 API，它将公开容器的实时资源使用信息（如 CPU、内存、网络 I/O 和块 I/O）。此 API 端点可用于创建显示容器行为的工具；例如，在生产系统上。

现在我们知道了 Docker 背后的理念，虚拟化和容器化之间的区别，以及使用 Docker 的好处，让我们开始行动吧。我们将首先安装 Docker。

# 安装 Docker

在本节中，我们将了解如何在 Windows、macOS 和 Linux 操作系统上安装 Docker。接下来，我们将运行一个示例`hello-world`图像来验证设置，并在安装过程后检查一切是否正常运行。

Docker 的安装非常简单，但有一些事情需要注意，以使其顺利运行。我们将指出这些问题，以使安装过程变得轻松。您应该知道，Linux 是 Docker 的自然环境。如果您运行容器，它将在 Linux 内核上运行。如果您在运行 Linux 上的 Docker 上运行容器，它将使用您自己机器的内核。这在 macOS 和 Windows 上并非如此；这就是为什么如果您想在这些操作系统上运行 Docker 容器，就需要虚拟化 Linux 内核的原因。当 Docker 引擎在 macOS 或 MS Windows 上运行时，它将使用轻量级的 Linux 发行版，专门用于运行 Docker 容器。它完全运行于 RAM 中，仅使用几兆字节，并在几秒钟内启动。在 macOS 和 Windows 上安装了主要的 Docker 软件包后，默认情况下将使用操作系统内置的虚拟化引擎。因此，您的机器有一些特殊要求。对于最新的本地 Docker 设置，它深度集成到操作系统中的本地虚拟化引擎中，您需要拥有 64 位的 Windows 10 专业版或企业版。对于 macOS，最新的 Docker for Mac 是一个全新开发的本地 Mac 应用程序，具有本地用户界面，集成了 OS X 本地虚拟化、hypervisor 框架、网络和文件系统。强制要求是 Yosemite 10.10.3 或更新版本。让我们从在 macOS 上安装开始。

# 在 macOS 上安装

要获取 Mac 的本地 Docker 版本，请转到[h](http://www.docker.com) [t](http://www.docker.com) [t](http://www.docker.com) [p](http://www.docker.com) [://w](http://www.docker.com) [w](http://www.docker.com) [w](http://www.docker.com) [.](http://www.docker.com) [d](http://www.docker.com) [o](http://www.docker.com) [c](http://www.docker.com) [k](http://www.docker.com) [e](http://www.docker.com) [r](http://www.docker.com) [.](http://www.docker.com) [c](http://www.docker.com) [o](http://www.docker.com) [m](http://www.docker.com)，然后转到获取 Docker macOS 部分。Docker for Mac 是一个标准的本地`dmg`软件包，您可以挂载。您将在软件包中找到一个单一的应用程序：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-k8s-java-dev/img/Image00009.jpg)

现在只需将`Docker.app`移动到您的`Applications`文件夹中，就可以了。再也没有更简单的了。如果您运行 Docker，它将作为 macOS 菜单中的一个小鲸鱼图标。该图标将在 Docker 启动过程中进行动画显示，并在完成后稳定下来：

+   如果您现在点击图标，它将为您提供一个方便的菜单，其中包含 Docker 状态和一些附加选项：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-k8s-java-dev/img/Image00010.jpg)

+   Docker for Mac 具有自动更新功能，这对于保持安装程序最新非常有用。首选项...窗格为您提供了自动检查更新的可能性；它默认标记为：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-k8s-java-dev/img/Image00011.jpg)

+   如果您是一个勇敢的人，您还可以切换到 beta 频道以获取更新。这样，您就可以始终拥有最新和最棒的 Docker 功能，但也会面临稳定性降低的风险，就像使用 beta 软件一样。还要注意，切换到 beta 频道将卸载当前稳定版本的 Docker 并销毁所有设置和容器。Docker 会警告您，以确保您真的想这样做：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-k8s-java-dev/img/Image00012.jpg)

+   首选项...的文件共享窗格将为您提供一个选项，可以将您的 macOS 目录标记为将来要运行的 Docker 容器中的绑定挂载。我们将在本书的后面详细解释挂载目录。目前，让我们只使用默认的一组选定目录：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-k8s-java-dev/img/Image00013.jpg)

+   高级窗格有一些选项，可以调整您的计算机为 Docker 提供的资源，包括处理器数量和内存量。如果您在 macOS 上开始使用 Docker，通常默认设置是一个很好的开始：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-k8s-java-dev/img/Image00014.jpg)

+   代理窗格为您提供了在您的计算机上设置代理的可能性。您可以选择使用系统或手动设置，如下面的屏幕截图所示：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-k8s-java-dev/img/Image00015.jpg)

+   在下一页，您可以编辑一些 Docker 守护程序设置。这将包括添加注册表和注册表镜像。Docker 在拉取镜像时将使用它们。高级选项卡包含一个文本字段，您可以在其中输入包含守护程序配置的 JSON 文本：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-k8s-java-dev/img/Image00016.jpg)

+   在守护程序窗格中，您还可以关闭 Docker 实验功能。有段时间以来，默认情况下已启用实验功能。不时，新版本的 Docker 会带来新的实验功能。在撰写本书时，它们将包括例如 Checkpoint & Restore（允许您通过对其进行检查点来冻结运行中的容器的功能），Docker 图形驱动程序插件（用于使用外部/独立进程图形驱动程序与 Docker 引擎一起使用的功能，作为使用内置存储驱动程序的替代方案），以及其他一些功能。了解新版本 Docker 中包含了哪些新功能总是很有趣。单击守护程序页面中的链接将带您转到 GitHub 页面，该页面列出并解释了所有新的实验功能。

+   最后一个“首选项...”窗格是“重置”。如果您发现您的 Docker 无法启动或表现不佳，您可以尝试将 Docker 安装重置为出厂默认设置：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-k8s-java-dev/img/Image00017.jpg)

但是，您应该注意，将 Docker 重置为出厂状态也将删除您可能在计算机上拥有的所有已下载的镜像和容器。如果您有尚未推送到任何地方的镜像，首先备份总是一个好主意。

在 Docker 菜单中打开 Kitematic 是打开我们之前提到的 Kitematic 应用程序的便捷快捷方式。这是一个用于在 Windows 和 Mac OS X 上使用 Docker 的桌面实用程序。如果您尚未安装 Kitematic，Docker 将为您提供安装包的链接：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-k8s-java-dev/img/Image00018.jpg)

+   如果您运行 Kitematic，它将首先呈现 Docker Hub 登录屏幕。您现在可以注册 Docker Hub，然后提供用户名和密码登录：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-k8s-java-dev/img/Image00019.jpg)

单击“暂时跳过”将带您到图像列表，而无需登录到 Docker Hub。让我们通过拉取和运行图像来测试我们的安装。让我们搜索`hello-java-world`，如下面的屏幕截图所示：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-k8s-java-dev/img/Image00020.jpg)

从注册表中拉取图像后，启动它。Kitematic 将呈现正在运行的容器日志，其中将是来自容器化的 Java 应用程序的著名`hello world`消息：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-k8s-java-dev/img/Image00021.jpg)

这就是在 Kitematic 中运行容器的全部内容。让我们尝试从 shell 中执行相同的操作。在终端中执行以下操作：

```
$ docker run milkyway/java-hello-world

```

因此，您将看到来自容器化的 Java 应用程序的相同问候，这次是在 macOS 终端中：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-k8s-java-dev/img/Image00022.jpg)

就是这样，我们在 macOS 上有一个本地的 Docker 正在运行。让我们在 Linux 上安装它。

# 在 Linux 上安装

有很多不同的 Linux 发行版，每个 Linux 发行版的安装过程可能会有所不同。我将在最新的 16.04 Ubuntu 桌面上安装 Docker：

1.  首先，我们需要允许`apt`软件包管理器使用 HTTPS 协议的存储库。从 shell 中执行：

```
$ sudo apt-get install -y --no-install-recommends apt-transport-https ca-certificates curl software-properties-common

```

1.  接下来要做的事情是将 Docker 的`apt`存储库`gpg`密钥添加到我们的`apt`源列表中：

```
$ curl -fsSL https://download.docker.com/linux/ubuntu/gpg | sudo apt-key add –

```

1.  成功后，简单的`OK`将是响应。使用以下命令设置稳定的存储库：

```
$ sudo add-apt-repository "deb [arch=amd64] https://download.docker.com/linux/ubuntu $(lsb_release -cs) stable"

```

1.  接下来，我们需要更新`apt`软件包索引：

```
$ sudo apt-get update

```

1.  现在我们需要确保`apt`安装程序将使用官方的 Docker 存储库，而不是默认的 Ubuntu 存储库（其中可能包含较旧版本的 Docker）：

```
$ apt-cache policy docker-ce

```

1.  使用此命令安装最新版本的 Docker：

```
$ sudo apt-get install -y docker-ce

```

1.  `apt`软件包管理器将下载许多软件包；这些将是所需的依赖项和`docker-engine`本身：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-k8s-java-dev/img/Image00023.jpg)

1.  就是这样，您应该已经准备好了。让我们验证一下 Docker 是否在我们的 Linux 系统上运行：

```
$sudo docker run milkyway/java-hello-world

```

1.  正如您所看到的，Docker 引擎将从 Docker Hub 拉取`milkyway/java-hello-world`镜像及其所有层，并以问候语作出响应：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-k8s-java-dev/img/Image00024.jpg)

但是我们需要用`sudo`运行 Docker 命令吗？原因是 Docker 守护程序始终以`root`用户身份运行，自 Docker 版本 0.5.2 以来，Docker 守护程序绑定到 Unix 套接字而不是 TCP 端口。默认情况下，该 Unix 套接字由用户`root`拥有，因此，默认情况下，您可以使用 sudo 访问它。让我们修复它，以便能够以普通用户身份运行`Docker`命令：

1.  首先，如果还不存在`Docker`组，请添加它：

```
$ sudo groupadd docker

```

1.  然后，将您自己的用户添加到 Docker 组。将用户名更改为与您首选的用户匹配：

```
$ sudo gpasswd -a jarek docker

```

1.  重新启动 Docker 守护程序：

```
$ sudo service docker restart

```

1.  现在让我们注销并再次登录，并且再次执行`docker run`命令，这次不需要`sudo`。正如您所看到的，您现在可以像普通的非`root`用户一样使用 Docker 了：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-k8s-java-dev/img/Image00025.jpg)

1.  就是这样。我们的 Linux Docker 安装已准备就绪。现在让我们在 Windows 上进行安装。

# 在 Windows 上安装

本机 Docker 软件包可在 64 位 Windows 10 专业版或企业版上运行。它使用 Windows 10 虚拟化引擎来虚拟化 Linux 内核。这就是安装包不再包含 VirtualBox 设置的原因，就像以前的 Docker for Windows 版本一样。本机应用程序以典型的`.msi`安装包提供。如果你运行它，它会向你打招呼，并说它将从现在开始生活在你的任务栏托盘下，小鲸鱼图标下：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-k8s-java-dev/img/Image00026.jpg)

托盘中的 Docker 图标会告诉你 Docker 引擎的状态。它还包含一个小但有用的上下文菜单：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-k8s-java-dev/img/Image00027.jpg)

让我们探索偏好设置，看看有什么可用的。第一个选项卡，常规，允许你设置 Docker 在你登录时自动运行。如果你每天使用 Docker，这可能是推荐的设置。你也可以标记自动检查更新并发送使用统计信息。发送使用统计信息将帮助 Docker 团队改进未来版本的工具；除非你有一些关键任务、安全工作要完成，我建议打开这个选项。这是为未来版本贡献的好方法：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-k8s-java-dev/img/Image00028.jpg)

第二个选项卡，共享驱动器，允许你选择本地 Windows 驱动器，这些驱动器将可用于你将要运行的 Docker 容器：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-k8s-java-dev/img/Image00029.jpg)

我们将在第二章中介绍 Docker 卷，*网络和持久存储*。在这里选择一个驱动器意味着你可以映射本地系统的一个目录，并将其作为 Windows 主机机器读取到你的 Docker 容器中。下一个偏好设置页面，高级，允许我们对在我们的 Windows PC 上运行的 Docker 引擎进行一些限制，并选择 Linux 内核的虚拟机镜像的位置：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-k8s-java-dev/img/Image00030.jpg)

默认值通常是开箱即用的，除非在开发过程中遇到问题，我建议保持它们不变。网络让你配置 Docker 与网络的工作方式，与子网地址和掩码或 DNS 服务器一样。我们将在第二章中介绍 Docker 网络，*网络和持久存储*：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-k8s-java-dev/img/Image00031.jpg)

如果你在网络中使用代理，并希望 Docker 访问互联网，你可以在代理选项卡中设置代理设置：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-k8s-java-dev/img/Image00032.jpg)

对话框类似于您在其他应用程序中找到的，您可以在其中定义代理设置。它可以接受无代理、系统代理设置或手动设置（使用不同的代理进行 HTPP 和 HTTPS 通信）。下一个窗格可以用来配置 Docker 守护程序：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-k8s-java-dev/img/Image00033.jpg)

基本开关意味着 Docker 使用基本配置。您可以将其切换到高级，并以 JSON 结构的形式提供自定义设置。实验性功能与我们在 macOS 上进行 Docker 设置时已经提到的相同，这将是 Checkpoint & Restore 或启用 Docker 图形驱动程序插件，例如。您还可以指定远程注册表的列表。Docker 将从不安全的注册表中拉取图像，而不是使用纯粹的 HTTP 而不是 HTTPS。

在最后一个窗格上使用重置选项可以让您重新启动或将 Docker 重置为出厂设置：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-k8s-java-dev/img/Image00034.jpg)

请注意，将 Docker 重置为其初始设置也将删除当前在您的计算机上存在的所有镜像和容器。

“打开 Kitematic...”选项也出现在 Docker 托盘图标上下文菜单中，这是启动 Kitematic 的快捷方式。如果您是第一次这样做，并且没有安装 Kitematic，Docker 会询问您是否想要先下载它：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-k8s-java-dev/img/Image00035.jpg)

安装 Docker for Windows 就是这样。这是一个相当轻松的过程。在安装过程的最后一步，让我们检查一下 Docker 是否可以从命令提示符中运行，因为这可能是您将来启动它的方式。在命令提示符或 PowerShell 中执行以下命令：

```
docker run milkyway/java-hello-world

```

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-k8s-java-dev/img/Image00036.jpg)

正如您在上一个屏幕截图中所看到的，我们有一个来自作为 Docker 容器启动的 Java 应用程序的 Hello World 消息。

# 摘要

就是这样。我们的 Docker for Windows 安装已经完全可用。在本章中，我们已经了解了 Docker 背后的理念以及传统虚拟化和容器化之间的主要区别。我们对 Docker 的核心概念，如镜像、层、容器和注册表，了解很多。我们应该已经在本地计算机上安装了 Docker；现在是时候继续学习更高级的 Docker 功能，比如网络和持久存储了。


# 第二章：网络和持久存储

在上一章中，我们学到了很多关于 Docker 概念的知识。我们知道容器是镜像的运行时。它将包含您的 Java 应用程序以及所有所需的依赖项，如 JRE 或应用程序服务器。但是，很少有情况下 Java 应用程序是自给自足的。它总是需要与其他服务器通信（如数据库），或者向其他人公开自己（如在应用程序服务器上运行的 Web 应用程序，需要接受来自用户或其他应用程序的请求）。现在是描述如何将 Docker 容器开放给外部世界、网络和持久存储的时候了。在本章中，您将学习如何配置网络，并公开和映射网络端口。通过这样做，您将使您的 Java 应用程序能够与其他容器通信。想象一下以下情景：您可以有一个容器运行 Tomcat 应用程序服务器与您的 Java 应用程序通信，与另一个运行数据库的容器通信，例如`PostgreSQL`。虽然 Kubernetes 对网络的处理方式与 Docker 默认提供的有些不同，但让我们先简要地关注 Docker 本身。稍后我们将介绍 Kubernetes 的特定网络。容器与外部世界的通信不仅仅是关于网络；在本章中，我们还将关注数据卷作为在容器运行和停止周期之间持久保存数据的一种方式。

本章涵盖以下主题：

+   Docker 网络类型

+   网络命令

+   创建网络

+   映射和暴露端口

+   与卷相关的命令

+   创建和删除卷

让我们从 Docker 网络开始。

# 网络

为了使您的容器能够与外部世界通信，无论是另一个服务器还是另一个 Docker 容器，Docker 提供了不同的配置网络的方式。让我们从可用于我们的容器的网络类型开始。

# Docker 网络类型

Docker 提供了三种不同的网络类型。要列出它们，请执行`docker network ls`命令：

```
$ docker network ls

```

Docker 将输出包含唯一网络标识符、名称和在幕后支持它的驱动程序的可用网络列表：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-k8s-java-dev/img/Image00037.jpg)

为了了解各种网络类型之间的区别，让我们现在逐一描述它们。

# 桥接

这是 Docker 中的默认网络类型。当 Docker 服务守护程序启动时，它会配置一个名为`docker0`的虚拟桥。如果您没有使用`docker run -net=<NETWORK>`选项指定网络，Docker 守护程序将默认将容器连接到桥接网络。此外，如果您创建一个新的容器，它将连接到桥接网络。对于 Docker 创建的每个容器，它都会分配一个虚拟以太网设备，该设备将连接到桥上。虚拟以太网设备被映射为在容器中显示为`eth0`，使用 Linux 命名空间，如您可以在以下图表中看到的那样：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-k8s-java-dev/img/Image00038.jpg)

`in-container eth0`接口从桥的地址范围中获得一个 IP 地址。换句话说，Docker 将从桥可用的范围中找到一个空闲的 IP 地址，并配置容器的`eth0`接口为该 IP 地址。从现在开始，如果新容器想要连接到互联网，它将使用桥；主机自己的 IP 地址。桥将自动转发连接到它的任何其他网络接口之间的数据包，并允许容器与主机机器以及同一主机上的容器进行通信。桥接网络可能是最常用的网络类型。

# 主机

这种类型的网络只是将容器放在主机的网络堆栈中。也就是说，主机上定义的所有网络接口都可以被容器访问，如您可以在以下图表中看到的那样：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-k8s-java-dev/img/Image00039.jpg)

如果您使用`-net=host`选项启动容器，那么容器将使用主机网络。它将与普通网络一样快：没有桥接，没有转换，什么都没有。这就是为什么当您需要获得最佳网络性能时，它可能会有用。在主机网络堆栈中运行的容器将比在桥接网络上运行的容器实现更快的网络性能，无需穿越`docker0` `bridge`和`iptables`端口映射。在主机模式下，容器共享主机的网络命名空间（例如您的本地计算机），直接暴露给外部世界。通过使用`-net=host`命令开关，您的容器将通过主机的 IP 地址访问。但是，您需要意识到这可能是危险的。如果您有一个以 root 身份运行的应用程序，并且它有一些漏洞，那么存在主机网络被 Docker 容器远程控制的风险。使用主机网络类型还意味着您需要使用端口映射来访问容器内的服务。我们将在本章后面介绍端口映射。

# 无

长话短说，none 网络根本不配置网络。这种网络类型不使用任何驱动程序。当您不需要容器访问网络时，`-net=none`开关将完全禁用`docker run`命令的网络。

Docker 提供了一组简短的命令来处理网络。您可以从 shell（Linux 或 macOS）或 Windows 的命令提示符和 PowerShell 中运行它们。现在让我们来了解它们。

# 网络命令

在 Docker 中管理网络的父命令是`docker network`。您可以使用`docker network help`命令列出整个命令集，如下面的屏幕截图所示：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-k8s-java-dev/img/Image00040.jpg)

要获得特定命令的每个选项的详细语法和描述，请对每个命令使用`-help`开关。例如，要获取`docker network create`可用参数的描述，执行`docker network create -help`。

让我们简要描述每个可用的命令：

+   `**$ docker network ls**`：这是我们之前使用的命令，它简单地列出了容器可用的网络。它将输出网络标识符、名称、使用的驱动程序和网络的范围。

+   `**$ docker network create**`：创建新网络。命令的完整语法是，`docker network create [OPTIONS] NETWORK`。我们将在短时间内使用该命令

+   `**$ docker network rm**`：`dockercnetworkcrm`命令简单地删除网络

+   `**$ docker network connect**`：将容器连接到特定网络

+   `**$ docker network disconnect**`：正如其名称所示，它将断开容器与网络的连接

+   `**$ docker network inspect**`：docker network inspect 命令显示有关网络的详细信息。如果您遇到网络问题，这非常有用。我们现在要创建和检查我们的网络

`docker network` inspect 命令显示有关网络的详细信息。如果您遇到网络问题，这非常有用。我们现在要创建和检查我们的网络。

# 创建和检查网络

让我们创建一个网络。我们将称我们的网络为`myNetwork`。从 shell 或命令行执行以下命令：

```
$ docker network create myNetwork

```

这是命令的最简单形式，但可能会经常使用。它采用默认驱动程序（我们没有使用任何选项来指定驱动程序，我们将只使用默认的桥接驱动程序）。作为输出，Docker 将打印出新创建的网络的标识符：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-k8s-java-dev/img/Image00041.jpg)

稍后您将使用此标识符来连接容器或检查网络属性。命令的最后一个参数是网络的名称，这比 ID 更方便和更容易记住。在我们的情况下，网络名称是`myNetwork`。`docker network` create 命令接受更多参数，如下表所示：

| **选项** | **描述** |
| --- | --- |
| `-d, -driver="bridge"` | 管理网络的驱动程序 |
| `-aux-address=map[]` | 网络驱动程序使用的辅助 IPv4 或 IPv6 地址 |
| `-gateway=[]` | 主子网的 IPv4 或 IPv6 网关 |
| `-ip-range=[]` | 从子范围分配容器 IP |
| `-ipam-driver=default` | IP 地址管理驱动程序 |
| `-o`，`-opt=map[]` | 设置驱动程序的特定选项 |
| `-subnet=[]` | 以 CIDR 格式表示网络段的子网 |

最重要的参数之一是`-d`（`--driver`）选项，默认值为 bridge。驱动程序允许您指定网络类型。您记得，Docker 默认提供了几个驱动程序：`host`，`bridge`和`none`。

创建网络后，我们可以使用`docker network inspect`命令检查其属性。从 shell 或命令行执行以下操作：

```
$ docker network inspect myNetwork

```

作为回应，你将获得关于你的网络的大量详细信息。正如你在截图中看到的，我们新创建的网络使用桥接驱动程序，即使我们没有明确要求使用它：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-k8s-java-dev/img/Image00042.jpg)

正如你所看到的，容器列表是空的，原因是我们还没有将任何容器连接到这个网络。让我们现在来做。

# 将容器连接到网络

现在我们的`myNetwork`准备就绪，我们可以运行 Docker 容器并将其附加到网络。要启动容器，我们将使用`docker run --net=<NETWORK>`选项，其中`<NETWORK>`是默认网络之一的名称，或者是你自己创建的网络的名称。例如，让我们运行 Apache Tomcat，这是 Java Servlet 和 JavaServer 页面技术的开源实现：

```
docker run -it --net=myNetwork tomcat

```

这将需要一些时间。Docker 引擎将从 Docker Hub 拉取所有 Tomcat 镜像层，然后运行 Tomcat 容器。还有另一种选项可以将网络附加到容器上，你可以告诉 Docker 你希望容器连接到其他容器使用的相同网络。这样，你不需要显式指定网络，只需告诉 Docker 你希望两个容器在同一网络上运行。要做到这一点，使用`container:`前缀，就像下面的例子一样：

```
docker run -it --net=bridge myTomcat

docker run -it --net=container:myTomcat myPostgreSQL

```

在前面的例子中，我们使用桥接网络运行了`myTomcat`镜像。下一个命令将使用与`myTomcat`相同的网络运行`myPostgreSQL`镜像。这是一个非常常见的情况；你的应用程序将在与数据库相同的网络上运行，这将允许它们进行通信。当然，你在同一网络中启动的容器必须在同一 Docker 主机上运行。网络中的每个容器都可以直接与网络中的其他容器通信。尽管如此，网络本身会将容器与外部网络隔离开来，如下图所示：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-k8s-java-dev/img/Image00043.jpg)

如果在桥接、隔离网络中运行容器，我们需要指示 Docker 如何将容器的端口映射到主机的端口。我们现在要做的就是这个。

# 暴露端口和映射端口

通常情况下，当您希望容器化应用程序接受传入连接时，无论是来自其他容器还是来自 Docker 之外，都会出现这种情况。它可以是一个在端口 80 上监听的应用服务器，也可以是一个接受传入请求的数据库。

镜像可以暴露端口。暴露端口意味着您的容器化应用程序将在暴露的端口上监听。例如，Tomcat 应用服务器默认将在端口`8080`上监听。在同一主机和同一网络上运行的所有容器都可以与该端口上的 Tomcat 通信。暴露端口可以通过两种方式完成。它可以在 Dockerfile 中使用`EXPOSE`指令（我们将在稍后关于创建镜像的章节中进行）或者在`docker run`命令中使用`--expose`选项。接下来是这个官方 Tomcat 镜像的 Dockerfile 片段（请注意，为了示例的清晰度，它已经被缩短）：

```
FROM openjdk:8-jre-alpine

ENV CATALINA_HOME /usr/local/tomcat

ENV PATH $CATALINA_HOME/bin:$PATH

RUN mkdir -p "$CATALINA_HOME"

WORKDIR $CATALINA_HOME

EXPOSE 8080

CMD ["catalina.sh", "run"]

```

正如您所看到的，在 Dockerfile 的末尾附近有一个`EXPOSE 8080`指令。这意味着我们可以期望该容器在运行时将监听端口号`8080`。让我们再次运行最新的 Tomcat 镜像。这次，我们还将为我们的容器命名为`myTomcat`。使用以下命令启动应用服务器：

```
docker run -it --name myTomcat --net=myNetwork tomcat

```

为了检查同一网络上的容器是否可以通信，我们将使用另一个镜像`busybox`。BusyBox 是一种软件，它在一个可执行文件中提供了几个精简的 Unix 工具。让我们在单独的 shell 或命令提示符窗口中运行以下命令：

```
docker run -it --net container:myTomcat busybox

```

正如您所看到的，我们已经告诉 Docker，我们希望我们的`busybox`容器使用与 Tomcat 相同的网络。作为另一种选择，当然也可以使用`--net myNetwork`选项显式指定网络名称。

让我们检查它们是否确实可以通信。在运行`busybox`的 shell 窗口中执行以下操作：

```
$ wget localhost:8080

```

上一个指令将在另一个容器上监听的端口`8080`上执行`HTTP GET`请求。在成功下载 Tomcat 的`index.html`之后，我们证明了两个容器可以通信：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-k8s-java-dev/img/Image00044.jpg)

到目前为止，运行在同一主机和同一网络上的容器可以相互通信。但是如何与外部通信呢？端口映射派上了用场。我们可以将 Docker 容器暴露的端口映射到主机的端口上，这将是我们的本地主机。总体思路是我们希望主机上的端口映射到运行容器中的特定端口，就像 Tomcat 容器的端口号`8080`一样。

绑定主机到容器的端口（或一组端口），我们使用`docker run`命令的`-p`标志，如下例所示：

```
$ docker run -it --name myTomcat2 --net=myNetwork -p 8080:8080 tomcat

```

上一个命令运行了另一个 Tomcat 实例，也连接到`myNetwork`网络。然而，这一次，我们将容器的端口`8080`映射到相同编号的主机端口。`-p`开关的语法非常简单：只需输入主机端口号，冒号，然后是您想要映射的容器中的端口号：

```
$ docker run -p <hostPort>:<containerPort> <image ID or name>

```

Docker 镜像可以使用 Dockerfile 中的`EXPOSE`指令（例如`EXPOSE 7000-8000`）或`docker run`命令向其他容器暴露一系列端口，例如：

```
$ docker run --expose=7000-8000 <container ID or name>

```

然后，您可以使用`docker run`命令将一系列端口从主机映射到容器：

```
$ docker run -p 7000-8000:7000-8000 <container ID or name>

```

让我们验证一下是否可以从 Docker 外部访问 Tomcat 容器。为此，让我们运行带有映射端口的 Tomcat：

```
$ docker run -it --name myTomcat2 --net=myNetwork -p 8080:8080 tomcat 

```

然后，我们可以在我们喜爱的网络浏览器中输入以下地址：`http://localhost:8080`。

结果，我们可以看到 Tomcat 的默认欢迎页面，直接从运行的 Docker 容器中提供，如下截图所示：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-k8s-java-dev/img/Image00045.jpg)

很好，我们可以从 Docker 外部与我们的容器通信。顺便说一句，我们现在在主机上有两个隔离的 Tomcat 运行，没有任何端口冲突、资源冲突等。这就是容器化的力量。

您可能会问，暴露和映射端口之间有什么区别，也就是`--expose`开关和`-p`开关之间有什么区别？嗯，`--expose`将在运行时暴露一个端口，但不会创建任何映射到主机。暴露的端口只对在同一网络上运行的另一个容器和在同一 Docker 主机上运行的容器可用。另一方面，`-p`选项与`publish`相同：它将创建一个端口映射规则，将容器上的端口映射到主机系统上的端口。映射的端口将从 Docker 外部可用。请注意，如果您使用`-p`，但 Dockerfile 中没有`EXPOSE`，Docker 将执行隐式的`EXPOSE`。这是因为，如果一个端口对公众开放，它也会自动对其他 Docker 容器开放。

无法在 Dockerfile 中创建端口映射。映射一个或多个端口只是一个运行时选项。原因是端口映射配置取决于主机。Dockerfile 需要是与主机无关且可移植的。

您只能在运行时使用`-p`绑定端口。

还有一种选项，允许您一次性自动映射镜像中暴露的所有端口（即 Dockerfile 中的端口）在容器启动时。`-P`开关（这次是大写`P`）将动态分配一个随机的主机端口映射到 Dockerfile 中已经暴露的所有容器端口。

`-p`选项在映射端口时比`-P`提供更多控制。Docker 不会自动选择任何随机端口；由您决定主机上应该映射到容器端口的端口。

如果您运行以下命令，Docker 将在主机上将一个随机端口映射到 Tomcat 的暴露端口号`8080`：

```
$ docker run -it --name myTomcat3 --net=myNetwork -P tomcat

```

要确切查看已映射的主机端口，可以使用`docker ps`命令。这可能是确定当前端口映射的最快方法。`docker ps`命令用于查看正在运行的容器列表。从单独的 shell 控制台执行以下操作：

```
$ docker ps

```

在输出中，Docker 将列出所有正在运行的容器，显示在`PORTS`列中已经映射了哪些端口：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-k8s-java-dev/img/Image00046.jpg)

正如您在上一张截图中所看到的，我们的`myTomcat3`容器将把`8080`端口映射到主机上的`32772`端口。再次在`http://localhost:32772`地址上执行`HTTP GET`方法将会显示`myTomcat3`的欢迎页面。`docker ps`命令的替代方法是 docker port 命令，与容器 ID 或名称一起使用（这将为您提供已映射的端口信息）。在我们的情况下，这将是：

```
$ docker port myTomcat3

```

因此，Docker 将输出映射，表示容器中的端口号 80 已映射到主机上的端口号`8080`：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-k8s-java-dev/img/Image00047.jpg)

关于所有端口映射的信息也可以在 docker inspect 命令的结果中找到。例如，执行以下命令：

```
$ docker inspect myTomcat2

```

在`docker inspect`命令的输出中，您将找到包含映射信息的`Ports`部分：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-k8s-java-dev/img/Image00048.jpg)

让我们简要总结一下与暴露和映射端口相关的选项：

| **指令** | **含义** |
| --- | --- |
| `EXPOSE` | 表示指定端口上有服务可用。在 Dockerfile 中使用，使暴露的端口对其他容器开放。 |
| `--expose` | 与`EXPOSE`相同，但在运行时，在容器启动期间使用。 |
| `-p hostPort:containerPort` | 指定端口映射规则，将容器上的端口与主机上的端口进行映射。使得 Docker 外部的端口开放。 |
| `-P` | 将主机的动态分配的随机端口（或端口）映射到使用`EXPOSE`或`--expose`暴露的所有端口。 |

映射端口是一个很棒的功能。它为您提供了灵活的配置可能性，可以将您的容器开放给外部世界。事实上，如果您希望容器化的 Web 服务器、数据库或消息服务器能够与其他服务器通信，这是必不可少的。如果默认的网络驱动程序集不够用，您可以尝试在互联网上找到特定的驱动程序，或者自己开发一个。Docker 引擎网络插件扩展了 Docker 以支持各种网络技术，如 IPVLAN、MACVLAN，或者完全不同和奇特的技术。在 Docker 中，网络的可能性几乎是无限的。现在让我们专注于 Docker 容器可扩展性卷的另一个非常重要的方面。

# 持久存储

正如您在第一章中所记得的，*Docker 简介*，Docker 容器文件系统默认是临时的。如果您启动一个 Docker 镜像（即运行容器），您将得到一个读写层，位于层栈的顶部。您可以随意创建，修改和删除文件；如果您将更改提交回镜像，它们将变得持久。如果您想在镜像中创建应用程序的完整设置，包括所有环境，这是一个很好的功能。但是，当涉及存储和检索数据时，这并不是很方便。最好的选择是将容器的生命周期和您的应用程序与数据分开。理想情况下，您可能希望将这些分开，以便由您的应用程序生成（或使用）的数据不会被销毁或绑定到容器的生命周期，并且可以被重复使用。

一个完美的例子是一个 Web 应用程序服务器：Docker 镜像包含 Web 服务器软件，例如 Tomcat，部署了您的 Java 应用程序，配置好并且可以立即使用。但是，服务器将使用的数据应该与镜像分离。这是通过卷来实现的，在本章的这部分我们将重点关注卷。卷不是联合文件系统的一部分，因此写操作是即时的并且尽可能快，不需要提交任何更改。

卷存在于联合文件系统之外，并且作为主机文件系统上的普通目录和文件存在。

Docker 数据卷有三个主要用途：

+   在主机文件系统和 Docker 容器之间共享数据

+   在容器被移除时保留数据

+   与其他 Docker 容器共享数据

让我们从我们可以使用的卷相关命令列表开始。

# 与卷相关的命令

与卷相关的命令的基础是 docker volume。命令如下：

+   `**$docker volume create**`：创建一个卷

+   `**$ docker volume inspect**`：显示一个或多个卷的详细信息

+   `**$docker volume ls**`：列出卷

+   `**$ docker volume rm**`：删除一个或多个卷

+   `**$ docker volume prune**`：删除所有未使用的卷，即不再映射到任何容器的所有卷

与与网络相关的命令类似，如果您使用`-help`开关执行每个命令，您可以获得详细的描述和所有可能的选项，例如：docker volume create `-help`。让我们开始创建一个卷。

# 创建卷

正如您从第一章 *Docker 简介*中记得的那样，Docker for Windows 或 Docker for Mac 中有一个设置屏幕，允许我们指定 Docker 可以访问哪些驱动器。首先，让我们在 Docker for Windows 中标记驱动器 D，以便让它可用于 Docker 容器：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-k8s-java-dev/img/Image00049.jpg)

为了我们的卷示例，我在我的 D 驱动器上创建了一个`docker_volumes/volume1`目录，并在其中创建了一个空的`data.txt`文件：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-k8s-java-dev/img/Image00050.jpg)

有两种创建卷的方法。第一种是在运行镜像时指定`-v`选项。让我们运行我们已经知道的`busybox`镜像，并同时为我们的数据创建一个卷：

```
$ docker run -v d:/docker_volumes/volume1:/volume -it busybox

```

在上一个命令中，我们使用`-v`开关创建了一个卷，并指示 Docker 将`host`目录`d:/docker_volumes/volume1`映射到正在运行的容器中的`/volume`目录。如果我们现在列出正在运行的`busybox`容器中`/volume`目录的内容，我们可以看到我们的空`data1.txt`文件，如下面的截图所示：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-k8s-java-dev/img/Image00051.jpg)

`-v`选项中的参数是主机上的目录（在这种情况下是您自己的操作系统，在我们的示例中是`d:/docker_volumes/volume1`），一个冒号，以及容器中可用的路径，在我们的示例中是`/volume1`。创建的卷是一种映射的目录。它将对容器可用，并且也可以从主机操作系统中访问。映射目录（主机的`d:/docker_volumes/volume1`）中已经存在的任何文件将在映射期间在容器内可用；它们不会在映射期间被删除。

`-v`选项不仅可以用于目录，还可以用于单个文件。如果您想在容器中使用配置文件，这将非常有用。最好的例子是官方 Docker 文档中的例子：

```
$ docker run -it -v ~/.bash_history:/root/.bash_history ubuntu

```

执行上一个命令将在本地机器和正在运行的 Ubuntu 容器之间给您相同的 bash 历史记录。最重要的是，如果您退出容器，您本地机器上的 bash 历史记录将包含您在容器内执行的 bash 命令。映射文件对您作为开发人员在调试或尝试应用程序配置时也很有用。

从主机映射单个文件允许暴露应用程序的配置。

除了在启动容器时创建卷外，还有一个命令可以在启动容器之前创建卷。我们现在将使用它。

创建无名称卷的最简单形式将是：

```
$ docker volume create

```

作为输出，Docker 将为您提供卷标识符，您以后可以使用它来引用此卷。最好给卷一个有意义的名称。要创建一个独立的命名卷，请执行以下命令：

```
$ docker volume create --name myVolume

```

要列出我们现在可用的卷，执行`docker volume ls`命令：

```
$ docker volume ls

```

输出将简单地列出到目前为止我们创建的卷的列表：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-k8s-java-dev/img/Image00052.jpg)

以这种方式创建的卷不会显式地映射到主机上的路径。如果容器的基本映像包含指定挂载点处的数据（作为 Dockerfile 处理的结果），则此数据将在卷初始化时复制到新卷中。这与显式指定`host`目录不同。其背后的想法是，在创建图像时，您不应该关心卷在主机系统上的位置，使图像在不同主机之间可移植。让我们运行另一个容器并将命名卷映射到其中：

```
$ docker run -it -v myVolume:/volume --name myBusybox3 busybox

```

请注意，这一次，我们没有在主机上指定路径。相反，我们指示 Docker 使用我们在上一步创建的命名卷。命名卷将在容器中的`/volume`路径处可用。让我们在卷上创建一个文本文件：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-k8s-java-dev/img/Image00053.jpg)

如果我们现在运行另一个容器，指定相同的命名卷，我们将能够访问我们在之前创建的`myBusybox3`容器中可用的相同数据：

```
$ docker run -it -v myVolume:/volume --name myBusybox4 busybox

```

我们的两个容器现在共享单个卷，如下截图所示：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-k8s-java-dev/img/Image00054.jpg)

Docker 命名卷是在容器之间共享卷的一种简单方法。它们也是数据专用容器的一个很好的替代方案，这在 Docker 的旧时代曾经是一种常见做法。现在已经不再是这样了——命名卷要好得多。值得注意的是，您不仅限于每个容器只有一个卷，因为那将是一个严重的限制。

您可以多次使用`-v`来挂载多个数据卷。

在容器之间共享卷的另一个选项是`-volumes-from`开关。如果您的一个容器已经挂载了卷，通过使用此选项，我们可以指示 Docker 使用另一个容器中映射的卷，而不是提供卷的名称。考虑以下示例：

```
$ docker run -it -volumes-from myBusybox4 --name myBusybox5 busybox

```

以这种方式运行`myBusybox5`容器后，如果再次进入运行的`myBusybox5`容器中的`/volume`目录，您将看到相同的`data.txt`文件。

`docker volume ls`命令可以接受一些过滤参数，这可能非常有用。例如，您可以列出未被任何容器使用的卷：

```
docker volume ls -f dangling=true

```

不再被任何容器使用的卷可以通过使用 docker volumes prune 命令轻松删除：

```
docker volume prune

```

要列出使用特定驱动程序创建的卷（我们将在短时间内介绍驱动程序），您可以使用驱动程序过滤器来过滤列表，如下例所示：

```
docker volume ls -f driver=local

```

最后但同样重要的是，创建卷的另一种方法是在 Dockerfile 中使用`VOLUME CREATE`指令。在本书的后面，当从 Dockerfile 创建镜像时，我们将使用它。使用`VOLUME CREATE`指令创建卷与在容器启动期间使用`-v`选项相比有一个非常重要的区别：当使用`VOLUME CREATE`时，您无法指定`host`目录。这类似于暴露和映射端口。您无法在 Dockerfile 中映射端口。Dockerfile 应该是可移植的、可共享的和与主机无关的。`host`目录是 100%依赖于主机的，会在任何其他机器上出现问题，这与 Docker 的理念有点不符。因此，在 Dockerfile 中只能使用可移植指令。

如果需要在创建卷时指定`host`目录，则需要在运行时指定它。

# 删除卷

与创建卷一样，Docker 中有两种删除卷的方法。首先，您可以通过引用容器的名称并执行 docker `rm -v`命令来删除卷：

```
$ docker rm -v <containerName or ID>

```

当删除容器时，如果没有提供`-v`选项，Docker 不会警告您删除其卷。结果，您将拥有`悬空`卷——不再被容器引用的卷。正如您记得的那样，使用`docker volume prune`命令很容易摆脱它们。

另一种删除卷的选项是使用`docker volume rm`命令：

```
$ docker volume rm <volumeName or ID>

```

如果卷恰好被容器使用，Docker 引擎将不允许您删除它，并会给出警告消息：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-k8s-java-dev/img/Image00055.jpg)

正如您所看到的，在 Docker 中创建、共享和删除卷并不那么棘手。它非常灵活，允许创建您的应用程序所需的设置。但这种灵活性还有更多。在创建卷时，您可以指定`--driver`选项（或简写为`-d`），如果您需要映射一些外部、不太标准的存储，这可能会很有用。到目前为止，我们创建的卷都是使用本地文件系统驱动程序（文件存储在主机系统的本地驱动器上）；您可以在使用`volume inspect`命令检查卷时看到驱动程序名称。不过还有其他选项——现在让我们来看看它们。

# 卷驱动程序

与网络驱动程序插件一样，卷插件扩展了 Docker 引擎的功能，并实现了与其他类型的存储的集成。在互联网上有大量可用的免费插件；您可以在 Docker 的 GitHub 页面上找到一个列表。其中一些包括：

+   **Azure 文件存储的 Docker 卷驱动程序**：这是一个 Docker 卷驱动程序，它使用 Azure 文件存储将文件共享挂载到 Docker 容器作为卷。它使用 Azure 文件存储的网络文件共享（SMB/CIFS 协议）功能。您可以创建可以在不同主机之间无缝迁移或在不同主机上运行的多个容器之间共享卷的 Docker 容器。

+   **IPFS**：开源卷插件，允许将 IPFS 文件系统用作卷。IPFS 是一个非常有趣和有前途的存储系统；它可以以高效的方式分发大量数据。它提供了去重、高性能和集群持久性，提供安全的 P2P 内容传递、快速性能和去中心化的归档。IPFS 提供了对数据的弹性访问，独立于低延迟或对骨干网的连接。

+   **Keywhiz**：您可以使用此驱动程序使您的容器与远程 Keywhiz 服务器通信。Keywhiz 是一个用于管理和分发秘密数据的系统，例如 TLS 证书/密钥、GPG 密钥、API 令牌和数据库凭据。Keywhiz 使管理变得更容易和更安全：Keywhiz 服务器在集群中将加密的秘密数据集中存储在数据库中。客户端使用**相互认证的 TLS**（**mTLS**）来检索他们有权限访问的秘密。

从前面的例子中可以看出，它们非常有趣，有时甚至是异国情调的。由于 Docker 及其插件架构的可扩展性，您可以创建非常灵活的设置。但是，第三方驱动程序并不总是引入全新的存储类型；有时它们只是扩展现有的驱动程序。一个例子就是 Local Persist Plugin，它通过允许您在主机的任何位置指定挂载点来扩展默认的本地驱动程序功能，从而使文件始终持久存在，即使通过`docker volume rm`命令删除了卷。

如果您需要一个尚未提供的卷插件，您可以自己编写。该过程在 Docker 的 GitHub 页面上有非常详细的文档，还有可扩展的示例。

我们现在已经了解了如何将我们的容器开放给外部世界。我们可以使用网络和挂载卷来在容器和其他主机之间共享数据。让我们总结一下我们在本章中学到的内容：

+   我们可以使用网络插件来进一步扩展网络数据交换

+   卷会持久保存数据，即使容器重新启动

+   对卷上的文件的更改是直接进行的，但在更新镜像时不会包括这些更改

+   数据卷即使容器本身被删除也会持久存在

+   卷允许在主机文件系统和 Docker 容器之间共享数据，或者在其他 Docker 容器之间共享数据

+   我们可以使用卷驱动程序来进一步扩展文件交换的可能性

同一台 Docker 主机上的容器在默认的桥接网络上会自动看到彼此。

# 总结

在本章中，我们学习了 Docker 网络和存储卷功能。我们知道如何区分各种网络类型，如何创建网络，以及如何公开和映射网络端口。

我们已经学习了与卷相关的命令，现在可以创建或删除卷。在第三章 *使用微服务*中，我们将专注于使用 Docker 和 Kubernetes 部署的软件，以及后来的 Java 微服务。


# 第三章：使用微服务

在阅读前两章之后，您现在应该对 Docker 架构及其概念有所了解。在我们继续 Java、Docker 和 Kubernetes 之旅之前，让我们先了解一下微服务的概念。

通过阅读本章，您将了解为什么转向微服务和云开发是必要的，以及为什么单片架构不再是一个选择。微服务架构也是 Docker 和 Kubernetes 特别有用的地方。

本章将涵盖以下主题：

+   微服务简介和与单片架构的比较

+   Docker 和 Kubernetes 如何适应微服务世界

+   何时使用微服务架构

在我们实际创建 Java 微服务并使用 Docker 和 Kubernetes 部署之前，让我们先解释一下微服务的概念，并将其与单片架构进行比较。

# 微服务简介

根据定义，微服务，也称为**微服务架构**（**MSA**），是一种架构风格和设计模式，它认为一个应用程序应该由一组松散耦合的服务组成。这种架构将业务领域模型分解为由服务实现的较小、一致的部分。换句话说，每个服务都将有自己的责任，独立于其他服务，每个服务都将提供特定的功能。

这些服务应该是孤立的和自治的。然而，它们当然需要通信以提供一些业务功能。它们通常使用`REST`暴露或通过发布和订阅事件的方式进行通信。

解释微服务背后理念的最好方式是将其与构建大型应用程序的旧传统方法——单片设计进行比较。

看一下下面的图表，展示了单片应用程序和由微服务组成的分布式应用程序。

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-k8s-java-dev/img/Image00056.jpg)

正如您在上一个图表中所看到的，单片应用程序与使用微服务架构创建的应用程序完全不同。让我们比较这两种方法，并指出它们的优点和缺点。

# 单片与微服务

我们从描述单片架构开始比较，以展示其特点。

# 单片架构

过去，我们习惯于创建完整、庞大和统一的代码片段作为应用程序。以 Web MVC 应用程序为例。这种应用程序的简化架构如下图所示：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-k8s-java-dev/img/Image00057.jpg)

正如你所看到的，该图表展示了典型的网络应用程序，这里是银行系统的一个片段。这是一个**模型** **视图** **控制器**（**MVC**）应用程序，由模型、视图和控制器组成，用于向客户端浏览器提供 HTML 内容。它可能还可以通过 REST 端点接受和发送 JSON 内容。这种应用程序是作为一个单一单元构建的。正如你所看到的，我们在这里有几个层。企业应用程序通常分为三个部分：客户端用户界面（包括在浏览器中运行的 HTML 页面和 JavaScript）、处理`HTTP`请求的服务器端部分（可能使用类似 spring 的控制器构建），然后我们有一个服务层，可能使用 EJB 或 Spring 服务来实现。服务层执行特定领域的业务逻辑，并最终检索/更新数据库中的数据。这是一个非常典型的网络应用程序，我们每个人可能都曾经创建过。整个应用程序是一个单体，一个单一的逻辑可执行文件。要对系统进行任何更改，我们必须构建和部署整个服务器端应用程序的更新版本；这种应用程序通常打包成单个 WAR 或 EAR 存档，连同所有静态内容，如 HTML 和 JavaScript 文件一起。一旦部署，所有应用程序代码都在同一台机器上运行。通常情况下，要扩展这种应用程序，需要在集群中的多台机器上部署多个相同的应用程序代码副本，可能在某个负载均衡器后面。

这个设计并不算太糟糕，毕竟我们的应用程序已经上线运行了。但是，世界变化很快，特别是在使用敏捷方法论的时候。企业已经开始要求比以往更快地发布软件。尽快成为 IT 开发语言词典中非常常见的词语。规格经常波动，所以代码经常变化并随着时间增长。如果团队规模庞大（在复杂的大型应用程序的情况下可能会是这样），每个人都必须非常小心，不要破坏彼此的工作。随着每个新增的功能，我们的应用程序变得越来越复杂。编译和构建时间变得更长，迟早会变得棘手，使用单元测试或集成测试来测试整个系统。此外，新成员加入团队的入口点可能令人望而生畏，他们需要从源代码存储库中检出整个项目。然后他们需要在他们的集成开发环境中构建它（在大型应用程序的情况下并不总是那么容易），并分析和理解组件结构以完成他们的工作。此外，负责用户界面部分的人需要与负责中间层的开发人员、数据库建模人员、数据库管理员等进行沟通。随着时间的推移，团队结构往往会开始模仿应用程序架构。有风险，即特定层上的开发人员倾向于尽可能多地将逻辑放入他所控制的层中。结果，随着时间的推移，代码可能变得难以维护。我们都曾经历过这种情况，对吧？

此外，单片系统的扩展并不像将 WAR 或 EAR 放入另一个应用服务器然后启动那么容易。因为所有应用代码都在服务器上的同一个进程中运行，通常几乎不可能扩展应用程序的各个部分。举个例子：我们有一个集成了 VOIP 外部服务的应用程序。我们的应用程序用户不多，但是来自 VOIP 服务的事件却很多，我们需要处理。为了处理不断增加的负载，我们需要扩展我们的应用程序，在单片系统的情况下，我们需要扩展整个系统。这是因为应用程序是一个单一的、庞大的工作单元。如果应用程序的一个服务是 CPU 或资源密集型的，整个服务器必须配备足够的内存和 CPU 来处理负载。这可能很昂贵。每个服务器都需要一个快速的 CPU 和足够的 RAM 来运行我们应用程序中最苛刻的组件。

所有单片应用程序都具有以下特点：

+   它们通常很大，经常涉及许多人参与其中。这可能是一个问题，当将项目加载到 IDE 中时，尽管拥有强大的机器和出色的开发环境，比如 IntelliJ IDEA。但问题不仅仅在于数百、数千或数百万行代码。它还涉及解决方案的复杂性，比如团队成员之间的沟通问题。沟通问题可能导致在应用程序的不同部分针对同一个问题出现多种解决方案。这将使问题变得更加复杂，很容易演变成一个无人能够理解整个系统的大团团乱。此外，人们可能害怕对系统进行重大更改，因为在相反的一端可能会突然停止工作。如果这是由用户在生产系统上报告的，那就太糟糕了。

+   它们有一个长的发布周期，我们都知道发布管理、权限、回归测试等流程。几乎不可能在一个庞大的单片应用程序中创建持续交付流程。

+   它们很难扩展；通常需要运维团队投入大量工作来在集群中增加一个新的应用实例。扩展特定功能是不可能的，你唯一的选择就是在集群中增加整个系统的实例。这使得扩展变得非常具有挑战性。

+   在部署失败的情况下，整个系统将不可用。

+   你被锁定在特定的编程语言或技术栈中。当然，使用 Java，系统的部分可以用在 JVM 上运行的一个或多个语言开发，比如 Scala、Kotlin 或 Groovy，但如果你需要与`.net`库集成，问题就开始了。这也意味着你不总是能够使用合适的工具来完成工作。想象一下，你想在数据库中存储大量复杂的文档。它们通常有不同的结构。作为文档数据库的 MongoDB 应该是合适的，对吧？是的，但我们的系统正在运行 Oracle。

+   它不太适合敏捷开发过程，在这种过程中，我们需要不断实施变更，几乎立即发布到生产环境，并准备好进行下一次迭代。

正如你所看到的，单体应用只适用于小规模团队和小型项目。如果你需要一个更大规模并涉及多个团队的系统，最好看看其他选择。但是对于现有的单体系统，你可能喜欢处理它，该怎么办呢？你可能会意识到，将系统的一些部分外包到小服务中可能会很方便。这将加快开发过程并增加可测试性。它还将使你的应用程序更容易扩展。虽然单体应用仍保留核心功能，但许多部分可以外包到支持核心模块的小边缘服务中。这种方法在下图中呈现：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-k8s-java-dev/img/Image00058.jpg)

在这种中间解决方案中，主要业务逻辑将保留在你的应用程序单体中。诸如集成、后台作业或其他可以通过消息触发的小子系统等事物可以移动到它们自己的服务中。你甚至可以将这些服务放入云中，以进一步减少管理基础设施的必要性。这种方法允许你逐渐将现有的单体应用程序转变为完全面向服务的架构。让我们来看看微服务的方法。

# 微服务架构

微服务架构旨在解决我们提到的单片应用程序的问题。主要区别在于单片应用程序中定义的服务被分解为单独的服务。最重要的是，它们是分别部署在不同的主机上的。看一下下面的图表：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-k8s-java-dev/img/Image00059.jpg)

使用微服务架构创建应用程序时，每个微服务负责单一的、特定的业务功能，并且只包含执行该特定业务逻辑所需的实现。这与创建系统的“分而治之”的方式相同。这似乎与面向 SOA 的架构相似。事实上，传统的 SOA 和微服务架构有一些共同的特点。两者都将应用程序的片段组织成服务，并且都定义了清晰的边界，服务可以在其中与其他服务解耦。然而，SOA 起源于需要将单片应用程序与另一个应用程序集成起来。通常情况下，这是通过通常基于 SOAP 的 API 完成的，使用繁重的 XML 消息传递。在 SOA 中，这种集成在中间通常严重依赖某种中间件，通常是企业服务总线（ESB）。微服务架构也可以利用消息总线，但有显著的区别。在微服务架构中，消息层中根本没有逻辑，它纯粹用作从一个服务到另一个服务的消息传输。这与 ESB 形成了鲜明对比，ESB 需要大量的逻辑来进行消息路由、模式验证、消息转换等。因此，微服务架构比传统的 SOA 更不繁琐。

在扩展方面，将微服务与单片应用程序进行比较时存在巨大的差异。微服务的关键优势在于单个服务可以根据资源需求进行独立扩展。这是因为它们是自给自足的和独立的。由于微服务通常部署在资源较小的主机上，主机只需要包含服务正常运行所需的资源。随着资源需求的增长，横向和纵向扩展都很容易。要进行横向扩展，只需部署所需数量的实例来处理特定组件的负载。

在接下来的章节中，当我们开始了解 Kubernetes 时，我们将回到这个概念。与单片系统相比，垂直扩展也更容易和更便宜，您只需升级部署微服务的主机。此外，引入服务的新版本也很容易，您不需要停止整个系统只是为了升级某个功能。事实上，您可以在运行时进行。部署后，微服务提高了整个应用程序的容错能力。例如，如果一个服务出现内存泄漏或其他问题，只有这个服务会受到影响，然后可以修复和升级，而不会干扰其他部分系统。这在单片架构中并非如此，那里一个故障组件可能会导致整个应用程序崩溃。

从开发者的角度来看，将应用程序拆分为单独部署的独立组件具有巨大优势。精通服务器端 JavaScript 的开发者可以开发其`node.js`部分，而系统的其余部分将使用 Java 开发。这一切都与每个微服务暴露的 API 有关；除了这个 API，每个微服务都不需要了解其他服务的任何信息。这使得开发过程变得更加容易。单独的微服务可以独立开发和测试。基本上，微服务的方法规定，不是所有开发者都在一个庞大的代码库上工作，而是由小而敏捷的团队管理的几个较小的代码库。服务之间唯一的依赖是它们暴露的 API。存储数据也有所不同。正如我们之前所说，每个微服务应该负责存储自己的数据，因为它应该是独立的。这导致了微服务架构的另一个特性，即具有多语言持久性的可能性。微服务应该拥有自己的数据。

微服务之间使用 REST 端点或事件进行通信和数据交换，它们可以以最适合工作的形式存储自己的数据。如果数据是关系型的，服务将使用传统的关系型数据库，如 MySQL 或 PostgreSQL。如果文档数据库更适合工作，微服务可以使用例如 MongoDB，或者如果是图形数据，可以使用 Neo4j。这导致另一个结论，通过实施微服务架构，我们现在只能选择最适合工作的编程语言或框架，这也适用于数据存储。当然，拥有自己的数据可能会导致微服务架构中的一个挑战，即数据一致性。我们将在本章稍后讨论这个主题。

让我们从开发过程的角度总结使用微服务架构的好处：

+   服务可以使用各种语言、框架及其版本进行编写

+   每个微服务相对较小，更容易被开发人员理解（从而减少错误），易于开发和可测试

+   部署和启动时间快，这使开发人员更加高效

+   每项服务可以由多个服务实例组成，以增加吞吐量和可用性

+   每个服务可以独立部署，更容易频繁部署新版本的服务

+   更容易组织开发过程；每个团队拥有并负责一个或多个服务，可以独立开发、发布或扩展他们的服务，而不受其他团队的影响

+   您可以选择您认为最适合工作的编程语言或框架。对技术栈没有长期承诺。如果需要，服务可以在新的技术栈中重写，如果没有 API 更改，这对系统的其他部分是透明的

+   对于持续交付来说更好，因为小单元更容易管理、测试和部署。只要每个团队保持向后和向前的 API 兼容性，就可以在与其他团队解耦的发布周期中工作。有一些情况下这些发布周期是耦合的，但这并不是常见情况

# 保持数据一致性

服务必须松散耦合，以便它们可以独立开发、部署和扩展。它们当然需要进行通信，但它们是彼此独立的。它们有明确定义的接口并封装实现细节。但是数据呢？在现实世界和非平凡的应用程序中（微服务应用程序可能是非平凡的），业务交易经常必须跨多个服务。例如，如果你创建一个银行应用程序，在执行客户的转账订单之前，你需要确保它不会超过他的账户余额。单体应用程序附带的单个数据库给了我们很多便利：原子事务，一个查找数据的地方等等。

另一方面，在微服务世界中，不同的服务需要是独立的。这也意味着它们可以有不同的数据存储需求。对于一些服务，它可能是关系型数据库，而其他服务可能需要像 MongoDB 这样擅长存储复杂的非结构化数据的文档数据库。

因此，在构建微服务并将我们的数据库拆分成多个较小的数据库时，我们如何管理这些挑战呢？我们还说过服务应该拥有自己的数据。也就是说，每个微服务应该只依赖于自己的数据库。服务的数据库实际上是该服务实现的一部分。这在设计微服务架构时会带来相当有趣的挑战。正如马丁·福勒在他的“微服务权衡”专栏中所说的：在分布式系统中保持强一致性非常困难，这意味着每个人都必须管理最终一致性。我们如何处理这个问题？嗯，这一切都与边界有关。

微服务应该有明确定义的责任和边界。

微服务需要根据其业务领域进行分组。此外，在实践中，您需要以这样的方式设计您的微服务，使它们不能直接连接到另一个服务拥有的数据库。松散耦合意味着微服务应该公开清晰的 API 接口，模拟与数据相关的数据和访问模式。它们必须遵守这些接口，当需要进行更改时，您可能会引入版本控制机制，并创建另一个版本的微服务。您可以使用发布/订阅模式将一个微服务的事件分派给其他微服务进行处理，就像您在下面的图表中看到的那样。

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-k8s-java-dev/img/Image00060.jpg)

您希望使用的发布/订阅机制应该为事件处理提供重试和回滚功能。在发布/订阅场景中，修改或生成数据的服务允许其他服务订阅事件。订阅的服务接收到事件，表明数据已被修改。通常情况下，事件包含已经被修改的数据。当然，事件发布/订阅模式不仅可以用于数据更改，还可以作为服务之间的通用通信机制。这是一种简单而有效的方法，但它也有一个缺点，就是可能会丢失事件。

在创建分布式应用程序时，您可能需要考虑一段时间会出现数据不一致的情况。当应用程序在一台机器上更改数据项时，该更改需要传播到其他副本。由于更改传播不是即时的，因此在某个时间间隔内，一些副本将具有最新的更改，而其他副本则没有。然而，更改最终将传播到所有副本。这就是为什么这被称为最终一致性。您的服务需要假设数据在一段时间内处于不一致状态，并需要通过使用数据本身，推迟操作，甚至忽略某些数据来处理这种情况。

正如你所看到的，微服务架构背后有很多挑战，但也有很多优势。不过，你应该注意，我们需要解决更多的挑战。由于服务彼此独立，它们可以用不同的编程语言实现。这意味着每个服务的部署过程可能会有所不同：对于 Java Web 应用程序和 node.js 应用程序来说，部署过程完全不同。这可能会使部署到服务器变得复杂。这正是 Docker 发挥作用的关键点。

# Docker 角色

正如你在前几章中所记得的，Docker 利用了容器化的概念。无论应用程序使用什么语言和技术，你只需将其放入一个可部署和可运行的软件中，称为镜像（在这种情况下，应用程序将是一个微服务）。我们将在第四章《创建 Java 微服务》中详细介绍将 Java 应用程序打包到镜像的过程。Docker 镜像将包含我们的服务所需的一切，可以是一个带有所有必需库和应用服务器的 Java 虚拟机，也可以是一个将 node.js 应用程序与所有所需的 node.js 模块（如 express.js 等）打包在一起的 node.js 运行时。一个微服务可能由两个容器组成，一个运行服务代码，另一个运行数据库以保存服务自己的数据。

Docker 将容器隔离到一个进程或服务。实际上，我们应用程序的所有部分只是一堆打包好的黑匣子，可以直接使用 Docker 镜像。容器作为完全隔离的沙盒运行，每个容器只有操作系统的最小内核。Docker 使用 Linux 内核，并利用诸如 cnames 和命名空间之类的内核接口，允许多个容器共享同一个内核，同时完全隔离运行。

由于底层系统的系统资源是共享的，您可以以最佳性能运行您的服务，与传统虚拟机相比，占用空间大大减小。因为容器是可移植的，正如我们在第二章中所说的，*网络和持久存储*，它们可以在 Docker 引擎可以运行的任何地方运行。这使得微服务的部署过程变得简单。要在给定主机上部署服务的新版本，只需停止运行的容器，并启动一个基于使用服务代码最新版本的 Docker 镜像的新容器。我们将在本书的后面介绍创建镜像新版本的过程。当然，主机上运行的所有其他容器都不会受到此更改的影响。

微服务需要使用`REST`协议进行通信，我们的 Docker 容器（或者更准确地说，您的 Java 微服务打包并在 Docker 容器内运行）也需要使用网络进行通信。正如您在第二章中记得的，关于网络的*网络和持久存储*，很容易暴露和映射 Docker 容器的网络端口。Docker 容器化似乎非常适合微服务架构的目的。您可以将微服务打包到一个便携式盒子中，并暴露所需的网络端口，使其能够与外部世界通信。在需要时，您可以运行任意数量的这些盒子。

让我们总结一下在处理微服务时有用的 Docker 功能：

+   很容易扩展和缩减服务，只需更改运行的容器实例数量

+   容器隐藏了每个服务背后技术的细节。我们的所有服务容器都以完全相同的方式启动和停止，无论它们使用什么技术栈

+   每个服务实例都是隔离的

+   您可以限制容器消耗的 CPU 和内存的运行时约束

+   容器构建和启动速度快。正如您在第一章中记得的，*Docker 简介*，与传统虚拟化相比，开销很小

+   Docker 镜像层被缓存，这在创建服务的新版本时可以提供另一个速度提升

微服务架构的定义完全符合吗？当然符合，但是有一个问题。因为我们的微服务分布在多个主机上，很难跟踪哪些主机正在运行某些服务，也很难监视哪些服务需要更多资源，或者在最坏的情况下，已经死掉并且无法正常运行。此外，我们需要对属于特定应用程序或功能的服务进行分组。这是我们拼图中缺少的元素：容器管理和编排。许多框架出现了，目的是处理更复杂的场景：在集群中管理单个服务或在多个主机上管理多个实例，或者如何在部署和管理级别协调多个服务之间。其中一个工具就是 Kubernetes。

# Kubernetes 的作用

虽然 Docker 提供了容器的生命周期管理，但 Kubernetes 将其提升到了下一个级别，提供了容器集群的编排和管理。正如你所知，使用微服务架构创建的应用程序将包含一些分离的、独立的服务。我们如何对它们进行编排和管理？Kubernetes 是一个开源工具，非常适合这种情况。它定义了一组构建块，提供了部署、维护和扩展应用程序的机制。Kubernetes 中的基本调度单元称为 pod。Pod 中的容器在同一主机上运行，共享相同的 IP 地址，并通过 localhost 找到彼此。它们还可以使用标准的进程间通信方式进行通信，比如共享内存或信号量。Pod 为容器化组件增加了另一个抽象级别。一个 pod 由一个或多个容器组成，这些容器保证在主机上共同定位，并且可以共享资源。它与一个应用程序相关的容器的逻辑集合是相同的。

对于传统服务，例如与相应数据库一起的 REST 端点（实际上是我们完整的微服务），Kubernetes 提供了服务的概念。服务定义了一组逻辑 pod，并强制执行从外部世界访问这些逻辑组的规则。Kubernetes 使用标签的概念来为 pod 和其他资源（服务、部署等）添加标签。这些标签是可以在创建时附加到资源上，然后随时添加和修改的简单键值对。我们稍后将使用标签来组织和选择资源的子集（例如 pod）以将它们作为一个实体进行管理。

Kubernetes 可以自动将您的容器或一组容器放置在特定的主机上。为了找到合适的主机（具有最小工作负载的主机），它将分析主机的当前工作负载以及不同的共存和可用性约束。当然，您可以手动指定主机，但拥有这种自动功能可以充分利用可用的处理能力和资源。Kubernetes 可以监视容器、pod 和集群级别的资源使用情况（CPU 和 RAM）。资源使用和性能分析代理在每个节点上运行，自动发现节点上的容器，并收集 CPU、内存、文件系统和网络使用统计信息。

Kubernetes 还管理您的容器实例的生命周期。如果实例过多，其中一些将被停止。如果工作负载增加，新的容器将自动启动。这个功能称为容器自动扩展。它将根据内存、CPU 利用率或您为服务定义的其他指标（例如每秒查询次数）自动更改运行容器的数量。

正如您从第二章中记得的那样，*网络和持久存储*，Docker 使用卷来持久保存您的应用数据。Kubernetes 也支持两种卷：常规卷与 pod 具有相同的生命周期，持久卷则独立于任何 pod 的生命周期。卷类型以插件的形式与 Docker 实现方式相同。这种可扩展的设计使您可以拥有几乎任何类型的卷。它目前包含存储插件，如 Google Cloud Platform 卷、AWS 弹性块存储卷等。

Kubernetes 可以监视您的服务的健康状况，它可以通过执行指定的`HTTP`方法（例如与`GET`相同）来执行指定的 URL 并分析响应中给出的`HTTP`状态代码来实现。此外，TCP 探测可以检查指定端口是否打开，也可以用于监视服务的健康状况。最后，但同样重要的是，您可以指定可以在容器中执行的命令，以及可以根据命令的响应采取的一些操作。如果指定的探测方法发出信号表明容器出现问题，它可以自动重新启动。当您需要更新软件时，Kubernetes 支持滚动更新。此功能允许您以最小的停机时间更新部署的容器化应用程序。滚动更新功能允许您指定在更新时可能关闭的旧副本的数量。使用 Docker 升级容器化软件特别容易，因为您已经知道，它只是容器的新图像版本。我想现在您已经完全了解了。部署可以更新、部署或回滚。负载平衡、服务发现，所有您在编排和管理运行在 Docker 容器中的微服务群时可能需要的功能都可以在 Kubernetes 中使用。最初由谷歌为大规模而制作，Kubernetes 现在被各种规模的组织广泛使用来在生产环境中运行容器。

# 何时使用微服务架构

微服务架构是一种新的思考应用程序结构的方式。在开始时，当您开始创建一个相对较小的系统时，可能不需要使用微服务方法。当然，基本的 Web 应用程序没有问题。在为办公室的人们制作基本的 Web 应用程序时，采用微服务架构可能有些过度。另一方面，如果您计划开发一个新的、超级互联网服务，将被数百万移动客户端使用，我会考虑从一开始就采用微服务。开玩笑的时候，您明白了，始终要选择最适合工作的工具。最终目标是提供业务价值。

然而，你应该在一段时间后牢记你系统的整体情况。如果你的应用程序在功能和功能上比你预期的要大，或者你从一开始就知道这一点，你可能想要开始将功能拆分成微服务。你应该尝试进行功能分解，并指出系统的片段具有明确的边界，并且在将来需要扩展和单独部署。如果有很多人在一个项目上工作，让他们开发应用程序的独立部分将极大地推动开发过程。每个服务可以使用不同的技术栈，可以用不同的编程语言或框架实现，并且可以在最合适的数据存储中存储自己的数据。这一切都与 API 和服务之间的通信方式有关。拥有这样的架构将导致更快的上市时间，与单体架构相比，构建、测试和部署时间大大缩短。如果只需要扩展需要处理更高工作负载的服务。有了 Docker 和 Kubernetes，没有理由不去使用微服务架构；这将在未来得到回报，毫无疑问。

微服务架构不仅仅是一个新潮的时髦词汇，它通常被认为是今天构建应用程序的更好方式。微服务理念的诞生是由于需要更好地利用计算资源以及需要维护越来越复杂的基于 Web 的应用程序。

在构建微服务时，Java 是一个很好的选择。你可以将微服务创建为一个单独的可执行 JAR，自包含的 Spring Boot 应用程序，或者部署在诸如 Wildfly 或 Tomcat 之类的应用服务器上的功能齐全的 Web 应用程序。根据你的用例和微服务的职责和功能，任何一种方式都可以。Docker 仓库包含许多有用的镜像，你可以自由地将其作为微服务的基础。Docker Hub 中的许多镜像是由私人个人创建的，有些是扩展官方镜像并根据自己的需求进行定制，但其他一些是从基础镜像定制的整个平台配置。基础镜像可以简单到纯 JDK，也可以是一个完全配置好的 Wildfly 准备运行。这将极大地提高开发性能。

# 总结

在这一章中，我们已经比较了单体架构和微服务架构。我希望你能看到使用后者的优势。我们还学习了 Docker 和 Kubernetes 在部署容器化应用程序时如何融入整个画面，使这个过程变得更加简单和愉快。Java 是一个实践证明的生态系统，用于实现微服务。您将要创建的软件将由小型、高度可测试和高效的模块组成。实际上，在第四章 *创建 Java 微服务*中，我们将亲自动手创建这样一个微服务。


# 第四章：创建 Java 微服务

在第三章中，我们已经看到了微服务架构背后的许多理论，*使用微服务*。现在是实践的时候；我们将要实现我们自己的微服务。这将是一个简单的 REST 服务，接受`GET`和`POST`等`HTTP`方法来检索和更新实体。在 Java 中开发微服务时有几种选择。在本章中，我们将概述两种主要方法，可能最流行的将是 JEE7 和 Spring Boot。我们将简要介绍如何使用 JEE JAX-RS 编写微服务。我们还将创建一个在 Spring Boot 上运行的微服务。实际上，在第五章中，*使用 Java 应用程序创建图像*，我们将从 Docker 容器中运行我们的 Spring Boot 微服务。正如我们在第三章中所说，*使用微服务*，微服务通常使用 REST 与外部世界通信。我们的 REST 微服务将尽可能简单；我们只需要有一些东西可以使用 Docker 和 Kubernetes 部署。我们不会专注于高级微服务功能，比如身份验证、安全、过滤器等等，因为这超出了本书的范围。我们的示例的目的是让您了解如何开发 REST 服务，然后使用 Docker 和 Kubernetes 部署它们。本章将涵盖以下主题：

+   REST 简介

+   使用 Java EE7 注解在 Java 中创建 REST 服务

+   使用 Spring Boot 创建 REST 服务

+   运行服务，然后使用不同的 HTTP 客户端调用它

在本章末尾，我们将熟悉一些有用的工具-我们将使用一些代码生成工具，比如 Spring Initialzr，快速启动一个 Spring Boot 服务项目。在我们开始编写自己的微服务之前，让我们简要解释一下 REST 是什么。

# REST 简介

REST 首字母缩略词代表表述性状态转移。这是一种基于网络的软件的架构风格和设计。它描述了一个系统如何与另一个系统通信状态。这非常适合微服务世界。正如您从第三章中所记得的，*使用微服务*，基于微服务架构的软件应用程序是一堆分离的、独立的服务相互通信。

在我们继续之前，有一些 REST 中的概念我们需要了解：

+   `resource`：这是 REST 架构中的主要概念。任何信息都可以是一个资源。银行账户、人员、图像、书籍。资源的表示必须是**无状态**的。

+   `representation`：资源可以被表示的特定方式。例如，银行账户资源可以使用 JSON、XML 或 HTML 来表示。不同的客户端可能请求资源的不同表示，一个可以接受 JSON，而其他人可能期望 XML。

+   `server`：服务提供者。它公开可以被客户端消费的服务。

+   `client`：服务消费者。这可以是另一个微服务、应用程序，或者只是运行 Angular 应用程序的用户的网络浏览器

正如定义所说，REST 被用来在网络上传输这些资源表示。表示本身是通过某种媒体类型创建的。媒体类型可以不同。一些媒体类型的例子包括 JSON、XML 或 RDF。JSON 媒体类型被广泛接受，可能是最常用的。在我们的例子中，我们也将使用 JSON 来与我们的服务进行通信。当然，REST 不是微服务通信的唯一选择；还有其他选择，比如谷歌的非常好的 gRPC，它带来了很多优势，比如 HTTP/2 和 protobuff。在 REST 架构中，资源由组件来操作。事实上，这些组件就是我们的微服务。组件通过标准统一接口请求和操作资源。REST 不绑定到任何特定的协议；然而，REST 调用最常使用最流行的 `HTTP` 或 `HTTPS` 协议。在 `HTTP` 的情况下，这个统一接口由标准的 HTTP 方法组成，比如 `GET`、`PUT`、`POST` 和 `DELETE`。

REST 不绑定到任何特定的协议。

在我们开始实现响应 `HTTP` 调用的服务之前，了解一下我们将要使用的 HTTP 方法是值得的。我们现在将更加关注它们。

# HTTP 方法

基于 REST 的架构使用标准的 HTTP 方法：`PUT`、`GET`、`POST` 和 `DELETE`。以下列表解释了这些操作：

+   `GET` 提供对资源的读取访问。调用 `GET` 不应该产生任何副作用。这意味着 `GET` 操作是幂等的。资源永远不会通过 `GET` 请求而被改变；例如，请求没有副作用。这意味着它是幂等的。

+   `PUT`创建一个新资源。与`GET`类似，它也应该是幂等的。

+   `DELETE`移除资源。当重复调用时，`DELETE`操作不应产生不同的结果。

+   `POST`将更新现有资源或创建新资源。

RESTful web 服务就是基于`REST`资源概念和使用 HTTP 方法的 web 服务。它应该定义暴露方法的基本 URI，支持的 MIME 类型，比如 XML、文本或 JSON，以及服务处理的一组操作（`POST`，`GET`，`PUT`和`DELETE`）。根据 RESTful 原则，HTTP 对 REST 来说是简单且非常自然的。这些原则是一组约束，确保客户端（比如服务消费者、其他服务或浏览器）可以以灵活的方式与服务器通信。现在让我们来看看它们。

在 REST 原则的客户端-服务器通信中，所有以 RESTful 风格构建的应用程序原则上也必须是客户端-服务器的。应该有一个服务器（服务提供者）和一个客户端（服务消费者）。这样可以实现松散耦合和服务器和客户端的独立演进。这非常符合微服务的概念。正如你在第三章中所记得的，*使用微服务*，它们必须是独立的：

+   **无状态**：每个客户端对服务器的请求都要求其状态完全表示。服务器必须能够完全理解客户端的请求，而不使用任何服务器上下文或服务器会话状态。换句话说，所有状态必须在客户端上管理。每个 REST 服务都应该是**无状态**的。后续请求不应该依赖于临时存储在先前请求中的某些数据。消息应该是自描述的。

+   **可缓存**：响应数据可以标记为可缓存或不可缓存。任何标记为可缓存的数据都可以在同一后续请求的响应中被重用。每个响应都应该指示它是否可缓存。

+   **统一接口**：所有组件必须通过单一统一的接口进行交互。因为所有组件的交互都通过这个接口进行，与不同服务的交互非常简单。

+   分层系统：服务的消费者不应假定与服务提供者直接连接。换句话说，客户端在任何时候都无法确定自己是连接到最终服务器还是中间服务器。中间层有助于强制执行安全策略，并通过启用负载平衡来提高系统的可伸缩性。由于请求可以被缓存，客户端可能会从中间层获取缓存的响应。

+   资源通过表示的操作：一个资源可以有多个表示。应该可以通过任何这些表示的消息来修改资源。

+   超媒体作为应用状态的引擎（HATEOAS）：RESTful 应用的消费者应该只知道一个固定的服务 URL。所有后续资源应该可以从资源表示中包含的链接中发现。

前述概念代表了 REST 的定义特征，并将 REST 架构与其他架构（如 Web 服务）区分开来。值得注意的是，REST 服务是 Web 服务，但 Web 服务不一定是 REST 服务。REST 微服务应该代表实体的状态。例如，让我们的实体是一本书（连同其属性，如 ID、标题和作者），表示为 XML、JSON 或纯文本。关于 REST 最基本的思考方式是将服务的 URL 格式化。例如，有了我们的`book`资源，我们可以想象在服务中定义以下操作：

+   `/books`将允许访问所有书籍

+   `/books/:id`将是查看单个书籍的操作，根据其唯一 ID 检索

+   向`/books`发送`POST`请求将是您实际上创建新书并将其存储在数据库中的方式

+   向`/books/:id`发送`PUT`请求将是您如何更新给定书籍的属性，再次根据其唯一 ID 进行标识

+   向`/books/:id`发送`DELETE`请求将是您如何删除特定书籍，再次根据其唯一 ID 进行标识

值得一试的是，REST 不是 HTTP。它通常使用 HTTP，因为在其最一般的形式中，REST 是关于将动词的概念映射到任意的名词集合，并且与 HTTP 方法很好地契合。HTTP 包含一组有用的通用动词（`GET`，`POST`，`PUT`，`PATCH`等）。在 REST 中，我们不传输实际对象，而是以特定形式的表示形式传输，例如 XML、文本或 JSON。作为一种架构风格，REST 只是一个概念。它的实现方式取决于你。Java 非常适合开发 REST 服务。让我们看看我们该如何做。

# Java 中的 REST

在 Java 中开发 REST 服务时，我们至少有几种框架可以选择。最流行的将是纯 JEE7 与 JAX-RS 或 Spring 框架与其 Spring Boot。您可以选择其中任何一个，或者将它们混合在一起。现在让我们更详细地看看这两个，从 JAX-RS 开始。

# Java EE7 - 使用 Jersey 的 JAX-RS

JAX-RS 诞生于**Java 规范请求**（**JSR**）311。正如官方定义所说，JAX-RS 是用于 RESTful web 服务的 Java API。它是一个规范，提供支持，根据 REST 架构模式创建 web 服务。JAX-RS 使用 Java 注解，引入自 Java SE 5，以简化 web 服务客户端和端点的开发和部署。从 1.1 版本开始，JAX-RS 是 Java EE 的官方一部分。作为 Java EE 的官方一部分的一个显著特点是，无需配置即可开始使用 JAX-RS。

Java EE 7 与 JAX-RS 2.0 带来了几个有用的功能，进一步简化了微服务的开发。JAX-RS 2.0 最重要的新功能之一是支持遵循 REST 的 HATEOAS 原则的超媒体。`Jersey`，来自 Oracle 的库，可能是最广为人知的实现了这一规范的库。

Jersey 是 JSR 311 规范的参考实现。

Jersey 实现提供了一个库，用于在 Java servlet 容器中实现 RESTful web 服务。在服务器端，Jersey 提供了一个 servlet 实现，它扫描预定义的类来识别 RESTful 资源。Jersey 使编写 RESTful 服务变得更加容易。它抽象了许多低级别的编码，否则你将需要自己完成。使用 Jersey，你可以以声明性的方式来完成。在`web.xml`文件中注册的 servlet 会分析传入的`HTTP`请求，并选择正确的类和方法来响应此请求。它通过查看类和方法级别的注解来找到要执行的正确方法。注解类可以存在于不同的包中，但是你可以通过`web.xml`指示 Jersey servlet 扫描特定的包以查找注解类。

JAX-RS 支持通过**Java XML 绑定架构**（**JAXB**）创建 XML 和 JSON。Jersey 实现还提供了一个`client`库，用于与 RESTful web 服务进行通信。

正如我们之前所说，我们使用 Java 注解开发 JAX-RS 应用程序。这很容易且愉快。现在让我们来描述这些注解。

# JAX-RS 注解

JAX-RS 中最重要的注解列在下表中：

| - **注解** | **含义** |
| --- | --- |
| - `@PATH` | 设置基本 URL + /your_path 的路径。基本 URL 基于你的应用程序名称、servlet 和`web.xml`配置文件中的 URL 模式。 |
| - `@POST` | 表示以下方法将响应`HTTP POST`请求。 |
| - `@GET` | 表示以下方法将响应`HTTP GET`请求。 |
| - `@PUT` | 表示以下方法将响应`HTTP PUT`请求。 |
| - `@DELETE` | 表示以下方法将响应`HTTP DELETE`请求。 |
| - `@Produces` | 定义了一个带有`@GET`注解的方法要传递的 MIME 类型。例如可以是`"text/plain"`，`"application/xml"`或`"application/json"`。 |
| - `@Consumes` | 定义了这个方法要消耗的 MIME 类型。 |
| - `@PathParam` | 用于从 URL 中提取（注入）值到方法参数中。这样，你可以将资源的 ID 注入到方法中，以获取正确的对象。 |
| - `@QueryParam` | 用于提取（注入）请求中携带的 URI 查询参数。**统一资源标识符**（**URI**）是用于在互联网上标识名称或资源的一串字符。 |
| `@DefaultValue` | 指定默认值。对于可选参数很有用。 |
| `@CookieParam` | 允许您将客户端请求发送的 cookie 注入到 JAX-RS 资源方法中的注释。 |
| `@Provider` | `@Provider`注释用于 JAX-RS 运行时感兴趣的任何内容，例如`MessageBodyReader`和`MessageBodyWriter`。对于`HTTP`请求，`MessageBodyReader`用于将`HTTP`请求实体主体映射到方法参数。在响应端，返回值通过使用`MessageBodyWriter`映射到`HTTP`响应实体主体。如果应用程序需要提供额外的元数据，例如`HTTP`标头或不同的状态代码，方法可以返回一个包装实体的响应，并且可以使用`Response.ResponseBuilder`构建。 |
| `@ApplicationPath` | `@ApplicationPath`注释用于定义应用程序的 URL 映射。`@ApplicationPath`指定的路径是`resource`类中`@Path`注释指定的所有资源 URI 的基本 URI。您只能将`@ApplicationPath`应用于`javax.ws.rs.core.Application`的子类。 |

注释名称一开始可能不够清晰或不够自解释。让我们看一下示例 REST 端点实现，它将变得更加清晰。应用程序本身带有`@ApplicationPath`注释。默认情况下，在启动符合 JEE 的服务器时，JAX-RS 将扫描 Java 应用程序存档中的所有资源，以查找公开的端点。我们可以重写`getClasses()`方法，手动向 JAX-RS 运行时注册应用程序中的`resource`类。您可以在以下示例中看到它：

```
package pl.finsys.jaxrs_example 
@ApplicationPath("/myApp") 
public class MyApplication extends Application { 
   @Override 
   public Set<Class<?>> getClasses() { 
      final Set<Class<?>> classes = new HashSet<>(); 
      classes.add(MyBeansExposure.class); 
      return classes; 
   } 
} 
```

在前面的示例中，我们只是注册了一个 REST 应用程序，给它了`/myApp`基本 URI 路径。只有一个`REST`方法处理程序（端点），即`MyBeansExposure`类，我们在 REST 应用程序中注册它。在单独的 Java 类中实现的简化 REST 端点可以看起来与此相同：

```
package pl.finsys.jaxrs_example 
import javax.annotation.PostConstruct; 
import javax.enterprise.context.ApplicationScoped; 
import javax.ws.rs.DELETE; 
import javax.ws.rs.GET; 
import javax.ws.rs.POST; 
import javax.ws.rs.Path; 
import javax.ws.rs.PathParam; 
import javax.ws.rs.container.ResourceContext; 
import javax.ws.rs.core.Context; 
import javax.ws.rs.core.Response; 

@ApplicationScoped 
@Path("beans") 
public class MyBeansExposure { 
    @Context ResourceContext rc; 
    private Map<String, Bean> myBeans; 

    @GET 
    @Produces("application/json") 
    public Collection<Bean> allBeans() { 
        return Response.status(200).entity(myBeans.values()).build(); 
    } 

    @GET 
    @Produces("application/json") 
    @Path("{id}") 
    public Bean singleBean(@PathParam("id") String id) { 
        return Response.status(200).entity(myBeans.get(id)).build(); 
    } 

    @POST 
    @Consumes("application/json") 
    public Response add(Bean bean) { 
        if (bean != null) { 
            myBeans.put(bean.getName(), bean); 
        } 
        final URI id = URI.create(bean.getName()); 
        return Response.created(id).build(); 
    } 

    @DELETE 
    @Path("{id}") 
    public void remove(@PathParam("id") String id) { 
        myBeans.remove(id); 
    } 

} 
```

正如你在上一个例子中所看到的，我们有类级别的`@Path`注解。每个标记有`@GET`，`@PUT`，`@DELETE`或`@POST`注解的方法都将响应于以基本`@Path`开头的 URI 的调用。此外，我们可以在方法级别上使用`@Path`注解；它将扩展特定方法响应的 URI 路径。在我们的例子中，使用 URI 路径`myApp/beans`执行的`HTTP GET`将调用`allBeans()`方法，以 JSON 格式返回豆子集合。使用`myApp/beans/12` URI 路径执行的`GET`方法将调用`singleBean()`方法，并且由于`@PathParam`注解，`{id}`参数将被传递给方法。在`myApp|beans|12` URI 上调用`HTTP DELETE`方法将执行`remove()`方法，参数值为`12`。为了给你几乎无限的灵活性，`@Path`注解支持正则表达式。考虑以下例子：

```
package pl.finsys.jaxrs_example 
import javax.ws.rs.GET; 
import javax.ws.rs.Path; 
import javax.ws.rs.PathParam; 
import javax.ws.rs.core.Response; 

@Stateless 
@Path("/books") 
public class BookResource { 

   @GET 
   @Path("{title : [a-zA-Z][a-zA-Z_0-9]}") 
    public Response getBookByTitle(@PathParam("title") String title) { 
      return Response.status(200).entity("getBookByTitle is called, title : " + title).build(); 
   } 

   @GET 
   @Path("{isbn : \\d+}") 
   public Response getBookByISBN(@PathParam("isbn") String isbn) { 
      return Response.status(200).entity("getBookByISBN is called, isbn : " + isbn).build(); 
   } 
} 
```

在上一个例子中，我们有两个`@GET`映射，每个映射都有相同的`/books/`路径映射。第一个映射，带有`/{title : [a-zA-Z][a-zA-Z_0-9]}`参数，只会对字母和数字做出反应。第二个映射，带有`/{isbn : \\d+}`参数，只有在调用 URI 时提供数字时才会执行。正如你所看到的，我们映射了两个相同的路径，但每个路径都会对不同类型的传入路径参数做出反应。

除了使用`@PathParam`，我们还可以使用`@QueryParams`来使用请求参数提供参数。看看下面的例子：

```
package pl.finsys.jaxrs_example 
import java.util.List; 
import javax.ws.rs.GET; 
import javax.ws.rs.Path; 
import javax.ws.rs.core.Context; 
import javax.ws.rs.core.Response; 
import javax.ws.rs.core.UriInfo; 

@Stateless 
@Path("/users") 
public class UserResource { 
   @EJB private UserService userService; 
   @GET 
   @Path("/query") 
   @Produces("application/json") 
   public Response getUsers( 
      @QueryParam("from") int from, 
      @QueryParam("to") int to, 
      @QueryParam("orderBy") List<String> orderBy)) { 
      List<User> users = userService.getUsers(from, to, orderBy); 
      return Response.status(200).entity(users).build(); 
   } 
} 
```

在上一个例子中，当在`/users/query?from=1&to=100&orderBy=name`上调用`HTTP GET`时，JAX-RS 将把 URI 参数传递给`getUsers()`方法参数，并调用注入的`userService`来获取数据（例如，从数据库中）。

要打包 JAX-RS 应用程序，我们当然需要一个 Maven `pom.xml`文件。在其最简单的形式中，它可以看起来与以下内容相同：

```
<?xml version="1.0" encoding="UTF-8"?> 
<project  

         xsi:schemaLocation="http://maven.apache.org/POM/4.0.0 http://maven.apache.org/xsd/maven-4.0.0.xsd"> 
    <modelVersion>4.0.0</modelVersion> 

    <groupId>pl.finsys</groupId> 
    <artifactId>jee7-rest</artifactId> 
    <packaging>war</packaging> 
    <version>1.0-SNAPSHOT</version> 

    <dependencies> 
        <dependency> 
            <groupId>javax</groupId> 
            <artifactId>javaee-api</artifactId> 
            <version>7.0</version> 
            <scope>provided</scope> 
        </dependency> 
    </dependencies> 
    <build> 
        <finalName>jee7-rest</finalName> 
    </build> 

    <properties> 
        <maven.compiler.source>1.8</maven.compiler.source> 
        <maven.compiler.target>1.8</maven.compiler.target> 
        <failOnMissingWebXml>false</failOnMissingWebXml> 
    </properties> 
</project> 

```

创建 JEE7 REST 服务非常简单，不是吗？通过构建项目并将其部署到符合 JEE 标准的应用服务器，我们有一些端点准备好等待通过`HTTP`调用。但还有一种更简单和更快的方法。在微服务时代，我们希望以最小的开销更快地创建单独的组件。这就是 Spring Boot 的用武之地。现在让我们来看看它。

# Spring Boot

Spring 本身是一个非常受欢迎的基于 Java 的框架，用于构建 Web 和企业应用程序。它不仅仅是关注依赖注入的 Spring Core。Spring 框架提供了许多功能，可以让开发人员的生活更轻松，并允许您更快地交付所需的功能。列表很长；这里只是一些例子：

+   Spring data：简化了与关系型和 NoSQL 数据存储的数据访问

+   Spring batch：提供了一个强大的批处理框架

+   Spring security：提供了许多保护应用程序的方式

+   Spring social：支持与 Twitter、Facebook、GitHub 等社交网络站点集成

+   Spring integration：实现了企业集成模式，以便使用轻量级消息传递和声明性适配器与其他企业应用程序集成

但是为什么 Spring 变得如此受欢迎？有几个原因：

+   它采用依赖注入方法，鼓励编写可测试、松耦合的代码

+   很容易包含数据库事务管理功能

+   与其他流行的 Java 框架集成，如 JPA/Hibernate 等

+   它包括一个用于更快地构建 Web 应用程序的最先进的 MVC 框架，将视图与业务逻辑分离。

在 Spring 框架中配置 bean 可以通过多种方式进行，如 XML 定义文件、Java 注解和代码配置。这可能是一个繁琐的过程。此外，我们经常为不同的应用程序做大量样板配置。Spring Boot 应运而生，以解决配置的复杂性。我们可以将 Spring Boot 用于自己的目的，并开发可以直接运行的小型独立服务。它可以是一个单独的可运行的 fat JAR 文件，其中包含运行应用程序所需的所有 Java 依赖项。无需应用服务器或复杂的部署描述符配置。实际上，在幕后，Spring Boot 将为您启动嵌入式服务器。当然，您并不一定要使用嵌入式应用服务器。您始终可以构建一个 WAR 文件，将其部署到自己的 Tomcat 或 Wildfly 上，例如。值得知道的是，即使在运行 Spring Boot 应用程序时大多数事情都会自动发生，它也不是一个代码生成框架。

所有这些是否让你想起了 Docker 容器的简单性和可移植性？当然，但是在应用程序级别。正如我们在第三章 *使用微服务*中讨论的那样，我们正在向着具有更小、独立部署的微服务的架构迈进。这意味着我们需要能够快速上手并运行新组件。使用 Spring Boot 时，我们可以获得很多开箱即用的功能。这些功能以 Maven 构件的形式提供，你只需在 Maven 的`pom.xml`文件中包含它们。

下表显示了 Spring Boot 提供的一些重要起始项目，我们将使用：

| **项目** | **描述** |
| --- | --- |
| `spring-boot-starter` | Spring Boot 应用程序的基本起始项目。提供自动配置和日志记录的支持。 |
| `spring-boot-starter-web` | 用于构建基于 Spring MVC 的 Web 应用程序或 RESTful 应用程序的起始项目。这使用 Tomcat 作为默认的嵌入式 Servlet 容器。 |
| `spring-boot-starter-data-jpa` | 提供对 Spring Data JPA 的支持。默认实现是 Hibernate。 |
| `spring-boot-starter-validation` | 提供对 Java Bean 验证 API 的支持。默认实现是 Hibernate Validator。 |
| `spring-boot-starter-test` | 提供对各种单元测试框架的支持，如 JUnit、Mockito 和 Hamcrest matchers |

还有很多其他项目，可能对你有用。我们不打算使用它们，但让我们看看还有什么其他选择：

| `spring-boot-starter-web-services` | 用于开发基于 XML 的 Web 服务的起始项目 |
| --- | --- |
| `spring-boot-starter-activemq` | 支持使用 ActiveMQ 上的 JMS 进行基于消息的通信 |
| `spring-boot-starter-integration` | 支持 Spring Integration，这是一个提供企业集成模式实现的框架 |
| `spring-boot-starter-jdbc` | 提供对 Spring JDBC 的支持。默认情况下配置了 Tomcat JDBC 连接池。 |
| `spring-boot-starter-hateoas` | HATEOAS 代表超媒体作为应用状态的引擎。使用`HATEOAS`的 RESTful 服务返回与当前上下文相关的附加资源的链接，以及数据。 |
| `spring-boot-starter-jersey` | JAX-RS 是开发 REST API 的 Java EE 标准。Jersey 是默认实现。这个起始项目提供了构建基于 JAX-RS 的 REST API 的支持。 |
| `spring-boot-starter-websocket` | `HTTP`是无状态的。Web 套接字允许在服务器和浏览器之间保持连接。这个启动器项目提供了对 Spring WebSockets 的支持。 |
| `spring-boot-starter-aop` | 提供面向切面编程的支持。还提供了对高级面向切面编程的 AspectJ 的支持。 |
| `spring-boot-starter-amqp` | 默认为`RabbitMQ`，这个启动器项目提供了使用 AMQP 进行消息传递的支持。 |
| `spring-boot-starter-security` | 这个启动器项目启用了 Spring Security 的自动配置。 |
| `spring-boot-starter-batch` | 提供使用 Spring Batch 开发批处理应用程序的支持。 |
| `spring-boot-starter-cache` | 使用 Spring Framework 基本支持缓存。 |
| `spring-boot-starter-data-rest` | 支持使用 Spring Data REST 公开 REST 服务。 |

让我们使用一些这些好东西来编写我们自己的 Spring Boot 微服务。

# 编写 Spring Boot 微服务

我们知道我们有一些启动器可用，所以让我们利用它们来节省一些时间。我们要创建的服务将是用于从数据库中存储和检索实体的简单 REST 微服务：在我们的案例中是书籍。我们不打算实现身份验证和安全功能，只是尽可能地使它简洁和简单。书籍将存储在内存关系型 H2 数据库中。我们将使用 Maven 构建和运行我们的书店，所以让我们从`pom.xml`构建文件开始。

# Maven 构建文件

正如你所看到的，我们自己服务的父项目是 spring-boot-starter-parent。Spring 这是为基于 Spring Boot 的应用程序提供依赖和插件管理的父项目。这为我们提供了很多功能。我们还包括两个启动器：

+   `spring-boot-starter-web`：这是因为我们将创建我们的请求映射（类似于使用 JEE7 JAX-RS 之前使用`@Path`注释的`@GET`或`@POST`映射）

+   `spring-boot-starter-data-jpa`：因为我们将把我们的书保存在内存中的 H2 数据库中

启动器是为不同目的定制的简化的依赖描述符。例如，`spring-boot-starter-web`是用于使用 Spring MVC 构建 Web 和 RESTful 应用程序的启动器。它使用 Tomcat 作为默认的嵌入式容器。我们还包括了 Spring Boot Maven 插件，它允许我们在原地运行应用程序，而无需构建 JAR 或 WAR，或准备 JAR 或 WAR 文件以供将来部署。我们完整的`pom.xml`应该与这个一样：

```
<?xml version="1.0" encoding="UTF-8"?> 
<project   
         xsi:schemaLocation="http://maven.apache.org/POM/4.0.0 http://maven.apache.org/xsd/maven-4.0.0.xsd"> 
    <modelVersion>4.0.0</modelVersion> 

    <groupId>pl.finsys</groupId> 
    <artifactId>rest-example</artifactId> 
    <version>0.1.0</version> 

    <parent> 
        <groupId>org.springframework.boot</groupId> 
        <artifactId>spring-boot-starter-

 parent</artifactId> 
        <version>1.5.2.RELEASE</version> 
    </parent> 

    <dependencies> 
        <dependency> 
            <groupId>org.springframework.boot</groupId> 
            <artifactId>spring-boot-starter-

 web</artifactId> 
        </dependency> 
        <dependency> 
            <groupId>org.springframework.boot</groupId> 
            <artifactId>spring-boot-starter-data-

 jpa</artifactId> 
        </dependency> 
        <dependency> 
            <groupId>org.hibernate</groupId> 
            <artifactId>hibernate-validator</artifactId> 
        </dependency> 
        <dependency> 
            <groupId>org.hsqldb</groupId> 
            <artifactId>hsqldb</artifactId> 
            <scope>runtime</scope> 
        </dependency> 

        <!--test dependencies--> 
        <dependency> 
            <groupId>org.springframework.boot</groupId> 
            <artifactId>spring-boot-starter-test</artifactId> 
            <scope>test</scope> 
        </dependency> 
        <dependency> 
            <groupId>com.jayway.jsonpath</groupId> 
            <artifactId>json-path</artifactId> 
            <scope>test</scope> 
        </dependency> 
    </dependencies> 

    <properties> 
        <java.version>1.8</java.version> 
    </properties> 

    <build> 
        <plugins> 
            <plugin> 
                <groupId>org.springframework.boot</groupId> 
                <artifactId>spring-boot-maven-plugin</artifactId> 
            </plugin> 
        </plugins> 
    </build> 

    <repositories> 
        <repository> 
            <id>spring-releases</id> 
            <url>https://repo.spring.io/libs-release</url> 
        </repository> 
    </repositories> 
    <pluginRepositories> 
        <pluginRepository> 
            <id>spring-releases</id> 
            <url>https://repo.spring.io/libs-release</url> 
        </pluginRepository> 
    </pluginRepositories> 
</project> 

```

首先，在`pom.xml`文件中，我们定义了父 Maven artifact。由于我们的应用是 Spring Boot 应用程序，我们从`spring-boot-starter-parent` artifact 继承我们的`pom.xml`。这为我们提供了所有 Spring Boot 的好处，例如启动机制，依赖注入等。通过将`spring-boot-starter-data-jpa`作为依赖项添加，我们将能够使用所有与数据库相关的功能，例如 JDBC 事务管理，用于实体类的 JPA 注解等。有了准备好的`pom.xml`，让我们继续定义微服务的入口点。

# 应用程序入口点

我们的应用程序入口点将被命名为`BookStoreApplication`，并且将是`BookstoreApplication.java`：

```
package pl.finsys.example; 

import org.springframework.boot.SpringApplication; 
import org.springframework.boot.autoconfigure.SpringBootApplication; 

@SpringBootApplication 
public class BookstoreApplication { 

    public static void main(final String[] args) { 
        SpringApplication.run(BookstoreApplication.class, args); 
    } 
} 
```

就是这样。整个代码只有九行，不包括空行。它不能再简洁了。`@SpringBootApplication`是一种快捷注解，非常方便。它替代了以下所有注解：

+   `@Configuration`：标有此注解的类成为应用程序上下文的 bean 定义源

+   `@EnableAutoConfiguration`：此注解使 Spring Boot 根据类路径设置、其他 bean 和各种属性设置添加 bean

+   `@EnableWebMvc`：通常你会为 Spring MVC 应用程序添加`这个`，但是当 Spring Boot 在类路径上看到`spring-webmvc`时，它会自动添加它。这标志着应用程序是一个 Web 应用程序，从而激活关键行为，如设置`DispatcherServlet`。

+   `@ComponentScan`：告诉 Spring 查找其他组件、配置和服务，使其能够找到控制器

到目前为止一切顺利。我们需要一些模型来为我们的服务。我们将在数据库中保存一些实体；这就是`spring-boot-starter-data-jpa`启动器派上用场的地方。我们将能够使用 JPA（使用 Hibernate 实现）和`javax.transaction-api`，甚至无需明确声明它。我们需要一个书店的实体模型。

# 领域模型和仓库

我们服务中的领域模型将是一个`Book`类，在`Book.java`文件中定义：

```
package pl.finsys.example.domain; 

import javax.persistence.Column; 
import javax.persistence.Entity; 
import javax.persistence.Id; 
import javax.validation.constraints.NotNull; 
import javax.validation.constraints.Size; 

@Entity 
public class Book { 

    @Id 
    @NotNull 
    @Column(name = "id", nullable = false, updatable = false) 
    private Long id; 

    @NotNull 
    @Size(max = 64) 
    @Column(name = "author", nullable = false) 
    private String author; 

    @NotNull 
    @Size(max = 64) 
    @Column(name = "title", nullable = false) 
    private String title; 

    public Book() { 
    } 

    public Book(final Long id, final String author, final String title) { 
        this.id = id; 
        this.title = title; 
        this.author = author; 
    } 

    public Long getId() { 
        return id; 
    } 

    public String getAuthor() { 
        return author; 
    } 

    public String getTitle() { 
        return title; 
    } 

    public void setTitle(String title) { 
        this.title = title; 
    } 

    @Override 
    public String toString() { 
        return "Book{" + 
                "id=" + id + 
                ", author='" + author + '\'' + 
                ", title='" + title + '\'' + 
                '}'; 
    } 
} 
```

正如您在前面的清单中所看到的，`Book`类是一个简单的 POJO，带有一些注解、属性和 getter 和 setter。`@Entity`注解来自`javax.persistence`包，并将 POJO 标记为数据库实体，以便 JPA 可以从 H2 数据库中存储或检索它。`@Column`注解指定了数据库列的名称，对应的书籍属性将被存储在其中。`@NotNull`和`@Size`注解将确保我们的实体在进入数据库之前填入了适当的值。

我们已经定义了我们的实体；现在是时候有一个机制来读取和存储它在数据库中。我们将使用 Spring 的`JpaRepository`来实现这个目的。我们的仓库的名称将在`BookRepository.java`文件中为`BookRepository`：

```
package pl.finsys.example.repository; 

import pl.finsys.example.domain.Book; 
import org.springframework.data.jpa.repository.JpaRepository; 

public interface BookRepository extends JpaRepository<Book, Long> { 
} 
```

Spring Data JPA 提供了一个仓库编程模型，它从每个受管领域对象的接口开始。定义这个接口有两个目的。首先，通过扩展`JPARepository`接口，我们可以在我们的类型中获得一堆通用的 CRUD 方法，允许保存我们的实体，删除它们等等。例如，以下方法是可用的（声明在我们正在扩展的`JPARepository`接口中）：

+   `List<T> findAll();`

+   `List<T> findAll(Sort sort);`

+   `List<T> findAll(Iterable<ID> ids);`

+   `<S extends T> List<S> save(Iterable<S> entities);`

+   `T getOne(ID id);`

+   `<S extends T> S save(S entity);`

+   `<S extends T> Iterable<S> save(Iterable<S> entities);`

+   `T findOne(ID id);`

+   `boolean exists(ID id);`

+   `Iterable<T> findAll();`

+   `Iterable<T> findAll(Iterable<ID> ids);`

+   `long count();`

+   `void delete(ID id);`

+   `void delete(T entity);`

+   `void delete(Iterable<? extends T> entities);`

+   `void deleteAll();`

没有 SQL 编码，没有 JPA-QL 查询，什么都没有。只需扩展 Spring 的`JPARepository`接口，所有这些方法都可以随时使用。当然，我们不局限于这些。我们可以在我们的接口中声明自己的方法，比如`findByTitle(String title)`。它将在运行时被 Spring 捕获，并通过标题找到一本书。我强烈建议阅读 Spring Data 项目文档并进一步实验；它非常方便使用。直接从控制器使用`entity`存储库通常不是很好的做法，所以现在是时候有一个书籍服务了。它将是一个`BookService`接口，在`BookService.java`中定义：

```
package pl.finsys.example.service; 

import pl.finsys.example.domain.Book; 
import javax.validation.Valid; 
import javax.validation.constraints.NotNull; 
import java.util.List; 

public interface BookService { 
    Book saveBook(@NotNull @Valid final Book book); 
    List<Book> getList(); 
    Book getBook(Long bookId); 
    void deleteBook(final Long bookId); 
} 
```

实现，在`BookServiceImpl.java`中可以看起来与以下内容相同：

```
package pl.finsys.example.service; 

import org.springframework.beans.factory.annotation.Autowired; 
import pl.finsys.example.domain.Book; 
import pl.finsys.example.repository.BookRepository; 
import pl.finsys.example.service.exception.BookAlreadyExistsException; 
import org.slf4j.Logger; 
import org.slf4j.LoggerFactory; 
import org.springframework.stereotype.Service; 
import org.springframework.transaction.annotation.Transactional; 
import org.springframework.validation.annotation.Validated; 

import javax.validation.Valid; 
import javax.validation.constraints.NotNull; 
import java.util.List; 

@Service 
@Validated 
public class BookServiceImpl implements BookService { 

    private static final Logger LOGGER = LoggerFactory.getLogger(BookServiceImpl.class); 
    private final BookRepository repository; 

    @Autowired 
    public BookServiceImpl(final BookRepository repository) { 
        this.repository = repository; 
    } 

    @Override 
    @Transactional 
    public Book saveBook(@NotNull @Valid final Book book) { 
        LOGGER.debug("Creating {}", book); 
        Book existing = repository.findOne(book.getId()); 
        if (existing != null) { 
            throw new BookAlreadyExistsException( 
                    String.format("There already exists a book with id=%s", book.getId())); 
        } 
        return repository.save(book); 
    } 

    @Override 
    @Transactional(readOnly = true) 
    public List<Book> getList() { 
        LOGGER.debug("Retrieving the list of all users"); 
        return repository.findAll(); 
    } 

    @Override 
    public Book getBook(Long bookId) { 
        return repository.findOne(bookId); 
    } 

    @Override 
    @Transactional 
    public void deleteBook(final Long bookId) { 
        LOGGER.debug("deleting {}", bookId); 
        repository.delete(bookId); 
    } 

} 
```

前面的清单介绍了`BookService`的实现。请注意，我们已经在构造函数中注入了`BookRepository`。所有实现方法，如`saveBook()`，`getBook()`，`deleteBook()`和`getList()`都将使用注入的`BookRepository`来操作数据库中的书籍实体。现在是最后一个类的时候，实际的控制器将把所有前面的类连接在一起。

# REST 控制器

REST 控制器定义了服务将要响应的 URI 路径。它声明了路径和相应的`HTTP`方法，每个控制器方法都应该对其做出反应。我们使用注解来定义所有这些。这种方法与 Jersey 的 JAX-RS 非常相似。我们的服务只有一个`book`资源，所以我们首先只会有一个控制器。它将是`BookController`类，在`BookController.java`中定义：

```
package pl.finsys.example.controller; 

import org.springframework.beans.factory.annotation.Autowired; 
import pl.finsys.example.domain.Book; 
import pl.finsys.example.service.BookService; 
import pl.finsys.example.service.exception.BookAlreadyExistsException; 
import org.slf4j.Logger; 
import org.slf4j.LoggerFactory; 
import org.springframework.http.HttpStatus; 
import org.springframework.web.bind.annotation.*; 

import javax.validation.Valid; 
import java.util.List; 

@RestController 
public class BookController { 

   private static final Logger LOGGER =     LoggerFactory.getLogger(BookController.class); 
private final BookService bookService; 

    @Autowired 
    public BookController(final BookService bookService) { 
        this.bookService = bookService; 
    } 

@RequestMapping(value = "/books", method = RequestMethod.POST, consumes={"application/json"}) 
    public Book saveBook(@RequestBody @Valid final Book book) { 
        LOGGER.debug("Received request to create the {}", book); 
        return bookService.saveBook(book); 
    } 

@RequestMapping(value = "/books", method = RequestMethod.GET, produces={"application/json"}) 
    public List<Book> listBooks() {             
        LOGGER.debug("Received request to list all books"); 
        return bookService.getList(); 
    } 

@RequestMapping(value = "/books/{id}", method = RequestMethod.GET, produces={"application/json"}) 
    public Book singleBook(@PathVariable Long id) { 
        LOGGER.debug("Received request to list a specific book"); 
        return bookService.getBook(id); 
    } 

@RequestMapping(value = "/books/{id}", method = RequestMethod.DELETE) 
    public void deleteBook(@PathVariable Long id) { 
        LOGGER.debug("Received request to delete a specific book"); 
        bookService.deleteBook(id); 
    } 
    @ExceptionHandler 
    @ResponseStatus(HttpStatus.CONFLICT) 
   public String handleUserAlreadyExistsException(BookAlreadyExistsException e) { 
        return e.getMessage(); 
    } 
} 
```

正如您在前面的示例中所看到的，该类使用`@RestController`注解进行了标注。这实际上是使其成为控制器的原因。事实上，这是一个方便的注解，它本身带有`@Controller`和`@ResponseBody`注解。`@Controller`表示一个被注解的类是一个控制器（Web 控制器），还允许通过 Spring 的类路径扫描自动检测实现类。控制器中应该对特定 URI 的调用做出响应的每个方法都使用`@RequestMapping`注解进行映射。`@RequestMapping`接受参数，其中最重要的是：

+   `value`：它将指定 URI 路径

+   `method`：指定要处理的`HTTP`方法

+   `headers`：映射请求的标头，格式为`myHeader=myValue`。只有当传入请求标头被发现具有给定值时，请求才会使用标头参数来处理该方法

+   `consumes`：指定映射请求可以消耗的媒体类型，例如`"text/plain"`或`"application/json"`。这也可以是媒体类型的列表，例如：`{"text/plain", "application/json"}`

+   `produces`：指定映射请求可以生成的媒体类型，例如`"text/plain"`或`"application/json"`。这也可以是媒体类型的列表，例如：`{"text/plain", "application/json"}`

`类似于 JAX-RS` `@PathParam`和`@QueryParam`用于指定控制器方法的输入参数，现在在 Spring 中我们有`@PathVariable`和`@RequestParam`。如果您需要使方法参数出现在请求体中（作为您想要保存的整个 JSON 对象，与我们的`saveBook()`方法中一样），则需要使用`@RequestBody`注释来映射参数。至于输出，`@ResponseBody`注释可以告诉我们的控制器，方法返回值应绑定到 Web 响应主体。

在现实世界的服务中，您可能会有很多具有许多映射路径的控制器。将这样的服务暴露给世界时，通常最好记录服务的 API。这个 API 文档就是服务合同。手动执行此操作可能会很繁琐。而且，如果您进行更改，最好将 API 文档同步。有一个工具可以使这变得更容易，Swagger。

# 记录 API

在客户端可以使用服务之前，它需要一个服务合同。服务合同定义了有关服务的所有细节；例如，服务如何被调用，服务的 URI 是什么，请求和响应格式是什么。您的客户端需要知道如何与您的 API 进行交互。在过去几年中，Swagger 得到了许多主要供应商的支持。Swagger 的规范以 JSON 格式呈现了服务资源和操作的所有细节。规范的格式被称为 OpenAPI 规范（Swagger RESTful API 文档规范）。它既可以被人类阅读，也可以被机器阅读，易于解析、传输和在集成中使用。`SpringFox`库可用于从 RESTful 服务代码生成 Swagger 文档。而且，还有一个名为 Swagger UI 的精彩工具，当集成到应用程序中时，提供人类可读的文档。在本节中，我们将为我们的服务生成 Swagger 文档。`SpringFox`库可在 GitHub 上找到[`springfox.github.io/springfox/`](http://springfox.github.io/springfox/)，并且在 Maven 中央库中也可以找到，它是一个用于自动构建 Spring 构建的 API 的 JSON API 文档的工具。更好的是，该库提供了 Swagger UI 工具。该工具将与您的服务一起部署，并且可以以非常便捷的方式浏览生成的 API 文档。让我们向我们的服务介绍 Swagger。我们首先要向我们的服务的`pom.xml`文件添加所需的依赖项：

```
<dependency> 
   <groupId>io.springfox</groupId> 
   <artifactId>springfox-swagger2</artifactId> 
   <version>2.6.1</version> 
</dependency> 

<dependency> 
   <groupId>io.springfox</groupId> 
   <artifactId>springfox-swagger-ui</artifactId> 
   <version>2.5.0</version> 
</dependency> 

```

在我们的应用程序的类路径中有了该库后，我们需要将其打开。接下来的步骤将是添加配置类以启用和生成 Swagger 文档。我们可以通过创建一个使用 Spring `@Configuration`注解的类来实现，就像下面的例子一样：

```
package pl.finsys.example.configuration; 

import org.springframework.context.annotation.Bean; 
import org.springframework.context.annotation.Configuration; 
import springfox.documentation.builders.PathSelectors; 
import springfox.documentation.builders.RequestHandlerSelectors; 
import springfox.documentation.spi.DocumentationType; 
import springfox.documentation.spring.web.plugins.Docket; 
import springfox.documentation.swagger2.annotations.EnableSwagger2; 

@Configuration 
@EnableSwagger2 
public class SwaggerConfig { 
    @Bean 
    public Docket api() { 
        return new Docket(DocumentationType.SWAGGER_2) 
                .select() 
                .apis(RequestHandlerSelectors.any()) 
                .paths(PathSelectors.any()).build(); 
    } 
} 
```

在这里解释一下。`@Configuration`表示被注释的类定义了一个 Spring 配置，`@EnableSwagger2`关闭了 Swagger 支持。`Docket`是一个构建器类，用于配置生成 Swagger 文档，配置为`DocumentationType.SWAGGER_2`以生成兼容 Swagger 2 的 API 文档。在`Docket`实例上调用的`select()`方法返回一个`ApiSelectorBuilder`，它提供了`apis()`和`paths()`方法，用于使用字符串谓词过滤要记录的控制器和方法。在我们的例子中，我们希望记录所有控制器和所有映射的路径；这就是为什么我们使用`.apis(RequestHandlerSelectors.any()).paths(PathSelectors.any())`。

您还可以使用传递给`paths()`的`regex`参数来提供一个额外的过滤器，仅为与正则表达式匹配的路径生成文档。

就是这样；这是为您的 API 生成文档的最简单形式。如果您现在运行服务（我们将在不久的将来这样做），将会有两个端点可用：

+   `http://localhost:8080/v2/api-docs`

+   `http://localhost:8080/swagger-ui.html`

第一个包含了 Swagger 2 兼容的文档，以 JSON 格式呈现，如下截图所示：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-k8s-java-dev/img/Image00061.jpg)

要以更加有用的形式浏览 API 文档，请将浏览器指向第二个 URL。您将看到 Swagger UI 工具界面：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-k8s-java-dev/img/Image00062.jpg)

Swagger UI 是一组 HTML、JavaScript 和 CSS 资源，可以根据符合 Swagger 的 API 动态生成美观的文档。它列出了您的服务操作以及其请求和响应格式。最重要的是，您可以使用此工具测试您的服务，执行特定的请求。实际上，这是一个快速测试您的服务的好工具。我们的文档并不是非常描述性的。当然，我们列出了我们的暴露端点及其输入和输出描述。如果我们能用一些更具体的细节增强文档就更好了。我们可以做到这一点，我们可以在服务的代码中使用 Java 注解来增强生成的文档。这些注解来自 Swagger-annotation 包，如果您在项目中使用`springfox-swagger2`库，它将可用。例如，考虑以下代码片段：

```
@ApiOperation(value = "Retrieve a list of books.",

responseContainer = "List")

@RequestMapping(value = "/books", method = RequestMethod.GET, produces = {"application/json"})

public List<Book> listBooks() {

LOGGER.debug("Received request to list all books");

return bookService.getList();

}
```

在前面的代码中，我们使用`@ApiOperation`注解提供了对操作的更详细描述。还有更多：`@ApiImplicitParam`用于描述参数，`@Authorization`提供要在此资源/操作上使用的授权方案的名称，`@License`提供有关许可证的信息，等等。所有这些注解都将被`springfox-swagger2`捕获并用于增强生成的文档。我强烈建议查看 swagger-annotations 的 JavaDoc；你将能够以详细、专业的方式记录你的 API。

我想我们的小服务已经准备好了；是时候让它活起来了。

# 运行应用程序

因为我们已经在`pom.xml`构建文件中定义了 Spring Boot 插件，所以现在可以使用 Maven 启动应用程序。你只需要在系统路径上有 Maven，但作为 Java 开发人员，你可能已经有了。要运行应用程序，请在命令行（MacOS 上的终端或 Windows 上的`cmd.exe`）中执行以下操作：

```
$ mvn spring-boot:run

```

过一会儿，Spring 的启动日志将出现在控制台上，你的微服务将准备好接受`HTTP`请求。很快，在第五章，*使用 Java 应用程序创建图像*，我们的目标将是从 Docker 容器中看到相同的情况：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-k8s-java-dev/img/Image00063.jpg)

如果你愿意，你也可以直接从 IDE（IntelliJ IDEA、Eclipse 或 Netbeans）运行应用程序。我们的`BookstoreApplication`类有一个`main()`方法；你只需要在你的 IDE 中创建一个运行时配置并运行它。这与 JEE7 JAX-RS 服务不同。在那种情况下，你需要将服务部署在一个符合 JEE 标准的应用服务器上才能运行它。当调试服务时，定义`main()`方法非常方便。只需以`BookstoreApplication`为入口点开始调试会话。无需创建远程调试会话。服务运行后，是时候对其公开的端点进行一些调用了。

# 发出调用

调用从服务中公开的操作可以使用任何可以执行`HTTP`请求的工具或库。第一个明显的选择可能只是一个网络浏览器。但是网络浏览器只方便执行`GET`请求（比如从我们的书店服务获取书籍列表）。如果你需要执行其他方法，比如`POST`或`PUT`，或者提供额外的请求参数、头部值等，你将需要使用一些替代方案。第一个选择可能是 cURL，一个用于使用各种协议传输数据的命令行工具。让我们看看我们还有哪些其他选择。

# Spring RestTemplate

如果你需要从另一个服务调用服务，你将需要一个`HTTP`客户端。Spring 提供了非常有用的`RestTemplate`类。它为你提供了同步的客户端端`HTTP`访问，简化了与 HTTP 服务器的通信，并强制执行 RESTful 原则。它处理 HTTP 连接，让应用程序代码提供 URL（可能带有模板变量）并提取结果。默认情况下，`RestTemplate`依赖于标准的 JDK 设施来建立 HTTP 连接。你可以通过其`setRequestFactory()`方法切换到你选择的不同的 HTTP 库，比如 Apache `HttpComponents`，`Netty`和`OkHttp`。调用`REST`资源以获取`ID = 1`的书可以简单地如下所示：

```
package pl.finsys.example.client; 

import org.springframework.http.ResponseEntity; 
import org.springframework.web.client.RestTemplate; 
import pl.finsys.example.domain.Book; 

public class ExampleClient { 
    public static void main(String[] args) { 
        try { 
            RestTemplate restTemplate = new RestTemplate(); 
            ResponseEntity<Book> response = restTemplate.getForEntity("http://localhost:8080/books/1", Book.class); 
            System.out.println(response.getBody()); 
        } catch (Exception e) { 
            e.printStackTrace(); 
        } 
    } 
} 
```

当然，这只是一个简化的客户端示例，来向你展示这个想法。你可以使用`RestTemplate`来创建更复杂的客户端调用 REST 资源。

# HTTPie

HTTPie 是 cURL 的一个很好的命令行替代品，可在[`httpie.org`](https://httpie.org)找到。它是一个命令行`HTTP`客户端。幸运的是，名字中的“ie”并不是来自于 Internet Explorer。如果你喜欢从 shell 或命令行工作，`HTTPie`只是一个单一的命令，它为 cUrl 添加了以下功能：合理的默认设置，表达和直观的命令语法，带颜色和格式的终端输出，内置的 JSON 支持，持久会话，表单和文件上传，代理和认证支持，以及对任意请求数据和头部的支持。它是用 Python 编写的，在 Linux、macOSX 和 Windows 上都可以运行。

# Postman

Postman 是许多开发人员的首选工具。它可以作为 Chrome 插件或独立实用程序在[`www.getpostman.com`](https://www.getpostman.com)上使用。Postman 非常方便使用。它是一个强大的 GUI 平台，可以使您的 API 开发更快速、更容易，从构建 API 请求到测试、文档编制和共享。您可以保存 HTTP 请求以供以后使用，并将它们组织成集合。如果您在多个环境中工作，例如在开发服务时使用本地主机和以后在生产环境中使用，Postman 引入了环境的概念。环境使您能够使用变量自定义您的请求。这样，您可以轻松地在不同的设置之间切换，而不必更改您的请求。每个环境都表示为一组键值对。这使得在多个环境中工作变得容易。它还具有非常方便的 UI 来编辑您的 HTTP 请求：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-k8s-java-dev/img/Image00064.jpg)

您可以定义请求头、cookie 和正文。如果您的服务支持身份验证，Postman 包含许多身份验证助手：它可以是基本身份验证、摘要身份验证和 OAuth。响应正文可以在三个视图中的一个中查看：漂亮、原始和预览。漂亮模式会格式化 JSON 或 XML 响应，使其更容易查看，并且标题会显示为标题选项卡中的键/值对。这是一个非常强大和愉快的工具。如果您在 macOS 上工作，甚至有更好的东西。

# Paw for Mac

Paw 是一个功能齐全的 HTTP 客户端，可以让您测试构建或使用的 API。它具有美丽的原生 OS X 界面，可以组合请求，检查服务器响应，并直接生成客户端代码。正如您在以下截图中所看到的，它还包含一个强大的编辑器来组合您的请求：

**![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-k8s-java-dev/img/Image00065.jpg)**

它还支持许多身份验证模式，包括 OAuth 1 和 2、基本身份验证、摘要身份验证、Hawk、AWS 签名版本 4 和 Amazon S3。与 Postman 类似，Paw 还允许您将请求组织到文件夹中。您还可以快速定义和切换不同的环境。有趣的功能是 Paw 可以生成客户端代码来执行您的请求。它可以为 cURL、HTTPie、Objective-C、Python、JavaScript、Ruby、PHP、Java、Go 等生成代码。猜猜？Paw 还可以导入我们一直在谈论的 Swagger 文档。您可以使用此功能来测试您获得文档的服务。

如果您需要快速启动新服务，有一些工具可能会派上用场。其中之一是**Initializr**。

# Spring Initializr

Spring Initializr 是一个基于 Web 的工具，可在[`start.spring.io`](https://start.spring.io)上使用。这是 Spring 项目的快速启动生成器。Spring Initializr 的使用方法如下：

+   从网页浏览器访问[`start.spring.io`](https://start.spring.io)

+   在您的 IDE（IntelliJ IDEA Ultimate 或 NetBeans，使用插件）

+   从命令行使用 Spring Boot CLI，或者简单地使用 cURL 或 HTTPie

使用 Web 应用程序非常方便；您只需要提供有关您的应用程序 Maven 原型的详细信息，例如组、工件名称、描述等：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-k8s-java-dev/img/Image00066.jpg)

在“依赖项”部分，您可以输入您想要包括的功能的关键字，例如 JPA、web 等。您还可以切换 UI 以查看高级视图，以列出所有功能并准备选择：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-k8s-java-dev/img/Image00067.jpg)

作为输出，Spring Initializr 将创建一个 ZIP 存档，其中包含您想要开始的基本 Maven 项目。Spring Initializr 创建的项目是一个 Maven 项目，并遵循标准的`Maven`目录布局。这在创建新的 Spring 项目时真的节省了很多时间。您不再需要搜索特定的 Maven 原型并寻找它们的版本。Initializr 将自动为您生成`pom.xml`。`pom.xml`中的依赖项的存在很重要，因为当在类路径上发现某些内容时，Spring Boot 将自动决定要自动创建什么。例如，如果 H2 数据库的依赖项存在并且在应用程序运行时存在于类路径上，Spring Boot 将自动创建数据连接和嵌入式 H2 数据库。

# 摘要

正如您所看到的，开发 Java 微服务并不像听起来那么棘手。您可以选择使用 JEE7 JAX-RS 或 Spring Boot，连接一些类，一个基本的服务就准备好了。您并不局限于使用 Spring MVC 来创建您的 REST 端点。如果您更熟悉 Java EE JAX-RS 规范，您可以很容易地将 JAX-RS 集成到 Spring 应用程序中，特别是 Spring Boot 应用程序。然后您可以从两者中选择最适合您的部分。

当然，在现实世界中，您可能希望包括一些更高级的功能，如身份验证和安全性。有了 Spring Initializr，您在开发自己的服务时可以获得严重的速度提升。在第五章中，*使用 Java 应用程序创建图像*，我们将把我们的书店服务打包成一个 Docker 镜像，并使用 Docker Engine 运行它。
