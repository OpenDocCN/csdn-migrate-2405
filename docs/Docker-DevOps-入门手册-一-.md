# Docker DevOps 入门手册（一）

> 原文：[`zh.annas-archive.org/md5/A074DB026A63DFD63D361454222593A5`](https://zh.annas-archive.org/md5/A074DB026A63DFD63D361454222593A5)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 前言

Docker 与 DevOps 概述了容器化的强大力量以及这种创新对开发团队和一般运营的影响。我们还将了解 DevOps 的真正含义，涉及的原则，以及通过实施 Docker 工作流程对产品健康的贡献。Docker 是一个开源的容器化工具，它使得简化产品交付并缩短从业务白板草图到实施的时间变得更加容易。

本书将提供以下知识：

+   Docker 和 DevOps 以及它们为什么以及如何集成

+   容器是什么，以及如何创建和管理它们

+   使用 Docker 扩展交付管道和多个部署

+   容器化应用程序的编排和交付

第 1 课*，图像和容器*，展示了 Docker 如何改进 DevOps 工作流程以及本书中将使用的基本 Docker 终端命令。我们将学习 Dockerfile 语法以构建图像。我们将从图像运行容器。然后我们将对图像和 Docker hub 进行版本控制，并将 Docker 图像部署到 Docker hub。

第 2 课*，应用容器管理*，探讨了 docker-compose 工具，并概述了多容器应用程序设置。然后我们将管理多个容器并分发应用程序包。最后，我们将使用 docker-compose 进行网络管理。

第 3 课*，编排和交付*，为我们概述了 Docker Swarm。然后我们将使用 Docker 引擎创建一个 Swarm 并管理 Swarm 中的服务和应用程序。最后，我们将扩展服务以测试真实世界的应用场景。

# 硬件

本书将需要以下最低硬件要求：

+   处理器：1.8 GHz 或更高（Core 2 Duo 及以上）

+   内存：最低 2GB RAM

+   硬盘：最低 10 GB

+   稳定的互联网连接（用于拉取和推送图像）

# 软件

+   操作系统：Windows 8 或更高版本

+   浏览器：Google Chrome 或 Mozilla Firefox（已安装最新更新）

+   已安装 Docker

# 本书适合谁

本书适合开发人员、系统架构师、初级和中级站点可靠性工程师，他们希望采用 Docker 工作流程来实现应用程序的一致性、速度和隔离。当我们深入研究 Docker 时，您需要对 UNIX 概念（如 ssh、端口和日志）有基本的了解。

# 约定

在本书中，您将找到许多文本样式，用于区分不同类型的信息。以下是一些示例以及它们的含义解释。

文本中的代码单词、数据库表名、文件夹名、文件名、文件扩展名、路径名、虚拟 URL、用户输入和 Twitter 句柄显示如下：“一旦您创建了一个新目录，访问该目录并创建一个名为`run.js`的文件。”

任何命令行输入或输出都以以下方式编写：

```
docker pull
```

**新术语**和**重要单词**以粗体显示。屏幕上看到的单词，例如菜单或对话框中的单词，以这种方式出现在文本中：“单击“下一步”按钮将您移至下一个屏幕。”

### 注意

警告或重要说明以这样的方式出现在框中。

### 提示

提示和技巧看起来像这样。


# 第一章：镜像和容器

本课程将涵盖有关容器化的基本概念，作为我们稍后将构建的镜像和容器的基础。我们还将了解 Docker 如何以及为什么参与到 DevOps 生态系统中。在开始之前，我们将看到虚拟化与 Docker 中的容器化有何不同。

# 课程目标

通过本课程结束时，您将能够：

+   描述 Docker 如何改进 DevOps 工作流程

+   解释 Dockerfile 语法

+   构建镜像

+   设置容器和镜像

+   建立本地动态环境

+   在 Docker 容器中运行应用程序

+   通过 Docker Hub 获取 Docker 管理镜像的基本概述

+   将 Docker 镜像部署到 Docker Hub

# 虚拟化与容器化

这个块图示给出了典型虚拟机设置的概述：

![虚拟化与容器化](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/bg-dop-dkr/img/image01_01a.jpg)

在虚拟机中，物理硬件被抽象化，因此我们可以在一个服务器上运行许多服务器。一个 hypervisor 可以帮助实现这一点。

虚拟机有时需要一些时间来启动，并且在容量上很昂贵（它们可以占用几 GB 的空间），尽管它们相对于容器的最大优势是能够运行不同的 Linux 发行版，如 CentOS 而不仅仅是 Ubuntu：

![虚拟化与容器化](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/bg-dop-dkr/img/image01_02a.jpg)

在容器化中，只有应用程序层（代码和依赖项打包的地方）被抽象化，这使得许多容器可以在相同的 OS 内核上运行，但在单独的用户空间上运行。

容器占用空间少，启动快。这使得开发更容易，因为您可以随时删除和启动容器，而不必考虑服务器或开发人员的工作空间有多大。

让我们从快速概述开始，了解 Docker 如何在 DevOps 工作流程和 Docker 环境中发挥作用。

# Docker 如何改进 DevOps 工作流程

DevOps 是一种思维方式，一种文化，一种思维方式。最终目标是尽可能改进和自动化流程。用通俗的语言说，DevOps 要求人们以最懒惰的观点思考，尽可能将大部分甚至所有的流程自动化。

Docker 是一个改进开发生命周期的船运过程的开源容器化平台。请注意，它既不是已经存在的平台的替代品，也不是组织希望它成为的替代品。

Docker 抽象了像 Puppet 这样的配置管理的复杂性。在这种设置下，shell 脚本变得不再必要。Docker 也可以用于小型或大型部署，从一个 hello world 应用到一个完整的生产服务器。

作为不同级别的开发人员，无论是初学者还是专家，您可能已经使用过 Docker，甚至没有意识到。如果您设置了一个持续集成管道来在线运行您的测试，大多数服务器都使用 Docker 来构建和运行您的测试。

Docker 因其灵活性而在技术社区中获得了很多支持，因此许多组织都在运行容器来提供服务。这些组织包括以下：

+   诸如 Circle CI、Travis CI 和 Codeship 之类的持续集成和持续交付平台

+   云平台，如亚马逊网络服务（AWS）和谷歌云平台（GCP）允许开发人员在容器中运行应用程序

+   思科和阿里巴巴集团也在容器中运行一些服务

Docker 在 DevOps 工作流程中的位置涉及但不限于以下内容：

### 注意

开发工作流程中 Docker 的使用案例示例。

统一要求是指使用单个配置文件。Docker 将要求抽象和限制到一个 Dockerfile 文件。

操作系统的抽象意味着不需要担心构建操作系统，因为存在预构建的镜像。

速度必须定义一个 Dockerfile 并构建容器进行测试，或者使用已构建的镜像而无需编写 Dockerfile。Docker 允许开发团队通过 shell 脚本避免对陡峭的学习曲线的投资，因为“自动化工具 X”太复杂了。

## Docker 环境的回顾

我们之前已经介绍了容器化的基本原理。让我强调一下 Docker 为我们带来的替代工作流程。

通常，一个工作应用程序有两个部分：项目代码库和配置脚本。代码库是应用程序代码。它由版本控制管理，并托管在 GitHub 等平台上。

配置脚本可以是一个简单的 shell 脚本，在主机上运行，可以是从 Windows 工作站到云中的完全专用服务器。

使用 Docker 不会干扰项目代码库，但会在配置方面进行创新，改进工作流程和交付速度。这是 Docker 如何实现这一点的一个示例设置：

![Docker 环境的回顾](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/bg-dop-dkr/img/image01_03a.jpg)

**Dockerfile** 取代了配置脚本的位置。这两者结合在一起（项目代码和 Dockerfile）形成了一个 **Docker 镜像**。Docker 镜像可以作为一个应用程序运行。从 Docker 镜像中运行的这个应用程序被称为 **Docker 容器**。

Docker 容器允许我们在我们的计算机上以全新的环境运行应用程序，这是完全可丢弃的。这意味着什么？

这意味着我们能够在我们的计算机上声明和运行 Linux 或任何其他操作系统，然后在其中运行我们的应用程序。这也强调了我们可以构建和运行容器，而不会干扰我们计算机的配置。

通过这些，我向您介绍了四个关键词：**image**，**container**，**build** 和 **run**。接下来我们将深入了解 Docker CLI。

# 基本的 Docker 终端命令

打开命令提示符，检查 Docker 是否安装在您的工作站上。在终端上输入 `docker` 命令应该显示以下内容：

![基本的 Docker 终端命令](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/bg-dop-dkr/img/image01_04a.jpg)

这是 Docker 可用子命令的列表。要了解每个子命令的作用，请在终端上输入 `docker-subcommand –help`：

![基本的 Docker 终端命令](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/bg-dop-dkr/img/image01_05a.jpg)

运行 `docker info` 并注意以下内容：

+   容器

+   镜像

+   服务器版本

![基本的 Docker 终端命令](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/bg-dop-dkr/img/image01_06a.jpg)

这个命令显示系统范围的信息。服务器版本号有时很重要，特别是当新版本引入了与旧版本不兼容的东西时。Docker 为他们的社区版提供了稳定版和边缘版。

现在我们将看一下一些常用的命令。

这个命令在 **Docker Hub** 中搜索镜像：

```
docker search <term> (for example, docker search ubuntu)
```

Docker Hub 是默认的 Docker 注册表。Docker 注册表保存了命名的 Docker 镜像。Docker Hub 基本上就是 "Docker 镜像的 GitHub"。之前，我们看过如何运行 Ubuntu 容器而不构建一个；这就是 Ubuntu 镜像存储和版本控制的地方：

![基本的 Docker 终端命令](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/bg-dop-dkr/img/image01_07a.jpg)

“有私有的 Docker 注册表，现在你意识到这一点很重要。” Docker Hub 在[hub.docker.com](http://hub.docker.com)。一些镜像托管在[store.docker.com](http://store.docker.com)，但 Docker Store 包含官方镜像。然而，它主要关注 Docker 镜像的商业方面，并为使用提供工作流程。

注册页面如下所示：

![基本 Docker 终端命令](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/bg-dop-dkr/img/image01_08a.jpg)

登录页面如下所示：

![基本 Docker 终端命令](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/bg-dop-dkr/img/image01_09a.jpg)

从结果中，你可以看出用户通过星号的数量对镜像进行了评价。你还可以知道这个镜像是否是官方的。这意味着这个镜像是由注册表推广的，在这种情况下是 Docker Hub。建议新的 Docker 用户使用官方镜像，因为它们有很好的文档，安全，促进最佳实践，并且设计用于大多数用例。一旦你选定了一个镜像，你需要在本地拥有它。

### 注意

确保你能够从 Docker Hub 搜索至少一个镜像。镜像种类从操作系统到库都有，比如 Ubuntu，Node.js 和 Apache。

这个命令允许你从 Docker Hub 搜索：

```
docker search <term>

```

例如，`docker search ubuntu`。

这个命令从注册表中拉取一个镜像到你的本地机器：

```
docker pull

```

例如，`docker pull ubuntu`。

一旦这个命令运行，你会注意到它正在使用默认标签：`latest`。在 Docker Hub 中，你可以看到标签的列表。对于**Ubuntu**，它们在这里列出：[`hub.docker.com/r/library/ubuntu/`](https://hub.docker.com/r/library/ubuntu/) 以及它们各自的 Dockerfiles：

![基本 Docker 终端命令](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/bg-dop-dkr/img/image01_010a.jpg)

从 Docker Hub 上下载 Ubuntu 镜像配置文件：[`hub.docker.com/r/library/ubuntu/`](https://hub.docker.com/r/library/ubuntu/)。

## 活动 1 —— 使用 docker pull 命令

让你熟悉`docker pull`命令。

这个活动的目标是通过运行列出的命令，以及在探索中寻求其他命令的帮助，通过操作构建的容器来对`docker-pull` CLI 有一个牢固的理解。

1.  Docker 是否正在运行？在终端或命令行应用程序上输入`docker`。

1.  这个命令用于从 Docker Hub 拉取镜像。

```
docker pull

```

图像的种类范围从操作系统到库，例如 Ubuntu、Node.js 和 Apache。此命令允许您从 Docker Hub 中拉取图像：

例如，`docker pull ubuntu`。

此命令列出我们在本地拥有的 Docker 图像：

+   `docker images`

当我们运行命令时，如果我们从 Docker Hub 拉取了图像，我们将能够看到图像列表：

![Activity 1 — Utilizing the docker pull Command](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/bg-dop-dkr/img/image01_11a.jpg)

它们根据存储库、标签、图像 ID、创建日期和大小进行列出。存储库只是图像名称，除非它是从不同的注册表中获取的。在这种情况下，您将获得一个没有`http://`和**顶级域（TLD）**的 URL，例如从 Heroku 注册表中的`>registry.heroku.com/<image-name>`。

此命令将检查名为`hello-world`的图像是否在本地存在：

```
docker run <image>

```

例如，`docker run hello-world`：

![Activity 1 — Utilizing the docker pull Command](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/bg-dop-dkr/img/image01_12a.jpg)

如果图像不是本地的，它将从默认注册表 Docker Hub 中拉取并默认情况下作为容器运行。

此命令列出正在运行的容器：

```
docker ps
```

如果没有运行的容器，您应该看到一个带有标题的空屏幕：

![Activity 1 — Utilizing the docker pull Command](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/bg-dop-dkr/img/image01_13a.jpg)

## Activity 2 — Analyzing the Docker CLI

通过在终端上键入`docker`来确保 Docker CLI 正在运行。

您被要求演示到目前为止涵盖的命令。

让您熟悉 Docker CLI。此活动的目标是通过运行列出的命令以及在探索过程中寻求其他命令的帮助来对`docker-compose` CLI 有牢固的理解，目标不仅是操作构建的容器，而且还要灵活使用 CLI，以便在运行自动化脚本等实际场景中使用它。

1.  Docker 是否正在运行？在终端或命令行应用程序上键入`docker`。

1.  使用 CLI 搜索官方 Apache 图像，使用`docker search apache:`![Activity 2 — Analyzing the Docker CLI](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/bg-dop-dkr/img/image01_14a.jpg)

1.  尝试使用`docker pull apache`拉取图像。

1.  使用`docker images`确认图像在本地的可用性。

1.  奖励：使用`docker run apache`将图像作为容器运行。

1.  奖励：使用`docker stop <container ID>`停止容器。

1.  奖励：使用`docker rm <container ID>`删除容器和图像。

# Dockerfile 语法

每个 Docker 镜像都始于一个**Dockerfile**。要创建一个应用程序或脚本的镜像，只需创建一个名为**Dockerfile**的文件。

### 注意

它没有扩展名，并以大写字母 D 开头。

Dockerfile 是一个简单的文本文档，其中写有模板容器的所有命令。Dockerfile 始终以基础镜像开头。它包含创建应用程序或运行所需脚本的步骤。

在构建之前，让我们快速看一下编写 Dockerfile 的一些最佳实践。

一些最佳实践包括但不限于以下内容：

+   **关注分离**：确保每个 Dockerfile 尽可能地专注于一个目标。这将使其在多个应用程序中更容易重用。

+   **避免不必要的安装**：这将减少复杂性，使镜像和容器足够紧凑。

+   **重用已构建的镜像**：Docker Hub 上有几个构建和版本化的镜像；因此，与其实现一个已经存在的镜像，最好是通过导入来重用。

+   **具有有限数量的层**：最小数量的层将允许一个紧凑或更小的构建。内存是构建镜像和容器时需要考虑的关键因素，因为这也会影响镜像的消费者或客户端。

我们将简单地从 Python 和 JavaScript 脚本开始。选择这些语言是基于它们的流行度和易于演示。

## 为 Python 和 JavaScript 示例编写 Dockerfile。

### 注意

对所选语言没有先验经验，因为它们旨在展示任何语言如何采用容器化的动态视图。

### Python

在开始之前，创建一个新的目录或文件夹；让我们将其用作我们的工作空间。

打开目录并运行`docker search python`。我们将选择官方镜像：`python`。官方镜像在**官方**列中具有值**[OK]**：

![Python](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/bg-dop-dkr/img/image01_15a.jpg)

前往[hub.docker.com](http://hub.docker.com)或[store.docker.com](http://store.docker.com)搜索 python 以获取正确的标签，或者至少知道带有最新标签的 Python 镜像的版本。我们将在*主题 D*中更多地讨论标签。

镜像标签应该是一个看起来像`3.x.x`或`3.x.x-rc.`的数字。

创建一个名为`run.py`的文件，并输入第一行如下：

```
print("Hello Docker - PY")
```

在同一文件夹级别上创建一个新文件，并将其命名为**Dockerfile**。

### 注意

我们没有 Dockerfile 的扩展名。

在**Dockerfile**中添加以下内容：

```
FROM python
ADD . .
RUN ls
CMD python run.py
```

**FROM**命令，正如前面所提到的，指定了基本图像。

该命令也可以从**继承**的角度来使用。这意味着如果已经存在一个包含这些包的图像，您不必在 Dockerfile 中包含额外的包安装。

**ADD**命令将指定的文件从源复制到图像文件系统中的目标位置。这意味着脚本的内容将被复制到指定的目录中。

在这种情况下，因为`run.py`和 Dockerfile 在同一级别，所以`run.py`被复制到我们正在构建的基本图像文件系统的工作目录中。

**RUN**命令在构建图像时执行。这里运行的`ls`只是为了让我们看到图像文件系统的内容。

**CMD**命令是在基于我们将使用此 Dockerfile 创建的图像运行容器时使用的。这意味着在 Dockerfile 执行结束时，我们打算运行一个容器。

### JavaScript

退出上一个目录并创建一个新目录。这个将演示一个 node 应用程序。

在脚本中添加以下行并保存：

```
console.log("Hello Docker - JS")
```

运行`docker search node` - 我们将选择官方图像：`node`

请记住，官方图像在**官方**列中具有值**[OK]**：

![JavaScript](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/bg-dop-dkr/img/image01_16a.jpg)

请注意，node 是基于谷歌高性能、开源 JavaScript 引擎 V8 的 JavaScript 运行时。

转到[hub.docker.com](http://hub.docker.com)并搜索 node 以获取正确的标签，或者至少知道具有最新标签的 node 图像的版本是什么。

创建一个新的**Dockerfile**并添加以下内容：

这应该与脚本在同一文件级别。

```
FROM node
ADD . .
RUN ls
CMD node run.js

```

我们现在将涵盖这些内容。

## 活动 3 —— 构建 Dockerfile

确保您的 Docker CLI 正在运行，通过在终端上键入`docker`。

为了让您熟悉 Dockerfile 语法。这项活动的目标是帮助理解和练习使用第三方图像和容器。这有助于更全面地了解协作如何通过容器化来实现。这通过构建已经存在的功能或资源来增加产品交付速度。

您被要求编写一个简单的 Dockerfile，打印`hello-world`。

1.  Docker 是否已经启动？在终端或命令行应用程序上键入`docker`。

1.  创建一个新目录并创建一个新的 Dockerfile。

1.  编写一个包括以下步骤的 Dockerfile：

```
FROM ubuntu:xenial 
RUN apt-get install -y apt-transport-https curl software-properties-common python-software-properties
RUN curl -fsSL https://apt.dockerproject.org/gpg | apt-key add 
RUN echo 'deb https://apt.dockerproject.org/repo ubuntu-xenial main' > /etc/apt/sources.list.d/docker.list
RUN apt-get update
RUN apt-get install -y python3-pip
RUN apt-get install -y build-essential libssl-dev libffi-dev python-dev

```

# 构建镜像

在我们开始构建镜像之前，让我们先了解一下上下文。镜像是一个独立的包，可以运行应用程序或分配服务。镜像是通过 Dockerfile 构建的，Dockerfile 是定义镜像构建方式的模板。

容器被定义为镜像的运行时实例或版本。请注意，这将在您的计算机或主机上作为一个完全隔离的环境运行，这使得它可以被丢弃并用于测试等任务。

有了准备好的 Dockerfiles，让我们进入 Python Dockerfile 目录并构建镜像。

## docker build

构建镜像的命令如下：

```
docker build -t <image-name> <relative location of the Dockerfile>
```

`-t`代表标签。`<image-name>`可以包括特定的标签，比如 latest。建议您始终以这种方式进行操作：给镜像打标签。

**Dockerfile 的相对位置**这里将是一个`点（.）`，表示 Dockerfile 与其余代码处于同一级别；也就是说，它位于项目的根级别。否则，您将进入 Dockerfile 所在的目录。

例如，如果它在 Docker 文件夹中，您将有`docker build -t <image-name> docker`，或者如果它在比根目录更高的文件夹中，您将有两个点。比根目录高两级将用三个点代替一个点。

### 注意

在终端上输出并与 Dockerfiles 中编写的步骤进行比较。您可能希望有两个或更多的 Dockerfiles 来配置不同的情况，比如，一个用于构建生产就绪的应用程序的 Dockerfile，另一个用于测试。无论您有什么原因，Docker 都有解决方案。

默认的 Dockerfile 是 Dockerfile。按照最佳实践，任何额外的 Dockerfile 都被命名为`Dockerfile.<name>`，比如，`Dockerfile.dev`。

要使用除默认 Dockerfile 之外的 Dockerfile 构建镜像，请运行以下命令：`docker build -f Dockerfile.<name> -t <image-name> <Dockerfile 的相对位置>`

### 注意

如果您在不指定不同标签的情况下使用更改 Dockerfile 重新构建镜像，将构建一个新的镜像，并且以`<none>`命名的前一个镜像将被命名。

`docker`构建命令有几个选项，您可以通过运行`docker build --help`来查看。使用名称如 latest 对镜像进行标记也用于版本控制。我们将在*Topic F*中更多地讨论这个问题。

要构建镜像，请在 Python 工作区运行以下命令：

```
>$ docker build -t python-docker .

```

### 注意

尾随的点是语法的重要部分：

![docker build](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/bg-dop-dkr/img/image01_17a.jpg)

### 注意

这里的尾部点是语法的重要部分：

![docker build](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/bg-dop-dkr/img/image01_18a.jpg)

打开 JavaScript 目录，并按以下方式构建 JavaScript 图像：

```
>$ docker build -t js-docker .

```

运行命令将根据**Dockerfile**中的四行命令概述四个步骤。

运行`docker images`列出了你创建的两个图像和之前拉取的任何其他图像。

## 删除 Docker 图像

`docker rmi <image-id>`命令用于删除图像。让我提醒你，可以通过运行`docker images`命令找到图像 ID。

要删除非标记的图像（假定不相关），需要了解 bash 脚本知识。使用以下命令：

```
docker rmi $(docker images | grep "^<none>" | awk "{print $3}")
```

这只是在`docker images`命令的行中搜索带有<none>的图像，并返回第三列中的图像 ID：

![删除 Docker 图像](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/bg-dop-dkr/img/image01_19a.jpg)

## 活动 4 —— 利用 Docker 图像

确保 Docker CLI 正在运行，通过在终端上键入`docker`。

让你熟悉从图像运行容器。

你被要求从*Activity C*中编写的 Dockerfile 构建一个图像。停止运行的容器，删除图像，并使用不同的名称重新构建它。

1.  Docker 是否正在运行？在终端或命令行应用程序上键入`docker`。

1.  打开 JavaScript 示例目录。

1.  运行 `docker build -t <选择一个名称>`（观察步骤并注意结果）。

1.  运行 `docker run <你选择的名称>`。

1.  运行 `docker stop <容器 ID>`。

1.  运行 `docker rmi <在这里添加镜像 ID>`。

1.  运行 `docker build -t <选择新名称>`。

1.  运行 `docker ps`（注意结果；旧图像不应存在）。

# 从图像运行容器

还记得我们提到过容器是从图像构建的吗？命令`docker run <image>`会创建一个基于该图像的容器。可以说容器是图像的运行实例。另一个提醒是，这个图像可以是本地的，也可以在注册表中。

继续运行已创建的图像`docker run python-docker`和`docker run js-docker:`

![从图像运行容器](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/bg-dop-dkr/img/image01_20a.jpg)

你注意到了什么？容器运行的输出显示在终端的相应行上。注意，在 Dockerfile 中由 CMD 前导的命令是运行的命令：

```
docker build -t python-docker:test .  and docker build -t js-docker:test .
```

然后，运行以下命令：

```
python-docker:test and docker run js-docker:test
```

### 注意

你不会在终端上看到任何输出。

这不是因为我们没有一个命令`CMD`在容器启动时运行。对于从**Python**和**Node**构建的镜像，都有一个从基础镜像继承的`CMD`。

### 注意

创建的镜像始终继承自基础镜像。

我们运行的两个容器包含运行一次并退出的脚本。检查`docker ps`的结果，您将不会看到之前运行的两个容器的任何内容。但是，运行`docker ps -a`会显示容器及其状态为已退出。

有一个命令列显示容器构建的镜像的 CMD。

运行容器时，可以按以下方式指定名称：

`docker run --name <container-name> <image-name>`（例如，`docker run --name py-docker-container python-docker`）：

![从镜像运行容器](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/bg-dop-dkr/img/image01_21a.jpg)

我们之前提到，您只想要相关的 Docker 镜像，而不是标记为`<none>`的 Docker 镜像。

至于容器，您需要知道可以从一个镜像中拥有多个容器。`docker rm <container-id>`是删除容器的命令。这适用于已退出的容器（即未运行的容器）。

### 注意

对于仍在运行的容器，您必须要么：

在删除之前停止容器（`docker stop <container-id>`）

强制删除容器（`docker rm <container-id> -f`）

如果运行`docker ps`，将不会列出任何容器，但是如果运行`docker ps -a`，您会注意到列出了容器及其命令列中显示的继承的 CMD 命令：`python3`和`node`：

![从镜像运行容器](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/bg-dop-dkr/img/image01_22a.jpg)

## Python

Python 镜像的 Dockerfile 中的 CMD 是`python3`。这意味着在容器中运行`python3`命令，然后容器退出。

### 注意

有了这个想法，您可以在自己的机器上运行 Python 而无需安装 Python。

尝试运行此命令：`docker run -it python-docker:test`（使用我们上次创建的镜像）。

我们进入容器中的交互式 bash shell。`-it`指示 Docker 容器创建此 shell。shell 运行`python3`，这是 Python 基础镜像中的 CMD：

![Python](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/bg-dop-dkr/img/image01_23a.jpg)

在命令`docker run -it python-docker:test python3 run.py, python3 run.py`中，`python3 run.py`会像在容器内的终端中一样运行。请注意`run.py`在容器内，所以会运行。运行`docker run -it python python3 run.py`将指示`run.py`脚本不存在：

![Python](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/bg-dop-dkr/img/image01_24a.jpg)![Python](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/bg-dop-dkr/img/image01_25a.jpg)

同样适用于 JavaScript，表明这个概念是普遍适用的。

`docker run -it js-docker:test`（我们上次创建的图像）将运行一个运行 node 的 shell（在 node 基础图像中的 CMD）：

![Python](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/bg-dop-dkr/img/image01_26a.jpg)

`docker run -it js-docker:test node run.js` 将输出 `Hello Docker - JS:`

![Python](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/bg-dop-dkr/img/image01_27a.jpg)

这证明了 Docker 图像中的继承因素。

现在，将 Dockerfile 恢复到它们的原始状态，最后一行上的**CMD 命令**。

# 图像版本控制和 Docker Hub

还记得我们在*主题 D*中谈论过图像版本控制吗？我们通过添加 latest 并在我们的图像中使用一些数字，比如`3.x.x`或`3.x.x-rc.`来实现这一点。

在这个主题中，我们将讨论使用标签进行版本控制，并查看过去官方图像是如何进行版本控制的，从而学习最佳实践。

这里使用的命令是：

```
docker build -t <image-name>:<tag> <relative location of the Dockerfile>
```

比如，我们知道 Python 有几个版本：Python 3.6，3.5 等等。Node.js 有更多的版本。如果你看一下 Docker Hub 上官方的 Node.js 页面，你会看到列表顶部有以下内容：

9.1.0, 9.1, 9, latest (9.1/Dockerfile)（截至 2017 年 11 月）：

![图像版本控制和 Docker Hub](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/bg-dop-dkr/img/image01_28a.jpg)

这个版本控制系统被称为语义化版本控制。这个版本号的格式是主要版本、次要版本、补丁版本，以增量方式递增：

**主要**：对于不兼容的更改

**次要**：当你有一个向后兼容的更改时

**补丁**：当你进行向后兼容的错误修复时

你会注意到标签，比如`rc`和其他预发布和构建元数据附加到图像上。

在构建图像时，特别是发布到公共或团队时，使用语义化版本控制是最佳实践。

也就是说，我主张你总是这样做，并把这作为个人的口头禅：语义化版本控制是关键。它将消除在处理图像时的歧义和混乱。

# 将 Docker 镜像部署到 Docker Hub

每次运行`docker build`时，创建的镜像都可以在本地使用。通常，Dockerfile 与代码库一起托管；因此，在新的机器上，需要使用`docker build`来创建 Docker 镜像。

通过 Docker Hub，任何开发人员都有机会将 Docker 镜像托管到任何运行 Docker 的机器上。这样做有两个作用：

+   消除了运行`docker build`的重复任务

+   增加了另一种分享应用程序的方式，与分享应用程序代码库和设置过程详细说明的链接相比，这种方式更简单

`docker login`是通过 CLI 连接到 Docker Hub 的命令。您需要在 hub.docker.com 上拥有一个帐户，并通过终端输入用户名和密码。

`docker push <docker-hub-username/image-name[:tag]>`是将镜像发送到注册表 Docker Hub 的命令：

![将 Docker 镜像部署到 Docker Hub](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/bg-dop-dkr/img/image01_30a.jpg)

在[hub.docker.com](http://hub.docker.com)上简单搜索您的镜像将输出您的 Docker 镜像。

在新的机器上，简单的`docker pull <docker-hub-username/your-image-name>`命令将在本地生成一个副本。

# 总结

在这节课中，我们做了以下几件事：

+   审查了 DevOps 工作流程和 Docker 的一些用例

+   浏览了 Dockerfile 语法

+   获得了构建应用程序和运行容器的图像的高层理解

+   构建了许多图像，对它们进行了版本控制，并将它们推送到 Docker Hub


# 第二章：应用容器管理

在本课程中，我们将把我们构建的一个容器扩展为多层设置。这将涉及将应用程序拆分为不同的逻辑部分。例如，我们可以在一个 Docker 容器上运行一个应用程序，并将应用程序的数据放在一个单独的数据库容器中；但是，两者应该作为一个单一实体工作。为此，我们将使用 Docker 的工具来运行多容器应用程序。该工具名为`docker-compose`。简而言之，`docker-compose`是用于定义和运行多容器 Docker 应用程序的工具。

# 课程目标

通过本课程，您将能够：

+   了解多容器应用程序设置的概述

+   通过`docker-compose`文件和 CLI 进行工作

+   管理多个容器和分布式应用程序包

+   使用`docker-compose`设置网络

+   处理和调试不同的应用程序层

# docker-compose 工具

让我们通过查看多容器设置是什么，为什么它很重要，以及 Docker 如何在这种情况下与`docker-compose`工具一起运行得很好来开始本课程。

我们最近介绍了应用程序如何工作，以及它们的各个部分：前端、后端和数据库。

要使用 Docker 运行这样的多层应用程序，需要在不同的终端会话中运行以下命令来启动容器：

```
- docker run <front-end>
- docker run <back-end>
- docker run <database>
```

### 注意

您可以使用（-d）作为分离运行`docker run`，以防止我们在单独的会话中运行三个命令，例如：`docker run <front-end> -d`

也就是说，链接不同的容器（网络）甚至变得特别繁重。

`docker-compose`进来拯救了我们。我们可以从一个文件 - `docker-compose.yml`中定义和运行多个容器。在接下来的主题中，我们将进一步讨论这个问题。首先，让我们安装它。

## 安装 docker-compose

如果您在*第 1 课*中安装了 Docker 的话，`docker-compose`很可能已经与 Docker 一起安装了。要确认这一点，请在终端中运行`docker-compose`。

如果命令被识别，您应该会得到以下输出：

![安装 docker-compose](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/bg-dop-dkr/img/image02_01.jpg)

Windows 用户应安装 Docker 的社区版，以便在其旁边安装`docker-compose`。 Docker Toolbox 在其安装中包括`docker-compose`。

### 注意

有关进一步的`docker-compose`安装步骤，请查看文档：[`docs.docker.com/compose/install/`](https://docs.docker.com/compose/install/)。

在这个主题上，请注意卸载它的各种方法。为了卸载程序：

转到**程序和功能**。

寻找 Docker，右键单击，然后**卸载**。

# 多容器应用程序设置概述

在上一课中，我们介绍了 Docker 和容器化。我们运行了一些 Python 和 JavaScript 脚本作为应用程序可以被容器化以及镜像可以被构建的演示。现在我们准备运行一个超越这一点的应用程序。

在 Dockerfile 中，每一行描述一个层。Docker 中使用的联合文件系统允许不同的目录透明地叠加，形成一个统一的文件系统。基础层始终是一个镜像，你可以在其上构建。每个带有命令（比如 RUN、CMD 等）的额外行都会向其添加一个层。层的优势在于，只要层没有被修改，就不会影响构建镜像的那部分。其次，当从 Docker 镜像注册表中拉取镜像时，它是以层的形式拉取的，因此可以减轻拉取和推送镜像时的连接中断等问题。

许多应用程序都是在一个常见的结构下构建的：**前端，后端**和**数据库**。让我们进一步分解并了解如何设置这个结构。

## 前端

当你打开一个 Web 应用程序时，你看到的页面是前端的一部分。有时，前端有控制器（逻辑端）和视图层（哑端）。布局和内容的样式（即 HTML 和 CSS）是视图层。这里的内容由控制器管理。

控制器根据用户的操作和/或数据库更改影响视图层中呈现的内容。举个例子，像 Twitter 这样的应用程序：如果有人关注你，你的数据就会发生变化。控制器将捕捉到这个变化，并用新的关注者数量更新视图层。

## 后端

你可能听说过模型-视图-控制器（MVC）**。**模型位于应用程序的后端。以 Twitter 的早期示例为例，模型不关心 HTML 或其布局。它处理应用程序的状态：关注者和你正在关注的人的数量，推文，图片，视频等。

### 注意

这是后端层包括的内容摘要。后端主要处理应用程序的逻辑。这包括操纵数据库的代码；这意味着所有查询都来自后端。但是，请求来自**前端**。例如，当用户点击按钮时。

您可能也听说过 API 这个术语。API 是**应用程序接口**的缩写。这也位于后端。API 公开应用程序的内部工作原理。

这意味着 API 也可以是应用程序的后端或逻辑层。

让我们以 Twitter 为例来说明。例如发布推文和搜索推文等操作可以很容易地作为 API 中的方法存在，如果 API 被公开，可以从任何前端应用程序调用。

### 注意

Docker 和`docker-compose` CLI 实际上是 API 调用，例如与外部资源或内容进行交互时，比如 Docker Hub。

## 数据库

数据库包含组织良好的数据（信息），易于访问、管理和更新。我们有基于文件的数据库和基于服务器的数据库。

基于服务器的数据库涉及运行服务器进程，接受请求并读写数据库文件本身。例如，数据库可以在云中。

### 注意

基于服务器的数据库托管在虚拟主机上，主要在云平台上，例如 Google Cloud Platform 和 Amazon Web Services。例如，Amazon RDS 和 Google Cloud SQL for PostgreSQL。

从以下链接获取基于服务器的数据库：

+   [`aws.amazon.com/rds/postgresql/`](https://aws.amazon.com/rds/postgresql/)

+   [`cloud.google.com/sql/docs/postgres`](https://cloud.google.com/sql/docs/postgres)

简而言之，开发一直涉及构建应用程序层，而交付一直是一项麻烦，考虑到云平台的价格以及涉及的开发和运营（简称 DevOps）。

Docker 和`docker-compose`帮助我们将所有应用程序组件作为一个单一捆绑包进行管理，这样更便宜、更快速、更容易管理。`docker-compose`帮助我们通过一个文件协调所有应用程序层，并且使用非常简单的定义。

随着我们结束这个概述，重要的是要知道开发人员随着时间的推移，已经创造了不同的堆栈变体来总结他们应用程序的前端、后端和数据库结构。以下是它们的列表及其含义（在本课程中我们不会深入探讨）：

+   PREN - PostgresDB，React，Express，Node.js

+   MEAN - MongoDB，Express，Angular，Node.js

+   VPEN - VueJS，PostgresDB，Express，Node.js

+   LAMP - Linux，Apache，MySQL，PHP

### 注意

重要的是要知道应用程序以这种方式结构化，以管理关注点的分离。

有了应用程序结构的知识，我们可以使用`docker-compose` CLI 并将这些知识付诸实践。

## 使用 docker-compose

使用`docker-compose`需要三个步骤：

1.  使用`Dockerfile`构建应用程序的环境作为一个镜像。

1.  使用`docker-compose.yml`文件来定义应用程序运行所需的服务。

1.  运行`docker-compose up`来运行应用程序。

### 注意

`docker-compose`就像 Docker CLI 一样是一个**命令行界面（CLI）**。运行`docker-compose`会给出一系列命令以及如何使用每个命令。

我们在上一课中已经讨论了镜像，所以第 1 步已经完成。

一些`docker-compose`版本与某些 Docker 版本不兼容。

我们将在第 2 步上停留一段时间。

这是`docker-compose`文件：

+   运行我们在上一课中创建的两个镜像的命令：

![使用 docker-compose](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/bg-dop-dkr/img/image02_02.jpg)

### 注意

参考放置在`Code/Lesson-2/example-docker-compose.yml`的完整代码。

访问[`goo.gl/11rwXV`](https://goo.gl/11rwXV)来获取代码。

### docker-compose 首次运行

1.  创建一个新目录并将其命名为`py-js`；如果您喜欢，也可以使用不同的目录名。

1.  在目录中创建一个新文件并将其命名为`docker-compose.yml`。复制上面的图片内容或在`example-docker-compose.yml`中分享的示例。

1.  从目录中运行命令`docker-compose up`。

注意运行`js-docker`和`python-docker`的输出。这也是因为我们在上一课中都本地构建了这两个镜像。

如果您没有这些镜像，运行`docker-compose up`将导致错误，或者尝试从 Docker Hub 上拉取它（如果在线存在）：

![docker-compose 首次运行](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/bg-dop-dkr/img/image02_03.jpg)

+   一个运行**WordPress**的`docker-compose.yml`。WordPress 是一个基于 PHP 和 MySQL 的免费开源**内容管理系统（CMS）**。

## 活动 1 — 使用 docker-compose 运行 WordPress

让您熟悉运行`docker-compose`命令。

有人要求您使用`docker-compose`构建 WordPress 网站。

1.  创建一个新目录并命名为`sandbox`。

1.  创建一个新文件并命名为`docker-compose.yml`。添加`wordpress-docker-compose.yml`中的代码或复制以下图示：![使用 docker-compose 运行 WordPress 的活动 1](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/bg-dop-dkr/img/image02_04.jpg)

### 注意

参考放置在`Code/Lesson-2/wordpress-docker-compose.yml`的完整代码。

访问[`goo.gl/t7UGvy`](https://goo.gl/t7UGvy)获取代码。

### 注意

注意文件中的缩进。建议在缩进行时使用相等数量的制表符和空格。

在`sandbox`目录中运行`docker-compose up`：

![使用 docker-compose 运行 WordPress 的活动 1](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/bg-dop-dkr/img/image02_05.jpg)

### 注意

您会注意到，基于一个文件，我们有一个应用程序正在运行。这个例子是`docker-compose`强大功能的完美展示。

运行`docker ps`。您会看到正在运行的容器：

![使用 docker-compose 运行 WordPress 的活动 1](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/bg-dop-dkr/img/image02_06.jpg)

打开浏览器，转到地址：`http://0.0.0.0:8000/`。我们将准备好设置 WordPress 网站。

继续设置，一会儿，您就会有一个准备好的 WordPress 网站。

### docker-compose 文件：docker-compose.yml

`docker-compose.yml`是一个 YAML 文件。它定义了**服务、网络**和**卷**。

### 注意

服务是应用程序容器定义，包括与应用程序相关的所有组件，例如**DB，前端**或**后端**。在定义服务时真正重要的是组件，这些组件是网络、卷和环境变量。

任何`docker-compose.yml`的第一行都定义了`docker-compose`文件格式的版本。

通过运行`docker -v`，您可以知道正在运行的 Docker 版本，从而知道应在文件的第一行上放置哪个版本。

对于`docker-compose`文件格式 1.0，第一行是不必要的。每个`docker-compose`文件都引入了一个新的配置或废弃了早期的配置。

我们将使用版本 3.3，并且程序应与版本 3.0 及以上兼容。

确保每个人都在运行版本 3，至少是 1.13.0+的 Docker。

接下来是**服务**。让我们使用这个简化的框架：

![docker-compose 文件：docker-compose.yml](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/bg-dop-dkr/img/image02_07.jpg)

### 注意

注意缩进。

在上面的示例中，我们有两个服务，即`db`和`web`。这两个服务只缩进了一次。

定义服务后的下一行定义了要构建镜像的图像或 Dockerfile。

第 4 行将指定`db`服务容器将从哪个图像运行。我们之前提到了许多堆栈；`db`图像可以是任何基于服务器的数据库。

### 注意

要确认您想要使用的堆栈是否存在，请运行以下命令：`docker search <image or name of your preferred stack>`（例如，`docker search mongo`或`docker search postgres`）。

第 6 行解释了 web 服务图像将从相对于 docker-compose.yml 的位置（`。`）中的 Dockerfile 构建。

我们还可以在第 6 行定义 Dockerfile 的名称。例如，在 docker-compose.yml 中，`docker-compose`将搜索具有列出的名称的文件：

```
Line 5| web:build: Dockerfilevolumes:
```

第 7 到 10 行为 web 服务提供了更多的定义。

如在我们用来构建和运行 WordPress 的 docker-compose.yml 中所示，有两个服务：`db`和`wordpress`。在`docker ps`的输出中，这些是容器名称：`sandbox_wordpress_1`和`sandbox_db_1`。

下划线之前的第一个单词表示包含`docker-compose.yml`的目录的名称。该容器名称中的第二个单词是`docker-compose.yml`中定义的服务名称。

我们将在接下来的主题中更详细地讨论。

### docker-compose CLI

一旦安装了`docker-compose`，我提到当您运行`docker-compose`时，您可以期望看到一系列选项。运行`docker-compose –v`。

### 注意

这两个命令，`docker-compose`和`docker-compose -v`，是唯一可以从终端命令行或 Git bash 中打开的任何工作目录中运行的命令。

否则，在`docker-compose`中的其他选项只能在存在`docker-compose.yml`文件的情况下运行。

让我们深入了解常见命令：`docker-compose build`。

此命令构建了模板`docker-compose.ym`中`docker-compose`行中引用的图像（构建：.）。

构建图像也可以通过命令`docker-compose up`来实现。请注意，除非尚未构建图像，或者最近有影响要运行的容器的更改，否则不会发生这种情况。

### 注意

这个命令也适用于 WordPress 示例，即使两个服务都是从 Docker 注册表中的镜像运行，而不是目录中的 Dockerfiles。这将是**拉取**一个镜像而不是构建，因为我们是从 Dockerfile 构建的。

这个命令列出了在`docker-compose.yml`中配置的服务：

+   `docker-compose config --services`

这个命令列出了创建的容器使用的镜像：

+   `docker-compose images`

这个命令列出了来自服务的日志：

+   `docker-compose logs`

`docker-compose logs <service>`列出特定服务的日志，例如，`docker-compose logs db`。

这个命令列出了基于`docker-compose`运行的容器：

+   `docker-compose ps`

请注意，在大多数情况下，`docker-compose ps`和`docker ps`的结果是不同的。在`docker-compose`的上下文中没有运行的容器不会被`docker-compose ps`命令显示出来。

这个命令构建，创建，重新创建和运行服务：

+   `docker-compose up`

### 注意

当运行`docker-compose up`时，如果一个服务退出，整个命令都会退出。

运行`docker-compose up -d`相当于以分离模式运行`docker-compose up`。也就是说，该命令将在后台运行。

## 活动 2 - 分析 docker-compose CLI

让您熟悉`docker-compose` CLI。

您被要求演示运行两个容器产生的更改的差异。

在带有 WordPress `docker-compose.yml`的目录中，例如 sandbox，运行*Activity B-1*的命令，然后运行以下命令：

```
docker-compose up -d
docker-compose stop
docker-compose rm
docker-compose start
docker-compose up -d
docker-compose stop
docker-compose start
```

# 管理多个容器和分布式应用程序包

这是运行 Django 应用程序的`docker-compose.yml`。类似的应用程序可以在`docker-compose`文档的 Django 示例下找到。

从[ttps://docs.docker.com/compose/django/](https://docs.docker.com/compose/django/)下载 Django 示例：

![管理多个容器和分布式应用程序包](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/bg-dop-dkr/img/image02_08.jpg)

### 注意

参考放置在`Code/Lesson-2/django-docker-compose.yml`的完整代码。

访问[`goo.gl/H624J1`](https://goo.gl/H624J1)以访问代码。

## 改进 Docker 工作流程

为了更多地了解`docker-compose`是如何参与并改进 Docker 工作流程的。

1.  创建一个新目录并命名为`django_docker`。

1.  在`django-docker`目录中，创建一个新的`docker-compose.yml`并添加上图中的信息，或者添加提供的`django-docker-compose.yml`脚本中的信息。

1.  创建一个新的 Dockerfile 并添加提供的 Dockerfile 脚本中的内容。

1.  创建一个 requirements 文件；简单地复制提供的`django-requirements.txt`文件。

1.  运行`docker-compose` up 并观察日志。

请注意，我们能够用一个简单的命令 docker-compose up 来启动两个容器。

### 注意

不需要有 Django 的先验经验；这是为了基本演示目的。`Code/Lesson-2/django-requirements.txt`。

### **拆解 Django Compose 文件**

首先，这个文件有多少个服务？是的，有两个：`db`和`web`。服务`db`基于 Postgres 镜像。服务 web 是从包含此`docker-compose.yml`的相同目录中的 Dockerfile 构建的。

没有`docker-compose`文件，`db`服务容器将以以下方式运行：

![拆解 Django Compose 文件](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/bg-dop-dkr/img/image02_09.jpg)

这个命令被翻译为以下内容：

![拆解 Django Compose 文件](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/bg-dop-dkr/img/image02_10.jpg)

在终端中打开另一个标签页或窗口，运行`docker ps`。你会看到容器正在运行。

另一方面，根据示例，`web`服务容器将按以下步骤运行：

![拆解 Django Compose 文件](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/bg-dop-dkr/img/image02_11.jpg)

第二个命令，拆解后的格式如下：

```
docker run (the command)
          -p  shows the <workstation-port>:<container-port>   (8000:8000)
          -v: shows the <present-working-directory>  `pwd` <working-directory-in-container>  (:/django_docker)
          <docker image> (django-web)
          <command-to-run-when-the-container-starts> (python3 manage.py runserver 0.0.0.0.8000)
```

因此，上述命令被翻译为以下内容：

![拆解 Django Compose 文件](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/bg-dop-dkr/img/image02_12.jpg)

使用`docker-compose.yml`的一个优势是，不需要在终端中一遍又一遍地运行命令，你只需要运行一个命令，就可以运行文件中包含的所有容器。

我们在上一课没有涵盖卷和端口。我会花时间帮助我们理解这一点。

### 使用卷持久化数据

卷用于持久化 Docker 容器生成和使用的数据。

### 注意

卷持久化本地文件或脚本的任何更新。这会在容器端产生相同的变化。

在这种情况下，命令如下：

![使用卷持久化数据](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/bg-dop-dkr/img/image02_13.jpg)

在主命令之后的 docker run 选项中：

```
-v .:/django_docker
```

这在`docker-compose.yml`文件中。

![使用卷持久化数据](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/bg-dop-dkr/img/image02_14.jpg)

### 注意

只要在`docker-compose`文件中定义了卷，例如文件更新，本地更改将自动同步到容器中的文件。

![Endure Data Using Volumes](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/bg-dop-dkr/img/image02_15.jpg)

### 端口

Django 和其他 Web 服务器一样，运行在特定端口上。用于构建 Django 镜像的 Dockerfile 具有类似于此命令：`EXPOSE 8000`。当容器运行时，此端口保持打开并可供连接。

在 Django Dockerfile 中，我们将端口定义为`8000`，并在数字前加上地址`(0.0.0.0):`

![Ports](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/bg-dop-dkr/img/image02_16.jpg)

数字`0.0.0.0`定义了运行容器的主机地址。

### 注意

地址告诉`docker-compose`在我们的机器上运行容器，或者简而言之，本地主机。如果我们跳过地址，只是暴露端口，我们的设置将产生意外结果，如空白页面。

考虑`docker run`选项中的以下行：

```
	-p 8000:8000
```

![Ports](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/bg-dop-dkr/img/image02_17.jpg)

以及在`do‑cker-compose.yml`中的以下行：

![Ports](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/bg-dop-dkr/img/image02_18.jpg)

`docker-compose`端口格式将本地工作站端口映射到容器端口。格式如下：

```
-p <workstation-port>:<container-port>
```

这允许我们从本地机器访问从容器端口映射的端口 8000。

最后有一个选项`depends_on`，它是特定于`docker-compose.yml`的。`depends_on`指定容器启动的顺序，只要我们运行`docker-compose` run。

在我们的情况下，`depends_on`选项位于 web 服务下。这意味着 web 服务容器依赖于`db`服务容器：

![Ports](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/bg-dop-dkr/img/image02_19.jpg)

## 活动 3 — 运行 docker-compose 文件

让您熟悉`docker-compose`的语法和命令。

您被要求构建并运行一个简单的 Python 应用程序，该应用程序从图像`josephmuli/flask-app`中暴露端口 5000。定义一个`docker-compose`文件，并将 Postgres 图像扩展为数据库。确保数据库与应用程序相关联。

1.  我已经预先构建了一个名为`josephmuli/flask-app`的图像。在您的`docker-compose.yml`文件中扩展此图像。

1.  确保编写版本 3 的`docker-compose`并定义两个服务。

1.  在端口`5000`上运行应用程序。

1.  打开浏览器并检查监听端口。

# 使用 docker-compose 进行网络连接

默认情况下，`docker-compose`为您的应用程序设置了一个单一网络，其中每个容器都可以访问和发现其他容器。

网络的名称是根据它所在的目录的名称而命名的。因此，如果您的目录名为`py_docker`，当您运行`docker-compose up`时，创建的网络就叫做`py_docker_default`。

我们在前面的主题中提到了端口，当创建 WordPress 容器时。为了更好地解释网络，我们将使用用于启动 WordPress 应用程序的`docker-compose.yml`：

![使用 docker-compose 进行网络连接](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/bg-dop-dkr/img/image02_20.jpg)

在这个文件中，我们有两个服务：`db`和`wordpress`。

在 WordPress 服务中，我们有`ports`选项将端口`80`映射到端口`8000`。难怪，WordPress 应用程序在我们的浏览器上运行在`0.0.0.0:8000`。

`db`服务中没有 ports 选项。然而，如果你去`docker hub 页面查看 mysql`，你会注意到端口`3306`是暴露的。这是 MySQL 的标准端口。你可以从这里获取更多关于 MySQL 的信息：[`hub.docker.com/r/library/mysql`](https://hub.docker.com/r/library/mysql)。

### 注意

我们没有为 DB 进行端口映射，因为我们不一定需要将端口映射到我们的计算机上；相反，我们希望 WordPress 应用程序映射到 DB 进行通信。

我们没有为`db`进行端口映射，因为我们不一定需要将端口映射到我们的本地工作站或计算机上。我们只需要它在容器环境中暴露，因此它可以从 Web 服务中连接，就像第 23 行中的`WORDPRESS_DB_HOST: db:3306`一样。

### 注意

在`docker-compose`文件中，这是如何连接一个容器到另一个容器的方法：

1.  注意所连接的镜像暴露的端口。

1.  引用连接到它的服务下的容器；在我们的情况下，`db`服务被 WordPress 服务连接。

由于我们将服务命名为`db`，我们将这个连接称为`db:3306`。

因此，格式是`<service>:<service 暴露的端口>`。

## 运行 WordPress 容器

为了更好地理解容器是如何连接、同步和通信的。

在 compose 文件中，你注意到了 restart 选项吗？这个选项的可用值如下：

+   no

+   always

+   on-failure

+   unless-stopped

![运行 WordPress 容器](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/bg-dop-dkr/img/image02_21.jpg)

如果没有指定，那么默认值是`no`。这意味着容器不会在任何情况下重新启动。然而，在这里`db`服务已经被指定为 restart: always，所以容器总是会重新启动。

让我们看看 Django 示例，并了解网络是如何工作的。这是`docker-compose.yml`：

![运行 WordPress 容器](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/bg-dop-dkr/img/image02_22.jpg)

立即，您可能看不到 WordPress 站点中存在网络部分。这是一个片段：

```
DATABASES = {
'default': {
'ENGINE': 'django.db.backends.postgresql',
'NAME': 'postgres',
'USER': 'postgres',
'HOST': 'db',
'PORT': 5432,
}
}
```

问题是，我们怎么知道名称和用户是`postgres`，主机是`db`，端口是`5432`？

这些是在`postgres`镜像和我们运行的容器中设置的默认值。

要更清楚地了解，您可以查看官方 Postgres Docker 库中的这一行。

您可以从 GitHub 获取一个 Postgres Docker 示例：[`github.com/docker-library/postgres/blob/master/10/docker-entrypoint.sh#L101.`](https://github.com/docker-library/postgres/blob/master/10/docker-entrypoint.sh#L101.)

![运行 WordPress 容器](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/bg-dop-dkr/img/image02_23.jpg)

如前所述，主机是`DB`，因为服务名称是通过运行`postgres`镜像创建的`db`。

您可以从 GitHub 获取一个 Postgres Docker 示例：[`github.com/docker-library/postgres/blob/master/10/Dockerfile#L132:`](https://github.com/docker-library/postgres/blob/master/10/Dockerfile#L132:)

![运行 WordPress 容器](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/bg-dop-dkr/img/image02_24.jpg)

间接地证明了为什么以那种方式配置了`settings.py`。

# 总结

在本课程中，我们已经完成了以下工作：

+   讨论并展示了一个多容器设置

+   通过`docker-compose`命令逐步构建和运行多个容器

+   获得了对容器网络和如何在本地机器上持久保存数据的高层理解

+   构建和运行应用程序，甚至无需设置，通过 Docker Hub


# 第三章：编排和交付

创建 Docker 主机集群的主要动机是为了实现高可用性。大多数，如果不是全部的集群和编排工具，如 Docker Swarm 和 Kubernetes，都利用集群创建主从关系。这确保了在环境中任何一个节点出现故障时，总是有一个节点可以借助。在向云提供商部署集群时，您可以利用一些技术来确保您的环境是高可用的，例如 Consul，并利用云的本地容错设计，通过在不同的可用性区域部署主节点和节点。

# 课程目标

到本课程结束时，您将能够：

+   获取 Docker Swarm 模式的概述

+   使用 Docker 引擎创建一组 Docker 引擎

+   在一组中管理服务和应用程序

+   扩展服务以处理应用程序的更多请求

+   负载均衡 Docker Swarm 部署

+   安全地管理 Docker 容器和部署

# 编排

在我们的本地环境中运行容器很容易，不需要我们付出很多努力；但是在云端，我们需要一种不同的思维方式和工具来帮助我们实现这一目标。我们的环境应该是高可用的、容错的和易于扩展的。协调资源和/或容器的过程，导致了一个整合的工作流程，这就是编排。

首先，让我们熟悉一些在编排时使用的术语：

+   `docker-engine`：这指的是我们当前在计算机上安装的 Docker 包或安装

+   `docker-machine`：一个帮助我们在虚拟主机上安装 Docker 的工具

+   `虚拟主机`：这些是在物理主机下运行的虚拟服务器

+   `docker-swarm`：Docker 的集群工具

+   `docker 主机`：已安装或设置了 Docker 的主机或服务器

+   `节点`：连接到群集的 Docker 主机

+   `集群`：一组 Docker 主机或节点

+   `副本`：一个实例的副本或多个副本

+   `任务`：在节点上运行的定义操作

+   `服务`：一组任务

### 注意

以下是整个课程中最常见的术语：

+   `docker-engine`：在我们的计算机上运行 Docker；

+   `docker-machine`：一个帮助我们安装 Docker 的工具或 CLI

+   `虚拟主机`：在物理主机上运行的主机或服务器。

+   `docker-swarm:`Docker 的集群工具

+   `Docker host`：运行 Docker 的任何服务器或主机

+   `Node`：这指的是绑定到 swarm 集群的任何主机。

+   `Cluster`：一组受管理和控制的主机。

+   `Replica`：其他正在运行的主机的副本，用于各种任务

+   任务：安装、升级或移除等操作。

+   `Service`：多个任务定义一个服务。

现在我们至少熟悉了上述术语，我们准备使用`docker-machine`实施 Docker Swarm 编排流程。

# Docker Swarm 概述

Docker Swarm 是 Docker 容器的**集群**工具。它允许您建立和管理一组 Docker **节点**作为一个单一的**虚拟系统**。这意味着我们可以在计算机上的多个主机上运行 Docker。

我们通过管理器来控制 swarm 集群，管理器主要**处理**和**控制**容器。通过 swarm 管理器，您可以创建一个主管理器实例和多个**副本**实例，以防主要实例失败。这意味着在 swarm 中可以有多个管理器！

### 注意

一个 swarm 是从一个管理节点创建的，其他 Docker 机器加入集群，可以作为工作节点或管理节点。

集群化很重要，因为它创建了一组合作系统，提供冗余，从而创建了一个容错环境。例如，如果一个或多个节点宕机，Docker Swarm 将故障转移到另一个正常工作的节点。

**Swarm manager** 执行以下角色：

+   接受`docker`命令

+   执行针对集群的命令

+   支持高可用性；部署主要和次要实例，可以在主要实例宕机时接管

Docker Swarm 使用**调度**来优化资源并确保环境的效率。它将**分配容器**给最合适的**节点**。这意味着 Docker Swarm 将容器分配给最健康的节点。

### 注意

记住，节点是运行 Docker 的**主机**，而不是**容器**。

Swarm 可以配置为使用以下任一调度策略：

+   **Random**：将新的容器部署到随机节点。

+   **Spread**：Swarm 将新的容器部署到具有最少数量容器的节点。

+   **Binpack**：binpack 策略涉及将新的容器部署到具有最多容器的节点。

您可以在以下网址下载 VirtualBox：[`www.virtualbox.org/wiki/Downloads`](https://www.virtualbox.org/wiki/Downloads)：

![Docker Swarm 概述](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/bg-dop-dkr/img/image03_01.jpg)

### 注意

为了模拟一个 Docker Swarm 集群，我们需要在本地安装一个 hypervisor（hypervisor type 2 是一种安装在现有操作系统上的软件应用程序的虚拟机管理器），在这种情况下是 VirtualBox，它将允许我们通过`docker-machine`创建多个运行 Docker 的主机，并将它们添加到集群中。在部署到云供应商时，可以使用它们的计算服务来实现，例如 AWS 上的 EC2。

对于 Windows 操作系统，选择您的操作系统分发版，您应该立即获得下载。运行可执行文件并安装 VirtualBox。

# 使用 Docker Engine 创建一个 Swarm

在创建我们的集群之前，让我们快速概述一下`docker-machine cli`。在您的终端上键入`docker-machine`应该会给您这个输出：

![使用 Docker Engine 创建 Swarm](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/bg-dop-dkr/img/image03_03.jpg)

就在下面，我们有我们的命令列表：

![使用 Docker Engine 创建 Swarm](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/bg-dop-dkr/img/image03_04.jpg)

### 注意

请记住，当您需要澄清某些事情时，始终使用`help`选项，即`docker-machine stop --help`

要创建我们的第一个 Docker Swarm 集群，我们将使用`docker-machine`首先创建我们的管理器和工作节点。

在创建第一台机器之前，快速概述我们的目标给出了以下内容：我们将拥有四台 docker-machines，一个管理器和三个工作节点；它们都在 VirtualBox 上运行，因此有四个虚拟机。

## 创建 Docker 机器

此命令用于创建一个新的虚拟 Docker 主机：

```
docker-machine create --driver <driver> <machine_name>

```

这意味着我们的 Docker 主机将在 VirtualBox 上运行，但由`docker-machine`进行管理和控制。`--driver`选项指定要使用的驱动程序来创建机器。在这种情况下，我们的驱动程序是 VirtualBox。

我们的命令将是`docker-machine create --driver virtualbox manager1`。

### 注意

我们在命令中需要指定驱动程序，因为这是我们主机的基础，这意味着我们的`manager1`机器将在 VirtualBox 上作为虚拟主机运行。有多个供应商提供的多个驱动程序可用，但这是用于演示目的的最佳驱动程序。

![创建 Docker 机器](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/bg-dop-dkr/img/image03_05.jpg)

## 创建机器清单

此命令将提供当前主机上所有 Docker 机器的列表以及有关机器的状态、驱动程序等的更多信息：`docker-machine ls`

![创建的机器清单](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/bg-dop-dkr/img/image03_06.jpg)

### 注意

列出我们的机器非常重要，因为它给我们提供了机器状态的更新。我们并不真正会收到错误通知，有时错误可能会积累成为一个重大事件。在对机器进行一些工作之前，这将给出一个简要的概述。可以通过`docker-machine status`命令运行更详细的检查。

## 工作机器创建

我们将按照相同的流程为我们的 swarm 集群创建三个工作机器，换句话说，连续三次运行`docker-machine create --driver virtualbox <machine_name>`，在每次运行时将`worker1, worker2`和`worker3`作为`<machine_name>`的值传递：

![工作机器创建](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/bg-dop-dkr/img/image03_07.jpg)![工作机器创建](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/bg-dop-dkr/img/image03_08.jpg)

最后，最后一个工作节点将显示如下：

![工作机器创建](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/bg-dop-dkr/img/image03_09.jpg)

这样做后，运行`docker-machine ls`，如果创建成功，您将看到类似以下的输出：

![工作机器创建](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/bg-dop-dkr/img/image03_10.jpg)

### 注意

根据它们的用途命名机器有助于避免意外地呼叫错误的主机。

## 初始化我们的 Swarm

现在我们的机器正在运行，是时候创建我们的 swarm 了。这将通过管理节点`manager1`完成。以下是我们将采取的步骤，以实现一个完整的 swarm：

1.  连接到管理节点。

1.  声明`manager1`节点为管理者并宣布其地址。

1.  获取节点加入 swarm 的邀请地址。

我们将使用`ssh`进行连接。`ssh`是一种安全的网络协议，用于访问或连接主机或服务器。

### 注意

Docker 机器通过`docker-machine cli`进行控制。Docker Swarm 作为一个服务运行，将所有 Docker 机器绑定在一个管理机器或节点下。这并不意味着 swarm 集群中的机器是相等或相似的，它们可能在运行不同的服务或操作，例如，数据库主机和 Web 服务器。Docker Swarm 帮助编排主机。

此命令用于获取一个或多个 Docker 机器的 IP 地址：

```
docker-machine ip <machine_names>

```

此命令用于获取一个或多个 Docker 机器的 IP 地址。`<machine_name>`是我们需要 IP 地址的机器的名称。在我们的情况下，我们将用它来获取`manager1`节点的 IP 地址，因为在初始化 swarm 模式时我们将需要它：

![初始化我们的 Swarm](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/bg-dop-dkr/img/image03_11.jpg)

## 连接到一个机器

此命令用于使用`SSH`登录到机器：

```
docker-machine ssh <machine_name>

```

成功连接到我们的`manager1`后，我们应该得到以下输出：

![连接到一个机器](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/bg-dop-dkr/img/image03_12.jpg)

### 注意

在云供应商上使用`ssh 协议`将需要通过用户名和密码或`ssh 密钥`进行身份验证和/或授权。我们不会深入讨论这个问题，因为这只是一个演示。

## 初始化 Swarm 模式

以下是初始化 Swarm 模式的命令：

```
docker swarm init --advertise-addr <MANAGER_IP>

```

让我们在管理节点内运行此命令以初始化 Swarm。`advertise-addr`选项用于指定将向集群的其他成员广告的地址，以进行 API 访问和网络。

在这种情况下，它的值是`管理者 IP 地址`，其值是我们之前运行`docker-machine ip manager1`得到的：

### 注意

我们之前提到过，Docker Swarm 是通过管理节点将所有机器绑定和编排的服务。为了实现这一点，Docker Swarm 让我们通过管理者的地址来广告集群，包括在`docker swarm init`命令中包含`advertise-addr`。

![初始化 Swarm 模式](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/bg-dop-dkr/img/image03_13.jpg)

运行该命令的输出显示我们的节点现在是一个管理者！

请注意，我们还有两个命令：一个应该允许我们邀请其他节点加入集群，另一个是将另一个管理者添加到集群中。

### 注意

在设计高可用性时，建议有多个管理者节点，以便在主管理者节点发生故障时接管。

### 注意

确保您保存输出中列出的两个命令，它们将有助于添加其他主机到集群中。

## 将工作节点添加到我们的 Swarm

此命令用于添加 Swarm 工作节点`：`

```
docker swarm join --token <provided_token> <manager_ip>:<port>

```

在我们可以将工作节点添加到集群之前，我们需要通过`ssh`连接到它们。

我们通过运行`docker-machine ssh <node_name>`，然后运行我们从`manager1 节点`得到的邀请命令来实现这一点。

### 注意

`docker-machine`命令可以从任何目录运行，并且始终与创建的机器一起工作。

首先，我们将使用`exit`命令退出管理节点：

![将工作节点添加到我们的 Swarm](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/bg-dop-dkr/img/image03_14.jpg)

然后，我们通过`ssh`连接到一个工作节点：

![将工作节点添加到我们的 Swarm](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/bg-dop-dkr/img/image03_15.jpg)

最后，我们将节点添加到集群中：

![将工作节点添加到我们的 Swarm](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/bg-dop-dkr/img/image03_16.jpg)

## 查看集群状态

我们使用此命令来查看我们集群的状态：

```
docker node ls
```

我们使用这个命令来查看我们集群的状态。这个命令在管理节点上运行，并显示我们集群中所有节点的状态和可用性。在我们的管理节点上运行这个命令会显示类似以下的输出：

![查看集群状态](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/bg-dop-dkr/img/image03_17.jpg)

## 活动 1 — 添加节点到集群

确保您有一个管理节点和节点邀请命令。

让您熟悉 `ssh` 和集群管理。

您被要求连接至少两个节点并将它们添加到集群中。

1.  `ssh` 进入您的第一个节点：![Activity 1 — 添加节点到集群](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/bg-dop-dkr/img/image03_18.jpg)

1.  在节点上运行邀请命令加入集群。记住，我们在第一次初始化管理节点时得到了这个命令：![Activity 1 — 添加节点到集群](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/bg-dop-dkr/img/image03_19.jpg)

1.  退出节点，`ssh` 进入另一个节点，并运行命令：![Activity 1 — 添加节点到集群](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/bg-dop-dkr/img/image03_20.jpg)

1.  `ssh` 进入管理节点，通过 `docker node ls` 检查集群状态：![Activity 1 — 添加节点到集群](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/bg-dop-dkr/img/image03_21.jpg)

# 在 Swarm 中管理服务和应用程序

现在我们的集群已经准备好了，是时候在我们的集群上安排一些服务了。如前所述，管理节点的角色是接受 Docker 命令并将其应用于集群。因此，我们将在管理节点上创建服务。

### 注意

在这一点上，worker 节点上真的没有太多可以做的，因为它们完全受管理节点控制。

## 创建服务

此命令用于创建服务：

```
docker service create --replicas <count> -p <host_port>:<container_port> --name <service_name> <image_name>

```

我们在管理节点上运行这个命令，正如前面所提到的。我们将使用我们在上一课中构建的 WordPress 示例。由于我们已经在本地拥有这个镜像，所以不需要从 hub 上拉取它。

我们的副本数量将是三，因为我们目前有三个工作节点；通过运行 `docker node ls` 确认您的节点编号。

### 注意

我们不创建副本数量；这引入了以下主题。`-p <host_port>:<container_port>` 将容器映射到我们计算机上定义的端口，与容器端口相对应。我们不需要与我们的节点编号相同数量的副本。其他节点可以处理不同的应用程序层，例如数据库：

![创建服务](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/bg-dop-dkr/img/image03_22.jpg)

我们创建了一个基于 WordPress 镜像的 web，并将主机端口 `80` 映射到容器端口 `80`。

## 服务列表

此命令用于查看当前正在运行的服务：

```
docker service ls
```

此命令用于查看当前正在运行的服务以及更多信息，例如副本、镜像、端口等。

从以下输出中，我们可以看到我们刚刚启动的服务和相关信息：

![列出服务](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/bg-dop-dkr/img/image03_23.jpg)

## 服务状态

此命令用于了解我们的服务是否运行正常：

```
docker service ps <service_name>
```

查看服务列表不会为我们提供所有所需的信息，比如我们的服务部署在哪些节点上。但是，我们可以知道我们的服务是否运行正常以及遇到的错误（如果有）。当我们在管理节点上运行此命令时，我们会得到以下输出：

![服务状态](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/bg-dop-dkr/img/image03_24.jpg)

### 注意

查看状态非常重要。在我们对节点进行升级或更新的情况下，运行`docker ps`会通知我们节点的状态。在理想的 Docker Swarm 设置中，当一个节点宕机时，管理节点会重新分配流量到可用节点，因此很难注意到停机时间，除非有监控可用。在处理节点之前，始终运行此命令以检查节点的状态。

## 我们如何知道我们的网站正在运行？

我们可以通过在浏览器上打开任何工作节点的 IP 地址来验证 WordPress 是否正在运行：

![我们如何知道我们的网站正在运行？](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/bg-dop-dkr/img/image03_25.jpg)

这是 WordPress 在我们的浏览器上的外观截图：

![我们如何知道我们的网站正在运行？](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/bg-dop-dkr/img/image03_26.jpg)

### 注意

打开任何运行 WordPress Web 服务的 IP 地址，包括管理节点，都会打开相同的地址。

## 活动 2 — 在集群上运行服务

确保您有一个管理节点正在运行。

让您熟悉集群中的服务管理。

已要求您向集群添加一个新的`postgres`服务。

1.  创建一个新节点并将其命名为`dbworker`：

```
docker-machine create --driver virtualbox dbworker
```

![活动 2 — 在集群上运行服务](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/bg-dop-dkr/img/image03_27.jpg)

1.  将新的工作节点添加到集群中：![活动 2 — 在集群上运行服务](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/bg-dop-dkr/img/image03_28.jpg)

1.  创建一个新的数据库服务，并将其命名为`db`，使用 postgres 镜像作为基础：

```
docker service create --replicas 1 --name db postgres
```

以下是输出的截图：

![活动 2 — 在集群上运行服务](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/bg-dop-dkr/img/image03_29.jpg)

1.  通过以下步骤验证`postgres`是否正在运行：

1.  将运行在`dbworker 节点`中的`postgres`容器映射到您的计算机上：

```
docker run --name db -e POSTGRES_PASSWORD=postgres -d -p 5432:5432 postgres

```

![活动 2 — 在集群上运行服务](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/bg-dop-dkr/img/image03_30.jpg)

1.  运行`docker ps`以列出正在运行的容器；这应该有我们的`postgres`容器，状态应为`UP`：![Activity 2 — Running Services on a Swarm](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/bg-dop-dkr/img/image03_31.jpg)

1.  通过以下方式退出并停止容器：![Activity 2 — Running Services on a Swarm](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/bg-dop-dkr/img/image03_32.jpg)

# 扩展服务上下。

随着进入应用程序的请求数量增加或减少，将需要扩展基础架构。我们最近使用了运行相同 WordPress 安装的节点副本。

### 注意

这是一个生产级设置的非常基本的示例。理想情况下，我们需要更多的管理节点和副本，但由于我们正在运行演示，这将足够了。

扩展涉及根据应用程序的流量增加和减少资源。

## 扩展我们的数据库服务

我们将扩展我们的数据库服务，作为扩展服务的示例。在现实世界的场景中，云服务如 Google Cloud Platform 和 Amazon Web Services 可能定义了自动扩展服务，其中创建了一些副本，并通过称为**负载平衡**的服务在副本之间分发流量。我们将在下一个活动中深入探讨这一点。首先，我们要从基础知识开始了解扩展是如何工作的。扩展数据库的命令格式如下：

```
docker service scale <service_name>=<count>
```

要扩展服务，请传入我们创建服务时提供的服务名称以及要将其增加到的副本数。

### 注意

`--detach=false`允许我们查看复制进度。命令是`docker service scale <service_name>=<count>:`

![扩展我们的数据库服务](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/bg-dop-dkr/img/image03_33.jpg)

从上面的输出中，我们可以看到我们的`db`服务已经被复制。我们现在在`dbworker`节点上运行了两个数据库服务。

## Swarm 如何知道在哪里安排服务？

我们之前介绍了调度模式；它们包括以下内容：

+   随机

+   Spread

+   Binpack

Docker Swarm 的默认调度策略是`spread`，它将新服务分配给资源**最少**的节点。

### 注意

如果在 swarm 上没有额外的未分配节点，则要扩展的服务将在当前运行的节点上复制。

swarm 管理器将使用 spread 策略并根据资源分配。

然后，我们可以使用`docker service ls`命令验证操作是否成功，我们可以看到副本的数量为两个：

![Swarm 如何知道在哪里安排服务？](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/bg-dop-dkr/img/image03_34.jpg)

缩减规模与扩大规模非常相似，只是我们传递的副本计数比以前少。从以下输出中，我们将规模缩减到一个副本，并验证副本计数为一个：

![Swarm 如何知道在哪里安排服务？](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/bg-dop-dkr/img/image03_35.jpg)

## Swarm 如何在副本之间平衡请求？

负载均衡器有助于处理和管理应用程序中的请求。在应用程序处理大量请求的情况下，可能在不到 5 分钟内就有 1000 个请求，我们需要在我们的应用程序上有多个副本和一个负载均衡器，特别是逻辑（后端）部分。负载均衡器有助于分发请求并防止实例过载，最终导致停机时间。

在像**Google Cloud Platform**或**Amazon Web Services**这样的云平台上部署到生产环境时，您可以利用外部负载均衡器将请求路由到您的 Swarm 主机。

Docker Swarm 包括一个内置的路由服务，使得群集中的每个节点都能接受对已发布端口的传入连接，即使节点上没有运行服务。`postgres`服务默认使用端口`5432`。

## 活动 3 —— 在 Swarm 上扩展服务

确保您至少有一个管理节点、两个服务和三个工作节点的群集。

让您熟悉扩展服务和复制节点。

要求将网络服务扩展到四个副本，数据库服务扩展到两个副本。

1.  创建三个新的工作节点，两个用于网络服务，一个用于数据库服务。

1.  连接到管理节点并扩展网络和数据库服务。

1.  使用 docker service ls 确认服务副本计数；最终结果应该如下：

+   WordPress 网络服务应该有两个副本计数

+   Postgres 数据库服务应该有四个副本计数

# 总结

在本课程中，我们已经完成了以下工作：

+   讨论了编排，并提到了一些示例工具

+   讨论了集群化以及为什么它在生产级设置中很重要

+   通过在 VirtualBox 上运行 Docker Machines 学习了虚拟主机

+   通过 Docker Swarm 以及如何创建和管理节点集群来了解

+   介绍了包括在我们的群集上运行的 Wordpress 在内的示例服务

+   对使用`docker-machine cli`进行工作有了高层次的理解

+   讨论了负载均衡以及 Docker Swarm 如何管理这一点

恭喜你到达终点！以下是我们通过课程获得的知识的总结。

在这本书中，我们涵盖了以下内容：

+   讨论了 DevOps 以及 Docker 如何促进工作流程

+   了解了如何在 Dockerfiles 上为应用程序创建模板

+   构建镜像和容器并将它们推送到 Docker Hub

+   通过`docker-compose`管理容器

+   学会了如何通过 Docker Swarm 编排我们的应用程序
