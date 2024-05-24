# GPT3 探索指南（一）

> 原文：[`zh.annas-archive.org/md5/e19ec4b9c1d08c12abd2983dace7ff20`](https://zh.annas-archive.org/md5/e19ec4b9c1d08c12abd2983dace7ff20)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 前言

# 关于本书

Docker 容器是高度可扩展软件系统的未来，并且可以轻松创建、运行和部署应用程序。

如果您希望利用它们而不被技术细节所压倒，那么请将*The Docker Workshop*添加到您的阅读列表中！

通过本书，您将能够快速掌握容器和 Docker 的知识，并通过互动活动使用它们。

这个研讨会从 Docker 容器的概述开始，让您了解它们的工作原理。您将运行第三方 Docker 镜像，并使用 Dockerfiles 和多阶段 Dockerfiles 创建自己的镜像。接下来，您将为 Docker 镜像创建环境，并通过持续集成加快部署过程。在前进的过程中，您将涉足有趣的主题，并学习如何使用 Docker Swarm 实现生产就绪环境。为了进一步保护 Docker 镜像，并确保生产环境以最大容量运行，您将应用最佳实践。随后，您将学会成功将 Docker 容器从开发转移到测试，然后进入生产。在此过程中，您将学习如何解决问题，清理资源瓶颈，并优化服务的性能。

通过本 Docker 书籍，您将精通 Docker 基础知识，并能够在实际用例中使用 Docker 容器。

## 受众

如果您是开发人员或 Docker 初学者，希望在实践中了解 Docker 容器，那么这本书是理想的指南。在开始阅读本 Docker 容器书籍之前，需要具备运行命令行和了解 IntelliJ、Atom 或 VSCode 编辑器的知识。

## 关于章节

*第一章*，*运行我的第一个 Docker 容器*，从 Docker 的基本介绍开始，讨论了背景架构、生态系统和基本 Docker 命令。

*第二章*，*使用 Dockerfiles 入门*，向您介绍了 Dockerfile、其背景以及如何使用 Dockerfile 创建和运行您的第一个 Docker 容器。

*第三章*，*管理您的 Docker 镜像*，提供了有关 Docker 镜像、镜像存储库和发布您自己的镜像的更多细节。

*第四章*，*多阶段 Dockerfiles*，向您展示如何进一步扩展您的 Dockerfile，在项目中使用多阶段 Dockerfile。

*第五章*，*使用 Docker Compose 组合环境*，介绍了 Docker Compose 以及如何使用 docker-compose 文件生成整个工作环境。

*第六章*，*介绍 Docker 网络*，解释了为什么在 Docker 中需要以不同的方式处理网络，以及如何实现服务和主机系统之间的通信。

*第七章*，*Docker 存储*，详细介绍了在您的 Docker 容器和环境中利用存储的方法。

*第八章*，*CI/CD 流水线*，描述了使用 Jenkins 创建持续集成/持续部署流水线。

*第九章*，*Docker Swarm*，介绍了使用 Swarm 编排您的 Docker 服务。

*第十章*，*Kubernetes*，将您的编排提升到下一个级别，向您介绍了 Kubernetes 以及如何在基本集群中部署您的容器镜像。

*第十一章*，*Docker 安全*，指导您如何使您的 Docker 镜像和容器尽可能安全，提供了在使用容器时减少风险的方法。

*第十二章*，*最佳实践*，提供了关于如何确保您的容器尽可能高效运行的信息。

*第十三章*，*监控 Docker 指标*，涵盖了正在运行的 Docker 容器的指标收集以及如何实现 Prometheus 来帮助监控这些指标。

*第十四章*，*收集容器日志*，教你如何使用 Splunk 从正在运行的 Docker 容器中收集日志，这将允许你聚合、搜索和显示日志详细信息。

*第十五章*，*使用插件扩展 Docker*，介绍了通过创建自己的插件来进一步扩展 Docker 的方法，以便与您的 Docker 应用程序一起使用。

注意

此外，本书的免费互动版本还附带了一个额外的章节，*Docker 的未来展望*。您可以在以下网址找到它：https://courses.packtpub.com/。

## 约定

文本中的代码单词、数据库表名、文件夹名、文件名、文件扩展名、路径名、虚拟 URL 和用户输入显示如下：

“在当前工作目录中创建一个名为`docker-compose.yml`的文件。”

代码块、终端命令或创建 YAML 文件的文本设置如下：

```
docker build -t test . 
```

新的重要单词显示为：“Docker 提供了一个在线存储库来存储您的镜像，称为**Docker Hub**。”

屏幕上显示的文字（例如菜单或对话框中的文字）会在文本中以这种方式出现：“在左侧边栏上，点击`设置`，然后点击`用户`。”

代码片段的关键部分如下所示：

```
1 FROM alpine
2 
3 RUN apk update
4 RUN apk add wget curl
5
6 RUN wget -O test.txt https://github.com/PacktWorkshops/   The-Docker-Workshop/raw/master/Chapter3/Exercise3.02/     100MB.bin
7
8 CMD mkdir /var/www/
9 CMD mkdir /var/www/html/
```

长代码片段被截断，并且在截断的代码顶部放置了 GitHub 上代码文件的相应名称。完整代码的永久链接放置在代码片段下方。它应该如下所示：

Dockerfile

```
7 # create root directory for our project in the container
7 RUN mkdir /service
9 RUN mkdir /service/static
10
11# Set the working directory to /service
12 WORKDIR /service
```

此示例的完整代码可以在[`packt.live/2E9OErr`](https://packt.live/2E9OErr)找到。

## 设置您的环境

在我们详细探讨本书之前，我们需要设置特定的软件和工具。在接下来的部分中，我们将看到如何做到这一点。

### 硬件要求

您至少需要一台支持虚拟化的双核 CPU，4GB 内存和 20GB 的可用磁盘空间。

### 操作系统要求

推荐的操作系统是 Ubuntu 20.04 LTS。如果您使用 Mac 或 Windows，您应该能够运行本书中的命令，但不能保证它们都能正常工作。我们建议您在系统上安装虚拟化环境，例如 VirtualBox 或 VMware。我们还在本节末尾提供了有关如何在 Windows 系统上设置双引导以使用 Ubuntu 的说明。

## 安装和设置

本节列出了 Docker 和 Git 的安装说明，因为它们是本次研讨会的主要要求。任何其他使用的软件的安装说明将在涵盖它的特定章节中提供。由于我们推荐使用 Ubuntu，我们将使用 APT 软件包管理器在 Ubuntu 中安装大部分所需的软件。

### 更新您的软件包列表

在 Ubuntu 上使用 APT 安装任何软件包之前，请确保您的软件包是最新的。使用以下命令：

```
sudo apt update
```

此外，您可以使用以下命令选择升级计算机上的任何可升级软件包：

```
sudo apt upgrade
```

### 安装 Git

本研讨会的代码包可以在我们的 GitHub 存储库上找到。您可以使用 Git 克隆存储库以获取所有代码文件。

使用以下命令在 Ubuntu 上安装 Git：

```
sudo apt install git-all
```

### Docker

Docker 是本研讨会使用的默认容器化引擎。随着您阅读本书的章节，您将更多地了解该应用程序。

使用以下命令在 Ubuntu 上安装 Docker：

```
sudo apt install docker.io -y
```

安装完成后，您需要确保 Docker 守护程序已启动并在系统上运行。使用以下命令执行此操作，确保您以`sudo`命令作为提升的用户运行此命令：

```
sudo systemctl start docker
```

确保 Docker 守护程序在下次启动系统时启动。运行以下命令，以确保 Docker 在您安装它的系统上每次停止或重新启动时启动：

```
sudo systemctl enable docker
```

使用`docker`命令和`--version`选项验证您安装的 Docker 版本。运行以下命令：

```
docker –version
```

您应该看到类似以下的输出：

```
Docker version 19.03.8, build afacb8b7f0
```

如果您不是以 root 用户身份执行命令，很有可能无法运行所需的大部分命令。如果运行以下示例命令，可能会遇到连接到 Docker 守护程序的访问问题：

```
docker ps
```

如果您以没有提升权限的用户身份运行该命令，可能会看到以下错误：

```
Got permission denied while trying to connect to the 
Docker daemon socket at unix:///var/run/docker.sock: Get http://%2Fvar%2Frun%2Fdocker.sock/v1.40/containers/json: 
dial unix /var/run/docker.sock: connect: permission denied
```

要解决此问题，请将当前用户添加到安装应用程序时创建的 Docker 组中。使用以下命令在您的系统上执行此操作：

```
sudo usermod -aG docker ${USER}
```

要激活这些更改，您需要注销系统，然后重新登录，或执行以下命令为当前用户创建一个新会话：

```
sudo su ${USER}
```

再次运行`docker ps`命令，以确保您的更改成功：

```
docker ps
```

如果一切正常，您应该看到类似以下的输出，显示您的系统上没有运行 Docker 容器：

```
CONTAINER ID  IMAGE  COMMAND  CREATED  STATUS  PORTS  NAMES
```

## 为 Windows 用户双引导 Ubuntu

在本节中，您将找到有关在运行 Windows 的情况下如何双引导 Ubuntu 的说明。

注意

在安装任何操作系统之前，强烈建议您备份系统状态和所有数据。

### 调整分区大小

如果您的计算机上安装了 Windows，那么您的硬盘很可能已完全被使用，即所有可用空间都已分区并格式化。您需要在硬盘上有一些未分配的空间，因此请调整具有大量可用空间的分区的大小，以为 Ubuntu 分区腾出空间。

1.  打开“计算机管理”实用程序。按下*Win* + *R*，输入`compmgmt.msc`：![图 1.0：Windows 上的计算机管理实用程序](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-ws/img/B15021_0_01.jpg)

图 1.0：Windows 上的计算机管理实用程序

1.  在左侧窗格中，转到`存储 > 磁盘管理`选项，如下截图所示：![图 0.2：磁盘管理](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-ws/img/B15021_0_02.jpg)

图 0.2：磁盘管理

您将在屏幕下半部分看到所有分区的摘要。您还可以看到与所有分区关联的驱动器号以及有关 Windows 引导驱动器的信息。如果您有一个有大量空闲空间（20 GB +）且既不是引导驱动器（`C：`）也不是恢复分区，也不是**可扩展固件接口**（**EFI**）系统分区的分区，则这将是理想的选择。如果没有这样的分区，那么您可以调整`C：`驱动器的大小。

1.  在本示例中，您将选择`D：`驱动器。右键单击任何分区并打开`属性`以检查可用的空闲空间：![图 0.3：检查 D：驱动器的属性](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-ws/img/B15021_0_03.jpg)

图 0.3：检查 D：驱动器的属性

现在，在调整分区大小之前，您需要确保文件系统或任何硬件故障没有错误。在 Windows 上使用**chkdsk**实用程序进行此操作。

1.  按下*Win* + *R*打开命令提示符，然后输入`cmd.exe`。现在运行以下命令：

```
chkdsk D: /f
```

用要使用的驱动器号替换它。您应该看到类似以下的响应：

![图 0.4：扫描驱动器以查找任何文件系统错误](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-ws/img/B15021_0_04.jpg)

图 0.4：扫描驱动器以查找任何文件系统错误

请注意，在*图 0.4*中，Windows 报告它已扫描文件系统并未发现问题。如果您的情况遇到任何问题，您应该先解决这些问题，以防止数据丢失。

1.  现在，返回到`计算机管理`窗口，右键单击所需的驱动器，然后单击`收缩卷`，如下截图所示：![图 0.5：打开收缩卷对话框](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-ws/img/B15021_0_05.jpg)

图 0.5：打开收缩卷对话框

1.  在提示窗口中，输入要收缩的空间量。在此示例中，您正在通过收缩`D：`驱动器来清除大约 25 GB 的磁盘空间：![图 0.6：通过收缩现有卷清除 25 GB](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-ws/img/B15021_0_06.jpg)

图 0.6：通过收缩现有卷清除 25 GB

收缩驱动器后，您应该能够在驱动器上看到未分配的空间：

![图 0.7：收缩卷后的未分配空间](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-ws/img/B15021_0_07.jpg)

图 0.7：缩小卷后的未分配空间

现在，您已经准备好安装 Ubuntu 了。但首先，您需要下载它并创建一个可启动的 USB，这是最方便的安装介质之一。

### 创建可启动的 Ubuntu USB 驱动器

您需要一个至少容量为 4GB 的闪存驱动器来创建一个可启动的 USB 驱动器。请注意，其中的所有数据将被删除：

1.  从[`releases.ubuntu.com/20.04/`](https://releases.ubuntu.com/20.04/)下载 Ubuntu 桌面版的 ISO 镜像。

1.  接下来，将 ISO 镜像刻录到 USB 闪存盘并创建一个可启动的 USB 驱动器。有许多可用的工具，您可以使用其中任何一个。在本例中，您将使用免费开源的 Rufus。您可以从[`www.fosshub.com/Rufus.html`](https://www.fosshub.com/Rufus.html)获取它。

1.  安装好 Rufus 后，插入您的 USB 闪存盘并打开 Rufus。确保选择了正确的“设备”选项，如*图 0.8*所示。

1.  按“启动选择”下的“选择”按钮，然后打开您下载的 Ubuntu 20.04 镜像。

1.  “分区方案”的选择将取决于您的 BIOS 和磁盘驱动器的配置。对于大多数现代系统来说，`GPT`将是最佳选择，而`MBR`将兼容较旧的系统：![图 0.8：Rufus 配置](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-ws/img/B15021_0_08.jpg)

图 0.8：Rufus 配置

1.  您可以将所有其他选项保留为默认值，然后按“开始”。完成后，关闭 Rufus。现在您已经有一个可启动的 USB 驱动器可以安装 Ubuntu 了。

### 安装 Ubuntu

现在，使用可启动的 USB 驱动器来安装 Ubuntu：

1.  要安装 Ubuntu，使用刚刚创建的可启动安装介质进行引导。在大多数情况下，您只需在启动计算机时插入 USB 驱动器即可。如果您没有自动引导到 Ubuntu 设置界面，请进入 BIOS 设置，并确保您的 USB 设备处于最高的启动优先级，并且安全启动已关闭。通常，在 POST 检查期间，BIOS 设置的输入说明通常显示在启动画面（启动计算机时显示您的 PC 制造商标志的屏幕）上。您也可能在启动时有进入启动菜单的选项。通常情况下，您必须在 PC 启动时按住*Delete*、*F1*、*F2*、*F12*或其他一些键。这取决于您主板的 BIOS。

你应该看到一个带有“尝试 Ubuntu”或“安装 Ubuntu”选项的屏幕。如果你没有看到这个屏幕，而是看到一个以“最小的 BASH 类似行编辑支持…”开头的消息的 shell，那么很可能在下载 ISO 文件或创建可启动的 USB 驱动器时可能发生了一些数据损坏。通过计算你下载文件的`MD5`、`SHA1`或`SHA256`哈希值来检查下载的 ISO 文件的完整性，并将其与你可以在 Ubuntu 下载页面上找到的文件`MD5SUMS`、`SHA1SUMS`或`SHA256SUMS`中的值进行比较。然后，重复上一节中的步骤来重新格式化和重新创建可启动的 USB 驱动器。

如果你已经在 BIOS 中将最高启动优先级设置为正确的 USB 设备，但仍然无法使用 USB 设备启动（你的系统可能会忽略它并启动到 Windows），那么你很可能正在处理以下一个或两个问题：

- USB 驱动器没有正确配置为可识别的可启动设备，或者 GRUB 引导加载程序没有正确设置。验证你下载的镜像的完整性并重新创建可启动的 USB 驱动器应该在大多数情况下解决这个问题。

- 你选择了错误的“分区方案”选项来配置你的系统。尝试另一个选项并重新创建 USB 驱动器。

1.  一旦你使用 USB 驱动器启动你的机器，选择“安装 Ubuntu”。

1.  选择你想要的语言，然后点击“继续”。

1.  在下一个屏幕上，选择适当的键盘布局，并继续到下一个屏幕。

1.  在下一个屏幕上，选择“正常安装”选项。

勾选“在安装 Ubuntu 时下载更新”和“安装用于图形和 Wi-Fi 硬件以及其他媒体格式的第三方软件”选项。

然后，继续到下一个屏幕。

1.  在下一个屏幕上，选择“在 Windows 引导管理器旁边安装 Ubuntu”，然后点击“立即安装”。你会看到一个提示，描述 Ubuntu 将对你的系统进行的更改，比如将要创建的新分区。确认更改并继续到下一个屏幕。

1.  在下一个屏幕上，选择你的地区并点击“继续”。

1.  在下一个屏幕上，设置你的名字（可选）、用户名、计算机名和密码，然后点击“继续”。

安装现在应该开始了。这将需要一些时间，具体取决于您的系统配置。安装完成后，您将收到提示重新启动计算机。拔掉您的 USB 驱动器，然后点击“立即重启”。

如果您忘记拔掉 USB 驱动器，可能会重新启动 Ubuntu 安装。在这种情况下，只需退出设置。如果已启动 Ubuntu 的实时实例，请重新启动您的机器。这次记得拔掉 USB 驱动器。

如果重新启动后，您直接进入 Windows，没有选择操作系统的选项，可能的问题是 Ubuntu 安装的 GRUB 引导加载程序没有优先于 Windows 引导加载程序。在某些系统中，硬盘上引导加载程序的优先级/优先级是在 BIOS 中设置的。您需要在 BIOS 设置菜单中找到适当的设置。它可能被命名为类似于“UEFI 硬盘驱动器优先级”的东西。确保将`GRUB`/`Ubuntu`设置为最高优先级。

安装任何操作系统后，确保所有硬件组件都按预期工作是个好主意。

## 其他要求

**Docker Hub 账户**：您可以在[`hub.docker.com/`](https://hub.docker.com/)免费创建 Docker 账户。

## 访问代码文件

您可以在我们的 GitHub 仓库中找到这个研讨会的完整代码文件，网址为[`packt.live/2RC99QI`](https://packt.live/2RC99QI)。

安装 Git 后，您可以使用以下命令克隆存储库：

```
git clone https://github.com/PacktWorkshops/The-Docker-Workshop
cd The-Docker-Workshop
```

如果您在安装过程中遇到任何问题或有任何疑问，请发送电子邮件至`workshops@packt.com`。


# 第一章：运行我的第一个 Docker 容器

概述

在本章中，您将学习 Docker 和容器化的基础知识，并探索将传统的多层应用程序迁移到快速可靠的容器化基础设施的好处。通过本章的学习，您将对运行容器化应用程序的好处有深入的了解，以及使用`docker run`命令运行容器的基础知识。本章不仅将向您介绍 Docker 的基础知识，还将为您提供对本次研讨会中将要构建的 Docker 概念的扎实理解。

# 介绍

近年来，各行各业的技术创新迅速增加了软件产品交付的速度。由于技术趋势，如敏捷开发（一种快速编写软件的方法）和持续集成管道，使软件的快速交付成为可能，运营人员最近一直在努力快速构建基础设施，以满足不断增长的需求。为了跟上发展，许多组织选择迁移到云基础设施。

云基础设施提供了托管的虚拟化、网络和存储解决方案，可以按需使用。这些提供商允许任何组织或个人注册并获得传统上需要大量空间和昂贵硬件才能在现场或数据中心实施的基础设施。云提供商，如亚马逊网络服务和谷歌云平台，提供易于使用的 API，允许几乎立即创建大量的虚拟机（或 VMs）。

将基础设施部署到云端为组织面临的许多传统基础设施解决了难题，但也带来了与在规模上运行这些服务相关的管理成本的额外问题。公司如何管理全天候运行昂贵服务器的持续月度和年度支出？

虚拟机通过利用 hypervisors 在较大的硬件之上创建较小的服务器，从而革新了基础设施。虚拟化的缺点在于运行虚拟机的资源密集程度。虚拟机本身看起来、行为和感觉都像真正的裸金属硬件，因为 hypervisors（如 Zen、KVM 和 VMWare）分配资源来引导和管理整个操作系统镜像。与虚拟机相关的专用资源使其变得庞大且难以管理。在本地 hypervisor 和云之间迁移虚拟机可能意味着每个虚拟机移动数百 GB 的数据。

为了提供更高程度的自动化，更好地利用计算密度，并优化他们的云存在，公司发现自己朝着容器化和微服务架构的方向迈进作为解决方案。容器提供了进程级别的隔离，或者在主机操作系统内核的隔离部分内运行软件服务。与运行整个操作系统内核以提供隔离不同，容器可以共享主机操作系统的内核来运行多个软件应用程序。这是通过 Linux 内核中的控制组（或 cgroups）和命名空间隔离等功能实现的。在单个虚拟机或裸金属机器上，用户可能会运行数百个容器，这些容器在单个主机操作系统上运行各自的软件应用程序实例。

这与传统的虚拟机架构形成鲜明对比。通常，当我们部署虚拟机时，我们目的是让该机器运行单个服务器或一小部分服务。这会导致宝贵的 CPU 周期的浪费，这些周期本可以分配给其他任务并提供其他请求。理论上，我们可以通过在单个虚拟机上安装多个服务来解决这个困境。然而，这可能会在关于哪台机器运行哪项服务方面造成极大的混乱。它还将多个软件安装和后端依赖项的托管权放在单个操作系统中。

容器化的微服务方法通过允许容器运行时在主机操作系统上调度和运行容器来解决了这个问题。容器运行时不关心容器内运行的是什么应用程序，而是关心容器是否存在，并且可以在主机操作系统上下载和执行。容器内运行的应用程序是 Go web API、简单的 Python 脚本还是传统的 Cobol 应用程序都无关紧要。由于容器是以标准格式存在的，容器运行时将下载容器镜像并在其中执行软件。在本书中，我们将学习 Docker 容器运行时，并学习在本地和规模化运行容器的基础知识。

Docker 是一个容器运行时，于 2013 年开发，旨在利用 Linux 内核的进程隔离功能。与其他容器运行时实现不同的是，Docker 开发了一个系统，不仅可以运行容器，还可以构建和推送容器到容器存储库。这一创新引领了容器不可变性的概念——只有在软件发生变化时才通过构建和推送容器的新版本来改变容器。

如下图所示（*图 1.1*），我们在两个 Docker 服务器上部署了一系列容器化应用程序。在两个服务器实例之间，部署了七个容器化应用程序。每个容器都托管着自己所需的二进制文件、库和自包含的依赖关系。当 Docker 运行一个容器时，容器本身承载了其正常运行所需的一切。甚至可以部署同一应用程序框架的不同版本，因为每个容器都存在于自己的内核空间中。

![图 1.1：在两个不同的容器服务器上运行的七个容器](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-ws/img/B15021_01_01.jpg)

图 1.1：在两个不同的容器服务器上运行的七个容器

在本章中，您将通过容器化的帮助了解 Docker 提供的各种优势。您还将学习使用`docker run`命令来运行容器的基础知识。

# 使用 Docker 的优势

在传统的虚拟机方法中，代码更改需要运维人员或配置管理工具访问该机器并安装软件的新版本。不可变容器的原则意味着当代码更改发生时，将构建新版本的容器映像，并创建为新的构件。如果需要回滚此更改，只需下载并重新启动容器映像的旧版本就可以了。

利用容器化方法还使软件开发团队能够在各种场景和多个环境中可预测和可靠地测试应用程序。由于 Docker 运行时环境提供了标准的执行环境，软件开发人员可以快速重现问题并轻松调试问题。由于容器的不可变性，开发人员可以确保相同的代码在所有环境中运行，因为相同的 Docker 映像可以部署在任何环境中。这意味着配置变量，如无效的数据库连接字符串、API 凭据或其他特定于环境的差异，是故障的主要来源。这减轻了运维负担，并提供了无与伦比的效率和可重用性。

使用 Docker 的另一个优势是，与传统基础设施相比，容器化应用程序通常更小、更灵活。容器通常只提供运行应用程序所需的必要库和软件包，而不是提供完整的操作系统内核和执行环境。

在构建 Docker 容器时，开发人员不再受限于主机操作系统上安装的软件包和工具，这些可能在不同环境之间有所不同。他们可以将容器映像中仅包含应用程序运行所需的确切版本的库和实用程序。在部署到生产机器上时，开发人员和运维团队不再关心容器运行在什么硬件或操作系统版本上，只要他们的容器在运行就可以了。

例如，截至 2020 年 1 月 1 日，Python 2 不再受支持。因此，许多软件仓库正在逐步淘汰 Python 2 包和运行时。利用容器化方法，您可以继续以受控、安全和可靠的方式运行传统的 Python 2 应用程序，直到这些传统应用程序可以被重写。这消除了担心安装操作系统级补丁的恐惧，这些补丁可能会移除 Python 2 支持并破坏传统应用程序堆栈。这些 Python 2 容器甚至可以与 Docker 服务器上的 Python 3 应用程序并行运行，以在这些应用程序迁移到新的现代化堆栈时提供精确的测试。

现在我们已经了解了 Docker 是什么以及它是如何工作的，我们可以开始使用 Docker 来了解进程隔离与虚拟化和其他类似技术的区别。

注意

在我们开始运行容器之前，您必须在本地开发工作站上安装 Docker。有关详细信息，请查看本书的*前言*部分。

# Docker 引擎

**Docker 引擎**是提供对 Linux 内核进程隔离功能的接口。由于只有 Linux 暴露了允许容器运行的功能，因此 Windows 和 macOS 主机利用后台的 Linux 虚拟机来实现容器执行。对于 Windows 和 macOS 用户，Docker 提供了“**Docker 桌面**”套件，用于在后台部署和运行这个虚拟机。这允许从 macOS 或 Windows 主机的终端或 PowerShell 控制台本地执行 Docker 命令。Linux 主机有特权直接在本地执行 Docker 引擎，因为现代版本的 Linux 内核支持`cgroups`和命名空间隔离。

注意

由于 Windows、macOS 和 Linux 在网络和进程管理方面具有根本不同的操作系统架构，本书中的一些示例（特别是在网络方面）有时会根据在您的开发工作站上运行的操作系统而有不同的行为。这些差异会在出现时进行说明。

Docker 引擎不仅支持执行容器镜像，还提供了内置机制，可以从源代码文件（称为`Dockerfiles`）构建和测试容器镜像。构建容器镜像后，可以将其推送到容器镜像注册表。**镜像注册表**是容器镜像的存储库，其他 Docker 主机可以从中下载和执行容器镜像。Docker 引擎支持运行容器镜像、构建容器镜像，甚至在配置为这样运行时托管容器镜像注册表。

当容器启动时，Docker 默认会下载容器镜像，将其存储在本地容器镜像缓存中，最后执行容器的`entrypoint`指令。`entrypoint`指令是启动应用程序主要进程的命令。当这个进程停止或关闭时，容器也将停止运行。

根据容器内运行的应用程序，`entrypoint`指令可能是长期运行的服务器守护程序，始终可用，或者可能是一个短暂的脚本，在执行完成后自然停止。另外，许多容器执行`entrypoint`脚本，在启动主要进程之前完成一系列设置步骤，这可能是长期或短期的。

在运行任何容器之前，最好先了解将在容器内运行的应用程序类型，以及它是短暂执行还是长期运行的服务器守护程序。

# 运行 Docker 容器

构建容器和微服务架构的最佳实践规定，一个容器应该只运行一个进程。牢记这一原则，我们可以设计容器，使其易于构建、故障排除、扩展和部署。

容器的生命周期由容器的状态和其中运行的进程定义。根据操作员、容器编排器或容器内部运行的应用程序的状态，容器可以处于运行或停止状态。例如，操作员可以使用`docker stop`或`docker start`命令手动停止或启动容器。如果 Docker 检测到容器进入不健康状态，它甚至可能自动停止或重新启动容器。此外，如果容器内部运行的主要应用程序失败或停止，运行的容器实例也应该停止。许多容器运行时平台，如 Docker，甚至提供自动机制来自动重新启动进入停止状态的容器。许多容器平台利用这一原则构建作业和任务执行功能。

由于容器在容器内部的主要进程完成时终止，容器是执行脚本和其他类型的具有无限寿命的作业的优秀平台。下面的*图 1.2*说明了典型容器的生命周期：

![图 1.2：典型容器的生命周期](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-ws/img/B15021_01_02.jpg)

图 1.2：典型容器的生命周期

一旦在目标操作系统上下载并安装了 Docker，就可以开始运行容器。Docker CLI 具有一个名为`docker run`的命令，专门用于启动和运行 Docker 容器。正如我们之前学到的，容器提供了与系统上运行的其他应用程序和进程隔离的功能。由于这个事实，Docker 容器的生命周期由容器内部运行的主要进程决定。当容器停止时，Docker 可能会尝试重新启动容器，以确保应用程序的连续性。

为了查看主机系统上正在运行的容器，我们还将利用`docker ps`命令。`docker ps`命令类似于 Unix 风格的`ps`命令，用于显示 Linux 或基于 Unix 的操作系统上运行的进程。

记住，当 Docker 首次运行容器时，如果它在本地缓存中没有存储容器镜像，它将从容器镜像注册表中下载容器镜像。要查看本地存储的容器镜像，使用`docker images`命令。

以下练习将演示如何使用`docker run`、`docker ps`和`docker images`命令来启动和查看简单的`hello-world`容器的状态。

## 练习 1.01：运行 hello-world 容器

一个简单的“Hello World”应用程序通常是开发人员在学习软件开发或开始新的编程语言时编写的第一行代码，容器化也不例外。Docker 发布了一个非常小且简单执行的`hello-world`容器。该容器演示了运行单个具有无限寿命的进程的容器的特性。

在这个练习中，你将使用`docker run`命令启动`hello-world`容器，并使用`docker ps`命令查看容器在执行完成后的状态。这将为你提供一个在本地开发环境中运行容器的基本概述。

1.  在 Bash 终端或 PowerShell 窗口中输入`docker run`命令。这会指示 Docker 运行一个名为`hello-world`的容器：

```
$ docker run hello-world
```

你的 shell 应该返回类似以下的输出：

```
Unable to find image 'hello-world: latest' locally
latest: Pulling from library/hello-world
0e03bdcc26d7: Pull complete 
Digest: sha256:
8e3114318a995a1ee497790535e7b88365222a21771ae7e53687ad76563e8e76
Status: Downloaded newer image for hello-world:latest
Hello from Docker!
This message shows that your installation appears to be working 
correctly.
To generate this message, Docker took the following steps:
 1\. The Docker client contacted the Docker daemon.
 2\. The Docker daemon pulled the "hello-world" image from the 
Docker Hub.
    (amd64)
 3\. The Docker daemon created a new container from that image 
which runs the executable that produces the output you are 
currently reading.
4\. The Docker daemon streamed that output to the Docker 
client, which sent it to your terminal.
To try something more ambitious, you can run an Ubuntu 
container with:
 $ docker run -it ubuntu bash
Share images, automate workflows, and more with a free Docker ID:
 https://hub.docker.com/
For more examples and ideas, visit:
 https://docs.docker.com/get-started/
```

刚刚发生了什么？你告诉 Docker 运行名为`hello-world`的容器。所以，首先，Docker 会在本地容器缓存中查找具有相同名称的容器。如果找不到，它将尝试在互联网上的容器注册表中查找以满足命令。通过简单地指定容器的名称，Docker 将默认查询 Docker Hub 以获取该名称的已发布容器镜像。

如你所见，它能够找到一个名为`library/hello-world`的容器，并开始逐层拉取容器镜像。在*第二章*《使用 Dockerfiles 入门》中，你将更深入地了解容器镜像和层。一旦镜像完全下载，Docker 运行该镜像，显示`Hello from Docker`输出。由于该镜像的主要进程只是显示该输出，容器在显示输出后停止并停止运行。

1.  使用`docker ps`命令查看系统上正在运行的容器。在 Bash 或 PowerShell 终端中，输入以下命令：

```
$ docker ps
```

这将返回类似以下的输出：

```
CONTAINER ID      IMAGE     COMMAND      CREATED
  STATUS              PORTS                   NAMES
```

`docker ps`命令的输出为空，因为它默认只显示当前正在运行的容器。这类似于 Linux/Unix 的`ps`命令，它只显示正在运行的进程。

1.  使用`docker ps -a`命令显示所有容器，甚至是已停止的容器：

```
$ docker ps -a
```

在返回的输出中，你应该看到`hello-world`容器实例：

```
CONTAINER ID     IMAGE           COMMAND     CREATED
  STATUS                          PORTS         NAMES
24c4ce56c904     hello-world     "/hello"    About a minute ago
  Exited (0) About a minute ago                 inspiring_moser
```

正如你所看到的，Docker 给容器分配了一个唯一的容器 ID。它还显示了运行的`IMAGE`，在该映像中执行的`COMMAND`，创建的`TIME`，以及运行该容器的进程的`STATUS`，以及一个唯一的可读名称。这个特定的容器大约一分钟前创建，执行了程序`/hello`，并成功运行。你可以看出程序运行并成功执行，因为它产生了一个`Exited (0)`的代码。

1.  你可以查询你的系统，看看 Docker 本地缓存了哪些容器映像。执行`docker images`命令来查看本地缓存：

```
$ docker images
```

返回的输出应该显示本地缓存的容器映像：

```
REPOSITORY     TAG        IMAGE ID        CREATED         SIZE
hello-world    latest     bf756fb1ae65    3 months ago    13.3kB
```

到目前为止，唯一缓存的映像是`hello-world`容器映像。这个映像正在运行`latest`版本，创建于 3 个月前，大小为 13.3 千字节。从前面的输出中，你知道这个 Docker 映像非常精简，开发者在 3 个月内没有发布过这个映像的代码更改。这个输出对于排除现实世界中软件版本之间的差异非常有帮助。

由于你只是告诉 Docker 运行`hello-world`容器而没有指定版本，Docker 将默认拉取最新版本。你可以通过在`docker run`命令中指定标签来指定不同的版本。例如，如果`hello-world`容器映像有一个版本`2.0`，你可以使用`docker run hello-world:2.0`命令运行该版本。

想象一下，如果容器比一个简单的`hello-world`应用程序复杂一些。想象一下，你的同事编写了一个软件，需要下载许多第三方库的非常特定的版本。如果你传统地运行这个应用程序，你将不得不下载他们开发语言的运行环境，以及所有的第三方库，以及详细的构建和执行他们的代码的说明。

然而，如果他们将他们的代码的 Docker 镜像发布到内部 Docker 注册表，他们只需要向您提供运行容器的`docker run`语法。由于您拥有 Docker，无论您的基础平台是什么，容器图像都将运行相同。容器图像本身已经包含了库和运行时的详细信息。

1.  如果您再次执行相同的`docker run`命令，那么对于用户输入的每个`docker run`命令，都将创建一个新的容器实例。值得注意的是，容器化的一个好处是能够轻松运行多个软件应用的实例。为了看到 Docker 如何处理多个容器实例，再次运行相同的`docker run`命令，以创建`hello-world`容器的另一个实例：

```
$ docker run hello-world
```

您应该看到以下输出：

```
Hello from Docker!
This message shows that your installation appears to be 
working correctly.
To generate this message, Docker took the following steps:
 1\. The Docker client contacted the Docker daemon.
 2\. The Docker daemon pulled the "hello-world" image from 
    the Docker Hub.
    (amd64)
 3\. The Docker daemon created a new container from that image 
    which runs the executable that produces the output you 
    are currently reading.
 4\. The Docker daemon streamed that output to the Docker client, 
    which sent it to your terminal.
To try something more ambitious, you can run an Ubuntu container 
with:
 $ docker run -it ubuntu bash
Share images, automate workflows, and more with a free Docker ID:
 https://hub.docker.com/
For more examples and ideas, visit:
 https://docs.docker.com/get-started/
```

请注意，这一次，Docker 不必再次从 Docker Hub 下载容器图像。这是因为您现在在本地缓存了该容器图像。相反，Docker 能够直接运行容器并将输出显示在屏幕上。让我们看看您的`docker ps -a`输出现在是什么样子。

1.  在您的终端中，再次运行`docker ps -a`命令：

```
docker ps -a
```

在输出中，您应该看到这个容器图像的第二个实例已经完成了执行并进入了停止状态，如输出的`STATUS`列中的`Exit (0)`所示：

```
CONTAINER ID     IMAGE           COMMAND       CREATED
  STATUS                      PORTS               NAMES
e86277ca07f1     hello-world     "/hello"      2 minutes ago
  Exited (0) 2 minutes ago                        awesome_euclid
24c4ce56c904     hello-world     "/hello"      20 minutes ago
  Exited (0) 20 minutes ago                       inspiring_moser
```

您现在在输出中看到了这个容器的第二个实例。每次执行`docker run`命令时，Docker 都会创建该容器的一个新实例，具有其属性和数据。您可以运行尽可能多的容器实例，只要您的系统资源允许。在这个例子中，您 20 分钟前创建了一个实例。您 2 分钟前创建了第二个实例。

1.  再次执行`docker images`命令，检查基本图像：

```
$ docker images
```

返回的输出将显示 Docker 从单个基本图像创建的两个运行实例：

```
REPOSITORY     TAG       IMAGE ID        CREATED         SIZE
hello-world    latest    bf756fb1ae65    3 months ago    13.3kB
```

在这个练习中，您使用`docker run`启动了`hello-world`容器。为了实现这一点，Docker 从 Docker Hub 注册表下载了图像，并在 Docker Engine 中执行了它。一旦基本图像被下载，您可以使用后续的`docker run`命令创建任意数量的该容器的实例。

Docker 容器管理比在开发环境中仅仅启动和查看容器状态更加复杂。Docker 还支持许多其他操作，这些操作有助于了解在 Docker 主机上运行的应用程序的状态。在接下来的部分中，我们将学习如何使用不同的命令来管理 Docker 容器。

# 管理 Docker 容器

在我们的容器之旅中，我们将经常从本地环境中拉取、启动、停止和删除容器。在将容器部署到生产环境之前，我们首先需要在本地运行容器，以了解其功能和正常行为。这包括启动容器、停止容器、获取有关容器运行方式的详细信息，当然还包括访问容器日志以查看容器内运行的应用程序的关键细节。这些基本命令如下所述：

+   `docker pull`：此命令将容器镜像下载到本地缓存

+   `docker stop`：此命令停止运行中的容器实例

+   `docker start`：此命令启动不再处于运行状态的容器实例

+   `docker restart`：此命令重新启动运行中的容器

+   `docker attach`：此命令允许用户访问（或附加）运行中的 Docker 容器实例的主要进程

+   `docker exec`：此命令在运行中的容器内执行命令

+   `docker rm`：此命令删除已停止的容器

+   `docker rmi`：此命令删除容器镜像

+   `docker inspect`：此命令显示有关容器状态的详细信息

容器生命周期管理是生产环境中有效容器管理的关键组成部分。在评估容器化基础设施的健康状况时，了解如何调查运行中的容器是至关重要的。

在接下来的练习中，我们将逐个使用这些命令，深入了解它们的工作原理以及如何利用它们来了解容器化基础设施的健康状况。

## 练习 1.02：管理容器生命周期

在开发和生产环境中管理容器时，了解容器实例的状态至关重要。许多开发人员使用包含特定基线配置的基础容器镜像，他们的应用程序可以在其上部署。Ubuntu 是一个常用的基础镜像，用户用它来打包他们的应用程序。

与完整的操作系统镜像不同，Ubuntu 基础容器镜像非常精简，故意省略了许多完整操作系统安装中的软件包。大多数基础镜像都有软件包系统，可以让您安装任何缺失的软件包。

请记住，在构建容器镜像时，您希望尽可能保持基础镜像的精简，只安装最必要的软件包。这样可以确保 Docker 主机可以快速拉取和启动容器镜像。

在这个练习中，您将使用官方的 Ubuntu 基础容器镜像。这个镜像将用于启动容器实例，用于测试各种容器生命周期管理命令，比如`docker pull`、`docker start`和`docker stop`。这个容器镜像很有用，因为默认的基础镜像允许我们在长时间运行的会话中运行容器实例，以了解容器生命周期管理命令的功能。在这个练习中，您还将拉取`Ubuntu 18.04`容器镜像，并将其与`Ubuntu 19.04`容器镜像进行比较：

1.  在新的终端或 PowerShell 窗口中，执行`docker pull`命令以下载`Ubuntu 18.04`容器镜像：

```
$ docker pull ubuntu:18.04
```

您应该看到以下输出，表明 Docker 正在下载基础镜像的所有层：

```
5bed26d33875: Pull complete 
f11b29a9c730: Pull complete 
930bda195c84: Pull complete 
78bf9a5ad49e: Pull complete 
Digest: sha256:bec5a2727be7fff3d308193cfde3491f8fba1a2ba392
        b7546b43a051853a341d
Status: Downloaded newer image for ubuntu:18.04
docker.io/library/ubuntu:18.04
```

1.  使用`docker pull`命令下载`Ubuntu 19.04`基础镜像：

```
$ docker pull ubuntu:19.04
```

当 Docker 下载`Ubuntu 19.04`基础镜像时，您将看到类似的输出：

```
19.04: Pulling from library/ubuntu
4dc9c2fff018: Pull complete 
0a4ccbb24215: Pull complete 
c0f243bc6706: Pull complete 
5ff1eaecba77: Pull complete 
Digest: sha256:2adeae829bf27a3399a0e7db8ae38d5adb89bcaf1bbef
        378240bc0e6724e8344
Status: Downloaded newer image for ubuntu:19.04
docker.io/library/ubuntu:19.04
```

1.  使用`docker images`命令确认容器镜像已下载到本地容器缓存：

```
$ docker images
```

本地容器缓存的内容将显示`Ubuntu 18.04`和`Ubuntu 19.04`基础镜像，以及我们之前练习中的`hello-world`镜像：

```
REPOSITORY     TAG        IMAGE ID         CREATED         SIZE
ubuntu         18.04      4e5021d210f6     4 weeks ago     64.2MB
ubuntu         19.04      c88ac1f841b7     3 months ago    70MB
hello-world    latest     bf756fb1ae65     3 months ago    13.3kB
```

1.  在运行这些镜像之前，使用`docker inspect`命令获取关于容器镜像的详细输出以及它们之间的差异。在你的终端中，运行`docker inspect`命令，并使用`Ubuntu 18.04`容器镜像的 ID 作为主要参数：

```
$ docker inspect 4e5021d210f6
```

`inspect`输出将包含定义该容器的所有属性的大型列表。例如，你可以看到容器中配置了哪些环境变量，容器在最后一次更新镜像时是否设置了主机名，以及定义该容器的所有层的详细信息。这个输出包含了在规划升级时可能会有价值的关键调试细节。以下是`inspect`命令的截断输出。在`Ubuntu 18.04`镜像中，`"Created"`参数应该提供构建容器镜像的日期和时间：

```
"Id": "4e5021d210f6d4a0717f4b643409eff23a4dc01c4140fa378b1b
       f0a4f8f4",
"Created": "2020-03-20T19:20:22.835345724Z",
"Path": "/bin/bash",
"Args": [],
```

1.  检查`Ubuntu 19.04`容器，你会看到这个参数是不同的。在`Ubuntu 19.04`容器镜像 ID 中运行`docker inspect`命令：

```
$ docker inspect c88ac1f841b7
```

在显示的输出中，你会看到这个容器镜像是在一个不同的日期创建的，与`18.04`容器镜像不同：

```
"Id": "c88ac1f841b74e5021d210f6d4a0717f4b643409eff23a4dc0
       1c4140fa"
"Created": "2020-01-16T01:20:46.938732934Z",
"Path": "/bin/bash",
"Args": []
```

如果你知道 Ubuntu 基础镜像中可能存在安全漏洞，这可能是至关重要的信息。这些信息也可以对帮助你确定要运行哪个版本的容器至关重要。

1.  在检查了两个容器镜像之后，很明显你最好的选择是坚持使用 Ubuntu 长期支持版 18.04 版本。正如你从前面的输出中看到的，18.04 版本比 19.04 版本更加更新。这是可以预期的，因为 Ubuntu 通常会为长期支持版本提供更稳定的更新。

1.  使用`docker run`命令启动 Ubuntu 18.04 容器的一个实例：

```
$ docker run -d ubuntu:18.04
```

请注意，这次我们使用了带有`-d`标志的`docker run`命令。这告诉 Docker 以守护进程模式（或后台模式）运行容器。如果我们省略`-d`标志，容器将占用我们当前的终端，直到容器内的主要进程终止。

注意

成功调用`docker run`命令通常只会返回容器 ID 作为输出。某些版本的 Docker 不会返回任何输出。

1.  使用`docker ps -a`命令检查容器的状态：

```
$ docker ps -a
```

这将显示类似于以下内容的输出：

```
CONTAINER ID     IMAGE           COMMAND        CREATED
  STATUS                     PORTS         NAMES
c139e44193de     ubuntu:18.04    "/bin/bash"    6 seconds ago
  Exited (0) 4 seconds ago                 xenodochial_banzai
```

正如你所看到的，你的容器已经停止并退出。这是因为容器内的主要进程是`/bin/bash`，这是一个 shell。Bash shell 不能在没有以交互模式执行的情况下运行，因为它期望来自用户的文本输入和输出。

1.  再次运行`docker run`命令，传入`-i`标志以使会话交互（期望用户输入），并传入`-t`标志以为容器分配一个**伪 tty**处理程序。`伪 tty`处理程序将基本上将用户的终端链接到容器内运行的交互式 Bash shell。这将允许 Bash 正确运行，因为它将指示容器以交互模式运行，期望用户输入。您还可以通过传入`--name`标志为容器指定一个易读的名称。在您的 Bash 终端中键入以下命令：

```
$ docker run -i -t -d --name ubuntu1 ubuntu:18.04
```

1.  再次执行`docker ps -a`命令以检查容器实例的状态：

```
$ docker ps -a 
```

您现在应该看到新的实例正在运行，以及刚刚无法启动的实例：

```
CONTAINER ID    IMAGE          COMMAND         CREATED
  STATUS            PORTS               NAMES
f087d0d92110    ubuntu:18.04   "/bin/bash"     4 seconds ago
  Up 2 seconds                          ubuntu1
c139e44193de    ubuntu:18.04   "/bin/bash"     5 minutes ago
  Exited (0) 5 minutes ago              xenodochial_banzai
```

1.  您现在有一个正在运行的 Ubuntu 容器。您可以使用`docker exec`命令在此容器内运行命令。运行`exec`命令以访问 Bash shell，这将允许我们在容器内运行命令。类似于`docker run`，传入`-i`和`-t`标志使其成为交互式会话。还传入容器的名称或 ID，以便 Docker 知道您要定位哪个容器。`docker exec`的最后一个参数始终是您希望执行的命令。在这种情况下，它将是`/bin/bash`，以在容器实例内启动 Bash shell：

```
docker exec -it ubuntu1 /bin/bash
```

您应该立即看到您的提示更改为根 shell。这表明您已成功在 Ubuntu 容器内启动了一个 shell。容器的主机名`cfaa37795a7b`取自容器 ID 的前 12 个字符。这使用户可以确定他们正在访问哪个容器，如下例所示：

```
root@cfaa37795a7b:/#
```

1.  在容器内，您所拥有的工具非常有限。与 VM 镜像不同，容器镜像在预安装的软件包方面非常精简。但是`echo`命令应该是可用的。使用`echo`将一个简单的消息写入文本文件：

```
root@cfaa37795a7b:/# echo "Hello world from ubuntu1" > hello-world.txt
```

1.  运行`exit`命令退出`ubuntu1`容器的 Bash shell。您应该返回到正常的终端 shell：

```
root@cfaa37795a7b:/# exit
```

该命令将返回以下输出。请注意，对于运行该命令的每个用户，输出可能会有所不同：

```
user@developmentMachine:~/
```

1.  现在创建一个名为`ubuntu2`的第二个容器，它也将在您的 Docker 环境中使用`Ubuntu 19.04`镜像运行：

```
$ docker run -i -t -d --name ubuntu2 ubuntu:19.04
```

1.  运行`docker exec`来访问第二个容器的 shell。记得使用你创建的新容器的名称或容器 ID。同样地，访问这个容器内部的 Bash shell，所以最后一个参数将是`/bin/bash`：

```
$ docker exec -it ubuntu2 /bin/bash
```

你应该观察到你的提示会变成一个 Bash root shell，类似于`Ubuntu 18.04`容器镜像的情况：

```
root@875cad5c4dd8:/#
```

1.  在`ubuntu2`容器实例内部运行`echo`命令，写入类似的`hello-world`类型的问候语：

```
root@875cad5c4dd8:/# echo "Hello-world from ubuntu2!" > hello-world.txt
```

1.  目前，在你的 Docker 环境中有两个运行中的 Ubuntu 容器实例，根账户的主目录中有两个单独的`hello-world`问候消息。使用`docker ps`来查看这两个运行中的容器镜像：

```
$ docker ps
```

运行容器的列表应该反映出两个 Ubuntu 容器，以及它们创建后经过的时间：

```
CONTAINER ID    IMAGE            COMMAND        CREATED
  STATUS              PORTS               NAMES
875cad5c4dd8    ubuntu:19.04     "/bin/bash"    3 minutes ago
  Up 3 minutes                            ubuntu2
cfaa37795a7b    ubuntu:18.04     "/bin/bash"    15 minutes ago
  Up 15 minutes                           ubuntu1
```

1.  不要使用`docker exec`来访问容器内部的 shell，而是使用它来显示你通过在容器内执行`cat`命令写入的`hello-world.txt`文件的输出：

```
$ docker exec -it ubuntu1 cat hello-world.txt
```

输出将显示你在之前步骤中传递给容器的`hello-world`消息。请注意，一旦`cat`命令完成并显示输出，用户就会被移回到主终端的上下文中。这是因为`docker exec`会话只会存在于用户执行命令的时间内。

在之前的 Bash shell 示例中，只有用户使用`exit`命令终止它时，Bash 才会退出。在这个例子中，只显示了`Hello world`输出，因为`cat`命令显示了输出并退出，结束了`docker exec`会话：

```
Hello world from ubuntu1
```

你会看到`hello-world`文件的内容显示，然后返回到你的主终端会话。

1.  在`ubuntu2`容器实例中运行相同的`cat`命令：

```
$ docker exec -it ubuntu2 cat hello-world.txt
```

与第一个例子类似，`ubuntu2`容器实例将显示之前提供的`hello-world.txt`文件的内容：

```
Hello-world from ubuntu2!
```

正如你所看到的，Docker 能够在两个容器上分配一个交互式会话，执行命令，并直接返回输出到我们正在运行的容器实例中。

1.  与你用来在运行中的容器内执行命令的方式类似，你也可以停止、启动和重新启动它们。使用`docker stop`命令停止其中一个容器实例。在你的终端会话中，执行`docker stop`命令，然后是`ubuntu2`容器的名称或容器 ID：

```
$ docker stop ubuntu2
```

该命令应该不返回任何输出。

1.  使用`docker ps`命令查看所有正在运行的容器实例：

```
$ docker ps
```

输出将显示`ubuntu1`容器正在运行：

```
CONTAINER ID    IMAGE           COMMAND        CREATED
  STATUS              PORTS               NAMES
cfaa37795a7b    ubuntu:18.04    "/bin/bash"    26 minutes ago
  Up 26 minutes                           ubuntu1
```

1.  执行`docker ps -a`命令以查看所有容器实例，无论它们是否正在运行，以查看您的容器是否处于停止状态：

```
$ docker ps -a
```

该命令将返回以下输出：

```
CONTAINER ID     IMAGE            COMMAND         CREATED
  STATUS                      PORTS             NAMES
875cad5c4dd8     ubuntu:19.04     "/bin/bash"     14 minutes ago
  Exited (0) 6 seconds ago                      ubuntu2
```

1.  使用`docker start`或`docker restart`命令重新启动容器实例：

```
$ docker start ubuntu2
```

该命令将不返回任何输出，尽管某些版本的 Docker 可能会显示容器 ID。

1.  使用`docker ps`命令验证容器是否再次运行：

```
$ docker ps
```

注意`STATUS`显示该容器只运行了很短的时间（`1 秒`），尽管容器实例是 29 分钟前创建的：

```
CONTAINER ID    IMAGE           COMMAND         CREATED
  STATUS              PORTS               NAMES
875cad5c4dd8    ubuntu:19.04    "/bin/bash"     17 minutes ago
  Up 1 second                             ubuntu2
cfaa37795a7b    ubuntu:18.04    "/bin/bash"     29 minutes ago
  Up 29 minutes                           ubuntu1
```

从这个状态开始，您可以尝试启动、停止或在这些容器内执行命令。

1.  容器管理生命周期的最后阶段是清理您创建的容器实例。使用`docker stop`命令停止`ubuntu1`容器实例：

```
$ docker stop ubuntu1
```

该命令将不返回任何输出，尽管某些版本的 Docker 可能会返回容器 ID。

1.  执行相同的`docker stop`命令以停止`ubuntu2`容器实例：

```
$ docker stop ubuntu2
```

1.  当容器实例处于停止状态时，使用`docker rm`命令彻底删除容器实例。使用`docker rm`后跟名称或容器 ID 删除`ubuntu1`容器实例：

```
$ docker rm ubuntu1
```

该命令将不返回任何输出，尽管某些版本的 Docker 可能会返回容器 ID。

在`ubuntu2`容器实例上执行相同的步骤：

```
$ docker rm ubuntu2
```

1.  执行`docker ps -a`以查看所有容器，即使它们处于停止状态。您会发现停止的容器由于之前的命令已被删除。您也可以删除`hello-world`容器实例。使用从`docker ps -a`输出中捕获的容器 ID 删除`hello-world`容器：

```
$ docker rm b291785f066c
```

1.  要完全重置我们的 Docker 环境状态，请删除您在此练习中下载的基本图像。使用`docker images`命令查看缓存的基本图像：

```
$ docker images
```

您的本地缓存中将显示 Docker 图像列表和所有关联的元数据：

```
REPOSITORY     TAG        IMAGE ID        CREATED         SIZE
ubuntu         18.04      4e5021d210f6    4 weeks ago     64.2MB
ubuntu         19.04      c88ac1f841b7    3 months ago    70MB
hello-world    latest     bf756fb1ae65    3 months ago    13.3kB
```

1.  执行`docker rmi`命令，后跟图像 ID 以删除第一个图像 ID：

```
$ docker rmi 4e5021d210f6
```

类似于`docker pull`，`rmi`命令将删除每个图像和所有关联的层：

```
Untagged: ubuntu:18.04
Untagged: ubuntu@sha256:bec5a2727be7fff3d308193cfde3491f8fba1a2b
a392b7546b43a051853a341d
Deleted: sha256:4e5021d210f65ebe915670c7089120120bc0a303b9020859
2851708c1b8c04bd
Deleted: sha256:1d9112746e9d86157c23e426ce87cc2d7bced0ba2ec8ddbd
fbcc3093e0769472
Deleted: sha256:efcf4a93c18b5d01aa8e10a2e3b7e2b2eef0378336456d86
53e2d123d6232c1e
Deleted: sha256:1e1aa31289fdca521c403edd6b37317bf0a349a941c7f19b
6d9d311f59347502
Deleted: sha256:c8be1b8f4d60d99c281fc2db75e0f56df42a83ad2f0b0916
21ce19357e19d853
```

对于要删除的每个映像，执行此步骤，替换各种映像 ID。对于删除的每个基本映像，您将看到所有图像层都被取消标记并与其一起删除。

定期清理 Docker 环境很重要，因为频繁构建和运行容器会导致长时间大量的硬盘使用。现在您已经知道如何在本地开发环境中运行和管理 Docker 容器，可以使用更高级的 Docker 命令来了解容器的主要进程功能以及如何解决问题。在下一节中，我们将看看`docker attach`命令，直接访问容器的主要进程。

注意

为了简化清理环境的过程，Docker 提供了一个`prune`命令，将自动删除旧的容器和基本映像：

`$ docker system prune -fa`

执行此命令将删除任何未绑定到现有运行容器的容器映像，以及 Docker 环境中的任何其他资源。

# 使用 attach 命令附加到容器

在上一个练习中，您看到了如何使用`docker exec`命令在运行的容器实例中启动新的 shell 会话以执行命令。`docker exec`命令非常适合快速访问容器化实例以进行调试、故障排除和了解容器运行的上下文。

但是，正如本章前面所述，Docker 容器按照容器内部运行的主要进程的生命周期运行。当此进程退出时，容器将停止。如果要直接访问容器内部的主要进程（而不是次要的 shell 会话），那么 Docker 提供了`docker attach`命令来附加到容器内部正在运行的主要进程。

使用`docker attach`时，您可以访问容器中运行的主要进程。如果此进程是交互式的，例如 Bash 或 Bourne shell 会话，您将能够通过`docker attach`会话直接执行命令（类似于`docker exec`）。但是，如果容器中的主要进程终止，整个容器实例也将终止，因为 Docker 容器的生命周期取决于主要进程的运行状态。

在接下来的练习中，您将使用`docker attach`命令直接访问 Ubuntu 容器的主要进程。默认情况下，此容器的主要进程是`/bin/bash`。

## 练习 1.03：附加到 Ubuntu 容器

`docker attach`命令用于在主要进程的上下文中附加到运行中的容器。在此练习中，您将使用`docker attach`命令附加到运行中的容器并直接调查主容器`entrypoint`进程：

1.  使用`docker run`命令启动一个新的 Ubuntu 容器实例。以交互模式（`-i`）运行此容器，分配一个 TTY 会话（`-t`），并在后台（`-d`）运行。将此容器命名为`attach-example1`：

```
docker run -itd --name attach-example1 ubuntu:latest
```

这将使用 Ubuntu 容器图像的最新版本启动一个名为`attach-example1`的新 Ubuntu 容器实例。

1.  使用`docker ps`命令来检查该容器是否在我们的环境中运行：

```
docker ps 
```

将显示运行中容器实例的详细信息。请注意，此容器的主要进程是 Bash shell（`/bin/bash`）：

```
CONTAINER ID    IMAGE            COMMAND          CREATED
  STATUS              PORTS               NAMES
90722712ae93    ubuntu:latest    "/bin/bash"      18 seconds ago
  Up 16 seconds                           attach-example1
```

1.  运行`docker attach`命令以附加到此容器内部的主要进程（`/bin/bash`）。使用`docker attach`后跟容器实例的名称或 ID：

```
$ docker attach attach-example1
```

这应该将您放入此容器实例的主 Bash shell 会话中。请注意，您的终端会话应更改为根 shell 会话，表示您已成功访问了容器实例：

```
root@90722712ae93:/#
```

在这里需要注意，使用诸如`exit`之类的命令来终止 shell 会话将导致停止容器实例，因为您现在已连接到容器实例的主要进程。默认情况下，Docker 提供了*Ctrl* + *P*然后*Ctrl* + *Q*的快捷键序列，以正常分离`attach`会话。

1.  使用键盘组合*Ctrl* + *P*然后*Ctrl* + *Q*正常分离此会话：

```
root@90722712ae93:/# CTRL-p CTRL-q
```

注意

您不会输入`CTRL-p CTRL-q`这些单词；相反，您将按住*Ctrl*键，按下*P*键，然后释放两个键。然后，再次按住*Ctrl*键，按下*Q*键，然后再次释放两个键。

成功分离容器后，将显示单词`read escape sequence`，然后将您返回到主终端或 PowerShell 会话：

```
root@90722712ae93:/# read escape sequence
```

1.  使用`docker ps`验证 Ubuntu 容器是否仍然按预期运行：

```
$ docker ps
```

`attach-example1`容器将被显示为预期运行：

```
CONTAINER ID    IMAGE            COMMAND          CREATED
  STATUS              PORTS               NAMES
90722712ae93    ubuntu:latest    "/bin/bash"      13 minutes ago
  Up 13 minutes                           attach-example1
```

1.  使用`docker attach`命令再次附加到`attach-example1`容器实例：

```
$ docker attach attach-example1
```

您应该被放回到主进程的 Bash 会话中：

```
root@90722712ae93:/#
```

1.  现在，使用`exit`命令终止这个容器的主进程。在 Bash shell 会话中，输入`exit`命令：

```
root@90722712ae93:/# exit
```

终端会话应该已经退出，再次返回到您的主终端。

1.  使用`docker ps`命令观察`attach-example1`容器不再运行：

```
$ docker ps
```

这应该不会显示任何正在运行的容器实例：

```
CONTAINER ID    IMAGE            COMMAND              CREATED
  STATUS              PORTS               NAMES
```

1.  使用`docker ps -a`命令查看所有容器，即使已停止或已退出的容器也会显示：

```
$ docker ps -a
```

这应该显示`attach-example1`容器处于停止状态：

```
CONTAINER ID      IMAGE                COMMAND 
  CREATED            STATUS    PORTS           NAMES
90722712ae93      ubuntu:latest        "/bin/bash"
  20 minutes ago     Exited (0) 3 minutes ago  attach-example1
```

正如你所看到的，容器已经优雅地终止（`Exited (0)`）大约 3 分钟前。`exit`命令会优雅地终止 Bash shell 会话。

1.  使用`docker system prune -fa`命令清理已停止的容器实例：

```
docker system prune -fa
```

这应该删除所有已停止的容器实例，包括`attach-example1`容器实例，如下面的输出所示：

```
Deleted Containers:
ry6v87v9a545hjn7535jk2kv9x8cv09wnkjnscas98v7a762nvnw7938798vnand
Deleted Images:
untagged: attach-example1
```

在这个练习中，我们使用`docker attach`命令直接访问正在运行的容器的主进程。这与我们在本章中早些时候探讨的`docker exec`命令不同，因为`docker exec`在运行的容器内执行一个新的进程，而`docker attach`直接附加到容器的主进程。然而，在附加到容器时，必须注意不要通过终止主进程来停止容器。

在下一个活动中，我们将整合本章中涵盖的 Docker 管理命令，开始组装成全景徒步旅行微服务应用程序堆栈的构建块容器。

## 活动 1.01：从 Docker Hub 拉取并运行 PostgreSQL 容器镜像

全景徒步旅行是我们将在本书中构建的多层 Web 应用程序。与任何 Web 应用程序类似，它将包括一个 Web 服务器容器（NGINX）、一个 Python Django 后端应用程序和一个 PostgreSQL 数据库。在部署 Web 应用程序或前端 Web 服务器之前，您必须先部署后端数据库。

在这个活动中，您被要求使用默认凭据启动一个 PostgreSQL 版本 12 的数据库容器。

注意

官方的 Postgres 容器映像提供了许多环境变量覆盖，您可以利用这些变量来配置 PostgreSQL 实例。在 Docker Hub 上查看有关容器的文档[`hub.docker.com/_/postgres`](https://hub.docker.com/_/postgres)。

执行以下步骤：

1.  创建一个 Postgres 数据库容器实例，将作为我们应用程序堆栈的数据层。

1.  使用环境变量在运行时配置容器以使用以下数据库凭据：

```
username: panoramic
password: trekking
```

1.  验证容器是否正在运行和健康。

**预期输出：**

运行`docker ps`命令应返回以下输出：

```
CONTAINER ID  IMAGE         COMMAND                 CREATED
  STATUS              PORTS               NAMES
29f115af8cdd  postgres:12   "docker-entrypoint.s…"  4 seconds ago
  Up 2 seconds        5432/tcp            blissful_kapitsa
```

注意

此活动的解决方案可以通过此链接找到。

在下一个活动中，您将访问刚刚在容器实例中设置的数据库。您还将与容器交互，以获取容器中运行的数据库列表。

## 活动 1.02：访问全景徒步应用程序数据库

本活动将涉及使用`PSQL` CLI 实用程序访问在容器实例内运行的数据库。一旦您使用凭据（`panoramic/trekking`）登录，您将查询容器中运行的数据库列表。

执行以下步骤：

1.  使用 PSQL 命令行实用程序登录到 Postgres 数据库容器。

1.  登录到数据库后，默认情况下返回 Postgres 中的数据库列表。

注意

如果您对 PSQL CLI 不熟悉，以下是一些参考命令的列表，以帮助您完成此活动：

登录：`psql --username username --password`

列出数据库：`\l`

退出 PSQL shell：`\q`

**预期输出：**

![图 1.3：活动 1.02 的预期输出](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-ws/img/B15021_01_03.jpg)

图 1.3：活动 1.02 的预期输出

注意

此活动的解决方案可以通过此链接找到。

# 摘要

在本章中，您学习了容器化的基础知识，以及在容器中运行应用程序的好处，以及管理容器化实例的基本 Docker 生命周期命令。您了解到容器作为一个真正可以构建一次并在任何地方运行的通用软件部署包。因为我们在本地运行 Docker，我们可以确信在我们的本地环境中运行的相同容器映像可以部署到生产环境并且可以放心地运行。

通过诸如`docker run`、`docker start`、`docker exec`、`docker ps`和`docker stop`之类的命令，我们通过 Docker CLI 探索了容器生命周期管理的基础知识。通过各种练习，我们从相同的基础映像启动了容器实例，使用`docker exec`对其进行了配置，并使用其他基本的容器生命周期命令（如`docker rm`和`docker rmi`）清理了部署。

在本章的最后部分，我们毅然决然地迈出了第一步，通过启动一个 PostgreSQL 数据库容器实例，开始运行我们的全景徒步应用程序。我们在`docker run`命令中使用环境变量创建了一个配置了默认用户名和密码的实例。我们通过在容器内部执行 PSQL 命令行工具并查询数据库来测试配置，以查看模式。

虽然这只是触及 Docker 能力表面的一部分，但我们希望它能激发你对即将在后续章节中涵盖的内容的兴趣。在下一章中，我们将讨论使用`Dockerfiles`和`docker build`命令构建真正不可变的容器。编写自定义的`Dockerfiles`来构建和部署独特的容器映像将展示在规模上运行容器化应用程序的强大能力。


# 第二章：使用 Dockerfile 入门

概述

在本章中，您将学习`Dockerfile`及其指令的形式和功能，包括`FROM`、`LABEL`和`CMD`，您将使用这些指令来 dockerize 一个应用程序。本章将为您提供关于 Docker 镜像的分层文件系统和在 Docker 构建过程中使用缓存的知识。在本章结束时，您将能够使用常见指令编写`Dockerfile`并使用`Dockerfile`构建自定义 Docker 镜像。

# 介绍

在上一章中，我们学习了如何通过从 Docker Hub 拉取预构建的 Docker 镜像来运行我们的第一个 Docker 容器。虽然从 Docker Hub 获取预构建的 Docker 镜像很有用，但我们必须知道如何创建自定义 Docker 镜像。这对于通过安装新软件包和自定义预构建 Docker 镜像的设置来在 Docker 上运行我们的应用程序非常重要。在本章中，我们将学习如何创建自定义 Docker 镜像并基于它运行 Docker 容器。

这将使用一个名为`Dockerfile`的文本文件完成。该文件包含 Docker 可以执行以创建 Docker 镜像的命令。使用`docker build`（或`docker image build`）命令从`Dockerfile`创建 Docker 镜像。

注意

从 Docker 1.13 开始，Docker CLI 的语法已重构为 Docker COMMAND SUBCOMMAND 的形式。例如，`docker build`命令被替换为`docker image build`命令。此重构是为了清理 Docker CLI 语法并获得更一致的命令分组。目前，两种语法都受支持，但预计将来会弃用旧语法。

Docker 镜像由多个层组成，每个层代表`Dockerfile`中提供的命令。这些只读层叠加在一起，以创建最终的 Docker 镜像。Docker 镜像可以存储在 Docker 注册表（如 Docker Hub）中，这是一个可以存储和分发 Docker 镜像的地方。

Docker **容器**是 Docker 镜像的运行实例。可以使用`docker run`（或`docker container run`）命令从单个 Docker 镜像创建一个或多个 Docker 容器。一旦从 Docker 镜像创建了 Docker 容器，将在 Docker 镜像的只读层之上添加一个新的可写层。然后可以使用 docker ps（或 docker container list）命令列出 Docker 容器：

![图 2.1：图像层和容器层](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-ws/img/B15021_02_01.jpg)

图 2.1：图像层和容器层

如前图所示，Docker 镜像可以由一个或多个只读层组成。这些只读层是在`Dockerfile`中的每个命令在 Docker 镜像构建过程中生成的。一旦从镜像创建了 Docker 容器，新的可写层（称为**容器层**）将被添加到镜像层之上，并将承载在运行容器上所做的所有更改。

在本章中，我们将编写我们的第一个`Dockerfile`，从`Dockerfile`构建 Docker 镜像，并从我们的自定义 Docker 镜像运行 Docker 容器。然而，在执行任何这些任务之前，我们必须首先定义一个`Dockerfile`。

# 什么是 Dockerfile？

`Dockerfile`是一个文本文件，包含了创建 Docker 镜像的指令。这些命令称为**指令**。`Dockerfile`是我们根据需求创建自定义 Docker 镜像的机制。

`Dockerfile`的格式如下：

```
# This is a comment
DIRECTIVE argument
```

`Dockerfile`可以包含多行注释和指令。这些行将由**Docker 引擎**按顺序执行，同时构建 Docker 镜像。与编程语言一样，`Dockerfile`也可以包含注释。

所有以#符号开头的语句将被视为注释。目前，`Dockerfiles`只支持单行注释。如果您希望编写多行注释，您需要在每行开头添加#符号。

然而，与大多数编程语言不同，`Dockerfile`中的指令不区分大小写。即使`DIRECTIVE`不区分大小写，最好将所有指令都以大写形式编写，以便与参数区分开来。

在下一节中，我们将讨论在`Dockerfiles`中可以使用的常见指令，以创建自定义 Docker 镜像。

注意

如果您使用的是 18.04 之后的 ubuntu 版本，将会提示输入时区。请使用`ARG DEBIAN_FRONTEND=non_interactive`来抑制提示

# Dockerfile 中的常见指令

如前一节所讨论的，指令是用于创建 Docker 镜像的命令。在本节中，我们将讨论以下五个`Dockerfile`指令：

1.  `FROM`指令

1.  `LABEL`指令

1.  `RUN`指令

1.  `CMD`指令

1.  `ENTRYPOINT`指令

## `FROM`指令

`Dockerfile`通常以`FROM`指令开头。这用于指定我们自定义 Docker 镜像的父镜像。父镜像是我们自定义 Docker 镜像的起点。我们所做的所有自定义将应用在父镜像之上。父镜像可以是来自 Docker Hub 的镜像，如 Ubuntu、CentOS、Nginx 和 MySQL。`FROM`指令接受有效的镜像名称和标签作为参数。如果未指定标签，将使用`latest`标签。

`FROM`指令的格式如下：

```
FROM <image>:<tag> 
```

在以下`FROM`指令中，我们使用带有`20.04`标签的`ubuntu`父镜像：

```
FROM ubuntu:20.04
```

此外，如果需要从头开始构建 Docker 镜像，我们可以使用基础镜像。基础镜像，即 scratch 镜像，是一个空镜像，主要用于构建其他父镜像。

在以下`FROM`指令中，我们使用`scratch`镜像从头开始构建我们的自定义 Docker 镜像：

```
FROM scratch
```

现在，让我们在下一节中了解`LABEL`指令是什么。

## `LABEL`指令

`LABEL`是一个键值对，可用于向 Docker 镜像添加元数据。这些标签可用于适当地组织 Docker 镜像。例如，可以添加`Dockerfile`的作者姓名或`Dockerfile`的版本。

`LABEL`指令的格式如下：

```
LABEL <key>=<value>
```

`Dockerfile`可以有多个标签，遵循前面的键值对格式：

```
LABEL maintainer=sathsara@mydomain.com
LABEL version=1.0
LABEL environment=dev
```

或者这些标签可以在单行上用空格分隔包含：

```
LABEL maintainer=sathsara@mydomain.com version=1.0 environment=dev
```

现有的 Docker 镜像标签可以使用`docker image inspect`命令查看。

运行`docker image inspect <image>:<tag>`命令时，输出应该如下所示：

```
...
...
"Labels": {
    "environment": "dev",
    "maintainer": "sathsara@mydomain.com",
    "version": "1.0"
}
...
...
```

如此所示，docker image inspect 命令将输出使用`LABEL`指令在`Dockerfile`中配置的键值对。

在下一节中，我们将学习如何使用`RUN`指令在构建镜像时执行命令。

## `RUN`指令

`RUN`指令用于在图像构建时执行命令。这将在现有层的顶部创建一个新层，执行指定的命令，并将结果提交到新创建的层。`RUN`指令可用于安装所需的软件包，更新软件包，创建用户和组等。

`RUN`指令的格式如下：

```
RUN <command>
```

`<command>`指定您希望作为图像构建过程的一部分执行的 shell 命令。一个`Dockerfile`可以有多个`RUN`指令，遵循上述格式。

在以下示例中，我们在父镜像的基础上运行了两个命令。`apt-get update`用于更新软件包存储库，`apt-get install nginx -y`用于安装 Nginx 软件包：

```
RUN apt-get update
RUN apt-get install nginx -y
```

或者，您可以通过使用`&&`符号将多个 shell 命令添加到单个`RUN`指令中。在以下示例中，我们使用了相同的两个命令，但这次是在单个`RUN`指令中，用`&&`符号分隔：

```
RUN apt-get update && apt-get install nginx -y
```

现在，让我们继续下一节，我们将学习`CMD`指令。

## CMD 指令

Docker 容器通常预期运行一个进程。`CMD`指令用于提供默认的初始化命令，当从 Docker 镜像创建容器时将执行该命令。`Dockerfile`只能执行一个`CMD`指令。如果`Dockerfile`中有多个`CMD`指令，Docker 将只执行最后一个。

`CMD`指令的格式如下：

```
CMD ["executable","param1","param2","param3", ...]
```

例如，使用以下命令将"`Hello World`"作为 Docker 容器的输出：

```
CMD ["echo","Hello World"]
```

当我们使用`docker container run <image>`命令（用 Docker 镜像的名称替换`<image>`）运行 Docker 容器时，上述`CMD`指令将产生以下输出：

```
$ docker container run <image>
Hello World
```

然而，如果我们使用`docker container run <image>`命令行参数，这些参数将覆盖我们定义的`CMD`指令。例如，如果我们执行以下命令（用 Docker 镜像的名称替换`<image>`），则会忽略使用`CMD`指令定义的默认的"`Hello World`"输出。相反，容器将输出"`Hello Docker !!!`"：

```
$ docker container run <image> echo "Hello Docker !!!"
```

正如我们讨论过的，`RUN`和`CMD`指令都可以用来执行 shell 命令。这两个指令之间的主要区别在于，`RUN`指令提供的命令将在镜像构建过程中执行，而`CMD`指令提供的命令将在从构建的镜像启动容器时执行。

`RUN`和`CMD`指令之间的另一个显着区别是，在`Dockerfile`中可以有多个`RUN`指令，但只能有一个`CMD`指令（如果有多个`CMD`指令，则除最后一个之外的所有其他指令都将被忽略）。

例如，我们可以使用`RUN`指令在 Docker 镜像构建过程中安装软件包，并使用`CMD`指令在从构建的镜像启动容器时启动软件包。

在下一节中，我们将学习`ENTRYPOINT`指令，它提供了与`CMD`指令相同的功能，除了覆盖。

## ENTRYPOINT 指令

与`CMD`指令类似，`ENTRYPOINT`指令也用于提供默认的初始化命令，该命令将在从 Docker 镜像创建容器时执行。`CMD`指令和`ENTRYPOINT`指令之间的区别在于，与`CMD`指令不同，我们不能使用`docker container run`命令发送的命令行参数来覆盖`ENTRYPOINT`命令。

注意

`--entrypoint`标志可以与`docker container run`命令一起发送，以覆盖镜像的默认`ENTRYPOINT`。

`ENTRYPOINT`指令的格式如下：

```
ENTRYPOINT ["executable","param1","param2","param3", ...]
```

与`CMD`指令类似，`ENTRYPOINT`指令也允许我们提供默认的可执行文件和参数。我们可以在`ENTRYPOINT`指令中使用`CMD`指令来为可执行文件提供额外的参数。

在以下示例中，我们使用`ENTRYPOINT`指令将`"echo"`作为默认命令，将`"Hello"`作为默认参数。我们还使用`CMD`指令提供了`"World"`作为额外的参数：

```
ENTRYPOINT ["echo","Hello"]
CMD ["World"]
```

`echo`命令的输出将根据我们如何执行`docker container run`命令而有所不同。

如果我们启动 Docker 镜像而没有任何命令行参数，它将输出消息`Hello World`：

```
$ docker container run <image>
Hello World
```

但是，如果我们使用额外的命令行参数（例如`Docker`）启动 Docker 镜像，输出消息将是`Hello Docker`：

```
$ docker container run <image> "Docker"
Hello Docker
```

在进一步讨论`Dockerfile`指令之前，让我们从下一个练习开始创建我们的第一个`Dockerfile`。

## 练习 2.01：创建我们的第一个 Dockerfile

在这个练习中，您将创建一个 Docker 镜像，可以打印您传递给 Docker 镜像的参数，前面加上文本`You are reading`。例如，如果您传递`hello world`，它将输出`You are reading hello world`。如果没有提供参数，则将使用`The Docker Workshop`作为标准值：

1.  使用`mkdir`命令创建一个名为`custom-docker-image`的新目录。该目录将是您的 Docker 镜像的**上下文**。`上下文`是包含成功构建镜像所需的所有文件的目录：

```
$ mkdir custom-docker-image
```

1.  使用`cd`命令导航到新创建的`custom-docker-image`目录，因为我们将在此目录中创建构建过程中所需的所有文件（包括`Dockerfile`）：

```
$ cd custom-docker-image
```

1.  在`custom-docker-image`目录中，使用`touch`命令创建一个名为`Dockerfile`的文件：

```
$ touch Dockerfile
```

1.  现在，使用您喜欢的文本编辑器打开`Dockerfile`：

```
$ vim Dockerfile
```

1.  将以下内容添加到`Dockerfile`中，保存并退出`Dockerfile`：

```
# This is my first Docker image
FROM ubuntu 
LABEL maintainer=sathsara@mydomain.com 
RUN apt-get update
CMD ["The Docker Workshop"]
ENTRYPOINT ["echo", "You are reading"]
```

Docker 镜像将基于 Ubuntu 父镜像。然后，您可以使用`LABEL`指令提供`Dockerfile`作者的电子邮件地址。接下来的一行执行`apt-get update`命令，将 Debian 的软件包列表更新到最新可用版本。最后，您将使用`ENTRYPOINT`和`CMD`指令来定义容器的默认可执行文件和参数。

我们已经提供了`echo`作为默认可执行文件，`You are reading`作为默认参数，不能使用命令行参数进行覆盖。此外，我们还提供了`The Docker Workshop`作为一个额外的参数，可以使用`docker container run`命令的命令行参数进行覆盖。

在这个练习中，我们使用了在前几节中学到的常见指令创建了我们的第一个`Dockerfile`。该过程的下一步是从`Dockerfile`构建 Docker 镜像。只有在从`Dockerfile`构建 Docker 镜像之后，才能运行 Docker 容器。在下一节中，我们将看看如何从`Dockerfile`构建 Docker 镜像。

# 构建 Docker 镜像

在上一节中，我们学习了如何创建`Dockerfile`。该过程的下一步是使用`Dockerfile`构建**Docker 镜像**。

**Docker 镜像**是用于构建 Docker 容器的模板。这类似于如何可以使用房屋平面图从相同的设计中创建多个房屋。如果您熟悉**面向对象编程**的概念，Docker 镜像和 Docker 容器的关系与**类**和**对象**的关系相同。面向对象编程中的类可用于创建多个对象。

Docker 镜像是一个二进制文件，由`Dockerfile`中提供的多个层组成。这些层堆叠在彼此之上，每个层依赖于前一个层。每个层都是基于其下一层的更改而生成的。Docker 镜像的所有层都是只读的。一旦我们从 Docker 镜像创建一个 Docker 容器，将在其他只读层之上创建一个新的可写层，其中包含对容器文件系统所做的所有修改：

![图 2.2：Docker 镜像层](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-ws/img/B15021_02_02.jpg)

图 2.2：Docker 镜像层

如前图所示，docker image build 命令将从`Dockerfile`创建一个 Docker 镜像。Docker 镜像的层将映射到`Dockerfile`中提供的指令。

这个图像构建过程是由 Docker CLI 发起并由 Docker 守护程序执行的。要生成 Docker 镜像，Docker 守护程序需要访问`Dockerfile`，源代码（例如`index.html`）和其他文件（例如属性文件），这些文件在`Dockerfile`中被引用。这些文件通常存储在一个被称为构建上下文的目录中。在执行 docker image build 命令时将指定此上下文。整个上下文将在图像构建过程中发送到 Docker 守护程序。

`docker image build`命令采用以下格式：

```
$ docker image build <context>
```

我们可以从包含`Dockerfile`和其他文件的文件夹中执行 docker image build 命令，如下例所示。请注意，命令末尾的点（`.`）用于表示当前目录：

```
$ docker image build.
```

让我们看看以下示例`Dockerfile`的 Docker 镜像构建过程：

```
FROM ubuntu:latest
LABEL maintainer=sathsara@mydomain.com
CMD ["echo","Hello World"]
```

这个`Dockerfile`使用最新的`ubuntu`镜像作为父镜像。然后，使用`LABEL`指令将`sathsara@mydomain.com`指定为维护者。最后，使用`CMD`指令将 echo`"Hello World"`用作图像的输出。

执行上述`Dockerfile`的 docker 镜像构建命令后，我们可以在构建过程中的控制台上看到类似以下的输出：

```
Sending build context to Docker daemon 2.048kB
Step 1/3 : FROM ubuntu:latest
latest: Pulling from library/ubuntu
2746a4a261c9: Pull complete 
4c1d20cdee96: Pull complete 
0d3160e1d0de: Pull complete 
c8e37668deea: Pull complete
Digest: sha256:250cc6f3f3ffc5cdaa9d8f4946ac79821aafb4d3afc93928
        f0de9336eba21aa4
Status: Downloaded newer image for ubuntu:latest
 ---> 549b9b86cb8d
Step 2/3 : LABEL maintainer=sathsara@mydomain.com
 ---> Running in a4a11e5e7c27
Removing intermediate container a4a11e5e7c27
 ---> e3add5272e35
Step 3/3 : CMD ["echo","Hello World"]
 ---> Running in aad8a56fcdc5
Removing intermediate container aad8a56fcdc5
 ---> dc3d4fd77861
Successfully built dc3d4fd77861
```

输出的第一行是`Sending build context to Docker daemon`，这表明构建开始时将构建上下文发送到 Docker 守护程序。上下文中的所有文件将被递归地发送到 Docker 守护程序（除非明确要求忽略某些文件）。

接下来，有`Step 1/3`和`Step 2/3`的步骤，对应于`Dockerfile`中的指令。作为第一步，Docker 守护程序将下载父镜像。在上述输出中，从 library/ubuntu 拉取表示这一点。对于`Dockerfile`的每一行，都会创建一个新的中间容器来执行指令，一旦这一步完成，这个中间容器将被移除。`Running in a4a11e5e7c27`和`Removing intermediate container a4a11e5e7c27`这两行用于表示这一点。最后，当构建完成且没有错误时，将打印出`Successfully built dc3d4fd77861`这一行。这行打印出了新构建的 Docker 镜像的 ID。

现在，我们可以使用`docker image list`命令列出可用的 Docker 镜像：

```
$ docker image list
```

此列表包含了本地构建的 Docker 镜像和从远程 Docker 仓库拉取的 Docker 镜像：

```
REPOSITORY   TAG       IMAGE ID        CREATED          SIZE
<none>       <none>    dc3d4fd77861    3 minutes ago    64.2MB
ubuntu       latest    549b9b86cb8d    5 days ago       64.2MB
```

如上述输出所示，我们可以看到两个 Docker 镜像。第一个 Docker 镜像的 IMAGE ID 是`dc3d4fd77861`，是在构建过程中本地构建的 Docker 镜像。我们可以看到，这个`IMAGE ID`与`docker image build`命令的最后一行中的 ID 是相同的。下一个镜像是我们用作自定义镜像的父镜像的 ubuntu 镜像。

现在，让我们再次使用`docker image build`命令构建 Docker 镜像：

```
$ docker image build
Sending build context to Docker daemon  2.048kB
Step 1/3 : FROM ubuntu:latest
 ---> 549b9b86cb8d
Step 2/3 : LABEL maintainer=sathsara@mydomain.com
 ---> Using cache
 ---> e3add5272e35
Step 3/3 : CMD ["echo","Hello World"]
 ---> Using cache
 ---> dc3d4fd77861
Successfully built dc3d4fd77861
```

这次，镜像构建过程是瞬时的。这是因为缓存。由于我们没有改变`Dockerfile`的任何内容，Docker 守护程序利用了缓存，并重用了本地镜像缓存中的现有层来加速构建过程。我们可以在上述输出中看到，这次使用了缓存，有`Using cache`行可用。

Docker 守护程序将在启动构建过程之前执行验证步骤，以确保提供的`Dockerfile`在语法上是正确的。在语法无效的情况下，构建过程将失败，并显示来自 Docker 守护程序的错误消息：

```
$ docker image build
Sending build context to Docker daemon  2.048kB
Error response from daemon: Dockerfile parse error line 5: 
unknown instruction: INVALID
```

现在，让我们使用`docker image list`命令重新查看本地可用的 Docker 镜像：

```
$ docker image list
```

该命令应返回以下输出：

```
REPOSITORY    TAG       IMAGE ID         CREATED          SIZE
<none>        <none>    dc3d4fd77861     3 minutes ago    64.2MB
ubuntu        latest    549b9b86cb8d     5 days ago       64.2MB
```

请注意，我们的自定义 Docker 镜像没有名称。这是因为我们在构建过程中没有指定任何存储库或标签。我们可以使用 docker image tag 命令为现有镜像打标签。

让我们用`IMAGE ID dc3d4fd77861`作为`my-tagged-image:v1.0`来为我们的镜像打标签：

```
$ docker image tag dc3d4fd77861 my-tagged-image:v1.0
```

现在，如果我们再次列出我们的镜像，我们可以看到`REPOSITORY`和`TAG`列下的 Docker 镜像名称和标签：

```
REPOSITORY        TAG       IMAGE ID        CREATED         SIZE
my-tagged-image   v1.0      dc3d4fd77861    20 minutes ago  64.2MB
ubuntu            latest    549b9b86cb8d    5 days ago      64.2MB
```

我们还可以通过指定`-t`标志在构建过程中为镜像打标签：

```
$ docker image build -t my-tagged-image:v2.0 .
```

上述命令将打印以下输出：

```
Sending build context to Docker daemon  2.048kB
Step 1/3 : FROM ubuntu:latest
 ---> 549b9b86cb8d
Step 2/3 : LABEL maintainer=sathsara@mydomain.com
 ---> Using cache
 ---> e3add5272e35
Step 3/3 : CMD ["echo","Hello World"]
 ---> Using cache
 ---> dc3d4fd77861
Successfully built dc3d4fd77861
Successfully tagged my-tagged-image:v2.0
```

这一次，除了`成功构建 dc3d4fd77861`行之外，我们还可以看到`成功标记 my-tagged-image:v2.0`行，这表明我们的 Docker 镜像已经打了标签。

在本节中，我们学习了如何从`Dockerfile`构建 Docker 镜像。我们讨论了`Dockerfile`和 Docker 镜像之间的区别。然后，我们讨论了 Docker 镜像由多个层组成。我们还体验了缓存如何加速构建过程。最后，我们为 Docker 镜像打了标签。

在下一个练习中，我们将从*练习 2.01：创建我们的第一个 Dockerfile*中创建的`Dockerfile`构建 Docker 镜像。

## 练习 2.02：创建我们的第一个 Docker 镜像

在这个练习中，您将从*练习 2.01：创建我们的第一个 Dockerfile*中创建的`Dockerfile`构建 Docker 镜像，并从新构建的镜像运行 Docker 容器。首先，您将在不传递任何参数的情况下运行 Docker 镜像，期望输出为“您正在阅读 Docker Workshop”。接下来，您将以`Docker Beginner's Guide`作为参数运行 Docker 镜像，并期望输出为“您正在阅读 Docker Beginner's Guide”：

1.  首先，请确保您在*练习 2.01：创建我们的第一个 Dockerfile*中创建的`custom-docker-image`目录中。确认该目录包含在*练习 2.01：创建我们的第一个 Dockerfile*中创建的以下`Dockerfile`：

```
# This is my first Docker image
FROM ubuntu 
LABEL maintainer=sathsara@mydomain.com 
RUN apt-get update
CMD ["The Docker Workshop"]
ENTRYPOINT ["echo", "You are reading"]
```

1.  使用`docker image build`命令构建 Docker 镜像。此命令具有可选的`-t`标志，用于指定镜像的标签。将您的镜像标记为`welcome:1.0`：

```
$ docker image build -t welcome:1.0 .
```

注意

不要忘记在前述命令的末尾加上点(`.`)，用于将当前目录作为构建上下文。

可以从以下输出中看到，在构建过程中执行了`Dockerfile`中提到的所有五个步骤。输出的最后两行表明成功构建并打了标签的镜像：

![图 2.3：构建 welcome:1.0 Docker 镜像](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-ws/img/B15021_02_03.jpg)

图 2.3：构建 welcome:1.0 Docker 镜像

1.  再次构建此镜像，而不更改`Dockerfile`内容：

```
$ docker image build -t welcome:2.0 .
```

请注意，由于使用了缓存，此构建过程比以前的过程快得多：

![图 2.4：使用缓存构建 welcome:1.0 Docker 镜像](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-ws/img/B15021_02_04.jpg)

图 2.4：使用缓存构建 welcome:1.0 Docker 镜像

1.  使用`docker image list`命令列出计算机上所有可用的 Docker 镜像：

```
$ docker image list
```

这些镜像可以在您的计算机上使用，无论是从 Docker 注册表中拉取还是在您的计算机上构建：

```
REPOSITORY   TAG      IMAGE ID        CREATED          SIZE
welcome      1.0      98f571a42e5c    23 minutes ago   91.9MB
welcome      2.0      98f571a42e5c    23 minutes ago   91.9MB
ubuntu       latest   549b9b86cb8d    2 weeks ago      64.2MB
```

从前述输出中可以看出，有三个 Docker 镜像可用。`ubuntu`镜像是从 Docker Hub 拉取的，`welcome`镜像的`1.0`和`2.0`版本是在您的计算机上构建的。

1.  执行`docker container run`命令，从您在`步骤 1`中构建的 Docker 镜像（`welcome:1.0`）启动一个新容器：

```
$ docker container run welcome:1.0
```

输出应如下所示：

```
You are reading The Docker Workshop
```

您将收到预期的输出`You are reading The Docker Workshop`。`You are reading`是由`ENTRYPOINT`指令提供的参数引起的，`The Docker Workshop`来自`CMD`指令提供的参数。

1.  最后，再次执行`docker container run`命令，这次使用命令行参数：

```
$ docker container run welcome:1.0 "Docker Beginner's Guide"
```

由于命令行参数`Docker 初学者指南`和`ENTRYPOINT`指令中提供的`You are reading`参数，您将获得输出`You are reading Docker 初学者指南`：

```
You are reading Docker Beginner's Guide
```

在这个练习中，我们学习了如何使用`Dockerfile`构建自定义 Docker 镜像，并从镜像运行 Docker 容器。在下一节中，我们将学习可以在`Dockerfile`中使用的其他 Docker 指令。

# 其他 Dockerfile 指令

在 Dockerfile 中的常见指令部分，我们讨论了可用于`Dockerfile`的常见指令。在该部分中，我们讨论了`FROM`、`LABEL`、`RUN`、`CMD`和`ENTRYPOINT`指令以及如何使用它们创建一个简单的`Dockerfile`。

在本节中，我们将讨论更高级的`Dockerfile`指令。这些指令可以用于创建更高级的 Docker 镜像。例如，我们可以使用`VOLUME`指令将主机机器的文件系统绑定到 Docker 容器。这将允许我们持久化 Docker 容器生成和使用的数据。另一个例子是`HEALTHCHECK`指令，它允许我们定义健康检查以评估 Docker 容器的健康状态。在本节中，我们将研究以下指令：

1.  `ENV`指令

1.  `ARG`指令

1.  `WORKDIR`指令

1.  `COPY`指令

1.  `ADD`指令

1.  `USER`指令

1.  `VOLUME`指令

1.  `EXPOSE`指令

1.  `HEALTHCHECK`指令

1.  `ONBUILD`指令

## ENV 指令

`Dockerfile`中的 ENV 指令用于设置环境变量。**环境变量**被应用程序和进程用来获取有关进程运行环境的信息。一个例子是`PATH`环境变量，它列出了要搜索可执行文件的目录。

环境变量按以下格式定义为键值对：

```
ENV <key> <value>
```

PATH 环境变量设置为以下值：

```
$PATH:/usr/local/myapp/bin/
```

因此，可以使用`ENV`指令设置如下：

```
ENV PATH $PATH:/usr/local/myapp/bin/
```

我们可以在同一行中用空格分隔设置多个环境变量。但是，在这种形式中，`key`和`value`应该由等号（`=`）分隔：

```
ENV <key>=<value> <key>=<value> ...
```

在下面的示例中，配置了两个环境变量。`PATH`环境变量配置为`$PATH:/usr/local/myapp/bin/`的值，`VERSION`环境变量配置为`1.0.0`的值：

```
ENV PATH=$PATH:/usr/local/myapp/bin/ VERSION=1.0.0
```

一旦使用`Dockerfile`中的`ENV`指令设置了环境变量，该变量就会在所有后续的 Docker 镜像层中可用。甚至在从此 Docker 镜像启动的 Docker 容器中也可用。

在下一节中，我们将研究`ARG`指令。

## ARG 指令

`ARG`指令用于定义用户可以在构建时传递的变量。`ARG`是唯一可以在`Dockerfile`中的`FROM`指令之前出现的指令。

用户可以在构建 Docker 镜像时使用`--build-arg <varname>=<value>`传递值，如下所示：

```
$ docker image build -t <image>:<tag> --build-arg <varname>=<value> .
```

`ARG`指令的格式如下：

```
ARG <varname>
```

`Dockerfile`中可以有多个`ARG`指令，如下所示：

```
ARG USER
ARG VERSION
```

`ARG`指令也可以定义一个可选的默认值。如果在构建时没有传递值，将使用此默认值：

```
ARG USER=TestUser
ARG VERSION=1.0.0
```

与`ENV`变量不同，`ARG`变量无法从正在运行的容器中访问。它们仅在构建过程中可用。

在下一个练习中，我们将利用迄今为止所学到的知识，在`Dockerfile`中使用`ENV`和`ARG`指令。 

## 练习 2.03：在 Dockerfile 中使用 ENV 和 ARG 指令

您的经理要求您创建一个`Dockerfile`，该文件将使用 ubuntu 作为父镜像，但您应该能够在构建时更改 ubuntu 版本。您还需要指定发布者的名称和 Docker 镜像的应用程序目录作为环境变量。您将使用`Dockerfile`中的`ENV`和`ARG`指令来执行此练习：

1.  使用`mkdir`命令创建一个名为`env-arg-exercise`的新目录：

```
mkdir env-arg-exercise
```

1.  使用`cd`命令导航到新创建的`env-arg-exercise`目录：

```
cd env-arg-exercise
```

1.  在`env-arg-exercise`目录中，创建一个名为`Dockerfile`的文件：

```
touch Dockerfile
```

1.  现在，使用您喜欢的文本编辑器打开`Dockerfile`：

```
vim Dockerfile
```

1.  将以下内容添加到`Dockerfile`中。然后，保存并退出`Dockerfile`：

```
# ENV and ARG example
ARG TAG=latest
FROM ubuntu:$TAG
LABEL maintainer=sathsara@mydomain.com 
ENV PUBLISHER=packt APP_DIR=/usr/local/app/bin
CMD ["env"]
```

此`Dockerfile`首先定义了一个名为`TAG`的参数，其默认值为最新版本。接下来是`FROM`指令，它将使用带有`TAG`变量值的 ubuntu 父镜像与`build`命令一起发送（或者如果没有使用`build`命令发送值，则使用默认值）。然后，`LABEL`指令设置了维护者的值。接下来是`ENV`指令，它使用值`packt`定义了`PUBLISHER`的环境变量，并使用值`/usr/local/app/bin`定义了`APP_DIR`的环境变量。最后，使用`CMD`指令执行`env`命令，该命令将打印所有环境变量。

1.  现在，构建 Docker 镜像：

```
$ docker image build -t env-arg --build-arg TAG=19.04 .
```

注意使用`env-arg --build-arg TAG=19.04`标志将`TAG`参数发送到构建过程中。输出应如下所示：

![图 2.5：构建 env-arg Docker 镜像](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-ws/img/B15021_02_05.jpg)

图 2.5：构建 env-arg Docker 镜像

请注意，在构建过程中使用了 ubuntu 镜像的`19.04`标签作为父镜像。这是因为您在构建过程中使用了`--build-arg`标志，并设置了值为`TAG=19.04`。

1.  现在，执行`docker container run`命令，从您在上一步中构建的 Docker 镜像启动一个新的容器：

```
$ docker container run env-arg
```

从输出中我们可以看到，`PUBLISHER`环境变量的值为`packt`，`APP_DIR`环境变量的值为`/usr/local/app/bin`：

![图 2.6：运行 env-arg Docker 容器](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-ws/img/B15021_02_06.jpg)

图 2.6：运行 env-arg Docker 容器

在这个练习中，我们使用`ENV`指令为 Docker 镜像定义了环境变量。我们还体验了如何在 Docker 镜像构建时使用`ARG`指令传递值。在下一节中，我们将介绍`WORKDIR`指令，它可以用来定义 Docker 容器的当前工作目录。

## 工作目录指令

`WORKDIR`指令用于指定 Docker 容器的当前工作目录。任何后续的`ADD`、`CMD`、`COPY`、`ENTRYPOINT`和`RUN`指令都将在此目录中执行。`WORKDIR`指令的格式如下：

```
WORKDIR /path/to/workdir
```

如果指定的目录不存在，Docker 将创建此目录并将其设置为当前工作目录，这意味着该指令隐式执行`mkdir`和`cd`命令。

`Dockerfile`中可以有多个`WORKDIR`指令。如果在后续的`WORKDIR`指令中提供了相对路径，那么它将相对于前一个`WORKDIR`指令设置的工作目录。

```
WORKDIR /one
WORKDIR two
WORKDIR three
RUN pwd
```

在前面的例子中，我们在`Dockerfile`的末尾使用`pwd`命令来打印当前工作目录。`pwd`命令的输出将是`/one/two/three`。

在下一节中，我们将讨论`COPY`指令，该指令用于将文件从本地文件系统复制到 Docker 镜像文件系统。

## 复制指令

在 Docker 镜像构建过程中，我们可能需要将文件从本地文件系统复制到 Docker 镜像文件系统。这些文件可以是源代码文件（例如 JavaScript 文件）、配置文件（例如属性文件）或者构件（例如 JAR 文件）。在构建过程中，可以使用`COPY`指令将文件和文件夹从本地文件系统复制到 Docker 镜像。该指令有两个参数。第一个是本地文件系统的源路径，第二个是镜像文件系统上的目标路径：

```
COPY <source> <destination>
```

在下面的例子中，我们使用`COPY`指令将`index.html`文件从本地文件系统复制到 Docker 镜像的`/var/www/html/`目录中：

```
COPY index.html /var/www/html/index.html
```

通配符也可以用来指定匹配给定模式的所有文件。以下示例将把当前目录中所有扩展名为`.html`的文件复制到 Docker 镜像的`/var/www/html/`目录中：

```
COPY *.html /var/www/html/
```

除了复制文件外，`--chown`标志还可以与`COPY`指令一起使用，以指定文件的用户和组所有权：

```
COPY --chown=myuser:mygroup *.html /var/www/html/
```

在上面的例子中，除了将所有 HTML 文件从当前目录复制到`/var/www/html/`目录外，`--chown`标志还用于设置文件所有权，用户为`myuser`，组为`mygroup`：

注意

`--chown`标志仅在 Docker 版本 17.09 及以上版本中受支持。对于低于 17.09 版本的 Docker，您需要在`COPY`命令之后运行`chown`命令来更改文件所有权。

在下一节中，我们将看一下`ADD`指令。

## ADD 指令

`ADD`指令也类似于`COPY`指令，格式如下：

```
ADD <source> <destination>
```

但是，除了`COPY`指令提供的功能外，`ADD`指令还允许我们将 URL 用作`<source>`参数：

```
ADD http://sample.com/test.txt /tmp/test.txt
```

在上面的例子中，`ADD`指令将从`http://sample.com`下载`test.txt`文件，并将文件复制到 Docker 镜像文件系统的`/tmp`目录中。

`ADD`指令的另一个特性是自动提取压缩文件。如果我们将一个压缩文件（gzip、bzip2、tar 等）添加到`<source>`参数中，`ADD`指令将会提取存档并将内容复制到镜像文件系统中。

假设我们有一个名为`html.tar.gz`的压缩文件，其中包含`index.html`和`contact.html`文件。以下命令将提取`html.tar.gz`文件，并将`index.html`和`contact.html`文件复制到`/var/www/html`目录：

```
ADD html.tar.gz /var/www/html
```

由于`COPY`和`ADD`指令提供几乎相同的功能，建议始终使用`COPY`指令，除非您需要`ADD`指令提供的附加功能（从 URL 添加或提取压缩文件）。这是因为`ADD`指令提供了额外的功能，如果使用不正确，可能会表现出不可预测的行为（例如，在想要提取文件时复制文件，或者在想要复制文件时提取文件）。

在下一个练习中，我们将使用`WORKDIR`，`COPY`和`ADD`指令将文件复制到 Docker 镜像中。

## 练习 2.04：在 Dockerfile 中使用 WORKDIR，COPY 和 ADD 指令

在这个练习中，您将部署自定义的 HTML 文件到 Apache Web 服务器。您将使用 Ubuntu 作为基础镜像，并在其上安装 Apache。然后，您将将自定义的 index.html 文件复制到 Docker 镜像，并从 https://www.docker.com 网站下载 Docker 标志，以与自定义的 index.html 文件一起使用：

1.  使用`mkdir`命令创建一个名为`workdir-copy-add-exercise`的新目录：

```
mkdir workdir-copy-add-exercise
```

1.  导航到新创建的`workdir-copy-add-exercise`目录：

```
cd workdir-copy-add-exercise
```

1.  在`workdir-copy-add-exercise`目录中，创建一个名为`index.html`的文件。此文件将在构建时复制到 Docker 镜像中：

```
touch index.html 
```

1.  现在，使用您喜欢的文本编辑器打开`index.html`：

```
vim index.html 
```

1.  将以下内容添加到`index.html`文件中，保存并退出`index.html`：

```
<html>
  <body>
    <h1>Welcome to The Docker Workshop</h1>
    <img src="logo.png" height="350" width="500"/>
  </body>
</html>
```

此 HTML 文件将在页面的标题中输出“欢迎来到 Docker 工作坊”，并作为图像输出`logo.png`（我们将在 Docker 镜像构建过程中下载）。您已经定义了`logo.png`图像的高度为`350`，宽度为`500`。

1.  在`workdir-copy-add-exercise`目录中，创建一个名为`Dockerfile`的文件：

```
touch Dockerfile
```

1.  现在，使用您喜欢的文本编辑器打开`Dockerfile`：

```
vim Dockerfile
```

1.  将以下内容添加到`Dockerfile`中，保存并退出`Dockerfile`：

```
# WORKDIR, COPY and ADD example
FROM ubuntu:latest 
RUN apt-get update && apt-get install apache2 -y 
WORKDIR /var/www/html/
COPY index.html .
ADD https://www.docker.com/sites/default/files/d8/2019-07/  Moby-logo.png ./logo.png
CMD ["ls"]
```

这个`Dockerfile`首先将 ubuntu 镜像定义为父镜像。下一行是`RUN`指令，它将执行`apt-get update`来更新软件包列表，以及`apt-get install apache2 -y`来安装 Apache HTTP 服务器。然后，您将设置`/var/www/html/`为工作目录。接下来，将我们在*步骤 3*中创建的`index.html`文件复制到 Docker 镜像中。然后，使用`ADD`指令从[`www.docker.com/sites/default/files/d8/2019-07/Moby-logo.png`](https://www.docker.com/sites/default/files/d8/2019-07/Moby-logo.png)下载 Docker 标志到 Docker 镜像中。最后一步是使用`ls`命令打印`/var/www/html/`目录的内容。

1.  现在，使用标签`workdir-copy-add`构建 Docker 镜像：

```
$ docker image build -t workdir-copy-add .
```

您会注意到，由于我们没有明确为镜像打标签，因此该镜像已成功构建并标记为`latest`：

![图 2.7：使用 WORKDIR、COPY 和 ADD 指令构建 Docker 镜像](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-ws/img/B15021_02_07.jpg)

图 2.7：使用 WORKDIR、COPY 和 ADD 指令构建 Docker 镜像

1.  执行`docker container run`命令，从您在上一步中构建的 Docker 镜像启动一个新的容器：

```
$ docker container run workdir-copy-add
```

从输出中可以看到，`index.html`和`logo.png`文件都在`/var/www/html/`目录中可用：

```
index.html
logo.png
```

在这个练习中，我们观察了`WORKDIR`、`ADD`和`COPY`指令在 Docker 中的工作方式。在下一节中，我们将讨论`USER`指令。

## USER 指令

Docker 将使用 root 用户作为 Docker 容器的默认用户。我们可以使用`USER`指令来改变这种默认行为，并指定一个非 root 用户作为 Docker 容器的默认用户。这是通过以非特权用户身份运行 Docker 容器来提高安全性的好方法。在`Dockerfile`中使用`USER`指令指定的用户名将用于运行所有后续的`RUN`、`CMD`和`ENTRYPOINT`指令。

`USER`指令采用以下格式：

```
USER <user>
```

除了用户名之外，我们还可以指定可选的组名来运行 Docker 容器：

```
USER <user>:<group>
```

我们需要确保`<user>`和`<group>`的值是有效的用户和组名。否则，Docker 守护程序在尝试运行容器时会抛出错误：

```
docker: Error response from daemon: unable to find user my_user: 
        no matching entries in passwd file.
```

现在，让我们在下一个练习中尝试使用`USER`指令。

## 练习 2.05：在 Dockerfile 中使用 USER 指令

您的经理要求您创建一个 Docker 镜像来运行 Apache Web 服务器。由于安全原因，他特别要求您在运行 Docker 容器时使用非 root 用户。在这个练习中，您将使用`Dockerfile`中的`USER`指令来设置默认用户。您将安装 Apache Web 服务器并将用户更改为`www-data`。最后，您将执行`whoami`命令来验证当前用户的用户名：

注意

`www-data`用户是 Ubuntu 上 Apache Web 服务器的默认用户。

1.  为这个练习创建一个名为`user-exercise`的新目录：

```
mkdir user-exercise
```

1.  导航到新创建的`user-exercise`目录：

```
cd user-exercise
```

1.  在`user-exercise`目录中，创建一个名为`Dockerfile`的文件：

```
touch Dockerfile
```

1.  现在，用你喜欢的文本编辑器打开`Dockerfile`：

```
vim Dockerfile
```

1.  将以下内容添加到`Dockerfile`中，保存并退出`Dockerfile`：

```
# USER example
FROM ubuntu
RUN apt-get update && apt-get install apache2 -y 
USER www-data
CMD ["whoami"]
```

这个`Dockerfile`首先将 Ubuntu 镜像定义为父镜像。下一行是`RUN`指令，它将执行`apt-get update`来更新软件包列表，以及`apt-get install apache2 -y`来安装 Apache HTTP 服务器。接下来，您使用`USER`指令将当前用户更改为`www-data`用户。最后，您有`CMD`指令，它执行`whoami`命令，将打印当前用户的用户名。

1.  构建 Docker 镜像：

```
$ docker image build -t user .
```

输出应该如下：

![图 2.8：构建用户 Docker 镜像](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-ws/img/B15021_02_08.jpg)

图 2.8：构建用户 Docker 镜像

1.  现在，执行`docker container` run 命令来从我们在上一步中构建的 Docker 镜像启动一个新的容器：

```
$ docker container run user
```

如您从以下输出中所见，`www-data`是与 Docker 容器关联的当前用户：

```
www-data
```

在这个练习中，我们在`Dockerfile`中实现了`USER`指令，将`www-data`用户设置为 Docker 镜像的默认用户。

在下一节中，我们将讨论`VOLUME`指令。

## VOLUME 指令

在 Docker 中，Docker 容器生成和使用的数据（例如文件、可执行文件）将存储在容器文件系统中。当我们删除容器时，所有数据都将丢失。为了解决这个问题，Docker 提出了卷的概念。卷用于持久化数据并在容器之间共享数据。我们可以在`Dockerfile`中使用`VOLUME`指令来创建 Docker 卷。一旦在 Docker 容器中创建了`VOLUME`，底层主机将创建一个映射目录。Docker 容器的卷挂载的所有文件更改将被复制到主机机器的映射目录中。

`VOLUME`指令通常以 JSON 数组作为参数：

```
VOLUME ["/path/to/volume"]
```

或者，我们可以指定一个包含多个路径的普通字符串：

```
VOLUME /path/to/volume1 /path/to/volume2
```

我们可以使用`docker container inspect <container>`命令查看容器中可用的卷。docker 容器 inspect 命令的输出 JSON 将打印类似以下内容的卷信息：

```
"Mounts": [
    {
        "Type": "volume",
        "Name": "77db32d66407a554bd0dbdf3950671b658b6233c509ea
ed9f5c2a589fea268fe",
        "Source": "/var/lib/docker/volumes/77db32d66407a554bd0
dbdf3950671b658b6233c509eaed9f5c2a589fea268fe/_data",
        "Destination": "/path/to/volume",
        "Driver": "local",
        "Mode": "",
        "RW": true,
        "Propagation": ""
    }
],
```

根据前面的输出，Docker 为卷指定了一个唯一的名称。此外，输出中还提到了卷的源路径和目标路径。

此外，我们可以执行`docker volume inspect <volume>`命令来显示有关卷的详细信息：

```
[
    {
        "CreatedAt": "2019-12-28T12:52:52+05:30",
        "Driver": "local",
        "Labels": null,
        "Mountpoint": "/var/lib/docker/volumes/77db32d66407a554
bd0dbdf3950671b658b6233c509eaed9f5c2a589fea268fe/_data",
        "Name": "77db32d66407a554bd0dbdf3950671b658b6233c509eae
d9f5c2a589fea268fe",
        "Options": null,
        "Scope": "local"
    }
]
```

这也类似于先前的输出，具有相同的唯一名称和卷的挂载路径。

在下一个练习中，我们将学习如何在`Dockerfile`中使用`VOLUME`指令。

## 练习 2.06：在 Dockerfile 中使用 VOLUME 指令

在这个练习中，您将设置一个 Docker 容器来运行 Apache Web 服务器。但是，您不希望在 Docker 容器失败时丢失 Apache 日志文件。作为解决方案，您决定通过将 Apache 日志路径挂载到底层 Docker 主机来持久保存日志文件。

1.  创建一个名为`volume-exercise`的新目录：

```
mkdir volume-exercise
```

1.  转到新创建的`volume-exercise`目录：

```
cd volume-exercise
```

1.  在`volume-exercise`目录中，创建一个名为`Dockerfile`的文件：

```
touch Dockerfile
```

1.  现在，使用您喜欢的文本编辑器打开`Dockerfile`：

```
vim Dockerfile
```

1.  将以下内容添加到`Dockerfile`中，保存并退出`Dockerfile`：

```
# VOLUME example
FROM ubuntu
RUN apt-get update && apt-get install apache2 -y
VOLUME ["/var/log/apache2"]
```

这个`Dockerfile`首先定义了 Ubuntu 镜像作为父镜像。接下来，您将执行`apt-get update`命令来更新软件包列表，以及`apt-get install apache2 -y`命令来安装 Apache Web 服务器。最后，使用`VOLUME`指令来设置一个挂载点到`/var/log/apache2`目录。

1.  现在，构建 Docker 镜像：

```
$ docker image build -t volume .
```

输出应该如下：

![图 2.9：构建卷 Docker 镜像](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-ws/img/B15021_02_09.jpg)

图 2.9：构建卷 Docker 镜像

1.  执行 docker 容器运行命令，从您在上一步构建的 Docker 镜像中启动一个新的容器。请注意，您正在使用`--interactive`和`--tty`标志来打开一个交互式的 bash 会话，以便您可以从 Docker 容器的 bash shell 中执行命令。您还使用了`--name`标志来将容器名称定义为`volume-container`：

```
$ docker container run --interactive --tty --name volume-container volume /bin/bash
```

您的 bash shell 将会被打开如下：

```
root@bc61d46de960: /#
```

1.  从 Docker 容器命令行，切换到`/var/log/apache2/`目录：

```
# cd /var/log/apache2/
```

这将产生以下输出：

```
root@bc61d46de960: /var/log/apache2#
```

1.  现在，列出目录中可用的文件：

```
# ls -l
```

输出应该如下：

![图 2.10：列出/var/log/apache2 目录的文件](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-ws/img/B15021_02_10.jpg)

图 2.10：列出/var/log/apache2 目录的文件

这些是 Apache 在运行过程中创建的日志文件。一旦您检查了该卷的主机挂载，相同的文件应该也是可用的。

1.  现在，退出容器以检查主机文件系统：

```
# exit
```

1.  检查`volume-container`以查看挂载信息：

```
$ docker container inspect volume-container
```

在"`Mounts`"键下，您可以看到与挂载相关的信息：

![图 2.11：检查 Docker 容器](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-ws/img/B15021_02_11.jpg)

图 2.11：检查 Docker 容器

1.  使用`docker volume inspect <volume_name>`命令来检查卷。`<volume_name>`可以通过前面输出的`Name`字段来识别：

```
$ docker volume inspect 354d188e0761d82e1e7d9f3d5c6ee644782b7150f51cead8f140556e5d334bd5
```

您应该会得到类似以下的输出：

![图 2.12：检查 Docker 卷](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-ws/img/B15021_02_12.jpg)

图 2.12：检查 Docker 卷

我们可以看到容器被挂载到`"/var/lib/docker/volumes/354d188e0761d82e1e7d9f3d5c6ee644782b 7150f51cead8f140556e5d334bd5/_data"`的主机路径上，这在前面的输出中被定义为`Mountpoint`字段。

1.  列出主机文件路径中可用的文件。主机文件路径可以通过前面输出的`"Mountpoint"`字段来识别：

```
$ sudo ls -l /var/lib/docker/volumes/354d188e0761d82e1e7d9f3d5c6ee644782b7150f51cead8f14 0556e5d334bd5/_data
```

在下面的输出中，您可以看到容器中`/var/log/apache2`目录中的日志文件被挂载到主机上：

![图 2.13：列出挂载点目录中的文件](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-ws/img/B15021_02_13.jpg)

图 2.13：列出挂载点目录中的文件

在这个练习中，我们观察了如何使用`VOLUME`指令将 Apache Web 服务器的日志路径挂载到主机文件系统上。在下一节中，我们将学习`EXPOSE`指令。

## EXPOSE 指令

`EXPOSE`指令用于通知 Docker 容器在运行时监听指定端口。我们可以使用`EXPOSE`指令通过 TCP 或 UDP 协议公开端口。`EXPOSE`指令的格式如下：

```
EXPOSE <port>
```

然而，使用`EXPOSE`指令公开的端口只能从其他 Docker 容器内部访问。要将这些端口公开到 Docker 容器外部，我们可以使用`docker container run`命令的`-p`标志来发布端口：

```
docker container run -p <host_port>:<container_port> <image>
```

举个例子，假设我们有两个容器。一个是 NodeJS Web 应用容器，应该通过端口`80`从外部访问。第二个是 MySQL 容器，应该通过端口`3306`从 Node 应用容器访问。在这种情况下，我们必须使用`EXPOSE`指令公开 NodeJS 应用的端口`80`，并在运行容器时使用`docker container run`命令和`-p`标志来将其公开到外部。然而，对于 MySQL 容器，我们在运行容器时只能使用`EXPOSE`指令，而不使用`-p`标志，因为`3306`端口只能从 Node 应用容器访问。

因此，总结来说，以下陈述定义了这个指令：

+   如果我们同时指定`EXPOSE`指令和`-p`标志，公开的端口将可以从其他容器以及外部访问。

+   如果我们不使用`-p`标志来指定`EXPOSE`，那么公开的端口只能从其他容器访问，而无法从外部访问。

在下一节中，您将学习`HEALTHCHECK`指令。

## HEALTHCHECK 指令

在 Docker 中使用健康检查来检查容器是否正常运行。例如，我们可以使用健康检查来确保应用程序在 Docker 容器内部运行。除非指定了健康检查，否则 Docker 无法判断容器是否健康。如果在生产环境中运行 Docker 容器，这一点非常重要。`HEALTHCHECK`指令的格式如下：

```
HEALTHCHECK [OPTIONS] CMD command
```

`Dockerfile`中只能有一个`HEALTHCHECK`指令。如果有多个`HEALTHCHECK`指令，只有最后一个会生效。

例如，我们可以使用以下指令来确保容器可以在`http://localhost/`端点接收流量：

```
HEALTHCHECK CMD curl -f http://localhost/ || exit 1
```

在上一个命令的最后，退出代码用于指定容器的健康状态。`0`和`1`是此字段的有效值。0 用于表示健康的容器，`1`用于表示不健康的容器。

除了命令，我们可以在`HEALTHCHECK`指令中指定一些其他参数，如下所示：

+   `--interval`：指定每次健康检查之间的时间间隔（默认为 30 秒）。

+   `--timeout`：如果在此期间未收到成功响应，则健康检查被视为失败（默认为 30 秒）。

+   `--start-period`：在运行第一次健康检查之前等待的持续时间。这用于为容器提供启动时间（默认为 0 秒）。

+   `--retries`：如果健康检查连续失败给定次数的重试（默认为 3 次），则容器将被视为不健康。

在下面的示例中，我们通过使用`HEALTHCHECK`指令提供我们的自定义值来覆盖了默认值：

```
HEALTHCHECK --interval=1m --timeout=2s --start-period=2m --retries=3 \    CMD curl -f http://localhost/ || exit 1
```

我们可以使用`docker container list`命令来检查容器的健康状态。这将在`STATUS`列下列出健康状态：

```
CONTAINER ID  IMAGE     COMMAND                  CREATED
  STATUS                        PORTS                NAMES
d4e627acf6ec  sample    "apache2ctl -D FOREG…"   About a minute ago
  Up About a minute (healthy)   0.0.0.0:80->80/tcp   upbeat_banach
```

一旦我们启动容器，健康状态将是健康：启动中。成功执行`HEALTHCHECK`命令后，状态将变为`健康`。

在下一个练习中，我们将使用`EXPOSE`和`HEALTHCHECK`指令来创建一个带有 Apache web 服务器的 Docker 容器，并为其定义健康检查。

## 练习 2.07：在 Dockerfile 中使用 EXPOSE 和 HEALTHCHECK 指令

你的经理要求你将 Apache web 服务器 docker 化，以便从 Web 浏览器访问 Apache 首页。此外，他要求你配置健康检查以确定 Apache web 服务器的健康状态。在这个练习中，你将使用`EXPOSE`和`HEALTHCHECK`指令来实现这个目标：

1.  创建一个名为`expose-healthcheck`的新目录：

```
mkdir expose-healthcheck
```

1.  导航到新创建的`expose-healthcheck`目录：

```
cd expose-healthcheck
```

1.  在`expose-healthcheck`目录中，创建一个名为`Dockerfile`的文件：

```
touch Dockerfile
```

1.  现在，用你喜欢的文本编辑器打开`Dockerfile`：

```
vim Dockerfile
```

1.  将以下内容添加到`Dockerfile`中，保存并退出`Dockerfile`：

```
# EXPOSE & HEALTHCHECK example
FROM ubuntu
RUN apt-get update && apt-get install apache2 curl -y 
HEALTHCHECK CMD curl -f http://localhost/ || exit 1
EXPOSE 80
ENTRYPOINT ["apache2ctl", "-D", "FOREGROUND"]
```

这个`Dockerfile`首先将 ubuntu 镜像定义为父镜像。接下来，我们执行`apt-get update`命令来更新软件包列表，以及`apt-get install apache2 curl -y`命令来安装 Apache web 服务器和 curl 工具。`Curl`是执行`HEALTHCHECK`命令所需的。接下来，我们使用 curl 将`HEALTHCHECK`指令定义为`http://localhost/`端点。然后，我们暴露了 Apache web 服务器的端口`80`，以便我们可以从网络浏览器访问首页。最后，我们使用`ENTRYPOINT`指令启动了 Apache web 服务器。

1.  现在，构建 Docker 镜像：

```
$ docker image build -t expose-healthcheck.
```

您应该会得到以下输出：

![图 2.14：构建 expose-healthcheck Docker 镜像](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-ws/img/B15021_02_14.jpg)

图 2.14：构建 expose-healthcheck Docker 镜像

1.  执行`docker container run`命令，从前一步构建的 Docker 镜像启动一个新的容器。请注意，您使用了`-p`标志将主机的端口`80`重定向到容器的端口`80`。此外，您使用了`--name`标志将容器名称指定为`expose-healthcheck-container`，并使用了`-d`标志以分离模式运行容器（这将在后台运行容器）：

```
$ docker container run -p 80:80 --name expose-healthcheck-container -d expose-healthcheck
```

1.  使用`docker container list`命令列出正在运行的容器：

```
$ docker container list
```

在下面的输出中，您可以看到`expose-healthcheck-container`的`STATUS`为健康：

![图 2.15：运行容器列表](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-ws/img/B15021_02_15.jpg)

图 2.15：运行容器列表

1.  现在，您应该能够查看 Apache 首页。从您喜欢的网络浏览器转到`http://127.0.0.1`端点：![图 2.16：Apache 首页](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-ws/img/B15021_02_16.jpg)

图 2.16：Apache 首页

1.  现在清理容器。首先，使用`docker container stop`命令停止 Docker 容器：

```
$ docker container stop expose-healthcheck-container
```

1.  最后，使用`docker container rm`命令删除 Docker 容器：

```
$ docker container rm expose-healthcheck-container
```

在这个练习中，您利用了`EXPOSE`指令将 Apache web 服务器暴露为 Docker 容器，并使用了`HEALTHCHECK`指令来定义一个健康检查，以验证 Docker 容器的健康状态。

在下一节中，我们将学习`ONBUILD`指令。

## ONBUILD 指令

`ONBUILD`指令用于在`Dockerfile`中创建可重用的 Docker 镜像，该镜像将用作另一个 Docker 镜像的基础。例如，我们可以创建一个包含所有先决条件的 Docker 镜像，如依赖和配置，以便运行一个应用程序。然后，我们可以使用这个“先决条件”镜像作为父镜像来运行应用程序。

在创建先决条件镜像时，我们可以使用`ONBUILD`指令，该指令将包括应仅在此镜像作为另一个`Dockerfile`中的父镜像时执行的指令。`ONBUILD`指令在构建包含`ONBUILD`指令的`Dockerfile`时不会被执行，而只有在构建子镜像时才会执行。

`ONBUILD`指令采用以下格式：

```
ONBUILD <instruction>
```

举个例子，假设我们的自定义基础镜像的`Dockerfile`中有以下`ONBUILD`指令：

```
ONBUILD ENTRYPOINT ["echo","Running ONBUILD directive"]
```

如果我们从自定义基础镜像创建一个 Docker 容器，那么`"Running ONBUILD directive"`值将不会被打印出来。然而，如果我们将我们的自定义基础镜像用作新的子 Docker 镜像的基础，那么`"Running ONBUILD directive"`值将被打印出来。

我们可以使用`docker image inspect`命令来列出父镜像的 OnBuild 触发器：

```
$ docker image inspect <parent-image>
```

该命令将返回类似以下的输出：

```
...
"OnBuild": [
    "CMD [\"echo\",\"Running ONBUILD directive\"]"
]
...
```

在下一个练习中，我们将使用`ONBUILD`指令来定义一个 Docker 镜像来部署 HTML 文件。

## 练习 2.08：在 Dockerfile 中使用 ONBUILD 指令

你的经理要求你创建一个能够运行软件开发团队提供的任何 HTML 文件的 Docker 镜像。在这个练习中，你将构建一个带有 Apache Web 服务器的父镜像，并使用`ONBUILD`指令来复制 HTML 文件。软件开发团队可以使用这个 Docker 镜像作为父镜像来部署和测试他们创建的任何 HTML 文件。

1.  创建一个名为`onbuild-parent`的新目录：

```
mkdir onbuild-parent
```

1.  导航到新创建的`onbuild-parent`目录：

```
cd onbuild-parent
```

1.  在`onbuild-parent`目录中，创建一个名为`Dockerfile`的文件：

```
touch Dockerfile
```

1.  现在，用你喜欢的文本编辑器打开`Dockerfile`：

```
vim Dockerfile
```

1.  将以下内容添加到`Dockerfile`中，保存并退出`Dockerfile`：

```
# ONBUILD example
FROM ubuntu
RUN apt-get update && apt-get install apache2 -y 
ONBUILD COPY *.html /var/www/html
EXPOSE 80
ENTRYPOINT ["apache2ctl", "-D", "FOREGROUND"]
```

这个`Dockerfile`首先将 ubuntu 镜像定义为父镜像。然后执行`apt-get update`命令来更新软件包列表，以及`apt-get install apache2 -y`命令来安装 Apache Web 服务器。`ONBUILD`指令用于提供一个触发器，将所有 HTML 文件复制到`/var/www/html`目录。`EXPOSE`指令用于暴露容器的端口`80`，`ENTRYPOINT`用于使用`apache2ctl`命令启动 Apache Web 服务器。

1.  现在，构建 Docker 镜像：

```
$ docker image build -t onbuild-parent .
```

输出应该如下所示：

![图 2.17：构建 onbuild-parent Docker 镜像](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-ws/img/B15021_02_17.jpg)

图 2.17：构建 onbuild-parent Docker 镜像

1.  执行`docker container run`命令以从上一步构建的 Docker 镜像启动新容器：

```
$ docker container run -p 80:80 --name onbuild-parent-container -d onbuild-parent
```

在上述命令中，您已经以分离模式启动了 Docker 容器，同时暴露了容器的端口`80`。

1.  现在，您应该能够查看 Apache 首页。在您喜欢的网络浏览器中转到`http://127.0.0.1`端点。请注意，默认的 Apache 首页是可见的：![图 2.18：Apache 首页](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-ws/img/B15021_02_16.jpg)

图 2.18：Apache 首页

1.  现在，清理容器。使用`docker container stop`命令停止 Docker 容器：

```
$ docker container stop onbuild-parent-container
```

1.  使用`docker container rm`命令删除 Docker 容器：

```
$ docker container rm onbuild-parent-container
```

1.  现在，使用`onbuild-parent-container`作为父镜像创建另一个 Docker 镜像，以部署自定义 HTML 首页。首先，将目录更改回到上一个目录：

```
cd ..
```

1.  为这个练习创建一个名为`onbuild-child`的新目录：

```
mkdir onbuild-child
```

1.  导航到新创建的`onbuild-child`目录：

```
cd onbuild-child
```

1.  在`onbuild-child`目录中，创建一个名为`index.html`的文件。这个文件将在构建时由`ONBUILD`命令复制到 Docker 镜像中：

```
touch index.html 
```

1.  现在，使用您喜欢的文本编辑器打开`index.html`文件：

```
vim index.html 
```

1.  将以下内容添加到`index.html`文件中，保存并退出`index.html`文件：

```
<html>
  <body>
    <h1>Learning Docker ONBUILD directive</h1>
  </body>
</html>
```

这是一个简单的 HTML 文件，将在页面的标题中输出`Learning Docker ONBUILD`指令。

1.  在`onbuild-child`目录中，创建一个名为`Dockerfile`的文件：

```
touch Dockerfile
```

1.  现在，使用您喜欢的文本编辑器打开`Dockerfile`：

```
vim Dockerfile
```

1.  将以下内容添加到`Dockerfile`中，保存并退出`Dockerfile`：

```
# ONBUILD example
FROM onbuild-parent
```

这个`Dockerfile`只有一个指令。它将使用`FROM`指令来利用您之前创建的`onbuild-parent` Docker 镜像作为父镜像。

1.  现在，构建 Docker 镜像：

```
$ docker image build -t onbuild-child .
```

![图 2.19：构建 onbuild-child Docker 镜像](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-ws/img/B15021_02_19.jpg)

图 2.19：构建 onbuild-child Docker 镜像

1.  执行`docker container run`命令，从上一步构建的 Docker 镜像启动一个新的容器：

```
$ docker container run -p 80:80 --name onbuild-child-container -d onbuild-child
```

在这个命令中，您已经从`onbuild-child` Docker 镜像启动了 Docker 容器，同时暴露了容器的端口`80`。

1.  您应该能够查看 Apache 首页。在您喜欢的网络浏览器中转到`http://127.0.0.1`端点：![图 2.20：Apache web 服务器的自定义首页](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-ws/img/B15021_02_20.jpg)

图 2.20：Apache web 服务器的自定义首页

1.  现在，清理容器。首先使用`docker container stop`命令停止 Docker 容器：

```
$ docker container stop onbuild-child-container
```

1.  最后，使用`docker container rm`命令删除 Docker 容器：

```
$ docker container rm onbuild-child-container
```

在这个练习中，我们观察到如何使用`ONBUILD`指令创建一个可重用的 Docker 镜像，能够运行提供给它的任何 HTML 文件。我们创建了名为`onbuild-parent`的可重用 Docker 镜像，其中包含 Apache web 服务器，并暴露了端口`80`。这个`Dockerfile`包含`ONBUILD`指令，用于将 HTML 文件复制到 Docker 镜像的上下文中。然后，我们使用`onbuild-parent`作为基础镜像创建了第二个 Docker 镜像，名为`onbuild-child`，它提供了一个简单的 HTML 文件，用于部署到 Apache web 服务器。

现在，让我们通过在下面的活动中使用 Apache web 服务器来测试我们在本章中学到的知识，将给定的 PHP 应用程序进行 docker 化。

## 活动 2.01：在 Docker 容器上运行 PHP 应用程序

假设您想要部署一个 PHP 欢迎页面，根据日期和时间来问候访客，使用以下逻辑。您的任务是使用安装在 Ubuntu 基础镜像上的 Apache web 服务器，对这里给出的 PHP 应用程序进行 docker 化。

```
<?php
$hourOfDay = date('H');
if($hourOfDay < 12) {
    $message = "Good Morning";
} elseif($hourOfDay > 11 && $hourOfDay < 18) {
    $message = "Good Afternoon";
} elseif($hourOfDay > 17){
    $message = "Good Evening";
}
echo $message;
?>
```

这是一个简单的 PHP 文件，根据以下逻辑来问候用户：

![图 2.21：PHP 应用程序的逻辑](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-ws/img/B15021_02_21.jpg)

图 2.21：PHP 应用程序的逻辑

执行以下步骤来完成这个活动：

1.  创建一个文件夹来存储活动文件。

1.  创建一个`welcome.php`文件，其中包含之前提供的代码。

1.  创建一个`Dockerfile`，并在 Ubuntu 基础镜像上使用 PHP 和 Apache2 设置应用程序。

1.  构建并运行 Docker 镜像。

1.  完成后，停止并删除 Docker 容器。

注意

这项活动的解决方案可以通过此链接找到。

# 摘要

在本章中，我们讨论了如何使用`Dockerfile`来创建我们自己的自定义 Docker 镜像。首先，我们讨论了什么是`Dockerfile`以及`Dockerfile`的语法。然后，我们讨论了一些常见的 Docker 指令，包括`FROM`、`LABEL`、`RUN`、`CMD`和`ENTRYPOINT`指令。然后，我们使用我们学到的常见指令创建了我们的第一个`Dockerfile`。

在接下来的部分，我们专注于构建 Docker 镜像。我们深入讨论了关于 Docker 镜像的多个方面，包括 Docker 镜像的分层文件系统，Docker 构建中的上下文，以及在 Docker 构建过程中缓存的使用。然后，我们讨论了更高级的`Dockerfile`指令，包括`ENV`、`ARG`、`WORKDIR`、`COPY`、`ADD`、`USER`、`VOLUME`、`EXPOSE`、`HEALTHCHECK`和`ONBUILD`指令。

在下一章中，我们将讨论 Docker 注册表是什么，看看私有和公共 Docker 注册表，并学习如何将 Docker 镜像发布到 Docker 注册表。
