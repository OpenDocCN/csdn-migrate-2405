# Kubernetes 研讨会（一）

> 原文：[`zh.annas-archive.org/md5/DFC15E6DFB274E63E53841C0858DE863`](https://zh.annas-archive.org/md5/DFC15E6DFB274E63E53841C0858DE863)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 前言

# 关于本书

由于其广泛的支持，可以管理数百个运行云原生应用程序的容器，Kubernetes 是最受欢迎的开源容器编排平台，使集群管理变得简单。本研讨会采用实用方法，让您熟悉 Kubernetes 环境及其应用。

从介绍 Kubernetes 的基础知识开始，您将安装和设置 Kubernetes 环境。您将了解如何编写 YAML 文件并部署您的第一个简单的 Web 应用程序容器使用 Pod。然后，您将为 Pod 分配人性化的名称，探索各种 Kubernetes 实体和功能，并发现何时使用它们。随着您逐章阅读，这本 Kubernetes 书将向您展示如何通过应用各种技术来设计组件和部署集群，充分利用 Kubernetes。您还将掌握限制对集群内部某些功能访问的安全策略。在本书的最后，您将了解构建自己的控制器和升级到 Kubernetes 集群的高级功能，而无需停机。

通过本研讨会，您将能够使用 Kubernetes 高效地管理容器并运行基于云的应用程序。

## 受众

无论您是新手网页编程世界，还是经验丰富的开发人员或软件工程师，希望使用 Kubernetes 来管理和扩展容器化应用程序，您都会发现这个研讨会很有用。要充分利用本书，需要对 Docker 和容器化有基本的了解。

## 关于章节

*第一章*，*Kubernetes 和容器简介*，从容器化技术以及支持容器化的各种基础 Linux 技术开始。该章节介绍了 Kubernetes，并阐明了它带来的优势。

*第二章*，*Kubernetes 概述*，为您提供了对 Kubernetes 的第一次实际介绍，并概述了 Kubernetes 的架构。

*第三章*，*kubectl - Kubernetes 命令中心*，介绍了使用 kubectl 的各种方式，并强调了声明式管理的原则。

*第四章*，*如何与 Kubernetes（API 服务器）通信*，深入介绍了 Kubernetes API 服务器的细节以及与其通信的各种方式。

第五章，“Pods”，介绍了部署任何应用程序所使用的基本 Kubernetes 对象。

第六章，“标签和注释”，涵盖了 Kubernetes 中用于对不同对象进行分组、分类和链接的基本机制。

第七章，“Kubernetes 控制器”，介绍了各种 Kubernetes 控制器，如部署和有状态集等，它们是声明式管理方法的关键推动者之一。

第八章，“服务发现”，描述了如何使不同的 Kubernetes 对象在集群内以及集群外可被发现。

第九章，“存储和读取磁盘上的数据”，解释了 Kubernetes 提供的各种数据存储抽象，以使应用程序能够在磁盘上读取和存储数据。

第十章，“ConfigMaps 和 Secrets”，教会你如何将应用程序配置数据与应用程序本身分离开来，同时看到采取这种方法的优势。

第十一章，“构建您自己的 HA 集群”，指导您在**亚马逊网络服务**（**AWS**）平台上设置自己的高可用性、多节点 Kubernetes 集群。

第十二章，“您的应用程序和 HA”，阐述了使用 Kubernetes 进行持续集成的一些概念，并演示了在**亚马逊弹性 Kubernetes 服务**上运行的高可用性、多节点、托管 Kubernetes 集群的一些方法。

第十三章，“Kubernetes 中的运行时和网络安全性”，概述了应用程序和集群可能受到攻击的方式，然后介绍了 Kubernetes 提供的访问控制和安全功能。

第十四章，“在 Kubernetes 中运行有状态的组件”，教会你如何正确使用不同的 Kubernetes 抽象来可靠地部署有状态的应用程序。

第十五章，“Kubernetes 中的监控和自动扩展”，涵盖了您可以监视不同 Kubernetes 对象的方式，然后利用这些信息来扩展集群的容量。

第十六章，“Kubernetes Admission Controllers”，描述了 Kubernetes 如何允许我们扩展 API 服务器提供的功能，以在 API 服务器接受请求之前实施自定义策略。

第十七章，“Kubernetes 中的高级调度”，描述了调度器如何在 Kubernetes 集群上放置 pod。您将使用高级功能来影响 pod 的调度器放置决策。

第十八章，“无停机升级您的集群”，教会您如何将您的 Kubernetes 平台升级到新版本，而不会对您的平台或应用程序造成任何停机时间。

第十九章，“Kubernetes 中的自定义资源定义”，向您展示了扩展 Kubernetes 提供的功能的主要方式之一。您将看到自定义资源如何允许您在集群上实现特定于您自己领域的概念。

注意

章节中提出的活动的解决方案可以在此地址找到：[`packt.live/304PEoD`](https://packt.live/304PEoD)。

## 约定

文本中的代码单词、数据库表名、文件夹名、文件名、文件扩展名、路径名、虚拟 URL 和用户输入显示如下：“在当前工作目录中创建名为`sample-pod.yaml`的文件。”

代码块、终端命令或创建 YAML 文件的文本设置如下：

```
kubectl -n webhooks create secret tls webhook-server-tls \
--cert "tls.crt" \
--key "tls.key"
```

新的重要单词会显示为：“Kubernetes 通过**Admission Controllers**提供了这种能力。”

代码片段的关键部分如下所示：

```
kind: Pod
metadata:
  name: infra-libraries-application-staging
  namespace: metadata-activity
  labels:
    environment: staging
    team: infra-libraries
  annotations:
      team-link: "https://jira-link/team-link-2"
spec:
  containers:
```

您在屏幕上看到的文字，例如菜单或对话框中的文字，会以如下方式出现在文本中：“在左侧边栏上，点击`配置`，然后点击`数据源`。”

长代码片段已被截断，并且在截断的代码顶部放置了 GitHub 上代码文件的相应名称。完整代码的永久链接放置在代码片段下方。它应该如下所示：

mutatingcontroller.go

```
46 //create the response with patch bytes 
47 var admissionResponse *v1beta1.AdmissionResponse 
48 admissionResponse = &v1beta1.AdmissionResponse { 
49     allowed: true, 
50     Patch:   patchBytes, 
51     PatchType: func() *v1beta1.PatchType { 
52         pt := v1beta1.PatchTypeJSONPatch 
53         return &pt 
54     }(), 
55 } 
```

此示例的完整代码可以在[`packt.live/35ieNiX`](https://packt.live/35ieNiX)找到。

## 设置您的环境

在我们详细探讨本书之前，我们需要设置特定的软件和工具。在接下来的部分中，我们将看到如何做到这一点。

### 硬件要求

您需要至少具有虚拟化支持的双核 CPU、4GB 内存和 20GB 可用磁盘空间。

### 操作系统要求

我们推荐的操作系统是 Ubuntu 20.04 LTS 或 macOS 10.15。如果您使用 Windows，可以双启动 Ubuntu。我们已在本节末尾提供了相关说明。

### 虚拟化

您需要在硬件和操作系统上启用虚拟化功能。

在 Linux 中，您可以运行以下命令来检查虚拟化是否已启用：

```
grep -E --color 'vmx|svm' /proc/cpuinfo
```

您应该收到此命令的非空响应。如果您收到空响应，则表示您未启用虚拟化。

在 macOS 中，运行以下命令：

```
sysctl -a | grep -E --color 'machdep.cpu.features|VMX'
```

如果虚拟化已启用，你应该能够在输出中看到`VMX`。

注意

如果你的主机环境是虚拟化的，你将无法按照本书中的说明进行操作，因为 Minikube（默认情况下）在虚拟机中运行所有 Kubernetes 组件，如果主机环境本身是虚拟化的，则无法工作。虽然可以在没有虚拟化程序的情况下使用 Minikube，但你的结果有时可能与本书中的演示不同。因此，我们建议直接在你的机器上安装其中一个推荐的操作系统。

## 安装和设置

本节列出了本书所需软件的安装说明。由于我们推荐使用 Ubuntu，我们将使用 APT 软件包管理器在 Ubuntu 中安装大部分所需软件。

对于 macOS，我们建议你使用 Homebrew 来方便。你可以通过在终端中运行此脚本来安装它：

```
/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/master/install.sh)"
```

此脚本的终端输出将显示将应用的更改，然后要求你确认。确认后，安装就可以完成了。

### 更新你的软件包列表

在 Ubuntu 中使用 APT 安装任何软件包之前，请确保你的软件包列表是最新的。使用以下命令：

```
sudo apt update
```

此外，你可以使用以下命令升级你机器上的任何可升级软件包：

```
sudo apt upgrade
```

同样，在 macOS 的情况下，使用以下命令更新 Homebrew 的软件包列表：

```
brew update
```

### 安装 Git

这个研讨会的代码包在我们的 GitHub 存储库中可用。你可以使用 Git 克隆存储库以获取所有代码文件。

在 Ubuntu 上安装 Git，请使用以下命令：

```
sudo apt install git-all
```

如果你在 macOS 上使用 Xcode，很可能已经安装了 Git。你可以通过运行此命令来检查：

```
git --version
```

如果出现“命令未找到”错误，则表示你没有安装它。你可以使用 Homebrew 来安装，使用以下命令：

```
brew install git
```

### jq

jq 是一个 JSON 解析器，对于从 JSON 格式的 API 响应中提取任何信息非常有用。你可以使用以下命令在 Ubuntu 上安装它：

```
sudo apt install jq
```

你可以使用以下命令在 macOS 上进行安装：

```
brew install jq
```

### Tree

Tree 是一个包，可以让你在终端中看到目录结构。你可以使用以下命令在 Ubuntu 上安装它：

```
sudo apt install tree
```

你可以使用以下命令在 macOS 上进行安装：

```
brew install tree
```

### AWS CLI

AWS 命令行工具是一个 CLI 工具，您可以从终端使用它来管理您的 AWS 资源。您可以使用此 URL 中的安装说明进行安装：[`docs.aws.amazon.com/cli/latest/userguide/install-cliv2.html`](https://docs.aws.amazon.com/cli/latest/userguide/install-cliv2.html)。

### Minikube 和 kubectl

Minikube 允许我们为学习和测试目的创建一个单节点 Kubernetes 集群。kubectl 是一个命令行接口工具，允许我们与我们的集群进行通信。您将在*第二章* *Kubernetes 概述*中找到这些工具的详细安装说明。

即使您已经安装了 Minikube，我们建议您使用*第二章* *Kubernetes 概述*中指定的版本，以确保本书中所有说明的可重复性。

Minikube 需要您安装一个 hypervisor。我们将使用 VirtualBox。

### VirtualBox

VirtualBox 是一个开源的 hypervisor，可以被 Minikube 用来为我们的集群虚拟化一个节点。使用以下命令在 Ubuntu 上安装 VirtualBox：

```
sudo apt install virtualbox
```

对于 macOS 的安装，请首先从此链接获取适当的文件：

[`www.virtualbox.org/wiki/Downloads`](https://www.virtualbox.org/wiki/Downloads).

然后，按照此处提到的安装说明进行操作：

[`www.virtualbox.org/manual/ch02.html#installation-mac`](https://www.virtualbox.org/manual/ch02.html#installation-mac).

### Docker

Docker 是 Kubernetes 使用的默认容器化引擎。您将在*第一章* *Kubernetes 和容器简介*中了解更多关于 Docker 的信息。

要安装 Docker，请按照此链接中的安装说明进行操作：

[`docs.docker.com/engine/install/`](https://docs.docker.com/engine/install/).

要在 Mac 中安装 Docker，请按照以下链接中的安装说明进行操作：

[`docs.docker.com/docker-for-mac/install/`](https://docs.docker.com/docker-for-mac/install/).

要在 Ubuntu 中安装 Docker，请按照以下链接中的安装说明进行操作：

[`docs.docker.com/engine/install/ubuntu/`](https://docs.docker.com/engine/install/ubuntu/).

### Go

Go 是一种用于构建本书中演示的应用程序的编程语言。此外，Kubernetes 也是用 Go 编写的。要在您的机器上安装 Go，请使用以下命令进行 Ubuntu 的安装：

```
sudo apt install golang-go
```

对于 macOS 的安装，请使用以下说明：

1.  使用以下命令安装 Go：

```
brew install golang
```

注意

该代码已经在 Go 版本 1.13 和 1.14 上进行了测试。请确保您拥有这些版本，尽管代码预计将适用于所有 1.x 版本。

1.  现在，我们需要设置一些环境变量。使用以下命令：

```
mkdir - p $HOME/go
export GOPATH=$HOME/go
export GOROOT="$(brew --prefix golang)/libexec"
export PATH="$PATH:${GOPATH}/bin:${GOROOT}/bin"
```

### kops

kops 是一个命令行接口工具，允许您在 AWS 上设置 Kubernetes 集群。使用 kops 安装 Kubernetes 的实际过程在*第十一章*“构建您自己的 HA 集群”中有所涵盖。为了确保本书中给出的说明的可重复性，我们建议您安装 kops 版本 1.15.1。

要在 Ubuntu 上安装，请按照以下步骤进行：

1.  使用以下命令下载 kops 版本 1.15.1 的二进制文件：

```
curl -LO https://github.com/kubernetes/kops/releases/download/1.15.0/kops-linux-amd64
```

1.  现在，使用以下命令使二进制文件可执行：

```
chmod +x kops-linux-amd64
```

1.  将可执行文件添加到您的路径：

```
sudo mv kops-linux-amd64 /usr/local/bin/kops
```

1.  通过运行以下命令检查 kops 是否已成功安装：

```
kops version
```

如果 kops 已成功安装，您应该会得到一个声明版本为 1.15.0 的响应。

要在 macOS 上安装，请按照以下步骤进行：

1.  使用以下命令下载 kops 版本 1.15.1 的二进制文件：

```
curl -LO https://github.com/kubernetes/kops/releases/download/1.15.0/kops-darwin-amd64
```

1.  现在，使用以下命令使二进制文件可执行：

```
chmod +x kops-darwin-amd64
```

1.  将可执行文件添加到您的路径：

```
sudo mv kops-darwin-amd64 /usr/local/bin/kops
```

1.  通过运行以下命令检查 kops 是否已成功安装：

```
kops version
```

如果 kops 已成功安装，您应该会得到一个声明版本为 1.15.0 的响应。

## 为 Windows 用户双引导 Ubuntu

在本节中，您将找到有关如何在运行 Windows 的计算机上双引导 Ubuntu 的说明。

注意

在安装任何操作系统之前，强烈建议您备份系统状态以及所有数据。

### 调整分区大小

如果您的计算机上安装了 Windows，那么您的硬盘很可能已完全被使用-也就是说，所有可用空间都已被分区和格式化。我们需要在硬盘上有一些未分配的空间。因此，我们将调整一个有大量空闲空间的分区的大小，以便为我们的 Ubuntu 分区腾出空间：

1.  打开计算机管理实用程序。按下`Win + R`并输入`compmgmt.msc`：![图 0.1：Windows 上的计算机管理实用程序](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/k8s-ws/img/B14870_0_01.jpg)

图 0.1：Windows 上的计算机管理实用程序

1.  在左侧窗格中，转到`存储 > 磁盘管理`选项，如下所示：![图 0.2：磁盘管理](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/k8s-ws/img/B14870_0_02.jpg)

图 0.2：磁盘管理

您将在屏幕下半部分看到所有分区的摘要。您还可以看到与所有分区相关的驱动器号以及有关 Windows 引导驱动器的信息。如果您有一个有大量可用空间（20 GB +）的分区，既不是引导驱动器（`C:`），也不是恢复分区，也不是 EFI 系统分区，那么这将是选择的理想选项。如果没有这样的分区，那么您可以调整`C:`驱动器。

1.  在这个例子中，我们将选择`D:`驱动器。您可以右键单击任何分区并打开`属性`来检查可用的空间：![图 0.3：检查 D:驱动器的属性](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/k8s-ws/img/B14870_0_03.jpg)

图 0.3：检查 D:驱动器的属性

现在，在我们调整分区大小之前，我们需要确保文件系统没有错误或任何硬件故障。我们将使用 Windows 上的**chkdsk**实用程序来做到这一点。

1.  通过按`Win + R`并输入`cmd.exe`来打开命令提示符。现在，运行以下命令：

```
chkdsk D: /f
```

用您想要使用的驱动器号替换驱动器号。您应该看到类似以下的响应：

![图 0.4：扫描驱动器以查找任何文件系统错误](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/k8s-ws/img/B14870_0_04.jpg)

图 0.4：扫描驱动器以查找任何文件系统错误

请注意，在此截图中，Windows 报告已扫描文件系统并未发现问题。如果您的情况遇到任何问题，您应该先解决这些问题，以防止数据丢失。

1.  现在，回到`计算机管理`窗口，右键单击所需的驱动器，然后单击`收缩卷`，如下所示：![图 0.5：打开收缩卷对话框](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/k8s-ws/img/B14870_0_05.jpg)

图 0.5：打开收缩卷对话框

1.  在提示窗口中，输入您想要清除的空间量在唯一可以编辑的字段中。在这个例子中，我们通过收缩我们的`D:`驱动器来清除大约 25 GB 的磁盘空间：![图 0.6：通过收缩现有卷清除 25 GB](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/k8s-ws/img/B14870_0_06.jpg)

图 0.6：通过收缩现有卷清除 25 GB

1.  收缩驱动器后，您应该能够在驱动器上看到未分配的空间，如下所示：![图 0.7：收缩卷后的未分配空间](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/k8s-ws/img/B14870_0_07.jpg)

图 0.7：收缩卷后的未分配空间

现在我们准备安装 Ubuntu。但首先，我们需要下载它并创建一个可启动的 USB，这是最方便的安装介质之一。

### 创建一个可启动的 USB 驱动器来安装 Ubuntu

您需要一个至少容量为 4GB 的闪存驱动器。请注意，其中的所有数据将被删除：

1.  从这个链接下载 Ubuntu 桌面的 ISO 映像：[`releases.ubuntu.com/20.04/`](https://releases.ubuntu.com/20.04/)。

1.  接下来，我们需要将 ISO 映像烧录到 USB 闪存盘并创建一个可启动的 USB 驱动器。有许多可用的工具，您可以使用其中任何一个。在本例中，我们使用的是免费开源的 Rufus。您可以从这个链接获取它：[`www.fosshub.com/Rufus.html`](https://www.fosshub.com/Rufus.html)。

1.  安装了 Rufus 后，插入您的 USB 闪存盘并打开 Rufus。确保选择了正确的`Device`选项，如下面的屏幕截图所示。

1.  在`Boot selection`下按`SELECT`按钮，然后打开您下载的 Ubuntu 18.04 映像。

1.  `分区方案`的选择将取决于您的 BIOS 和磁盘驱动器的配置方式。对于大多数现代系统来说，`GPT`将是最佳选择，而`MBR`将兼容较旧的系统：![图 0.8：Rufus 的配置](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/k8s-ws/img/B14870_0_08.jpg)

图 0.8：Rufus 的配置

1.  您可以将所有其他选项保持默认，然后按`START`。完成后，关闭 Rufus。您现在有一个可启动的 USB 驱动器，准备安装 Ubuntu。

### 安装 Ubuntu

现在，我们将使用可启动的 USB 驱动器来安装 Ubuntu：

1.  安装 Ubuntu，使用我们刚刚创建的可启动安装介质进行引导。在大多数情况下，您应该可以通过在启动机器时插入 USB 驱动器来实现这一点。如果您没有自动引导到 Ubuntu 设置，请进入 BIOS 设置，并确保您的 USB 设备处于最高的引导优先级，并且安全启动已关闭。输入 BIOS 设置的说明通常显示在启动计算机时显示的闪屏（即您的个人电脑制造商标志的屏幕）上。您也可以在启动时选择进入启动菜单的选项。通常情况下，您必须在 PC 启动时按住`Delete`、`F1`、`F2`、`F12`或其他一些键。这取决于您主板的 BIOS。

您应该看到一个带有“尝试 Ubuntu”或“安装 Ubuntu”选项的屏幕。如果您没有看到这个屏幕，而是看到一个以“最小的 BASH 类似行编辑支持…”开头的消息的 shell，那么很可能在下载 ISO 文件或创建可启动的 USB 驱动器时可能出现了一些数据损坏。通过计算您下载文件的`MD5`、`SHA1`或`SHA256`哈希值来检查下载的 ISO 文件的完整性，并将其与 Ubuntu 下载页面上的文件`MD5SUMS`、`SHA1SUMS`或`SHA256SUMS`中的哈希值进行比较。然后，重复上一节中的步骤重新格式化和重新创建可启动的 USB 驱动器。

如果您已经在 BIOS 中将最高启动优先级设置为正确的 USB 设备，但仍然无法使用 USB 设备启动（您的系统可能会忽略它而启动到 Windows），那么可能有两个最常见的问题：

- USB 驱动器未正确配置为可识别的可启动设备，或者 GRUB 引导加载程序未正确设置。验证您下载的镜像的完整性并重新创建可启动的 USB 驱动器应该在大多数情况下解决这个问题。

- 您选择了错误的“分区方案”选项适用于您的系统配置。尝试另一个选项并重新创建 USB 驱动器。

1.  使用 USB 驱动器启动计算机后，选择“安装 Ubuntu”。

1.  选择您想要的语言，然后按“继续”。

1.  在下一个屏幕上，选择适当的键盘布局，然后继续到下一个屏幕。

1.  在下一个屏幕上，选择“普通安装”。

勾选“在安装 Ubuntu 时下载更新”和“为图形和 Wi-Fi 硬件以及其他媒体格式安装第三方软件”选项。

然后，继续到下一个屏幕。

1.  在下一个屏幕上，选择“在 Windows 引导管理器旁边安装 Ubuntu”，然后点击“立即安装”。您将看到一个提示描述 Ubuntu 将对您的系统进行的更改，例如将创建的新分区。确认更改并继续到下一个屏幕。

1.  在下一个屏幕上，选择您的地区，然后按“继续”。

1.  在下一个屏幕上，设置您的姓名（可选）、用户名、计算机名和密码，然后按“继续”。

安装现在应该开始了。根据您的系统配置，这将需要一些时间。安装完成后，您将收到提示重新启动计算机。拔掉您的 USB 驱动器，然后点击“立即重启”。

如果您忘记拔掉 USB 驱动器，可能会重新启动到 Ubuntu 安装界面。在这种情况下，只需退出安装程序。如果已启动 Ubuntu 的实例，请重新启动您的机器。这次记得拔掉 USB 驱动器。

如果重新启动后，您直接进入 Windows 而没有选择操作系统的选项，可能的问题是 Ubuntu 安装的 GRUB 引导加载程序没有优先于 Windows 引导加载程序。在某些系统中，硬盘上引导加载程序的优先级是在 BIOS 中设置的。您需要在 BIOS 设置菜单中找到适当的设置。它可能被命名为类似于`UEFI 硬盘驱动器优先级`的内容。确保将`GRUB`/`Ubuntu`设置为最高优先级。

## 其他要求

**Docker Hub 账户**：您可以在此链接创建免费的 Docker 账户：[`hub.docker.com/`](https://hub.docker.com/)。

**AWS 账户**：您将需要自己的 AWS 账户以及一些关于使用 AWS 的基本知识。您可以在此处创建一个账户：[`aws.amazon.com/`](https://aws.amazon.com/)。

注意

本书中的练习和活动要求超出了 AWS 的免费套餐范围，因此您应该知道您将因使用云服务而产生费用。您可以在此处查看定价信息：[`aws.amazon.com/pricing/`](https://aws.amazon.com/pricing/)。

## 访问代码文件

您可以在[`packt.live/3bE3zWY`](https://packt.live/3bE3zWY)找到本书的完整代码文件。

安装 Git 后，您可以使用以下命令克隆存储库：

```
git clone https://github.com/PacktWorkshops/Kubernetes-Workshop
cd Kubernetes-Workshop
```

如果您在安装过程中遇到任何问题或有任何疑问，请发送电子邮件至`workshops@packt.com`。


# 第一章： Kubernetes 和容器简介

概述

本章首先描述了软件开发和交付的演变，从在裸机上运行软件，到现代容器化方法。我们还将看一下支持容器化的底层 Linux 技术。在本章结束时，您将能够从镜像中运行基本的 Docker 容器。您还将能够打包自定义应用程序以制作自己的 Docker 镜像。接下来，我们将看一下如何控制容器的资源限制和分组。最后，本章结束时描述了为什么我们需要像 Kubernetes 这样的工具，以及对其优势的简短介绍。

# 介绍

大约十年前，关于服务导向架构、敏捷开发和软件设计模式等软件开发范式进行了大量讨论。回顾来看，这些都是很好的想法，但只有少数被实际采纳了十年前。

这些范式缺乏采纳的一个主要原因是底层基础设施无法提供资源或能力来抽象细粒度的软件组件，并管理最佳的软件开发生命周期。因此，仍然需要大量重复的工作来解决软件开发的一些常见问题，如管理软件依赖关系和一致的环境、软件测试、打包、升级和扩展。

近年来，以 Docker 为首的容器技术提供了一种新的封装机制，允许您捆绑应用程序、其运行时和其依赖项，并为软件开发带来了新的视角。通过使用容器技术，底层基础设施被抽象化，以便应用程序可以在异构环境中无缝移动。然而，随着容器数量的增加，您可能需要编排工具来帮助您管理它们之间的交互，以及优化底层硬件的利用率。

这就是 Kubernetes 发挥作用的地方。Kubernetes 提供了各种选项来自动化部署、扩展和管理容器化应用程序。它近年来得到了爆炸式的采用，并已成为容器编排领域的事实标准。

作为本书的第一章，我们将从过去几十年软件开发的简要历史开始，然后阐述容器和 Kubernetes 的起源。我们将重点解释它们可以解决什么问题，以及它们为什么在最近几年的采用率大幅上升的**三个关键原因**。

# 软件开发的演变

随着虚拟化技术的发展，公司通常使用**虚拟机**（**VMs**）来管理其软件产品，无论是在公共云还是本地环境中。这带来了诸如自动机器配置、更好的硬件资源利用、资源抽象等巨大好处。更为重要的是，它首次采用了计算、网络和存储资源的分离，使软件开发摆脱了硬件管理的繁琐。虚拟化还带来了以编程方式操纵底层基础设施的能力。因此，从系统管理员和开发人员的角度来看，他们可以更好地优化软件维护和开发的工作流程。这是软件开发历史上的一大进步。

然而，在过去的十年中，软件开发的范围和生命周期发生了巨大变化。以前，将软件开发成大型的单块是很常见的，发布周期很慢。如今，为了跟上业务需求的快速变化，一款软件可能需要被拆分成个别的细粒度子组件，并且每个组件可能需要有自己的发布周期，以便尽可能频繁地发布，以便更早地从市场获得反馈。此外，我们可能希望每个组件都具有可伸缩性和成本效益。

那么，这对应用程序开发和部署有什么影响呢？与裸机时代相比，采用虚拟机并没有太大帮助，因为虚拟机并没有改变不同组件管理的粒度；整个软件仍然部署在一台机器上，只不过是虚拟机而不是物理机。使一些相互依赖的组件共同工作仍然不是一件容易的事情。

这里的一个直接的想法是添加一个抽象层，将机器与运行在其上的应用程序连接起来。这样应用程序开发人员只需要专注于业务逻辑来构建应用程序。一些例子包括 Google App Engine（GAE）和 Cloud Foundry。

这些解决方案的第一个问题是不同环境之间缺乏一致的开发体验。开发人员在他们的机器上开发和测试应用程序，使用他们本地的依赖关系（无论是在编程语言还是操作系统级别）；而在生产环境中，应用程序必须依赖另一组底层依赖关系。而且我们还没有谈到需要不同团队中不同开发人员合作的软件组件。

第二个问题是应用程序和底层基础设施之间的硬性边界会限制应用程序的高性能，特别是如果应用程序对存储、计算或网络资源敏感。例如，您可能希望应用程序部署在多个可用区（数据中心内的隔离地理位置，云资源在其中管理），或者您可能希望一些应用程序共存，或者不与其他特定应用程序共存。或者，您可能希望一些应用程序遵循特定的硬件（例如固态驱动器）。在这种情况下，很难专注于应用程序的功能，而不向上层应用程序暴露基础设施的拓扑特征。

事实上，在软件开发的生命周期中，基础设施和应用程序之间没有明确的界限。我们想要实现的是自动管理应用程序，同时最大限度地利用基础设施。

那么，我们如何实现这一点呢？Docker（我们将在本章后面介绍）通过利用 Linux 容器化技术来解决第一个问题，封装应用程序及其依赖关系。它还引入了 Docker 镜像的概念，使应用程序运行时环境的软件方面变得轻量、可重现和可移植。

**第二个问题**更加复杂。这就是 Kubernetes 发挥作用的地方。Kubernetes 利用一种经过考验的设计理念，称为声明式 API，来抽象基础设施以及应用交付的每个阶段，如部署、升级、冗余、扩展等。它还为用户提供了一系列构建模块，供用户选择、编排并组合成最终的应用程序。我们将逐渐开始学习 Kubernetes，这是本书的核心内容，在本章末尾。

注意

如果没有特别指定，本书中可能会将术语“容器”与“Linux 容器”互换使用。

# 虚拟机与容器

**虚拟机**（**VM**），顾名思义，旨在模拟物理计算机系统。从技术上讲，虚拟机是由虚拟化监控程序提供的，并且虚拟化监控程序运行在主机操作系统上。下图说明了这个概念：

![图 1.1：在虚拟机上运行应用程序](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/k8s-ws/img/B14870_01_01.jpg)

图 1.1：在虚拟机上运行应用程序

在这里，虚拟机具有完整的操作系统堆栈，虚拟机上运行的操作系统（称为“客户操作系统”）必须依赖底层的虚拟化监控程序才能运行。应用程序和操作系统驻留并在虚拟机内运行。它们的操作经过客户操作系统的内核，然后由虚拟化监控程序翻译成系统调用，最终在主机操作系统上执行。

另一方面，容器不需要底层的虚拟化监控程序。通过利用一些 Linux 容器化技术，如命名空间和 cgroups（我们稍后会重新讨论），每个容器都可以独立地在主机操作系统上运行。下图说明了容器化，以 Docker 容器为例：

![图 1.2：在容器中运行应用程序](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/k8s-ws/img/B14870_01_02.jpg)

图 1.2：在容器中运行应用程序

值得一提的是，我们将 Docker 放在容器旁边，而不是在容器和主机操作系统之间。这是因为从技术上讲，没有必要让 Docker 引擎托管这些容器。Docker 引擎更多地扮演着一个管理者的角色，来管理容器的生命周期。将 Docker 引擎比作虚拟化监控程序也是不恰当的，因为一旦容器启动运行，我们就不需要额外的层来“翻译”应用程序操作，使其能够被主机操作系统理解。从*图 1.2*中，你也可以看出容器内的应用程序实质上是直接在主机操作系统上运行的。

当我们启动一个容器时，我们不需要启动整个操作系统；相反，它利用了主机操作系统上 Linux 内核的特性。因此，与虚拟机相比，容器启动更快，功能开销更小，占用的空间也要少得多。以下是一个比较虚拟机和容器的表格：

![图 1.3：虚拟机和容器的比较](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/k8s-ws/img/B14870_01_03.jpg)

图 1.3：虚拟机和容器的比较

从这个比较来看，容器在所有方面都胜过虚拟机，除了隔离性。容器所利用的 Linux 容器技术并不新鲜。关键的 Linux 内核特性，命名空间和 cgroup（我们将在本章后面学习）已经存在了十多年。在 Docker 出现之前，还有一些旧的容器实现，如 LXC 和 Cloud Foundry Warden。现在，一个有趣的问题是：鉴于容器技术有这么多好处，为什么它在最近几年才被采用，而不是十年前？我们将在接下来的章节中找到这个问题的一些答案。

# Docker 基础知识

到目前为止，我们已经看到了容器化相对于在虚拟机上运行应用程序提供的不同优势。Docker 是目前最常用的容器化技术。在本节中，我们将从一些 Docker 基础知识开始，并进行一些练习，让您亲身体验使用 Docker 的工作。

注意

除了 Docker 之外，还有其他容器管理器，如 containerd 和 podman。它们在功能和用户体验方面表现不同，例如，containerd 和 podman 被称为比 Docker 更轻量级，比 Kubernetes 更合适。然而，它们都符合**Open Container Initiatives** (**OCI**)标准，以确保容器镜像兼容。

尽管 Docker 可以安装在任何操作系统上，但你应该知道，在 Windows 和 macOS 上，它实际上创建了一个 Linux 虚拟机（或者在 macOS 中使用类似的虚拟化技术，如 HyperKit），并将 Docker 嵌入到虚拟机中。在本章中，我们将使用 Ubuntu 18.04 LTS 作为操作系统，以及 Docker Community Edition 18.09.7。

在继续之前，请确保按照*前言*中的说明安装了 Docker。您可以通过使用以下命令查询 Docker 的版本来确认 Docker 是否已安装：

```
docker --version
```

您应该看到以下输出：

```
Docker version 18.09.7, build 2d0083d
```

注意

以下部分中的所有命令都是以`root`身份执行的。在终端中输入`sudo -s`，然后在提示时输入管理员密码，以获取 root 访问权限。

## docker run 背后是什么？

安装 Docker 后，运行容器化应用程序非常简单。为了演示目的，我们将使用 Nginx web 服务器作为示例应用程序。我们可以简单地运行以下命令来启动 Nginx 服务器：

```
docker run -d nginx
```

你应该看到类似的结果：

![图 1.4：启动 Nginx](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/k8s-ws/img/B14870_01_04.jpg)

图 1.4：启动 Nginx

这个命令涉及几个动作，描述如下：

1.  `docker run`告诉 Docker 引擎运行一个应用程序。

1.  `-d`参数（`--detach`的缩写）强制应用程序在后台运行，这样你就看不到应用程序在终端的输出。相反，你必须运行`docker logs <container ID>`来隐式获取输出。

注意

“分离”模式通常意味着应用程序是一个长时间运行的服务。

1.  最后一个参数`nginx`表示应用程序所基于的镜像名称。该镜像封装了 Nginx 程序及其依赖项。

输出日志解释了一个简要的工作流程：首先，它尝试在本地获取`nginx`镜像，但失败了，所以它从公共镜像仓库（稍后我们将重新讨论的 Docker Hub）中检索了镜像。一旦镜像在本地下载完成，它就使用该镜像启动一个实例，然后输出一个 ID（在前面的示例中，这是`96c374…`），用于标识运行中的实例。正如你所看到的，这是一个十六进制字符串，你可以在实践中使用前四个或更多的唯一字符来引用任何实例。你应该看到，即使`docker`命令的终端输出也会截断 ID。

可以使用以下命令验证运行实例：

```
docker ps
```

你应该看到以下结果：

![图 1.5：获取所有正在运行的 Docker 容器的列表](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/k8s-ws/img/B14870_01_05.jpg)

图 1.5：获取所有正在运行的 Docker 容器的列表

`docker ps`命令列出所有正在运行的容器。在前面的示例中，只有一个名为`nginx`的容器正在运行。与在物理机器或虚拟机上本地运行的典型 Nginx 发行版不同，`nginx`容器以隔离的方式运行。`nginx`容器默认不会在主机端口上公开其服务。相反，它在其容器的端口上提供服务，这是一个隔离的实体。我们可以通过调用容器 IP 的端口`80`来访问`nginx`服务。

首先，让我们通过运行以下命令获取容器 IP：

```
docker inspect --format '{{.NetworkSettings.IPAddress}}' <Container ID or NAME>
```

您应该看到以下输出（具体内容可能因您的本地环境而异）：

```
172.17.0.2
```

正如您所看到的，在这种情况下，`nginx`容器的 IP 地址为`172.17.0.2`。让我们通过在端口`80`上访问此 IP 来检查 Nginx 是否有响应：

```
curl <container IP>:80
```

您应该看到以下输出：

![图 1.6：Nginx 容器的响应](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/k8s-ws/img/B14870_01_06.jpg)

图 1.6：Nginx 容器的响应

正如您在*图 1.6*中所看到的，我们得到了一个响应，它显示在终端上作为默认主页的源 HTML。

通常，我们不依赖内部 IP 来访问服务。更实际的方法是在主机的某个端口上暴露服务。要将主机端口`8080`映射到容器端口`80`，请使用以下命令：

```
docker run -p 8080:80 -d nginx
```

您应该看到类似的响应：

```
39bf70d02dcc5f038f62c276ada1675c25a06dd5fb772c5caa19f02edbb0622a
```

`-p 8080:80`参数告诉 Docker Engine 启动容器并将主机端口 8080 上的流量映射到容器内部的端口`80`。现在，如果我们尝试在端口`8080`上访问`localhost`，我们将能够访问容器化的`nginx`服务。让我们试一试：

```
curl localhost:8080
```

您应该看到与*图 1.6*中相同的输出。

Nginx 是一种没有固定终止时间的工作负载的示例，也就是说，它不仅仅显示输出然后终止。这也被称为**长时间运行的服务**。另一种工作负载，只是运行到完成并退出的类型，称为**短时间服务**，或简称为**作业**。对于运行作业的容器，我们可以省略`-d`参数。以下是作业的一个示例：

```
docker run hello-world
```

您应该看到以下响应：

![图 1.7：运行 hello-world 镜像](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/k8s-ws/img/B14870_01_07.jpg)

图 1.7：运行 hello-world 镜像

现在，如果您运行`docker ps`，这是用于列出运行中容器的命令，它不会显示`hello-world`容器。这是预期的，因为容器已经完成了它的工作（即，打印出我们在上一个截图中看到的响应文本）并退出了。为了能够找到已退出的容器，您可以使用相同的命令加上`-a`标志运行，这将显示所有容器：

```
docker ps -a
```

您应该看到以下输出：

![图 1.8：检查我们的已退出容器](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/k8s-ws/img/B14870_01_08.jpg)

图 1.8：检查我们的已退出容器

对于已停止的容器，您可以使用`docker rm <container ID>`删除它，或者使用`docker run <container ID>`重新运行它。或者，如果您重新运行`docker run hello-world`，它将再次启动一个新的容器，并在完成工作后退出。您可以按照以下步骤自行尝试：

```
docker run hello-world
docker ps -a
```

您应该看到以下输出：

![图 1.9：检查多个已退出的容器](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/k8s-ws/img/B14870_01_09.jpg)

图 1.9：检查多个已退出的容器

因此，您可以看到基于相同基础镜像运行多个容器是非常简单的。

到目前为止，您应该对容器是如何启动以及如何检查其状态有了非常基本的了解。

## Dockerfile 和 Docker 镜像

在虚拟机时代，没有标准或统一的方式来抽象和打包各种类型的应用程序。传统的方法是使用工具，比如 Ansible，来管理每个应用程序的安装和更新过程。这种方法现在仍在使用，但它涉及大量的手动操作，并且由于不同环境之间的不一致性而容易出错。从开发人员的角度来看，应用程序是在本地机器上开发的，这与分级和最终生产环境大不相同。

那么，Docker 是如何解决这些问题的呢？它带来的创新被称为`Dockerfile`和 Docker 镜像。`Dockerfile`是一个文本文件，它抽象了一系列指令来构建一个可重现的环境，包括应用程序本身以及所有的依赖项。

通过使用`docker build`命令，Docker 使用`Dockerfile`生成一个名为 Docker 镜像的标准化实体，您可以在几乎任何操作系统上运行它。通过利用 Docker 镜像，开发人员可以在与生产环境相同的环境中开发和测试应用程序，因为依赖项被抽象化并捆绑在同一个镜像中。让我们退一步，看看我们之前启动的`nginx`应用程序。使用以下命令列出所有本地下载的镜像：

```
docker images
```

您应该看到以下列表：

![图 1.10：获取镜像列表](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/k8s-ws/img/B14870_01_10.jpg)

图 1.10：获取镜像列表

与虚拟机镜像不同，Docker 镜像只捆绑必要的文件，如应用程序二进制文件、依赖项和 Linux 根文件系统。在内部，Docker 镜像被分成不同的层，每个层都堆叠在另一个层上。这样，升级应用程序只需要更新相关的层。这既减少了镜像的占用空间，也减少了升级时间。

以下图显示了一个假想的 Docker 镜像的分层结构，该镜像是从基本操作系统层（Ubuntu）、Java Web 应用程序运行时层（Tomcat）和最顶层的用户应用程序层构建而成：

![图 1.11：容器中堆叠层的示例](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/k8s-ws/img/B14870_01_11.jpg)

图 1.11：容器中堆叠层的示例

请注意，通常会使用流行操作系统的镜像作为构建 Docker 镜像的起点（正如您将在以下练习中看到的），因为它方便地包含了开发应用程序所需的各种组件。在上述假设的容器中，应用程序将使用 Tomcat 以及 Ubuntu 中包含的一些依赖项才能正常运行。这是将 Ubuntu 包含为基础层的唯一原因。如果我们愿意，我们可以在不包含整个 Ubuntu 基础镜像的情况下捆绑所需的依赖项。因此，不要将其与虚拟机的情况混淆，虚拟机需要包含一个客户操作系统的情况。

让我们看看如何在以下练习中为我们自己构建一个 Docker 镜像。

## 练习 1.01：创建 Docker 镜像并将其上传到 Docker Hub

在这个练习中，我们将为一个用 Go 语言编写的简单应用程序构建一个 Docker 镜像。

在这个练习中，我们将使用 Go，这样源代码和它的语言依赖可以编译成一个可执行的二进制文件。然而，你可以自由选择任何你喜欢的编程语言；只要记得如果你要使用 Java、Python、Node.js 或任何其他语言，就要捆绑语言运行时依赖。

1.  在这个练习中，我们将创建一个名为`Dockerfile`的文件。请注意，这个文件名没有扩展名。你可以使用你喜欢的文本编辑器创建这个文件，内容如下：

```
FROM alpine:3.10
COPY k8s-for-beginners /
CMD ["/k8s-for-beginners"]
```

注意

从终端，无论你是使用 vim 或 nano 这样的简单文本编辑器，还是使用`cat`命令创建文件，它都会被创建在当前工作目录中，无论是在任何 Linux 发行版还是 macOS 中。当你打开终端时，默认的工作目录是`/home/`。如果你想使用不同的目录，请在遵循本书中的任何练习步骤时考虑这一点。

第一行指定了要使用的基础镜像。这个示例使用了 Alpine，一个流行的基础镜像，只占用大约 5MB，基于 Alpine Linux。第二行将一个名为`k8s-for-beginners`的文件从`Dockerfile`所在的目录复制到镜像的根目录。在这个示例中，我们将构建一个微型网络服务器，并将其编译成一个名为`k8s-for-beginners`的二进制文件，该文件将放在与`Dockerfile`相同的目录中。第三行指定了默认的启动命令。在这种情况下，我们只是启动我们的示例网络服务器。

1.  接下来，让我们构建我们的示例网络服务器。创建一个名为`main.go`的文件，内容如下：

```
package main
import (
        "fmt"
        "log"
        "net/http"
)
func main() {
        http.HandleFunc("/", handler)
        log.Fatal(http.ListenAndServe("0.0.0.0:8080", nil))
}
func handler(w http.ResponseWriter, r *http.Request) {
        log.Printf("Ping from %s", r.RemoteAddr)
        fmt.Fprintln(w, "Hello Kubernetes Beginners!")
}
```

正如你可以从`func main()`中观察到的那样，这个应用程序充当一个网络服务器，在 8080 端口的根路径接受传入的 HTTP 请求，并用消息`Hello Kubernetes Beginners`做出响应。

1.  要验证这个程序是否有效，你可以运行`go run main.go`，然后在浏览器上打开[`http://localhost:8080`](http://localhost:8080)。你应该会得到"`Hello Kubernetes Beginners!`"的输出。

1.  使用`go build`将运行时依赖和源代码编译成一个可执行的二进制文件。在终端中运行以下命令：

```
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o k8s-for-beginners
```

注意

与*步骤 3*不同，参数`GOOS=linux GOARCH=amd64`告诉 Go 编译器在特定平台上编译程序，这与我们将要构建的 Linux 发行版兼容。`CGO_ENABLED=0`旨在生成一个静态链接的二进制文件，以便它可以与一些最小定制的镜像一起工作（例如 alpine）。

1.  现在，检查`k8s-for-beginners`文件是否已创建：

```
ls
```

您应该会看到以下响应：

```
Dockerfile k8s-for-beginners  main.go
```

1.  现在我们有了`Dockerfile`和可运行的二进制文件。使用以下命令构建 Docker 镜像：

```
docker build -t k8s-for-beginners:v0.0.1 .
```

不要错过这个命令末尾的点（`.`）。您应该会看到以下响应：

![图 1.12：docker build 命令的输出](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/k8s-ws/img/B14870_01_12.jpg)

图 1.12：docker build 命令的输出

我们使用的命令中有两个参数：`-t k8s-for-beginners:v0.0.1`为镜像提供了一个格式为`<imagename:version>`的标签，而`.`（命令末尾的点）表示查找`Dockerfile`的路径。在这种情况下，`.`指的是当前工作目录。

注意

如果您克隆了本章的 GitHub 存储库，您会发现我们在每个目录中都提供了`Dockerfile`的副本，以便您可以方便地通过转到该目录运行`docker build`命令。

1.  现在，我们本地有了`k8s-for-beginners:v0.0.1`镜像。您可以通过运行以下命令来确认：

```
docker images
```

您应该会看到以下响应：

![图 1.13：验证我们的 Docker 镜像是否已创建](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/k8s-ws/img/B14870_01_13.jpg)

图 1.13：验证我们的 Docker 镜像是否已创建

一个有趣的观察是，该镜像仅占用 11.4 MB，其中包括 Linux 系统文件和我们的应用程序。这里的建议是只在 Docker 镜像中包含必要的文件，使其紧凑，以便易于分发和管理。

现在我们已经构建了我们的镜像，接下来我们将在容器中运行它。另一个需要注意的是，目前这个镜像驻留在我们的本地机器上，我们只能在本地机器上使用它构建一个容器。然而，将应用程序与其依赖项打包的优势在于它可以轻松地在不同的机器上运行。为了方便起见，我们可以将我们的镜像上传到在线 Docker 镜像仓库，如 Docker Hub（[`hub.docker.com/`](https://hub.docker.com/)）。

注意：

除了 Docker Hub，还有其他公共镜像仓库，如[quay.io](http://quay.io)，[gcr.io](http://gcr.io)等。您可以参考各自仓库的文档，以正确配置在您的 Docker 客户端中。

## 练习 1.02：在 Docker 中运行您的第一个应用程序

在*练习 1.01*中，*创建 Docker 镜像并将其上传到 Docker Hub*，我们将 Web 应用程序打包成 Docker 镜像。在这个练习中，我们将运行它并将其推送到 Docker Hub：

1.  首先，我们应该通过在终端中运行以下命令清理掉上一个练习中的任何残留容器：

```
docker rm -f $(docker ps -aq)
```

您应该看到以下响应：

```
43c01e2055cf
286bc0c92b3a
39bf70d02dcc
96c374000f6f
```

我们已经看到`docker ps -a`返回所有容器的信息。`-aq`标志中的额外`q`表示“安静”，该标志只会显示数字 ID。这些 ID 将被传递给`docker rm -f`，因此所有容器将被强制删除。

1.  运行以下命令启动 web 服务器：

```
docker run -p 8080:8080 -d k8s-for-beginners:v0.0.1
```

您应该看到以下响应：

```
9869e9b4ab1f3d5f7b2451a7086644c1cd7393ac9d78b6b4c1bef6d423fd25ac
```

如前述命令中所示，我们将容器的内部端口`8080`映射到主机的端口`8080`。由`-p`前置的`8080:8080`参数将容器的端口`8080`映射到主机上的端口`8080`。`-d`参数表示分离模式。默认情况下，Docker 首先检查本地注册表。因此，在这种情况下，将使用本地 Docker 镜像来启动容器。

1.  现在，让我们通过向`localhost`的端口`8080`发送 HTTP 请求来检查它是否按预期工作：

```
curl localhost:8080
```

`curl`命令检查来自指定地址的响应。您应该看到以下响应：

```
Hello Kubernetes Beginners!
```

1.  我们还可以使用以下命令观察运行容器的日志：

```
docker logs <container ID>
```

您应该看到以下日志：

```
2019/11/18  05:19:41 Ping from 172.17.0.1:41416
```

注意

在运行以下命令之前，您应该注册一个 Docker Hub 帐户，并准备好您的用户名和密码。

1.  最后，我们需要登录到 Docker Hub，然后将本地镜像推送到远程 Docker Hub 注册表。使用以下命令：

```
docker login
```

现在在提示时输入您的 Docker Hub 帐户的用户名和密码。您应该看到以下响应：

![图 1.14：登录到 Docker Hub](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/k8s-ws/img/B14870_01_14.jpg)

图 1.14：登录到 Docker Hub

1.  接下来，我们将把本地镜像`k8s-for-beginners:v0.0.1`推送到远程 Docker Hub 注册表。运行以下命令：

```
docker push k8s-for-beginners:v0.0.1
```

您应该看到以下响应：

![图 1.15：无法将镜像推送到 Docker Hub](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/k8s-ws/img/B14870_01_15.jpg)

图 1.15：无法将图像推送到 Docker Hub

但是，等等，为什么它说“`请求访问被拒绝`”?那是因为`docker push`后面的参数必须符合`<username/imagename:version>`的命名约定。在上一个练习中，我们指定了一个本地图像标签，`k8s-for-beginners:v0.0.1`，没有用户名。在`docker push`命令中，如果没有指定用户名，它将尝试将其推送到默认用户名`library`的存储库，该存储库还托管一些知名库，如 Ubuntu、nginx 等。

1.  要将我们的本地图像推送到我们自己的用户，我们需要通过运行`docker tag <imagename:version> <username/imagename:version>`来为本地图像提供符合规范的名称，如下命令所示：

```
docker tag k8s-for-beginners:v0.0.1 <your_DockerHub_username>/k8s-for-beginners:v0.0.1
```

1.  您可以使用以下命令验证图像是否已正确标记：

```
docker images
```

您应该看到以下输出：

![图 1.16：检查标记的 Docker 图像](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/k8s-ws/img/B14870_01_16.jpg)

图 1.16：检查标记的 Docker 图像

标记正确后，您可以看到新图像实际上与旧图像具有相同的`IMAGE ID`，这意味着它们是相同的图像。

1.  现在我们已经适当地标记了图像，我们准备通过运行以下命令将此图像推送到 Docker Hub：

```
docker push <your_username>/k8s-for-beginners:v0.0.1
```

您应该看到类似于此的响应：

![图 1.17：图像成功推送到 Docker Hub](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/k8s-ws/img/B14870_01_17.jpg)

图 1.17：图像成功推送到 Docker Hub

1.  图像将在 Docker Hub 上短时间后上线。您可以通过在以下链接中用您的用户名替换`<username>`来验证它：`https://hub.docker.com/repository/docker/<username>/k8s-for-beginners/tags`。

您应该能够看到有关您的图像的一些信息，类似于以下图像：

![图 1.18：我们图像的 Docker Hub 页面](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/k8s-ws/img/B14870_01_18.jpg)

图 1.18：我们图像的 Docker Hub 页面

现在我们的 Docker 图像对任何人都是公开可访问的，就像我们在本章开头使用的`nginx`图像一样。

在这一部分，我们学习了如何构建 Docker 镜像并将其推送到 Docker Hub。尽管看起来不起眼，但这是我们第一次拥有一个统一的机制来一致地管理应用程序及其依赖项，跨所有环境。Docker 镜像及其底层分层文件系统也是容器技术近年来被广泛采用的**主要原因**，与十年前相比。

在下一节中，我们将深入了解 Docker，看看它如何利用 Linux 容器技术。

# Linux 容器技术的本质

所有事物从外表看起来都优雅而简单。但是在底层是如何运作的，让一个容器如此强大？在这一部分，我们将尝试打开引擎盖，看看里面。让我们来看看一些为容器奠定基础的 Linux 技术。

## 命名空间

容器依赖的第一个关键技术称为 Linux 命名空间。当 Linux 系统启动时，它会创建一个默认命名空间（`root`命名空间）。然后，默认情况下，稍后创建的进程将加入相同的命名空间，因此它们可以无限制地相互交互。例如，两个进程能够查看同一文件夹中的文件，并通过`localhost`网络进行交互。这听起来很简单，但从技术上讲，这都归功于连接所有进程的`root`命名空间。

为了支持高级用例，Linux 提供了命名空间 API，以便将不同的进程分组到不同的命名空间中，这样只有属于同一命名空间的进程才能相互感知。换句话说，不同组的进程被隔离。这也解释了为什么我们之前提到 Docker 的隔离是进程级别的。以下是 Linux 内核支持的命名空间类型列表：

+   挂载命名空间

+   PID（进程 ID）命名空间

+   网络命名空间

+   IPC（进程间通信）命名空间

+   UTS（Unix 时间共享系统）命名空间

+   用户命名空间（自 Linux 内核 3.8 以来）

+   Cgroup 命名空间（自 Linux 内核 4.6 以来）

+   时间命名空间（将在未来版本的 Linux 内核中实现）

为了简洁起见，我们将选择两个简单的（UTS 和 PID）并使用具体示例来解释它们如何在 Docker 中体现。

注意

如果你正在运行 macOS，一些以下命令将需要以不同的方式使用，因为我们正在探索 Linux 的特性。Docker 在 macOS 上使用 HyperKit 在 Linux VM 中运行。因此，你需要打开另一个终端会话并登录到 VM 中：

`screen ~/Library/Containers/com.docker.docker/Data/vms/0/tty`

运行此命令后，你可能会看到一个空屏幕。按 *Enter*，你应该获得运行 Docker 的 VM 的 root 访问权限。要退出会话，你可以按 *Ctrl* *+* *A* *+* *K*，然后在要求确认关闭窗口时按 *Y*。 

我们建议您使用另一个终端窗口访问 Linux VM。如果你使用 macOS，我们将提到需要在此终端会话中运行哪些命令。如果你使用任何 Linux 操作系统，你可以忽略这一点，并在同一个终端会话中运行所有命令，除非在说明中另有说明。

创建 Docker 容器后，Docker 会创建并关联一些命名空间到容器。例如，让我们看看在上一节中创建的示例容器。让我们使用以下命令：

```
docker inspect --format '{{.State.Pid}}' <container ID>
```

上述命令检查在主机操作系统上运行的容器的 PID。你应该看到类似以下的响应：

```
5897
```

在这个例子中，PID 是 `5897`，正如你在前面的响应中所看到的。现在，在 Linux VM 中运行以下命令：

```
ps -ef | grep k8s-for-beginners
```

这应该产生类似于以下内容的输出：

![图 1.19：检查我们进程的 PID](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/k8s-ws/img/B14870_01_19.jpg)

图 1.19：检查我们进程的 PID

`ps -ef` 命令列出主机操作系统上所有正在运行的进程，然后 `| grep k8s-for-beginners` 过滤此列表，以显示名称中包含 `k8s-for-beginners` 的进程。我们可以看到该进程还具有 PID `5897`，这与第一个命令一致。这揭示了一个重要的事实，即容器只是直接在主机操作系统上运行的特定进程。

接下来，运行此命令：

```
ls -l /proc/<PID>/ns
```

对于 macOS，在 VM 终端中运行此命令。你应该看到以下输出：

![图 1.20：列出为我们的容器创建的不同命名空间](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/k8s-ws/img/B14870_01_20.jpg)

图 1.20：列出为我们的容器创建的不同命名空间

此命令检查`/proc`文件夹（这是一个 Linux 伪文件系统），列出了随着容器启动创建的所有命名空间。结果显示了一些众所周知的命名空间（看一下突出显示的矩形），如`uts`、`pid`、`net`等。让我们仔细看看它们。

`uts`命名空间被创建，以使容器具有其主机名，而不是主机的主机名。默认情况下，容器被分配其容器 ID 作为主机名，并且可以在运行容器时使用`-h`参数进行更改，如下所示：

```
docker run -h k8s-for-beginners -d packtworkshops/the-kubernetes-workshop:k8s-for-beginners
```

这应该给出以下响应：

```
df6a15a8e2481ec3e46dedf7850cb1fbef6efafcacc3c8a048752da24ad793dc
```

使用返回的容器 ID，我们可以进入容器并使用以下两个命令依次检查其主机名：

```
docker exec -it <container ID> sh
hostname
```

您应该看到以下响应：

```
k8s-for-beginners
```

`docker exec`命令尝试进入容器并执行`sh`命令，在容器内启动 shell。一旦我们进入容器，我们运行`hostname`命令来检查容器内的主机名。从输出中，我们可以看出`-h`参数正在生效，因为我们可以看到`k8s-for-beginners`作为主机名。

除了`uts`命名空间，容器还在其自己的`PID`命名空间中进行隔离，因此它只能查看由自己启动的进程，而启动进程（由我们在*练习 1.01*中创建的`Dockerfile`中的`CMD`或`ENTRYPOINT`指定）被分配为`PID` `1`。让我们通过依次输入以下两个命令来看一下这个：

```
docker exec -it <container ID> sh
ps
```

您应该看到以下响应：

![图 1.21：容器内的进程列表](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/k8s-ws/img/B14870_01_21.jpg)

图 1.21：容器内的进程列表

Docker 为容器提供了`--pid`选项，以加入另一个容器的 PID 命名空间。

除了`uts`和`pid`命名空间，Docker 还利用了一些其他命名空间。我们将在下一个练习中检查网络命名空间（*图 1.20*中的"`net`"）。

## 练习 1.03：将一个容器加入另一个容器的网络命名空间

在这个练习中，我们将重新创建`k8s-for-beginners`容器，而不进行主机映射，然后创建另一个容器加入其网络命名空间：

1.  与之前的练习一样，通过运行以下命令删除所有现有容器：

```
docker rm -f $(docker ps -aq)
```

您应该看到类似于这样的输出：

```
43c01e2055cf
286bc0c92b3a
39bf70d02dcc
96c374000f6f
```

1.  现在，开始使用以下命令运行我们的容器：

```
docker run -d packtworkshops/the-kubernetes-workshop:k8s-for-beginners
```

您应该会看到以下响应：

```
33003ddffdf4d85c5f77f2cae2528cb2035d37f0a7b7b46947206ca104bbbaa5
```

1.  接下来，我们将获取正在运行的容器列表，以便查看容器的 ID：

```
docker ps
```

您应该会看到以下响应：

![图 1.22：获取所有正在运行的容器列表](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/k8s-ws/img/B14870_01_22.jpg)

图 1.22：获取所有正在运行的容器列表

1.  现在，我们将在与我们在*步骤 1*中创建的容器相同的网络命名空间中运行一个名为`netshoot`的镜像，使用`--net`参数：

```
docker run -it --net container:<container ID> nicolaka/netshoot
```

使用我们在上一步中获得的先前容器的容器 ID。您应该会看到类似于以下响应：

![图 1.23：启动 netshoot 容器](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/k8s-ws/img/B14870_01_23.jpg)

图 1.23：启动 netshoot 容器

`nicolaka/netshoot`是一个打包了一些常用网络库（如`iproute2`、`curl`等）的微型镜像。

1.  现在，让我们在`netshoot`内部运行`curl`命令，以检查我们是否能够访问`k8s-for-beginners`容器：

```
curl localhost:8080
```

您应该会看到以下响应：

```
Hello Kubernetes Beginners!
```

前面的示例证明了`netshoot`容器是通过加入`k8s-for-beginners`的网络命名空间而创建的；否则，在`localhost`上访问端口`8080`就不会得到响应。

1.  这也可以通过在接下来的步骤中验证两个容器的网络命名空间 ID 来进行验证。

为了确认我们的结果，让我们首先在不退出`netshoot`容器的情况下打开另一个终端。获取容器列表以确保两个容器都在运行：

```
docker ps
```

您应该会看到以下响应：

![图 1.24：检查 k8s-for-beginners 和 netshoot 是否都在线容器都在线](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/k8s-ws/img/B14870_01_24.jpg)

图 1.24：检查 k8s-for-beginners 和 netshoot 容器是否都在线

1.  接下来，获取`k8s-for-beginners`容器的 PID：

```
docker inspect --format '{{.State.Pid}}' <container ID>
```

您应该会看到以下响应：

```
7311
```

如您所见，此示例的 PID 为`7311`。

1.  现在使用前面的 PID 获取进程的伪文件系统：

```
ls -l /proc/<PID>/ns/net
```

如果您使用的是 macOS，请在另一个终端会话中在 Linux VM 上运行此命令。在此命令中使用您在上一步中获得的 PID。您应该会看到以下响应：

```
lrwxrwxrwx 1 root root 0 Nov 19 08:11 /proc/7311/ns/net -> 'net:[4026532247]'
```

1.  同样地，使用以下命令获取`netshoot`容器的 PID：

```
docker inspect --format '{{.State.Pid}}' <container ID>
```

在此命令中使用*步骤 6*中的适当容器 ID。您应该会看到以下响应：

```
8143
```

如您所见，`netshoot` 容器的 PID 是 `8143`。

1.  接下来，我们可以通过其 PID 或使用此命令获取其伪文件系统：

```
ls -l /proc/<PID>/ns/net
```

如果您使用 macOS，在另一个会话中在 Linux VM 上运行此命令。在此命令中使用上一步中的 PID。您应该会看到以下响应：

```
lrwxrwxrwx 1 root root 0 Nov 19 09:15 /proc/8143/ns/net -> 'net:[4026532247]'
```

正如您从 *步骤 8* 和 *步骤 10* 的输出中所观察到的，这两个容器共享相同的网络命名空间（`4026532247`）。

1.  作为最后的清理步骤，让我们删除所有的容器：

```
docker rm -f $(docker ps -aq)
```

您应该会看到类似以下的响应：

```
61d0fa62bc49
33003ddffdf4
```

1.  如果您想要将容器加入到主机的根命名空间中怎么办？嗯，`--net host` 是实现这一目标的好方法。为了演示这一点，我们将使用相同的镜像启动一个容器，但使用 `--net host` 参数：

```
docker run --net host -d packtworkshops/the-kubernetes-workshop:k8s-for-beginners
```

您应该会看到以下响应：

```
8bf56ca0c3dc69f09487be759f051574f291c77717b0f8bb5e1760c8e20aebd0
```

1.  现在，列出所有正在运行的容器：

```
docker ps
```

您应该会看到以下响应：

![图 1.25：列出所有容器](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/k8s-ws/img/B14870_01_25.jpg)

图 1.25：列出所有容器

1.  使用以下命令获取正在运行的容器的 PID：

```
docker inspect --format '{{.State.Pid}}' <container ID>
```

在此命令中使用适当的容器 ID。您应该会看到以下响应：

```
8380
```

1.  通过查找 PID 查找网络命名空间 ID：

```
ls -l /proc/<PID>/ns/net
```

如果您使用 macOS，在 Linux VM 上运行此命令。在此命令中使用适当的 PID。您应该会看到以下响应：

```
lrwxrwxrwx 1 root root 0 Nov 19 09:20 /proc/8380/ns/net -> 'net:[4026531993]'
```

您可能会对 `4026531993` 命名空间感到困惑。通过给出 `--net host` 参数，Docker 不应该绕过创建新的命名空间吗？答案是这不是一个新的命名空间；事实上，它就是前面提到的 Linux 根命名空间。我们将在下一步中确认这一点。

1.  获取主机操作系统的 PID `1` 的命名空间：

```
ls -l /proc/1/ns/net
```

如果您使用 macOS，在 Linux VM 上运行此命令。您应该会看到以下响应：

```
lrwxrwxrwx 1 root root 0 Nov 19 09:20 /proc/1/ns/net -> 'net:[4026531993]'
```

正如您在此输出中所看到的，主机的这个命名空间与我们在 *步骤 15* 中看到的容器的命名空间是相同的。

通过这个练习，我们可以对容器如何被隔离到不同的命名空间以及哪些 Docker 参数可以用来与其他命名空间相关联有所了解。

## Cgroups

默认情况下，无论容器加入哪个命名空间，它都可以使用主机的所有可用资源。这当然不是我们在系统上运行多个容器时想要的情况；否则，一些容器可能会独占所有容器共享的资源。

为了解决这个问题，Linux 内核版本 2.6.24 以后引入了 **cgroups**（**Control Groups** 的缩写）功能，用于限制进程的资源使用。使用这个功能，系统管理员可以控制最重要的资源，如内存、CPU、磁盘空间和网络带宽。

在 Ubuntu 18.04 LTS 中，默认情况下会在路径 `/sys/fs/cgroup/<cgroup type>` 下创建一系列 cgroups。

注意

您可以运行 `mount -t cgroup` 来查看 Ubuntu 中的所有 cgroups；尽管如此，我们不会在本书的范围内涉及它们，因为它们对我们来说并不是很相关。

现在，我们并不太关心系统进程及其 cgroups；我们只想关注 Docker 在整个 cgroups 图中的关系。Docker 在路径 `/sys/fs/cgroup/<resource kind>/docker` 下有其 cgroups 文件夹。使用 `find` 命令来检索列表：

```
find /sys/fs/cgroup/* -name docker -type d
```

如果您使用的是 macOS，在 Linux VM 的另一个会话中运行此命令。您应该会看到以下结果：

![图 1.26：获取与 Docker 相关的所有 cgroups](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/k8s-ws/img/B14870_01_26.jpg)

图 1.26：获取与 Docker 相关的所有 cgroups

每个文件夹都被视为一个控制组，这些文件夹是分层的，这意味着每个 cgroup 都有一个从其继承属性的父级，一直到在系统启动时创建的根 cgroup。

为了说明 cgroup 在 Docker 中的工作原理，我们将使用 *图 1.26* 中突出显示的 `memory` cgroup 作为示例。

但首先，让我们使用以下命令删除所有现有的容器：

```
docker rm -f $(docker ps -aq)
```

您应该会看到类似以下的响应：

```
61d0fa62bc49
```

让我们通过以下命令来确认：

```
docker ps
```

您应该会看到一个空列表，如下所示：

```
CONTAINER ID     IMAGE       COMMAND          CREATED          STATUS
        PORTS          NAMES
```

让我们看看是否有 `cgroup` 内存文件夹：

```
find /sys/fs/cgroup/memory/docker/* -type d
```

如果您使用的是 macOS，在 Linux VM 上运行此命令。然后您应该会看到以下响应：

```
root@ubuntu: ~# find /sys/fs/cgroup/memory/docker/* -type d
```

没有文件夹显示出来。现在，让我们运行一个容器：

```
docker run -d packtworkshops/the-kubernetes-workshop:k8s-for-beginners 
```

您应该会看到类似以下的输出：

```
8fe77332244b2ebecbda27a4496268264218c4e59614d59b5849a22b12941e1
```

再次检查 `cgroup` 文件夹：

```
find /sys/fs/cgroup/memory/docker/* -type d
```

如果您使用的是 macOS，在 Linux VM 上运行此命令。您应该会看到以下响应：

```
/sys/fs/cgroup/memory/docker/8fe77332244b2ebecbda27a4496268264218c4e59614d59b5849a22b12941e1
```

到目前为止，您可以看到一旦我们创建一个容器，Docker 就会在特定资源类型（在我们的示例中是内存）下创建其 cgroup 文件夹。现在，让我们看看在这个文件夹中创建了哪些文件：

```
ls /sys/fs/cgroup/memory/docker/8fe77332244b2ebecbd8a2704496268264218c4e59614d59b5849022b12941e1
```

如果您使用的是 macOS，在 Linux VM 上运行此命令。请使用您从上一张截图中获得的适当路径。您应该会看到以下文件列表：

![图 1.27：探索 Docker 创建的内存 cgroups](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/k8s-ws/img/B14870_01_27.jpg)

图 1.27：探索 Docker 创建的内存 cgroups

我们不会在这里介绍每个设置。 我们感兴趣的设置是`memory.limit_in_bytes`，如前所述，它表示容器可以使用多少内存。 让我们看看这个文件中写了什么值：

```
cat /sys/fs/cgroup/memory/docker/8fe77332244b2ebecbd8a2704496268264218c4e59614d59b5849022b12941e1/memory.limit_in_bytes
```

如果您使用的是 macOS，请在 Linux VM 上运行此命令。 您应该看到以下响应：

```
9223372036854771712
```

值`9223372036854771712`是 64 位系统中最大的正有符号整数（263-1），这意味着此容器可以使用无限的内存。

为了了解 Docker 如何处理过度使用声明内存的容器，我们将向您展示另一个程序，该程序消耗一定量的 RAM。 以下是一个用于逐步消耗 50 MB RAM 然后保持整个程序（休眠 1 小时）以防止退出的 Golang 程序：

```
package main
import (
        "fmt"
        "strings"
        "time"
)
func main() {
        var longStrs []string
        times := 50
        for i := 1; i <= times; i++ {
                fmt.Printf("===============%d===============\n", i)
                // each time we build a long string to consume 1MB                     (1000000 * 1byte) RAM
                longStrs = append(longStrs, buildString(1000000,                     byte(i)))
        }
        // hold the application to exit in 1 hour
        time.Sleep(3600 * time.Second)
}
// buildString build a long string with a length of `n`.
func buildString(n int, b byte) string {
        var builder strings.Builder
        builder.Grow(n)
        for i := 0; i < n; i++ {
                builder.WriteByte(b)
        }
        return builder.String()
}
```

您可以尝试使用此代码构建一个镜像，如*练习 1.01*中所示，*创建 Docker 镜像并将其上传到 Docker Hub*。 此代码将用于替换该练习中*步骤 2*中提供的代码，然后您可以使用`<username>/memconsumer`为镜像打标签。 现在，我们可以测试资源限制。 让我们使用 Docker 镜像并使用`--memory`（或`-m`）标志运行它，以指示 Docker 我们只想使用一定量的 RAM。

如果您使用的是 Ubuntu 或任何其他基于 Debian 的 Linux，在继续本章之前，如果在运行此命令时看到以下警告消息，则可能需要手动启用 cgroup 内存和交换功能：

```
docker info > /dev/null
```

这是您可能会看到的警告消息：

```
WARNING: No swap limit support
```

启用 cgroup 内存和交换功能的步骤如下：

注意

如果您使用的是 macOS，则以下三个步骤不适用。

1.  编辑`/etc/default/grub`文件（可能需要 root 权限）。 添加或编辑`GRUB_CMDLINE_LINUX`行以添加以下两个键值对：

```
GRUB_CMDLINE_LINUX="cgroup_enable=memory swapaccount=1"
```

1.  使用 root 权限运行`update-grub`。

1.  重新启动机器。

接下来，我们应该能够通过运行以下命令来限制容器的内存使用量为 100 MB：

```
docker run --name memconsumer -d --memory=100m --memory-swap=100m packtworkshops/the-kubernetes-workshop:memconsumer
```

注意

此命令拉取了我们为此演示提供的镜像。 如果您已构建了自己的镜像，可以在前面的命令中使用`<your_username>/<tag_name>`。

您应该看到以下响应：

```
WARNING: Your kernel does not support swap limit capabilities or the cgroup is not mounted. Memory limited without swap.
366bd13714cadb099c7ef6056e3b72853735473938b2e633a5cdbf9e94273143
```

这个命令禁用了交换内存的使用（因为我们在`--memory`和`--memory-swap`上指定了相同的值），以便轻松地衡量内存的消耗。

让我们检查一下我们的容器的状态：

```
docker ps
```

你应该看到以下响应：

![图 1.28：获取容器列表](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/k8s-ws/img/B14870_01_28.jpg)

图 1.28：获取容器列表

现在，让我们通过读取容器的`cgroup`文件来确认对容器施加的限制：

```
cat /sys/fs/cgroup/memory/docker/366bd13714cadb099c7ef6056e3b7285373547e9e8b2e633a5cdbf9e94273143/memory.limit_in_bytes
```

如果您使用的是 macOS，请在 Linux VM 上运行此命令。请在此命令中使用适当的路径。你应该看到以下响应：

```
104857600
```

容器启动时请求了 100 MB 的 RAM，并且它在内部只消耗了 50 MB 的 RAM，因此可以正常运行。从 cgroup 设置中，您可以观察到该值已更新为`104857600`，这正好是 100 MB。

但是，如果容器请求少于 50 MB，而其中运行的程序需要超过 50 MB 呢？Docker 和 Linux 会如何响应？让我们来看看。

首先，让我们删除任何正在运行的容器：

```
docker rm -f $(docker ps -aq)
```

你应该看到以下响应：

```
366bd13714ca
```

接下来，我们将再次运行容器，但是我们只会请求 20 MB 的内存：

```
docker run --name memconsumer -d --memory=20m --memory-swap=20m packtworkshops/the-kubernetes-workshop:memconsumer
```

你应该看到这个响应：

```
298541bc46855a749f9f8944860a73f3f4f2799ebda7969a5eada60e3809539bab
```

现在，让我们检查一下我们的容器的状态：

```
docker ps
```

你应该看到一个空列表，就像这样：

```
CONTAINER ID     IMAGE       COMMAND      CREATED        STATUS
       PORTS          NAMES
```

如您所见，我们无法看到我们的容器。让我们列出所有类型的容器：

```
docker ps -a
```

你应该看到以下输出：

![图 1.29：获取所有容器的列表](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/k8s-ws/img/B14870_01_29.jpg)

图 1.29：获取所有容器的列表

我们找到了我们的容器。它已被强制终止。可以通过检查容器日志来验证：

```
docker logs memconsumer
```

你应该看到以下输出：

![图 1.30：我们终止的容器的日志](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/k8s-ws/img/B14870_01_30.jpg)

图 1.30：我们终止的容器的日志

容器试图每次增加 1 MB 的内存消耗，当它达到内存限制（20 MB）时，它被杀死。

从前面的例子中，我们已经看到 Docker 如何向最终用户公开标志，以及这些标志如何与底层的 Linux cgroups 交互以限制资源使用。

## 容器化：思维方式的改变

在前面的章节中，我们看了 Linux 命名空间和 cgroups 的解剖。我们解释了容器本质上是在主机操作系统上本地运行的进程。它是一个特殊的进程，具有额外的限制，如与其他进程的操作系统级隔离和资源配额的控制。

自 Docker 1.11 以来，containerd 已被采用为默认的容器运行时，而不是直接使用 Docker Daemon（`dockerd`）来管理容器。让我们来看看这个运行时。首先，正常重启我们的容器：

```
docker run -d packtworkshops/the-kubernetes-workshop:k8s-for-beginners
```

您应该看到以下响应：

```
c7ee681ff8f73fa58cf0b37bc5ce08306913f27c5733c725f7fe97717025625d
```

我们可以使用`ps -aef --forest`来列出层次结构中所有运行的进程，然后使用`| grep containerd`来通过`containerd`关键字过滤输出。最后，我们可以使用`-A 1`来输出一行额外的内容（使用`-A 1`），以便至少有一个运行的容器显示出来：

```
ps -aef --forest | grep containerd -A 1
```

如果您正在使用 macOS，请在没有`--forest`标志的 Linux VM 上运行此命令。您应该看到以下响应：

![图 1.31：获取与 containerd 相关的进程](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/k8s-ws/img/B14870_01_31.jpg)

图 1.31：获取与 containerd 相关的进程

在输出中，我们可以看到`containerd`（PID `1037`）充当顶级父进程，并管理`containerd-shim`（PID `19374`），而`containerd-shim`管理`k8s-for-beginners`（PID `19394`）的大多数子进程，这是我们启动的容器。

牢记容器的核心思想可以帮助您将任何基于 VM 的应用程序迁移到基于容器的应用程序。基本上，有两种模式可以部署容器中的应用程序：

### 一个容器中的多个应用程序

这种实现需要一个监督者应用程序来启动和持有容器。然后，我们可以将应用程序放入容器作为监督者的子进程。监督者有几个变体：

+   自定义包装脚本：这需要复杂的脚本来控制受管应用程序的故障。

+   第三方工具，如 supervisord 或 systemd：在应用程序失败时，监督者负责重新启动它。

### 一个容器中的一个应用程序

这种实现不需要像之前那样的监督者。事实上，应用程序的生命周期与容器的生命周期相关联。

### 这些方法的比较

通过在单个容器中部署多个应用程序，我们实质上是将容器视为 VM。这种*容器作为轻量级 VM*的方法曾经被用作容器技术的宣传口号。然而，正如所解释的，它们在许多方面都有所不同。当然，这种方式可以节省从基于 VM 的开发/部署模型迁移到容器的工作，但它也在以下方面引入了一些缺点：

+   应用程序生命周期控制：从外部看，容器暴露为一个状态，因为它本质上是一个单一的主机进程。内部应用程序的生命周期由“监督者”管理，因此无法从外部观察。因此，从外部看，您可能会观察到容器保持健康，但其中一些应用程序可能会持续重启。它可能会因为内部应用程序的致命错误而持续重启，而您可能无法指出这一点。

+   版本升级：如果您想升级容器中的任何一个不同的应用程序，您可能需要拉下整个容器。这会导致容器中其他不需要版本升级的应用程序不必要的停机时间。因此，如果应用程序需要由不同团队开发的组件，它们的发布周期必须紧密耦合。

+   水平扩展：如果只有一个应用程序需要扩展，您别无选择，只能扩展整个容器，这也会复制所有其他应用程序。这会导致不需要扩展的应用程序浪费资源。

+   运行时的考虑：检查应用程序的日志变得更具挑战性，因为容器的标准输出（`stdout`）和错误（`stderr`）不代表容器内应用程序的日志。您必须额外努力来管理这些日志，比如安装额外的监控工具来诊断每个应用程序的健康状况。

从技术上讲，在单个容器中运行多个应用程序是可行的，并且不需要从虚拟机的角度进行太多思维转变。然而，当我们采用容器技术来享受其好处时，我们需要在迁移便利性和长期可维护性之间进行权衡。

第二种方式（即一个容器中只有一个应用程序）使容器能够自动管理其内部唯一应用程序的生命周期。通过利用原生的 Linux 功能，例如通过检查容器状态获取应用程序状态，并从容器的`stdout/stderr`获取应用程序日志，我们可以统一容器管理。这使您能够管理每个应用程序的发布周期。

然而，这并不是一件容易的事情。这需要你重新思考不同组件之间的关系和依赖，以将单片应用程序拆分为微服务。这可能需要对架构设计进行一定程度的重构，包括源代码和交付流程的改变。

总之，采用容器技术是一次分离和重组的旅程。这不仅需要技术成熟的时间，更重要的是，它需要改变人们的思维方式。只有通过这种思维方式的改变，你才能重构应用程序以及底层基础设施，释放容器的价值并享受它们的真正好处。正是这个**第二个原因**，容器技术才在最近几年开始崛起，而不是十年前。

# 容器编排的需求

我们在*练习 1.01*中构建的`k8s-for-beginners`容器只是一个简单的演示。在生产环境中部署严重工作负载，并在集群中运行数十万个容器时，我们需要考虑更多的事情。我们需要一个系统来解决以下问题：

## 容器交互

举个例子，假设我们要构建一个 Web 应用程序，其中前端容器显示信息并接受用户请求，后端容器作为与前端容器交互的数据存储。第一个挑战是如何指定后端容器的地址给前端容器。硬编码 IP 并不是一个好主意，因为容器 IP 不是静态的。在分布式系统中，由于意外问题，容器或机器可能会失败。因此，任何两个容器之间的链接必须是可发现的，并且在所有机器上都是有效的。另一方面，第二个挑战是我们可能希望限制哪些容器（例如后端容器）可以被哪种类型的容器（例如其对应的前端容器）访问。

## 网络和存储

在前面的部分中，我们给出的所有示例都是在同一台机器上运行的容器。这相当简单，因为底层的 Linux 命名空间和 cgroup 技术是设计为在同一操作系统实体内工作的。如果我们想在生产环境中运行数千个容器，这是非常常见的，我们必须解决网络连接问题，以确保不同机器上的不同容器能够相互连接。另一方面，本地或临时的磁盘存储并不总是适用于所有工作负载。应用程序可能需要将数据存储在远程位置，并且可以随时挂载到集群中任何一台机器上，无论容器是第一次启动还是在故障后重新启动。

## 资源管理和调度

我们已经看到，容器利用 Linux cgroups 来管理其资源使用情况。要成为现代资源管理器，它需要构建一个易于使用的资源模型，以抽象资源，如 CPU、RAM、磁盘和 GPU。我们需要有效地管理多个容器，并及时分配和释放资源，以实现高集群利用率。

调度涉及为集群中的每个工作负载分配适当的机器来运行。随着我们在本书中继续深入研究，我们将更仔细地研究调度。为了确保每个容器都有最佳的机器来运行，调度器（负责调度的 Kubernetes 组件）需要全局查看集群中不同机器上所有容器的分布情况。此外，在大型数据中心中，容器需要根据机器的物理位置或云服务的可用区进行分布。例如，如果支持某项服务的所有容器都分配给同一台物理机，而该机器发生故障，无论您部署了多少个容器的副本，该服务都将经历一段宕机期。

## 故障转移和恢复

在分布式系统中，应用程序或机器错误是相当常见的。因此，我们必须考虑容器和机器故障。当容器遇到致命错误并退出时，它们应该能够在同一台或另一台可用的机器上重新启动。我们应该能够检测机器故障或网络分区，以便将容器从有问题的机器重新调度到健康的机器上。此外，协调过程应该是自主的，以确保应用程序始终以其期望的状态运行。

## 可扩展性

随着需求的增加，您可能希望扩展应用程序。以 Web 前端应用程序为例。我们可能需要运行多个副本，并使用负载均衡器将传入的流量均匀分配到支持服务的容器的多个副本中。更进一步，根据传入请求的数量，您可能希望应用程序动态扩展，无论是水平扩展（增加或减少副本）还是垂直扩展（分配更多或更少的资源）。这使得系统设计的难度提升到了另一个层次。

## 服务暴露

假设我们已经解决了之前提到的所有挑战；也就是说，在集群内一切都运行良好。好吧，又来了另一个挑战：应用程序如何可以被外部访问？一方面，外部端点需要与基础的本地或云环境相关联，以便利用基础设施的 API 使其始终可访问。另一方面，为了保持内部网络流量始终通过，外部端点需要动态关联内部备份副本 - 任何不健康的副本都需要被自动取出并自动填充，以确保应用程序保持在线。此外，L4（TCP/UDP）和 L7（HTTP，HTTPS）流量在数据包方面具有不同的特征，因此需要以稍微不同的方式处理以确保效率。例如，HTTP 头信息可以用于重用相同的公共 IP 来为多个后端应用程序提供服务。

## 交付管道

从系统管理员的角度来看，一个健康的集群必须是可监控的、可操作的，并且能够自主应对故障。这要求部署在集群上的应用程序遵循标准化和可配置的交付流程，以便在不同阶段和不同环境中进行良好的管理。

一个单独的容器通常只用于完成单一功能，这是不够的。我们需要提供几个构建块来将所有容器连接在一起，以完成复杂的任务。

## 编排器：将所有事物整合在一起

我们并不是要压倒你，但上述问题非常严重，这是由于需要自动管理大量容器而产生的。与虚拟机时代相比，容器在大型分布式集群中为应用程序管理打开了另一扇门。然而，这也将容器和集群管理的挑战提升到了另一个层面。为了将容器连接在一起，以以可扩展、高性能和自我恢复的方式实现所需的功能，我们需要一个设计良好的容器编排器。否则，我们将无法将我们的应用程序从虚拟机迁移到容器中。这是**第三个原因**，为什么近年来容器化技术开始大规模采用，特别是在 Kubernetes 出现后 - 它现在是事实上的容器编排器。

# 欢迎来到 Kubernetes 世界

与通常逐步发展的典型软件不同，Kubernetes 是一个快速启动的项目，因为它是基于谷歌内部大规模集群管理软件（如 Borg 和 Omega）多年经验的设计而来。也就是说，Kubernetes 诞生时就装备了容器编排和管理领域的许多最佳实践。从一开始，团队就理解了真正的痛点，并提出了适当的设计来解决这些问题。像 Pod、每个 Pod 一个 IP、声明式 API 和控制器模式等概念，都是 Kubernetes 首次引入的，似乎有点“不切实际”，当时可能有人质疑它们的真正价值。然而，5 年后，这些设计原理仍然保持不变，并已被证明是与其他软件的关键区别。

Kubernetes 解决了前一节提到的所有挑战。Kubernetes 提供的一些众所周知的功能包括：

+   **本地支持应用程序生命周期管理**

这包括对应用程序复制、自动缩放、部署和回滚的内置支持。您可以描述应用程序的期望状态（例如，多少个副本，哪个镜像版本等），Kubernetes 将自动协调实际状态以满足其期望状态。此外，在部署和回滚方面，Kubernetes 确保旧副本逐渐被新副本替换，以避免应用程序的停机时间。

+   **内置健康检查支持**

通过实现一些“健康检查”钩子，您可以定义容器何时被视为就绪、存活或失败。只有当容器健康且就绪时，Kubernetes 才会开始将流量引导到容器，并且会自动重新启动不健康的容器。

+   **服务发现和负载均衡**

Kubernetes 在工作负载的不同副本之间提供内部负载均衡。由于容器偶尔会失败，Kubernetes 不使用 IP 进行直接访问。相反，它使用内部 DNS，并为集群内的通信为每个服务公开一个 DNS 记录。

+   **配置管理**

Kubernetes 使用标签来描述机器和工作负载。它们受 Kubernetes 组件的尊重，以松散耦合和灵活的方式管理容器和依赖关系。此外，简单但强大的标签可以用于实现高级调度功能（例如，污点/容忍和亲和性/反亲和性）。

在安全方面，Kubernetes 提供了 Secret API，允许您存储和管理敏感信息。这可以帮助应用程序开发人员安全地将凭据与应用程序关联起来。从系统管理员的角度来看，Kubernetes 还提供了各种选项来管理身份验证和授权。

此外，一些选项，如 ConfigMaps，旨在提供精细的机制来构建灵活的应用交付流水线。

+   **网络和存储抽象**

Kubernetes 启动了抽象网络和存储规范的标准，即 CNI（容器网络接口）和 CSI（容器存储接口）。每个网络和存储提供商都遵循接口并提供其实现。这种机制解耦了 Kubernetes 和异构提供商之间的接口。有了这个，最终用户可以使用标准的 Kubernetes API 以可移植的方式编排其工作负载。

在引擎盖下，有一些支持前面提到的功能的关键概念，更为关键的是，Kubernetes 为最终用户提供了不同的扩展机制，以构建定制的集群甚至他们自己的平台：

+   **声明式 API**

声明式 API 是描述您想要完成的方式。在这个约定下，我们只需指定期望的最终状态，而不是描述到达那里的步骤。

声明式模型在 Kubernetes 中被广泛使用。它不仅使 Kubernetes 的核心功能能够以容错的方式运行，而且还作为构建 Kubernetes 扩展解决方案的黄金法则。

+   **简洁的 Kubernetes 核心**

软件项目随着时间的推移往往会变得越来越庞大，尤其是像 Kubernetes 这样著名的开源软件。越来越多的公司参与了 Kubernetes 的开发。但幸运的是，自从第一天起，Kubernetes 的先驱者们就设定了一些基线，以保持 Kubernetes 的核心简洁整洁。例如，Kubernetes 并没有绑定到特定的容器运行时（例如 Docker 或 Containerd），而是定义了一个接口（**CRI**或**容器运行时接口**）以保持技术的中立性，使用户可以选择使用哪种运行时。此外，通过定义**CNI**（**容器网络接口**），它将 pod 和主机的网络路由实现委托给不同的项目，如 Calico 和 Weave Net。这样，Kubernetes 能够保持其核心的可管理性，并鼓励更多的供应商加入，以便最终用户可以有更多的选择，避免供应商锁定。

+   **可配置、可插拔和可扩展的设计**

所有 Kubernetes 组件都提供配置文件和标志，供用户自定义功能。每个核心组件都严格实现以符合公共 Kubernetes API；对于高级用户，您可以选择自己实现部分或整个组件，以满足特殊需求，只要它符合 API。此外，Kubernetes 提供了一系列扩展点来扩展 Kubernetes 的功能，以及构建您的平台。

在本书的过程中，我们将带您了解高级别的 Kubernetes 架构、其核心概念、最佳实践和示例，以帮助您掌握 Kubernetes 的基本知识，这样您就可以在 Kubernetes 上构建您的应用程序，并扩展 Kubernetes 以满足复杂的需求。

## 活动 1.01：创建一个简单的页面计数应用程序

在这个活动中，我们将创建一个简单的网络应用程序，用于统计访问者的数量。我们将把这个应用程序放入容器中，将其推送到 Docker 镜像注册表，然后运行容器化的应用程序。

**页面浏览网络应用**

我们将首先构建一个简单的网络应用程序，用于显示特定网页的页面浏览量：

1.  使用您喜欢的编程语言编写一个 HTTP 服务器，监听端口`8080`，在根路径(`/`)。一旦收到请求，它会将`1`添加到其内部变量，并以消息`Hello, you're visitor #i`做出响应，其中`i`是累积数字。您应该能够在本地开发环境中运行此应用程序。

注意

如果您需要代码帮助，我们提供了一个用 Go 编写的示例代码片段，也用于解决这个活动的问题。您可以从以下链接获取：[`packt.live/2DcCQUH`](https://packt.live/2DcCQUH)。

1.  编写一个`Dockerfile`来构建 HTTP 服务器，并将其与其依赖项打包到 Docker 镜像中。在最后一行设置启动命令以运行 HTTP 服务器。

1.  构建`Dockerfile`并将镜像推送到公共 Docker 镜像注册表（例如，[`hub.docker.com/`](https://hub.docker.com/)）。

1.  通过启动 Docker 容器来测试您的 Docker 镜像。您应该使用 Docker 端口映射或内部容器 IP 来访问 HTTP 服务器。

您可以通过重复使用`curl`命令来访问它，以测试您的应用程序是否正常工作。

```
root@ubuntu:~# curl localhost: 8080
Hello, you're visitor #1.
root@ubuntu:~# curl localhost: 8080
Hello, you're visitor #2.
root@ubuntu:~# curl localhost: 8080
Hello, you're visitor #3.
```

**奖励目标**

到目前为止，我们已经实现了本章学到的 Docker 的基础知识。然而，我们可以通过扩展这个活动来演示连接不同容器的需求。

对于一个应用程序，通常我们需要多个容器来专注于不同的功能，然后将它们连接在一起作为一个完全功能的应用程序。在本书的后面，您将学习如何使用 Kubernetes 来做到这一点；然而，现在让我们直接连接容器。

我们可以通过附加后端数据存储来增强此应用程序。这将使其能够在容器终止后保持其状态，即保留访问者数量。如果容器重新启动，它将继续计数，而不是重置计数。以下是构建到目前为止构建的应用程序的一些建议。

一个后端数据存储

当容器终止时，我们可能会丢失页面浏览次数，因此我们需要将其持久化到后端数据存储中：

1.  在容器中运行三种知名的数据存储之一：Redis、MySQL 或 MongoDB。

注意

此活动的解决方案可以在以下地址找到：[`packt.live/304PEoD`](https://packt.live/304PEoD)。我们已经为我们的数据存储实现了 Redis。

您可以在此链接找到有关 Redis 容器用法的更多详细信息：[`hub.docker.com/_/redis`](https://hub.docker.com/_/redis)。

如果您希望使用 MySQL，您可以在此链接找到有关其用法的详细信息：[`hub.docker.com/_/mysql`](https://hub.docker.com/_/mysql)。

如果您希望使用 MongoDB，您可以在此链接找到有关其用法的详细信息：[`hub.docker.com/_/mongo`](https://hub.docker.com/_/mongo)。

1.  您可能需要使用`--name db`标志运行容器以使其可发现。如果您使用 Redis，则命令应如下所示：

```
docker run --name db -d redis
```

修改 Web 应用程序以连接到后端数据存储

1.  每当有请求时，您应该修改逻辑以从后端读取页面浏览次数，然后将`1`添加到其内部变量，并响应消息`Hello, you're visitor #i`，其中`i`是累积数字。同时，将添加的页面浏览次数存储在数据存储中。您可能需要使用数据存储的特定 SDK（软件开发工具包）来连接到数据存储。您现在可以将连接 URL 设置为`db:<db 端口>`。

注意

您可以使用以下链接的源代码：[`packt.live/3lBwOhJ`](https://packt.live/3lBwOhJ)。

如果您正在使用此链接中的代码，请确保将其修改为映射到数据存储的公开端口。

1.  使用新的镜像版本重建网络应用程序。

1.  使用`--link db:db`标志运行网络应用程序容器。

1.  验证页面浏览次数是否正确返回。

1.  终止网络应用程序容器并重新启动，以查看页面浏览次数是否恢复正常。

创建应用程序成功后，通过重复访问来测试它。您应该看到它的工作如下：

```
root@ubuntu:~# curl localhost: 8080
Hello, you're visitor #1.
root@ubuntu:~# curl localhost: 8080
Hello, you're visitor #2.
root@ubuntu:~# curl localhost: 8080
Hello, you're visitor #3.
```

然后，终止容器并重新启动。现在，尝试访问它。应用程序的状态应该被保留，也就是说，计数必须从您重新启动容器之前的位置继续。您应该看到以下结果：

```
root@ubuntu:~# curl localhost: 8080
Hello, you're visitor #4.
```

注意

此活动的解决方案可以在以下地址找到：[`packt.live/304PEoD`](https://packt.live/304PEoD)。

# 摘要

在本章中，我们向您介绍了软件开发的简要历史，并解释了 VM 时代的一些挑战。随着 Docker 的出现，容器化技术在解决早期软件开发方法存在的问题方面开辟了新的大门。

我们向您介绍了 Docker 的基础知识，并详细介绍了 Linux 的基本特性，如命名空间和 cgroups，这些特性实现了容器化。然后，我们提出了容器编排的概念，并阐明了它旨在解决的问题。最后，我们对 Kubernetes 的一些关键特性和方法进行了非常简要的概述。

在下一章中，我们将深入了解 Kubernetes 的架构，以了解其工作原理。


# 第二章： Kubernetes 概述

概述

在本章中，我们将首次介绍 Kubernetes。本章将为您简要介绍 Kubernetes 的不同组件以及它们如何协同工作。我们还将尝试使用一些基本的 Kubernetes 组件。

在本章结束时，您将拥有一个设置好的单节点 Minikube 环境，可以在其中运行本书中的许多练习和活动。您将能够理解 Kubernetes 的高层架构，并确定不同组件的角色。您还将学会将容器化应用程序迁移到 Kubernetes 环境所需的基础知识。

# 介绍

我们在上一章中通过提供简要和抽象的介绍以及一些优势来结束了对 Kubernetes 的介绍。在本章中，我们将为您提供对 Kubernetes 工作方式的更具体的高层次理解。首先，我们将带您了解如何安装 Minikube，这是一个方便的工具，可以创建单节点集群，并为 Kubernetes 提供便捷的学习环境。然后，我们将对所有组件进行一次总览，包括它们的职责以及它们如何相互交互。之后，我们将把我们在上一章中构建的 Docker 应用迁移到 Kubernetes，并说明它如何享受 Kubernetes 所提供的好处，比如创建多个副本和版本更新。最后，我们将解释应用程序如何响应外部和内部流量。

在我们深入了解 Kubernetes 的不同方面之前，了解 Kubernetes 的概述是很重要的，这样当我们学习更多关于不同方面的具体内容时，您将知道它们在整体中的位置。此外，当我们进一步探索如何使用 Kubernetes 在生产环境中部署应用程序时，您将了解到后台是如何处理一切的。这也将帮助您进行优化和故障排除。

# 设置 Kubernetes

如果三年前你问这样一个问题：“*如何轻松安装 Kubernetes？*”，那么很难给出一个令人信服的答案。尴尬但却是事实。Kubernetes 是一个复杂的系统，安装和有效管理它并不是一件容易的事。

然而，随着 Kubernetes 社区的扩大和成熟，出现了越来越多用户友好的工具。截至今天，根据您的需求，有很多选择：

+   如果您正在使用物理（裸机）服务器或虚拟机（VMs），Kubeadm 是一个很好的选择。

+   如果您在云环境中运行，Kops 和 Kubespray 可以简化 Kubernetes 的安装，以及与云提供商的集成。事实上，我们将教您如何在 AWS 上使用 Kops 部署 Kubernetes，*第十一章*，*构建您自己的 HA 集群*，我们将再次看看我们可以使用的各种选项来设置 Kubernetes。

+   如果您想摆脱管理 Kubernetes 控制平面的负担（我们将在本章后面学习），几乎所有的云提供商都有他们的 Kubernetes 托管服务，如 Google Kubernetes Engine（GKE）、Amazon Elastic Kubernetes Service（EKS）、Azure Kubernetes Service（AKS）和 IBM Kubernetes Service（IKS）。

+   如果您只是想要一个用来学习 Kubernetes 的游乐场，Minikube 和 Kind 可以帮助您在几分钟内建立一个 Kubernetes 集群。

在本书中，我们将广泛使用 Minikube 作为一个方便的学习环境。但在我们继续安装过程之前，让我们更仔细地看一下 Minikube 本身。

## Minikube 概述

Minikube 是一个用于设置单节点集群的工具，它提供了方便的命令和参数来配置集群。它的主要目标是提供一个本地测试环境。它打包了一个包含所有 Kubernetes 核心组件的虚拟机，一次性安装到您的主机上。这使得它能够支持任何操作系统，只要预先安装了虚拟化工具（也称为 Hypervisor）。以下是 Minikube 支持的最常见的 Hypervisors：

+   VirtualBox（适用于所有操作系统）

+   KVM（特定于 Linux）

+   Hyperkit（特定于 macOS）

+   Hyper-V（特定于 Windows）

关于所需的硬件资源，最低要求是 2GB RAM 和任何支持虚拟化的双核 CPU（Intel VT 或 AMD-V），但如果您要尝试更重的工作负载，当然需要一台更强大的机器。

就像任何其他现代软件一样，Kubernetes 提供了一个方便的命令行客户端，称为 kubectl，允许用户方便地与集群交互。在下一个练习中，我们将设置 Minikube 并使用一些基本的 kubectl 命令。我们将在下一章更详细地介绍 kubectl。

## 练习 2.01：开始使用 Minikube 和 Kubernetes 集群

在这个练习中，我们将使用 Ubuntu 20.04 作为基本操作系统来安装 Minikube，使用它可以轻松启动单节点 Kubernetes 集群。一旦 Kubernetes 集群设置好了，你应该能够检查它的状态并使用`kubectl`与之交互：

注意

由于这个练习涉及软件安装，你需要以 root/superuser 身份登录。切换到 root 用户的简单方法是运行以下命令：`sudo su -`。

在这个练习的第 9 步中，我们将创建一个普通用户，然后切换回该用户。

1.  首先确保 VirtualBox 已安装。你可以使用以下命令确认：

```
which VirtualBox
```

你应该看到以下输出：

```
/usr/bin/VirtualBox
```

如果 VirtualBox 已成功安装，`which`命令应该显示可执行文件的路径，就像前面的截图中显示的那样。如果没有，那么请确保你已按照*前言*中提供的说明安装了 VirtualBox。

1.  使用以下命令下载 Minikube 独立二进制文件：

```
curl -Lo minikube https://github.com/kubernetes/minikube/releases/download/<version>/minikube-<ostype-arch> && chmod +x minikube
```

在这个命令中，`<version>`应该被替换为一个特定的版本，比如`v1.5.2`（这是本章中我们将使用的版本）或者`latest`。根据你的主机操作系统，`<ostype-arch>`应该被替换为`linux-amd64`（对于 Ubuntu）或者`darwin-amd64`（对于 macOS）。

注意

为了确保与本书提供的命令兼容，我们建议安装 Minikube 版本`v1.5.2`。

你应该看到以下输出：

![图 2.1：下载 Minikube 二进制文件](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/k8s-ws/img/B14870_02_01.jpg)

图 2.1：下载 Minikube 二进制文件

上述命令包含两部分：第一个命令`curl`下载 Minikube 二进制文件，而第二个命令`chmod`更改权限以使其可执行。

1.  将二进制文件移动到系统路径（在本例中是`/usr/local/bin`），这样我们可以直接运行 Minikube，而不管命令在哪个目录中运行：

```
mv minikube /usr/local/bin
```

当成功执行时，移动（`mv`）命令不会在终端中给出响应。

1.  运行移动命令后，我们需要确认 Minikube 可执行文件现在位于正确的位置：

```
which minikube
```

您应该看到以下输出：

```
/usr/local/bin/minikube
```

注意

如果`which minikube`命令没有给出预期的结果，您可能需要通过运行`export PATH=$PATH:/usr/local/bin`来显式将`/usr/local/bin`添加到系统路径。

1.  您可以使用以下命令检查 Minikube 的版本：

```
minikube version
```

您应该看到以下输出：

```
minikube version: v1.5.2
commit: 792dbf92a1de583fcee76f8791cff12e0c9440ad-dirty
```

1.  现在，让我们下载 kubectl 版本`v1.16.2`（以便与稍后我们的 Minikube 设置创建的 Kubernetes 版本兼容），并使用以下命令使其可执行：

```
curl -LO https://storage.googleapis.com/kubernetes-release/release/v1.16.2/bin/<ostype>/amd64/kubectl && chmod +x kubectl
```

如前所述，`<ostype>`应替换为`linux`（对于 Ubuntu）或`darwin`（对于 macOS）。

您应该看到以下输出：

![图 2.2：下载 kubectl 二进制文件](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/k8s-ws/img/B14870_02_02.jpg)

图 2.2：下载 kubectl 二进制文件

1.  然后，将其移动到系统路径，就像我们之前为 Minikube 的可执行文件所做的那样：

```
mv kubectl /usr/local/bin
```

1.  现在，让我们检查 kubectl 的可执行文件是否在正确的路径上：

```
which kubectl
```

您应该看到以下响应：

```
/usr/local/bin/kubectl
```

1.  由于我们当前以`root`用户登录，让我们通过运行以下命令创建一个名为`k8suser`的常规用户：

```
useradd k8suser
```

在提示时输入您想要的密码。您还将被提示输入其他详细信息，例如您的全名。您可以选择通过简单地按*Enter*来跳过这些细节。您应该看到类似于以下的输出：

![图 2.3：创建新的 Linux 用户](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/k8s-ws/img/B14870_02_03.jpg)

图 2.3：创建一个新的 Linux 用户

输入`Y`并按*Enter*确认创建用户的最终提示，如前一个屏幕截图的末尾所示。

1.  现在，从`root`切换用户到`k8suser`：

```
su - k8suser
```

您应该看到以下输出：

```
root@ubuntu:~# su – k8suser
k8suser@ubuntu:~$
```

1.  现在，我们可以使用`minikube start`创建一个 Kubernetes 集群：

```
minikube start --kubernetes-version=v1.16.2
```

注意

如果您想管理多个集群，Minikube 为每个集群提供了一个`--profile <profile name>`参数。

下载 VM 镜像并进行所有设置需要几分钟时间。Minikube 成功启动后，您应该看到类似于以下的响应：

![图 2.4：Minikube 首次启动](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/k8s-ws/img/B14870_02_04.jpg)

图 2.4：Minikube 首次启动

正如我们之前提到的，Minikube 在一个 VM 实例中启动了所有 Kubernetes 的组件。默认情况下，它使用 VirtualBox，并且您可以使用`--vm-driver`标志来指定特定的 hypervisor 驱动程序（例如`hyperkit`用于 macOS）。Minikube 还提供了`--kubernetes-version`标志，因此您可以指定要使用的 Kubernetes 版本。如果未指定，它将使用 Minikube 发布时可用的最新版本。在本章中，为了确保 Kubernetes 版本与 kubectl 版本的兼容性，我们明确指定了 Kubernetes 版本`v1.16.2`。

以下命令应该有助于建立 Minikube 启动的 Kubernetes 集群是否正常运行。

1.  使用以下命令获取集群各个组件的基本状态： 

```
minikube status
```

您应该看到以下响应：

```
host: Running
kubelet: Running
apiserver: Running
kubeconfig: Configured
```

1.  现在，让我们看一下 kubectl 客户端和 Kubernetes 服务器的版本：

```
kubectl version --short
```

您应该看到以下响应：

```
Client Version: v1.16.2
Server Version: v1.16.2
```

1.  让我们了解一下集群由多少台机器组成，并获取一些关于它们的基本信息：

```
kubectl get node
```

您应该看到类似以下的响应：

```
NAME          STATUS          ROLES          AGE          VERSION
minikube      Ready           master         2m41s        v1.16.2
```

完成这个练习后，您应该已经设置好了一个单节点的 Kubernetes 集群。在下一节中，我们将进入 Minikube 虚拟机，看看集群是如何组成的，以及使其工作的 Kubernetes 的各个组件。

# Kubernetes 组件概述

通过完成上一个练习，您已经拥有一个单节点的 Kubernetes 集群正在运行。在开始您的第一场音乐会之前，让我们等一下，拉开帷幕，看看 Kubernetes 在幕后是如何架构的，然后检查 Minikube 是如何在其虚拟机内将其各个组件粘合在一起的。

Kubernetes 有几个核心组件，使机器的轮子转动。它们如下：

+   API 服务器

+   etcd

+   控制器管理器

+   调度器

+   Kubelet

这些组件对于 Kubernetes 集群的运行至关重要。

除了这些核心组件，您将在容器中部署您的应用程序，这些应用程序被捆绑在一起作为 pod。我们将在*第五章* *Pods*中更多地了解 pod。这些 pod 和其他几个资源是由称为 API 对象的东西定义的。

**API 对象**描述了在 Kubernetes 中应该如何尊重某个资源。我们通常使用人类可读的清单文件来定义 API 对象，然后使用工具（如 kubectl）来解析它并将其交给 Kubernetes API 服务器。然后，Kubernetes 尝试创建对象中指定的资源，并将其状态与清单文件中指定的期望状态匹配。接下来，我们将带您了解 Minikube 创建的单节点集群中这些组件是如何组织和行为的。

Minikube 提供了一个名为`minikube ssh`的命令，用于从主机（在我们的机器上，它是运行 Ubuntu 20.04 的物理机）到`minikube`虚拟机的 SSH 访问，后者作为我们 Kubernetes 集群中唯一的节点。让我们看看它是如何工作的：

```
minikube ssh
```

您将看到以下输出：

![图 2.5：通过 SSH 访问 Minikube 虚拟机](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/k8s-ws/img/B14870_02_05.jpg)

图 2.5：通过 SSH 访问 Minikube 虚拟机

注意

本节中将显示的所有命令都假定已在 Minikube 虚拟机内运行`minikube ssh`之后运行。

容器技术带来了封装应用程序的便利。Minikube 也不例外 - 它利用容器将 Kubernetes 组件粘合在一起。在 Minikube 虚拟机中，Docker 预先安装，以便它可以管理核心 Kubernetes 组件。您可以通过运行`docker ps`来查看这一点；但是，结果可能会让人不知所措，因为它包括所有正在运行的容器 - 包括核心 Kubernetes 组件和附加组件，以及所有列 - 这将输出一个非常大的表格。

为了简化输出并使其更易于阅读，我们将把`docker ps`的输出传输到另外两个 Bash 命令中：

1.  `grep -v pause`：这将通过不显示“沙盒”容器来过滤结果。

如果没有`grep -v pause`，您会发现每个容器都与一个“沙盒”容器（在 Kubernetes 中，它被实现为`pause`镜像）“配对”。这是因为，如前一章所述，Linux 容器可以通过加入相同（或不同）的 Linux 命名空间来关联（或隔离）。在 Kubernetes 中，“沙盒”容器用于引导 Linux 命名空间，然后运行真实应用程序的容器可以加入该命名空间。为了简洁起见，关于所有这些是如何在幕后工作的细节已被忽略。

注意

如果没有明确指定，本书中术语“命名空间”与“Kubernetes 命名空间”可以互换使用。在“Linux 命名空间”方面，“Linux”不会被省略以避免混淆。

1.  `awk '{print $NF}'`：这将只打印最后一列的容器名称。

因此，最终命令如下：

```
docker ps | grep -v pause | awk '{print $NF}'
```

您应该看到以下输出：

![图 2.6：通过运行 Minikube VM 获取容器列表](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/k8s-ws/img/B14870_02_06.jpg)

图 2.6：通过运行 Minikube VM 获取容器列表

在前面的截图中显示的突出显示的容器基本上是 Kubernetes 的核心组件。我们将在接下来的章节中详细讨论每一个。

## etcd

分布式系统可能在任何时刻面临各种故障（网络、存储等）。为了确保在出现故障时仍能正常工作，关键的集群元数据和状态必须以可靠的方式存储。

Kubernetes 将集群元数据和状态抽象为一系列 API 对象。例如，节点 API 对象代表了 Kubernetes 工作节点的规范，以及其最新状态。

Kubernetes 使用**etcd**作为后端键值数据库，在 Kubernetes 集群的生命周期中持久化 API 对象。重要的是要注意，没有任何东西（内部集群资源或外部客户端）被允许直接与 etcd 通信，而必须通过 API 服务器。对 etcd 的任何更新或请求都只能通过对 API 服务器的调用来进行。

实际上，etcd 通常部署多个实例，以确保数据以安全和容错的方式持久化。

## API 服务器

API 服务器允许标准 API 访问 Kubernetes API 对象。它是唯一与后端存储（etcd）通信的组件。

此外，通过利用它作为与 etcd 通信的唯一接触点，它为客户端提供了一个方便的接口，以“监视”它们可能感兴趣的任何 API 对象。一旦 API 对象被创建、更新或删除，正在“监视”的客户端将立即收到通知，以便他们可以对这些更改采取行动。正在“监视”的客户端也被称为“控制器”，它已经成为内置 Kubernetes 对象和 Kubernetes 扩展中广受欢迎的实体。

注意

您将在*第四章*“如何与 Kubernetes 通信”（API 服务器）中了解更多关于 API 服务器的信息，并在*第七章*“Kubernetes 控制器”中了解有关控制器的信息。

## 调度器

调度程序负责将传入的工作负载分配给最合适的节点。关于分配的决定是由调度程序对整个集群的理解以及一系列调度算法来做出的。

注意

您将在《第十七章》《Kubernetes 高级调度》中了解更多关于调度程序的信息。

## 控制器管理器

正如我们在《API 服务器》小节中提到的，API 服务器公开了几乎任何 API 对象的“监视”方式，并通知观察者有关正在观察的 API 对象的更改。

它的工作方式几乎与发布者-订阅者模式相似。控制器管理器充当典型的订阅者，监视它感兴趣的唯一 API 对象，然后尝试进行适当的更改，以将当前状态移向对象中描述的期望状态。

例如，如果它从 API 服务器那里得到一个更新，说一个应用程序要求两个副本，但是现在集群中只有一个副本，它将创建第二个副本，以使应用程序符合其期望的副本数量。协调过程在控制器管理器的生命周期中持续运行，以确保所有应用程序保持在预期状态。

控制器管理器聚合各种类型的控制器，以遵守 API 对象的语义，例如部署和服务，我们将在本章后面介绍。

## kubelet 在哪里？

请注意，etcd、API 服务器、调度程序和控制器管理器组成了 Kubernetes 的控制平面。运行这些组件的机器称为主节点。另一方面，kubelet 部署在每台工作节点上。

在我们的单节点 Minikube 集群中，kubelet 部署在携带控制平面组件的同一节点上。然而，在大多数生产环境中，它不会部署在任何主节点上。当我们在《第十一章》《构建您自己的 HA 集群》中部署多节点集群时，我们将了解更多关于生产环境的信息。

kubelet 主要是与底层容器运行时（例如 Docker、containerd 或 cri-o）进行通信，以启动容器并确保容器按预期运行。此外，它负责将状态更新发送回 API 服务器。

然而，如前面的屏幕截图所示，`docker ps`命令并没有显示任何名为`kubelet`的内容。通常，为了启动、停止或重新启动任何软件并使其在失败时自动重新启动，我们需要一个工具来管理其生命周期。在 Linux 中，systemd 负责这个责任。在 Minikube 中，kubelet 由 systemd 管理，并作为本地二进制文件而不是 Docker 容器运行。我们可以运行以下命令来检查其状态：

```
systemctl status kubelet
```

您应该看到类似以下的输出：

![图 2.7：kubelet 的状态](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/k8s-ws/img/B14870_02_07.jpg)

图 2.7：kubelet 的状态

默认情况下，kubelet 在其配置文件中（存储在`/var/lib/kubelet/config.yaml`）具有`staticPodPath`的配置。kubelet 被指示持续监视该路径下文件的更改，该路径下的每个文件代表一个 Kubernetes 组件。让我们首先找到 kubelet 的`config`文件中的`staticPodPath`，以了解这意味着什么：

```
grep "staticPodPath" /var/lib/kubelet/config.yaml
```

您应该看到以下输出：

```
staticPodPath: /etc/kubernetes/manifests
```

现在，让我们看看这个路径的内容：

```
ls /etc/kubernetes/manifests
```

您应该看到以下输出：

```
addon-manager.yaml.tmpl kube-apiserver.yaml      kube-scheduler.yaml
etcd.yaml               kube-controller-manager.yaml
```

如文件列表所示，Kubernetes 的核心组件由在 YAML 文件中指定定义的对象定义。在 Minikube 环境中，除了管理用户创建的 pod 之外，kubelet 还充当 systemd 的等效物，以管理 Kubernetes 系统级组件的生命周期，如 API 服务器、调度程序、控制器管理器和其他附加组件。一旦这些 YAML 文件中的任何一个发生变化，kubelet 会自动检测到并更新集群的状态，使其与更新后的 YAML 配置中定义的期望状态相匹配。

我们将在这里停下，不深入探讨 Minikube 的设计。除了“静态组件”之外，kubelet 还是“常规应用程序”的管理者，以确保它们在节点上按预期运行，并根据 API 规范或资源短缺驱逐 pod。

## kube-proxy

kube-proxy 出现在`docker ps`命令的输出中，但在我们在上一小节中探索该目录时，它并不存在于`/etc/kubernetes/manifests`中。这意味着它的角色——它更多地被定位为一个附加组件，而不是核心组件。

kube-proxy 被设计为在每个节点上运行的分布式网络路由器。它的最终目标是确保流入到 Service（这是我们稍后将介绍的一个 API 对象）端点的流量能够正确路由。此外，如果多个容器提供一个应用程序，它可以通过利用底层的 Linux iptables/IPVS 技术以循环方式平衡流量。

还有一些其他附加组件，比如 CoreDNS，但我们将跳过它们，以便我们可以专注于核心组件并获得高层次的图像。

注意

有时，kube-proxy 和 CoreDNS 也被认为是 Kubernetes 安装的核心组件。在某种程度上，从技术上讲，这是正确的，因为它们在大多数情况下是必需的；否则，Service API 对象将无法工作。然而，在本书中，我们更倾向于将它们归类为“附加组件”，因为它们侧重于实现特定的 Kubernetes API 资源，而不是一般的工作流程。此外，kube-proxy 和 CoreDNS 是在`addon-manager.yaml.tmpl`中定义的，而不是被描绘在与其他核心 Kubernetes 组件同一级别。

# Kubernetes 架构

在前一节中，我们对核心 Kubernetes 组件有了初步印象：etcd、API 服务器、调度器、控制器管理器和 kubelet。这些组件，加上其他附加组件，构成了 Kubernetes 架构，可以在以下图表中看到：

![图 2.8：Kubernetes 架构](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/k8s-ws/img/B14870_02_08.jpg)

图 2.8：Kubernetes 架构

在这一点上，我们不会过多地查看每个组件。然而，在高层次上，理解组件如何相互通信以及它们为什么以这种方式设计是至关重要的。

首先要理解的是 API 服务器可以与哪些组件进行交互。从前面的图表中，我们可以很容易地看出 API 服务器几乎可以与每个其他组件进行通信（除了容器运行时，由 kubelet 处理），它还可以直接与最终用户进行交互。这种设计使 API 服务器充当 Kubernetes 的“心脏”。此外，API 服务器还会审查传入的请求，并将 API 对象写入后端存储（etcd）。换句话说，这使得 API 服务器成为安全控制措施（如身份验证、授权和审计）的节流阀。

理解的第二件事是不同的 Kubernetes 组件（除了 API 服务器）如何相互交互。事实证明它们之间没有明确的连接 - 控制器管理器不与调度程序交谈，kubelet 也不与 kube-proxy 交谈。

没错 - 他们确实需要协调工作来完成许多功能，但它们从不直接交谈。相反，它们通过 API 服务器隐式通信。更准确地说，它们通过观察、创建、更新或删除相应的 API 对象进行通信。这也被称为控制器/操作员模式。

## 容器网络接口

有几个网络方面需要考虑，比如一个 pod 如何与其主机的网络接口通信，一个节点如何与其他节点通信，最终一个 pod 如何与不同节点上的任何 pod 通信。由于云端或本地环境中的网络基础设施差异巨大，Kubernetes 选择通过定义一个称为**容器网络接口**（**CNI**）的规范来解决这些问题。不同的 CNI 提供者可以遵循相同的接口并实现符合 Kubernetes 标准的逻辑，以确保整个 Kubernetes 网络运行。我们将在*第十一章*，*构建您自己的 HA 集群*中重新讨论 CNI 的概念。现在，让我们回到讨论不同的 Kubernetes 组件如何工作。

在本章的后面，*练习 2.05*，*Kubernetes 如何管理 Pod 的生命周期*，将帮助您巩固对此的理解，并澄清一些问题，比如不同的 Kubernetes 组件如何同步或异步地操作，以确保典型的 Kubernetes 工作流程，以及如果其中一个或多个组件发生故障会发生什么。这个练习将帮助您更好地理解整体的 Kubernetes 架构。但在那之前，让我们把我们在上一章中介绍的容器化应用引入到 Kubernetes 世界中，并探索 Kubernetes 的一些好处。

# 将容器化应用迁移到 Kubernetes

在上一章中，我们构建了一个名为`k8s-for-beginners`的简单 HTTP 服务器，并且它作为一个 Docker 容器运行。对于一个示例应用程序来说，它运行得很完美。但是，如果你需要管理成千上万个容器，并且正确协调和调度它们，该怎么办？你如何在没有停机的情况下升级一个服务？在意外故障时如何保持服务的健康？这些问题超出了仅仅使用容器的系统的能力。我们需要的是一个可以编排和管理我们的容器的平台。

我们已经告诉过你，Kubernetes 是我们需要的解决方案。接下来，我们将带你进行一系列关于如何使用 Kubernetes 本地方法编排和运行容器的练习。

## Pod 规范

一个直观的想法是，我们希望看到在 Kubernetes 中运行容器的等效 API 调用或命令是什么。正如*第一章* *Kubernetes 和容器简介*中所解释的，一个容器可以加入另一个容器的命名空间，以便它们可以访问彼此的资源（例如网络、存储等），而无需额外的开销。在现实世界中，一些应用程序可能需要多个容器密切合作，无论是并行工作还是按特定顺序工作（一个的输出将由另一个处理）。此外，一些通用容器（例如日志代理、网络限速代理等）可能需要与它们的目标容器密切合作。

由于一个应用程序通常可能需要多个容器，容器不是 Kubernetes 中的最小操作单元；相反，它引入了一个称为**pods**的概念来捆绑一个或多个容器。Kubernetes 提供了一系列规范来描述这个 pod 应该是什么样的，包括诸如镜像、资源请求、启动命令等几个具体的内容。为了将这个 pod 规范发送给 Kubernetes，特别是 Kubernetes API 服务器，我们将使用 kubectl。

注意

我们将在*第五章* *Pods*中了解更多关于 Pods 的内容，但在本章中，我们将使用它们进行简单演示。您可以在此链接查看可用 Pod 规范的完整列表：[`godoc.org/k8s.io/api/core/v1#PodSpec`](https://godoc.org/k8s.io/api/core/v1#PodSpec)。

接下来，让我们学习如何通过编写 pod 规范文件（也称为规范、清单、配置或配置文件）在 Kubernetes 中运行单个容器。在 Kubernetes 中，您可以使用 YAML 或 JSON 来编写此规范文件，尽管 YAML 通常更常用，因为它更易读和可编辑。

考虑以下用于一个非常简单的 pod 的 YAML 规范：

```
kind: Pod
apiVersion: v1
metadata:
  name: k8s-for-beginners
spec:
  containers:
  - name: k8s-for-beginners
    image: packtworkshops/the-kubernetes-workshop:k8s-for-beginners
```

让我们简要地浏览一下不同的字段：

+   `kind` 告诉 Kubernetes 您想要创建哪种类型的对象。在这里，我们正在创建一个 `Pod`。在后面的章节中，您将看到许多其他类型，比如 Deployment、StatefulSet、ConfigMap 等等。

+   `apiVersion` 指定 API 对象的特定版本。不同版本可能会有一些不同的行为。

+   `metadata` 包括一些属性，可以用来唯一标识 pod，比如名称和命名空间。如果我们不指定命名空间，它就会放在 `default` 命名空间中。

+   `spec` 包含一系列描述 pod 的字段。在这个例子中，有一个容器，它有指定的镜像 URL 和名称。

Pod 是部署的最简单的 Kubernetes 对象之一，因此我们将使用它们来学习如何使用 YAML 清单部署对象。

## 应用 YAML 清单

一旦我们准备好一个 YAML 清单，我们可以使用 `kubectl apply -f <yaml file>` 或 `kubectl create -f <yaml file>` 来指示 API 服务器持久化在此清单中定义的 API 资源。当您首次从头开始创建一个 pod 时，您使用这两个命令之一并没有太大的区别。然而，我们经常需要修改 YAML（比如说，如果我们想要升级镜像版本），然后重新应用它。如果我们使用 `kubectl create` 命令，我们必须删除并重新创建它。但是，使用 `kubectl apply` 命令，我们可以重新运行相同的命令，Kubernetes 会自动计算并应用增量变化。

从运维的角度来看，这非常方便。例如，如果我们使用某种形式的自动化，重复相同的命令会更简单。因此，我们将在接下来的练习中使用 `kubectl apply`，无论是第一次应用还是不是。

注意

可以在 *第四章* *如何与 Kubernetes（API 服务器）通信* 中获取有关 kubectl 的详细信息。

## 练习 2.02：在 Kubernetes 中运行一个 Pod

在上一个练习中，我们启动了 Minikube，并查看了各种作为 pod 运行的 Kubernetes 组件。现在，在这个练习中，我们将部署我们的 pod。按照以下步骤完成这个练习：

注意

如果您一直在尝试*Kubernetes 组件概述*部分的命令，请不要忘记在开始这个练习之前使用`exit`命令离开 SSH 会话。除非另有说明，所有使用`kubectl`的命令应该在主机上运行，而不是在 Minikube VM 内部。

1.  在 Kubernetes 中，我们使用一个 spec 文件来描述一个 API 对象，比如一个 pod。如前所述，我们将坚持使用 YAML，因为它更易读和易编辑。创建一个名为`k8s-for-beginners-pod.yaml`的文件（使用你选择的任何文本编辑器），内容如下：

```
kind: Pod
apiVersion: v1
metadata:
  name: k8s-for-beginners
spec:
  containers:
  - name: k8s-for-beginners
    image: packtworkshops/the-kubernetes-workshop:k8s-for-      beginners
```

注意

请用前面 YAML 文件中最后一行的路径替换成您在上一章中创建的图像的路径。

1.  在主机上运行以下命令来创建这个 pod：

```
kubectl apply -f k8s-for-beginners-pod.yaml
```

您应该看到以下输出：

```
pod/k8s-for-beginners created
```

1.  现在，我们可以使用以下命令来检查 pod 的状态：

```
kubectl get pod
```

您应该看到以下响应：

```
NAME                   READY     STATUS      RESTARTS       AGE
k8s-for-beginners      1/1       Running     0              7s
```

默认情况下，`kubectl get pod`将以表格格式列出所有的 pod。在前面的输出中，我们可以看到`k8s-for-beginners` pod 正常运行，并且它有一个容器是就绪的（`1/1`）。此外，kubectl 提供了一个额外的标志叫做`-o`，这样我们可以调整输出格式。例如，`-o yaml`或`-o json`将分别以 YAML 或 JSON 格式返回 pod API 对象的完整输出，因为它存储在 Kubernetes 的后端存储（etcd）中。

1.  您可以使用以下命令获取有关 pod 的更多信息：

```
kubectl get pod -o wide
```

您应该看到以下输出：

![图 2.9：获取有关 pod 的更多信息](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/k8s-ws/img/B14870_02_09.jpg)

图 2.9：获取有关 pod 的更多信息

正如你所看到的，输出仍然是表格格式，我们得到了额外的信息，比如`IP`（内部 pod IP）和`NODE`（pod 所在的节点）。

1.  您可以通过运行以下命令来获取我们集群中节点的列表：

```
kubectl get node
```

您应该看到以下响应：

```
NAME          STATUS          ROLES          AGE          VERSION
minikube      Ready           master         30h          v1.16.2
```

1.  *图 2.9*中列出的 IP 是 Kubernetes 为此 pod 分配的内部 IP，用于 pod 之间的通信，而不是用于将外部流量路由到 pod。因此，如果您尝试从集群外部访问此 IP，您将得到空白。您可以尝试使用以下命令从主机上执行，但会失败：

```
curl 172.17.0.4:8080
```

注意

请记得将`172.17.0.4`更改为您在*步骤 4*中获得的值，如*图 2.9*所示。

`curl`命令将会挂起并返回空白，如下所示：

```
k8suser@ubuntu:~$ curl 172.17.0.4:8080
^C
```

您需要按下*Ctrl* + *C*来中止它。

1.  在大多数情况下，最终用户不需要与内部 pod IP 进行交互。但是，仅出于观察目的，让我们 SSH 进入 Minikube VM：

```
minikube ssh
```

您将在终端中看到以下响应：

![图 2.10：通过 SSH 访问 Minikube VM](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/k8s-ws/img/B14870_02_10.jpg)

图 2.10：通过 SSH 访问 Minikube VM

1.  现在，尝试从 Minikube VM 内部调用 IP 以验证其是否有效：

```
curl 172.17.0.4:8080
```

您应该会收到一个成功的响应：

```
Hello Kubernetes Beginners!
```

有了这个，我们已经成功在 Kubernetes 集群上部署了我们的应用程序。我们可以确认它正在工作，因为当我们从集群内部调用应用程序时，我们会得到一个响应。现在，您可以使用`exit`命令结束 Minikube SSH 会话。

## Service 规范

前一节的最后部分证明了集群内不同组件之间的网络通信非常顺畅。但在现实世界中，您不希望应用程序的用户获得 SSH 访问权限来使用您的应用程序。因此，您希望您的应用程序可以从外部访问。

为了方便起见，Kubernetes 提供了一个称为**Service**的概念，用于抽象应用程序 pod 的网络访问。Service 充当网络代理，接受来自外部用户的网络流量，然后将其分发到内部 pod。但是，应该有一种方法来描述 Service 和相应 pod 之间的关联规则。Kubernetes 使用标签（在 pod 定义中定义）和标签选择器（在 Service 定义中定义）来描述这种关系。

注意

您将在*第六章*，*标签和注释*中了解更多关于标签和标签选择器的内容。

让我们考虑以下 Service 的样本规范：

```
kind: Service
apiVersion: v1
metadata:
  name: k8s-for-beginners
spec:
  selector:
    tier: frontend
  type: NodePort
  ports:
  - port: 80
    targetPort: 8080
```

与 Pod 规范类似，在这里，我们定义了 `kind` 和 `apiVersion`，而 `name` 是在 `metadata` 字段下定义的。在 `spec` 字段下，有几个关键字段需要注意：

+   `selector` 定义要选择的标签，以便与相应的 pod 匹配关系，正如您将在接下来的练习中看到的，这些标签应该被正确地标记。

+   `type` 定义了服务的类型。如果未指定，默认类型为 `ClusterIP`，这意味着它仅在集群内部使用。在这里，我们将其指定为 `NodePort`。这意味着服务将在集群的每个节点上公开一个端口，并将该端口与相应的 pod 关联起来。另一个众所周知的类型称为 `LoadBalancer`，通常不在原始的 Kubernetes 提供中实现。相反，Kubernetes 将实现委托给每个云提供商，例如 GKE、EKS 等。

+   `ports` 包括一系列 `port` 字段，每个字段都有一个 `targetPort` 字段。`targetPort` 字段是目标 pod 公开的实际端口。

因此，可以通过 `<service ip>:<port>` 内部访问服务。现在，例如，如果您有一个在内部运行并在端口 8080 上侦听的 NGINX pod，则应将 `targetPort` 定义为 `8080`。您可以在此案例中为 `port` 字段指定任意数字，例如 `80`。Kubernetes 将建立并维护 `<service IP>:<port>` 与 `<pod IP>:<targetPort>` 之间的映射。在接下来的练习中，我们将学习如何从集群外访问服务，并通过服务将外部流量带入集群。

在接下来的练习中，我们将定义服务清单并使用 `kubectl apply` 命令创建它们。您将了解到在 Kubernetes 中解决问题的常见模式是找到适当的 API 对象，然后使用 YAML 清单组合详细规范，最后创建对象以使其生效。

## 练习 2.03：通过服务访问 Pod

在之前的练习中，我们观察到内部 pod IP 对于集群外部的任何人都不起作用。在这个练习中，我们将创建服务，这些服务将充当连接器，将外部请求映射到目标 pod，以便我们可以在不进入集群的情况下外部访问 pod。按照以下步骤完成这个练习：

1.  首先，让我们调整来自 *练习 2.02*，*在 Kubernetes 中运行一个 Pod* 的 pod 规范，以应用一些标签。修改 `k8s-for-beginners-pod1.yaml` 文件的内容如下：

```
kind: Pod
apiVersion: v1
metadata:
  name: k8s-for-beginners
  labels:
    tier: frontend
spec:
  containers:
  - name: k8s-for-beginners
    image: packtworkshops/the-kubernetes-workshop:k8s-for-      beginners
```

在这里，我们在 `labels` 字段下添加了一个标签对，`tier: frontend`。

1.  因为 pod 名称保持不变，让我们重新运行 `apply` 命令，这样 Kubernetes 就知道我们正在尝试更新 pod 的规范，而不是创建一个新的 pod：

```
kubectl apply -f k8s-for-beginners-pod1.yaml
```

你应该看到以下响应：

```
pod/k8s-for-beginners configured
```

在 `kubectl apply` 命令背后，kubectl 生成指定 YAML 和 Kubernetes 服务器端存储（即 etcd）中存储版本的差异。如果请求有效（即，我们在规范格式或命令中没有出现任何错误），kubectl 将向 Kubernetes API 服务器发送 HTTP 补丁。因此，只会应用增量更改。如果查看返回的消息，你会看到它说 `pod/k8s-for-beginners configured` 而不是 `created`，所以我们可以确定它正在应用增量更改，而不是创建一个新的 pod。

1.  你可以使用以下命令显式显示已应用到现有 pod 的标签：

```
kubectl get pod --show-labels
```

你应该看到以下响应：

```
NAME              READY  STATUS   RESTARTS   AGE  LABELS
k8s-for-beginners 1/1    Running  0          16m  tier=frontend
```

现在，pod 具有 `tier: frontend` 属性，我们准备创建一个服务并将其链接到这些 pod。

1.  创建一个名为 `k8s-for-beginners-svc.yaml` 的文件，内容如下：

```
kind: Service
apiVersion: v1
metadata:
  name: k8s-for-beginners
spec:
  selector:
    tier: frontend
  type: NodePort
  ports:
  - port: 80
    targetPort: 8080
```

1.  现在，让我们使用以下命令创建服务：

```
kubectl apply -f k8s-for-beginners-svc.yaml
```

你应该看到以下响应：

```
service/k8s-for-beginners created
```

1.  使用 `get` 命令返回已创建服务的列表，并确认我们的服务是否在线：

```
kubectl get service
```

你应该看到以下响应：

![图 2.11：获取服务列表](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/k8s-ws/img/B14870_02_11.jpg)

图 2.11：获取服务列表

所以，你可能已经注意到 `PORT(S)` 列输出 `80:32571/TCP`。端口 `32571` 是在每个节点上暴露的自动生成的端口，这是有意为之，以便外部用户可以访问它。现在，在进行下一步之前，退出 SSH 会话。

1.  现在，我们有了“外部端口”为 `32571`，但我们仍然需要找到外部 IP。Minikube 提供了一个实用程序，我们可以使用它轻松访问 `k8s-for-beginners` 服务：

```
minikube service k8s-for-beginners
```

应该看到类似以下的响应：

![图 2.12：获取访问 NodePort 服务的 URL 和端口](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/k8s-ws/img/B14870_02_12.jpg)

图 2.12：获取访问 NodePort 服务的 URL 和端口

根据您的环境，这可能还会自动打开一个浏览器页面，以便您可以访问服务。从 URL 中，您将能够看到服务端口是`32571`。外部 IP 实际上是 Minikube VM 的 IP。

1.  您还可以通过命令行从集群外部访问我们的应用：

```
curl http://192.168.99.100:32571
```

您应该看到以下响应：

```
Hello Kubernetes Beginners!
```

总之，在这个练习中，我们创建了一个`NodePort`服务，以便外部用户可以访问内部的 Pod，而不需要进入集群。在幕后，有几个层次的流量转换使这成为可能：

+   第一层是从外部用户到机器 IP 的自动生成的随机端口（3XXXX）。

+   第二层是从随机端口（3XXXX）到服务 IP（10.X.X.X）的端口`80`。

+   第三层是从服务 IP（10.X.X.X）最终到端口`8080`的 Pod IP。

以下是一个说明这些交互的图表：

![图 2.13：将来自集群外部用户的流量路由到运行我们应用的 Pod 到运行我们应用的 Pod](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/k8s-ws/img/B14870_02_13.jpg)

图 2.13：将来自集群外部用户的流量路由到运行我们应用的 Pod

## 服务和 Pod

在上一个练习的*步骤 3*中，您可能已经注意到服务尝试通过标签（`spec`部分下的`selector`字段）来匹配 Pod，而不是使用固定的 Pod 名称或类似的东西。从 Pod 的角度来看，它不需要知道哪个服务正在为其带来流量。（在一些罕见的情况下，它甚至可以映射到多个服务；也就是说，多个服务可能会向一个 Pod 发送流量。）

这种基于标签的匹配机制在 Kubernetes 中被广泛使用。它使 API 对象在运行时松散耦合。例如，您可以指定`tier: frontend`作为标签选择器，这将与被标记为`tier: frontend`的 Pod 相关联。

因此，一旦创建了 Service，备份 pod 是否存在都无关紧要。备份 pod 后来创建也是完全可以接受的，创建后，Service 对象将与正确的 pod 关联起来。在内部，整个映射逻辑是由服务控制器实现的，它是控制器管理器组件的一部分。Service 可能一次有两个匹配的 pod，并且后来创建了一个具有匹配标签的第三个 pod，或者其中一个现有的 pod 被删除。在任何一种情况下，服务控制器都可以检测到这些更改，并确保用户始终可以通过 Service 端点访问其应用程序。

在 Kubernetes 中使用不同类型的 API 对象来编排应用程序，然后通过使用标签或其他松散耦合的约定将它们粘合在一起是一个非常常见的模式。这也是容器编排的关键部分。

# 交付 Kubernetes 原生应用程序

在前面的部分中，我们将基于 Docker 的应用程序迁移到了 Kubernetes，并成功地从 Minikube VM 内部和外部访问了它。现在，让我们看看如果我们从头开始设计我们的应用程序，使其可以使用 Kubernetes 进行部署，Kubernetes 还可以提供哪些其他好处。

随着您的应用程序使用量增加，运行多个特定 pod 的副本以提供业务功能可能很常见。在这种情况下，仅仅将不同容器分组在一个 pod 中是不够的。我们需要继续创建一组共同工作的 pod。Kubernetes 为 pod 组提供了几种抽象，例如 Deployments、DaemonSets、Jobs、CronJobs 等。就像 Service 对象一样，这些对象也可以通过在 YAML 文件中定义的 spec 来创建。

要开始了解 Kubernetes 的好处，让我们使用 Deployment 来演示如何在多个 pod 中复制（扩展/缩减）应用程序。

使用 Kubernetes 对 pod 组进行抽象化给我们带来了以下优势：

+   **创建 pod 的副本以实现冗余**：这是使用 Deployments 等 pod 组抽象的主要优势。Deployment 可以根据给定的 spec 创建多个 pod。Deployment 将自动确保它创建的 pod 处于在线状态，并将自动替换任何失败的 pod。

+   **简单的升级和回滚**：Kubernetes 提供了不同的策略，你可以使用这些策略来升级你的应用程序，以及回滚版本。这很重要，因为在现代软件开发中，软件经常是迭代开发的，更新频繁。升级可以改变部署规范中的任何内容。它可以是标签或任何其他字段的更新，镜像版本的升级，对其嵌入式容器的更新等等。

让我们来看一下样本部署规范的一些值得注意的方面：

k8s-for-beginners-deploy.yaml

```
apiVersion: apps/v1
kind: Deployment
metadata:
  name: k8s-for-beginners
spec:
  replicas: 3
  selector:
    matchLabels:
      tier: frontend
  template:
    metadata:
      labels:
        tier: frontend
    spec:
      containers:
      - name: k8s-for-beginners
        image: packtworkshops/the-kubernetes-workshop:k8s-for-          beginners
```

除了将 pod 规范包装为 "template"，部署还必须指定其种类（`Deployment`），以及 API 版本（`apps/v1`）。

注意

出于某些历史原因，规范名称 `apiVersion` 仍在使用。但从技术上讲，它实际上意味着 `apiGroupVersion`。在前面的部署示例中，它属于 `apps` 组，版本为 `v1`。

在部署规范中，`replicas` 字段指示 Kubernetes 使用在 `template` 字段中定义的 pod 规范启动三个 pod。`selector` 字段扮演了与服务案例中相同的角色 - 它旨在以一种松散耦合的方式将部署对象与特定的 pod 关联起来。如果你想要将任何现有的 pod 纳入新部署的管理，这将特别有用。

在部署或其他类似的 API 对象中定义的副本数量代表了持续运行的 pod 数量的期望状态。如果其中一些 pod 因某些意外原因而失败，Kubernetes 将自动检测到并创建相应数量的 pod 来替代它们。我们将在接下来的练习中探讨这一点。

我们将在接下来的练习中看到部署的实际操作。

## 练习 2.04：扩展 Kubernetes 应用程序

在 Kubernetes 中，通过更新部署规范的 `replicas` 字段，很容易增加运行应用程序的副本数量。在这个练习中，我们将尝试如何扩展 Kubernetes 应用程序的规模。按照以下步骤完成这个练习：

1.  使用这里显示的内容创建一个名为 `k8s-for-beginners-deploy.yaml` 的文件：

```
apiVersion: apps/v1
kind: Deployment
metadata:
  name: k8s-for-beginners
spec:
  replicas: 3
  selector:
    matchLabels:
      tier: frontend
  template:
    metadata:
      labels:
        tier: frontend
    spec:
      containers:
      - name: k8s-for-beginners
        image: packtworkshops/the-kubernetes-workshop:k8s-for-          beginners
```

如果你仔细看，你会发现这个部署规范在很大程度上基于之前练习中的 pod 规范（`k8s-for-beginners-pod1.yaml`），你可以在 `template` 字段下看到。

1.  接下来，我们可以使用 kubectl 来创建部署：

```
kubectl apply -f k8s-for-beginners-deploy.yaml
```

您应该会看到以下输出：

```
deployment.apps/k8s-for-beginners created
```

1.  鉴于部署已经成功创建，我们可以使用以下命令来显示所有部署的状态，比如它们的名称、运行的 pod 等等：

```
kubectl get deploy
```

您应该会得到以下响应：

```
NAME                   READY   UP-TO-DATE   AVAILABLE    AGE
k8s-for-beginners      3/3     3            3            41s
```

注意

如前面的命令所示，我们使用的是`deploy`而不是`deployment`。这两者都可以使用，`deploy`是`deployment`的允许的简称。您可以在此链接找到一些常用的简称列表：[`kubernetes.io/docs/reference/kubectl/overview/#resource-types`](https://kubernetes.io/docs/reference/kubectl/overview/#resource-types)。

您也可以通过运行`kubectl api-resources`来查看短名称，而不指定资源类型。

1.  我们在上一个练习中创建的名为`k8s-for-beginners`的 pod 存在。为了确保我们只看到由部署管理的 pod，让我们删除旧的 pod：

```
kubectl delete pod k8s-for-beginners
```

您应该会看到以下响应：

```
pod "k8s-for-beginners" deleted
```

1.  现在，获取所有的 pod 列表：

```
kubectl get pod
```

您应该会看到以下响应：

![图 2.14：获取 pod 列表](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/k8s-ws/img/B14870_02_14.jpg)

图 2.14：获取 pod 列表

部署已经创建了三个 pod，并且它们的标签（在*步骤 1*中指定的`labels`字段）恰好与我们在上一节中创建的 Service 匹配。那么，如果我们尝试访问 Service 会发生什么呢？网络流量会聪明地路由到这三个新的 pod 吗？让我们来测试一下。

1.  为了查看流量是如何分配到这三个 pod 的，我们可以通过在 Bash 的`for`循环中运行`curl`命令来模拟一系列连续的请求到 Service 端点，如下所示：

```
for i in $(seq 1 30); do curl <minikube vm ip>:<service node port>; done
```

注意

在这个命令中，如果您正在运行相同的 Minikube 实例，请使用与上一个练习中相同的 IP 和端口。如果您重新启动了 Minikube 或进行了其他更改，请按照上一个练习的*步骤 9*获取您的 Minikube 集群的正确 IP。

一旦您使用正确的 IP 和端口运行了命令，您应该会看到以下输出：

![图 2.15：重复访问我们的应用](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/k8s-ws/img/B14870_02_15.jpg)

图 2.15：重复访问我们的应用

从输出中，我们可以看出所有 30 个请求都得到了预期的响应。

1.  您可以运行`kubectl logs <pod name>`来检查每个 pod 的日志。让我们再进一步，找出每个 pod 实际响应的确切请求数，这可能有助于我们找出流量是否均匀分布。为此，我们可以将每个 pod 的日志传输到`wc`命令中以获取行数：

```
kubectl logs <pod name> | wc -l
```

运行上述命令三次，复制您获得的 pod 名称，如*图 2.16*所示：

![图 2.16：获取运行我们应用程序的三个 pod 副本的日志](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/k8s-ws/img/B14870_02_16.jpg)

图 2.16：获取运行我们应用程序的三个 pod 副本的日志

结果显示，三个 pod 分别处理了`9`、`10`和`11`个请求。由于样本量较小，分布并不绝对均匀（即每个`10`），但足以表明服务使用的默认轮询分发策略。

注意

您可以通过查看官方文档了解 kube-proxy 如何利用 iptables 执行内部负载平衡：[`kubernetes.io/docs/concepts/services-networking/service/#proxy-mode-iptables`](https://kubernetes.io/docs/concepts/services-networking/service/#proxy-mode-iptables)。

1.  接下来，让我们学习如何扩展部署。有两种方法可以实现这一点：一种方法是修改部署的 YAML 配置，我们可以将`replicas`的值设置为另一个数字（例如`5`），另一种方法是使用`kubectl scale`命令，如下所示：

```
kubectl scale deploy k8s-for-beginners --replicas=5
```

您应该会看到以下响应：

```
deployment.apps/k8s-for-beginners scaled
```

1.  让我们验证一下是否有五个 pod 在运行：

```
kubectl get pod
```

您应该会看到类似以下的响应：

![图 2.17：获取 pod 列表](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/k8s-ws/img/B14870_02_17.jpg)

图 2.17：获取 pod 列表

输出显示现有的三个 pod 被保留，另外创建了两个新的 pod。

1.  同样，您也可以指定小于当前数量的副本。在我们的示例中，假设我们想将副本数量缩减到`2`。此命令如下所示：

```
kubectl scale deploy k8s-for-beginners --replicas=2
```

您应该会看到以下响应：

```
deployment.apps/k8s-for-beginners scaled
```

1.  现在，让我们验证一下 pod 的数量：

```
kubectl get pod
```

您应该会看到类似以下的响应：

![图 2.18：获取 pod 列表](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/k8s-ws/img/B14870_02_18.jpg)

图 2.18：获取 pod 列表

如前面的截图所示，有两个 pod，它们都按预期运行。因此，在 Kubernetes 术语中，我们可以说，“部署处于期望的状态”。

1.  我们可以运行以下命令来验证这一点：

```
kubectl get deploy
```

你应该看到以下响应：

```
NAME                   READY    UP-TO-DATE   AVAILABLE    AGE
k8s-for-beginners      2/2      2            2           19m
```

1.  现在，让我们看看如果我们删除两个 pod 中的一个会发生什么：

```
kubectl delete pod <pod name>
```

你应该得到以下响应：

```
pod "k8s-for-beginners-66644bb776-7j9mw" deleted
```

1.  检查 pod 的状态以查看发生了什么：

```
kubectl get pod
```

你应该看到以下响应：

![图 2.19：获取 pod 列表](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/k8s-ws/img/B14870_02_19.jpg)

图 2.19：获取 pod 列表

我们可以看到仍然有两个 pod。从输出中值得注意的是，第一个 pod 的名称与*图 2.18*中的第二个 pod 的名称相同（这是未被删除的那个），但是突出显示的 pod 名称与*图 2.18*中的任何一个 pod 的名称都不同。这表明突出显示的那个是新创建的用来替换已删除的 pod。部署创建了一个新的 pod，以使运行中的 pod 数量满足部署的期望状态。

在这个练习中，我们学习了如何扩展部署的规模。您可以以相同的方式扩展其他类似的 Kubernetes 对象，例如 DaemonSets 和 StatefulSets。此外，对于这样的对象，Kubernetes 将尝试自动恢复失败的 pod。

# Pod 生命周期和 Kubernetes 组件

本章的前几节简要描述了 Kubernetes 组件以及它们如何在内部相互工作。另一方面，我们还演示了如何使用一些 Kubernetes API 对象（Pods、Services 和 Deployments）来组合您的应用程序。

但是 Kubernetes API 对象如何由不同的 Kubernetes 组件管理呢？让我们以 pod 为例。其生命周期可以如下所示：

![图 2.20：创建 pod 的过程](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/k8s-ws/img/B14870_02_20.jpg)

图 2.20：创建 pod 的过程

整个过程可以分解如下：

1.  用户通过向 Kubernetes API 服务器发送部署 Deployment YAML 清单来部署应用程序。API 服务器验证请求并检查其是否有效。如果有效，它将持久化部署 API 对象到其后端数据存储（etcd）。

注意

对于通过修改 API 对象演变的任何步骤，etcd 和 API 服务器之间必须发生交互，因此我们不会将交互列为额外的步骤。

1.  到目前为止，pod 还没有被创建。控制器管理器从 API 服务器那里收到通知，部署已经被创建。

1.  然后，控制器管理器会检查所需数量的副本 pod 是否已经在运行。

1.  如果正在运行的 Pod 数量不足，它会创建适当数量的 Pod。创建 Pod 是通过向 API 服务器发送具有 Pod 规范的请求来完成的。这与用户应用部署 YAML 的方式非常相似，但主要区别在于这是以编程方式在控制器管理器内部发生的。

1.  尽管 Pod 已经被创建，但它们只是存储在 etcd 中的一些 API 对象。现在，调度器从 API 服务器那里收到通知，称新的 Pod 已被创建，但尚未分配节点来运行它们。

1.  调度器检查资源使用情况，以及现有的 Pod 分配情况，然后计算最适合每个新 Pod 的节点。在这一步结束时，调度器通过将 Pod 的`nodeName`规范设置为所选节点，向 API 服务器发送更新请求。

1.  到目前为止，Pod 已被分配到适当的节点上运行。然而，没有运行实际的容器。换句话说，应用程序还没有运行。每个 kubelet（运行在不同的工作节点上）都会收到通知，指示某些 Pod 应该被运行。然后，每个 kubelet 将检查将要运行的 Pod 是否已被分配到 kubelet 正在运行的节点。

1.  一旦 kubelet 确定一个 Pod 应该在其节点上，它会调用底层的容器运行时（例如 Docker、containerd 或 cri-o）在主机上启动容器。一旦容器启动，kubelet 负责向 API 服务器报告其状态。

有了这个基本流程，现在你应该对以下问题的答案有一个模糊的理解：

+   谁负责创建 Pod？创建后 Pod 的状态是什么？

+   谁负责放置 Pod？放置后 Pod 的状态是什么？

+   谁启动具体的容器？

+   谁负责整体消息传递过程，以确保所有组件协同工作？

在接下来的练习中，我们将使用一系列具体的实验来帮助您巩固这一理解。这将让您看到事情在实践中是如何运作的。

## 练习 2.05：Kubernetes 如何管理 Pod 的生命周期

由于 Kubernetes 集群包括多个组件，并且每个组件同时工作，通常很难知道每个 pod 生命周期的每个阶段发生了什么。为了解决这个问题，我们将使用电影剪辑技术来“以慢动作播放整个生命周期”，以便观察每个阶段。我们将关闭主平面组件，然后尝试创建一个 pod。然后，我们将响应我们看到的错误，并逐步将每个组件逐个上线。这将使我们能够放慢速度，逐步检查 pod 创建过程的每个阶段。按照以下步骤完成此练习：

1.  首先，让我们使用以下命令删除之前创建的部署和服务：

```
kubectl delete deploy k8s-for-beginners && kubectl delete service k8s-for-beginners
```

您应该看到以下响应：

```
deployment.apps "k8s-for-beginners" deleted
service "k8s-for-beginners" deleted
```

1.  准备两个终端会话：一个（主机终端）用于在主机上运行命令，另一个（Minikube 终端）用于通过 SSH 在 Minikube VM 内部传递命令。因此，您的 Minikube 会话将像这样启动：

```
minikube ssh
```

您将看到以下输出：

![图 2.21：通过 SSH 访问 Minikube VM](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/k8s-ws/img/B14870_02_21.jpg)

图 2.21：通过 SSH 访问 Minikube VM

注意

所有`kubectl`命令都应在主机终端会话中运行，而所有`docker`命令都应在 Minikube 终端会话中运行。

1.  在 Minikube 会话中，清理所有已停止的 Docker 容器：

```
docker rm $(docker ps -a -q)
```

您应该看到以下输出：

![图 2.22：清理所有已停止的 Docker 容器](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/k8s-ws/img/B14870_02_22.jpg)

图 2.22：清理所有已停止的 Docker 容器

您可能会看到一些错误消息，比如“您无法删除正在运行的容器...”。这是因为前面的`docker rm`命令针对所有容器（`docker ps -a -q`）运行，但不会停止任何正在运行的容器。

1.  在 Minikube 会话中，通过运行以下命令停止 kubelet：

```
sudo systemctl stop kubelet
```

此命令在成功执行后不会显示任何响应。

注意

在本练习中，我们将手动停止和启动其他由 kubelet 在 Minikube 环境中管理的 Kubernetes 组件，例如 API 服务器。因此，在本练习中，需要先停止 kubelet；否则，kubelet 将自动重新启动其管理的组件。

请注意，在典型的生产环境中，与 Minikube 不同，不需要在主节点上运行 kubelet 来管理主平面组件；kubelet 只是工作节点上的一个强制组件。

1.  30 秒后，在主机终端会话中运行以下命令来检查集群的状态：

```
kubectl get node
```

您应该看到以下响应：

```
NAME         STATUS       ROLES      AGE       VERSION
minikube     NotReady     master     32h       v1.16.2
```

预计`minikube`节点的状态将更改为`NotReady`，因为 kubelet 已停止。

1.  在您的 Minikube 会话中，停止`kube-scheduler`、`kube-controller-manager`和`kube-apiserver`。正如我们之前所看到的，所有这些都作为 Docker 容器运行。因此，您可以依次使用以下命令：

```
docker stop $(docker ps | grep kube-scheduler | grep -v pause | awk '{print $1}')
docker stop $(docker ps | grep kube-controller-manager | grep -v pause | awk '{print $1}')
docker stop $(docker ps | grep kube-apiserver | grep -v pause | awk '{print $1}')
```

您应该看到以下响应：

![图 2.23：停止运行 Kubernetes 组件的容器](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/k8s-ws/img/B14870_02_23.jpg)

图 2.23：停止运行 Kubernetes 组件的容器

正如我们在*Kubernetes 组件概述*部分所解释的，`grep -v pause | awk '{print $1}'`命令可以获取所需 Docker 容器的确切容器 ID（`$1` = 第一列）。然后，`docker pause`命令可以暂停正在运行的 Docker 容器。

现在，三个主要的 Kubernetes 组件已经停止。

1.  现在，您需要在主机机器上创建一个部署规范。创建一个名为`k8s-for-beginners-deploy2.yaml`的文件，内容如下：

```
apiVersion: apps/v1
kind: Deployment
metadata:
  name: k8s-for-beginners
spec:
  replicas: 1
  selector:
    matchLabels:
      tier: frontend
  template:
    metadata:
      labels:
        tier: frontend
    spec:
      containers:
      - name: k8s-for-beginners
        image: packtworkshops/the-kubernetes-workshop:k8s-for-          beginners
```

1.  尝试在主机会话中运行以下命令来创建部署：

```
kubectl apply -f k8s-for-beginners-deploy2.yaml
```

您应该看到类似于以下内容的响应：

![图 2.24：尝试创建新的部署](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/k8s-ws/img/B14870_02_24.jpg)

图 2.24：尝试创建新的部署

毫不奇怪，我们收到了网络超时错误，因为我们有意停止了 Kubernetes API 服务器。如果 API 服务器宕机，您将无法运行任何`kubectl`命令或使用任何依赖 API 请求的等效工具（例如 Kubernetes 仪表板）：

```
The connection to the server 192.168.99.100:8443 was refused – did you specify the right host or port?
```

1.  让我们看看如果重新启动 API 服务器并尝试再次创建部署会发生什么。通过在 Minikube 会话中运行以下命令来重新启动 API 服务器容器：

```
docker start $(docker ps -a | grep kube-apiserver | grep -v pause | awk '{print $1}')
```

该命令尝试查找携带 API 服务器的停止容器的容器 ID，然后启动它。您应该得到类似于这样的响应：

```
9e1cf098b67c
```

1.  等待 10 秒。然后，检查 API 服务器是否在线。您可以在主机会话中运行任何简单的 kubectl 命令来进行此操作。让我们尝试通过运行以下命令来获取节点列表：

```
kubectl get node
```

您应该看到以下响应：

```
NAME         STATUS       ROLES      AGE       VERSION
minikube     NotReady     master     32h       v1.16.2
```

正如您所看到的，我们能够得到一个没有错误的响应。

1.  让我们再次尝试创建部署：

```
kubectl apply -f k8s-for-beginners-deploy2.yaml
```

您应该看到以下响应：

```
deployment.apps/k8s-for-beginners created
```

1.  通过运行以下命令来检查部署是否已成功创建：

```
kubectl get deploy
```

您应该看到以下响应：

```
NAME               READY     UP-TO-DATE    AVAILABLE   AGE
k8s-for-beginners  0/1       0             0           113s
```

从前面的截图中，似乎有些问题，因为在`READY`列中，我们可以看到`0/1`，这表明与此部署关联的 pod 数量为 0，而期望的数量是 1（我们在部署规范中指定的`replicas`字段）。

1.  让我们检查所有在线的 pod：

```
kubectl get pod
```

您应该看到以下响应：

```
No resources found in default namespace.
```

我们可以看到我们的 pod 尚未创建。这是因为 Kubernetes API 服务器只创建 API 对象；任何 API 对象的实现都是由其他组件执行的。例如，在部署的情况下，是`kube-controller-manager`创建相应的 pod。

1.  现在，让我们重新启动`kube-controller-manager`。在 Minikube 会话中运行以下命令：

```
docker start $(docker ps -a | grep kube-controller-manager | grep -v pause | awk '{print $1}')
```

您应该看到类似以下的响应：

```
35facb013c8f
```

1.  等待几秒钟后，在主机会话中运行以下命令来检查部署的状态：

```
kubectl get deploy
```

您应该看到以下响应：

```
NAME               READY     UP-TO-DATE    AVAILABLE   AGE
k8s-for-beginners  0/1       1             0           5m24s
```

正如我们所看到的，我们正在寻找的 pod 仍然没有上线。

1.  现在，检查 pod 的状态：

```
kubectl get pod
```

您应该看到以下响应：

![图 2.25：获取 pod 列表](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/k8s-ws/img/B14870_02_25.jpg)

图 2.25：获取 pod 列表

输出与*步骤 15*中的输出不同，因为在这种情况下，一个 pod 是由`kube-controller-manager`创建的。但是，在`STATUS`列下我们可以看到`Pending`。这是因为将 pod 分配给适当的节点不是`kube-controller-manager`的责任；这是`kube-scheduler`的责任。

1.  在启动`kube-scheduler`之前，让我们看一下有关 pod 的一些额外信息：

```
kubectl get pod -o wide
```

您应该看到以下响应：

![图 2.26：获取有关 pod 的更多信息](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/k8s-ws/img/B14870_02_26.jpg)

图 2.26：获取有关 pod 的更多信息

突出显示的`NODE`列表明尚未为此 pod 分配节点。这证明了调度程序没有正常工作，我们知道这是因为我们将其下线。如果调度程序在线，此响应将表明没有地方可以放置此 pod。

注意

您将在*第十七章*，*Kubernetes 中的高级调度*中学到更多关于 pod 调度的知识。

1.  让我们通过在 Minikube 会话中运行以下命令来重新启动`kube-scheduler`：

```
docker start $(docker ps -a | grep kube-scheduler | grep -v pause | awk '{print $1}')
```

您应该看到类似以下的响应：

```
11d8a27e3ee0
```

1.  我们可以通过在主机会话中运行以下命令来验证`kube-scheduler`是否工作：

```
kubectl describe pod k8s-for-beginners-66644bb776-kvwfr
```

请从*步骤 17*中获得响应中的 pod 名称，如*图 2.26*中所示。您应该看到以下输出：

```
Name:         k8s-for-beginners-66644bb776-kvwfr
Namespace:    default
Priority:     0
Node:         <none>
```

我们正在截断输出截图以便更好地展示。请看以下摘录，重点是`Events`部分：

![图 2.27：检查 pod 报告的事件](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/k8s-ws/img/B14870_02_27.jpg)

图 2.27：检查 pod 报告的事件

在`Events`部分，我们可以看到`kube-scheduler`尝试调度，但它报告没有可用的节点。为什么会这样？

这是因为我们之前停止了 kubelet，并且 Minikube 环境是一个单节点集群，因此没有可用的带有运行 kubelet 的节点，可以放置 pod。

1.  让我们通过在 Minikube 会话中运行以下命令来重新启动 kubelet：

```
sudo systemctl start kubelet
```

成功执行后，终端不应该给出任何响应。

1.  在主机终端中，通过在主机会话中运行以下命令来验证部署的状态：

```
kubectl get deploy
```

您应该看到以下响应：

```
NAME               READY     UP-TO-DATE    AVAILABLE   AGE
k8s-for-beginners  1/1       1             1           11m
```

现在，一切看起来都很健康，因为部署在`READY`列下显示`1/1`，这意味着 pod 在线。

1.  同样地，验证 pod 的状态：

```
kubectl get pod -o wide
```

您应该得到类似以下的输出：

![图 2.28：获取有关 pod 的更多信息](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/k8s-ws/img/B14870_02_28.jpg)

图 2.28：获取有关 pod 的更多信息

我们可以看到`STATUS`下是`Running`，并且它已被分配给`minikube`节点。

在这个练习中，我们通过逐个破坏 Kubernetes 组件然后逐个恢复它们来追踪 pod 生命周期的每个阶段。现在，基于我们对这个练习所做的观察，我们对在这个练习之前提出的问题有了更清晰的认识：

+   **步骤 12 – 16**：我们看到在部署的情况下，控制器管理器负责请求创建 pod。

+   **步骤 17 – 19**：调度程序负责选择要放置在 pod 中的节点。它通过将 pod 的`nodeName`规范设置为所需的节点来分配节点。此时，将 pod 关联到节点仅仅发生在 API 对象的级别。

+   **步骤 20 – 22**：kubelet 实际上会启动容器来运行我们的 pod。

在整个 Pod 的生命周期中，Kubernetes 组件通过适当地更新 Pod 的规范来合作。API 服务器作为接受 Pod 更新请求的关键组件，同时向感兴趣的方报告 Pod 的变化。

在接下来的活动中，我们将汇集本章学到的技能，以找出如何从基于容器的环境迁移到 Kubernetes 环境，以便运行我们的应用程序。

## 活动 2.01：在 Kubernetes 中运行 Pageview 应用程序

在*Activity 1.01*中，*创建一个简单的页面计数应用程序*，在上一章中，我们构建了一个名为 Pageview 的 Web 应用程序，并将其连接到了一个 Redis 后端数据存储。所以，这里有一个问题：在不对源代码进行任何更改的情况下，我们能否将基于 Docker 的应用程序迁移到 Kubernetes，并立即享受 Kubernetes 的好处？根据给定的指导方针，在这个活动中尝试一下。

这个活动分为两个部分：在第一部分中，我们将创建一个简单的 Pod，其中包含我们的应用程序，通过一个 Service 暴露给集群外的流量，并连接到另一个作为另一个 Pod 运行的 Redis 数据存储。在第二部分中，我们将将应用程序扩展到三个副本。

**使用 Service 将 Pageview 应用程序连接到 Redis 数据存储**

类似于 Docker 中的`--link`选项，Kubernetes 提供了一个 Service，作为一个抽象层来暴露一个应用程序（比如，一系列带有相同标签集的 Pod）可以在内部或外部访问。例如，正如我们在本章中讨论的那样，前端应用程序可以通过`NodePort` Service 暴露，以便外部用户访问。除此之外，在这个活动中，我们需要定义一个内部 Service，以便将后端应用程序暴露给前端应用程序。按照以下步骤进行：

1.  在*Activity 1.01*中，*创建一个简单的页面计数应用程序*，我们构建了两个 Docker 镜像——一个用于前端 Pageview Web 应用程序，另一个用于后端 Redis 数据存储。您可以使用本章学到的技能将它们迁移到 Kubernetes YAML 中。

1.  为该应用程序创建两个 Pod（每个由一个 Deployment 管理）是不够的。我们还必须创建 Service YAML 来将它们连接在一起。

确保清单中的`targetPort`字段与 Redis 镜像中定义的暴露端口一致，在这种情况下是`6379`。就`port`字段而言，理论上它可以是任何端口，只要它与 Pageview 应用程序中指定的端口一致即可。

这里值得一提的另一件事是 Redis 数据存储的 pod 的`name`字段。这是 Pageview 应用程序源代码中用来引用 Redis 数据存储的符号。

现在，您应该有三个 YAML 文件 - 两个 pod 和一个 Service。使用`kubectl -f <yaml 文件名>`应用它们，然后使用`kubectl get deploy,service`来确保它们被成功创建。

1.  在这个阶段，Pageview 应用程序应该能够正常运行，因为它通过 Service 与 Redis 应用程序连接在一起。然而，Service 只能作为内部连接器工作，以确保它们可以在集群内部相互通信。

要从外部访问 Pageview 应用程序，我们需要定义一个`NodePort` Service。与内部 Service 不同，我们需要明确指定`type`为`NodePort`。

1.  使用`kubectl -f <yaml 文件名>`应用外部 Service YAML。

1.  运行`minikube service <外部 service 名称>`来获取 Service URL。

1.  多次访问 URL，确保 Pageview 数量每次增加一个。

有了这个，我们成功地在 Kubernetes 中运行了 Pageview 应用程序。但是如果 Pageview 应用程序宕机怎么办？尽管 Kubernetes 可以自动创建替代的 pod，但在故障被检测到和新的 pod 准备就绪之间仍然存在停机时间。

一个常见的解决方案是增加应用程序的副本数量，以便只要至少有一个副本在运行，整个应用程序就是可用的。

**在多个副本中运行 Pageview 应用程序**

Pageview 应用程序当然可以使用单个副本运行。然而，在生产环境中，高可用性是必不可少的，并且通过在节点之间维护多个副本来避免单点故障来实现。（这将在接下来的章节中详细介绍。）

在 Kubernetes 中，为了确保应用程序的高可用性，我们可以简单地增加副本数量。按照以下步骤来做：

1.  修改 Pageview YAML 将`replicas`更改为`3`。

1.  通过运行`kubectl apply -f <pageview 应用 yaml>`来应用这些更改。

1.  通过运行`kubectl get pod`，您应该能够看到三个 Pageview pod 正在运行。

1.  使用`minikube service`命令输出中显示的 URL 多次访问。

检查每个 pod 的日志，看看请求是否均匀地分布在三个 pod 之间。

1.  现在，让我们验证 Pageview 应用程序的高可用性。在保持一个健康的 pod 的同时连续终止任意的 pod。您可以通过手动或编写脚本来实现这一点。或者，您可以打开另一个终端，检查 Pageview 应用程序是否始终可访问。

如果您选择编写脚本来终止 pod，您将看到类似以下的结果：

![图 2.29：通过脚本杀死 pod](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/k8s-ws/img/B14870_02_29.jpg)

图 2.29：通过脚本杀死 pod

假设您采用类似的方法并编写脚本来检查应用程序是否在线，您应该会看到类似以下的输出：

![图 2.30：通过脚本重复访问应用程序](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/k8s-ws/img/B14870_02_30.jpg)

图 2.30：通过脚本重复访问应用程序

注

此活动的解决方案可在以下地址找到：[`packt.live/304PEoD`](https://packt.live/304PEoD)。

## Kubernetes 多节点集群优势一览

只有在多节点集群的环境中才能真正体会到 Kubernetes 的优势。本章以单节点集群（Minikube 环境）来演示 Kubernetes 提供的功能，就像本书的许多其他章节一样。然而，在真实的生产环境中，Kubernetes 是部署在多个工作节点和主节点上的。只有这样，您才能确保单个节点的故障不会影响应用程序的一般可用性。可靠性只是多节点 Kubernetes 集群可以为我们带来的众多好处之一。

但等等 - 难道我们不是可以在*不使用 Kubernetes*的情况下实现应用程序并以高可用的方式部署它们吗？这是真的，但通常会伴随着大量的管理麻烦，无论是在管理应用程序还是基础设施方面。例如，在初始部署期间，您可能需要手动干预，以确保所有冗余容器不在同一台机器上运行。在节点故障的情况下，您不仅需要确保新的副本被正确地重新生成，还需要确保新的副本不会落在已经运行现有副本的节点上。这可以通过使用 DevOps 工具或在应用程序端注入逻辑来实现。然而，无论哪种方式都非常复杂。Kubernetes 提供了一个统一的平台，我们可以使用它来通过描述我们想要的高可用特性（Kubernetes 原语（API 对象））将应用程序连接到适当的节点。这种模式使应用程序开发人员的思维得到解放，因为他们只需要考虑如何构建他们的应用程序。Kubernetes 在幕后处理了高可用性所需的功能，如故障检测和恢复。

# 总结

在本章中，我们使用 Minikube 来提供单节点 Kubernetes 集群，并对 Kubernetes 的核心组件以及其关键设计原理进行了高层概述。之后，我们将现有的 Docker 容器迁移到 Kubernetes，并探索了一些基本的 Kubernetes API 对象，如 pod、服务和部署。最后，我们有意破坏了一个 Kubernetes 集群，并逐个恢复了它的组件，这使我们能够了解不同的 Kubernetes 组件是如何协同工作的，以便在节点上启动和运行一个 pod。

在整个本章中，我们使用 kubectl 来管理我们的集群。我们对这个工具进行了快速介绍，但在接下来的章节中，我们将更仔细地了解这个强大的工具，并探索我们可以使用它的各种方式。
