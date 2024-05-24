# Kubernetes DevOps 完全秘籍（一）

> 原文：[`zh.annas-archive.org/md5/2D2322071D8188F9AA9E93F3DAEEBABE`](https://zh.annas-archive.org/md5/2D2322071D8188F9AA9E93F3DAEEBABE)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 前言

Kubernetes 是一个开源的容器编排平台，最初由谷歌开发，并于 2014 年向公众开放。它使得基于容器的复杂分布式系统的部署对开发人员来说更加简单。自诞生以来，社区已经围绕 Kubernetes 构建了一个庞大的生态系统，涵盖了许多开源项目。本书专门设计为快速帮助 Kubernetes 管理员和可靠性工程师找到合适的工具，并快速掌握 Kubernetes。本书涵盖了从在最流行的云和本地解决方案上部署 Kubernetes 集群到帮助您自动化测试并将应用程序移出到生产环境的配方。

*Kubernetes – 一个完整的 DevOps 食谱*为您提供了清晰的，逐步的说明，以成功安装和运行您的私有 Kubernetes 集群。它充满了实用的配方，使您能够使用 Kubernetes 的最新功能以及其他第三方解决方案，并实施它们。

# 本书的受众

本书面向开发人员、IT 专业人员、可靠性工程师和 DevOps 团队和工程师，他们希望使用 Kubernetes 在其组织中管理、扩展和编排应用程序。需要对 Linux、Kubernetes 和容器化有基本的了解。

# 本书涵盖的内容

第一章，*构建生产就绪的 Kubernetes 集群*，教你如何在不同的公共云或本地配置 Kubernetes 服务，使用当今流行的选项。

第二章，*在 Kubernetes 上操作应用程序*，教你如何在 Kubernetes 上使用最流行的生命周期管理选项部署 DevOps 工具和持续集成/持续部署（CI/CD）基础设施。

第三章，*构建 CI/CD 流水线*，教你如何从开发到生产构建、推送和部署应用程序，以及在过程中检测错误、反模式和许可问题的方法。

第四章，*在 DevOps 中自动化测试*，教你如何在 DevOps 工作流中自动化测试，加快生产时间，减少交付风险，并使用 Kubernetes 中已知的测试自动化工具检测服务异常。

第五章，*为有状态的工作负载做准备*，教您如何保护应用程序的状态免受节点或应用程序故障的影响，以及如何共享数据和重新附加卷。

第六章，*灾难恢复和备份*，教您如何处理备份和灾难恢复方案，以保持应用程序在生产中高可用，并在云提供商或基本 Kubernetes 节点故障期间快速恢复服务。

第七章，*扩展和升级应用程序*，教您如何在 Kubernetes 上动态扩展容器化服务，以处理服务的变化流量需求。

第八章，*Kubernetes 上的可观察性和监控*，教您如何监控性能分析的指标，以及如何监控和管理 Kubernetes 资源的实时成本。

第九章，*保护应用程序和集群*，教您如何将 DevSecOps 构建到 CI/CD 流水线中，检测性能分析的指标，并安全地管理秘密和凭据。

第十章，*Kubernetes 上的日志记录*，教您如何设置集群以摄取日志，以及如何使用自管理和托管解决方案查看日志。

# 为了充分利用本书

要使用本书，您需要访问计算机、服务器或云服务提供商服务，您可以在其中提供虚拟机实例。为了设置实验室环境，您可能还需要更大的云实例，这将需要您启用计费。

我们假设您正在使用 Ubuntu 主机（在撰写本文时为 18.04，代号 Bionic Beaver）；本书提供了 Ubuntu 环境的步骤。

| 本书涵盖的软件/硬件 | 操作系统要求 |
| --- | --- |
| GitLab、Jenkins X、OpenShift、Rancher、kops、cURL、Python、Vim 或 Nano、kubectl、helm | Ubuntu/Windows/macOS |

您将需要 AWS、GCP 和 Azure 凭据来执行本书中的一些示例。

**如果您使用本书的数字版本，我们建议您自己输入代码或通过 GitHub 存储库访问代码（链接在下一节中提供）。这样做将有助于避免与复制/粘贴代码相关的任何潜在错误。**

## 下载示例代码文件

您可以从[www.packt.com](http://www.packt.com)的帐户中下载本书的示例代码文件。如果您在其他地方购买了本书，您可以访问[www.packtpub.com/support](https://www.packtpub.com/support)并注册，以便文件直接发送到您的邮箱。

您可以按照以下步骤下载代码文件：

1.  登录或注册[www.packt.com](http://www.packt.com)。

1.  选择支持选项卡。

1.  单击代码下载。

1.  在搜索框中输入书名，并按照屏幕上的说明操作。

下载文件后，请确保使用以下最新版本解压或提取文件夹：

+   Windows 上的 WinRAR/7-Zip

+   Mac 上的 Zipeg/iZip/UnRarX

+   Linux 上的 7-Zip/PeaZip

本书的代码包也托管在 GitHub 上，网址为[`github.com/k8sdevopscookbook/src`](https://github.com/k8sdevopscookbook/src)和[`github.com/PacktPublishing/Kubernetes-A-Complete-DevOps-Cookbook`](https://github.com/PacktPublishing/Kubernetes-A-Complete-DevOps-Cookbook)。如果代码有更新，将在现有的 GitHub 存储库上进行更新。

我们还有其他代码包，来自我们丰富的图书和视频目录，可在[`github.com/PacktPublishing/`](https://github.com/PacktPublishing/)上找到。去看看吧！

## 下载彩色图片

我们还提供了一个 PDF 文件，其中包含本书中使用的屏幕截图/图表的彩色图片。您可以在这里下载：[`www.packtpub.com/sites/default/files/downloads/9781838828042_ColorImages.pdf`](http://www.packtpub.com/sites/default/files/downloads/9781838828042_ColorImages.pdf)。

## 代码实例

访问以下链接，查看代码运行的视频：

[`bit.ly/2U0Cm8x`](http://bit.ly/2U0Cm8x)

## 使用的约定

本书中使用了许多文本约定。

`CodeInText`：表示文本中的代码词、数据库表名、文件夹名、文件名、文件扩展名、路径名、虚拟 URL、用户输入和 Twitter 句柄。例如："将下载的`WebStorm-10*.dmg`磁盘映像文件挂载为系统中的另一个磁盘。"

一块代码设置如下：

```
html, body, #map {
 height: 100%; 
 margin: 0;
 padding: 0
}
```

当我们希望引起您对代码块的特定部分的注意时，相关行或项目将以粗体显示：

```
[default]
exten => s,1,Dial(Zap/1|30)
exten => s,2,Voicemail(u100)
exten => s,102,Voicemail(b100)
exten => i,1,Voicemail(s0)
```

任何命令行输入或输出都以以下方式编写：

```
$ mkdir css
$ cd css
```

**粗体**：表示一个新术语，一个重要词，或者您在屏幕上看到的词。例如，菜单或对话框中的单词会以这种形式出现在文本中。这是一个例子：“从管理面板中选择系统信息。”

警告或重要说明会出现在这样的形式中。提示和技巧会出现在这样的形式中。

# 章节

在这本书中，您会经常看到几个标题（*准备工作*，*如何做*，*它是如何工作的*，*还有更多*，和*另请参阅*）。

为了清晰地说明如何完成一个食谱，使用以下章节。

## 准备工作

这一部分告诉您在食谱中可以期待什么，并描述如何设置任何所需的软件或初步设置。

## 如何做…

这一部分包含了遵循食谱所需的步骤。

## 它是如何工作的…

这一部分通常包括了对前一部分发生的事情的详细解释。

## 还有更多…

这一部分包括了有关食谱的额外信息，以使您对食谱更加了解。

## 另请参阅

这一部分为食谱提供了其他有用信息的链接。


# 第一章：构建生产就绪的 Kubernetes 集群

本章提出了最常用的部署方法，这些方法在流行的云服务以及本地都有使用，尽管您肯定会在互联网上找到其他教程，解释其他方法。本章解释了托管/托管云服务与自我管理云或本地 Kubernetes 部署之间的区别，以及一个供应商相对于另一个的优势。

在本章中，我们将涵盖以下示例：

+   在亚马逊网络服务上配置 Kubernetes 集群

+   在谷歌云平台上配置 Kubernetes 集群

+   在 Microsoft Azure 上配置 Kubernetes 集群

+   在阿里云上配置 Kubernetes 集群

+   使用 Rancher 配置和管理 Kubernetes 集群

+   配置 Red Hat OpenShift

+   使用 Ansible 配置 Kubernetes 集群

+   故障排除安装问题

# 技术要求

建议您对 Linux 容器和 Kubernetes 有基本的了解。为了准备您的 Kubernetes 集群，建议使用 Linux 主机。如果您的工作站基于 Windows，则建议您使用**Windows 子系统用于 Linux**（**WSL**）。WSL 在 Windows 上提供了一个 Linux 命令行，并允许您在 Windows 上运行 ELF64 Linux 二进制文件。

始终使用相同的环境进行开发是一个良好的实践（这意味着相同的发行版和相同的版本），就像将在生产中使用的一样。这将避免意外的惊喜，比如**它在我的机器上运行**（**IWOMM**）。如果您的工作站使用不同的操作系统，另一个很好的方法是在您的工作站上设置一个虚拟机。VirtualBox（[`www.virtualbox.org/`](https://www.virtualbox.org/)）是一个在 Windows、Linux 和 macOS 上运行的免费开源的虚拟化程序。

在本章中，我们假设您正在使用 Ubuntu 主机（18.04，在撰写时的代号为 Bionic Beaver）。由于本章中的所有示例都将部署和运行在云实例上，因此没有特定的硬件要求。以下是在本地主机上完成示例所需的软件包列表：

+   cURL

+   Python

+   Vim 或 Nano（或您喜欢的文本编辑器）

# 在亚马逊网络服务上配置 Kubernetes 集群

本节中的操作将带您了解如何获得一个功能齐全的 Kubernetes 集群，具有完全可定制的主节点和工作节点，您可以在以下章节或生产中使用。

在本节中，我们将涵盖 Amazon EC2 和 Amazon EKS 的操作步骤，以便我们可以在**Amazon Web Services**（**AWS**）上运行 Kubernetes。

## 准备工作

这里提到的所有操作都需要一个 AWS 账户和一个具有使用相关服务权限的 AWS 用户。如果您没有，请访问[`aws.amazon.com/account/`](https://aws.amazon.com/account/)并创建一个。

当在 AWS 上运行 Kubernetes 时，AWS 提供了两个主要选项。如果您想完全管理部署并具有特定的强大实例要求，可以考虑使用**Amazon Elastic Compute Cloud**（**Amazon EC2**）。否则，强烈建议考虑使用**Amazon Elastic Container Service for Kubernetes**（**Amazon EKS**）等托管服务。

## 如何做…

根据您想要使用 AWS EC2 服务还是 EKS，您可以按照以下步骤使用 kops 或 eksctl 工具来启动和运行您的集群：

+   安装命令行工具以配置 AWS 服务

+   安装 kops 以配置 Kubernetes 集群

+   在 Amazon EC2 上配置 Kubernetes 集群 provision a Kubernetes cluster on Amazon EC2.

+   在 Amazon EKS 上配置托管的 Kubernetes 集群

### 安装命令行工具以配置 AWS 服务

在这个操作中，我们将获取 AWS **命令行界面**（**CLI**）`awscli`和 Amazon EKS CLI `eksctl`以访问和配置 AWS 服务。

让我们执行以下步骤：

1.  在您的工作站上安装`awscli`：

```
$ sudo apt-get update && sudo apt-get install awscli
```

1.  配置 AWS CLI 以使用您的访问密钥 ID 和秘密访问密钥：

```
$ aws configure
```

1.  下载并安装 Amazon EKS 命令行界面`eksctl`：

```
$ curl --silent --location "https://github.com/weaveworks/eksctl/releases/download/latest_release/eksctl_$(uname -s)_amd64.tar.gz" | tar xz -C /tmp
$ sudo mv /tmp/eksctl /usr/local/bin
```

1.  验证其版本并确保`eksctl`已安装：

```
$ eksctl version
```

为了能够执行以下操作，`eksctl`版本应为`0.13.0`或更高。

### 安装 kops 以配置 Kubernetes 集群

在这个操作中，我们将获取 Kubernetes 操作工具`kops`和 Kubernetes 命令行工具`kubectl`，以便配置和管理 Kubernetes 集群。

让我们执行以下步骤：

1.  下载并安装 Kubernetes 操作工具`kops`：

```
$ curl -LO https://github.com/kubernetes/kops/releases/download/$(curl -s https://api.github.com/repos/kubernetes/kops/releases/latest | grep tag_name | cut -d '"' -f 4)/kops-linux-amd64
$ chmod +x kops-linux-amd64 && sudo mv kops-linux-amd64 /usr/local/bin/kops
```

1.  运行以下命令以确保`kops`已安装并确认版本为`1.15.0`或更高：

```
$ kops version
```

1.  下载并安装 Kubernetes 命令行工具`kubectl`：

```
$ curl -LO https://storage.googleapis.com/kubernetes-release/release/$(curl -s https://storage.googleapis.com/kubernetes-release/release/stable.txt)/bin/linux/amd64/kubectl
$ chmod +x ./kubectl && sudo mv ./kubectl /usr/local/bin/kubectl
```

1.  验证其版本并确保`kubectl`已安装：

```
$ kubectl version --short
```

为了能够执行以下操作，`kubectl`版本应该是`v1.15`或更高。

### 在 Amazon EC2 上创建一个 Kubernetes 集群

这个步骤将带您完成如何获得一个完全可定制的主节点和工作节点的完全功能的 Kubernetes 集群，您可以在后续章节或生产中使用。

让我们执行以下步骤：

1.  为您的集群创建一个域。

按照云管理最佳实践，最好使用子域名，并使用逻辑和有效的 DNS 名称来划分您的集群，以便`kops`成功地发现它们。

例如，我将使用`k8s.containerized.me`子域作为我们的托管区域。此外，如果您的域名是在 Amazon Route 53 之外的注册商注册的，您必须更新注册商的名称服务器，并为托管区域添加 Route 53 NS 记录到您的注册商的 DNS 记录中：

```
$ aws route53 create-hosted-zone --name k8s.containerized.me \
--caller-reference k8s-devops-cookbook \
--hosted-zone-config Comment="Hosted Zone for my K8s Cluster" 
```

1.  创建一个 S3 存储桶，用于存储 Kubernetes 配置和集群状态。在我们的示例中，我们将使用`s3.k8s.containerized.me`作为我们的存储桶名称：

```
$ aws s3api create-bucket --bucket s3.k8s.containerized.me \
--region us-east-1
```

1.  通过列出可用的存储桶来确认您的 S3 存储桶：

```
$ aws s3 ls
2019-07-21 22:02:58 s3.k8s.containerized.me
```

1.  启用存储桶版本控制：

```
$ aws s3api put-bucket-versioning --bucket s3.k8s.containerized.me \
--versioning-configuration Status=Enabled
```

1.  设置`kops`的环境参数，以便您可以默认使用位置：

```
$ export KOPS_CLUSTER_NAME=useast1.k8s.containerized.me
$ export KOPS_STATE_STORE=s3://s3.k8s.containerized.me
```

1.  如果您还没有创建 SSH 密钥，请创建一个：

```
$ ssh-keygen -t rsa
```

1.  使用您希望主节点运行的区域列表创建集群配置：

```
$ kops create cluster --node-count=6 --node-size=t3.large \
 --zones=us-east-1a,us-east-1b,us-east-1c \
 --master-size=t3.large \
 --master-zones=us-east-1a,us-east-1b,us-east-1c
```

1.  创建集群：

```
$ kops update cluster --name ${KOPS_CLUSTER_NAME} --yes
```

1.  等待几分钟，直到节点启动并验证：

```
$ kops validate cluster
```

1.  现在，您可以使用`kubectl`来管理您的集群：

```
$ kubectl cluster-info
```

默认情况下，`kops`在`~/.kube/config`下创建和导出 Kubernetes 配置。因此，连接集群使用`kubectl`不需要额外的步骤。

### 在 Amazon EKS 上创建托管的 Kubernetes 集群

执行以下步骤，在 Amazon EKS 上使用`eksctl`启动和运行您的托管 Kubernetes 服务集群：

1.  使用默认设置创建一个集群：

```
$ eksctl create cluster
...
[√] EKS cluster "great-outfit-123" in "us-west-2" region is ready
```

默认情况下，`eksctl`使用 AWS EKS AMI 在`us-west-2`地区部署一个带有两个`m5.large`实例的集群。`eksctl`在`~/.kube/config`下创建和导出 Kubernetes 配置。因此，连接集群使用`kubectl`不需要额外的步骤。

1.  确认集群信息和工作节点：

```
$ kubectl cluster-info && kubectl get nodes
Kubernetes master is running at https://gr7.us-west-2.eks.amazonaws.com
CoreDNS is running at https://gr7.us-west-2.eks.amazonaws.com/api/v1/namespaces/kube-system/services/kube-dns:dns/proxy
NAME                                  STATUS ROLES  AGE   VERSION
ip-1-2-3-4.us-west-2.compute.internal Ready  <none> 5m42s v1.13.8-eks-cd3eb0
ip-1-2-3-4.us-west-2.compute.internal Ready  <none> 5m40s v1.13.8-eks-cd3eb0
```

现在，您已经有一个运行中的双节点 Amazon EKS 集群。

## 工作原理...

在亚马逊 EC2 上的第一个配方向您展示了如何提供多个可以在主节点故障以及单个 AZ 故障中生存的主节点副本。虽然与亚马逊 EKS 的第二个配方中具有多 AZ 支持相似，但在 EC2 上的集群给您更高的灵活性。当您使用亚马逊 EKS 时，它为每个集群运行一个单租户 Kubernetes 控制平面，控制平面由至少两个 API 服务器节点和三个`etcd`节点组成，这些节点跨越区域内的三个 AZ 运行。

让我们看看我们在第 7 步中使用的集群选项，使用 `kops create cluster` 命令：

+   `--node-count=3` 设置要创建的节点数。在我们的示例中，这是 `6`。这个配置将在定义的每个区域部署两个节点，使用`--zones=us-east-1a,us-east-1b,us-east-1c`，总共有三个主节点和六个工作节点。

+   `--node-size` 和 `--master-size` 设置了工作节点和主节点的实例大小。在我们的示例中，工作节点使用 `t2.medium`，主节点使用 `t2.large`。对于更大的集群，建议工作节点使用 `t2.large`。

+   `--zones` 和 `--master-zones` 设置了集群将在其中运行的区域。在我们的示例中，我们使用了三个区域，分别是 `us-east-1a`，`us-east-1b`，和 `us-east-1c`。

有关额外区域信息，请查看*另请参阅* 部分中的 AWS 全球基础设施链接。

AWS 集群不能跨多个区域，所有已定义的主节点和工作节点的区域都应该在同一个区域内。

在部署多主节点集群时，应创建奇数个主实例。还要记住，Kubernetes 依赖于 etcd，一个分布式键/值存储。etcd quorum 要求超过 51%的节点随时可用。因此，有三个主节点时，我们的控制平面只能在单个主节点或 AZ 故障时生存。如果需要处理更多情况，需要考虑增加主实例的数量。

## 还有更多...

还有以下信息也很有用：

+   使用 AWS Shell

+   使用基于 gossip 的集群

+   在 S3 存储桶中使用不同的区域

+   编辑集群配置

+   删除您的集群

+   使用亚马逊 EKS 仪表板来提供 EKS 集群

+   部署 Kubernetes 仪表板

### 使用 AWS Shell

在这里值得一提的另一个有用工具是`aws-shell`。它是一个与 AWS CLI 一起工作的集成式 shell。它使用 AWS CLI 配置，并通过自动完成功能提高了生产力。

使用以下命令安装`aws-shell`并运行它：

```
$ sudo apt-get install aws-shell && aws-shell
```

您将看到以下输出：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/k8s-cpl-dop-cb/img/5c520f0d-774a-4224-a917-223d3cbf2101.png)

您可以使用`aws-shell`与更少的输入来使用 AWS 命令。按*F10*键退出 shell。

### 使用基于八卦的集群

在这个示例中，我们创建了一个域（可以从亚马逊购买或其他注册商购买）和一个托管区域，因为 kops 使用 DNS 进行发现。虽然它需要是一个有效的 DNS 名称，但从 kops 1.6.2 开始，DNS 配置变成了可选项。可以轻松地创建一个基于八卦的集群，而不是实际的域或子域。通过使用注册的域名，我们使我们的集群更容易共享，并且可以被其他人用于生产。

如果出于任何原因，您更喜欢基于八卦的集群，您可以跳过托管区域的创建，并使用以`k8s.local`结尾的集群名称：

```
$ export KOPS_CLUSTER_NAME=devopscookbook.k8s.local
$ export KOPS_STATE_STORE=s3://devops-cookbook-state-store
```

设置`kops`的环境参数是可选的，但强烈建议，因为它可以缩短您的 CLI 命令。

### 为 S3 存储桶使用不同的地区

为了让 kops 存储集群配置，需要一个专用的 S3 存储桶。

`eu-west-1`地区的示例如下：

```
$ aws s3api create-bucket --bucket s3.k8s.containerized.me \
--region eu-west-1 --create-bucket-configuration \
LocationConstraint=eu-west-1
```

这个 S3 存储桶将成为我们 Kubernetes 集群配置的真相来源。为了简单起见，建议使用`us-east-1`地区；否则，需要指定适当的`LocationConstraint`以便在所需的地区创建存储桶。

### 编辑集群配置

`kops create cluster`命令，我们用来创建集群配置，实际上并不创建集群本身并启动 EC2 实例；相反，它在我们的 S3 存储桶中创建配置文件。

创建配置文件后，您可以使用`kops edit cluster`命令对配置进行更改。

您可以使用以下命令分别编辑您的节点实例组：

```
$ kops edit ig nodes 
$ kops edit ig master-us-east-1a
```

配置文件是从 S3 存储桶的状态存储位置调用的。如果您喜欢不同的编辑器，您可以例如设置`$KUBE_EDITOR=nano`来更改它。

### 删除您的集群

要删除您的集群，请使用以下命令：

```
$ kops delete cluster --name ${KOPS_CLUSTER_NAME} --yes
```

这个过程可能需要几分钟，完成后，您将收到确认。

### 使用亚马逊 EKS 管理控制台配置 EKS 集群

在《在 Amazon EKS 上提供托管的 Kubernetes 集群》教程中，我们使用 eksctl 部署了一个集群。作为替代方案，您也可以使用 AWS 管理控制台 Web 用户界面来部署 EKS 集群。

执行以下步骤来在 Amazon EKS 上启动和运行您的集群：

1.  打开浏览器并转到 Amazon EKS 控制台[`console.aws.amazon.com/eks/home#/clusters`](https://console.aws.amazon.com/eks/home#/clusters)。

1.  输入集群名称并点击“下一步”按钮。

1.  在创建集群页面上，选择 Kubernetes 版本、角色名称、至少两个或更多可用区的子网列表和安全组。

1.  点击创建。

1.  使用 EKS 创建集群大约需要 20 分钟。在 15-20 分钟后刷新页面并检查其状态。

1.  使用以下命令更新您的`kubectl`配置：

```
$ aws eks --region us-east-1 update-kubeconfig \
--name K8s-DevOps-Cookbook  
```

1.  现在，使用`kubectl`来管理您的集群：

```
$ kubectl get nodes
```

现在您的集群已配置好，您可以配置`kubectl`来管理它。

### 部署 Kubernetes 仪表板

最后但并非最不重要的是，在 AWS 集群上部署 Kubernetes 仪表板应用程序，您需要按照以下步骤进行操作：

1.  在我写这个教程的时候，Kubernetes Dashboard v.2.0.0 仍处于测试阶段。由于 v.1.x 版本很快就会过时，我强烈建议您安装最新版本，即 v.2.0.0。新版本带来了许多功能和对 Kubernetes v.1.16 及更高版本的支持。在部署仪表板之前，请确保删除之前的版本（如果有）。通过以下信息框中的链接检查最新发布，并使用最新发布进行部署，类似于以下操作：

```
$ kubectl delete ns kubernetes-dashboard
# Use the latest version link from https://github.com/kubernetes/dashboard/releases
$ kubectl apply -f https://raw.githubusercontent.com/kubernetes/dashboard/v2.0.0-beta5/aio/deploy/recommended.yaml
```

随着 Kubernetes 版本的升级，仪表板应用程序也经常会更新。要使用最新版本，请在发布页面[`github.com/kubernetes/dashboard/releases`](https://github.com/kubernetes/dashboard/releases)上找到 YAML 清单的最新链接。如果您在使用仪表板的最新版本时遇到兼容性问题，您可以始终使用以下命令部署以前的稳定版本：`$ kubectl apply -f`

`https://raw.githubusercontent.com/kubernetes/dashboard/v1.10.1/src/depl`

`oy/recommended/kubernetes-dashboard.yaml`

1.  默认情况下，`kubernetes-dashboard`服务使用`ClusterIP`类型进行公开。如果您想从外部访问它，请使用以下命令编辑服务，并将`ClusterIP`类型替换为`LoadBalancer`；否则，请使用端口转发进行访问：

```
$ kubectl edit svc kubernetes-dashboard -n kubernetes-dashboard
```

1.  从`kubernetes-dashboard`服务中获取仪表板的外部 IP：

```
$ kubectl get svc kubernetes-dashboard -n kubernetes-dashboard
NAME                 TYPE          CLUSTER-IP    EXTERNAL-IP PORT(S) AGE
kubernetes-dashboard LoadBalancer 100.66.234.228 myaddress.us-east-1.elb.amazonaws.com 443:30221/TCP 5m46s
```

1.  在浏览器中打开外部 IP 链接。在我们的示例中，它是`https://myaddress.us-east-1.elb.amazonaws.com`。

1.  我们将使用令牌选项来访问 Kubernetes 仪表板。现在，让我们使用以下命令在我们的集群中找到令牌。在这个例子中，该命令返回`kubernetes-dashboard-token-bc2w5`作为令牌名称：

```
$ kubectl get secrets -A | grep dashboard-token
kubernetes-dashboard kubernetes-dashboard-token-bc2w5 kubernetes.io/service-account-token 3 17m
```

1.  用前一个命令的输出替换密钥名称。从 Secret 的描述中获取令牌详细信息：

```
$ kubectl describe secrets kubernetes-dashboard-token-bc2w5 -nkubernetes-dashboard
```

1.  从前面命令的输出中复制令牌部分，并将其粘贴到 Kubernetes 仪表板中以登录到仪表板：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/k8s-cpl-dop-cb/img/2d90464c-0905-4590-a4c6-4a2da4455555.png)

现在，您可以访问 Kubernetes 仪表板来管理您的集群。

## 另请参阅

+   最新版本和额外的`create cluster`参数的 Kops 文档：

+   [`github.com/kubernetes/kops/blob/master/docs/aws.md`](https://github.com/kubernetes/kops)

+   [`github.com/kubernetes/kops/blob/master/docs/cli/kops_create_cluster.md`](https://github.com/kubernetes/kops/blob/master/docs/cli/kops_create_cluster.md)

+   AWS 命令参考 S3 创建存储桶 API：[`docs.aws.amazon.com/cli/latest/reference/s3api/create-bucket.html`](https://docs.aws.amazon.com/cli/latest/reference/s3api/create-bucket.html)

+   AWS 全球基础设施地图： [`aws.amazon.com/about-aws/global-infrastructure/ `](https://aws.amazon.com/about-aws/global-infrastructure/)

+   Amazon EKS 常见问题： [`aws.amazon.com/eks/faqs/`](https://aws.amazon.com/eks/faqs/)

+   AWS Fargate 产品，另一个 AWS 服务，如果您希望在不管理服务器或集群的情况下运行容器： [`aws.amazon.com/fargate/`](https://aws.amazon.com/fargate/)

+   CNCF 认证的 Kubernetes 安装程序的完整列表： [`landscape.cncf.io/category=certified-kubernetes-installer&format=card-mode&grouping=category`](https://landscape.cncf.io/category=certified-kubernetes-installer&format=card-mode&grouping=category)。

+   在 AWS 上获取高可用集群的其他推荐工具：

+   Konvoy: [`d2iq.com/solutions/ksphere/konvoy`](https://d2iq.com/solutions/ksphere/konvoy)

+   KubeAdm: [`github.com/kubernetes/kubeadm `](https://github.com/kubernetes/kubeadm)

+   KubeOne: [`github.com/kubermatic/kubeone`](https://github.com/kubermatic/kubeone)

+   KubeSpray: [`github.com/kubernetes-sigs/kubespray`](https://github.com/kubernetes-sigs/kubespray)

# 在 Google Cloud Platform 上配置 Kubernetes 集群

本节将逐步指导您在 GCP 上配置 Kubernetes 集群。您将学习如何在不需要配置或管理主节点和 etcd 实例的情况下运行托管的 Kubernetes 集群，使用 GKE。

## 准备工作

这里提到的所有操作都需要启用计费的 GCP 帐户。如果您还没有，请转到[`console.cloud.google.com`](https://console.cloud.google.com)并创建一个帐户。

在 Google Cloud Platform（GCP）上，运行 Kubernetes 有两个主要选项。如果您想完全管理部署并具有特定的强大实例要求，可以考虑使用 Google Compute Engine（GCE）。否则，强烈建议使用托管的 Google Kubernetes Engine（GKE）。

## 如何做…

本节进一步分为以下小节，以使此过程更易于跟进：

+   安装命令行工具以配置 GCP 服务

+   在 GKE 上配置托管的 Kubernetes 集群

+   连接到 GKE 集群

### 安装命令行工具以配置 GCP 服务

在这个教程中，我们将安装 Google 云平台的主要 CLI，`gcloud`，以便我们可以配置 GCP 服务：

1.  运行以下命令以下载`gcloud` CLI：

```
$ curl https://sdk.cloud.google.com | bash
```

1.  初始化 SDK 并按照给定的说明进行操作：

```
$ gcloud init
```

1.  在初始化期间，当询问时，请选择您有权限的现有项目或创建一个新项目。

1.  为项目启用 Compute Engine API：

```
$ gcloud services enable compute.googleapis.com
Operation "operations/acf.07e3e23a-77a0-4fb3-8d30-ef20adb2986a" finished successfully.
```

1.  设置默认区域：

```
$ gcloud config set compute/zone us-central1-a
```

1.  确保您可以从命令行启动 GCE 实例：

```
$ gcloud compute instances create "devops-cookbook" \
--zone "us-central1-a" --machine-type "f1-micro"
```

1.  删除测试 VM：

```
$ gcloud compute instances delete "devops-cookbook"
```

如果所有命令都成功，您可以配置您的 GKE 集群。

### 在 GKE 上配置托管的 Kubernetes 集群

让我们执行以下步骤：

1.  创建一个集群：

```
$ gcloud container clusters create k8s-devops-cookbook-1 \
--cluster-version latest --machine-type n1-standard-2 \
--image-type UBUNTU --disk-type pd-standard --disk-size 100 \
--no-enable-basic-auth --metadata disable-legacy-endpoints=true \
--scopes compute-rw,storage-ro,service-management,service-control,logging-write,monitoring \
--num-nodes "3" --enable-stackdriver-kubernetes \ --no-enable-ip-alias --enable-autoscaling --min-nodes 1 \
--max-nodes 5 --enable-network-policy \
--addons HorizontalPodAutoscaling,HttpLoadBalancing \
--enable-autoupgrade --enable-autorepair --maintenance-window "10:00"
```

集群创建需要 5 分钟或更长时间才能完成。

### 连接到 Google Kubernetes Engine（GKE）集群

要访问您的 GKE 集群，您需要按照以下步骤进行操作：

1.  配置`kubectl`以访问您的`k8s-devops-cookbook-1`集群：

```
$ gcloud container clusters get-credentials k8s-devops-cookbook-1
```

1.  验证您的 Kubernetes 集群：

```
$ kubectl get nodes
```

现在，您有一个运行中的三节点 GKE 集群。

## 工作原理...

这个教程向您展示了如何使用一些默认参数快速配置 GKE 集群。

在 *步骤 1* 中，我们使用了一些默认参数创建了一个集群。虽然所有参数都非常重要，但我想在这里解释其中一些。

`--cluster-version` 设置要用于主节点和节点的 Kubernetes 版本。只有在想要使用与默认值不同的版本时才使用它。您可以使用 `gcloud container get-server-config` 命令获取可用版本信息。

我们使用 `--machine-type` 参数设置了实例类型。如果没有设置，默认值是 `n1-standard-1`。您可以使用 `gcloud compute machine-types list` 命令获取预定义类型的列表。

默认镜像类型是 COS，但我个人偏好 Ubuntu，所以我使用 `--image-type UBUNTU` 来将 OS 镜像设置为 `UBUNTU`。如果没有设置，服务器会选择默认镜像类型，即 COS。您可以使用 `gcloud container get-server-config` 命令获取可用镜像类型的列表。

GKE 提供了高级集群管理功能，并配备了节点实例的自动扩展、自动升级和自动修复功能，以维护节点的可用性。`--enable-autoupgrade` 启用了 GKE 的自动升级功能，用于集群节点，`--enable-autorepair` 启用了自动修复功能，该功能在使用 `--maintenance-window` 参数定义的时间开始。这里设置的时间是 UTC 时区，并且必须以 `HH:MM` 格式。

## 还有更多...

以下是在上一节描述的教程之外可以采用的一些替代方法：

+   使用 Google 云 Shell

+   使用自定义网络配置部署

+   删除您的集群

+   查看工作负载仪表板

### 使用 Google 云 Shell

作为 Linux 工作站的替代方案，您可以在浏览器上获得 CLI 接口，以管理您的云实例。

转到 [`cloud.google.com/shell/`](https://cloud.google.com/shell/) 获取 Google 云 Shell。

### 使用自定义网络配置部署

以下步骤演示了如何使用自定义网络配置来配置您的集群：

1.  创建 VPC 网络：

```
$ gcloud compute networks create k8s-devops-cookbook \
--subnet-mode custom
```

1.  在您的 VPC 网络中创建一个子网。在我们的示例中，这是 `10.240.0.0/16`：

```
$ gcloud compute networks subnets create kubernetes \
--network k8s-devops-cookbook --range 10.240.0.0/16
```

1.  创建防火墙规则以允许内部流量：

```
$ gcloud compute firewall-rules create k8s-devops-cookbook-allow-int \
--allow tcp,udp,icmp --network k8s-devops-cookbook \
--source-ranges 10.240.0.0/16,10.200.0.0/16
```

1.  创建防火墙规则以允许外部 SSH、ICMP 和 HTTPS 流量：

```
$ gcloud compute firewall-rules create k8s-devops-cookbook-allow-ext \
--allow tcp:22,tcp:6443,icmp --network k8s-devops-cookbook \
--source-ranges 0.0.0.0/0
```

1.  验证规则：

```
$ gcloud compute firewall-rules list
 NAME                          NETWORK             DIRECTION PRIORITY ALLOW  DENY    DISABLED
 ...
 k8s-devops-cookbook-allow-ext k8s-devops-cookbook INGRESS   1000     tcp:22,tcp:6443,icmp      False
 k8s-devops-cookbook-allow-int k8s-devops-cookbook INGRESS   1000     tcp,udp,icmp              False
```

1.  将`--network k8s-devops-cookbook`和`--subnetwork kubernetes`参数添加到您的`container clusters create`命令并运行它。

### 删除您的集群

要删除您的`k8s-devops-cookbook-1`集群，请使用以下命令：

```
$ gcloud container clusters delete k8s-devops-cookbook-1
```

这个过程可能需要几分钟，完成后，您将收到确认消息。

### 查看工作负载仪表板

在 GCP 上，您可以使用内置的工作负载仪表板并通过 Google Marketplace 部署容器化应用程序，而不是使用 Kubernetes 仪表板应用程序。按照以下步骤：

1.  要从 GCP 仪表板访问工作负载仪表板，请选择您的 GKE 集群并单击工作负载。

1.  单击“显示系统工作负载”以查看已部署在`kube-system`命名空间中的现有组件和容器。

## 另请参阅

+   GCP 文档：[`cloud.google.com/docs/`](https://cloud.google.com/docs/)

+   GKE 本地安装：[`cloud.google.com/gke-on-prem/docs/how-to/install-overview-basic`](https://cloud.google.com/gke-on-prem/docs/how-to/install-overview-basic)

# 在 Microsoft Azure 上配置 Kubernetes 集群

在本节中，我们将使用 Microsoft **Azure Kubernetes Service**（**AKS**）创建 Microsoft Azure 云上的 Kubernetes 集群。

## 准备就绪

这里提到的所有操作都需要 Microsoft Azure 订阅。如果您还没有，请转到[`portal.azure.com`](https://portal.azure.com)并创建一个免费帐户。

## 如何做…

本节将带您了解如何在 Microsoft Azure 上配置 Kubernetes 集群。本节进一步分为以下子节，以使此过程更容易：

+   安装命令行工具以配置 Azure 服务

+   在 AKS 上配置托管的 Kubernetes 集群

+   连接到 AKS 集群

### 安装命令行工具以配置 Azure 服务

在这个配方中，我们将安装名为`az`和`kubectl`的 Azure CLI 工具。

让我们执行以下步骤：

1.  安装必要的依赖项：

```
$ sudo apt-get update && sudo apt-get install -y libssl-dev \
libffi-dev python-dev build-essential
```

1.  下载并安装`az` CLI 工具：

```
$ curl -L https://aka.ms/InstallAzureCli | bash
```

1.  验证您正在使用的`az`版本：

```
$ az --version
```

1.  如果尚未安装，请安装`kubectl`：

```
$ az aks install-cli
```

如果所有命令都成功，您可以开始配置您的 AKS 集群。

### 在 AKS 上配置托管的 Kubernetes 集群

让我们执行以下步骤：

1.  登录到您的帐户：

```
$ az login
```

1.  在您喜欢的区域创建一个名为`k8sdevopscookbook`的资源组：

```
$ az group create --name k8sdevopscookbook --location eastus
```

1.  创建服务主体并记下您的`appId`和`password`以进行下一步：

```
$ az ad sp create-for-rbac --skip-assignment
{
 "appId": "12345678-1234-1234-1234-123456789012",
 "displayName": "azure-cli-2019-05-11-20-43-47",
 "name": "http://azure-cli-2019-05-11-20-43-47",
 "password": "12345678-1234-1234-1234-123456789012",
 "tenant": "12345678-1234-1234-1234-123456789012"
```

1.  创建一个集群。用前面命令的输出替换`appId`和`password`：

```
$ az aks create  --resource-group k8sdevopscookbook \  --name AKSCluster \ --kubernetes-version 1.15.4 \
 --node-vm-size Standard_DS2_v2 \ --node-count 3 \ --service-principal <appId> \ --client-secret <password> \ --generate-ssh-keys
```

集群创建大约需要 5 分钟。当成功完成时，您将看到`"provisioningState": Succeeded"`。

### 连接到 AKS 集群

让我们执行以下步骤：

1.  收集一些凭据并配置`kubectl`以便您可以使用它们：

```
$ az aks get-credentials --resource-group k8sdevopscookbook \
--name AKSCluster
```

1.  验证您的 Kubernetes 集群：

```
$ kubectl get nodes
```

现在，您有一个运行中的三节点 GKE 集群。

## 它是如何工作的…

本教程向您展示了如何使用一些常见选项快速创建 AKS 集群。

在*步骤 3*中，命令以`az aks create`开头，后面跟着`-g`或`--resource-group`，这样您就可以选择资源组的名称。您可以使用`az configure --defaults group=k8sdevopscookbook`来配置默认组，并在下次跳过这个参数。

我们使用`--name AKSCluster`参数来设置托管集群的名称为`AKSCluster`。其余的参数是可选的；`--kubernetes-version`或`-k`设置要用于集群的 Kubernetes 版本。您可以使用`az aks get-versions --location eastus --output table`命令来获取可用选项的列表。

我们使用`--node-vm-size`来设置 Kubernetes 工作节点的实例类型。如果没有设置，默认值为`Standard_DS2_v2`。

接下来，我们使用`--node-count`来设置 Kubernetes 工作节点的数量。如果没有设置，默认值为`3`。可以使用`az aks scale`命令来更改这个值。

最后，使用`--generate-ssh-keys`参数来自动生成 SSH 公钥和私钥文件，这些文件存储在`~/.ssh`目录中。

## 还有更多…

尽管 Kubernetes 现在支持基于 Windows 的容器，但要能够运行 Windows Server 容器，您需要运行基于 Windows Server 的节点。AKS 节点目前在 Linux OS 上运行，不支持基于 Windows Server 的节点。但是，您可以使用 Virtual Kubelet 在容器实例上调度 Windows 容器，并将其作为集群的一部分进行管理。在本节中，我们将看一下以下内容：

+   删除您的集群

+   查看 Kubernetes 仪表板

### 删除您的集群

要删除您的集群，请使用以下命令：

```
$ az aks delete --resource-group k8sdevopscookbook --name AKSCluster
```

这个过程将需要几分钟，完成后，您将收到确认信息。

### 查看 Kubernetes 仪表板

要查看 Kubernetes 仪表板，您需要按照以下步骤进行：

1.  要启动 Kubernetes 仪表板，请使用以下命令：

```
$ az aks browse --resource-group k8sdevopscookbook --name AKSCluster
```

1.  如果您的集群启用了 RBAC，则创建`Clusterrolebinding`：

```
$ kubectl create clusterrolebinding kubernetes-dashboard \
--clusterrole=cluster-admin \
--serviceaccount=kube-system:kubernetes-dashboard
```

1.  打开浏览器窗口，转到代理运行的地址。在我们的示例中，这是`http://127.0.0.1:8001/`。

## 另请参阅

+   Microsoft AKS FAQ：[`docs.microsoft.com/en-us/azure/aks/faq`](https://docs.microsoft.com/en-us/azure/aks/faq)

+   在 GitHub 上的 AKS 开源核心存储库：[`github.com/Azure/aks-engine`](https://github.com/Azure/aks-engine)

# 在阿里巴巴云上配置 Kubernetes 集群

阿里巴巴云（也称为阿里云）提供了多个模板，您可以使用这些模板来提供 Kubernetes 环境。有四个主要的服务类别：

+   Kubernetes：在单个区域的 ECS 实例上部署的具有三个主节点的自管理 Kubernetes。工作节点可以是 ECS 或裸金属。

+   托管的 Kubernetes：类似于 Kubernetes 集群选项，只是主节点由阿里巴巴云管理。

+   多 AZ Kubernetes：类似于 Kubernetes 集群选项，只是自管理的主节点和工作节点可以部署在不同的可用区。

+   无服务器 Kubernetes：一种 Kubernetes 服务提供，您可以在其中部署容器应用程序，而无需管理和维护集群实例：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/k8s-cpl-dop-cb/img/d5d00123-6c97-4086-b3df-8808269e905b.png)

在本节中，我们将介绍如何在不需要配置或管理主节点和 etcd 实例的情况下，提供一个高可用的多 AZ Kubernetes 集群。

## 做好准备

这里提到的所有操作都需要阿里巴巴云账户（也称为阿里云）和 AccessKey。如果您还没有，请转到[`account.alibabacloud.com`](https://account.alibabacloud.com)并创建一个账户。

## 如何做到…

本节将带您了解如何在阿里巴巴云上配置 Kubernetes 集群。本节进一步分为以下子节，以使此过程更加简单：

+   安装命令行工具以配置阿里巴巴云服务

+   在阿里巴巴云上提供一个高可用的 Kubernetes 集群

+   连接到阿里巴巴容器服务集群

### 安装命令行工具以配置阿里巴巴云服务

对于此示例，我们将使用阿里巴巴云控制台，并从仪表板生成 API 请求参数，该参数将与 CLI 一起使用。您还需要安装阿里巴巴云 CLI `aliyun`和`kubectl`。

1.  运行以下命令以下载`aliyun`工具：

```
$ curl -O https://aliyuncli.alicdn.com/aliyun-cli-linux-3.0.15-amd64.tgz
```

您可以在此处找到最新版本的链接：[`github.com/aliyun/aliyun-cli`](https://github.com/aliyun/aliyun-cli)。

1.  提取文件并安装它们：

```
$ tar –zxvf aliyun-cli*.tgz && sudo mv aliyun /usr/local/bin/.
```

1.  验证您正在使用的`aliyun` CLI 版本：

```
$ aliyun --version
```

1.  如果您还没有创建 AccessKey，请转到您的帐户中的安全管理并创建一个([`usercenter.console.aliyun.com/#/manage/ak`](https://account.alibabacloud.com/login/login.htm?spm=a2c44.11131515.0.0.4e57525cYlZEdf))。

1.  通过输入您的 AccessKey ID、AccessKey Secret 和区域 ID 完成 CLI 配置：

```
$ aliyun configure
Configuring profile '' in '' authenticate mode...
Access Key Id []: <Your AccessKey ID>
Access Key Secret []: <Your AccessKey Secret>
Default Region Id []: us-west-1
Default Output Format [json]: json (Only support json))
Default Language [zh|en] en: en
Saving profile[] ...Done.
```

1.  启用`bash/zsh`自动完成：

```
$ aliyun auto-completion
```

1.  转到容器服务控制台([`cs.console.aliyun.com`](https://cs.console.aliyun.com))，为容器服务授予权限访问云资源。在这里，选择`AliyunCSDefaultRole`、`AliyunCSServerlessKuberentesRole`、`AliyunCSClusterRole`和`AliyunCSManagedKubernetesRole`，然后点击“确认授权策略”。

确保已启用**资源编排服务（ROS）**和自动伸缩服务，因为它们是部署 Kubernetes 集群所需的。ROS 用于根据您的模板自动提供和配置资源以进行自动部署、操作和维护，而自动伸缩用于根据需求调整计算资源。

### 在阿里云上部署高可用的 Kubernetes 集群

让我们执行以下步骤：

1.  打开浏览器窗口，转到阿里云虚拟私有云控制台[`vpc.console.aliyun.com`](https://vpc.console.aliyun.com)。

1.  确保选择至少有三个区域的区域（中国大陆的大多数区域都有三个以上的区域），然后点击“创建 VPC”。

1.  为您的 VPC 指定一个唯一名称并选择一个 IPv4 CIDR 块。在我们的示例中，这是`10.0.0.0/8`。

1.  为您的第一个 VSwitch（`k8s-1`）输入一个名称，并选择一个区域（`北京 A 区`）。

1.  设置一个 IPv4 CIDR 块。在我们的示例中，我们使用了`10.10.0.0./16`。

1.  点击“添加”按钮，然后重复*步骤 4*和*步骤 5*以获取不同的区域。使用以下 CIDR 块信息：

|  | **VSwitch 2** | **VSwitch 3** |
| --- | --- | --- |
| **名称：** | k8s-2 | k8s-3 |
| **区域：** | 北京 B 区 | 北京 E 区 |
| **IPv4 CIDR 块：** | 10.20.0.0/16 | 10.30.0.0/16 |

1.  点击“确定”创建您的 VPC 和 VSwitches。

1.  在您的 Web 浏览器上打开阿里云 Web 控制台([`cs.console.aliyun.com`](https://cs.console.aliyun.com)。)。

1.  点击“创建 Kubernetes 集群”。

1.  选择标准托管集群。

1.  点击“多可用区 Kubernetes”选项卡，为您的集群命名，并选择与创建 VPC 和 VSwitches 时相同的区域。

1.  如果您选择了相同的区域，VPC 下拉菜单将显示为`k8s-devops-cookbook-vpc`。现在，选择我们创建的所有三个 VSwitches：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/k8s-cpl-dop-cb/img/63922633-60f0-438c-9ec7-268c8e4a5d7a.png)

1.  在每个区域的 Master 节点配置中设置实例类型。

1.  在每个区域的 Worker 节点配置中设置实例类型，并将每个区域的节点数设置为`3`。否则，请使用默认设置。

1.  选择 Kubernetes 版本（`1.12.6-aliyun.1`，在撰写时）。

1.  从下拉菜单中选择“密钥对名称”，或者点击“创建新密钥对”来创建一个：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/k8s-cpl-dop-cb/img/c4c99701-34e6-4578-ba6e-6cc294d78b35.png)

1.  阿里巴巴提供两种 CNI 选项：Flannel 和 Terway。区别在本食谱的*更多内容…*部分有解释。使用`Flannel`保留默认网络选项。默认参数支持集群中最多 512 台服务器。

1.  监控和日志记录将在第八章 *Kubernetes 上的可观察性和监控*和第十章 *Kubernetes 上的日志记录*中进行解释。因此，此步骤是可选的。勾选“在您的 ECS 上安装云监控插件”和“使用日志服务”选项以启用监控和日志记录。

1.  现在，点击“创建”以配置您的多可用区 Kubernetes 集群。此步骤可能需要 15-20 分钟才能完成。

### 连接到阿里巴巴容器服务集群

要访问阿里巴巴云上的集群，您需要按照以下步骤进行：

1.  要获取集群的凭据，请转到“集群”菜单，然后单击要访问的“集群名称”：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/k8s-cpl-dop-cb/img/dd1791c1-c581-4109-8292-a3f4541dd025.png)

1.  复制 KubeConfig 选项卡中显示的内容到您本地机器的`$HOME/.kube/config`文件中：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/k8s-cpl-dop-cb/img/d48997ed-5c67-4ccb-b8ac-b01612fe45af.png)

1.  验证您的 Kubernetes 集群：

```
$ kubectl get nodes
```

作为替代方案，请参阅*查看 Kubernetes 仪表板*部分下的说明，以管理您的集群。

## 工作原理…

本食谱向您展示了如何使用集群模板在阿里巴巴云上配置托管的 Kubernetes 集群。

在容器服务菜单下，阿里巴巴云提供了一些 Kubernetes 集群，其中提供了七个集群模板。我们在这里使用了标准托管集群。此选项只允许您管理工作节点，并为您节省了主节点的资源和管理成本：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/k8s-cpl-dop-cb/img/4509b205-b24a-41dc-9263-877047ddcc67.png)

默认情况下，帐户支持最多 20 个集群和每个集群 40 个节点。您可以通过提交支持工单来请求配额增加。

## 还有更多...

作为使用阿里巴巴云控制台的替代方法，您可以通过`aliyuncli`使用 REST API 调用来创建 ECS 实例和您的集群。按照以下步骤操作：

1.  在阿里巴巴云控制台上配置了集群选项后，点击“创建”按钮下方的“生成 API 请求参数”以生成用于`aliyun` CLI 的 POST 请求主体内容。

1.  将内容保存到文件中。在我们的案例中，这个文件被称为`cscreate.json`。

1.  有关本节中列出的其他参数的解释，请参阅[`www.alibabacloud.com/help/doc-detail/87525.htm`](https://www.alibabacloud.com/help/doc-detail/87525.htm)中的*创建 Kubernetes*部分。

1.  使用以下命令创建您的集群：

```
$ aliyun cs POST /clusters --header "Content-Type=application/json" \
--body "$(cat cscreate.json)"
```

阿里巴巴云容器服务为其 Kubernetes 集群提供了两种网络插件选项：Terway 和 Flannel。

Flannel 基于社区 Flannel CNI 插件。Flannel 是一个非常常见和稳定的网络插件，提供基本的网络功能。除了不支持 Kubernetes NetworkPolicy 之外，它是大多数用例的推荐选项。Terway 是阿里巴巴云 CS 开发的网络插件。它与 Flannel 完全兼容。Terway 可以根据 Kubernetes NetworkPolicy 定义容器之间的访问策略。Terway 还支持对容器进行带宽限制。

# 使用 Rancher 配置和管理 Kubernetes 集群

Rancher 是一个容器管理平台，具有使用**Rancher Kubernetes Engine**（**RKE**）或基于云的 Kubernetes 服务（如 GKE、AKS 和 EKS）创建 Kubernetes 集群的灵活性，这些我们在前面的章节中讨论过。

在本节中，我们将介绍配置 Rancher 的方法，以便部署和管理 Kubernetes 服务。

## 准备工作

Rancher 可以安装在 Ubuntu、RHEL/CentOS、RancherOS 甚至 Windows Server 上。您可以在高可用配置或单节点中启动 Rancher 服务器。请参考*另请参阅...*部分，获取替代安装说明的链接。在本教程中，我们将在单个节点上运行 Rancher。

## 如何做...

本节将带您了解如何使用 Rancher 配置和管理 Kubernetes 集群。为此，本节进一步分为以下子节，以使此过程更加简单：

+   安装 Rancher 服务器

+   部署 Kubernetes 集群

+   导入现有集群

+   启用集群和节点提供程序

### 安装 Rancher 服务器

按照以下步骤安装 Rancher 服务器：

1.  安装支持的 Docker 版本。如果您已经安装了 Docker，则可以跳过此步骤：

```
$ sudo apt-get -y install apt-transport-https ca-certificates curl \
software-properties-common
$ curl -fsSL https://download.docker.com/linux/ubuntu/gpg | sudo apt-key add -
$ sudo add-apt-repository "deb [arch=amd64] https://download.docker.com/linux/ubuntu $(lsb_release -cs) stable"
$ sudo apt-get -y install docker-ce && docker --version
```

1.  将用户添加到 Docker 组：

```
$ sudo usermod -a -G docker $USER
```

1.  要安装 Rancher 服务器，请运行以下命令：

```
docker run -d --restart=unless-stopped \
-p 80:80 -p 443:443 rancher/rancher:latest
```

1.  打开浏览器窗口，转到`https://localhost`。如有必要，请将`localhost`替换为您主机的 IP。

1.  设置新密码，然后单击继续。

1.  设置 Rancher 服务器的公共 IP 地址，并单击保存 URL。这个 IP 地址需要从您的集群外部访问。

### 部署 Kubernetes 集群

要部署一个新的集群，您需要按照以下步骤进行：

1.  单击添加集群。

1.  选择提供程序。在我们的示例中，我们将使用 GKE。其他提供程序的一些设置可能略有不同：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/k8s-cpl-dop-cb/img/fd8b3f2f-0c40-49ed-8c94-88b35db3b5cd.png)

1.  输入集群名称。

如果您有我们之前保存的 GCP 服务帐户 JSON 文件，请跳至*步骤 10*。

1.  从 GCP 导航菜单中，转到 IAM，然后单击服务帐户链接。

1.  单击创建服务帐户。

1.  输入服务帐户名称，然后单击创建。

1.  添加所需的最低权限；即，Compute Viewer、Viewer、Kubernetes Engine Admin 和 Service Account User，然后单击继续。

1.  单击创建密钥。使用 JSON 作为密钥类型，以保存您的服务帐户。

1.  在 Rancher UI 上，单击从文件读取，并加载您之前保存的服务帐户 JSON 文件。

1.  根据需要自定义集群选项；否则，使用默认设置，然后单击创建以部署您的 Kubernetes 集群：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/k8s-cpl-dop-cb/img/636bbafa-332b-4915-b95b-29b298f6cd68.png)

您的集群将被列出，并立即可以在 Rancher 仪表板上进行管理。

### 导入现有集群

要导入现有集群，您需要按照以下步骤进行：

1.  单击添加集群

1.  单击导入：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/k8s-cpl-dop-cb/img/23165978-0c4b-4a3a-9902-7dcee75cb117.png)

1.  输入集群名称，然后单击“创建”。

1.  按照显示的说明，复制并运行显示在屏幕上的`kubectl`命令到现有的 Kubernetes 集群。如果您使用的是不受信任/自签名的 SSL 证书，则此命令看起来类似于以下内容：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/k8s-cpl-dop-cb/img/e0f4937e-352f-4b2f-8113-6765b3960efe.png)

1.  点击“完成”后，您的集群将被列出，并且可以立即在 Rancher 仪表板上进行管理：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/k8s-cpl-dop-cb/img/b72b4d19-a180-4661-85f2-66626655ab8f.png)

最后一步可能需要一分钟的时间来完成。最终，当准备就绪时，您的集群状态将从待定变为活动。

### 启用集群和节点提供者

为了支持多个提供者，Rancher 使用集群和节点驱动程序。如果您在列表中找不到您的提供者，则很可能是未启用。

要启用其他提供者，请按照以下步骤操作：

1.  从“工具”中，单击“驱动程序”。

1.  在列表中找到您的提供者，然后单击“激活”：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/k8s-cpl-dop-cb/img/756d1cff-2dc4-43ad-b047-d6a75df90f51.png)

从同一页，您还可以停用您不打算使用的提供者。

## 它是如何工作的...

这个教程向您展示了如何快速运行 Rancher 服务器来管理您的 Kubernetes 集群。

在*步骤 1*中，我们使用了默认的自签名证书方法进行单节点安装。出于安全目的，与集群交互需要 SSL。因此，需要证书。

如果您更喜欢使用由认可的 CA 签名的自己的证书，可以使用以下命令，并提供路径以将它们挂载到容器中，通过用您的签名证书替换`FULLCHAIN.pem`和`PRIVATEKEY.pem`文件：

```
$ docker run -d --restart=unless-stopped \
 -p 80:80 -p 443:443 \
 -v /<CERTDIRECTORY>/<FULLCHAIN.pem>:/etc/rancher/ssl/cert.pem \
 -v /<CERTDIRECTORY>/<PRIVATEKEY.pem>:/etc/rancher/ssl/key.pem \
 rancher/rancher:latest --no-cacerts
```

使用认可的证书将消除登录页面上的安全警告。

## 还有更多...

还有以下信息也很有用：

+   绑定挂载主机卷以保留数据

+   保持用户卷持久

+   在主机卷上保持数据持久

+   在相同的 Kubernetes 节点上运行 Rancher

### 绑定挂载主机卷以保留数据

在使用单节点安装时，持久数据保存在容器中的`/var/lib/rancher`路径上。

要在主机上保留数据，可以使用以下命令将主机卷绑定到位置：

```
$ docker run -d --restart=unless-stopped \
 -p 80:80 -p 443:443 \
 -v /opt/rancher:/var/lib/rancher \
 -v /var/log/rancher/auditlog:/var/log/auditlog \
 rancher/rancher:latest 
```

与卷相比，绑定挂载具有有限的功能。当使用绑定挂载启动 Rancher 时，主机上的目录将被挂载到容器中的指定目录。

### 保持用户卷持久

在使用 RancherOS 时，只有特定目录才能使`user-volumes`参数定义的数据持久。

要添加额外的持久`user-volumes`，例如，添加`/var/openebs`目录：

```
$ ros config set rancher.services.user-volumes.volumes \[/home:/home,/opt:/opt,/var/lib/kubelet:/var/lib/kubelet,/etc/kubernetes:/etc/kubernetes,/var/openebs]
$ system-docker rm all-volumes
$ reboot
```

重新启动后，指定目录中的数据将是持久的。

### 在相同的 Kubernetes 节点上运行 Rancher

要将运行 Rancher 服务器的节点添加到集群中，请将默认端口`-p 80:80 -p 443:443`替换为以下内容，并使用以下命令启动 Rancher：

```
$ docker run -d --restart=unless-stopped \
 -p 8080:80 -p 8443:443 rancher/rancher:latest
```

在这种情况下，Rancher 服务器将通过`https://localhost:8443`而不是标准的`443`端口访问。

## 另请参阅

+   Rancher 2.x 文档：[`rancher.com/docs/rancher/v2.x/en/`](https://rancher.com/docs/rancher/v2.x/en/)

+   K3s，来自 Rancher Labs 的轻量级 Kubernetes：[`k3s.io/`](https://k3s.io/)

+   Rio，来自 Rancher Labs 的 Kubernetes 应用部署引擎：[`rio.io/`](https://rio.io/)

# 配置 Red Hat OpenShift

在这个教程中，我们将学习如何在 AWS、裸金属或 VMware vSphere VM 上部署 Red Hat OpenShift。

*部署 OpenShift 集群教程*中的步骤可以应用于在虚拟化环境上运行的 VM 或裸金属服务器上部署 OpenShift。

## 准备就绪

这里提到的所有操作都需要具有活动 Red Hat Enterprise Linux 和 OpenShift Container Platform 订阅的 Red Hat 帐户。如果您还没有，请转到[`access.redhat.com`](https://access.redhat.com)并创建一个帐户。

在部署 VM 时，请确保计划在 Kubernetes 节点上创建的区域实际上位于单独的 hypervisor 节点上。

对于这个教程，我们需要至少有六个节点，上面安装了 Red Hat Enterprise CoreOS。这些节点可以是裸金属、VM 或裸金属和 VM 的混合体。

## 如何做…

本节将带您了解如何配置 Red Hat OpenShift。为此，本节进一步分为以下子节，以使此过程更加简单：

+   下载 OpenShift 二进制文件

+   部署 OpenShift 集群

+   连接到 OpenShift 集群

### 下载 OpenShift 二进制文件

确保您在第一个主节点的终端上，并且具有 root 访问权限的帐户，或者正在以超级用户身份运行。按照以下步骤操作：

1.  转到 [`cloud.redhat.com/openshift/install`](https://cloud.redhat.com/openshift/install) 并下载最新的 `OpenShift Installer`：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/k8s-cpl-dop-cb/img/ca4493dd-b52c-4cb7-8575-107a4395153c.png)

1.  在您的工作站上提取安装程序文件：

```
$ tar -xzf openshift-install-linux-*.tar.gz
```

上述命令将在同一文件夹中创建一个名为 `openshift-install` 的文件。

### 配置 OpenShift 集群

在此教程中，我们将使用 AWS 平台部署 OpenShift：

1.  要启动您的 OpenShift 集群，请使用以下命令：

```
$ ./openshift-install create cluster
```

1.  选择 `aws` 作为您的平台，并输入您的 `AWS Access Key ID` 和 `Secret Access Key`。

1.  选择您的地区。在我们的示例中，这是 `us-east-1`。

1.  选择一个基础域。在我们的示例中，这是 `k8s.containerized.me`。

1.  输入一个集群名称。

1.  从 Red Hat 网站复制 Pull Secret，并将其粘贴到命令行中：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/k8s-cpl-dop-cb/img/54710f98-e2fe-4123-8fe1-cd372651908f.png)

1.  安装完成后，您将看到控制台 URL 和访问新集群的凭据，类似于以下内容：

```
INFO Install complete!
INFO To access the cluster as the system:admin user when using 'oc', run 'export KUBECONFIG=/home/ubuntu/auth/kubeconfig'
INFO Access the OpenShift web-console here: https://console-openshift-console.apps.os.k8s.containerized.me
INFO Login to the console with user: kubeadmin, password: ABCDE-ABCDE-ABCDE-ABCDE
```

1.  转到 Red Hat 网站，单击 `Download Command-Line Tools` 链接以下载 `openshift-client`。

1.  在您的工作站上提取 `openshift-client` 文件：

```
$ tar -xzf openshift-client-linux-*.tar.gz && sudo mv oc /usr/local/bin
```

上述命令将在同一文件夹中创建 `kubectl` 和 `oc` 文件，并将 `oc` 二进制文件移动到 PATH。

### 连接到 OpenShift 集群

要连接到 OpenShift 集群，请按照以下步骤操作：

1.  要访问您的 OpenShift 集群，请使用以下命令：

```
$ export KUBECONFIG=~/auth/kubeconfig
```

1.  替换 `password` 和 `cluster address` 后登录到您的 OpenShift 集群：

```
$ oc login -u kubeadmin -p ABCDE-ABCDE-ABCDE-ABCDE \
https://api.openshift.k8s.containerized.me:6443 \
--insecure-skip-tls-verify=true
```

如果您更喜欢使用 Web 控制台，可以在 *配置 OpenShift 集群* 教程中的步骤 7 中打开 Web 控制台 URL 地址。

## 工作原理…

此教程向您展示了如何在 AWS 上快速部署 OpenShift 集群。

在 *步骤 1* 中，我们使用安装程序提供的基础设施的默认配置创建了一个集群。

安装程序询问了一系列关于用户信息的问题，并且大多数其他配置选项都使用了默认值。如果需要，这些默认值可以通过 `install-config.yaml` 文件进行编辑和自定义。

要查看部署时使用的默认值，让我们创建一个 `install-config.yaml` 文件并查看它：

```
$ ./openshift-install create install-config && cat install-config.yaml
```

如您从以下输出中所见，文件的默认配置创建了一个由三个主节点和三个工作节点组成的集群：

```
apiVersion: v1
baseDomain: k8s.containerized.me
compute:
- hyperthreading: Enabled
 name: worker
 platform: {}
 replicas: 3
controlPlane:
 hyperthreading: Enabled
 name: master
 platform: {}
 replicas: 3
...
```

根据需要编辑`install-config.yaml`。下次创建集群时，将使用新参数。

## 还有更多...

还有以下信息也是有用的：

+   删除您的集群

### 删除您的集群

要删除您的集群，请使用以下命令：

```
$ ./openshift-install destroy cluster
```

此过程将需要几分钟时间，完成后将收到确认消息。

## 另请参阅

+   OpenShift 容器平台 4.3 文档：[`docs.openshift.com/container-platform/4.3/welcome/index.html`](https://docs.openshift.com/container-platform/4.3/welcome/index.html)

# 使用 Ansible 配置 Kubernetes 集群

强大的 IT 自动化引擎，如 Ansible，可用于自动化几乎任何日常 IT 任务，包括在裸机集群上部署 Kubernetes 集群。在本节中，我们将学习如何使用 Ansible playbook 部署一个简单的 Kubernetes 集群。

## 准备工作

在本食谱中，我们将使用一个 Ansible playbook。这些食谱中将使用的示例可通过`k8sdevopscookbook` GitHub 存储库访问。

在执行本节食谱中的命令之前，请使用以下命令克隆 Ansible playbook 示例：

```
$ git clone https://github.com/k8sdevopscookbook/src.git
```

您将在`k8sdevopscookbook/src`目录下找到示例存储。

## 如何做…

本节将带您了解如何使用 Ansible 配置 Kubernetes 集群。为此，本节进一步分为以下子节，以使此过程更加简单：

+   安装 Ansible

+   使用 Ansible playbook 提供 Kubernetes 集群

+   连接到 Kubernetes 集群

### 安装 Ansible

为了使用 Ansible playbook 提供 Kubernetes 集群，请按照以下步骤进行：

1.  要在 Linux 工作站上安装 Ansible，首先需要添加必要的存储库：

```
$ sudo apt-get install software-properties-common
$ sudo apt-add-repository --yes --update ppa:ansible/ansible
```

1.  使用以下命令安装 Ansible：

```
$ sudo apt-get update && *sudo apt-get install ansible -y*
```

1.  验证其版本并确保已安装 Ansible：

```
$ ansible --version
```

在撰写本食谱时，最新的 Ansible 版本是`2.9.4`。

### 使用 Ansible playbook 提供 Kubernetes 集群

为了使用 Ansible playbook 提供 Kubernetes 集群，请按照以下步骤进行：

1.  编辑`hosts.ini`文件，并用您想要配置 Kubernetes 的节点 IP 地址替换主节点和节点 IP 地址：

```
$ cd src/chapter1/ansible/ && vim hosts.ini
```

1.  `hosts.ini`文件应如下所示：

```
[master]
192.168.1.10
[node]
192.168.1.[11:13]
[kube-cluster:children]
master
node
```

1.  编辑`groups_vars/all.yml`文件以自定义您的配置。以下是如何执行此操作的示例：

```
kube_version: v1.14.0
token: b0f7b8.8d1767876297d85c
init_opts: ""
kubeadm_opts: ""
service_cidr: "10.96.0.0/12"
pod_network_cidr: "10.244.0.0/16"
calico_etcd_service: "10.96.232.136"
network: calico
network_interface: ""
enable_dashboard: yes
insecure_registries: []
systemd_dir: /lib/systemd/system
system_env_dir: /etc/sysconfig
network_dir: /etc/kubernetes/network
kubeadmin_config: /etc/kubernetes/admin.conf
kube_addon_dir: /etc/kubernetes/addon
```

1.  运行`site.yaml` playbook 来创建您的集群：

```
$ ansible-playbook site.yaml
```

您的集群将根据您的配置部署。

### 连接到 Kubernetes 集群

要访问您的 Kubernetes 集群，您需要按照以下步骤进行操作：

1.  从`master1`节点复制配置文件：

```
$ scp root@master:/etc/kubernetes/admin.conf ~/.kube/config
```

1.  现在，使用`kubectl`来管理您的集群。

## 另请参阅

+   用于与 Kubernetes 一起工作的 Ansible 模块：[`docs.ansible.com/ansible/latest/modules/k8s_module.html`](https://docs.ansible.com/ansible/latest/modules/k8s_module.html)

+   使用 Ansible 和 Operator SDK 的 Kubernetes 运算符示例：[`github.com/operator-framework/operator-sdk/blob/master/doc/ansible/user-guide.md`](https://github.com/operator-framework/operator-sdk/blob/master/doc/ansible/user-guide.md)

# 故障排除安装问题

Kubernetes 由许多松散耦合的组件和 API 组成。基于环境的不同，您可能会遇到需要更多关注才能使一切正常运行的问题。幸运的是，Kubernetes 提供了许多指出问题的方法。

在本节中，我们将学习如何获取集群信息，以便排除潜在问题。

## 如何执行…

按照以下步骤收集集群信息，以便排除潜在问题：

1.  创建名为`cluster-state`的集群状态文件转储：

```
$ kubectl cluster-info dump --all-namespaces \
 --output-directory=$PWD/cluster-state
```

1.  显示主节点和服务地址：

```
$ kubectl cluster-info
Kubernetes master is running at https://172.23.1.110:6443
Heapster is running at https://172.23.1.110:6443/api/v1/namespaces/kube-system/services/heapster/proxy
KubeDNS is running at https://172.23.1.110:6443/api/v1/namespaces/kube-system/services/kube-dns:dns/proxy
```

1.  显示`us-west-2.compute.internal`节点的资源使用情况：

```
$ kubectl top node us-west-2.compute.internal
NAME CPU(cores) CPU% MEMORY(bytes) MEMORY%
us-west-2.compute.internal 42m 2% 1690Mi 43%
```

1.  将`us-west-2.compute.internal`节点标记为不可调度：

```
$ kubectl cordon us-west-2.compute.internal
```

1.  安全地从`us-west-2.compute.internal`节点中撤出所有的 pod 以进行维护：

```
$ kubectl drain us-west-2.compute.internal
```

1.  在维护后，将`us-west-2.compute.internal`节点标记为可调度：

```
$ kubectl uncordon us-west-2.compute.internal
```

## 工作原理…

这个教程向您展示了如何快速排除常见的 Kubernetes 集群问题。

在第 1 步中，当使用`kubectl cluster-info`命令执行`--output-directory`参数时，Kubernetes 将集群状态的内容转储到指定文件夹下。您可以使用以下命令查看完整列表：

```
$ tree ./cluster-state
./cluster-state
├── default
│ ├── daemonsets.json
│ ├── deployments.json
│ ├── events.json
│ ├── pods.json
│....
```

在第 4 步中，我们使用`kubectl cordon`命令将节点标记为不可用。Kubernetes 有一个调度应用程序的概念，这意味着它会将 pod 分配给可用的节点。如果您事先知道集群中的实例将被终止或更新，您不希望在特定节点上安排新的 pod。 Cordoning 意味着使用`node.Spec.Unschedulable=true`对节点进行修补。当节点设置为不可用时，不会在该节点上安排新的 pod。

在第 5 步中，我们使用`kubectl drain`命令驱逐现有的 pod，因为仅使用 cordoning 不会对当前已安排的 pod 产生影响。驱逐 API 会考虑中断预算。如果所有者设置了中断预算，中断预算将限制复制应用程序中同时处于自愿中断状态的 pod 数量。如果不支持或设置了中断预算，驱逐 API 将在宽限期后简单地删除节点上的 pod。

## 还有更多...

以下信息也很有用：

+   设置日志级别

### 设置日志级别

在使用`kubectl`命令时，您可以使用`--v`标志设置输出详细程度，后面跟着日志级别的整数，该整数介于 0 和 9 之间。 Kubernetes 文档中描述了一般的 Kubernetes 日志约定和相关的日志级别：[`kubernetes.io/docs/reference/kubectl/cheatsheet/#kubectl-output-verbosity-and-debugging`](https://kubernetes.io/docs/reference/kubectl/cheatsheet/#kubectl-output-verbosity-and-debugging)。

将输出详细信息以特定格式获取是有用的，方法是在命令中添加以下参数之一：

+   `-o=wide` 用于获取资源的附加信息。示例如下：

```
$ kubectl get nodes -owide
NAME STATUS ROLES AGE VERSION INTERNAL-IP EXTERNAL-IP OS-IMAGE KERNEL-VERSION CONTAINER-RUNTIME
ip-192-168-41-120.us-west-2.compute.internal Ready <none> 84m v1.13.8-eks-cd3eb0 192.168.41.120 34.210.108.135 Amazon Linux 2 4.14.133-113.112.amzn2.x86_64 docker://18.6.1
ip-192-168-6-128.us-west-2.compute.internal Ready <none> 84m v1.13.8-eks-cd3eb0 192.168.6.128 18.236.119.52 Amazon Linux 2 4.14.133-113.112.amzn2.x86_64 docker://18.6.1
```

+   `-o=yaml` 用于以 YAML 格式返回输出。示例如下：

```
$ kubectl get pod nginx-deployment-5c689d88bb-qtvsx -oyaml
apiVersion: v1
kind: Pod
metadata:
 annotations:
 kubernetes.io/limit-ranger: 'LimitRanger plugin set: cpu request for container
 nginx'
 creationTimestamp: 2019-09-25T04:54:20Z
 generateName: nginx-deployment-5c689d88bb-
 labels:
 app: nginx
 pod-template-hash: 5c689d88bb
 name: nginx-deployment-5c689d88bb-qtvsx
 namespace: default
...
```

正如您所看到的，`-o=yaml`参数的输出也可以用来从现有资源创建清单文件。

## 另请参阅

+   kubectl 命令的概述和详细用法：[`kubernetes.io/docs/reference/kubectl/overview/`](https://kubernetes.io/docs/reference/kubectl/overview/)

+   kubectl 速查表：[`kubernetes.io/docs/reference/kubectl/cheatsheet/`](https://kubernetes.io/docs/reference/kubectl/cheatsheet/)

+   Kubernetes 部署故障排除的可视化指南：[`learnk8s.io/a/troubleshooting-kubernetes.pdf`](https://learnk8s.io/a/troubleshooting-kubernetes.pdf)

+   K9s – 用时尚的 Kubernetes CLI 管理您的集群：[`github.com/derailed/k9s`](https://github.com/derailed/k9s)


# 第二章：在 Kubernetes 上操作应用程序

在本章中，我们将讨论可用于在 Kubernetes 上部署云原生应用程序的供应工具。您将学习如何使用最流行的生命周期管理选项在 Kubernetes 上部署 DevOps 工具和 CI/CD（持续集成/持续交付或持续部署）基础设施。您将掌握执行第 1 天和第 2 天的操作的技能，例如安装、升级和版本控制部署，排除新应用程序，并在不再需要时删除部署。

在本章中，我们将涵盖以下主题：

+   使用 YAML 文件部署工作负载

+   使用自定义部署工作负载

+   使用 Helm 图表部署工作负载

+   使用 Kubernetes 运算符部署和操作应用程序

+   部署和管理 Jenkins X 的生命周期

+   部署和管理 GitLab 的生命周期

# 技术要求

本节中的配方假设您已部署了一个功能齐全的 Kubernetes 集群，遵循第一章中描述的推荐方法之一。

Kubernetes 操作工具 kubectl 将用于本节中其余的配方，因为它是针对 Kubernetes 集群运行命令的主要命令行界面。如果您使用 Red Hat OpenShift 集群，可以将 kubectl 替换为 oc，并且所有命令预计将类似地运行。

# 使用 YAML 文件部署工作负载

在本节中，我们将创建在 Kubernetes 中部署应用程序所需的资源配置。您将学习如何创建 Kubernetes 清单，部署工作负载，并使用 YAML 文件推出新版本。

## 准备工作

在开始之前，请克隆本章中使用的示例存储库：

```
$ git clone https://github.com/k8sdevopscookbook/src.git
```

确保您已准备好一个 Kubernetes 集群，并配置 kubectl 以管理集群资源。

## 操作步骤

本节进一步分为以下子节，以便简化流程：

+   创建部署

+   验证部署

+   编辑部署

+   回滚部署

+   删除部署

### 创建部署

这个教程将带您按照说明创建一个使用清单文件的部署，该文件保持一组 pod 运行。部署用于声明应该运行多少个 pod 的副本。部署可以进行扩展和缩减；我们将在第七章中更多地了解这个主题，*扩展和升级* *应用程序*。

让我们执行以下步骤：

1.  切换到`src/chapter2/yaml/`目录，这里是本教程的示例文件所在的位置：

```
$ cd src/chapter2/yaml/
```

1.  查看部署清单：

```
$ cat deployment-nginx.yaml
apiVersion: apps/v1
kind: deployment
metadata:
 name: nginx-deployment
 labels:
 app: nginx
spec:
 replicas: 2
 selector:
 matchLabels:
 app: nginx
# actual file is longer, shortened to show structure of the file only
```

YAML 是对空格敏感的。查看示例文件以了解文件的结构。您会发现 YAML 文件不使用制表符，而是使用空格字符。

如果有疑问，请使用 YAML 文件的 linter。

1.  通过应用 YAML 清单创建一个部署：

```
$ kubectl apply -f deployment-nginx.yaml
```

在运行了上述命令之后，YAML 清单中提到的容器镜像将从容器注册表中拉取，并且应用程序将按照部署清单中定义的方式在您的 Kubernetes 集群中安排。现在您应该能够通过以下教程来验证部署。

### 验证部署

这个教程将带您按照说明验证部署的状态，并在需要时进行故障排除。

让我们执行以下步骤：

1.  通过观察部署状态来确认部署状态显示了一个“成功部署”消息：

```
$ kubectl rollout status deployment nginx-deployment
deployment "nginx-deployment" successfully rolled out
```

1.  验证`DESIRED`和`CURRENT`值的数量是否相等，在我们的情况下是`2`：

```
$ kubectl get deployments
NAME             DESIRED CURRENT UP-TO-DATE AVAILABLE AGE
nginx-deployment 2       2       2          2         2m40s
```

1.  最后，还要检查作为部署的一部分部署的 ReplicaSets（`rs`）和`pods`：

```
$ kubectl get rs,pods
NAME                              DESIRED CURRENT READY AGE
nginx-deployment-5c689d88bb       2       2       2      28m
NAME                              READY STATUS  RESTARTS AGE
nginx-deployment-5c689d88bb-r2pp9 1/1   Running 0        28m
nginx-deployment-5c689d88bb-xsc5f 1/1   Running 0        28m
```

现在您已经验证了新的部署成功部署并运行。在生产环境中，您还需要编辑、更新和扩展现有的应用程序。在下一个教程中，您将学习如何对现有的部署执行这些修改操作。

### 编辑部署

这个教程将带您按照说明编辑现有的 Kubernetes 对象，并学习在需要时如何更改部署对象的参数。

让我们执行以下步骤：

1.  编辑部署对象并将容器镜像从 nginx 1.7.9 更改为 nginx 1.16.0：

```
$ kubectl edit deployment nginx-deployment
```

1.  您可以看到，部署首先进入挂起终止状态，然后在运行以下命令后，部署状态显示了一个“成功部署”的消息：

```
$ kubectl rollout status deployment nginx-deployment
Waiting for deployment "nginx-deployment" rollout to finish: 1 old replicas are pending termination...
deployment "nginx-deployment"
```

1.  确认您的部署通过创建新的 ReplicaSet 并将旧的 ReplicaSet 从`2`缩减到`0`来启动新的 pod：

```
$ kubectl get rs
NAME                        DESIRED CURRENT READY AGE
nginx-deployment-5c689d88bb 0       0       0     36m
nginx-deployment-f98cbd66f  2       2       2     46s
```

1.  我们将创建一个更改原因注释。以下命令将向您当前的部署添加在`kubernetes.io/change-cause`参数中定义的描述：

```
$ kubectl annotate deployment nginx-deployment kubernetes.io/change-cause="image updated to 1.16.0"
```

1.  现在，作为编辑部署的另一种替代方法，编辑`deployment-nginx.yaml`文件，并将副本从`replicas: 2`更改为`replicas: 3`，将`nginx:1.7.9`更改为`image: nginx:1.17.0`：

```
$ nano deployment-nginx.yaml
```

1.  通过应用更新后的 YAML 清单来更新部署。此步骤将应用用于部署的镜像标记的更改以及我们在*步骤 5*中增加的副本数：

```
$ kubectl apply -f deployment-nginx.yaml
```

1.  通过创建新的 ReplicaSet 并将旧的 pod 缩减到新的 pod 来确认您的部署正在启动新的 pod：

```
$ kubectl get rs
NAME                        DESIRED CURRENT READY AGE
nginx-deployment-5c689d88bb 0       0       0     56m
nginx-deployment-5d599789c6 3       3       3     15s
nginx-deployment-f98cbd66f  0       0       0     20m
```

1.  通过定义我们使用`kubernetes.io/change-cause`参数所做的更改来创建另一个更改原因注释：

```
$ kubectl annotate deployment nginx-deployment kubernetes.io/change-cause="image updated to 1.17.0 and scaled up to 3 replicas"
```

现在您已经学会了如何编辑、扩展，并使用 ReplicaSet 发布应用程序的新版本。

### 回滚部署

本教程将带您按照说明审查所做的更改，并通过比较注释回滚部署到旧的修订版本。

让我们执行以下步骤：

1.  检查部署的详细信息和事件，并注意最近的`ScalingReplicaSet`事件：

```
$ kubectl describe deployments
```

1.  现在，显示部署的发布历史。输出将显示修订版本以及我们创建的注释：

```
$ kubectl rollout history deployment nginx-deployment
deployment.extensions/nginx-deployment
REVISION CHANGE-CAUSE
1        <none>
2        image updated to 1.16.0
3        image updated to 1.17.0 and scaled up to 3 replicas
```

1.  回滚最后一次发布。此命令将使您的部署回到上一个修订版本，在本示例中为修订版本 2：

```
$ kubectl rollout undo deployment nginx-deployment
deployment.apps/nginx-deployment rolled back
```

1.  确认部署已回滚到上一个版本：

```
$ kubectl get rs
NAME                        DESIRED CURRENT READY AGE
nginx-deployment-5c689d88bb 0       0       0     69m
nginx-deployment-5d599789c6 0       0       0     12m
nginx-deployment-f98cbd66f  3       3       3     33m
```

请注意，回滚命令只会将部署回滚到不同的镜像版本发布，并不会撤消其他规范更改，例如副本的数量。

1.  现在，回滚到特定的修订版本。此命令将使您的部署回到使用`--to-revision`参数定义的特定修订版本：

```
$ kubectl rollout undo deployment nginx-deployment --to-revision=1
```

现在您已经学会了如何查看发布历史并在需要时回滚更改。

### 删除部署

Kubernetes 根据资源的可用性在工作节点上调度资源。如果您使用的是 CPU 和内存资源有限的小集群，您可能会很容易耗尽资源，这将导致新的部署无法在工作节点上调度。因此，除非在配方的要求中提到，否则在继续下一个配方之前始终清理旧的部署。

让我们执行以下步骤来删除`nginx-deployment`：

1.  在继续下一个步骤之前，请删除部署：

```
$ kubectl delete deployment nginx-deployment
```

上述命令将立即终止部署并从集群中删除应用程序。

## 工作原理...

*创建部署*的步骤向您展示了如何使用 YAML 清单文件将您的 Pod 和 ReplicaSets 的期望状态应用到部署控制器。

在第 2 步中，我们使用了`kubectl apply`命令，这是声明性管理方法的一部分，它进行增量更改而不是覆盖它们。第一次创建资源意图时，您可以使用`kubectl create`命令，这被认为是一种命令式管理方法。

我更喜欢使用`apply`命令，因为它允许声明性模式，而不是`create`，因为它更适合创建 CI 脚本，并且如果资源已经存在，则不会引发错误。

现在您已经学会了在 Kubernetes 中运行单个部署的基本步骤，我们可以继续进行更复杂的部署用例，使用 Kustomize、Helm 和 Operator 框架来组成一系列对象。

## 另请参阅

+   YAML 文件的语法检查器：[`github.com/adrienverge/yamllint`](https://github.com/adrienverge/yamllint)

+   在线 Kubernetes YAML 验证器：[`kubeyaml.com/`](https://kubeyaml.com/)

+   阅读更多关于使用配置文件进行 Kubernetes 对象的声明性管理：[`kubernetes.io/docs/tasks/manage-kubernetes-objects/declarative-config/`](https://kubernetes.io/docs/tasks/manage-kubernetes-objects/declarative-config/)

+   编写 Kubernetes 清单指南：[`github.com/bitnami/charts/blob/master/_docs/authoring-kubernetes-manifests.md`](https://github.com/bitnami/charts/blob/master/_docs/authoring-kubernetes-manifests.md)

# 使用 Kustomize 部署工作负载

在本节中，我们将向您展示如何从文件生成资源，并在 Kubernetes 中组成和自定义资源集合。您将了解使用 Kustomize 进行 Kubernetes 对象的声明性管理。

## 做好准备

确保您已准备好一个 Kubernetes 集群，并配置了`kubectl`来管理集群资源。

本节中创建的源文件可以在我的 GitHub 存储库中找到，位于[`github.com/k8sdevopscookbook/src/tree/master/chapter2/kustomize`](https://github.com/k8sdevopscookbook/src/tree/master/chapter2/kustomize)。建议您按照说明创建和编辑它们，并且只在遇到问题时使用存储库中的文件与您的文件进行比较。

## 操作步骤如下…

本节进一步分为以下小节，以便简化流程：

+   验证 Kubernetes 集群版本

+   从文件生成 Kubernetes 资源

+   为开发和生产部署创建一个基础

### 验证 Kubernetes 集群版本

为了使 Kustomize 正常运行，需要 Kubernetes 集群版本 1.14.0 或更高版本，因为 Kustomize 支持仅包含在 kubectl v.1.14.0 及更高版本中。

1.  列出节点以确认您的 Kubernetes 集群版本，并确保其为 1.14.0 或更高版本：

```
$ kubectl get nodes
 NAME STATUS ROLES AGE VERSION
 ip-172-20-112-25.ec2.internal Ready master 7h19m v1.15.0
 ip-172-20-126-108.ec2.internal Ready node 7h18m v1.15.0
 ip-172-20-51-209.ec2.internal Ready node 7h18m v1.15.0
 ip-172-20-92-89.ec2.internal Ready node 7h19m v1.15.0
```

在上面的例子中，版本显示为`v1.15.0`。

### 从文件生成 Kubernetes 资源

让我们学习如何使用 Kustomize 定制我们在上一个配方中做的 nginx 滚动：

1.  创建一个名为`nginx`的目录：

```
$ mkdir nginx
```

1.  将您在“使用 YAML 文件部署工作负载”配方中创建的`deployment-nginx.yaml`文件复制到`nginx`目录下。这个文件仍然使用`image: nginx:1.7.9`作为容器镜像：

```
$ cp deployment-nginx.yaml ./nginx/
```

1.  通过指定新的镜像版本创建一个`kustomization.yaml`文件：

```
$ cat <<EOF >./nginx/kustomization.yaml
apiVersion: kustomize.config.k8s.io/v1beta1
kind: Kustomization
resources:
- deployment-nginx.yaml
images:
 - name: nginx
 newName: nginx
 newTag: 1.16.0
commonAnnotations:
 kubernetes.io/change-cause: "Initial deployment with 1.16.0"
EOF
```

1.  通过运行以下命令检查新版本是否被注入到您的部署中。在输出中，您将看到`image: nginx:1.16.0`，而不是我们之前在`deployment-nginx.yaml`文件中使用的原始镜像版本`nginx:1.7.9`：

```
$ kubectl kustomize ./nginx/
```

1.  使用`-k`参数应用定制的部署：

```
$ kubectl apply -k nginx
```

1.  通过指定一个更新的镜像版本创建一个新的`kustomization.yaml`文件：

```
$ cat <<EOF > nginx/kustomization.yaml
apiVersion: kustomize.config.k8s.io/v1beta1
kind: Kustomization
resources:
 - deployment-nginx.yaml
images:
 - name: nginx
 newName: nginx
 newTag: 1.17.0
commonAnnotations:
 kubernetes.io/change-cause: "image updated to 1.17.0"
EOF
```

1.  使用`-k`参数应用定制的部署：

```
$ kubectl apply -k nginx
```

1.  现在，显示部署的滚动历史：

```
$ kubectl rollout history deployment nginx-deployment
deployment.extensions/nginx-deployment
REVISION CHANGE-CAUSE
1        Initial deployment with 1.16.0
2        image updated to 1.17.0
```

现在您已经学会了如何使用 Kustomize 编辑、扩展，并通过 Kustomize 推出应用的新版本。

### 为开发和生产部署创建一个基础

让我们执行以下步骤来创建一个本地 Docker 镜像注册表部署的基础，我们将在本章后面使用：

1.  创建一个名为`registry`的目录，并在其下创建一个名为`base`的目录：

```
$ mkdir registry && mkdir registry/base
```

1.  在`registry/base`下，从示例存储库中下载名为`deployment-registry.yaml`的部署文件：

```
$ cd registry/base/
$ wget https://raw.githubusercontent.com/k8sdevopscookbook/src/master/chapter2/kustomize/registry/base/deployment-registry.yaml
```

1.  查看文件以了解其结构。您将看到它是一个包含两个名为`registry`和`registryui`的容器的`Deployment`清单。您将看到注册表容器有一个名为`registry-storage`的`volumeMount`，这个卷是由名为`registry-pvc`的持久卷声明提供的：

```
$ cat deployment-registry.yaml
apiVersion: extensions/v1beta1
kind: Deployment
# actual file is longer, shortened to highlight important structure of the file only
 - image: registry:2
#....#
 - name: registry-storage
 mountPath: /var/lib/registry
#....#
 - name: registryui
 image: hyper/docker-registry-web:latest
#....#
 - name: registry-storage
 persistentVolumeClaim:
 claimName: registry-pvc
```

1.  在相同的`registry/base`下，从示例存储库中下载名为`service-registry.yaml`的服务清单文件：

```
$ wget https://raw.githubusercontent.com/k8sdevopscookbook/src/master/chapter2/kustomize/registry/base/service-registry.yaml
```

1.  查看文件以了解其结构。您将看到这是一个服务清单，它在每个节点的 IP 上以静态端口暴露服务；在这个示例中，`registry`服务的端口为`5000`，`registry-ui`服务的端口为`80`：

```
$ cat <<EOF > registry/base/service-registry.yaml
kind: Service
# actual file is longer, shortened to highlight important structure of the file only
 type: NodePort
 ports:
 - name: registry
 port: 5000
 protocol: TCP 
 nodePort: 30120
 - name: registry-ui
 port: 80
 protocol: TCP
 nodePort: 30220 
#....#
```

1.  创建一个名为`pvc-registry.yaml`的`PersistentVolumeClaim`清单文件，内容如下：

```
$ cat <<EOF > registry/base/pvc-registry.yaml
apiVersion: v1
kind: PersistentVolumeClaim
metadata:
 name: registry-pvc
 labels:
 app: kube-registry-pv-claim
spec:
 accessModes:
 - ReadWriteOnce
 resources:
 requests:
 storage: 10G
EOF
```

此时，您可以使用`kubectl apply -f registry/base`来部署`registry`目录下的所有资源文件。但是，每当您需要更改资源中的参数，比如`app`或`label`时，您需要编辑这些文件。使用 Kustomize 的整个目的是利用重用文件而无需修改文件的源。

1.  最后，创建`kustomization.yaml`文件。以下命令将创建 Kustomize 资源内容，其中包括我们之前创建的三个单独的清单文件：

```
$ cat <<EOF >./registry/base/kustomization.yaml
apiVersion: kustomize.config.k8s.io/v1beta1
kind: Kustomization
resources:
 - deployment-registry.yaml
 - service-registry.yaml
 - pvc-registry.yaml
EOF
```

1.  现在，创建两个用于开发和生产部署的叠加层。第一个是用于开发的：

```
$ mkdir registry/overlays && mkdir registry/overlays/dev 
$ cat <<EOF >./registry/overlays/dev/kustomization.yaml
apiVersion: kustomize.config.k8s.io/v1beta1
kind: Kustomization
bases:
 - ../../base
namePrefix: dev-
commonAnnotations:
 note: Hello, I am development!
EOF
```

1.  第二个清单将为生产创建叠加层：

```
$ mkdir registry/overlays/prod
$ cat <<EOF >./registry/overlays/prod/kustomization.yaml
apiVersion: kustomize.config.k8s.io/v1beta1
kind: Kustomization
bases:
 - ../../base
namePrefix: prod-
commonAnnotations:
 note: Hello, I am production!
EOF
```

1.  检查`dev`和`prod`前缀是否注入到您的部署中。当您指向`prod`文件夹时，注释说明将显示“你好，我是生产！”：

```
$ kubectl kustomize ./registry/overlays/prod/
# result shortened to highlight the annotation
metadata:
 annotations:
 note: Hello, I am production!
 labels:
 app: kube-registry-pv-claim
 name: prod-registry-pvc
#...#
```

1.  当您指向`dev`文件夹时，注释说明将显示“你好，我是开发！”：

```
$ kubectl kustomize ./dev/
... # removed
metadata:
 annotations:
 note: Hello, I am development!
 labels:
 app: kube-registry-pv-claim
 name: dev-registry-pvc
... # removed
```

1.  现在，部署您应用的`dev`版本：

```
$ kubectl apply -k ./registry/overlays/dev
```

同样，您可以注入标签，修补图像版本，更改副本的数量，并将资源部署到不同的命名空间。

## 它是如何工作的...

这个示例向您展示了如何使用 Git 管理和实现配置文件的基本版本控制。

在*为开发和生产部署创建基础*配方中，我们在`base`目录下创建的资源代表应用程序/工作负载的上游存储库，而在`overlay`目录下在第 8 步和第 10 步之间创建的自定义内容是您在存储库中控制和存储的更改。

稍后，如果您需要查看变体的差异，可以使用以下`diff`参数：

```
$ kubectl diff -k registry/overlays/prod/
```

通过将更改与基础分离，我们能够为多种目的定制无模板的 YAML 文件，保持原始 YAML 文件不变，从而实现源和更改的版本控制。

## 另请参阅

+   Kustomize 概念概述幻灯片：[`speakerdeck.com/spesnova/introduction-to-kustomize`](https://speakerdeck.com/spesnova/introduction-to-kustomize)

+   Kubernetes 背景下的声明式应用程序管理白皮书-强烈推荐阅读：[`goo.gl/T66ZcD`](https://goo.gl/T66ZcD)

+   Kustomize 中的常见术语：[`github.com/kubernetes-sigs/kustomize/blob/master/docs/glossary.md`](https://github.com/kubernetes-sigs/kustomize/blob/master/docs/glossary.md)

+   其他 Kustomize 示例：[`github.com/kubernetes-sigs/kustomize/tree/master/examples`](https://github.com/kubernetes-sigs/kustomize/tree/master/examples)

# 使用 Helm 图表部署工作负载

在本节中，我们将向您展示如何在 Kubernetes 中使用 Helm 图表。Helm 是 Kubernetes 的软件包管理器，可帮助开发人员和 SRE 轻松打包、配置和部署应用程序。

您将学习如何在集群上安装 Helm 并使用 Helm 来管理第三方应用程序的生命周期。

## 准备工作

确保您已准备好 Kubernetes 集群，并配置了`kubectl`来管理集群资源。

## 如何做…

本节进一步分为以下子节，以便简化流程：

+   安装 Helm 2.x

+   使用 Helm 图表安装应用程序

+   在 Helm 存储库中搜索应用程序

+   使用 Helm 更新应用程序

+   使用 Helm 回滚应用程序

+   添加新的 Helm 存储库

+   使用 Helm 删除应用程序

+   构建 Helm 图表

### 安装 Helm 2.x

让我们执行以下步骤来配置先决条件并安装 Helm：

1.  使用以下命令创建`ServiceAccount`：

```
$ cat <<EOF | kubectl apply -f -
apiVersion: v1
kind: ServiceAccount
metadata:
 name: tiller
 namespace: kube-system
EOF
```

1.  使用以下命令创建`ClusterRoleBinding`：

```
$ cat <<EOF | kubectl apply -f -
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
 name: tiller
roleRef:
 apiGroup: rbac.authorization.k8s.io
 kind: ClusterRole
 name: cluster-admin
subjects:
 - kind: ServiceAccount
 name: tiller
 namespace: kube-system
EOF
```

1.  下载 Helm 安装脚本。此`install-helm.sh`脚本将检测系统的架构并获取最新的正确二进制文件以安装 Helm：

```
$ curl https://raw.githubusercontent.com/kubernetes/helm/master/scripts/get > install-helm.sh
```

1.  运行脚本安装 Helm。以下命令将安装运行 Helm 所需的两个重要二进制文件 Helm 和 Tiller：

```
$ chmod u+x install-helm.sh && ./install-helm.sh
```

1.  运行`init`参数以使用我们在第 1 步创建的服务帐户配置 Helm。`--history-max`参数用于清除和限制 Helm 历史记录，因为如果没有此设置，历史记录可能会无限增长并引起问题：

```
$ helm init --service-account tiller --history-max 200
```

此过程将在您的集群中安装 Helm 服务器端组件 Tiller。

如果收到`Tiller 已经安装在集群中`的消息，可以在命令的末尾添加`--upgrade`参数运行相同的命令，并强制升级现有版本。

1.  通过运行以下命令确认 Helm 版本：

```
$ helm version --short
```

在撰写本文时，Helm 的最新稳定版本是 v2.15.1，下一个版本 Helm 3 仍处于测试阶段。在接下来的章节和配方中，我们将基于 Helm 2.x 版本进行指导。

### 使用 Helm 图表安装应用程序

让我们执行以下步骤，从官方 Helm 存储库位置安装 Helm 图表：

1.  在安装图表之前，始终同步存储库以获取最新内容。否则，您可能会得到旧版本的 Helm 图表：

```
$ helm repo update
```

1.  安装示例图表，例如`stable/mysql`：

```
$ helm install --name my-mysqlrelease stable/mysql
```

同样，您可以从 Helm 图表稳定存储库安装其他应用程序，或者添加自己的存储库以获取自定义图表。

每次安装图表时，都会创建一个具有随机名称的新发布，除非使用`--name`参数指定。现在，列出发布：

```
$ helm ls
NAME            REVISION UPDATED                 STATUS   CHART         APP VERSION NAMESPACE
my-mysqlrelease 1        Thu Aug 8 02:30:27 2019 DEPLOYED mysql-1.3.0 5.7.14        default
```

1.  检查发布状态，在我们的示例中是`my-mysqlrelease`：

```
$ helm status my-mysqlrelease
```

您将获得部署状态和所有资源的信息。

### 在 Helm 存储库中搜索应用程序

让我们执行以下步骤，从 Helm 图表存储库中搜索要在 Kubernetes 上部署的应用程序：

1.  在存储库中搜索图表。以下命令将在您可以访问的 Helm 存储库中查找您搜索的词语：

```
$ helm search redis
NAME CHART VER APP VER DESCRIPTION 
stable/prometheus-redis-exporter 3.0.0 1.0.3 Prometheus export
stable/redis 9.0.1 5.0.5 Open source, adva
stable/redis-ha 3.6.2 5.0.5 Highly available 
stable/sensu 0.2.3 0.28 Sensu monitoring 
```

您可以在 helm/stable 中找到所有工作负载的完整列表，并在以下 GitHub 链接的存储库中找到源代码：[`github.com/helm/charts/tree/master/stable `](https://github.com/helm/charts/tree/master/stable)

1.  您的`search`关键字不一定要是项目的确切名称。您还可以搜索关键字，如`Storage`、`MQ`或`Database`：

```
$ helm search storage
NAME                 CHART VERSION APP VERSION DESCRIPTION ...
stable/minio         2.5.4 RELEASE.2019-07-17T22-54-12Z MinIO is a hi
stable/nfs-server-pr 0.3.0 2.2.1-k8s1.12 nfs-server-provisioner is an
stable/openebs       1.0.0 1.0.0 Containerized Storage for Containers
```

默认情况下，您的存储库列表仅限于`helm/stable`位置，但稍后在*添加新的 Helm 存储库*配方中，您还将学习如何添加新的存储库以扩展您的搜索范围到其他存储库。

### 使用 Helm 升级应用程序

有几种使用升级的方法。让我们执行以下步骤：

1.  升级发布，在我们的例子中是`my-mysqlrelease`，使用更新的图表版本：

```
$ helm upgrade my-mysqlrelease stable/mysql
```

1.  在将来，您可能会发现应用程序的特定版本在您的环境中更加稳定，或者在多个集群中保持安装的一致。在这种情况下，您可以使用以下命令使用您偏好的图表版本更新图表版本：

```
$ helm upgrade my-mysqlrelease stable/mysql --version 1.2.0
```

1.  使用以下命令确认图表版本更改。在第 2 步升级版本后，您应该期望看到`mysql --version 1.2.0`：

```
$ helm ls
NAME            REVISION UPDATED                  STATUS   CHART       APP VERSION NAMESPACE
my-mysqlrelease 3        Tue Jul 30 22:44:07 2019 DEPLOYED mysql-1.2.0 5.7.14      default
```

1.  使用以下命令查看修订历史。由于我们最近更新了图表版本，您应该在历史记录中看到至少两个修订版本：

```
$ helm history my-mysqlrelease stable/mysql
REV UPDATED             STATUS     CHART       DESCRIPTION
1   Oct 1 22:47:37 2019 SUPERSEDED mysql-1.3.3 Install complete
2   Oct 1 22:57:32 2019 SUPERSEDED mysql-1.3.3 Upgrade complete
3   Oct 1 23:00:44 2019 DEPLOYED   mysql-1.2.0 Upgrade complete
```

1.  使用`helm upgrade`函数通过使用`--set key=value[,key=value]`参数指定参数来更新现有发布上的参数。以下命令将使用`--set mysqlRootPassword`参数设置两个 MySQL 密码：

```
$ helm upgrade my-mysqlrelease stable/mysql --version 1.2.0 --set mysqlRootPassword="MyNevvPa55w0rd"
```

1.  确认密码实际上已更新。您应该期望得到与第 4 步设置的相同密码：

```
$ kubectl get secret --namespace default my-mysqlrelease -o jsonpath="{.data.mysql-root-password}" | base64 --decode; echo
MyNevvPa55w0rd
```

现在您已经学会了如何使用新参数升级 Helm 发布。

### 使用 Helm 回滚应用程序

让我们执行以下步骤，撤消升级并将应用程序状态恢复到先前的修订版本：

1.  列出您的发布的修订历史，例如`coy-jellyfish`：

```
$ helm history my-mysqlrelease
REV UPDATED                 STATUS     CHART       DESCRIPTION
1   Tue Oct 1 22:47:37 2019 SUPERSEDED mysql-1.3.3 Install complete
2   Tue Oct 1 22:57:32 2019 SUPERSEDED mysql-1.3.3 Upgrade complete
3   Tue Oct 1 23:00:44 2019 SUPERSEDED mysql-1.2.0 Upgrade complete
4   Tue Oct 1 23:07:23 2019 SUPERSEDED mysql-1.3.3 Upgrade complete
5   Tue Oct 1 23:10:39 2019 DEPLOYED   mysql-1.2.0 Upgrade complete
```

1.  假设您需要从最后一次升级回滚到修订版本`4`。回滚到特定的修订版本：

```
$ helm rollback my-mysqlrelease 4
Rollback was a success.
```

1.  修订历史将更新以反映您的回滚：

```
$ helm history my-mysqlrelease
 REV UPDATED                  STATUS     CHART       DESCRIPTION
...
 5   Tue Jul 30 22:44:07 2019 SUPERSEDED mysql-1.2.0 Upgrade complete
 6   Tue Jul 30 23:11:52 2019 DEPLOYED   mysql-1.3.0 Rollback to 4
```

现在您已经学会了如何查看发布历史并在需要时回滚 Helm 发布。

### 使用 Helm 删除应用程序

让我们执行以下步骤，从您的 Kubernetes 集群中使用 Helm 删除部署的应用程序：

1.  使用`helm ls`命令和`--all`参数列出所有发布，包括已删除的修订版本：

```
helm ls --all
NAME REVISION UPDATED STATUS CHART APP VERSION NAMESPACE
my-mysqlrelease 6 Thu Aug 8 02:34:13 2019 DEPLOYED mysql-1.3.0 5.7.14 default
```

1.  使用`--purge`参数删除一个发布。以下命令将完全从您的集群中删除应用程序：

```
helm delete --purge my-mysqlrelease
```

上述命令将立即终止部署并从集群中删除 Helm 发布。

### 添加新的 Helm 存储库

默认情况下，Helm 只使用官方的 Helm/stable 存储库进行查找，通常在接下来的章节中，我们需要使用本教程中解释的方法从第三方供应商那里添加额外的存储库。

让我们执行以下步骤来将额外的 Helm 存储库添加到你的源列表中：

1.  检查现有存储库的列表。你应该只能看到列表上的`stable`和`local`：

```
$ helm repo list
 NAME   URL
 stable https://kubernetes-charts.storage.googleapis.com
 local  http://127.0.0.1:8879/charts
```

1.  我们需要为我们的存储库服务器配置一个持久卷和认证。使用以下内容创建一个名为`customhelmrepo.yaml`的文件：

```
cat <<EOF >customhelmrepo.yaml
env:
 open:
 STORAGE: local
persistence:
 enabled: true
 accessMode: ReadWriteOnce
 size: 10Gi
 secret:
 BASIC_AUTH_USER: helmcurator
 BASIC_AUTH_PASS: myhelmpassword
EOF
```

1.  使用持久卷创建一个存储库服务器：

```
$ helm install --name my-chartmuseum -f customhelmrepo.yaml stable/chartmuseum
```

1.  获取`chartmuseum`的服务 IP。以下命令将返回一个 IP 地址，在我们的例子中是`10.3.0.37`：

```
$ kubectl get svc --namespace default -l "app=chartmuseum" -l \
"release=my-chartmuseum" -o jsonpath="{.items[0].spec.clusterIP}"; echo
10.3.0.37
```

1.  将新的 Helm 存储库添加到你的存储库列表中；在我们的例子中，IP 是`10.3.0.37`：

```
$ helm repo add chartmuseum http://10.3.0.37:8080
```

1.  检查现有存储库的列表：

```
$ helm repo list
NAME        URL
stable      https://kubernetes-charts.storage.googleapis.com
local       http://127.0.0.1:8879/charts
chartmuseum http://10.3.0.37:8080
```

有许多选项可用于托管你的图表存储库。你可以使用一个名为 ChartMuseum 的开源 Helm 存储库服务器部署一个本地存储库，也可以使用 S3 存储桶、GitHub 页面或经典的 Web 服务器。为了简单起见，我们使用 Helm 本身来部署服务器。你可以在*另请参阅*部分找到 Helm 图表的替代托管方法。

### 构建一个 Helm 图表

让我们执行以下步骤来构建一个自定义的 Helm 图表，以便发布到你的本地`chartmuseum`存储库中：

1.  创建一个名为`mychart`的图表：

```
$ helm create mychart
```

1.  根据你的喜好编辑你的图表结构并测试模板可能出现的错误：

```
$ helm lint ./mychart
==> Linting ./mychart
[INFO] Chart.yaml: icon is recommended
1 chart(s) linted, no failures
```

1.  使用`--dry-run`测试你的应用程序：

```
$ helm install ./mychart --debug --dry-run
```

4. 构建 Helm 图表。通过运行以下命令，你将从`mychart`位置生成一个 Helm 存储库的 tarball 包：

```
$ helm package .
```

1.  用你的 Helm 服务器替换 Helm 存储库服务器地址，并使用 URL 上传这个 Helm 图表包：

```
$ cd mychart && curl --data-binary "@mychart-0.1.0.tgz" http://10.3.0.37:8080/api/charts
```

现在你已经学会了如何创建、清理、测试、打包和上传你的新图表到本地基于 ChartMuseum 的 Helm 存储库。

## 它是如何工作的...

这个教程向你展示了如何安装 Helm 包管理器并构建你的第一个 Helm 图表。

当我们在*构建 Helm 图表*教程中构建 Helm 图表时，在第 1 步中，`helm create`命令在`chart`文件夹下创建了一些文件作为模板。你可以通过编辑这些文件或者在你对结构更加熟悉时从头开始创建它们。

`helm create`命令创建了构建我们 Helm 图表的模板。这里解释了内容及其功能：

```
mychart 
├── Chart.yaml          --> Description of the chart
├── charts              --> Directory for chart dependencies
├── mychart-0.1.0.tgz   --> Packaged chart following the SemVer 2 standard
├── templates           --> Directory for chart templates
│   ├── NOTES.txt       --> Help text displayed to users
│   ├── _helpers.tpl    --> Helpers that you can re-use 
│   ├── deployment.yaml --> Application - example deployment
│   ├── service.yaml    --> Application - example service endpoint
└── values.yaml         --> Default values for a chart
```

在*构建 Helm 图表*的步骤中，在第 3 步`helm install`中，当与`--dry-run`参数一起使用时，会将图表发送到服务器，并返回渲染的模板，而不是安装它。这通常用于测试 Helm 图表。

在同一步骤中，在第 4 步中，`helm package`命令将您的完整图表打包成图表存档，基本上是一个 tarball。

在第 5 步中，我们使用`curl`命令将打包的 tarball 二进制文件发送到我们的 ChartMuseum 服务器，一个 HTTP 服务器，以便在接收到`helm`命令的`GET`请求时为我们提供 Helm 图表存档。

现在您已经学会了如何安装 Helm 图表并在本地存储库中创建您自己的 Helm 图表，您将能够安装下一章节中所需的第三方图表，以及在 CI/CD 流水线中构建您自己的构件。

## 另请参阅

+   Helm 文档：[`docs.helm.sh`](https://docs.helm.sh)

+   Helm 图表的替代托管方法：https://v2.helm.sh/docs/chart_repository/

+   使用图表模板入门：[`helm.sh/docs/chart_template_guide/`](https://helm.sh/docs/chart_template_guide/)

+   构建`Chart.yaml`文件所需的字段：[`v2.helm.sh/docs/chart_template_guide/`](https://v2.helm.sh/docs/chart_template_guide/)

+   J-Frog 容器注册表，一个强大的混合 Docker 和 Helm 注册表：[`jfrog.com/container-registry/`](https://jfrog.com/container-registry/)

# 使用 Kubernetes 操作员部署和操作应用程序

Kubernetes 操作员是另一种在 Kubernetes 上打包、部署和管理应用程序的方法。操作员比 Helm 等包管理器更复杂。操作员有助于消除手动步骤、特定于应用程序的准备工作和部署后步骤，甚至自动化用户的二天操作，如扩展或升级。

例如，一个应用程序的要求可能会根据其安装的平台而有所不同，或者可能需要更改其配置并与外部系统进行交互。

在本节中，我们将部署两个基于两种不同操作员框架的热门有状态应用程序的操作员，并了解它们提供了哪些功能。

## 准备工作

确保您已经准备好一个 Kubernetes 集群，并配置了`kubectl`来管理集群资源。

## 如何做…

该部分进一步分为以下子部分以简化流程：

+   安装**KUDO**（**Kubernetes 通用声明运算符**）和 KUDO kubectl 插件

+   使用 KUDO 安装 Apache Kafka 运算符

+   安装 Operator Lifecycle Manager

+   安装 Zalando PostgreSQL 运算符

### 安装 KUDO 和 KUDO kubectl 插件

在使用 KUDO 运算符安装应用程序之前，您需要安装 KUDO。我们将使用`brew`来安装 KUDO，这是 Linux 上用于简单安装二进制文件的软件包管理器；因此，如果您还没有安装`brew`，您也需要安装它：

1.  按照*使用 Helm 图表部署工作负载*中的 Helm 说明来运行 Helm。

1.  使用以下命令安装`brew`：

```
$ sh -c "$(curl -fsSL https://raw.githubusercontent.com/Linuxbrew/install/master/install.sh)"
$ PATH=/home/linuxbrew/.linuxbrew/bin/:$PATH
```

1.  通过运行以下命令使用`brew install`安装 KUDO 和`kudo kubectl`插件：

```
$ brew tap kudobuilder/tap && brew install kudo-cli
```

1.  按照以下方式安装 KUDO：

```
$ kubectl kudo init
```

值得一提的是，Kubernetes 运算符是 Kubernetes 社区中一个不断发展的概念。有多个运算符框架，例如 Red Hat Operator Framework、D2iQ 的 KUDO 等。此外，对于每个工作负载，您会发现社区开发了许多运算符。我建议在决定使用运算符之前测试几种不同的运算符，以找到适合您用例的运算符。

现在您已经安装了 KUDO 控制器，可以使用 Kubernetes Operators 测试一些有状态的运行应用程序。

### 使用 KUDO 安装 Apache Kafka Operator

在*另请参阅*部分列出了多个 Kafka 运算符，例如 Strimzi、Banzai Cloud、Confluent、krallistic 等。虽然在本文中我没有偏好，但作为示例，我们将基于 KUDO Operator 部署 Apache Kafka Operator。

让我们执行以下步骤：

1.  Kafka 需要 ZooKeeper。让我们创建一个 ZooKeeper 集群：

```
$ kubectl kudo install zookeeper --instance=zk
```

1.  使用 KUDO Kafka Operator 创建 Kafka 集群：

```
$ kubectl kudo install kafka --instance=kafka
```

1.  通过查询`Operators` CRD API 列出 KUDO 运算符如下。在部署 Kafka 之后，您还应该看到`kafka`和`zookeeper`运算符：

```
$ kubectl get Operators
NAME      AGE
kafka     9s
zookeeper 17s
```

1.  列出 KUDO 实例：

```
$ kubectl get instances
NAME  AGE
kafka 25s
zk    33s
```

现在您已经学会了如何使用 KUDO Operator 部署 ZooKeeper 和 Kafka。

### 安装 Operator Lifecycle Manager

在使用 Red Hat Operator Framework 运算符安装应用程序之前，您需要安装**Operator Lifecycle Manager**（**OLM**）。请注意，OLM 在 OpenShift 4.0 及更高版本中默认安装。

1.  安装 OLM。这是我们下一个配方*安装 Zalando PostgreSQL Operator*所需的：

```
$ kubectl create -f https://raw.githubusercontent.com/Operator-framework/Operator-lifecycle-manager/master/deploy/upstream/quickstart/crds.yaml
$ kubectl create -f https://raw.githubusercontent.com/Operator-framework/Operator-lifecycle-manager/master/deploy/upstream/quickstart/olm.yaml
```

现在您已经安装了 OLM 来测试使用 Operator Framework 运行一些有状态的应用程序。

### 安装 Zalando PostgreSQL Operator

在*另请参阅*部分列出了多个 PostgreSQL Operators，例如 CrunchyDB 和 Zalando。在本示例中，我们将部署 Zalando PostgreSQL Operator 来管理 Kubernetes 集群中的 PostgreSQL 部署的生命周期。

让我们执行以下步骤来使用 Operator Hub 部署 Zalando PostgreSQL Operator：

1.  从 Operator Hub 安装`postgres-Operator`：

```
$ kubectl create -f https://Operatorhub.io/install/postgres-Operator.yaml
```

1.  验证`postgres-Operator`是否正在运行：

```
$ kubectl get pods -n Operators
NAME                               READY STATUS  RESTARTS AGE
postgres-Operator-5cd9d99494-5nl5r 1/1   Running 0        3m56s
```

1.  现在 PostgreSQL Operator 已经启动运行，让我们部署 Postgres Operator UI：

```
$ kubectl apply -f https://raw.githubusercontent.com/k8sdevopscookbook/src/master/chapter2/postgres-Operator/ui/postgres-ui.yaml
```

1.  部署 PostgreSQL。以下命令将创建一个小的两实例 PostgreSQL 集群：

```
$ kubectl create -f https://raw.githubusercontent.com/zalando/postgres-Operator/master/manifests/minimal-postgres-manifest.yaml
```

1.  列出由 Zalando Operator 管理的 PostgreSQL 实例。它将显示一个名为`acid-minimal-cluster`的集群：

```
$ kubectl get postgresql
NAME                 TEAM VERSION PODS VOLUME CPU-REQUEST MEMORY-REQUEST AGE STATUS
acid-minimal-cluster acid 11      2    1Gi                               7s
```

1.  首先获取您的集群凭据，并使用`psql`交互式 PostgreSQL 终端连接到您的 PostgreSQL，如下所示：

```
$ export PGPASSWORD=$(kubectl get secret postgres.acid-minimal-cluster.credentials -o 'jsonpath={.data.password}' | base64 -d)
$ export PGSSLMODE=require
$ psql -U postgres
```

1.  删除您的 PostgreSQL 集群：

```
$ kubectl delete postgresql acid-minimal-cluster
```

现在您已经学会了如何简单地使用流行的 Kubernetes Operators 在 Kubernetes 上部署和管理工作负载。您可以稍后应用这些知识，以简化您在开发和生产环境中使用的有状态工作负载的生命周期管理。

## 另请参阅

+   在 KubeCon 2018 上深入了解 Kubernetes Operators：[`developers.redhat.com/blog/2018/12/18/kubernetes-Operators-in-depth/`](https://developers.redhat.com/blog/2018/12/18/kubernetes-operators-in-depth/)

+   社区提供的 Kubernetes Operators 列表：[`github.com/Operator-framework/awesome-Operators`](https://github.com/operator-framework/awesome-operators)

+   使用 Red Hat Operator SDK 构建的 Kubernetes Operators 列表：[`Operatorhub.io/`](https://operatorhub.io/)

+   **Kubernetes 通用声明 Operator**（**KUDO**）：[`kudo.dev/`](https://kudo.dev/)

+   基于 KUDO 的 Operators 的存储库：[`github.com/kudobuilder/Operators`](https://github.com/kudobuilder/operators)

+   一个 Python 框架，可以用几行代码编写 Kubernetes Operators：[`github.com/zalando-incubator/kopf`](https://github.com/zalando-incubator/kopf)

+   备用 Kafka Operators 列表：

+   在 OpenShift 上运行的 Apache Kafka Operator：[`strimzi.io/`](http://strimzi.io/)

+   KUDO Kafka Operator: [`github.com/kudobuilder/Operators/tree/master/repository/kafka`](https://github.com/kudobuilder/operators/tree/master/repository/kafka)

+   另一个用于 Kubernetes 的 Kafka Operator: [`github.com/banzaicloud/kafka-Operator`](https://github.com/banzaicloud/kafka-operator)

+   Istio Operator: [`github.com/banzaicloud/istio-Operator`](https://github.com/banzaicloud/istio-operator)

+   备用的 PostgreSQL Operator 列表：

+   Crunchy Data PostgreSQL Operator: [`github.com/CrunchyData/postgres-Operator`](https://github.com/CrunchyData/postgres-operator)

+   Zalando PostgreSQL Operator: [`github.com/zalando/postgres-Operator`](https://github.com/zalando/postgres-operator)

# 部署和管理 Jenkins X 的生命周期

Jenkins X 是一个开源解决方案，为软件开发人员提供管道自动化、内置 GitOps、CI、自动化测试和 CD，即 CI/CD，在 Kubernetes 中。Jenkins X 专注于利用 Kubernetes 生态系统加速大规模软件交付。

在本节中，我们将专注于 Jenkins X 示例，并在您的云提供商上创建具有 CI/CD 功能的 Kubernetes 集群。

## 准备工作

在以下示例中，您将学习如何创建一个静态的 Jenkins 服务器，以部署具有管道自动化和自动 CI/CD 的 Kubernetes 集群，并使用 GitOps 推广和预览环境。

此示例需要 kubectl 和 Helm。对于此示例，我们将使用**GKE**（**Google Kubernetes Engine**的缩写），因此还需要安装 gcloud CLI 工具。您还需要创建一个适当的 GitHub 组织和 GitHub 帐户。

## 如何做到...

本节进一步分为以下小节，以便简化流程：

+   安装 Jenkins X CLI

+   创建 Jenkins X Kubernetes 集群

+   验证 Jenkins X 组件

+   切换 Kubernetes 集群

+   验证集群一致性

### 安装 Jenkins X CLI

Jenkins X CLI `jx` 与您首选的云提供商 CLI 一起用于编排 Kubernetes 集群的部署。Jenkins X 支持 Azure、AWS、**GCP**（**Google Cloud Platform**的缩写）、IBM Cloud、Oracle Cloud、Minikube、Minishift 和 OpenShift 作为部署的提供者。对于此示例，我们将使用 GKE。请参阅 Jenkins X 文档以获取其他供应商的说明。

让我们执行以下步骤来安装 Jenkins X CLI 工具：

1.  访问 JX 发布站点[`github.com/jenkins-x/jx/releases`](https://github.com/jenkins-x/jx/releases)并注意最新的发布版本。在撰写本文时，最新的发布版本是 v2.0.905。

1.  在以下命令中更新发布版本。下载并安装最新版本的 Jenkins X CLI：

```
$ curl -L https://github.com/jenkins-x/jx/releases/download/v2.0.905/jx-linux-amd64.tar.gz | tar xzv 
$ sudo mv jx /usr/local/bin
```

现在你已经安装了 Jenkins X CLI，你可以继续下一个步骤了。

### 创建一个 Jenkins X Kubernetes 集群

你可能更喜欢其他云供应商或本地部署。在这个示例中，我们将使用 GKE。查看 Jenkins X 文档以获取其他供应商的说明。

让我们执行以下步骤来使用`jx`创建你的第一个 Jenkins X Kubernetes 集群：

1.  使用以下命令和`gke`参数创建一个 GKE 的 Kubernetes 集群：

```
$ jx create cluster gke --skip-login
```

1.  选择你的 Google Cloud 项目；在我们的例子中是`devopscookbook`。

1.  选择`us-central1-a`当被要求选择一个 Google Cloud 区域时。

1.  选择静态 Jenkins 服务器和 Jenkinsfiles 作为安装类型。

1.  输入你的 GitHub 用户名：

```
Creating a local Git user for GitHub server
? GitHub username:
```

1.  输入你的 GitHub API 令牌。前往 GitHub Token 页面[`github.com/settings/tokens/new?scopes=repo,read:user,read:org,user:email,write:repo_hook,delete_repo`](https://github.com/settings/tokens/new?scopes=repo,read:user,read:org,user:email,write:repo_hook,delete_repo)获取你的 API 令牌：

```
Please click this URL and generate a token
https://github.com/settings/tokens/new?scopes=repo,read:user,read:org,user:email,write:repo_hook,delete_repo
Then COPY the token and enter it following:
? API Token:
```

1.  默认情况下，Jenkins X 会设置入口规则来使用魔术 DNS `nip.io` 域：

```
? Domain [? for help] (your_IP.nip.io)
```

1.  对以下问题输入`Yes`：

```
? Do you wish to use GitHub as the pipelines Git server: (Y/n)
```

1.  选择你想要创建环境仓库的 GitHub 组织；在我们的例子中是`k8devopscookbook`。

1.  当你的部署成功时，你会看到类似以下的消息：

```
Jenkins X installation completed successfully
 ********************************************************
 NOTE: Your admin password is: your_password
 ********************************************************
...
Context "gke_devopscookbook_us-central1-a_slayersunset" modified.
NAME            HOSTS                             ADDRESS PORTS AGE
chartmuseum     chartmuseum.jx.your_IP.nip.io     your_IP 80    7m43s
docker-registry docker-registry.jx.your_IP.nip.io your_IP 80    7m43s
jenkins         jenkins.jx.your_IP.nip.io         your_IP 80    7m43s
nexus           nexus.jx.your_IP.nip.io           your_IP 80    7m43s
```

你也可以在前面的输出中找到你的管理员密码。

### 验证 Jenkins X 组件

让我们执行以下步骤来验证所有 Jenkins X 组件是否按预期运行：

1.  确认所有的 pod 都在运行。`jx`命名空间中的所有 pod 都应该处于运行状态：

```
$ kubectl get pods -n jx
NAME                                          READY STATUS  RESTARTS AGE
jenkins-956c58866-pz5vl                       1/1   Running 0       11m
jenkins-x-chartmuseum-75d45b6d7f-5bckh        1/1   Running 0       11m
jenkins-x-controllerrole-bd4d7b5c6-sdkbg      1/1   Running 0       11m
jenkins-x-controllerteam-7bdd76dfb6-hh6c8     1/1   Running 0       11m
jenkins-x-controllerworkflow-7545997d4b-hlvhm 1/1   Running 0       11m
jenkins-x-docker-registry-6d555974c7-sngm7    1/1   Running 0       11m
jenkins-x-heapster-7777b7d7d8-4xgb2           2/2   Running 0       11m
jenkins-x-nexus-6ccd45c57c-btzjr              1/1   Running 0       11m
maven-brcfq                                   2/2   Running 0       63s
maven-qz0lc                                   2/2   Running 0       3m
maven-vqw9l                                   2/2   Running 0       32s
```

1.  获取我们需要连接的 Jenkins X 服务 URL 列表。你将会得到类似以下的`jenkins`、`chartmuseum`、`docker-registry`和`nexus`的 URL 列表：

```
$ jx get urls
NAME                      URL
jenkins                   http://jenkins.jx.your_IP.nip.io
jenkins-x-chartmuseum     http://chartmuseum.your_IP.nip.io
jenkins-x-docker-registry http://docker-registry.jx.your_IP.nip.io
nexus                     http://nexus.jx.your_IP.nip.io
```

现在你可以通过访问`jx get urls`命令的前面输出中的第一个 URL 连接到 Jenkins UI。

### 切换 Kubernetes 集群

让我们执行以下步骤来在 Jenkins X 中切换你可以访问的 Kubernetes 集群：

1.  通过列出上下文来获取现有的 Kubernetes 集群：

```
$ jx context
```

1.  选择您想要使用的集群。在我们的情况下，我们切换到使用 Jenkins X 创建的 `gke_devopscookbook` 集群：

```
Change Kubernetes context: [Use arrows to move, space to select, type to filter]
> gke_devopscookbook_us-central1-a_slayersunset
eks_devopscookbook_us-west
openshift_cluster
```

现在您知道如何使用 Jenkins X CLI 切换上下文了。

### 验证集群符合性

如果您在现有的 Kubernetes 集群之间切换，建议在运行流水线之前验证集群配置。让我们执行以下步骤：

1.  验证您的集群是否合规。这些测试通常需要一个小时：

```
jx compliance run
```

1.  检查状态。此命令仅在测试完成后返回“合规性测试已完成”消息：

```
$ jx compliance status
Compliance tests completed.
```

1.  查看结果。如果您的集群符合规定，所有执行的测试结果应显示为“通过”：

```
$ jx compliance results
```

现在您知道如何检查集群符合性结果了。

## 工作原理...

《创建 Jenkins X Kubernetes 集群》的教程向您展示了如何为流水线自动化和自动化 CI/CD 提供 Kubernetes 集群。

在《创建 Jenkins X Kubernetes 集群》的教程中，在第 1 步，我们使用 Jenkins X CLI 创建了集群。默认情况下，Jenkins X 在 GKE 上使用 `n1-standard-2` 作为机器类型，并创建一个最小为三个、最大为五个节点的集群。请记住，您也可以使用现有的 Kubernetes 集群，而不是创建新的集群。大多数设置将在下次运行 `create cluster` 命令时保存和记住。

Jenkins X 部署了一些服务，包括 Jenkins、私有 Docker 注册表、私有 Helm 仓库 ChartMuseum、用于管理 Helm 图表的 Monocular，以及名为 Nexus 的 Maven 和 npm 仓库。

安装后，您将在存储库中找到，Jenkins X 创建了两个 Git 存储库，一个用于暂存环境，一个用于生产环境。Jenkins X 使用 GitOps 方法通过 Git 拉取请求（PR）从一个存储库推广代码到另一个存储库。因此，每个存储库都包含一个 Jenkins 流水线来处理推广。

在《创建 Jenkins X Kubernetes 集群》的教程中，在第 7 步，Jenkins X 使用魔术 DNS 服务，并通过 `nip.io` 服务将您的 GKE 集群的 IP 地址转换为可通过 DNS 发现的主机名。如果您拥有自己的域并且 DNS 配置为指向您的集群，您可以使用 `jx upgrade ingress --cluster` 命令稍后更新设置。

稍后，在第 10 步，您将获得分配给您的管理员用户的默认密码。当您首次通过本步骤提供的 URL 连接到 Jenkins UI 时，将要求您更改此密码。

## 还有更多...

了解以下信息也很有用：

+   导入应用程序

+   升级 Jenkins X

+   删除 Jenkins X Kubernetes 集群

### 导入应用程序

让我们执行以下步骤来将现有应用程序导入 Jenkins X 环境：

1.  克隆或使用现有应用程序。例如，我们将创建`hello-world`示例的克隆：

```
$ mkdir import && cd import
$ git clone https://github.com/k8sdevopscookbook/hello-world.git
```

1.  从`cloned`目录中删除 Git 文件。这将从目录中删除 Git 历史记录：

```
$ cd hello-world & sudo rm -r .git/
```

1.  在文件夹中运行以下命令以将源代码导入 Jenkins X：

```
$ jx import
```

### 升级 Jenkins X 应用程序

让我们执行以下步骤来升级 Jenkins X 应用程序及其组件：

1.  首先，升级`jx` CLI。如果远程存储库中有新版本可用，此命令将升级应用程序：

```
$ jx upgrade cli
```

1.  一旦您使用最新的 CLI，使用以下命令升级平台。如果存在新版本，新的`jx` CLI 命令将升级平台组件：

```
$ jx upgrade platform
```

### 删除 Jenkins X Kubernetes 集群

删除托管的 Kubernetes 集群可能会很棘手，特别是如果不是您创建它们的人。由于我们使用 GKE 创建它们，使用 gcloud CLI 工具更快地删除它们。让我们执行以下步骤来删除我们使用 Jenkins X 创建的 Kubernetes 集群：

1.  使用您的云提供商的说明来删除 Kubernetes 集群。在我们的情况下，我们使用 GKE 来进行操作。首先，列出集群：

```
$ gcloud container clusters list
NAME LOCATION MASTER_VERSION MASTER_IP MACHINE_TYPE NODE_VERSION NUM_NODES STATUS
clustername us-central1-a 1.12.8-gke.10 your_IP n1-standard-2 1.12.8-gke.10 3 RUNNING
```

1.  使用步骤 1 的输出中的`clustername`删除集群：

```
$ gcloud container clusters delete <clustername>
```

现在您已经学会了如何使用 Jenkins X 来创建您的集群。这些知识已经为您准备好了第三章，*构建 CI/CD 流水线*，在那里您将继续使用这个环境，并学会在 Jenkins X 中将应用程序导入为流水线。

## 另请参阅

+   Jenkins 简介：[`jenkins.io/blog/2018/03/19/introducing-jenkins-x/`](https://jenkins.io/blog/2018/03/19/introducing-jenkins-x/)

+   Jenkins X 存储库和二进制文件：[`github.com/jenkins-x/jx`](https://github.com/jenkins-x/jx)

+   Jenkins X 教程：[`jenkins-x.io/tutorials/`](https://jenkins-x.io/tutorials/)

+   Jenkins X 入门说明：[`jenkins-x.io/getting-started/install-on-cluster/`](https://jenkins-x.io/getting-started/install-on-cluster/)

+   Jenkins X CLI 命令及其使用说明：[`jenkins-x.io/commands/jx/`](https://jenkins-x.io/commands/jx/)

# 部署和管理 GitLab 的生命周期

GitLab 是一个完整的 DevOps 工具链，提供在单个应用平台中交付。GitLab 提供了您管理、计划、创建、验证、打包、发布、配置、监视和保护应用程序所需的所有工具。

在本节中，我们将使用 Helm 图表来覆盖 GitLab 的部署和生命周期管理。

## 准备工作

在下一个步骤中，您将学习如何在现有的 Kubernetes 集群上安装 GitLab，从而可以管理整个 DevOps 生命周期。

此步骤需要 kubectl 和 Helm，以及现有的 Kubernetes 集群。对于此步骤，我们将使用在第一章中部署的 AWS 集群，*构建生产就绪的 Kubernetes 集群*。您应该能够在任何 Kubernetes 集群版本 1.11 或更高版本上运行相同的步骤，最低要求为 6vCPU 和 16GB RAM。

## 操作步骤：

本节进一步分为以下小节，以便简化流程：

+   使用 Helm 安装 GitLab

+   连接到 GitLab 仪表板

+   创建第一个 GitLab 用户

+   升级 GitLab

+   删除 GitLab

### 使用 Helm 安装 GitLab

对于此步骤，我们将使用在*第一章中部署的 Amazon EC2 上的 Kubernetes 集群，*构建生产就绪的 Kubernetes 集群*下的*在 Amazon Web Services 上配置 Kubernetes 集群*部分：

1.  将 GitLab Helm 图表存储库添加到本地存储库：

```
$ helm repo add gitlab https://charts.gitlab.io/
$ helm repo update
```

1.  用您的域名替换以下`externalUrl`，并在`gitlab`命名空间中使用 Helm 部署 GitLab：

```
$ helm upgrade --install gitlab gitlab/gitlab --namespace gitlab \
--timeout 600 \
--set global.edition=ce \
--set certmanager-issuer.email=youremail@domain.com \
--set global.hosts.domain=yourdomain.com
```

为简单起见，我建议您在*使用自动生成的自签名证书*部分使用您自己的证书。然后，您可以使用`CNAME`记录将您的 DNS 名称映射到创建的 ELB。

1.  部署可能需要大约 10-15 分钟。确认服务状态并注意`gitlab-gitlab-ce`服务的外部 IP：

```
$ kubectl get svc -n gitlab
```

### 连接到 GitLab 仪表板

让我们执行以下步骤，以获取 GitLab 服务地址，以便使用您的 Web 浏览器连接：

1.  获取 GitLab 服务的外部地址：

```
$ echo http://$(kubectl get svc --namespace gitlab \
gitlab-nginx-ingress-controller \
-o jsonpath='{.status.loadBalancer.ingress[0].hostname}')
```

1.  在浏览器中打开上一个命令返回的地址。

1.  通过运行以下命令获取 GitLab 创建的默认 root 密码：

```
$ kubectl get secret gitlab-gitlab-initial-root-password \
-ojsonpath='{.data.password}' | base64 --decode ; echo
```

1.  设置新密码并使用`root`用户和新密码登录。

1.  要使用自定义 URL，请在 DNS 上创建一个`CNAME`记录，将别名指向第 1 步中使用的外部 URL。

### 创建第一个 GitLab 用户

默认情况下，我们使用 root 帐户来管理 GitLab 部署。所有新用户都需要使用自己的凭据登录 GitLab。

让我们执行以下步骤来创建新用户：

1.  以`root`用户身份登录。

1.  登录到 GitLab 仪表板后，您将看到类似以下内容的欢迎屏幕。在 GitLab 欢迎屏幕上点击*添加人员*：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/k8s-cpl-dop-cb/img/8587bddd-31a1-4045-ab3a-7dae018094fa.png)

1.  在*新用户*菜单下，至少输入姓名、用户名和电子邮件字段，然后点击*创建用户*以保存更改。

### 升级 GitLab

GitLab 经常发布具有额外功能的新版本。偶尔，您可能还需要升级以获得错误修复。升级可以使用 Helm upgrade 轻松完成。让我们执行以下步骤来升级 GitLab 到新版本：

1.  首先，使用`helm get values`命令将当前使用的参数导出到 YAML 文件中，如下所示：

```
$ helm get values gitlab > gitlab.yaml
```

1.  升级图表存储库以获取远程存储库中可用的新版本：

```
$ helm repo update
```

1.  列出可用的图表版本：

```
$ helm search -l gitlab/gitlab
NAME CHART VERSION APP VERSION DESCRIPTION
gitlab/gitlab 2.1.7 12.1.6 Web-based Git-repository manager with wiki and issue-trac...
gitlab/gitlab 2.1.6 12.1.4 Web-based Git-repository manager with wiki and issue-trac...
...
```

1.  使用相同的参数升级新版本：

```
$ helm upgrade gitlab gitlab/gitlab --version 2.1.7 -f gitlab.yaml
```

## 工作原理...

*使用 Helm 安装 GitLab*配方向您展示了如何使用所有内置组件和外部依赖项来配置 GitLab。

在*使用 Helm 安装 GitLab*配方中，在第 1 步中，我们确保将官方最新的 GitLab Helm 图表存储库添加到本地存储库列表中。否则，将使用来自 stable/gitlab 存储库的旧版本的 GitLab 图表。

在相同的配方中，在第 2 步中，我们使用 Helm 图表在`gitlab`命名空间中使用`--namespace gitlab`参数部署了 GitLab。这个命令不仅部署了 GitLab 组件，还部署了 Redis、PostgreSQL、Minio 对象存储用于数据持久性、Cert Manager、本地容器注册表和 nginx ingress 控制器。

要使用现有的 PostgreSQL、Redis、Gitaly、S3 存储和 ingress 控制器的部署，请按照此处描述的高级配置说明：[`docs.gitla`](https://docs.gitlab.com/charts/advanced/)[b.com/charts/advanced/](https://docs.gitlab.com/charts/advanced/)。

默认情况下，GitLab Helm 图表部署 GitLab 的企业版。通过使用`--set global.edition=ce`参数，我们将部署切换到了免费的社区版。

在*使用 Helm 安装 GitLab*教程中执行了命令后，在第 2 步，Helm 图表假定我们有一个现有的默认存储类，并使用默认存储类为有状态应用创建 PVCs 和 PVs。

## 还有更多...

还有以下信息也很有用：

+   使用您自己的通配符证书

+   使用自动生成的自签名证书

+   启用 GitLab Operator

+   删除 GitLab

### 使用您自己的通配符证书

GitLab 的 Helm 图表安装支持使用 nginx 控制器进行 TLS 终止。当您安装 GitLab 时，您有选择。为了提高安全性，您可以使用 Cert Manager 和 Let's Encrypt，或者选择使用您自己的通配符证书。在本教程中，我们将解释如何使用您自己的通配符证书选项，具体如下：

1.  将您的证书和密钥添加到集群作为一个密钥：

```
$ kubectl create secret tls mytls --cert=cert.crt --key=key.key
```

1.  使用以下附加参数从 Helm 图表部署 GitLab：

```
$ helm upgrade --install gitlab gitlab/gitlab --namespace gitlab \
--timeout 600 \
--set global.edition=ce \
--version 2.1.6 \
--set certmanager.install=false \
--set global.ingress.configureCertmanager=false \
--set global.ingress.tls.secretName=mytls
```

### 使用自动生成的自签名证书

如果您无法使用自己的通配符证书，但仍希望快速测试或小规模使用 GitLab，您也可以使用自动生成的自签名证书。在本教程中，我们将解释如何使用自签名证书，这在 Let's Encrypt 不可用但仍需要 SSL 安全的环境中非常有用：

1.  在您的域名无法从 Let's Encrypt 服务器访问的情况下，您可以提供一个自动生成的自签名通配符证书：

```
$ helm upgrade --install gitlab gitlab/gitlab --namespace gitlab \
--timeout 600 \
--set global.edition=ce \
--version 2.1.6 \
--set certmanager.install=false \
--set global.ingress.configureCertmanager=false \
--set gitlab-runner.install=false
```

1.  检索证书，稍后可以导入到 Web 浏览器或系统存储中：

```
$ kubectl get secret gitlab-wildcard-tls-ca -n gitlab \
-ojsonpath='{.data.cfssl_ca}' | base64 --decode > gitlab.mydomain.com.ca.pem
```

### 启用 GitLab Operator

GitLab 提供了一个实验性的 Operator。这个 Operator 控制升级过程，并帮助执行无停机的滚动升级。让我们执行以下步骤，使 GitLab Operator 运行起来：

1.  首先，通过使用以下 Helm 参数来确保 CRD 已经就位：

```
$ helm upgrade --install gitlab . --set global.Operator.enabled=true \
--set global.Operator.bootstrap=true 
```

1.  使用 Helm 图表部署 GitLab Operator：

```
$ helm upgrade gitlab . --set global.Operator.enabled=true \
--set global.Operator.bootstrap=false 
```

### 删除 GitLab

让我们执行以下步骤，完全删除我们在本节中创建的 GitLab 部署：

1.  使用 Helm 删除 GitLab 的现有发布：

```
$ helm delete --purge gitlab
```

1.  您可能还想删除命名空间，以确保没有留下任何东西：

```
$ kubectl delete ns gitlab
```

现在您已经学会了如何在 Kubernetes 上启动和运行 GitLab。这些知识将在第三章“构建 CI/CD 流水线”中的 GitLab 部分中需要，您将学习如何在 GitLab 中导入应用程序并创建流水线。

## 另请参阅

+   GitLab 原生云 Helm 图表文档：[`docs.gitlab.com/charts/`](https://docs.gitlab.com/charts/)

+   高级配置选项：[`docs.gitlab.com/charts/advanced/`](https://docs.gitlab.com/charts/advanced/)

+   GitLab 运算符：[`docs.gitlab.com/charts/installation/Operator.html`](https://docs.gitlab.com/charts/installation/operator.html)

+   安装 GitLab 社区版的替代方法：[`about.gitlab.com/install/?version=ce/`](https://about.gitlab.com/install/?version=ce/)
