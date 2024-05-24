# 精通 Docker 第三版（三）

> 原文：[`zh.annas-archive.org/md5/3EE782924E03F9CE768AD8AE784D47E6`](https://zh.annas-archive.org/md5/3EE782924E03F9CE768AD8AE784D47E6)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第七章：Docker Machine

在本章中，我们将更深入地了解 Docker Machine，这是我们在上一章中提到的。它可以用于轻松启动和引导针对各种平台的 Docker 主机，包括本地或云环境。您也可以使用它来控制您的 Docker 主机。让我们看看本章将涵盖的内容：

+   Docker Machine 简介

+   使用 Docker Machine 设置本地 Docker 主机

+   在云中启动 Docker 主机

+   使用其他基本操作系统

# 技术要求

与以前的章节一样，我们将继续使用我们的本地 Docker 安装。同样，在本章中的截图将来自我首选的操作系统 macOS。

我们将看看如何使用 Docker Machine 在本地使用 VirtualBox 启动基于 Docker 的虚拟机，以及在公共云中使用，因此，如果您想要在本章中的示例中跟随，您将需要一个 Digital Ocean 账户。

与以前一样，我们将在迄今为止安装了 Docker 的三个操作系统上运行 Docker 命令。然而，一些支持命令可能只适用于 macOS 和基于 Linux 的操作系统。

观看以下视频以查看代码的实际操作：

[`bit.ly/2Ansb5v`](http://bit.ly/2Ansb5v)

# Docker Machine 简介

在我们卷起袖子并开始使用 Docker Machine 之前，我们应该花点时间讨论它在整个 Docker 生态系统中的地位。

Docker Machine 的最大优势在于它为多个公共云提供了一致的接口，例如亚马逊网络服务、DigitalOcean、微软 Azure 和谷歌云，以及自托管的虚拟机/云平台，包括 OpenStack 和 VMware vSphere。最后，它还支持以下本地托管的虚拟化平台，如 Oracle VirtualBox 和 VMware Workstation 或 Fusion。

能够使用单个命令以最少的用户交互来针对所有这些技术是一个非常大的时间节省器，如果你需要快速访问亚马逊网络服务的 Docker 主机，然后第二天又需要访问 DigitialOcean，你知道你将获得一致的体验。

由于它是一个命令行工具，因此非常容易向同事传达指令，甚至可以对 Docker 主机的启动和关闭进行脚本化：想象一下，每天早上开始工作时，您的环境都是新建的，然后为了节省成本，每天晚上都会被关闭。

# 使用 Docker Machine 部署本地 Docker 主机

在我们进入云之前，我们将通过启动 Oracle VirtualBox 来查看 Docker Machine 的基础知识，以提供虚拟机。

VirtualBox 是 Oracle 提供的免费虚拟化产品。它允许您在许多不同的平台和 CPU 类型上安装虚拟机。从[`www.virtualbox.org/wiki/Downloads/`](https://www.virtualbox.org/wiki/Downloads/)下载并安装 VirtualBox。

要启动虚拟机，您只需要运行以下命令：

```
$ docker-machine create --driver virtualbox docker-local
```

这将启动部署过程，期间您将获得 Docker Machine 正在运行的任务列表。对于每个使用 Docker Machine 启动的 Docker 主机，都会经历相同的步骤。

首先，Docker Machine 运行一些基本检查，例如确认 VirtualBox 是否已安装，并创建证书和目录结构，用于存储所有文件和虚拟机：

```
Creating CA: /Users/russ/.docker/machine/certs/ca.pem
Creating client certificate: /Users/russ/.docker/machine/certs/cert.pem
Running pre-create checks...
(docker-local) Image cache directory does not exist, creating it at /Users/russ/.docker/machine/cache...
```

然后检查将用于虚拟机的镜像是否存在。如果不存在，将下载该镜像：

```
(docker-local) No default Boot2Docker ISO found locally, downloading the latest release...
(docker-local) Latest release for github.com/boot2docker/boot2docker is v18.06.1-ce
(docker-local) Downloading /Users/russ/.docker/machine/cache/boot2docker.iso from https://github.com/boot2docker/boot2docker/releases/download/v18.06.1-ce/boot2docker.iso...
(docker-local) 0%....10%....20%....30%....40%....50%....60%....70%....80%....90%....100%
```

一旦检查通过，它将使用所选的驱动程序创建虚拟机：

```
Creating machine...
(docker-local) Copying /Users/russ/.docker/machine/cache/boot2docker.iso to /Users/russ/.docker/machine/machines/docker-local/boot2docker.iso...
(docker-local) Creating VirtualBox VM...
(docker-local) Creating SSH key...
(docker-local) Starting the VM...
(docker-local) Check network to re-create if needed...
(docker-local) Found a new host-only adapter: "vboxnet0"
(docker-local) Waiting for an IP...
Waiting for machine to be running, this may take a few minutes...
```

正如您所看到的，Docker Machine 为虚拟机创建了一个唯一的 SSH 密钥。这意味着您将能够通过 SSH 访问虚拟机，但稍后会详细介绍。虚拟机启动后，Docker Machine 会连接到虚拟机：

```
Detecting operating system of created instance...
Waiting for SSH to be available...
Detecting the provisioner...
Provisioning with boot2docker...
Copying certs to the local machine directory...
Copying certs to the remote machine...
Setting Docker configuration on the remote daemon...
Checking connection to Docker...
```

正如您所看到的，Docker Machine 会检测正在使用的操作系统，并选择适当的引导脚本来部署 Docker。一旦安装了 Docker，Docker Machine 会在本地主机和 Docker 主机之间生成和共享证书。然后，它会为证书认证配置远程 Docker 安装，这意味着您的本地客户端可以连接并与远程 Docker 服务器进行交互：

一旦安装了 Docker，Docker Machine 会在本地主机和 Docker 主机之间生成和共享证书。然后，它会为证书认证配置远程 Docker 安装，这意味着您的本地客户端可以连接并与远程 Docker 服务器进行交互：

```
Docker is up and running!
To see how to connect your Docker Client to the Docker Engine running on this virtual machine, run: docker-machine env docker-local
```

最后，它检查您的本地 Docker 客户端是否可以进行远程连接，并通过提供有关如何配置本地客户端以连接新启动的 Docker 主机的说明来完成任务。

如果您打开 VirtualBox，您应该能够看到您的新虚拟机：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/ms-dkr-3e/img/e31b049f-31be-45cc-9084-ac9b2ab29006.png)

接下来，我们需要配置本地 Docker 客户端以连接到新启动的 Docker 主机；如在启动主机的输出中已经提到的，运行以下命令将向您显示如何进行连接：

```
$ docker-machine env docker-local
```

该命令返回以下内容：

```
export DOCKER_TLS_VERIFY="1"
export DOCKER_HOST="tcp://192.168.99.100:2376"
export DOCKER_CERT_PATH="/Users/russ/.docker/machine/machines/docker-local"
export DOCKER_MACHINE_NAME="docker-local"
# Run this command to configure your shell:
# eval $(docker-machine env docker-local)
```

这将通过提供新启动的 Docker 主机的 IP 地址和端口号以及用于身份验证的证书路径来覆盖本地 Docker 安装。在输出的末尾，它会给出一个命令来运行并配置您的终端会话，以便进行连接。

在运行该命令之前，让我们运行`docker version`以获取有关当前设置的信息：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/ms-dkr-3e/img/68b803b8-d173-47f2-8575-63ec407bd92a.png)

这基本上是我正在运行的 Docker for Mac 安装。运行以下命令，然后再次运行`docker version`应该会显示服务器的一些更改：

```
$ eval $(docker-machine env docker-local)
```

该命令的输出如下：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/ms-dkr-3e/img/5f64477c-35a8-4f7f-abe1-54bed7e4abe9.png)

正如您所看到的，Docker Machine 启动的服务器基本上与我们在本地安装的内容一致；实际上，唯一的区别是构建时间。如您所见，我在 Docker for Mac 安装中的 Docker Engine 二进制文件是在 Docker Machine 版本之后一分钟构建的。

从这里，我们可以以与本地 Docker 安装相同的方式与 Docker 主机进行交互。在继续在云中启动 Docker 主机之前，还有一些其他基本的 Docker Machine 命令需要介绍。

首先列出当前配置的 Docker 主机：

```
$ docker-machine ls
```

该命令的输出如下：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/ms-dkr-3e/img/172d6b76-17f2-4e7b-84ec-a9a7d2155fb1.png)

正如您所看到的，它列出了机器名称、使用的驱动程序和 Docker 端点 URL 的详细信息，以及主机正在运行的 Docker 版本。

您还会注意到`ACTIVE`列中有一个`*`；这表示您的本地客户端当前配置为与之交互的 Docker 主机。您还可以通过运行`docker-machine active`来找出活动的机器。

接下来的命令使用 SSH 连接到 Docker 主机：

```
$ docker-machine ssh docker-local
```

该命令的输出如下：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/ms-dkr-3e/img/d13ebe1b-2e6a-468b-8155-44c1e1c2505d.png)

如果您需要在 Docker Machine 之外安装其他软件或配置，则这很有用。如果您需要查看日志等，也很有用，因为您可以通过运行`exit`退出远程 shell。一旦回到本地机器上，您可以通过运行以下命令找到 Docker 主机的 IP 地址：

```
$ docker-machine ip docker-local
```

我们将在本章后面经常使用这个。还有一些命令可以获取有关 Docker 主机的更多详细信息：

```
$ docker-machine inspect docker-local
$ docker-machine config docker-local
$ docker-machine status docker-local
$ docker-machine url docker-local
```

最后，还有一些命令可以`stop`，`start`，`restart`和删除您的 Docker 主机。使用最后一个命令来删除您本地启动的主机：

```
$ docker-machine stop docker-local
$ docker-machine start docker-local
$ docker-machine restart docker-local
$ docker-machine rm docker-local
```

运行`docker-machine rm`命令将提示您确定是否真的要删除实例：

```
About to remove docker-local
WARNING: This action will delete both local reference and remote instance.
Are you sure? (y/n): y
Successfully removed docker-local
```

现在我们已经快速了解了基础知识，让我们尝试一些更有冒险精神的东西。

# 在云中启动 Docker 主机

在本节中，我们将只看一下 Docker Machine 支持的公共云驱动程序之一。如前所述，有很多可用的驱动程序，但 Docker Machine 的吸引力之一是它提供一致的体验，因此驱动程序之间的差异不会太大。

我们将使用 Docker Machine 在 DigitalOcean 中启动一个 Docker 主机。我们唯一需要的是一个 API 访问令牌。而不是在这里解释如何生成一个，您可以按照[`www.digitalocean.com/help/api/`](https://www.digitalocean.com/help/api/)上的说明进行操作。

使用 API 令牌启动 Docker 主机将产生费用；确保您跟踪您启动的 Docker 主机。有关 DigitalOcean 的定价详情，请访问[`www.digitalocean.com/pricing/`](https://www.digitalocean.com/pricing/)。此外，保持您的 API 令牌秘密，因为它可能被用来未经授权地访问您的帐户。本章中使用的所有令牌都已被撤销。

首先，我们要做的是将我们的令牌设置为环境变量，这样我们就不必一直使用它。要做到这一点，请运行以下命令，确保您用自己的 API 令牌替换 API 令牌：

```
$ DOTOKEN=0cb54091fecfe743920d0e6d28a29fe325b9fc3f2f6fccba80ef4b26d41c7224
```

由于我们需要传递给 Docker Machine 命令的额外标志，我将使用`\`来将命令分割成多行，以使其更易读。

要启动名为`docker-digtialocean`的 Docker 主机，我们需要运行以下命令：

```
$ docker-machine create \
 --driver digitalocean \ --digitalocean-access-token $DOTOKEN \ docker-digitalocean
```

由于 Docker 主机是远程机器，它将需要一些时间来启动、配置和访问。如您从以下输出中所见，Docker Machine 启动 Docker 主机的方式也有一些变化：

```
Running pre-create checks...
Creating machine...
(docker-digitalocean) Creating SSH key...
(docker-digitalocean) Creating Digital Ocean droplet...
(docker-digitalocean) Waiting for IP address to be assigned to the Droplet...
Waiting for machine to be running, this may take a few minutes...
Detecting operating system of created instance...
Waiting for SSH to be available...
Detecting the provisioner...
Provisioning with ubuntu(systemd)...
Installing Docker...
Copying certs to the local machine directory...
Copying certs to the remote machine...
Setting Docker configuration on the remote daemon...
Checking connection to Docker...
Docker is up and running!
To see how to connect your Docker Client to the Docker Engine running on this virtual machine, run: docker-machine env docker-digitalocean
```

启动后，您应该能够在 DigitalOcean 控制面板中看到 Docker 主机：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/ms-dkr-3e/img/bfffcab0-e5f0-466c-ad23-16bee375745f.png)

通过运行以下命令重新配置本地客户端以连接到远程主机：

```
$ eval $(docker-machine env docker-digitalocean)
```

此外，您可以运行 `docker version` 和 `docker-machine inspect docker-digitalocean` 来获取有关 Docker 主机的更多信息。

最后，运行 `docker-machine ssh docker-digitalocean` 将使您通过 SSH 进入主机。如您从以下输出中所见，以及您首次启动 Docker 主机时的输出中，所使用的操作系统有所不同：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/ms-dkr-3e/img/cb1e120a-b732-47be-a345-353509316d83.png)

您可以通过运行 `exit` 退出远程 shell。正如您所见，我们不必告诉 Docker Machine 要使用哪种操作系统，Docker 主机的大小，甚至在哪里启动它。这是因为每个驱动程序都有一些相当合理的默认值。将这些默认值添加到我们的命令中，使其看起来像以下内容：

```
$ docker-machine create \
 --driver digitalocean \
 --digitalocean-access-token $DOTOKEN \
 --digitalocean-image ubuntu-16-04-x64 \
 --digitalocean-region nyc3 \
 --digitalocean-size 512mb \
 --digitalocean-ipv6 false \
 --digitalocean-private-networking false \
 --digitalocean-backups false \
 --digitalocean-ssh-user root \
 --digitalocean-ssh-port 22 \
 docker-digitalocean
```

如您所见，您可以自定义 Docker 主机的大小、区域和操作系统，甚至是启动 Docker 主机的网络。假设我们想要更改操作系统和 droplet 的大小。在这种情况下，我们可以运行以下命令：

```
$ docker-machine create \
 --driver digitalocean \
 --digitalocean-access-token $DOTOKEN \
 --digitalocean-image ubuntu-18-04-x64 \
 --digitalocean-size 1gb \
 docker-digitalocean
```

如您在 DigitalOcean 控制面板中所见，这将启动一个看起来像以下内容的机器：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/ms-dkr-3e/img/766a16c6-50f5-4439-b972-9aa69d25de4b.png)

您可以通过运行以下命令删除 DigitalOcean Docker 主机：

```
$ docker-machine rm docker-digitalocean
```

# 使用其他基本操作系统

您不必使用 Docker Machine 的默认操作系统；它确实提供了其他基本操作系统的配置程序，包括专门用于运行容器的操作系统。在完成本章之前，我们将看一下如何启动其中一个，CoreOS。

我们将要查看的发行版刚好有足够的操作系统来运行内核、网络堆栈和容器，就像 Docker 自己的 MobyOS 一样，它被用作 Docker for Mac 和 Docker for Windows 的基础。

虽然 CoreOS 支持自己的容器运行时，称为 RKT（发音为 Rocket），但它也附带了 Docker。然而，正如我们将看到的，目前与 CoreOS 稳定版本一起提供的 Docker 版本有点过时。

要启动 DigitalOcean 管理的`coreos-stable`版本，请运行以下命令：

```
$ docker-machine create \
 --driver digitalocean \
 --digitalocean-access-token $DOTOKEN \
 --digitalocean-image coreos-stable \
 --digitalocean-size 1GB \
 --digitalocean-ssh-user core \
 docker-coreos
```

与在公共云上启动其他 Docker 主机一样，输出基本相同。您会注意到 Docker Machine 使用 CoreOS 提供程序：

```
Running pre-create checks...
Creating machine...
(docker-coreos) Creating SSH key...
(docker-coreos) Creating Digital Ocean droplet...
(docker-coreos) Waiting for IP address to be assigned to the Droplet...
Waiting for machine to be running, this may take a few minutes...
Detecting operating system of created instance...
Waiting for SSH to be available...
Detecting the provisioner...
Provisioning with coreOS...
Copying certs to the local machine directory...
Copying certs to the remote machine...
Setting Docker configuration on the remote daemon...
Checking connection to Docker...
Docker is up and running!
To see how to connect your Docker Client to the Docker Engine running on this virtual machine, run: docker-machine env docker-coreos
```

一旦启动，您可以运行以下命令：

```
$ docker-machine ssh docker-coreos cat /etc/*release
```

这将返回`release`文件的内容：

```
DISTRIB_ID="Container Linux by CoreOS"
DISTRIB_RELEASE=1800.7.0
DISTRIB_CODENAME="Rhyolite"
DISTRIB_DESCRIPTION="Container Linux by CoreOS 1800.7.0 (Rhyolite)"
NAME="Container Linux by CoreOS"
ID=coreos
VERSION=1800.7.0
VERSION_ID=1800.7.0
BUILD_ID=2018-08-15-2254
PRETTY_NAME="Container Linux by CoreOS 1800.7.0 (Rhyolite)"
ANSI_COLOR="38;5;75"
HOME_URL="https://coreos.com/"
BUG_REPORT_URL="https://issues.coreos.com"
COREOS_BOARD="amd64-usr"
```

运行以下命令将显示有关在 CoreOS 主机上运行的 Docker 版本的更多信息：

```
$ docker $(docker-machine config docker-coreos) version
```

您可以从以下输出中看到这一点；另外，正如已经提到的，它落后于当前版本：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/ms-dkr-3e/img/1717210e-d830-4cab-bb21-092e16c042fc.png)

这意味着本书中使用的并非所有命令都能正常工作。要删除 CoreOS 主机，请运行以下命令：

```
$ docker-machine rm docker-coreos
```

# 摘要

在本章中，我们看了如何使用 Docker Machine 在 VirtualBox 上本地创建 Docker 主机，并回顾了您可以使用的命令来交互和管理由 Docker Machine 启动的 Docker 主机。

然后，我们看了如何使用 Docker Machine 在云环境中部署 Docker 主机，即 DigitalOcean。最后，我们快速看了如何启动不同的容器优化 Linux 操作系统，即 CoreOS。

我相信您会同意，使用 Docker Machine 来运行这些任务，通常具有非常不同的方法，会带来非常一致的体验，并且从长远来看，也将节省大量时间并解释清楚。

在下一章中，我们将不再与单个 Docker 主机进行交互，而是启动和运行 Docker Swarm 集群。

# 问题

1.  在运行`docker-machine create`时，哪个标志可以让您定义 Docker Machine 用于启动 Docker 主机的服务或提供程序？

1.  真或假：运行`docker-machine env my-host`将重新配置本地 Docker 客户端以与`my-host`进行交互？

1.  解释 Docker Machine 背后的基本原理。

# 进一步阅读

有关 Docker Machine 支持的各种平台的信息，请参考以下内容：

+   亚马逊网络服务：[`aws.amazon.com/`](https://aws.amazon.com/)

+   Microsoft Azure：[`azure.microsoft.com/`](https://azure.microsoft.com/)

+   DigitalOcean：[`www.digitalocean.com/`](https://www.digitalocean.com/)

+   Exoscale: [`www.exoscale.ch/`](https://www.exoscale.ch/)

+   Google Compute Engine: [`cloud.google.com/`](https://cloud.google.com/)

+   Rackspace: [`www.rackspace.com/`](https://www.rackspace.com/)

+   IBM SoftLayer: [`www.softlayer.com/`](https://www.softlayer.com/)

+   微软 Hyper-V: [`www.microsoft.com/en-gb/cloud-platform/server-virtualization/`](https://www.microsoft.com/en-gb/cloud-platform/server-virtualization/)

+   OpenStack: [`www.openstack.org/`](https://www.openstack.org/)

+   VMware vSphere: [`www.vmware.com/uk/products/vsphere.html`](https://www.vmware.com/uk/products/vsphere.html)

+   Oracle VirtualBox: [`www.virtualbox.org/`](https://www.virtualbox.org/)

+   VMware Fusion: [`www.vmware.com/uk/products/fusion.html`](https://www.vmware.com/uk/products/fusion.html)

+   VMware Workstation: [`www.vmware.com/uk/products/workstation.html`](https://www.vmware.com/uk/products/workstation.html)

+   CoreOS: [`coreos.com/`](https://coreos.com/)


# 第八章：Docker Swarm

在本章中，我们将介绍 Docker Swarm。使用 Docker Swarm，您可以创建和管理 Docker 集群。Swarm 可用于在多个主机上分发容器，并且还具有扩展容器的能力。我们将涵盖以下主题：

+   介绍 Docker Swarm

+   Docker Swarm 集群中的角色

+   创建和管理 Swarm

+   Docker Swarm 服务和堆栈

+   Docker Swarm 负载均衡和调度

# 技术要求

与以前的章节一样，我们将继续使用我们的本地 Docker 安装。同样，本章中的截图将来自我首选的操作系统 macOS。

与以前一样，我们将运行的 Docker 命令将适用于我们迄今为止安装了 Docker 的三种操作系统。但是，一些支持命令可能只适用于基于 macOS 和 Linux 的操作系统。

观看以下视频以查看代码的实际操作：

[`bit.ly/2yWA4gl`](http://bit.ly/2yWA4gl)

# 介绍 Docker Swarm

在我们继续之前，我应该提到 Docker Swarm 有两个非常不同的版本。有一个独立的 Docker Swarm 版本；这个版本受支持直到 Docker 1.12，并且不再被积极开发；但是，您可能会发现一些旧的文档提到它。不建议安装独立的 Docker Swarm，因为 Docker 在 2017 年第一季度结束了对 1.11.x 版本的支持。

Docker 1.12 版本引入了 Docker Swarm 模式。这将所有独立的 Docker Swarm 中可用的功能引入了核心 Docker 引擎，还增加了大量的功能。由于本书涵盖的是 Docker 18.06 及更高版本，我们将使用 Docker Swarm 模式，本章剩余部分将称之为 Docker Swarm。

由于您已经运行了内置 Docker Swarm 支持的 Docker 版本，因此您无需安装 Docker Swarm；您可以通过运行以下命令验证 Docker Swarm 是否可用于您的安装：

```
$ docker swarm --help
```

当运行以下命令时，您应该会看到类似以下终端输出：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/ms-dkr-3e/img/c12154f3-2fe8-4d38-9ff5-cab971d15d00.png)

如果出现错误，请确保您正在运行 Docker 18.06 或更高版本，我们在第一章*，Docker 概述*中涵盖了其安装。现在我们知道我们的 Docker 客户端支持 Docker Swarm，那么 Swarm 是什么意思呢？

**Swarm**是一组主机，都在运行 Docker，并已设置为在集群配置中相互交互。一旦配置完成，您将能够使用我们迄今为止一直在针对单个主机运行的所有命令，并让 Docker Swarm 通过使用部署策略来决定启动容器的最合适的主机来决定容器的放置位置。

Docker Swarm 由两种类型的主机组成。现在让我们来看看这些。

# Docker Swarm 集群中的角色

Docker Swarm 涉及哪些角色？让我们来看看在 Docker Swarm 集群中运行时主机可以承担的两种角色。

# Swarm 管理器

**Swarm 管理器**是一个主机，是所有 Swarm 主机的中央管理点。Swarm 管理器是您发出所有命令来控制这些节点的地方。您可以在节点之间切换，加入节点，移除节点，并操纵这些主机。

每个集群可以运行多个 Swarm 管理器。对于生产环境，建议至少运行五个 Swarm 管理器：这意味着在开始遇到任何错误之前，我们的集群可以容忍最多两个 Swarm 管理器节点故障。Swarm 管理器使用 Raft 一致性算法（有关更多详细信息，请参阅进一步阅读部分）来在所有管理节点上维护一致的状态。

# Swarm 工作者

**Swarm 工作者**，我们之前称之为 Docker 主机，是运行 Docker 容器的主机。Swarm 工作者是从 Swarm 管理器管理的：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/ms-dkr-3e/img/0dc79ce2-c308-4a06-ac4d-70530101cf4a.png)

这是所有 Docker Swarm 组件的示意图。我们看到 Docker Swarm 管理器与具有 Docker Swarm 工作者角色的每个 Swarm 主机进行通信。工作者确实具有一定程度的连接性，我们将很快看到。

# 创建和管理 Swarm

现在让我们来看看如何使用 Swarm 以及我们如何执行以下任务：

+   创建集群

+   加入工作者

+   列出节点

+   管理集群

# 创建集群

让我们从创建一个以 Swarm 管理器为起点的集群开始。由于我们将在本地机器上创建一个多节点集群，我们应该使用 Docker Machine 通过运行以下命令来启动一个主机：

```
$ docker-machine create \
 -d virtualbox \
 swarm-manager 
```

这里显示了您获得的输出的缩略版本：

```
(swarm-manager) Creating VirtualBox VM...
(swarm-manager) Starting the VM...
(swarm-manager) Check network to re-create if needed...
(swarm-manager) Waiting for an IP...
Waiting for machine to be running, this may take a few minutes...
Checking connection to Docker...
Docker is up and running!
To see how to connect your Docker Client to the Docker Engine running on this virtual machine, run: docker-machine env swarm-manager
```

Swarm 管理节点现在正在使用 VirtualBox 启动和运行。我们可以通过运行以下命令来确认：

```
$ docker-machine ls
```

您应该看到类似以下输出：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/ms-dkr-3e/img/a2046c70-6991-407c-bef0-cc89a9795b3f.png)

现在，让我们将 Docker Machine 指向新的 Swarm 管理器。从我们创建 Swarm 管理器时的先前输出中，我们可以看到它告诉我们如何指向该节点：

```
$ docker-machine env swarm-manager
```

这将向您显示配置本地 Docker 客户端与我们新启动的 Docker 主机通信所需的命令。当我运行该命令时，以下代码块显示了返回的配置：

```
export DOCKER_TLS_VERIFY="1"
export DOCKER_HOST="tcp://192.168.99.100:2376"
export DOCKER_CERT_PATH="/Users/russ/.docker/machine/machines/swarm-manager"
export DOCKER_MACHINE_NAME="swarm-manager"
# Run this command to configure your shell:
# eval $(docker-machine env swarm-manager)
```

在运行上一个命令后，我们被告知运行以下命令指向 Swarm 管理器：

```
$ eval $(docker-machine env swarm-manager)
```

现在，如果我们查看我们主机上有哪些机器，我们可以看到我们有 Swarm 主节点，以及它现在被设置为`ACTIVE`，这意味着我们现在可以在其上运行命令：

```
$ docker-machine ls
```

它应该向您显示类似以下内容：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/ms-dkr-3e/img/9bbe1018-54b2-4139-be47-72fe23d7fe3a.png)

现在我们已经启动并运行了第一个主机，我们应该添加另外两个工作节点。要做到这一点，只需运行以下命令来启动另外两个 Docker 主机：

```
$ docker-machine create \
 -d virtualbox \
 swarm-worker01
$ docker-machine create \
 -d virtualbox \
 swarm-worker02
```

一旦您启动了另外两个主机，您可以使用以下命令获取主机列表：

```
$ docker-machine ls
```

它应该向您显示类似以下内容：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/ms-dkr-3e/img/f3dd5f78-b321-4507-b50c-e58a5cc83402.png)

值得指出的是，到目前为止，我们还没有做任何事情来创建我们的 Swarm 集群；我们只是启动了它将要运行的主机。

您可能已经注意到在运行`docker-machine ls`命令时的一列是`SWARM`。只有在使用独立的 Docker Swarm 命令（内置于 Docker Machine 中）启动 Docker 主机时，此列才包含信息。

# 向集群添加 Swarm 管理器

让我们引导我们的 Swarm 管理器。为此，我们将传递一些 Docker Machine 命令的结果给我们的主机。要创建我们的管理器的命令如下：

```
$ docker $(docker-machine config swarm-manager) swarm init \
 --advertise-addr $(docker-machine ip swarm-manager):2377 \
 --listen-addr $(docker-machine ip swarm-manager):2377
```

您应该收到类似于这样的消息：

```
Swarm initialized: current node (uxgvqhw6npr9glhp0zpabn4ha) is now a manager.

To add a worker to this swarm, run the following command:

 docker swarm join --token SWMTKN-1-1uulmpx4j4hub2qmd8q2ozxmonzcehxcomt7cw92xarg3yrkx2-dfiqnfisl75bwwh8yk9pv3msh 192.168.99.100:2377

To add a manager to this swarm, run 'docker swarm join-token manager' and follow the instructions.
```

从输出中可以看出，一旦初始化了您的管理器，您将获得一个唯一的令牌。在上面的示例中，完整的令牌是`SWMTKN-1-1uulmpx4j4hub2qmd8q2ozxmonzcehxcomt7cw92xarg3yrkx2-dfiqnfisl75bwwh8yk9pv3msh`。这个令牌将被工作节点用于验证自己并加入我们的集群。

# 加入 Swarm 工作节点到集群

要将我们的两个工作节点添加到集群中，请运行以下命令。首先，让我们设置一个环境变量来保存我们的令牌，确保您用初始化自己管理器时收到的令牌替换它：

```
$ SWARM_TOKEN=SWMTKN-1-1uulmpx4j4hub2qmd8q2ozxmonzcehxcomt7cw92xarg3yrkx2-dfiqnfisl75bwwh8yk9pv3msh
```

现在我们可以运行以下命令将`swarm-worker01`添加到集群中：

```
$ docker $(docker-machine config swarm-worker01) swarm join \
 --token $SWARM_TOKEN \
 $(docker-machine ip swarm-manager):2377
```

对于`swarm-worker02`，您需要运行以下命令：

```
$ docker $(docker-machine config swarm-worker02) swarm join \
 --token $SWARM_TOKEN \
 $(docker-machine ip swarm-manager):2377
```

两次，您都应该得到确认，您的节点已加入集群：

```
This node joined a swarm as a worker.
```

# 列出节点

您可以通过运行以下命令来检查 Swarm：

```
$ docker-machine ls
```

检查您的本地 Docker 客户端是否仍然配置为连接到 Swarm 管理节点，如果没有，请重新运行以下命令：

```
$ eval $(docker-machine env swarm-manager)
```

现在我们正在连接到 Swarm 管理节点，您可以运行以下命令：

```
$ docker node ls
```

这将连接到 Swarm 主节点并查询组成我们集群的所有节点。您应该看到我们的三个节点都被列出：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/ms-dkr-3e/img/9b53fe45-f48a-4b9b-93e0-674240551e44.png)

# 管理集群

让我们看看如何对我们创建的所有这些集群节点进行一些管理。

有两种方式可以管理这些 Swarm 主机和您正在创建的每个主机上的容器，但首先，您需要了解一些关于它们的信息。

# 查找集群信息

正如我们已经看到的，我们可以使用我们的本地 Docker 客户端列出集群中的节点，因为它已经配置为连接到 Swarm 管理主机。我们只需输入：

```
$ docker info
```

这将为我们提供有关主机的大量信息，如您从下面的输出中所见，我已经截断了：

```
Containers: 0
 Running: 0
 Paused: 0
 Stopped: 0
Images: 0
Plugins:
 Volume: local
 Network: bridge host macvlan null overlay
 Log: awslogs fluentd gcplogs gelf journald json-file logentries splunk syslog
Swarm: active
 NodeID: uxgvqhw6npr9glhp0zpabn4ha
 Is Manager: true
 ClusterID: pavj3f2ym8u1u1ul5epr3c73f
 Managers: 1
 Nodes: 3
 Orchestration:
 Task History Retention Limit: 5
 Raft:
 Snapshot Interval: 10000
 Number of Old Snapshots to Retain: 0
 Heartbeat Tick: 1
 Election Tick: 10
 Dispatcher:
 Heartbeat Period: 5 seconds
 CA Configuration:
 Expiry Duration: 3 months
 Force Rotate: 0
 Autolock Managers: false
 Root Rotation In Progress: false
 Node Address: 192.168.99.100
 Manager Addresses:
 192.168.99.100:2377
Runtimes: runc
Default Runtime: runc
Init Binary: docker-init
containerd version: 468a545b9edcd5932818eb9de8e72413e616e86e
runc version: 69663f0bd4b60df09991c08812a60108003fa340
init version: fec3683
Kernel Version: 4.9.93-boot2docker
Operating System: Boot2Docker 18.06.1-ce (TCL 8.2.1); HEAD : c7e5c3e - Wed Aug 22 16:27:42 UTC 2018
OSType: linux
Architecture: x86_64
CPUs: 1
Total Memory: 995.6MiB
Name: swarm-manager
ID: NRV7:WAFE:FWDS:63PT:UMZY:G3KU:OU2A:RWRN:RC7D:5ESI:NWRN:NZRU
```

如您所见，在 Swarm 部分有关集群的信息；但是，我们只能针对当前客户端配置为通信的主机运行`docker info`命令。幸运的是，`docker node`命令是集群感知的，因此我们可以使用它来获取有关我们集群中每个节点的信息，例如以下内容：

```
$ docker node inspect swarm-manager --pretty
```

使用`docker node inspect`命令的`--pretty`标志来评估输出，将以易于阅读的格式呈现。如果省略`--pretty`，Docker 将返回包含`inspect`命令针对集群运行的查询结果的原始`JSON`对象。

这应该提供了关于我们 Swarm 管理节点的以下信息：

```
ID: uxgvqhw6npr9glhp0zpabn4ha
Hostname: swarm-manager
Joined at: 2018-09-15 12:14:59.663920111 +0000 utc
Status:
 State: Ready
 Availability: Active
 Address: 192.168.99.100
Manager Status:
 Address: 192.168.99.100:2377
 Raft Status: Reachable
 Leader: Yes
Platform:
 Operating System: linux
 Architecture: x86_64
Resources:
 CPUs: 1
 Memory: 995.6MiB
Plugins:
 Log: awslogs, fluentd, gcplogs, gelf, journald, json-file, logentries, splunk, syslog
 Network: bridge, host, macvlan, null, overlay
 Volume: local
Engine Version: 18.06.1-ce
Engine Labels:
 - provider=virtualbox
```

运行相同的命令，但这次是针对其中一个工作节点：

```
$ docker node inspect swarm-worker01 --pretty
```

这给我们提供了类似的信息：

```
ID: yhqj03rkfzurb4aqzk7duidf4
Hostname: swarm-worker01
Joined at: 2018-09-15 12:24:09.02346782 +0000 utc
Status:
 State: Ready
 Availability: Active
 Address: 192.168.99.101
Platform:
 Operating System: linux
 Architecture: x86_64
Resources:
 CPUs: 1
 Memory: 995.6MiB
Plugins:
 Log: awslogs, fluentd, gcplogs, gelf, journald, json-file, logentries, splunk, syslog
 Network: bridge, host, macvlan, null, overlay
 Volume: local
Engine Version: 18.06.1-ce
Engine Labels:
 - provider=virtualbox
```

但是你会发现，它缺少了关于管理功能状态的信息。这是因为工作节点不需要知道管理节点的状态，它们只需要知道它们可以接收来自管理节点的指令。

通过这种方式，我们可以看到关于这个主机的信息，比如容器的数量，主机上的镜像数量，以及关于 CPU 和内存的信息，还有其他有趣的信息。

# 提升工作节点

假设你想对单个管理节点进行一些维护，但又想保持集群的可用性。没问题，你可以将工作节点提升为管理节点。

我们的本地三节点集群已经运行起来了，现在让我们把`swarm-worker01`提升为新的管理节点。要做到这一点，运行以下命令：

```
$ docker node promote swarm-worker01
```

执行命令后，你应该会收到一个确认你的节点已经被提升的消息：

```
Node swarm-worker01 promoted to a manager in the swarm.
```

通过运行这个命令来列出节点：

```
$ docker node ls
```

这应该显示你现在有两个节点在`MANAGER STATUS`列中显示了一些内容：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/ms-dkr-3e/img/9bf51b6f-2de8-49c7-ad01-563f2199b316.png)

我们的`swarm-manager`节点仍然是主要的管理节点。让我们来处理一下这个问题。

# 降级管理节点

你可能已经联想到了，要将管理节点降级为工作节点，你只需要运行这个命令：

```
$ docker node demote swarm-manager
```

同样，你将立即收到以下反馈：

```
Manager swarm-manager demoted in the swarm.
```

现在我们已经降级了我们的节点，你可以通过运行这个命令来检查集群中节点的状态：

```
$ docker node ls
```

由于你的本地 Docker 客户端仍然指向新降级的节点，你将收到以下消息：

```
Error response from daemon: This node is not a swarm manager. Worker nodes can't be used to view or modify cluster state. Please run this command on a manager node or promote the current node to a manager.
```

正如我们已经学到的，使用 Docker Machine 很容易更新我们本地客户端配置以与其他节点通信。要将本地客户端指向新的管理节点，运行以下命令：

```
$ eval $(docker-machine env swarm-worker01)
```

现在我们的客户端又在与一个管理节点通信了，重新运行这个命令：

```
$ docker node ls
```

它应该列出节点，正如预期的那样：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/ms-dkr-3e/img/0bf7fe15-6d01-4c87-ad79-c4b55d039cb5.png)

# 排水节点

为了暂时从集群中移除一个节点，以便我们可以进行维护，我们需要将节点的状态设置为 Drain。让我们看看如何排水我们以前的管理节点。要做到这一点，我们需要运行以下命令：

```
$ docker node update --availability drain swarm-manager
```

这将停止任何新任务，比如新容器的启动或在我们排水的节点上执行。一旦新任务被阻止，所有正在运行的任务将从我们排水的节点迁移到具有`ACTIVE`状态的节点。

如您从以下终端输出中所见，现在列出节点显示`swarm-manager`节点在`AVAILABILITY`列中被列为`Drain`：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/ms-dkr-3e/img/b656b676-0f32-409d-835a-77c2021e4666.png)

现在我们的节点不再接受新任务，所有正在运行的任务都已迁移到我们剩下的两个节点，我们可以安全地进行维护，比如重新启动主机。要重新启动 Swarm 管理器，请运行以下两个命令，确保您连接到 Docker 主机（您应该看到`boot2docker`横幅，就像在命令后面的截图中一样）：

```
$ docker-machine ssh swarm-manager
$ sudo reboot
```

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/ms-dkr-3e/img/1cb99ead-ce1e-44aa-aee0-5ccf89af0c0a.png)

主机重新启动后，运行此命令：

```
$ docker node ls
```

它应该显示节点的`AVAILABILITY`为`Drain`。要将节点重新添加到集群中，只需通过运行以下命令将`AVAILABILITY`更改为 active：

```
$ docker node update --availability active swarm-manager
```

如您从以下终端输出中所见，我们的节点现在处于活动状态，这意味着可以对其执行新任务：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/ms-dkr-3e/img/b2d8703d-fc56-4745-8cff-087c167cdb54.png)

现在我们已经看过如何创建和管理 Docker Swarm 集群，我们应该看看如何运行诸如创建和扩展服务之类的任务。

# Docker Swarm 服务和堆栈

到目前为止，我们已经看过以下命令：

```
$ docker swarm <command>
$ docker node <command>
```

这两个命令允许我们从一组现有的 Docker 主机引导和管理我们的 Docker Swarm 集群。我们接下来要看的两个命令如下：

```
$ docker service <command>
$ docker stack <command>
```

`service`和`stack`命令允许我们执行任务，进而在我们的 Swarm 集群中启动、扩展和管理容器。

# 服务

`service`命令是启动利用 Swarm 集群的容器的一种方式。让我们来看看在我们的 Swarm 集群上启动一个非常基本的单容器服务。要做到这一点，运行以下命令：

```
$ docker service create \
 --name cluster \
 --constraint "node.role == worker" \
 -p:80:80/tcp \
 russmckendrick/cluster
```

这将创建一个名为 cluster 的服务，该服务由一个单个容器组成，端口`80`从容器映射到主机，它只会在具有工作节点角色的节点上运行。

在我们查看如何处理服务之前，我们可以检查它是否在我们的浏览器上运行。为此，我们需要两个工作节点的 IP 地址。首先，我们需要通过运行此命令再次确认哪些是工作节点：

```
$ docker node ls
```

一旦我们知道哪个节点具有哪个角色，您可以通过运行此命令找到您节点的 IP 地址：

```
$ docker-machine ls
```

查看以下终端输出：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/ms-dkr-3e/img/ec92169f-f6c8-465b-a6fd-ed3c9a670640.png)

我的工作节点是`swarm-manager`和`swarm-worker02`，它们的 IP 地址分别是`192.168.99.100`和`192.168.99.102`。

在浏览器中输入工作节点的任一 IP 地址，例如[`192.168.99.100/`](http://192.168.99.100/)或[`192.168.99.102/`](http://192.168.99.102/)，将显示`russmckendrick/cluster`应用程序的输出，这是 Docker Swarm 图形和页面提供服务的容器的主机名：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/ms-dkr-3e/img/5c4522f7-b026-427a-afd9-9d91648800be.png)

现在我们的服务在集群上运行，我们可以开始了解更多关于它的信息。首先，我们可以通过运行以下命令再次列出服务：

```
$ docker service ls
```

在我们的情况下，这应该返回我们启动的单个名为 cluster 的服务：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/ms-dkr-3e/img/110247ed-8f1f-42f6-8a30-3f9be2da0c99.png)

如您所见，这是一个`replicated`服务，有`1/1`个容器处于活动状态。接下来，您可以通过运行`inspect`命令深入了解有关服务的更多信息：

```
$ docker service inspect cluster --pretty
```

这将返回有关服务的详细信息：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/ms-dkr-3e/img/5289633f-34eb-4900-a7d7-7c6a647e141d.png)

到目前为止，您可能已经注意到，我们无需关心我们的两个工作节点中的服务当前正在哪个节点上运行。这是 Docker Swarm 的一个非常重要的特性，因为它完全消除了您担心单个容器放置的需要。

在我们查看如何扩展我们的服务之前，我们可以通过运行以下命令快速查看我们的单个容器正在哪个主机上运行：

```
$ docker node ps
$ docker node ps swarm-manager
$ docker node ps swarm-worker02
```

这将列出在每个主机上运行的容器。默认情况下，它将列出命令所针对的主机，我这里是`swarm-worker01`：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/ms-dkr-3e/img/ce578e7c-7393-4a2b-8e4b-64f5b33aa575.png)

让我们来看看将我们的服务扩展到六个应用程序容器实例。运行以下命令来扩展和检查我们的服务：

```
$ docker service scale cluster=6
$ docker service ls
$ docker node ps swarm-manager
$ docker node ps swarm-worker02
```

我们只检查两个节点，因为我们最初告诉我们的服务在工作节点上启动。从以下终端输出中可以看出，我们现在在每个工作节点上运行了三个容器：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/ms-dkr-3e/img/8b4bd90c-fa5c-4073-a197-1b20ec53e0c3.png)

在继续查看 stack 之前，让我们删除我们的服务。要做到这一点，请运行以下命令：

```
$ docker service rm cluster
```

这将删除所有容器，同时保留主机上下载的镜像。

# Stacks

使用 Swarm 和服务可以创建相当复杂、高可用的多容器应用程序是完全可能的。在非 Swarm 集群中，手动为应用程序的一部分启动每组容器开始变得有点费力，也很难共享。为此，Docker 创建了功能，允许您在 Docker Compose 文件中定义您的服务。

以下 Docker Compose 文件，应命名为`docker-compose.yml`，将创建与上一节中启动的相同服务：

```
version: "3"
services:
 cluster:
 image: russmckendrick/cluster
 ports:
 - "80:80"
 deploy:
 replicas: 6
 restart_policy:
 condition: on-failure
 placement:
 constraints:
 - node.role == worker
```

正如您所看到的，stack 可以由多个服务组成，每个服务在 Docker Compose 文件的`services`部分下定义。

除了常规的 Docker Compose 命令外，您可以添加一个`deploy`部分；这是您定义与 stack 的 Swarm 元素相关的所有内容的地方。

在前面的示例中，我们说我们想要六个副本，应该分布在我们的两个工作节点上。此外，我们更新了默认的重启策略，您在上一节中检查服务时看到的，它显示为暂停，因此，如果容器变得无响应，它将始终重新启动。

要启动我们的 stack，请将先前的内容复制到名为`docker-compose.yml`的文件中，然后运行以下命令：

```
$ docker stack deploy --compose-file=docker-compose.yml cluster
```

与使用 Docker Compose 启动容器时一样，Docker 将创建一个新网络，然后在其上启动您的服务。

您可以通过运行此命令来检查您的`stack`的状态：

```
$ docker stack ls
```

这将显示已创建一个单一服务。您可以通过运行以下命令来获取由`stack`创建的服务的详细信息：

```
$ docker stack services cluster
```

最后，运行以下命令将显示`stack`中容器的运行位置：

```
$ docker stack ps cluster
```

查看终端输出：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/ms-dkr-3e/img/cb8a2a68-8757-47e4-85b2-96e4dc5dc737.png)

同样，您将能够使用节点的 IP 地址访问堆栈，并且将被路由到其中一个正在运行的容器。要删除一个堆栈，只需运行此命令：

```
$ docker stack rm cluster
```

这将在启动时删除堆栈创建的所有服务和网络。

# 删除 Swarm 集群

在继续之前，因为我们不再需要它用于下一节，您可以通过运行以下命令删除您的 Swarm 集群：

```
$ docker-machine rm swarm-manager swarm-worker01 swarm-worker02
```

如果出于任何原因需要重新启动 Swarm 集群，只需按照本章开头的说明重新创建集群。

# 负载平衡、覆盖和调度

在最后几节中，我们看了如何启动服务和堆栈。要访问我们启动的应用程序，我们可以使用集群中任何主机的 IP 地址；这是如何可能的？

# Ingress 负载平衡

Docker Swarm 内置了一个入口负载均衡器，可以轻松地将流量分发到我们面向公众的容器。

这意味着您可以将 Swarm 集群中的应用程序暴露给服务，例如，像 Amazon Elastic Load Balancer 这样的外部负载均衡器，知道您的请求将被路由到正确的容器，无论当前托管它的主机是哪个，如下图所示：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/ms-dkr-3e/img/2fcef96f-1873-487a-9691-81816678fac5.png)

这意味着我们的应用程序可以进行扩展或缩减、失败或更新，而无需重新配置外部负载均衡器。

# 网络覆盖

在我们的示例中，我们启动了一个运行单个应用程序的简单服务。假设我们想在我们的应用程序中添加一个数据库层，这通常是网络中的一个固定点；我们该如何做呢？

Docker Swarm 的网络覆盖层将您启动容器的网络扩展到多个主机，这意味着每个服务或堆栈可以在其自己的隔离网络中启动。这意味着我们的运行 MongoDB 的数据库容器将在相同的覆盖网络上的所有其他容器上的端口`27017`可访问，无论这些容器运行在哪个主机上。

您可能会想*等一下。这是否意味着我必须将 IP 地址硬编码到我的应用程序配置中？*嗯，这与 Docker Swarm 试图解决的问题不太匹配，所以不，您不必这样做。

每个覆盖网络都有自己内置的 DNS 服务，这意味着在网络中启动的每个容器都能解析同一网络中另一个容器的主机名到其当前分配的 IP 地址。这意味着当我们配置我们的应用程序连接到我们的数据库实例时，我们只需要告诉它连接到，比如，`mongodb:27017`，它就会连接到我们的 MongoDB 容器。

这将使我们的图表如下所示：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/ms-dkr-3e/img/1883cbd8-9542-4be9-a1c4-6477bba73ddc.png)

在采用这种模式时，还有一些其他考虑因素需要考虑，但我们将在第十四章*《Docker 工作流程》*中进行讨论。

# 调度

在撰写本文时，Docker Swarm 中只有一种调度策略，称为 Spread。这种策略的作用是将任务安排在满足你在启动服务或堆栈时定义的任何约束的最轻载节点上运行。在大多数情况下，你不应该对你的服务添加太多约束。

Docker Swarm 目前不支持的一个特性是亲和性和反亲和性规则。虽然可以通过使用约束来解决这个问题，但我建议您不要过于复杂化，因为如果在定义服务时设置了太多约束，很容易导致主机过载或创建单点故障。

# 摘要

在本章中，我们探讨了 Docker Swarm。我们看了如何安装 Docker Swarm 以及组成 Docker Swarm 的 Docker Swarm 组件。我们看了如何使用 Docker Swarm：加入、列出和管理 Swarm 管理器和工作节点。我们回顾了服务和堆栈命令以及如何使用它们，并谈到了 Swarm 内置的入口负载均衡器、覆盖网络和调度器。

在下一章中，我们将介绍一个名为 Kubernetes 的 Docker Swarm 替代方案。这也得到了 Docker 以及其他提供商的支持。

# 问题

1.  真或假：你应该使用独立的 Docker Swarm 而不是内置的 Docker Swarm 模式来运行你的 Docker Swarm？

1.  在启动 Docker Swarm 管理器后，你需要什么来将你的工作节点添加到 Docker Swarm 集群中？

1.  你会使用哪个命令来查找 Docker Swarm 集群中每个节点的状态？

1.  你会添加哪个标志到 docker node inspect Swarm manager 来使其更易读？

1.  如何将节点提升为管理节点？

1.  您可以使用什么命令来扩展您的服务？

# 进一步阅读

关于 Raft 共识算法的详细解释，我推荐阅读名为*数据的秘密生活*的优秀演示，可以在[`thesecretlivesofdata.com/raft`](http://thesecretlivesofdata.com/raft)找到。它通过易于理解的动画解释了后台管理节点上发生的所有过程。


# 第九章：Docker 和 Kubernetes

在本章中，我们将看一下 Kubernetes。与 Docker Swarm 一样，您可以使用 Kubernetes 来创建和管理运行基于容器的应用程序的集群。

本章将涵盖以下主题：

+   Kubernetes 简介

+   启用 Kubernetes

+   使用 Kubernetes

+   Kubernetes 和其他 Docker 工具

# 技术要求

Docker 中的 Kubernetes 仅受 Docker for Mac 和 Docker for Windows 桌面客户端支持。与之前的章节一样，我将使用我偏好的操作系统，即 macOS。与之前一样，一些支持命令可能只适用于 macOS。

查看以下视频以查看代码的运行情况：

[`bit.ly/2q6xpwl`](http://bit.ly/2q6xpwl)

# Kubernetes 简介

如果您一直在考虑查看容器，那么您在旅行中某个时候一定会遇到 Kubernetes，因此在我们在 Docker 桌面安装中启用它之前，让我们花点时间看看 Kubernetes 的来源。

**Kubernetes**（发音为**koo-ber-net-eez**）源自希腊语，意为船长或船长。**Kubernetes**（也被称为**K8s**）是一个源自谷歌的开源项目，允许您自动化部署、管理和扩展容器化的应用程序。

# 谷歌容器的简要历史

谷歌已经在基于 Linux 容器的解决方案上工作了很长时间。它在 2006 年首次采取了行动，通过开发名为**控制组**（**cgroups**）的 Linux 内核功能。这个功能在 2008 年被合并到了 Linux 内核的 2.6.24 版本中。该功能允许您隔离资源，如 CPU、RAM、网络和磁盘 I/O，或一个或多个进程。控制组仍然是 Linux 容器的核心要求，不仅被 Docker 使用，还被其他容器工具使用。

谷歌接下来尝试了一个名为**lmctfy**的容器堆栈，代表**Let Me Contain That For You**。这是**LXC**工具和库的替代品。这是他们自己内部工具的开源版本，用于管理他们自己应用程序中的容器。

谷歌下一次因其容器使用而成为新闻焦点是在 2014 年 5 月的 Gluecon 大会上 Joe Beda 发表讲话之后。在讲话中，Beda 透露谷歌几乎所有的东西都是基于容器的，并且他们每周要启动大约 20 亿个容器。据说这个数字不包括任何长期运行的容器，这意味着这些容器只是短暂活跃。然而，经过一些快速计算，这意味着谷歌平均每秒启动大约 3000 个容器！

在讲话的后来，Beda 提到谷歌使用调度程序，这样他们就不必手动管理每周 20 亿个容器，甚至不必担心它们被启动的位置，以及在较小程度上，每个容器的可用性。

谷歌还发表了一篇名为《谷歌的大规模集群管理与博格》的论文。这篇论文不仅让谷歌以外的人知道他们正在使用的调度程序**博格**的名称，还详细介绍了他们在设计调度程序时所做的设计决策。

论文提到，除了他们的内部工具，谷歌还在运行其面向客户的应用程序，如 Google 文档、Gmail 和 Google 搜索，这些应用程序在由博格管理的容器运行的集群中。

**博格**是以《星际迷航：下一代》电视剧中的外星种族博格而命名的。在电视剧中，博格是一种基于集体意识的网络的赛博人类，使他们不仅能够共享相同的思想，还能通过次空间网络确保集体意识对每个成员进行指导和监督。我相信你会同意，博格种族的特征与你希望你的容器集群运行的方式非常相似。

博格在谷歌内部运行了数年，最终被一种更现代的调度程序**Omega**所取代。大约在这个时候，谷歌宣布他们将采取博格的一些核心功能，并将其复制为一个新的开源项目。这个项目在内部被称为**Seven**，由博格的几位核心贡献者共同开发。它的目标是创建一个更友好的博格版本，不再紧密地与谷歌自己的内部程序和工作方式联系在一起。

**Seven**，以*星际迷航：航海家号*中的角色 Seven of Nine 命名，她是一个从集体中脱离出来的博格，最终在首次公开提交时被命名为**Kubernetes**。

# Kubernetes 概述

现在我们知道了 Kubernetes 的由来，我们可以深入了解一下 Kubernetes 是什么。项目的大部分，精确地说是 88.5%，是用**Go**语言编写的，这一点应该不足为奇，因为 Go 是一种在 2011 年开源之前在 Google 内部开发的编程语言。项目文件的其余部分由 Python 和 Shell 辅助脚本以及 HTML 文档组成。

一个典型的 Kubernetes 集群由承担主节点或节点角色的服务器组成。您也可以运行一个承担两种角色的独立安装。

主节点是魔术发生的地方，也是集群的大脑。它负责决定 Pod 的启动位置，并监视集群本身和集群内运行的 Pod 的健康状况。我们在讨论完这两个角色后会讨论 Pod。

通常，部署到被赋予主节点角色的主机上的核心组件有：

+   kube-apiserver：这个组件暴露了主要的 Kubernetes API。它被设计为水平扩展，这意味着您可以不断添加更多的实例来使您的集群高度可用。

+   etcd：这是一个高可用的一致性键值存储。它用于存储集群的状态。

+   kube-scheduler：这个组件负责决定 Pod 的启动位置。

+   kube-controller-manager：这个组件运行控制器。这些控制器在 Kubernetes 中有多个功能，比如监视节点、关注复制、管理端点，以及生成服务账户和令牌。

+   cloud-controller-manager：这个组件负责管理各种控制器，这些控制器与第三方云进行交互，启动和配置支持服务。

现在我们已经涵盖了管理组件，我们需要讨论它们在管理什么。一个节点由以下组件组成：

+   kubelet：这个代理程序在集群中的每个节点上运行，是管理者与节点交互的手段。它还负责管理 Pod。

+   `kube-proxy`：这个组件管理节点和 pod 的所有请求和流量的路由。

+   `容器运行时`：这可以是 Docker RKT 或任何其他符合 OCI 标准的运行时。

到目前为止，您可能已经注意到我并没有提到容器。这是因为 Kubernetes 实际上并不直接与您的容器交互；相反，它与一个 pod 进行通信。将 pod 视为一个完整的应用程序；有点像我们使用 Docker Compose 启动由多个容器组成的应用程序时的情况。

# Kubernetes 和 Docker

最初，Kubernetes 被视为 Docker Swarm 的竞争技术，Docker 自己的集群技术。然而，在过去几年中，Kubernetes 已经几乎成为容器编排的事实标准。

所有主要的云提供商都提供 Kubernetes 即服务。我们有以下内容：

+   谷歌云：谷歌 Kubernetes 引擎（GKE）

+   Microsoft Azure：Azure Kubernetes 服务（AKS）

+   亚马逊网络服务：亚马逊弹性 Kubernetes 容器服务（EKS）

+   IBM：IBM 云 Kubernetes 服务

+   甲骨文云：甲骨文 Kubernetes 容器引擎

+   DigitalOcean：DigitalOcean 上的 Kubernetes

从表面上看，所有主要支持 Kubernetes 的参与者可能看起来并不像是一件大事。然而，请考虑我们现在知道了一种在多个平台上部署我们的容器化应用程序的一致方式。传统上，这些平台一直是封闭的花园，并且与它们互动的方式非常不同。

尽管 Docker 在 2017 年 10 月的 DockerCon Europe 上的宣布最初令人惊讶，但一旦尘埃落定，这一宣布就变得非常合理。为开发人员提供一个环境，在这个环境中他们可以在本地使用 Docker for Mac 和 Docker for Windows 工作，然后使用 Docker 企业版来部署和管理他们自己的 Kubernetes 集群，或者甚至使用之前提到的云服务之一，这符合我们在[第一章]中讨论的解决“在我的机器上可以运行”的问题，Docker 概述。

现在让我们看看如何在 Docker 软件中启用支持并开始使用它。

# 启用 Kubernetes

Docker 已经使安装过程变得非常简单。要启用 Kubernetes 支持，您只需打开首选项，然后点击 Kubernetes 选项卡：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/ms-dkr-3e/img/f8afeef8-84b7-4a46-9736-c66e4c55fad1.png)

如你所见，有两个主要选项。选中**启用 Kubernetes**框，然后选择**Kubernetes**作为默认编排器。暂时不要选中**显示系统容器**；我们在启用服务后会更详细地看一下这个。点击**应用**将弹出以下消息：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/ms-dkr-3e/img/05f430c4-01bf-4762-b57b-73baa62a256c.png)

点击**安装**按钮将下载所需的容器，以启用 Docker 安装上的 Kubernetes 支持：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/ms-dkr-3e/img/da563414-8ffb-4c6c-80a8-b6ddd796ef84.png)

如在第一个对话框中提到的，Docker 将需要一段时间来下载、配置和启动集群。完成后，你应该看到**Kubernetes 正在运行**旁边有一个绿点：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/ms-dkr-3e/img/50d81853-7da1-42ac-bbb2-bff9d816bda9.png)

打开终端并运行以下命令：

```
$ docker container ls -a
```

这应该显示没有异常运行。运行以下命令：

```
$ docker image ls
```

这应该显示一个与 Kubernetes 相关的图像列表：

+   `docker/kube-compose-controller`

+   `docker/kube-compose-api-server`

+   `k8s.gcr.io/kube-proxy-amd64`

+   `k8s.gcr.io/kube-scheduler-amd64`

+   `k8s.gcr.io/kube-apiserver-amd64`

+   `k8s.gcr.io/kube-controller-manager-amd64`

+   `k8s.gcr.io/etcd-amd64`

+   `k8s.gcr.io/k8s-dns-dnsmasq-nanny-amd64`

+   `k8s.gcr.io/k8s-dns-sidecar-amd64`

+   `k8s.gcr.io/k8s-dns-kube-dns-amd64`

+   `k8s.gcr.io/pause-amd64`

这些图像来自 Docker 和 Google 容器注册表（`k8s.gcr.io`）上可用的官方 Kubernetes 图像。

正如你可能已经猜到的，选中**显示系统容器（高级）**框，然后运行以下命令将显示在本地 Docker 安装上启用 Kubernetes 服务的所有正在运行的容器的列表：

```
$ docker container ls -a
```

由于运行上述命令时会产生大量输出，下面的屏幕截图只显示了容器的名称。为了做到这一点，我运行了以下命令：

```
$ docker container ls --format {{.Names}}
```

运行该命令给我以下结果：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/ms-dkr-3e/img/1e714f65-62af-41da-8cca-59d3b6cea891.png)

有 18 个正在运行的容器，这就是为什么你可以选择隐藏它们。正如你所看到的，几乎我们在上一节讨论的所有组件都包括在内，还有一些额外的组件，提供了与 Docker 的集成。我建议取消选中**显示系统容器**框，因为我们不需要每次查看正在运行的容器时都看到 18 个容器的列表。

此时需要注意的另一件事是，Kubernetes 菜单项现在已经有内容了。这个菜单可以用于在 Kubernetes 集群之间进行切换。由于我们目前只有一个活动的集群，所以只有一个被列出来：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/ms-dkr-3e/img/ebc6ad44-b922-4b56-9512-072df178d34c.png)

现在我们的本地 Kubernetes 集群已经运行起来了，我们可以开始使用它了。

# 使用 Kubernetes

现在我们的 Kubernetes 集群已经在我们的 Docker 桌面安装上运行起来了，我们可以开始与之交互了。首先，我们将看一下与 Docker 桌面组件一起安装的命令行`kubectl`。

如前所述，`kubectl`是与之一起安装的。以下命令将显示有关客户端以及连接到的集群的一些信息：

```
$ kubectl version
```

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/ms-dkr-3e/img/5005937f-00f6-4be5-a2a8-06ddbfdb23d1.png)

接下来，我们可以运行以下命令来查看`kubectl`是否能够看到我们的节点：

```
$ kubectl get nodes
```

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/ms-dkr-3e/img/05607ef3-a64a-4c33-96bf-8ead71987a7b.png)

现在我们的客户端正在与我们的节点进行交互，我们可以通过运行以下命令查看 Kubernetes 默认配置的`namespaces`：

```
$ kubectl get namespaces
```

然后我们可以使用以下命令查看命名空间内的`pods`：

```
$ kubectl get --namespace kube-system pods
```

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/ms-dkr-3e/img/f5f27507-e03d-458a-aca5-341fdda41a14.png)

Kubernetes 中的命名空间是在集群内隔离资源的好方法。从终端输出中可以看到，我们的集群内有四个命名空间。有一个`default`命名空间，通常是空的。有两个主要 Kubernetes 服务的命名空间：`docker`和`kube-system`。这些包含了构成我们集群的 pod，最后一个命名空间`kube-public`，与默认命名空间一样，是空的。

在启动我们自己的 pod 之前，让我们快速看一下我们如何与正在运行的 pod 进行交互，首先是如何找到有关我们的 pod 的更多信息：

```
$ kubectl describe --namespace kube-system pods kube-scheduler-docker-for-desktop 
```

上面的命令将打印出`kube-scheduler-docker-for-desktop` pod 的详细信息。您可能注意到我们必须使用`--namespace`标志传递命名空间。如果我们不这样做，那么`kubectl`将默认到默认命名空间，那里没有名为`kube-scheduler-docker-for-desktop`的 pod 在运行。

命令的完整输出如下：

```
Name: kube-scheduler-docker-for-desktop
Namespace: kube-system
Node: docker-for-desktop/192.168.65.3
Start Time: Sat, 22 Sep 2018 14:10:14 +0100
Labels: component=kube-scheduler
 tier=control-plane
Annotations: kubernetes.io/config.hash=6d5c9cb98205e46b85b941c8a44fc236
 kubernetes.io/config.mirror=6d5c9cb98205e46b85b941c8a44fc236
 kubernetes.io/config.seen=2018-09-22T11:07:47.025395325Z
 kubernetes.io/config.source=file
 scheduler.alpha.kubernetes.io/critical-pod=
Status: Running
IP: 192.168.65.3
Containers:
 kube-scheduler:
 Container ID: docker://7616b003b3c94ca6e7fd1bc3ec63f41fcb4b7ce845ef7a1fb8af1a2447e45859
 Image: k8s.gcr.io/kube-scheduler-amd64:v1.10.3
 Image ID: docker-pullable://k8s.gcr.io/kube-scheduler-amd64@sha256:4770e1f1eef2229138e45a2b813c927e971da9c40256a7e2321ccf825af56916
 Port: <none>
 Host Port: <none>
 Command:
 kube-scheduler
 --kubeconfig=/etc/kubernetes/scheduler.conf
 --address=127.0.0.1
 --leader-elect=true
 State: Running
 Started: Sat, 22 Sep 2018 14:10:16 +0100
 Ready: True
 Restart Count: 0
 Requests:
 cpu: 100m
 Liveness: http-get http://127.0.0.1:10251/healthz delay=15s timeout=15s period=10s #success=1 #failure=8
 Environment: <none>
 Mounts:
 /etc/kubernetes/scheduler.conf from kubeconfig (ro)
Conditions:
 Type Status
 Initialized True
 Ready True
 PodScheduled True
Volumes:
 kubeconfig:
 Type: HostPath (bare host directory volume)
 Path: /etc/kubernetes/scheduler.conf
 HostPathType: FileOrCreate
QoS Class: Burstable
Node-Selectors: <none>
Tolerations: :NoExecute
Events: <none>
```

正如您所见，关于 pod 有很多信息，包括容器列表；我们只有一个叫做`kube-scheduler`。我们可以看到容器 ID，使用的镜像，容器启动时使用的标志，以及 Kubernetes 调度器用于启动和维护 pod 的数据。

现在我们知道了容器名称，我们可以开始与其交互。例如，运行以下命令将打印我们一个容器的日志：

```
$ kubectl logs --namespace kube-system kube-scheduler-docker-for-desktop -c kube-scheduler 
```

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/ms-dkr-3e/img/f153d87e-fd6b-40e0-a0c2-bd142037ee33.png)

运行以下命令将获取 pod 中每个容器的`logs`：

```
$ kubectl logs --namespace kube-system kube-scheduler-docker-for-desktop
```

与 Docker 一样，您还可以在您的 pod 和容器上执行命令。例如，以下命令将运行`uname -a`命令：

请确保在以下两个命令后添加`--`后面的空格。如果未这样做，将导致错误。

```
$ kubectl exec --namespace kube-system kube-scheduler-docker-for-desktop -c kube-scheduler -- uname -a
$ kubectl exec --namespace kube-system kube-scheduler-docker-for-desktop -- uname -a
```

同样，我们可以选择在命名容器上运行命令，或者跨 pod 内的所有容器运行命令：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/ms-dkr-3e/img/8ea74f60-7de1-418a-8bcb-7499fa8c9d1b.png)

通过安装并登录到基于 Web 的仪表板，让我们对 Kubernetes 集群有更多了解。虽然这不是 Docker 的默认功能，但使用 Kubernetes 项目提供的定义文件进行安装非常简单。我们只需要运行以下命令：

```
$ kubectl create -f https://raw.githubusercontent.com/kubernetes/dashboard/master/src/deploy/recommended/kubernetes-dashboard.yaml
```

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/ms-dkr-3e/img/20527938-448d-441a-bee4-90a1f5db0896.png)

一旦服务和部署已经创建，启动需要几分钟。您可以通过运行以下命令来检查状态：

```
$ kubectl get deployments --namespace kube-system
$ kubectl get services --namespace kube-system
```

一旦您的输出看起来像以下内容，您的仪表板应该已经安装并准备就绪：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/ms-dkr-3e/img/1f52f317-e1e9-4018-ac30-f73aa6933cfa.png)

现在我们的仪表板正在运行，我们将找到一种访问它的方法。我们可以使用`kubectl`中的内置代理服务来实现。只需运行以下命令即可启动：

```
$ kubectl proxy
```

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/ms-dkr-3e/img/315bb32e-3b82-4a00-b8af-91af2501ccd3.png)

这将启动代理，并打开您的浏览器并转到`http://127.0.0.1:8001/version/`将显示有关您的集群的一些信息：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/ms-dkr-3e/img/6750c373-4a9e-4a2f-a7e0-b391af94acba.png)

然而，我们想要看到的是仪表板。可以通过以下网址访问：`http://localhost:8001/api/v1/namespaces/kube-system/services/https:kubernetes-dashboard:/proxy/`。

当您首次在浏览器中打开 URL 时，将会看到登录屏幕。由于我们是通过代理访问仪表板，因此我们只需按下**SKIP**按钮：

**![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/ms-dkr-3e/img/ddd8e4aa-30aa-4377-a812-693beee5b196.png)**

登录后，您将能够看到有关您的集群的大量信息：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/ms-dkr-3e/img/5f146b4a-3f88-4d8f-9c2b-eec242281cbe.png)

既然我们的集群已经启动运行，我们现在可以看一下启动一些示例应用程序。

# Kubernetes 和其他 Docker 工具

当我们启用 Kubernetes 时，我们选择了 Kubernetes 作为 Docker 堆栈命令的默认编排器。在上一章中，Docker `stack`命令将在 Docker Swarm 中启动我们的 Docker Compose 文件。我们使用的 Docker Compose 看起来像下面这样：

```
version: "3"
services:
 cluster:
 image: russmckendrick/cluster
 ports:
 - "80:80"
 deploy:
 replicas: 6
 restart_policy:
 condition: on-failure
 placement:
 constraints:
 - node.role == worker
```

在 Kubernetes 上启动应用程序之前，我们需要进行一些微调并删除放置，这样我们的文件看起来像下面这样：

```
version: "3"
services:
 cluster:
 image: russmckendrick/cluster
 ports:
 - "80:80"
 deploy:
 replicas: 6
 restart_policy:
 condition: on-failure
```

编辑文件后，运行以下命令将启动`stack`：

```
$ docker stack deploy --compose-file=docker-compose.yml cluster
```

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/ms-dkr-3e/img/1a9cfbdc-f787-4737-b52f-c5197eec5a00.png)

正如您所看到的，Docker 会等到堆栈可用后才将您返回到提示符。我们还可以运行与我们在 Docker Swarm 上启动堆栈时使用的相同命令来查看有关我们的堆栈的一些信息：

```
$ docker stack ls
$ docker stack services cluster
$ docker stack ps cluster
```

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/ms-dkr-3e/img/db628bed-b212-4e3a-9ab8-a28cd4264f59.png)

我们还可以使用`kubectl`查看详细信息：

```
$ kubectl get deployments
$ kubectl get services
```

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/ms-dkr-3e/img/73e1ed2f-01d7-4cb2-82d3-ce93d24c7126.png)

您可能已经注意到，这一次我们不需要提供命名空间。这是因为我们的堆栈是在默认命名空间中启动的。此外，在列出服务时，为集群堆栈列出了 ClusterIP 和 LoadBalancer。查看 LoadBalancer，您会看到外部 IP 是`localhost`，端口是`80`。

在我们的浏览器中打开[`localhost/`](http://localhost/)显示应用程序：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/ms-dkr-3e/img/875e57d6-b43c-453c-b980-bdaed5ad4397.png)

如果您仍然打开着仪表板，您可以探索您的堆栈，甚至打开一个容器的终端：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/ms-dkr-3e/img/8536ae3e-d84c-4df9-b481-2823300abb52.png)

您可以通过运行以下命令来删除`stack`：

```
$ docker stack rm cluster
```

最后一件事 - 您可能会想，太好了，我可以在 Kubernetes 集群的任何地方运行我的 Docker Compose 文件。嗯，这并不完全正确。如前所述，当我们首次启用 Kubernetes 时，会启动一些仅适用于 Docker 的组件。这些组件旨在尽可能紧密地集成 Docker。但是，由于这些组件在非 Docker 管理的集群中不存在，因此您将无法再使用`docker stack`命令。

尽管如此，还有一个工具叫做**Kompose**，它是 Kubernetes 项目的一部分，可以接受 Docker Compose 文件并将其即时转换为 Kubernetes 定义文件。

要在 macOS 上安装 Kompose，请运行以下命令：

```
$ curl -L https://github.com/kubernetes/kompose/releases/download/v1.16.0/kompose-darwin-amd64 -o /usr/local/bin/kompose
$ chmod +x /usr/local/bin/kompose
```

Windows 10 用户可以使用 Chocolatey 来安装二进制文件：

**Chocolatey**是一个基于命令行的软件包管理器，可用于在基于 Windows 的机器上安装各种软件包，类似于在 Linux 机器上使用`yum`或`apt-get`，或在 macOS 上使用`brew`。

```
$ choco install kubernetes-kompose
```

最后，Linux 用户可以运行以下命令：

```
$ curl -L https://github.com/kubernetes/kompose/releases/download/v1.16.0/kompose-linux-amd64 -o /usr/local/bin/kompose
$ chmod +x /usr/local/bin/kompose
```

安装完成后，您可以通过运行以下命令启动您的 Docker Compose 文件：

```
$ kompose up
```

您将得到类似以下输出：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/ms-dkr-3e/img/90c65ca1-44e3-419b-9896-98dc7f5d225f.png)

如输出所建议的，运行以下命令将为您提供刚刚启动的服务和 pod 的详细信息：

```
$ kubectl get deployment,svc,pods,pvc
```

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/ms-dkr-3e/img/7dc83cb6-26c1-4e87-a584-802608ede4c7.png)

您可以通过运行以下命令来删除服务和 pod：

```
$ kompose down
```

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/ms-dkr-3e/img/d3076f4e-b5ad-4eda-8243-150499252542.png)

虽然您可以使用`kompose up`和`kompose down`，但我建议生成 Kubernetes 定义文件并根据需要进行调整。要做到这一点，只需运行以下命令：

```
$ kompose convert
```

这将生成 pod 和 service 文件：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/ms-dkr-3e/img/1a7d963d-ee6f-40e4-935b-f52c9a15467f.png)

您将能够看到 Docker Compose 文件和生成的两个文件之间有很大的区别。`cluster-pod.yaml`文件如下所示：

```
apiVersion: v1
kind: Pod
metadata:
 creationTimestamp: null
 labels:
 io.kompose.service: cluster
 name: cluster
spec:
 containers:
 - image: russmckendrick/cluster
 name: cluster
 ports:
 - containerPort: 80
 resources: {}
 restartPolicy: OnFailure
status: {}
```

`cluster-service.yaml`文件如下所示：

```
apiVersion: v1
kind: Service
metadata:
 annotations:
 kompose.cmd: kompose convert
 kompose.version: 1.16.0 (0c01309)
 creationTimestamp: null
 labels:
 io.kompose.service: cluster
 name: cluster
spec:
 ports:
 - name: "80"
 port: 80
 targetPort: 80
 selector:
 io.kompose.service: cluster
status:
 loadBalancer: {}
```

然后，您可以通过运行以下命令来启动这些文件：

```
$ kubectl create -f cluster-pod.yaml
$ kubectl create -f cluster-service.yaml
$ kubectl get deployment,svc,pods,pvc
```

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/ms-dkr-3e/img/4909293e-096a-4729-9f2c-2af7c39e8d52.png)

删除集群 pod 和服务，我们只需要运行以下命令：

```
$ kubectl delete service/cluster pod/cluster
```

虽然 Kubernetes 将在接下来的章节中出现，您可能希望在 Docker 桌面安装中禁用 Kubernetes 集成，因为它在空闲时会增加一些开销。要做到这一点，只需取消选中**启用 Kubernetes**。单击**应用**后，Docker 将停止运行 Kubernetes 所需的所有容器；但它不会删除镜像，因此当您重新启用它时，不会花费太长时间。

# 摘要

在本章中，我们从 Docker 桌面软件的角度看了 Kubernetes。Kubernetes 比我们在本章中介绍的要复杂得多，所以请不要认为这就是全部。在讨论了 Kubernetes 的起源之后，我们看了如何使用 Docker for Mac 或 Docker for Windows 在本地机器上启用它。

然后我们讨论了一些`kubectl`的基本用法，然后看了如何使用`docker stack`命令来启动我们的应用程序，就像我们为 Docker Swarm 做的那样。

在本章末尾，我们讨论了 Kompose，这是 Kubernetes 项目下的一个工具。它可以帮助您将 Docker Compose 文件转换为 Kubernetes 可用，从而让您提前开始将应用程序迁移到纯 Kubernetes。

在下一章中，我们将看看在公共云上使用 Docker，比如亚马逊网络服务，以及简要回顾 Kubernetes。

# 问题

+   真或假：当未选中**显示系统容器（高级）**时，您无法看到用于启动 Kubernetes 的镜像。

+   四个命名空间中的哪一个托管了用于在 Docker 中运行 Kubernetes 并支持的容器？

+   您将运行哪个命令来查找运行在 pod 中的容器的详细信息？

+   您将使用哪个命令来启动 Kubernetes 定义的 YAML 文件？

+   通常，命令`kubectl`代理在本地机器上打开哪个端口？

+   Google 容器编排平台的原始名称是什么？

# 进一步阅读

在本章开头提到的一些 Google 工具、演示文稿和白皮书可以在以下位置找到：

+   cgroups: [`man7.org/linux/man-pages/man7/cgroups.7.html`](http://man7.org/linux/man-pages/man7/cgroups.7.html)

+   lmctfy:[ https://github.com/google/lmctfy/](https://github.com/google/lmctfy/)

+   Google Borg 中的大规模集群管理：[`ai.google/research/pubs/pub43438`](https://ai.google/research/pubs/pub43438)

+   Google Borg 中的大规模集群管理：[`ai.google/research/pubs/pub43438`](https://ai.google/research/pubs/pub43438)

+   LXC - [`linuxcontainers.org/`](https://linuxcontainers.org/)

您可以在本章中提到的云服务的详细信息。

+   Google Kubernetes Engine (GKE): [`cloud.google.com/kubernetes-engine/`](https://cloud.google.com/kubernetes-engine/)

+   Azure Kubernetes 服务 (AKS): [`azure.microsoft.com/en-gb/services/kubernetes-service/`](https://azure.microsoft.com/en-gb/services/kubernetes-service/)

+   亚马逊弹性容器服务 for Kubernetes (Amazon EKS): [`aws.amazon.com/eks/`](https://aws.amazon.com/eks/)

+   IBM 云 Kubernetes 服务: [`www.ibm.com/cloud/container-service`](https://www.ibm.com/cloud/container-service)

+   Oracle 容器引擎 for Kubernetes: [`cloud.oracle.com/containers/kubernetes-engine`](https://cloud.oracle.com/containers/kubernetes-engine)

+   DigitalOcean 上的 Kubernetes: [`www.digitalocean.com/products/kubernetes/`](https://www.digitalocean.com/products/kubernetes/)

您可以在以下找到 Docker 关于 Kubernetes 支持的公告：

+   Docker Enterprise 宣布支持 Kubernetes：[`blog.docker.com/2017/10/docker-enterprise-edition-kubernetes/`](https://blog.docker.com/2017/10/docker-enterprise-edition-kubernetes/)

+   Kubernetes 发布稳定版本：[ https://blog.docker.com/2018/07/kubernetes-is-now-available-in-docker-desktop-stable-channel/](https://blog.docker.com/2018/07/kubernetes-is-now-available-in-docker-desktop-stable-channel/)

最后，Kompose 的主页可以在以下找到：

+   Kompose - [`kompose.io/`](http://kompose.io/)


# 第十章：在公共云中运行 Docker

到目前为止，我们一直在使用 Digital Ocean 在基于云的基础设施上启动容器。在本章中，我们将研究使用 Docker 提供的工具在 Amazon Web Services 和 Microsoft Azure 中启动 Docker Swarm 集群。然后，我们将研究 Amazon Web Services、Microsoft Azure 和 Google Cloud 提供的容器解决方案。

本章将涵盖以下主题：

+   Docker Cloud

+   Amazon ECS 和 AWS Fargate

+   Microsoft Azure 应用服务

+   Microsoft Azure、Google Cloud 和 Amazon Web Services 中的 Kubernetes

# 技术要求

在本章中，我们将使用各种云提供商，因此如果您在跟进，您将需要在每个提供商上拥有活跃的账户。同样，本章中的截图将来自我首选的操作系统 macOS。与以前一样，我们将运行的命令应该在我们迄今为止所针对的三个操作系统上都能工作，除非另有说明。

我们还将研究云提供商提供的一些命令行工具，以帮助管理他们的服务-本章不作为这些工具的详细使用指南，但在本章的*进一步阅读*部分中将提供更详细的使用指南的链接。

查看以下视频，了解代码的运行情况：

[`bit.ly/2Se544n`](http://bit.ly/2Se544n)

# Docker Cloud

在我们开始查看其他服务之前，我认为快速讨论一下 Docker Cloud 会是一个好主意，因为仍然有很多关于 Docker 曾经提供的云管理服务的参考资料。

Docker Cloud 由几个 Docker 服务组成。这些包括用于构建和托管镜像的 SaaS 服务，这是另一项提供的服务，应用程序、节点和 Docker Swarm 集群管理。在 2018 年 5 月 21 日，所有提供远程节点管理的服务都已关闭。

Docker 建议使用 Docker Cloud 的用户将其使用该服务管理节点的工作负载迁移到 Docker **Community Edition** (**CE**)或 Docker **Enterprise Edition** (**EE**)以及其自己硬件的云中。Docker 还推荐了 Azure 容器服务和 Google Kubernetes 引擎。

因此，在本章中，我们不会像在以前的*掌握 Docker*版本中那样讨论任何 Docker 托管服务。

然而，考虑到我们所讨论的内容，下一节可能会有点令人困惑。虽然 Docker 已经停止了所有托管的云管理服务，但它仍然提供工具来帮助您在两个主要的公共云提供商中管理您的 Docker Swarm 集群。

# 云上的 Docker

在本节中，我们将看看 Docker 提供的两个模板化云服务。这两个都会启动 Docker Swarm 集群，并且与目标平台有深度集成，并且还考虑了 Docker 的最佳实践。让我们先看看 Amazon Web Services 模板。

# Docker 社区版适用于 AWS

Docker 社区版适用于 AWS（我们从现在开始称之为 Docker for AWS）是由 Docker 创建的一个 Amazon CloudFormation 模板，旨在在 AWS 中轻松启动 Docker Swarm 模式集群，并应用了 Docker 的最佳实践和建议。

**CloudFormation**是亚马逊提供的一项服务，允许您在一个模板文件中定义您希望您的基础架构看起来的方式，然后可以共享或纳入版本控制。

我们需要做的第一件事 - 也是在启动 Docker for AWS 之前唯一需要配置的事情 - 是确保我们在将要启动集群的区域中为我们的帐户分配了 SSH 密钥。要做到这一点，请登录到 AWS 控制台[`console.aws.amazon.com/`](https://console.aws.amazon.com/)，或者如果您使用自定义登录页面，则登录到您的组织的自定义登录页面。登录后，转到页面左上角的服务菜单，找到**EC2**服务。

为了确保您在所需的区域中，您可以在用户名和支持菜单之间的右上角使用区域切换器。一旦您在正确的区域中，点击**密钥对**，它可以在左侧菜单中的**网络和安全**下找到。进入**密钥对**页面后，您应该看到您当前密钥对的列表。如果没有列出或者您无法访问它们，您可以单击**创建密钥对**或**导入密钥对**，然后按照屏幕提示操作。

Docker for AWS 可以在 Docker Store 中找到[`store.docker.com/editions/community/docker-ce-aws`](https://store.docker.com/editions/community/docker-ce-aws)。您可以选择 Docker for AWS 的两个版本：稳定版和 Edge 版本。

Edge 版本包含来自即将推出的 Docker 版本的实验性功能；因此，我们将看看如何启动 Docker for AWS（稳定版）。要做到这一点，只需点击按钮，您将直接进入 AWS 控制台中的 CloudFormation，Docker 模板已经加载。

您可以查看原始模板，目前由 3100 行代码组成，方法是转到[`editions-us-east-1.s3.amazonaws.com/aws/stable/Docker.tmpl`](https://editions-us-east-1.s3.amazonaws.com/aws/stable/Docker.tmpl)，或者您可以在 CloudFormation 设计师中可视化模板。如您从以下可视化中所见，有很多内容可以启动集群：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/ms-dkr-3e/img/94c34f21-31ad-4493-900c-293d3dcf0cd2.png)

这种方法的美妙之处在于，您不必担心任何这些复杂性。Docker 已经为您考虑周全，并且已经承担了所有关于如何启动上述基础设施和服务的工作。

启动集群的第一步已经为您准备好了。您只需在**选择模板**页面上点击**下一步**：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/ms-dkr-3e/img/efd42eec-ca73-40ba-a7f0-10dfade0ac1e.png)

接下来，我们必须指定有关我们的集群的一些细节。除了 SSH 密钥，我们将保持一切默认值不变：

+   **堆栈名称**：`Docker`

+   **Swarm 管理器数量**：`3`

+   **Swarm 工作节点数量**：`5`

+   **要使用哪个 SSH 密钥**：（从列表中选择您的密钥）

+   **启用每日资源清理**：否

+   **使用 CloudWatch 进行容器日志记录**：是

+   **为 CloudStore 创建 EFS 先决条件**：否

+   **Swarm 管理器实例类型**：t2.micro

+   **管理器临时存储卷大小**：20

+   **管理器临时存储卷类型**：标准

+   **代理工作实例类型**：t2.micro

+   **工作实例临时存储卷大小**：20

+   **工作实例临时存储卷类型**：标准

+   **启用 EBS I/O 优化？** 否

+   **加密 EFS 对象？** 假

一旦您确认一切**正常**，请点击**下一步**按钮。在下一步中，我们可以将一切保持不变，然后点击**下一步**按钮，进入审核页面。在审核页面上，您应该找到一个链接，给出了估算成本：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/ms-dkr-3e/img/d39ed962-001f-49a0-aa2a-210eb1bc50eb.png)

如您所见，我的集群的月度估算为 113.46 美元。

我对“估算成本”链接的成功率有所不同——如果它没有出现，并且您已根据上述列表回答了问题，那么您的成本将与我的相似。

在启动集群之前，您需要做的最后一件事是勾选“我承认 AWS CloudFormation 可能会创建 IAM 资源”的复选框，然后点击“创建”按钮。正如您所想象的那样，启动集群需要一些时间；您可以通过在 AWS 控制台中选择您的 CloudFormation 堆栈并选择“事件”选项卡来检查启动的状态：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/ms-dkr-3e/img/a8a82d94-d51e-4d61-82d9-e7ca88708725.png)

大约 15 分钟后，您应该会看到状态从“CREATE_IN_PROGRESS”更改为“CREATE_COMPLETE”。当您看到这一点时，点击“输出”选项卡，您应该会看到一系列 URL 和链接：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/ms-dkr-3e/img/98e173dc-9ce2-48a0-9a5e-7e24156c1349.png)

要登录到我们的 Swarm 集群，点击“管理者”旁边的链接，进入 EC2 实例列表，这些是我们的管理节点。选择一个实例，然后记下其公共 DNS 地址。在终端中，使用 docker 作为用户名 SSH 到节点。例如，我运行以下命令登录并获取所有节点列表：

```
$ ssh docker@ec2-34-245-167-38.eu-west-1.compute.amazonaws.com
$ docker node ls
```

如果您在添加密钥时从 AWS 控制台下载了您的 SSH 密钥，您应该更新上述命令以包括您下载密钥的路径，例如，`ssh -i /path/to/private.key docker@ec2-34-245-167-38.eu-west-1.compute.amazonaws.com`。

登录并获取所有节点列表的先前命令显示在以下截图中：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/ms-dkr-3e/img/9198f5ee-5731-4b5f-b733-78de04e63158.png)

从这里，您可以像对待任何其他 Docker Swarm 集群一样对待它。例如，我们可以通过运行以下命令来启动和扩展集群服务：

```
$ docker service create --name cluster --constraint "node.role == worker" -p 80:80/tcp russmckendrick/cluster
$ docker service scale cluster=6
$ docker service ls
$ docker service inspect --pretty cluster
```

现在您的服务已经启动，您可以在 CloudFormation 页面的“输出”选项卡中查看给定 URL 作为“DefaultDNSTarget”的应用程序。这是一个 Amazon 弹性负载均衡器，所有节点都在其后面。

例如，我的“DefaultDNSTarget”是`Docker-ExternalLoa-PCIAX1UI53AS-1796222965.eu-west-1.elb.amazonaws.com`。将其放入浏览器中显示了集群应用程序：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/ms-dkr-3e/img/80e2bf26-45b2-4e45-a601-073052f7e191.png)

完成集群后，返回到 AWS 控制台中的 CloudFormation 页面，选择您的堆栈，然后从“操作”下拉菜单中选择“删除堆栈”。这将删除 Amazon Web Services 集群中 Docker 的所有痕迹，并阻止您产生任何意外费用。

请确保检查删除堆栈时没有出现任何问题——如果此过程遇到任何问题，任何留下的资源都将产生费用。

# Docker 社区版 Azure

接下来，我们有 Azure 的 Docker 社区版，我将称之为 Docker for Azure。这使用 Azure 资源管理器（ARM）模板来定义我们的 Docker Swarm 集群。使用 ARMViz 工具，我们可以可视化集群的外观：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/ms-dkr-3e/img/3c55ee06-9812-4e68-9646-2f31719b7fac.png)

如您所见，它将启动虚拟机、带有公共 IP 地址的负载均衡器和存储。在启动我们的集群之前，我们需要找到有关我们的 Azure 帐户的一些信息：

+   AD 服务主体 ID

+   AD 服务主体密钥

为了生成所需的信息，我们将使用一个在容器内运行的辅助脚本。要运行该脚本，您需要对有效的 Azure 订阅具有管理员访问权限。要运行脚本，只需运行以下命令：

```
$ docker run -ti docker4x/create-sp-azure sp-name
```

这将为您提供一个 URL，[`microsoft.com/devicelogin`](https://microsoft.com/devicelogin)，还有一个要输入的代码。转到该 URL 并输入代码：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/ms-dkr-3e/img/72247725-713a-42ad-a02e-97369dde5f79.png)

这将在命令行中登录您的帐户，并询问您想要使用哪个订阅。辅助脚本的完整输出可以在以下截图中找到：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/ms-dkr-3e/img/e996f939-d086-454c-805a-eddb97d1e319.png)

在输出的最后，您将找到所需的信息，请记下来。

在撰写本书时，已知在 Docker Store 的 Docker 社区版 Azure 页面上使用“Docker for Azure（稳定版）”按钮存在问题。目前，我们需要使用较旧版本的模板。您可以通过以下链接执行此操作：[`portal.azure.com/#create/Microsoft.Template/uri/https%3A%2F%2Fdownload.docker.com%2Fazure%2Fstable%2F18.03.0%2FDocker.tmpl`](https://portal.azure.com/#create/Microsoft.Template/uri/https%3A%2F%2Fdownload.docker.com%2Fazure%2Fstable%2F18.03.0%2FDocker.tmpl)。

这将打开 Azure 门户，并呈现一个屏幕，您需要在其中输入一些信息：

+   **订阅**：从下拉列表中选择您想要使用的订阅

+   **资源组**：选择您想要使用或创建新的资源组

+   **位置**：选择您想要启动 Docker Swarm 集群的位置

+   **广告服务原则应用程序 ID**：这是由我们刚刚运行的辅助脚本生成的

+   **广告服务原则应用程序密钥**：这是由我们刚刚运行的辅助脚本生成的

+   **启用 Ext 日志**：是

+   **启用系统清理**：否

+   **Linux SSH 公钥**：在此处输入本地 SSH 密钥的公共部分

+   **Linux 工作节点计数**：2

+   **Linux 工作节点 VM 大小**：Standard_D2_v2

+   **管理器计数**：1

+   **管理器 VM 大小**：Standard_D2_v2

+   **Swarm 名称**：dockerswarm

同意条款和条件，然后点击页面底部的**购买**按钮。一旦您通过点击菜单顶部通知区域的“部署中”链接查看启动的进度，您应该会看到类似以下内容：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/ms-dkr-3e/img/f8479606-7175-4d43-8c08-1cf260a92606.png)

完成后，您将在您选择或创建的资源组下看到几个服务。其中一个将是`dockerswarm-externalSSHLoadBalancer-public-ip`。深入研究资源，您将获得可以用于 SSH 到您的 Swarm Manager 的 IP 地址。要做到这一点，请运行以下命令：

```
$ ssh docker@52.232.99.223 -p 50000
$ docker node ls
```

请注意，我们使用的是端口 5000，而不是标准端口 22。您应该会看到类似以下内容：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/ms-dkr-3e/img/e2bf3c3a-b3ce-4fef-b867-45ca8f93d88d.png)

一旦您登录到管理节点，我们可以使用以下命令启动应用程序：

```
$ docker service create --name cluster --constraint "node.role == worker" -p 80:80/tcp russmckendrick/cluster
$ docker service scale cluster=6
$ docker service ls
$ docker service inspect --pretty cluster
```

启动后，转到`dockerswarm-externalLoadBalancer-public-ip`—这将显示应用程序。完成集群后，我建议删除资源组，而不是尝试删除单个资源：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/ms-dkr-3e/img/097dd1a2-64c9-48e0-add1-51a68c786429.png)

请记住，只要资源处于活动状态，您就会被收费，即使您没有使用它们。

与亚马逊网络服务集群一样，请确保资源完全被删除，否则您可能会收到意外的账单。

# 云摘要 Docker

正如您所看到的，使用 Docker 提供的模板在 Azure 和亚马逊网络服务中启动 Swarm 集群大多是直截了当的。虽然这些模板很棒，但如果您刚开始使用，它们在 Docker 方面的支持很少。我建议，如果您正在寻找一种在公共云中运行生产工作负载的容器的简单方法，您可以看一下我们接下来要讨论的一些解决方案。

# 亚马逊 ECS 和 AWS Fargate

亚马逊网络服务提供了几种不同的容器解决方案。我们将在本节中查看的是亚马逊**弹性容器服务**（**ECS**）的一部分，称为 AWS Fargate。

传统上，亚马逊 ECS 启动 EC2 实例。一旦启动，亚马逊 ECS 代理会部署在容器运行时旁边，允许您使用 AWS 控制台和命令行工具来管理您的容器。AWS Fargate 消除了启动 EC2 实例的需要，使您可以简单地启动容器，而无需担心管理集群或承担 EC2 实例的费用。

我们将稍微作弊，并通过**Amazon ECS 首次运行过程**进行操作。您可以通过以下网址访问：[`console.aws.amazon.com/ecs/home#/firstRun.`](https://console.aws.amazon.com/ecs/home#/firstRun) 这将带领我们完成启动 Fargate 集群中容器所需的四个步骤。

亚马逊 ECS 使用以下组件：

+   容器定义

+   任务定义

+   服务

+   集群

在启动我们的 AWS Fargate 托管容器的第一步是实际配置前两个组件，即容器和任务定义。

容器定义是容器的基本配置所在。可以将其视为在命令行上使用 Docker 客户端启动容器时添加的标志，例如，您可以命名容器，定义要使用的镜像，设置网络等等。

对于我们的示例，有三个预定义选项和一个自定义选项。单击自定义选项中的“配置”按钮，并输入以下信息：

+   **容器名称**：`cluster-container`

+   **镜像**：`russmckendrick/cluster:latest`

+   **内存限制（MiB）**：保持默认值

+   **端口映射**：输入`80`，并保留选择`tcp`

然后，单击**更新**按钮。对于任务定义，单击**编辑**按钮，并输入以下内容：

+   **任务定义名称**：`cluster-task`

+   **网络模式**：应该是`awsvpc`；您无法更改此选项

+   **任务执行角色**：保持为`ecsTaskExecutionRole`

+   **兼容性**：这应该默认为 FARGATE，您应该无法编辑它

+   **任务内存**和**任务 CPU**：将两者都保留在它们的默认选项上

更新后，点击**保存**按钮。现在，您可以点击页面底部的下一步按钮。这将带我们到第二步，即定义服务的地方。

一个服务运行任务，而任务又与一个容器相关联。默认服务是可以的，所以点击**下一步**按钮，继续启动过程的第三步。第一步是创建集群。同样，默认值是可以的，所以点击**下一步**按钮，进入审阅页面。

这是您最后一次在启动任何服务之前仔细检查任务、服务和集群定义的机会。如果您对一切满意，然后点击**创建**按钮。从这里，您将被带到一个页面，您可以查看使我们的 AWS Fargate 集群的各种 AWS 服务的状态：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/ms-dkr-3e/img/b3ded49a-504d-40c2-b6ad-689bf2251a3d.png)

一旦一切从**待定**变为**完成**，您就可以点击**查看服务**按钮，进入服务概述页面：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/ms-dkr-3e/img/2a59d6e9-66b1-436b-8c41-a3c085ce0db7.png)

现在，我们只需要知道容器的公共 IP 地址。要找到这个，点击**任务**选项卡，然后选择正在运行的任务的唯一 ID。在页面的网络部分，您应该能够找到任务的私有和公共 IP 地址。在浏览器中输入公共 IP 地址应该会打开现在熟悉的集群应用程序：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/ms-dkr-3e/img/81f3646d-0867-437f-a2f6-f9cebb7b82ed.png)

您会注意到显示的容器名称是容器的主机名，并包括内部 IP 地址。您还可以通过点击日志选项卡查看容器的日志：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/ms-dkr-3e/img/da035de0-00f4-4c76-970e-d4b9dfd0f203.png)

那么，这要花费多少钱呢？要能够运行容器一个整月大约需要花费 14 美元，这相当于每小时约 0.019 美元。

这种成本意味着，如果您要全天候运行多个任务，那么 Fargate 可能不是运行容器的最具成本效益的方式。相反，您可能希望选择 Amazon ECS EC2 选项，在那里您可以将更多的容器打包到您的资源上，或者 Amazon EKS 服务，我们将在本章后面讨论。然而，对于快速启动容器然后终止它，Fargate 非常适用——启动容器的门槛很低，支持资源的数量也很少。

完成 Fargate 容器后，应删除集群。这将删除与集群关联的所有服务。一旦集群被移除，进入**任务定义**页面，如果需要，取消注册它们。

接下来，我们将看一下 Azure 应用服务。

# Microsoft Azure 应用服务

**Microsoft Azure 应用服务**是一个完全托管的平台，允许您部署应用程序，并让 Azure 担心管理它们正在运行的平台。在启动应用服务时有几个选项可用。您可以运行用.NET、.NET Core、Ruby、Node.js、PHP、Python 和 Ruby 编写的应用程序，或者您可以直接从容器镜像注册表启动镜像。

在这个快速演示中，我们将从 Docker Hub 启动集群镜像。要做到这一点，请登录到 Azure 门户网站[`portal.azure.com/`](https://portal.azure.com/)，并从左侧菜单中选择应用服务。

在加载的页面上，点击**+添加**按钮。您有几个选项可供选择：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/ms-dkr-3e/img/3917916c-1828-44cd-92f2-fe766b956704.png)

我们将要启动一个 Web 应用，所以点击相应的图块。一旦图块展开，点击**创建**按钮。

在打开的页面上，有几个选项。按以下方式填写它们：

+   **应用名称**：为应用程序选择一个唯一的名称。

+   **订阅**：选择有效的订阅。

+   **资源组**：保持选择创建新选项。

+   **操作系统**：保持为 Linux。

+   **发布**：选择 Docker 镜像。

+   **应用服务计划/位置**：默认情况下，选择最昂贵的计划，因此点击这里将带您到一个页面，您可以在其中创建一个新计划。要做到这一点，点击**创建新的**，命名您的计划并选择一个位置，最后选择一个定价层。对于我们的需求，**开发**/**测试**计划将很好。一旦选择，点击**应用**。

+   **配置容器：** 点击这里将带您到容器选项。在这里，您有几个选项：单个容器、Docker Compose 或 Kubernetes。现在，我们将启动一个单个容器。点击 **Docker Hub** 选项并输入 `russmckendrick/cluster:latest`。输入后，您将能够点击 **应用** 按钮。

一旦所有信息都填写完毕，您就可以点击 **创建** 来启动 Web 应用服务。一旦启动，您应该能够通过 Azure 提供的 URL 访问服务，例如，我的是 `https://masteringdocker.azurewebsites.net/`。在浏览器中打开这个链接将显示集群应用程序：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/ms-dkr-3e/img/379ca74a-fc1d-4ccb-a7cb-24880887ae55.png)

正如您所看到的，这一次我们有容器 ID 而不是像在 AWS Fargate 上启动容器时得到的完整主机名。这个规格的容器每小时大约会花费我们 0.05 美元，或者每月 36.50 美元。要删除容器，只需删除资源组。

# 在 Microsoft Azure、Google Cloud 和 Amazon Web Services 中的 Kubernetes

我们要看的最后一件事是在三个主要的公共云中启动 Kubernetes 集群有多容易。在上一章中，我们使用 Docker Desktop 应用程序的内置功能在本地启动了一个 Kubernetes 集群。首先，我们将看一下在公共云上开始使用 Kubernetes 的最快方法，从 Microsoft Azure 开始。

# Azure Kubernetes Service

**Azure Kubernetes Service**（**AKS**）是一个非常简单的服务，可以启动和配置。我将在本地机器上使用 Azure 命令行工具；您也可以使用内置在 Azure 门户中的 Azure Cloud Shell 使用命令行工具。

我们需要做的第一件事是创建一个资源组，将我们的 AKS 集群启动到其中。要创建一个名为 `MasteringDockerAKS` 的资源组，请运行以下命令：

```
$ az group create --name MasteringDockerAKS --location eastus
```

现在我们有了资源组，我们可以通过运行以下命令来启动一个两节点的 Kubernetes 集群：

```
$ az aks create --resource-group MasteringDockerAKS \
 --name MasteringDockerAKSCluster \
 --node-count 2 \
 --enable-addons monitoring \
 --generate-ssh-keys
```

启动集群需要几分钟时间。一旦启动，我们需要复制配置，以便我们可以使用本地的 `kubectl` 副本与集群进行交互。要做到这一点，请运行以下命令：

```
$ az aks get-credentials \
    --resource-group MasteringDockerAKS \
    --name MasteringDockerAKSCluster
```

这将配置您本地的 `kubectl` 副本，以便与您刚刚启动的 AKS 集群进行通信。现在您应该在 Docker 菜单下的 Kubernetes 中看到集群列表：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/ms-dkr-3e/img/1eb9ae6d-7ee8-4742-9401-ab8de398248b.png)

运行以下命令将显示您的`kubectl`客户端正在与其交谈的服务器版本以及有关节点的详细信息：

```
$ kubectl version
$ kubectl get nodes
```

您可以在以下截图中看到前面命令的输出：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/ms-dkr-3e/img/37a0e9be-d1de-4cf7-85aa-55b3529f2d03.png)

现在我们的集群已经正常运行，我们需要启动一些东西。幸运的是，Weave 有一个出色的开源微服务演示，可以启动一个出售袜子的演示商店。要启动演示，我们只需要运行以下命令：

```
$ kubectl create namespace sock-shop
$ kubectl apply -n sock-shop -f "https://github.com/microservices-demo/microservices-demo/blob/master/deploy/kubernetes/complete-demo.yaml?raw=true"
```

演示启动大约需要五分钟。您可以通过运行以下命令来检查`pods`的状态：

```
$ kubectl -n sock-shop get pods
```

一切都正常运行后，您应该看到类似以下的输出：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/ms-dkr-3e/img/7acc42f3-dfd4-4920-b859-73cb984930b4.png)

现在我们的应用程序已经启动，我们需要一种访问它的方式。通过运行以下命令来检查服务：

```
$ kubectl -n sock-shop get services
```

这向我们展示了一个名为`front-end`的服务。我们将创建一个负载均衡器并将其附加到此服务。要做到这一点，请运行以下命令：

```
$ kubectl -n sock-shop expose deployment front-end --type=LoadBalancer --name=front-end-lb
```

您可以通过运行以下命令来检查负载均衡器的状态：

```
$ kubectl -n sock-shop get services front-end-lb
$ kubectl -n sock-shop describe services front-end-lb
```

启动后，您应该看到类似以下的内容：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/ms-dkr-3e/img/de5124d9-7437-41de-a789-dd18f33e536f.png)

从前面的输出中可以看出，对于我的商店，IP 地址是`104.211.63.146`，端口是`8079`。在浏览器中打开`http://104.211.63.146:8079/`后，我看到了以下页面：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/ms-dkr-3e/img/635d767c-7e48-42f0-90fa-2d934c687d6f.png)

完成商店浏览后，您可以通过运行以下命令将其删除：

```
$ kubectl delete namespace sock-shop
```

要删除 AKS 集群和资源组，请运行以下命令：

```
$ az group delete --name MasteringDockerAKS --yes --no-wait
```

请记住检查 Azure 门户中的所有内容是否按预期移除，以避免任何意外费用。最后，您可以通过运行以下命令从本地`kubectl`配置中删除配置：

```
$ kubectl config delete-cluster MasteringDockerAKSCluster
$ kubectl config delete-context MasteringDockerAKSCluster
```

接下来，我们将看看如何在 Google Cloud 中启动类似的集群。

# Google Kubernetes Engine

正如您可能已经猜到的那样，**Google Kubernetes Engine**与 Google 的云平台紧密集成。而不是深入了解更多细节，让我们直接启动一个集群。我假设您已经拥有 Google Cloud 账户，一个启用了计费的项目，最后安装并配置了 Google Cloud SDK 以与您的项目进行交互。

要启动集群，只需运行以下命令：

```
$ gcloud container clusters create masteringdockergke --num-nodes=2
```

一旦集群启动，您的`kubectl`配置将自动更新，并为新启动的集群设置上下文。您可以通过运行以下命令查看有关节点的信息：

```
$ kubectl version
$ kubectl get nodes
```

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/ms-dkr-3e/img/4b3bd18a-a747-4f9f-85ad-5c8c20d6efb2.png)

现在我们的集群已经运行起来了，让我们通过重复上次使用的命令来启动演示商店：

```
$ kubectl create namespace sock-shop
$ kubectl apply -n sock-shop -f "https://github.com/microservices-demo/microservices-demo/blob/master/deploy/kubernetes/complete-demo.yaml?raw=true"
$ kubectl -n sock-shop get pods
$ kubectl -n sock-shop get services
$ kubectl -n sock-shop expose deployment front-end --type=LoadBalancer --name=front-end-lb
$ kubectl -n sock-shop get services front-end-lb
```

再次，一旦创建了`front-end-lb`服务，您应该能够找到要使用的外部 IP 地址端口：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/ms-dkr-3e/img/1b88a296-8862-4db4-9aee-417969dc98e4.png)

将这些输入到浏览器中将打开商店：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/ms-dkr-3e/img/dc44d962-fe1e-4fdc-9903-74f85f5b7c90.png)

要删除集群，只需运行以下命令：

```
$ kubectl delete namespace sock-shop
$ gcloud container clusters delete masteringdockergke
```

这也将从`kubectl`中删除上下文和集群。

# 亚马逊弹性容器服务 for Kubernetes

我们要看的最后一个 Kubernetes 服务是**亚马逊弹性容器服务 for Kubernetes**，简称**Amazon EKS**。这是我们正在介绍的三项服务中最近推出的服务。事实上，你可以说亚马逊非常晚才加入 Kubernetes 的行列。

不幸的是，亚马逊的命令行工具不像我们用于 Microsoft Azure 和 Google Cloud 的工具那样友好。因此，我将使用一个名为`eksctl`的工具，这个工具是由 Weave 编写的，他们也创建了我们一直在使用的演示商店。您可以在本章末尾的*进一步阅读*部分找到有关`eksctl`和亚马逊命令行工具的详细信息。

要启动我们的 Amazon EKS 集群，我们需要运行以下命令：

```
$ eksctl create cluster
```

启动集群需要几分钟时间，但在整个过程中，您将在命令行中收到反馈。此外，由于`eksctl`正在使用 CloudFormation，您还可以在 AWS 控制台中检查其进度。完成后，您应该会看到类似以下输出：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/ms-dkr-3e/img/4c382493-e1ee-4ea7-9599-6da285f0e2f8.png)

作为启动的一部分，`eksctl`将配置您的本地`kubectl`上下文，这意味着您可以运行以下命令：

```
$ kubectl version
$ kubectl get nodes
```

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/ms-dkr-3e/img/59956609-90b8-468a-8db8-f878996e8997.png)

现在我们的集群已经运行起来了，我们可以像之前一样启动演示商店：

```
$ kubectl create namespace sock-shop
$ kubectl apply -n sock-shop -f "https://github.com/microservices-demo/microservices-demo/blob/master/deploy/kubernetes/complete-demo.yaml?raw=true"
$ kubectl -n sock-shop get pods
$ kubectl -n sock-shop get services
$ kubectl -n sock-shop expose deployment front-end --type=LoadBalancer --name=front-end-lb
$ kubectl -n sock-shop get services front-end-lb
```

您可能会注意到在运行最后一个命令时列出的外部 IP 看起来有点奇怪：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/ms-dkr-3e/img/50a3cbee-1b92-4813-9307-2948a9b16d39.png)

这是因为它是一个 DNS 名称而不是 IP 地址。要找到完整的 URL，您可以运行以下命令：

```
$ kubectl -n sock-shop describe services front-end-lb
```

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/ms-dkr-3e/img/c4d6c6ea-15b9-49e4-b88c-96a35fd6cae7.png)

在浏览器中输入 URL 和端口将会显示演示商店，正如您可能已经猜到的那样：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/ms-dkr-3e/img/08ad77e8-6b8f-4743-9bcf-130c42f9c263.png)

要删除集群，请运行以下命令：

```
$ kubectl delete namespace sock-shop
$ eksctl get cluster
```

这将返回正在运行的集群的名称。一旦您有了名称，运行以下命令，确保引用您自己的集群：

```
$ eksctl delete cluster --name=beautiful-hideout-1539511992
```

您的终端输出应如下所示：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/ms-dkr-3e/img/fb0a673e-7663-483f-8b99-313189fbf179.png)

# Kubernetes 摘要

这结束了我们对 Microsoft Azure、Google Cloud 和 Amazon Web Services 中 Kubernetes 的简要介绍。我们在这里涵盖了一些有趣的观点。首先是，我们成功地使用命令行启动和管理了我们的集群，只需几个简单的步骤，尽管我们确实需要使用第三方工具来使用 Amazon EKS。

第二个最重要的观点是，一旦我们使用 `kubectl` 访问集群，体验在所有三个平台上都是完全相同的。在任何时候，我们都不需要访问云提供商的基于 web 的控制面板来调整或审查设置。一切都是使用相同的命令完成的；部署相同的代码和服务都是毫不费力的，我们不需要考虑云提供商提供的任何个别服务。

我们甚至可以使用 Docker 在本地运行演示商店，使用完全相同的命令。只需启动您的 Kubernetes 集群，确保选择了本地 Docker 上下文，然后运行以下命令：

```
$ kubectl create namespace sock-shop
$ kubectl apply -n sock-shop -f "https://github.com/microservices-demo/microservices-demo/blob/master/deploy/kubernetes/complete-demo.yaml?raw=true"
$ kubectl -n sock-shop get pods
$ kubectl -n sock-shop get services
$ kubectl -n sock-shop expose deployment front-end --type=LoadBalancer --name=front-end-lb
$ kubectl -n sock-shop get services front-end-lb
```

如您从以下输出中所见，*负载均衡* IP，在这种情况下，是 `localhost`。打开浏览器并输入 `http://localhost:8079` 将带您进入商店：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/ms-dkr-3e/img/d8fe2e37-04a3-4b51-a7bb-7af5cae602f9.png)

您可以通过运行以下命令删除商店：

```
$ kubectl delete namespace sock-shop
```

在多个提供商甚至本地机器上实现这种一致性水平以前确实是不可行的，除非经过大量工作和配置，或者通过封闭源订阅服务。

# 摘要

在本章中，我们已经看了一下如何使用 Docker 自己提供的工具将 Docker Swarm 集群部署到云提供商。我们还看了公共云提供的两项服务，以便远离核心 Docker 工具集来运行容器。

最后，我们看了在各种云中启动 Kubernetes 集群，并在所有云中运行相同的演示应用程序。尽管从我们运行的任何命令中都很明显，所有三个公共云都使用各种版本的 Docker 作为容器引擎。尽管在您阅读本文时可能会发生变化，但理论上，它们可以切换到另一个引擎而几乎没有影响。

在下一章中，我们将回到使用 Docker 并查看 Portainer，这是一个用于管理 Docker 安装的基于 Web 的界面。

# 问题

1.  真或假：Docker for AWS 和 Docker for Azure 为您启动 Kubernetes 集群，以便在其上启动容器。

1.  如果使用 Amazon Fargate，您不必直接管理哪种亚马逊服务？

1.  我们需要在 Azure 中启动什么类型的应用程序？

1.  一旦启动，我们需要运行什么命令来为 Sock Shop 商店创建命名空间？

1.  如何找到有关负载均衡器的详细信息？

# 进一步阅读

您可以在以下链接找到有关 Docker Cloud 服务关闭的详细信息：

+   Docker Cloud 迁移通知和常见问题解答：[`success.docker.com/article/cloud-migration`](https://success.docker.com/article/cloud-migration)

+   卡住了！Docker Cloud 关闭！：[`blog.cloud66.com/stuck-docker-cloud-shutdown/`](https://blog.cloud66.com/stuck-docker-cloud-shutdown/)

有关 Docker for AWS 和 Docker for Azure 使用的模板服务的更多详细信息，请参阅以下链接：

+   AWS CloudFormation：[`aws.amazon.com/cloudformation/`](https://aws.amazon.com/cloudformation/)

+   Azure ARM 模板：[`azure.microsoft.com/en-gb/resources/templates/`](https://docs.microsoft.com/en-gb/azure/azure-resource-manager/resource-group-overview)

+   ARM 模板可视化器：[`armviz.io/`](http://armviz.io/)

我们用来启动容器的云服务可以在以下链接找到：

+   Amazon ECS：[`aws.amazon.com/ecs/`](https://aws.amazon.com/ecs/)

+   AWS Fargate: [`aws.amazon.com/fargate/`](https://aws.amazon.com/fargate/)

+   Azure Web Apps：[`azure.microsoft.com/en-gb/services/app-service/web/`](https://azure.microsoft.com/en-gb/services/app-service/web/)

三个 Kubernetes 服务可以在以下链接找到：

+   Azure Kubernetes 服务：[`azure.microsoft.com/en-gb/services/kubernetes-service/`](https://azure.microsoft.com/en-gb/services/kubernetes-service/)

+   Google Kubernetes Engine：[`cloud.google.com/kubernetes-engine/`](https://cloud.google.com/kubernetes-engine/)

+   亚马逊弹性容器服务 for Kubernetes：[`aws.amazon.com/eks/`](https://aws.amazon.com/eks/)

本章中使用的各种命令行工具的快速入门可以在以下链接找到：

+   Azure CLI：[`docs.microsoft.com/en-us/cli/azure/?view=azure-cli-latest`](https://docs.microsoft.com/en-us/cli/azure/?view=azure-cli-latest)

+   谷歌云 SDK：[`cloud.google.com/sdk/`](https://cloud.google.com/sdk/)

+   AWS 命令行界面：[`aws.amazon.com/cli/`](https://aws.amazon.com/cli/)

+   eksctl - 用于 Amazon EKS 的 CLI：[`eksctl.io/`](https://eksctl.io/)

最后，有关演示商店的更多详细信息，请访问以下链接：

+   Sock Shop：[`microservices-demo.github.io`](https://microservices-demo.github.io)
