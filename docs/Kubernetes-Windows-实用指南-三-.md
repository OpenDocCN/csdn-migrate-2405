# Kubernetes Windows 实用指南（三）

> 原文：[`zh.annas-archive.org/md5/D85F9AD23476328708B2964790249673`](https://zh.annas-archive.org/md5/D85F9AD23476328708B2964790249673)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第三部分：创建 Windows Kubernetes 集群

本节重点讨论围绕创建（配置和部署）混合 Linux/Windows Kubernetes 集群的高级主题，其中包括 Linux 主节点和 Windows 节点。这些章节涵盖了在本地和云（Azure）场景中的部署。

本节包括以下章节：

+   第七章，*部署混合本地 Kubernetes 集群*

+   第八章，*部署混合 Azure Kubernetes 服务引擎集群*


# 第七章：部署混合本地 Kubernetes 集群

在之前的章节中，我们更多地从理论角度关注了 Docker 和 Kubernetes 的概念，现在是时候利用这些知识并从头开始部署一个 Kubernetes 集群了。本章的目标是在本地环境中拥有一个功能齐全的混合 Windows/Linux Kubernetes 集群。

根据您的需求，您可以使用这种方法创建一个最小化的本地开发集群（一个充当主节点的 Linux 虚拟机（VM）和一个充当节点的 Windows VM），或者部署一个具有 Linux 和 Windows 节点的生产级本地集群。您不仅限于 Hyper-V 集群——只要设置了适当的网络并且机器能够运行容器化工作负载，这种方法就可以用于裸机、VMware 集群或在云中运行的 VM。使用 kubeadm 创建 Kubernetes 集群可以让您灵活地在任何地方部署集群，只要设置了适当的网络并且机器能够运行容器化工作负载。

我们还建议使用 kubeadm，因为它是一个低级工具，可以深入了解集群的实际创建过程。在未来，您可以期待基于 kubeadm 构建的其他解决方案（如 Kubespray），支持混合集群。但即使如此，仍建议尝试纯 kubeadm 方法来学习 Kubernetes 集群部署的基本步骤。

本章涵盖以下主题：

+   准备 Hyper-V 环境

+   使用 kubeadm 创建 Kubernetes 主节点

+   安装 Kubernetes 网络

+   为 Windows 节点准备虚拟机

+   使用 kubeadm 加入 Windows 节点

+   部署和检查您的第一个应用程序

# 技术要求

对于本章，您将需要以下内容：

+   Windows 10 专业版、企业版或教育版（1903 版本或更高版本，64 位）；至少 16GB RAM 的 Hyper-V 主机（如果选择不安装 Windows Server 和 Ubuntu Server VMs 的桌面体验，则可能更少）。您可以使用任何其他具有 Hyper-V 功能的 Windows 或 Windows Server 版本。对于 Hyper-V，需要在基本输入/输出系统（BIOS）中启用英特尔虚拟化技术（Intel VT）或 AMD 虚拟化（AMD-V）技术功能。

注意：Windows 10 家庭版不能用作 Hyper-V 主机。

+   Linux 主节点 VM 需要至少 15GB 磁盘空间，每个 Windows 节点 VM 需要至少 30GB 磁盘空间。

+   Ubuntu Server 18.04 **长期支持** (**LTS**) **国际标准化组织** (**ISO**) ([`releases.ubuntu.com/18.04.3/ubuntu-18.04.3-live-server-amd64.iso`](http://releases.ubuntu.com/18.04.3/ubuntu-18.04.3-live-server-amd64.iso))。

+   Windows Server 2019 (**长期服务渠道** (**LTSC**), 可用桌面体验) ISO 或 Windows Server 1903 (**半年频道** (**SAC**), 无桌面体验) ISO。您应该查看[`kubernetes.io/docs/setup/production-environment/windows/intro-windows-in-kubernetes/`](https://kubernetes.io/docs/setup/production-environment/windows/intro-windows-in-kubernetes/)，了解有关当前 Windows Server 版本的最新建议。您可以从 Microsoft 评估中心获取评估 ISO([`www.microsoft.com/en-us/evalcenter/evaluate-windows-server-2019`](https://www.microsoft.com/en-us/evalcenter/evaluate-windows-server-2019))，或者，如果您有 Visual Studio 订阅([`my.visualstudio.com/Downloads/Featured`](https://my.visualstudio.com/Downloads/Featured))，您可以下载用于开发和测试目的的 ISO。

+   Kubectl 已安装-安装过程已在第六章中介绍过，*与 Kubernetes 集群交互*。

您可以从官方 GitHub 存储库下载本章的最新代码示例：[`github.com/PacktPublishing/Hands-On-Kubernetes-on-Windows/tree/master/Chapter07`](https://github.com/PacktPublishing/Hands-On-Kubernetes-on-Windows/tree/master/Chapter07)。

# 准备 Hyper-V 环境

集群部署的第一步是为 Kubernetes 主节点和节点 VM 准备 Hyper-V 主机。

如果您选择使用不同的 hypervisor 或裸机，可以跳过本节。

现在，如果您在之前的章节中已在您的计算机上安装了 Windows 的 Docker Desktop，那么 Hyper-V 已启用和配置。您只需要创建一个内部**网络地址转换** (**NAT**)或外部 Hyper-V **虚拟交换机** (**vSwitch**)，然后您就可以开始了。

以下图表显示了我们将在本章中部署的集群设计。请记住，主节点*不*配置为**高可用性**（**HA**）- HA 设置与 Windows 容器的支持无关，您可以在准备 Linux 主节点时执行它，根据官方文档（[`kubernetes.io/docs/setup/production-environment/tools/kubeadm/high-availability/`](https://kubernetes.io/docs/setup/production-environment/tools/kubeadm/high-availability/)）：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/hsn-k8s-win/img/a864ac65-13ab-4d85-b84a-6f58d46a49e4.png)

最小部署是一个 Ubuntu Server 18.04 LTS Kubernetes 主节点（具有调度应用程序 Pod 的可能性）和一个 Windows Server 2019 LTS Kubernetes 节点。可选地，您可以决定部署更多的 Windows 和 Linux 节点（在图表中用虚线标记），按照相同的说明或克隆 VM。

# 启用 Hyper-V

首先，让我们启用 Hyper-V 功能，如果您之前没有启用它，如下所示：

1.  以管理员身份打开 PowerShell 窗口。

1.  执行以下命令以启用 Hyper-V 功能：

```
Enable-WindowsOptionalFeature -Online -FeatureName  Microsoft-Hyper-V -All
```

1.  重新启动计算机。

如果您正在使用 Windows Server 作为您的 Hyper-V 主机，可以在官方文档中找到启用 Hyper-V 角色的说明：[`docs.microsoft.com/en-us/windows-server/virtualization/hyper-v/get-started/install-the-hyper-v-role-on-windows-server`](https://docs.microsoft.com/en-us/windows-server/virtualization/hyper-v/get-started/install-the-hyper-v-role-on-windows-server)。

现在，根据您的网络设置，您必须创建一个适当的 Hyper-V vSwitch。您有两个选项：

1.  **内部 NAT Hyper-V vSwitch**：如果您计划仅将集群用于本地开发，请使用此选项。任何外部入站通信（除了您的 Hyper-V 主机机器）都将需要 NAT。在大多数情况下，此选项适用于简单的 Windows 10 开发设置，因为您连接到不允许您自行管理**动态主机配置协议**（**DHCP**）和**域名系统**（**DNS**）的外部网络（以太网或 Wi-Fi）。换句话说，如果您使用外部 vSwitch，您将得到节点的不可预测的 IP 地址分配。没有 DNS，您将无法确保适当的 Kubernetes 集群连接。

1.  **外部 Hyper-V vSwitch**：如果您的网络有一个 DHCP 和 DNS 服务器，您（或网络管理员）可以管理，那么请使用此选项。这在大多数生产部署中都是这样。然后，您需要为 VM 分配适当的**媒体访问控制**（**MAC**）地址，以便获得所需的 IP 地址。

我们将遵循网络的默认网关为`10.0.0.1`，主节点的 IP 地址为`10.0.0.2`，节点具有连续的 IP 地址`10.0.0.X`的约定。

# 创建内部 NAT Hyper-V vSwitch

为了创建内部 NAT vSwitch，请执行以下步骤：

1.  以管理员身份打开 PowerShell 窗口。

1.  执行以下命令创建名为`Kubernetes NAT Switch`的内部 vSwitch：

```
New-VMSwitch -SwitchName "Kubernetes NAT Switch" -SwitchType Internal
```

1.  找到您刚刚创建的 vSwitch 的`ifIndex`。`ifIndex`将需要用于 NAT 网关的创建。您可以通过运行以下命令来执行此操作：

```
Get-NetAdapter
```

以下截图显示了上述命令的输出：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/hsn-k8s-win/img/c979eca5-b246-4abb-bff2-282f9b654a46.png)

1.  配置 NAT 网关，如下所示：

```
New-NetIPAddress -IPAddress 10.0.0.1 -PrefixLength 8 -InterfaceIndex <ifIndex>
```

1.  创建新的 NAT 网络`Kubernetes NAT Network`，如下所示：

```
New-NetNAT -Name "Kubernetes NAT Network" -InternalIPInterfaceAddressPrefix 10.0.0.0/8
```

如果您使用内部 NAT vSwitch，则必须为每个 VM 提供静态 IP 地址、网关 IP 地址和 DNS 服务器信息。静态 IP 地址必须在 NAT 内部前缀范围内。

请注意，目前您的系统中只能有一个自定义内部 NAT vSwitch。您可以在官方文档中阅读更多信息：[`docs.microsoft.com/en-us/virtualization/hyper-v-on-windows/user-guide/setup-nat-network`](https://docs.microsoft.com/en-us/virtualization/hyper-v-on-windows/user-guide/setup-nat-network)。

# 创建外部 Hyper-V vSwitch

或者，为了创建外部 vSwitch，请执行以下步骤：

1.  使用“开始”菜单启动 Hyper-V 管理器。

1.  从“操作”选项卡中单击“虚拟交换机管理器…”，选择“外部”，然后单击“创建虚拟交换机”。

1.  使用名称`Kubernetes External Switch`，并选择用于连接到互联网的网络适配器，例如您的 Wi-Fi 适配器，如下截图所示：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/hsn-k8s-win/img/9ab7c843-10af-48e4-8f75-ff9901ea2e9b.png)

1.  单击“确定”以接受更改。

现在，Hyper-V 环境准备就绪，您可以继续下一步——在运行 Ubuntu Server 18.04 LTS VM 上创建 Kubernetes 主节点。

# 使用 kubeadm 创建 Kubernetes 主节点

对于混合 Windows/Linux Kubernetes 集群，您需要部署一个 Linux 主节点——这一步与仅 Linux 的 Kubernetes 集群几乎相同，并且您可以使用任何支持的操作系统来完成此目的。我们选择了 Ubuntu 服务器 18.04 LTS，因为它得到了广泛的支持（官方和社区支持），具有简单的安装过程，并且易于管理。

本章的说明重点是将 Windows 节点添加到 Kubernetes 集群。主节点的准备步骤很少。如果您在本地机器上部署开发集群，使用 kubeadm 在集群中部署单个控制平面就足够了。对于生产部署，您应该考虑部署一个 HA 主节点配置。您可以在以下网址了解有关 HA 和 kubeadm 的更多信息：[`kubernetes.io/docs/setup/production-environment/tools/kubeadm/high-availability/`](https://kubernetes.io/docs/setup/production-environment/tools/kubeadm/high-availability/)。

如果您还没有下载 Ubuntu 服务器 18.04 LTS 的 ISO 镜像，官方镜像可以在以下网址找到：[`releases.ubuntu.com/18.04.3/ubuntu-18.04.3-live-server-amd64.iso`](http://releases.ubuntu.com/18.04.3/ubuntu-18.04.3-live-server-amd64.iso)。

# 创建虚拟机并安装 Ubuntu 服务器

本小节将指导您完成以下步骤，以准备一个带有 Ubuntu 服务器的新虚拟机：

1.  创建虚拟机

1.  安装 Ubuntu 服务器

1.  配置网络

1.  安装用于与 Hyper-V 集成的额外软件包

1.  建立一个无密码的安全外壳（SSH）登录

# 创建虚拟机

首先，您需要创建一个将用作主节点的虚拟机，运行 Ubuntu 服务器 18.04。要做到这一点，打开 Hyper-V 管理器应用程序，并执行以下步骤：

1.  从“操作”菜单中，选择“新建”，然后点击“虚拟机”。

1.  点击“下一步”，为主节点虚拟机选择一个名称。我们将用`Kubernetes Master`来命名。可选地，配置一个自定义目录来存储虚拟机数据，以确保有足够的磁盘空间来托管虚拟机，如下截图所示：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/hsn-k8s-win/img/e6f49608-18a1-4cd6-811c-bf0978a54866.png)

1.  在下一个对话框中，选择第 2 代并继续，如下截图所示：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/hsn-k8s-win/img/6e1ef1d7-fe34-4b2b-b96c-926f14631b3d.png)

1.  为主节点分配至少`2048` MB 的 RAM。您也可以选择使用动态内存分配功能。您可以在官方文档中找到有关硬件最低要求的更多信息，网址为：[`kubernetes.io/docs/setup/production-environment/tools/kubeadm/install-kubeadm/#before-you-begin`](https://kubernetes.io/docs/setup/production-environment/tools/kubeadm/install-kubeadm/#before-you-begin)。对于生产场景，请考虑使用至少`16384` MB 的 RAM。下面的截图说明了这个过程：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/hsn-k8s-win/img/d17bff58-307b-4fe4-bd9a-057c78eac84e.png)

1.  选择内部 NAT 或外部交换作为虚拟机的连接，如下截图所示：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/hsn-k8s-win/img/d09eade9-aaec-4dde-8a56-2b52da1a75d3.png)

1.  创建一个大小为`250` GB 的新虚拟硬盘。由于**虚拟硬盘 v2**（**VHDX**）是动态可扩展的，因此最好从一开始就分配更多的空间，而不是以后再扩展磁盘和分区。下面的截图说明了这个过程：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/hsn-k8s-win/img/3afdde40-0434-4a19-ab2b-b8e7ed83d009.png)

1.  选择从 ISO 安装操作系统，并选择 Ubuntu Server 18.04 LTS 镜像文件，如下截图所示：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/hsn-k8s-win/img/0fe4fd70-cb12-4149-a510-7f403b07538e.png)

1.  完成虚拟机创建向导。在启动虚拟机之前，我们需要进一步配置它。右键单击 Kubernetes Master VM 并打开设置。

1.  在安全菜单中，确保安全启动模板设置为 Microsoft UEFI 证书颁发机构，如下截图所示：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/hsn-k8s-win/img/f8e9c9ab-42a3-4c92-a272-919cf42756a3.png)

1.  在处理器菜单中，将虚拟处理器的数量设置为至少`2`，如下截图所示：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/hsn-k8s-win/img/2a2f66be-a2b6-433e-81be-550e975cf0c3.png)

1.  在网络适配器高级功能菜单中，选择为容器启用 MAC 地址欺骗。如果您正在使用外部 vSwitch 并且有外部 DHCP，您可能还想配置静态 DHCP 分配。对于内部 NAT vSwitch，您可以保留默认的动态设置，如下截图所示：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/hsn-k8s-win/img/eee9bc8e-6372-4141-89a0-f2b8f75fa23a.png)

1.  应用所有更改并启动虚拟机。

如果您考虑完全自动化这个过程，您可以选择 Vagrant（[`www.vagrantup.com/`](https://www.vagrantup.com/)）用于开发目的，或者 Packer 用于生产场景（[`www.packer.io/`](https://www.packer.io/)）。使用 Vagrant，您可以轻松地从头开始创建开发 VM，并使用例如 Ansible 自动化配置过程。使用 Packer，您可以为 VM 或云提供商生成机器映像，以便使用**基础设施即代码**（**IaC**）范例。

# 安装 Ubuntu 服务器

主节点的虚拟机已经创建，现在我们需要在虚拟机上安装 Ubuntu Server 18.04 LTS。为了做到这一点，请执行以下步骤：

1.  通过在 Hyper-V 管理器中双击 Kubernetes Master VM 来连接到正在运行的 VM 终端。

1.  等待安装程序初始化。

1.  选择英语作为首选语言。

1.  选择所需的键盘布局。

1.  在网络连接中，根据您的外部网络配置进行操作：

+   如果您使用内部 NAT vSwitch，则必须手动设置配置。打开 eth0 接口并编辑 IPv4，选择手动方法。设置子网`10.0.0.0/8`，地址`10.0.0.2`，网关`10.0.0.1`，名称服务器`8.8.8.8,8.8.4.4`（如果可能，请使用您的提供商的 DNS 服务器地址）。

+   如果您使用外部 vSwitch，请根据您的要求使用自动配置或手动配置网络。

1.  可选地，配置网络代理。请记住，如果您在网络代理后运行，您将稍后需要配置 Docker 以使用代理。

1.  继续使用默认的镜像地址。

1.  在文件系统设置中，配置为使用整个磁盘。

1.  选择默认的磁盘进行安装。

1.  按照建议的文件系统设置进行操作。

1.  在配置文件设置中，您可以配置机器名称和第一个用户名。我们将使用`kubernetes-master`作为机器名称，`ubuntu`作为用户名。

1.  在 SSH 菜单中，选择安装 OpenSSH 服务器。

1.  不要选择任何额外的软件包，并继续安装。

1.  等待安装完成。

1.  重新启动。

可以使用 Kickstart 或 preseed 配置文件自动安装 Ubuntu 服务器。您可以在官方文档中找到更多信息，网址为：[`help.ubuntu.com/lts/installation-guide/i386/ch04s06.html`](https://help.ubuntu.com/lts/installation-guide/i386/ch04s06.html)。这种方法可以与 Vagrant 或 Packer 一起使用。可以在以下网址找到适用于 Packer 的 Ubuntu Server 18.04 的示例 preseed 配置文件：[`github.com/ptylenda/ironic-packer-template-ubuntu1804-kubernetes-ansible-proxy/blob/master/http/preseed.cfg`](https://github.com/ptylenda/ironic-packer-template-ubuntu1804-kubernetes-ansible-proxy/blob/master/http/preseed.cfg)。

让我们来看看网络配置。

# 配置网络

如果您正在使用内部 NAT vSwitch 或外部 vSwitch 与外部基于 Windows 的 DHCP 服务器，则在机器重新启动后需要进行一些额外的网络配置，如下所示：

1.  在 VM 终端窗口中，使用用户名`ubuntu`和您的密码登录。

1.  使用`vim`或`nano`打开以下文件：

```
sudo vim /etc/netplan/01-netcfg.yaml
```

如果您不熟悉 Vim 编辑器，我们强烈建议学习基础知识。例如，可以在以下网址找到一个简明指南：[`eastmanreference.com/a-quick-start-guide-for-beginners-to-the-vim-text-editor`](https://eastmanreference.com/a-quick-start-guide-for-beginners-to-the-vim-text-editor)。Vim 非常适用于在 Linux 和 Windows 上编辑文件，而无需桌面环境。作为替代，您可以使用 nano ([`www.nano-editor.org/`](https://www.nano-editor.org/))。

1.  如果您正在使用内部 NAT vSwitch，请按以下方式强制执行 Kubernetes 主节点的静态 IP 地址配置：

```
network:
  ethernets:
    eth0:
      dhcp4: no
      addresses: [10.0.0.2/8]
      gateway4: 10.0.0.1
      nameservers:
        addresses: [8.8.8.8,8.8.4.4]
  version: 2
```

1.  或者，如果您正在使用外部 vSwitch 和外部基于 Windows 的 DHCP 服务器，请将文件内容设置为以下内容：

```
network:
  ethernets:
    eth0:
      dhcp4: yes
      dhcp-identifier: mac
  version: 2
```

将`dhcp-identifier`设置为`mac`对于使 DHCP 租约正常工作至关重要。

1.  保存文件并使用`sudo reboot`命令重新启动机器。

我们现在将安装一些额外的软件包。

# 安装与 Hyper-V 集成的额外软件包

对于任何网络配置（包括内部 NAT 和外部 vSwitch），您现在应该安装一些额外的虚拟化工具，以启用与 hypervisors 集成的一些专用功能，如下所示：

1.  再次登录到机器上。

1.  通过运行以下命令更新`apt-get`缓存：

```
sudo apt-get update
```

1.  安装额外的虚拟化工具，如下所示：

```
sudo apt-get install -y --install-recommends linux-tools-virtual linux-cloud-tools-virtual
```

1.  重启。

现在，让我们设置一个无密码 SSH 登录。

# 设置无密码 SSH 登录

在这一点上，建议使用 SSH 而不是 VM 终端来管理机器。这将需要以下操作：

1.  在您用于连接到 VM 的 Windows 机器上安装 SSH 客户端（在大多数情况下，您的 VM 主机机器）

1.  生成 SSH 密钥对以禁用 SSH 的密码身份验证

要在 Windows 机器上安装本机 SSH 客户端，请执行以下步骤：

1.  以管理员身份打开 PowerShell 窗口

1.  运行以下命令以获取当前可用版本的 OpenSSH 客户端：

```
PS C:\WINDOWS\system32> Get-WindowsCapability -Online | ? Name -like 'OpenSSH*'
Name : OpenSSH.Client~~~~0.0.1.0
State : NotPresent

Name : OpenSSH.Server~~~~0.0.1.0
State : NotPresent
```

1.  像这样安装客户端：

```
Add-WindowsCapability -Online -Name OpenSSH.Client~~~~0.0.1.0
```

1.  要连接到 Kubernetes 主节点 VM，您需要知道其 IP 地址。如果您使用静态 IP 地址配置，这相当简单——您使用`10.0.0.2`。对于由 DHCP 提供的动态 IP 地址，您需要首先确定它。由于在前面的步骤中安装了虚拟化工具，您可以在 Hyper-V 管理器的网络选项卡中轻松找到它，如下面截图底部所示：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/hsn-k8s-win/img/8773db22-cacf-49bc-a8e6-cd7ac057c64a.png)

1.  在这种情况下，IP 地址是`10.0.0.2`，我们可以使用它来 SSH 进入 VM，如下所示：

```
PS C:\WINDOWS\system32> ssh ubuntu@10.0.0.2
The authenticity of host '10.0.0.2 (10.0.0.2)' can't be established.
ECDSA key fingerprint is SHA256:X6iv9E7Xixl5GFvV+WxiP10Gbkvh1j3xPsBEV/4YcFo.
Are you sure you want to continue connecting (yes/no)? yes
Warning: Permanently added '10.0.0.2' (ECDSA) to the list of known hosts.
ubuntu@10.0.0.2's password:
Welcome to Ubuntu 18.04.3 LTS (GNU/Linux 4.15.0-65-generic x86_64)
```

如果遇到连接问题，例如`Connection closed by 10.0.0.2 port 22`，您需要重新生成 SSH 主机密钥。在 VM 终端中运行`sudo ssh-keygen -A`，然后尝试重新连接。如果问题仍然存在，请使用`sudo service sshd status`分析 sshd 服务日志。

下一步是为无密码登录到 Kubernetes 主 VM 生成 SSH 密钥对。要做到这一点，请执行以下步骤：

1.  打开 PowerShell 窗口。

1.  运行以下命令生成密钥对。不要指定密码：

```
ssh-keygen.exe
```

1.  现在，您的公钥可在`C:\Users\<user>\.ssh\id_rsa.pub`中找到。使用以下命令将其复制到 Kubernetes Master VM。此命令确保`authorized_keys`文件具有适当的安全访问权限：

```
cat ~/.ssh/id_rsa.pub | ssh ubuntu@10.0.0.2 "cat >> ~/.ssh/authorized_keys && chmod 600 ~/.ssh/authorized_keys"
```

1.  最后一步是测试无密码身份验证，并禁用 SSH 服务器的密码身份验证以获得最佳安全性，如下面的代码片段所示：

```
ssh ubuntu@192.168.43.105
# You should not be asked for password at this point!
```

1.  编辑`/etc/ssh/sshd_config`，如下所示：

```
sudo vim /etc/ssh/sshd_config
```

1.  找到`PasswordAuthentication yes`行并将其注释掉，如下所示：

```
#PasswordAuthentication yes
```

1.  保存更改并重新启动 SSH 服务器，如下所示：

```
sudo service sshd restart
```

1.  重新连接以验证您的配置。

在这一点上，最好为`Kubernetes Master`导出 Hyper-V VM 镜像（或创建检查点）。如果在 Kubernetes 主配置期间出现任何问题，这将使恢复到初始配置变得更容易。

# 安装和配置 Kubernetes 先决条件

为 Kubernetes 主机（以及 Kubernetes 节点）准备 Ubuntu Server 18.04 LTS 机器需要执行以下步骤：

1.  更改操作系统配置，例如禁用交换空间。

1.  安装 Docker 容器运行时。

Ubuntu Server 为 Kubernetes 准备的所有步骤也可以在书籍的官方 GitHub 存储库中作为 bash 脚本找到，网址为：[`github.com/PacktPublishing/Hands-On-Kubernetes-on-Windows/blob/master/Chapter07/02_ubuntu-prepare-node.sh`](https://github.com/PacktPublishing/Hands-On-Kubernetes-on-Windows/blob/master/Chapter07/02_ubuntu-prepare-node.sh)。

截至 Kubernetes 1.17，**经过验证**的 Docker 版本列表如下：1.13.1、17.03、17.06、17.09、18.06、18.09、19.03。

为了配置操作系统以运行 Kubernetes，执行以下步骤：

1.  打开 PowerShell 窗口。

1.  SSH 进入 Kubernetes 主机，如下所示：

```
ssh ubuntu@10.0.0.2
```

1.  更新`apt-get`并升级所有软件包，如下所示：

```
sudo apt-get update
sudo apt-get dist-upgrade -y
```

1.  安装所需的软件包，如下所示：

```
sudo apt-get install apt-transport-https ca-certificates curl software-properties-common ebtables ethtool -y 
```

1.  禁用当前引导的交换分区，如下所示：

```
sudo swapoff -a
```

1.  永久删除交换分区。编辑`sudo vim /etc/fstab`并删除任何类型为`swap`的行，例如以下行：

```
/swap.img       none    swap    sw      0       0
```

编辑`/etc/fstab`应始终使用创建的文件**备份**执行。此文件中的配置错误可能导致无法引导的系统！

1.  可选地，重新启动计算机以检查交换分区是否未再次挂载。重新启动计算机后，SSH 进入计算机并检查`swap`是否已禁用-列表应为空，如下所示：

```
swapon -s
```

1.  确保在系统引导期间加载`br_netfilter`内核模块。使用`sudo vim /etc/modules-load.d/kubernetes.conf`命令创建文件并设置以下内容：

```
br_netfilter
```

1.  为 Kubernetes 配置`sysctl`变量（Flannel 网络所需）。使用`sudo vim /etc/sysctl.d/99-kubernetes.conf`命令创建一个新文件，并确保文件具有以下内容：

```
net.bridge.bridge-nf-call-ip6tables = 1
net.bridge.bridge-nf-call-iptables = 1
net.bridge.bridge-nf-call-arptables = 1
```

1.  加载`br_netfilter`内核模块以进行当前引导，并使用以下命令重新加载`sysctl`变量：

```
sudo modprobe br_netfilter
sudo sysctl --system
```

此时，您的 Ubuntu 服务器虚拟机已准备好安装 Docker 和 Kubernetes。为了安装 Docker 18.09，这是与 Kubernetes 1.16 一起使用的最新验证版本，请执行以下步骤：

1.  为 Docker `apt`软件包存储库添加官方**GNU 隐私保护**（**GPG**）密钥，如下所示：

```
curl -fsSL https://download.docker.com/linux/ubuntu/gpg | sudo apt-key add -
```

Ubuntu 上 Docker 的最新安装说明可以在以下网址找到：[`docs.docker.com/install/linux/docker-ce/ubuntu/`](https://docs.docker.com/install/linux/docker-ce/ubuntu/)。始终与 Kubernetes 容器运行时安装文档进行交叉检查，因为它包含额外重要信息，可以在以下网址找到：[`kubernetes.io/docs/setup/production-environment/container-runtimes/#docker`](https://kubernetes.io/docs/setup/production-environment/container-runtimes/#docker)。

1.  添加 Docker `apt`软件包存储库，如下所示：

```
sudo add-apt-repository \
 "deb [arch=amd64] https://download.docker.com/linux/ubuntu \
 $(lsb_release -cs) \
 stable"
```

1.  更新`apt-get`缓存以刷新存储库的信息，如下所示：

```
sudo apt-get update
```

1.  安装经过 Kubernetes 使用验证的最新 Docker 版本，如下所示：

```
sudo apt-get install docker-ce=5:18.09.9~3-0~ubuntu-bionic -y
```

1.  通过运行以下命令禁用`docker-ce`软件包的自动更新（这将防止安装未经验证的 Docker 版本）：

```
sudo apt-mark hold docker-ce
```

1.  为 Kubernetes 配置 Docker 守护程序。使用`sudo vim /etc/docker/daemon.json`命令创建一个新文件，并设置以下内容：

```
{
 "exec-opts": ["native.cgroupdriver=systemd"],
 "log-driver": "json-file",
 "log-opts": {
 "max-size": "100m"
 },
 "storage-driver": "overlay2"
}
```

1.  重新加载`systemctl`并重新启动 Docker 守护程序，使用以下命令：

```
sudo systemctl daemon-reload
sudo systemctl restart docker
```

1.  验证 Docker 是否已正确安装，方法是运行`hello-world`容器，如下所示：

```
ubuntu@kubernetes-master:~$ sudo docker run hello-world
Unable to find image 'hello-world:latest' locally
latest: Pulling from library/hello-world
1b930d010525: Pull complete Digest: sha256:c3b4ada4687bbaa170745b3e4dd8ac3f194ca95b2d0518b417fb47e5879d9b5f
Status: Downloaded newer image for hello-world:latest

Hello from Docker!
This message shows that your installation appears to be working correctly.
```

如果您在网络代理后面工作，您应该确保您有以下内容：

+   包含适当代理变量的`/etc/environment`（示例指南：[`kifarunix.com/how-to-set-system-wide-proxy-in-ubuntu-18-04/`](https://kifarunix.com/how-to-set-system-wide-proxy-in-ubuntu-18-04/)）。

+   包含具有代理变量的附加文件的`/etc/systemd/system/docker.service.d`目录（示例指南：[`docs.docker.com/config/daemon/systemd/`](https://docs.docker.com/config/daemon/systemd/)）。

您的 Ubuntu 服务器虚拟机现在已准备好作为 Kubernetes 主节点进行初始化。首先，在安装 Kubernetes 二进制文件之前，让我们对集群进行初始规划。

# 规划集群

在开始初始化集群之前，您需要确定 Kubernetes 组件将使用的特定子网和地址范围。这取决于您的外部网络设置（例如，避免任何 IP 地址冲突）以及您计划在集群中运行的 Pod 和服务的数量。一般来说，特别是在本地机器后面的内部 NAT vSwitch 上运行的开发集群，使用默认值是一个好主意。您需要从表中确定以下值用于您的集群： 

|  | **描述** | **默认值** |
| --- | --- | --- |
| **服务子网** | 用于 Pod 访问服务的虚拟子网（不可路由）。节点上运行的`kube-proxy`执行从虚拟 IP 到可路由地址的地址转换。 | `10.96.0.0/12` |
| **集群（Pod）子网** | 集群中所有 Pod 使用的全局子网。一般来说，使用 Flannel 时，每个节点被分配一个较小的/24 子网用于其 Pod。请记住，这个子网必须足够大，以容纳集群中运行的所有 Pod。 | `10.244.0.0/16` |
| **Kubernetes DNS 服务 IP** | 用于集群服务发现和域名解析的`kube-dns`服务的 IP 地址。 | `10.96.0.10` |

这些值将在初始化集群的下一步骤中需要。

# 初始化集群

为了初始化 Kubernetes 的 Ubuntu 主节点并加入 Windows 节点，我们将使用 kubeadm——在 Kubernetes 1.16（以及 1.17）中，这是唯一一个用于混合 Windows/Linux 集群的自动化部署方法。第一步是在 Ubuntu 服务器 VM 上安装 kubeadm、kubelet 和 kubectl。这也在 GitHub 存储库中的脚本中有所涵盖，链接为：[`github.com/PacktPublishing/Hands-On-Kubernetes-on-Windows/blob/master/Chapter07/03_ubuntu-install-kubeadm.sh`](https://github.com/PacktPublishing/Hands-On-Kubernetes-on-Windows/blob/master/Chapter07/03_ubuntu-install-kubeadm.sh)。

安装 kubeadm 和初始化 Kubernetes 主节点的官方说明可以在以下链接找到：[`kubernetes.io/docs/setup/production-environment/tools/kubeadm/install-kubeadm/`](https://kubernetes.io/docs/setup/production-environment/tools/kubeadm/install-kubeadm/) 和 [`kubernetes.io/docs/setup/production-environment/tools/kubeadm/create-cluster-kubeadm/`](https://kubernetes.io/docs/setup/production-environment/tools/kubeadm/create-cluster-kubeadm/)。

SSH 进入 Ubuntu 服务器 VM，并执行以下步骤：

1.  按照以下步骤添加 Kubernetes apt 软件包存储库的 GPG 密钥：

```
curl -s https://packages.cloud.google.com/apt/doc/apt-key.gpg | sudo apt-key add -
```

1.  添加 Kubernetes apt 软件包存储库。使用`sudo vim /etc/apt/sources.list.d/kubernetes.list`命令创建一个新文件，并设置以下内容（请注意，您目前必须使用`kubernetes-xenial`存储库，因为`bionic`目前还不可用）：

```
deb https://apt.kubernetes.io/ kubernetes-xenial main
```

1.  更新`apt-get`并安装所需的软件包，如下：

```
sudo apt-get update
sudo apt-get install kubelet kubeadm kubectl -y
```

1.  通过运行以下代码验证最新的 Kubernetes 版本是否已安装：

```
ubuntu@kubernetes-master:~$ kubeadm version
kubeadm version: &version.Info{Major:"1", Minor:"16", GitVersion:"v1.16.1", GitCommit:"d647ddbd755faf07169599a625faf302ffc34458", GitTreeState:"clean", BuildDate:"2019-10-02T16:58:27Z", GoVersion:"go1.12.10", Compiler:"gc", Platform:"linux/amd64"}
```

1.  通过运行以下命令禁用 Kubernetes 软件包的自动更新（这一点尤为重要，因为任何 Kubernetes 组件的升级都应该经过深思熟虑并以受控的方式进行，考虑到所有的兼容性问题）：

```
sudo apt-mark hold kubelet kubeadm kubectl
```

到目前为止，初始化 Kubernetes 主节点和节点的步骤完全相同。当向集群添加更多专用的 Ubuntu 节点或克隆您的 VM 时，您可以按照相同的步骤进行。如果决定克隆机器，请记住确保每个节点的主机名、MAC 地址和`product_uuid`都是唯一的。在官方文档中了解更多关于如何确保这一点的信息，网址为：[`kubernetes.io/docs/setup/production-environment/tools/kubeadm/install-kubeadm/#verify-the-mac-address-and-product-uuid-are-unique-for-every-node`](https://kubernetes.io/docs/setup/production-environment/tools/kubeadm/install-kubeadm/#verify-the-mac-address-and-product-uuid-are-unique-for-every-node)。

现在，我们准备使用 kubeadm 初始化集群。为了做到这一点，请执行以下步骤：

1.  执行以下命令，假设服务网络为`10.96.0.0/12`，Pod 网络为`10.244.0.0/16`：

```
sudo kubeadm init --service-cidr "10.96.0.0/12" --pod-network-cidr "10.244.0.0/16"
```

1.  仔细检查 kubeadm 初始化输出，并记录`kubeadm join`信息，如下：

```
Your Kubernetes control-plane has initialized successfully!

To start using your cluster, you need to run the following as a regular user:

 mkdir -p $HOME/.kube
 sudo cp -i /etc/kubernetes/admin.conf $HOME/.kube/config
 sudo chown $(id -u):$(id -g) $HOME/.kube/config

You should now deploy a pod network to the cluster.
Run "kubectl apply -f [podnetwork].yaml" with one of the options listed at:
 https://kubernetes.io/docs/concepts/cluster-administration/addons/

Then you can join any number of worker nodes by running the following on each as root:

kubeadm join 10.0.0.2:6443 --token c4kkga.50606d1zr7w0s2w8 \
 --discovery-token-ca-cert-hash sha256:44b2f0f05f79970cc295ab1a7e7ebe299c05fcbbec9d0c08133d4c5ab7fadb0b
```

1.  如果您的 kubeadm 令牌过期（24 小时后），您可以始终使用以下命令创建一个新的：

```
kubeadm token create --print-join-command
```

1.  将**kubectl config** (**kubeconfig**)复制到默认位置，如下：

```
mkdir -p $HOME/.kube
sudo cp -i /etc/kubernetes/admin.conf $HOME/.kube/config
sudo chown $(id -u):$(id -g) $HOME/.kube/config
```

1.  现在，建议将配置复制到 Windows 机器，以便能够在不登录到主节点的情况下管理集群。在 PowerShell 窗口中，执行以下命令：

```
scp ubuntu@10.0.0.2:.kube/config config
$env:KUBECONFIG="config;$env:USERPROFILE\.kube\config"
kubectl config view --raw
```

1.  仔细检查合并的配置，以确保您没有覆盖任何现有集群的配置。您可以在第六章中了解有关合并`kubeconfigs`的更多信息，*与 Kubernetes 集群交互*。如果合并的配置正确，您可以将其保存为`$env:USERPROFILE\.kube\config`，并使用以下命令切换到`kubernetes-admin@kubernetes`上下文：

```
$env:KUBECONFIG="config;$env:USERPROFILE\.kube\config"
kubectl config view --raw > $env:USERPROFILE\.kube\config_new 
Move-Item -Force $env:USERPROFILE\.kube\config_new $env:USERPROFILE\.kube\config

kubectl config use-context "kubernetes-admin@kubernetes"
```

1.  验证配置是否正常工作。按照以下方式检索节点列表（请注意，`NotReady`状态是由于尚未安装 Pod 网络）：

```
PS C:\src> kubectl get nodes
NAME                STATUS     ROLES    AGE   VERSION
kubernetes-master   NotReady   master   22m   v1.16.1
```

1.  如果您不打算添加任何 Ubuntu 节点，可以选择**untaint**主节点，以允许在主节点上调度 Linux Pods。请注意，这仅适用于开发集群。通过运行以下代码来实现：

```
kubectl taint nodes --all node-role.kubernetes.io/master-
```

如果您想重新设置集群，首先需要使用 kubeadm 拆除集群。在官方文档中了解更多关于此过程的信息：[`kubernetes.io/docs/setup/production-environment/tools/kubeadm/create-cluster-kubeadm/#tear-down`](https://kubernetes.io/docs/setup/production-environment/tools/kubeadm/create-cluster-kubeadm/#tear-down)。

您的 Kubernetes 主节点几乎准备就绪。最后一步是安装 Pod 网络。让我们继续！

# 安装 Kubernetes 网络

在使用 kubeadm 初始化 Kubernetes 主节点之后，下一步是安装 Pod 网络。我们在第五章中介绍了 Kubernetes 网络选项，详细解释了混合 Windows/Linux 集群支持的**容器网络接口**（**CNI**）插件。对于本地部署的集群，我们将使用 Flannel 网络和`host-gw`后端（Windows 节点上的`win-bridge` CNI 插件）。请记住，只有在节点之间存在**第 2 层**（**L2**）连接性（没有**第 3 层**（**L3**）路由）时，才能使用此方法。一般来说，`host-gw`后端更可取，因为它处于稳定的功能状态，而覆盖后端对于 Windows 节点仍处于 alpha 功能状态。

如果您对使用覆盖后端的 Flannel 安装感兴趣，请参考官方文档中的详细步骤：[`kubernetes.io/docs/setup/production-environment/windows/user-guide-windows-nodes/#configuring-flannel-in-vxlan-mode-on-the-linux-control-plane`](https://kubernetes.io/docs/setup/production-environment/windows/user-guide-windows-nodes/#configuring-flannel-in-vxlan-mode-on-the-linux-control-plane)。请注意，您需要安装了 KB4489899 补丁的 Windows Server 2019 以进行覆盖网络。

要安装带有`host-gw`后端的 Flannel，请执行以下步骤（在 PowerShell 窗口中或通过 SSH 在 Kubernetes 主节点上）：

1.  下载 Flannel for Kubernetes 的最新官方清单文件，如下所示：

```
# Bash
wget https://raw.githubusercontent.com/coreos/flannel/master/Documentation/kube-flannel.yml

# Powershell
wget https://raw.githubusercontent.com/coreos/flannel/master/Documentation/kube-flannel.yml -OutFile kube-flannel.yml
```

1.  自定义清单，使`net-conf.json`文件部分具有`host-gw`后端类型和正确定义的 Pod 网络（默认值：`10.244.0.0/16`），如下所示：

```
net-conf.json: |
 {
 "Network": "10.244.0.0/16",
 "Backend": {
 "Type": "host-gw"
 }
 }
```

1.  应用修改后的清单，如下所示：

```
kubectl apply -f kube-flannel.yml
```

1.  最新的官方清单不需要额外的补丁来进行仅 Linux 调度，因为它已经涵盖了这一要求。如果您遵循官方指南，可以跳过此步骤。

1.  验证 Pod 网络安装是否成功。您应该能够安排一个运行 Bourne shell 的简单交互式 Pod——只有在您有一个未被污染的主节点用于 Pod 调度或者有其他 Linux 节点时才能工作。通过运行以下代码来实现这一点：

```
PS C:\src> kubectl run --generator=run-pod/v1 busybox-debug -i --tty --image=busybox --rm --restart=Never -- sh
If you don't see a command prompt, try pressing enter.
/ #
```

Kubernetes 主节点完全初始化后，我们可以继续为 Windows 节点准备 VM。

# 为 Windows 节点准备 VM

本节的结构与 Ubuntu Server VM 准备类似。对于 Windows VM，我们将执行以下步骤：

1.  创建 VM

1.  安装 Windows Server 2019

1.  配置网络

1.  安装 SSH 服务器

1.  安装和配置 Kubernetes 先决条件

# 创建 VM

创建 Windows Server 2019 VM 的步骤几乎与 Ubuntu Server 18.04 相同。如果您对该过程的截图感兴趣，请参考前面的部分。

要创建 Windows Server 2019 Kubernetes 节点 VM，请打开 Hyper-V 管理器应用程序并执行以下步骤：

1.  从“操作”菜单中，选择“新建”，然后单击“虚拟机”。

1.  点击“下一步”，选择 Windows 节点 VM 的名称。我们将使用`Kubernetes Windows Node 01`来命名。可选地，配置一个自定义目录来存储 VM 数据，以确保有足够的磁盘空间来托管 VM。每个节点至少需要 30GB 的磁盘空间。

1.  在下一个对话框中，选择“第二代”并继续。

1.  为 Windows 节点分配至少 4096MB 的 RAM。使用更少的内存可能会导致偶尔报告`KubeletHasInsufficientMemory`并阻止 Pod 的调度。由于我们将为此机器启用嵌套虚拟化，动态内存分配功能将不起作用。对于生产场景，考虑分配更多资源。

1.  选择内部 NAT 或外部交换机作为 VM 的连接。这必须是您用于主节点的相同交换机。

1.  创建一个新的虚拟硬盘，大小为 250GB 或更大。由于 VHDX 是动态可扩展的，因此最好从一开始就分配更多的空间，而不是以后再扩展磁盘和分区。

1.  选择从 ISO 安装操作系统，并选择您的 Windows Server 2019（或 1903）镜像文件。

1.  完成 VM 创建向导。在启动 VM 之前，我们需要进一步配置它。右键单击`Kubernetes Windows Node 01`VM 并打开“设置”。

1.  在“处理器”菜单中，将“虚拟处理器数量”设置为至少 2。

1.  在“网络适配器高级功能”菜单中，选择为容器启用 MAC 地址欺骗。如果您使用外部 vSwitch 并且有外部 DHCP，您可能还想配置静态 DHCP 分配。对于内部 NAT vSwitch，您可以保留默认的“动态”设置。

1.  应用所有更改。

1.  在以管理员身份运行的 PowerShell 窗口中使用以下命令启用嵌套虚拟化。

```
Set-VMProcessor -VMName "Kubernetes Windows Node 01" -ExposeVirtualizationExtensions $true
```

该机器现在已准备好启动操作系统安装。

# 安装 Windows Server 2019

Windows Server 2019 的安装过程是使用图形界面执行的。如果您考虑自动化安装过程，例如对于 Vagrant 或 Packer，您应该考虑使用虚拟软驱提供的`Autounattend.xml`文件。您可以在 GitHub 上找到这样一个配置文件的示例，网址为：[`github.com/ptylenda/kubernetes-for-windows/blob/master/packer/windows/http/Autounattend.xml`](https://github.com/ptylenda/kubernetes-for-windows/blob/master/packer/windows/http/Autounattend.xml)。

执行以下步骤来执行安装：

1.  通过在 Hyper-V 管理器中双击`Kubernetes Windows Node 01 VM`来连接。

1.  启动虚拟机，并立即按任意键以从安装到虚拟机中的安装 DVD 启动。

1.  选择语言和区域设置。

1.  点击立即安装。

1.  提供安装产品密钥。

1.  在下一个对话框中，您可以选择是否安装桌面体验。我们建议不安装它，因为这样可以使安装更紧凑，并且将配置留给命令行，这对于**自动化**更好。

1.  阅读并接受许可条款。

1.  选择 Windows Server 的自定义安装。

1.  继续使用默认的安装目标（整个磁盘，无需分区）。

1.  等待安装完成并等待机器重新启动。

1.  在第一次登录时，您必须设置管理员密码。

现在，您已经启动并运行了一个 Windows Server 2019 虚拟机，但在加入 Kubernetes 集群之前，我们需要配置网络并安装先决条件。

# 配置网络

只有在运行内部 NAT vSwitch 时才需要进行额外的网络配置——在这种情况下，您需要配置静态 IP 地址、网关地址和 DNS 服务器信息。如果您正在运行具有外部 DHCP 的外部 vSwitch，则配置应自动执行。

在本指南中，我们遵循 Kubernetes 节点具有以`10.0.0.3`开头的连续 IP 地址的约定。为了将`10.0.0.3`配置为集群中第一个节点的静态 IP 地址，请执行以下步骤：

1.  通过在虚拟机上运行`powershell`命令来启动 PowerShell。

1.  执行以下命令以查找主`Ethernet`接口的`ifIndex`：

```
Get-NetAdapter
```

1.  为接口创建一个新的静态 IP 地址`10.0.0.3`，如下所示：

```
New-NetIPAddress –IPAddress 10.0.0.3 -DefaultGateway 10.0.0.1 -PrefixLength 8 -InterfaceIndex <ifIndex>
```

1.  为接口设置 DNS 服务器信息，如下所示（如果需要，请使用适当的 DNS 服务器）：

```
Set-DNSClientServerAddress –InterfaceIndex <ifIndex> –ServerAddresses 8.8.8.8,8.8.4.4
```

如果您在网络代理后面，可以使用 PowerShell 中的以下命令在机器级别定义适当的环境变量：

**`[Environment]::SetEnvironmentVariable("HTTP_PROXY", "http://proxy.example.com:80/", [EnvironmentVariableTarget]::Machine)`**

**`[Environment]::SetEnvironmentVariable("HTTPS_PROXY", "http://proxy.example.com:443/", [EnvironmentVariableTarget]::Machine)`**

现在让我们看看如何远程访问 Windows Server 虚拟机。

# 安装 SSH 服务器

现在，我们需要一种连接到 VM 而不使用 Hyper-V 终端的方法——如果您愿意，仍然可以使用它，但与使用**远程桌面协议**（**RDP**）或 SSH 相比，它的功能更有限。您有以下选项：

1.  安装 SSH 服务器并使用 Vim 来管理配置文件。

1.  启用 RDP 连接（示例指南：[`theitbros.com/how-to-remotely-enable-remote-desktop-using-powershell/`](https://theitbros.com/how-to-remotely-enable-remote-desktop-using-powershell/)）。

1.  使用 PowerShell 远程连接（示例指南：[`docs.microsoft.com/en-us/powershell/module/microsoft.powershell.core/enable-psremoting?view=powershell-6`](https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.core/enable-psremoting?view=powershell-6)）。

我们将演示如何在 Windows Server 2019 上启用第一个选项，即 SSH 服务器和 Vim。此选项使得访问我们的 Kubernetes 集群变得统一，您可以在所有节点上使用相同的 SSH 密钥。执行以下步骤：

1.  在 Windows Server 机器的 Hyper-V 终端连接中，通过使用`powershell`命令启动 PowerShell。

1.  通过运行以下代码验证当前可以安装的 SSH 服务器的版本：

```
Get-WindowsCapability -Online | ? Name -like 'OpenSSH*'

Name : OpenSSH.Client~~~~0.0.1.0
State : NotPresent

Name : OpenSSH.Server~~~~0.0.1.0
State : NotPresent
```

1.  安装`OpenSSH.Server`功能，如下所示：

```
Add-WindowsCapability -Online -Name OpenSSH.Server~~~~0.0.1.0
```

1.  启动`sshd`服务，如下所示：

```
Start-Service sshd
```

1.  启用`sshd`服务的自动启动，如下所示：

```
Set-Service -Name sshd -StartupType 'Automatic'
```

1.  确保适当的防火墙规则已经就位（`OpenSSH-Server-In-TCP`），如下所示：

```
Get-NetFirewallRule -Name *ssh*
```

1.  如果不存在，请手动添加，如下所示：

```
New-NetFirewallRule -Name sshd -DisplayName 'OpenSSH Server (sshd)' -Enabled True -Direction Inbound -Protocol TCP -Action Allow -LocalPort 22
```

1.  从开发机器上，验证通过 SSH 连接到`10.0.0.3`的 VM 是否可行，如下所示：

```
PS C:\src> ssh Administrator@10.0.0.3
The authenticity of host '10.0.0.3 (10.0.0.3)' can't be established.
ECDSA key fingerprint is SHA256:VYTfj0b1uZmVgHu9BY17q1wpINNEuzb4dsSGtMFQKw4.
Are you sure you want to continue connecting (yes/no)? yes
Warning: Permanently added '10.0.0.3' (ECDSA) to the list of known hosts.
Administrator@10.0.0.3's password:
Microsoft Windows [Version 10.0.17763.737]
(c) 2018 Microsoft Corporation. All rights reserved.

administrator@WIN-GJD24M0P8DA C:\Users\Administrator>
```

1.  默认情况下，启动具有有限功能的`cmd` shell。通过使用`powershell`命令在 SSH 会话中启动 PowerShell。

1.  将 SSH 的默认 shell 更改为`powershell`，使用以下命令：

```
New-ItemProperty -Path "HKLM:\SOFTWARE\OpenSSH" -Name DefaultShell -Value "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe" -PropertyType String -Force
```

1.  安装 Chocolatey 软件包管理器以安装 Vim 编辑器，如下所示：

```
Set-ExecutionPolicy Bypass -Scope Process -Force; iex ((New-Object System.Net.WebClient).DownloadString('https://chocolatey.org/install.ps1'))
```

1.  使用 Chocolatey 安装 Vim，如下所示：

```
 choco install vim -y
```

1.  配置无密码 SSH 登录。使用`vim C:\ProgramData\ssh\administrators_authorized_keys`命令将您的`~/.ssh/id_rsa.pub`公共 SSH 密钥添加到 Windows Server VM 上的`administrators_authorized_keys`。

1.  修复`administrators_authorized_keys`文件的权限，如下所示：

```
icacls C:\ProgramData\ssh\administrators_authorized_keys /remove "NT AUTHORITY\Authenticated Users"
icacls C:\ProgramData\ssh\administrators_authorized_keys /inheritance:r
```

1.  重新启动`sshd`服务，如下所示：

```
Restart-Service -Name sshd -Force
```

所有 Windows 配置操作都可以通过`Autounattend.xml`自动化 Windows 设置（使用常规的`cmd`和`powershell`脚本）和在 Windows 主机上支持的 Ansible 的混合来执行。您可以在此最小示例存储库中检查 Packer 如何使用此方法，网址为：[`github.com/ptylenda/ironic-packer-template-windows2016`](https://github.com/ptylenda/ironic-packer-template-windows2016)。

此时，您的 Windows Server VM 已连接到网络，并准备安装 Kubernetes 的先决条件。

# 安装和配置 Kubernetes 的先决条件

首先，确保 Windows Server 2019 已经更新。为了做到这一点，使用 Hyper-V 终端连接并执行以下步骤：

如果您不想使用第三方模块来管理更新，可以使用`sconfig`命令。目前，这些操作无法通过 SSH 轻松执行，因为它们需要**图形用户界面**（**GUI**）交互。

1.  打开 PowerShell 会话，使用`powershell`命令。

1.  安装用于管理 Windows 更新的`PSWindowsUpdate`自定义模块，如下所示：

```
Install-Module -Name PSWindowsUpdate
```

1.  通过运行以下代码触发 Windows 更新（此过程可能需要一些时间才能完成）：

```
Get-WUInstall -AcceptAll -Install
```

下一步是安装 Docker 和 Kubernetes 本身。可以通过两种方式来实现：

+   手动安装和配置 Docker，如官方微软文档中所述，网址为：[`docs.microsoft.com/en-us/virtualization/windowscontainers/kubernetes/joining-windows-workers`](https://docs.microsoft.com/en-us/virtualization/windowscontainers/kubernetes/joining-windows-workers)

+   使用 Kubernetes `sig-windows-tools`脚本进行半自动化安装，如官方 Kubernetes 文档中所述，网址为：[`kubernetes.io/docs/setup/production-environment/windows/user-guide-windows-nodes/#join-windows-worker-node`](https://kubernetes.io/docs/setup/production-environment/windows/user-guide-windows-nodes/#join-windows-worker-node)

我们将使用第二个选项，因为这是一个更近期的方法，与 kubeadm 支持 Windows 节点一致，从版本 1.16 开始可用。`sig-windows-tools`脚本执行以下操作：

1.  启用 Windows Server 容器功能。

1.  下载所选的容器运行时（Docker 或**容器运行时接口**（**CRI**））。

1.  拉取所需的 Docker 镜像。

1.  下载 Kubernetes 和 Flannel 二进制文件，安装它们，并将它们添加到`$env:PATH`变量中。

1.  下载所选的 CNI 插件。

要在 Windows 上安装 Kubernetes 的所有先决条件，请执行以下步骤：

1.  SSH 进入 Windows Server 节点 VM，如下所示：

```
ssh Administrator@10.0.0.3
```

1.  创建并使用一个新目录，其中将下载`sig-windows-tools`脚本，例如`sig-windows-tools-kubeadm`，如下所示：

```
mkdir .\sig-windows-tools-kubeadm
cd .\sig-windows-tools-kubeadm
```

1.  下载最新的`sig-windows-tools`存储库并解压它。请注意，存储库中的路径可能会更改，因为它目前专门用于`v1.15.0`（您可以在官方文档中查看最新版本，网址为：[`kubernetes.io/docs/setup/production-environment/windows/user-guide-windows-nodes/#preparing-a-windows-node`](https://kubernetes.io/docs/setup/production-environment/windows/user-guide-windows-nodes/#preparing-a-windows-node)）。或者，您可以使用书中 GitHub 存储库中的分支：[`github.com/PacktPublishing/Hands-On-Kubernetes-on-Windows/tree/master/Chapter07/07_sig-windows-tools-kubeadm`](https://github.com/PacktPublishing/Hands-On-Kubernetes-on-Windows/tree/master/Chapter07/07_sig-windows-tools-kubeadm)。这些脚本包含了一些从`sig-windows-tools`中挑选出来的修复 bug，以确保网络正常工作。这一步的代码可以在下面的片段中看到：

```
Invoke-WebRequest -Uri https://github.com/kubernetes-sigs/sig-windo
ws-tools/archive/master.zip -OutFile .\master.zip
tar -xvf .\master.zip --strip-components 3 sig-windows-tools-master/kubeadm/v1.15.0/*
Remove-Item .\master.zip
```

1.  现在，您需要自定义`Kubeclusterbridge.json`文件。这个配置文件是由一个辅助的 PowerShell 模块使用的，它安装先决条件并加入 Windows 节点。在下面的代码块中，您可以找到 Windows Server 2019 节点的配置。您也可以从书的 GitHub 存储库下载它：[`github.com/PacktPublishing/Hands-On-Kubernetes-on-Windows/blob/master/Chapter07/07_sig-windows-tools-kubeadm/Kubeclusterbridge.json`](https://github.com/PacktPublishing/Hands-On-Kubernetes-on-Windows/blob/master/Chapter07/07_sig-windows-tools-kubeadm/Kubeclusterbridge.json)。您需要确保`Images`的版本与您的节点操作系统版本匹配，并且`Network`有适当的`ServiceCidr`和`ClusterCidr`。此外，您需要提供一个`KubeadmToken`和`KubeadmCAHash`，这是在初始化 Kubernetes 主节点时生成的。您可以使用`kubeadm token create --print-join-command`命令在 Kubernetes 主节点上生成一个新的令牌。这一步的代码可以在下面的片段中看到：

```
{
    "Cri" : {
       "Name" : "dockerd",
        "Images" : {
            "Pause" : "mcr.microsoft.com/k8s/core/pause:1.2.0",
            "Nanoserver" : "mcr.microsoft.com/windows/nanoserver:1809",
            "ServerCore" : "mcr.microsoft.com/windows/servercore:ltsc2019"
        }
    },
    "Cni" : {
        "Name" : "flannel",
        "Source" : [{ 
            "Name" : "flanneld",
            "Url" : "https://github.com/coreos/flannel/releases/download/v0.11.0/flanneld.exe"
            }
        ],
        "Plugin" : {
            "Name": "bridge"
        },
        "InterfaceName" : "Ethernet"
    },
    "Kubernetes" : {
        "Source" : {
            "Release" : "1.16.1",
            "Url" : "https://dl.k8s.io/v1.16.1/kubernetes-node-windows-amd64.tar.gz"
        },
        "ControlPlane" : {
            "IpAddress" : "10.0.0.2",
            "Username" : "ubuntu",
            "KubeadmToken" : "<token>",
            "KubeadmCAHash" : "<discovery-token-ca-cert-hash>"
        },
        "KubeProxy" : {
            "Gates" : "WinDSR=true"
        },
        "Network" : {
            "ServiceCidr" : "10.96.0.0/12",
            "ClusterCidr" : "10.244.0.0/16"
        }
    },
    "Install" : {
        "Destination" : "C:\\ProgramData\\Kubernetes"
    }
}
```

1.  此时，您需要切换到 RDP 连接或 Hyper-V 终端连接。安装脚本需要一些交互和无法通过 SSH PowerShell 会话执行的提升权限。

1.  使用`powershell`命令启动 PowerShell 会话，转到`.\sig-windows-tools-kubeadm`目录，并开始安装过程，如下所示：

```
cd .\sig-windows-tools-kubeadm
.\KubeCluster.ps1 -ConfigFile .\Kubeclusterbridge.json -Install
```

1.  在安装过程中，机器将需要重新启动，重新登录后安装将继续。通过检查以下截图中显示的信息，验证加载的配置是否符合预期：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/hsn-k8s-win/img/318ae8af-2dd1-489c-9d22-7ae13610da62.png)

1.  您可能会遇到完全运行的 Docker 守护程序和正在拉取的镜像之间的*竞争条件*。如果出现错误，只需再次重启或使用相同命令重新启动安装过程——请记住在下一次尝试之前关闭现有的 PowerShell 会话并启动一个新的会话。根据您的网络连接情况，下载镜像可能需要一些时间。

1.  镜像已经被拉取，Kubernetes、Flannel 和 CNI 插件已经安装完毕，接下来将会要求您为从新的 Windows 节点访问主节点生成新的 SSH 密钥对——或者您也可以自己操作或重用现有的密钥对。这将使加入过程更加简单，因为加入脚本需要使用 SSH 来检索集群配置。在`10.0.0.2`主节点上执行脚本输出的命令，以将公钥添加到 Ubuntu 用户的`authorized_keys`中，如下截图所示：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/hsn-k8s-win/img/68a0e9e6-640f-4b64-820b-5c25bfb98857.png)

1.  安装完成后，关闭 PowerShell 窗口并打开一个新窗口，使用`powershell`命令。

1.  目前，您需要清理`ContainerBootstrap`调度程序任务，该任务在每次启动后重新运行脚本（这可能在未来的版本中得到修复），操作如下：

```
 Unregister-ScheduledTask -TaskName "ContainerBootstrap"
```

1.  使用`docker images`命令验证 Docker 镜像是否已被拉取，并通过运行`kubectl version`命令验证 Kubernetes 二进制文件是否已安装。

考虑导出 VM 镜像或创建检查点——如果您选择向集群添加更多的 Windows 节点或在加入过程中遇到问题，这将非常有用。现在我们终于可以将第一个 Windows 节点加入集群了！

# 使用 kubeadm 加入 Windows 节点

下一个任务是将我们的 Windows Server 2019 VM 作为 Kubernetes 集群中的节点加入。我们将使用来自 Kubernetes `sig-windows-tools`存储库的相同`KubeCluster.ps1`脚本，该脚本在内部使用**kubeadm**加入集群。该脚本将执行以下操作：

1.  使用 SSH 从`10.0.0.2`主节点检索*kubeconfig*文件。

1.  将**kubelet**注册为 Windows 服务。这将确保 kubelet 进程始终在 Windows 节点上运行。

1.  准备 CNI 插件的配置。

1.  创建**主机网络服务**（**HNS**）网络。

1.  添加防火墙规则（如果需要）。

1.  将**flanneld**和**kube-proxy**注册为 Windows 服务。

如果加入脚本失败，请启动新的 PowerShell 会话并重新运行脚本。

要加入 Windows 节点，请按以下步骤进行：

1.  在 Windows Server VM 的 Hyper-V 终端中，使用`powershell`命令启动新的 PowerShell 会话。

1.  通过运行以下命令导航到带有`sig-windows-tools`脚本的目录：

```
cd .\sig-windows-tools-kubeadm
```

1.  执行加入命令，就像这样：

```
.\KubeCluster.ps1 -ConfigFile .\Kubeclusterbridge.json -Join
```

如果`kubeadm join`命令出现任何问题（例如，挂起的预检查），您可以编辑`KubeClusterHelper.psm1`文件，找到`kubeadm join`命令，并添加`--v=3`参数（或任何其他详细程度）以获得更详细的信息。此外，您可以检查`C:\ProgramData\Kubernetes\logs`目录中的服务日志。还可以验证问题是否已知，网址为[`github.com/kubernetes-sigs/sig-windows-tools/issues`](https://github.com/kubernetes-sigs/sig-windows-tools/issues)——修复可能已经可用。

1.  加入新的 Windows 节点是一个相对快速的过程，几秒钟后，操作应该完成。现在，验证新节点是否在集群中可见，并且具有`Ready`状态，就像这样：

```
PS C:\src> kubectl get nodes
NAME                STATUS   ROLES    AGE   VERSION
kubernetes-master   Ready    master   26h   v1.16.1
win-gjd24m0p8da     Ready    <none>   11m   v1.16.1
```

1.  在 Windows 节点上，使用`ipconfig`命令验证 Flannel 是否已创建`cbr0_ep`接口，如下面的屏幕截图所示：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/hsn-k8s-win/img/10ed8551-4d88-49f1-92b4-0d581839e863.png)

1.  通过创建一个临时的 PowerShell Pod 命名为`powershell-debug`来对新节点进行快速的烟雾测试。 Pod 规范覆盖必须包含`nodeSelector`，与 Windows 节点匹配，如下面的代码块所示：

```
kubectl run `
 --generator=run-pod/v1 powershell-debug `
 -i --tty `
 --image=mcr.microsoft.com/powershell:nanoserver-1809 `
 --restart=Never `
 --overrides='{\"apiVersion\": \"v1\", \"spec\": {\"nodeSelector\": { \"beta.kubernetes.io/os\": \"windows\" }}}'
```

1.  镜像拉取可能需要一些时间。您可以使用以下命令观察 Pod 事件：

```
kubectl describe pod powershell-debug
```

1.  当 Pod 启动时，请验证 DNS 解析和对外部地址的连接 - 例如，通过使用 `ping google.com` 命令，如下截图所示：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/hsn-k8s-win/img/8fd7dfa6-09b2-48df-b5c5-ff27dba7d263.png)

1.  退出容器，然后通过运行以下命令删除 Pod（我们没有使用 `--rm` 标志，以便您可以轻松使用 `kubectl describe` 命令调查任何问题）：

```
kubectl delete pod powershell-debug
```

为了完整起见，为了删除 Windows 节点并重置机器的状态（例如，在配置更改后，为了重新安装和加入），使用相同的 `KubeCluster.ps1` 脚本并执行以下命令：

```
.\KubeCluster.ps1 -ConfigFile .\Kubeclusterbridge.json -Reset
```

恭喜 - 现在，您拥有一个完全功能的混合 Windows/Linux Kubernetes 集群正在运行！您可以选择按照相同的说明或使用 VM 镜像添加更多的 Windows 或 Linux 节点（记得重新生成主机名、MAC 地址和 `product_uuids`）。

# 部署和检查您的第一个应用程序

现在，是时候用新创建的 Kubernetes 集群玩一些游戏了。我们将创建一个最小的 Deployment 与 NodePort Service，将应用程序暴露给用户。应用程序本身是官方的 ASP.NET Core 3.0 示例，打包为 Docker 镜像 - 您可以随意使用任何其他 Windows web 应用程序容器镜像，或者创建您自己的镜像。我们选择了官方示例，以便尽快进行部署，以便我们可以专注于 Kubernetes 操作。

要部署示例应用程序，请执行以下步骤：

1.  创建一个包含 Deployment 和 Service 定义的 `windows-example.yaml` 清单文件。您可以从 GitHub 仓库 ([`raw.githubusercontent.com/PacktPublishing/Hands-On-Kubernetes-on-Windows/master/Chapter07/09_windows-example/windows-example.yaml`](https://raw.githubusercontent.com/PacktPublishing/Hands-On-Kubernetes-on-Windows/master/Chapter07/09_windows-example/windows-example.yaml)) 下载它，或者直接将其应用到集群，如下所示：

```
apiVersion: apps/v1
kind: Deployment
metadata:
  name: windows-example
  labels:
    app: sample
spec:
  replicas: 3
  selector:
    matchLabels:
      app: windows-example
  template:
    metadata:
      name: windows-example
      labels:
        app: windows-example
    spec:
      nodeSelector:
        "beta.kubernetes.io/os": windows
      containers:
      - name: windows-example
        image: mcr.microsoft.com/dotnet/core/samples:aspnetapp-nanoserver-1809
        resources:
          limits:
            cpu: 1
            memory: 800M
          requests:
            cpu: .1
            memory: 300M
        ports:
          - containerPort: 80
---
apiVersion: v1
kind: Service
metadata:
  name: windows-example
spec:
  type: NodePort
  ports:
  - protocol: TCP
    port: 80
    nodePort: 31001
    targetPort: 80
  selector:
    app: windows-example
```

在此清单文件中有三个重要的点，已用粗体标记出来：

+   +   **为 Windows 节点进行调度** 需要使用带有值为 `"beta.kubernetes.io/os": windows` 的 `nodeSelector`。同样，如果您需要为 Linux 节点调度 Pods，在混合集群中应该使用带有值为 `"beta.kubernetes.io/os": linux` 的节点选择器。

+   Pod 定义包括一个基于`mcr.microsoft.com/dotnet/core/samples:aspnetapp-nanoserver-1809`镜像的容器。确保容器主机操作系统版本与容器基础镜像版本之间的**兼容性**非常重要。在这种情况下，Windows Server 2019 LTS 与基于 1809 的镜像兼容。如果您选择使用 Windows Server 1903 节点，则必须使用基于 1903 的镜像。

+   **NodePort Service**将在集群中的每个节点上的端口**31001**上公开。换句话说，您可以期望该应用程序在`10.0.0.2:31001`和`10.0.0.3:31001`端点可用。请注意，对于负载均衡器服务，如果您的基础设施没有负载均衡器，您可以考虑使用**keepalived**（[`github.com/munnerz/keepalived-cloud-provider`](https://github.com/munnerz/keepalived-cloud-provider)）。

1.  打开 PowerShell 窗口，并使用`kubectl`应用清单文件，就像这样：

```
kubectl apply -f .\windows-example.yaml
```

1.  等待 Pod 启动——初始镜像拉取可能需要几分钟。您可以使用以下命令观察 Pod 的状态：

```
PS C:\src> kubectl get pods --watch 
NAME                               READY STATUS   RESTARTS  AGE
windows-example-66cdf8c4bf-4472x   1/1   Running   0        9m17s
windows-example-66cdf8c4bf-647x8   1/1   Running   0        9m17s
windows-example-66cdf8c4bf-zxjdv   1/1   Running   0        9m17s
```

1.  打开你的互联网浏览器，转到`http://10.0.0.2:31001`和`http://10.0.0.3:31001`。您应该看到确认部署成功的示例应用程序网页，如下截图所示：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/hsn-k8s-win/img/91d84c1f-bfab-4e8b-a3e2-94f4f37d6948.png)

现在，让我们执行两个在调试应用程序时有用的常见操作，如下所示：

1.  检索 Pod 容器日志：要访问部署中一个 Pod（`windows-example-66cdf8c4bf-4472x`）的日志，请使用以下`kubectl logs`命令：

```
PS C:\src> kubectl logs windows-example-66cdf8c4bf-4472x
warn: Microsoft.AspNetCore.DataProtection.Repositories.FileSystemXmlRepository[60]
 Storing keys in a directory 'C:\Users\ContainerUser\AppData\Local\ASP.NET\DataProtection-Keys' that may not be persisted outside of the container. Protected data will be unavailable when container is destroyed.
info: Microsoft.Hosting.Lifetime[0]
 Now listening on: http://[::]:80
info: Microsoft.Hosting.Lifetime[0]
 Application started. Press Ctrl+C to shut down.
info: Microsoft.Hosting.Lifetime[0]
 Hosting environment: Production
info: Microsoft.Hosting.Lifetime[0]
 Content root path: C:\app
warn: Microsoft.AspNetCore.HttpsPolicy.HttpsRedirectionMiddleware[3]
 Failed to determine the https port for redirect.
```

1.  执行进入 Pod 容器以检查应用程序配置。要启动一个新的`cmd` shell（`nanoserver`镜像中不可用 PowerShell），请运行以下`kubectl exec`命令：

```
PS C:\src> kubectl exec -it windows-example-66cdf8c4bf-4472x cmd
Microsoft Windows [Version 10.0.17763.802]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\app>
```

1.  您现在可以自由访问和修改容器，这在调试和测试场景中非常有用。例如，您可以像这样获取`appsettings.json`文件的内容：

```
C:\app>type appsettings.json
{
 "Logging": {
 "LogLevel": {
 "Default": "Information",
 "Microsoft": "Warning",
 "Microsoft.Hosting.Lifetime": "Information"
 }
 },
 "AllowedHosts": "*"
}
```

正如您所看到的，将示例 Windows 应用程序部署到 Kubernetes 集群非常容易，而且您从 Linux Kubernetes 集群中了解的所有调试技术都完全相同。

# 摘要

在本章中，您已经学习了如何在 Hyper-V 主机上创建本地 Windows/Linux Kubernetes 集群的过程。这种方法对于创建本地开发集群以及在云环境之外部署生产集群非常有用。让我们回顾一下程序——我们首先规划了节点、Pod 和 Service 的集群设计和网络**无类域间路由**（**CIDRs**）。然后，我们创建了 Ubuntu Server 18.04 LTS VM——我们的 Kubernetes 主节点。创建主节点需要对操作系统进行初始配置并安装 Docker。使用 kubeadm 进行初始化。下一个重要步骤是安装 Kubernetes Pod 网络，该网络必须与 Linux 和 Windows 节点兼容。在我们的情况下，我们选择了带有`host-gw`后端的 Flannel，这是目前唯一稳定的本地混合集群的网络解决方案。之后，您将学习如何创建 Windows Server 2019 LTS VM 以及如何使用 kubeadm 和`sig-windows-tools`脚本将机器加入 Kubernetes 集群。最后，我们部署了一个示例 ASP.NET Core 3.0 应用程序，并执行了常见操作，如访问容器日志或进入容器。

在下一章中，您将学习如何使用 AKS Engine 执行类似的集群部署。目前，这是在云中部署混合 Kubernetes 集群的最佳和最稳定的方法。

# 问题

1.  何时应该使用内部 NAT Hyper-V vSwitch？外部 vSwitch 有哪些用例？

1.  为准备 Linux 节点或主节点需要哪些配置步骤？

1.  服务子网范围和 Pod 子网范围是什么？

1.  如何生成一个新的 kubeadm 令牌以加入集群？

1.  如何允许将应用程序 Pod 调度到主节点？

1.  在本地集群中，Linux 和 Windows 节点的推荐网络解决方案是什么？

1.  加入集群的 Windows 节点需要执行哪些步骤？

1.  访问 Pod 容器日志的命令是什么？

您可以在本书的后部的*评估*中找到这些问题的答案。

# 进一步阅读

+   目前，关于混合 Windows/Linux 集群部署的大多数资源都可以在线获得。有两个官方指南用于创建这样的集群：

+   Kubernetes 指南，网址为：[`kubernetes.io/docs/setup/production-environment/windows/intro-windows-in-kubernetes/`](https://kubernetes.io/docs/setup/production-environment/windows/intro-windows-in-kubernetes/)。

+   Microsoft 指南，网址为：[`docs.microsoft.com/en-us/virtualization/windowscontainers/kubernetes/getting-started-kubernetes-windows`](https://docs.microsoft.com/en-us/virtualization/windowscontainers/kubernetes/getting-started-kubernetes-windows)。

这两个指南经常更新，因此值得检查它们，因为随着时间的推移，部署过程可能会变得更加简化。

+   您还可以在 Microsoft 的以下**软件定义网络**（**SDN**）存储库中找到有用的信息，网址为：[`github.com/microsoft/SDN/tree/master/Kubernetes/windows`](https://github.com/microsoft/SDN/tree/master/Kubernetes/windows)。它包含许多辅助脚本，逐渐被采用到官方部署说明和 kubeadm 集成中。

+   有关 kubeadm 的用法和文档，请参阅[`kubernetes.io/docs/setup/production-environment/tools/kubeadm/create-cluster-kubeadm/`](https://kubernetes.io/docs/setup/production-environment/tools/kubeadm/create-cluster-kubeadm/)。

+   如果您需要帮助解决问题和常见问题，您可以使用以下指南：

+   [`docs.microsoft.com/en-us/virtualization/windowscontainers/kubernetes/common-problems`](https://docs.microsoft.com/en-us/virtualization/windowscontainers/kubernetes/common-problems)。

+   [`kubernetes.io/docs/setup/production-environment/windows/intro-windows-in-kubernetes/#troubleshooting`](https://kubernetes.io/docs/setup/production-environment/windows/intro-windows-in-kubernetes/#troubleshooting)。

+   [`techcommunity.microsoft.com/t5/Networking-Blog/Troubleshooting-Kubernetes-Networking-on-Windows-Part-1/ba-p/508648`](https://techcommunity.microsoft.com/t5/Networking-Blog/Troubleshooting-Kubernetes-Networking-on-Windows-Part-1/ba-p/508648)——特定于 Windows 容器网络问题的故障排除指南。


# 第八章：部署混合 Azure Kubernetes 服务引擎集群

上一章概述了如何在本地环境中创建混合 Windows/Linux Kubernetes 集群的方法。这种方法也可以用于基础设施即服务云环境中的部署，但如果您使用 Azure，您有一个更简单的解决方案：**Azure Kubernetes 服务**（**AKS**）**引擎** ([`github.com/Azure/aks-engine`](https://github.com/Azure/aks-engine))。该项目旨在提供一种使用**Azure 资源管理器**（**ARM**）模板部署自管理 Kubernetes 集群的 Azure 本地方式，可以利用 Kubernetes 的所有 Azure 云集成，例如负载均衡器服务。此外，使用 AKS Engine，您可以支持使用 Windows 节点部署 Kubernetes 集群，与本地环境相比，需要的配置和节点准备较少。换句话说，您将能够在几分钟内部署一个生产级的高可用混合集群。

AKS Engine 与其他概念（如 AKS、acs-engine 和 Azure Stack）的关系进行简要总结非常重要：

+   AKS Engine 和 AKS 不是相同的 Azure 产品。AKS 是一个 Azure 服务，可以让您创建一个完全托管的 Kubernetes 集群-我们在第四章中概述了 AKS 并演示了如何使用 AKS 部署混合 Windows/Linux 集群，但 AKS Engine 是 AKS 内部使用的，但您不能使用 AKS 来管理 AKS

+   acs-engine 是 AKS Engine 的前身，因此您可能会发现很多文档提到 acs-engine 而不是 AKS Engine。AKS Engine 是 acs-engine 的向后兼容的延续。

+   从技术上讲，如果您使用 Azure Stack，也可以在本地环境中使用 AKS Engine。您可以在这里阅读更多信息：[`docs.microsoft.com/en-us/azure-stack/user/azure-stack-kubernetes-aks-engine-overview`](https://docs.microsoft.com/en-us/azure-stack/user/azure-stack-kubernetes-aks-engine-overview)。

在本章中，我们将重点关注 AKS Engine 并在 Azure 云中部署混合 Windows/Linux 集群。我们将涵盖以下主题：

+   安装 AKS Engine

+   创建 Azure 资源组和服务主体

+   使用 API 模型和生成 Azure 资源管理器模板

+   部署集群

+   部署和检查您的第一个应用程序

# 技术要求

对于本章，您将需要以下内容：

+   已安装 Windows 10 Pro、企业版或教育版（1903 版本或更高版本，64 位）

+   一个 Azure 账户

+   已安装 Windows 的 Chocolatey 软件包管理器（[`chocolatey.org/`](https://chocolatey.org/)）

+   可选地，如果您想要可视化 AKS Engine 生成的 ARM 模板，可以安装 Visual Studio Code

使用 Chocolatey 软件包管理器并非强制，但它可以使安装过程和应用程序版本管理更加简单。安装过程在此处有文档：[`chocolatey.org/install`](https://chocolatey.org/install)。

要跟着做，您需要自己的 Azure 账户以创建 Kubernetes 集群的 Azure 资源。如果您之前还没有创建过账户，您可以在此处了解如何获取个人使用的有限免费账户：[`azure.microsoft.com/en-us/free/`](https://azure.microsoft.com/en-us/free/)。

您可以从官方 GitHub 存储库下载本章的最新代码示例：[`github.com/PacktPublishing/Hands-On-Kubernetes-on-Windows/tree/master/Chapter08`](https://github.com/PacktPublishing/Hands-On-Kubernetes-on-Windows/tree/master/Chapter08)。

# 安装 AKS Engine

AKS Engine 本身是一个命令行工具，可以根据提供的配置文件生成基于 Azure 资源管理器（ARM）模板。要使用 AKS Engine，您需要以下内容，其安装过程在前几章中有描述：

+   **Azure CLI 和 Azure Cloud Shell：** 指南可在第二章中找到，*管理容器中的状态*，在*使用远程/云存储进行容器存储*部分。

+   **kubectl：** 指南可在第六章中找到，*与 Kubernetes 集群交互*，在*安装 Kubernetes 命令行工具*部分。

+   **Windows 下的 SSH 客户端：** 指南可在第七章中找到，*部署混合本地 Kubernetes 集群*，在*使用 kubeadm 创建 Kubernetes 主节点*部分。

在您的计算机上安装了所有工具后，您可以继续安装 AKS Engine 本身。在 Windows 上推荐的安装方法是使用 Chocolatey。或者，您可以下载 AKS Engine 二进制文件（[`github.com/Azure/aks-engine/releases/latest`](https://github.com/Azure/aks-engine/releases/latest)），解压它们，并将它们添加到您的`$env:PATH`环境变量中。要使用 Chocolatey 安装 AKS Engine，请按照以下步骤进行：

1.  以管理员身份打开 PowerShell 窗口。

1.  要安装`aks-engine`软件包，请执行以下命令：

```
choco install aks-engine
```

1.  如果您想安装特定版本的 AKS Engine，例如`0.42.0`，请使用以下命令：

```
choco install aks-engine --version=0.42.0
```

1.  验证您的安装是否成功：

```
PS C:\src> aks-engine version
Version: v0.42.0
GitCommit: 0959ab812
GitTreeState: clean
```

现在，您已经准备好继续下一步-配置 Kubernetes 集群的先决条件。让我们开始收集初始集群信息并创建 Azure 资源组。

# 创建 Azure 资源组和服务主体

在使用 AKS Engine 部署 Kubernetes 集群之前，我们需要执行以下初始步骤：

1.  您需要确保在 Azure 订阅中具有适当的权限来创建和分配 Azure 活动目录服务主体。如果您只是为了进行演示而创建了 Azure 帐户，则默认情况下将具有权限。

1.  确定要用于部署集群的 Azure 订阅的`SubscriptionId`。您可以通过打开 PowerShell 窗口并执行以下命令来执行此操作：

```
PS C:\src> az login
PS C:\src> az account list -o table
Name           CloudName    SubscriptionId                        State    IsDefault
-------------  -----------  ------------------------------------  -------  -----------
Pay-As-You-Go  AzureCloud   cc9a8166-829e-401e-a004-76d1e3733b8e  Enabled  True
```

在接下来的段落中，我们将使用`cc9a8166-829e-401e-a004-76d1e3733b8e`作为`SubscriptionId`。

1.  确定一个全局唯一的`dnsPrefix`，您想要用于集群内主机名的。或者，您可以依赖于 AKS Engine 自动生成的前缀。在接下来的段落中，我们将使用`handson-aks-engine-win`作为前缀。

1.  选择要用于部署集群的 Azure 位置。在接下来的示例中，我们将使用`westeurope`。

1.  为您的集群选择一个新的 Azure 资源组的名称。在接下来的段落中，我们将使用`aks-engine-windows-resource-group`。

1.  为 Windows 节点选择用户名和密码。为此，我们将使用`azureuser`和`S3cur3P@ssw0rd`-请记住使用您自己的安全密码！

1.  生成一个 SSH 密钥对，您可以用它来连接到 Linux 节点。如果您选择在 Windows 节点上安装 OpenSSH 服务器，您以后可以使用相同的密钥对来访问 Windows 节点。

下一段描述的先决条件创建和 AKS Engine 部署步骤已在此处提供的 PowerShell 脚本中捕获：[`github.com/PacktPublishing/Hands-On-Kubernetes-on-Windows/blob/master/Chapter08/01_aks-engine/01_CreateAKSEngineClusterWithWindowsNodes.ps1`](https://github.com/PacktPublishing/Hands-On-Kubernetes-on-Windows/blob/master/Chapter08/01_aks-engine/01_CreateAKSEngineClusterWithWindowsNodes.ps1)。

现在，请按照以下步骤创建 Azure 资源组和 Azure 活动目录服务主体：

1.  打开 PowerShell 窗口并使用 Azure CLI 登录：

```
az login
```

1.  使用以下命令为您的集群创建 Azure 资源组：

```
az group create `
 --name aks-engine-windows-resource-group `
 --location westeurope
```

1.  为您的集群创建 Azure 活动目录服务主体。使用适当的`Subscription ID`和`Resource Group`名称：

```
az ad sp create-for-rbac `
 --role="Contributor" `
 --scopes="/subscriptions/cc9a8166-829e-401e-a004-76d1e3733b8e/resourceGroups/aks-engine-windows-resource-group"
```

请注意，如果范围仅限于特定的资源组，则将无法使用容器监视附加组件。我们将在接下来的章节中介绍为此目的配置 AAD 服务主体。

1.  检查上一个命令的输出，并注意`appId`和`password`。您无法以后检索密码：

```
{
 "appId": "7614823f-aca5-4a31-b2a5-56f30fa8bd8e",
 "displayName": "azure-cli-2019-10-19-12-48-08",
 "name": "http://azure-cli-2019-10-19-12-48-08",
 "password": "8737c1e6-b1b1-4c49-a195-f7ea0fe37613",
 "tenant": "86be0945-a0f3-44c2-8868-9b6aa96b0b62"
}
```

最后一步是为访问集群中的 Linux 节点生成 SSH 密钥对：

1.  打开 PowerShell 窗口。

1.  如果您已经按照前面的章节操作，可能已经生成了一个 SSH 密钥对，您可以重复使用并跳过下一步。要检查是否有现有的 SSH 密钥对，请使用以下命令：

```
ls ~\.ssh\id_rsa.pub
```

1.  如果您需要生成密钥对，请执行以下命令（建议使用默认值）：

```
ssh-keygen
```

现在，您拥有 AKS Engine 部署所需的所有信息。我们需要做的就是准备 AKS Engine apimodel 并为我们的集群生成 ARM 模板。

# 使用 apimodel 并生成 Azure 资源管理器模板

在其核心，AKS Engine 使用一个**apimodel**（或集群定义）JSON 文件来生成可以用于直接部署 Kubernetes 集群到 Azure 的 Azure 资源管理器模板。apimodel 的文档和模式可以在这里找到：[`github.com/Azure/aks-engine/blob/master/docs/topics/clusterdefinitions.md`](https://github.com/Azure/aks-engine/blob/master/docs/topics/clusterdefinitions.md)。AKS Engine 在集群定义中提供了对 Windows 节点的开箱即用支持。您可以在官方 AKS Engine GitHub 存储库中找到示例：[`github.com/Azure/aks-engine/tree/master/examples/windows`](https://github.com/Azure/aks-engine/tree/master/examples/windows)。

现在让我们根据最小的 Windows 集群示例定义（[`github.com/Azure/aks-engine/blob/master/examples/windows/kubernetes.json`](https://github.com/Azure/aks-engine/blob/master/examples/windows/kubernetes.json)）创建一个自定义的 apimodel。我们还将包括两个 Linux 节点，以便运行混合的 Windows/Linux 配置（一个 Linux 主节点，两个 Windows 节点和两个 Linux 节点）。按照以下步骤进行：

1.  下载以下文件，并将其保存为`kubernetes-windows.json`：[`raw.githubusercontent.com/Azure/aks-engine/master/examples/windows/kubernetes.json`](https://raw.githubusercontent.com/Azure/aks-engine/master/examples/windows/kubernetes.json)。

1.  将`properties.orchestratorProfile.orchestratorRelease`更改为所需的 Kubernetes 版本，例如`1.16`。

1.  将`properties.masterProfile.dnsPrefix`修改为所选的 DNS 前缀。在示例中，我们使用`handson-aks-engine-win`，但您需要选择您自己的唯一前缀。

1.  通过将以下 JSON 对象添加到`properties.agentPoolProfiles`中，添加一个 Linux 节点池：

```
{
    "name": "linuxpool1",
    "count": 2,
    "vmSize": "Standard_D2_v3",
    "availabilityProfile": "AvailabilitySet"
}
```

1.  将`properties.windowsProfile.adminUsername`和`properties.windowsProfile.adminPassword`修改为 Windows 节点的所选用户名和密码。

1.  将`~\.ssh\id_rsa.pub`的内容复制到`properties.linuxProfile.ssh.publicKeys.keyData`。

1.  在`properties.servicePrincipalProfile.clientId`中使用服务主体`appId`，在`properties.servicePrincipalProfile.secret`中使用`password`。

1.  一个示例的自定义文件具有以下内容：

```
{
 "apiVersion": "vlabs",
    "properties": {
        "orchestratorProfile": {
            "orchestratorType": "Kubernetes",
            "orchestratorRelease": "1.16"
        },
        "masterProfile": {
            "count": 1,
            "dnsPrefix": "handson-aks-engine-win",
            "vmSize": "Standard_D2_v3"
        },
        "agentPoolProfiles": [{
                "name": "linuxpool1",
                "count": 2,
                "vmSize": "Standard_D2_v3",
                "availabilityProfile": "AvailabilitySet"
            },{
                "name": "windowspool2",
                "count": 2,
                "vmSize": "Standard_D2_v3",
                "availabilityProfile": "AvailabilitySet",
                "osType": "Windows",
                "osDiskSizeGB": 128,
                "extensions": [{
                        "name": "winrm"
                    }
                ]
            }
        ],
        "windowsProfile": {
            "adminUsername": "azureuser",
            "adminPassword": "S3cur3P@ssw0rd",
            "sshEnabled": true
        },
        "linuxProfile": {
            "adminUsername": "azureuser",
            "ssh": {
                "publicKeys": [{
                        "keyData": "<contents of ~\.ssh\id_rsa.pub>"
                    }
                ]
            }
        },
        "servicePrincipalProfile": {
            "clientId": "8d4d1104-7818-4883-88d2-2146b658e4b2",
            "secret": "9863e38c-896f-4dba-ac56-7a3c1849a87a"
        },
        "extensionProfiles": [{
                "name": "winrm",
                "version": "v1"
            }
        ]
    }
}
```

apimodel 已准备好供 AKS Engine 使用。使用以下命令生成 ARM 模板：

```
aks-engine generate .\kubernetes-windows.json
```

这将在`_output\<dnsPrefix>`目录中生成 ARM 模板（带参数）、完整的 apimodel 和 kubeconfigs（对于每个可能的 Azure 位置）。您可以检查这些文件以了解集群的设计方式 - 可选地，如果您安装了 Visual Studio Code，可以使用以下优秀的扩展来可视化 ARM 模板 - [`marketplace.visualstudio.com/items?itemName=bencoleman.armview`](https://marketplace.visualstudio.com/items?itemName=bencoleman.armview)：

1.  在 VS Code 中，安装了扩展程序后，打开`_output\<dnsPrefix>\azuredeploy.json` ARM 模板文件。

1.  使用以下图标可视化 ARM 模板：

！[](assets/0c7a2ed2-e1da-4a5f-8c71-39fcd491d5a0.png)

1.  使用以下图标加载 ARM 模板参数`_output\<dnsPrefix>\azuredeploy.parameters.json`：

！[](assets/2a732b78-e8bc-4bb7-a93d-5fb04f0aceae.png)

1.  您现在可以方便地检查 ARM 模板：

！[](assets/e1cf1e78-dea2-465b-b44d-e4273c0fa74b.png)

此时，我们准备使用 Azure CLI 部署集群！

# 部署集群

为了从 Azure 资源管理器模板部署 Kubernetes 集群，我们将使用`az group deployment create`命令。这个 Azure CLI 命令需要传递 ARM 模板（`_output\<dnsPrefix>\azuredeploy.json`）和 ARM 参数文件（`_output\<dnsPrefix>\azuredeploy.parameters.json`）。要部署集群，请执行以下步骤：

1.  执行命令：

```
az group deployment create `
 --name kubernetes-windows-cluster `
 --resource-group aks-engine-windows-resource-group `
 --template-file ".\_output\<dnsPrefix>\azuredeploy.json" `
 --parameters ".\_output\<dnsPrefix>\azuredeploy.parameters.json"
```

如果遇到任何问题，您可以通过转到资源组并单击右上角的“部署：失败”链接，在 Azure 门户中检查 ARM 部署失败的详细信息。对于任何`InternalServerErrors`，您可以尝试选择另一个 Azure 位置，例如`westus`。

1.  部署完成后，将以 JSON 格式返回创建的资源列表和输出变量：

```
      ...
      "agentStorageAccountSuffix": {
        "type": "String",
        "value": ""
      },
      "masterFQDN": {
        "type": "String",
        "value": "<dnsPrefix>.westeurope.cloudapp.azure.com"
      },
      "primaryAvailabilitySetName": {
        "type": "String",
        "value": "windowspool2-availabilitySet-70017404"
      },
      ...
```

1.  提取`masterFQDN`属性。这是您的 Kubernetes 主 DNS 名称。

或者，您可以采用使用`aks-engine deploy`命令的方法，该命令结合了自定义集群定义和生成并部署 ARM 模板为一条命令。请注意，为了使用容器监视功能，您现在必须使用`aks-engine deploy`命令。

现在，我们需要连接到我们的新集群。 AKS Engine 与 ARM 模板一起生成了一组`kubeconfigs`，用于所有可能的 Azure 位置，格式为`.\_output\<dnsPrefix>\kubeconfig\kubeconfig.<azureLocation>.json`。在我们的情况下，我们使用了位置`westeurope`，因此 kubeconfig 是`.\_output\<dnsPrefix>\kubeconfig\kubeconfig.westeurope.json`。要将此 kubeconfig 用于您的 kubectl，您可以使用第六章中提供的配置管理技术之一，*与 Kubernetes 集群交互*。例如，要将此文件与您现有的默认 kubeconfig 合并，请执行以下步骤：

1.  检查`.\_output\<dnsPrefix>\kubeconfig\kubeconfig.westeurope.json`的内容，以了解集群名称和上下文名称。两者应与您的`<dnsPrefix>`相同。

1.  执行文件与默认 kubeconfig 的测试合并。使用以下命令：

```
$env:KUBECONFIG=".\_output\<dnsPrefix>\kubeconfig\kubeconfig.westeurope.json;$env:USERPROFILE\.kube\config"
kubectl config view --raw
```

1.  仔细检查输出，以确定合并的配置是否包含您期望的所有集群和上下文。

1.  将合并后的文件保存为默认配置，并切换到使用新的`<dnsPrefix>`上下文：

```
$env:KUBECONFIG=".\_output\<dnsPrefix>\kubeconfig\kubeconfig.westeurope.json;$env:USERPROFILE\.kube\config"
kubectl config view --raw > $env:USERPROFILE\.kube\config_new 
Move-Item -Force $env:USERPROFILE\.kube\config_new $env:USERPROFILE\.kube\config

kubectl config use-context "<dnsPrefix>"
```

1.  测试与您的新集群的连接：

```
PS C:\src\temp> kubectl get nodes --all-namespaces
NAME                        STATUS   ROLES    AGE   VERSION
7001k8s000                  Ready    agent    16m   v1.16.1
7001k8s001                  Ready    agent    16m   v1.16.1
k8s-linuxpool1-70017404-0   Ready    agent    13m   v1.16.1
k8s-linuxpool1-70017404-1   Ready    agent    13m   v1.16.1
k8s-master-70017404-0       Ready    master   18m   v1.16.1
PS C:\src\temp> kubectl get pods --all-namespaces
NAMESPACE     NAME                                            READY   STATUS    RESTARTS   AGE
kube-system   azure-cni-networkmonitor-ftnqs                  1/1     Running   0          18m
kube-system   azure-ip-masq-agent-vqdhz                       1/1     Running   0          18m
...
```

请注意，由 AKS Engine 部署的集群根据在 ARM 模板中使用的资源计费。您应该使用 Azure 定价计算器来确定预计成本。如果您不再需要该集群，建议删除以避免任何不必要的费用。要删除 AKS Engine 集群，请使用以下命令：`az group delete --name aks-engine-windows-resource-group --yes --no-wait`。

恭喜！您已经使用 AKS Engine 在 Azure 上部署了一个功能齐全的混合 Windows/Linux 集群！让我们看看如何将一个简单的应用程序部署到集群，并与集群进行交互。

# 部署和检查您的第一个应用程序

在这一部分，我们将执行与上一章类似的练习 - 我们将部署一个示例的 ASP.NET Core 3.0 应用程序（使用部署对象）到我们的 AKS Engine 集群，并演示基本的 kubectl 操作。与在本地集群的工作许多方面保持一致 - 最大的区别是您可以轻松地利用 Azure 的功能和集成。为了演示这一点，我们将使用 LoadBalancer 类型的服务来暴露应用程序，而不是 NodePort。由于 Kubernetes 云提供程序为 Azure，LoadBalancer 服务将与 Azure 负载均衡器实例进行本地集成。

# 基本操作

要部署示例应用程序，请按照以下步骤进行：

1.  创建一个`windows-example.yaml`清单文件，其中包含一个部署和服务定义。您可以从 GitHub 存储库（[`raw.githubusercontent.com/PacktPublishing/Hands-On-Kubernetes-on-Windows/master/Chapter08/03_windows-example/windows-example.yaml`](https://raw.githubusercontent.com/PacktPublishing/Hands-On-Kubernetes-on-Windows/master/Chapter08/03_windows-example/windows-example.yaml)）下载它，或者直接将其应用到集群中：

```
apiVersion: apps/v1
kind: Deployment
metadata:
  name: windows-example
  labels:
    app: sample
spec:
  replicas: 3
  selector:
    matchLabels:
      app: windows-example
  template:
    metadata:
      name: windows-example
      labels:
        app: windows-example
    spec:
      nodeSelector:
 "beta.kubernetes.io/os": windows
      containers:
      - name: windows-example
        image: mcr.microsoft.com/dotnet/core/samples:aspnetapp-nanoserver-1809
        resources:
          limits:
            cpu: 1
            memory: 800M
          requests:
            cpu: .1
            memory: 300M
        ports:
          - containerPort: 80
---
apiVersion: v1
kind: Service
metadata:
  name: windows-example
spec:
  type: LoadBalancer
  ports:
  - protocol: TCP
    port: 80
  selector:
    app: windows-example
```

在这个清单文件中有三个重要的点，已经用粗体标记出来：

+   +   **为 Windows 节点调度**需要使用`nodeSelector`，其值为`"beta.kubernetes.io/os": windows`。同样，如果您需要为 Linux 节点调度 Pods，您应该在混合集群中使用`"beta.kubernetes.io/os": linux`节点选择器。这与本地集群完全相同。

+   Pod 定义包括一个基于`mcr.microsoft.com/dotnet/core/samples:aspnetapp-nanoserver-1809`镜像的容器。确保容器的主机操作系统版本与容器的基本镜像版本**兼容**非常重要-这个要求与本地集群中的要求相同。您可以使用 AKS Engine apimodel JSON 文件中的`properties.windowsProfile`中的自定义`windowsSku`属性来控制 AKS Engine 集群中的 Windows Server 版本。您可以在官方文档中阅读更多内容：[`github.com/Azure/aks-engine/blob/master/docs/topics/windows-and-kubernetes.md#choosing-the-windows-server-version`](https://github.com/Azure/aks-engine/blob/master/docs/topics/windows-and-kubernetes.md#choosing-the-windows-server-version)。对于现有集群，您可以使用`kubectl get nodes -o wide`命令检查节点的 Windows Server 版本。

+   服务规范的类型设置为`LoadBalancer`。这将导致为服务创建一个外部可访问的 Azure 负载均衡器。您可以在第五章中了解更多关于这种类型服务的信息，*Kubernetes Networking*。

1.  打开 PowerShell 窗口并使用`kubectl`应用清单文件。如果您还没有合并您的`kubeconfigs`，请记得首先设置正确的`$env:KUBECONFIG`变量，并切换到适当的 kubectl 上下文：

```
kubectl apply -f .\windows-example.yaml
```

1.  等待 Pod 启动-初始镜像拉取可能需要几分钟。您可以使用以下命令观察 Pod 的状态：

```
PS C:\src> kubectl get pods --watch 
NAME                               READY   STATUS    RESTARTS   AGE
windows-example-66cdf8c4bf-f5bd8   1/1     Running   0          101s
windows-example-66cdf8c4bf-g4v4s   1/1     Running   0          101s
windows-example-66cdf8c4bf-xkbpf   1/1     Running   0          101s
```

1.  等待服务的外部 IP 创建。您可以使用以下命令观察服务的状态：

```
PS C:\src> kubectl get services --watch
NAME              TYPE           CLUSTER-IP     EXTERNAL-IP      PORT(S)        AGE
kubernetes        ClusterIP      10.0.0.1       <none>           443/TCP        24m
windows-example   LoadBalancer   10.0.158.121   52.136.234.203   80:32478/TCP   3m55s
```

1.  打开您的互联网浏览器并导航到 Azure 负载均衡器地址-在这个例子中，它是`http://52.136.234.203/`。您应该看到示例应用程序的网页，这证实了部署成功：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/hsn-k8s-win/img/aa17aac0-0438-40da-9dc4-a7e93889c539.png)

执行常见操作，如访问 Pod 容器日志或在 Pod 容器内执行临时进程，与本地集群完全相同-我们将简要回顾如何做到这一点：

1.  为了访问作为部署的一部分创建的一个 Pod（`windows-example-66cdf8c4bf-f5bd8`）的日志，使用以下`kubectl logs`命令：

```
kubectl logs windows-example-66cdf8c4bf-f5bd8
```

1.  要**exec**到相同的 Pod 容器中，例如，启动一个交互式`cmd` shell 并运行`kubectl exec`命令：

```
kubectl exec -it windows-example-66cdf8c4bf-f5bd8 cmd
```

1.  您现在可以自由访问和修改容器，这在调试和测试场景中非常有用。例如，您可以获取`appsettings.json`文件的内容：

```
C:\app>type appsettings.json
{
 "Logging": {
 "LogLevel": {
 "Default": "Information",
 "Microsoft": "Warning",
 "Microsoft.Hosting.Lifetime": "Information"
 }
 },
 "AllowedHosts": "*"
}
```

接下来，让我们看看如何连接到在 AKS Engine 集群中使用的实际虚拟机。

# 连接到虚拟机

要连接到 Linux 主虚拟机，您可以使用 SSH 并直接连接到它，因为它暴露在公共网络中：

1.  在 PowerShell 窗口中，执行以下命令（您的公共 SSH 密钥将用于身份验证）：

```
ssh azureuser@<dnsPrefix>.westeurope.cloudapp.azure.com
```

1.  现在，您可以执行任何维护或调试操作，例如访问 kubelet 服务日志：

```
azureuser@k8s-master-70017404-0:~$ sudo journalctl -u kubelet -o cat
Stopped Kubelet.
Starting Kubelet...
net.ipv4.tcp_retries2 = 8
Bridge table: nat
Bridge chain: PREROUTING, entries: 0, policy: ACCEPT
Bridge chain: OUTPUT, entries: 0, policy: ACCEPT
Bridge chain: POSTROUTING, entries: 0, policy: ACCEPT
Chain PREROUTING (policy ACCEPT)
```

对于 Windows 节点（或其他 Linux 节点），该过程会更加复杂，因为 VM 位于私有 IP 范围内。这意味着您需要通过 Linux 主节点使用 SSH 本地端口转发来连接远程桌面连接或 SSH：

1.  首先，查询要连接的 Windows 节点的私有 IP 地址。您可以使用以下命令查看所有节点的名称：

```
az vm list --resource-group aks-engine-windows-resource-group -o table
```

1.  使用名称获取节点的私有 IP 地址，例如`7001k8s000`：

```
PS C:\src> az vm show -g aks-engine-windows-resource-group -n 7001k8s000 --show-details --query 'privateIps'
"10.240.0.4,10.240.0.5,10.240.0.6,10.240.0.7,10.240.0.8,10.240.0.9,10.240.0.10,10.240.0.11,10.240.0.12,10.240.0.13,10.240.0.14,10.240.0.15,10.240.0.16,10.240.0.17,10.240.0.18,10.240.0.19,10.240.0.20,10.240.0.21,10.240.0.22,10.240.0.23,10.240.0.24,10.240.0.25,10.240.0.26,10.240.0.27,10.240.0.28,10.240.0.29,10.240.0.30,10.240.0.31,10.240.0.32,10.240.0.33,10.240.0.34"
```

1.  使用其中一个私有 IP 来创建一个 SSH 隧道，从您的本地`5500`端口通过主节点到`3389`端口（RDP）连接到 Windows 节点：

```
ssh -L 5500:10.240.0.4:3389 azureuser@<dnsPrefix>.westeurope.cloudapp.azure.com
```

1.  在另一个 PowerShell 窗口中，通过隧道启动一个 RDP 会话：

```
mstsc /v:localhost:5500
```

1.  提供您的 Windows 节点凭据（如在 apimodel 中）并连接：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/hsn-k8s-win/img/31e251f6-97de-4d3e-a536-bc1ca8bd94bd.png)

1.  或者，您也可以从主节点使用 SSH：

```
ssh 10.240.0.4
```

现在，让我们看看如何为容器启用 Azure Log Analytics 和 Azure Monitor。

# 启用 Azure Log Analytics 和 Azure Monitor for containers

AKS Engine 集成了 Azure Log Analytics 和 Azure Monitor for containers，这是由运行在集群节点上的**运营管理套件**（**OMS**）代理提供的。在部署 Kubernetes 集群时，您可以在 Kubernetes 集群定义中指定一个额外的`container-monitoring`附加组件 - 请注意，目前，您必须在创建新集群时启用容器监控；您不能修改现有的集群定义。

此外，此功能仅在使用`aks-engine deploy`命令时才能使用。如果您想使用此功能，请执行以下步骤：

1.  如果您在`aks-engine-windows-resource-group`中有现有的集群，请先删除它。

1.  修改您的集群定义（apimodel），使`properties.orchestratorProfile.kubernetesConfig`属性具有以下内容。或者，您可以使用[`github.com/PacktPublishing/Hands-On-Kubernetes-on-Windows/tree/master/Chapter08/05_windows-apimodel-container-monitoring/kubernetes-windows.json`](https://github.com/PacktPublishing/Hands-On-Kubernetes-on-Windows/tree/master/Chapter08/05_windows-apimodel-container-monitoring/kubernetes-windows.json)作为基础：

```
{
    "addons": [{
            "name": "container-monitoring",
            "enabled": true
        }
    ]
}
```

1.  确保您的服务主体（在本例中为`appId: 7614823f-aca5-4a31-b2a5-56f30fa8bd8e`）还具有 Azure 订阅的`Log Analytics Contributor`角色：

```
az role assignment create `
 --assignee 7614823f-aca5-4a31-b2a5-56f30fa8bd8e `
 --role "Log Analytics Contributor" `
 --scope="/subscriptions/cc9a8166-829e-401e-a004-76d1e3733b8e"
```

1.  执行 AKS Engine 部署，使用服务主体`appId`作为`--client-id`，`password`作为`--client-secret`：

```
aks-engine deploy `
 --subscription-id cc9a8166-829e-401e-a004-76d1e3733b8e `
 --resource-group aks-engine-windows-resource-group `
 --location westeurope `
 --api-model .\kubernetes-windows.json `
 --client-id 7614823f-aca5-4a31-b2a5-56f30fa8bd8e `
 --client-secret 8737c1e6-b1b1-4c49-a195-f7ea0fe37613 `
 --force-overwrite
```

1.  几分钟后，您的集群将准备就绪，您可以将默认 kubeconfig 与 AKS Engine kubeconfig 合并。

这个`container-monitoring`附加组件将使两件事情成为可能：

1.  使用 Azure Log Analytics 来使用 Kusto 查询语言查询 Kubernetes 和您的应用程序日志（[`docs.microsoft.com/en-us/azure/azure-monitor/log-query/get-started-portal`](https://docs.microsoft.com/en-us/azure/azure-monitor/log-query/get-started-portal)）

1.  使用 Azure Monitor 服务来监视在您的集群中运行的容器（[`docs.microsoft.com/en-us/azure/azure-monitor/insights/container-insights-overview`](https://docs.microsoft.com/en-us/azure/azure-monitor/insights/container-insights-overview)）

请注意，在 AKS Engine 中的[`github.com/Azure/aks-engine/issues/2066`](https://github.com/Azure/aks-engine/issues/2066)问题得到解决之前，Kubernetes 1.16 将无法正确集成 Log Analytics 和 Monitor 服务。您可以尝试使用不同的 Kubernetes 版本在 apimodel 中重新部署您的集群。

这些服务为在 Kubernetes 上运行的容器化应用程序提供了监视、警报和调试的基本构建模块-您可以利用多个 Azure 门户 UI 功能来使分析和管理更加容易，例如：

1.  使用以下 URL 访问 Azure Monitor for containers：[`aka.ms/azmon-containers`](https://aka.ms/azmon-containers)。Azure Monitor 值得拥有一本单独的书籍来覆盖其所有功能-例如，您可以探索为监视您的 Kubernetes 集群提供的默认仪表板：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/hsn-k8s-win/img/9790777b-a47b-4e13-ac18-58f306bba459.png)

1.  使用以下 URL 访问 Azure 日志分析：[`portal.azure.com/#blade/Microsoft_Azure_Monitoring/AzureMonitoringBrowseBlade/logs`](https://portal.azure.com/#blade/Microsoft_Azure_Monitoring/AzureMonitoringBrowseBlade/logs)。展开 ContainerInsights 数据库，并选择，例如，KubeEvents 表。您现在可以执行一个简单的 Kusto 查询来检查表中的数据：

```
KubeEvents
| limit 50
```

以下屏幕截图显示了前面命令的输出：

![](https://github.com/OpenDocCN/freelearn-devops-pt2-zh/raw/master/docs/hsn-k8s-win/img/dc0209e5-b5a3-40ea-acdc-3a7884553108.png)

您可以在官方文档中了解有关容器监视的 Log Analytics 表的更多信息：[`docs.microsoft.com/en-us/azure/azure-monitor/insights/containers#monitor-containers`](https://docs.microsoft.com/en-us/azure/azure-monitor/insights/containers#monitor-containers)。有关 Kusto 查询语言的文档，请参阅[`docs.microsoft.com/en-us/azure/azure-monitor/log-query/query-language`](https://docs.microsoft.com/en-us/azure/azure-monitor/log-query/query-language)。建立适当的监视和日志分析解决方案对于运行分布式应用程序至关重要。如果您没有在 Azure 上使用集群，您可以考虑不同的解决方案，例如 Prometheus 和 Elasticsearch，它们提供类似的功能。

# 摘要

在本章中，您已经学会了如何使用 AKS Engine 在 Azure 上部署运行的混合 Windows/Linux Kubernetes 集群。目前，这种方法是运行具有 Windows 节点的自管理生产级集群的最合适解决方案。部署过程很简单-首先，在本地机器上安装所有先决条件和 AKS Engine，然后创建一个专用的 Azure 资源组和 Azure 活动目录服务主体。之后，您需要为 AKS Engine 定义一个 apimodel（集群定义）JSON 文件，以生成 Azure 资源管理器模板，并使用该模板部署集群。此外，您已经学会了如何部署一个示例 Windows 容器应用程序，以及如何使用 kubectl 执行基本操作。除此之外，我们还展示了如何连接到集群中的虚拟机进行调试和监视，并如何为您的集群启用 Azure Monitor 和 Azure 日志分析。

下一章将进一步关注将应用程序部署到 Kubernetes 集群以及如何在集群中执行“第二天”的操作。

# 问题

1.  AKS 和 AKS Engine 之间有什么区别？

1.  AKS Engine 的基本工作原理是什么？

1.  您能使用 AKS Engine 管理 AKS 集群，反之亦然吗？

1.  使用 AKS Engine 的先决条件是什么？

1.  AKS Engine 中的 apimodel 是什么？

1.  如何连接到 Kubernetes Linux 主节点？

1.  如何连接到 Kubernetes Windows 节点？

您可以在本书的*评估*中找到这些问题的答案。

# 进一步阅读

+   目前，关于使用 AKS Engine 部署混合 Windows/Linux 集群的大多数资源都可以在网上找到。请查看 GitHub 上的官方文档以获取更多详细信息：

+   [`github.com/Azure/aks-engine/blob/master/docs/topics/windows.md`](https://github.com/Azure/aks-engine/blob/master/docs/topics/windows.md)

+   [`github.com/Azure/aks-engine/blob/master/docs/topics/windows-and-kubernetes.md`](https://github.com/Azure/aks-engine/blob/master/docs/topics/windows-and-kubernetes.md)

+   一般来说，许多关于 AKS（托管的 Kubernetes Azure 提供的内容，而不是 AKS Engine 本身）的主题都很有用，因为它们涉及如何将 Kubernetes 与 Azure 生态系统集成。您可以在以下 Packt 书籍中找到有关 AKS 本身的更多信息：

+   *使用 Kubernetes 进行 DevOps-第二版* ([`www.packtpub.com/virtualization-and-cloud/devops-kubernetes-second-edition`](https://www.packtpub.com/virtualization-and-cloud/devops-kubernetes-second-edition))

+   如果您需要帮助解决问题和常见问题，可以使用以下指南：

+   [`github.com/Azure/aks-engine/blob/master/docs/howto/troubleshooting.md`](https://github.com/Azure/aks-engine/blob/master/docs/howto/troubleshooting.md)

+   [`docs.microsoft.com/en-us/virtualization/windowscontainers/kubernetes/common-problems`](https://docs.microsoft.com/en-us/virtualization/windowscontainers/kubernetes/common-problems)

+   [`kubernetes.io/docs/setup/production-environment/windows/intro-windows-in-kubernetes/#troubleshooting`](https://kubernetes.io/docs/setup/production-environment/windows/intro-windows-in-kubernetes/#troubleshooting)

+   [`techcommunity.microsoft.com/t5/Networking-Blog/Troubleshooting-Kubernetes-Networking-on-Windows-Part-1/ba-p/508648`](https://techcommunity.microsoft.com/t5/Networking-Blog/Troubleshooting-Kubernetes-Networking-on-Windows-Part-1/ba-p/508648) - 专门针对 Windows 容器网络问题的故障排除指南
