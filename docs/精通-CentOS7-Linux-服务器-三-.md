# 精通 CentOS7 Linux 服务器（三）

> 原文：[`zh.annas-archive.org/md5/9720AF936D0BA95B59108EAF3F9811A7`](https://zh.annas-archive.org/md5/9720AF936D0BA95B59108EAF3F9811A7)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第六章：虚拟化

如今，计算基础设施在许多方面发生了变化。我们不再看到一个房间里放满了服务器，每个服务器负责根据其强大程度提供多种服务。在这些时代，我们只看到一些由多个单元组成的大型服务器，以增强它们的容量。这种类型的服务器托管了几个虚拟服务器，以满足基础设施要求。

在我们的时代，成为裸机系统管理员已经不够了。虚拟机正在兴起；我们应该承认这一点。大公司不再使用旧的架构；这已经不再是一个好选择。需要大量资金和巨大的管理工作来维持它们。

在这一章中，我们将解释虚拟化的概念，我们将看到如何设置几种虚拟化技术，然后举例说明如何为每种技术创建一些虚拟机。最后，我们将简要解释 Docker 是什么，以及如何添加镜像和访问 Docker 容器。

通过本章，您将学习以下主题：

+   虚拟化基础

+   全虚拟化的概念

+   半虚拟化的概念

+   了解 Xen 以及如何使用它

+   使用 KVM 设置一些 Linux 虚拟机

+   使用 OpenVZ 创建虚拟机

+   在 VirtualBox 上设置和配置虚拟机

+   了解 Docker 以及如何创建容器和访问它

+   使用 HAProxy 建立服务的高可用性

# Linux 上的虚拟化基础

虚拟化是创建一个类似机器的程序的能力，模拟真实机器通过虚拟硬件运行，包括 CPU、RAM、硬盘、网络卡等，这些资源都来自运行虚拟机的物理机器。

早些时候，管理服务的方式是部署新服务器或升级旧服务器以满足新服务的要求，进行长时间复杂的迁移以应对硬件故障。一直以来，内存太少，磁盘太少，或者处理能力不足。管理者们厌倦了试图修复现有系统，同时支付大量资金来帮助维护不再受支持的旧服务器。然而，他们没有太多选择，因为运行在这些机器上的服务非常重要和必不可少。公司部署了无法在其高峰容量上运行的服务器，没有更好的方法来控制每台服务器的容量，以满足正确的硬件设备的正确服务。所有这些原因使得虚拟化这一新生解决方案迅速增长。虚拟化部署后不久，就已经在许多领域，特别是在计算机科学领域得到了整合。虚拟化允许对物理硬件进行抽象，以在单个共享资源（CPU、内存、网络和存储）上运行多个虚拟机：

![Linux 上的虚拟化基础](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/ms-centos7-linux-svr/img/B04674_06_01.jpg)

来源：[`cdn.arstechnica.net`](http://cdn.arstechnica.net)

现在，这种新技术正在蓬勃发展。我们每天都在见证新的虚拟化服务诞生。虚拟化已经分为许多类型：

+   我们有网络虚拟化，它涉及虚拟网络的创建和管理，以将一组机器与另一组机器分开。它们连接到同一个交换机和一组交换机。

+   我们还有应用虚拟化，其中我们将一个应用程序或一组应用程序放入容器中，然后让应用程序相信它是在其原始支持的系统上运行。因此，它相信它可以访问所需的资源。

+   最后，我们有完整的机器虚拟化。这是一种虚拟化，它创建一个完整的虚拟机（桌面、服务器），具有其虚拟硬件和按需的专用服务。这种虚拟化涉及将基于服务器的工作负载（虚拟机用户要求的工作负载）与底层硬件分离。只要硬件满足其服务对资源（存储数据、网络访问其他机器等）的需求，虚拟机就不会注意到它是在物理硬件上还是在虚拟硬件上运行。

在本章中，我们将重点关注应用虚拟化和桌面虚拟化。

一种名为 hypervisor 的软件在物理机器上执行，以帮助数据中心的虚拟化，目标是为虚拟机提供平台。 Hypervisor 的主要工作是在其控制下运行的不同虚拟机之间动态组织物理资源。这使它们能够独立于物理机器运行，系统管理员可以将虚拟机从一个主机重新定位到另一个主机而不会影响它。 Hypervisor，也称为虚拟机管理器，是一种允许多个操作系统共享单个硬件主机的程序。

在使用虚拟机或容器时，我们期望提供可以托管应用程序或服务并简化其与硬件通信的操作系统。由于这些机器实际上并未在物理硬件上运行，虚拟化允许它们根据需要动态和灵活地访问 CPU、内存、存储和网络资源。

虚拟化可以增加灵活性和管理，并提供更好的可扩展性，大大节省成本。服务的工作负载部署速度更快，性能按需可见增加，同时自动化可扩展性功能，简化了 IT 支持人员的基础设施管理。

让我们列举一些在服务器基础设施上安装虚拟化解决方案的主要优势：

+   减少硬件和运营成本

+   提供高可用性的应用程序和服务

+   最小化或消除停机时间（采用最佳实践方法）

+   提高 IT 团队的生产力、效率、灵活性和响应能力

+   加快应用和资源配置的速度和简化

+   支持业务连续性和灾难恢复，增加系统安全性

+   实现集中管理

+   构建真正的软件定义数据中心

+   充分利用多核处理器机器的优势

下图显示了在一个 Linux 服务器上运行的三个 Linux 虚拟机的示例。这些机器由根据所选择的虚拟化类型控制和管理：

利用 Linux 上虚拟化的基础知识

虚拟机实际上只是主机机器上特定位置存储的一些文件。对于某些技术，它也可以是 LVM 逻辑卷或直接设备。虚拟机使用的虚拟磁盘只是其中封装的另一个文件。在虚拟机内部，管理操作系统和应用程序可以简化（在某些方面；在其他方面则很复杂）。

但好处在于，将虚拟机作为一个充满文件的文件夹，可以复制和移动，这样在物理机器发生硬件故障时更容易备份。在这种情况下，管理者只需购买一台新服务器，将备份的虚拟机加载到其中，并再次运行整个环境，就好像从未发生过一样。

使用 CentOS 存储库，我们可以在**Xen**和**KVM**之间选择两种虚拟化技术。要了解这些虚拟化技术，您需要了解虚拟化的两种不同方法：完全虚拟化和半虚拟化。

### 注意

已经创建了半虚拟化和完全虚拟化的组合，称为**混合虚拟化**。在其中，客户操作系统的某些部分使用半虚拟化来进行某些硬件驱动程序，而主机使用完全虚拟化来进行其他功能。这通常会在客户机上产生更好的性能，而无需客户机完全进行半虚拟化。

# 完全虚拟化

完全虚拟化是一种完全模拟虚拟机下的虚拟硬件的虚拟化技术，与物理硬件没有任何交互。它要求虚拟机下的整个硬件变得不可察觉。这项技术可以根据系统在虚拟机上运行的需求模拟任何类型的物理硬件，以满足特定裸机硬件的任何服务或应用需求。换句话说，完全虚拟化是一种完全运行客户机而不让其意识到它在虚拟环境中运行的虚拟化能力。在这种情况下，虚拟机具有完全虚拟化的硬件来运行其服务。它们与物理硬件没有任何交互。

以下图表显示了在完全虚拟化期间，底层平台运行客户操作系统而不被修改或知道它正在虚拟化上运行：

![完全虚拟化](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/ms-centos7-linux-svr/img/B04674_06_03.jpg)

有一种特定类型的完全虚拟化称为硬件辅助虚拟化。在这种情况下，CPU 架构通过一些特殊指令帮助执行硬件虚拟化，这些指令可能允许客户机直接在 CPU 上执行特权指令，尽管它是虚拟化的。

使用 CentOS 7 服务器，我们可以使用 Xen 或 KVM 进行完全虚拟化或硬件辅助完全虚拟化。我们将在*为 CentOS 7 设置 Xen*部分中看到如何做到这一点。

在更大的范围内，可以实现完全虚拟化的解决方案包括 VMware 的一系列 hypervisors、Xen 和 XenServer、VirtualBox、QEMU 和 KVM。

# 半虚拟化

半虚拟化是虚拟化技术的一种新型增强。它具有在为虚拟机提供服务的垂直机器上安装客户操作系统之前重新编译的能力，以区分虚拟和物理硬件。通过使用这种虚拟化，我们可以通过保留计算资源来更好地优化系统性能。这是因为我们不需要为虚拟机专门分配资源，只有在需要时才会使用。与需要创建虚拟资源并将其分配给虚拟机的完全虚拟化不同，它只是被使用或不被使用。

在半虚拟化中，客户操作系统由 hypervisor 管理，作为位于物理机器和虚拟机之间的一层，以有效地启用和共享物理设备访问。虽然通常不需要完全设备仿真或动态重新编译来执行特权指令，但半虚拟化通常以接近本机速度运行。

![半虚拟化](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/ms-centos7-linux-svr/img/B04674_06_04.jpg)

前述架构显示了半虚拟化虚拟机如何通过直接与修改器 OS 通信的特殊 hypervisor 与物理硬件交互以优化通信。

Paravirtualization 是 IBM 发明的一种技术的扩展。Xen 是一个开源软件项目，它包含了 paravirtualization。Xen hypervisor 是带来术语*paravirtualization*的东西。今天，大多数虚拟化解决方案都支持 paravirtualization 作为一种规范。一些 Linux 开发供应商合作开发了一种新形式的 paravirtualization，最初由 Xen 小组开发，并为 hypervisor 和客户操作系统内核之间提供了一个与 hypervisor 无关的接口。

# 在 CentOS 7 上设置 Xen

Xen 是一个开源解决方案，用于在一台机器上运行多个虚拟系统。它支持 paravirtualization 和硬件辅助的全虚拟化。Xen 是一个非常强大的虚拟化解决方案。它提供了同时使用两种虚拟化技术以始终满足用户需求的能力。

为了使用 Xen 创建我们的虚拟化环境，我们需要确保 Xen Hypervisor 将在机器自己的内核之前启动，以便尽可能多地访问物理硬件，因此可以用来为我们的环境的虚拟机提供服务。

![在 CentOS 7 上设置 Xen](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/ms-centos7-linux-svr/img/B04674_06_05.jpg)

来源：[`www.2virt.com`](http://www.2virt.com)

在本节中，我们将为 CentOS 7 设置 Xen4。默认的 CentOS 7 仓库不支持 Xen4，因此我们需要添加 CentOS Xen 仓库。但首先，我们需要确保安装了一些软件包。这些将在安装 Xen 时稍后需要：

```
$ sudo yum install bridge-utils SDL net-tools

```

然后，我们使用 YUM 添加最新的 Xen 仓库：

```
$ sudo yum install centos-release-xen

```

在本教程中，我们将安装 Xen 4.5 版本，因此我们需要运行安装命令如下：

```
$ sudo yum install xen

```

要验证安装是否完成，我们需要列出 Xen 内核存档，它位于`/boot`文件夹中：

```
$ ls –l /boot/xen.gz

```

我们应该看到以下代码：

```
lrwxrwxrwx. 1 root root       12 Aug 23 02:10 /boot/xen.gz -> xen-4.5.1.gz

```

现在，我们继续安装`kernel-xen`软件包。此安装应该单独执行，安装 Xen 之后，以便系统引导加载程序 grub 可以检测到新内核并正确配置：

```
$ sudo yum install kernel-xen

```

安装了新内核后，我们应该解决 SELinux 问题。我们可以尝试通过确定 SELinux 正在阻止哪些模块并解决问题来解决问题，或者如果我们有更好的方法来保护我们的服务器，我们可以直接禁用它。要禁用 SELinux，我们只需要进入其配置文件并禁用它：

```
$ sudo nano /etc/sysconfig/selinux

```

然后，考虑这一行：

```
SELINUX=enforcing

```

将其更改为以下内容：

```
SELINUX=disabled

```

否则，如果我们需要检查问题，我们可以按照这个步骤。首先，我们检查问题的日志文件：

```
$ sudo cat /var/log/messages

```

然后，我们激活阻塞：

```
$ sudo grep xend /var/log/audit/audit.log | audit2allow -M custom_xen
$ sudo semodule -i custom_xen.pp

```

这应该解决问题。最后，我们可以重新启动系统并引导新的 Xen 内核。重新启动后，我们需要检查 Xen 内核是否正确安装：

```
$ sudo xl info

```

要使用 Xen，我们需要安装一些工具和软件包，以确保虚拟机运行良好。首先，我们需要确保安装了基本的使用软件包：

```
$ sudo yum install bridge-utils tunctl wget vim-enhanced rsync openssh-clients libvirt python-virtinst libvirt-daemon-xen 

```

然后，我们需要配置网络。但在此之前，我们必须创建桥接接口：

```
$ sudo nano /etc/sysconfig/network-scripts/ifcfg-brid0

```

接下来，我们在刚刚使用 nano 打开的文件中添加以下行并保存：

```
DEVICE=brid0
TYPE=Bridge
BOOTPROTO=dhcp
ONBOOT=yes

```

然后，我们对默认网络接口配置文件进行微小更改，以使用桥接接口：

```
$ sudo nano /etc/sysconfig/network-scripts/ifcfg-eth0
DEVICE=eth0
HWADDR=XX:XX:XX:XX:XX:XX
ONBOOT=yes
TYPE=Ethernet
IPV6INIT=no
USERCTL=no
BRIDGE=brid0

```

### 注意

我们需要用以太网接口的 MAC 地址更改 MAC 地址。我们可以使用`ifconfig`来检查。

之后，我们重新启动系统。这样，桥接网络就准备好使用了。然后，我们下载任何 Linux 系统进行测试。接下来，我们需要使用`dd`命令将其制作为 IMG 文件：

```
$ sudo dd if=/dev/zero of=Centos.img bs=4K count=0 seek=1024K
qemu-img create -f raw Centos.img 8G

```

然后，我们下载任何 Linux 系统进行测试。此外，我们必须创建一个 kick-start 文件并将其放在相同的位置：

```
$ sudo nano ks.cfg

```

然后，我们添加以下代码并进行必要的修改：

```
kernel = "/boot/vmlinuz-xen-install"
ramdisk = "/boot/initrd-xen-install"
extra = "text"
name = "mailserver"
memory = "256"
disk = [ 'tap:aio:/srv/xen/mailserver.img,xvda,w', ]
vif = [ 'bridge=brid0', ]
vcpus=1
on_reboot = 'destroy'
on_crash = 'destroy'

```

最后，我们使用`virt-install`来创建虚拟机：

```
$ sudo virt-install -d -n CentOS7VM1 -r 1024 --vcpus=2 \
--bridge=brid0 --disk ./Centos.img \
--nographics -p -l "./Centos" \
--extra-args="text console=com1 utf8 console=hvc0 ks=./ks.cfg"

```

现在虚拟机应该启动并能够从 DHCP 服务器获取 IP；因此我们可以继续调整它并添加所需的服务。

对于 Xen 的使用，我们需要使用以下命令（我们将介绍最常见的命令。更多信息，请访问此链接[`www.centos.org/docs/5/html/Virtualization-en-US/virt-task-xm-create-manage-doms.html`](https://www.centos.org/docs/5/html/Virtualization-en-US/virt-task-xm-create-manage-doms.html)）：

+   连接到虚拟机：

```
$ sudo xm console CentOS7VM1

```

+   关闭或重启一个机器：

```
$ sudo xm shutdown CentOS7VM1
$ sudo xm reboot CentOS7VM1

```

+   要删除（终止）一个机器：

```
$ sudo xm destroy CentOS7VM1

```

+   暂停和恢复一个机器：

```
$ sudo xm suspend CentOS7VM1
$ sudo xm resume CentOS7VM1

```

+   重命名一个机器

```
$ sudo xm rename CentOS7VM1 CentOS7VM2

```

+   暂停，然后取消暂停一个机器：

```
$ sudo xm pause CentOS7VM1
$ sudo xm unpause CentOS7VM1

```

# 在 CentOS 7 上设置 KVM 进行完全虚拟化

KVM 只能支持硬件辅助的完全虚拟化。目前还在支持半虚拟化方面进行工作。KVM 是一个内核模块，只能与默认的 Linux 内核一起使用（不应该安装在 Xen 上）。KVM 使用一个名为**Qemu-kvm**的个性化版本的 Qemu 来创建虚拟机。

![在 CentOS 7 上设置 KVM 进行完全虚拟化](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/ms-centos7-linux-svr/img/B04674_06_06.jpg)

来源：[`www.virtualopensystems.com`](http://www.virtualopensystems.com)

KVM 具有许多有用的功能和优势，由其 hypervisor 支持：

+   **薄配置**：这是分配灵活存储空间和管理虚拟机可用空间的能力

+   过度承诺：这是分配更多的 CPU 和内存资源的能力，超过了物理机上可用的资源

+   **自动 NUMA 平衡**：这是对在 NUMA 硬件上运行的应用程序的改进

+   **磁盘 I/O 限制**：这是管理虚拟机发送的物理系统磁盘输入和输出请求的限制的能力

+   **虚拟 CPU 热添加功能**：这是在没有任何停机时间的情况下调整虚拟机的处理能力的能力

在开始 KVM 安装之前，我们需要检查一些预安装步骤。首先，我们检查机器的 CPU 是否能够处理虚拟化技术：

```
$ sudo grep -e '(vmx|svm)' /proc/cpuinfo

```

要知道是否正确，我们需要查看命令输出中是否突出显示了`vmx`或`svm`字样：

然后，我们确保系统软件包都已更新：

```
$ sudo yum update

```

接下来，我们将 SELinux 的工作模式更改为宽松模式，以确保它不会干扰 KVM 的执行：

```
$ sudo nano /etc/sysconfig/selinux

```

然后，考虑这一行：

```
SELINUX=enforcing

```

将其更改为以下内容：

```
SELINUX=permissive

```

现在我们可以开始安装了。首先，我们将安装`Qemu`软件包，以提供 KVM 的用户级和其磁盘映像管理器：

```
$ sudo yum install qemu-img qemu-kvm 

```

然后，我们需要安装虚拟机管理的 GUI，命令行工具来管理虚拟环境，帮助从 CLI 创建虚拟机的工具，以及 hypervisor 库：

```
$ sudo yum install virt-manager libvirt libvirt-python libvirt-client xauth dejavu-lgc-sans-fonts

```

最后，对于 CentOS 7，我们添加了虚拟化客户端、虚拟化平台和虚拟化工具：

```
$ sudo yum groupinstall virtualization-client virtualization-tools virtualization-platform 

```

完成了这一步，我们可以说我们已经安装了所需的工具和软件包。现在，我们进入配置部分。首先，我们需要重新启动虚拟化守护程序，以确保整个配置设置正确：

```
$ sudo systemctl restart libvirtd

```

然后，我们检查它是否运行良好：

```
$ sudo systemctl status libvirtd

```

我们应该看到这个输出：

![在 CentOS 7 上设置 KVM 进行完全虚拟化](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/ms-centos7-linux-svr/img/B04674_06_07.jpg)

现在，我们继续进行网络配置。我们需要创建一个桥接口，以允许客户系统访问外部网络。为此，我们必须启用 IP 转发：

```
$ sudo echo "net.ipv4.ip_forward = 1"|sudo tee /etc/sysctl.d/99-ipforward.conf

```

然后，我们检查它是否设置正确：

```
$ sudo sysctl -p /etc/sysctl.d/99-ipforward.conf

```

之后，我们需要通过保持原始接口不变来更改网络配置，但是我们将把其 IP 地址分配给桥接口：

```
$ sudo nano /etc/sysconfig/network-scripts/ifcfg-eth0

```

接下来，我们在文件末尾添加以下行并保存：

```
BRIDGE=virbrid0

```

然后，我们创建桥接口配置文件：

```
$ sudo nano /etc/sysconfig/network-scripts/ifcfg-brid0

```

之后，我们将以下代码放入我们刚刚打开进行编辑的文件中，并保存：

```
DEVICE="brid0"
TYPE=BRIDGE
ONBOOT=yes
BOOTPROTO=static
IPADDR="10.0.0.2"
NETMASK="255.255.255.0"
GATEWAY="10.0.0.1"
DNS1="8.8.8.8"

```

重新启动系统后，我们可以说网络配置已经设置好了。

在完成 KVM 安装和配置后，是时候开始使用主机了。我们需要做的第一件事是创建一个新的域或虚拟机。为此，使用 CLI，我们将使用`virt-install`命令。首先，我们需要查看已知于我们的 KVM 安装的模板列表：

```
$ sudo virt-install --os-variant=list

```

我们需要一个 Linux OS 的 ISO 文件来用于安装。然后，我们可以开始设置新的虚拟机：

```
$ sudo virt-install  --name=CentOS7guest  --ram=1024  --vcpus=2  --cdrom=./CentOS-7.1-x86_64-minimal.iso --os-type=linux --os-variant=rhel7  --network bridge=brid0 --graphics=spice  --disk path=/var/lib/libvirt/images/CentOS7.dsk,size=10

```

前述命令中的选项如下：

+   `name`：这是虚拟机的名称

+   `ram`：这是内存大小（以 MB 为单位）

+   `vcpus`：这是虚拟 CPU 的数量

+   `cdrom`：这是 ISO 镜像的位置

+   `os-type`：这是操作系统类型，如 Linux、Windows 或 Unix

+   `os-variant`：这是 OS 变体，如 rhel 6 或 Solaris

+   `network`：这是网络接口和连接

+   `graphics`：这是客户端显示设置

+   `disk path`：这是具有 10GB 大小的磁盘的位置

一旦我们发出了前述命令，`virt-install`将创建一个虚拟机，并启动 OS 安装的`virt`查看器控制台。

### 注意

总是有一个图形模式执行前面的处理。图形工具称为系统工具中的 virt-manager。

以下命令旨在更好地管理部署后的 KVM 虚拟机：

+   列出在 KVM 上运行的虚拟机：

```
$ sudo virsh --connect qemu:///system list

```

+   要获取有关虚拟机的更多信息：

```
$ sudo virsh dominfo CentOS7guest

```

+   停止运行的客户机：

```
$ sudo virsh --connect qemu:///system shutdown CentOS7guest

```

+   启动虚拟机：

```
$ sudo virsh --connect qemu:///system start CentOS7guest

```

+   要删除客户机：

```
$ sudo virsh --connect qemu:///system destroy CentOS7guest
$ sudo virsh --connect qemu:///system undefineCentOS7guest
$ sudo rm -f /var/lib/libvirt/images/CentOS7guest.img

```

+   最后，用于在主机系统启动时自动启动虚拟机的代码：

```
$ sudo virsh --connect qemu:///system autostart CentOS7guest
$ sudo virsh --connect qemu:///system dominfo CentOS7guest | grep Auto

```

![在 CentOS 7 上设置 KVM 进行完全虚拟化](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/ms-centos7-linux-svr/img/B04674_06_08.jpg)

来源：[`virt-manager.org/`](https://virt-manager.org/)

# 在 CentOS 7 上设置 OpenVZ 虚拟化

OpenVZ 是一种我们称之为基于容器的新型虚拟化技术。它基本上在单个 Linux 服务器上创建多个安全和隔离的 Linux 容器。这种容器技术允许更好地利用服务器，因为我们不是安装完整的虚拟机，只是一个容器来容纳其中的一些内容，并且它消除了应用程序冲突。在 OpenVZ 平台上运行的虚拟机处于独立模式，它具有在不与同一平台上运行的任何其他虚拟机发生任何冲突的能力。这些机器彼此独立。

在 OpenVZ 上运行的虚拟机有自己的操作系统、IP 地址、进程、内存或存储空间、应用程序和配置文件等。

![在 CentOS 7 上设置 OpenVZ 虚拟化](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/ms-centos7-linux-svr/img/B04674_06_09.jpg)

来源：[`www.quantact.com`](http://www.quantact.com)

在使用 OpenVZ 时，虚拟化是通过系统级虚拟化技术运行的，其中客户系统使用与物理机系统相同的内核，不同于 KVM 和 VirtualBox，这有助于提高物理机处理能力和存储能力的使用效率。

为了更好地使用 OpenVZ，我们可能需要使用 QEMU 和 Virtuozzo 作为管理实用程序。我们真的建议在 Virtuozzo 镜像的 OpenVZ 容器和虚拟机上使用。

对于 CentOS 7，目前还没有可用的 OpenVZ 发行版。因此，我们将安装其分支项目 Virtuozzo 7，它能够实现所有 OpenVZ 选项以及更多功能。然而，我们将仅使用 OpenVZ 工具。

要安装 Virtuozzo 7，我们需要安装基于 RPM 的发行包。首先，我们需要将`virtuozzo-release`包的元信息引入 YUM 存储库：

```
$ sudo yum localinstall http://download.openvz.org/virtuozzo/releases/7.0/x86_64/os/Packages/v/virtuozzo-release-7.0.0-10.vz7.x86_64.rpm

```

然后，我们安装必需的 Virtuozzo RPM 包：

```
$ sudo yum install -y prlctl prl-disp-service vzkernel

```

现在，我们已经安装了 OpenVZ 内核。我们继续进行内核参数配置：

```
$ sudo nano /etc/sysctl.conf

```

然后，我们添加以下代码：

```
# On Hardware Node we generally need
# packet forwarding enabled and proxy arp disabled
net.ipv4.ip_forward = 1
net.ipv6.conf.default.forwarding = 1
net.ipv6.conf.all.forwarding = 1
net.ipv4.conf.default.proxy_arp = 0

# Enables source route verification
net.ipv4.conf.all.rp_filter = 1

# Enables the magic-sysrq key
kernel.sysrq = 1

# We do not want all our interfaces to send redirects
net.ipv4.conf.default.send_redirects = 1
net.ipv4.conf.all.send_redirects = 0

```

之后，我们使 SELinux 处于宽松模式，以确保 OpenVZ 正常工作：

```
$ sudo nano /etc/sysconfig/selinux

```

接下来，我们需要有配置行，使其看起来像下面这样：

```
SELINUX=permissive

```

这部分是可选的。如果需要，我们可以安装 OpenVZ 使用统计工具：

```
$ sudo yum install vzctl vzquota ploop

```

现在，我们已经成功安装了 OpenVZ，我们可以重新启动系统并通过 OpenVZ 内核登录。我们需要编辑 OpenVZ 配置文件，为物理和虚拟机设置相同的子网：

```
$ sudo nano /etc/vz/vz.conf

```

然后，我们找到并取消注释以下行，并将其选项更改为这样：

```
NEIGHBOUR_DEVS=all

```

现在，我们可以为 OpenVZ 设置一个基于 Web 的界面来帮助管理它。我们需要下载安装脚本并运行它：

```
$ sudo wget -O - http://ovz-web-panel.googlecode.com/svn/installer/ai.sh | sh

```

然后，使用 Firewalld 添加从中提供 Web 界面的端口：

```
$ sudo firewall-cmd --zone=public --permanent --add-port=3000/tcp

```

然后，重新加载 Firewalld：

```
$ sudo firewall-cmd --reload

```

基于 Web 的界面将在机器主机名或 IP 地址后跟端口号`3000`上提供其 Web 界面：

```
http://<the-hostname>:3000

```

现在，我们将开始使用 OpenVZ 来下载一个容器并开始使用它。首先，我们需要指定一个文件夹来放置我们的容器：

```
$ mkdir OpenVZCont
$ cd OpenVZCont

```

然后，我们下载一个示例容器：

```
$ wget http://download.openvz.org/template/precreated/centos-7-x86_64-minimal.tar.gz

```

接下来，我们解压`tar`文件：

```
$ tar –xzvf centos-7-x86_64-minimal.tar.gz

```

然后，我们输入此命令来创建我们的第一个虚拟机：

```
$ sudo vzctl create 101 --ostemplate centos-7-x86_64-minimal

```

我们的容器 ID 是`101`，因为它们通常从`100`开始。现在，我们为容器设置一个 IP 地址：

```
$ sudo vzctl set 101 --ipadd 10.0.0.14 --save

```

然后是 DNS 服务器：

```
$ sudo vzctl set 101 --nameserver 8.8.8.8 --save

```

在网络配置准备就绪后，我们可以启动我们新创建的容器：

```
$ sudo vzctl start 101

```

我们可以通过 ping 其 IP 地址来验证它是否正在运行：

```
$ ping 10.0.0.14

```

现在，我们可以登录到我们的容器中进行探索：

```
$ sudo vzctl enter 101

```

我们现在在新创建的容器中。我们可以随心所欲地使用它。要退出虚拟机，我们只需在终端中输入 exit。此外，使用 OpenVZ Web 界面，我们可以可视化其状态并通过它进行一些管理管理。

![在 CentOS 7 上设置 OpenVZ 虚拟化](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/ms-centos7-linux-svr/img/B04674_06_10.jpg)

来源：[`bderzhavets.wordpress.com/`](https://bderzhavets.wordpress.com/)

# 在 CentOS 7 上设置 VirtualBox 虚拟化

Oracle VirtualBox 是一个虚拟化应用程序，可以在多个计算机架构（Intel、基于 AMD 的系统）和几乎所有可用的操作系统（OSX、Linux、Windows、Solaris 等）上运行，它允许用户在同一台物理机器上运行多个操作系统。基本上，虚拟盒是一种完全虚拟化技术。

大多数人在使用多个系统时都依赖它，并且需要导出和导入模板虚拟机，虚拟盒提供了各种选项，可以在各种基础设施之间交换虚拟机。

![在 CentOS 7 上设置 VirtualBox 虚拟化](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/ms-centos7-linux-svr/img/B04674_06_11.jpg)

来源：[`www.oracle.com`](http://www.oracle.com)

本节将向您展示如何在 CentOS 7 上安装 Oracle VirtualBox 5.0.2。首先，我们需要将 VirtualBox yum 存储库添加到我们的系统中。因此，我们需要在 YUM 存储库目录中创建其 repo 文件：

```
$ sudo nano /etc/yum.repos.d/virtualbox.repo

```

然后，我们需要将以下代码放入文件并保存：

```
[virtualbox]
name=Oracle Linux / RHEL / CentOS-$releasever / $basearch - VirtualBox
baseurl=http://download.virtualbox.org/virtualbox/rpm/el/$releasever/$basearch
enabled=1
gpgcheck=1
gpgkey=http://download.virtualbox.org/virtualbox/debian/oracle_vbox.asc

```

我们还应该安装 EPEL 存储库：

```
$ sudo rpm -ivh http://ftp.jaist.ac.jp/pub/Linux/Fedora/epel/7/x86_64/e/epel-release-7-5.noarch.rpm

```

在开始安装之前，我们需要安装一些必要的软件包，以确保 VirtualBox 正常工作：

```
$ sudo yum install gcc make kernel-headers kernel-devel fontforge binutils patch  dkms glibc-headers glibc-devel qt libgomp

```

然后，我们设置一个名为`KERN_DIR`的环境变量，VirtualBox 将从中获取内核源代码：

```
$ export KERN_DIR=/usr/src/kernels/3.10.0-229.14.1.el7.x86_64

```

### 提示

我的最新内核版本存储在这个目录中：`3.10.0-229.14.1.el7.x86_64`。由于升级，它可能会随时间而改变。

然后，我们可以使用 YUM 开始安装 VirtualBox：

```
$ sudo yum install VirtualBox-5.0

```

安装完成后，我们需要使用以下命令重建内核模块：

```
$ sudo systemctl start vboxdrv

```

现在，我们已经安装了 VirtualBox 并准备好使用。不过，VirtualBox 只支持图形界面，所以我们需要安装一个图形界面，然后我们可以启动并使用它。

我们需要在服务器上安装一个图形界面，我们有一个很长的列表可供选择。我建议使用 Gnome，因为它是最常用的界面之一，用户友好且资源消耗低。

使用 Gnome 作为图形界面，我们可以启动 VirtualBox：

```
$ sudo virtualbox &

```

![在 CentOS 7 上设置 VirtualBox 虚拟化](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/ms-centos7-linux-svr/img/B04674_06_12.jpg)

然后，我们可以继续创建一个新的虚拟机。我们给它一个名称和类型，如下所示：

![在 CentOS 7 上设置 VirtualBox 虚拟化](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/ms-centos7-linux-svr/img/B04674_06_13.jpg)

接下来，我们继续配置要分配的 RAM 数量，如下截图所示：

![在 CentOS 7 上设置 VirtualBox 虚拟化](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/ms-centos7-linux-svr/img/B04674_06_14.jpg)

然后是磁盘空间的数量，如下所示：

![在 CentOS 7 上设置 VirtualBox 虚拟化](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/ms-centos7-linux-svr/img/B04674_06_15.jpg)

VirtualBox 提供了一些额外的服务，允许原始系统的鼠标和键盘在物理机和虚拟机之间切换。要安装这些工具，我们可以转到 VM 菜单，然后选择**Guest**选项，然后安装虚拟机客户端工具。安装需要一些时间，然后我们需要重新启动虚拟机，以便这些工具可以开始工作。

最后，我们的虚拟机已准备好执行，如下截图所示：

![在 CentOS 7 上设置 VirtualBox 虚拟化](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/ms-centos7-linux-svr/img/B04674_06_16.jpg)

# 在 CentOS 7 上设置 Docker

与 OpenVZ 使用容器技术相同的技术，Docker 是基于容器的软件虚拟化的另一种选择。Docker 因其自动部署应用程序的能力而闻名。这些模板或容器分为社区容器（由 Docker 社区提供的模板）和个人用户提供的私有容器。一些用户个性化的容器可以公开使用，其他的可以存储在可以被其创建者或他想要分享的人访问的私人文件夹中。Docker 容器是可移植的、轻量级的、封装的应用程序模块。

根据行业分析公司 451 Research 的说法：

> *"Docker 是一个工具，可以将应用程序及其依赖项打包到一个虚拟容器中，在任何 Linux 服务器上都可以运行。这有助于实现应用程序可以运行的灵活性和可移植性，无论是在本地、公共云、私有云、裸机等。"*

要安装 Docker，我们将使用 Docker 安装脚本。在这里，我们还有另一种通过 YUM 安装 Docker 的方式——传统方式：

1.  首先，我们需要确保我们的系统软件包已更新：

```
$ sudo yum update

```

1.  然后，我们运行 Docker 安装脚本：

```
$ sudo curl -sSL https://get.docker.com/ | sh

```

![在 CentOS 7 上设置 Docker](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/ms-centos7-linux-svr/img/B04674_06_17.jpg)

来源：[`blog.ouseful.info/`](http://blog.ouseful.info/)

1.  此脚本将把 Docker 存储库添加到系统存储库，然后安装 Docker。

1.  如果我们系统中要使用 Docker 的用户太多，我们需要将他们添加到 Docker 组中：

```
$ sudo usermod -aG docker packt

```

1.  然后，我们启动 Docker 守护程序。将其添加到系统启动脚本中：

```
$ sudo systemctl docker start
$ sudo systemctl enable docker.service

```

1.  要验证 Docker 是否正确安装，我们有一个简单的镜像容器可以测试：

```
$ sudo docker run hello-world

```

1.  要下载一个 Docker 容器，我们需要查找它的名称，然后输入以下命令：

```
$ sudo docker pull centos7

```

1.  要运行容器，我们需要使用`docker run`命令，使用`-i`选项将`stdin`和`stdout`附加到容器，使用`-t`选项分配一个`tty`接口。

```
$ sudo docker run -i -t centos7 /bin/bash

```

1.  要使 Docker 容器保持不丢失 shell 终端，我们需要按照以下顺序操作：同时按下`Ctrl-p`和`Ctrl-q`。

1.  要获取更多公开可用的 Web 社区容器，我们可以始终使用以下命令：

```
$ sudo docker search centos7

```

![在 CentOS 7 上设置 Docker](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/ms-centos7-linux-svr/img/B04674_06_18.jpg)

来源：[`blog.ouseful.info/`](http://blog.ouseful.info/)

# 使用 HAProxy 建立服务的高可用性

对于这一部分，我们将简要展示如何设置高可用性/负载均衡器来控制特定服务的流量；在我们的案例中，我们将使用 HTTP 作为 Web 服务器的流量。

![使用 HAProxy 建立服务的高可用性](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/ms-centos7-linux-svr/img/B04674_06_19.jpg)

来源：[assets.digitalocean.com](http://assets.digitalocean.com)

为此工作，我们使用 HAProxy 作为负载平衡和服务高可用性的开源解决方案，通过多个服务器。它通常用于网站的流量负载平衡。HAProxy 将工作负载分布到提供相同服务的许多服务器上（基本上是 Web 服务器、数据库等），以提高服务的整体性能和可靠性。

正如我们之前所说，本节将安装和配置高可用性负载均衡器，以在三个 Web 服务器和备用服务器之间共享负载，以便在服务器或服务故障时接管。

因此，我们将拥有一个看起来像这样的基础设施：

+   HAProxy 服务器：

+   **操作系统**：CentOS 7

+   **IP 地址**：172.25.25.166 和 10.0.0.10

+   **主机名**：haproxy.packt.co.uk

+   Web 服务器 1：

+   **操作系统**：CentOS 7

+   **IP 地址**：10.0.0.11

+   **主机名**：webserver1.packt.co.uk

+   Web 服务器 2：

+   **操作系统**：CentOS 7

+   **IP 地址**：10.0.0.12

+   **主机名**：webserver2.packt.co.uk

+   Web 服务器 3：

+   **操作系统**：CentOS 7

+   **IP 地址**：10.0.0.13

+   **主机名**：webserver3.packt.co.uk

+   备用 Web 服务器：

+   **操作系统**：CentOS 7

+   **IP 地址**：10.0.0.20

+   **主机名**：backupwebserver.packt.co.uk

![使用 HAProxy 建立服务的高可用性](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/ms-centos7-linux-svr/img/B04674_06_20.jpg)

首先，我们将开始设置 Web 服务器，为此，我们将仅使用安装后由 Apache 生成的默认页面。有关如何设置 Web 服务器的更多信息，您可以随时参考第三章，*不同用途的 Linux*。因此，我们只需要安装和运行 Apache，并且需要配置网络和机器的主机名。

首先，我们将使用 CentOS 7 YUM 的默认软件包管理器安装 Apache Web 服务器：

```
$ sudo yum install httpd

```

然后之后，我们配置主机名：

```
$ sudo nano /etc/hostname

```

并确保它看起来像这样：

```
Webserver1.packt.co.uk

```

之后，我们进入每个主机文件并将域配置为默认的本地主机，同时添加所有服务器及其 IP 地址的列表：

```
$ sudo nano /etc/hosts

```

### 注意

如果基础设施内没有可靠的 DNS 服务器可以解析所有基础设施服务器，则只需要此部分。

我们更改默认的本地主机地址`127.0.0.1`域名：

```
127.0.0.1  webserver1  Webserver1.packt.co.uk

```

然后，我们添加以下行：

```
10.0.0.10  haproxy  haproxy.packt.co.uk
10.0.0.11  Webserver1  Webserver1.packt.co.uk
10.0.0.12  Webserver2  Webserver2.packt.co.uk
10.0.0.13  Webserver3  Webserver3.packt.co.uk
10.0.0.20  backupWebserver   backupWebserver.packt.co.uk

```

在完成之前，我们需要在 Web 服务器防火墙上打开 HTTPS 和 HTTPS 端口，以使服务对访问者可用：

```
$ sudo firewall­cmd ­­permanent ­­zone=public ­­add­port=80/tcp
$ sudo firewall­cmd ­­permanent ­­zone=public ­­add­port=443/tcp
$ sudo firewall­cmd ­­reload

```

通过这一步，我们可以说我们所有的 Web 服务器都准备好了。现在我们可以转到我们的 HAProxy 服务器安装。首先，我们需要为 Web 服务和 HAProxy 使用的日志接收打开所需的端口：

```
$ sudo firewall­cmd ­­permanent ­­zone=public ­­add­port=80/tcp
$ sudo firewall­cmd ­­permanent ­­zone=public ­­add­port=443/tcp
$ sudo firewall­cmd ­­permanent ­­zone=public ­­add­port=514/udp
$ sudo firewall­cmd ­­reload

```

然后，我们可以开始安装：

```
$ sudo yum install haproxy

```

现在，我们进入配置部分。在进行主要的 HAProxy 配置之前，我们需要为调试设置 HAProxy 日志记录功能配置：

```
$ sudo nano /etc/haproxy/haproxy.cfg

```

在**#全局设置**选项下，我们需要确保以下行没有被注释掉：

```
log         127.0.0.1 local2 info

```

在`Rsyslog`配置文件中也需要进行一些小的修改：

```
$ sudo nano /etc/rsyslog.conf

```

这是我们需要取消注释以下两行的地方：

```
$ModLoad imudp
$UDPServerRun 514

```

在完成之前，我们需要有一个代表`HAProxy`在`Rsyslog 日志`文件夹中的文件：

```
$ sudo nano /etc/rsyslog.d/haproxy.conf

```

在使用 Nano 创建时，我们需要在其中放入以下行：

```
local2.*  /var/log/haproxy.log

```

保存文件，然后应用更改并重新启动`Rsyslog 服务`：

```
$ sudo systemctl restart rsyslog.service

```

现在，我们可以进入 HAProxy 全局设置配置：

```
$ sudo nano /etc/haproxy/haproxy.cfg

```

首先，在默认部分，我们需要设置超时以获得更个性化的解决方案。由于我们的服务器只是进行负载平衡，我们可以始终使用端口 80。因此，我们需要接管该端口，通过删除其与`Httpd`服务的关联来实现：

```
$ sudo nano /etc/httpd/conf/httpd.conf

```

然后，我们将监听端口更改为除 80 之外的任何其他端口。在我们的示例中，`8080`：

```
Listen 8080 

```

然后，我们转到**主前端**部分，更改 Web 界面提供服务的端口。因此，我们需要更改整个部分，使其看起来像以下内容：

```
Frontend  HAProxy
bind  *:80
reqadd X-Forwarded-Proto:\ http
default_backend  HAProxy

```

并且我们需要注释掉**Backend**部分，以替换为以下内容：

```
# use_backend static  if url_static
backend HAProxy *:80
mode http
stats enable
stats hide-version
stats uri /stats
stats realm Haproxy\ Statistics
stats auth haproxy:password    # Change "password" with a well secured password
balance roundrobin 
option httpchk
option  httpclose
option forwardfor
cookie LB insert
 server webserver1 10.0.0.11:80 cookie webserver1 check
server webserver3 10.0.0.12:80 cookie webserver2 check
server webserver3 10.0.0.13:80 cookie webserver3 check
server backupwebserver 10.0.0.20:80 check backup

```

我们需要确保文件的结尾与我们的基础设施 IP 地址和主机名匹配。然后，我们可以启动 HAProxy 服务器并将其添加到启动系统服务中：

```
$ sudo systemctl start haproxy.service
$ sudo systemctl enable haproxy.service

```

要验证配置文件没有错误，我们可以随时使用以下命令检查服务状态：

```
$ sudo systemctl status haproxy.service -l

```

然后，我们获取每个 Web 服务器并放置一个测试页面，以便访问并收集测试结果。然后，我们打开 HAProxy 的 Web 界面来可视化负载平衡的状态`http://10.0.0.10/stats`或`http://172.25.25.166/stats`。

![使用 HAProxy 建立服务的高可用性](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/ms-centos7-linux-svr/img/B04674_06_21.jpg)

如果我们看到以下界面，那意味着我们的高可用服务器正在正常运行。如果我们需要启用 https 以使用 SSL 访问 HAProxy 的 Web 界面，我们可以随时安装 OpenSSL 并配置我们的服务器以使用它。

# 参考资料

现在，让我们看一下本章中使用的参考资料：

+   **VMware** **Documentation Center**: [`pubs.vmware.com/vsphere-51/index.jsp`](http://pubs.vmware.com/vsphere-51/index.jsp)

+   **VMware** **Virtualization**: [`www.vmware.com/virtualization.html`](http://www.vmware.com/virtualization.html)

+   **Full** **virtualization wiki**: [`en.wikipedia.org/wiki/Full_virtualization`](https://en.wikipedia.org/wiki/Full_virtualization)

+   **Paravirtualization** **wiki**: [`en.wikipedia.org/wiki/Paravirtualization`](https://en.wikipedia.org/wiki/Paravirtualization)

+   **Xen project** **wiki**: [`wiki.xen.org/wiki/Xen_Project_Software_Overview`](http://wiki.xen.org/wiki/Xen_Project_Software_Overview)

+   **KVM home** **page**: [`www.linux-kvm.org/page/Main_Page`](http://www.linux-kvm.org/page/Main_Page)

+   **OpenVZ home** **page**: [`openvz.org/Main_Page`](https://openvz.org/Main_Page)

+   **VirtualBox** **home page**: [`www.virtualbox.org`](https://www.virtualbox.org)

+   **Docker** **documentation**: [`www.modssl.org/docs/`](http://www.modssl.org/docs/)

+   **HAProxy web** **page**: [`www.haproxy.org/`](http://www.haproxy.org/)

# 总结

本章以对虚拟化基础知识的简要描述开始。然后，我们定义了完全虚拟化和半虚拟化。接下来，为了更好地通过各种开源虚拟化工具实际地解释所有这些，我们从 Xen 作为半虚拟化和完全虚拟化解决方案开始。我们转向 KVM 作为完全虚拟化解决方案，容器虚拟化，OpenVZ 和 VirtualBox 工具。这通过其美丽的图形界面实现了简单的设置。

我们在本章中介绍了 Docker 及其从 Web 使用容器的方式。在本章结束时，我们可以说我们已经看到了各种虚拟化技术以及如何使用它们创建虚拟机。

在下一章中，我们将有机会探索云计算技术，并使用开源解决方案 OpenStack 应用一些示例。


# 第七章：云计算

通过互联网提供的新一代服务被称为云计算。在计算机行业，许多组织使用云计算，因为他们不喜欢购买可以解决其资源问题的设备，或者雇佣所需的管理和维护人员。云计算就像第三方数据源，提供各种功能来存储和处理数据。

在建立云计算环境的最佳解决方案列表中，我们选择了 OpenStack。在本章中，我们将简要介绍云计算是什么，以及如何使用 OpenStack 设置单个节点。

在本章的过程中，我们将涉及以下主题：

+   云计算概述

+   云计算服务

+   介绍 OpenStack

+   OpenStack 的组件

+   安装和设置 OpenStack

# 云计算概述

云计算是在不依赖本地机器的通常方式之外执行计算的能力。云计算依赖于共享资源来处理所需的计算或处理。它与网格计算具有相同的特点，两种技术都将其处理能力聚集起来解决或处理对独立机器（服务器或个人计算机）来说过于繁重的问题。

云计算的目标是利用高超级计算能力在面向消费者的应用程序中执行高级计算，例如金融、个性化信息传递、数据存储等。

为了执行这项艰巨的任务，云计算依赖于大量超强大的服务器（刀片…）通过极快的连接（InfiniBand（IB））连接在一起，以在它们的计算单元之间共享工作负载。这种基础设施运行在特别配置的系统上，它们被连接在一起以简化任务。一些基础设施依赖于虚拟化技术来增强其云计算。

![云计算概述](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/ms-centos7-linux-svr/img/B04674_07_10.jpg)

来源：[`networksolutionsintl.com`](http://networksolutionsintl.com)

简而言之，许多公司使用云计算的最精确原因是，它使它们能够将计算资源看作是一种实用工具，可以随着时间付费，而无需在现场拥有真正的硬件并承担管理和维护的负担。此外，云计算为企业提供了许多有趣的功能，例如：

+   **弹性**：根据需求扩展和缩减计算资源的能力

+   **自助服务供应**：根据需求提供所需数量的资源的能力

+   **按使用量付费**：衡量用户使用的资源的能力，使他们只需为他们使用的资源付费

云计算随着时间的推移发展迅速。然而，它始终保持着主要的三个核心服务：

+   软件即服务（SaaS）

+   **平台即服务**（PaaS）

+   **基础设施即服务**（IaaS）

## 软件即服务

SaaS 指的是在当前用户机器之外运行的每个应用程序，用户可以通过其 Web 浏览器访问其部分或全部服务，有时也可以通过仅作为演示界面的薄客户端应用程序访问。SaaS 应用程序通常可以在全球范围内使用任何可以访问互联网的设备（计算机、移动设备等）。使 SaaS 应用程序运行良好的是它是一种可扩展的应用程序，用户可以根据需要在尽可能多的虚拟机上处理其处理以满足负载需求。大多数云计算基础设施使用负载平衡系统在虚拟机之间组织负载，应用程序可以在没有任何中断的情况下继续运行并获得更好的执行结果。

![软件即服务](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/ms-centos7-linux-svr/img/B04674_07_11.jpg)

来源：[`icorees.com/`](http://icorees.com/)

SaaS 的特点如下：

+   其服务可供任何连接设备访问

+   登录后即可使用易于使用的应用程序

+   一切都存储在云上，分布在数百台机器上，配置良好，可以应对磁盘崩溃等灾难，此外用户数据和服务始终可用

+   应用程序的计算能力在需要时始终是可扩展的

我们可以区分一些我们每天使用的最著名的 SaaS，比如电子邮件服务（Gmail，Yahoo…），社交媒体和通讯工具（Facebook，Skype…）。我们使用这些日常服务所需的只是互联网连接和具有 Web 浏览器或移动设备的薄客户端应用程序。

## 平台即服务（PaaS）

PaaS 是一种为客户提供在基于云的环境中构建和部署应用程序的能力的服务。PaaS 在为用户提供可扩展性时就像 SaaS 一样。在部署他们的应用程序时，他们可以按需访问所需的资源来运行他们的应用程序，而无需购买、维护和管理应用程序运行所需的硬件，以及其背后的所有后勤工作。PaaS 已经得到很好的发展，为其客户提供了预先准备的模板，以简化在平台上的初始化。

![平台即服务（PaaS）](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/ms-centos7-linux-svr/img/B04674_07_12.jpg)

来源：[`www.zoho.com/`](https://www.zoho.com/)

使用 PaaS 相比传统解决方案有一些主要好处，如下所示：

+   加快了应用程序的开发，环境已经准备好，使其准备好上市

+   消除了管理中间件的复杂性，并简化了任务

+   简化了 Web 应用程序的部署

## 基础设施即服务（IaaS）

第三项服务是 IaaS，一种为用户提供建立完全合格基础设施所需的服务。IaaS 提供具有不同特征的服务器、网络设备和按需存储空间。基础设施的用户拥有管理其基础设施的所有权利，具有系统和网络管理员的所有权利。该服务为用户提供的不仅仅是基础设施，还有一种资源包（小型、中型和超大型计算能力和内存）来满足工作负载要求。正如我们之前所说，用户可以作为系统和网络管理员来部署他们的应用程序。然后他们需要建立他们的网络，安装所需的操作系统，并设置他们的机器，用户还需要手动维护、管理和更新他们的系统。

![基础设施即服务（IaaS）](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/ms-centos7-linux-svr/img/B04674_07_13.jpg)

来源：[`cloudplus.com/`](http://cloudplus.com/)

IaaS 的好处可以总结如下：

+   它消除了投资硬件的任务

+   与其他云解决方案一样，IaaS 可以根据需求进行可扩展，以满足用户对资源和设备的需求

+   根据用户需求提供各种灵活和创新的服务！基础设施即服务（IaaS）

# 云计算服务

在解释了不同类型的云计算之后，我们现在应该看一下这些服务是如何提供的。为此，我们将它们分类为三种主要类型：公共云、私有云和混合云。

## 公共云

我们将首先介绍公共云。公共云，顾名思义，是公开可用的云。通常，公共云服务可以根据用户愿意支付的金额进行扩展，无论是资源还是特殊服务。由于它在云上，用户不必担心硬件购买、管理和维护。大多数作为公共云提供的服务都是 SaaS，只有少数是 PaaS。大多数这些服务都是按需提供的。通常，用户支付的是他们使用的资源（CPU、内存、存储、互联网带宽）而不是服务本身。

![公共云](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/ms-centos7-linux-svr/img/B04674_07_14.jpg)

来源：[`nextgenaccess.zserver.co.uk/`](http://nextgenaccess.zserver.co.uk/)

在公共云上共享资源出现在多个用户访问托管在一个或多个服务器上的相同服务的情况下，也在这些服务器需要处理客户发送的任务的情况下。一些基础设施比其他基础设施更好，因为它们可以处理非常繁重的流量；其他可能会发现这有些困难。在这个阶段，客户可能会在他们的应用程序中经历速度变慢，这确实会以不好的方式影响服务。

## 私有云

与公共云相比，私有云是一种专门为一个用户或一个组织提供的服务。被一个客户使用并不意味着它与任何其他云有所不同。它仍然可以由第三方公司或内部团队进行管理和管理。

大多数组织倾向于使用私有云，因为它具有分配和控制资源的优势。这与公共云不同，后者在多个用户之间共享。此外，公共云具有自助服务界面，可帮助简化系统管理员的资源管理和分配，以及更快的按需方法，更先进的安全协议以更好地保护用户数据的安全，以及帮助优化工作负载的先进自动化系统。

![私有云](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/ms-centos7-linux-svr/img/B04674_07_15.jpg)

来源：[`blogs.dlt.com`](http://blogs.dlt.com)

## 混合云

混合云是公共云和私有云的结合。更具体地说，私有云有时可能非常昂贵且难以调整，特别是对于不需要私有云提供的优势的小型应用。而公共云的解决方案并不那么昂贵，而且具有快速部署应用程序的优势，组织倾向于根据自己的需求混合使用这两种服务，这就是混合云变得流行的原因。混合云允许组织将重要数据保存在其私有云上，并在公共云上提供诸如 SaaS 之类的轻型服务，具有在需要时切换到所需服务的能力。

![混合云](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/ms-centos7-linux-svr/img/B04674_07_16.jpg)

来源：[`www8.hp.com`](http://www8.hp.com)

# 介绍 OpenStack

我们现在已经彻底描述了云计算、其服务以及客户如何利用这些服务。现在，我们需要谈谈我们在其中的角色。了解如何使用云计算服务，例如 IaaS 来部署基础设施，对于系统管理员来说并不是最困难的任务。但每个系统管理员都应该知道如何部署并如何向他们的客户提供这些服务。在本节中，我们将探讨如何在我们的基础设施中运行云，并如何在我们的 CentOS 7 服务器上运行这些服务。为了执行这项任务，我们将使用 Linux 最著名的开源云解决方案之一，即 OpenStack，这是一个免费的云计算解决方案，可帮助启动、管理和维护所需资源（CPU、内存、网络和存储）的大量虚拟机。该基础设施通过用户友好的 Web 界面进行管理，帮助向系统管理员呈现节点的状态，并为他们提供轻松访问以管理基础设施资源。OpenStack 根据用户的需求提供开源和企业服务，因此被多个组织广泛使用。

今天，全球数百家组织使用 OpenStack 来维护他们的云基础设施，他们使用它来使他们的云解决方案正常运行，并且它被用于公共或私有云服务。大多数提供云服务的组织，无论是公共云还是私有云，都使用 OpenStack 提供 IaaS 服务。

![介绍 OpenStack](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/ms-centos7-linux-svr/img/B04674_07_02.jpg)

[`www.openstack.org/software/`](https://www.openstack.org/software/)

OpenStack 在其 API 下管理三个主要部分：计算、网络和存储。通过这个 API，OpenStack 为其管理的基础设施创建了一个可持续的环境。

## OpenStack 计算

OpenStack 计算是在客户端需求时提供计算资源，并管理已请求的资源。OpenStack 计算不仅提供客户端应用程序的运行情况，还通过组织资源和应用程序来确保服务本身的良好运行。OpenStack 计算可通过 Web 界面进行管理，也可通过 API 进行开发和构建应用程序。这种架构使得物理硬件的经济使用可以横向扩展。这项技术还管理和自动化了大量的计算资源，并与各种虚拟化技术兼容。

## OpenStack 网络

OpenStack 网络是管理 OpenStack 管理的云资源的网络能力。这项技术确保连接云基础设施的网络资源始终可用，并且不包含任何瓶颈，只需执行网络管理员应该做的维护基础设施网络的任务。

OpenStack 网络提供了灵活的网络模型，以满足扁平网络、VLAN 配置、GRE 和 VXLAN 等需求。它提供了与普通物理网络硬件提供的相同服务，如路由、NAT 和 DHCP，以及静态 IP 关联。它还配备了一个智能系统，可以在故障或过载的情况下帮助重定向流量，以帮助维护更好的网络容量。OpenStack 网络不仅支持自动化网络管理，还为用户提供了手动管理网络的能力，通过调整适当的连接，连接服务器和终端。用户还可以利用软件定义的网络（SDN）技术进行多租户配置和大规模配置，如 OpenFlow。它还支持来自多个常见供应商的高级网络服务架构。最后，它提供了一个集成常见网络管理技术的高级扩展，如用于私人连接的 VPN，用于加固安全性的 IDS，用于设置访问规则的负载平衡和防火墙等。

## OpenStack 存储

OpenStack 存储是 OpenStack 架构内提供的数据存储服务。通过其完全分布式的 API 存储平台，云应用程序可以通过多种技术和架构（归档、备份、数据保留）访问存储空间。OpenStack 存储始终是可扩展的，以满足用户和应用程序的需求，通过允许块设备相互添加并确保更好的性能。OpenStack 存储具有与 SolidFire 和 NetApp 等企业存储平台集成的能力。

# OpenStack 的组件

OpenStack 是一个非常庞大的平台，拥有许多小组件，确保其服务的完整功能。其中大多数组件都是由开源社区制作的，以帮助满足用户的需求。在本节中，我们将讨论 OpenStack 社区组件作为其核心的一部分。这些组件的特点是它们由 OpenStack 社区维护，作为解决方案的一部分呈现出来。

![OpenStack 的组件](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/ms-centos7-linux-svr/img/B04674_07_17.jpg)

来源：[`redhatstackblog.redhat.com/`](http://redhatstackblog.redhat.com/)

这些组件描述如下：

+   Horizon：这是负责设置 OpenStack 仪表板的组件。这是 OpenStack 管理员管理基础设施的地方。到目前为止，它是 OpenStack 唯一的图形界面。Horizon 提供了对云基础设施中发生的事情的了解，并为系统管理员提供了一些管理功能。另一方面，仪表板不支持开发人员的访问。开发人员始终可以通过**应用程序编程接口**（**API**）访问云的资源和其他方面。

+   Nova：这是 OpenStack 的主要计算引擎。它是负责部署和管理云基础设施的虚拟机的主要组件，而不仅仅是一个小型基础设施或一组超级计算机。它还管理和组织其他实例，如处理云计算任务。

+   Neutron：这是 OpenStack 的网络组件。它基本上是确保云基础架构的不同组件之间进行网络通信的一个重要部分。它还支持多种技术，以确保通信可靠。

+   Keystone：这是负责识别 OpenStack 管理的服务。它组织使用云的用户，并组织他们的访问权限。它组织他们正在使用的资源。它还对开发人员跟踪用户使用和访问方法提供了很大帮助。

+   Swift：这是负责 OpenStack 存储系统的组件。它以一种先进的方法存储数据，开发人员只需将文件指定为信息的一部分，OpenStack 决定在哪里存储，这有助于扩展并解决存储容量问题。它使大多数常见任务，如备份和安全性，成为系统而不是开发人员的责任。

+   Cinder：这是一个较小的存储组件，用于组织块存储。它有助于增强磁盘驱动器中的数据访问，并根据需要以传统方式组织数据访问速度。

+   Heat：这是 OpenStack 的编排组件。它是一种存储有关云应用程序信息的方法，其中已经定义了该应用程序所需的资源，以更好地组织云基础设施。

+   Glance：这是组织硬盘的虚拟副本，即所谓的镜像，以便稍后用作部署新虚拟机的模板的组件。

+   Ceilometer：这是帮助个人用户云使用计费服务的组件。它充当一个报告系统使用情况的计量器，用户开始使用云的期间。

这些组件非常重要，其中一些依赖于其他组件，如果其中一些组件被禁用或排除，许多基本的云服务将不可用。其中一个非常重要的组件是编排组件，它有助于组织大量的机器并执行高性能计算而无需任何困难。

# 安装和配置 OpenStack

在对云计算和 OpenStack 进行简要解释之后，我们现在可以继续在 CentOS 7 Linux 服务器上安装 OpenStack。首先，我们将进行一些基本的环境配置，然后进行设置。

对于这个安装，我们将把我们的云基础设施设置如下：

+   路由器/网关服务器作为*e*th 机器，为外部网站提供互联网访问，IP 地址为：`10.0.1.1`

+   托管 OpenStack 的云服务器，IP 地址为：`10.0.1.2`

+   用于云计算的主机，其 IP 地址如下：`10.0.1.4`，`10.0.1.5`，`10.0.1.6`

为了使 OpenStack 安全可靠，社区集成了许多服务，以确保其中一些服务通过加密数据传输来保护数据访问和用户认证。为此，我们需要在我们的云服务器上安装 OpenSSL，以便 OpenStack 可以使用它来运行其服务：

```
$ sudo yum install openssl

```

为了安全安装而没有错误，如果有防火墙，我们需要禁用它，就像这样：

```
$ sudo systemctl stop firewalld.service

```

然后我们需要确保服务器连接到本地网络并具有互联网访问权限。为此，我们需要 ping 本地网络上的一台机器和一个工作正常的网页服务器（[`www.google.co.in/`](https://www.google.co.in/)）：

```
$ ping –c 5 10.0.1.1
PING 10.0.1.1 (10.0.1.1) 56(84) bytes of data.
64 bytes from 10.0.1.1: icmp_seq=1 ttl=255 time=1.21 ms
64 bytes from 10.0.1.1: icmp_seq=2 ttl=255 time=4.19 ms
64 bytes from 10.0.1.1: icmp_seq=3 ttl=255 time=4.32 ms
64 bytes from 10.0.1.1: icmp_seq=4 ttl=255 time=4.15 ms
64 bytes from 10.0.1.1: icmp_seq=5 ttl=255 time=4.01 ms
--- 10.0.1.1 ping statistics ---
5 packets transmitted, 5 received, 0% packet loss, time 4007ms
rtt min/avg/max/mdev = 1.214/3.580/4.324/1.186 ms
$ ping –c 5 www.google.com

```

测试的结果应该如下所示：

![安装和配置 OpenStack](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/ms-centos7-linux-svr/img/B04674_07_03.jpg)

然后我们需要添加所有涉及的节点（控制节点、网络节点、计算节点、对象存储节点和块存储节点）：

```
$ sudo nano /etc/hosts

```

接下来，为了使节点之间同步良好，我们需要设置一个时间服务器来为所有服务器配置时间。为此，我们将使用 NTP 服务。但首先，我们需要安装它：

```
$ sudo yum install ntp

```

然后我们需要启动它，并使其在系统启动时运行：

```
$ sudo systemctl enable ntpd.service
$ sudo systemctl start ntpd.service

```

要验证安装，我们需要使用以下命令：

```
$ sudo ntpq -c peers

```

要查看此命令的输出，请参考以下内容：

![安装和配置 OpenStack](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/ms-centos7-linux-svr/img/B04674_07_04.jpg)

```
$ sudo ntpq -c assoc

```

要查看此命令的输出，请参考以下内容：

![安装和配置 OpenStack](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/ms-centos7-linux-svr/img/B04674_07_05.jpg)

我们需要在任何一行的条件列中看到`sys.peer`。

### 注意

我们需要对所有涉及的节点执行相同的操作。

现在，我们将 SELinux 设置为宽松模式：

```
$ sudo nano /etc/selinux/config

```

然后考虑这一行：

```
SELINUX=enforcing

```

将其更改为以下行：

```
SELINUX= permissive

```

然后我们应该重新启动系统，以使更改生效。

系统启动后，我们可以继续进行软件包源配置。首先，我们需要确保我们的系统软件包都已更新：

```
$ sudo yum update –y

```

然后我们安装`epel`仓库：

```
$ sudo yum install epel-release

```

接下来，我们检查额外的 EPEL 仓库是否已启用：

```
$ sudo nano /etc/yum.repos.d/epel.repo

```

我们需要确保所有模块（[epel] [epel-debuginfo] [epel-source]）都已启用：

```
enabled=1

```

然后我们继续安装 YUM 插件优先级，以在仓库内分配相对优先级：

```
$ sudo yum install yum-plugin-priorities

```

最后，我们可以设置 OpenStack 仓库：

```
$ sudo yum install https://repos.fedorapeople.org/repos/openstack/openstack-juno/rdo-release-juno-1.noarch.rpm

```

为了让 OpenStack 自动管理其服务的安全策略，我们需要安装 OpenStack-SELinux 包：

```
$ sudo yum install openstack-selinux

```

在安装 OpenStack 服务的官方包之前，我们将安装一些用于我们云计算平台 OpenStack 的 SELinux 策略所需的工具。我们将首先安装数据库服务器。为此，我们将安装 Python MySQL 库和 MariaDB 服务器：

```
$ sudo yum install mariadb mariadb-server MySQL-python

```

在安装了 MariaDB 之后，我们需要继续配置它。首先，我们需要启动数据库服务器并将其添加到系统启动项中：

```
$ sudo systemctl enable mariadb.service
$ sudo systemctl start mariadb.service

```

默认情况下，OpenStack 安装时为 root 用户设置了无密码策略。在第一次使用时，我们需要更改它以进行安全设置。

在这一点上，我们已经正确设置了所有所需的工具和配置。我们可以开始安装 OpenStack 包。我们可以单独安装每个 OpenStack 组件，或者通过同时安装和配置它们来加快速度。为此，我们将使用`yum`包管理器：

```
$ sudo yum install -y openstack-packstack

```

对于单节点 OpenStack 部署，我们应该使用以下命令进行配置：

```
$ sudo packstack --allinone

```

我们应该看到以下消息开头，以确定安装是否正确完成并且配置已经正确启动。这可能需要一些时间来完成。

![安装和配置 OpenStack](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/ms-centos7-linux-svr/img/B04674_07_06.jpg)

如果配置正确，将出现以下屏幕：

![安装和配置 OpenStack](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/ms-centos7-linux-svr/img/B04674_07_07.jpg)

配置完成后，将生成两个用于管理员使用的身份验证凭据。第一个是用于 Nagios 服务器的。登录名和密码将显示在屏幕上，因此我们需要保存它们以便稍后更改密码。第二个是用于 OpenStack 仪表板的，它将存储在`root`目录中的一个名为`keystonerc_admin`的文件中。

两个 Web 界面中的第一个应该如此，以确认节点正在运行：

![安装和配置 OpenStack](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/ms-centos7-linux-svr/img/B04674_07_08.jpg)

第二个界面看起来像以下截图所示：

![安装和配置 OpenStack](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/ms-centos7-linux-svr/img/B04674_07_09.jpg)

现在我们可以继续进行网络桥接配置。我们需要创建一个桥接接口：

```
$ sudo nano /etc/sysconfig/network-scripts/ifcfg-br-ex

```

创建文件后，我们需要将以下代码放入其中：

```
DEVICE=br-ex
DEVICETYPE=ovs
TYPE=OVSBridge
BOOTPROTO=static
IPADDR=10.0.1.2 # Old eth0 IP 
NETMASK=255.255.255.0 # the netmask
GATEWAY=10.0.1.1 # the gateway
DNS1=8.8.8.8 # the nameserver
ONBOOT=yes
Now we've got to fix the eth0 configuration file to look like the following:
BOOTPROTO="none"
IPV4_FAILURE_FATAL="no"
IPV6INIT="yes"
IPV6_AUTOCONF="yes"
IPV6_DEFROUTE="yes"
IPV6_FAILURE_FATAL="no"
NAME="eth0"
UUID="XXXXXXXXXX"
ONBOOT="yes"
HWADDR="XXXXXXXXXXXXXX" # this is the Ethernet network Mac address
IPV6_PEERDNS="yes"
IPV6_PEERROUTES="yes"
TYPE=OVSPort
DEVICETYPE=ovs
OVS_BRIDGE=br-ex
ONBOOT=yes

```

然后我们将以下行添加到 Neutron 配置文件中，使其在`[ovs]`模块中如下所示：

```
$ sudo nano /etc/neutron/plugin.ini
[ovs]
network_vlan_ranges = physnet1
bridge_mappings = physnet1:br-ex

```

接下来，我们重新启动网络：

```
$ sudo systemctl restart network.service

```

接下来的部分是可选的，我们将详细介绍如果我们以手动方式而不是自动交互方式运行会发生什么。

如果我们想要手动部署其他节点，我们应该使用`packstack`和`--install-hosts`选项，然后输入其他主机的 IP 地址：

```
$ sudo packstack --install-hosts=10.0.1.4

```

如果有许多主机，我们可以在 IP 地址之间添加逗号（,）：

```
$ sudo packstack --install-hosts=10.0.1.4,10.0.1.5,10.0.1.6

```

在执行此命令时，我们将被要求分别输入每个系统的 root 密码，以连接到系统，安装 OpenStack 并接管它：

```
root@10.0.1.4's password:

```

当我们看到以下消息时，我们知道安装已完成：

```
**** Installation completed successfully ******

```

包含所有选择的配置选项的答案文件将保存在我们运行`packstack`的系统的磁盘上。此文件可用于自动化未来的部署：

```
* A new answerfile was created in: /root/packstack-answers-XXXXXXXX-XXXX.txt

```

包含 OpenStack 管理员用户的身份验证详细信息的文件将保存在部署 OpenStack 客户端工具的系统的磁盘上。我们将需要这些详细信息来管理 OpenStack 环境：

```
* To use the command line tools you need to source the file /root/keystonerc_admin created on 10.0.1.4

```

我们可以交互式运行`packstack`来创建单节点和多节点 OpenStack 部署：

```
$ sudo packstack

```

运行此命令后，我们需要按照部署节点的步骤列表进行操作。

首先，它将要求将公钥存储在服务器中以获得自动 SSH 访问权限，因此我们需要已经生成一个：

```
$ ssh-keygen –t rsa

```

然后我们给出其位置，即`~/.ssh/id_rsa.pub`：

```
Enter the path to your ssh Public key to install on servers:

```

接下来，我们选择需要部署的服务。我们可以选择任何我们需要的：

```
Should Packstack install Glance image service [y|n] [y] :
Should Packstack install Cinder volume service [y|n] [y] :
Should Packstack install Nova compute service [y|n] [y] :
Should Packstack install Horizon dashboard [y|n] [y] :
Should Packstack install Swift object storage [y|n] [y] :

```

每个选择的服务都可以部署在本地或远程系统上。将根据我们稍后在部署过程中提供的 IP 地址来确定每个服务的部署位置。

OpenStack 包括许多客户端工具。输入`y`来安装客户端工具。还将创建一个包含管理员用户的身份验证值的文件：

```
Should Packstack install OpenStack client tools [y|n] [y] :

```

可选地，`packstack`脚本将配置部署中的所有服务器，以使用**网络时间协议**（**NTP**）检索日期和时间信息。要使用此功能，请输入逗号分隔的 NTP 服务器池：

```
Enter a comma separated list of NTP server(s). Leave plain if Packstack should not install ntpd on instances.:

```

可选地，`packstack`脚本将安装和配置 Nagios，以提供对 OpenStack 环境中节点的高级监控设施：

```
Should Packstack install Nagios to monitor openstack hosts [y|n] [n] : 

```

现在我们继续配置 MySQL 实例。OpenStack 服务需要 MySQL 数据库来存储数据。要配置数据库，我们按照以下步骤进行。

我们输入要在其上部署 MySQL 数据库服务器的服务器的 IP 地址：

```
Enter the IP address of the MySQL server [10.0.1.1] :

```

输入要用于 MySQL 管理用户的密码。如果我们不输入值，它将随机生成。生成的密码将在当前用户的`~/.my.cnf`文件和答案文件中都可用：

```
Enter the password for the MySQL admin user :

```

OpenStack 服务使用 Qpid 消息系统进行通信。输入要部署 Qpid 的服务器的 IP 地址：

```
Enter the IP address of the QPID service  [10.0.1.2] :

```

OpenStack 使用 keystone（openstack-keystone）提供身份、令牌、目录和策略服务。如果选择了 keystone 安装，则在提示时输入要部署 keystone 的服务器的 IP 地址：

```
Enter the IP address of the Keystone server  [10.0.1.2] :

```

OpenStack 使用 glance（`openstack-glance-*`）来存储、发现和检索虚拟机镜像。如果选择了 glance 安装，则在提示时输入要部署 glance 的服务器的 IP 地址：

```
Enter the IP address of the Glance server  [10.0.1.2] :

```

为提供卷存储服务，OpenStack 使用 Cinder（`openstack-cinder-*`）。输入要在其上部署 Cinder 的服务器的 IP 地址。如果选择了卷服务的安装，则将呈现这些额外的配置提示：

```
Enter the IP address of the Cinder server  [10.0.1.2] :

```

`packstack`实用程序期望用于 Cinder 的存储可用于名为 cinder-volumes 的卷组。如果此卷组不存在，则将询问我们是否要自动创建它。

回答“是”意味着`packstack`将在`/var/lib/cinder`中创建一个原始磁盘映像，并使用回环设备挂载它供 Cinder 使用：

```
Should Cinder's volumes group be createdi (for proof-of-concept installation)? [y|n] [y]:

```

如果我们选择让 packstack 创建 cinder-volumes 卷组，那么我们将被提示输入其大小（以**GB**为单位）：

```
Enter Cinder's volume group size  [20G] :

```

OpenStack 使用 Nova 提供计算服务。Nova 本身由许多互补的服务组成，必须部署这些服务。如果选择了计算服务的安装，则将呈现这些额外的配置提示。

Nova API 服务（`openstack-nova-api`）为通过 HTTP 或 HTTPS 对 OpenStack 环境进行身份验证和交互提供 Web 服务端点。我们输入要在其上部署 Nova API 服务的服务器的 IP 地址：

```
Enter the IP address of the Nova API service  [10.0.1.3] :

```

Nova 包括一个证书管理服务（`openstack-nova-cert`）。输入要在其上部署 Nova 证书管理服务的服务器的 IP 地址：

```
Enter the IP address of the Nova Cert service  [10.0.1.3] :

```

Nova VNC 代理提供了连接 Nova 计算服务的用户与其在 OpenStack 云中运行的实例的设施。输入要在其上部署 Nova VNC 代理的服务器的 IP 地址：

```
Enter the IP address of the Nova VNC proxy  [10.0.1.3] :

```

`packstack`脚本能够部署一个或多个计算节点。输入一个逗号分隔的列表，包含您希望在其上部署计算服务的所有节点的 IP 地址或主机名：

```
Enter a comma separated list of IP addresses on which to install the Nova Compute services  [10.0.1.3] :

```

必须配置私有接口以在 Nova 计算节点上提供 DHCP 服务。输入要使用的私有接口的名称：

```
Enter the Private interface for Flat DHCP on the Nova compute servers  [eth1] :

```

`Nova`网络服务（`openstack-nova-network`）为计算实例提供网络服务。输入要在其上部署`Nova`网络服务的服务器的 IP 地址：

```
Enter the IP address of the Nova Network service  [10.0.1.3] :

```

必须配置公共接口以允许其他节点和客户端的连接。输入要使用的公共接口的名称：

```
Enter the Public interface on the Nova network server  [eth0] :

```

必须配置私有接口以在 Nova 网络服务器上提供 DHCP 服务。输入要使用的私有接口的名称：

```
Enter the Private interface for Flat DHCP on the Nova network server  [eth1] :

```

所有计算实例都会自动分配一个私有 IP 地址。输入必须分配这些私有 IP 地址的范围：

```
Enter the IP Range for Flat DHCP [10.0.2.0/24] :

```

计算实例可以选择分配公共可访问的浮动 IP 地址。输入将分配浮动 IP 地址的范围：

```
Enter the IP Range for Floating IP's [10.0.1.0/24] :

```

Nova 调度程序（`openstack-nova-scheduler`）用于将计算请求映射到计算资源。输入要部署`Nova`调度程序的服务器的 IP 地址：

```
Enter the IP address of the Nova Scheduler service  [10.0.1.4] :

```

在默认配置中，Nova 允许对物理 CPU 和内存资源进行“过度承诺”。这意味着可以为运行实例提供比实际上在计算节点上物理存在的这些资源更多的资源。

允许的“过度承诺”量是可配置的。

CPU“过度承诺”的默认级别允许为每个物理 CPU 插座或核心分配 16 个虚拟 CPU。按*Enter*接受默认级别，或者输入其他值（如果需要）：

```
Enter the CPU overcommitment ratio. Set to 1.0 to disable CPU overcommitment [16.0] : 

```

默认的内存超额分配级别允许分配的虚拟内存比物理计算节点上存在的内存多 50%。按*Enter*接受默认值，或者如果需要，输入不同的值：

```
Enter the RAM overcommitment ratio. Set to 1.0 to disable RAM overcommitment [1.5] :

```

如果选择安装客户端工具，则在提示时输入要在其上安装客户端工具的服务器的 IP 地址：

```
Enter the IP address of the client server  [10.0.1.4] :

```

OpenStack 使用 Horizon（`openstack-dashboard`）提供基于 Web 的用户界面或仪表板，用于访问 OpenStack 服务，包括 Cinder、Nova、Swift 和 Keystone。如果选择安装 Horizon 仪表板，则将请求这些额外的配置值。

输入要在其上部署 Horizon 的服务器的 IP 地址：

```
Enter the IP address of the Horizon server  [10.0.1.4] :

```

要启用与仪表板的`HTTPS`通信，我们在提示时输入`y`。启用此选项可确保用户访问仪表板时进行加密：

```
Would you like to set up Horizon communication over https [y|n] [n] : 

```

如果我们已经选择安装`Swift`对象存储，那么将会请求这些额外的配置值。

输入要充当 Swift 代理的服务器的 IP 地址。此服务器将充当客户端和 Swift 对象存储之间的公共链接：

```
Enter the IP address of the Swift proxy service  [10.0.1.2] :

```

输入逗号分隔的设备列表，Swift 对象存储将使用这些设备来存储对象。每个条目必须以 HOST/DEVICE 格式指定，其中 Host 由设备附加到的主机的 IP 地址替换，Device 由设备的适当路径替换：

```
Enter the Swift Storage servers e.g. host/dev,host/dev  [10.0.1.2] :

```

`Swift`对象存储使用区域来确保给定对象的每个副本都是单独存储的。一个区域可以代表一个独立的磁盘驱动器或阵列，一个服务器，一个机架中的所有服务器，甚至整个数据中心。

在提示时，输入必须定义的 Swift 存储区域的数量。请注意，提供的数量不能大于指定的各个设备的数量，如下所示：

```
Enter the number of swift storage zones, MUST be no bigger than the number of storage devices configured  [1] :

```

Swift 对象存储依赖复制来维护对象的状态，即使在一个或多个配置的存储区域中发生存储中断的情况下。在提示时输入 Swift 必须保留每个对象的副本数量。

建议至少使用三个副本来确保对象存储具有合理的容错性。但是请注意，指定的副本数量不能大于存储区域的数量，否则会导致一个或多个区域包含同一对象的多个副本：

```
Enter the number of swift storage replicas, MUST be no bigger than the number of storage zones configured  [1] :

```

目前，`packstack`支持使用`Ext4`或`XFS`文件系统进行对象存储。默认和推荐的选择是`ext4`。在提示时输入所需的值：

```
Enter FileSystem type for storage nodes [xfs|ext4]  [ext4] :

```

`packstack`实用程序允许我们配置目标服务器以从多个来源检索软件包。我们可以将此部分留空，以依赖节点的默认软件包来源：

```
Enter a comma-separated list of URLs to any additional yum repositories to install:

```

在这一点上，我们将被要求确认我们提供的部署细节。输入 yes 并按*Enter*继续部署。然后，它将显示整个阶段已经提供的所有信息。在验证一切设置正确后，我们对以下问题输入 yes：

```
Proceed with the configuration listed above? (yes|no): yes

```

现在，`packstack`将开始部署。请注意，当`packstack`设置 SSH 密钥时，它将提示我们输入根密码，以连接到尚未配置为使用密钥身份验证的机器。

将 Puppet 清单应用于部署中涉及的所有机器需要大量时间。`packstack`实用程序提供持续更新，指示正在部署哪些清单，随着部署过程的进行。一旦过程完成，将显示确认消息：

```
 **** Installation completed successfully ******
 (Please allow Installer a few moments to start up.....)
Additional information:
 * A new answerfile was created in: /root/packstack-answers-xxxxx-xxxxx.txt
 * Time synchronization was skipped. Please note that unsynchronized time on server instances might be a problem for some OpenStack components.
 * To use the command line tools source the file /root/keystonerc_admin created on 10.0.1.2
 * To use the console, browse to http://10.0.0.2/dashboard
 * The installation log file is available at: /var/tmp/packstack/xxxx-xxxx-TkY04B/openstack-setup.log
You have mail in /var/spool/mail/root
You have successfully deployed OpenStack using packstack.

```

我们提供的配置详细信息也记录在答案文件中，可以用于将来重新创建部署。此答案文件默认存储在`~/answers.txt`中。

通过这一步，我们可以说我们已经很好地安装和配置了 OpenStack 作为一个云计算解决方案，用于在 CentOS 7 Linux 服务器的小型基础设施内使用。

OpenStack 仪表板将是我们最好的方式，以更清晰的方式可视化有关云基础设施状态的有用信息。对于系统管理员来说，这非常有用，可以维护基础设施并排除任何问题。以下是一些显示仪表板概览页面的屏幕截图：

![安装和配置 OpenStack](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/ms-centos7-linux-svr/img/B04674_07_18.jpg)

来源：[`dachary.org/?p=2969`](http://dachary.org/?p=2969)

接下来的页面显示了正在运行的机器（节点）的列表，并提供了一些有关节点的有用信息，还为我们提供了一些管理它们的选项。

![安装和配置 OpenStack](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/ms-centos7-linux-svr/img/B04674_07_19.jpg)

来源：[`assist-software.net`](http://assist-software.net)

然后我们将看到网络页面，显示持有云节点的网络拓扑。

![安装和配置 OpenStack](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/ms-centos7-linux-svr/img/B04674_07_20.jpg)

来源：[`4.bp.blogspot.com`](http://4.bp.blogspot.com)

另外还有一个 Nova API 仪表板，具有更好设计的界面，用于展示，并且有一个特别用于监视大型网格计算基础设施的巨大仪表板屏幕。第一个仪表板屏幕显示了有关正在使用的 API 的信息：

![安装和配置 OpenStack](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/ms-centos7-linux-svr/img/B04674_07_21.jpg)

来源：[`openstack-in-production.blogspot.com`](http://openstack-in-production.blogspot.com)

第二个仪表板屏幕显示了这些 API 执行的历史以及呈现的日志：

![安装和配置 OpenStack](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/ms-centos7-linux-svr/img/B04674_07_22.jpg)

来源：[`openstack-in-production.blogspot.com`](http://openstack-in-production.blogspot.com)

# 参考资料

现在，让我们看一下本章中使用的参考资料：

+   什么是云计算？IBM：[`www.ibm.com/cloud-computing/what-is-cloud-computing.html`](http://www.ibm.com/cloud-computing/what-is-cloud-computing.html)

+   OpenStack 主页：[`www.openstack.org/`](https://www.openstack.org/)

+   Redhat 的 OpenStack 平台：[`access.redhat.com/documentation/en/`](https://access.redhat.com/documentation/en/)

# 总结

本章描述了如何在小型或大型计算基础设施中拥有开源云计算解决方案。我们首先定义了云计算的概念，然后介绍了 OpenStack 并简要描述了其组件。我们展示了一种实际的方法来设置和配置 OpenStack 节点，选择使用其所有组件。

在下一章中，您将学习使用最近的工具之一进行自动系统配置的方法，这种方法组织得很好——Puppet。
