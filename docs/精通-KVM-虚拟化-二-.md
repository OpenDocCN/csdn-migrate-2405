# 精通 KVM 虚拟化（二）

> 原文：[`zh.annas-archive.org/md5/937685F0CEE189D5B83741D8ADA1BFEE`](https://zh.annas-archive.org/md5/937685F0CEE189D5B83741D8ADA1BFEE)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第五章：Libvirt 存储

这一章节为您提供了 KVM 使用存储的见解。具体来说，我们将涵盖运行虚拟机的主机内部存储和*共享存储*。不要让术语在这里让您困惑——在虚拟化和云技术中，术语*共享存储*表示多个虚拟化程序可以访问的存储空间。正如我们稍后将解释的那样，实现这一点的三种最常见方式是使用块级、共享级或对象级存储。我们将以 NFS 作为共享级存储的示例，以**Internet Small Computer System Interface**（**iSCSI**）和**Fiber Channel**（**FC**）作为块级存储的示例。在对象级存储方面，我们将使用 Ceph。GlusterFS 如今也被广泛使用，因此我们也会确保涵盖到它。为了将所有内容整合到一个易于使用和管理的框架中，我们将讨论一些可能在练习和创建测试环境时对您有所帮助的开源项目。

在本章中，我们将涵盖以下主题：

+   存储介绍

+   存储池

+   NFS 存储

+   iSCSI 和 SAN 存储

+   存储冗余和多路径处理

+   Gluster 和 Ceph 作为 KVM 的存储后端

+   虚拟磁盘映像和格式以及基本的 KVM 存储操作

+   存储的最新发展—NVMe 和 NVMeOF

# 存储介绍

与网络不同，大多数 IT 人员至少对网络有基本的了解，而存储往往是完全不同的。简而言之，是的，它往往更加复杂。涉及许多参数、不同的技术，而且……坦率地说，有许多不同类型的配置选项和强制执行这些选项的人。还有*很多*问题。以下是其中一些：

+   我们应该为每个存储设备配置一个 NFS 共享还是两个？

+   我们应该为每个存储设备创建一个 iSCSI 目标还是两个？

+   我们应该创建一个 FC 目标还是两个？

+   每个**逻辑单元号**（**LUN**）每个目标应该有多少个？

+   我们应该使用何种集群大小？

+   我们应该如何进行多路径处理？

+   我们应该使用块级还是共享级存储？

+   我们应该使用块级还是对象级存储？

+   我们应该选择哪种技术或解决方案？

+   我们应该如何配置缓存？

+   我们应该如何配置分区或掩码？

+   我们应该使用多少个交换机？

+   我们应该在存储级别使用某种集群技术吗？

正如你所看到的，问题不断堆积，而我们几乎只是触及了表面，因为还有关于使用哪种文件系统、使用哪种物理控制器来访问存储以及使用何种类型的布线等问题——这些问题变成了一个包含许多潜在答案的大杂烩。更糟糕的是，许多答案都可能是正确的，而不仅仅是其中一个。

让我们先把基本的数学问题解决掉。在企业级环境中，共享存储通常是环境中*最昂贵*的部分，同时也可能对虚拟机性能产生*最显著的负面影响*，同时又是该环境中*最过度订阅的资源*。让我们想一想这个问题——每个开机的虚拟机都会不断地向我们的存储设备发送 I/O 操作。如果我们在单个存储设备上运行了 500 台虚拟机，那么我们是不是对存储设备要求过高了？

与此同时，某种共享存储概念是虚拟化环境的关键支柱。基本原则非常简单——有许多高级功能可以通过共享存储更好地发挥作用。此外，如果有共享存储可用，许多操作会更快。更重要的是，如果我们的虚拟机存储和执行位置不在同一地方，那么高可用性的简单选项就有很多。

作为一个额外的好处，如果我们正确设计共享存储环境，我们可以轻松避免**单点故障**（**SPOF**）的情况。在企业级环境中，避免 SPOF 是关键设计原则之一。但是当我们开始将交换机、适配器和控制器添加到*购买*清单上时，我们的经理或客户通常会开始头痛。我们谈论性能和风险管理，而他们谈论价格。我们谈论他们的数据库和应用程序需要适当的 I/O 和带宽供应，而他们觉得你可以凭空产生这些。只需挥动魔术棒，我们就有了：无限的存储性能。

但是，你的客户肯定会试图强加给你的最好的、我们永远喜欢的苹果和橙子比较是这样的……“我的闪亮新款 1TB NVMe SSD 笔记本电脑的 IOPS 比你的 5 万美元的存储设备多 1000 倍，性能比你的存储设备多 5 倍，而成本却少 100 倍！你根本不知道你在做什么！”

如果你曾经有过这种经历，我们为你感到难过。很少会有这么多关于盒子里的一块硬件的讨论和争论。但它是一个如此重要的盒子里的硬件，这是一场很好的争论。因此，让我们解释一些 libvirt 在存储访问方面使用的关键概念，以及如何利用我们的知识从我们的存储系统和使用它的 libvirt 中尽可能多地提取性能。

在本章中，我们基本上将通过安装和配置示例涵盖几乎所有这些存储类型。每一种都有自己的用例，但一般来说，你将要选择你要使用的是什么。

因此，让我们开始我们通过这些支持的协议的旅程，并学习如何配置它们。在我们讨论存储池之后，我们将讨论 NFS，这是一种典型的虚拟机存储的共享级协议。然后，我们将转向块级协议，如 iSCSI 和 FC。然后，我们将转向冗余和多路径，以增加我们存储设备的可用性和带宽。我们还将讨论不太常见的文件系统（如 Ceph、Gluster 和 GFS）在 KVM 虚拟化中的各种用例。我们还将讨论当前的事实趋势的新发展。

# 存储池

当你第一次开始使用存储设备时，即使它们是更便宜的盒子，你也会面临一些选择。他们会要求你进行一些配置——选择 RAID 级别、配置热备份、SSD 缓存……这是一个过程。同样的过程也适用于从头开始构建数据中心或扩展现有数据中心的情况。你必须配置存储才能使用它。

当涉及到存储时，虚拟化管理程序有点“挑剔”，因为它们支持一些存储类型，而不支持一些存储类型。例如，微软的 Hyper-V 支持 SMB 共享用于虚拟机存储，但实际上不支持 NFS 存储用于虚拟机存储。VMware 的 vSphere Hypervisor 支持 NFS，但不支持 SMB。原因很简单——一家开发虚拟化管理程序的公司选择并验证其虚拟化管理程序将支持的技术。然后，各种 HBA/控制器供应商（英特尔、Mellanox、QLogic 等）开发该虚拟化管理程序的驱动程序，存储供应商决定他们的存储设备将支持哪些存储协议。

从 CentOS 的角度来看，有许多不同类型的存储池得到支持。以下是其中一些：

+   基于**逻辑卷管理器**（**LVM**）的存储池

+   基于目录的存储池

+   基于分区的存储池

+   基于 GlusterFS 的存储池

+   基于 iSCSI 的存储池

+   基于磁盘的存储池

+   基于 HBA 的存储池，使用 SCSI 设备

从 libvirt 的角度来看，存储池可以是 libvirt 管理的目录、存储设备或文件。这导致了 10 多种不同的存储池类型，你将在下一节中看到。从虚拟机的角度来看，libvirt 管理虚拟机存储，虚拟机使用它来存储数据。

另一方面，oVirt 看待事情有所不同，因为它有自己的服务与 libvirt 合作，从数据中心的角度提供集中的存储管理。*数据中心的角度*可能听起来有点奇怪。但想想看——数据中心是一种*更高级*的对象，你可以在其中看到所有的资源。数据中心使用*存储*和*虚拟化平台*为我们提供虚拟化所需的所有服务——虚拟机、虚拟网络、存储域等。基本上，从数据中心的角度来看，你可以看到所有属于该数据中心成员的主机上发生了什么。然而，从主机级别来看，你无法看到另一个主机上发生了什么。从管理和安全的角度来看，这是一个完全合乎逻辑的层次结构。

oVirt 可以集中管理这些不同类型的存储池（随着时间的推移，列表可能会变得更长或更短）：

+   **网络文件系统**（**NFS**）

+   **并行 NFS**（**pNFS**）

+   iSCSI

+   FC

+   本地存储（直接连接到 KVM 主机）

+   GlusterFS 导出

+   符合 POSIX 的文件系统

让我们先搞清一些术语：

+   **Brtfs**是一种文件系统，支持快照、RAID 和类似 LVM 的功能、压缩、碎片整理、在线调整大小以及许多其他高级功能。在发现其 RAID5/6 很容易导致数据丢失后，它被弃用了。

+   **ZFS**是一种文件系统，支持 Brtfs 的所有功能，还支持读写缓存。

CentOS 有一种新的处理存储池的方式。虽然仍处于技术预览阶段，但通过这个名为**Stratis**的新工具进行完整配置是值得的。基本上，几年前，Red Hat 最终放弃了推动 Brtfs 用于未来版本的想法，开始致力于 Stratis。如果你曾经使用过 ZFS，那么这可能是类似的——一套易于管理的、类似 ZFS 的卷管理工具，Red Hat 可以在未来的发布中支持。此外，就像 ZFS 一样，基于 Stratis 的池可以使用缓存；因此，如果你有一块 SSD 想要专门用于池缓存，你也可以做到。如果你一直期待 Red Hat 支持 ZFS，那么有一个基本的 Red Hat 政策阻碍了这一点。具体来说，ZFS 不是 Linux 内核的一部分，主要是因为许可证的原因。Red Hat 对这些情况有一个政策——如果它不是内核的一部分（上游），那么他们就不提供也不支持。就目前而言，这不会很快发生。这些政策也反映在了 CentOS 中。

## 本地存储池

另一方面，Stratis 现在就可以使用。我们将使用它来管理我们的本地存储，创建存储池。创建池需要我们事先设置分区或磁盘。创建池后，我们可以在其上创建卷。我们只需要非常小心一件事——虽然 Stratis 可以管理 XFS 文件系统，但我们不应该直接从文件系统级别对 Stratis 管理的 XFS 文件系统进行更改。例如，不要使用基于 XFS 的命令直接重新配置或重新格式化基于 Stratis 的 XFS 文件系统，因为这会在系统上造成混乱。

Stratis 支持各种不同类型的块存储设备：

+   硬盘和固态硬盘

+   iSCSI LUNs

+   LVM

+   LUKS

+   MD RAID

+   设备映射器多路径

+   NVMe 设备

让我们从头开始安装 Stratis，以便我们可以使用它。我们使用以下命令：

```
yum -y install stratisd stratis-cli
systemctl enable --now stratisd
```

第一条命令安装了 Stratis 服务和相应的命令行实用程序。第二条命令将启动并启用 Stratis 服务。

现在，我们将通过一个完整的示例来介绍如何使用 Stratis 来配置您的存储设备。我们将介绍这种分层方法的一个示例。因此，我们将按照以下步骤进行：

+   使用 MD RAID 创建软件 RAID10 +备用

+   从 MD RAID 设备创建一个 Stratis 池。

+   向池中添加缓存设备以使用 Stratis 的缓存功能。

+   创建一个 Stratis 文件系统并将其挂载在我们的本地服务器上

这里的前提很简单——通过 MD RAID 的软件 RAID10+备用将近似于常规的生产方法，其中您将有某种硬件 RAID 控制器向系统呈现单个块设备。我们将向池中添加缓存设备以验证缓存功能，因为这是我们在使用 ZFS 时很可能会做的事情。然后，我们将在该池上创建一个文件系统，并通过以下命令将其挂载到本地目录：

```
mdadm --create /dev/md0 --verbose --level=10 --raid-devices=4 /dev/sdb /dev/sdc /dev/sdd /dev/sde --spare-devices=1 /dev/sdf2
stratis pool create PacktStratisPool01 /dev/md0
stratis pool add-cache PacktStratisPool01 /dev/sdg
stratis pool add-cache PacktStratisPool01 /dev/sdg
stratis fs create PackStratisPool01 PacktStratisXFS01
mkdir /mnt/packtStratisXFS01
mount /stratis/PacktStratisPool01/PacktStratisXFS01 /mnt/packtStratisXFS01
```

这个挂载的文件系统是 XFS 格式的。然后我们可以通过 NFS 导出轻松地使用这个文件系统，这正是我们将在 NFS 存储课程中要做的。但现在，这只是一个使用 Stratis 创建池的示例。

我们已经介绍了本地存储池的一些基础知识，这使我们更接近我们下一个主题，即如何从 libvirt 的角度使用存储池。因此，这将是我们下一个主题。

## Libvirt 存储池

Libvirt 管理自己的存储池，这是出于一个目的——为虚拟机磁盘和相关数据提供不同的存储池。考虑到 libvirt 使用底层操作系统支持的内容，它支持多种不同的存储池类型并不奇怪。一幅图值千言，这里有一个从 virt-manager 创建 libvirt 存储池的截图：

![图 5.1 - libvirt 支持的不同存储池类型](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/ms-kvm-vrt/img/B14834_05_01.jpg)

图 5.1 - libvirt 支持的不同存储池类型

libvirt 已经预先定义了一个默认存储池，这是本地服务器上的一个目录存储池。此默认池位于`/var/lib/libvirt/images`目录中。这代表了我们将保存所有本地安装的虚拟机的数据的默认位置。

在接下来的几节中，我们将创建各种不同类型的存储池——基于 NFS 的存储池，基于 iSCSI 和 FC 的存储池，以及 Gluster 和 Ceph 存储池：全方位的。我们还将解释何时使用每一种存储池，因为涉及到不同的使用模型。

# NFS 存储池

作为协议，NFS 自 80 年代中期以来就存在。最初由 Sun Microsystems 开发为共享文件的协议，直到今天仍在使用。实际上，它仍在不断发展，这对于一项如此“古老”的技术来说是相当令人惊讶的。例如，NFS 4.2 版本于 2016 年发布。在这个版本中，NFS 得到了很大的更新，例如以下内容：

+   服务器端复制：通过在 NFS 服务器之间直接进行克隆操作，显著提高了克隆操作的速度

+   稀疏文件和空间保留：增强了 NFS 处理具有未分配块的文件的方式，同时关注容量，以便在需要写入数据时保证空间可用性

+   应用程序数据块支持：一项帮助与文件作为块设备（磁盘）工作的应用程序的功能

+   更好的 pNFS 实现

v4.2 中还有其他一些增强的部分，但目前这已经足够了。您可以在 IETF 的 RFC 7862 文档中找到更多关于此的信息（[`tools.ietf.org/html/rfc7862`](https://tools.ietf.org/html/rfc7862)）。我们将专注于 NFS v4.2 的实现，因为这是 NFS 目前提供的最好的版本。它也恰好是 CentOS 8 支持的默认 NFS 版本。

我们首先要做的事情是安装必要的软件包。我们将使用以下命令来实现这一点：

```
yum -y install nfs-utils
systemctl enable --now nfs-server
```

第一条命令安装了运行 NFS 服务器所需的实用程序。第二条命令将启动它并永久启用它，以便在重新启动后 NFS 服务可用。

我们接下来的任务是配置我们将通过 NFS 服务器共享的内容。为此，我们需要*导出*一个目录，并使其在网络上对我们的客户端可用。NFS 使用一个配置文件`/etc/exports`来实现这个目的。假设我们想要创建一个名为`/exports`的目录，然后将其共享给我们在`192.168.159.0/255.255.255.0`网络中的客户端，并且我们希望允许他们在该共享上写入数据。我们的`/etc/exports`文件应该如下所示：

```
/mnt/packtStratisXFS01	192.168.159.0/24(rw)
exportfs -r
```

这些配置选项告诉我们的 NFS 服务器要导出哪个目录（`/exports`），导出到哪些客户端（`192.168.159.0/24`），以及使用哪些选项（`rw`表示读写）。

其他可用选项包括以下内容：

+   `ro`：只读模式。

+   `sync`：同步 I/O 操作。

+   `root_squash`：来自`UID 0`和`GID 0`的所有 I/O 操作都映射到可配置的匿名 UID 和 GID（`anonuid`和`anongid`选项）。

+   `all_squash`：来自任何 UID 和 GID 的所有 I/O 操作都映射到匿名 UID 和 GID（`anonuid`和`anongid`选项）。

+   `no_root_squash`：来自`UID 0`和`GID 0`的所有 I/O 操作都映射到`UID 0`和`GID 0`。

如果您需要将多个选项应用到导出的目录中，可以在它们之间用逗号添加，如下所示：

```
/mnt/packtStratisXFS01	192.168.159.0/24(rw,sync,root_squash)
```

您可以使用完全合格的域名或短主机名（如果它们可以通过 DNS 或任何其他机制解析）。此外，如果您不喜欢使用前缀（`24`），您可以使用常规的网络掩码，如下所示：

```
/mnt/packtStratisXFS01 192.168.159.0/255.255.255.0(rw,root_squash)
```

现在我们已经配置了 NFS 服务器，让我们看看我们将如何配置 libvirt 来使用该服务器作为存储池。和往常一样，有几种方法可以做到这一点。我们可以只创建一个包含池定义的 XML 文件，并使用`virsh pool-define --file`命令将其导入到我们的 KVM 主机中。以下是该配置文件的示例：

![图 5.2 - NFS 池的 XML 配置文件示例](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/ms-kvm-vrt/img/B14834_05_02.jpg)

图 5.2 - NFS 池的 XML 配置文件示例

让我们解释一下这些配置选项：

+   `池类型`：`netfs`表示我们将使用 NFS 文件共享。

+   `name`：池名称，因为 libvirt 使用池作为命名对象，就像虚拟网络一样。

+   `host`：我们正在连接的 NFS 服务器的地址。

+   `dir path`：我们在 NFS 服务器上通过`/etc/exports`配置的 NFS 导出路径。

+   `path`：我们的 KVM 主机上的本地目录，该 NFS 共享将被挂载到该目录。

+   `permissions`：用于挂载此文件系统的权限。

+   `owner`和`group`：用于挂载目的的 UID 和 GID（这就是为什么我们之前使用`no_root_squash`选项导出文件夹的原因）。

+   `label`：此文件夹的 SELinux 标签-我们将在*第十六章*，*KVM 平台故障排除指南*中讨论这个问题。

如果我们愿意，我们本可以通过虚拟机管理器 GUI 轻松地完成相同的事情。首先，我们需要选择正确的类型（NFS 池），并给它起一个名字：

![图 5.3 - 选择 NFS 池类型并给它命名](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/ms-kvm-vrt/img/B14834_05_03.jpg)

图 5.3 - 选择 NFS 池类型并给它命名

点击**前进**后，我们可以进入最后的配置步骤，需要告诉向导我们从哪个服务器挂载我们的 NFS 共享：

![图 5.4–配置 NFS 服务器选项](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/ms-kvm-vrt/img/B14834_05_04.jpg)

图 5.4–配置 NFS 服务器选项

当我们完成输入这些配置选项（**主机名**和**源路径**）后，我们可以点击**完成**，这意味着退出向导。此外，我们之前的配置屏幕，只包含**默认**存储池，现在也列出了我们新配置的存储池：

![图 5.5–新配置的 NFS 存储池在列表中可见](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/ms-kvm-vrt/img/B14834_05_05.jpg)

图 5.5–新配置的 NFS 存储池在列表中可见

我们何时在 libvirt 中使用基于 NFS 的存储池，以及为什么？基本上，我们可以很好地用它们来存储安装映像的任何相关内容——ISO 文件、虚拟软盘文件、虚拟机文件等等。

请记住，尽管似乎 NFS 在企业环境中几乎已经消失了一段时间，但 NFS 仍然存在。实际上，随着 NFS 4.1、4.2 和 pNFS 的引入，它在市场上的未来实际上看起来比几年前更好。这是一个非常熟悉的协议，有着非常悠久的历史，在许多场景中仍然具有竞争力。如果您熟悉 VMware 虚拟化技术，VMware 在 ESXi 6.0 中引入了一种称为虚拟卷的技术。这是一种基于对象的存储技术，可以同时使用基于块和 NFS 的协议作为其基础，这对于某些场景来说是一个非常引人注目的用例。但现在，让我们转向块级技术，比如 iSCSI 和 FC。

# iSCSI 和 SAN 存储

长期以来，使用 iSCSI 进行虚拟机存储一直是常规做法。即使考虑到 iSCSI 并不是处理存储的最有效方式这一事实，它仍然被广泛接受，你会发现它无处不在。效率受到两个原因的影响：

+   iSCSI 将 SCSI 命令封装成常规 IP 数据包，这意味着 IP 数据包有一个相当大的头部，这意味着分段和开销，这意味着效率较低。

+   更糟糕的是，它是基于 TCP 的，这意味着有序号和重传，这可能导致排队和延迟，而且环境越大，你通常会感觉到这些影响对虚拟机性能的影响越大。

也就是说，它基于以太网堆栈，使得部署基于 iSCSI 的解决方案更容易，同时也提供了一些独特的挑战。例如，有时很难向客户解释，在虚拟机流量和 iSCSI 流量使用相同的网络交换机并不是最好的主意。更糟糕的是，客户有时会因为渴望节省金钱而无法理解他们正在违背自己的最佳利益。特别是在涉及网络带宽时。我们大多数人都曾经历过这种情况，试图回答客户的问题，比如“但我们已经有了千兆以太网交换机，为什么你需要比这更快的东西呢？”

事实是，对于 iSCSI 的复杂性来说，更多就意味着更多。在磁盘/缓存/控制器方面拥有更快的速度，以及在网络方面拥有更多的带宽，就有更多的机会创建一个更快的存储系统。所有这些都可能对我们的虚拟机性能产生重大影响。正如您将在*存储冗余和多路径*部分中看到的那样，您实际上可以自己构建一个非常好的存储系统——无论是对于 iSCSI 还是 FC。当您尝试创建某种测试实验室/环境来发展您的 KVM 虚拟化技能时，这可能会非常有用。您可以将这些知识应用到其他虚拟化环境中。

iSCSI 和 FC 架构非常相似 - 它们都需要一个目标（iSCSI 目标和 FC 目标）和一个发起者（iSCS 发起者和 FC 发起者）。在这个术语中，目标是*服务器*组件，发起者是*客户端*组件。简单地说，发起者连接到目标以访问通过该目标呈现的块存储。然后，我们可以使用发起者的身份来*限制*发起者在目标上能够看到的内容。这就是当比较 iSCSI 和 FC 时术语开始有点不同的地方。

在 iSCSI 中，发起者的身份可以由四个不同的属性来定义。它们如下：

+   **iSCSI 合格名称**（**IQN**）：这是所有发起者和目标在 iSCSI 通信中都具有的唯一名称。我们可以将其与常规以太网网络中的 MAC 或 IP 地址进行比较。您可以这样想 - 对于以太网网络来说，IQN 就是 iSCSI 的 MAC 或 IP 地址。

+   **IP 地址**：每个发起者都有一个不同的 IP 地址，用于连接到目标。

+   **MAC 地址**：每个发起者在第 2 层都有一个不同的 MAC 地址。

+   **完全合格的域名**（**FQDN**）：这代表了服务器的名称，它是由 DNS 服务解析的。

从 iSCSI 目标的角度来看 - 根据其实现方式 - 您可以使用这些属性中的任何一个来创建一个配置，该配置将告诉 iSCSI 目标可以使用哪些 IQN、IP 地址、MAC 地址或 FQDN 来连接到它。这就是所谓的*掩码*，因为我们可以通过使用这些身份并将它们与 LUN 配对来*掩盖*发起者在 iSCSI 目标上可以*看到*的内容。LUN 只是我们通过 iSCSI 目标向发起者导出的原始块容量。LUN 通常是*索引*或*编号*的，通常从 0 开始。每个 LUN 编号代表发起者可以连接到的不同存储容量。

例如，我们可以有一个 iSCSI 目标，其中包含三个不同的 LUN - `LUN0`，容量为 20 GB，`LUN1`，容量为 40 GB，和`LUN2`，容量为 60 GB。这些都将托管在同一存储系统的 iSCSI 目标上。然后，我们可以配置 iSCSI 目标以接受一个 IQN 来查看所有 LUN，另一个 IQN 只能看到`LUN1`，另一个 IQN 只能看到`LUN1`和`LUN2`。这实际上就是我们现在要配置的。

让我们从配置 iSCSI 目标服务开始。为此，我们需要安装`targetcli`软件包，并配置服务（称为`target`）运行：

```
yum -y install targetcli
systemctl enable --now target
```

要注意防火墙配置；您可能需要配置它以允许在端口`3260/tcp`上进行连接，这是 iSCSI 目标门户使用的端口。因此，如果您的防火墙已启动，请输入以下命令：

```
firewall-cmd --permanent --add-port=3260/tcp ; firewall-cmd --reload
```

在 Linux 上，关于使用什么存储后端的 iSCSI 有三种可能性。我们可以使用常规文件系统（如 XFS）、块设备（硬盘）或 LVM。所以，这正是我们要做的。我们的情景将如下所示：

+   `LUN0`（20 GB）：基于 XFS 的文件系统，位于`/dev/sdb`设备上

+   `LUN1`（40 GB）：硬盘驱动器，位于`/dev/sdc`设备上

+   `LUN2`（60 GB）：LVM，位于`/dev/sdd`设备上

因此，在安装必要的软件包并配置目标服务和防火墙之后，我们应该开始配置我们的 iSCSI 目标。我们只需启动`targetcli`命令并检查状态，因为我们刚刚开始这个过程，状态应该是空白的：

![图 5.6 - targetcli 的起点 - 空配置](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/ms-kvm-vrt/img/B14834_05_06.jpg)

图 5.6 - targetcli 的起点 - 空配置

让我们从逐步的过程开始：

1.  因此，让我们配置基于 XFS 的文件系统，并配置`LUN0`文件映像保存在那里。首先，我们需要对磁盘进行分区（在我们的情况下是`/dev/sdb`）：![图 5.7 - 为 XFS 文件系统分区`/dev/sdb`](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/ms-kvm-vrt/img/B14834_05_07.jpg)

图 5.7 - 为 XFS 文件系统分区`/dev/sdb`

1.  接下来是格式化这个分区，创建并使用一个名为`/LUN0`的目录来挂载这个文件系统，并提供我们的`LUN0`镜像，我们将在接下来的步骤中进行配置：![图 5.8 - 格式化 XFS 文件系统，创建目录，并将其挂载到该目录](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/ms-kvm-vrt/img/B14834_05_08.jpg)

图 5.8 - 格式化 XFS 文件系统，创建目录，并将其挂载到该目录

1.  下一步是配置`targetcli`，使其创建`LUN0`并为`LUN0`分配一个镜像文件，该文件将保存在`/LUN0`目录中。首先，我们需要启动`targetcli`命令：![图 5.9 - 创建 iSCSI 目标，LUN0，并将其作为文件托管](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/ms-kvm-vrt/img/B14834_05_09.jpg)

图 5.9 - 创建 iSCSI 目标，LUN0，并将其作为文件托管

1.  接下来，让我们配置一个基于块设备的 LUN 后端— `LUN2`—它将使用`/dev/sdc1`（使用前面的示例创建分区）并检查当前状态：

![图 5.10 - 创建 LUN1，直接从块设备托管](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/ms-kvm-vrt/img/B14834_05_10.jpg)

图 5.10 - 创建 LUN1，直接从块设备托管

因此，`LUN0`和`LUN1`及其各自的后端现在已配置完成。让我们通过配置 LVM 来完成这些事情：

1.  首先，我们将准备 LVM 的物理卷，从该卷创建一个卷组，并显示有关该卷组的所有信息，以便我们可以看到我们有多少空间可用于`LUN2`：![图 5.11 - 为 LVM 配置物理卷，构建卷组，并显示有关该卷组的信息和显示有关该卷组的信息](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/ms-kvm-vrt/img/B14834_05_11.jpg)

图 5.11 - 为 LVM 配置物理卷，构建卷组，并显示有关该卷组的信息

1.  下一步是实际创建逻辑卷，这将是我们 iSCSI 目标中`LUN2`的块存储设备后端。我们可以从`vgdisplay`输出中看到我们有 15,359 个 4MB 块可用，所以让我们用它来创建我们的逻辑卷，称为`LUN2`。转到`targetcli`并配置`LUN2`的必要设置：![图 5.12 - 使用 LVM 后端配置 LUN2](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/ms-kvm-vrt/img/B14834_05_12.jpg)

图 5.12 - 使用 LVM 后端配置 LUN2

1.  让我们停在这里，转而转到 KVM 主机（iSCSI 发起者）的配置。首先，我们需要安装 iSCSI 发起者，这是一个名为`iscsi-initiator-utils`的软件包的一部分。因此，让我们使用`yum`命令来安装它：

```
yum -y install iscsi-initiator-utils
```

1.  接下来，我们需要配置我们发起者的 IQN。通常我们希望这个名称能让人联想到主机名，所以，看到我们主机的 FQDN 是`PacktStratis01`，我们将使用它来配置 IQN。为了做到这一点，我们需要编辑`/etc/iscsi/initiatorname.iscsi`文件并配置`InitiatorName`选项。例如，让我们将其设置为`iqn.2019-12.com.packt:PacktStratis01`。`/etc/iscsi/initiatorname.iscsi`文件的内容应该如下所示：

```
InitiatorName=iqn.2019-12.com.packt:PacktStratis01
```

1.  现在这已经配置好了，让我们回到 iSCSI 目标并创建一个**访问控制列表**（**ACL**）。ACL 将允许我们的 KVM 主机发起者连接到 iSCSI 目标门户：![图 5.13 - 创建 ACL，以便 KVM 主机的发起者可以连接到 iSCSI 目标](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/ms-kvm-vrt/img/B14834_05_13.jpg)

图 5.13 - 创建 ACL，以便 KVM 主机的发起者可以连接到 iSCSI 目标

1.  接下来，我们需要将我们预先创建的基于文件和基于块的设备发布到 iSCSI 目标 LUNs。因此，我们需要这样做：

![图 5.14 - 将我们的基于文件和基于块的设备添加到 iSCSI 目标 LUNs 0、1 和 2](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/ms-kvm-vrt/img/B14834_05_14.jpg)

图 5.14 - 将我们的基于文件和基于块的设备添加到 iSCSI 目标 LUNs 0、1 和 2

最终结果应该如下所示：

![图 5.15 - 最终结果](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/ms-kvm-vrt/img/B14834_05_15.jpg)

图 5.15 - 最终结果

此时，一切都已配置好。我们需要回到我们的 KVM 主机，并定义一个将使用这些 LUN 的存储池。做到这一点最简单的方法是使用一个 XML 配置文件来定义池。因此，这是我们的示例配置 XML 文件；我们将称其为`iSCSIPool.xml`：

```
<pool type='iscsi'>
  <name>MyiSCSIPool</name>
  <source>
    <host name='192.168.159.145'/>
    <device path='iqn.2003-01.org.linux-iscsi.packtiscsi01.x8664:sn.7b3c2efdbb11'/>
  </source>
  <initiator>
   <iqn name='iqn.2019-12.com.packt:PacktStratis01' />
</initiator>
  <target>
    <path>/dev/disk/by-path</path>
  </target>
</pool>
```

让我们一步一步地解释这个文件：

+   `池类型= 'iscsi'`：我们告诉 libvirt 这是一个 iSCSI 池。

+   `名称`：池名称。

+   `主机名`：iSCSI 目标的 IP 地址。

+   `设备路径`：iSCSI 目标的 IQN。

+   发起者部分的 IQN 名称：发起者的 IQN。

+   `目标路径`：iSCSI 目标的 LUN 将被挂载的位置。

现在，我们所要做的就是定义、启动和自动启动我们的新的基于 iSCSI 的 KVM 存储池：

```
virsh pool-define --file iSCSIPool.xml
virsh pool-start --pool MyiSCSIPool
virsh pool-autostart --pool MyiSCSIPool
```

配置的目标路径部分可以通过`virsh`轻松检查。如果我们在 KVM 主机上输入以下命令，我们将得到刚刚配置的`MyiSCSIPool`池中可用 LUN 的列表：

```
virsh vol-list --pool MyiSCSIPool
```

我们对此命令得到以下结果：

![图 5.16 - 我们 iSCSI 池 LUN 的运行时名称](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/ms-kvm-vrt/img/B14834_05_16.jpg)

图 5.16 - 我们 iSCSI 池 LUN 的运行时名称

如果这个输出让你有点想起 VMware vSphere Hypervisor 存储运行时名称，那么你肯定是对的。当我们开始部署我们的虚拟机时，我们将能够在*第七章*，*虚拟机-安装、配置和生命周期管理*中使用这些存储池。

# 存储冗余和多路径

冗余是 IT 的关键词之一，任何单个组件的故障都可能对公司或其客户造成重大问题。避免 SPOF 的一般设计原则是我们应该始终坚持的。归根结底，没有任何网络适配器、电缆、交换机、路由器或存储控制器会永远工作。因此，将冗余计算到我们的设计中有助于我们的 IT 环境在其正常生命周期内。

同时，冗余可以与多路径结合，以确保更高的吞吐量。例如，当我们将物理主机连接到具有每个四个 FC 端口的两个控制器的 FC 存储时，我们可以使用四条路径（如果存储是主备的）或八条路径（如果是主动-主动的）连接到从存储设备导出给主机的相同 LUN(s)。这为我们提供了多种额外的 LUN 访问选项，除了在故障情况下为我们提供更多的可用性外。

让一个普通的 KVM 主机执行，例如 iSCSI 多路径，是相当复杂的。在文档方面存在多个配置问题和空白点，这种配置的支持性是值得怀疑的。然而，有一些使用 KVM 的产品可以直接支持，比如 oVirt（我们之前介绍过）和**Red Hat 企业虚拟化 Hypervisor**（**RHEV-H**）。因此，让我们在 iSCSI 的例子中使用 oVirt。

在你这样做之前，请确保你已经完成了以下工作：

+   您的 Hypervisor 主机已添加到 oVirt 清单中。

+   您的 Hypervisor 主机有两个额外的网络卡，独立于管理网络。

+   iSCSI 存储在与两个额外的 Hypervisor 网络卡相同的 L2 网络中有两个额外的网络卡。

+   iSCSI 存储已经配置好，至少有一个目标和一个 LUN 已经配置好，这样就能使 Hypervisor 主机连接到它。

因此，当我们在 oVirt 中进行这项工作时，有一些事情是我们需要做的。首先，从网络的角度来看，为存储创建一些存储网络是一个好主意。在我们的情况下，我们将为 iSCSI 分配两个网络，并将它们称为`iSCSI01`和`iSCSI02`。我们需要打开 oVirt 管理面板，悬停在`iSCSI01`（第一个）上，取消选中`iSCSI02`网络：

![图 5.17 - 配置 iSCSI 绑定网络](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/ms-kvm-vrt/img/B14834_05_17.jpg)

图 5.17 - 配置 iSCSI 绑定网络

下一步是将这些网络分配给主机网络适配器。转到`compute/hosts`，双击您添加到 oVirt 清单的主机，选择第二个网络接口上的`iSCSI01`和第三个网络接口上的`iSCSI02`。第一个网络接口已被 oVirt 管理网络占用。它应该看起来像这样：

![图 5.18 - 将虚拟网络分配给 hypervisor 的物理适配器](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/ms-kvm-vrt/img/B14834_05_18.jpg)

图 5.18 - 将虚拟网络分配给 hypervisor 的物理适配器

在关闭窗口之前，请确保单击`iSCSI01`和`iSCSI02`上的*铅笔*图标，为这两个虚拟网络设置 IP 地址。分配可以将您连接到相同或不同子网上的 iSCSI 存储的网络配置：

![图 5.19 - 在数据中心级别创建 iSCSI 绑定](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/ms-kvm-vrt/img/B14834_05_19.jpg)

图 5.19 - 在数据中心级别创建 iSCSI 绑定

您刚刚配置了一个 iSCSI 绑定。我们配置的最后一部分是启用它。同样，在 oVirt GUI 中，转到**计算** | **数据中心**，双击选择您的数据中心，然后转到**iSCSI 多路径**选项卡：

![图 5.20 - 在数据中心级别配置 iSCSI 多路径](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/ms-kvm-vrt/img/B14834_05_20.jpg)

图 5.20 - 在数据中心级别配置 iSCSI 多路径

在弹出窗口的顶部部分单击`iSCSI01`和`iSCSI02`网络，然后在底部单击 iSCSI 目标。

现在我们已经介绍了存储池、NFS 和 iSCSI 的基础知识，我们可以继续使用标准的开源方式部署存储基础设施，即使用 Gluster 和/或 Ceph。

# Gluster 和 Ceph 作为 KVM 的存储后端

还有其他高级类型的文件系统可以用作 libvirt 存储后端。因此，让我们现在讨论其中的两种 - Gluster 和 Ceph。稍后，我们还将检查 libvirt 如何与 GFS2 一起使用。

## Gluster

Gluster 是一个经常用于高可用性场景的分布式文件系统。它相对于其他文件系统的主要优势在于，它是可扩展的，可以使用复制和快照，可以在任何服务器上工作，并且可用作共享存储的基础，例如通过 NFS 和 SMB。它是由一家名为 Gluster Inc.的公司开发的，该公司于 2011 年被 RedHat 收购。然而，与 Ceph 不同，它是一个*文件*存储服务，而 Ceph 提供*块*和*对象*为基础的存储。基于对象的存储对于基于块的设备意味着直接的二进制存储，直接到 LUN。这里没有涉及文件系统，理论上意味着由于没有文件系统、文件系统表和其他可能减慢 I/O 过程的构造，因此开销更小。

让我们首先配置 Gluster 以展示其在 libvirt 中的用途。在生产中，这意味着安装至少三台 Gluster 服务器，以便我们可以实现高可用性。Gluster 配置非常简单，在我们的示例中，我们将创建三台 CentOS 7 机器，用于托管 Gluster 文件系统。然后，我们将在我们的 hypervisor 主机上挂载该文件系统，并将其用作本地目录。我们可以直接从 libvirt 使用 GlusterFS，但是实现方式并不像通过 gluster 客户端服务使用它、将其挂载为本地目录并直接在 libvirt 中使用它作为目录池那样精致。

我们的配置将如下所示：

![图 5.21 - 我们 Gluster 集群的基本设置](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/ms-kvm-vrt/img/B14834_05_21.jpg)

图 5.21 - 我们 Gluster 集群的基本设置

因此，让我们投入生产。在配置 Gluster 并将其暴露给我们的 KVM 主机之前，我们必须在所有服务器上发出一系列大量的命令。让我们从`gluster1`开始。首先，我们将进行系统范围的更新和重启，以准备 Gluster 安装的核心操作系统。在所有三台 CentOS 7 服务器上输入以下命令：

```
yum -y install epel-release*
yum -y install centos-release-gluster7.noarch
yum -y update
yum -y install glusterfs-server
systemctl reboot
```

然后，我们可以开始部署必要的存储库和软件包，格式化磁盘，配置防火墙等。在所有服务器上输入以下命令：

```
mkfs.xfs /dev/sdb
mkdir /gluster/bricks/1 -p
echo '/dev/sdb /gluster/bricks/1 xfs defaults 0 0' >> /etc/fstab
mount -a
mkdir /gluster/bricks/1/brick
systemctl disable firewalld
systemctl stop firewalld
systemctl start glusterd
systemctl enable glusterd
```

我们还需要进行一些网络配置。如果这三台服务器可以*相互解析*，那将是很好的，这意味着要么配置一个 DNS 服务器，要么在我们的`/etc/hosts`文件中添加几行。我们选择后者。将以下行添加到您的`/etc/hosts`文件中：

```
192.168.159.147 gluster1
192.168.159.148 gluster2
192.168.159.149 gluster3
```

在配置的下一部分，我们只需登录到第一台服务器，并将其用作我们的 Gluster 基础设施的事实管理服务器。输入以下命令：

```
gluster peer probe gluster1
gluster peer probe gluster2
gluster peer probe gluster3
gluster peer status
```

前三个命令应该让您得到`peer probe: success`状态。第三个应该返回类似于这样的输出：

![图 5.22 - 确认 Gluster 服务器成功对等](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/ms-kvm-vrt/img/B14834_05_22.jpg)

图 5.22 - 确认 Gluster 服务器成功对等

现在配置的这一部分已经完成，我们可以创建一个 Gluster 分布式文件系统。我们可以通过输入以下命令序列来实现这一点：

```
gluster volume create kvmgluster replica 3 \ gluster1:/gluster/bricks/1/brick gluster2:/gluster/bricks/1/brick \ gluster3:/gluster/bricks/1/brick 
gluster volume start kvmgluster
gluster volume set kvmgluster auth.allow 192.168.159.0/24
gluster volume set kvmgluster allow-insecure on
gluster volume set kvmgluster storage.owner-uid 107
gluster volume set kvmgluster storage.owner-gid 107
```

然后，我们可以将 Gluster 挂载为 NFS 目录进行测试。例如，我们可以为所有成员主机（`gluster1`、`gluster2`和`gluster3`）创建一个名为`kvmgluster`的分布式命名空间。我们可以通过使用以下命令来实现这一点：

```
echo 'localhost:/kvmgluster /mnt glusterfs \ defaults,_netdev,backupvolfile-server=localhost 0 0' >> /etc/fstab
mount.glusterfs localhost:/kvmgluster /mnt
```

Gluster 部分现在已经准备就绪，所以我们需要回到我们的 KVM 主机，并通过输入以下命令将 Gluster 文件系统挂载到它上面：

```
wget \ https://download.gluster.org/pub/gluster/glusterfs/6/LATEST/CentOS/gl\ usterfs-rhel8.repo -P /etc/yum.repos.d
yum install glusterfs glusterfs-fuse attr -y
mount -t glusterfs -o context="system_u:object_r:virt_image_t:s0" \ gluster1:/kvmgluster /var/lib/libvirt/images/GlusterFS 
```

我们必须密切关注服务器和客户端上的 Gluster 版本，这就是为什么我们下载了 CentOS 8 的 Gluster 存储库信息（我们正在 KVM 服务器上使用它），并安装了必要的 Gluster 客户端软件包。这使我们能够使用最后一个命令挂载文件系统。

现在我们已经完成了配置，我们只需要将这个目录作为 libvirt 存储池添加进去。让我们通过使用一个包含以下条目的存储池定义的 XML 文件来做到这一点：

```
<pool type='dir'>
  <name>glusterfs-pool</name>
  <target>
    <path>/var/lib/libvirt/images/GlusterFS</path>
    <permissions>
      <mode>0755</mode>
      <owner>107</owner>
      <group>107</group>
      <label>system_u:object_r:virt_image_t:s0</label>
    </permissions>
  </target>
</pool> 
```

假设我们将这个文件保存在当前目录，并且文件名为`gluster.xml`。我们可以通过使用以下`virsh`命令将其导入并在 libvirt 中启动：

```
virsh pool-define --file gluster.xml
virsh pool-start --pool glusterfs-pool
virsh pool-autostart --pool glusterfs-pool
```

我们应该在启动时自动挂载这个存储池，以便 libvirt 可以使用它。因此，我们需要将以下行添加到`/etc/fstab`中：

```
gluster1:/kvmgluster       /var/lib/libvirt/images/GlusterFS \ glusterfs   defaults,_netdev  0  0
```

使用基于目录的方法使我们能够避免 libvirt（及其 GUI 界面`virt-manager`）在 Gluster 存储池方面存在的两个问题：

+   我们可以使用 Gluster 的故障转移功能，这将由我们直接安装的 Gluster 实用程序自动管理，因为 libvirt 目前还不支持它们。

+   我们将避免*手动*创建虚拟机磁盘，这是 libvirt 对 Gluster 支持的另一个限制，而基于目录的存储池则可以无任何问题地支持它。

我们提到*故障转移*似乎有点奇怪，因为似乎我们没有将它作为任何之前步骤的一部分进行配置。实际上，我们已经配置了。当我们发出最后一个挂载命令时，我们使用了 Gluster 的内置模块来建立与*第一个*Gluster 服务器的连接。这反过来意味着在建立这个连接之后，我们得到了关于整个 Gluster 池的所有细节，我们配置了它以便它托管在三台服务器上。如果发生任何故障—我们可以很容易地模拟—这个连接将继续工作。例如，我们可以通过关闭任何一个 Gluster 服务器来模拟这种情况—比如`gluster1`。您会看到我们挂载 Gluster 目录的本地目录仍然可以工作，即使`gluster1`已经关闭。让我们看看它的运行情况（默认超时时间为 42 秒）：

![图 5.23 - Gluster 故障转移工作；第一个节点已经关闭，但我们仍然能够获取我们的文件](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/ms-kvm-vrt/img/B14834_05_23.jpg)

图 5.23 - Gluster 故障转移工作；第一个节点已经关闭，但我们仍然能够获取我们的文件

如果我们想更积极一些，可以通过在任何一个 Gluster 服务器上发出以下命令来将此超时期缩短到——例如——2 秒：

```
gluster volume set kvmgluster network.ping-timeout number
```

`number`部分是以秒为单位的，通过分配一个较低的数字，我们可以直接影响故障切换过程的积极性。

因此，现在一切都配置好了，我们可以开始使用 Gluster 池部署虚拟机，我们将在*第七章*中进一步讨论，*虚拟机-安装、配置和生命周期管理*。

鉴于 Gluster 是一个基于文件的后端，可以用于 libvirt，自然而然地需要描述如何使用高级块级和对象级存储后端。这就是 Ceph 的用武之地，所以让我们现在来处理这个问题。

## Ceph

Ceph 可以作为文件、块和对象存储。但在大多数情况下，我们通常将其用作块或对象存储。同样，这是一款设计用于任何服务器（或虚拟机）的开源软件。在其核心，Ceph 运行一个名为**可控复制下可扩展哈希**（**CRUSH**）的算法。该算法试图以伪随机的方式在对象设备之间分发数据，在 Ceph 中，它由一个集群映射（CRUSH 映射）管理。我们可以通过添加更多节点轻松扩展 Ceph，这将以最小的方式重新分发数据，以确保尽可能少的复制。

一个名为**可靠自主分布式对象存储**（**RADOS**）的内部 Ceph 组件用于快照、复制和薄配置。这是一个由加利福尼亚大学开发的开源项目。

在架构上，Ceph 有三个主要服务：

+   **ceph-mon**：用于集群监控、CRUSH 映射和**对象存储守护程序**（**OSD**）映射。

+   **ceph-osd**：处理实际数据存储、复制和恢复。至少需要两个节点；出于集群化的原因，我们将使用三个。

+   **ceph-mds**：元数据服务器，在 Ceph 需要文件系统访问时使用。

根据最佳实践，确保您始终在设计 Ceph 环境时牢记关键原则——所有数据节点需要具有相同的配置。这意味着相同数量的内存、相同的存储控制器（如果可能的话，不要使用 RAID 控制器，只使用普通的 HBA 而不带 RAID 固件）、相同的磁盘等。这是确保您的环境中 Ceph 性能保持恒定水平的唯一方法。

Ceph 的一个非常重要的方面是数据放置和放置组的工作原理。放置组为我们提供了将创建的对象分割并以最佳方式放置在 OSD 中的机会。换句话说，我们配置的放置组数量越大，我们将获得的平衡就越好。

因此，让我们从头开始配置 Ceph。我们将再次遵循最佳实践，并使用五台服务器部署 Ceph——一台用于管理，一台用于监控，三个 OSD。

我们的配置将如下所示：

![图 5.24 - 我们基础设施的基本 Ceph 配置](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/ms-kvm-vrt/img/B14834_05_24.jpg)

图 5.24 - 我们基础设施的基本 Ceph 配置

确保这些主机可以通过 DNS 或`/etc/hosts`相互解析，并配置它们都使用相同的 NTP 源。确保通过以下方式更新所有主机：

```
yum -y update; reboot
```

此外，请确保您以*root*用户身份在所有主机上输入以下命令。让我们从部署软件包、创建管理员用户并赋予他们`sudo`权限开始：

```
rpm -Uhv http://download.ceph.com/rpm-jewel/el7/noarch/ceph-release-1-1.el7.noarch.rpm
yum -y install ceph-deploy ceph ceph-radosgw
useradd cephadmin
echo "cephadmin:ceph123" | chpasswd
echo "cephadmin ALL = (root) NOPASSWD:ALL" | sudo tee /etc/sudoers.d/cephadmin
chmod 0440 /etc/sudoers.d/cephadmin
```

对于这个演示来说，禁用 SELinux 会让我们的生活更轻松，摆脱防火墙也是如此。

```
sed -i 's/SELINUX=enforcing/SELINUX=disabled/g' /etc/selinux/config
systemctl stop firewalld
systemctl disable firewalld
systemctl mask firewalld
```

让我们将主机名添加到`/etc/hosts`中，以便我们更容易进行管理：

```
echo "192.168.159.150 ceph-admin" >> /etc/hosts
echo "192.168.159.151 ceph-monitor" >> /etc/hosts
echo "192.168.159.152 ceph-osd1" >> /etc/hosts
echo "192.168.159.153 ceph-osd2" >> /etc/hosts
echo "192.168.159.154 ceph-osd3" >> /etc/hosts
```

更改最后的`echo`部分以适应您的环境 - 主机名和 IP 地址。我们只是在这里举例说明。下一步是确保我们可以使用我们的管理主机连接到所有主机。最简单的方法是使用 SSH 密钥。因此，在`ceph-admin`上，以 root 身份登录并输入`ssh-keygen`命令，然后一直按*Enter*键。它应该看起来像这样：

![图 5.25-为 Ceph 设置目的为 root 生成 SSH 密钥](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/ms-kvm-vrt/img/B14834_05_25.jpg)

图 5.25-为 Ceph 设置目的为 root 生成 SSH 密钥

我们还需要将此密钥复制到所有主机。因此，再次在`ceph-admin`上，使用`ssh-copy-id`将密钥复制到所有主机：

```
ssh-copy-id cephadmin@ceph-admin
ssh-copy-id cephadmin@ceph-monitor
ssh-copy-id cephadmin@ceph-osd1
ssh-copy-id cephadmin@ceph-osd2
ssh-copy-id cephadmin@ceph-osd3
```

当 SSH 询问您时，请接受所有密钥，并使用我们在较早步骤中选择的`ceph123`作为密码。完成所有这些之后，在我们开始部署 Ceph 之前，`ceph-admin`还有最后一步要做 - 我们必须配置 SSH 以使用`cephadmin`用户作为默认用户登录到所有主机。我们将通过以 root 身份转到`ceph-admin`上的`.ssh`目录，并创建一个名为`config`的文件，并添加以下内容来完成这一步：

```
Host ceph-admin
        Hostname ceph-admin
        User cephadmin
Host ceph-monitor
        Hostname ceph-monitor
        User cephadmin
Host ceph-osd1
        Hostname ceph-osd1
        User cephadmin
Host ceph-osd2
        Hostname ceph-osd2
        User cephadmin
Host ceph-osd3
        Hostname ceph-osd3
        User cephadmin
```

那是一个很长的预配置，不是吗？现在是时候真正开始部署 Ceph 了。第一步是配置`ceph-monitor`。因此，在`ceph-admin`上输入以下命令：

```
cd /root
mkdir cluster
cd cluster
ceph-deploy new ceph-monitor
```

由于我们选择了一个配置，其中有三个 OSD，我们需要配置 Ceph 以便使用这另外两个主机。因此，在`cluster`目录中，编辑名为`ceph.conf`的文件，并在末尾添加以下两行：

```
public network = 192.168.159.0/24
osd pool default size = 2
```

这将确保我们只能使用我们的示例网络（`192.168.159.0/24`）进行 Ceph，并且我们在原始的基础上有两个额外的 OSD。

现在一切准备就绪，我们必须发出一系列命令来配置 Ceph。因此，再次在`ceph-admin`上输入以下命令：

```
ceph-deploy install ceph-admin ceph-monitor ceph-osd1 ceph-osd2 ceph-osd3
ceph-deploy mon create-initial
ceph-deploy gatherkeys ceph-monitor
ceph-deploy disk list ceph-osd1 ceph-osd2 ceph-osd3
ceph-deploy disk zap ceph-osd1:/dev/sdb  ceph-osd2:/dev/sdb  ceph-osd3:/dev/sdb
ceph-deploy osd prepare ceph-osd1:/dev/sdb ceph-osd2:/dev/sdb ceph-osd3:/dev/sdb
ceph-deploy osd activate ceph-osd1:/dev/sdb1 ceph-osd2:/dev/sdb1 ceph-osd3:/dev/sdb1
```

让我们逐一描述这些命令：

+   第一条命令启动实际的部署过程 - 用于管理、监视和 OSD 节点的安装所有必要的软件包。

+   第二个和第三个命令配置监视主机，以便它准备好接受外部连接。

+   这两个磁盘命令都是关于磁盘准备 - Ceph 将清除我们分配给它的磁盘（每个 OSD 主机的`/dev/sdb`）并在上面创建两个分区，一个用于 Ceph 数据，一个用于 Ceph 日志。

+   最后两个命令准备这些文件系统供使用并激活 Ceph。如果您的`ceph-deploy`脚本在任何时候停止，请检查您的 DNS 和`/etc/hosts`和`firewalld`配置，因为问题通常出现在那里。

我们需要将 Ceph 暴露给我们的 KVM 主机，这意味着我们需要进行一些额外的配置。我们将 Ceph 公开为对象池给我们的 KVM 主机，因此我们需要创建一个池。让我们称之为`KVMpool`。连接到`ceph-admin`，并发出以下命令：

```
ceph osd pool create KVMpool 128 128
```

此命令将创建一个名为`KVMpool`的池，其中包含 128 个放置组。

下一步涉及从安全角度接近 Ceph。我们不希望任何人连接到这个池，因此我们将为 Ceph 创建一个用于身份验证的密钥，我们将在 KVM 主机上用于身份验证。我们通过输入以下命令来做到这一点：

```
ceph auth get-or-create client.KVMpool mon 'allow r' osd 'allow rwx pool=KVMpool'
```

它将向我们抛出一个状态消息，类似于这样：

```
key = AQB9p8RdqS09CBAA1DHsiZJbehb7ZBffhfmFJQ==
```

然后我们可以切换到 KVM 主机，在那里我们需要做两件事：

+   定义一个秘密 - 一个将 libvirt 链接到 Ceph 用户的对象 - 通过这样做，我们将创建一个带有其**通用唯一标识符**（**UUID**）的秘密对象。

+   在定义 Ceph 存储池时，使用该秘密的 UUID 将其与 Ceph 密钥进行关联。

完成这两个步骤的最简单方法是使用两个 libvirt 的 XML 配置文件。因此，让我们创建这两个文件。让我们称第一个为`secret.xml`，以下是其内容：

```
   <secret ephemeral='no' private='no'>
   <usage type='ceph'>
     <name>client.KVMpool secret</name>
   </usage>
</secret>
```

确保您保存并导入此 XML 文件，输入以下命令：

```
virsh secret-define --file secret.xml
```

按下*Enter*键后，此命令将抛出一个 UUID。请将该 UUID 复制并粘贴到一个安全的地方，因为我们将需要它用于池 XML 文件。在我们的环境中，这个第一个`virsh`命令抛出了以下输出：

```
Secret 95b1ed29-16aa-4e95-9917-c2cd4f3b2791 created
```

我们需要为这个秘密分配一个值，这样当 libvirt 尝试使用这个秘密时，它就知道要使用哪个*密码*。这实际上是我们在 Ceph 级别创建的密码，当我们使用`ceph auth get-create`时，它会给我们抛出密钥。因此，现在我们既有秘密 UUID 又有 Ceph 密钥，我们可以将它们结合起来创建一个完整的认证对象。在 KVM 主机上，我们需要输入以下命令：

```
virsh secret-set-value 95b1ed29-16aa-4e95-9917-c2cd4f3b2791 AQB9p8RdqS09CBAA1DHsiZJbehb7ZBffhfmFJQ==
```

现在，我们可以创建 Ceph 池文件。让我们把配置文件命名为`ceph.xml`，以下是它的内容：

```
   <pool type="rbd">
     <source>
       <name>KVMpool</name>
       <host name='192.168.159.151' port='6789'/>
       <auth username='KVMpool' type='ceph'>
         <secret uuid='95b1ed29-16aa-4e95-9917-c2cd4f3b2791'/>
       </auth>
     </source>
   </pool>
```

因此，上一步的 UUID 被用于这个文件中，用来引用哪个秘密（身份）将被用于 Ceph 池访问。现在，如果我们想要永久使用它（在 KVM 主机重新启动后），我们需要执行标准程序——导入池，启动它，并自动启动它。因此，让我们在 KVM 主机上使用以下命令序列来执行：

```
virsh pool-define --file ceph.xml
virsh pool-start KVMpool
virsh pool-autostart KVMpool
virsh pool-list --details
```

最后一个命令应该产生类似于这样的输出：

![图 5.26-检查我们的池的状态；Ceph 池已配置并准备好使用](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/ms-kvm-vrt/img/B14834_05_26.jpg)

图 5.26-检查我们的池的状态；Ceph 池已配置并准备好使用

现在，Ceph 对象池对我们的 KVM 主机可用，我们可以在其上安装虚拟机。我们将在*第七章*中再次进行这项工作——*虚拟机-安装、配置和生命周期管理*。

# 虚拟磁盘镜像和格式以及基本的 KVM 存储操作

磁盘镜像是存储在主机文件系统上的标准文件。它们很大，作为客人的虚拟硬盘。您可以使用`dd`命令创建这样的文件，如下所示：

```
# dd if=/dev/zero of=/vms/dbvm_disk2.img bs=1G count=10
```

以下是这个命令的翻译：

从输入文件（`if`）`/dev/zero`（几乎无限的零）复制数据（`dd`）到输出文件（`of`）`/vms/dbvm_disk2.img`（磁盘镜像），使用 1G 大小的块（`bs` = 块大小），并重复这个操作（`count`）只一次（`10`）。

重要提示：

`dd`被认为是一个耗费资源的命令。它可能会在主机系统上引起 I/O 问题，因此最好先检查主机系统的可用空闲内存和 I/O 状态，然后再运行它。如果系统已经加载，降低块大小到 MB，并增加计数以匹配您想要的文件大小（使用`bs=1M`，`count=10000`，而不是`bs=1G`，`count=10`）。

`/vms/dbvm_disk2.img`是前面命令的结果。该镜像现在已经预分配了 10GB，并准备好与客人一起使用，无论是作为引导磁盘还是第二个磁盘。同样，您也可以创建薄配置的磁盘镜像。预分配和薄配置（稀疏）是磁盘分配方法，或者您也可以称之为格式：

+   **预分配**：预分配的虚拟磁盘在创建时立即分配空间。这通常意味着比薄配置的虚拟磁盘写入速度更快。

+   `dd`命令中的`seek`选项，如下所示：

```
dd if=/dev/zero of=/vms/dbvm_disk2_seek.imgbs=1G seek=10 count=0
```

每种方法都有其优缺点。如果您正在寻求 I/O 性能，选择预分配格式，但如果您有非 I/O 密集型负载，请选择薄配置。

现在，您可能想知道如何识别某个虚拟磁盘使用了什么磁盘分配方法。有一个很好的实用程序可以找出这一点：`qemu-img`。这个命令允许您读取虚拟镜像的元数据。它还支持创建新的磁盘和执行低级格式转换。

## 获取镜像信息

`qemu-img`命令的`info`参数显示有关磁盘镜像的信息，包括镜像的绝对路径、文件格式和虚拟和磁盘大小。通过从 QEMU 的角度查看虚拟磁盘大小，并将其与磁盘上的镜像文件大小进行比较，您可以轻松地确定正在使用的磁盘分配策略。例如，让我们看一下我们创建的两个磁盘镜像：

```
# qemu-img info /vms/dbvm_disk2.img
image: /vms/dbvm_disk2.img
file format: raw
virtual size: 10G (10737418240 bytes)
disk size: 10G
# qemu-img info /vms/dbvm_disk2_seek.img
image: /vms/dbvm_disk2_seek.img
file format: raw
virtual size: 10G (10737418240 bytes)
disk size: 10M
```

查看两个磁盘的“磁盘大小”行。对于`/vms/dbvm_disk2.img`，显示为`10G`，而对于`/vms/dbvm_disk2_seek.img`，显示为`10M` MiB。这种差异是因为第二个磁盘使用了薄配置格式。虚拟大小是客户看到的，磁盘大小是磁盘在主机上保留的空间。如果两个大小相同，这意味着磁盘是预分配的。差异意味着磁盘使用了薄配置格式。现在，让我们将磁盘镜像附加到虚拟机；您可以使用`virt-manager`或 CLI 替代方案`virsh`进行附加。

## 使用 virt-manager 附加磁盘

从主机系统的图形桌面环境启动 virt-manager。也可以使用 SSH 远程启动，如以下命令所示：

```
ssh -X host's address
[remotehost]# virt-manager
```

那么，让我们使用虚拟机管理器将磁盘附加到虚拟机：

1.  在虚拟机管理器的主窗口中，选择要添加辅助磁盘的虚拟机。

1.  转到虚拟硬件详细信息窗口，然后单击对话框底部左侧的“添加硬件”按钮。

1.  在“添加新虚拟硬件”中，选择“存储”，然后选择“为虚拟机创建磁盘镜像”按钮和虚拟磁盘大小，如下面的屏幕截图所示：![图 5.27 - 在 virt-manager 中添加虚拟磁盘](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/ms-kvm-vrt/img/B14834_05_27.jpg)

图 5.27 - 在 virt-manager 中添加虚拟磁盘

1.  如果要附加先前创建的`dbvm_disk2.img`镜像，选择`/vms`目录中的`dbvm_disk2.img`文件或在本地存储池中找到它，然后选择它并单击`/dev/sdb`）或磁盘分区（`/dev/sdb1`）或 LVM 逻辑卷。我们可以使用任何先前配置的存储池来存储此镜像，无论是作为文件还是对象，还是直接到块设备。

1.  点击`virsh`命令。

使用 virt-manager 创建虚拟磁盘非常简单——只需点击几下鼠标并输入一些内容。现在，让我们看看如何通过命令行来做到这一点，即使用`virsh`。

## 使用 virsh 附加磁盘

`virsh`是 virt-manager 的非常强大的命令行替代品。您可以在几秒钟内执行一个动作，而通过 virt-manager 等图形界面可能需要几分钟。它提供了`attach-disk`选项，用于将新的磁盘设备附加到虚拟机。与`attach-disk`一起提供了许多开关：

```
attach-disk domain source target [[[--live] [--config] | [--current]] | [--persistent]] [--targetbusbus] [--driver driver] [--subdriversubdriver] [--iothreadiothread] [--cache cache] [--type type] [--mode mode] [--sourcetypesourcetype] [--serial serial] [--wwnwwn] [--rawio] [--address address] [--multifunction] [--print-xml]
```

然而，在正常情况下，以下内容足以对虚拟机执行热添加磁盘附加：

```
# virsh attach-disk CentOS8 /vms/dbvm_disk2.img vdb --live --config
```

在这里，`CentOS8`是执行磁盘附加的虚拟机。然后是磁盘镜像的路径。`vdb`是目标磁盘名称，在宿主操作系统中可见。`--live`表示在虚拟机运行时执行操作，`--config`表示在重新启动后持久地附加它。不添加`--config`开关将使磁盘仅在重新启动前附加。

重要提示：

热插拔支持：在 Linux 宿主操作系统中加载`acpiphp`内核模块以识别热添加的磁盘；`acpiphp`提供传统的热插拔支持，而`pciehp`提供本地的热插拔支持。`pciehp`依赖于`acpiphp`。加载`acpiphp`将自动加载`pciehp`作为依赖项。

您可以使用`virsh domblklist <vm_name>`命令快速识别附加到虚拟机的 vDisks 数量。以下是一个示例：

```
# virsh domblklist CentOS8 --details
Type Device Target Source
------------------------------------------------
file disk vda /var/lib/libvirt/images/fedora21.qcow2
file disk vdb /vms/dbvm_disk2_seek.img
```

这清楚地表明连接到虚拟机的两个 vDisks 都是文件映像。它们分别显示为客户操作系统的`vda`和`vdb`，并且在主机系统上的磁盘映像路径的最后一列中可见。

接下来，我们将看到如何创建 ISO 库。

## 创建 ISO 镜像库

虚拟机上的客户操作系统虽然可以通过将主机的 CD/DVD 驱动器传递到虚拟机来从物理媒体安装，但这并不是最有效的方法。从 DVD 驱动器读取比从硬盘读取 ISO 文件慢，因此更好的方法是将用于安装操作系统和虚拟机应用程序的 ISO 文件（或逻辑 CD）存储在基于文件的存储池中，并创建 ISO 镜像库。

要创建 ISO 镜像库，可以使用 virt-manager 或`virsh`命令。让我们看看如何使用`virsh`命令创建 ISO 镜像库：

1.  首先，在主机系统上创建一个目录来存储`.iso`镜像：

```
# mkdir /iso
```

1.  设置正确的权限。它应该由 root 用户拥有，权限设置为`700`。如果 SELinux 处于强制模式，则需要设置以下上下文：

```
# chmod 700 /iso
# semanage fcontext -a -t virt_image_t "/iso(/.*)?"
```

1.  使用`virsh`命令定义 ISO 镜像库，如下面的代码块所示：

```
iso_library to demonstrate how to create a storage pool that will hold ISO images, but you are free to use any name you wish.
```

1.  验证是否已创建池（ISO 镜像库）：

```
# virsh pool-info iso_library
Name: iso_library
UUID: 959309c8-846d-41dd-80db-7a6e204f320e
State: running
Persistent: yes
Autostart: no
Capacity: 49.09 GiB
Allocation: 8.45 GiB
Available: 40.64 GiB
```

1.  现在可以将`.iso`镜像复制或移动到`/iso_lib`目录中。

1.  将`.iso`文件复制到`/iso_lib`目录后，刷新池，然后检查其内容：

```
# virsh pool-refresh iso_library
Pool iso_library refreshed
# virsh vol-list iso_library
Name Path
------------------------------------------------------------------
------------
CentOS8-Everything.iso /iso/CentOS8-Everything.iso
CentOS7-EVerything.iso /iso/CentOS7-Everything.iso
RHEL8.iso /iso/RHEL8.iso
Win8.iso /iso/Win8.iso
```

1.  这将列出存储在目录中的所有 ISO 镜像，以及它们的路径。这些 ISO 镜像现在可以直接与虚拟机一起用于客户操作系统的安装、软件安装或升级。

在今天的企业中，创建 ISO 镜像库是一种事实上的规范。最好有一个集中的地方存放所有的 ISO 镜像，并且如果需要在不同位置进行同步（例如`rsync`），这样做会更容易。

## 删除存储池

删除存储池相当简单。请注意，删除存储域不会删除任何文件/块设备。它只是将存储从 virt-manager 中断开。文件/块设备必须手动删除。

我们可以通过 virt-manager 或使用`virsh`命令删除存储池。让我们首先看看如何通过 virt-manager 进行操作：

![图 5.28–删除存储池](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/ms-kvm-vrt/img/B14834_05_28.jpg)

图 5.28–删除存储池

首先，选择红色停止按钮停止池，然后单击带有**X**的红色圆圈以删除池。

如果要使用`virsh`，那就更简单了。假设我们要删除上一个截图中名为`MyNFSpool`的存储池。只需输入以下命令：

```
virsh pool-destroy MyNFSpool
virsh pool-undefine MyNFSpool
```

创建存储池后的下一个逻辑步骤是创建存储卷。从逻辑上讲，存储卷将存储池划分为较小的部分。现在让我们学习如何做到这一点。

## 创建存储卷

存储卷是在存储池之上创建的，并作为虚拟磁盘附加到虚拟机。为了创建存储卷，启动存储管理控制台，导航到 virt-manager，然后单击**编辑** | **连接详细信息** | **存储**，并选择要创建新卷的存储池。单击创建新卷按钮（**+**）：

![图 5.29–为虚拟机创建存储卷](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/ms-kvm-vrt/img/B14834_05_29.jpg)

图 5.29–为虚拟机创建存储卷

接下来，提供新卷的名称，选择磁盘分配格式，并单击`virsh`命令。libvirt 支持几种磁盘格式（`raw`、`cow`、`qcow`、`qcow2`、`qed`和`vmdk`）。使用适合您环境的磁盘格式，并在`最大容量`和`分配`字段中设置适当的大小，以决定您是否希望选择预分配的磁盘分配或薄置备。如果在`qcow2`格式中保持磁盘大小不变，则不支持厚磁盘分配方法。

在[*第八章*]（B14834_08_Final_ASB_ePub.xhtml#_idTextAnchor143）*创建和修改 VM 磁盘、模板和快照*中，详细解释了所有磁盘格式。现在，只需了解`qcow2`是为 KVM 虚拟化专门设计的磁盘格式。它支持创建内部快照所需的高级功能。

## 使用 virsh 命令创建卷

使用`virsh`命令创建卷的语法如下：

```
# virsh vol-create-as dedicated_storage vm_vol1 10G
```

这里，`dedicated_storage`是存储池，`vm_vol1`是卷名称，10 GB 是大小。

```
# virsh vol-info --pool dedicated_storage vm_vol1
Name: vm_vol1
Type: file
Capacity: 1.00 GiB
Allocation: 1.00 GiB
```

`virsh`命令和参数用于创建存储卷，几乎不管它是在哪种类型的存储池上创建的，都几乎相同。只需输入适当的输入以使用`--pool`开关。现在，让我们看看如何使用`virsh`命令删除卷。

## 使用 virsh 命令删除卷

使用`virsh`命令删除卷的语法如下：

```
# virsh vol-delete dedicated_storage vm_vol2
```

执行此命令将从`dedicated_storage`存储池中删除`vm_vol2`卷。

我们存储之旅的下一步是展望未来，因为本章提到的所有概念多年来都广为人知，甚至有些已经有几十年的历史了。存储世界正在改变，朝着新的有趣方向发展，让我们稍微讨论一下。

# 存储的最新发展 - NVMe 和 NVMeOF

在过去的 20 年左右，就技术而言，存储世界最大的颠覆是**固态硬盘**（**SSD**）的引入。现在，我们知道很多人已经习惯在他们的计算机上使用它们 - 笔记本电脑、工作站，无论我们使用哪种类型的设备。但是，我们正在讨论虚拟化的存储和企业存储概念，这意味着我们常规的 SATA SSD 不够用。尽管很多人在中档存储设备和/或手工制作的存储设备中使用它们来托管 ZFS 池（用于缓存），但这些概念在最新一代存储设备中有了自己的生命。这些设备从根本上改变了技术的工作方式，并在现代 IT 历史的某些部分进行了重塑，包括使用的协议、速度有多快、延迟有多低，以及它们如何处理存储分层 - 分层是一个区分不同存储设备或它们的存储池的概念，通常是速度的能力。

让我们简要解释一下我们正在讨论的内容，通过一个存储世界的发展方向的例子。除此之外，存储世界正在带动虚拟化、云和 HPC 世界一起前进，因此这些概念并不离奇。它们已经存在于现成的存储设备中，您今天就可以购买到。

SSD 的引入显著改变了我们访问存储设备的方式。这一切都关乎性能和延迟，而像**高级主机控制器接口**（**AHCI**）这样的旧概念，我们今天市场上仍在积极使用，已经不足以处理 SSD 的性能。AHCI 是常规硬盘（机械硬盘或常规磁头）通过软件与 SATA 设备通信的标准方式。然而，关键部分是*硬盘*，这意味着圆柱、磁头扇区—这些 SSD 根本没有，因为它们不会旋转，也不需要那种范式。这意味着必须创建另一个标准，以便我们可以更本地地使用 SSD。这就是**非易失性内存扩展**（**NVMe**）的全部内容—弥合 SSD 的能力和实际能力之间的差距，而不使用从 SATA 到 AHCI 到 PCI Express（等等）的转换。

SSD 的快速发展速度和 NVMe 的整合使企业存储取得了巨大的进步。这意味着必须发明新的控制器、新的软件和完全新的架构来支持这种范式转变。随着越来越多的存储设备为各种目的集成 NVMe—主要是用于缓存，然后也用于存储容量—变得清楚的是，还有其他问题需要解决。其中第一个问题是我们将如何连接提供如此巨大能力的存储设备到我们的虚拟化、云或 HPC 环境。

在过去的 10 年左右，许多人争论说 FC 将从市场上消失，许多公司对不同的标准进行了押注—iSCSI、iSCSI over RDMA、NFS over RDMA 等。这背后的推理似乎足够坚实：

+   FC 很昂贵——它需要单独的物理交换机、单独的布线和单独的控制器，所有这些都需要花费大量的钱。

+   涉及许可证—当你购买一个拥有 40 个 FC 端口的 Brocade 交换机时，并不意味着你可以立即使用所有端口，因为需要许可证来获取更多端口（8 端口、16 端口等）。

+   FC 存储设备昂贵，并且通常需要更昂贵的磁盘（带有 FC 连接器）。

+   配置 FC 需要广泛的知识和/或培训，因为你不能简单地去配置一堆 FC 交换机给一个企业级公司，而不知道概念和交换机供应商的 CLI，还要知道企业的需求。

+   作为一种协议，FC 加速发展以达到新的速度的能力一直很差。简单来说，在 FC 从 8 Gbit/s 加速到 32 Gbit/s 的时间内，以太网从 1 Gbit/s 加速到 25、40、50 和 100 Gbit/s 的带宽。已经有关于 400 Gbit/s 以太网的讨论，也有第一个支持该标准的设备。这通常会让客户感到担忧，因为更高的数字意味着更好的吞吐量，至少在大多数人的想法中是这样。

但市场上*现在*发生的事情告诉我们一个完全不同的故事—不仅 FC 回来了，而且它回来了有使命。企业存储公司已经接受了这一点，并开始推出具有*疯狂*性能水平的存储设备（首先是 NVMe SSD 的帮助）。这种性能需要转移到我们的虚拟化、云和 HPC 环境中，这需要最佳的协议，以实现最低的延迟、设计、质量和可靠性，而 FC 具备所有这些。

这导致了第二阶段，NVMe SSD 不仅被用作缓存设备，而且也被用作容量设备。

请注意，目前存储内存/存储互连市场上正在酝酿一场大战。有多种不同的标准试图与英特尔的**快速路径互连**（**QPI**）竞争，这项技术已经在英特尔 CPU 中使用了十多年。如果这是你感兴趣的话题，本章末尾有一个链接，在*进一步阅读*部分，你可以找到更多信息。基本上，QPI 是一种点对点互连技术，具有低延迟和高带宽，是当今服务器的核心。具体来说，它处理 CPU 之间、CPU 和内存、CPU 和芯片组等之间的通信。这是英特尔在摆脱**前端总线**（**FSB**）和芯片组集成内存控制器后开发的技术。FSB 是一个在内存和 I/O 请求之间共享的总线。这种方法具有更高的延迟，不易扩展，带宽较低，并且在内存和 I/O 端发生大量 I/O 的情况下存在问题。在切换到内存控制器成为 CPU 的一部分的架构后（因此，内存直接连接到它），对于英特尔最终转向这种概念是至关重要的。

如果你更熟悉 AMD CPU，QPI 对英特尔来说就像内置内存控制器的 CPU 上的 HyperTransport 总线对 AMD CPU 来说一样。

随着 NVMe SSD 变得更快，PCI Express 标准也需要更新，这就是为什么最新版本（PCIe 4.0 - 最新产品最近开始发货）如此受期待的原因。但现在，焦点已经转移到需要解决的另外两个问题。让我们简要描述一下：

+   第一个问题很简单。对于普通计算机用户，在 99%或更多的情况下，一两个 NVMe SSD 就足够了。实际上，普通计算机用户需要更快的 PCIe 总线的唯一真正原因是为了更快的显卡。但对于存储制造商来说，情况完全不同。他们希望生产企业存储设备，其中将有 20、30、50、100、500 个 NVMe SSD 在一个存储系统中-他们希望现在就能做到这一点，因为 SSD 作为一种技术已经成熟并且广泛可用。

+   第二个问题更为复杂。更令人沮丧的是，最新一代的 SSD（例如基于英特尔 Optane 的 SSD）可以提供更低的延迟和更高的吞吐量。随着技术的发展，这种情况只会变得更糟（更低的延迟，更高的吞吐量）。对于今天的服务-虚拟化、云和 HPC-存储系统能够处理我们可能投入其中的任何负载是至关重要的。这些技术在存储设备变得更快的程度上是真正的游戏改变者，只要互连能够处理它（QPI、FC 等）。从英特尔 Optane 衍生出的两个概念-**存储级内存**（**SCM**）和**持久内存**（**PM**）是存储公司和客户希望快速采用到他们的存储系统中的最新技术。

+   第三个问题是如何将所有这些带宽和 I/O 能力传输到使用它们的服务器和基础设施。这就是为什么创建了**NVMe over Fabrics**（**NVMe-OF**）的概念，试图在存储基础设施堆栈上工作，使 NVMe 对其消费者更加高效和快速。

从概念上看，几十年来，RAM 样的内存是我们拥有的最快、最低延迟的技术。逻辑上，我们正在尽可能地将工作负载转移到 RAM。想想内存数据库（如 Microsoft SQL、SAP Hana 和 Oracle）。它们已经存在多年了。

这些技术从根本上改变了我们对存储的看法。基本上，我们不再讨论基于技术（SSD 与 SAS 与 SATA）或纯粹速度的存储分层，因为速度是不容置疑的。最新的存储技术讨论存储分层是基于*延迟*。原因非常简单——假设你是一个存储公司，你建立了一个使用 50 个 SCM SSD 作为容量的存储系统。对于缓存，唯一合理的技术将是 RAM，数百 GB 的 RAM。你能够在这样的设备上使用存储分层的唯一方法就是通过在软件中*模拟*它，通过创建额外的技术来产生基于排队、处理缓存（RAM）中的优先级和类似概念的分层式服务。为什么？因为如果你使用相同的 SCM SSD 作为容量，并且它们提供相同的速度和 I/O，你就无法基于技术或能力进行分层。

让我们通过使用一个可用的存储系统来进一步解释这一点。最好的设备来阐明我们的观点是戴尔/EMC 的 PowerMax 系列存储设备。如果你用 NVMe 和 SCM SSD 装载它们，最大型号（8000）可以扩展到 1500 万 IOPS(!)，350GB/s 吞吐量，低于 100 微秒的延迟，容量高达 4PB。想一想这些数字。然后再加上另一个数字——在前端，它可以有高达 256 个 FC/FICON/iSCSI 端口。就在最近，戴尔/EMC 发布了新的 32 Gbit/s FC 模块。较小的 PowerMax 型号（2000）可以做到 750 万 IOPS，低于 100 微秒的延迟，并扩展到 1PB。它还可以做所有*通常的 EMC 功能*——复制、压缩、去重、快照、NAS 功能等等。所以，这不仅仅是市场宣传；这些设备已经存在，并被企业客户使用：

![图 3.30 – PowerMax 2000 – 看起来很小，但功能强大](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/ms-kvm-vrt/img/B14834_05_30.jpg)

图 3.30 – PowerMax 2000 – 看起来很小，但功能强大

这些对于未来非常重要，因为越来越多的制造商生产类似的设备（它们正在途中）。我们完全期待基于 KVM 的世界在大规模环境中采用这些概念，特别是对于具有 OpenStack 和 OpenShift 基础设施的情况。

# 总结

在本章中，我们介绍并配置了 libvirt 的各种开源存储概念。我们还讨论了行业标准的方法，比如 iSCSI 和 NFS，因为它们经常在不基于 KVM 的基础设施中使用。例如，基于 VMware vSphere 的环境可以使用 FC、iSCSI 和 NFS，而基于 Microsoft 的环境只能使用 FC 和 iSCSI，从我们在本章中涵盖的主题列表中选择。

下一章将涵盖与虚拟显示设备和协议相关的主题。我们将深入介绍 VNC 和 SPICE 协议。我们还将描述其他用于虚拟机连接的协议。所有这些将帮助我们理解我们在过去三章中涵盖的与虚拟机一起工作所需的完整基础知识栈。

# 问题

1.  什么是存储池？

1.  NFS 存储如何与 libvirt 一起工作？

1.  iSCSI 如何与 libvirt 一起工作？

1.  我们如何在存储连接上实现冗余？

1.  除了 NFS 和 iSCSI，我们可以用什么来作为虚拟机存储？

1.  我们可以使用哪种存储后端来进行基于对象的存储与 libvirt 的连接？

1.  我们如何创建一个虚拟磁盘映像以供 KVM 虚拟机使用？

1.  使用 NVMe SSD 和 SCM 设备如何改变我们创建存储层的方式？

1.  为虚拟化、云和 HPC 环境提供零层存储服务的基本问题是什么？

# 进一步阅读

有关本章涵盖内容的更多信息，请参考以下链接：

+   RHEL8 文件系统和存储的新功能：[`www.redhat.com/en/blog/whats-new-rhel-8-file-systems-and-storage`](https://www.redhat.com/en/blog/whats-new-rhel-8-file-systems-and-storage)

+   oVirt 存储：[`www.ovirt.org/documentation/administration_guide/#chap-Storage`](https://www.ovirt.org/documentation/administration_guide/#chap-Storage)

+   RHEL 7 存储管理指南：[`access.redhat.com/documentation/en-us/red_hat_enterprise_linux/7/html/storage_administration_guide/index`](https://access.redhat.com/documentation/en-us/red_hat_enterprise_linux/7/html/storage_administration_guide/index)

+   RHEL 8 管理存储设备：[`access.redhat.com/documentation/en-us/red_hat_enterprise_linux/8/html/managing_storage_devices/index`](https://access.redhat.com/documentation/en-us/red_hat_enterprise_linux/8/html/managing_storage_devices/index)

+   OpenFabrics CCIX，Gen-Z，OpenCAPI（概述和比较）：[`www.openfabrics.org/images/eventpresos/2017presentations/213_CCIXGen-Z_BBenton.pdf`](https://www.openfabrics.org/images/eventpresos/2017presentations/213_CCIXGen-Z_BBenton.pdf)


# 第六章：虚拟显示设备和协议

在本章中，我们将讨论通过虚拟图形卡和协议访问虚拟机的方式。我们可以在虚拟机中使用近 10 种可用的虚拟显示适配器，并且有多种可用的协议和应用程序可以用来访问我们的虚拟机。除了 SSH 和任何一般的基于控制台的访问，市场上还有各种协议可供我们使用来访问虚拟机的控制台，如 VNC、SPICE 和 noVNC。

在基于 Microsoft 的环境中，我们倾向于使用**远程桌面协议**（**RDP**）。如果我们谈论**虚拟桌面基础设施**（**VDI**），那么甚至有更多的协议可用 - **PC over IP**（**PCoIP**）、VMware Blast 等等。其中一些技术提供了额外的功能，如更大的色深、加密、音频和文件系统重定向、打印机重定向、带宽管理以及 USB 和其他端口重定向。这些是当今云计算世界中远程桌面体验的关键技术。

所有这些意味着我们必须花更多的时间和精力去了解各种显示设备和协议，以及如何配置和使用它们。我们不希望出现这样的情况，即因为选择了错误的虚拟显示设备而无法看到虚拟机的显示，或者尝试打开控制台查看虚拟机内容时控制台无法打开的情况。

在本章中，我们将涵盖以下主题：

+   使用虚拟机显示设备

+   讨论远程显示协议

+   使用 VNC 显示协议

+   使用 SPICE 显示协议

+   使用 NoVNC 实现显示可移植性

+   让我们开始吧！

# 使用虚拟机显示设备

为了使虚拟机上的图形工作，QEMU 需要为其虚拟机提供两个组件：虚拟图形适配器和从客户端访问图形的方法或协议。让我们讨论这两个概念，从虚拟图形适配器开始。最新版本的 QEMU 有八种不同类型的虚拟/仿真图形适配器。所有这些都有一些相似之处和差异，这些差异可能是在功能和/或支持的分辨率方面，或者其他更多技术细节方面。因此，让我们描述它们，并看看我们将为特定虚拟图形卡偏爱哪些用例：

+   **tcx**：一种 SUN TCX 虚拟图形卡，可用于旧的 SUN 操作系统。

+   **cirrus**：一种基于旧的 Cirrus Logic GD5446 VGA 芯片的虚拟图形卡。它可以与 Windows 95 之后的任何客户操作系统一起使用。

+   **std**：一种标准的 VGA 卡，可用于 Windows XP 之后的客户操作系统的高分辨率模式。

+   **vmware**：VMware 的 SVGA 图形适配器，在 Linux 客户操作系统中需要额外的驱动程序和 Windows 操作系统中需要安装 VMware Tools。

+   **QXL**：事实上的标准半虚拟图形卡，当我们使用 SPICE 远程显示协议时需要使用，我们稍后将在本章中详细介绍。这个虚拟图形卡的旧版本称为 QXL VGA，它缺少一些更高级的功能，但提供更低的开销（使用更少的内存）。

+   **Virtio**：一种基于 virgl 项目的半虚拟 3D 虚拟图形卡，为 QEMU 客户操作系统提供 3D 加速。它有两种不同的类型（VGA 和 gpu）。virtio-vga 通常用于需要多显示器支持和 OpenGL 硬件加速的情况。virtio-gpu 版本没有内置的标准 VGA 兼容模式。

+   **cg3**：一种虚拟图形卡，可用于较旧的基于 SPARC 的客户操作系统。

+   **none**：禁用客户操作系统中的图形卡。

在配置虚拟机时，您可以在启动或创建虚拟机时选择这些选项。在 CentOS 8 中，分配给新创建的虚拟机的默认虚拟图形卡是**QXL**，如下面的新虚拟机配置的屏幕截图所示：

![图 6.1 - 客户操作系统的默认虚拟图形卡 - QXL](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/ms-kvm-vrt/img/B14834_06_01.jpg)

图 6.1 - 客户操作系统的默认虚拟图形卡 - QXL

此外，默认情况下，我们可以为任何给定的虚拟机选择这三种类型的虚拟图形卡，因为这些通常已经预先安装在为虚拟化配置的任何 Linux 服务器上：

+   QXL

+   VGA

+   Virtio

在 KVM 虚拟化中运行的一些新操作系统不应该使用旧的图形卡适配器，原因有很多。例如，自从 Red Hat Enterprise Linux/CentOS 7 以来，有一个建议不要为 Windows 10 和 Windows Server 2016 使用 cirrus 虚拟图形卡。原因是虚拟机的不稳定性，以及 - 例如 - 您无法使用 cirrus 虚拟图形卡进行全高清分辨率显示。以防万一您开始安装这些客户操作系统，请确保您使用 QXL 视频图形卡，因为它提供了最佳性能和与 SPICE 远程显示协议的兼容性。

从理论上讲，您仍然可以为一些*非常*老的客户操作系统（旧的 Windows NT，如 4.0 和旧的客户操作系统，如 Windows XP）使用 cirrus 虚拟图形卡，但仅限于此。对于其他所有情况，最好使用 std 或 QXL 驱动程序，因为它们提供了最佳的性能和加速支持。此外，这些虚拟图形卡还提供更高的显示分辨率。

QEMU 还提供了一些其他虚拟图形卡，例如各种**片上系统**（**SoC**）设备的嵌入式驱动程序，ati vga，bochs 等。其中一些经常被使用，比如 SoCs - 只需记住世界上所有的树莓派和 BBC Micro:bits。这些新的虚拟图形选项还通过**物联网**（**IoT**）得到进一步扩展。因此，有很多很好的理由让我们密切关注这个市场空间中发生的事情。

让我们通过一个例子来展示这一点。假设我们想创建一个新的虚拟机，并为其分配一组自定义参数，以便我们访问其虚拟显示。如果您还记得*第三章*，*安装 KVM Hypervisor、libvirt 和 ovirt*，我们讨论了各种 libvirt 管理命令（`virsh`、`virt-install`），并使用`virt-install`创建了一些虚拟机和一些自定义参数。让我们在这些基础上添加一些内容，并使用一个类似的例子：

```
virt-install --virt-type=kvm --name MasteringKVM01 --vcpus 2  --ram 4096 --os-variant=rhel8.0 --/iso/CentOS-8-x86_64-1905-dvd1.iso --network=default --video=vga --graphics vnc,password=Packt123 --disk size=16
```

以下是将要发生的事情：

![图 6.2 - 创建了一个带有 VGA 虚拟图形卡的 KVM 虚拟机。在这里，VNC 要求指定密码](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/ms-kvm-vrt/img/B14834_06_02.jpg)

图 6.2 - 创建了一个带有 VGA 虚拟图形卡的 KVM 虚拟机。在这里，VNC 要求指定密码

在我们输入密码（`Packt123`，如在 virt-install 配置选项中指定的那样）之后，我们面对这个屏幕：

![图 6.3 - VGA 显示适配器及其低默认（640x480）初始分辨率 - 对于在 80 年代长大的我们来说是一个熟悉的分辨率](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/ms-kvm-vrt/img/B14834_06_03.jpg)

图 6.3 - VGA 显示适配器及其低默认（640x480）初始分辨率 - 对于在 80 年代长大的我们来说是一个熟悉的分辨率

也就是说，我们只是用这个作为一个例子，来展示如何向`virt-install`命令添加一个高级选项 - 具体来说，如何使用特定的虚拟图形卡安装虚拟机。

还有其他更高级的概念，即使用我们在计算机或服务器上安装的真实图形卡，将它们的*功能*直接转发给虚拟机。这对于 VDI 等概念非常重要，正如我们之前提到的。让我们讨论一下这些概念，并使用一些真实世界的例子和比较来理解大规模 VDI 解决方案的复杂性。

## VDI 场景中的物理和虚拟图形卡

正如我们在《第一章》中讨论的那样，《理解 Linux 虚拟化》，VDI 是一个利用虚拟化范式来为客户端操作系统提供服务的概念。这意味着最终用户通过运行客户端操作系统（例如 Windows 8.1、Windows 10 或 Linux Mint）*直接*连接到他们的虚拟机，这些虚拟机要么是*专门*为他们保留的，要么是*共享*的，这意味着多个用户可以访问相同的虚拟机并通过额外的 VDI 功能访问它们的*数据*。

现在，如果我们谈论大多数商业用户，他们只需要我们开玩笑称之为*打字机*的东西。这种使用模式涉及用户使用客户端操作系统阅读和撰写文件、电子邮件和浏览互联网。对于这些用例，如果我们要使用任何供应商的解决方案（VMware 的 Horizon、Citrix 的 Xen Desktop 或微软基于远程桌面服务的 VDI 解决方案），我们可以使用其中任何一个。

然而，有一个很大的*但是*。如果场景包括数百名需要访问 2D 和/或 3D 视频加速的用户会发生什么？如果我们正在为一个创建设计的公司设计 VDI 解决方案——比如建筑、管道、石油和天然气以及视频制作？基于 CPU 和软件虚拟图形卡的 VDI 解决方案在这种情况下将毫无作为，特别是在大规模情况下。这就是 Xen Desktop 和 Horizon 在技术水平上要更加功能丰富的地方。而且，说实话，基于 KVM 的方法在显示选项方面并不逊色，只是在一些其他企业级功能上稍显不足，我们将在后面的章节中讨论这些功能，比如《第十二章》，*使用 OpenStack 扩展 KVM*。

基本上，我们可以使用三个概念来获得虚拟机的图形卡性能：

+   我们可以使用基于 CPU 的软件渲染器。

+   我们可以为特定的虚拟机保留一个 GPU（PCI 直通）。

+   我们可以*分区*一个 GPU，这样我们可以在多个虚拟机中使用它。

仅使用 VMware Horizon 解决方案作为比喻，这些解决方案将被称为 CPU 渲染、**虚拟直接图形加速**（**vDGA**）和**虚拟共享图形加速**（**vSGA**）。或者在 Citrix 中，我们会谈论 HDX 3D Pro。在 CentOS 8 中，我们在共享图形卡方案中谈论*中介设备*。

如果我们谈论 PCI 直通，它绝对能提供最佳性能，因为你可以使用 PCI-Express 图形卡，直接转发给虚拟机，在客户操作系统内安装本机驱动程序，并完全拥有图形卡。但这会带来四个问题：

+   你只能将 PCI-Express 图形卡转发给*一个*虚拟机。

+   由于服务器在升级方面可能存在限制，例如，你不能像在一台物理服务器上那样运行 50 个虚拟机，因为你无法在单个服务器上放置 50 个图形卡——无论是从物理上还是从 PCI-Express 插槽上来看，通常情况下在一个典型的 2U 机架服务器上最多只有六个。

+   如果你使用刀片服务器（例如，HP c7000），情况会更糟，因为如果你要使用额外的图形卡，那么每个刀片机箱的服务器密度将减半，因为这些卡只能安装在双高刀片上。

+   如果您要将任何这类解决方案扩展到数百个虚拟桌面，甚至更糟的是数千个虚拟桌面，您将花费大量资金。

如果我们谈论的是一种共享方法，即将物理图形卡分区，以便在多个虚拟机中使用它，那么这将产生另一组问题：

+   在选择要使用的图形卡方面，您的选择要受到更多限制，因为可能只有大约 20 种图形卡支持这种使用模式（其中一些包括 NVIDIA GRID、Quadro、Tesla 卡以及几张 AMD 和英特尔卡）。

+   如果您与四、八、十六或三十二个虚拟机共享同一块图形卡，您必须意识到您的性能会降低，因为您正在与多个虚拟机共享同一块 GPU。

+   与 DirectX、OpenGL、CUDA 和视频编码卸载的兼容性可能不如您期望的那样好，您可能会被迫使用这些标准的较旧版本。

+   可能会涉及额外的许可证，这取决于供应商和解决方案。

我们列表上的下一个主题是如何更高级地使用 GPU - 通过使用 GPU 分区概念将 GPU 的部分提供给多个虚拟机。让我们解释一下这是如何工作的，并通过使用 NVIDIA GPU 作为示例来配置它。

使用 NVIDIA vGPU 作为示例的 GPU 分区

让我们使用一个示例来看看我们如何使用分区我们的 GPU（NVIDIA vGPU）与我们基于 KVM 的虚拟机。这个过程与我们在*第四章*中讨论的 SR-IOV 过程非常相似，*Libvirt Networking*，在那里我们使用受支持的英特尔网络卡将虚拟功能呈现给我们的 CentOS 主机，然后通过将它们用作 KVM 虚拟桥的上行链路来呈现给我们的虚拟机。

首先，我们需要检查我们有哪种类型的显卡，它必须是受支持的（在我们的情况下，我们使用的是 Tesla P4）。让我们使用`lshw`命令来检查我们的显示设备，它应该看起来类似于这样：

```
# yum -y install lshw
# lshw -C display
*-display
       description: 3D controller
       product: GP104GL [Tesla P4]
       vendor: NVIDIA Corporation
       physical id: 0
       bus info: pci@0000:01:00.0
       version: a0
       width: 64 bits
       clock: 33MHz
       capabilities: pm msi pciexpress cap_list
       configuration: driver=vfio-pci latency=0
       resources: irq:15 memory:f6000000-f6ffffff memory:e0000000-efffffff memory:f0000000-f1ffffff
```

这个命令的输出告诉我们我们有一个支持 3D 的 GPU - 具体来说，是基于 NVIDIA GP104GL 的产品。它告诉我们这个设备已经在使用`vfio-pci`驱动程序。这个驱动程序是**虚拟化功能**（**VF**）的本机 SR-IOV 驱动程序。这些功能是 SR-IOV 功能的核心。我们将使用这个 SR-IOV 兼容的 GPU 来描述这一点。

我们需要做的第一件事 - 我们所有的 NVIDIA GPU 用户多年来一直在做的事情 - 是将 nouveau 驱动程序列入黑名单，因为它会妨碍我们。如果我们要永久使用 GPU 分区，我们需要永久地这样做，这样在服务器启动时就不会加载它。但要警告一下 - 这有时会导致意外行为，比如服务器启动时没有任何输出而没有任何真正的原因。因此，我们需要为`modprobe`创建一个配置文件，将 nouveau 驱动程序列入黑名单。让我们在`/etc/modprobe.d`目录中创建一个名为`nouveauoff.conf`的文件，内容如下：

```
blacklist nouveau
options nouveau modeset 0
```

然后，我们需要强制服务器重新创建在服务器启动时加载的`initrd`映像，并重新启动服务器以使更改生效。我们将使用`dracut`命令来执行此操作，然后是常规的`reboot`命令：

```
# dracut –-regenerate-all –force
# systemctl reboot
```

重新启动后，让我们检查 NVIDIA 图形卡的`vfio`驱动程序是否已加载，如果已加载，请检查 vGPU 管理器服务：

```
# lsmod | grep nvidia | grep vfio
nvidia_vgpu_vfio 45011 0
nvidia 14248203 10 nvidia_vgpu_vfio
mdev 22078 2 vfio_mdev,nvidia_vgpu_vfio
vfio 34373 3 vfio_mdev,nvidia_vgpu_vfio,vfio_iommu_type1
# systemctl status nvidia-vgpu-mgr
vidia-vgpu-mgr.service - NVIDIA vGPU Manager Daemon
   Loaded: loaded (/usr/lib/systemd/system/nvidia-vgpu-mgr.service; enabled; vendor preset: disabled)
   Active: active (running) since Thu 2019-12-12 20:17:36 CET; 0h 3min ago
 Main PID: 1327 (nvidia-vgpu-mgr)
```

我们需要创建一个 UUID，我们将使用它来向 KVM 虚拟机呈现我们的虚拟功能。我们将使用`uuidgen`命令来执行此操作：

```
uuidgen
c7802054-3b97-4e18-86a7-3d68dff2594d
```

现在，让我们使用这个 UUID 来为将共享我们的 GPU 的虚拟机。为此，我们需要创建一个 XML 模板文件，然后以复制粘贴的方式将其添加到我们虚拟机的现有 XML 文件中。让我们称之为`vsga.xml`：

```
<hostdev mode='subsystem' type='mdev' managed='no' model='vfio-pci'>
  <source>
    <address uuid='c7802054-3b97-4e18-86a7-3d68dff2594d'/>
  </source>
</hostdev>
```

使用这些设置作为模板，只需将完整内容复制粘贴到任何虚拟机的 XML 文件中，您希望访问我们共享的 GPU。

我们需要讨论的下一个概念是 SR-IOV 的完全相反，其中我们将设备切片成多个部分，以将这些部分呈现给虚拟机。在 GPU 直通中，我们将*整个*设备直接呈现给*一个*对象，即一个虚拟机。让我们学习如何配置它。

## GPU PCI 直通

与每个高级功能一样，启用 GPU PCI 直通需要按顺序完成多个步骤。通过按照正确的顺序执行这些步骤，我们直接将这个硬件设备呈现给虚拟机。让我们解释这些配置步骤并执行它们：

1.  要启用 GPU PCI 直通，我们需要在服务器的 BIOS 中配置和启用 IOMMU，然后在 Linux 发行版中启用。我们使用基于 Intel 的服务器，因此我们需要向`/etc/default/grub`文件中添加`iommu`选项，如下截图所示：![图 6.4 - 向 GRUB 文件添加 intel_iommu iommu=pt 选项](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/ms-kvm-vrt/img/B14834_06_04.jpg)

图 6.4 - 向 GRUB 文件添加 intel_iommu iommu=pt 选项

1.  下一步是重新配置 GRUB 配置并重新启动它，可以通过输入以下命令来实现：

```
# grub2-mkconfig -o /etc/grub2.cfg
# systemctl reboot
```

1.  重新启动主机后，我们需要获取一些信息 - 具体来说，是关于我们要转发到虚拟机的 GPU 设备的 ID 信息。让我们这样做：![](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/ms-kvm-vrt/img/B14834_06_05.jpg)

图 6.5 - 使用 lspci 显示相关配置信息

在我们的用例中，我们希望将 Quadro 2000 卡转发到我们的虚拟机，因为我们正在使用 GT740 连接我们的显示器，而 Quadro 卡目前没有任何工作负载或连接。因此，我们需要记下两个数字；即`0000:05:00.0`和`10de:0dd8`。

我们将需要这两个 ID 继续前进，每个 ID 用于定义我们要使用的设备和位置。

1.  下一步是向我们的主机操作系统解释，它不会为自己使用这个 PCI Express 设备（Quadro 卡）。为了做到这一点，我们需要再次更改 GRUB 配置，并向同一文件(`/etc/defaults/grub`)添加另一个参数：![](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/ms-kvm-vrt/img/B14834_06_06.jpg)

```
# grub2-mkconfig -o /etc/grub2.cfg
# systemctl reboot
```

这一步标志着*物理*服务器配置的结束。现在，我们可以继续进行下一阶段的过程，即如何在虚拟机中使用现在完全配置的 PCI 直通设备。

1.  让我们通过使用`virsh nodedev-dumpxml`命令检查是否一切都正确完成了，检查 PCI 设备 ID：![图 6.7 - 检查 KVM 堆栈是否能看到我们的 PCIe 设备](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/ms-kvm-vrt/img/B14834_06_07.jpg)

图 6.7 - 检查 KVM 堆栈是否能看到我们的 PCIe 设备

在这里，我们可以看到 QEMU 看到了两个功能：`0x1`和`0x0`。`0x1`功能实际上是 GPU 设备的*音频*芯片，我们不会在我们的过程中使用它。我们只需要`0x0`功能，即 GPU 本身。这意味着我们需要屏蔽它。我们可以通过使用以下命令来实现：

![图 6.8 - 分离 0x1 设备，以便它不能用于直通](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/ms-kvm-vrt/img/B14834_06_08.jpg)

图 6.8 - 分离 0x1 设备，以便它不能用于直通

1.  现在，让我们通过 PCI 直通将 GPU 添加到我们的虚拟机。为此，我们使用了一个名为`MasteringKVM03`的新安装的虚拟机，但您可以使用任何您想要的虚拟机。我们需要创建一个 XML 文件，QEMU 将使用它来知道要添加到虚拟机的设备。之后，我们需要关闭机器并将该 XML 文件导入到我们的虚拟机中。在我们的情况下，XML 文件将如下所示：![图 6.9 - 用于 KVM 的 GPU PCI 直通定义的 XML 文件](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/ms-kvm-vrt/img/B14834_06_09.jpg)

图 6.9 - 用于 KVM 的 GPU PCI 直通定义的 XML 文件

1.  下一步是将这个 XML 文件附加到`MasteringKVM03`虚拟机上。我们可以使用`virsh attach-device`命令来实现这一点：![图 6.10-将 XML 文件导入域/虚拟机](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/ms-kvm-vrt/img/B14834_06_10.jpg)

图 6.10-将 XML 文件导入域/虚拟机

1.  在上一步之后，我们可以启动虚拟机，登录，并检查虚拟机是否看到了我们的 GPU：

![图 6.11-检查虚拟机中 GPU 的可见性](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/ms-kvm-vrt/img/B14834_06_11.jpg)

图 6.11-检查虚拟机中 GPU 的可见性

下一个合乎逻辑的步骤将是为 Linux 安装这张卡的 NVIDIA 驱动程序，这样我们就可以自由地将其用作我们的独立 GPU。

现在，让我们继续讨论与远程显示协议相关的另一个重要主题。在本章的前一部分中，我们也围绕这个主题打转了一下，但现在我们要正面对待它。

# 讨论远程显示协议

正如我们之前提到的，有不同的虚拟化解决方案，因此访问虚拟机的方法也是多种多样的。如果你看一下虚拟机的历史，你会发现有许多不同的显示协议来解决这个特定的问题。因此，让我们稍微讨论一下这段历史。

## 远程显示协议历史

会有人对这个前提提出异议，但远程协议最初是文本协议。无论你怎么看，串行、文本模式终端在微软、苹果和基于 UNIX 的世界中的 X Windows 或任何类似 GUI 的东西出现之前就已经存在了。此外，你无法否认的是 telnet 和 rlogin 协议也用于访问远程显示。恰巧我们通过 telnet 和 rlogin 访问的远程显示是基于文本的显示。同样的情况也适用于 SSH。串行终端、文本控制台和 telnet、rlogin 等基于文本的协议是一些最常用的起点，可以追溯到上世纪 70 年代。

20 世纪 70 年代末是计算机历史上的重要时刻，因为当时有许多尝试为大量人群开始大规模生产个人计算机（例如，1977 年的 Apple II）。在 20 世纪 80 年代，人们开始更多地使用个人计算机，任何 Amiga、Commodore、Atari、Spectrum 或 Amstrad 的粉丝都会告诉你。请记住，真正的、公开可用的基于 GUI 的操作系统直到 Xerox Star（1981）和 Apple Lisa（1983）才开始出现。第一个广泛可用的基于苹果的 GUI 操作系统是 1984 年的 Mac OS System 1.0。大多数其他先前提到的计算机都在使用基于文本的操作系统。即使是那个时代的游戏（以及很多年后的游戏）看起来都像是手绘的。Amiga 的 Workbench 1.0 于 1985 年发布，其 GUI 和颜色使用模型使其领先于时代。然而，1985 年可能会因为另一件事而被记住-这是第一个微软 Windows 操作系统（v1.0）发布的年份。后来，它变成了 Windows 2.0（1987）、Windows 3.0（1990）、Windows 3.1（1992），到那时微软已经开始在操作系统世界中掀起风暴。是的，其他制造商也有其他操作系统：

+   苹果：Mac OS System 7 (1991)

+   IBM: OS/2 v1 (1988), v1.2 (1989), v2.0 (1992), Warp 4 (1996)

所有这些与 1995 年发生的大风暴相比只是一个小点。那一年，微软推出了 Windows 95。这是微软首个能够默认启动到 GUI 的客户端操作系统，因为之前的版本都是从命令行启动的。然后是 Windows 98 和 XP，这意味着微软获得了更多的市场份额。后来的故事可能非常熟悉，包括 Vista、Windows 7、Windows 8 和 Windows 10。

这个故事的重点不是教你有关操作系统历史本身的知识。它是关于注意到趋势，这足够简单。我们从命令行中的文本界面开始（例如，IBM 和 MS DOS，早期的 Windows，Linux，UNIX，Amiga，Atari 等）。然后，我们慢慢地转向更加视觉化的界面（GUI）。随着网络、GPU、CPU 和监控技术的进步，我们已经达到了一个阶段，我们希望拥有一个闪亮的、4K 分辨率的显示器，4 兆像素的分辨率，低延迟，强大的 CPU 性能，出色的颜色以及特定的用户体验。这种用户体验需要是即时的，而且我们使用本地操作系统或远程操作系统（VDI、云或其他背景技术）并不重要。

这意味着除了我们刚提到的所有硬件组件之外，还需要开发其他（软件）组件。具体来说，需要开发的是高质量的远程显示协议，这些协议现在必须能够扩展到基于浏览器的使用模型。人们不想被迫安装额外的应用程序（客户端）来访问他们的远程资源。

## 远程显示协议的类型

让我们只提一下目前市场上非常活跃的一些协议：

+   Microsoft 远程桌面协议/Remote FX：由远程桌面连接使用，这种多通道协议允许我们连接到基于 Microsoft 的虚拟机。

+   VNC：Virtual Network Computing 的缩写，这是一个远程桌面共享系统，用于传输鼠标和键盘事件以访问远程机器。

+   SPICE：独立计算环境的简单协议的缩写，这是另一种远程显示协议，可用于访问远程机器。它是由 Qumranet 开发的，后来被 Red Hat 收购。

如果我们进一步扩展我们的协议列表，用于 VDI 的协议，那么列表将进一步增加：

+   Teradici PCoIP（PC over IP）：基于 UDP 的 VDI 协议，我们可以使用它来访问 VMware、Citrix 和基于 Microsoft 的 VDI 解决方案上的虚拟机

+   VMware Blast Extreme：VMware 针对 VMware Horizon 基于 VDI 解决方案的 PcoIP 的答案

+   Citrix HDX：Citrix 用于虚拟桌面的协议。

当然，还有其他可用但使用较少且不太重要的协议，例如以下内容：

+   Colorado CodeCraft

+   OpenText Exceed TurboX

+   NoMachine

+   FreeNX

+   Apache Guacamole

+   Chrome 远程桌面

+   Miranex

常规远程协议和完整功能的 VDI 协议之间的主要区别与附加功能有关。例如，在 PCoIP、Blast Extreme 和 HDX 上，您可以微调带宽设置，控制 USB 和打印机重定向（手动或通过策略集中控制），使用多媒体重定向（以卸载媒体解码），Flash 重定向（以卸载 Flash），客户端驱动器重定向，串口重定向等等。例如，您无法在 VNC 或远程桌面上执行其中一些操作。

话虽如此，让我们讨论一下开源世界中最常见的两种：VNC 和 SPICE。

# 使用 VNC 显示协议

当通过 libvirt 启用 VNC 图形服务器时，QEMU 将将图形输出重定向到其内置的 VNC 服务器实现。VNC 服务器将监听 VNC 客户端可以连接的网络端口。

以下屏幕截图显示了如何添加 VNC 图形服务器。只需转到**虚拟机管理器**，打开虚拟机的设置，然后转到左侧的**显示 Spice**选项卡：

![图 6.12 - 用于 KVM 虚拟机的 VNC 配置](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/ms-kvm-vrt/img/B14834_06_12.jpg)

图 6.12 - 用于 KVM 虚拟机的 VNC 配置

添加 VNC 图形时，您将看到前面截图中显示的选项：

+   **类型**：图形服务器的类型。这里是**VNC 服务器**。

+   **地址**：VNC 服务器监听地址。它可以是全部、本地主机或 IP 地址。默认情况下，它是**仅本地主机**。

+   端口：VNC 服务器监听端口。您可以选择自动，其中 libvirt 根据可用性定义端口，或者您可以自己定义一个。确保它不会产生冲突。

+   **密码**：保护 VNC 访问的密码。

+   `virt-xml`命令行工具。

例如，让我们向名为`PacktGPUPass`的虚拟机添加 VNC 图形，然后修改其 VNC 监听 IP 为`192.168.122.1`：

```
# virt-xml MasteringKVM03 --add-device --graphics type=vnc
# virt-xml MasteringKVM03 --edit --graphics listen=192.168.122.1
```

这是在`PacktVM01` XML 配置文件中的外观：

```
<graphics type='vnc' port='-1' autoport='yes' listen='192.168.122.1'>
    <listen type='address' address='192.168.122.1'/>
</graphics>
```

您还可以使用`virsh`编辑`PacktGPUPass`并单独更改参数。

## 为什么使用 VNC？

当您在局域网上访问虚拟机或直接从控制台访问 VM 时，可以使用 VNC。使用 VNC 在公共网络上暴露虚拟机不是一个好主意，因为连接没有加密。如果虚拟机是没有安装 GUI 的服务器，VNC 是一个不错的选择。另一个支持 VNC 的点是客户端的可用性。您可以从任何操作系统平台访问虚拟机，因为该平台将有适用于该平台的 VNC 查看器。

# 使用 SPICE 显示协议

与 KVM 一样，**独立计算环境的简单协议**（**SPICE**）是进入开源虚拟化技术的最佳创新之一。它推动了开源虚拟化技术向大规模**虚拟桌面基础设施**（**VDI**）的实施。

重要说明

Qumranet 最初在 2007 年将 SPICE 作为闭源代码库开发。Red Hat，Inc.在 2008 年收购了 Qumranet，并于 2009 年 12 月决定在开源许可下发布代码并将协议视为开放标准。

SPICE 是 Linux 上唯一可用的开源解决方案，可以实现双向音频。它具有高质量的 2D 渲染能力，可以利用客户端系统的视频卡。SPICE 还支持多个高清监视器、加密、智能卡身份验证、压缩和网络上传输的 USB。有关完整的功能列表，您可以访问[`www.spice-space.org/features.html`](http://www.spice-space.org/features.html)。如果您是开发人员，并且想了解 SPICE 的内部情况，请访问[`www.spice-space.org/documentation.html`](http://www.spice-space.org/documentation.html)。如果您计划进行 VDI 或安装需要 GUI 的虚拟机，SPICE 是您的最佳选择。

在某些较旧的虚拟机上，SPICE 可能与一些较旧的虚拟机不兼容，因为它们不支持 QXL。在这些情况下，您可以将 SPICE 与其他通用虚拟视频卡一起使用。

现在，让我们学习如何向我们的虚拟机添加 SPICE 图形服务器。这可以被认为是开源世界中性能最佳的虚拟显示协议。

## 添加 SPICE 图形服务器

Libvirt 现在选择 SPICE 作为大多数虚拟机安装的默认图形服务器。您必须按照我们之前提到的 VNC 相同的程序来添加 SPICE 图形服务器。只需在下拉菜单中将 VNC 更改为 SPICE。在这里，您将获得一个额外的选项来选择**TLS 端口**，因为 SPICE 支持加密：

![图 6.13–KVM 虚拟机的 SPICE 配置](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/ms-kvm-vrt/img/B14834_06_13.jpg)

图 6.13–KVM 虚拟机的 SPICE 配置

要进入此配置窗口，只需编辑虚拟机的设置。转到**显示 Spice**选项，并从下拉菜单中选择**Spice 服务器**。所有其他选项都是可选的，因此您不一定需要进行任何其他配置。

完成了上述步骤后，我们已经涵盖了有关显示协议的所有必要主题。现在让我们讨论一下我们可以使用的各种方法来访问虚拟机控制台。

# 访问虚拟机控制台的方法

有多种方法可以连接到虚拟机控制台。如果您的环境具有完整的图形用户界面访问权限，那么最简单的方法就是使用 virt-manager 控制台本身。`virt-viewer`是另一个工具，可以让您访问虚拟机控制台。如果您尝试从远程位置访问虚拟机控制台，则此工具非常有用。在以下示例中，我们将连接到具有 IP`192.168.122.1`的远程 hypervisor。连接通过 SSH 会话进行隧道传输，并且是安全的。

第一步是在客户端系统和 hypervisor 之间建立一个无密码的身份验证系统：

1.  在客户端机器上，使用以下代码：

```
# ssh-keygen
# ssh-copy-id root@192.168.122.1
# virt-viewer -c qemu+ssh://root@192.168.122.1/system
```

您将看到 hypervisor 上可用的虚拟机列表。选择要访问的虚拟机，如下截图所示：

![图 6.14 - 用于虚拟机访问的 virt-viewer 选择菜单](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/ms-kvm-vrt/img/B14834_06_14.jpg)

图 6.14 - 用于虚拟机访问的 virt-viewer 选择菜单

1.  要直接连接到 VM 的控制台，请使用以下命令：

```
virsh – to be more specific, virsh console vm_name. This needs some additional configuration inside the virtual machine OS, as described in the following steps.
```

1.  如果您的 Linux 发行版使用 GRUB（而不是 GRUB2），请将以下行附加到`/boot/grub/grub.conf`中现有的引导内核行，并关闭虚拟机：

```
console=tty0 console=ttyS0,115200
```

如果您的 Linux 发行版使用 GRUB2，则步骤会变得有点复杂。请注意，以下命令已在 Fedora 22 虚拟机上进行了测试。对于其他发行版，配置 GRUB2 的步骤可能会有所不同，尽管 GRUB 配置文件所需的更改应保持不变：

```
# cat /etc/default/grub (only relevant variables are shown)
GRUB_TERMINAL_OUTPUT="console"
GRUB_CMDLINE_LINUX="rd.lvm.lv=fedora/swap rd.lvm.lv=fedora/root rhgb quiet"
```

更改后的配置如下：

```
# cat /etc/default/grub (only relevant variables are shown)
GRUB_TERMINAL_OUTPUT="serial console"
GRUB_CMDLINE_LINUX="rd.lvm.lv=fedora/swap rd.lvm.lv=fedora/root console=tty0 console=ttyS0"
# grub2-mkconfig -o /boot/grub2/grub.cfg
```

1.  现在，关闭虚拟机。然后使用`virsh`再次启动它：

```
# virsh shutdown PacktGPUPass
# virsh start PacktGPUPass --console
```

1.  运行以下命令以连接到已启动的虚拟机控制台：

```
# virsh console PacktGPUPass
```

您也可以从远程客户端执行此操作，如下所示：

```
# virsh -c qemu+ssh://root@192.168.122.1/system console PacktGPUPass
Connected to domain PacktGPUPass:
Escape character is ^]
```

在某些情况下，我们发现控制台命令卡在`^]`。要解决此问题，请多次按*Enter*键以查看登录提示。有时，当您想要捕获用于故障排除目的的引导消息时，配置文本控制台非常有用。使用*ctrl +]*退出控制台。

我们的下一个主题将带我们进入 noVNC 的世界，这是另一种基于 VNC 的协议，它比*常规*VNC 具有一些主要优势。现在让我们讨论这些优势以及 noVNC 的实现。

# 使用 noVNC 实现显示可移植性

所有这些显示协议都依赖于能够访问某种类型的客户端应用程序和/或附加软件支持，这将使我们能够访问虚拟机控制台。但是当我们无法访问所有这些附加功能时会发生什么？当我们只能以文本模式访问我们的环境时，但我们仍然希望以基于 GUI 的方式管理对我们的虚拟机的连接时会发生什么？

输入 noVNC，这是一个基于 HTML5 的 VNC 客户端，您可以通过兼容 HTML5 的 Web 浏览器使用，这只是对市场上*几乎每个*Web 浏览器的花哨说法。它支持所有最流行的浏览器，包括移动浏览器，以及许多其他功能，例如以下内容：

+   剪贴板复制粘贴

+   支持分辨率缩放和调整大小

+   它在 MPL 2.0 许可下免费

+   安装它相当容易，并支持身份验证，并且可以通过 HTTPS 轻松实现安全性

如果要使 noVNC 工作，您需要两样东西：

+   已配置为接受 VNC 连接的虚拟机，最好进行了一些配置 - 例如设置了密码和正确设置的网络接口以连接到虚拟机。您可以自由使用`tigervnc-server`，将其配置为接受特定用户的连接 - 例如 - 在端口`5901`上，并使用该端口和服务器的 IP 地址进行客户端连接。

+   在客户端计算机上安装 noVNC，您可以从 EPEL 存储库下载，也可以作为`zip/tar.gz`软件包直接从 Web 浏览器运行。要安装它，我们需要输入以下一系列命令：

```
yum -y install novnc
cd /etc/pki/tls/certs
openssl req -x509 -nodes -newkey rsa:2048 -keyout /etc/pki/tls/certs/nv.pem -out /etc/pki/tls/certs/nv.pem -days 365
websockify -D --web=/usr/share/novnc --cert=/etc/pki/tls/certs/nv.pem 6080 localhost:5901 
```

最终结果将看起来像这样：

![](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/ms-kvm-vrt/img/B14834_06_15.jpg)

图 6.15 - noVNC 控制台配置屏幕

在这里，我们可以使用我们的 VNC 服务器密码来访问特定的控制台。输入密码后，我们会得到这个：

![图 6.16 - noVNC 控制台实际操作 - 我们可以看到虚拟机控制台并使用它来处理我们的虚拟机](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/ms-kvm-vrt/img/B14834_06_16.jpg)

图 6.16 - noVNC 控制台实际操作 - 我们可以看到虚拟机控制台并使用它来处理我们的虚拟机

我们也可以在 oVirt 中使用所有这些选项。在安装 oVirt 时，我们只需要在 engine-setup 阶段选择一个额外的选项：

```
--otopi-environment="OVESETUP_CONFIG/websocketProxyConfig=bool:True"
```

此选项将使 oVirt 能够使用 noVNC 作为远程显示客户端，除了现有的 SPICE 和 VNC。

让我们看一个在 oVirt 中配置虚拟机的示例，几乎包括了本章讨论的所有选项。特别注意**监视器**配置选项：

![图 6.17 - oVirt 还支持本章讨论的所有设备](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/ms-kvm-vrt/img/B14834_06_17.jpg)

图 6.17 - oVirt 还支持本章讨论的所有设备

如果我们点击**图形协议**子菜单，我们将得到使用 SPICE、VNC、noVNC 和各种组合的选项。此外，在屏幕底部，我们还有可用的选项，用于我们想要在远程显示中看到的显示器数量。如果我们想要一个高性能的多显示远程控制台，这可能非常有用。

鉴于 noVNC 已经集成到 noVNC 中，您可以将其视为未来的迹象。从这个角度来看 - IT 中与管理应用程序相关的一切已经稳步地转移到基于 Web 的应用程序多年了。同样的事情发生在虚拟机控制台上也是合乎逻辑的。其他供应商的解决方案也已经实施了这一点，因此在这里使用 noVNC 不应该是一个大惊喜。

# 总结

在本章中，我们涵盖了虚拟显示设备和用于显示虚拟机数据的协议。我们还深入研究了 GPU 共享和 GPU 直通的世界，这是大规模运行 VDI 的虚拟化环境中的重要概念。我们讨论了这些情景的一些好处和缺点，因为它们往往相当复杂，需要大量资源，包括财政资源。想象一下，为 100 台虚拟机进行 2D/3D 加速的 PCI 直通。这实际上需要购买 100 张显卡，这在财务上是一个很大的要求。在我们讨论的其他主题中，我们讨论了可以用于控制台访问我们的虚拟机的各种显示协议和选项。

在下一章中，我们将带您了解一些常规虚拟机操作 - 安装、配置和生命周期管理，包括讨论快照和虚拟机迁移。

# 问题

1.  我们可以使用哪些类型的虚拟机显示设备？

1.  使用 QXL 虚拟显示设备与 VGA 相比的主要好处是什么？

1.  GPU 共享的好处和缺点是什么？

1.  GPU PCI 直通的好处是什么？

1.  SPICE 相对于 VNC 的主要优势是什么？

1.  为什么要使用 noVNC？

# 进一步阅读

有关本章内容的更多信息，请参考以下链接：

+   配置和管理虚拟化：[`access.redhat.com/documentation/en-us/red_hat_enterprise_linux/8/html/configuring_and_managing_virtualization/index`](https://access.redhat.com/documentation/en-us/red_hat_enterprise_linux/8/html/configuring_and_managing_virtualization/index)

+   QEMU 文档：[`www.qemu.org/documentation/`](https://www.qemu.org/documentation/)

+   NVIDIA 虚拟 GPU 软件文档：[`docs.nvidia.com/grid/latest/grid-vgpu-release-notes-red-hat-el-kvm/index.html`](https://docs.nvidia.com/grid/latest/grid-vgpu-release-notes-red-hat-el-kvm/index.html)

+   使用 IOMMU 组：[`access.redhat.com/documentation/en-us/red_hat_enterprise_linux/7/html/virtualization_deployment_and_administration_guide/app-iommu`](https://access.redhat.com/documentation/en-us/red_hat_enterprise_linux/7/html/virtualization_deployment_and_administration_guide/app-iommu)


# 第七章：虚拟机：安装、配置和生命周期管理

在本章中，我们将讨论安装和配置`virt-manager`、`virt-install`、oVirt 的不同方式，并建立在前几章中获得的知识基础上。然后，我们将对虚拟机迁移进行详细讨论，这是虚拟化的最基本方面之一，因为几乎无法想象在没有迁移选项的情况下使用虚拟化。为了能够为虚拟机迁移配置我们的环境，我们还将使用*第四章*中讨论的主题，*Libvirt 网络*，以及*第五章*中讨论的主题，*Libvirt 存储*，因为虚拟机迁移需要满足一些先决条件。

在本章中，我们将涵盖以下主题：

+   使用`virt-manager`创建新的虚拟机，使用`virt`命令

+   使用 oVirt 创建新的虚拟机

+   配置您的虚拟机

+   向虚拟机添加和删除虚拟硬件

+   迁移虚拟机

# 使用 virt-manager 创建新的虚拟机

`virt-manager`（用于管理虚拟机的图形界面工具）和`virt-install`（用于管理虚拟机的命令行实用程序）是`virt-*`命令堆栈中最常用的实用程序之一，非常有用。

让我们从`virt-manager`及其熟悉的图形界面开始。

## 使用 virt-manager

`virt-manager`是管理 KVM 虚拟机的首选图形界面实用程序。它非常直观和易于使用，尽管在功能上有点欠缺，我们稍后会描述一下。这是主`virt-manager`窗口：

![图 7.1 - 主 virt-manager 窗口](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/ms-kvm-vrt/img/B14834_07_01.jpg)

图 7.1 - 主 virt-manager 窗口

从这个屏幕截图中，我们已经可以看到在此服务器上安装了三个虚拟机。我们可以使用顶级菜单（**文件**，**编辑**，**查看**和**帮助**）进一步配置我们的 KVM 服务器和/或虚拟机，以及连接到网络上的其他 KVM 主机，如下面的屏幕截图所示：

![图 7.2 - 使用“添加连接...”选项连接到其他 KVM 主机](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/ms-kvm-vrt/img/B14834_07_02.jpg)

图 7.2 - 使用“添加连接...”选项连接到其他 KVM 主机

选择`virt-manager`后。该过程如下截图所示：

![图 7.3 - 连接到远程 KVM 主机](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/ms-kvm-vrt/img/B14834_07_03.jpg)

图 7.3 - 连接到远程 KVM 主机

此时，您可以通过右键单击主机名并选择**新建**来自由在远程 KVM 主机上安装虚拟机，如果选择这样做，如下截图所示：

![图 7.4 - 在远程 KVM 主机上创建新的虚拟机](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/ms-kvm-vrt/img/B14834_07_04.jpg)

图 7.4 - 在远程 KVM 主机上创建新的虚拟机

由于此向导与在本地服务器上安装虚拟机的向导相同，我们将一次性涵盖这两种情况。**新建虚拟机**向导的第一步是选择您要从哪里安装虚拟机。如下截图所示，有四个可用选项：

![图 7.5 - 选择引导介质](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/ms-kvm-vrt/img/B14834_07_05.jpg)

图 7.5 - 选择引导介质

选择如下：

+   如果您已经在本地计算机上（或作为物理设备）有一个**国际标准化组织**（**ISO**）文件可用，请选择第一个选项。

+   如果您想从网络安装，请选择第二个选项。

+   如果您在环境中设置了**预引导执行环境**（**PXE**）引导，并且可以从网络引导您的虚拟机安装，请选择第三个选项。

+   如果您有一个虚拟机磁盘，并且只想将其作为底层定义为虚拟机，请选择第四个选项。

通常，我们谈论网络安装（第二个选项）或 PXE 引导网络安装（第三个选项），因为这些是生产中最常见的用例。原因非常简单 - 没有理由在 ISO 文件上浪费本地磁盘空间，而这些文件现在相当大。例如，CentOS 8 v1905 ISO 文件大约为 8 **GB**。如果需要能够安装多个操作系统，甚至是这些操作系统的多个版本，最好使用一种仅用于 ISO 文件的集中存储空间。

在基于 VMware **ESX 集成**（**ESXi**）的基础设施中，人们通常使用 ISO 数据存储或内容库来实现此功能。在基于 Microsoft Hyper-V 的基础设施中，人们通常拥有一个用于 VM 安装所需 ISO 文件的**服务器消息块**（**SMB**）文件共享。每台主机都拷贝一个操作系统 ISO 文件是毫无意义的，因此一种共享的方法更加方便，也是一个很好的节省空间的机制。

假设我们正在从网络（**超文本传输协议**（**HTTP**）、**超文本传输安全协议**（**HTTPS**）或**文件传输协议**（**FTP**））安装 VM。我们需要一些东西来继续，如下所示：

+   一个`8.x.x`目录，然后转到`BaseOS/x86_64/os`。

+   显然，需要一个功能正常的互联网连接，尽可能快，因为我们将从前面的 URL 下载所有必要的安装包。

+   可选地，我们可以展开**URL 选项**三角形，并使用内核行的附加选项，最常见的是使用类似以下内容的 kickstart 选项：

```
ks=http://kickstart_file_url/file.ks
```

因此，让我们输入如下内容：

![图 7.6 - URL 和客户操作系统选择](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/ms-kvm-vrt/img/B14834_07_06.jpg)

图 7.6 - URL 和客户操作系统选择

请注意，我们*手动*选择的`virt-manager`目前不认识我们指定的 URL 中的 CentOS 8（1905）作为客户操作系统。如果操作系统在当前识别的操作系统列表中，我们可以只需选择**从安装媒体/源自动检测**复选框，有时需要多次重新检查和取消检查才能使其正常工作。

点击**前进**按钮后，我们需要为此 VM 设置内存和**中央处理单元**（**CPU**）设置。同样，您可以选择两种不同的方向，如下所示：

+   选择最少的资源（例如，1 个**虚拟 CPU**（**vCPU**）和 1GB 内存），然后根据需要更改。

+   选择适量的资源（例如，2 个 vCPU 和 4GB 内存），并考虑特定的用途。例如，如果此 VM 的预期用途是文件服务器，如果添加 16 个 vCPU 和 64GB 内存，性能将不会很好，但在其他用例中可能会适用。

下一步是配置 VM 存储。如下截图所示，有两个可用选项：

![图 7.7 - 配置 VM 存储](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/ms-kvm-vrt/img/B14834_07_07.jpg)

图 7.7 - 配置 VM 存储

为 VM 选择一个*合适*的存储设备非常重要，因为如果你不这样做，将来可能会遇到各种问题。例如，如果你在生产环境中将 VM 放在错误的存储设备上，你将不得不将该 VM 的存储迁移到另一个存储设备，这是一个繁琐且耗时的过程，会对你的 VM 产生一些不好的副作用，特别是如果你的源或目标存储设备上有大量的 VM 在运行。首先，它会严重影响它们的性能。然后，如果你的环境中有一些动态工作负载管理机制，它可能会触发基础设施中的额外 VM 或 VM 存储移动。像 VMware 的**分布式资源调度器**（**DRS**）/存储 DRS，带有**System Center Operations Manager**（**SCOM**）集成的 Hyper-V 性能和资源优化，以及 oVirt/Red Hat Enterprise Virtualization 集群调度策略等功能就是这样做的。因此，采用*三思而后行*的策略可能是正确的方法。

如果你选择第一个可用选项，`virt-manager`将在其默认位置创建一个 VM 硬盘——在`/var/lib/libvirt/images`目录中。确保你有足够的空间来存放你的 VM 硬盘。假设我们在`/var/lib/libvirt/images`目录及其底层分区中有 8GB 的可用空间。如果我们保持前面截图中的一切不变，我们会收到一个错误消息，因为我们试图在只有 8GB 可用的本地磁盘上创建一个 10GB 的文件。

在我们点击`virt-manager`之后，在安装过程之前自定义配置，并选择 VM 将使用的虚拟网络。我们将在本章稍后讨论 VM 的硬件定制。当你点击**完成**时，如下截图所示，你的 VM 将准备好部署，并且在我们安装操作系统后使用：

![图 7.8 – 最终 virt-manager 配置步骤](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/ms-kvm-vrt/img/B14834_07_08.jpg)

图 7.8 – 最终 virt-manager 配置步骤

使用`virt-manager`创建一些 VM 绝对不是一项困难的任务，但在现实生产环境中，你不一定会在服务器上找到 GUI。因此，我们的逻辑下一个任务是了解命令行工具来管理 VM——具体来说是`virt-*`命令。让我们接着做。

## 使用 virt-*命令

如前所述，我们需要学习一些新的命令来掌握基本 VM 管理任务。为了这个特定的目的，我们有一堆`virt-*`命令。让我们简要地介绍一些最重要的命令，并学习如何使用它们。

### virt-viewer

由于我们之前已经大量使用了`virt-install`命令（查看*第三章*，*安装基于内核的虚拟机（KVM）超级监视器，libvirt 和 ovirt*，我们使用这个命令安装了相当多的 VM），我们将覆盖剩下的命令。

让我们从`virt-viewer`开始，因为我们之前使用过这个应用程序。每次我们在`virt-viewer`中双击一个虚拟机，我们就打开了一个虚拟机控制台，这恰好是这个过程背后的`virt-viewer`。但是如果我们想要从 shell 中使用`virt-viewer`——就像人们经常做的那样——我们需要一些关于它的更多信息。所以，让我们举几个例子。

首先，让我们通过运行以下命令连接到一个名为`MasteringKVM01`的本地 KVM，它位于我们当前以`root`连接的主机上：

```
# virt-viewer --connect qemu:///system MasteringKVM01
```

我们还可以以`kiosk`模式连接到 VM，这意味着当我们关闭连接的 VM 时，`virt-viewer`也会关闭。要做到这一点，我们将运行以下命令：

```
# virt-viewer --connect qemu:///system MasteringKVM01 --kiosk --kiosk-quit on-disconnect
```

如果我们需要连接到*远程*主机，我们也可以使用`virt-viewer`，但我们需要一些额外的选项。连接到远程系统的最常见方式是通过 SSH，所以我们可以这样做：

```
# virt-viewer --connect qemu+ssh://username@remote-host/system VirtualMachineName
```

如果我们配置了 SSH 密钥并将它们复制到`username@remote-host`，这个前面的命令就不会要求我们输入密码。但如果没有，它将会要求我们输入密码两次——一次是建立与 hypervisor 的连接，另一次是建立与 VM **Virtual Network Computing** (**VNC**) 会话的连接。

### virt-xml

我们列表中的下一个命令行实用程序是`virt-xml`。我们可以使用它与`virt-install`命令行选项来更改 VM 配置。让我们从一个基本的例子开始——让我们只是为 VM 启用引导菜单，如下所示：

```
# virt-xml MasgteringKVM04 --edit --boot bootmenu=on
```

然后，让我们向 VM 添加一个薄配置的磁盘，分三步——首先，创建磁盘本身，然后将其附加到 VM，并检查一切是否正常工作。输出可以在下面的截图中看到：

![图 7.9 – 向 VM 添加一个薄配置 QEMU 写时复制（qcow2）格式的虚拟磁盘](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/ms-kvm-vrt/img/B14834_07_09.jpg)

图 7.9 – 向 VM 添加一个薄配置 QEMU 写时复制（qcow2）格式的虚拟磁盘

正如我们所看到的，`virt-xml`非常有用。通过使用它，我们向我们的 VM 添加了另一个虚拟磁盘，这是它可以做的最简单的事情之一。我们可以使用它向现有的 VM 部署任何额外的 VM 硬件。我们还可以使用它编辑 VM 配置，在较大的环境中特别方便，特别是当你必须对这样的过程进行脚本化和自动化时。

### virt-clone

现在让我们通过几个例子来检查`virt-clone`。假设我们只是想要一种快速简单的方式来克隆现有的 VM 而不需要任何额外的麻烦。我们可以这样做：

```
# virt-clone --original VirtualMachineName --auto-clone
```

结果，这将产生一个名为`VirtualMachineName-clone`的 VM，我们可以立即开始使用。让我们看看这个过程，如下所示：

![图 7.10 – 使用 virt-clone 创建 VM 克隆](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/ms-kvm-vrt/img/B14834_07_10.jpg)

图 7.10 – 使用 virt-clone 创建 VM 克隆

让我们看看如何使这个更加*定制化*。通过使用`virt-clone`，我们将创建一个名为`MasteringKVM05`的 VM，克隆一个名为`MasteringKVM04`的 VM，并且我们还将自定义虚拟磁盘名称，如下面的截图所示：

![图 7.11 – 自定义 VM 创建：自定义 VM 名称和虚拟硬盘文件名](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/ms-kvm-vrt/img/B14834_07_11.jpg)

图 7.11 – 自定义 VM 创建：自定义 VM 名称和虚拟硬盘文件名

在现实生活中，有时需要将 VM 从一种虚拟化技术转换为另一种。其中大部分工作实际上是将 VM 磁盘格式从一种格式转换为另一种格式。这就是`virt-convert`的工作原理。让我们学习一下它是如何工作的。

### qemu-img

现在让我们看看如何将一个虚拟磁盘转换为另一种格式，以及如何将一个 VM *配置文件*从一种虚拟化方法转换为另一种。我们将使用一个空的 VMware VM 作为源，并将其`vmdk`虚拟磁盘和`.vmx`文件转换为新格式，如下面的截图所示：

![图 7.12 – 将 VMware 虚拟磁盘转换为 KVM 的 qcow2 格式](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/ms-kvm-vrt/img/B14834_07_12.jpg)

图 7.12 – 将 VMware 虚拟磁盘转换为 KVM 的 qcow2 格式

如果我们面对需要在这些平台之间移动或转换 VM 的项目，我们需要确保使用这些实用程序，因为它们易于使用和理解，只需要一点时间。例如，如果我们有一个 1 `qcow2`格式，所以我们必须耐心等待。此外，我们需要随时准备好编辑`vmx`配置文件，因为从`vmx`到`kvm`格式的转换过程并不是 100%顺利，正如我们可能期望的那样。在这个过程中，会创建一个新的配置文件。KVM VM 配置文件的默认目录是`/etc/libvirt/qemu`，我们可以轻松地看到`virsh`列表输出。

在 CentOS 8 中还有一些新的实用工具，这些工具将使我们更容易管理不仅本地服务器还有 VM。Cockpit web 界面就是其中之一——它具有在 KVM 主机上进行基本 VM 管理的功能。我们只需要通过 Web 浏览器连接到它，我们在*第三章*中提到过这个 Web 应用程序，*安装基于内核的 VM（KVM）Hypervisor，libvirt 和 ovirt*，当讨论 oVirt 设备的部署时。因此，让我们通过使用 Cockpit 来熟悉 VM 管理。

## 使用 Cockpit 创建新的 VM

要使用 Cockpit 管理我们的服务器及其 VM，我们需要安装和启动 Cockpit 及其附加包。让我们从那开始，如下所示：

```
yum -y install cockpit*
systemctl enable --now cockpit.socket
```

在此之后，我们可以启动 Firefox 并将其指向`https://kvm-host:9090/`，因为这是 Cockpit 可以访问的默认端口，并使用 root 密码登录为`root`，这将给我们以下**用户界面**（**UI**）：

![图 7.14 – Cockpit web 控制台，我们可以用它来部署 VM](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/ms-kvm-vrt/img/B14834_07_14.jpg)

图 7.14 – Cockpit web 控制台，我们可以用它来部署 VM

在上一步中，当我们安装了`cockpit*`时，我们还安装了`cockpit-machines`，这是 Cockpit web 控制台的一个插件，它使我们能够在 Cockpit web 控制台中管理`libvirt` VM。因此，在我们点击**VMs**后，我们可以轻松地看到我们以前安装的所有 VM，打开它们的配置，并通过简单的向导安装新的 VM，如下面的屏幕截图所示：

![图 7.15 – Cockpit VM 管理](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/ms-kvm-vrt/img/B14834_07_15.jpg)

图 7.15 – Cockpit VM 管理

VM 安装向导非常简单——我们只需要为我们的新 VM 配置基本设置，然后我们就可以开始安装，如下所示：

![图 7.16 – 从 Cockpit web 控制台安装 KVM VM](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/ms-kvm-vrt/img/B14834_07_16.jpg)

图 7.16 – 从 Cockpit web 控制台安装 KVM VM

现在我们已经了解了如何*本地*安装 VM——意味着没有某种集中管理应用程序，让我们回过头来看看如何通过 oVirt 安装 VM。

# 使用 oVirt 创建新的 VM

如果我们将主机添加到 oVirt，当我们登录时，我们可以转到**Compute-VMs**，并通过简单的向导开始部署 VM。因此，在该菜单中点击**New**按钮后，我们可以这样做，然后我们将被带到以下屏幕：

![图 7.17 – oVirt 中的新 VM 向导](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/ms-kvm-vrt/img/B14834_07_17.jpg)

图 7.17 – oVirt 中的新 VM 向导

考虑到 oVirt 是 KVM 主机的集中管理解决方案，与在 KVM 主机上进行本地 VM 安装相比，我们有*大量*的额外选项——我们可以选择一个将托管此 VM 的集群；我们可以使用模板，配置优化和实例类型，配置**高可用性**（**HA**），资源分配，引导选项...基本上，这就是我们开玩笑称之为*选项麻痹*，尽管这对我们自己有利，因为集中化解决方案总是与任何一种本地解决方案有些不同。

至少，我们将不得不配置一般的 VM 属性——名称、操作系统和 VM 网络接口。然后，我们将转到**System**选项卡，在那里我们将配置内存大小和虚拟 CPU 数量，如下面的屏幕截图所示：

![图 7.18 – 选择 VM 配置：虚拟 CPU 和内存](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/ms-kvm-vrt/img/B14834_07_18.jpg)

图 7.18 – 选择 VM 配置：虚拟 CPU 和内存

我们肯定会想要配置引导选项——连接 CD/ISO，添加虚拟硬盘，并配置引导顺序，如下面的屏幕截图所示：

![图 7.19 – 在 oVirt 中配置 VM 引导选项](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/ms-kvm-vrt/img/B14834_07_19.jpg)

图 7.19 – 在 oVirt 中配置 VM 引导选项

我们可以使用`sysprep`或`cloud-init`来自定义 VM 的安装后设置，我们将在*第九章*中讨论，*使用 cloud-init 自定义 VM*。

以下是 oVirt 中基本的配置外观：

![图 7.20-从 oVirt 安装 KVM VM：确保选择正确的启动选项](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/ms-kvm-vrt/img/B14834_07_20.jpg)

图 7.20-从 oVirt 安装 KVM VM：确保选择正确的启动选项

实际上，如果您管理的环境有两到三个以上的 KVM 主机，您会希望使用某种集中式实用程序来管理它们。oVirt 非常适合这一点，所以不要跳过它。

现在我们已经以各种不同的方式完成了整个部署过程，是时候考虑 VM 配置了。请记住，VM 是一个具有许多重要属性的对象，例如虚拟 CPU 的数量、内存量、虚拟网络卡等，因此学习如何自定义 VM 设置非常重要。所以，让我们把它作为下一个主题。

# 配置您的 VM

当我们使用`virt-manager`时，如果您一直进行到最后一步，您可以选择一个有趣的选项，即**在安装前自定义配置**选项。如果您在安装后检查 VM 配置，也可以访问相同的配置窗口。因此，无论我们选择哪种方式，我们都将面临为分配给我们刚创建的 VM 的每个 VM 硬件设备的全面配置选项，如下截图所示：

![图 7.21-VM 配置选项](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/ms-kvm-vrt/img/B14834_07_21.jpg)

图 7.21-VM 配置选项

例如，如果我们在左侧点击**CPU**选项，您将看到可用 CPU 的数量（当前和最大分配），还将看到一些非常高级的选项，例如**CPU 拓扑**（**插槽**/**核心**/**线程**），它使我们能够配置特定的**非均匀内存访问**（**NUMA**）配置选项。这就是该配置窗口的样子：

![图 7.22-VM CPU 配置](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/ms-kvm-vrt/img/B14834_07_22.jpg)

图 7.22-VM CPU 配置

这是 VM 配置的*非常*重要部分，特别是如果您正在设计一个承载大量虚拟服务器的环境。此外，如果虚拟化服务器承载**输入/输出**（**I/O**）密集型应用程序，例如数据库，这一点变得更加重要。如果您想了解更多信息，可以在本章末尾的*进一步阅读*部分中查看链接，它将为您提供有关 VM 设计的大量额外信息。

然后，如果我们打开`virt-*`命令。这是`virt-manager` **内存**配置选项的外观：

![图 7.23-VM 内存配置](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/ms-kvm-vrt/img/B14834_07_23.jpg)

图 7.23-VM 内存配置

`virt-manager`中最重要的配置选项集之一位于**启动选项**子菜单中，如下截图所示：

![图 7.24-VM 启动配置选项](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/ms-kvm-vrt/img/B14834_07_24.jpg)

图 7.24-VM 启动配置选项

在那里，您可以做两件非常重要的事情，如下所示：

+   选择此 VM 在主机启动时自动启动

+   启用启动菜单并选择启动设备和启动设备优先级

就配置选项而言，`virt-manager`中功能最丰富的配置菜单是虚拟存储菜单，即我们的情况下的**VirtIO Disk 1**。如果我们点击它，我们将得到以下配置选项的选择：

![图 7.25-配置 VM 硬盘和存储控制器选项](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/ms-kvm-vrt/img/B14834_07_25.jpg)

图 7.25-配置 VM 硬盘和存储控制器选项

让我们看看其中一些配置选项的重要性，如下所示：

+   **磁盘总线** - 这里通常有五个选项，**VirtIO**是默认（也是最好的）选项。与 Vmware、ESXi 和 Hyper-V 一样，KVM 有不同的虚拟存储控制器可用。例如，VMware 有 BusLogic、LSI Logic、Paravirtual 和其他类型的虚拟存储控制器，而 Hyper-V 有**集成驱动电子学**（**IDE**）和**小型计算机系统接口**（**SCSI**）控制器。此选项定义了 VM 在其客户操作系统中将看到的存储控制器。 

+   `qcow2`和`raw`（`dd`类型格式）。最常见的选项是`qcow2`，因为它为 VM 管理提供了最大的灵活性 - 例如，它支持薄配置和快照。

+   `缓存`模式 - 有六种类型：`writethrough`，`writeback`，`directsync`，`unsafe`，`none`和`default`。这些模式解释了从 VM 发起的 I/O 如何从 VM 下面的存储层写入数据。例如，如果我们使用`writethrough`，I/O 会被缓存在 KVM 主机上，并且也会通过写入到 VM 磁盘。另一方面，如果我们使用`none`，主机上没有缓存（除了磁盘`writeback`缓存），数据直接写入 VM 磁盘。不同的模式有不同的优缺点，但通常来说，`none`是 VM 管理的最佳选择。您可以在*进一步阅读*部分了解更多信息。

+   `IO`模式 - 有两种模式：`native`和`threads`。根据此设置，VM I/O 将通过内核异步 I/O 或用户空间中的线程池进行写入（这是默认值）。当使用`qcow2`格式时，通常认为`threads`模式更好，因为`qcow2`格式首先分配扇区，然后写入它们，这将占用分配给 VM 的 vCPU，并直接影响 I/O 性能。

+   `丢弃`模式 - 这里有两种可用模式，称为`忽略`和`取消映射`。如果选择`取消映射`，当您从 VM 中删除文件（这会转换为`qcow2` VM 磁盘文件中的可用空间），`qcow2` VM 磁盘文件将缩小以反映新释放的容量。取决于您使用的 Linux 发行版、内核和内核补丁以及**快速仿真器**（**QEMU**）版本，此功能*可能*仅适用于 SCSI 磁盘总线。它支持 QEMU 版本 4.0+。

+   `检测零` - 有三种可用模式：`关闭`，`打开`和`取消映射`。如果您选择`取消映射`，零写入将被转换为取消映射操作（如丢弃模式中所解释的）。如果将其设置为`打开`，操作系统的零写入将被转换为特定的零写入命令。

在任何给定 VM 的寿命期内，有很大的机会我们会重新配置它。无论是添加还是删除虚拟硬件（当然，通常是添加），这是 VM 生命周期的一个重要方面。因此，让我们学习如何管理它。

# 从 VM 添加和删除虚拟硬件

通过使用 VM 配置屏幕，我们可以轻松添加额外的硬件，或者删除硬件。例如，如果我们点击左下角的**添加硬件**按钮，我们可以轻松添加一个设备 - 比如，一个虚拟网络卡。以下截图说明了这个过程：

![图 7.26 - 点击“添加硬件”后，我们可以选择要要添加到我们的 VM 的虚拟硬件设备](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/ms-kvm-vrt/img/B14834_07_26.jpg)

图 7.26 - 点击“添加硬件”后，我们可以选择要添加到虚拟机的虚拟硬件设备

另一方面，如果我们选择一个虚拟硬件设备（例如**Sound ich6**）并按下随后出现的**删除**按钮，我们也可以删除这个虚拟硬件设备，确认我们要这样做后，如下截图所示：

![图 7.27 - 删除 VM 硬件设备的过程：在左侧并单击删除](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/ms-kvm-vrt/img/B14834_07_27.jpg)

图 7.27 – 删除虚拟机硬件设备的流程：在左侧选择它，然后单击删除

正如您所看到的，添加和删除虚拟机硬件就像 123 一样简单。我们之前确实提到过这个话题，当时我们正在处理虚拟网络和存储（*第四章*，*Libvirt 网络*），但那里，我们使用了 shell 命令和 XML 文件定义。如果您想了解更多，请查看这些示例。

虚拟化的关键在于灵活性，能够在我们的环境中将虚拟机放置在任何给定的主机上是其中的重要部分。考虑到这一点，虚拟机迁移是虚拟化中可以用作营销海报的功能之一，它有许多优势。虚拟机迁移到底是什么？这就是我们接下来要学习的内容。

# 迁移虚拟机

简单来说，迁移使您能够将虚拟机从一台物理机器移动到另一台物理机器，几乎没有或没有任何停机时间。我们还可以移动虚拟机存储，这是一种资源密集型的操作，需要仔细规划，并且—如果可能—在工作时间之后执行，以便它不会像可能影响其他虚拟机的性能那样影响其他虚拟机的性能。

有各种不同类型的迁移，如下：

+   离线（冷）

+   在线（实时）

+   暂停迁移

还有各种不同类型的在线迁移，具体取决于您要移动的内容，如下：

+   虚拟机的计算部分（将虚拟机从一个 KVM 主机移动到另一个 KVM 主机）

+   虚拟机的存储部分（将虚拟机文件从一个存储池移动到另一个存储池）

+   两者（同时将虚拟机从主机迁移到主机和从存储池迁移到存储池）

如果您只是使用普通的 KVM 主机，与使用 oVirt 或 Red Hat 企业虚拟化相比，支持的迁移场景有一些差异。如果您想进行实时存储迁移，您不能直接在 KVM 主机上执行，但如果虚拟机已关闭，则可以轻松执行。如果您需要进行实时存储迁移，您将需要使用 oVirt 或 Red Hat 企业虚拟化。

我们还讨论了**单根输入输出虚拟化**（**SR-IOV**）、**外围组件互连**（**PCI**）设备透传、**虚拟图形处理单元**（**vGPUs**）等概念（在*第二章*中，*KVM 作为虚拟化解决方案*，以及*第四章*中，*Libvirt 网络*）。在 CentOS 8 中，您不能对具有这些选项之一分配给运行中的虚拟机的虚拟机进行实时迁移。

无论用例是什么，我们都需要意识到迁移需要以`root`用户或属于`libvirt`用户组的用户（Red Hat 所称的系统与用户`libvirt`会话）执行。

虚拟机迁移是一个有价值的工具的原因有很多。有些原因很明显，而其他原因则不那么明显。让我们尝试解释虚拟机迁移的不同用例和其好处。

## 虚拟机迁移的好处

虚拟机实时迁移的最重要的好处如下：

+   **增加的正常运行时间和减少的停机时间**—精心设计的虚拟化环境将为您的应用程序提供最大的正常运行时间。

+   **节约能源，走向绿色**—您可以根据虚拟机的负载和使用情况在非工作时间将它们合并到较少的虚拟化主机上。一旦虚拟机迁移完成，您可以关闭未使用的虚拟化主机。

+   通过在不同的虚拟化主机之间移动您的虚拟机，轻松进行硬件/软件升级过程—一旦您有能力在不同的物理服务器之间自由移动您的虚拟机，好处是无穷无尽的。

虚拟机迁移需要适当的规划。迁移有一些基本要求。让我们逐一看看它们。

生产环境的迁移要求如下：

+   VM 应该使用在共享存储上创建的存储池。

+   存储池的名称和虚拟磁盘的路径应该在两个超级主机（源和目标超级主机）上保持相同。

查看*第四章*，*Libvirt 网络*，以及*第五章*，*Libvirt 存储*，以便回顾如何使用共享存储创建存储池。

这里总是有一些适用的规则。这些规则相当简单，所以我们需要在开始迁移过程之前学习它们。它们如下：

+   可以使用在非共享存储上创建的存储池进行实时存储迁移。您只需要保持相同的存储池名称和文件位置，但在生产环境中仍建议使用共享存储。

+   如果连接到使用**光纤通道**（**FC**）、**Internet 小型计算机系统接口**（**iSCSI**）、**逻辑卷管理器**（**LVM**）等的 VM 的未管理虚拟磁盘，则相同的存储应该在两个超级主机上都可用。

+   VM 使用的虚拟网络应该在两个超级主机上都可用。

+   为网络通信配置的桥接应该在两个超级主机上都可用。

+   如果超级主机上的`libvirt`和`qemu-kvm`的主要版本不同，迁移可能会失败，但您应该能够将运行在具有较低版本`libvirt`或`qemu-kvm`的超级主机上的 VM 迁移到具有这些软件包较高版本的超级主机上，而不会出现任何问题。

+   源和目标超级主机上的时间应该同步。强烈建议您使用相同的**网络时间协议**（**NTP**）或**精密时间协议**（**PTP**）服务器同步超级主机。

+   重要的是系统使用`/etc/hosts`将无法工作。您应该能够使用`host`命令解析主机名。

在为 VM 迁移规划环境时，我们需要牢记一些先决条件。在大多数情况下，这些先决条件对所有虚拟化解决方案都是相同的。让我们讨论这些先决条件，以及如何为 VM 迁移设置环境。

## 设置环境

让我们构建环境来进行 VM 迁移 - 离线和实时迁移。以下图表描述了两个标准的 KVM 虚拟化主机，运行具有共享存储的 VM：

![图 7.28 - 共享存储上的 VM](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/ms-kvm-vrt/img/B14834_07_28.jpg)

图 7.28 - 共享存储上的 VM

我们首先通过设置共享存储来开始。在本例中，我们使用`libvirt`。

我们将在 CentOS 8 服务器上创建一个 NFS 共享。它将托管在`/testvms`目录中，我们将通过 NFS 导出它。服务器的名称是`nfs-01`。（在我们的情况下，`nfs-01`的 IP 地址是`192.168.159.134`）

1.  第一步是从`nfs-01`创建和导出`/testvms`目录，并关闭 SELinux（查看*第五章*，*Libvirt 存储*，Ceph 部分以了解如何）：

```
# mkdir /testvms
# echo '/testvms *(rw,sync,no_root_squash)' >> /etc/exports
```

1.  然后，通过执行以下代码在防火墙中允许 NFS 服务：

```
# firewall-cmd --get-active-zones
public
interfaces: ens33
# firewall-cmd --zone=public --add-service=nfs
# firewall-cmd --zone=public --list-all
```

1.  启动 NFS 服务，如下所示：

```
# systemctl start rpcbind nfs-server
# systemctl enable rpcbind nfs-server
# showmount -e
```

1.  确认共享是否可以从您的 KVM 超级主机访问。在我们的情况下，它是`PacktPhy01`和`PacktPhy02`。运行以下代码：

```
# mount 192.168.159.134:/testvms /mnt
```

1.  如果挂载失败，请重新配置 NFS 服务器上的防火墙并重新检查挂载。可以使用以下命令完成：

```
firewall-cmd --permanent --zone=public --add-service=nfs
firewall-cmd --permanent --zone=public --add-service=mountd
firewall-cmd --permanent --zone=public --add-service=rpc-bind
firewall-cmd -- reload
```

1.  验证了两个超级主机的 NFS 挂载点后，卸载卷，如下所示：

```
# umount /mnt
```

1.  在`PacktPhy01`和`PacktPhy02`上创建名为`testvms`的存储池，如下所示：

```
# mkdir -p /var/lib/libvirt/images/testvms/
# virsh pool-define-as --name testvms --type netfs --source-host 192.168.159.134 --source-path /testvms --target /var/lib/libvirt/images/testvms/
# virsh pool-start testvms
# virsh pool-autostart testvms
```

`testvms`存储池现在在两个超级主机上创建并启动。

在下一个示例中，我们将隔离迁移和 VM 流量。特别是在生产环境中，如果您进行大量迁移，强烈建议您进行此隔离，因为它将把这个要求严格的过程转移到一个单独的网络接口，从而释放其他拥挤的网络接口。因此，这样做有两个主要原因，如下所示：

+   `PacktPhy01`和`PacktPhy02`上的`ens192`接口用于迁移以及管理任务。它们有一个 IP 地址，并连接到网络交换机。使用`PacktPhy01`和`PacktPhy02`上的`ens224`创建了一个`br1`桥。`br1`没有分配 IP 地址，专门用于 VM 流量（连接到 VM 的交换机的上行）。它也连接到一个（物理）网络交换机。

+   **安全原因**：出于安全原因，建议您将管理网络和虚拟网络隔离。您不希望用户干扰您的管理网络，您可以在其中访问您的虚拟化程序并进行管理。

我们将讨论三种最重要的场景——离线迁移、非实时迁移（挂起）和实时迁移（在线）。然后，我们将讨论存储迁移作为一个需要额外规划和考虑的单独场景。

## 离线迁移

正如名称所示，在离线迁移期间，VM 的状态将被关闭或挂起。然后在目标主机上恢复或启动 VM。在这种迁移模型中，`libvirt`只会将 VM 的 XML 配置文件从源 KVM 主机复制到目标 KVM 主机。它还假定您在目标地点已经创建并准备好使用相同的共享存储池。在迁移过程的第一步中，您需要在参与的 KVM 虚拟化程序上设置双向无密码 SSH 身份验证。在我们的示例中，它们被称为`PacktPhy01`和`PacktPhy02`。

在接下来的练习中，暂时禁用**安全增强型 Linux**（**SELinux**）。

在`/etc/sysconfig/selinux`中，使用您喜欢的编辑器修改以下代码行：

```
SELINUX=enforcing
```

需要修改如下：

```
SELINUX=permissive
```

同样，在命令行中，作为`root`，我们需要临时将 SELinux 模式设置为宽松模式，如下所示：

```
# setenforce 0
```

在`PacktPhy01`上，作为`root`，运行以下命令：

```
# ssh-keygen
# ssh-copy-id root@PacktPhy02
```

在`PacktPhy02`上，作为`root`，运行以下命令：

```
# ssh-keygen
# ssh-copy-id root@PacktPhy01
```

现在您应该能够以`root`身份登录到这两个虚拟化程序，而无需输入密码。

让我们对已经安装的`MasteringKVM01`进行离线迁移，从`PacktPhy01`迁移到`PacktPhy02`。迁移命令的一般格式看起来类似于以下内容：

```
# virsh migrate migration-type options name-of-the-vm-destination-uri
```

在`PacktPhy01`上，运行以下代码：

```
[PacktPhy01] # virsh migrate --offline --verbose –-persistent MasteringKVM01 qemu+ssh://PacktPhy02/system
Migration: [100 %]
```

在`PacktPhy02`上，运行以下代码：

```
[PacktPhy02] # virsh list --all
# virsh list --all
Id Name State
----------------------------------------------------
- MasteringKVM01 shut off
[PacktPhy02] # virsh start MasteringKVM01
Domain MasteringKVM01 started
```

当 VM 在共享存储上，并且您在其中一个主机上遇到了一些问题时，您也可以手动在另一个主机上注册 VM。这意味着在您修复了初始问题的主机上，同一个 VM 可能会在两个虚拟化程序上注册。这是在没有像 oVirt 这样的集中管理平台的情况下手动管理 KVM 主机时会发生的情况。那么，如果您处于这种情况下会发生什么呢？让我们讨论这种情况。

### 如果我意外地在两个虚拟化程序上启动 VM 会怎么样？

意外地在两个虚拟化程序上启动 VM 可能是系统管理员的噩梦。这可能导致 VM 文件系统损坏，特别是当 VM 内部的文件系统不是集群感知时。`libvirt`的开发人员考虑到了这一点，并提出了一个锁定机制。事实上，他们提出了两种锁定机制。启用这些锁定机制将防止 VM 同时在两个虚拟化程序上启动。

两个锁定机制如下：

+   `lockd`：`lockd`利用了`POSIX fcntl()`的咨询锁定功能。它由`virtlockd`守护程序启动。它需要一个共享文件系统（最好是 NFS），可供共享相同存储池的所有主机访问。

+   `sanlock`：这是 oVirt 项目使用的。它使用磁盘`paxos`算法来维护持续更新的租约。

对于仅使用`libvirt`的实现，我们更喜欢`lockd`而不是`sanlock`。最好在 oVirt 中使用`sanlock`。

### 启用 lockd

对于符合 POSIX 标准的基于镜像的存储池，您可以通过取消注释`/etc/libvirt/qemu.conf`中的以下命令或在两个虚拟化程序上启用`lockd`：

```
lock_manager = "lockd" 
```

现在，在两个虚拟化程序上启用并启动`virtlockd`服务。另外，在两个虚拟化程序上重新启动`libvirtd`，如下所示：

```
# systemctl enable virtlockd; systemctl start virtlockd
# systemctl restart libvirtd
# systemctl status virtlockd
```

在`PacktPhy02`上启动`MasteringKVM01`，如下所示：

```
[root@PacktPhy02] # virsh start MasteringKVM01
Domain MasteringKVM01 started
```

在`PacktPhy01`上启动相同的`MasteringKVM01`虚拟机，如下所示：

```
[root@PacktPhy01] # virsh start MasteringKVM01
error: Failed to start domain MasteringKVM01
error: resource busy: Lockspace resource '/var/lib/libvirt/images/ testvms/MasteringKVM01.qcow2' is locked
```

启用`lockd`的另一种方法是使用磁盘文件路径的哈希。锁保存在通过 NFS 或类似共享导出到虚拟化程序的共享目录中。当您有通过多路径创建和附加的虚拟磁盘时，这是非常有用的，在这种情况下无法使用`fcntl()`。我们建议您使用下面详细介绍的方法来启用锁定。

在 NFS 服务器上运行以下代码（确保您首先不要从此 NFS 服务器运行任何虚拟机！）：

```
mkdir /flockd
# echo "/flockd *(rw,no_root_squash)" >> /etc/exports
# systemctl restart nfs-server
# showmount -e
Export list for :
/flockd *
/testvms *
```

在`/etc/fstab`中为两个虚拟化程序添加以下代码，并输入其余命令：

```
# echo "192.168.159.134:/flockd /var/lib/libvirt/lockd/flockd nfs rsize=8192,wsize=8192,timeo=14,intr,sync" >> /etc/fstab
# mkdir -p /var/lib/libvirt/lockd/flockd
# mount -a
# echo 'file_lockspace_dir = "/var/lib/libvirt/lockd/flockd"' >> /etc/libvirt/qemu-lockd.conf
```

重新启动两个虚拟化程序，并在重新启动后验证`libvirtd`和`virtlockd`守护程序在两个虚拟化程序上是否正确启动，如下所示：

```
[root@PacktPhy01 ~]# virsh start MasteringKVM01
Domain MasteringKVM01 started
[root@PacktPhy02 flockd]# ls
36b8377a5b0cc272a5b4e50929623191c027543c4facb1c6f3c35bacaa745 5ef
51e3ed692fdf92ad54c6f234f742bb00d4787912a8a674fb5550b1b826343 dd6
```

`MasteringKVM01`有两个虚拟磁盘，一个是从 NFS 存储池创建的，另一个是直接从 LUN 创建的。如果我们尝试在`PacktPhy02`虚拟化程序主机上启动它，`MasteringKVM01`将无法启动，如下面的代码片段所示：

```
[root@PacktPhy02 ~]# virsh start MasteringKVM01
error: Failed to start domain MasteringKVM01
error: resource busy: Lockspace resource '51e3ed692fdf92ad54c6f234f742bb00d4787912a8a674fb5550b1b82634 3dd6' is locked
```

当使用可以跨多个主机系统可见的 LVM 卷时，最好基于`libvirt`对 LVM 执行基于 UUID 的锁定：

```
lvm_lockspace_dir = "/var/lib/libvirt/lockd/lvmvolumes"
```

当使用可以跨多个主机系统可见的 SCSI 卷时，最好基于每个卷关联的 UUID 进行锁定，而不是它们的路径。设置以下路径会导致`libvirt`对 SCSI 执行基于 UUID 的锁定：

```
scsi_lockspace_dir = "/var/lib/libvirt/lockd/scsivolumes"
```

与`file_lockspace_dir`一样，前面的目录也应该与虚拟化程序共享。

重要提示

如果由于锁定错误而无法启动虚拟机，只需确保它们没有在任何地方运行，然后删除锁定文件。然后再次启动虚拟机。我们在`lockd`主题上偏离了一点。让我们回到迁移。

## 实时或在线迁移

在这种类型的迁移中，虚拟机在运行在源主机上的同时迁移到目标主机。这个过程对正在使用虚拟机的用户是不可见的。他们甚至不会知道他们正在使用的虚拟机在他们使用时已经被迁移到另一个主机。实时迁移是使虚拟化如此受欢迎的主要功能之一。

KVM 中的迁移实现不需要虚拟机的任何支持。这意味着您可以实时迁移任何虚拟机，而不管它们使用的操作系统是什么。KVM 实时迁移的一个独特特性是它几乎完全与硬件无关。您应该能够在具有**Advanced Micro Devices**（**AMD**）处理器的虚拟化程序上实时迁移运行在 Intel 处理器上的虚拟机。

我们并不是说这在 100%的情况下都会奏效，或者我们以任何方式推荐拥有这种混合环境，但在大多数情况下，这是可能的。

在我们开始这个过程之前，让我们深入了解一下在幕后发生了什么。当我们进行实时迁移时，我们正在移动一个正在被用户访问的活动虚拟机。这意味着用户在进行实时迁移时不应该感受到虚拟机可用性的任何中断。

即使这些过程对系统管理员不可见，活迁移是一个包含五个阶段的复杂过程。一旦发出 VM 迁移操作，`libvirt`将会完成必要的工作。VM 迁移经历的阶段如下所述：

1.  `libvirt`（`SLibvirt`）将与目的地`libvirt`（`DLibvirt`）联系，并提供将要进行实时传输的 VM 的详细信息。`DLibvirt`将将此信息传递给底层的 QEMU，并提供相关选项以启用实时迁移。QEMU 将通过在`pause`模式下启动 VM 并开始侦听来自`DLibvirt`的连接到目的地 TCP 端口的实际实时迁移过程。

1.  在目的地处于`pause`模式。

b)一次性将 VM 使用的所有内存传输到目的地。传输速度取决于网络带宽。假设 VM 使用 10 `migrate-setmaxdowntime`，单位为毫秒。

1.  **停止源主机上的虚拟机**：一旦脏页的数量达到所述阈值，QEMU 将停止源主机上的虚拟机。它还将同步虚拟磁盘。

1.  **传输 VM 状态**：在此阶段，QEMU 将尽快将 VM 的虚拟设备状态和剩余的脏页传输到目的地。我们无法在此阶段限制带宽。

1.  **继续 VM**：在目的地，VM 将从暂停状态恢复。虚拟**网络接口控制器**（**NICs**）变为活动状态，桥接将发送自由**地址解析协议**（**ARPs**）以宣布更改。在收到桥接的通知后，网络交换机将更新各自的 ARP 缓存，并开始将 VM 的数据转发到新的 hypervisor。

请注意，*步骤 3、4 和 5*将在毫秒内完成。如果发生错误，QEMU 将中止迁移，VM 将继续在源 hypervisor 上运行。在整个迁移过程中，来自两个参与的 hypervisor 的`libvirt`服务将监视迁移过程。

我们的 VM 称为`MasteringKVM01`，现在安全地在`PacktPhy01`上运行，并启用了`lockd`。我们将要将`MasteringKVM01`实施活迁移到`PacktPhy02`。

我们需要打开用于迁移的必要 TCP 端口。您只需要在目的地服务器上执行此操作，但最好在整个环境中执行此操作，以便以后不必逐个微观管理这些配置更改。基本上，您需要使用以下`firewall-cmd`命令为默认区域（在我们的情况下是`public`区域）在所有参与的 hypervisor 上打开端口：

```
# firewall-cmd --zone=public --add-port=49152-49216/tcp --permanent
```

检查两台服务器上的名称解析，如下所示：

```
[root@PacktPhy01 ~] # host PacktPhy01
PacktPhy01 has address 192.168.159.136
[root@PacktPhy01 ~] # host PacktPhy02
PacktPhy02 has address 192.168.159.135
[root@PacktPhy02 ~] # host PacktPhy01
PacktPhy01 has address 192.168.159.136
[root@PacktPhy02 ~] # host PacktPhy02
PacktPhy02 has address 192.168.159.135
```

检查和验证所有附加的虚拟磁盘是否在目的地上可用，路径相同，并且存储池名称相同。这也适用于附加的未管理（iSCSI 和 FC LUN 等）虚拟磁盘。

检查和验证目的地可用的 VM 所使用的所有网络桥接和虚拟网络。之后，我们可以通过运行以下代码开始迁移过程：

```
# virsh migrate --live MasteringKVM01 qemu+ssh://PacktPhy02/system --verbose --persistent
Migration: [100 %]
```

我们的 VM 只使用 4,096 `--persistent`选项是可选的，但我们建议添加这个选项。

这是迁移过程中`ping`的输出（`10.10.48.24`是`MasteringKVM01`的 IP 地址）：

```
# ping 10.10.48.24
PING 10.10.48.24 (10.10.48.24) 56(84) bytes of data.
64 bytes from 10.10.48.24: icmp_seq=12 ttl=64 time=0.338 ms
64 bytes from 10.10.48.24: icmp_seq=13 ttl=64 time=3.10 ms
64 bytes from 10.10.48.24: icmp_seq=14 ttl=64 time=0.574 ms
64 bytes from 10.10.48.24: icmp_seq=15 ttl=64 time=2.73 ms
64 bytes from 10.10.48.24: icmp_seq=16 ttl=64 time=0.612 ms
--- 10.10.48.24 ping statistics ---
17 packets transmitted, 17 received, 0% packet loss, time 16003ms
rtt min/avg/max/mdev = 0.338/0.828/3.101/0.777 ms
```

如果收到以下错误消息，请将附加的虚拟磁盘上的`cache`更改为`none`：

```
# virsh migrate --live MasteringKVM01 qemu+ssh://PacktPhy02/system --verbose
error: Unsafe migration: Migration may lead to data corruption if disks use cache != none
# virt-xml MasteringKVM01 --edit --disk target=vda,cache=none
```

`target`是要更改缓存的磁盘。您可以通过运行以下命令找到目标名称：

```
virsh dumpxml MasteringKVM01
```

在执行活迁移时，您可以尝试一些其他选项，如下所示：

+   --未定义域：用于从 KVM 主机中删除 KVM 域的选项。

+   --暂停域：暂停 KVM 域，即暂停 KVM 域，直到我们恢复它。

+   `--compressed`：当我们进行虚拟机迁移时，此选项使我们能够压缩内存。这将意味着更快的迁移过程，基于`–comp-methods`参数。

+   `--abort-on-error`：如果迁移过程出现错误，它会自动停止。这是一个安全的默认选项，因为它将有助于在迁移过程中发生任何类型的损坏的情况下。

+   `--unsafe`：这个选项有点像`–abort-on-error`选项的反面。这个选项会不惜一切代价进行迁移，即使出现错误、数据损坏或其他意外情况。对于这个选项要非常小心，不要经常使用，或者在任何您想要确保虚拟机数据一致性的情况下使用。

您可以在 RHEL 7—虚拟化部署和管理指南中阅读更多关于这些选项的信息（您可以在本章末尾的*进一步阅读*部分找到链接）。此外，`virsh`命令还支持以下选项：

+   `virsh migrate-setmaxdowntime <domain>`：在迁移虚拟机时，不可避免地会有时候虚拟机会短暂不可用。这可能发生，例如，因为交接过程，当我们将虚拟机从一个主机迁移到另一个主机时，我们刚好到达状态平衡点（也就是说，源主机和目标主机具有相同的虚拟机内容，并准备好从源主机清除源虚拟机并在目标主机上运行）。基本上，源虚拟机被暂停和终止，目标主机虚拟机被取消暂停并继续。通过使用这个命令，KVM 堆栈试图估计这个停止阶段将持续多长时间。这是一个可行的选择，特别是对于非常繁忙的虚拟机，因此在迁移过程中它们的内存内容会发生很大变化。

+   `virsh migrate-setspeed <domain> bandwidth`：我们可以将这个选项视为准**服务质量**（**QoS**）选项。通过使用它，我们可以设置以 MiB/s 为单位的迁移过程中的带宽量。如果我们的网络很忙，这是一个非常好的选择（例如，如果我们在同一物理网络上有多个**虚拟局域网**（**VLANs**），并且由于此原因有带宽限制）。较低的数字会减慢迁移过程。

+   `virsh migrate-getspeed <domain>`：我们可以将这个选项视为`migrate-setspeed`命令的*获取信息*选项，以检查我们为`virsh migrate-setspeed`命令分配了哪些设置。

正如您所看到的，从技术角度来看，迁移是一个复杂的过程，有多种不同类型和大量额外的配置选项，可以用于管理目的。尽管如此，它仍然是虚拟化环境中非常重要的功能，很难想象在没有它的情况下工作。

# 摘要

在本章中，我们涵盖了创建虚拟机和配置虚拟机硬件的不同方法。我们还详细介绍了虚拟机迁移，以及在线和离线虚拟机迁移。在下一章中，我们将学习虚拟机磁盘、虚拟机模板和快照。了解这些概念非常重要，因为它们将使您在管理虚拟化环境时更加轻松。

# 问题

1.  我们可以使用哪些命令行工具来在`libvirt`中部署虚拟机？

1.  我们可以使用哪些图形界面工具来在`libvirt`中部署虚拟机？

1.  在配置我们的虚拟机时，我们应该注意哪些配置方面？

1.  在线和离线虚拟机迁移有什么区别？

1.  虚拟机迁移和虚拟机存储迁移有什么区别？

1.  我们如何为迁移过程配置带宽？

# 进一步阅读

请参考以下链接，了解本章涵盖的更多信息：

+   使用`virt-manager`管理虚拟机：[`virt-manager.org/`](https://virt-manager.org/)

+   oVirt-安装 Linux VM：[`www.ovirt.org/documentation/vmm-guide/chap-Installing_Linux_Virtual_Machines.html`](https://www.ovirt.org/documentation/vmm-guide/chap-Installing_Linux_Virtual_Machines.html)

+   克隆 VM：[`access.redhat.com/documentation/en-us/red_hat_enterprise_linux/8/html/configuring_and_managing_virtualization/cloning-virtual-machines_configuring-and-managing-virtualization`](https://access.redhat.com/documentation/en-us/red_hat_enterprise_linux/8/html/configuring_and_managing_virtualization/cloning-virtual-machines_configuring-and-managing-virtualization)

+   迁移 VM：[`access.redhat.com/documentation/en-us/red_hat_enterprise_linux/8/html/configuring_and_managing_virtualization/migrating-virtual-machines_configuring-and-managing-virtualization`](https://access.redhat.com/documentation/en-us/red_hat_enterprise_linux/8/html/configuring_and_managing_virtualization/migrating-virtual-machines_configuring-and-managing-virtualization)

+   缓存：[`access.redhat.com/documentation/en-us/red_hat_enterprise_linux/7/html/virtualization_tuning_and_optimization_guide/sect-virtualization_tuning_optimization_guide-blockio-caching`](https://access.redhat.com/documentation/en-us/red_hat_enterprise_linux/7/html/virtualization_tuning_and_optimization_guide/sect-virtualization_tuning_optimization_guide-blockio-caching)

+   NUMA 和内存局部性对 Microsoft SQL Server 2019 性能的影响：[`www.daaam.info/Downloads/Pdfs/proceedings/proceedings_2019/049.pdf`](https://www.daaam.info/Downloads/Pdfs/proceedings/proceedings_2019/049.pdf)

+   虚拟化部署和管理指南：[`access.redhat.com/documentation/en-us/red_hat_enterprise_linux/7/html/virtualization_deployment_and_administration_guide/index`](https://access.redhat.com/documentation/en-us/red_hat_enterprise_linux/7/html/virtualization_deployment_and_administration_guide/index)
