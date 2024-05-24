# 精通 KVM 虚拟化（三）

> 原文：[`zh.annas-archive.org/md5/937685F0CEE189D5B83741D8ADA1BFEE`](https://zh.annas-archive.org/md5/937685F0CEE189D5B83741D8ADA1BFEE)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第八章：创建和修改 VM 磁盘、模板和快照

这一章代表了本书第二部分的结束，我们在这一部分专注于各种`libvirt`功能——安装`libvirt`网络和存储，虚拟设备和显示协议，安装**虚拟机**（**VMs**）并配置它们……所有这些都是为了为本书的下一部分做准备，下一部分将涉及自动化、定制和编排。为了让我们能够学习这些概念，我们现在必须把焦点转移到 VM 及其高级操作上——修改、模板化、使用快照等。本书的后面经常会提到这些主题中的一些，这些主题在生产环境中出于各种业务原因可能会更有价值。让我们深入研究并涵盖它们。

在本章中，我们将涵盖以下主题：

+   使用`libguestfs`工具修改 VM 映像

+   VM 模板化

+   `virt-builder`和`virt-builder`存储库

+   快照

+   在使用快照时的用例和最佳实践

# 使用`libguestfs`工具修改 VM 映像

随着本书重点转向扩展，我们不得不在本书的这一部分结束时介绍一系列命令，这些命令将在我们开始构建更大的环境时非常有用。对于更大的环境，我们确实需要各种自动化、定制和编排工具，我们将在下一章开始讨论这些工具。但首先，我们必须专注于我们已经掌握的各种定制工具。这些命令行实用程序对于许多不同类型的操作都非常有帮助，从`guestfish`（用于访问和修改 VM 文件）到`virt-p2v`（`virt-sysprep`（在模板化和克隆之前*sysprep* VM）。因此，让我们以工程方式逐步接触这些实用程序的主题。

`libguestfs`是一个用于处理 VM 磁盘的命令行实用程序库。该库包括大约 30 个不同的命令，其中一些包括在以下列表中：

+   `guestfish`

+   `virt-builder`

+   `virt-builder-repository`

+   `virt-copy-in`

+   `virt-copy-out`

+   `virt-customize`

+   `virt-df`

+   `virt-edit`

+   `virt-filesystems`

+   `virt-rescue`

+   `virt-sparsify`

+   `virt-sysprep`

+   `virt-v2v`

+   `virt-p2v`

我们将从五个最重要的命令开始——`virt-v2v`、`virt-p2v`、`virt-copy-in`、`virt-customize`和`guestfish`。在我们讨论 VM 模板化时，我们将涵盖`virt-sysprep`，并且本章的一个单独部分专门介绍了`virt-builder`，因此我们暂时跳过这些命令。

## virt-v2v

假设您有一个基于 Hyper-V、Xen 或 VMware 的 VM，并且希望将其转换为 KVM、oVirt、Red Hat Enterprise Virtualization 或 OpenStack。我们将以 VMware 为例，将其转换为由`libvirt`实用程序管理的 KVM VM。由于 VMware 平台的 6.0+版本（无论是在**ESX 集成**（**ESXi**）hypervisor 方面还是在 vCenter 服务器和插件方面）引入了一些更改，将 VM 导出并转换为 KVM 机器将非常耗时——无论是使用 vCenter 服务器还是 ESXi 主机作为源。因此，将 VMware VM 转换为 KVM VM 的最简单方法如下：

1.  在 vCenter 或 ESXi 主机中关闭 VM。

1.  将 VM 导出为`Downloads`目录。

1.  从[`code.vmware.com/web/tool/4.3.0/ovf`](https://code.vmware.com/web/tool/4.3.0/ovf)安装 VMware `OVFtool`实用程序。

1.  将导出的 VM 文件移动到`OVFtool`安装文件夹。

1.  将 VM 以 OVF 格式转换为**Open Virtualization Appliance**（**OVA**）格式。

我们需要`OVFtool`的原因相当令人失望——似乎 VMware 删除了直接导出 OVA 文件的选项。幸运的是，`OVFtool`适用于基于 Windows、Linux 和 OS X 的平台，因此您不会在使用它时遇到麻烦。以下是该过程的最后一步：

![图 8.1 - 使用 OVFtool 将 OVF 转换为 OVA 模板格式](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/ms-kvm-vrt/img/B14834_08_01.jpg)

图 8.1 - 使用 OVFtool 将 OVF 转换为 OVA 模板格式

完成后，我们可以轻松地将`v2v.ova`文件上传到我们的 KVM 主机，并在`ova`文件目录中键入以下命令：

```
virt-v2v -i ova v2v.ova -of qcow2 -o libvirt -n default
```

`-of`和`-o`选项指定输出格式（`qcow2` libvirt 映像），`-n`确保 VM 连接到默认虚拟网络。

如果您需要将 Hyper-V VM 转换为 KVM，可以这样做：

```
virt-v2v -i disk /location/of/virtualmachinedisk.vhdx -o local -of qcow2 -os /var/lib/libvirt/images
```

确保您正确指定了 VM 磁盘位置。 `-o local` 和 `-os /var/lib/libvirt/images` 选项确保转换后的磁盘映像被保存在指定目录中（KVM 默认映像目录）。

还有其他类型的 VM 转换过程，例如将物理机器转换为虚拟机。让我们现在来介绍一下。

## virt-p2v

现在我们已经介绍了`virt-v2v`，让我们转而介绍`virt-p2v`。基本上，`virt-v2v`和`virt-p2v`执行的工作似乎相似，但`virt-p2v`的目的是将*物理*机器转换为*VM*。从技术上讲，这是有很大不同的，因为使用`virt-v2v`，我们可以直接访问管理服务器和 hypervisor，并在转换 VM 时（或通过 OVA 模板）进行转换。对于物理机器，没有管理机器可以提供某种支持或**应用程序编程接口**（**API**）来执行转换过程。我们必须直接*攻击*物理机器。在 IT 的实际世界中，通常通过某种代理或附加应用程序来完成这一点。

举个例子，如果您想将物理 Windows 机器转换为基于 VMware 的 VM，您需要在需要转换的系统上安装 VMware vCenter Converter Standalone。然后，您需要选择正确的操作模式，并将完整的转换过程*流式传输*到 vCenter/ESXi。这确实效果很好，但是举个例子，RedHat 的方法有点不同。它使用引导介质来转换物理服务器。因此，在使用此转换过程之前，您必须登录到客户门户（位于[`access.redhat.com/downloads/content/479/ver=/rhel---8/8.0/x86_64/product-software`](https://access.redhat.com/downloads/content/479/ver=/rhel---8/8.0/x86_64/product-software)）以使用`virt-p2v`和`virt-p2v-make-disk`实用程序创建映像。但是，`virt-p2v-make-disk`实用程序使用`virt-builder`，我们稍后将在本章的另一部分中详细介绍。因此，让我们暂时搁置这个讨论，因为我们很快将全力回来。

作为一个旁注，在此命令的支持目的地列表中，我们可以使用 Red Hat 企业虚拟化、OpenStack 或 KVM/`libvirt`。在支持的架构方面，`virt-p2v`仅支持基于 x86_64 的平台，并且仅在 RHEL/CentOS 7 和 8 上使用。在计划进行 P2V 转换时，请记住这一点。

## guestfish

本章介绍的最后一个实用程序是`guestfish`。这是一个非常重要的实用程序，它使您能够对实际的 VM 文件系统进行各种高级操作。我们还可以使用它进行不同类型的转换，例如，将`tar.gz`转换为虚拟磁盘映像；将虚拟磁盘映像从`ext4`文件系统转换为`ext4`文件系统；等等。我们将向您展示如何使用它来打开 VM 映像文件并进行一些操作。

第一个例子是一个非常常见的例子——您已经准备好了一个带有完整 VM 的`qcow2`镜像；客户操作系统已安装；一切都已配置好；您准备将该 VM 文件复制到其他地方以便重复使用；然后……您记得您没有根据某些规范配置根密码。假设这是您为客户做的事情，该客户对初始根密码有特定的要求。这对客户来说更容易——他们不需要通过电子邮件收到您发送的密码；他们只需要记住一个密码；并且，在收到镜像后，它将用于创建 VM。在创建并运行 VM 之后，根密码将被更改为根据安全实践使用的客户密码。

因此，基本上，第一个例子是一个*人类*的例子——忘记做某事，然后想要修复，但（在这种情况下）不实际运行 VM，因为这可能会改变很多设置，特别是如果您的`qcow2`镜像是为 VM 模板化而创建的，那么您*绝对*不希望启动该 VM 来修复某些东西。关于这一点，我们将在本章的下一部分详细介绍。

这是`guestfish`的一个理想用例。假设我们的`qcow2`镜像名为`template.qcow2`。让我们将根密码更改为其他内容——例如，`packt123`。首先，我们需要该密码的哈希。最简单的方法是使用带有`-6`选项的`openssl`（相当于 SHA512 加密），如下面的截图所示：

![图 8.2 – 使用 openssl 创建基于 SHA512 的密码哈希](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/ms-kvm-vrt/img/B14834_08_02.jpg)

图 8.2 – 使用 openssl 创建基于 SHA512 的密码哈希

现在我们有了哈希，我们可以挂载和编辑我们的镜像，如下所示：

![图 8.3 – 使用 guestfish 编辑我们的 qcow2 VM 镜像中的根密码](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/ms-kvm-vrt/img/B14834_08_03.jpg)

图 8.3 – 使用 guestfish 编辑我们的 qcow2 VM 镜像中的根密码

我们输入的 Shell 命令用于直接访问图像（无需涉及`libvirt`）并以读写模式挂载我们的图像。然后，我们启动了我们的会话（`guestfish run`命令），检查图像中存在哪些文件系统（`list-filesystems`），并将文件系统挂载到根文件夹上。在倒数第二步中，我们将根密码的哈希更改为由`openssl`创建的哈希。`exit`命令关闭我们的`guestfish`会话并保存更改。

您可以使用类似的原理——例如——从`/etc/ssh`目录中删除遗忘的`sshd`密钥，删除用户`ssh`目录等。该过程如下截图所示：

![图 8.4 – 使用 virt-customize 在 qcow2 镜像内执行命令](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/ms-kvm-vrt/img/B14834_08_04.jpg)

图 8.4 – 使用 virt-customize 在 qcow2 镜像内执行命令

第二个例子也非常有用，因为它涉及到下一章中涵盖的一个主题（`cloud-init`），通常用于通过操纵 VM 实例的早期初始化来配置云 VM。此外，从更广泛的角度来看，您可以使用这个`guestfish`示例来操纵 VM 镜像*内部*的服务配置。因此，假设我们的 VM 镜像被配置为自动启动`cloud-init`服务。出于某种原因，我们希望禁用该服务——例如，为了调试`cloud-init`配置中的错误。如果我们没有能力操纵`qcow`镜像内容，我们将不得不启动该 VM，使用`systemctl`来*禁用*该服务，然后——也许——执行整个过程来重新封装该 VM，如果这是一个 VM 模板的话。因此，让我们使用`guestfish`来达到相同的目的，如下所示：

![图 8.5 – 使用 guestfish 在 VM 启动时禁用 cloud-init 服务](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/ms-kvm-vrt/img/B14834_08_05.jpg)

图 8.5 – 使用 guestfish 在 VM 启动时禁用 cloud-init 服务

重要提示

在这个例子中要小心，因为通常我们会在`ln -sf`之间使用空格字符。但在我们的`guestfish`示例中不是这样—它需要*不*使用空格。

最后，假设我们需要将文件复制到我们的镜像。例如，我们需要将本地的`/etc/resolv.conf`文件复制到镜像中，因为我们忘记为此目的配置我们的`virt-copy-in`命令，如下截图所示：

![图 8.6 - 使用 virt-copy-in 将文件复制到我们的镜像](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/ms-kvm-vrt/img/B14834_08_06.jpg)

图 8.6 - 使用 virt-copy-in 将文件复制到我们的镜像

我们在本章的这一部分涵盖的主题对接下来的内容非常重要，即讨论创建虚拟机模板。

# VM 模板化

虚拟机最常见的用例之一是创建虚拟机*模板*。因此，假设我们需要创建一个将用作模板的虚拟机。我们在这里字面上使用术语*模板*，就像我们可以为 Word、Excel、PowerPoint 等使用模板一样，因为虚拟机模板存在的原因与此相同—为了让我们拥有一个*熟悉*的预配置工作环境，以便我们不需要从头开始。在虚拟机模板的情况下，我们谈论的是*不从头安装虚拟机客户操作系统*，这是一个巨大的时间节省。想象一下，如果你得到一个任务，需要为某种测试环境部署 500 个虚拟机，以测试某种东西在扩展时的工作情况。即使考虑到你可以并行安装，也会花费数周时间。

虚拟机需要被视为*对象*，它们具有某些*属性*或*特性*。从*外部*的角度来看（即从`libvirt`的角度），虚拟机有一个名称、一个虚拟磁盘、一个虚拟中央处理单元（CPU）和内存配置、连接到虚拟交换机等等。我们在*第七章*中涵盖了这个主题，*VM：安装、配置和生命周期管理*。也就是说，我们没有涉及*虚拟机内部*的主题。从这个角度来看（基本上是从客户操作系统的角度），虚拟机也有一些属性—安装的客户操作系统版本、Internet Protocol（IP）配置、虚拟局域网（VLAN）配置...之后，这取决于基于哪个操作系统的家族虚拟机。因此，我们需要考虑以下内容：

+   如果我们谈论基于 Microsoft Windows 的虚拟机，我们必须考虑服务和软件配置，注册表配置和许可证配置。

+   如果我们谈论基于 Linux 的虚拟机，我们必须考虑服务和软件配置，安全外壳（SSH）密钥配置，许可证配置等等。

甚至可以更具体。例如，为基于 Ubuntu 的虚拟机准备模板与为基于 CentOS 8 的虚拟机准备模板是不同的。为了正确创建这些模板，我们需要学习一些基本程序，然后每次创建虚拟机模板时都可以重复使用。

考虑这个例子：假设你希望创建四个 Apache Web 服务器来托管你的 Web 应用程序。通常，使用传统的手动安装方法，你首先必须创建四个具有特定硬件配置的虚拟机，逐个在每个虚拟机上安装操作系统，然后使用`yum`或其他软件安装方法下载并安装所需的 Apache 软件包。这是一项耗时的工作，因为你将主要进行重复的工作。但是使用模板方法，可以在较短的时间内完成。为什么？因为你将绕过操作系统安装和其他配置任务，直接从包含预配置操作系统镜像的模板中生成虚拟机，其中包含所有所需的 Web 服务器软件包，准备供使用。

以下截图显示了手动安装方法涉及的步骤。您可以清楚地看到*步骤 2-5*只是在所有四个 VM 上执行的重复任务，它们将占用大部分时间来准备您的 Apache Web 服务器：

![图 8.7 - 不使用 VM 模板安装四个 Apache Web 服务器](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/ms-kvm-vrt/img/B14834_08_07.jpg)

图 8.7 - 不使用 VM 模板安装四个 Apache Web 服务器

现在，看看通过简单地遵循*步骤 1-5*一次，创建一个模板，然后使用它部署四个相同的 VM，步骤数量是如何大幅减少的。这将为您节省大量时间。您可以在以下图表中看到差异：

![图 8.8 - 使用 VM 模板安装四个 Apache Web 服务器](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/ms-kvm-vrt/img/B14834_08_08.jpg)

图 8.8 - 使用 VM 模板安装四个 Apache Web 服务器

然而，这并不是全部。实际上从*步骤 3*到*步骤 4*（从**创建模板**到部署 VM1-4）有不同的方式，其中包括完全克隆过程或链接克隆过程，详细介绍如下：

+   **完全克隆**：使用完全克隆机制部署的 VM 将创建 VM 的完整副本，问题在于它将使用与原始 VM 相同的容量。

+   **链接克隆**：使用薄克隆机制部署的 VM 将模板镜像作为只读模式的基础镜像，并链接一个额外的**写时复制**（COW）镜像来存储新生成的数据。这种配置方法在云和虚拟桌面基础设施（VDI）环境中被广泛使用，因为它可以节省大量磁盘空间。请记住，快速存储容量是非常昂贵的，因此在这方面的任何优化都将节省大量资金。链接克隆还会对性能产生影响，我们稍后会讨论一下。

现在，让我们看看模板是如何工作的。

## 使用模板

在本节中，您将学习如何使用`virt-manager`中可用的`virt-clone`选项创建 Windows 和 Linux VM 的模板。虽然`virt-clone`实用程序最初并不是用于创建模板，但当与`virt-sysprep`和其他操作系统封装实用程序一起使用时，它可以实现这一目的。请注意，克隆和主镜像之间存在差异。克隆镜像只是一个 VM，而主镜像是可以用于部署数百甚至数千个新 VM 的 VM 副本。

### 创建模板

模板是通过将 VM 转换为模板来创建的。实际上，这是一个包括以下步骤的三步过程：

1.  安装和定制 VM，包括所有所需的软件，这将成为模板或基础镜像。

1.  删除所有系统特定属性以确保 VM 的唯一性 - 我们需要处理 SSH 主机密钥、网络配置、用户帐户、媒体访问控制（MAC）地址、许可信息等。

1.  通过在名称前加上模板前缀将 VM 标记为模板。一些虚拟化技术对此有特殊的 VM 文件类型（例如 VMware 的`.vmtx`文件），这实际上意味着您不必重命名 VM 来标记它为模板。

要了解实际的过程，让我们创建两个模板并从中部署一个 VM。我们的两个模板将是以下内容：

+   具有完整 Linux、Apache、MySQL 和 PHP（LAMP）堆栈的 CentOS 8 VM

+   具有 SQL Server Express 的 Windows Server 2019 VM

让我们继续创建这些模板。

#### 示例 1 - 准备一个带有完整 LAMP 堆栈的 CentOS 8 模板

CentOS 的安装对我们来说应该是一个熟悉的主题，所以我们只会专注于 LAMP 堆栈的*AMP*部分和模板部分。因此，我们的过程将如下所示：

1.  创建一个 VM 并在其上安装 CentOS 8，使用您喜欢的安装方法。保持最小化，因为这个 VM 将被用作为为此示例创建的模板的基础。

1.  通过 SSH 进入或接管虚拟机并安装 LAMP 堆栈。以下是一个脚本，用于在操作系统安装完成后在 CentOS 8 上安装 LAMP 堆栈所需的一切。让我们从软件包安装开始，如下所示：

```
yum -y update
yum -y install httpd httpd-tools mod_ssl
systemctl start httpd
systemctl enable httpd
yum -y install mariadb-server mariadb
yum install -y php php-fpm php-mysqlnd php-opcache php-gd php-xml php-mbstring libguestfs*
```

在软件安装完成后，让我们进行一些服务配置——启动所有必要的服务并启用它们，并重新配置防火墙以允许连接，如下所示：

```
systemctl start mariadb
systemctl enable mariadb
systemctl start php-fpm
systemctl enable php-fpm
firewall-cmd --permanent --zone=public --add-service=http
firewall-cmd --permanent --zone=public --add-service=https
systemctl reload firewalld
```

我们还需要配置一些与目录所有权相关的安全设置，例如 Apache Web 服务器的**安全增强型 Linux**（**SELinux**）配置。让我们像这样进行下一步操作：

```
chown apache:apache /var/www/html -R
semanage fcontext -a -t httpd_sys_content_t "/var/www/html(/.*)?"
restorecon -vvFR /var/www/html
setsebool -P httpd_execmem 1
```

1.  完成此操作后，我们需要配置 MariaDB，因为我们必须为数据库管理用户设置某种 MariaDB 根密码并配置基本设置。这通常是通过 MariaDB 软件包提供的`mysql_secure_installation`脚本完成的。因此，这是我们的下一步，如下面的代码片段所示：

```
mysql_secure_installation script, it is going to ask us a series of questions, as illustrated in the following screenshot:![Figure 8.9 – First part of MariaDB setup: assigning a root password that is empty after installation    ](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/ms-kvm-vrt/img/B14834_08_09.jpg)Figure 8.9 – First part of MariaDB setup: assigning a root password that is empty after installationAfter assigning a root password for the MariaDB database, the next steps are more related to housekeeping—removing anonymous users, disallowing remote login, and so on. Here's what that part of wizard looks like:![Figure 8.10 – Housekeeping: anonymous users, root login setup, test database data removal    ](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/ms-kvm-vrt/img/B14834_08_10.jpg)Figure 8.10 – Housekeeping: anonymous users, root login setup, test database data removalWe installed all the necessary services—Apache, MariaDB—and all the necessary additional packages (PHP, `sample index.html` file and place it in `/var/www/html`), but we're not going to do that right now. In production environments, we'd just copy web page contents to that directory and be done with it.
```

1.  现在，必需的 LAMP 设置已按我们的要求配置好，关闭虚拟机并运行`virt-sysprep`命令进行封存。如果要*过期*根密码（即在下次登录时强制更改根密码），请输入以下命令：

```
passwd --expire root
```

我们的测试虚拟机名为 LAMP，主机名为`PacktTemplate`，因此以下是必要的步骤，通过一行命令呈现：

```
virsh shutdown LAMP; sleep 10; virsh list
```

我们的 LAMP 虚拟机现在已准备好重新配置为模板。为此，我们将使用`virt-sysprep`命令。

#### 什么是 virt-sysprep？

这是`libguestfs-tools-c`软件包提供的命令行实用程序，用于简化 Linux 虚拟机的封存和通用化过程。它会自动删除系统特定信息，使克隆可以从中创建。`virt-sysprep`可用于添加一些额外的配置位和部分，例如用户、组、SSH 密钥等。

有两种方法可以针对 Linux 虚拟机调用`virt-sysprep`：使用`-d`或`-a`选项。第一个选项指向预期的客户端，使用其名称或`virt-sysprep`命令，即使客户端未在`libvirt`中定义。

执行`virt-sysprep`命令后，它会执行一系列的`sysprep`操作，通过从中删除系统特定信息使虚拟机镜像变得干净。如果您想了解此命令在后台的工作原理，请在命令中添加`--verbose`选项。该过程可以在以下截图中看到：

![图 8.11 – virt-sysprep 在虚拟机上发挥魔力](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/ms-kvm-vrt/img/B14834_08_11.jpg)

图 8.11 – virt-sysprep 在虚拟机上发挥魔力

默认情况下，`virt-sysprep`执行超过 30 个操作。您还可以选择要使用的特定 sysprep 操作。要获取所有可用操作的列表，请运行`virt-sysprep --list-operation`命令。默认操作用星号标记。您可以使用`--operations`开关更改默认操作，后跟逗号分隔的要使用的操作列表。请参阅以下示例：

![图 8.12 – 使用 virt-sysprep 自定义在模板虚拟机上执行的操作](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/ms-kvm-vrt/img/B14834_08_12.jpg)

图 8.12 – 使用 virt-sysprep 自定义在模板虚拟机上执行的操作

请注意，这一次它只执行了`ssh-hostkeys`和`udev-persistentnet`操作，而不是典型的操作。您可以自行决定在模板中进行多少清理工作。

现在，我们可以通过在名称前添加*template*来将此虚拟机标记为模板。甚至可以在从`libvirt`中取消定义虚拟机之前备份其**可扩展标记语言**（**XML**）文件。

重要提示

确保从现在开始，此虚拟机永远不要启动；否则，它将丢失所有 sysprep 操作，甚至可能导致使用薄方法部署的虚拟机出现问题。

要重命名虚拟机，请使用`virsh domrename`作为 root 用户，如下所示：

```
# virsh domrename LAMP LAMP-Template
```

`LAMP-Template`，我们的模板，现在已准备好用于未来的克隆过程。您可以使用以下命令检查其设置：

```
# virsh dominfo LAMP-Template
```

最终结果应该是这样的：

![图 8.13 - 在我们的模板 VM 上使用 virsh dominfo](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/ms-kvm-vrt/img/B14834_08_13.jpg)

图 8.13 - 在我们的模板 VM 上使用 virsh dominfo

下一个示例将是关于准备一个预安装了 Microsoft **结构化查询语言**（**SQL**）数据库的 Windows Server 2019 模板 - 这是我们许多人在环境中需要使用的常见用例。让我们看看我们如何做到这一点。

#### 示例 2 - 准备带有 Microsoft SQL 数据库的 Windows Server 2019 模板

`virt-sysprep` 不适用于 Windows 客户端，而且很少有可能在短时间内添加支持。因此，为了通用化 Windows 机器，我们需要访问 Windows 系统并直接运行`sysprep`。

`sysprep`工具是一个用于从 Windows 映像中删除特定系统数据的本机 Windows 实用程序。要了解有关此实用程序的更多信息，请参阅本文：[`docs.microsoft.com/en-us/windows-hardware/manufacture/desktop/sysprep--generalize--a-windows-installation`](https://docs.microsoft.com/en-us/windows-hardware/manufacture/desktop/sysprep--generalize--a-windows-installation)。

我们的模板准备过程将如下进行：

1.  创建一个 VM 并在其上安装 Windows Server 2019 操作系统。我们的 VM 将被称为`WS2019SQL`。

1.  安装 Microsoft SQL Express 软件，并在配置好后，重新启动 VM 并启动`sysprep`应用程序。`sysprep`的`.exe`文件位于`C:\Windows\System32\sysprep`目录中。通过在运行框中输入`sysprep`并双击`sysprep.exe`来导航到那里。

1.  在**系统清理操作**下，选择**进入系统的 OOBE**并勾选**通用化**复选框，如果您想进行**系统标识号**（**SID**）重建，如下截图所示：![图 8.14 - 小心使用 sysprep 选项；OOBE，通用化，并且强烈建议使用关闭选项](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/ms-kvm-vrt/img/B14834_08_14.jpg)

图 8.14 - 小心使用 sysprep 选项；OOBE，通用化和关闭选项是强烈建议的

1.  在那之后，`sysprep`过程将开始，并在完成后关闭。

1.  使用与我们在 LAMP 模板上使用的相同过程来重命名 VM，如下所示：

```
# virsh domrename WS2019SQL WS2019SQL-Template
```

同样，我们可以使用`dominfo`选项来检查我们新创建的模板的基本信息，如下所示：

```
# virsh dominfo WS2019SQL-Template
```

重要提示

在将来更新模板时要小心 - 您需要运行它们，更新它们，并重新密封它们。对于 Linux 发行版，这样做不会有太多问题。但是，对于 Microsoft Windows `sysprep`（启动模板 VM，更新，`sysprep`，并在将来重复）将使您陷入`sysprep`会抛出错误的情况。因此，这里还有另一种思路可以使用。您可以像我们在本章的这一部分中所做的那样执行整个过程，但不要`sysprep`它。这样，您可以轻松更新 VM，然后克隆它，然后`sysprep`它。这将节省您大量时间。

接下来，我们将看到如何从模板部署 VM。

## 从模板部署 VM

在前一节中，我们创建了两个模板映像；第一个模板映像仍然在`libvirt`中定义为`VM`，并命名为`LAMP-Template`，第二个称为`WS2019SQL-Template`。我们现在将使用这两个 VM 模板来从中部署新的 VM。

### 使用完全克隆部署 VM

执行以下步骤使用克隆配置来部署 VM：

1.  打开 VM 管理器（`virt-manager`），然后选择`LAMP-Template` VM。右键单击它，然后选择**克隆**选项，这将打开**克隆虚拟机**窗口，如下截图所示：![图 8.15 - 从 VM 管理器克隆 VM](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/ms-kvm-vrt/img/B14834_08_15.jpg)

图 8.15 - 从 VM 管理器克隆 VM

1.  为生成的 VM 提供名称并跳过所有其他选项。单击**克隆**按钮开始部署。等待克隆操作完成。

1.  完成后，您新部署的 VM 已经准备好使用，您可以开始使用它。您可以在以下截图中看到该过程的输出：

![图 8.16-已创建完整克隆（LAMP01）](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/ms-kvm-vrt/img/B14834_08_16.jpg)

图 8.16-已创建完整克隆（LAMP01）

由于我们之前的操作，`LAMP01` VM 是从`LAMP-Template`部署的，但由于我们使用了完整克隆方法，它们是独立的，即使您删除`LAMP-Template`，它们也会正常运行。

我们还可以使用链接克隆，这将通过创建一个锚定到基本映像的 VM 来节省大量的磁盘空间。让我们接下来做这个。

### 使用链接克隆部署 VM

执行以下步骤，使用链接克隆方法开始 VM 部署：

1.  使用`/var/lib/libvirt/images/WS2019SQL.qcow2`作为后备文件创建两个新的`qcow2`图像，如下所示：

```
# qemu-img create -b /var/lib/libvirt/images/WS2019SQL.qcow2 -f qcow2 /var/lib/libvirt/images/LinkedVM1.qcow2
# qemu-img create -b /var/lib/libvirt/images/WS2019SQL.qcow2 -f qcow2 /var/lib/libvirt/images/LinkedVM2.qcow2
```

1.  验证新创建的`qcow2`图像的后备文件属性是否正确指向`/var/lib/libvirt/images/WS2019SQL.qcow2`图像，使用`qemu-img`命令。这三个步骤的最终结果应该如下所示：![图 8.17-创建链接克隆图像](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/ms-kvm-vrt/img/B14834_08_17.jpg)

图 8.17-创建链接克隆图像

1.  现在，使用`virsh`命令将模板 VM 配置转储到两个 XML 文件中。我们这样做两次，以便我们有两个 VM 定义。在更改了一些参数后，我们将它们导入为两个新的 VM，如下所示：

```
virsh dumpxml WS2019SQL-Template > /root/SQL1.xml
virsh dumpxml WS2019SQL-Template > /root/SQL2.xml
```

1.  使用`uuidgen -r`命令生成两个随机 UUID。我们将需要它们用于我们的 VM。该过程可以在以下截图中看到：![图 8.18-为我们的 VM 生成两个新的 UUID](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/ms-kvm-vrt/img/B14834_08_18.jpg)

图 8.18-为我们的 VM 生成两个新的 UUID

1.  通过为它们分配新的 VM 名称和 UUID 编辑`SQL1.xml`和`SQL2.xml`文件。这一步是强制性的，因为 VM 必须具有唯一的名称和 UUID。让我们将第一个 XML 文件中的名称更改为`SQL1`，将第二个 XML 文件中的名称更改为`SQL2`。我们可以通过更改`<name></name>`语句来实现这一点。然后，在`SQL1.xml`和`SQL2.xml`的`<uuid></uuid>`语句中复制并粘贴我们使用`uuidgen`命令创建的 UUID。因此，配置文件中这两行的相关条目应该如下所示：![图 8.19-更改其各自 XML 配置文件中的 VM 名称和 UUID](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/ms-kvm-vrt/img/B14834_08_19.jpg)

图 8.19-更改其各自 XML 配置文件中的 VM 名称和 UUID

1.  我们需要更改`SQL1`和`SQL2`镜像文件中虚拟磁盘的位置。在这些配置文件后面找到`.qcow2`文件的条目，并更改它们，使其使用我们在*步骤 1*中创建的文件的绝对路径，如下所示：![图 8.20-更改 VM 镜像位置，使其指向新创建的链接克隆图像](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/ms-kvm-vrt/img/B14834_08_20.jpg)

图 8.20-更改 VM 镜像位置，使其指向新创建的链接克隆图像

1.  现在，使用`virsh create`命令将这两个 XML 文件作为 VM 定义导入，如下所示：![图 8.21-从 XML 定义文件创建两个新的 VM](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/ms-kvm-vrt/img/B14834_08_21.jpg)

图 8.21-从 XML 定义文件创建两个新的 VM

1.  使用`virsh`命令验证它们是否已定义和运行，如下所示：![图 8.22-两个新的 VM 已经启动](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/ms-kvm-vrt/img/B14834_08_22.jpg)

图 8.22-两个新的 VM 已经启动

1.  VM 已经启动，所以我们现在可以检查我们链接克隆过程的最终结果。这两个 VM 的虚拟磁盘应该相当小，因为它们都使用相同的基本镜像。让我们检查客户磁盘映像大小-请注意在以下截图中，`LinkedVM1.qcow`和`LinkedVM2.qcow`文件的大小大约是其基本映像的 50 倍小：

![图 8.23 – 链接克隆部署的结果：基础镜像，小增量镜像](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/ms-kvm-vrt/img/B14834_08_23.jpg)

图 8.23 – 链接克隆部署的结果：基础镜像，小增量镜像

这应该提供了大量关于使用链接克隆过程的示例和信息。不要走得太远（在单个基础镜像上创建许多链接克隆），你应该没问题。但现在，是时候转到我们的下一个主题了，那就是关于`virt-builder`。如果你想快速部署 VM 而不实际安装它们，`virt-builder`的概念非常重要。我们可以使用`virt-builder`存储库来实现这一点。让我们学习如何做到这一点。

# virt-builder 和 virt-builder 存储库

在`libguestfs`软件包中最重要的工具之一是`virt-builder`。假设你*真的*不想从头构建一个 VM，要么是因为你没有时间，要么是因为你根本不想麻烦。我们将以 CentOS 8 为例，尽管现在支持的发行版列表大约有 50 个（发行版及其子版本），如你在以下截图中所见：

![图 8.24 – virt-builder 支持的操作系统和 CentOS 发行版](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/ms-kvm-vrt/img/B14834_08_24.jpg)

图 8.24 – virt-builder 支持的操作系统和 CentOS 发行版

在我们的测试场景中，我们需要尽快创建一个 CentOS 8 镜像，并从该镜像创建一个 VM。到目前为止，部署 VM 的所有方式都是基于从头安装、克隆或模板化的想法。这些要么是*从零开始*，要么是*先部署模板，然后再进行配置*的机制。如果还有其他方法呢？

`virt-builder`为我们提供了一种方法。通过发出几个简单的命令，我们可以导入一个 CentOS 8 镜像，将其导入到 KVM，并启动它。让我们继续，如下所示：

1.  首先，让我们使用`virt-builder`下载一个具有指定参数的 CentOS 8 镜像，如下所示：![图 8.25 – 使用 virt-builder 获取 CentOS 8.0 镜像并检查其大小](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/ms-kvm-vrt/img/B14834_08_25.jpg)

图 8.25 – 使用 virt-builder 获取 CentOS 8.0 镜像并检查其大小

1.  一个合乎逻辑的下一步是进行`virt-install`，所以，我们开始吧：![图 8.26 – 配置、部署和添加到本地 KVM 虚拟化管理程序的新 VM](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/ms-kvm-vrt/img/B14834_08_26.jpg)

图 8.26 – 配置、部署和添加到本地 KVM 虚拟化管理程序的新 VM

1.  如果你觉得这很酷，让我们继续扩展。假设我们想要获取一个`virt-builder`镜像，向该镜像添加一个名为`Virtualization Host`的`yum`软件包组，并且在此过程中添加 root 的 SSH 密钥。我们会这样做：

![图 8.27 – 添加虚拟化主机](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/ms-kvm-vrt/img/B14834_08_27.jpg)

图 8.27 – 添加虚拟化主机

实际上，这真的非常酷，它让我们的生活变得更加轻松，为我们做了很多工作，而且以一种非常简单的方式完成了，它也适用于微软 Windows 操作系统。此外，我们可以使用自定义的`virt-builder`存储库下载特定的虚拟机，以满足我们自己的需求，接下来我们将学习如何做到这一点。

## virt-builder 存储库

显然，有一些预定义的`virt-builder`存储库（[`libguestfs.org/`](http://libguestfs.org/)是其中之一），但我们也可以创建自己的存储库。如果我们转到`/etc/virt-builder/repos.d`目录，我们会看到那里有几个文件（`libguestfs.conf`及其密钥等）。我们可以轻松地创建自己的额外配置文件，以反映我们的本地或远程`virt-builder`存储库。假设我们想创建一个本地`virt-builder`存储库。让我们在`/etc/virt-builder/repos.d`目录中创建一个名为`local.conf`的配置文件，内容如下：

```
[local]
uri=file:///root/virt-builder/index
```

然后，将镜像复制或移动到`/root/virt-builder`目录（我们将使用在上一步中创建的`centos-8.0.img`文件，通过使用`xz`命令将其转换为`xz`格式），并在该目录中创建一个名为`index`的文件，内容如下：

```
[Packt01]
name=PacktCentOS8
osinfo=centos8.0
arch=x86_64
file=centos-8.0.img.xz
checksum=ccb4d840f5eb77d7d0ffbc4241fbf4d21fcc1acdd3679 c13174194810b17dc472566f6a29dba3a8992c1958b4698b6197e6a1689882 b67c1bc4d7de6738e947f
format=raw
size=8589934592
compressed_size=1220175252
notes=CentOS8 with KVM and SSH
```

一些解释。`checksum`是使用`centos-8.0.img.xz`上的`sha512sum`命令计算的。`size`和`compressed_size`是原始和 XZd 文件的实际大小。之后，如果我们发出`virt-builder --list |more`命令，我们应该会得到如下所示的内容：

![图 8.28-我们成功将图像添加到本地 virt-builder 存储库](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/ms-kvm-vrt/img/B14834_08_28.jpg)

图 8.28-我们成功将图像添加到本地 virt-builder 存储库

您可以清楚地看到我们的`Packt01`映像位于列表的顶部，我们可以轻松使用它来部署新的 VM。通过使用额外的存储库，我们可以极大地增强我们的工作流程，并重复使用我们现有的 VM 和模板来部署任意数量的 VM。想象一下，这与`virt-builder`的自定义选项结合使用，对于 OpenStack、**Amazon Web Services**（**AWS**）等云服务有何作用。

我们列表上的下一个主题与快照有关，这是一个非常有价值但被误用的 VM 概念。有时，您在 IT 中有一些概念，既可以是好的，也可以是坏的，快照通常是其中的嫌疑犯。让我们解释一下快照的全部内容。

# 快照

VM 快照是系统在特定时间点的基于文件的表示。快照包括配置和磁盘数据。通过快照，您可以将 VM 恢复到某个时间点，这意味着通过对 VM 进行快照，您可以保留其状态，并在将来需要时轻松恢复到该状态。

快照有许多用途，例如在进行可能具有破坏性操作之前保存 VM 的状态。例如，假设您想要对现有的 Web 服务器 VM 进行一些更改，目前它正在正常运行，但您不确定您计划进行的更改是否会起作用或会破坏某些内容。在这种情况下，您可以在执行预期的配置更改之前对 VM 进行快照，如果出现问题，您可以通过恢复快照轻松恢复到 VM 的先前工作状态。

`libvirt`支持拍摄实时快照。您可以在客户机运行时对 VM 进行快照。但是，如果 VM 上有任何**输入/输出**（**I/O**）密集型应用程序正在运行，建议首先关闭或暂停客户机，以确保干净的快照。

`libvirt`客户端主要有两类快照：内部和外部；每种都有其自己的优点和局限，如下所述：

+   `qcow2`文件。快照前后的位存储在单个磁盘中，从而提供更大的灵活性。`virt-manager`提供了一个图形管理实用程序来管理内部快照。以下是内部快照的限制：

a) 仅支持`qcow2`格式

b) 在拍摄快照时 VM 被暂停

c) 无法与 LVM 存储池一起使用

+   **外部快照**：外部快照基于 COW 概念。当快照被拍摄时，原始磁盘映像变为只读，并创建一个新的覆盖磁盘映像以容纳客户写入，如下图所示：

![图 8.29-快照概念](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/ms-kvm-vrt/img/B14834_08_29.jpg)

图 8.29-快照概念

覆盖磁盘映像最初创建为`0`字节的长度，它可以增长到原始磁盘的大小。覆盖磁盘映像始终为`qcow2`。但是，外部快照可以与任何基本磁盘映像一起使用。您可以对原始磁盘映像、`qcow2`或任何其他`libvirt`支持的磁盘映像格式进行外部快照。但是，目前尚无**图形用户界面**（**GUI**）支持外部快照，因此与内部快照相比，管理起来更昂贵。

## 使用内部快照

在本节中，您将学习如何为 VM 创建、删除和恢复内部快照（离线/在线）。您还将学习如何使用`virt-manager`来管理内部快照。

内部快照仅适用于`qcow2`磁盘映像，因此首先确保要为其创建快照的虚拟机使用`qcow2`格式作为基础磁盘映像。如果不是，请使用`qemu-img`命令将其转换为`qcow2`格式。内部快照是磁盘快照和虚拟机内存状态的组合——这是一种可以在需要时轻松恢复的检查点。

我在这里使用`LAMP01`虚拟机作为示例来演示内部快照。`LAMP01`虚拟机位于本地文件系统支持的存储池上，并具有`qcow2`映像作为虚拟磁盘。以下命令列出了与虚拟机关联的快照：

```
# virsh snapshot-list LAMP01
Name Creation Time State
-------------------------------------------------
```

可以看到，目前与虚拟机关联的快照不存在；`LAMP01` `virsh snapshot-list`命令列出了给定虚拟机的所有可用快照。默认信息包括快照名称、创建时间和域状态。通过向`snapshot-list`命令传递附加选项，可以列出许多其他与快照相关的信息。

### 创建第一个内部快照

在 KVM 主机上为虚拟机创建内部快照的最简单和首选方法是通过`virsh`命令。`virsh`具有一系列选项来创建和管理快照，如下所示：

+   `snapshot-create`: 使用 XML 文件创建快照

+   `snapshot-create-as`: 使用参数列表创建快照

+   `snapshot-current`: 获取或设置当前快照

+   `snapshot-delete`: 删除虚拟机快照

+   `snapshot-dumpxml`: 以 XML 格式转储快照配置

+   `snapshot-edit`: 编辑快照的 XML

+   `snapshot-info`: 获取快照信息

+   `snapshot-list`: 列出虚拟机快照

+   `snapshot-parent`: 获取快照的父名称

+   `snapshot-revert`: 将虚拟机恢复到特定快照

以下是创建快照的简单示例。运行以下命令将为`LAMP01`虚拟机创建一个内部快照：

```
# virsh snapshot-create LAMP01
Domain snapshot 1439949985 created
```

默认情况下，新创建的快照会以唯一编号作为名称。要创建具有自定义名称和描述的快照，请使用`snapshot-create-as`命令。这两个命令之间的区别在于后者允许将配置参数作为参数传递，而前者不允许。它只接受 XML 文件作为输入。在本章中，我们使用`snapshot-create-as`，因为它更方便和易于使用。

### 使用自定义名称和描述创建内部快照

要为`LAMP01`虚拟机创建一个名称为`快照 1`且描述为`第一个快照`的内部快照，请键入以下命令：

```
# virsh snapshot-create-as LAMP01 --name "Snapshot 1" --description "First snapshot" --atomic
```

使用`--atomic`选项指定，`libvirt`将确保如果快照操作成功或失败，不会发生任何更改。建议始终使用`--atomic`选项以避免在进行快照时发生任何损坏。现在，检查这里的`snapshot-list`输出：

```
# virsh snapshot-list LAMP01
Name Creation Time State
----------------------------------------------------
Snapshot1 2020-02-05 09:00:13 +0230 running
```

我们的第一个快照已准备就绪，现在我们可以使用它来恢复虚拟机的状态，如果将来出现问题。此快照是在虚拟机处于运行状态时拍摄的。快照创建所需的时间取决于虚拟机的内存量以及客户端在那个时间修改内存的活动程度。

请注意，虚拟机在创建快照时会进入暂停模式；因此，建议在虚拟机未运行时进行快照。从已关闭的虚拟机中进行快照可以确保数据完整性。

### 创建多个快照

我们可以根据需要继续创建更多快照。例如，如果我们创建两个额外的快照，使总数达到三个，那么`snapshot-list`的输出将如下所示：

```
# virsh snapshot-list LAMP01 --parent
Name Creation Time State Parent
--------------------------------------------------------------------
Snapshot1 2020-02-05 09:00:13 +0230 running (null)
Snapshot2 2020-02-05 09:00:43 +0230 running Snapshot1
Snapshot3 2020-02-05 09:01:00 +0230 shutoff Snapshot2
```

在这里，我们使用了`--parent`开关，它打印出快照的父-子关系。第一个快照的父级是`(null)`，这意味着它直接在磁盘映像上创建，`Snapshot1`是`Snapshot2`的父级，`Snapshot2`是`Snapshot3`的父级。这有助于我们了解快照的顺序。使用`--tree`选项还可以获得类似树状的快照视图，如下所示：

```
# virsh snapshot-list LAMP01 --tree
Snapshot1
   |
  +- Snapshot2
       |
      +- Snapshot3
```

现在，检查`state`列，它告诉我们特定快照是在线还是离线。在前面的示例中，第一个和第二个快照是在 VM 运行时拍摄的，而第三个是在 VM 关闭时拍摄的。

恢复到关闭状态的快照将导致 VM 关闭。您还可以使用`qemu-img`命令实用程序获取有关内部快照的更多信息-例如，快照大小，快照标记等。在以下示例输出中，您可以看到名为`LAMP01.qcow2`的磁盘具有三个具有不同标记的快照。这还向您展示了特定快照的创建日期和时间：

```
# qemu-img info /var/lib/libvirt/qemu/LAMP01.qcow2
image: /var/lib/libvirt/qemu/LAMP01.qcow2
file format: qcow2
virtual size: 8.0G (8589934592 bytes)
disk size: 1.6G
cluster_size: 65536
Snapshot list:
ID TAG VM SIZE DATE VM CLOCK
1 1439951249 220M 2020-02-05 09:57:29 00:09:36.885
2 Snapshot1 204M 2020-02-05 09:00:13 00:01:21.284
3 Snapshot2 204M 2020-02-05 09:00:43 00:01:47.308
4 Snapshot3 0 2020-02-05 09:01:00 00:00:00.000
```

这也可以用来使用`check`开关检查`qcow2`镜像的完整性，如下所示：

```
# qemu-img check /var/lib/libvirt/qemu/LAMP01.qcow2
No errors were found on the image.
```

如果镜像中发生了任何损坏，上述命令将抛出错误。一旦在`qcow2`镜像中检测到错误，就应立即对 VM 进行备份。

### 恢复内部快照

拍摄快照的主要目的是在需要时恢复 VM 的干净/工作状态。让我们举个例子。假设在拍摄 VM 的`Snapshot3`之后，您安装了一个搞乱了整个系统配置的应用程序。在这种情况下，VM 可以轻松地恢复到创建`Snapshot3`时的状态。要恢复到快照，请使用`snapshot-revert`命令，如下所示：

```
# virsh snapshot-revert <vm-name> --snapshotname "Snapshot1"
```

如果要恢复到一个关闭的快照，那么您将不得不手动启动 VM。使用`virsh snapshot-revert`命令的`--running`开关可以使其自动启动。

### 删除内部快照

一旦确定不再需要快照，就可以删除它以节省空间。要删除 VM 的快照，请使用`snapshot-delete`命令。根据我们之前的示例，让我们删除第二个快照，如下所示：

```
# virsh snapshot-list LAMP01
Name Creation Time State
------------------------------------------------------
Snapshot1 2020-02-05 09:00:13 +0230 running
Snapshot2 2020-02-05 09:00:43 +0230 running
Snapshot3 2020-02-05 09:01:00 +0230 shutoff
Snapshot4 2020-02-18 03:28:36 +0230 shutoff
# virsh snapshot-delete LAMP01 Snapshot 2
Domain snapshot Snapshot2 deleted
# virsh snapshot-list LAMP01
Name Creation Time State
------------------------------------------------------
Snapshot1 2020-02-05 09:00:13 +0230 running
Snapshot3 2020-02-05 09:00:43 +0230 running
Snapshot4 2020-02-05 10:17:00 +0230 shutoff
```

现在让我们看看如何使用`virt-manager`执行这些程序，这是我们的 VM 管理的 GUI 实用程序。

## 使用 virt-manager 管理快照

正如您所期望的那样，`virt-manager`具有用于创建和管理 VM 快照的用户界面。目前，它仅适用于`qcow2`镜像，但很快也将支持原始镜像。使用`virt-manager`拍摄快照实际上非常简单；要开始，请打开 VM Manager 并单击要拍摄快照的 VM。

快照用户界面按钮（在下面的屏幕截图中用红色标记）出现在工具栏上；只有当 VM 使用`qcow2`磁盘时，此按钮才会被激活：

![图 8.30-使用 virt-manager 快照](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/ms-kvm-vrt/img/B14834_08_30.jpg)

图 8.30-使用 virt-manager 快照

然后，如果我们想要拍摄快照，只需使用**+**按钮，这将打开一个简单的向导，以便我们可以为快照命名和描述，如下面的屏幕截图所示：

![图 8.31-创建快照向导](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/ms-kvm-vrt/img/B14834_08_31.jpg)

图 8.31-创建快照向导

接下来，让我们看看如何使用外部磁盘快照，这是一种更快，更现代（尽管不太成熟）的 KVM/VM 快照概念。请记住，外部快照将会一直存在，因为它们具有对于现代生产环境非常重要的更多功能。

## 使用外部磁盘快照

您在上一节中了解了内部快照。内部快照非常简单，易于创建和管理。现在，让我们探索外部快照。外部快照主要涉及`overlay_image`和`backing_file`。基本上，它将`backing_file`转换为只读状态，并开始在`overlay_image`上写入。这两个图像描述如下：

+   `backing_file`：VM 的原始磁盘图像（只读）

+   `overlay_image`：快照图像（可写）

如果出现问题，您可以简单地丢弃`overlay_image`图像，然后回到原始状态。

使用外部磁盘快照，`backing_file`图像可以是任何磁盘图像（`raw`；`qcow`；甚至`vmdk`），而不像内部快照只支持`qcow2`图像格式。

### 创建外部磁盘快照

我们在这里使用`WS2019SQL-Template` VM 作为示例来演示外部快照。此 VM 位于名为`vmstore1`的文件系统存储池中，并具有充当虚拟磁盘的原始图像。以下代码片段提供了有关此 VM 的详细信息：

```
# virsh domblklist WS2019SQL-Template --details
Type Device Target Source
------------------------------------------------
file disk vda /var/lib/libvirt/images/WS2019SQL-Template.img
```

让我们看看如何创建此 VM 的外部快照，如下所示：

1.  通过执行以下代码检查要对其进行快照的 VM 是否正在运行：

```
# virsh list
Id Name State
-----------------------------------------
4 WS2019SQL-Template running
```

您可以在 VM 运行时或关闭时进行外部快照。支持在线和离线快照方法。

1.  通过`virsh`创建 VM 快照，如下所示：

```
--disk-only parameter creates a disk snapshot. This is used for integrity and to avoid any possible corruption.
```

1.  现在，检查`snapshot-list`输出，如下所示：

```
# virsh snapshot-list WS2019SQL-Template
Name Creation Time State
----------------------------------------------------------
snapshot1 2020-02-10 10:21:38 +0230 disk-snapshot
```

1.  现在，快照已经创建，但它只是磁盘状态的快照；内存内容没有被存储，如下截图所示：

```
# virsh snapshot-info WS2019SQL-Template snapshot1
Name: snapshot1
Domain: WS2019SQL-Template
Current: no
State: disk-snapshot
Location: external <<
Parent: -
Children: 1
Descendants: 1
Metadata: yes
```

1.  现在，再次列出与 VM 关联的所有块设备，如下所示：

```
image /var/lib/libvirt/images/WS2019SQL-Template.snapshot1 snapshot, as follows:

```

/var/lib/libvirt/images/WS2019SQL-Template.img。

```

```

1.  这表明新的`image /var/lib/libvirt/images/WS2019SQL-Template.snapshot1`快照现在是原始镜像`/var/lib/libvirt/images/WS2019SQL-Template.img`的读/写快照；对`WS2019SQL-Template.snapshot1`所做的任何更改都不会反映在`WS2019SQL-Template.img`中。

重要说明

`/var/lib/libvirt/images/WS2019SQL-Template.img`是支持文件（原始磁盘）。

`/var/lib/libvirt/images/WS2019SQL-Template.snapshot1`是新创建的叠加图像，现在所有写操作都在此进行。

1.  现在，让我们创建另一个快照：

```
# virsh snapshot-create-as WS2019SQL-Template snapshot2 --description "Second Snapshot" --disk-only --atomic
Domain snapshot snapshot2 created
# virsh domblklist WS2019SQL-Template --details
Type Device Target Source
------------------------------------------------
file disk vda /snapshot_store/WS2019SQL-Template.snapshot2
```

在这里，我们使用了`--diskspec`选项在所需位置创建快照。该选项需要以`disk[,snapshot=type][,driver=type][,file=name]`格式进行格式化。使用的参数表示如下：

+   `disk`：在`virsh domblklist <vm_name>`中显示的目标磁盘。

+   `snapshot`：内部或外部。

+   `driver`：`libvirt`。

+   `file`：要创建结果快照磁盘的位置路径。您可以使用任何位置；只需确保已设置适当的权限。

让我们再创建一个快照，如下所示：

```
# virsh snapshot-create-as WS2019SQL-Template snapshot3 --description "Third Snapshot" --disk-only --quiesce
Domain snapshot snapshot3 created
```

请注意，这次我添加了一个选项：`--quiesce`。我们将在下一节讨论这个。

### 什么是 quiesce？

Quiesce 是一个文件系统冻结（`fsfreeze`/`fsthaw`）机制。这将使客户文件系统处于一致状态。如果不执行此步骤，等待写入磁盘的任何内容都不会包含在快照中。此外，在快照过程中进行的任何更改可能会损坏图像。为了解决这个问题，需要在客户机上安装并运行`qemu-guest`代理。快照创建将失败并显示错误，如下所示：

```
error: Guest agent is not responding: Guest agent not available for now
```

在进行快照时，始终使用此选项以确保安全。客户工具安装在*第五章*，*Libvirt Storage*中进行了介绍；如果尚未安装，您可能需要重新查看并在 VM 中安装客户代理。

到目前为止，我们已经创建了三个快照。让我们看看它们如何连接在一起，以了解外部快照链是如何形成的，如下所示：

1.  列出与 VM 关联的所有快照，如下所示：

```
# virsh snapshot-list WS2019SQL-Template
Name Creation Time State
----------------------------------------------------------
snapshot1 2020-02-10 10:21:38 +0230 disk-snapshot
snapshot2 2020-02-10 11:51:04 +0230 disk-snapshot
snapshot3 2020-02-10 11:55:23 +0230 disk-snapshot
```

1.  通过运行以下代码检查虚拟机的当前活动（读/写）磁盘/快照：

```
# virsh domblklist WS2019SQL-Template
Target Source
------------------------------------------------
vda /snapshot_store/WS2019SQL-Template.snapshot3
```

1.  您可以使用 `qemu-img` 提供的 `--backing-chain` 选项枚举当前活动（读/写）快照的支持文件链。`--backing-chain` 将向我们显示磁盘镜像链中父子关系的整个树。有关更多描述，请参考以下代码片段：

```
# qemu-img info --backing-chain /snapshot_store/WS2019SQL-Template.snapshot3|grep backing
backing file: /snapshot_store/WS2019SQL-Template.snapshot2
backing file format: qcow2
backing file: /var/lib/libvirt/images/WS2019SQL-Template.snapshot1
backing file format: qcow2
backing file: /var/lib/libvirt/images/WS2019SQL-Template.img
backing file format: raw
```

从前面的细节中，我们可以看到链是以以下方式形成的：

![图 8.32 – 我们示例虚拟机的快照链](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/ms-kvm-vrt/img/B14834_08_32.jpg)

图 8.32 – 我们示例虚拟机的快照链

因此，它必须按照以下方式读取：`snapshot3` 有 `snapshot2` 作为其支持文件；`snapshot2` 有 `snapshot1` 作为其支持文件；`snapshot1` 有基础镜像作为其支持文件。目前，`snapshot3` 是当前活动的快照，即发生实时客户写入的地方。

### 恢复到外部快照

在一些较旧的 RHEL/CentOS 版本中，`libvirt` 对外部快照的支持是不完整的，甚至在 RHEL/CentOS 7.5 中也是如此。快照可以在线或离线创建，在 RHEL/CentOS 8.0 中，在快照处理方式方面发生了重大变化。首先，Red Hat 现在建议使用外部快照。此外，引用 Red Hat 的话：

在 RHEL 8 中不支持创建或加载运行中虚拟机的快照，也称为实时快照。此外，请注意，在 RHEL 8 中不建议使用非实时虚拟机快照。因此，支持创建或加载关闭的虚拟机快照，但 Red Hat 建议不要使用它。

需要注意的是，`virt-manager` 仍不支持外部快照，正如以下截图所示，以及我们几页前创建这些快照时，从未有选择外部快照作为快照类型的选项：

![图 8.33 – 从 virt-manager 和 libvirt 命令创建的所有快照没有额外选项的是内部快照](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/ms-kvm-vrt/img/B14834_08_33.jpg)

图 8.33 – 从 virt-manager 和 libvirt 命令创建的所有快照，没有额外选项的是内部快照

现在，我们还使用 `WS2019SQL-Template` 虚拟机并在其上创建了*外部*快照，因此情况有所不同。让我们检查一下，如下所示：

![图 8.34 – WS2019SQL-Template 有外部快照](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/ms-kvm-vrt/img/B14834_08_34.jpg)

图 8.34 – WS2019SQL-Template 有外部快照

我们可以采取的下一步是恢复到先前的状态—例如，`snapshot3`。我们可以轻松地通过使用 `virsh snapshot-revert` 命令从 shell 中执行此操作，如下所示：

```
# virsh snapshot-revert WS2019SQL-Template --snapshotname "snapshot3"
error: unsupported configuration: revert to external snapshot not supported yet
```

这是否意味着一旦为虚拟机创建了外部磁盘快照，就无法恢复到该快照？不—不是这样的；您肯定可以恢复到快照，但没有 `libvirt` 支持来完成这一点。您将不得不通过操纵域 XML 文件来手动恢复。

以 `WS2019SQL-Template` 虚拟机为例，它有三个关联的快照，如下所示：

```
virsh snapshot-list WS2019SQL-Template
Name Creation Time State
------------------------------------------------------------
snapshot1 2020-02-10 10:21:38 +0230 disk-snapshot
snapshot2 2020-02-10 11:51:04 +0230 disk-snapshot
snapshot3 2020-02-10 11:55:23 +0230 disk-snapshot
```

假设您想要恢复到 `snapshot2`。解决方案是关闭虚拟机（是的—关闭/关机是强制性的），并编辑其 XML 文件，将磁盘映像指向 `snapshot2` 作为引导映像，如下所示：

1.  找到与 `snapshot2` 关联的磁盘映像。我们需要图像的绝对路径。您可以简单地查看存储池并获取路径，但最好的选择是检查快照 XML 文件。如何？从 `virsh` 命令获取帮助，如下所示：

```
# virsh snapshot-dumpxml WS2019SQL-Template --snapshotname snapshot2 | grep
'source file' | head -1
<source file='/snapshot_store/WS2019SQL-Template.snapshot2'/>
```

1.  `/snapshot_store/WS2019SQL-Template.snapshot2` 是与 `snapshot2` 相关的文件。验证它是否完好，并且与 `backing_file` 正确连接，如下所示：

```
backing_file is correctly pointing to the snapshot1 disk. All good. If an error is detected in the qcow2 image, use the -r leaks/all parameter. It may help repair the inconsistencies, but this isn't guaranteed. Check this excerpt from the qemu-img man page:
```

1.  使用 qemu-img 的 -r 开关尝试修复发现的任何不一致性

1.  在检查期间。-r leaks 仅修复集群泄漏，而 -r all 修复所有

1.  错误的类型，选择错误修复或隐藏的风险更高

1.  已经发生的损坏。

让我们检查有关此快照的信息，如下所示：

```
# qemu-img info /snapshot_store/WS2019SQL-Template.snapshot2 | grep backing
backing file: /var/lib/libvirt/images/WS2019SQL-Template.snapshot1
backing file format: qcow2
```

1.  现在是操作 XML 文件的时候了。您可以从 VM 中删除当前附加的磁盘和`add /snapshot_store/WS2019SQL-Template.snapshot2`。或者，手动编辑 VM 的 XML 文件并修改磁盘路径。其中一个更好的选择是使用`virt-xml`命令，如下所示：

```
WS2019SQL-Template.snapshot2 as the boot disk for the VM; you can verify that by executing the following command:

```

virt-xml 命令。请参阅其手册以熟悉它。它也可以在脚本中使用。

```

```

1.  启动 VM，您将回到`snapshot2`被拍摄时的状态。类似地，您可以在需要时恢复到`snapshot1`或基本镜像。

我们列表中的下一个主题是删除外部磁盘快照，正如我们提到的那样，这有点复杂。让我们看看接下来我们如何做到这一点。

### 删除外部磁盘快照

删除外部快照有些棘手。外部快照不能像内部快照那样直接删除。它首先需要手动与基本层或向活动层合并，然后才能删除。有两种在线合并快照的实时块操作，如下所示：

+   `blockcommit`：将数据与基本层合并。使用此合并机制，您可以将叠加图像合并到后备文件中。这是最快的快照合并方法，因为叠加图像可能比后备图像小。

+   `blockpull`：向活动层合并数据。使用此合并机制，您可以将数据从`backing_file`合并到叠加图像。结果文件将始终以`qcow2`格式存在。

接下来，我们将阅读有关使用`blockcommit`合并外部快照的信息。

#### 使用`blockcommit`合并外部快照

我们创建了一个名为`VM1`的新 VM，它有一个名为`vm1.img`的基本镜像（原始），有四个外部快照。`/var/lib/libvirt/images/vm1.snap4`是活动快照图像，实时写入发生在这里；其余的处于只读模式。我们的目标是删除与此 VM 相关的所有快照，操作如下：

1.  列出当前正在使用的活动磁盘镜像，如下所示：

```
the /var/lib/libvirt/images/vm1.snap4 image is the currently active image on which all writes are occurring.
```

1.  现在，枚举`/var/lib/libvirt/images/vm1.snap4`的后备文件链，如下所示：

```
# qemu-img info --backing-chain /var/lib/libvirt/images/vm1.snap4 | grep backing
backing file: /var/lib/libvirt/images/vm1.snap3
backing file format: qcow2
backing file: /var/lib/libvirt/images/vm1.snap2
backing file format: qcow2
backing file: /var/lib/libvirt/images/vm1.snap1
backing file format: qcow2
backing file: /var/lib/libvirt/images/vm1.img
backing file format: raw
```

1.  是时候将所有快照图像合并到基本图像中了，如下所示：

```
# virsh blockcommit VM1 hda --verbose --pivot --active
Block Commit: [100 %]
Successfully pivoted
4\. Now, check the current active block device in use:
# virsh domblklist VM1
Target Source
--------------------------
hda /var/lib/libvirt/images/vm1.img
```

请注意，当前活动的块设备现在是基本镜像，所有写入都切换到它，这意味着我们成功地将快照图像合并到基本镜像中。但是以下代码片段中的`snapshot-list`输出显示仍然有与 VM 相关的快照：

```
# virsh snapshot-list VM1
Name Creation Time State
-----------------------------------------------------
snap1 2020-02-12 09:10:56 +0230 shutoff
snap2 2020-02-12 09:11:03 +0230 shutoff
snap3 2020-02-12 09:11:09 +0230 shutoff
snap4 2020-02-12 09:11:17 +0230 shutoff
```

如果您想摆脱这个问题，您需要删除适当的元数据并删除快照图像。正如前面提到的，`libvirt`不完全支持外部快照。目前，它只能合并图像，但没有自动删除快照元数据和叠加图像文件的支持。这必须手动完成。要删除快照元数据，请运行以下代码：

```
# virsh snapshot-delete VM1 snap1 --children --metadata
# virsh snapshot-list VM1
Name Creation Time State
```

在这个例子中，我们学习了如何使用`blockcommit`方法合并外部快照。接下来让我们学习如何使用`blockpull`方法合并外部快照。

#### 使用`blockpull`合并外部快照

我们创建了一个名为`VM2`的新 VM，它有一个名为`vm2.img`的基本镜像（原始），只有一个外部快照。快照磁盘是活动镜像，可以进行实时写入，而基本镜像处于只读模式。我们的目标是删除与此 VM 相关的快照。操作如下：

1.  列出当前正在使用的活动磁盘镜像，如下所示：

```
/var/lib/libvirt/images/vm2.snap1 image is the currently active image on which all writes are occurring.
```

1.  现在，枚举`/var/lib/libvirt/imagesvar/lib/libvirt/images/vm2.snap1`的后备文件链，如下所示：

```
# qemu-img info --backing-chain /var/lib/libvirt/images/vm2.snap1 | grep backing
backing file: /var/lib/libvirt/images/vm1.img
backing file format: raw
```

1.  将基本镜像合并到快照镜像（从基本镜像到叠加图像合并），如下所示：

```
/var/lib/libvirt/images/vm2.snap1. It got considerably larger because we pulled the base_image and merged it into the snapshot image to get a single file.
```

1.  现在，您可以按以下方式删除`base_image`和快照元数据：

```
# virsh snapshot-delete VM2 snap1 --metadata
```

我们在 VM 运行状态下运行了合并和快照删除任务，没有任何停机时间。`blockcommit`和`blockpull`也可以用于从快照链中删除特定的快照。查看`virsh`的 man 页面以获取更多信息并尝试自己操作。在本章的*进一步阅读*部分中，你还会找到一些额外的链接，所以确保你仔细阅读它们。

# 在使用快照时的用例和最佳实践

我们提到在 IT 世界中关于快照存在着一种爱恨交织的关系。让我们讨论一下在使用快照时的原因和一些常识的最佳实践，如下所示：

+   当你拍摄 VM 快照时，你正在创建 VM 磁盘的新增量副本，`qemu2`，或者一个原始文件，然后你正在写入该增量。因此，你写入的数据越多，提交和合并回父级的时间就越长。是的——你最终需要提交快照，但不建议你在 VM 上附加快照进入生产环境。

+   快照不是备份；它们只是在特定时间点拍摄的状态图片，你可以在需要时恢复到该状态。因此，不要将其作为直接备份过程的依赖。为此，你应该实施备份基础设施和策略。

+   不要将带有快照的 VM 保留很长时间。一旦你验证了不再需要恢复到快照拍摄时的状态，立即合并并删除快照。

+   尽可能使用外部快照。与内部快照相比，外部快照的损坏几率要低得多。

+   限制快照数量。连续拍摄多个快照而没有任何清理可能会影响 VM 和主机的性能，因为`qemu`将不得不遍历快照链中的每个图像来从`base_image`读取新文件。

+   在拍摄快照之前在 VM 中安装 Guest Agent。通过来宾内的支持，快照过程中的某些操作可以得到改进。

+   在拍摄快照时始终使用`--quiesce`和`--atomic`选项。

如果你使用这些最佳实践，我们建议你使用快照来获益。它们会让你的生活变得更轻松，并为你提供一个可以回到的点，而不会带来所有的问题和麻烦。

# 总结

在本章中，你学会了如何使用`libguestfs`实用程序来修改 VM 磁盘，创建模板和管理快照。我们还研究了`virt-builder`和各种为我们的 VM 提供方法，因为这些是现实世界中最常见的场景之一。在下一章中，我们将更多地了解在大量部署 VM 时的概念（提示：云服务），这就是关于`cloud-init`的一切。

# 问题

1.  我们为什么需要修改 VM 磁盘？

1.  我们如何将 VM 转换为 KVM？

1.  我们为什么使用 VM 模板？

1.  我们如何创建基于 Linux 的模板？

1.  我们如何创建基于 Microsoft Windows 的模板？

1.  你知道哪些从模板部署的克隆机制？它们之间有什么区别？

1.  我们为什么使用`virt-builder`？

1.  我们为什么使用快照？

1.  使用快照的最佳实践是什么？

# 进一步阅读

有关本章内容的更多信息，请参考以下链接：

+   `libguesfs`文档：[`libguestfs.org/`](http://libguestfs.org/)

+   `virt-builder`：[`libguestfs.org/virt-builder.1.html`](http://libguestfs.org/virt-builder.1.html)

+   管理快照：[`access.redhat.com/documentation/en-us/red_hat_enterprise_linux/7/html/virtualization_deployment_and_administration_guide/sect-managing_guests_with_the_virtual_machine_manager_virt_manager-managing_snapshots`](https://access.redhat.com/documentation/en-us/red_hat_enterprise_linux/7/html/virtualization_deployment_and_administration_guide/sect-managing_guests_with_the_virtual_machine_manager_virt_manager-managing_snapshots)

+   使用`virt-builder`生成 VM 镜像：[`www.admin-magazine.com/Articles/Generate-VM-Images-with-virt-builder`](http://www.admin-magazine.com/Articles/Generate-VM-Images-with-virt-builder)

+   QEMU 快照文档：[`wiki.qemu.org/Features/Snapshots`](http://wiki.qemu.org/Features/Snapshots)

+   `libvirt`—快照 XML 格式：[`libvirt.org/formatsnapshot.html`](https://libvirt.org/formatsnapshot.html)


# 第三部分：KVM 虚拟机的自动化、定制和编排

在本书的这一部分，您将完全了解如何使用`cloud-init`和`cloudbase-init`来定制 KVM 虚拟机。本部分还涵盖了如何利用 Ansible 的自动化能力来管理和编排 KVM 基础架构。

本书的这一部分包括以下章节：

+   *第九章*, *使用 cloud-init 自定义虚拟机*

+   *第十章*, *自动化的 Windows 客户端部署和定制*

+   *第十一章*, *Ansible 和编排自动化脚本*


# 第九章：使用云初始化自定义虚拟机

定制虚拟机通常看起来很简单 - 从模板克隆它；启动；点击几个**下一步**按钮（或文本标签）；创建一些用户、密码和组；配置网络设置... 这对于一两台虚拟机可能有效。但如果我们需要部署两三百台虚拟机并对它们进行配置呢？突然间，我们面临着一项庞大的任务 - 如果我们手动完成所有工作，这项任务将容易出现错误。我们在做这些事情的时候浪费了宝贵的时间，而不是以更简化、自动化的方式进行配置。这就是云初始化派上用场的地方，因为它可以定制我们的虚拟机，在它们上安装软件，并且可以在首次和后续虚拟机启动时进行。因此，让我们讨论一下云初始化以及它如何为你的大规模配置噩梦带来价值。

在本章中，我们将涵盖以下主题：

+   虚拟机定制的需求是什么？

+   理解云初始化

+   云初始化架构

+   如何在启动时安装和配置云初始化

+   云初始化镜像

+   云初始化数据源

+   向云初始化传递元数据和用户数据

+   如何使用云配置脚本与云初始化

# 虚拟机定制的需求是什么？

一旦你真正开始使用虚拟机并学会如何掌握它们，你会注意到一件事似乎经常发生：虚拟机部署。由于一切都很容易配置和部署，你会开始为几乎任何事情创建新的虚拟机实例，有时甚至只是为了检查特定应用程序是否在特定操作系统版本上运行。这让作为开发人员和系统管理员的生活变得更加轻松，但也带来了一系列问题。其中最困难的之一是模板管理。即使你有一小组不同的服务器和相对较少的不同配置，事情也会开始累积起来，如果你决定通过 KVM 以正常方式管理模板，组合的数量将很快变得太大。

你很快会面临的另一个问题是兼容性。当你离开你选择的 Linux 发行版，需要部署另一个具有自己规则和部署策略的 Linux 发行版时，事情就会变得复杂起来。通常，最大的问题是系统定制。在网络设置和主机名方面，网络上的每台计算机都应该有自己独特的身份。使用 DHCP 网络配置的模板可以解决其中一个问题，但这远远不足以简化事情。例如，我们可以在 CentOS / RHEL 和兼容的 Linux 发行版上使用 Kickstart。Kickstart 是一种在部署时配置系统的方法，如果你使用这些特定的发行版，这可能是快速部署物理或虚拟机的最佳方式。另一方面，Kickstart 会使你的部署比应该更慢，因为它使用一个配置文件，使我们能够向干净的安装添加软件和配置。

基本上，它用我们之前定义的设置填充了额外的配置提示。这意味着我们基本上每次需要部署新的虚拟机时都在进行完整的安装，并创建一个完整的系统。

主要问题是*其他发行版不使用 Kickstart*。有类似的系统可以实现无人值守安装。Debian 和 Ubuntu 使用一个叫做*preseed*的工具/系统，并且能够在某些部分支持 Kickstart，SuSe 使用 AutoYaST，甚至有一些工具提供某种跨平台功能。其中一个叫做**Fully Automated Install**（**FAI**）的工具能够自动安装甚至在线重新配置不同的 Linux 发行版。但这仍然不能解决我们所有的问题。在虚拟化的动态世界中，主要目标是尽快部署并尽可能自动化，因为我们在从生产环境中移除虚拟机时也倾向于使用相同的灵活性。

想象一下：你需要创建一个单一的应用部署，以测试你的新应用在不同的 Linux 发行版上的情况。你所有未来的虚拟机都需要有一个主机名的唯一标识符，一个部署的 SSH 身份，可以通过 Ansible 进行远程管理，当然还有你的应用。你的应用有三个依赖项——两个以可以通过 Ansible 部署的软件包形式存在，但其中一个依赖于正在使用的 Linux 发行版，并且必须为该特定的 Linux 发行版进行定制。为了使事情更加真实，你预计你将不时地重复这个测试，并且每次你都需要重建你的依赖项。

你可以创建这种环境的几种方式。一种方法是简单地手动安装所有服务器并创建模板。这意味着手动配置一切，然后创建将要部署的虚拟机模板。如果我们打算部署到超过几个 Linux 发行版，这是很多工作。一旦发行版升级，这将变得更加繁重，因为我们从中部署的所有模板必须经常升级，通常在不同的时间点。这意味着我们可以手动更新所有虚拟机模板，或者在每个模板上执行安装后升级。这是很多工作，而且非常慢。再加上这样一个事实，即这样的测试可能涉及在新旧版本的虚拟机模板上运行你的测试应用。除此之外，我们还需要解决为每个部署的 Linux 发行版定制我们的网络设置的问题。当然，这也意味着我们的虚拟机模板远非通用。过一段时间，我们将会为每个测试周期拥有数十个虚拟机模板。

解决这个问题的另一种方法可以是使用像 Ansible 这样的系统——我们从虚拟机模板部署所有系统，然后通过 Ansible 进行定制。这更好——Ansible 就是为这样的场景设计的，但这意味着我们必须首先创建能够支持 Ansible 部署的虚拟机模板，带有实现的 SSH 密钥和 Ansible 运行所需的其他一切。

这两种方法都无法解决的一个问题是大规模部署机器。这就是为什么设计了一个叫做 cloud-init 的框架。

# 理解 cloud-init

我们需要在技术上更深入一些，以了解 cloud-init 是什么，以及了解它的局限性是什么。因为我们正在谈论一种使用简单配置文件完全自动重新配置系统的方式，这意味着有些事情需要事先准备好，以使这个复杂的过程更加用户友好。

我们已经在*第八章*中提到了虚拟机模板，*创建和修改 VM 磁盘、模板和快照*。在这里，我们谈论的是一个特别配置的模板，它具有阅读、理解和部署我们将在文件中提供的配置所需的所有元素。这意味着这个特定的镜像必须提前准备好，是整个系统中最复杂的部分。

幸运的是，cloud-init 镜像可以预先下载并进行配置，我们唯一需要知道的是我们想要使用哪个发行版。我们在本书中提到的所有发行版（CentOS 7 或 8、Debian、Ubuntu 和 Red Hat Enterprise Linux 7 和 8）都有我们可以使用的镜像。其中一些甚至有基本操作系统的不同版本可用，因此如果需要，我们可以使用它们。请注意，安装的 cloud-init 版本可能会有所不同，特别是在旧版本的镜像上。

为什么这个镜像很重要？因为它被准备好可以检测其运行的云系统，确定是否应该使用 cloud-init 或者禁用它，然后读取并执行系统本身的配置。

# 理解 cloud-init 架构

Cloud-init 使用引导阶段的概念，因为它需要对系统在引导期间发生的事情进行精细和细粒度的控制。当然，使用 cloud-init 的前提是有一个 cloud-init 镜像。从[`cloudinit.readthedocs.io`](https://cloudinit.readthedocs.io)提供的文档中，我们可以了解到 cloud-init 引导有五个阶段：

+   存在`/etc/cloud/cloud-init.diabled`。有关本章中的所有内容和其他内容的更多信息，请阅读文档（从[`cloudinit.readthedocs.io/en/latest/topics/boot.html`](https://cloudinit.readthedocs.io/en/latest/topics/boot.html)开始），因为它包含了关于 cloud-init 支持的开关和不同选项的更多详细信息。

+   名为`cloud-init-local.service`的`systemd`服务，它将尽快运行并阻塞网络直到完成。在 cloud-init 初始化中经常使用阻塞服务和目标的概念，原因很简单 - 以确保系统稳定性。由于 cloud-init 过程修改了系统的许多核心设置，我们不能让通常的启动脚本运行并创建可能覆盖 cloud-init 创建的配置的并行配置。

+   `cloud-init.service`。这是主要服务，将启动之前配置好的网络，并尝试配置我们在数据文件中安排的一切。这通常包括获取我们配置中指定的所有文件，提取它们，并执行其他准备任务。如果指定了这样的配置更改，磁盘也将在此阶段进行格式化和分区。还将创建挂载点，包括那些动态的和特定于特定云平台的挂载点。

+   `yum_repos`或`apt`模块），添加 SSH 密钥（`ssh-import-id`模块），并执行类似的任务，为下一阶段做准备，我们实际上可以在这个阶段使用在此阶段完成的配置。

+   **最终**阶段是系统引导的一部分，运行可能属于用户空间的东西 - 安装软件包、配置管理插件部署和执行可能的用户脚本。

所有这些都完成后，系统将完全配置好并运行。

这种方法的主要优势，尽管看起来复杂，是在云中只存储一个镜像，然后创建简单的配置文件，只覆盖*vanilla*默认配置和我们需要的配置之间的差异。镜像也可以相对较小，因为它们不包含太多面向最终用户的软件包。

Cloud-init 经常被用作部署许多将由编排系统（如 Puppet 或 Ansible）管理的机器的第一阶段，因为它提供了一种创建包括连接到每个实例的方式的工作配置的方法。每个阶段都使用 YAML 作为其主要数据语法，几乎所有内容都只是不同选项和变量的列表，这些选项和变量会被转换为配置信息。由于我们正在配置一个系统，我们还可以在配置中包含几乎任何其他类型的文件——一旦我们可以在配置系统时运行 shell 脚本，一切皆有可能。

*为什么所有这些如此重要？*

cloud-init 源自一个简单的想法：创建一个单一模板，定义您计划使用的操作系统的基本内容。然后，我们创建一个单独的、特殊格式的数据文件，其中包含定制数据，然后在运行时将这两者组合起来，以创建在需要时的新实例。您甚至可以通过使用模板作为基础镜像，然后创建不同的系统作为差异镜像，稍微改善一下，以便在几分钟而不是几小时内部署。

cloud-init 的构想是尽可能多地支持多平台，并包括尽可能多的操作系统。目前，它支持以下操作系统：

+   Ubuntu

+   SLES/openSUSE

+   RHEL/CentOS

+   Fedora

+   Gentoo Linux

+   Debian

+   Arch Linux

+   FreeBSD

我们列举了所有的发行版，但正如其名称所示，cloud-init 也是“云感知”的，这意味着 cloud-init 能够自动检测并使用几乎任何云环境。在任何硬件或云上运行任何发行版总是可能的，即使没有类似 cloud-init 这样的东西，但由于想要创建一个平台无关的配置，可以在任何云上部署而无需重新配置，我们的系统需要自动考虑不同云基础设施之间的任何差异。此外，即使 cloud-init 并非专门为裸金属部署而设计，或者更准确地说，即使它的设计远不止于此，它也可以用于裸金属部署。

重要提示

云感知意味着 cloud-init 为我们提供了进行部署后检查和配置更改的工具，这是另一个极其有用的选项。

这一切听起来比应该更加理论化。实际上，一旦开始使用 cloud-init 并学会如何配置它，您将开始创建一个几乎完全独立于您所使用的云基础设施的虚拟机基础架构。在本书中，我们使用 KVM 作为主要的虚拟化基础设施，但 cloud-init 可以与任何其他云环境一起使用，通常无需任何修改。cloud-init 最初是为了在 Amazon AWS 上实现简单部署而设计的，但它早已超越了这种限制。

此外，cloud-init 知晓不同发行版之间的所有细微差别，因此您在配置文件中设置的所有内容都将被转换为特定发行版用于完成特定任务的内容。在这方面，cloud-init 的行为很像 Ansible——实质上，您定义需要做什么，而不是如何做，cloud-init 会接管并实现它。

# 在启动时安装和配置 cloud-init。

我们在本章中要讨论的主要内容是如何使 cloud-init 运行，并在部署机器时将其所有部分放在正确的位置，但这只是揭示了 cloud-init 实际工作原理的一部分。您需要理解的是，cloud-init 作为一个服务运行，配置系统，并按照我们告诉它的方式进行操作。系统启动后，我们可以连接到它并查看已完成的工作，以及如何完成的，并分析日志。这可能与完全自动化部署的想法相悖，但这是有原因的-无论我们做什么，总会有可能需要调试系统或执行一些后安装任务，这些任务也可以自动化。

使用 cloud-init 并不仅仅局限于调试。系统启动后，系统会生成大量关于启动方式、系统实际的云配置以及定制方面的数据。然后您的应用程序和脚本可以依赖这些数据，并用它来运行和检测某些配置和部署参数。请看这个例子，取自在 Microsoft Azure 上运行 Ubuntu 的虚拟机：

![图 9.1-启动时 cloud-init 输出的一部分](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/ms-kvm-vrt/img/B14834_09_01.jpg)

图 9.1-启动时 cloud-init 输出的一部分

cloud-init 实际上在启动时显示这个（根据 cloud-init 配置文件的不同，可能还有更多内容），然后将所有这些输出放入其日志文件中。因此，我们在额外信息方面得到了很好的覆盖。

我们 cloud-init 之旅的下一步是讨论 cloud-init 图片，因为这些是我们需要使 cloud-init 工作的东西。让我们现在来做这件事。

## Cloud-init 图片

为了在启动时使用 cloud-init，我们首先需要一个云镜像。在其核心，它基本上是一个半安装的系统，其中包含专门设计的脚本，支持 cloud-init 安装。在所有发行版上，这些脚本都是 cloud-init 包的一部分，但是镜像通常比这更加准备就绪，因为它们试图在大小和安装便利性之间找到一个平衡点。

在我们的示例中，我们将使用以下网址提供的图片：

+   [`cloud.centos.org/`](https://cloud.centos.org/)

+   [`cloud-images.ubuntu.com/`](https://cloud-images.ubuntu.com/)

在我们将要处理的所有示例中，主要意图是展示系统如何在两种完全不同的架构上运行，几乎没有或没有最小的修改。

在正常情况下，获取镜像就是您需要能够运行 cloud-init 的一切。其他一切都由数据文件处理。

例如，这些是 CentOS 发行版的一些可用图片：

![图 9.2-为 CentOS 提供的丰富的 cloud-init 图片](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/ms-kvm-vrt/img/B14834_09_02.jpg)

图 9.2-为 CentOS 提供的丰富的 cloud-init 图片

注意，几乎所有发行版的发布都包含了图片，因此我们不仅可以在最新版本上测试我们的系统，还可以在所有其他可用版本上进行测试。我们可以自由使用所有这些图片，这正是我们稍后将要做的事情，当我们开始使用我们的示例时。

## Cloud-init 数据源

让我们稍微谈谈数据文件。到目前为止，我们已经泛泛地提到它们，并且我们有充分的理由这样做。使 cloud-init 脱颖而出的一件事是它支持不同的获取安装信息和如何安装的方式。我们称这些配置文件为数据源，它们可以分为两大类 - **用户数据**和**元数据**。我们将在本章中更详细地讨论每一个，但作为早期介绍，让我们说一下，用户作为配置的一部分创建的所有东西，包括 YAML 文件、脚本、配置文件，可能还有其他要放在系统上的文件，比如用户数据的应用程序和依赖项。元数据通常直接来自云提供商或用于标识机器。

它包含实例数据、主机名、网络名称和其他在部署时可能有用的云特定细节。我们可以在引导过程中使用这两种类型的数据，并且将这样做。我们放入的所有内容都将在运行时存储在`/run/cloud-init/instance-data.json`中的大型 JSON 存储中，或作为实际机器配置的一部分。这个文件的一个很好的例子是主机名，作为最终将成为个别机器上实际主机名的元数据的一部分。这个文件由 cloud-init 填充，并且可以通过命令行或直接访问。

在创建任何配置文件时，我们可以使用任何可用的文件格式，并且如果需要，我们可以压缩文件 - cloud-init 将在运行之前对其进行解压缩。如果我们需要将实际文件传递到配置中，尽管有一个限制 - 文件需要编码为文本并放入 YAML 文件中的变量中，以便在我们正在配置的系统上稍后使用和写入。就像 cloud-init 一样，YAML 语法是声明性的 - 这是一个重要的事情要记住。

现在，让我们学习如何将元数据和用户数据传递给 cloud-init。

# 将元数据和用户数据传递给 cloud-init

在我们的示例中，我们将创建一个文件，它实质上是一个`.iso`镜像，并且会像连接到引导机器的 CD-ROM 一样行为。Cloud-init 知道如何处理这种情况，并且会挂载文件，提取所有脚本，并按照预定顺序运行它们，就像我们在解释引导顺序是已经提到的那样（在本章前面的*理解 cloud-init 架构*部分中检查）。

基本上，我们需要做的是创建一个镜像，将其连接到云模板，并在模板内部提供所有数据文件给 cloud-init 脚本。这是一个三步过程：

1.  我们必须创建保存配置信息的文件。

1.  我们必须创建一个包含文件数据的镜像，并将其放在正确的位置。

1.  我们需要在引导时将镜像与模板关联起来。

最复杂的部分是定义在引导时如何配置以及需要配置什么。所有这些都是在运行给定发行版的云工具软件包的机器上完成的。

在这一点上，我们需要指出在所有发行版中用于启用 cloud-init 支持的两种不同软件包：

+   `cloud-init` - 包含使计算机能够在引导过程中重新配置自身的一切必要内容，如果遇到云初始化配置

+   `cloud-utils` - 用于创建要应用于云镜像的配置

这些软件包之间的主要区别是我们安装它们的计算机。`cloud-init`是要安装在我们正在配置的计算机上的，并且是部署镜像的一部分。`cloud-utils`是用于在将创建配置的计算机上使用的软件包。

在本章的所有示例和所有配置步骤中，实际上我们在引用两台不同的计算机/服务器：一台可以被视为主要计算机，而我们在本章中使用的计算机-除非另有说明-是我们用来创建 cloud-init 部署配置的计算机。这不是将使用此配置进行配置的计算机，而只是我们用作工作站准备文件的计算机。

在这种简化的环境中，这是运行整个 KVM 虚拟化并用于创建和部署虚拟机的同一台计算机。在正常设置中，我们可能会在工作站上创建我们的配置，并部署到某种基于 KVM 的主机或集群。在这种情况下，我们在本章中呈现的每个步骤基本上保持不变；唯一的区别是我们部署的位置，以及第一次启动时调用虚拟机的方式。

我们还将注意到，一些虚拟化环境，如 OpenStack、oVirt 或 RHEV-M，有直接的方式与启用了 cloud-init 的模板进行通信。其中一些甚至允许您在首次启动时直接从 GUI 重新配置机器，但这超出了本书的范围。

我们列表中的下一个主题是 cloud-init 模块。Cloud-init 使用模块的原因是为了扩展其在虚拟机引导阶段可以采取的可用操作范围。有数十个可用的 cloud-init 模块-`SSH`、`yum`、`apt`、设置`hostname`、`password`、`locale`和创建用户和组等。让我们看看如何使用它们。

## 使用 cloud-init 模块

在创建配置文件时，在 cloud-init 中，几乎与任何其他软件抽象层一样，我们正在处理将我们更多或少通用的配置需求（例如*需要安装此软件包*）转换为特定系统上的实际 shell 命令的模块。这是通过**模块**完成的。模块是将不同功能分解为较小组的逻辑单元，并使我们能够使用不同的命令。您可以在以下链接中查看所有可用模块的列表：[`cloudinit.readthedocs.io/en/latest/topics/modules.html`](https://cloudinit.readthedocs.io/en/latest/topics/modules.html)。这是一个相当长的列表，这将进一步显示出 cloud-init 的开发程度。

从列表中我们可以看到，例如`Disk setup`或`Locale`等一些模块是完全独立于平台的，而例如`Puppet`等一些模块则设计用于与特定软件解决方案及其配置一起使用，而一些则特定于特定发行版或一组发行版，如`Yum Add Repo`或`Apt Configure`。

这似乎破坏了完全与发行版无关的部署一切的想法，但您必须记住两件事-cloud-init 首先是与云无关的，而不是与发行版无关的，并且发行版有时具有太不同的东西，无法用任何简单的解决方案解决。因此，云-init 解决了足够多的问题以便有用，并且同时尽量不制造新问题。

重要提示

我们不会逐个处理特定模块，因为这将使本章变得太长，并可能使其成为一本独立的书。如果您打算使用 cloud-init，请参阅模块文档，因为它将提供您所需的所有最新信息。

# 如何使用 cloud-init 的 cloud-config 脚本的示例

首先，您需要下载云镜像并调整大小，以确保在安装所有文件后磁盘大小足够大，可以容纳您计划放入所创建的机器中的所有文件。在这些示例中，我们将使用两个镜像，一个用于 CentOS，另一个用于 Ubuntu 服务器。我们可以看到我们使用的 CentOS 镜像大小为 8 GB，我们将其扩大到 10 GB。请注意，磁盘上的实际大小不会达到 10 GB；我们只是允许镜像增长到这个大小。

我们将从互联网上获取 Ubuntu 镜像后，对其进行相同操作。Ubuntu 还会每天发布其分布的云版本，适用于所有支持的版本。主要区别在于 Ubuntu 创建的镜像在满时设计为 2.2 GB。我们从[`cloud.centos.org`](https://cloud.centos.org)下载了一个镜像；现在让我们获取一些关于它的信息：

![图 9.3 - Cloud-init 镜像大小](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/ms-kvm-vrt/img/B14834_09_03.jpg)

图 9.3 - Cloud-init 镜像大小

请注意磁盘上的实际大小不同- `qemu-img`给出的是 679 MB 和 2.2 GB，而实际磁盘使用量大约为 330 MB 和 680 MB：

![图 9.4 - 通过 qemu-img 测得的镜像大小与实际虚拟镜像大小不同](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/ms-kvm-vrt/img/B14834_09_04.jpg)

图 9.4 - 通过 qemu-img 测得的镜像大小与实际虚拟镜像大小不同

现在我们可以对这些镜像进行一些日常管理任务-扩大它们，将它们移动到 KVM 的正确目录，将它们用作基础镜像，然后通过 cloud-init 进行自定义：

1.  让我们把这些镜像变大，这样我们就可以为未来的容量需求（和实践）做好准备：![图 9.5 - 通过 qemu-img 将 Ubuntu 和 CentOS 的最大镜像大小增加到 10 GB](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/ms-kvm-vrt/img/B14834_09_05.jpg)

图 9.5 - 通过 qemu-img 将 Ubuntu 和 CentOS 的最大镜像大小增加到 10 GB

扩大我们的镜像后，请注意磁盘上的大小几乎没有变化：

![图 9.6 - 实际磁盘使用量只有轻微变化](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/ms-kvm-vrt/img/B14834_09_06.jpg)

图 9.6 - 实际磁盘使用量只有轻微变化

下一步是准备我们的环境以进行云镜像过程，以便我们可以启用 cloud-init 发挥其作用。

1.  我们将使用的镜像将存储在`/var/lib/libvirt/images`中：![图 9.7 - 将镜像移动到 KVM 默认系统目录](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/ms-kvm-vrt/img/B14834_09_07.jpg)

图 9.7 - 将镜像移动到 KVM 默认系统目录

我们将以最简单的方式创建我们的第一个云启用部署，只需重新分区磁盘并创建一个带有单个 SSH 密钥的用户。密钥属于主机的根目录，因此在 cloud-init 完成后我们可以直接登录到部署的机器上。

此外，我们将通过运行以下命令将我们的镜像用作基础镜像：

![图 9.8 - 创建用于部署的镜像磁盘](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/ms-kvm-vrt/img/B14834_09_08.jpg)

图 9.8 - 创建用于部署的镜像磁盘

现在镜像已经准备好了。下一步是开始 cloud-init 配置。

1.  首先，创建一个本地元数据文件，并在其中放入新的虚拟机名称。

1.  文件将被命名为`meta-data`，我们将使用`local-hostname`来设置名称：

```
cloud. This user will not be able to log in using a password since we are not creating one, but we will enable login using SSH keys associated with the local root account, which we will create by using the ssh-keygen command. This is just an example SSH key, and SSH key that you're going to use might be different. So, as root, go through the following procedure:![Figure 9.10 – SSH keygen procedure done, SSH keys are present and accounted for    ](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/ms-kvm-vrt/img/B14834_09_10.jpg)Figure 9.10 – SSH keygen procedure done, SSH keys are present and accounted forKeys are stored in the local `.ssh` directory, so we just need to copy them. When we are doing cloud deployments, we usually use this method of authentication, but cloud-init enables us to define any method of user authentication. It all depends on what we are trying to do and whether there are security policies in place that enforce one authentication method over another.In the cloud environments, we will rarely define users that are able to log in with a password, but for example, if we are deploying bare-metal machines for workstations, we will probably create users that use normal passwords. When we create a configuration file like this, it is standard practice to use hashes of passwords instead of literal cleartext passwords. The directive you are looking for is probably `passwd:` followed by a string containing the hash of a password. Next, we configured `sudo`. Our user needs to have root permissions since there are no other users defined for this machine. This means they need to be a member of the `sudo` group and have to have the right permissions defined in the `sudoers` file. Since this is a common setting, we only need to declare the variables, and cloud-init is going to put the settings in the right files. We will also define a user shell. In this file, we can also define all the other users' settings available on Linux, a feature that is intended to help deploy user computers. If you need any of those features, check the documentation available here: [`cloudinit.readthedocs.io/en/latest/topics/modules.html#users-and-groups`](https://cloudinit.readthedocs.io/en/latest/topics/modules.html#users-and-groups). All the extended user information fields are supported. The last thing we are doing is using the `runcmd` directive to define what will happen after the installation finishes, in the last stage. In order to permit the user to log in, we need to put them on the list of allowed users in the `sshd` and we need to restart the service. Now we are ready for our first deployment. 
```

1.  我们的目录中有三个文件：一个使用云模板的基本文件的硬盘，一个包含仅对我们的部署至关重要的最小信息的`meta-data`文件，以及`user-data`，其中包含我们用户的定义。我们甚至没有尝试安装或复制任何东西；这个安装尽可能地简化，但在正常环境中，这是一个常规的起点，因为很多部署只是为了让我们的机器上线，然后通过其他工具完成其余的安装。让我们进入下一步。

我们需要一种方法来连接我们刚刚创建的文件和配置与虚拟机。通常有几种方法可以做到这一点。最简单的方法通常是生成一个包含文件的`.iso`文件。然后在创建机器时，我们只需将文件挂载为虚拟 CD-ROM。在启动时，cloud-init 将自动查找文件。

另一种方法是将文件托管在网络上的某个地方，并在需要时获取它们。也可以结合这两种策略。我们稍后会讨论这一点，但让我们先完成我们的部署。本地的`.iso`映像是我们将在这次部署中采用的方式。有一个名为`genisoimage`的工具（由同名的软件包提供），对此非常有用（以下命令是一行命令）：

```
genisoimage -output deploy-1-cidata.iso -volid cidata -joliet -rock user-data meta-data
```

我们在这里做的是创建一个仿真的 CD-ROM 映像，它将遵循 ISO9660/Joliet 标准和 Rock Ridge 扩展。如果你不知道我们刚才说了什么，就忽略这一切，这样想一想 - 我们正在创建一个将保存我们的元数据和用户数据并呈现为 CD-ROM 的文件：

![ 图 9.11 - 创建 ISO 映像](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/ms-kvm-vrt/img/B14834_09_11.jpg)

图 9.11 - 创建 ISO 映像

最后，我们将得到类似于这样的东西：

![图 9.12 - ISO 已创建，我们准备开始云初始化部署](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/ms-kvm-vrt/img/B14834_09_12.jpg)

图 9.12 - ISO 已创建，我们准备开始云初始化部署

请注意，图像是在部署后拍摄的，因此磁盘的大小可能会根据您的配置而大不相同。这就是所有需要的准备工作。剩下的就是启动我们的虚拟机。

现在，让我们开始我们的部署。

## 第一次部署

我们将使用命令行部署我们的虚拟机：

```
virt-install --connect qemu:///system --virt-type kvm --name deploy-1 --ram 2048 --vcpus=1 --os-type linux --os-variant generic --disk path=/var/lib/libvirt/images/deploy-1/centos1.qcow2,format=qcow2 --disk /var/lib/libvirt/images/deploy-1/deploy-1-cidata.iso,device=cdrom --import --network network=default --noautoconsole
```

尽管看起来可能很复杂，但如果你在阅读了本书之前的章节后来到这一部分，那么你应该已经见过了。我们正在使用 KVM，为我们的域（虚拟机）创建一个名称，我们将给它 1 个 CPU 和 2GB 的 RAM。我们还告诉 KVM 我们正在安装一个通用的 Linux 系统。我们已经创建了我们的硬盘，所以我们正在将它挂载为我们的主要驱动器，并且我们也正在挂载我们的`.iso`文件作为 CD-ROM。最后，我们将连接我们的虚拟机到默认网络：

![](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/ms-kvm-vrt/img/B14834_09_13.jpg)

图 9.13 - 部署和测试一个经过云初始化定制的虚拟机

部署可能需要一两分钟。一旦机器启动，它将获得 IP 地址，我们可以使用预定义的密钥通过 SSH 连接到它。唯一没有自动化的是自动接受新启动的机器的指纹。

现在，是时候看看当我们启动机器时发生了什么。Cloud-init 在`/var/log`生成了一个名为`cloud-init.log`的日志。文件会相当大，你会注意到的第一件事是日志设置为提供调试信息，所以几乎所有内容都会被记录：

![图 9.14 - cloud-init.log 文件，用于检查 cloud-init 对操作系统的操作](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/ms-kvm-vrt/img/B14834_09_14.jpg)

图 9.14 - cloud-init.log 文件，用于检查 cloud-init 对操作系统的操作

另一件事是在表面以下完全自动发生了多少。由于这是 CentOS，cloud-init 必须实时处理 SELinux 安全上下文，因此很多信息只是这样。还有很多探测和测试正在进行。Cloud-init 必须确定运行环境是什么以及它正在哪种类型的云下运行。如果在启动过程中发生了任何与 cloud-init 有关的事情，这是第一个要查看的地方。

现在让我们通过使用第二个（Ubuntu）映像来部署我们的第二个虚拟机。这就是 cloud-init 真正发挥作用的地方 - 它可以与各种 Linux（和*BSD）发行版一起工作，无论它们是什么。我们现在可以测试一下。

## 第二次部署

下一个明显的步骤是创建另一个虚拟机，但为了证明一点，我们将使用 Ubuntu Server（Bionic）作为我们的镜像：

![图 9.15-为另一个基于 cloud-init 的虚拟机部署准备我们的环境](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/ms-kvm-vrt/img/B14834_09_15.jpg)

图 9.15-为另一个基于 cloud-init 的虚拟机部署准备我们的环境

我们需要做什么？我们需要将`meta-data`和`user-data`都复制到新文件夹中。我们需要编辑元数据文件，因为其中包含主机名，我们希望我们的新机器有一个不同的主机名。至于`user-data`，它将与我们的第一个虚拟机完全相同。然后我们需要创建一个新的磁盘并调整其大小：

![图 9.16-为部署目的扩展我们的虚拟机镜像](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/ms-kvm-vrt/img/B14834_09_16.jpg)

图 9.16-为部署目的扩展我们的虚拟机镜像

我们正在从下载的镜像创建虚拟机，并且在运行镜像时允许更多空间。最后一步是启动虚拟机：

![图 9.17-使用 cloud-init 部署我们的第二个虚拟机](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/ms-kvm-vrt/img/B14834_09_17.jpg)

图 9.17-使用 cloud-init 部署我们的第二个虚拟机

命令行几乎完全相同，只是名称不同：

```
virt-install --connect qemu:///system --virt-type kvm --name deploy-2 --ram 2048 --vcpus=1 --os-type linux --os-variant generic --disk path=/var/lib/libvirt/images/deploy-2/bionic.qcow2,format=qcow2 --disk /var/lib/libvirt/images/deploy-2/deploy-2-cidata.iso,device=cdrom --import --network network=default –noautoconsole
```

现在让我们检查 IP 地址：

![图 9.18-检查虚拟机 IP 地址](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/ms-kvm-vrt/img/B14834_09_18.jpg)

图 9.18-检查虚拟机 IP 地址

我们可以看到两台机器都已经启动并运行。现在进行大测试-我们能连接吗？让我们使用`SSH`命令尝试：

![图 9.19-使用 SSH 验证我们是否可以连接到虚拟机](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/ms-kvm-vrt/img/B14834_09_19.jpg)

图 9.19-使用 SSH 验证我们是否可以连接到虚拟机

正如我们所看到的，连接到我们的虚拟机没有任何问题。

还有一件事是检查部署日志。请注意，由于我们正在运行 Ubuntu，因此没有提到配置 SELinux：

![图 9.20-Ubuntu cloud-init 日志文件中没有提到 SELinux](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/ms-kvm-vrt/img/B14834_09_20.jpg)

图 9.20-Ubuntu cloud-init 日志文件中没有提到 SELinux

只是为了好玩，让我们以一个变通的方式进行另一个部署-让我们使用一个模块来部署一个软件包。

## 第三次部署

让我们部署另一个镜像。在这种情况下，我们创建另一个 CentOS 7，但这次我们是*安装*（而不是*启动*）`httpd`，以展示这种类型的配置如何工作。再次，步骤足够简单：创建一个目录，复制元数据和用户数据文件，修改文件，创建`.iso`文件，创建磁盘，运行机器。

这次我们正在向配置添加另一部分（`packages`），以便我们可以*告诉*cloud-init 我们需要安装一个软件包（`httpd`）：

![图 9.21-用于第三次虚拟机部署的 Cloud-init 配置文件](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/ms-kvm-vrt/img/B14834_09_21.jpg)

图 9.21-用于第三次虚拟机部署的 Cloud-init 配置文件

由于所有步骤多多少少都是相同的，我们得到了相同的结果-成功：

![图 9.22-重复第三个虚拟机的部署过程](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/ms-kvm-vrt/img/B14834_09_22.jpg)

图 9.22-重复第三个虚拟机的部署过程

我们应该等一会儿，以便虚拟机部署完成。之后，让我们登录并检查镜像是否正确部署。我们要求在部署过程中安装`httpd`。是吗？

![图 9.23-检查 httpd 是否已安装但未启动](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/ms-kvm-vrt/img/B14834_09_23.jpg)

图 9.23-检查 httpd 是否已安装但未启动

我们可以看到一切都如预期完成。我们没有要求启动服务，因此它是按默认设置安装的，并且默认情况下是禁用和停止的。

### 安装后

cloud-init 的预期用途是配置机器并创建一个能够实现进一步配置或直接部署到生产环境的环境。但是，为了实现这一点，cloud-init 有很多选项，我们甚至还没有提到。由于我们有一个正在运行的实例，我们可以浏览一下在新启动的虚拟机中可以找到的最重要和最有用的东西。

首先要检查的是`/run/cloud-init`文件夹：

![图 9.24 - /run/cloud-init 文件夹内容](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/ms-kvm-vrt/img/B14834_09_24.jpg)

图 9.24 - /run/cloud-init 文件夹内容

所有在运行时创建的内容都写在这里，并且对用户可用。我们的演示机器是在本地 KVM hypervisor 下运行的，因此 cloud-init 没有检测到云，并且因此无法提供有关云的更多数据，但我们可以看到一些有趣的细节。第一个是两个名为`enabled`和`network-config-ready`的文件。它们都是空的，但非常重要。它们存在的事实表明 cloud-init 已启用，并且网络已配置并且正在工作。如果文件不存在，那么出了问题，我们需要返回并进行调试。有关调试的更多信息可以在[`cloudinit.readthedocs.io/en/latest/topics/debugging.html`](https://cloudinit.readthedocs.io/en/latest/topics/debugging.html)找到。

`results.json`文件保存了这个特定实例的元数据。`status.json`更集中于整个过程运行时发生了什么，并提供了关于可能的错误、配置系统不同部分所花费的时间以及是否完成的信息。

这两个文件都旨在帮助配置和编排，而且，虽然这些文件中的一些内容只对 cloud-init 重要，但检测和与不同的云环境进行交互的能力是其他编排工具可以使用的。文件只是其中的一部分。

这个方案的另一个重要部分是名为`cloud-init`的命令行实用程序。要从中获取信息，我们首先需要登录到我们创建的机器上。我们将展示由相同文件创建的机器之间的差异，并同时展示不同发行版之间的相似之处和不同之处。

在我们开始讨论之前，请注意，与所有 Linux 软件一样，cloud-init 有不同的版本。CentOS 7 镜像使用的是一个旧版本，0.7.9：

![图 9.25 - CentOS 上的 cloud-init 版本 - 相当旧](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/ms-kvm-vrt/img/B14834_09_25.jpg)

图 9.25 - CentOS cloud-init 版本 - 相当旧

Ubuntu 带有一个更新的版本，19.3：

![图 9.26 - Ubuntu 上的 cloud-init 版本 - 最新](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/ms-kvm-vrt/img/B14834_09_26.jpg)

图 9.26 - Ubuntu 上的 cloud-init 版本 - 最新

在你惊慌之前，情况并不像看起来那么糟。Cloud-init 在几年前决定切换了其版本系统，因此在 0.7.9 之后是 17.1。发生了许多变化，其中大部分直接与 cloud-init 命令和配置文件相关。这意味着部署将会成功，但我们部署后会有很多问题。可能最明显的区别是当我们运行`cloud-init --help`时。对于 Ubuntu 来说，它看起来是这样的：

![图 2.27 - Ubuntu 上的 Cloud-init 功能](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/ms-kvm-vrt/img/B14834_09_27.jpg)

图 2.27 - Ubuntu 上的 Cloud-init 功能

实际上，CentOS 缺少了很多东西，其中一些完全缺失：

![图 9.28 - CentOS 上的 Cloud-init 功能](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/ms-kvm-vrt/img/B14834_09_28.jpg)

图 9.28 - CentOS 上的 Cloud-init 功能

由于我们的示例共有三个运行实例 - 一个 Ubuntu 和两个 CentOS 虚拟机 - 让我们尝试手动升级到 CentOS 上可用的最新稳定版本的 cloud-init。我们可以使用常规的`yum update`命令来实现，结果如下：

![图 9.29 - 经过一段时间的 yum update 后，cloud-init 功能的最新列表](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/ms-kvm-vrt/img/B14834_09_29.jpg)

图 9.29 - 经过一段 yum 更新后，cloud-init 功能的最新列表

正如我们所看到的，这将使事情变得更加容易。

我们不会过多地详细介绍 cloud-init CLI 工具，因为像这样的书籍中有太多的信息可用，而且正如我们所看到的，新功能正在迅速添加。你可以通过浏览[`cloudinit.readthedocs.io/en/latest/topics/cli.html`](https://cloudinit.readthedocs.io/en/latest/topics/cli.html)自由地查看额外的选项。事实上，它们添加得非常快，以至于有一个`devel`选项，其中包含了正在积极开发中的新功能。一旦完成，它们就会成为独立的命令。

有两个命令你需要了解，它们都提供了关于引导过程和引导系统状态的大量信息。第一个是`cloud-init analyze`。它有两个非常有用的子命令：`blame`和`show`。

恰如其名的`blame`实际上是一个工具，返回了在引导过程中 cloud-init 执行不同过程时花费了多少时间。例如，我们可以看到在 Ubuntu 上配置`grub`和处理文件系统是最慢的操作：

![图 9.30 - 检查 cloud-init 过程的时间消耗](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/ms-kvm-vrt/img/B14834_09_30.jpg)

图 9.30 - 检查 cloud-init 过程的时间消耗

我们部署的第三个虚拟机使用了 CentOS 镜像，并添加了`httpd`。从某种程度上来说，这是 cloud-init 过程中发生的最慢的事情：

![图 9.31 - 检查时间消耗 - cloud-init 部署必要的 httpd 包花费了相当长的时间使用 cloud-init 部署必要的 httpd 包](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/ms-kvm-vrt/img/B14834_09_31.jpg)

图 9.31 - 检查时间消耗 - cloud-init 部署必要的 httpd 包花费了相当长的时间

这样的工具使得优化部署变得更加容易。在我们的特定情况下，几乎没有意义，因为我们部署了几乎没有更改默认配置的简单机器，但能够理解部署为什么慢是一件有用的，如果不是必不可少的事情。

另一个有用的功能是能够看到实际引导虚拟机所花费的时间：

![图 9.32 - 检查引导时间](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/ms-kvm-vrt/img/B14834_09_32.jpg)

图 9.32 - 检查引导时间

我们将以一个查询结束这一部分 - `cloud-init query`使你能够从服务中请求信息，并以可用的结构化格式获取它，然后进行解析：

![图 9.33 - 查询 cloud-init 信息](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/ms-kvm-vrt/img/B14834_09_33.jpg)

图 9.33 - 查询 cloud-init 信息

使用了几个小时后，cloud-init 成为系统管理员不可或缺的工具之一。当然，它的本质意味着它更适合于我们这些必须在云环境中工作的人，因为它最擅长的是从脚本快速无痛地部署机器。但即使你不是在使用云技术，快速创建实例进行测试，然后无痛地删除它们的能力，是每个管理员都需要的。

# 总结

在本章中，我们介绍了 cloud-init，它的架构以及在更大的部署场景中的好处，其中配置一致性和灵活性至关重要。再加上我们不再手动完成所有事情的范式变化 - 我们有一个工具来为我们完成 - 这是我们部署流程的一个很好的补充。确保你尝试使用它，因为它将使你的生活变得更加轻松，同时为你使用云虚拟机做好准备，而在那里，cloud-init 被广泛使用。

在下一章中，我们将学习如何将这种用法模型扩展到 Windows 虚拟机，使用 cloudbase-init。

# 问题

1.  使用 CentOS 7 和 Ubuntu 基础 cloud-init 镜像重新创建我们的设置。

1.  使用相同的基础镜像创建一个 Ubuntu 和两个 CentOS 实例。

1.  使用 Ubuntu 作为基础镜像添加第四个虚拟机。

1.  尝试使用其他发行版作为基础镜像，而不更改任何配置文件。试试 FreeBSD。

1.  不要使用 SSH 密钥，使用预定义密码。这样更安全还是更不安全？

1.  创建一个脚本，使用 cloud-init 和一个基础镜像创建 10 个相同的机器实例。

1.  您能找到任何理由，为什么使用分发本地的安装方式而不是使用 cloud-init 会更有利吗？

# 进一步阅读

请参考以下链接，了解本章涵盖的更多信息：

+   Cloud-init 文档中心：[`cloudinit.readthedocs.io/en/latest/`](https://cloudinit.readthedocs.io/en/latest/)

+   cloud-init 项目主页：[`cloud-init.io/`](https://cloud-init.io/)

+   源代码：[`code.launchpad.net/cloud-init`](https://code.launchpad.net/cloud-init)

+   配置文件的特别好的例子：[`cloudinit.readthedocs.io/en/latest/topics/examples.html`](https://cloudinit.readthedocs.io/en/latest/topics/examples.html)


# 第十章：自动化 Windows 客户端部署和自定义

现在，我们已经介绍了在 KVM 中部署基于 Linux 的**虚拟机**（**VMs**）的不同方法，是时候将我们的重点转移到 Microsoft Windows 了。具体来说，我们将专注于在 KVM 上运行的 Windows Server 2019 机器，并涵盖部署和自定义 Windows Server 2019 虚拟机的先决条件和不同场景。本书不是基于**虚拟桌面基础设施**（**VDI**）和桌面操作系统的想法，这需要与虚拟化服务器操作系统完全不同的场景、方法和技术实施。

在本章中，我们将涵盖以下主题：

+   在 KVM 上创建 Windows 虚拟机的先决条件

+   使用`virt-install`实用程序创建 Windows 虚拟机

+   使用`cloudbase-init`自定义 Windows 虚拟机

+   `cloudbase-init`自定义示例

+   解决常见的`cloudbase-init`自定义问题

# 在 KVM 上创建 Windows 虚拟机的先决条件

在 KVM 虚拟化上启动客户操作系统的安装时，我们总是有相同的起点。我们需要以下之一：

+   具有操作系统安装的 ISO 文件

+   具有虚拟机模板的镜像

+   一个现有的虚拟机进行克隆和重新配置

让我们从头开始。在本章中，我们将创建一个 Windows Server 2019 虚拟机。版本选择是为了与市场上最新发布的微软服务器操作系统保持联系。我们的目标是部署一个 Windows Server 2019 虚拟机模板，以便以后用于更多部署和`cloudbase-init`，而此安装过程的选择工具将是`virt-install`。如果您需要安装旧版本（2016 或 2012），您需要知道两个事实：

+   它们在 CentOS 8 上得到了支持。

+   安装过程与我们的 Windows Server 2019 虚拟机将是相同的。

如果您想使用虚拟机管理器部署 Windows Server 2019，请确保正确配置虚拟机。这包括为客户操作系统安装选择正确的 ISO 文件，并连接另一个虚拟 CD-ROM 以安装`virtio-win`驱动程序，以便您可以在安装过程中安装它们。确保您的虚拟机在本地 KVM 主机上有足够的磁盘空间（建议为 60 GB+），并且有足够的性能来运行。从两个虚拟 CPU 和 4 GB 内存开始，因为这很容易以后更改。

我们场景的下一步是创建一个 Windows 虚拟机，我们将在本章中使用`cloudbase-init`进行自定义。在真实的生产环境中，我们需要尽可能多地在其中进行配置-驱动程序安装、Windows 更新、常用应用程序等。所以，让我们首先做这个。

# 使用`virt-install`实用程序创建 Windows 虚拟机

我们需要做的第一件事是确保我们已经准备好安装`virtio-win`驱动程序-如果没有安装，虚拟机将无法正常工作。因此，让我们首先安装`libguestfs`软件包和`virtio-win`软件包，以防您的服务器上尚未安装它们：

```
yum –y install virtio-win libguestfs*
```

然后，是时候开始部署我们的虚拟机了。以下是我们的设置：

+   Windows Server 2019 ISO 位于`/iso/windows-server-2019.iso`。

+   `virtio-win` ISO 文件位于默认系统文件夹`/usr/share/virtio-win/virtio-win.iso`。

+   我们将创建一个位于默认系统文件夹`/var/lib/libvirt/images`的 60 GB 虚拟磁盘。

现在，让我们开始安装过程：

```
virt-install --name WS2019 --memory=4096 --vcpus 2 --cpu host --video qxl --features=hyperv_relaxed=on,hyperv_spinlocks=on,hyperv_vapic=on --clock hypervclock_present=yes --disk /var/lib/libvirt/images/WS2019.qcow2,format=qcow2,bus=virtio,cache=none,size=60 --cdrom /iso/windows-server-2019.iso --disk /usr/share/virtio-win/virtio-win.iso,device=cdrom --vnc --os-type=windows --os-variant=win2k19 --accelerate --noapic 
```

安装过程开始时，我们必须点击`virtio-win`驱动程序。确保取消选中**隐藏与此计算机硬件不兼容的驱动程序**复选框。然后，逐个添加以下驱动程序，从指定目录中选择并用鼠标选择它们：

+   `AMD64\2k19`：**Red Hat VirtIO SCSI 控制器**。

+   `Balloon\2k19\amd64`：**VirtIO 气球驱动程序**。

+   `NetKVM\2k19\AMD64`：**Red Hat VirtIO 以太网适配器**。

+   `qemufwcfg\2k19\amd64`：**QEMU FWCfg 设备**。

+   `qemupciserial\2k19\amd64`：**QEMU 串行 PCI 卡**。

+   `vioinput\2k19\amd64`：**VirtIO 输入驱动程序**和**VirtIO 输入驱动程序助手**；选择它们两个。

+   `viorng\2k19\amd64`：**VirtIO RNG 设备**。

+   `vioscsi\2k19\amd64`：**Red Hat VirtIO SCSI 直通控制器**。

+   `vioserial\2k19\amd64`：**VirtIO 串行驱动程序**。

+   `viostor\2k19\amd64`：**Red Hat VirtIO SCSI 控制器**。

之后，点击**下一步**，等待安装过程完成。

您可能会问自己：*为什么我们在安装过程的早期就这样微观管理，而不是稍后再做呢？*答案有两个方面-如果我们稍后再做，我们会遇到以下问题：

+   有可能-至少对于某些操作系统-在安装开始之前我们不会加载所有必要的驱动程序，这可能意味着安装会崩溃。

+   我们会在**设备管理器**中看到大量的黄色感叹号，这通常会让人感到恼火。

部署后，我们的设备管理器很满意，安装成功了：

![图 10.1-操作系统和所有驱动程序从一开始就安装](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/ms-kvm-vrt/img/B14834_10_01.jpg)

图 10.1-操作系统和所有驱动程序从一开始就安装

安装后唯一强烈建议的事情是，在启动 VM 后从`virtio-win.iso`安装客户代理。您会在虚拟 CD-ROM 中的`guest-agent`目录中找到一个`.exe`文件，只需点击**下一步**按钮，直到安装完成。

现在我们的 VM 已经准备好，我们需要开始考虑定制。特别是大规模的定制，这是云中 VM 部署的正常使用模式。这就是为什么我们需要使用`cloudbase-init`，这是我们的下一步。

# 使用 cloudbase-init 自定义 Windows VM

如果您有机会阅读*第九章*，*使用 cloud-init 自定义虚拟机*，我们讨论了一个工具叫做`cloud-init`。我们使用它来进行客户操作系统定制，特别是针对 Linux 机器。`cloud-init`在基于 Linux 的环境中被广泛使用，特别是在基于 Linux 的云中，用于执行云 VM 的初始化和配置。

`cloudbase-init`的理念是一样的，但它针对的是 Windows 客户操作系统。它的基本服务在我们启动 Windows 客户操作系统实例时启动，然后阅读配置信息并进行配置/初始化。我们稍后将展示一些`cloudbase-init`操作的例子。

`cloudbase-init`能做什么？功能列表相当长，因为`cloudbase-init`的核心是模块化的，所以它提供了许多插件和解释器，可以用于扩展其功能：

+   它可以执行自定义命令和脚本，最常见的是用 PowerShell 编写，尽管也支持常规的 CMD 脚本。

+   它可以与 PowerShell 远程和**Windows 远程管理**（**WinRM**）服务一起工作。

+   它可以管理和配置磁盘，例如进行卷扩展。

+   它可以进行基本的管理，包括以下内容：

a) 创建用户和密码

b) 设置主机名

c) 配置静态网络

d) 配置 MTU 大小

e) 分配许可证

f) 使用公钥

g) 同步时钟

我们之前提到过，我们的 Windows Server 2019 虚拟机将用于`cloudbase-init`定制，所以这是我们接下来要讨论的主题。让我们为`cloudbase-init`准备我们的虚拟机。我们将通过下载`cloudbase-init`安装程序并安装来实现这一点。我们可以通过将我们的互联网浏览器指向[`cloudbase-init.readthedocs.io/en/latest/intro.html#download`](https://cloudbase-init.readthedocs.io/en/latest/intro.html#download)来找到`cloudbase-init`安装程序。安装非常简单，可以以常规 GUI 方式或静默方式工作。如果您习惯使用 Windows Server Core 或更喜欢静默安装，可以使用 MSI 安装程序进行静默安装，方法是使用以下命令：

```
msiexec /i CloudbaseInitSetup.msi /qn /l*v log.txt
```

确保您检查`cloudbase-init`文档，以获取更多配置选项，因为安装程序支持额外的运行时选项。它位于[`cloudbase-init.readthedocs.io/en/latest/`](https://cloudbase-init.readthedocs.io/en/latest/)。

让我们使用 GUI 安装程序，因为它更简单易用，特别是对于第一次使用的用户。首先，安装程序将要求您同意许可协议和安装位置 – 就是通常的东西。然后，我们将得到以下选项屏幕：

![图 10.2 – 基本配置屏幕](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/ms-kvm-vrt/img/B14834_10_02.jpg)

图 10.2 – 基本配置屏幕

它要求我们允许使用特定未来用户创建`cloudbase-init`配置文件（`cloudbase-init-unattend.conf`和`cloudbase-init.conf`）。这个用户将是本地`Administrators`组的成员，并且将在我们开始使用新镜像时用于登录。这将反映在我们的两个配置文件中，因此如果我们在这里选择`Admin`，那么将创建该用户。它还要求我们是否希望`cloudbase-init`服务作为`LocalSystem`服务运行，我们选择这样做是为了使整个过程更容易。原因非常简单 – 这是我们可以给予`cloudbase-init`服务的最高权限级别，以便它可以执行其操作。翻译：`cloudbase-init`服务将作为`LocalSystem`服务账户运行，该账户对所有本地系统资源具有无限访问权限。

最后一个配置屏幕将要求我们运行 sysprep。通常，我们不会检查`cloudbase-init`定制文件并在此之后运行 sysprep。因此，请保持以下窗口打开：

![图 10.3 – 完成 cloudbase-init 安装向导](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/ms-kvm-vrt/img/B14834_10_03.jpg)

图 10.3 – 完成 cloudbase-init 安装向导

现在`cloudbase-init`服务已安装和配置好，让我们创建一个定制文件，通过使用`cloudbase-init`来配置这个虚拟机。同样，请确保保持此配置屏幕打开（完成设置向导），以便我们在完成创建`cloudbase-init`配置时可以轻松开始整个过程。

# cloudbase-init 定制示例

安装过程完成后，在我们的安装位置将创建一个包含一组文件的目录。例如，在我们的虚拟机中，创建了一个名为`c:\Program Files\Cloudbase Solutions\Cloudbase-init\`的目录，它具有以下一组子目录：

+   `bin`：一些二进制文件安装的位置，例如`elevate`，`bsdtar`，`mcopy`，`mdir`等。

+   `conf`：我们将要处理的三个主要配置文件的位置，稍后会讨论。

+   `LocalScripts`：PowerShell 和类似脚本的默认位置，我们希望在启动后运行。

+   `Log`：默认情况下，我们将存储`cloudbase-init`日志文件的位置，以便我们可以调试任何问题。

+   `Python`：本地安装 Python 的位置，以便我们也可以使用 Python 进行脚本编写。

让我们专注于包含我们配置文件的`conf`目录：

+   `cloudbase-init.conf`

+   `cloudbase-init-unattend.conf`

+   `unattend.xml`

`cloudbase-init`的工作方式相当简单 - 它在 Windows sysprep 阶段使用`unattend.xml`文件来执行`cloudbase-init`，并使用`cloudbase-init-unattend.conf`配置文件。默认的`cloudbase-init-unattend.conf`配置文件非常易读，我们可以使用`cloudbase-init`项目提供的示例，逐步解释默认配置文件：

```
[DEFAULT]
# Name of the user that will get created, group for that user
username=Admin
groups=Administrators
firstlogonbehaviour=no
inject_user_password=true  # Use password from the metadata (not random).
```

配置文件的下一部分是关于设备 - 具体来说，是要检查哪些设备可能有配置驱动器（元数据）：

```
config_drive_raw_hhd=true
config_drive_cdrom=true
# Path to tar implementation from Ubuntu.
bsdtar_path=C:\Program Files\Cloudbase Solutions\Cloudbase-Init\bin\bsdtar.exe
mtools_path= C:\Program Files\Cloudbase Solutions\Cloudbase-Init\bin\
```

我们还需要配置一些日志记录的设置：

```
# Logging level
verbose=true
debug=true
# Where to store logs
logdir=C:\Program Files (x86)\Cloudbase Solutions\Cloudbase-Init\log\
logfile=cloudbase-init-unattend.log
default_log_levels=comtypes=INFO,suds=INFO,iso8601=WARN
logging_serial_port_settings=
```

配置文件的下一部分是关于网络的，因此我们将在我们的示例中使用 DHCP 获取所有网络设置：

```
# Use DHCP to get all network and NTP settings
mtu_use_dhcp_config=true
ntp_use_dhcp_config=true
```

我们需要配置脚本所在的位置，这些脚本可以作为`cloudbase-init`过程的一部分使用：

```
# Location of scripts to be started during the process
local_scripts_path=C:\Program Files\Cloudbase Solutions\Cloudbase-Init\LocalScripts\
```

配置文件的最后一部分是关于要加载的服务和插件，以及一些全局设置，例如是否允许`cloudbase-init`服务重新启动系统，以及我们将如何处理`cloudbase-init`关闭过程（`false=优雅服务关闭`）：

```
# Services for loading
metadata_services=cloudbaseinit.metadata.services.configdrive.ConfigDriveService, cloudbaseinit.metadata.services.httpservice.HttpService,
cloudbaseinit.metadata.services.ec2service.EC2Service,
cloudbaseinit.metadata.services.maasservice.MaaSHttpService
# Plugins to load
plugins=cloudbaseinit.plugins.common.mtu.MTUPlugin,
        cloudbaseinit.plugins.common.sethostname.SetHostNamePlugin
# Miscellaneous.
allow_reboot=false    # allow the service to reboot the system
stop_service_on_exit=false
```

让我们从一开始就澄清一些事情。默认配置文件已经包含了一些已弃用的设置，您很快就会发现。特别是像`verbose`，`logdir`和`logfile`这样的设置在此版本中已经被弃用，您可以从以下截图中看到，`cloudbase-init`正在抱怨这些选项：

![图 10.4 - cloudbase-init 抱怨其自己的默认配置文件选项](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/ms-kvm-vrt/img/B14834_10_04.jpg)

图 10.4 - cloudbase-init 抱怨其自己的默认配置文件选项

如果我们想要使用默认配置文件启动`cloudbase-init`进行 sysprep，实际上我们将得到一个非常好配置的虚拟机 - 它将被 sysprep，它将重置管理员密码并要求我们在第一次登录时更改密码，并删除现有的管理员用户及其目录。因此，在执行此操作之前，我们需要确保将我们的管理员用户设置和数据（文档，安装程序，下载等）保存在安全的地方。此外，默认配置文件不会默认重新启动虚拟机，这可能会让您感到困惑。我们需要手动重新启动虚拟机，以便整个过程可以开始。

与`cloud-init`和`cloudbase-init`一起工作的最简单方法是写下一个需要在虚拟机初始化过程中完成的场景。因此，我们将这样做 - 选择我们想要配置的一大堆设置，并相应地创建一个自定义文件。以下是我们的设置：

+   我们希望我们的虚拟机在`cloudbase-init`过程后要求我们更改密码。

+   我们希望我们的虚拟机从 DHCP 获取所有的网络设置（IP 地址，子网掩码，网关，DNS 服务器和 NTP）。

+   我们希望对虚拟机进行 sysprep，以使其对每个场景和策略都是唯一的。

因此，让我们创建一个`cloudbase-init-unattend.conf`配置文件来为我们执行此操作。配置文件的第一部分取自默认配置文件：

```
[DEFAULT]
username=Admin
groups=Administrators
inject_user_password=true
config_drive_raw_hhd=true
config_drive_cdrom=true
config_drive_vfat=true
bsdtar_path=C:\Program Files\Cloudbase Solutions\Cloudbase-Init\bin\bsdtar.exe
mtools_path= C:\Program Files\Cloudbase Solutions\Cloudbase-Init\bin\
debug=true
default_log_levels=comtypes=INFO,suds=INFO,iso8601=WARN
logging_serial_port_settings=
mtu_use_dhcp_config=true
ntp_use_dhcp_config=true
```

我们决定使用 PowerShell 进行所有脚本编写，因此我们为我们的 PowerShell 脚本创建了一个单独的目录：

```
local_scripts_path=C:\PS1
```

文件的其余部分也只是从默认配置文件中复制过来的：

```
metadata_services=cloudbaseinit.metadata.services.base.EmptyMetadataService
plugins=cloudbaseinit.plugins.common.mtu.MTUPlugin,
        cloudbaseinit.plugins.common.sethostname.SetHostNamePlugin, cloudbaseinit.plugins.common.localscripts.LocalScriptsPlugin,cloudbaseinit.plugins.common.userdata.UserDataPlugin
allow_reboot=false    
stop_service_on_exit=false
```

至于`cloudbase-init.conf`文件，我们唯一做的更改是选择正确的本地脚本路径（稍后将提到的原因），因为我们将在下一个示例中使用此路径：

```
[DEFAULT]
username=Admin
groups=Administrators
inject_user_password=true
config_drive_raw_hhd=true
config_drive_cdrom=true
config_drive_vfat=true
```

此外，我们默认的配置文件包含了`tar`，`mtools`和调试的路径：

```
bsdtar_path=C:\Program Files\Cloudbase Solutions\Cloudbase-Init\bin\bsdtar.exe
mtools_path= C:\Program Files\Cloudbase Solutions\Cloudbase-Init\bin\
debug=true
```

配置文件的这一部分也是从默认配置文件中获取的，我们只更改了`local_scripts_path`，以便将其设置为我们用于填充 PowerShell 脚本的目录：

```
first_logon_behaviour=no
default_log_levels=comtypes=INFO,suds=INFO,iso8601=WARN
logging_serial_port_settings=
mtu_use_dhcp_config=true
ntp_use_dhcp_config=true
local_scripts_path=C:\PS1
```

然后，我们可以返回到`cloudbase-init`安装屏幕，选中 sysprep 选项，然后单击**完成**。启动 sysprep 过程并完成后，这就是最终结果：

![图 10.5 - 当我们按“登录”时，我们将被要求更改管理员密码](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/ms-kvm-vrt/img/B14834_10_05.jpg)

图 10.5 - 当我们按“登录”时，我们将被要求更改管理员密码

现在，让我们再进一步，稍微复杂一些。假设您想执行相同的过程，但还要添加一些额外的 PowerShell 代码来进行一些额外的配置。考虑以下示例：

+   它应该创建另外两个名为`packt1`和`packt2`的本地用户，预定义密码设置为`Pa$$w0rd`。

+   它应该创建一个名为`students`的新本地组，并将`packt1`和`packt2`添加为成员。

+   它应该将主机名设置为`Server1`。

使我们能够执行此操作的 PowerShell 代码应具有以下内容：

```
Set-ExecutionPolicy -ExecutionPolicy Unrestricted -Force
$password = "Pa$$w0rd" | ConvertTo-SecureString -AsPlainText -Force
New-LocalUser -name "packt1" -Password $password
New-LocalUser -name "packt2" -Password $password
New-LocalGroup -name "Students"
Add-LocalGroupMember -group "Students" -Member "packt1","packt2"
Rename-Computer -NewName "Server1" -Restart
```

看一下脚本本身，这就是它的作用：

+   将 PowerShell 执行策略设置为无限制，以便我们的主机不会停止我们的脚本执行，这是默认情况下会发生的。

+   从纯文本字符串（`Pa$$w0rd`）创建一个密码变量，将其转换为安全字符串，我们可以将其与`New-LocalUser` PowerShell 命令一起使用来创建本地用户。

+   `New-LocalUser`是一个 PowerShell 命令，用于创建本地用户。强制参数包括用户名和密码，这就是为什么我们创建了一个安全字符串。

+   `New-LocalGroup`是一个 PowerShell 命令，用于创建本地组。

+   `Add-LocalGroupMember`是一个 PowerShell 命令，允许我们创建一个新的本地组并向其中添加成员。

+   `Rename-Computer`是一个 PowerShell 命令，用于更改 Windows 计算机的主机名。

我们还需要以某种方式从`cloudbase-init`中调用此代码，因此我们需要将此代码添加为脚本。最常见的是，在`cloudbase-init`安装文件夹中使用名为`LocalScripts`的目录。让我们将此脚本命名为`userdata.ps1`，将先前提到的内容保存到文件夹中，如`.conf`文件中定义的那样（`c:\PS1`），并在文件顶部添加一个`cloudbase-init`参数：

```
# ps1
$password = "Pa$$w0rd" | ConvertTo-SecureString -AsPlainText -Force
New-LocalUser -name "packt1" -Password $password
New-LocalUser -name "packt2" -Password $password
New-LocalGroup -name "Students"
Add-LocalGroupMember -group "Students" -Member "packt1","packt2"
Rename-Computer -NewName "Server1" –Restart
```

再次启动`cloudbase-init`过程，可以通过启动`cloudbase-init`安装向导并按照之前的示例进行操作来实现，以下是用户方面的最终结果：

![图 10.6 - 创建了 packt1 和 packt2 用户，并将其添加到我们的 PowerShell 脚本创建的组中](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/ms-kvm-vrt/img/B14834_10_06.jpg)

图 10.6 - 创建了 packt1 和 packt2 用户，并将其添加到我们的 PowerShell 脚本创建的组中

我们可以清楚地看到创建了`packt1`和`packt2`用户，以及一个名为`Students`的组。然后，我们可以看到`Students`组有两个成员 - `packt1`和`packt2`。此外，在设置服务器名称方面，我们有以下内容：

![图 10.7 - Slika 1。通过 PowerShell 脚本更改服务器名称也有效](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/ms-kvm-vrt/img/B14834_10_07.jpg)

图 10.7 - Slika 1。通过 PowerShell 脚本更改服务器名称也有效

使用`cloudbase-init`确实并不简单，需要在时间和摆弄方面进行一些投资。但之后，它将使我们的工作变得更加容易 - 不再被迫一遍又一遍地执行这些平凡的任务应该是一个足够的奖励，这就是为什么我们需要稍微谈谈故障排除。我们相信，随着您增加`cloudbase-init`的使用量，您一定会遇到这些问题。

# 排除常见的 cloudbase-init 自定义问题

坦率地说，您可以自由地说`cloudbase-init`文档并不是那么好。找到如何执行 PowerShell 或 Python 代码的示例实际上是相当困难的，而官方页面在这方面并没有提供任何帮助。因此，让我们讨论一些在使用`cloudbase-init`时经常发生的常见错误。

尽管这似乎有些违反直觉，但我们在使用最新的开发版本而不是最新的稳定版本时取得了更大的成功。我们不太确定问题出在哪里，但最新的开发版本（在撰写本文时，这是版本 0.9.12.dev125）对我们来说一开始就可以使用。使用版本 0.9.11 时，我们在启动 PowerShell 脚本时遇到了很大的问题。

除了这些问题，当您开始了解`cloudbase-init`时，还会遇到其他问题。第一个是重启循环。这个问题非常常见，几乎总是因为两个原因：

+   配置文件中的错误 - 模块或选项的名称错误输入，或类似的错误

+   在`cloudbase-init`过程中调用的一些外部文件（位置或语法）出现错误

在配置文件中犯错误是经常发生的事情，这会使`cloudbase-init`陷入一个奇怪的状态，最终会变成这样：

![图 10.8 - 配置错误](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/ms-kvm-vrt/img/B14834_10_08.jpg)

图 10.8 - 配置错误

我们已经多次看到这种情况。真正的问题在于有时需要等待数小时，有时需要循环多次重启，但这不仅仅是一个常规的重启循环。似乎`cloudbase-init`正在做某些事情 - CMD 已经启动，屏幕上没有错误，但它一直在做某些事情，然后以这种方式完成。

您可能遇到的其他问题更加挑剔 - 例如，当`cloudbase-init`在 sysprep/`cloudbase-init`过程中无法重置密码时。如果您手动更改了`cloudbase-init`服务使用的帐户密码（因此，使用`LocalSystem`是一个更好的主意），就会发生这种情况。这将导致整个`cloudbase-init`过程失败，其中的一部分可能是无法重置密码。

还有一个更加隐晦的原因可能会导致这种情况发生 - 有时我们会使用`services.msc`控制台手动管理系统服务，并且会有意地禁用我们不立即识别的服务。如果将`cloudbase-init`服务设置为禁用，它将在其过程中失败。这些服务需要具有自动启动优先级，并且不应手动重新配置为禁用。

重置密码失败也可能是因为某些安全策略 - 例如，如果密码不够复杂。这就是为什么我们在 PowerShell 脚本中使用了更复杂的密码，因为我们大多数系统工程师很早就学到了这个教训。

此外，有时公司会制定不同的安全策略，这可能导致某些管理应用程序（例如软件清单）停止`cloudbase-init`服务或完全卸载它。

我们可能遇到的最令人沮丧的错误是`cloudbase-init`进程无法从指定文件夹启动脚本。在花费数小时完善您的 Python、bash、cmd 或 PowerShell 脚本后，需要将其添加到定制过程中，看到这种情况发生总是令人发狂。为了能够使用这些脚本，我们需要使用一个能够调用外部脚本并执行它的特定插件。这就是为什么我们通常使用`UserDataPlugin` - 无论是出于执行还是调试的原因 - 因为它可以执行所有这些脚本类型并给我们一个错误值，然后我们可以用于调试目的。

最后一件事 - 确保不要直接将 PowerShell 代码插入到`conf`文件夹中的`cloudbase-init`配置文件中。你只会得到一个重启循环作为回报，所以要小心。

# 总结

在本章中，我们讨论了 Windows VM 的定制化，这是与 Linux VM 定制化同样重要的话题。甚至更重要，考虑到市场份额和许多人在云环境中使用 Windows。

现在我们已经涵盖了与 VM、模板化和定制化相关的所有基础知识，是时候介绍一种与`cloud-init`和`cloudbase-init`互补的附加定制化方法了。因此，下一章将介绍基于 Ansible 的方法。

# 问题

1.  我们需要安装哪些驱动程序到 Windows 客户操作系统中，以便在 KVM 虚拟化程序上创建 Windows 模板？

1.  我们需要安装哪个代理程序到 Windows 客户操作系统中，以便更好地查看 VM 的性能数据？

1.  sysprep 是什么？

1.  `cloudbase-init`用于什么？

1.  `cloudbase-init`的常规用例是什么？

# 进一步阅读

请参考以下链接获取更多信息：

+   Microsoft `LocalSystem`账户文档：[`docs.microsoft.com/en-us/windows/win32/ad/the-localsystem-account`](https://docs.microsoft.com/en-us/windows/win32/ad/the-localsystem-account)

+   `cloudbase-init`文档：[`cloudbase-init.readthedocs.io/en/latest/intro.html`](https://cloudbase-init.readthedocs.io/en/latest/intro.html)

+   `cloudbase-init`插件文档：[`cloudbase-init.readthedocs.io/en/latest/plugins.html`](https://cloudbase-init.readthedocs.io/en/latest/plugins.html)

+   `cloudbase-init`服务文档：[`cloudbase-init.readthedocs.io/en/latest/services.html`](https://cloudbase-init.readthedocs.io/en/latest/services.html)
