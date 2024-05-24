# Azure 上的 Linux 管理实用指南（三）

> 原文：[`zh.annas-archive.org/md5/0EE39A6B040A18FF64595B6B3C82179F`](https://zh.annas-archive.org/md5/0EE39A6B040A18FF64595B6B3C82179F)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第六章：管理 Linux 安全和身份

在上一章中，我们讨论了处理存储、网络和进程管理。然而，作为系统管理员，您的主要目标是保护 Linux 机器，拒绝任何未经授权的访问或限制用户的访问。在企业环境中，安全漏洞是一个巨大的关注点。在本章中，我们将涵盖安全性——在操作系统级别保护您的工作负载；例如，如果您的组织是一个金融机构，在那里您将处理涉及货币承诺甚至客户的**个人可识别信息**（**PII**）的工作负载，那么保护工作负载以避免任何违规行为就至关重要。当然，Azure 已经为您提供了多种方式和多个层面的服务来保护您的 VM。以下是其中一些服务：

+   Azure 资源管理器，提供安全性、审计和标记功能

+   Web 应用程序防火墙，可防范诸如 SQL 注入等许多攻击

+   网络安全组的有状态数据包过滤功能

+   Azure 防火墙，提供与 Azure 监控功能紧密集成的有状态防火墙

您还可以订阅 Azure 安全中心服务，进行统一的安全管理，具有许多有吸引力的功能，如持续安全评估。

有了所有这些可能性，我们是否仍然需要在操作系统级别进行保护？在我们看来，多层保护是一个好主意。这将使黑客付出更多的努力和时间，这将使检测黑客变得更容易。没有完全没有漏洞的软件：如果一个应用程序有漏洞，至少操作系统应该受到保护。

身份管理是与安全相关的一个话题。您可以将 Linux 与**Azure Active Directory**（**Azure AD**）集成，以集中管理您的登录帐户，通过使用基于角色的访问控制进行细粒度访问，撤销访问权限，并启用多因素身份验证。

在本章结束时，您将能够：

+   实施**强制访问控制**（**MAC**）系统，如 SELinux 或 AppArmor。

+   了解**自主访问控制**（**DAC**）的基础知识。

+   使用 Azure 中可用的身份管理系统。

+   使用防火墙守护程序和 systemd 增强 Linux 安全性。

## Linux 安全提示

在深入讨论您可以采取的所有出色安全措施之前，这里有一些关于安全性的提示。

一般来说，在多个层面上实施安全性是一个好主意。这样，黑客需要不同的方法来获取访问权限，这会花费他们时间。由于这段时间，希望也是由于日志记录和监控，您有更大的机会发现未经授权的访问。

对于文件和目录，尽可能使用`suid/sgid`位。是否有需要更改自己密码的用户？没有？那么从`passwd`命令中删除该位。

使用分区，特别是对于`/tmp`、`/var`、`/var/tmp`和`/home`等目录，并使用`noexec`、`nodev`和`nosuid`标志进行挂载：

+   一般来说，允许用户从这些位置执行程序并不是一个好主意。幸运的是，如果你无法将所有者设置为 root，你可以将带有`suid`位的程序复制到自己的目录中作为普通用户。

+   这些目录中文件的`suid`和`sgid`权限非常危险。

+   不允许在此分区上创建或存在字符或特殊设备。

要访问虚拟机，请使用基于 SSH 密钥的身份验证，而不是密码。使用 ACL 或防火墙限制对特定 IP 的访问。限制用户，并且不允许 root 进行远程访问（使用`PermitRootLogin no`参数和`AllowUsers`只允许一个或两个帐户访问）。使用`sudo`以 root 身份执行命令。也许在`sudo`配置中创建特殊用户或用户组来执行特殊任务。

不要在虚拟机上安装太多软件，特别是涉及网络服务的软件，比如 Web 服务器和电子邮件服务器。定期使用 `ss` 命令来查看开放端口，并将其与 ACL 和/或防火墙规则进行比较。

另一个提示是不要在系统上禁用 SELinux，这是 Linux 内核中的一个安全模块。现在不用担心这个问题，因为我们有一个专门的章节介绍 SELinux。

保持系统更新；Linux 供应商提供更新是有原因的。可以手动进行更新，也可以使用自动化/编排工具。一定要做！

## 技术要求

在本章中，您需要部署 RedHat/CentOS 7 和 Ubuntu 18.04 VM。另一个选择是使用 SUSE SLE 12 或 openSUSE LEAP 而不是 CentOS 和 Ubuntu VM。SUSE 支持本章讨论的所有选项。

## DAC

**DAC** 也被称为用户控制的访问控制。您可能已经熟悉 Linux 中的经典权限和 ACL。这两者结合形成了 DAC。经典权限检查当前进程的 **用户 ID**（**UID**）和 **组 ID**（**GID**）。经典权限将试图访问文件的用户的 UID 和 GID 与文件设置的 UID 和 GID 进行匹配。让我们看看 DAC 是如何引入的，以及您在 Linux 中拥有什么级别的权限。但是，我们不会详细讨论这个问题，因为主要目的是让您熟悉 Linux 中的权限。

### DAC 简介

大多数操作系统，如 Linux、macOS、各种 Unix 的变种，甚至 Windows，都是基于 DAC 的。MAC 和 DAC 在美国国防部发布的《可信计算机系统评估标准》（TCSEC），也称为橙皮书中定义。我们将在下一节讨论 MAC。顾名思义，DAC 允许文件的所有者或创建者决定他们需要为同一文件提供其他用户的访问级别。

尽管我们看到 DAC 在所有系统中都得到了实施，但它也被认为是薄弱的。例如，如果我们授予用户读取权限，它将具有传递性质。因此，没有任何东西会阻止用户将别人文件的内容复制到用户可以访问的对象中。换句话说，信息的分发在 DAC 中没有得到管理。在下一节中，我们将快速了解文件权限。

### Linux 中的文件权限

Linux 中的每个文件和目录都被视为一个对象，并且具有三种所有者类型：用户、组和其他。接下来，我们通常将文件和目录称为对象。首先，让我们了解三种不同类型的所有者：

+   用户：用户是创建对象的人。默认情况下，这个人将成为对象的所有者。

+   **组**：组是用户的集合。所有属于同一组的用户将对对象具有相同的访问级别。组的概念使您能够一次为多个用户分配权限更加容易。想象一种情况，您将创建一个文件，并且希望您的团队成员也能访问该文件。如果您是一个庞大的团队，并且为每个用户分配权限，这将是繁琐的。相反，您可以将用户添加到一个组中，并为该组定义权限，这意味着组中的所有用户都继承了访问权限。

+   **其他**：这指的是任何不是对象所有者（创建者）或不是用户组成员的其他用户。换句话说，想象一个包含创建者和具有权限的组中的所有用户的集合；“其他”指的是不是这个集合元素的用户。

如前所述，每个对象都有三种所有者类型。每个所有者（用户、组、所有者）对对象都有三种权限。它们如下：

+   **读取**：读取权限将允许读取或打开文件。目录上的读取权限意味着用户将能够列出目录的内容。

+   **写入**：如果应用于文件，这将允许修改文件的内容。将此权限添加到目录将授予添加、删除和重命名文件的权限。

+   **执行**：这个权限对于运行可执行程序或脚本是必需的。例如，如果你有一个 bash 脚本并且有读/写权限，这意味着你可以读取和修改代码。然而，要执行代码，你需要这个权限。

这是所有者和相关权限的图示表示：

![代表三种所有者（用户、组和其他人）及其在对象上的读、写和执行权限的流程图](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/hsn-linux-adm-az/img/B15455_06_01.jpg)

###### 图 6.1：所有者类型和访问权限

让我们继续了解如何从 Linux 终端中找出权限。

要列出目录的内容，执行`ls -lah`。

输出将根据你要列出的目录中的内容而有所不同：

![列出目录内容的输出](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/hsn-linux-adm-az/img/B15455_06_02.jpg)

###### 图 6.2：列出目录的内容

如果观察`数据`行，第一个字母是`d`，这意味着它是一个目录。至于`external.png`，显示的是`-`，代表一个文件，而`home`有`l`，意味着一个链接（更像是一个快捷方式）。

让我们仔细看一下：

![目录输出数据行的一瞥](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/hsn-linux-adm-az/img/B15455_06_03.jpg)

###### 图 6.3：目录输出的数据行

首先，`rwx`表示用户/所有者有读、写和执行权限。

第二，`r-x`表示组有读和执行权限。然而，没有写权限。

第三，`r-x`表示所有其他人都有读和执行权限，但没有写权限。

同样地，你可以理解分配给其他对象的权限。

这些将按顺序写成`读(r)`、`写(w)`和`执行`。如果有一个字母缺失，那意味着该权限不存在。下面是一个解释这些字母代表的表格：

![访问权限列表及其对应的符号](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/hsn-linux-adm-az/img/B15455_06_04.jpg)

###### 图 6.4：访问权限的符号

你可能想知道这个文件的所有者是谁，以及哪个组在访问。这在输出中已经有答案了：

![包含有关所有者和组的信息的输出](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/hsn-linux-adm-az/img/B15455_06_05.jpg)

###### 图 6.5：所有者和组的详细信息

在这种情况下：

+   用户有读和写权限，但没有执行权限。

+   组只有读权限，没有写和执行权限。

+   所有其他人只有读权限。

以下的图表将帮助你理解如何区分每个所有者的权限：

![理解不同所有者的各种权限之间的差异](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/hsn-linux-adm-az/img/B15455_06_06.jpg)

###### 图 6.6：区分每个所有者的权限

你可以使用`chmod`命令来改变文件或文件夹的权限。一般的语法是：

```
chmod permissions filename/directory
```

然而，对目录应用权限并不会继承到子文件夹和文件中。如果希望权限被继承，可以使用`-R`参数，代表*递归*。

此命令也不会给出任何输出；也就是说，无论是否应用了权限，它都不会返回任何输出。你可以使用`-v`参数来获得详细输出。

有两种方式可以传递权限给`chmod`命令：

+   符号方法

+   绝对方法/数字模型

### 符号方法

在符号方法中，我们将使用操作符和用户表示。以下是操作符列表：

![用于设置、添加和移除权限的操作符列表](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/hsn-linux-adm-az/img/B15455_06_07.jpg)

###### 图 6.7：符号方法中的操作符

以下是用户表示列表：

![用户表示列表](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/hsn-linux-adm-az/img/B15455_06_08.jpg)

###### 图 6.8：用户表示

现在，让我们看看如何结合操作符和表示法来更改权限。我们将使用`-v`参数来理解发生了什么变化。

让我们回顾一下我们对`external.png`文件的权限：

![查看 external.png 文件的权限](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/hsn-linux-adm-az/img/B15455_06_09.jpg)

###### 图 6.9：external.png 文件的权限

目前，用户没有执行权限。要添加这些权限，请执行以下命令：

```
chmod -v u+x external.png
```

在输出中，您可以看到该值从`rw-r--r--`更改为`rwxr--r--`：

![为用户添加执行权限](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/hsn-linux-adm-az/img/B15455_06_10.jpg)

###### 图 6.10：添加执行权限

这里会显示一些数字。我们将在讨论绝对方法时讨论这些内容。

接下来，让我们尝试为组添加写和执行权限，执行以下命令：

```
chmod -v g+wx external.png
```

因此，向`g（组）`添加`wx（写、执行）`将给您一个类似以下的输出。您可以清楚地从输出中理解变化：

![为组添加写和执行权限](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/hsn-linux-adm-az/img/B15455_06_11.jpg)

###### 图 6.11：为组添加写和执行权限

到目前为止，我们一直在添加权限。现在，让我们看看如何移除其他人的现有读权限。

执行以下命令：

```
chmod -v o-r external.png
```

这将移除读权限，从以下输出中可以明显看出：

![显示读权限更改的输出](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/hsn-linux-adm-az/img/B15455_06_12.jpg)

###### 图 6.12：移除读权限

让我们为所有人（用户、组和其他人）设置读、写和执行权限。

执行以下命令：

```
chmod -v a=rwx external.png
```

输出显示权限更改为`rwxrwxrwx`：

![为所有所有者（用户、组和其他人）设置读、写和执行权限](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/hsn-linux-adm-az/img/B15455_06_13.jpg)

###### 图 6.13：为所有人设置读、写和执行权限

另一个例子涉及将每个所有者的权限组合在一起，并一次性传递这些权限，如下所示：

```
chmod -v u=rw,g=r,o=x external.png
```

在这里，用户权限设置为读写，组权限设置为只读，其他权限设置为仅执行。同样，您可以使用逗号分隔权限，并使用必要的运算符授予权限。

### 绝对（数字）节点

在这种方法中，我们将使用一个三位八进制数来设置权限。以下是数值及其对应权限的表格：

![数字值及其对应权限的列表](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/hsn-linux-adm-az/img/B15455_06_14.jpg)

###### 图 6.14：数字值及其对应权限

让我们举个例子。检查位于当前目录中的`new-file`文件的权限。执行`ls -lah`：

![执行 ls -lah 以检查 new-file 的权限](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/hsn-linux-adm-az/img/B15455_06_15.jpg)

###### 图 6.15：检查 new-file 的权限

现在，让我们使用数字模式并分配权限。我们将把用户权限更改为`rwx`，因此 4 + 2 + 1 = 7，然后将组权限更改为`rw`，因此 4 + 2 + 0 = 6，其他人仅执行，因此 0 + 0 + 1 = 1。

将这三个数字组合起来，我们得到 761，因此这是我们需要传递给`chmod`的值。

执行以下命令：

```
chmod -v 761 new-file
```

输出如下：

![使用三位八进制代码分配权限](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/hsn-linux-adm-az/img/B15455_06_16.jpg)

###### 图 6.16：使用三位八进制代码分配权限

现在，我们可以将我们在使用符号方法进行测试时得到的数字与之前的输出相关联。

这是该值的图示表示：

![三位八进制代码的图示表示](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/hsn-linux-adm-az/img/B15455_06_17.jpg)

###### 图 6.17：三位八进制代码的图示表示

您可能已经注意到我们分配的权限之前有一个额外的数字（例如，0761）。这个`0`是用于高级文件权限。如果您还记得提示，我们有“*这些目录中文件的 suid 和 sgid 权限非常危险*”和“*尽量避免使用 suid/sgid 位*”。这些`suid/sgid`值通过额外的数字传递。最好不要使用这个，而是坚持使用基本权限，因为这些非常危险且复杂。

现在我们知道如何更改权限，但是我们如何更改拥有用户和组呢？为此，我们将使用`chown`命令。语法如下：

```
chown user:group filename/directory
```

这将更改文件的所有者和组。如果只想更改所有者，可以使用这个：

```
chown user filename/directory
```

如果只想更改组，使用`chgrp`命令：

```
chgrp group filename/directory
```

就像在`chown`命令的情况下解释的那样，这个命令也不是递归的。如果要使更改继承到目录的子文件夹和文件中，使用`-R`（递归）参数。就像我们在`chmod`中看到的那样，您还有一个详细的（`-v`）选项。

现在我们知道如何处理权限，让我们进入下一个关于 MAC 的部分。DAC 完全是关于使用 UID 和 GID 进行权限检查。另一方面，MAC 是基于策略的访问控制。现在让我们更仔细地看看 MAC。

## MAC

在 MAC 中，系统根据特定资源的授权和敏感性限制对特定资源的访问。它更多地基于策略，并使用**Linux 安全模块**（**LSM**）来实现。

安全标签是 MAC 的核心。每个主体都被赋予了一定级别的安全许可（例如，机密或保密），每个数据对象都有安全分类。例如，一个安全许可级别为保密的用户试图检索一个具有绝密安全分类的数据对象，因为他们的许可级别低于对象的分类，所以被拒绝访问。

因此，很明显，您可以在机密性非常重要的环境中（政府机构等）大多数情况下使用 MAC 模型。

SELinux 和 AppArmor 是基于 MAC 的商业系统的例子。

### LSM

LSM 是一个提供在 DAC 之上添加 MAC 接口的框架。这种额外的安全层可以通过 SELinux（基于 Red Hat 的发行版和 SUSE）、AppArmor（Ubuntu 和 SUSE）或较少人知道的 Tomoyo（SUSE）来添加。在本节中，我们将介绍 SELinux 和 AppArmor。

DAC 是一个基于用户组成员和文件设备权限的访问控制模型。MAC 限制对资源对象的访问，例如以下内容：

+   文件

+   进程

+   TCP/UDP 端口

+   用户及其角色

MAC，由 SELinux 实现，通过为每个资源对象分配一个分类标签，也称为上下文标签，来工作，而 AppArmor 是基于路径的。在任何情况下，如果一个资源对象需要访问另一个对象，它需要许可。因此，即使黑客成功进入您的网络应用程序，其他资源仍然受到保护！

### SELinux

正如我们之前提到的，SELinux 是 Linux 中的一个安全模块，作为一个安全提示，建议不要禁用它。SELinux 是由 NSA 和 Red Hat 开发的。最初发布于 2000 年 12 月 22 日，在撰写本书时，可用的稳定版本是 2019 年发布的 2.9 版。它可以在每个基于 Red Hat 的发行版和 SUSE 上使用。本书将介绍在 Red Hat 上的实现。如果您想在 SUSE 上使用它，请访问 SUSE 文档[`doc.opensuse.org/documentation/leap/security/html/book.security/cha-selinux.html`](https://doc.opensuse.org/documentation/leap/security/html/book.security/cha-selinux.html)来安装和启用 SELinux。之后，程序是相同的。过去曾经努力使其在 Ubuntu 上运行，但目前没有积极的开发，而且软件包已经损坏。

所有访问必须明确授权，但在使用 SELinux 的发行版上，已经有许多策略。这几乎涵盖了每个资源对象。除了文档中已经提到的列表之外，还包括以下内容：

+   完整的网络堆栈，包括 IPsec

+   内核功能

+   **进程间通信**（**IPC**）

+   内存保护

+   文件描述符（通信通道）继承和传输

对于 Docker 等容器虚拟化解决方案，SELinux 可以保护主机并在容器之间提供保护。

### SELinux 配置

SELinux 是通过`/etc/selinux/config`文件进行配置的：

```
#  This file controls the state of SELinux on the system.
#  SELINUX= can take one of these three values:
#  enforcing - SELinux security policy is enforced.
#  permissive - SELinux prints warnings instead of enforcing.
#  disabled - No SELinux policy is loaded.
SELINUX=enforcing
```

在生产环境中，状态应该是`enforcing`模式。策略是强制执行的，如果访问受限，可以进行审计以修复 SELinux 引起的问题。如果您是软件开发人员或打包人员，并且需要为您的软件创建 SELinux 策略，`permissive`模式可能会有用。

可以使用`setenforce`命令在`enforcing`和`permissive`模式之间切换。使用`setenforce 0`切换到 permissive 模式，使用`setenforce 1`切换回 enforcing 模式。`getenforce`命令可用于查看当前状态：

```
#  SELINUXTYPE= can take one of these three values:
#  targeted - Targeted processes are protected,
#  minimum - Modification of targeted policy.
#  Only selected processes are protected.
#  mls - Multi Level Security protection.
SELINUXTYPE=targeted
```

默认策略—`targeted`，保护所有资源，并为大多数工作负载提供足够的保护。**多级安全**（**MLS**）通过使用类别和敏感性提供的许可级别以及 SELinux 用户和角色提供额外的安全性。这对于提供文件共享的文件服务器非常有用。

如果选择了`minimum`类型，那么只有最基本的保护；如果需要更多的保护，就需要自己配置其他所有内容。如果在保护多进程应用程序（通常是非常老的应用程序）时遇到困难，并且生成的策略去除了太多限制，那么这种类型可能会有用。在这种情况下，最好是让特定应用程序不受保护，并保护系统的其余部分。在本节中，我只会讨论`SELINUXTYPE=targeted`，这是最常用的选项。

要显示 SELinux 的状态，可以使用`sestatus`命令。输出应该类似于以下屏幕截图：

![运行 sestatus 命令查看 SELinux 状态](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/hsn-linux-adm-az/img/B15455_06_18.jpg)

###### 图 6.18：SELinux 状态

在探索 SELinux 之前，您需要向系统添加必要的软件包，以便审计 SELinux。请执行以下命令：

```
sudo yum install setroubleshoot
```

之后，您需要重新启动虚拟机：

```
sudo systemctl reboot
```

重启后，我们准备使用和排除 SELinux 故障：

```
SELinux context on ports
```

让我们从涉及 SSH 服务的简单示例开始。如前所述，所有进程都带有上下文标签。为了使此标签可见，许多实用程序，如`ls`、`ps`和`lsof`，都有`-Z`参数。首先，您需要找到此服务的主要进程 ID：

```
systemctl status sshd | grep PID
```

使用此进程 ID，我们可以请求上下文标签：

```
ps -q <PID> -Z
```

上下文标签是`system_u`，`system_r`，`sshd_t`和`s0-s0，c0.c1023`。因为我们使用的是有针对性的 SELinux 类型，所以我们只关心 SELinux 类型部分：`sshd_t`。

SSH 正在端口 22 上运行。现在让我们调查端口的标签：

```
ss -ltn sport eq 22 -Z
```

您将确定上下文标签是`system_u`，`system_r`，`sshd_t`，`s0-s0`和`c0.c1023`，换句话说，完全相同。不难理解`sshd`进程确实具有以相同标签运行在此端口的权限：

![sshd 进程的上下文标签](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/hsn-linux-adm-az/img/B15455_06_19.jpg)

###### 图 6.19：sshd 进程的上下文标签

这并不总是那么简单，但在进入更复杂的情景之前，让我们将 SSH 服务器监听的端口修改为端口 44。要这样做，请编辑`/etc/ssh/sshd_config`文件：

```
sed -i 's/#Port 22/Port 44/' /etc/ssh/sshd_config
```

然后，重新启动 SSH 服务器：

```
sudo systemctl restart sshd
```

这将失败：

```
Job for sshd.service failed because the control process exited with error code.
See systemctl status sshd.service and journalctl -xe for details.
```

如果您执行`journalctl -xe`命令，您将看到以下消息：

```
SELinux is preventing /usr/sbin/sshd from name_bind access  
on the tcp_socket port 44.
```

有多种方法可以用于排除 SELinux 故障。您可以直接使用日志文件`/var/log/audit/audit.log`，或者使用`sealert -a /var/log/audit/audit.log`命令，或者使用`journalctl`命令：

```
journalctl --identifier setroubleshoot
```

日志条目还说明了以下内容：

```
For complete SELinux messages run: sealert -l <audit id>
```

执行此命令（可能将输出重定向到文件或通过`less`或`more`进行管道传输），它不仅会再次显示相同的 SELinux 消息，而且还会提出如何修复它的建议：

```
If you want to allow /usr/sbin/sshd to bind to network port 44
Then you need to modify the port type.
Do 
# semanage port -a -t PORT_TYPE -p tcp 44 
where PORT_TYPE is one of the following: ssh_port_t, vnc_port_t, xserver_port_t.
```

在进入此解决方案之前，SELinux 与包含资源对象和上下文标签的多个数据库一起工作，即应将`/`应用于资源对象。`semanage`工具可用于修改数据库并向其中添加条目；在我们的情况下，是端口数据库。日志的输出建议为 TCP 端口 44 添加上下文标签到数据库。有三种可能的上下文；它们都将解决您的问题。

另一个重要的方面是有时还有其他可能的解决方案。有一个信心评级可以让您更容易地做出选择。但即使如此，您仍然必须仔细阅读。特别是对于文件，有时，您希望添加一个正则表达式，而不是一遍又一遍地为每个文件做同样的事情。

您可以采取一种实用的方法并声明“我不使用`vnc`和`xserver`，所以我选择`ssh_port_t`”，或者您可以使用`sepolicy`实用程序，该程序是`policycoreutils-devel`软件包的一部分。如果您收到错误消息，请使用`sudo yum install –y policycoreutils-devel`安装`policycoreutils-devel`：

```
sepolicy network -a /usr/sbin/sshd 
```

在输出中搜索 TCP `name_bind`，因为 SELinux 访问正在阻止`/usr/sbin/sshd`对`tcp_socket port 44`进行`name_bind`访问。

现在您知道建议来自何处，请查看端口 22 的当前标签：

```
sepolicy network -p 22 
```

标签是`ssh_port_t`。

#### 注意

您可以使用`semanage port -l`和`grep`来查找端口 22 的内容。

使用相同的标签确实是有道理的。不相信？让我们生成手册页：

```
sepolicy manpage -a -p /usr/share/man/man8/ 
mandb  
```

`ssh_selinux`手册页告诉您`ssh_port_t`。

最后，让我们解决问题：

```
semanage port -a -t ssh_port_t -p tcp 44 
```

您不必重新启动`sshd`服务；`systemd`将在 42 秒内自动重新启动此服务。顺便说一句，`sshd_config`文件已经有一条注释描述了这个修复。在`#Port 22`之前的行中明确说明了这一点：

```
If you want to change the port on a SELinux system, you have to tell:
# SELinux about this change. 
# semanage port -a -t ssh_port_t -p tcp #PORTNUMBER 
```

最好撤消配置更改并将其重新配置为端口 22；否则，您可能会被锁在测试系统外。

### 文件上的 SELinux 上下文

在我们与 SELinux 的第一次会议以及调查端口上的上下文标签之后，现在是时候调查文件上的上下文标签了。作为示例，我们将使用`vsftpd`和 FTP 客户端：

```
sudo yum install vsftpd ftp 
```

然后，创建一个名为`/srv/ftp/pub`的目录：

```
sudo mkdir -p /srv/ftp/pub 
chown -R ftp:ftp /srv/ftp 
```

然后在`/srv/ftp`中创建一个文件：

```
echo WELCOME > /srv/ftp/README 
```

编辑配置文件`/etc/vsftpd/vsftpd.conf`，并在`local_enable=YES`行下添加以下内容：

```
anon_root=/srv/ftp 
```

这将使`/srv/ftp`成为匿名用户`vsftpd`服务的默认根目录。现在您可以开始服务了：

```
sudo systemctl start vsftpd.service
sudo systemctl status vsftpd.service
```

使用`ftp`实用程序，尝试以用户`anonymous`的身份登录到 FTP 服务器，无需密码：

```
ftp localhost 

Trying ::1... 
Connected to localhost (::1). 
220 (vsFTPd 3.0.2) 
Name (localhost:root): anonymous 
331 Please specify the password. 
Password: 
230 Login successful. 
Remote system type is UNIX. 
Using binary mode to transfer files. 
ftp> ls 
229 Entering Extended Passive Mode (|||57280|). 
150 Here comes the directory listing. 
-rw-r--r-- 1 14 50 8 Jul 16 09:47 README 
drwxr-xr-x 2 14 50 6 Jul 16 09:44 pub 
226 Directory send OK. 
Try to get the file:  
get README 
```

而且它有效！为什么会这样？因为数据库中已经有了`/srv/ftp/README`的正确标签条目：

```
semanage fcontext -l | grep /srv  
```

上面的命令显示以下行：

```
/srv/([^/]*/)?ftp(/.*)? all files system_u:object_r:public_content_t:s0 
```

在创建新文件时应用：

```
stat -c %C /srv/ftp/README 
ls -Z /srv/ftp/README 
```

这两个命令告诉你类型是`public_content_t`。`ftpd_selinux`的 man 页面有两个在这里很重要的部分：`public_content_t`类型只允许你读取（下载）文件，但不允许你使用这种类型写入（上传）文件。你需要另一种类型`public_content_rw_t`才能上传文件。

创建一个上传目录：

```
mkdir -m 2770 /srv/ftp/incoming 

chown -R ftp:ftp /srv/ftp/incoming 
```

查看当前标签并更改它：

```
ls -dZ /srv/ftp/incoming 

semanage fcontext -a -t public_content_rw_t "/srv/ftp/incoming(/.*)?" 

restorecon -rv /srv/ftp/incoming 

ls -dZ /srv/ftp/incoming 
```

首先，你必须将策略添加到`fcontext`数据库；之后，你可以将策略应用到已经存在的目录。

#### 注意

阅读`selinux-fcontext`的 man 页面。除了描述所有选项外，还有一些很好的例子。

### SELinux 布尔值

使用单个字符串，你可以改变 SELinux 的行为。这个字符串被称为`SELinux 布尔值`。你可以使用`getsebool -a`获取布尔值及其值的列表。使用`boolean allow_ftpd_anon_write`，我们将改变 SELinux 的反应方式。再次匿名连接到 FTP 服务器并尝试上传文件：

```
ftp> cd /incoming 
250 Directory successfully changed. 
ftp> put /etc/hosts hosts 
local: /etc/hosts remote: hosts 
229 Entering Extended Passive Mode (|||12830|). 
550 Permission denied. 
```

`journalctl --identifier setroubleshoot`命令非常清楚地告诉你：

```
SELinux is preventing vsftpd from write access on the directory ftp.   
```

`sealert`命令将为你提供修复问题所需的信息：

```
setsebool -P allow_ftpd_anon_write 1 
```

那么，这里发生了什么？有时，对于端口或文件的简单规则是不够的，例如，如果一个 NFS 共享也必须与 Samba 一起导出。在这种情况下，你可以创建自己的复杂 SELinux 策略，或者使用易于使用的开关数据库。为此，你可以使用较旧的`setsebool`实用程序或`semanage`：

```
semanage boolean --list | grep "ftpd_anon_write" 
semanage boolean --modify ftpd_anon_write --on 
```

使用`setsebool`而不加上`-P`会进行更改，但不是持久的。`semanage`实用程序没有选项可以进行非永久更改。

### AppArmor

在 Debian、Ubuntu 和 SUSE 发行版中，AppArmor 可用于实现 MAC。请注意，各发行版之间存在一些细微差异，但总的来说，一个发行版可以添加更少或更多的配置文件和一些额外的工具。在本节中，我们以 Ubuntu 18.04 为例。

此外，你必须确保保持你的发行版最新，特别是 AppArmor；Debian 和 Ubuntu 的软件包经常受到错误的困扰，有时会导致意外的行为。

确保必要的软件包已安装：

```
sudo apt install apparmor-utils apparmor-easyprof \ 
  apparmor-profiles apparmor-profiles-extra apparmor-easyprof 
```

与 SELinux 相比，存在一些基本差异：

+   默认情况下，只有最低限度受到保护。你必须为每个应用程序应用安全性。

+   你可以混合强制和投诉模式；你可以针对每个应用程序做出决定。

+   当 AppArmor 开发开始时，范围相当有限：进程和文件。如今，除了进程和文件，你还可以用它来进行基于角色的访问控制（RBAC）、MLS、登录策略以及其他方面的控制。

在本章中，我们将涵盖初始范围：需要访问文件的进程。

### AppArmor 状态

首先要做的是检查 AppArmor 服务是否正在运行：

```
sudo systemctl status apparmor 
```

或者，执行以下命令：

```
sudo aa-enabled 
```

之后，使用以下命令更详细地查看状态：

```
sudo apparmor_status 
```

以下是上述命令的替代方法：

```
sudo aa-status 
```

以下截图显示了使用`apparmor_status`命令派生的 AppArmor 状态：

使用`apparmor_status`命令检查 AppArmor 状态

###### 图 6.20：AppArmor 状态

### 生成 AppArmor 配置文件

你想要保护的每个应用程序都需要一个配置文件，可以由`apparmor-profiles`或`apparmor-profiles-extra`软件包、应用程序软件包或你自己提供。这些配置文件存储在`/etc/apparmor.d`中。

让我们以安装 nginx web 服务器为例：

```
sudo apt install nginx 
```

如果您浏览`/etc/apparmor.d`目录，您会发现没有 nginx 的配置文件。创建一个默认的：

```
sudo aa-autodep nginx 
```

创建了一个配置文件：`/etc/apparmor.d/usr.sbin.nginx`。这个文件几乎是空的，只包括一些基本规则和变量，称为抽象，以及以下行：

```
/usr/sbin/nginx mr, 
```

`mr`值定义了访问模式：`r`表示读取模式，`m`允许将文件映射到内存中。

让我们强制执行 nginx 的模式：

```
sudo aa-enforce /usr/sbin/nginx 
sudo systemctl restart nginx 
```

nginx 将无法启动。前述命令的输出如下：

```
sudo journalctl --identifier audit 
```

这非常明显地指向了 AppArmor：

```
sudo journalctl -k | grep audit 
```

要解决问题，请为此配置文件设置投诉模式。这样，它不会强制执行策略，但会对安全策略的每个违规行为进行投诉：

```
sudo aa-complain /usr/sbin/nginx 
sudo systemctl start nginx 
```

通过浏览器或实用程序（例如`curl`）发出`http`请求：

```
curl http://127.0.0.1 
```

下一步是扫描“日志文件”并批准或拒绝每个操作：

```
sudo aa-logprof 
```

非常仔细地阅读并使用箭头键选择正确的选项（如果需要）：

![配置 nginx 配置文件](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/hsn-linux-adm-az/img/B15455_06_21.jpg)

###### 图 6.21：配置 nginx 配置文件

**LXC**（**Linux 容器**）是一种容器技术，我们只是在为 web 服务器配置配置文件。似乎修复 DAC 的问题是一个不错的选择：

![使用 DAC 配置 web 服务器的配置文件](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/hsn-linux-adm-az/img/B15455_06_22.jpg)

###### 图 6.22：修复 nginx 的 DAC

审计建议一个新模式：`w`表示对`/var/log/nginx/error.log`文件的写访问。

此外，您可以阻止访问以下目录：

+   对`/etc/ssl/openssl.conf`的读访问。这是一个困难的问题，但是`ssl`的抽象听起来是正确的。

+   对`/etc/nginx/nginx.conf`的读访问。同样，不是一个容器，因此文件的所有者必须是 OK 的。

+   一般来说，文件的所有者是一个不错的选择。

现在，是时候保存更改并重试了：

```
sudo aa-enforce /usr/sbin/nginx 
sudo systemctl restart nginx
curl http://127.0.0.1 
```

一切似乎现在都运行正常，至少对于对一个简单网站的请求。正如您所看到的，这主要是基于合理的猜测。另一种选择是深入研究所有建议的抽象。

创建的文件`/etc/apparmor.d/usr.sbin.nginx`相对容易阅读。它以应该对每个配置文件可用的所有可调整变量开始：

```
#include <tunables/global> 
```

文件之后是其他抽象，比如以下内容：

```
#include <abstractions/nameservice 
```

要知道他们在做什么，只需查看文件。例如，`/etc/apparmor.d/abstractions/nameservice`文件中列出了以下内容：

```
/usr/sbin/nginx flags=(complain) { 
 #include <abstractions/base> 
 #include <abstractions/nameservice> 
 #include <abstractions/openssl> 
 #include <abstractions/web-data> 
```

#### 注意

许多程序希望执行类似名称服务的操作，例如按名称或 ID 查找用户、按名称或 ID 查找组，以及按名称或 IP 查找主机。这些操作可以通过 DNS、NIS、NIS+、LDAP、hesiod 和 wins 文件执行。在这里允许所有这些选项。

下一节是关于 Posix 功能的；有关更多信息，请参阅`man 7 capabilities`：

```
capability dac_override, 
```

最后一节是权限；有关完整列表，请参阅`man 5 apparmor.d`：

```
/var/log/nginx/error.log w, 
 owner /etc/nginx/modules-enabled/ r, 
 owner /etc/nginx/nginx.conf r, 
 owner /run/nginx.pid w, 
 owner /usr/lib/nginx/modules/ngx_http_geoip_module.so mr, 
 owner /usr/share/nginx/modules-available/mod-http-geoip.conf r, 
 owner /usr/share/nginx/modules-available/mod-http-image-filter.conf r, 
 owner /var/log/nginx/access.log w, 
} 
```

特别是在开始使用`aa-logprof`时，可能会有点压倒性。但是配置文件并不难阅读；每个选项都在两个 man 页面中，并且包含的抽象都有注释进行了记录。

## firewalld 和 systemd

在*第五章*，*高级 Linux 管理*中，systemd 被介绍为系统和服务管理器。在 systemd 中，有几个选项可以为您的守护进程和文件系统添加额外的保护层。

老实说，我们认为在 Azure 网络安全组之上使用 Azure 防火墙确实是有道理的。它易于设置，提供集中管理，并且几乎不需要维护。它在 VM、虚拟网络甚至不同的 Azure 订阅之间提供安全性。

#### 注意

如果您想使用这个防火墙，还会有额外的费用。但是 Linux 防火墙不会产生任何费用，因为它是安装在您的机器上的安全措施。

在 Azure 防火墙和 Linux 防火墙之间的选择取决于许多因素：

+   成本

+   VM 和应用程序的部署和编排

+   不同的角色：是否有一个管理员负责一切？

希望在介绍了 Linux 防火墙实现之一后，可以清楚地了解 Linux 防火墙绝不是 Azure 防火墙的完全替代品。它只能为 VM 的传入流量提供安全性，是的，也可以配置此防火墙来阻止传出流量，但这相当复杂。另一方面，如果它配置在 Azure 网络安全组之上，在许多情况下，这已经足够了。

Linux 有不同类型的防火墙解决方案，包括 firewalld 和 iptables。在本书中，我们将遵循 firewalld，因为它具有可用的配置选项和流行度。请确保已安装 firewalld 软件，并且已从系统中删除其他防火墙软件，以避免冲突。在基于 RHEL/CentOS 的发行版中，这已经是这样。在 Ubuntu 中，使用以下命令：

```
sudo apt remove ufw 
sudo apt install firewalld 
```

在基于 SUSE 的发行版中，使用以下命令：

```
sudo zypper install susefirewall2-to-firewalld 
sudo susefirewall2-to-firewalld -c 
```

Linux 有多种防火墙实现；其中一些甚至是为特定发行版开发的，比如 SuSEfirewall2。在本章中，我们将介绍 firewalld，它在每个发行版上都可用。

firewalld 由一个管理防火墙所有组件的守护程序组成：

+   区域

+   接口

+   来源

+   iptables 和 ebtables 的直接规则（本书未涉及）

firewalld 利用内核模块：iptables/IP6 表用于 IPv4 和 IPv6 流量，ebtables 用于过滤通过 Linux 桥接的网络流量。在较新的发行版中，比如 RHEL 8，使用 `nftables` 模块。

要配置 firewalld 规则，有一个命令行实用程序可用：`firewall-cmd`。规则可以是运行时的或持久的。这种行为有两个重要的原因：这样就不需要重新加载所有规则，意味着临时的安全风险。您可以动态添加和删除规则。如果您犯了一个错误，因此无法再次登录，只需重新启动作为一个快速解决方案。我们还可以使用 `systemd-run --oncalendar` 命令创建一个定时任务，执行 `firewall-cmd --reload`，这是一个更好的解决方案：

```
sudo systemd-run --on-calendar='2018-08-20 13:00:00' \ 
  firewall-cmd --reload  

sudo systemctl list-timers 
```

如果防火墙规则正确（并且您没有被锁定），不要忘记停止和禁用计时器。

您还可以使用编排工具配置守护程序，这些工具与守护程序通信或将 XML 文件推送到主机。

#### 注意

端口仅对连接到虚拟机网络的虚拟机开放，除非您在网络安全组中打开了端口！

重要的是要知道 Azure Service Fabric（基础设施）将根据需要向防火墙配置添加额外规则。建议不要删除这些规则，因为它们很重要，因为它们被 Azure 平台使用。如果您使用 `journalctl` 命令在日志数据库中搜索，就可以看到这一点：

```
sudo journalctl | grep "Azure fabric firewall"
```

使用 `iptables-save` 命令查看所有活动防火墙规则，或者如果您的发行版使用 `nftables`：

```
sudo nft list ruleset
```

### firewalld 区域

firewalld 的最重要的概念之一是区域。区域包括默认规则（称为目标）、网络接口或网络源，以及其他服务、端口、协议和丰富规则。

只有在网络接口连接到接口或网络源时，区域才处于活动状态。

要列出可用的区域，请使用以下命令：

```
sudo firewall-cmd --get-zones
```

这些区域配置在 `/usr/lib/firewalld/zones` 中。您不应该对这些文件进行更改。新区域或对区域的更改将写入 `/etc/firewalld/zones` 目录。

默认区域是公共区域：

```
sudo firewall-cmd --get-default-zone
```

要列出公共区域的区域配置，请使用以下命令：

```
sudo firewall-cmd --zone public --list-all
```

区域配置如下所示：

```
public 
  target: default 
  icmp-block-inversion: no 
  interfaces: 
  sources: 
  services: ssh dhcpv6-client 
  ports: 
  protocols: 
  masquerade: no 
  forward-ports: 
  source-ports: 
  icmp-blocks: 
  rich rules: 
```

公共区域的目标策略是 `default`，这意味着默认情况下会阻止所有传入的东西，除非配置了服务、端口和协议。

该区域的相应 `/usr/lib/firewalld/zones/public.xml` 文件如下：

```
<?xml version="1.0" encoding="utf-8"?> 
<zone> 
 <short>Public</short> 
 <description>For use in public areas. You do not trust the other computers on networks to not harm your computer. Only selected incoming connections are accepted.</description> 
 <service name="ssh"/> 
 <service name="dhcpv6-client"/> 
</zone> 
```

还有用于配置伪装和端口转发的选项。丰富规则是高级防火墙规则，如`firewalld.richlanguage`手册中所述。

执行`man firewalld.richlanguages`，如下截图所示：

![`man firewalld.richlanguages`命令的输出](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/hsn-linux-adm-az/img/B15455_06_23.jpg)

###### 图 6.23：`man firewalld.richlanguages`命令的输出

根据您使用的发行版，可能会有其他服务名称。例如，如果您使用的是 RHEL 8，您可能会看到`cockpit`列为服务。`cockpit`是用于管理 RHEL 机器的基于 Web 的界面。

您可能已经注意到，在公共区域中，它说`target: default`。目标是默认行为。可能的值如下：

+   默认：不执行任何操作，接受每个 ICMP 数据包，并拒绝其他所有内容。

+   `%%REJECT%%`：这通过 ICMP 协议向客户端发送拒绝响应。

+   `DROP`：这会发送 TCP SYN/ACK，就像在打开端口上一样，但所有其他流量都会被丢弃。没有 ICMP 消息通知客户端。

+   接受：接受一切。

在 Ubuntu 中，默认情况下，没有附加网络接口。请不要在附加接口之前重新启动虚拟机！执行以下命令：

```
sudo firewall-cmd --add-interface=eth0 --zone=public 

sudo firewall-cmd --add-interface=eth0 --zone=public --permanent 

sudo firewall-cmd --zone=public --list-all 
```

如果修改区域，则文件将从`/usr/lib/firewalld/zones`复制到`/etc/firewalld/zones`。下一次修改将创建一个带有`.old`文件扩展名的区域备份，并创建一个包含修改内容的新文件。

### firewalld 服务

服务是一个以应用为中心的配置，允许一个或多个端口。要接收可用服务的列表，请使用以下命令：

```
sudo firewall-cmd --get-services 
```

如果要添加服务，例如 MySQL，请执行以下命令：

```
sudo firewall-cmd --add-service=mysql --zone=public 

sudo firewall-cmd --add-service=mysql --zone=public \ 
  --permanent 
```

如果要从区域中删除服务，请使用`--remove-service`参数。

服务配置在`/usr/lib/firewalld/services`目录中。同样，您不应该修改这些文件。您可以通过将它们复制到`/etc/firewalld/services`目录中来更改它们或创建自己的服务。

也可以添加单个端口，但一般来说，这不是一个好主意：过一段时间后，您还能记得哪些端口被哪个应用程序使用吗？相反，如果服务尚未定义，请创建自己的服务。

现在，让我们为 Microsoft PPTP 防火墙协议创建一个服务文件，`/etc/firewalld/services/pptp.xml`：

```
<?xml version="1.0" encoding="utf-8"?> 
<service> 
 <short>PPtP</short> 
 <description>Microsoft VPN</description> 
 <port protocol="tcp" port="1723"/> 
</service> 
```

在前面的文件中，您可以看到允许 TCP 端口`1723`。您可以添加尽可能多的端口规则。例如，如果要添加 TCP 端口`1724`，则行项目将如下所示：

```
<port protocol="tcp" port="1724" /> 
```

使用`firewalld-cmd --reload`重新加载防火墙后，服务可用。这还不够：**GRE**（通用路由封装）协议不被允许。要允许此协议，请使用以下命令：

```
sudo firewall-cmd --service=pptp --add-protocol=gre \ 
  --permanent 

sudo firewall-cmd --reload 
```

这将向服务文件添加以下行：

```
<protocol value="gre"/>  
```

您可以使用`--remove-protocol`参数删除协议。

### firewalld 网络源

只有在网络接口连接到它或网络源时，区域才处于活动状态。将网络接口添加到拒绝区域是没有意义的。拒绝区域是所有传入数据包都被丢弃且不回复的地方；但是，允许传出连接。所以，正如我提到的，如果将网络接口添加到拒绝区域，所有传入数据包将被 firewalld 丢弃，这根本没有任何意义。

但是，添加网络源是有意义的。源由一个或多个条目组成：媒体访问控制地址、IP 地址或 IP 范围。

例如，出于任何原因，假设您想要阻止来自百慕大的所有流量。网站[`ipdeny.com`](http://ipdeny.com)可以为您提供 IP 地址列表：

```
cd /tmp 
wget http://www.ipdeny.com/ipblocks/data/countries/bm.zone 
```

有几种类型的`ipset`。要查看支持的`ipset`类型列表，请执行以下命令：

```
sudo firewall-cmd --get-ipset-types 
```

在我们的场景中，我们希望`hash:net` IP 范围的类型：

```
sudo firewall-cmd --new-ipset=block_bermuda --type=hash:net --permanent 
sudo firewall-cmd --reload 
```

现在，我们可以使用下载的文件向`ipset`添加条目：

```
sudo firewall-cmd --ipset=block_bermuda --add-entries-from-file=/tmp/bm.zone 
sudo firewall-cmd --ipset=block_bermuda --add-entries-from-file=/tmp/bm.zone \ 
  --permanent 
sudo firewall-cmd --reload 
```

最后一步涉及将`ipset`添加为区域的源：

```
sudo firewall-cmd --zone=drop --add-source=ipset:block_bermuda 
sudo firewall-cmd --zone=drop --add-source=ipset:block_bermuda --permanent 
sudo firewall-cmd --reload 
```

丢弃区的目的是在不让客户端知道流量被丢弃的情况下丢弃所有流量。将`ipset`添加到此区域会使其激活，并且来自百慕大的所有流量都将被丢弃：

```
sudo firewall-cmd --get-active-zones 
drop 
 sources: ipset:block_bermuda 
public 
 interfaces: eth0 
```

现在我们知道了 firewalld 的工作原理，以及如何使用区域来保护我们的机器，让我们跳到下一节。

### systemd 安全

如前一章所述，systemd 负责在启动过程中并行启动所有进程，除了那些由内核创建的进程。之后，问题在于按需激活服务等。systemd 单元还可以提供额外的安全层。您可以向单元文件添加多个选项，以使您的单元更加安全。

只需使用`systemctl edit`编辑单元文件并添加安全措施。例如，执行以下命令：

```
sudo systemctl edit sshd 
```

然后，添加以下行：

```
[Service] 
ProtectHome=read-only 
```

保存文件，重新读取`systemctl`配置，并重新启动`sshd`：

```
sudo systemctl daemon-reload 
sudo systemctl restart sshd 
```

现在，使用 SSH 客户端再次登录，并尝试在您的家目录中保存文件。这将失败，因为它是一个只读文件系统：

![无法在家目录中保存文件，因为权限已更改为只读](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/hsn-linux-adm-az/img/B15455_06_24.jpg)

###### 图 6.24：登录失败，因为单元文件被更改为只读

### 限制对文件系统的访问

`ProtectHome`参数是一个非常有趣的参数。以下值可用：

+   `true`：`/home`、`/root`和`/run/user`目录对该单元不可访问，并且对于在该单元内启动的进程来说是空的。

+   `read-only`：这些目录是只读的。

另一个非常相似的参数是`ProtectSystem`：

+   `true`：`/usr`和`/boot`被挂载为只读。

+   `full`：`/etc`被挂载为只读，以及`/usr`和`/boot`。

+   `strict`：整个文件系统是只读的，除了`/proc`、`/dev`和`/sys`。

除了`ProtectHome`和`ProtectSystem`之外，还可以使用以下参数：`ReadWritePaths`来列出目录，`ReadOnlyPaths`和`InaccessiblePaths`。

一些守护进程使用`/tmp`目录进行临时存储。这个目录的问题在于它是可读的。`PrivateTmp=true`参数为进程设置了一个新的临时文件系统，只能被该进程访问。

还有与内核相关的参数：`ProtectKernelModules=true`参数使加载模块变得不可能，`ProtectKernelTunables=true`参数使使用`sysctl`命令或手动在`/proc`和`/sys`目录结构中更改内核参数变得不可能。

最后，`SELinuxContext`和`AppArmorProfile`参数强制了单元的上下文。

### 限制网络访问

systemd 也可以用于限制网络访问，例如可以列出可以允许或拒绝的 IP 地址。在版本 235 之后的新版本 systemd，例如 Ubuntu 18.04、SLE 15 SP1 和 RHEL 8，还支持 IP 账户和访问列表来限制网络访问。

`IPAccounting=yes`允许一个单元收集和分析网络数据。要查看结果，可以使用`systemctl`命令：

```
systemctl show <service name> -p IPIngressBytes \ 
 -p IPIngressPackets \ 
 -p IPEgressBytes -p IPEgressPackets 
```

与每个参数一样，您也可以在`systemd-run`中使用它：

![使用 systemd-run 和 systemctl 命令收集和分析网络数据](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/hsn-linux-adm-az/img/B15455_06_25.jpg)

###### 图 6.25：使用 systemd-run 和 systemctl 收集和分析网络数据

您还可以使用`IPAddressDeny`来拒绝 IP 地址或 IP 范围。可以使用`IPAddressAllow`进行例外。甚至可以在系统范围内拒绝所有内容，并在每个服务的基础上进行白名单处理：

```
sudo systemctl set-property sshd.service IPAddressAllow=any 
sudo systemctl set-property waagent.service IPAddressAllow=10.0.0.1 
```

#### 注意

如果您使用的是 Ubuntu，服务名称是`walinuxagent`。

```
sudo systemctl set-property system.slice IPAddressAllow=localhost  
sudo systemctl set-property system.slice IPAddressAllow=10.0.0.1  
sudo systemctl set-property system.slice IPAddressDeny=any  
```

更改保存在`/etc/systemd/system.control`目录结构中：

![更改保存在 system.control 目录中](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/hsn-linux-adm-az/img/B15455_06_26.jpg)

###### 图 6.26：保存更改在 system.control 目录中

以下是一些备注：

+   当然，您必须将 IP 范围更改为您的虚拟子网，并且必须允许对您的子网的第一个 IP 地址进行访问，以供 Azure 代理和网络服务使用，例如**DHCP**（动态主机配置协议）。

+   将 SSH 访问限制为您自己网络的 IP 地址也是一个很好的主意。

+   非常仔细地查看 systemd 日志，以找出是否需要打开更多端口。

systemd 访问列表功能可能不像 firewalld 那样先进，但它是应用级别限制的一个很好的替代方法（在守护程序的配置文件中使用 hosts allow 指令，或者对于使用 libwrap 支持编译的应用程序，使用`/etc/hosts.allow`和`/etc/hosts.deny`）。在我们看来，在 Azure 中，您不需要更多。如果所有发行版都有最新版本的 systemd 就好了。

#### 注意

我们不会在本书中涵盖`libwrap`库，因为越来越多的应用程序不再使用这个选项，一些供应商，如 SUSE，正忙于删除对这个库的完全支持。

## Azure 中的身份和访问管理 - IAM

到目前为止，我们一直在讨论如何在 Linux 中管理安全性。由于我们在 Azure 中部署，Azure 还为我们的 Linux VM 提供了一些额外的安全性。例如，之前我们讨论了 Azure 防火墙和网络安全组，这有助于控制流量，限制对不需要的端口的访问，并过滤来自未知位置的流量。除此之外，Azure 还有其他服务，如 Azure AD 域服务，它将允许您将 Linux VM 加入到域中。最近，微软推出了一项选项，允许 Azure AD 用户登录 Linux VM。这样做的好处是您不必使用其他用户名；相反，您可以使用 Azure AD 凭据。让我们更仔细地了解这些服务，并了解如何利用它们来增加我们的 Linux VM 的安全性。

### Azure AD 域服务

到目前为止，我们一直在讨论 Linux VM 内部可以做什么。由于我们在 Azure 上，我们应该利用**Azure AD 域服务**，通过它可以将 Linux 机器加入域并强制执行组织的策略。Azure AD 域服务是一个作为服务的域控制器，为您提供 DNS 服务和身份管理。集中身份管理始终是安全解决方案的重要组成部分。它使用户能够访问资源。除此之外，您还可以强制执行策略并启用多因素身份验证。

在这一部分，我们将重点讨论如何设置服务和加入域。

### 设置 Azure AD 域服务

设置 Azure AD 域服务的最简单方法是通过 Azure 门户。在左侧栏中，选择**创建资源**并搜索*Domain Services*。选择**Azure AD 域服务**，然后单击**创建**按钮。

在向导中，您将被要求进行一些设置：

+   .onmicrosoft.com。对于本书的目的，这就足够了。

+   **虚拟网络**：创建一个新的虚拟网络和一个新的子网是一个好主意。标签并不重要。

+   AAD DC Administrators。要能够使用用户加入域，用户必须是该组的成员，在 Azure 门户中的左侧栏中使用**Active Directory**部分。

现在您已经准备好部署服务了。这将需要一些时间；根据我的个人经验，可能需要 20 到 30 分钟。

完成后，转到左侧栏中的**虚拟网络**部分，并输入新创建的虚拟网络。您将找到两个新创建的网络接口及其 IP 地址。您将需要这些信息，所以记下来。

在这个虚拟网络中创建一个新的子网是一个好主意，但不是必需的。

### Linux 配置

您必须在与部署 Azure AD 目录服务的相同虚拟网络或对等网络中部署 Linux VM。正如所述，最好将其附加到另一个子网。在这里，我们不遵循安全 LDAP。

### 主机名

使用`hostnamectl`实用程序将主机名更改为正确的`fqdn`：

```
sudo hostnamectl set-hostname ubuntu01.frederikvoslinvirt.onmicrosoft.com 
```

然后编辑`/etc/hosts`文件。添加以下条目：

```
127.0.0.1 ubuntu01.frederikvoslinvirt.onmicrosoft.com ubuntu01 
```

### DNS 服务器

在 Azure 门户的左侧栏中，转到**虚拟网络**，并导航到 Azure AD 域服务网络接口所在的子网。选择**DNS 服务器**并使用自定义选项设置 Azure AD 域服务网络接口的 IP 地址。通过这样做，每当需要主机名的 DNS 解析时，它将指向 Azure AD 域服务。

或者，如果您的 Azure AD 域服务是新部署的，在 Azure 门户的**概述**窗格中，它将要求您更改 DNS 服务器。只需点击**配置**按钮即可将虚拟网络中的 DNS 服务器更改为指向 Azure AD 域服务。

通常，重新启动 VM 中的网络应该就足够了，但最好现在重启。有时，旧设置和新设置都会生效。

在 RHEL、Ubuntu 和 SUSE 中，查看`/etc/resolv.conf`文件的内容以验证结果。然后，查看`eth0`的设置。

### 安装依赖项

有一些重要的组件和依赖项是必需的，才能使用 Azure AD 域服务：

+   用于授权的 Kerberos 客户端

+   SSSD，负责配置和利用功能，如使用和缓存凭据的后端

+   Samba 库，以兼容 Windows 功能/选项

+   一些用于加入和管理域的实用程序，如`realm`，`adcli`和`net`命令

安装必要的软件以便能够加入域。

对于基于 RHEL/CentOS 的发行版，执行以下命令：

```
sudo yum install realmd sssd krb5-workstation krb5-libs samba-common-tools 
```

在 Ubuntu 中，执行以下命令：

```
sudo apt install krb5-user samba sssd sssd-tools libnss-sss libpam-sss realmd adcli 
```

在 SLE/OpenSUSE LEAP 中，依赖项将由 YaST 处理。

### 加入域 - Ubuntu 和 RHEL/CentOS

在 Ubuntu 和基于 RHEL/CentOS 的发行版中，`realm`实用程序可用于加入域。首先，发现域：

```
sudo realm discover <your domain> 
```

输出应类似于以下内容：

![在 Ubuntu 和基于 RHEL/CentOS 的发行版中发现域](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/hsn-linux-adm-az/img/B15455_06_27.jpg)

###### 图 6.27：发现域

现在，您已经准备好加入域：

```
sudo realm join <your domain> -U <username@domain>
```

使用您之前添加的用户名作为 Azure AD 域服务管理员组的成员。如果收到`未安装必要的软件包`的消息，但您确定已安装，可以在`realm`命令中添加`--install=/`参数。

要验证结果，请执行以下命令：

```
sudo realm list
```

输出应类似于以下内容：

![使用 realm 实用程序加入域](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/hsn-linux-adm-az/img/B15455_06_28.jpg)

###### 图 6.28：加入域

您应该能够执行以下操作：

```
id <user>@<domain>
su <user>@<domain>
```

使用此用户远程登录`ssh`。

#### 注意

如果这不起作用，并且加入成功，请重新启动 VM。

### 加入域 - SUSE

在 SUSE SLE 和 LEAP 中，加入域的最佳方法是使用 YaST。

启动 YaST 实用程序：

```
sudo yast
```

从 YaST 主窗口开始**用户登录管理**模块，然后点击**更改设置**。点击**加入域**并填写域名。之后，您将能够成功加入域。如果需要，将安装依赖项。

将出现一个新窗口来管理域用户登录。您至少需要以下内容：**允许域用户登录**和**创建主目录**。在 Azure AD 域服务中，其他所有选项目前都不可能。

YaST 将为您在 shell 上提供一个类似 GUI 的彩色界面，使用它可以将机器加入域。运行`sudo yast`后，您将会得到如下所示的屏幕。从列表中，使用箭头键选择**网络服务**，然后选择**Windows 域成员资格**：

![运行 sudo yast 命令查看 YaST 界面](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/hsn-linux-adm-az/img/B15455_06_29.jpg)

###### 图 6.29：在 Shell 上的 YaST 界面

最好的部分是，如果缺少任何依赖项，YaST 将提示您安装它们，因此请继续并完成依赖项安装。安装完成后，您可以输入您的域名，一旦保存，您将被提示输入用户名和密码，如下面的屏幕截图所示：

![在 YaST 中提供凭据以将机器注册到 Azure AD 域服务](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/hsn-linux-adm-az/img/B15455_06_30.jpg)

###### 图 6.30：提供注册机器的凭据

以`user@domain`格式输入您的凭据，然后输入您的密码。完成流程后，SUSE 机器将连接到 Azure AD 域服务并注册您的机器。如果加入成功，您将在屏幕上收到一条消息，如下所示：

![提示成功加入域的消息提示](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/hsn-linux-adm-az/img/B15455_06_31.jpg)

###### 图 6.31：域加入成功

您可以通过使用`su`命令将当前用户切换为您的 AD 用户名来进行验证，如下面的屏幕截图所示：

![使用 su 命令验证域加入](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/hsn-linux-adm-az/img/B15455_06_32.jpg)

###### 图 6.32：验证域加入

最后，我们已经成功将我们的 Linux 机器加入了 Azure AD 域服务。最近，微软添加了对 Linux VM 进行 Azure AD 登录的支持，无需将机器加入域。将在下一节中讨论安装代理以完成授权。

### 使用 Azure AD 凭据登录到 Linux VM

Azure AD 还可以实现另一种形式的身份管理。这是一个完全不同的身份管理系统，没有 LDAP 和 Kerberos，正如前一节所讨论的。在 Linux 中，Azure AD 将允许您使用 Azure 凭据登录到您的 VM，但不支持应用程序级别。在撰写本书时，此功能仍处于预览阶段。此外，此功能在 SUSE 中不可用。

要使用 Azure AD，您必须部署一个 VM 扩展，例如使用 Azure CLI：

```
az vm extension set \ 
    --publisher Microsoft.Azure.ActiveDirectory.LinuxSSH \ 
    --name AADLoginForLinux \ 
    --resource-group myResourceGroup \ 
    --vm-name myVM 
```

之后，您必须为您的 Azure AD 帐户分配一个角色，可以是`虚拟机管理员登录`（具有 root 权限）或`虚拟机用户登录`（非特权用户）角色，并将范围限制在此 VM 上：

```
az role assignment create \ 
    --role "Virtual Machine Administrator Login" \ 
    --assignee <ad user name> \ 
    --scope <your vm> 
```

在这里，您可以在订阅级别设置范围，`--scope /subscriptions/<subcription ID>`。通过这样做，该角色将被订阅中的所有资源继承。

如果您只想对特定的 VM 进行细粒度访问控制，可以执行以下命令（在 PowerShell 中）：

```
$vm = Get-AzVM –Name <VM Name> -ResourceGroup <resource group> 
```

`$vm.Id` 将为您提供虚拟机的范围。

在 bash 中，执行以下命令：

```
 az vm show --name<name> --resource-group <resource group> --query id 
```

此命令将查询虚拟机的 ID，并且是角色分配的范围。

您可以使用您的 AD 凭据登录：

```
ssh <ad user>@<ad domain>@<ip address> 
```

最后，您将能够看到您正在使用 Azure AD 凭据登录到 Linux VM。

### Azure 中的其他安全解决方案

在本章中，我们已经讨论了如何提高 Linux 安全级别并整合某些 Azure 服务来提高安全性。话虽如此，可以用于提高安全性的 Azure 服务列表非常长。以下是其中一些重点：

+   Azure AD 托管身份：使用此功能，您可以为虚拟机创建托管身份，用于对支持 Azure AD 身份验证的任何服务进行身份验证。以前，此服务被称为**托管服务身份**（**MSI**），现在称为**Azure 资源的托管身份**。

+   密钥保管库：可用于安全存储密钥。例如，在 Azure 磁盘加密中，密钥将存储在密钥保管库中，并在需要时进行访问。

+   Azure 磁盘加密：磁盘加密将帮助您加密操作系统磁盘以及数据磁盘，从而为存储的数据提供额外的安全性。

+   RBAC：Azure 中的 RBAC 允许您为虚拟机分配细粒度权限。Azure 中有许多内置角色可用，您可以根据安全需求分配其中一个。此外，您可以创建自定义 RBAC 角色以提供更细粒度的权限。

+   **Azure 安全中心**（**ASC**）：ASC 是一个统一的基础设施安全管理系统，旨在 consolida 您的安全。

+   Azure 策略客户端配置：这可用于审核 Linux 虚拟机内部的设置。在*第八章* *探索持续配置自动化*中已经详细讨论过。

我们建议您阅读微软文档，以更好地了解这些服务如何在您的环境中使用，以加强整体安全性。

## 总结

安全是当今一个非常重要的话题。关于这个主题已经写了许多报告、书籍等。在本章中，我们介绍了 Linux 中增加安全级别的几种选项。所有这些选项都是在 Azure 通过网络安全组提供的基本安全性之上的。它们相对容易实施，并将产生重大影响！

中央身份管理不仅是为用户提供访问虚拟机的一种方式，也是减少安全风险的一部分。Azure AD 域服务通过 LDAP 和 Kerberos 为所有支持这些协议的操作系统和应用程序提供身份管理解决方案。

*第八章，探索持续配置自动化*，将涵盖自动化和编排。请注意，本章涵盖的所有安全措施都可以轻松进行编排。编排使得中央配置管理成为可能。其一个重要优势是防止错误和难以管理的配置。因此，即使编排也是您安全计划的一部分！

如果您要创建自己的虚拟机，尤其是如果您要构建自己的镜像，那将是很好的。我们将在下一章讨论如何构建自己的镜像。此外，我们将考虑推送这些镜像和在您的环境中部署它们的安全方面。

## 问题

1.  如果要实施 firewalld，有哪些配置此防火墙的方法？

1.  使用`--permanent`参数的`firewall-cmd`的原因是什么？

1.  还有哪些选项可用于限制网络访问？

1.  解释 DAC 和 MAC 之间的区别。

1.  在 Azure 上运行的 VM 中使用 Linux 安全模块为什么很重要？

1.  哪个 MAC 系统适用于哪个发行版？

1.  AppArmor 和 SELinux 之间的主要区别是什么？

1.  在依赖和 Linux 配置方面，加入 Azure AD 域服务的要求是什么？

## 进一步阅读

与上一章类似，我强烈建议您访问*第十一章*，“故障排除和监视工作负载”，以了解有关 Linux 日志记录的信息，因为通常`systemctl status`命令提供的信息不足够。我也已经指向了 Lennart Poettering 的博客和 systemd 网站。

对于 Linux 安全性，您可以开始阅读 Donald A. Tevault 的书*掌握 Linux 安全和加固*。本章涵盖的许多主题以及其他许多主题都有详细的解释。

firewalld 守护程序有一个项目网站，[`firewalld.org`](https://firewalld.org)，有博客和优秀的文档。对于较旧的发行版，Arch Linux 的维基是学习更多的好地方：[`wiki.archlinux.org/index.php/iptables`](https://wiki.archlinux.org/index.php/iptables)。由于 iptables 被 firewalld 使用，所以在深入研究`firewalld.richlanguage`的 man 页面之前，这是一个很好的开始。

有关 SELinux 的所有细节都在 Red Hat 提供的指南中有所涵盖：[`access.redhat.com/documentation/en-us/red_hat_enterprise_linux/7/html/selinux_users_and_administrators_guide/`](https://access.redhat.com/documentation/en-us/red_hat_enterprise_linux/7/html/selinux_users_and_administrators_guide/)虽然有点过时，但观看这个关于 SELinux 的 Red Hat 峰会的 YouTube 视频是一个很好的主意：[`www.youtube.com/watch?v=MxjenQ31b70`](https://www.youtube.com/watch?v=MxjenQ31b70)。

然而，要找到关于 AppArmor 的好信息更加困难。在[`gitlab.com/apparmor/apparmor/wikis/Documentation`](https://gitlab.com/apparmor/apparmor/wikis/Documentation)上有项目文档可用，Ubuntu 服务器指南是一个很好的起点。这可以在[`help.ubuntu.com/lts/serverguide/apparmor.html.en`](https://help.ubuntu.com/lts/serverguide/apparmor.html.en)找到。


# 第七章：部署您的虚拟机

在 Azure 中部署单个虚拟机（VM）很容易，但一旦您想以一种单一的、可重复的方式部署更多的工作负载，您就需要某种自动化。

在 Azure 中，您可以使用 Azure 资源管理器（ARM）使用模板配置文件部署 VM，还可以使用 Azure CLI、PowerShell、Ruby 和 C#。本章后面将讨论用于创建 VM 映像的第三方工具，如 Packer 和 Vagrant。

所有这些部署方法或映像创建方法都使用 Azure 中的映像，但也可以创建自己的自定义 VM 并使用自定义映像。

在进入所有可能选项的配置之前，了解不同的部署选项以及为什么应该或不应该使用它们是很重要的。首先，您必须先问自己几个问题：

+   您何时打算部署您的应用程序？

+   工作负载的哪些部分应该是可重复的？

+   工作负载的配置的哪些部分应该在部署期间完成？

所有这些问题将在本章结束时得到解答。以下是本章的主要要点：

+   我们将讨论 Azure 中的自动化部署选项。

+   我们将看到如何使用 Azure CLI 和 PowerShell 自动化部署。

+   我们将介绍 Azure ARM 模板用于部署以及它们如何可以被重用于重新部署。

+   将讨论 VM 映像创建工具，如 Packer 和 Vagrant。

+   最后，我们将解释如何使用自定义映像并将我们自己的 VHD（虚拟硬盘）带入 Azure。

## 部署场景

介绍中提到的三个问题非常重要；这些可能因公司、应用程序和开发阶段而异。以下是一些部署场景的示例：

+   应用程序是内部开发的，甚至可能是在您的本地计算机上。完成后，应用程序将在 Azure 中部署。更新将应用于正在运行的工作负载。

+   这是相同的情景，但现在更新将通过部署新的 VM 来完成。

+   应用程序由另一个供应商提供。

这三个示例非常常见，可能会影响您想要部署工作负载的方式。

### 你需要什么？

在跳入部署之前，您应该知道您需要什么，或者换句话说，需要哪些资源才能使您的应用程序正常工作。此外，Azure 中的所有内容都有限制和配额。一些限制是硬性的，有些可以通过联系微软支持来增加。要查看完整的 Azure 限制和配额列表，请访问[`docs.microsoft.com/en-us/azure/azure-subscription-service-limits`](https://docs.microsoft.com/en-us/azure/azure-subscription-service-limits)。

在部署之前，我们需要计划并确保我们的订阅限制不会阻碍我们的项目。如果有限制或限制，请联系微软支持并增加配额。但是，如果您正在使用免费试用，配额请求将不会被批准。您可能需要将部署移至您有足够配额来完成部署的地区。这些是我们将要部署的关键资源：

+   一个资源组

+   一个存储账户（未管理）或托管磁盘

+   网络安全组

+   一个虚拟网络

+   虚拟网络的子网

+   连接到 VM 的网络接口

关于 VM，您需要指定并考虑以下内容：

+   VM 大小

+   存储

+   VM 扩展

+   操作系统

+   初始配置

+   应用程序的部署

如果您看一下这些列表，您可能会想知道自动化部署是否是必要的或必需的。答案并不容易找到。让我们再次看看这些情景，并尝试找到答案。我们可以决定做以下事情：

1.  创建一个 PowerShell 或 Bash 脚本来准备工作负载的 Azure 环境

1.  创建第二个脚本来部署基于 Azure 中的一个提供的 VM，并使用 Azure VM 扩展来配置初始配置

1.  使用像 Yum 这样的软件管理器部署应用程序

决定这样做没有错；这可能是您的最佳解决方案！然而，不管您喜不喜欢，都有依赖关系：

+   您的操作系统是基于一个镜像部署的。这个镜像是由发布者提供的。如果镜像更新到您的应用程序不支持的版本会发生什么？

+   这个镜像中已经完成了多少初始配置？还需要多少，谁控制这个镜像？

+   这个镜像是否符合您的安全策略？

+   如果出于任何原因您想离开 Azure，您能把您的应用程序迁移到其他地方吗？

## Azure 中的自动化部署选项

在这个漫长的介绍之后，是时候看一下功能选项了，这些选项使得自动化部署您的工作负载成为可能：

+   脚本编写

+   Azure 资源管理器

+   Ansible

+   Terraform

我们将在*第八章，探索持续配置自动化*中讨论 Ansible 和 Terraform。

### 脚本编写

自动化可以通过脚本完成。在 Azure 中，有许多由 Microsoft 支持的选项：

+   使用 Azure CLI 的 Bash

+   带有 Az 模块的 PowerShell

+   Python，完整的 SDK 可在[`docs.microsoft.com/en-us/azure/python/python-sdk-azure-install`](https://docs.microsoft.com/en-us/azure/python/python-sdk-azure-install )找到

+   Ruby，预览 SDK 可在[`azure.microsoft.com/en-us/develop/ruby`](https://azure.microsoft.com/en-us/develop/ruby )找到

+   Go，完整的 SDK 可在[`github.com/Azure/azure-sdk-for-go`](https://github.com/Azure/azure-sdk-for-go )找到

+   还有可用于 Node.js 的库

此外，您还可以使用 Java 和 C#等编程语言。也有社区项目；例如，[`github.com/capside/azure-sdk-perl`](https://github.com/capside/azure-sdk-perl) 是一个构建 Perl 的完整 Azure SDK 的尝试。

所有语言都是有效的选择；选择您已经熟悉的语言。请注意，Ruby SDK 在撰写本书时处于预览状态。在预览状态下，语法可能会发生变化。

脚本编写特别适用于准备 Azure 环境。您还可以使用脚本来部署您的 VM，并且甚至可以使用 VM 扩展来包含初始配置。这是否是一个好主意取决于您的脚本能力、操作系统的基本镜像以及其中安装的软件版本。

使用脚本的最大反对意见是编写脚本很耗时。以下是一些可以帮助您高效编写脚本的提示：

+   尽可能使用多个变量。这样，如果您需要在脚本中进行更改，您只需要更改变量的值。

+   在循环中使用可识别的变量名，而不是像`for i in`这样的东西。

+   特别是对于更大的脚本，声明可以重复使用的函数。

+   有时，将变量（例如提供身份验证的变量）和函数放在单独的文件中是有意义的。通常一个脚本执行一个任务是个好主意。

+   在您的代码中包含修改的时间戳，或者更好的是使用 Git 这样的版本控制系统。

+   包含测试。例如，只有在资源不存在时才创建此资源。使用可读的退出代码。如果脚本无法部署资源，请使用类似*无法创建$resource*的内容，这样运行脚本的人就会明白脚本无法创建资源。

+   包含足够的注释。如果您需要在一段时间后调试或重用脚本，您仍然会知道它的作用。不要忘记在标题中包含描述。

+   在布局上花一些时间；使用缩进使代码易读。使用两个空格进行缩进，而不是制表符！

现在是举一个简短示例的时候了。这个示例将让您了解在部署虚拟机之前如何创建脚本来提供 Azure 所需的东西。

首先，声明变量。您也可以将变量添加到一个文件中，并让 PowerShell 加载这些变量。建议将它们存储在同一个脚本中，这样您可以随时返回并在需要时更新它们。

```
#Declare Variables
$myResourceGroup = "LinuxOnAzure" 
$myLocation = "West Europe" 
$myNSG = "NSG_LinuxOnAzure" 
$mySubnet = "10.0.0.0/24"
$myVnet= "VNET_LinuxOnAzure"
```

接下来，编写一个脚本来创建一个资源组。如果资源已经存在，脚本将跳过创建部分。如前所述，添加注释是使脚本可读的最佳实践，因此请使用`#`标记的注释，以便您了解代码块的作用：

```
# Test if the Resource Group already exists, if not: create it. 
Get-AzResourceGroup -Name $myResourceGroup -ErrorVariable notPresent -ErrorAction SilentlyContinue | out-null  
if ($notPresent) 
  { 
    # ResourceGroup doesn't exist, create it: 
    New-AzResourceGroup -Name $myResourceGroup -Location $myLocation     
    Write-Host "The Resource Group $myResourceGroup is created in the location $myLocation" 
  }  
else 
  { 
    Write-Host "The Resource Group $myResourceGroup already exists in the location $myLocation" 
  }
```

创建虚拟网络并配置子网：

```
#Test if the vnet name not already exists: 
Get-AzVirtualNetwork -Name $myVnet -ResourceGroupName $myResourceGroup -ErrorVariable notPresent -ErrorAction SilentlyContinue | out-null 
if ($notPresent) 
  { 
    # vnet doesn't exist, create the vnet

    $virtualNetwork = New-AzVirtualNetwork -ResourceGroupName $myResourceGroup -Location $myLocation -Name $myVnet -AddressPrefix 10.0.0.0/16
    # add subnet configuration
    $subnetConfig = Add-AzVirtualNetworkSubnetConfig -Name default -AddressPrefix $mySubnet -VirtualNetwork $virtualNetwork
    # Associate the subnet to the virtual network
    $virtualNetwork | Set-AzVirtualNetwork
     Write-Host "The virtual network $myVnet with $mySubnet configured is created in the location $myLocation" 
  }
else 
  { 
    Write-Host "The Resource Group $myVnet already exists in the location $myLocation" 
  }
```

这是创建网络安全组的一个示例：

```
# Create NSG
# Test if the Network Security Group does not already exist:  

Get-AzNetworkSecurityGroup -ResourceGroupName $myResourceGroup -Name $myNSG -ErrorVariable notPresent -ErrorAction SilentlyContinue | out-null 
if ($notPresent) 
{ 
# create the NSG 
$nsg = New-AzNetworkSecurityGroup -ResourceGroupName $myResourceGroup -Location $myLocation -Name $myNSG
# create the rules for SSH and HTTP 
$nsg | Add-AzNetworkSecurityRuleConfig -Name "allow_http" -Description "Allow HTTP" -Access Allow '
    -Protocol "TCP" -Direction Inbound -Priority 1002 -SourceAddressPrefix "*" -SourcePortRange * '
    -DestinationAddressPrefix * -DestinationPortRange 80 
$nsg | Add-AzNetworkSecurityRuleConfig -Name "allow_ssh" -Description "Allow SSH" -Access Allow '
    -Protocol "TCP" -Direction Inbound -Priority 1001 -SourceAddressPrefix "*" -SourcePortRange * '
    -DestinationAddressPrefix * -DestinationPortRange 22 
# Update the NSG.
  $nsg | Set-AzNetworkSecurityGroup
Write-Host "The NSG: $myNSG is configured is created with rules for SSH and HTTP in the resource group $myResourceGroup" 
} 
else 
{ 
Write-Host "The NSG $myNSG already existed in the resource group $myResourceGroup"  
}
```

到目前为止，您应该已经对如何创建脚本和虚拟网络有了一个很好的想法。正如在本节开头提到的，脚本编写并不是自动化部署的唯一手段；还有其他方法。在下一节中，我们将讨论如何使用 Azure 资源管理器模板来自动化部署。

### 使用 Azure 资源管理器进行自动化部署

在*第二章，开始使用 Azure 云*中，我们将**Azure 资源管理器**（**ARM**）定义如下：

“基本上，Azure 资源管理器使您能够使用诸如存储和虚拟机之类的资源。为此，您必须创建一个或多个资源组，以便您可以执行生命周期操作，例如在单个操作中部署、更新和删除资源组中的所有资源。”

从 Azure 门户或使用脚本，您可以做到上述所有的事情。但这只是其中的一小部分。您可以通过 ARM 使用模板部署 Azure 资源。微软提供了数百个快速启动模板，可在[`azure.microsoft.com/en-us/resources/templates`](https://azure.microsoft.com/en-us/resources/templates)找到。

当您通过 Azure 门户创建虚拟机时，甚至在创建之前就可以将该虚拟机下载为模板。如果您参考以下截图，您会发现即使在创建虚拟机之前，我们也有一个下载自动化模板的选项：

![在仪表板中导航以创建并下载虚拟机作为模板](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/hsn-linux-adm-az/img/B15455_07_01.jpg)

###### 图 7.1：将虚拟机下载为模板

如果您点击**下载自动化模板**，您将会看到以下屏幕：

![在模板窗格中添加脚本到库中](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/hsn-linux-adm-az/img/B15455_07_02.jpg)

###### 图 7.2：VM 模板窗格

正如您所看到的，您可以将脚本添加到 Azure 的库中，或者将此文件下载到您的本地计算机。您还将获得一个**部署**选项，通过它您可以更改参数并直接部署到 Azure。

在**脚本**窗格中，Azure 给出了使用 PowerShell 和 CLI 进行部署的链接。

您可以轻松更改参数并部署新的虚拟机，或者重新部署完全相同的虚拟机。这与使用自己的脚本并没有太大的不同，但在开发方面更节省时间。

这并不是您可以使用 ARM 做的唯一事情；您可以配置 Azure 资源的每一个方面。例如，如果您通过 ARM 模板部署网络安全组，您可以像在 Azure 门户或通过 CLI 创建一样，定义一切，比如规则、端口范围和规则的优先级。创建自己的 ARM 模板并不那么困难。您需要 ARM 参考指南，可以在[`docs.microsoft.com/en-us/azure/templates`](https://docs.microsoft.com/en-us/azure/templates)找到。再加上这些示例，这是一个很好的入门资源。

另一种开始的方法是使用可在 Windows、Linux 和 macOS 上使用的 Visual Studio Code 编辑器，网址为[`code.visualstudio.com`](https://code.visualstudio.com)。**Azure 资源管理器工具**扩展是必不可少的，如果您要开始使用 ARM，还有其他一些扩展，如**Azure 帐户和登录**、**Azure 资源管理器片段**和**Azure CLI 工具**。您可以开始使用现有模板，甚至可以将它们上传到 Cloud Shell，执行它们并对其进行调试。

要安装 Azure 资源管理器工具扩展，请按照以下步骤进行：

1.  打开 Visual Studio Code。

1.  从左侧菜单中选择**扩展**。或者，从**查看**菜单中选择**扩展**以打开**扩展**窗格。

1.  搜索**资源管理器**。

1.  在**Azure 资源管理器工具**下选择**安装**。

这是您找到**安装**选项的屏幕：

![在 Visual Studio Code 上导航以安装 Azure 资源管理器工具](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/hsn-linux-adm-az/img/B15455_07_03.jpg)

###### 图 7.3：安装 Azure 资源管理器工具

Azure 中的另一个不错的功能是 ARM Visualizer，您可以在[`armviz.io`](http://armviz.io)找到它。它仍处于早期开发阶段。这是一个可以帮助您快速了解从 Quickstart 模板网站下载的 ARM 模板目的的工具。

除了下载模板，还可以将其保存到库中：

![使用 ARM Visualizer 将模板保存到库中](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/hsn-linux-adm-az/img/B15455_07_04.jpg)

###### 图 7.4：将模板保存到库中

如此窗格所述，您可以通过在左侧导航栏中使用**所有资源**并搜索模板来轻松在 Azure 门户中导航：

![在 Azure 门户上导航到模板](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/hsn-linux-adm-az/img/B15455_07_05.jpg)

###### 图 7.5：在 Azure 门户上导航到模板

您仍然可以在这里编辑您的模板！另一个不错的功能是，您可以与您的租户的其他用户共享您的模板。这可能非常有用，因为您可以创建一个只允许使用此模板进行部署的用户。

现在我们知道了如何从 Azure 门户部署模板，让我们看看如何可以使用 PowerShell 和 Bash 部署 ARM 模板。

### 使用 PowerShell 部署 ARM 模板

首先，验证模板格式是否正确，执行以下命令：

```
Test-AzResourceGroupDeployment -ResourceGroupName ExampleResourceGroup' -TemplateFile c:\MyTemplates\azuredeploy.json '
-TemplateParameterFile  c:\MyTemplates\storage.parameters.json
```

然后继续部署：

```
New-AzResourceGroupDeployment -Name <deployment name> -ResourceGroupName <resource group name> -TemplateFile c:\MyTemplates\azuredeploy.json
-TemplateParameterFile c:\MyTemplates\storage.parameters.json
```

### 使用 Bash 部署 ARM 模板

您还可以在部署之前验证您的模板和参数文件，以避免任何意外错误：

```
az group deployment validate \  
--resource-group ResourceGroupName \
   --template-file template.json \
   --parameters parameters.json
```

要部署，请执行以下命令：

```
az group deployment create \
  --name DeploymentName \
  --resource-group ResourceGroupName \
  --template-file template.json \
  --parameters parameters.json
```

现在我们已经部署了一个新的 VM，我们可以保留`templates.json`和`parameters.json`，通过更改变量值可以重复使用它们。

假设我们已经删除了 VM，并且您希望重新部署它。您只需要 JSON 文件。如前所述，如果您已将模板存储在 Azure 中，您可以在那里找到重新部署的选项：

![使用 JSON 文件重新部署 VM](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/hsn-linux-adm-az/img/B15455_07_06.jpg)

###### 图 7.6：使用 JSON 文件重新部署 VM

如果您希望通过 Azure CLI 或 PowerShell 完成相同的任务，请运行我们之前使用的命令，您的 VM 将准备好，配置与 ARM 模板中提到的相同。

## 初始配置

在部署工作负载之后，需要进行后部署配置。如果您想将其作为自动化解决方案的一部分来完成，那么有两个选项：

+   自定义脚本扩展可以在部署后的任何时间使用。

+   `cloud-init`在引导期间可用。

### 使用自定义脚本扩展进行初始配置

在 VM 部署后，可以使用自定义脚本扩展执行后部署脚本。在前面的示例中，我们使用 ARM 模板部署了 VM。如果您想在部署后运行脚本怎么办？这就是自定义脚本扩展的作用。例如，假设您想部署一个 VM，并且在部署后，您想在其中安装 Apache 而无需登录到 VM。在这种情况下，我们将编写一个脚本来安装 Apache，并且将使用自定义脚本扩展在部署后安装 Apache。

该扩展将适用于除 CoreOS 和 OpenSUSE LEAP 之外的所有 Microsoft 认可的 Linux 操作系统。如果您使用的是除 Debian 或 Ubuntu 之外的发行版，则将脚本中的`apt-get`命令更改为您的发行版支持的软件管理器。

您可以使用 PowerShell 来配置扩展：

```
$myResourceGroup = "<resource group name>"
$myLocation = "<location>"
$myVM = "<vm name>"
$Settings = @{ "commandToExecute" = "apt-get -y install nginx";};
Set-AzVMExtension -VMName $myVM '
-ResourceGroupName $myResourceGroup'
-Location $myLocation '
-Name "CustomscriptLinux" -ExtensionType "CustomScript" '
-Publisher "Microsoft.Azure.Extensions" '
-typeHandlerVersion "2.0" -InformationAction SilentlyContinue '
-Verbose -Settings $Settings
```

PowerShell 输出将在配置后给出状态，即是否正常或出现了问题。运行脚本后，您可以在 VM 的日志中验证安装是否成功。由于我们正在 Ubuntu VM 上进行此操作，您可以通过检查`/var/log/apt/history.log`文件来验证 nginx 的安装。输出确认了 nginx 和所有其他依赖项都已安装：

![检查日志以验证 nginx 安装](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/hsn-linux-adm-az/img/B15455_07_07.jpg)

###### 图 7.7：检查日志以验证 nginx 安装

您还可以提供脚本而不是命令。

让我们创建一个非常简单的脚本：

```
#!/bin/sh
apt-get install -y nginx firewalld
firewall-cmd --add-service=http
firewall-cmd --add-service=http --permanent
```

现在，脚本必须使用`base64`命令进行编码。您可以在任何 Linux VM 上执行此操作，或者您可以使用`base64`字符串：

```
cat nginx.sh| base64
```

#### 注意

在某些版本的 base64 中，您必须添加`-w0`参数以禁用换行。只需确保它是一行！

`$Settings`变量将如下所示：

```
$Settings = @{"script" = "<base64 string>";};
```

由于我们已经使用第一个脚本安装了 nginx，您可以使用`apt purge nginx`来删除 ngnix，或者您可以完全创建一个新的 VM。与之前一样，我们可以去检查历史日志：

![检查 nginx 的历史日志](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/hsn-linux-adm-az/img/B15455_07_08.jpg)

###### 图 7.8：检查历史日志

日志条目清楚地显示了`apt install –y nginx firewalld`已被执行。由于我们正在查看 apt 历史记录，我们将无法确认是否添加了 firewalld HTTP 规则。要确认这一点，您可以运行`firewall-cmd –list-services`：

![验证 firewalld 规则](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/hsn-linux-adm-az/img/B15455_07_09.jpg)

###### 图 7.9：检查是否添加了 firewalld HTTP 规则

如果需要，脚本可以被压缩或上传到存储 blob 中。

当然，您可以使用 Azure CLI 进行初始配置。在这种情况下，您必须提供类似于此的 JSON 文件：

```
{
    "autoUpgradeMinorVersion": true,
    "location": "<location>",
    "name": "CustomscriptLinux",
    "protectedSettings": {},
    "provisioningState": "Failed",
    "publisher": "Microsoft.Azure.Extensions",
    "resourceGroup": "<resource group name>",
    "settings": {
      "script": "<base64 string"
    },
    "tags": {},
    "type": "Microsoft.Compute/virtualMachines/extensions",
    "typeHandlerVersion": "2.0",
    "virtualMachineExtensionType": "CustomScript"
  }
```

然后，执行以下`az`命令：

```
az vm extension set --resource-group <resource group> \
  --vm-name <vm name> \
  --name customScript --publisher Microsoft.Azure.Extensions \
  --settings ./nginx.json
```

#### 注意

JSON 文件可以包含在 ARM 模板中。

如果您正在使用 PowerShell 或 Azure CLI 进行调试目的，`/var/log/azure/custom-script`目录包含您的操作日志。

### 使用 cloud-init 进行初始配置

自定义 VM 扩展的问题在于脚本可能非常特定于发行版。您已经可以在使用的示例中看到这一点。如果使用不同的发行版，您将需要多个脚本，或者您将需要包含发行版检查。

在部署 VM 后进行一些初始配置的另一种方法是使用 cloud-init。

cloud-init 是一个由 Canonical 创建的项目，旨在为定制云映像提供云解决方案和 Linux 发行版不可知的方法。在 Azure 中，它可以与映像一起使用，以在第一次引导期间或创建 VM 时准备操作系统。

并非所有得到 Microsoft 认可的 Linux 发行版都受支持；Debian 和 SUSE 根本不受支持，而且在最新版本的发行版可以使用之前通常需要一些时间。

cloud-init 可用于运行 Linux 命令和创建文件。cloud-init 中有可用的模块来配置系统，例如安装软件或进行一些用户和组管理。如果有可用的模块，那么这是最好的方法。它不仅更容易（为您完成了艰苦的工作），而且还与发行版无关。

cloud-init 使用 YAML；请注意缩进很重要！脚本的目的是安装`npm`，`nodejs`和`nginx`软件包，然后配置 nginx，最后显示消息`Hello World from host $hostname`，其中`$hostname`是 VM 的名称。首先，让我们创建一个 YAML 文件，内容如下，并将其命名为`cloudinit.yml`：

```
#cloud-config
groups: users
users:
  - default
  - name: azureuser
  - groups: users
  - shell: /bin/bash
package_upgrade: true
packages:
  - nginx
  - nodejs
  - npm
write_files:
  - owner: www-data:www-data
  - path: /etc/nginx/sites-available/default
    content: |
      server {
        listen 80;
        location / {
          proxy_pass http://localhost:3000;
          proxy_http_version 1.1;
          proxy_set_header Upgrade $http_upgrade;
          proxy_set_header Connection keep-alive;
          proxy_set_header Host $host;
          proxy_cache_bypass $http_upgrade;
        }
      }
  - owner: azureuser:users
  - path: /home/azureuser/myapp/index.js
    content: |
      var express = require('express')
      var app = express()
      var os = require('os');
      app.get('/', function (req, res) {
        res.send('Hello World from host ' + os.hostname() + '!')
      })
      app.listen(3000, function () {
        console.log('Hello world app listening on port 3000!')
      })
runcmd:
  - systemctl restart nginx
  - cd "/home/azureuser/myapp"
  - npm init
  - npm install express -y
  - nodejs index.js
```

如果您查看此配置文件，您可以看到以下模块的一些使用情况：

+   `users`和`groups`：用户管理

+   `packages`和`package_upgrade`：软件管理

+   `write_files`：文件创建

+   `runcmd`：运行模块无法实现的命令

您还可以创建一个 VM：

```
az vm create --resource-group <resource group> \
  --name <vm name> --image UbuntuLTS \
  --admin-username linuxadmin \
  --generate-ssh-keys --custom-data cloudinit.txt
```

部署后，需要一些时间才能完成所有工作。日志记录在 VM 的`/var/log/cloud-init.log`和`/var/log/cloud-init-output.log`文件中。

更改网络安全组规则以允许端口`80`上的流量。之后，打开浏览器到 VM 的 IP 地址。如果一切正常，它将显示以下内容：`Hello World from host ubuntu-web!`

#### 注意

Az cmdlets 不支持 cloud-init。

## Vagrant

到目前为止，我们使用了 Microsoft 提供的解决方案；也许我们应该称它们为本地解决方案。这不是在 Azure 中部署工作负载的唯一方法。许多供应商已经创建了在 Azure 中自动化部署的解决方案。在本节中，我们想介绍来自名为 HashiCorp 的公司的解决方案（[`www.hashicorp.com`](https://www.hashicorp.com)）。在本章的后面，我们将介绍该公司的另一款产品：Packer。我们选择这些产品有几个原因：

+   这些产品非常受欢迎和知名。

+   Microsoft 和 HashiCorp 之间有着良好的关系；他们一起努力实现越来越多的功能。

+   而且最重要的原因是：HashiCorp 有不同的产品，可以用于不同的实施场景。这将让您再次考虑在不同的用例中选择什么方法。

Vagrant 是开发人员可以用来部署的工具。它可以帮助您以标准化的方式设置环境，以便您可以一遍又一遍地重新部署。

### 安装和配置 Vagrant

Vagrant 适用于多个 Linux 发行版、Windows 和 macOS，并可从[`www.vagrantup.com/downloads.html`](https://www.vagrantup.com/downloads.html)下载：

1.  要在 Ubuntu 中安装软件，请使用以下命令：

```
cd /tmp
wget \ https://releases.hashicorp.com/vagrant/2.1.2/vagrant_2.1.2_x86_64.deb
sudo dpkg -i vagrant_2.1.2_x86_64.deb
```

在 RHEL/CentOS 中，使用以下命令：

```
sudo yum install \
 https://releases.hashicorp.com/vagrant/2.1.2/ \
 vagrant_2.1.2_x86_64.rpm
```

如果您将其部署在单独的 VM 或工作站上，请确保您也安装了 Azure CLI。

登录到 Azure：

```
az login
```

创建一个服务主体帐户，Vagrant 可以用来进行身份验证：

```
az ad sp create-for-rbac --name vagrant
```

从输出中，您需要`appID`，也称为**客户端 ID**，以及密码，它与**客户端密钥**相同。

1.  执行以下命令以获取您的租户 ID 和订阅 ID：

```
az account show
```

在此命令的输出中，您可以看到您的租户 ID 和订阅 ID。

1.  创建一个具有以下内容的文件，并将其保存到`~/.azure/vagrant.sh`：

```
AZURE_TENANT_ID="<tenant id>"
AZURE_SUBSCRIPTION_ID="<account id>"
AZURE_CLIENT_ID="<app id>"
AZURE_CLIENT_SECRET="<password>"
export AZURE_TENANT_ID AZURE_SUBSCRIPTION_ID AZURE_CLIENT_ID\
  AZURE_CLIENT_SECRET
```

1.  在使用 Vagrant 之前，必须导出这些变量。在 macOS 和 Linux 中，您可以通过执行以下命令来实现：

```
source <file>
```

1.  必须有一个 SSH 密钥对可用。如果尚未完成此操作，请使用此命令创建密钥对：

```
ssh-keygen
```

1.  最后一步涉及安装 Vagrant 的 Azure 插件：

```
vagrant plugin install vagrant-azure
```

1.  验证安装：

```
vagrant version
```

![使用版本命令验证 vagrant 安装](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/hsn-linux-adm-az/img/B15455_07_10.jpg)

###### 图 7.10：验证 vagrant 安装

现在我们已经确认 Vagrant 已经启动运行，让我们继续使用 Vagrant 部署一个 VM。

### 使用 Vagrant 部署虚拟机

要使用 Vagrant 部署虚拟机，你需要创建一个新的工作目录，在那里我们将创建`Vagrantfile`：

```
Vagrant.configure('2') do |config|  
config.vm.box = 'azure'  
# use local ssh key to connect to remote vagrant box  config.ssh.private_key_path = '~/.ssh/id_rsa'  
config.vm.provider :azure do |azure, override|       
azure.tenant_id = ENV['AZURE_TENANT_ID']    
azure.client_id = ENV['AZURE_CLIENT_ID']    
azure.client_secret = ENV['AZURE_CLIENT_SECRET']    azure.subscription_id = ENV['AZURE_SUBSCRIPTION_ID']  
end
end
```

配置文件以一个声明开始，我们需要之前安装的 Vagrant 的 Azure 插件。之后，VM 的配置开始。为了能够使用 Vagrant 提供工作负载，需要一个虚拟 box。它几乎是一个空文件：只注册 Azure 作为提供者。要获得这个虚拟 box，执行以下命令：

```
vagrant box add azure-dummy\
  https://github.com/azure/vagrant-azure/raw/v2.0/dummy.box\
  --provider azure
```

通常，很多选项，比如`vm_image_urn`，将被嵌入到一个 box 文件中，你只需要在`Vagrantfile`中提供最少的选项。由于我们使用的是一个虚拟 box，没有预先配置的默认值。`az.vm_image_urn`是 Azure 提供的实际镜像，语法如下：

```
 <publisher>:<image>:<sku>:<version>
```

除了使用标准镜像，还可以使用自定义**虚拟硬盘**（**VHD**）文件，使用这些指令：

+   `vm_vhd_uri`

+   `vm_operating_system`

+   `vm_vhd_storage_account_id`

在本章的后面，我们将更详细地讨论这些自定义 VHD 文件。

另一个重要的值是虚拟机的名称；它也被用作 DNS 前缀。这必须是唯一的！否则，你会得到这个错误：`DNS 记录<name>.<location>.cloudapp.azure.com 已经被另一个公共 IP 使用了`。

部署 Vagrant box，虚拟机：

```
vagrant up 
```

输出应该是这样的：

![使用 up 命令部署 vagrant box](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/hsn-linux-adm-az/img/B15455_07_11.jpg)

###### 图 7.11：部署 vagrant box

当机器准备好使用时，你可以使用这个命令登录：

```
vagrant ssh
```

你的工作目录的内容被复制到 VM 中的`/vagrant`。这可以是一个非常好的方式，让你的文件在 VM 中可用。

使用这个命令清理你的工作：

```
vagrant destroy
```

#### 注意

也可以创建多台虚拟机。

### Vagrant Provisioners

提供一种简单的方式来部署虚拟机并不是 Vagrant 最重要的特性。使用 Vagrant 的主要原因是让一个完整的环境运行起来；部署后，虚拟机需要配置。有 provisioners 来完成后续工作。provisioners 的目的是进行配置更改，自动安装软件包等。你可以使用 shell provisioner，在客户端 VM 中上传和执行脚本，以及文件 provisioner 来运行命令并将文件复制到 VM 中。

另一个可能性是使用 Vagrant provisioners 来进行编排工具，比如 Ansible 和 Salt。下一章将讨论这些工具。在本章中，连同 Vagrant 网站上的 provisioners 文档（[`www.vagrantup.com/docs/provisioning/`](https://www.vagrantup.com/docs/provisioning/)），我们将配置 shell provisioners 和文件 provisioner。让我们继续通过将以下代码块添加到`Vagrantfile`来配置 provisioners。

将这段代码添加到`Vagrantfile`的底部：

```
# Configure the Shell Provisioner
config.vm.provision "shell", path: "provision.sh"
end # Vagrant.config
```

我们在 shell provisioner 中引用了一个文件`provision.sh`。所以让我们创建一个简短的`provision.sh`脚本，包含一些简单的命令：

```
#!/bin/sh
touch /tmp/done
touch /var/lib/cloud/instance/locale-check.skip
```

再次部署 VM，你会看到 Vagrant 已经接受了我们创建的 SSH 密钥，并开始了配置：

![再次部署 VM 以使 Vagrant 接受 SSH 密钥并开始配置](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/hsn-linux-adm-az/img/B15455_07_12.jpg)

###### 图 7.12：Vagrant 已开始配置

执行这段代码来验证在 VM 中是否已经创建了`/tmp/done`目录，就像我们在`provision.sh`文件中指示的那样：

```
vagrant ssh -c "ls -al /tmp/done"
```

## Packer

对于开发人员来说，尤其是如果有许多人在同一应用上工作，拥有标准化的环境非常重要。如果您不使用容器技术（请参阅*第九章*，*Azure 中的容器虚拟化*，以及*第十章*，*使用 Azure Kubernetes 服务*，了解有关此技术的更多信息），Vagrant 是一个很好的工具，它可以帮助开发人员管理虚拟机的生命周期，以便以可重复的方式快速启动应用程序。它根据镜像提供或自定义 VHD 进行配置。如果您想在云中开发应用程序，这就是您所需要的一切。

但是，如果您想要更复杂的环境、构建自己的镜像、多机部署、跨云环境等，这并非完全不可能，但一旦尝试，您会发现 Vagrant 并不适用于这些场景。

这就是另一个 HashiCorp 产品 Packer 派上用场的地方。在本节中，我们将使用与之前与 Vagrant 相似的配置来使用 Packer。

### 安装和配置 Packer

Packer 可用于 macOS、Windows、多个 Linux 发行版和 FreeBSD。可在[`www.packer.io/downloads.html`](https://www.packer.io/downloads.html)下载软件包。

下载软件包，解压缩，然后就可以使用了。在 Linux 中，最好创建一个`~/.bin`目录并在那里解压缩：

```
mkdir ~/bin
cd /tmp
wget wget https://releases.hashicorp.com/packer/1.2.5/\
  packer_1.2.5_linux_amd64.zip
unzip /tmp/packer*zip
cp packer ~/bin 
```

注销并重新登录。几乎每个发行版都会在`~/bin`目录可用时将其添加到`PATH`变量中，但您必须注销并重新登录。

通过执行`$PATH`检查`PATH`变量。如果您无法看到`bin`文件夹添加到路径中，请执行以下操作：

```
export PATH=~/bin:$PATH
```

验证安装：

```
packer version
```

如果安装成功，该命令将返回 Packer 的版本，如图中所示：

![通过 Packer 版本验证 Packer 安装](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/hsn-linux-adm-az/img/B15455_07_13.jpg)

###### 图 7.13：通过 Packer 版本验证 Packer 安装

对于 Packer 的配置，我们将需要与 Vagrant 相同的信息：

+   Azure 租户 ID（`az account show`）

+   Azure 订阅 ID（`az account show`）

+   服务主体帐户的 ID（如果要使用与 Vagrant 相同的帐户，请使用`az app list --display-name vagrant`命令）

+   此帐户的秘密密钥（如果需要，可以使用`az ad sp reset-credentials`命令生成新的密钥）

+   在正确的位置中存在的资源组；在此示例中，我们使用`LinuxOnAzure`作为资源组名称，`West Europe`作为位置（使用`az group create --location "West Europe" --name "LinuxOnAzure"`命令创建）

创建一个文件（例如`/packer/ubuntu.json`），其中包含以下内容：

```
{ 
    "builders": [{ 
      "type": "azure-arm", 
      "client_id": "<appId>", 
      "client_secret": "<appPassword>", 
      "tenant_id": "<tenantId>", 
      "subscription_id": "<subscriptionID>", 
      "managed_image_resource_group_name": "LinuxOnAzure", 
      "managed_image_name": "myPackerImage", 
      "os_type": "Linux", 
      "image_publisher": "Canonical",
      "image_offer": "UbuntuServer", 
      "image_sku": "18.04-LTS", 
      "location": "West Europe", 
      "vm_size": "Standard_B1s" 
    }], 
    "provisioners": [{ 
   "type": "shell", 
   "inline": [ 
   "touch /tmp/done", 
   "sudo touch /var/lib/cloud/instance/locale-check.skip" 
   ] 
    }] 
  }
```

验证语法：

```
packer validate ubuntu.json
```

然后，按以下方式构建镜像：

```
packer build ubuntu.json
```

![使用 Packer 构建命令构建镜像](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/hsn-linux-adm-az/img/B15455_07_14.jpg)

###### 图 7.14：使用 Packer 构建命令构建镜像

Packer 需要一些时间来构建虚拟机，运行配置程序并清理部署。

构建完成后，Packer 将为您提供构建的摘要，例如资源组、虚拟机部署位置、镜像名称和位置：

![Packer 提供的图像摘要，构建完成后](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/hsn-linux-adm-az/img/B15455_07_15.jpg)

###### 图 7.15：镜像摘要

构建将创建一个镜像，但不会创建运行中的虚拟机。从 Packer 创建的镜像中，您可以使用以下命令部署虚拟机：

```
az vm create \ 
--resource-group LinuxOnAzure \
 --name mypackerVM \ 
--image myPackerImage \ 
--admin-username azureuser \ 
--generate-ssh-keys
```

要清理环境并删除 Packer 创建的镜像，请执行以下命令：

```
az resource delete --resource-group LinuxOnAzure --resource-type images \
  --namespace Microsoft.Compute --name myPackerImage
```

我在本章前面提供的 JSON 文件足以创建镜像。这与我们在 Vagrant 中所做的非常相似，但为了将其转换为可部署的镜像，我们必须将 VM 进行泛化，这意味着允许它为多个部署进行镜像化。将`/usr/sbin/waagent -force -deprovision+user & export HISTSIZE=0 && sync`添加到代码中将泛化 VM。不要担心这段代码-在下一节中，当我们通过 Azure CLI 泛化 VM 时，您将再次看到它。

找到以下代码：

```
 "provisioners": [{
    "type": "shell",
    "inline": [
      "touch /tmp/done",
      "sudo touch /var/lib/cloud/instance/locale-check.skip"
    ]
```

这需要用以下代码替换：

```
     "provisioners": [{
    "type": "shell",
    "execute_command": "echo '{{user 'ssh_pass'}}' | {{ .Vars }} sudo -S -E sh '{{ .Path }}'",
    "inline": [
     "touch /tmp/done",
     "touch /var/lib/cloud/instance/locale-check.skip",
     "/usr/sbin/waagent -force -deprovision+user && export HISTSIZE=0 && sync"
    ]
    }]
  }
```

`execute_command`是用于以正确用户身份执行脚本的命令。

使用`packer validate`命令验证模板，以避免任何错误并重新构建镜像。

到目前为止，我们已经使用 Packer 创建了镜像，但也可以使用 Azure CLI 和 Powershell 来完成。接下来的部分将详细介绍这一点。

## 自定义虚拟机和 VHD

在上一节中，我们在 Azure 中使用了标准 VM 提供，并使用了两种不同的方法进行了一些配置工作。然而，正如之前所述，存在一些原因使得默认镜像可能不适合您。让我们再次总结一下原因。

Azure 的本机镜像提供了部署 VM 的良好起点。使用本机镜像的一些好处如下：

+   由 Linux 发行版供应商或可信赖的合作伙伴创建和支持

+   快速部署，无论是手动还是编排，当然，您之后可以自定义它们

+   使用 Azure 扩展功能和选项轻松扩展

如果您选择使用本机提供的服务，那么也会有一些缺点或者说一些不足之处：

+   如果您需要比标准镜像更加安全的镜像，那么您必须依赖于市场上昂贵的加固镜像版本。

+   标准镜像不符合公司标准，尤其是在分区方面。

+   标准镜像并非针对特定应用进行了优化。

+   一些 Linux 发行版不受支持，例如 Alpine 和 ArchLinux。

+   关于可重现环境的问题：某个镜像版本可用多长时间？

因此，我们需要自定义镜像，以便我们可以自定义镜像并减轻问题或不足之处。我们并不是在暗示本机提供不安全或无法完成任务，但在企业环境中，存在一些情况，例如为 RHEL/SLES VMs 提供自己的订阅和作为镜像打包的第三方**独立软件供应商**（**ISV**）软件，您必须使用自定义镜像。让我们继续看看如何在 Azure 中使用自定义镜像。

### 创建托管镜像

在上一节中，我们调查了 Packer。创建了一个 VM，然后将其转换为镜像。此镜像可用于部署新的 VM。这种技术也称为**捕获 VM 镜像**。

让我们看看是否可以逐步使用 Azure CLI 手动进行操作：

1.  创建资源组：

```
myRG=capture
myLocation=westus
az group create --name $myRG --location $myLocation
```

1.  创建 VM：

```
myVM=ubuntudevel
AZImage=UbuntuLTS
Admin=linvirt
az vm create --resource-group $myRG  --name $myVM \
  --image $AZImage \
  --admin-username linvirt  --generate-ssh-keys
```

1.  登录到 VM 并使用 Azure VM Agent 取消配置它。它通过删除特定于用户的数据来泛化 VM：

```
sudo waagent -deprovision+user
```

执行命令后，输出将显示有关即将删除的数据的警告。您可以输入`y`继续，如下所示：

![使用 VM Agent 取消配置 VM](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/hsn-linux-adm-az/img/B15455_07_16.jpg)

###### 图 7.16：取消配置 VM

输入`exit`退出 SSH 会话。

1.  释放 VM：

```
az vm deallocate --resource-group $myRG --name $myVM
```

1.  将其标记为泛化。这意味着允许它为多个部署进行镜像化：

```
az vm generalize --resource-group $myRG --name $myVM
```

1.  从此资源组中的 VM 创建镜像：

```
destIMG=customUbuntu
az image create --resource-group $myRG --name $destIMG --source $myVM
```

1.  验证结果：

```
az image list -o table
```

输出将以表格格式显示镜像列表：

![以表格格式列出的 Azure 镜像列表](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/hsn-linux-adm-az/img/B15455_07_17.jpg)

###### 图 7.17：Azure 镜像列表

1.  您可以使用此镜像部署新的 VM：

```
az vm create --resource-group <resource group> \
  --name <vm name> \ 
  --image $destIMG \    
  --admin-username <username> \    
  --generate-ssh-key
```

如果您在 PowerShell 中，这也是可能的。让我们非常快速地通过第一步。流程非常相似；唯一的区别是我们使用 PowerShell cmdlet：

```
$myRG="myNewRG" 
$myLocation="westus" 
$myVM="ubuntu-custom" 
$AZImage="UbuntuLTS"

#Create resource group
New-AzResourceGroup -Name $myRG -Location $myLocation 

#Create VM
New-AzVm '
-ResourceGroupName $myRG '
-Name $myVM '
-ImageName $AZimage '
-Location $myLocation '
-VirtualNetworkName "$myVM-Vnet" '
-SubnetName "$myVM-Subnet" '
-SecurityGroupName "$myVM-NSG" '
-PublicIpAddressName "$myVM-pip"
```

PowerShell 可能提示您输入凭据。继续输入凭据以访问您的 VM。之后，我们将继续对 VM 进行去配置：

```
Stop-AzureRmVM -ResourceGroupName <resource group>'
  -Name <vm name> 
```

与之前一样，现在我们必须将 VM 标记为通用化：

```
Set-AzVm -ResourceGroupName <resource group> -Name <vm name> '
 -Generalized
```

让我们捕获 VM 信息并将其保存到一个变量中，因为我们将需要它来创建图像的配置：

```
$vm = Get-AzVM –Name <vm name> -ResourceGroupName <resource group name>
```

现在让我们创建图像的配置：

```
$image = New-AzImageConfig -Location<location> -SourceVirtualMachineId $vm.Id
```

因为我们在`$image`中存储了配置，所以使用它来创建图像：

```
New-AzImage -Image $image -ImageName <image name> '
 -ResourceGroupName <resource group name>
```

验证图像是否已创建：

```
Get-AzImage –ImageName <Image Name>
```

运行上述命令将为您提供类似以下的输出，其中包含您创建的图像的详细信息：

![使用 Get-AzImage –ImageName 命令获取的图像详细信息摘要](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/hsn-linux-adm-az/img/B15455_07_18.jpg)

###### 图 7.18：获取图像详细信息

如果您想使用刚刚创建的图像创建 VM，请执行以下命令：

```
New-AzVm ' 
-ResourceGroupName "<resource group name>" ' 
-Name "<VM Name>" ' 
-ImageName "<Image Name>" ' 
-Location "<location>" ' 
-VirtualNetworkName "<vnet name>" ' 
-SubnetName "<subnet name>" ' 
-SecurityGroupName "<nsg name>" ' 
-PublicIpAddressName "<public IP name>"
```

总结我们所做的，我们创建了一个 VM，通用化了它，并创建了一个可以进一步用于部署多个 VM 的图像。还有一种从参考图像创建多个 VM 的替代方法，即使用''快照''。这将在下一节中介绍。

### 使用快照的备用方法

如果您想保留原始 VM，可以从快照创建 VM 图像。Azure 中的快照实际上是一个完整的 VM！

**使用 PowerShell**

1.  声明一个变量`$vm`，它将存储有关我们将要获取和创建快照的 VM 的信息：

```
$vm = Get-AzVm -ResourceGroupName <resource group> '
  -Name $vmName
$snapshot = New-AzSnapshotConfig '   
  -SourceUri $vm.StorageProfile.OsDisk.ManagedDisk.Id '   
  -Location <location> -CreateOption copy
New-AzSnapshot '    
  -Snapshot $snapshot -SnapshotName <snapshot name> '    
  -ResourceGroupName <resource group>
```

1.  因为我们需要快照 ID 用于后续步骤，所以我们将重新初始化快照变量：

```
$snapshot = Get-AzSnapshot –SnapshotName <Snapshot Name>
```

1.  下一步涉及从快照创建图像配置。

```
$imageConfig = New-AzImageConfig -Location <location>

$imageConfig = Set-AzImageOsDisk -Image $imageConfig '
 -OsState Generalized -OsType Linux -SnapshotId $snapshot.Id
```

1.  最后，创建图像：

```
New-AzImage -ImageName <image name> '
  -ResourceGroupName <resource group> -Image $imageConfig
```

**使用 Azure CLI**

在 Azure CLI 中，事情更容易；只需获取快照的 ID 并将其转换为磁盘：

1.  使用 Azure CLI 创建快照：

```
disk=$(az vm show --resource-group <resource group>\
  --name <vm name> --query "storageProfile.osDisk.name" -o tsv)
az snapshot create --resource-group <resource group>\
  --name <snapshot name> --source $disk
```

1.  创建图像：

```
snapshotId=$(az snapshot show --name <snapshot name>\
  --resource-group <resource group> --query "id" -o tsv)
az image create --resource-group <resource group> --name myImage \
  --source $snapshotID --os-type Linux 
```

在对 VM 进行快照之前不要忘记通用化 VM。如果您不想这样做，可以从快照创建磁盘，并将其用作 Azure CLI 中的`--attach-os-disk`命令的磁盘参数，或者在 PowerShell 中使用`Set-AzVMOSDisk`。

### 自定义 VHD

您可以完全从头开始构建自己的图像。在这种情况下，您必须构建自己的 VHD 文件。有多种方法可以做到这一点：

+   在 Hyper-V 或 VirtualBox 中创建一个 VM，它是 Windows、Linux 和 macOS 可用的免费 hypervisor。这两种产品都原生支持 VHD。

+   在 VMware Workstation 或 KVM 中创建您的 VM，并在 Linux `qemu-img`中使用它来转换图像。对于 Windows，可以在[`www.microsoft.com/en-us/download/details.aspx?id=42497`](https://www.microsoft.com/en-us/download/details.aspx?id=42497)下载 Microsoft Virtual Machine Converter。这包括一个 PowerShell cmdlet，`ConvertTo-MvmcVirtualHardDisk`，用于进行转换。

#### 注意

Azure 仅支持 Type-1 VHD 文件，并且应该具有与 1 MB 对齐的虚拟大小。在撰写本书时，Type-2 正在预览中（[`docs.microsoft.com/en-us/azure/virtual-machines/windows/generation-2`](https://docs.microsoft.com/en-us/azure/virtual-machines/windows/generation-2)）。

Azure 在 Hyper-V 上运行。Linux 需要特定的内核模块才能在 Azure 中运行。如果 VM 是在 Hyper-V 之外创建的，Linux 安装程序可能不包括 Hyper-V 驱动程序在初始 ramdisk（`initrd`或`initramfs`）中，除非 VM 检测到它正在运行在 Hyper-V 环境中。

当使用不同的虚拟化系统（如 VirtualBox 或 KVM）来准备您的 Linux 图像时，您可能需要重建`initrd`，以便至少`hv_vmbus`和`hv_storvsc`内核模块在初始 ramdisk 上可用。这个已知问题适用于基于上游 Red Hat 发行版的系统，可能也适用于其他系统。

重建`initrd`或`initramfs`映像的机制可能因发行版而异。请查阅您发行版的文档或支持以获取正确的操作步骤。以下是使用`mkinitrd`实用程序重建`initrd`的示例：

1.  备份现有的`initrd`映像：

```
cd /boot
sudo cp initrd-'uname -r'.img  initrd-'uname -r'.img.bak
```

1.  使用`hv_vmbus`和`hv_storvsc 内核`模块重建`initrd`：

```
sudo mkinitrd --preload=hv_storvsc --preload=hv_vmbus -v -f initrd-'uname -r'.img 'uname -r'
```

几乎不可能描述每个 Linux 发行版和每个 hypervisor 的所有可用选项。总的来说，您需要做的事情在这里列出。非常重要的是我们要准确地按照步骤进行，否则无法完成此任务。我们强烈建议按照 Microsoft 的文档进行操作（[`docs.microsoft.com/en-us/azure/virtual-machines/linux/create-upload-generic`](https://docs.microsoft.com/en-us/azure/virtual-machines/linux/create-upload-generic)）。

1.  修改 GRUB 或 GRUB2 中的内核引导行，以包括以下参数，以便所有控制台消息都发送到第一个串行端口。这些消息可以帮助 Azure 支持调试任何问题：

```
console=ttyS0,115200n8 earlyprintk=ttyS0,115200 rootdelay=300
```

1.  Microsoft 还建议删除以下参数（如果存在）：

```
rhgb quiet crashkernel=auto
```

1.  安装 Azure Linux 代理，因为代理是在 Azure 上为 Linux 映像进行配置所必需的。您可以使用`rpm`或`deb`文件安装它，或者您可以按照 Linux 代理指南中提供的步骤手动安装它（[`docs.microsoft.com/en-us/azure/virtual-machines/extensions/agent-linux`](https://docs.microsoft.com/en-us/azure/virtual-machines/extensions/agent-linux)）。

1.  确保安装了 OpenSSH 服务器并在启动时自动启动。

1.  不要创建交换。如果需要，稍后可以启用它，就像我们在前一章中讨论的那样。

1.  取消配置 VM，如*创建托管映像*部分所述。

1.  关闭 VM，您的 VHD 已准备好上传到 VM。

为简单起见，我们将跳过前面的步骤，并从 Ubuntu 的云映像存储库下载官方映像，因为最重要的部分是将映像上传到 Azure。从[`cloud-images.ubuntu.com/bionic/`](https://cloud-images.ubuntu.com/bionic/)下载云映像。此网页包含所有 Bionic 的版本，您可以浏览目录并下载 Azure 的 tar.gz 文件。文件名类似于`bionic-server-cloudimg-amd64-azure.vhd.tar.gz`；但是，这个名称可能会根据您查看的版本有所不同。

现在我们必须将 VHD 上传到 Azure：

1.  首先，为映像准备一个单独的存储帐户是个好主意，所以让我们创建一个新的存储帐户。在这里，我们选择`Premium_LRS`，但如果您愿意，也可以选择`Standard_LRS`以节省一些成本：

```
az storage account create --location <location> \
  --resource-group <resource group> --sku Premium_LRS \
  --name <account name> --access-tier Cool --kind StorageV2
```

1.  保存输出以备后用。列出访问密钥：

```
az storage account keys list --account-name <storage account name>\
  --resource-group <resource group>
```

1.  再次保存输出。我们需要的下一步是创建一个容器来存储文件：

```
 az storage container create \
  --account-name <storage account>\
  --account-key <storage account key 1>  
  --name <container name> 
```

1.  现在您可以上传 VHD：

```
az storage blob upload --account-name <storage account>\
  --account-key <storage account key> \
  --container-name <container name> \ 
  --type page --file ./bionic-server-cloudimg-amd64.vhd \
  --name bionic.vhd
```

#### 注意

您还可以使用 Azure 门户或 PowerShell 上传文件。其他方法包括 Azure 存储资源管理器（[`azure.microsoft.com/en-us/features/storage-explorer/`](https://azure.microsoft.com/en-us/features/storage-explorer/)）或 Azure VHD 工具（[`github.com/Microsoft/azure-vhd-utils`](https://github.com/Microsoft/azure-vhd-utils)）。最后一个方法速度非常快！

1.  接收 blob URL：

```
az storage blob url --account-name <storage account> \
  --account-key <storage account key> \
  --container-name <container name> \
  --name bionic.vhd
```

1.  现在可以从上传创建一个磁盘：

```
az disk create --resource-group <resoure group> \
 --name bionic --source <blob url> --Location <location>
```

1.  使用此磁盘创建 VM 映像：

```
az image create --resource-group <resource group> \
  --name bionic --source <blob url> --os-type linux 
  --location <location>
```

1.  最后，基于此映像创建一个 VM：

```
az vm create --resource-group <resource group> \
 --name <vm name> \ 
 --image bionic \    
 --admin-username <username> \    
 --generate-ssh-key \
 --location <location>
```

#### 注意

您可以将 VHD 映像设为公共；一个很好的例子是一个名为 NixOS 的鲜为人知的 Linux 发行版。在他们的网站上，[`nixos.org/nixos/download.html`](https://nixos.org/nixos/download.html)，他们描述了在 Azure 中部署其操作系统的方法！

让我们总结一下我们所做的。我们采取了两种方法。我们从现有的 VM 创建并上传了一个 Linux VHD，然后手动下载了一个 Ubuntu VHD 并使用它。无论哪种方式，我们都将把它上传到存储账户，并将使用它创建一个镜像。这个镜像是可重复使用的，你可以部署任意多个 VM。

自动化过程和可用工具是广泛的。在下一章中，我们将继续讨论自动化过程，并讨论最广泛使用的工具，即 Ansible 和 Terraform。

## 总结

在本章中，我们开始思考在 Azure 中为什么以及何时应该使用自动化。随后，我们添加了关于使用 Azure 提供的镜像的问题。

考虑到这些问题，我们探讨了自动化部署的选项：

+   脚本编写

+   ARM 模板

+   Vagrant

+   Packer

+   构建和使用自己的镜像

Vagrant 和 Packer 是第三方解决方案的例子，它们是非常受欢迎的工具，可以轻松地创建和重新创建环境，作为你的开发过程的重要部分。

重要的是要知道，本章中描述的所有技术都可以组合成一个完整的解决方案。例如，你可以将 cloud-init 与 ARM 一起使用，也可以与 Vagrant 一起使用。

自动化和编排是密切相关的。在本章中，我们讨论了自动化，特别是作为开发环境的一部分，用于自动化 VM 的部署。自动化通常是一个难以维护的解决方案，用于跟踪开发和部署的工作负载。这就是编排发挥作用的地方，下一章将涵盖这一点。

## 问题

1.  在 Azure 中使用自动化部署的主要原因是什么？

1.  在开发环境中自动化的目的是什么？

1.  你能描述脚本编写和自动化之间的区别吗？

1.  你能说出 Azure 中可用的一些自动化部署选项吗？

1.  Vagrant 和 Packer 有什么区别？

1.  为什么应该使用自己的镜像而不是 Azure 提供的镜像？

1.  有哪些选项可以创建自己的镜像？

也许你可以抽出一些时间来完成*脚本编写*部分的示例脚本，用你选择的语言。

## 进一步阅读

特别是关于 Azure CLI、PowerShell 和 ARM，Azure 文档包含大量有价值的信息和许多示例。我们在*第二章，开始使用 Azure 云*的*进一步阅读*部分中写的一切对本章也很重要。

微软提供的另一个资源是其博客。如果你访问[`blogs.msdn.microsoft.com/wriju/category/azure/`](https://blogs.msdn.microsoft.com/wriju/category/azure/)，你会发现许多关于自动化的有趣帖子，包括更详细的示例。

在他的博客[`michaelcollier.wordpress.com`](https://michaelcollier.wordpress.com)中，Michael S. Collier 提供了大量关于 Azure 的信息。几乎每篇帖子都包括脚本编写和自动化的可能性。

关于 Vagrant 并没有太多最近的书。我们相信你会喜欢一年前出版的*Infrastructure as Code (IAC) Cookbook*，作者是 Stephane Jourdan 和 Pierre Pomes。这本书不仅涉及 Vagrant；它还涵盖了其他解决方案，如 cloud-init 和 Terraform。作者创作了一本不仅是很好的介绍，而且还能用作参考指南的书。

我们可以推荐一本最近出版的书吗？*Hands-On DevOps with Vagrant: Implement End-to-End DevOps and Infrastructure Management Using Vagrant*，作者是 Alex Braunton。他在 YouTube 上关于这个主题的帖子也值得一看。
