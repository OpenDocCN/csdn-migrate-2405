# 精通 CentOS7 Linux 服务器（一）

> 原文：[`zh.annas-archive.org/md5/9720AF936D0BA95B59108EAF3F9811A7`](https://zh.annas-archive.org/md5/9720AF936D0BA95B59108EAF3F9811A7)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 前言

CentOS 7 Linux 是最可靠的 Linux 操作系统之一，可用于计算机基础设施中的多种功能。对于任何系统管理员来说，它就像潘多拉魔盒，因为他可以塑造它来执行环境中的任何任务。

在任何基础设施中拥有 CentOS 7 服务器可以帮助部署许多有用的服务，以智能和自动化的方式维护、保护和管理基础设施。

# 本书涵盖的内容

第一章，“高级用户管理”，教您如何在 CentOS 7 上管理用户和组，以更好地了解其组织结构。

第二章，“安全”，展示了保护您的 CentOS 7 和一些宝贵服务免受可能禁用服务或暴露一些关键数据的攻击的最佳实践。

第三章，“用于不同目的的 Linux”，列举并介绍了一步一步的教程，说明如何设置计算机基础设施应具有的一系列非常有用的服务。

第四章，“使用 Postfix 的邮件服务器”，介绍了 Postfix 作为常见的开源邮件服务器，以便安装和配置以进行高级使用。

第五章，“监控和日志记录”，通过用户友好的监控和日志记录工具监控您的基础设施，并跟踪您的机器问题。

第六章，“虚拟化”，启动您的虚拟环境，并探索所有虚拟技术可以提供的可能性和好处。

第七章，“云计算”，通过使用 OpenStack 及其令人惊叹的组件构建自己的云环境，探索云计算。

第八章，“配置管理”，将您的基础设施提升到一个高级水平，使一切都在使用 Puppet 进行配置管理，因为它是这个领域中最著名的配置管理工具之一。

第九章，“一些额外的技巧和工具”，教您在管理 CentOS 7 服务器时可以使生活更轻松的一些小技巧和工具。

# 您需要什么

要正确地遵循本书，我们建议您拥有一个 CentOS 7 服务器，以满足大多数这些服务的以下特征：

+   CPU：4 核 3.00 GHz

+   内存：6 GB RAM

+   硬盘：150 GB

+   网络：1 Gbit/s

此外，您需要一些具有以下特征的机器来测试服务：

+   CPU：2 核 3.00 GHz

+   内存：2 GB RAM

+   硬盘：50 GB

+   网络：1Gbit/s

还需要良好的互联网连接和千兆网络交换机。

# 这本书适合谁

如果您是具有中级管理水平的 Linux 系统管理员，那么这是您掌握全新的 CentOS 发行版的机会。如果您希望拥有一个完全可持续的 Linux 服务器，具有所有新工具和调整，为用户和客户提供各种服务，那么这本书非常适合您。这是您轻松适应最新变化的通行证。

# 惯例

本书中，您将找到许多文本样式，用于区分不同类型的信息。以下是这些样式的一些示例以及它们的含义解释。

文本中的代码词、数据库表名、文件夹名、文件名、文件扩展名、路径名、虚拟 URL、用户输入和 Twitter 句柄显示如下：“我们可以通过使用`include`指令包含其他上下文。”

代码块设置如下：

```
<html>
    <title>
  Test page
    </title>
    <body>
  <h1>This is a test page</h1>
    </body>
</html>
```

任何命令行输入或输出都以以下形式编写：

```
testuser:x:1001:1001::/home/testuser:/bin/bash

```

**新术语**和**重要单词**以粗体显示。屏幕上看到的单词，例如菜单或对话框中的单词，会以这样的方式出现在文本中："然后我们定义要填写的字段**国家名称**，**州或省名称**，**地点名称**，**组织名称**，**组织单位名称**，**通用名称**和**电子邮件地址**"。

### 注意

警告或重要说明会出现在这样的框中。

### 提示

技巧和窍门会出现在这样。


# 第一章：高级用户管理

在本章中，我们将介绍一些高级用户和组管理场景，以及如何处理高级选项（如密码过期、管理 sudoers 等）的示例，以及如何在日常工作中处理这些选项。在这里，我们假设我们已经成功安装了 CentOS 7，并且像传统格式中一样拥有 root 和用户凭据。此外，在本章中的命令示例中，假设您已登录或切换到 root 用户。

将涵盖以下主题：

+   从 GUI 和命令行管理用户和组

+   配额

+   密码寿命

+   Sudoers

# 从 GUI 和命令行管理用户和组

我们可以使用命令行使用`useradd`将用户添加到系统中，命令如下：

```
useradd testuser

```

这将在`/etc/passwd`文件中创建一个用户条目，并在`/home`中自动创建用户的`home`目录。`/etc/passwd`条目如下所示：

```
testuser:x:1001:1001::/home/testuser:/bin/bash

```

但是，众所周知，用户处于锁定状态，除非我们使用命令为用户添加密码，否则无法登录系统：

```
passwd testuser

```

这将反过来修改`/etc/shadow`文件，同时解锁用户，用户将能够登录系统。

默认情况下，上述一系列命令将在系统上为`testuser`用户创建用户和组。如果我们想要一组特定的用户成为一个公共组的一部分怎么办？我们将使用`useradd`命令以及`-g`选项来为用户定义组，但是我们必须确保该组已经存在。因此，要创建用户（例如`testuser1`、`testuser2`和`testuser3`）并使它们成为名为`testgroup`的公共组的一部分，我们将首先创建该组，然后使用`-g`或`-G`开关创建用户。所以，我们将这样做：

```
# To create the group :
groupadd testgroup
# To create the user with the above group and provide password and unlock
user at the same time :

useradd testuser1 -G testgroup
passwd testuser1

useradd testuser2 -g 1002
passwd testuser2

```

在这里，我们同时使用了`-g`和`-G`。它们之间的区别是：使用`-G`，我们创建用户并将其分配到其默认组以及公共`testgroup`，但使用`-g`，我们只将用户创建为`testgroup`的一部分。在这两种情况下，我们可以使用`gid`或从`/etc/group`文件中获取的组名。

我们可以用于高级用户创建的其他一些选项；例如，对于`uid`小于 500 的系统用户，我们必须使用`-r`选项，这将在系统上创建一个用户，但`uid`将小于 500。我们还可以使用`-u`来定义特定的`uid`，它必须是唯一的，并且大于 499。我们可以与`useradd`命令一起使用的常见选项有：

+   -c：此选项用于注释，通常用于定义用户的真实姓名，例如`-c“John Doe”`。

+   -d：此选项用于定义`home-dir`；默认情况下，`home`目录创建在`/home`中，例如`-d /var/<user name>`。

+   -g：此选项用于用户的默认组的组名或组号。该组必须已经在之前创建过。

+   -G：此选项用于附加的组名或组号，用逗号分隔，用户是该组的成员。同样，这些组也必须已经创建过。

+   -r：此选项用于创建一个 UID 小于 500 且没有`home`目录的系统帐户。

+   -u：此选项是用户的用户 ID。它必须是唯一的，并且大于 499。

有一些我们与`passwd`命令一起使用的快速选项。这些是：

+   -l：此选项是锁定用户帐户的密码

+   -u：此选项是解锁用户帐户的密码

+   -e：此选项是为用户设置密码过期

+   -x：此选项是定义密码寿命的最大天数

+   -n：此选项是定义密码寿命的最小天数

# 配额

为了控制 Linux 文件系统中使用的磁盘空间，我们必须使用配额，这使我们能够控制磁盘空间，从而帮助我们在很大程度上解决低磁盘空间问题。为此，我们必须在 Linux 系统上启用用户和组配额。

在 CentOS 7 中，默认情况下未启用用户和组配额，因此我们必须首先启用它们。

检查配额是否启用，我们发出以下命令：

```
mount | grep ' / '

```

![Quotas](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/ms-centos7-linux-svr/img/B04674_01_01.jpg)

该图显示了根文件系统未启用配额，如输出中的`noquota`所述。

现在，我们必须在根（`/`）文件系统上启用配额，为此，我们必须首先编辑文件`/etc/default/grub`并将以下内容添加到`GRUB_CMDLINE_LINUX`中：

```
rootflags=usrquota,grpquota

```

在文件`GRUB_CMDLINE_LINUX`中应该读取如下：

```
GRUB_CMDLINE_LINUX="rd.lvm.lv=centos/swap vconsole.font=latarcyrheb-sun16 rd.lvm.lv=centos/root crashkernel=auto  vconsole.keymap=us rhgb quiet rootflags=usrquota,grpquota"

```

cat `/etc/default/grub`命令的输出应该如下屏幕截图所示：

![Quotas](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/ms-centos7-linux-svr/img/B04674_01_02.jpg)

由于我们必须反映刚刚做出的更改，我们应该使用以下命令备份 grub 配置：

```
cp /boot/grub2/grub.cfg /boot/grub2/grub.cfg.original

```

现在，我们必须使用以下命令重新构建 grub 以应用刚刚做出的更改：

```
grub2-mkconfig -o /boot/grub2/grub.cfg

```

接下来，重新启动系统。一旦启动，登录并使用我们之前使用的命令验证配额是否已启用：

```
mount | grep ' / '

```

现在应该显示配额已启用，并将显示以下输出：

```
/dev/mapper/centos-root on / type xfs (rw,relatime,attr2,inode64,usrquota,grpquota)

```

在图像之前添加以下引导，并将 CIT 样式应用于**mount | grep ' / '**

![Quotas](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/ms-centos7-linux-svr/img/B04674_01_03.jpg)

现在，由于配额已启用，我们将使用以下命令进一步安装配额，以便为不同用户和组操作配额等：

```
yum -y install quota

```

安装配额后，我们使用以下命令检查用户的当前配额：

```
repquota -as

```

上述命令将以人类可读的格式报告用户配额。

![Quotas](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/ms-centos7-linux-svr/img/B04674_01_04.jpg)

从上述屏幕截图中，我们可以限制用户和组的配额的两种方式；一种是为使用的磁盘空间设置软限制和硬限制，另一种是通过限制用户或组创建的文件数量来限制用户或组。在这两种情况下，都使用软限制和硬限制。软限制是在达到软限制时警告用户的东西，而硬限制是他们无法绕过的限制。

我们将使用以下命令修改用户配额：

```
edquota -u username

```

上述命令的输出应该如下屏幕截图所示：

![Quotas](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/ms-centos7-linux-svr/img/B04674_01_05.jpg)

现在，我们将使用以下命令修改组配额：

```
edquota -g groupname

```

![Quotas](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/ms-centos7-linux-svr/img/B04674_01_06.jpg)

如果您有其他分区单独挂载，您必须修改`/etc/fstab`文件命令，通过在特定分区的默认值后添加`usrquota`和`grpquota`来启用文件系统的配额，如下面的屏幕截图所示，在那里我们已经为`/var`分区启用了配额：

![Quotas](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/ms-centos7-linux-svr/img/B04674_01_07.jpg)

一旦您完成了启用配额，重新挂载文件系统并运行以下命令：

```
To remount /var :
mount -o remount /var
To enable quota :
quotacheck -avugm
quotaon -avug

```

配额是所有系统管理员用来处理用户或组在服务器上消耗的磁盘空间并限制空间过度使用的东西。因此，它有助于他们管理系统上的磁盘空间使用。在这方面，应该注意在安装之前进行规划并相应地创建分区，以便正确使用磁盘空间。通常建议使用多个单独的分区，如`/var`和`/home`等，因为这些通常是 Linux 系统上占用最多空间的分区。因此，如果我们将它们放在单独的分区上，它将不会占用根（`/`）文件系统空间，并且比仅使用根文件系统挂载更加安全。

# 密码过期

设置密码过期是一个很好的策略，这样用户被迫在一定的时间间隔内更改他们的密码。这反过来也有助于保持系统的安全性。

我们可以使用`chage`配置密码，在用户首次登录系统时过期。

### 注意

注意：如果用户使用 SSH 登录系统，则此过程将无法工作。

使用`chage`的这种方法将确保用户被强制立即更改密码。

### 提示

如果我们只使用`chage <username>`，它将显示指定用户的当前密码过期值，并允许交互式更改它们。

需要执行以下步骤来完成密码过期：

1.  锁定用户。如果用户不存在，我们将使用`useradd`命令创建用户。但是，我们不会为用户分配任何密码，以便保持锁定。但是，如果用户已经存在于系统中，我们将使用`usermod`命令锁定用户：

```
Usermod -L <username>

```

1.  使用以下命令强制立即更改密码：

```
chage -d 0 <username>

```

1.  解锁帐户。可以通过两种方式实现。一种是分配初始密码，另一种是分配空密码。我们将采用第一种方法，因为第二种方法虽然可能，但在安全方面不是一个好的做法。因此，我们要做的是分配初始密码：

+   使用 Python 命令启动命令行 Python 解释器：

```
import crypt; print
crypt.crypt("Q!W@E#R$","Bing0000/")

```

+   在这里，我们使用了带有字母数字字符的盐组合`Bing0000`后跟`/`字符的`Q!W@E#R$`密码。输出是加密密码，类似于`BiagqBsi6gl1o`。

+   按下*Ctrl* + *D*退出 Python 解释器。

1.  在 shell 中，输入以下命令以 Python 解释器的加密输出：

```
usermod -p "<encrypted-password>" <username>

```

因此，在我们的情况下，如果用户名是`testuser`，加密输出是`" BiagqBsi6gl1o"`，我们将执行：

```
usermod -p "BiagqBsi6gl1o" testuser

```

现在，使用`Q!W@E#R$`密码首次登录后，用户将被提示输入新密码。

## 设置密码策略

这是一组规则，定义在某些文件中，必须在设置系统用户时遵循。这是安全性的一个重要因素，因为许多安全漏洞历史始于黑客攻击用户密码。这就是为什么大多数组织为其用户设置密码策略的原因。所有用户和密码必须符合此策略。

密码策略通常由以下定义：

+   密码过期

+   密码长度

+   密码复杂性

+   限制登录失败

+   限制先前密码重用

## 配置密码过期和密码长度

密码过期和密码长度在`/etc/login.defs`中定义。过期基本上是指密码可以使用的最大天数，允许更改密码之间的最小天数，以及密码过期前的警告次数。长度是指创建密码所需的字符数。要配置密码过期和长度，我们应该编辑`/etc/login.defs`文件，并根据组织设置的不同`PASS`值。

### 注意

注意：此处定义的密码过期控件不会影响现有用户；它只影响新创建的用户。因此，我们必须在设置系统或服务器时设置这些策略。我们修改的值是：

+   `PASS_MAX_DAYS`：密码可以使用的最大天数

+   `PASS_MIN_DAYS`：允许更改密码之间的最小天数

+   `PASS_MIN_LEN`：最小可接受的密码长度

+   `PASS_WARN_AGE`：密码过期前要提前多少天的警告

让我们看一下`login.defs`文件的示例配置：

![配置密码过期和密码长度](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/ms-centos7-linux-svr/img/B04674_01_08.jpg)

## 配置密码复杂性和限制重复使用的密码

通过编辑`/etc/pam.d/system-auth`文件，我们可以配置密码复杂性和要拒绝的重复使用密码的数量。密码复杂性是指密码中使用的字符的复杂性，而重复使用密码拒绝是指拒绝用户过去使用的密码的数量。通过设置复杂性，我们强制密码中使用所需数量的大写字符、小写字符、数字和符号。除非符合规则设置的复杂性，否则系统将拒绝密码。我们使用以下术语来实现这一点：

+   **强制密码中的大写字符**：`ucredit=-X`，其中`X`是密码中所需的大写字符数量。

+   **强制密码中的小写字符**：`lcredit=-X`，其中`X`是密码中所需的小写字符数量。

+   **强制密码中的数字**：`dcredit=-X`，其中`X`是密码中所需的数字数量。

+   **强制密码中使用符号**：`ocredit=-X`，其中`X`是密码中所需的符号数量。例如：

```
password requisite pam_cracklib.so try_first_pass retry=3 type= ucredit=-2 lcredit=-2 dcredit=-2 ocredit=-2

```

+   **拒绝重复使用的密码**：`remember=X`，其中`X`是要拒绝的过去密码的数量。例如：

```
password sufficient pam_unix.so sha512 shadow nullok try_first_pass use_authtok remember=5

```

现在让我们来看一下`/etc/pam.d/system-auth`的一个示例配置：

![配置密码复杂性和限制重复使用的密码](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/ms-centos7-linux-svr/img/B04674_01_09.jpg)

## 配置登录失败

我们在`/etc/pam.d/password-auth`、`/etc/pam.d/system-auth`和`/etc/pam.d/login`文件中设置了用户允许的登录失败次数。当用户的失败登录尝试次数高于此处定义的数字时，帐户将被锁定，只有系统管理员才能解锁帐户。要进行配置，请向文件添加以下内容。以下的`deny=X`参数配置了这一点，其中`X`是允许的失败登录尝试次数。

将这两行添加到`/etc/pam.d/password-auth`和`/etc/pam.d/system-auth`文件中，只将第一行添加到`/etc/pam.d/login`文件中：

```
auth        required    pam_tally2.so file=/var/log/tallylog deny=3 no_magic_root unlock_time=300
account     required    pam_tally2.so

```

以下是一个`/etc/pam.d/system-auth`文件的示例截图：

![配置登录失败](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/ms-centos7-linux-svr/img/B04674_01_10.jpg)

以下是一个`/etc/pam.d/login`文件的示例：

![配置登录失败](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/ms-centos7-linux-svr/img/B04674_01_11.jpg)

要查看失败，请使用以下命令：

```
pam_tally2 –user=<User Name>

```

要重置失败尝试并允许用户再次登录，请使用以下命令：

```
pam_tally2 –user=<User Name> --reset

```

# Sudoers

在 Linux 操作系统中，用户权限的分离是主要特点之一。普通用户在有限的权限会话中操作，以限制他们对整个系统的影响范围。Linux 上存在一个我们已经知道的特殊用户`root`，具有超级用户权限。此帐户没有任何适用于普通用户的限制。用户可以以多种不同的方式执行具有超级用户或 root 权限的命令。

主要有三种不同的方法可以在系统上获得 root 权限：

+   以`root`身份登录系统。

+   以任何用户身份登录系统，然后使用`su -`命令。这将要求您输入`root`密码，一旦验证，将为您提供 root shell 会话。我们可以使用*Ctrl* + *D*或使用`exit`命令断开此 root shell。退出后，我们将回到我们的普通用户 shell。

+   使用`sudo`以 root 权限运行命令，而不生成`root` shell 或以 root 身份登录。此`sudo`命令的工作方式如下：

```
sudo <command to execute>
```

与`su`不同，`sudo`将要求调用命令的用户密码，而不是 root 密码。

`sudo`默认情况下不起作用，需要在其正确运行之前进行设置。

在接下来的部分中，我们将看到如何配置`sudo`并修改`/etc/sudoers`文件，以使其按我们的意愿工作。

## visudo

`sudo`是使用`/etc/sudoers`文件进行修改或实现的，`visudo`是使我们能够编辑该文件的命令。

### 注意

注意：为了避免在更新文件时出现潜在的竞争条件，不应使用普通文本编辑器编辑此文件。应该使用`visudo`命令。

`visudo`命令通常会打开文本编辑器，然后在保存时验证文件的语法。这可以防止配置错误阻止`sudo`操作。

![visudo](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/ms-centos7-linux-svr/img/B04674_01_12.jpg)

默认情况下，`visudo`会在 vi 编辑器中打开`/etc/sudoers`文件，但我们可以配置它使用`nano`文本编辑器。为此，我们必须确保`nano`已安装，或者我们可以使用以下命令安装`nano`：

```
yum install nano -y

```

现在，我们可以通过编辑`~/.bashrc`文件将其更改为使用`nano`：

```
export EDITOR=/usr/bin/nano

```

然后，使用以下命令源文件：

```
. ~/.bashrc

```

现在，我们可以使用`visudo`和`nano`编辑`/etc/sudoers`文件。所以，让我们用`visudo`打开`/etc/sudoers`文件并学习一些东西。

我们可以为不同的命令、软件、服务、用户、组等创建不同类型的别名。例如：

```
Cmnd_Alias NETWORKING = /sbin/route, /sbin/ifconfig, /bin/ping, /sbin/dhclient, /usr/bin/net, /sbin/iptables, /usr/bin/rfcomm, /usr/bin/wvdial, /sbin/iwconfig, /sbin/mii-tool
Cmnd_Alias SOFTWARE = /bin/rpm, /usr/bin/up2date, /usr/bin/yum
Cmnd_Alias SERVICES = /sbin/service, /sbin/chkconfig

```

我们可以使用这些别名为用户或组分配一组命令执行权限。例如，如果我们想要将`NETWORKING`命令集分配给`netadmin`组，我们将定义：

```
%netadmin ALL = NETWORKING

```

否则，如果我们想要允许`wheel`组的用户运行所有命令，我们将执行以下操作：

```
%wheel  ALL=(ALL)  ALL

```

如果我们想要特定用户`john`获得对所有命令的访问权限，我们将执行以下操作：

```
john  ALL=(ALL)  ALL

```

我们可以创建不同的用户组，其成员可能有重叠的权限。

```
User_Alias      GROUPONE = abby, brent, carl
User_Alias      GROUPTWO = brent, doris, eric,
User_Alias      GROUPTHREE = doris, felicia, grant

```

组名必须以大写字母开头。然后，我们可以允许`GROUPTWO`的成员更新`yum`数据库和前述软件分配的所有命令，通过创建如下规则：

```
GROUPTWO    ALL = SOFTWARE

```

如果我们不指定要运行的用户/组，`sudo`默认为 root 用户。

我们可以允许`GROUPTHREE`的成员关闭和重新启动机器，通过创建一个`命令别名`并在`GROUPTHREE`的规则中使用它：

```
Cmnd_Alias      POWER = /sbin/shutdown, /sbin/halt, /sbin/reboot, /sbin/restart
GROUPTHREE  ALL = POWER

```

我们创建了一个名为`POWER`的命令别名，其中包含关闭电源和重新启动机器的命令。然后，我们允许`GROUPTHREE`的成员执行这些命令。

我们还可以创建`Runas`别名，它可以替换规则的部分，指定用户以其身份执行命令：

```
Runas_Alias     WEB = www-data, apache
GROUPONE    ALL = (WEB) ALL

```

这将允许`GROUPONE`的任何成员以`www-data`用户或`apache`用户的身份执行命令。

请记住，稍后的规则将覆盖先前的规则，当两者之间存在冲突时。

有许多方法可以更好地控制`sudo`如何处理命令。以下是一些例子：

与`mlocate`软件包相关联的`updatedb`命令相对无害。如果我们希望允许用户以 root 权限执行它而无需输入密码，我们可以制定如下规则：

```
GROUPONE    ALL = NOPASSWD: /usr/bin/updatedb

```

`NOPASSWD`是一个标签，表示不会请求密码。它有一个伴随命令叫做`PASSWD`，这是默认行为。标签对于规则的其余部分是相关的，除非在后面被其`双胞胎`标签覆盖。

例如，我们可以有如下行：

```
GROUPTWO    ALL = NOPASSWD: /usr/bin/updatedb, PASSWD: /bin/kill 

```

在这种情况下，用户可以作为 root 用户运行`updatedb`命令而无需密码，但运行`kill`命令将需要输入 root 密码。另一个有用的标签是`NOEXEC`，它可以用于防止某些程序中的一些危险行为。

例如，一些程序，如`less`，可以通过在其界面内输入以下内容来生成其他命令：

```
!command_to_run

```

这基本上会以`less`正在运行的相同权限执行用户给出的任何命令，这可能非常危险。

为了限制这一点，我们可以使用以下行：

```
username    ALL = NOEXEC: /usr/bin/less

```

现在你应该清楚了`sudo`是什么，以及我们如何使用`visudo`修改和提供访问权限。这里还有很多事情。你可以使用`visudo`命令检查默认的`/etc/sudoers`文件，其中包含很多示例，或者你也可以阅读`sudoers`手册。

要记住的一点是，常规用户通常不会被赋予 root 权限。当您以 root 权限执行这些命令时，了解这些命令的作用非常重要。不要轻视这份责任。学习如何最好地为您的用例使用这些工具，并锁定任何不需要的功能。

# 参考

现在，让我们来看一下本章中使用的主要参考资料：

[`access.redhat.com/documentation/en-US/Red_Hat_Enterprise_Linux/7/html/System_Administrators_Guide/index.html`](https://access.redhat.com/documentation/en-US/Red_Hat_Enterprise_Linux/7/html/System_Administrators_Guide/index.html)

# 摘要

在本章中，您了解了一些高级用户管理知识，以及如何通过命令行管理用户，包括密码过期、配额、暴露给 `/etc/sudoers`，以及如何使用 `visudo` 修改它们。用户和密码管理是系统管理员在服务器上经常执行的任务，它在系统的整体安全中起着非常重要的作用。

在下一章中，我们将研究称为**安全增强型 Linux**（**SELinux**）的高级安全功能，它与 CentOS 或 RedHat Linux 操作系统集成在一起。


# 第二章：安全

在本章中，我们将找到不同的工具和实用程序，可以用来保护我们正在使用的 CentOS 系统。安全是系统或服务器最重要的部分，因此，系统管理员的工作始终是保持系统最新和安全，以防止服务器上定期发生的各种攻击。

我们将从 SELinux 到其他安全工具和措施开始讨论这里的几个工具，并逐一深入了解它们。

在本章中，我们将研究：

+   SELinux 及其工具

+   安装 SELinux

+   域转换

+   SELinux 用户

+   SELinux 审计日志和故障排除

# 介绍 SELinux

**安全增强型 Linux**（**SELinux**）是一组内核修改和用户空间工具，已经在 CentOS 中存在了相当长的时间。它是一种支持强制访问控制安全策略的机制，最初由美国国家安全局开发，后来在公共领域发布，以保护计算机系统免受恶意侵入和篡改。

并不是很多系统管理员使用 SELinux。通常，人们不愿意学习 SELinux，而是直接禁用它。然而，一个正确配置的 SELinux 系统可以在很大程度上减少安全风险。

SELinux 实现**强制访问控制**（**MAC**），它建立在 CentOS 7 上已有的**自主访问控制**（**DAC**）之上。 DAC 是我们在 Linux 系统上拥有的传统安全模型，其中有三个实体：用户、组和其他人可以对文件和目录拥有读、写和执行权限的组合。默认情况下，如果用户在他的主目录中创建任何文件，用户和他的组将具有读取访问权限，用户将具有写访问权限，但其他实体也可能具有读取访问权限。

拥有文件的用户可以更改此访问策略，并授予或撤销文件的访问权限以及所有权。这可能会使关键文件暴露给不需要访问这些文件的帐户，从而对正在运行的系统构成安全威胁。它将每个进程限制在自己的域中，并确保它只能与一种定义的文件和进程类型进行交互，从而保护系统免受黑客通过劫持脚本或进程并通过它获得系统范围控制的威胁。

要检查系统上安装了哪些 SELinux 软件包，请运行以下命令：

```
rpm -qa | grep selinux

```

该命令将显示以下输出：

![介绍 SELinux](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/ms-centos7-linux-svr/img/B04674_02_01.jpg)

## 安装 SELinux

使用以下命令安装所有软件包；这将安装系统上剩余的软件包并更新已安装的软件包：

```
yum install policycoreutils policycoreutils-python selinux-policy selinux-policy-targeted libselinux-utils setroubleshoot-server setools setools-console mcstrans

```

现在，我们将在系统上安装 SELinux 所需的所有软件包。让我们在系统上安装另外两个服务 apache（`httpd`）用于 Web 服务器和 FTP（`vsftpd`）服务器，以便我们可以测试它们的 SELinux：

```
yum install httpd vsftpd

```

现在使用以下命令运行 apache 服务：

```
systemctl start httpd
service httpd start

```

使用以下命令之一检查 httpd 的状态：

```
service status httpd
systemctl status httpd

```

这些命令将显示它正在运行，如下面的截图所示：

![安装 SELinux](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/ms-centos7-linux-svr/img/B04674_02_02.jpg)

还可以使用以下命令之一启动 vsftpd，然后以相同的方式检查`vsftp`的状态：

```
systemctl start vsftpd
service vsftpd start

```

使用以下命令之一检查 ftpd 的状态：

```
service status ftpd
systemctl status ftpd

```

![安装 SELinux](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/ms-centos7-linux-svr/img/B04674_02_03.jpg)

## SELinux 模式

有三种类型的 SELinux 模式，它们如下：

+   **强制执行**：在此模式下，SELinux 强制执行其策略到系统，并确保未经授权的用户或进程的所有访问都被拒绝。这些访问拒绝事件也会记录在系统中，我们稍后将在本章中进行讨论。

+   **宽容**：这类似于半启用模式状态，其中 SELinux 不会拒绝任何访问，因为策略处于宽容模式。这是测试 SELinux 策略的最佳模式。

+   **禁用**：在此模式下，SELinux 处于完全禁用状态，不会创建日志或拒绝权限。

我们可以运行以下命令来获取当前的 SELinux 状态：

```
getenforce
sestatus

```

当系统启用 SELinux 时，前述命令的输出显示在以下图像中：

![SELinux 模式](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/ms-centos7-linux-svr/img/B04674_02_04.jpg)

主要的 SELinux 配置文件是`/etc/selinux/config`。我们现在将通过在该文件中设置`SELINUX=permissive`来启用 SELinux，然后保存并重新启动系统。

![SELinux 模式](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/ms-centos7-linux-svr/img/B04674_02_05.jpg)

`config`文件中的`SELINUXTYPE`参数也有三个选项，如下所示：

+   **Targeted**：这是允许您自定义和微调策略的默认值。

+   **最小**：在此模式下，只有选定的进程受到保护。

+   **MLS**：多级安全是一种高级的保护模式，您需要安装额外的软件包。

我们将保持`SELINUXTYPE`为默认值（即，targeted）。

第一次运行时，有必要将 SELinux 设置为宽容模式，因为需要为系统上的所有文件打标签。否则，在受限域下运行的进程可能会失败，因为它们无法访问具有正确上下文的文件。

一旦我们设置并重新启动系统，它将为所有文件打标签，这将根据具有 SELinux 上下文的系统而需花费一些时间。由于它处于宽容模式，只会报告失败和访问拒绝。

一旦系统启动，我们必须使用以下命令检查是否有任何错误：

```
grep 'SELinux' /var/log/messages

```

如果 SELinux 以宽容模式运行，将显示以下输出：

```
May 25 01:54:46 localhost kernel: SELinux:  Disabled at runtime.
May 25 03:06:40 localhost kernel: SELinux:  Initializing.
May 25 03:06:58 localhost systemd[1]: Successfully loaded SELinux policy in 2.863609s.
May 27 06:31:39 localhost kernel: SELinux:  Initializing.
May 27 06:31:55 localhost systemd[1]: Successfully loaded SELinux policy in 1.944267s.

```

现在，由于所有规则都已加载并且文件已被标记，我们必须启用 SELinux 强制模式，而不是宽容模式。因此，再次编辑`SELinux 配置`文件，并将以下内容设置为强制：

```
SELINUX=enforcing

```

![SELinux 模式](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/ms-centos7-linux-svr/img/B04674_02_06.jpg)

现在再次重新启动服务器。

一旦系统恢复，使用`sestatus`命令检查 SELinux 状态，它将显示类似以下内容的输出：

![SELinux 模式](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/ms-centos7-linux-svr/img/B04674_02_04.jpg)

现在，如果在`/var/log/messages`中使用`grep`查找 SELinux，将找到以下内容：

```
May 27 11:18:21 localhost kernel: SELinux: Initializing.
May 27 11:18:34 localhost systemd[1]: Successfully loaded SELinux policy in 715.664ms.

```

要检查 SELinux 强制状态，请运行`getenforce`命令，它将显示状态为`enforcing`。

`sestatus`命令将显示有关操作中的 SELinux 配置的更多详细信息，如下所示：

![SELinux 模式](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/ms-centos7-linux-svr/img/B04674_02_07.jpg)

如果我们想在运行 SELinux 时临时更改 SELinux 模式，可以使用`setenforce`命令，如下所示：

```
setenforce permissive

```

现在，`sestatus`将显示以下屏幕：

![SELinux 模式](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/ms-centos7-linux-svr/img/B04674_02_08.jpg)

使用以下命令切换回强制模式：

```
setenforce enforcing

```

## SELinux 策略

你一定已经注意到了之前在`/var/log/messages`中的 SELinux 输出是基于策略的。策略意味着一组规则，定义了与以下内容的关系、安全性和访问权限：

+   **用户**：所有常规 Linux 用户都由一个或多个 SELinux 用户定义。但请注意，SELinux 用户与 Linux 用户不同。还要注意，运行的进程或程序在 SELinux 中被定义为主题。

+   **角色**：它们类似于定义哪个用户可以访问进程等的过滤器。它就像用户和进程之间的网关。只有在角色授予访问权限并且用户有权访问角色时，用户才能运行特定进程。SELinux 基于**基于角色的访问控制**（**RBAC**）。

+   **主题**和**对象**：主题类似于进程或程序，对象是可以被操作的任何东西；如文件、端口、目录等。主题对对象执行的操作取决于主题的权限。

+   **域**：这类似于主体（进程）的包装器，告诉进程它可以或不能做什么。例如，域将定义进程可以访问的目录、文件夹、文件、端口等。域与 SELinux 中的主体相关。

+   **类型**：文件的上下文称为其类型。例如，文件的上下文描述了它是否仅对本地 Web 服务器进程可访问，或者对任何其他目录中的任何进程可访问，比如`/`等等，或者文件的特定 SELinux 用户是文件的所有者。类型与 SELinux 中的对象相关。

在 SELinux 中，策略定义了用户访问角色的规则，角色访问域的规则，以及域访问类型的规则。

SELinux 中由`/etc/selinux/config`文件中的`SELINUXTYPE`定义的三种访问控制形式：

+   **类型强制**（**TE**）：这是定向策略中使用的访问控制的主要机制

+   **基于角色的访问控制**（**RBAC**）：这是基于 SELinux 用户（不一定与 Linux 用户相同）的，但在默认的定向策略中不使用。

+   **多级安全**（**MLS**）：这不常用，通常在默认的定向策略中隐藏。

定向策略是 SELinux 中默认使用的策略，我们将在此基础上继续讨论。

还要记住，SELinux 不会取代 Linux 系统中的传统 DAC 策略。相反，如果 DAC 策略禁止文件访问，SELinux 策略将不会被评估，并且不会授予文件访问权限，即使 SELinux 允许。

SELinux 策略以模块化格式加载到内存中，并可以使用以下命令查看：

```
semodule -l | more

```

![SELinux 策略](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/ms-centos7-linux-svr/img/B04674_02_09.jpg)

`semodule`命令可用于安装、删除、重新加载、升级、启用和禁用 SELinux 策略模块。

模块文件位于`/etc/selinux/targeted/modules/active/modules/`目录中，具有`.pp`扩展名，不是人类可读的。但是，如果你仔细查看它们，你肯定会发现它们实际上与 Linux 中的不同应用程序相关。

![SELinux 策略](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/ms-centos7-linux-svr/img/B04674_02_10.jpg)

这些策略模块被合并为一个活动策略，然后加载到内存中。这个合并的二进制策略可以在`/etc/selinux/targeted/policy/`目录中找到：

![SELinux 策略](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/ms-centos7-linux-svr/img/B04674_02_11.jpg)

我们不能直接修改这些规则，但可以使用`semanage boolean`命令来管理它们。`semanage boolean -l | less`命令的输出将显示给我们这些信息。

![SELinux 策略](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/ms-centos7-linux-svr/img/B04674_02_12.jpg)

在前面输出的第二行清楚地表明，FTP 服务访问用户主目录目前已关闭。我们还可以使用以下命令管道查看`ftpd`服务策略的状态：

```
semanage boolean -l | grep ftpd

```

![SELinux 策略](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/ms-centos7-linux-svr/img/B04674_02_13.jpg)

现在，为了允许 FTP 用户访问他们的主目录并允许读写访问，我们必须发出以下命令。首先使用以下命令检查`ftp_home_dir`策略的状态：

```
getsebool ftp_home_dir

```

这将显示以下输出：

```
ftp_home_dir --> off

```

现在，使用`setsebool -P`永久启用对用户主目录的访问：

```
setsebool -P ftp_home_dir on

```

现在，再次检查状态：

```
getsebool ftp_home_dir

```

这将显示以下输出：

```
ftp_home_dir --> on

```

现在，用户将被允许通过 FTP 访问其主目录；防火墙中允许 FTP 协议。

## SELinux 文件和进程

到目前为止，我们已经了解了 SELinux 的基础知识，以及如何允许`vsftpd`等服务允许用户从 ftp 访问其文件。让我们深入了解文件的上下文以及它们在 SELinux 中的定义。在 SELinux 中，上下文是与安全相关的信息集合，它帮助 SELinux 确定访问控制策略。在 Linux 中，一切都可以有安全上下文，如文件、目录、服务或端口，但是安全上下文对不同的对象意味着不同类型的事物。

我们可以使用`ls –Z`参数显示任何文件的 SELinux 文件上下文，如下所示：

```
ls -laZ /home/test/*

```

![SELinux 文件和进程](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/ms-centos7-linux-svr/img/B04674_02_14.jpg)

在前面的输出中，这部分是特定文件的 SELinux 上下文：

```
system_u:object_r:user_home_t:s0

```

有四个部分，每个部分由冒号（`:`）分隔。第一部分是 SELinux 用户上下文，在这里显示为`system_u`。正如您已经知道的，每个 Linux 系统用户都映射到一个 SELinux 用户，这里是`system_u`。

第二部分是 SELinux 角色，在这里是`object_r`。

这里最重要的部分是第三部分，即`user_home_t`。这是定义文件类型的部分，从中我们可以理解它属于用户的主目录。

第四部分（s0）实际上解释了文件的敏感性，它实际上与多级安全性一起工作。前三部分更重要，所以我们只会处理它们。

现在，让我们使用之前安装的`httpd`文件查看 SELinux 进程上下文。首先使用以下命令启动`httpd`进程：

```
systemctl httpd start

```

现在让我们运行带有额外`-Z`标志的`ps`命令来查看进程上下文：

```
ps -efZ | grep httpd

```

![SELinux 文件和进程](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/ms-centos7-linux-svr/img/B04674_02_15.jpg)

前面输出中的安全上下文如下：

```
system_u:system_r:httpd_t:s0

```

在 SELinux 中，用户后缀为`_u`，角色后缀为`_r`，类型后缀为`_t`。

对于像`httpd`这样的进程，它需要访问其文件并执行操作。我们已经看到每个进程只能访问特定类型（文件、目录、端口等）。

SELinux 在策略中定义了这些访问规则。这些访问规则遵循标准的`allow`语句，如下所示：

```
allow <domain> <type>:<class> { <permissions> };

```

通用的`allow`语句表示：

+   进程是否属于某个域

+   进程正在尝试访问的资源对象是某个类和类型

+   它是否允许访问或拒绝访问

让我们看看这如何与我们已经查看过的 https 进程的安全上下文相结合。

文档根目录或`httpd`的默认目录是`/var/www/html`。现在，让我们在那里创建一个文件并检查其安全上下文：

```
touch /var/www/html/index.html
ls -Z /var/www/html/*

```

![SELinux 文件和进程](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/ms-centos7-linux-svr/img/B04674_02_16.jpg)

我们创建的`index.html`文件的文件上下文显示为`httpd_sys_content_t`。

我们将以以下方式使用`sesearch`命令来检查`httpd`守护程序允许的访问类型：

```
sesearch --allow --source httpd_t --target httpd_sys_content_t --class file

```

![SELinux 文件和进程](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/ms-centos7-linux-svr/img/B04674_02_17.jpg)

在前面的命令中使用的标志很容易理解；源域是`httpd_t`，这是 apache 正在其中运行的域。我们想列出目标资源，这些资源是文件，并且具有类型上下文`httpd_sys_content_t`。

请注意前面截图中上下文输出的第一行是：

```
allow httpd_t httpd_sys_content_t : file { ioctl read getattr lock open } ;

```

现在，如果您将其与之前的通用 allow 语句联系起来，我们将清楚地了解到`httpd`服务对`httpd_sys_content_t`类型的文件具有 I/O 控制、读取、获取属性、锁定和打开访问权限。而且，在我们的情况下，我们创建的`index.html`文件也是相同类型的，这意味着`httpd`服务将可以访问这个`index.html`文件。

让我们创建一个测试网页，修改`index.html`文件，以便我们可以从浏览器中检查其输出。使用您喜欢的编辑器将以下行添加到`index.html`文件中，并保存：

```
<html>
    <title>
  Test page
    </title>
    <body>
  <h1>This is a test page</h1>
    </body>
</html>
```

我们将使用以下命令更改`/var/www`文件夹的权限，然后使用`httpd restart`：

```
chmod -R 755 /var/wwwsystemctl restart httpd

```

如果您是第一次这样做，可能需要在防火墙中允许 http 端口，使用以下命令：

```
firewall-cmd --permanent --add-port=80/tcp
firewall-cmd --permanent --add-service=http
firewall-cmd –reload

```

现在尝试从浏览器中访问它。它将显示以下截图中的输出：

![SELinux 文件和进程](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/ms-centos7-linux-svr/img/B04674_02_18.jpg)

现在，让我们看看如果我们更改`index.html`文件的类型上下文，我们是否仍然能够访问它。我们将使用`chcon`命令更改类型上下文，并将使用`-type`标志进行此操作，如下所示：

```
chcon --type var_t /var/www/html/index.html

```

如果我们使用`ls -Z`检查文件的上下文，它会显示：

```
-rwxr-xr-x. root root unconfined_u:object_r:var_t:s0   /var/www/html/index.html

```

在这里可以看到类型已更改为`var_t`。

现在，如果您再次尝试访问网页，它将显示错误，或者您可能会看到一个默认页面，但不是我们之前看到的同一个页面。这是因为我们已经更改了`index.html`文件的类型上下文。

要恢复它，我们将使用以下命令：

```
restorecon -v /var/www/html/index.html

```

现在，如果我们再次访问该站点，我们将看到它再次像以前一样工作。

SELinux 强制执行模式保证，除非策略另有规定，否则进程和文件将以与其父级相同的上下文创建。这意味着如果进程 A 生成进程 B，生成的进程 B 将在与进程 A 相同的域中运行，除非 SELinux 策略另有规定，同样，如果我们有一个带有一些`context_t`类型的目录，除非另有规定，其下的文件或目录将继承相同的`context_t`类型。

在 CentOS 7 中，系统中存在的所有文件的上下文都列在`/etc/selinux/targeted/contexts/files/file_contexts`文件中，新目录和文件的上下文记录在`/etc/selinux/targeted/contexts/files/file_contexts.local`文件中。由于`chcon`用于临时更改上下文，`restorecon`用于恢复上下文，`restorecon`实际上会查看此文件以恢复文件的原始上下文。

让我们创建`/www/html`：

```
mkdir -p /www/html

```

现在，我们使用以下命令将`/var/www/html`的内容复制到`/www/html`：

```
cp /var/www/html/index.html /www/html/

```

如果我们检查文件的上下文，我们会发现它与`/var/www/html/index.html`及其`default_t`的上下文不同，因为那是其父目录的上下文。

此外，即使我们将`httpd`配置文件更改为从这个新位置打开`index.html`文件，我们仍然会遇到错误，因为上下文还不正确。在从`/var/www/html`复制`index.html`文件到`/www/html`时，它继承了其父目录的上下文，即`default_t`。

为了解决这个问题，我们将不得不更改它的上下文。

要永久更改之前在`/www/html`下创建的`index.html`文件的上下文，我们将遵循两个步骤：

```
semanage fcontext --add --type httpd_sys_content_t "/www(/.*)?"
semanage fcontext --add --type httpd_sys_content_t "/www/html(/.*)?"

```

现在，我们从`/etc/selinux/targeted/contexts/files/file_contexts.local`文件检查上下文数据库：

![SELinux 文件和进程](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/ms-centos7-linux-svr/img/B04674_02_19.jpg)

现在，我们将运行`restorecon`命令，将文件或目录重新标记为前一步记录的内容：

```
restorecon -Rv /www

```

这将在三个级别上起作用；首先它将重新标记`/www`目录，然后是`/www/html`目录，最后是`/www/html/index.html`文件。

![SELinux 文件和进程](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/ms-centos7-linux-svr/img/B04674_02_20.jpg)

现在，如果我们尝试访问网页，它应该可以正常工作。

还有一个名为`matchpathcon`的命令，非常方便用于解决与上下文相关的问题。它可以将当前资源的上下文与 SELinux 上下文数据库中的内容进行比较并报告回来。如果匹配不同，它会建议所需的更改。我们可以使用以下方式使用`-V`标志为`/www/html/index.html`运行该命令：

```
matchpathcon -V /www/html/index.html

```

# 域转换

现在，让我们找出一个进程如何访问其他进程。

假设`vsftpd`进程正在运行；如果它没有启动，我们可以使用以下命令启动它：

```
systemctl start vsftpd

```

`vsftpd`进程是由`systemd`进程启动的；这是`Sys V init`进程的替代品，并在`init_t`的上下文中运行：

```
ps -eZ | grep init

```

![域转换](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/ms-centos7-linux-svr/img/B04674_02_21.jpg)

在`init_t`域下运行的`systemd`进程的生命周期非常短暂；它调用`/usr/sbin/vsftpd`，其类型上下文为`ftpd_exec_t`，当这个二进制可执行文件启动时，它就成为`vsftpd`服务本身，并在`ftpd_t`域中运行。

![域转换](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/ms-centos7-linux-svr/img/B04674_02_22.jpg)

因此，这里的`systemd`进程在`init_t`域下执行一个具有`ftpd_exec_t`类型的二进制文件。然后二进制文件在`ftpd_t`域内启动一个服务。

域转换遵循三个严格的规则：

+   源域的父进程必须有权限在两个域之间执行应用程序

+   该应用程序的文件上下文必须被识别为目标域的入口点

+   原始域必须被允许转换到目标域

让我们运行`sesearch`命令来检查`vsftpd`服务是否遵循这些规则：

1.  首先，源域`init_t`必须有权限在`ftpd_exec_t`上下文中执行应用程序。所以我们运行：

```
sesearch -s init_t -t ftpd_exec_t -c file -p execute -Ad

```

我们找到了以下输出：

```
allow init_t ftpd_exec_t : file { read getattr execute open } ;

```

因此，`init_t`可以读取、获取属性、执行和打开`ftpd_exec_t`上下文的文件。

![域转换](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/ms-centos7-linux-svr/img/B04674_02_23.jpg)

1.  接下来，我们检查二进制文件是否是目标域`ftpd_t`的入口点：

```
sesearch -s ftpd_t -t ftpd_exec_t -c file -p entrypoint -Ad

```

我们发现它是：

```
allow ftpd_t ftpd_exec_t : file { ioctl read getattr lock execute execute_no_trans entrypoint open } ;

```

![域转换](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/ms-centos7-linux-svr/img/B04674_02_24.jpg)

1.  最后，源域`init_t`需要有权限转换到目标`ftpd_t`域：

```
sesearch -s init_t -t ftpd_t -c process -p transition –Ad

```

我们可以看到源域也有这个权限：

```
allow init_t ftpd_t : process transition ;

```

![域转换](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/ms-centos7-linux-svr/img/B04674_02_25.jpg)

SELinux 还支持在未受限制的域下运行的进程；例如，`unconfined_t`。这是已登录用户默认运行其进程的域。

# SELinux 用户

如前所述，SELinux 用户与普通 Linux 用户不同。SELinux 用户在引导时加载到内存中的策略中定义，而且这些用户很少。

在启用 SELinux 之后，每个常规用户帐户都映射到一个 SELinux 用户帐户。可以将多个用户帐户映射到同一个 SELinux 用户。这使得普通用户帐户能够继承其 SELinux 对应帐户的权限。

要查看映射，我们将运行以下命令：

```
semanage login -l

```

![SELinux 用户](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/ms-centos7-linux-svr/img/B04674_02_26.jpg)

在这里，我们会发现在前面的屏幕截图中只有三个登录名，代表 Linux 用户帐户。任何 Linux 用户都映射到此处显示的`__default__`。根用户没有映射到默认值，而是有自己的条目，正在运行的进程或服务有`system_u`。第二列表示它们映射到的 SELinux 用户。普通用户帐户和根用户映射到`unconfined_u`，而进程和服务映射到`system_u` SELinux 用户。暂时忽略第三列，它显示用户的**多级安全**（**MLS**）**多类别安全**（MCS）类，以及最后一列（服务）。

要查看系统中可用的 SELinux 用户，使用`semanage`用户命令如下：

```
semanage user -l

```

![SELinux 用户](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/ms-centos7-linux-svr/img/B04674_02_27.jpg)

在前面的屏幕截图中，表格显示了系统中可用的 SELinux 用户以及他们可以访问的角色。我们已经讨论过 SELinux 角色就像用户和进程之间的网关。我们还将它们比作过滤器，用户可以进入一个角色，前提是该角色授予了权限。如果一个角色被授权访问一个进程域，与该角色相关联的用户将能够进入该进程域。

现在，以根用户身份运行`id -Z`命令。它将显示根用户的 SELinux 安全上下文：

![SELinux 用户](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/ms-centos7-linux-svr/img/B04674_02_28.jpg)

因此，根用户映射到`unconfined_t` SELinux 用户，该用户被授权`unconfined_r`角色，该角色又被授权在`unconfined_t`域中运行进程。

我们已经看到系统中有几个 SELinux 用户可用。让我们在这里讨论其中一些：

+   `guest_u`：这种类型的用户无法访问 X Windows 系统或网络，也无法执行`su`或`sudo`命令

+   `xguest_u`：这种类型的用户只能通过浏览器访问 GUI 和网络

+   `user_u`：这种类型的用户可以访问 GUI 和网络，但不能运行`su`或`sudo`

+   `staff_u`：与`user_u`相同，只是他们可以运行`sudo`。

+   `system_u`：这是为系统服务而设计的，不与常规用户帐户映射

# 限制对 su 或 sudo 的访问

我们可以通过更改用户的 SELinux 用户映射来限制用户运行`su`或`sudo`命令，如下所示：

```
semanage login -a -s user_u test

```

上述命令将更改 Linux `test`用户的映射为`user_u`，并且不允许`su`或`sudo`命令的访问。

### 注意

这只有在用户未登录时才会生效。

## 限制运行脚本的权限

要限制 Linux `test`用户运行脚本的能力，我们必须做两件事。首先，我们将用户的映射更改为`guest_u`，与之前的操作方式相同：

```
semanage login -a -s guest_u test

```

默认情况下，SELinux 允许映射到`guest_t`的用户从其主目录执行脚本。我们可以使用以下命令确认相同的情况：

```
getsebool allow_guest_exec_content

```

它将显示`guest_exec_content`已启用。因此，第二步是我们使用以下命令禁用`guest_exec_content`：

```
setsebool allow_guest_exec_content off

```

现在，我们更改了映射的测试用户将无法执行任何脚本，即使他对自己的主目录和在那里创建的文件有完全访问权限。

如果我们使用 grep 查看 SELinux 正在阻止`/var/log/messages`，它将向我们显示访问拒绝以及警报 ID。我们可以记录警报 ID 并运行：

```
sealert -l <alert id>

```

它将向我们显示有关访问拒绝的详细信息以及一些建议来删除它。

## 限制对服务的访问

假设我们有一个名为 admin 的用户，具有`sudo`访问权限，因此可以使用`sudo`运行命令来启动和停止`httpd`等服务。现在，即使用户具有`sudo`访问权限，我们也可以通过将其用户映射更改为`user_u`来阻止他管理对服务的访问，与之前的操作方式相同：

```
semanage login -a -s user_u admin

```

这将限制用户 admin 重新启动或停止服务。

我们可以通过以 root 身份运行`seinfo`命令来验证`user_u`的访问信息：

```
seinfo -uuser_u -x

```

![限制对服务的访问](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/ms-centos7-linux-svr/img/B04674_02_29.jpg)

此输出显示`user_u`可以访问的角色；它们是`object_r`和`user_r`。

让我们再进一步，并运行相同的命令来查找`user_r`角色被授权进入哪些域：

```
seinfo -ruser_r -x

```

![限制对服务的访问](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/ms-centos7-linux-svr/img/B04674_02_30.jpg)

角色可以进入的域有一个很长的列表。现在，让我们通过使用 grep 过滤输出来找出角色是否可以进入域`httpd_t`：

```
seinfo -ruser_r -x | grep httpd_t

```

这将返回空，这意味着`user_r`角色未被授权进入`httpd_t`域，因此无法启动`httpd`进程或守护程序。

# SELinux 审计日志

在 CentOS 7 中，我们应该查看两个与 SELinux 相关的错误和警报文件；它们如下：

+   /var/log/audit/audit.log

+   /var/log/messages

# SELinux 故障排除

SELinux 配备了一些非常有用的工具，用于检查错误和故障排除。我们已经看到其中一个，`sealert -l <alert id>`，我们通过查看`/var/log/messages`来收集警报 ID。还有另一个命令叫做`ausearch`，如果`auditd`服务正在运行，它也非常有助于检查错误，如下所示：

```
ausearch -m avc -c httpd

```

# 总结

在本章中，我们研究了 SELinux 的各个方面以及如何配置它；我们还演示了如何根据我们的需求使用它。然而，要小心，永远不要在生产系统上测试 SELinux。最好使用生产副本并首先在那里测试所有内容。当系统正确配置时，SELinux 设施将增强系统的安全性，但最好在需要严格安全控制时使用，并且只有在小心部署时才使用。

在下一章中，我们将看看 Linux 如何用于各种目的。


# 第三章：不同用途的 Linux

我们制定的设置服务器基础设施或数据中心的计划通常是相同的。我们总是尝试在运行的服务器之间组织服务，以满足我们的需求。在 Linux 系统上运行的服务器可以同时运行多个服务，也可以根据服务所需的处理能力和其在网络中的位置而选择只运行一个服务。根据用户的需求，系统管理员应始终准备好在其基础设施中设置或关闭服务。通常，对于基本系统安装，已经安装了一些服务，但配置不佳。

本章将涵盖大多数用户需要的一些主要 Linux 服务，以及如何设置、配置和操作它们。然后，我们将探讨这些服务的一些方面，如何保护它们，以及如何以最佳方式操作它们。

在本章中，我们将学习：

+   使用 iptables 和 IP 伪装配置网关服务器

+   安装 VPN 服务器

+   实施 BIND 作为 DNS 服务器

+   使用 Apache-MySQL-PHP 和 ModSecurity 设置和使用 Web 服务器

+   安装 FTP 服务器

+   在 Apache 和 FTP 中实施 OpenSSL

# 配置网关服务器

在许多网络基础设施中，系统管理员需要将他们的服务器和工作站分隔在多个子网络中。其他人使用可以使用**网络地址转换**（**NAT**）技术将私有网络地址与公共地址关联起来。Linux 网关服务器是可以帮助设置这种配置的常见解决方案之一。以下屏幕截图是一个架构示例，其中网关服务器用于通过本地和外部网络：

![配置网关服务器](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/ms-centos7-linux-svr/img/B04674_03_01.jpg)

根据要求，我们需要至少两个网络接口的 Linux 服务器（作为最佳实践）。然后我们需要在它们之间建立一个桥接。在本节中，我们将设置在公共（外部）和私有（本地）地址之间建立网关，使用 IP 转发和 NAT 规则将流量从私有网络路由到公共网络。我们将称外部网络为**广域网**（**WAN**），本地网络为**局域网**（**LAN**）。

### 注意

从本地网络生成的流量将看起来是从网关服务器到外部网络发出的。在这个例子中，我们将需要另一台机器在 LAN 网络中提供服务器。

首先，我们将设置`WAN`接口的网络配置。为此，有两个选项：要么接口将通过 DHCP（自动）获取其 IP 配置，要么我们手动设置它（静态）。在我们的情况下，我们将进行自动配置，因为我们的 WAN 网络由提供 DHCP 配置的路由器提供。

我们将首先编辑指定接口`eth0`的配置文件：

```
$ sudo nano /etc/sysconfig/network-scripts/ifcfg-eth0

```

文件将包含以下行：

```
HWADDR="XX:XX:XX:XX:XX:XX"
TYPE="Ethernet"
BOOTPROTO="dhcp"
DEFROUTE="yes"
PEERDNS="yes"
PEERROUTES="yes"
IPV4_FAILURE_FATAL="no"
IPV6INIT="yes"
IPV6_AUTOCONF="yes"
IPV6_DEFROUTE="yes"
IPV6_PEERDNS="yes"
IPV6_PEERROUTES="yes"
IPV6_FAILURE_FATAL="no"
DEVICE="eth0"
UUID="01f7dbb3-7ac8-406d-a88b-76082e0fa6eb"
ONBOOT="yes"

```

我们应该关注`BOOTPROTO`所写的行，这是用于网络配置的协议，我们需要确保它设置为`dhcp`。

默认安装将所有接口设置为 DHCP 配置，除非它们在安装期间或以后已被修改。

此外，我们需要确保`DEVICE`设置为我们将用于提供 DHCP 服务器的接口名称，并且与我们服务器中的命名相同（对于我们的情况，它是`eth0`）。然后，选项`ONBOOT`设置为`yes`。

### 注意

编辑文件后，如有需要，请确保在离开文本编辑器之前保存修改。

确保所有更改都已成功设置后，我们需要重新启动网络管理器，以便机器可以接受 DHCP 配置：

```
$ sudo systemctl restart network.service

```

在执行此步骤期间，可能会丢失网络连接。我们需要确保在此期间不需要它。

现在我们可以继续配置连接到 LAN 的网关服务器的第二个网络接口。对于此配置，我们需要使用静态 IP 地址。

与第一个接口类似，我们将编辑此接口`eth1`的配置文件：

```
$ sudo nano /etc/sysconfig/network-scripts/ifcfg-eth1

```

此文件还将包含一些配置文件，但我们只对其中的一些感兴趣：

```
HWADDR="XX:XX:XX:XX:XX:XX"
TYPE="Ethernet"
BOOTPROTO="dhcp"
DEFROUTE="yes"
PEERDNS="yes"
PEERROUTES="yes"
IPV4_FAILURE_FATAL="no"
IPV6INIT="yes"
IPV6_AUTOCONF="yes"
IPV6_DEFROUTE="yes"
IPV6_PEERDNS="yes"
IPV6_PEERROUTES="yes"
IPV6_FAILURE_FATAL="no"
DEVICE="eth1"
UUID=" b3fcc00e-a7d9-4b55-a32c-1e88e394aaf6"
ONBOOT="yes"

```

这是默认配置，因此我们需要将其从动态配置更改为静态配置。

修改将包括修改一些行和添加其他行。

我们首先将配置协议从`dhcp`更改为`static`，看起来像这样：

`BOOTPROTO="static"`

然后我们添加静态 IP 地址这一行：`IPADDR="10.0.1.1"`。

然后网络掩码，`NETMASK="255.255.255.0"`。

最后，我们确保选项`DEVICE`设置为`eth1`，选项`ONBOOT`设置为`yes`。

同样，为了确保此配置成功应用，我们需要重新启动网络服务：

```
$ sudo systemctl restart network.service

```

### 注意

如果在输入`ifconfig`时配置没有生效，要检查接口的配置，我们需要运行此命令：

```
$ sudo systemctl restart network.service
$ sudo systemctl status network.service

```

现在我们继续配置客户端，即将使用网关服务器的机器。因此，我们需要为其 LAN 网络配置接口。由于我们不限于一个特定的客户端，如果我们有图形界面，我们可以直接转到连接的接口并输入这些配置：

**IP 地址**：`10.0.1.2`

**网络掩码**：`255.255.255.0`

**网关**：`10.0.1.1`

对于 DNS 服务器，我们将选择非常可靠的 Google DNS。

**DNS 服务器**：`8.8.8.8`

### 注意

输入 Google DNS 服务器地址并不是义务。有些网站可能会阻止它，其他网站可能会使用他们的本地 DNS 服务器。根据需要，如果我们没有任何需求，Google DNS 就可以了。

如果我们需要使用另一台 CentOS 7 服务器，可能需要在静态服务器配置期间执行相同的步骤。

我们编辑接口的配置文件：

```
$ sudo nano /etc/sysconfig/network-scripts/ifcfg-eth1

```

通过将配置协议更改为`static`并添加这两行：

```
IPADDR="10.0.1.2"
NETMASK="255.255.255.0"

```

我们还确保`ONBOOT=yes`和`DEVICE=eth0`。

要使用 Google DNS 服务器，我们可以编辑`/etc/resolv.conf`文件：

```
$ nano /etc/resolv.conf

```

添加这两行：

```
nameserver 8.8.8.8
nameserver 8.8.4.4

```

然后重新启动网络服务：

```
$ sudo systemctl restart network.service

```

我们回到我们的网关服务器，然后开始进行 IP 转发的配置。首先，我们需要启用 IPv4 数据包转发：

```
$ sudo sysctl -w net.ipv4.ip_forward=1

```

为了在每次系统重启时保持配置，我们需要对 IP 转发配置文件进行修改：

```
$ sudo nano /etc/sysctl.conf

```

然后添加这一行并保存：

```
net.ipv4.ip_forward = 1

```

要重新加载对文件所做的配置，我们需要运行此命令：

```
$ sudo sysctl –w

```

可以通过此命令可视化当前配置：

```
$ sudo cat /proc/sys/net/ipv4/ip_forward

```

现在我们开始启用 NAT 配置。使用`iptables`，我们需要启用 IP 伪装。 `firewalld`是一个允许轻松配置`iptables`的服务。要使用`firewalld`，我们将依赖于命令`firewalld-cmd`，然后输入所需的配置。

我们首先在`firewalld`中配置 NAT。首先，我们将 LAN 网络设置为受信任的区域：

```
$ sudo firewall-cmd --permanent --zone=trusted --add-source=10.0.1.0/24

```

然后我们将 LAN 接口`eth1`集成到一个名为`internal`的区域中：

```
$ sudo firewall-cmd --change-interface=eth1 --zone=internal --permanent

```

我们也对 WAN 接口`eth0`进行相似的操作，将其设置为名为`external`的区域：

```
$ sudo firewall-cmd --change-interface=eth0 --zone=external --permanent

```

然后我们为外部 WAN 配置`masquerade`选项：

```
$ sudo firewall-cmd --zone=external --add-masquerade --permanent

```

对于可选的 DNS 配置，我们可以通过`internal`区域进行传递：

```
$ sudo firewall-cmd --zone=internal --add-service=dns –-permanent

```

在完成之前，我们确保 NAT 已配置为将 LAN 上的流量传递到 WAN 接口：

```
$ sudo firewall-cmd --permanent --direct --passthrough ipv4 -t nat -I POSTROUTING -o eth0 -j MASQUERADE -s 10.0.1.0/24 

```

最后，我们需要重新加载防火墙服务，以使配置生效：

```
$ sudo firewall-cmd –reload

```

在此点之后，网关服务器应该正常运行。要测试配置，我们需要从 LAN 网络上的任何机器上 ping 任何网站：

```
$ ping www.google.com

```

然后我们需要查看以下类型的输出，以知道我们的网关服务器是否正常工作：

```
PING www.google.com (216.58.210.196): 56 data bytes
64 bytes from 216.58.210.196: seq=0 ttl=50 time=55.799 ms
64 bytes from 216.58.210.196: seq=1 ttl=50 time=65.751 ms
64 bytes from 216.58.210.196: seq=2 ttl=50 time=54.878 ms
64 bytes from 216.58.210.196: seq=3 ttl=50 time=54.186 ms
64 bytes from 216.58.210.196: seq=4 ttl=50 time=93.656 ms
--- www.google.com ping statistics ---
5 packets transmitted, 5 packets received, 0% packet loss
round-trip min/avg/max = 54.186/64.854/93.656 ms

```

如果我们使用台式机并且不需要静态配置，我们建议使用 DHCP 服务器为所有客户端设置配置。即使对于更高级的 DHCP 配置，我们也可以通过它们的接口 MAC 地址将特定 IP 地址与服务器关联起来。

# 设置 VPN 服务器

OpenVPN 是一种开源软件应用程序，实现了**虚拟专用网络**（**VPN**）技术，用于创建路由或桥接配置和远程访问设施中的安全点对点或站点到站点连接。

作为本节的要求，我们需要一个 CentOS 7 服务器，具有安装一些软件包和对网络配置文件（Internet 和 root 访问）进行一些更改的能力。在以后的阶段，我们可能需要创建一些身份验证证书。我们也将介绍如何执行此操作。

首先，我们将开始安装所需的软件包。在执行此操作之前，OpenVPN 不在默认的 CentOS 标准存储库中，因此我们需要添加包含流行附加软件包的 EPEL 存储库：

```
$ sudo yum install epel-release

```

完成此命令后，我们可以启动 OpenVPN。我们还需要安装 RSA 生成器来生成我们将用于保护 VPN 连接的 SSL 密钥对：

```
$ sudo yum install openvpn easy-rsa

```

在执行该命令结束时，OpenVPN 和 easy-rsa 已成功安装在系统上。

现在我们转移到 OpenVPN 的配置部分。由于 OpenVPN 在其文档目录中有一个配置文件的示例，我们将使用`server.conf`文件作为我们的初始配置并在此基础上构建。为此，我们需要将其复制到`/etc`目录：

```
$ sudo cp /usr/share/doc/openvpn-*/sample/sample-config-files/server.conf /etc/openvpn/

```

然后我们可以编辑它以满足我们的需求：

```
$ sudo nano /etc/openvpn/server.conf

```

打开文件后，我们需要删除一些注释行并进行一些小的更改，如下所示（使用`nano`查找要更改的行，我们应该使用*Ctrl* + *w*，然后输入我们要查找的单词）。

首先，我们需要将 RSA 加密长度设置为 2048 字节，因此我们需要确保指示文件名的选项行将以以下方式使用。

```
dh dh2048.pem

```

### 注意

一些文章建议使用 1024 字节的 DH 密钥是有漏洞的，因此我们建议使用 2048 字节或更多的 DH 密钥以获得更好的安全性。这种漏洞称为 Logjam，有关更多详细信息，您可以在以下网址阅读更多内容：[`sourceforge.net/p/openvpn/mailman/message/34132515/`](http://sourceforge.net/p/openvpn/mailman/message/34132515/)

然后我们需要取消注释`push redirect-gateway def1 bypass-dhcp""`这一行，告诉客户端将所有流量重定向到 OpenVPN。

接下来，我们需要为客户端设置 DNS 服务器，因为它将无法使用 ISP 提供的 DNS。同样，我将使用 Google DNS `8.8.8.8`和`8.8.4.4`：

```
push "dhcp-option DNS 8.8.8.8"
push "dhcp-option DNS 8.8.4.4"

```

最后，为了使 OpenVPN 顺利运行，我们需要首先以无特权运行它。为此，我们需要通过名为`nobody`的用户和组运行它：

```
user nobody
group nobody

```

然后保存文件并退出。

到目前为止，OpenVPN 服务的配置部分已经完成。我们将继续进行证书和密钥生成部分，需要使用 Easy RSA 创建一些脚本。我们首先需要在 OpenVPN 的配置文件夹中创建一个 Easy RSA 的目录：

```
$ sudo mkdir -p /etc/openvpn/easy-rsa/keys

```

然后我们需要使用 Easy RSA 的预定义脚本填充文件夹，以生成密钥和证书：

```
$ sudo cp -rf /usr/share/easy-rsa/2.0/* /etc/openvpn/easy-rsa/

```

为了执行简单的 VPN 设置，我们将首先在`vars`文件中输入我们的信息一次并永久保存：

```
$ sudo nano /etc/openvpn/easy-rsa/vars

```

我们基本上正在更改以`export KEY_`开头的行，以更新它们的值以匹配所需组织的值，并且在某些时候我们可能需要取消注释它们：

```
export KEY_COUNTRY="UK"
export KEY_PROVINCE="GL"
export KEY_CITY="London"
export KEY_ORG="City-Center"
export KEY_EMAIL="user@packt.co.uk"
export KEY_OU="PacktPublishing"

# X509 Subject Field
export KEY_NAME="server"

export KEY_CN="openvpn.packt.co.uk"

```

然后保存文件并退出。

`KEY_NAME`字段代表文件`.key`和`.crt`的名称。

`KEY_CN`字段是我们应该放置指向 VPN 服务器的域或子域的地方。

为了确保在使用 OpenSSL 配置文件时不会出现由于版本更新而引起的问题，我们将从文件名中删除版本：

```
$ sudo cp /etc/openvpn/easy-rsa/openssl-1.0.0.cnf /etc/openvpn/easy-rsa/openssl.cnf

```

现在我们转到证书和密钥的创建。我们需要在`/etc/openvpn/easy-ras`文件夹中运行脚本：

```
$ cd /etc/openvpn/easy-rsa

```

然后我们在变量中启动源：

```
$ sudo source ./vars

```

之后，清除任何旧生成的密钥和证书：

```
$ sudo ./clean-all

```

然后我们构建认证机构，其信息已经定义为默认选项：

```
$ sudo ./build-ca

```

现在我们为 VPN 服务器创建密钥和证书。我们通过按*Enter*跳过挑战密码阶段。然后我们确保通过在最后一步输入`Y`来验证：

```
$ sudo ./build-key-server server

```

运行此命令时，如果它运行正确，我们应该看到以下消息：

```
Check that the request matches the signature
Signature ok
The Subject's Distinguished Name is as follows
countryName           :PRINTABLE:'UK'
stateOrProvinceName   :PRINTABLE:'GL'
localityName          :PRINTABLE:'London'
organizationName      :PRINTABLE:'City-Center'
organizationalUnitName:PRINTABLE:'PacktPublishing'
commonName            :PRINTABLE:'server'
name                  :PRINTABLE:'server'
emailAddress          :IA5STRING:'user@packt.co.uk'

```

此外，我们需要生成 Diffie-Hellman（`dh`）密钥交换。与其他命令相比，这可能需要更长的时间：

```
$ sudo ./build-dh

```

完成此步骤后，我们将准备好所有的密钥和证书。我们需要复制它们，以便它们可以被我们的 OpenVPN 服务使用：

```
$ cd /etc/openvpn/easy-rsa/keys
$ sudo cp dh2048.pem ca.crt server.crt server.key /etc/openvpn

```

这个 VPN 服务器的所有客户端都需要证书进行身份验证。因此，我们需要与所需的客户端共享这些密钥和证书。最好为需要连接的每个客户端生成单独的密钥。

在这个例子中，我们只为一个客户端生成密钥：

```
$ cd /etc/openvpn/easy-rsa
$ sudo ./build-key client

```

通过这一步，我们可以说我们已经完成了证书。

现在是路由步骤。我们将使用`iptables`直接进行路由配置，而无需使用`firewalld`。

如果我们只想使用`iptables`配置，我们首先要确保其服务已安装：

```
$ sudo yum install iptables-services

```

然后禁用`firewalld`服务：

```
$ sudo systemctl mask firewalld
$ sudo systemctl enable iptables
$ sudo systemctl stop firewalld
$ sudo systemctl start iptables
$ sudo iptables --flush

```

然后我们添加规则到`iptables`，进行路由到 OpenVPN 子网的转发：

```
$ sudo iptables -t nat -A POSTROUTING -s 10.0.1.0/24 -o eth0 -j MASQUERADE
$ sudo iptables-save > /etc/sysconfig/iptables

```

然后我们需要通过编辑文件`sysctl.conf`在`sysctl`中启用 IP 转发：

```
$ sudo nano /etc/sysctl.conf

```

然后添加以下行：

```
net.ipv4.ip_forward = 1

```

最后，重新启动网络服务，使此配置生效：

```
$ sudo systemctl restart network.service

```

现在我们可以启动 OpenVPN 服务，但在这之前，我们需要将其添加到`systemctl`：

```
$ sudo systemctl -f enable openvpn@server.service

```

然后我们可以启动服务：

```
$ sudo systemctl start openvpn@server.service

```

如果我们想要检查服务是否正在运行，可以使用命令`systemctl`：

```
$ sudo systemctl status openvpn@server.service

```

我们应该看到这条消息的活动状态为`active (running)`：

```
openvpn@server.service - OpenVPN Robust And Highly Flexible Tunneling Application On server
 Loaded: loaded (/usr/lib/systemd/system/openvpn@.service; enabled)
 Active: active (running) since Thu 2015-07-30 15:54:52 CET; 25s ago

```

经过这个检查，我们可以说我们的 VPN 服务器配置已经完成。现在我们可以去客户端配置，不论操作系统如何。我们需要从服务器复制证书和密钥。我们需要复制这三个文件：

```
/etc/openvpn/easy-rsa/keys/ca.crt
/etc/openvpn/easy-rsa/keys/client.crt
/etc/openvpn/easy-rsa/keys/client.key

```

有各种工具可以将这些文件从服务器复制到任何客户端。最简单的是`scp`，这是两台 Unix 机器之间的 shell 复制命令。对于 Windows 机器，我们可以使用文件夹共享工具，如 Samba，或者我们可以使用另一个等效于 SCP 的工具**WinSCP**。

从客户端机器开始，我们首先复制所需的文件：

```
$ scp user@openvpn.packt.co.uk:/etc/openvpn/easy-rsa/keys/ca.crt /home/user/
$ scp user@openvpn.packt.co.uk:/etc/openvpn/easy-rsa/keys/client.crt /home/user/
$ scp user@openvpn.packt.co.uk:/etc/openvpn/easy-rsa/keys/client.key /home/user/

```

复制完成后，我们应该创建一个名为`client.ovpn`的文件，这是 OpenVPN 客户端的配置文件，可以帮助设置客户端连接到服务器提供的 VPN 网络。文件应包含以下内容：

```
client
dev tun
proto udp
remote server.packt.co.uk 1194
resolv-retry infinite
nobind
persist-key
persist-tun
comp-lzo
verb 3
ca /home/user/ca.crt
cert /home/user/client.crt
key /home/user/client.key

```

我们需要确保第一行包含在密钥和证书中输入的客户端名称。之后，远程应该是服务器的公共 IP 地址或其域地址。最后，应该从服务器复制三个客户端文件的正确位置。

文件`client.ovpn`可以与多个 VPN 客户端（Linux 的 OpenVPN 客户端，MAC OS X 的 Tunnelblick，Windows 的 OpenVPN Community Edition Binaries）一起使用，以便配置它们连接到 VPN。

在 CentOS 7 服务器上，我们将使用 OpenVPN 客户端。要使用此配置，我们使用命令`openvpn --config`：

```
$ sudo openvpn --config ~/path/to/client.ovpn

```

通过将客户端连接到 VPN 服务器，我们可以确认我们的 VPN 服务运行良好。

# 实施 BIND 作为 DNS 服务器

BIND 是最广泛使用的开源名称服务器应用程序。它帮助实现互联网的**域名系统**（**DNS**）协议。它提供了一个强大而稳定的平台，用于构建分布式计算系统，确保这些系统完全符合已发布的 DNS 标准。它通过将这些问题发送到适当的服务器并对服务器的回复做出适当的响应来帮助解决有关名称的查询。

作为 BIND 实现的示例，我们将设置一个内部 DNS 服务器来解析网络内部的一些公共 IP 地址，以简化大型环境中的映射。

我们需要以下先决条件来实现 BIND：

+   一个服务器上安装和配置 BIND

+   两台机器，可以是服务器也可以是简单的工作站，用来测试 DNS 服务

+   需要 root 权限才能设置 BIND 并配置网络以从我们的内部 DNS 服务器解析

首先，我们将在我们的 DNS 服务器上安装 BIND：

```
$ sudo yum install bind bind-utils

```

安装完 BIND 后，我们开始配置我们的 DNS 服务器。

BIND 服务有一堆配置文件，这些文件从它的主配置文件`named.conf`中包含，这个文件与 BIND 运行的进程相关联：

```
$ sudo nano /etc/named.conf

```

在文件的开头，我们需要在`options`块之前添加一个块，名为`acl "trusted"`，在这里我们将定义允许进行递归 DNS 查询的客户端列表。由于我们的服务器将为两个子网提供服务，我们将添加它的两个地址：

```
acl "trusted" {
 192.168.8.12;  # Our DNS server inside the subnet 192.168.8.0/24
 10.0.1.1;  # Our DNS server inside the subnet 10.0.1.0/24
 192.168.8.5;    # Webserver
 10.0.1.2;    # client host
};

```

我们需要在`options`内进行一些修改。由于我们只使用 IPv4，我们需要注释掉 IPv6 行：

```
# listen-on-v6 port 53 { ::1; }; 

```

为了确保 DNS 服务器将在两个子网中监听，我们将添加以下两个地址：

```
listen-on port 53 { 127.0.0.1; 192.168.8.12; 10.0.1.1; };

```

使用 IP 地址`192.168.8.12`作为 DNS 服务器的 IP 地址。

然后我们将`allow-query`行从指向`localhost`改为指向`trusted`客户端 ACL：

```
allow-query { trusted; };

```

### 注意

如果我们不完全依赖我们的 DNS 服务器来响应所有查询，我们可以通过在`options`中输入以下命令来使用辅助 DNS 服务器：

```
allow-transfer { localhost; 192.168.8.1; };

```

最后，在文件的末尾，我们需要添加包含本地文件配置的行：

```
include "/etc/named/named.conf.local";

```

然后我们保存文件，转到本地文件配置以设置 DNS 区域：

```
$ sudo nano /etc/named/named.conf.local

```

由于我们是创建它的人，所以文件将是空的，因此我们需要用必要的区域填充它。

首先，我们将添加正向区域。为此，我们需要输入以下行：

```
zone "packt.co.uk" {
type master;
file "/etc/named/zones/db.packt.co.uk";  # The location of the zone configuration file.
};

```

现在我们将添加反向区域。由于我们的第一个 LAN 在`192.168.8.0/24`，我们从反向区域名称开始，它将是`8.168.192`，即`192.168.8`的反向：

```
zone "8.168.192.in-addr.arpa" {
type master;
file "/etc/named/zones/db.8.168.192";  # The subnet of 192.168.8.0/24
};

```

现在我们对`10.0.1.0/24`上的第二个 LAN 做同样的操作，所以它的反向区域名称是`1.0.10`：

```
zone "1.0.10.in-addr.arpa" {
type master;
file "/etc/named/zones/db.1.0.10";  # The subnet of 10.0.1.0/24
};

```

我们需要对网络中的所有子网做同样的操作，然后保存文件。

完成设置区域和反向区域后，我们继续创建并填写它们对应的文件。

我们首先创建转发文件，这是我们为正向 DNS 查找定义 DNS 记录的地方。我们创建一个文件夹，用来放置所有区域文件。然后我们开始在其中创建我们的区域文件：

```
$ sudo chmod 755 /etc/named
$ sudo mkdir /etc/named/zones

```

然后我们创建正向区域文件并填写它：

```
$ sudo nano /etc/named/zones/db.packt.co.uk

```

我们需要添加以下行。首先是 SOA 记录，通过添加 DNS 服务器的域名，我们需要每次编辑区域文件时增加序列值，以便在重新启动服务后生效：

```
$TTL    604800
@  IN  SOA  server.packt.co.uk.  admin.packt.co.uk.  (
3    ; Serial
604800    ; Refresh
86400    ; Retry
2419200  ; Expire
604800 )  ; Negative Cache TTL

```

对于序列号，我们可以通过使其看起来像一个`日期：{yyyymmmdddss} yyyy = 年`，`mm = 月`，`dd = 日`，`ss = 一个`序列号来使其更易理解。

然后我们添加名称服务器记录：

```
; name servers - NS records 
IN  NS  server.packt.co.uk.

```

然后我们为属于该区域的主机添加`A 记录`，其中将包括我们希望使用我们的 DNS 服务器寻址的每台机器，无论是服务器还是工作站：

```
; name servers - A records
server.packt.co.uk.  IN  A  192.168.8.12

; 192.168.8.0/24 - A records
server2.packt.co.uk.  IN  A  192.168.8.5

; 10.0.1.0/24 - A records
client1.packt.co.uk.  IN  A  10.0.1.2
server.packt.co.uk.  IN  A  10.0.1.1

```

现在我们创建反向区域文件。这是我们为反向 DNS 查找定义 DNS PTR 记录的地方。

我们从第一个反向区域`db.1.0.10`开始：

```
$ sudo nano /etc/named/zones/db.1.0.10

```

与第一个区域文件一样，我们需要定义 SOA 域：

```
$TTL    604800
@  IN  SOA  server.packt.co.uk.  admin.packt.co.uk. (
 3         ; Serial
 604800         ; Refresh
 86400         ; Retry
 2419200         ; Expire
 604800 )       ; Negative Cache TTL

```

然后是名称服务器记录：

```
; name servers - NS records
IN  NS  server.packt.co.uk.

```

最后，我们添加列出子网区域上具有 IP 地址的所有机器的 PTR 记录：

```
; PTR Records
1  IN  PTR  server.packt.co.uk.  ; 10.0.1.1
2  IN  PTR  client1.packt.co.uk.  ; 10.0.1.2

```

然后我们做第二个反向区域文件`db.8.168.192`：

```
$ sudo nano /etc/named/zones/db.8.168.192

```

我们添加 SOA 域：

```
$TTL    604800
@  IN  SOA  server.packt.co.uk.  admin.packt.co.uk. (
 3         ; Serial
 604800         ; Refresh
 86400         ; Retry
 2419200         ; Expire
 604800 )       ; Negative Cache TTL

```

然后我们添加名称服务器记录：

```
; name servers - NS records
IN  NS  server.packt.co.uk.

```

最后我们完成 PTR 记录：

```
; PTR Records
12  IN  PTR  server.packt.co.uk.  ; 192.168.8.12
5  IN  PTR  webserver.packt.co.uk.  ; 192.168.8.5

```

我们保存所有文件。然后通过检查文件`named.conf*`的语法来检查 BIND 配置：

```
$ sudo named-checkconf

```

如果没有显示错误，这意味着所有配置文件都写得很好，没有语法错误。否则，请尝试跟踪错误并使用错误消息进行修复。

然后使用命令`named-checkzone`在每个区域中检查区域文件（如果有多个）：

```
$ sudo named-checkzone packt.co.uk /etc/named/zones/db.packt.co.uk

```

如果区域成功设置，我们应该看到这种消息：

```
zone packt.co.uk/IN: loaded serial 3
OK

```

我们应该看到反向区域的相同内容：

```
$ sudo named-checkzone 1.0.10.in-addr.arpa /etc/named/zones/db.1.0.10
$ sudo named-checkzone 8.168.192.in-addr.arpa /etc/named/zones/db.8.168.192

```

如果一切配置正确，我们也应该看到相同的消息。否则，我们需要排除以下错误消息：

```
zone 8.168.192.in-addr.arpa/IN: loaded serial 3
OK

```

在检查所有配置后，我们现在准备启动 BIND 服务。

在此之前，我们需要确保我们的防火墙允许我们这样做。我们需要使用`Firewalld`服务打开端口 53：

```
$ sudo firewall-cmd --permanent --add-port=53/tcp
$ sudo firewall-cmd --permanent --add-port=53/udp
$ sudo firewall-cmd --reload

```

重新加载防火墙后，更改将生效，现在我们可以启动 DNS 服务：

```
$ sudo systemctl start named

```

然后启用它，以便它可以在系统启动时启动：

```
$ sudo systemctl enable named

```

通过这一步，DNS 服务器现在已准备好接收和响应 DNS 查询。

现在让我们进行客户端配置以测试 DNS 服务器。在 Linux 服务器上，我们只需要通过添加名称服务器 IP 地址和搜索域来修改`resolv.conf`文件：

```
$ sudo nano /etc/resolv.conf

```

通过添加以下行，然后保存：

```
search nyc3.example.   # Our domain
nameserver 10.0.1.1   # The DNS server IP address

```

现在我们可以开始测试。我们将使用简单的 ping 和命令`nslookup`。ping 只会测试我们是否能够通过其域名到达该机器：

```
$ ping webserver.packt.co.uk
PING webserver.packt.co.uk (192.168.8.5): 56 data bytes
64 bytes from 192.168.8.5: icmp_seq=0 ttl=64 time=0.046 ms
64 bytes from 192.168.8.5: icmp_seq=1 ttl=64 time=0.092 ms
64 bytes from 192.168.8.5: icmp_seq=2 ttl=64 time=0.117 ms
64 bytes from 192.168.8.5: icmp_seq=3 ttl=64 time=0.092 ms

--- webserver.packt.co.uk ping statistics ---
4 packets transmitted, 4 packets received, 0.0% packet loss
round-trip min/avg/max/stddev = 0.046/0.087/0.117/0.026 ms

```

还有其他工具可以在测试 DNS 服务时提供更详细的结果，例如`dig`和`nslookup`进行简单的 DNS 查找：

```
$ nslookup webserver.packt.co.uk
Server:    10.0.1.1
Address:    10.0.1.1#53

Name:      webserver.packt.co.uk
Address:     192.168.8.5 webserver.packt.co.uk

```

运行 DNS 查找后，我们将尝试进行反向 DNS 查找：

```
$ nslookup webserver.packt.co.uk
Server:    10.0.1.1
Address:    10.0.1.1#53

5.8.168.192.in-addr.arpa  name = webserver.packt.co.uk.

```

在运行所有这些测试后，我们应该检查所有值是否为`true`，以确认我们拥有一个完全正常工作的 DNS 服务器。

# 使用 Apache-MySQL-PHP 设置 Web 服务器

Linux 服务器提供的常见服务之一是作为 Web 服务器，使其用户能够在安全、快速和可靠的位置托管其 Web 内容，可从世界各地浏览。在本节中，我们将向您展示如何在 CentOS 7 服务器上设置可靠的 Web 服务器，并使用一些安全模块来保护网站，并实施**内容管理系统**（**CMS**）：Joomla。

我们的 Web 服务器将托管动态网站和 Web 应用程序。因此，我们将安装一个 LAMP（堆栈）服务器，代表一个具有 Apache Web 服务器的 Linux 操作系统，其中站点数据将存储在 MySQL 数据库中（使用 MariaDB，这是 MySQL 关系数据库管理系统的社区开发分支，旨在在 GNU GPL 下保持免费），并且动态内容由 PHP 处理。

我们将从安装 Apache Web 服务器开始，这是世界上最流行的 Web 服务器：

```
$ sudo yum install httpd

```

在命令结束时，Apache Web 服务器已成功安装。我们可以使用`systemctl`命令启动它：

```
$ sudo systemctl start httpd.service

```

在测试服务之前，我们需要确保服务器防火墙允许 Web 访问。因此，我们需要打开 Apache 正在提供的端口，HTTP（80）和 HTTPS（443）：

```
$ sudo firewall-cmd --permanent --add-service=http
$ sudo firewall-cmd --permanent --add-service=https
$ sudo firewall-cmd --reload

```

现在我们可以通过在同一网络内的任何其他机器的 Web 浏览器中键入服务器的 IP 地址（`http://Server_IP_Address`）来测试 Web 服务器。我们应该看到类似于这样的东西：

![使用 Apache-MySQL-PHP 设置 Web 服务器](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/ms-centos7-linux-svr/img/B04674_03_02.jpg)

确认服务正常运行后，我们需要将其添加到系统启动服务中：

```
$ sudo systemctl enable httpd.service

```

现在我们将在 Apache 上设置两个虚拟主机，以展示 Apache 支持多个网站的能力。

接下来，我们将对 Apache 配置文件进行一些更改，因此我们将创建一个备份文件：

```
$ sudo cp /etc/httpd/conf/httpd.conf /etc/httpd/conf/httpd.conf.backup

```

Apache 有能力将其功能和组件分离为可以独立定制和配置的单元。这些单元称为**虚拟主机**。虚拟主机允许我们托管多个域。每个配置的域将访问者引导到指定给网站的特定文件夹，其中包含其信息。只要服务器能够处理吸引网站的流量，这种技术就是可扩展的。

首先，我们需要创建我们将存储网站的文件夹。目录`/var/www/`是我们的 Web 服务器根目录：

```
$ sudo mkdir –p /var/www/packt.co.uk/home
$ sudo mkdir –p /var/www/packt2.co.uk/home

```

然后我们授予这些文件夹权限，通过将所有权从根用户（刚刚创建它们的用户）更改为`$USER`（当前登录的用户）：

```
$ sudo chown –R $USER:$USER /var/www/packt.co.uk/home
$ sudo chown –R $USER:$USER /var/www/packt2.co.uk/home

```

为了完全测试虚拟主机，我们需要创建一个示例 HTML 页面，以在客户端 Web 浏览器中打开：

```
$ nano /var/www/packt.co.uk/home/index.html

```

然后我们添加一些 HTML 代码来填充页面：

```
<html>
  <head>
    <title>Packt Home Page</title>
  </head>
  <body>
    <h1>Welcome to the home page of the Packt Publishing 1st example web server </h1>
  </body>
</html>
```

同样地，对于第二个主机，我们需要创建相同的文件，但内容不同以区分：

```
$ nano /var/www/packt2.co.uk/home/index.html

```

然后我们放入以下 HTML 代码：

```
<html>
  <head>
    <title>Packt2 Home Page</title>
  </head>
  <body>
    <h1>Welcome to the home page of the Packt Publishing 2nd example web server </h1>
  </body>
</html>
```

现在我们需要在 Apache 配置文件夹中创建虚拟主机文件。我们首先创建需要放置文件的文件夹：

```
$ sudo mkdir /etc/httpd/sites-available
$ sudo mkdir /etc/httpd/sites-enabled

```

然后我们需要告诉 Apache 服务使用`sites-enabled`目录中提供的配置，方法是编辑 Apache 主配置文件。此配置也可以作为配置目录`/etc/httpd/conf.d`获得。

```
$ sudo nano /etc/httpd/conf/httpd.conf.

```

然后我们在文件末尾添加以下行：

```
IncludeOptional sites-enabled/*.conf

```

我们保存文件，然后移动到`sites-available`文件夹中创建虚拟主机文件。文件名应该以`.conf`结尾，这样 Apache 服务才能使用它：

```
$ sudo nano /etc/httpd/sites-available/packt.co.uk.conf

```

然后我们在其中放入以下配置：

```
<VirtualHost *:80>

 ServerName www.packt.co.uk
 ServerAlias packt.co.uk
 DocumentRoot /var/www/packt.co.uk/home
 ErrorLog /var/log/httpd/packt.co.uk_error.log
 CustomLog /var/log/httpd/packt.co.uk_requests.log combined

</VirtualHost>

```

我们保存文件，然后对第二个虚拟主机做同样的操作：

```
$ sudo nano /etc/httpd/sites-available/packt2.co.uk.conf

```

然后我们在其中放入以下命令：

```
<VirtualHost *:80>

 ServerName www.packt2.co.uk
 ServerAlias packt2.co.uk
 DocumentRoot /var/www/packt2.co.uk/home
 ErrorLog /var/log/httpd/packt2.co.uk_error.log
 CustomLog /var/log/httpd/packt2.co.uk_requests.log combined

</VirtualHost>

```

在配置两个站点之后，我们现在可以激活虚拟主机以供使用：

```
$ sudo ln -s /etc/httpd/sites-available/packt.co.uk.conf /etc/httpd/sites-enabled/packt.co.uk.conf
$ sudo ln -s /etc/httpd/sites-available/packt2.co.uk.conf /etc/httpd/sites-enabled/packt2.co.uk.conf

```

为了确保我们所做的所有配置都会生效，我们需要使用以下命令之一重新启动 Apache 服务：

```
$ sudo apachectl restart
$ sudo systemctl restart httpd.service

```

### 注意

如果我们遇到与服务器主机名相关的任何错误，请尝试使用此命令进行更改并消除错误：

```
$ sudo hostnamectl set-hostname --static packt.co.uk

```

在我们的情况下，这些域名不是公共的，也没有被任何 DNS 服务器定义。因此，我们可以将它们添加到我们的本地 DNS 服务器，或者只需将它们添加到我们客户端机器（我们将在其中打开 Web 浏览器的机器）的`/etc/hosts`文件中。此步骤仅用于测试。通常，我们应该在 ISP 的 DNS 服务器或本地 DNS 服务器上定义它们：

```
$ sudo nano /etc/hosts

```

然后我们添加两行，将我们的 Web 服务器 IP 地址与我们创建的两个域关联起来：

```
Server_IP_Address    packt.co.uk
Server_IP_Address    packt2.co.uk

```

然后我们转到客户端 Web 浏览器，输入域名到地址栏中：

```
http://packt.co.uk

```

我们应该看到与第一个域关联的页面。我们对第二个域做同样的操作。如果测试有效，我们确认我们的虚拟主机已正确创建。

现在我们可以开始保护 Apache 免受影响世界网站的最常见攻击之一。暴力攻击或**分布式拒绝服务**（**DDoS**）攻击是一种向同一 Web 服务器发送多个请求以使其超载并使其无法访问的攻击。现在我们将设置模块来帮助保护我们的 Web 服务器免受此类攻击。`Mod_Security`和`Mod_evasive`是基本模块，将帮助检测和防止入侵，并帮助加强 Web 服务器对暴力或 DDoS 攻击的保护。首先，我们需要使用软件包管理器安装这些模块。我们要求系统已经安装了 EPEL 存储库：

```
$ sudo yum install mod_security mod_evasive

```

因此，为了验证安装是否完成，我们需要查看`/etc/httpd/conf.d/`文件夹中是否创建了两个文件：

```
$ sudo ls /etc/httpd/conf.d/mod_*
/etc/httpd/conf.d/mod_evasive.conf
/etc/httpd/conf.d/mod_security.conf

```

为了确保 Apache 在启动时加载这两个模块，我们需要向两个配置文件添加一些配置选项，这些选项在安装后已经创建：

```
$ sudo nano /etc/httpd/conf.d/mod_evasive.conf
$ sudo nano /etc/httpd/conf.d/mod_security.conf

```

然后我们分别添加以下行，或者确保它们是取消注释的：

```
LoadModule evasive20_module modules/mod_evasive24.so
LoadModule security2_module modules/mod_security2.so

```

现在我们可以重新启动 Apache，以便配置生效：

```
$ sudo service httpd restart

```

我们首先要配置`Mod_Security`模块。因此，我们需要设置一个**核心规则集**（**CRS**）。我们将下载一个免费的 CRS（OWASP）来为我们的 Web 服务器配置它。在下载其包之前，我们需要创建一个目录来放置规则：

```
$ sudo mkdir /etc/httpd/crs-tecmint
$ cd /etc/httpd/crs-tecmint
$ sudo wget https://github.com/SpiderLabs/owasp-modsecurity-crs/tarball/master

```

之后，我们可以在那里提取包，并将其名称更改为合适的名称：

```
$ sudo tar –xzvf master
$ sudo mv SpiderLabs-owasp-modsecurity-crs-c63affc/ owasp-modsecurity-crs

```

现在我们可以开始配置`Mod_Security`模块。我们需要将示例文件配置复制到另一个没有`.example`扩展名的文件中：

```
$ cd owasp-modsecurity-crs
$ sudo cp modsecurity_crs_10_setup.conf.example modsecurity_crs_10_setup.conf

```

然后告诉 Apache 使用这个模块，通过将以下行插入到 Apache 主配置文件中：

```
$ sudo nano /etc/httpd/conf/httpd.conf
<IfModule security2_module>
    Include crs-tecmint/owasp-modsecurity-crs/modsecurity_crs_10_setup.conf
    Include crs-tecmint/owasp-modsecurity-crs/base_rules/*.conf
</IfModule>
```

现在我们需要在`/etc/httpd/modsecurity.d/`目录中创建一个配置文件，以便在有新版本时更容易升级 CRSs：

```
$ sudo nano /etc/httpd/modsecurity.d/tecmint.conf

```

创建新文件后，我们需要添加以下行并保存文件：

```
<IfModule mod_security2.c>
 SecRuleEngine On
 SecRequestBodyAccess On
 SecResponseBodyAccess On 
 SecResponseBodyMimeType text/plain text/html text/xml application/octet-stream 
 SecDataDir /tmp
</IfModule>

```

通过这一步，我们可以说`Mod_Security`模块已经成功安装和配置。现在我们可以转移到下一个模块`Mod_Evasive`。要配置这个模块，我们需要确保主配置文件中的一些行没有被注释掉：

```
$ sudo nano /etc/httpd/conf.d/mod_evasive.conf

```

然后检查`IfModule`选项是否成功设置：

```
<IfModule mod_evasive24.c>
 DOSHashTableSize    3097
 DOSPageCount        2
 DOSSiteCount        50
 DOSPageInterval     1
 DOSSiteInterval     1
 DOSBlockingPeriod   10
</IfModule>

```

让我们详细了解一下之前的代码：

+   `DOSHashTableSize`：此选项指定用于跟踪 IP 活动的哈希表的大小

+   `DOSPageCount`：来自一个 IP 地址对一个资源的相同请求的合法数量

+   `DOSSiteCount`：与`DOSPageCount`相同，但适用于所有可能发生的请求

+   `DOSBlockingPeriod`：排除顶部选项的 IP 的黑名单期限

这些数字是配置的示例。我们可以根据需要进行更改。

一个额外的有用选项是`DOSSystemCommand`，它有助于运行一些可以阻止 IP 地址的脚本。为此，我们需要将其添加到配置文件中。

```
DOSSystemCommand "sudo /etc/httpd/scripts/ban_ip.sh %s".

```

并且我们需要在适当的位置创建脚本：

```
$ sudo nano /etc/httpd/scripts/ban_ip.sh

```

我们应该在其中添加以下代码：

```
#!/bin/sh
IP=$1
IPTABLES="/sbin/iptables"
MOD_EVASIVE_LOGDIR=/tmp
$IPTABLES -I INPUT -s $IP -j DROP
echo "$IPTABLES -D INPUT -s $IP -j DROP" | at now + 2 hours
rm -f "$MOD_EVASIVE_LOGDIR"/dos-"$IP"

```

这个脚本需要一些系统修改才能正常运行。让我们将其设置为可执行：

```
$ sudo chmod +x /etc/httpd/scripts/ban_ip.sh

```

我们需要在`Sudoers`规则文件中添加一行：

```
$ sudo nano /etc/Sudoers
apache ALL=NOPASSWD: /usr/local/bin/scripts/ban_ip.sh
Defaults:apache !requiretty

```

出于安全原因，直接编辑文件可能会有害。我们建议使用以下命令：

```
$ sudo visudo

```

其次，这个脚本与`iptables`一起工作，所以我们需要停用`Firewalld`并安装并激活`iptables`：

```
$ sudo yum update && yum install iptables-services
$ sudo systemctl enable iptables
$ sudo systemctl start iptables
$ sudo systemctl status iptables

```

然后应用新配置，我们需要重新启动 Apache 服务：

```
$ sudo systemctl restart httpd

```

最后，我们的 Web 服务器已经得到了很好的安全和配置。

作为一个小提示，默认情况下，Apache 服务器显示它所运行的操作系统和版本。有时它会显示安装的模块。这些信息对攻击者来说可能非常有价值，因此我们需要禁用显示这些信息：

```
$ sudo nano /etc/httpd/conf/httpd.conf

```

然后我们将以下两行更改为如下所示：

```
ServerSignature Off
ServerTokens Prod

```

现在我们可以开始数据库安装。服务器中的数据库对于执行动态网站并用作存储其数据的媒介是至关重要的。通常，在旧的 Linux 版本上，我们将 MySQL 安装为默认数据库服务器，但最近大多数 Linux 发行版已经迁移到了 MariaDB 数据库服务器。为此，我们需要使用软件包管理器进行安装：

```
$ sudo yum install mariadb-server mariadb

```

我们将安装一些默认存储库中不可用的模块。因此，我们需要安装 EPEL 存储库，以确保我们在这一部分得到覆盖：

```
$ sudo yum install epel-release

```

然后我们启动服务并启用它以便下次启动：

```
$ sudo systemctl start mariadb
$ sudo systemctl enable mariadb.service

```

为了拥有一个良好安全的数据库服务器，我们需要使用 MariaDB 安全安装命令。这个命令非常有用，可以通过各种选项自定义数据库服务器的安全级别：

```
$ sudo mysql_secure_installation

```

### 注意

在执行命令时，我们应该确保为数据库指定一个强大的根密码。

为了确保我们的数据库服务器正常工作，我们可以运行 CLI 界面并运行一些基本的 SQL 命令：

```
$ sudo mysql -u root -p

```

我们输入已在安全安装期间设置的密码，然后就可以进入 MariaDB CLI 了。要退出，只需输入`quit`。

为了不必每次输入密码，我们可以将密码写入位于我们的主目录`~/.my.cnf`中的文件，并添加以下行：

```
[mysql]\npassword=password

```

现在我们可以开始安装 PHP5。将来，我们将添加`phpmyadmin`，这是一个允许通过网页浏览器访问的图形界面管理 MariaDB 数据库的程序。首先，我们开始安装 PHP5 和支持 MySQL 的库：

```
$ sudo yum install php php-mysql

```

我们可以编辑`/etc/php/php.ini`以配置错误消息的放置位置，上传文件到网站的最大大小（对于处理文件的动态网站非常有用），等等。

我们可以进行一些小的配置，使 PHP 更安全。首先，我们可以删除信息和错误消息，并将它们记录到日志文件中。然后关闭远程代码执行。此外，如果我们不需要在网站上上传文件，我们可以禁用它。我们需要使用安全的 SQL 模式。最后，我们禁用危险的 PGP 函数：

```
$ sudo nano /etc/php.d/secutity.ini

```

然后更改以下行：

```
expose_php=Off
display_errors=Off

log_errors=On
error_log=/var/log/httpd/php_scripts_error.log

allow_url_fopen=Off
allow_url_include=Off

sql.safe_mode=On
magic_quotes_gpc=Off

disable_functions =exec,passthru,shell_exec,system,proc_open,popen,curl_exec,curl_multi_exec,parse_ini_file,show_source

```

为了保护 PHP 免受已知和未知的漏洞，我们考虑安装 Suhosin 高级保护系统：

```
$ sudo yum install php-devel
$ sudo cd /usr/local 
$ sudo wget –c https://download.suhosin.org/suhosin-0.9.38.tar.gz
$ sudo tar -xzvf suhosin-0.9.38.tar.gz
$ sudo cd suhosin-0.9.38
$ sudo phpize
$ sudo ./configure
$ sudo make 
$ sudo make install

```

现在我们配置 Apache 以使用它：

```
$ sudo echo 'extension=suhosin.so' > /etc/php.d/suhosin.ini

```

然后我们重新启动 Apache：

```
$ sudo systemctl restart httpd

```

现在，我们开始安装`phpmyadmin`所需的软件包：

```
$ sudo yum install php-gd php-pear php-mbstring 

```

安装它们后，我们安装`phpmyadmin`软件包：

```
$ sudo yum install phpMyAdmin

```

我们需要进行一些配置，以便在服务器之外启用对`phpmyadmin`界面的访问。我们需要编辑它的配置文件：

```
$ sudo nano /etc/httpd/conf.d/phpMyAdmin.conf

```

然后我们需要注释掉旧的配置：

```
#<Directory /usr/share/phpMyAdmin/>
#   <IfModule mod_authz_core.c>
#     # Apache 2.4
#     <RequireAny>
#       Require ip 127.0.0.1
#       Require ip ::1
#     </RequireAny>
#   </IfModule>
#   <IfModule !mod_authz_core.c>
#     # Apache 2.2
#     Order Deny,Allow
#     Deny from All
#     Allow from 127.0.0.1
#     Allow from ::1
#   </IfModule>
#</Directory>

```

并添加授予访问权限的新配置：

```
<Directory /usr/share/phpMyAdmin/>
 Options none
 AllowOverride Limit
 Require all granted
</Directory>

```

最后，我们需要将身份验证从`cookie`更改为`http`：

```
$ sudo nano /etc/phpMyAdmin/config.inc.php

```

并将此行更改为以下内容：

```
$cfg['Servers'][$i]['auth_type']     = 'http';

```

为了使更改生效，我们需要重新启动 Apache：

```
$ sudo systemctl restart httpd.service

```

要测试它是否起作用，我们只需要在与 Web 服务器位于同一网络的任何 Web 浏览器中输入`http://Server_IP_Addr` `ess/phpmyadmin`。然后我们需要提供数据库根用户及其密码以登录。我们可以通过编辑其配置文件来保护`phpMyAdmin`，例如限制可以访问该服务的源 IP 地址。

为了能够安装**内容管理系统**（**CMS**）如 Wordpress、Joomla 或 Drupal，我们需要安装一些 PHP 模块：

```
$ sudo yum -y install php-gd php-ldap php-odbc php-pear php-xml php-xmlrpc php-mbstring php-snmp php-soap curl curl-devel

```

安装这些模块后，我们可以继续进行 CMS 安装。在我们的情况下，我们将安装 Joomla。首先，我们需要访问 Joomla 网站并将最新版本下载到`/var/www`或任何`虚拟主机`文件夹中。使用 Wget 我们将下载 Joomla 软件包：

```
$ cd /var/www/packt2.co.uk/home/
$ get -c https://github.com/joomla/joomla-cms/releases/download/3.4.3/Joomla_3.4.3-Stable-Full_Package.zip

```

然后我们需要使用`unzip`命令提取软件包：

```
$ unzip Joomla_3.4.3-Stable-Full_Package.zip

```

### 注意

我们需要确保我们将要提取软件包的文件夹是空的，以确保安装过程中没有错误。

之后，我们可以在任何客户端 Web 浏览器中打开我们提取 CMS 软件包的域：

```
http://packt2.co.uk

```

然后我们需要按照网站上提供的安装步骤进行操作。以下是我们应该提供以完成安装的简要描述：

1.  我们需要提供网站名称和一些站点管理员信息（邮件、姓名、密码）：![使用 Apache-MySQL-PHP 设置 Web 服务器](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/ms-centos7-linux-svr/img/B04674_03_03.jpg)

1.  在数据库部分，我们需要提供我们正在使用的数据库（`MySQL`），然后是服务器主机名（`localhost`），以及数据库的用户和密码（`root`），最后是用于存储站点信息的数据库名称：![使用 Apache-MySQL-PHP 设置 Web 服务器](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/ms-centos7-linux-svr/img/B04674_03_04.jpg)

1.  如果需要，我们可以通过提供 FTP 用户及其密码来启用 FTP 服务器，并验证服务以检查它是否正在运行。

1.  然后我们将有一个概述，我们可以检查我们输入的配置，并可以通过电子邮件发送给管理员。

1.  最后，我们点击安装，让网站安装和配置。

正如这个屏幕截图所显示的，我们可以确定我们的 CMS 的先决条件的状态：

![使用 Apache-MySQL-PHP 设置 Web 服务器](https://github.com/OpenDocCN/freelearn-linux-pt2-zh/raw/master/docs/ms-centos7-linux-svr/img/B04674_03_05.jpg)

1.  安装站点会提醒我们删除安装文件夹，因为它可能对网站造成漏洞。因此，为了加强安全性，我们需要手动删除它：

```
$ sudo rm -rf installation/

```

1.  然后我们需要复制网站上提供的配置，并将其放入我们在站点文件夹中创建的文件中，然后保存它：

```
$ sudo nano configuration.php

```

我们可以访问网站并导航到它，或者我们可以打开管理面板对网站进行一些调整或管理设置：

```
http://packt2.co.uk/administator

```

现在我们可以说我们已经安装并保护了我们的 Web 服务器，它已经可以使用了。

# 设置 FTP 服务器

众所周知，多个客户端需要文件交换，其中一个常见的服务是 FTP 技术，它允许轻松快速地进行文件交换。在本节中，我们将讨论如何设置 FTP 服务器，以帮助在同一网络中的两台计算机或来自不同网络的计算机之间传输数据。

首先，我们需要使用默认的软件包管理器安装 FTP 服务器：

```
$ sudo yum install vsftpd ftp

```

安装服务器后，我们可以通过编辑`VSFTPD`配置文件开始配置服务：

```
$ sudo nano /etc/vsftpd/vsftpd.conf

```

我们需要找到以下行并按照所示更改它们：

```
anonymous_enable=NO  # Disable anonymous login
ftpd_banner=Welcome to The Packt FTP Service.  # Banner message
use_localtime=YES  # Make the server use the local machine time
local_enable=YES  # Allow local users to login
write_enable=YES  # Allow Local users to write to directory

```

然后我们应该重新启动服务，并将其添加到系统启动项，以在下次启动时自动启动：

```
$ sudo systemctl enable vsftpd
$ sudo systemctl start vsftpd

```

### 注意：

基本上，大多数导致服务无法启动的错误都与配置文件中的拼写错误有关。如果我们遇到任何错误，我们应该首先检查文件中是否有任何拼写错误的选项。

之后，为了确保服务可以从除本机之外的其他机器访问，我们需要在防火墙中打开 FTP 端口：

```
$ sudo firewall-cmd --permanent --add-port=21/tcp
$ sudo firewall-cmd --permanent --add-port=20/tcp
$ sudo firewall-cmd --permanent --add-service=ftp
$ sudo firewall-cmd --reload

```

然后更新 FTP 服务的 SELinux 布尔值：

```
$ sudo setsebool -P ftp_home_dir on

```

最后，我们应该创建一些 FTP 用户，以便客户端可以使用它们进行登录：

```
$ sudo useradd packt
$ sudo passwd packt

```

现在我们可以开始测试服务，方法是转到同一网络或外部的客户端之一，然后执行以下操作：

```
$ ftp Server_IP_Address

```

或者：

```
$ ftp domain_name

```

然后我们输入我们已经定义的用户及其密码。如果我们能访问 FTP 服务，那就意味着我们的 FTP 服务器已经成功设置好了。

# 使用 OpenSSL 保护 Apache 和 FTP

全球提供的大多数服务都非常吸引黑客攻击和窃取有价值的信息，或者阻止其活动。在本节中，我们将提出一个解决方案，帮助保护两个最常用的服务（`HTTPFTP`）。这个解决方案是 OpenSSL，它是一个实现**安全套接字层**（**SSL**）和**传输层安全**（**TLS**）协议以及强大的加密库的开源工具包。

我们将从实施 OpenSSL 开始进行 FTP 文件传输，以使其更加安全。首先，我们需要确保 OpenSSL 已安装在我们的系统上：

```
$ sudo yum install openssl

```

然后我们开始配置服务以与我们的 FTP 服务器 VSFTPD 一起工作。因此，我们需要创建一个 SSL 证书以与 TLS 一起使用，因为它是最新的最安全的技术。为此，我们需要创建一个文件夹来存储使用 SSL 生成的文件：

```
$ sudo mkdir /etc/ssl/private

```

然后我们使用密钥创建证书：

```
$ sudo openssl req -x509 -nodes -days 365 -newkey rsa:2048 -keyout /etc/ssl/private/vsftpd.pem -out /etc/ssl/private/vsftpd.pem  -sha256

```

在执行命令时，我们需要填写所需的详细信息：

+   `openssl`：管理 SSL 证书和密钥的基本 SSL 命令

+   `req –x509`：指定 SSL 和 TLS 的公钥基础设施标准

+   `-node`：告诉 OpenSSL 跳过密码安全选项

+   `-days 365`：设置此证书的有效时间

+   `-newkey rsa:1024`：创建一个新的 1024 位长的 RSA 密钥

+   `-keyout`：告诉 OpenSSL 在哪里生成私钥文件

+   `-out`：告诉 OpenSSL 在哪里生成证书文件

然后我们将 SSL 详细信息添加到我们的 FTP 服务器主配置文件中：

```
$ sudo nano /etc/vsftpd/vsftpd.conf

```

我们指定证书和密钥文件的位置：

```
rsa_cert_file=/etc/ssl/private/vsftpd.pem
rsa_private_key_file=/etc/ssl/private/vsftpd.pem

```

然后我们启用 SSL 的使用：

```
ssl_enable=YES
allow_anon_ssl=NO
force_local_data_ssl=YES
force_local_logins_ssl=YES

```

然后我们限制连接到 TLS：

```
ssl_tlsv1=YES
ssl_sslv2=NO
ssl_sslv3=NO

```

然后我们添加一些可选的配置来加强站点安全性：

```
require_ssl_reuse=NO
ssl_ciphers=HIGH

```

然后我们重新启动 FTP 服务以启用更改：

```
$ sudo systemctl restart vsftpd

```

然后我们可以通过具有连接到 FTPS 的能力的 FTP 客户端（Filezilla）进行测试，以查看连接/传输是否已经安全。

现在我们进入本节的第二部分，我们将保护我们的 Web 服务器 Apache。我们将安装 Apache 的 OpenSSL 模块，然后配置它来保护 Apache。

首先，我们需要确保 Apache 已成功安装，同样的事情也适用于 OpenSSL。然后我们可以开始安装`Mod_ssl`模块：

```
$ sudo yum install mod_ssl

```

安装完成后，我们进入配置部分。我们需要创建一个文件夹，用于存储我们的密钥和证书文件：

```
$ sudo mkdir /etc/httpd/ssl

```

然后，我们使用 OpenSSL 创建我们的密钥和证书：

```
$ sudo sudo openssl req -x509 -nodes -days 365 -newkey rsa:2048 -keyout /etc/httpd/ssl/apache.key -out /etc/httpd/ssl/apache.crt –sha256

```

我们需要填写所有必需的细节来完成文件的创建。

### 注意

Apache 中的 SSL 密钥必须没有密码，以免在每次服务器重新启动时引起手动重新配置。

创建所有文件后，我们需要设置一个虚拟主机以与新证书一起使用。为此，我们需要首先编辑 Apache 的 SSL 配置文件：

```
$ sudo nano /etc/httpd/conf.d/ssl.conf

```

我们需要找到以`<VirtualHost _default_:443>`开头的部分，对其进行一些更改，以确保 SSL 证书设置正确。

首先，我们需要取消注释`DocumentRoot`行，并将位置更改为需要保护的站点所需的位置：

```
DocumentRoot "/var/www/packt.co.uk/home"

```

我们对`ServerName`行执行相同的操作，并将域更改为所需的域：

```
ServerName packt.co.uk:443

```

最后，我们需要找到`SSLCertificateFile`和`SSLCertificateKeyFile`行，并将它们更改为指向我们创建 SSL 证书和密钥的位置：

```
SSLCertificateFile /etc/httpd/ssl/apache.crt
SSLCertificateKeyFile /etc/httpd/ssl/apache.key
SSLEngine on
SSLProtocol all -SSLv2 -SSLv3
SSLCipherSuite HIGH:MEDIUM:!aNULL:!MD5

```

然后我们保存文件并重新启动 Apache 以启用更改：

```
$ sudo systemctl restart httpd

```

为了测试这个配置，我们需要使用客户机的 Web 浏览器，并输入[`www.packtpub.com/`](https://www.packtpub.com/) `uk`。然后接受证书并访问该站点。

# 参考资料

现在我们已经完成了本章，让我们来看一下使用的参考资料：

+   Firewalld 配置指南：[`www.digitalocean.com/community/tutorials/how-to-set-up-a-firewall-using-firewalld-on-centos-7`](https://www.digitalocean.com/community/tutorials/how-to-set-up-a-firewall-using-firewalld-on-centos-7)

+   OpenVPN 服务器概述：[`openvpn.net/index.php/access-server/overview.html`](https://openvpn.net/index.php/access-server/overview.html)

+   BIND DNS 服务器页面：[`www.isc.org/downloads/bind/`](https://www.isc.org/downloads/bind/)

+   Web 服务器（LAMP）维基页面：[`en.wikipedia.org/wiki/LAMP_(software_bundle)`](https://en.wikipedia.org/wiki/LAMP_(software_bundle))

+   FTP 服务器维基页面：[`en.wikipedia.org/wiki/File_Transfer_Protocol`](https://en.wikipedia.org/wiki/File_Transfer_Protocol)

+   FTPS vs SFTP: [`www.eldos.com/security/articles/4672.php?page=all`](https://www.eldos.com/security/articles/4672.php?page=all)

+   Apache 的`Mod_SSL`文档：[`www.modssl.org/docs/`](http://www.modssl.org/docs/)

+   OpenSSL 网页：[`www.openssl.org/`](https://www.openssl.org/)

# 总结

本章是对 CentOS Linux 系统为用户提供的一系列服务的描述。这一描述是对如何在 CentOS 7 上安装这些服务以及如何配置它们以实现最佳实践的逐步解释。我们已经讨论了在本地网络中使用 Firewalld 实现网关服务器。然后我们建立了一个使用 OpenVPN 的 VPN 服务器，以便客户端可以从世界各地访问网络。之后，我们使用 BIND 服务设置了一个 DNS 服务器。然后我们安装了必要的软件包，建立了一个完全运行的 Web 服务器，可以支持动态网站，并进行了一些调整以使其更安全、易于管理和可扩展，使用 Apache 及其模块、MariaDB 和 PHP。我们继续设置了一个 FTP 服务器，以便客户端可以访问并传输数据。最后，我们使用 OpenSSL 自签名证书和密钥对我们的 Web 服务器和 FTP 服务器进行了安全保护。

我们还没有完成 CentOS 7 可以提供的功能。查看我们接下来的第四章，*使用 PostFix 的邮件服务器*，深入探讨如何设置、配置和保护使用 Postfix 的邮件服务器。
