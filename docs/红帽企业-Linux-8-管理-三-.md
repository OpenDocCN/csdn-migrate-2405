# 红帽企业 Linux 8 管理（三）

> 原文：[`zh.annas-archive.org/md5/0CCDE6F20D3A1D212C45A9BF7E65144A`](https://zh.annas-archive.org/md5/0CCDE6F20D3A1D212C45A9BF7E65144A)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第七章：添加、打补丁和管理软件

维护系统的软件，关闭安全问题，应用修复程序并保持系统最新是系统管理中的重要任务。在本章中，我们将回顾**Red Hat 订阅管理系统**的工作原理，如何确保软件包经过验证，以及保持系统更新的其他软件管理任务。

深入了解一些细节，在本章中，我们将介绍订阅系统的工作原理以及如何使用开发者订阅进行自我培训或安装个人服务器。我们还将检查如何管理软件来源，也称为仓库，您的系统将使用它们。这包括学习软件包管理中签名的作用，以确保安装的软件是 Red Hat 提供的软件。我们还将学习添加和删除软件包和软件包组，使用模块化的不同软件版本，以及审查和回滚更改等关键任务。

为了简化扩展您的知识，使您能够准备自己的实验室，我们将看到如何在您的系统中拥有所有**Red Hat 企业 Linux（RHEL）**仓库的完整本地副本。

最后但同样重要的是，我们需要了解**Red Hat 软件包管理器**（**RPM**），现在更名为 RPM 软件包管理器，通过学习软件包管理内部工作的基础知识。

总之，在本章中，我们将涵盖以下主题：

+   RHEL 订阅注册和管理

+   使用 Yum/DNF 管理仓库和签名

+   使用 Yum/DNF 进行软件安装、更新和回滚

+   使用 createrepo 和 reposync 创建和同步仓库

+   理解 RPM 内部

现在，让我们开始管理我们系统中的软件。

# RHEL 订阅注册和管理

RHEL 是一个完全的**开源操作系统**，这意味着用于构建它的所有源代码都可以访问、修改、重新分发和学习。另一方面，预构建的二进制文件是作为服务交付的，并通过订阅可访问。正如在*第一章*中所见，*安装 RHEL8*，我们可以为自己的个人使用获得开发者订阅。该订阅提供对 ISO 映像的访问，还提供了 RHEL 8 的更新、签名软件包。这些软件包与全球许多公司在生产中使用的完全相同。

让我们看看如何在我们自己的系统中使用该订阅。

首先，让我们来看看**Red Hat 客户门户**[`access.redhat.com`](https://access.redhat.com)，然后点击**登录**：

![图 7.1–登录到 Red Hat 客户门户](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/rhel8-adm/img/B16799_07_001.jpg)

图 7.1–登录到 Red Hat 客户门户

一旦我们点击`student`作为示例：

![图 7.2–在 Red Hat 单一登录中输入我们的用户名](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/rhel8-adm/img/B16799_07_002.jpg)

图 7.2–在 Red Hat 单一登录中输入我们的用户名

现在是时候输入我们的密码进行验证了：

![图 7.3–在 Red Hat 单一登录中输入我们的密码](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/rhel8-adm/img/B16799_07_003.jpg)

图 7.3–在 Red Hat 单一登录中输入我们的密码

登录后，我们将通过点击顶部栏中的**订阅**链接转到**Red Hat 订阅页面**：

![图 7.4–在 Red Hat 客户门户中访问订阅页面](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/rhel8-adm/img/B16799_07_004.jpg)

图 7.4–在 Red Hat 客户门户中访问订阅页面

对于已订阅一个物理机的用户，订阅页面将如下所示：

![图 7.5–Red Hat 客户门户中的订阅页面示例](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/rhel8-adm/img/B16799_07_005.jpg)

图 7.5–Red Hat 客户门户中的订阅页面示例

提示

开发者订阅于 2021 年 1 月更新，支持最多 16 个系统。您可以使用您的帐户为一个以上的单个系统模拟类似生产的部署。

现在让我们注册我们的新系统：

```
[root@rhel8 ~]# subscription-manager register
Registering to: subscription.rhsm.redhat.com:443/subscription
Username: student
Password: 
The system has been registered with ID: d9673662-754f-49f3-828c-86fd9f5b4e93
The registered system name is: rhel8.example.com
```

有了这个，我们的系统将被注册到红帽**内容交付网络**（**CDN**），但仍然没有分配订阅。

让我们转到订阅页面并刷新以查看新系统。我们将点击**查看所有系统**以继续：

![图 7.6 - 具有新订阅系统的订阅页面](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/rhel8-adm/img/B16799_07_006.jpg)

图 7.6 - 具有新订阅系统的订阅页面

我们可以在页面上看到我们的新系统`rhel8.example.com`，旁边有一个红色的方块，表示它没有附加的订阅。让我们点击系统名称以查看详细信息：

![图 7.7 - 具有新订阅系统的订阅页面](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/rhel8-adm/img/B16799_07_007.jpg)

图 7.7 - 具有新订阅系统的订阅页面

一旦进入特定系统页面，我们就可以看到系统的所有详细信息。我们点击**订阅**以查看已附加的订阅：

![图 7.8 - 具有新订阅系统详细信息的订阅页面](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/rhel8-adm/img/B16799_07_008.jpg)

图 7.8 - 具有新订阅系统详细信息的订阅页面

我们可以在页面上看到，这个系统没有附加的订阅：

![图 7.9 - 具有新订阅系统的订阅页面，没有附加的订阅](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/rhel8-adm/img/B16799_07_009.jpg)

图 7.9 - 具有新订阅系统的订阅页面，没有附加的订阅

让我们使用`subscription-manager attach`为我们的系统附加一个订阅：

```
[root@rhel8 ~]# subscription-manager attach --auto
Installed Product Current Status:
Product Name: Red Hat Enterprise Linux for x86_64
Status:       Subscribed
```

命令的结果显示，系统现在已注册，并为`Red Hat Enterprise Linux for x86_64`附加了一个订阅。让我们刷新系统页面以确保订阅附加正常运行：

![图 7.10 - 具有新订阅系统的订阅页面，附有一个订阅](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/rhel8-adm/img/B16799_07_010.jpg)

图 7.10 - 具有新订阅系统的订阅页面，附有一个订阅

有了这个，我们可以确定系统已正确注册并订阅了红帽 CDN，并且已准备好访问来自它的所有软件、补丁和更新。

此外，在系统中，我们可以看到一个包含有关软件**存储库**或**repos**信息的新文件已经创建：

```
[root@rhel8 ~]# ls -l /etc/yum.repos.d/redhat.repo 
-rw-r--r--. 1 root root 94154 feb  6 15:17 /etc/yum.repos.d/redhat.repo
```

现在我们知道如何管理可用的订阅并将它们分配给正在运行的系统，以便它可以访问由红帽构建的软件二进制文件。让我们在下一节中了解如何使用提供的存储库。

# 使用 YUM/DNF 管理存储库和签名

像许多其他 Linux 发行版一样，RHEL 有一个基于存储库提供软件的机制。这些存储库包含软件包的列表（可以是最终用户应用程序，如 Firefox，或者用于它们的组件，如 GTK3），软件包之间的依赖关系列表以及其他有用的元数据。

一旦我们完成订阅系统，我们可以使用`yum`或`dnf`查看系统中可用的存储库：

```
[root@rhel8 ~]# yum repolist
Updating Subscription Management repositories.
repo id                              repo name
rhel-8-for-x86_64-appstream-rpms     Red Hat Enterprise Linux 8 for x86_64 - AppStream (RPMs)
rhel-8-for-x86_64-baseos-rpms        Red Hat Enterprise Linux 8 for x86_64 - BaseOS (RPMs)
[root@rhel8 ~]# dnf repolist
Updating Subscription Management repositories.
repo id                              repo name
rhel-8-for-x86_64-appstream-rpms     Red Hat Enterprise Linux 8 for x86_64 - AppStream (RPMs)
rhel-8-for-x86_64-baseos-rpms        Red Hat Enterprise Linux 8 for x86_64 - BaseOS (RPMs)
```

正如您所看到的，`yum`和`dnf`的输出完全相同。事实上，`dnf`是`yum`的演变，在 RHEL8 中，`yum`命令只是`dnf`的符号链接：

```
[root@rhel8 ~]# which yum 
/usr/bin/yum
[root@rhel8 ~]# ll /usr/bin/yum
lrwxrwxrwx. 1 root root 5 jul 29  2020 /usr/bin/yum -> dnf-3
[root@rhel8 ~]# which dnf
/usr/bin/dnf
[root@rhel8 ~]# ll /usr/bin/dnf
lrwxrwxrwx. 1 root root 5 jul 29  2020 /usr/bin/dnf -> dnf-3
```

它们在 RHEL8 中可以互换使用。从现在开始，我们将只使用`dnf`，但请记住，如果您更喜欢`yum`，请随意使用。

提示

**YUM**曾经是**Yellowdog Updater Modified**的首字母缩写，这是一个最初是为 Mac 开发的 Linux 发行版项目。**DNF**代表**Dandified YUM**。

现在让我们来看一下在订阅附加期间创建的存储库定义`/etc/yum.repos.d/redhat.repo`。我们可以编辑文件并转到`BaseOS`存储库的条目，如上面显示的`rhel-8-for-x86_64-baseos-rpms`：

```
[rhel-8-for-x86_64-baseos-rpms]
name = Red Hat Enterprise Linux 8 for x86_64 - BaseOS (RPMs)
baseurl = https://cdn.redhat.com/content/dist/rhel8/$releasever/x86_64/baseos/os
enabled = 1
gpgcheck = 1
gpgkey = file:///etc/pki/rpm-gpg/RPM-GPG-KEY-redhat-release
sslverify = 1
sslcacert = /etc/rhsm/ca/redhat-uep.pem
sslclientkey = /etc/pki/entitlement/7881187918683323950-key.pem
sslclientcert = /etc/pki/entitlement/7881187918683323950.pem
metadata_expire = 86400
enabled_metadata = 1
```

正如您所看到的，文件中的每个部分都以方括号之间的部分名称开头 - 在前面的情况下，`[rhel-8-for-x86_64-baseos-rpms]`。现在让我们检查此部分下的所有条目：

+   **name**：存储库的长描述性名称。这是我们在前面的示例中列出存储库时显示的名称。

+   `$releasever` 变量将在访问之前被替换。其他方法包括 NFS、HTTP 和 FTP。

+   `1`，它将被启用，设置为 `0` 时将被禁用。

+   `1` 将启用，并且系统中使用 `dnf` / `yum` 安装的所有软件包将使用它们的 `gpg` 签名钥匙进行验证。

+   `gpg`，下载的软件包。

+   `1`，设置为 `0` 时将被禁用。

+   **sslcacert**：用作证书颁发机构的证书，用于验证客户端证书。

+   **sslclient key**：用于激活客户端证书的客户端密钥。

+   **sslclientcert**：机器用来在 CDN 上标识自己的客户端证书。

+   **metadata_expire**：在检索到的元数据被视为过期之后的秒数。默认值如下所示，为 24 小时。

+   `dnf`）以使用在此存储库中下载的元数据。

拥有运行存储库所需的最小选项是：`name`、`baseurl` 和 `gpgckeck`，并将最后一个设置为 `0`。

重要提示

虽然可以通过编辑文件更改存储库的配置，但修改 Red Hat 提供的存储库的最佳方法是使用本章中将显示的命令。这是因为当刷新数据时，`redhat.repo` 文件将被订阅管理器覆盖。

通过运行 `dnf repolist`，我们获得了系统中 `enabled` 的存储库列表。如果我们想要查看所有存储库，包括已启用和已禁用的存储库，该怎么办？可以通过运行 `dnf` `repolist --all` 来实现。

![图 7.11 – dnf repolist –all 的部分输出](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/rhel8-adm/img/B16799_07_011.jpg)

图 7.11 – dnf repolist –all 的部分输出

列表非常广泛。它包括了许多生产案例中使用的二进制库，从 SAP 到使用 Satellite 管理系统。我们可以使用 `grep` 过滤它来搜索 `supplementary`：

```
[root@rhel8 ~]# dnf repolist --all | grep supplementary
rhel-8-for-x86_64-supplementary-debug-rpms               disabled
rhel-8-for-x86_64-supplementary-eus-debug-rpms           disabled
rhel-8-for-x86_64-supplementary-eus-rpms                 disabled
rhel-8-for-x86_64-supplementary-eus-source-rpms          disabled
rhel-8-for-x86_64-supplementary-rpms                     disabled
rhel-8-for-x86_64-supplementary-source-rpms              disabled
```

这里有四种不同类型的通道：

+   `rhel-8-for-x86_64-supplementary-rpms`，其中包含准备安装在系统中的软件包，也称为 `rpms`。这些适用于标准维护期间。

+   `rhel-8-for-x86_64-supplementary-eus-rpms`，其中名称中包含 `eus`。这些提供了带有后端支持的软件包，以便能够保持相同的次要版本更长时间。除非第三方供应商要求，否则不要使用它们。

+   `rhel-8-for-x86_64-supplementary-source-rpms`，其中名称中包含 `source`。它们提供了用于构建 *常规* 和 *扩展更新支持* 通道中交付的软件包的源代码。

+   `rhel-8-for-x86_64-supplementary-debug-rpms`，其中名称中包含 `debug`。这些包括在构建软件包时生成的调试信息，对于深度故障排除非常有用。

我们可以使用 `dnf` 的 `config-manager` 选项启用 `rhel-8-for-x86_64-supplementary-rpms`，运行以下命令：

```
[root@rhel8 ~]# dnf config-manager --enable rhel-8-for-x86_64-supplementary-rpms
Updating Subscription Management repositories.
[root@rhel8 ~]# dnf repolist
Updating Subscription Management repositories.
repo id                                               repo name
rhel-8-for-x86_64-appstream-rpms                      Red Hat Enterprise Linux 8 for x86_64 - AppStream (RPMs)
rhel-8-for-x86_64-baseos-rpms                         Red Hat Enterprise Linux 8 for x86_64 - BaseOS (RPMs)
rhel-8-for-x86_64-supplementary-rpms                  Red Hat Enterprise Linux 8 for x86_64 - Supplementary (RPMs)
```

存储库现在已启用。您可能希望尝试启用和禁用其他存储库以进行练习。

现在让我们尝试添加一个我们只知道其 URL 的存储库，例如 `dnf config-manager`：

```
[root@rhel8 ~]# dnf config-manager --add-repo="http://mirror.uv.es/mirror/fedora-epel/8/Everything/x86_64/"
Updating Subscription Management repositories.
Adding repo from: http://mirror.uv.es/mirror/fedora-epel/8/Everything/x86_64/
[root@rhel8 ~]# dnf repolist
Updating Subscription Management repositories.
repo id                                              repo name
mirror.uv.es_mirror_fedora-epel_8_Everything_x86_64_ created by dnf config-manager from http://mirror.uv.es/mirror/fedora-epel/8/Everything/x86_64/
rhel-8-for-x86_64-appstream-rpms                     Red Hat Enterprise Linux 8 for x86_64 - AppStream (RPMs)
rhel-8-for-x86_64-baseos-rpms                        Red Hat Enterprise Linux 8 for x86_64 - BaseOS (RPMs)
rhel-8-for-x86_64-supplementary-rpms                 Red Hat Enterprise Linux 8 for x86_64 - Supplementary (RPMs)
```

我们可以检查新创建的文件 – `/etc/yum.repos.d/mirror.uv.es_mirror_fedora-epel_8_Everything_x86_64_.repo`：

```
[mirror.uv.es_mirror_fedora-epel_8_Everything_x86_64_]
name=created by dnf config-manager from http://mirror.uv.es/mirror/fedora-epel/8/Everything/x86_64/
baseurl=http://mirror.uv.es/mirror/fedora-epel/8/Everything/x86_64/
enabled=1
```

您可能已经意识到这个存储库中缺少一个选项，但是，让我们继续。我可以搜索 EPEL 中可用的软件包，例如 `screen`：

```
[root@rhel8 ~]# dnf info screen
Updating Subscription Management repositories.
created by dnf config-manager from http://mirror.uv.es/mirror/fedor  18 MB/s | 8.9 MB     00:00    
Last metadata expiration check: 0:00:02 ago on sáb 13 feb 2021 15:34:56 CET.
Available Packages
Name         : screen
Version      : 4.6.2
Release      : 10.el8
Architecture : x86_64
Size         : 582 k
Source       : screen-4.6.2-10.el8.src.rpm
Repository   : mirror.uv.es_mirror_fedora-epel_8_Everything_x86_64_
Summary      : A screen manager that supports multiple logins on one terminal
URL          : http://www.gnu.org/software/screen
License      : GPLv3+
Description  : The screen utility allows you to have multiple logins on just one
             : terminal. Screen is useful for users who telnet into a machine or are
             : connected via a dumb terminal, but want to use more than just one
             : login.
             : 
             : Install the screen package if you need a screen manager that can
             : support multiple logins on one terminal.
```

找到了软件包，现在让我们尝试安装它：

```
[root@rhel8 ~]# dnf install screen
[omitted]
Install  1 Package

Total download size: 582 k
Installed size: 971 k
Is this ok [y/N]: y
Downloading Packages:
screen-4.6.2-10.el8.x86_64.rpm                                      2.8 MB/s | 582 kB     00:00    
----------------------------------------------------------------------------------------------------
Total                                                               2.8 MB/s | 582 kB     00:00     
warning: /var/cache/dnf/mirror.uv.es_mirror_fedora-epel_8_Everything_x86_64_-ee39120d2e2a3152/packages/screen-4.6.2-10.el8.x86_64.rpm: Header V3 RSA/SHA256 Signature, key ID 2f86d6a1: NOKEY
Public key for screen-4.6.2-10.el8.x86_64.rpm is not installed
The downloaded packages were saved in cache until the next successful transaction.
You can remove cached packages by executing 'yum clean packages'.
Error: GPG check FAILED
```

正如我们所看到的，尝试从此源安装时出现了错误，因为它要求配置 `gpgcheck` 和 `gpgkey` 条目以确保具有适当的安全性（因为 `gpg` 确保交付的内容与创建的内容相同）。

我们可以从同一个镜像获取`gpgkey`，URL 为[`mirror.uv.es/mirror/fedora-epel/RPM-GPG-KEY-EPEL-8`](http://mirror.uv.es/mirror/fedora-epel/RPM-GPG-KEY-EPEL-8)，并将其放在`dnf`将搜索的位置`/etc/pki/rpm-gpg/`：

```
[root@rhel8 ~]# curl -s http://mirror.uv.es/mirror/fedora-epel/RPM-GPG-KEY-EPEL-8 > /etc/pki/rpm-gpg/RPM-GPG-KEY-EPEL-8
[root@rhel8 ~]# head –n 1 /etc/pki/rpm-gpg/RPM-GPG-KEY-EPEL-8
-----BEGIN PGP PUBLIC KEY BLOCK-----
```

现在让我们修改文件`/etc/yum.repos.d/mirror.uv.es_mirror_fedora-epel_8_Everything_x86_64_.repo`，使其如下所示：

```
[mirror.uv.es_mirror_fedora-epel_8_Everything_x86_64_]
name=created by dnf config-manager from http://mirror.uv.es/mirror/fedora-epel/8/Everything/x86_64/
baseurl=http://mirror.uv.es/mirror/fedora-epel/8/Everything/x86_64/
enabled=1
gpgcheck=1
gpgkey=file:///etc/pki/rpm-gpg/RPM-GPG-KEY-EPEL-8
```

您可以看到我们在文件中添加了`gpgcheck`和`gpgkey`条目。让我们再次尝试安装`screen`包：

```
[root@rhel8 ~]# dnf install screen
[omitted]
Install  1 Package

Total size: 582 k
Installed size: 971 k
Is this ok [y/N]: y
Downloading Packages:
[SKIPPED] screen-4.6.2-10.el8.x86_64.rpm: Already downloaded                                       
warning: /var/cache/dnf/mirror.uv.es_mirror_fedora-epel_8_Everything_x86_64_-ee39120d2e2a3152/packages/screen-4.6.2-10.el8.x86_64.rpm: Header V3 RSA/SHA256 Signature, key ID 2f86d6a1: NOKEY
created by dnf config-manager from http://mirror.uv.es/mirror/fedor 1.6 MB/s | 1.6 kB     00:00    
Importing GPG key 0x2F86D6A1:
Userid     : "Fedora EPEL (8) <epel@fedoraproject.org>"
Fingerprint: 94E2 79EB 8D8F 25B2 1810 ADF1 21EA 45AB 2F86 D6A1
From       : /etc/pki/rpm-gpg/RPM-GPG-KEY-EPEL-8
Is this ok [y/N]: y
Key imported successfully
Running transaction check
Transaction check succeeded.
Running transaction test
Transaction test succeeded.
Running transaction
  Preparing        :                               1/1 
  Running scriptlet: screen 4.6.2-10.el8.x86_64    1/1 
  Installing       : screen-4.6.2-10.el8.x86_64    1/1 
  Running scriptlet: screen-4.6.2-10.el8.x86_64    1/1 
  Verifying        : screen-4.6.2-10.el8.x86_64    1/1 
Installed products updated.

Installed:
  screen-4.6.2-10.el8.x86_64 

Complete!
```

您会注意到有一步要求您确认`gpg`密钥指纹是否正确：`94E2 79EB 8D8F 25B2 1810 ADF1 21EA 45AB 2F86 D6A1`。为此，您可以转到 Fedora 安全页面进行检查，因为 Fedora 项目正在管理 EPEL。该页面的 URL 是[`getfedora.org/security/`](https://getfedora.org/security/)：

![图 7.12 – Fedora 安全页面的部分截图，带有 EPEL8 gpg 指纹](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/rhel8-adm/img/B16799_07_012.jpg)

图 7.12 – Fedora 安全页面的部分截图，带有 EPEL8 gpg 指纹

正如您所看到的，是正确的。我们刚刚验证了我们使用的签名与项目管理它的公告的指纹相同，现在从该仓库下载的所有包都将使用它进行验证，以避免包篡改（即在您收到包之前有人更改内容）。

让我们回顾一下我们使用的命令，`dnf`提供了管理仓库的命令：

![](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/rhel8-adm/img/B16799_07_Table_7.1.jpg)

现在我们知道如何在 RHEL 中安全地管理仓库，让我们开始向系统添加更多的包，更新它们，并在需要时撤消安装。

# 使用 YUM/DNF 进行软件安装、更新和回滚

在前一节中，我们看到了如何安装一个包。在这个过程中，我们看到了一个确认请求，以确保我们确定要在系统中包含新软件。现在让我们使用`dnf install`安装软件，但使用`-y`选项来回答命令将发出的所有问题都是“是”：

```
[root@rhel8 ~]# dnf install zip –y
[omitted]
Installed:
unzip-6.0-43.el8.x86_64 zip-3.0-23.el8.x86_64                          

Complete!
```

正如您所看到的，`zip`包已经安装，还有一个名为`unzip`的依赖包，而不需要询问问题。我们还注意到`dnf`找到了依赖包，解决了**依赖关系**，并安装了所有运行一个包所需的内容。这样，系统就保持在一个一致的状态，使其更加可靠和可预测。

我们可以使用`dnf check-update`命令来查看哪些包准备更新：

```
[root@rhel8 ~]# dnf check-update
Updating Subscription Management repositories.
Last metadata expiration check: 0:20:00 ago on sáb 13 feb 2021 16:04:58 CET.

kernel.x86_64           4.18.0-240.10.1.el8_3            rhel-8-for-x86_64-baseos-rpms   
kernel-core.x86_64      4.18.0-240.10.1.el8_3           rhel-8-for-x86_64-baseos-rpms
kernel-modules.x86_64   4.18.0-240.10.1.el8_3       rhel-8-for-x86_64-baseos-rpms   
kernel-tools.x86_64      4.18.0-240.10.1.el8_3     rhel-8-for-x86_64-baseos-rpms   
kernel-tools-libs.x86_64 4.18.0-240.10.1.el8_3     rhel-8-for-x86_64-baseos-rpms   
python3-perf.x86_64      4.18.0-240.10.1.el8_3         rhel-8-for-x86_64-baseos-rpms   
qemu-guest-agent.x86_64  15:4.2.0-34.module+el8.3.0+8829+e7a0a3ea.1          rhel-8-for-x86_64-appstream-rpms
selinux-policy.noarch    3.14.3-54.el8_3.2         rhel-8-for-x86_64-baseos-rpms   
selinux-policy-targeted.noarch   3.14.3-54.el8_3.2 rhel-8-for-x86_64-baseos-rpms
sudo.x86_64              1.8.29-6.el8_3.1                 rhel-8-for-x86_64-baseos-rpms   
tzdata.noarch           2021a-1.el8                      rhel-8-for-x86_64-baseos-rpms
```

更新包并应用修复和安全补丁的最简单方法是使用`dnf update`：

```
[root@rhel8 ~]# dnf update tzdata –y
[omitted]
Upgraded:
  tzdata-2021a-1.el8.noarch                     
Complete!
```

要更新所有内容，只需运行`dnf update`而不指定包：

![图 7.13 – RHEL 使用 dnf/yum 进行部分更新的截图](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/rhel8-adm/img/B16799_07_013.jpg)

图 7.13 – RHEL 使用 dnf/yum 进行部分更新的截图

在系统中运行`dnf update`的结果如下：

```
Upgraded:
  kernel-tools-4.18.0-240.10.1.el8_3.x86_64    
  kernel-tools-libs-4.18.0-240.10.1.el8_3.x86_64  
  python3-perf-4.18.0-240.10.1.el8_3.x86_64                
  qemu-guest-agent 15:4.2.0-34.module+el8.3.0+8829+e7a0a3ea.1.x86_64
  selinux-policy-3.14.3-54.el8_3.2.noarch  
  selinux-policy-targeted-3.14.3-54.el8_3.2.noarch 
  sudo-1.8.29-6.el8_3.1.x86_64                            

Installed:
  kernel-4.18.0-240.10.1.el8_3.x86_64  
  kernel-core-4.18.0-240.10.1.el8_3.x86_64       
  kernel-modules-4.18.0-240.10.1.el8_3.x86_64       

Complete!
```

这些是系统中升级的包的示例。您的系统，根据您上次升级的时间和新发布的包，可能会有不同的输出。

重要提示

`kernel`是系统中最重要的部分。它使硬件访问和操作系统的所有基本功能都得以实现。这就是为什么，而不是升级它，会安装一个新版本。系统会保留前两个版本，以防系统无法启动，可以轻松选择其中一个来运行。

我们可以使用`dnf search`命令搜索可用的包：

```
[root@rhel8 ~]# dnf search wget
Updating Subscription Management repositories.
Last metadata expiration check: 0:05:02 ago on sáb 13 feb 2021 16:34:00 CET.
=================== Name Exactly Matched: wget ===================
wget.x86_64 : A utility for retrieving files using the HTTP or FTP protocols
```

我们可以使用`dnf info`来获取有关包的详细信息，无论是已安装还是未安装的：

```
[root@rhel8 ~]# dnf info wget
Updating Subscription Management repositories.
Last metadata expiration check: 0:06:45 ago on sáb 13 feb 2021 16:34:00 CET.
Available Packages
Name         : wget
Version      : 1.19.5
Release      : 10.el8
Architecture : x86_64
Size         : 734 k
Source       : wget-1.19.5-10.el8.src.rpm
Repository   : rhel-8-for-x86_64-appstream-rpms
Summary      : A utility for retrieving files using the HTTP or FTP protocols
URL          : http://www.gnu.org/software/wget/
License      : GPLv3+
Description  : GNU Wget is a file retrieval utility which can use either the HTTP or
             : FTP protocols. Wget features include the ability to work in the
             : background while you are logged out, recursive retrieval of
             : directories, file name wildcard matching, remote file timestamp
             : storage and comparison, use of Rest with FTP servers and Range with
             : HTTP servers to retrieve files over slow or unstable connections,
             : support for Proxy servers, and configurability.
```

我们还可以使用`dnf remove`来删除已安装的包：

```
[root@rhel8 ~]# dnf remove screen –y
[omitted]
Removed:  screen-4.6.2-10.el8.x86_64                  
Complete!
```

有时您想安装一些一起执行特定任务的包，这就是`dnf grouplist`的作用：

```
[root@rhel8 ~]# dnf grouplist | grep Tools
   Additional Virtualization Tools
   RPM Development Tools
   Security Tools
   Development Tools
   System Tools
   Graphical Administration Tools
```

您可以不使用`| grep Tools`来查看完整的列表。

让我们使用`dnf groupinstall`来安装`System Tools`组：

```
[root@rhel8 ~]# dnf groupinstall "System Tools"
Updating Subscription Management repositories.
Last metadata expiration check: 0:16:03 ago on sáb 13 feb 2021 16:34:00 CET.
Dependencies resolved.
```

上述命令的整个输出显示在以下截图中：

![图 7.14 – RHEL 安装组 dnf/yum 的部分截图](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/rhel8-adm/img/B16799_07_014.jpg)

图 7.14 - RHEL 安装组 dnf/yum 的部分截图

一旦预安装完成，我们可以看到我们将安装 78 个软件包：

```
Install  78 Packages

Total download size: 44 M
Installed size: 141 M
Is this ok [y/N]:y
```

回复`y`将执行安装（请注意，`-y`选项在这里也有效，假设对所有问题都回答是）。

我们可以使用`dnf history`来检查所有安装交易的历史记录：

![图 7.15 - RHEL dnf/yum 历史记录的部分截图](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/rhel8-adm/img/B16799_07_015.jpg)

图 7.15 - RHEL dnf/yum 历史记录的部分截图

从每个交易中获取特定信息很容易，只需指定交易编号为`dnf history`：

```
[root@rhel8 ~]# dnf history info 12
Updating Subscription Management repositories.
Transaction ID : 12
Begin time     : sáb 13 feb 2021 16:27:06 CET
Begin rpmdb    : 393:cec089e1c176497af3eb97582311fcd7cb7adb02
End time       : sáb 13 feb 2021 16:27:06 CET (0 seconds)
End rpmdb      : 393:6cf80ca6746149100bb1a49d76ebbf7407804e56
User           : root <root>
Return-Code    : Success
Releasever     : 8
Command Line   : update tzdata
Comment        : 
Packages Altered:
    Upgrade  tzdata-2021a-1.el8.noarch @rhel-8-for-x86_64-baseos-rpms
    Upgraded tzdata-2020d-1.el8.noarch @@System
```

更有趣的是，我们可以回滚到以`dnf history rollback`标记的以前的某个点。为了加快速度，*安装*`lsof`软件包，然后*回滚*到以前的编号：

```
[root@rhel8 ~]# dnf history rollback 15
[omitted]
Removed:  lsof-4.93.2-1.el8.x86_64                                                                          
Complete!
```

我们也可以使用`yum history undo`来撤消单个交易。让我们看看这个交易：

```
[root@rhel8 ~]# dnf history undo 10 –y
[omitted]
Removed:
   screen-4.6.2-10.el8.x86_64 
Complete!
```

让我们回顾使用`dnf`进行的最重要的交易：

![](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/rhel8-adm/img/B16799_07_Table_7.2a.jpg)

![](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/rhel8-adm/img/B16799_07_Table_7.2b.png)

在 RHEL 8 中有一个在以前版本中不可用的新功能，即`dnf`，因此无需安装额外的软件：

```
[root@rhel8 repos]# dnf module list postgresql
Updating Subscription Management repositories.
Last metadata expiration check: 0:00:30 ago on dom 14 feb 2021 19:25:32 CET.
Red Hat Enterprise Linux 8 for x86_64 - AppStream (RPMs)
Name              Stream        Profiles                Summary
postgresql        9.6           client, server [d]        PostgreSQL server and client module      
postgresql        10 [d]        client, server [d]        PostgreSQL server and client module      
postgresql        12            client, server [d]        PostgreSQL server and client module      

Hint: [d]efault, [e]nabled, [x]disabled, [i]nstalled
```

提示

使用`dnf module list`命令，不指定任何软件包，将显示完整的模块列表。试试看！

正如您所看到的，我们在 RHEL8 中有三个不同版本的 PostgreSQL 数据库可用，分别是 9.6、10 和 12。它们都没有启用，默认版本是 10。

使用`dnf module`启用 PostgreSQL 的版本 12：

```
[root@rhel8 ~]# dnf module enable postgresql:12
[omitted]
Enabling module streams: postgresql                 12
[omitted]
Is this ok [y/N]: y
Complete!
[root@rhel8 ~]# dnf module list postgresql
```

上述命令的输出可以在以下截图中看到：

![图 7.16 - PostgreSQL 模块列表的截图](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/rhel8-adm/img/B16799_07_016.jpg)

图 7.16 - PostgreSQL 模块列表的截图

从现在开始，Yum 将在此系统中安装、更新和维护 PostgreSQL 的版本 12。让我们安装它：

```
[root@rhel8 ~]# dnf install postgresql -y
[omitted] 
Installed:
  libpq-12.5-1.el8_3.x86_64          
  postgresql-12.5-1.module+el8.3.0+9042+664538f4.x86_64
Complete!
```

在前面的例子中，安装了版本 12。

我们可以删除 PostgreSQL 软件包并重置模块状态以返回到初始状态：

```
[root@rhel8 ~]# dnf remove postgresql -y
[omitted]
Removing:
postgresql  x86_64  12.5-1.module+el8.3.0+9042+664538f4  @rhel-8-for-x86_64-appstream-rpms  5.4 M
Removing unused dependencies:
libpq       x86_64  12.5-1.el8_3                         @rhel-8-for-x86_64-appstream-rpms  719 k
[omitted]
Complete!
[root@rhel8 ~]# dnf module reset postgresql
Updating Subscription Management repositories.
Last metadata expiration check: 1:23:08 ago on dom 14 feb 2021 19:25:32 CET.
Dependencies resolved.
=========================================================Package                 Architecture          Version                 Repository              Size
=========================================================Resetting modules:
postgresql                                                                                       
Transaction Summary
=========================================================Is this ok [y/N]: y
Complete!
[root@rhel8 ~]# dnf module list postgresql
Updating Subscription Management repositories.
Last metadata expiration check: 1:23:21 ago on dom 14 feb 2021 19:25:32 CET.
Red Hat Enterprise Linux 8 for x86_64 - AppStream (RPMs)
Name              Stream        Profiles                Summary
postgresql        9.6           client, server [d]        PostgreSQL server and client module      
postgresql        10 [d]        client, server [d]        PostgreSQL server and client module      
postgresql        12            client, server [d]        PostgreSQL server and client module      

Hint: [d]efault, [e]nabled, [x]disabled, [i]nstalled
```

让我们回顾一下本节中显示的模块化命令：

![](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/rhel8-adm/img/B16799_07_Table_7.3.jpg)

提示

要了解有关模块化的更多信息，请运行`man dnf.modularity`查看系统的手册页。

现在我们已经学会了如何在 RHEL 中处理软件交易，让我们继续学习如何创建和处理本地存储库。

# 使用 createrepo 和 reposync 创建和同步存储库

通常我们会收到一个 RPM 文件并将其保存在我们可以在自己的机器上使用的存储库中（有时还会与具有 Web 服务器或 NFS 共享的其他机器共享）。当我们开始构建自己的 RPM 时，通常会分发它们，为了这样做，我们需要创建一个存储库。为此，我们可以使用**createrepo**工具。

首先让我们在`/var/tmp`中为存储库创建一个文件夹：

```
[root@rhel8 ~]# cd /var/tmp/
[root@rhel8 tmp]# mkdir repos
[root@rhel8 tmp]# cd repos/
```

然后让我们为`slack`创建一个文件夹，这是一个与您的团队进行通信的常用工具，并下载 RPM 软件包：

```
[root@rhel8 repos]# mkdir slack
[root@rhel8 repos]# cd slack/
[root@rhel8 repos]# curl -s -O https://downloads.slack-edge.com/linux_releases/slack-4.12.2-0.1.fc21.x86_64.rpm 
[root@rhel8 slack]# ls -l
total 62652
-rw-r--r--. 1 root 64152596 feb 14 18:12 slack-4.12.2-0.1.fc21.x86_64.rpm
```

现在我们有一个带有 RPM 文件的存储库。我们可以有一个带有任意数量 RPM 的存储库，但我们将继续只使用这个单个软件包。

让我们安装`createrepo`工具：

```
[root@rhel8 slack]# dnf install -y createrepo
[omitted]
Installed:
  createrepo_c-0.15.11-2.el8.x86_64 createrepo_c-libs-0.15.11-2.el8.x86_64 drpm-0.4.1-3.el8.x86_64
Complete!
```

现在我们可以简单地运行它，在当前文件夹中使用以下命令创建一个存储库：

```
[root@rhel8 slack]# createrepo .
Directory walk started
Directory walk done - 1 packages
Temporary output repo path: ./.repodata/
Preparing sqlite DBs
Pool started (with 5 workers)
Pool finished
[root@rhel8 slack]# ls -l
total 62656
drwxr-xr-x. 2 root     4096 feb 14 18:19 repodata
-rw-r--r--. 1 root 64152596 feb 14 18:12 slack-4.12.2-0.1.fc21.x86_64.rpm
```

我们看到`repodata`文件夹已经被创建。在其中，我们可以找到定义存储库内容的`repomd.xml`文件，还有最近创建的索引文件：

```
[root@rhel8 slack]# ls repodata/
13b6b81deb95354164189de7fe5148b4dbdb247fb910973cc94c120d36c0fd27-filelists.xml.gz
18fb83942e8cb5633fd0653a4c8ac3db0f93ea73581f91d90be93256061043f0-other.sqlite.bz2
aa72116fa9b47caaee313ece2c16676dce26ffcc78c69dc74ebe4fc59aea2c78-filelists.sqlite.bz2
d5e2ff4b465544a423bfa28a4bc3d054f316302feab8604d64f73538809b1cf0-primary.xml.gz
e92cd0e07c758c1028054cfeb964c4e159004be61ae5217927c27d27ea2c7966-primary.sqlite.bz2
f68973de8a710a9a078faf49e90747baaf496c5a43865cd5dc5757512a0664a8-other.xml.gz
repomd.xml
```

现在我们可以将存储库添加到系统中。我们可以在没有`gpg`签名的情况下进行，将`gpgcheck`变量设置为`0`，但为了更好的安全性，让我们使用`gpg`签名。通过在`slack`页面搜索，我们找到签名并将其下载到`/etc/pki/rpm-gpg`目录：

```
[root@rhel8 slack]# curl https://slack.com/gpg/slack_pubkey_2019.gpg -o /etc/pki/rpm-gpg/RPM-GPG-KEY-SLACK
```

然后通过创建文件`/etc/yum.repos.d/local-slack.repo`并添加以下内容将存储库添加到系统中：

```
[local-slack-repo]
name=Local Slack Repository
baseurl=file:///var/tmp/repos/slack
enabled=1
gpgcheck=1
gpgkey=file:///etc/pki/rpm-gpg/RPM-GPG-KEY-SLACK
```

现在我们可以尝试安装`slack`。要完全运行，需要安装*带有 GUI 的服务器*软件包组，但是为了完成本练习，我们可以继续安装。我们可以通过运行`dnf -y install slack`来实现这一点-请注意`gpg`密钥如何自动导入并验证和安装软件包：

```
root@rhel8 slack]# dnf -y install slack
[omitted]
warning: /var/tmp/repos/slack/slack-4.12.2-0.1.fc21.x86_64.rpm: Header V4 RSA/SHA1 Signature, key ID 8e6c9578: NOKEY
Local Slack Repository                                              1.6 MB/s | 1.6 kB     00:00    
Importing GPG key 0x8E6C9578:
Userid     : "Slack Packages (Signing Key) <packages@slack-corp.com>"
Fingerprint: 93D5 D2A6 2895 1B43 83D8 A4CE F184 6207 8E6C 9578
From       : /etc/pki/rpm-gpg/RPM-GPG-KEY-SLACK
Key imported successfully
Running transaction check
Transaction check succeeded.
Running transaction test
Transaction test succeeded.
[omitted]
  slack-4.12.2-0.1.fc21.x86_64                      
Complete!
```

一旦出现 Slack 的新版本，我们可以将其下载到同一文件夹，并通过再次运行`createrepo`来重新生成仓库索引。这样，所有使用该仓库的系统在运行`yum update`时都会更新`slack`。这是保持所有系统标准化和版本一致的好方法。有关管理 RPM 仓库的高级功能，请查看 Red Hat Satellite。

有时我们希望在我们的系统中有仓库的本地副本。为此，我们可以使用**reposync**工具。

首先，我们安装`reposync`，它包含在`yum-utils`软件包中：

```
[root@rhel8 ~]# dnf install yum-utils -y
[omitted]
Installed:
  yum-utils-4.0.17-5.el8.noarch                                   
Complete!
```

提示

如果尝试安装`dnf-utils`软件包，将安装相同的软件包。

现在是时候禁用 Red Hat 提供的除`rhel-8-for-x86_64-baseos-rpms`之外的所有仓库了，可以使用以下命令完成：

```
[root@rhel8 ~]# subscription-manager repos --disable="*" --enable="rhel-8-for-x86_64-baseos-rpms"
```

检查变化的时间到了：

```
[root@rhel8 ~]# dnf repolist
Updating Subscription Management repositories.
repo id                                              repo name
local-slack-repo                                     Local Slack Repository
mirror.uv.es_mirror_fedora-epel_8_Everything_x86_64_ created by dnf config-manager from http://mirror.uv.es/mirror/fedora-epel/8/Everything/x86_64/
rhel-8-for-x86_64-baseos-rpms                        Red Hat Enterprise Linux 8 for x86_64 - BaseOS (RPMs)
```

我们也可以禁用其他仓库，但这次我们将以不同的方式进行，将它们重命名为不以`.repo`结尾的名称：

```
[root@rhel8 ~]# mv /etc/yum.repos.d/local-slack.repo  /etc/yum.repos.d/local-slack.repo_disabled
[root@rhel8 ~]# mv /etc/yum.repos.d/mirror.uv.es_mirror_fedora-epel_8_Everything_x86_64_.repo  /etc/yum.repos.d/mirror.uv.es_mirror_fedora-epel_8_Everything_x86_64_.repo_disabled
[root@rhel8 ~]# yum repolist
Updating Subscription Management repositories.
repo id                               repo name
rhel-8-for-x86_64-baseos-rpms         Red Hat Enterprise Linux 8 for x86_64 - BaseOS (RPMs)
```

现在我们可以使用一些选项运行`reposync`：

```
[root@rhel8 ~]# cd /var/tmp/repos
[root@rhel8 repos]# reposync --newest-only --download-metadata --destdir /var/tmp/repos
Updating Subscription Management repositories.
[omitted]
(1725/1726): selinux-policy-3.14.3-54.el8_3.2.noarch.rpm           2.3 MB/s | 622 kB     00:00    
(1726/1726): selinux-policy-devel-3.14.3-54.el8_3.2.noarch.rpm     4.1 MB/s | 1.5 MB     00:00    
[root@rhel8 repos]# ls
rhel-8-for-x86_64-baseos-rpms  slack
[root@rhel8 repos]# ls rhel-8-for-x86_64-baseos-rpms/
Packages  repodata
[root@rhel8 repos]# ls rhel-8-for-x86_64-baseos-rpms/repodata/
14d4e7f9bbf5901efa7c54db513a2ac68cb0b6650ae23a2e0bff15dc03565f25-other.sqlite.bz2
26727acbd819c59d4da7c8aeaddb027adbfb7ddb4861d31922465b4c0922f969-updateinfo.xml.gz
46f0b974d2456ad4f66dec3afff1490648f567ee9aa4fe695494ec2cfc9a88f6-primary.sqlite.bz2
580de0089dbaa82ca8963963da9cb74abf7a5c997842492210e2c10e1deac832-primary.xml.gz
5954c1ef-00bc-457b-9586-e51789358b97
a7504888345e2440fa62e21a85f690c64a5f5b9ffd84d8e525a077c955644abe-filelists.xml.gz
acad9f7dfbc7681c2532f2fd1ff56e0f4e58eb0e2be72cc1d4a4ec8613008699-comps.xml
d2e90d6a0f138e6d8ea190cf995902c821309a03606c7acc28857e186489974a-filelists.sqlite.bz2
e0a7c4b677c633b859dba5eac132de68e138223e4ad696c72a97c454f2fe70bd-other.xml.gz
repomd.xml
```

这将下载已启用通道的最新软件包。让我们来看看选项：

+   `--newest-only`：Red Hat 仓库保留自首次发布以来的所有软件包版本。这将仅下载最新版本。

+   `--download-metadata`：为了确保我们下载一个完全功能的仓库，并且不需要在其上运行`createrepo`，我们可以使用这个选项，它将检索源仓库中的所有元数据。

+   `--destdir /var/tmp/repos`：设置下载文件的目标目录。它还将为每个配置的仓库创建一个目录，因此指定的目录将是它们所有的父目录。

有了这个复制的仓库，我们还可以在隔离的环境中工作。准备测试环境可能非常方便。对于高级的仓库管理功能，请记得尝试 Red Hat Satellite。

在学习了仓库的基础知识以及如何使用它们来管理软件之后，让我们深入了解其背后的技术，即**Red Hat 软件包管理器**或**RPM**。

# 理解 RPM 内部

Linux 发行版往往有自己的软件包管理器，从 Debian 的`.deb`到 Arch Linux 中的 Pacman 和其他更奇特的机制。软件包管理器的目的是保持系统上安装的软件，更新它，修补它，保持依赖关系，并维护系统上安装的内部数据库。RPM 被 Fedora、openSUSE、CentOS、Oracle Linux 和当然还有 RHEL 等发行版使用。

要处理 RPM 包，系统中有`rpm`命令，但自从引入`yum`/`dnf`以来，它在系统管理中几乎不再使用，并且不包含在 RHCSA 中。

RPM 包含以下内容：

+   要安装在系统上的文件，以 CPIO 格式存储并压缩

+   有关每个文件的权限和分配的所有者和组的信息

+   每个软件包所需和提供的依赖关系，以及与其他软件包的冲突

+   在任何这些阶段应用的安装、卸载和升级脚本

+   确保软件包未被修改的签名

为了了解一些简单有用的命令，我们将展示一些。

检查软件包的命令包括以下内容：

+   `rpm –qa`：列出系统中安装的所有软件包

+   `rpm –qf <filename>`：显示安装了所述文件名的软件包

+   `rpm –ql <packagefile>`：列出下载软件包中包含的文件（检查先前下载的软件包很有趣）

安装、升级和删除的命令包括以下内容：

+   `rpm -i <packagefile>`：安装提供的软件包列表，不获取依赖项。

+   `rpm -U <packagefile>`：使用下载的软件包升级一个软件包。检查依赖关系，但不管理它们。

+   `rpm -e <packagename>`：删除指定的软件包，尽管它不会删除依赖项。

如果你想了解`yum`/`dnf`中的依赖管理系统是如何工作的，可以尝试使用`rpm -i`安装软件包。

重要的是要知道，所有已安装软件包的数据库都位于`/var/lib/rpm`中，并且可以使用`rpmdb`命令进行管理。

在现代时代，不得不使用`rpm`命令通常意味着有低级问题，所以最好在真实生活中使用之前先尝试在测试系统中进行测试。

通过这个，我们已经完成了 RHEL 系统中的软件管理。

# 总结

在本章中，我们已经了解了 RHEL 8 系统中软件管理的管理部分，从订阅到安装，再到模块化和其他杂项提示。

RHEL 中所有的系统修补、更新和管理都依赖于`yum`/`dnf`，简化了管理依赖关系、安装正确版本的软件以及在隔离环境中分发软件。这是系统管理员更常见的任务之一，应该完全理解。

对于红帽认证工程师级别，需要更深入地了解，包括创建 RPM 软件包，这对于在自己的环境中管理、维护和分发内部生产的软件非常有用，利用红帽提供的经验和工具。

现在我们的系统已经更新，让我们继续学习如何在即将到来的章节中远程管理它们。


# 第二部分：使用 SSH、SELinux、防火墙和系统权限进行安全管理

生产系统的安全是系统管理员的直接责任。为了处理这个问题，RHEL 包括了诸如 SELinux、集成防火墙和标准系统权限等功能。本节提供了 RHEL 安全机制的概述和理解，以便您可以执行日常维护任务。

本节包括以下章节：

+   第八章 远程管理系统

+   第九章 使用 firewalld 保护网络连接

+   第十章 用 SELinux 保护系统

+   第十一章 使用 OpenSCAP 进行系统安全配置文件


# 第八章：远程管理系统

在处理系统时，一旦安装了服务器，甚至在安装过程中，管理可以远程执行。一旦安装了一台机器，其生命周期中需要执行的任务与已经执行的任务并没有太大不同。

在本章中，我们将从连接的角度讨论如何连接到远程系统，传输文件，以及如何自动化连接，使其可以被脚本化，并在网络链接出现问题时使其具有弹性。可以在系统上执行的管理任务与我们在前几章中描述的相同，例如安装软件，配置额外的网络设置，甚至管理用户。

由于管理系统需要特权凭据，我们将重点关注可被认为是安全的可用工具，以执行此类连接，以及如何使用它们来封装其他流量。

我们将涵盖以下主题：

+   SSH 和 OpenSSH 概述和基本配置

+   使用 SSH 访问远程系统

+   使用 SSH 进行基于密钥的身份验证

+   使用 SCP/rsync 进行远程文件管理

+   高级远程管理 – SSH 隧道和 SSH 重定向

+   使用 tmux 进行远程终端管理

通过涵盖这些主题，我们将能够掌握远程系统访问，并将我们的管理技能提升到下一个水平。

让我们从下一节开始讨论 SSH 协议和 OpenSSH 客户端和服务器。

# 技术要求

您可以继续使用我们在本书开头创建的虚拟机，在*第一章* *安装 RHEL8*中。所需的任何额外软件包将在文本中指示。本章所需的任何额外文件可以从[`github.com/PacktPublishing/Red-Hat-Enterprise-Linux-8-Administration`](https://github.com/PacktPublishing/Red-Hat-Enterprise-Linux-8-Administration)下载。

# SSH 和 OpenSSH 概述和基本配置

**SSH**是**Secure Shell Host**的缩写。它开始取代传统的 telnet 使用，telnet 是一种远程登录协议，用于连接主机时不使用加密，因此用于登录的凭据以明文形式传输。这意味着在用户终端和远程服务器之间有系统的任何人都可以拦截用户名和密码，并使用该信息连接到远程系统。这类似于通过 HTTP 而不是 HTTPS 将凭据传输到 Web 服务器时发生的情况。

使用 SSH，即使在不受信任或不安全的网络上进行连接，也会在客户端和目标主机之间创建安全通道。在这里，创建的 SSH 通道是安全的，不会泄漏任何信息。

OpenSSH 提供了服务器和客户端（在**Red Hat Enterprise Linux** (**RHEL**)中的`openssh-server`和`openssh-clients`软件包），可用于连接到远程主机并允许远程主机连接。

提示

知道一切是不可能的，所以对于`rpm –ql package`来说，如果您记不住要使用哪个文件，审查软件包提供的文件列表非常重要。

默认情况下，客户端和服务器都允许连接，但有许多可以调整的选项。

## OpenSSH 服务器

OpenSSH 是基于 OpenBSD 成员创建的最后一个免费 SSH 版本的免费实现，并更新了所有相关的安全和功能。它已成为许多操作系统的标准，既作为服务器又作为客户端，以在它们之间建立安全连接。

OpenSSH 服务器的主要配置文件位于`/etc/ssh/sshd_config`（您可以使用`man sshd_config`获取有关不同选项的详细信息）。一些最常用的选项如下：

+   `AcceptEnv`：定义客户端设置的哪些环境变量将在远程主机上使用（例如，区域设置，终端类型等）。

+   `AllowGroups`：用户应该是其成员的一组组的列表，以便访问系统。

+   `AllowTcpForwarding`：允许我们使用 SSH 连接转发端口（我们将在本章后面讨论这一点，在*SSH 隧道和 SSH 重定向*部分）。

+   `DisableForwarding`：这优先于其他转发选项，使得更容易限制服务。

+   `AuthenticationMethods`：定义可以使用的身份验证方法，例如禁用基于密码的访问。

+   `Banner`：在允许身份验证之前发送给连接用户的文件。这默认为无横幅，这也可能会透露运行服务的人，这可能向可能的攻击者提供了太多数据。

+   `Ciphers`：与服务器交互时要使用的有效密码列表。您可以使用`+`或`-`来启用或禁用它们。

+   `ListenAddress`：`sshd`守护程序应该监听传入连接的主机名或地址和端口。

+   `PasswordAuthentication`：默认为是，可以禁用以阻止用户与系统进行交互连接，除非使用公钥/私钥对。

+   `PermitEmptyPasswords`：允许没有密码的帐户访问系统（默认为否）。

+   `PermitRootLogin`：定义根用户的登录方式，例如，避免根用户使用密码远程连接。

+   `Port`：与`ListenAddress`相关，这默认为`22`。这是`sshd`守护程序监听传入连接的端口号。

+   `Subsystem`：配置外部子系统的命令。例如，它与`sftp`一起用于文件传输。

+   `X11Forwarding`：这定义了是否允许`X11`转发，以便远程用户可以通过隧道连接在本地显示器上打开图形程序。

以下截图显示了我们在删除注释时系统安装的选项：

![图 8.1 - 安装时在/etc/ssh/sshd_config 中定义的默认值](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/rhel8-adm/img/B16799_08_001.jpg)

图 8.1 - 安装时在/etc/ssh/sshd_config 中定义的默认值

我们将在下一节检查配置的客户端部分。

## OpenSSH 客户端

OpenSSH 的客户端部分通过`/etc/ssh/ssh_config`文件和`/etc/ssh/ssh_config.d/`文件夹中的文件进行系统范围的配置。它们还通过每个用户的`~/.ssh/config`文件进行配置。

通常，系统范围的文件只包含一些注释，而不是实际设置，因此我们将专注于每个用户配置文件和命令行参数。

我们`~/.ssh/config`文件中的一个示例条目可能如下：

```
Host jump
    Hostname jump.example.com
    User root
    Compression yes
    StrictHostKeyChecking no
    GSSAPIAuthentication yes
    GSSAPIDelegateCredentials yes
    GSSAPIKeyExchange yes
    ProxyCommand connect-proxy -H squid.example.com:3128 %h %p
    ControlPath ~/.ssh/master-%r@%h:%p
    ControlMaster auto
```

在前面的示例中，我们定义了一个名为`jump`的条目（我们可以在`ssh jump`中使用），它将`root`用户名连接到`jump.example.com`主机。

这是一个基本设置，但我们还定义了我们将使用`ProxyCommand`中的辅助程序，该程序将利用端口`3128`上的`squid.example.com`代理服务器连接到`%h`主机和`%p`端口以到达我们的目标系统。此外，我们正在使用`Compression`并使用`ControlMaster`进行额外的`GSSAPI`身份验证。

一个具有安全影响的特性是`StrictHostKeyChecking`。当我们第一次连接到主机时，密钥在客户端和主机之间交换，并且服务器使用这些密钥来标识自己。如果它们被接受，它们将被存储在用户家目录下的`.ssh/known_hosts`文件中。

如果远程主机密钥发生变化，`ssh`客户端的终端将打印警告并拒绝连接，但当我们将`StrictHostKeyChecking`设置为`no`时，我们将接受服务器发送的任何密钥，这在我们使用频繁重新部署的测试系统时可能很有用（因此会生成新的主机密钥）。一般情况下不建议使用，因为它可以保护我们免受服务器被替换以及有人冒充我们要连接的服务器并记录用户名和密码以后访问我们系统的风险。

在接下来的部分，我们将学习如何使用`ssh`访问远程系统。

# 使用 SSH 访问远程系统

正如我们在本章前面提到的，SSH 是用于连接远程系统的协议。一般来说，其最基本形式的语法就是在终端中执行`ssh host`。

然后，`ssh`客户端将使用当前登录用户的用户名默认地在目标主机上启动与`ssh`服务器的连接，并尝试在默认的`22/tcp`端口上到达远程服务器，这是 SSH 服务的默认端口。

在下面的截图中，我们可以看到离我们的`localhost`系统最近的服务器，这意味着我们将连接到我们自己的服务器：

![图 8.2 – 向本地主机发起 SSH 连接](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/rhel8-adm/img/B16799_08_002.jpg)

图 8.2 – 向本地主机发起 SSH 连接

在前面的截图中，我们可以看到与服务器的第一次交互打印了服务器的指纹以进行身份验证。这就是前一节讨论的内容；即`StrictHostKeyChecking`。一旦接受，如果主机密钥发生变化，连接将被拒绝，直到我们手动删除旧密钥以确认我们知道服务器的变化。

让我们添加密钥并再试一次，如下面的截图所示：

![图 8.3 – 向本地主机发起 SSH 连接被拒绝](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/rhel8-adm/img/B16799_08_003.jpg)

图 8.3 – 向本地主机发起 SSH 连接被拒绝

在我们的第二次尝试中，连接失败了，但让我们来看一下输出；即`Permission denied (publickey,gssapi-keyex,gssapi-with-mic)`。这是什么意思？如果我们注意到，`password`没有列出，这意味着我们无法通过密码提示连接到这个主机（这是因为我们在`/etc/ssh/sshd_config`文件中将`PasswordAuthentication`设置为`no`）。

在下面的截图中，我们可以看到一旦我们将`PasswordAuthentication`设置为`yes`，系统会要求输入密码，密码不会显示在屏幕上。一旦验证通过，我们就会得到一个 shell 提示，这样我们就可以开始输入命令了：

![图 8.4 – SSH 连接已完成](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/rhel8-adm/img/B16799_08_004.jpg)

图 8.4 – SSH 连接已完成

一般来说，密码身份验证可能存在安全风险，因为键盘可能被拦截，有人可能在你身边偷看，可能会对帐户使用暴力攻击等等。因此，通常的做法是至少禁用`root`用户的密码身份验证，这意味着试图登录系统的人应该知道一个用户的用户名和密码，然后使用系统工具成为`root`。

让我们学习如何通过身份验证密钥登录禁用密码的远程系统。

# 使用 SSH 进行基于密钥的身份验证

SSH 连接的一个重要优势是可以给出要在远程主机上执行的命令，例如，获取可以用于监视的更新数据，而无需在主机上安装特定的代理。

在每次连接时提供登录详细信息并不是我们认为对用户体验有所改进的事情，但 SSH 也允许我们创建一个密钥对，用于对远程系统进行身份验证，因此不需要输入密码或凭据。

密钥包含两部分：一部分是公开的，必须在我们要连接的每个主机上进行配置，另一部分是私有的，必须得到保护，因为它将用于在我们尝试连接到远程主机时识别我们。

毋庸置疑，整个过程都是在 SSH 创建的加密连接上进行的。因此，使用 SSH 和压缩也将使我们的连接速度更快，而不是其他遗留方法，如未加密的 telnet。 

首先，让我们为身份验证创建一个密钥对。

提示

建议每个用户至少拥有一个密钥对，以便每个用户在连接到服务器时都可以基于角色拥有密钥。即使密钥可以共享给角色中的用户，最好还是让每个用户拥有自己的密钥对，以便可以单独撤销密钥。例如，我们可以保留几个`ssh`密钥对，用于不同的角色，如个人系统、生产系统、实验室系统等。必须指定用于连接的密钥对也是额外的安全措施：除非使用生产密钥对，否则我们无法连接到生产系统。

创建密钥对，我们可以使用`ssh-keygen`工具，该工具有几个选项用于创建密钥，如下面的屏幕截图所示：

![图 8.5 - ssh-keygen 选项](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/rhel8-adm/img/B16799_08_005.jpg)

图 8.5 - ssh-keygen 选项

当没有提供参数时，默认情况下，它将为当前用户创建一个密钥，并要求为密钥设置密码。当我们使用默认值并不提供数值时，我们会得到类似于下面屏幕截图中所示的输出。

![图 8.6 - ssh-keygen 执行在~/.ssh/{id_rsa,id_rsa.pub}下创建 RSA 密钥对](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/rhel8-adm/img/B16799_08_006.jpg)

图 8.6 - ssh-keygen 执行在~/.ssh/{id_rsa,id_rsa.pub}下创建 RSA 密钥对

从这一点开始，该系统已为根用户创建了一个密钥对，并将其两部分存储在同一个文件夹中，默认情况下是`.ssh`。公共部分包含`.pub`后缀，而另一个包含私钥。

我们如何使用它们？如果我们在家目录的`.ssh`文件夹中查看，可以看到几个文件：我们有一个`authorized_keys`文件和一个`known_hosts`文件，除了刚刚创建的密钥对。`authorized_keys`文件将每行包含一个条目。这包含了可以用于此用户登录到此系统的公钥。

提示

可以与`authorized_keys`一起使用的各种选项远不止添加常规密钥 - 您还可以定义要执行的命令、密钥的到期时间、可以用于连接的远程主机，以便只有这些主机才能成功使用该密钥，等等。再次强调，`man sshd`是您的朋友，因此请查看其中的`AUTHORIZED_KEYS FILE FORMAT`部分，以了解更复杂的设置。

为了简化在远程系统上设置密钥的过程，我们有`ssh-copy-id`实用程序，它通过`ssh`连接到远程主机。这将要求输入`ssh`密码，并在我们的系统上安装可用的公钥。但是，这需要系统启用密码验证。

另一种方法是手动将我们的公钥附加到该文件（`.ssh/authorized_keys`），如下面的屏幕截图所示：

![图 8.7 - ssh-copy-id 失败和私钥手动授权](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/rhel8-adm/img/B16799_08_007.jpg)

图 8.7 - ssh-copy-id 失败和私钥手动授权

第一行尝试使用`ssh-copy-id`，但由于我们启用了密码验证，它尝试复制我们的公钥并失败了。然后，我们使用`>>`将公钥附加到`authorized_keys`文件中。最后，我们演示了如何使用`ssh`连接到`localhost`并在不需要密码的情况下执行命令。

重要提示

`.ssh`文件夹和`authorized_keys`文件的权限不能太开放（例如，777）。如果是这样，`ssh`守护程序将拒绝它们，因为有人可能已经添加了新的密钥，并试图在没有真正成为系统合法用户的情况下获得访问权限。

刚刚发生的事情打开了一个新的自动化世界。使用我们的系统和远程主机之间交换的密钥，我们现在可以远程连接到它们，以交互方式运行命令或对要在远程主机上执行的命令进行脚本化。我们可以在我们的终端中检查结果。让我们考虑这个简单的脚本，用于系统负载平均值检查，可以在[`github.com/PacktPublishing/Red-Hat-Enterprise-Linux-8-Administration/blob/main/chapter-08-remote-systems-administration/loadaverage-check.sh`](https://github.com/PacktPublishing/Red-Hat-Enterprise-Linux-8-Administration/blob/main/chapter-08-remote-systems-administration/loadaverage-check.sh)找到：

```
#!/usr/bin/bash
for system in host1 host2 host3 host4;
do
    echo "${system}: $(ssh ${system} cat /proc/loadavg)"
done
```

在这个例子中，我们正在运行一个循环来连接四个系统，然后输出该系统的名称和负载平均值，如下面的屏幕截图所示：

![图 8.8-无密码登录到四个主机以检查其负载平均值](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/rhel8-adm/img/B16799_08_008.jpg)

图 8.8-无密码登录到四个主机以检查其负载平均值

正如我们所看到的，我们迅速从四个主机上获取了信息。如果您想在您的环境中测试这一点，您可能想要实践一下我们在*第六章*中学到的关于在`/etc/hosts`文件中创建条目的内容，该文件指向我们想要尝试的主机名的`127.0.0.1`，以便连接到您自己的练习系统，正如我们在*第六章*中解释的那样，*启用网络连接*。

现在，想想我们远程管理系统的不同选项：

+   检查一系列主机的 IP。

+   安装更新或添加/删除一个软件包。

+   检查本地时间以防系统偏离。

+   在向系统添加新用户后重新启动一个服务。

还有更多选项，但这些是主要选项。

当然，还有更适合远程管理系统并确保错误被正确检测和处理的工具，比如使用 Ansible，但在这种情况下，对于简单的任务，我们可以继续进行。

以前，我们创建了一个密钥，并在要求输入密码时回复了`<ENTER>`。如果我们输入了密码会怎样？我们将在下一节中讨论这个问题。

## SSH 代理

如果我们决定创建一个带有密码保护的 SSH 密钥（明智的选择），我们将需要在每次使用密钥时输入密码，因此最终它可能与输入密码一样不安全，因为有人可能在我们的肩膀上观察。为了克服这一点，我们可以使用一个名为`ssh-agent`的程序，它可以临时将密码保留在内存中。这很方便，可以减少在输入密钥时有人观察的机会。

当您使用图形桌面时，比如`ssh-agent`。

当执行`ssh-agent`时，它将输出一些变量，必须在我们的环境中设置这些变量，以便我们可以利用它，如下面的屏幕截图所示：

![图 8.9-使用 ssh-agent 设置所需的变量](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/rhel8-adm/img/B16799_08_009.jpg)

图 8.9-使用 ssh-agent 设置所需的变量

如前面的屏幕截图所示，在被执行之前，或者在我们执行代理时，这些变量是未定义的。但是，如果我们执行`eval $(ssh-agent)`，我们将实现目标，即使这些变量被定义并准备好使用。

下一步是将密钥添加到代理。这可以通过`ssh-add`命令来完成，该命令可以在不带参数的情况下使用，也可以通过指定要添加的密钥来使用。如果密钥需要密码，它将提示您输入密码。完成后，我们可能能够使用该密钥以缓存的密码登录到系统，直到我们退出执行代理的会话，从而将密码从内存中清除。

下面的屏幕截图显示了用于生成带密码的新密钥对的命令。在这里，我们可以看到唯一的区别是我们将其存储在名为`withpass`的文件中，而不是我们在本章早些时候所做的：

![图 8.10 - 使用密码创建额外的 ssh 密钥对](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/rhel8-adm/img/B16799_08_010.jpg)

图 8.10 - 使用密码创建额外的 ssh 密钥对

我们可以看到如何连接到我们的本地主机（我们已经为其添加了带密码的公共部分到我们的`.ssh/authorized_keys`，同时删除了没有密码的部分），以及连接在下面的屏幕截图中的行为：

![图 8.11 - 使用 ssh-agent 记住我们的密码](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/rhel8-adm/img/B16799_08_011.jpg)

图 8.11 - 使用 ssh-agent 记住我们的密码

为了更清楚地说明这一点，让我们分析一下正在发生的事情：

1.  首先，我们`ssh`到主机。由于我们使用的默认密钥已从`authorized_keys`中删除，因此权限被拒绝。

1.  我们再次`ssh`，但在定义身份文件（密钥对）以连接时，我们可以看到，我们被要求输入密钥的密码，而不是登录到系统。

1.  然后，我们注销并关闭连接。

1.  接下来，我们尝试添加密钥，但由于我们尚未为代理设置环境变量，因此出现错误。

1.  按照我们介绍代理时的指示，我们在当前 shell 中执行加载代理环境变量的命令。

1.  当我们尝试使用`ssh-add withpass`添加密钥时，代理会要求输入我们的密码。

1.  当我们最终`ssh`到主机时，我们可以连接而无需密码，因为密钥已经在我们的密钥对的内存中。

在这里，我们已经实现了两件事：我们现在有了一个自动化/无人参与的连接系统的方法，并确保只有授权用户才能知道解锁它们的密码。

我们将在下一节学习如何进行远程文件管理！

# SCP/rsync - 远程文件管理

与`telnet`类似，许多设备和系统上已经用`ssh`替换了它，使用不安全的文件传输解决方案正在减少。默认情况下是`21`，但由于通信是明文的，因此很容易被拦截凭据。FTP 仍然被广泛使用，主要用于在只允许匿名访问并希望转移到更安全选项的服务器上提供文件。

SSH 通常启用两个接口来复制文件：`scp`和`sftp`。第一个用法类似于常规的`cp`命令，但在这里，我们接受远程主机作为我们的目标或源，而`sftp`使用了类似于与 FTP 服务器交互的传统`ftp`命令的客户端方法。只需记住，在这两种情况下，连接都是加密的，并且在目标主机上通过`22/tcp`端口进行。

我们将在下一节深入研究 SCP。

## 使用 OpenSSH 安全文件传输传输文件

`scp`命令是`openssh-clients`软件包的一部分，允许我们使用整个过程的`ssh`层在系统之间复制文件。这使我们能够安全地传输文件内容，以及通过密钥对登录引入的所有自动化功能，到各种系统。

为了设置这个例子，我们将在我们的示例系统中创建一个新用户，该用户将用于使用本节描述的工具复制文件，如下面的屏幕截图所示：

![图 8.12 - 准备我们的系统，添加额外用户以练习文件传输](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/rhel8-adm/img/B16799_08_012.jpg)

图 8.12 - 准备我们的系统，添加额外用户以练习文件传输

您可以在[`github.com/PacktPublishing/Red-Hat-Enterprise-Linux-8-Administration/blob/main/chapter-08-remote-systems-administration/create-kys-user.sh`](https://github.com/PacktPublishing/Red-Hat-Enterprise-Linux-8-Administration/blob/main/chapter-08-remote-systems-administration/create-kys-user.sh)中找到前面的命令的脚本。

一旦用户已创建并且密钥已复制，我们就可以开始测试了！

在本章的前面，我们创建了一个名为`withpass`的密钥，其公共对应物为`withpass.pub`。为了将密钥提供给新创建的用户，我们可以通过以下命令将两个文件都复制到`kys`用户：

```
scp withpass* kys@localhost:
```

让我们使用这个模板来分析命令的每个部分：

```
scp origin target
```

在我们的情况下，`origin`用`withpass.*`表示，这意味着它将选择以`withpass`字符串开头的所有文件。

我们的`target`值是一个远程主机。在这里，用户名是`kys`，主机是`localhost`，应该存储文件的文件夹是默认文件夹，通常是指定用户的主文件夹（在`:`符号后的空路径的用户）。

在下面的截图中，我们可以看到命令的输出以及我们稍后可以通过远程执行进行的验证：

![图 8.13 - 将 SCP 文件复制到远程路径并验证已复制的文件](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/rhel8-adm/img/B16799_08_013.jpg)

图 8.13 - 将 SCP 文件复制到远程路径并验证已复制的文件

在前面的截图中，您还可以检查由 root 用户拥有的文件是否已复制。复制的文件由`kys`用户拥有，因此文件内容相同，但由于目标上的创建者是`kys`用户，文件具有其所有权。

我们还可以通过首先指定远程文件然后将本地路径作为目标来进行更复杂的复制，以便将文件下载到我们的系统，或者甚至在远程位置之间复制文件（除非我们指定`-3`选项，否则它们将直接从`origin`到`target`）。

提示

提醒时间！`man scp`将向您显示`scp`命令的所有可用选项，但由于它基于`ssh`，我们使用`ssh`的大多数选项也可用，以及我们在`.ssh/config`文件中定义的主机定义。

我们将在下一节中探索`sftp`客户端。

## 使用 sftp 传输文件

与`scp`相比，可以像使用常规`cp`命令一样编写脚本，`sftp`具有用于浏览远程系统的交互式客户端。但是，当指定包含文件的路径时，它也可以自动检索文件。

要了解可用的不同命令，可以调用`help`命令，它将列出可用的选项，如下面的截图所示：

![图 8.14 - 可用的 sftp 交互模式命令](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/rhel8-adm/img/B16799_08_014.jpg)

图 8.14 - 可用的 sftp 交互模式命令

让我们通过以下截图来看一个例子：

![图 8.15 - sftp 的两种操作模式 - 自动传输或交互传输](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/rhel8-adm/img/B16799_08_015.jpg)

图 8.15 - sftp 的两种操作模式 - 自动传输或交互传输

在这个例子中，我们创建了一个本地文件夹作为我们的工作文件夹，名为`getfilesback`。首先，我们使用远程路径和我们识别的文件调用了`sftp`。在这里，`sftp`已自动传输了文件并停止执行。我们收到的文件现在属于我们的用户。

在第二个命令中，当我们使用用户和主机调用`sftp`并进入交互模式时，我们可以执行多个命令，类似于在远程 shell 会话上可以执行的操作。最后，使用带有`*`通配符字符的`mget`命令，我们将文件传输到我们的本地系统。

在这两种情况下，文件都已从远程系统传输到我们的本地系统，因此我们的目标已经实现。但是，使用`scp`需要知道要传输的文件的确切路径。另一方面，如果我们记不住，可能更方便使用`sftp`交互式客户端内的`ls`和`cd`命令来浏览系统，直到找到要传输的文件。

现在，让我们学习如何使用`rsync`快速传输文件和树。

## 使用 rsync 传输文件

虽然我们可以使用`scp`的`-r`选项来递归传输文件，但`scp`只处理文件的完全复制，如果我们只是想在系统之间同步一些文件夹，这并不理想。

1996 年，`rsync`推出，并且许多系统通过使用一个专用服务器来实现它，该服务器正在监听客户端连接。这是为了允许树与文件同步。这是通过复制文件之间的差异来完成的。在这里，比较了源和目标的部分，以查看是否应该复制差异。

通过`ssh`，并且在客户端和服务器上都安装了`rsync`软件包，我们可以利用`ssh`创建的安全通道和`rsync`提供的更快同步。

使用`rsync`守护程序和使用`ssh`的区别在于源或目标的语法，它要么使用`rsync://`协议，要么在主机名后使用`::`。在其他情况下，它将使用`ssh`甚至本地文件系统。

下面的截图显示了我们通过`rsync –help`命令提到的 URL 模式：

![图 8.16 – rsync 命令的帮助输出](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/rhel8-adm/img/B16799_08_016.jpg)

图 8.16 – rsync 命令的帮助输出

现在，让我们回顾一些我们可以与`rsync`一起使用的有用选项：

+   `-v`：在传输过程中提供更详细的输出。

+   `-r`：递归进入目录。

+   `-u`：更新 - 仅复制比目标文件更新的文件。

+   `-a`：归档（包括多个选项，如`–rlptgoD`）。

+   `-X`：保留扩展属性。

+   `-A`：保留 ACL。

+   `-S`：稀疏 - 空值序列将转换为稀疏块。

+   `--preallocate`：在传输文件之前声明所需的空间。

+   `--delete-during`：在复制过程中删除目标上没有的文件。

+   `--delete-before`：在复制之前删除目标上没有的文件。

+   `--progress`：显示复制的进度信息（已复制的文件与总文件数）。

`r``sync`算法将文件分成块，并为传输到源的每个块计算校验和。然后将它们与本地文件的校验和进行比较。我们只允许共享源和目标之间的差异。`rsync`默认不检查修改文件日期和大小，因此，如果文件在没有留下任何更改的情况下发生了更改，除非对每个候选文件强制进行校验和检查，否则可能无法检测到更改。

让我们看一些基本的例子：

+   `rsync –avr getfilesback/ newfolder/` 将会复制本地`getfilesback/`文件夹中的文件到`newfolder/`，并显示进度更新，但只针对更新的文件，如下面的截图所示：

![图 8.17 – 在相同的源/目标上使用 rsync 操作，重复以说明传输优化](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/rhel8-adm/img/B16799_08_017.jpg)

图 8.17 – 在相同的源/目标上使用的 rsync 操作，重复以说明传输优化

正如我们所看到的，第二个操作只发送了 85 字节并接收了 12 字节。这是因为在文件夹之间进行了一些校验和操作以验证，因为文件没有发生更改。如果我们使用`rsync -avr --progress getfilesback/ root@localhost:newfolder/`的远程目标方法，也可以获得相同的输出，但在这种情况下，将使用`ssh`传输。

让我们获取一些更大的示例文件，并通过在某个时间点检出 Git 存储库，传输文件，然后更新到最新版本来比较它们，以模拟对存储库的工作。然后，我们将再次进行同步。

首先，如果尚未安装，请安装`git`并执行以下代码检出一个示例存储库：

```
dnf –y install git   # install git in our system
git clone https://github.com/citellusorg/citellus.git  # clone a repository over https
cd citellus # to enter into the repository folder
git reset HEAD~400  # to get back 400 commits in history
```

此时，我们有一个准备好进行传输的文件夹。完成后，我们将执行`git pull`以与最新更改同步，并再次使用`rsync`复制差异。稍后，我们将使用`--delete`删除源上不再存在的任何文件。

让我们查看以下截图中显示的顺序：

![图 8.18 - 使用 rsync 将 git 文件夹同步到新文件夹](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/rhel8-adm/img/B16799_08_018.jpg)

图 8.18 - 使用 rsync 将 git 文件夹同步到新文件夹

在前面的截图中，注意命令的最后一行报告的加速情况。

现在，让我们执行`git pull`以获取我们缺少的 400 个更改，并再次执行`rsync`。我们将得到类似以下的输出：

![图 8.19 - 再次使用 rsync 复制差异](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/rhel8-adm/img/B16799_08_019.jpg)

图 8.19 - 再次使用 rsync 复制差异

在前面的截图中，注意最后一行报告的加速情况，以便与之前的进行比较。

通过这一系列截图，我们可以检查发送的总字节数的最后数字，以查看传输的改进，以及一些已接收的文件（因为我们添加了`-v`修饰符以获取详细输出和`--progress`）。

最大的优势在于在较慢的网络链接上执行复制，并且定期执行，例如，作为备份目的的远程复制。这是因为`rsync`只会复制更改，更新源上已修改的更新文件，并允许我们在`ssh`通道上使用压缩。例如，可以使用`rsync`镜像[`www.kernel.org/`](https://www.kernel.org/)上的 Linux 内核。

在接下来的部分，我们将深入探讨 SSH 的一个非常有趣的功能，使得连接到没有直接访问权限的服务器变得容易。

# 高级远程管理 - SSH 隧道和 SSH 重定向

SSH 有两个非常强大的功能，即 SSH 隧道和 SSH 重定向。当建立 SSH 连接时，不仅可以用来向远程主机发送命令并让我们像在本地系统上一样工作，还可以创建相互连接我们系统的隧道。

让我们尝试想象一个在许多公司中很常见的场景，即使用 VPN 来访问内部网络和所有服务和服务器，但使用 SSH 而不是常规 VPN。

所以，让我们在这个想象的场景中加入一些背景。

我们可以使用一个接收外部流量的主机，将来自我们的互联网路由器的`ssh`重定向到该系统中的`ssh`服务。因此，简而言之，我们的路由器通过 TCP 在端口`22`上接收连接，并将连接转发到我们的服务器。在本练习中，我们将为这个服务器命名为堡垒。

在这种情况下，我们的常识告诉我们，即使我们可以使用其他工具或甚至`ssh`连接到其他系统，我们也可以通过 SSH 到达那个堡垒主机。

我们能直接连接到内部网络中的其他主机吗？答案是肯定的，因为默认情况下，SSH 允许我们使用 TCP 转发（`sshd_config`设置`AllowTcpForwarding`），这使我们作为远程登录用户能够创建端口重定向，甚至是用于我们的连接的**SOCKS**代理。

例如，我们可以使用那个堡垒主机创建一个隧道，通过**Internet Message Access Protocol**（**IMAP**）和**Simple Mail Transfer Protocol**（**SMTP**）协议到达我们的内部邮件服务器，只需执行以下代码：

```
ssh –L 10993:imap.example.com:993 –L 10025:smtp.example.com:25 user@bastionhost
```

这个命令将监听本地端口`10993`和`10025`。所有在那里执行的连接将被隧道传输，直到`bastionhost`将它们连接到端口`993`的`imap.example.com`和端口`25`的`smtp.example.com`。这允许我们的本地系统使用这些自定义端口配置我们的电子邮件帐户，并使用`localhost`作为服务器，仍然能够访问这些服务。

提示

`1024`以下的端口被视为特权端口，通常只有 root 用户才能将服务绑定到这些端口。这就是为什么我们将它们用于我们的重定向端口`10025`和`10093`，这样普通用户就可以使用它们，而不需要 root 用户执行`ssh`连接。当您尝试绑定到本地端口时，请注意`ssh`消息，以防这些端口正在使用中，因为连接可能会失败。

此外，从目标服务器的角度来看，连接将看起来好像是从堡垒服务器发起的，因为它实际上是执行连接的服务器。

当打开端口列表开始增长时，最好回到本章开头所解释的内容：`~/.ssh/config`文件可以保存主机定义，以及我们想要创建的重定向，就像这个例子中所示的那样。

```
Host bastion
    ProxyCommand none
    Compression yes
    User myuser
    HostName mybastion.example.com
    Port 330
    LocalForward 2224 mail.example.com:993
    LocalForward 2025 smtp.example.com:25
    LocalForward 2227 ldap.example.com:389
    DynamicForward 9999
```

在这个例子中，当我们连接到我们的堡垒主机（通过`ssh bastion`）时，我们会自动启用`mybastion.example.com`的`330`端口，并为我们的`imap`，`smtp`和`ldap`服务器以及`9999`端口的动态转发（SOCKS 代理）定义端口转发。如果我们有不同的身份（密钥对），我们还可以通过`IdentityFile`配置指令为每个主机定义我们希望使用的身份，甚至可以使用通配符，如`Host *.example.com`，自动将这些选项应用于以该域结尾且没有特定配置段的主机。

注意

有时，在使用`ssh`，`scp`或`sftp`时，目标是要到达一个可以从堡垒主机访问的系统。这里不需要其他端口转发 - 只需要到达这些系统。在这种情况下，您可以使用方便的`-J`命令行选项（相当于定义`ProxyJump`指令）将该主机用作跳转主机，以便到达您想要到达的最终目标。例如，`ssh -J bastion mywebsiteserver.example.com`将透明地连接到`bastion`，然后从那里跳转到`mywebsiteserver.example.com`。

在下一节中，我们将学习如何保护自己免受远程连接的网络问题，并充分利用我们的远程终端连接。

# 使用 tmux 的远程终端

`tmux`是一个终端复用器，这意味着它允许我们在单个屏幕内打开和访问多个终端。一个很好的类比是图形桌面中的窗口管理器，它允许我们打开多个窗口，这样我们就可以在只使用一个监视器的情况下切换上下文。

`tmux`还允许我们分离和重新连接会话，因此在连接中断的情况下，它是完美的工具。例如，想象一下在服务器上执行软件升级。如果由于某种原因连接中断，那么相当于突然停止了升级过程，无论它当时处于什么状态，都可能导致不良后果。但是，如果升级是在`tmux`中启动的，命令将继续执行，一旦连接恢复，会话可以重新连接，并且输出将可供检查。

首先，让我们通过`dnf -y install tmux`在我们的系统上安装它。这行将下载软件包并使`tmux`命令可用。请记住，`tmux`的目标不是在我们的系统上安装它（即使这很有用），而是让它在我们连接的服务器上可用，以便在发生断开连接时获得额外的保护层。因此，习惯于在我们连接的所有服务器上安装它是一个好习惯。

提示

在`RHEL8`之前的版本中，用于创建虚拟多路复用终端的工具是`screen`，它已被标记为不推荐使用，并且只能通过`EPEL`存储库获得。如果您习惯于它的键绑定（`CTRL-A + <key`>），那么在`tmux`中大多数都是等效的（`CTRL-B + <key>`）。

在下面的截图中，我们可以看到在命令行上执行`tmux`后`tmux`的默认配置是什么样子的：

![图 8.20 – 执行后的 tmux 默认布局](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/rhel8-adm/img/B16799_08_020.jpg)

图 8.20 – 执行后的 tmux 默认布局

如前面的截图所示，我们的终端的视图并没有改变太多，除了窗口下部的状态栏。这显示了有关主机的一些信息，例如其名称，时间，日期以及打开窗口的列表，其中`0:bash`是活动窗口，如星号（`*`）符号所示。

有很多组合可以使用`tmux`，让我们熟悉一些最初的用例：

+   运行`tmux`以创建一个新会话。

+   运行`tmux at`以附加到先前的会话（例如，在重新连接到主机后）。

+   运行`tmux at –d`以附加到先前的会话并从中分离其他连接。

一旦我们进入`tmux`，就有一整套命令可以使用，这些命令都是以`CTRL+B`键为前缀的。让我们查看一些重要的命令（请记住在使用列表中的下一个项目之前必须先按下*Ctrl + B*）：

+   `?`：显示有关要使用的快捷键的内联帮助。

+   `c`：创建一个新窗口。

+   `n`/`p`：转到下一个/上一个窗口。

+   `d`：分离`tmux`会话。

+   `0-9`：转到按下数字编号的窗口。

+   `,`：重命名窗口。

+   `"`：水平分割窗格。

+   `%`：垂直分割窗格。

+   `space`：切换到下一个布局。

+   `&`：关闭窗口。

+   `Pg down`/`pg up`：在窗口历史记录中向上或向下移动。

+   箭头键：选择按下的方向中的窗格。

让我们在下面的截图中看一个示例：

![图 8.21 – tmux 中有四个窗格，在同一个窗口内运行不同的命令](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/rhel8-adm/img/B16799_08_021.jpg)

图 8.21 – tmux 中有四个窗格，在同一个窗口内运行不同的命令

正如我们所看到的，有几个命令同时运行 – `top`，`journalctl –f`，`iostat –x`和`ping` – 因此这是在执行操作时监视系统的好方法。

此外，`tmux`的一个优点是可以进行脚本化，因此如果我们在管理系统时使用一个布局，我们可以复制该脚本，并在连接到它们时立即执行它，这样我们就可以享受相同的布局甚至正在执行的命令。

如果您想在您的系统上尝试，可以在[`github.com/PacktPublishing/Red-Hat-Enterprise-Linux-8-Administration/blob/main/chapter-08-remote-systems-administration/term.sh`](https://github.com/PacktPublishing/Red-Hat-Enterprise-Linux-8-Administration/blob/main/chapter-08-remote-systems-administration/term.sh)找到带有额外注释和描述的以下代码：

```
#!/bin/bash
SESSION=$USER
tmux -2 new-session -d -s $SESSION # create new session
tmux select-window -t $SESSION:0  # select first window
tmux rename-window -t $SESSION "monitoring" #rename to monitoring
tmux split-window –h #split horizontally
tmux split-window –v #split vertically
tmux split-window –h # split again horizontally
tmux select-layout tiled #tile panes
tmux selectp –t1 # select pane 1
tmux send-keys "top" C-m #run top by sending the letters + RETURN
tmux selectp –t2 # select pane 2
tmux send-keys "journalctl -f" C-m # run journalctl
tmux selectp –t3 # select pane 3
tmux send-keys "iostat -x" C-m # run iostat
tmux selectp –t0 #select the pane without commands executed
```

一旦设置了带有`tmux`的会话，我们可以通过执行`tmux`附加到刚刚创建和配置的会话，这将显示类似于前面截图中显示的布局。

# 总结

在本章中，我们介绍了 SSH 以及如何使用它连接到远程系统，如何使用密钥进行身份验证，无论是否需要密码，以及如何利用它进行自动化，传输文件，甚至通过端口重定向使服务可访问或可达。通过`tmux`，我们学会了如何使我们的管理会话在网络中断时保持存活，并且通过自动化布局一目了然地显示重要信息。

在下一章中，我们将深入探讨通过 firewalld 来保护我们的系统网络，以仅暴露所需的服务。


# 第九章：使用 firewalld 保护网络连接

一位在军事受限环境中工作的优秀导师和技术专家曾经告诉我：“唯一安全的系统是关闭的系统，断开任何网络连接，并埋在沙漠中。”当然，他是对的，但我们必须提供服务使系统有用。这意味着让它运行并连接到网络。

在安全中使用的一种技术是减少事件发生，例如避免意外暴露漏洞和启用未经授权的远程访问，这是减少攻击面和应用深度防御原则的步骤之一。在网络中这样做的第一步是使用`firewall-cmd`和`systemd`服务单元来过滤连接，以简化其管理。

在本章中，我们将涵盖以下主题，以便更好地了解如何管理 RHEL 中的默认防火墙：

+   介绍 RHEL 防火墙 - firewalld

+   在系统上启用 firewalld 并查看默认区域

+   审查 firewalld 下的不同配置项

+   启用和管理服务和端口

+   创建和使用 firewalld 的服务定义

+   使用 Web 界面配置 firewalld

# 介绍 RHEL 防火墙 - firewalld

RHEL 带有两种低级网络流量过滤机制：`firewall-cmd`）。在本节中，我们将查看 RHEL 中的防火墙默认设置。

firewalld 默认安装在系统中，我们可以使用`rpm`命令来检查，因此无需安装它：

```
[root@rhel8 ~]# rpm -qa | grep firewalld
firewalld-filesystem-0.8.2-2.el8.noarch
firewalld-0.8.2-2.el8.noarch
```

如果由于某种原因我们的安装不包括 firewalld，我们可以通过运行`dnf install firewalld`来安装它。

firewalld 包括一个名为`firewalld`的服务，默认情况下配置为在启动时运行。我们可以使用`systemctl status firewalld`命令来检查这一点：

![图 9.1 - "systemctl status firewalld"的输出](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/rhel8-adm/img/B16799_09_001.jpg)

图 9.1 - "systemctl status firewalld"的输出

正如我们所看到的，`firewalld`服务已启用并正在运行。这是 RHEL 系统的默认状态。

系统管理员配置 firewalld 的主要方式是使用`firewall-cmd`命令。但是，您也可以执行以下操作：

+   在`/etc/firewalld/`中添加带有服务定义的新文件（如本章的*创建和使用 firewalld 的服务定义*部分所述）

+   使用名为**cockpit**的 Web 界面配置防火墙（如本章的*使用 Web 界面配置 firewalld*部分所述）

+   在您的桌面环境中使用`firewall-config`图形界面

在本章中，我们将回顾主要机制和 Web 界面。

现在我们知道了 RHEL 主防火墙的默认设置，让我们学习如何启用它。

# 在系统上启用 firewalld 并查看默认区域

我们已经看到了`systemctl`。让我们停止`firewalld`服务：

```
[root@rhel8 ~]# systemctl stop firewalld
[root@rhel8 ~]# systemctl status firewalld
  firewalld.service - firewalld - dynamic firewall daemon
   Loaded: loaded (/usr/lib/systemd/system/firewalld.service; enabled; vendor preset: enabled)
   Active: inactive (dead) since Sun 2021-02-28 17:36:45 CET; 4s ago
     Docs: man:firewalld(1)
  Process: 860 ExecStart=/usr/sbin/firewalld --nofork --nopid $FIREWALLD_ARGS (code=exited, status=>
Main PID: 860 (code=exited, status=0/SUCCESS)

feb 28 17:36:19 rhel8.example.com systemd[1]: Starting firewalld - dynamic firewall daemon...
feb 28 17:36:20 rhel8.example.com systemd[1]: Started firewalld - dynamic firewall daemon.
feb 28 17:36:20 rhel8.example.com firewalld[860]: WARNING: AllowZoneDrifting is enabled. This is co>
feb 28 17:36:45 rhel8.example.com systemd[1]: Stopping firewalld - dynamic firewall daemon...
feb 28 17:36:45 rhel8.example.com systemd[1]: firewalld.service: Succeeded.
feb 28 17:36:45 rhel8.example.com systemd[1]: Stopped firewalld - dynamic firewall daemon.
```

在上一个输出中，如粗体所示，服务处于非活动状态。我们可以使用`firewall-cmd --state`命令来检查这一点：

```
[root@rhel8 ~]# firewall-cmd --state
not running
```

目前，防火墙服务已停止，所有规则已被删除。然而，服务的配置并未更改，因此如果我们重新启动系统，firewalld 将会再次运行。

提示

我们可以通过运行`nft list table filter`命令始终查看底层的`netfilter`规则。您可能希望在停止服务之前和之后运行它以查看差异。

现在，让我们尝试重新启动服务：

```
[root@rhel8 ~]# systemctl start firewalld
[root@rhel8 ~]# systemctl status firewalld
  firewalld.service - firewalld - dynamic firewall daemon
   Loaded: loaded (/usr/lib/systemd/system/firewalld.service; enabled; vendor preset: enabled)
   Active: active (running) since Sun 2021-02-28 17:43:31 CET; 7s ago
     Docs: man:firewalld(1)
Main PID: 1518 (firewalld)
    Tasks: 2 (limit: 8177)
   Memory: 23.3M
   CGroup: /system.slice/firewalld.service
           └─1518 /usr/libexec/platform-python -s /usr/sbin/firewalld --nofork –nopid
```

让我们检查 firewalld 是否正在运行：

```
[root@rhel8 ~]# firewall-cmd --state
running
```

要完全禁用服务，我们需要运行以下命令：

```
[root@rhel8 ~]# systemctl disable firewalld
Removed /etc/systemd/system/multi-user.target.wants/firewalld.service.
Removed /etc/systemd/system/dbus-org.fedoraproject.FirewallD1.service.
```

让我们看看服务已禁用但仍在运行：

```
[root@rhel8 ~]# systemctl status firewalld -n0
  firewalld.service - firewalld - dynamic firewall daemon
   Loaded: loaded (/usr/lib/systemd/system/firewalld.service; disabled; vendor preset: enabled)
   Active: active (running) since Sun 2021-02-28 17:43:31 CET; 8min ago
     Docs: man:firewalld(1)
Main PID: 1518 (firewalld)
    Tasks: 2 (limit: 8177)
   Memory: 24.1M
   CGroup: /system.slice/firewalld.service
           └─1518 /usr/libexec/platform-python -s /usr/sbin/firewalld --nofork –nopid
```

当您使用`systemctl`管理服务时，您需要了解启用和禁用服务只影响启动顺序中的行为，而启动和停止只影响服务的当前状态。

提示

要在一条命令中禁用和停止，我们可以使用`--now`选项；例如，`systemctl disable firewalld --now`。此选项也可用于启用和启动；例如，`systemctl enable firewalld --now`。

让我们重新启用服务，并确保它正在运行：

```
[root@rhel8 ~]# systemctl enable firewalld --now
Created symlink /etc/systemd/system/dbus-org.fedoraproject.FirewallD1.service → /usr/lib/systemd/system/firewalld.service.
Created symlink /etc/systemd/system/multi-user.target.wants/firewalld.service → /usr/lib/systemd/system/firewalld.service.
[root@rhel8 ~]# firewall-cmd --state
running
```

现在我们知道如何启动和停止，以及启用和禁用`firewalld`服务，让我们通过审查默认配置来了解配置结构并学习如何与其交互。

## 审查 firewalld 下的不同配置项

firewalld 在其配置中管理三个概念：

+   **区域**：firewalld 区域是一组规则，可以一起激活并分配给网络接口。它包括不同的服务和规则，还包括改变网络流量过滤行为的设置。

+   **服务**：firewalld 服务是必须一起配置的端口或端口组，以便特定系统服务（因此得名）能够正常工作。

+   `80`）和流量类型（即 TCP），可用于手动启用网络流量到自定义系统服务。

firewalld 管理两种类型的配置：

+   **运行**：当前应用于系统的规则。

+   **永久**：已保存的规则，将在服务启动时加载。

重要提示

运行与永久之间的概念是在运行系统中尝试网络过滤规则，一旦确保它们运行良好，就将它们保存为永久规则。记得检查你想要的规则是否已经正确保存在系统中。

现在，让我们检查一下我们的系统，看看有哪些可用的区域：

```
[root@rhel8 ~]# firewall-cmd --get-zones
block dmz drop external home internal nm-shared public trusted work
```

我们还可以检查默认应用的区域是哪个：

```
[root@rhel8 ~]# firewall-cmd --get-default-zone
public
```

让我们通过查看以下表格来回顾 firewalld 中可用的区域：

![](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/rhel8-adm/img/B16799_09_Table_9.1.jpg)

重要提示

您可以随时通过访问系统中可用的`firewalld.zones`手册页面来获取有关这些区域以及更多信息。一个很好的练习是查看前面提到的手册页面。

上述服务将在下一节中进行更详细的审查。现在，让我们学习如何管理区域。

让我们将默认区域更改为`home`：

```
[root@rhel8 ~]# firewall-cmd --set-default-zone=home
success
[root@rhel8 ~]# firewall-cmd --get-default-zone
home
```

我们可以将`public`区域设为默认，并将`home`区域分配给我们的本地网络：

```
[root@rhel8 ~]# firewall-cmd --set-default-zone=public
success
[root@rhel8 ~]# firewall-cmd --permanent --zone=internal \
--add-source=192.168.122.0/24
success
[root@rhel8 ~]# firewall-cmd --reload
success
[root@rhel8 ~]# firewall-cmd --get-active-zones
internal
  sources: 192.168.122.0/24
public
  interfaces: enp1s0
```

此配置允许我们仅将服务发布到本地网络，该网络被定义为`192.168.122.0/24`，并分配给`internal`区域。从现在开始，分配给`internal`区域的任何服务或端口只有在从内部网络的 IP 地址访问时才能访问。我们避免允许其他网络访问这些服务。

此外，要使服务可以从任何其他网络访问，我们只需要将它们分配给`public`区域。

让我们回顾一下常用的主要选项，以及可能有用的一些其他选项：

+   `--get-zones`：列出系统中已配置的区域。

+   `--get-default-zone`：显示默认配置的区域。

+   `--set-default-zone=<zone>`：设置默认区域。这将应用于运行和永久配置。

+   `--get-active-zones`：显示正在使用的区域以及它们适用于哪些网络/接口。

+   `--zone=<zone>`：用于为另一个选项指定区域。

+   `--permanent`：用于将更改应用于保存的配置。当使用此选项时，更改将不会应用于运行配置。

+   `--reload`：加载保存的配置作为运行配置。

+   `--add-source=<network>`：将源网络（CIDR 格式）添加到指定的区域。如果未指定区域，则使用默认区域。更改将应用于运行配置；使用`--permanent`来保存它们。

+   `--remove-source=<network>`：从指定的区域中删除源网络（CIDR 格式）。如果未指定区域，则使用默认区域。更改将应用于运行配置；使用`--permanent`来保存它们。

+   `--add-interface=<interface>`：将来自接口的流量路由到一个区域。如果没有指定，默认区域将被使用。

+   `--change-interface=<interface>`：更改路由到接口的流量到一个区域。如果没有指定，将使用默认区域。

尽管这些选项列表可能非常有用，但完整的选项列表可在`firewall-cmd`的手册页上找到。您应该经常使用它来重新配置防火墙选项。

提示

要查看`firewall-cmd`的手册页，只需运行`man firewall-cmd`。

既然我们知道了区域是什么以及它们是如何选择的，让我们学习如何管理服务和端口。

# 启用和管理服务和端口

正如我们在前一节中提到的，**firewalld 服务**是一种端口或一组端口，它们被一起配置为特定系统服务（因此得名）以使其正常工作。有一组服务在一个或多个可用的**firewalld 区域**中默认启用。让我们从回顾它们开始：

+   `22`，是`TCP`类型。

+   `224.0.0.251`（IPv4）或`ff02::fb`（IPv6），端口`5353`，是`UDP`类型。

+   `631`，使用`UDP`协议。

+   `137`和`138`，是`UDP`类型。

+   `fe80::/64`，端口`546`，是`UDP`类型。

+   `9090`，它是`TCP`类型。

如您所见，firewalld 服务可以指定多个端口、目标地址，甚至目标网络。

现在，让我们看看在我们的防火墙中配置的服务：

```
[root@rhel8 ~]# firewall-cmd --list-services
cockpit dhcpv6-client ssh
[root@rhel8 ~]# firewall-cmd --list-services --zone=internal
cockpit dhcpv6-client mdns samba-client ssh
```

请注意，当您没有建立一个区域时，显示的服务是与默认区域相关的服务 - 在这种情况下是`public`。但是，请考虑我们配置了多个区域。

现在，让我们安装一个 Web 服务器 - 在这种情况下，是 Apache `httpd`服务器：

```
[root@rhel8 ~]# dnf install httpd -y
Updating Subscription Management repositories.
Last metadata expiration check: 0:25:05 ago on lun 01 mar 2021 17:02:09 CET.
Dependencies resolved.
====================================================================================================
Package       Arch   Version                                Repository                        Size
====================================================================================================
Installing:
httpd         x86_64 2.4.37-30.module+el8.3.0+7001+0766b9e7 rhel-8-for-x86_64-appstream-rpms 1.4 M
Installing dependencies:
apr           x86_64 1.6.3-11.el8                           rhel-8-for-x86_64-appstream-rpms 125 k
[omitted]
Installed:
  apr-1.6.3-11.el8.x86_64
  apr-util-1.6.1-6.el8.x86_64                          
  apr-util-bdb-1.6.1-6.el8.x86_64                                  
  apr-util-openssl-1.6.1-6.el8.x86_64                              
  httpd-2.4.37-30.module+el8.3.0+7001+0766b9e7.x86_64      
  httpd-filesystem-2.4.37-30.module+el8.3.0+7001+0766b9e7.noarch 
  httpd-tools-2.4.37-30.module+el8.3.0+7001+0766b9e7.x86_64   
  mailcap-2.1.48-3.el8.noarch  
  mod_http2-1.15.7-2.module+el8.3.0+7670+8bf57d29.x86_64 
  redhat-logos-httpd-81.1-1.el8.noarch                      

Complete!
```

让我们启用并启动`httpd`服务：

```
[root@rhel8 ~]# systemctl enable httpd --now
Created symlink /etc/systemd/system/multi-user.target.wants/httpd.service → /usr/lib/systemd/system/httpd.service.
[root@rhel8 ~]# systemctl status httpd -n0
● httpd.service - The Apache HTTP Server
   Loaded: loaded (/usr/lib/systemd/system/httpd.service; enabled; vendor preset: disabled)
   Active: active (running) since Mon 2021-03-01 17:31:57 CET; 8s ago
     Docs: man:httpd.service(8)
Main PID: 2413 (httpd)
   Status: "Started, listening on: port 80"
    Tasks: 213 (limit: 8177)
   Memory: 25.0M
   CGroup: /system.slice/httpd.service
           ├─2413 /usr/sbin/httpd -DFOREGROUND
           ├─2414 /usr/sbin/httpd -DFOREGROUND
           ├─2415 /usr/sbin/httpd -DFOREGROUND
           ├─2416 /usr/sbin/httpd -DFOREGROUND
           └─2417 /usr/sbin/httpd -DFOREGROUND
```

现在，让我们检查服务是否在所有接口上监听：

```
[root@rhel8 ~]# ss -a -A "tcp" | grep http
LISTEN    0         128                 *:http                  *:*
```

可选地，我们可以使用外部机器检查端口是否打开（如果有的话）：

```
[root@external:~]# nmap 192.168.122.8
Starting Nmap 7.80 ( https://nmap.org ) at 2021-03-01 17:45 CET
Nmap scan report for rhel.redhat.lan (192.168.122.8)
Host is up (0.00032s latency).
Not shown: 998 filtered ports
PORT     STATE  SERVICE
22/tcp   open   ssh
9090/tcp closed zeus-admin
MAC Address: 52:54:00:E6:B4:A4 (QEMU virtual NIC)

Nmap done: 1 IP address (1 host up) scanned in 5.15 seconds
```

现在，我们可以在防火墙上启用`http`服务：

```
[root@rhel8 ~]# firewall-cmd --add-service http \
--zone=public --permanent
success
[root@rhel8 ~]# firewall-cmd --add-service http \
--zone=internal --permanent
success
[root@rhel8 ~]# firewall-cmd --reload
success
[root@rhel8 ~]# firewall-cmd --list-services
cockpit dhcpv6-client http ssh
[root@rhel8 ~]# firewall-cmd --list-services --zone=internal
cockpit dhcpv6-client http mdns samba-client ssh
```

有了这个，服务已经启用，端口已经打开。我们可以从外部机器验证这一点（这是可选的）：

```
[root@external:~]# nmap 192.168.122.8
Starting Nmap 7.80 ( https://nmap.org ) at 2021-03-01 17:50 CET
Nmap scan report for rhel.redhat.lan (192.168.122.8)
Host is up (0.00032s latency).
Not shown: 997 filtered ports
PORT     STATE  SERVICE
22/tcp   open   ssh
80/tcp   open   http
9090/tcp closed zeus-admin
MAC Address: 52:54:00:E6:B4:A4 (QEMU virtual NIC)

Nmap done: 1 IP address (1 host up) scanned in 5.18 seconds
```

我们现在可以看到端口`80`已经打开。我们还可以从 Web 服务器检索主页并显示第一行：

```
[root@external:~]# curl -s http://192.168.122.8 | head -n 1
<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.1//EN" "http://www.w3.org/TR/xhtml11/DTD/xhtml11.dtd">
```

重要提示

firewalld 中的服务定义保存在`/usr/lib/firewalld/services`目录中的独立文件中。如果您需要查看服务的详细信息，可以去那里检查文件和其定义。

现在，让我们尝试从公共网络中删除该服务，因为这将是一个内部服务：

```
[root@rhel8 ~]# firewall-cmd --list-services --zone=public
cockpit dhcpv6-client http ssh
[root@rhel8 ~]# firewall-cmd --remove-service http \
--zone=public --permanent
success
[root@rhel8 ~]# firewall-cmd --reload
success
[root@rhel8 ~]# firewall-cmd --list-services --zone=public
cockpit dhcpv6-client ssh
```

假设我们没有服务定义，但仍然想在`public`接口上打开`TCP`端口`80`：

```
[root@rhel8 ~]# firewall-cmd --list-ports --zone=public

[root@rhel8 ~]# firewall-cmd --add-port 80/tcp --zone=public --permanent
success
[root@rhel8 ~]# firewall-cmd --reload
success
[root@rhel8 ~]# firewall-cmd --list-ports --zone=public
80/tcp
```

我们可以一次性查看端口和服务，如下所示：

```
[root@rhel8 ~]# firewall-cmd --list-all --zone=public
public (active)
  target: default
  icmp-block-inversion: no
  interfaces: enp1s0
  sources: 
  services: cockpit dhcpv6-client ssh
  ports: 80/tcp
  protocols: 
  masquerade: no
  forward-ports: 
  source-ports: 
  icmp-blocks: 
  rich rules:
```

现在，我们可以移除该端口：

```
[root@rhel8 ~]# firewall-cmd --list-ports --zone=public
80/tcp
[root@rhel8 ~]# firewall-cmd --remove-port 80/tcp --zone=public --permanent
success
[root@rhel8 ~]# firewall-cmd --reload
success
[root@rhel8 ~]# firewall-cmd --list-ports --zone=public

[root@rhel8 ~]#
```

有了这个，我们知道如何向防火墙添加和删除服务和端口，并检查它们的状态。让我们回顾一下我们可以用于`firewall-cmd`的选项：

+   `--zone=<zone>`：用于指定一个区域。当没有指定区域时，将使用默认区域。

+   `--list-services`：显示指定区域的服务列表。

+   `--add-service`：将服务添加到指定区域。

+   `--remove-service`：从指定区域中删除一个服务。

+   `--list-ports`：列出指定区域中打开的端口。

+   `--add-port`：将端口添加到指定区域。

+   `--remove-port`：从指定区域中删除一个端口。

+   `--list-all`：列出与指定区域相关的端口、服务和所有配置项。

+   `--permanent`：规则将应用于保存的配置，而不是运行的配置。

+   `--reload`：从保存的配置重新加载规则。

现在我们知道如何在防火墙中为不同的区域分配服务和端口，让我们来看看它们是如何定义的。

# 创建和使用 firewalld 的服务定义

firewalld 的服务定义存储在`/usr/lib/firewalld/services`目录中。让我们看一下一个简单的服务，比如存储在`ssh.xml`文件中的`ssh`服务，它具有以下内容：

```
<?xml version="1.0" encoding="utf-8"?>
<service>
  <short>SSH</short>
  <description>Secure Shell (SSH) is a protocol for logging into and executing commands on remote machines. It provides secure encrypted communications. If you plan on accessing your machine remotely via SSH over a firewalled interface, enable this option. You need the openssh-server package installed for this option to be useful.</description>
  <port protocol="tcp" port="22"/>
</service>
```

在这里，我们可以看到我们只需要一个包含三个部分的 XML 文件来描述一个基本服务：

+   `short`: 服务的简称

+   `description`: 服务的详细描述

+   `port`: 为此服务打开的端口

假设我们想在服务器上安装 Oracle 数据库。我们必须打开`1521`端口，并且它必须是`TCP`类型。让我们创建`/etc/firewalld/services/oracledb.xml`文件，内容如下：

```
<?xml version="1.0" encoding="utf-8"?>
<service>
  <short>OracleDB</short>

  <description>Oracle Database firewalld service. It allows connections to the Oracle Database service. You will need to deploy Oracle Database in this machine and enable it for this option to be useful.</description>
  <port protocol="tcp" port="1521"/>
</service>
```

我们可以使用以下代码来启用它：

```
[root@rhel8 ~]# firewall-cmd --reload
success
[root@rhel8 ~]# firewall-cmd --add-service oracledb
success
[root@rhel8 ~]# firewall-cmd --list-services
cockpit dhcpv6-client oracledb ssh
```

现在，它已经准备好在运行配置中使用。我们可以这样将其添加到永久配置中：

```
[root@rhel8 ~]# firewall-cmd --add-service oracledb --permanent
success
```

提示

很少需要打开更复杂的服务。无论如何，描述如何创建 firewalld 服务的手册页面是`firewalld.service`，可以通过运行`man firewalld.service`来打开。

有了这个，我们可以很容易地标准化要在我们系统的防火墙中打开的服务。我们可以将这些文件包含在我们的配置存储库中，以便与整个团队共享。

现在我们可以创建一个服务，让我们看一种更简单的方式来配置 RHEL 防火墙；也就是使用 Web 界面。

# 使用 Web 界面配置 firewalld

要使用 RHEL8 的 RHEL Web 管理界面，我们必须安装它。运行它的软件包和服务都称为`cockpit`。我们可以通过运行以下代码来安装它：

```
[root@rhel8 ~]# dnf install cockpit -y
Updating Subscription Management repositories.
[omitted]     
Installing:
cockpit                      x86_64 224.2-1.el8             rhel-8-for-x86_64-baseos-rpms     74 k
[omitted]     
  cockpit-224.2-1.el8.x86_64                      
  cockpit-bridge-224.2-1.el8.x86_64               
  cockpit-packagekit-224.2-1.el8.noarch           
  cockpit-system-224.2-1.el8.noarch               
  cockpit-ws-224.2-1.el8.x86_64                         

Complete!
```

现在，让我们启用它：

```
[root@rhel8 ~]# systemctl enable --now cockpit.socket
Created symlink /etc/systemd/system/sockets.target.wants/cockpit.socket → /usr/lib/systemd/system/cockpit.socket.
```

提示

Cockpit 使用了一个巧妙的技巧来节省资源。界面被停止，但启用了一个套接字来监听端口`9090`。当它接收到连接时，cockpit 就会启动。这样，它只会在使用时消耗您机器上的资源。

现在，让我们学习如何将`DNS`服务添加到`public`区域。

让我们通过将浏览器指向机器的 IP 和端口`9090`来访问 cockpit – 在这种情况下，`https://192.168.122.8:9090`。让我们使用在安装过程中提供的密码以`root`身份登录：

![图 9.2 – Cockpit 登录界面](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/rhel8-adm/img/B16799_09_002.jpg)

图 9.2 – Cockpit 登录界面

现在，我们可以访问 cockpit 仪表板，其中包含有关系统的信息：

![图 9.3 – Cockpit 初始界面和仪表板](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/rhel8-adm/img/B16799_09_003.jpg)

图 9.3 – Cockpit 初始界面和仪表板

现在，让我们转到**网络**，然后点击**防火墙**，如下面的截图所示：

![图 9.4 – Cockpit 访问防火墙配置](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/rhel8-adm/img/B16799_09_004.jpg)

图 9.4 – Cockpit 访问防火墙配置

在这一点上，我们可以点击**添加服务**在**公共区域**部分来修改它并添加一个服务：

![图 9.5 – Cockpit 防火墙配置界面](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/rhel8-adm/img/B16799_09_005.jpg)

图 9.5 – Cockpit 防火墙配置界面

将**dns**服务添加到防火墙的**公共区域**部分的步骤很简单：

1.  点击**服务**。

1.  通过输入`dns`来筛选服务。

1.  选择**dns**服务，使用**TCP:53**和**UDP:53**。

1.  点击**添加服务**：

![图 9.6 – Cockpit 防火墙 – 将服务添加到公共区域](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/rhel8-adm/img/B16799_09_006.jpg)

图 9.6 – Cockpit 防火墙 – 将服务添加到公共区域

一旦你这样做了，该服务将被添加到运行和永久配置中。它将显示在 cockpit 的**公共区域**部分上：

![图 9.7 – Cockpit 防火墙 – 将 DNS 服务添加到公共区域的结果](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/rhel8-adm/img/B16799_09_007.jpg)

图 9.7 – Cockpit 防火墙 – 将 DNS 服务添加到公共区域的结果

有了这个，我们知道如何使用 Web 界面对 RHEL8 中的防火墙进行修改。我们将把在本章开头使用命令行进行的配置删除并重新进行，但这次使用 Web 界面。

# 总结

安全性是系统管理的一个非常重要的部分。仅仅因为系统在隔离网络中就禁用安全措施是违背了深度防御原则的，因此这是极为不鼓励的。

在本章中，我们看到了在 RHEL8 中使用 firewalld 配置防火墙是多么简单和容易，从而为我们提供了另一个工具来管理、过滤和保护系统中的网络连接。我们还使用了 cockpit，这是一个使这项任务更加直观和易于执行的 Web 管理工具。

我们现在可以控制系统的网络连接，提供我们想要提供的服务，并为它们增加一层安全性。我们还知道如何管理区域以及如何根据系统的用例来使用它们。我们现在可以定义我们自己的自定义服务，以便我们始终可以为它们过滤网络连接。我们现在还可以通过使用 RHEL 中包含的防火墙来部署更安全的系统。

现在，我们准备在下一章中学习更多关于 RHEL 中的安全性。记住，安全是一个团队运动，系统管理员是关键。
