# 红帽企业 Linux 8 管理（四）

> 原文：[`zh.annas-archive.org/md5/0CCDE6F20D3A1D212C45A9BF7E65144A`](https://zh.annas-archive.org/md5/0CCDE6F20D3A1D212C45A9BF7E65144A)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第十章：使用 SELinux 保护系统

在本章中，我们将熟悉 SELinux。SELinux 已经存在一段时间了，但对其工作原理的不了解导致许多人建议禁用它。

这不是我们想要的，因为这就像告诉用户放弃密码因为难记一样。

我们将介绍 SELinux 的起源，以及默认模式和策略是什么。然后，我们将了解 SELinux 如何应用于我们的文件、文件夹和进程，以及如何将它们恢复到系统默认值。

此外，我们将探讨如何使用布尔值对策略进行微调，并通过以下部分的帮助解决常见问题：

+   强制和宽松模式下的 SELinux 使用

+   审查文件和进程的 SELinux 上下文

+   使用 semanage 调整策略

+   将更改的文件上下文恢复为默认策略

+   使用 SELinux 布尔设置启用服务

+   SELinux 故障排除和常见修复

最后，我们将更好地了解如何正确使用 SELinux 以及如何从它为我们的系统提供的额外保护中受益。

在本章中，将详细解释 SELinux 的工作原理，以帮助我们了解它的运作方式，即使在现实中使用它也要简单得多。我们还将使用这些示例来说明 SELinux 防止攻击或配置错误的情况。

让我们亲自动手使用 SELinux！

# 技术要求

可以继续使用本书开头创建的虚拟机*第一章*中的练习，*安装 RHEL8*。本章所需的任何额外软件包都将在文本旁边标明，并可从[`github.com/PacktPublishing/Red-Hat-Enterprise-Linux-8-Administration`](https://github.com/PacktPublishing/Red-Hat-Enterprise-Linux-8-Administration)下载。

# 强制和宽松模式下的 SELinux 使用

**安全增强型 Linux**（**SELinux**）于 2000 年 12 月通过 Linux-Kernel 邮件列表推出，是由**国家安全局**（**NSA**）启动的产品，旨在通过强制访问控制和基于角色的访问控制来提高操作系统的安全性，而不是系统中可用的传统自主访问控制。

在 Linux 内核引入 SELinux 之前，关于正确的实施方式进行了讨论，最终引入了一个名为**Linux 安全模块（LSM）**的内核框架，并使用它实施了 SELinux，以便其他方法也可以使用 LSM，而不仅仅是 SELinux。

SELinux 为 Linux 提供了安全改进，用户、进程甚至其他资源对文件的访问可以以非常精细的方式进行控制。

让我们举一个例子来更清楚地说明 SELinux 何时发挥作用：当 Web 服务器从用户中提供页面时，它会从用户的主目录中的`public_html`或`www`文件夹（最常见的文件夹）读取文件。能够从用户的主目录中读取文件可能会在 Web 服务器进程被攻击者劫持时泄露内容，而正是在这一刻，SELinux 发挥作用，因为它将自动阻止对 Web 服务器不应访问的文件的访问。

然后，SELinux 限制进程和服务只执行它们应该执行的操作，并且只使用经授权的资源。这是一个非常重要的功能，即使在可能导致访问意外文件或资源的软件错误的情况下也能保持控制。如果没有经活动策略授权，SELinux 将阻止它。

重要提示

如果用户由于不正确的文件权限而无法访问文件，那么 SELinux 权限总是在常规**自主访问控制**（**DAC**）之后出现。SELinux 在这里无能为力。

默认情况下，系统安装应该以“强制执行”模式部署，并使用“定向”策略。可以通过执行`sestatus`来检查当前系统状态，如下面的屏幕截图所示：

![图 10.1 – 我们系统的 sestatus 输出](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/rhel8-adm/img/B16799_10_001.jpg)

图 10.1 – 我们系统的 sestatus 输出

正如我们所看到的，我们的系统已经启用了 SELinux，并使用了“定向”策略，目前处于“强制执行”状态。让我们了解一下这意味着什么。

SELinux 通过在系统中定义`dnf list selinux-policy-*`来工作，“定向”和`mls`是最常见的。

我们将专注于定向策略，但为了对`mls`进行类比，`su`或`sudo`，它们仍然会附加原始标签，因此如果通过本地终端或远程连接进行根登录和`sudo`执行，权限可能会降低。

列为“强制执行”的模式意味着当前正在执行策略，这与“宽松”相反。我们可以将其视为处于活动状态并提供保护，而“宽松”则意味着处于活动状态但只提供警告，不提供保护。

为什么我们有“宽松”而不是只禁用呢？这个问题有点棘手，所以让我们更详细地解释一下它的工作原理，以提供更好的答案。

SELinux 使用文件系统中的扩展属性来存储标签。每次创建文件时，都会根据策略分配一个标签，但只有在 SELinux 处于活动状态时才会发生这种情况，因此这使得 SELinux“禁用”与 SELinux“宽松”不同，因为前者不会为新创建的文件创建这些标签。

此外，SELinux 在“宽松”模式下允许我们查看如果程序没有得到良好的策略或文件没有适当的标签将会引发的错误。

从“强制执行”切换到“宽松”和反之都非常容易，始终通过`setenforce`命令进行，而我们可以使用`getenforce`来检索当前状态，如下面的屏幕截图所示：

![图 10.2 – 改变 SELinux 强制执行状态](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/rhel8-adm/img/B16799_10_002.jpg)

图 10.2 – 改变 SELinux 强制执行状态

这可能看起来很基础，但实际上就是这么简单，只是运行一个命令而已。但是，如果状态被禁用，情况将完全不同。

SELinux 状态通过编辑`/etc/selinux/config`文件进行配置，但更改只有在系统重新启动后才会生效；也就是说，我们可以实时从“强制执行”切换到“宽松”，或从“宽松”切换到“强制执行”，但当从“禁用”切换到“启用”，或反之，则需要重新启动系统。

一般建议是将 SELinux 保持在强制执行模式，但如果出于任何原因它被禁用，建议在从“禁用”切换时首先将 SELinux 切换到“宽松”。这将使我们能够检查系统是否实际上可以正常工作，而不会因为内核阻止对文件和资源的访问而被锁定在外面。

注意

在从“禁用”切换到“宽松”或“强制执行”后的重新启动过程中，系统将根据策略强制重新标记文件系统。这是通过在我们文件系统的根文件夹中创建一个名为`/.autorelabel`的文件来实现的，这将触发该过程，并在之后再次重启。

但为什么选择禁用而不是“宽松”？例如，一些软件可能需要将其设置为禁用模式，即使以后可以重新启用以进行操作或出于其他原因，但请记住 SELinux 是一项保护系统的安全功能，应该保留。

请记住，SELinux 使用`/var/log/audit/audit.log`文件以及系统日志，是一个缓存，因此规则不会被频繁检查，以加快操作速度。

让我们回到文件系统存储标签的概念，并跳转到下一节，看看它们与进程、文件以及 SELinux 提供的 RBAC 之间的关系。

# 审查文件和进程的 SELinux 上下文

SELinux 使用标签，也称为附加到每个文件的安全上下文，并定义了几个方面。让我们用`ls –l`命令在我们的 home 文件夹中检查一个示例，但使用一个特殊的修饰符`Z`，它也会显示 SELinux 属性，如下截图所示：

![图 10.3 – 显示 SELinux 属性的文件列表](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/rhel8-adm/img/B16799_10_003.jpg)

图 10.3 – 显示 SELinux 属性的文件列表

让我们专注于其中一个文件的输出：

```
-rw-r--r--.  1 root unconfined_u:object_r:admin_home_t:s0     540 Mar  6 19:33 term.sh
```

SELinux 属性是列为`unconfined_u:object_r:admin_home_t:s0`的属性：

+   `unconfined_u`

+   `object_r`

+   `admin_home_t`

+   `s0`在多级安全和多类别安全中

进程也会发生类似的情况，同样，我们可以在许多常见命令后添加`Z`来获取上下文，例如，使用`ps Z`，如下截图所示：

![图 10.4 – 带有 SELinux 上下文的 ps 输出](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/rhel8-adm/img/B16799_10_004.jpg)

图 10.4 – 带有 SELinux 上下文的 ps 输出

再次，让我们检查其中一行：

```
unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023 2287661 pts/0 S+   0:00 tmux
```

同样，我们可以看到相同的方法：用户、角色、类型和多级安全和多类别安全。

现在我们已经介绍了它的外观，让我们专注于它在有针对性的策略中的工作方式。

有针对性的策略允许所有东西都可以像系统中没有启用 SELinux 一样运行，除了它所针对的服务。这在安全性和可用性之间取得了很好的平衡。

在策略开发过程中，会添加新的服务，同时对其他服务进行改进，并且对许多最常见的服务编写了保护它们的策略。

SELinux 还具有名为**转换**的功能。转换允许由用户启动的一个进程，具有某个特定角色的二进制文件，通过执行转换为其他角色，后者用于定义其权限。

正如你所想象的那样，我们的用户也有一个 SELinux 上下文，同样，我们可以使用`id -Z`命令来检查它：

```
unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023
```

因此，回到第一个例子，Apache Web 服务器由`httpd`软件包提供，可以通过`dnf –y install httpd`进行安装。安装后，让我们使用`systemctl start httpd`启动它，并使用`systemctl enable httpd`启用它，然后使用`firewall-cmd --add-service=http`和`firewall-cmd --add-service=https`打开防火墙，就像我们在前几章中对其他服务所做的那样。

先前的命令可以在以下脚本中找到：[`github.com/PacktPublishing/Red-Hat-Enterprise-Linux-8-Administration/blob/main/chapter-10-selinux/apache.sh`](https://github.com/PacktPublishing/Red-Hat-Enterprise-Linux-8-Administration/blob/main/chapter-10-selinux/apache.sh)。

让我们看看以下截图中所有这些是如何发挥作用的：

![图 10.5 – Web 服务器 SELinux 上下文](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/rhel8-adm/img/B16799_10_005.jpg)

图 10.5 – Web 服务器 SELinux 上下文

在这里，我们可以看到磁盘上的可执行文件具有上下文`httpd_exec_t`，进程是`httpd_t`，它提供的文件/文件夹是`httpd_sys_content_t`，它可以工作！

现在让我们在我们的`home`文件夹中创建一个`index.htm`文件，并将其移动到`Apache Web Root`文件夹中，如下所示：

```
# echo '<html><head><title>Our test</title></head><body>This is our test html</body></html>' > index.htm
# cp index.htm /var/www/html/index2.htm
# mv index.htm /var/www/html/index1.htm
```

让我们看看当我们尝试访问文件时会发生什么，如下截图所示：

![图 10.6 – Apache 生成文件的行为](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/rhel8-adm/img/B16799_10_006.jpg)

图 10.6 – Apache 生成文件的行为

正如我们所看到的，每个文件都有一个 SELinux 上下文，但除此之外，Apache 拒绝访问我们移动的文件(`index1.htm`)，但显示我们复制的文件(`index2.htm`)的内容。

这里发生了什么？我们复制了一个文件并移动了另一个文件，来自同一个源，但它们具有两个不同的 SELinux 上下文。

让我们扩展测试，如下截图所示：

![图 10.7 – 在 SELinux 的宽容模式下重试](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/rhel8-adm/img/B16799_10_007.jpg)

图 10.7 – 在 SELinux 的宽容模式下重试

正如我们在前面的截图中所看到的，我们现在能够访问文件内容，所以你可以说：“SELinux 有什么问题，不允许我的网站工作？”，但正确的表达方式应该是：“看看 SELinux 如何保护我们不让个人文件在网站上泄露”。

如果不是直接将文件移动到 Apache 的`/var/www/html`，而是攻击者试图访问我们的家庭文件夹文件，SELinux 将默认拒绝这些访问。`httpd_t`进程无法访问`admin_home_t`上下文。

当我们尝试让 Apache 或任何其他受目标策略约束的服务监听默认配置的端口之外的端口时，类似的事情会发生，了解我们可以或不可以做什么的最佳方法是学习`semanage`实用程序。

使用`semanage`，我们可以列出、编辑、添加或删除策略中的不同值，甚至导出和导入我们的自定义内容，所以让我们使用它来通过我们的`httpd`示例学习更多关于它的知识。

让我们在下一节学习关于`semanage`的知识。

# 使用 semanage 调整策略

正如我们之前介绍的，目标策略包含一些为其定义的服务强制执行的配置，允许保护这些服务，同时不干扰它不知道的服务。

有时候我们需要调整一些设置，比如允许`http`或`ssh`守护程序监听备用端口或访问其他文件类型，但又不失去 SELinux 提供的额外保护层。

首先，让我们确保在我们的系统中安装了`policycoreutils`和`policycoreutils-python-utils`，使用`dnf –y install policycoreutils-python-utils policycoreutils`，因为它们提供了我们将在本章和下一节中使用的工具。

让我们通过一个例子来学习。让我们看看`httpd_t`可以访问哪些端口，使用`semanage port -l|grep http`命令：

```
http_cache_port_t              tcp      8080, 8118, 8123, 10001-10010
http_cache_port_t              udp      3130
http_port_t                    tcp      80, 81, 443, 488, 8008, 8009, 8443, 9000
```

正如我们所看到的，`http_port_t`，由 Apache 守护程序使用，默认情况下允许使用`tcp`的端口`80`、`81`、`443`、`488`、`8008`、`9009`、`8443`和`9000`。

这意味着如果我们想在这些端口中的任何一个上运行 Apache，不需要对策略进行任何更改。

如果我们重复这个命令，但是对于`ssh`，我们只看到端口`22`被打开（执行`semanage port -l|grep ssh`）：

```
ssh_port_t                     tcp      22
```

例如，我们可能想要添加另一个端口，比如`2222`，到可能端口的列表中，以便隐藏标准端口被端口扫描器测试。我们可以通过`semanage port -a -p tcp -t ssh_port_t 2222`来实现，然后使用先前的命令`semanage port –l|grep ssh`进行验证，现在显示如下：

```
ssh_port_t                     tcp      2222, 22
```

正如我们所看到的，端口`2222`已经添加到`ssh_port_t`类型的可用端口列表中，这使得`ssh`守护程序可以开始监听它（当然，这需要在我们获得可用服务之前对`ssh`守护程序配置和防火墙进行额外的配置）。

同样地，例如，一些网络服务需要写入特定文件夹以存储配置，但默认情况下，`/var/www/html`上的上下文是`httpd_sys_content_t`，不允许写入磁盘。

我们可以通过`semanage fcontext –l`检查可用的文件上下文，类似于我们对端口所做的方式，但是文件列表很长，因为 Web 服务器可能使用常见位置，如`logs`和`cgi-bin`，以及用于证书、配置和家目录的文件系统文件，以及 PHP 等扩展名。当您使用前面的命令检查上下文时，注意可用的不同类型以及一个列表的结构是什么，例如：

```
/var/www/html(/.*)?/wp-content(/.*)?               all files          system_u:object_r:httpd_sys_rw_content_t:s0
```

正如我们所看到的，有一个正则表达式匹配`/var/www/html`路径内`wp-content`文件夹中的文件，适用于所有文件，并设置了`httpd_sys_rw_content_t`的 SELinux 上下文，这允许读写访问。这个文件夹被流行的博客软件**WordPress**使用，因此策略已经准备好覆盖一些最受欢迎的服务、文件夹和要求，而无需系统管理员自行编写。

在调用`semanage`时，它将输出一些我们可以使用的子命令，例如以下内容：

+   `import`：这允许导入本地修改。

+   `export`：这允许导出本地更改。

+   `login`：这允许管理登录和 SELinux 用户关联。

+   `user`：这管理具有角色和级别的 SELinux 用户。

+   `port`：这管理端口定义和类型。

+   `ibpkey`：这管理 InfiniBand 定义。

+   `ibendport`：这管理 InfiniBand 端口定义。

+   `interface`：这定义了网络接口定义。

+   `module`：这管理 SELinux 的策略模块。

+   `node`：这管理网络节点的定义。

+   `fcontext`：这管理文件上下文定义。

+   `boolean`：这管理用于调整策略的布尔值。

+   `permissive`：这管理强制模式。

+   `dontaudit`：这管理策略中的`dontaudit`规则。

对于上述每个命令，我们可以使用`-h`参数来列出、帮助和了解可以用于每个命令的额外参数。

对于日常使用情况，大多数时候我们将使用`port`和`fcontext`，因为它们将涵盖扩展或调整 Red Hat Enterprise Linux 提供的可用服务，就像我们在`ssh`监听额外端口的示例中展示的那样。

重要提示

传统上，`semanage`，`regexp`用于将要使用的路径。遵循这种方法时，如果文件系统重新标记或恢复上下文，应用程序将继续工作。

让我们看看如何手动设置文件的上下文以及如何在下一节中恢复默认值。

# 将更改的文件上下文恢复为默认策略

在前一节中，我们提到了`semanage`如何使我们能够对策略进行更改，这是执行更改并将其持久化到未来文件和文件夹的推荐方式，但这并不是我们执行操作的唯一方式。

从命令行，我们可以使用`chcon`实用程序来更改文件的上下文。这将允许我们为要更改的文件定义用户、角色和类型，并且与其他文件系统实用程序（如`chmod`或`chown`）类似，我们也可以递归地影响文件，因此很容易将整个文件夹层次结构设置为所需的上下文。

我一直觉得非常有趣的一个功能是能够通过`--reference`标志复制文件的上下文，以便将引用文件的相同上下文应用于目标文件。

当我们在本章前面介绍`httpd`的示例时，我们对`index1.htm`和`index2.htm`进行了测试，它们被移动并复制到`/var/www/html`文件夹中。为了深入探讨这个例子，我们将额外复制`index1.htm`，以便在下一张截图中演示`chcon`的用法。请记住，直接在`/var/www/html`文件夹中创建文件将设置文件具有适当的上下文，因此我们需要在`/root`中创建它们，然后将它们移动到目标文件夹，正如我们在下一张截图中所看到的：

![图 10.8 – 演示 chcon 用法](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/rhel8-adm/img/B16799_10_008.jpg)

图 10.8 – 演示 chcon 用法

正如我们所看到的，`index1.htm`和`index3.htm`文件现在都具有适当的上下文，在第一种情况下，使用引用，在第二种情况下，定义要使用的类型。

当然，这不是唯一的方法。正如我们之前所指出的，为应用程序设置上下文的推荐方法是通过`semanage`定义`regexps`路径，这使我们能够使用`restorecon`命令根据配置将正确的上下文应用于文件。让我们看看下面的截图中它是如何操作的：

![图 10.9 – 使用 restorecon 恢复上下文](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/rhel8-adm/img/B16799_10_009.jpg)

图 10.9 – 使用 restorecon 恢复上下文

正如我们所见，我们使用了`restorecon –vR /var/www/html/`，它自动将`index3.htm`文件更改为`httpd_sys_content_t`，这是我们在测试`semanage`列出上下文时看到的该文件夹的定义。使用的参数`v`和`R`使实用程序报告更改（详细信息）并在提供的路径上递归工作。

假设我们通过在根文件系统上运行`chcon`来搞乱了系统。修复的方法是什么？在这种情况下，正如我们之前提到的，我们应该执行以下操作：

+   将操作模式设置为`permissive`以通过`setenforce 0`不阻止进一步访问。

+   放置标记以通过`touch /.autorelabel`重新标记文件系统。

+   修改`/etc/selinux/config`文件以将引导模式设置为`permissive`。

+   重新启动系统以进行重新标记。

+   系统重新启动后，再次编辑`/etc/selinux/config`，将操作模式定义为`enforcing`。

通过这种方式操作，而不仅仅是运行`restorecon -R /`，我们确保系统是可操作的，并且在重新启动和对文件系统应用完整的重新标记后将继续运行，因此可以安全地重新启用`enforcing`模式。

在下一节中，让我们看看如何在策略内部调整策略，使用布尔值来调整其工作方式。

# 使用 SELinux 布尔设置来启用服务

许多服务具有许多常见情况的广泛配置选项，但并非总是相同。例如，`http`服务器不应访问用户文件，但与此同时，从每个用户的主目录中的`www`或`public_html`文件夹启用个人网站是一种常见的操作方式。

为了克服这种情况，并同时提供增强的安全性，SELinux 策略使用布尔值。

布尔值是管理员可以设置的可调整的条件，可以在策略代码中启用或禁用条件。例如，通过执行`getsebol -a|grep ^http`（缩小列表）来查看`httpd`可用的布尔值：

```
httpd_can_network_connect --> off
httpd_can_network_connect_db --> off
httpd_can_sendmail --> off
httpd_enable_homedirs --> off
httpd_use_nfs --> off
```

此列表是可用布尔值的缩小子集，但它确实给了我们一个它可以实现的想法；例如，默认情况下，`http`不能使用网络连接到其他主机，或发送电子邮件（通常在 PHP 脚本中完成），甚至不能访问用户的主目录。

例如，如果我们想要在系统中启用用户从其主目录中的`www`文件夹发布其个人网页，即`/home/user/www/`，我们将不得不通过运行以下命令启用`httpd_enable_homedirs`布尔值：

```
setsebool -P httpd_enable_homedirs=1
```

这将调整策略以使`http`能够访问用户的主目录以在那里提供页面。如果服务器还存储在**网络文件系统**（**NFS**）或**公共互联网文件系统**（**CIFS**）挂载上，将需要额外的布尔值。我们仍然使用相同的有针对性的策略，但我们已经启用了内部条件，以允许访问不会被 SELinux 阻止。

重要提示

`-P`参数对于`setsebool`是必需的，以使更改*永久*。这意味着写入更改以使其持久化；如果没有它，一旦重新启动服务器，更改将丢失。

正如我们所见，`getsebool`和`setsebool`允许我们查询和设置调整策略的布尔值，而`semanage boolean -l`也可以帮助我们，正如我们在下面的截图中所看到的：

![图 10.10 – 使用 semanage 管理布尔值](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/rhel8-adm/img/B16799_10_010.jpg)

图 10.10 - 使用 semanage 管理布尔值

在前面的截图中，我们不仅可以看到使用`setsebool`编辑的布尔值，还可以看到预期行为的描述。

其中一个好处是，正如我们介绍的，`semanage`允许我们导出和导入对策略的本地更改，因此可以将进行的任何自定义导出并导入到另一个系统，以便轻松设置类似的服务器配置文件。

策略中的所有可能的布尔值都可以使用`semanage boolean –l`进行检查，类似于我们在`http`示例中列出应用程序的绑定端口时所做的。

我们已经了解了使用布尔值来调整策略如何适应一些特定但相当常见的情况。接下来，我们将探索管理员可能最常用的部分，即故障排除，但重点是 SELinux。

# SELinux 故障排除和常见修复

适应 SELinux 的主要问题之一是，许多不熟悉它的人会因为事情无法正常工作而责怪它；然而，这个论点已经有点过时了：SELinux 是在 2005 年推出的 Red Hat Enterprise Linux 4 中引入的。

大多数时候，与 SELinux 和我们的系统有关的问题都与更改文件上下文和更改服务端口有关，与策略本身有关的问题较少。

首先，有几个地方可以检查错误，但在我们的列表中，我们应该从审计日志或系统消息开始。例如，我们可以从我们在本章前面介绍的`/var/log/audit/audit.log`文件开始。

还要记住，SELinux**强制访问控制**（**MAC**）只有在我们从常规**自主访问控制**（**DAC**）中获得了访问权限后才起作用，也就是说，如果我们没有权限检查文件（例如，模式 400 和我们的用户不是所有者），那么 SELinux 几乎不可能阻止访问。

大多数情况下，我们的系统将安装`setroubleshoot-server`和`setroubleshoot-plugins`软件包，提供多个工具，包括`sealert`，用于查询接收到的 SELinux 消息，并且很多时候也会建议更改。

让我们来看看我们应该始终验证的一些基础知识：

+   审查所有其他控件（用户和组所有权和权限是否设置正确）。

+   不要禁用 SELinux。

如果程序无法正常工作，并且是随操作系统一起发布的，那可能是一个错误，应该通过支持案例或 Bugzilla 报告给[`bugzilla.redhat.com`](https://bugzilla.redhat.com)。

只有当程序无法正常工作时，才可能使其运行不受限制，但通过定向策略保护所有其余系统服务。

+   如果这是一个现有程序，请考虑错误发生之前做了什么。

也许文件被移动而不是复制或创建，或者也许软件的端口或文件夹被更改了。

到达这一点后，我们应该检查`audit.log`以获取相关消息。例如，关于我们提到的关于`/var/www/html/`中文件错误上下文的示例，审计条目如下：

```
type=AVC msg=audit(1617210395.481:1603680): avc:  denied  { getattr } for  pid=2826802 comm="httpd" path="/var/www/html/index3.htm" dev="dm-0" ino=101881472 scontext=system_u:system_r:httpd_t:s0 tcontext=unconfined_u:object_r:admin_home_t:s0 tclass=file permissive=0
```

看起来很奇怪，但如果我们检查参数，我们会看到受影响文件的路径、PID、源上下文（`scontext`）和目标上下文（`tcontext`），因此简而言之，我们可以看到`httpd_t`尝试访问（获取属性）目标上下文`admin_home_t`并且被拒绝的情况。

同时，如果我们正在使用`setroubleshoot`，我们将在系统日志中收到这样的消息：

![图 10.11 - 在系统日志中记录 setroubleshoot](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/rhel8-adm/img/B16799_10_011.jpg)

图 10.11 - 在系统日志中记录 setroubleshoot

正如我们在前面的截图中看到的，它已经确定其中一个插件建议对文件应用`restorecon`命令，因为它与所在文件夹不匹配，并且甚至建议使用确切的命令来恢复标签。

另一个插件建议使用以下两个命令生成自定义策略：

```
# ausearch -c 'httpd' --raw | audit2allow -M my-httpd
# semodule -X 300 -i my-httpd.pp
```

然而，这种建议应该在了解正在进行的操作的情况下进行，这意味着前面的命令将修复`httpd_t`以便访问`home_admin_t`文件。我们可以通过仅运行第一个命令以及`audit2allow`管道来了解会发生什么。

运行`ausearch –c 'httpd' --raw | audit2allow –M my-httpd`在当前文件夹中创建了几个名为`my-httpd`的文件，一个名为`my-httpd.te`，另一个名为`my-httpd.pp`。我们将不使用第二个命令来安装修改后的策略，请在了解发生了什么之前，永远不要这样做，因为我们将在接下来的行中看到。

现在对我们来说有趣的文件是`my-httpd.te`（其中*te*表示*类型强制*）：

```
module my-httpd 1.0;
require {
        type httpd_t;
        type admin_home_t;
        class file getattr;
}
#============= httpd_t ==============
allow httpd_t admin_home_t:file getattr;
```

从那里，我们可以看到它使用了一个要求会话来处理涉及的类型，以及稍后的规则本身，这允许`httpd_t`访问`admin_home_t`文件以使用`getattr`函数，没有其他东西，也没有更多东西。

正如之前所说，这将解决我们的问题吗？它将有效地允许`httpd_t`访问`index3.html`文件，因此将不再出现任何错误，但这将付出巨大的代价。从那时起，`httpd_t`也可以读取主目录文件而不会有任何投诉。

重要提示

我不知道这个事实需要强调多少次，但在对系统采取行动之前三思。SELinux 是一种增加系统安全性的保护机制；不要禁用它，不要盲目接受`audit2allow`创建的策略，而没有对问题进行初步调查和了解提出的解决方案可能是什么，因为这几乎等同于禁用 SELinux。

如果在这一点上，我们已经安装了该模块，我们可以使用`semodule`来执行以下操作：

+   列出`semodule -l`。

+   安装`semodule -i $MODULE_NAME`。

+   删除`semodule –r $MODULE_NAME`。

通过前面的命令，我们可以检查或更改已加载策略模块的当前状态。

回顾系统日志后，我们可能会意识到某些事情实际上是在开始后的某个时候失败的，但不是从一开始就失败，因此使用`ausearch`或将完整日志传递给`audit2allow`可能没有帮助；但是，我们可以使用`setroubleshootd`建议的命令来列出它们：

```
Mar 31 17:06:41 bender setroubleshoot[2924281]: SELinux is preventing /usr/sbin/httpd from getattr access on the file /var/www/html/index3.htm. For complete SELinux messages run: sealert -l 1b4d549b-f566-409f-90eb-7a825471aca8
```

如果我们执行`sealert –l <ID>`，我们将收到不同插件提供的输出，以修复问题以及类似于*图 10.11*中显示的上下文信息。

在部署不支持 SELinux 的新软件的情况下，我们可以在测试系统中以相反的方式进行以下检查：

+   将 SELinux 设置为`permissive`模式。

+   部署软件。

+   分析收到的所有警报，看看是否有什么意外情况。

+   与软件供应商联系，并启动与 Red Hat 合作解决策略的支持案例。

如果我们因为 SELinux 正在执行并且我们已经严重搞乱了标签而被系统锁定，例如通过递归运行错误的`chcon`命令来针对我们的根文件夹（例如，根据一个变量编写上下文更改的脚本，而该变量为空），我们仍然有以下方法来摆脱麻烦：

+   使用`setenforce 0`将 SELinux 置于`permissive`模式。

+   运行`touch /.autorelabel`。

+   重新启动主机，以便在下次启动时，SELinux 恢复适当的标签

如果我们处于一个非常糟糕的情况，例如无法使用`setenforce 0`或系统甚至无法正确引导或执行重标记，仍然有希望，但需要一些额外的步骤。

当系统重新启动时，我们可以在 grub 提示符下看到已安装内核的列表，并使用它来编辑内核引导参数。

使用`selinux=0`参数，我们完全禁用了 SELinux，这是我们不想要的，但我们可以使用`enforcing=0`来实现启用 SELinux，但处于`permissive`模式。

一旦我们的系统启动进入`permissive`模式，我们可以重复之前的过程，恢复到先前的行为，并继续在系统内部调试情况（检查系统日志等）。

# 总结

本章介绍了 SELinux 的工作原理，以及如何检查进程、文件和端口，以及如何通过添加新选项或使用布尔值来对它们进行微调。我们还介绍了一些初始的故障排除技能，我们应该进一步探索以增强我们的知识和经验。

正如我们所见，SELinux 是一个强大的工具，可以通过额外的层保护我们的系统，即使是来自软件本身缺陷的未知问题。

我们已经介绍了如何在文件和进程中找到 SELinux 上下文，以及这些上下文是如何通过策略应用的，以及如何调整它以使我们的系统受到保护，同时仍能提供预期的服务。

排除 SELinux 故障是一项技能，将帮助我们适应不带 Red Hat Enterprise Linux 的软件，以便仍能正常运行。

在下一章中，我们将学习使用 OpenSCAP 的安全配置文件，以继续保持我们的系统安全。


# 第十一章：使用 OpenSCAP 进行系统安全配置文件

**SCAP**代表**安全内容自动化协议**，这是一种标准化的检查、验证和报告漏洞评估和策略评估的方式。Red Hat Enterprise Linux (RHEL) 8 包括了工具**OpenSCAP**，以及用于审计和管理系统安全的配置文件。这有助于确保您正在管理的系统符合标准的安全策略，如**支付卡行业数据安全标准**（**PCI DSS**）或**通用操作系统保护配置文件**，或简称为**OSPP**，以及发现漏洞。

RHEL 8 包括了这个工具，用于审查安全配置文件以发现可能的攻击向量（配置错误或漏洞），并可以获得如何更好地加固系统的指导。我们将学习如何对系统进行扫描，并发现需要更改以准备系统完全符合监管要求的内容。我们还将学习如何使用这个工具来改进系统的安全性，以便通过审查和应用推荐的更改来提高系统的安全性。

为了了解如何使用 OpenSCAP，在本章中我们将讨论以下主题：

+   开始使用 OpenSCAP 并发现系统漏洞

+   使用 OpenSCAP 进行 OSPP 和 PCI DSS 的安全配置文件

# 开始使用 OpenSCAP 并发现系统漏洞

让我们从实际角度开始使用 OpenSCAP，首先审查`安全工具`软件组，其中有一些值得了解的工具，然后继续运行一些扫描。

我们的初始步骤将是获取有关`安全工具`的信息：

```
[root@rhel8 ~]# dnf group info "Security Tools"
Updating Subscription Management repositories.
Last metadata expiration check: 0:37:16 ago on dom 14 mar 2021 16:55:55 CET.

Group: Security Tools
Description: Security tools for integrity and trust verification.
Default Packages:
   scap-security-guide
Optional Packages:
   aide
   hmaccalc
   openscap
   openscap-engine-sce
   openscap-utils
   scap-security-guide-doc
   scap-workbench
   tpm-quote-tools
   tpm-tools
   tpm2-tools
   trousers
   udica
```

这个组包括了几个安全工具，比如`aide`，用于确保系统文件的完整性；`tpm-tools`，用于管理`openscap-utils`以审查系统中的安全策略。

我们可以通过使用`dnf`来获取有关这些工具的更多信息。让我们来审查对本章更相关的一个工具，`openscap-utils`：

```
[root@rhel8 ~]# dnf info openscap-utils
Updating Subscription Management repositories.
Last metadata expiration check: 0:03:24 ago on dom 14 mar 2021 17:38:49 CET.
Available Packages
Name         : openscap-utils
Version      : 1.3.3
Release      : 6.el8_3
Architecture : x86_64
Size         : 43 k
Source       : openscap-1.3.3-6.el8_3.src.rpm
Repository   : rhel-8-for-x86_64-appstream-rpms
Summary      : OpenSCAP Utilities
URL          : http://www.open-scap.org/
License      : LGPLv2+
Description  : The openscap-utils package contains command-line tools build on top
             : of OpenSCAP library. Historically, openscap-utils included oscap
             : tool which is now separated to openscap-scanner sub-package.
```

我们可以在上一个命令的输出中看到`openscap-utils`软件包的相关信息，包括简要描述和主要网页的链接，其中包括更详细的信息。

提示

对于提到的每个工具运行`dnf info`命令并访问它们的网页将会很有用。这样你就能更好地了解这些工具提供的功能，并能够使用它们。

现在让我们安装`openscap-utils`：

```
[root@rhel8 ~]# dnf install openscap-utils -y
Updating Subscription Management repositories.
Last metadata expiration check: 0:04:25 ago on dom 14 mar 2021 17:38:49 CET.
Dependencies resolved.
====================================================================================================
Package              Arch   Version                         Repository                        Size
====================================================================================================
Installing:
openscap-utils       x86_64 1.3.3-6.el8_3                   rhel-8-for-x86_64-appstream-rpms  43 k
Installing dependencies:
GConf2               x86_64 3.2.6-22.el8                    rhel-8-for-x86_64-appstream-rpms 1.0 M
[omitted]
  rpmdevtools-8.10-8.el8.noarch                  
  rust-srpm-macros-5-2.el8.noarch             
  zstd-1.4.4-1.el8.x86_64                              

Complete!
```

现在让我们安装`scap-security-guide`，其中包括了 RHEL 特定的 SCAP 配置文件：

```
[root@rhel8 ~]# dnf install scap-security-guide -y
Updating Subscription Management repositories.
Last metadata expiration check: 15:06:55 ago on dom 14 mar 2021 17:38:49 CET.
Dependencies resolved.
====================================================================================================
Package                 Arch       Version              Repository                            Size
====================================================================================================
Installing:
scap-security-guide     noarch     0.1.50-16.el8_3      rhel-8-for-x86_64-appstream-rpms     7.4 M
Installing dependencies:
xml-common              noarch     0.6.3-50.el8         rhel-8-for-x86_64-baseos-rpms         39 k
[omitted] 

Installed:
  scap-security-guide-0.1.50-16.el8_3.noarch             xml-common-0.6.3-50.el8.noarch            

Complete!
```

这个软件包包括了 SCAP 安全指南，包括了与 RHEL 8 漏洞相关的指南，位于`/usr/share/xml/scap/ssg/content/ssg-rhel8-oval.xml`。现在我们可以运行一个初始扫描，使用配置文件中包含的所有检查。请注意，这将包括 2323 个测试，并且这将作为一个学习可能漏洞和加固系统的练习。所以，让我们运行它：

```
[root@rhel8 ~]# oscap oval eval --report \
vulnerability.html \
/usr/share/xml/scap/ssg/content/ssg-rhel8-oval.xml
Definition oval:ssg-zipl_vsyscall_argument:def:1: false
Definition oval:ssg-zipl_slub_debug_argument:def:1: false
Definition oval:ssg-zipl_page_poison_argument:def:1: false
Definition oval:ssg-zipl_bootmap_is_up_to_date:def:1: false
[omitted]
Definition oval:ssg-accounts_logon_fail_delay:def:1: false
Definition oval:ssg-accounts_have_homedir_login_defs:def:1: true
Definition oval:ssg-account_unique_name:def:1: true
Definition oval:ssg-account_disable_post_pw_expiration:def:1: false
Evaluation done.
```

将生成一个名为`vulnerability.html`的文件，其中包含扫描的输出。结果将如下所示：

![图 11.1 – OpenSCAP 测试扫描的初始结果](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/rhel8-adm/img/B16799_11_001.jpg)

图 11.1 – OpenSCAP 测试扫描的初始结果

让我们检查报告的一些细节。在左上角，我们将找到**OVAL 结果生成器信息**，其中包含运行的详细信息和结果摘要：

![图 11.2 – OpenSCAP 测试扫描摘要](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/rhel8-adm/img/B16799_11_002.jpg)

图 11.2 – OpenSCAP 测试扫描摘要

在右上角，我们可以看到**OVAL 定义生成器信息**，其中包含用于检查的定义摘要：

![图 11.3 – OpenSCAP 测试扫描定义摘要](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/rhel8-adm/img/B16799_11_003.jpg)

图 11.3 – OpenSCAP 测试扫描定义摘要

在这些信息标记下方，我们可以看到系统的基本摘要，如果我们有一个很长的扫描列表，并且想要将此扫描分配给适当的系统，这将非常有用：

![图 11.4 - OpenSCAP 测试扫描系统摘要](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/rhel8-adm/img/B16799_11_004.jpg)

图 11.4 - OpenSCAP 测试扫描系统摘要

在下面，我们有有关生成器的信息：

![图 11.5 - OpenSCAP 测试扫描生成器信息](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/rhel8-adm/img/B16799_11_005.jpg)

图 11.5 - OpenSCAP 测试扫描生成器信息

最后，检查结果如下：

![图 11.6 - OpenSCAP 测试扫描结果](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/rhel8-adm/img/B16799_11_006.jpg)

图 11.6 - OpenSCAP 测试扫描结果

通过这次测试，我们对系统进行了漏洞扫描，得到了一组结果，根据系统的使用情况，这些结果将需要被处理。在许多情况下，收到的警告并不适用，因此我们需要仔细审查它们。这种练习在生产系统上必须小心进行，确保在应用更改之前有适当的备份和系统快照。建议在构建服务时在测试环境中运行加固，然后再将其移至生产环境。

重要提示

*RHEL 8 红帽企业 Linux 系统设计指南*是一个很好的文档，可以帮助我们开始系统安全工作。建议阅读该文档，以扩展本章中所学到的知识。可在[`access.redhat.com/documentation/en-us/red_hat_enterprise_linux/8/html/system_design_guide/index`](https://access.redhat.com/documentation/en-us/red_hat_enterprise_linux/8/html/system_design_guide/index)找到。

让我们了解更多基础知识。对于这次扫描，我们使用了由系统软件包提供的 Red Hat 安全公告**开放式漏洞评估语言**（**OVAL**）订阅。为了检查，我们运行了 OpenSCAP 工具来审查不同的安全公告和漏洞，这些漏洞是按照 OVAL 编写的。

OVAL 要求分析的资源处于特定状态才能被认为是正确的。它以声明方式进行，这意味着描述和审查的是最终状态，而不是如何达到这个状态。

红帽安全团队生成红帽安全公告，以解决系统可能存在的不同漏洞，并为每一个漏洞发布一个 OVAL 定义。这些是公开发布的，并可在[`www.redhat.com/security/data/oval/v2/`](https://www.redhat.com/security/data/oval/v2/)上找到。

现在让我们看一下在我们的报告中找到的一个例子：

+   `oval:ssg-accounts_logon_fail_delay:def:1`

+   `false`

+   `合规性`

+   `[accounts_logon_fail_delay]`

+   `确保在/etc/login.defs 中配置了 FAIL_DELAY`

我们可以通过运行`man login.defs`来查看其手册页面。在其中，我们会找到以下内容：

```
FAIL_DELAY (number)
    Delay in seconds before being allowed another attempt after a 
    login failure.
```

这是一个用来确定用户在失败的登录尝试后需要等待多长时间的值。它旨在避免对系统中的帐户进行暴力攻击。我们可以采取两种方法来解决这个问题：

+   将`FAIL_DELAY`变量和值添加到`login.defs`中。

+   只允许使用 SSH 密钥而不是密码来登录系统。

或者更好的是，两者都做（深度安全）。我们可以继续审查列表中的每一项，并了解每一项，以完成系统的加固，尽量避免暴露。这通常需要与安全团队协调，并且需要持续审查。

现在我们已经运行了第一次漏洞扫描，让我们看看如何在下一节中进行合规性扫描。

# 使用 OpenSCAP 进行 OSPP 和 PCI DSS 的安全配置文件

在行业中有几种用于合规性的安全配置文件。其中两种最常见的，我们将在这里进行审查，分别是**操作系统保护配置文件**（**OSPP**）和 PCI DSS。

OSPP 标准在公共部门中被广泛使用，为通用系统提供服务，并且也作为其他更严格环境（即，国防认证系统）的基线。

PCI DSS 是金融领域中最广泛使用的标准之一，也适用于其他希望使用信用卡进行在线支付的部门。

RHEL 8 提供了使用 OpenSCAP 工具验证这些配置文件的参考。让我们转到`/usr/share/xml/scap/ssg/content/`目录，查看它们所在的位置：

```
[root@rhel8 ~]# cd   /usr/share/xml/scap/ssg/content/
[root@rhel8 content]# ls *rhel8*
ssg-rhel8-cpe-dictionary.xml
ssg-rhel8-ds-1.2.xml 
ssg-rhel8-ocil.xml  
ssg-rhel8-xccdf.xml
ssg-rhel8-cpe-oval.xml 
ssg-rhel8-ds.xml
ssg-rhel8-oval.xml
```

正如您所看到的，我们有不同类型的描述可以与 OpenSCAP 一起使用。我们已经了解了 OVAL。让我们检查最重要的几个：

+   **可扩展配置清单描述格式（XCCDF）**：XCCDF 用于构建安全检查表。它非常常用于合规性测试和评分。

+   **通用平台枚举（CPE）**：CPE 通过分配唯一的标识符名称来帮助识别系统。这样，它可以关联测试和名称。

+   **开放清单交互语言（OCIL）**：OCIL 是 SCAP 标准的一部分。它是一种聚合来自不同数据存储的其他检查的方法。

+   **数据流（DS）**：DS 是一种格式，它将几个组件组合成一个单个文件。它用于轻松分发配置文件。

提示

有关不同安全描述和组件的更多信息可以在 OpenSCAP 网页上找到，通过检查组件 URL：[`www.open-scap.org/features/scap-components/`](https://www.open-scap.org/features/scap-components/)。

在这种情况下，我们将使用`ssg-rhel8-ds.xml`文件。让我们检查与之相关的信息：

```
[root@rhel8 content]# oscap info ssg-rhel8-ds.xml
Document type: Source Data Stream
[omitted]
Profiles:
Title: CIS Red Hat Enterprise Linux 8 Benchmark
Id: xccdf_org.ssgproject.content_profile_cis
Title: Unclassified Information in Non-federal Information Systems and Organizations (NIST 800-171)
Id: xccdf_org.ssgproject.content_profile_cui
Title: Australian Cyber Security Centre (ACSC) Essential Eight
Id: xccdf_org.ssgproject.content_profile_e8
Title: Health Insurance Portability and Accountability Act (HIPAA)
Id: xccdf_org.ssgproject.content_profile_hipaa
Title: Protection Profile for General Purpose Operating Systems
Id: xccdf_org.ssgproject.content_profile_ospp
Title: PCI-DSS v3.2.1 Control Baseline Red Hat Enterprise Linux 8
Id: xccdf_org.ssgproject.content_profile_pci-dss
Title: [DRAFT] DISA STIG for Red Hat Enterprise Linux 8
Id: xccdf_org.ssgproject.content_profile_stig
Referenced check files: ssg-rhel8-oval.xml
system: http://oval.mitre.org/XMLSchema/oval-definitions-5
ssg-rhel8-ocil.xml
system: http://scap.nist.gov/schema/ocil/2
security-data-oval-com.redhat.rhsa-RHEL8.xml
system: http://oval.mitre.org/XMLSchema/oval-definitions-5
Checks:
Ref-Id: scap_org.open-scap_cref_ssg-rhel8-oval.xml
Ref-Id: scap_org.open-scap_cref_ssg-rhel8-ocil.xml
Ref-Id: scap_org.open-scap_cref_ssg-rhel8-cpe-oval.xml
Ref-Id: scap_org.open-scap_cref_security-data-oval-com.redhat.rhsa-RHEL8.xml
Dictionaries:
Ref-Id: scap_org.open-scap_cref_ssg-rhel8-cpe-dictionary.xml
```

如您所见，它包括 RHEL 8 的 OSPP 和 PCI DSS 配置文件。让我们试试看。

## 扫描 OSPP 合规性

我们可以使用`oscap`的`--profile`选项来获取特定于**OSPP**配置文件的信息：

```
[root@rhel8 content]# oscap info --profile \
ospp ssg-rhel8-ds.xml 
Document type: Source Data Stream
Imported: 2020-10-12T09:41:22

Stream: scap_org.open-scap_datastream_from_xccdf_ssg-rhel8-xccdf-1.2.xml
Generated: (null)
Version: 1.3
WARNING: Datastream component 'scap_org.open-scap_cref_security-data-oval-com.redhat.rhsa-RHEL8.xml' points out to the remote 'https://www.redhat.com/security/data/oval/com.redhat.rhsa-RHEL8.xml'. Use '--fetch-remote-resources' option to download it.
WARNING: Skipping 'https://www.redhat.com/security/data/oval/com.redhat.rhsa-RHEL8.xml' file which is referenced from datastream
Profile
Title: Protection Profile for General Purpose Operating Systems
Id: xccdf_org.ssgproject.content_profile_ospp

Description: This profile reflects mandatory configuration controls identified in the NIAP Configuration Annex to the Protection Profile for General Purpose Operating Systems (Protection Profile Version 4.2.1).  This configuration profile is consistent with CNSSI-1253, which requires U.S. National Security Systems to adhere to certain configuration parameters. Accordingly, this configuration profile is suitable for use in U.S. National Security Systems.
```

在信息中，我们可以看到 OSPP 配置文件被描述为`xccdf`。我们现在可以运行`oscap`，指定我们要使用`xcddf`选项的格式，并且我们要执行的操作是使用`eval`评估系统。命令如下：

```
[root@rhel8 content]# oscap xccdf eval \
--report ospp-report.html --profile ospp ssg-rhel8-ds.xml 
[omitted]
Title   Set Password Maximum Consecutive Repeating Characters
Rule    xccdf_org.ssgproject.content_rule_accounts_password_pam_maxrepeat
Ident   CCE-82066-2
Result  fail
Title   Ensure PAM Enforces Password Requirements - Maximum Consecutive Repeating Characters from Same Character Class
Rule    xccdf_org.ssgproject.content_rule_accounts_password_pam_maxclassrepeat
Ident   CCE-81034-1
Result  fail
[omitted]
Title   Disable Kerberos by removing host keytab
Rule    xccdf_org.ssgproject.content_rule_kerberos_disable_no_keytab
Ident   CCE-82175-1
Result  pass
```

我们将获得`ospp-report.html`文件，其中包含有关 OSPP 规则结果的完整报告：

![图 11.7 – OpenSCAP OSPP 扫描结果](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/rhel8-adm/img/B16799_11_007.jpg)

图 11.7 – OpenSCAP OSPP 扫描结果

它将显示需要修改以符合配置文件的要点：

![图 11.8 – OpenSCAP OSPP 扫描结果，需要采取行动的详细规则](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/rhel8-adm/img/B16799_11_008.jpg)

图 11.8 – OpenSCAP OSPP 扫描结果，需要采取行动的详细规则

现在我们可以一步一步地遵循建议并修复它们，以便完全符合 OSPP。此外，我们可以使用此扫描来加固系统，即使它们不需要符合 OSPP，也将处于暴露的网络中，例如 DMZ，并且我们希望对它们进行加固。

重要提示

Red Hat 提供了一种自动应用所有这些更改的方法。它基于自动化工具`/usr/share/scap-security-guide/ansible/rhel8-playbook-ospp.yml`。

现在我们已经审查了 OSPP 合规性的系统，让我们转向下一个目标，即 PCI DSS 合规性。

## 扫描 PCI DSS 合规性

我们可以按照之前的步骤进行，同样使用`oscap`的`--profile`选项来获取特定于 PCI DSS 配置文件的信息：

```
[root@rhel8 content]# oscap info --profile pci-dss \
ssg-rhel8-ds.xml 
Document type: Source Data Stream
Imported: 2020-10-12T09:41:22

Stream: scap_org.open-scap_datastream_from_xccdf_ssg-rhel8-xccdf-1.2.xml
Generated: (null)
Version: 1.3
WARNING: Datastream component 'scap_org.open-scap_cref_security-data-oval-com.redhat.rhsa-RHEL8.xml' points out to the remote 'https://www.redhat.com/security/data/oval/com.redhat.rhsa-RHEL8.xml'. Use '--fetch-remote-resources' option to download it.
WARNING: Skipping 'https://www.redhat.com/security/data/oval/com.redhat.rhsa-RHEL8.xml' file which is referenced from datastream
Profile
Title: PCI-DSS v3.2.1 Control Baseline for Red Hat Enterprise Linux 8
Id: xccdf_org.ssgproject.content_profile_pci-dss

Description: Ensures PCI-DSS v3.2.1 security configuration settings are applied.
```

我们可以使用与上一节相同的选项运行`oscap`，但指定`pci-dss`作为配置文件。它将生成适当的报告：

```
[root@rhel8 content]# oscap xccdf eval –report \
pci-dss-report.html --profile pci-dss ssg-rhel8-ds.xml 
WARNING: Datastream component 'scap_org.open-scap_cref_security-data-oval-com.redhat.rhsa-RHEL8.xml' points out to the remote 'https://www.redhat.com/security/data/oval/com.redhat.rhsa-RHEL8.xml'. Use '--fetch-remote-resources' option to download it.
WARNING: Skipping 'https://www.redhat.com/security/data/oval/com.redhat.rhsa-RHEL8.xml' file which is referenced from datastream
WARNING: Skipping ./security-data-oval-com.redhat.rhsa-RHEL8.xml file which is referenced from XCCDF content
Title   Ensure PAM Displays Last Logon/Access Notification
Rule    xccdf_org.ssgproject.content_rule_display_login_attempts
Ident   CCE-80788-3
Result  pass
[omitted]
Title   Specify Additional Remote NTP Servers
Rule    xccdf_org.ssgproject.content_rule_chronyd_or_ntpd_specify_multiple_servers
Ident   CCE-80764-4
Result  fail
[root@rhel8 content]# ls -l pci-dss-report.html 
-rw-r--r--. 1 root root 3313684 mar 21 20:16 pci-dss-report.html
```

我们可以开始审查报告中的项目并开始修复它们。

重要提示

与上一节一样，Red Hat 还提供了一种使用 Ansible 自动应用所有这些更改的方法。PCI DSS 的 playbook 位于`/usr/share/scap-security-guide/ansible/rhel8-playbook-pci-dss.yml`。

我们已经看到，使用 OpenSCAP 从一个配置文件切换到另一个配置文件非常容易，我们可以扫描尽可能多的配置文件。

# 总结

通过学习**OpenSCAP**的基础知识，我们已经准备好审查和加固系统，使其符合我们需要其运行的法规要求。

现在，如果您被要求遵守任何监管要求，您可以找到适合它的 SCAP 配置文件（如果不存在，可以构建它），并确保您的系统完全符合要求。

此外，即使没有监管要求，使用 OpenSCAP 也可以帮助您发现系统中的漏洞，或者应用更安全（和限制性）的配置以减少风险。

通过学习 Ansible 并能够自动应用系统变更的方式，我们可以扩展我们的知识和技能，这种方式易于扩展，以及 Red Hat Satellite，它可以帮助我们对我们管理的整个 IT 基础进行 SCAP 扫描，即使我们可能谈论的是成千上万的系统。

现在我们的安全技能正在提高并得到巩固，让我们深入探讨更多关于本地存储和文件系统的低级主题，如下一章所述。


# 第三部分：资源管理 - 存储、引导过程、调优和容器

管理运行 RHEL 的机器的资源对于构建高性能、高效的 IT 环境至关重要。了解存储、调优性能（包括在引导过程中使其永久生效所需的配置），然后使用容器来隔离进程并更有效地分配资源，这些都是系统管理员在日常工作中必然会涉及的领域。

本节包括以下章节：

+   *第十二章*, *管理本地存储和文件系统*

+   *第十三章*, *使用 LVM 进行灵活的存储管理*

+   *第十四章*, *使用 Stratis 和 VDO 进行高级存储管理*

+   *第十五章*, *了解引导过程*

+   , *使用 tuned 进行内核调优和管理性能配置文件*

+   *第十七章*, *使用 Podman、Buildah 和 Skopeo 管理容器*


# 第十二章：管理本地存储和文件系统

在之前的章节中，我们已经学习了安全和系统管理。在本章中，我们将专注于资源管理，特别是存储管理。

存储管理是保持系统运行的重要部分：系统日志可能会占用可用空间，新应用程序可能需要为它们设置额外的存储空间（甚至在单独的磁盘上以提高性能），这些问题可能需要我们采取行动来解决。

在本章中，我们将学习以下主题：

+   分区磁盘（**主引导记录**（**MBR**）和**全局唯一标识符**（**GUID**）**分区表**（**GPT**）磁盘）

+   格式化和挂载文件系统

+   在`fstab`中设置默认挂载和选项

+   使用**网络文件系统**（**NFS**）的网络文件系统

这将为我们提供基本知识，以便在存储管理技能上建立，以保持系统运行。

让我们动手操作！

# 技术要求

您可以继续使用本书开头创建的**虚拟机**（**VM**）进行练习*第一章*，*安装 RHEL8*。本章所需的任何其他软件包将在文本旁边指示。您还需要分区磁盘（MBR 和 GPT 磁盘）。

## 让我们从一个定义开始

分区是存储设备的逻辑分割，用于将可用存储逻辑地分成较小的部分。

现在，让我们继续学习一些关于存储起源的知识，以更好地理解它。

## 一点历史

存储也与系统使用它的能力有关，因此让我们简要解释一下**个人计算机**（**PC**）的历史，允许它们引导的软件（**基本输入/输出系统**（**BIOS**）），以及这如何影响存储管理。

这可能听起来有点奇怪，但最初的存储需求只是一小部分**千字节**（**KB**），对于 PC 中的第一块硬盘，存储只是几**兆字节**（**MB**）。

PC 还具有一个特点和限制：PC 是兼容的，这意味着后续型号与最初的**国际商业机器**（**IBM**）PC 设计兼容。

传统的磁盘分区在 MBR 之后使用了一些空间，允许四个分区寄存器（起始、结束、大小、分区类型、活动标志），称为**主**分区。

当 PC 启动时，BIOS 将通过在 MBR 中运行一个小程序来检查磁盘的分区表，然后加载活动分区的引导区域并执行它，以启动操作系统。

包含**磁盘操作系统**（**DOS**）和兼容（MS-DOS、DR-DOS、FreeDOS 等）的 IBM PC 还使用了一个名为**文件分配表**（**FAT**）的文件系统。 FAT 包含了几个基于其演变的结构，指示为簇寻址大小（以及其他一些特性）。

由于簇的数量有限，更大的磁盘意味着更大的块，因此，如果一个文件只使用了有限的空间，剩下的空间就不能被其他文件使用。因此，将更大的硬盘分成较小的逻辑分区变得更加正常，这样小文件就不会因为限制而占用可用空间。

把这看作是一个议程，最多有一定数量的条目，类似于手机上的快速拨号：如果你只有九个快速拨号的位置，一个短号码，比如打语音信箱，仍然会占用一个位置，就像存储一个大的国际号码一样。

其中一些限制在 FAT 大小的后续版本中得到了减少，与此同时增加了最大支持的磁盘大小。

当然，其他操作系统也引入了自己的文件系统，但使用相同的分区模式。

后来，创建了一种新的分区类型：**扩展分区**，它使用了四个可用的**主分区**插槽之一，并允许在其中定义额外的分区，从而使我们能够创建逻辑磁盘以根据需要分配。

此外，拥有多个主分区还允许在同一台计算机上安装不同操作系统，并且这些操作系统具有完全独立的专用空间。

所以...分区允许计算机拥有不同的操作系统，更好地利用可用的存储空间，甚至通过在不同的区域保留数据来逻辑地对数据进行排序，例如将操作系统空间与用户数据分开，以便用户填满可用空间不会影响计算机的运行。

正如我们所说，许多这些设计都带有原始 IBM PC 的兼容性限制，因此当新的使用**可扩展固件接口**（**EFI**）的计算机出现以克服传统 BIOS 的限制时，就出现了一种新的分区表格式称为**GPT**。

使用 GPT 的系统使用 32 位和 64 位支持，而 BIOS 使用 16 位支持（从 IBM PC 兼容性继承），因此可以为磁盘使用更大的寻址，以及额外的功能，如扩展控制器加载。

现在，让我们在下一节学习关于磁盘分区。

# 分区磁盘（MBR 和 GPT 磁盘）

正如前面提到的，使用磁盘分区允许我们更有效地利用计算机和服务器中可用的空间。

让我们首先通过识别要操作的磁盘来深入了解磁盘分区。

重要提示

一旦我们了解了导致磁盘被分区以及其限制的原因，我们应该根据我们的系统规格遵循一个模式或另一个模式，但要记住 EFI 需要 GPT，BIOS 需要 MBR，因此支持 UEFI 的系统，但磁盘分区为 MBR，将会将系统引导到兼容 BIOS 的模式。

Linux 根据连接到系统的方式使用不同的符号表示磁盘，因此，例如，您可以看到磁盘为`hda`或`sda`或`mmbclk0`，具体取决于所使用的连接。传统上，使用`hda`，`hdb`等连接的磁盘，而使用`sda`，`sdb`等连接的磁盘。

我们可以使用`fdisk –l`或`lsblk –fp`列出可用设备，如下面的屏幕截图所示：

![图 12.1 – lsblk-fp 和 fdisk –l 输出](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/rhel8-adm/img/B16799_12_001.jpg)

图 12.1 – lsblk-fp 和 fdisk –l 输出

正如我们所看到的，我们的名为`/dev/sda`的磁盘有三个分区：`sda1`，`sda2`和`sda3`，其中`sda3`是一个`LVM`卷组，其卷名为`/dev/mapper/rhel-root`。

为了以安全的方式演示磁盘分区，并使读者在使用虚拟机进行测试时更容易，我们将创建一个虚拟的`truncate`实用程序，该实用程序随`coreutil`软件包一起提供，以及一个随`util-linux`软件包一起提供的`losetup`实用程序。

为了创建一个 VHD，我们将按照*图 12.2*中显示的命令序列执行以下命令：

1.  `truncate –s 20G myharddrive.hdd`

注意

此命令创建一个大小为 20**GB**的文件，但这将是一个空文件，这意味着该文件实际上并未在我们的磁盘上使用 20 GB 的空间，只是显示了那个大小。除非我们使用它，它将不会占用更多的磁盘空间（这称为**稀疏文件**）。

1.  `losetup –f`，将找到下一个可用设备

1.  `losetup /dev/loop0 myharddrive.hdd`，将`loop0`与创建的文件关联

1.  `lsblk –fp`，验证新循环磁盘

1.  `fdisk –l /dev/loop0`，列出新磁盘中的可用空间

以下屏幕截图显示了前面顺序命令的输出：

![图 12.2 – 执行指定命令以创建一个虚拟硬盘](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/rhel8-adm/img/B16799_12_002.jpg)

图 12.2 – 执行指定命令以创建一个虚拟硬盘

`losetup -f`命令找到下一个可用的回环设备，这是用于将访问回环到支持文件的设备。例如，这经常用于本地挂载 ISO 文件。

使用第三个命令，我们使用先前可用的回环设备来设置设备`loop0`和我们用第一个命令创建的文件之间的回环连接。

正如我们所看到的，在剩下的命令中，当运行相同的命令时，设备现在会出现，我们在*图 12.1*中执行，显示我们有一个可用的 20 GB 磁盘。

重要提示

在磁盘上进行分区操作可能是危险的，并且可能使系统无法使用，需要恢复或重新安装。为了减少这种可能性，本章中的示例将使用`/dev/loop0`虚拟创建的磁盘，并且只与此交互。在对真实卷、磁盘等执行此操作时要注意。

让我们通过在我们新创建的设备上执行`fdisk /dev/loop0`来开始创建分区，如下一张截图所示：

![图 12.3 - fdisk 在/dev/loop0 上执行](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/rhel8-adm/img/B16799_12_003.jpg)

图 12.3 - fdisk 在/dev/loop0 上执行

正如我们在*图 12.3*中所看到的，磁盘不包含已识别的分区表，因此创建了一个新的 DOS 分区磁盘标签，但更改只保留在内存中，直到写回磁盘。

在`fdisk`命令中，我们可以使用多个选项来创建分区。我们应该注意的第一个选项是`m`，如*图 12.3*中所示，它显示了帮助功能和可用命令。

首先要考虑的是我们之前关于 UEFI、BIOS 等的解释。默认情况下，`fdisk`正在创建一个 DOS 分区，但正如我们在手册（`m`）中所看到的，我们可以通过在`fdisk`中运行`g`命令来创建一个 GPT 分区。

要记住的一个重要命令是`p`，它打印当前磁盘布局和分区，如下一张截图中所定义的：

![图 12.4 - fdisk 创建新的分区表](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/rhel8-adm/img/B16799_12_004.jpg)

图 12.4 - fdisk 创建新的分区表

正如我们所看到的，初始的`disklabel`类型是`dos`，现在是`gpt`，与 EFI/UEFI 兼容。

让我们回顾一些我们可以使用的基本命令，如下所示：

+   `n`：创建一个新分区

+   `d`：删除一个分区

+   `m`：显示手册页（帮助）

+   `p`：打印当前布局

+   `x`：进入高级模式（专为专家设计的额外功能）

+   `q`：退出而不保存

+   `w`：将更改写入磁盘并退出

+   `g`：创建新的 GPT 磁盘标签

+   `o`：创建 DOS 磁盘标签

+   `a`：在 DOS 模式下，将可引导标志设置为其中一个主分区

创建具有用于操作系统的可引导分区和用于用户数据的另一个分区的新传统磁盘分区布局的顺序是什么？

这将是命令的顺序（这些命令也显示在*图 12.5*中）：

1.  `o`并按*Enter*创建新的 DOS 磁盘标签

1.  `n`并按*Enter*创建一个新分区

1.  按*Enter*接受主分区类型

1.  按*Enter*确认使用第一个分区（`1`）

1.  按*Enter*接受初始扇区

1.  `+10G`并按*Enter*指示从第一个扇区开始的大小为 10 GB

1.  `n`并按*Enter*创建第二个新分区

1.  按*Enter*接受它作为主分区类型

1.  按*Enter*接受分区号（`2`）

1.  按*Enter*接受 fdisk 提出的默认第一个扇区

1.  按*Enter*接受 fdisk 提出的默认结束扇区

1.  `a`并按*Enter*将分区标记为可引导

1.  `1`并按*Enter*标记第一个分区

正如您所看到的，大多数选项接受默认值；唯一的更改是指定分区大小为`+10G`，表示应为 10 GB（磁盘为 20 GB），然后使用新的`n`命令开始第二个分区，现在不指定大小，因为我们要使用所有剩余的分区。最后一步是将第一个分区标记为可引导的。

当然，记住我们之前说过的：除非执行`w`命令，否则更改不会写入磁盘，我们可以使用`p`来查看它们，如下面的屏幕截图所示：

![图 12.5 – 在将其写回磁盘之前创建和验证磁盘分区布局](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/rhel8-adm/img/B16799_12_005.jpg)

图 12.5 – 在将其写回磁盘之前创建和验证磁盘分区布局

为了结束本节，让我们使用`w`命令将更改写入磁盘，并继续讨论下一节中的文件系统。然而，在此之前，让我们执行`partprobe /dev/loop0`，以使内核更新其对磁盘的内部视图，并找到两个新分区。如果不这样做，`/dev/loop0p1`和`/dev/loop0p2`特殊文件可能不会被创建，也无法使用。

请注意，一些分区修改即使在执行`partprobe`后也不会更新，并可能需要系统重新启动。例如，在使用分区的磁盘上，例如我们计算机中保存根文件系统的磁盘上，就会发生这种情况。

# 格式化和挂载文件系统

在上一节中，我们学习了如何在逻辑上划分我们的磁盘，但该磁盘仍然无法用于存储数据。为了使其可用于存储数据，我们需要在其上定义一个**文件系统**，这是使其对我们的系统可用的第一步。

文件系统是一个逻辑结构，定义了文件、文件夹等的存储方式，并根据每种类型提供了不同的功能集。

支持的文件系统数量和类型取决于操作系统版本，因为在其演变过程中，可能会添加、删除新的文件系统等。

提示

请记住，**Red Hat Enterprise Linux** (**RHEL**) 专注于稳定性，因此严格控制了哪些功能被添加或在新版本中被淘汰，但不包括当前版本内。您可以在[`access.redhat.com/articles/rhel8-abi-compatibility`](https://access.redhat.com/articles/rhel8-abi-compatibility)了解更多信息。

在 RHEL 8 中，默认文件系统是**eXtended File System** (**XFS**)，但您可以在 RHEL 文档中找到可用文件系统的列表，网址为[`access.redhat.com/documentation/en-us/red_hat_enterprise_linux/8/html/system_design_guide/overview-of-available-file-systems_system-design-guide`](https://access.redhat.com/documentation/en-us/red_hat_enterprise_linux/8/html/system_design_guide/overview-of-available-file-systems_system-design-guide)，当然，也可以使用**Fourth Extended Filesystem** (**EXT4**)等其他文件系统。

文件系统的选择取决于诸多因素，如使用意图、将要使用的文件类型等，不同的文件系统可能会对性能产生影响。

例如，EXT4 和 XFS 都是日志文件系统，可以提供更多的保护，防止断电故障，但在其他方面，如文件系统的最大值等方面有所不同。

在选择文件系统之前，了解部署的文件类型和它们的使用模式是一个很好的做法，因为选择错误的文件系统可能会影响系统性能。

正如我们在上一节中定义的，在我们的 VHD 上创建了两个分区，我们可以尝试创建 XFS 和 EXT4 文件系统。然而，在执行操作时要非常小心，因为文件系统的创建是一种破坏性操作，会将新的结构写回磁盘，当以系统的 root 用户操作时，选择错误的文件系统可能会在几秒钟内摧毁我们系统上的可用数据。

重要提示

请记住查看正在使用的命令的 man 页面，以熟悉每个命令的不同建议和可用选项。

然后，让我们使用我们创建的两个分区来测试两种文件系统，XFS 和 EXT4，分别使用`mkfs.xfs`和`mkfs.ext4`命令对每个设备进行操作，如下所示：

![图 12.6—在创建的 VHD 上创建文件系统](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/rhel8-adm/img/B16799_12_006.jpg)

图 12.6—在创建的 VHD 上创建文件系统

请注意，我们已经指定了不同的循环设备分区，并且还为每个命令指定了一个`-L`参数。稍后我们将再次查看这个。

现在文件系统已经创建，我们可以运行`lsblk -fp`来验证这一点，我们可以看到两个设备，现在指示文件系统正在使用以及`LABEL`和`UUID`值（我们使用`mkfs`创建文件系统时显示的值），如下面的屏幕截图所示：

![图 12.7—创建文件系统后 lsblk –fp 的输出](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/rhel8-adm/img/B16799_12_007.jpg)

图 12.7—创建文件系统后 lsblk –fp 的输出

从前面的输出中，重要的是要注意`UUID`和`LABEL`的值（如果您记得，列出的值是我们在`mkfs`命令中使用`-L`选项指定的值），因为我们将在本章后面使用它们。

现在文件系统已经创建，为了使用它们，我们需要挂载它们，这意味着使文件系统在我们的系统中的某个路径上可用，这样每次我们存储在该路径中，我们将使用该设备。

挂载文件系统可以通过多种方式完成，但最简单的方法是使用自动检测，只需指定要挂载的设备和要挂载的本地路径，但在检查`man mount`帮助页面时，还可以找到更复杂的方法，允许定义多个选项。

为了挂载我们创建的两个文件系统，我们将创建两个文件夹，然后执行以下命令挂载每个设备：

1.  `cd`

1.  `mkdir first second`

1.  `mount /dev/loop0p1 first/`

1.  `mount /dev/loop0p2 second/`

此时，两个文件系统将在我们的主文件夹（根用户）中的名为`first`和`second`的子文件夹中可用。

内核已自动找到每个设备正在使用的文件系统，并通过适当的控制器加载它，这很有效，但有时我们可能想要定义特定的选项——例如，强制文件系统类型，在过去使用`ext2`和`ext3`作为常见文件系统时启用或禁用日志记录，或者例如，禁用更新文件或目录访问时间的内置功能，以减少磁盘 I/O 并提高性能。

在命令行上指定的所有选项，或者挂载的文件系统，在系统重新启动后将不可用，因为这些只是运行时更改。让我们继续下一节，学习如何在系统启动时定义默认选项和文件系统挂载。

# 在 fstab 中设置默认挂载和选项

在前一节中，我们介绍了如何挂载磁盘和分区，以便我们的服务和用户可以使用它们。在本节中，我们将学习如何以持久的方式使这些文件系统可用。

`/etc/fstab`文件包含系统的文件系统定义，并且当然有一个专门的手册页面，可以使用`man fstab`来查看，其中包含有关格式、字段、排序等必须考虑的有用信息，因为这个文件对系统的平稳运行至关重要。

文件格式由用制表符或空格分隔的几个字段定义，以`#`开头的行被视为注释。

例如，我们将使用这行来查看每个字段的描述：

```
LABEL=/ / xfs defaults 0 0
```

第一个字段是设备定义，可以是特殊的块设备、远程文件系统，或者—正如我们所看到的—由`LABEL`、`UUID`或`PARTUUID`或`PARTLABEL`制作的选择器。`mount`、`blkid`和`lsblk`的`man`页面提供了有关设备标识符的更多信息。

第二个字段是文件系统的挂载点，这是根据我们的系统目录层次结构使该文件系统的内容可用的位置。一些特殊的设备/分区，如交换区，将其定义为`none`，因为实际上内容不会通过文件系统可用。

第三个字段是由`mount`命令或`swap`支持的文件系统类型，用于交换分区。

第四个字段是由`mount`或`swapon`命令支持的挂载选项（查看它们的`man`页面以获取更多详细信息），在其默认设置下，它是大多数常见选项的别名（读/写，允许设备，允许执行，自动挂载启动，异步访问等）。其他常见选项可能是`noauto`，它定义了文件系统但不会在启动时挂载（通常与可移动设备一起使用），`user`，它允许用户挂载和卸载它，以及`_netdev`，它定义了需要在尝试挂载之前网络处于连接状态的远程路径。

第五个字段由`dump`用于确定应使用哪些文件系统 - 其值默认为`0`。

第六个字段由`fsck`用于确定在启动时要检查的文件系统的顺序。根文件系统的值应为 1，其他文件系统的值应为 2（默认值为 0，而不是`fsck`）。检查是并行执行的，以加快启动过程。请注意，具有日志的文件系统本身可以执行快速验证而不是完整验证。

在下面的屏幕截图中，让我们看看我们系统中`cat /etc/fstab`的输出是什么：

![图 12.8 - 我们系统的 fstab 示例](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/rhel8-adm/img/B16799_12_008.jpg)

图 12.8 - 我们系统的 fstab 示例

为什么我们应该使用`UUID`或`LABEL`而不是`/dev/sda1`等设备？

当系统启动时，磁盘排序可能会发生变化，因为一些内核可能会引入设备访问方式的差异等，导致设备的枚举发生变化；这不仅发生在可移动设备（如**通用串行总线**（**USB**）设备），还发生在网络接口或硬盘等内部设备上。

当我们使用`UUID`或`LABEL`而不是指定设备时，即使在设备重新排序的情况下，系统仍将能够找到正确的设备并从中引导。这在系统以前使用**IDE**和**串行高级技术附件**（**SATA**）驱动器和**SCSI**驱动器时尤为重要，甚至在今天，**Internet SCSI**（**iSCSI**）设备可能以与预期不同的顺序连接，导致设备名称更改和在到达时失败。

请记住使用`blkid`或`lsblk -fp`命令来检查文件系统的标签和**通用唯一标识符**（**UUID**），这些标识符在引用它们时可能会用到。

重要提示

在编辑`/etc/fstab`文件时，务必小心：更改系统使用的挂载点可能会导致系统无法使用。如果有疑问，请仔细检查任何更改，并确保熟悉系统恢复方法，并在需要时准备好救援介质。

让我们在下一节学习如何挂载远程 NFS

# 使用 NFS 进行网络文件系统

挂载远程 NFS 与挂载本地设备并没有太大区别，但是与在上一节中使用`/dev/loop0p1`文件指定本地设备不同，我们提供`server:export`作为设备。

我们可以通过检查手册页面`man mount`来找到一系列可用选项，这将向我们显示几个选项以及设备的外观。

当要使用 NFS 挂载时，管理员需要使用主机和导出名称来挂载该设备，例如，基于以下关于 NFS 导出的数据：

+   `server.example.com`

+   `/isos`

+   `/mnt/nfs`

有了上述数据，很容易构建`mount`命令，它将如下所示：

```
mount –t nfs sever.example.com:/isos /mnt/nfs
```

如果我们分析上述命令，它将定义要挂载的文件系统类型为`nfs`，由`server.example.com`主机名提供，并使用`/isos` NFS 导出，并将在本地的`/mnt/nfs`文件夹下可用。

如果我们想要在启动时定义此文件系统为可用，我们应该在`/etc/fstab`中添加一个条目，但是...我们应该如何指示这一点呢？

根据本章节中解释的设置，构建的条目将看起来像这样：

```
server.example.com:/isos /mnt/nfs nfs defaults,_netdev 0 0
```

上一行代码包含了我们在命令行上指定的参数，但它还添加了在尝试挂载之前需要网络访问的资源，因为网络访问是必需的，以便能够访问 NFS 服务器，类似于其他基于网络的存储，如 Samba 挂载、iSCSI 等，都需要的情况。

重要提示

重申保持系统可引导的想法，一旦我们对`/etc/fstab`配置文件进行修改，建议执行`mount -a`，以便在运行系统时执行验证。如果执行后新的文件系统可用，并且在执行例如`df`时显示，并且没有出现错误，那么应该是安全的。

# 总结

在本章中，我们学习了如何对磁盘进行逻辑划分，以便最佳利用存储空间，并且如何稍后在该磁盘划分上创建文件系统，以便实际存储数据。

一旦实际文件系统被创建，我们学会了如何在系统中使其可访问，以及如何通过修改`/etc/fstab`配置文件来确保在下次系统重启后它仍然可用。

最后，我们还学习了如何使用提供给我们的数据来使用 NFS 远程文件系统，并将其添加到我们的`fstab`文件中以使其持久化。

在下一章中，我们将学习如何通过**逻辑卷管理**（**LVM**）使存储更加有用，它赋予了定义不同逻辑单元的能力，可以调整大小，组合以提供数据冗余等。


# 第十三章：使用 LVM 进行灵活的存储管理

通过使用**逻辑卷管理器**（**LVM**），可以以比*第十二章*中更灵活的方式来管理本地存储和文件系统。LVM 允许您将多个磁盘分配给同一个逻辑卷（在 LVM 中相当于分区），在不同磁盘之间复制数据，并对卷进行快照。

在本章中，我们将回顾 LVM 的基本用法和用于管理存储的主要对象。我们将学习如何准备磁盘以便与 LVM 一起使用，然后将它们聚合到一个池中，从而不仅增加了可用空间，还使您能够一致地使用它。我们还将学习如何将聚合的磁盘空间分配到类似分区的块中，如果需要的话可以很容易地扩展。为此，我们将学习以下主题：

+   理解 LVM

+   创建、移动和删除物理卷

+   将物理卷合并到卷组中

+   创建和扩展逻辑卷

+   向卷组添加新磁盘并扩展逻辑卷

+   删除逻辑卷、卷组和物理卷

+   审查 LVM 命令

# 技术要求

在这一章中，我们将向我们正在使用的机器添加两个磁盘，以便能够按照本章中提到的示例进行操作。以下是您的选择：

+   如果您正在使用物理机，您可以添加一对 USB 驱动器。

+   如果您正在使用本地虚拟机，您需要添加两个新的虚拟驱动器。

+   如果您正在使用云实例，可以向其添加两个新的块设备。

例如，让我们看看如何在 Linux 中将这些磁盘添加到我们的虚拟机中。首先，我们关闭了在*第一章*中安装的虚拟机，*安装 RHEL8*，名为`rhel8`。然后我们打开虚拟机的特性页面。在那里我们找到了**添加硬件**按钮：

![图 13.1-编辑虚拟机属性](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/rhel8-adm/img/B16799_13_001.jpg)

图 13.1-编辑虚拟机属性

提示

根据您使用的虚拟化平台，到达虚拟机特性的路径可能不同。但是，很常见的是从虚拟机菜单直接访问选项。

单击**添加硬件**将打开以下截图中的对话框。在其中，我们将选择**存储**选项，并指定要创建并附加到虚拟机的虚拟磁盘的大小，本例中为 1 GiB，然后单击**完成**：

![图 13.2-向虚拟机添加磁盘](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/rhel8-adm/img/B16799_13_002.jpg)

图 13.2-向虚拟机添加磁盘

我们将重复此过程两次以添加两个磁盘。最终结果将如下所示：

![图 13.3-向虚拟机添加两个新磁盘，总共三个](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/rhel8-adm/img/B16799_13_003.jpg)

图 13.3-向虚拟机添加两个新磁盘，总共三个

现在我们将打开虚拟机并登录以检查新设备的可用性：

```
[root@rhel8 ~]# lsblk 
NAME          MAJ:MIN RM SIZE RO TYPE MOUNTPOINT
vda           252:0    0  10G  0 disk 
├─vda1        252:1    0   1G  0 part /boot
└─vda2        252:2    0   9G  0 part 
  ├─rhel-root 253:0    0   8G  0 lvm  /
  └─rhel-swap 253:1    0   1G  0 lvm  [SWAP]
vdb           252:16   0   1G  0 disk 
vdc           252:32   0   1G  0 disk
```

我们可以看到新的 1 GiB 磁盘`vdb`和`vdc`是可用的。现在我们有一个系统磁盘，我们在其中安装了 RHEL 8 操作系统，还有两个可以使用的磁盘，我们准备继续进行本章的操作。

提示

在 Linux 中，磁盘设备的命名取决于它们使用的驱动程序。连接为 SATA 或 SCSI 的设备显示为`sd`和一个字母，例如`sda`或`sdb`。连接为 IDE 总线的设备使用`hd`和一个字母，例如`hda`或`hdb`。例如使用 VirtIO 虚拟化驱动程序的设备使用`vd`和一个字母，例如`vda`或`vdb`。

# 理解 LVM

LVM 使用三层来管理系统中的存储设备。这些层如下：

+   **物理卷**（**PV**）：LVM 的第一层。直接分配给块设备。物理卷可以是磁盘上的分区，也可以是完整的原始磁盘本身。

+   **卷组**（**VG**）：LVM 的第二层。它将物理卷组合起来以聚合空间。这是一个中间层，不太显眼，但它的作用非常重要。

+   **逻辑卷**（**LV**）：LVM 的第三层。它分配了卷组聚合的空间。

让我们看看我们想要使用这两个新添加的磁盘来实现的示例：

![图 13.4 – 使用两个磁盘的 LVM 示例](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/rhel8-adm/img/B16799_13_004.jpg)

图 13.4 – 使用两个磁盘的 LVM 示例

让我们解释这个例子图表，以理解所有的层：

+   我们有两个磁盘，在图中分别是**Disk1**和**Disk2**。

+   **Disk1**被分成了两个分区，**Part1**和**Part2**。

+   **Disk2**没有分区。

+   有三个物理卷。它们的任务是准备磁盘空间以供 LVM 使用。物理卷如下：

- **PV1**，创建在**Disk1**的**Part1**分区上

- **PV2**，创建在**Disk1**的**Part2**分区上

- **PV3**，直接创建在**Disk2**上

+   一个卷组**VG1**，聚合了所有三个物理卷**PV1**、**PV2**和**PV3**。现在，所有的磁盘空间都被整合起来，可以很容易地重新分配。

+   为了分配空间，有四个逻辑卷 – **LV1**、**LV2**、**LV3**和**LV4**。请注意，逻辑卷并不使用整个磁盘。这样，如果我们需要扩展一个卷或创建一个快照，都是可能的。

这是对层是如何分布的基本描述，而不涉及复杂的情况，比如镜像、薄置备或快照。

作为一个经验法则，我们需要理解 PVs 的设计是为了准备设备供 LVM 使用，VGs 用于聚合 PVs，LVs 用于分配聚合空间。

有趣的是，如果我们创建了一个 VG，我们可以向其添加额外的磁盘，从而增加其大小，而无需停止或重新启动机器。同样，我们可以将添加的空间分配给需要它的 LV，而无需停止或重新启动机器。这是 LVM 如此强大并且被推荐用于每台服务器的主要原因之一，几乎没有例外。

现在我们知道 LVM 被分成了几层，让我们开始使用它们来开始理解它们是如何工作的。

# 创建、移动和删除物理卷

根据*技术要求*部分的说明，我们的机器已准备好了两个新磁盘`vdb`和`vdc`，我们可以开始在我们的机器上实现示例图表，就像*图 13.4*中所示的那样。

第一步与 LVM 没有直接关联，但继续示例仍然很重要。这一步涉及对`vdb`磁盘进行分区。让我们用分区管理工具`parted`来看一下：

```
[root@rhel8 ~]# parted /dev/vdb print
Error: /dev/vdb: unrecognised disk label
Model: Virtio Block Device (virtblk)
Disk /dev/vdb: 1074MB
Sector size (logical/physical): 512B/512B
Partition Table: unknown
Disk Flags:
```

重要提示

您的磁盘设备，如果您使用的是物理机器或不同的磁盘驱动程序，可能会有所不同。例如，如果我们使用 SATA 磁盘，它将是`/dev/sdb`而不是`/dev/vdb`。

磁盘完全未分区，正如我们在`unrecognised disk label`消息中所看到的。正如在*第十二章*中所解释的，*管理本地存储和文件系统*，我们可以使用两种类型的磁盘标签；`msdos`（也称为`gpt`，这是一种新类型，适用于带有`gpt`的机器，就像我们在这个例子中所做的那样。用于使用`parted`创建新标签的选项是`mklabel`：

```
[root@rhel8 ~]# parted /dev/vdb mklabel gpt
Information: You may need to update /etc/fstab.

[root@rhel8 ~]# parted /dev/vdb print
Model: Virtio Block Device (virtblk)
Disk /dev/vdb: 1074MB
Sector size (logical/physical): 512B/512B
Partition Table: gpt
Disk Flags: 

Number  Start  End  Size  File system  Name  Flags
```

提示

要创建一个`msdos`标签，命令将是`parted /dev/vdb mklabel msdos`。

现在我们有一个带有`gpt`标签的磁盘，但没有分区。让我们使用交互模式中的`mkpart`选项来创建一个分区：

```
[root@rhel8 ~]# parted /dev/vdb mkpart
```

现在我们可以输入分区名称`mypart0`：

```
Partition name?  []? mypart0
```

对于下一步，指定文件系统，我们将使用`ext2`：

```
File system type?  [ext2]? ext2 
```

现在是设置起始点的时候了。我们将使用第一个可用的扇区，即`2048s`：

```
Start? 2048s
```

提示

现代磁盘中的第一个扇区，根据定义是`2048s`。这不是由工具提供的。当有疑问时，我们可以通过运行`parted /dev/vda unit s print`来查看其他现有磁盘。

然后我们来到最后一步，设置终点，也就是我们想要创建的分区的大小：

```
End? 200MB
```

该命令附带以下警告：

```
Information: You may need to update /etc/fstab.
```

为了确保分区表在系统中得到刷新，并且允许设备在`/dev`下生成，我们可以运行以下命令：

```
[root@rhel8 ~]# udevadm settle
```

提示

在非交互模式下运行的完整命令是`parted /dev/vdb mkpart mypart0 xfs 2048s 200MB`。

我们可以看到新的分区可用：

```
[root@rhel8 ~]# parted /dev/vdb print
Model: Virtio Block Device (virtblk)
Disk /dev/vdb: 1074MB
Sector size (logical/physical): 512B/512B
Partition Table: gpt
Disk Flags: 

Number  Start   End    Size   File system  Name     Flags
1      1049kB  200MB  199MB               mypart0
```

我们需要更改分区以能够托管`LVM`物理卷。`parted`命令使用`set`选项来更改分区类型。我们需要指定分区的编号，即`1`，然后输入`lvm`和`on`来激活：

```
root@rhel8 ~]# parted /dev/vdb set 1 lvm on
Information: You may need to update /etc/fstab.

[root@rhel8 ~]# udevadm settle
[root@rhel8 ~]# parted /dev/vdb print
Model: Virtio Block Device (virtblk)
Disk /dev/vdb: 1074MB
Sector size (logical/physical): 512B/512B
Partition Table: gpt
Disk Flags: 

Number  Start   End    Size   File system  Name     Flags
1      1049kB  200MB  199MB               mypart0  lvm
```

我们看到分区的标志现在设置为`lvm`。

让我们添加第二个分区，`mypart1`：

```
[root@rhel8 ~]# parted /dev/vdb mkpart mypart1 xfs \
200MB 100%
Information: You may need to update /etc/fstab.

[root@rhel8 ~]# parted /dev/vdb set 2 lvm on
Information: You may need to update /etc/fstab.

[root@rhel8 ~]# parted /dev/vdb print
Model: Virtio Block Device (virtblk)
Disk /dev/vdb: 1074MB
Sector size (logical/physical): 512B/512B
Partition Table: gpt
Disk Flags: 

Number  Start   End     Size   File system  Name     Flags
1      1049kB  200MB   199MB               mypart0  lvm
2      200MB   1073MB  872MB               mypart1  lvm
```

现在我们已经创建了两个分区，`/dev/vdb1`（名称为`mypart0`）和`/dev/vdb2`（名称为`mypart1`），这就是我们的存储的样子：

![图 13.5 - 在我们的两个新磁盘上创建的分区](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/rhel8-adm/img/B16799_13_005.jpg)

图 13.5 - 在我们的两个新磁盘上创建的分区

提示

RHEL8 中默认提供了另一个用于管理分区的工具，即`fdisk`。您可能想尝试一下，看看是否更容易使用。

现在是创建持久卷的时候了。我们只会在新创建的分区上执行。首先，我们使用`pvs`命令检查可用的持久卷：

```
[root@rhel8 ~]# pvs
  PV         VG   Fmt  Attr PSize  PFree
  /dev/vda2  rhel lvm2 a--  <9,00g    0 
```

现在，我们继续使用`pvcreate`创建持久卷：

```
[root@rhel8 ~]# pvcreate /dev/vdb1
  Physical volume "/dev/vdb1" successfully created.
[root@rhel8 ~]# pvcreate /dev/vdb2
  Physical volume "/dev/vdb2" successfully created.
```

然后我们再次使用`pvs`检查它们是否已正确创建：

```
[root@rhel8 ~]# pvs
  PV         VG   Fmt  Attr PSize   PFree  
  /dev/vda2  rhel lvm2 a--   <9,00g      0 
  /dev/vdb1       lvm2 ---  190,00m 190,00m
  /dev/vdb2       lvm2 ---  832,00m 832,00m
```

请注意，持久卷没有自己的名称，而是使用它们所创建的分区（或设备）的名称。我们可以将它们称为`PV1`和`PV2`来绘制图表。

现在的状态是：

![图 13.6 - 在两个新分区中创建的持久卷](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/rhel8-adm/img/B16799_13_006.jpg)

图 13.6 - 在两个新分区中创建的持久卷

我们也可以直接在磁盘设备`vdc`上创建一个持久卷。让我们来做一下：

```
[root@rhel8 ~]# pvcreate /dev/vdc 
  Physical volume "/dev/vdc" successfully created.
[root@rhel8 ~]# pvs
  PV         VG   Fmt  Attr PSize   PFree  
  /dev/vda2  rhel lvm2 a--   <9,00g      0 
  /dev/vdb1       lvm2 ---  190,00m 190,00m
  /dev/vdb2       lvm2 ---  832,00m 832,00m
  /dev/vdc        lvm2 ---    1,00g   1,00g
```

与之前的示例一样，物理卷没有名称，我们将其称为`PV3`。结果如下：

![图 13.7 - 在两个新分区和新磁盘设备中创建的持久卷](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/rhel8-adm/img/B16799_13_007.jpg)

图 13.7 - 在两个新分区和新磁盘设备中创建的持久卷

现在我们有了持久卷，让我们在下一节中使用虚拟卷组对它们进行分组。

# 将物理卷合并为卷组

现在是创建一个新的卷组，使用之前添加的物理卷。在这之前，我们可以使用`vgs`命令检查可用的卷组：

```
[root@rhel8 ~]# vgs
  VG   #PV #LV #SN Attr   VSize  VFree
  rhel   1   2   0 wz--n- <9,00g    0
```

我们可以看到只有在安装过程中为操作系统创建的卷组可用。让我们使用`vgcreate`命令创建我们的`storage`卷组，使用`/dev/vdb1`和`/dev/vdb2`分区：

```
[root@rhel8 ~]# vgcreate storage /dev/vdb1 /dev/vdb2 
  Volume group "storage" successfully created
[root@rhel8 ~]# vgs
  VG      #PV #LV #SN Attr   VSize    VFree   
  rhel      1   2   0 wz--n-   <9,00g       0 
  storage   2   0   0 wz--n- 1016,00m 1016,00m
```

如您所见，新的`storage`卷组已经创建。当前状态的图表现在看起来是这样的：

![图 13.8 - 使用两个物理卷创建的第一个卷组](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/rhel8-adm/img/B16799_13_008.jpg)

图 13.8 - 使用两个物理卷创建的第一个卷组

重要提示

**卷组**是 LVM 中的一个非常薄的层，其唯一目标是将磁盘或分区聚合成一个存储池。对该存储的高级管理，例如在两个不同的磁盘上镜像数据，是通过逻辑卷完成的。

我们已经准备好了将分区和磁盘作为物理卷，并将它们聚合到卷组中，因此我们有了一个磁盘空间池。让我们继续学习如何使用逻辑卷来分配该磁盘空间的分布。

# 创建和扩展逻辑卷

我们目前已经创建了几个物理卷，并且其中两个被分组到一个卷组中。让我们移动到下一层，并使用`lvs`命令检查逻辑卷：

```
[root@rhel8 ~]# lvs
  LV   VG   Attr       LSize  Pool Origin Data%  Meta%  Move Log Cpy%Sync Convert
  root rhel -wi-ao---- <8,00g
  swap rhel -wi-ao----  1,00g  
```

我们在`rhel`卷组上看到了`root`和`swap`卷，它们承载着操作系统。

现在，我们可以在`storage`卷组上创建一个名为`data`的简单逻辑卷，大小为 200 MB：

```
[root@rhel8 ~]# lvcreate --name data --size 200MB storage 
  Logical volume "data" created.
[root@rhel8 ~]# lvs
  LV   VG      Attr       LSize   Pool Origin Data%  Meta%  Move Log Cpy%Sync Convert
  root rhel    -wi-ao----  <8,00g                         
  swap rhel    -wi-ao----   1,00g                                  
  data storage -wi-a----- 200,00m
```

我们的配置现在如下：

![图 13.9 - 使用卷组空间创建的第一个逻辑卷](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/rhel8-adm/img/B16799_13_009.jpg)

图 13.9 - 使用卷组空间创建的第一个逻辑卷

创建的逻辑卷是一个块设备，并且类似于磁盘分区。因此，为了使用它，我们需要用文件系统格式化它。让我们通过使用`xfs`格式对其进行格式化：

```
[root@rhel8 ~]# mkfs.xfs /dev/storage/data 
meta-data=/dev/storage/data      isize=512 agcount=4, agsize=12800 blks
         =                       sectsz=512   attr=2, projid32bit=1
         =                       crc=1 finobt=1, sparse=1, rmapbt=0
         =                       reflink=1
data     =                       bsize=4096 blocks=51200,imaxpct=25
         =                       sunit=0      swidth=0 blks
naming   =version 2              bsize=4096   ascii-ci=0, ftype=1
log      =internal log           bsize=4096  blocks=1368, version=2
         =                       sectsz=512 sunit=0 blks, lazy-count=1
realtime =none                   extsz=4096   blocks=0, rtextents=0
Discarding blocks...Done.
```

现在可以挂载了。我们可以创建`/srv/data`目录并在那里挂载它：

```
[root@rhel8 ~]# mkdir /srv/data
[root@rhel8 ~]# mount -t xfs /dev/storage/data /srv/data
[root@rhel8 ~]# df -h /srv/data/
Filesystem                Size  Used Avail Use% Mounted on
/dev/mapper/storage-data  195M   12M  184M   6% /srv/data
```

我们已经设置了 LVM 启用的可用空间。手动挂载文件系统，就像前面的例子一样，在系统关闭或重新启动时有效。为了使其持久化，我们需要将以下行添加到`/etc/fstab`中：

```
/dev/storage/data   /srv/data    xfs    defaults        0 0
```

为了测试该行是否正确编写，我们可以运行以下命令。首先，卸载文件系统：

```
[root@rhel8 ~]# umount /srv/data
```

检查挂载点中的可用空间：

```
[root@rhel8 ~]# df -h /srv/data/
Filesystem             Size  Used Avail Use% Mounted on
/dev/mapper/rhel-root  8,0G  2,8G  5,3G  35% /
```

`df`（*磁盘空闲*）命令的输出显示`/srv/data/`目录中的空间与`root`分区相关联，这意味着该文件夹没有任何关联的文件系统。现在让我们在系统启动时运行`mount`命令：

```
[root@rhel8 ~]# mount –a
```

`/etc/fstab`中的所有未挂载的文件系统将被挂载，如果存在任何问题（例如`/etc/fstab`中的拼写错误），则会显示错误。让我们检查它是否已挂载：

```
[root@rhel8 ~]# df -h /srv/data/
Filesystem                Size  Used Avail Use% Mounted on
/dev/mapper/storage-data  195M   12M  184M   6% /srv/data
```

重要提示

`/dev/storage/data`和`/dev/mapper/storage-data`设备是由一个名为**设备映射器**的组件生成的同一设备的别名（或者更准确地说是符号链接）。它们是完全可互换的。

正如我们所看到的，文件系统已正确挂载。现在我们知道如何创建逻辑卷并为其分配文件系统和挂载点，我们可以继续进行更高级的任务，例如在我们的 LVM 层和更高级别中扩展磁盘空间。

# 添加新磁盘到卷组并扩展逻辑卷

LVM 的一个很棒的功能，更具体地说是卷组，是我们可以向其中添加新的磁盘并开始使用新扩展的空间。让我们尝试通过将`/dev/vdc`中的物理卷添加到`storage`卷组来实现：

```
[root@rhel8 ~]# vgs
  VG      #PV #LV #SN Attr   VSize    VFree  
  rhel      1   2   0 wz--n-   <9,00g      0 
  storage   2   1   0 wz--n- 1016,00m 816,00m
[root@rhel8 ~]# vgextend storage /dev/vdc
  Volume group "storage" successfully extended
[root@rhel8 ~]# vgs
  VG      #PV #LV #SN Attr   VSize  VFree
  rhel      1   2   0 wz--n- <9,00g    0 
  storage   3   1   0 wz--n- <1,99g 1,79g
```

现在，我们的磁盘分布如下：

![图 13.10 - 扩展的卷组，包含三个物理卷](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/rhel8-adm/img/B16799_13_010.jpg)

图 13.10 - 扩展的卷组，包含三个物理卷

现在让我们通过向`data`逻辑卷添加 200 MB 来扩展它：

```
[root@rhel8 ~]# lvs
  LV   VG      Attr       LSize   Pool Origin Data%  Meta%  Move Log Cpy%Sync Convert
  root rhel    -wi-ao----  <8,00g
  swap rhel    -wi-ao----   1,00g 
  data storage -wi-ao---- 200,00m 
[root@rhel8 ~]# lvextend --size +200MB /dev/storage/data
  Size of logical volume storage/data changed from 200,00 MiB (50 extents) to 400,00 MiB (100 extents).
  Logical volume storage/data successfully resized.
[root@rhel8 ~]# lvs
  LV   VG      Attr       LSize   Pool Origin Data%  Meta%  Move Log Cpy%Sync Convert
  root rhel    -wi-ao----  <8,00g 
  swap rhel    -wi-ao----   1,00g
  data storage -wi-ao---- 400,00m
```

逻辑卷已经扩展。但是上面的文件系统还没有：

```
[root@rhel8 ~]# df -h /srv/data/
Filesystem                Size  Used Avail Use% Mounted on
/dev/mapper/storage-data  195M   12M  184M   6% /srv/data
```

我们需要扩展文件系统。要执行此操作的工具取决于文件系统的类型。在我们的情况下，由于它是`xfs`，扩展它的工具是`xfs_growfs`。让我们来做：

```
[root@rhel8 ~]# xfs_growfs /dev/storage/data 
meta-data=/dev/mapper/storage-data isize=512    agcount=4, agsize=12800 blks
         =                       sectsz=512   attr=2, projid32bit=1
         =                       crc=1 finobt=1, sparse=1, rmapbt=0
         =                       reflink=1
data     =                       bsize=4096 blocks=51200 imaxpct=25
         =                       sunit=0      swidth=0 blks
naming   =version 2              bsize=4096   ascii-ci=0, ftype=1
log      =internal log           bsize=4096   blocks=1368 version=2
         =                       sectsz=512   sunit=0 blks, lazy-count=1
realtime =none                   extsz=4096   blocks=0, rtextents=0
data blocks changed from 51200 to 102400
[root@rhel8 ~]# df -h /srv/data/
Filesystem                Size  Used Avail Use% Mounted on
/dev/mapper/storage-data  395M   14M  382M   4% /srv/data
```

现在，文件系统已经添加了一些额外的空间并可用。

重要提示

在执行此任务时，逻辑卷可以被挂载并被系统使用。LVM 已准备好在运行时对生产系统进行卷扩展。

重新分配空间并添加另一个逻辑卷非常容易：

```
[root@rhel8 ~]# lvcreate --size 100MB --name img storage 
  Logical volume "img" created.
[root@rhel8 ~]# lvs
  LV   VG      Attr       LSize   Pool Origin Data%  Meta%  Move Log Cpy%Sync Convert
  root rhel    -wi-ao----  <8,00g                     
  swap rhel    -wi-ao----   1,00g                        
  data storage -wi-ao---- 400,00m                          
  img  storage -wi-a----- 100,00m                          
[root@rhel8 ~]# mkfs.xfs /dev/storage/img 
meta-data=/dev/storage/img       isize=512    agcount=4, agsize=6400 blks
         =                       sectsz=512   attr=2, projid32bit=1
         =                       crc=1 finobt=1, sparse=1, rmapbt=0
         =                       reflink=1
data     =                       bsize=4096 blocks=25600 imaxpct=25
         =                       sunit=0      swidth=0 blks
naming   =version 2              bsize=4096   ascii-ci=0, ftype=1
log      =internal log           bsize=4096  blocks=1368, version=2
         =                       sectsz=512   sunit=0 blks, lazy-count=1
realtime =none                   extsz=4096   blocks=0, rtextents=0
Discarding blocks...Done.
[root@rhel8 ~]# mkdir /srv/img
[root@rhel8 ~]# mount -t xfs /dev/storage/img /srv/img
[root@rhel8 ~]# df /srv/img/
Filesystem              1K-blocks  Used Available Use% Mounted on
/dev/mapper/storage-img     96928  6068     90860   7% /srv/img
[root@rhel8 ~]# df -h /srv/img/
Filesystem               Size  Used Avail Use% Mounted on
/dev/mapper/storage-img   95M  6,0M   89M   7% /srv/img
```

`lvcreate`命令的`--size`和`--extents`选项有几个选项可用于定义要使用的空间：

+   `GB`，或者兆字节，使用`MB`（换句话说，`--size 3GB`）。

+   `--extents`，该命令将使用其内部度量单位`extents`，它类似于磁盘分区的块大小（即`--extents 125`）。

`--size`和`--extents`选项也适用于`lvextend`命令。在这种情况下，我们可以使用先前显示的选项来定义逻辑卷的新大小。我们还有其他选项来定义分配给它们的空间的增量：

+   在`lvextend`命令的数字之前加上`+`符号，这将以提供的度量单位增加大小（即`--size +1GB`会向当前逻辑卷添加 1GB 的额外空间）。

+   `--extents`，以及要使用的剩余空间的百分比，后面跟着`%FREE`（即`--extents 10%FREE`）。

提示

正如我们之前在其他工具中看到的那样，我们可以使用手册页来了解可用的选项。请运行`man lvcreate`和`man lvextend`来熟悉这些工具的手册页。

我们将创建一个逻辑卷用作**交换空间**，这是系统用作内存停车位的磁盘的一部分。系统将消耗内存但不活动的进程放在那里，以便释放物理内存（比磁盘快得多）。当系统中没有更多的空闲物理内存时，也会使用它。

让我们在 LVM 上创建一个交换设备：

```
[root@rhel8 ~]# lvcreate --size 100MB --name swap storage
  Logical volume "swap" created.
[root@rhel8 ~]# mkswap /dev/storage/swap 
Setting up swapspace version 1, size = 100 MiB (104853504 bytes)
no label, UUID=70d07e58-7e8d-4802-8d20-38d774ae6c22
```

我们可以使用`free`命令检查内存和交换状态：

```
[root@rhel8 ~]# free
              total        used        free      shared   buff/cache   available
Mem:        1346424      218816      811372        9140       316236      974844
Swap:       1048572           0     1048572
[root@rhel8 ~]# swapon /dev/storage/swap
[root@rhel8 ~]# free
              total        used        free      shared   buff/cache   available
Mem:        1346424      219056      811040        9140       316328      974572
Swap:       1150968           0     1150968
```

重要提示

这两个新的更改需要为每个添加一行到`/etc/fstab`，以便在重新启动时持久地使用它们。

我们的磁盘空间分布现在看起来是这样的：

![图 13.11 - 扩展的卷组，有三个物理卷](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/rhel8-adm/img/B16799_13_011.jpg)

图 13.11 - 扩展的卷组，有三个物理卷

这个分布看起来很像我们用来描述 LVM 层的初始示例。我们现在已经练习了所有层，创建了每一层所需的部分。我们知道如何创建，现在是时候学习如何在下一节中删除它们了。

# 删除逻辑卷、卷组和物理卷

首先，让我们从用于移除的命令开始，先做一个简单的步骤，移除`img`逻辑卷。首先，我们需要检查它是否已挂载：

```
[root@rhel8 ~]# mount | grep img
/dev/mapper/storage-img on /srv/img type xfs (rw,relatime,seclabel,attr2,inode64,logbufs=8,logbsize=32k,noquota)
```

因为它已经挂载，我们需要卸载它：

```
[root@rhel8 ~]# umount /srv/img 
[root@rhel8 ~]# mount | grep img
```

最后一个命令显示了空输出，这意味着它没有被挂载。让我们继续移除它：

```
[root@rhel8 ~]# lvremove /dev/storage/img 
Do you really want to remove active logical volume storage/img? [y/n]: y
  Logical volume "img" successfully removed
```

现在，我们也可以移除挂载点：

```
[root@rhel8 ~]# rmdir /srv/img
```

逻辑卷的移除也完成了。这个过程是不可逆的，所以要小心运行。我们的磁盘分布现在看起来是这样的：

![图 13.12 - 移除逻辑卷的卷组](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/rhel8-adm/img/B16799_13_012.jpg)

图 13.12 - 移除逻辑卷的卷组

现在是时候进行一个更复杂的任务了，从虚拟组中移除物理卷。这样做的原因是有时您想要将存储在物理磁盘上的数据转移到另一个磁盘，然后将其分离并从系统中移除。这是可以做到的，但首先让我们向`data`逻辑卷添加一些文件：

```
[root@rhel8 ~]# cp -ar /usr/share/scap-security-guide \
/srv/data/
[root@rhel8 ~]# ls /srv/data/
scap-security-guide
[root@rhel8 ~]# du -sh /srv/data/
30M  /srv/data/
```

现在让我们使用`pvmove`命令从`/dev/vdb1`中疏散数据：

```
[root@rhel8 ~]# pvmove /dev/vdb1
  /dev/vdb1: Moved: 7,75%
  /dev/vdb1: Moved: 77,52%
  /dev/vdb1: Moved: 100,00%
```

重要提示

根据分配的 extent，您可能会收到一条消息，指出“没有要移动的数据”。这意味着保存的数据已经分配给了其他磁盘。您可以使用`pvmove`与其他设备来尝试。

现在`/dev/vdb1`中没有存储数据，可以从卷组中移除。我们可以使用`vgreduce`命令来做到这一点：

```
[root@rhel8 ~]# vgreduce storage /dev/vdb1
  Removed "/dev/vdb1" from volume group "storage"
```

我们可以看到存储卷组中现在有更少的空间：

```
[root@rhel8 ~]# vgs
  VG      #PV #LV #SN Attr   VSize  VFree
  rhel      1   2   0 wz--n- <9,00g    0 
  storage   2   2   0 wz--n-  1,80g 1,30g
[root@rhel8 ~]# vgdisplay storage
  --- Volume group ---
  VG Name               storage
  System ID             
  Format                lvm2
  Metadata Areas        2
  Metadata Sequence No  20
  VG Access             read/write
  VG Status             resizable
  MAX LV                0
  Cur LV                2
  Open LV               2
  Max PV                0
  Cur PV                2
  Act PV                2
  VG Size               1,80 GiB
  PE Size               4,00 MiB
  Total PE              462
  Alloc PE / Size       129 / 516,00 MiB
  Free  PE / Size       333 / 1,30 GiB
  VG UUID               1B6Nil-rvcM-emsU-mBLu-wdjL-mDlw-66dCQU
```

我们还可以看到物理卷`/dev/vdb1`没有连接到任何卷组：

```
[root@rhel8 ~]# pvs
  PV         VG      Fmt  Attr PSize    PFree   
  /dev/vda2  rhel    lvm2 a--    <9,00g       0 
  /dev/vdb1          lvm2 ---   190,00m  190,00m
  /dev/vdb2  storage lvm2 a--   828,00m  312,00m
  /dev/vdc   storage lvm2 a--  1020,00m 1020,00m
[root@rhel8 ~]# pvdisplay /dev/vdb1
  "/dev/vdb1" is a new physical volume of "190,00 MiB"
  --- NEW Physical volume ---
  PV Name               /dev/vdb1
  VG Name               
  PV Size               190,00 MiB
  Allocatable           NO
  PE Size               0   
  Total PE              0
  Free PE               0
  Allocated PE          0
  PV UUID               veOsec-WV0n-JP9D-WMz8-UYeZ-Zjs6-sJSJst
```

提示

`vgdisplay`、`pvdisplay`和`lvdisplay`命令显示了 LVM 的任何部分的详细信息。

最重要的部分是，我们可以在系统运行生产工作负载的同时执行这些操作。我们的磁盘分布现在看起来是这样的：

![图 13.13 - 移除物理卷的卷组](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/rhel8-adm/img/B16799_13_013.jpg)

图 13.13 - 带有移除物理卷的卷组

现在是时候移除卷组了，但我们需要先移除逻辑卷，就像之前做的一样（随时运行`lvs`和`vgs`来检查进度）：

```
[root@rhel8 ~]# swapoff /dev/storage/swap
[root@rhel8 ~]# lvremove /dev/storage/swap
Do you really want to remove active logical volume storage/swap? [y/n]: y
  Logical volume "swap" successfully removed
```

现在，我们已经移除了`/dev/storage/swap`。现在让我们使用`--yes`选项移除`/dev/storage/data`，这样我们就不会被要求确认（在脚本中使用此命令时很重要）：

```
[root@rhel8 ~]# umount /dev/storage/data
[root@rhel8 ~]# lvremove --yes /dev/storage/data 
  Logical volume "data" successfully removed
```

现在是时候移除`storage`卷组了：

```
[root@rhel8 ~]# vgremove storage
```

`storage`卷组已成功移除。

最后，清理物理卷：

```
[root@rhel8 ~]# pvremove /dev/vdb1 /dev/vdb2
  Labels on physical volume "/dev/vdb1" successfully wiped.
  Labels on physical volume "/dev/vdb2" successfully wiped.
```

通过这样，我们知道如何在我们的 RHEL8 系统中处理 LVM 的每个部分。让我们回顾下一节中使用的命令。

# 回顾 LVM 命令

作为管理物理卷使用的命令的总结，让我们看一下下表：

![](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/rhel8-adm/img/B16799_Table_13.1.jpg)

现在，让我们回顾一下用于管理卷组的命令：

![](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/rhel8-adm/img/B16799_Table_13.2.jpg)

最后，让我们回顾一下用于管理逻辑卷的命令：

![](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/rhel8-adm/img/B16799_Table_13.3.jpg)

请记住，您可以随时使用每个命令的手册页面获取有关要使用的选项的更多信息，并通过运行`man <command>`来学习新的选项。

重要提示

Web 管理界面 Cockpit 具有用于管理存储组件的扩展。可以使用以下命令以`root`（或使用`sudo`）安装它：`dnf install cockpit-storaged`。您可以尝试在 Cockpit 的存储界面中重复本章中所做的过程，这对您来说是一个很好的练习。

# 总结

LVM 是 Red Hat Enterprise Linux 中非常有用的一部分，它提供了管理、重新分配、分发和分配磁盘空间的能力，而无需停止系统中的任何内容。经过多年的考验，它是系统管理员的关键组件，同时也有助于在我们的系统中引入其他扩展功能（一种通过 iSCSI 共享存储的灵活方式）。

在测试机上练习 LVM 非常重要，这样我们就可以确保在生产系统上运行的命令不会导致服务停止或数据丢失。

在本章中，我们已经看到了可以使用 LVM 完成的最基本但也最重要的任务。我们已经了解了 LVM 的不同层如何工作：物理卷、卷组和逻辑卷。此外，我们还看到了它们如何相互作用以及如何进行管理。我们已经练习了创建、扩展和删除逻辑卷、卷组和物理卷。重要的是要练习它们以巩固所学知识，并能够在生产系统中使用它们。然而，现在已经奠定了这样做的基础。

现在，让我们继续下一章，发现 RHEL8 中的一个新功能，通过添加去重功能来进一步改进存储层 - **虚拟数据优化器**（**VDO**）。
