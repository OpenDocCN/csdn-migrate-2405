# CentOS7 Linux 服务器秘籍（五）

> 原文：[`zh.annas-archive.org/md5/85DEE4E32CF6CFC6347B684FDF685546`](https://zh.annas-archive.org/md5/85DEE4E32CF6CFC6347B684FDF685546)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第十五章：监控 IT 基础设施

在本章中，我们将涵盖以下主题：

+   安装和配置 Nagios Core

+   在远程客户端主机上设置 NRPE

+   监控重要的远程系统指标

# 引言

本章是一系列食谱的集合，提供了设置行业标准的开源网络监控框架：Nagios Core 的必要步骤。

# 安装和配置 Nagios Core

在本食谱中，我们将学习如何安装 Nagios Core 版本 4，这是一个开源网络监控系统，用于检查主机和服务是否正常工作，并在出现问题或服务不可用时通知用户。Nagios 提供了监控您完整 IT 基础设施的解决方案，并设计了一个高度可扩展和可定制的架构，远远超出了简单的 bash 脚本来监控您的服务。（请参阅第三章，*管理系统*中的*监控重要服务器基础设施*食谱。）

## 准备工作

要完成本食谱，您需要一个具有 root 权限的 CentOS 7 操作系统的有效安装，您选择的基于控制台的文本编辑器，以及连接到互联网以便于下载额外软件包的能力。Nagios Core 4 在官方源中不可用，而是来自 EPEL 仓库；请确保在安装之前已安装它（请参阅第四章，*使用 YUM 管理软件包*中的*使用第三方仓库*食谱）。对于 Nagios Web 前端，您还需要一个运行的 Apache2 Web 服务器以及 PHP（请参阅第十二章，*提供 Web 服务*中的食谱）安装在您的 Nagios 服务器上。在我们的示例中，Nagios 服务器的 IP 地址为 192.168.1.7，它将能够监控整个 192.168.1.0/24 子网中的所有 IT 基础设施。

## 如何操作...

Nagios Core 4 默认不可用，因此让我们从安装所有必需的软件包开始：

1.  为此，以 root 身份登录并键入以下命令：

    ```
    yum install nagios nagios-plugins-all nagios-plugins-nrpe nrpe

    ```

1.  首先，创建一个名为 `nagiosadmin` 的新用户账户，该账户用于对 Web 前端进行身份验证（在提示时输入一个安全的密码），然后重新加载 Apache 配置：

    ```
    htpasswd /etc/nagios/passwd nagiosadmin  && systemctl reload httpd

    ```

1.  现在，为 `nagiosadmin` 网络用户添加一个电子邮件地址到 Nagios 配置中，打开以下文件，并搜索并替换字符串 `nagios@localhost`，将其替换为您想要使用的适当电子邮件地址（可以是域内或外部电子邮件地址）：

    ```
    vi /etc/nagios/objects/contacts.cfg

    ```

1.  现在，我们需要调整主配置文件以激活 `/etc/nagios/servers` 作为我们服务器的定义配置目录，我们将在稍后放置所有服务器配置文件，但首先，请备份：

    ```
    cp /etc/nagios/nagios.cfg  /etc/nagios/nagios.cfg.BAK
    sed -i -r 's/^#cfg_dir=(.+)servers$/cfg_dir=\1servers/g' 
    /etc/nagios/nagios.cfg

    ```

1.  我们需要创建在上一步中刚刚定义的服务器配置目录：

    ```
    mkdir /etc/nagios/servers
    chown nagios: /etc/nagios/servers;chmod 750 /etc/nagios/servers

    ```

1.  之后，要检查 `nagios.cfg` 语法的正确性，请运行以下命令：

    ```
    nagios -v /etc/nagios/nagios.cfg

    ```

1.  最后，在启动时启用 Nagios 守护进程并启动服务：

    ```
    systemctl enable nagios && systemctl start nagios

    ```

## 它是如何工作的...

在本方法中，我们向您展示了如何在 CentOS 7 上安装 Nagios Core v4 服务器（Core 是 Nagios 项目的开源版本）。除了主要的 Nagios 软件包外，我们还需要在我们的 Nagios 服务器上安装 NRPE 软件包和所有 Nagios 插件。安装后，我们创建了一个用户帐户，该帐户能够登录到 Web 前端，并在主 Nagios 配置文件中设置了该用户的电子邮件地址。接下来，我们使用 `sed` 激活了 `/etc/nagios/servers` 目录，我们将在本章后面的方法中将所有服务器定义文件放入该目录。然后，我们创建了目录并更改了权限以允许 Nagios 用户访问。要测试 Nagios 服务器安装，请在同一子网 192.168.1.0/24 中的计算机上打开 Web 浏览器，打开以下 URL（在我们的示例中，Nagios 服务器的 IP 地址为 192.168.1.7，因此请相应更改），然后使用新创建的 `nagiosadmin` 用户帐户登录到 `http://192.168.1.7/nagios`。

# 在远程客户端主机上设置 NRPE

**Nagios 远程插件执行器**（**NRPE**）是一个系统守护进程，使用特殊的客户端-服务器协议，并且应该安装在您希望通过远程 Nagios 服务器监控的所有客户端主机上。它允许中央 Nagios 服务器在这些客户端主机上安全地触发任何 Nagios 检查，并且开销很低。在这里，我们将向您展示如何设置和配置任何 CentOS 7 客户端以使用 NRPE；如果您在网络中有多个计算机需要监控，则需要为每个实例应用此方法。

## 准备就绪

要完成此方法，您需要一台除 Nagios 服务器之外的计算机，该计算机安装了 CentOS 7 操作系统，并具有 root 权限，您希望监控该计算机，并且需要在计算机上安装您选择的基于控制台的文本编辑器，以及连接到互联网以便下载额外的软件包。该计算机需要能够通过网络访问我们的 Nagios 服务器。在我们的示例中，Nagios 服务器的 IP 地址为 `192.168.1.7`，我们的客户端系统的 IP 地址为 `192.168.1.8`。

## 如何操作...

1.  以 root 用户身份登录到 CentOS 7 客户端系统，并安装所有 Nagios 插件以及 NRPE：

    ```
    yum install epel-release;yum install nrpe nagios-plugins-all nagios-plugins-nrpe

    ```

1.  之后，打开主 NRPE 配置文件（首先进行备份）：

    ```
    cp /etc/nagios/nrpe.cfg /etc/nagios/nrpe.cfg.BAK && vi /etc/nagios/nrpe.cfg

    ```

1.  找到以 `allowed_hosts` 开头的行，并添加 Nagios 服务器的 IP 地址，用逗号分隔，以便我们可以与之通信（在我们的示例中，`192.168.1.7`，因此请相应更改）；它应该如下所示：

    ```
    allowed_hosts=127.0.0.1,192.168.1.7

    ```

1.  保存并关闭文件，然后在启动时启用 NRPE 并启动它：

    ```
    systemctl enable nrpe && systemctl start nrpe

    ```

1.  然后在 firewalld 中启用 NRPE 端口。为此，为 NRPE 创建一个新的 firewalld 服务文件：

    ```
    sed 's/80/5666/g' /usr/lib/firewalld/services/http.xml | sed 's/WWW (HTTP)/Nagios NRPE/g' | sed 's/<description>.*<\/description>//g' > /etc/firewalld/services/nrpe.xml
    firewall-cmd --reload
    firewall-cmd --permanent --add-service=nrpe; firewall-cmd --reload

    ```

1.  最后，测试 NRPE 连接。为此，以 root 用户身份登录到您的 Nagios 服务器（例如，在`192.168.1.7`）并执行以下命令以在我们的客户端（`192.168.1.8`）上检查 NRPE：

    ```
    /usr/lib64/nagios/plugins/check_nrpe -H 192.168.1.8 -c check_load

    ```

1.  如果输出显示带有数字的`OK - load average`消息，那么您已成功在客户端配置了 NRPE！

## 工作原理...

在本食谱中，我们向您展示了如何在您希望使用 Nagios 服务器监控的 CentOS 7 客户端上安装 NRPE。如果您想监控运行其他发行版（如 Debian 或 BSD）的其他 Linux 系统，您应该能够使用它们自己的包管理器找到适当的包，或者从源代码编译 NRPE。除了 NRPE 包之外，我们还在这台机器上安装了所有 Nagios 插件，因为 NRPE 只是在客户端计算机上运行监控命令的守护进程，但它不包括这些插件。安装后，NRPE 默认只监听本地主机（`127.0.0.1`）连接，因此我们随后不得不将其更改为也监听来自我们的 Nagios 服务器的连接，该服务器使用 IP `192.168.1.7`，在主 NRPE 配置文件中使用`allowed_hosts`指令。NRPE 端口`5666`需要来自 Nagios 服务器的传入连接，因此我们还需要在防火墙中打开它。由于默认情况下没有 firewalld 规则可用，我们创建了自己的新服务文件并将其添加到当前的 firewalld 配置中。之后，我们可以通过在我们的 Nagios 服务器上运行一个`check_nrpe`命令来测试我们的 NRPE 安装，使用客户端的 IP 地址和一个随机检查命令（`check_load`返回系统的负载）。

# 监控重要的远程系统指标

Nagios 插件`check_multi`是一个便捷的工具，可以在单个检查命令中执行多个检查，并生成一个总体返回状态和输出。在本食谱中，我们将向您展示如何设置它并使用它快速监控客户端上的一系列重要系统指标。

## 准备工作

假设您已经按照本章的食谱逐一操作，因此到现在为止，您应该已经有一个运行的 Nagios 服务器和另一个您想要监控的客户端计算机，该计算机已经可以通过其 NRPE 服务从外部被我们的 Nagios 服务器访问。您想要监控的这台客户端计算机需要安装 CentOS 7 操作系统，具有 root 权限，并在其上安装了您选择的基于控制台的文本编辑器，以及连接到互联网以便下载额外的软件包。客户端计算机将具有 IP 地址`192.168.1.8`。

## 如何操作...

`check_multi` Nagios 插件可在 Github 上获得，因此我们将开始本食谱以安装`git`程序，方法是下载它：

1.  以 root 用户身份登录到客户端计算机，如果尚未安装 Git，请进行安装：

    ```
    yum install git

    ```

1.  现在，通过从源代码编译来下载并安装`check_multi`插件：

    ```
    cd /tmp;git clone git://github.com/flackem/check_multi;cd /tmp/check_multi
    ./configure --with-nagios-name=nagios --with-nagios-user=nagios --with-nagios-group=nagios --with-plugin-path=/usr/lib64/nagios/plugins --libexecdir=/usr/lib64/nagios/plugins/
    make all;make install;make install-config

    ```

1.  接下来，我们安装另一个非常有用的插件，名为`check_mem`，该插件在 CentOS 7 Nagios 插件`rpms`中不可用。

    ```
    cd /tmp;git clone https://github.com/justintime/nagios-plugins.git
    cp /tmp/nagios-plugins/check_mem/check_mem.pl  /usr/lib64/nagios/plugins/

    ```

1.  接下来，让我们创建一个`check_multi`命令文件，该文件将包含您希望在单次运行中组合的所有客户端检查；打开以下文件：

    ```
    vi /usr/local/nagios/etc/check_multi/check_multi.cmd

    ```

1.  插入以下内容：

    ```
    command[ sys_load::check_load ] = check_load -w 5,4,3 -c 10,8,6
    command[ sys_mem::check_mem ] = check_mem.pl -w 10 -c 5 -f -C
    command[ sys_users::check_users ] = check_users -w 5 -c 10
    command[ sys_disks::check_disk ] = check_disk -w 5% -c 2% -X nfs
    command[ sys_procs::check_procs ] = check_procs

    ```

1.  接下来，使用以下命令行测试我们上一步创建的命令文件：

    ```
    /usr/lib64/nagios/plugins/check_multi -f   /usr/local/nagios/etc/check_multi/check_multi.cmd

    ```

1.  如果一切正确，它应该打印出您的五个插件检查的结果和一个总体结果，例如，`OK - 5 plugins checked`。接下来，我们将在客户端的 NRPE 服务上安装这个新命令，以便 Nagios 服务器能够通过调用其名称远程执行它。打开 NRPE 配置文件：

    ```
    vi /etc/nagios/nrpe.cfg

    ```

1.  在文件的末尾，紧接在最后一个`# command`行下面添加以下行，以便向我们的 Nagios 服务器公开一个名为`check_multicmd`的新命令。

    ```
    command[check_multicmd]=/usr/lib64/nagios/plugins/check_multi -f   /usr/local/nagios/etc/check_multi/check_multi.cmd

    ```

1.  最后，让我们重新加载 NRPE：

    ```
    systemctl restart nrpe

    ```

1.  现在，让我们检查是否可以从我们的 Nagios 服务器执行我们在上一步中定义的新的`check_multicmd`命令。以 root 身份登录并输入以下命令（根据您的客户端适当更改 IP 地址`192.168.1.8`）：

    ```
    /usr/lib64/nagios/plugins/check_nrpe  -H 192.168.1.8 -c "check_multicmd"

    ```

1.  如果输出与在客户端本地运行它（查看前一步）相同，我们可以成功地通过我们的服务器在客户端上执行远程 NRPE 命令，因此让我们在我们的 Nagios 服务器系统上定义该命令，以便我们可以在 Nagios 系统中开始使用它。打开以下文件：

    ```
    vi /etc/nagios/objects/commands.cfg

    ```

1.  在文件末尾插入以下内容，以定义一个名为`check_nrpe_multi`的新命令，我们可以在任何服务定义中使用它：

    ```
    define command {
     command_name check_nrpe_multi
     command_line $USER1$/check_nrpe -H $HOSTADDRESS$ -c "check_multicmd"
    }

    ```

1.  接下来，我们将在 Nagios 服务器上为我们要监控的客户端定义一个新的服务器定义（为配置文件指定一个合适的名称，例如，其域名或 IP 地址）：

    ```
    vi /etc/nagios/servers/192.168.1.8.cfg

    ```

1.  插入以下内容，这将定义一个带有其服务的新主机，使用我们刚刚创建的新 Nagios 命令：

    ```
    define host {
     use                   linux-server
     host_name              host1
     address               192.168.1.22
     contact_groups         unix-admins
    }
    define service {
     use generic-service
     host_name host1
     check_command check_nrpe_multi
     normal_check_interval 15
     service_description check_nrpe_multi service
    }

    ```

1.  最后，我们需要配置所有应该在出现错误时为我们的新服务接收通知电子邮件的人员。打开以下文件：

    ```
    vi /etc/nagios/objects/contacts.cfg

    ```

1.  在文件末尾插入以下内容：

    ```
    define contactgroup{
     contactgroup_name       unix-admins
     alias                   Unix Administrators
     }
    define contact {
     contact_name                    pelz
     use                             generic-contact
     alias                           Oliver Pelz
     contactgroups                   unix-admins
     email                           oliverpelz@mymailhost.com
    }

    ```

1.  现在，重新启动 Nagios 服务：

    ```
    systemctl restart nagios

    ```

## 工作原理...

我们首先从作者的 Github 仓库安装了`check_multi`和`check_mem`插件，它们是简单的命令行工具。Nagios 通过运行这些外部命令来执行检查，并使用返回代码以及命令的输出来判断检查是否成功。Nagios 拥有一个非常灵活的架构，可以通过插件、附加组件和扩展轻松扩展。所有类型的扩展都可以在[`exchange.nagios.org/`](https://exchange.nagios.org/)找到一个中心位置进行搜索。接下来，我们为`check_multi`添加了一个新的命令文件，其中我们放置了五个不同的系统`check_`命令。这些检查作为定制监控需求的一个起点，将检查系统负载、内存消耗、系统用户、可用空间和进程。所有可用的`check_`命令都可以在`/usr/lib64/nagios/plugins/check_*`找到。正如您在我们的命令文件中看到的，这些`check_`命令的参数可能非常不同，解释它们所有超出了本食谱的范围。它们中的大多数用于设置阈值以达到某个状态，例如`CRITICAL`状态。要获取有关特定命令的更多信息，请使用命令的`--help`参数。例如，要了解`check_load -w 5,4,3 -c 10,8,6`命令中的所有参数的作用，请使用`run /usr/lib64/nagios/plugins/check_load --help`。您可以轻松地从现有插件中添加任意数量的新检查命令到我们的命令文件，或者如果您愿意，可以下载并安装任何新命令。`check_multi`插件还附带了许多命令文件示例，对于学习非常有用，因此请查看目录：`/usr/local/nagios/etc/check_multi/*.cmd`。

之后，我们通过在客户端本地以`-f`参数从`check_multi`命令干运行来检查我们刚刚创建的新命令文件的正确性。在其输出中，您将找到所有单个输出的信息，就像您单独运行这五个命令一样。如果单个检查失败，整个`check_multi`也会失败。接下来，我们在 NRPE 配置文件中定义了一个新的 NRPE 命令`check_multicmd`，然后可以从 Nagios 服务器执行，我们在下一步从 Nagios 服务器进行了测试。为了测试成功，我们期望得到与从客户端本身调用命令时相同的结果。之后，我们在 Nagios 服务器上的`commands.cfg`中定义了这个命令，以便我们可以在任何服务定义中通过引用命令名称`check_nrpe_multi`来重复使用它。接下来，我们创建了一个以 IP 地址命名的新服务器文件（只要它在目录中具有`.cfg`扩展名，您可以将其命名为任何您喜欢的名称），我们想要监控的客户端的 IP 地址为：`192.168.1.8.cfg`。它包含恰好一个主机定义和一个或多个服务定义，这些定义通过主机定义中的`host_name`值与服务定义中的`host_name`值相关联。

在主机定义中，我们定义了一个`contact_groups`联系人，该联系人与`contacts.cfg`文件中的联系人组和联系人条目相关联。如果检查的服务出现任何错误，这些将用于发送通知电子邮件。服务定义中最重要的值是`check_command check_nrpe_multi`行，它执行我们之前创建的唯一检查命令。此外，`normal_check_interval`也很重要，因为它定义了在正常情况下服务检查的频率。在这里，它每 15 分钟检查一次。您可以向主机添加任意数量的服务定义。

现在，请前往您的 Nagios 网页前端检查您新添加的主机和服务。在这里，点击**主机**标签，您将看到在本教程中定义的新主机**host1**，它应该会提供有关其状态的信息。如果您点击**服务**标签，您将看到**check_nrpe_multi**服务。它应该显示**状态**为**待定**、**正常**或**关键**，这取决于单个检查的成功与否。如果您点击其**check_nrpe_multi**链接，您将看到有关检查的详细信息。

在本章中，我们只能向您展示 Nagios 的基础知识，但总有更多需要学习的内容，因此请阅读官方 Nagios Core 文档，网址为[`www.nagios.org`](https://www.nagios.org)，或者查看书籍《Learning Nagios 4》，*Packt Publishing*，作者 Wojciech Kocjan。
