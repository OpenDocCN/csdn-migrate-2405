# CentOS7 Linux 服务器秘籍（三）

> 原文：[`zh.annas-archive.org/md5/85DEE4E32CF6CFC6347B684FDF685546`](https://zh.annas-archive.org/md5/85DEE4E32CF6CFC6347B684FDF685546)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第七章：构建网络

在本章中，我们将涵盖以下主题：

+   使用 CUPS 打印

+   运行 DHCP 服务器

+   使用 WebDAV 进行文件共享

+   安装和配置 NFS

+   使用 NFS

+   使用 Samba 安全共享资源

# 引言

本章是一系列食谱的集合，涵盖了当今工作环境的许多方面。从跨不同类型的办公计算机系统的打印和文件共享到保持您的计算机在线，本章提供了关于如何快速使用 CentOS 来实施必要的工具，这些工具将在您的网络环境中最大化效率的必要细节。

# 使用 CUPS 打印

**打印服务器**允许本地打印设备连接到网络并被多个用户和部门共享。使用这样的系统有很多优点，包括不需要为每个用户、房间或部门购买专用的打印机硬件。**通用 Unix 打印系统**（**CUPS**）是 Linux 以及包括 OS X 在内的 Unix 发行版上打印服务器的事实标准。它采用典型的客户端/服务器架构，网络中的客户端将打印作业发送到中央打印服务器，该服务器安排这些任务，然后将实际的打印任务委派给本地连接到我们的打印服务器的打印机，或者将打印作业远程发送到具有请求打印机的物理连接的计算机，或者发送到独立的网络打印机。如果您在 CUPS 系统中设置打印机，几乎所有 Linux 和 OS X 打印应用程序在您网络中的任何客户端上都将自动配置为开箱即用，无需安装额外的驱动程序。在这里，在本食谱中，我们将向您展示如何开始使用 CUPS 打印服务器系统。

## 准备

要完成这个食谱，您将需要一个具有 root 权限的工作 CentOS 7 操作系统安装，您选择的基于控制台的文本编辑器，以及连接到互联网以下载额外的软件包。在这个食谱中，我们将使用具有 IP 地址`192.168.1.8`的网络接口，以及相应的网络地址`192.168.1.0/24`，将 CUPS 打印服务器提供给我们的网络。

## 怎么做...

我们从这个食谱开始安装 CUPS 打印服务器软件，这在新鲜的 CentOS 7 最小系统上默认不可用：

1.  为此，以`root`身份登录并安装以下软件包：

    ```
    yum install cups

    ```

1.  接下来，为 CUPS 服务器创建一个 SSL 证书，我们将需要它来进行安全的身份验证到 CUPS Web 应用程序（在询问时添加一个安全密码）：

    ```
    cd /etc/pki/tls/certs
    make cups-server.key

    ```

1.  现在，让我们打开 CUPS 主配置文件以自定义服务器（首先备份）：

    ```
    cp /etc/cups/cupsd.conf /etc/cups/cupsd.conf.BAK
    vi /etc/cups/cupsd.conf

    ```

1.  首先，为了让 CUPS 在整个网络上可用，找到以下行：`Listen localhost:631`，然后将其更改为：

    ```
    Listen 631
    ```

1.  接下来，我们想要配置对基于 Web 的 CUPS 前端所有常规网页的访问。搜索`<Location />`指令（不要与其他指令如`<Location /admin>`混淆），并通过添加您的网络地址来更改整个块。更改后，整个块看起来像这样：

    ```
    <Location />
     Order allow,deny
     Allow 192.168.1.0/24
    </Location>
    ```

1.  接下来，为`/admin`和`/admin/conf Location`指令设置访问权限，仅授予本地服务器的访问权限：

    ```
    <Location /admin>
       Order allow,deny
       Allow localhost
    </Location>
    <Location /admin/conf>
       AuthType Default
       Require user @SYSTEM
       Order allow,deny
       Allow localhost
    </Location>
    ```

1.  最后，将我们的 SSL 证书信息添加到配置文件的末尾：

    ```
    ServerCertificate /etc/pki/tls/certs/cups-server.crt
    ServerKey /etc/pki/tls/certs/cups-server.key
    ```

1.  关闭并保存文件，然后重新启动 CUPS 服务器并在启动时启用它：

    ```
    systemctl restart cups.service systemctl enable cups.service

    ```

1.  现在，我们必须在 firewalld 中打开 CUPS 服务器端口，以便网络中的其他计算机可以连接到它：

    ```
    firewall-cmd --permanent --add-service=ipp firewall-cmd --reload

    ```

1.  您可以通过从`192.168.1.0/24`网络中的另一台计算机浏览以下位置来测试您的 CUPS 服务器的可访问性（在浏览器询问时允许安全异常）：

    ```
    https://<IP address of your CUPS server>:631
    ```

1.  要访问 CUPS 前端内的管理区域，您需要位于运行 CUPS 的服务器上（在 CentOS 7 最小安装上，请安装窗口管理器和浏览器），然后使用系统用户`root`和适当的密码登录。

## 它是如何工作的...

在本配方中，我们向您展示了安装和设置 CUPS 打印服务器是多么容易。

那么，我们从这次经历中学到了什么？

我们的旅程始于在我们的服务器上安装 CUPS 服务器软件包，因为默认情况下 CentOS 7 系统上不可用。之后，我们生成了一个 SSL 密钥对，我们将在稍后的过程中需要它（了解更多信息，请阅读第六章中的*生成自签名证书*配方，*提供安全性*）。它用于允许通过安全的 HTTPS 连接加密提交您的登录凭据到 CUPS 管理 Web 前端。接下来，我们使用我们选择的文本编辑器打开了 CUPS 的主配置文件`/etc/cups/cupsd.conf`。如您所见，配置格式与 Apache 配置文件格式非常相似。我们开始通过删除本地主机名来更改`Listen`地址，从而允许您网络中的所有客户端（`192.168.1.0/24`）访问我们的 CUPS 服务器端口`631`，而不是仅允许本地接口连接到打印服务器。

### 注意

默认情况下，CUPS 服务器启用了`浏览功能`，它会每 30 秒向同一子网上的所有客户端计算机广播系统中所有共享打印机的更新列表。如果还想向其他子网广播，请使用`BrowseRelay`指令。

接下来，我们配置了对 CUPS Web 界面的访问。这个前端可以用来方便地浏览网络上所有可用的打印机，或者如果您使用管理员账户登录，甚至可以安装新打印机或配置它们。由于用户界面中有不同的任务，因此可以使用三个不同的指令来精细调整其访问权限。可以使用`<Location />`指令设置对所有正常网页的访问，而所有管理页面可以使用`<Location /admin>`管理，更具体地更改配置可以使用`<Location /admin/conf>`标签。在这些`Location`标签中的每一个中，我们都添加了不同的`Allow`指令，从而允许从您的完整网络（例如，`192.168.1.0/24`）访问正常的 CUPS 网页（例如，浏览所有可用的网络打印机），而访问特殊管理页面则限制为运行 CUPS 服务的`localhost`服务器。请记住，如果这对您的环境来说太严格，您可以随时调整这些`Allow`设置。此外，还有各种其他类型的`Location`可用，例如用于在其他子网中激活我们的服务的类型。请使用`man cupsd.conf`阅读 CUPS 配置手册。接下来，我们配置了 SSL 加密，从而为 Web 界面激活了安全的`https://`地址。然后，我们首次启动了 CUPS 服务器，并启用了它在服务器启动时自动启动。最后，我们添加了`ipp` firewalld 服务，从而允许 CUPS 客户端连接到服务器。

## 不仅如此...

既然我们已经成功设置并配置了 CUPS 服务器，那么是时候向其添加一些打印机并打印测试页了。在这里，我们将向您展示如何使用命令行将*两种不同*类型的打印机添加到系统中。

### 注意

使用基于图形的 Web 界面 CUPS，也可以添加或配置打印机。

首先，我们将安装一个真正的*网络*打印机，该打印机已经在我们 CUPS 服务器所在的同一网络（在我们的例子中，是`192.168.1.0/24`网络）中可用，然后是一个本地连接的打印机（例如，通过 USB 连接到我们的 CUPS 服务器或同一网络中的任何其他计算机）。

### 注意

为什么您应该将已连接的网络打印机安装到我们的 CUPS 服务器上？CUPS 不仅仅可以打印：它是一个集中式打印服务器，因此可以管理打印机及其作业的调度和队列，为不同子网中的打印机提供服务，并为任何 Linux 或 Mac 客户端提供统一的打印协议和标准，以便方便访问。

### 如何将网络打印机添加到 CUPS 服务器

要开始将网络打印机添加到我们的 CUPS 服务器，我们将使用`lpinfo -v`命令列出 CUPS 服务器已知的所有可用打印设备或驱动程序。通常情况下，CUPS 服务器会自动识别所有本地（USB、并行、串行等）和远程可用（网络协议，如`socket`、`http`、`ipp`、`lpd`等）的打印机，而不会出现任何问题。在我们的示例中，以下网络打印机已成功识别（输出已被截断）：

```
network dnssd://Photosmart%20C5100%20series%20%5BF8B652%5D._pdl-datastream._tcp.local/

```

接下来，我们将把这个打印机安装到 CUPS 服务器上，使其处于其控制之下。首先，我们需要找到正确的打印机驱动程序。正如我们在最后输出中看到的，它是一台 HP Photosmart C5100 系列打印机。因此，让我们在 CUPS 服务器上所有当前安装的驱动程序列表中搜索该驱动程序：

```
lpinfo --make-and-model HP -m | grep Photosmart

```

列表中不包含我们的型号 C5100，因此我们必须使用以下命令安装额外的 HP 驱动程序包：

```
yum install hplip

```

现在，如果我们再次发出命令，我们就能找到正确的驱动程序：

```
lpinfo --make-and-model HP -m | grep Photosmart | grep c5100

```

### 注意

对于其他打印机型号和制造商，也有其他可用的驱动程序包，例如，`gutenprint-cups` RPM 包。

这个打印机的正确驱动程序将显示如下：

```
drv:///hp/hpcups.drv/hp-photosmart_c5100_series.ppd

```

现在，我们准备好使用以下语法安装打印机：

```
lpadmin -p <printer-name> -v <device-uri> -m <model> -L <location> -E

```

在我们的示例中，我们使用以下命令安装了它：

```
lpadmin -p hp-photosmart -v "dnssd://Photosmart%20C5100%20series%20%5BF8B652%5D._pdl-datastream._tcp.local/" -m "drv:///hp/hpcups.drv/hp-photosmart_c5100_series.ppd" -L room123 -E

```

现在，打印机应该处于我们 CUPS 服务器的控制之下，并且应该立即在整个网络中共享并被任何 Linux 或 OS X 计算机看到（在 CentOS 7 最小客户端上，你还需要首先安装`cups`包，并使用 firewalld 的`ipp-client`服务启用传入的`ipp`连接，然后我们 CUPS 服务器共享的网络打印机信息才会变得可用）。

你可以稍后通过打开并更改位于`/etc/cups/printers.conf`的文件来更改此打印机的配置。要实际打印测试页，你现在应该能够使用其名称`hp-photosmart`从任何客户端访问打印机（在 CentOS 7 最小客户端上，你需要安装`cups-client`包）：

```
echo "Hello printing world" | lpr -P hp-photosmart  -H 192.168.1.8:631

```

### 如何将本地打印机共享到 CUPS 服务器

如果你想将物理连接到我们 CUPS 服务器的本地打印机共享出去，只需将打印机插入系统（例如，通过 USB），然后按照之前的步骤操作，即*如何将网络打印机添加到 CUPS 服务器*。在步骤`lpinfo -v`中，你应该看到它以`usb://`地址出现，因此你需要获取这个地址并遵循剩余的步骤。

如果您想连接并共享位于 CUPS 网络中任何其他计算机上的中央 CUPS 服务器上的打印机，请在该其他计算机上安装`cups`守护程序（遵循主节中的所有步骤），然后按照本节中的说明安装打印机驱动程序。这将确保本地 CUPS 守护程序将在网络上提供打印机，就像在我们的中央 CUPS 服务器上一样。现在它已在网络上可用，您可以轻松地将其添加到我们的主 CUPS 服务器，以享受中央打印服务器带来的所有好处。

在本节中，我们仅触及了设置 CUPS 服务器的基础知识，并为您介绍了基础知识。总有更多要学习的内容，您可以构建非常复杂的 CUPS 服务器系统，在企业环境中管理数百台打印机，这超出了本节的范围。

# 运行 DHCP 服务器

如果需要建立网络连接，每台计算机都需要在其系统上安装正确的**互联网协议**（**IP**）配置才能进行通信。使用**动态主机控制协议**（**DHCP**）从*中央点*自动分配 IP 客户端配置可以使管理员的工作更轻松，并且与在网络中的每台计算机系统上手动设置静态 IP 信息相比，简化添加新机器到网络的过程。在小型家庭网络中，人们通常直接在互联网路由器上安装内置的 DHCP 服务器，但这些设备通常缺乏高级功能，并且只有一套基本的配置选项。大多数情况下，这对于大型网络或企业环境来说是不够的，在这些环境中，您更有可能找到专用的 DCHP 服务器，以应对更复杂的场景和更好的控制。在本节中，我们将向您展示如何在 CentOS 7 系统上安装和配置 DHCP 服务器。

## 准备工作

要完成本节，您需要一个具有 root 权限的 CentOS 7 操作系统的有效安装，您选择的基于控制台的文本编辑器以及互联网连接，以便下载额外的软件包。预计您的 DHCP 服务器将使用静态 IP 地址；如果您没有静态 IP 地址，请参阅第二章中的“构建静态网络连接”节。如果您还计划通过 DHCP 向客户端发送 DNS 信息，则应已应用第八章中的“安装和配置简单名称服务器”节。

## 如何操作...

在本例中，我们将为静态网络接口配置 DHCP 服务器，该接口为单个网络提供所有可用的 IP 地址，所有直接连接到它的计算机（它们都在同一子网中）。

1.  首先，以`root`身份登录，并输入以下命令以安装 DHCP 服务器软件包：

    ```
    yum install dhcp

    ```

1.  在我们的示例中，我们将使用名为`ifcfg-enp5s0f1`的网络接口来处理我们的 DHCP 请求。接下来，我们需要收集一些非常重要的网络信息，我们将在稍后配置 DHCP 服务器时使用（将网络接口名称更改为适合您自己的需求）：

    ```
    cat /etc/sysconfig/network-scripts/ifcfg-enp5s0f1

    ```

1.  从这次输出中，我们需要以下信息，请记下来（很可能，您的输出会有所不同）：

    ```
    BOOTPROTO="static"
    IPADDR="192.168.1.8"
    NETMASK="255.255.255.0"
    GATEWAY="192.168.1.254"

    ```

1.  我们还需要子网网络地址，这可以通过以下行计算得出：

    ```
    ipcalc -n 192.168.1.8/24

    ```

1.  这将打印以下输出（请记下来以备后用）：

    ```
    NETWORK=192.168.1.0

    ```

1.  现在，我们将打开主 DHCP 配置文件，在此之前，我们需要对原始文件进行备份：

    ```
    cp /etc/dhcp/dhcpd.conf /etc/dhcp/dhcpd.conf.BAK
    vi /etc/dhcp/dhcpd.conf

    ```

1.  将以下行附加到文件末尾，考虑到您在前面的步骤中从个人网络接口配置中获得的配置（`routers = GATEWAY`，`subnet = NETWORK`）：

    ```
    authoriative;
    default-lease-time 28800;
    max-lease-time 86400;
    shared-network MyNetwork {
        option domain-name           "example.com";
        option domain-name-servers      8.8.8.8, 8.8.4.4;
        option routers                  192.168.1.254;
        subnet 192.168.1.0 netmask 255.255.255.0 {
            range 192.168.1.10 192.168.1.160;
        }
    }
    ```

1.  最后，启动并启用 DHCP 服务：

    ```
    systemctl start dhcpd
    systemctl enable dhcpd

    ```

## 它是如何工作的...

在本食谱中，我们向您展示了为单个网络设置 DHCP 服务器是多么容易。有了这个，每当有新机器加入网络时，计算机都会自动获得正确的 IP 信息，这是它连接到网络所必需的，无需任何进一步的人工干预。

那么，我们从这次经历中学到了什么？

我们通过安装 DHCP 服务器软件包开始了这个配方，因为它不是随 CentOS 7 一起提供的。由于我们的 DHCP 守护进程通过网络接口与其客户端通信以分配 IP 信息，因此下一步我们必须选择将用于该服务的网络设备。在我们的示例中，我们选择了名为`enp5s0f1`的设备。默认情况下，DHCP 服务器可以管理与关联网络接口相同的子网中的所有可用 IP 地址。请记住，主 DHCP 服务器的网络接口必须配置为静态获取其自己的 IP 信息，而不是通过（另一个）DHCP 服务器！接下来，我们使用`cat`命令打印出我们`enp5s0f1`网络接口配置文件中所有有趣的行，这些行我们将需要用于配置 DHCP 服务器。之后，我们使用`ipcalc`工具计算我们 DHCP 服务器的网络接口的（子网）网络地址。然后，我们打开了主 DHCP 服务器配置，开始配置一些*全局*设置，并定义了一个新的*共享网络*。在全局设置中，我们首先将我们的 DHCP 服务器设置为`authoriative`，这意味着它是网络中唯一且主要的负责 DHCP 服务器。接下来，我们将`default-lease-time`定义为`28800`秒，即八小时，将`max-lease-time`定义为`86400`，即 24 小时。租约时间是 DHCP 服务器将 IP 地址“出租”给客户端的时间，之后客户端必须再次向 DHCP 服务器注册以请求 IP 租约的延期。如果它没有在那时请求现有租约的续订，IP 地址将从客户端释放并放回空闲 IP 地址池中，准备提供给想要连接到网络的新机器。客户端可以自行定义它想要租用 IP 地址的时间。如果客户端没有向 DHCP 服务器提供时间范围，将使用默认租约时间。

所有共享同一物理网络接口的子网都应在`shared-network`声明中定义，因此我们使用方括号定义了这个区域。这也称为作用域。在我们的示例中，我们只有一个网络，因此只需要一个共享网络作用域。在其中，我们首先定义了一个`domain-name`选项，该选项将被发送并可被客户端用作其基础域名。接下来，我们将**域名服务器**（**DNS**）添加到我们的配置中。向客户端发送 DNS 信息不是 DHCP 服务器的强制要求，但可能很有用。客户端为给定网络获得的信息越多，越好，因为需要的手动配置步骤就越少。

### 注意

您可以通过 DHCP 向客户端发送有关其连接到的网络的大量其他有用信息：网关、时间、WINS 等。

在我们的示例中，我们使用了官方的 Google DNS 服务器；如果您已经设置了自己的 DNS 服务器（请参阅第八章，*使用 FTP*），您也可以在这里使用这些地址。接下来，我们指定了`routers`选项，这是另一个有用的信息，也将发送给客户端。之后，我们指定了任何 DHCP 服务器最重要的部分：`subnet`范围。在这里，我们定义了分配给客户端的 IP 地址的网络范围。我们需要提供子网网络地址、其子网掩码，然后是我们要允许客户端的开始和结束 IP 地址范围。在我们的示例中，我们允许主机 IP 地址从`192.168.1.10`，`192.168.1.11`，`192.168.1.12` ...到`192.168.1.160`。如果您有多个子网，可以使用多个`subnet`范围指令（称为多宿主 DHCP 服务器）。

接下来，我们启动了 DHCP 服务器并在启动时启用它。现在，您的客户端应该能够从我们的新系统动态获取 IP 地址。

总之，我们只向您展示了一些非常基本的 DHCP 服务器配置选项，以帮助您入门，并且还有许多其他设置可用，允许您构建非常复杂的 DHCP 服务器解决方案。要更好地了解其可能性，请查看 DHCP 服务器文档提供的示例配置文件`less /usr/share/doc/dhcp-4*/dhcpd.conf.example`。

## 还有更多...

在主配方中，我们配置了基本的 DHCP 服务器，以便能够向客户端发送完整的 IP 网络信息，使他们能够加入我们的网络。要使用此服务器，您需要在客户端的网络接口上启用 DHCP 寻址。在 CentOS 客户端上，请不要忘记使用`BOOTPROTO=dhcp`并删除所有静态条目，例如`IPADDR`在适当的网络脚本`ifcfg`文件中（阅读配方，*构建静态网络连接*在第二章，*配置系统*以帮助您开始使用网络脚本文件）。然后，要进行 DHCP 请求，请使用`systemctl restart network`重新启动网络或尝试重新启动客户端系统（使用`ONBOOT=yes`选项）。使用`ip addr list`进行确认。

# 使用 WebDAV 进行文件共享

**基于 Web 的分布式创作和版本控制**（**WebDAV**）开放标准可用于网络上的文件共享。它是一种流行的协议，可以方便地访问远程数据，就像一个*在线硬盘*。许多在线存储和电子邮件提供商通过 WebDAV 账户提供在线空间。大多数图形化的 Linux 或 Windows 系统都可以在其文件管理器中开箱即用地访问 WebDAV 服务器。对于其他操作系统，也有免费的选择。另一个很大的优势是 WebDAV 运行在普通的 HTTP 或 HTTPS 端口上，因此您可以确保它几乎在任何环境中都能工作，即使是在受限的防火墙后面。

在这里，我们将向您展示如何安装和配置 WebDAV 作为 FTP 协议的替代方案，以满足您的文件共享需求。我们将使用 HTTPS 作为我们的通信协议，以实现安全连接。

## 准备就绪

要完成本教程，您需要一个具有 root 权限的工作 CentOS 7 操作系统和一个您选择的基于控制台的文本编辑器。您需要一个在您的网络中可访问的带有 SSL 加密的工作 Apache Web 服务器；请参阅第十一章，*提供邮件服务*，了解如何安装 HTTP 守护程序，特别是*使用 SSL 设置 HTTPS*的教程。此外，熟悉 Apache 配置文件格式也是有利的。

## 如何操作…

1.  创建一个用于共享数据和 WebDAV 锁文件的位置：

    ```
    mkdir -p /srv/webdav /etc/httpd/var/davlock

    ```

1.  由于 WebDAV 作为 Apache 模块在 HTTPS 上运行，我们必须为标准`httpd`用户设置适当的权限：

    ```
    chown apache:apache /srv/webdav /etc/httpd/var/davlock
    chmod 770 /srv/webdav

    ```

1.  现在，创建并打开以下 Apache WebDAV 配置文件：

    ```
    vi /etc/httpd/conf.d/webdav.conf

    ```

1.  输入以下内容：

    ```
    DavLockDB "/etc/httpd/var/davlock"
    Alias /webdav /srv/webdav
    <Location /webdav>
        DAV On
        SSLRequireSSL
        Options None
        AuthType Basic
        AuthName webdav
        AuthUserFile /etc/httpd/conf/dav_passwords
        Require valid-user
    </Location>
    ```

1.  保存并关闭文件。现在，要添加一个名为`john`的新 WebDAV 用户（在提示时为该用户输入新密码）：

    ```
    htpasswd -c /etc/httpd/conf/dav_passwords john

    ```

1.  最后，重新启动 Apache2 Web 服务器：

    ```
    systemctl restart httpd

    ```

1.  要测试我们是否可以连接到我们的 WebDAV 服务器，您可以使用任何客户端网络上的图形用户界面（大多数 Linux 文件管理器支持 WebDAV 浏览），或者我们可以使用命令行挂载驱动器。

1.  在任何客户端机器上以`root`身份登录，该机器与我们的 WebDAV 服务器位于同一网络中（在 CentOS 上，您需要从 EPEL 仓库安装`davfs2`文件系统驱动程序包，并且必须禁用文件锁的使用，因为当前版本无法与文件锁一起工作），输入我们的 DAV 用户账户名为`john`的密码，并在询问时确认自签名证书：

    ```
    yum install davfs2
    echo "use_locks 0" >> /etc/davfs2/davfs2.conf
    mkdir /mnt/webdav
    mount -t davfs https://<WebDAV Server IP>/webdav /mnt/webdav

    ```

1.  现在，让我们看看是否可以写入新的网络存储类型：

    ```
    touch /mnt/webdav/testfile.txt

    ```

1.  如果您遇到连接问题，请检查 WebDAV 服务器上的防火墙设置，以及客户端上的`http`和`https`服务。

## 它是如何工作的…

在本教程中，我们向您展示了如何轻松设置 WebDAV 服务器以实现简单的文件共享。

那么，我们从这次经历中学到了什么？

我们的旅程始于创建两个目录：一个用于存放 WebDAV 服务器的所有共享文件，另一个用于为 WebDAV 服务器进程创建锁定文件数据库。后者是必需的，以便用户可以*阻止*对文档的访问，以避免与其他人发生冲突，如果文件当前正在被他们修改。由于 WebDAV 作为本机 Apache 模块（`mod_dav`）运行，该模块在 CentOS 7 中默认启用，因此我们只需要创建一个新的 Apache 虚拟主机配置文件，我们可以在其中设置所有 WebDAV 设置。首先，我们必须将 WebDAV 主机链接到用于跟踪用户锁定的锁定数据库的完整路径。接下来，我们为 WebDAV 共享文件夹定义了一个别名，然后使用`Location`指令对其进行了配置。如果有人在`/webdav`路径 URL 上使用特定的 HTTP 方法，这将激活。在此区域内，我们指定此 URL 将是一个 DAV 启用的共享，为其启用 SSL 加密，并指定基于用户的密码身份验证。用户帐户的密码将存储在名为`/etc/httpd/conf/dav_passwords`的用户帐户数据库中。为了在此数据库文件中创建有效帐户，我们随后在命令行上使用了 Apache2 `htpasswd`实用程序。最后，我们重新启动了服务以应用我们的更改。

为了测试，我们使用了`davfs`文件系统驱动程序，您需要在 CentOS 7 上使用 EPEL 存储库中的`davfs2`包进行安装。还有许多其他选项，例如`cadaver` WebDAV 命令行客户端（也来自 EPEL 存储库）；或者，您可以直接使用 GNOME、KDE 或 Xfce 等图形用户界面中的集成 WebDAV 支持来访问它。

# 安装和配置 NFS

**网络文件系统**（**NFS**）协议通过网络连接实现对文件系统的远程访问。它基于客户端-服务器架构，允许中央服务器与其他计算机共享文件。客户端可以将这些导出的共享挂载到自己的文件系统中，以便方便地访问，就像它们位于本地存储上一样。虽然 Samba 和 AFP 在 Windows 和 OS X 上更常见的分布式文件系统，但 NFS 现在已成为事实上的标准，是任何 Linux 服务器系统的关键组成部分。在本食谱中，我们将向您展示如何轻松设置 NFS 服务器以在网络上共享文件。

## 准备工作

要完成此操作，您需要具备 CentOS 7 操作系统的有效安装，具有 root 权限，您选择的基于控制台的文本编辑器以及连接到互联网以方便下载其他软件包。预计您的 NFS 服务器和所有客户端将能够相互 ping 通，并且通过静态 IP 地址相互连接（请参阅第二章，*配置系统*中的*建立静态网络连接*配方）。在我们的示例中，NFS 服务器以 IP`192.168.1.10`运行，两个客户端的 IP 分别为`192.168.1.11`和`192.168.1.12`，网络的域名为`example.com`。

## 如何操作...

在本节中，我们将学习如何安装和配置 NFS 服务器，并在客户端上创建和导出共享。

### 安装和配置 NFS 服务器

NFSv4 默认未安装，因此我们将首先下载并安装所需的软件包：

1.  为此，请以`root`身份登录到您要运行 NFS 守护程序的服务器上，并键入以下命令以安装所需的软件包：

    ```
    yum install nfs-utils

    ```

1.  为了使 NFSv4 正常工作，我们需要所有客户端和 NFS 服务器的*相同基*域。因此，如果我们尚未使用 DNS 设置域名（请参阅第九章，*域操作*），我们将在`/etc/hosts`文件中为我们的计算机设置一个新主机名：

    ```
    echo "192.168.1.10 myServer.example.com" >> /etc/hosts
    echo "192.168.1.11 myClient1.example.com" >> /etc/hosts
    echo "192.168.1.12 myClient2.example.com" >> /etc/hosts
    ```

1.  现在，打开`/etc/idmapd.conf`文件，并输入 NFS 服务器的基域名（不是完整的域名）；查找读取`#Domain = local.domain.edu`的行，并将其替换为以下内容：

    ```
    Domain = example.com
    ```

1.  接下来，我们需要为服务器打开一些防火墙端口，以便它具有适当的 NFS 访问权限：

    ```
    for s in {nfs,mountd,rpc-bind}; do firewall-cmd --permanent --add-service $s; done; firewall-cmd --reload

    ```

1.  最后，让我们启动 NFS 服务器服务并在重启时启用它：

    ```
    systemctl start rpcbind nfs-server systemctl enable rpcbind nfs-server systemctl status nfs-server

    ```

### 创建导出共享

既然我们的 NFS 服务器已配置并运行，现在是时候创建一些文件共享，我们可以将其导出到我们的客户端：

1.  首先，让我们为我们的共享创建一个文件夹并更改其权限：

    ```
    mkdir /srv/nfs-data

    ```

1.  创建一个具有特定 GID 的新组，并将其与导出关联，然后更改权限：

    ```
    groupadd -g 50000 nfs-share;chown root:nfs-share /srv -R;chmod 775 /srv -R

    ```

1.  打开以下文件：

    ```
    vi /etc/exports

    ```

1.  现在，输入以下文本，但输入时要非常专注：

    ```
    /srv/nfs-data *(ro) 192.168.1.11(rw) 192.168.1.12(rw) /home *.example.com(rw)

    ```

1.  保存并关闭文件，然后使用以下命令重新导出`/etc/exports`中的所有条目：

    ```
    exportfs -ra

    ```

## 它是如何工作的...

在 CentOS 7 上，您可以安装版本 4 的 NFS，它比以前的版本有一些增强，例如更灵活的认证选项，并且与旧版本的 NFS 完全向后兼容。在这里，我们向您展示了安装和配置 NFS 服务器以及为我们的客户端创建一些共享导出是多么容易。

那么，我们从这次经历中学到了什么？

我们首先通过安装`nfs-utils`包来启动这个配置过程，因为在 CentOS 7 上默认情况下 NFS 服务器功能是不可用的。接下来，我们使用`/etc/hosts`文件配置了服务器域名，因为在我们的示例中，我们还没有配置自己的 DNS 服务器。如果你已经设置了 DNS 服务器，你应该遵循与此处类似的域名模式，因为这对 NFSv4 的正常工作至关重要，因为所有客户端和服务器都应该位于同一个基本域中。在我们的示例中，我们指定了它们都是`example.com`的子域：`myClient1.example.com`，`myClient2.example.com`和`myServer.example.com`。这是一种确保数据共享安全的方法，因为 NFS 服务器只允许来自客户端的文件访问，如果域名匹配（在我们的示例中，服务器和客户端都是`example.com`域的一部分）。接下来，我们将这个基本域放入`idmapd.conf`文件中，该文件负责将用户名和组 ID 映射到 NFSv4 ID。之后，我们在 firewalld 实例中启用了`nfs`，`mountd`和`rpc-bind`服务，这些都是客户端和服务器之间完整支持和通信所必需的。为了完成我们的基本配置，我们启动了`rpcbind`和 NFS 服务器，并设置了开机自启。

在成功设置 NFS 服务器之后，我们为其添加了一些导出项，实际上允许客户端从服务器访问一些共享文件夹。因此，我们在文件系统中创建了一个特殊的目录，用于存放我们所有的共享文件。我们将这个共享文件夹`/srv/nfs-data`与一个新组`nfs-share`关联，并赋予其读/写/执行权限。出于实际原因，我们将在组级别上控制我们的导出 Linux 文件权限。名称并不重要，但其组标识符（GID）必须设置为静态值（例如，`50000`）。这个新的 GID 在服务器和每个客户端上都必须相同，对于每个想要拥有写权限的用户来说，因为 NFS 在服务器和客户端之间通过用户（UID）或 GID 级别在网络上传递任何访问权限。整个共享的魔法发生在`/etc/exports`文件中。它包含一个表格；在其中，你指定了所有关于你的共享文件夹及其客户端访问安全性的重要信息。这个文件中的每一行都相当于系统中的一个共享文件夹，以及一个允许访问它们的以空格分隔的主机列表，以及它们的访问选项。如你所见，有不同的方法来定义目标客户端，使用 IP 地址或主机名。对于主机名，你可以使用通配符如`*`和`?`来使文件更紧凑，并允许一次多个机器，但你也可以为每个单独的主机名定义导出选项。解释所有选项超出了本书的范围；如果你需要更多帮助，请阅读导出手册，可以通过`man exports`找到。

例如，行 `/srv/nfs-data *(ro) 192.168.1.11(rw) 192.168.1.12(rw)` 定义了我们希望将 `/srv/nfs-data` 文件夹的内容导出到所有主机名（因为使用了 `*` 符号）；只读 (`ro`) 意味着每个客户端都可以读取文件夹的内容但不能写入。对于 IP 地址以 `192.168.1` 结尾，且末尾为 `11` 和 `12` 的客户端，我们允许读写 (`rw`)。第二行定义了我们正在将 `/home` 目录导出到 `*.example.com` 子域中的所有客户端，并具有读写能力。每当您对 `/etc/exports` 文件进行更改时，运行 `exportfs -r` 命令以将更改应用到 NFS 服务器。

最后，我们可以说在 CentOS 7 中设置和启动 NFSv4 非常容易。它是 Linux 系统之间共享文件或集中式家目录的完美解决方案。

# 使用 NFS

在客户端计算机可以使用 NFS 服务器共享的文件系统导出之前，它必须配置为正确访问该系统。在本步骤中，我们将向您展示如何在客户端机器上设置和使用 NFS。

## 准备工作

要完成此操作，您需要一个具有 root 权限的 CentOS 7 操作系统的工作安装，您选择的基于控制台的文本编辑器，以及互联网连接以便下载额外的软件包。我们假设您已经遵循了 *安装和配置 NFS* 的步骤，并已经设置了一个 NFS 服务器，例如在本例中。我们假设所有客户端都可以相互 ping 通，并且连接到了 NFS 服务器，并且将使用静态 IP 地址（请参阅 第二章 *系统配置* 中的 *建立静态网络连接* 步骤）。在我们的示例中，NFS 服务器运行在 IP `192.168.1.10` 上，两个客户端分别在 IP `192.168.1.11` 和 `192.168.1.12` 上。

## 操作步骤...

在我们的客户端系统上，我们也需要相同的 NFS 软件包，以及与服务器上类似的配置，以便在它们之间建立通信：

1.  首先，以 `root` 身份登录到您的客户端，并应用与 *安装和配置 NFS* 步骤中完全相同的步骤，直到步骤 3 结束。跳过步骤 4，因为不需要打开 firewalld 服务。然后，在步骤 5 中，使用以下命令，这些命令不会启动和启用 `nfs-server`，而只会启动 `rpcbind` 服务：

    ```
    systemctl start rpcbind
    systemctl enable rpcbind

    ```

1.  在此停止，不要应用原始步骤中的其他内容。为了测试与我们的 NFS 服务器的连接，请使用以下命令：

    ```
    showmount -e myServer.example.com

    ```

1.  现在，为了测试挂载 NFS 导出是否有效，您可以手动使用新用户 `john` 进行测试。首先需要将 `john` 添加到 `nfs-share` 组中，以便我们可以在共享上进行写操作：

    ```
    groupadd -g 50000 nfs-share;useradd john;passwd john;usermod -G nfs-share john
    mount -t nfs4 myServer.example.com:/srv/nfs-data /mnt
    su - john;touch /mnt/testfile.txt

    ```

1.  如果在共享目录中创建文件成功，您可以将导入项放入`fstab`文件中，以便在系统启动时自动挂载：

    ```
    vi /etc/fstab

    ```

1.  添加以下行：

    ```
    myServer.example.com:/srv/nfs-data  /mnt nfs defaults 0 0

    ```

1.  最后，要从`fstab`重新挂载所有内容，请键入以下内容：

    ```
    mount -a

    ```

## 它是如何工作的...

在本食谱中，我们向您展示了从现有的 NFSv4 服务器使用一些共享文件系统导出是多么容易。

那么，我们从这次经历中学到了什么？

正如您所见，要设置 NFS 客户端，您需要与 NFS 服务器本身非常相似的设置，除了启动`rpcbind`服务而不是`nfs-server`（顾名思义，仅在服务器端需要）。`rpcbind`服务是一个端口映射器，用于**远程过程调用**（**RPC**），这是 NFS 工作所需的通信标准。在配置中您应该记住的另一个非常重要的步骤是在`/etc/idmapd.conf`文件中设置域名。我们必须在服务器上使用*相同*的基本域名（`example.com`），以便在服务器和客户端之间进行 NFSv4 通信。在启动并启用`rpcbind`服务后，我们可以将 NFS 共享挂载到本地目录，要么直接使用`mount`命令（使用`-t`类型`nfs4`），要么通过`fstab`文件。请记住，每个想要对共享具有适当的读/写/执行权限的系统用户都需要在 NFS 服务器上具有*相同*的权限；在我们的示例中，我们在相同的 GID 级别上管理正确的权限。我们使用默认选项挂载共享；如果您需要不同的或高级的选项，请参阅`man fstab`。为了应用对`fstab`文件的更改，执行`mount -a`以从该文件重新挂载所有内容。

# 使用 Samba 安全地共享资源

**Samba**是一个软件包，它使您能够跨网络共享文件、打印机和其他常见资源。对于任何工作环境来说，它都是一个无价的工具。在异构网络（即不同的计算机系统，如 Windows 和 Linux）上共享文件资源的最常见方式之一是安装和配置 Samba 作为独立文件服务器，通过*用户级安全*使用系统用户的家目录提供基本的文件共享服务。独立服务器被配置为提供本地身份验证和对其维护的所有资源的访问控制。总而言之，每个管理员都知道 Samba 仍然是一个非常流行的开源发行版，本食谱的目的是向您展示如何提供一种即时文件共享方法，该方法可以在整个工作环境中无缝集成任何数量的用户在任何类型的现代计算机上。

## 准备

要完成此配方，您需要一个具有 root 权限的 CentOS 7 操作系统的工作安装，您选择的基于控制台的文本编辑器，以及连接到 Internet 以便下载其他软件包。预计您的服务器将使用静态 IP 地址。

## 如何操作...

Samba 默认不安装，因此我们将从下载和安装所需软件包开始。

1.  为此，以`root`身份登录并键入以下命令以安装所需的软件包：

    ```
    yum install samba samba-client samba-common

    ```

1.  完成此操作后，第一步是重命名原始配置文件：

    ```
    mv /etc/samba/smb.conf /etc/samba/smb.conf.BAK

    ```

1.  现在，在您喜欢的文本编辑器中创建一个新的配置文件，方法是键入以下内容：

    ```
    vi /etc/samba/smb.conf

    ```

1.  开始构建新的配置，方法是添加以下行，将显示的值替换为更好地代表您自己需求的值：

    ```
    [global]
    unix charset = UTF-8
    dos charset = CP932
    workgroup = <WORKGROUP_NAME>
    server string = <MY_SERVERS_NAME>
    netbios name = <MY_SERVERS_NAME>
    dns proxy = no
    wins support = no
    interfaces = 127.0.0.0/8 XXX.XXX.XXX.XXX/24 <NETWORK_NAME>
    bind interfaces only = no
    log file = /var/log/samba/log.%m
    max log size = 1000
    syslog only = no
    syslog = 0
    panic action = /usr/share/samba/panic-action %d
    ```

    ### 注意

    `WORKGROUP_NAME`是 Windows 工作组的名称。如果您没有此值，请使用标准 Windows 名称`WORKGROUP`。`MY_SERVERS_NAME`指的是您的服务器名称。在大多数情况下，这可能是`FILESERVER`或`SERVER1`等形式。`XXX.XXX.XXX.XXX/XX`指的是 Samba 服务运行的主要网络地址，例如`192.168.1.0/24`。`NETWORK_NAME`指的是您的以太网接口的名称。这可能是`enp0s8`。

1.  现在，我们将配置 Samba 作为独立服务器。为此，只需继续将以下行添加到主配置文件中：

    ```
    security = user
    encrypt passwords = true
    passdb backend = tdbsam
    obey pam restrictions = yes
    unix password sync = yes
    passwd program = /usr/bin/passwd %u
    passwd chat = *Enter\snew\s*\spassword:* %n\n *Retype\snew\s*\spassword:* %n\n *password\supdated\ssuccessfully* .
    pam password change = yes
    map to guest = bad user
    usershare allow guests = no
    ```

1.  对于这个配方，我们不打算将 Samba 配置为域主或主浏览器。为此，添加以下行：

    ```
    domain master = no
    local master = no
    preferred master = no
    os level = 8
    ```

1.  现在，我们将添加对主目录共享的支持，允许有效用户访问其主目录。此功能将支持适当的读/写权限，并且所有文件夹都将保持对其他用户的私密性。为此，添加以下新行：

    ```
    [homes]
         comment = Home Directories
         browseable = no
         writable = yes
         valid users = %S
         create mask =0755
         directory mask =0755
    ```

1.  保存并关闭文件。要测试我们刚刚创建的 Samba 配置文件的语法，请使用以下命令：

    ```
    testparm

    ```

1.  现在，将现有系统用户`john`添加到 Samba 用户管理系统（这是为了稍后测试；请根据您系统上的用户名适当更改）：

    ```
    smbpasswd -a john

    ```

1.  现在，保存文件并关闭它；回到命令行，打开防火墙中的端口：

    ```
    firewall-cmd --permanent --add-service=samba && firewall-cmd --reload

    ```

1.  配置 SELinux 以使用 Samba 主目录：

    ```
    setsebool -P samba_enable_home_dirs on

    ```

1.  现在，确保`samba`和`nmb`服务将在启动过程中启动，并立即启动它们：

    ```
    systemctl enable smb && systemctl enable nmb systemctl start smb && systemctl start nmb

    ```

## 它是如何工作的...

本配方的目的是安装 Samba 并配置其文件共享服务，从而为您的网络中的所有现代计算机系统提供完全的连接性。

那么，我们从这次经历中学到了什么？

安装了必要的软件包后，我们将原始安装的配置文件重命名，以便在以后出现问题时备份，然后我们开始从头设置 Samba，从空白的`smb.conf`配置文件开始。打开这个新文件后，我们开始设置全局配置选项；第一步是声明与基于 Unicode 的字符集兼容。您需要注意，由于您的具体情况和网络，值可能会有所不同。更多信息请参阅`man smb.conf`。

完成这一步后，我们接着确认了工作组和服务器的名称，禁用了 WINS，建立了 Samba 日志文件，并注册了网络接口。然后，我们选择了以下独立选项，包括基于用户的安全选项、密码加密和`tdbsam`数据库后端。首选的安全模式是用户级安全，采用这种方法意味着每个共享可以分配给特定用户。因此，当用户请求连接共享时，Samba 通过验证配置文件和 Samba 数据库中的授权用户提供的用户名和密码来验证此请求。接下来，我们添加了`master`信息。在混合操作系统环境中，当单个客户端试图成为主浏览器时，将产生已知的冲突。这种情况可能不会破坏整个文件共享服务，但会在 Samba 日志文件中记录潜在问题。因此，通过配置 Samba 服务器不声明自己为主浏览器，您将能够降低此类问题被报告的可能性。因此，完成这些步骤后，该方案接下来考虑了启用`homes`目录文件共享的主要任务。当然，您可以尝试显示的选项，但这一简单的指令集不仅确保了有效用户能够使用相关的读/写权限访问其主目录，而且通过将`browseable`标志设置为`no`，您还能够隐藏主目录，使其不在公共视图中显示，从而为用户提供更高程度的隐私。在我们的设置中，Samba 与您的 Linux 系统用户配合工作，但您应该记住，任何现有或新用户都不会自动添加到 Samba 中，必须使用`smbpasswd -a`手动添加。

因此，在保存您的新配置文件后，我们使用`testparm`程序测试其正确性，并使用`samba`服务在 firewalld 中打开与 Samba 相关的传入端口。下一步是确保在启动过程中使用`systemctl`使 Samba 及其相关进程可用。Samba 为了正确工作需要两个主要进程：`smbd`和`nmbd`。从`smbd`开始，该服务的角色是为使用 SMB（或 CIFS）协议的 Windows 客户端提供文件共享、打印服务、用户认证和资源锁定。同时，`nmbd`服务的角色是监听、理解和回复 NetBIOS 名称服务的请求。

### 注意

Samba 通常包括另一个名为`winbindd`的服务，但由于提供基于**Windows Internet Naming Service**（**WINS**）的服务或 Active Directory 认证需要额外的考虑，这超出了本食谱的范围，因此它被广泛忽略。

因此，我们的最终任务是启动 Samba 服务（`smb`）和相关的 NetBIOS 服务（`nmb`）。

您现在知道安装、配置和维护 Samba 是多么简单。总有更多要学习的内容，但这个简单的介绍已经说明了 Samba 的相对易用性和其语法的简单性。它提供了一个解决方案，能够支持各种不同的需求和一系列不同的计算机系统，它将满足您未来多年的文件共享需求。

## 还有更多...

您可以从网络中的任何客户端测试我们的 Samba 服务器配置，只要该客户端可以 ping 通服务器。如果是基于 Windows 的客户端，请打开**Windows 资源管理器**地址栏，并使用以下语法：`\\<Samba 服务器的 IP 地址>\<Linux 用户名>`。例如，我们使用`\\192.168.1.10\john`（成功连接后，您需要输入 Samba 用户名的密码）。在任何 Linux 客户端系统上（在 CentOS 7 上需要安装`samba-client`包），要列出 NFS 服务器的所有可用共享，请使用以下命令：

```
smbclient -L <hostname or IP address of NFS server> -U <username>

```

在我们的示例中，我们将使用以下内容：

```
smbclient -L 192.168.1.10 -U john

```

要进行测试，请使用以下语法挂载共享（这需要在 CentOS 7 上安装`cifs-utils`包）：

```
mount -t cifs  //<ip address of the Samba server>/<linux username> <local mount point> -o  "username=<linux username>"

```

在我们的示例中，我们将使用以下内容：

```
mkdir /mnt/samba-share
mount -t cifs //192.168.1.10/john  /mnt/samba-share -o "username=john"

```

您还可以将此导入放入`/etc/fstab`文件中以进行永久挂载，使用以下语法：

```
//<server>/<share> <mount point> cifs <list of options>  0  0

```

例如：

例如，向文件中添加以下行：

```
//192.168.1.10/john /mnt/samba-share cifs username=john,password=xyz  0 0

```

如果您不想在此文件中使用明文密码，请阅读有关使用`man mount.cifs`的凭据的部分，然后创建一个凭据文件，并使用`chmod 600`在您的主目录中保护它，以确保没有其他人可以读取它。

在本章中，我们向您展示了如何将 Samba 配置为独立服务器并启用家目录，以及如何从客户端连接到它以开始使用。但 Samba 的功能远不止于此！它可以提供打印服务或充当完整的域控制器。如果您想了解更多信息，请随时访问[`www.packtpub.com/`](https://www.packtpub.com/)以了解其他可用材料。


# 第八章：使用 FTP

在本章中，我们将介绍以下主题：

+   安装和配置 FTP 服务

+   使用虚拟 FTP 用户

+   定制 FTP 服务

+   解决用户和文件传输问题

# 引言

本章是一系列操作的集合，提供了揭示 Linux 世界中最基本服务之一的步骤，并提供了安装、配置和无犹豫地提供文件传输协议所需的起点。

# 安装和配置 FTP 服务

尽管存在几种现代且非常安全的网络文件共享技术，但古老的**文件传输协议**（**FTP**）仍然是计算机之间共享和传输文件的最广泛使用的协议之一。在 Linux 世界中，有多种不同的 FTP 服务器可用。在本操作中，您将学习如何安装和配置**非常安全的 FTP 守护程序**（**vsftpd**），这是一个著名的 FTP 服务器解决方案，支持广泛的功能，并允许您在本地网络和互联网上上传和分发大文件。在这里，我们将展示如何安装 vsftpd 守护程序，并提供一些基本设置，主要目标是提高守护程序的安全性。

### 注意

完成此操作后，建议使用 SSL/TLS 加密以进一步增强您的 FTP 服务器（请参阅第六章，*使用 SELinux*，以了解更多关于 SELinux 的信息。接下来，我们在`systemd`中启用`vsftpd`开机启动并启动服务。此时，`vsftpd`将开始运行，并且可以使用任何常规的 FTP 桌面软件进行测试。用户可以使用有效的系统用户名和密码通过连接到服务器的名称、域或 IP 地址（取决于服务器的配置）进行登录。

本食谱的目的是向你展示`vsftpd`并不是一个难以安装和配置的软件包。总有很多事情要做，但是通过这个简单的介绍，我们已经迅速启用了我们的服务器来运行标准的 FTP 服务。

## 还有更多...

安装并配置了基本的 FTP 服务后，你可能会想知道如何将用户引导到其主目录中的特定文件夹。为此，打开你选择的编辑器中的主配置文件`/etc/vsftpd/vsftpd.conf`。

滚动到文件底部，并通过将`<users_local_folder_name>`值替换为更适合你需求的值来添加以下行：

```
local_root=<users_local_folder_name>

```

例如，如果这个 FTP 服务器主要是为了访问和上传用户私人网页的内容，而这些网页托管在同一服务器上，你可能需要配置 Apache 使用用户的主目录中的一个名为/`home/<username>/public_html`的文件夹。为此，你可以在`vsftpd`配置文件的底部添加以下参考：

```
local_root=public_html

```

完成后，保存并关闭配置文件，然后重新启动`vsftpd`服务。在测试此新功能时，请确保`local_root`位置存在于你想要登录的用户的家目录中（例如，`~/public_html`）。

# 使用虚拟 FTP 用户

在本食谱中，你将学习如何实现虚拟用户，以摆脱使用本地系统用户账户的限制。在你的服务器生命周期中，可能会有时候你希望为没有本地系统账户的用户启用 FTP 认证。你可能还希望考虑实施一个解决方案，允许特定个人维护多个账户，以便访问服务器上的不同位置。这种配置意味着使用虚拟用户提供了一定程度的灵活性。由于你不是使用本地系统账户，可以说这种方法提供了改进的安全性。

## 准备就绪

要完成此步骤，你需要一个具有 root 权限的 CentOS 7 操作系统的有效安装，以及你选择的基于控制台的文本编辑器。预计你的服务器将使用静态 IP 地址，并且`vsftpd`已经安装了 chroot 监狱并且正在运行。此步骤需要安装`policycoreutils-python`包。

## 如何做到这一点...

1.  第一步是作为 root 登录到我们的`vsftpd`服务器，并创建一个名为`virtual-users.txt`的纯文本文件，该文件维护虚拟用户的用户名和密码列表。为此，请输入以下命令：

    ```
    vi /tmp/virtual-users.txt

    ```

1.  现在以以下方式添加你的用户名和相应的密码：

    ```
    virtual-username1
    password1
    virtual-username2
    password2
    virtual-username3
    password3

    ```

    ### 注意

    根据需要为每个用户重复此过程，但出于明显的原因，请保持良好的密码策略，并且不要重复使用同一个虚拟用户名。

1.  完成操作后，只需按照常规方式保存并关闭文件。然后，通过输入以下命令来构建数据库文件：

    ```
    db_load -T -t hash -f /tmp/virtual-users.txt /etc/vsftpd/virtual-users.db

    ```

1.  完成此操作后，我们现在将创建将使用此数据库验证虚拟用户的 PAM 文件。为此，请输入以下命令：

    ```
    vi /etc/pam.d/vsftpd-virtual

    ```

1.  现在添加以下行：

    ```
    auth required pam_userdb.so db=/etc/vsftpd/virtual-users
    account required pam_userdb.so db=/etc/vsftpd/virtual-users

    ```

1.  完成后，按照常规方式保存并关闭文件。按照以下方式在你的首选文本编辑器中打开主`vsftpd`配置文件：

    ```
    vi /etc/vsftpd/vsftpd.conf

    ```

1.  现在，在打开的文件中，找到`pam_service_name=vsftpd`行，并通过在行首添加`#`符号来禁用它，使其读作如下：

    ```
    #pam_service_name=vsftpd

    ```

1.  向下滚动到文件底部，并通过自定义`local_root`的值以满足你自己的特定需求来添加以下行——这将是所有虚拟用户将*居住*的基本目录（例如，我们将使用`/srv/virtualusers/$USER`，如下所示）：

    ```
    virtual_use_local_privs=YES
    guest_enable=YES
    pam_service_name=vsftpd-virtual
    user_sub_token=$USER
    local_root=/srv/virtualusers/$USER
    hide_ids=YES

    ```

1.  现在在你之前定义的`/tmp/virtual-users.txt`文件中为每个虚拟用户创建一个子文件夹，并在你使用`local_root`指令指定的目录中。记得将此文件夹的所有权委派给 FTP 用户。为了保持我们的`/srv/virtualusers`示例，我们将使用以下命令以自动方式执行此操作（再次，如果需要，请自定义`/srv/virtualusers`目录）：

    ```
    for u in `sed -n 1~2p /tmp/virtual-users.txt`;
    do
    mkdir -p /srv/virtualusers/$u
    chown ftp: /srv/virtualusers/$u
    done

    ```

1.  现在我们需要通知 SELinux 允许对我们的自定义`local_root`目录进行读/写访问，该目录位于典型的`/home`目录之外：

    ```
    setsebool -P allow_ftpd_full_access on
    semanage fcontext -a -t public_content_rw_t "/srv/virtualusers(/.*)?"
    restorecon -R -v /srv/virtualusers

    ```

1.  接下来，按照以下方式重新启动 FTP 服务：

    ```
    systemctl restart vsftpd

    ```

1.  出于安全原因，现在删除纯文本文件，并使用以下命令保护生成的数据库文件：

    ```
    rm /tmp/virtual-users.txt
    chmod 600 /etc/vsftpd/virtual-users.db

    ```

## 它是如何工作的...

遵循前面的步骤后，你现在将能够邀请无限数量的虚拟用户访问你的 FTP 服务。此功能的配置非常简单；你的整体安全性得到了提升，并且所有访问都限制在你选择的定义的`local_root`目录中。请注意，使用虚拟用户将禁用系统用户从第一个步骤登录到 FTP 服务器。

那么我们从这次经历中学到了什么？

我们首先创建了一个新的临时文本文件，该文件将包含我们所有用户名及其对应的明文密码。然后，我们逐个添加所有必需的用户名和密码，每行一个。完成对每个虚拟用户的这一步骤后，我们保存并关闭了文件，然后运行了 CentOS 7 默认安装的`db_load`命令。该命令用于从我们的文本文件生成一个 BerkeleyDB 数据库，稍后将用于 FTP 用户认证。完成这一步骤后，我们的下一个任务是在`/etc/pam.d/vsftpd-virtual`创建一个 Pluggable Authentication Modules（PAM）文件。该文件读取前面的数据库文件，使用典型的 PAM 配置文件语法（更多信息，请参阅`man pam.d`）为我们的`vsftpd`服务提供认证。然后，我们打开、修改并添加新的配置指令到主`vsftpd`配置文件`/etc/vsftpd/vsftpd.conf`，以便让`vsftpd`通过 PAM 意识到我们的虚拟用户认证。

最重要的设置是`local_root`指令，它定义了所有虚拟用户目录的基本位置。别忘了在路径末尾加上`$USER`字符串。然后，您被提示为文本文件中定义的每个虚拟用户创建相关的虚拟主机文件夹。

由于虚拟用户不是真正的系统用户，我们必须将 FTP 系统用户分配给我们的新 FTP 用户，以完全拥有这些文件。我们使用 bash `for`循环来自动化对临时`/tmp/virtual-users.txt`文件中定义的所有用户的处理过程。接下来，我们设置了正确的 SELinux 布尔值，以允许虚拟用户访问系统，并为我们的`/srv/virtualusers`目录设置了正确的上下文。应用所有这些更改只需使用`systemctl`命令重新启动`vsftpd`服务。

之后，我们删除了包含我们明文密码的临时用户文本文件。我们通过删除除 root 之外的所有访问权限来保护 BerkeleyDB 数据库文件。如果您定期更新、添加或删除 FTP 用户，最好不要删除这个临时明文`/tmp/virtual-users.txt`文件，而是将其放在安全的地方，例如`/root`目录。然后，您应该使用`chmod 600`来保护它。然后，每当您对这个文件进行更改时，都可以重新运行`db_load`命令以保持用户信息的最新状态。如果您需要在以后添加新用户，您还必须为他们创建新的虚拟用户文件夹（请重新运行第 9 步的命令）。之后运行`restorecon -R -v /srv/virtualusers`命令。

现在，您可以通过使用本菜谱中创建的新账户登录 FTP 服务器来测试您的新虚拟用户账户。

# 自定义 FTP 服务

在本教程中，您将学习如何自定义您的`vsftpd`安装。`vsftpd`有许多配置参数，这里我们将展示如何创建一个自定义欢迎横幅，更改服务器的默认超时时间，限制用户连接，以及禁止用户访问服务。

## 准备就绪

要完成本教程，您需要一个具有 root 权限的 CentOS 7 操作系统的工作安装和一个您选择的基于控制台的文本编辑器。预计您的服务器将使用静态 IP 地址，并且`vsftpd`已经安装了 chroot 监狱并且正在运行。

## 如何做到这一点...

1.  首先，以 root 身份登录并打开主要的`vsftpd`配置文件：

    ```
    vi /etc/vsftpd/vsftpd.conf

    ```

1.  首先提供一个替代的欢迎信息，取消注释以下行，并根据需要修改信息。例如，您可以使用这个：

    ```
    ftpd_banner=Welcome to my new FTP server

    ```

1.  要更改默认 FTP 超时时间，取消注释这些行并根据需要替换数值：

    ```
    idle_session_timeout=600
    data_connection_timeout=120

    ```

1.  现在，我们将限制连接：数据传输速率每秒字节数，客户端数量，以及每个 IP 地址的最大并行连接数。在文件末尾添加以下行：

    ```
    local_max_rate=1000000
    max_clients=50 
    max_per_ip=2

    ```

1.  接下来，保存并关闭文件。要禁止特定用户，您可以使用以下命令，同时将用户名替换为适合您需求的适当系统用户值：

    ```
    echo "username" >> /etc/vsftpd/user_list

    ```

1.  现在要应用更改，请重启 FTP 服务：

    ```
    systemctl restart vsftpd

    ```

## 它是如何工作的...

在本教程中，我们已经展示了一些最重要的`vsftpd`设置。涵盖所有配置参数超出了本教程的范围。要了解更多信息，请阅读整个主要的`vsftpd`配置文件`/etc/vsftpd/vsftpd.conf`，因为它包含了许多有用的注释；或者，您可以阅读`man vsftpd.conf`手册。

那么我们从这次经历中学到了什么？

我们首先打开主要的`vsftpd`配置文件，然后使用`ftpd_banner`指令激活并自定义欢迎横幅。在下次成功登录时，您的用户应该看到您的新消息。接下来，当处理大量用户时，您可能想要考虑更改默认超时值并限制连接，以提高您的 FTP 服务的效率。

首先，我们更改了服务器的超时数值。`idle_session_timeout`为`600`秒将使在 10 分钟内不活跃（未执行 FTP 命令）的用户注销，而`data_connection_timeout`为`120`秒将在客户端数据传输停滞（未进展）20 分钟后终止连接。然后我们更改了连接限制。`local_max_rate`为`1000000`字节每秒将限制单个用户的数据传输速率大约为每秒一兆字节。`max_clients`值为`50`将告诉 FTP 服务器只允许 50 个并行用户访问系统，而`max_per_ip`为`2`只允许每个 IP 地址两个连接。

然后我们保存并关闭了文件。最后，我们展示了如何禁止用户使用我们的 FTP 服务。如果您想禁止特定用户使用 FTP 服务，则应将该用户的名称添加到`/etc/vsftpd/user_list`文件中。如果您需要随时重新启用该用户，只需通过从`/etc/vsftpd/user_list`中删除相关用户来反转之前的操作。

# 解决用户和文件传输问题

分析日志文件是解决 Linux 上各种问题或改进服务最重要的技术。在本教程中，您将学习如何配置和启用 vsftpd 的广泛日志记录功能，以帮助系统管理员在出现问题时或仅监视此服务的使用情况。

## 准备就绪

要完成本教程，您需要具备具有 root 权限的 CentOS 7 操作系统的有效安装，以及您选择的基于控制台的文本编辑器。预计您的服务器将使用静态 IP 地址，并且`vsftpd`已经安装了 chroot 监狱并正在运行。

## 如何做到这一点...

1.  要执行此操作，请以 root 身份登录，并键入以下命令以使用您喜欢的文本编辑器打开主配置文件：

    ```
    vi /etc/vsftpd/vsftpd.conf

    ```

1.  现在，将以下行添加到配置文件的末尾，以启用详细的日志记录功能：

    ```
    dual_log_enable=YES
    log_ftp_protocol=YES

    ```

1.  最后，重新启动`vsftpd`守护程序以应用更改：

    ```
    systemctl restart vsftpd

    ```

## 它是如何工作的...

在本教程中，我们展示了如何启用两个独立的日志记录机制：首先，`xferlog`日志文件将记录有关用户上传和下载的详细信息，然后是`vsftpd`日志文件，其中包含客户端和服务器之间的每个 FTP 协议事务，输出`vsftpd`可能的最详细的日志信息。

那么我们从这次经历中学到了什么？

在本教程中，我们打开了主要的`vsftpd`配置文件，并在文件末尾添加了两条指令。首先，`dual_log_enable`确保`xferlog`和`vsftpd`日志文件都将用于记录日志。之后，我们通过启用`log_ftp_protocol`来增加`vsftpd`日志文件的详细程度。

重新启动服务后，`/var/log/xferlog`和`/var/log/vsftdp.log`这两个日志文件将被创建并填充有用的 FTP 活动信息。现在，在我们打开文件之前，让我们创建一些 FTP 用户活动。使用`ftp`命令行工具在服务器上以任何 FTP 用户身份登录，并在`ftp>`提示符下发出以下 FTP 命令，将客户端上的随机文件上传到服务器：

```
put ~/.bash_profile bash_profile_test

```

现在，回到服务器上，检查`/var/log/xferlog`文件以查看有关上传文件的详细信息，并打开`/var/log/vsftpd.log`以查看其他用户活动（例如登录时间或其他用户发出的 FTP 命令）。

请注意，日志文件仅记录用户和 FTP 活动，并不用于调试`vsftpd`服务的问题，例如配置文件错误。要调试服务的一般问题，请使用`systemctl status vsftpd -l`或`journalctl -xn`。


# 第九章：使用域

在本章中，我们将涵盖：

+   安装和配置仅缓存名称服务器

+   设置仅授权的名称服务器

+   创建集成名称服务器解决方案

+   填充域

+   构建一个辅助（从属）DNS 服务器

# 引言

本章是一系列尝试揭开网络世界中使一切正常工作的关键组件技术的神秘面纱的章节。从电子邮件到网页，从远程登录到在线聊天，本章提供了使用 CentOS 快速提供域名服务所需的详细信息，该服务将为您的办公环境提供动力。

# 安装和配置仅缓存名称服务器

计算机之间的每项网络通信只能通过使用唯一 IP 地址来识别通信的确切端点。对于人脑来说，数字总是比给*事物*命名更难记住和工作。因此，IT 先驱从 70 年代初开始发明将名称转换为物理网络地址的系统，使用文件和后来的简单数据库。在现代计算机网络和互联网上，计算机名称与 IP 地址之间的关系在**域名系统**（**DNS**）数据库中定义。它是一个全球分布式系统，提供域名到 IP 地址的解析，以及反向解析，即 IP 地址到域名的解析。DNS 是一个庞大的主题，本章的目的是通过向您展示如何安装和设置自己的仅缓存和转发名称服务器，为您提供完美的起点。我们将使用*Unbound*，这是一个高度安全且快速的递归和缓存 DNS 服务器解决方案，因此是我们的首选。但您需要记住，Unbound 不能用作完全授权的 DNS 服务器（这意味着它提供自己的域名解析记录），我们将在后面的章节中使用流行的 BIND 服务器。仅缓存 DNS 服务器将用于将所有名称解析查询转发到远程 DNS 服务器。这样的系统旨在通过缓存任何域名解析请求的结果来加快对互联网的总体访问。当缓存 DNS 服务器找到客户端查询的答案时，它将答案返回给客户端。但是，它还将答案存储在其缓存中一段时间。然后，缓存可以用作后续请求的来源，以加快总往返时间。

## 准备就绪

要完成此操作，您需要一个具有 root 权限、静态 IP 地址和您选择的基于控制台的文本编辑器的 CentOS 7 操作系统的工作安装。下载额外软件包时需要互联网连接。在本例中，我们的 DNS 服务器在具有网络地址`192.168.1.0/24`的私有网络中运行。

## 如何操作...

在本食谱中，我们将首先配置一个*仅缓存*的 DNS 服务器，然后是一个*仅转发*的 DNS 服务器。

### 配置仅缓存 Unbound DNS 服务器

在本节中，我们将考虑 Unbound 作为仅缓存名称服务器的角色，处理对其他远程 DNS 服务器的递归 DNS 请求，并在一定时间内缓存查询以提高响应时间，当服务器再次被请求相同名称解析时：

1.  首先，以 root 身份登录并键入以下内容安装所需软件包：

    ```
    yum install unbound bind-utils

    ```

1.  现在制作`unbound`配置文件的副本，以便我们以后可以恢复更改，然后使用您喜欢的文本编辑器打开它：

    ```
    cp /etc/unbound/unbound.conf /etc/unbound/unbound.conf.BAK
    vi /etc/unbound/unbound.conf

    ```

1.  向下滚动找到以下行：`# interface: 0.0.0.0`。删除`#`符号以取消注释它（激活它），使其读作如下：

    ```
    interface: 0.0.0.0
    ```

1.  接下来，向下滚动找到以下行：`# access-control: 127.0.0.0/8 allow`。取消注释该行以激活它，并根据需要更改网络地址：

    ```
    access-control: 192.168.1.0/24 allow
    ```

1.  保存并关闭文件，然后创建用于安全 DNSSEC 支持的 RSA 密钥对证书，之后再检查更改后的配置文件的正确性：

    ```
    unbound-control-setup && unbound-checkconf
    ```

1.  接下来，在服务器上的 firewalld 配置中打开 DNS 服务，因为我们希望能够在网络中的其他客户端上使用我们的新 DNS 服务进行查询：

    ```
    firewall-cmd --permanent --add-service dns &&  firewall-cmd --reload

    ```

1.  现在确保服务将在启动时可用，并在之后启动它：

    ```
    systemctl enable unbound && systemctl start unbound

    ```

1.  要测试我们是否可以到达我们的 Unbound DNS 服务器并进行查询，请从同一台服务器上执行以下命令，该服务器正在本地运行我们的 Unbound DNS 服务，这应该会返回[www.packtpub.com](http://www.packtpub.com)的 IP 地址：

    ```
    nslookup www.packtpub.com 127.0.0.1

    ```

1.  对于请求的更详细视图，您还可以在 DNS 服务器上本地运行：

    ```
    unbound-host -d www.packtpub.com

    ```

1.  从网络中的任何其他客户端（需要安装`bind-utils`），您也可以使用我们的新 DNS 服务器查询任何公共域名。例如，如果我们的 DNS 服务器的 IP 是`192.168.1.7`：

    ```
    nslookup www.packtpub.com 192.168.1.7

    ```

1.  最后，让我们在服务器本身上使用我们的新名称服务器。为此，在制作备份副本后，使用您喜欢的文本编辑器打开以下文件：

    ```
    cp /etc/resolv.conf /etc/resolv.conf.BAK; vi /etc/resolv.conf

    ```

1.  删除所有当前的名称服务器引用，并用以下内容替换它们：

    ```
    nameserver 127.0.0.1
    ```

    ### 注意

    如果您在网络脚本接口中设置了某些 DNS 服务器信息（例如，在配置静态 IP 地址时，请参阅第二章服务器的解析 IP 地址。在 DNS 服务器上，您还可以使用`unbound-host -d`命令来获得 Unbound 服务内部 DNS 查询的更技术性的视图。

在我们成功完成这些测试后，我们更新了 DNS 服务器上的当前名称服务器解析器信息，使用我们运行在本地主机上的新 DNS 服务。

## 还有更多...

现在我们想要看看 BIND 将如何执行缓存 DNS 信息。为此，在您的 DNS 服务器上，只需选择一个您之前未访问过的目标网站，并使用`dig`命令。例如：

```
dig www.wikipedia.org

```

运行此测试后，您可能会看到一个查询时间，结果如下：

```
;; Query time: 223 msec

```

现在重复这个练习，重新测试同一个 URL。根据您的网络环境，这可能会产生以下结果：

```
;; Query time: 0 msec

```

现在为另一个网站再次执行此操作。在每次重复前面的命令时，您不仅应该看到查询时间的减少，还应该体验到输出交付的更快响应时间。同样的结果将在浏览器刷新率中体现，因此我们可以这样说，这个简单的练习不仅向您介绍了 Unbound，而且最终将有助于提高您在浏览万维网时本地网络的速度。

# 设置一个仅授权的 DNS 服务器

在本节中，我们将学习如何创建一个*权威专用* DNS 服务器，它可以自己回答关于其控制下的域的查询，而不是将查询重定向到其他 DNS 服务器（例如我们之前的缓存专用 DNS 服务器）。我们将创建一个 DNS 服务器，以解析我们自己的私有本地网络中的所有我们自己的主机名和服务。

如前所述，虽然 Unbound 应该是您在需要缓存专用 DNS 服务器时的首选，因为它是目前最安全的 DNS 服务器解决方案，但它只有有限的权威功能，这通常对于专业 DNS 服务器使用来说是不够的。在这里，我们将使用流行的权威 BIND DNS 服务器包，而不是查询我们的本地服务器名称，并配置一个新的 DNS 区域以提供高度可定制的名称解析。从技术上讲，我们将为我们自己的域编写一个*正向*和*反向区域*文件。区域文件是包含实际域名到 IP 地址映射或相反的文本文件，即 IP 地址映射到域名映射。虽然对任何 DNS 服务器的大多数查询都是将名称翻译为 IP 地址，但反向部分也很重要，如果您需要为任何给定 IP 地址提供正确的域名，则需要设置。我们将配置 BIND 为权威专用，这意味着服务器只会回答它具有权威性的查询（在其区域中有匹配的记录），因此如果 DNS 服务器无法解析请求的域，它将停止请求，并且不会使用递归请求联系其他 DNS 服务器以获取并构建正确的答案。

## 准备工作

要完成此操作，您需要一个具有 root 权限的 CentOS 7 操作系统的工作安装，一个静态 IP 地址，以及您选择的基于控制台的文本编辑器。下载额外软件包时需要互联网连接。在本例中，我们的 DNS 服务器在私有网络中运行，网络地址为`192.168.1.0/24`。我们的 DNS 服务器应该管理我们决定作为`centos7.home`（形式为`domain.toplevel-domain`）的本地私有域。新 DNS 服务器的 IP 地址将是`192.168.1.7`，并且应该获得主机名`ns1`，从而得到完全限定域名（FQDN）`ns1.centos7.home`。（有关 FQDN 的更多信息，请参阅第二章             ; Minimum negative caching
    ```

1.  之后，添加文件的其余内容：

    ```
    ; add your name servers here for your domain
            IN      NS      ns1.centos7.home.
    ; add your mail server here for the domain  
            IN      MX      10   mailhost.centos7.home.
    ; now follows the actual domain name to IP 
    ; address mappings:

    ; first add all referenced hostnames from above
    ns1        IN      A       192.168.1.7
    mailhost   IN      A       192.168.1.8
    ; add all accessible domain to ip mappings here
    router     IN      A       192.168.1.0
    www        IN      A       192.168.1.9
    ftp        IN      A       192.168.1.10
    ; add all the private clients on the Lan here
    client1    IN      A       192.168.1.11
    client2    IN      A       192.168.1.12
    client3    IN      A       192.168.1.13
    ; finally we can define some aliases for 
    ; existing domain name mappings
    webserver  IN      CNAME   www
    johnny     IN      CNAME   client2
    ```

1.  当你完成操作后，请先保存并关闭文件，然后再为我们的私有子网络创建反向区域文件，该子网络用于我们的域名（`C-Class` 是指前三个数字（八位组），它们之间用点分隔：`XXX.XXX.XXX`。例如，对于 `192.168.1.0/24` 子网，`C-Class` 是 `192.168.1`：

    ```
    vi /var/named/db.<C-Class of our search IP in reverse order>

    ```

1.  在我们的示例中，一个解析我们 `centos7.home` 的 `192.168.1` C-Class 子网的反向区域文件将是：

    ```
    vi /var/named/db.1.168.192

    ```

1.  首先，像第 10 步一样输入完全相同的 SOA，然后将以下内容添加到文件的末尾：

    ```
    ;add your name servers for your domain
                 IN      NS      ns1.centos7.home.
    ; here add the actual IP octet to
    ; subdomain mappings:
    7      IN      PTR     ns1.centos7.home.
    8      IN      PTR     mailhost.centos7.home.
    9      IN      PTR     www.centos7.home.
    10     IN      PTR     ftp.centos7.home.
    11     IN      PTR     client1.centos7.home.
    12     IN      PTR     client2.centos7.home.
    13     IN      PTR     client3.centos7.home.
    ```

1.  保存并关闭文件，然后将我们的新区域对添加到命名配置中。为此，再次打开 `named.conf`：

    ```
    vi /etc/named.conf

    ```

1.  现在找到包含 `"/etc/named.rfc1912.zones"` 的行。紧接在这行之后，为你的工作留出空间，并添加适当的区域声明以启用你的*反向*区域，如下所示（将 `XXX.XXX.XXX` 替换为你的反向区域文件名的反向 C-Class，在我们的示例中是 `1.168.192`）：

    ```
    zone "XXX.XXX.XXX.in-addr.arpa." IN {
      type master;
      file "/var/named/db.XXX.XXX.XXX";
      update-policy local;
    };
    ```

1.  完成这一步后，你现在可以继续为你的正向区域添加一个区域声明，如下所示（将 `<domain>.<top-level domain>.db` 替换为你的正向区域文件名，在我们的示例中是 `centos7.home`）：

    ```
    zone "<domain>.<top-level domain>." IN {
      type master;
      file "/var/named/<domain>.<top-level domain>.db";
      update-policy local;
    };
    ```

1.  完成操作后，请保存并关闭文件，然后使用以下命令重启 `bind` 服务：

    ```
     named-checkconf && systemctl restart named
    ```

## 它是如何工作的...

所有 DNS 服务器都配置为执行缓存功能，但是缓存专用服务器仅限于从远程 DNS 服务器回答查询的能力，而权威名称服务器是维护特定记录的主区域的 DNS 服务器。

那么，我们从这次经历中学到了什么？

本教程的目的是设置一个仅权威的 BIND DNS 服务器，并为它提供一个新的区域。DNS 区域定义了单个域下的所有可用资源（主机名和服务）。任何 DNS 区域都应始终包含正向和反向区域文件。为了理解区域配置，我们首先需要讨论 DNS 层次结构。例如，取本教程中的一个 DNS 域名`client1.centos7.home`。我们私有网络中的每台计算机都有一个主机名（例如，`client1`或`www`），并且属于一个域。域由**二级域名**（**SLD**）（例如，`centos7`）和**顶级域名**（**TLD**）（例如，`home`、`org`、`com`等）组成。在 TLD 之上是根域（用`.`点表示），这在与其他程序或配置一起工作时经常被忽略。然而，在处理或定义 FQDN 的区域配置时，非常重要的一点是永远不要忘记在 TLD 后面添加这个点`.`。例如，我们`client1`计算机的 DNS 域名是`client1.centos7.home`，而`/etc/hosts`文件中的 FQDN 通常写成`client1.centos7.home`（从技术上讲这是不正确的，但大多数情况下是足够的）。根域非常重要，因为它包含了根 DNS 服务器，如果权威 DNS 服务器在其自己的记录（区域）或缓存中找不到请求域的现有条目，它将首先被查询。但是，我们在所有其他域层次结构中也有 DNS 服务器，这就是 DNS 服务器进行递归请求的方式。根 DNS 服务器，像任何其他 DNS 服务器一样，解析其区域文件中定义的所有子域，即 TLD。这些 TLD 本身可以解析所有 SLD（也在它们的区域文件中定义）。二级域解析其所有主机名（作为特殊子域，它们指的是网络上的单个计算机或服务）。因此，任何 DNS 请求都会通过不同的 DNS 服务器层次结构，从根 DNS 到 TLD DNS，再到 SLD DNS 服务器。根和 TLD DNS 服务器不能完全解析完整的域名 DNS 查询，如`www.centos7.home`，而是将解析下一个 DNS 层次结构的正确地址。这个系统确保根 DNS 总是能找到正确的 TLD DNS 服务器地址，TLD DNS 服务器总是将请求发送到正确的 SLD DNS，后者拥有正确的区域文件，并最终能够回答请求的 DNS 查询。

那么，我们从这次经历中学到了什么？

正如我们所学，区域文件是一个简单的文本文件，由指令和资源记录组成，由于包含大量两字母缩写，它可能看起来相当复杂。请记住，您需要在基础域级别（例如，`centos7.home`）为所有在该域下运行的主机名和服务（例如，`www`、`host1`、`api`等）设置一对区域文件（正向和反向）。安装`named` DNS 服务器（它是**伯克利互联网名称域**（**BIND**）软件包的一部分）后，我们复制了原始主配置文件，并将默认监听端口从 53 更改为 8053（因为 unbound 已经在端口 53 上监听），但仍仅监听 localhost，并禁用了 IPv6 以保持与其他主要 DNS 服务器的兼容性（因为 IPv6 支持在互联网上仍然有限）。此外，我们在这里禁用了递归，因为我们的 BIND DNS 服务器必须是权威的，这意味着当它无法从自己的区域记录中解析查询时，不允许将 DNS 请求转发到其他远程 DNS 服务器。

然后我们开始创建并自定义我们自己的正向 DNS 区域文件，文件名约定为`/var/named/<domain>.<top-level domain>.db`。该文件以`$TTL`控制语句打开，该语句代表**生存时间**，并向其他名称服务器提供一个时间值，该值决定了它们可以从该区域缓存记录的时间长度。与其他许多指令一样，此指令默认以秒为单位定义，但您也可以使用 BIND 特定的简写形式来表示分钟（`m`）、小时（`h`）、天（`d`）和周（`w`），正如我们在示例中所示（`3h`）。接下来，我们提供了一个**授权开始**（**SOA**）记录。该记录包含有关整个区域的具体信息。这从区域名称（`@`）开始，指定区域类（`IN`），该名称服务器的 FQDN 格式为`hostname.domain.TLD.`，以及区域管理员的电子邮件地址。后一个值通常采用`hostmaster.hostname.domain.TLD.`的形式，并通过将典型的`@`符号替换为点（`.`）来形成。完成此操作后，接下来就是打开括号以分配区域的序列号、刷新值、重试值、过期值和负缓存`生存时间`值。这些指令可以总结如下：

+   序列号（`serial-number`）值是一个数值，通常采用反向日期（`YYYYMMDD`）的形式，并附加一个值（`VV`），该值在每次修改或更新区域文件时递增，以指示该名称服务需要重新加载区域。值`VV`通常从`00`开始，下次修改此文件时，只需将其递增为`01`、`02`、`03`等。

+   `刷新时间`值决定了辅助或从属名称服务器将多频繁地询问主名称服务器区域是否发生了任何更改。

+   `重试时间`值决定了辅助或从属名称服务器在序列号失败后应多久检查一次主服务器。如果在`到期时间`值指定的时间范围内发生故障，辅助名称服务器将停止响应作为请求的权威。

+   `最小 TTL`值决定了其他名称服务器可以缓存否定响应的时间长度。

完成这一部分并关闭相应的括号后，我们接着添加了权威名称服务器信息（`NS`），使用`IN NS <名称服务器的 FQDN>`定义。通常情况下，您至少会有两个，如果不是三个名称服务器（将每个名称服务器的 FQDN 放在新的`IN NS`行中）。然而，如果您的服务器运行在办公室或家庭环境中，并且您希望享受本地名称解析的好处，例如`.home`、`.lan`或`.dev`，那么设置一个名称服务器就特别有用。接下来，我们需要为区域指定邮件服务器，因此需要包含**邮件交换器**（**MX**）记录的引用。格式为`IN MX <优先级> <您的邮件服务器的 FQDN>`。如果您定义了多个邮件服务器（每个在其单独的`IN MX`行中），优先级就变得重要了——数字越低，优先级越高。在这方面，辅助邮件服务器应该有一个更高的值。

### 注意

在`SOA`、`NS`和`MX`行中，我们已经引用了尚未定义为 IP 映射的主机名（`A`记录）。我们可以这样做，因为区域文件不是按顺序处理的。但不要忘记稍后为每个主机名创建相应的`A`行。

根据您的需求，您可能还想将您的名称服务器用作邮件服务器（那么您会写成`MX 10 ns1.centos7.home.`），尽管在示例中您可能有一个专门用于该角色的服务器。

接下来，需要创建适当的`A`记录（`A`代表地址）并将适当的 IP 地址分配给显示的值。这是任何域名解析请求到服务器的心脏。`A`记录用于将 FQDN 链接到 IP 地址，但大部分前面的设置将基于您的确切需求。在这里，您可以定义所有要在网络中映射的本地主机名。由于我们已经在区域文件中使用并引用了一些域名，例如名称服务器或邮件服务器，我们将从这些开始。之后，我们为所有公开可用和内部客户端定义了主机名到 IP 地址的映射。请记住，使用`A`记录时，您可以有多个相同的 IP 地址到不同主机名的映射。例如，如果您在网络中没有为每个服务配备专用服务器，而是有一台运行所有`DNS`、`邮件`、`Web`和`FTP`服务的服务器，您可以编写以下行：

```
ns1        IN A 192.168.1.7
mailhost   IN A 192.168.1.7
www        IN A 192.168.1.7
ftp        IN A 192.168.1.7
```

您还可以使用规范名称（`CNAME`）记录来完成此任务，它用于为现有的`A`记录分配别名。可以说，`CNAME`值通过指向`A`记录，使您的 DNS 数据更易于管理。因此，如果您考虑需要更改`A`记录的 IP 地址，所有指向该记录的`CNAME`记录都会自动更新。然而，正如本教程所尝试展示的，替代解决方案是拥有多个`A`记录，这意味着需要进行多次更新才能更改 IP 地址。

在本教程的这一阶段，我们将注意力转向了反向 DNS 区域。与正向区域文件一样，反向区域文件也有一个特殊的命名约定`/var/named/db.<C-Class of our search IP in reverse order>`。将反向区域文件命名为`db.1.168.192`可能一开始看起来很奇怪，但当你看到反向查找的工作原理时，它就有意义了。它从最高节点（在我们的例子中是`192`，对应于正向区域文件中的根域）开始，并从那里向下遍历。正如你所看到的，我们在这个文件中放置的内容在指令和在正向区域文件中使用的资源之间有一些相似之处。然而，重要的是要记住，反向 DNS 与正向 DNS 是完全独立和不同的。

反向 DNS 区域旨在帮助将 IP 地址转换为域名。这可以通过使用**指针资源记录**（**PTR**）来实现，该记录将唯一的 IP 地址分配给一个或多个主机名。因此，您必须确保每个`A`记录都有一个唯一的 PTR 记录。每个反向区域文件收集完整的 C 类地址范围（例如，前三个点分数字`192.168.1`）的 IP 到主机名转换。此类 IP 范围的最后一个八位字节是可以在该文件中定义的所有主机名。请记住，PTR 记录中第一列的 IP 地址值应该只显示这个最后一个八位字节。例如，在反向区域文件`db.1.168.192`中的行`9 IN PTR www.centos7.home.`将能够将任何反向 IP 地址请求`192.168.1.9`解析为域值`www.centos7.home`。

在本教程中，我们创建了正向和反向区域文件，然后通过将新区域添加到 BIND 服务器来完成 named 服务的配置，以便开始解析我们网络的本地域名。在这些新添加的正向和反向区域定义块中，我们定义了自己是主区域持有者，并指定了`update-policy local;`，因为如果我们想从本地主机使用`nsupdate`命令动态更新我们的区域，这是必需的（稍后会看到）。您可以添加无限数量的区域对，但请记住，每个正向或反向区域定义必须在大括号中给出单个区域条目。

总之，我们可以说正向和反向区域文件是基于单个基础域名定义的，一个基础域名对应一个正向区域文件。对于反向区域文件，情况略有不同，因为我们处理的是 IP 地址。我们根据域的网络地址的 C 类地址范围创建一个区域文件，这里的最后一个八位组称为主机名，我们在此特定文件中定义映射。

BIND 是一个庞大的主题，还有很多需要学习，本食谱仅作为介绍。在大多数情况下，你甚至可能会发现你的初始学习阶段将成为一个试错过程，但这将得到改善。记住，熟能生巧，如果你创建了额外的正向区域，请始终在反向区域文件中引用它们。

## 还有更多...

在为 BIND 服务器创建并添加了区域后，你现在可以测试配置了。为此，你可以使用`host`、`dig`或`nslookup`命令仅从 localhost 解析内部主机名。例如，为了测试正向 DNS 解析，我们可以使用`dig`命令，指定我们的 DNS 服务器在 localhost 上运行，端口为`8053`：`dig -p 8053 @127.0.0.1 client2.centos7.home`。这应该能成功完成 DNS 查找并返回以下行（输出已截断）：

```
;; ANSWER SECTION:
client2.centos7.home.  10800  IN  A  192.168.1.12

```

对于反向查找，你将使用 IP 地址（在本例中，使用的 IP 地址应对应于你已配置反向 DNS 的域）：`nslookup -port=8053 192.168.1.12 127.0.0.1`。由于我们已经将 BIND 配置为仅权威 DNS 服务器，因此任何超出我们区域本地记录的 DNS 请求都无法完全解析。为了测试这一点，使用`dig -p 8053 @127.0.0.1 www.google.com`，它应该返回状态`REFUSED`和`WARNING: recursion requested but not available`消息。

出于安全考虑，我们仅将 BIND 服务器限制为 localhost，不允许它连接到其他 DNS 服务器。因此，你不能将其作为私有网络的唯一 DNS 解决方案。相反，在下一个配方中，我们将学习如何结合 Unbound 和 BIND 来创建一个集成且非常安全的全能 DNS 服务器解决方案。但如果你不想这样做，并且想将 BIND 作为你的单一且完整的权威 DNS 服务器解决方案（这在 CentOS 7 上不再推荐），你可以通过禁用或卸载 Unbound，恢复原始的`named.conf.BAK`配置文件，并在 BIND 配置文件中启用以下指令来实现：`allow-query {localhost;192.168.1.0/24;}`;（允许整个`192.168.1.0/24`网络进行 DNS 请求），`listen-on port 53 {any;}`;（在任何网络上监听请求），`listen-on-v6 port 8053 { none; }`;（禁用 IPv6）。如果你想让 BIND 转发所有它不权威的内容，而不是使用递归来找出答案，也可以添加以下指令（在这个例子中，我们使用官方的 Google DNS 服务器进行任何转发请求，但你可以根据需要进行更改）：`forwarders { 8.8.8.8;};forward only;`。然后重启`bind`服务。

# 创建一个集成的名称服务器解决方案

到目前为止，在本章中，我们使用 Unbound 作为仅缓存的 DNS 服务器解决方案，因为它非常安全和快速，而使用 BIND 作为我们的仅权威 DNS 服务器，因为它的区域管理高度可配置和可定制。BIND 已经存在很长时间，是有史以来使用最广泛的 DNS 软件。然而，过去发现了一些严重的漏洞（幸运的是已经修复）。在本配方中，我们将结合 Unbound 和 BIND，以获得两全其美的效果：只有非常安全的 Unbound 服务将直接暴露给你的私有网络，并可以从你的客户端接收和提供 DNS 查询。BIND 服务仅绑定到 localhost，正如在前一个配方中配置的那样，只允许解析内部主机名，并且没有直接访问互联网或你的客户端的权限。如果客户端连接到你的 Unbound 服务并请求解析私有网络中的内部主机名，Unbound 将在本地查询 BIND 服务器以进行 DNS 解析并将响应缓存。另一方面，如果客户端请求解析外部域名，Unbound 本身将递归查询或转发其他远程 DNS 服务器并将响应缓存。这两种 DNS 服务器系统的集成使其成为完美的全能 DNS 服务器解决方案。

## 准备就绪

要完成这个配方，你需要一个正常运行的 CentOS 7 操作系统和一个你选择的基于控制台的文本编辑器。预计在本章中找到的配方指导下，一个仅缓存的 Unbound 服务器（端口 53）和一个仅权威的 BIND 服务器（端口 8053）已经安装并正在运行。

## 操作方法...

在本教程中，我们将向您展示如何配置 Unbound，以便当客户端请求内部主机名时，它能够查询我们本地运行的权威性仅限的 BIND 服务。对于其他任何请求，应将其作为递归 DNS 请求发送到远程根服务器以构建答案：

1.  以 root 用户身份登录运行 Unbound 和 BIND 服务的我们的服务器，并打开 Unbound 的主配置文件：

    ```
    vi /etc/unbound/unbound.conf

    ```

1.  首先在`server:`子句中的某个位置添加以下行：

    ```
    local-zone: "168.192.in-addr.arpa." nodefault

    ```

1.  接下来，我们需要允许 Unbound 连接到默认禁用的 localhost，查找读取以下内容的行：`# do-not-query-localhost: yes`，然后激活并将其设置为 no：

    ```
    do-not-query-localhost: no

    ```

1.  接下来，由于我们的 BIND 服务器未使用 DNSSEC 配置，因此我们需要告诉 Unbound 无论如何都要使用它（默认情况下，Unbound 拒绝连接到未使用 DNSSEC 的 DNS 服务器）。查找以`# domain-insecure: "example.com"`开头的行，然后激活它并将其更改为以下内容：

    ```
    domain-insecure: "centos7.home."
    domain-insecure: "168.192.in-addr.arpa."

    ```

1.  接下来，我们需要告诉 Unbound 将我们内部域`centos7.home.`的所有请求转发到本地运行的 BIND 服务器（端口`8053`）。在文件末尾添加以下内容：

    ```
    stub-zone:
     name: "centos7.home."
     stub-addr: 127.0.0.1@8053

    ```

1.  此外，我们还需要告诉 Unbound 对我们的内部域使用 BIND 进行任何反向查找时执行相同的操作：

    ```
    stub-zone:
     name: "1.168.192.in-addr.arpa."
     stub-addr: 127.0.0.1@8053

    ```

1.  保存并关闭文件，然后重新启动 Unbound 服务：

    ```
    unbound-checkconf && systemctl restart unbound

    ```

## 工作原理

恭喜！您现在拥有一个完整的权威且非常安全的 DNS 服务器解决方案，采用集成方法结合了 Unbound 和 BIND 的所有优点。在本教程中，我们向您展示了如何使用存根区域配置 Unbound 服务，以便连接到内部运行的 BIND 服务以处理正向和反向请求。`存根区域`是 Unbound 的一个特殊功能，用于配置无法通过公共互联网服务器访问的权威数据。其`名称`字段定义了 Unbound 将转发任何传入 DNS 请求的区域名称，而`存根地址`字段配置了访问 DNS 服务器的位置（IP 地址和端口）；在我们的示例中，这是本地运行的 BIND 服务器，端口为`8053`。为了让 Unbound 能够连接到 localhost，我们首先必须使用`do-not-query-localhost: no`指令允许这样做，必须将我们的正向和反向域标记为`不安全`，还必须定义一个新的`本地区域`，这是必要的，以便 Unbound 知道客户端可以向`存根区域`权威服务器发送查询。

## 还有更多...

为了测试我们的新 Unbound/BIND DNS 集群，请从同一网络中的另一台计算机向 Unbound 服务发出一个公共和一个内部主机名的 DNS 请求（您也可以在 DNS 服务器本身上运行类似的测试）。如果我们的 Unbound/BIND DNS 集群的 IP 为`192.168.1.7`，则应能够从网络中的任何其他计算机获得`dig @192.168.1.7 www.packtpub.com`和`dig @192.168.1.7 client1.centos7.home`的正确答案。

如果您需要解决服务问题或需要监控新安装的 Unbound/BIND DNS 服务器的 DNS 查询，您可以配置日志记录参数。对于 BIND，在主配置文件`named.conf`中，您可以设置日志输出的详细程度（或日志级别）。这个参数称为`severity`，可以在`logging`指令中找到。它已经设置为`dynamic`，这意味着可以输出尽可能多的日志消息。然后，您可以使用`tail -f /var/named/data/named.run`来读取当前日志。对于 Unbound，您可以在其主配置文件`unbound.conf`中使用`verbosity`指令设置详细程度级别，该级别默认为最低的`1`，但可以增加到`5`。要了解更多关于不同级别的信息，请使用`man unbound.conf`。使用`journald`读取 Unbound 日志信息，使用命令`journalctl -f -u unbound.service`（按下*Ctrl*+*c*键退出命令）。

我们不仅可以记录系统和服务的日志信息，还可以启用查询日志。对于 Unbound，只需使用`verbosity`为`3`或以上来记录查询信息。对于 BIND，为了激活查询日志（查询输出将发送到日志文件`named.run`），使用命令`rndc querylog on`（要关闭它，使用`rndc querylog off`）。请记住，在配置生产系统上的 DNS 服务器时，应关闭任何过多的日志信息，例如查询日志，因为它可能会降低您的服务性能。您还可以安装其他第三方工具，如`dnstop`（来自`EPEL`存储库）来监控您的 DNS 活动。

# 填充域

在本教程中，我们将向您展示如何快速向权威的 BIND 服务器添加新的本地域记录条目，这些条目目前对您的名称服务器来说是未知的。

## 准备工作

要完成本教程，您需要一个正常运行的 CentOS 7 操作系统和一个基于控制台的文本编辑器。预计 Unbound 和 BIND 都已经安装并正在运行，并且您已经阅读并应用了本章中的区域教程，并为您的私有网络的主机名解析准备了所需的正向和反向区域文件。

## 如何操作...

如果您想向 DNS 服务器添加新的域名到 IP 地址映射，例如为本地网络中的新主机或未知主机，您有两种选择。由于我们已经为本地网络创建了区域文件，因此我们可以简单地为每个新子域在我们的基本域名中添加新的`A`（和/或`CNAME`）以及相应的`PTR`条目到我们的正向和反向区域文件配置中，使用我们选择的文本编辑器。或者，我们可以使用`nsupdate`命令行工具以交互方式添加这些记录，而无需重新启动 DNS 服务器。在本节中，我们将向您展示如何准备和使用`nsupdate`工具。在我们的示例中，我们将为 IP 地址为`192.168.1.14`的计算机添加一个新的子域`client4.centos7.home`到我们的 DNS 服务器的区域：

1.  以 root 身份登录运行 BIND 服务的服务器。现在首先我们需要激活`named`，以便允许其通过 SELinux 写入区域文件：

    ```
    setsebool -P named_write_master_zones 1

    ```

1.  接下来，我们需要解决一些与命名配置目录的权限问题，否则`nsupdate`无法稍后更新我们的区域文件：

    ```
    chown :named /var/named -R; chmod 775 /var/named -R

    ```

1.  由于我们的 BIND 服务器运行在端口`8053`上，请键入以下命令以在本地启动交互式`nsupdate`会话：

    ```
    nsupdate -p 8053 -d -l

    ```

1.  在提示符(`>`)下，首先通过键入以下内容连接到本地 DNS 服务器（按*Return*键完成命令）：

    ```
     local 127.0.0.1

    ```

1.  要向 DNS 服务器添加新的正向域名到 IP 映射，请键入以下内容：

    ```
    update add client4.centos7.home. 115200 A 192.168.1.14
    send

    ```

1.  现在使用以下命令添加反向关系：

    ```
    update add 14.1.168.192.in-addr.arpa. 115200 PTR client4.centos7.home.
    send

    ```

    如果更新命令的输出包含消息`NOERROR`，请按*Ctrl*+*c*键退出交互式`nsupdate`会话。

1.  最后，检查新区域条目的域名和 IP 解析是否正常工作（这也应该通过 Unbound 服务器远程工作）：

    ```
    dig -p 8053 @127.0.0.1  client4.centos7.home.
    nslookup -port=8053 192.168.1.14 127.0.0.1

    ```

## 它是如何工作的…

在这个相当简单的教程中，我们向您展示了如何使用`nsupdate`工具在运行时动态添加新的域名解析记录，而无需重新启动您的 BIND DNS 服务器。

那么，我们从这次经历中学到了什么？

在本教程中，我们向您介绍了`nsupdate`命令行工具，该工具可以在不编辑区域文件或重新启动服务器的情况下对正在运行的 BIND DNS 数据库进行更改。如果您已经在 DNS 服务器上配置了区域文件，那么这是对 DNS 服务器进行更改的首选方式。它有几个选项，例如，您可以连接到远程 DNS 服务器，但由于简单性和安全原因，我们将仅使用和允许最简单的形式，并且仅将`nsupdate`连接到我们的本地 BIND 服务器（要使用`nsupdate`远程连接到 BIND 服务器，您需要进行更多配置，例如生成安全密钥对，打开防火墙等）。

在允许`named`写入其自己的区域文件（否则会被 SELinux 禁止）并修复默认 named 配置目录的一些权限问题后，我们使用`-l`（本地连接）和`-p 8053`（连接到 BIND DNS 服务器端口`8053`）启动了`nsupdate`程序。`-d`为我们提供了调试输出，这对于解决问题非常有用。然后，我们被一个交互式 shell 提示，在那里我们可以运行 BIND 特定的`update`命令。首先，我们设置`local` `127.0.0.1`，这连接到我们的本地服务器，然后我们使用`update add`命令向正在运行的 DNS 服务器添加一个新的正向`A`记录。语法类似于在区域文件中定义记录。在这里，我们使用以下行添加一个新的`A`记录，TTL 为三天（115200 秒），域名为`client4.centos7.home`，解析到 IP 地址`192.168.1.14`。下一行用于为我们的新域配置一些反向解析规则，并将域名作为`PTR`条目添加到我们的反向区域中。在这里，需要注意的是，您需要以下列方式定义反向`update add`规则的域部分：`<规则的主机名>.<反向 C 类>.in-addr.arpa`。为了最终执行我们的命令并将它们永久保存在 DNS 服务器的数据库中，而不需要重新启动服务器，我们使用`send`命令分别对反向和正向命令，因为它们针对不同的区域。最后，我们测试了新添加到 DNS 服务器的区域文件中的条目是否正常工作，通过查询 BIND 服务器。

# 构建辅助（从属）DNS 服务器

为了确保网络的高可用性，在您的环境中运行多个 DNS 服务器以应对任何服务器故障是有益的。如果您运行的是公共 DNS 服务器，这一点尤其重要，因为持续访问服务至关重要，而且同时拥有五个或更多 DNS 服务器并不罕见。由于配置和管理多个 DNS 服务器可能耗时，BIND DNS 服务器使用节点之间传输区域文件的功能，以便每个 DNS 服务器都具有相同的域解析和配置信息。为了实现这一点，我们需要定义一个主 DNS 服务器和一个或多个辅助或从属 DNS 服务器。然后，我们只需要在主服务器上调整一次区域文件，它就会将当前版本传输到我们所有的辅助服务器，保持一切一致和最新。对于客户端来说，连接到哪个 DNS 服务器将没有区别。

## 准备就绪

要完成此配方，您将至少需要两个在同一网络中可以相互看到和 ping 通的 CentOS 7 服务器。需要互联网连接以下载并在我们想要包含在我们的 DNS 服务器*农场*中的所有计算机上安装 BIND 服务器软件。在本示例中，我们有两个服务器，`192.168.1.7`，它已经安装并配置为 BIND 服务器，以及`192.168.1.15`，它将是子网`192.168.1.0/24`内的第二个 BIND 服务器。您还应该阅读并应用本章中的区域文件配方，并创建正向和反向区域文件，因为这是我们想要在 DNS 服务器之间传输的内容。

## 如何操作...

我们通过在想要包含在我们的 BIND DNS 服务器集群中的每个 CentOS 7 计算机上安装 BIND 来开始这个配方。为此，请遵循配方*设置权威 DNS 服务器*为所有剩余系统。在我们开始之前，我们需要定义哪个服务器将是我们的主 DNS 服务器。为了简化我们的示例，我们将选择 IP 地址为`192.168.1.7`的服务器。现在让我们让我们的 DNS 服务器节点了解它们的角色。

### 对主 DNS 服务器进行的更改

1.  让我们以 root 身份登录到主服务器并打开其主配置：

    ```
    vi /etc/named.conf

    ```

1.  现在我们定义哪些辅助 DNS 服务器将被允许接收区域文件，在新的一行中，在选项花括号之间写下以下命令（我们只有一个辅助 DNS 服务器，其 IP 地址为`192.168.1.15`，请根据需要更改）：

    ```
    allow-transfer { 192.168.1.15; };
    notify yes;
    ```

1.  此外，我们还必须允许其他名称服务器连接到我们的主名称服务器。为此，您需要将`listen-on`指令更改为包括 DNS 服务器的主网络接口（在我们的示例中为`192.168.1.7`，因此请相应更改）：

    ```
    listen-on port 8053 { 127.0.0.1;192.168.1.7; };

    ```

1.  保存并关闭文件。现在在您的服务器防火墙中打开新端口`8053`（或者为其创建一个 firewalld 服务，参见第六章，*提供安全性*）：

    ```
    firewall-cmd --permanent --zone=public --add-port=8053/tcp --add-port=8053/udp;firewall-cmd --reload

    ```

1.  保存并关闭文件。接下来，更新我们之前创建的区域文件，以包括系统中所有新名称服务器的 IP 地址。更改正向和反向区域文件，`/var/named/centos7.home.db`和`/var/named/db.1.168.192`，以包括我们的新辅助 DNS 服务器。在正向区域文件中，添加以下行（您也可以使用`nsupdate`程序来执行此操作）到适当的节中：

    ```
    NS  ns2.centos7.home.
    ns2  A   192.168.1.15

    ```

1.  在反向区域文件中，添加到适当的节中：

    ```
    NS  ns2.centos7.home.
    15 PTR ns2.centos7.home.

    ```

1.  最后，重启 BIND 并重新检查配置文件：

    ```
    named-checkconf && systemctl restart named

    ```

### 对辅助 DNS 服务器进行的更改

为了简化和演示，只需在您想要用作 BIND 从属服务器的任何服务器上安装`named`（我们只在这里展示重要的配置）：

1.  以 root 身份登录到新服务器，安装 BIND，并打开其主配置：

    ```
    yum install bind; vi /etc/named.conf

    ```

1.  现在找到行`include /etc/named.rfc1912.zones`。紧跟在这行之后，为你的工作创建空间，并添加以下区域（适当地替换区域和文件名）：

    ```
     zone "centos7.home" IN {
     type slave;
     masters port 8053 { 192.168.1.7; };
     file "/var/named/centos7.home.db";
    };
     zone "1.168.192.in-addr.arpa" IN {
     type slave;
     masters port 8053{ 192.168.1.7; };
     file "/var/named/db.1.168.192.db";
     };

    ```

1.  保存并关闭文件。然后修复一些不正确的 BIND 文件夹权限，并启用`named`写入其区域文件目录，然后重新启动 BIND：

    ```
    chown :named /var/named -R; chmod 775 /var/named -R
    setsebool -P named_write_master_zones 1
    named-checkconf && systemctl restart named

    ```

1.  现在使用以下命令启动新的区域传输：

    ```
    rndc refresh centos7.home.

    ```

1.  等待一段时间后，为了测试辅助 DNS 服务器是否按预期工作，检查主区域文件是否已被传输：

    ```
    ls /var/named/*.db

    ```

1.  最后，我们现在可以测试我们是否也可以在辅助 DNS 服务器上查询我们的本地域：

    ```
    dig @127.0.0.1 client2.centos7.home.

    ```

## 它是如何工作的...

在本配方中，我们向您展示了如何在您的网络中设置辅助 BIND 服务器，这有助于提高您的 DNS 服务器系统的稳定性和可用性。

那么我们从这次经历中学到了什么？

我们首先决定哪些服务器应作为主 DNS 服务器，哪些应作为从 DNS 服务器。然后在主服务器上打开 BIND 主配置文件，并引入两行代码，将我们的服务器配置为 DNS 集群的头部。`allow-transfer`指令定义了我们希望向哪些客户端传输更新的区域文件，而`notify yes`指令启用了当区域文件发生任何更改时的自动传输。如果你有多个辅助 BIND DNS 服务器，可以在`allow-transfer`指令中添加多个 IP 地址，用分号隔开。然后，我们打开在本章前一个配方中创建的区域文件，并引入新的一行`IN NS <IP 地址>`，这定义了我们需要的辅助 DNS 服务器的 IP 地址，以便在我们的系统中的每个 DNS 节点上都能意识到。如果我们有多个服务器，那么我们就引入多个`IN NS`行。最后，我们引入了一个小注释，以便在辅助服务器上轻松检查区域文件传输是否成功。

之后，我们配置了我们的从 DNS 服务器。在这里，我们引入了与主服务器上的 BIND 配置相同的区域文件定义，不同的是我们使用了类型`slave`而不是 master 来表示我们是辅助 DNS 服务器，并且将从主节点获取区域文件的副本，通过使用`masters`指令定义主 DNS 服务器的 IP 地址（请不要忘记，在我们的例子中，我们的主 BIND 监听在非默认端口`8053`上）。

由于我们没有在从 DNS 服务器上自己创建或复制区域文件，因此在重新启动 BIND 服务后，使用`ls`命令很容易检查区域文件传输是否成功。最后，我们通过运行测试查询使用`dig`或`nslookup`来验证传输的区域文件内容，看看我们是否可以在辅助 DNS 服务器上解析相同的本地主机名。记住，如果你后来对你的主区域文件进行了更改，你必须增加它们的`serial`号，以便这些更改被传输到你所有的从服务器。


# 第十章：使用数据库

在本章中，我们将涵盖：

+   安装 MariaDB 数据库服务器

+   管理 MariaDB 数据库

+   允许对 MariaDB 服务器的远程访问

+   安装 PostgreSQL 服务器和管理数据库

+   配置对 PostgreSQL 的远程访问

+   安装 phpMyAdmin 和 phpPgAdmin

# 引言

本章是一系列配方的集合，提供了在 Linux 世界中实施和维护两个最流行的数据库管理系统所需的步骤。数据的需求无处不在，对于几乎任何服务器来说，它都是*必须提供的服务*，本章提供了在任何环境中部署这些数据库系统所需的起点。

# 安装 MariaDB 数据库服务器

支持超过 70 种排序规则，30 多种字符集，多种存储引擎，以及在虚拟化环境中的部署，MySQL 是一个关键任务的数据库服务器，被全球的生产服务器所使用。它能够托管大量的独立数据库，并能为你的整个网络提供各种角色的支持。MySQL 服务器已经成为**万维网** (**WWW**) 的代名词，被桌面软件使用，扩展本地服务，并且是全球最受欢迎的关系数据库系统之一。本配方的目的是向你展示如何下载、安装和锁定 MariaDB，这是 CentOS 7 中 MySQL 的默认实现。MariaDB 是开源的，与 MySQL 完全兼容，并增加了几个新功能；例如，非阻塞客户端 API 库，具有更好性能的新存储引擎，增强的服务器状态变量，以及复制。

## 准备工作

为了完成这个配方，你需要一个具有 root 权限的 CentOS 7 操作系统的工作安装，一个你选择的基于控制台的文本编辑器，以及一个互联网连接以下载额外的软件包。预计你的服务器将使用静态 IP 地址。

## 如何操作...

由于 MariaDB **数据库管理系统** (**DBMS**) 在 CentOS 7 上默认未安装，我们将从这个配方开始安装所需的软件包。

1.  首先，以 root 身份登录并输入以下命令来安装所需的软件包：

    ```
    yum install mariadb-server mariadb

    ```

1.  完成后，确保服务在启动时启动，然后再启动服务：

    ```
    systemctl enable mariadb.service && systemctl start mariadb.service

    ```

1.  最后，使用以下命令开始安全安装过程：

    ```
    mysql_secure_installation

    ```

1.  当你首次运行前面的命令时，系统会要求你提供一个密码，但由于此值尚未设置，请按*Enter*键表示该值（空白）无。

1.  现在，你将被问到一系列简单的问题，这些问题将帮助你在加固 MariaDB DBMS 系统的过程中。除非你已经是 MariaDB 专家并且确实需要某个特定功能，否则选择 Yes (`Y`) 回答每个问题以获得最大安全性是一个好建议。

1.  最后，测试你是否可以使用 MariaDB 命令行客户端`mysql`本地连接并登录到 MariaDB 服务。如果以下命令输出了 MariaDB 服务器已知的所有用户名及其关联的主机，则测试通过（在提示时输入你在上一步设置的管理员 root 密码）：

    ```
    echo "select User,Host from user" | mysql -u root -p mysql

    ```

## 它是如何运作的...

MariaDB 是一个快速、高效、多线程且强大的 SQL 数据库服务器。它支持多个用户，并提供多种存储引擎的访问。通过遵循几个简短的步骤，你现在知道如何安装、保护并登录到你的 MariaDB 服务器。

那么，我们从这次经历中学到了什么？

我们首先安装了 MariaDB 服务器所需的软件包（`mariadb-server`），以及用于控制和查询服务器的客户端 Shell 接口（`mariadb`）。完成这一步后，我们确保 MariaDB 守护进程（`mariadb.service`）会在启动过程中启动，然后我们才真正启动它。此时，我们有了一个可用的安装，但为了确保我们的安装是安全的，我们随后调用了安全安装脚本，引导我们通过几个简单的步骤来加强我们的基本安装。由于基本安装过程不允许我们为 root 用户设置默认密码，我们在这里作为脚本的第一步进行了设置，这样我们就可以确保没有人可以在没有所需授权的情况下访问 MariaDB 的 root 用户账户。然后我们发现，典型的 MariaDB 安装保留了一个匿名用户。这样做的目的是允许任何人在没有有效用户账户的情况下登录到我们的数据库服务器。它通常仅用于测试目的，除非你处于需要此功能的特殊情况，否则总是建议删除此功能。接下来，为了确保 root 用户无法访问我们的 MariaDB 服务器安装，我们选择禁止远程 root 访问，然后删除测试数据库并重新加载权限表。最后，我们运行了一个小测试，看看我们是否可以使用 root 用户连接到数据库，并从`user`表（这是标准`mysql`数据库的一部分）查询一些数据。

完成这些步骤后，我们了解到安装和保护 MariaDB 服务器的过程非常简单。当然，总有一些事情可以做，以使安装更有用，但这个食谱的目的是向你展示，安装新数据库系统最重要的部分是使其安全。记住，运行`mysql_secure_installation`对于所有 MariaDB 服务器都是推荐的，无论你是在构建开发服务器还是用于生产环境的服务器，这都是明智的。作为服务器管理员，安全应始终是你的首要任务。

# 管理 MariaDB 数据库

在本配方中，我们将学习如何为 MariaDB 服务器创建一个新的数据库和数据库用户。MariaDB 可以与各种图形工具（例如，免费的 MySQL Workbench）结合使用，但在您只需要创建一个数据库、提供关联用户并分配正确权限的情况下，通常使用命令行执行此任务非常有用。被称为 MariaDB shell 的这个简单的交互式基于文本的命令行工具支持完整的 SQL 命令范围，并提供对数据库服务器的本地和远程访问。该 shell 为您提供了对数据库服务器的完全控制，因此它代表了您开始 MariaDB 工作的完美工具。

## 准备工作

要完成本配方，您需要一个正常运行的 CentOS 7 操作系统。预计您的服务器上已经安装并运行了 MariaDB 服务器。

## 如何做到这一点...

MariaDB 命令行工具支持在批处理模式（从文件或标准输入读取）和交互模式（输入语句并等待结果）中执行命令。在本配方中，我们将使用后者。

1.  首先，使用您喜欢的任何系统用户登录到您的 CentOS 7 服务器，然后输入以下命令，以便使用名为`root`的主要 MariaDB 管理用户通过 MariaDB shell 访问 MariaDB 服务器（使用在前一个配方中创建的密码）：

    ```
    mysql -u root -p

    ```

1.  成功登录后，您将看到 MariaDB 命令行界面。此功能由 MariaDB shell 提示符表示：

    ```
    MariaDB [(none)]>

    ```

1.  在第一步中，我们将创建一个新的数据库。为此，只需通过将以下命令中的`<database-name>`替换为适当的值来定制命令：

    ```
    CREATE DATABASE <database-name> CHARACTER SET utf8 COLLATE utf8_general_ci;

    ```

    ### 注意

    如果您是第一次接触 MariaDB shell，请记住在每行末尾加上分号（`;`），并在输入每个命令后按*Enter*键。

1.  创建了我们的数据库后，我们现在将创建一个 MariaDB 用户。每个用户将由一个用户名和一个与操作系统用户完全独立的密码组成。出于安全考虑，我们将确保数据库的访问仅限于本地主机。要继续，只需通过更改以下命令中的`<username>`、`<password>`和`<database-name>`值来定制命令以反映您的需求：

    ```
    GRANT ALL ON <database-name>.* TO '<username>'@'localhost' IDENTIFIED BY '<password>' WITH GRANT OPTION;

    ```

1.  接下来，让 MariaDB DBMS 知道您的新用户：

    ```
    FLUSH PRIVILEGES;

    ```

1.  现在，只需输入以下命令即可退出 MariaDB shell：

    ```
    EXIT;

    ```

1.  最后，您可以通过以下方式从命令行访问 MariaDB shell 来测试新`<username>`的可访问性：

    ```
    mysql -u <username> -p

    ```

1.  现在回到 MariaDB shell（`MariaDB [(none)]>`），输入以下命令：

    ```
    SHOW DATABASES;
    EXIT;

    ```

## 它是如何工作的...

在本配方过程中，您不仅被展示了如何创建数据库，还展示了如何创建数据库用户。

那么，我们从这次经历中学到了什么？

我们通过使用`mysql`命令以 root 用户身份访问 MariaDB shell 开始了这个操作步骤。这样，我们就可以使用简单的 SQL 函数`CREATE DATABASE`创建一个数据库，并为`<database-name>`字段提供一个自定义名称。我们还指定了`utf8`作为新数据库的字符集，以及`utf8_general_ci`作为排序规则。字符集是数据库中字符的编码方式，而排序规则是一组比较字符集中的字符的规则。由于历史原因，并为了保持 MariaDB 与旧版本服务器的向后兼容性，默认字符集是`latin1`和`latin1_swedish_ci`，但对于任何现代数据库，您应该始终倾向于使用`utf-8`，因为它是国际字符集（非英语字母）最标准和兼容的编码。但是，可以通过使用以下命令来修改此命令，以检查数据库名称是否已在使用中：`CREATE DATABASE IF NOT EXISTS <database-name>`。这样，您就可以使用以下命令删除或移除数据库：

```
DROP DATABASE IF EXISTS <database-name>;

```

完成这些操作后，只需通过运行我们的`GRANT ALL`命令为新数据库用户添加适当的权限。在这里，我们为本地主机上的`<username>`提供了通过定义的`<password>`获得完全权限。由于选择了特定的`<database-name>`，因此这种级别的权限将限于该特定数据库，并且使用`<database-name>.*`允许我们将这些规则指定给该数据库中的所有表（使用星号符号）。为了向选定的用户提供特定权限，一般语法是：

```
GRANT [type of permission] ON <database name>.<table name> TO '<username>'@'<hostname>';
```

出于安全考虑，在本操作步骤中，我们将`<hostname>`限制为本地主机，但如果您想授予远程用户权限，则需要更改此值（稍后会看到）。在我们的示例中，我们将`[type of permission]`设置为`ALL`，但您始终可以通过提供单个或以逗号分隔的权限类型列表来决定最小化特权，如下所示：

```
GRANT SELECT, INSERT, DELETE ON <database name>.* TO '<username>'@'localhost';
```

使用前面的技术，以下是可以使用的权限的总结：

+   `ALL`：允许`<username>`值拥有所有可用的权限类型

+   `CREATE`：允许`<username>`值创建新表或数据库

+   `DROP`：允许`<username>`值删除表或数据库

+   `DELETE`：允许`<username>`值删除表行

+   `INSERT`：允许`<username>`值插入表行

+   `SELECT`：允许`<username>`值从表中读取

+   `UPDATE`：允许`<username>`值更新表行

然而，一旦授予了特权，操作步骤就会向您展示我们必须`FLUSH`系统，以便使我们的新设置对系统本身可用。需要注意的是，MariaDB shell 中的所有命令都应以分号（`;`）结尾。完成任务后，我们只需使用`EXIT;`语句退出控制台。

MariaDB 是一个出色的数据库系统，但像所有服务一样，它可能会被滥用。因此，始终保持警惕，并且通过考虑之前的建议，你可以确信你的 MariaDB 安装将保持安全和稳定。

## 还有更多...

创建受限用户是提供数据库访问的一种方式，但如果你的开发团队需要持续访问开发服务器，你可能希望考虑提供一个拥有超级用户权限的通用用户。要实现这一点，只需使用管理员用户 root 登录到 MariaDB shell，然后按照以下方式创建一个新用户：

```
GRANT ALL ON *.* TO '<username>'@'localhost' IDENTIFIED BY '<password>' WITH GRANT OPTION;

```

通过这样做，你将使`<username>`能够添加、删除和管理整个 MariaDB 服务器上的数据库（`*.*`中的星号告诉 MariaDB 将权限应用于数据库服务器上找到的所有数据库及其关联表），但由于管理功能的范围，这个新用户账户将所有活动限制在本地主机。所以简单来说，如果你想为`<username>`提供对任何数据库或任何表的访问权限，始终使用星号（`*`）代替数据库名或表名。最后，每次更新或更改用户权限时，请务必在使用`EXIT;`命令退出 MariaDB shell 之前使用`FLUSH PRIVILEGES`命令。

### 审查和撤销权限或删除用户

除非用户账户正在使用，否则保留活动状态并不是一个好主意，因此你首先在 MariaDB shell 中（使用管理员用户 root 登录）考虑的是通过输入以下内容来审查它们当前的状态：

```
SELECT HOST,USER FROM mysql.user WHERE USER='<username>';
```

完成此操作后，如果你打算`REVOKE`权限或从此处列出的用户中删除用户，你可以使用`DROP`命令来执行此操作。首先，你应该审查感兴趣的用户拥有的权限，通过运行：

```
SHOW GRANTS FOR '<username>'@'localhost';
```

你现在有两种选择，首先是撤销用户的权限，如下所示：

```
REVOKE ALL PRIVILEGES, GRANT OPTION FROM '<username>'@'localhost';
```

然后你可以选择重新分配权限，使用主配方中提供的公式，或者你可以决定通过输入以下内容来删除用户：

```
DROP USER '<username>'@'localhost';
```

最后，使用`FLUSH PRIVILEGES;`以通常的方式更新所有你的权限，然后在使用`EXIT;`命令退出 shell 之前。

# 允许远程访问 MariaDB 服务器

除非你正在运行 MariaDB 数据库服务器来驱动同一服务器硬件上的本地 Web 应用程序，否则如果禁止远程访问数据库服务器，大多数工作环境将变得毫无用处。在许多 IT 环境中，你会发现高可用性、集中式的专用数据库服务器在硬件上进行了优化（例如，大量的 RAM），并托管多个数据库，允许从外部到服务器的数百个并行连接。在本配方中，我们将向你展示如何使远程连接到服务器成为可能。

## 准备就绪

要完成此配方，您需要一个具有 root 权限的 CentOS 7 操作系统的有效安装。预计 MariaDB 服务器已经安装并运行，并且您已经阅读并应用了*管理 MariaDB 数据库*配方，以了解权限以及如何测试（本地）数据库连接。

## 如何做到这一点...

在我们的示例中，我们希望从同一网络中的客户端计算机（IP 地址为`192.168.1.33`）访问 IP 地址为`192.168.1.12`的 MariaDB 数据库服务器。请根据您的需求适当更改：

1.  首先，以 root 身份登录到您的 MariaDB 数据库服务器，并为传入的 MariaDB 连接打开防火墙：

    ```
    firewall-cmd --permanent --add-service=mysql && firewall-cmd --reload

    ```

1.  之后，我们需要创建一个可以远程连接到我们的 MariaDB 服务器的用户账户（因为我们已经阻止`root`这样做，以增强安全性），使用 MariaDB 命令行界面`mysql`以用户`root`登录数据库服务器，并输入以下 MariaDB 语句（将`XXXX`替换为您选择的密码，也可以根据需要调整用户名和客户端的远程 IP 地址——在我们的例子中，客户端的 IP 地址是`192.168.1.33`）：

    ```
    GRANT SELECT ON mysql.user TO 'johndoe'@'192.168.1.33' IDENTIFIED BY 'XXXX';
    FLUSH PRIVILEGES;EXIT;

    ```

1.  现在我们可以从我们网络中 IP 地址为`192.168.1.33`的客户端计算机测试连接。这台计算机需要安装 MariaDB shell（在 CentOS 7 客户端上，安装软件包`mariadb`），并且需要能够 ping 通运行 MariaDB 服务的服務器（在我们的示例中，IP 为`192.168.1.12`）。您可以通过使用以下命令测试与服务器的连接（成功的话，这将打印出`mysql`用户表的内容）：

    ```
    echo "select user from mysql.user" | mysql -u johndoe -p mysql -h 192.168.1.12

    ```

## 工作原理...

我们的旅程始于通过使用 firewalld 预定义的 MariaDB 服务打开标准的 MariaDB 防火墙端口 3306，该服务在 CentOS 7 上默认是禁用的。之后，我们配置了允许访问数据库服务器的 IP 地址，这是在数据库级别使用 MariaDB shell 完成的。在我们的示例中，我们使用`GRANT SELECT`命令允许用户`johndoe`在客户端 IP 地址`192.168.1.33`和密码`'XXXX'`访问名为`mysql`的数据库和用户表，仅进行`SELECT`查询。请记住，在这里您也可以在`<hostname>`字段中使用通配符`%`（表示任何字符）。例如，为了定义 C 类网络中的任何可能的主机名组合，您可以使用`%`符号，如下所示`192.168.1.%`。授予对`mysql.user`数据库和表的访问权限仅用于测试目的，您应该在完成测试后使用以下命令从该访问权限中删除用户`johndoe`：`REVOKE ALL PRIVILEGES`, `GRANT OPTION FROM 'johndoe'@'192.168.1.33';`。如果您愿意，也可以删除用户`DROP USER 'johndoe'@'192.168.1.33';`，因为我们不再需要它了。

# 安装 PostgreSQL 服务器和管理数据库

在本食谱中，我们不仅将学习如何在服务器上安装 PostgreSQL DBMS，还将学习如何添加新用户并创建我们的第一个数据库。PostgreSQL 被认为是世界上最先进的开源数据库系统。它以稳定、可靠和精心设计的系统而闻名，完全能够支持高事务和关键任务应用程序。PostgreSQL 是 Ingres 数据库的后代。它由来自世界各地的大量贡献者社区驱动和维护。它可能不如 MariaDB 灵活或普及，但由于 PostgreSQL 是一个非常安全的数据库系统，在数据完整性方面表现出色，因此本食谱的目的是向您展示如何开始探索这个被遗忘的朋友。

## 准备工作

为了完成本食谱，您需要一个具有 root 权限的 CentOS 7 操作系统的有效安装，您选择的基于控制台的文本编辑器，以及互联网连接以便下载额外的软件包。预计您的服务器将使用静态 IP 地址。

## 如何操作...

PostgreSQL（也称为 Postgres）是一个对象关系数据库管理系统。它支持大部分 SQL 标准，并且可以通过服务器管理员以多种方式进行扩展。然而，为了开始，我们必须首先安装必要的软件包：

1.  首先以 root 身份登录您的服务器，然后输入：

    ```
    yum install postgresql postgresql-server

    ```

1.  安装数据库系统后，我们现在必须通过输入以下命令在启动时启用数据库服务器：

    ```
    systemctl enable postgresql

    ```

1.  完成上述步骤后，按照以下方式初始化数据库系统：

    ```
    postgresql-setup initdb

    ```

1.  现在通过启动数据库服务器来完成此过程：

    ```
    systemctl start postgresql

    ```

1.  现在为您的`postgres`管理员设置一个新的初始密码。由于默认的`postgres`用户目前使用的是对等认证，我们需要以`postgres`用户身份执行任何与 Postgres 相关的命令：

    ```
    su - postgres -c "psql --command '\password postgres'"

    ```

1.  为了消除`postgres`用户必须在系统用户基础上登录才能执行如`psql`等与 Postgres 相关的命令的要求，并允许使用数据库用户账户登录，我们需要将`localhost`的认证方法从`peer`更改为`md5`。您可以手动执行此操作，或者使用`sed`工具，如下所示，首先备份文件：

    ```
    cp /var/lib/pgsql/data/pg_hba.conf /var/lib/pgsql/data/pg_hba.conf.BAK
    sed -i 's/^\(local.*\)peer$/\1md5/g' /var/lib/pgsql/data/pg_hba.conf

    ```

1.  接下来，我们必须重启`postgresql`服务以应用我们的更改：

    ```
    systemctl restart postgresql

    ```

1.  现在，您将能够使用用户`postgres`登录到您的 Postgres 服务器，而无需先登录`postgres` Linux 系统用户：

    ```
    psql -U postgres

    ```

1.  要退出 shell（`postgres=#`），请输入以下命令（然后按*回车*键）：

    ```
    \q

    ```

1.  现在，我们将发出一个 shell 命令来创建一个新的数据库用户，通过将 `<username>` 替换为适合您自己需求的相应用户名（在提示时输入新用户的密码，重复它，然后输入管理员用户 `postgres` 的密码以应用这些设置）：

    ```
    createuser -U postgres -P <username>

    ```

1.  现在，也在 shell 中创建您的第一个数据库，并将其分配给我们新用户，通过将 `<database-name>` 和 `<username>` 的值替换为更适合您需求的值（输入 `postgres` 用户的密码）：

    ```
    createdb -U postgres <database-name> -O <username>

    ```

1.  最后，通过打印所有数据库名称来测试您是否可以使用新用户访问 Postgres 服务器：

    ```
    psql -U <username> -l

    ```

## 它是如何工作的...

PostgreSQL 是一种对象关系型数据库管理系统，它适用于所有 CentOS 服务器。虽然 Postgres 可能不如 MariaDB 常见，但其架构和丰富的功能确实使其成为许多关注数据完整性的公司的吸引解决方案。

那么我们从这次经历中学到了什么？

我们从这个配方开始，通过使用 `yum` 安装必要的服务器和客户端 `rpm` 包。完成此操作后，我们在启动时使 Postgres 系统可用，然后使用 `postgresql-setup initdb` 命令初始化数据库系统。我们通过启动数据库服务完成了这个过程。在下一阶段，我们被要求为 Postgres 管理员用户设置密码以加强系统安全性。默认情况下，`postgresql` 包创建一个名为 `postgres` 的新 Linux 系统用户（也用作访问我们的 Postgres DBMS 的管理员 Postgres 用户帐户），通过使用 `su - postgres - c`，我们能够以 `postgres` 用户身份执行 `psql` 命令，这在安装时是强制性的（这称为对等身份验证）。

设置管理员密码后，为了更像 MariaDB shell 类型的登录过程，其中每个数据库用户（包括管理员 `postgres` 用户）都可以使用数据库 `psql` 客户端的用户 `-U` 参数登录，我们将这种 `peer` 身份验证更改为 `md5` 数据库密码身份验证，用于本地主机在 `pg_hba.conf` 文件中（请参阅下一个配方）。重新启动服务后，我们然后使用 Postgres 的 `createuser` 和 `createdb` 命令行工具创建一个新的 Postgres 用户并将其连接到新数据库（我们需要为 `postgres` 用户提供 `-U` 参数，因为只有他有权限）。最后，我们向您展示了如何使用新用户使用 `-l` 标志（列出所有可用数据库）测试与数据库的连接。此外，您可以使用 `-d` 参数使用以下语法连接到特定数据库：`psql -d <database-name> -U <username>`。

## 还有更多...

除了使用`createuser`或`createdb`Postgres 命令行工具（正如我们在这个示例中向你展示的那样）来创建数据库和用户之外，你还可以使用 Postgres shell 来完成相同的操作。实际上，这些命令行工具实际上只是 Postgres shell 命令的包装器，两者之间没有实质性的区别。`psql`是用于在 Postgres 服务器上输入 SQL 查询或其他命令的主要命令行客户端工具，类似于本章中另一个示例中向你展示的 MariaDB shell。在这里，我们将使用名为`template1`的模板启动`psql`，这是用于开始构建数据库的样板（或默认模板）。登录后（`psql -U postgres template1`），输入管理员密码，你应该会看到交互式 Postgres 提示符（`template1=#`）。现在，要在`psql` shell 中创建一个新用户，请输入：

```
CREATE USER <username> WITH PASSWORD '<password>';

```

要创建数据库，请输入：

```
CREATE DATABASE <database-name>;

```

将最近创建的数据库的所有权限授予新用户的选项是：

```
GRANT ALL ON DATABASE <database-name> to <username>;

```

要退出交互式 shell，请使用：`\q`，然后按*回车*键。

完成这个示例后，你可以说你不仅知道如何安装 PostgreSQL，而且这个过程还突显了这个数据库系统与 MariaDB 之间的一些简单的架构差异。

# 配置对 PostgreSQL 的远程访问

在这个示例中，我们将学习如何配置对默认情况下禁用的 Postgres 服务器的远程访问。Postgres 使用一种称为基于主机的身份验证的方法，这个示例的目的是向你介绍其概念，以便为你提供运行安全可靠的数据库服务器所需的访问权限。

## 准备工作

要完成这个示例，你需要一个具有 root 权限的 CentOS 7 操作系统的有效安装，以及你选择的文本编辑器。预计 PostgreSQL 已经安装并正在运行。

## 如何操作...

在前面的示例中，我们已经使用`sed`修改了基于主机的身份验证配置文件`pg_hba.conf`，以管理我们的 Postgres 客户端身份验证，从对等模式更改为`md5`。在这里，我们将对其进行更改，以管理对我们的 Postgres 服务器的远程访问。

1.  首先，以 root 身份登录，并打开防火墙以允许任何传入的 PostgreSQL 连接到服务器：

    ```
    firewall-cmd --permanent --add-service=postgresql;firewall-cmd --reload

    ```

1.  现在，在你的首选文本编辑器中打开基于主机的身份验证配置文件，方法是输入：

    ```
    vi /var/lib/pgsql/data/pg_hba.conf

    ```

1.  滚动到文件末尾，并添加以下行，使这些行读作如下内容（将`XXX.XXX.XXX.XXX/XX`值替换为你想要授予访问权限的网络地址。例如，如果你的服务器 IP 地址是`192.168.1.12`，那么网络地址将是`192.168.1.0/24`）：

    ```
    host    all          all         XXX.XXX.XXX.XXX/XX    md5

    ```

1.  完成后，只需以通常的方式保存并关闭文件，然后通过输入打开主 Postgres 配置文件：

    ```
    vi /var/lib/pgsql/data/postgresql.conf

    ```

1.  将以下行添加到文件末尾：

    ```
    listen_addresses = '*'
    port = 5432

    ```

1.  完成后，以通常的方式保存文件，然后通过输入以下命令重新启动数据库服务器：

    ```
    systemctl restart postgresql

    ```

1.  在同一网络中的任何其他计算机上（由之前设置的`XXX.XXX.XXX.XXX/XX`值定义），您现在可以使用`psql` shell 测试与您的 Postgres 服务器的远程连接是否正常工作（如果您的客户端计算机是 CentOS，您需要使用`yum install postgresql`安装它），通过远程登录到服务器并打印出一些测试数据。在我们的例子中，Postgres 服务器正在运行，IP 地址为`192.168.1.12`。

    ```
    psql -h 192.168.1.12 -U <username> -d <database-name>

    ```

## 它是如何工作的...

PostgreSQL 是一个安全可靠的数据库系统，但我们访问它的方式（无论是远程还是本地）常常会引起混淆。本食谱的目的是揭开基于主机的认证的神秘面纱，并提供一个易于使用的解决方案，帮助您让系统运行起来。

那么我们从这次经历中学到了什么？

我们首先在防火墙中打开 Postgres 服务的标准端口，以便首先从任何远程计算机建立连接。然后，我们使用最喜欢的文本编辑器打开名为`pg_hba.conf`的 Postgres 基于主机的认证配置文件。请记住，我们已经在之前的食谱中将所有本地连接从`对等`更改为`md5`认证，以提供基于用户的认证。插入的主机记录行指定了连接类型、数据库名称、用户名、客户端 IP 地址范围和认证方法。虽然许多之前的命令可能已经理解，但重要的是要认识到有几种不同的认证方法：

+   **信任**: 无条件允许连接，并允许任何人无需密码即可连接到数据库服务器。

+   **拒绝**: 允许数据库服务器无条件拒绝连接，在过滤某些 IP 地址或某些主机时，这一功能仍然很有用。

+   **md5**: 意味着客户端需要提供一个 MD5 加密的密码进行认证。

+   **对等和标识**: 如果客户端登录的 Linux 用户名在系统中作为数据库用户被找到，则授予访问权限。标识用于远程连接，而对等用于本地连接。

完成这项任务后，我们保存并关闭文件，然后打开位于`/var/lib/pgsql/data/postgresql.conf`的主 PostgreSQL 配置文件。你可能知道也可能不知道，除非服务器以适当的`listen_addresses`值启动，否则远程连接是不可能的。默认设置将此设置为本地回环地址，因此有必要允许数据库服务器监听所有网络接口（用星号或`*`表示）以接收 5432 端口的 Postgres 连接。完成后，我们只需保存文件并重新启动数据库服务器。

总有更多的东西要学习，但通过完成这个配方，你不仅对基于主机的认证有了更好的理解，而且你还有能力在本地和远程访问你的 PostgreSQL 数据库服务器。

# 安装 phpMyAdmin 和 phpPgAdmin

使用 MariaDB 或 Postgres 命令行 shell 足以执行基本的数据库管理任务，例如用户权限设置或创建简单的数据库，正如我们在本章中向你展示的那样。随着你的模式和表之间的关系变得更加复杂，以及你的数据增长，你应该考虑使用一些图形数据库用户界面以获得更好的控制和工作性能。对于新手数据库管理员来说也是如此，因为这样的工具为你提供了语法高亮和验证，有些工具甚至有数据库的图形表示（例如，显示实体关系模型）。在这个配方中，我们将向你展示如何安装市场上最流行的两个图形开源数据库管理软件，即`phpMyadmin`和`phpPgAdmin`，它们是基于 Web 的浏览器应用程序，用 PHP 编写。

## 准备就绪

要完成这个配方，你需要具备以下条件：CentOS 7 操作系统的有效安装，具有 root 权限，你选择的基于控制台的文本编辑器，以及互联网连接以便下载额外的软件包。预计你的 MariaDB 或 PostgreSQL 服务器已经按照本章中的配方运行。此外，你需要一个运行中的 Apache 网络服务器，该服务器已安装 PHP，并且必须可以从你的私人网络中的所有计算机访问以部署这些应用程序（请参阅第十二章，*提供网络服务*以获取说明）。此外，你需要启用 EPEL 存储库以安装正确的软件包（请参阅第四章中的配方*使用第三方存储库*，*使用 YUM 管理软件包*）。最后，你需要在你的网络中有一台计算机，该计算机具有图形窗口管理器和现代网络浏览器，以便访问这些网络应用程序。

## 如何做到这一点...

在这个配方中，我们将首先向你展示如何安装和配置`phpMyAdmin`以进行远程访问，然后是如何为`phpPgAdmin`做同样的事情。

### 安装和配置 phpMyAdmin

要安装和配置 phpMyAdmin，请执行以下步骤：

1.  输入以下命令以安装所需的软件包：

    ```
    yum install phpMyAdmin

    ```

1.  现在创建主`phpMyadmin`配置文件的副本：

    ```
    cp /etc/httpd/conf.d/phpMyAdmin.conf /etc/httpd/conf.d/phpMyAdmin.conf.BAK

    ```

1.  接下来，打开主`phpMyAdmin.conf`配置文件，并在您想要授权访问 Web 应用程序的已定义子网的网络地址下添加一行`Require ip XXX.XXX.XXX.XXX/XX`，例如，在`Require ip 127.0.0.1`行下添加`Require ip 192.168.1.0/24`。您需要在文件中执行此操作两次，或者可以使用`sed`自动执行此操作，如下所示。在命令行中，根据您自己的子网网络地址相应地定义环境变量`NET=`。

    ```
    NET="192.168.1.0/24"

    ```

1.  然后输入以下行以将更改应用到配置文件：

    ```
    sed -i "s,\(Require ip 127.0.0.1\),\1\nRequire ip $NET,g" /etc/httpd/conf.d/phpMyAdmin.conf

    ```

1.  之后，重新加载您的 Apache 服务器，现在您应该能够从子网中的任何其他计算机浏览到运行 Web 应用程序的服务器的 IP 地址的`phpMyAdmin`网站，例如`192.168.1.12`（使用 MariaDB 管理员用户 root 或其他数据库用户登录）：

    ```
    http://192.168.1.12/phpMyAdmin

    ```

### 安装和配置 phpPgAdmin

以下是安装和配置 phpPgAdmin 的步骤：

1.  输入以下命令以安装所需的软件包：

    ```
    yum install phpPgAdmin

    ```

1.  在编辑`phpPgAdmin`主配置之前，首先对其进行备份：

    ```
    cp /etc/httpd/conf.d/phpPgAdmin.conf /etc/httpd/conf.d/phpPgAdmin.conf.BAK

    ```

1.  允许远程访问`phpPgAdmin`与`phpMyAdmin`非常相似。在这里，您也可以在`phpPgAdmin.conf`文件中的`Require local`行下添加一行`Require ip XXX.XXX.XXX.XXX/XX`，其中包含您定义的子网网络地址，或者使用`sed`实用程序自动执行此操作：

    ```
    NET="192.168.1.0/24"
    sed -i "s,\(Require local\),\1\nRequire ip $NET,g" /etc/httpd/conf.d/phpPgAdmin.conf

    ```

1.  重启 Apache 并浏览到`phpPgAdmin`主页：

    ```
    http://192.168.1.12/phpPgAdmin

    ```

## 它是如何工作的...

在这个相当简单的教程中，我们向您展示了如何在同一台服务器上安装两个最流行的 MariaDB 和 Postgres 的图形化管理工具，这些工具作为 Web 应用程序在您的浏览器中运行（使用 PHP 编写），并启用了对它们的远程访问。

那么我们从这次经历中学到了什么？

使用`yum`包管理器安装`phpMyAdmin`以管理 MariaDB 数据库和`phpPgAdmin`以管理 Postgres 数据库就像安装相应的`rpm`包一样简单。由于这两个工具在官方的 CentOS 7 仓库中找不到，您需要在能够访问和安装这些包之前启用第三方仓库 EPEL。默认情况下，在安装这两个 Web 应用程序时，拒绝来自服务器本身（仅本地）以外的任何连接。由于我们希望从网络中的不同计算机访问它，因此安装了 Web 浏览器后，您需要首先允许远程连接。对于这两个 Web 应用程序，可以使用 Apache 的`Require ip`指令来实现，该指令是 Apache 的`mod_authz_core`模块的一部分。在`phpMyAdmin`和`phpPgAdmin`的配置文件中，我们定义了一个完整的子网，例如`192.168.1.0/24`，以允许连接到服务器，但您也可以在这里使用单个 IP 地址，您希望允许访问该地址。`sed`命令将这些重要的`Require`行插入到配置文件中，但如前所述，如果您愿意，也可以通过使用您选择的文本编辑器编辑这些文件来手动完成。重新加载 Apache 配置后，您就可以使用本食谱中显示的两个 URL 浏览到网页。在两个网站的首页上，您可以使用任何数据库用户登录，无需为他们启用远程权限；任何具有本地权限的用户都足够了。

总之，我们可以说我们只向您展示了两种管理工具的基本配置。总有更多需要学习的内容；例如，您应该考虑使用 SSL 加密来保护 PHP 网站，或者配置您的实例以连接到不同的数据库服务器。此外，如果您更喜欢使用桌面软件来管理数据库，可以查看开源的 MySQL Workbench 社区版，该版本可以从官方 MySQL 网站下载，适用于所有主要操作系统（Windows、OS X、Linux）。
