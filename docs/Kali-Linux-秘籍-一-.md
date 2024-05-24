# Kali Linux 秘籍（一）



# 第一章：安装和启动 Kali

> 作者：Willie L. Pritchett, David De Smet

> 译者：[飞龙](https://github.com/)

> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

## 简介

Kali Linux，简称 Kali，是用于安全攻击的最新 Linux 发行版。它是 BackTrack Linux 的后继者。不像多数 Linux 发行版那样，Kali Linux 用于渗透测试。渗透测试是一种通过模拟攻击评估计算机系统或网络安全性的方法。在整本书中，我们将会探索一些 Kali Linux 所提供的工具。

这一章涉及到 Kali Linux 在不同场景下的的安装和启动，从插入 Kali Linux DVD 到配置网络。

对于本书中所有秘籍，我们都要使用以 64 位 GNOME 作为窗口管理器（WM）和架构的 Kali Linux（[http://www.Kali.org/downloads/](http://www.Kali.org/downloads/)）。然而，使用 KDE 作为 WM 的用法并不在这本书里涉及，你应该能够遵循这些秘籍，并没有多少问题。

## 1.1 安装到硬盘

硬盘的安装是最基本的操作之一。这个任务需要我们不带 DVD 运行 Kali 来完成。

> 执行这个秘籍中的步骤会抹掉你的硬盘，并把 Kali 标记为你电脑上的主操作系统。

### 准备

在解释整个过程之前，需要满足以下要求：

+ 为 KaliLinux 的安装准备最小 8GB 的空闲磁盘空间（然而我们推荐至少 25GB 来存放这本书中额外的程序和生成的词汇表）。
+ 最小 512MB 的内存。
+ 在[KaliLinux 的下载页面](http://www.kali.org/downloads/)下载 Kali Linux。

让我们开始安装吧。

### 操作步骤

1.  在光驱中插入 Kali Linux Live DVD 来开始。你会看到它的启动菜单。选择`Graphical install`（图形化安装）。

    ![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-cb/img/1-1-1.jpg)

2.  选择语言。这里我们选择`English`（英语）。

    ![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-cb/img/1-1-2.jpg)

3.  选择你的位置。这里我们选择`United States`（美国）。

    ![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-cb/img/1-1-3.jpg)

4.  选择你的键盘配置。这里我们选择`American English`（美国英语）。

    ![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-cb/img/1-1-4.jpg)

5.  下面要完成网络服务配置。输入主机名称，这里我们输入`Kali`。

    ![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-cb/img/1-1-5.jpg)

6.  下面，我们需要输入域名。这里我们输入`kali.secureworks. com`。

    ![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-cb/img/1-1-6.jpg)

7.  现在你会看到输入 root 密码的地方，需要输入两次。

    ![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-cb/img/1-1-7.jpg)

8.  选择你的时区，这里我们选择`Eastern`（东方）。

    ![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-cb/img/1-1-8.jpg)

9.  我们现在可以选择磁盘分区方式。你会看到四个选项。选择`Guided - use entire disk`，这会便于你分区。

    ![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-cb/img/1-1-9.jpg)

0.  在这一步，你需要知道你的磁盘会被抹掉，点击`Continue`（继续）。

    ![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-cb/img/1-1-10.jpg)

1.  下面，你有机会选择三个分区方式之一：所有文件放在一个分区、分离`/home`、以及分离`/home/user/var`和`/tmp`。考虑到 Kali 用于渗透测试，分区不需要也不必要（即使这对于你的桌面主操作系统是个好主意）。这里我们选择` All files in one partition`（所有文件放在一个分区）并点击`Continue`（继续）。

    ![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-cb/img/1-1-11.jpg)

2.  一旦你看到了一个界面，让你知道将要对你磁盘执行的改动，选择`Yes`之后点击`Continue`（继续）。要注意这是撤销抹掉你磁盘所有数据的最后机会。

    ![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-cb/img/1-1-12.jpg)

3.  下面，你会被询问是否希望链接到网络镜像。网络镜像允许你接收到 Kali 的更新。这里我们选择`Yes`之后点击`Continue`（继续）。

    ![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-cb/img/1-1-13.jpg)

4.  你可以通过点击`Continue`（继续）跳过 HTTP 代理界面。

    ![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-cb/img/1-1-14.jpg)

5.  最后，你会被询问来安装 GRUB 启动器到主引导记录（MBR）中。选择`Yes`之后点击`Continue`（继续）。

    ![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-cb/img/1-1-15.jpg)

6.  祝贺你现在完成了 Kali Linux 的安装！点击`Continue`，系统会重启并展示登录界面。

    ![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-cb/img/1-1-16.jpg)

## 1.2 安装到 U 盘或持久存储器中

Kali Linux U 盘能够持久化储存系统设置，以及在 U 盘中永久升级和安装新的软件包，并让我们将个人定制的 Kali Linux 随时带在身上。

多亏了 Win32 Disk Imager，我们可以为大多数 Linux 发行版创建可启动的 U 盘，包括持久化存储的 Kali Linux。

### 准备

需要下列工具和准备工作以继续：

+ FAT32 格式的 U 盘，最小 8GB。
+ Kali Linux ISO 镜像。
+ [Win32 Disk Imager](http://sourceforge.net/projects/win32diskimager/)。
+ 你可以从[这里](http://www.kali.org/downloads/)下载 Kali。

### 操作步骤

让我们开始讲 Kali Linux 安装到 U 盘：

1.  插入格式化且可写入的 U 盘：

    ![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-cb/img/1-2-1.jpg)

2.  启动 Win32 Disk Imager。

3.  点击目录图表，选择 Kali Linux DVD ISO 镜像的位置：

    ![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-cb/img/1-2-2.jpg)

4.  确保`Space used to preserve files across reboots`（用于在启动中保存文件的空间）设置为 4096。

    ![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-cb/img/1-2-3.jpg)

5.  选择我们的 U 盘，并点击 OK 按钮来开始创建可启动的 U 盘：


6.  当它解压并复制 DVD 的文件到 U 盘，以及安装 bootloader 时，这个过程会花一些时间来完成。

7.  安装完成之后，我们就可以重启电脑，从新创建的 Kali Linux U 盘以持久存储器来启动了。

    ![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-cb/img/1-2-4.jpg)

## 1.3 在 VirtualBox 中安装

这个秘籍会引导你使用知名的开源虚拟机软件 VirtualBox，将 Kali Linux 安装在一个完全分离的访客操作系统中，它在你的宿主操作系统中。

### 准备

需要满足下列要求：

+ [VirtualBox](https://www.virtualbox.org/wiki/Downloads) 的最新版本（本书编写时为 4.2.16）。
+ Kali Linux ISO 镜像的副本。你可以在[这里](http://www. Kali.org/downloads/)下载。

### 操作步骤

让我们在 VirtualBox 中安装 Kali Linux：

1.  运行 VirtualBox，点击`New`（新建）来启动虚拟机向导：

    ![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-cb/img/1-3-1.jpg)

2.  点击`Next`（下一步）按钮，键入虚拟机的名称，并选择 OS 类型和版本。这里我们选择 Linux 类型和 Ubuntu（64 位）作为版本。点击`Next`按钮来继续：

    ![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-cb/img/1-3-2.jpg)

3.  选择分配给虚拟机的基本内存（RAM）的总数。我们打算使用默认值，点击`Next`。

4.  为新的虚拟机创建新的虚拟硬盘，点击`Next`按钮。

    ![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-cb/img/1-3-3.jpg)

5.  一个新的向导窗口将会打开，保留默认的 VDI 文件类型，因为我们并不需要使用其它的虚拟机软件。

6.  我们会保留默认选项作为虚拟机磁盘存储的详情。点击`Next`来继续：

7.  设置虚拟机磁盘文件类型和大小：

    ![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-cb/img/1-3-4.jpg)

8.  检查设置是否正确，之后点击`Create`（创建）按钮来开始虚拟磁盘文件的创建。

9.  我们将会返回前面的向导，带有虚拟机参数的概览。点击`Create`以结束：

    ![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-cb/img/1-3-5.jpg)

0.  新的虚拟机创建之后，我们将要安装 Kali Linux。

1.  在 VirtualBox 的主窗口，高亮 Kali Linux，之后点击`Settings`（设置）按钮：

    ![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-cb/img/1-3-6.jpg)

2.  现在基本的安装步骤就完成了，我们需要让你将下载的 ISO 文件用于虚拟光盘。这会为你节省烧录物理 DVD 的时间来完成这个安装。在`Settings`界面中，点击`Storage`（存储器）菜单选项：

    ![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-cb/img/1-3-7.jpg)

3.  下一步，在`Storage Tree`（存储器树形图）下面，高亮`Empty`（空）磁盘图标，它在`IDE Controller`（IDE 控制器）的下面。这户选择我们的虚拟 CD/DVD ROM 驱动器。在屏幕的最右边，在
`Attributes`底下，点击光盘图表。在上面弹出的菜单上选择你的`Choose a virtual CD/DVD disc file...`（Kali Linux ISO CD/DVD 光盘文件）选项，并找到你的 ISO。一旦你完成了这些步骤，点击 OK 按钮。

    ![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-cb/img/1-3-8.jpg)

4.  点击 Start（开始）按钮，之后点击里面的新窗口来进行安装。安装步骤在 1.1 节中已经包括了。

    > 安装 VirtualBox 扩展包也允许我们通过添加 USB2.0（EHCI）、VirtualBox RDP 和 Intel PXE boot ROM 的支持，来扩展虚拟机的功能。

## 1.4 安装  VMware Tools

这个秘籍中，我们会展示如何使用 VMware Tools 将 Kali Linux 安装在虚拟机中。

### 准备

需要满足下列要求：

+ 已经安装好的 Kali Linux VMware 虚拟机。
+ 网络连接。

### 操作步骤

让我们开始将 Kali Linux 安装到 VMware 上：

1.  打开你的虚拟机的访客操作系统并连接到互联网，之后打开`Terminal`（终端）窗口，并键入下列命令来准备核心资源：

    ```
    prepare-kernel-sources
    ```

    > 这些命令假设你使用 Linux 或者 Mac OS。你不需要在 Windows 下执行它们。

2.  在 VMware Workstaion 的菜单栏上，访问`VM | Install VMware Tools…`：

    ![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-cb/img/1-4-1.jpg)

3.  将 VMware Tools 安装工具复制到临时目录下，之后将当前位置改为目标目录：

    ```
    cp /media/VMware\ Tools/VMwareTools-8.8.2-590212.tar.gz /tmp/; cd /tmp
    ```

    > 根据你的 VMware Tools 来替换文件名：`VMwareTools-<version>-<build>.tar.gz`。

4.  使用以下命令解压并安装：

    ```
    tar zxpf VMwareTools-8.8.2-590212.tar.gz
    ```

5.  进入 VMware Tools 的目录中，之后运行安装工具：

    ```
    cd vmware-tools-distrib/
    ./vmware-install.pl
    ```

6.  按下回车键来接受每个配置询问的默认值；`vmware-config-tools.pl`脚本同上。

7.  最后重启系统，工作就完成了。

### 工作原理

在第一步中，我们准备好了核心资源。之后，我们向访客操作系统插入了虚拟的 VMware Tools CD 。接着，我们创建了挂载点，并挂载虚拟 CD。我们在临时目录中复制并解压了安装工具。最后我们保留默认配置来运行安装工具。

## 1.5 修复启动画面

我们首次启动新安装的 Kali Linux 系统时，会注意到启动画面消失了。为了手动修复它，我们需要解压`Initrd`，修改它，之后将它再次压缩。幸运的是，有一个由 Mati Aharoni（也称为“muts”，Kali Linux 的创造者）编写的自动化 bash 脚本使这件事变得容易。

### 操作步骤

键入下列命令并且按下回车键来修复消失的启动画面：

```
fix-splash
```

## 1.6 启动网络服务

Kali Linux 自带了多种网络服务，它们在多种情况下可能很实用，并且默认是禁用的。这个秘籍中，我们会涉及到通过多种方法设置和启动每个服务的步骤。

### 准备

需要满足下列要求以继续：

+ 带有有效 IP 地址的网络连接。

### 操作步骤

让我们开始启动默认服务：

1.  启动 Apache 服务器：

    ```
    service apache2 start
    ```

    我们可以通过浏览本地地址来验证服务器是否打开。

2.  为了启动 SSH 服务，首次需要生成 SSH 密钥：

    ```
    sshd-generate
    ```

3.  启动 SSH 服务器：

    ```
    service ssh start
    ```

4.  使用`netstat`命令来验证服务器是否开启并正在监听：

    ```
    netstat -tpan | grep 22
    ```

5.  启动 FTP 服务器：

    ```
    service pure-ftpd start
    ```

6.  使用下列命令来验证 FTP 服务器：

    ```
    netstat -ant | grep 21
    ```

    > 你也可以使用` ps-ef | grep 21 `命令。

7.  使用下列命令来停止服务：

    ```
    service <servicename> stop
    ```

    其中`<servicename>`代表我们希望停止的网络服务，例如：

    ```
    service apache2 stop
    ```

8.  使用下列命令来在开机时启用服务：

    ```
    update-rc.d –f <servicename> defaults
    ```

    其中`<servicename>`代表打算启动的网络服务，例如：

    ```
    update-rc.d –f ssh defaults
    ```

    > 你也可以在 Kali Linux 中通过`Services`（服务）菜单来完成它。从`Start`（开始）菜单开始，访问`Kali Linux | Services`。

## 1.7 设置无线网络

最后，我们来到了这一章的最后一个秘籍。这个秘籍中，我们会了解在安全状态下的无线网络连接步骤，通过 Wicd Network Manager 和提供加密的细节。无线网络的设置允许我们以无线方式使用 Kali Linux。在真实的、合乎道德的渗透测试中，我们可以不依赖于网线而自由地使用所有常规桌面。

### 操作步骤

让我们开始设置无线网络：

1.  从桌面启动网络管理器，通过点击`Applications`（应用）菜单并且访问`Internet | Wicd Network Manager`，或者在终端窗口中键入下列命令：

    ```
    wicd-gtk --no-tray
    ```

2.  Wicd Network Manager 会打开，并带有可用网络的列表：

    ![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-cb/img/1-7-1.jpg)

3.  点击`Properties`（属性）按钮来设定网络细节。完成之后点击 OK。

    ![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-cb/img/1-7-2.jpg)

4.  最后，点击`Connect`（连接）按钮，就完成了。

### 工作原理

这个秘籍中，我们总结了无线网络的设置方式。这个秘籍以启动网络管理器，和连接到我们的路由器作为开始。


# 第二章：定制 Kali Linux

> 作者：Willie L. Pritchett, David De Smet

> 译者：[飞龙](https://github.com/)

> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

这一章会向你介绍 Kali 的定制，便于你更好地利用它。我们会涉及到 ATI 和英伟达 GPU 技术的安装和配置，以及后面章节所需的额外工具。基于 ATI 和英伟达 GPU 的显卡允许我们使用它们的图像处理单元（GPU）来执行与 CPU 截然不同的操作。我们会以 ProxyChains 的安装和数字信息的加密来结束这一章。

## 2.1 准备内核头文件

有时我们需要使用所需的内核头文件来编译代码。内核头文件是 Linux 内核的源文件。这个秘籍中，我们会解释准备内核头文件所需的步骤，便于以后使用。

### 准备

完成这个秘籍需要网络连接。

### 操作步骤

让我们开始准备内核头文件：

1.  我们首先通过执行下列命令升级发行版作为开始：

    ```
    apt-get update
    ```
    
    ![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-cb/img/2-1-1.jpg)
    
2.  下面，我们需要再次使用`apt-get`来准备内核头文件，执行下列命令：

    ```
    apt-get install linux-headers - `uname –r`
    ```
    
    ![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-cb/img/2-1-2.jpg)
    
3.  复制下列目录以及其中的全部内容：

    ```
    cd /usr/src/linux 
    cp -rf include/generated/* include/linux/
    ```
    
4.  我们现在已准备好编译需要内核头文件的代码。

## 2.2 安装 Broadcom 驱动

在这个秘籍中，我们将要安装 Broadcom 官方的 Linux 混合无线驱动。 使用 Broadcom 无线 USB 适配器可以让我们在 Kali 上连接我们的无线 USB 接入点。对于这本书的其余秘籍，我们假设 Broadcom 无线驱动已经安装。

### 准备

完成这个秘籍需要网络连接。

### 操作步骤

让我们开始安装 Broadcom 驱动：

1.  打开终端窗口，从[http://www.broadcom.com/support/802.11/linux_sta.php](http://www.broadcom.com/support/802.11/linux_sta.php)下载合适的 Broadcom 驱动：

    ```
    cd /tmp/ 
    wget http://www.broadcom.com/docs/linux_sta/hybrid-portsrc_ x86_64-v5_100_82_112.tar.gz
    ```
    
    ![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-cb/img/2-2-1.jpg)
    
2.  使用下列命令解压下载的驱动：

    ```
    mkdir broadcom 
    tar xvfz hybrid-portsrc_x86_64-v5_100_82_112.tar.gz –C /tmp/ broadcom
    ```
    
3.  修改`wl_cfg80211.c`文件，由于 5.100.82.112 版本中有个 bug，会阻止小于 2.6.39 内核版本上的编译：

    ```
    vim /tmp/broadcom/src/wl/sys/wl_cfg80211.c
    ```
    
    观察代码段的 1814 行：
    
    ```c
    #if LINUX_VERSION_CODE > KERNEL_VERSION(2, 6, 39)
    ```
    
    将其改为：
    
    ```c
    #if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 39) 
    ```
    
    并保存修改。
    
4.  编译代码：

    ```
    make clean
    make
    make install
    ```
    
5.  更新依赖：

    ```
    depmod -a
    ```
    
6.  通过下列命令找到加载的模块：

    ```
    lsmod | grep b43\|ssb\|bcma
    ```
    
7.  通过执行下列命令移除发现的模块：

    ```
    rmmod <module>b43
    ```
    
    其中`<module>`应为`b43`、`ssb`或`bcma`。
    
8.  将模块加入黑名单，防止它们在系统启动中加载：

    ```
    echo "blacklist <module>" >> /etc/modprobe.d/blacklist.conf 
    ```
    
    其中`<module>`应为`b43`、`ssb`或`wl`。
    
9.  最后，将新模块添加到 Linux 内核中，来使它成为启动进程的一部分：

    ```
    modprobe wl
    ```

## 2.3 安装和配置 ATI 显卡驱动

这个秘籍中，我们会详细讲解 ATI 显卡驱动的安装和配置，在此之前需要 AMD Accelerated Parallel Processing (APP) SDK、OepnCL 和 CAL++。我们可以利用 ATI Stream 技术的优势来运行计算密集型任务 -- 它们通常运行在 CPU 上 -- 使它们更快更高效地执行。更多 ATI Stream 技术相关的详细信息，请访问[www.amd.com/stream]( www.amd.com/stream)。

### 准备

需要网络连接来完成这个秘籍。同时在开始这个秘籍之前需要准备内核头文件，它在第一节有所涉及。

### 操作步骤

让我们开始安装和配置 ATI 驱动：

1.  下载系统所需的 ATI 显示驱动：

    ```
    cd /tmp/ 
    wget http://www2.ati.com/drivers/linux/amd-driver-installer-121-x86.x86_64.run
    ```
    
    我们也可以从下面的网址下载显示驱动：[http://support. amd.com/us/gpudownload/Pages/index.aspx](http://support. amd.com/us/gpudownload/Pages/index.aspx)。
    
    ![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-cb/img/2-3-1.jpg)
    
2.  通过键入下列命令来开始安装：

    ```
    sh amd-driver-installer-12-1-x86.x86_64.run
    ```
    
    ![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-cb/img/2-3-2.jpg)
    
3.  在安装完成之后，重启你的系统来使改变生效，并且避免不稳定。

4.  为之后的步骤安装一些依赖：

    ```
    apt-get install libroot-python-dev libboost-python-dev libboost1.40-all-dev cmake
    ```
    
5.  下载并解压 AMD APP SDK，根据你的 CPU 架构：

    ```
    wget http://developer.amd.com/Downloads/AMD-APP-SDK-v2.6-lnx64.tgz 
    mkdir AMD-APP-SDK-v2.6-lnx64 
    tar zxvf AMD-APP-SDK-v2.6-lnx64.tgz –C /tmp/AMD-APP-SDK-v2.6-lnx64 
    cd AMD-APP-SDK-v2.6-lnx64
    ```
    
6.  通过下列命令安装 AMD APP SDK：

    ```
    sh Install-AMD-APP.sh
    ```
    
7.  在`.bashsrc`文件中设置 ATI Stream 的路径：

    ```
    echo export ATISTREAMSDKROOT=/opt/AMDAPP/ >> ~/.bashrc 
    source ~/.bashrc
    ```
    
8.  下载并编译`calpp`：

    ```
    cd /tmp/ 
    svn co https://calpp.svn.sourceforge.net/svnroot/calpp calpp 
    cd calpp/trunk 
    cmake . 
    make 
    make install
    ```
    
9.  下载并编译`pyrit`：

    ```
    cd /tmp/ 
    svn co http://pyrit.googlecode.com/svn/trunk/ pyrit_src 
    cd pyrit_src/pyrit 
    python setup.py build 
    python setup.py install
    ```
    
0.  构建并安装 OpenCL：

    ```
    cd /tmp/pyrit_src/cpyrit_opencl 
    python setup.py build 
    python setup.py install\
    ```
    
1.  对` cpyrit_calpp `的安装做一些小修改：

    ```
    cd /tmp/pyrit_source/cpyrit_calpp 
    vi setup.py
    ```
    
    找到下面这一行：
    
    ```py
    VERSION = '0.4.0-dev' 
    ```
    
    把它改成：
    
    ```py
    VERSION = '0.4.1-dev' 
    ```
    
    之后，找到下面这一行：
    
    ```py
    CALPP_INC_DIRS.append(os.path.join(CALPP_INC_DIR, 'include')) 
    ```
    
    把它改成：
    
    ```py
    CALPP_INC_DIRS.append(os.path.join(CALPP_INC_DIR, 'include/CAL'))
    ```
    
2.  最后将 ATI GPU 模块添加到 pyrit：

    ```
    python setup.py build 
    python setup.py install
    ```
    
> 为了展示可用的 CAL++设备和 CPU 的核数，我们需要键入下列命令：

> ```
> pyrit list_cores
> ```

> 为了进行跑分，我们只需要键入：

> ```
> pyrit benchmark
> ```

## 2.4 安装和配置英伟达显卡驱动

这个秘籍中，我们会拥抱 CUDA，英伟达的并行计算架构。在 CUDA 工具包的安装之后，首先会安装英伟达开发者显示驱动。通过使用 GPU 的威力，这会带来计算性能的戏剧性提升，它们通常用于一些类似密码破解的场合。

> 有关 CUDA 的更多信息，请浏览[他们的官方网站](http://www.nvidia.com/object/cuda_home_new.html)。

### 准备

需要网络连接来完成这个秘籍。

同时需要在开始之前准备内核头文件，这在第一节中有所涉及。

为了完成英伟达驱动的安装，需要关闭 X 会话。

### 操作步骤

让我们开始安装和配置英伟达显卡驱动：

1.  下载英伟达开发者显示驱动，根据你的 CPU 架构：
    
    ```
    cd /tmp/ 
    wget http://developer.download.nvidia.com/compute/cuda/4_1/rel/ drivers/NVIDIA-Linux-x86_64-285.05.33.run
    ```
    
    ![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-cb/img/2-4-1.jpg)
    
2.  安装驱动：

    ```
    chmod +x NVIDIA-Linux-x86_64-285.05.33.run 
    ./NVIDIA-Linux-x86_64-285.05.33.run –kernel-source-path='/usr/src/ linux'
    ```
    
3.  下载 CUDA 工具包：

    ```
    wget http://developer.download.nvidia.com/compute/cuda/4_1/rel/ toolkit/cudatoolkit_4.1.28_linux_64_ubuntu11.04.run
    ```
    
4.  安装 CUDA 工具包到`/opt`：

    ```
    chmod +x cudatoolkit_4.1.28_linux_64_ubuntu11.04.run 
    ./cudatoolkit_4.1.28_linux_64_ubuntu11.04.runConfigure the environment variables required for nvcc to work: 
    echo PATH=$PATH:/opt/cuda/bin >> ~/.bashrc 
    echo LD_LIBRARY_PATH=$LD_LIBRARY_PATH:/opt/cuda/lib >> ~/.bashrc 
    echo export PATH >> ~/.bashrc 
    echo export LD_LIBRARY_PATH >> ~/.bashrc
    ```
    
5.  运行以下命令来使变量生效：

    ```
    source ~/.bashrc 
    ldconfig
    ```
    
6.  安装`pyrit`的依赖：

    ```
    apt-get install libssl-dev python-dev python-scapy
    ```
    
7.  下载并安装 GPU 增效工具`pyrit`：

    ```
    svn co http://pyrit.googlecode.com/svn/trunk/ pyrit_src 
    cd pyrit_src/pyrit 
    python setup.py build 
    python setup.py install
    ```
    
8.  最后，将英伟达 GPU 模块添加到`pyrit`：

    ```
    cd /tmp/pyrit_src/cpyrit_cuda 
    python setup.py 
    build python setup.py install
    ```
    
> 为了验证`nvcc`是否正确安装，我们需要键入下列命令：

> ```
> nvcc -V
> ```

> 为了进行跑分，我们只需要键入下列命令：

> ```
> pyrit benchmark
> ```

## 2.5 升级和配置额外的安全工具

这个秘籍中，我们会涉及到升级 Kali，以及配置一些额外的工具，它们对于之后的章节和秘籍十分实用。由于 Kali 的包在发布之间会不断升级，你很快就会发现比起之前在你的 DVD 中下载好的工具，又提供了一系列新的工具。我们会以升级来开始，之后获得 Nessus 的激活码，并以安装 Squid 来结束。

### 操作步骤

让我们开始进行升级，以及配置额外的安全工具。

1.  使用仓库中最新的修改来更新本地的包索引：

    ```
    apt-get update
    ```
    
2.  升级现有的包：

    ```
    apt-get upgrade
    ```
    
3.  升级到最新版本（如果可用的话）：

    ```
    apt-get dist-upgrade
    ```
    
4.  获得 Nessus 的激活码，通过在[这里]( http://www.nessus.org/ products/nessus/nessus-plugins/obtain-an-activation-code)注册。

5.  通过执行下列命令来激活 Nessus：

    ```
    /opt/nessus/bin/nessus-fetch --register A60F-XXXX-XXXX-XXXX-0006 
    ```
    
    其中`A60F-XXXX-XXXX-XXXX-0006`应为你的激活码。
    
6.  为 Nessus Web 界面创建账户：

    ```
    /opt/nessus/sbin/nessus-adduser
    ```
    
7.  为了启动 Nessus 服务器，我们只需要执行下列命令：

    ```
    /etc/init.d/nessusd start
    ```
    
8.  安装 Squid：

    ```
    apt-get install squid3 
    ```
    
9.  阻止 Squid 在启动时自动运行：

    ```
    update-rc.d -f squid3 remove
    ```
    
> 为了在仓库中找到特定的包，我们可以在`apt-get update`之后使用下列命令：

> ```
> apt-cache search <keyword> 
> ```

> 其中`<keyword>`是包名称或者正则表达式。

## 2.6 配置 ProxyChains

这个章节中，我们会强制指定应用的网络连接使用用户定义的代理列表，来打破接受者和发送者之间的直接连接。

### 操作步骤

1.  打开 ProxyChains 的配置文件：

    ```
    vim /etc/proxychains.conf 
    ```
    
2.  解除我们打算使用的链接类型的注释，这里是`dynamic_chain`：

    ![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-cb/img/2-6-1.jpg)
    
3.  向列表中添加一些代理服务器：

    ![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-cb/img/2-6-2.jpg)

4.  使用我们的链式代理来解析目标主机：

    ```
    proxyresolv www.targethost.com 
    ```
    
5.  现在可以在我们打算使用的应用上运行 ProxyChains，例如`msfconsole`：

    ```
    proxychains msfconsole
    ```
    
## 2.7 目录加密

这一章的最后一个秘籍关于信息隐私。我们会使用 TrueCrypt 通过密钥来隐藏重要和私密的数字信息，远离公众的眼睛。

### 操作步骤

1.  通过访问`Applications Menu | Kali | Forensics | Digital Anti Forensics | install truecrypt`来安装 TrueCrypt。

    ![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-cb/img/2-7-1.jpg)
    
    点击`Install TrueCrypt`（安装 TrueCrypt）并且遵循屏幕上的指导。
    
2.  从`Applications Menu | Kali Linux | Forensics | Digital Anti Forensics | truecrypt`运行 TrueCrypt，你会看到下面的窗口：

    ![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-cb/img/2-7-2.jpg)

3.  点击`Create Volume`（新建卷）来启动`TrueCrypt Volume Creation Wizard`（TrueCrypt 卷创建向导）。

4.  保留默认选项并点击`Next`。

5.  选择`Standard TrueCrypt`（标准 TrueCrypt）模式并点击`Next`。

6.  点击`Select File…`（选择文件）按钮并为新的 TrueCrypt 卷指定名称和路径。完成后点击`Save`（保存）。

    ![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-cb/img/2-7-3.jpg)

7.  点击`Next`按钮并选择打算使用的加密和哈希算法。

8.  在下个屏幕中，我们会为容器指定空间总量。

9.  现在我们需要为我们的卷键入密码。点击`Next`。

0.  选择文件系统类型。

1.  按需选择`Cross-Platform Support`（跨平台支持）。

2.  在下个屏幕中，向导会让我们在窗口内移动鼠标，来增加加密密钥的密码强度。完成后点击`Format`（格式化）按钮。

3.  格式化会开始，完成时 TrueCrypt 的卷就创建好了。按下`OK`或`Exit`（退出）。

4.  我们现在回到 TrupCrypt 窗口。

5.  从列表中选择一个`Slot`（槽）来解密我们的卷，点击`Select File…`（选择文件），并打开我们创建的卷。

6.  点击`Mount`（挂载）并键入我们的密码，完成后点击`OK`。

    ![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-cb/img/2-7-4.jpg)

7.  我们现在可以通过在槽上双击或通过挂载目录来访问卷，以及在里面保存文件。当我们完成之后，只需要点击`Dismount All`（解除所有挂载）。

### 工作原理

这个秘籍中，我们配置了 Truecrypt，创建了保护卷，之后挂载了它。这是个用于保护数据安全性的实用工具。



# 第三章：高级测试环境

> 作者：Willie L. Pritchett, David De Smet

> 译者：[飞龙](https://github.com/)

> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

## 简介

既然我们已经了解了 Kali Linux 所包含的工具，现在我们要调查一些真实世界的场景。我们进行的许多攻击都有意在有漏洞的软件和系统上执行。但是，当你使用 Kali 攻击一个系统时，它不可能像我们当前的测试平台那样没有防护。

这一章中，我们会探索一些技巧，来建立起一些真实的测试环境。在当前的信息技术水平中，多数公司都使用平台即服务（PAAS）解决方案，云服务器主机，或者使用小型网络，它们由桌面、服务器和防火墙（单独）或防火墙和路由的组合组成。我们会建立这些环境，之后对它们发起攻击。

我们所有攻击的目的都是获取 root 级别的访问。

## 3.1 熟悉 VirtualBox

在第一章（安装和启动 Kali）中，我们简要谈多了 VirtualBox 的用法，便于在虚拟环境中安装 Kali Linux。VirtualBox 是 Oracle 的现有产品，并且作为应用运行在宿主操作系统上。它通过创建虚拟环境允许操作系统安装并运行。这个工具极其重要，可以提供靶机来测试你的 Kali Linux 技巧。

这一章中，我们会极大依赖 VirtualBox，并且会修改它的配置来得到我们希望的网络配置类型。我们将这一节作为每个场景单元的起点，所以关键要熟悉这些步骤。

### 准备

需要因特网或内部网络的链接来完成这个模块。

### 操作步骤

让我们通过打开 VirtualBox 来开始：

1.  启动 VirtualBox ，并点击`New`来开启虚拟机向导：

    ![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-cb/img/3-1-1.jpg)
    
2.  点击`Next`按钮，输入虚拟机的名称，并选择 OS 类型和版本：这一章中我们会使用 Linux、Solaris 或 Windows 操作系统。选择合适的操作系统并点击`Next`按钮来继续：

    ![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-cb/img/3-1-2.jpg)
    
3.  选择基本内存（RAM）的总量，它们会分配给虚拟机。我们使用默认值。点击`Next`。

4.  为新的虚拟机创建新的虚拟硬盘，点击`Next`按钮。

    ![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-cb/img/3-1-3.jpg)
    
5.  新的向导窗口会打开。保留默认的 VDI 文件类型，因为我们不打算使用其它可视化软件。

6.  我们会在虚拟磁盘储存上保留默认选项。点击`Next`来继续。

7.  设置虚拟磁盘文件位置和大小：

    ![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-cb/img/3-1-4.jpg)
    
8.  检查设置是否正确，并且点击`Create`按钮来开始创建虚拟磁盘文件。

9.  我们现在回到前一个向导，展示了虚拟机参数的汇总。点击`Create`来结束：

    ![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-cb/img/3-1-5.jpg)
    
0.  创建新的虚拟机之后，我们准备好了安装操作系统，它刚刚在 VirtualBox 中配置好。

1.  在 VirtualBox 的主窗口中，选中我们刚刚创建的操作系统名称，之后点击`Settings`按钮：

    ![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-cb/img/3-1-6.jpg)
    
2.  既然基本的安装步骤已经完成了，我们现在使用下载的 ISO 文件作为虚拟光盘。这会节省你烧录物理 DVD 来完成安装的时间。在`Settings`界面，点击`Storage`菜单项：

    ![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-cb/img/3-1-7.jpg)
    
3.  之后，在`Storage Tree`下面，选中`Controller: IDE`下面的`Empty`光盘图标。这会选择我们的“虚拟” CD/DVD ROM 驱动。在屏幕的右边，`Attribute`下面，点击光盘图标。在弹出的菜单中，从列表中选择你的 ISO 文件。如果 ISO 文件没有出现，选择`Choose a virtual CD/DVD disc file... `选项并找到你的 ISO。一旦你完成了这些步骤，点击`OK`按钮。

    ![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-cb/img/3-1-8.jpg)
    
4.  点击`Start`按钮，之后点击内部的新窗口，并执行安装。安装步骤在这一章的“安装到硬盘”中有所涉及。

### 工作原理

这一章以创建新的 VirtualBox 虚拟实例来开始，之后我们选择了我们的操作系统，并设置内存和硬盘大小。之后，我们选择了 ISO 文件，之后将 ISO 插入我们的虚拟 CD/DVD 驱动器中。最后，我们启动了虚拟环境，便于安装操作系统。

在这一章的剩余部分中，我们会使用 VirtualBox 作为所选工具来建立不同的环境。

### 更多

我们所执行的操作可能会让主机不稳定甚至崩溃。VirtualBox 提供了杰出的工具来备份虚拟环境：

1.  在主窗口中，点击你打算备份的虚拟服务器：

2.  右击虚拟服务器，点击`Clone`菜单项：

    ![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-cb/img/3-1-9.jpg)
    
3.  在克隆窗口中，为你的新虚拟服务器输入名称。

    ![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-cb/img/3-1-10.jpg)
    
4.  点击`Next`，在随后的界面中，选择`Linked clone `或`Full clone`，它们在下面展示：

    +   `Full clone`：在完整克隆的模式中，会创建完全独立的虚拟机备份。
    +   `Linked clone`：在链接克隆的模式中，会截取快照来创建备份。但是，链接克隆依赖于原始文件的功能。这会降低链接克隆的性能。
    
    ![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-cb/img/3-1-11.jpg)

5.  点击`Clone`并等待虚拟机克隆完成。

    ![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-cb/img/3-1-12.jpg)

## 3.2 下载 Windows 靶机

到目前为止，以及可见的未来中，微软的 Windows 系统都是许多个人和企业所选的操作系统。

幸运的是，微软提供了一种方法来获取测试操作系统。

### 准备

需要互联网或内部网络连接来完成这个模块。

### 操作步骤

下载 Windows 靶机的步骤如下所示：

1.  打开浏览器并访问 Microsoft Technet：<http://technet. microsoft.com/en-us/ms376608>。

2.  在屏幕的右侧，点击`Downloads`链接：

    ![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-cb/img/3-2-1.jpg)
    
3.  在`Download`菜单项中，选择`Evaluate new products`。

    ![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-cb/img/3-2-2.jpg)

4.  在下一个界面中，你可以选择要下载的东西，取决于你想要测试的产品。推荐你选择 Windows Server 2012，Windows 8 和 Windows 7。

    ![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-cb/img/3-2-3.jpg)
    
5.  一旦你下载了 ISO，请遵循这一章“熟悉 VirtualBox”秘籍中的指南。

    
## 3.3 下载 Linux 靶机

对于多数的面向 Web 的服务器的部署，Linux 是一种备选的操作系统。与 Windows 先比，它的开销相对较低（主流发行版免费），这使它成为多数云主机、PAAS 和服务器环境的理想操作系统。

这个秘籍中，我们会示例如何下载多种 Linux 发行版。

### 准备

需要互联网或内部网络连接来完成这个模块。

### 操作步骤

下载 Linux 靶机的步骤如下所示：

1.  打开浏览器并访问 Distro Watch：<http://www.distrowatch.com>。

2.  你会看到超过 100 个 Linux 发行版的列表。推荐选择一个最小的发行版，而不是流行的版本（CentOS、Ubuntu、Fedora 和 Debian）。这个页面像下面这样：

    ![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-cb/img/3-3-1.jpg)

3.  一旦你下载了 ISO，请遵循这一章“熟悉 VirtualBox”秘籍中的指南。

## 3.4 攻击 WordPress 和其它应用

选择越来越多的公司在日常业务中使用 SAAS （软件及服务）工具。例如，公司普遍使用 WordPress 作为网站的内容管理系统，或 Drupal 作为内部网络。在这些应用中定位漏洞的能力具有极大的价值。

收集被测试应用的一个很好的方式就是 [Turnkey Linux](http://www. turnkeylinux.org)。这个秘籍中，我们会下载流行的 WordPress Turnkey Linux 发行版。

### 准备

需要互联网或内部网络连接来完成这个模块。

### 操作步骤

攻击 WordPress 应用的步骤如下所示：

1.  打开浏览器并访问 Turnkey Linux 的主页：<http://www. turnkeylinux.org>。主页如图所示：

    ![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-cb/img/3-4-1.jpg)

2.  有许多应用在这里列出，我推荐都试试它们，便于你发现漏洞并提升这方面的技能。但是，对于这个秘籍，我们只测试 WordPress。在` Instant Search`框中，输入`WordPress`。

    ![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-cb/img/3-4-2.jpg)
    
3.  在 WordPress 下载页面中，选择 ISO 镜像。下载完成后，请遵循这一章“熟悉 VirtualBox”秘籍中的指南：

    ![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-cb/img/3-4-3.jpg)
    
### 更多

既然我们加载的 WordPress 虚拟机，我们可以使用 WPScan 来攻击它了。WPScan 是个黑盒的 WordPress 安全扫描器，允许用户发现 WordPress 上的漏洞。

WPScan 接受多种参数，包括：

+   `-u <目标域名或 url>`：参数`u`允许你指定目标的域名。

+   `-f`：参数`f`允许你强制检查 WordPress 是否安装。

+   `-e[选项]`：参数`e`允许你设置枚举。

让我们开始使用 WPScan。

> 确保你的 WordPress 虚拟机和 Kali Linux 虚拟机都开着，并使用`VirtualBox Host Only Adapter `网络设置。

1.  在 Kali Linux 虚拟机中，加载器 WPScan 帮助文件：

    ```
    wpscan -h
    ```
    
    页面会像下面这样：
    
    ![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-cb/img/3-4-4.jpg)
    
2.  让我们对 WordPress 虚拟机执行基本的 WPScan 测试。这里，我们靶机的 IP 地址是`192.168.56.102`。

    ```
    wpscan –u 192.168.56.102
    ```
3.  现在，让我们通过执行下列命令枚举用户名列表：

    ```
    wpscan –u 192.186.56.102 –e u vp
    ```
    
    页面会像下面这样：
    
    ![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-cb/img/3-4-5.jpg)
    
4.  最后，我们通过使用`–wordlist <文件路径>`选项来提供单词列表：

    ```
    wpscan –u 192.168.56.102 -e u --wordlist /root/wordlist.txt
    ```
    
    页面会像下面这样：
    
    ![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-cb/img/3-4-6.jpg)
    
5.  这就结束了。我们已经成功获取了 WordPress 的密码。


# 第四章：信息收集

> 作者：Willie L. Pritchett, David De Smet

> 译者：[飞龙](https://github.com/)

> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

## 简介

攻击的重要阶段之一就是信息收集。为了能够实施攻击，我们需要收集关于目标的基本信息。我们获得的信息越多，攻击成功的概率就越高。

我也强调这一阶段的一个重要方面，它就是记录。在编写这本书的时候，最新的 Kali 发行版包含了一组工具用于帮助我们核对和组织来自目标的数据，以便我们更好地侦查目标。类似 Maltego CaseFile 和 KeepNote 的工具就是一个例子。

## 4.1 服务枚举

在这个秘籍中，我们将会展示一些服务枚举的小技巧。枚举是我们从网络收集信息的过程。我们将要研究 DNS 枚举和 SNMP 枚举技术。DNS 枚举是定位某个组织的所有 DNS 服务器和 DNS 条目的过程。DNS 枚举允许我们收集有关该组织的重要信息，例如用户名、计算机名称、IP 地址以及其它。为了完成这些任务我们会使用 DNSenum。对于 SNMP 枚举，我们会使用叫做 SnmpEnum 的工具，它是一个强大的 SNMP 枚举工具，允许我们分析网络上的 SNMP 流量。

### 操作步骤

让我们以 DNS 枚举作为开始：

1.  我们使用 DNSenum 进行 DNS 枚举。为了开始 DNS 枚举，打开 Gnome 终端，并且输入以下命令：

    ```
    cd /usr/bin
    ./dnsenum --enum adomainnameontheinternet.com
    ```

    > 请不要在不属于你的公共网站或者不是你自己的服务器上运行这个工具。这里我们将`adomainnameontheinternet.com`作为一个例子，你应该替换掉这个目标。要当心！

2.  我们需要获取信息输出，例如主机、名称服务器、邮件服务器，如果幸运的话还可以得到区域转换：

    ![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-cb/img/4-1-1.jpg)

3.  我们可以使用一些额外的选项来运行 DNSenum，它们包括这些东西：

    +   `-- threads [number]`允许你设置一次所运行的线程数量。
    +   `-r`允许你开启递归查找。
    +   `-d`允许你设置在 WHOIS 请求之间的时间延迟，单位为秒。
    +   `-o`允许我们制定输出位置。
    +   `-w`允许我们开启 WHOIS 查询。

    > 更多 WHOIS 上的例子，请见[WHOIS 的维基百科](http://en.wikipedia.org/wiki/Whois)。

4.  我们可以使用另一个命令`snmpwalk`来检测 Windows 主机。Snmpwalk 是一个使用 SNMP GETNEXT 请求在网络实体中查询信息树的 SNMP 应用。在命令行中键入下列命令：

    ```
    snmpwalk -c public 192.168.10.200 -v 2c
    ```

5.  我们也可以枚举安装的软件：

    ```
    snmpwalk -c public 192.168.10.200 -v 1 | grep  hrSWInstalledName

    HOST-RESOURCES-MIB::hrSWInstalledName.1 = STRING: "VMware  Tools"
    HOST-RESOURCES-MIB::hrSWInstalledName.2 = STRING: "WebFldrs"
    ```

6.  以及使用相同工具枚举开放的 TCP 端口：

    ```
    snmpwalk -c public 192.168.10.200 -v 1 | grep tcpConnState |  cut -d"." -f6 | sort –nu

    21
    25
    80
    443
    ```

7.  另一个通过 SNMP 收集信息的工具叫做`snmpcheck`：

    ```
    cd /usr/bin
    snmpcheck -t 192.168.10.200
    ```

8.  为了使用 fierce（一个尝试多种技术来寻找所有目标所用的 IP 地址和域名的工具）进行域名扫描，我们可以键入以下命令：

    ```
    cd /usr/bin
    fierce -dns adomainnameontheinternet.com
    ```

    > 请不要在不属于你的公共网站或者不是你自己的服务器上运行这个工具。这里我们将`adomainnameontheinternet.com`作为一个例子，你应该替换掉这个目标。要当心！

9.  为了以指定的词语列表进行相同的操作，键入以下命令：

    ```
    fierce -dns adomainnameontheinternet.com -wordlist  hosts.txt -file /tmp/output.txt
    ```

0.  为了在 SMTP 服务器上启动用户的 SMTP 枚举，键入以下命令：

    ```
    smtp-user-enum -M VRFY -U /tmp/users.txt -t 192.168.10.200
    ```

1.  我们现在可以记录所获得的结果了。

## 4.2 判断网络范围

使用上一节中我们所收集的信息，我们就能着眼于判断目标网络的 IP 地址范围。在这个秘籍中我们将要探索完成它所用的工具。

### 操作步骤

让我们通过打开终端窗口来开始判断网络范围：

1.  打开新的终端窗口，并且键入以下命令：

    ```
    dmitry -wnspb targethost.com -o /root/Desktop/dmitry-result
    ```

2.  完成之后，我们应该在桌面上得到了一个文本文件，名称为`dmitry-result.txt`，含有收集到的目标信息：

    ![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-cb/img/4-2-1.jpg)

3.  键入以下命令来执行 ICMP netmask 请求：

    ```
    netmask -s targethost.com
    ```

4.  使用 scapy，我们就可以执行并行路由跟踪。键入以下命令来启动它：

    ```
    scapy
    ```

5.  scapy 启动之后，我们现在可以输入以下函数：

    ```
    ans,unans=sr(IP(dst="www.targethost.com/30", ttl=(1,6))/TCP()
    ```

6.  我们可以输入以下函数来将结果展示为表格：

    ```
    ans.make_table( lambda (s,r): (s.dst, s.ttl, r.src) )
    ```

    结果如下：

    ```
    216.27.130.162  216.27.130.163  216.27.130.164 216.27.130.165  
    1 192.168.10.1   192.168.10.1    192.168.10.1   192.168.10.1     
    2 51.37.219.254  51.37.219.254   51.37.219.254  51.37.219.254   
    3 223.243.4.254  223.243.4.254   223.243.4.254  223.243.4.254   
    4 223.243.2.6    223.243.2.6     223.243.2.6    223.243.2.6     
    5 192.251.254.1  192.251.251.80  192.251.254.1  192.251.251.80
    ```

7.  我们需要键入以下函数来使用 scapy 获得 TCP 路由踪迹：

    ```
    res,unans=traceroute(["www.google.com","www.Kali- linux.org","www.targethost.com"],dport=[80,443],maxttl=20, retry=-2)
    ```

8.  我们只需要键入以下函数来将结果展示为图片：

    ```
    res.graph()
    ```

    ![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-cb/img/4-2-2.jpg)

9.  保存图片只需要下列命令：

    ```
    res.graph(target="> /tmp/graph.svg")
    ```

0.  我们可以生成 3D 展示的图片，通过键入下列函数来实现：

    ```
    res.trace3D()
    ```

1.  键入以下命令来退出 scapy：

    ```
    exit()
    ```

2.  在获得结果之后，我们现在可以对其做记录。

### 工作原理

在步骤 1 中，我们使用了`dmitry`来获取目标信息。参数`-wnspub`允许我们在域名上执行 WHOIS 查询，检索`Netcraft.com`的信息，搜索可能的子域名，以及扫描 TCP 端口。选项`-o`允许我们将结果保存到文本文件中。在步骤 3 中，我们建立了一个简单的 ICMP netmask 请求，带有`-s`选项，来输出 IP 地址和子网掩码。接下来，我们使用 scapy 来执行目标上的并行路由跟踪，并在表格中展示结果。在步骤 7 中，我们在不同主机的 80 和 443 端口上执行了 TCP 路由跟踪，并且将最大 TTL 设置为 20 来停止这个过程。在获得结果之后，我们创建了它的图片表示，将它保存到临时目录中，同时创建了相同结果的 3D 表示。最后，我们退出了 scapy。

## 4.3 识别活动主机

在尝试渗透之前，我们首先需要识别目标网络范围内的活动主机。

一个简单的方法就是对目标网络执行`ping`操作。当然，这可以被主机拒绝或忽略，这不是我们希望的。

### 操作步骤

让我们打开终端窗口，开始定位活动主机：

1.  我们可以使用 Nmap 来判断某个主机是否打开或关闭，像下面这样：

    ```
    nmap -sP 216.27.130.162

    Starting Nmap 5.61TEST4 ( http://nmap.org ) at 2012-04-27  23:30 CDT
    Nmap scan report for test-target.net (216.27.130.162)
    Host is up (0.00058s latency).
    Nmap done: 1 IP address (1 host up) scanned in 0.06 seconds
    ```

2.  我们也可以使用 Nping（Nmap 组件），它提供给我们更详细的结果：

    ```
    nping --echo-client "public" echo.nmap.org
    ```

    ![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-cb/img/4-3-1.jpg)

3.  我们也可以向指定端口发送一些十六进制数据：

    ```
    nping -tcp -p 445 –data AF56A43D 216.27.130.162
    ```

## 4.4 寻找开放端口

在了解目标网络范围和活动主机之后，我们需要执行端口扫描操作来检索开放的 TCP 和 UDP 端口和接入点。

### 准备

完成这个秘籍需要启动 Apache Web 服务器。

### 操作步骤

让我们通过打开终端窗口，开始寻找开放端口：

1.  运行终端窗口并输入下列命令作为开始：

    ```
    nmap 192.168.56.101
    ```

    ![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-cb/img/4-4-1.jpg)

2.  我们也可以显式指定要扫描的端口（这里我们指定了 1000 个端口）：

    ```
    nmap -p 1-1000 192.168.56.101
    ```

    ![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-cb/img/4-4-2.jpg)

3.  或指定 Nmap 来扫描某个组织所有网络的 TCP 22 端口：

    ```
    nmap -p 22 192.168.56.*
    ```

    ![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-cb/img/4-4-3.jpg)

4.  或者以特定格式输出结果：

    ```
    nmap -p 22 192.168.10.* -oG /tmp/nmap-targethost-tcp445.tx
    ```

### 工作原理

这个秘籍中，我们使用 Nmap 来扫描我们网络上的目标主机，并判断开放了哪个端口。


### 更多

Nmap 的 GUI 版本叫做 Zenmap，它可以通过在终端上执行`zenmap`命令，或者访问`Applications | Kali Linux | Information Gathering | Network Scanners | zenmap`来启动。

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-cb/img/4-4-4.jpg)

## 4.5 操作系统指纹识别

到信息收集的这个步骤，我们应该记录了一些 IP 地址，活动主机，以及所识别的目标组织的开放端口。下一步就是判断活动主机上运行的操作系统，以便了解我们所渗透的系统类型。

### 准备

需要用到 Wireshark 捕获文件来完成这个秘籍的步骤 2。

### 操作步骤

让我们在终端窗口中进行 OS 指纹识别：

1.  我们可以使用 Nmap 执行下列命令，带有`-O`命令来开启 OS 检测功能：

    ```
    nmap -O 192.168.56.102
    ```

    ![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-cb/img/4-5-1.jpg)

2.  使用`p0f`来分析 Wireshark 捕获文件：

    ```
    p0f -s /tmp/targethost.pcap -o p0f-result.log -l

    p0f - passive os fingerprinting utility, version 2.0.8
    (C) M. Zalewski <lcamtuf@dione.cc>, W. Stearns  
    <wstearns@pobox.com>
    p0f: listening (SYN) on 'targethost.pcap', 230 sigs (16  generic), rule: 'all'.
    [+] End of input file.
    ```

## 4.6 服务指纹识别

判断运行在特定端口上的服务是目标网络上成功渗透的保障。它也会排除任何由 OS 指纹之别产生的疑惑。

### 操作步骤

让我们通过开始终端窗口来进行服务指纹识别：

1.  打开终端窗口并键入以下命令：

    ```
    nmap -sV 192.168.10.200

    Starting Nmap 5.61TEST4 ( http://nmap.org ) at 2012-03-28  05:10 CDT
    Interesting ports on 192.168.10.200:
    Not shown: 1665 closed ports
    PORT STATE SERVICE VERSION
    21/tcp open ftp Microsoft ftpd 5.0
    25/tcp open smtp Microsoft ESMTP 5.0.2195.6713
    80/tcp open http Microsoft IIS webserver 5.0
    119/tcp open nntp Microsoft NNTP Service 5.0.2195.6702  (posting ok)
    135/tcp open msrpc Microsoft Windows RPC
    139/tcp open netbios-ssn
    443/tcp open https?
    445/tcp open microsoft-ds Microsoft Windows 2000 microsoft-ds
    1025/tcp open mstask Microsoft mstask
    1026/tcp open msrpc Microsoft Windows RPC
    1027/tcp open msrpc Microsoft Windows RPC
    1755/tcp open wms?
    3372/tcp open msdtc?
    6666/tcp open nsunicast Microsoft Windows Media Unicast  Service (nsum.exe)

    MAC Address: 00:50:56:C6:00:01 (VMware)
    Service Info: Host: DC; OS: Windows

    Nmap finished: 1 IP address (1 host up) scanned in 63.311  seconds
    ```

2.  我们也可以使用`amap`来识别运行在特定端口或端口范围内的应用，比如下面这个例子：

    ```
    amap -bq 192.168.10.200 200-300

    amap v5.4 (www.thc.org/thc-amap) started at 2012-03-28  06:05:30 - MAPPING mode
    Protocol on 127.0.0.1:212/tcp matches ssh - banner: SSH-2.0- OpenSSH_3.9p1\n
    Protocol on 127.0.0.1:212/tcp matches ssh-openssh - banner:  SSH-2.0-OpenSSH_3.9p1\n
    amap v5.0 finished at 2005-07-14 23:02:11
    ```

## 4.7 Maltego 风险评估

在这个秘籍中，我们将要开始使用 Maltego 的特殊 Kali 版本，它可以在信息收集阶段协助我们，通过将获得的信息以易于理解的形式展示。Maltego 是开源的风险评估工具，被设计用来演示网络上故障单点的复杂性和严重性。它也具有从内部和外部来源聚合信息来提供简洁的风险图表的能力。

### 准备

需要一个账号来使用 Maltego。访问[https://www.paterva.com/web6/community/](https://www.paterva.com/web6/community/)来注册账号。

### 操作步骤

让我们从启动 Maltego 开始：

1.  访问` Applications | Kali Linux | Information Gathering | OSINT Analysis | maltego`来启动 Maltego。窗口如下：

    ![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-cb/img/4-7-1.jpg)

2.  点击开始向导的`Next`来查看登录细节：

    ![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-cb/img/4-7-2.jpg)

3.  点击`Next`来验证我们的登录凭证。验证之后，点击`Next`以继续：

4.  选择 transform seed 设置，之后点击`Next`：

    ![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-cb/img/4-7-3.jpg)

5.  这个向导在跳到下个页面之前会执行多次操作。完成之后，选择`Open a blank graph and let me play around`并点击`Finish`。

    ![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-cb/img/4-7-4.jpg)

6.  最开始，将`Domain`实体从`Palette`组件拖放到`New Graph`标签页中。

    ![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-cb/img/4-7-5.jpg)

7.  通过点击创建的`Domain`实体来设置目标域名，并且编辑`Property View`中的`Domain Name`属性。

    ![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-cb/img/4-7-6.jpg)

8.  目标一旦设置好，我们就可以开始收集信息了。最开始，右键点击创建的`Domain`实体，并且选择`Run Transform`来显示可用的选项：

    ![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-cb/img/4-7-7.jpg)

9.  我们可以选择查找 DNS 名称，执行 WHOIS 查询，获得邮件地址，以及其它。或者我们还可以选择运行下面展示的全部转换。

    ![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-cb/img/4-7-8.jpg)

0.  我们甚至可以通过在链接的子节点上执行相同操作，来获得更多信息，直到我们找到了想要的信息。

### 工作原理

在这个秘籍中，我们使用 Maltego 来映射网络。Maltego 是一个开源工具，用于信息收集和取证，由 Paterva 出品。我们通过完成开始向导来开始这个秘籍。之后我们使用`Domain`实体，通过将它拖到我们的图表中。最后，我们让 Maltego 完成我们的图表，并且查找各种来源来完成任务。Maltego 十分有用，因为我们可以利用这一自动化的特性来快速收集目标信息，例如收集邮件地址、服务器的信息、执行 WHOIS 查询，以及其它。

> 社区版只允许我们在信息收集中使用 75 个转换。Maltego 的完整版需要$650。

### 更多

启用和禁用转换可以通过`Manage`标签栏下方的`Transform Manager`窗口设置：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-cb/img/4-7-9.jpg)

一些转换首先需要接受才可以使用。

## 4.8 映射网络

使用前面几个秘籍获得的信息，我们就可以创建该组织网络的蓝图。在这一章的最后一个·秘籍中，我们会了解如何使用 Maltego CaseFile 来可视化地编译和整理所获得的信息。

`CaseFile`就像开发者的网站上那样，相当于不带转换的 Maltego，但拥有大量特性。多数特性会在这个秘籍的“操作步骤”一节中展示。

### 操作步骤

当我们从启动 CaseFile 来开始：

1.  访问`Applications | Kali Linux | Reporting Tools | Evidence Management | casefile`来启动 CaseFile。

2.  点击 CaseFile 应用菜单的`New`来创建新的图表：

    ![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-cb/img/4-8-1.jpg)

3.  就像 Maltego 那样，我们将每个实体从`Palette`组建拖放到图表标签页中。让我们从拖放`Domain`实体以及修改`Domain Name`属性来开始。

    ![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-cb/img/4-8-2.jpg)

4.  将鼠标指针置于实体上方，并且双击注解图标来添加注解。

    ![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-cb/img/4-8-3.jpg)

5.  让我们拖放另一个实体来记录目标的 DNS 信息：

    ![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-cb/img/4-8-4.jpg)

6.  链接实体只需要在实体之前拖出一条线：

    ![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-cb/img/4-8-5.jpg)

7.  按需自定义链接的属性：

    ![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-cb/img/4-8-6.jpg)

8.  重复步骤 5~7 来向图中添加更多关于该组织网络的信息。

    ![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-cb/img/4-8-7.jpg)

9.  最后我们保存了信息图表。图表的记录可以在之后打开和编辑，如果我们需要的话，和我们从已知目标获得更多信息的情况一样。

### 工作原理

在这个秘籍中，我们使用 Maltego CaseFile 来映射网络。CaseFile 是个可视化的智能应用，可以用于判断数百个不同类型信息之间的关系和现实世界的联系。它的本质是离线情报，也就是说它是个手动的过程。我们以启动 CaseFile 并且创建新的图表作为开始。接下来，我们使用了收集到或已知的目标网络信息，并且开始向图表中添加组件来做一些设置。最后保存图表来结束这个秘籍。

### 更多

我们也可以加密图表记录，使它在公众眼里更安全。为了加密图表，需要在保存的时候选择`Encrypt (AES-128)`复选框并提供一个密码。


# 第五章：漏洞评估

> 作者：Willie L. Pritchett, David De Smet

> 译者：[飞龙](https://github.com/)

> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

## 简介

扫描和识别目标的漏洞通常被渗透测试者看做无聊的任务之一。但是，它也是最重要的任务之一。这也应该被当做为你的家庭作业。就像在学校那样，家庭作业和小测验的设计目的是让你熟练通过考试。

漏洞识别需要你做一些作业。你会了解到目标上什么漏洞更易于利用，便于你发送威力更大的攻击。本质上，如果攻击者本身就是考试，那么漏洞识别就是你准备的机会。

Nessus 和 OpenVAS 都可以扫描出目标上相似的漏洞。这些漏洞包括：

+ Linux 漏洞
+ Windows 漏洞
+ 本地安全检查
+ 网络服务漏洞

## 5.1 安装、配置和启动 Nessus

在这个秘籍中，我们会安装、配置和启动 Nessus。为了在我们所选的目标上定位漏洞，Nessus 的漏洞检测有两种版本：家庭版和专业版。

+ 家庭版：家庭版用于非商业/个人用途。以任何原因在专业环境下适用 Nessus 都需要使用专业版。
+ 上夜班：专业版用于商业用途。它包括支持和额外特性，例如无线的并发连接数，以及其它。如果你是一个顾问，需要对某个客户执行测试，专业版就是为你准备的。

对于我们的秘籍，我们假定你使用家庭版。

### 准备

需要满足下列需求：

+ 需要网络连接来完成这个秘籍。
+ Nessus 家庭版的有效许可证。

### 操作步骤

让我们开始安装、配置和启动 Nessus， 首先打开终端窗口：

1.  打开 Web 浏览器，访问这个网址：<http://www. tenable.com/products/nessus/select-your-operating-system>。

2.  在屏幕的左侧，`Download Nessus`的下面，选择`Linux`并且选择`Nessus-5.2.1-debian6_amd64.deb`（或新版本）。

    ![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-cb/img/5-1-1.jpg)

3.  将文件下载到本地根目录下。

    ![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-cb/img/5-1-2.jpg)

4.  打开终端窗口

5.  执行下列命令来安装 Nessus：

    ```
    dpkg -i "Nessus-5.2.1-debian6_i386.deb"
    ```

    这个命令的输出展示在下面：

    ![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-cb/img/5-1-3.jpg)

6.  Nessus 会安装到`/opt/nessus`目录下。

7.  一旦安装好了，你就能通过键入下列命令启动 Nessus：

    ```
    /etc/init.d/nessusd start
    ```

    > 在你启动 Nessus 之前，你需要先拥有注册码。你可以从“更多”一节中得到更多信息。

8.  通过执行下列命令，激活你的 Nessus：

    ```
    /opt/nessus/bin/nessus-fetch --register XXXX-XXXX-XXXX-XXXX- XXXX
    ```

    这一步中，我们会从<http://plugins.nessus.org>获取新的插件。

    > 取决于你的网络连接，这可能需要一到两分钟。

9.  现在在终端中键入下列命令：

    ```
    /opt/nessus/sbin/nessus-adduser
    ```

0.  在登录提示框中，输入用户的登录名称。

1.  输入两次密码。

2.  回答 Y（Yes），将用户设置为管理员。

    > 这一步只需要在第一次使用时操作。

3.  完成后，你可以通过键入以下命令来启动 Nessus（没有用户账户则不能工作）。

4.  在<https://127.0.0.1:8834>上登录 Nessus。

    > 如果你打算使用 Nessus，要记得从安装在你的主机上 ，或者虚拟机上的 kali Linux 版本中访问。原因是，Nessus 会基于所使用的机器来激活自己。如果你安装到优盘上了，在每次重启后你都需要重新激活你的版本。

### 工作原理

在这个秘籍中，我们以打开终端窗口，并通过仓库来安装 Nessus 开始。之后我们启动了 Nessus，并为了使用它安装了我们的证书。

### 更多

为了注册我们的 Nessus 副本，你必须拥有有效的许可证，它可以从<http://www.tenable.com/products/nessus/nessus-homefeed>获取。而且，Nessus 运行为浏览器中的 Flash，所以首次启动程序时，你必须为 Firefox 安装 Flash 插件。如果你在使用 Flash 时遇到了问题，访问<www.get.adobe.com/flashplayer>来获得信息。

## 5.2 Nessus - 发现本地漏洞

现在我们已经安装并配置了 Nessus，我们将要执行第一次漏洞测试。Nessus 允许我们攻击很多种类的漏洞，它们取决于我们的版本。我们也需要评估的目标漏洞列表限制为针对我们想要获取的信息类型的漏洞。在这个秘籍中，我们将要以发现本地漏洞开始，这些漏洞针对我们当前使用的操作系统。

### 准备

为了完成这个秘籍，你将要测试你的本地系统（Kali Linux）。

### 操作步骤

让我们开始使用 Nessus 来发现本地漏洞，首先打开 Firefox 浏览器：

1.  在 <https://127.0.0.1:8834> 登录 Nessus。

2.  访问` Policies`。

3.  点击`New Policy`。

    ![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-cb/img/5-2-1.jpg)

4.  在`General Settings`标签页，进行如下操作：

    1.  在` Settings Type`中选择` Basic`。

    2.  为你的扫描输入一个名称。我们选择了`Local Vulnerability Assessment`，但你可以选择想要的其它名称。

    3.  有两个可见性的选择：‘

        +   `Shared`：其它用户可以利用这次扫描。

        +   `Private`：这次扫描只能被你使用。

    4.  其它项目保留默认。

    5.  点击`Update`。

5.  在`Plugins`标签页中，选择`Disable All`并选择下列特定的漏洞：

    1.  `Ubuntu Local Security Checks `。

    2.  ` Default Unix Accounts`。

    ![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-cb/img/5-2-2.jpg)

6.  点击`Update`来保存新的策略。

7.  在主菜单中，点击`Scan Queue`菜单选项。

8.  点击`New Scan`按钮并进行如下操作：

    1.  为你的扫描输入名称。如果你一次运行多个扫描，这会非常有用。这是区分当前运行的不同扫描的方式。

    2.  输入扫描类型：

        +   `Run Now`：默认开启，这个选项会立即运行扫描。

        +   `Scehduled`：允许你选择日期和时间来运行扫描。

        +   `Template`：将扫描设置为模板。

    3.  选择扫描策略。这里，我们选择之前创建的`Local Vulnerabilities Assessment`策略。

    4.  选择你的目标，包含下列要点：

        +   目标必须每行输入一个。

        +   你也可以在每行输入目标的范围。

    5.  你也可以上传目标文件（如果有的话）或选择` Add Target  IP Address`。

9.  点击`Run Scan`：

    ![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-cb/img/5-2-3.jpg)

0.  你会被要求确认，你的测试将会执行（取决于你选择了多少目标，以及要执行多少测试）。

1.  一旦完成了，你会收到一份报告。

2.  双击报告来分析下列要点（在`Results`标签页中）：

    +   每个发现了漏洞的目标会被列出。

    +   双击 IP 地址来观察端口，和每个端口的问题。

    +   点击列下方的数字，来获得所发现的特定漏洞的列表。

    +   漏洞会详细列出。

3.  点击`Reports`主菜单中的` Download Report `。

## 5.3 Nessus -  发现网络漏洞

Nessus 允许我们攻击很多种类的漏洞，它们取决于我们的版本。我们也需要评估的目标漏洞列表限制为针对我们想要获取的信息类型的漏洞。这个秘籍中，我们会配置 Nessus 来发现目标上的网络漏洞。这些漏洞针对主机或网络协议。

### 准备

为了完成这个秘籍，你需要被测试的虚拟机。

+ Windows XP
+ Windows 7
+ Metasploitable 2.0
+ 网络防火墙或路由
+ 任何其它 Linux 版本

### 操作步骤

让我们开始使用 Nessus 来发现本地漏洞，首先打开 Firefox 浏览器：

1.  在 <https://127.0.0.1:8834> 登录 Nessus。

2.  访问` Policies`。

3.  点击`Add Policy`。

    ![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-cb/img/5-3-1.jpg)

4.  在`General`标签页，进行如下操作：

    1.  为你的扫描输入一个名称。我们选择了`Internal Network Scan`，但你可以选择想要的其它名称。

    2.  有两个可见性的选择：‘

        +   `Shared`：其它用户可以利用这次扫描。

        +   `Private`：这次扫描只能被你使用。

    3.  其它项目保留默认。

    4.  点击`Update`。

5.  在`Plugins`标签页中，点击` Disable All `并选择下列特定的漏洞：

    +   `CISCO`     
    +   `DNS`     
    +   `Default Unix Accounts`     
    +   `FTP`     
    +   `Firewalls`     
    +   `Gain a shell remotely`     
    +   `General`     
    +   `Netware`     
    +   `Peer-To-Peer File Sharing`     
    +   `Policy Compliance`     
    +   `Port Scanners`     
    +   `SCADA`     
    +   `SMTP Problems`     
    +   `SNMP`     
    +   `Service Detection`     
    +   `Settings`

    ![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-cb/img/5-3-2.jpg)

6.  点击`Update`来保存新的策略。

7.  在主菜单中，点击`Scan Queue`菜单选项。

8.  点击`New Scan`按钮并进行如下操作：

    1.  为你的扫描输入名称。如果你一次运行多个扫描，这会非常有用。这是区分当前运行的不同扫描的方式。

    2.  输入扫描类型：

        +   `Run Now`：默认开启，这个选项会立即运行扫描。

        +   `Scehduled`：允许你选择日期和时间来运行扫描。

        +   `Template`：将扫描设置为模板。

    3.  选择扫描策略。这里，我们选择之前创建的`Internal Network Scan`策略。

    4.  选择你的目标，包含下列要点：

        +   目标必须每行输入一个。

        +   你也可以在每行输入目标的范围。

    5.  你也可以上传目标文件（如果有的话）或选择` Add Target  IP Address`。

9.  点击`Run Scan`：

    ![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-cb/img/5-3-3.jpg)

0.  你会被要求确认，你的测试将会执行（取决于你选择了多少目标，以及要执行多少测试）。

    ![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-cb/img/5-3-4.jpg)

1.  一旦完成了，你会收到一份报告，它在`Results`标签页中。

2.  双击报告来分析下列要点（在`Results`标签页中）：

    +   每个发现了漏洞的目标会被列出。

    +   双击 IP 地址来观察端口，和每个端口的问题。

    +   点击列下方的数字，来获得所发现的特定问题/漏洞的列表。

    +   漏洞会详细列出。

3.  点击`Reports`主菜单中的` Download Report `。

## 5.4 发现 Linux 特定漏洞

在这个秘籍中，我们会使用 Nessus 探索如何发现 Linux 特定漏洞。这些漏洞针对网络上运行 Linux 的主机。

### 准备

为了完成这个秘籍，你需要被测试的虚拟机：

+  Metasploitable 2.0
+  其它 Linux 版本

### 操作步骤

让我们开始使用 Nessus 来发现 Linux 特定漏洞，首先打开 Firefox 浏览器：

1.  在 <https://127.0.0.1:8834> 登录 Nessus。

2.  访问` Policies`。

3.  点击`Add Policy`。

    ![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-cb/img/5-4-1.jpg)

4.  在`General Settings `标签页，进行如下操作：

    1.  为你的扫描输入一个名称。我们选择了`Linux Vulnerability Scan`，但你可以选择想要的其它名称。

    2.  有两个可见性的选择：‘

        +   `Shared`：其它用户可以利用这次扫描。

        +   `Private`：这次扫描只能被你使用。

    3.  其它项目保留默认。

5.  在`Plugins`标签页中，点击` Disable All `并选择下列特定的漏洞。当我们扫描可能在我们的 Linux 目标上运行的服务时，这份列表会变得很长：

    +   `Backdoors`
    +   `Brute Force Attacks`
    +   `CentOS Local Security Checks`
    +   `DNS`  
    +   `Debian Local Security Checks`  
    +   `Default Unix Accounts`  
    +   `Denial of Service`  
    +   `FTP`  
    +   `Fedora Local Security Checks`  
    +   `Firewalls`  
    +   `FreeBSD Local Security Checks`  
    +   `Gain a shell remotely`  
    +   `General`  
    +   `Gentoo Local Security Checks`  
    +   `HP-UX Local Security Checks`  
    +   `Mandriva Local Security Checks`  
    +   `Misc`  
    +   `Port Scanners`  
    +   `Red Hat Local Security Checks`  
    +   `SMTP Problems`  
    +   `SNMP`  
    +   `Scientific Linux Local Security Checks`  
    +   `Slackware Local Security Checks`  
    +   `Solaris Local Security Checks`
    +   `SuSE Local Security Checks`  
    +   `Ubuntu Local Security Checks`  
    +   `Web Servers`

    ![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-cb/img/5-4-2.jpg)

6.  点击`Update`来保存新的策略。

7.  在主菜单中，点击`Scan Queue`菜单选项。

8.  点击`New Scan`按钮并进行如下操作：

    1.  为你的扫描输入名称。如果你一次运行多个扫描，这会非常有用。这是区分当前运行的不同扫描的方式。

    2.  输入扫描类型：

        +   `Run Now`：默认开启，这个选项会立即运行扫描。

        +   `Scehduled`：允许你选择日期和时间来运行扫描。

        +   `Template`：将扫描设置为模板。

    3.  选择扫描策略。这里，我们选择之前创建的`Linux Vulnerabilities Scan`策略。

    4.  选择你的目标，包含下列要点：

        +   目标必须每行输入一个。

        +   你也可以在每行输入目标的范围。

        +   上传目标文件（如果有的话）或选择` Add Target  IP Address`。

9.  点击`Launch Scan`：

    ![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-cb/img/5-4-3.jpg)

0.  你会被要求确认，你的测试将会执行（取决于你选择了多少目标，以及要执行多少测试）。

1.  一旦完成了，你会收到一份报告，它在 `Reports`标签页中。

2.  双击报告来分析下列要点：

    +   每个发现了漏洞的目标会被列出。

    +   双击 IP 地址来观察端口，和每个端口的问题。

    +   点击列下方的数字，来获得所发现的特定问题/漏洞的列表。

    +   漏洞会详细列出。

3.  点击`Reports`主菜单中的` Download Report `。

## 5.5 Nessus - 发现 Windows 特定的漏洞

在这个秘籍中，我们会使用 Nessus 探索如何发现 Windows 特定漏洞。这些漏洞针对网络上运行 Windows 的主机。

### 准备

为了完成秘籍，你需要被测试的虚拟机：

+ Windows XP
+ Windows 7

### 操作步骤

让我们开始使用 Nessus 发现 Windows 特定的漏洞，首先打开 Firefox 浏览器：

1.  在 <https://127.0.0.1:8834> 登录 Nessus。

2.  访问` Policies`。

3.  点击`Add Policy`。

    ![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-cb/img/5-5-1.jpg)

4.  在`General Settings `标签页，进行如下操作：

    1.  为你的扫描输入一个名称。我们选择了` Windows Vulnerability Scan`，但你可以选择想要的其它名称。

    2.  有两个可见性的选择：‘

        +   `Shared`：其它用户可以利用这次扫描。

        +   `Private`：这次扫描只能被你使用。

    3.  其它项目保留默认。

    4.  点击`Submit`。

5.  在`Plugins`标签页中，点击` Disable All `并选择下列特定的漏洞。它们可能出现在 Windows 系统中：

    +   DNS  Databases  
    +   Denial of Service  
    +   FTP  
    +   SMTP Problems  
    +   SNMP  Settings  
    +   Web Servers  
    +   Windows  
    +   Windows: Microsoft Bulletins  
    +   Windows: User management

    ![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-cb/img/5-5-2.jpg)

6.  点击`Submit`来保存新的策略。

7.  在主菜单中，点击`Scan`菜单选项。

8.  点击`Add Scan`按钮并进行如下操作：

    1.  为你的扫描输入名称。如果你一次运行多个扫描，这会非常有用。这是区分当前运行的不同扫描的方式。

    2.  输入扫描类型：

        +   `Run Now`：默认开启，这个选项会立即运行扫描。

        +   `Scehduled`：允许你选择日期和时间来运行扫描。

        +   `Template`：将扫描设置为模板。

    3.  选择扫描策略。这里，我们选择之前创建的`Windows Vulnerabilities Scan`策略。

    4.  选择你的目标，包含下列要点：

        +   目标必须每行输入一个。

        +   你也可以在每行输入目标的范围。

        +   上传目标文件（如果有的话）或选择` Add Target  IP Address`。

9.  点击`Launch Scan`：

    ![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-cb/img/5-5-3.jpg)

0.  你会被要求确认，你的测试将会执行（取决于你选择了多少目标，以及要执行多少测试）。

1.  一旦完成了，你会收到一份报告，它在 `Reports`标签页中。

2.  双击报告来分析下列要点：

    +   每个发现了漏洞的目标会被列出。

    +   双击 IP 地址来观察端口，和每个端口的问题。

    +   点击列下方的数字，来获得所发现的特定问题/漏洞的列表。

    +   漏洞会详细列出。

3.  点击`Reports`主菜单中的` Download Report `。

## 5.6 安装、配置和启动 OpenVAS

OpenVAS，即开放漏洞评估系统，是一个用于评估目标漏洞的杰出框架。它是 Nessus 项目的分支。不像 Nessus，OpenVAS 提供了完全免费的版本。由于 OpenVAS 在 Kali Linux 中成为标准，我们将会以配置开始。

### 准备

需要网络连接。

### 操作步骤

让我们开始安装、配置和启动 OpenVAS，首先在终端窗口中访问它的路径。

1.  OpenVAS 默认安装，并且只需要配置便于使用。

2.  在终端窗口中，将路径变为 OpenVAS 的路径：

    ```
    cd /usr/share/openvas
    ```

3.  执行下列命令：

    ```
    openvas-mkcert
    ```

    这一步我们为 OpenVAS 创建了 SSL 证书。

    1.  保留 CA 的默认生命周期。

    2.  更新证书的生命周期，来匹配 CA 证书的天数：`1460`。

    3.  输入国家或地区。

    4.  输入州或省。

    5.  组织名称保留默认。

    6.  你会看到证书确认界面，之后按下回车键来退出。

    ![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-cb/img/5-6-1.jpg)

4.  执行下列命令：

    ```
    openvas-nvt-sync
    ```

    这会将 OpenVAS NVT 数据库和当前的 NVT 版本同步。也会更新到最新的漏洞检查。

    ![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-cb/img/5-6-2.jpg)

5.  执行下列命令：

    ```
    openvas-mkcert-client -n om -i
    openvasmd -rebuild
    ```

    这会生成客户证书并分别重构数据库。

6.  执行下列命令：

    ```
    openvassd
    ```

    这会启动 OpenVAS 扫描器并加载所有插件（大约 26406 个），所以会花一些时间。

7.  执行下列命令：

    ```
    openvasmd --rebuild
    openvasmd --backup
    ```

8.  执行下列命令来创建你的管理员用户（我们使用 `openvasadmin`）：

    ```
    openvasad -c  'add_user' -n openvasadmin -r admin
    ```

    ![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-cb/img/5-6-3.jpg)

9.  执行下列命令：

    ```
    openvas-adduser
    ```

    这会让你创建普通用户：

    1.  输入登录名称。

    2.  在校验请求上按下回车键（这会自动选择密码）。

    3.  输入两次密码。

    4.  对于规则，按下`Ctrl + D`。

    5.  按下`Y`来添加用户。

    ![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-cb/img/5-6-4.jpg)

0.  执行下列命令来配置 OpenVAS 的交互端口：

    ```
    openvasmd -p 9390 -a 127.0.0.1
    openvasad -a 127.0.0.1 -p 9393
    gsad --http-only --listen=127.0.0.1 -p 9392
    ```

    > 9392 是用于 Web 浏览器的推荐端口，但是你可以自己选择。

1.  访问<http://127.0.0.1:9392>，在你的浏览器中查看 OpenVAS 的 Web 界面。

    ![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-cb/img/5-6-5.jpg)

### 工作原理

在这个秘籍中，我们以打开终端窗口并通过仓库安装 OpenVAS 来开始。之后我们创建了一个证书并安装我们的插件数据库。然后，我们创建了一个管理员和一个普通用户账号。最后，我们启动了 OpenVAS 的 Web 界面并展示了登录界面。

> 每次你在 OpenVAS 中执行操作的时候，你都需要重建数据库。

### 更多

这一节展示了除了启动 OpenVAS 之外的一些附加信息。

**编写 SSH 脚本来启动 OpenVAS**

每次你打算启动 OpenVAS 的时候，你需要：

1.  同步 NVT 版本（这非常不错，因为这些项目会在新漏洞发现的时候更改）。

2.  启动 OpenVAS 扫描器。

3.  重建数据库。

4.  备份数据库。

5.  配置你的端口。

为了节省时间，下面的简单 Bash 脚本可以让你启动 OpenVAS。把文件保存为` OpenVAS.sh`，并放在你的`/root`文件夹中：

```sh
#!/bin/bash
openvas-nvt-sync
openvassd
openvasmd --rebuild
openvasmd --backup
openvasmd -p 9390 -a 127.0.0.1
openvasad -a 127.0.0.1 -p 9393
gsad --http-only --listen=127.0.0.1 -p 9392
```

**使用 OpenVAS 桌面**

你可以选择通过 OpenVAS 桌面来执行相同步骤。OpenVAS 桌面是一个 GUI 应用。为了启动这个应用：

1.  在 Kali Linux 的桌面的启动菜单中，访问`Applications | Kali Linux | Vulnerability Assessment | Vulnerability Scanners | OpenVAS | Start GreenBone Security Desktop`，就像下面展示的那样：

    ![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-cb/img/5-6-6.jpg)

2.  将服务器地址输入为`127.0.0.1`。

3.  输入你的用户名。

4.  输入你的密码。

5.  点击`Log in`按钮。

## 5.7 OpenVAS - 发现本地漏洞

OpenVAS 允许我们攻击很多种类的漏洞，它们取决于我们的版本。我们也需要评估的目标漏洞列表限制为针对我们想要获取的信息类型的漏洞。在这个秘籍中，我们将要使用 OpenVAS 扫描目标上的本地漏洞，这些漏洞针对我们当前的本地主机。

### 操作步骤

让我们以使用 OpenVAS 发现本地漏洞开始，首先打开 Firefox 浏览器：

1.  访问<http://127.0.0.1:9392>并登陆 OpenVAS。

2.  访问` Configuration | Scan Configs`。

    ![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-cb/img/5-7-1.jpg)

3.  输入扫描的名称。这个秘籍中，我们使用` Local Vulnerabilities`。

4.  我们选择`Empty, static and fast`选项。这个选项可以让我们从零开始并创建我们自己的配置。

5.  点击` Create Scan Config`：

    ![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-cb/img/5-7-2.jpg)

6.  我们现在打算编辑我们的扫描配置。点击` Local Vulnerabilities`旁边的扳手图标。

    ![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-cb/img/5-7-3.jpg)

7.  按下`Ctrl + F`并在查找框中输入`Local`。

8.  对于每个找到的本地族，点击` Select all NVT's `框中的复选框。族是一组漏洞。选择的漏洞为：

    + `Compliance`
    + `Credentials`
    + `Default Accounts`
    + `Denial of Service`
    + `FTP`
    + `Ubuntu Local Security Checks`

    ![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-cb/img/5-7-4.jpg)

9.  点击`Save Config`。

0.  访问`Configuration | Targets`：

    ![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-cb/img/5-7-5.jpg)

1.  创建新的目标并执行下列操作：

    1.  输入目标名称。

    2.  输入主机，通过下列方式之一：

        +   输入唯一的地址：`192.168.0.10 `

        +   输入多个地址，以逗号分隔：`192.168.0.10,192.168.0.115`

        +   输入地址范围：`192.168.0.1-20`

2.  点击` Create Target`。

3.  现在选择` Scan Management | New Task`，并执行下列操作：

    1.  输入任务名称。

    2.  输入注释（可选）。

    3.  选择你的扫描配置。这里是` Local Vulnerabilities`。

    4.  选择扫描目标。这里是`Local Network`。

    5.  所有其他选项保留默认。

    6.  点击` Create Task`。

    ![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-cb/img/5-7-6.jpg)

4.  现在访问` Scan Management | Tasks`。

5.  点击扫描旁边的播放按钮。这里是`Local Vulnerability Scan`：

    ![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-cb/img/5-7-7.jpg)

### 工作原理

这个秘籍中，我们启动 OpenVAS 并登入它的 Web 界面。之后我们配置了 OpenVAS 来搜索一系列本地漏洞。最后，我们选择了目标并完成了扫描。OpenVAS 之后扫描了目标系统上已知漏洞，包括我们的 NVT 版本。

### 更多

一旦执行了扫描，你可以通过查看报告来观察结果：

1.  访问` Scan Management | Tasks`。

2.  点击`Local Vulnerabilities Scan`旁边的放大镜图标：

    ![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-cb/img/5-7-8.jpg)

3.  点击下载箭头来查看报告：

    ![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-cb/img/5-7-9.jpg)

## 5.8 OpenVAS - 发现网络漏洞

在这个秘籍中，我们将要使用 OpenVAS 扫描目标上的网络漏洞，这些漏洞针对我们目标网络上的设备。

### 准备

为了完成这个秘籍，你需要被测试的虚拟机。

+ Windows XP
+ Windows 7
+ Metasploitable 2.0
+ 其它版本的 Linux

### 操作步骤

让我们以使用 OpenVAS 发现网络漏洞开始，首先打开 Firefox 浏览器：

1.  访问<http://127.0.0.1:9392>并登陆 OpenVAS。

2.  访问` Configuration | Scan Configs`。

    ![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-cb/img/5-8-1.jpg)

3.  输入扫描的名称。这个秘籍中，我们使用` Network Vulnerabilities`。

4.  我们选择`Empty, static and fast`选项。这个选项可以让我们从零开始并创建我们自己的配置。

5.  点击` Create Scan Config`：

    ![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-cb/img/5-8-2.jpg)

6.  我们现在打算编辑我们的扫描配置。点击` Network Vulnerabilities`旁边的扳手图标。

7.  按下`Ctrl + F`并在查找框中输入`Network `。

8.  对于每个找到的族，点击` Select all NVT's `框中的复选框。族是一组漏洞。选择的漏洞为：

    + `Brute force attacks`
    + `Buffer overflow`
    + `CISCO`
    + `Compliance`
    + `Credentials`
    + `Databases`
    + `Default Accounts`
    + `Denial of Service`
    + `FTP`
    + `Finger abuses`
    + `Firewalls`
    + `Gain a shell remotely`
    + `General`
    + `Malware`
    + `Netware`
    + `NMAP NSE`
    + `Peer-To-Peer File Sharing`
    + `Port Scanners`
    + `Privilege Escalation`
    + `Product Detection`
    + `RPC`
    + `Remote File Access`
    + `SMTP Problems`
    + `SNMP`
    + `Service detection`
    + `Settings`
    + `Wireless services`

    ![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-cb/img/5-8-3.jpg)

9.  点击`Save Config`。

0.  访问`Configuration | Targets`：

    ![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-cb/img/5-8-4.jpg)

1.  创建新的目标并执行下列操作：

    1.  输入目标名称。

    2.  输入主机，通过下列方式之一：

        +   输入唯一的地址：`192.168.0.10 `

        +   输入多个地址，以逗号分隔：`192.168.0.10,192.168.0.115`

        +   输入地址范围：`192.168.0.1-20`

2.  点击` Create Target`。

3.  现在选择` Scan Management | New Task`，并执行下列操作：

    1.  输入任务名称。

    2.  输入注释（可选）。

    3.  选择你的扫描配置。这里是` Network Vulnerabilities`。

    4.  选择扫描目标。这里是`Local Network`。

    5.  所有其他选项保留默认。

    6.  点击` Create Task`。

    ![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-cb/img/5-8-5.jpg)

4.  现在访问` Scan Management | Tasks`。

5.  点击扫描旁边的播放按钮。这里是`Network Vulnerability Scan`：

### 工作原理

这个秘籍中，我们启动 OpenVAS 并登入它的 Web 界面。之后我们配置了 OpenVAS 来搜索一系列网络漏洞。最后，我们选择了目标并完成了扫描。OpenVAS 之后扫描了目标系统上已知漏洞，包括我们的 NVT 版本。

### 更多

一旦执行了扫描，你可以通过查看报告来观察结果：

1.  访问` Scan Management | Tasks`。

2.  点击`Network Vulnerabilities Scan`旁边的放大镜图标：

3.  点击下载箭头来查看报告：

    ![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-cb/img/5-8-6.jpg)

## 5.9 OpenVAS - 发现 Linux 特定漏洞

在这个秘籍中，我们将要使用 OpenVAS 扫描 Linux 漏洞，这些漏洞针对我们目标网络上的 Linux 主机。

### 准备

为了完成这个秘籍，你需要被测试的虚拟机。

+ Metasploitable 2.0
+ 其它版本的 Linux

### 操作步骤

让我们以使用 OpenVAS 发现 Linux 特定漏洞开始，首先打开 Firefox 浏览器：

1.  访问<http://127.0.0.1:9392>并登陆 OpenVAS。

2.  访问` Configuration | Scan Configs`。

    ![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-cb/img/5-9-1.jpg)

3.  输入扫描的名称。这个秘籍中，我们使用`Linux Vulnerabilities`。

4.  我们选择`Empty, static and fast`选项。这个选项可以让我们从零开始并创建我们自己的配置。

5.  点击` Create Scan Config`：

    ![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-cb/img/5-9-2.jpg)

6.  我们现在打算编辑我们的扫描配置。点击`Linux Vulnerabilities`旁边的扳手图标。

7.  按下`Ctrl + F`并在查找框中输入`Linux`。

8.  对于每个找到的族，点击` Select all NVT's `框中的复选框。族是一组漏洞。选择的漏洞为：

    + `Brute force attacks`
    + `Buffer overflow`
    + `Compliance`
    + `Credentials`
    + `Databases`
    + `Default Accounts`
    + `Denial of Service`
    + `FTP`
    + `Finger abuses`
    + `Gain a shell remotely`
    + `General`
    + `Malware`
    + `Netware`
    + `NMAP NSE`
    + `Port Scanners`
    + `Privilege Escalation`
    + `Product Detection`
    + `RPC`
    + `Remote File Access`
    + `SMTP Problems`
    + `SNMP`
    + `Service detection`
    + `Settings`
    + `Wireless services`
    + `Web Server`

    ![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-cb/img/5-9-3.jpg)

9.  点击`Save Config`。

0.  访问`Configuration | Targets`：

1.  创建新的目标并执行下列操作：

    1.  输入目标名称。

    2.  输入主机，通过下列方式之一：

        +   输入唯一的地址：`192.168.0.10 `

        +   输入多个地址，以逗号分隔：`192.168.0.10,192.168.0.115`

        +   输入地址范围：`192.168.0.1-20`

2.  点击` Create Target`。

3.  现在选择` Scan Management | New Task`，并执行下列操作：

    1.  输入任务名称。

    2.  输入注释（可选）。

    3.  选择你的扫描配置。这里是`Linux Vulnerabilities`。

    4.  选择扫描目标。这里是`Local Network`。

    5.  所有其他选项保留默认。

    6.  点击` Create Task`。

    ![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-cb/img/5-9-4.jpg)

4.  现在访问` Scan Management | Tasks`。

5.  点击扫描旁边的播放按钮。这里是`Linux Vulnerability Scan`：

### 工作原理

这个秘籍中，我们启动 OpenVAS 并登入它的 Web 界面。之后我们配置了 OpenVAS 来搜索一系列 Linux 漏洞。最后，我们选择了目标并完成了扫描。OpenVAS 之后扫描了目标系统上已知漏洞，包括我们的 NVT 版本。

### 更多

一旦执行了扫描，你可以通过查看报告来观察结果：

1.  访问` Scan Management | Tasks`。

2.  点击`Linux Vulnerabilities Scan`旁边的放大镜图标：

3.  点击下载箭头来查看报告：

    ![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-cb/img/5-9-5.jpg)

## 5.10 OpenVAS - 发现 Windows 特定漏洞

在这个秘籍中，我们将要使用 OpenVAS 扫描 Windows 漏洞，这些漏洞针对我们目标网络上的 Windows 主机。

### 准备

为了完成这个秘籍，你需要被测试的虚拟机。

+ Windows XP
+ Windows 7

### 操作步骤

让我们以使用 OpenVAS 发现 Windows 特定漏洞开始，首先打开 Firefox 浏览器：

1.  访问<http://127.0.0.1:9392>并登陆 OpenVAS。

2.  访问` Configuration | Scan Configs`。

    ![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-cb/img/5-10-1.jpg)

3.  输入扫描的名称。这个秘籍中，我们使用`Windows Vulnerabilities`。

4.  我们选择`Empty, static and fast`选项。这个选项可以让我们从零开始并创建我们自己的配置。

5.  点击` Create Scan Config`：

    ![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-cb/img/5-10-2.jpg)

6.  我们现在打算编辑我们的扫描配置。点击`Windows Vulnerabilities`旁边的扳手图标。

7.  按下`Ctrl + F`并在查找框中输入`Windows`。

8.  对于每个找到的族，点击` Select all NVT's `框中的复选框。族是一组漏洞。选择的漏洞为：

    + `Brute force attacks`
    + `Buffer overflow`
    + `Compliance`
    + `Credentials`
    + `Databases`
    + `Default Accounts`
    + `Denial of Service`
    + `FTP`
    + `Gain a shell remotely`
    + `General`
    + `Malware`
    + `NMAP NSE`
    + `Port Scanners`
    + `Privilege Escalation`
    + `Product Detection`
    + `RPC`
    + `Remote File Access`
    + `SMTP Problems`
    + `SNMP`
    + `Service detection`
    + `Web Server`
    + `Windows`
    + `Windows: Microsoft Bulletins`

    ![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-cb/img/5-10-3.jpg)

9.  点击`Save Config`。

0.  访问`Configuration | Targets`：

    ![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-cb/img/5-10-5.jpg)

1.  创建新的目标并执行下列操作：

    1.  输入目标名称。

    2.  输入主机，通过下列方式之一：

        +   输入唯一的地址：`192.168.0.10 `

        +   输入多个地址，以逗号分隔：`192.168.0.10,192.168.0.115`

        +   输入地址范围：`192.168.0.1-20`

2.  点击` Create Target`。

3.  现在选择` Scan Management | New Task`，并执行下列操作：

    1.  输入任务名称。

    2.  输入注释（可选）。

    3.  选择你的扫描配置。这里是`Windows Vulnerabilities`。

    4.  选择扫描目标。这里是`Local Network`。

    5.  所有其他选项保留默认。

    6.  点击` Create Task`。

    ![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-cb/img/5-10-4.jpg)

4.  现在访问` Scan Management | Tasks`。

5.  点击扫描旁边的播放按钮。这里是`Windows Vulnerability Scan`：

### 工作原理

这个秘籍中，我们启动 OpenVAS 并登入它的 Web 界面。之后我们配置了 OpenVAS 来搜索一系列 Windows 漏洞。最后，我们选择了目标并完成了扫描。OpenVAS 之后扫描了目标系统上已知漏洞，包括我们的 NVT 版本。

### 更多

一旦执行了扫描，你可以通过查看报告来观察结果：

1.  访问` Scan Management | Tasks`。

2.  点击`Windows Vulnerabilities Scan`旁边的放大镜图标：

3.  点击下载箭头来查看报告：

    ![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-cb/img/5-9-5.jpg)
