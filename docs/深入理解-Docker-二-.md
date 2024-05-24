# 深入理解 Docker（二）

> 原文：[`zh.annas-archive.org/md5/8474E71CF7E3D29A70BB0D1BE42B1C22`](https://zh.annas-archive.org/md5/8474E71CF7E3D29A70BB0D1BE42B1C22)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第八章：容器

现在我们对镜像有了一些了解，是时候进入容器了。由于这是一本关于 Docker 的书，我们将专门讨论 Docker 容器。然而，Docker 一直在努力实现由开放容器倡议（OCI）在 https://www.opencontainers.org 发布的镜像和容器规范。这意味着你在这里学到的很多东西将适用于其他符合 OCI 标准的容器运行时。

我们将把本章分为通常的三个部分：

+   简而言之

+   深入探讨

+   命令

让我们去学习关于容器的知识吧！

### Docker 容器-简而言之

容器是镜像的运行时实例。就像我们可以从虚拟机模板启动虚拟机（VM）一样，我们可以从单个镜像启动一个或多个容器。容器和虚拟机之间的主要区别在于容器更快速和更轻量级-容器不像虚拟机一样运行完整的操作系统，而是与它们运行的主机共享操作系统/内核。

图 7.1 显示了一个 Docker 镜像被用来启动多个 Docker 容器。

![图 7.1](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-dpdv/img/figure7-1.png)

图 7.1

启动容器的最简单方法是使用`docker container run`命令。该命令可以带很多参数，但在其最基本的形式中，你告诉它要使用的镜像和要运行的应用程序：`docker container run <image> <app>`。下一个命令将启动一个运行 Bash shell 的 Ubuntu Linux 容器：`docker container run -it ubuntu /bin/bash`。要启动一个运行 PowerShell 应用程序的 Windows 容器，你可以这样做：`docker container run -it microsoft/powershell:nanoserver pwsh.exe`。

`-it`标志将把你当前的终端窗口连接到容器的 shell。

容器运行直到它们执行的应用退出。在上面的两个例子中，Linux 容器将在 Bash shell 退出时退出，而 Windows 容器将在 PowerShell 进程终止时退出。

一个非常简单的演示方法是启动一个新的容器，并告诉它运行 sleep 命令 10 秒钟。容器将启动，运行 10 秒钟然后退出。如果你从 Linux 主机（或在 Linux 容器模式下运行的 Windows 主机）运行以下命令，你的 shell 将附加到容器的 shell 上 10 秒钟，然后退出：`docker container run alpine:latest sleep 10`。你可以用以下命令在 Windows 容器中做同样的事情：`docker container run microsoft/powershell:nanoserver Start-Sleep -s 10`。

您可以使用`docker container stop`命令手动停止容器，然后使用`docker container start`重新启动它。要永久删除容器，必须使用`docker container rm`显式删除它。

这就是电梯推介！现在让我们深入了解细节...

### Docker 容器-深入探讨

我们将在这里首先介绍容器和虚拟机之间的基本区别。目前主要是理论，但这很重要。在此过程中，我们将指出容器模型相对于虚拟机模型的潜在优势。

> **注意：**作为作者，在我们继续之前，我要说这个。我们很多人对我们所做的事情和我们拥有的技能都很热情。我记得*大型 Unix*的人抵制 Linux 的崛起。你可能也记得同样的事情。你可能还记得人们试图抵制 VMware 和 VM 巨头。在这两种情况下，“抵抗是徒劳的”。在本节中，我将强调容器模型相对于 VM 模型的一些优势。但我猜你们中的很多人都是 VM 专家，对 VM 生态系统投入了很多。我猜你们中的一两个人可能想和我争论我说的一些事情。所以让我明白一点...我是个大个子，我会在肉搏战中打败你 :-D 只是开玩笑。但我不是想摧毁你的帝国或者说你的孩子丑陋！我是想帮助你。我写这本书的整个原因就是为了帮助你开始使用 Docker 和容器！

我们开始吧。

#### 容器 vs 虚拟机

容器和虚拟机都需要主机来运行。这可以是从您的笔记本电脑，到您数据中心的裸机服务器，一直到公共云实例的任何东西。在这个例子中，我们假设需要在单个物理服务器上运行 4 个业务应用程序。

在虚拟机模型中，物理服务器启动并引导虚拟机监视器（我们跳过 BIOS 和引导加载程序代码等）。一旦虚拟机监视器启动，它就会占用系统上的所有物理资源，如 CPU、RAM、存储和 NIC。然后，虚拟机监视器将这些硬件资源划分为看起来、闻起来和感觉起来与真实物品完全相同的虚拟版本。然后将它们打包成一个名为虚拟机（VM）的软件构造。然后我们将这些 VM 安装操作系统和应用程序。我们说我们有一个单独的物理服务器，需要运行 4 个应用程序，所以我们会创建 4 个 VM，安装 4 个操作系统，然后安装 4 个应用程序。完成后，它看起来有点像图 7.2。

![图 7.2](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-dpdv/img/figure7-2.png)

图 7.2

容器模型中有些不同。

当服务器启动时，您选择的操作系统引导。在 Docker 世界中，这可以是 Linux，或者具有对其内核中容器基元支持的现代 Windows 版本。与虚拟机模型类似，操作系统占用所有硬件资源。在操作系统之上，我们安装了一个名为 Docker 的容器引擎。容器引擎然后获取**操作系统资源**，如*进程树*、*文件系统*和*网络堆栈*，并将它们划分为安全隔离的构造，称为*容器*。每个容器看起来、闻起来和感觉起来就像一个真正的操作系统。在每个*容器*内部，我们可以运行一个应用程序。与之前一样，我们假设有一个单独的物理服务器，需要运行 4 个应用程序。因此，我们会划分出 4 个容器，并在每个容器内运行一个应用程序。这在图 7.3 中显示。

![图 7.3](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-dpdv/img/figure7-3.png)

图 7.3

在高层次上，我们可以说虚拟机监视器执行**硬件虚拟化** - 它们将物理硬件资源划分为虚拟版本。另一方面，容器执行**操作系统虚拟化** - 它们将操作系统资源划分为虚拟版本。

#### 虚拟机的开销

让我们在刚才讨论的基础上深入探讨虚拟机监视器模型的一个主要问题。

我们最初只有一个物理服务器，需要运行 4 个业务应用程序。在两种模型中，我们安装了操作系统或者虚拟机监视器（一种针对虚拟机高度优化的操作系统）。到目前为止，这两种模型几乎是相同的。但这就是相似之处的尽头。

然后，虚拟机模型将低级硬件资源划分为虚拟机。每个虚拟机都是一个包含虚拟 CPU、虚拟 RAM、虚拟磁盘等的软件构造。因此，每个虚拟机都需要自己的操作系统来声明、初始化和管理所有这些虚拟资源。不幸的是，每个操作系统都带有自己的一套负担和开销。例如，每个操作系统都会消耗一部分 CPU、一部分 RAM、一部分存储空间等。大多数还需要自己的许可证，以及人员和基础设施来打补丁和升级它们。每个操作系统还呈现出相当大的攻击面。我们经常将所有这些称为“操作系统税”或“虚拟机税”——你安装的每个操作系统都会消耗资源！

容器模型在主机操作系统中运行一个单一的内核。可以在单个主机上运行数十甚至数百个容器，每个容器共享同一个操作系统/内核。这意味着一个单一的操作系统消耗 CPU、RAM 和存储空间。一个需要许可证的单一操作系统。一个需要升级和打补丁的单一操作系统。以及一个呈现攻击面的单一操作系统内核。总而言之，只有一个操作系统税账单！

在我们的例子中，这可能看起来不是很多，因为一个单独的服务器需要运行 4 个业务应用程序。但是当我们谈论数百或数千个应用程序时，这可能会改变游戏规则。

考虑的另一件事是启动时间。因为容器不是一个完整的操作系统，所以它的启动速度比虚拟机快得多。记住，容器内部没有需要定位、解压和初始化的内核，更不用说与正常内核引导相关的所有硬件枚举和初始化。启动容器时不需要任何这些！在操作系统级别下，单个共享的内核已经启动了！最终结果是，容器可以在不到一秒的时间内启动。唯一影响容器启动时间的是运行的应用程序启动所需的时间。

所有这些都导致容器模型比虚拟机模型更精简和高效。我们可以在更少的资源上运行更多的应用程序，更快地启动它们，并且在许可和管理成本上支付更少，同时对黑暗面呈现出更少的攻击面。这有什么不好的呢！

有了这个理论，让我们来玩一下一些容器。

#### 运行容器

要跟随这些示例，您需要一个可用的 Docker 主机。对于大多数命令，它是 Linux 还是 Windows 都没有关系。

#### 检查 Docker 守护程序

我登录到 Docker 主机时，总是首先检查 Docker 是否正在运行。

```
$ docker version
Client:
 Version:      `17`.05.0-ce
 API version:  `1`.29
 Go version:   go1.7.5
 Git commit:   89658be
 Built:        Thu May  `4` `22`:10:54 `2017`
 OS/Arch:      linux/amd64

Server:
 Version:      `17`.05.0-ce
 API version:  `1`.29 `(`minimum version `1`.12`)`
 Go version:   go1.7.5
 Git commit:   89658be
 Built:        Thu May  `4` `22`:10:54 `2017`
 OS/Arch:      linux/amd64
 Experimental: `false` 
```

只要在 `Client` 和 `Server` 部分得到响应，你就可以继续。如果在 `Server` 部分得到错误代码，很可能是 docker 守护程序（服务器）没有运行，或者你的用户账户没有权限访问它。

如果你正在运行 Linux，并且你的用户账户没有权限访问守护程序，你需要确保它是本地 `docker` Unix 组的成员。如果不是，你可以用 `usermod -aG docker <user>` 添加它，然后你需要注销并重新登录到你的 shell 以使更改生效。

如果你的用户账户已经是本地 `docker` 组的成员，问题可能是 Docker 守护程序没有运行。要检查 Docker 守护程序的状态，请根据 Docker 主机的操作系统运行以下命令之一。

```
//Run this command on Linux systems not using Systemd
$ service docker status
docker start/running, process 29393

//Run this command on Linux systems that are using Systemd
$ systemctl is-active docker
active

//Run this command on Windows Server 2016 systems from a PowerShell window
> Get-Service docker

Status    Name      DisplayName
------    ----      -----------
Running   Docker    docker 
```

如果 Docker 守护程序正在运行，你可以继续。

#### 启动一个简单的容器

启动容器的最简单方法是使用 `docker container run` 命令。

以下命令启动一个简单的容器，将运行 Ubuntu Linux 的容器化版本。

```
`$` `docker` `container` `run` `-``it` `ubuntu``:``latest` `/``bin``/``bash`
`Unable` `to` `find` `image` `'``ubuntu``:``latest``'` `locally`
`latest``:` `Pulling` `from` `library``/``ubuntu`
`952132``ac251a``:` `Pull` `complete`
`82659f8f``1``b76``:` `Pull` `complete`
`c19118ca682d``:` `Pull` `complete`
`8296858250f``e``:` `Pull` `complete`
`24e0251``a0e2c``:` `Pull` `complete`
`Digest``:` `sha256``:``f4691c96e6bbaa99d9``...``e95a60369c506dd6e6f6ab`
`Status``:` `Downloaded` `newer` `image` `for` `ubuntu``:``latest`
`root``@3027``eb644874``:``/``#` 
```

Windows 的一个例子可能是

```
docker container run -it microsoft/powershell:nanoserver pwsh.exe 
```

命令的格式基本上是 `docker container run <options> <image>:<tag> <app>`。

让我们分解一下这个命令。

我们从 `docker container run` 开始，这是启动新容器的标准命令。然后我们使用了 `-it` 标志使容器交互，并将其附加到我们的终端。接下来，我们告诉它使用 `ubuntu:latest` 或 `microsoft/powershell:nanoserver` 镜像。最后，我们告诉它在 Linux 示例中运行 Bash shell，在 Windows 示例中运行 PowerShell 应用程序。

当我们按下 `Return` 键时，Docker 客户端会向 Docker 守护程序发出适当的 API 调用。Docker 守护程序接受了命令，并搜索 Docker 主机的本地缓存，看看它是否已经有所请求的镜像的副本。在所引用的例子中，它没有，所以它去 Docker Hub 看看是否能在那里找到。它找到了，所以它在本地 *拉取* 并将其存储在本地缓存中。

> **注意：** 在标准的 Linux 安装中，Docker 守护程序在本地 IPC/Unix 套接字`/var/run/docker.sock`上实现 Docker 远程 API。在 Windows 上，它在`npipe:////./pipe/docker_engine`上监听一个命名管道。也可以配置 Docker 客户端和守护程序通过网络进行通信。Docker 的默认非 TLS 网络端口是 2375，默认的 TLS 端口是 2376。

一旦镜像被拉取，守护程序就会创建容器并在其中执行指定的应用程序。

如果你仔细看，你会发现你的 shell 提示已经改变，你现在在容器内部。在所引用的例子中，shell 提示已经改变为`root@3027eb644874:/#`。`@`后面的长数字是容器唯一 ID 的前 12 个字符。

尝试在容器内执行一些基本命令。你可能会注意到一些命令无法使用。这是因为我们使用的镜像，就像几乎所有的容器镜像一样，都是针对容器高度优化的。这意味着它们并没有安装所有正常的命令和软件包。下面的例子展示了一些命令 - 一个成功，另一个失败。

```
`root``@3027``eb644874``:``/``#` `ls` `-``l`
`total` `64`
`drwxr``-``xr``-``x`   `2` `root` `root` `4096` `Aug` `19` `00``:``50` `bin`
`drwxr``-``xr``-``x`   `2` `root` `root` `4096` `Apr` `12` `20``:``14` `boot`
`drwxr``-``xr``-``x`   `5` `root` `root`  `380` `Sep` `13` `00``:``47` `dev`
`drwxr``-``xr``-``x`  `45` `root` `root` `4096` `Sep` `13` `00``:``47` `etc`
`drwxr``-``xr``-``x`   `2` `root` `root` `4096` `Apr` `12` `20``:``14` `home`
`drwxr``-``xr``-``x`   `8` `root` `root` `4096` `Sep` `13`  `2015` `lib`
`drwxr``-``xr``-``x`   `2` `root` `root` `4096` `Aug` `19` `00``:``50` `lib64`
`drwxr``-``xr``-``x`   `2` `root` `root` `4096` `Aug` `19` `00``:``50` `media`
`drwxr``-``xr``-``x`   `2` `root` `root` `4096` `Aug` `19` `00``:``50` `mnt`
`drwxr``-``xr``-``x`   `2` `root` `root` `4096` `Aug` `19` `00``:``50` `opt`
`dr``-``xr``-``xr``-``x` `129` `root` `root`    `0` `Sep` `13` `00``:``47` `proc`
`drwx``------`   `2` `root` `root` `4096` `Aug` `19` `00``:``50` `root`
`drwxr``-``xr``-``x`   `6` `root` `root` `4096` `Aug` `26` `18``:``50` `run`
`drwxr``-``xr``-``x`   `2` `root` `root` `4096` `Aug` `26` `18``:``50` `sbin`
`drwxr``-``xr``-``x`   `2` `root` `root` `4096` `Aug` `19` `00``:``50` `srv`
`dr``-``xr``-``xr``-``x`  `13` `root` `root`    `0` `Sep` `13` `00``:``47` `sys`
`drwxrwxrwt`   `2` `root` `root` `4096` `Aug` `19` `00``:``50` `tmp`
`drwxr``-``xr``-``x`  `11` `root` `root` `4096` `Aug` `26` `18``:``50` `usr`
`drwxr``-``xr``-``x`  `13` `root` `root` `4096` `Aug` `26` `18``:``50` `var`

`root``@3027``eb644874``:``/``#` `ping` `www``.``docker``.``com`
`bash``:` `ping``:` `command` `not` `found`
`root``@3027``eb644874``:``/``#` 
```

`如上所示，`ping`实用程序不包含在官方 Ubuntu 镜像中。

#### 容器进程

当我们在上一节中启动 Ubuntu 容器时，我们告诉它运行 Bash shell（`/bin/bash`）。这使得 Bash shell 成为**容器内唯一运行的进程**。你可以通过在容器内运行`ps -elf`来看到这一点。

```
`root``@3027``eb644874``:``/``#` `ps` `-``elf`
`F` `S` `UID`   `PID`  `PPID`   `NI` `ADDR` `SZ` `WCHAN`  `STIME` `TTY`     `TIME`      `CMD`
`4` `S` `root`    `1`     `0`    `0` `-`  `4558` `wait`   `00``:``47` `?`     `00``:``00``:``00`  `/``bin``/``bash`
`0` `R` `root`   `11`     `1`    `0` `-`  `8604` `-`      `00``:``52` `?`     `00``:``00``:``00`  `ps` `-``elf` 
```

`虽然在上面的输出中看起来有两个进程在运行，但实际上并没有。列表中的第一个进程，PID 为 1，是我们告诉容器运行的 Bash shell。第二个进程是我们运行的`ps -elf`命令来生成列表。这是一个短暂的进程，在输出显示时已经退出。长话短说，这个容器正在运行一个单一的进程 - `/bin/bash`。

> **注意：** Windows 容器略有不同，通常会运行相当多的进程。

这意味着如果你输入`exit`来退出 Bash shell，容器也会退出（终止）。原因是容器不能在没有运行的进程的情况下存在 - 终止 Bash shell 会终止容器的唯一进程，导致容器也被终止。这对 Windows 容器也是适用的 - **终止容器中的主进程也会终止容器**。

按下`Ctrl-PQ`退出容器而不终止它。这样做会将你放回 Docker 主机的 shell，并将容器保持在后台运行。你可以使用`docker container ls`命令查看系统上正在运行的容器列表。

```
$ docker container ls
CNTNR ID  IMAGE          COMMAND    CREATED  STATUS    NAMES
`302`...74  ubuntu:latest  /bin/bash  `6` mins   Up 6mins  sick_montalcini 
```

重要的是要理解，这个容器仍在运行，你可以使用`docker container exec`命令重新连接你的终端。

```
`$` `docker` `container` `exec` `-``it` `3027``eb644874` `bash`
`root``@3027``eb644874``:``/``#` 
```

重新连接到 Windows Nano Server PowerShell 容器的命令将是`docker container exec -it <container-name-or-ID> pwsh.exe`。

如您所见，shell 提示已经改回到容器。如果再次运行`ps`命令，您现在将看到**两个** Bash 或 PowerShell 进程。这是因为`docker container exec`命令创建了一个新的 Bash 或 PowerShell 进程并附加到其中。这意味着在这个 shell 中输入`exit`不会终止容器，因为原始的 Bash 或 PowerShell 进程将继续运行。

输入`exit`离开容器，并使用`docker container ps`验证它仍在运行。它仍在运行。

如果您正在自己的 Docker 主机上跟着示例操作，您应该使用以下两个命令停止并删除容器（您需要替换您的容器的 ID）。

```
$ docker container stop 3027eb64487
3027eb64487

$ docker container rm 3027eb64487
3027eb64487 
```

在前面的示例中启动的容器将不再存在于您的系统中。

#### 容器生命周期

普遍的误解是容器无法持久保存数据。它们可以！

人们认为容器不适合持久工作负载或持久数据的一个很大的原因是因为它们在非持久性工作上表现得很好。但擅长一件事并不意味着你不能做其他事情。很多虚拟机管理员会记得微软和甲骨文这样的公司告诉你他们的应用程序不能在虚拟机内运行，或者至少如果你这样做他们不会支持你。我想知道我们是否在容器化的过程中看到了类似的情况——是否有人试图保护他们认为受到容器威胁的持久工作负载帝国？

在本节中，我们将看一下容器的生命周期——从诞生，工作和休假，到最终的死亡。

我们已经看到如何使用`docker container run`命令启动容器。让我们启动另一个，以便我们可以完整地了解其生命周期。以下示例将来自运行 Ubuntu 容器的 Linux Docker 主机。但是，所有示例都将适用于我们在先前示例中使用的 Windows PowerShell 容器 - 尽管您将不得不用其等效的 Windows 命令替换 Linux 命令。

```
`$` `docker` `container` `run` `--``name` `percy` `-``it` `ubuntu``:``latest` `/``bin``/``bash`
`root``@9``cb2d2fd1d65``:``/``#` 
```

这就是我们创建的容器，我们将其命名为“percy”以表示持久:-S

现在让我们通过向其写入一些数据来让其工作。

在新容器的 shell 中，按照以下步骤将一些数据写入`tmp`目录中的新文件，并验证写入操作是否成功。

```
`root``@9``cb2d2fd1d65``:``/``#` `cd` `tmp`

`root``@9``cb2d2fd1d65``:``/``tmp``#` `ls` `-``l`
`total` `0`

`root``@9``cb2d2fd1d65``:``/``tmp``#` `echo` `"DevOps FTW"` `>` `newfile`

`root``@9``cb2d2fd1d65``:``/``tmp``#` `ls` `-``l`
`total` `4`
`-``rw``-``r``--``r``--` `1` `root` `root` `14` `May` `23` `11``:``22` `newfile`

`root``@9``cb2d2fd1d65``:``/``tmp``#` `cat` `newfile`
`DevOps` `FTW` 
```

按`Ctrl-PQ`退出容器而不杀死它。

现在使用`docker container stop`命令停止容器并将其放在*休假*中。

```
$ docker container stop percy
percy 
```

您可以使用`docker container stop`命令的容器名称或 ID。格式为`docker container stop <container-id 或 container-name>`。

现在运行`docker container ls`命令以列出所有正在运行的容器。

```
$ docker container ls
CONTAINER ID   IMAGE   COMMAND   CREATED  STATUS  PORTS   NAMES 
```

容器未在上面的输出中列出，因为您使用`docker container stop`命令将其置于停止状态。再次运行相同的命令，只是这次添加`-a`标志以显示所有容器，包括那些已停止的容器。

```
$ docker container ls -a
CNTNR ID  IMAGE          COMMAND    CREATED  STATUS      NAMES
9cb...65  ubuntu:latest  /bin/bash  `4` mins   Exited `(``0``)`  percy 
```

现在我们可以看到容器显示为`Exited (0)`。停止容器就像停止虚拟机一样。尽管它目前没有运行，但它的整个配置和内容仍然存在于 Docker 主机的文件系统中，并且可以随时重新启动。

让我们使用`docker container start`命令将其从休假中带回来。

```
$ docker container start percy
percy

$ docker container ls
CONTAINER ID  IMAGE          COMMAND      CREATED  STATUS     NAMES
9cb2d2fd1d65  ubuntu:latest  `"/bin/bash"`  `4` mins   Up `3` secs  percy 
```

停止的容器现在已重新启动。是时候验证我们之前创建的文件是否仍然存在了。使用`docker container exec`命令连接到重新启动的容器。

```
`$` `docker` `container` `exec` `-``it` `percy` `bash`
`root``@9``cb2d2fd1d65``:``/``#` 
```

您的 shell 提示符将更改以显示您现在正在容器的命名空间中操作。

验证您之前创建的文件是否仍然存在，并且包含您写入其中的数据。

```
`root``@9``cb2d2fd1d65``:``/``#` `cd` `tmp`
`root``@9``cb2d2fd1d65``:``/``#` `ls` `-``l`
`-``rw``-``r``--``r``--` `1` `root` `root` `14` `Sep` `13` `04``:``22` `newfile`
`root``@9``cb2d2fd1d65``:``/``#`
`root``@9``cb2d2fd1d65``:``/``#` `cat` `newfile`
`DevOps` `FTW` 
```

就像魔术一样，您创建的文件仍然存在，并且其中包含的数据与您离开时完全相同！这证明停止容器不会销毁容器或其中的数据。

虽然这个例子说明了容器的持久性，我应该指出，*卷*是在容器中存储持久数据的首选方式。但在我们的旅程中的这个阶段，我认为这是容器持久性的一个有效例子。

到目前为止，我认为你很难在容器与虚拟机的行为中找到重大差异。

现在让我们杀死容器并从系统中删除它。

可以通过向`docker container rm`传递`-f`标志来删除*运行中*的容器。然而，最佳做法是先停止容器，然后再删除容器。这样做可以给容器正在运行的应用/进程一个干净停止的机会。稍后会详细介绍这一点。

下一个例子将停止`percy`容器，删除它，并验证操作。如果您的终端仍然连接到 percy 容器，您需要通过按`Ctrl-PQ`返回到 Docker 主机的终端。

```
$ docker container stop percy
percy

$ docker container rm percy
percy

$ docker container ls -a
CONTAINER ID    IMAGE      COMMAND    CREATED  STATUS     PORTS      NAMES 
```

“容器现在已被删除 - 在地球上被彻底抹去。如果它是一个好容器，它将成为*无服务器函数*在来世。如果它是一个淘气的容器，它将成为一个愚蠢的终端:-D

总结容器的生命周期...您可以停止、启动、暂停和重新启动容器多次。而且这一切都会发生得非常快。但容器及其数据始终是安全的。直到您明确删除容器，您才有可能丢失其数据。即使在那种情况下，如果您将容器数据存储在*卷*中，那么数据将在容器消失后仍然存在。

让我们快速提一下为什么我们建议在删除容器之前采取两阶段的停止容器的方法。

#### 优雅地停止容器

在 Linux 世界中，大多数容器将运行单个进程。在 Windows 世界中，它们会运行一些进程，但以下规则仍然适用。

在我们之前的例子中，容器正在运行`/bin/bash`应用程序。当您使用`docker container rm <container> -f`杀死正在运行的容器时，容器将在没有警告的情况下被杀死。这个过程非常暴力 - 有点像从容器背后悄悄接近并向其后脑勺开枪。您实际上给了容器和它正在运行的应用程序在被杀死之前没有机会整理自己的事务。

然而，`docker container stop`命令要温和得多（就像拿枪指着容器的头说“你有 10 秒钟说最后的话”）。它会提醒容器内的进程即将被停止，让它有机会在结束之前整理好事情。一旦`docker stop`命令返回，你就可以用`docker container rm`删除容器。

这里背后的魔法可以用 Linux/POSIX *信号*来解释。`docker container stop`向容器内的 PID 1 进程发送**SIGTERM**信号。正如我们刚才说的，这给了进程一个机会来清理事情并优雅地关闭自己。如果它在 10 秒内没有退出，它将收到**SIGKILL**。这实际上就是子弹打在头上。但是嘿，它有 10 秒的时间先整理自己！

`docker container rm <container> -f`不会用**SIGTERM**客气地询问，它直接使用**SIGKILL**。就像我们刚才说的，这就像从背后悄悄接近并猛击头部。顺便说一句，我不是一个暴力的人！

#### 使用重启策略的自我修复容器

通常情况下，使用重启策略来运行容器是个好主意。这是一种自我修复的形式，使 Docker 能够在发生某些事件或故障后自动重新启动它们。

重启策略是针对每个容器应用的，并且可以作为`docker-container run`命令的一部分在命令行上进行配置，也可以在 Compose 文件中声明式地用于 Docker Compose 和 Docker Stacks。

在撰写本文时，存在以下重启策略：

+   `always`

+   `unless-stopped`

+   `on-failed`

**always**策略是最简单的。它会始终重新启动已停止的容器，除非它已被明确停止，比如通过`docker container stop`命令。演示这一点的简单方法是使用`--restart always`策略启动一个新的交互式容器，并告诉它运行一个 shell 进程。当容器启动时，您将附加到其 shell。从 shell 中输入 exit 将杀死容器的 PID 1 进程，从而杀死容器。但是，Docker 会自动重新启动它，因为它是使用`--restart always`策略启动的。如果您发出`docker container ls`命令，您将看到容器的正常运行时间将少于其创建时间。我们在以下示例中展示了这一点。

如果你在 Windows 上进行操作，请用以下命令替换示例中的`docker container run`命令：`docker container run --name neversaydie -it --restart always microsoft/powershell:nanoserver`。

```
$ docker container run --name neversaydie -it --restart always alpine sh

//Wait a few seconds before typing the ````exit```` `command`

/# `exit`

$ docker container ls
CONTAINER ID    IMAGE     COMMAND    CREATED           STATUS
0901afb84439    alpine    `"sh"`       `35` seconds ago    Up `1` second 
```

 `Notice that the container was created 35 seconds ago, but has only been up for 1 second. This is because we killed it when we issued the `exit` command from within the container, and Docker has had to restart it.

An interesting feature of the `--restart always` policy is that a stopped container will be restarted when the Docker daemon starts. For example, you start a new container with the `--restart always` policy and then stop it with the `docker container stop` command. At this point the container is in the `Stopped (Exited)` state. However, if you restart the Docker daemon, the container will be automatically restarted when the daemon comes back up.

The main difference between the **always** and **unless-stopped** policies is that containers with the `--restart unless-stopped` policy will not be restarted when the daemon restarts if they were in the `Stopped (Exited)` state. That might be a confusing sentence, so let’s walk through an example.

We’ll create two new containers. One called “always” with the `--restart always` policy, and one called “unless-stopped” with the `--restart unless-stopped` policy. We’ll stop them both with the `docker container stop` command and then restart Docker. The “always” container will restart, but the “unless-stopped” container will not.

1.  Create the two new containers

    ```
     $ docker container run -d --name always \
       --restart always \
       alpine sleep 1d

     $ docker container run -d --name unless-stopped \
       --restart unless-stopped \
       alpine sleep 1d

     $ docker container ls
     CONTAINER ID   IMAGE     COMMAND       STATUS       NAMES
     3142bd91ecc4   alpine    "sleep 1d"    Up 2 secs    unless-stopped
     4f1b431ac729   alpine    "sleep 1d"    Up 17 secs   always 
    ```

 `We now have two containers running. One called “always” and one called “unless-stopped”.

1.  Stop both containers

    ```
     $ docker container stop always unless-stopped

     $ docker container ls -a
     CONTAINER ID   IMAGE     STATUS                        NAMES
     3142bd91ecc4   alpine    Exited (137) 3 seconds ago    unless-stopped
     4f1b431ac729   alpine    Exited (137) 3 seconds ago    always 
    ```

`*   Restart Docker.`

 `The process for restarting Docker is different on different Operating Systems. This example shows how to stop Docker on Linux hosts running `systemd`. To restart Docker on Windows Server 2016 use `restart-service Docker`.

```
 $ systemlctl restart docker 
```

 `1.  Once Docker has restarted, you can check the status of the containers.

    ```
     $ docker container ls -a
     CONTAINER   CREATED             STATUS                       NAMES
     314..cc4    2 minutes ago      Exited (137) 2 minutes ago    unless-stopped
     4f1..729    2 minutes ago      Up 9 seconds                  always 
    ```

 `Notice that the “always” container (started with the `--restart always` policy) has been restarted, but the “unless-stopped” container (started with the `--restart unless-stopped` policy) has not.

The **on-failure** policy will restart a container if it exits with a non-zero exit code. It will also restart containers when the Docker daemon restarts, even containers that were in the stopped state.

If you are working with Docker Compose or Docker Stacks, you can apply the restart policy to a `service` object as follows:

```
version: "3"
services:
  myservice:
    <Snip>
    restart_policy:
      condition: always | unless-stopped | on-failure 
```

 `#### Web server example

So far, we’ve seen how to start a simple container and interact with it. We’ve also seen how to stop, restart and delete containers. Now let’s take a look at a Linux web server example.

In this example, we’ll start a new container from an image I use in a few of my [Pluralsight video courses](https://www.pluralsight.com/search?q=nigel%20poulton%20docker&categories=all). The image runs an insanely simple web server on port 8080.

Use the `docker container stop` and `docker container rm` commands to clean up any existing containers on your system. Then run the following `docker container run` command.

```
$ docker container run -d --name webserver -p `80`:8080 `\`
  nigelpoulton/pluralsight-docker-ci

Unable to find image `'nigelpoulton/pluralsight-docker-ci:latest'` locally
latest: Pulling from nigelpoulton/pluralsight-docker-ci
a3ed95caeb02: Pull `complete`
3b231ed5aa2f: Pull `complete`
7e4f9cd54d46: Pull `complete`
929432235e51: Pull `complete`
6899ef41c594: Pull `complete`
0b38fccd0dab: Pull `complete`
Digest: sha256:7a6b0125fe7893e70dc63b2...9b12a28e2c38bd8d3d
Status: Downloaded newer image `for` nigelpoulton/plur...docker-ci:latest
6efa1838cd51b92a4817e0e7483d103bf72a7ba7ffb5855080128d85043fef21 
```

 `Notice that your shell prompt hasn’t changed. This is because we started this container in the background with the `-d` flag. Starting a container in the background does not attach it to your terminal.

This example threw a few more arguments at the `docker container run` command, so let’s take a quick look at them.

We know `docker container run` starts a new container. But this time we give it the `-d` flag instead of `-it`. `-d` stands for **d**aemon mode, and tells the container to run in the background.

After that, we name the container and then give it `-p 80:8080`. The `-p` flag maps ports on the Docker host to ports inside the container. This time we’re mapping port 80 on the Docker host to port 8080 inside the container. This means that traffic hitting the Docker host on port 80 will be directed to port 8080 inside of the container. It just so happens that the image we’re using for this container defines a web service that listens on port 8080\. This means our container will come up running a web server listening on port 8080.

Finally, we tell it which image to use: `nigelpoulton/pluralsight-docker-ci`. This image is not kept up-to-date and **will** contain vulnerabilities!

Running a `docker container ls` command will show the container as running and show the ports that are mapped. It’s important to know that port mappings are expressed as `host-port:container-port`.

```
$ docker container ls
CONTAINER ID  COMMAND        STATUS       PORTS               NAMES
6efa1838cd51  /bin/sh -c...  Up `2` mins  `0`.0.0.0:80->8080/tcp  webserver 
```

 `> **Note:** We’ve removed some of the columns from the output above to help with readability.

Now that the container is running and ports are mapped, we can connect to the container by pointing a web browser at the IP address or DNS name of the **Docker host** on port 80\. Figure 7.4 shows the web page that is being served up by the container.

![Figure 7.4](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-dpdv/img/figure7-4.png)

Figure 7.4

The same `docker container stop`, `docker container pause`, `docker container start`, and `docker container rm` commands can be used on the container. Also, the same rules of persistence apply — stopping or pausing the container does not destroy the container or any data stored in it.

#### Inspecting containers

In the previous example, you might have noticed that we didn’t specify an app for the container when we issued the `docker container run` command. Yet the container ran a simple web service. How did this happen?

When building a Docker image, it’s possible to embed an instruction that lists the default app you want containers using the image to run. If we run a `docker image inspect` against the image we used to run our container, we’ll be able to see the app that the container will run when it starts.

```
$ docker image inspect nigelpoulton/pluralsight-docker-ci

`[`
    `{`
        `"Id"`: `"sha256:07e574331ce3768f30305519...49214bf3020ee69bba1"`,
        `"RepoTags"`: `[`
            `"nigelpoulton/pluralsight-docker-ci:latest"`

            <Snip>

            `]`,
            `"Cmd"`: `[`
                `"/bin/sh"`,
                `"-c"`,
                `"#(nop) CMD [\"/bin/sh\" \"-c\" \"cd /src \u0026\u0026 node \`
`./app.js\"]"`
            `]`,
<Snip> 
```

 `We’ve snipped the output to make it easier to find the information we’re interested in.

The entries after `Cmd` show the command/app that the container will run unless you override with a different one when you launch the container with `docker container run`. If you remove all of the shell escapes in the example, you get the following command `/bin/sh -c "cd /src && node ./app.js"`. That’s the default app a container based on this image will run.

It’s common to build images with default commands like this, as it makes starting containers easier. It also forces a default behavior and is a form of self documentation for the image — i.e. we can *inspect* the image and know what app it’s supposed to run.

That’s us done for the examples in this chapter. Let’s see a quick way to tidy our system up.

#### Tidying up

Let’s look at the simplest and quickest way to get rid of **every running container** on your Docker host. Be warned though, the procedure will forcible destroy **all** containers without giving them a chance to clean up. **This should never be performed on production systems or systems running important containers.

Run the following command from the shell of your Docker host to delete all containers.

```
$ docker container rm `$(`docker container ls -aq`)` -f
6efa1838cd51 
```

 `In this example, we only had a single container running, so only one was deleted (6efa1838cd51). However, the command works the same way as the `docker image rm $(docker image ls -q)` command we used in the previous chapter to delete all images on a single Docker host. We already know the `docker container rm` command deletes containers. Passing it `$(docker container ls -aq)` as an argument, effectively passes it the ID of every container on the system. The `-f` flag forces the operation so that running containers will also be destroyed. Net result… all containers, running or stopped, will be destroyed and removed from the system.

The above command will work in a PowerShell terminal on a Windows Docker host.

### Containers - The commands

*   `docker container run` is the command used to start new containers. In its simplest form, it accepts an *image* and a *command* as arguments. The image is used to create the container and the command is the application you want the container to run. This example will start an Ubuntu container in the foreground, and tell it to run the Bash shell: `docker container run -it ubuntu /bin/bash`.
*   `Ctrl-PQ` will detach your shell from the terminal of a container and leave the container running `(UP)` in the background.
*   `docker container ls` lists all containers in the running `(UP)` state. If you add the `-a` flag you will also see containers in the stopped `(Exited)` state.
*   `docker container exec` lets you run a new process inside of a running container. It’s useful for attaching the shell of your Docker host to a terminal inside of a running container. This command will start a new Bash shell inside of a running container and connect to it: `docker container exec -it <container-name or container-id> bash`. For this to work, the image used to create your container must contain the Bash shell.
*   `docker container stop` will stop a running container and put it in the `Exited (0)` state. It does this by issuing a `SIGTERM` to the process with PID 1 inside of the container. If the process has not cleaned up and stopped within 10 seconds, a SIGKILL will be issued to forcibly stop the container. `docker container stop` accepts container IDs and container names as arguments.
*   `docker container start` will restart a stopped `(Exited)` container. You can give `docker container start` the name or ID of a container.
*   `docker container rm` will delete a stopped container. You can specify containers by name or ID. It is recommended that you stop a container with the `docker container stop` command before deleting it with `docker container rm`.
*   `docker container inspect` will show you detailed configuration and runtime information about a container. It accepts container names and container IDs as its main argument.

### Chapter summary

In this chapter, we compared and contrasted the container and VM models. We looked at the *OS tax* problem inherent in the VM model, and saw how the container model can bring huge advantages in much the same way as the VM model brought huge advantages over the physical model.

We saw how to use the `docker container run` command to start a couple of simple containers, and we saw the difference between interactive containers in the foreground versus containers running in the background.

We know that killing the PID 1 process inside of a container will kill the container. And we’ve seen how to start, stop, and delete containers.

We finished the chapter using the `docker container inspect` command to view detailed container metadata.

So far so good!````````````````````````````


# 第九章：容器化应用程序

Docker 的全部内容都是关于将应用程序放入容器中运行。

将应用程序配置为容器运行的过程称为“容器化”。有时我们称之为“Docker 化”。

在本章中，我们将介绍将一个简单的 Linux Web 应用程序容器化的过程。如果您没有 Linux Docker 环境可以跟随操作，可以免费使用*Play With Docker*。只需将您的网络浏览器指向 https://play-with-docker.com 并启动一些 Linux Docker 节点。这是我启动 Docker 并进行测试的最喜欢的方式！

我们将把这一章分为通常的三个部分：

+   简而言之

+   深入探讨

+   命令

让我们将应用程序容器化！

### 容器化应用程序-简而言之

容器都是关于应用程序！特别是，它们是关于使应用程序简单**构建**、**交付**和**运行**。

容器化应用程序的过程如下：

1.  从您的应用程序代码开始。

1.  创建一个描述您的应用程序、其依赖关系以及如何运行它的*Dockerfile*。

1.  将此*Dockerfile*输入`docker image build`命令。

1.  坐下来，让 Docker 将您的应用程序构建成一个 Docker 镜像。

一旦您的应用程序被容器化（制作成 Docker 镜像），您就可以准备将其交付并作为容器运行。

图 8.1 以图片形式展示了这个过程。

![图 8.1-容器化应用程序的基本流程](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-dpdv/img/figure8-1.png)

图 8.1-容器化应用程序的基本流程

### 容器化应用程序-深入探讨

我们将把本章的深入探讨部分分为以下几个部分：

+   容器化单容器应用程序

+   使用多阶段构建进行生产

+   一些最佳实践

#### 容器化单容器应用程序

本章的其余部分将引导您完成容器化一个简单的单容器 Node.js Web 应用程序的过程。这个过程对于 Windows 是一样的，未来版本的书籍将包括一个 Windows 示例。

我们将完成以下高层次的步骤：

+   获取应用程序代码

+   检查 Dockerfile

+   容器化应用程序

+   运行应用程序

+   测试应用程序

+   仔细观察一下

+   使用**多阶段构建**进行生产

+   一些最佳实践

尽管在本章中我们将使用单容器应用程序，但在下一章关于 Docker Compose 中，我们将转向多容器应用程序。之后，我们将在关于 Docker Stacks 的章节中转向更复杂的应用程序。

##### 获取应用程序代码

本示例中使用的应用程序可以从 GitHub 克隆：

https://github.com/nigelpoulton/psweb.git

从 GitHub 克隆示例应用程序。

```
$ git clone https://github.com/nigelpoulton/psweb.git

Cloning into `'psweb'`...
remote: Counting objects: `15`, `done`.
remote: Compressing objects: `100`% `(``11`/11`)`, `done`.
remote: Total `15` `(`delta `2``)`, reused `15` `(`delta `2``)`, pack-reused `0`
Unpacking objects: `100`% `(``15`/15`)`, `done`.
Checking connectivity... `done`. 
```

`克隆操作会创建一个名为`psweb`的新目录。切换到`psweb`目录并列出其内容。

```
$ `cd` psweb

$ ls -l
total `28`
-rw-r--r-- `1` root root  `341` Sep `29` `16`:26 app.js
-rw-r--r-- `1` root root  `216` Sep `29` `16`:26 circle.yml
-rw-r--r-- `1` root root  `338` Sep `29` `16`:26 Dockerfile
-rw-r--r-- `1` root root  `421` Sep `29` `16`:26 package.json
-rw-r--r-- `1` root root  `370` Sep `29` `16`:26 README.md
drwxr-xr-x `2` root root `4096` Sep `29` `16`:26 `test`
drwxr-xr-x `2` root root `4096` Sep `29` `16`:26 views 
```

“这个目录包含了所有的应用程序源代码，以及用于视图和单元测试的子目录。随意查看这些文件 - 应用程序非常简单。在本章中，我们不会使用单元测试。

现在我们有了应用程序代码，让我们来看看它的 Dockerfile。

##### 检查 Dockerfile

请注意，存储库有一个名为**Dockerfile**的文件。这个文件描述了应用程序，并告诉 Docker 如何将其构建成一个镜像。

包含应用程序的目录被称为*构建上下文*。将 Dockerfile 放在*构建上下文*的根目录是一种常见做法。同时，**Dockerfile**以大写的“**D**”开头，并且是一个单词。 “dockerfile”和“Docker file”都是无效的。

让我们来看看 Dockerfile 的内容。

```
$ cat Dockerfile

FROM alpine
LABEL `maintainer``=``"nigelpoulton@hotmail.com"`
RUN apk add --update nodejs nodejs-npm
COPY . /src
WORKDIR /src
RUN npm install
EXPOSE `8080`
ENTRYPOINT `[``"node"`, `"./app.js"``]` 
```

`Dockerfile 有两个主要目的：

1.  描述应用程序

1.  告诉 Docker 如何将应用程序容器化（创建一个包含应用程序的镜像）

不要低估 Dockerfile 作为文档的影响！它有助于弥合开发和运维之间的差距！它还有助于加快新开发人员等的入职速度。这是因为该文件准确描述了应用程序及其依赖关系，格式易于阅读。因此，它应被视为代码，并检入源代码控制系统。

在高层次上，示例 Dockerfile 表示：从`alpine`镜像开始，将“nigelpoulton@hotmail.com”添加为维护者，安装 Node.js 和 NPM，复制应用程序代码，设置工作目录，安装依赖项，记录应用程序的网络端口，并将`app.js`设置为默认要运行的应用程序。

让我们更详细地看一下。

所有 Dockerfile 都以`FROM`指令开头。这将是镜像的基础层，应用程序的其余部分将作为附加层添加在顶部。这个特定的应用程序是一个 Linux 应用程序，所以很重要的是`FROM`指令引用一个基于 Linux 的镜像。如果您要容器化一个 Windows 应用程序，您需要指定适当的 Windows 基础镜像 - 比如`microsoft/aspnetcore-build`。

此时，镜像看起来像图 8.2。

![图 8.2](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-dpdv/img/figure8-2.png)

图 8.2

接下来，Dockerfile 创建了一个 LABEL，指定“nigelpoulton@hotmail.com”作为镜像的维护者。标签是简单的键值对，是向镜像添加自定义元数据的绝佳方式。将镜像的维护者列出来被认为是最佳实践，这样其他潜在的用户在使用时有一个联系点。

> **注意：** 我将不会维护这个镜像。我包含这个标签是为了向您展示如何使用标签，同时向您展示最佳实践。

`RUN apk add --update nodejs nodejs-npm` 指令使用 Alpine `apk` 包管理器将 `nodejs` 和 `nodejs-npm` 安装到镜像中。RUN 指令将这些软件包安装为新的镜像层，放在由 `FROM alpine` 指令创建的 `alpine` 基础镜像之上。镜像现在看起来像图 8.3。

![图 8.3](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-dpdv/img/Figure8-3.png)

图 8.3

`COPY . /src` 指令从*构建上下文*中复制应用程序文件。它将这些文件作为新层复制到镜像中。镜像现在有三个层，如图 8.4 所示。

![图 8.4](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-dpdv/img/figure8-4.png)

图 8.4

接下来，Dockerfile 使用 `WORKDIR` 指令为文件中的其余指令设置工作目录。此目录是相对于镜像的，并且该信息被添加为镜像配置的元数据，而不是作为新层。

然后，`RUN npm install` 指令使用 `npm` 在构建上下文中列出的 `package.json` 文件中安装应用程序依赖项。它在前一条指令中设置的 `WORKDIR` 上下文中运行，并将依赖项安装为镜像中的新层。镜像现在有四个层，如图 8.5 所示。

![图 8.5](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-dpdv/img/figure8-5.png)

图 8.5

该应用程序在 TCP 端口 8080 上公开了一个 Web 服务，因此 Dockerfile 使用 `EXPOSE 8080` 指令记录了这一点。这被添加为镜像元数据，而不是镜像层。

最后，`ENTRYPOINT` 指令用于设置镜像（容器）应该运行的主要应用程序。这也被添加为元数据，而不是镜像层。

##### 容器化应用/构建镜像

现在我们了解了它是如何工作的，让我们来构建它吧！

以下命令将构建一个名为 `web:latest` 的新镜像。命令末尾的句点 (`.`) 告诉 Docker 使用当前 shell 的工作目录作为*构建上下文*。

确保在命令的末尾包括句点（.），并确保从包含 Dockerfile 和应用程序代码的`psweb`目录运行命令。

```
$ docker image build -t web:latest .

Sending build context to Docker daemon  `76`.29kB
Step `1`/8 : FROM alpine
latest: Pulling from library/alpine
ff3a5c916c92: Pull `complete`
Digest: sha256:7df6db5aa6...0bedab9b8df6b1c0
Status: Downloaded newer image `for` alpine:latest
 ---> 76da55c8019d
<Snip>
Step `8`/8 : ENTRYPOINT node ./app.js
 ---> Running in 13977a4f3b21
 ---> fc69fdc4c18e
Removing intermediate container 13977a4f3b21
Successfully built fc69fdc4c18e
Successfully tagged web:latest 
```

`检查镜像是否存在于您的 Docker 主机的本地存储库中。

```
$ docker image ls
REPO    TAG       IMAGE ID          CREATED              SIZE
web     latest    fc69fdc4c18e      `10` seconds ago       `64`.4MB 
```

`恭喜，应用已经容器化！

您可以使用`docker image inspect web:latest`命令来验证镜像的配置。它将列出从 Dockerfile 配置的所有设置。

##### 推送镜像

创建了一个镜像后，将其存储在镜像注册表中是一个好主意，以确保其安全并使其对他人可用。Docker Hub 是最常见的公共镜像注册表，也是`docker image push`命令的默认推送位置。

为了将镜像推送到 Docker Hub，您需要使用您的 Docker ID 登录。您还需要适当地标记镜像。

让我们登录 Docker Hub 并推送新创建的镜像。

在以下示例中，您需要用您自己的 Docker ID 替换我的 Docker ID。因此，每当您看到“nigelpoulton”时，请将其替换为您的 Docker ID。

```
$ docker login
Login with **your** Docker ID to push and pull images from Docker Hub...
Username: nigelpoulton
Password:
Login Succeeded 
```

`在您可以推送镜像之前，您需要以特殊方式标记它。这是因为 Docker 在推送镜像时需要以下所有信息：

+   `注册表`

+   `存储库`

+   `标签`

Docker 有自己的观点，因此您不需要为`Registry`和`Tag`指定值。如果您不指定值，Docker 将假定`Registry=docker.io`和`Tag=latest`。但是，Docker 没有默认值用于存储库值，它从正在推送的镜像的“REPOSITORY”值中获取。这可能会让人感到困惑，因此让我们仔细看一下我们示例中的值。

先前的`docker image ls`输出显示我们的镜像的存储库名称为`web`。这意味着`docker image push`将尝试将镜像推送到`docker.io/web:latest`。但是，我无法访问`web`存储库，我的所有镜像都必须位于`nigelpoulton`的二级命名空间中。这意味着我们需要重新标记镜像以包含我的 Docker ID。

```
$ docker image tag web:latest nigelpoulton/web:latest 
```

`命令的格式是`docker image tag <current-tag> <new-tag>`，它会添加一个额外的标签，而不是覆盖原始标签。

另一个镜像列表显示，该镜像现在有两个标签，其中一个包含我的 Docker ID。

```
$ docker image ls
REPO                TAG       IMAGE ID         CREATED         SIZE
web                 latest    fc69fdc4c18e     `10` secs ago     `64`.4MB
nigelpoulton/web    latest    fc69fdc4c18e     `10` secs ago     `64`.4MB 
```

`现在我们可以将其推送到 Docker Hub。

```
$ docker image push nigelpoulton/web:latest
The push refers to repository `[`docker.io/nigelpoulton/web`]`
2444b4ec39ad: Pushed
ed8142d2affb: Pushed
d77e2754766d: Pushed
cd7100a72410: Mounted from library/alpine
latest: digest: sha256:68c2dea730...f8cf7478 size: `1160` 
```

`图 8.6 显示了 Docker 如何确定推送位置。

![图 8.6](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-dpdv/img/figure8-6.png)

图 8.6

您将无法将镜像推送到我的 Docker Hub 命名空间中的存储库，您将需要使用您自己的存储库。

本章其余部分的所有示例都将使用两个标签中较短的一个（`web:latest`）。

##### 运行应用程序

我们容器化的应用程序是一个简单的 Web 服务器，监听 TCP 端口 8080。您可以在`app.js`文件中验证这一点。

以下命令将基于我们刚刚创建的`web:latest`镜像启动一个名为`c1`的新容器。它将 Docker 主机上的端口`80`映射到容器内部的端口`8080`。这意味着您将能够将网络浏览器指向 Docker 主机的 DNS 名称或 IP 地址，并访问该应用程序。

> **注意：**如果您的主机已经在端口 80 上运行服务，您可以在`docker container run`命令中指定不同的端口。例如，要将应用程序映射到 Docker 主机上的端口 5000，请使用`-p 5000:8080`标志。

```
$ docker container run -d --name c1 `\`
  -p `80`:8080 `\`
  web:latest 
```

`-d`标志在后台运行容器，`-p 80:8080`标志将主机上的端口 80 映射到运行容器内部的端口 8080。

检查容器是否正在运行并验证端口映射。

```
$ docker container ls

ID    IMAGE       COMMAND           STATUS      PORTS
`49`..  web:latest  `"node ./app.js"`   UP `6` secs   `0`.0.0.0:80->8080/tcp 
```

上面的输出被剪辑以提高可读性，但显示应用程序容器正在运行。请注意，端口 80 被映射到容器中的端口 8080，映射到所有主机接口（`0.0.0.0:80`）。

##### 测试应用程序

打开一个网络浏览器，并将其指向容器正在运行的主机的 DNS 名称或 IP 地址。您将看到图中显示的网页。

![图 8.7](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-dpdv/img/figure8-7.png)

图 8.7

如果测试不起作用，请尝试以下操作：

1.  确保容器正在运行并且使用`docker container ls`命令。容器名称为`c1`，您应该看到端口映射为`0.0.0.0:80->8080/tcp`。

1.  检查防火墙和其他网络安全设置是否阻止 Docker 主机上的 80 端口的流量。

恭喜，应用程序已经容器化并正在运行！

##### 更仔细地观察

现在应用程序已经容器化，让我们更仔细地看看一些机制是如何工作的。

Dockerfile 中的注释行以`#`字符开头。

所有非注释行都是**指令**。指令采用`INSTRUCTION argument`的格式。指令名称不区分大小写，但通常习惯将它们写成大写。这样可以更容易地阅读 Dockerfile。

`docker image build`命令逐行解析 Dockerfile，从顶部开始。

一些指令创建新的层，而其他一些只是向镜像添加元数据。

创建新层的指令示例包括`FROM`、`RUN`和`COPY`。创建元数据的指令示例包括`EXPOSE`、`WORKDIR`、`ENV`和`ENTRYPOINT`。基本原则是 - 如果一条指令正在向镜像添加*内容*，比如文件和程序，它将创建一个新的层。如果它正在添加有关如何构建镜像和运行应用程序的指令，它将创建元数据。

您可以使用`docker image history`命令查看用于构建镜像的指令。

```
$ docker image `history` web:latest

IMAGE     CREATED BY                                      SIZE
fc6..18e  /bin/sh -c `#(nop)  ENTRYPOINT ["node" "./a...   0B`
`334`..bf0  /bin/sh -c `#(nop)  EXPOSE 8080/tcp              0B`
b27..eae  /bin/sh -c npm install                          `14`.1MB
`932`..749  /bin/sh -c `#(nop) WORKDIR /src                  0B`
`052`..2dc  /bin/sh -c `#(nop) COPY dir:2a6ed1703749e80...   22.5kB`
c1d..81f  /bin/sh -c apk add --update nodejs nodejs-npm   `46`.1MB
`336`..b92  /bin/sh -c `#(nop)  LABEL maintainer=nigelp...   0B`
3fd..f02  /bin/sh -c `#(nop)  CMD ["/bin/sh"]              0B`
<missing> /bin/sh -c `#(nop) ADD file:093f0723fa46f6c...   4.15MB` 
```

上面输出中的两点值得注意。

首先。每行对应 Dockerfile 中的一条指令（从底部开始向上工作）。`CREATED BY`列甚至列出了执行的确切 Dockerfile 指令。

其次。在输出中显示的行中，只有 4 行创建了新的层（`SIZE`列中的非零值）。这些对应于 Dockerfile 中的`FROM`、`RUN`和`COPY`指令。尽管其他指令看起来像是创建了层，但实际上它们创建的是元数据而不是层。`docker image history`输出使所有指令看起来都创建了层的原因是 Docker 构建和镜像分层的方式的产物。

使用`docker image inspect`命令确认只创建了 4 个层。

```
$ docker image inspect web:latest

<Snip>
`}`,
`"RootFS"`: `{`
    `"Type"`: `"layers"`,
    `"Layers"`: `[`
        `"sha256:cd7100...1882bd56d263e02b6215"`,
        `"sha256:b3f88e...cae0e290980576e24885"`,
        `"sha256:3cfa21...cc819ef5e3246ec4fe16"`,
        `"sha256:4408b4...d52c731ba0b205392567"`
    `]`
`}`, 
```

使用`FROM`指令从官方仓库中使用镜像被认为是一个良好的做法。这是因为它们往往遵循最佳实践，并且相对免受已知漏洞的影响。从小型镜像（`FROM`）开始也是一个好主意，因为这样可以减少潜在的漏洞。

您可以查看`docker image build`命令的输出，以了解构建镜像的一般过程。如下摘录所示，基本过程是：`启动临时容器` > `在该容器内运行 Dockerfile 指令` > `将结果保存为新的镜像层` > `删除临时容器`。

```
Step 3/8 : RUN apk add --update nodejs nodejs-npm
 ---> Running in e690ddca785f    << Run inside of temp container
fetch http://dl-cdn...APKINDEX.tar.gz
fetch http://dl-cdn...APKINDEX.tar.gz
(1/10) Installing ca-certificates (20171114-r0)
<Snip>
OK: 61 MiB in 21 packages
 ---> c1d31d36b81f               << Create new layer
Removing intermediate container  << Remove temp container
Step 4/8 : COPY . /src 
```

#### 使用**多阶段构建**进行生产部署

在 Docker 镜像中，大尺寸是不好的！

大尺寸意味着慢。大尺寸意味着难以处理。大尺寸意味着更多的潜在漏洞，可能意味着更大的攻击面！

因此，Docker 镜像应该尽量保持小尺寸。游戏的目标是只在生产镜像中包含**必要**的内容来运行您的应用程序。

问题是...保持镜像尺寸小曾经是一项艰苦的工作。

例如，您编写 Dockerfile 的方式对映像的大小有很大影响。一个常见的例子是每个`RUN`指令都会添加一个新的层。因此，通常被认为是最佳实践的是将多个命令作为单个 RUN 指令的一部分 - 所有这些命令都用双和号（&&）和反斜杠（`\`）换行符粘合在一起。虽然这并不是什么高深的学问，但它需要时间和纪律。

另一个问题是我们没有清理干净。我们将针对一个映像运行一个命令，拉取一些构建时工具，并在将其发送到生产环境时将所有这些工具留在映像中。这并不理想！

有解决方法 - 最明显的是*构建者模式*。但其中大多数都需要纪律和增加复杂性。

构建者模式要求您至少有两个 Dockerfile - 一个用于开发，一个用于生产。您将编写 Dockerfile.dev 以从大型基础映像开始，拉入所需的任何其他构建工具，并构建您的应用程序。然后，您将从 Dockerfile.dev 构建一个映像，并从中创建一个容器。然后，您将使用 Dockerfile.prod 从较小的基础映像构建一个新的映像，并从刚刚从构建映像创建的容器中复制应用程序内容。所有内容都需要用脚本粘合在一起。

这种方法是可行的，但代价是复杂性。

多阶段构建来拯救！

多阶段构建的目标是优化构建而不增加复杂性。它们实现了承诺！

这是一个高层次的…

使用多阶段构建，我们有一个包含多个 FROM 指令的单个 Dockerfile。每个 FROM 指令都是一个新的**构建阶段**，可以轻松地从以前的**阶段**复制构件。

让我们看一个例子！

此示例应用程序可在 https://github.com/nigelpoulton/atsea-sample-shop-app.git 上找到，Dockerfile 位于`app`目录中。这是一个基于 Linux 的应用程序，因此只能在 Linux Docker 主机上运行。

该存储库是`dockersamples/atsea-sample-shop-app`的一个分支，我已经分叉了它，以防上游存储库被删除或删除。

Dockerfile 如下所示：

```
FROM node:latest AS storefront
WORKDIR /usr/src/atsea/app/react-app
COPY react-app .
RUN npm install
RUN npm run build

FROM maven:latest AS appserver
WORKDIR /usr/src/atsea
COPY pom.xml .
RUN mvn -B -f pom.xml -s /usr/share/maven/ref/settings-docker.xml dependency\
:resolve
COPY . .
RUN mvn -B -s /usr/share/maven/ref/settings-docker.xml package -DskipTests

FROM java:8-jdk-alpine AS production
RUN adduser -Dh /home/gordon gordon
WORKDIR /static
COPY --from=storefront /usr/src/atsea/app/react-app/build/ .
WORKDIR /app
COPY --from=appserver /usr/src/atsea/target/AtSea-0.0.1-SNAPSHOT.jar .
ENTRYPOINT ["java", "-jar", "/app/AtSea-0.0.1-SNAPSHOT.jar"]
CMD ["--spring.profiles.active=postgres"] 
```

“首先要注意的是 Dockerfile 有三个`FROM`指令。每个都构成一个独立的**构建阶段**。在内部，它们从顶部开始编号为 0。但是，我们还给每个阶段起了一个友好的名字。

+   第 0 阶段称为“店面”

+   第 1 阶段称为“应用服务器”

+   第 2 阶段称为“生产”

`storefront`阶段拉取了大小超过 600MB 的`node:latest`镜像。它设置了工作目录，复制了一些应用代码，并使用了两个 RUN 指令来执行一些`npm`魔法。这增加了三层和相当大的大小。结果是一个更大的镜像，其中包含了大量的构建工具和非常少的应用代码。

`appserver`阶段拉取了大小超过 700MB 的`maven:latest`镜像。它通过两个 COPY 指令和两个 RUN 指令添加了四层内容。这产生了另一个非常大的镜像，其中包含了大量的构建工具和非常少的实际生产代码。

生产阶段从拉取`java:8-jdk-alpine`镜像开始。这个镜像大约 150MB，比之前构建阶段使用的 node 和 maven 镜像要小得多。它添加了一个用户，设置了工作目录，并从`storefront`阶段生成的镜像中复制了一些应用代码。之后，它设置了一个不同的工作目录，并从`appserver`阶段生成的镜像中复制了应用程序代码。最后，它设置了启动容器时要运行的主应用程序镜像。

需要注意的一件重要的事情是，`COPY --from`指令用于**仅从前几个阶段构建的镜像中复制与生产相关的应用代码**。它们不会复制不需要用于生产的构建产物。

还需要注意的是，我们只需要一个 Dockerfile，并且`docker image build`命令不需要额外的参数！

说到这个……让我们来构建它。

克隆存储库。

```
$ git clone https://github.com/nigelpoulton/atsea-sample-shop-app.git

Cloning into `'atsea-sample-shop-app'`...
remote: Counting objects: `632`, `done`.
remote: Total `632` `(`delta `0``)`, reused `0` `(`delta `0``)`, pack-reused `632`
Receiving objects: `100`% `(``632`/632`)`, `7`.23 MiB `|` `1`.88 MiB/s, `done`.
Resolving deltas: `100`% `(``195`/195`)`, `done`.
Checking connectivity... `done`. 
```

切换到克隆存储库的`app`文件夹，并验证 Dockerfile 是否存在。

```
$ `cd` atsea-sample-shop-app/app

$ ls -l
total `24`
-rw-r--r-- `1` root root  `682` Oct  `1` `22`:03 Dockerfile
-rw-r--r-- `1` root root `4365` Oct  `1` `22`:03 pom.xml
drwxr-xr-x `4` root root `4096` Oct  `1` `22`:03 react-app
drwxr-xr-x `4` root root `4096` Oct  `1` `22`:03 src 
```

进行构建（这可能需要几分钟才能完成）。

```
$ docker image build -t multi:stage .

Sending build context to Docker daemon  `3`.658MB
Step `1`/19 : FROM node:latest AS storefront
latest: Pulling from library/node
aa18ad1a0d33: Pull `complete`
15a33158a136: Pull `complete`
<Snip>
Step `19`/19 : CMD --spring.profiles.active`=`postgres
 ---> Running in b4df9850f7ed
 ---> 3dc0d5e6223e
Removing intermediate container b4df9850f7ed
Successfully built 3dc0d5e6223e
Successfully tagged multi:stage 
```

> **注意：**上面示例中使用的`multi:stage`标签是任意的。您可以根据自己的要求和标准为镜像打标签 - 没有必要像我们在这个示例中那样为多阶段构建打标签。

运行`docker image ls`以查看构建操作拉取和创建的镜像列表。

```
$ docker image ls

REPO    TAG             IMAGE ID        CREATED        SIZE
node    latest          9ea1c3e33a0b    `4` days ago     673MB
<none>  <none>          6598db3cefaf    `3` mins ago     816MB
maven   latest          cbf114925530    `2` weeks ago    750MB
<none>  <none>          d5b619b83d9e    `1` min ago      891MB
java    `8`-jdk-alpine    3fd9dd82815c    `7` months ago   145MB
multi   stage           3dc0d5e6223e    `1` min ago      210MB 
```

上面输出的第一行显示了`storefront`阶段拉取的`node:latest`镜像。下面的镜像是该阶段生成的镜像（通过添加代码并运行 npm install 和构建操作创建）。两者都是非常大的镜像，包含了大量的构建工具。

第三和第四行是由`appserver`阶段拉取和生成的镜像。这两个镜像都很大，包含了很多构建工具。

最后一行是由 Dockerfile 中最终构建阶段（stage2/production）构建的`multi:stage`镜像。你可以看到，这个镜像比之前阶段拉取和生成的镜像要小得多。这是因为它是基于更小的`java:8-jdk-alpine`镜像，并且只添加了前几个阶段的与生产相关的应用文件。

最终结果是通过一个普通的`docker image build`命令和零额外脚本创建的小型生产镜像！

多阶段构建是 Docker 17.05 中的新功能，非常适合构建小型的生产级镜像。

#### 一些最佳实践。

在结束本章之前，让我们列举一些最佳实践。这个列表并不打算是详尽无遗的。

##### 利用构建缓存

Docker 使用的构建过程有一个缓存的概念。看到缓存的影响最好的方法是在一个干净的 Docker 主机上构建一个新的镜像，然后立即重复相同的构建。第一次构建将拉取镜像并花费时间构建层。第二次构建将几乎立即完成。这是因为第一次构建的产物，比如层，被缓存并被后续构建所利用。

正如我们所知，`docker image build` 过程是逐行迭代 Dockerfile，从顶部开始。对于每个指令，Docker 会查看它的缓存中是否已经有了该指令的镜像层。如果有，这就是*缓存命中*，它会使用该层。如果没有，这就是*缓存未命中*，它会根据该指令构建一个新的层。获得*缓存命中*可以极大地加快构建过程。

让我们再仔细看一下。

我们将使用这个示例 Dockerfile 进行快速演示：

```
FROM alpine
RUN apk add --update nodejs nodejs-npm
COPY . /src
WORKDIR /src
RUN npm install
EXPOSE 8080
ENTRYPOINT ["node", "./app.js"] 
```

`第一条指令告诉 Docker 使用`alpine:latest`镜像作为其*基础镜像*。如果该镜像已经存在于主机上，构建将继续进行到下一条指令。如果该镜像不存在，它将从 Docker Hub（docker.io）上拉取。

下一条指令（`RUN apk...`）针对镜像运行一个命令。此时，Docker 会检查构建缓存，查找是否有一个层是从相同的基础镜像构建的，并且使用了当前要执行的相同指令。在这种情况下，它正在寻找一个直接在`alpine:latest`之上构建的层，通过执行`RUN apk add --update nodejs nodejs-npm`指令。

如果它找到了一个层，它会跳过该指令，链接到该现有层，并继续使用缓存进行构建。如果它**没有**找到一个层，它会使缓存失效并构建该层。使缓存失效的操作会使其在剩余的构建过程中失效。这意味着所有后续的 Dockerfile 指令都将完全完成，而不会尝试引用构建缓存。

假设 Docker 已经在缓存中为此指令创建了一个层（缓存命中）。假设该层的 ID 是`AAA`。

下一条指令将一些代码复制到镜像中（`COPY . /src`）。由于前一条指令导致了缓存命中，Docker 现在会检查是否有一个缓存的层是从`AAA`层使用`COPY . /src`命令构建的。如果有，它会链接到该层并继续执行下一条指令。如果没有，它会构建该层并使得剩余的构建过程缓存失效。

假设 Docker 已经在缓存中为此指令创建了一个层（缓存命中）。假设该层的 ID 是`BBB`。

该过程将继续进行，直到 Dockerfile 的其余部分。

重要的是要理解一些事情。

首先，一旦任何指令导致缓存未命中（没有找到该指令的层），缓存将不再用于整个构建的剩余部分。这对您如何编写 Dockerfile 有重要影响。尝试以一种方式构建它们，将可能更改的任何指令放在文件末尾。这意味着直到构建的后期阶段才会发生缓存未命中，从而使构建尽可能多地受益于缓存。

您可以通过向`docker image build`命令传递`--no-cache=true`标志来强制构建过程忽略整个缓存。

还重要的是要理解`COPY`和`ADD`指令包括确保复制到镜像中的内容自上次构建以来没有更改的步骤。例如，Dockerfile 中的`COPY . /src`指令可能自上次构建以来没有更改，**但是...**被复制到镜像中的目录的内容**已经**发生了变化！

为了防止这种情况发生，Docker 对每个被复制的文件执行校验和，并将其与缓存层中相同文件的校验和进行比较。如果校验和不匹配，则缓存将被作废，并构建一个新的层。

##### 压缩镜像

压缩镜像并不是一个最佳实践，因为它有利有弊。

在高层次上，Docker 遵循构建镜像的正常流程，但然后添加了一个额外的步骤，将所有内容压缩成一个单一层。

在镜像开始具有大量层并且这并不理想的情况下，压缩可能是有益的。例如，当创建一个新的基础镜像，您希望将来从中构建其他镜像时 - 这作为单层镜像要好得多。

消极的一面是，压缩的镜像不共享镜像层。这可能导致存储效率低下和更大的推送和拉取操作。

如果要创建压缩的镜像，请在`docker image build`命令中添加`--squash`标志。

图 8.8 显示了压缩镜像带来的一些效率低下。两个镜像除了一个是压缩的，另一个不是，其他都完全相同。压缩的镜像与主机上的其他镜像共享层（节省磁盘空间），但压缩的镜像不共享。压缩的镜像还需要在`docker image push`命令中发送每个字节到 Docker Hub，而非压缩的镜像只需要发送唯一的层。

![图 8.8 - 压缩镜像与非压缩镜像](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-dpdv/img/figure8-8.png)

图 8.8 - 压缩镜像与非压缩镜像

##### 不安装推荐软件

如果您正在构建 Linux 镜像，并使用 apt 软件包管理器，您应该在`apt-get install`命令中使用`no-install-recommends`标志。这可以确保`apt`只安装主要依赖项（`Depends`字段中的软件包），而不是推荐或建议的软件包。这可以大大减少下载到镜像中的不需要的软件包的数量。

##### 不要从 MSI 软件包（Windows）安装

如果您正在构建 Windows 映像，应尽量避免使用 MSI 软件包管理器。它不够节省空间，导致映像比所需的要大得多。

### 容器化应用程序 - 命令

+   `docker image build`是一个读取 Dockerfile 并将应用程序容器化的命令。`-t`标志为映像打标签，`-f`标志允许您指定 Dockerfile 的名称和位置。使用`-f`标志，可以使用任意名称和位置的 Dockerfile。*构建上下文*是您的应用程序文件所在的位置，可以是本地 Docker 主机上的目录，也可以是远程 Git 存储库。

+   Dockerfile 中的`FROM`指令指定了要构建的新映像的基础映像。通常是 Dockerfile 中的第一条指令。

+   Dockerfile 中的`RUN`指令允许您在映像内部运行命令，从而创建新的层。每个`RUN`指令都会创建一个新的层。

+   Dockerfile 中的`COPY`指令将文件添加到映像中作为一个新层。通常使用`COPY`指令将应用程序代码复制到映像中。

+   Dockerfile 中的`EXPOSE`指令记录了应用程序使用的网络端口。

+   Dockerfile 中的`ENTRYPOINT`指令设置了在将映像启动为容器时要运行的默认应用程序。

+   其他 Dockerfile 指令包括`LABEL`、`ENV`、`ONBUILD`、`HEALTHCHECK`、`CMD`等等…

### 章节总结

在本章中，我们学习了如何将应用程序容器化（Docker 化）。

我们从远程 Git 存储库中提取了一些应用程序代码。存储库包括应用程序代码以及一个包含如何将应用程序构建成映像的 Dockerfile。我们学习了 Dockerfile 的基础知识，并将其输入到`docker image build`命令中以创建一个新的映像。

创建映像后，我们启动了一个容器并使用 Web 浏览器测试了它的工作情况。

之后，我们了解了多阶段构建如何为我们提供了一种简单的方式来构建和部署更小的映像到生产环境。

我们还了解到 Dockerfile 是一个很好的工具，可以用来记录应用程序。因此，它可以加快新开发人员的入职速度，并弥合开发人员和运维人员之间的鸿沟！考虑到这一点，将其视为代码，并将其检入和检出源代码控制系统。

尽管引用的例子是一个基于 Linux 的例子，但容器化 Windows 应用程序的过程是相同的：从您的应用程序代码开始，创建描述应用程序的 Dockerfile，使用`docker image build`构建镜像。工作完成！


# 第十章：使用 Docker Compose 部署应用程序

在本章中，我们将看看如何使用 Docker Compose 部署多容器应用程序。

Docker Compose 和 Docker Stacks 非常相似。在本章中，我们将专注于 Docker Compose，它在**单引擎模式**下部署和管理多容器应用程序在 Docker 节点上运行。在后面的章节中，我们将专注于 Docker Stacks。Stacks 在**Swarm 模式**下部署和管理多容器应用程序。

我们将把这一章分成通常的三个部分：

+   简而言之

+   深入研究

+   命令

### 使用 Compose 部署应用程序-简而言之

大多数现代应用程序由多个较小的服务组成，这些服务相互交互形成一个有用的应用程序。我们称之为微服务。一个简单的例子可能是一个具有以下四个服务的应用程序：

+   Web 前端

+   排序

+   目录

+   后端数据库

把所有这些放在一起，你就有了一个*有用的应用程序*。

部署和管理大量服务可能很困难。这就是*Docker Compose*发挥作用的地方。

与使用脚本和冗长的`docker`命令将所有内容粘合在一起不同，Docker Compose 允许你在一个声明性的配置文件中描述整个应用程序。然后你可以用一个命令部署它。

一旦应用程序被*部署*，你可以用一组简单的命令*管理*它的整个生命周期。你甚至可以将配置文件存储和管理在版本控制系统中！这一切都非常成熟 :-D

这就是基础知识。让我们深入了解一下。

### 使用 Compose 部署应用程序-深入研究

我们将把深入研究部分分为以下几个部分：

+   Compose 背景

+   安装 Compose

+   Compose 文件

+   使用 Compose 部署应用程序

+   使用 Compose 管理应用程序

#### Compose 背景

一开始是*Fig*。Fig 是一个强大的工具，由一个叫做*Orchard*的公司创建，它是管理多容器 Docker 应用程序的最佳方式。它是一个 Python 工具，位于 Docker 之上，允许你在一个单独的 YAML 文件中定义整个多容器应用程序。然后你可以用`fig`命令行工具部署应用程序。Fig 甚至可以管理整个应用程序的生命周期。

在幕后，Fig 会读取 YAML 文件，并通过 Docker API 部署和管理应用程序。这是一件好事！

事实上，2014 年，Docker 公司收购了 Orchard 并将 Fig 重新命名为*Docker Compose*。命令行工具从`fig`改名为`docker-compose`，自收购以来，它一直是一个外部工具，可以附加到 Docker Engine 上。尽管它从未完全集成到 Docker Engine 中，但它一直非常受欢迎并被广泛使用。

就目前而言，Compose 仍然是一个外部的 Python 二进制文件，您必须在运行 Docker Engine 的主机上安装它。您可以在 YAML 文件中定义多容器（多服务）应用程序，将 YAML 文件传递给`docker-compose`二进制文件，然后 Compose 通过 Docker Engine API 部署它。

是时候看它的表现了。

#### 安装 Compose

Docker Compose 在多个平台上都可用。在本节中，我们将演示在 Windows、Mac 和 Linux 上安装它的*一些*方法。还有更多的安装方法，但我们在这里展示的方法可以让您开始。

##### 在 Windows 10 上安装 Compose

在 Windows 10 上运行 Docker 的推荐方式是*Docker for Windows (DfW)*。Docker Compose 包含在标准的 DfW 安装中。因此，如果您安装了 DfW，您就有了 Docker Compose。

使用以下命令检查是否已安装 Compose。您可以从 PowerShell 或 CMD 终端运行此命令。

```
> docker-compose --version
docker-compose version 1.18.0, build 8dd22a96 
```

如果您需要有关在 Windows 10 上安装*Docker for Windows*的更多信息，请参阅**第三章：安装 Docker**。

##### 在 Mac 上安装 Compose

与 Windows 10 一样，Docker Compose 作为*Docker for Mac (DfM)*的一部分安装。因此，如果您安装了 DfM，您就有了 Docker Compose。

从终端窗口运行以下命令以验证您是否安装了 Docker Compose。

```
$ docker-compose --version
docker-compose version `1`.18.0, build 8dd22a96 
```

如果您需要有关在 Mac 上安装*Docker for Mac*的更多信息，请参阅**第三章：安装 Docker**。

##### 在 Windows Server 上安装 Compose

Docker Compose 作为一个独立的二进制文件安装在 Windows Server 上。要使用它，您需要在 Windows Server 上安装最新的 Docker。

在 PowerShell 终端中键入以下命令以安装 Docker Compose。

为了可读性，该命令使用反引号（`）来转义回车并将命令包装在多行上。

以下命令安装了 Docker Compose 的`1.18.0`版本。您可以安装此处列出的任何版本：https://github.com/docker/compose/releases。只需用您想要安装的版本替换 URL 中的`1.18.0`。

```
> Invoke-WebRequest ` "https://github.com/docker/compose/releases/download/1\
.18.0/docker-compose-Windows-x86_64.exe" `
-UseBasicParsing `
-OutFile $Env:ProgramFiles\docker\docker-compose.exe

Writing web request
Writing request stream... (Number of bytes written: 5260755) 
```

使用`docker-compose --version`命令验证安装。

```
> docker-compose --version
docker-compose version 1.18.0, build 8dd22a96 
```

Compose 现在已安装。只要您的 Windows Server 机器安装了最新版本的 Docker Engine，您就可以开始了。

##### 在 Linux 上安装 Compose

在 Linux 上安装 Docker Compose 是一个两步过程。首先，您使用`curl`命令下载二进制文件。然后使用`chmod`使其可执行。

要使 Docker Compose 在 Linux 上工作，您需要一个可用的 Docker Engine 版本。

以下命令将下载 Docker Compose 的版本`1.18.0`并将其复制到`/usr/bin/local`。您可以在[GitHub](https://github.com/docker/compose/releases)的发布页面上检查最新版本，并将 URL 中的`1.18.0`替换为您想要安装的版本。

该命令可能会在书中跨越多行。如果您在一行上运行该命令，您需要删除任何反斜杠（`\`）。

```
`$` `curl` `-``L` `\`
 `https``:``//``github``.``com``/``docker``/``compose``/``releases``/``download``/``1.18.0``/``docker``-``compose-``````

`uname` `-``s`````-`````uname` `-``m```` `\`
 `-``o` `/``usr``/``local``/``bin``/``docker``-``compose`

`% Total    % Received   Time        Time     Time    Current`
                        `Total`       `Spent`    `Left`    `Speed`
`100`   `617`    `0`   `617`    `0` `--:--:--` `--:--:--` `--:--:--`  `1047`
`100` `8280``k`  `100` `8280``k`    `0`  `0``:``00``:``03`  `0``:``00``:``03` `--:--:--`  `4069``k` 
```

 `Now that you’ve downloaded the `docker-compose` binary, use the following `chmod` command to make it executable.

```
$ chmod +x /usr/local/bin/docker-compose 
```

 `Verify the installation and check the version.

```
$ docker-compose --version
docker-compose version `1`.18.0, build 8dd22a9 
```

 `You’re ready to use Docker Compose on Linux.

You can also use `pip` to install Compose from its Python package. But we don’t want to waste pages showing every possible installation method. Enough is enough, time to move on!

#### Compose files

Compose uses YAML files to define multi-service applications. YAML is a subset of JSON, so you can also use JSON. However, all of the examples in this chapter will be YAML.

The default name for the Compose YAML file is `docker-compose.yml`. However, you can use the `-f` flag to specify custom filenames.

The following example shows a very simple Compose file that defines a small Flask app with two services (`web-fe` and `redis`). The app is a simple web server that counts the number of visits and stores the value in Redis. We’ll call the app `counter-app` and use it as the example application for the rest of the chapter.

```
version: "3.5"
services:
  web-fe:
    build: .
    command: python app.py
    ports:
      - target: 5000
        published: 5000
    networks:
      - counter-net
    volumes:
      - type: volume
        source: counter-vol
        target: /code
  redis:
    image: "redis:alpine"
    networks:
      counter-net:

networks:
  counter-net:

volumes:
  counter-vol: 
```

 `We’ll skip through the basics of the file before taking a closer look.

The first thing to note is that the file has 4 top-level keys:

*   `version`
*   `services`
*   `networks`
*   `volumes`

Other top-level keys exist, such as `secrets` and `configs`, but we’re not looking at those right now.

The `version` key is mandatory, and it’s always the first line at the root of the file. This defines the version of the Compose file format (basically the API). You should normally use the latest version.

It’s important to note that the `versions` key does not define the version of Docker Compose or the Docker Engine. For information regarding compatibility between versions of the Docker Engine, Docker Compose, and the Compose file format, google “Compose file versions and upgrading”.

For the remainder of this chapter we’ll be using version 3 or higher of the Compose file format.

The top-level `services` key is where we define the different application services. The example we’re using defines two services; a web front-end called `web-fe`, and an in-memory database called `redis`. Compose will deploy each of these services as its own container.

The top-level `networks` key tells Docker to create new networks. By default, Compose will create `bridge` networks. These are single-host networks that can only connect containers on the same host. However, you can use the `driver` property to specify different network types.

The following code can be used in your Compose file to create a new *overlay* network called `over-net` that allows standalone containers to connect to it (`attachable`).

```
`networks``:`
  `over``-``net``:`
  `driver``:` `overlay`
  `attachable``:` `true` 
```

 `The top-level `volumes` key is where we tell Docker to create new volumes.

##### Our specific Compose file

The example file we’ve listed uses the Compose v3.5 file format, defines two services, defines a network called counter-net, and defines a volume called counter-vol.

Most of the detail is in the `services` section, so let’s take a closer look at that.

The services section of our Compose file has two second-level keys:

*   web-fe
*   redis

Each of these defines a service in the app. It’s important to understand that Compose will deploy each of these as a container, and it will use the name of the keys as part of the container names. In our example, we’ve defined two keys; `web-fe` and `redis`. This means Compose will deploy two containers, one will have `web-fe` in its name and the other will have `redis`.

Within the definition of the `web-fe` service, we give Docker the following instructions:

*   `build: .` This tells Docker to build a new image using the instructions in the `Dockerfile` in the current directory (`.`). The newly built image will be used to create the container for this service.
*   `command: python app.py` This tells Docker to run a Python app called `app.py` as the main app in the container. The `app.py` file must exist in the image, and the image must contain Python. The Dockerfile takes care of both of these requirements.
*   `ports:` Tells Docker to map port 5000 inside the container (`-target`) to port 5000 on the host (`published`). This means that traffic sent to the Docker host on port 5000 will be directed to port 5000 on the container. The app inside the container listens on port 5000.
*   `networks:` Tells Docker which network to attach the service’s container to. The network should already exist, or be defined in the `networks` top-level key. If it’s an overlay network, it will need to have the `attachable` flag so that standalone containers can be attached to it (Compose deploys standalone containers instead of Docker Services).
*   `volumes:` Tells Docker to mount the counter-vol volume (`source:`) to `/code` (‘target:’) inside the container. The `counter-vol` volume needs to already exist, or be defined in the `volumes` top-level key at the bottom of the file.

In summary, Compose will instruct Docker to deploy a single standalone container for the `web-fe` service. It will be based on an image built from a Dockerfile in the same directory as the Compose file. This image will be started as a container and run `app.py` as its main app. It will expose itself on port 5000 on the host, attach to the `counter-net` network, and mount a volume to `/code`.

> **Note:** Technically speaking, we don’t need the `command: python app.py` option. This is because the application’s Dockerfile already defines `python app.py` as the default app for the image. However, we’re showing it here so you know how it works. You can also use it to override CMD instructions set in Dockerfiles.

The definition of the `redis` service is simpler:

*   `image: redis:alpine` This tells Docker to start a standalone container called `redis` based on the `redis:alpine` image. This image will be pulled from Docker Hub.
*   `networks:` The `redis` container will be attached to the `counter-net` network.

As both services will be deployed onto the same `counter-net` network, they will be able to resolve each other by name. This is important as the application is configured to communicate with the redis service by name.

Now that we understand how the Compose file works, let’s deploy it!

#### Deploying an app with Compose

In this section, we’ll deploy the app defined in the Compose file from the previous section. To do this, you’ll need the following 4 files from https://github.com/nigelpoulton/counter-app:

*   Dockerfile
*   app.py
*   requirements.txt
*   docker-compose.yml

Clone the Git repo locally.

```
$ git clone https://github.com/nigelpoulton/counter-app.git

Cloning into `'counter-app'`...
remote: Counting objects: `9`, `done`.
remote: Compressing objects: `100`% `(``8`/8`)`, `done`.
remote: Total `9` `(`delta `1``)`, reused `5` `(`delta `0``)`, pack-reused `0`
Unpacking objects: `100`% `(``9`/9`)`, `done`.
Checking connectivity... `done`. 
```

 `Cloning the repo will create a new sub-directory called `counter-app`. This will contain all of the required files and will be considered your *build context*. Compose will also use the name of the directory (`counter-app`) as your project name. We’ll see this later, but Compose will pre-pend all resource names with `counter-app_`.

Change into the `counter-app` directory and check the files are present.

```
$ `cd` counter-app
$ ls
app.py  docker-compose.yml  Dockerfile  requirements.txt ... 
```

 `Let’s quickly describe each file:

*   `app.py` is the application code (a Python Flask app)
*   `docker-compose.yml` is the Docker Compose file that describes how Docker should deploy the app
*   `Dockerfile` describes how to build the image for the `web-fe` service
*   `requirements.txt` lists the Python packages required for the app

Feel free to inspect the contents of each file.

The `app.py` file is obviously the core of the application. But `docker-compose.yml` is the glue that sticks all the app components together.

Let’s use Compose to bring the app up. You must run the all of the following commands from within the `counter-app` directory that you just cloned from GitHub.

```
$ docker-compose up `&`

`[``1``]` `1635`
Creating network `"counterapp_counter-net"` with the default driver
Creating volume `"counterapp_counter-vol"` with default driver
Pulling redis `(`redis:alpine`)`...
alpine: Pulling from library/redis
1160f4abea84: Pull `complete`
a8c53d69ca3a: Pull `complete`
<Snip>
web-fe_1  `|`  * Debugger PIN: `313`-791-729 
```

 `It’ll take a few seconds for the app to come up, and the output can be quite verbose.

We’ll step through what happened in a second, but first let’s talk about the `docker-compose` command.

`docker-compose up` is the most common way to bring up a Compose app (we’re calling a multi-container app defined in a Compose file a *Compose app*). It builds all required images, creates all required networks and volumes, and starts all required containers.

By default, `docker-compose up` expects the name of the Compose file to `docker-compose.yml` or `docker-compose.yaml`. If your Compose file has a different name, you need to specify it with the `-f` flag. The following example will deploy an application from a Compose file called `prod-equus-bass.yml`

```
$ docker-compose -f prod-equus-bass.yml up 
```

 `It’s also common to use the `-d` flag to bring the app up in the background. For example:

```
docker-compose up -d

--OR--

docker-compose -f prod-equus-bass.yml up -d 
```

 `Our example brought the app up in the foreground (we didn’t use the `-d` flag), but we used the `&` to give us the terminal window back. This is not normal, but it will output logs directly in our terminal window which we’ll use later.

Now that the app is built and running, we can use normal `docker` commands to view the images, containers, networks, and volumes that Compose created.

```
$ docker image ls
REPOSITORY          TAG         IMAGE ID    CREATED         SIZE
counterapp_web-fe   latest      `96`..6ff9e   `3` minutes ago   `95`.9MB
python              `3`.4-alpine  `01`..17a02   `2` weeks ago     `85`.5MB
redis               alpine      ed..c83de   `5` weeks ago     `26`.9MB 
```

 `We can see that three images were either built or pulled as part of the deployment.

The `counterapp_web-fe:latest` image was created by the `build: .` instruction in the `docker-compose.yml` file. This instruction caused Docker to build a new image using the Dockerfile in the same directory. It contains the application code for the Python Flask web app, and was built from the `python:3.4-alpine` image. See the contents of the `Dockerfile` for more information.

```
FROM python:3.4-alpine           << Base image
ADD . /code                      << Copy app into image
WORKDIR /code                    << Set working directory
RUN pip install -r requirements.txt  << install requirements
CMD ["python", "app.py"]         << Set the default app 
```

 `I’ve added comments to the end of each line to help explain. They must be removed before deploying the app.

Notice how Compose has named the newly built image as a combination of the project name (counter-app), and the resource name as specified in the Compose file (web-fe). Compose has removed the dash (`-`) from the project name. All resources deployed by Compose will follow this naming convention.

The `redis:alpine` image was pulled from Docker Hub by the `image: "redis:alpine"` instruction in the `.Services.redis` section of the Compose file.

The following container listing shows two containers. The name of each is prefixed with the name of the project (name of the working directory). Also, each one has a numeric suffix that indicates the instance number — this is because Compose allows for scaling.

```
$ docker container ls
ID    COMMAND           STATUS    PORTS                   NAMES
`12`..  `"python app.py"`   Up `2` min  `0`.0.0.0:5000->5000/tcp  counterapp_web-fe_1
`57`..  `"docker-entry.."`  Up `2` min  `6379`/tcp                counterapp_redis_1 
```

 `The `counterapp_web-fe` container is running the application’s web front end. This is running the `app.py` code and is mapped to port `5000` on all interfaces on the Docker host. We’ll connect to this in just a second.

The following network and volume listings show the `counterapp_counter-net` and `counterapp_counter-vol` networks and volumes.

```
$ docker network ls
NETWORK ID     NAME                     DRIVER    SCOPE
1bd949995471   bridge                   bridge    `local`
40df784e00fe   counterapp_counter-net   bridge    `local`
f2199f3cf275   host                     host      `local`
67c31a035a3c   none                     null      `local`

$ docker volume ls
DRIVER     VOLUME NAME
<Snip>
`local`      counterapp_counter-vol 
```

 `With the application successfully deployed, you can point a web browser at your Docker host on port `5000` and see the application in all its glory.

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-dpdv/img/figure9-1.png)

Pretty impressive ;-)

Hitting your browser’s refresh button will cause the counter to increment. Feel free to inspect the app (`app.py`) to see how the counter data is stored in the Redis back-end.

If you brought the application up using the `&`, you will be able to see the `HTTP 200` response codes being logged in the terminal window. These indicate successful requests, and you’ll see one for each time you load the web page.

```
web-fe_1  | 172.18.0.1 - - [09/Jan/2018 11:13:21] "GET / HTTP/1.1" 200 -
web-fe_1  | 172.18.0.1 - - [09/Jan/2018 11:13:33] "GET / HTTP/1.1" 200 - 
```

 `Congratulations. You’ve successfully deployed a multi-container application using Docker Compose!

#### Managing an app with Compose

In this section, we’ll see how to start, stop, delete, and get the status of applications being managed by Docker Compose. We’ll also see how the volume we’re using can be used to directly inject updates to the app’s web front-end.

As the application is already up, let’s see how to bring it down. To do this, replace the `up` sub-command with `down`.

```
$ docker-compose down
 `1`. Stopping counterapp_redis_1  ...
 `2`. Stopping counterapp_web-fe_1 ...
 `3`. redis_1   `|` `1`:signal-handler Received SIGTERM scheduling shutdown...
 `4`. redis_1   `|` `1`:M `09` Jan `11`:16:00.456 `# User requested shutdown...`
 `5`. redis_1   `|` `1`:M `09` Jan `11`:16:00.456 * Saving the final RDB snap...
 `6`. redis_1   `|` `1`:M `09` Jan `11`:16:00.463 * DB saved on disk
 `7`. Stopping counterapp_redis_1  ... `done`
 `8`. counterapp_redis_1 exited with code `0`
 `9`. Stopping counterapp_web-fe_1 ... `done`
`10`. Removing counterapp_redis_1  ... `done`
`11`. Removing counterapp_web-fe_1 ... `done`
`12`. Removing network counterapp_counter-net
`13`. `[``1``]`+  Done          docker-compose up 
```

 `Because we started the app with the `&`, it’s running in the foreground. This means we get a verbose output to the terminal, giving us an excellent insight into how things work. Let’s step through what each line is telling us.

Lines 1 and 2 are stopping the two services. These are the `web-fe` and `redis` services defined in the Compose file.

Line 3 shows that the `stop` instruction sends a `SIGTERM` signal. This is sent to the PID 1 process in each container. Lines 4-6 show the Redis container gracefully handling the signal and shutting itself down. Lines 7 and 8 report the success of stop operation.

Line 9 shows the `web-fe` service successfully stopping.

Lines 10 and 11 show the stopped services being removed.

Line 12 shows the `counter-net` network being removed, and line 13 shows the `docker-compose up` process exiting.

It’s important to note that the `counter-vol` volume was **not** deleted. This is because volumes are intended to be long-term persistent data stores. As such, their lifecycle is entirely decoupled from the containers they serve. Running a `docker volume ls` will show that the volume is still present on the system. If you’d written any data to the volume it would still exist.

Also, any images that were built or pulled as part of the `docker-compose up` operation will still remain on the system. This means future deployments of the app will be faster.

Let’s look at a few other `docker-compose` sub-commands.

Use the following command to bring the app up again, but this time in the background.

```
$ docker-compose up -d
Creating network `"counterapp_counter-net"` with the default driver
Creating counterapp_redis_1  ... `done`
Creating counterapp_web-fe_1 ... `done` 
```

 `See how the app started much faster this time — the counter-vol volume already exists, and no images needed building or pulling.

Show the current state of the app with the `docker-compose ps` command.

```
$ docker-compose ps
Name                  Command               State   Ports
--------------------------------------------------------------------------
counterapp_redis_1    docker-entrypoint...  Up      `6379`/tcp
counterapp_web-fe_1   python app.py         Up      `0`.0.0.0:5000->5000/tcp 
```

 `We can see both containers, the commands they are running, their current state, and the network ports they are listening on.

Use the `docker-compose top` command to list the processes running inside of each service (container).

```
$ docker-compose top
counterapp_redis_1
PID     USER     TIME     COMMAND
------------------------------------
`843`   dockrema   `0`:00   redis-server

counterapp_web-fe_1
PID    USER   TIME             COMMAND
-------------------------------------------------
`928`    root   `0`:00   python app.py
`1016`   root   `0`:00   /usr/local/bin/python app.py 
```

 `The PID numbers returned are the PID numbers as seen from the Docker host (not from within the containers).

Use the `docker-compose stop` command to stop the app without deleting its resources. Then show the status of the app with `docker-compose ps`.

```
$ docker-compose stop
Stopping counterapp_web-fe_1 ... `done`
Stopping counterapp_redis_1  ... `done`

$ docker-compose ps
Name                  Command                      State
---------------------------------------------------------
counterapp_redis_1    docker-entrypoint.sh redis   Exit `0`
counterapp_web-fe_1   python app.py                Exit `0` 
```

 `As we can see, stopping a Compose app does not remove the application definition from the system. It just stops the app’s containers. You can verify this with the `docker container ls -a` command.

You can delete a stopped Compose app with the `docker-compose rm` command. This will delete the containers and networks the app is using, but it will not delete volumes or images. Nor will it delete the application source code (`app.py`, `Dockerfile`, `requirements.txt`, and `docker-compose.yml`) in your project directory.

Restart the app with the `docker-compose restart` command.

```
$ docker-compose restart
Restarting counterapp_web-fe_1 ... `done`
Restarting counterapp_redis_1  ... `done` 
```

 `Verify the operation.

```
$ docker-compose ps
Name                  Command               State   Ports
--------------------------------------------------------------------------
counterapp_redis_1    docker-entrypoint...  Up      `6379`/tcp
counterapp_web-fe_1   python app.py         Up      `0`.0.0.0:5000->5000/tcp 
```

 `Use the `docker-compose down` command to **stop and delete** the app with a single command.

```
$ docker-compose down
Stopping counterapp_web-fe_1 ... `done`
Stopping counterapp_redis_1  ... `done`
Removing counterapp_web-fe_1 ... `done`
Removing counterapp_redis_1  ... `done`
Removing network counterapp_counter-net 
```

 `The app is now deleted. Only its images, volumes and source code remain.

Let’s deploy the app one last time and see its volume in action.

```
$ docker compose up -d
Creating network `"counterapp_counter-net"` with the default driver
Creating counterapp_redis_1  ... `done`
Creating counterapp_web-fe_1 ... `done` 
```

 `If you look in the Compose file, you’ll see that we’re defing a new volume called `counter-vol` and mounting it in to the `web-fe` service at `/code`.

```
`services``:`
  `web``-``fe``:`
  `<``Snip``>`
    `volumes``:`
      `-` `type``:` `volume`
        `source``:` `counter``-``vol`
        `target``:` `/``code`
`<``Snip``>`
`volumes``:`
  `counter``-``vol``:` 
```

 `The first time we deployed the app, Compose checked to see if a volume already existed with this name. It did not, so it created it. You can see it with the `docker volume ls` command.

```
$ docker volume ls
RIVER              VOLUME NAME
`local`               counterapp_counter-vol 
```

 `It’s also worth knowing that Compose builds networks and volumes **before** deploying services. This makes sense, as they are lower-level infrastructure objects that are consumed by services (containers). The following snippet shows Compose creating the network and volume as its first two tasks (even before building and pulling images).

```
$ docker-compose up -d

Creating network `"counterapp_counter-net"` with the default driver
Creating volume `"counterapp_counter-vol"` with default driver
Pulling redis `(`redis:alpine`)`...
<Snip> 
```

 `If we take another look at the service definition for `web-fe`, we’ll see that it’s mounting the counter-app volume into the service’s container at `/code`. We can also see from the Dockerfile that `/code` is where the app is installed and executed from. Net result, our app code resides on a Docker volume.

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-dpdv/img/figure9-2.png)

This all means we can make changes to files in the volume, from the host side, and have them reflected immediately in the app. Let’s see it.

The next few steps will walk through the following process. We’ll edit the `app.py` file in the project’s working directory so that the app will display different text in the web browser. We’ll copy updated app to the volume on the Docker host. We’ll refresh the app’s web page to see the updated text. This will work because whatever you write to the location of the volume on the Docker host will immediately appear in the volume in the container.

Use you favourite text editor to edit the `app.py` file in the projects working directory. We’ll use `vim` in the example.

```
$ vim ~/counter-app/app.py 
```

 `Change text between the double quote marks (“”) on line 22\. The line starts with `return "What's up..."`. Enter any text you like, as long as it’s within the double-quote marks, and save your changes.

Now that we’ve updated the app, we need to copy it into the volume on the Docker host. Each Docker volume is exposed at a location within the Docker host’s filesystem, as well as a mount point in one or more containers. Use the following `docker volume inspect` command to find where the volume is exposed on the Docker host.

```
$ docker volume inspect counterapp_counter-vol `|` grep Mount

`"Mountpoint"`: `"/var/lib/docker/volumes/counterapp_counter-vol/_data"`, 
```

 `Copy the updated app file to the volume’s mount point on your Docker host. This will make it appear in the `web-fe` container at `/code`. The operation will overwrite the existing `/code/app.py` file in the container.

```
$ cp ~/counterapp/app.py `\`
  /var/lib/docker/volumes/counterapp_counter-vol/_data/app.py 
```

 `The updated app file is now on the container. Connect to the app to see your change. You can do this by pointing your web browser to the IP of your Docker host on port 5000.

Figure 9.3 shows the updated app.

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-dpdv/img/figure9-3.png)

Obviously you wouldn’t do this in production, but it’s a real time-saver in development.

Congratulations! You’ve deployed and managed a simple multi-container app using Docker Compose.

Before reminding ourselves of the major commands we learned, it’s important to understand that this was a very simple example. Docker Compose is capable of deploying and managing far more complex applications.

### Deploying apps with Compose - The commands

*   `docker-compose up` is the command we use to deploy a Compose app. It expects the Compose file to be called `docker-compose.yml` or `docker-compose.yaml`, but you can specify a custom filename with the `-f` flag. It’s common to start the app in the background with the `-d` flag.
*   `docker-compose stop` will stop all of the containers in a Compose app without deleting them from the system. The app can be easily restarted with `docker-compose restart`.
*   `docker-compose rm` will delete a stopped Compose app. It will delete containers and networks, but it will not delete volumes and images.
*   `docker-compose restart` will restart a Compose app that has been stopped with `docker-compose stop`. If you have made changes to your Compose app since stopping it, these changes will **not** appear in the restarted app. You will need to re-deploy the app to get the changes.
*   `docker-compose ps` will list each container in the Compose app. It shows current state, the command each one is running, and network ports.
*   `docker-compose down` will stop and delete a running Compose app. It deletes containers and networks, but not volumes and images.

### Chapter Summary

In this chapter, we learned how to deploy and manage a multi-container application using Docker Compose.

Docker Compose is a Python application that we install on top of the Docker Engine. It lets us define multi-container apps in a single declarative configuration file and deploy it with a single command.

Compose files can be YAML or JSON, and they define all of the containers, networks, volumes, and secrets that an application requires. We then feed the file to the `docker-compose` command line tool, and Compose instructs Docker to deploy it.

Once the app is deployed, we can manage its entire lifecycle using the many `docker-compose` sub-commands.

We also saw how volumes can be used to mount changes directly into containers.

Docker Compose is very popular with developers, and the Compose file is an excellent source of application documentation — it defies all the services that make up the app, the images they use, ports they expose, networks and volumes they use, and much more. As such, it can help bridge the gap between dev and ops. You should also treat your Compose files as if they were code. This means, among other things, storing them in source control repos.``````````````````````````````````


# 第十一章：Docker Swarm

现在我们知道如何安装 Docker，拉取镜像并使用容器，我们需要的下一步是以规模处理事物的方法。这就是 Docker Swarm 出现的地方。

在高层次上，Swarm 有两个主要组件：

+   一个安全的集群

+   一个编排引擎

像往常一样，我们将把本章分为三个部分：

+   TLDR

+   深入探讨

+   命令

我们将使用基于 Linux 的 Swarm 的示例和输出。然而，大多数命令和功能都适用于 Windows 上的 Docker。

### Docker Swarm - TLDR

Docker Swarm 有两个方面：一个是企业级安全的 Docker 主机集群，另一个是用于编排微服务应用程序的引擎。

在集群方面，它将一个或多个 Docker 节点分组，并允许您将它们作为一个集群进行管理。开箱即用，您将获得加密的分布式集群存储、加密网络、相互 TLS、安全的集群加入令牌，以及使管理和轮换证书变得轻而易举的 PKI！您甚至可以非破坏性地添加和删除节点。这是一件美妙的事情！

在编排方面，Swarm 公开了丰富的 API，允许您轻松部署和管理复杂的微服务应用程序。您可以在声明性清单文件中定义应用程序，并使用本机 Docker 命令部署它们。您甚至可以执行滚动更新、回滚和扩展操作。同样，所有这些都可以通过简单的命令完成。

过去，Docker Swarm 是一个单独的产品，你可以在 Docker 引擎之上进行层叠。自 Docker 1.12 以来，它已完全集成到 Docker 引擎中，并可以通过单个命令启用。截至 2018 年，它具有部署和管理本地 Swarm 应用程序以及 Kubernetes 应用程序的能力。尽管在撰写本文时，对 Kubernetes 应用程序的支持相对较新。

### Docker Swarm - 深入探讨

我们将把本章的深入探讨部分分为以下几个部分：

+   Swarm 入门

+   构建一个安全的 Swarm 集群

+   部署一些 Swarm 服务

+   故障排除

引用的示例将基于 Linux，但也适用于 Windows。如果有差异，我们一定会指出。

#### Swarm 模式入门

在集群方面，*Swarm*由一个或多个 Docker *节点*组成。这些可以是物理服务器、虚拟机、树莓派或云实例。唯一的要求是所有节点都可以通过可靠的网络进行通信。

节点被配置为*管理节点*或*工作节点*。*管理节点*负责集群的控制平面，意味着集群的状态和向*工作节点*分发任务等。*工作节点*接受*管理节点*的任务并执行它们。

*swarm*的配置和状态存储在所有管理节点上的分布式*etcd*数据库中。它保存在内存中，并且非常及时更新。但最好的是，它不需要任何配置——它作为 swarm 的一部分安装，并且只需要自己照顾自己。

在集群前端具有颠覆性的东西是安全性的方法。TLS 集成得如此紧密，以至于没有它就不可能构建一个集群。在当今注重安全的世界，像这样的东西都应该得到应有的赞赏！总之，*swarm*使用 TLS 加密通信，验证节点，并授权角色。自动密钥轮换也被加入其中，就像是锦上添花一样！而且一切都进行得如此顺利，以至于你甚至都不知道它的存在！

在应用编排方面，swarm 上调度的原子单位是*服务*。这是 API 中的一个新对象，与 swarm 一起引入，并且是一个更高级的构造，围绕容器添加了一些高级功能。

当一个容器被包装成一个服务时，我们称之为*任务*或*副本*，而服务构造添加了诸如扩展、滚动更新和简单回滚等功能。

高级视图如图 10.1 所示。

![图 10.1 高级 swarm](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-dpdv/img/figure10-1.png)

图 10.1 高级 swarm

这就足够作为入门了。让我们用一些示例来动手实践吧。

#### 构建一个安全的 Swarm 集群

在本节中，我们将构建一个安全的 swarm 集群，其中包括三个*管理节点*和三个*工作节点*。你可以使用不同数量的*管理节点*和*工作节点*以及不同的名称和 IP 的不同实验室，但接下来的示例将使用图 10.2 中的值。

![图 10.2](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-dpdv/img/figure10-2.png)

图 10.2

每个节点都需要安装 Docker，并且需要能够与其余的 swarm 进行通信。如果配置了名称解析，也是有益的——这样可以更容易地在命令输出中识别节点，并在故障排除时有所帮助。

在网络方面，你应该在路由器和防火墙上打开以下端口：

+   `2377/tcp:` 用于安全的客户端到 swarm 的通信

+   `7946/tcp 和 7946/udp:` 用于控制平面的八卦

+   `4789/udp:` 用于基于 VXLAN 的覆盖网络

一旦你满足了先决条件，你就可以继续构建一个集群。

构建集群的过程有时被称为 *初始化集群*，高级过程如下：初始化第一个管理器节点 > 加入其他管理器节点 > 加入工作节点 > 完成。

##### 初始化一个全新的集群

不属于集群的 Docker 节点被称为 *单引擎模式*。一旦它们被添加到集群中，它们就会切换到 *集群模式*。

![图 10.3 集群模式 vs 单引擎模式](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-dpdv/img/figure10-3.png)

图 10.3 集群模式 vs 单引擎模式

在 *单引擎模式* 的 Docker 主机上运行 `docker swarm init` 将会将该节点切换到 *集群模式*，创建一个新的 *集群*，并将该节点作为集群的第一个 *管理器*。

然后可以将其他节点作为工作节点和管理器 *加入*。这显然会将它们作为操作的一部分切换到 *集群模式*。

以下步骤将把 **mgr1** 切换到 *集群模式* 并初始化一个新的集群。然后，它将加入 **wrk1**、**wrk2** 和 **wrk3** 作为工作节点 —— 自动将它们切换到 *集群模式*。最后，它将添加 **mgr2** 和 **mgr3** 作为额外的管理器，并将它们切换到 *集群模式*。在该过程结束时，所有 6 个节点都将处于 *集群模式* 并作为同一个集群的一部分运行。

本示例将使用图 10.2 中显示的节点的 IP 地址和 DNS 名称。你的情况可能不同。

1.  登录到 **mgr1** 并初始化一个新的集群（如果你在 Windows 的 PowerShell 终端中跟随操作，请不要忘记使用反引号而不是反斜杠）。

```
$ docker swarm init `\`
  --advertise-addr `10`.0.0.1:2377 `\`
  --listen-addr `10`.0.0.1:2377

Swarm initialized: current node `(`d21lyz...c79qzkx`)` is now a manager. 
```

该命令可以分解如下：

+   `docker swarm init` 告诉 Docker 初始化一个新的集群，并将该节点设为第一个管理器。它还在该节点上启用了集群模式。

+   `--advertise-addr` 是其他节点应该用来连接到此管理器的 IP 和端口。这是一个可选标志，但它可以让你控制在具有多个 IP 的节点上使用哪个 IP。它还可以让你指定一个在节点上不存在的 IP 地址，比如负载均衡器 IP。

+   `--listen-addr` 允许你指定你想要监听的集群流量的 IP 和端口。这通常会匹配 `--advertise-addr`，但在你想要将集群限制在具有多个 IP 的系统上的情况下很有用。在 `--advertise-addr` 指向负载均衡器等远程 IP 地址的情况下也是必需的。

我建议你具体说明并始终使用这两个标志。

集群模式操作的默认端口是**2377**。这是可以自定义的，但惯例是使用`2377/tcp`用于安全（HTTPS）的客户端到集群的连接。

`*列出集群中的节点

```
$ docker node ls
ID            HOSTNAME   STATUS  AVAILABILITY  MANAGER STATUS
d21...qzkx *  mgr1       Ready   Active        Leader 
```

`请注意，**mgr1**目前是集群中唯一的节点，并被列为*Leader*。我们稍后会回到这一点。`*从**mgr1**运行`docker swarm join-token`命令来提取添加新工作节点和管理节点到集群所需的命令和令牌。

```
$ docker swarm join-token worker
To add a manager to this swarm, run the following command:
   docker swarm join `\`
   --token SWMTKN-1-0uahebax...c87tu8dx2c `\`
   `10`.0.0.1:2377

$ docker swarm join-token manager
To add a manager to this swarm, run the following command:
   docker swarm join `\`
   --token SWMTKN-1-0uahebax...ue4hv6ps3p `\`
   `10`.0.0.1:2377 
```

请注意，加入工作节点和管理节点的命令除了加入令牌（`SWMTKN...`）之外是相同的。这意味着节点是作为工作节点还是管理节点加入取决于加入时使用的令牌。**您应该确保您的加入令牌受到保护，因为这是加入节点到集群所需的全部内容！**`*登录**wrk1**并使用`docker swarm join`命令使用工作节点加入令牌加入到集群。

```
$ docker swarm join `\`
    --token SWMTKN-1-0uahebax...c87tu8dx2c `\`
    `10`.0.0.1:2377 `\`
    --advertise-addr `10`.0.0.4:2377 `\`
    --listen-addr `10`.0.0.4:2377

This node joined a swarm as a worker. 
```

`--advertise-addr`和`--listen-addr`标志是可选的。我添加了它们，因为我认为在网络配置方面尽可能具体是最佳实践。`*在**wrk2**和**wrk3**上重复上一步，使它们作为工作节点加入到集群。确保您使用**wrk2**和**wrk3**自己的 IP 地址作为`--advertise-addr`和`--listen-addr`标志。*登录**mgr2**并使用用于加入管理节点的令牌使用`docker swarm join`命令将其加入到集群。

```
$ docker swarm join `\`
    --token SWMTKN-1-0uahebax...ue4hv6ps3p `\`
    `10`.0.0.1:2377 `\`
    --advertise-addr `10`.0.0.2:2377 `\`
    --listen-addr `10`.0.0.1:2377

This node joined a swarm as a manager. 
```

`*在**mgr3**上重复上一步，记得使用**mgr3**的 IP 地址作为`advertise-addr`和`--listen-addr`标志。*通过从集群中的任何管理节点运行`docker node ls`来列出集群中的节点。

```
$ docker node ls
ID               HOSTNAME     STATUS  AVAILABILITY  MANAGER STATUS
0g4rl...babl8 *  mgr2         Ready   Active        Reachable
2xlti...l0nyp    mgr3         Ready   Active        Reachable
8yv0b...wmr67    wrk1         Ready   Active
9mzwf...e4m4n    wrk3         Ready   Active
d21ly...9qzkx    mgr1         Ready   Active        Leader
e62gf...l5wt6    wrk2         Ready   Active 
```````` 

 ```Congratulations! You’ve just created a 6-node swarm with 3 managers and 3 workers. As part of the process you put the Docker Engine on each node into *swarm mode*. As a bonus, the *swarm* is automatically secured with TLS.

If you look in the `MANAGER STATUS` column you’ll see that the three manager nodes are showing as either “Reachable” or “Leader”. We’ll learn more about leaders shortly. Nodes with nothing in the `MANAGER STATUS` column are *workers*. Also note the asterisk (`*`) after the ID on the line showing **mgr2**. This shows us which node we ran the `docker node ls` command from. In this instance the command was issued from **mgr2**.

> **Note:** It’s a pain to specify the `--advertise-addr` and `--listen-addr` flags every time you join a node to the swarm. However, it can be a much bigger pain if you get the network configuration of your swarm wrong. Also, manually adding nodes to a swarm is unlikely to be a daily task, so I think it’s worth the extra up-front effort to use the flags. It’s your choice though. In lab environments or nodes with only a single IP you probably don’t need to use them.

Now that we have a *swarm* up and running, let’s take a look at manager high availability (HA).

#### Swarm manager high availability (HA)

So far, we’ve added three manager nodes to a swarm. Why did we add three, and how do they work together? We’ll answer all of this, plus more in this section.

Swarm *managers* have native support for high availability (HA). This means one or more can fail, and the survivors will keep the swarm running.

Technically speaking, swarm implements a form of active-passive multi-manager HA. This means that although you might — and should — have multiple *managers*, only one of them is ever considered *active*. We call this active manager the “*leader*”, and the leader’s the only one that will ever issue live commands against the *swarm*. So it’s only ever the leader that changes the config, or issues tasks to workers. If a passive (non-active) manager receives commands for the swarm, it proxies them across to the leader.

This process is shown in Figure 10.4\. Step `1` is the command coming in to a *manager* from a remote Docker client. Step 2 is the non-leader manager proxying the command to the leader. Step 3 is the leader executing the command on the swarm.

![Figure 10.4](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-dpdv/img/figure10-4.png)

Figure 10.4

If you look closely at Figure 10.4 you’ll notice that managers are either *leaders* or *followers*. This is Raft terminology, because swarm uses an implementation of the [Raft consensus algorithm](https://raft.github.io/) to power manager HA. And on the topic of HA, the following two best practices apply:

1.  Deploy an odd number of managers.
2.  Don’t deploy too many managers (3 or 5 is recommended)

Having an odd number of *managers* reduces the chances of split-brain conditions. For example, if you had 4 managers and the network partitioned, you could be left with two managers on each side of the partition. This is known as a split brain — each side knows there used to be 4 but can now only see 2\. But crucially, neither side has any way of knowing if the other two are still alive and whether it holds a majority (quorum). The cluster continues to operate during split-brain conditions, but you are no longer able to alter the configuration or add and manage application workloads.

However, if you had 3 or 5 managers and the same network partition occurred, it would be impossible to have the same number of managers on both sides of the partition. This means that one side achieve quorum and cluster management would remain available. The example on the right side of Figure 10.5 shows a partitioned cluster where the left side of the split knows it has a majority of managers.

![Figure 10.5](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-dpdv/img/figure10-5.png)

Figure 10.5

As with all consensus algorithms, more participants means more time required to achieve consensus. It’s like deciding where to eat — it’s always quicker and easier to decide with 3 people than it is with 33! With this in mind, it’s a best practice to have either 3 or 5 managers for HA. 7 might work, but it’s generally accepted that 3 or 5 is optimal. You definitely don’t want more than 7, as the time taken to achieve consensus will be longer.

A final word of caution regarding manager HA. While it’s obviously a good practice to spread your managers across availability zones within your network, you need to make sure that the networks connecting them are reliable! Network partitions can be a royal pain in the backside! This means, at the time of writing, the nirvana of hosting your active production applications and infrastructure across multiple cloud providers such as AWS and Azure is a bit of a daydream. Take time to make sure your managers are connected via reliable high-speed networks!

##### Built-in Swarm security

Swarm clusters have a ton of built-in security that’s configured out-of-the-box with sensible defaults — CA settings, join tokens, mutual TLS, encrypted cluster store, encrypted networks, cryptographic node ID’s and more. See **Chapter 15: Security in Docker** for a detailed look at these.

##### Locking a Swarm

Despite all of this built-in native security, restarting an older manager or restoring an old backup has the potential to compromise the cluster. Old managers re-joining a swarm automatically decrypt and gain access to the Raft log time-series database — this can pose security concerns. Restoring old backups can wipe the current swarm configuration.

To prevent situations like these, Docker allows you to lock a swarm with the Autolock feature. This forces managers that have been restarted to present the cluster unlock key before being permitted back into the cluster.

It’s possible to apply a lock directly to a new swarm you are creating by passing the `--autolock` flag to the `docker swarm init` command. However, we’ve already built a swarm, so we’ll lock our existing swarm with the `docker swarm update` command.

Run the following command from a swarm manager.

```
$ docker swarm update --autolock`=``true`
Swarm updated.
To unlock a swarm manager after it restarts, run the ```docker swarm
unlock````command` and provide the following key:

    SWMKEY-1-5+ICW2kRxPxZrVyBDWzBkzZdSd0Yc7Cl2o4Uuf9NPU4

Please remember to store this key in a password manager, since without
it you will not be able to restart the manager. 
```

 `Be sure to keep the unlock key in a secure place!

Restart one of your manager nodes to see if it automatically re-joins the cluster. You may need to prepend the command with `sudo`.

```
$ service docker restart 
```

 `Try and list the nodes in the swarm.

```
$ docker node ls
Error response from daemon: Swarm is encrypted and needs to be unlocked befo`\`
re
it can be used. 
```

 `Although the Docker service has restarted on the manager, it has not been allowed to re-join the cluster. You can prove this even further by running the `docker node ls` command on another manager node. The restarted manager will show as `down` and `unreachable`.

Use the `docker swarm unlock` command to unlock the swarm for the restarted manager. You’ll need to run this command on the restarted manager, and you’ll need to provide the unlock key.

```
$ docker swarm unlock
Please enter unlock key: <enter your key> 
```

 `The node will be allowed to re-join the swarm, and will show as `ready` and `reachable` if you run another `docker node ls`.

Locking your swarm and protecting the unlock key is recommended for production environments.

Now that we’ve got our *swarm* built, and we understand the concepts of *leaders* and *manager HA*, let’s move on to *services*.

#### Swarm services

Everything we do in this section of the chapter gets improved on by Docker Stacks (Chapter 14). However, it’s important that you learn the concepts here so that you’re prepared for Chapter 14.

Like we said in the *swarm primer*… *services* are a new construct introduced with Docker 1.12, and they only exist in *swarm mode*.

They let us specify most of the familiar container options, such as *name, port mappings, attaching to networks,* and *images*. But they add things, like letting us declare the *desired state* for an application service, feed that to Docker, and let Docker take care of deploying it and managing it. For example, assume you’ve got an app with a web front-end. You have an image for it, and testing has shown that you’ll need 5 instances to handle normal daily traffic. You would translate this requirement into a single *service* declaring the image the containers should use, and that the service should always have 5 running replicas.

We’ll see some of the other things that can be declared as part of a service in a minute, but before we do that, let’s see how to create what we just described.

You create a new service with the `docker service create` command.

> **Note:** The command to create a new service is the same on Windows. However, the image used in this example is a Linux image and will not work on Windows. You can substitute the image for a Windows web server image and the command will work. Remember, if you are typing Windows commands from a PowerShell terminal you will need to use the backtick (`) to indicate continuation on the next line.

```
$ docker service create --name web-fe `\`
   -p `8080`:8080 `\`
   --replicas `5` `\`
   nigelpoulton/pluralsight-docker-ci

z7ovearqmruwk0u2vc5o7ql0p 
```

 `Notice that many of the familiar `docker container run` arguments are the same. In the example, we specified `--name` and `-p` which work the same for standalone containers as well as services.

Let’s review the command and output.

We used `docker service create` to tell Docker we are declaring a new service, and we used the `--name` flag to name it **web-fe**. We told Docker to map port 8080 on every node in the swarm to 8080 inside of each service replica. Next, we used the `--replicas` flag to tell Docker that there should always be 5 replicas of this service. Finally, we told Docker which image to use for the replicas — it’s important to understand that all service replicas use the same image and config!

After we hit `Return`, the manager acting as leader instantiated 5 replicas across the *swarm* — remember that swarm managers also act as workers. Each worker or manager then pulled the image and started a container from it running on port 8080\. The swarm leader also ensured a copy of the service’s desired state was stored on the cluster and replicated to every manager in the swarm.

But this isn’t the end. All *services* are constantly monitored by the swarm — the swarm runs a background *reconciliation loop* that constantly compares the *actual state* of the service to the *desired state*. If the two states match, the world is a happy place and no further action is needed. If they don’t match, swarm takes actions so that they do. Put another way, the swarm is constantly making sure that *actual state* matches *desired state*.

As an example, if a *worker* hosting one of the 5 **web-fe** replicas fails, the *actual state* for the **web-fe** service will drop from 5 replicas to 4\. This will no longer match the *desired state* of 5, so Docker will start a new **web-fe** replica to bring *actual state* back in line with *desired state*. This behavior is very powerful and allows the service to self-heal in the event of node failures and the likes.

#### Viewing and inspecting services

You can use the `docker service ls` command to see a list of all services running on a swarm.

```
$ docker service ls
ID        NAME     MODE        REPLICAS   IMAGE               PORTS
z7o...uw  web-fe   replicated  `5`/5        nigel...ci:latest   *:8080->8080/t`\`
cp 
```

 `The output above shows a single running service as well as some basic information about state. Among other things, we can see the name of the service and that 5 out of the 5 desired replicas are in the running state. If you run this command soon after deploying the service it might not show all tasks/replicas as running. This is often due to the time it takes to pull the image on each node.

You can use the `docker service ps` command to see a list of service replicas and the state of each.

```
$ docker service ps web-fe
ID         NAME      IMAGE             NODE  DESIRED  CURRENT
`817`...f6z  web-fe.1  nigelpoulton/...  mgr2  Running  Running `2` mins
a1d...mzn  web-fe.2  nigelpoulton/...  wrk1  Running  Running `2` mins
cc0...ar0  web-fe.3  nigelpoulton/...  wrk2  Running  Running `2` mins
6f0...azu  web-fe.4  nigelpoulton/...  mgr3  Running  Running `2` mins
dyl...p3e  web-fe.5  nigelpoulton/...  mgr1  Running  Running `2` mins 
```

 `The format of the command is `docker service ps <service-name or service-id>`. The output displays each replica (container) on its own line, shows which node in the swarm it’s executing on, and shows desired state and actual state.

For detailed information about a service, use the `docker service inspect` command.

```
$ docker service inspect --pretty web-fe
ID:             z7ovearqmruwk0u2vc5o7ql0p
Name:           web-fe
Service Mode:   Replicated
 Replicas:      `5`
Placement:
UpdateConfig:
 Parallelism:   `1`
 On failure:    pause
 Monitoring Period: 5s
 Max failure ratio: `0`
 Update order:      stop-first
RollbackConfig:
 Parallelism:   `1`
 On failure:    pause
 Monitoring Period: 5s
 Max failure ratio: `0`
 Rollback order:    stop-first
ContainerSpec:
 Image:   nigelpoulton/pluralsight-docker-ci:latest@sha256:7a6b01...d8d3d
Resources:
Endpoint Mode:  vip
Ports:
 `PublishedPort` `=` `8080`
  `Protocol` `=` tcp
  `TargetPort` `=` `8080`
  `PublishMode` `=` ingress 
```

 `The example above uses the `--pretty` flag to limit the output to the most interesting items printed in an easy-to-read format. Leaving off the `--pretty` flag will give a more verbose output. I highly recommend you read through the output of `docker inspect` commands as they’re a great source of information and a great way to learn what’s going on under the hood.

We’ll come back to some of these outputs later.

#### Replicated vs global services

The default replication mode of a service is `replicated`. This will deploy a desired number of replicas and distribute them as evenly as possible across the cluster.

The other mode is `global`, which runs a single replica on every node in the swarm.

To deploy a *global service* you need to pass the `--mode global` flag to the `docker service create` command.

#### Scaling a service

Another powerful feature of *services* is the ability to easily scale them up and down.

Let’s assume business is booming and we’re seeing double the amount of traffic hitting the web front-end. Fortunately, scaling the **web-fe** service is as simple as running the `docker service scale` command.

```
$ docker service scale web-fe`=``10`
web-fe scaled to `10` 
```

 `This command will scale the number of service replicas from 5 to 10\. In the background it’s updating the service’s *desired state* from 5 to 10\. Run another `docker service ls` command to verify the operation was successful.

```
$ docker service ls
ID        NAME     MODE        REPLICAS   IMAGE               PORTS
z7o...uw  web-fe   replicated  `10`/10      nigel...ci:latest   *:8080->8080/t`\`
cp 
```

 `Running a `docker service ps` command will show that the service replicas are balanced across all nodes in the swarm evenly.

```
$ docker service ps web-fe
ID         NAME      IMAGE             NODE  DESIRED  CURRENT
nwf...tpn  web-fe.1  nigelpoulton/...  mgr1  Running  Running `7` mins
yb0...e3e  web-fe.2  nigelpoulton/...  wrk3  Running  Running `7` mins
mos...gf6  web-fe.3  nigelpoulton/...  wrk2  Running  Running `7` mins
utn...6ak  web-fe.4  nigelpoulton/...  wrk3  Running  Running `7` mins
2ge...fyy  web-fe.5  nigelpoulton/...  mgr3  Running  Running `7` mins
64y...m49  web-fe.6  igelpoulton/...   wrk3  Running  Running about a min
ild...51s  web-fe.7  nigelpoulton/...  mgr1  Running  Running about a min
vah...rjf  web-fe.8  nigelpoulton/...  wrk2  Running  Running about a mins
xe7...fvu  web-fe.9  nigelpoulton/...  mgr2  Running  Running `45` seconds ago
l7k...jkv  web-fe.10 nigelpoulton/...  mgr2  Running  Running `46` seconds ago 
```

 `Behind the scenes, swarm runs a scheduling algorithm that defaults to balancing replicas as evenly as possible across the nodes in the swarm. At the time of writing, this amounts to running an equal number of replicas on each node without taking into consideration things like CPU load etc.

Run another `docker service scale` command to bring the number back down from 10 to 5.

```
$ docker service scale web-fe`=``5`
web-fe scaled to `5` 
```

 `Now that we know how to scale a service, let’s see how we remove one.

#### Removing a service

Removing a service is simple — may be too simple.

The following `docker service rm` command will delete the service deployed earlier.

```
$ docker service rm web-fe
web-fe 
```

 `Confirm it’s gone with the `docker service ls` command.

```
$ docker service ls
ID      NAME    MODE   REPLICAS    IMAGE      PORTS 
```

 `Be careful using the `docker service rm` command, as it deletes all service replicas without asking for confirmation.

Now that the service is deleted from the system, let’s look at how to push rolling updates to one.

#### Rolling updates

Pushing updates to deployed applications is a fact of life. And for the longest time it’s been really painful. I’ve lost more than enough weekends to major application updates, and I’ve no intention of doing it again.

Well… thanks to Docker *services*, pushing updates to well-designed apps just got a lot easier!

To see this, we’re going to deploy a new service. But before we do that we’re going to create a new overlay network for the service. This isn’t necessary, but I want you to see how it is done and how to attach the service to it.

```
$ docker network create -d overlay uber-net
43wfp6pzea470et4d57udn9ws 
```

 `This creates a new overlay network called “uber-net” that we’ll be able to leverage with the service we’re about to create. An overlay network creates a new layer 2 network that we can place containers on, and all containers on it will be able to communicate. This works even if the Docker hosts the containers are running on are on different underlying networks. Basically, the overlay network creates a new layer 2 container network on top of potentially multiple different underlying networks.

Figure 10.6 shows two underlay networks connected by a layer 3 router. There is then a single overlay network across both. Docker hosts are connected to the two underlay networks and containers are connected to the overlay. All containers on the overlay can communicate even if they are on Docker hosts plumbed into different underlay networks.

![Figure 10.6](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-dpdv/img/figure10-6.png)

Figure 10.6

Run a `docker network ls` to verify that the network created properly and is visible on the Docker host.

```
$ docker network ls
NETWORK ID          NAME                DRIVER      SCOPE
<Snip>
43wfp6pzea47        uber-net            overlay     swarm 
```

 `The `uber-net` network was successfully created with the `swarm` scope and is *currently* only visible on manager nodes in the swarm.

Let’s create a new service and attach it to the network.

```
$ docker service create --name uber-svc `\`
   --network uber-net `\`
   -p `80`:80 --replicas `12` `\`
   nigelpoulton/tu-demo:v1

dhbtgvqrg2q4sg07ttfuhg8nz 
```

 `Let’s see what we just declared with that `docker service create` command.

The first thing we did was name the service and then use the `--network` flag to tell it to place all replicas on the new `uber-net` network. We then exposed port 80 across the entire swarm and mapped it to port 80 inside of each of the 12 replicas we asked it to run. Finally, we told it to base all replicas on the nigelpoulton/tu-demo:v1 image.

Run a `docker service ls` and a `docker service ps` command to verify the state of the new service.

```
$ docker service ls
ID            NAME      REPLICAS  IMAGE
dhbtgvqrg2q4  uber-svc  `12`/12     nigelpoulton/tu-demo:v1

$ docker service ps uber-svc
ID        NAME          IMAGE                NODE  DESIRED   CURRENT STATE
0v...7e5  uber-svc.1    nigelpoulton/...:v1  wrk3  Running   Running `1` min
bh...wa0  uber-svc.2    nigelpoulton/...:v1  wrk2  Running   Running `1` min
`23`...u97  uber-svc.3    nigelpoulton/...:v1  wrk2  Running   Running `1` min
`82`...5y1  uber-svc.4    nigelpoulton/...:v1  mgr2  Running   Running `1` min
c3...gny  uber-svc.5    nigelpoulton/...:v1  wrk3  Running   Running `1` min
e6...3u0  uber-svc.6    nigelpoulton/...:v1  wrk1  Running   Running `1` min
`78`...r7z  uber-svc.7    nigelpoulton/...:v1  wrk1  Running   Running `1` min
2m...kdz  uber-svc.8    nigelpoulton/...:v1  mgr3  Running   Running `1` min
b9...k7w  uber-svc.9    nigelpoulton/...:v1  mgr3  Running   Running `1` min
ag...v16  uber-svc.10   nigelpoulton/...:v1  mgr2  Running   Running `1` min
e6...dfk  uber-svc.11   nigelpoulton/...:v1  mgr1  Running   Running `1` min
e2...k1j  uber-svc.12   nigelpoulton/...:v1  mgr1  Running   Running `1` min 
```

 `Passing the service the `-p 80:80` flag will ensure that a **swarm-wide** mapping is created that maps all traffic, coming in to any node in the swarm on port 80, through to port 80 inside of any service replica.

This mode of publishing a port on every node in the swarm — even nodes not running service replicas — is called *ingress mode* and is the default. The alternative mode is *host mode* which only publishes the service on swarm nodes running replicas. Publishing a service in *host mode* requires the long-form syntax and looks like the following:

```
docker service create --name uber-svc \
   --network uber-net \
   --publish published=80,target=80,mode=host \
   --replicas 12 \
   nigelpoulton/tu-demo:v1 
```

 `Open a web browser and point it to the IP address of any of the nodes in the swarm on port 80 to see the service running.

![Figure 10.7](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-dpdv/img/figure10-7.png)

Figure 10.7

As you can see, it’s a simple voting application that will register votes for either “football” or “soccer”. Feel free to point your web browser to other nodes in the swarm. You’ll be able to reach the web service from any node because the `-p 80:80` flag creates an *ingress mode* mapping on every swarm node. This is true even on nodes that are not running a replica for the service — **every node gets a mapping and can therefore redirect your request to a node that runs the service**.

Now let’s assume that this particular vote has come to an end and your company is wants to run a new poll. A new image has been created for the new poll and has been added to the same Docker Hub repository, but this one is tagged as `v2` instead of `v1`.

Let’s also assume that you’ve been tasked with pushing the updated image to the swarm in a staged manner — 2 replicas at a time with a 20 second delay between each. We can use the following `docker service update` command to accomplish this.

```
$ docker service update `\`
   --image nigelpoulton/tu-demo:v2 `\`
   --update-parallelism `2` `\`
   --update-delay 20s uber-svc 
```

 `Let’s review the command. `docker service update` lets us make updates to running services by updating the service’s desired state. This time we gave it a new image tag `v2` instead of `v1`. And we used the `--update-parallelism` and the `--update-delay` flags to make sure that the new image was pushed to 2 replicas at a time with a 20 second cool-off period in between each. Finally, we told Docker to make these changes to the `uber-svc` service.

If we run a `docker service ps` against the service we’ll see that some of the replicas are at `v2` while some are still at `v1`. If we give the operation enough time to complete (4 minutes) all replicas will eventually reach the new desired state of using the `v2` image.

```
$ docker service ps uber-svc
ID        NAME              IMAGE        NODE   DESIRED   CURRENT STATE
7z...nys  uber-svc.1    nigel...v2   mgr2  Running   Running `13` secs
0v...7e5  `\_`uber-svc.1  nigel...v1   wrk3  Shutdown  Shutdown `13` secs
bh...wa0  uber-svc.2    nigel...v1   wrk2  Running   Running `1` min
e3...gr2  uber-svc.3    nigel...v2   wrk2  Running   Running `13` secs
`23`...u97  `\_`uber-svc.3  nigel...v1   wrk2  Shutdown  Shutdown `13` secs
`82`...5y1  uber-svc.4    nigel...v1   mgr2  Running   Running `1` min
c3...gny  uber-svc.5    nigel...v1   wrk3  Running   Running `1` min
e6...3u0  uber-svc.6    nigel...v1   wrk1  Running   Running `1` min
`78`...r7z  uber-svc.7    nigel...v1   wrk1  Running   Running `1` min
2m...kdz  uber-svc.8    nigel...v1   mgr3  Running   Running `1` min
b9...k7w  uber-svc.9    nigel...v1   mgr3  Running   Running `1` min
ag...v16  uber-svc.10   nigel...v1   mgr2  Running   Running `1` min
e6...dfk  uber-svc.11   nigel...v1   mgr1  Running   Running `1` min
e2...k1j  uber-svc.12   nigel...v1   mgr1  Running   Running `1` min 
```

 `You can witness the update happening in real-time by opening a web browser to any node in the swarm and hitting refresh several times. Some of the requests will be serviced by replicas running the old version and some will be serviced by replicas running the new version. After enough time, all requests will be serviced by replicas running the updated version of the service.

Congratulations. You’ve just pushed a rolling update to a live containerized application. Remember, Docker Stacks take all of this to the next level in Chapter 14.

If you run a `docker inspect --pretty` command against the service, you’ll see the update parallelism and update delay settings are now part of the service definition. This means future updates will automatically use these settings unless you override them as part of the `docker service update` command.

```
$ docker service inspect --pretty uber-svc
ID:             mub0dgtc8szm80ez5bs8wlt19
Name:           uber-svc
Service Mode:   Replicated
 Replicas:      `12`
UpdateStatus:
 State:         updating
 Started:       About a minute
 Message:       update in progress
Placement:
UpdateConfig:
 Parallelism:   `2`
 Delay:         20s
 On failure:    pause
 Monitoring Period: 5s
 Max failure ratio: `0`
 Update order:      stop-first
RollbackConfig:
 Parallelism:   `1`
 On failure:    pause
 Monitoring Period: 5s
 Max failure ratio: `0`
 Rollback order:    stop-first
ContainerSpec:
 Image:    nigelpoulton/tu-demo:v2@sha256:d3c0d8c9...cf0ef2ba5eb74c
Resources:
Networks: uber-net
Endpoint Mode:  vip
Ports:
 `PublishedPort` `=` `80`
  `Protocol` `=` tcp
  `TargetPort` `=` `80`
  `PublishMode` `=` ingress 
```

 `You should also note a couple of things about the service’s network config. All nodes in the swarm that are running a replica for the service will have the `uber-net` overlay network that we created earlier. We can verify this by running `docker network ls` on any node running a replica.

You should also note the `Networks` portion of the `docker inspect` output. This shows the `uber-net` network as well as the swarm-wide `80:80` port mapping.

#### Troubleshooting

Swarm Service logs can be viewed with the `docker service logs` command. However, not all logging drivers support the command.

By default, Docker nodes configure services to use the `json-file` log driver, but other drivers exist, including:

*   `journald` (only works on Linux hosts running `systemd`)
*   `syslog`
*   `splunk`
*   `gelf`

`json-file` and `journald` are the easiest to configure, and both work with the `docker service logs` command. The format of the command is `docker service logs <service-name>`.

If you’re using 3rd-party logging drivers you should view those logs using the logging platform’s native tools.

The following snippet from a `daemon.json` configuration file shows a Docker host configured to use `syslog`.

```
{
  "log-driver": "syslog"
} 
```

 `You can force individual services to use a different driver by passing the `--log-driver` and `--log-opts` flags to the `docker service create` command. These will override anything set in `daemon.json`.

Service logs work on the premise that your application is running as PID 1 in its container and sending logs to `STDOUT`, and errors to `STDERR`. The logging driver forwards these “logs” to the locations configured via the logging driver.

The following `docker service logs` command shows the logs for all replicas in the `svc1` service that experienced a couple of failures starting a replica.

```
$ docker service logs seastack_reverse_proxy
svc1.1.zhc3cjeti9d4@wrk-2 `|` `[`emerg`]` `1``#1: host not found...`
svc1.1.6m1nmbzmwh2d@wrk-2 `|` `[`emerg`]` `1``#1: host not found...`
svc1.1.6m1nmbzmwh2d@wrk-2 `|` nginx: `[`emerg`]` host not found..
svc1.1.zhc3cjeti9d4@wrk-2 `|` nginx: `[`emerg`]` host not found..
svc1.1.1tmya243m5um@mgr-1 `|` `10`.255.0.2 `"GET / HTTP/1.1"` `302` 
```

 `The output is trimmed to fit the page, but you can see that logs from all three service replicas are shown (the two that failed and the one that’s running). Each line starts with the name of the replica, which includes the service name, replica number, replica ID, and name of host that it’s scheduled on. Following that is the log output.

It’s hard to tell because it’s trimmed to fit the book, but it looks like the first two replicas failed because they were trying to connect to another service that was still starting (a sort of race condition when dependent services are starting).

You can follow the logs (`--follow`), tail them (`--tail`), and get extra details (`--details`).

### Docker Swarm - The Commands

*   `docker swarm init` is the command to create a new swarm. The node that you run the command on becomes the first manager and is switched to run in *swarm mode*.
*   `docker swarm join-token` reveals the commands and tokens needed to join workers and managers to existing swarms. To expose the command to join a new manager, use the `docker swarm join-token manager` command. To get the command to join a worker, use the `docker swarm join-token worker` command.
*   `docker node ls` lists all nodes in the swarm including which are managers and which is the leader.
*   `docker service create` is the command to create a new service.
*   `docker service ls` lists running services in the swarm and gives basic info on the state of the service and any replicas it’s running.
*   `docker service ps <service>` gives more detailed information about individual service replicas.
*   `docker service inspect` gives very detailed information on a service. It accepts the `--pretty` flag to limit the information returned to the most important information.
*   `docker service scale` lets you scale the number of replicas in a service up and down.
*   `docker service update` lets you update many of the properties of a running service.
*   `docker service logs` lets you view the logs of a service.
*   `docker service rm` is the command to delete a service from the swarm. Use it with caution as it deletes all service replicas without asking for confirmation.

### Chapter summary

Docker swarm is key to the operation of Docker at scale.

At its core, swarm has a secure clustering component, and an orchestration component.

The secure clustering component is enterprise-grade and offers a wealth of security and HA features that are automatically configured and extremely simple to modify.

The orchestration component allows you to deploy and manage microservices applications in a simple declarative manner. Native Docker Swarm apps are supported, and so are Kubernetes apps.

We’ll dig deeper into deploying microservices apps in a declarative manner in Chapter 14.```````````````````````````
