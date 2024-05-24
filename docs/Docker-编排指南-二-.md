# Docker 编排指南（二）

> 原文：[`zh.annas-archive.org/md5/1B8FD79C063269548A48D0E2E43C2BF6`](https://zh.annas-archive.org/md5/1B8FD79C063269548A48D0E2E43C2BF6)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第三章：配置 Docker 容器

在上一章中，我们看到了 Docker 中所有可用的不同命令。我们看了一些示例，涵盖了如何拉取镜像、运行容器、将镜像附加到容器、提交并将镜像推送到存储库的过程。我们还学习了如何编写 Dockerfile，使构建镜像成为一个可重复的过程。

在本章中，我们将更仔细地了解如何控制容器的运行方式。尽管 Docker 容器被隔离，但这并不能阻止其中一个容器中的流浪进程占用其他容器（包括主机）可用的资源。例如，要小心这个命令（不要运行它）：

```
$ docker run ubuntu /bin/bash -c ":(){ :|:& };:"

```

通过运行前面的命令，您将 fork bomb 容器以及运行它的主机。

*fork bomb*的维基百科定义如下：

> *"在计算机中，fork bomb 是一种拒绝服务攻击，其中一个进程不断复制自身以耗尽可用的系统资源，导致资源匮乏并减慢或崩溃系统。"*

由于预计 Docker 将用于生产，一个容器使所有其他容器停滞的可能性将是致命的。因此，有机制来限制容器可以拥有的资源量，我们将在本章中进行讨论。

在上一章中，当我们谈论`docker` run 时，我们对卷进行了基本介绍。现在我们将更详细地探讨卷，并讨论它们为什么重要以及如何最好地使用它们。我们还将尝试更改`docker`守护程序使用的存储驱动程序。

另一个方面是网络。在检查运行中的容器时，您可能已经注意到 Docker 会随机选择一个子网并分配一个 IP 地址（默认通常是范围 172.17.42.0/16）。我们将尝试通过设置自己的子网来覆盖这一点，并探索其他可用的帮助管理网络方面的选项。在许多情况下，我们需要在容器之间进行通信（想象一个容器运行您的应用程序，另一个容器运行您的数据库）。由于 IP 地址在构建时不可用，我们需要一种机制来动态发现在其他容器中运行的服务。我们将探讨实现这一点的方法，无论容器是在同一主机上运行还是在不同主机上运行。

简而言之，在本章中，我们将涵盖以下主题：

+   限制资源

+   CPU

+   RAM

+   存储

+   使用卷在容器中管理数据

+   配置 Docker 使用不同的存储驱动程序

+   配置网络

+   端口转发

+   自定义 IP 地址范围

+   链接容器

+   使用容器链接在同一主机内进行链接

+   使用大使容器进行跨主机链接

# 约束资源

对于任何承诺提供沙箱功能的工具来说，提供一种约束资源分配的机制是至关重要的。Docker 在容器启动时提供了限制 CPU 内存和 RAM 使用量的机制。

## 设置 CPU 份额

可以使用`docker run`命令中的`-c`选项来控制容器所占用的 CPU 份额：

```
$ docker run -c 10 -it ubuntu /bin/bash

```

值`10`是相对于其他容器给予该容器的优先级。默认情况下，所有容器都具有相同的优先级，因此具有相同的 CPU 处理周期比率，您可以通过运行`$ cat /sys/fs/cgroup/cpu/docker/cpu.shares`来检查（如果您使用的是 OS X 或 Windows，请在执行此操作之前将 SSH 添加到 boot2Docker VM）。但是，您可以在运行容器时提供自己的优先级值。

在容器已经运行时设置 CPU 份额是否可能？是的。编辑`/sys/fs/cgroup/cpu/docker/<container-id>/cpu.shares`文件，并输入您想要给它的优先级。

### 注意

如果提到的位置不存在，请通过运行命令`$ grep -w cgroup /proc/mounts | grep -w cpu`找出`cpu` `cgroup`挂载的位置。

然而，这是一个 hack，如果 Docker 决定改变 CPU 共享的实现方式，将来可能会发生变化。有关更多信息，请访问[`groups.google.com/forum/#!topic/docker-user/-pP8-KgJJGg`](https://groups.google.com/forum/#!topic/docker-user/-pP8-KgJJGg)。

## 设置内存限制

类似地，容器被允许消耗的 RAM 量在启动容器时也可以受到限制：

```
$ docker run -m <value><optional unit>

```

在这里，`unit`可以是`b`、`k`、`m`或`g`，分别表示字节、千字节、兆字节和千兆字节。

单位的示例可以表示如下：

```
$ docker run -m 1024m -dit ubuntu /bin/bash

```

这为容器设置了 1GB 的内存限制。

与限制 CPU 份额一样，您可以通过运行以下代码来检查默认的内存限制：

```
$ cat /sys/fs/cgroup/memory/docker/memory.limit_in_bytes
18446744073709551615

```

正如文件名所示，前面的代码以字节为单位打印限制。输出中显示的值对应于 1.8 x 1010 千字节，这实际上意味着没有限制。

在容器已经运行时设置内存限制是否可能？

与 CPU 份额一样，内存限制是通过`cgroup`文件强制执行的，这意味着我们可以通过更改容器的`cgroup`内存文件的值来动态更改限制：

```
$ echo 1073741824 > \ /sys/fs/cgroup/memory/docker/<container_id>/memory.limit_in_bytes

```

### 注意

如果`cgroup`文件的位置不存在，请通过运行`$ grep -w cgroup /proc/mounts | grep -w memory`找出文件的挂载位置。

这也是一个黑客，如果 Docker 决定改变内部实现内存限制的方式，可能会在将来发生变化。

有关此更多信息，请访问[`groups.google.com/forum/#!topic/docker-user/-pP8-KgJJGg`](https://groups.google.com/forum/#!topic/docker-user/-pP8-KgJJGg)。

## 在虚拟文件系统（Devicemapper）上设置存储限制

限制磁盘使用可能有点棘手。没有直接的方法来限制容器可以使用的磁盘空间的数量。默认存储驱动程序 AUFS 不支持磁盘配额，至少没有没有黑客（困难是因为 AUFS 没有自己的块设备。访问[`aufs.sourceforge.net/aufs.html`](http://aufs.sourceforge.net/aufs.html)以获取有关 AUFS 工作原理的深入信息）。在撰写本书时，需要磁盘配额的 Docker 用户选择`devicemapper`驱动程序，该驱动程序允许每个容器使用一定量的磁盘空间。但是，正在进行跨存储驱动程序的更通用机制，并且可能会在将来的版本中引入。

### 注意

`devicemapper`驱动程序是用于将块设备映射到更高级虚拟块设备的 Linux 内核框架。

`devicemapper`驱动程序基于两个块设备（将它们视为虚拟磁盘），一个用于数据，另一个用于元数据，创建一个存储块的`thin`池。默认情况下，这些块设备是通过将稀疏文件挂载为回环设备来创建的。

### 注意

**稀疏文件**是一个文件，其中大部分是空白空间。因此，100 GB 的稀疏文件实际上可能只包含一点字节在开头和结尾（并且只占据磁盘上的这些字节），但对应用程序来说，它可能是一个 100 GB 的文件。在读取稀疏文件时，文件系统会在运行时将空块透明地转换为实际填充了零字节的实际块。它通过文件的元数据跟踪已写入和空块的位置。在类 UNIX 操作系统中，回环设备是一个伪设备，它使文件作为块设备可访问。

“薄”池之所以被称为“薄”，是因为只有在实际写入块时，它才将存储块标记为已使用（来自池）。每个容器都被配置了一个特定大小的基础薄设备，容器不允许累积超过该大小限制的数据。

默认限制是什么？“薄”池的默认限制为 100 GB。但由于用于此池的回环设备是稀疏文件，因此最初不会占用这么多空间。

为每个容器和镜像创建的基础设备的默认大小限制为 10 GB。同样，由于这是稀疏的，因此最初不会占用物理磁盘上的这么多空间。但是，随着大小限制的增加，它占用的空间也会增加，因为块设备的大小越大，稀疏文件的（虚拟）大小就越大，需要存储的元数据也越多。

如何更改这些默认值？您可以在运行`docker`守护程序时使用`--storage-opts`选项更改这些选项，该选项带有`dm`（用于`devicemapper`）前缀。

### 注意

在运行本节中的任何命令之前，请使用`docker save`备份所有镜像并停止`docker`守护程序。完全删除`/var/lib/docker`（Docker 存储图像数据的路径）可能也是明智的。

### Devicemapper 配置

可用的各种配置如下：

+   `dm.basesize`：这指定了基础设备的大小，容器和镜像将使用它。默认情况下，这被设置为 10 GB。创建的设备是稀疏的，因此最初不会占用 10 GB。相反，它将随着数据写入而填满，直到达到 10 GB 的限制。

```
$ docker -d -s devicemapper --storage-opt dm.basesize=50G

```

+   `dm.loopdatasize`：这是“薄”池的大小。默认大小为 100 GB。需要注意的是，这个文件是稀疏的，因此最初不会占用这个空间；相反，随着越来越多的数据被写入，它将逐渐填满：

```
$ docker -d -s devicemapper --storage-opt dm.loopdatasize=1024G

```

+   `dm.loopmetadatasize`：如前所述，创建了两个块设备，一个用于数据，另一个用于元数据。此选项指定创建此块设备时要使用的大小限制。默认大小为 2 GB。这个文件也是稀疏的，因此最初不会占用整个大小。建议的最小大小是总池大小的 1％：

```
$ docker -d -s devicemapper --storage-opt dm.loopmetadatasize=10G

```

+   `dm.fs`：这是用于基础设备的文件系统类型。支持`ext4`和`xfs`文件系统，尽管默认情况下采用`ext4`：

```
$ docker -d -s devicemapper --storage-opt dm.fs=xfs

```

+   `dm.datadev`：这指定要使用的自定义块设备（而不是回环）用于`thin`池。如果您使用此选项，建议同时为数据和元数据指定块设备，以完全避免使用回环设备：

```
$ docker -d -s devicemapper --storage-opt dm.datadev=/dev/sdb1 \-storage-opt dm.metadatadev=/dev/sdc1

```

还有更多选项可用，以及关于所有这些工作原理的清晰解释，请参阅[`github.com/docker/docker/tree/master/daemon/graphdriver/devmapper/README.md`](https://github.com/docker/docker/tree/master/daemon/graphdriver/devmapper/README.md)。

另一个很好的资源是 Docker 贡献者 Jérôme Petazzoni 在[`jpetazzo.github.io/2014/01/29/docker-device-mapper-resize/`](http://jpetazzo.github.io/2014/01/29/docker-device-mapper-resize/)上发布的有关调整容器大小的博文。

### 注意

如果切换存储驱动程序，旧容器和图像将不再可见。

在本节的开头提到了有可能通过一个黑客手段实现配额并仍然使用 AUFS。这个黑客手段涉及根据需要创建基于`ext4`文件系统的回环文件系统，并将其作为容器的卷进行绑定挂载：

```
$ DIR=$(mktemp -d)
$ DB_DIR=(mktemp -d)
$ dd if=/dev/zero of=$DIR/data count=102400
$ yes | mkfs -t ext4 $DIR/data
$ mkdir $DB_DIR/db
$ sudo mount -o loop=/dev/loop0 $DIR/data $DB_DIR

```

您现在可以使用`docker run`命令的`-v`选项将`$DB_DIR`目录绑定到容器：

```
$ docker run -v $DB_DIR:/var/lib/mysql mysql mysqld_safe.

```

# 使用卷管理容器中的数据

Docker 卷的一些显着特点如下所述：

+   卷是与容器的`root`文件系统分开的目录。

+   它由`docker`守护程序直接管理，并可以在容器之间共享。

+   卷还可以用于在容器内挂载主机系统的目录。

+   对卷进行的更改不会在从运行中的容器更新图像时包含在内。

+   由于卷位于容器文件系统之外，它没有数据层或快照的概念。因此，读取和写入直接在卷上进行。

+   如果多个容器使用相同的卷，则卷将持久存在，直到至少有一个容器使用它。

创建卷很容易。只需使用`-v`选项启动容器：

```
$ docker run -d -p 80:80 --name apache-1 -v /var/www apache.

```

现在请注意，卷没有`ID`参数，因此您无法像命名容器或标记图像一样确切地命名卷。但是，可以利用一个容器使用它至少一次的条件来使卷持久存在，这引入了仅包含数据的容器的概念。

### 注意

自 Docker 版本 1.1 以来，如果您愿意，可以使用`-v`选项将主机的整个文件系统绑定到容器，就像这样：

```
$ docker run -v /:/my_host ubuntu:ro ls /my_host****.

```

但是，禁止挂载到容器的/，因此出于安全原因，您无法替换容器的`root`文件系统。

## 仅数据容器

数据专用容器是一个除了公开其他数据访问容器可以使用的卷之外什么也不做的容器。数据专用容器用于防止容器访问卷停止或由于意外崩溃而被销毁。

## 使用另一个容器的卷

一旦我们使用`-v`选项启动容器，就创建了一个卷。我们可以使用`--volumes-from`选项与其他容器共享由容器创建的卷。此选项的可能用例包括备份数据库、处理日志、对用户数据执行操作等。

## 用例 - 在 Docker 上生产中使用 MongoDB

作为一个用例，假设您想在生产环境中使用**MongoDB**，您将运行一个 MongoDB 服务器以及一个`cron`作业，定期备份数据库快照。

### 注意

MongoDB 是一个文档数据库，提供高性能、高可用性和易扩展性。您可以在[`www.mongodb.org`](http://www.mongodb.org)获取有关 MongoDB 的更多信息。

让我们看看如何使用`docker`卷设置 MongoDB：

1.  首先，我们需要一个数据专用容器。该容器的任务只是公开 MongoDB 存储数据的卷：

```
$ docker run -v /data/db --name data-only mongo \ echo "MongoDB stores all its data in /data/db"

```

1.  然后，我们需要运行 MongoDB 服务器，该服务器使用数据专用容器创建的卷：

```
$ docker run -d --volumes-from data-only -p 27017:27017 \ --name mongodb-server mongo mongod

```

### 注意

`mongod`命令运行 MongoDB 服务器，通常作为守护程序/服务运行。它通过端口`27017`访问。

1.  最后，我们需要运行`backup`实用程序。在这种情况下，我们只是将 MongoDB 数据存储转储到主机上的当前目录：

```
$ docker run -d --volumes-from data-only --name mongo-backup \ -v $(pwd):/backup mongo $(mkdir -p /backup && cd /backup && mongodump)

```

### 注意

这绝不是在生产中设置 MongoDB 的详尽示例。您可能需要一个监视 MongoDB 服务器健康状况的过程。您还需要使 MongoDB 服务器容器可以被您的应用程序容器发现（我们将在后面详细学习）。

# 配置 Docker 以使用不同的存储驱动程序

在使用不同的存储驱动程序之前，使用`docker save`备份所有图像，并停止`docker`守护程序。一旦备份了所有重要图像，删除`/var/lib/docker`。更改存储驱动程序后，可以恢复保存的图像。

我们现在将把默认存储驱动程序 AUFS 更改为两种备用存储驱动程序-devicemapper 和 btrfs。

## 使用 devicemapper 作为存储驱动程序

切换到 devicemapper 驱动程序很容易。只需使用-s 选项启动 docker 守护程序：

```
$ docker -d -s devicemapper

```

此外，您可以使用--storage-opts 标志提供各种 devicemapper 驱动程序选项。devicemapper 驱动程序的各种可用选项和示例已在本章的*限制资源存储*部分中介绍。

### 注意

如果您在没有 AUFS 的 RedHat/Fedora 上运行，Docker 将使用 devicemapper 驱动程序，该驱动程序可用。

切换存储驱动程序后，您可以通过运行 docker info 来验证更改。

## 使用 btrfs 作为存储驱动程序

要将 btrfs 用作存储驱动程序，您必须首先设置它。本节假定您正在运行 Ubuntu 14.04 操作系统。根据您运行的 Linux 发行版，命令可能会有所不同。以下步骤将设置一个带有 btrfs 文件系统的块设备：

1.  首先，您需要安装 btrfs 及其依赖项：

```
# apt-get -y btrfs-tools

```

1.  接下来，您需要创建一个 btrfs 文件系统类型的块设备：

```
# mkfs btrfs /dev/sdb

```

1.  现在为 Docker 创建目录（到此时，您应该已经备份了所有重要的镜像并清理了/var/lib/docker）。

```
# mkdir /var/lib/docker

```

1.  然后在/var/lib/docker 挂载 btrfs 块设备：

```
# mount /dev/sdb var/lib/docker

```

1.  检查挂载是否成功：

```
$ mount | grep btrfs
/dev/sdb on /var/lib/docker type btrfs (rw)

```

### 注意

来源：[`serverascode.com/2014/06/09/docker-btrfs.html`](http://serverascode.com/2014/06/09/docker-btrfs.html)。

现在，您可以使用-s 选项启动 docker 守护程序：

```
$ docker -d -s btrfs

```

切换存储驱动程序后，您可以通过运行 docker info 命令来验证其中的更改。

# 配置 Docker 的网络设置

Docker 为每个容器创建一个单独的网络堆栈和一个虚拟桥（docker0）来管理容器内部、容器与主机之间以及两个容器之间的网络通信。

有一些网络配置可以作为 docker run 命令的参数设置。它们如下：

+   --dns：DNS 服务器是将 URL（例如[`www.docker.io`](http://www.docker.io)）解析为运行网站的服务器的 IP 地址。

+   --dns-search：这允许您设置 DNS 搜索服务器。

### 注意

如果将 DNS 搜索服务器解析`abc`为`abc.example.com`，则`example.com`设置为 DNS 搜索域。如果您有许多子域在您的公司网站中需要经常访问，这将非常有用。反复输入整个 URL 太痛苦了。如果您尝试访问一个不是完全合格的域名的站点（例如`xyz.abc.com`），它会为查找添加搜索域。来源：[`superuser.com/a/184366`](http://superuser.com/a/184366)。

+   `-h`或`--hostname`：这允许您设置主机名。这将被添加为对容器的面向主机的 IP 的`/etc/hosts`路径的条目。

+   `--link`：这是另一个可以在启动容器时指定的选项。它允许容器与其他容器通信，而无需知道它们的实际 IP 地址。

+   `--net`：此选项允许您为容器设置网络模式。它可以有四个值：

+   `桥接`：这为 docker 容器创建了一个网络堆栈。

+   `none`：不会为此容器创建任何网络堆栈。它将完全隔离。

+   `container:<name|id>`：这使用另一个容器的网络堆栈。

+   `host`：这使用主机的网络堆栈。

### 提示

这些值具有副作用，例如本地系统服务可以从容器中访问。此选项被认为是不安全的。

+   `--expose`：这将暴露容器的端口，而不在主机上发布它。

+   `--publish-all`：这将所有暴露的端口发布到主机的接口。

+   `--publish`：这将以以下格式将容器的端口发布到主机：`ip:hostPort:containerPort | ip::containerPort | hostPort:containerPort | containerPort`。

### 提示

如果未给出`--dns`或`--dns-search`，则容器的`/etc/resolv.conf`文件将与守护程序正在运行的主机的`/etc/resolv.conf`文件相同。

然而，当你运行它时，`docker`守护进程也可以给出一些配置。它们如下所述：

### 注意

这些选项只能在启动`docker`守护程序时提供，一旦运行就无法调整。这意味着您必须在`docker -d`命令中提供这些参数。

+   `--ip`：此选项允许我们在面向容器的`docker0`接口上设置主机的 IP 地址。因此，这将是绑定容器端口时使用的默认 IP 地址。例如，此选项可以显示如下：

```
$ docker -d --ip 172.16.42.1

```

+   `--ip-forward`：这是一个`布尔`选项。如果设置为`false`，则运行守护程序的主机将不会在容器之间或从外部世界到容器之间转发数据包，从网络角度完全隔离它。

### 注意

可以使用`sysctl`命令来检查此设置：

```
$ sysctl net.ipv4.ip_forward
net.ipv4.ip_forward = 1
.

```

+   `--icc`：这是另一个`布尔`选项，代表`容器间通信`。如果设置为`false`，容器将彼此隔离，但仍然可以向包管理器等发出一般的 HTTP 请求。

### 注意

如何只允许那两个容器之间的通信？通过链接。我们将在*链接容器*部分详细探讨链接。

+   `-b 或--bridge`：您可以让 Docker 使用自定义桥接而不是`docker0`。（创建桥接超出了本讨论的范围。但是，如果您感兴趣，可以在[`docs.docker.com/articles/networking/#building-your-own-bridge`](http://docs.docker.com/articles/networking/#building-your-own-bridge)找到更多信息。）

+   `-H 或--host`：此选项可以接受多个参数。Docker 具有 RESTful API。守护程序充当服务器，当您运行客户端命令（如`run`和`ps`）时，它会向服务器发出`GET`和`POST`请求，服务器执行必要的操作并返回响应。`-H`标志用于告诉`docker`守护程序必须监听哪些通道以接收客户端命令。参数可以如下：

+   以`tcp://<host>:<port>`形式表示的 TCP 套接字

+   `unix:///path/to/socket`形式的 UNIX 套接字

## 在容器和主机之间配置端口转发

容器可以在没有任何特殊配置的情况下连接到外部世界，但外部世界不允许窥视它们。这是一项安全措施，显而易见，因为容器都通过虚拟桥连接到主机，从而有效地将它们放置在虚拟网络中。但是，如果您在容器中运行一个希望暴露给外部世界的服务呢？

端口转发是暴露在容器中运行的服务的最简单的方法。在镜像的 Dockerfile 中提到需要暴露的端口是明智的。在早期版本的 Docker 中，可以在 Dockerfile 本身指定 Dockerfile 应绑定到的主机端口，但这样做是因为有时主机中已经运行的服务会干扰容器。现在，您仍然可以在 Dockerfile 中指定要暴露的端口（使用`EXPOSE`指令），但如果要将其绑定到您选择的端口，需要在启动容器时执行此操作。

有两种方法可以启动容器并将其端口绑定到主机端口。它们的解释如下：

+   `-P 或--publish-all`：使用`docker run`启动容器，并使用`-P`选项将发布在镜像的 Dockerfile 中使用`EXPOSE`指令暴露的所有端口。Docker 将浏览暴露的端口，并将它们绑定到`49000`到`49900`之间的随机端口。

+   `-p 或--publish`：此选项允许您明确告诉 Docker 应将哪个 IP 上的哪个端口绑定到容器上的端口（当然，主机中的一个接口应该具有此 IP）。可以多次使用该选项进行多个绑定：

1.  `docker run -p ip:host_port:container_port`

1.  `docker run -p ip::container_port`

1.  `docker run -p host_port:container_port`

## 自定义 IP 地址范围

我们已经看到了如何将容器的端口绑定到主机的端口，如何配置容器的 DNS 设置，甚至如何设置主机的 IP 地址。但是，如果我们想要自己设置容器和主机之间网络的子网怎么办？Docker 在 RFC 1918 提供的可用私有 IP 地址范围中创建了一个虚拟子网。

设置自己的子网范围非常容易。`docker`守护程序的`--bip`选项可用于设置桥接的 IP 地址以及它将创建容器的子网：

```
$ docker -d --bip 192.168.0.1/24

```

在这种情况下，我们已将 IP 地址设置为`192.168.0.1`，并指定它必须将 IP 地址分配给子网范围`192.168.0.0/24`中的容器（即从`192.168.0.2`到`192.168.0.254`，共 252 个可能的 IP 地址）。

就是这样！在[`docs.docker.com/articles/networking/`](https://docs.docker.com/articles/networking/)上有更多高级网络配置和示例。一定要查看它们。

# 链接容器

如果您只有一个普通的 Web 服务器想要暴露给互联网，那么将容器端口绑定到主机端口就可以了。然而，大多数生产系统由许多不断相互通信的单独组件组成。诸如数据库服务器之类的组件不应绑定到公开可见的 IP，但运行前端应用程序的容器仍然需要发现数据库容器并连接到它们。在应用程序中硬编码容器的 IP 地址既不是一个干净的解决方案，也不会起作用，因为 IP 地址是随机分配给容器的。那么我们如何解决这个问题呢？答案如下。

## 在同一主机内链接容器

可以在启动容器时使用`--link`选项指定链接：

```
$ docker run --link CONTAINER_IDENTIFIER:ALIAS . . .

```

这是如何工作的？当给出链接选项时，Docker 会向容器的`/etc/hosts`文件添加一个条目，其中`ALIAS`命令作为主机名，容器命名为`CONTAINER_IDENTIFIER`的 IP 地址。

### 注意

`/etc/hosts`文件可用于覆盖 DNS 定义，即将主机名指向特定的 IP 地址。在主机名解析期间，在向 DNS 服务器发出请求之前，将检查`/etc/hosts`。

例如，下面显示了命令行代码：

```
$ docker run --name pg -d postgres
$ docker run --link pg:postgres postgres-app

```

上面的命令运行了一个 PostgreSQL 服务器（其 Dockerfile 公开了端口 5432，PostgeSQL 的默认端口），第二个容器将使用`postgres`别名链接到它。

### 注意

PostgreSQL 是一个完全符合**ACID**的功能强大的开源对象关系数据库系统。

## 使用 ambassador 容器进行跨主机链接

当所有容器都在同一主机上时，链接容器可以正常工作，但是 Docker 的容器通常可能分布在不同的主机上，在这些情况下链接会失败，因为在当前主机上运行的`docker`守护程序不知道在不同主机上运行的容器的 IP 地址。此外，链接是静态的。这意味着如果容器重新启动，其 IP 地址将更改，并且所有链接到它的容器将失去连接。一个可移植的解决方案是使用 ambassador 容器。

以下图显示了 ambassador 容器：

![使用 ambassador 容器进行跨主机链接](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/ocs-dkr/img/4787OS_03_02.jpg)

在这种架构中，一个主机中的数据库服务器暴露给另一个主机。同样，如果数据库容器发生更改，只需要重新启动`host1`阶段的 ambassador 容器。

### 用例 - 多主机 Redis 环境

让我们使用`progrium/ambassadord`命令设置一个多主机 Redis 环境。还有其他可以用作大使容器的镜像。它们可以使用`docker search`命令搜索，或者在[`registry.hub.docker.com`](https://registry.hub.docker.com)上搜索。

### 注意

Redis 是一个开源的、网络化的、内存中的、可选的持久性键值数据存储。它以快速的速度而闻名，无论是读取还是写入。

在这个环境中，有两个主机，`Host` `1`和`Host` `2`。`Host` `1`的 IP 地址是`192.168.0.100`，是私有的（不暴露给公共互联网）。`Host` `2`在 192.168.0.1，并绑定到一个公共 IP。这是运行您的前端 Web 应用程序的主机。

### 注意

要尝试这个例子，启动两个虚拟机。如果您使用 Vagrant，我建议使用安装了 Docker 的 Ubuntu 镜像。如果您有 Vagrant v1.5，可以通过运行`$ vagrant init phusion/ubuntu-14.04-amd64`来使用 Phusion 的 Ubuntu 镜像。

#### 主机 1

在第一个主机上，运行以下命令：

```
$ docker run -d --name redis --expose 6379 dockerfile/redis

```

这个命令启动了一个 Redis 服务器，并暴露了端口`6379`（这是 Redis 服务器运行的默认端口），但没有将其绑定到任何主机端口。

以下命令启动一个大使容器，链接到 Redis 服务器，并将端口 6379 绑定到其私有网络 IP 地址的 6379 端口（在这种情况下是 192.168.0.100）。这仍然不是公开的，因为主机是私有的（不暴露给公共互联网）：

```
$ docker run -d --name redis-ambassador-h1 \
-p 192.168.0.100:6379:6379 --link redis:redis \
progrium/ambassadord --links

```

#### 主机 2

在另一个主机（如果您在开发中使用 Vagrant，则是另一个虚拟机），运行以下命令：

```
$ docker run -d --name redis-ambassador-h2 --expose 6379 \
progrium/ambassadord 192.168.0.100:6379

```

这个大使容器监听目标 IP 的端口，这种情况下是主机 1 的 IP 地址。我们已经暴露了端口 6379，这样它现在可以被我们的应用容器连接：

```
$ docker run -d --name application-container \--link redis-ambassador-h2:redis myimage mycommand

```

这将是在互联网上公开的容器。由于 Redis 服务器在私有主机上运行，因此无法从私有网络外部受到攻击。

# 总结

在本章中，我们看到了如何在 Docker 容器中配置 CPU、RAM 和存储等资源。我们还讨论了如何使用卷和卷容器来管理容器中应用程序产生的持久数据。我们了解了切换 Docker 使用的存储驱动程序以及各种网络配置及其相关用例。最后，我们看到了如何在主机内部和跨主机之间链接容器。

在下一章中，我们将看看哪些工具和方法可以帮助我们考虑使用 Docker 部署我们的应用程序。我们将关注的一些内容包括多个服务的协调、服务发现以及 Docker 的远程 API。我们还将涵盖安全考虑。


# 第四章：自动化和最佳实践

此时，我们现在知道如何在开发环境中设置 Docker，熟悉 Docker 命令，并且对 Docker 适用的情况有一个很好的了解。我们还知道如何配置 Docker 及其容器以满足我们所有的需求。

在这一章中，我们将专注于各种使用模式，这些模式将帮助我们在生产环境中部署我们的 Web 应用程序。我们将从 Docker 的远程 API 开始，因为登录到生产服务器并运行命令总是被认为是危险的。因此，最好运行一个监视和编排主机中容器的应用程序。如今有许多用于 Docker 的编排工具，并且随着 v1.0 的宣布，Docker 还宣布了一个新项目**libswarm**，它提供了一个标准接口来管理和编排分布式系统，这将是我们将要深入探讨的另一个主题。

Docker 开发人员建议每个容器只运行一个进程。如果您想要检查已经运行的容器，这可能有些困难。我们将看一下一个允许我们将进程注入到已经运行的容器中的命令。

随着组织的发展，负载也会增加，您将需要开始考虑扩展。Docker 本身是用于在单个主机中使用的，但是通过使用一系列工具，如`etcd`和`coreos`，您可以轻松地在集群中运行一堆 Docker 主机并发现该集群中的每个其他容器。

每个在生产环境中运行 Web 应用程序的组织都知道安全性的重要性。在本章中，我们将讨论与`docker`守护程序相关的安全方面，以及 Docker 使用的各种 Linux 功能。总之，在本章中，我们将看到以下内容：

+   Docker 远程 API

+   使用 Docker exec 命令将进程注入容器

+   服务发现

+   安全性

# Docker 远程 API

Docker 二进制文件可以同时作为客户端和守护程序运行。当 Docker 作为守护程序运行时，默认情况下会将自己附加到 Unix 套接字`unix:///var/run/docker.sock`（当然，在启动 docker 时可以更改此设置），并接受 REST 命令。然后，相同的 Docker 二进制文件可以用于运行所有其他命令（这只是客户端向`docker`守护程序发出 REST 调用）。

下图显示了`docker`守护程序的图表：

![Docker 远程 API](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/ocs-dkr/img/4787OS_04_04.jpg)

本节将主要通过示例来解释，因为我们在查看 Docker 命令时已经遇到了这些操作的工作原理。

要测试这些 API，运行`docker`守护程序，使用 TCP 端口，如下所示：

```
$ export DOCKER_HOST=tcp://0.0.0.0:2375
$ sudo service docker restart
$ export DOCKER_DAEMON=http://127.0.0.1:2375 # or IP of your host

```

### 注意

这不会是一个参考指南，因为我们在第二章中已经涵盖了 Docker 可用的功能，*Docker CLI 和 Dockerfile*。相反，我们将涵盖一些 API，并且您可以在[docs.docker.com/reference/api/docker_remote_api](http://docs.docker.com/reference/api/docker_remote_api)上查找其余部分。

在我们开始之前，让我们确保`docker`守护程序正在响应我们的请求：

```
$ curl $DOCKER_DAEMON/_ping
OK

```

好的，一切都很好。让我们开始吧。

## 容器的远程 API

让我们首先看一下可用的一些端点，这些端点有助于创建和管理容器。

### 创建命令

`create`命令创建一个容器：

```
$ curl \
> -H "Content-Type: application/json" \
> -d '{"Image":"ubuntu:14.04",\
> "Cmd":["echo", "I was started with the API"]}' \
> -X POST $DOCKER_DAEMON/containers/create?\
> name=api_container;
{"Id":"4e145a6a54f9f6bed4840ac730cde6dc93233659e7eafae947efde5caf583f c3","Warnings":null}

```

### 注意

`curl`实用程序是一个简单的 Unix 实用程序，可用于构造 HTTP 请求和分析响应。

在这里，我们向`/containers/create`端点发出`POST`请求，并传递一个包含我们希望容器基于的镜像的详细信息以及我们期望容器运行的命令的`JSON`对象。

请求类型：POST

与`POST`请求一起发送的`JSON`数据：

| 参数 | 类型 | 说明 |
| --- | --- | --- |

|

```
config

```

| `JSON` | 描述要启动的容器的配置 |
| --- | --- |

POST 请求的查询参数：

| 参数 | 类型 | 说明 |
| --- | --- | --- |

|

```
name

```

| `String` | 这为容器分配一个名称。它必须匹配`/?[a-zA-Z0-9_-]+`正则表达式。 |
| --- | --- |

以下表格显示了响应的状态码：

| 状态码 | 意义 |
| --- | --- |

|

```
201

```

| 无错误 |
| --- |

|

```
404

```

| 没有这样的容器 |
| --- |

|

```
406

```

| 无法附加（容器未运行） |
| --- |

|

```
500

```

| 内部服务器错误 |
| --- |

### 列表命令

`list`命令获取容器列表：

```
$ curl $DOCKER_DAEMON/containers/json?all=1\&limit=1
[{"Command":"echo 'I was started with the API'","Created":1407995735,"Id":"96bdce1493715c2ca8940098db04b99e3629 4a333ddacab0e04f62b98f1ec3ae","Image":"ubuntu:14.04","Names":["/api_c ontainer"],"Ports":[],"Status":"Exited (0) 3 minutes ago"}

```

这是一个`GET`请求 API。对`/containers/json`的请求将返回一个`JSON`响应，其中包含满足条件的容器列表。在这里，传递`all`查询参数将列出未运行的容器。`limit`参数是响应中将列出的容器数量。

有一些查询参数可以与这些 API 调用一起提供，可以微调响应。

请求类型：GET

| 参数 | 类型 | 说明 |
| --- | --- | --- |

|

```
all

```

| 1/`True`/`true` 或 0/`False`/`false` | 这告诉是否显示所有容器。默认情况下只显示正在运行的容器。 |
| --- | --- |

|

```
limit

```

| `整数` | 这显示最后 [*n*] 个容器，包括非运行中的容器。 |
| --- | --- |

|

```
since

```

| `容器` `ID` | 这只显示自 [x] 以来启动的容器，包括非运行中的容器。 |
| --- | --- |

|

```
before

```

| `容器` `ID` | 这只显示在 [x] 之前启动的容器，包括非运行中的容器。 |
| --- | --- |

|

```
size

```

| 1/`True`/`true` 或 0/`False`/`false` | 这告诉是否在响应中显示容器大小。 |
| --- | --- |

响应的状态码遵循相关的 **请求** **评论** (**RFC**) 2616：

| 状态码 | 意义 |
| --- | --- |

|

```
200

```

| 没有错误 |
| --- |

|

```
400

```

| 错误的参数和客户端错误 |
| --- |

|

```
500

```

| 服务器错误 |
| --- |

有关容器的其他端点可以在[docs.docker.com/reference/api/docker_remote_api_v1.13/#21-containers](http://docs.docker.com/reference/api/docker_remote_api_v1.13/#21-containers)上阅读。

## 图像的远程 API

与容器类似，还有用于构建和管理图像的 API。

### 列出本地 Docker 图像

以下命令列出本地图像：

```
$ curl $DOCKER_DAEMON/images/json
[{"Created":1406791831,"Id":"7e03264fbb7608346959378f270b32bf31daca14d15e9979a5803ee32e9d2221","ParentId":"623cd16a51a7fb4ecd539eb1e5d9778 c90df5b96368522b8ff2aafcf9543bbf2","RepoTags":["shrikrishna/apt- moo:latest"],"Size":0,"VirtualSize":281018623} ,{"Created":1406791813,"Id":"c5f4f852c7f37edcb75a0b712a16820bb8c729a6 a5093292e5f269a19e9813f2","ParentId":"ebe887219248235baa0998323342f7f 5641cf5bff7c43e2b802384c1cb0dd498","RepoTags":["shrikrishna/onbuild:l atest"],"Size":0,"VirtualSize":281018623} ,{"Created":1406789491,"Id":"0f0dd3deae656e50a78840e58f63a5808ac53cb4 dc87d416fc56aaf3ab90c937","ParentId":"061732a839ad1ae11e9c7dcaa183105 138e2785954ea9e51f894f4a8e0dc146c","RepoTags":["shrikrishna/optimus:g it_url"],"Size":0,"VirtualSize":670857276}

```

这是一个 `GET` 请求 API。对 `/images/json` 的请求将返回一个包含满足条件的图像详细信息列表的 `JSON` 响应。

请求类型：GET

| 参数 | 类型 | 解释 |
| --- | --- | --- |

|

```
all

```

| 1/`True`/`true` 或 0/`False`/`false` | 这告诉是否显示中间容器。默认为假。 |
| --- | --- |

|

```
filters

```

| `JSON` | 这些用于提供图像的筛选列表。 |
| --- | --- |

有关图像的其他端点可以在[docs.docker.com/reference/api/docker_remote_api_v1.13/#22-images](http://docs.docker.com/reference/api/docker_remote_api_v1.13/#22-images)上阅读。

## 其他操作

还有其他 API，比如我们在本节开头检查的 ping API。其中一些在下一节中探讨。

### 获取系统范围的信息

以下命令获取 Docker 的系统范围信息。这是处理 `docker info` 命令的端点：

```
$ curl $DOCKER_DAEMON/info
{"Containers":41,"Debug":1,"Driver":"aufs","DriverStatus":[["Root Dir","/mnt/sda1/var/lib/docker/aufs"],["Dirs","225"]],"ExecutionDrive r":"native- 0.2","IPv4Forwarding":1,"Images":142,"IndexServerAddress":"https://in dex.docker.io/v1/","InitPath":"/usr/local/bin/docker","InitSha1":""," KernelVersion":"3.15.3- tinycore64","MemoryLimit":1,"NEventsListener":0,"NFd":15,"NGoroutines ":15,"Sockets":["unix:///var/run/docker.sock","tcp://0.0.0.0:2375"]," SwapLimit":1}

```

### 从容器中提交图像

以下命令从容器中提交图像：

```
$ curl \
> -H "Content-Type: application/json" \
> -d '{"Image":"ubuntu:14.04",\
> "Cmd":["echo", "I was started with the API"]}' \
> -X POST $DOCKER_DAEMON/commit?\
> container=96bdce149371\
> \&m=Created%20with%20remote%20api\&repo=shrikrishna/api_image;

{"Id":"5b84985879a84d693f9f7aa9bbcf8ee8080430bb782463e340b241ea760a5a 6b"}

```

提交是对`/commit`参数的`POST`请求，其中包含有关其基础图像和与将在提交时创建的图像相关联的命令的数据。关键信息包括要提交的`container` `ID`参数，提交消息以及它所属的存储库，所有这些都作为查询参数传递。

请求类型：POST

与`POST`请求一起发送的`JSON`数据：

| 参数 | 类型 | 解释 |
| --- | --- | --- |

|

```
config

```

| `JSON` | 这描述了要提交的容器的配置 |
| --- | --- |

以下表格显示了`POST`请求的查询参数：

| 参数 | 类型 | 解释 |
| --- | --- | --- |

|

```
container

```

| `Container ID` | 您打算提交的容器的`ID` |
| --- | --- |

|

```
repo

```

| `String` | 要在其中创建图像的存储库 |
| --- | --- |

|

```
tag

```

| `String` | 新图像的标签 |
| --- | --- |

|

```
m

```

| `String` | 提交消息 |
| --- | --- |

|

```
author

```

| `String` | 作者信息 |
| --- | --- |

以下表格显示了响应的状态码：

| 状态码 | 意义 |
| --- | --- |

|

```
201

```

| 没有错误 |
| --- |

|

```
404

```

| 没有这样的容器 |
| --- |

|

```
500

```

| 内部服务器错误 |
| --- |

### 保存图像

从以下命令获取存储库的所有图像和元数据的 tarball 备份：

```
$ curl $DOCKER_DAEMON/images/shrikrishna/code.it/get > \
> code.it.backup.tar.gz

```

这将需要一些时间，因为图像首先必须被压缩成一个 tarball，然后被流式传输，但然后它将被保存在 tar 存档中。

其他端点可以在[docs.docker.com/reference/api/docker_remote_api_v1.13/#23-misc](http://docs.docker.com/reference/api/docker_remote_api_v1.13/#23-misc)上了解。

## docker run 的工作原理

既然我们意识到我们运行的每个 Docker 命令实际上都是客户端执行的一系列 RESTful 操作，让我们加深一下对运行`docker run`命令时发生的事情的理解：

1.  要创建一个 API，需要调用`/containers/``create`参数。

1.  如果响应的状态码是 404，则表示图像不存在。尝试使用`/images/create`参数拉取图像，然后返回到步骤 1。

1.  获取创建的容器的`ID`并使用`/containers/(id)/start`参数启动它。

这些 API 调用的查询参数将取决于传递给`docker run`命令的标志和参数。

# 使用 Docker execute 命令将进程注入容器

在您探索 Docker 的过程中，您可能会想知道 Docker 强制执行的每个容器规则是否限制了其功能。事实上，您可能会原谅认为 Docker 容器只运行一个进程。但不是！一个容器可以运行任意数量的进程，但只能以一个命令启动，并且与命令相关联的进程存在的时间就是容器的生存时间。这种限制是因为 Docker 相信一个容器一个应用程序的理念。与其将所有内容加载到单个容器中，典型的依赖于 Docker 的应用程序架构将包括多个容器，每个容器运行一个专门的服务，所有这些服务都链接在一起。这有助于保持容器轻便，使调试更容易，减少攻击向量，并确保如果一个服务崩溃，其他服务不受影响。

然而，有时您可能需要在容器运行时查看容器。随着时间的推移，Docker 社区采取了许多方法来调试运行中的容器。一些成员将 SSH 加载到容器中，并运行了一个进程管理解决方案，如**supervisor**来运行 SSH +应用程序服务器。然后出现了诸如**nsinit**和**nsenter**之类的工具，这些工具帮助在容器正在运行的命名空间中生成一个 shell。然而，所有这些解决方案都是黑客攻击。因此，随着 v1.3 的到来，Docker 决定提供`docker exec`命令，这是一个安全的替代方案，可以调试运行中的容器。

`docker exec`命令允许用户通过 Docker API 和 CLI 在其 Docker 容器中生成一个进程，例如：

```
$ docker run -dit --name exec_example -v $(pwd):/data -p 8000:8000 dockerfile/python python -m SimpleHTTPServer
$ docker exec -it exec_example bash

```

第一个命令启动一个简单的文件服务器容器。使用`-d`选项将容器发送到后台。在第二个命令中，使用`docker exec`，我们通过在其中创建一个 bash 进程来登录到容器。现在我们将能够检查容器，读取日志（如果我们已经登录到文件中），运行诊断（如果需要检查是因为错误而出现），等等。

### 注意

Docker 仍然没有从其一个应用程序每个容器的理念中移动。 `docker exec`命令存在只是为了提供一种检查容器的方法，否则将需要变通或黑客攻击。

# 服务发现

Docker 会动态地从可用地址池中为容器分配 IP。虽然在某些方面这很好，但当您运行需要相互通信的容器时，就会产生问题。在构建镜像时，您无法知道其 IP 地址将是什么。您可能的第一反应是启动容器，然后通过`docker exec`登录到它们，并手动设置其他容器的 IP 地址。但请记住，当容器重新启动时，此 IP 地址可能会更改，因此您将不得不手动登录到每个容器并输入新的 IP 地址。有没有更好的方法？是的，有。

服务发现是一系列需要完成的工作，让服务知道如何找到并与其他服务通信。在服务发现下，容器在刚启动时并不知道它们的对等体。相反，它们会动态地发现它们。这应该在容器位于同一主机以及位于集群中时都能正常工作。

有两种技术可以实现服务发现：

+   使用默认的 Docker 功能，如名称和链接

+   使用专用服务，如`Etcd`或`Consul`

## 使用 Docker 名称、链接和大使容器

我们在第三章的*链接容器*部分学习了如何链接容器。为了提醒您，这就是它的工作原理。

### 使用链接使容器彼此可见

以下图表显示了链接的使用：

![使用链接使容器彼此可见](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/ocs-dkr/img/4787OS_04_05.jpg)

链接允许容器连接到另一个容器，而无需硬编码其 IP 地址。在启动第二个容器时，将第一个容器的 IP 地址插入`/etc/hosts`中即可实现这一点。

可以在启动容器时使用`--link`选项指定链接：

```
$ docker run --link CONTAINER_IDENTIFIER:ALIAS . . .

```

您可以在第三章中了解更多关于链接的信息。

### 使用大使容器进行跨主机链接

以下图表代表了使用大使容器进行跨主机链接：

![使用大使容器进行跨主机链接](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/ocs-dkr/img/4787OS_04_03.jpg)

大使容器用于链接跨主机的容器。在这种架构中，您可以重新启动/替换数据库容器，而无需重新启动应用程序容器。

您可以在第三章*配置 Docker 容器*中了解有关 ambassador 容器的更多信息。

## 使用 etcd 进行服务发现

为什么我们需要专门的服务发现解决方案？虽然 ambassador 容器和链接解决了在不需要知道其 IP 地址的情况下找到容器的问题，但它们确实有一个致命的缺陷。您仍然需要手动监视容器的健康状况。

想象一种情况，您有一组后端服务器和通过 ambassador 容器与它们连接的前端服务器的集群。如果其中一个服务器宕机，前端服务器仍然会继续尝试连接到后端服务器，因为在它们看来，那是唯一可用的后端服务器，这显然是错误的。

现代服务发现解决方案，如`etcd`、`Consul`和`doozerd`，不仅提供正确的 IP 地址和端口，它们实际上是分布式键值存储，具有容错和一致性，并在故障发生时处理主节点选举。它们甚至可以充当锁服务器。

`etcd`服务是由**CoreOS**开发的开源分布式键值存储。在集群中，`etcd`客户端在集群中的每台机器上运行。`etcd`服务在网络分区和当前主节点丢失期间优雅地处理主节点选举。

您的应用程序可以读取和写入`etcd`服务中的数据。`etcd`服务的常见示例包括存储数据库连接详细信息、缓存设置等。

`etcd`服务的特点在这里列出：

+   简单的可 curl API（HTTP + JSON）

+   可选的**安全**套接字层（**SSL**）客户端证书认证

+   键支持**生存时间**（**TTL**）

### 注意

`Consul`服务是`etcd`服务的一个很好的替代方案。没有理由选择其中一个而不是另一个。本节只是为了向您介绍服务发现的概念。

我们在两个阶段使用`etcd`服务如下：

1.  我们使用`etcd`服务注册我们的服务。

1.  我们进行查找以查找已注册的服务。

以下图显示了`etcd`服务：

![使用 etcd 进行服务发现](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/ocs-dkr/img/4787OS_04_06.jpg)

这似乎是一个简单的任务，但构建一个容错和一致的解决方案并不简单。您还需要在服务失败时收到通知。如果以天真的集中方式运行服务发现解决方案本身，它可能会成为单点故障。因此，服务发现服务器集群中的所有实例都需要与正确的答案同步，这就需要有趣的方法。CoreOS 团队开发了一种称为**Raft**的共识算法来解决这个问题。您可以在[`raftconsensus.github.io`](http://raftconsensus.github.io)上阅读更多信息。

让我们来看一个例子，了解一下情况。在这个例子中，我们将在一个容器中运行`etcd`服务器，并看看注册服务和发现服务有多么容易。

1.  步骤 1：运行`etcd`服务器：

```
$ docker run -d -p 4001:4001 coreos/etcd:v0.4.6 -name myetcd

```

1.  步骤 2：一旦镜像下载完成并且服务器启动，运行以下命令注册一条消息：

```
$ curl -L -X PUT http://127.0.0.1:4001/v2/keys/message -d value="Hello"
{"action":"set","node":{"key":"/message","value":"Hello","modifiedIndex":3,"createdIndex":3}}

```

这只是对`/v2/keys/message`路径上的服务器发出的`PUT`请求（这里的密钥是`message`）。

1.  步骤 3：使用以下命令获取密钥：

```
$ curl -L http://127.0.0.1:4001/v2/keys/message
{"action":"get","node":{"key":"/message","value":"Hello","modifiedIndex":4,"createdIndex":4}}

```

您可以继续尝试更改值，尝试无效的密钥等。您会发现响应是`JSON`格式的，这意味着您可以轻松地将其与应用程序集成，而无需使用任何库。

但是我该如何在我的应用程序中使用它呢？如果您的应用程序需要运行多个服务，它们可以通过链接和大使容器连接在一起，但如果其中一个变得不可用或需要重新部署，就需要做很多工作来恢复链接。

现在想象一下，您的服务使用`etcd`服务。每个服务都会根据其名称注册其 IP 地址和端口号，并通过其名称（恒定的）发现其他服务。现在，如果容器因崩溃/重新部署而重新启动，新容器将根据修改后的 IP 地址进行注册。这将更新`etcd`服务返回的值，以供后续发现请求使用。但是，这意味着单个`etcd`服务器也可能是单点故障。解决此问题的方法是运行一组`etcd`服务器。这就是 CoreOS（创建`etcd`服务的团队）开发的 Raft 一致性算法发挥作用的地方。可以在[`jasonwilder.com/blog/2014/07/15/docker-service-discovery/`](http://jasonwilder.com/blog/2014/07/15/docker-service-discovery/)找到使用`etcd`服务部署的应用服务的完整示例。

## Docker 编排

一旦您超越简单的应用程序进入复杂的架构，您将开始使用诸如`etcd`、`consul`和`serf`之类的工具和服务，并且您会注意到它们都具有自己的一套 API，即使它们具有重叠的功能。如果您设置基础设施为一组工具，并发现需要切换，这需要相当大的努力，有时甚至需要更改代码才能切换供应商。这种情况可能导致供应商锁定，这将破坏 Docker 设法创建的有前途的生态系统。为了为这些服务提供商提供标准接口，以便它们几乎可以用作即插即用的解决方案，Docker 发布了一套编排服务。在本节中，我们将对它们进行介绍。但是，请注意，在撰写本书时，这些项目（Machine、Swarm 和 Compose）仍处于 Alpha 阶段，并且正在积极开发中。

## Docker Machine

Docker Machine 旨在提供一个命令，让您从零开始进行 Docker 项目。

在 Docker Machine 之前，如果您打算在新主机上开始使用 Docker，无论是虚拟机还是基础设施提供商（如亚马逊网络服务（AWS）或 Digital Ocean）上的远程主机，您都必须登录到实例，并运行特定于其中运行的操作系统的设置和配置命令。

使用 Docker Machine，无论是在新笔记本电脑上、数据中心的虚拟机上，还是在公共云实例上配置`docker`守护程序，都可以使用相同的单个命令准备目标主机以运行 Docker 容器：

```
$ machine create -d [infrastructure provider] [provider options] [machine name]

```

然后，您可以从相同的界面管理多个 Docker 主机，而不管它们的位置，并在它们上运行任何 Docker 命令。

除此之外，该机器还具有可插拔的后端，这使得很容易为基础设施提供商添加支持，同时保留了常见的用户界面 API。Machine 默认提供了用于在 Virtualbox 上本地配置 Docker 以及在 Digital Ocean 实例上远程配置的驱动程序。

请注意，Docker Machine 是 Docker Engine 的一个独立项目。您可以在其 Github 页面上找到有关该项目的更新详细信息：[`github.com/docker/machine`](https://github.com/docker/machine)。

## Swarm

**Swarm**是 Docker 提供的本地集群解决方案。它使用 Docker Engine 并对其进行扩展，以使您能够在容器集群上工作。使用 Swarm，您可以管理 Docker 主机的资源池，并安排容器在其上透明地运行，自动管理工作负载并提供故障转移服务。

要进行安排，它需要容器的资源需求，查看主机上的可用资源，并尝试优化工作负载的放置。

例如，如果您想要安排一个需要 1GB 内存的 Redis 容器，可以使用 Swarm 进行安排：

```
$ docker run -d -P -m 1g redis

```

除了资源调度，Swarm 还支持基于策略的调度，具有标准和自定义约束。例如，如果您想在支持 SSD 的主机上运行您的**MySQL**容器（以确保更好的写入和读取性能），可以按照以下方式指定：

```
$ docker run -d -P -e constraint:storage=ssd mysql

```

除了所有这些，Swarm 还提供了高可用性和故障转移。它不断监视容器的健康状况，如果一个容器发生故障，会自动重新平衡，将失败主机上的 Docker 容器移动并重新启动到新主机上。最好的部分是，无论您是刚开始使用一个实例还是扩展到 100 个实例，界面都保持不变。

与 Docker Machine 一样，Docker Swarm 处于 Alpha 阶段，并不断发展。请前往其 Github 存储库了解更多信息：[`github.com/docker/swarm/`](https://github.com/docker/swarm/)。

## Docker Compose

**Compose**是这个谜题的最后一块。通过 Docker Machine，我们已经配置了 Docker 守护程序。通过 Docker Swarm，我们可以放心，我们将能够从任何地方控制我们的容器，并且如果有任何故障，它们将保持可用。Compose 帮助我们在这个集群上组合我们的分布式应用程序。

将这与我们已经了解的东西进行比较，可能有助于我们理解所有这些是如何一起工作的。Docker Machine 的作用就像操作系统对程序的作用一样。它提供了容器运行的地方。Docker Swarm 就像程序的编程语言运行时一样。它管理资源，提供异常处理等等。

Docker Compose 更像是一个 IDE，或者是一种语言语法，它提供了一种表达程序需要做什么的方式。通过 Compose，我们指定了我们的分布式应用程序在集群中的运行方式。

我们使用 Docker Compose 通过编写`YAML`文件来声明我们的多容器应用程序的配置和状态。例如，假设我们有一个使用 Redis 数据库的 Python 应用程序。以下是我们为 Compose 编写`YAML`文件的方式：

```
containers:
  web:
     build: .
     command: python app.py
     ports:
     - "5000:5000"
     volumes:
     - .:/code
     links:
     - redis
     environment:
     - PYTHONUNBUFFERED=1
  redis:
     image: redis:latest
     command: redis-server --appendonly yes
```

在上面的例子中，我们定义了两个应用程序。一个是需要从当前目录的 Dockerfile 构建的 Python 应用程序。它暴露了一个端口（`5000`），并且要么有一个卷，要么有一段代码绑定到当前工作目录。它还定义了一个环境变量，并且与第二个应用程序容器`redis`链接。第二个容器使用了 Docker 注册表中的`redis`容器。

有了定义的配置，我们可以使用以下命令启动两个容器：

```
$ docker up

```

通过这个单一的命令，Python 容器使用 Dockerfile 构建，并且`redis`镜像从注册表中拉取。然而，`redis`容器首先启动，因为 Python 容器的规范中有 links 指令，并且 Python 容器依赖于它。

与 Docker Machine 和 Docker Swarm 一样，Docker Compose 是一个“正在进行中”的项目，其开发可以在[`github.com/docker/docker/issues/9459`](https://github.com/docker/docker/issues/9459)上跟踪。

有关 swarm 的更多信息可以在[`blog.docker.com/2014/12/announcing-docker-machine-swarm-and-compose-for-orchestrating-distributed-apps/`](http://blog.docker.com/2014/12/announcing-docker-machine-swarm-and-compose-for-orchestrating-distributed-apps/)找到。

# 安全

安全性在决定是否投资于技术时至关重要，特别是当该技术对基础设施和工作流程有影响时。Docker 容器大多是安全的，而且由于 Docker 不会干扰其他系统，您可以使用额外的安全措施来加固`docker`守护程序周围的安全性。最好在专用主机上运行`docker`守护程序，并将其他服务作为容器运行（除了诸如`ssh`、`cron`等服务）。

在本节中，我们将讨论 Docker 中用于安全性的内核特性。我们还将考虑`docker`守护程序本身作为可能的攻击向量。

图片来源[`xkcd.com/424/`](http://xkcd.com/424/)

![安全性](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/ocs-dkr/img/4787OS_04_01.jpg)

## 内核命名空间

命名空间为容器提供了沙盒功能。当容器启动时，Docker 会为容器创建一组命名空间和控制组。因此，属于特定命名空间的容器无法看到或影响属于其他命名空间或主机的另一个容器的行为。

以下图表解释了 Docker 中的容器：

![内核命名空间](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/ocs-dkr/img/4787OS_04_07.jpg)

内核命名空间还为容器创建了一个网络堆栈，可以进行最后的详细配置。默认的 Docker 网络设置类似于简单的网络，主机充当路由器，`docker0`桥充当以太网交换机。

命名空间功能是模仿 OpenVZ 而设计的，OpenVZ 是基于 Linux 内核和操作系统的操作系统级虚拟化技术。OpenVZ 是目前市场上大多数廉价 VPS 所使用的技术。它自 2005 年以来就存在，命名空间功能是在 2008 年添加到内核中的。从那时起就被用于生产环境，因此可以称之为“经过严峻考验的”。

## 控制组

控制组提供资源管理功能。虽然这与特权无关，但由于其可能作为拒绝服务攻击的第一道防线，因此与安全性相关。控制组也存在已经相当长时间，因此可以认为在生产环境中是安全的。

有关控制组的进一步阅读，请参阅[`www.kernel.org/doc/Documentation/cgroups/cgroups.txt`](https://www.kernel.org/doc/Documentation/cgroups/cgroups.txt)。

## 容器中的根

容器中的`root`命令被剥夺了许多特权。例如，默认情况下，您无法使用`mount`命令挂载设备。另一方面，使用`--privileged`标志运行容器将使容器中的`root`用户完全访问主机中`root`用户拥有的所有特权。Docker 是如何实现这一点的呢？

您可以将标准的`root`用户视为具有广泛能力的人。其中之一是`net_bind_service`服务，它绑定到任何端口（甚至低于 1024）。另一个是`cap_sys_admin`服务，这是挂载物理驱动器所需的。这些被称为功能，是进程用来证明其被允许执行操作的令牌。

Docker 容器是以减少的能力集启动的。因此，您会发现您可以执行一些 root 操作，但不能执行其他操作。具体来说，在非特权容器中，`root`用户无法执行以下操作：

+   挂载/卸载设备

+   管理原始套接字

+   文件系统操作，如创建设备节点和更改文件所有权

在 v1.2 之前，如果您需要使用任何被列入黑名单的功能，唯一的解决方案就是使用`--privileged`标志运行容器。但是 v1.2 引入了三个新标志，`--cap-add`，`--cap-drop`和`--device`，帮助我们运行需要特定功能的容器，而不会影响主机的安全性。

`--cap-add`标志向容器添加功能。例如，让我们改变容器接口的状态（这需要`NET_ADMIN`服务功能）：

```
$ docker run --cap-add=NET_ADMIN ubuntu sh -c "ip link eth0 down"

```

`--cap-drop`标志在容器中列入黑名单功能。例如，让我们在容器中列入黑名单除`chown`命令之外的所有功能，然后尝试添加用户。这将失败，因为它需要`CAP_CHOWN`服务。

```
$ docker run --cap-add=ALL --cap-drop=CHOWN -it ubuntu useradd test
useradd: failure while writing changes to /etc/shadow

```

`--devices`标志用于直接在容器上挂载外部/虚拟设备。在 v1.2 之前，我们必须在主机上挂载它，并在`--privileged`容器中使用`-v`标志进行绑定挂载。使用`--device`标志，您现在可以在容器中使用设备，而无需使用`--privileged`容器。

例如，要在容器上挂载笔记本电脑的 DVD-RW 设备，请运行以下命令：

```
$ docker run --device=/dev/dvd-rw:/dev/dvd-rw ...

```

有关这些标志的更多信息，请访问[`blog.docker.com/tag/docker-1-2/`](http://blog.docker.com/tag/docker-1-2/)。

Docker 1.3 版本还引入了其他改进。CLI 中添加了`--security-opts`标志，允许您设置自定义的**SELinux**和**AppArmor**标签和配置文件。例如，假设您有一个策略，允许容器进程仅监听 Apache 端口。假设您在`svirt_apache`中定义了此策略，您可以将其应用于容器，如下所示：

```
$ docker run --security-opt label:type:svirt_apache -i -t centos \ bash

```

这一功能的好处之一是，用户将能够在支持 SELinux 或 AppArmor 的内核上运行 Docker，而无需在容器上使用`docker run --privileged`。不像`--privileged`容器一样给予运行容器所有主机访问权限，这显著减少了潜在威胁的范围。

来源：[`blog.docker.com/2014/10/docker-1-3-signed-images-process-injection-security-options-mac-shared-directories/`](http://blog.docker.com/2014/10/docker-1-3-signed-images-process-injection-security-options-mac-shared-directories/)。

您可以在[`github.com/docker/docker/blob/master/daemon/execdriver/native/template/default_template.go`](https://github.com/docker/docker/blob/master/daemon/execdriver/native/template/default_template.go)上查看已启用功能的完整列表。

### 注意

对于好奇的人，所有可用功能的完整列表可以在 Linux 功能手册页中找到。也可以在[`man7.org/linux/man-pages/man7/capabilities.7.html`](http://man7.org/linux/man-pages/man7/capabilities.7.html)上找到。

## Docker 守护程序攻击面

`docker`守护程序负责创建和管理容器，包括创建文件系统，分配 IP 地址，路由数据包，管理进程等需要 root 权限的许多任务。因此，将守护程序作为`sudo`用户启动是必不可少的。这就是为什么`docker`守护程序默认绑定到 Unix 套接字，而不是像 v5.2 之前那样绑定到 TCP 套接字的原因。

Docker 的最终目标之一是能够将守护程序作为非 root 用户运行，而不影响其功能，并将确实需要 root 的操作（如文件系统操作和网络）委托给具有提升权限的专用子进程。

如果您确实希望将 Docker 的端口暴露给外部世界（以利用远程 API），建议确保只允许受信任的客户端访问。一个简单的方法是使用 SSL 保护 Docker。您可以在[`docs.docker.com/articles/https`](https://docs.docker.com/articles/https)找到设置此项的方法。

## 安全最佳实践

现在让我们总结一些在您的基础设施中运行 Docker 时的关键安全最佳实践：

+   始终在专用服务器上运行`docker`守护程序。

+   除非您有多个实例设置，否则在 Unix 套接字上运行`docker`守护程序。

+   特别注意将主机目录作为卷进行绑定挂载，因为容器有可能获得完全的读写访问权限，并在这些目录中执行不可逆的操作。

+   如果必须绑定到 TCP 端口，请使用基于 SSL 的身份验证进行安全保护。

+   避免在容器中以 root 权限运行进程。

+   在生产中绝对没有理智的理由需要运行特权容器。

+   考虑在主机上启用 AppArmor/SELinux 配置文件。这使您可以为主机添加额外的安全层。

+   与虚拟机不同，所有容器共享主机的内核。因此，保持内核更新以获取最新的安全补丁非常重要。

# 总结

在本章中，我们了解了各种工具、API 和实践，这些工具、API 和实践帮助我们在基于 Docker 的环境中部署应用程序。最初，我们研究了远程 API，并意识到所有 Docker 命令都不过是对`docker`守护程序的基于 REST 的调用的结果。

然后我们看到如何注入进程来帮助调试运行中的容器。

然后，我们看了各种方法来实现服务发现，既使用本机 Docker 功能，如链接，又借助专门的`config`存储，如`etcd`服务。

最后，我们讨论了在使用 Docker 时的各种安全方面，它所依赖的各种内核特性，它们的可靠性以及它们对容器所在主机安全性的影响。

在下一章中，我们将进一步采取本章的方法，并查看各种开源项目。我们将学习如何集成或使用它们，以充分实现 Docker 的潜力。


# 第五章：Docker 的朋友

到目前为止，我们一直忙于学习有关 Docker 的一切。影响开源项目寿命的一个主要因素是其周围的社区。Docker 的创建者 Docker Inc.（**dotCloud**的分支）负责开发和维护 Docker 及其姊妹项目，如 libcontainer、libchan、swarm 等（完整列表可在[github.com/docker](http://github.com/docker)找到）。然而，像任何其他开源项目一样，开发是公开的（在 GitHub 上），他们接受拉取请求。

行业也接受了 Docker。像谷歌、亚马逊、微软、eBay 和 RedHat 这样的大公司积极使用和贡献 Docker。大多数流行的 IaaS 解决方案，如亚马逊网络服务、谷歌计算云等，都支持创建预加载和优化为 Docker 的镜像。许多初创公司也在 Docker 上押注他们的财富。CoreOS、Drone.io 和 Shippable 是一些初创公司，它们提供基于 Docker 的服务。因此，您可以放心，它不会很快消失。

在本章中，我们将讨论围绕 Docker 的一些项目以及如何使用它们。我们还将看看您可能已经熟悉的项目，这些项目可以促进您的 Docker 工作流程（并使您的生活变得更加轻松）。

首先，我们将讨论如何使用 Chef 和 Puppet 配方与 Docker。你们中的许多人可能已经在工作流程中使用这些工具。本节将帮助您将 Docker 与当前工作流程集成，并使您逐步进入 Docker 生态系统。

接下来，我们将尝试设置一个**apt-cacher**，这样我们的 Docker 构建就不会花费大量时间从 Canonical 服务器获取经常使用的软件包。这将大大减少使用 Dockerfile 构建镜像所需的时间。

在早期阶段，给 Docker 带来如此大的关注的一件事是，一些本来被认为很难的事情在 Docker 实现时似乎变得很容易。其中一个项目是**Dokku**，一个 100 行的 bash 脚本，可以设置一个类似于**mini**-**Heroku**的 PaaS。在本章中，我们将使用 Dokku 设置我们自己的 PaaS。本书中我们将讨论的最后一件事是使用 CoreOS 和 Fleet 部署高可用服务。

简而言之，在我们旅程的最后一段，我们将讨论以下主题：

+   使用 Docker 与 Chef 和 Puppet

+   设置一个 apt-cacher

+   设置您自己的 mini-Heroku

+   设置一个高可用的服务

# 使用 Docker 与 Chef 和 Puppet

当企业开始进入云时，扩展变得更加容易，因为可以从一台单机扩展到数百台而不费吹灰之力。但这也意味着需要配置和维护这些机器。配置管理工具，如 Chef 和 Puppet，是为了自动部署公共/私有云中的应用而产生的需求。如今，Chef 和 Puppet 每天都被全球各地的初创公司和企业用来管理他们的云环境。

## 使用 Docker 与 Chef

Chef 的网站上写着：

> *"Chef 将基础设施转化为代码。使用 Chef，您可以自动化构建、部署和管理基础设施。您的基础设施变得像应用代码一样可版本化、可测试和可重复。"*

现在，假设您已经设置好了 Chef，并熟悉了 Chef 的工作流程，让我们看看如何使用 chef-docker 食谱在 Chef 中使用 Docker。

您可以使用任何食谱依赖管理器安装此食谱。有关 Berkshelf、Librarian 和 Knife 的安装说明可在该食谱的 Chef 社区网站上找到（[`supermarket.getchef.com/cookbooks/docker`](https://supermarket.getchef.com/cookbooks/docker)）。

### 安装和配置 Docker

安装 Docker 很简单。只需将`recipe[docker]`命令添加到运行列表（配置设置列表）即可。举个例子，让我们看看如何编写一个 Chef 配方来在 Docker 上运行`code.it`文件（我们的示例项目）。

### 编写一个 Chef 配方，在 Docker 上运行 Code.it

以下 Chef 配方基于`code.it`启动一个容器：

```
# Include Docker recipe
include_recipe 'docker'

# Pull latest image
docker_image 'shrikrishna/code.it'

# Run container exposing ports
docker_container 'shrikrishna/code.it' do
  detach true
  port '80:8000'
  env 'NODE_PORT=8000'
  volume '/var/log/code.it:/var/log/code.it'
end
```

第一个非注释语句包括 Chef-Docker 配方。`docker_image 'shrikrishna/code.it'`语句相当于在控制台中运行`$ docker pull shrikrishna/code.it`命令。配方末尾的语句块相当于运行`$ docker run --d -p '8000:8000' -e 'NODE_PORT=8000' -v '/var/log/code.it:/var/log/code.it' shrikrishna/code.it`命令。

## 使用 Docker 与 Puppet

PuppetLabs 的网站上写着：

> “Puppet 是一个配置管理系统，允许您定义 IT 基础架构的状态，然后自动强制执行正确的状态。无论您是管理几台服务器还是成千上万台物理和虚拟机，Puppet 都会自动化系统管理员经常手动执行的任务，从而节省时间和精力，使系统管理员可以专注于提供更大商业价值的项目。”

Puppet 的等效于 Chef cookbooks 的模块。有一个为 Docker 提供支持的模块可用。通过运行以下命令来安装它：

```
$ puppet module install garethr-docker

```

### 编写一个 Puppet 清单来在 Docker 上运行 Code.it

以下 Puppet 清单启动了一个`code.it`容器：

```
# Installation
include 'docker'

# Download image
docker::image {'shrikrishna/code.it':}

# Run a container
docker::run { 'code.it-puppet':
  image   => 'shrikrishna/code.it',
  command => 'node /srv/app.js',
  ports   => '8000',
  volumes => '/var/log/code.it'
}
```

第一个非注释语句包括`docker`模块。`docker::image {'shrikrishna/code.it':}`语句相当于在控制台中运行`$ docker pull shrikrishna/code.it`命令。在配方末尾的语句块相当于运行`$ docker run --d -p '8000:8000' -e 'NODE_PORT=8000' -v '/var/log/code.it:/var/log/code.it' shrikrishna/code.it node /srv/app.js`命令。

# 设置 apt-cacher

当您有多个 Docker 服务器，或者当您正在构建多个不相关的 Docker 镜像时，您可能会发现每次都必须下载软件包。这可以通过在服务器和客户端之间设置缓存代理来防止。它在您安装软件包时缓存软件包。如果您尝试安装已经缓存的软件包，它将从代理服务器本身提供，从而减少获取软件包的延迟，大大加快构建过程。

让我们编写一个 Dockerfile 来设置一个 apt 缓存服务器作为缓存代理服务器：

```
FROM        ubuntu

VOLUME      ["/var/cache/apt-cacher-ng"]
RUN       apt-get update ; apt-get install -yq apt-cacher-ng

EXPOSE      3142
RUN     echo "chmod 777 /var/cache/apt-cacher-ng ;" + "/etc/init.d/apt-cacher-ng start ;" + "tail -f /var/log/apt-cacher-ng/*" >> /init.sh
CMD     ["/bin/bash", "/init.sh"]
```

这个 Dockerfile 在镜像中安装了`apt-cacher-ng`软件包，并暴露端口`3142`（供目标容器使用）。

使用此命令构建镜像：

```
$ sudo docker build -t shrikrishna/apt_cacher_ng

```

然后运行它，绑定暴露的端口：

```
$ sudo docker run -d -p 3142:3142 --name apt_cacher shrikrishna/apt_cacher_ng

```

要查看日志，请运行以下命令：

```
$ sudo docker logs -f apt_cacher

```

## 在构建 Dockerfiles 时使用 apt-cacher

所以我们已经设置了一个 apt-cacher。现在我们必须在我们的 Dockerfiles 中使用它：

```
FROM ubuntu
RUN  echo 'Acquire::http { Proxy "http://<host's-docker0-ip- here>:3142"; };' >> /etc/apt/apt.conf.d/01proxy

```

在第二条指令中，用您的 Docker 主机的 IP 地址（在`docker0`接口处）替换`<host's-docker0-ip-here>`命令。在构建这个 Dockerfile 时，如果遇到任何已经安装过的软件包的`apt-get install`安装命令（无论是为了这个镜像还是其他镜像），它将从本地代理服务器获取软件包，从而加快构建过程中的软件包安装速度。如果要安装的软件包不在缓存中，则从 Canonical 仓库获取并保存在缓存中。

### 提示

apt-cacher 只对使用 Apt 软件包管理工具的基于 Debian 的容器（如 Ubuntu）有效。

# 设置您自己的迷你 Heroku

现在让我们做一些酷炫的事情。对于初学者来说，Heroku 是一个云 PaaS，这意味着您在构建应用程序时只需要将其推送到 Heroku，它就会部署在[`www.herokuapp.com`](https://www.herokuapp.com)上。您不需要担心应用程序运行的方式或位置。只要 PaaS 支持您的技术栈，您就可以在本地开发并将应用程序推送到服务上，让其在公共互联网上实时运行。

除了 Heroku 之外，还有许多 PaaS 提供商。一些流行的提供商包括 Google App Engine、Red Hat Cloud 和 Cloud Foundry。Docker 是由一个这样的 PaaS 提供商 dotCloud 开发的。几乎每个 PaaS 都通过在预定义的沙盒环境中运行应用程序来工作，而这正是 Docker 擅长的。如今，Docker 已经使得设置 PaaS 变得更加容易，如果不是简单的话。证明这一点的项目是 Dokku。Dokku 与 Heroku 共享使用模式和术语（如`buildpacks`、`slug` `builder`脚本），这使得它更容易使用。在本节中，我们将使用 Dokku 设置一个迷你 PaaS，并推送我们的`code.it`应用程序。

### 注意

接下来的步骤应该在虚拟专用服务器（VPS）或虚拟机上完成。您正在使用的主机应该已经设置好了 git 和 SSH。

## 使用 bootstrapper 脚本安装 Dokku

有一个`bootstrapper`脚本可以设置 Dokku。在 VPS/虚拟机内运行此命令：

```
$ wget -qO- https://raw.github.com/progrium/dokku/v0.2.3/bootstrap.sh | sudo DOKKU_TAG=v0.2.3 bash

```

### 注意

12.04 版本的用户需要在运行上述`bootstrapper`脚本之前运行`$ apt-get install -y python-software-properties`命令。

`bootstrapper`脚本将下载所有依赖项并设置 Dokku。

## 使用 Vagrant 安装 Dokku

步骤 1：克隆 Dokku：

```
$ git clone https://github.com/progrium/dokku.git

```

步骤 2：在您的`/etc/hosts`文件中设置 SSH 主机：

```
10.0.0.2 dokku.app

```

步骤 3：在`~/.ssh/config`中设置 SSH 配置

```
Host dokku.app
Port 2222

```

步骤 4：创建虚拟机

以下是一些可选的 ENV 参数设置：

```
# - `BOX_NAME`
# - `BOX_URI`
# - `BOX_MEMORY`
# - `DOKKU_DOMAIN`
# - `DOKKU_IP`.
cd path/to/dokku
vagrant up

```

步骤 5：使用此命令复制您的 SSH 密钥：

```
$ cat ~/.ssh/id_rsa.pub | pbcopy

```

在`http://dokku.app`的 dokku-installer 中粘贴您的 SSH 密钥（指向`/etc/hosts`文件中分配的`10.0.0.2`）。在**Dokku 设置**屏幕上更改**主机名**字段为您的域名，然后选中**使用虚拟主机命名**的复选框。然后，单击**完成设置**以安装您的密钥。您将从这里被引导到应用程序部署说明。

您现在已经准备好部署应用程序或安装插件。

## 配置主机名并添加公钥

我们的 PaaS 将子域路由到使用相同名称部署的应用程序。这意味着设置了 Dokku 的机器必须对您的本地设置以及运行 Dokku 的机器可见。

设置一个通配符域，指向 Dokku 主机。运行`bootstrapper`脚本后，检查 Dokku 主机中的`/home/dokku/VHOST`文件是否设置为此域。只有当 dig 工具可以解析主机名时，它才会被创建。

在此示例中，我已将我的 Dokku 主机名设置为`dokku.app`，方法是将以下配置添加到我的本地主机的`/etc/hosts`文件中：

```
10.0.0.2 dokku.app

```

我还在本地主机的`~/.ssh/config`文件中设置了 SSH 端口转发规则：

```
Host dokku.app
Port 2222

```

### 注意

根据维基百科，**域名信息检索器**（**dig**）是一个用于查询 DNS 名称服务器的网络管理命令行工具。这意味着给定一个 URL，dig 将返回 URL 指向的服务器的 IP 地址。

如果`/home/dokku/VHOST`文件没有自动创建，您将需要手动创建它并将其设置为您喜欢的域名。如果在部署应用程序时缺少此文件，Dokku 将使用端口名称而不是子域名发布应用程序。

最后要做的事情是将您的公共`ssh`密钥上传到 Dokku 主机并将其与用户名关联起来。要这样做，请运行此命令：

```
$ cat ~/.ssh/id_rsa.pub | ssh dokku.app "sudo sshcommand acl-add dokku shrikrishna"

```

在上述命令中，将`dokku.app`名称替换为您的域名，将`shrikrishna`替换为您的名称。

太好了！现在我们已经准备好了，是时候部署我们的应用程序了。

## 部署应用程序

我们现在有了自己的 PaaS，可以在那里部署我们的应用程序。让我们在那里部署`code.it`文件。您也可以尝试在那里部署您自己的应用程序：

```
$ cd code.it
$ git remote add dokku dokku@dokku.app:codeit
$ git push dokku master
Counting objects: 456, done.
Delta compression using up to 4 threads.
Compressing objects: 100% (254/254), done.
Writing objects: 100% (456/456), 205.64 KiB, done.
Total 456 (delta 34), reused 454 (delta 12)
-----> Building codeit ...
Node.js app detected
-----> Resolving engine versions

......
......
......

-----> Application deployed:
http://codeit.dokku.app

```

就是这样！我们现在在我们的 PaaS 中有一个可用的应用程序。有关 Dokku 的更多详细信息，您可以查看其 GitHub 存储库页面[`github.com/progrium/dokku`](https://github.com/progrium/dokku)。

如果您想要一个生产就绪的 PaaS，您必须查找 Deis [`deis.io/`](http://deis.io/)，它提供多主机和多租户支持。

# 建立一个高可用的服务

虽然 Dokku 非常适合部署偶尔的副业，但对于较大的项目可能不太合适。大规模部署基本上具有以下要求：

+   **水平可扩展**：单个服务器实例只能做这么多。随着负载的增加，处于快速增长曲线上的组织将发现自己必须在一组服务器之间平衡负载。在早期，这意味着必须设计数据中心。今天，这意味着向云中添加更多实例。

+   **容错**：即使有广泛的交通规则来避免交通事故，事故也可能发生，但即使您采取了广泛的措施来防止事故，一个实例的崩溃也不应该导致服务停机。良好设计的架构将处理故障条件，并使另一个服务器可用以取代崩溃的服务器。

+   **模块化**：虽然这可能看起来不是这样，但模块化是大规模部署的一个定义特征。模块化架构使其灵活且具有未来可塑性（因为模块化架构将随着组织的范围和影响力的增长而容纳新的组件）。

这绝不是一个详尽的清单，但它标志着构建和部署高可用服务所需的努力。然而，正如我们到目前为止所看到的，Docker 仅用于单个主机，并且（直到现在）没有可用于管理运行 Docker 的一组实例的工具。

这就是 CoreOS 的用武之地。它是一个精简的操作系统，旨在成为 Docker 大规模部署服务的构建模块。它配备了一个高可用的键值配置存储，称为`etcd`，用于配置管理和服务发现（发现集群中其他组件的位置）。`etcd`服务在第四章中进行了探讨，*自动化和最佳实践*。它还配备了 fleet，这是一个利用`etcd`提供的一种在整个集群上执行操作的工具，而不是在单个实例上执行操作。

### 注意

您可以将 fleet 视为在集群级别而不是机器级别运行的`systemd`套件的扩展。`systemd`套件是单机初始化系统，而 fleet 是集群初始化系统。您可以在[`coreos.com/using-coreos/clustering/`](https://coreos.com/using-coreos/clustering/)了解更多关于 fleet 的信息。

在本节中，我们将尝试在本地主机上的三节点 CoreOS 集群上部署我们的标准示例`code.it`。这是一个代表性的示例，实际的多主机部署将需要更多的工作，但这是一个很好的起点。这也帮助我们欣赏多年来在硬件和软件方面所做的伟大工作，使得部署高可用服务成为可能，甚至变得容易，而这在几年前只有在大型数据中心才可能。

## 安装依赖项

运行上述示例需要以下依赖项：

1.  **VirtualBox**：VirtualBox 是一种流行的虚拟机管理软件。您可以从[`www.virtualbox.org/wiki/Downloads`](https://www.virtualbox.org/wiki/Downloads)下载适用于您平台的安装可执行文件。

1.  **Vagrant**：Vagrant 是一个开源工具，可以被视为 Docker 的虚拟机等效物。它可以从[`www.vagrantup.com/downloads.html`](https://www.vagrantup.com/downloads.html)下载。

1.  **Fleetctl**：Fleet 简而言之是一个分布式初始化系统，这意味着它将允许我们在集群级别管理服务。Fleetctl 是一个 CLI 客户端，用于运行 fleet 命令。要安装 fleetctl，请运行以下命令：

```
$ wget \ https://github.com/coreos/fleet/releases/download/v0.3.2/fleet -v0.3.2-darwin-amd64.zip && unzip fleet-v0.3.2-darwin-amd64.zip
$ sudo cp fleet-v0.3.2-darwin-amd64/fleetctl /usr/local/bin/

```

## 获取并配置 Vagrantfile

Vagrantfiles 是 Dockerfiles 的 Vagrant 等价物。Vagrantfile 包含诸如获取基本虚拟机、运行设置命令、启动虚拟机镜像实例数量等详细信息。CoreOS 有一个包含 Vagrantfile 的存储库，可用于下载和在虚拟机中使用 CoreOS。这是在开发环境中尝试 CoreOS 功能的理想方式：

```
$ git clone https://github.com/coreos/coreos-vagrant/
$ cd coreos-vagrant

```

上述命令克隆了包含 Vagrantfile 的`coreos-vagrant`存储库，该文件下载并启动基于 CoreOS 的虚拟机。

### 注意

Vagrant 是一款免费开源软件，用于创建和配置虚拟开发环境。它可以被视为围绕虚拟化软件（如 VirtualBox、KVM 或 VMware）和配置管理软件（如 Chef、Salt 或 Puppet）的包装器。您可以从[`www.vagrantup.com/downloads.html`](https://www.vagrantup.com/downloads.html)下载 Vagrant。

不过，在启动虚拟机之前，我们需要进行一些配置。

### 获取发现令牌

每个 CoreOS 主机都运行`etcd`服务的一个实例，以协调在该机器上运行的服务，并与集群中其他机器上运行的服务进行通信。为了实现这一点，`etcd`实例本身需要相互发现。

CoreOS 团队构建了一个发现服务（[`discovery.etcd.io`](https://discovery.etcd.io)），它提供了一个免费服务，帮助`etcd`实例通过存储对等信息相互通信。它通过提供一个唯一标识集群的令牌来工作。集群中的每个`etcd`实例都使用此令牌通过发现服务识别其他`etcd`实例。生成令牌很容易，只需通过`GET`请求发送到[discovery.etcd.io/new](http://discovery.etcd.io/new)即可。

```
$ curl -s https://discovery.etcd.io/new
https://discovery.etcd.io/5cfcf52e78c320d26dcc7ca3643044ee

```

现在打开`coreos-vagrant`目录中名为`user-data.sample`的文件，并找到包含`etcd`服务下的`discovery`配置选项的注释行。取消注释并提供先前运行的`curl`命令返回的令牌。完成后，将文件重命名为`user-data`。

### 注意

`user-data`文件用于为 CoreOS 实例中的`cloud-config`程序设置配置参数。Cloud-config 受`cloud-init`项目中的`cloud-config`文件的启发，后者定义自己为处理云实例的早期初始化的事实多发行包（`cloud-init`文档）。简而言之，它有助于配置各种参数，如要打开的端口，在 CoreOS 的情况下，`etcd`配置等。您可以在以下网址找到更多信息：

[`coreos.com/docs/cluster-management/setup/cloudinit-cloud-config/`](https://coreos.com/docs/cluster-management/setup/cloudinit-cloud-config/)和[`cloudinit.readthedocs.org/en/latest/index.html`](http://cloudinit.readthedocs.org/en/latest/index.html)。

以下是 CoreOS 代码的示例：

```
coreos:
  etcd:
    # generate a new token for each unique cluster from https://discovery.etcd.io/new
    # WARNING: replace each time you 'vagrant destroy'
    discovery: https://discovery.etcd.io/5cfcf52e78c320d26dcc7ca3643044ee
    addr: $public_ipv4:4001
    peer-addr: $public_ipv4:7001
  fleet:
    public-ip: $public_ipv4
  units:
```

### 提示

每次运行集群时，您都需要生成一个新的令牌。简单地重用令牌将不起作用。

### 设置实例数量

在`coreos-vagrant`目录中，还有另一个名为`config.rb.sample`的文件。找到该文件中的注释行，其中写着`$num_instances=1`。取消注释并将值设置为`3`。这将使 Vagrant 生成三个 CoreOS 实例。现在将文件保存为`config.rb`。

### 注意

`cnfig.rb`文件保存了 Vagrant 环境的配置以及集群中的机器数量。

以下是 Vagrant 实例的代码示例：

```
# Size of the CoreOS cluster created by Vagrant
$num_instances=3
```

### 生成实例并验证健康

现在我们已经准备好配置，是时候在本地机器上看到一个运行的集群了：

```
$ vagrant up
Bringing machine 'core-01' up with 'virtualbox' provider...
Bringing machine 'core-02' up with 'virtualbox' provider...
Bringing machine 'core-03' up with 'virtualbox' provider...
==> core-01: Box 'coreos-alpha' could not be found. Attempting to find and install...
core-01: Box Provider: virtualbox
core-01: Box Version: >= 0
==> core-01: Adding box 'coreos-alpha' (v0) for provider: virtualbox
. . . . .
. . . . .
. . . . .

```

创建完机器后，您可以 SSH 登录到它们，尝试以下命令，但您需要将`ssh`密钥添加到您的 SSH 代理中。这样做将允许您将 SSH 会话转发到集群中的其他节点。要添加密钥，请运行以下命令：

```
$ ssh-add ~/.vagrant.d/insecure_private_key
Identity added: /Users/CoreOS/.vagrant.d/insecure_private_key (/Users/CoreOS/.vagrant.d/insecure_private_key)
$ vagrant ssh core-01 -- -A

```

现在让我们验证一下机器是否正常运行，并要求 fleet 列出集群中正在运行的机器：

```
$ export FLEETCTL_TUNNEL=127.0.0.1:2222
$ fleetctl list-machines
MACHINE     IP           METADATA
daacff1d... 172.17.8.101 -
20dddafc... 172.17.8.102 -
eac3271e... 172.17.8.103 -

```

### 启动服务

要在新启动的集群中运行服务，您将需要编写`unit-files`文件。单元文件是列出必须在每台机器上运行的服务以及如何管理这些服务的一些规则的配置文件。

创建三个名为`code.it.1.service`、`code.it.2.service`和`code.it.3.service`的文件。用以下配置填充它们：

`code.it.1.service`

```
[Unit]
Description=Code.it 1
Requires=docker.service  
After=docker.service

[Service]
ExecStart=/usr/bin/docker run --rm --name=code.it-1 -p 80:8000 shrikrishna/code.it
ExecStartPost=/usr/bin/etcdctl set /domains/code.it-1/%H:%i running  
ExecStop=/usr/bin/docker stop code.it-1  
ExecStopPost=/usr/bin/etcdctl rm /domains/code.it-1/%H:%i

[X-Fleet]
X-Conflicts=code.it.*.service
```

`code.it.2.service`

```
[Unit]
Description=Code.it 2  
Requires=docker.service  
After=docker.service

[Service]
ExecStart=/usr/bin/docker run --rm --name=code.it-2 -p 80:8000 shrikrishna/code.it
ExecStartPost=/usr/bin/etcdctl set /domains/code.it-2/%H:%i running  
ExecStop=/usr/bin/docker stop code.it-2  
ExecStopPost=/usr/bin/etcdctl rm /domains/code.it-2/%H:%i

[X-Fleet]
X-Conflicts=code.it.2.service
```

`code.it.3.service`

```
[Unit]
Description=Code.it 3  
Requires=docker.service  
After=docker.service

[Service]
ExecStart=/usr/bin/docker run --rm --name=code.it-3 -p 80:8000 shrikrishna/code.it
ExecStartPost=/usr/bin/etcdctl set /domains/code.it-3/%H:%i running  
ExecStop=/usr/bin/docker stop code.it-3  
ExecStopPost=/usr/bin/etcdctl rm /domains/code.it-3/%H:%i

[X-Fleet]
X-Conflicts=code.it.*.service  
```

您可能已经注意到这些文件中的模式。`ExecStart`参数保存了必须执行的命令，以启动服务。在我们的情况下，这意味着运行`code.it`容器。`ExecStartPost`是在`ExecStart`参数成功后执行的命令。在我们的情况下，服务的可用性被注册在`etcd`服务中。相反，`ExecStop`命令将停止服务，而`ExecStopPost`命令在`ExecStop`命令成功后执行，这在这种情况下意味着从`etcd`服务中删除服务的可用性。

`X-Fleet`是 CoreOS 特有的语法，告诉 fleet 两个服务不能在同一台机器上运行（因为它们在尝试绑定到相同端口时会发生冲突）。现在所有的块都就位了，是时候将作业提交到集群了：

```
$ fleetctl submit code.it.1.service code.it.2.service code.it.3.service

```

让我们验证服务是否已提交到集群：

```
$ fleetctl list-units
UNIT              LOAD  ACTIVE  SUB  DESC                 MACHINE
code.it.1.service  -     -       -   Code.it 1  -
code.it.2.service  -     -       -   Code.it 2  -
code.it.3.service  -     -       -   Code.it 3  -

```

机器列为空，活动状态未设置。这意味着我们的服务尚未启动。让我们启动它们：

```
$ fleetctl start code.it.{1,2,3}.service
Job code.it.1.service scheduled to daacff1d.../172.17.8.101
Job code.it.1.service scheduled to 20dddafc.../172.17.8.102
Job code.it.1.service scheduled to eac3271e.../172.17.8.103

```

让我们通过再次执行`$ fleetctl list-units`文件来验证它们是否正在运行：

```
$ fleetctl list-units
UNIT               LOAD    ACTIVE   SUB     DESC                     MACHINE
code.it.1.service  loaded  active  running  Code.it 1 daacff1d.../172.17.8.101
code.it.1.service  loaded  active  running  Code.it 2 20dddafc.../172.17.8.102
code.it.1.service  loaded  active  running  Code.it 3 eac3271e.../172.17.8.103

```

恭喜！您刚刚建立了自己的集群！现在在 Web 浏览器中转到`172.17.8.101`、`172.17.8.102`或`172.17.8.103`，看看`code.it`应用程序正在运行！

在这个例子中，我们只是建立了一个运行高可用服务的机器集群。如果我们添加一个负载均衡器，它与`etcd`服务保持连接，将请求路由到可用的机器，我们将在我们的系统中运行一个完整的端到端生产级服务。但这样做会偏离主题，所以留给你作为练习。

通过这个，我们来到了尽头。Docker 仍在积极发展，像 CoreOS、Deis、Flynn 等项目也是如此。因此，尽管我们在过去几个月看到了很棒的东西，但即将到来的将会更好。我们生活在激动人心的时代。因此，让我们充分利用它，构建能让这个世界变得更美好的东西。祝愉快！

# 总结

在本章中，我们学习了如何使用 Docker 与 Chef 和 Puppet。然后我们设置了一个 apt-cacher 来加快软件包的下载速度。接下来，我们用 Dokku 搭建了自己的迷你 PaaS。最后，我们使用 CoreOS 和 Fleet 搭建了一个高可用性的服务。恭喜！我们一起获得了使用 Docker 构建容器、"dockerize"我们的应用甚至运行集群所需的知识。我们的旅程到此结束了。但是对于你，亲爱的读者，一个新的旅程刚刚开始。这本书旨在奠定基础，帮助你使用 Docker 构建下一个大事件。我祝你世界上一切成功。如果你喜欢这本书，在 Twitter 上给我发消息`@srikrishnaholla`。如果你不喜欢，也请告诉我如何改进。
