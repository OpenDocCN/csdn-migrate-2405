# Docker 网络学习手册（二）

> 原文：[`zh.annas-archive.org/md5/EA91D8E763780FFC629216A68518897B`](https://zh.annas-archive.org/md5/EA91D8E763780FFC629216A68518897B)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第五章：Docker 容器的安全性和 QoS

在本章中，我们将学习安全性是如何在容器的上下文中实现的，以及如何实施 QoS 策略以确保 CPU 和 IO 等资源按预期共享。大部分讨论将集中在这些主题在 Docker 上下文中的相关性。

在本章中，我们将涵盖以下内容：

+   文件系统限制

+   只读挂载点

+   写时复制

+   Linux 功能和 Docker

+   在 AWS ECS（EC2 容器服务）中保护容器

+   理解 Docker 安全性 I - 内核命名空间

+   理解 Docker 安全性 II - cgroups

+   使用 AppArmour 来保护 Docker 容器

+   Docker 安全基准

# 文件系统限制

在本节中，我们将研究 Docker 容器启动时的文件系统限制。下一节解释了只读挂载点和写时复制文件系统，这些文件系统被用作 Docker 容器的基础和内核对象的表示。

## 只读挂载点

Docker 需要访问文件系统，如 sysfs 和 proc，以使进程正常运行。但它不一定需要修改这些挂载点。

两个主要的只读挂载点是：

+   `/sys`

+   `/proc`

### sysfs

sysfs 文件系统加载到挂载点`/sys`中。sysfs 是一种表示内核对象、它们的属性和它们之间关系的机制。它提供了两个组件：

+   用于通过 sysfs 导出这些项目的内核编程接口

+   一个用户界面，用于查看和操作这些项目，它映射回它们所代表的内核对象

以下代码显示了挂载的挂载点：

```
{
  Source:      "sysfs",
  Destination: "/sys",
  Device:      "sysfs",
  Flags:       defaultMountFlags | syscall.MS_RDONLY,
},
```

上述代码的参考链接在[`github.com/docker/docker/blob/ecc3717cb17313186ee711e624b960b096a9334f/daemon/execdriver/native/template/default_template_linux.go`](https://github.com/docker/docker/blob/ecc3717cb17313186ee711e624b960b096a9334f/daemon/execdriver/native/template/default_template_linux.go)。

### procfs

proc 文件系统（procfs）是 Unix-like 操作系统中的一个特殊文件系统，它以分层文件样式的结构呈现有关进程和其他系统信息的信息。它加载到`/proc`中。它提供了一个更方便和标准化的方法来动态访问内核中保存的进程数据，而不是传统的跟踪方法或直接访问内核内存。它在引导时映射到名为`/proc`的挂载点：

```
{
  Source:      "proc",
  Destination: "/proc",
  Device:      "proc",
  Flags:       defaultMountFlags,
},
```

使用`/proc`的只读路径：

```
ReadonlyPaths: []string{
  "/proc/asound",
  "/proc/bus",
  "/proc/fs",
  "/proc/irq",
  "/proc/sys",
  "/proc/sysrq-trigger",
}
```

### /dev/pts

这是另一个在创建过程中作为读写挂载的挂载点。`/dev/pts`完全存在于内存中，没有任何内容存储在磁盘上，因此可以安全地以读写模式加载它。

`/dev/pts`中的条目是伪终端（简称 pty）。Unix 内核有终端的通用概念。终端提供了应用程序通过终端设备显示输出和接收输入的方式。一个进程可能有一个控制终端。对于文本模式应用程序，这是它与用户交互的方式：

```
{
  Source:      "devpts",
  Destination: "/dev/pts",
  Device:      "devpts",
  Flags:       syscall.MS_NOSUID | syscall.MS_NOEXEC,
  Data:        "newinstance,ptmxmode=0666,mode=0620,gid=5",
},
```

### /sys/fs/cgroup

这是 cgroups 实现的挂载点，并且在容器中加载为`MS_RDONLY`：

```
{
  Source:      "cgroup",
  Destination: "/sys/fs/cgroup",
  Device:      "cgroup",
  Flags:       defaultMountFlags | syscall.MS_RDONLY,
},
```

## 写时复制

Docker 使用联合文件系统，这是写时复制文件系统。这意味着容器可以使用相同的文件系统镜像作为容器的基础。当容器向镜像写入内容时，它会被写入到特定于容器的文件系统中。即使它们是从相同的文件系统镜像创建的，一个容器也不能访问另一个容器的更改。一个容器不能改变镜像内容以影响另一个容器中的进程。以下图解释了这个过程：

![写时复制](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/lrn-dkr-net/img/00041.jpeg)

# Linux 功能

1.2 版本之前的 Docker 容器可以在特权模式下获得完整的功能，或者它们可以遵循允许的功能白名单，同时放弃所有其他功能。如果使用`--privileged`标志，它将授予容器所有功能。这在生产中是不推荐的，因为它真的很不安全；它允许 Docker 作为直接主机下的进程拥有所有特权。

使用 Docker 1.2 引入了两个`docker run`标志：

+   `--cap-add`

+   `--cap-drop`

这两个标志为容器提供了细粒度的控制，例如：

+   更改 Docker 容器接口的状态：

```
docker run --cap-add=NET_ADMIN busybox sh -c "ip link eth0 down"

```

+   防止 Docker 容器中的任何 chown：

```
docker run --cap-drop=CHOWN ...

```

+   允许除`mknod`之外的所有功能：

```
docker run --cap-add=ALL --cap-drop=MKNOD ...

```

Docker 默认以受限的功能集启动容器。功能将根和非根的二进制模式转换为更精细的访问控制。例如，提供 HTTP 请求的 Web 服务器需要绑定到端口 80 进行 HTTP 和端口 443 进行 HTTPs。这些服务器不需要以根模式运行。这些服务器可以被授予`net_bind_service`功能。

在这个情境中，容器和服务器有一些不同。服务器需要以 root 模式运行一些进程。例如，ssh，cron 和网络配置来处理 dhcp 等。另一方面，容器不需要这种访问。

以下任务不需要在容器中发生：

+   ssh 访问由 Docker 主机管理

+   cron 作业应该在用户模式下运行

+   网络配置，如 ipconfig 和路由，不应该在容器内发生

我们可以安全地推断容器可能不需要 root 权限。

可以拒绝的示例如下：

+   不允许挂载操作

+   不允许访问套接字

+   阻止对文件系统操作的访问，如更改文件属性或文件所有权

+   阻止容器加载新模块

Docker 只允许以下功能：

```
Capabilities: []string{
  "CHOWN",
  "DAC_OVERRIDE",
  "FSETID",
  "FOWNER",
  "MKNOD",
  "NET_RAW",
  "SETGID",
  "SETUID",
  "SETFCAP",
  "SETPCAP",
  "NET_BIND_SERVICE",
  "SYS_CHROOT",
  "KILL",
  "AUDIT_WRITE",
},
```

对先前代码的引用在[`github.com/docker/docker/blob/master/daemon/execdriver/native/template/default_template_linux.go`](https://github.com/docker/docker/blob/master/daemon/execdriver/native/template/default_template_linux.go)。

可以在 Linux man-pages 中找到所有可用功能的完整列表([`man7.org/linux/man-pages/man7/capabilities.7.html`](http://man7.org/linux/man-pages/man7/capabilities.7.html))。

运行 Docker 容器的一个主要风险是，容器的默认功能和挂载集可能提供不完整的隔离，无论是独立使用还是与内核漏洞结合使用。

Docker 支持添加和删除功能，允许使用非默认配置文件。这可以通过删除功能或添加功能使 Docker 更安全或更不安全。用户的最佳做法是删除除了明确需要的功能之外的所有功能。

# 在 AWS ECS 中保护容器

亚马逊**EC2 容器服务**(**ECS**)提供了一个高度可扩展、高性能的容器管理服务，支持 Docker 容器。它允许您轻松地在一组托管的亚马逊 EC2 实例上运行应用程序。Amazon ECS 消除了您安装、操作和扩展自己的集群管理基础设施的需要。通过简单的 API 调用，您可以启动和停止启用 Docker 的应用程序，并查询集群的完整状态。

在以下示例中，我们将看到如何使用两个 Docker 容器部署一个安全的 Web 应用程序，一个包含一个简单的 Web 应用程序（应用程序容器），另一个包含启用了限流的反向代理（代理容器），可以用来保护 Web 应用程序。这些容器将在 Amazon EC2 实例上使用 ECS 部署。如下图所示，所有网络流量将通过限流请求的代理容器路由。此外，我们可以在代理容器上使用各种安全软件执行过滤、日志记录和入侵检测等活动。

以下是这样做的步骤：

1.  我们将从 GitHub 项目构建一个基本的 PHP Web 应用程序容器。以下步骤可以在单独的 EC2 实例或本地机器上执行：

```
$ sudo yum install -y git
$ git clone https://github.com/awslabs/ecs-demo-php-simple-app

```

1.  切换到`ecs-demo-php-simple-app`文件夹：

```
$ cd ecs-demo-php-simple-app

```

1.  我们可以检查`Dockerfile`如下，以了解它将部署的 Web 应用程序：

```
$ cat Dockerfile

```

1.  使用 Dockerfile 构建容器镜像，然后将其推送到您的 Docker Hub 帐户。 Docker Hub 帐户是必需的，因为它可以通过指定容器名称来在 Amazon ECS 服务上部署容器：

```
$ docker build -t my-dockerhub-username/amazon-ecs-sample.

```

此处构建的镜像需要将`dockerhub-username`（无空格）作为第一个参数。

下图描述了黑客无法访问 Web 应用程序，因为请求通过代理容器进行过滤并且被阻止：

![在 AWS ECS 中保护容器](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/lrn-dkr-net/img/00042.jpeg)

1.  将 Docker 镜像上传到 Docker Hub 帐户：

```
$ docker login

```

1.  检查以确保您的登录成功：

```
$ docker info

```

1.  将您的镜像推送到 Docker Hub 帐户：

```
$ docker push my-dockerhub-username/amazon-ecs-sample

```

1.  创建示例 Web 应用程序 Docker 容器后，我们将创建代理容器，如果需要，还可以包含一些与安全相关的软件，以加强安全性。我们将使用定制的 Dockerfile 创建一个新的代理 Docker 容器，然后将镜像推送到您的 Docker Hub 帐户：

```
$ mkdir proxy-container
$ cd proxy-container
$ nano Dockerfile
FROM ubuntu
RUN apt-get update && apt-get install -y nginx
COPY nginx.conf /etc/nginx/nginx.conf
RUN echo "daemon off;" >> /etc/nginx/nginx.conf
EXPOSE 80
CMD service nginx start

```

在上一个 Dockerfile 中，我们使用了一个基本的 Ubuntu 镜像，并安装了 nginx，并将其暴露在 80 端口。

1.  接下来，我们将创建一个定制的`nginx.conf`，它将覆盖默认的`nginx.conf`，以确保反向代理配置正确：

```
user www-data;
worker_processes 4;
pid /var/run/nginx.pid;

events {
 worker_connections 768;
 # multi_accept on;
}

http {
 server {
 listen           80;

 # Proxy pass to servlet container
 location / {
 proxy_pass      http://application-container:80;
 }
 }
}

```

1.  构建代理 Docker 镜像并将构建的镜像推送到 Docker Hub 帐户：

```
$ docker build -t my-dockerhub-username/proxy-image.
$ docker push my-dockerhub-username/proxy-image

```

1.  可以通过转到 AWS 管理控制台（[`aws.amazon.com/console/`](https://aws.amazon.com/console/)）来部署 ECS 容器服务。

1.  在左侧边栏中单击“任务定义”，然后单击“创建新任务定义”。

1.  给你的任务定义起一个名字，比如`SecurityApp`。

1.  接下来，单击“添加容器”，并插入推送到 Docker Hub 帐户的代理 Web 容器的名称，以及应用程序 Web 容器的名称。使用“通过 JSON 配置”选项卡查看 JSON 的内容，以查看您创建的任务定义。它应该是这样的：

```
Proxy-container:
Container Name: proxy-container
Image: username/proxy-image
Memory: 256
Port Mappings
Host port: 80
Container port: 80
Protocol: tcp
CPU: 256
Links: application-container
Application container:
Container Name: application-container
Image: username/amazon-ecs-sample
Memory: 256
CPU: 256

```

单击“创建”按钮以部署应用程序。

1.  在左侧边栏中单击“集群”。如果默认集群不存在，则创建一个。

1.  启动一个 ECS 优化的 Amazon 机器映像（AMI），确保它具有公共 IP 地址和通往互联网的路径。

1.  当您的实例正在运行时，导航到 AWS 管理控制台的 ECS 部分，然后单击“集群”，然后单击“默认”。现在，我们应该能够在“ECS 实例”选项卡下看到我们的实例。

1.  从 AWS 管理控制台选项卡的左侧导航到任务定义，然后单击“运行任务”。

1.  在下一页上，确保集群设置为“默认”，任务数为“1”，然后单击“运行任务”。

1.  进程完成后，我们可以从挂起状态到绿色运行状态看到任务的状态。

1.  单击“ECS”选项卡，我们可以看到先前创建的容器实例。单击它，我们将获得有关其公共 IP 地址的信息。通过浏览器点击此公共 IP 地址，我们将能够看到我们的示例 PHP 应用程序。

# 理解 Docker 安全性 I—内核命名空间

命名空间提供了对内核全局系统资源的包装器，并使资源对于命名空间内的进程看起来像是有一个隔离的实例。全局资源更改对于相同命名空间中的进程是可见的，但对其他进程是不可见的。容器被认为是内核命名空间的一个很好的实现。

Docker 实现了以下命名空间：

+   pid 命名空间：用于进程隔离（PID—进程 ID）

+   net 命名空间：用于管理网络接口（NET—网络）

+   IPC 命名空间：用于管理对 IPC 资源（IPC—进程间通信）的访问

+   mnt 命名空间：用于管理挂载点（MNT—挂载）

+   **uts 命名空间**：用于隔离内核和版本标识（**UTS**—**Unix Time sharing System**）

在 libcontainer 中添加命名空间支持需要在 GoLang 的系统层中添加补丁（[`codereview.appspot.com/126190043/patch/140001/150001`](https://codereview.appspot.com/126190043/patch/140001/150001)<emphsis>src/syscall/exec_linux.go</emphsis>），以便可以维护新的数据结构用于 PID、用户 UID 等。

## pid 命名空间

pid 命名空间隔离了进程 ID 号空间；不同 pid 命名空间中的进程可以拥有相同的 pid。pid 命名空间允许容器提供功能，如暂停/恢复容器中的一组进程，并在容器内部的进程保持相同的 pid 的情况下将容器迁移到新主机。

新命名空间中的 PID 从 1 开始。内核需要配置标志`CONFIG_PID_NS`才能使命名空间工作。

pid 命名空间可以嵌套。每个 pid 命名空间都有一个父命名空间，除了初始（根）pid 命名空间。pid 命名空间的父命名空间是使用 clone 或 unshare 创建命名空间的进程的 pid 命名空间。pid 命名空间形成一棵树，所有命名空间最终都可以追溯到根命名空间，如下图所示：

![pid 命名空间](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/lrn-dkr-net/img/00043.jpeg)

## net 命名空间

net 命名空间提供了与网络相关的系统资源隔离。每个网络命名空间都有自己的网络设备、IP 地址、IP 路由表、`/proc/net`目录、端口号等。

网络命名空间使容器在网络方面变得有用：每个容器可以拥有自己的（虚拟）网络设备和绑定到每个命名空间端口号空间的应用程序；主机系统中适当的路由规则可以将网络数据包定向到与特定容器关联的网络设备。使用网络命名空间需要内核配置`CONFIG_NET_NS`选项（[`lwn.net/Articles/531114/`](https://lwn.net/Articles/531114/)）。

由于每个容器都有自己的网络命名空间，基本上意味着拥有自己的网络接口和路由表，net 命名空间也被 Docker 直接利用来隔离 IP 地址、端口号等。

### 基本网络命名空间管理

通过向`clone()`系统调用传递一个标志`CLONE_NEWNET`来创建网络命名空间。不过，从命令行来看，使用 IP 网络配置工具来设置和处理网络命名空间是很方便的：

```
# ip netns add netns1

```

这个命令创建了一个名为`netns1`的新网络命名空间。当 IP 工具创建网络命名空间时，它将在`/var/run/netns`下为其创建一个绑定挂载，这样即使在其中没有运行任何进程时，命名空间也会持续存在，并且便于对命名空间本身进行操作。由于网络命名空间通常需要大量配置才能准备好使用，这个特性将受到系统管理员的赞赏。

`ip netns exec`命令可用于在命名空间内运行网络管理命令：

```
# ip netns exec netns1 ip link list
1: lo: <LOOPBACK> mtu 65536 qdisc noop state DOWN mode DEFAULT link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00

```

这个命令列出了命名空间内可见的接口。可以使用以下命令删除网络命名空间：

```
# ip netns delete netns1

```

这个命令移除了指向给定网络命名空间的绑定挂载。然而，命名空间本身将持续存在，只要其中有任何进程在其中运行。

### 网络命名空间配置

新的网络命名空间将拥有一个环回设备，但没有其他网络设备。除了环回设备外，每个网络设备（物理或虚拟接口，桥接等）只能存在于单个网络命名空间中。此外，物理设备（连接到真实硬件的设备）不能被分配到除根之外的命名空间。相反，可以创建虚拟网络设备（例如虚拟以太网或 vEth）并分配给命名空间。这些虚拟设备允许命名空间内的进程通过网络进行通信；决定它们可以与谁通信的是配置、路由等。

创建时，新命名空间中的`lo`环回设备是关闭的，因此即使是环回的`ping`也会失败。

```
# ip netns exec netns1 ping 127.0.0.1
connect: Network is unreachable

```

在前面的命令中，我们可以看到由于 Docker 容器的网络命名空间存储在单独的位置，因此需要创建到`/var/run/netns`的符号链接，可以通过以下方式完成：

```
# pid=`docker inspect -f '{{.State.Pid}}' $container_id`
# ln -s /proc/$pid/ns/net /var/run/netns/$container_id

```

在这个例子中，通过启动该接口来实现，这将允许对环回地址进行 ping。

```
# ip netns exec netns1 ip link set dev lo up
# ip netns exec netns1 ping 127.0.0.1
 PING 127.0.0.1 (127.0.0.1) 56(84) bytes of data.
64 bytes from 127.0.0.1: icmp_seq=1 ttl=64 time=0.052 ms
64 bytes from 127.0.0.1: icmp_seq=2 ttl=64 time=0.042 ms
64 bytes from 127.0.0.1: icmp_seq=3 ttl=64 time=0.044 ms
64 bytes from 127.0.0.1: icmp_seq=4 ttl=64 time=0.031 ms
64 bytes from 127.0.0.1: icmp_seq=5 ttl=64 time=0.042 ms

```

这仍然不允许`netns1`和根命名空间之间的通信。为了实现这一点，需要创建和配置虚拟以太网设备。

```
# ip link add veth0 type veth peer name veth1
# ip link set veth1 netns netns1

```

第一条命令设置了一对连接的虚拟以太网设备。发送到`veth0`的数据包将被`veth1`接收，反之亦然。第二条命令将`veth1`分配给`netns1`命名空间。

```
# ip netns exec netns1 ifconfig veth1 10.0.0.1/24 up
# ifconfig veth0 10.0.0.2/24 up

```

然后，这两条命令为这两个设备设置了 IP 地址。

```
# ping 10.0.0.1
# ip netns exec netns1 ping 10.0.0.2

```

现在可以进行双向通信，就像之前的`ping`命令所示。

如前所述，命名空间不共享路由表或防火墙规则，运行`route`和`iptables -L`在`netns1`中将证明这一点：

```
# ip netns exec netns1 route
Kernel IP routing table
Destination   Gateway    Genmask        Flags    Metric Ref    Use Iface
10.0.0.0         *      255.255.255.0     U        0  0  0       veth1

# ip netns exec netns1 iptables -L
Chain INPUT (policy ACCEPT)
target     prot opt source               destination
Chain FORWARD (policy ACCEPT)
target     prot opt source               destination
Chain OUTPUT (policy ACCEPT)
target     prot opt source               destination

```

## 用户命名空间

用户命名空间允许用户和组 ID 在命名空间内进行映射。这意味着命名空间内的进程的用户 ID 和组 ID 可以与其在命名空间外的 ID 不同。一个进程在命名空间外可以具有非零用户 ID，同时在命名空间内可以具有零用户 ID。该进程在用户命名空间外进行操作时没有特权，但在命名空间内具有 root 特权。

### 创建新的用户命名空间

通过在调用`clone()`或`unshare()`时指定`CLONE_NEWUSER`标志来创建用户命名空间：

`clone()` 允许子进程与调用进程共享其执行上下文的部分，例如内存空间、文件描述符表和信号处理程序表。

`unshare()` 允许进程（或线程）取消与其他进程（或线程）共享的执行上下文的部分。当使用`fork()`或`vfork()`创建新进程时，执行上下文的一部分，例如挂载命名空间，会隐式共享。

如前所述，Docker 容器与 LXC 容器非常相似，因为为容器单独创建了一组命名空间和控制组。每个容器都有自己的网络堆栈和命名空间。除非容器没有特权访问权限，否则不允许访问其他主机的套接字或接口。如果将主机网络模式赋予容器，那么它才能访问主机端口和 IP 地址，这可能对主机上运行的其他程序造成潜在威胁。

如下例所示，在容器中使用`host`网络模式，并且能够访问所有主机桥接设备：

```
docker run -it --net=host ubuntu /bin/bash
$ ifconfig
docker0   Link encap:Ethernet  HWaddr 02:42:1d:36:0d:0d
 inet addr:172.17.0.1  Bcast:0.0.0.0  Mask:255.255.0.0
 inet6 addr: fe80::42:1dff:fe36:d0d/64 Scope:Link
 UP BROADCAST MULTICAST  MTU:1500  Metric:1
 RX packets:24 errors:0 dropped:0 overruns:0 frame:0
 TX packets:38 errors:0 dropped:0 overruns:0 carrier:0
 collisions:0 txqueuelen:0
 RX bytes:1608 (1.6 KB)  TX bytes:5800 (5.8 KB)

eno16777736 Link encap:Ethernet  HWaddr 00:0c:29:02:b9:13
 inet addr:192.168.218.129  Bcast:192.168.218.255  Mask:255.255.255.0
 inet6 addr: fe80::20c:29ff:fe02:b913/64 Scope:Link
 UP BROADCAST RUNNING MULTICAST  MTU:1500  Metric:1
 RX packets:4934 errors:0 dropped:0 overruns:0 frame:0
 TX packets:4544 errors:0 dropped:0 overruns:0 carrier:0
 collisions:0 txqueuelen:1000
 RX bytes:2909561 (2.9 MB)  TX bytes:577079 (577.0 KB)

$ docker ps -q | xargs docker inspect --format '{{ .Id }}: NetworkMode={{ .HostConfig.NetworkMode }}'
52afb14d08b9271bd96045bebd508325a2adff98dbef8c10c63294989441954d: NetworkMode=host

```

在审核过程中，应该检查所有容器，默认情况下网络模式是否设置为`default`而不是`host`：

```
$ docker ps -q | xargs docker inspect --format '{{ .Id }}: NetworkMode={{ .HostConfig.NetworkMode }}'
1aca7fe47882da0952702c383815fc650f24da2c94029b5ad8af165239b78968: NetworkMode=default

```

每个 Docker 容器都连接到以太网桥，以便在容器之间提供互连性。它们可以相互 ping 以发送/接收 UDP 数据包并建立 TCP 连接，但如果有必要，可以进行限制。命名空间还提供了一种简单的隔离，限制了在其他容器中运行的进程以及主机的访问。

我们将使用以下`nsenter`命令行实用程序进入命名空间。它是 GitHub 上的一个开源项目，可在[`github.com/jpetazzo/nsenter`](https://github.com/jpetazzo/nsenter)上找到。

使用它，我们将尝试进入现有容器的命名空间，或者尝试生成一组新的命名空间。它与 Docker `exec`命令不同，因为`nsenter`不会进入 cgroups，这可以通过使用命名空间来逃避资源限制，从而为调试和外部审计带来潜在好处。

我们可以从 PyPI 安装`nsenter`（它需要 Python 3.4），并使用命令行实用程序连接到正在运行的容器：

```
$ pip install nsenter

```

使用以下命令替换 pid 为容器的 pid：

```
$ sudo nsenter --net --target=PID /bin/ip a
1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default
 link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
 inet 127.0.0.1/8 scope host lo
 valid_lft forever preferred_lft forever
 inet6 ::1/128 scope host
 valid_lft forever preferred_lft forever
14: eth0: <BROADCAST,UP,LOWER_UP> mtu 1500 qdisc noqueue state UP group default
 link/ether 02:42:ac:11:00:06 brd ff:ff:ff:ff:ff:ff
 inet 172.17.0.6/16 scope global eth0
 valid_lft forever preferred_lft forever
 inet6 fe80::42:acff:fe11:6/64 scope link
 valid_lft forever preferred_lft forever

```

我们可以使用`docker inspect`命令使其更加方便：

1.  首先启动一个新的 nginx 服务器：

```
$ docker run -d --name=nginx -t nginx

```

1.  然后获取容器的 pid：

```
PID=$(docker inspect --format {{.State.Pid}} nginx)

```

1.  连接到正在运行的 nginx 容器：

```
$ nsenter --target $PID --uts --ipc --net –pid

```

`docker-enter`也是可以用来进入容器并指定 shell 命令的包装器，如果没有指定命令，将调用一个 shell。如果需要在不执行其他命令行工具的情况下检查或操作容器，可以使用上下文管理器来实现：

```
import subprocess
from nsenter import Namespace
with Namespace(mypid, 'net'):
# output network interfaces as seen from within the mypid's net NS:
 subprocess.check_output(['ip', 'a'])

```

# 理解 Docker 安全 II - cgroups

在本节中，我们将看看 cgroups 如何构成容器隔离的基础。

## 定义 cgroups

控制组提供了一种将任务（进程）及其所有未来的子任务聚合/分区到分层组中的机制。

cgroup 将一组任务与子系统的参数关联起来。子系统本身是用于定义 cgroups 边界或为资源提供的资源控制器。

层次结构是一组以树状排列的 cgroups，系统中的每个任务都恰好位于层次结构中的一个 cgroup 中，并且一组子系统。

## 为什么需要 cgroups？

Linux 内核中有多个努力提供进程聚合，主要用于资源跟踪目的。

这些努力包括 cpusets、CKRM/ResGroups、UserBeanCounters 和虚拟服务器命名空间。所有这些都需要基本的进程分组/分区概念，新分叉的进程最终进入与其父进程相同的组（cgroup）。

内核 cgroup 补丁提供了必要的内核机制，以有效地实现这些组。它对系统快速路径的影响很小，并为特定子系统提供了钩子，例如 cpusets，以提供所需的附加行为。

## 手动创建一个 cgroup

在以下步骤中，我们将创建一个`cpuset`控制组：

```
# mount -t tmpfs cgroup_root /sys/fs/cgroup

```

`tmpfs`是一种将所有文件保存在虚拟内存中的文件系统。`tmpfs`中的所有内容都是临时的，即不会在硬盘上创建任何文件。如果卸载`tmpfs`实例，则其中存储的所有内容都会丢失：

```
# mkdir /sys/fs/cgroup/cpuset
# mount -t cgroup -ocpuset cpuset /sys/fs/cgroup/cpuset
# cd /sys/fs/cgroup/cpuset
# mkdir Charlie
# cd Charlie
# ls
cgroup.clone_children  cpuset.cpu_exclusive  cpuset.mem_hardwall     cpuset.memory_spread_page  cpuset.sched_load_balance  tasks
cgroup.event_control   cpuset.cpus           cpuset.memory_migrate   cpuset.memory_spread_slab  cpuset.sched_relax_domain_level
cgroup.procs           cpuset.mem_exclusive  cpuset.memory_pressure  cpuset.mems                notify_on_release

```

为此 cgroup 分配 CPU 和内存限制：

```
# /bin/echo 2-3 > cpuset.cpus
# /bin/echo 0 > cpuset.mems
# /bin/echo $$ > tasks

```

以下命令显示`/Charlie`作为 cpuset cgroup： 

```
# cat /proc/self/cgroup
11:name=systemd:/user/1000.user/c2.session
10:hugetlb:/user/1000.user/c2.session
9:perf_event:/user/1000.user/c2.session
8:blkio:/user/1000.user/c2.session
7:freezer:/user/1000.user/c2.session
6:devices:/user/1000.user/c2.session
5:memory:/user/1000.user/c2.session
4:cpuacct:/user/1000.user/c2.session
3:cpu:/user/1000.user/c2.session
2:cpuset:/Charlie

```

## 将进程附加到 cgroups

将进程 ID`PID{X}`添加到任务文件中，如下所示：

```
# /bin/echo PID > tasks

```

请注意，这是`PID`，而不是 PIDs。

您一次只能附加一个任务。如果有多个任务要附加，您必须一个接一个地执行：

```
# /bin/echo PID1 > tasks
# /bin/echo PID2 > tasks
...
# /bin/echo PIDn > tasks

```

通过回显`0`将当前 shell 任务附加：

```
# echo 0 > tasks

```

## Docker 和 cgroups

cgroups 作为 Docker 的 GitHub 存储库（[`github.com/opencontainers/runc/tree/master/libcontainer/cgroups`](https://github.com/opencontainers/runc/tree/master/libcontainer/cgroups)）下的 libcontainer 项目的一部分进行管理。有一个 cgroup 管理器，负责与内核中的 cgroup API 进行交互。

以下代码显示了管理器管理的生命周期事件：

```
type Manager interface {
 // Apply cgroup configuration to the process with the specified pid
 Apply(pid int) error
 // Returns the PIDs inside the cgroup set
 GetPids() ([]int, error)
 // Returns statistics for the cgroup set
 GetStats() (*Stats, error)
 // Toggles the freezer cgroup according with specified state
 Freeze(state configs.FreezerState) error
 // Destroys the cgroup set
 Destroy() error
 // Paths maps cgroup subsystem to path at which it is mounted.
 // Cgroups specifies specific cgroup settings for the various subsystems
 // Returns cgroup paths to save in a state file and to be able to
 // restore the object later.
 GetPaths() map[string]string
 // Set the cgroup as configured.
 Set(container *configs.Config) error
}

```

# 使用 AppArmor 保护 Docker 容器

AppArmor 是一种**强制访问控制**（**MAC**）系统，是内核增强功能，用于将程序限制在有限的资源集合中。AppArmor 的安全模型是将访问控制属性绑定到程序，而不是用户。

AppArmor 约束是通过加载到内核中的配置文件提供的，通常在启动时加载。AppArmor 配置文件可以处于两种模式之一：强制执行或投诉。

以强制执行模式加载的配置文件将导致强制执行配置文件中定义的策略，并报告策略违规尝试（通过 syslog 或 auditd）。

投诉模式下的配置文件不会强制执行策略，而是报告策略违规尝试。

AppArmor 与 Linux 上的其他一些 MAC 系统不同：它是基于路径的，允许混合强制和投诉模式配置文件，使用包含文件来简化开发，并且比其他流行的 MAC 系统具有更低的入门门槛。以下图显示了与应用程序相关联的 AppArmour 应用程序配置文件：

![使用 AppArmor 保护 Docker 容器](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/lrn-dkr-net/img/00044.jpeg)

AppArmor 是一项成熟的技术，最初出现在 Immunix 中，后来集成到 Ubuntu、Novell/SUSE 和 Mandriva 中。核心 AppArmor 功能从 Linux 内核 2.6.36 版本开始就已经在主线内核中；AppArmor、Ubuntu 和其他开发人员正在进行工作，将其他额外的 AppArmor 功能合并到主线内核中。

您可以在[`wiki.ubuntu.com/AppArmor`](https://wiki.ubuntu.com/AppArmor)找到有关 AppArmor 的更多信息。

## AppArmor 和 Docker

在 Docker 内运行的应用程序可以利用 AppArmor 来定义策略。这些配置文件可以手动创建，也可以使用一个名为 bane 的工具加载。

### 注意

在 Ubuntu 14.x 上，确保安装了 systemd 才能使以下命令生效。

以下步骤显示了如何使用这个工具：

1.  从 GitHub 下载 bane 项目：

```
$ git clone https://github.com/jfrazelle/bane

```

确保这是在您的 GOPATH 目录中完成的。例如，我们使用了`/home/ubuntu/go`，bane 源代码下载在`/home/Ubuntu/go/src/github.com/jfrazelle/bane`。

1.  安装 bane 编译所需的 toml 解析器：

```
$ go get github.com/BurntSushi/toml

```

1.  转到`/home/Ubuntu/go/src/github.com/jfrazelle/bane`目录并运行以下命令：

```
$ go install

```

1.  您将在`/home/Ubuntu/go/bin`中找到 bane 二进制文件。

1.  使用`.toml`文件创建配置文件：

```
Name = "nginx-sample"
[Filesystem]
# read only paths for the container
ReadOnlyPaths = [
 "/bin/**",
 "/boot/**",
 "/dev/**",
 "/etc/**",
 …
]
AllowExec = [
 "/usr/sbin/nginx"
]
# denied executable files
DenyExec = [
 "/bin/dash",
 "/bin/sh",
 "/usr/bin/top"
]

```

1.  执行 bane 加载配置文件。`sample.toml`是在`/home/Ubuntu/go/src/github.com/jfrazelle/bane`目录中的文件：

```
$ sudo bane sample.toml
# Profile installed successfully you can now run the profile with # `docker run --security-opt="apparmor:docker-nginx-sample"`

```

这个配置文件将使大量路径变为只读，并且只允许在我们将要创建的容器中执行 nginx。它禁用了 TOP、PING 等。

1.  一旦配置文件加载，您就可以创建一个 nginx 容器：

```
$ docker run --security-opt="apparmor:docker-nginx-sample" -p 80:80 --rm -it nginx bash

```

注意，如果 AppArmor 无法找到文件，将文件复制到`/etc/apparmor.d`目录并重新加载 AppArmour 配置文件：

```
$ sudo invoke-rc.d apparmor reload

```

使用 AppArmor 配置文件创建 nginx 容器：

```
ubuntu@ubuntu:~/go/src/github.com$ docker run --security-opt="apparmor:docker-nginx-sample" -p 80:80 --rm -it nginx bash
root@84d617972e04:/# ping 8.8.8.8
ping: Lacking privilege for raw socket.

```

以下图显示了容器中运行的 nginx 应用程序如何使用 AppArmour 应用程序配置文件：

![AppArmor and Docker](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/lrn-dkr-net/img/00045.jpeg)

## Docker 安全基准

以下教程展示了一些重要的准则，应遵循以在安全和生产环境中运行 Docker 容器。这是从 CIS Docker 安全基准[`benchmarks.cisecurity.org/tools2/docker/CIS_Docker_1.6_Benchmark_v1.0.0.pdf`](https://benchmarks.cisecurity.org/tools2/docker/CIS_Docker_1.6_Benchmark_v1.0.0.pdf)中引用的。

### 定期审计 Docker 守护程序

除了审计常规的 Linux 文件系统和系统调用外，还要审计 Docker 守护程序。Docker 守护程序以 root 权限运行。因此，有必要审计其活动和使用情况：

```
$ apt-get install auditd
Reading package lists... Done
Building dependency tree
Reading state information... Done
The following extra packages will be installed:
 libauparse0
Suggested packages:
 audispd-plugins
The following NEW packages will be installed:
 auditd libauparse0
0 upgraded, 2 newly installed, 0 to remove and 50 not upgraded.
Processing triggers for libc-bin (2.21-0ubuntu4) ...
Processing triggers for ureadahead (0.100.0-19) ...
Processing triggers for systemd (225-1ubuntu9) ...

```

如果存在审计日志文件，则删除：

```
$ cd /etc/audit/
$ ls
audit.log
$ nano audit.log
$ rm -rf audit.log

```

为 Docker 服务添加审计规则并审计 Docker 服务：

```
$ nano audit.rules
-w /usr/bin/docker -k docker
$ service auditd restart
$ ausearch -k docker
<no matches>
$ docker ps
CONTAINER ID    IMAGE      COMMAND    CREATED    STATUS   PORTS     NAMES
$ ausearch -k docker
----
time->Fri Nov 27 02:29:50 2015
type=PROCTITLE msg=audit(1448620190.716:79): proctitle=646F636B6572007073
type=PATH msg=audit(1448620190.716:79): item=1 name="/lib64/ld-linux-x86-64.so.2" inode=398512 dev=08:01 mode=0100755 ouid=0 ogid=0 rdev=00:00 nametype=NORMAL
type=PATH msg=audit(1448620190.716:79): item=0 name="/usr/bin/docker" inode=941134 dev=08:01 mode=0100755 ouid=0 ogid=0 rdev=00:00 nametype=NORMAL
type=CWD msg=audit(1448620190.716:79):  cwd="/etc/audit"
type=EXECVE msg=audit(1448620190.716:79): argc=2 a0="docker" a1="ps"
type=SYSCALL msg=audit(1448620190.716:79): arch=c000003e syscall=59 success=yes exit=0 a0=ca1208 a1=c958c8 a2=c8

```

### 为容器创建一个用户

目前，Docker 不支持将容器的 root 用户映射到主机上的非 root 用户。用户命名空间的支持将在未来版本中提供。这会导致严重的用户隔离问题。因此，强烈建议确保为容器创建一个非 root 用户，并使用该用户运行容器。

如我们在以下片段中所见，默认情况下，`centos` Docker 镜像的`user`字段为空，这意味着默认情况下容器在运行时将获得 root 用户，这应该避免：

```
$ docker inspect centos
[
 {
 "Id": "e9fa5d3a0d0e19519e66af2dd8ad6903a7288de0e995b6eafbcb38aebf2b606d",
 "RepoTags": [
 "centos:latest"
 ],
 "RepoDigests": [],
 "Parent": "c9853740aa059d078b868c4a91a069a0975fb2652e94cc1e237ef9b961afa572",
 "Comment": "",
 "Created": "2015-10-13T23:29:04.138328589Z",
 "Container": "eaa200e2e187340f0707085b9b4eab5658b13fd190af68c71a60f6283578172f",
 "ContainerConfig": {
 "Hostname": "7aa5783a47d5",
 "Domainname": "",
 "User": "",
 contd

```

在构建 Docker 镜像时，可以在 Dockerfile 中提供`test`用户，即权限较低的用户，如以下片段所示：

```
$ cd
$ mkdir test-container
$ cd test-container/
$ cat Dockerfile
FROM centos:latest
RUN useradd test
USER test
root@ubuntu:~/test-container# docker build -t vkohli .
Sending build context to Docker daemon 2.048 kB
Step 1 : FROM centos:latest
 ---> e9fa5d3a0d0e
Step 2 : RUN useradd test
 ---> Running in 0c726d186658
 ---> 12041ebdfd3f
Removing intermediate container 0c726d186658
Step 3 : USER test
 ---> Running in 86c5e0599c72
 ---> af4ba8a0fec5
Removing intermediate container 86c5e0599c72
Successfully built af4ba8a0fec5
$ docker images | grep vkohli
vkohli    latest     af4ba8a0fec5      9 seconds ago     172.6 MB

```

当我们启动 Docker 容器时，可以看到它获得了一个`test`用户，而`docker inspect`命令也显示默认用户为`test`：

```
$ docker run -it vkohli /bin/bash
[test@2ff11ee54c5f /]$ whoami
test
[test@2ff11ee54c5f /]$ exit
$ docker inspect vkohli
[
 {
 "Id": "af4ba8a0fec558d68b4873e2a1a6d8a5ca05797e0bfbab0772bcedced15683ea",
 "RepoTags": [
 "vkohli:latest"
 ],
 "RepoDigests": [],
 "Parent": "12041ebdfd3f38df3397a8961f82c225bddc56588e348761d3e252eec868d129",
 "Comment": "",
 "Created": "2015-11-27T14:10:49.206969614Z",
 "Container": "86c5e0599c72285983f3c5511fdec940f70cde171f1bfb53fab08854fe6d7b12",
 "ContainerConfig": {
 "Hostname": "7aa5783a47d5",
 "Domainname": "",
 "User": "test",
 Contd..

```

### 不要在容器上挂载敏感主机系统目录

如果敏感目录以读写模式挂载，可能会对这些敏感目录内的文件进行更改。这些更改可能带来安全隐患或不必要的更改，可能使 Docker 主机处于受损状态。

如果在容器中挂载了`/run/systemd`敏感目录，那么我们实际上可以从容器本身关闭主机：

```
$ docker run -ti -v /run/systemd:/run/systemd centos /bin/bash
[root@1aca7fe47882 /]# systemctl status docker
docker.service - Docker Application Container Engine
 Loaded: loaded (/lib/systemd/system/docker.service; enabled)
 Active: active (running) since Sun 2015-11-29 12:22:50 UTC; 21min ago
 Docs: https://docs.docker.com
 Main PID: 758
 CGroup: /system.slice/docker.service
[root@1aca7fe47882 /]# shutdown

```

可以通过使用以下命令进行审计，该命令返回当前映射目录的列表以及每个容器实例是否以读写模式挂载：

```
$ docker ps -q | xargs docker inspect --format '{{ .Id }}: Volumes={{ .Volumes }} VolumesRW={{ .VolumesRW }}'

```

### 不要使用特权容器

Docker 支持添加和删除功能，允许使用非默认配置文件。这可能通过删除功能使 Docker 更安全，或者通过添加功能使其不太安全。因此建议除了容器进程明确需要的功能外，删除所有功能。

正如下所示，当我们在不使用特权模式的情况下运行容器时，我们无法更改内核参数，但是当我们使用`--privileged`标志在特权模式下运行容器时，可以轻松更改内核参数，这可能会导致安全漏洞。

```
$ docker run -it centos /bin/bash
[root@7e1b1fa4fb89 /]#  sysctl -w net.ipv4.ip_forward=0
sysctl: setting key "net.ipv4.ip_forward": Read-only file system
$ docker run --privileged -it centos /bin/bash
[root@930aaa93b4e4 /]#  sysctl -a | wc -l
sysctl: reading key "net.ipv6.conf.all.stable_secret"
sysctl: reading key "net.ipv6.conf.default.stable_secret"
sysctl: reading key "net.ipv6.conf.eth0.stable_secret"
sysctl: reading key "net.ipv6.conf.lo.stable_secret"
638
[root@930aaa93b4e4 /]# sysctl -w net.ipv4.ip_forward=0
net.ipv4.ip_forward = 0

```

因此，在审核时，必须确保所有容器的特权模式未设置为`true`。

```
$ docker ps -q | xargs docker inspect --format '{{ .Id }}: Privileged={{ .HostConfig.Privileged }}'
930aaa93b4e44c0f647b53b3e934ce162fbd9ef1fd4ec82b826f55357f6fdf3a: Privileged=true

```

# 总结

在本章中，我们深入探讨了 Docker 安全性，并概述了 cgroups 和内核命名空间。我们还讨论了文件系统和 Linux 功能的一些方面，容器利用这些功能来提供更多功能，例如特权容器，但代价是在威胁方面更容易暴露。我们还看到了如何在 AWS ECS（EC2 容器服务）中部署容器以在受限流量中使用代理容器来在安全环境中部署容器。AppArmor 还提供了内核增强功能，以将应用程序限制在有限的资源集上。利用它们对 Docker 容器的好处有助于在安全环境中部署它们。最后，我们快速了解了 Docker 安全基准和在生产环境中进行审核和 Docker 部署期间可以遵循的一些重要建议。

在下一章中，我们将学习使用各种工具在 Docker 网络中进行调优和故障排除。


# 第六章：Docker 的下一代网络堆栈：libnetwork

在本章中，我们将学习关于 Docker 的新网络堆栈：libnetwork，它提供了一个可插拔的架构，具有单主机和多主机虚拟网络的默认实现：

+   介绍

+   目标

+   设计

+   CNM 对象

+   CNM 属性

+   CNM 生命周期

+   驱动程序

+   桥接驱动程序

+   覆盖网络驱动程序

+   使用 Vagrant 进行覆盖网络

+   使用 Docker Machine 和 Docker Swarm 的覆盖网络

+   手动创建覆盖网络并将其用于容器

+   容器网络接口

+   Calico 的 libnetwork 驱动程序

# 目标

libnetwork 是用 go 语言编写的，是连接 Docker 容器的新方法。其目标是提供一个容器网络模型，帮助程序员并提供网络库的抽象。libnetwork 的长期目标是遵循 Docker 和 Linux 的哲学，提供独立工作的模块。libnetwork 的目标是为容器提供网络的可组合需求。它还旨在通过以下方式将 Docker Engine 和 libcontainer 中的网络逻辑模块化为单一可重用库：

+   用 libnetwork 替换 Docker Engine 的网络模块

+   作为一个允许本地和远程驱动程序为容器提供网络的模型

+   提供一个用于管理和测试 libnetwork 的工具 dnet-仍在进行中的工作（参考自[`github.com/docker/libnetwork/issues/45`](https://github.com/docker/libnetwork/issues/45)）。

# 设计

libnetwork 实现了**容器网络模型**（**CNM**）。它规范了为容器提供网络所需的步骤，同时提供了一个抽象，可用于支持多个网络驱动程序。其端点 API 主要用于管理相应的对象，并对其进行簿记，以提供 CNM 模型所需的抽象级别。

CNM 建立在三个主要组件上。下图显示了 libnetwork 的网络沙盒模型：

![设计](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/lrn-dkr-net/img/00046.jpeg)

# CNM 对象

让我们详细讨论 CNM 对象。

## 沙盒

这包含容器网络堆栈的配置，包括管理路由表、容器接口和 DNS 设置。沙箱的实现可以是 Linux 网络命名空间、FreeBSD 监狱或其他类似的概念。一个沙箱可以包含来自多个网络的许多端点。它还表示容器的网络配置，如 IP 地址、MAC 地址和 DNS 条目。libnetwork 利用特定于操作系统的参数来填充沙箱所代表的网络配置。libnetwork 提供了在多个操作系统中实现沙箱的框架。Netlink 用于管理命名空间中的路由表，目前存在两种沙箱的实现，`namespace_linux.go`和`configure_linux.go`，以唯一标识主机文件系统上的路径。

沙箱与单个 Docker 容器相关联。以下数据结构显示了沙箱的运行时元素：

```
type sandbox struct {
  id            string
  containerID   string
  config        containerConfig
  osSbox        osl.Sandbox
  controller    *controller
  refCnt        int
  endpoints     epHeap
  epPriority    map[string]int
  joinLeaveDone chan struct{}
  dbIndex       uint64
  dbExists      bool
  isStub        bool
  inDelete      bool
  sync.Mutex
}
```

新的沙箱是从网络控制器实例化的（稍后将更详细地解释）。

```
func (c *controller) NewSandbox(containerID string, options ...SandboxOption) (Sandbox, error) {
  …..
}
```

## 端点

端点将沙箱连接到网络，并为容器公开的服务提供与部署在同一网络中的其他容器的连接。它可以是 Open vSwitch 的内部端口或类似的 veth 对。一个端点只能属于一个网络，但可能只属于一个沙箱。端点代表一个服务，并提供各种 API 来创建和管理端点。它具有全局范围，但只附加到一个网络，如下图所示：

![端点](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/lrn-dkr-net/img/00047.jpeg)

端点由以下数据结构指定：

```
type endpoint struct {
  name          string
  id            string
  network       *network
  iface         *endpointInterface
  joinInfo      *endpointJoinInfo
  sandboxID     string
  exposedPorts  []types.TransportPort
  anonymous     bool
  generic       map[string]interface{}
  joinLeaveDone chan struct{}
  prefAddress   net.IP
  prefAddressV6 net.IP
  ipamOptions   map[string]string
  dbIndex       uint64
  dbExists      bool
  sync.Mutex
}
```

端点与唯一 ID 和名称相关联。它附加到网络和沙箱 ID。它还与 IPv4 和 IPv6 地址空间相关联。每个端点都与`endpointInterface`结构相关联。

## 网络

网络是能够直接相互通信的端点组。它在同一主机或多个主机之间提供所需的连接，并在创建或更新网络时通知相应的驱动程序。例如，VLAN 或 Linux 桥，在集群中具有全局范围。

网络由网络控制器控制，我们将在下一节中讨论。每个网络都有名称、地址空间、ID 和网络类型：

```
type network struct {
  ctrlr        *controller
  name         string
  networkType  string
  id           string
  ipamType     string
  addrSpace    string
  ipamV4Config []*IpamConf
  ipamV6Config []*IpamConf
  ipamV4Info   []*IpamInfo
  ipamV6Info   []*IpamInfo
  enableIPv6   bool
  postIPv6     bool
  epCnt        *endpointCnt
  generic      options.Generic
  dbIndex      uint64
  svcRecords   svcMap
  dbExists     bool
  persist      bool
  stopWatchCh  chan struct{}
  drvOnce      *sync.Once
  internal     bool
  sync.Mutex
}
```

## 网络控制器

网络控制器对象提供 API 来创建和管理网络对象。它是 libnetwork 中的入口点，通过将特定的驱动程序绑定到给定的网络，支持多个活动驱动程序，包括内置和远程驱动程序。网络控制器允许用户将特定的驱动程序绑定到给定的网络：

```
type controller struct {
  id             string
  drivers        driverTable
  ipamDrivers    ipamTable
  sandboxes      sandboxTable
  cfg            *config.Config
  stores         []datastore.DataStore
  discovery      hostdiscovery.HostDiscovery
  extKeyListener net.Listener
  watchCh        chan *endpoint
  unWatchCh      chan *endpoint
  svcDb          map[string]svcMap
  nmap           map[string]*netWatch
  defOsSbox      osl.Sandbox
  sboxOnce       sync.Once
  sync.Mutex
}
```

每个网络控制器都引用以下内容：

+   数据结构 driverTable 中有一个或多个驱动程序

+   数据结构中有一个或多个沙盒

+   数据存储库

+   ipamTable

下图显示了**网络控制器**如何位于**Docker 引擎**和其连接的容器和网络之间：

![网络控制器](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/lrn-dkr-net/img/00048.jpeg)

## CNM 属性

有两种类型的属性，如下：

+   **选项**：它们对终端用户不可见，但是提供了一种灵活的机制，可以直接从用户传递驱动程序特定的配置数据的键值对。只有当键匹配一个众所周知的标签时，libnetwork 才会处理选项，结果值被选中，这由一个通用对象表示。

+   **标签**：它们是选项的一个子集，是终端用户变量，使用`-labels`选项在 UI 中表示。它们的主要功能是执行特定于驱动程序的操作，并且它们从 UI 传递。

## CNM 生命周期

容器网络模型的消费者通过 CNM 对象及其 API 进行交互，以网络管理他们管理的容器。

驱动程序在网络控制器中注册。内置驱动程序在 libnetwork 内部注册，而远程驱动程序通过插件机制（WIP）在 libnetwork 中注册。每个驱动程序处理特定的网络类型。

使用`libnetwork.New()` API 创建一个网络控制器对象来管理网络的分配，并可选择使用特定于驱动程序的选项配置驱动程序。

使用控制器的`NewNetwork()` API 通过提供名称和`networkType`来创建网络。`networkType`参数有助于选择相应的驱动程序，并将创建的网络绑定到该驱动程序。从这一点开始，对网络的任何操作都将由该驱动程序处理。

`controller.NewNetwork()` API 还接受可选的选项参数，其中包含驱动程序特定的选项和标签，驱动程序可以用于其目的。

`network.CreateEndpoint()`可以调用以在给定网络中创建新的端点。此 API 还接受可选的选项参数，这些参数随驱动程序而异。

当在网络中创建端点时，将调用驱动程序的`driver.CreateEndpoint`，它可以选择在网络中创建端点时保留 IPv4/IPv6 地址。驱动程序将使用`driver` API 中定义的`InterfaceInfo`接口来分配这些地址。IPv4/IPv6 地址是完成端点作为服务定义所需的，以及端点公开的端口。服务端点是应用程序容器正在侦听的网络地址和端口号。

`endpoint.Join()`可用于将容器附加到端点。`Join`操作将为该容器创建一个沙盒（如果不存在）。驱动程序利用沙盒键来标识附加到同一容器的多个端点。

有一个单独的 API 用于创建端点，另一个用于加入端点。

端点表示独立于容器的服务。创建端点时，为容器保留了资源，以便稍后附加到端点。这提供了一致的网络行为。

当容器停止时，将调用`endpoint.Leave()`。驱动程序可以清理在`Join()`调用期间分配的状态。当最后一个引用端点离开网络时，libnetwork 将删除沙盒。

只要端点仍然存在，libnetwork 将继续持有 IP 地址。当容器（或任何容器）再次加入时，这些地址将被重用。这确保了在容器停止和重新启动时重用容器的资源。

`endpoint.Delete()`用于从网络中删除端点。这将导致删除端点并清理缓存的`sandbox.Info`。

`network.Delete()`用于删除网络。如果没有端点附加到网络上，则允许删除。

# 驱动程序

驱动程序拥有一个网络，并负责使网络工作并管理它。网络控制器提供了一个 API，用于使用特定标签/选项配置驱动程序，这些标签/选项对用户不可见，但对 libnetwork 透明，并且可以由驱动程序直接处理。驱动程序可以是内置的（如桥接、主机或覆盖）和远程的（来自插件提供者），可以部署在各种用例和部署场景中。

驱动程序拥有网络实现，并负责管理它，包括**IP 地址管理（IPAM）**。以下图解释了这个过程：

![Driver](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/lrn-dkr-net/img/00049.jpeg)

以下是内置驱动程序：

+   **Null**：为了与旧的`docker --net=none`向后兼容，存在这个选项，主要是在不需要网络的情况下。

+   **桥**：它提供了一个特定于 Linux 的桥接实现驱动程序。

+   **覆盖**：覆盖驱动程序实现了可以跨多个主机网络封装的网络。我们将深入研究其中两种实现：与 Consul 的基本设置和使用 Vagrant 部署覆盖驱动程序的设置。

+   **远程**：它提供了一种支持远程传输的驱动程序的手段，可以根据选择编写特定的驱动程序。

## 桥驱动程序

桥驱动程序代表了一个在 Linux 桥上充当 libcontainer 网络的包装器。它为每个创建的网络创建一个 veth 对。一个端点连接到容器，另一个端点连接到桥。以下数据结构表示了一个桥接网络：

```
type driver struct {
  config      *configuration
  etwork      *bridgeNetwork
  natChain    *iptables.ChainInfo
  filterChain *iptables.ChainInfo
  networks    map[string]*bridgeNetwork
  store       datastore.DataStore
  sync.Mutex
}
```

在桥驱动程序中执行的一些操作：

+   配置 IPTables

+   管理 IP 转发

+   管理端口映射

+   启用桥网过滤

+   在桥上设置 IPv4 和 IPv6

以下图表显示了如何使用`docker0`和`veth`对来表示网络，以连接端点和`docker0`桥：

![桥驱动程序](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/lrn-dkr-net/img/00050.jpeg)

## 覆盖网络驱动程序

libnetwork 中的覆盖网络使用 VXLan 和 Linux 桥来创建叠加的地址空间。它支持多主机网络：

```
const (
  networkType  = "overlay"
  vethPrefix   = "veth"
  vethLen      = 7
  vxlanIDStart = 256
  vxlanIDEnd   = 1000
  vxlanPort    = 4789
  vxlanVethMTU = 1450
)
type driver struct {
  eventCh      chan serf.Event
  notifyCh     chan ovNotify
  exitCh       chan chan struct{}
  bindAddress  string
  neighIP      string
  config       map[string]interface{}
  peerDb       peerNetworkMap
  serfInstance *serf.Serf
  networks     networkTable
  store        datastore.DataStore
  ipAllocator  *idm.Idm
  vxlanIdm     *idm.Idm
  once         sync.Once
  joinOnce     sync.Once
  sync.Mutex
}
```

# 使用 Vagrant 使用覆盖网络

覆盖网络是在两个容器之间创建的，VXLan 隧道通过桥接连接容器。

## 覆盖网络部署 Vagrant 设置

这个设置是使用 Docker 实验版本部署的，它会定期更新，可能不支持一些功能：

1.  克隆官方的 libnetwork 存储库，并切换到`docs`文件夹：

```
$ git clone
$ cd
 libnetwork/docs

```

1.  Vagrant 脚本已经存在于存储库中；我们将使用以下命令为我们的 Docker 覆盖网络驱动程序测试部署三节点设置：

```
$ vagrant up
Bringing machine 'consul-server' up with 'virtualbox' provider...
Bringing machine 'net-1' up with 'virtualbox' provider...
Bringing machine 'net-2' up with 'virtualbox' provider...
==> consul-server: Box 'ubuntu/trusty64' could not be found.
Attempting to find and install...
 consul-server: Box Provider: virtualbox
 consul-server: Box Version: >= 0
==> consul-server: Loading metadata for box 'ubuntu/trusty64'
 consul-server: URL: https://atlas.hashicorp.com/ubuntu/trusty64
==> consul-server: Adding box 'ubuntu/trusty64' (v20151217.0.0) for
provider: virtualbox
 consul-server: Downloading:
https://atlas.hashicorp.com/ubuntu/boxes/trusty64/versions/20151217.0.0/providers/virtualbox.box
==> consul-server: Successfully added box 'ubuntu/trusty64'
(v20151217.0.0) for 'virtualbox'!
==> consul-server: Importing base box 'ubuntu/trusty64'...
==> consul-server: Matching MAC address for NAT networking...
==> consul-server: Checking if box 'ubuntu/trusty64' is up to date...
==> consul-server: Setting the name of the VM:
libnetwork_consul-server_1451244524836_56275
==> consul-server: Clearing any previously set forwarded ports...
==> consul-server: Clearing any previously set network interfaces...
==> consul-server: Preparing network interfaces based on
configuration...
 consul-server: Adapter 1: nat
 consul-server: Adapter 2: hostonly
==> consul-server: Forwarding ports...
 consul-server: 22 => 2222 (adapter 1)
==> consul-server: Running 'pre-boot' VM customizations...
==> consul-server: Booting VM...
==> consul-server: Waiting for machine to boot. This may take a few minutes...
consul-server:
101aac79c475b84f6aff48352ead467d6b2b63ba6b64cc1b93c630489f7e3f4c
==> net-1: Box 'ubuntu/vivid64' could not be found. Attempting to find and install...
 net-1: Box Provider: virtualbox
 net-1: Box Version: >= 0
==> net-1: Loading metadata for box 'ubuntu/vivid64'
 net-1: URL: https://atlas.hashicorp.com/ubuntu/vivid64
\==> net-1: Adding box 'ubuntu/vivid64' (v20151219.0.0) for provider: virtualbox
 net-1: Downloading:
https://atlas.hashicorp.com/ubuntu/boxes/vivid64/versions/20151219.0.0/providers/virtualbox.box
contd...

```

1.  我们可以按照 Vagrant 列出已部署的机器如下：

```
$ vagrant status
Current machine states:
consul-server           running (virtualbox)
net-1                   running (virtualbox)
net-2                   running (virtualbox)
This environment represents multiple VMs. The VMs are all listed above with their current state. For more information about a specific VM, run `vagrant status NAME`.

```

1.  感谢 Vagrant 脚本，设置已经完成；现在，我们可以 SSH 到 Docker 主机并启动测试容器：

```
$ vagrant ssh net-1
Welcome to Ubuntu 15.04 (GNU/Linux 3.19.0-42-generic x86_64)
* Documentation:https://help.ubuntu.com/
System information as of Sun Dec 27 20:04:06 UTC 2015
System load:  0.0               Users logged in:       0
Usage of /:   4.5% of 38.80GB   IP address for eth0:   10.0.2.15
Memory usage: 24%               IP address for eth1:    192.168.33.11
Swap usage:   0%                IP address for docker0: 172.17.0.1
Processes:    78
Graph this data and manage this system at:  https://landscape.canonical.com/
Get cloud support with Ubuntu Advantage Cloud Guest:  http://www.ubuntu.com/business/services/cloud

```

1.  我们可以创建一个新的 Docker 容器，在容器内部我们可以列出`/etc/hosts`文件的内容，以验证它是否具有先前部署的覆盖桥规范，并且在启动时自动连接到它：

```
$ docker run -it --rm ubuntu:14.04 bash
Unable to find image 'ubuntu:14.04' locally
14.04: Pulling from library/ubuntu
6edcc89ed412: Pull complete
bdf37643ee24: Pull complete
ea0211d47051: Pull complete
a3ed95caeb02: Pull complete
Digest: sha256:d3b59c1d15c3cfb58d9f2eaab8a232f21fc670c67c11f582bc48fb32df17f3b3
Status: Downloaded newer image for ubuntu:14.04

root@65db9144c65b:/# cat /etc/hosts
172.21.0.4  2ac726b4ce60
127.0.0.1   localhost
::1 localhost ip6-localhost ip6-loopback
fe00::0 ip6-localnet
ff00::0 ip6-mcastprefix
ff02::1 ip6-allnodes
ff02::2 ip6-allrouters
172.21.0.3  distracted_bohr
172.21.0.3  distracted_bohr.multihost
172.21.0.4  modest_curie
172.21.0.4  modest_curie.multihost

```

1.  同样，我们也可以在另一个主机`net-2`中创建 Docker 容器，并验证覆盖网络驱动程序的工作，因为尽管部署在不同的主机上，但这两个容器都能够相互 ping 通。

在前面的示例中，我们使用默认选项启动了 Docker 容器，并且它们自动添加到了覆盖类型的多主机网络中。

我们还可以创建一个单独的覆盖桥，并使用`--publish-service`选项手动将容器添加到其中，该选项是 Docker 实验的一部分：

```
vagrant@net-1:~$ docker network create -d overlay tester
447e75fd19b236e72361c270b0af4402c80e1f170938fb22183758c444966427
vagrant@net-1:~$ docker network ls
NETWORK ID           NAME               DRIVE
447e75fd19b2         tester             overlay
b77a7d741b45         bridge             bridge
40fe7cfeee20         none               null
62072090b6ac         host               host

```

第二个主机也将看到此网络，我们可以使用 Docker 命令中的以下选项在这两个主机中的覆盖网络中创建容器：

```
$ docker run -it --rm --publish-service=bar.tester.overlay ubuntu:14.04 bash

```

我们将能够验证覆盖驱动程序的工作，因为这两个容器都能够相互 ping 通。此外，还可以使用 tcpdump、wireshark、smartsniff 等工具来捕获 vXLAN 数据包。

# 使用 Docker Machine 和 Docker Swarm 创建覆盖网络

本节介绍了创建多主机网络的基础知识。Docker 引擎通过覆盖网络驱动程序支持多主机网络。覆盖驱动程序需要以下先决条件才能工作：

+   3.16 Linux 内核或更高版本

+   访问键值存储

+   Docker 支持以下键值存储：Consul、etcd 和 ZooKeeper

+   连接到键值存储的主机集群

+   集群中每个主机上的 Docker 引擎守护程序

此示例使用 Docker Machine 和 Docker Swarm 来创建多网络主机。

Docker Machine 用于创建键值存储服务器和集群。创建的集群是 Docker Swarm 集群。

以下图解释了如何使用 Docker Machine 设置三个虚拟机：

![使用 Docker Machine 和 Docker Swarm 创建覆盖网络](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/lrn-dkr-net/img/00051.jpeg)

## 先决条件

+   Vagrant

+   Docker 引擎

+   Docker Machine

+   Docker Swarm

## 键值存储安装

覆盖网络需要一个键值存储。键值存储存储有关网络状态的信息，例如发现、网络、端点、IP 地址等。Docker 支持各种键值存储，如 Consul、etcd 和 Zoo Keeper。本节已使用 Consul 实现。

以下是安装键值存储的步骤：

1.  创建名为`mh-keystore`的 VirtualBox 虚拟机。

当新的虚拟机被配置时，该过程会将 Docker Engine 添加到主机上。Consul 实例将使用 Docker Hub 帐户中的 consul 镜像（[`hub.docker.com/r/progrium/consul/`](https://hub.docker.com/r/progrium/consul/)）：

```
$ docker-machine create -d virtualbox mh-keystore
Running pre-create checks...
Creating machine...
(mh-keystore) Creating VirtualBox VM...
(mh-keystore) Creating SSH key...
(mh-keystore) Starting VM...
Waiting for machine to be running, this may take a few minutes...
Machine is running, waiting for SSH to be available...
Detecting operating system of created instance...
Detecting the provisioner...
Provisioning with boot2docker...
Copying certs to the local machine directory...
Copying certs to the remote machine...
Setting Docker configuration on the remote daemon...
Checking connection to Docker...
Docker is up and running!
To see how to connect Docker to this machine, run: docker-machine env mh-keystore

```

1.  在`mh-keystore`虚拟机上启动先前创建的`progrium/consul`容器：

```
$ docker $(docker-machine config mh-keystore) run -d \
>     -p "8500:8500" \
>     -h "consul" \
>     progrium/consul -server –bootstrap

Unable to find image 'progrium/consul:latest' locally
latest: Pulling from progrium/consul
3b4d28ce80e4: Pull complete
…
d9125e9e799b: Pull complete
Digest: sha256:8cc8023462905929df9a79ff67ee435a36848ce7a10f18d6d0faba9306b97274
Status: Downloaded newer image for progrium/consul:latest
032884c7834ce22707ed08068c24c503d599499f1a0a58098c31be9cc84d8e6c

```

使用 bash 扩展`$(docker-machine config mh-keystore)`将连接配置传递给 Docker `run`命令。客户端从在`mh-keystore`机器中运行的`progrium/consul`镜像启动程序。容器名为`consul`（标志`-h`），并监听端口`8500`（您也可以选择任何其他端口）。

1.  将本地环境设置为`mh-keystore`虚拟机：

```
$ eval "$(docker-machine env mh-keystore)"

```

1.  执行`docker ps`命令，确保 Consul 容器已启动：

```
$ docker ps
CONTAINER ID      IMAGE            COMMAND               CREATED
032884c7834c   progrium/consul   "/bin/start -server -"   47 seconds ago
 STATUS          PORTS
Up 46 seconds  53/tcp, 53/udp, 8300-8302/tcp, 8301-8302/udp, 8400/tcp, 0.0.0.0:8500->8500/tcp
NAMES
sleepy_austin

```

## 创建具有两个节点的 Swarm 集群

在此步骤中，我们将使用 Docker Machine 为您的网络配置两个主机。我们将在 VirtualBox 中创建两个虚拟机。其中一个机器将是 Swarm 主节点，将首先创建。

创建每个主机时，将使用覆盖网络驱动程序的选项通过 Swarm 传递给 Docker Engine，具体步骤如下：

1.  创建一个 Swarm 主节点虚拟机`mhs-demo0`：

```
$ docker-machine create \
-d virtualbox \
--swarm --swarm-master \
--swarm-discovery="consul://$(docker-machine ip mh-keystore):8500" \
--engine-opt="cluster-store=consul://$(docker-machine ip mh-keystore):8500" \
--engine-opt="cluster-advertise=eth1:2376" \
mhs-demo0

```

在创建时，您提供引擎守护程序`--cluster-store`选项。此选项告诉引擎覆盖网络的键值存储位置。bash 扩展`$(docker-machine ip mh-keystore)`解析为您在前一节的第 1 步中创建的 Consul 服务器的 IP 地址。`--cluster-advertise`选项会在网络上宣传该机器。

1.  创建另一个虚拟机`mhs-demo1`并将其添加到 Docker Swarm 集群：

```
$ docker-machine create -d virtualbox \
 --swarm \
 --swarm-discovery="consul://$(docker-machine ip mh-keystore):8500" \
 --engine-opt="cluster-store=consul://$(docker-machine ip mh-keystore):8500" \
 --engine-opt="cluster-advertise=eth1:2376" \
mhs-demo1

Running pre-create checks...
Creating machine...
(mhs-demo1) Creating VirtualBox VM...
(mhs-demo1) Creating SSH key...
(mhs-demo1) Starting VM...
Waiting for machine to be running, this may take a few minutes...
Machine is running, waiting for SSH to be available...
Detecting operating system of created instance...
Detecting the provisioner...
Provisioning with boot2docker...
Copying certs to the local machine directory...
Copying certs to the remote machine...
Setting Docker configuration on the remote daemon...
Configuring swarm...
Checking connection to Docker...
Docker is up and running!
To see how to connect Docker to this machine, run: docker-machine env mhs-demo1

```

1.  使用 Docker Machine 列出虚拟机，以确认它们都已启动并运行：

```
$ docker-machine ls

NAME          ACTIVE   DRIVER       STATE     URL                         SWARM                DOCKER   ERRORS
mh-keystore   *        virtualbox   Running   tcp://192.168.99.100:2376                        v1.9.1
mhs-demo0     -        virtualbox   Running   tcp://192.168.99.101:2376   mhs-demo0 (master)   v1.9.1
mhs-demo1     -        virtualbox   Running   tcp://192.168.99.102:2376   mhs-demo0            v1.9.1

```

此时，虚拟机正在运行。我们准备使用这些虚拟机为容器创建多主机网络。

## 创建覆盖网络

使用以下命令创建覆盖网络：

```
$ docker network create --driver overlay my-net

```

我们只需要在 Swarm 集群中的一个主机上创建网络。我们使用了 Swarm 主节点，但此命令可以在 Swarm 集群中的任何主机上运行：

1.  检查覆盖网络是否正在运行，使用以下命令：

```
$ docker network ls

bd85c87911491d7112739e6cf08d732eb2a2841c6ca1efcc04d0b20bbb832a33
rdua1-ltm:overlay-tutorial rdua$ docker network ls
NETWORK ID          NAME                DRIVER
bd85c8791149        my-net              overlay
fff23086faa8        mhs-demo0/bridge    bridge
03dd288a8adb        mhs-demo0/none      null
2a706780454f        mhs-demo0/host      host
f6152664c40a        mhs-demo1/bridge    bridge
ac546be9c37c        mhs-demo1/none      null
c6a2de6ba6c9       mhs-demo1/host     host

```

由于我们正在使用 Swarm 主环境，我们能够看到所有 Swarm 代理上的所有网络：每个引擎上的默认网络和单个覆盖网络。在这种情况下，有两个引擎在`mhs-demo0`和`mhs-demo1`上运行。

每个`NETWORK ID`都是唯一的。

1.  依次切换到每个 Swarm 代理并列出网络：

```
$ eval $(docker-machine env mhs-demo0)

$ docker network ls
NETWORK ID          NAME                DRIVER
bd85c8791149        my-net              overlay
03dd288a8adb        none                  null
2a706780454f        host                  host
fff23086faa8        bridge              bridge

$ eval $(docker-machine env mhs-demo1)
$ docker network ls

NETWORK ID          NAME                DRIVER
bd85c8791149        my-net              overlay
358c45b96beb        docker_gwbridge     bridge
f6152664c40a        bridge              bridge
ac546be9c37c        none                null
c6a2de6ba6c9        host                host

```

两个代理都报告它们具有使用覆盖驱动程序的`my-net`网络。我们有一个运行中的多主机覆盖网络。

以下图显示了如何使用覆盖`my-net`创建并连接两个容器：

![创建覆盖网络](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/lrn-dkr-net/img/00052.jpeg)

# 使用覆盖网络创建容器

以下是使用覆盖网络创建容器的步骤：

1.  在`mhs-demo0`上创建一个名为`c0`的容器，并连接到`my-net`网络：

```
$ eval $(docker-machine env mhs-demo0)
root@843b16be1ae1:/#

$ sudo docker run -i -t --name=c0 --net=my-net  debian /bin/bash

```

执行`ifconfig`以查找`c0`的 IP 地址。在这种情况下，它是`10.0.0.4`：

```
root@843b16be1ae1:/# ifconfig
eth0      Link encap:Ethernet  HWaddr 02:42:0a:00:00:04
 inet addr:10.0.0.4  Bcast:0.0.0.0  Mask:255.255.255.0
 inet6 addr: fe80::42:aff:fe00:4/64 Scope:Link
 UP BROADCAST RUNNING MULTICAST  MTU:1450  Metric:1
 RX packets:17 errors:0 dropped:0 overruns:0 frame:0
 TX packets:17 errors:0 dropped:0 overruns:0 carrier:0
 collisions:0 txqueuelen:0
 RX bytes:1474 (1.4 KB)  TX bytes:1474 (1.4 KB)

eth1      Link encap:Ethernet  HWaddr 02:42:ac:12:00:03
 inet addr:172.18.0.3  Bcast:0.0.0.0  Mask:255.255.0.0
 inet6 addr: fe80::42:acff:fe12:3/64 Scope:Link
 UP BROADCAST RUNNING MULTICAST  MTU:1500  Metric:1
 RX packets:8 errors:0 dropped:0 overruns:0 frame:0
 TX packets:8 errors:0 dropped:0 overruns:0 carrier:0
 collisions:0 txqueuelen:0
 RX bytes:648 (648.0 B)  TX bytes:648 (648.0 B)

lo        Link encap:Local Loopback
 inet addr:127.0.0.1  Mask:255.0.0.0
 inet6 addr: ::1/128 Scope:Host
 UP LOOPBACK RUNNING  MTU:65536  Metric:1
 RX packets:0 errors:0 dropped:0 overruns:0 frame:0
 TX packets:0 errors:0 dropped:0 overruns:0 carrier:0
 collisions:0 txqueuelen:0
 RX bytes:0 (0.0 B)  TX bytes:0 (0.0 B)

```

1.  在`mhs-demo1`上创建一个名为`c1`的容器，并连接到`my-net`网络：

```
$ eval $(docker-machine env mhs-demo1)

$ sudo docker run -i -t --name=c1 --net=my-net  debian /bin/bash
Unable to find image 'ubuntu:latest' locally
latest: Pulling from library/ubuntu
0bf056161913: Pull complete
1796d1c62d0c: Pull complete
e24428725dd6: Pull complete
89d5d8e8bafb: Pull complete
Digest: sha256:a2b67b6107aa640044c25a03b9e06e2a2d48c95be6ac17fb1a387e75eebafd7c
Status: Downloaded newer image for ubuntu:latest
 root@2ce83e872408:/#

```

1.  执行`ifconfig`以查找`c1`的 IP 地址。在这种情况下，它是`10.0.0.3`：

```
root@2ce83e872408:/# ifconfig
eth0      Link encap:Ethernet  HWaddr 02:42:0a:00:00:03
 inet addr:10.0.0.3  Bcast:0.0.0.0  Mask:255.255.255.0
 inet6 addr: fe80::42:aff:fe00:3/64 Scope:Link
 UP BROADCAST RUNNING MULTICAST  MTU:1450  Metric:1
 RX packets:13 errors:0 dropped:0 overruns:0 frame:0
 TX packets:7 errors:0 dropped:0 overruns:0 carrier:0
 collisions:0 txqueuelen:0
 RX bytes:1066 (1.0 KB)  TX bytes:578 (578.0 B)

eth1      Link encap:Ethernet  HWaddr 02:42:ac:12:00:02
 inet addr:172.18.0.2  Bcast:0.0.0.0  Mask:255.255.0.0
 inet6 addr: fe80::42:acff:fe12:2/64 Scope:Link
 UP BROADCAST RUNNING MULTICAST  MTU:1500  Metric:1
 RX packets:7 errors:0 dropped:0 overruns:0 frame:0
 TX packets:7 errors:0 dropped:0 overruns:0 carrier:0
 collisions:0 txqueuelen:0
 RX bytes:578 (578.0 B)  TX bytes:578 (578.0 B)

lo        Link encap:Local Loopback
 inet addr:127.0.0.1  Mask:255.0.0.0
 inet6 addr: ::1/128 Scope:Host
 UP LOOPBACK RUNNING  MTU:65536  Metric:1
 RX packets:0 errors:0 dropped:0 overruns:0 frame:0
 TX packets:0 errors:0 dropped:0 overruns:0 carrier:0
 collisions:0 txqueuelen:0
 RX bytes:0 (0.0 B)  TX bytes:0 (0.0 B)

```

1.  从`c0`(`10.0.0.4`) ping `c1`(`10.0.0.3`)，反之亦然：

```
root@2ce83e872408:/# ping 10.0.04
PING 10.0.04 (10.0.0.4) 56(84) bytes of data.
64 bytes from 10.0.0.4: icmp_seq=1 ttl=64 time=0.370 ms
64 bytes from 10.0.0.4: icmp_seq=2 ttl=64 time=0.443 ms
64 bytes from 10.0.0.4: icmp_seq=3 ttl=64 time=0.441 ms

```

## 容器网络接口

**容器网络接口**（**CNI**）是一个规范，定义了可执行插件如何用于配置 Linux 应用容器的网络接口。CNI 的官方 GitHub 存储库解释了一个 go 库如何解释实施规范。

容器运行时首先为容器创建一个新的网络命名空间，在其中确定该容器应属于哪个网络以及应执行哪些插件。网络配置以 JSON 格式定义，并在容器启动时定义应为网络执行哪个插件。CNI 实际上是一个源自 rkt 网络协议的不断发展的开源技术。每个 CNI 插件都被实现为可执行文件，并由容器管理系统、docker 或 rkt 调用。

将容器插入网络命名空间，即将 veth 对的一端连接到容器，将另一端连接到桥接，然后分配一个 IP 给接口，并通过调用适当的 IPAM 插件设置与 IP 地址管理一致的路由。

CNI 模型目前用于 Kubernetes 模型中 kubelet 的网络。Kubelet 是 Kubernetes 节点的最重要组件，负责在其上运行容器的负载。

kubelet 的 CNI 包定义在以下 Kubernetes 包中：

```
Constants
const (
 CNIPluginName        = "cni"
 DefaultNetDir        = "/etc/cni/net.d"
 DefaultCNIDir        = "/opt/cni/bin"
 DefaultInterfaceName = "eth0"
 VendorCNIDirTemplate = "%s/opt/%s/bin"
)
func ProbeNetworkPlugins
func ProbeNetworkPlugins(pluginDir string) []network.NetworkPlugin

```

以下图显示了 CNI 的放置：

![容器网络接口](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/lrn-dkr-net/img/00053.jpeg)

# CNI 插件

根据官方 GitHub 存储库（[`github.com/appc/cni`](https://github.com/appc/cni)），CNI 插件需要的参数以便将容器添加到网络中为：

+   **版本**：调用者使用的 CNI 规范的版本（调用插件的容器调用）。

+   **容器 ID**：这是可选的，但建议使用，并定义了容器在活动时在管理域中应该有一个唯一的 ID。例如，IPAM 系统可能要求为每个容器分配一个唯一的 ID，以便可以正确地将其与后台运行的容器相关联。

+   **网络命名空间路径**：这表示要添加的网络命名空间的路径，例如`/proc/[pid]/ns/net`或`bind-mount/link`到它。

+   **网络配置**：这是描述容器可以加入的网络的 JSON 文档，并在以下部分中进行了解释。

+   **额外参数**：它允许根据每个容器的需求对 CNI 插件进行细粒度配置。

+   **容器内部接口的名称**：这是分配给容器的名称，并符合 Linux 对接口名称的限制。

实现的结果如下：

+   **分配给接口的 IP 地址**：这是根据要求分配给网络的 IPv4 地址或 IPv6 地址。

+   **DNS 名称服务器列表**：这是 DNS 名称服务器的优先顺序地址列表。

## 网络配置

网络配置以 JSON 格式呈现，可以存储在磁盘上或由容器运行时从其他来源生成。以下 JSON 中的字段很重要，如下所述：

+   **cniVersion（字符串）**：这是此配置符合的 CNI 规范的语义版本 2.0。

+   **name（字符串）**：这是网络名称。它在主机（或其他管理域）上的所有容器中是唯一的。

+   **type（字符串）**：指的是 CNI 插件可执行文件的文件名。

+   **ipMasq（布尔值）**：可选，设置主机上的 IP 伪装，因为主机需要作为无法路由到容器分配的 IP 的子网的网关。

+   **ipam**：具有 IPAM 特定值的字典。

+   **type（字符串）**：指的是 IPAM 插件可执行文件的文件名。

+   **routes（列表）**：CNI 插件应确保通过网络路由可达的子网列表（以 CIDR 表示）。每个条目都是包含的字典：

+   **dst（字符串）**：CIDR 表示法中的子网

+   **gw（字符串）**：要使用的网关的 IP 地址。如果未指定，则假定子网的默认网关（由 IPAM 插件确定）。

插件特定 OVS 的示例配置如下：

```
{
  "cniVersion": "0.1.0",
  "name": "pci",
  "type": "ovs",
  // type (plugin) specific
  "bridge": "ovs0",
  "vxlanID": 42,
  "ipam": {
    "type": "dhcp",
    "routes": [ { "dst": "10.3.0.0/16" }, { "dst": "10.4.0.0/16" } ]
  }
}
```

## IP 分配

CNI 插件为接口分配 IP 地址并为接口安装必要的路由，因此它为 CNI 插件提供了很大的灵活性，并且许多 CNI 插件在内部具有支持多种 IP 管理方案的相同代码。

为了减轻 CNI 插件的负担，定义了第二种类型的插件，**IP 地址管理插件**（**IPAM**），它确定接口 IP/子网、网关和路由，并将此信息返回给主要插件以应用。 IPAM 插件通过网络配置文件中定义的`ipam`部分或存储在本地文件系统上的数据获取信息。

## IP 地址管理界面

IPAM 插件通过运行可执行文件来调用，该文件在预定义路径中搜索，并由 CNI 插件通过`CNI_PATH`指示。 IPAM 插件从此可执行文件接收所有系统环境变量，这些变量传递给 CNI 插件。

IPAM 通过 stdin 接收网络配置文件。成功的指示是零返回代码和以下 JSON，它被打印到 stdout（在`ADD`命令的情况下）：

```
{
  "cniVersion": "0.1.0",
  "ip4": {
    "ip": <ipv4-and-subnet-in-CIDR>,
    "gateway": <ipv4-of-the-gateway>,  (optional)
    "routes": <list-of-ipv4-routes>    (optional)
  },
  "ip6": {
    "ip": <ipv6-and-subnet-in-CIDR>,
    "gateway": <ipv6-of-the-gateway>,  (optional)
    "routes": <list-of-ipv6-routes>    (optional)
  },
  "dns": <list-of-DNS-nameservers>     (optional)
}
```

以下是使用 CNI 运行 Docker 网络的示例：

1.  首先，安装 Go Lang 1.4+和 jq（命令行 JSON 处理器）以构建 CNI 插件：

```
$ wget https://storage.googleapis.com/golang/go1.5.2.linux-amd64.tar.gz
$ tar -C /usr/local -xzf go1.5.2.linux-amd64.tar.gz
$ export PATH=$PATH:/usr/local/go/bin
$ go version
go version go1.5.2 linux/amd64
$ sudo apt-get install jq

```

1.  克隆官方 CNI GitHub 存储库：

```
$ git clone https://github.com/appc/cni.git
Cloning into 'cni'...
remote: Counting objects: 881, done.
remote: Total 881 (delta 0), reused 0 (delta 0), pack-reused 881
Receiving objects: 100% (881/881), 543.54 KiB | 313.00 KiB/s, done.
Resolving deltas: 100% (373/373), done.
Checking connectivity... done.

```

1.  现在我们将创建一个`netconf`文件，以描述网络：

```
mkdir -p /etc/cni/net.d
root@rajdeepd-virtual-machine:~# cat >/etc/cni/net.d/10-mynet.conf <<EOF
>{
>  "name": "mynet",
>  "type": "bridge",
>  "bridge": "cni0",
>  "isGateway": true,
>  "ipMasq": true,
>  "ipam": {
>    "type": "host-local",
>    "subnet": "10.22.0.0/16",
>    "routes": [
>      { "dst": "0.0.0.0/0" }
>    ]
>  }
>}
> EOF

```

1.  构建 CNI 插件：

```
~/cni$ ./build
Building API
Building reference CLI
Building plugins
 flannel
 bridge
 ipvlan
 macvlan
 ptp
 dhcp
 host-local

```

1.  现在我们将执行`priv-net-run.sh`脚本，以创建带有 CNI 插件的私有网络：

```
~/cni/scripts$ sudo CNI_PATH=$CNI_PATH ./priv-net-run.sh ifconfig
eth0      Link encap:Ethernet  HWaddr 8a:72:75:7d:6d:6c
 inet addr:10.22.0.2  Bcast:0.0.0.0  Mask:255.255.0.0
 inet6 addr: fe80::8872:75ff:fe7d:6d6c/64 Scope:Link
 UP BROADCAST RUNNING MULTICAST  MTU:1500  Metric:1
 RX packets:1 errors:0 dropped:0 overruns:0 frame:0
 TX packets:1 errors:0 dropped:0 overruns:0 carrier:0
 collisions:0 txqueuelen:0
 RX bytes:90 (90.0 B)  TX bytes:90 (90.0 B)

lo        Link encap:Local Loopback
 inet addr:127.0.0.1  Mask:255.0.0.0
 inet6 addr: ::1/128 Scope:Host
 UP LOOPBACK RUNNING  MTU:65536  Metric:1
 RX packets:0 errors:0 dropped:0 overruns:0 frame:0
 TX packets:0 errors:0 dropped:0 overruns:0 carrier:0
 collisions:0 txqueuelen:0
 RX bytes:0 (0.0 B)  TX bytes:0 (0.0 B)

```

1.  使用之前使用 CNI 插件设置的网络命名空间运行 Docker 容器：

```
~/cni/scripts$ sudo CNI_PATH=$CNI_PATH ./docker-run.sh --rm busybox:latest /bin/ifconfig
eth0      Link encap:Ethernet  HWaddr 92:B2:D3:E5:BA:9B
 inet addr:10.22.0.2  Bcast:0.0.0.0  Mask:255.255.0.0
 inet6 addr: fe80::90b2:d3ff:fee5:ba9b/64 Scope:Link
 UP BROADCAST RUNNING MULTICAST  MTU:1500  Metric:1
 RX packets:2 errors:0 dropped:0 overruns:0 frame:0
 TX packets:2 errors:0 dropped:0 overruns:0 carrier:0
 collisions:0 txqueuelen:0
 RX bytes:180 (180.0 B)  TX bytes:168 (168.0 B)

lo        Link encap:Local Loopback
 inet addr:127.0.0.1  Mask:255.0.0.0
 inet6 addr: ::1/128 Scope:Host
 UP LOOPBACK RUNNING  MTU:65536  Metric:1
 RX packets:0 errors:0 dropped:0 overruns:0 frame:0
 TX packets:0 errors:0 dropped:0 overruns:0 carrier:0
 collisions:0 txqueuelen:0
 RX bytes:0 (0.0 B)  TX bytes:0 (0.0 B)

```

# Project Calico 的 libnetwork 驱动程序

Calico 为连接容器、虚拟机或裸金属提供可扩展的网络解决方案。 Calico 使用可扩展的 IP 网络原则作为第 3 层方法提供连接。 Calico 可以在不使用覆盖或封装的情况下部署。 Calico 服务应该作为每个节点上的一个容器部署，并为每个容器提供其自己的 IP 地址。 它还处理所有必要的 IP 路由、安全策略规则和在节点集群中分发路由。

Calico 架构包含四个重要组件，以提供更好的网络解决方案：

+   Felix，Calico 工作进程，是 Calico 网络的核心，主要路由并提供所需的连接到主机上的工作负载。 它还为出站端点流量提供内核接口。

+   BIRD，路由分发开源 BGP，交换主机之间的路由信息。 BIRD 捕获的内核端点分布给 BGP 对等体，以提供主机之间的路由。 calico-node 容器中运行两个 BIRD 进程，一个用于 IPv4（bird），一个用于 IPv6（bird6）。

+   Confd，一个模板化进程，用于自动生成 BIRD 的配置，监视 etcd 存储中对 BGP 配置的任何更改，如日志级别和 IPAM 信息。 Confd 还根据 etcd 中的数据动态生成 BIRD 配置文件，并在数据应用更新时自动触发。 Confd 在配置文件更改时触发 BIRD 加载新文件。

+   calicoctl 是用于配置和启动 Calico 服务的命令行工具，甚至允许数据存储（etcd）定义和应用安全策略。 该工具还提供了通用管理 Calico 配置的简单界面，无论 Calico 是在虚拟机、容器还是裸金属上运行。 calicoctl 支持以下命令：

```
$ calicoctlOverride the host:port of the ETCD server by setting the environment variable ETCD_AUTHORITY [default: 127.0.0.1:2379]Usage: calicoctl <command> [<args>...]
status            Print current status information
node              Configure the main calico/node container and establish Calico networking
container         Configure containers and their addresses
profile           Configure endpoint profiles
endpoint          Configure the endpoints assigned to existing containers
pool              Configure ip-pools
bgp               Configure global bgp
ipam              Configure IP address management
checksystem       Check for incompatibilities on the host system
diags             Save diagnostic information
version           Display the version of calicoctl
config            Configure low-level component configuration
See 'calicoctl <command> --help' to read about a specific subcommand.

```

根据 Calico 存储库的官方 GitHub 页面（[`github.com/projectcalico/calico-containers`](https://github.com/projectcalico/calico-containers)），存在以下 Calico 集成：

+   Calico 作为 Docker 网络插件

+   不使用 Docker 网络的 Calico

+   Calico 与 Kubernetes

+   Calico 与 Mesos

+   Calico 与 Docker Swarm

以下图显示了 Calico 架构：

![Project Calico 的 libnetwork 驱动程序](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/lrn-dkr-net/img/00054.jpeg)

在接下来的教程中，我们将在单节点机器上运行 Calico 的手动设置，该机器使用 Docker 1.9，这最终将 libnetwork 从实验版本带到主要发布版本，并且可以直接配置 Calico，而无需其他 Docker 实验版本的需要：

1.  获取 etcd 的最新版本并在默认端口 2379 上进行配置：

```
$ curl -L https://github.com/coreos/etcd/releases/download/v2.2.1/etcd-v2.2.1-linux-amd64.tar.gz -o etcd-v2.2.1-linux-amd64.tar.gz
 % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current
 Dload  Upload   Total   Spent    Left  Speed
100   606    0   606    0     0    445      0 --:--:--  0:00:01 --:--:--   446
100 7181k  100 7181k    0     0   441k      0  0:00:16  0:00:16 --:--:-- 1387k
$ tar xzvf etcd-v2.2.1-linux-amd64.tar.gz
etcd-v2.2.1-linux-amd64/
etcd-v2.2.1-linux-amd64/Documentation/
etcd-v2.2.1-linux-amd64/Documentation/04_to_2_snapshot_migration.md
etcd-v2.2.1-linux-amd64/Documentation/admin_guide.md
etcd-v2.2.1-linux-amd64/Documentation/api.md
contd..
etcd-v2.2.1-linux-amd64/etcd
etcd-v2.2.1-linux-amd64/etcdctl
etcd-v2.2.1-linux-amd64/README-etcdctl.md
etcd-v2.2.1-linux-amd64/README.md

$ cd etcd-v2.2.1-linux-amd64
$ ./etcd
2016-01-06 15:50:00.065733 I | etcdmain: etcd Version: 2.2.1
2016-01-06 15:50:00.065914 I | etcdmain: Git SHA: 75f8282
2016-01-06 15:50:00.065961 I | etcdmain: Go Version: go1.5.1
2016-01-06 15:50:00.066001 I | etcdmain: Go OS/Arch: linux/amd64
Contd..
2016-01-06 15:50:00.107972 I | etcdserver: starting server... [version: 2.2.1, cluster version: 2.2]
2016-01-06 15:50:00.508131 I | raft: ce2a822cea30bfca is starting a new election at term 5
2016-01-06 15:50:00.508237 I | raft: ce2a822cea30bfca became candidate at term 6
2016-01-06 15:50:00.508253 I | raft: ce2a822cea30bfca received vote from ce2a822cea30bfca at term 6
2016-01-06 15:50:00.508278 I | raft: ce2a822cea30bfca became leader at term 6
2016-01-06 15:50:00.508313 I | raft: raft.node: ce2a822cea30bfca elected leader ce2a822cea30bfca at term 6
2016-01-06 15:50:00.509810 I | etcdserver: published {Name:default ClientURLs:[http://localhost:2379 http://localhost:4001]} to cluster 7e27652122e8b2ae

```

1.  打开新的终端，并通过运行以下命令将 Docker 守护程序配置为 etcd 键值存储：

```
$ service docker stop
$ docker daemon --cluster-store=etcd://0.0.0.0:2379
INFO[0000] [graphdriver] using prior storage driver "aufs"
INFO[0000] API listen on /var/run/docker.sock
INFO[0000] Firewalld running: false
INFO[0015] Default bridge (docker0) is assigned with an IP address 172.16.59.1/24\. Daemon option --bip can be used to set a preferred IP address
WARN[0015] Your kernel does not support swap memory limit.
INFO[0015] Loading containers: start.
.....INFO[0034] Skipping update of resolv.conf file with ipv6Enabled: false because file was touched by user
INFO[0043] Loading containers: done.
INFO[0043] Daemon has completed initialization
INFO[0043] Docker daemon       commit=a34a1d5 execdriver=native-0.2 graphdriver=aufs version=1.9.1
INFO[0043] GET /v1.21/version
INFO[0043] GET /v1.21/version
INFO[0043] GET /events
INFO[0043] GET /v1.21/version

```

1.  现在，在新的终端中，以以下方式启动 Calico 容器：

```
$ ./calicoctl node --libnetwork
No IP provided. Using detected IP: 10.22.0.1
Pulling Docker image calico/node:v0.10.0
Calico node is running with id: 79e75fa6d875777d31b8aead10c2712f54485c031df50667edb4d7d7cb6bb26c
Pulling Docker image calico/node-libnetwork:v0.5.2
Calico libnetwork driver is running with id: bc7d65f6ab854b20b9b855abab4776056879f6edbcde9d744f218e556439997f
$ docker ps
CONTAINER ID        IMAGE                           COMMAND         CREATED             STATUS              PORTS               NAMES
7bb7a956af37        calico/node-libnetwork:v0.5.2   "./start.sh"           3 minutes ago       Up 3 minutes             calico-libnetwork
13a0314754d6        calico/node:v0.10.0             "/sbin/start_runit"    3 minutes ago       Up 3 minutes             calico-node
1f13020cc3a0        weaveworks/plugin:1.4.1         "/home/weave/plugin"   3 days ago          Up 3 minutes             weaveplugin

```

1.  使用最近在 Docker CLI 中引入的`docker network`命令创建 Calico 桥接：

```
$docker network create –d calico net1
$ docker network ls
NETWORK ID          NAME                DRIVER
9b5f06307cf2        docker_gwbridge     bridge
1638f754fbaf        host                host
02b10aaa25d7        weave               weavemesh
65dc3cbcd2c0        bridge              bridge
f034d78cc423        net1                calico

```

1.  启动连接到 Calico `net1`桥接的`busybox`容器：

```
$docker run --net=net1 -itd --name=container1 busybox
1731629b6897145822f73726194b1f7441b6086ee568e973d8a88b554e838366
$ docker ps
CONTAINER ID        IMAGE                           COMMAND                CREATED             STATUS              PORTS               NAMES
1731629b6897        busybox                         "sh"                   6 seconds ago       Up 5 seconds                            container1
7bb7a956af37        calico/node-libnetwork:v0.5.2   "./start.sh"           6 minutes ago       Up 6 minutes                            calico-libnetwork
13a0314754d6        calico/node:v0.10.0             "/sbin/start_runit"    6 minutes ago       Up 6 minutes                            calico-node
1f13020cc3a0        weaveworks/plugin:1.4.1         "/home/weave/plugin"   3 days ago          Up 6 minutes                            weaveplugin
$ docker attach 1731
/ #
/ # ifconfig
cali0     Link encap:Ethernet  HWaddr EE:EE:EE:EE:EE:EE
 inet addr:10.0.0.2  Bcast:0.0.0.0  Mask:255.255.255.0
 inet6 addr: fe80::ecee:eeff:feee:eeee/64 Scope:Link
 UP BROADCAST RUNNING MULTICAST  MTU:1500  Metric:1
 RX packets:29 errors:0 dropped:0 overruns:0 frame:0
 TX packets:8 errors:0 dropped:0 overruns:0 carrier:0
 collisions:0 txqueuelen:1000
 RX bytes:5774 (5.6 KiB)  TX bytes:648 (648.0 B)

eth1      Link encap:Ethernet  HWaddr 02:42:AC:11:00:02
 inet addr:172.17.0.2  Bcast:0.0.0.0  Mask:255.255.0.0
 inet6 addr: fe80::42:acff:fe11:2/64 Scope:Link
 UP BROADCAST RUNNING MULTICAST  MTU:1500  Metric:1
 RX packets:21 errors:0 dropped:0 overruns:0 frame:0
 TX packets:8 errors:0 dropped:0 overruns:0 carrier:0
 collisions:0 txqueuelen:0
 RX bytes:4086 (3.9 KiB)  TX bytes:648 (648.0 B)

lo        Link encap:Local Loopback
 inet addr:127.0.0.1  Mask:255.0.0.0
 inet6 addr: ::1/128 Scope:Host
 UP LOOPBACK RUNNING  MTU:65536  Metric:1
 RX packets:0 errors:0 dropped:0 overruns:0 frame:0
 TX packets:0 errors:0 dropped:0 overruns:0 carrier:0
 collisions:0 txqueuelen:0
 RX bytes:0 (0.0 B)  TX bytes:0 (0.0 B)

```

在容器内部，我们可以看到容器现在连接到了 Calico 桥接，并且可以连接到同一桥接上部署的其他容器。

# 摘要

在本章中，我们深入研究了 Docker 网络的一些更深层次和更概念性的方面之一，其中之一是 libnetworking，这是未来的 Docker 网络模型，已经随着 Docker 1.9 的发布而开始成形。在解释 libnetworking 的同时，我们还研究了 CNM 模型及其各种对象和组件以及其实现代码片段。接下来，我们详细研究了 CNM 的驱动程序，主要是覆盖驱动程序，并作为 Vagrant 设置的一部分进行部署。我们还研究了容器与覆盖网络的独立集成，以及与 Docker Swarm 和 Docker Machine 的集成。在接下来的部分中，我们解释了 CNI 接口、其可执行插件以及使用 CNI 插件配置 Docker 网络的教程。

在最后一节中，详细解释了 Calico 项目，它提供了一个基于 libnetwork 的可扩展网络解决方案，并与 Docker、Kubernetes、Mesos、裸机和虚拟机进行集成。
