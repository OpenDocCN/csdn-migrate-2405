# Docker 学习手册第二版（二）

> 原文：[`zh.annas-archive.org/md5/4FF7CBA6C5E093012874A6BAC2B803F8`](https://zh.annas-archive.org/md5/4FF7CBA6C5E093012874A6BAC2B803F8)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第五章：数据卷和配置

在上一章中，我们学习了如何构建和共享我们自己的容器镜像。特别关注了如何通过只包含容器化应用程序真正需要的构件来尽可能地减小镜像的大小。

在本章中，我们将学习如何处理有状态的容器，即消耗和产生数据的容器。我们还将学习如何使用环境变量和配置文件在运行时和构建时配置容器。

以下是我们将讨论的主题列表：

+   创建和挂载数据卷

+   在容器之间共享数据

+   使用主机卷

+   在镜像中定义卷

+   配置容器

完成本章后，您将能够做到以下事项：

+   创建、删除和列出数据卷。

+   将现有的数据卷挂载到容器中。

+   在容器内部使用数据卷创建持久化数据。

+   使用数据卷在多个容器之间共享数据。

+   使用数据卷将任何主机文件夹挂载到容器中。

+   定义容器访问数据卷中数据的访问模式（读/写或只读）。

+   为在容器中运行的应用程序配置环境变量。

+   通过使用构建参数对`Dockerfile`进行参数化。

# 技术要求

在本章中，您需要在您的机器上安装 Docker Toolbox 或者访问在您的笔记本电脑或云中运行 Docker 的 Linux 虚拟机（VM）。此外，最好在您的机器上安装 Docker for Desktop。本章没有附带任何代码。

# 创建和挂载数据卷

所有有意义的应用程序都会消耗或产生数据。然而，容器最好是无状态的。我们该如何处理这个问题呢？一种方法是使用 Docker 卷。卷允许容器消耗、产生和修改状态。卷的生命周期超出了容器的生命周期。当使用卷的容器死亡时，卷仍然存在。这对状态的持久性非常有利。

# 修改容器层

在我们深入讨论卷之前，让我们首先讨论一下如果容器中的应用程序更改了容器文件系统中的内容会发生什么。在这种情况下，更改都发生在我们在《精通容器》第三章中介绍的可写容器层中。我们可以通过运行一个容器并在其中执行一个创建新文件的脚本来快速演示这一点，就像这样：

```
$ docker container run --name demo \
 alpine /bin/sh -c 'echo "This is a test" > sample.txt'
```

上述命令创建了一个名为`demo`的容器，并在该容器内创建了一个名为`sample.txt`的文件，内容为`This is a test`。运行`echo`命令后容器退出，但仍保留在内存中，供我们进行调查。让我们使用`diff`命令来查找容器文件系统中与原始镜像文件系统相关的更改，如下所示：

```
$ docker container diff demo
```

输出应该如下所示：

```
A /sample.txt
```

显然，如`A`所示，容器的文件系统中已经添加了一个新文件，这是预期的。由于所有源自基础镜像（在本例中为`alpine`）的层都是不可变的，更改只能发生在可写容器层中。

与原始镜像相比发生了变化的文件将用`C`标记，而已删除的文件将用`D`标记。

如果我们现在从内存中删除容器，它的容器层也将被删除，所有更改将被不可逆转地删除。如果我们需要我们的更改持久存在，甚至超出容器的生命周期，这不是一个解决方案。幸运的是，我们有更好的选择，即 Docker 卷。让我们来了解一下它们。

# 创建卷

由于在这个时候，在 macOS 或 Windows 计算机上使用 Docker for Desktop 时，容器并不是在 macOS 或 Windows 上本地运行，而是在 Docker for Desktop 创建的（隐藏的）VM 中运行，为了说明问题，最好使用`docker-machine`来创建和使用运行 Docker 的显式 VM。在这一点上，我们假设您已经在系统上安装了 Docker Toolbox。如果没有，请返回到第二章《设置工作环境》中，我们提供了如何安装 Toolbox 的详细说明：

1.  使用`docker-machine`列出当前在 VirtualBox 中运行的所有虚拟机，如下所示：

```
$ docker-machine ls 
```

1.  如果您的列表中没有名为`node-1`的 VM，请使用以下命令创建一个：

```
$ docker-machine create --driver virtualbox node-1 
```

如果您在启用了 Hyper-V 的 Windows 上运行，可以参考第二章 *设置工作环境*中的内容，了解如何使用`docker-machine`创建基于 Hyper-V 的 VM。

1.  另一方面，如果您有一个名为`node-1`的 VM，但它没有运行，请按以下方式启动它：

```
$ docker-machine start node-1
```

1.  现在一切准备就绪，使用`docker-machine`以这种方式 SSH 到这个 VM：

```
$ docker-machine ssh node-1
```

1.  您应该会看到这个欢迎图片：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/lrn-dkr-2e/img/223cb246-5c36-42aa-8905-22913d6642ba.png)

docker-machine VM 欢迎消息

1.  要创建一个新的数据卷，我们可以使用`docker volume create`命令。这将创建一个命名卷，然后可以将其挂载到容器中，用于持久数据访问或存储。以下命令创建一个名为`sample`的卷，使用默认卷驱动程序：

```
$ docker volume create sample 
```

默认的卷驱动程序是所谓的本地驱动程序，它将数据存储在主机文件系统中。

1.  找出主机上存储数据的最简单方法是使用`docker volume inspect`命令查看我们刚刚创建的卷。实际位置可能因系统而异，因此这是找到目标文件夹的最安全方法。您可以在以下代码块中看到这个命令：

```
$ docker volume inspect sample [ 
    { 
        "CreatedAt": "2019-08-02T06:59:13Z",
        "Driver": "local",
        "Labels": {},
        "Mountpoint": "/mnt/sda1/var/lib/docker/volumes/sample/_data",
        "Name": "my-data",
        "Options": {},
        "Scope": "local"
    } 
] 
```

主机文件夹可以在输出中的`Mountpoint`下找到。在我们的情况下，当使用基于 LinuxKit 的 VM 在 VirtualBox 中运行`docker-machine`时，文件夹是`/mnt/sda1/var/lib/docker/volumes/sample/_data`。

目标文件夹通常是受保护的文件夹，因此我们可能需要使用`sudo`来导航到这个文件夹并在其中执行任何操作。

在我们基于 LinuxKit 的 VM 中，Docker Toolbox 中，访问也被拒绝，但我们也没有`sudo`。我们的探索到此为止了吗？

幸运的是，我已经准备了一个`fundamentalsofdocker/nsenter`实用程序容器，允许我们访问我们之前创建的`sample`卷的后备文件夹。

1.  我们需要以`privileged`模式运行此容器，以访问文件系统的受保护部分，就像这样：

```
$ docker run -it --rm --privileged --pid=host \
 fundamentalsofdocker/nsenter / #
```

我们正在使用`--privileged`标志运行容器。这意味着在容器中运行的任何应用程序都可以访问主机的设备。`--pid=host`标志表示容器被允许访问主机的进程树（Docker 守护程序运行的隐藏 VM）。现在，前面的容器运行 Linux `nsenter`工具以进入主机的 Linux 命名空间，然后在其中运行一个 shell。通过这个 shell，我们因此被授予对主机管理的所有资源的访问权限。

在运行容器时，我们基本上在容器内执行以下命令：

`nsenter -t 1 -m -u -n -i sh`

如果这对你来说听起来很复杂，不用担心；随着我们在本书中的学习，你会更多地理解。如果有一件事可以让你受益，那就是意识到正确使用容器可以有多强大。

1.  在容器内部，我们现在可以导航到代表卷挂载点的文件夹，然后列出其内容，如下所示：

```
/ # cd /mnt/sda1/var/lib/docker/volumes/sample/_data
/ # ls -l total 0
```

由于我们尚未在卷中存储任何数据，该文件夹目前为空。

1.  通过按下*Ctrl* + *D*退出工具容器。

还有其他来自第三方的卷驱动程序，以插件的形式提供。我们可以在`create`命令中使用`--driver`参数来选择不同的卷驱动程序。其他卷驱动程序使用不同类型的存储系统来支持卷，例如云存储、网络文件系统（NFS）驱动、软件定义存储等。然而，正确使用其他卷驱动程序的讨论超出了本书的范围。

# 挂载卷

一旦我们创建了一个命名卷，我们可以按照以下步骤将其挂载到容器中：

1.  为此，我们可以在`docker container run`命令中使用`-v`参数，如下所示：

```
$ docker container run --name test -it \
 -v sample:/data \
    alpine /bin/sh Unable to find image 'alpine:latest' locally
latest: Pulling from library/alpine
050382585609: Pull complete
Digest: sha256:6a92cd1fcdc8d8cdec60f33dda4db2cb1fcdcacf3410a8e05b3741f44a9b5998
Status: Downloaded newer image for alpine:latest
/ #
```

上述命令将`sample`卷挂载到容器内的`/data`文件夹。

1.  在容器内，我们现在可以在`/data`文件夹中创建文件，然后退出，如下所示：

```
/ # cd /data / # echo "Some data" > data.txt 
/ # echo "Some more data" > data2.txt 
/ # exit
```

1.  如果我们导航到包含卷数据的主机文件夹并列出其内容，我们应该看到我们刚刚在容器内创建的两个文件（记住：我们需要使用`fundamentalsofdocker/nsenter`工具容器来这样做），如下所示：

```
$ docker run -it --rm --privileged --pid=host \
 fundamentalsofdocker/nsenter
/ # cd /mnt/sda1/var/lib/docker/volumes/sample/_data
/ # ls -l 
total 8 
-rw-r--r-- 1 root root 10 Jan 28 22:23 data.txt
-rw-r--r-- 1 root root 15 Jan 28 22:23 data2.txt
```

1.  我们甚至可以尝试输出，比如说，第二个文件的内容，如下所示：

```
/ # cat data2.txt
```

1.  让我们尝试从主机在这个文件夹中创建一个文件，然后像这样使用另一个容器的卷：

```
/ # echo "This file we create on the host" > host-data.txt 
```

1.  通过按下*Ctrl* + *D*退出工具容器。

1.  现在，让我们删除`test`容器，并基于 CentOS 运行另一个容器。这次，我们甚至将我们的卷挂载到不同的容器文件夹`/app/data`中，就像这样：

```
$ docker container rm test
$ docker container run --name test2 -it \
 -v my-data:/app/data \
 centos:7 /bin/bash Unable to find image 'centos:7' locally
7: Pulling from library/centos
8ba884070f61: Pull complete
Digest: sha256:a799dd8a2ded4a83484bbae769d97655392b3f86533ceb7dd96bbac929809f3c
Status: Downloaded newer image for centos:7
[root@275c1fe31ec0 /]#
```

1.  一旦进入`centos`容器，我们可以导航到我们已经挂载卷的`/app/data`文件夹，并列出其内容，如下所示：

```
[root@275c1fe31ec0 /]# cd /app/data 
[root@275c1fe31ec0 /]# ls -l 
```

正如预期的那样，我们应该看到这三个文件：

```
-rw-r--r-- 1 root root 10 Aug 2 22:23 data.txt
-rw-r--r-- 1 root root 15 Aug 2 22:23 data2.txt
-rw-r--r-- 1 root root 32 Aug 2 22:31 host-data.txt
```

这是数据在 Docker 卷中持久存在超出容器生命周期的明确证据，也就是说，卷可以被其他甚至不同的容器重复使用，而不仅仅是最初使用它的容器。

重要的是要注意，在容器内部挂载 Docker 卷的文件夹被排除在 Union 文件系统之外。也就是说，该文件夹及其任何子文件夹内的每个更改都不会成为容器层的一部分，而是将持久保存在卷驱动程序提供的后备存储中。这一事实非常重要，因为当相应的容器停止并从系统中删除时，容器层将被删除。

1.  使用*Ctrl* + *D*退出`centos`容器。现在，再次按*Ctrl* + *D*退出`node-1`虚拟机。

# 删除卷

可以使用`docker volume rm`命令删除卷。重要的是要记住，删除卷会不可逆地销毁包含的数据，因此应该被视为危险命令。在这方面，Docker 在一定程度上帮助了我们，因为它不允许我们删除仍然被容器使用的卷。在删除卷之前，一定要确保要么有数据的备份，要么确实不再需要这些数据。让我们看看如何按照以下步骤删除卷：

1.  以下命令删除了我们之前创建的`sample`卷：

```
$ docker volume rm sample 
```

1.  执行上述命令后，仔细检查主机上的文件夹是否已被删除。

1.  为了清理系统，删除所有正在运行的容器，运行以下命令：

```
$ docker container rm -f $(docker container ls -aq)  
```

请注意，在用于删除容器的命令中使用`-v`或`--volume`标志，您可以要求系统同时删除与该特定容器关联的任何卷。当然，这只有在特定卷只被该容器使用时才有效。

在下一节中，我们将展示在使用 Docker for Desktop 时如何访问卷的后备文件夹。

# 访问使用 Docker for Desktop 创建的卷

按照以下步骤：

1.  让我们创建一个`sample`卷并使用我们的 macOS 或 Windows 机器上的 Docker for Desktop 进行检查，就像这样：

```
$ docker volume create sample
$ docker volume inspect sample
[
 {
 "CreatedAt": "2019-08-02T07:44:08Z",
 "Driver": "local",
 "Labels": {},
 "Mountpoint": "/var/lib/docker/volumes/sample/_data",
 "Name": "sample",
 "Options": {},
 "Scope": "local"
 }
]
```

`Mountpoint`显示为`/var/lib/docker/volumes/sample/_data`，但您会发现在您的 macOS 或 Windows 机器上没有这样的文件夹。原因是显示的路径是与 Docker for Windows 用于运行容器的隐藏 VM 相关的。此时，Linux 容器无法在 macOS 或 Windows 上本地运行。

1.  接下来，让我们从`alpine`容器内部生成两个带有卷数据的文件。要运行容器并将示例`volume`挂载到容器的`/data`文件夹，请使用以下代码：

```
$ docker container run --rm -it -v sample:/data alpine /bin/sh
```

1.  在容器内的`/data`文件夹中生成两个文件，就像这样：

```
/ # echo "Hello world" > /data/sample.txt
/ # echo "Other message" > /data/other.txt
```

1.  通过按*Ctrl + D*退出`alpine`容器。

如前所述，我们无法直接从我们的 macOS 或 Windows 访问`sample`卷的支持文件夹。这是因为该卷位于 macOS 或 Windows 上运行的隐藏 VM 中，该 VM 用于在 Docker for Desktop 中运行 Linux 容器。

要从我们的 macOS 访问隐藏的 VM，我们有两个选项。我们可以使用特殊容器并以特权模式运行它，或者我们可以使用`screen`实用程序来筛选 Docker 驱动程序。第一种方法也适用于 Windows 的 Docker。

1.  让我们从运行容器的`fundamentalsofdocker/nsenter`镜像开始尝试提到的第一种方法。我们在上一节中已经在使用这个容器。运行以下代码：

```
$ docker run -it --rm --privileged --pid=host fundamentalsofdocker/nsenter / #
```

1.  现在我们可以导航到支持我们`sample`卷的文件夹，就像这样：

```
/ # cd /var/lib/docker/volumes/sample/_data
```

通过运行此代码来查看此文件夹中有什么：

```
/ # ls -l 
total 8
-rw-r--r-- 1 root root 14 Aug 2 08:07 other.txt
-rw-r--r-- 1 root root 12 Aug 2 08:07 sample.txt
```

1.  让我们尝试从这个特殊容器内创建一个文件，然后列出文件夹的内容，如下所示：

```
/ # echo "I love Docker" > docker.txt
/ # ls -l total 12
-rw-r--r-- 1 root root 14 Aug 2 08:08 docker.txt
-rw-r--r-- 1 root root 14 Aug 2 08:07 other.txt
-rw-r--r-- 1 root root 12 Aug 2 08:07 sample.txt
```

现在，我们在`sample`卷的支持文件夹中有了文件。

1.  要退出我们的特权容器，只需按*Ctrl* + *D*。

1.  现在我们已经探索了第一种选项，如果您使用的是 macOS，让我们尝试`screen`工具，如下所示：

```
$ screen ~/Library/Containers/com.docker.docker/Data/com.docker.driver.amd64-linux/tty
```

1.  这样做，我们将会看到一个空屏幕。按*Enter*，将显示一个`docker-desktop:~#`命令行提示符。现在我们可以导航到卷文件夹，就像这样：

```
docker-desktop:~# cd /var/lib/docker/volumes/sample/_data
```

1.  让我们创建另一个带有一些数据的文件，然后列出文件夹的内容，如下所示：

```
docker-desktop:~# echo "Some other test" > test.txt 
docker-desktop:~# ls -l
total 16 -rw-r--r-- 1 root root 14 Aug 2 08:08 docker.txt -rw-r--r-- 1 root root 14 Aug 2 08:07 other.txt
-rw-r--r-- 1 root root 12 Aug 2 08:07 sample.txt
-rw-r--r-- 1 root root 16 Aug 2 08:10 test.txt
```

1.  要退出 Docker VM 的会话，请按*Ctrl* + *A* + *K*。

我们现在已经使用三种不同的方法创建了数据，如下所示：

+   +   从已挂载`sample`卷的容器内部。

+   使用特权文件夹来访问 Docker for Desktop 使用的隐藏虚拟机，并直接写入`sample`卷的后备文件夹。

+   仅在 macOS 上，使用`screen`实用程序进入隐藏的虚拟机，并直接写入`sample`卷的后备文件夹。

# 在容器之间共享数据

容器就像应用程序在其中运行的沙盒。这在很大程度上是有益的和需要的，以保护运行在不同容器中的应用程序。这也意味着对于在容器内运行的应用程序可见的整个文件系统对于这个应用程序是私有的，其他在不同容器中运行的应用程序不能干扰它。

有时，我们想要在容器之间共享数据。假设在容器 A 中运行的应用程序生成了一些数据，将被在容器 B 中运行的另一个应用程序使用。*我们该如何实现这一点？*好吧，我相信你已经猜到了——我们可以使用 Docker 卷来实现这一目的。我们可以创建一个卷，并将其挂载到容器 A，以及容器 B。这样，应用程序 A 和 B 都可以访问相同的数据。

现在，当多个应用程序或进程同时访问数据时，我们必须非常小心以避免不一致。为了避免并发问题，如竞争条件，理想情况下只有一个应用程序或进程创建或修改数据，而所有其他进程同时访问这些数据只读取它。我们可以通过将卷作为只读挂载来强制在容器中运行的进程只能读取卷中的数据。看一下以下命令：

```
$ docker container run -it --name writer \
 -v shared-data:/data \
 alpine /bin/sh
```

在这里，我们创建了一个名为`writer`的容器，它有一个卷`shared-data`，以默认的读/写模式挂载：

1.  尝试在这个容器内创建一个文件，就像这样：

```
# / echo "I can create a file" > /data/sample.txt 
```

它应该成功。

1.  退出这个容器，然后执行以下命令：

```
$ docker container run -it --name reader \
 -v shared-data:/app/data:ro \
 ubuntu:19.04 /bin/bash
```

我们有一个名为`reader`的容器，它有相同的卷挂载为**只读**(`ro`)。

1.  首先，确保你能看到在第一个容器中创建的文件，就像这样：

```
$ ls -l /app/data 
total 4
-rw-r--r-- 1 root root 20 Jan 28 22:55 sample.txt
```

1.  然后，尝试创建一个文件，就像这样：

```
# / echo "Try to break read/only" > /app/data/data.txt
```

它将失败，并显示以下消息：

```
bash: /app/data/data.txt: Read-only file system
```

1.  通过在命令提示符处输入`exit`来退出容器。回到主机上，让我们清理所有容器和卷，如下所示：

```
$ docker container rm -f $(docker container ls -aq) 
$ docker volume rm $(docker volume ls -q) 
```

1.  完成后，通过在命令提示符处输入 exit 退出 docker-machine VM。您应该回到您的 Docker for Desktop。使用 docker-machine 停止 VM，就像这样：

```
$ docker-machine stop node-1 
```

接下来，我们将展示如何将 Docker 主机中的任意文件夹挂载到容器中。

# 使用主机卷

在某些情况下，比如开发新的容器化应用程序或者容器化应用程序需要从某个文件夹中消耗数据——比如说——由传统应用程序产生，使用挂载特定主机文件夹的卷非常有用。让我们看下面的例子：

```
$ docker container run --rm -it \
 -v $(pwd)/src:/app/src \
 alpine:latest /bin/sh
```

前面的表达式交互式地启动一个带有 shell 的 alpine 容器，并将当前目录的 src 子文件夹挂载到容器的 /app/src。我们需要使用 $(pwd)（或者 ``pwd``，无论哪种方式），即当前目录，因为在使用卷时，我们总是需要使用绝对路径。

开发人员在他们在容器中运行的应用程序上工作时，经常使用这些技术，并希望确保容器始终包含他们对代码所做的最新更改，而无需在每次更改后重新构建镜像和重新运行容器。

让我们做一个示例来演示它是如何工作的。假设我们想要使用 nginx 创建一个简单的静态网站作为我们的 web 服务器，如下所示：

1.  首先，在主机上创建一个新的文件夹，我们将把我们的网页资产—如 HTML、CSS 和 JavaScript 文件—放在其中，并导航到它，就像这样：

```
$ mkdir ~/my-web 
$ cd ~/my-web 
```

1.  然后，我们创建一个简单的网页，就像这样：

```
$ echo "<h1>Personal Website</h1>" > index.html 
```

1.  现在，我们添加一个 `Dockerfile`，其中包含构建包含我们示例网站的镜像的说明。

1.  在文件夹中添加一个名为 `Dockerfile` 的文件，内容如下：

```
FROM nginx:alpine
COPY . /usr/share/nginx/html
```

Dockerfile 以最新的 Alpine 版本的 nginx 开始，然后将当前主机目录中的所有文件复制到 /usr/share/nginx/html 容器文件夹中。这是 nginx 期望网页资产位于的位置。

1.  现在，让我们用以下命令构建镜像：

```
$ docker image build -t my-website:1.0 . 
```

1.  最后，我们从这个镜像中运行一个容器。我们将以分离模式运行容器，就像这样：

```
$ docker container run -d \
 --name my-site \
 -p 8080:80 \
 my-website:1.0
```

注意 `-p 8080:80` 参数。我们还没有讨论这个，但我们将在第十章《单主机网络》中详细讨论。目前，只需知道这将把 nginx 监听传入请求的容器端口 80 映射到您的笔记本电脑的端口 8080，然后您可以访问应用程序。

1.  现在，打开一个浏览器标签，导航到`http://localhost:8080/index.html`，你应该看到你的网站，目前只包括一个标题，`个人网站`。

1.  现在，在你喜欢的编辑器中编辑`index.html`文件，使其看起来像这样：

```
<h1>Personal Website</h1> 
<p>This is some text</p> 
```

1.  现在保存它，然后刷新浏览器。哦！那没用。浏览器仍然显示`index.html`文件的先前版本，只包括标题。所以，让我们停止并删除当前容器，然后重建镜像，并重新运行容器，如下所示：

```
$ docker container rm -f my-site
$ docker image build -t my-website:1.0 .
$ docker container run -d \
 --name my-site \
   -p 8080:80 \
 my-website:1.0
```

这次，当你刷新浏览器时，新内容应该显示出来。好吧，它起作用了，但涉及的摩擦太多了。想象一下，每次对网站进行简单更改时都要这样做。这是不可持续的。

1.  现在是使用主机挂载卷的时候了。再次删除当前容器，并使用卷挂载重新运行它，就像这样：

```
$ docker container rm -f my-site
$ docker container run -d \
 --name my-site \
   -v $(pwd):/usr/share/nginx/html \
 -p 8080:80 \
 my-website:1.0
```

1.  现在，向`index.html`文件追加一些内容，并保存。然后，刷新你的浏览器。你应该看到变化。这正是我们想要实现的；我们也称之为*编辑和继续*体验。你可以对网页文件进行任意更改，并立即在浏览器中看到结果，而无需重建镜像和重新启动包含你的网站的容器。

重要的是要注意，更新现在是双向传播的。如果你在主机上进行更改，它们将传播到容器，反之亦然。同样重要的是，当你将当前文件夹挂载到容器目标文件夹`/usr/share/nginx/html`时，已经存在的内容将被主机文件夹的内容替换。

# 在镜像中定义卷

如果我们回顾一下我们在第三章中学到的关于容器的知识，*掌握容器*，那么我们有这样的情况：每个容器的文件系统在启动时由底层镜像的不可变层和特定于该容器的可写容器层组成。容器内运行的进程对文件系统所做的所有更改都将持久保存在该容器层中。一旦容器停止并从系统中删除，相应的容器层将从系统中删除并且不可逆地丢失。

一些应用程序，比如在容器中运行的数据库，需要将它们的数据持久保存超出容器的生命周期。在这种情况下，它们可以使用卷。为了更加明确，让我们看一个具体的例子。MongoDB 是一个流行的开源文档数据库。许多开发人员使用 MongoDB 作为他们应用程序的存储服务。MongoDB 的维护者已经创建了一个镜像，并将其发布到 Docker Hub，可以用来在容器中运行数据库的实例。这个数据库将产生需要长期持久保存的数据，但 MongoDB 的维护者不知道谁使用这个镜像以及它是如何被使用的。因此，他们对于用户启动这个容器的`docker container run`命令没有影响。*他们现在如何定义卷呢？*

幸运的是，在`Dockerfile`中有一种定义卷的方法。这样做的关键字是`VOLUME`，我们可以添加单个文件夹的绝对路径或逗号分隔的路径列表。这些路径代表容器文件系统的文件夹。让我们看一些这样的卷定义示例，如下：

```
VOLUME /app/data 
VOLUME /app/data, /app/profiles, /app/config 
VOLUME ["/app/data", "/app/profiles", "/app/config"] 
```

前面片段中的第一行定义了一个要挂载到`/app/data`的单个卷。第二行定义了三个卷作为逗号分隔的列表。最后一个与第二行定义相同，但这次值被格式化为 JSON 数组。

当容器启动时，Docker 会自动创建一个卷，并将其挂载到`Dockerfile`中定义的每个路径对应的容器目标文件夹。由于每个卷都是由 Docker 自动创建的，它将有一个 SHA-256 作为其 ID。

在容器运行时，在`Dockerfile`中定义为卷的文件夹被排除在联合文件系统之外，因此这些文件夹中的任何更改都不会改变容器层，而是持久保存到相应的卷中。现在，运维工程师有责任确保卷的后备存储得到适当备份。

我们可以使用`docker image inspect`命令来获取关于`Dockerfile`中定义的卷的信息。让我们按照以下步骤来看看 MongoDB 给我们的信息：

1.  首先，我们使用以下命令拉取镜像：

```
$ docker image pull mongo:3.7
```

1.  然后，我们检查这个镜像，并使用`--format`参数来从大量数据中提取必要的部分，如下：

```
 $ docker image inspect \
    --format='{{json .ContainerConfig.Volumes}}' \
    mongo:3.7 | jq . 
```

请注意命令末尾的`| jq .`。我们正在将`docker image inspect`的输出导入`jq`工具，它会很好地格式化输出。如果您尚未在系统上安装`jq`，您可以在 macOS 上使用`brew install jq`，或在 Windows 上使用`choco install jq`来安装。

上述命令将返回以下结果：

```
{
 "/data/configdb": {},
 "/data/db": {}
}
```

显然，MongoDB 的`Dockerfile`在`/data/configdb`和`/data/db`定义了两个卷。

1.  现在，让我们作为后台守护进程运行一个 MongoDB 实例，如下所示：

```
$ docker run --name my-mongo -d mongo:3.7
```

1.  我们现在可以使用`docker container inspect`命令获取有关已创建的卷等信息。

使用此命令只获取卷信息：

```
$ docker inspect --format '{{json .Mounts}}' my-mongo | jq .
```

前面的命令应该输出类似这样的内容（缩短）：

```
[
  {
    "Type": "volume",
    "Name": "b9ea0158b5...",
    "Source": "/var/lib/docker/volumes/b9ea0158b.../_data",
    "Destination": "/data/configdb",
    "Driver": "local",
    ...
  },
  {
    "Type": "volume",
    "Name": "5becf84b1e...",
    "Source": "/var/lib/docker/volumes/5becf84b1.../_data",
    "Destination": "/data/db",
    ...
  }
]
```

请注意，为了便于阅读，`Name`和`Source`字段的值已被修剪。`Source`字段为我们提供了主机目录的路径，MongoDB 在容器内生成的数据将存储在其中。

目前关于卷的内容就是这些。在下一节中，我们将探讨如何配置在容器中运行的应用程序，以及容器镜像构建过程本身。

# 配置容器

往往我们需要为容器内运行的应用程序提供一些配置。配置通常用于允许同一个容器在非常不同的环境中运行，例如开发、测试、暂存或生产环境。

在 Linux 中，通常通过环境变量提供配置值。

我们已经了解到，在容器内运行的应用程序与其主机环境完全隔离。因此，在主机上看到的环境变量与在容器内看到的环境变量是不同的。

让我们首先看一下在我们的主机上定义了什么：

1.  使用此命令：

```
$ export
```

在我的 macOS 上，我看到类似这样的东西（缩短）：

```
...
COLORFGBG '7;0'
COLORTERM truecolor
HOME /Users/gabriel
ITERM_PROFILE Default
ITERM_SESSION_ID w0t1p0:47EFAEFE-BA29-4CC0-B2E7-8C5C2EA619A8
LC_CTYPE UTF-8
LOGNAME gabriel
...
```

1.  接下来，让我们在`alpine`容器内运行一个 shell，并列出我们在那里看到的环境变量，如下所示：

```
$ docker container run --rm -it alpine /bin/sh
/ # export 
export HOME='/root'
export HOSTNAME='91250b722bc3'
export PATH='/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin'
export PWD='/'
export SHLVL='1'
export TERM='xterm'
```

我们从`export`命令看到的前面的输出显然与我们直接在主机上看到的完全不同。

1.  按下*Ctrl* + *D*离开`alpine`容器。

接下来，让我们为容器定义环境变量。

# 为容器定义环境变量

现在，好处是我们实际上可以在启动时将一些配置值传递到容器中。我们可以使用`--env`（或简写形式`-e`）参数以`--env <key>=<value>`的形式这样做，其中`<key>`是环境变量的名称，`<value>`表示与该变量关联的值。假设我们希望在容器中运行的应用程序能够访问名为`LOG_DIR`的环境变量，其值为`/var/log/my-log`。我们可以使用以下命令来实现：

```
$ docker container run --rm -it \
 --env LOG_DIR=/var/log/my-log \
 alpine /bin/sh
/ #
```

上述代码在`alpine`容器中启动了一个 shell，并在运行的容器内定义了所请求的环境。为了证明这是真的，我们可以在`alpine`容器内执行这个命令：

```
/ # export | grep LOG_DIR 
export LOG_DIR='/var/log/my-log'
```

输出看起来如预期的那样。我们现在确实在容器内有了所请求的环境变量和正确的值。

当然，当我们运行容器时，我们可以定义多个环境变量。我们只需要重复`--env`（或`-e`）参数。看一下这个示例：

```
$ docker container run --rm -it \
 --env LOG_DIR=/var/log/my-log \    --env MAX_LOG_FILES=5 \
 --env MAX_LOG_SIZE=1G \
 alpine /bin/sh
/ #
```

如果我们现在列出环境变量，我们会看到以下内容：

```
/ # export | grep LOG 
export LOG_DIR='/var/log/my-log'
export MAX_LOG_FILES='5'
export MAX_LOG_SIZE='1G'
```

让我们现在看一下我们有许多环境变量需要配置的情况。

# 使用配置文件

复杂的应用程序可能有许多环境变量需要配置，因此我们运行相应容器的命令可能会变得难以控制。为此，Docker 允许我们将环境变量定义作为文件传递，并且我们在`docker container run`命令中有`--env-file`参数。

让我们试一下，如下所示：

1.  创建一个`fod/05`文件夹并导航到它，就像这样：

```
$ mkdir -p ~/fod/05 && cd ~/fod/05
```

1.  使用您喜欢的编辑器在此文件夹中创建一个名为`development.config`的文件。将以下内容添加到文件中，并保存如下：

```
LOG_DIR=/var/log/my-log
MAX_LOG_FILES=5
MAX_LOG_SIZE=1G
```

注意我们每行定义一个环境变量的格式是`<key>=<value>`，其中，再次，`<key>`是环境变量的名称，`<value>`表示与该变量关联的值。

1.  现在，从`fod/05`文件夹中，让我们运行一个`alpine`容器，将文件作为环境文件传递，并在容器内运行`export`命令，以验证文件中列出的变量确实已经在容器内部创建为环境变量，就像这样：

```
$ docker container run --rm -it \
 --env-file ./development.config \
 alpine sh -c "export"
```

确实，变量已经被定义，正如我们在生成的输出中所看到的：

```
export HOME='/root'
export HOSTNAME='30ad92415f87'
export LOG_DIR='/var/log/my-log'
export MAX_LOG_FILES='5'
export MAX_LOG_SIZE='1G'
export PATH='/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin'
export PWD='/'
export SHLVL='1'
export TERM='xterm'
```

接下来，让我们看看如何为给定 Docker 镜像的所有容器实例定义环境变量的默认值。

# 在容器镜像中定义环境变量

有时，我们希望为必须存在于给定容器镜像的所有容器实例中的环境变量定义一些默认值。我们可以在用于创建该镜像的`Dockerfile`中这样做，按照以下步骤：

1.  使用您喜欢的编辑器在`~/fod/05`文件夹中创建一个名为`Dockerfile`的文件。将以下内容添加到文件中，并保存：

```
FROM alpine:latest
ENV LOG_DIR=/var/log/my-log
ENV  MAX_LOG_FILES=5
ENV MAX_LOG_SIZE=1G
```

1.  使用前述`Dockerfile`创建一个名为`my-alpine`的容器镜像，如下所示：

```
$ docker image build -t my-alpine .
```

从该镜像运行一个容器实例，输出容器内定义的环境变量，就像这样：

```
$ docker container run --rm -it \
    my-alpine sh -c "export | grep LOG" 
export LOG_DIR='/var/log/my-log'
export MAX_LOG_FILES='5'
export MAX_LOG_SIZE='1G'
```

这正是我们所期望的。

不过，好消息是，我们并不完全受困于这些变量值。我们可以使用`docker container run`命令中的`--env`参数覆盖其中一个或多个变量。看一下以下命令及其输出：

```
$ docker container run --rm -it \
    --env MAX_LOG_SIZE=2G \
    --env MAX_LOG_FILES=10 \
    my-alpine sh -c "export | grep LOG" 
export LOG_DIR='/var/log/my-log'
export MAX_LOG_FILES='10'
export MAX_LOG_SIZE='2G'
```

我们还可以使用环境文件和`docker container run`命令中的`--env-file`参数来覆盖默认值。请自行尝试。

# 构建时的环境变量

有时，我们希望在构建容器镜像时定义一些环境变量，这些变量在构建时是有效的。想象一下，你想定义一个`BASE_IMAGE_VERSION`环境变量，然后在你的`Dockerfile`中将其用作参数。想象一下以下的`Dockerfile`：

```
ARG BASE_IMAGE_VERSION=12.7-stretch
FROM node:${BASE_IMAGE_VERSION}
WORKDIR /app
COPY packages.json .
RUN npm install
COPY . .
CMD npm start
```

我们使用`ARG`关键字来定义一个默认值，每次从前述`Dockerfile`构建镜像时都会使用这个默认值。在这种情况下，这意味着我们的镜像使用`node:12.7-stretch`基础镜像。

现在，如果我们想为—比如—测试目的创建一个特殊的镜像，我们可以使用`--build-arg`参数在构建镜像时覆盖这个变量，如下所示：

```
$ docker image build \
 --build-arg BASE_IMAGE_VERSION=12.7-alpine \
 -t my-node-app-test .
```

在这种情况下，生成的`my-node-test:latest`镜像将从`node:12.7-alpine`基础镜像构建，而不是从`node:12.7-stretch`默认镜像构建。

总之，通过`--env`或`--env-file`定义的环境变量在容器运行时有效。在`Dockerfile`中使用`ARG`或在`docker container build`命令中使用`--build-arg`定义的变量在容器镜像构建时有效。前者用于配置容器内运行的应用程序，而后者用于参数化容器镜像构建过程。

# 总结

在本章中，我们介绍了 Docker 卷，可以用来持久保存容器产生的状态并使其持久。我们还可以使用卷来为容器提供来自各种来源的数据。我们已经学会了如何创建、挂载和使用卷。我们已经学会了各种定义卷的技术，例如按名称、通过挂载主机目录或在容器镜像中定义卷。

在这一章中，我们还讨论了如何配置环境变量，这些变量可以被容器内运行的应用程序使用。我们已经展示了如何在`docker container run`命令中定义这些变量，可以明确地一个一个地定义，也可以作为配置文件中的集合。我们还展示了如何通过使用构建参数来参数化容器镜像的构建过程。

在下一章中，我们将介绍常用的技术，允许开发人员在容器中运行代码时进行演变、修改、调试和测试。

# 问题

请尝试回答以下问题，以评估您的学习进度：

1.  如何创建一个名为`my-products`的命名数据卷，使用默认驱动程序？

1.  如何使用`alpine`镜像运行一个容器，并将`my-products`卷以只读模式挂载到`/data`容器文件夹中？

1.  如何找到与`my-products`卷关联的文件夹并导航到它？另外，您将如何创建一个带有一些内容的文件`sample.txt`？

1.  如何在另一个`alpine`容器中运行，并将`my-products`卷挂载到`/app-data`文件夹中，以读/写模式？在此容器内，导航到`/app-data`文件夹并创建一个带有一些内容的`hello.txt`文件。

1.  如何将主机卷（例如`~/my-project`）挂载到容器中？

1.  如何从系统中删除所有未使用的卷？

1.  在容器中运行的应用程序看到的环境变量列表与应用程序直接在主机上运行时看到的相同。

A. 真

B. 假

1.  您的应用程序需要在容器中运行，并为其配置提供大量环境变量。运行一个包含您的应用程序并向其提供所有这些信息的容器的最简单方法是什么？

# 进一步阅读

以下文章提供更深入的信息：

+   使用卷，在[`dockr.ly/2EUjTml`](http://dockr.ly/2EUjTml)

+   在 Docker 中管理数据，在[`dockr.ly/2EhBpzD`](http://dockr.ly/2EhBpzD)

+   **Play with Docker** (**PWD**)上的 Docker 卷，在[`bit.ly/2sjIfDj`](http://bit.ly/2sjIfDj)

+   `nsenter`—Linux man 页面，在[`bit.ly/2MEPG0n`](https://bit.ly/2MEPG0n)

+   设置环境变量，在[`dockr.ly/2HxMCjS`](https://dockr.ly/2HxMCjS)

+   了解`ARG`和`FROM`如何交互，在[`dockr.ly/2OrhZgx`](https://dockr.ly/2OrhZgx)


# 第六章：在容器中运行的代码调试

在上一章中，我们学习了如何处理有状态的容器，即消耗和产生数据的容器。我们还学习了如何使用环境变量和配置文件在运行时和镜像构建时配置我们的容器。

在本章中，我们将介绍常用的技术，允许开发人员在容器中运行时演变、修改、调试和测试他们的代码。有了这些技术，您将享受到在容器中运行应用程序时无摩擦的开发过程，类似于开发本地运行的应用程序时的体验。

以下是我们将讨论的主题列表：

+   在容器中运行的代码进行演变和测试

+   在更改后自动重新启动代码

+   在容器内逐行调试代码

+   为您的代码添加仪表，以产生有意义的日志信息

+   使用 Jaeger 进行监控和故障排除

完成本章后，您将能够做到以下事情：

+   将源代码挂载到运行中的容器中

+   配置在容器中运行的应用程序在代码更改后自动重新启动

+   配置 Visual Studio Code 以逐行调试在容器内运行的 Java、Node.js、Python 或.NET 编写的应用程序

+   从应用程序代码中记录重要事件

# 技术要求

在本章中，如果您想跟着代码进行操作，您需要在 macOS 或 Windows 上安装 Docker for Desktop 和一个代码编辑器——最好是 Visual Studio Code。该示例也适用于安装了 Docker 和 VS Code 的 Linux 机器。

# 在容器中运行的代码进行演变和测试

在开发最终将在容器中运行的代码时，通常最好的方法是从一开始就在容器中运行代码，以确保不会出现意外的情况。但是，我们必须以正确的方式来做这件事，以免在开发过程中引入不必要的摩擦。让我们首先看一下我们可以在容器中运行和测试代码的天真方式：

1.  创建一个新的项目文件夹并导航到它：

```
$ mkdir -p ~/fod/ch06 && cd ~/fod/ch06
```

1.  让我们使用`npm`来创建一个新的 Node.js 项目：

```
$ npm init
```

1.  接受所有默认设置。请注意，将创建一个`package.json`文件，内容如下：

```
{
  "name": "ch06",
  "version": "1.0.0",
  "description": "",
  "main": "index.js",
  "scripts": {
    "test": "echo \"Error: no test specified\" && exit 1"
  },
  "author": "",
  "license": "ISC"
}
```

1.  我们想在我们的 Node 应用程序中使用 Express.js 库；因此，使用`npm`来安装它：

```
$ npm install express --save
```

这将在我们的机器上安装最新版本的 Express.js，并且由于`--save`参数，会向我们的`package.json`文件添加一个类似于这样的引用：

```
"dependencies": {
  "express": "⁴.17.1"
}
```

1.  从该文件夹中启动 VS Code：

```
$ code .
```

1.  在 VS Code 中，创建一个新的`index.js`文件，并将以下代码片段添加到其中。不要忘记保存：

```
const express = require('express');
const app = express();

app.listen(3000, '0.0.0.0', ()=>{
    console.log('Application listening at 0.0.0.0:3000');
})

app.get('/', (req,res)=>{
    res.send('Sample Application: Hello World!');
})
```

1.  从终端窗口中再次启动应用程序：

```
$ node index.js
```

您应该看到以下输出：

```
Application listening at 0.0.0.0:3000
```

这意味着应用程序正在运行并准备在`0.0.0.0:3000`上监听。您可能会问自己主机地址`0.0.0.0`的含义是什么，为什么我们选择了它。稍后我们会回到这个问题，当我们在容器内运行应用程序时。暂时只需知道`0.0.0.0`是一个具有特殊含义的保留 IP 地址，类似于环回地址`127.0.0.1`。`0.0.0.0`地址简单地意味着*本地机器上的所有 IPv4 地址*。如果主机有两个 IP 地址，比如`52.11.32.13`和`10.11.0.1`，并且在主机上运行的服务器监听`0.0.0.0`，它将在这两个 IP 上可达。

1.  现在在您喜欢的浏览器中打开一个新标签，并导航到`localhost:3000`。您应该看到这个：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/lrn-dkr-2e/img/90516b3c-77d7-4443-9850-c5483270a0ea.png)

在浏览器中运行的示例 Node.js 应用程序

太好了——我们的 Node.js 应用程序正在我们的开发者机器上运行。在终端中按*Ctrl* + *C*停止应用程序。

1.  现在我们想通过在容器内运行来测试我们迄今为止开发的应用程序。为此，我们首先必须创建一个`Dockerfile`，以便我们可以构建一个容器镜像，然后从中运行一个容器。让我们再次使用 VS Code 将一个名为`Dockerfile`的文件添加到我们的项目文件夹中，并给它以下内容：

```
FROM node:latest
WORKDIR /app
COPY package.json ./
RUN npm install
COPY . .
CMD node index.js
```

1.  然后我们可以使用这个`Dockerfile`来构建一个名为`sample-app`的镜像，如下所示：

```
$ docker image build -t sample-app .
```

1.  构建后，使用以下命令在容器中运行应用程序：

```
$ docker container run --rm -it \
    --name my-sample-app \
    -p 3000:3000 \
    sample-app
```

上述命令从容器镜像`sample-app`运行一个名为`my-sample-app`的容器，并将容器端口`3000`映射到等效的主机端口。端口映射是必要的；否则，我们无法从容器外部访问在容器内运行的应用程序。我们将在*第十章*，*单主机网络*中学到更多关于端口映射的知识。

与我们在主机上直接运行应用程序时类似，输出如下：

```
Application listening at 0.0.0.0:3000
```

1.  刷新之前的浏览器标签（或者打开一个新的浏览器标签并导航到`localhost:3000`，如果你关闭了它）。你应该看到应用程序仍然运行，并产生与本地运行时相同的输出。这很好。我们刚刚证明了我们的应用不仅在我们的主机上运行，而且在容器内部也可以运行。

1.  通过在终端中按*Ctrl* + *C*停止和删除容器。

1.  现在让我们修改我们的代码并添加一些额外的功能。我们将在`/hobbies`处定义另一个`HTTP GET`端点。请将以下代码片段添加到您的`index.js`文件中：

```
const hobbies = [
  'Swimming', 'Diving', 'Jogging', 'Cooking', 'Singing'
];

app.get('/hobbies', (req,res)=>{
  res.send(hobbies);
})
```

我们可以首先在主机上运行应用程序，通过`node index.js`运行应用程序，并在浏览器中导航到`localhost:3000/hobbies`。我们应该在浏览器窗口中看到预期的输出。测试完成后，不要忘记使用*Ctrl* + *C*停止应用程序。

1.  接下来，我们需要测试代码在容器内运行时的情况。因此，首先，我们创建一个新版本的容器映像：

```
$ docker image build -t sample-app .
```

1.  接下来，我们从这个新映像运行一个容器：

```
$ docker container run --rm -it \
    --name my-sample-app \
    -p 3000:3000 \
    sample-app 
```

现在，我们可以在浏览器中导航到`localhost:3000/hobbies`，并确认应用程序在容器内部也按预期工作。再次强调，测试完成后，请不要忘记通过按*Ctrl* + *C*停止容器。

我们可以一遍又一遍地重复这一系列任务，为我们添加的每个功能或改进的现有功能。事实证明，与我们开发的所有应用程序都直接在主机上运行的时候相比，这增加了很多摩擦。

然而，我们可以做得更好。在下一节中，我们将看一种技术，它允许我们消除大部分摩擦。

# 将不断发展的代码装载到正在运行的容器中

如果在代码更改后，我们不必重新构建容器映像并重新运行容器呢？如果我们在编辑器（如 VS Code）中保存更改后，更改立即在容器内部可用，这不是很好吗？好吧，使用卷映射确实可以做到这一点。在上一章中，我们学习了如何将任意主机文件夹映射到容器内的任意位置。我们想要在本节中利用这一点。

在*第五章*中，*数据卷和配置*，我们看到了如何将主机文件夹映射为容器中的卷。例如，如果我想要将主机文件夹`/projects/sample-app`挂载到容器中的`/app`，则其语法如下：

```
$ docker container run --rm -it \
 --volume /projects/sample-app:/app \
 alpine /bin/sh
```

注意行`--volume <host-folder>:<container-folder>`。主机文件夹的路径需要是绝对路径，就像示例中的`/projects/sample-app`一样。

如果我们现在想要从我们的`sample-app`容器映像运行一个容器，并且如果我们从项目文件夹中这样做，那么我们可以将当前文件夹映射到容器的`/app`文件夹中，如下所示：

```
$ docker container run --rm -it \
 --volume $(pwd):/app \
    -p 3000:3000 \
```

请注意`$(pwd)`代替主机文件夹路径。`$(pwd)`会计算为当前文件夹的绝对路径，这非常方便。

现在，如果我们按照上述描述将当前文件夹挂载到容器中，那么`sample-app`容器映像的`/app`文件夹中的内容将被映射主机文件夹的内容覆盖，也就是在我们的情况下是当前文件夹。这正是我们想要的 - 我们希望将主机中的当前源映射到容器中。

让我们测试一下是否有效：

1.  如果您已经启动了容器，请按*Ctrl* + *C*停止它。

1.  然后将以下代码片段添加到`index.js`文件的末尾：

```
app.get('/status', (req,res)=>{
  res.send('OK');
})
```

不要忘记保存。

1.  然后再次运行容器 - 这次不需要先重新构建镜像 - 看看会发生什么：

```
$ docker container run --rm -it \
    --name my-sample-app \
 --volume $(pwd):/app \
 -p 3000:3000 \
 sample-app
```

1.  在浏览器中，导航到`localhost:3000/status`，并期望在浏览器窗口中看到`OK`输出。或者，您可以在另一个终端窗口中使用`curl`。

```
$ curl localhost:3000/status
OK
```

对于所有在 Windows 和/或 Docker for Windows 上工作的人，您可以使用 PowerShell 命令`Invoke-WebRequest`或`iwr`代替`curl`。然后，前面命令的等效命令将是`iwr -Url localhost:3000/status`。

1.  暂时让容器中的应用程序继续运行，并进行另一个更改。我们不仅希望在导航到`/status`时返回`OK`，还希望返回消息“OK，一切正常”。进行修改并保存更改。

1.  然后再次执行`curl`命令，或者如果您使用了浏览器，请刷新页面。你看到了什么？没错 - 什么也没发生。我们所做的更改没有反映在运行的应用程序中。

1.  好吧，让我们再次仔细检查更改是否已在运行的容器中传播。为此，让我们执行以下命令：

```
$ docker container exec my-sample-app cat index.js
```

我们应该看到类似这样的东西 - 我已经缩短了输出以便阅读：

```
...
app.get('/hobbies', (req,res)=>{
 res.send(hobbies);
})

app.get('/status', (req,res)=>{
 res.send('OK, all good');
})
...
```

显然，我们的更改已经按预期传播到容器中。那么，为什么更改没有反映在运行的应用程序中呢？嗯，答案很简单：要应用更改到应用程序，必须重新启动应用程序。

1.  让我们试试看。通过按*Ctrl* + *C*停止运行应用程序的容器。然后重新执行前面的`docker container run`命令，并使用`curl`来探测端点`localhost:3000/status`。现在，应该显示以下新消息：

```
$ curl localhost:3000/status
 OK, all good
```

因此，通过在运行的容器中映射源代码，我们在开发过程中实现了摩擦的显著减少。现在，我们可以添加新的或修改现有的代码并进行测试，而无需首先构建容器镜像。然而，仍然存在一些摩擦。每次想要测试一些新的或修改过的代码时，我们必须手动重新启动容器。我们能自动化这个过程吗？答案是肯定的！我们将在下一节中具体演示这一点。

# 在更改后自动重启代码

很好，在上一节中，我们展示了如何通过在容器中进行源代码文件的卷映射来大大减少摩擦，从而避免不断重建容器镜像和重新运行容器。

但我们仍然感到一些摩擦。容器内运行的应用程序在代码更改发生时不会自动重启。因此，我们必须手动停止和重新启动容器才能应用新的更改。

# Node.js 的自动重启

如果你编程一段时间了，肯定听说过一些有用的工具，可以在发现代码库中的更改时运行应用程序并自动重启它们。对于 Node.js 应用程序，最流行的工具就是`nodemon`。我们可以使用以下命令在系统上全局安装`nodemon`：

```
$ npm install -g nodemon
```

现在，有了`nodemon`，我们可以不再用`node index.js`在主机上启动应用程序，而是直接执行`nodemon`，我们应该会看到以下内容：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/lrn-dkr-2e/img/22d2758a-af1d-4dde-8ad2-130203229506.png)

使用 nodemon 运行 Node.js 应用程序

显然，`nodemon`已经从解析我们的`package.json`文件中认识到，它应该使用`node index.js`作为启动命令。

现在尝试更改一些代码，例如，在`index.js`的末尾添加以下代码片段，然后保存文件：

```
app.get('/colors', (req,res)=>{
 res.send(['red','green','blue']);
})
```

看一下终端窗口。你看到有什么发生了吗？你应该看到这个额外的输出：

```
[nodemon] restarting due to changes...
[nodemon] starting `node index.js`
Application listening at 0.0.0.0:3000
```

这清楚地表明`nodemon`已经认识到了一些更改，并自动重新启动了应用程序。通过浏览器尝试一下，导航到`localhost:3000/colors`。你应该在浏览器中看到以下预期的输出：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/lrn-dkr-2e/img/83c6ee39-05cc-4c27-a7d2-c609feb6f425.png)

获取颜色

这很酷——你得到了这个结果，而不必手动重新启动应用程序。这使我们又多了一点生产力。现在，我们能在容器内做同样的事情吗？是的，我们可以。我们不会使用在我们的`Dockerfile`的最后一行中定义的启动命令`node index.js`：

```
CMD node index.js
```

我们将使用`nodemon`代替。

我们需要修改我们的`Dockerfile`吗？还是我们需要两个不同的`Dockerfiles`，一个用于开发，一个用于生产？

我们的原始`Dockerfile`创建了一个不幸不包含`nodemon`的镜像。因此，我们需要创建一个新的`Dockerfile`。让我们称之为`Dockerfile-dev`。它应该是这样的：

```
FROM node:latest          
RUN npm install -g nodemon
WORKDIR /app
COPY package.json ./
RUN npm install
COPY . .
CMD nodemon
```

与我们的原始 Dockerfile 相比，我们添加了第 2 行，安装了`nodemon`。我们还改变了最后一行，现在使用`nodemon`作为我们的启动命令。

让我们按照以下方式构建我们的开发镜像：

```
$ docker image build -t sample-app-dev .
```

我们将像这样运行一个容器：

```
$ docker container run --rm -it \
   -v $(pwd):/app \
   -p 3000:3000 \
   sample-app-dev
```

现在，当应用程序在容器中运行时，改变一些代码，保存，并注意到容器内的应用程序会自动重新启动。因此，我们在容器中运行时实现了与直接在主机上运行时相同的减少摩擦。

你可能会问，这只适用于 Node.js 吗？不，幸运的是，许多流行的语言支持类似的概念。

# Python 的自动重启

让我们看看同样的东西在 Python 中是如何工作的：

1.  首先，为我们的示例 Python 应用程序创建一个新的项目文件夹，并导航到它：

```
$ mkdir -p ~/fod/ch06/python && cd ~/fod/ch06/python
```

1.  使用命令`code .`从这个文件夹中打开 VS Code。

1.  我们将创建一个使用流行的 Flask 库的示例 Python 应用程序。因此，向这个文件夹添加一个`requirements.txt`文件，其中包含`flask`的内容。

1.  接下来，添加一个`main.py`文件，并给它这个内容：

```
from flask import Flask
app = Flask(__name__)

@app.route("/")
def hello():
  return "Hello World!"

if __name__ == "__main__":
  app.run()
```

这是一个简单的**Hello World**类型的应用程序，在`localhost:5000/`上实现了一个 RESTful 端点。

1.  在我们可以运行和测试这个应用程序之前，我们需要安装依赖项——在我们的情况下是 Flask。在终端中运行以下命令：

```
$ pip install -r requirements.txt
```

这应该在你的主机上安装 Flask。我们现在准备好了。

1.  在使用 Python 时，我们也可以使用`nodemon`来在代码发生任何更改时自动重新启动我们的应用程序。例如，假设你的启动 Python 应用程序的命令是`python main.py`。那么你只需要像下面这样使用`nodemon`：

```
$ nodemon main.py
```

你应该看到这个：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/lrn-dkr-2e/img/ad1953cc-ef81-47b5-98a3-f1e499a79d2e.png)

1.  使用`nodemon`启动和监视 Python 应用程序，我们可以使用`curl`测试该应用程序，并应该看到这个：

```
$ curl localhost:5000/
Hello World!
```

1.  现在让我们通过将此片段添加到`main.py`中的`/`端点的定义之后，并保存来修改代码：

```
from flask import jsonify

@app.route("/colors")
def colors():
   return jsonify(["red", "green", "blue"])
```

`nodemon`将发现更改并重新启动 Python 应用程序，正如我们可以在终端产生的输出中看到的那样：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/lrn-dkr-2e/img/4a5a9882-9ffa-4e7c-b3f4-96291e0a18a8.png)

nodemon 发现 Python 代码的更改

1.  再次，相信是好的，测试更好。因此，让我们再次使用我们的朋友`curl`来探测新的端点，看看我们得到了什么：

```
$ curl localhost:5000/colors
["red", "green", "blue"]
```

很好-它有效！有了这个，我们已经涵盖了 Python。.NET 是另一个流行的平台。让我们看看在.NET 上开发 C#应用程序时是否可以做类似的事情。

# .NET 的自动重启

我们的下一个候选者是用 C#编写的.NET 应用程序。让我们看看.NET 中的自动重启是如何工作的。

1.  首先，为我们的示例 C#应用程序创建一个新的项目文件夹并导航到它：

```
$ mkdir -p ~/fod/ch06/csharp && cd ~/fod/ch06/csharp
```

如果您以前没有这样做，请在您的笔记本电脑或工作站上安装.NET Core。您可以在[`dotnet.microsoft.com/download/dotnet-core`](https://dotnet.microsoft.com/download/dotnet-core)上获取它。在撰写本文时，版本 2.2 是当前稳定版本。安装完成后，使用`dotnet --version`检查版本。对我来说是`2.2.401`。

1.  导航到本章的源文件夹：

```
$ cd ~/fod/ch06
```

1.  从这个文件夹内，使用`dotnet`工具创建一个新的 Web API，并将其放在`dotnet`子文件夹中：

```
$ dotnet new webapi -o dotnet
```

1.  导航到这个新项目文件夹：

```
$ cd dotnet
```

1.  再次使用`code .`命令从`dotnet`文件夹内打开 VS Code。

如果这是您第一次使用 VS Code 打开.NET Core 2.2 项目，那么编辑器将开始下载一些 C#依赖项。等到所有依赖项都下载完成。编辑器可能还会显示一个弹出窗口，询问您是否要为我们的`dotnet`项目添加缺少的依赖项。在这种情况下点击“是”按钮。

在 VS Code 的项目资源管理器中，您应该看到这个：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/lrn-dkr-2e/img/e3bc6adf-1a8c-47a6-abaa-c82a45273bf6.png)

在 VS Code 项目资源管理器中的 DotNet Web API 项目

1.  请注意`Controllers`文件夹中的`ValuesController.cs`文件。打开此文件并分析其内容。它包含了`ValuesController`类的定义，该类实现了一个简单的 RESTful 控制器，其中包含`GET`、`PUT`、`POST`和`DELETE`端点在`api/values`。

1.  从您的终端运行应用程序使用 `dotnet run`。您应该会看到类似以下内容：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/lrn-dkr-2e/img/ce9234ee-0777-4f2a-b923-096fa5eed231.png)

在主机上运行.NET 示例 Web API

1.  我们可以使用 `curl` 测试应用程序，例如：

```
$ curl --insecure https://localhost:5001/api/values ["value1","value2"]
```

应用程序运行并返回了预期的结果。

请注意，默认情况下，该应用程序配置为将 `http://localhost:5000` 重定向到 `https://localhost:5001`。但是，这是一个不安全的端点，为了抑制警告，我们使用 `--insecure` 开关。

1.  现在我们可以尝试修改 `ValuesController.cs` 中的代码，并从第一个 `GET` 端点返回三个项目而不是两个。

```
[HttpGet]
public ActionResult<IEnumerable<string>> Get()
{
    return new string[] { "value1", "value2", "value3" };
}
```

1.  保存您的更改并重新运行 `curl` 命令。注意结果不包含新添加的值。这与我们观察到的 Node.js 和 Python 的问题相同。要查看新更新的返回值，我们需要（手动）重新启动应用程序。

1.  因此，在您的终端中，使用 *Ctrl* + *C* 停止应用程序，并使用 `dotnet run` 重新启动。再次尝试 `curl` 命令。结果现在应该反映您的更改。

1.  幸运的是，`dotnet` 工具有 `watch` 命令。通过按 *Ctrl* + *C* 停止应用程序并执行 `dotnet watch run`。您应该会看到类似以下内容的输出：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/lrn-dkr-2e/img/301a815c-a80b-481b-9dc9-62e4c3c3b1c4.png)

使用 watch 任务运行.NET 示例应用程序

注意前面输出的第二行，指出正在运行的应用程序现在正在监视更改。

1.  在 `ValuesController.cs` 中进行另一个更改；例如，在第一个 `GET` 端点的返回值中添加第四个项目并保存。观察终端中的输出。它应该看起来像这样：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/lrn-dkr-2e/img/9fba6353-e07a-4a10-b126-527c6a8db185.png)

自动重新启动正在运行的.NET Core 示例应用程序

1.  通过对代码进行更改，应用程序会自动重新启动，结果立即对我们可用，并且我们可以通过运行 `curl` 命令轻松测试它：

```
$ curl --insecure https://localhost:5001/api/values ["value1","value2","value3","value4"]
```

1.  现在我们在主机上有自动重启工作，我们可以编写一个 Dockerfile，在容器内运行的应用程序也可以实现相同的功能。在 VS Code 中，向项目添加一个名为 `Dockerfile-dev` 的新文件，并向其中添加以下内容：

```
FROM mcr.microsoft.com/dotnet/core/sdk:2.2
WORKDIR /app
COPY dotnet.csproj ./
RUN dotnet restore
COPY . .
CMD dotnet watch run
```

1.  在我们继续构建容器镜像之前，我们需要对.NET 应用程序的启动配置进行轻微修改，使得 Web 服务器（在这种情况下是 Kestrel）监听，例如，`0.0.0.0:3000`，因此能够在容器内运行并且能够从容器外部访问。打开`Program.cs`文件，并对`CreateWebHostBuilder`方法进行以下修改：

```
public static IWebHostBuilder CreateWebHostBuilder(string[] args) =>
    WebHost.CreateDefaultBuilder(args)
    .UseUrls("http://0.0.0.0:3000")
    .UseStartup<Startup>();
```

通过`UseUrls`方法，我们告诉 Web 服务器监听所需的端点。

现在我们准备构建容器镜像：

1.  使用以下命令构建镜像：

```
$ docker image build -f Dockerfile-dev -t sample-app-dotnet .
```

1.  一旦镜像构建完成，我们就可以从中运行一个容器：

```
$ docker container run --rm -it \
   -p 3000:3000 \
   -v $(pwd):/app \
   sample-app-dotnet
```

我们应该看到类似于本地运行时看到的输出：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/lrn-dkr-2e/img/4b6f2740-1d2a-41ce-9da3-757f75512528.png)

在容器中运行的.NET 示例应用程序

1.  让我们用我们的朋友`curl`来测试应用程序：

```
$ curl localhost:3000/api/values
["value1","value2","value3","value4"]
$
$ curl localhost:3000/api/values/1
value
```

这里没有什么意外——它按预期工作。

1.  现在让我们在控制器中进行代码更改，然后保存。观察终端窗口中发生的情况。我们应该看到类似于这样的输出：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/lrn-dkr-2e/img/7f7041fc-6e7e-4f62-b663-1f828997d1fa.png)

在容器内运行的.NET 示例应用程序的自动重启

好吧，这正是我们所期望的。通过这样做，我们已经消除了在开发.NET 应用程序时使用容器引入的大部分摩擦。

# 在容器内逐行代码调试

在我们深入讨论容器内运行代码的逐行调试之前，让我先做一个声明。你将在这里学到的东西通常应该是你最后的选择，如果其他方法都不起作用的话。理想情况下，在开发应用程序时遵循测试驱动的方法，由于你已经为它编写了单元测试和集成测试，并对代码进行了测试，所以代码大部分是可以保证工作的，这些测试也是在容器中运行的。或者，如果单元测试或集成测试不能为你提供足够的洞察力，你确实需要逐行调试你的代码，你可以在主机上直接运行你的代码，从而利用开发环境的支持，比如 Visual Studio、Eclipse 或 IntelliJ 等 IDE。

通过这一切准备，你应该很少需要手动调试你的代码，因为它是在容器内运行的。也就是说，让我们看看你如何做到这一点！

在本节中，我们将专注于如何在使用 Visual Studio Code 时进行调试。其他编辑器和 IDE 可能或可能不提供类似的功能。

# 调试 Node.js 应用程序

我们将从最简单的开始——一个 Node.js 应用程序。我们将使用我们在本章早些时候使用过的`~/fod/ch06/node`文件夹中的示例应用程序：

1.  确保您导航到此项目文件夹并从其中打开 VS Code：

```
$ cd ~/fod/ch06/node
$ code .
```

1.  在终端窗口中，从项目文件夹内部，运行一个带有我们示例 Node.js 应用程序的容器：

```
$ docker container run --rm -it \
   --name my-sample-app \
   -p 3000:3000 \
   -p 9229:9229 \
   -v $(pwd):/app \
   sample-app node --inspect=0.0.0.0 index.js
```

注意我是如何将端口`9229`映射到主机的。这个端口是调试器使用的，VS Studio 将通过这个端口与我们的 Node 应用程序通信。因此，重要的是您打开这个端口——但只在调试会话期间！还要注意，我们用`node --inspect=0.0.0.0 index.js`覆盖了 Dockerfile 中定义的标准启动命令（`node index.js`）。`--inspect=0.0.0.0`告诉 Node 以调试模式运行，并在容器中监听所有 IP4 地址。

现在我们准备为手头的场景定义一个 VS Code 启动任务，也就是我们的代码在容器内运行：

1.  要打开`launch.json`文件，按*Ctrl*+*Shift*+*P*（或在 Windows 上按*Ctrl*+*Shift*+*P*）打开命令面板，然后搜索`Debug:Open launch.json`并选择它。`launch.json`文件应该在编辑器中打开。

1.  点击蓝色的“Add Configuration...”按钮，添加我们需要在容器内调试的新配置。

1.  从选项中选择`Docker: Attach to Node`。新条目将被添加到`launch.json`文件的配置列表中。它应该看起来类似于这样：

```
{
  "type": "node",
  "request": "attach",
  "name": "Docker: Attach to Node",
  "remoteRoot": "/usr/src/app"
},
```

由于我们的代码在`/app`文件夹中，容器内部，我们需要相应地更改`remoteRoot`的值。将`/usr/src/app`的值更改为`/app`。不要忘记保存您的更改。就是这样，我们已经准备好了。

1.  通过按下*command* + *Shift* + *D*（在 Windows 上为*Ctrl* + *Shift* + *D*）来打开 VS Code 中的调试视图。

1.  确保您在视图顶部的绿色启动按钮旁边的下拉菜单中选择正确的启动任务。选择`Docker: Attach to Node`如下所示：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/lrn-dkr-2e/img/b1ea1249-cad6-4c9a-86af-5fc24de37ce6.png)

在 VS Code 中选择正确的启动任务进行调试

1.  接下来，点击绿色的启动按钮，将 VS Code 连接到运行在容器中的 Node 应用程序。

1.  在编辑器中打开`index.js`，并在调用端点'/'时在返回消息`"Sample Application: Hello World!"`的行上设置断点。

1.  在另一个终端窗口中，使用`curl`导航到`localhost:3000/`，并观察代码执行是否在断点处停止：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/lrn-dkr-2e/img/65e22b06-430b-48ec-ab33-d522d29b3480.png)

代码执行在断点处停止

在前面的屏幕截图中，我们可以看到黄色条表示代码执行已在断点处停止。在右上角，我们有一个工具栏，允许我们浏览代码，例如，逐步执行。在左侧，我们看到`VARIABLES`，`WATCH`和`CALL STACK`窗口，我们可以使用它们来观察我们运行的应用程序的细节。我们真正调试运行在容器内的代码的事实可以通过在启动容器的终端窗口中看到输出`Debugger attached.`来验证，这是我们在 VS Code 中开始调试时生成的。

让我们看看如何进一步改进调试体验：

1.  要停止容器，请在终端中输入以下命令：

```
$ docker container rm -f my-sample-app
```

1.  如果我们想要使用`nodemon`来获得更大的灵活性，那么我们必须稍微改变`container run`命令：

```
$ docker container run --rm -it \
   --name my-sample-app \
   -p 3000:3000 \
   -p 9229:9229 \
   -v $(pwd):/app \
   sample-app-dev nodemon --inspect=0.0.0.0 index.js
```

注意我们如何使用启动命令`nodemon --inspect=0.0.0.0 index.js`。这将带来一个好处，即在任何代码更改时，容器内运行的应用程序将自动重新启动，就像我们在本章前面学到的那样。您应该看到以下内容：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/lrn-dkr-2e/img/8379cd11-64ae-4823-b772-f879d145b95a.png)

使用 nodemon 启动 Node.js 应用程序并打开调试功能

1.  不幸的是，应用程序重新启动的后果是调试器与 VS Code 失去了连接。但别担心，我们可以通过在`launch.json`文件中的启动任务中添加`"restart": true`来减轻这一点。修改任务，使其看起来像这样：

```
{
  "type": "node",
  "request": "attach",
  "name": "Docker: Attach to Node",
  "remoteRoot": "/app",
  "restart": true
},
```

1.  保存更改后，通过单击调试窗口中的绿色启动按钮在 VS Code 中启动调试器。在终端中，您应该再次看到输出`Debugger attached.`。除此之外，VS Code 在底部显示一个橙色状态栏，指示编辑器处于调试模式。

1.  在另一个终端窗口中，使用`curl`并尝试导航到`localhost:3000/`，以测试逐行调试是否仍然有效。确保代码执行在代码中设置的任何断点处停止。

1.  一旦您验证了调试仍然有效，请尝试修改一些代码；例如，将消息`"Sample Application: Hello World!"`更改为`"Sample Application: Message from within container"`，然后保存您的更改。观察`nodemon`如何重新启动应用程序，并且调试器自动重新附加到容器内运行的应用程序：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/lrn-dkr-2e/img/2786f876-ec6c-47de-b54a-79dc3cde1e03.png)

`nodemon`重新启动应用程序，并且调试器自动重新附加到应用程序

有了这些，我们现在可以像在主机上本地运行相同的代码一样，在容器内运行代码。我们已经基本上消除了引入容器带来的开发过程中的所有摩擦。现在我们可以享受在容器中部署代码的好处。

清理时，按*Ctrl* + *C*停止容器。

# 调试.NET 应用程序

现在我们想快速介绍一下如何逐行调试.NET 应用程序。我们将使用本章前面创建的示例.NET 应用程序。

1.  转到项目文件夹并从其中打开 VS Code：

```
$ cd ~/fod/ch06/dotnet
$ code .
```

1.  要使用调试器，我们首先需要在容器中安装调试器。因此，让我们在项目目录中创建一个新的`Dockerfile`。将其命名为`Dockerfile-debug`并添加以下内容：

```
FROM mcr.microsoft.com/dotnet/core/sdk:2.2
RUN apt-get update && apt-get install -y unzip && \
    curl -sSL https://aka.ms/getvsdbgsh | \
        /bin/sh /dev/stdin -v latest -l ~/vsdbg
WORKDIR /app
COPY dotnet.csproj ./
RUN dotnet restore
COPY . .
CMD dotnet watch run
```

请注意`Dockerfile`的第二行，它使用`apt-get`安装`unzip`工具，然后使用`curl`下载并安装调试器。

1.  我们可以按照以下方式从这个`Dockerfile`构建一个名为`sample-app-dotnet-debug`的镜像：

```
$ docker image build -t sample-app-dotnet-debug .
```

这个命令可能需要一些时间来执行，因为调试器需要下载和安装。

1.  完成后，我们可以从这个镜像中交互式运行一个容器：

```
$ docker run --rm -it \
   -v $(pwd):/app \
   -w /app \
   -p 3000:3000 \
   --name my-sample-app \
   --hostname sample-app \
   sample-app-dotnet-debug
```

我们会看到类似这样的东西：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/lrn-dkr-2e/img/eecd50e0-5674-474a-b60d-600c956d815a.png)

在 SDK 容器内交互式启动示例.NET 应用程序

1.  在 VS Code 中，打开`launch.json`文件并添加以下启动任务：

```
{
   "name": ".NET Core Docker Attach",
   "type": "coreclr",
   "request": "attach",
   "processId": "${command:pickRemoteProcess}",
   "pipeTransport": {
      "pipeProgram": "docker",
      "pipeArgs": [ "exec", "-i", "my-sample-app" ],
      "debuggerPath": "/root/vsdbg/vsdbg",
      "pipeCwd": "${workspaceRoot}",
      "quoteArgs": false
   },
   "sourceFileMap": {
      "/app": "${workspaceRoot}"
   },
   "logging": {
      "engineLogging": true
   }
},
```

1.  保存您的更改，并切换到 VS Code 的调试窗口（使用*command* + *Shift* + *D*或*Ctrl* + *Shift* + *D *打开它）。确保您已选择了正确的调试启动任务——它的名称是`.NET Core Docker Attach`：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/lrn-dkr-2e/img/f4744775-bcb8-4275-add7-0236bbcf96c1.png)

在 VS Code 中选择正确的调试启动任务

1.  现在单击绿色的启动按钮启动调试器。因此，弹出窗口显示了要附加到的潜在进程列表。选择看起来像下面截图中标记的进程。

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/lrn-dkr-2e/img/d80edd11-6973-4b92-a886-569ddbd47bda.png)

选择要附加调试器的进程

1.  让我们在`ValuesController.cs`文件的第一个`GET`请求中设置一个断点，然后执行一个`curl`命令：

```
$ curl localhost:3000/api/values
```

代码执行应该在断点处停止，如下所示：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/lrn-dkr-2e/img/86642156-418e-4b9a-a322-7638e3970993.png)

在容器内运行的.NET Core 应用程序进行逐行调试

1.  现在我们可以逐步执行代码，定义观察点，或者分析应用程序的调用堆栈，类似于我们在示例 Node.js 应用程序中所做的。单击调试工具栏上的“继续”按钮或按*F5*继续执行代码。

1.  现在更改一些代码并保存更改。观察终端窗口中应用程序如何自动重新启动。

1.  再次使用`curl`测试您的更改是否对应用程序可见。确实，更改是可用的，但您是否注意到了什么？是的，代码执行没有从断点开始。不幸的是，重新启动应用程序会导致调试器断开连接。您必须通过单击 VS Code 调试视图中的启动按钮并选择正确的进程来重新附加调试器。

1.  要停止应用程序，请在启动容器的终端窗口中按*Ctrl* + *C*。

现在我们知道如何逐行调试容器中运行的代码，是时候为我们的代码添加有意义的日志信息了。

# 为您的代码添加有意义的日志信息

一旦应用程序在生产环境中运行，就不可能或者强烈不建议交互式调试应用程序。因此，当系统行为异常或引起错误时，我们需要想出其他方法来找到根本原因。最好的方法是让应用程序生成详细的日志信息，然后开发人员可以使用这些信息来跟踪任何错误。由于日志记录是如此常见的任务，所有相关的编程语言或框架都提供了使应用程序内部生成日志信息的库。

将应用程序输出的信息分类为日志，并称为严重级别是很常见的。以下是这些严重级别的列表，以及每个的简短描述：

| **安全级别** | **解释** |
| --- | --- |
| TRACE | 非常精细的信息。在这个级别，您正在捕获关于应用程序行为的每一个可能的细节。 |
| DEBUG | 相对细粒度和大多数诊断信息，有助于确定潜在问题。 |
| INFO | 正常的应用程序行为或里程碑。 |
| WARN | 应用程序可能遇到问题，或者您检测到异常情况。 |
| ERROR | 应用程序遇到严重问题。这很可能代表了重要应用程序任务的失败。 |
| FATAL | 应用程序的灾难性失败。建议立即关闭应用程序。 |

生成日志信息时使用的严重级别列表

日志库通常允许开发人员定义不同的日志接收器，即日志信息的目的地。常见的接收器是文件接收器或控制台流。在使用容器化应用程序时，强烈建议始终将日志输出定向到控制台或`STDOUT`。然后 Docker 将通过`docker container logs`命令向您提供此信息。还可以使用其他日志收集器，如 Prometheus，来抓取此信息。

# 为 Python 应用程序进行仪器化

现在让我们尝试为我们现有的 Python 示例应用程序进行仪器化：

1.  首先，在您的终端中，导航到项目文件夹并打开 VS Code：

```
$ cd ~/fob/ch06/python
$ code .
```

1.  打开`main.py`文件，并在顶部添加以下代码片段：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/lrn-dkr-2e/img/871e4924-7ec2-432a-a734-32236d84e6dd.png)

为我们的 Python 示例应用程序定义一个记录器

在第`1`行，我们导入标准的`logging`库。然后我们在第`3`行为我们的示例应用程序定义一个`logger`。在第`4`行，我们定义要使用的日志过滤器。在这种情况下，我们将其设置为`WARN`。这意味着应用程序产生的所有日志消息，其严重程度等于或高于`WARN`，将被输出到在本节开头称为`logging`处理程序或接收器的定义。在我们的情况下，只有具有`WARN`、`ERROR`或`FATAL`日志级别的日志消息将被输出。

在第`6`行，我们创建了一个日志接收器或处理程序。在我们的情况下，它是`StreamHandler`，输出到`STDOUT`。然后，在第`8`行，我们定义了我们希望`logger`如何格式化输出的消息。在这里，我们选择的格式将输出时间和日期、应用程序（或`logger`）名称、日志严重级别，最后是我们开发人员在代码中定义的实际消息。在第`9`行，我们将格式化程序添加到日志处理程序中，在第`10`行，我们将处理程序添加到`logger`中。请注意，我们可以为每个 logger 定义多个处理程序。现在我们准备使用`logger`了。

1.  让我们来对`hello`函数进行仪器化，当我们导航到端点`/`时会调用该函数：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/lrn-dkr-2e/img/fd0e1528-73d0-4dc2-9f33-1b788f7a9049.png)

使用日志记录对方法进行仪器化

如您在上面的截图中所见，我们在第`17`行添加了一行，我们在那里使用`logger`对象生成了一个日志级别为`INFO`的日志消息。消息是："访问端点'/'"。

1.  让我们对另一个函数进行仪器化，并输出一个日志级别为`WARN`的消息：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/lrn-dkr-2e/img/2e8a0fd1-181f-42ac-9222-60b87d106f48.png)

生成一个警告

这一次，我们在`colors`函数的第`24`行以`WARN`日志级别生成了一条消息。到目前为止，一切都很顺利——这并不难！

1.  现在让我们运行应用程序，看看我们得到什么输出：

```
$ python main.py
```

1.  然后，在浏览器中，首先导航到`localhost:5000/`，然后导航到`localhost:5000/colors`。您应该看到类似于这样的输出：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/lrn-dkr-2e/img/94cb7b3f-8a45-4b3d-a3ee-4888acffcac0.png)

运行经过仪器化的示例 Python 应用程序

如您所见，只有警告被输出到控制台；`INFO`消息没有。这是由于我们在定义 logger 时设置的过滤器。还请注意，我们的日志消息是如何以日期和时间开头，然后是 logger 的名称，日志级别，最后是我们在应用程序的第`24`行定义的实际消息。完成后，请按*Ctrl* + *C*停止应用程序。

# 对.NET C#应用程序进行仪器化

现在让我们对我们的示例 C#应用程序进行仪器化：

1.  首先，导航到项目文件夹，从那里您将打开 VS Code：

```
$ cd ~/fod/ch06/dotnet
$ code .
```

1.  接下来，我们需要向项目添加一个包含日志库的 NuGet 包：

```
$ dotnet add package Microsoft.Extensions.Logging
```

这应该会将以下行添加到您的`dotnet.csproj`项目文件中：

```
<PackageReference  Include="Microsoft.Extensions.Logging"  Version="2.2.0"  />
```

1.  打开`Program.cs`类，并注意我们在第`21`行调用了`CreateDefaultBuilder(args)`方法。

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/lrn-dkr-2e/img/cc3af0cf-28b2-4e96-a70e-738c8e871f1b.png)

在 ASP.NET Core 2.2 中配置日志记录

默认情况下，此方法向应用程序添加了一些日志提供程序，其中包括控制台日志提供程序。这非常方便，使我们无需进行任何复杂的配置。当然，您可以随时使用自己的设置覆盖默认设置。

1.  接下来，在`Controllers`文件夹中打开`ValuesController.cs`文件，并在文件顶部添加以下`using`语句：

```
using Microsoft.Extensions.Logging;
```

1.  然后，在类主体中，添加一个名为`_logger`的实例变量，类型为`ILogger`，并添加一个具有类型为`ILogger<T>`的参数的构造函数。将此参数分配给实例变量`_logger`：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/lrn-dkr-2e/img/114ba9e1-3443-46be-8da0-70cb5f48bde9.png)

为 Web API 控制器定义一个记录器

1.  现在我们准备在控制器方法中使用记录器。让我们使用`INFO`消息对`Get`方法进行调试：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/lrn-dkr-2e/img/98f9a43a-89d6-4850-993c-3d1f0253e917.png)

从 API 控制器记录 INFO 消息

1.  现在让我们对`Get(int id)`方法进行一些调试：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/lrn-dkr-2e/img/161ac8ba-ad9b-43a9-9cbe-b3151ddf2062.png)

使用日志级别 WARN 和 ERROR 记录消息

在第 31 行，我们让记录器生成一个 DEBUG 消息，然后在第 32 行对`id`的意外值进行一些逻辑处理，并生成 ERROR 消息并返回 HTTP 响应状态 404（未找到）。

1.  让我们使用以下内容运行应用程序：

```
$ dotnet run
```

1.  当导航到`localhost:3000/api/values`时，我们应该看到这个：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/lrn-dkr-2e/img/7b90f29e-efdc-4077-ba5e-40260a5a84ad.png)

访问端点`/api/values`时我们示例.NET 应用程序的日志

我们可以看到我们的 INFO 类型的日志消息输出。所有其他日志项都是由 ASP.NET Core 库生成的。您可以看到如果需要调试应用程序，则有大量有用的信息可用。

1.  现在让我们尝试使用无效的`{id}`值访问端点`/api/values/{id}`。我们应该看到类似于以下内容：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/lrn-dkr-2e/img/872f1f7b-a2ac-4fd4-9fd1-f40e69862d30.png)

我们的.NET 示例应用程序生成的调试和错误日志项

我们首先可以清楚地看到级别为`DEBUG`的日志项，然后是级别为`ERROR`的日志项。输出中后者标记为`fail`并以红色显示。

1.  完成后，请使用*Ctrl +* C 结束应用程序。

现在我们已经了解了如何进行调试，接下来我们将在下一节中学习 Jaeger。

# 使用 Jaeger 进行监视和故障排除

当我们想要监视和排查复杂分布式系统中的事务时，我们需要比我们刚刚学到的更强大的东西。当然，我们可以并且应该继续用有意义的日志消息来仪器化我们的代码，但我们需要更多的东西。这*更多*是追踪单个请求或事务的能力，从而使其在由许多应用服务组成的系统中流动时，我们可以端到端地追踪它。理想情况下，我们还希望捕获其他有趣的指标，比如在每个组件上花费的时间与请求所花费的总时间。

幸运的是，我们不必重新发明轮子。有经过实战考验的开源软件可以帮助我们实现上述目标。这样一个基础设施组件或软件的例子就是 Jaeger（[`www.jaegertracing.io/`](https://www.jaegertracing.io/)）。使用 Jaeger 时，您运行一个中央 Jaeger 服务器组件，每个应用组件都使用一个 Jaeger 客户端，该客户端会将调试和跟踪信息透明地转发到 Jaeger 服务器组件。对于所有主要的编程语言和框架，如 Node.js、Python、Java 和.NET，都有 Jaeger 客户端。

我们不会在本书中详细介绍如何使用 Jaeger 的所有细节，但会对其工作原理进行高层次的概述：

1.  首先，我们定义一个 Jaeger`tracer`对象。这个对象基本上协调了我们的分布式应用程序中追踪请求的整个过程。我们可以使用这个`tracer`对象，还可以从中创建一个`logger`对象，我们的应用代码可以使用它来生成日志项，类似于我们在之前的 Python 和.NET 示例中所做的。

1.  接下来，我们需要用 Jaeger 称为`span`的代码来包装每个方法。`span`有一个名称，并为我们提供一个`scope`对象。让我们看一些 C#伪代码，以说明这一点：

```
public void SayHello(string helloTo) {
  using(var scope = _tracer.BuildSpan("say-hello").StartActive(true)) {
    // here is the actual logic of the method
    ...
    var helloString = FormatString(helloTo);
    ...
  }
}
```

正如你所看到的，我们正在为`SayHello`方法进行仪器化。通过使用`using`语句创建一个 span，我们将整个该方法的应用代码进行包装。我们将 span 命名为`"say-hello"`，这将是我们在 Jaeger 生成的跟踪日志中用来识别该方法的 ID。

请注意，该方法调用另一个嵌套方法`FormatString`。就需要为其进行仪器化所需的代码而言，这个方法看起来会非常相似：

```
public void string Format(string helloTo) {
   using(var scope = _tracer.BuildSpan("format-string").StartActive(true)) {
       // here is the actual logic of the method
       ...
       _logger.LogInformation(helloTo);
       return 
       ...
   }
}
```

我们的`tracer`对象在此方法中构建的 span 将是调用方法的子 span。这里的子 span 称为`"format-string"`。还要注意，我们在前面的方法中使用`logger`对象显式生成了一个级别为`INFO`的日志项。

在本章附带的代码中，您可以找到一个完整的 C#示例应用程序，其中包括一个 Jaeger 服务器容器和两个应用程序容器，称为客户端和库，它们使用 Jaeger 客户端库来对代码进行仪器化。

1.  转到项目文件夹：

```
$ cd ~/fod/ch06/jaeger-sample
```

1.  接下来，启动 Jaeger 服务器容器：

```
$ docker run -d --name jaeger \
   -e COLLECTOR_ZIPKIN_HTTP_PORT=9411 \
   -p 5775:5775/udp \
   -p 6831:6831/udp \
   -p 6832:6832/udp \
   -p 5778:5778 \
   -p 16686:16686 \
   -p 14268:14268 \
   -p 9411:9411 \
   jaegertracing/all-in-one:1.13
```

1.  接下来，我们需要运行 API，它是作为 ASP.NET Core 2.2 Web API 组件实现的。转到`api`文件夹并启动组件：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/lrn-dkr-2e/img/94b336c6-7649-43d3-8dc2-7687bf922446.png)

启动 Jaeger 示例的 API 组件

1.  现在打开一个新的终端窗口，然后进入`client`子文件夹，然后运行应用程序：

```
$ cd ~/fod/ch06/jaeger-sample/client
 $ dotnet run Gabriel Bonjour
```

请注意我传递的两个参数—`Gabriel`和`Bonjour`—它们对应于`<name>`和`<greeting>`。您应该看到类似于这样的内容：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/lrn-dkr-2e/img/8eccae4c-eeaa-4704-9253-17e52bb39e7a.png)

运行 Jaeger 示例应用程序的客户端组件

在前面的输出中，您可以看到用红色箭头标记的三个 span，从最内部到最外部的 span。我们还可以使用 Jaeger 的图形界面来查看更多细节：

1.  在浏览器中，转到`http://localhost:16686`以访问 Jaeger UI。

1.  在搜索面板中，确保选择了`hello-world`服务。将操作保留为`all`，然后点击`Find Traces`按钮。您应该看到以下内容：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/lrn-dkr-2e/img/7824fa13-dd4b-4f0e-94aa-b0c6e6f15989.png)

Jaeger UI 的搜索视图

1.  现在点击（唯一的）条目`hello-world: say-hello`以查看该请求的详细信息：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/lrn-dkr-2e/img/4832a62b-7d0c-473f-b4a5-079070ae44f2.png)

Jaeger 报告的请求细节

在前面的截图中，我们可以看到请求是如何从`hello-world`组件的`say-hello`方法开始，然后导航到同一组件中的`format-string`方法，然后调用`Webservice`中的一个端点，其逻辑是在`FormatController`控制器中实现的。对于每一步，我们都可以看到确切的时间以及其他有趣的信息。您可以在此视图中深入了解更多细节。

在继续之前，您可能想花些时间浏览一下我们刚刚用于此演示的 API 和`client`组件的代码。

1.  清理时，请停止 Jaeger 服务器容器：

```
$ docker container rm -f jaeger
```

同时停止 API，使用*Ctrl* + *C*。

# 摘要

在本章中，我们学习了如何调试在容器内运行的 Node.js、Python、Java 和.NET 代码。我们首先通过将主机的源代码挂载到容器中，以避免每次代码更改时重新构建容器映像。然后，我们进一步简化了开发过程，通过在代码更改时在容器内启用自动应用程序重启。接下来，我们学习了如何配置 Visual Studio Code 以启用在容器内运行的代码的完全交互式调试。最后，我们学习了如何对我们的应用程序进行配置，使其生成日志信息，这些信息可以帮助我们对在生产环境中运行的失败或行为不端的应用程序或应用程序服务进行根本原因分析。

在下一章中，我们将展示如何使用 Docker 容器可以加速您的自动化，从在容器中运行简单的自动化任务，到使用容器构建 CI/CD 流水线。

# 问题

请尝试回答以下问题，以评估您的学习进度：

1.  列举两种有助于减少容器使用引入的开发过程中的摩擦的方法。

1.  如何实现容器内代码的实时更新？

1.  在何时以及为什么会使用在容器内运行的代码的逐行调试？

1.  为什么在代码中加入良好的调试信息至关重要？

# 进一步阅读

+   使用 Docker 进行实时调试：[`www.docker.com/blog/live-debugging-docker/`](https://www.docker.com/blog/live-debugging-docker/)

+   在本地 Docker 容器中调试应用程序：[`docs.microsoft.com/en-us/visualstudio/containers/edit-and-refresh?view=vs-2019`](https://docs.microsoft.com/en-us/visualstudio/containers/edit-and-refresh?view=vs-2019)

+   使用 IntelliJ IDEA*在 Docker 中调试您的 Java 应用程序：[`blog.jetbrains.com/idea/2019/04/debug-your-java-applications-in-docker-using-intellij-idea/`](https://blog.jetbrains.com/idea/2019/04/debug-your-java-applications-in-docker-using-intellij-idea/)
