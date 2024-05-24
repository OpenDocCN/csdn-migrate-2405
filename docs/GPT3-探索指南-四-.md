# GPT3 探索指南（四）

> 原文：[`zh.annas-archive.org/md5/e19ec4b9c1d08c12abd2983dace7ff20`](https://zh.annas-archive.org/md5/e19ec4b9c1d08c12abd2983dace7ff20)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第七章：Docker 存储

概述

在本章中，您将学习 Docker 如何管理数据。了解在哪里存储数据以及您的服务将如何访问它是至关重要的。本章将探讨无状态与有状态的 Docker 容器运行，并深入探讨不同应用程序存储的配置设置选项。到本章结束时，您将能够区分 Docker 中不同的存储类型，并识别容器的生命周期及其各种状态。您还将学习如何创建和管理 Docker 卷。

# 介绍

在之前的章节中，您学习了如何从镜像运行容器以及如何配置其网络。您还学习了在从镜像创建容器时可以传递各种 Docker 命令。在本章中，您将学习如何在创建容器后控制这些容器。

假设您被指派为电子商店构建一个网络应用程序。您将需要一个数据库来存储产品目录、客户信息和购买交易。为了存储这些细节，您需要配置应用程序的存储设置。

Docker 中有两种类型的数据存储。第一种是与容器生命周期紧密耦合的存储。如果容器被移除，该存储类型上的文件也将被移除且无法检索。这些文件存储在容器本身内部的薄读/写层中。这种存储类型也被称为其他术语，例如本地存储、`graphdriver`存储和存储驱动程序。本章的第一部分专注于这种存储类型。这些文件可以是任何类型，例如，在基础镜像之上安装新层后 Docker 创建的文件。

本章的第二部分探讨了无状态和有状态服务。有状态应用程序是需要持久存储的应用程序，例如持久且超越容器生存期的数据库。在有状态服务中，即使容器被移除，数据仍然可以被访问。

容器以两种方式在主机上存储数据：通过卷和绑定挂载。不推荐使用绑定挂载，因为绑定挂载会将主机上的现有文件或目录绑定到容器内的路径。这种绑定增加了在主机上使用完整或相对路径的负担。然而，当您使用卷时，在主机上的 Docker 存储目录中创建一个新目录，并且 Docker 管理目录的内容。我们将在本章的第三部分专注于使用卷。

在探索 Docker 中不同类型的存储之前，让我们先探索容器的生命周期。

# 容器生命周期

容器是从其基本镜像中制作的。容器通过在图像层堆栈的顶部创建一个薄的读/写层来继承图像的文件系统。基本镜像保持完整，不对其进行任何更改。所有更改都发生在容器的顶层。例如，假设您创建了一个`ubuntu:14.08`的容器。这个镜像中没有`wget`软件包。当您安装`wget`软件包时，实际上是在顶层安装它。因此，您有一个用于基本镜像的层，以及另一个用于`wget`的层。

如果您也安装了`Apache`服务器，它将成为前两层之上的第三层。要保存所有更改，您需要将所有这些更改提交到新的镜像，因为您不能覆盖基本镜像。如果您不将更改提交到新镜像，这些更改将随容器的移除而被删除。

容器在其生命周期中经历许多其他状态，因此重要的是要了解容器在其生命周期中可能具有的所有状态。因此，让我们深入了解不同的容器状态：

![图 7.1：容器生命周期](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-ws/img/B15021_07_01.jpg)

图 7.1：容器生命周期

容器经历的不同阶段如下：

+   使用`docker container run`子命令，容器进入`CREATED`状态，如*图 7.1*所示。

+   在每个容器内部，都有一个主要的进程在运行。当这个进程开始运行时，容器的状态会变为`UP`状态。

+   使用`docker container pause`子命令，容器的状态变为`UP(PAUSED)`。容器被冻结或暂停，但仍处于`UP`状态，没有停止或移除。

+   要恢复运行容器，请使用`docker container unpause`子命令。在这里，容器的状态将再次变为`UP`状态。

+   使用`docker container stop`子命令停止容器而不删除它。容器的状态将变为`EXITED`状态。

+   容器将在执行`docker container kill`或`docker container stop`子命令时退出。要杀死容器，请使用`docker container kill`子命令。容器状态将变为`EXITED`。但是，要使容器退出，应该使用`docker container stop`子命令而不是`docker container kill`子命令。不要杀死你的容器；总是删除它们，因为删除容器会触发对容器的优雅关闭，给予时间，例如将数据保存到数据库，这是一个较慢的过程。然而，杀死不会这样做，可能会导致数据不一致。

+   在停止或杀死容器后，您还可以恢复运行容器。要启动容器并将其返回到`UP`状态，请使用`docker container start`或`docker container start -a`子命令。`docker container start -a`等同于运行`docker container start`然后`docker container attach`。您不能将本地标准输入、输出和错误流附加到已退出的容器；容器必须首先处于`UP`状态才能附加本地标准输入、输出和错误流。

+   要重新启动容器，请使用`docker container restart`子命令。重新启动子命令的作用类似于执行`docker container stop`，然后执行`docker container start`。

+   停止或杀死容器不会从系统中删除容器。要完全删除容器，请使用`docker container rm`子命令。

注意

您可以将几个 Docker 命令连接在一起 - 例如，`docker container rm -f $(docker container ls -aq)`。您想要首先执行的命令应包含在括号中。

在这种情况下，`docker container ls -aq`告诉 Docker 以安静模式列出所有容器，甚至是已退出的容器。`-a`选项表示显示所有容器，无论它们的状态如何。`-q`选项用于安静模式，这意味着仅显示数字 ID，而不是所有容器的详细信息。此命令的输出`docker container ls -aq`将成为`docker container rm -f`命令的输入。

了解 Docker 容器生命周期事件可以为某些应用程序是否需要持久存储提供良好的背景。在继续讨论 Docker 中存在的不同存储类型之前，让我们执行上述命令并在以下练习中探索不同的容器状态。

注意

请使用`touch`命令创建文件，并使用`vim`命令使用 vim 编辑器处理文件。

## 练习 7.01：通过 Docker 容器的常见状态进行过渡

ping www.google.com 是验证服务器或集群节点是否连接到互联网的常见做法。在这个练习中，您将在检查服务器或集群节点是否连接到互联网的同时，经历 Docker 容器的所有状态。

在这个练习中，您将使用两个终端。一个终端将用于运行一个容器来 ping www.google.com，另一个终端将用于通过执行先前提到的命令来控制这个正在运行的容器。

要 ping www.google.com，您将从`ubuntu:14.04`镜像中创建一个名为`testevents`的容器：

1.  打开第一个终端并执行`docker container run`命令来运行一个容器。使用`--name`选项为容器指定一个特定的昵称，例如`testevents`。不要让 Docker 主机为您的容器生成一个随机名称。使用`ubuntu:14.04`镜像和`ping google.com`命令来验证服务器是否在容器上运行：

```
$docker container run --name testevents ubuntu:14.04 ping google.com
```

输出将如下所示：

```
PING google.com (172.217.165.142) 56(84) bytes of data.
64 bytes from lax30s03-in-f14.1e100.net (172.217.165.142):
icmp_seq=1 ttl=115 time=68.9 ms
64 bytes from lax30s03-in-f14.1e100.net (172.217.165.142):
icmp_seq=2 ttl=115 time=349 ms
64 bytes from lax30s03-in-f14.1e100.net (172.217.165.142):
icmp_seq=3 ttl=115 time=170 ms
```

如前面的输出所示，ping 已经开始。您将发现数据包正在传输到`google.com`。

1.  将第一个终端用于 ping 输出。现在，通过在另一个终端中执行命令来控制此容器。在第二个终端中，执行`docker container ls`以列出所有正在运行的容器：

```
$docker container ls
```

查找名称为`testevents`的容器。状态应为`Up`：

```
CONTAINER ID    IMAGE           COMMAND            CREATED
   STATUS           PORTS          NAMES
10e235033813     ubuntu:14.04   "ping google.com"  10 seconds ago
   Up 5 seconds                    testevents
```

1.  现在，在第二个终端中运行`docker container pause`命令来暂停第一个终端中正在运行的容器：

```
$docker container pause testevents
```

您将看到 ping 已经停止，不再传输数据包。

1.  再次使用第二个终端中的`docker container ls`列出正在运行的容器：

```
$docker container ls
```

如下面的输出所示，`testevents`的状态为`Up(Paused)`。这是因为您之前运行了`docker container pause`命令：

```
CONTAINER ID    IMAGE         COMMAND            CREATED
   STATUS            PORTS          NAMES
10e235033813    ubuntu:14.04  "ping google.com"  26 seconds ago
   Up 20 seconds (Paused)           testevents
```

1.  在第二个终端中使用 `docker container unpause` 来启动暂停的容器，并使其恢复发送数据包：

```
$docker container unpause testevents
```

您会发现 ping 恢复，并且在第一个终端中传输新的数据包。

1.  在第二个终端中，再次运行 `docker container ls` 命令以查看容器的当前状态：

```
$docker container ls
```

您将看到 `testevents` 容器的状态是 `Up`：

```
CONTAINER ID    IMAGE         COMMAND            CREATED
   STATUS            PORTS          NAMES
10e235033813    ubuntu:14.04  "ping google.com"  43 seconds ago
   Up 37 seconds                    testevents
```

1.  现在，运行 `docker container stop` 命令来停止容器：

```
$docker container stop testevents
```

您将观察到容器退出，并且在第一个终端中返回了 shell 提示符：

```
64 bytes from lax30s03-in-f14.1e100.net (142.250.64.110):
icmp_seq = 42 ttl=115 time=19.8 ms
64 bytes from lax30s03-in-f14.1e100.net (142.250.64.110):
icmp_seq = 43 ttl=115 time=18.7 ms
```

1.  现在，在任何终端中运行 `docker container ls` 命令：

```
$docker container ls
```

您会发现 `testevents` 容器不再在列表中，因为 `docker container ls` 子命令只显示正在运行的容器：

```
CONTAINER ID      IMAGE      COMMAND     CREATED
        STATUS         PORTS                   NAMES
```

1.  运行 `docker container ls -a` 命令来显示所有容器：

```
$docker container ls -a
```

您可以看到 `testevents` 容器的状态现在是 `Exited`：

```
CONTAINER ID    IMAGE         COMMAND            CREATED
   STATUS            PORTS          NAMES
10e235033813    ubuntu:14.04  "ping google.com"  1 minute ago
   Exited (137) 13 seconds ago      testevents
```

1.  使用 `docker container start` 命令来启动容器。另外，添加 `-a` 选项来附加本地标准输入、输出和错误流到容器，并查看其输出：

```
$docker container start -a testevents
```

如您在以下片段中所见，ping 恢复并在第一个终端中执行：

```
64 bytes from lax30s03-in-f14.1e100.net (142.250.64.110):
icmp_seq = 55 ttl=115 time=63.5 ms
64 bytes from lax30s03-in-f14.1e100.net (142.250.64.110):
icmp_seq = 56 ttl=115 time=22.2 ms
```

1.  在第二个终端中再次运行 `docker ls` 命令：

```
$docker container ls
```

您将观察到 `testevents` 返回到列表中，其状态为 `Up`，并且正在运行：

```
CONTAINER ID    IMAGE         COMMAND            CREATED
   STATUS            PORTS          NAMES
10e235033813    ubuntu:14.04  "ping google.com"  43 seconds ago
   Up 37 seconds                    testevents
```

1.  现在，使用带有 `-f` 选项的 `rm` 命令来删除 `testevents` 容器。 `-f` 选项用于强制删除容器：

```
$docker container rm -f testevents
```

第一个终端停止执行 `ping` 命令，第二个终端将返回容器的名称：

```
testevents
```

1.  运行 `ls -a` 命令来检查容器是否正在运行：

```
$docker container ls -a
```

您将在列表中找不到 `testevents` 容器，因为我们刚刚从系统中删除了它。

现在，您已经看到了容器的各种状态，除了 `CREATED`。这是很正常的，因为通常不会看到 `CREATED` 状态。在每个容器内部，都有一个主进程，其 **进程 ID (PID)** 为 0，**父进程 ID (PPID)** 为 1。此进程在容器外部具有不同的 ID。当此进程被终止或移除时，容器也会被终止或移除。通常情况下，当主进程运行时，容器的状态会从 `CREATED` 改变为 `UP`，这表明容器已成功创建。如果主进程失败，容器状态不会从 `CREATED` 改变，这就是您要设置的内容：

1.  运行以下命令以查看`CREATED`状态。使用`docker container run`命令从`ubuntu:14.04`镜像创建一个名为`testcreate`的容器：

```
$docker container run --name testcreate ubuntu:14.04 time
```

`time`命令将生成一个错误，因为`ubuntu:14.04`中没有这样的命令。

1.  现在，列出正在运行的容器：

```
$docker container ls
```

您会看到列表是空的：

```
CONTAINER ID    IMAGE         COMMAND            CREATED
   STATUS            PORTS          NAMES
```

1.  现在，通过添加`-a`选项列出所有的容器：

```
$docker container ls -a
```

在列表中查找名为`testcreate`的容器；您会观察到它的状态是`Created`：

```
CONTAINER ID    IMAGE         COMMAND         CREATED
   STATUS            PORTS          NAMES
C262e6718724    ubuntu:14.04  "time"          30 seconds ago
   Created                          testcreate
```

如果一个容器停留在`CREATED`状态，这表明已经生成了一个错误，并且 Docker 无法使容器运行起来。

在这个练习中，您探索了容器的生命周期及其不同的状态。您还学会了如何使用`docker container start -a <container name or ID>`命令开始附加，并使用`docker container rm <container name or ID>`停止容器。最后，我们讨论了如何使用`docker container rm -f <container name or ID>`强制删除正在运行的容器。然后，我们看到了`CREATED`的罕见情况，只有在命令生成错误并且容器无法启动时才会显示。

到目前为止，我们已经关注容器的状态而不是其大小。在下一个练习中，我们将学习如何确定容器所占用的内存大小。

## 练习 7.02：检查磁盘上容器的大小

当您首次创建一个容器时，它的大小与基础镜像相同，并带有一个顶部的读/写层。随着每个添加到容器中的层，其大小都会增加。在这个练习中，您将创建一个以`ubuntu:14.04`作为基础镜像的容器。在其上更新并安装`wget`以突出状态转换对数据保留的影响：

1.  使用`-it`选项运行`docker container run`命令以创建一个名为`testsize`的容器。`-it`选项用于在运行的容器内部运行命令时具有交互式终端：

```
$docker container run -it --name testsize ubuntu:14.04
```

提示现在会变成`root@<container ID>:/#`，其中容器 ID 是 Docker Engine 生成的一个数字。因此，当您在自己的机器上运行此命令时，会得到一个不同的数字。如前所述，处于容器内意味着容器将处于`UP`状态。

1.  将第一个终端专用于运行的容器，并在第二个终端中执行命令。有两个终端可以避免我们分离容器来运行命令，然后重新附加到容器以在其中运行另一个命令。

现在，验证容器最初是否具有`ubuntu:14.04`基础镜像的大小。使用`docker image ls`命令在第二个终端中列出镜像。检查`ubuntu:14.04`镜像的大小：

```
$docker image ls
```

如下输出所示，镜像的大小为`188MB`：

```
REPOSITORY     TAG      IMAGE ID         CREATED
  SIZE
ubuntu         14.04    971bb3841501     23 months ago
  188MB
```

1.  现在，通过运行`docker container ls -s`命令来检查容器的大小：

```
$docker container ls -s
```

寻找`testsize`容器。您会发现大小为`0B（虚拟 188MB）`：

```
CONTAINER ID    IMAGE          COMMAND      CREATED
  STATUS     PORTS    NAMES      SIZE
9f2d2d1ee3e0    ubuntu:14.04   "/bin/bash"  6 seconds ago
  Up 6 minutes        testsize   0B (virtual 188MB)
```

`SIZE`列指示容器的薄读/写层的大小，而虚拟大小指示容器中封装的所有先前层的薄读/写层的大小。因此，在这种情况下，薄层的大小为`0B`，虚拟大小等于镜像大小。

1.  现在，安装`wget`软件包。在第一个终端中运行`apt-get update`命令。在 Linux 中，一般建议在安装任何软件包之前运行`apt-get update`以更新系统上当前软件包的最新版本：

```
root@9f2d2d1ee3e0: apt-get update
```

1.  当容器完成更新后，运行以下命令以在基础镜像上安装`wget`软件包。使用`-y`选项自动回答所有安装问题为是。

```
root@9f2d2d1ee3e: apt-get install -y wget
```

1.  在在`ubuntu:14.04`上安装`wget`完成后，通过在第二个终端中运行`ls -s`命令来重新检查容器的大小：

```
$docker container ls -s
```

如下片段所示，`testsize`容器的大小为`27.8MB（虚拟 216MB）`：

```
CONTAINER ID    IMAGE          COMMAND      CREATED
  STATUS     PORTS    NAMES      SIZE
9f2d2d1ee3e0    ubuntu:14.04   "/bin/bash"  9 seconds ago
  Up 9 minutes        testsize   27.8MB (virtual 216MB)
```

现在，薄层的大小为`27.8MB`，虚拟大小等于所有层的大小。在这个练习中，层包括基础镜像，大小为 188MB；更新；以及`wget`层，大小为 27.8MB。因此，近似后总大小将为 216MB。

在这个练习中，您了解了`docker container ls`子命令中使用的`-s`选项的功能。此选项用于显示基础镜像和顶部可写层的大小。了解每个容器消耗的大小对于避免磁盘空间不足异常是有用的。此外，它可以帮助我们进行故障排除并为每个容器设置最大大小。

注意

Docker 使用存储驱动程序来写入可写层。存储驱动程序取决于您使用的操作系统。要查找更新的存储驱动程序列表，请访问 https://docs.docker.com/storage/storagedriver/select-storage-driver/。

要找出您的操作系统正在使用哪个驱动程序，请运行`$docker info`命令。

了解 Docker 容器生命周期事件可以为研究某些应用程序是否需要持久存储提供良好的背景，并概述了在容器明确移除之前 Docker 的默认主机存储区域（文件系统位置）。

现在，让我们深入研究有状态和无状态模式，以决定哪个容器需要持久存储。

# 有状态与无状态容器/服务

容器和服务可以以两种模式运行：**有状态**和**无状态**。无状态服务是不保留持久数据的服务。这种类型比有状态服务更容易扩展和更新。有状态服务需要持久存储（如数据库）。因此，它更难 dockerize，因为有状态服务需要与应用程序的其他组件同步。

假设您正在处理一个需要某个文件才能正常工作的应用程序。如果这个文件保存在容器内，就像有状态模式一样，当这个容器因任何原因被移除时，整个应用程序就会崩溃。然而，如果这个文件保存在卷或外部数据库中，任何容器都可以访问它，应用程序将正常工作。假设业务蒸蒸日上，我们需要增加运行的容器数量来满足客户的需求。所有容器都可以访问该文件，并且扩展将变得简单和顺畅。

Apache 和 NGINX 是无状态服务的示例，而数据库是有状态容器的示例。*Docker 卷和有状态持久性*部分将重点关注数据库镜像所需的卷。

在接下来的练习中，您将首先创建一个无状态服务，然后创建一个有状态服务。两者都将使用 Docker 游乐场，这是一个网站，可以在几秒钟内提供 Docker Engine。这是一个免费的虚拟机浏览器，您可以在其中执行 Docker 命令并在集群模式下创建集群。

## 练习 7.03：创建和扩展无状态服务，NGINX

通常，在基于 Web 的应用程序中，有前端和后端。例如，在全景徒步应用程序中，您在前端使用 NGINX，因为它可以处理大量连接并将负载分发到后端较慢的数据库。因此，NGINX 被用作反向代理服务器和负载均衡器。

在这个练习中，您将专注于创建一个无状态服务，仅仅是 NGINX，并看看它有多容易扩展。您将初始化一个 swarm 来创建一个集群，并在其上扩展 NGINX。您将使用 Docker playground 在 swarm 模式下工作：

1.  连接到 Docker playground，网址为 https://labs.play-with-docker.com/，如*图 7.2*所示：![图 7.2：Docker playground](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-ws/img/B15021_07_02.jpg)

图 7.2：Docker playground

1.  在左侧菜单中点击`ADD NEW INSTANCE`来创建一个新节点。从顶部节点信息部分获取节点 IP。现在，使用`docker swarm init`命令创建一个 swarm，并使用`–advertise-addr`选项指定节点 IP。如*图 7.2*所示，Docker 引擎生成一个长令牌，允许其他节点（无论是管理节点还是工作节点）加入集群：

```
$docker swarm init --advertise-addr <IP>
```

1.  使用`docker service create`命令创建一个服务，并使用`-p`选项指定端口`80`。将`--replicas`选项的副本数设置为`2`，使用`nginx:1.14.2`镜像：

```
$ docker service create -p 80 --replicas 2 nginx:1.14.2
```

`docker service create`命令从容器内的`nginx:1.14.2`镜像创建了两个副本服务，端口为`80`。Docker 守护程序选择任何可用的主机端口。在这种情况下，它选择了端口`30000`，如*图 7.2*顶部所示。

1.  验证服务是否已创建，使用`docker service ls`命令列出所有可用的服务：

```
$docker service ls
```

如下输出所示，Docker 守护程序自动生成了一个服务 ID，并为服务分配了一个名为`amazing_hellman`的名称，因为您没有使用`--name`选项指定一个名称：

```
ID            NAME             MODE        REPLICAS  IMAGE
     PORTS
xmnp23wc0m6c  amazing_hellman  replicated  2/2       nginx:1.14.2
     *:30000->80/tcp
```

注意

在容器中，Docker 守护程序为容器分配一个随机的**形容词 _ 名词**名称。

1.  使用`curl <IP:Port Number>` Linux 命令来查看服务的输出并连接到它，而不使用浏览器：

```
$curl 192.168.0.223:3000
```

输出是`NGINX`欢迎页面的 HTML 版本。这表明它已经正确安装：

```
<!DOCTYPE html>
<html>
<head>
<title>Welcome to nginx!</title>
<style>
    body {
        width: 35em;
        margin: 0 auto;
        font-family: Tahoma, Verdana, Arial, sans-serif;
    }
</style>
</head>
</body>
<h1>Welcome to nginx!<h1>
<p>If you see this page, the nginx web server is successfully 
installed and working. Further configuration is required. </p>
<p>For online documentation and support please refer to
<a href="http://nginx.org/">nginx.org</a>.<br/>
Commercial support is available at
<a href="http://nginx.com/">nginx.com</a>.</p>
<p><em>Thank you for using nginx.</em></p>
</body>
<html>
```

1.  假设业务更加繁荣，两个副本已经不够了。您需要将其扩展到五个副本，而不是两个。使用`docker service scale <service name>=<number of replicas>`子命令：

```
$docker service scale amazing_hellman=5
```

您将获得以下输出：

```
amazing_hellman scaled to 5
overall progress: 5 out of 5 tasks
1/5: running
2/5: running
3/5: running
4/5: running
5/5: running
verify: Service converged
```

1.  要验证 Docker Swarm 是否复制了服务，请再次使用`docker service ls`子命令：

```
$docker service ls
```

输出显示副本数量从`2`增加到`5`个副本：

```
ID            NAME             MODE        REPLICAS  IMAGE
     PORTS
xmnp23wc0m6c  amazing_hellman  replicated  5/5       nginx:1.14.2
     *:30000->80/tcp
```

1.  使用`docker service rm`子命令删除服务：

```
$docker service rm amazing_hellman
```

该命令将返回服务的名称：

```
amazing_hellman
```

1.  要验证服务是否已删除，请再次使用`docker service ls`子命令列出服务：

```
$docker service ls
```

输出将是一个空列表：

```
ID       NAME      MODE      REPLICAS      IMAGE      PORTS
```

在这个练习中，您部署了一个无状态服务 NGINX，并使用`docker service scale`命令进行了扩展。然后，您使用了 Docker playground（一个免费的解决方案，您可以使用它来创建一个集群，并使用 Swarm 来初始化一个 Swarm）。

注意

这个练习使用 Docker Swarm。要使用 Kubernetes 做同样的事情，您可以按照 https://kubernetes.io/docs/tasks/run-application/run-stateless-application-deployment/上的步骤进行操作。

现在，我们完成了 NGINX 的前端示例。在下一个练习中，您将看到如何创建一个需要持久数据的有状态服务。我们将使用数据库服务 MySQL 来完成以下练习。

## 练习 7.04：部署有状态服务，MySQL

如前所述，基于 Web 的应用程序有前端和后端。您已经在上一个练习中看到了前端组件的示例。在这个练习中，您将部署一个单个有状态的 MySQL 容器作为后端组件的数据库。

要安装 MySQL，请按照 https://hub.docker.com/_/mysql 中的`通过 stack deploy`部分的步骤进行操作。选择并复制`stack.yml`文件到内存：

1.  使用编辑器粘贴`stack.yml`文件。您可以使用`vi`或`nano` Linux 命令在 Linux 中打开文本编辑器并粘贴 YAML 文件：

```
$vi stack.yml
```

粘贴以下代码：

```
# Use root/example as user/password credentials
version: '3.1'
services:
  db:
    image: mysql
    command: --default-authentication-plugin=      mysql_native_password
    restart: always
    environment:
      MYSQL_ROOT_PASSWORD: example
  adminer:
    image: adminer
    restart: always
    ports:
      - 8080:8080
```

在这个 YAML 文件中，您有两个服务：`db`和`adminer`。`db`服务基于`mysql`镜像，而`adminer`镜像是`adminer`服务的基础镜像。`adminer`镜像是一个数据库管理工具。在`db`服务中，您输入命令并设置环境变量，其中包含具有始终重新启动策略的数据库密码，如果出现任何原因失败。同样，在`adminer`服务中，如果出现任何原因失败，策略也被设置为始终重新启动。

1.  在键盘上按*Esc*键。然后，运行以下命令退出并保存代码：

```
:wq
```

1.  要验证文件是否已正确保存，请使用`cat` Linux 命令显示`stack.yml`的内容：

```
$cat stack.yml
```

文件将被显示。如果出现错误，请重复上一步。

1.  如果代码正确，请使用`docker stack deploy`子命令部署`YML`文件：

```
$docker stack deploy -c stack.yml mysql
```

您应该看到如下输出：

```
Ignoring unsupported options: restart
Creating network mysql_default
Creating service mysql_db
Creating service mysql_adminer
```

要连接到服务，请在 Docker playground 窗口顶部的节点 IP 旁边右键单击端口`8080`，并在新窗口中打开它：

![图 7.3：连接到服务](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-ws/img/B15021_07_03.jpg)

图 7.3：连接到服务

1.  使用`docker stack ls`子命令列出堆栈：

```
$docker stack ls
```

您应该看到如下输出：

```
NAME     SERVICES    ORCHESTRATOR
mysql    2           Swarm
```

1.  使用`docker stack rm`子命令来移除堆栈：

```
$docker stack rm mysql
```

在移除堆栈时，Docker 将移除两个服务：`db`和`adminer`。它还将移除默认创建的用于连接所有服务的网络：

```
Removing service mysql_adminer
Removing service mysql_db
Removing network mysql_default
```

在这个练习中，您部署了一个有状态的服务 MySQL，并能够从浏览器访问数据库服务。同样，我们使用 Docker playground 作为执行练习的平台。

注意

复制 MySQL 并不是一件容易的事情。您不能像在*练习 7.03*，*创建和扩展无状态服务，NGINX*中那样在一个数据文件夹上运行多个副本。这种方式不起作用，因为必须应用数据一致性、数据库锁定和缓存以确保您的数据正确。因此，MySQL 使用主从复制，您在主服务器上写入数据，然后数据同步到从服务器。要了解更多关于 MySQL 复制的信息，请访问 https://dev.mysql.com/doc/refman/8.0/en/replication.html。

我们已经了解到容器需要持久存储，超出容器生命周期，但还没有涵盖如何做到这一点。在下一节中，我们将学习关于卷来保存持久数据。

# Docker 卷和有状态的持久性

我们可以使用卷来保存持久数据，而不依赖于容器。您可以将卷视为一个共享文件夹。在任何情况下，如果您将卷挂载到任意数量的容器中，这些容器将能够访问卷中的数据。创建卷有两种方式：

+   通过使用`docker volume create`子命令，创建一个独立于任何容器之外的卷。

将卷作为容器之外的独立对象创建，可以增加数据管理的灵活性。这些类型的卷也被称为**命名卷**，因为您为其指定了一个名称，而不是让 Docker 引擎生成一个匿名的数字名称。命名卷会比系统中的所有容器存在更久，并保留其数据。

尽管这些卷被挂载到容器中，但即使系统中的所有容器都被删除，这些卷也不会被删除。

+   通过在`docker container run`子命令中使用`--mount`或`-v`或`--volume`选项创建一个卷。Docker 会为您创建一个匿名卷。当容器被删除时，除非使用`-v`选项显式指示`docker container rm`子命令或使用`docker volume rm`子命令，否则卷也不会被删除。

以下练习将提供每种方法的示例。

## 练习 7.05：管理容器范围之外的卷并将其挂载到容器

在这个练习中，您将创建一个不受限于容器的卷。您将首先创建一个卷，将其挂载到一个容器上，并在上面保存一些数据。然后您将删除容器并列出卷，以检查即使在系统中没有容器时，卷是否仍然存在：

1.  使用`docker volume create`命令创建名为`vol1`的卷：

```
$docker volume create vol1
```

该命令将返回卷的名称，如下所示：

```
vol1
```

1.  使用`docker volume ls`命令列出所有卷：

```
$docker volume ls
```

这将导致以下输出：

```
DRIVER            VOLUME NAME
Local             vol1
```

1.  使用以下命令检查卷以获取其挂载点：

```
$docker volume inspect vol1
```

您应该会得到以下输出：

```
[
    {
        "CreatedAt": "2020-06-16T16:44:13-04:00",
        "Driver": "local",
        "Labels": {},
        "Mountpoint: "/var/lib/docker/volumes/vol1/_data",
        "Name": "vol1",
        "Options": {},
        "Scope": "local"
    }
]
```

卷检查显示了其创建日期和时间、挂载路径、名称和范围。

1.  将卷挂载到容器并修改其内容。添加到`vol1`的任何数据都将被复制到容器内的卷中：

```
$ docker container run -it -v vol1:/container_vol --name container1 ubuntu:14.04 bash
```

在上述命令中，您使用`ubuntu:14.04`镜像和`bash`命令创建了一个容器。`bash`命令允许您在容器内部输入命令。`-it`选项用于启用交互式终端。`-v`选项用于在主机和容器内部的`container_vol`之间同步数据。使用`--name`选项为容器命名为`container1`。

1.  提示会改变，表示您现在在容器内。在名为`new_file.txt`的文件中写入单词`hello`到卷中。容器内的卷称为`container_vol`。在这种情况下，该卷在主机和容器之间共享。从主机上，该卷称为`vol1`：

```
root@acc8900e4cf1:/# echo hello > /container_vol/new_file.txt
```

1.  列出卷的内容以验证文件是否已保存：

```
root@acc8900e4cf1:/# ls /container_vol
```

1.  使用`exit`命令退出容器：

```
root@acc8900e4cf1:/# exit
```

1.  通过运行以下命令检查来自主机的新文件的内容：

```
$ sudo ls /var/lib/docker/volumes/vol1/_data
```

该命令将返回新文件的名称：

```
new_file.txt
```

1.  通过运行以下命令验证单词`hello`作为文件内容是否也已保存：

```
$ sudo cat /var/lib/docker/volumes/vol1/_data/new_file.txt
```

1.  使用`-v`选项删除容器以删除在容器范围内创建的任何卷：

```
$docker container rm -v container1
```

该命令将返回容器的名称：

```
container1
```

1.  通过列出所有卷来验证卷是否仍然存在：

```
$docker volume ls
```

卷`vol1`被列出，表明该卷是在容器之外创建的，即使使用`-v`选项，当容器被删除时也不会被删除：

```
DRIVER        VOLUME NAME
Local         vol1
```

1.  现在，使用`rm`命令删除卷：

```
$docker volume rm vol1
```

该命令应返回卷的名称：

```
vol1
```

1.  通过列出当前的卷列表来验证卷是否已被删除：

```
$docker volume ls
```

将显示一个空列表，表明卷已被删除：

```
DRIVER        VOLUME NAME
```

在这个练习中，您学会了如何在 Docker 中创建独立的卷对象，而不在容器的范围内，并且如何将这个卷挂载到容器上。卷在删除容器时没有被删除，因为卷是在容器范围之外创建的。最后，您学会了如何删除这些类型的卷。

在下一个练习中，我们将创建、管理和删除一个在容器范围内的未命名或匿名卷。

## 练习 7.06：管理容器范围内的卷

在运行容器之前，您不需要创建卷。Docker 会自动为您创建一个无名卷。同样，除非在`docker container rm`子命令中指定`-v`选项，否则在删除容器时不会删除卷。在这个练习中，您将在容器的范围内创建一个匿名卷，然后学习如何删除它：

1.  使用以下命令创建一个带有匿名卷的容器：

```
$docker container run -itd -v /newvol --name container2 ubuntu:14.04 bash
```

该命令应返回一个长的十六进制数字，这是卷的 ID。

1.  列出所有卷：

```
$ docker volume ls
```

请注意，这次 `VOLUME NAME` 是一个长的十六进制数字，而不是一个名称。这种类型的卷被称为匿名卷，可以通过在 `docker container rm` 子命令中添加 `-v` 选项来删除：

```
DRIVER     VOLUME NAME
Local      8f4087212f6537aafde7eaca4d9e4a446fe99933c3af3884d
0645b66b16fbfa4
```

1.  这次删除带有卷的容器。由于它处于分离模式并在后台运行，使用 `-f` 选项强制删除容器。还添加 `v` 选项（使其为 `-fv`）以删除卷。如果这个卷不是匿名的，并且您为其命名了，那么它将不会被此选项删除，您必须使用 `docker volume rm <volume name>` 来删除它：

```
$docker container rm -fv container2
```

该命令将返回容器的名称。

1.  验证卷已被删除。使用 `docker volume ls` 子命令，您会发现列表为空：

```
$ docker volume ls
```

与之前的练习相比，使用 `-v` 选项在删除容器时删除了卷。Docker 这次删除了卷，因为卷最初是在容器的范围内创建的。

注意

1\. 如果您将卷挂载到服务而不是容器，则不能使用 `-v` 或 `--volume` 选项。您必须使用 `--mount` 选项。

2\. 要删除所有未在其容器被删除时删除的匿名卷，您可以使用 `docker volume prune` 子命令。

有关更多详细信息，请访问 https://docs.docker.com/storage/volumes/。

现在，我们将看到一些更多的例子，展示卷与有状态容器一起使用。请记住，将卷与有状态容器（如数据库）一起使用是最佳实践。容器是临时的，而数据库上的数据应该保存在持久卷中，任何新容器都可以获取并使用保存的数据。因此，卷必须被命名，您不应该让 Docker 自动生成一个带有十六进制数字作为名称的匿名卷。

在下一个练习中，您将运行一个带有卷的 PostgreSQL 数据库容器。

## 练习 7.07：运行带有卷的 PostgreSQL 容器

假设您在一个使用带有数据库卷的 PostgreSQL 容器的组织中工作，由于某些意外情况，容器被删除了。但是，数据仍然存在并且超出了容器的生存期。在这个练习中，您将运行一个带有数据库卷的 PostgreSQL 容器：

1.  运行一个带有卷的 PostgreSQL 容器。将容器命名为`db1`。如果您本地没有该镜像，Docker 将为您拉取镜像。从`postgress`镜像创建一个名为`db1`的容器。使用`-v`选项将主机上的`db`卷与容器内的`/var/lib/postgresql/data`共享，并使用`-e`选项将 SQL 回显到标准输出流。使用`POSTGRES_PASSWORD`选项设置数据库密码，并使用`-d`选项以分离模式运行此容器：

```
$docker container run --name db1 -v db:/var/lib/postgresql/data -e POSTGRES_PASSWORD=password -d postgres
```

1.  使用`exec`命令与容器进行交互，从`bash`中执行命令。`exec`命令不会创建新进程，而是用要执行的命令替换`bash`。在这里，提示将更改为`posgres=#`，表示您在`db1`容器内：

```
$ docker container exec -it db1 psql -U postgres
```

`psql`命令允许您交互式输入、编辑和执行 SQL 命令。使用`-U`选项输入数据库的用户名，即`postgres`。

1.  创建一个名为`PEOPLE`的表，有两列 - `Name`和`age`：

```
CREATE TABLE PEOPLE(NAME TEXT, AGE int);
```

1.  向`PEOPLE`表中插入一些值：

```
INSERT INTO PEOPLE VALUES('ENGY','41');
INSERT INTO PEOPLE VALUES('AREEJ','12');
```

1.  验证表中的值是否正确插入：

```
SELECT * FROM PEOPLE;
```

该命令将返回两行，验证数据已正确插入：

![图 7.4：SELECT 语句的输出](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-ws/img/B15021_07_04.jpg)

图 7.4：SELECT 语句的输出

1.  退出容器以退出数据库。shell 提示将返回：

```
\q
```

1.  使用`volume ls`命令验证您的卷是否是命名卷而不是匿名卷：

```
$ docker volume ls
```

您应该会得到以下输出：

```
DRIVER            VOLUME NAME
Local             db
```

1.  使用`-v`选项删除`db1`容器：

```
$ docker container rm -fv db1
```

该命令将返回容器的名称：

```
db1
```

1.  列出卷：

```
$ docker volume ls
```

列表显示卷仍然存在，并且未随容器一起删除：

```
DRIVER          VOLUME NAME
Local           db
```

1.  与*步骤 1*一样，创建一个名为`db2`的新容器，并挂载卷`db`：

```
$docker container run --name db2 -v db:/var/lib/postgresql/data -e POSTGRES_PASSWORD=password -d postgres
```

1.  运行`exec`命令从`bash`执行命令，并验证即使删除`db1`，数据仍然存在：

```
$ docker container exec -it db2 psql -U postgres
postgres=# SELECT * FROM PEOPLE;
```

上述命令将导致以下输出：

![图 7.5：SELECT 语句的输出](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-ws/img/B15021_07_05.jpg)

图 7.5：SELECT 语句的输出

1.  退出容器以退出数据库：

```
\q
```

1.  现在，使用以下命令删除`db2`容器：

```
$ docker container rm -f db2
```

该命令将返回容器的名称：

```
db2
```

1.  使用以下命令删除`db`卷：

```
$ docker volume rm db
```

该命令将返回卷的名称：

```
db
```

在这个练习中，您使用了一个命名卷来保存您的数据库以保持数据持久。您看到即使在删除容器后数据仍然持久存在。新容器能够追上并访问您在数据库中保存的数据。

在下一个练习中，您将运行一个没有卷的 PostgreSQL 数据库，以比较其效果与上一个练习的效果。

## 练习 7.08：运行没有卷的 PostgreSQL 容器

在这个练习中，您将运行一个默认的 PostgreSQL 容器，而不使用数据库卷。然后，您将删除容器及其匿名卷，以检查在删除容器后数据是否持久存在：

1.  运行一个没有卷的 PostgreSQL 容器。将容器命名为`db1`：

```
$ docker container run --name db1 -e POSTGRES_PASSWORD=password -d postgres
```

1.  运行`exec`命令以执行来自`bash`的命令。提示将更改为`posgres=#`，表示您在`db1`容器内：

```
$ docker container exec -it db1 psql -U postgres
```

1.  创建一个名为`PEOPLE`的表，其中包含两列 - `NAME`和`AGE`：

```
CREATE TABLE PEOPlE(NAME TEXT, AGE int);
```

1.  在`PEOPLE`表中插入一些值：

```
INSERT INTO PEOPLE VALUES('ENGY','41');
INSERT INTO PEOPLE VALUES('AREEJ','12');
```

1.  验证表中的值是否已正确插入：

```
SELECT * FROM PEOPLE;
```

该命令将返回两行，从而验证数据已正确插入：

![图 7.6：SELECT 语句的输出](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-ws/img/B15021_07_04.jpg)

图 7.6：SELECT 语句的输出

1.  退出容器以退出数据库。shell 提示将返回：

```
\q
```

1.  使用以下命令列出卷：

```
$ docker volume ls
```

Docker 已为`db1`容器创建了一个匿名卷，如下输出所示：

```
DRIVER     VOLUME NAME
Local      6fd85fbb83aa8e2169979c99d580daf2888477c654c
62284cea15f2fc62a42c32
```

1.  使用以下命令删除带有匿名卷的容器：

```
$ docker container rm -fv db1
```

该命令将返回容器的名称：

```
db1
```

1.  使用`docker volume ls`命令列出卷，以验证卷是否已删除：

```
$docker volume ls
```

您将观察到列表是空的：

```
DRIVER     VOLUME NAME
```

与之前的练习相反，这次练习使用了匿名卷而不是命名卷。因此，该卷在容器的范围内，并且已从容器中删除。

因此，我们可以得出结论，最佳做法是将数据库共享到命名卷上，以确保数据库中保存的数据将持久存在并超出容器的生命周期。

到目前为止，您已经学会了如何列出卷并对其进行检查。但是还有其他更强大的命令可以获取有关您的系统和 Docker 对象的信息，包括卷。这将是下一节的主题。

## 杂项有用的 Docker 命令

可以使用许多命令来排除故障和检查您的系统，其中一些命令如下所述：

+   使用`docker system df`命令来查找系统中所有 Docker 对象的大小：

```
$docker system df
```

如下输出所示，列出了图像、容器和卷的数量及其大小：

```
TYPE            TOTAL     ACTIVE     SIZE      RECLAIMABLE
Images          6         2          1.261GB   47.9MB (75%)
Containers      11        2          27.78MB   27.78MB (99%)
Local Volumes   2         2          83.26MB   OB (0%)
Build Cache                          0B        0B
```

+   您可以通过在`docker system df`命令中添加`-v`选项来获取有关 Docker 对象的更详细信息：

```
$docker system df -v
```

它应该返回以下类似的输出：

![图 7.7：docker system df -v 命令的输出](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-ws/img/B15021_07_07.jpg)

图 7.7：docker system df -v 命令的输出

+   运行`docker volume ls`子命令来列出系统上所有的卷：

```
$docker volume ls
```

复制卷的名称，以便用它来获取使用它的容器的名称：

```
DRIVER    VOLUME NAME
local     a7675380798d169d4d969e133f9c3c8ac17e733239330397ed
ba9e0bc05e509fc
local     db
```

然后，运行`docker ps -a --filter volume=<Volume Name>`命令来获取正在使用该卷的容器的名称：

```
$docker ps -a --filter volume=db
```

您将获得容器的详细信息，如下所示：

```
CONTAINER ID    IMAGE     COMMAND                 CREATED
  STATUS       PORTS         NAMES
55c60ad38164    postgres  "docker-entrypoint.s…"  2 hours ago
  Up 2 hours   5432/tcp      db_with
```

到目前为止，我们一直在容器和 Docker 主机之间共享卷。这种共享类型并不是 Docker 中唯一可用的类型。您还可以在容器之间共享卷。让我们在下一节中看看如何做到这一点。

# 持久卷和临时卷

有两种类型的卷：持久卷和临时卷。到目前为止，我们所看到的是持久卷，它们位于主机和容器之间。要在容器之间共享卷，我们使用`--volumes-from`选项。这种卷只存在于被容器使用时。当最后一个使用该卷的容器退出时，该卷就会消失。这种类型的卷可以从一个容器传递到下一个，但不会被保存。这些卷被称为临时卷。

卷可用于在主机和容器之间或容器之间共享日志文件。在主机上共享它们会更容易，这样即使容器因错误而被移除，我们仍然可以通过在容器移除后检查主机上的日志文件来跟踪错误。

在实际微服务应用程序中，卷的另一个常见用途是在卷上共享代码。这种做法的优势在于可以实现零停机时间。开发团队可以即时编辑代码。团队可以开始添加新功能或更改接口。Docker 会监视代码的更新，以便执行新代码。

在接下来的练习中，我们将探索数据容器，并学习一些在容器之间共享卷的新选项。

## 练习 7.09：在容器之间共享卷

有时，你需要一个数据容器在不同操作系统上运行的各种容器之间共享数据。在将数据发送到生产环境之前，测试在不同平台上相同的数据是很有用的。在这个练习中，你将使用数据容器，它将使用`--volume-from`在容器之间共享卷：

1.  创建一个名为`c1`的容器，使用一个名为`newvol`的卷，这个卷不与主机共享：

```
$docker container run -v /newvol --name c1 -it ubuntu:14.04 bash
```

1.  移动到`newvol`卷：

```
cd newvol/
```

1.  在这个卷内保存一个文件：

```
echo hello > /newvol/file1.txt
```

1.  按下转义序列，*CTRL* + *P*，然后*CTRL* + *Q*，这样容器就会在后台以分离模式运行。

1.  创建第二个容器`c2`，使用`--volumes-from`选项挂载`c1`容器的卷：

```
$docker container run --name c2 --volumes-from c1 -it ubuntu:14.04 bash
```

1.  验证`c2`能够通过`ls`命令访问你从`c1`保存的`file1.txt`：

```
cd newvol/
ls
```

1.  在`c2`内添加另一个文件`file2.txt`：

```
echo hello2 > /newvol/file2.txt
```

1.  验证`c2`能够通过`ls`命令访问你从`c1`保存的`file1.txt`和`file2.txt`：

```
ls
```

你会看到两个文件都被列出：

```
file1.txt	file2.txt
```

1.  将本地标准输入、输出和错误流附加到`c1`：

```
docker attach c1
```

1.  检查`c1`能够通过`ls`命令访问这两个文件：

```
ls
```

你会看到两个文件都被列出：

```
file1.txt	file2.txt
```

1.  使用以下命令退出`c1`：

```
exit
```

1.  使用以下命令列出卷：

```
$ docker volume ls
```

你会发现即使你退出了`c1`，卷仍然存在：

```
DRIVER    VOLUME NAME
local     2d438bd751d5b7ec078e9ff84a11dbc1f11d05ed0f82257c
4e8004ecc5d93350
```

1.  使用`-v`选项移除`c1`：

```
$ docker container rm -v c1
```

1.  再次列出卷：

```
$ docker volume ls
```

你会发现`c1`退出后卷并没有被移除，因为`c2`仍在使用它：

```
DRIVER    VOLUME NAME
local     2d438bd751d5b7ec078e9ff84a11dbc1f11d05ed0f82257c
4e8004ecc5d93350
```

1.  现在，使用`-v`选项移除`c2`以及它的卷。你必须同时使用`-f`选项来强制移除容器，因为它正在运行中：

```
$ docker container rm -fv c2
```

1.  再次列出卷：

```
$ docker volume ls
```

你会发现卷列表现在是空的：

```
DRIVER           VOLUME NAME
```

这证实了当使用卷的所有容器被移除时，临时卷也会被移除。

在这个练习中，你使用了`--volumes-from`选项在容器之间共享卷。此外，这个练习还证明了最佳实践是始终使用`-v`选项移除容器。只要至少有一个容器在使用该卷，Docker 就不会移除这个卷。

如果我们将`c1`或`c2`中的任何一个提交为一个新镜像，那么保存在共享卷上的数据仍然不会被上传到新镜像中。即使卷在容器和主机之间共享，卷上的数据也不会被上传到新镜像中。

在下一节中，我们将看到如何使用文件系统而不是卷将这些数据刻在新提交的镜像中。

# 卷与文件系统和图像

请注意，卷不是镜像的一部分，因此保存在卷上的数据不会随镜像一起上传或下载。卷将被刻在镜像中，但不包括其数据。因此，如果您想在镜像中保存某些数据，请将其保存为文件，而不是卷。

下一个练习将演示并澄清在卷上保存数据和在文件上保存数据时的不同输出。

## 练习 7.10：在卷上保存文件并将其提交到新镜像

在这个练习中，您将运行一个带有卷的容器，在卷上保存一些数据，将容器提交到一个新的镜像，并根据这个新的镜像创建一个新的容器。当您从容器内部检查数据时，您将找不到它。数据将丢失。这个练习将演示当将容器提交到一个新的镜像时数据将如何丢失。请记住，卷上的数据不会被刻在新镜像中：

1.  创建一个带有卷的新容器：

```
$docker container run --name c1 -v /newvol -it ubuntu:14.04 bash
```

1.  在这个卷中保存一个文件：

```
echo hello > /newvol/file.txt
cd newvol
```

1.  导航到`newvol`卷：

```
cd newvol
```

1.  验证`c1`可以使用`ls`命令访问`file.txt`：

```
ls
```

你会看到文件已列出：

```
file.txt
```

1.  使用`cat`命令查看文件的内容：

```
cat file.txt
```

这将产生以下输出：

```
hello
```

1.  使用以下命令退出容器：

```
exit
```

1.  将此容器提交到名为`newimage`的新镜像：

```
$ docker container commit c1 newimage
```

1.  检查镜像以验证卷是否被刻在其中：

```
$ docker image inspect newimage --format={{.ContainerConfig.Volumes}}
```

这将产生以下输出：

```
map[/newvol:{}]
```

1.  根据您刚刚创建的`newimage`镜像创建一个容器：

```
$ docker container run -it newimage
```

1.  导航到`newvol`并列出卷及其数据中的文件。您会发现文件和单词`hello`没有保存在镜像中：

```
cd newvol
ls
```

1.  使用以下命令退出容器：

```
exit
```

从这个练习中，您了解到卷上的数据不会上传到镜像中。为了解决这个问题，请使用文件系统而不是卷。

假设单词`hello`是我们希望保存在镜像中的重要数据，以便我们在从这个镜像创建容器时可以访问它。您将在下一个练习中看到如何做到这一点。

## 练习 7.11：在新镜像文件系统中保存文件

在这个练习中，您将使用文件系统而不是卷。您将创建一个目录而不是卷，并将数据保存在这个新目录中。然后，您将提交容器到一个新的镜像中。当您使用这个镜像作为基础镜像创建一个新的容器时，您会发现容器中有这个目录和其中保存的数据：

1.  删除之前实验中可能存在的任何容器。您可以将多个 Docker 命令连接在一起：

```
$ docker container rm -f $(docker container ls -aq)
```

该命令将返回将被移除的容器的 ID。

1.  创建一个没有卷的新容器：

```
$ docker container run --name c1 -it ubuntu:14.04 bash
```

1.  使用`mkdir`命令创建一个名为`new`的文件夹，并使用`cd`命令打开它：

```
mkdir new 
cd new
```

1.  导航到`new`目录，并将单词`hello`保存在一个名为`file.txt`的新文件中：

```
echo hello > file.txt
```

1.  使用以下命令查看文件的内容：

```
cat file.txt
```

该命令应返回`hello`：

```
hello
```

1.  使用以下命令退出`c1`：

```
exit
```

1.  将此容器提交到名为`newimage`的新镜像中：

```
$ docker container commit c1 newimage
```

1.  根据您刚刚创建的`newimage`镜像创建一个容器：

```
$ docker container run -it newimage
```

1.  使用`ls`命令列出文件：

```
ls
```

这次你会发现`file.txt`被保存了：

```
bin  boot  dev  etc  home  lib  lib64  media  mnt  new  opt
proc  root  run sbin  srv  sys  tmp  usr  var
```

1.  导航到`new`目录，并使用`ls`命令验证容器是否可以访问`file.txt`：

```
cd new/
ls
```

您会看到文件被列出：

```
file.txt
```

1.  使用`cat`命令显示`file.txt`的内容：

```
cat file.txt
```

它将显示单词`hello`已保存：

```
hello
```

1.  使用以下命令退出容器：

```
exit
```

在这个练习中，您看到当使用文件系统时数据被上传到镜像中，与我们在数据保存在卷上看到的情况相比。

在接下来的活动中，我们将看到如何将容器的状态保存在 PostgreSQL 数据库中。因此，如果容器崩溃，我们将能够追溯发生了什么。它将充当黑匣子。此外，您将在接下来的活动中使用 SQL 语句查询这些事件。

## 活动 7.01：将容器事件（状态）数据存储在 PostgreSQL 数据库中

在 Docker 中可以通过几种方式进行日志记录和监控。其中一种方法是使用`docker logs`命令，它获取单个容器内部发生的情况。另一种方法是使用`docker events`子命令，它实时获取 Docker 守护程序内发生的一切。这个功能非常强大，因为它监视发送到 Docker 服务器的所有对象事件，而不仅仅是容器。这些对象包括容器、镜像、卷、网络、节点等等。将这些事件存储在数据库中是有用的，因为它们可以被查询和分析以调试和排除任何错误。

在这个活动中，您将需要使用`docker events --format '{{json .}}'`命令将容器事件的样本输出存储到 PostgreSQL 数据库中的`JSON`格式中。

执行以下步骤完成此活动：

1.  清理您的主机，删除任何 Docker 对象。

1.  打开两个终端：一个用于查看`docker events --format '{{json .}}'`的效果，另一个用于控制运行的容器。

1.  在`docker events`终端中点击*Ctrl* + *C*来终止它。

1.  了解 JSON 输出结构。

1.  运行 PostgreSQL 容器。

1.  创建一个表。

1.  从第一个终端复制`docker events`子命令的输出。

1.  将这个 JSON 输出插入到 PostgreSQL 数据库中。

1.  使用以下 SQL 查询使用 SQL`SELECT`语句查询 JSON 数据。

**查询 1**：

```
SELECT * FROM events WHERE info ->> 'status' = 'pull';
```

您应该得到以下输出：

![图 7.8：查询 1 的输出](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-ws/img/B15021_07_08.jpg)

图 7.8：查询 1 的输出

**查询 2**：

```
SELECT * FROM events WHERE info ->> 'status' = 'destroy';
```

您将获得类似以下内容的输出：

![图 7.9：查询 2 的输出](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-ws/img/B15021_07_09.jpg)

图 7.9：查询 2 的输出

**查询 3**：

```
SELECT info ->> 'id' as id FROM events WHERE info ->> status'     = 'destroy';
```

最终输出应该类似于以下内容：

![图 7.10：查询 3 的输出](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-ws/img/B15021_07_10.jpg)

图 7.10：查询 3 的输出

注意

此活动的解决方案可以通过此链接找到。

在下一个活动中，我们将看另一个示例，分享容器的 NGINX 日志文件，而不仅仅是它的事件。您还将学习如何在容器和主机之间共享日志文件。

## 活动 7.02：与主机共享 NGINX 日志文件

正如我们之前提到的，将应用程序的日志文件共享到主机是很有用的。这样，如果容器崩溃，您可以轻松地从容器外部检查其日志文件，因为您无法从容器中提取它们。这种做法对有状态和无状态容器都很有用。

在这个活动中，您将共享从 NGINX 镜像创建的无状态容器的日志文件到主机。然后，通过访问主机上的 NGINX 日志文件来验证这些文件。

**步骤**：

1.  请验证您的主机上是否没有`/var/mylogs`文件夹。

1.  运行基于 NGINX 镜像的容器。在`run`命令中指定主机上和容器内共享卷的路径。在容器内，NGINX 使用`/var/log/nginx`路径来存储日志文件。在主机上指定路径为`/var/mylogs`。

1.  转到`/var/mylogs`路径。列出该目录中的所有文件。您应该在那里找到两个文件：

```
access.log       error.log
```

注意

此活动的解决方案可以通过此链接找到。

# 摘要

本章涵盖了 Docker 容器的生命周期和各种事件。它比较了有状态和无状态应用程序以及每种应用程序如何保存其数据。如果我们需要数据持久化，我们应该使用卷。本章介绍了卷的创建和管理。它进一步讨论了不同类型的卷，以及在容器提交到新镜像时卷的使用和文件系统的区别，以及两者的数据在容器提交到新镜像时受到的影响。

在下一章中，您将学习持续集成和持续交付的概念。您将学习如何集成 GitHub、Jenkins、Docker Hub 和 SonarQube，以便自动将您的图像发布到注册表，以便准备投入生产。


# 第八章：CI/CD 流水线

概述

在进入生产之前，本章介绍了**持续集成和持续交付**（**CI/CD**）这一最关键的步骤。这是开发和生产之间的中间阶段。本章将演示 Docker 是 CI 和 CD 的强大技术，以及它如何轻松地与其他广泛使用的平台集成。在本章结束时，您将能够配置 GitHub、Jenkins 和 SonarQube，并将它们整合以自动发布您的图像以供生产使用。

# 介绍

在之前的章节中，您学习了如何编写`docker-compose`文件，并探索了服务的网络和存储。在本章中，您将学习如何集成应用程序的各种微服务并将其作为一个整体进行测试。

**CI/CD**代表**持续集成和持续交付**。有时，**CD**也用于**持续部署**。这里的部署意味着通过自动化流水线工作流从特定 URL 公开访问应用程序，而交付意味着使应用程序准备部署。在本章中，我们将重点讨论 CI/CD 的概念。

本章讨论了 Docker 如何在 CI/CD 流水线中进行逐步练习。您还将学习如何安装和运行 Jenkins 作为 Docker 容器。Jenkins 是一个开源的自动化服务器。您可以使用它来构建、测试、部署，并通过自动化软件开发的部分来促进 CI/CD。安装 Jenkins 只需一个 Docker 命令。在 Docker 上安装 Jenkins 比将其安装为应用程序更加强大，并且不会与特定操作系统紧密耦合。

注意

如果您没有 GitHub 和 Docker Hub 的帐户，请创建它们。您可以在以下链接免费创建：[www.github.com](http://www.github.com) 和 [`hub.docker.com`](http://hub.docker.com)。

# 什么是 CI/CD？

CI/CD 是一种帮助应用程序开发团队更频繁和可靠地向用户提供代码更改的方法。CI/CD 将自动化引入到代码部署的各个阶段中。

当多个开发人员共同协作并为同一应用程序做出贡献（每个人负责特定的微服务或修复特定的错误）时，他们使用代码版本控制提供程序使用开发人员上传和推送的最新代码版本来汇总应用程序。GitHub、Bitbucket 和 Assembla 是版本控制系统的示例。开发人员和测试人员将应用程序代码和 Docker 文件推送到自动化软件以构建、测试和部署 CI/CD 流水线。Jenkins、Circle CI 和 GitLab CI/CD 是此类自动化平台的示例。

通过测试后，将构建 Docker 镜像并发布到您的存储库。这些存储库可以是 Docker Hub、您公司的 Docker Trusted Register（DTR）或 Amazon Elastic Container Registry（ECR）。

在本章中，就像*图 8.1*一样，我们将使用 GitHub 存储库进行代码版本控制。然后，我们将使用 Jenkins 来构建和发布框架，并使用 Docker Hub 作为注册表。

![图 8.1：CI/CD 流水线](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-ws/img/B15021_08_01.jpg)

图 8.1：CI/CD 流水线

在生产阶段之前，您必须构建 Docker 镜像，因为在生产中使用的`docker-stack.yml`文件中没有`build`关键字。然后将在集成和自动化的目标环境中将镜像部署到生产环境。在生产中，运维（或 DevOps）人员配置编排器从注册表中拉取镜像。Kubernetes、Docker Swarm 和 Google Kubernetes Engine 是可以用来从注册表中拉取镜像的生产编排器和管理服务的示例。

总之，我们有三个主要步骤：

1.  将代码上传到 GitHub。

1.  在 Jenkins 中创建一个项目，并输入 GitHub 和 Docker Hub 凭据。Jenkins 将自动构建镜像并将其推送到您的 Docker Hub 账户。当您将代码推送到 GitHub 时，Jenkins 会自动检测、测试和构建镜像。如果没有生成错误，Jenkins 会将镜像推送到注册表。

1.  验证镜像是否在您的 Docker Hub 账户上。

在下一个练习中，您将安装 Jenkins 作为一个容器，用于构建镜像。Jenkins 是市场上最受欢迎的测试平台之一。Jenkins 有几种项目类型。在本章中，我们将使用 Freestyle 项目类型。

注意

请使用`touch`命令创建文件，使用`vim`命令在 vim 编辑器中处理文件。

## 练习 8.01：将 Jenkins 安装为一个容器

在这个练习中，您将安装 Jenkins，完成其设置，并安装初步插件。您将安装 Git 和 GitHub 插件，这些插件将在本章中使用。执行以下步骤成功地将 Jenkins 安装为一个容器：

1.  运行以下命令拉取 Jenkins 镜像：

```
$docker run -d -p 8080:8080 -v /var/run/docker.sock:/var/run/docker.sock jenkinsci/blueocean
```

这将导致类似以下的输出：

![图 8.2：docker run 命令的输出](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-ws/img/B15021_08_02.jpg)

图 8.2：docker run 命令的输出

注意

Docker Hub 上有许多 Jenkins 镜像。随意拉取其中任何一个，并玩转端口和共享卷，但要注意弃用的镜像，因为 Jenkins 官方镜像现在已弃用为`Jenkins/Jenkins:lts`镜像。因此，请仔细阅读镜像的文档。但是，如果一个镜像不起作用，不要担心。这可能不是你的错。寻找另一个镜像，并严格按照文档的说明操作。

1.  打开浏览器，并连接到`http://localhost:8080`上的 Jenkins 服务。

如果它给出一个错误消息，说明它无法连接到 Docker 守护程序，请使用以下命令将 Jenkins 添加到`docker`组：

```
$ sudo groupadd docker
$ sudo usermod –aG docker jenkins
```

注意

如果您的计算机操作系统是 Windows，本地主机名可能无法解析。在 Windows PowerShell 中运行`ipconfig`命令。在输出的第二部分中，`ipconfig`显示`switch`网络的信息。复制 IPv4 地址，并在练习中使用它，而不是本地主机名。

您还可以从`控制面板` > `网络和共享中心`获取 IP 地址，然后点击您的以太网或 Wi-Fi 连接的`详细信息`。

安装完成后，Jenkins 将要求输入`管理员密码`来解锁它：

![图 8.3：开始使用 Jenkins](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-ws/img/B15021_08_03.jpg)

图 8.3：开始使用 Jenkins

Jenkins 会为您生成一个密码，用于解锁应用程序。在下一步中，您将看到如何获取这个密码。

1.  运行`docker container ls`命令以获取当前正在运行的容器列表：

```
$ docker container ls
```

您将获得从`jekinsci/blueocean`镜像创建的容器的详细信息：

```
CONTAINER ID IMAGE              COMMAND               CREATED
  STATUS              PORTS
9ed51541b036 jekinsci/blueocean "/sbin/tini../usr/.." 5 minutes ago
  Up 5 minutes        0.0.0.0:8080->8080/tcp, 5000/tcp
```

1.  复制容器 ID 并运行`docker logs`命令：

```
$ docker logs 9ed51541b036
```

在日志文件的末尾，您将找到六行星号。密码将在它们之间。复制并粘贴到浏览器中：

![图 8.4：docker logs 命令的输出](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-ws/img/B15021_08_04.jpg)

图 8.4：docker logs 命令的输出

1.  选择“安装建议的插件”。然后，单击“跳过并继续作为管理员”。单击“保存并完成”：![图 8.5：安装插件以自定义 Jenkins](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-ws/img/B15021_08_05.jpg)

图 8.5：安装插件以自定义 Jenkins

在建议的插件中，有 Git 和 GitHub 插件，Jenkins 将自动为您安装这些插件。您将需要这些插件来完成所有即将进行的练习。

注意

在*练习 8.04*，*集成 Jenkins 和 Docker Hub*中，您将需要安装更多插件，以便 Jenkins 可以将镜像推送到 Docker Hub 注册表。稍后将详细讨论这一点，以及如何逐步管理 Jenkins 插件的实验。

1.  安装完成后，它将显示“Jenkins 已准备就绪！”。单击“开始使用 Jenkins”：![图 8.6：设置 Jenkins](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-ws/img/B15021_08_06.jpg)

图 8.6：设置 Jenkins

1.  单击“创建作业”以构建软件项目：![图 8.7：Jenkins 的欢迎页面](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-ws/img/B15021_08_07.jpg)

图 8.7：Jenkins 的欢迎页面

前面的截图验证了您已成功在系统上安装了 Jenkins。

在接下来的章节中，我们将遵循本章的 CI/CD 流水线。第一步是将代码上传到 GitHub，然后将 Jenkins 与 GitHub 集成，以便 Jenkins 可以自动拉取代码并构建镜像。最后一步将是将 Jenkins 与注册表集成，以便将该镜像推送到注册表而无需任何手动干预。

# 集成 GitHub 和 Jenkins

安装 Jenkins 后，我们将创建我们的第一个作业并将其与 GitHub 集成。在本节中，就像*图 8.8*中一样，我们将专注于 GitHub 和 Jenkins。Docker Hub 稍后将进行讨论。

![图 8.8：集成 GitHub 和 Jenkins](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-ws/img/B15021_08_08.jpg)

图 8.8：集成 GitHub 和 Jenkins

我们将使用一个简单的 Python 应用程序来统计网站点击次数。每次刷新页面，计数器都会增加，从而增加网站点击次数。

注意

`Getting Started`应用程序的代码文件可以在以下链接找到：[`github.com/efoda/hit_counter`](https://github.com/efoda/hit_counter)。

该应用程序由四个文件组成：

+   `app.py`：这是 Python 应用程序代码。它使用`Redis`来跟踪网站点击次数的计数。

+   `requirments.txt`：该文件包含应用程序正常工作所需的依赖项。

+   `Dockerfile`：这将使用所需的库和依赖项构建图像。

+   `docker-compose.yml`：当两个或更多容器一起工作时，拥有 YAML 文件是必不可少的。

在这个简单的应用程序中，我们还有两个服务，`Web`和`Redis`，如*图 8.9*所示：

![图 8.9：hit_counter 应用程序架构](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-ws/img/B15021_08_09.jpg)

图 8.9：hit_counter 应用程序架构

如果您不知道如何将此应用程序上传到您的 GitHub 帐户，请不要担心。下一个练习将指导您完成此过程。

## 练习 8.02：将代码上传到 GitHub

您可以使用 GitHub 保存您的代码和项目。在这个练习中，您将学习如何下载和上传代码到 GitHub。您可以通过在 GitHub 网站上 fork 代码或从命令提示符推送代码来实现。在这个练习中，您将从命令提示符中执行。

执行以下步骤将代码上传到 GitHub：

1.  在 GitHub 网站上，创建一个名为`hit_counter`的新空存储库。打开终端并输入以下命令来克隆代码：

```
$ git clone https://github.com/efoda/hit_counter
```

这将产生类似以下的输出：

```
Cloning into 'hit counter'...
remote: Enumerating objects: 38, done.
remote: Counting objects: 100% (38/38), done
remote: Compressing objects: 100% (35/35), done
remote: Total 38 (delta 16), reused 0 (delta 0), pack-reused 0
Receiving object: 100% (38/38), 8.98 KiB | 2.25 MiB/s, done.
Resolving deltas: 100% (16/16), done
```

1.  通过列出目录来验证代码是否已下载到本地计算机。然后，打开应用程序目录：

```
$ cd hit_counter
~/hit_counter$ ls
```

您会发现应用程序文件已下载到您的本地计算机：

```
app.py docker-compose.yml Dockerfile README.md requirements.txt
```

1.  初始化并配置 Git：

```
$ git init
```

您应该会得到类似以下的输出：

```
Reinitialized existing Git repository in 
/home/docker/hit_counter/.git/
```

1.  输入您的用户名和电子邮件：

```
$ git config user.email "<you@example.com>"
$ git config user.name "<Your Name>"
```

1.  指定 Git 帐户的名称，`origin`和`destination`：

```
$ git remote add origin https://github.com/efoda/hit_counter.git
fatal: remote origin already exists.
$ git remote add destination https://github.com/<your Github Username>/hit_counter.git
```

1.  添加当前路径中的所有内容：

```
$ git add .
```

您还可以通过输入以下命令添加特定文件而不是所有文件：

```
$ git add <filename>.<extension>
```

1.  指定一个`commit`消息：

```
$ git commit -m "first commit"
```

这将产生类似以下的输出：

```
On branch master
Your branch is up to date with 'origin/master'.
nothing to commit, working tree clean
```

1.  将代码推送到您的 GitHub 帐户：

```
$ git push -u destination master
```

它会要求您输入用户名和密码。一旦您登录，文件将被上传到您的 GitHub 存储库：

![图 8.10：将代码推送到 GitHub](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-ws/img/B15021_08_10.jpg)

图 8.10：将代码推送到 GitHub

1.  检查您的 GitHub 帐户。您会发现文件已经上传到那里。

现在我们已经完成了 CI/CD 管道的第一步，并且已经将代码上传到 GitHub，我们将把 GitHub 与 Jenkins 集成。

注意

从这一点开始，将 GitHub 用户名`efoda`替换为您的用户名。

## 练习 8.03：集成 GitHub 和 Jenkins

在*练习 8.01*，*将 Jenkins 安装为容器*中，您安装了 Jenkins 作为一个容器。在这个练习中，您将在 Jenkins 中创建一个作业，并将其配置为 GitHub。您将检查 Jenkins 的`输出控制台`，以验证它是否成功构建了镜像。然后，您将修改 GitHub 上的`Dockerfile`，并确保 Jenkins 已经检测到`Dockerfile`中的更改并自动重新构建了镜像：

1.  回到浏览器中的 Jenkins。点击`创建作业`：![图 8.11：在 Jenkins 中创建作业](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-ws/img/B15021_08_07.jpg)

图 8.11：在 Jenkins 中创建作业

1.  在`输入项目名称`文本框中填写项目名称。点击`自由风格项目`，然后点击`确定`：![图 8.12：选择自由风格项目](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-ws/img/B15021_08_12.jpg)

图 8.12：选择自由风格项目

您将看到六个选项卡：`常规`，`源代码管理`，`构建触发器`，`构建环境`，`构建`和`后构建操作`，就像*图 8.13*中那样。

1.  在`常规`选项卡中，选择`丢弃旧构建`选项，以防止旧构建占用磁盘空间。Jenkins 也会为您做好清理工作：![图 8.13：选择丢弃旧构建选项](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-ws/img/B15021_08_13.jpg)

图 8.13：选择丢弃旧构建选项

1.  在`源代码管理`选项卡中，选择`Git`。在`存储库 URL`中，输入`https://github.com/<your GitHub username>/hit_counter`，就像*图 8.14*中那样。如果您没有 Git，请检查您的插件并下载 Git 插件。我们将在*练习 8.04*，*集成 Jenkins 和 Docker Hub*中讨论管理插件的问题：![图 8.14：输入 GitHub 存储库 URL](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-ws/img/B15021_08_14.jpg)

图 8.14：输入 GitHub 存储库 URL

1.  在`构建触发器`选项卡中，选择`轮询 SCM`。这是您指定 Jenkins 执行测试的频率的地方。如果您输入`H/5`，并在每个星号之间加上四个星号和空格，这意味着您希望 Jenkins 每分钟执行一次测试，就像*图 8.16*中那样。如果您输入`H * * * *`，这意味着轮询将每小时进行一次。如果您输入`H/15 * * * *`，则每 15 分钟进行一次轮询。点击文本框外部。如果您输入的代码正确，Jenkins 将显示下次执行作业的时间。否则，它将显示红色的错误。![图 8.15：构建触发器](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-ws/img/B15021_08_15.jpg)

图 8.15：构建触发器

1.  点击“构建”选项卡。点击“添加构建步骤”。选择“执行 shell”，如*图 8.17*所示：![图 8.16：选择执行 shell](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-ws/img/B15021_08_16.jpg)

图 8.16：选择执行 shell

1.  将显示一个文本框。写入以下命令：

```
docker build -t hit_counter .
```

然后点击“保存”，如*图 8.17*所示：

![图 8.17：在“执行 shell 命令”框中输入 docker 构建命令](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-ws/img/B15021_08_17.jpg)

图 8.17：在“执行 shell 命令”框中输入 docker 构建命令

应该出现类似以下截图的屏幕：

![图 8.18：成功创建 hit_count 项目](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-ws/img/B15021_08_18.jpg)

图 8.18：成功创建 hit_count 项目

1.  在 Jenkins 中进一步操作之前，请检查您主机上当前拥有的镜像。在终端中运行`docker images`命令列出镜像：

```
$docker images
```

如果在本章之前清理了实验室，您将只有`jenkinsci/blueocean`镜像：

```
REPOSITORY           TAG     IMAGE ID      CREATED
       SIZE
jenkinsci/blueocean  latest  e287a467e019  Less than a second ago
       562MB
```

1.  返回到 Jenkins。从左侧菜单中点击“立即构建”。

注意

如果连接到 Docker 守护程序时出现权限被拒绝错误，请执行以下步骤：

1\. 如果尚不存在，请将 Jenkins 用户添加到 docker 主机：

`$ sudo useradd jenkins`

2\. 将 Jenkins 用户添加到 docker 组中：

`$ sudo usermod -aG docker jenkins`

3\. 从`/etc/group`获取 docker 组 ID，即`998`：

`$ sudo cat /etc/group | grep docker`

4\. 使用`docker exec`命令在运行中的 Jenkins 容器中创建一个 bash shell：

`$ docker container ls`

`$ docker exec -it -u root <CONTAINER NAME | CONTAINER ID> /bin/bash`

5\. 编辑 Jenkins 容器内的`/etc/group`文件：

`# vi /etc/group`

6\. 用从主机获取的 ID 替换 docker 组 ID，并将 Jenkins 用户添加到 docker 组中：

`docker:x:998:jenkins`

7\. 保存`/etc/group`文件并关闭编辑器：

`:wq`

8\. 退出 Jenkins 容器：

`# exit`

9\. 停止 Jenkins 容器：

`$ docker container ls`

`$ docker container stop <CONTAINER NAME | CONTAINER ID>`

注意

10\. 重新启动 Jenkins 容器：

`$ docker container ls`

`$ docker container start <CONTAINER NAME | CONTAINER ID>`

现在，作业将成功构建。

1.  点击“返回仪表板”。将出现以下屏幕。在左下角，您将看到“构建队列”和“构建执行器状态”字段。您可以看到一个构建已经开始，并且旁边有`#1`，如*图 8.19*所示：![图 8.19：检查构建队列](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-ws/img/B15021_08_19.jpg)

图 8.19：检查构建队列

构建尚未成功或失败。构建完成后，其状态将显示在屏幕上。过一段时间，您会发现已经进行了两次构建。

1.  单击`最后成功`字段下的`#2`旁边的小箭头。将出现一个下拉菜单，如下图所示。选择`控制台输出`以检查 Jenkins 自动为我们执行的操作，如*图 8.20*所示：![图 8.20：选择控制台输出](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-ws/img/B15021_08_20.jpg)

图 8.20：选择控制台输出

在`控制台输出`中，您会发现 Jenkins 执行了您在项目配置期间在`构建`步骤中输入的`docker build`命令：

向下滚动到`控制台输出`的底部，以查看执行结果。您将看到镜像已成功构建。您还会找到镜像 ID 和标签：

![图 8.21：验证镜像是否成功构建](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-ws/img/B15021_08_21.jpg)

图 8.21：验证镜像是否成功构建

1.  从终端验证镜像 ID 和标签。重新运行`docker images`命令。

```
$docker images
```

您会发现已为您创建了`hit_counter`镜像。您还会发现`python:3.7-alpine`镜像，因为这是`Dockerfile`中的基础镜像，Jenkins 已自动拉取它：

```
REPOSITORY           TAG           IMAGE ID
  CREATED                      SIZE
jenkinsci/blueocean  latest        e287a467e019
  Less than a second ago       562MB
hit_counter          latest        bdaf6486f2ce
  3 minutes ago                227MB
python               3.7-alpine    6a5ca85ed89b
  2 weeks ago                  72.5MB
```

通过这一步，您可以确认 Jenkins 能够成功地从 GitHub 拉取文件。

1.  现在，您将在 GitHub 代码中进行所需的更改。但首先，请验证您尚未提交任何更改到代码。返回 Jenkins，向上滚动并在顶部的左侧菜单中单击`返回项目`。然后单击`最近的更改`，如*图 8.22*所示：![图 8.22：选择最近的更改](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-ws/img/B15021_08_22.jpg)

图 8.22：选择最近的更改

Jenkins 将显示所有构建中都没有更改，如下图所示：

![图 8.23：验证代码中的更改](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-ws/img/B15021_08_23.jpg)

图 8.23：验证代码中的更改

1.  前往 GitHub，并编辑`Dockerfile`，将基础镜像的标签从`3.7-alpine`更改为仅`alpine`。

您也可以像以前一样从终端通过任何文本编辑器编辑文件来执行相同操作。然后运行`git add`和`git push`命令：

```
$ git add Dockerfile
$ git commit -m "editing the Dockerfile"
$ git push -u destination master
```

1.  向下滚动并将更改提交到 GitHub。

1.  返回 Jenkins。删除`hit_counter`和`python:3.7-alpine`镜像，以确保 Jenkins 不使用先前的本地镜像：

```
$ docker rmi hit_counter python:3.7-alpine
```

1.  再次点击`立即构建`以立即开始构建作业。刷新`最近更改`页面。它将显示一个消息，说明发生了变化。

如果您点击发生的更改，它会将您转到 GitHub，显示旧代码和新代码之间的差异。

1.  点击浏览器返回到 Jenkins。再次检查`控制台输出`，以查看 Jenkins 使用的基础镜像：

在底部，您会发现 Jenkins 成功构建了镜像。

1.  转到终端并再次检查镜像：

```
$ docker images
```

您会发现`hit_counter`和`python:alpine`在列表上：

```
REPOSITORY             TAG           IMAGE ID
  CREATED                      SIZE
jenkinsci/blueocean    latest        e287a467e019
  Less than a second ago       562MB
hit_counter            latest        6288f76c1f15
  3 minutes ago                234MB
<none>                 <none>        786bdbef6ea2
  10 minutes ago               934MB
python                 alpine        8ecf5a48c789
  2 weeks ago                  78.9MB
```

1.  清理您的实验室，以便进行下一个练习，删除除`jenkinsci/blueocean`之外的所有列出的镜像：

```
$ docker image rm hit_counter python:alpine 786
```

在这个练习中，您学会了如何将 Jenkins 与 GitHub 集成。Jenkins 能够自动从 GitHub 拉取代码并构建镜像。

在接下来的部分，您将学习如何将这个镜像推送到您的注册表，而无需手动干预，以完成您的 CI/CD 流水线。

# 集成 Jenkins 和 Docker Hub

在本节中，就像*图 8.31*中一样，我们将专注于我们的 CI/CD 流水线的最后一步，即将 Jenkins 与 Docker Hub 集成。正如我们之前提到的，市面上有很多注册表。我们将使用 Docker Hub，因为它是免费且易于使用的。在您的工作场所，您的公司可能会有一个私有的本地注册表。您需要向运维或 IT 管理员申请一个账户，并授予您一些权限，以便您能够访问注册表并将您的镜像推送到其中。

![图 8.24：集成 Jenkins 和 Docker Hub](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-ws/img/B15021_08_24.jpg)

图 8.24：集成 Jenkins 和 Docker Hub

在接下来的练习中，您将学习如何将 Jenkins 与 Docker Hub 集成，以及如何推送 Jenkins 在上一个练习中构建的镜像。

## 练习 8.04：集成 Jenkins 和 Docker Hub

在这个练习中，您将把 Jenkins 与 Docker Hub 集成，并将该镜像推送到您的存储库。首先，您将安装`Docker`、`docker-build-step`和“Cloudbees Docker 构建和发布”插件，以便 Jenkins 可以连接到 Docker Hub。然后，您将学习如何在 Jenkins 中输入您的 Docker Hub 凭据，以便 Jenkins 可以自动访问您的 Docker Hub 帐户并将您的镜像推送到其中。最后，您将在 Docker Hub 中检查您的镜像，以验证流水线是否正确执行。在本练习结束时，您将通过检查您的 Docker Hub 帐户来验证镜像是否成功推送到存储库：

1.  点击左侧菜单中的“管理 Jenkins”以安装插件：![图 8.25：点击“管理 Jenkins”](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-ws/img/B15021_08_25.jpg)

图 8.25：点击“管理 Jenkins”

1.  点击“插件管理”。会出现四个选项卡。点击“可用”选项卡，然后选择`Docker`、`docker-build-step`和“Cloudbees Docker 构建和发布”插件：![图 8.26：安装 Docker、docker-build-step 和 CloudbeesDocker 构建和发布插件](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-ws/img/B15021_08_26.jpg)

图 8.26：安装 Docker、docker-build-step 和 Cloudbees Docker 构建和发布插件

1.  点击“无需重启安装”。安装完成后，勾选“安装完成且没有作业运行时重新启动 Jenkins”。

1.  Jenkins 将花费较长时间来重新启动，具体取决于您的磁盘空间、内存和互联网连接速度。等待直到完成，并显示仪表板。点击项目的名称，即`hit_count`：![图 8.27：Jenkins 仪表板显示 hit_count 项目](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-ws/img/B15021_08_27.jpg)

图 8.27：Jenkins 仪表板显示 hit_count 项目

1.  点击左侧菜单中的“配置”以修改项目配置：![图 8.28：左侧菜单中的配置选项](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-ws/img/B15021_08_28.jpg)

图 8.28：左侧菜单中的配置选项

1.  只修改“构建”选项卡中的详细信息。点击它，然后选择“添加构建步骤”。会出现比之前更大的菜单。如果你在菜单中看到“Docker 构建和发布”，那么说明你的插件安装成功了。点击“Docker 构建和发布”：![图 8.29：从菜单中选择 Docker 构建和发布](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-ws/img/B15021_08_29.jpg)

图 8.29：从菜单中选择 Docker 构建和发布

1.  在“注册表凭据”中，点击“添加”。然后从下拉菜单中选择`Jenkins`。

1.  将出现一个弹出框。输入您的 Docker Hub 用户名和密码。然后，单击“添加”：![图 8.30：添加 Jenkins 凭据](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-ws/img/B15021_08_30.jpg)

图 8.30：添加 Jenkins 凭据

1.  现在，在“注册表凭据”中，单击第一个下拉菜单，并选择您在上一步中输入的凭据。然后，在“存储库名称”字段中输入“<您的 Docker Hub 用户名>/<图像名称>”。通过单击右上角的红色`X`删除您在*练习 8.02*“将代码上传到 GitHub”中输入的“执行 Shell”选项。现在，您将只有一个构建步骤，即“Docker 构建和发布”步骤。单击“保存”以保存新配置：![图 8.31：Docker 构建和发布步骤](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-ws/img/B15021_08_31.jpg)

图 8.31：Docker 构建和发布步骤

1.  再次在左侧菜单中单击“立即构建”，并在“构建历史”选项中，跟踪图像构建的进度。它将与您在上一步中指定的“存储库名称”相同。Jenkins 将自动添加`docker build`步骤，因为您从插件中选择了它。如果图像成功通过构建，Jenkins 将使用您的 Docker 凭据并自动连接到 Docker Hub 或您在“存储库名称”中指定的任何注册表。最后，Jenkins 将自动将新图像推送到您的注册表，这在本练习中是您的 Docker Hub 注册表。

1.  作为进一步检查，当图像正在构建并在完成之前，转到终端并使用`docker images`命令列出您拥有的图像：

```
$ docker images
```

因为您在上一练习结束时清理了实验室，所以您应该只会找到`jenkinsci/blueocean`图像：

```
REPOSITORY              TAG        IMAGE ID
  CREATED                       SIZE
jenkinsci/blueocean     latest     e287a467e019
  Less than a second ago        562MB
```

此外，检查您的 Docker Hub 帐户，以验证是否构建了`hit_counter`图像。您将找不到`hit_counter`图像：

![图 8.32：检查您的 Docker Hub](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-ws/img/B15021_08_32.jpg)

图 8.32：检查您的 Docker Hub

1.  如果作业成功构建，您将在图像名称旁边找到一个蓝色的球。如果是红色的球，这意味着出现了错误。现在，单击图像名称旁边的箭头，并选择“控制台输出”：![图 8.33：选择控制台输出](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-ws/img/B15021_08_33.jpg)

图 8.33：选择控制台输出

如下图所示，您将发现 Jenkins 成功构建了图像并将其推送到您的 Docker Hub：

![图 8.34：在控制台输出中，验证 Jenkins 是否已构建并推送了图像](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-ws/img/B15021_08_34.jpg)

图 8.34：在控制台输出中，验证 Jenkins 是否已构建并推送了镜像

1.  返回终端并重新运行`docker images`命令以列出镜像：

```
$ docker images
```

您将在`<your Docker Hub Username>/hit_count`中找到一张图片：

```
REPOSITORY             TAG             IMAGE ID
  CREATED                      SIZE
jenkinsci/blueocean    latest          e287a467e019
  Less than a second ago       562MB
engyfouda/hit_count    latest          65e2179392ca
  5 minutes ago                227MB
<none>                 <none>          cf4adcf1ac88
  10 minutes ago               1.22MB
python                 3.7alpine       6a5ca85ed89b
  2 weeks ago                  72.5MB
```

1.  在浏览器中刷新 Docker Hub 页面。您会在顶部找到您的镜像；Jenkins 会自动为您推送它：![图 8.35：验证 Jenkins 是否已自动将镜像推送到您的 Docker Hub](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-ws/img/B15021_08_35.jpg)

图 8.35：验证 Jenkins 是否已自动将镜像推送到您的 Docker Hub

在这个练习中，我们完成了 CI/CD 管道的最后阶段，并将 Jenkins 与 Docker Hub 集成。Jenkins 将构建的镜像推送到 Docker Hub。您还通过检查 Docker Hub 账户来验证镜像是否被正确推送。

在下一个活动中，我们将应用相同的方法来安装额外的插件，将 Jenkins 与 SonarQube 集成。SonarQube 是另一个强大的工具，可以分析代码并生成关于其质量的报告，并在大量编程语言中检测错误、代码异味和安全漏洞。

## 活动 8.01：利用 Jenkins 和 SonarQube

通常，在提交代码给测试人员之前，您会被要求评估代码的质量。您可以利用 Jenkins 进一步检查代码，通过添加 SonarQube 插件生成关于调试错误、代码异味和安全漏洞的报告。

在这个活动中，我们将利用 Jenkins 和 SonarQube 插件来进行我们的`hit_count` Python 示例。

**步骤**：

1.  在容器中安装和运行 SonarQube，就像你在*练习 8.01*，*将 Jenkins 安装为容器*中所做的那样。使用默认端口`9000`。

1.  在 Jenkins 中安装 SonarQube 插件。使用`admin/admin`登录 SonarQube 并生成身份验证令牌。不要忘记复制令牌并将其保存在文本文件中。在这一步之后，您将无法检索到令牌。如果您丢失了令牌，请删除 SonarQube 容器，像*步骤 1*中重新构建它，并重新执行这些步骤。

1.  重新启动 Jenkins。

1.  在 Jenkins 中，将 SonarQube 的身份验证令牌添加到`全局凭据`域中作为秘密文本。

1.  通过调整`全局系统配置`和`配置系统`选项来将 Jenkins 与 SonarQube 集成。

1.  通过启用`准备 SonarQube 扫描仪`环境来修改`构建环境`选项卡中的字段。

1.  修改`构建`步骤并添加`分析属性`。

1.  在浏览器中，转到 SonarQube 窗口，并检查其报告。

输出应该如下所示：

![图 8.36：预期的 SonarQube 输出](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-ws/img/B15021_08_36.jpg)

图 8.36：预期的 SonarQube 输出

注意

此活动的解决方案可以通过此链接找到。

在下一个活动中，您将集成 Jenkins 和 SonarQube 与我们的全景徒步应用程序。

## 活动 8.02：在全景徒步应用中利用 Jenkins 和 SonarQube

全景徒步应用程序也有前端和后端，就像`hit_counter`应用程序一样。在这个活动中，您将在 Jenkins 中创建一个新项目，该项目链接到 GitHub 上的全景徒步应用程序。然后，您将运行 SonarQube 以获取关于其错误和安全漏洞的详细报告，如果徒步应用程序有任何问题的话。

按照以下步骤完成活动：

1.  在 Jenkins 中创建一个名为`trekking`的新项目。

1.  将其选择为`FREESTYLE`项目。

1.  在“常规”选项卡中，选择“丢弃旧构建”。

1.  在“源代码管理”中，选择`GIT`。然后输入 URL`http://github.com/efoda/trekking_app`。

1.  在“构建触发器”中，选择“轮询 SCM”，并将其设置为每 15 分钟进行分析和测试。

1.  在“构建”选项卡中，输入“分析属性”代码。

1.  保存并单击“立即构建”。

1.  在浏览器的`SonarQube`选项卡中检查报告。

输出应该如下所示在 SonarQube 中：

![图 8.37：活动 8.02 的预期输出](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-ws/img/B15021_08_37.jpg)

图 8.37：活动 8.02 的预期输出

注意

此活动的解决方案可以通过此链接找到。

# 摘要

本章提供了集成代码使用 CI/CD 流水线的实际经验。CI 帮助开发人员将代码集成到共享和易于访问的存储库中。CD 帮助开发人员将存储在存储库中的代码交付到生产环境。CI/CD 方法还有助于使产品与最新技术保持同步，并为新功能和错误修复提供快速交付的最新版本给客户。

一旦本章定义的 CI/CD 流水线的三个阶段成功完成，您只需要专注于在 GitHub 上编辑您的代码。Jenkins 将成为您的自动助手，并且将自动处理其余的阶段，并使图像可用于生产。

在下一章中，您将学习关于 Docker 集群模式以及如何执行服务发现、集群、扩展和滚动更新。
