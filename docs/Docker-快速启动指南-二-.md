# Docker 快速启动指南（二）

> 原文：[`zh.annas-archive.org/md5/23ECB0A103B038BBAFCFDE067D60BC3D`](https://zh.annas-archive.org/md5/23ECB0A103B038BBAFCFDE067D60BC3D)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第四章：Docker 卷

在本章中，我们将学习 Docker 卷的秘密。我们将学习如何在 Docker 容器内部使用工作站上的文件夹，以及如何创建和使用持久卷，允许多个容器共享数据。我们将学习如何清理未使用的卷。最后，我们将学习如何创建数据卷容器，成为其他容器的卷的来源。

每年大约有 675 个集装箱在海上丢失。1992 年，一个装满玩具的 40 英尺集装箱实际上掉进了太平洋，10 个月后，其中一些玩具漂到了阿拉斯加海岸 - [`www.clevelandcontainers.co.uk/blog/16-fun-facts-about-containers`](https://www.clevelandcontainers.co.uk/blog/16-fun-facts-about-containers)

在本章中，我们将涵盖以下主题：

+   什么是 Docker 卷？

+   创建 Docker 卷

+   删除 Docker 卷的两种方法

+   使用数据卷容器在容器之间共享数据

# 技术要求

您将从 Docker 的公共存储库中拉取 Docker 镜像，因此需要基本的互联网访问权限来执行本章中的示例。

本章的代码文件可以在 GitHub 上找到：

[`github.com/PacktPublishing/Docker-Quick-Start-Guide/tree/master/Chapter04`](https://github.com/PacktPublishing/Docker-Quick-Start-Guide/tree/master/Chapter04)

查看以下视频以查看代码的运行情况：[`bit.ly/2QqK78a`](http://bit.ly/2QqK78a)

# 什么是 Docker 卷？

正如我们在第三章中学到的，Docker 使用一种称为**联合文件系统**的特殊文件系统。这是 Docker 分层镜像模型的关键，也允许许多使用 Docker 变得如此令人向往的功能。然而，联合文件系统无法提供数据的持久存储。回想一下，Docker 镜像的层是只读的。当你从 Docker 镜像运行一个容器时，Docker 守护进程会创建一个新的读写层，其中包含代表容器的所有实时数据。当容器对其文件系统进行更改时，这些更改会进入该读写层。因此，当容器消失时，带着读写层一起消失，容器对该层内数据所做的任何更改都将被删除并永远消失。这等同于非持久存储。然而，请记住，一般来说这是一件好事。事实上，是一件很好的事情。大多数情况下，这正是我们希望发生的。容器是临时的，它们的状态数据也是如此。然而，持久数据有很多用例，比如购物网站的客户订单数据。如果一个容器崩溃或需要重新堆叠，如果所有订单数据都消失了，那将是一个相当糟糕的设计。

这就是 Docker 卷的作用。Docker 卷是一个完全独立于联合文件系统之外的存储位置。因此，它不受镜像的只读层或容器的读写层所施加的相同规则的约束。Docker 卷是一个存储位置，默认情况下位于运行使用该卷的容器的主机上。当容器消失时，无论是出于设计还是因为灾难性事件，Docker 卷都会留下并可供其他容器使用。Docker 卷可以同时被多个容器使用。

描述 Docker 卷最简单的方式是：Docker 卷是一个存在于 Docker 主机上并在运行的 Docker 容器内部挂载和访问的文件夹。这种可访问性是双向的，允许从容器内部修改该文件夹的内容，或者在文件夹所在的 Docker 主机上进行修改。

现在，这个描述有点泛化。使用不同的卷驱动程序，作为卷被挂载的文件夹的实际位置可能不在 Docker 主机上。使用卷驱动程序，您可以在远程主机或云提供商上创建您的卷。例如，您可以使用 NFS 驱动程序允许在远程 NFS 服务器上创建 Docker 卷。

与 Docker 镜像和 Docker 容器一样，卷命令代表它们自己的管理类别。正如您所期望的那样，卷的顶级管理命令如下：

```
# Docker volume managment command
docker volume
```

卷管理组中可用的子命令包括以下内容：

```
# Docker volume management subcommands
docker volume create # Create a volume
docker volume inspect # Display information on one or more volumes
docker volume ls # List volumes
docker volume rm # Remove one or more volumes
docker volume prune          # Remove all unused local volumes
```

有几种不同的方法可以创建 Docker 卷，所以让我们继续通过创建一些来调查 Docker 卷。

# 参考

查看以下链接以获取更多信息：

+   使用 Docker 卷的 Docker 参考：[`docs.docker.com/storage/volumes/`](https://docs.docker.com/storage/volumes/)

+   Docker 卷插件信息：[`docs.docker.com/engine/extend/plugins_volume/`](https://docs.docker.com/engine/extend/plugins_volume/)

+   Docker 引擎卷插件：[`docs.docker.com/engine/extend/legacy_plugins/#volume-plugins`](https://docs.docker.com/engine/extend/legacy_plugins/#volume-plugins)

# 创建 Docker 卷

有几种方法可以创建 Docker 卷。一种方法是使用`volume create`命令。该命令的语法如下：

```
# Syntax for the volume create command
Usage:  docker volume create [OPTIONS] [VOLUME]
```

除了可选的卷名称参数外，`create`命令还允许使用以下选项：

```
# The options available to the volume create command:
-d, --driver string         # Specify volume driver name (default "local")
--label list                # Set metadata for a volume
-o, --opt map               # Set driver specific options (default map[])
```

让我们从最简单的例子开始：

```
# Using the volume create command with no optional parameters
docker volume create
```

执行上述命令将创建一个新的 Docker 卷并分配一个随机名称。该卷将使用内置的本地驱动程序（默认情况下）。使用`volume ls`命令，您可以看到 Docker 守护程序分配给我们新卷的随机名称。它看起来会像这样：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-qk-st-gd/img/2073a1d1-1f61-47c2-b94d-7e410c5854c4.png)

再上一层，让我们创建另一个卷，这次使用命令提供一个可选的卷名称。命令看起来会像这样：

```
# Create a volume with a fancy name
docker volume create my-vol-02
```

这次，卷已创建，并被命名为`my-vol-02`，如所请求的：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-qk-st-gd/img/eff9a8b0-13cb-4efb-8a08-f24ae1580c30.png)

这个卷仍然使用默认的本地驱动程序。使用本地驱动程序只意味着这个卷所代表的文件夹的实际位置可以在 Docker 主机上本地找到。我们可以使用卷检查子命令来查看该文件夹实际上可以找到的位置：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-qk-st-gd/img/39fe956e-5fdb-43a7-86d3-cd6ba89060b6.png)

正如您在前面的屏幕截图中所看到的，该卷的挂载点位于 Docker 主机的文件系统上，路径为`/var/lib/docker/volumes/my-vol-02/_data`。请注意，文件夹路径由 root 所有，这意味着您需要提升的权限才能从主机访问该位置。还要注意，这个示例是在 Linux 主机上运行的。

如果您使用的是 OS X，您需要记住，您的 Docker 安装实际上是在使用一个几乎无缝的虚拟机。其中一个无缝显示的领域是使用 Docker 卷。在 OS X 主机上创建 Docker 卷时创建的挂载点存储在虚拟机的文件系统中，而不是在您的 OS X 文件系统中。当您使用 docker volume inspect 命令并查看卷的挂载点路径时，它不是您的 OS X 文件系统上的路径，而是隐藏虚拟机文件系统上的路径。

有一种方法可以查看隐藏虚拟机的文件系统（和其他功能）。通过一个命令，通常称为魔术屏幕命令，您可以访问正在运行的 Docker VM。该命令如下：

```
# The Magic Screen command
screen ~/Library/Containers/com.docker.docker/Data
/com.docker.driver.amd64-linux/tty
# or if you are using Mac OS High Sierra
screen ~/Library/Containers/com.docker.docker/Data/vms/0/tty
```

使用*Ctrl* + *AK*来终止屏幕会话。

您可以使用*Ctrl* + *A Ctrl* + *D*分离，然后使用`screen -r`重新连接，但不要分离然后启动新的屏幕会话。在 VM 上运行多个屏幕会给您 tty 垃圾。

这是一个在 OS X 主机上创建的卷的挂载点访问示例。这是设置：

```
# Start by creating a new volume
docker volume create my-osx-volume
# Now find the Mountpoint
docker volume inspect my-osx-volume -f "{{json .Mountpoint}}"
# Try to view the contents of the Mountpoint's folder
sudo ls -l /var/lib/docker/volumes/my-osx-volume
# "No such file or directory" because the directory does not exist on the OS X host
```

这就是设置的样子：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-qk-st-gd/img/5b7d7fed-96dd-4ba6-9d30-0c538740bba6.png)

现在，这是如何使用魔术屏幕命令来实现我们想要的，即访问卷的挂载点：

```
# Now issue the Magic Screen command and hit <enter> to get a prompt
screen ~/Library/Containers/com.docker.docker/Data/vms/0/tty
# You are now root in the VM, and can issue the following command
ls -l /var/lib/docker/volumes/my-osx**-volume** # The directory exists and you will see the actual Mountpoint sub folder "_data"
# Now hit control-a followed by lower case k to kill the screen session
<CTRL-a>k 
```

然后...

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-qk-st-gd/img/5d6fff12-917a-40f8-9b3b-a3c66a9d51f4.png)

现在是一个很好的时机指出，我们创建了这些卷，而从未创建或使用 Docker 容器。这表明 Docker 卷是在正常容器联合文件系统之外的领域。

我们在第三章中看到，*创建 Docker 镜像*，我们还可以使用容器运行命令上的参数或在 Dockerfile 中添加`VOLUME`指令来创建卷。并且，正如您所期望的那样，您可以使用 Docker `volume create`命令预先创建的卷通过使用容器运行参数，即`--mount`参数，将卷挂载到容器中，例如，如下所示：

```
# mount a pre-created volume with --mount parameter
docker container run --rm -d \
--mount source=my-vol-02,target=/myvol \
--name vol-demo2 \
volume-demo2:1.0 tail -f /dev/null
```

这个例子将运行一个新的容器，它将挂载现有的名为`my-vol-02`的卷。它将在容器中的`/myvol`处挂载该卷。请注意，前面的例子也可以在不预先创建`my-vol-02:volume`的情况下运行，使用`--mount`参数运行容器的行为将在启动容器的过程中创建卷。请注意，当挂载卷时，图像挂载点文件夹中定义的任何内容都将添加到卷中。但是，如果图像挂载点文件夹中存在文件，则它也存在于主机的挂载点，并且主机文件的内容将最终成为文件中的内容。使用此 Dockerfile 中的图像，看起来是这样的：

```
# VOLUME instruction Dockerfile for Docker Quick Start
FROM alpine
RUN mkdir /myvol
RUN echo "Data from image" > /myvol/both-places.txt
CMD ["sh"]
```

请注意`Data from image`行。现在，使用一个包含与`both-places.txt`匹配名称的文件的预先创建的卷，但文件中包含`Data from volume`内容，我们将基于该图像运行一个容器。发生了什么：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-qk-st-gd/img/07d94005-aefb-4b4a-ba28-a0b452e64ca2.png)

正如您所看到的，尽管 Dockerfile 创建了一个带有`Data from image`内容的文件，但当我们从该图像运行一个容器并挂载一个具有相同文件的卷时，卷中的内容（`Data from volume`）占优势，并且是在运行容器中找到的内容。

请记住，无法通过 Dockerfile 中的`VOLUME`指令挂载预先创建的卷。不存在名为 volume 的 Dockerfile `VOLUME`指令。原因是 Dockerfile 无法指定卷从主机挂载的位置。允许这样做会有几个原因。首先，由于 Dockerfile 创建了一个镜像，从该镜像运行的每个容器都将尝试挂载相同的主机位置。这可能会很快变得非常糟糕。其次，由于容器镜像可以在不同的主机操作系统上运行，很可能一个操作系统的主机路径定义在另一个操作系统上甚至无法工作。再次，很糟糕。第三，定义卷主机路径将打开各种安全漏洞。糟糕，糟糕，糟糕！因此，使用 Dockerfile 构建的图像运行具有`VOLUME`指令的容器将始终在主机上创建一个新的，具有唯一名称的挂载点。在 Dockerfile 中使用`VOLUME`指令的用途有些有限，例如当容器将运行始终需要读取或写入预期在文件系统中特定位置的数据的应用程序，但不应该是联合文件系统的一部分。

还可以在主机上的文件与容器中的文件之间创建一对一的映射。要实现这一点，需要在容器运行命令中添加一个`-v`参数。您需要提供要从主机共享的文件的路径和文件名，以及容器中文件的完全限定路径。容器运行命令可能如下所示：

```
# Map a single file from the host to a container
echo "important data" > /tmp/data-file.txt
docker container run --rm -d \
 -v /tmp/data-file.txt:/myvol/data-file.txt \
 --name vol-demo \
 volume-demo2:1.0 tail -f /dev/null
# Prove it
docker exec vol-demo cat /myvol/data-file.txt
```

可能如下所示：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-qk-st-gd/img/032361dd-e5c7-413f-9808-95f9a6022f8c.png)

有几种不同的方法可以在容器运行命令中定义卷。为了说明这一点，看看以下运行命令，每个都将完成相同的事情：

```
# Using --mount with source and target
docker container run --rm -d \
 --mount source=my-volume,target=/myvol,readonly \
 --name vol-demo1 \
 volume-demo:latest tail -f /dev/null
 # Using --mount with source and destination
docker container run --rm -d \
 --mount source=my-volume,destination=/myvol,readonly \
 --name vol-demo2 \
 volume-demo:latest tail -f /dev/null
 # Using -v 
docker container run --rm -d \
 -v my-volume:/myvol:ro \
 --name vol-demo3 \
 volume-demo:latest tail -f /dev/null
```

前面三个容器运行命令都将创建一个已挂载相同卷的容器，以只读模式。可以使用以下命令进行验证：

```
# Check which container have mounted a volume by name
docker ps -a --filter volume=in-use-volume
```

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-qk-st-gd/img/7ad05dcb-f85f-488e-947d-c83d390a8360.png)

# 参考资料

查看以下链接获取更多信息：

+   Docker `volume create`参考：[`docs.docker.com/engine/reference/commandline/volume_create/`](https://docs.docker.com/engine/reference/commandline/volume_create/)

+   Docker 存储参考文档：[`docs.docker.com/storage/`](https://docs.docker.com/storage/)

# 删除卷

我们已经看到并使用了卷列表命令`volume ls`和检查命令`volume inspect`，我认为您应该对这些命令的功能有很好的理解。卷管理组中还有另外两个命令，都用于卷的移除。第一个是`volume rm`命令，您可以使用它按名称移除一个或多个卷。然后，还有`volume prune`命令；使用清理命令，您可以移除所有未使用的卷。在使用此命令时要特别小心。以下是删除和清理命令的语法：

```
# Remove volumes command syntax
Usage: docker volume rm [OPTIONS] VOLUME [VOLUME...]
# Prune volumes command syntax
Usage: docker volume prune [OPTIONS]
```

以下是使用删除和清理命令的一些示例：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-qk-st-gd/img/21aedc2c-bc31-4731-a064-d4ca50ece52e.png)

由于`in-use-volume`卷被挂载在`vol-demo`容器中，它没有被清理命令移除。您可以在卷列表命令上使用过滤器，查看哪些卷与容器不相关，因此将在清理命令中被移除。以下是过滤后的 ls 命令：

```
# Using a filter on the volume ls command
docker volume ls --filter dangling=true
```

# 参考资料

查看以下链接以获取更多信息：

+   Docker 的卷删除命令的维基文档：[`docs.docker.com/engine/reference/commandline/volume_rm/`](https://docs.docker.com/engine/reference/commandline/volume_rm/)

+   Docker 的卷清理命令的维基文档：[`docs.docker.com/engine/reference/commandline/volume_prune`](https://docs.docker.com/engine/reference/commandline/volume_prune)/

+   有关清理 Docker 对象的信息：[`docs.docker.com/config/pruning/`](https://docs.docker.com/config/pruning/)

# 使用数据卷容器在容器之间共享数据

Docker 卷的另一个功能允许您将一个 Docker 容器中挂载的卷与其他容器共享。这被称为**数据卷容器**。使用数据卷容器基本上是一个两步过程。在第一步中，您运行一个容器，该容器创建或挂载 Docker 卷（或两者），在第二步中，当运行其他容器时，您使用特殊的卷参数`--volumes-from`来配置它们挂载在第一个容器中的所有卷。以下是一个例子：

```
# Step 1
docker container run \
 --rm -d \
 -v data-vol-01:/data/vol1 -v data-vol-02:/data/vol2 \
 --name data-container \
 vol-demo2:1.0 tail -f /dev/null
# Step 2
docker container run \
 --rm -d \
 --volumes-from data-container \
 --name app-container \
 vol-demo2:1.0 tail -f /dev/null
# Prove it
docker container exec app-container ls -l /data
# Prove it more
docker container inspect -f '{{ range .Mounts }}{{ .Name }} {{ end }}' app-container
```

执行时的样子如下：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-qk-st-gd/img/9da94735-93f4-4976-bc7b-1451b0ebf11a.png)

在这个例子中，第一个容器运行命令正在创建卷，但它们也可以很容易地在之前的容器运行命令中预先创建，或者来自`volume create`命令。

# 参考资料

这是一篇关于数据卷容器的优秀文章，包括如何使用它们进行数据备份和恢复：[`www.tricksofthetrades.net/2016/03/14/docker-data-volumes/`](https://www.tricksofthetrades.net/2016/03/14/docker-data-volumes/)。

# 摘要

在本章中，我们深入探讨了 Docker 卷。我们了解了 Docker 卷的实际含义，以及创建它们的几种方法。我们学习了使用`volume create`命令、容器运行命令和 Dockerfile 的`VOLUME`指令创建 Docker 卷的区别。我们还看了一些删除卷的方法，以及如何使用数据容器与其他容器共享卷。总的来说，你现在应该对自己的 Docker 卷技能感到非常自信。到目前为止，我们已经建立了扎实的 Docker 知识基础。

在第五章中，*Docker Swarm*，我们将通过学习 Docker Swarm 来扩展基础知识。这将是真正开始变得令人兴奋的地方。如果你准备好学习更多，请翻页！


# 第五章：Docker Swarm

在本章中，我们将学习什么是 Docker swarm，以及如何设置 Docker swarm 集群。我们将了解所有的集群管理命令，然后我们将更多地了解集群管理者和集群工作者。接下来，我们将发现集群服务。最后，我们将发现在集群中任何节点上运行的容器应用程序是多么容易访问。

目前全球有超过 17,000,000 个集装箱，其中 5 或 6,000,000 个正在船舶、卡车和火车上运输。总共，它们每年大约进行 200,000,000 次旅行。- [`www.billiebox.co.uk/facts-about-shipping-containers`](https://www.billiebox.co.uk/facts-about-shipping-containers)

在本章中，我们将涵盖以下主题：

+   什么是 Docker swarm？

+   建立 Docker swarm 集群

+   管理者和工作者

+   集群服务

+   访问集群中的容器应用程序

# 技术要求

您将从 Docker 的公共存储库中拉取 Docker 镜像，因此需要基本的互联网访问权限来执行本章中的示例。您将设置一个多节点的集群，因此需要多个节点来完成本章的示例。您可以使用物理服务器、EC2 实例、vSphere 或 Workstation 上的虚拟机，甚至是 Virtual Box 上的虚拟机。我在 Vmware Workstation 上使用了 6 个虚拟机作为我的节点。每个虚拟机配置为 1GB 内存、1 个 CPU 和 20GB 硬盘。所使用的客户操作系统是 Xubuntu 18.04，因为它体积小且具有完整的 Ubuntu 功能集。Xubuntu 可以从[`xubuntu.org/download/`](https://xubuntu.org/download/)下载。任何现代的 Linux 操作系统都可以作为节点的选择。

本章的代码文件可以在 GitHub 上找到：

[`github.com/PacktPublishing/Docker-Quick-Start-Guide/tree/master/Chapter05`](https://github.com/PacktPublishing/Docker-Quick-Start-Guide/tree/master/Chapter05)

查看以下视频以查看代码的运行情况：[`bit.ly/2KENJOD`](http://bit.ly/2KENJOD)

# 什么是 Docker swarm？

你可能没有注意到，但到目前为止，我们在示例中使用的所有 Docker 工作站部署或节点都是以单引擎模式运行的。这是什么意思？这告诉我们，Docker 安装是直接管理的，作为一个独立的 Docker 环境。虽然这是有效的，但它不太高效，也不具有良好的扩展性。当然，Docker 了解到这些限制，并为这个问题提供了一个强大的解决方案。它被称为 Docker 蜂群。Docker 蜂群是将 Docker 节点连接在一起，并有效地管理这些节点和在其上运行的 docker 化应用程序的一种方式。简而言之，Docker 蜂群是一组 Docker 节点连接并作为集群或蜂群进行管理。Docker 蜂群内置在 Docker 引擎中，因此无需额外安装即可使用。当 Docker 节点是蜂群的一部分时，它运行在蜂群模式下。如果有任何疑问，您可以使用`docker system info`命令轻松检查运行 Docker 的系统是否是蜂群的一部分或者是以单引擎模式运行：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-qk-st-gd/img/9e0e8cfa-39dd-47f7-a668-80354184afee.png)

提供蜂群模式的功能是 Docker SwarmKit 的一部分，这是一个用于在规模上编排分布式系统的工具，即 Docker 蜂群集群。一旦 Docker 节点加入蜂群，它就成为蜂群节点，成为管理节点或工作节点。我们很快会谈到管理节点和工作节点之间的区别。现在，知道加入新蜂群的第一个 Docker 节点成为第一个管理节点，也被称为领导者。当第一个节点加入蜂群并成为领导者时，会发生很多技术上的魔法（实际上，它创建并初始化了蜂群，然后加入了蜂群）。以下是发生的一些巫术（没有特定顺序）：

+   创建了基于 Swarm-ETCD 的配置数据库或集群存储，并进行了加密

+   为所有节点间通信设置了双向 TLS（mTLS）认证和加密

+   启用了容器编排，负责管理容器在哪些节点上运行

+   集群存储被配置为自动复制到所有管理节点

+   该节点被分配了一个加密 ID

+   启用了基于 Raft 的分布式共识管理系统

+   节点成为管理节点并被选举为蜂群领导者

+   蜂群管理器被配置为高可用

+   创建了一个公钥基础设施系统

+   节点成为证书颁发机构，允许其向加入集群的任何节点颁发客户端证书

+   证书颁发机构上配置了默认的 90 天证书轮换策略

+   节点获得其客户端证书，其中包括其名称、ID、集群 ID 和节点在集群中的角色

+   为添加新的 swarm 管理者创建一个新的加密加入令牌

+   为添加新的 swarm 工作节点创建一个新的加密加入令牌

该列表代表了通过将第一个节点加入到 swarm 中获得的许多强大功能。伴随着强大的功能而来的是巨大的责任，这意味着您确实需要准备好做大量工作来创建您的 Docker swarm，正如您可能想象的那样。因此，让我们继续下一节，我们将讨论在设置 swarm 集群时如何启用所有这些功能。

# 参考资料

查看以下链接获取更多信息：

+   SwarmKit 的存储库：[`github.com/docker/swarmkit`](https://github.com/docker/swarmkit)

+   Raft 一致性算法：[`raft.github.io/`](https://raft.github.io/)

# 如何设置 Docker swarm 集群

您刚刚了解了创建 Docker swarm 集群时启用和设置的所有令人难以置信的功能。现在我将向您展示设置 Docker swarm 集群所需的所有步骤。准备好了吗？以下是它们：

```
# Set up your Docker swarm cluster
docker swarm init
```

什么？等等？剩下的在哪里？没有。没有遗漏任何内容。在上一节描述的所有设置和功能都可以通过一个简单的命令实现。通过单个的`swarm init`命令，集群被创建，节点从单实例节点转变为 swarm 模式节点，节点被分配为管理者角色并被选举为集群的领导者，集群存储被创建，节点成为集群的证书颁发机构并为自己分配一个包含加密 ID 的新证书，为管理者创建一个新的加密加入令牌，为工作节点创建另一个令牌，依此类推。这就是简化的复杂性。

swarm 命令组成了另一个 Docker 管理组。以下是 swarm 管理命令：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-qk-st-gd/img/bd6dff1c-08fb-4b1b-9361-ad8741316fff.png)

我们将在片刻后审查每个命令的目的，但在此之前，我想让您了解一些重要的网络配置。我们将在第六章 *Docker Networking*中更多地讨论 Docker 网络，但现在请注意，您可能需要在 Docker 节点上打开一些协议和端口的访问权限，以使 Docker swarm 正常运行。以下是来自 Docker 的*Getting started with swarm mode*维基的信息：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-qk-st-gd/img/4a75151b-36db-43db-b9e7-ab46c7288927.png)

您可能需要为 REST API 打开的另外两个端口如下：

+   TCP 2375 用于 Docker REST API（纯文本）

+   TCP 2376 用于 Docker REST API（ssl）

好了，让我们继续审查 swarm 命令。

# docker swarm init

您已经看到了 init 命令的用途，即创建 swarm 集群，将第一个 Docker 节点添加到其中，然后设置和启用我们刚刚介绍的所有 swarm 功能。init 命令可以简单地使用它而不带任何参数，但有许多可用的可选参数可用于微调初始化过程。您可以通过使用`--help`获得所有可选参数的完整列表，但现在让我们考虑一些可用的参数：

+   `--autolock`：使用此参数启用管理器自动锁定。

+   `--cert-expiry duration`：使用此参数更改节点证书的默认有效期（90 天）。

+   `--external-ca external-ca`：使用此参数指定一个或多个证书签名端点，即外部 CA。

# docker swarm join-token

当您在第一个节点上运行`swarm init`命令初始化 swarm 时，执行的功能之一是创建唯一的加密加入令牌，一个加入额外的管理节点，一个加入工作节点。使用`join-token`命令，您可以获取这两个加入令牌。实际上，使用`join-token`命令将为您提供指定角色的完整加入命令。角色参数是必需的。以下是命令的示例：

```
# Get the join token for adding managers
docker swarm join-token manager
# Get the join token for adding workers
docker swarm join-token worker
```

以下是它的样子：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-qk-st-gd/img/2f9b447e-3447-40f2-8449-5f4d754a4182.png)

```
# Rotate the worker join token
docker swarm join-token --rotate worker
```

请注意，这不会使已使用旧的、现在无效的加入令牌的现有工作节点失效。它们仍然是 swarm 的一部分，并且不受加入令牌更改的影响。只有您希望加入 swarm 的新节点需要使用新令牌。

# docker swarm join

您已经在前面的 *docker swarm join-token* 部分看到了 join 命令的使用。join 命令与加密的 join token 结合使用，用于将 Docker 节点添加到 swarm 中。除了第一个节点之外，所有节点都将使用 join 命令加入到 swarm 中（第一个节点当然使用 "init" 命令）。join 命令有一些参数，其中最重要的是 `--token` 参数。这是必需的 join token，可通过 `join-token` 命令获取。以下是一个示例：

```
# Join this node to an existing swarm
docker swarm join --token SWMTKN-1-3ovu7fbnqfqlw66csvvfw5xgljl26mdv0dudcdssjdcltk2sen-a830tv7e8bajxu1k5dc0045zn 192.168.159.156:2377
```

您会注意到，此命令不需要角色。这是因为 token 本身与其创建的角色相关联。当您执行 join 时，输出会提供一个信息消息，告诉您节点加入的角色是管理节点还是工作节点。如果您无意中使用了管理节点 token 加入工作节点，或反之，您可以使用 `leave` 命令将节点从 swarm 中移除，然后使用实际所需角色的 token，重新将节点加入到 swarm。

# docker swarm ca

当您想要查看 swarm 的当前证书或需要旋转当前的 swarm 证书时，可以使用 `swarm ca` 命令。要旋转证书，您需要包括 `--rotate` 参数：

```
# View the current swarm certificate
docker swarm ca
# Rotate the swarm certificate
docker swarm ca --rotate
```

`swarm ca` 命令只能在 swarm 管理节点上成功执行。您可能使用旋转 swarm 证书功能的一个原因是，如果您正在从内部根 CA 切换到外部 CA，或者反之。另一个可能需要旋转 swarm 证书的原因是，如果一个或多个管理节点受到了威胁。在这种情况下，旋转 swarm 证书将阻止所有其他管理节点能够使用旧证书与旋转证书的管理节点或彼此进行通信。旋转证书时，命令将保持活动状态，直到所有 swarm 节点（管理节点和工作节点）都已更新。以下是在一个非常小的集群上旋转证书的示例：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-qk-st-gd/img/2a03929d-d015-43f8-a233-3a03370983b6.png)

由于命令将保持活动状态，直到所有节点都更新了 TLS 证书和 CA 证书，如果集群中有离线的节点，可能会出现问题。当这是一个潜在的问题时，您可以包括`--detach`参数，命令将启动证书旋转并立即返回会话控制。请注意，当您使用`--detach`可选参数时，您将不会得到有关证书旋转进度、成功或失败的任何状态。您可以使用 node ls 命令查询集群中证书的状态以检查进度。以下是您可以使用的完整命令：

```
# Query the state of the certificate rotation in a swarm cluster
docker node ls --format '{{.ID}} {{.Hostname}} {{.Status}} {{.TLSStatus}}'
```

`ca rotate`命令将继续尝试完成，无论是在前台还是在后台（如果分离）。如果在旋转启动时节点离线，然后重新上线，证书旋转将完成。这里有一个示例，`node04`在执行旋转命令时处于离线状态，然后过了一会儿，它重新上线；检查状态发现它成功旋转了：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-qk-st-gd/img/5889e8b1-e526-4871-9c48-c0a45664a4c2.png)

另一个重要的要点要记住的是，旋转证书将立即使当前的加入令牌无效。

# docker swarm unlock

您可能还记得关于`docker swarm init`命令的讨论，其中一个可选参数是`--autolock`。使用此参数将在集群中启用自动锁定功能。这是什么意思？嗯，当一个集群配置为使用自动锁定时，任何时候管理节点的 docker 守护程序离线，然后重新上线（即重新启动），都需要输入解锁密钥才能允许节点重新加入集群。为什么要使用自动锁定功能来锁定您的集群？自动锁定功能有助于保护集群的相互 TLS 加密密钥，以及用于集群的 raft 日志的加密和解密密钥。这是一个旨在补充 Docker Secrets 的额外安全功能。当锁定的集群的管理节点上的 docker 守护程序重新启动时，您必须输入解锁密钥。以下是使用解锁密钥的样子：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-qk-st-gd/img/cb49b249-6ef8-4013-a8f4-a1aa987b8927.png)

顺便说一句，对于其余的群集，尚未解锁的管理节点将报告为已关闭，即使 Docker 守护程序正在运行。Swarm 自动锁定功能可以使用`swarm update`命令在现有的 Swarm 集群上启用或禁用，我们很快将看一下。解锁密钥是在 Swarm 初始化期间生成的，并将在那时在命令行上呈现。如果您丢失了解锁密钥，可以使用`swarm unlock-key`命令在未锁定的管理节点上检索它。

# docker swarm unlock-key

`swarm unlock-key`命令很像`swarm ca`命令。解锁密钥命令可用于检索当前的 Swarm 解锁密钥，或者可以用于将解锁密钥更改为新的：

```
# Retrieve the current unlock key
docker swarm unlock-key
# Rotate to a new unlock key
docker swarm unlock-key --rotate
```

根据 Swarm 集群的大小，解锁密钥轮换可能需要一段时间才能更新所有管理节点。

当您轮换解锁密钥时，最好在更新密钥之前将当前（旧）密钥随手放在一边，以防万一管理节点在获取更新的密钥之前离线。这样，您仍然可以使用旧密钥解锁节点。一旦节点解锁并接收到轮换（新）解锁密钥，旧密钥就可以丢弃了。

正如您可能期望的那样，`swarm unlock-key`命令只在启用了自动锁定功能的集群的管理节点上使用时才有用。如果您的集群未启用自动锁定功能，可以使用`swarm update`命令启用它。

# docker swarm update

在第一个管理节点上通过`docker swarm init`命令初始化集群时，将启用或配置几个 Swarm 集群功能。在集群初始化后，可能会有时候您想要更改哪些功能已启用、已禁用或已配置。要实现这一点，您需要使用`swarm update`命令。例如，您可能想要为 Swarm 集群启用自动锁定功能。或者，您可能想要更改证书有效期。这些都是您可以使用`swarm update`命令执行的更改类型。这样做可能看起来像这样：

```
# Enable autolock on your swarm cluster
docker swarm update --autolock=true
# Adjust certificate expiry to 30 days
docker swarm update --cert-expiry 720h
```

以下是`swarm update`命令可能影响的设置列表：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-qk-st-gd/img/4137a701-e2f1-4dd9-886a-7f344bcc1e65.png)

# docker swarm leave

这基本上是你所期望的。您可以使用`leave`命令从 swarm 中移除 docker 节点。以下是需要使用`leave`命令来纠正用户错误的示例：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-qk-st-gd/img/4e74723e-4d0d-4f2a-8d68-ca2e556fe0a0.png)

Node03 原本是一个管理节点。我不小心将该节点添加为工作者。意识到我的错误后，我使用`swarm leave`命令将节点从 swarm 中移除，将其放回单实例模式。然后，使用*manager*加入令牌，我将节点重新添加到 swarm 作为管理者。哦！危机已解除。

# 参考资料

查看以下链接获取更多信息：

+   使用 swarm 模式教程入门：[`docs.docker.com/engine/swarm/swarm-tutorial/`](https://docs.docker.com/engine/swarm/swarm-tutorial/)

+   `docker swarm init`命令的 wiki 文档：[`docs.docker.com/engine/reference/commandline/swarm_init/`](https://docs.docker.com/engine/reference/commandline/swarm_init/)

+   `docker swarm ca`命令的 wiki 文档：[`docs.docker.com/engine/reference/commandline/swarm_ca/`](https://docs.docker.com/engine/reference/commandline/swarm_ca/)

+   `docker swarm join-token`命令的 wiki 文档：[`docs.docker.com/engine/reference/commandline/swarm_join-token/`](https://docs.docker.com/engine/reference/commandline/swarm_join-token/)

+   `docker swarm join`命令的 wiki 文档：[`docs.docker.com/engine/reference/commandline/swarm_join/`](https://docs.docker.com/engine/reference/commandline/swarm_join/)

+   `docker swarm unlock`命令的 wiki 文档：[`docs.docker.com/engine/reference/commandline/swarm_unlock/`](https://docs.docker.com/engine/reference/commandline/swarm_unlock/)

+   `docker swarm unlock-key`命令的 wiki 文档：[`docs.docker.com/engine/reference/commandline/swarm_unlock-key/`](https://docs.docker.com/engine/reference/commandline/swarm_unlock-key/)

+   `docker swarm update`命令的 wiki 文档：[`docs.docker.com/engine/reference/commandline/swarm_update/`](https://docs.docker.com/engine/reference/commandline/swarm_update/)

+   `docker swarm leave`命令的 wiki 文档：[`docs.docker.com/engine/reference/commandline/swarm_leave/`](https://docs.docker.com/engine/reference/commandline/swarm_leave/)

+   了解更多关于 Docker Secrets 的信息：[`docs.docker.com/engine/swarm/secrets/`](https://docs.docker.com/engine/swarm/secrets/)

# 管理者和工作者

我们在前面的章节中已经讨论了集群管理节点，但让我们更仔细地看看管理节点的工作。管理节点确切地做了你所期望的事情。它们管理和维护集群的状态。它们调度集群服务，我们将在本章的*集群服务*部分中讨论，但现在，把集群服务想象成运行的容器。管理节点还提供集群的 API 端点，允许通过 REST 进行编程访问。管理节点还将流量引导到正在运行的服务，以便任何容器都可以通过任何管理节点访问，而无需知道实际运行容器的节点。作为维护集群状态的一部分，管理节点将处理系统中节点的丢失，在管理节点丢失时选举新的领导节点，并在容器或节点宕机时保持所需数量的服务容器运行。

集群中管理节点的最佳实践是三个、五个或七个。你会注意到所有这些选项都代表管理节点的奇数数量。这是为了在领导节点丢失时，raft 一致性算法可以更容易地为集群选择新的领导者。你可以运行一个只有一个管理节点的集群，这实际上比有两个管理节点更好。但是，对于一个更高可用的集群，建议至少有三个管理节点。对于更大的集群，有五个或七个管理节点是不错的选择，但不建议超过七个。一旦在同一集群中有超过七个管理节点，你实际上会遇到性能下降的问题。

对于管理节点来说，另一个重要考虑因素是它们之间的网络性能。管理节点需要低延迟的网络连接以实现最佳性能。例如，如果你在 AWS 上运行你的集群，你可能不希望管理节点分布在不同的地区。如果这样做，你可能会遇到集群的问题。如果你将管理节点放在同一地区的不同可用区内，你不应该遇到任何与网络性能相关的问题。

工作节点除了运行容器之外什么也不做。当领导节点宕机时，它们没有发言权。它们不处理 API 调用。它们不指挥流量。它们除了运行容器之外什么也不做。事实上，你不能只有一个工作节点的 swarm。另一方面，你可以只有一个管理节点的 swarm，在这种情况下，管理节点也将充当工作节点，并在其管理职责之外运行容器。

默认情况下，所有管理节点实际上也是工作节点。这意味着它们可以并且将运行容器。如果您希望您的管理节点不运行工作负载，您需要更改节点的可用性设置。将其更改为排水将小心地停止标记为排水的管理节点上的任何运行容器，并在其他（非排水）节点上启动这些容器。在排水模式下，不会在节点上启动新的容器工作负载，例如如下所示：

```
# Set node03's availability to drain
docker node update --availability drain ubuntu-node03
```

也许有时候您想要或需要改变 swarm 中 docker 节点的角色。您可以将工作节点提升为管理节点，或者将管理节点降级为工作节点。以下是这些活动的一些示例：

```
# Promote worker nodes 04 and 05 to manager status
docker node promote ubuntu-node04 ubuntu-node05
# Demote manager nodes 01 and 02 to worker status
docker node demote ubuntu-node01 ubuntu-node02
```

# 参考

请查看有关节点如何工作的官方文档[https://docs.docker.com/engine/swarm/how-swarm-mode-works/nodes/]。

# Swarm 服务

好了。现在你已经了解了如何设置 Docker swarm 集群，以及它的节点如何从单引擎模式转换为 swarm 模式。你也知道这样做的意义是为了让你摆脱直接管理单个运行的容器。因此，你可能开始想知道，如果我现在不直接管理我的容器，我该如何管理它们？你来对地方了！这就是 swarm 服务发挥作用的地方。swarm 服务允许您根据容器应用程序的并发运行副本数量来定义所需的状态。让我们快速看一下在 swarm 服务的管理组中有哪些可用的命令，然后我们将讨论这些命令：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-qk-st-gd/img/430b9977-6481-4879-916d-7a80e747488a.png)

您可能想要做的第一件事情是创建一个新的服务，因此我们将从`service create`命令开始讨论我们的 swarm 服务。以下是`service create`命令的语法和基本示例：

```
# Syntax for the service create command
# Usage: docker service create [OPTIONS] IMAGE [COMMAND] [ARG...]
# Create a service
docker service create --replicas 1 --name submarine alpine ping google.com
```

好的。让我们分解一下这里显示的`service create`命令示例。首先，你有管理组服务，然后是`create`命令。然后，我们开始进入参数；第一个是`--replicas`。这定义了应同时运行的容器副本数量。接下来是`--name`参数。这个很明显，是我们要创建的服务的名称，在这种情况下是`submarine`。我们将能够在其他服务命令中使用所述名称。在名称参数之后，我们有完全合格的 Docker 镜像名称。在这种情况下，它只是`alpine`。它可以是诸如`alpine:3.8`或`alpine:latest`之类的东西，或者更合格的东西，比如`tenstartups/alpine:latest`。在用于服务的图像名称之后是运行容器时要使用的命令和传递给该命令的参数——分别是`ping`和`google.com`。因此，前面的`service create`命令示例将从`alpine`镜像启动一个单独的容器，该容器将使用`ping`命令和 google.com 参数运行，并将服务命名为`submarine`。看起来是这样的：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-qk-st-gd/img/3701eca6-03c6-412d-8dfd-49676e2fb619.png)

你现在知道了创建 docker 服务的基础知识。但在你过于兴奋之前，`service create`命令还有很多内容要涵盖。事实上，这个命令有很多选项，列出它们将占据本书两页的篇幅。所以，我希望你现在使用`--help`功能并输入以下命令：

```
# Get help with the service create command
docker service create --help
```

我知道，对吧？有很多可选参数可以使用。别担心。我不会丢下你不管的。我会给你一些指导，帮助你建立创建服务的坚实基础，然后你可以扩展并尝试一些你在`--help`中看到的其他参数。

只是让你知道，到目前为止我们使用的两个参数，`--replicas`和`--name`，都是可选的。如果你不提供要使用的副本数量，服务将以默认值 1 创建。此外，如果你不为服务提供名称，将会编造一个奇特的名称并赋予服务。这与我们在第二章中使用`docker container run`命令时看到的默认命名类型相同，*学习 Docker 命令*。通常最好为每个发出的`service create`命令提供这两个选项。

另外，要知道，一般来说，在前面的示例中提供的镜像的命令和命令参数也是可选的。在这种特定情况下，它们是必需的，因为单独从 alpine 镜像运行的容器，如果没有提供其他命令或参数，将会立即退出。在示例中，这将显示为无法收敛服务，Docker 将永远尝试重新启动服务。换句话说，如果使用的镜像内置了命令和参数（比如在 Dockerfile 的`CMD`或`ENTRYPOINT`指令中），则可以省略命令及其参数。

现在让我们继续讨论一些创建参数。你应该还记得第二章中提到的`--publish`参数，你可以在`docker container run`命令上使用，它定义了在 docker 主机上暴露的端口以及主机端口映射到的容器中的端口。它看起来像这样：

```
# Create a nginx web-server that redirects host traffic from port 8080 to port 80 in the container docker container run --detach --name web-server1 --publish 8080:80 nginx
```

好吧，你需要为一个集群服务使用相同的功能，在他们的智慧中，Docker 使`container run`命令和`service create`命令使用相同的参数：`--publish`。你可以使用我们之前看到的相同的缩写格式，`--publish 8080:80`，或者你可以使用更详细的格式：`--publish published=8080`，`target=80`。这仍然意味着将主机流量从端口`8080`重定向到容器中的端口 80。让我们尝试另一个例子，这次使用`--publish`参数。我们将再次运行`nginx`镜像：

```
# Create a nginx web-server service using the publish parameter
docker service create --name web-service --replicas 3 --publish published=8080,target=80 nginx
```

这个例子将创建一个新的服务，运行三个容器副本，使用`nginx`镜像，在容器上暴露端口`80`，在主机上暴露端口`8080`。看一下：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-qk-st-gd/img/d43881b1-4d53-443c-916e-bb51f16581d8.png)

现在，您已经接近成功了。让我们快速介绍另外三个参数，然后您就可以准备好应对世界（至少是集群服务的世界）。首先是 `--restart-window`。此参数用于告诉 Docker 守护程序在测试容器是否健康之前等待多长时间启动其应用程序。默认值为五秒。如果您在容器中创建了一个需要超过五秒才能启动并报告为健康的应用程序，您将需要在 `service create` 中包含 `--restart-window` 参数。接下来是 `--restart-max-attempts`。此参数告诉 Docker 守护程序在放弃之前尝试启动未报告为健康的容器副本的次数。默认值是*永不放弃*。*永不投降*！最后，让我们谈谈 `--mode` 参数。集群服务的默认模式是*replicated*。这意味着 Docker 守护程序将继续为您的服务创建容器，直到同时运行的容器数量等于您在 `--replicas` 参数中提供的值（如果您没有提供该参数，则为 1）。例如，使用 `--replicas 3` 参数，您将在集群中获得三个运行中的容器。还有另一种模式，称为**global**。如果您在创建服务时提供 `--mode global` 参数，Docker 守护程序将在集群中的每个节点上精确地创建一个容器。如果您有一个六节点的集群，您将得到六个运行中的容器，每个节点一个。对于一个 12 节点的集群，您将得到 12 个容器，依此类推。当您有为每个主机提供功能的服务时，例如监控应用程序或日志转发器，这是一个非常方便的选项。

让我们回顾一些其他您需要了解和使用的服务命令。一旦您创建了一些服务，您可能想要列出这些服务。这可以通过 `service list` 命令来实现。如下所示：

```
# List services in the swarm
# Usage: docker service ls [OPTIONS]
docker service list
```

一旦您查看了运行中服务的列表，您可能想要了解一个或多个服务的更多详细信息。为了实现这一点，您将使用 `service ps` 命令。看一下：

```
# List the tasks associated with a service
# Usage: docker service ps [OPTIONS] SERVICE [SERVICE...]
docker service ps
```

一旦一个服务已经没有用处，您可能想要终止它。执行此操作的命令是 `service remove` 命令。如下所示：

```
# Remove one or more services from the swarm
# Usage: docker service rm SERVICE [SERVICE...]
docker service remove sleepy_snyder
```

如果您想要删除在集群中运行的所有服务，您可以组合其中一些命令并执行类似以下的命令：

```
# Remove ALL the services from the swarm
docker service remove $(docker service list -q)
```

最后，如果您意识到当前配置的副本数量未设置为所需数量，您可以使用`service scale`命令进行调整。以下是您可以这样做的方法：

```
# Adjust the configured number of replicas for a service
# Usage: docker service scale SERVICE=REPLICAS [SERVICE=REPLICAS...]
docker service scale web-service=4
```

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-qk-st-gd/img/354cacd5-2139-4ad7-acb7-abb6cc0f00fa.png)

这应该足够让您忙一段时间了。在我们继续第六章之前，*Docker 网络*，让我们在本章中再涵盖一个主题：访问在集群中运行的容器应用程序。

# 参考

阅读有关 Docker 服务创建参考的更多信息[`docs.docker.com/engine/reference/commandline/service_create/`](https://docs.docker.com/engine/reference/commandline/service_create/)。

# 在集群中访问容器应用程序

所以，现在您有一个运行着奇数个管理节点和若干个工作节点的集群。您已经部署了一些集群服务来运行您喜爱的容器化应用程序。接下来呢？嗯，您可能想要访问在您的集群中运行的一个或多个应用程序。也许您已经部署了一个 web 服务器应用程序。能够访问该 web 服务器共享的网页将是很好的，对吧？让我们快速看一下，看看这是多么容易。

集群管理器为我们处理的功能之一是将流量引导到我们的服务。在之前的示例中，我们设置了一个在集群中运行三个副本的 web 服务。我目前使用的集群恰好有三个管理节点和三个工作节点。所有六个节点都有资格运行工作负载，因此当服务启动时，六个节点中的三个将最终运行一个容器。如果我们使用`service ps`命令查看服务的任务的详细信息，您可以看到六个节点中哪些正在运行 web 服务容器：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-qk-st-gd/img/f42332f8-0d66-4aab-a195-d99bd73fc86a.png)

在这个例子中，您可以看到 web 服务容器正在节点 01、02 和 04 上运行。美妙的是，您不需要知道哪些节点正在运行您的服务容器。您可以通过集群中的任何节点访问该服务。当然，您期望能够访问节点 01、02 或 04 上的容器，但是看看这个：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-qk-st-gd/img/63e01e66-7ca6-4121-9a4c-b653f2b773cb.png)

拥有在集群中的任何节点上访问服务的能力会带来一个不幸的副作用。你能想到可能是什么吗？我不会让你悬念太久。副作用是你只能将（主机）端口分配给集群中的一个服务。在我们的例子中，我们正在为我们的 web 服务使用端口`8080`。这意味着我们不能将端口`8080`用于我们想要在这个集群中运行的任何其他服务的主机端口：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-qk-st-gd/img/71ca5156-7db9-4eb0-ad77-00a558c82bdc.png)

# 参考资料

查看以下链接以获取更多信息：

+   维基文档中有关在集群上部署服务的非常详细的概述：[`docs.docker.com/v17.09/engine/swarm/services/`](https://docs.docker.com/v17.09/engine/swarm/services/)

+   服务的工作原理：[`docs.docker.com/engine/swarm/how-swarm-mode-works/services/`](https://docs.docker.com/engine/swarm/how-swarm-mode-works/services/)

+   Docker 的入门培训：[`docs.docker.com/v17.09/engine/swarm/swarm-tutorial/`](https://docs.docker.com/v17.09/engine/swarm/swarm-tutorial/)

# 总结

在本章中，我们最终开始整合一些要点，并实现一些有趣的事情。我们了解了通过启用集群模式和创建集群集群可以获得多少功能。而且，我们发现了使用一个`swarm init`命令设置一切有多么容易。然后，我们学会了如何扩展和管理我们的集群集群，最后，我们学会了如何在我们的新集群集群中将我们的容器作为服务运行。很有趣，对吧？！

现在，让我们把事情提升到下一个级别。在第六章中，*Docker 网络*，我们将学习关于 Docker 网络的知识。如果你准备好了解更多好东西，就翻页吧。


# 第六章：Docker 网络

在本章中，我们将学习关于 Docker 网络的知识。我们将深入研究 Docker 网络，学习容器如何被隔离，它们如何相互通信，以及它们如何与外部世界通信。我们将探索 Docker 在开箱即用安装中提供的本地网络驱动程序。然后，我们将通过部署 Weave 驱动程序的示例来研究远程网络驱动程序的使用。之后，我们将学习如何创建 Docker 网络。我们将通过查看我们的 Docker 网络所获得的免费服务来结束讨论。

“大约 97%的集装箱都是在中国制造的。在装运时，生产集装箱比在世界各地重新定位集装箱要容易得多。” - [`www.billiebox.co.uk/`](https://www.billiebox.co.uk/)

在本章中，我们将涵盖以下主题：

+   什么是 Docker 网络？

+   内置（也称为**本地**）Docker 网络的全部内容

+   第三方（也称为**远程**）Docker 网络如何？

+   如何创建 Docker 网络

+   免费的服务发现和负载平衡功能

+   选择适合您需求的正确 Docker 网络驱动程序

# 技术要求

您将从 Docker 的公共存储库中拉取 Docker 镜像，并从 Weave 安装网络驱动程序，因此在执行本章示例时需要基本的互联网访问。此外，我们将使用`jq 软件`包，因此如果您尚未安装，请参阅如何执行此操作的说明-可以在第二章的*容器检查命令*部分找到，*学习 Docker 命令*。

本章的代码文件可以在 GitHub 上找到：

[`github.com/PacktPublishing/Docker-Quick-Start-Guide/tree/master/Chapter06`](https://github.com/PacktPublishing/Docker-Quick-Start-Guide/tree/master/Chapter06)

查看以下视频以查看代码的实际操作：[`bit.ly/2FJ2iBK`](http://bit.ly/2FJ2iBK)

# 什么是 Docker 网络？

正如你已经知道的，网络是一个允许计算机和其他硬件设备进行通信的连接系统。Docker 网络也是一样的。它是一个连接系统，允许 Docker 容器在同一台 Docker 主机上相互通信，或者与容器、计算机和容器主机之外的硬件进行通信，包括在其他 Docker 主机上运行的容器。

如果你熟悉宠物与牛群的云计算类比，你就明白了能够在规模上管理资源的必要性。Docker 网络允许你做到这一点。它们抽象了大部分网络的复杂性，为你的容器化应用程序提供了易于理解、易于文档化和易于使用的网络。Docker 网络基于一个由 Docker 创建的标准，称为**容器网络模型**（**CNM**）。还有一个由 CoreOS 创建的竞争性网络标准，称为**容器网络接口**（**CNI**）。CNI 标准已被一些项目采用，尤其是 Kubernetes，可以提出支持其使用的论点。然而，在本章中，我们将把注意力集中在 Docker 的 CNM 标准上。

CNM 已经被 libnetwork 项目实现，你可以通过本节参考中的链接了解更多关于该项目的信息。用 Go 编写的 CNM 实现由三个构造组成：沙盒、端点和网络。沙盒是一个网络命名空间。每个容器都有自己的沙盒。它保存了容器的网络堆栈配置。这包括其路由表、接口和 IP 和 MAC 地址的 DNS 设置。沙盒还包含容器的网络端点。接下来，端点是连接沙盒到网络的东西。端点本质上是网络接口，比如**eth0**。一个容器的沙盒可能有多个端点，但每个端点只能连接到一个网络。最后，网络是一组连接的端点，允许连接之间进行通信。每个网络都有一个名称、地址空间、ID 和网络类型。

Libnetwork 是一个可插拔的架构，允许网络驱动程序实现我们刚刚描述的组件的具体内容。每种网络类型都有自己的网络驱动程序。Docker 提供了内置驱动程序。这些默认或本地驱动程序包括桥接驱动程序和覆盖驱动程序。除了内置驱动程序，libnetwork 还支持第三方创建的驱动程序。这些驱动程序被称为远程驱动程序。一些远程驱动程序的例子包括 Calico、Contiv 和 Weave。

现在你已经了解了 Docker 网络是什么，阅读了这些细节之后，你可能会想，他说的“简单”在哪里？坚持住。现在我们将开始讨论你如何轻松地创建和使用 Docker 网络。与 Docker 卷一样，网络命令代表它们自己的管理类别。正如你所期望的，网络的顶级管理命令如下：

```
# Docker network managment command
docker network 
```

网络管理组中可用的子命令包括以下内容：

```
# Docker network management subcommands
docker network connect # Connect a container to a network
docker network create            # Create a network
docker network disconnect        # Disconnect a container from a network
docker network inspect # Display network details
docker network ls # List networks
docker network rm # Remove one or more networks
docker network prune # Remove all unused networks
```

现在让我们来看看内置或本地网络驱动程序。

# 参考

查看以下链接以获取更多信息：

+   宠物与牛的对话幻灯片：[`www.slideshare.net/randybias/architectures-for-open-and-scalable-clouds`](https://www.slideshare.net/randybias/architectures-for-open-and-scalable-clouds)

+   Libnetwork 项目：[`github.com/docker/libnetwork`](https://github.com/docker/libnetwork)

+   Libnetwork 设计：[`github.com/docker/libnetwork/blob/master/docs/design.md`](https://github.com/docker/libnetwork/blob/master/docs/design.md)

+   Calico 网络驱动程序：[`www.projectcalico.org/`](https://www.projectcalico.org/)

+   Contiv 网络驱动程序：[`contiv.github.io/`](http://contiv.github.io/)

+   Weave 网络驱动程序：[`www.weave.works/docs/net/latest/overview/`](https://www.weave.works/docs/net/latest/overview/)

# 内置（本地）Docker 网络

Docker 的开箱即用安装包括一些内置网络驱动程序。这些也被称为本地驱动程序。最常用的两个驱动程序是桥接网络驱动程序和覆盖网络驱动程序。其他内置驱动程序包括 none、host 和 MACVLAN。此外，没有创建网络的情况下，你的新安装将会有一些预先创建并准备好使用的网络。使用`network ls`命令，我们可以轻松地查看新安装中可用的预先创建的网络列表：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-qk-st-gd/img/75a654de-335d-4082-bf45-f0a8b6a60b6f.png)

在这个列表中，您会注意到每个网络都有其独特的 ID、名称、用于创建它（并控制它）的驱动程序以及网络范围。不要将本地范围与驱动程序的类别混淆，驱动程序的类别也是本地。本地类别用于区分驱动程序的来源，而不是具有远程类别的第三方驱动程序。本地范围值表示网络的通信限制仅限于本地 Docker 主机内。为了澄清，如果两个 Docker 主机 H1 和 H2 都包含具有本地范围的网络，即使它们使用相同的驱动程序并且网络具有相同的名称，H1 上的容器也永远无法直接与 H2 上的容器通信。另一个范围值是 swarm，我们稍后会更多地谈论它。

在所有 Docker 部署中找到的预创建网络是特殊的，因为它们无法被移除。不需要将容器附加到其中任何一个，但是尝试使用 `docker network rm` 命令移除它们将始终导致错误。

有三个内置的网络驱动程序，其范围为本地：桥接、主机和无。主机网络驱动程序利用 Docker 主机的网络堆栈，基本上绕过了 Docker 的网络。主机网络上的所有容器都能够通过主机的接口相互通信。使用主机网络驱动程序的一个重要限制是每个端口只能被单个容器使用。也就是说，例如，您不能运行两个绑定到端口 `80` 的 nginx 容器。正如您可能已经猜到的那样，因为主机驱动程序利用了其所在主机的网络，每个 Docker 主机只能有一个使用主机驱动程序的网络：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-qk-st-gd/img/8878cc4b-db35-4ae2-9bd1-2bef6653af31.png)

接下来是空或无网络。使用空网络驱动程序创建一个网络，当容器连接到它时，会提供一个完整的网络堆栈，但不会在容器内配置任何接口。这使得容器完全隔离。这个驱动程序主要是为了向后兼容而提供的，就像主机驱动程序一样，Docker 主机上只能创建一个空类型的网络：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-qk-st-gd/img/ae095a5c-2365-445b-84b0-f4930d6f947e.png)

第三个具有本地范围的网络驱动程序是桥接驱动程序。桥接网络是最常见的类型。连接到同一桥接网络的任何容器都能够彼此通信。Docker 主机可以使用桥接驱动程序创建多个网络。但是，连接到一个桥接网络的容器无法与不同桥接网络上的容器通信，即使这些网络位于同一个 Docker 主机上。请注意，内置桥接网络和任何用户创建的桥接网络之间存在轻微的功能差异。最佳实践是创建自己的桥接网络并利用它们，而不是使用内置的桥接网络。以下是使用桥接网络运行容器的示例：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-qk-st-gd/img/e929dbdf-7012-41dc-8577-789de4f1c1ae.png)

除了创建具有本地范围的网络的驱动程序之外，还有内置网络驱动程序创建具有集群范围的网络。这些网络将跨越集群中的所有主机，并允许连接到它们的容器进行通信，尽管它们在不同的 Docker 主机上运行。您可能已经猜到，使用具有集群范围的网络需要 Docker 集群模式。实际上，当您将 Docker 主机初始化为集群模式时，将为您创建一个具有集群范围的特殊新网络。这个集群范围网络被命名为*ingress*，并使用内置的覆盖驱动程序创建。这个网络对于集群模式的负载平衡功能至关重要，该功能在第五章的*访问集群中的容器应用*部分中使用了*Docker Swarm*。在`swarm init`中还创建了一个名为 docker_gwbridge 的新桥接网络。这个网络被集群用于向外通信，有点像默认网关。以下是在新的 Docker 集群中找到的默认内置网络： 

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-qk-st-gd/img/73d4326f-1d8f-409a-906d-603de525d80c.png)

使用覆盖驱动程序允许您创建跨 Docker 主机的网络。这些是第 2 层网络。在创建覆盖网络时，幕后会铺设大量网络管道。集群中的每个主机都会获得一个带有网络堆栈的网络沙盒。在该沙盒中，会创建一个名为 br0 的桥接。然后，会创建一个 VXLAN 隧道端点并将其附加到桥接 br0 上。一旦所有集群主机都创建了隧道端点，就会创建一个连接所有端点的 VXLAN 隧道。实际上，这个隧道就是我们看到的覆盖网络。当容器连接到覆盖网络时，它们会从覆盖子网中分配一个 IP 地址，并且该网络上的容器之间的所有通信都通过覆盖网络进行。当然，在幕后，通信流量通过 VXLAN 端点传递，穿过 Docker 主机网络，并且通过连接主机与其他 Docker 主机网络的任何路由器。但是，您永远不必担心所有幕后的事情。只需创建一个覆盖网络，将您的容器连接到它，您就大功告成了。

我们将讨论的下一个本地网络驱动程序称为 MACVLAN。该驱动程序创建的网络允许每个容器都有自己的 IP 和 MAC 地址，并连接到非 Docker 网络。这意味着除了使用桥接和覆盖网络进行容器间通信外，使用 MACVLAN 网络还可以连接到 VLAN、虚拟机和其他物理服务器。换句话说，MACVLAN 驱动程序允许您将容器连接到现有网络和 VLAN。必须在每个要运行需要连接到现有网络的容器的 Docker 主机上创建 MACVLAN 网络。而且，您需要为要连接的每个 VLAN 创建一个不同的 MACVLAN 网络。虽然使用 MACVLAN 网络听起来是一个好方法，但使用它有两个重要的挑战。首先，您必须非常小心地分配给 MACVLAN 网络的子网范围。容器将从您的范围中分配 IP，而不考虑其他地方使用的 IP。如果您有一个分配 IP 的 DHCP 系统与您给 MACVLAN 驱动程序的范围重叠，很容易导致重复的 IP 情况。第二个挑战是 MACVLAN 网络需要将您的网络卡配置为混杂模式。这在企业网络中通常是不被赞成的，但在云提供商网络中几乎是被禁止的，例如 AWS 和 Azure，因此 MACVLAN 驱动程序的使用情况非常有限。

本节涵盖了大量关于本地或内置网络驱动程序的信息。不要绝望！它们比这些丰富的信息所表明的要容易得多。我们将在*创建 Docker 网络*部分很快讨论创建和使用信息，但接下来，让我们快速讨论一下远程（也称为第三方）网络驱动程序。

# 参考资料

查看以下链接以获取更多信息：

+   优秀的、深入的 Docker 网络文章：[`success.docker.com/article/networking`](https://success.docker.com/article/networking)

+   使用覆盖网络进行网络连接：[`docs.docker.com/network/network-tutorial-overlay/`](https://docs.docker.com/network/network-tutorial-overlay/)

+   使用 MACVLAN 网络：[`docs.docker.com/v17.12/network/macvlan/`](https://docs.docker.com/v17.12/network/macvlan/)

# 第三方（远程）网络驱动程序

如前所述，在*什么是 Docker 网络*？部分中，除了 Docker 提供的内置或本地网络驱动程序外，CNM 还支持社区和供应商创建的网络驱动程序。其中一些第三方驱动程序的例子包括 Contiv、Weave、Kuryr 和 Calico。使用这些第三方驱动程序的好处之一是它们完全支持在云托管环境中部署，例如 AWS。为了使用这些驱动程序，它们需要在每个 Docker 主机的单独安装步骤中安装。每个第三方网络驱动程序都带来了自己的一套功能。以下是 Docker 在参考架构文档中分享的这些驱动程序的摘要描述：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-qk-st-gd/img/4b8d5ba1-8d15-41fe-9a21-fe4577e95705.png)

尽管这些第三方驱动程序各自具有独特的安装、设置和执行方法，但一般步骤是相似的。首先，您下载驱动程序，然后处理任何配置设置，最后运行驱动程序。这些远程驱动程序通常不需要群集模式，并且可以在有或没有群集模式的情况下使用。例如，让我们深入了解如何使用织物驱动程序。要安装织物网络驱动程序，请在每个 Docker 主机上发出以下命令：

```
# Install the weave network driver plug-in
sudo curl -L git.io/weave -o /usr/local/bin/weave
sudo chmod a+x /usr/local/bin/weave
# Disable checking for new versions
export CHECKPOINT_DISABLE=1
# Start up the weave network
weave launch [for 2nd, 3rd, etc. optional hostname or IP of 1st Docker host running weave]
# Set up the environment to use weave
eval $(weave env)
```

上述步骤需要在将用于在织物网络上相互通信的容器的每个 Docker 主机上完成。启动命令可以提供第一个 Docker 主机的主机名或 IP 地址，该主机已设置并已运行织物网络，以便与其对等，以便它们的容器可以通信。例如，如果您已经在`node01`上设置了织物网络，当您在`node02`上启动织物时，您将使用以下命令：

```
# Start up weave on the 2nd node
weave launch node01
```

或者，您可以使用连接命令连接新的（Docker 主机）对等体，从已配置的第一个主机执行。要添加`node02`（在安装和运行织物后），请使用以下命令：

```
# Peer host node02 with the weave network by connecting from node01
weave connect node02
```

您可以在主机上不启用群集模式的情况下使用织物网络驱动程序。一旦织物被安装和启动，并且对等体（其他 Docker 主机）已连接，您的容器将自动利用织物网络，并能够相互通信，无论它们是在同一台 Docker 主机上还是在不同的主机上。

织物网络显示在您的网络列表中，就像您的其他任何网络一样：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-qk-st-gd/img/77ef436f-4d57-4313-9ec0-9a109434c4f8.png)

让我们测试一下我们闪亮的新网络。首先确保你已经按照之前描述的步骤在所有你想要连接的主机上安装了 weave 驱动。确保你要么使用`node01`作为参数启动命令，要么从`node01`开始为你配置的每个额外节点使用 connect 命令。在这个例子中，我的实验服务器名为 ubuntu-node01 和 ubuntu-`node02`。让我们从`node02`开始：

请注意，在`ubuntu-node01`上：

```
# Install and setup the weave driver
sudo curl -L git.io/weave -o /usr/local/bin/weave
sudo chmod a+x /usr/local/bin/weave
export CHECKPOINT_DISABLE=1
weave launch
eval $(weave env)
```

并且，请注意，在`ubuntu-node02`上：

```
# Install and setup the weave driver
sudo curl -L git.io/weave -o /usr/local/bin/weave
sudo chmod a+x /usr/local/bin/weave
export CHECKPOINT_DISABLE=1
weave launch
eval $(weave env)
```

现在，回到`ubuntu-node01`，请注意以下内容：

```
# Bring node02 in as a peer on node01's weave network
weave connect ubuntu-node02
```

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-qk-st-gd/img/c4bd83df-3b2a-4931-9dbd-bcd67e7bb982.png)

现在，让我们在每个节点上启动一个容器。确保给它们命名以便易于识别，从`ubuntu-node01`开始：

```
# Run a container detached on node01
docker container run -d --name app01 alpine tail -f /dev/null
```

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-qk-st-gd/img/3a1ca418-01e8-4774-96ac-cf34e7d948f3.png)

现在，在`ubuntu-node02`上启动一个容器：

```
# Run a container detached on node02
docker container run -d --name app02 alpine tail -f /dev/null
```

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-qk-st-gd/img/6e796094-aece-4402-96d3-fcb4854893d2.png)

很好。现在，我们在两个节点上都有容器在运行。让我们看看它们是否可以通信。因为我们在`node02`上，我们首先检查那里：

```
# From inside the app02 container running on node02,
# let's ping the app01 container running on node01
docker container exec -it app02 ping -c 4 app01
```

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-qk-st-gd/img/69fb11da-ad53-4ec5-8b6a-f4ba031e70e4.png)

是的！成功了。让我们试试反过来：

```
# Similarly, from inside the app01 container running on node01,
# let's ping the app02 container running on node02
docker container exec -it app01 ping -c 4 app02
```

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-qk-st-gd/img/5ed6a092-d5db-46d9-bc71-2157d4bb58e1.png)

太棒了！我们有双向通信。你注意到了什么其他的吗？我们的应用容器有名称解析（我们不仅仅需要通过 IP 来 ping）。非常好，对吧？

# 参考资料

查看这些链接以获取更多信息：

+   安装和使用 weave 网络驱动：[`www.weave.works/docs/net/latest/overview/`](https://www.weave.works/docs/net/latest/overview/)

+   Weaveworks weave github 仓库：[`github.com/weaveworks/weave`](https://github.com/weaveworks/weave)

# 创建 Docker 网络

好的，现在你已经对本地和远程网络驱动有了很多了解，你已经看到了在安装 Docker 和/或初始化 swarm 模式（或安装远程驱动）时，有几个驱动是为你创建的。但是，如果你想使用其中一些驱动创建自己的网络怎么办？这其实非常简单。让我们来看看。`network create`命令的内置帮助如下：

```
# Docker network create command syntax
# Usage: docker network create [OPTIONS] NETWORK
```

检查这个，我们看到这个命令基本上有两个部分需要处理，OPTIONS 后面跟着我们想要创建的网络的 NETWORK 名称。我们有哪些选项？嗯，有相当多，但让我们挑选一些让你快速上手的。

可能最重要的选项是`--driver`选项。这是我们告诉 Docker 在创建此网络时要使用哪个可插拔网络驱动程序的方式。正如您所见，驱动程序的选择决定了网络的特性。您提供给驱动程序选项的值将类似于从`docker network ls`命令的输出中显示的 DRIVER 列中显示的值。一些可能的值是 bridge、overlay 和 macvlan。请记住，您不能创建额外的主机或空网络，因为它们限制为每个 Docker 主机一个。到目前为止，这可能是什么样子？以下是使用大部分默认选项创建新覆盖网络的示例：

```
# Create a new overlay network, with all default options
docker network create -d overlay defaults-over
```

这很好。您可以运行新服务并将它们附加到您的新网络。但是我们可能还想控制网络中的其他内容吗？嗯，IP 空间怎么样？是的，Docker 提供了控制网络 IP 设置的选项。这是使用`--subnet`、`--gateway`和`--ip-range`可选参数来完成的。所以，让我们看看如何使用这些选项创建一个新网络。如果您还没有安装 jq，请参阅第二章，*学习 Docker 命令*，了解如何安装它：

```
# Create a new overlay network with specific IP settings
docker network create -d overlay \
--subnet=172.30.0.0/24 \
--ip-range=172.30.0.0/28 \
--gateway=172.30.0.254 \
specifics-over
# Initial validation
docker network inspect specifics-over --format '{{json .IPAM.Config}}' | jq
```

在我的实验室中执行上述代码看起来是这样的：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-qk-st-gd/img/bbd502b4-374d-406d-915c-b2af371914b3.png)

通过查看这个例子，我们看到我们使用特定的 IP 参数为子网、IP 范围和网关创建了一个新的覆盖网络。然后，我们验证了网络是否使用了请求的选项进行创建。接下来，我们使用我们的新网络创建了一个服务。然后，我们找到了属于该服务的容器的容器 ID，并用它来检查容器的网络设置。我们可以看到，容器是使用我们配置网络的 IP 范围中的 IP 地址（在这种情况下是`172.30.0.7`）运行的。看起来我们成功了！

如前所述，在创建 Docker 网络时还有许多其他选项可用，我将把它作为一个练习留给您，让您使用`docker network create --help`命令来发现它们，并尝试一些选项以查看它们的功能。

# 参考资料

您可以在[`docs.docker.com/engine/reference/commandline/network_create/`](https://docs.docker.com/engine/reference/commandline/network_create/)找到`network create`命令的文档。

# 免费网络功能

有两个网络功能或服务是您在 Docker 群集网络中免费获得的。第一个是服务发现，第二个是负载均衡。当您创建 Docker 服务时，您会自动获得这些功能。我们在本章和第五章《Docker Swarm》中体验了这些功能，但并没有真正以名称的方式提到它们。所以，在这里我们来具体提一下。

首先是服务发现。当您创建一个服务时，它会得到一个唯一的名称。该名称会在群集 DNS 中注册。而且，每个服务都使用群集 DNS 进行名称解析。这里有一个例子。我们将利用之前在创建 Docker 网络部分创建的`specifics-over`叠加网络。我们将创建两个服务（`tester1`和`tester2`）并连接到该网络，然后我们将连接到`tester1`服务中的一个容器，并通过名称 ping`tester2`服务。看一下：

```
# Create service tester1
docker service create --detach --replicas 3 --name tester1 \
 --network specifics-over alpine tail -f /dev/null
# Create service tester2
docker service create --detach --replicas 3 --name tester2 \
 --network specifics-over alpine tail -f /dev/null
# From a container in the tester1 service ping the tester2 service by name
docker container exec -it tester1.3.5hj309poppj8jo272ks9n4k6a ping -c 3 tester2
```

以下是执行前述命令时的样子：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-qk-st-gd/img/d89ec999-415d-4163-832d-414748894ff4.png)

请注意，我输入了服务名称的第一部分（`tester1`）并使用命令行补全，通过按下*Tab*键来填写 exec 命令的容器名称。但是，正如您所看到的，我能够在`tester1`容器内通过名称引用`tester2`服务。

免费！

我们得到的第二个免费功能是负载均衡。这个强大的功能非常容易理解。它允许将发送到服务的流量发送到群集中的任何主机，而不管该主机是否正在运行服务的副本。

想象一下这样的情景：您有一个六节点的群集集群，以及一个只部署了一个副本的服务。您可以通过群集中的任何主机发送流量到该服务，并知道无论容器实际在哪个主机上运行，流量都会到达服务的一个容器。事实上，您可以使用负载均衡器将流量发送到群集中的所有主机，比如采用轮询模式，每次将流量发送到负载均衡器时，该流量都会无误地传递到应用程序容器。

相当方便，对吧？再次强调，这是免费的！

# 参考资料

想要尝试服务发现吗？那就查看[`training.play-with-docker.com/swarm-service-discovery/`](https://training.play-with-docker.com/swarm-service-discovery/)。

你可以在[`docs.docker.com/engine/swarm/key-concepts/#load-balancing`](https://docs.docker.com/engine/swarm/key-concepts/#load-balancing)阅读有关 swarm 服务负载平衡的信息。

# 我应该使用哪个 Docker 网络驱动程序？

对于这个问题的简短答案就是适合工作的正确驱动程序。这意味着没有单一的网络驱动程序适合每种情况。如果你在笔记本电脑上工作，swarm 处于非活动状态，并且只需要容器之间能够通信，那么简单的桥接模式驱动程序是理想的。

如果你有多个节点，只需要容器对容器的流量，那么覆盖驱动程序是正确的选择。如果你需要容器对 VM 或容器对物理服务器的通信（并且可以容忍混杂模式），那么 MACVLAN 驱动程序是最佳选择。或者，如果你有更复杂的需求，许多远程驱动程序可能正是你需要的。

我发现对于大多数多主机场景，覆盖驱动程序可以胜任，所以我建议你启用 swarm 模式，并在升级到其他多主机选项之前尝试覆盖驱动程序。

# 总结

你现在对 Docker 网络有什么感觉？Docker 已经将复杂的技术网络变得易于理解和使用。大部分疯狂、困难的设置都可以通过一个`swarm init`命令来处理。让我们回顾一下：你了解了 Docker 创建的网络设计，称为容器网络模型或 CNM。然后，你了解了 libnetwork 项目如何将该模型转化为可插拔架构。之后，你发现 Docker 创建了一组强大的驱动程序，可以插入 libnetwork 架构，以满足大部分容器通信需求的各种网络选项。由于架构是可插拔的，其他人已经创建了更多的网络驱动程序，解决了 Docker 驱动程序无法处理的任何边缘情况。Docker 网络真的已经成熟了。

我希望你已经做好准备，因为在第七章中，*Docker Stacks*，我们将深入探讨 Docker 堆栈。这是你迄今为止学到的所有信息真正汇聚成一种辉煌的交响乐。深呼吸，翻开下一页吧！


# 第七章：Docker 堆栈

在本章中，我们将汇集前六章所学，并用它来定义、部署和管理多容器应用程序。我们将通过使用 Docker 堆栈来实现这一点。我们将学习如何使用 Docker 堆栈和定义多容器应用程序所需的 YAML 文件。我们将利用我们对 Docker 服务、Docker 卷、Docker 集群和 Docker 网络的了解来创建功能齐全的基于 Docker 的多服务应用程序。

最大的货船长 400 米，可以携带 15,000 至 18,000 个集装箱！

在本章中，我们将涵盖以下主题：

+   使用 Docker 堆栈

+   部署多服务 Docker 应用程序

+   创建和使用 compose（堆栈）YAML 文件

+   扩展已部署的多服务 Docker 应用程序

# 技术要求

您将从 Docker 的公共存储库中拉取 Docker 镜像，并从 Weave 安装网络驱动程序，因此执行本章示例需要基本的互联网访问。此外，我们将使用 jq 软件包，因此如果您尚未安装，请参阅如何安装的说明；可以在第二章的*容器检查命令*部分找到。

本章的代码文件可以在 GitHub 上找到：

[`github.com/PacktPublishing/Docker-Quick-Start-Guide/tree/master/Chapter07`](https://github.com/PacktPublishing/Docker-Quick-Start-Guide/tree/master/Chapter07)

查看以下视频以查看代码的实际操作：[`bit.ly/2E2qc9U`](http://bit.ly/2E2qc9U)

# 了解 Docker 堆栈的使用

到目前为止，我们主要关注的是从单个 Docker 镜像中运行 Docker 容器，简化 Docker 模型，想象一个世界，每个应用程序只需要一个服务，因此只需要一个 Docker 镜像来运行。然而，正如你所知，这是一个相当不现实的模型。现实世界的应用程序由多个服务组成，并且这些服务是使用多个 Docker 镜像部署的。要运行所有必要的容器，并将它们保持在所需数量的副本，处理计划和非计划的停机时间，扩展需求以及所有其他服务管理需求是一个非常艰巨和复杂的任务。最近，这种情况是使用一个名为 Docker Compose 的工具来处理的。Docker Compose（正如你在第一章中学到的，*设置 Docker 开发环境*）是一个额外的工具，你可以在 Docker 环境中安装，我们已经在工作站的环境中完成了安装。虽然 Docker Compose 的许多功能与 Docker 堆栈中的功能类似，但我们将在本章中专注于 Docker 堆栈。我们这样做是因为 Docker Compose 用于管理容器，而 Docker 世界已经向服务作为通用单元的演变。Docker 堆栈管理服务，因此我认为 Docker 堆栈是 Docker Compose 的演变（它是一个名为 Fig 的项目的演变）。我们之所以没有在第一章中安装 Docker 堆栈，*设置 Docker 开发环境*，是因为堆栈已经作为标准 Docker 安装的一部分包含在内。

好的，所以 Docker 堆栈是新的改进版 Docker Compose，并且已包含在我们的安装中。我敢打赌你在想，太好了。但这意味着什么？Docker 堆栈的用例是什么？好问题！Docker 堆栈是利用我们在前几章中学到的所有功能的方式，比如 Docker 命令、Docker 镜像、Docker 服务、Docker 卷、Docker 集群和 Docker 网络，将所有这些功能包装在一个易于使用、易于理解的声明性文档文件中，这将代表我们实例化和维护一个复杂的多镜像应用程序。

大部分工作，仍然是简单的部分，将在创建用于 Docker 堆栈命令的 compose 文件中进行。当 Docker 创建、启动和管理所有多服务（多容器）应用程序所需的所有服务时，所有真正的艰苦工作都将由 Docker 完成。所有这些都由您的一条命令处理。就像镜像一样，容器和 swarm 堆栈是另一个 Docker 管理组。让我们来看看堆栈管理命令：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-qk-st-gd/img/122c40cb-3742-4665-be75-2ce2ecfaa9df.png)

那么，我们在这里有什么？对于这个管理组所代表的所有功能，它有一组非常简单的命令。主要命令是`deploy`命令。它是强大的！通过此命令（和一个 compose 文件），您将启动您的应用程序，拉取任何不在本地环境中的镜像，运行镜像，根据需要创建卷，根据需要创建网络，为每个镜像部署定义的副本数量，将它们分布在您的 swarm 中以实现高可用性和负载平衡，并且更多。这个命令有点像《指环王》中的一环。除了部署应用程序，当您需要执行诸如扩展应用程序之类的操作时，您将使用相同的命令来更新正在运行的应用程序。

管理组中的下一个命令是列出堆栈的命令。顾名思义，ls 命令允许您获取当前部署到您的 swarm 的所有堆栈的列表。当您需要关于正在 swarm 中运行的特定堆栈的更详细信息时，您将使用`ps`命令列出特定堆栈的所有任务。当到达结束生命周期部署的堆栈时，您将使用强大的 rm 命令。最后，作为管理命令的补充，我们有 services 命令，它允许我们获取堆栈的一部分的服务列表。堆栈谜题的另一个重要部分是`--orchestrator`选项。通过此选项，我们可以指示 Docker 使用 Docker swarm 或 Kubernetes 进行堆栈编排。当然，要使用 Kubernetes，必须已安装，并且要使用 swarm——如果未指定该选项，则必须启用 swarm 模式。

在本章的其余部分，我们将深入研究使用示例应用程序的 Docker stacks。Docker 提供了几个这样的示例，但我们要检查的是投票应用程序示例。我将提供应用程序的 Docker 存储库的链接，以及我空间中项目的分支的链接，以防 Docker 应用程序发生重大变化或项目消失。让我们来看一下示例投票应用程序的堆栈文件。

# 参考资料

查看以下链接以获取更多信息：

+   Docker Compose 概述：[`docs.docker.com/compose/overview/`](https://docs.docker.com/compose/overview/)

+   Docker stack 命令参考：[`docs.docker.com/engine/reference/commandline/stack/`](https://docs.docker.com/engine/reference/commandline/stack/)

+   Docker 样本：[`github.com/dockersamples`](https://github.com/dockersamples)

+   Docker 投票应用示例：[`github.com/dockersamples/example-voting-app`](https://github.com/dockersamples/example-voting-app)

+   我的投票应用的分支：[`github.com/EarlWaud/example-voting-app`](https://github.com/EarlWaud/example-voting-app)

# 如何创建和使用 Compose YAML 文件用于 Stacks

堆栈文件是一个 YAML 文件，基本上与 Docker Compose 文件相同。两者都是定义 Docker 基础应用程序的 YAML 文件。从技术上讲，堆栈文件是一个需要特定版本（或更高版本）的 Compose 规范的 Compose 文件。Docker stacks 仅支持版本 3.0 规范及以上。如果您有一个使用 Docker compose YAML 文件的现有项目，并且这些文件使用的是版本 2 或更旧的规范，那么您需要将 YAML 文件更新到版本 3 规范，以便能够在 Docker stacks 中使用它们。值得注意的是，相同的 YAML 文件可以用于 Docker stacks 或 Docker compose（前提是使用了版本 3 规范或更高版本）。但是，有一些指令将被其中一个工具忽略。例如，Docker stacks 会忽略构建指令。这是因为堆栈和 compose 之间最重要的区别之一是，所有使用的 Docker 映像必须预先创建以供堆栈使用，而 Docker 映像可以作为建立基于 compose 的应用程序的一部分而创建。另一个重要的区别是，堆栈文件能够定义 Docker 服务作为应用程序的一部分。

现在是克隆投票应用程序项目和可视化器镜像存储库的好时机。

```
# Clone the sample voting application and the visualizer repos
git clone https://github.com/EarlWaud/example-voting-app.git
git clone https://github.com/EarlWaud/docker-swarm-visualizer.git
```

严格来说，您不需要克隆这两个存储库，因为您真正需要的只是投票应用程序的堆栈组合文件。这是因为所有的镜像已经被创建并且可以从 hub.docker.com 公开获取，并且当您部署堆栈时，这些镜像将作为部署的一部分被获取。因此，这是获取堆栈 YAML 文件的命令：

```
# Use curl to get the stack YAML file
curl -o docker-stack.yml\
 https://raw.githubusercontent.com/earlwaud/example-voting-app/master/docker-stack.yml
```

当然，如果您想以任何方式自定义应用程序，将项目本地化可以让您构建自己的 Docker 镜像版本，然后使用您的自定义镜像部署应用程序的自定义版本。

一旦您在系统上拥有项目（或至少有`docker-stack.yml`文件），您就可以开始使用 Docker 堆栈命令进行操作。现在，让我们继续使用`docker-stack.yml`文件来部署我们的应用程序。您需要设置好 Docker 节点并启用 swarm 模式才能使其工作，所以如果您还没有这样做，请按照第五章中描述的设置您的 swarm，*Docker Swarm*。然后，使用以下命令来部署您的示例投票应用程序：

```
# Deploy the example voting application 
# using the downloaded stack YAML file
docker stack deploy -c docker-stack.yml voteapp
```

这是它可能看起来的样子：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-qk-st-gd/img/2aee2f71-d5df-4f98-846b-ac4b0b65e79b.png)

让我快速解释一下这个命令：我们正在使用`deploy`命令与`docker-stack.yml`组合文件，并将我们的堆栈命名为`voteapp`。这个命令将处理我们新应用程序的所有配置、部署和管理。根据`docker-stack.yml`文件中定义的内容，需要一些时间来使一切都正常运行，所以在这段时间里，让我们开始深入了解我们的堆栈组合文件。

到目前为止，您知道我们正在使用`docker-stack.yml`文件。因此，当我们解释堆栈组合文件的各个部分时，您可以在您喜欢的编辑器中打开该文件，并跟随我们的讲解。我们开始吧！

我们要看的第一件事是顶层键。在这种情况下，它们如下所示：

+   版本

+   服务

+   网络

+   卷

如前所述，版本必须至少为 3 才能与 Docker 堆栈一起使用。查看`docker-stack.yml`文件中的第 1 行（版本键始终在第 1 行），我们看到以下内容：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-qk-st-gd/img/db63823a-5514-4548-8c15-00c967515e96.png)

完美！我们有一个符合版本 3 规范的组合文件。在一分钟内跳过（折叠的）服务密钥部分，让我们看一下网络密钥，然后是卷密钥。在网络密钥部分，我们指示 Docker 创建两个网络，一个名为 frontend，一个名为 backend。实际上，在我们的情况下，网络将被命名为`voteapp_frontend`和`voteapp_backend`。这是因为我们将我们的堆栈命名为`voteapp`，Docker 将在部署堆栈的一部分时将堆栈的名称前置到各个组件的名称之前。通过在堆栈文件的网络密钥中包含我们所需网络的名称，Docker 将在部署堆栈时创建我们的网络。我们可以为每个网络提供特定的细节（正如我们在第六章中学到的，*Docker 网络*），但如果我们不提供任何细节，那么将使用某些默认值。我们的堆栈可能已经足够长时间来部署我们的网络了，所以让我们使用网络列表命令来看看我们现在有哪些网络：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-qk-st-gd/img/4f26a50f-92fc-4fb0-a453-2a1448250df9.png)

它们在这里：`voteapp_frontend`和`voteapp_backend`。您可能想知道`voteapp_default`网络是什么。当您部署一个堆栈时，您将始终获得一个默认的 Swarm 网络，如果它们在堆栈组合文件中没有为它们定义任何其他网络连接，那么所有容器都将连接到它。这非常酷，对吧？！您不必执行任何 docker 网络创建命令，您的所需网络已经在应用程序中创建并准备好使用。

卷密钥部分基本上与网络密钥部分做了相同的事情，只是它是为卷而不是网络。当您部署堆栈时，您的定义卷将自动创建。如果在堆栈文件中没有提供额外的配置，卷将以默认设置创建。在我们的示例中，我们要求 Docker 创建一个名为`db-data`的卷。正如您可能已经猜到的那样，实际创建的卷的名称实际上是`voteapp_db-data`，因为 Docker 将我们堆栈的名称前置到卷名称之前。在我们的情况下，它看起来像这样：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-qk-st-gd/img/457d5f8c-cb66-4cd6-96b8-75adb3afcfe9.png)

因此，部署我们的堆栈创建了我们期望的网络和我们期望的卷。所有这些都是通过我们堆栈组合文件中易于创建、易于阅读和理解的内容实现的。好的，现在我们对堆栈组合文件中的四个顶级键部分中的三个有了很好的理解。现在，让我们返回到服务键部分。如果我们展开这个键部分，我们将看到我们希望作为应用程序的一部分部署的每个服务的定义。在`docker-stack.yml`文件的情况下，我们定义了六个服务。这些是 redis、db、vote、result、worker 和 visualizer。在堆栈组合文件中，它们看起来像这样：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-qk-st-gd/img/3fc6f525-3d09-4045-bc56-d9da65483394.png)

让我们扩展第一个 redis，并仔细看一下为我们的应用程序定义的 redis 服务：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-qk-st-gd/img/4bf276e3-699f-4d20-a441-9182e0db84cb.png)

如果您回忆一下来自第五章的 Docker 服务的讨论，*Docker Swarm*，那么这里显示的许多键对您来说应该是很熟悉的。现在让我们来检查 redis 服务中的键。首先，我们有`image`键。图像键是服务定义所必需的。这个键告诉 docker 要拉取和运行这个服务的 Docker 镜像是`redis:alpine`。正如您现在应该理解的那样，这意味着我们正在使用来自 hub.docker.com 的官方 redis 镜像，请求标记为`alpine`的版本。接下来使用的键是`ports`。它定义了容器将从主机暴露的端口以及主机的端口。在这种情况下，要映射到容器的暴露端口（`6379`）的主机端口由 Docker 分配。您可以使用`docker container ls`命令找到分配的端口。在我的情况下，redis 服务将主机的端口`30000`映射到容器的端口`6379`。接下来使用的键是`networks`。我们已经看到部署堆栈将为我们创建网络。这个指令告诉 Docker 应该将 redis 副本容器连接到哪些网络；在这种情况下是`frontend`网络。如果我们检查 redis 副本容器，检查网络部分，我们将看到这是准确的。您可以使用这样的命令查看您的部署（请注意，容器名称在您的系统上可能略有不同）：

```
# Inspect a redis replica container looking at the networks
docker container inspect voteapp_redis.1.nwy14um7ik0t7ul0j5t3aztu5  \
 --format '{{json .NetworkSettings.Networks}}' | jq
```

在我们的示例中，您应该看到容器连接到两个网络：入口网络和我们的`voteapp_frontend`网络。

我们 redis 服务定义中的下一个键是 deploy 键。这是在 compose 文件规范的 3 版本中添加的一个键类别。它定义了基于此服务中的镜像运行容器的具体信息：在这种情况下，是 redis 镜像。这实质上是编排指令。`replicas`标签告诉 docker 在应用程序完全部署时应该运行多少副本或容器。在我们的示例中，我们声明我们只需要一个 redis 容器的实例运行。`update_config`键提供了两个子键，`parallelism`和`delay`，告诉 Docker 应该以多少容器`replicas`并行启动，并且在启动每个`parallel`容器`replicas`之间等待多长时间。当然，对于一个副本，parallelism 和 delay 的细节几乎没有用处。如果`replicas`的值更大，比如`10`，我们的 update_config 键将导致两个副本同时启动，并且在启动之间等待 10 秒。最后的 deploy 键是`restart_policy`，它定义了在部署的堆栈中新副本将被创建的条件。在这种情况下，如果一个 redis 容器失败，将启动一个新的 redis 容器来替代它。让我们来看看我们应用程序中的下一个服务，`db`服务：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-qk-st-gd/img/05c62070-b99e-44b6-9aeb-87a5a39cd8e4.png)

db 服务与 redis 服务将有几个相同的键，但值不同。首先，我们有 image 键。这次我们指定要使用带有版本 9.4 标签的官方 postgres 镜像。我们的下一个键是 volumes 键。我们指定我们正在使用名为 db-data 的卷，并且在 DB 容器中，卷应该挂载在`/var/lib/postgresql/data`。让我们来看看我们环境中的卷信息：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-qk-st-gd/img/cc874b3a-4a1f-4e7c-9205-1370c49b6cb7.png)

使用 volume inspect 命令，我们可以获取卷的挂载点，然后比较容器内文件夹的内容与主机上挂载点的内容：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-qk-st-gd/img/c15dc49d-8cbc-44b6-92c8-17fa68ade32c.png)

哇！正如预期的那样，它们匹配。在 Mac 上，情况并非如此简单。有关如何在 OS X 上处理此问题的详细信息，请参阅 Docker Volumes 第四章，有关 Docker 卷的详细信息。接下来是网络密钥，在这里我们指示 Docker 将后端网络连接到我们的 db 容器。接下来是部署密钥。在这里，我们看到一个名为`placement`的新子密钥。这是一个指令，告诉 Docker 我们只希望 db 容器在管理节点上运行，也就是说，在具有`manager`角色的节点上。

您可能已经注意到，部署密钥的一些子密钥存在于 redis 服务中，但在我们的 db 服务中不存在，最显著的是`replicas`密钥。默认情况下，如果您没有指定要维护的副本数量，Docker 将默认为一个副本。总的来说，db 服务配置的描述与 redis 服务几乎相同。您将看到所有服务的配置之间的相似性。这是因为 Docker 已经非常容易地定义了我们服务的期望状态，以及我们的应用程序。为了验证这一点，让我们来看一下堆栈组合文件中的下一个服务，即`vote`服务：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-qk-st-gd/img/c7b6874c-7c27-4aa9-895c-297b22c27b06.png)

您应该开始熟悉这些密钥及其值。在投票服务中，我们看到定义的镜像不是官方容器镜像之一，而是在名为`dockersamples`的公共存储库中。在该存储库中，我们使用了名为`examplevotingapp_vote`的图像，版本标签为`before`。我们的端口密钥告诉 Docker 和我们，我们要在 swarm 主机上打开端口`5000`，并且将该端口上的流量映射到正在运行的投票服务容器中的端口 80。事实证明，投票服务是我们应用程序的`face`，我们将通过端口`5000`访问它。由于它是一个服务，我们可以通过在 swarm 中的*任何*主机上的端口`5000`访问它，即使特定主机没有运行其中一个副本。

看着下一个关键点，我们看到我们正在将`frontend`网络连接到我们的投票服务容器。在那里没有什么新的，然而，因为我们下一个关键点是我们以前没有见过的：`depends_on`关键点。这个关键点告诉 Docker 我们的投票服务需要 redis 服务才能运行。对于我们的`deploy`命令来说，这意味着被依赖的服务需要在启动这个服务之前启动。具体来说，redis 服务需要在投票服务之前启动。这里的一个关键区别是我说的是启动。这并不意味着在启动这个服务之前必须运行依赖的服务；依赖的服务只需要在之前启动。再次强调，具体来说，redis 服务在启动投票服务之前不必处于运行状态，它只需要在投票服务之前启动。在投票服务的部署关键点中，我们还没有看到任何新的东西，唯一的区别是我们要求投票服务有两个副本。你开始理解堆栈组合文件中服务定义的简单性和强大性了吗？

在我们的堆栈组合文件中定义的下一个服务是结果服务。然而，由于在该服务定义中没有我们之前没有见过的关键点，我将跳过对结果服务的讨论，转而讨论工作人员服务，我们将看到一些新东西。以下是工作人员服务的定义：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-qk-st-gd/img/b4ddec41-7ece-487d-a782-615d8853be3c.png)

你知道图像密钥及其含义。你也知道网络密钥及其含义。你知道部署密钥，但是我们在这里有一些新的子密钥，所以让我们谈谈它们，从`mode`密钥开始。你可能还记得我们在第五章中讨论服务时，*Docker Swarm*，有一个`--mode`参数，可以有两个值：`global`或`replicated`。这个密钥与我们在第五章中看到的参数完全相同，*Docker Swarm*。默认值是 replicated，所以如果你不指定 mode 密钥，你将得到 replicated 行为，即确切地有定义的副本数量（或者如果没有指定副本数量，则为一个副本）。使用 global 的其他值选项将忽略 replicas 密钥，并在集群中的每个主机上部署一个容器。

我们在这个堆栈组合文件中以前没有见过的下一个密钥是`labels`密钥。这个密钥的位置很重要，因为它可以作为自己的上层密钥出现，也可以作为 deploy 密钥的子密钥出现。有什么区别？当你将`labels`密钥作为 deploy 密钥的子密钥使用时，标签将仅设置在服务上。当你将`labels`密钥作为自己的上层密钥使用时，标签将被添加到作为服务的一部分部署的每个副本或容器中。在我们的例子中，`APP=VOTING`标签将被应用到服务，因为`labels`密钥是 deploy 密钥的子密钥。再次，在我们的环境中看看这个：

```
# Inspect the worker service to see its labels
docker service inspect voteapp_worker \
 --format '{{json .Spec.Labels}}' | jq
```

在我的系统上看起来是这样的：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-qk-st-gd/img/4b1b7fba-94cd-40ec-ac68-66fd1d791c1d.png)

在工作容器上执行 inspect 命令以查看其标签，将显示`APP=VOTING`标签不存在。如果你想在你的系统上确认这一点，命令将如下（使用不同的容器名称）：

```
# Inspect the labels on a worker container
docker container inspect voteapp_worker.1.rotx91qw12d6x8643z6iqhuoj \
 -f '{{json .Config.Labels}}' | jq
```

在我的系统上看起来是这样的：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-qk-st-gd/img/c4206773-5d0a-4903-a6d6-af59fc260ead.png)

重启策略键的两个新子键是`max_attempts`和`window`键。你可能能猜到它们的目的；`max_attempts`键告诉 Docker 在放弃之前尝试启动工作容器的次数，最多三次。`window`键告诉 Docker 在之前多久等待重新尝试启动工作容器，如果之前启动失败。相当简单，对吧？同样，这些定义很容易设置，易于理解，并且对于编排我们应用程序的服务非常强大。

好的。我们还有一个服务定义需要审查新内容，那就是可视化服务。在我们的堆栈组合文件中，它看起来是这样的：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-qk-st-gd/img/9a9366b9-a6af-4510-990e-0c8af430a4da.png)

唯一真正新的键是`stop_grace_period`键。这个键告诉 Docker 在它告诉一个容器停止之后等待多长时间才会强制停止容器。如果没有使用`stop_grace_period`键，默认时间段是 10 秒。当你需要更新一个堆栈，本质上是重新堆叠，一个服务的容器将被告知优雅地关闭。Docker 将等待在`stop_grace_period`键中指定的时间量，或者如果没有提供键，则等待 10 秒。如果容器在那段时间内关闭，容器将被移除，并且一个新的容器将被启动来取代它。如果容器在那段时间内没有关闭，它将被强制停止，杀死它，然后移除它，然后启动一个新的容器来取代它。这个键的重要性在于它允许运行需要更长时间才能优雅停止的进程的容器有必要的时间来实际优雅停止。

我想指出这项服务的最后一个方面，那就是关于列出的有点奇怪的卷。这不是一个典型的卷，并且在卷键定义中没有条目。`/var/run/docker.sock:/var/run/docker.sock`卷是一种访问主机的 Docker 守护程序正在侦听的 Unix 套接字的方式。在这种情况下，它允许容器与其主机通信。可视化器容器正在收集关于哪些容器在哪些主机上运行的信息，并且能够以图形方式呈现这些数据。你会注意到它将 8080 主机端口映射到 8080 容器端口，所以我们可以通过浏览到任何我们的 swarm 节点上的 8080 端口来查看它共享的数据。这是我（当前）三节点 swarm 上的样子：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-qk-st-gd/img/51807fb7-0768-419a-80af-5281df5e2ef8.png)

# 堆栈其余命令

现在，让我们通过我们部署了`voteapp`堆栈的 swarm 的视角快速看一下我们的其他与堆栈相关的命令。首先，我们有列出堆栈的命令：`docker stack ls`。试一下看起来像这样：

```
# List the stacks deployed in a swarm
docker stack ls
```

这是示例环境中的样子：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-qk-st-gd/img/9b32a41a-3a67-427f-bc1c-a6d2167d52aa.png)

这表明我们当前部署了一个名为 voteapp 的堆栈，它由六个服务组成，并且正在使用 swarm 模式进行编排。知道部署堆栈的名称可以让我们使用其他堆栈命令来收集更多关于它的信息。接下来是列出堆栈任务的命令。让我们在示例环境中尝试一下这个命令：

```
# List the tasks for our voteapp stack filtered by desried state
docker stack ps voteapp --filter desired-state=running
```

这是我当前环境中的结果；你的应该看起来非常相似：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-qk-st-gd/img/d6dbb6ce-fbfb-4386-8250-2bfd9bc4857e.png)

现在，让我们来看看堆栈服务命令。这个命令将为我们提供一个关于作为堆栈应用程序一部分部署的服务的简要摘要。命令看起来像这样：

```
# Look at the services associated with a deployed stack
docker stack services voteapp
```

这是我们在示例环境中看到的：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-qk-st-gd/img/d7c657d4-540a-433b-97ee-b230735ed4c8.png)

这个命令提供了一些非常有用的信息。我们可以快速看到我们服务的名称，所需副本的数量，以及每个服务的实际副本数量。我们可以看到用于部署每个服务的镜像，并且我们可以看到每个服务使用的端口映射。在这里，我们可以看到可视化服务正在使用端口`8080`，就像我们之前提到的那样。我们还可以看到我们的投票服务暴露在我们集群主机的端口`5000`上。让我们通过浏览到端口`5000`（在集群中的任何节点上）来看看我们在我们的 voteapp 中展示了什么：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-qk-st-gd/img/96258e39-c554-4dd6-b33c-697eb17986ec.png)

你是狗派还是猫派？你可以通过在你自己的 voteapp 中投票来表达自己！投票然后使用堆栈服务命令中的数据来查看投票结果，浏览到端口`5001`：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-qk-st-gd/img/7c015ab2-78dd-47e0-b949-dffb749946d9.png)

是的，我是一个狗派。还有一个最终的堆栈命令：删除命令。我们可以通过发出`rm`命令来快速轻松地关闭使用堆栈部署的应用程序。看起来是这样的：

```
# Remove a deploy stack using the rm command
docker stack rm voteapp
```

现在你看到它了，现在你看不到了：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-qk-st-gd/img/46c33edf-aa70-4eb8-9eb3-598d69cab70a.png)

你应该注意到这里没有任何“你确定吗？”的提示，所以在按下*Enter*键之前一定要非常确定和非常小心。让我们通过快速查看作为 Docker 堆栈部署的应用程序的扩展或重新堆叠的最佳实践来结束对 Docker 堆栈的讨论。

# 扩展堆栈应用程序的最佳实践

与大多数 Docker 相关的事物一样，有几种不同的方法可以实现应用程序的期望状态。当您使用 Docker 堆栈时，应始终使用与部署应用程序相同的方法来更新应用程序。在堆栈 compose 文件中进行任何期望的状态更改，然后运行与部署堆栈时使用的完全相同的命令。这允许您使用标准源代码控制功能来正确处理您的 compose 文件，例如跟踪和审查更改。而且，它允许 Docker 正确地为您的应用程序进行编排。如果您需要在应用程序中缩放服务，您应该在堆栈 compose 文件中更新 replicas 键，然后再次运行部署命令。在我们的示例中，我们的投票服务有两个副本。如果投票需求激增，我们可以通过将 replica 值从 2 更改为 16 来轻松扩展我们的应用程序，方法是编辑`docker-stack.yml`文件，然后发出与最初用于部署应用程序相同的命令：

```
# After updating the docker-stack.yml file, scale the app using the same deploy command
docker stack deploy -c docker-stack.yml voteapp
```

现在，当我们检查服务时，我们可以看到我们正在扩展我们的应用程序：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-qk-st-gd/img/c8149abc-acce-4e48-bf42-3d65cb21a180.png)

就是这样，一个易于使用、易于理解且非常强大的 Docker 应用程序编排！

# 参考资料

查看以下链接获取更多信息：

+   Compose 文件参考：[`docs.docker.com/compose/compose-file/`](https://docs.docker.com/compose/compose-file/)

+   一些 Compose 文件示例：[`github.com/play-with-docker/stacks`](https://github.com/play-with-docker/stacks)

+   Docker hub 上的示例镜像：[`hub.docker.com/u/dockersamples/`](https://hub.docker.com/u/dockersamples/)

+   在 Docker hub 上找到的官方 redis 镜像标签：[`hub.docker.com/r/library/redis/tags/`](https://hub.docker.com/r/library/redis/tags/)

+   关于使用 Docker 守护程序套接字的精彩文章：[`medium.com/lucjuggery/about-var-run-docker-sock-3bfd276e12fd`](https://medium.com/lucjuggery/about-var-run-docker-sock-3bfd276e12fd)

+   堆栈部署命令参考：[`docs.docker.com/engine/reference/commandline/stack_deploy/`](https://docs.docker.com/engine/reference/commandline/stack_deploy/)

+   堆栈 ps 命令参考：[`docs.docker.com/engine/reference/commandline/stack_ps/`](https://docs.docker.com/engine/reference/commandline/stack_ps/)

+   堆栈服务命令参考：[`docs.docker.com/engine/reference/commandline/stack_services/`](https://docs.docker.com/engine/reference/commandline/stack_services/)

# 摘要

现在你对 Docker 堆栈有了很多了解。你可以使用 compose 文件轻松创建应用程序定义，然后使用 stack deploy 命令部署这些应用程序。你可以使用 ls、ps 和 services 命令探索已部署堆栈的细节。你可以通过对 compose 文件进行简单修改并执行与部署应用程序相同的命令来扩展你的应用程序。最后，你可以使用 stack rm 命令移除已经到达生命周期终点的应用程序。伴随着强大的能力而来的是巨大的责任，所以在使用移除命令时要非常小心。现在你已经有足够的信息来创建和编排世界级的企业级应用程序了，所以开始忙碌起来吧！然而，如果你想学习如何将 Docker 与 Jenkins 一起使用，你会很高兴地知道这就是第八章《Docker 和 Jenkins》的主题，所以翻开书页开始阅读吧！


# 第八章：Docker 和 Jenkins

在本章中，我们将学习如何利用 Jenkins 来构建我们的 Docker 镜像并部署我们的 Docker 容器。接下来，我们将学习如何将我们的 Jenkins 服务器部署为 Docker 容器。然后，我们将学习如何在 Docker 化的 Jenkins 服务器中构建 Docker 镜像。这通常被称为 Docker 中的 Docker。最后，我们将看到如何利用 Docker 容器作为 Jenkins 构建代理，允许每个构建在一个原始的、短暂的 Docker 容器中运行。当然，我们将展示如何在我们的 Docker 化的 Jenkins 构建代理中构建 Docker 镜像、测试应用程序，并将经过测试的镜像推送到 Docker 注册表中。这将为您提供设置 CI/CD 系统所需的所有工具。

如果世界上所有的集装箱都被排成一排，它们将绕地球超过两次。- [`www.bigboxcontainers.co.za/`](https://www.bigboxcontainers.co.za/)

在本章中，我们将涵盖以下主题：

+   使用 Jenkins 构建 Docker 镜像

+   设置 Docker 化的 Jenkins 服务器

+   在 Docker 化的 Jenkins 服务器中构建 Docker 镜像

+   使用 Docker 容器作为您的 Jenkins 构建节点

+   在 Docker 化的构建节点中构建、测试和推送 Docker 镜像

# 技术要求

您将从 Docker 的公共仓库中拉取 Docker 镜像，并安装 Jenkins 服务器软件，因此执行本章示例需要基本的互联网访问。还要注意，这些示例的系统要求比前几章中介绍的要高。本章示例中使用的服务器具有 8GB 的内存、2 个 CPU 和 20GB 的硬盘。

本章的代码文件可以在 GitHub 上找到：

[`github.com/PacktPublishing/Docker-Quick-Start-Guide/tree/master/Chapter08`](https://github.com/PacktPublishing/Docker-Quick-Start-Guide/tree/master/Chapter08)

查看以下视频以查看代码的实际操作：[`bit.ly/2AyRz7k`](http://bit.ly/2AyRz7k)

# 使用 Jenkins 构建 Docker 镜像

您可能已经知道 Jenkins 是一个广泛使用的持续集成/持续交付（CI/CD）系统工具。几乎每家公司，无论大小，都在某种程度上使用它。它非常有效，高度可配置，特别是可以与之一起使用的各种插件。因此，将其用于创建 Docker 镜像是非常自然的。使用 Jenkins 与 Docker 的第一步相当容易完成。如果您今天正在使用现有的 Jenkins 服务器，要使用它来构建 Docker 镜像，您只需要在 Jenkins 服务器上安装 Docker。您可以使用我们在第一章“设置 Docker 开发环境”中看到和使用的完全相同的安装技术。根据运行 Jenkins 服务器的系统的操作系统，您可以按照第一章中学到的安装步骤，设置 Docker 开发环境；完成后，您可以使用 Jenkins 构建 Docker 镜像。

如果您还没有运行的 Jenkins 服务器，您可以按照以下“参考”部分中的*安装 Jenkins*网页链接中找到的指南进行操作，并在您正在使用的任何操作系统上安装 Jenkins。例如，我们将使用该页面的信息在 Ubuntu 系统上设置 Jenkins 服务器。首先打开一个终端窗口。现在获取 Jenkins 软件包的 apt-key。接下来，您将向 apt 源列表中添加 Debian Jenkins 源。然后，您将更新系统上的软件包，最后，您将使用 apt-get 安装 Jenkins。命令看起来像下面这样：

```
# If Java has not yet been installed, install it now
sudo apt install openjdk-8-jre-headless

# Install Jenkins on an Ubuntu system
wget -q -O - https://pkg.jenkins.io/debian/jenkins.io.key | sudo apt-key add -
sudo sh -c 'echo deb http://pkg.jenkins.io/debian-stable binary/ > /etc/apt/sources.list.d/jenkins.list'
sudo apt-get update
sudo apt-get install jenkins
```

在我的系统上运行这些命令看起来像下面这样：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-qk-st-gd/img/9ffd1d7c-3383-4e84-acf8-771ca376e97c.png)

安装完成后，您将要打开浏览器，并浏览到系统上的端口`8080`，完成 Jenkins 系统的设置和配置。这将包括输入管理员密码，然后决定在 Jenkins 服务器的初始部署中安装哪些插件。我建议使用 Jenkins 建议的设置，因为这是一个很好的起点：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-qk-st-gd/img/95c474c0-2d10-402b-af99-71ad922f7dd7.png)

既然你有了一个 Jenkins 服务器，你可以开始创建工作来执行确认它是否按预期工作。让我们从一个微不足道的 Hello world!工作开始，以确认 Jenkins 正在工作。登录到你的 Jenkins 服务器，点击“新建项目”链接。在新项目页面中，输入我们的工作名称。我使用`hello-test`。选择我们要创建的工作类型为 pipeline。接下来，点击页面左下角附近的“确定”按钮。这将带你到我们新工作的配置屏幕。这个将会非常简单。我们将创建一个 pipeline 脚本，所以向下滚动直到看到 Pipeline 脚本输入框，并输入以下脚本（注意 pipeline 脚本是用 groovy 编写的，它使用 Java（和 C）形式的注释）：

```
// Our hello world pipeline script, named "hello-test"
node {
  stage('Say Hello') {
      echo 'Hello Docker Quick Start Guide Readers!'
   }
}
```

现在就这样吧，点击“保存”按钮保存我们 Jenkins 工作的更新配置。一旦配置保存了，让我们通过点击“立即构建”链接来测试工作。如果一切都按预期运行，我们应该看到工作成功完成。它会看起来像下面这样：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-qk-st-gd/img/076b8ce5-1c78-4a28-9822-c898bf0ef082.png)

现在让我们创建另一个工作。点击链接返回仪表板，然后再次点击“新建项目”链接。这次，让我们把工作命名为`hello-docker-test`。同样，选择 pipeline 作为你想要创建的工作类型，然后点击“确定”按钮。再次向下滚动到 Pipeline 脚本输入框，并输入以下内容：

```
// Our Docker hello world pipeline script, named "hello-docker-test"
node {
   stage('Hello via Alpine') {
      docker.image('alpine:latest').inside {
         sh 'echo Hello DQS Readers - from inside an alpine container!'
      }
   }
}
```

点击“保存”按钮保存新工作的配置，然后点击“立即构建”链接启动 Jenkins 工作。以下是这次可能看起来的样子：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-qk-st-gd/img/140e4cd5-a668-4c00-928e-d2f9dd279357.png)

这次发生了什么？这次没有成功完成。显然失败了，因为我们的 Jenkins 服务器上还没有安装 Docker。所以让我们继续按照第一章“设置 Docker 开发环境”中找到的指令，安装 Docker，并将其安装在我们的 Jenkins 服务器上。一旦安装好了，还有一个额外的步骤你会想要做，那就是将 Jenkins 用户添加到 Docker 组中。命令如下：

```
# Add the jenkins user to the docker group
sudo usermod -aG docker jenkins
# Then restart the jenkins service
sudo service jenkins restart
```

这与我们用来将我们的 Docker 服务器的当前用户添加到 docker 组的命令非常相似，因此在 Docker 命令中不需要使用`sudo`。好的，现在让我们回到我们的 Jenkins 服务器 UI 和我们的`hello-docker-test`作业，再次点击“立即构建”按钮。

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-qk-st-gd/img/6ab728c9-55d5-4d7f-a12e-43f03623c137.png)

恭喜！您有一个全新的 Jenkins 服务器，已正确配置为构建（测试、推送和部署）Docker 映像。干得好。尽管这是一个伟大的成就，但工作量还是有点大。您难道不希望有更简单的方法来设置新的 Jenkins 服务器吗？所以，您知道您已经有一组运行 Docker 的服务器？您认为您可以使用该环境以更简单的方式建立起您的 Jenkins 服务器吗？当然可以！让我们来看看。

# 参考资料

以下是安装 Jenkins 的网页：[`jenkins.io/doc/book/installing/`](https://jenkins.io/doc/book/installing/)。

# 设置 Docker 化的 Jenkins 服务器

您刚刚看到了设置新的 Jenkins 服务器有多少工作。虽然这并不是一个艰巨的工作，但至少有五个步骤您必须完成，然后才能选择您的插件并登录开始工作。并且在游戏节目*猜猜这首歌*的精神下，我可以在三个步骤内部署一个 Jenkins 服务器，前两个步骤只是为了让我们的 Jenkins 数据在托管 Jenkins 服务器的 Docker 容器的生命周期之外持久存在。假设您已经按照第一章“设置 Docker 开发环境”的说明设置并运行了 Docker 主机，我们希望创建一个位置，让 Jenkins 服务器存储其数据。我们将创建一个文件夹并分配所有权。它将如下所示：

```
# Setup volume location to store Jenkins configuration
mkdir $HOME/jenkins_home
chown 1000 $HOME/jenkins_home
```

所有者`1000`是将在 Docker 容器内用于 jenkins 用户的用户 ID。

第三步是部署我们的容器。在我向您展示命令之前，让我稍微谈一下要使用哪个容器映像。我包含了一个链接，可以在 Docker hub 上搜索 Jenkins 映像。如果您使用该链接或自行搜索，您会发现有很多选择。最初，您可能会考虑使用官方的 Jenkins 映像。然而，如果您浏览该存储库，您会发现我觉得有点奇怪的是，官方映像已经被弃用。它已经停止更新到 LTS 2.60.x 版本：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-qk-st-gd/img/69a04bfa-7556-4017-9b3a-dad4edb474a7.png)

它建议使用在 jenkins/jenkins:lts Jenkins 镜像库中找到的镜像，目前的版本是 2.149.x。这是我们将在下面的示例中使用的镜像。以下是我们将使用的命令来部署我们的 Jenkins 服务器容器：

```
# Deploy a Jenkins server that is configured to build Docker images
docker container run -d -p 8080:8080 -p 50000:50000 \
-v $HOME/jenkins_home:/var/jenkins_home \
--name jenkins --rm jenkins/jenkins:lts
```

仔细看这个命令，我们可以看到我们正在将容器作为守护进程（非交互式）启动。我们看到我们在主机上打开了两个端口，它们映射到容器上的相同端口号，具体是`8080`和`50000`。接下来，我们看到我们正在使用一个卷，并且它映射到我们之前创建的文件夹。这是 Jenkins 将存储其数据的地方，比如我们创建的作业和它们执行的状态。然后您会注意到我们给容器命名为`jenkins`。之后，我们告诉 Docker 在退出时删除容器，使用`--rm`标志。最后，我们告诉 Docker 我们要运行哪个镜像。

当您运行此容器时，请给它一两分钟来启动，并浏览到 Docker 主机上的端口`8080`，您将看到与在部署 Jenkins 作为独立应用程序时看到的密码提示相同。然后会出现创建第一个用户的屏幕和默认插件配置屏幕。试试看吧。

由于我们为 Jenkins 数据创建了一个卷（写入`/var/jenkins_home`），我们的 Jenkins 配置数据被保存到主机上，并且将超出容器本身的生命周期。当然，您可以使用存储驱动程序，并将这些数据保存在比 Docker 主机更持久的地方，但您明白我的意思，对吧？

唯一的问题是，官方的 Jenkins 镜像和`jenkins/jenkins`镜像都不支持创建将构建 Docker 镜像的作业。而且由于本书都是关于 Docker 的，我们需要做的不仅仅是使用上述镜像运行我们的 Jenkins 服务器。别担心，我有个计划……继续阅读。

# 参考资料

+   Docker hub 搜索 Jenkins 镜像：[`hub.docker.com/search/?isAutomated=0&isOfficial=0&page=1&pullCount=0&q=jenkins&starCount=0`](https://hub.docker.com/search/?isAutomated=0&isOfficial=0&page=1&pullCount=0&q=jenkins&starCount=0)

+   官方的 Jenkins 镜像库：[`hub.docker.com/_/jenkins/`](https://hub.docker.com/_/jenkins/)

+   Jenkins/jenkins 镜像库：[`hub.docker.com/r/jenkins/jenkins/`](https://hub.docker.com/r/jenkins/jenkins/)

# 在 Docker 化的 Jenkins 服务器内构建 Docker 镜像

好了。现在你知道如何将 Jenkins 部署为 Docker 容器，但我们真的希望能够使用 Jenkins 来构建 Docker 镜像，就像我们在独立部署 Jenkins 时所做的那样。为了做到这一点，我们可以部署相同的 Jenkins 镜像，并在其中安装 Docker，可能可以让它工作，但我们不需要那么麻烦。我们不是第一个走上这条路的先驱。已经创建了几个 Docker 镜像，可以做我们想做的事情。其中一个镜像是`h1kkan/jenkins-docker:lts`。您可以通过以下*参考*部分中的链接阅读有关它的信息，但现在只需知道它是一个已设置为 Jenkins 服务器的镜像，并且其中已经安装了 Docker。实际上，它还预先安装了 Ansible 和 AWSCLI，因此您可以使用它来构建 Docker 镜像以外的其他操作。

首先，我们将在 Docker 主机上创建一个位置，以挂载 Docker 卷来存储和保留 Jenkins 配置。如果您正在使用与上一节相同的 Docker 主机，您应该已经创建了文件夹并将其分配给 ID`1000`。如果没有，以下是您可以使用的命令：

```
# Setup volume location to store Jenkins configuration
mkdir $HOME/jenkins_home
chown 1000 $HOME/jenkins_home
```

另外，如果您还没有这样做，您可以使用`docker container stop jenkins`命令来停止（并删除）我们在上一节中创建的 Jenkins 容器，以为我们的新的、改进的 Jenkins 服务器腾出空间。当您准备创建新的容器时，您可以使用以下命令：

```
# Deploy a Jenkins server that is configured to build Docker images
docker container run -d -p 8080:8080 -p 50000:50000 \
-v $HOME/jenkins_home:/var/jenkins_home \
-v /var/run/docker.sock:/var/run/docker.sock \
--name jenkins --rm h1kkan/jenkins-docker:lts

# Start the Docker service in the Jenkins docker container
docker container exec -it -u root jenkins service docker start
```

您可能已经注意到了这个代码块中的一些不同之处。第一个是使用了第二个卷。这是一种众所周知的技巧，允许容器向其主机发出 Docker 命令。这本质上允许了所谓的 Docker-in-Docker。下一个不同之处是额外的 Docker 命令，它将在运行的容器内启动 Docker 服务。因为每个容器都会启动一个单一进程，所以同时运行 Jenkins 服务器进程和 Docker 守护程序需要这一额外步骤。

一旦在 Jenkins 容器内启动了 Docker 服务，您就可以创建使用和构建 Docker 镜像的新 Jenkins 作业。您可以通过在新的 Jenkins 服务器中重新创建上面的第二个示例`hello-docker-test`来自行测试。由于我们使用的是挂载在主机上的 Docker 卷`$HOME/jenkins_home`来存储我们的 Jenkins 数据，这应该是您需要创建此作业的最后一次。

这一切都运作得很好，但您可能还记得第七章*Docker Stacks*中我们有一个比使用`docker container run`命令更好的部署应用程序的方法，即使用 Docker 堆栈。那么，您想看到我们的示例重新构想为 Docker 堆栈吗？我也是！好的，那么，让我们来做吧。

首先，使用容器停止命令停止当前的 Jenkins 容器。它将保留我们的 Jenkins 服务器数据的`jenkins_home`文件夹，但如果由于某种原因您跳到本章的这一部分并且还没有创建它，以下是要使用的命令：

```
# Setup volume location to store Jenkins configuration
mkdir $HOME/jenkins_home
chown 1000 $HOME/jenkins_home
```

再次强调，如果您对先前的示例中的这两个命令进行了操作，并且您正在使用相同的 Docker 主机，您就不必再次执行这些操作，因为该文件夹已经存在并且具有正确的所有权。

接下来，您需要为我们的 Jenkins 堆栈创建一个 compose 文件。我把我的命名为`jenkins-stack.yml`，并输入以下 YML 代码：

```
# jenkins-stack.yml
version: "3"
services:
  jenkins:
    image: h1kkan/jenkins-docker:lts
    ports:
       - 8080:8080
       - 50000:50000
    volumes:
       - $HOME/jenkins_home:/var/jenkins_home
       - /var/run/docker.sock:/var/run/docker.sock
    deploy:
       replicas: 1
       restart_policy:
         condition: on-failure
    placement:
      constraints: [node.role == manager]

  registry:
    image: registry
    ports:
       - 5000:5000
 deploy:
    replicas: 1
    restart_policy:
      condition: on-failure
```

您将注意到我们正在创建两个服务；一个是我们的 Jenkins 服务器，另一个是 Docker 注册表。我们将在即将到来的示例中使用注册表服务，所以现在把它放在心里。查看 Jenkins 服务描述时，我们没有看到在第七章*Docker Stacks*中学到的任何内容。您将注意到我们的两个端口映射和上一个示例中使用的两个卷。我们将把单个 Jenkins 副本限制在我们的管理节点上。

记住，要使用 Docker 堆栈，我们必须在集群模式下运行，因此，如果您还没有这样做，请使用我们在第五章学到的`docker swarm init`命令创建您的集群，*Docker Swarm*。

请注意，如果您的集群有多个管理节点，您需要进一步将 Jenkins 副本限制在只有您的`jenkins_home`卷挂载点的单个管理节点上。这可以通过角色和标签的组合来实现。或者，您可以使用存储驱动程序并挂载一个可以在集群管理节点之间共享的卷。为了简单起见，我们假设我们的示例中有一个单独的管理节点。

现在使用堆栈部署命令来设置 Jenkins 应用程序。以下是要使用的命令的示例：

```
# Deploy our Jenkins application via a Docker stack
docker stack deploy -c jenkins-stack.yml jenkins
```

一旦堆栈部署并且服务正在运行，您可以浏览到您集群中的任何节点，端口为 8080，并访问您的 Jenkins 服务器。更重要的是，如果您正在重用我们之前示例中的`jenkins_home`文件夹，您将不必提供管理员密码，创建新用户和选择插件，因为所有与这些任务相关的数据都存储在`jenkins_home`文件夹中，并且现在由基于堆栈的 Jenkins 服务重用。另一个有趣的事实是，当您在堆栈应用程序中使用此镜像时，您无需启动 Docker 服务。奖励！

好了，现在我们有一个甜蜜的基于堆栈的 Jenkins 服务，可以使用和构建 Docker 镜像。一切看起来都很好。但有一件事可以让这更好。通过更好，我指的是更加 Docker 化：而不是使用普通的 Jenkins 代理进行我们的构建作业，如果我们想要为每次执行 Jenkins 作业都启动一个新的原始 Docker 容器呢？这将确保每个构建都是在一个干净、一致的环境中从头构建的。此外，这真的可以提升 Docker 的内在水平，所以我非常喜欢。如果您想看看如何做到这一点，请继续阅读。

# 参考资料

+   H1kkan/jenkins-docker 仓库：[`hub.docker.com/r/h1kkan/jenkins-docker/`](https://hub.docker.com/r/h1kkan/jenkins-docker/)

# 使用 Docker 容器作为 Jenkins 构建节点

要将 Docker 容器用于 Jenkins 构建代理，您需要对 Jenkins 配置进行一些操作：

+   构建一个新的 Docker 镜像，可以作为 Jenkins 构建代理，并能够构建 Docker 镜像（当然）

+   将新镜像推送到 Docker 注册表

+   关闭默认的 Jenkins 构建代理

+   安装 Jenkins 的 Docker 插件

+   配置一个新的云以启用 Docker 化的构建代理

# 构建 Docker 镜像

让我们开始吧。我们要做的第一件事是构建我们专门的 Docker 镜像，用于我们的 Jenkins 代理。为此，我们将使用第三章“创建 Docker 镜像”中学到的技能来创建 Docker 镜像。首先在您的开发系统上创建一个新文件夹，然后将工作目录更改为该文件夹。我把我的命名为`jenkins-agent`：

```
# Make a new folder to use for the build context of your new Docker image, and cd into it
mkdir jenkins-agent
cd jenkins-agent
```

现在创建一个新文件，命名为`Dockerfile`，使用您喜欢的编辑器，输入以下代码，然后保存：

```
# jenkins-agent Dockerfile
FROM h1kkan/jenkins-docker:lts-alpine
USER root
ARG user=jenkins

ENV HOME /home/${user}
ARG VERSION=3.26
ARG AGENT_WORKDIR=/home/${user}/agent

RUN apk add --update --no-cache curl bash git openssh-client openssl procps \
 && curl --create-dirs -sSLo /usr/share/jenkins/slave.jar https://repo.jenkins-ci.org/public/org/jenkins-ci/main/remoting/${VERSION}/remoting-${VERSION}.jar \
 && chmod 755 /usr/share/jenkins \
 && chmod 644 /usr/share/jenkins/slave.jar \
 && apk del curl

ENV AGENT_WORKDIR=${AGENT_WORKDIR}
RUN mkdir -p /home/${user}/.jenkins && mkdir -p ${AGENT_WORKDIR}
USER ${user}

VOLUME /home/${user}/.jenkins
VOLUME ${AGENT_WORKDIR}
WORKDIR /home/${user}
```

我们的新 Dockerfile 正在做什么：在我们的`FROM`指令中，我们使用了与上面的 Docker-in-Docker 示例中相同的 Docker 镜像，以便我们有一个基础镜像，可以让我们构建 Docker 镜像。接下来，我们使用`USER`命令将当前用户设置为 root。然后，我们创建一个名为用户的`ARG`并将其设置为`jenkins`的值。之后，我们设置了一个名为`HOME`的环境变量，该变量具有 Jenkins 用户的主目录的值。然后，我们设置了另外两个`ARGs`，一个用于版本，一个用于 Jenkins 代理的工作目录。接下来是魔术发生的地方。我们使用`RUN`命令来设置并获取 Jenkins 的`slave.jar`文件。这是作为 Jenkins 代理所需的部分。我们还在文件夹和文件上设置了一些权限，然后通过删除 curl 来进行一些清理。之后，我们设置了另一个环境变量，这个环境变量是`AGENT_WORKDIR`。接下来，我们在容器中创建了一些文件夹。然后，我们再次使用`USER`指令，这次将当前用户设置为我们的 Jenkins 用户。最后，我们通过创建一些`VOLUME`实例来完成 Dockerfile，并将当前工作目录设置为我们的 Jenkins 用户的主目录。哦！这似乎很多，但实际上并不那么糟糕，您只需将上述代码复制粘贴到您的 Dockerfile 中并保存即可。

现在我们的 Dockerfile 准备好使用了，现在是创建一个 git 仓库并将代码保存到其中的好时机。一旦您确认您的项目已经正确地使用 git 设置好，我们就可以构建我们的新 Docker 镜像。以下是您将用于此目的的命令：

```
# Build our new Jenkins agent image
docker image build -t jenkins-agent:latest .
```

它应该成功构建并创建一个本地缓存的镜像，标记为`jenkins-agent:latest`。

# 将新镜像推送到 Docker 注册表。

接下来，我们需要将我们的新镜像推送到 Docker 注册表。当然，我们可以将其推送到 hub.docker.com 中的我们的仓库，但由于我们恰好部署了一个 Docker 注册表的应用程序堆栈，为什么不利用它来存储我们的 Jenkins 代理镜像呢？首先，我们需要使用注册表为我们的新镜像打标签。基于您的 Docker Swarm 的域名，您的标签命令将与我的不同，但对于我的示例，以下是我的标签命令的样子：

```
# Tag the image with our swarm service registry
docker image tag jenkins-agent:latest ubuntu-node01:5000/jenkins-agent:latest
```

现在镜像已经在本地标记，我们可以使用以下命令将其推送到注册表；同样，基于您的 Swarm 的域名，您的命令将有所不同：

```
# Push the Jenkins agent image to the registry
docker image push ubuntu-node01:5000/jenkins-agent:latest
```

所有这些命令可能会使用比`latest`标签更好的版本方案，但您应该能够自行解决这个问题。随着我们的镜像构建、标记和推送到 Docker 注册表，我们准备好更新 Jenkins 配置以使用它。

# 关闭默认的 Jenkins 构建代理

现在我们准备更新 Jenkins 配置以支持我们的 Docker 化构建代理。我们要做的第一个配置更改是关闭默认的构建代理。要做到这一点，登录到您的 Jenkins 服务器，然后单击“管理 Jenkins”菜单链接。这将带您进入各种配置组，例如系统、插件和 CLI 设置。现在，我们需要进入“配置系统”管理组：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-qk-st-gd/img/ca007e0f-82ae-4c3e-a93a-cd1c22f5d9d4.png)

一旦您进入“配置系统”管理组，您将更改“执行器数量”的值为`0`。它应该看起来像下面这样：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-qk-st-gd/img/930fbb65-4fa9-4fd7-b80e-7166516f870c.png)

当您将“执行器数量”更改为`0`后，您可以点击屏幕左下角的保存按钮保存设置。在这一点上，由于没有配置 Jenkins 代理来运行作业，您的 Jenkins 服务器将无法运行任何作业。因此，让我们快速进行下一步，即安装 Docker 插件。

# 安装 Jenkins 的 Docker 插件

现在我们需要为 Jenkins 安装 Docker 插件。您可以像安装其他插件一样完成此操作。单击“管理 Jenkins”菜单链接，然后从配置组列表中，单击“管理插件”组的链接：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-qk-st-gd/img/b844e146-e6c0-45f3-9795-d35802f31383.png)

一旦您进入“管理插件”配置组，选择“可用插件”选项卡，然后在筛选框中输入`docker`以缩小可用插件的列表，以便找到与 Docker 相关的插件：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-qk-st-gd/img/8ac3ae3c-383f-4ec3-8cfe-de0d89fe93f2.png)

即使有一个经过筛选的列表，仍然有很多插件可供选择。找到并勾选 Docker 插件。它看起来像下面这样：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-qk-st-gd/img/a78b0276-360d-4e6c-aaeb-686e4b69ef4e.png)

勾选 Docker 插件复选框，向下滚动并单击“无需重新启动安装”按钮。这将为您下载并安装插件，然后在 Jenkins 重新启动时启用它。在安装屏幕上，您可以选择在插件安装完成后立即执行重新启动的选项。要执行此操作，请勾选“安装完成后重新启动 Jenkins 并且没有作业正在运行”复选框：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-qk-st-gd/img/df355ed4-fc95-4e7d-90f8-7ad906a74f02.png)

由于我们几分钟前将执行器数量设置为`0`，现在不会有任何作业正在运行，因此一旦安装插件，Jenkins 将重新启动。Jenkins 一旦恢复在线，插件将被安装。我们需要重新登录 Jenkins 并设置我们的云。

# 创建一个新的云，以启用我们的 Docker 化构建代理

现在，我们将告诉 Jenkins 使用我们的自定义 Docker 镜像来作为 Jenkins 构建代理运行容器。再次，单击“管理 Jenkins”菜单链接。从配置组列表中，您将再次单击“配置系统”组的链接。您将在配置选项的底部附近找到云配置。单击“添加新云”下拉菜单，并选择`Docker`：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-qk-st-gd/img/85ccfde1-560f-4fcd-8957-d8bb1409904d.png)

屏幕将更新，您将看到两个新的配置组：Docker Cloud 详细信息...和 Docker 代理模板...：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-qk-st-gd/img/bd8072d5-822e-4414-9048-d83ba0de2a74.png)

让我们先处理 Docker Cloud 的细节。现在点击该按钮。您可以将名称值保留为`docker`的默认值。在 Docker 主机 URI 字段中，输入`unix:///var/run/docker.sock`。您可以通过单击问号帮助图标并将其复制粘贴到输入字段中来找到此值。接下来，单击“测试连接”按钮，您应该会看到一个版本行显示出来，类似于您将在以下屏幕截图中看到的内容。记下 API 版本号，因为您将需要它进行高级设置。单击“高级”按钮，并在 Docker API 版本字段中输入 API 版本号。您需要勾选“已启用”复选框以启用此功能，所以一定要这样做。最后，您可能需要更改系统可以同时运行的容器数量。默认值为 100。例如，我将该值减少到`10`。完成后，您的配置应该看起来类似于以下内容：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-qk-st-gd/img/f2e0d7ea-7952-4496-a6d5-fd3a9cf456a7.png)

接下来，点击 Docker 代理模板...按钮，然后点击出现的添加 Docker 模板按钮，以便配置 Jenkins 代理设置。在这里，您将要点击代理的已启用复选框，以启用我们的新代理模板。您可以给一个名称，用作由 Jenkins 作为构建代理运行的容器的前缀，或者您可以将名称留空，将使用`docker`前缀。接下来，输入您要用于构建代理容器的镜像的存储库和名称标签。我们创建了我们的自定义镜像，标记了它，并将其推送到我们的 Jenkins 堆栈应用程序存储库，使用`ubuntu-node01:5000/jenkins-agent:latest`镜像名称，因此将该值输入到 Docker 镜像字段中。将实例容量值设置为`1`，将远程文件系统根值设置为`/home/jenkins/agent`。确保使用值设置为`尽可能多地使用此节点`，并使用`连接方法`的`附加 Docker 容器`值。将用户设置为`root`。将拉取策略值更改为`拉取一次并更新最新`：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-qk-st-gd/img/79d3e2f7-bed3-4876-8839-acd362836905.png)

最后，我们需要配置一些容器设置..., 所以点击展开该部分。我们需要在这里输入的值是容器运行时要使用的命令。Docker 命令字段中需要的值是 `java -jar /usr/share/jenkins/slave.jar`。卷字段中需要的值是 `/var/run/docker.sock:/var/run/docker.sock`：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-qk-st-gd/img/91b7b76b-f375-4e9a-96dd-fc80c59193a3.png)

最后，勾选分配伪 TTY 的复选框：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-qk-st-gd/img/2361d7a1-efdd-4143-a14a-91c14c5be184.png)

滚动到配置屏幕底部，然后单击保存按钮以保存所有云设置。这是一些严肃的配置功夫 - 做得好！但是，以防万一您想要所有输入值的快速参考，这里是我们示例中用于配置 Docker 云的所有自定义（或非默认）值：

| **字段名称** | **使用的值** |
| --- | --- |
| Docker 主机 URI | `unix:///var/run/docker.sock` |
| Docker API 版本 | `1.38`（与连接测试中显示的版本匹配） |
| Docker 云已启用 | 已勾选 |
| 容器容量 | `10` |
| Docker 代理已启用 | 已勾选 |
| Docker 代理模板名称 | `agent` |
| Docker 镜像 | `ubuntu-node01:5000/jenkins-agent:latest` |
| 实例容量 | `1` |
| 远程文件系统根 | `/home/jenkins/agent` |
| 用途 | `尽可能多地使用此节点` |
| 连接方法 | `附加 Docker 容器` |
| 用户 | `root` |
| 拉取策略 | `拉取一次并更新最新` |
| Docker 命令 | `java -jar /usr/share/jenkins/slave.jar` |
| 卷 | `/var/run/docker.sock:/var/run/docker.sock` |
| 分配伪 TTY | 已选中 |

现在一切都配置好了，让我们测试一下我们新定义的 Jenkins 代理。

# 测试我们的新构建代理

返回 Jenkins 仪表板，点击“计划构建”按钮，为我们的`hello-docker-test`作业。这将为我们的作业启动一个新的构建，然后将创建一个新的 Docker 化构建代理。它使用我们设置的配置来执行`docker container run`命令，以运行一个基于我们指定的镜像的新容器。最初，执行器将处于离线状态，因为容器正在启动：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-qk-st-gd/img/5ef3cfa0-9f85-4bd8-9f0d-8033edc1ab22.png)

注意，执行器名称具有我们指定的代理前缀。一旦容器运行起来，Jenkins 作业将在其中启动，基本上使用`docker container exec`命令。当 Jenkins 作业启动时，正常的作业进度图形将显示，并且执行器将不再显示为离线状态。状态然后会看起来像这样：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-qk-st-gd/img/fe9dfbb5-5374-4b37-8847-010948778f6f.png)

如果您点击正在执行的作业的进度条，您可以查看作业的控制台输出，不久后，作业将显示已完成：成功状态，如下所示：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-qk-st-gd/img/5b261ded-6411-40af-affc-42214a2e25ed.png)

工作完成得很好！让我们检查最后一个例子 Jenkins 作业，展示一个具有更多阶段的流水线脚本，代表了一个真实世界的 Docker 作业的例子。你准备好了吗？继续阅读。

# 在 Docker 化构建节点内构建、测试和推送 Docker 镜像

在 Docker 和 Jenkins 的这一章结束之前，让我们走一遍为真实世界的 Docker 化节点应用程序创建模板的步骤。以下是我们将要做的：

准备我们的应用程序：

+   在 GitHub 上创建一个新的存储库

+   克隆存储库到我们的开发工作站

+   创建我们的应用程序文件

+   将我们的应用程序文件上传到 GitHub

创建并测试将构建我们的 Docker 化节点应用程序的 Jenkins 作业：

+   创建一个利用 GitHub 存储库的新 Jenkins 作业

+   测试我们的 Jenkins 作业，将拉取存储库，构建应用程序，测试它，并发布镜像

+   庆祝我们的成功！

让我们开始准备我们的应用程序。

我们要做的第一件事是在 GitHub 上创建我们的应用程序存储库。浏览并登录[github.com](http://www.github.com)，转到你的存储库页面，然后点击创建新存储库按钮。输入新存储库的名称。在我们的示例中，我使用了`dqs-example-app`。输入一个合适的描述。你可以将你的存储库设置为公开或私有。在这个示例中，我将其设置为公开，以简化后续不需要身份验证即可拉取存储库的过程。勾选初始化存储库复选框，这样你就可以立即在你的工作站上克隆空的存储库。你可以选择创建`.gitignore`文件时要使用的项目类型。我选择了`Node`。当你输入并选择了所有这些内容后，它会看起来像下面这样：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-qk-st-gd/img/48bc3985-be57-41e8-a45e-e19d7f4998e0.png)

点击创建存储库按钮来创建你的新应用程序存储库。现在它在 GitHub 上创建好了，你会想要将它克隆到你的工作站上。使用克隆或下载按钮，然后使用复制按钮来复制存储库的 URL 以进行克隆步骤：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-qk-st-gd/img/44409c48-3703-4a37-a8ef-bb67901d05a2.png)

现在，回到你的工作站，在你保存本地存储库的位置，克隆这个新的（大部分是）空的存储库。然后切换到新存储库的文件夹中。对我来说，看起来像下面这样：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-qk-st-gd/img/983a1f97-6082-47e2-85df-40b296775617.png)

现在我们要创建应用程序的脚手架。这将包括创建一个`Dockerfile`，一个`Jenkinsfile`，`main.js`和`test.js`文件，以及`package.json`文件。使用你喜欢的编辑器在你的应用程序文件夹中创建这些文件。以下是这些文件的内容：

以下是`Dockerfile`文件的内容：

```
FROM node:10-alpine
COPY . .
RUN npm install
EXPOSE 8000
CMD npm start
```

以下是`Jenkinsfile`文件的内容：

```
node {
   def app
   stage('Clone repository') {
      /* Clone the repository to our workspace */
      checkout scm
   }
   stage('Build image') {
      /* Builds the image; synonymous to docker image build on the command line */
      /* Use a registry name if pushing into docker hub or your company registry, like this */
      /* app = docker.build("earlwaud/jenkins-example-app") */
      app = docker.build("jenkins-example-app")
   }
   stage('Test image') {
      /* Execute the defined tests */
      app.inside {
         sh 'npm test'
      }
   }
   stage('Push image') {
      /* Now, push the image into the registry */
      /* This would probably be docker hub or your company registry, like this */
      /* docker.withRegistry('https://registry.hub.docker.com', 'docker-hub-credentials') */

      /* For this example, We are using our jenkins-stack service registry */
      docker.withRegistry('https://ubuntu-node01:5000') {
         app.push("latest")
      }
   }
}
```

以下是`main.js`文件的内容：

```
// load the http module
var http = require('http');

// configure our HTTP server
var server = http.createServer(function (request, response) {
   response.writeHead(200, {"Content-Type": "text/plain"});
   response.end("Hello Docker Quick Start\n");
});

// listen on localhost:8000
server.listen(8000);
console.log("Server listening at http://127.0.0.1:8000/");
```

以下是`package.json`文件的内容：

```
{
   "name": "dqs-example-app",
   "version": "1.0.0",
   "description": "A Docker Quick Start Example HTTP server",
   "main": "main.js",
   "scripts": {
      "test": "node test.js",
      "start": "node main.js"
   },
   "repository": {
      "type": "git",
      "url": "https://github.com/earlwaud/dqs-example-app/"
   },
   "keywords": [
      "node",
      "docker",
      "dockerfile",
      "jenkinsfile"
   ],
   "author": "earlwaud@hotmail.com",
   "license": "ISC",
   "devDependencies": { "test": ">=0.6.0" }
}
```

最后，以下是`test.js`文件的内容：

```
var assert = require('assert')

function test() {
   assert.equal(1 + 1, 2);
}

if (module == require.main) require('test').run(test);
```

当你完成所有操作后，你的存储库文件夹应该看起来像下面这样：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-qk-st-gd/img/94cd891d-3d0f-44a1-87bd-a5b1d51a81cf.png)

现在，让我们将我们的工作推送到 GitHub 存储库。你将使用标准的 git 命令来添加文件，提交文件，然后将文件推送到存储库。以下是我使用的命令：

```
# Initial commit of our application files to the new repo
git add Dockerfile Jenkinsfile main.js package.json test.js
git commit -m "Initial commit"
git push origin master
```

对我来说，情况是这样的：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-qk-st-gd/img/f01fd31d-6e5e-42cd-8382-a8657926144b.png)

现在，我们的应用程序的初始版本已经创建并推送到我们的 GitHub 仓库，我们准备创建 Jenkins 作业来拉取我们的仓库代码，构建我们的应用程序镜像，对其进行测试，然后发布我们应用程序的 Docker 镜像。首先，通过登录到 Jenkins 服务器并单击“新项目”链接来创建一个新的 Jenkins 作业。接下来，在“输入项目名称”输入框中输入要用于作业的名称。我正在使用`dqs-example-app`。选择“流水线”作为我们正在创建的作业类型，然后单击“确定”按钮。

您可以并且可能应该为我们正在创建的构建作业提供有意义的描述。只需将其输入到配置屏幕顶部的“描述：”输入框中。对于我们的示例，我输入了略显简洁的描述“使用来自 SCM 的管道脚本构建 dqs-example-app”。您可能可以做得更好。

我们将设置 Jenkins 作业，每五分钟轮询 GitHub 仓库，以查找主分支的更改。有更好的选项，可以在仓库更改时触发构建作业，而不是定期轮询，但为了简单起见，我们将只使用轮询方法。因此，请滚动到作业配置的“构建触发器”部分，并选中“轮询 SCM”。然后在计划中输入值`H/5 * * * *`：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-qk-st-gd/img/2edd77ba-1fd9-43c2-a54b-c0721a69ebd8.png)

接下来，我们要设置我们的流水线。与以前的示例不同，这次我们将选择“来自 SCM 的管道脚本”选项。我们将为我们的 SCM 选择`Git`，然后输入 GitHub 上我们应用程序仓库的存储库 URL。对于此示例，该 URL 为`https://github.com/EarlWaud/dqs-example-app.git`。确保“要构建的分支”值设置为`*/master`，这是默认值。您的流水线定义应该看起来很像以下内容：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-qk-st-gd/img/c00bff59-f503-4d42-a9b0-5ace6f9aaf57.png)

流水线的另一个关键设置是脚本路径。这是 Jenkins 脚本文件的（路径和）文件名。在我们的情况下，这实际上只是`Jenkinsfile`，因为我们给文件的名称是`Jenkinsfile`，它位于我们仓库的根目录。这是我们示例的输入样子：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-qk-st-gd/img/50c3760a-1450-49fd-9276-ab3def3f10a4.png)

这是目前所需的所有配置。其他一切都已经在我们的源文件中设置好了，它们将从我们的应用程序存储库中拉取。配置所需做的就是点击保存按钮。回到作业页面，我们已经准备好执行我们的第一个构建。在我们的示例中，新创建的作业屏幕看起来像这样：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-qk-st-gd/img/33667e7a-61d6-4fa0-8c47-8deffb2a9522.png)

现在，只需等待。在五分钟或更短的时间内，作业的第一个构建将自动启动，因为我们已经设置了每五分钟轮询存储库。当作业完成后，我们将查看控制台日志，但首先让我们看一下作业完成后的 Jenkins 作业视图（当然是成功的）：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-qk-st-gd/img/2d26df0f-15ab-4df0-908a-45787221ef31.png)

以下是控制台日志输出的编辑视图，供参考（完整的日志输出可以在源代码包中找到）：

```
Started by an SCM change
Started by user Earl Waud
Obtained Jenkinsfile from git https://github.com/EarlWaud/dqs-example-app.git
[Pipeline] node
Running on agent-00042y2g983xq on docker in /home/jenkins/agent/workspace/dqs-example-app
[Pipeline] { (Clone repository)
Cloning repository https://github.com/EarlWaud/dqs-example-app.git
> git init /home/jenkins/agent/workspace/dqs-example-app # timeout=10
[Pipeline] { (Build image)
+ docker build -t jenkins-example-app .
Successfully built b228cd7c0013
Successfully tagged jenkins-example-app:latest
[Pipeline] { (Test image)
+ docker inspect -f . jenkins-example-app
+ npm test
> node test.js
Passed:1 Failed:0 Errors:0
[Pipeline] { (Push image)
+ docker tag jenkins-example-app ubuntu-node01:5000/jenkins-example-app:latest
+ docker push ubuntu-node01:5000/jenkins-example-app:latest
Finished: SUCCESS
```

现在剩下的就是庆祝我们的成功：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-qk-st-gd/img/0d4fb92f-733c-4808-bc8a-904b799a8bd6.png)

说真的，这是创建自己的 Docker 应用程序并使用 Jenkins 构建、测试和发布它们的一个很好的基础。把它看作一个模板，你可以重复使用并构建。现在你已经准备好以任何你想要的方式在 Jenkins 中使用 Docker 了。

# 摘要

好了，我们到了本章的结尾。我希望你阅读本章的乐趣和我写作时一样多。我们有机会运用我们在之前章节学到的许多技能。不仅如此，本章还包含一些非常有用的 Jenkins 知识。以至于你可以认真考虑跳过任何计划中的 Jenkins 培训或书籍阅读，因为你几乎可以在这里找到关于使用 Jenkins 的一切知识。

让我们回顾一下：首先，我们学习了如何设置独立的 Jenkins 服务器。我们很快过渡到将 Jenkins 服务器部署为 Docker 容器。这就是你阅读这本书的目的，对吧？然后我们学会了如何在 Docker 化的 Jenkins 服务器中构建 Docker 镜像。接下来，我们找出了如何用超酷的 Docker 容器替换无聊的 Jenkins 代理，这些容器可以构建我们的 Docker 镜像。你可能会考虑这个以及 Docker 中的 Docker 中的 Docker。你看过电影《盗梦空间》吗？嗯，你刚刚经历了它。最后，在本章的总结中，我们创建了一个示例的 Docker 化应用程序和构建、测试和发布该应用程序镜像的 Jenkins 作业。这是一个示例，你可以将其用作未来创建的真实应用程序的模板和基础。

现在，我们来到了书的结尾。我再说一遍……我希望你阅读这本书和我写这本书一样开心。我也希望你从中学到的和我写这本书一样多。在这些章节中，我们涵盖了大量关于 Docker 的信息。在第一章中，*设置 Docker 化的开发环境*，我们成功搭建了 Docker 工作站，无论你喜欢的操作系统类型是什么。在第二章中，*学习 Docker 命令*，我们学到了几乎所有关于 Docker 命令集的知识。在第三章中，*创建 Docker 镜像*，我们深入研究了`Dockerfile`指令集，并学会了如何创建几乎任何你想构建的 Docker 镜像。第四章，*Docker 卷*，向我们展示了 Docker 卷的强大和实用性。在第五章中，*Docker Swarm*，我们开始运用前几章的几个教训，练习了几乎神奇的 Docker swarm 的功能。然后，在第六章中，*Docker 网络*，我们继续学习 Docker 知识，这次学习了 Docker 如何为我们简化了复杂的网络主题。在第七章中，*Docker 堆栈*，我们看到了更多 Docker 的魔力和力量，当我们了解了 Docker 堆栈。最后，在第八章中，*Docker 和 Jenkins*，我们将所有学到的知识应用起来，利用 Docker 和 Jenkins 为我们准备好创建真实世界的应用程序。

我所能做的就是说声谢谢，并祝愿你在 Docker 之旅中取得成功。
