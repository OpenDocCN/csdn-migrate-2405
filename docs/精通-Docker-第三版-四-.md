# 精通 Docker 第三版（四）

> 原文：[`zh.annas-archive.org/md5/3EE782924E03F9CE768AD8AE784D47E6`](https://zh.annas-archive.org/md5/3EE782924E03F9CE768AD8AE784D47E6)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第十一章：Portainer - Docker 的图形用户界面

在本章中，我们将介绍 Portainer。Portainer 是一个允许您从 Web 界面管理 Docker 资源的工具。将涵盖的主题如下：

+   通往 Portainer 的道路

+   启动和运行 Portainer

+   使用 Portainer 和 Docker Swarm

# 技术要求

与之前的章节一样，我们将继续使用本地的 Docker 安装。此外，本章中的截图将来自我首选的操作系统 macOS。在本章的最后，我们将使用 Docker Machine 和 VirtualBox 启动本地 Docker Swarm 集群。

与之前一样，我们将运行的 Docker 命令将适用于迄今为止安装了 Docker 的三种操作系统，但是一些支持命令可能只适用于基于 macOS 和 Linux 的操作系统。

观看以下视频以查看代码的实际操作：

[`bit.ly/2yWAdQV`](http://bit.ly/2yWAdQV)

# 通往 Portainer 的道路

在我们开始安装和使用 Portainer 之前，我们应该讨论一下项目的背景。本书的第一版涵盖了 Docker UI。Docker UI 是由 Michael Crosby 编写的，大约一年后，他将项目移交给了 Kevan Ahlquist。正是在这个阶段，由于商标问题，该项目被重命名为 UI for Docker。

Docker 的 UI 开发一直持续到 Docker 开始加速引入 Swarm 模式等功能到核心 Docker 引擎。大约在这个时候，UI for Docker 项目被分叉成了将成为 Portainer 的项目，Portainer 在 2016 年 6 月发布了第一个重要版本。

自从首次公开发布以来，Portainer 团队估计大部分代码已经更新或重写，并且到 2017 年中期，已经添加了新功能，例如基于角色的控制和 Docker Compose 支持。

2016 年 12 月，UI for Docker GitHub 存储库提交了一份通知，说明该项目现在已被弃用，应该使用 Portainer。

# 启动和运行 Portainer

我们首先将看看如何使用 Portainer 来管理本地运行的单个 Docker 实例。我正在使用 Docker for Mac，所以我将使用它，但这些说明也适用于其他 Docker 安装：

1.  首先，要从 Docker Hub 获取容器镜像，我们只需要运行以下命令：

```
$ docker image pull portainer/portainer
$ docker image ls
```

1.  如您在运行`docker image ls`命令时所见，Portainer 镜像只有 58.7MB。要启动 Portainer，如果您正在运行 macOS 或 Linux，只需运行以下命令：

```
$ docker container run -d \
 -p 9000:9000 \
 -v /var/run/docker.sock:/var/run/docker.sock \
 portainer/portainer
```

1.  Windows 用户需要运行以下命令：

```
$ docker container run -d -p 9000:9000 -v \\.\pipe\docker_engine:\\.\pipe\docker_engine portainer/portainer
```

如您刚刚运行的命令所示，我们正在挂载 Docker 引擎的套接字文件到我们的 Docker 主机机器上。这样做将允许 Portainer 完全无限制地访问主机上的 Docker 引擎。它需要这样做才能管理主机上的 Docker；但是，这也意味着您的 Portainer 容器可以完全访问您的主机机器，因此在如何授予其访问权限以及在远程主机上公开 Portainer 时要小心。

下面的截图显示了在 macOS 上执行此操作：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/ms-dkr-3e/img/f63b2904-5c6a-44d2-a8ab-b8c16cbc2d7d.png)

1.  对于最基本的安装类型，这就是我们需要运行的全部内容。完成安装还需要进行一些步骤；所有这些步骤都是在浏览器中完成的。要完成这些步骤，请转到[`localhost:9000/`](http://localhost:9000/)。

您将首先看到的屏幕要求您为管理员用户设置密码。

1.  设置密码后，您将被带到登录页面：输入用户名`admin`和刚刚配置的密码。登录后，您将被询问您希望管理的 Docker 实例。有两个选项：

+   管理 Portainer 正在运行的 Docker 实例

+   管理远程 Docker 实例

目前，我们想要管理 Portainer 正在运行的实例，即本地选项，而不是默认的远程选项：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/ms-dkr-3e/img/033eadfb-a669-42ea-adb8-ee1b7dd00bdf.png)

由于我们在启动 Portainer 容器时已经考虑了挂载 Docker 套接字文件，我们可以点击**连接**来完成我们的安装。这将直接带我们进入 Portainer 本身，显示仪表板。

# 使用 Portainer

现在我们已经运行并配置了 Portainer 与我们的 Docker 安装进行通信，我们可以开始逐个使用左侧菜单中列出的功能，从仪表板开始，这也是您的 Portainer 安装的默认登录页面。

# 仪表板

从下面的截图中可以看到，**仪表板**为我们提供了与 Portainer 配置通信的 Docker 实例的当前状态概览：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/ms-dkr-3e/img/1dd6011f-fe9c-43e5-aad4-3d00627cf26e.png)

在我的情况下，这显示了我正在运行的**容器**数量，目前只有已经运行的 Portainer 容器，以及我已经下载的**镜像**数量。我们还可以看到 Docker 实例上可用的**卷**和**网络**的数量，还会显示正在运行的**堆栈**的数量。

它还显示了 Docker 实例本身的基本信息；如您所见，Docker 实例正在运行 Moby Linux，有两个 CPU 和 2GB 的 RAM。这是 Docker for Mac 的默认配置。

**仪表板**将适应您运行 Portainer 的环境，因此当我们查看如何将 Portainer 附加到 Docker Swarm 集群时，我们将重新访问它。

# 应用程序模板

接下来，我们有**应用程序模板**。这部分可能是核心 Docker 引擎中唯一不直接可用的功能；相反，它是使用从 Docker Hub 下载的容器启动常见应用程序的一种方式：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/ms-dkr-3e/img/81d8277b-9f6f-41da-8882-0a5a4061dab4.png)

Portainer 默认提供了大约 25 个模板。这些模板以 JSON 格式定义。例如，nginx 模板如下所示：

```
 {
 "type": "container",
 "title": "Nginx",
 "description": "High performance web server",
 "categories": ["webserver"],
 "platform": "linux",
 "logo": "https://portainer.io/images/logos/nginx.png",
 "image": "nginx:latest",
 "ports": [
 "80/tcp",
 "443/tcp"
 ],
 "volumes": ["/etc/nginx", "/usr/share/nginx/html"]
 }
```

还有更多选项可以添加，例如 MariaDB 模板：

```
 {
 "type": "container",
 "title": "MariaDB",
 "description": "Performance beyond MySQL",
 "categories": ["database"],
 "platform": "linux",
 "logo": "https://portainer.io/images/logos/mariadb.png",
 "image": "mariadb:latest",
 "env": [
 {
 "name": "MYSQL_ROOT_PASSWORD",
 "label": "Root password"
 }
 ],
 "ports": [
 "3306/tcp"
 ],
 "volumes": ["/var/lib/mysql"]
 }
```

如您所见，模板看起来类似于 Docker Compose 文件；但是，这种格式仅由 Portainer 使用。在大多数情况下，选项都相当直观，但我们应该提及**名称**和**标签**选项。

对于通常需要通过环境变量传递自定义值来定义选项的容器，**名称**和**标签**选项允许您向用户呈现自定义表单字段，在启动容器之前需要完成，如下面的截图所示：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/ms-dkr-3e/img/81479591-d561-413e-9abe-d744fe3e71af.png)

如您所见，我们有一个字段，我们可以在其中输入我们想要用于 MariaDB 容器的根密码。填写这个字段将获取该值并将其作为环境变量传递，构建以下命令来启动容器：

```
$ docker container run --name [Name of Container] -p 3306 -e MYSQL_ROOT_PASSWORD=[Root password] -d mariadb:latest
```

有关应用程序模板的更多信息，我建议查阅文档，本章的进一步阅读部分中可以找到链接。

# 容器

接下来我们要查看左侧菜单中的**容器**。这是您启动和与在您的 Docker 实例上运行的容器进行交互的地方。点击**容器**菜单项将显示您的 Docker 实例上所有容器的列表，包括运行和停止的。

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/ms-dkr-3e/img/28f3d88f-f07c-4c7a-8b83-c97cc5a739b5.png)

如您所见，我目前只运行了一个容器，那恰好是 Portainer。与其与之交互，不如点击**+添加容器**按钮来启动一个运行我们在前几章中使用的集群应用程序的容器。

**创建容器**页面上有几个选项；应该填写如下：

+   **名称**：`cluster`

+   **镜像**：`russmckendrick/cluster`

+   **始终拉取镜像**：打开

+   **发布所有暴露的端口**：打开

最后，通过点击**+映射其他端口**，从主机的端口`8080`到容器的端口`80`添加端口映射。您完成的表格应该看起来像以下的屏幕截图：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/ms-dkr-3e/img/994969a3-833f-4080-902b-aa4b924c5ea9.png)

一旦完成，点击**部署容器**，几秒钟后，您将返回正在运行的容器列表，您应该会看到您新启动的容器：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/ms-dkr-3e/img/df751dbc-16d2-4f8b-8dc6-1abba5022868.png)

在列表中每个容器左侧的复选框将启用顶部的按钮，您可以控制容器的状态 - 确保不要**终止**或**删除**Portainer 容器。点击容器的名称，在我们的情况下是**cluster**，将会显示有关容器本身的更多信息：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/ms-dkr-3e/img/cd68e95c-2580-4dfa-ac5e-41af1c5dcf3b.png)

如您所见，有关容器的信息与您运行此命令时获得的信息相同：

```
$ docker container inspect cluster
```

您可以通过点击**检查**来查看此命令的完整输出。您还会注意到有**统计**、**日志**和**控制台**的按钮。

# 统计

**统计**页面显示了容器的 CPU、内存和网络利用率，以及您正在检查的容器的进程列表：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/ms-dkr-3e/img/9e874f94-8dfd-4f46-82d4-b06e9f9ce701.png)

如果您让页面保持打开状态，图表将自动刷新，刷新页面将清零图表并重新开始。这是因为 Portainer 正在使用以下命令从 Docker API 接收此信息：

```
$ docker container stats cluster
```

每次刷新页面时，该命令都会从头开始，因为 Portainer 目前不会在后台轮询 Docker 以记录每个运行容器的统计信息。

# 日志

接下来，我们有**日志**页面。这向您显示运行以下命令的结果：

```
$ docker container logs cluster
```

它显示`STDOUT`和`STDERR`日志：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/ms-dkr-3e/img/85131733-5b8c-45a0-a519-70b57c460ec1.png)

您还可以选择将时间戳添加到输出中；这相当于运行以下命令：

```
$ docker container logs --timestamps cluster
```

# 控制台

最后，我们有**控制台**。这将打开一个 HTML5 终端，允许您登录到正在运行的容器中。在连接到容器之前，您需要选择一个 shell。您可以选择三种 shell 来使用：`/bin/bash`，`/bin/sh`或`/bin/ash`，还可以选择要连接的用户，root 是默认值。虽然集群镜像都安装了这些 shell，我选择使用`/bin/bash`：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/ms-dkr-3e/img/a1a2535d-fb95-4cca-badd-1c84c17f5c45.png)

这相当于运行以下命令以访问您的容器：

```
$ docker container exec -it cluster /bin/sh
```

从屏幕截图中可以看出，`bash`进程的 PID 为`15`。这个进程是由`docker container exec`命令创建的，一旦您从 shell 会话中断开，这将是唯一终止的进程。

# 图像

左侧菜单中的下一个是**图像**。从这里，您可以管理、下载和上传图像：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/ms-dkr-3e/img/e2b3db1c-dcb7-4b2d-949b-84a7d2bdd4c1.png)

在页面顶部，您可以选择拉取图像。例如，只需在框中输入`amazonlinux`，然后点击**拉取**，将从 Docker Hub 下载 Amazon Linux 容器镜像的副本。Portainer 执行的命令将是这样的：

```
$ docker image pull amazonlinux
```

您可以通过单击图像 ID 查找有关每个图像的更多信息；这将带您到一个页面，该页面很好地呈现了运行此命令的输出：

```
$ docker image inspect russmckendrick/cluster
```

看一下以下屏幕截图：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/ms-dkr-3e/img/0e6e4323-5fae-4de1-8c74-47c357492212.png)

您不仅可以获取有关图像的所有信息，还可以选择将图像的副本推送到您选择的注册表，或者默认情况下推送到 Docker Hub。

您还可以完整地分解图像中包含的每个层，显示在构建过程中执行的命令和每个层的大小。

# 网络和卷

菜单中的下两个项目允许您管理网络和卷；我不会在这里详细介绍，因为它们没有太多内容。

# 网络

在这里，您可以快速使用默认的桥接驱动程序添加网络。单击**高级设置**将带您到一个具有更多选项的页面。这些选项包括使用其他驱动程序，定义子网，添加标签以及限制对网络的外部访问。与其他部分一样，您还可以删除网络和检查现有网络。

# 卷

这里除了添加或删除卷之外，没有太多选项。添加卷时，您可以选择驱动程序，并且可以填写要传递给驱动程序的选项，这允许使用第三方驱动程序插件。除此之外，这里没有太多可看的，甚至没有检查选项。

# 事件

事件页面显示了过去 24 小时内的所有事件；您还可以选择过滤结果，这意味着您可以快速找到您需要的信息：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/ms-dkr-3e/img/1f6b826a-dd7c-437a-bd0b-4e03e23c0e74.png)

这相当于运行以下命令：

```
$ docker events --since '2018-09-27T16:30:00' --until '2018-09-28T16:30:00'
```

# 引擎

最后一个条目只是简单地显示以下输出：

```
$ docker info
```

以下显示了命令的输出：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/ms-dkr-3e/img/7322577c-78c1-4836-b290-5f95e5b3e4bd.png)

如果您正在针对多个 Docker 实例端点进行操作，并且需要有关端点正在运行的环境的信息，这可能很有用。

在这一点上，我们将转而查看在 Docker Swarm 上运行的 Portainer，现在是一个很好的时机来删除正在运行的容器，以及在我们首次启动 Portainer 时创建的卷，您可以使用以下命令删除卷：

```
$ docker volume prune
```

# Portainer 和 Docker Swarm

在上一节中，我们看了如何在独立的 Docker 实例上使用 Portainer。Portainer 还支持 Docker Swarm 集群，并且界面中的选项会适应集群环境。我们应该尝试启动一个 Swarm，然后将 Portainer 作为服务启动，看看有什么变化。

# 创建 Swarm

就像在 Docker Swarm 章节中一样，我们将使用 Docker Machine 在本地创建 Swarm；要做到这一点，请运行以下命令：

```
$ docker-machine create -d virtualbox swarm-manager
$ docker-machine create -d virtualbox swarm-worker01
$ docker-machine create -d virtualbox swarm-worker02
```

一旦三个实例启动，运行以下命令初始化 Swarm：

```
$ docker $(docker-machine config swarm-manager) swarm init \
 --advertise-addr $(docker-machine ip swarm-manager):2377 \
 --listen-addr $(docker-machine ip swarm-manager):2377
```

然后运行以下命令，插入您自己的令牌，以添加工作节点：

```
$ SWARM_TOKEN=SWMTKN-1-45acey6bqteiro42ipt3gy6san3kec0f8dh6fb35pnv1xz291v-4l89ei7v6az2b85kb5jnf7nku
$ docker $(docker-machine config swarm-worker01) swarm join \
 --token $SWARM_TOKEN \
 $(docker-machine ip swarm-manager):2377
$ docker $(docker-machine config swarm-worker02) swarm join \
 --token $SWARM_TOKEN \
 $(docker-machine ip swarm-manager):2377
```

现在我们已经形成了我们的集群，运行以下命令将本地 Docker 客户端指向管理节点：

```
$ eval $(docker-machine env swarm-manager)
```

最后，使用以下命令检查 Swarm 的状态：

```
$ docker node ls
```

# Portainer 服务

现在我们有一个 Docker Swarm 集群，并且我们的本地客户端已配置为与管理节点通信，我们可以通过简单运行以下命令来启动 Portainer 服务：

```
$ docker service create \
 --name portainer \
 --publish 9000:9000 \
 --constraint 'node.role == manager' \
 --mount type=bind,src=/var/run/docker.sock,dst=/var/run/docker.sock \
 portainer/portainer \
 -H unix:///var/run/docker.sock
```

如您所见，这将在管理节点上启动 Portainer 作为服务，并使服务挂载管理节点的套接字文件，以便它能够看到 Swarm 的其余部分。您可以使用以下命令检查服务是否已启动而没有任何错误：

```
$ docker service ls 
$ docker service inspect portainer --pretty
```

以下显示了输出：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/ms-dkr-3e/img/53d7a673-1fe4-482c-9525-50f925aaf3c4.png)

现在服务已启动，您可以在集群中任何节点的 IP 地址上的端口`9000`上访问 Portainer，或者运行以下命令：

```
$ open http://$(docker-machine ip swarm-manager):9000
```

当页面打开时，您将再次被要求为管理员用户设置密码；设置后，您将看到登录提示。登录后，您将直接进入仪表板。这是因为这次我们启动 Portainer 时，传递了参数`-H unix:///var/run/docker.sock`，这告诉 Portainer 选择我们在单主机上启动 Portainer 时手动选择的选项。 

# Swarm 差异

如前所述，当连接到 Docker Swarm 集群时，Portainer 界面会有一些变化。在本节中，我们将对它们进行介绍。如果界面的某个部分没有提到，则在单主机模式下运行 Portainer 时没有区别。

# 端点

当您登录时，首先要做的是选择一个端点，如下屏幕所示，有一个称为**primary**的端点：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/ms-dkr-3e/img/f73d75d1-6f79-4794-a20e-6bebdce83c3b.png)

点击端点将带您到**仪表板**，我们将在本节末再次查看**端点**。

# 仪表板和 Swarm

您将注意到的第一个变化是仪表板现在显示有关 Swarm 集群的信息，例如：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/ms-dkr-3e/img/fd4d1e74-0ad4-4dbf-a2c3-5a34b91ee1bf.png)

请注意，CPU 显示为 3，总 RAM 为 3.1 GB，集群中的每个节点都有 1 GB 的 RAM 和 1 个 CPU，因此这些值是集群的总计。

点击**转到集群可视化器**将带您到 Swam 页面，这给您提供了集群的视觉概述，目前唯一运行的服务是 Portainer：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/ms-dkr-3e/img/a13868d7-88bf-40ae-9c9c-b01ba405b27d.png)

# 堆栈

我们在左侧菜单中没有涵盖的一项是**堆栈**，从这里，您可以像我们在查看 Docker Swarm 时那样启动堆栈。实际上，让我们使用我们之前使用的 Docker Compose 文件，它看起来像下面这样：

```
version: "3"

services:
   redis:
     image: redis:alpine
     volumes:
       - redis_data:/data
     restart: always
   mobycounter:
     depends_on:
       - redis
     image: russmckendrick/moby-counter
     ports:
       - "8080:80"
     restart: always

volumes:
    redis_data:
```

单击**+添加堆栈**按钮，然后将上面的内容粘贴到 Web 编辑器中，输入名称为`MobyCounter`，名称中不要添加任何空格或特殊字符，因为 Docker 会使用该名称，然后单击**部署堆栈**。

部署后，您将能够单击**MobyCounter**并管理堆栈：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/ms-dkr-3e/img/f6b6017d-3a92-44d3-8c19-2720e6115860.png)

堆栈是服务的集合，让我们接着看看它们。

# 服务

这个页面是您可以创建和管理服务的地方；它应该已经显示了包括 Portainer 在内的几个服务。为了不与正在运行的 Portainer 容器造成任何问题，我们将创建一个新的服务。要做到这一点，单击**+添加服务**按钮。在加载的页面上，输入以下内容：

+   **名称**：`cluster`

+   图像：`russmckendrick/cluster`

+   **调度模式**：**复制**

+   **副本**：**1**

这一次，我们需要为主机上的端口`8000`添加端口映射，映射到容器上的端口`80`，这是因为我们在上一节中启动的堆栈已经在主机上使用端口`8080`：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/ms-dkr-3e/img/098c7993-08e7-4248-94de-46effda21158.png)

输入信息后，单击**创建服务**按钮。您将被带回服务列表，其中现在应该包含我们刚刚添加的 cluster 服务。您可能已经注意到，在调度模式列中，有一个选项可以进行扩展。单击它，并将**cluster**服务的副本数增加到**6**。

单击**名称**列中的**cluster**将带我们到服务的概述。正如您所看到的，服务上有很多信息：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/ms-dkr-3e/img/a9e27419-518a-475d-ba8b-0e4204160578.png)

您可以在**服务**上进行许多实时更改，包括放置约束、重启策略、添加服务标签等。页面底部是与服务相关的任务列表：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/ms-dkr-3e/img/e5341775-3d05-45d8-8f58-9cf92908c2fc.png)

正如您所看到的，我们有六个正在运行的任务，每个节点上有两个。单击左侧菜单中的**容器**可能会显示与您预期不同的内容：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/ms-dkr-3e/img/d60f20dd-8806-4bfd-bc7a-fa44f6973644.png)

只列出了三个容器，其中一个是 Portainer 服务。为什么会这样？

好吧，如果您还记得 Docker Swarm 章节中，我们学到`docker container`命令只适用于您针对其运行的节点，并且由于 Portainer 只与我们的管理节点通信，因此 Docker 容器命令只针对该节点执行。请记住，Portainer 只是 Docker API 的 Web 界面，因此它反映了在命令行上运行`docker container ls`时获得的相同结果。

# 添加终端

但是，我们可以将我们的另外两个集群节点添加到 Portainer 中。要做到这一点，请点击左侧菜单中的**终端**条目。

要添加终端，我们需要知道终端 URL 并访问证书，以便 Portainer 可以对其自身进行身份验证，以针对节点上运行的 Docker 守护程序。幸运的是，由于我们使用 Docker Machine 启动了主机，这是一项简单的任务。要获取终端 URL，请运行以下命令： 

```
$ docker-machine ls
```

对我来说，两个终端 URL 分别是`192.168.99.101:2376`和`192.168.99.102:2376`；您的可能不同。我们需要上传的证书可以在您的机器上的`~/.docker/machine/certs/`文件夹中找到。我建议运行以下命令来在您的查找器中打开文件夹：

```
$ cd ~/.docker/machine/certs/
$ open .
```

添加节点后，您将能够使用**设置/终端**页面中的**+添加终端**按钮切换到该节点。

从这里输入以下信息：

+   **名称**：`swarm-worker01`

+   **终端 URL**：`192.168.99.101:2376`

+   **公共 IP：** `192.168.99.101`

+   **TLS**：打开

+   **带服务器和客户端验证的 TLS**：已选中

+   从`~/.docker/machine/certs/`上传证书

然后点击**+添加终端**按钮，点击**主页**将带您到我们在本章节开始时首次看到的终端概述屏幕。

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/ms-dkr-3e/img/e367b2ca-bca4-4833-82c5-22682805ecce.png)

您还会注意到除了在终端中提到 Swarm 之外，没有提到 Swarm 服务。同样，这是因为 Portainer 只知道与您的 Docker 节点一样多，Swarm 模式只允许具有管理器角色的节点启动服务和任务，并与集群中的其他节点进行交互。

不要忘记通过运行以下命令来删除您的本地 Docker Swarm 集群：

```
$ docker-machine rm swarm-manager swarm-worker01 swarm-worker02
```

# 总结

我们的深入探讨到此结束。正如你所看到的，Portainer 非常强大，但使用起来简单，随着功能的发布，它将继续增长并集成更多的 Docker 生态系统。使用 Portainer，你不仅可以对主机进行大量操作，还可以对单个或集群主机上运行的容器和服务进行操作。

在下一章中，我们将看看如何保护您的 Docker 主机以及如何对容器映像运行扫描。

# 问题

1.  在 macOS 或 Linux 机器上，挂载 Docker 套接字文件的路径是什么？

1.  Portainer 运行的默认端口是多少？

1.  真或假：您可以使用 Docker Compose 文件作为应用程序模板？

1.  真或假：Portainer 中显示的统计数据只是实时的，无法查看历史数据？

# 进一步阅读

你可以在这里找到更多关于 Portainer 的信息：

+   主要网站: [`portainer.io/`](https://portainer.io/)

+   Portainter on GitHub: [`github.com/portainer/`](https://github.com/portainer/)

+   最新文档: [`portainer.readthedocs.io/en/latest/index.html`](https://portainer.readthedocs.io/en/latest/index.html)

+   模板文档: [`portainer.readthedocs.io/en/latest/templates.html`](https://portainer.readthedocs.io/en/latest/templates.html)


# 第十二章：Docker 安全

在本章中，我们将看一下 Docker 安全，这是当今所有人都关注的话题。我们将把本章分成以下五个部分：

+   容器考虑

+   Docker 命令

+   最佳实践

+   Docker Bench Security 应用程序

+   第三方安全服务

# 技术要求

在本章中，我们将在桌面上使用 Docker，并使用 Docker Machine 在云中启动 Docker 主机。与之前的章节一样，我将使用我偏好的操作系统，即 macOS。与之前一样，我们将运行的 Docker 命令将适用于迄今为止我们安装 Docker 的三种操作系统。然而，一些支持命令可能只适用于基于 macOS 和 Linux 的操作系统，而且数量很少。

查看以下视频以查看代码的实际操作：

[`bit.ly/2AnEv5G`](http://bit.ly/2AnEv5G)

# 容器考虑

当 Docker 首次发布时，有很多关于 Docker 与虚拟机的讨论。我记得在杂志上读到的文章，评论 Reddit 上的帖子，以及读了无数的博客文章。在 Docker 的 alpha 和 beta 版本的早期，人们习惯将 Docker 容器视为虚拟机，因为当时没有其他参考点，我们将它们视为微型虚拟机。

过去，我会启用 SSH，在容器中运行多个进程，甚至通过启动容器并运行安装软件堆栈的命令来创建我的容器映像。这是我们在第二章《构建容器映像》中讨论过的内容；你绝对不应该这样做，因为这被认为是一种不良实践。

因此，与其讨论容器与虚拟机的区别，不如看看在运行容器而不是虚拟机时需要考虑的一些因素。

# 优势

当您启动 Docker 容器时，Docker 引擎在幕后进行了大量工作。在启动容器时，Docker 引擎执行的任务之一是设置命名空间和控制组。这是什么意思？通过设置命名空间，Docker 将每个容器中的进程隔离 - 不仅与其他容器隔离，而且与主机系统隔离。控制组确保每个容器获得自己的 CPU、内存和磁盘 I/O 等资源份额。更重要的是，它们确保一个容器不会耗尽给定 Docker 主机上的所有资源。

正如您在前几章中看到的，能够将容器启动到 Docker 控制的网络中意味着您可以在应用程序级别隔离您的容器；应用程序 A 的所有容器在网络层面上都无法访问应用程序 B 的容器。

此外，这种网络隔离可以在单个 Docker 主机上运行，使用默认的网络驱动程序，或者可以通过使用 Docker Swarm 的内置多主机网络驱动程序，或者 Weave 的 Weave Net 驱动程序跨多个 Docker 主机。

最后，我认为 Docker 相对于典型虚拟机的最大优势之一是您不应该需要登录到容器中。 Docker 正在尽最大努力让您不需要登录到容器中来管理它正在运行的进程。通过诸如`docker container exec`、`docker container top`、`docker container logs`和`docker container stats`之类的命令，您可以做任何需要做的事情，而无需暴露更多的服务。

# 您的 Docker 主机

当您处理虚拟机时，您可以控制谁可以访问哪个虚拟机。假设您只希望开发人员 User 1 访问开发虚拟机。然而，User 2 是负责开发和生产环境的运营商，因此他需要访问所有虚拟机。大多数虚拟机管理工具允许您为虚拟机授予基于角色的访问权限。

使用 Docker 时，您有一点劣势，因为无论是通过被授予 sudo 访问权限还是通过将其用户添加到 Docker Linux 组，只要有人可以访问您的 Docker 主机上的 Docker 引擎，他们就可以访问您运行的每个 Docker 容器。他们可以运行新的容器，停止现有的容器，也可以删除镜像。小心授予谁访问您主机上的 Docker 引擎的权限。他们基本上掌握了您所有容器的王国之钥。鉴于此，建议仅将 Docker 主机用于 Docker；将其他服务与您的 Docker 主机分开。

# 镜像信任

如果您正在运行虚拟机，您很可能会自己设置它们，从头开始。由于下载的大小（以及启动的工作量），您可能不会下载某个随机人在互联网上创建的预构建机器镜像。通常情况下，如果您这样做，那将是来自受信任软件供应商的预构建虚拟设备。

因此，您将了解虚拟机内部的内容和不了解的内容，因为您负责构建和维护它。

Docker 吸引人的部分原因是其易用性；然而，这种易用性可能会让您很容易忽视一个非常关键的安全考虑：您知道容器内部在运行什么吗？

我们已经在早期章节中提到了**镜像信任**。例如，我们谈到了不要发布或下载未使用 Dockerfile 定义的镜像，也不要直接将自定义代码或秘密信息等嵌入到您将要推送到 Docker Hub 的镜像中。

容器虽然有命名空间、控制组和网络隔离的保护，但我们讨论了一个错误判断的镜像下载可能会引入安全问题和风险到您的环境中。例如，一个完全合法的容器运行一个未打补丁的软件可能会给您的应用程序和数据的可用性带来风险。

# Docker 命令

让我们来看看 Docker 命令，可以用来加强安全性，以及查看您可能正在使用的镜像的信息。

我们将专注于两个命令。第一个将是`docker container run`命令，这样你就可以看到一些你可以利用这个命令的项目。其次，我们将看一下`docker container diff`命令，你可以用它来查看你计划使用的镜像做了什么。

# run 命令

关于`docker run`命令，我们主要关注的是允许你将容器内的所有内容设置为只读的选项，而不是指定目录或卷。这有助于限制恶意应用程序可能造成的损害，它们也可能通过更新其二进制文件来劫持一个易受攻击的应用程序。

让我们来看看如何启动一个只读容器，然后分解它的功能，如下所示：

```
$ docker container run -d --name mysql --read-only -v /var/lib/mysql -v /tmp -v /var/run/mysqld -e MYSQL_ROOT_PASSWORD=password mysql
```

在这里，我们正在运行一个 MySQL 容器，并将整个容器设置为只读，除了以下文件夹：

+   `/var/lib/mysql`

+   `/var/run/mysqld`

+   `/tmp`

这些将被创建为三个单独的卷，然后挂载为读/写。如果你不添加这些卷，那么 MySQL 将无法启动，因为它需要读/写访问权限才能在`/var/run/mysqld`中创建套接字文件，在`/tmp`中创建一些临时文件，最后，在`/var/lib/mysql`中创建数据库本身。

容器内的任何其他位置都不允许你在其中写任何东西。如果你尝试运行以下命令，它将失败：

```
$ docker container exec mysql touch /trying_to_write_a_file
```

前面的命令将给你以下消息：

```
touch: cannot touch '/trying_to_write_a_file': Read-only file system
```

如果你想控制容器可以写入的位置（或者不能写入的位置），这可能非常有帮助。一定要明智地使用它。进行彻底测试，因为当应用程序无法写入某些位置时可能会产生后果。

类似于前一个命令`docker container run`，我们将所有内容设置为只读（除了指定的卷），我们可以做相反的操作，只设置一个卷（或者如果你使用更多的`-v`开关，则设置更多卷）为只读。关于卷的一点要记住的是，当你使用一个卷并将其挂载到容器中时，它将作为空卷挂载到容器内的目录上，除非你使用`--volumes-from`开关或在启动后以其他方式向容器添加数据：

```
$ docker container run -d -v /local/path/to/html/:/var/www/html/:ro nginx
```

这将把 Docker 主机上的`/local/path/to/html/`挂载到`/var/www/html/`，并将其设置为只读。如果您不希望运行的容器写入卷，以保持数据或配置文件的完整性，这可能会很有用。

# diff 命令

让我们再看一下`docker diff`命令；由于它涉及容器的安全方面，您可能希望使用托管在 Docker Hub 或其他相关存储库上的镜像。

请记住，谁拥有对您的 Docker 主机和 Docker 守护程序的访问权限，谁就可以访问您所有正在运行的 Docker 容器。也就是说，如果您没有监控，某人可能会对您的容器执行命令并进行恶意操作。

让我们看看我们在上一节中启动的 MySQL 容器：

```
$ docker container diff mysql
```

您会注意到没有返回任何文件。为什么呢？

嗯，`diff`命令告诉您自容器启动以来对镜像所做的更改。在上一节中，我们使用只读镜像启动了 MySQL 容器，然后挂载了卷到 MySQL 需要读写的位置——这意味着我们下载的镜像和正在运行的容器之间没有文件差异。

停止并删除 MySQL 容器，然后运行以下命令清理卷：

```
$ docker container stop mysql
$ docker container rm mysql
$ docker volume prune
```

然后，再次启动相同的容器，去掉只读标志和卷；这会给我们带来不同的情况，如下所示：

```
$ docker container run -d --name mysql -e MYSQL_ROOT_PASSWORD=password mysql
$ docker container exec mysql touch /trying_to_write_a_file
$ docker container diff mysql
```

正如您所看到的，创建了两个文件夹并添加了几个文件：

```
A /trying_to_write_a_file
C /run
C /run/mysqld
A /run/mysqld/mysqld.pid
A /run/mysqld/mysqld.sock
A /run/mysqld/mysqld.sock.lock
A /run/mysqld/mysqlx.sock
A /run/mysqld/mysqlx.sock.lock
```

这是发现容器内可能发生的任何不当或意外情况的好方法。

# 最佳实践

在本节中，我们将研究在使用 Docker 时的最佳实践，以及*互联网安全中心*指南，以正确地保护 Docker 环境的所有方面。

# Docker 最佳实践

在我们深入研究互联网安全中心指南之前，让我们回顾一下使用 Docker 的一些最佳实践，如下所示：

+   **每个容器一个应用程序**：将您的应用程序分散到每个容器中。Docker 就是为此而构建的，这样做会让一切变得更容易。我们之前讨论的隔离就是关键所在。

+   **只安装所需内容**：正如我们在之前的章节中所介绍的，只在容器镜像中安装所需的内容。如果必须安装更多内容来支持容器应该运行的一个进程，我建议你审查原因。这不仅使你的镜像小而且便携，还减少了潜在的攻击面。

+   **审查谁可以访问你的 Docker 主机**：请记住，拥有 Docker 主机的 root 或 sudo 访问权限的人可以访问和操作主机上的所有镜像和容器。

+   **使用最新版本**：始终使用最新版本的 Docker。这将确保所有安全漏洞都已修补，并且你拥有最新的功能。在修复安全问题的同时，使用社区版本保持最新可能会引入由功能或新特性变化引起的问题。如果这对你是一个问题，那么你可能需要查看 Docker 提供的 LTS 企业版本，以及 Red Hat。

+   利用资源：如果需要帮助，请利用可用的资源。Docker 社区庞大而乐于助人。在规划 Docker 环境和评估平台时，利用他们的网站、文档和 Slack 聊天室会对你有所帮助。有关如何访问 Slack 和社区其他部分的更多信息，请参阅《第十四章》，《Docker 的下一步》。

# 互联网安全中心基准

**互联网安全中心（CIS）**是一个独立的非营利组织，其目标是提供安全的在线体验。他们发布的基准和控制被认为是 IT 各个方面的最佳实践。

Docker 的 CIS 基准可免费下载。你应该注意，它目前是一个 230 页的 PDF，根据知识共享许可发布，涵盖了 Docker CE 17.06 及更高版本。

当你实际运行扫描（在本章的下一部分）并获得需要修复的结果时，你将参考本指南。该指南分为以下几个部分：

+   主机配置

+   Docker 守护程序配置

+   Docker 守护程序配置文件

+   容器镜像/运行时

+   Docker 安全操作

# 主机配置

本指南的这一部分涵盖了您的 Docker 主机的配置。这是 Docker 环境中所有容器运行的部分。因此，保持其安全性至关重要。这是对抗攻击者的第一道防线。

# Docker 守护程序配置

本指南的这一部分包含了保护正在运行的 Docker 守护程序的建议。您对 Docker 守护程序配置所做的每一项更改都会影响每个容器。这些是您可以附加到 Docker 守护程序的开关，我们之前看到的，以及下一节中我们运行工具时将看到的项目。

# Docker 守护程序配置文件

本指南的这一部分涉及 Docker 守护程序使用的文件和目录。这涵盖了从权限到所有权的各种方面。有时，这些区域可能包含您不希望他人知道的信息，这些信息可能以纯文本格式存在。

# 容器图像/运行时和构建文件

本指南的这一部分包含了保护容器图像和构建文件的信息。

第一部分包含图像、封面基础图像和使用的构建文件。正如我们之前所讨论的，您需要确保您使用的图像，不仅仅是基础图像，还包括 Docker 体验的任何方面。本指南的这一部分涵盖了在创建自己的基础图像时应遵循的条款。

# 容器运行时

这一部分以前是后面的一部分，但现在已经移动到 CIS 指南的自己的部分。容器运行时涵盖了许多与安全相关的项目。

小心使用运行时变量。在某些情况下，攻击者可以利用它们，而您可能认为您正在利用它们。在您的容器中暴露太多，例如将应用程序秘密和数据库连接暴露为环境变量，不仅会危及您的容器的安全性，还会危及 Docker 主机和在该主机上运行的其他容器的安全性。

# Docker 安全操作

本指南的这一部分涵盖了涉及部署的安全领域；这些项目与 Docker 最佳实践更紧密相关。因此，最好遵循这些建议。

# Docker 基准安全应用程序

在本节中，我们将介绍您可以安装和运行的 Docker 基准安全应用程序。该工具将检查以下内容：

+   主机配置

+   Docker 守护程序配置

+   Docker 守护程序配置文件

+   容器镜像和构建文件

+   容器运行时

+   Docker 安全操作

+   Docker Swarm 配置

看起来熟悉吗？应该是的，因为这些是我们在上一节中审查过的相同项目，只是构建成一个应用程序，它将为您做很多繁重的工作。它将向您显示配置中出现的警告，并提供有关其他配置项的信息，甚至通过了测试的项目。

现在，我们将看一下如何运行该工具，一个实时示例，以及该过程的输出意味着什么。

# 在 Docker for macOS 和 Docker for Windows 上运行该工具

运行该工具很简单。它已经被打包到一个 Docker 容器中。虽然您可以获取源代码并自定义输出或以某种方式操纵它（比如，通过电子邮件输出），但默认情况可能是您所需要的。

该工具的 GitHub 项目可以在[`github.com/docker/docker-bench-security/`](https://github.com/docker/docker-bench-security/)找到，要在 macOS 或 Windows 机器上运行该工具，您只需将以下内容复制并粘贴到您的终端中。以下命令缺少检查`systemd`所需的行，因为作为 Docker for macOS 和 Docker for Windows 的基础操作系统的 Moby Linux 不运行`systemd`。我们将很快看一下基于`systemd`的系统：

```
$ docker run -it --net host --pid host --cap-add audit_control \
 -e DOCKER_CONTENT_TRUST=$DOCKER_CONTENT_TRUST \
 -v /var/lib:/var/lib \
 -v /var/run/docker.sock:/var/run/docker.sock \
 -v /etc:/etc --label docker_bench_security \
 docker/docker-bench-security
```

一旦镜像被下载，它将启动并立即开始审核您的 Docker 主机，打印结果，如下面的屏幕截图所示：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/ms-dkr-3e/img/6fa485b2-d0d5-45fe-ba81-74a1a26e9697.png)

如您所见，有一些警告（`[WARN]`），以及注释（`[NOTE]`）和信息（`[INFO]`）；但是，由于这个主机是由 Docker 管理的，正如您所期望的那样，没有太多需要担心的。

# 在 Ubuntu Linux 上运行

在我们更详细地查看审核输出之前，我将在 DigitalOcean 上启动一个原始的 Ubuntu 16.04.5 LTS 服务器，并使用 Docker Machine 进行干净的 Docker 安装，如下所示：

```
$ DOTOKEN=0cb54091fecfe743920d0e6d28a29fe325b9fc3f2f6fccba80ef4b26d41c7224
$ docker-machine create \
 --driver digitalocean \
 --digitalocean-access-token $DOTOKEN \
 docker-digitalocean
```

安装完成后，我将启动一些容器，所有这些容器都没有非常合理的设置。我将从 Docker Hub 启动以下两个容器：

```
$ docker container run -d --name root-nginx -v /:/mnt nginx
$ docker container run -d --name priv-nginx --privileged=true nginx
```

然后，我将基于 Ubuntu 16.04 构建一个自定义镜像，运行 SSH，使用以下`Dockerfile`：

```
FROM ubuntu:16.04

RUN apt-get update && apt-get install -y openssh-server
RUN mkdir /var/run/sshd
RUN echo 'root:screencast' | chpasswd
RUN sed -i 's/PermitRootLogin prohibit-password/PermitRootLogin yes/' /etc/ssh/sshd_config
RUN sed 's@session\s*required\s*pam_loginuid.so@session optional pam_loginuid.so@g' -i /etc/pam.d/sshd
ENV NOTVISIBLE "in users profile"
RUN echo "export VISIBLE=now" >> /etc/profile
EXPOSE 22
CMD ["/usr/sbin/sshd", "-D"]
```

我将使用以下代码构建和启动它：

```
$ docker image build --tag sshd .
$ docker container run -d -P --name sshd sshd
```

正如您所看到的，在一个图像中，我们正在使用`root-nginx`容器以完全读/写访问权限挂载我们主机的根文件系统。我们还在`priv-nginx`中以扩展特权运行，并最后在`sshd`中运行 SSH。

要在我们的 Ubuntu Docker 主机上开始审计，我运行了以下命令：

```
$ docker run -it --net host --pid host --cap-add audit_control \
 -e DOCKER_CONTENT_TRUST=$DOCKER_CONTENT_TRUST \
 -v /var/lib:/var/lib \
 -v /var/run/docker.sock:/var/run/docker.sock \
 -v /usr/lib/systemd:/usr/lib/systemd \
 -v /etc:/etc --label docker_bench_security \
 docker/docker-bench-security
```

由于我们正在运行支持`systemd`的操作系统，我们正在挂载`/usr/lib/systemd`，以便我们可以对其进行审计。

有很多输出和很多需要消化的内容，但这一切意味着什么呢？让我们来看看并分解每个部分。

# 理解输出

我们将看到三种类型的输出，如下所示：

+   **`[PASS]`**：这些项目是可靠的并且可以正常运行。它们不需要任何关注，但是很好阅读，让您感到内心温暖。这些越多，越好！

+   `[WARN]`：这些是需要修复的项目。这些是我们不想看到的项目。

+   `[INFO]`：这些是您应该审查并修复的项目，如果您认为它们与您的设置和安全需求相关。

+   `[NOTE]`：这些提供最佳实践建议。

如前所述，审计中涵盖了七个主要部分，如下所示：

+   主机配置

+   Docker 守护程序配置

+   Docker 守护程序配置文件

+   容器镜像和构建文件

+   容器运行时

+   Docker 安全操作

+   Docker Swarm 配置

让我们看看我们在扫描的每个部分中看到了什么。这些扫描结果来自默认的 Ubuntu Docker 主机，在此时没有对系统进行任何调整。我们想专注于每个部分中的`[WARN]`项目。当您运行您自己的扫描时，可能会出现其他警告，但这些将是大多数人（如果不是所有人）首先遇到的警告。

# 主机配置

我的主机配置有五个带有`[WARN]`状态的项目，如下所示：

```
[WARN] 1.1 - Ensure a separate partition for containers has been created
```

默认情况下，Docker 在主机机器上使用`/var/lib/docker`来存储所有文件，包括默认驱动程序创建的所有镜像、容器和卷。这意味着这个文件夹可能会迅速增长。由于我的主机机器正在运行单个分区（并且取决于您的容器在做什么），这可能会填满整个驱动器，这将使我的主机机器无法使用：

```
[WARN] 1.5 - Ensure auditing is configured for the Docker daemon
[WARN] 1.6 - Ensure auditing is configured for Docker files and directories - /var/lib/docker
[WARN] 1.7 - Ensure auditing is configured for Docker files and directories - /etc/docker
[WARN] 1.10 - Ensure auditing is configured for Docker files and directories - /etc/default/docker
```

这些警告之所以被标记，是因为未安装`auditd`，并且没有 Docker 守护程序和相关文件的审计规则；有关`auditd`的更多信息，请参阅博客文章[`www.linux.com/learn/customized-file-monitoring-auditd/`](https://www.linux.com/learn/customized-file-monitoring-auditd/)。

# Docker 守护程序配置

我的 Docker 守护程序配置标记了八个`[WARN]`状态，如下所示：

```
[WARN] 2.1 - Ensure network traffic is restricted between containers on the default bridge
```

默认情况下，Docker 允许在同一主机上的容器之间无限制地传递流量。可以更改此行为；有关 Docker 网络的更多信息，请参阅[`docs.docker.com/engine/userguide/networking/`](https://docs.docker.com/engine/userguide/networking/)。

```
[WARN] 2.5 - Ensure aufs storage driver is not used
```

在 Docker 的早期，AUFS 被广泛使用；然而，现在不再被认为是最佳实践，因为它可能导致主机机器的内核出现问题：

```
[WARN] 2.8 - Enable user namespace support
```

默认情况下，用户命名空间不会被重新映射。尽管可以映射它们，但目前可能会导致几个 Docker 功能出现问题；有关已知限制的更多详细信息，请参阅[`docs.docker.com/engine/reference/commandline/dockerd/`](https://docs.docker.com/engine/reference/commandline/dockerd/)：

```
[WARN] 2.11 - Ensure that authorization for Docker client commands is enabled
```

Docker 的默认安装允许对 Docker 守护程序进行不受限制的访问；您可以通过启用授权插件来限制对经过身份验证的用户的访问。有关更多详细信息，请参阅[`docs.docker.com/engine/extend/plugins_authorization/`](https://docs.docker.com/engine/extend/plugins_authorization/)：

```
[WARN] 2.12 - Ensure centralized and remote logging is configured
```

由于我只运行单个主机，我没有使用诸如`rsyslog`之类的服务将我的 Docker 主机日志发送到中央服务器，也没有在我的 Docker 守护程序上配置日志驱动程序；有关更多详细信息，请参阅[`docs.docker.com/engine/admin/logging/overview/`](https://docs.docker.com/engine/admin/logging/overview/)：

```
[WARN] 2.14 - Ensure live restore is Enabled
```

`--live-restore`标志在 Docker 中启用了对无守护程序容器的全面支持；这意味着，与其在守护程序关闭时停止容器，它们会继续运行，并在重新启动时正确重新连接到容器。由于向后兼容性问题，默认情况下未启用；有关更多详细信息，请参阅[`docs.docker.com/engine/admin/live-restore/`](https://docs.docker.com/engine/admin/live-restore/)：

```
[WARN] 2.15 - Ensure Userland Proxy is Disabled
```

您的容器可以通过两种方式路由到外部世界：使用 hairpin NAT 或用户态代理。对于大多数安装来说，hairpin NAT 模式是首选模式，因为它利用了 iptables 并具有更好的性能。在这种模式不可用的情况下，Docker 使用用户态代理。大多数现代操作系统上的 Docker 安装都将支持 hairpin NAT；有关如何禁用用户态代理的详细信息，请参阅[`docs.docker.com/engine/userguide/networking/default_network/binding/`](https://docs.docker.com/engine/userguide/networking/default_network/binding/)：

```
[WARN] 2.18 - Ensure containers are restricted from acquiring new privileges
```

这样可以防止容器内的进程通过设置 suid 或 sgid 位获得任何额外的特权；这可以限制任何试图访问特权二进制文件的危险操作的影响。

# Docker 守护程序配置文件

在这一部分中，我没有`[WARN]`状态，这是可以预料的，因为 Docker 是使用 Docker Machine 部署的。

# 容器映像和构建文件

我在容器映像和构建文件中有三个`[WARN]`状态；您可能会注意到多行警告在状态之后加上了`*`：

```
[WARN] 4.1 - Ensure a user for the container has been created
[WARN]     * Running as root: sshd
[WARN]     * Running as root: priv-nginx
[WARN]     * Running as root: root-nginx
```

我正在运行的容器中的进程都以 root 用户身份运行；这是大多数容器的默认操作。有关更多信息，请参阅[`docs.docker.com/engine/security/security/`](https://docs.docker.com/engine/security/security/)：

```
[WARN] 4.5 - Ensure Content trust for Docker is Enabled
```

为 Docker 启用内容信任可以确保您拉取的容器映像的来源，因为在推送它们时它们是数字签名的；这意味着您始终运行您打算运行的映像。有关内容信任的更多信息，请参阅[`docs.docker.com/engine/security/trust/content_trust/`](https://docs.docker.com/engine/security/trust/content_trust/)：

```
[WARN] 4.6 - Ensure HEALTHCHECK instructions have been added to the container image
[WARN]     * No Healthcheck found: [sshd:latest]
[WARN]     * No Healthcheck found: [nginx:latest]
[WARN]     * No Healthcheck found: [ubuntu:16.04]
```

构建图像时，可以构建`HEALTHCHECK`；这可以确保当容器从您的图像启动时，Docker 会定期检查容器的状态，并在需要时重新启动或重新启动它。更多详细信息可以在[`docs.docker.com/engine/reference/builder/#healthcheck`](https://docs.docker.com/engine/reference/builder/#healthcheck)找到。

# 容器运行时

由于我们在审核的 Docker 主机上启动容器时有点愚蠢，我们知道这里会有很多漏洞，总共有 11 个：

```
[WARN] 5.2 - Ensure SELinux security options are set, if applicable
[WARN]     * No SecurityOptions Found: sshd
[WARN]     * No SecurityOptions Found: root-nginx
```

前面的漏洞是一个误报；我们没有运行 SELinux，因为它是一个 Ubuntu 机器，SELinux 只适用于基于 Red Hat 的机器；相反，`5.1`向我们展示了结果，这是一个`[PASS]`，这是我们想要的：

```
[PASS] 5.1  - Ensure AppArmor Profile is Enabled
```

接下来的两个`[WARN]`状态是我们自己制造的，如下所示：

```
[WARN] 5.4 - Ensure privileged containers are not used
[WARN]     * Container running in Privileged mode: priv-nginx
```

以下也是我们自己制造的：

```
[WARN] 5.6 - Ensure ssh is not run within containers
[WARN]     * Container running sshd: sshd
```

这些可以安全地忽略；你很少会需要启动以`Privileged mode`运行的容器。只有当你的容器需要与运行在 Docker 主机上的 Docker 引擎交互时才需要；例如，当你运行一个 GUI（如 Portainer）时，我们在第十一章*, Portainer - A GUI for Docker*中介绍过。

我们还讨论过你不应该在容器中运行 SSH；有一些用例，比如在某个网络中运行跳板主机；然而，这些应该是例外情况。

接下来的两个`[WARN]`状态被标记，因为在 Docker 上，默认情况下，所有在 Docker 主机上运行的容器共享资源；为你的容器设置内存和 CPU 优先级的限制将确保你希望具有更高优先级的容器不会被优先级较低的容器耗尽资源：

```
[WARN] 5.10 - Ensure memory usage for container is limited
[WARN]      * Container running without memory restrictions: sshd
[WARN]      * Container running without memory restrictions: priv-nginx
[WARN]      * Container running without memory restrictions: root-nginx [WARN] 5.11 - Ensure CPU priority is set appropriately on the container [WARN]      * Container running without CPU restrictions: sshd
[WARN]      * Container running without CPU restrictions: priv-nginx
[WARN]      * Container running without CPU restrictions: root-nginx
```

正如我们在本章前面讨论过的，如果可能的话，你应该以只读模式启动你的容器，并为你知道需要写入数据的地方挂载卷：

```
[WARN] 5.12 - Ensure the container's root filesystem is mounted as read only
[WARN]      * Container running with root FS mounted R/W: sshd
[WARN]      * Container running with root FS mounted R/W: priv-nginx
[WARN]      * Container running with root FS mounted R/W: root-nginx
```

引发以下标志的原因是我们没有告诉 Docker 将我们的暴露端口绑定到 Docker 主机上的特定 IP 地址：

```
[WARN] 5.13 - Ensure incoming container traffic is binded to a specific host interface
[WARN] * Port being bound to wildcard IP: 0.0.0.0 in sshd
```

由于我的测试 Docker 主机只有一个网卡，这并不是太大的问题；然而，如果我的 Docker 主机有多个接口，那么这个容器将暴露给所有网络，如果我有一个外部和内部网络，这可能是一个问题。有关更多详细信息，请参阅[`docs.docker.com/engine/userguide/networking/`](https://docs.docker.com/engine/userguide/networking/)：

```
[WARN] 5.14 - Ensure 'on-failure' container restart policy is set to '5'
[WARN]      * MaximumRetryCount is not set to 5: sshd
[WARN]      * MaximumRetryCount is not set to 5: priv-nginx
[WARN]      * MaximumRetryCount is not set to 5: root-nginx
```

虽然我还没有使用`--restart`标志启动我的容器，但`MaximumRetryCount`没有默认值。这意味着如果一个容器一次又一次地失败，它会很高兴地坐在那里尝试重新启动。这可能会对 Docker 主机产生负面影响；添加`MaximumRetryCount`为`5`将意味着容器在放弃之前会尝试重新启动五次：

```
[WARN] 5.25 - Ensure the container is restricted from acquiring additional privileges
[WARN]      * Privileges not restricted: sshd
[WARN]      * Privileges not restricted: priv-nginx
[WARN]      * Privileges not restricted: root-nginx
```

默认情况下，Docker 不会限制进程或其子进程通过 suid 或 sgid 位获得新特权。要了解如何阻止此行为的详细信息，请参阅[`www.projectatomic.io/blog/2016/03/no-new-privs-docker/`](http://www.projectatomic.io/blog/2016/03/no-new-privs-docker/)：

```
[WARN] 5.26 - Ensure container health is checked at runtime
[WARN]      * Health check not set: sshd
[WARN]      * Health check not set: priv-nginx
[WARN]      * Health check not set: root-nginx
```

再次强调，我们没有使用任何健康检查，这意味着 Docker 不会定期检查容器的状态。要查看引入此功能的拉取请求的 GitHub 问题，请浏览[`github.com/moby/moby/pull/22719/`](https://github.com/moby/moby/pull/22719/)：

```
[WARN] 5.28 - Ensure PIDs cgroup limit is used
[WARN]      * PIDs limit not set: sshd
[WARN]      * PIDs limit not set: priv-nginx
[WARN]      * PIDs limit not set: root-nginx
```

潜在地，攻击者可以通过容器内的单个命令触发 fork bomb。这有可能导致您的 Docker 主机崩溃，唯一的恢复方法是重新启动主机。您可以使用`--pids-limit`标志来防止这种情况发生。有关更多信息，请参阅拉取请求[`github.com/moby/moby/pull/18697/`](https://github.com/moby/moby/pull/18697/)。

# Docker 安全操作

这一部分包括有关最佳实践的`[INFO]`，如下所示：

```
[INFO] 6.1 - Perform regular security audits of your host system and containers
[INFO] 6.2 - Monitor Docker containers usage, performance and metering
[INFO] 6.3 - Backup container data
[INFO] 6.4 - Avoid image sprawl
[INFO]     * There are currently: 4 images
[INFO] 6.5 - Avoid container sprawl
[INFO]     * There are currently a total of 8 containers, with 4 of them currently running
```

# Docker Swarm 配置

这一部分包括`[PASS]`信息，因为我们在主机上没有启用 Docker Swarm：

```
[PASS] 7.1 - Ensure swarm mode is not Enabled, if not needed
[PASS] 7.2 - Ensure the minimum number of manager nodes have been created in a swarm (Swarm mode not enabled)
[PASS] 7.3 - Ensure swarm services are binded to a specific host interface (Swarm mode not enabled)
[PASS] 7.5 - Ensure Docker's secret management commands are used for managing secrets in a Swarm cluster (Swarm mode not enabled)
[PASS] 7.6 - Ensure swarm manager is run in auto-lock mode (Swarm mode not enabled)
[PASS] 7.7 - Ensure swarm manager auto-lock key is rotated periodically (Swarm mode not enabled)
[PASS] 7.8 - Ensure node certificates are rotated as appropriate (Swarm mode not enabled)
[PASS] 7.9 - Ensure CA certificates are rotated as appropriate (Swarm mode not enabled)
[PASS] 7.10 - Ensure management plane traffic has been separated from data plane traffic (Swarm mode not enabled)
```

# 总结 Docker Bench

正如您所见，运行 Docker Bench 来评估 Docker 主机要比手动逐个测试 230 页文档中的每个测试要好得多。

# 第三方安全服务

在完成本章之前，我们将看一些可用的第三方服务，以帮助您评估图像的漏洞。

# Quay

Quay，由 CoreOS 提供的图像注册服务，被 Red Hat 收购，类似于 Docker Hub/Registry；一个区别是 Quay 实际上在每次推送/构建图像后执行安全扫描。

您可以通过查看所选图像的存储库标记来查看扫描结果；在这里，您将看到一个安全扫描的列。正如您在下面的截图中所看到的，在我们创建的示例图像中，没有问题：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/ms-dkr-3e/img/922c1364-af21-4585-8b54-82931a58942d.png)

单击**Passed**将带您进入检测到图像中的任何漏洞的更详细的分解。目前没有漏洞（这是一件好事），因此此屏幕并没有告诉我们太多。但是，单击左侧菜单中的**Packages**图标将向我们显示扫描发现的软件包列表。对于我们的测试图像，它发现了 29 个没有漏洞的软件包，所有这些软件包都显示在这里，还确认了软件包的版本以及它们是如何引入到图像中的：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/ms-dkr-3e/img/bd3ddf6d-d5d3-46f8-9766-20686840a568.png)

正如您也可以看到的，Quay 正在扫描我们公开可用的图像，该图像正在 Quay 提供的免费开源计划上托管。安全扫描是 Quay 所有计划的标准功能。

# Clair

**Clair**是来自 CoreOS 的开源项目。实质上，它是一个为托管版本的 Quay 和商业支持的企业版本提供静态分析功能的服务。

它通过创建以下漏洞数据库的本地镜像来工作：

+   Debian 安全漏洞跟踪器：[`security-tracker.debian.org/tracker/`](https://security-tracker.debian.org/tracker/)

+   Ubuntu CVE 跟踪器：[`launchpad.net/ubuntu-cve-tracker/`](https://launchpad.net/ubuntu-cve-tracker/)

+   Red Hat 安全数据：[`www.redhat.com/security/data/metrics/`](https://www.redhat.com/security/data/metrics/)

+   Oracle Linux 安全数据：[`linux.oracle.com/security/`](https://linux.oracle.com/security/)

+   Alpine SecDB：[`git.alpinelinux.org/cgit/alpine-secdb/`](https://git.alpinelinux.org/cgit/alpine-secdb/)

+   NIST NVD：[`nvd.nist.gov/`](https://nvd.nist.gov/)

一旦它镜像了数据源，它就会挂载图像的文件系统，然后对安装的软件包进行扫描，将它们与前述数据源中的签名进行比较。

Clair 并不是一个简单的服务；它只有一个基于 API 的接口，并且默认情况下 Clair 没有附带任何花哨的基于 Web 或命令行的工具。API 的文档可以在[`coreos.com/clair/docs/latest/api_v1.html`](https://coreos.com/clair/docs/latest/api_v1.html)找到。

安装说明可以在项目的 GitHub 页面找到，网址为[`github.com/coreos/clair/`](https://github.com/coreos/clair/)。

此外，您可以在其集成页面上找到支持 Clair 的工具列表，网址为[`coreos.com/clair/docs/latest/integrations.html`](https://coreos.com/clair/docs/latest/integrations.html)。

# Anchore

我们要介绍的最后一个工具是**Anchore**。它有几个版本；有基于云的版本和本地企业版本，两者都配备了完整的基于 Web 的图形界面。还有一个可以连接到 Jenkins 的版本，以及开源命令行扫描仪，这就是我们现在要看的。

这个版本是作为 Docker Compose 文件分发的，所以我们将首先创建我们需要的文件夹，并且还将从项目 GitHub 存储库下载 Docker Compose 和基本配置文件。

```
$ mkdir anchore anchore/config
$ cd anchore
$ curl https://raw.githubusercontent.com/anchore/anchore-engine/master/scripts/docker-compose/docker-compose.yaml -o docker-compose.yaml
$ curl https://raw.githubusercontent.com/anchore/anchore-engine/master/scripts/docker-compose/config.yaml -o config/config.yaml
```

现在我们已经有了基本设置，您可以按照以下步骤拉取图像并启动容器：

```
$ docker-compose pull
$ docker-compose up -d
```

在我们与 Anchore 部署进行交互之前，我们需要安装命令行客户端。如果您使用的是 macOS，则必须运行以下命令，如果已经安装了`pip`，则忽略第一个命令：

```
$ sudo easy_install pip
$ pip install --user anchorecli
$ export PATH=${PATH}:${HOME}/Library/Python/2.7/bin
```

对于 Ubuntu 用户，您应该运行以下命令，如果已经安装了`pip`，则这次忽略前两个命令：

```
$ sudo apt-get update
$ sudo apt-get install python-pip
$ sudo pip install anchorecli
```

安装完成后，您可以运行以下命令来检查安装的状态：

```
$ anchore-cli --u admin --p foobar system status
```

这将显示您安装的整体状态；从您第一次启动开始，可能需要一两分钟才能显示所有内容为`up`：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/ms-dkr-3e/img/6b81a2d0-bbcd-40e5-a5c7-b25b122f5a5d.png)

下一个命令会显示 Anchore 在数据库同步中的位置：

```
$ anchore-cli --u admin --p foobar system feeds list
```

如您在以下截图中所见，我的安装目前正在同步 CentOS 6 数据库。这个过程可能需要几个小时；但是，对于我们的示例，我们将扫描一个基于 Alpine Linux 的镜像，如下所示：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/ms-dkr-3e/img/db3a369b-9f0b-46c6-9304-de864536aefe.png)

接下来，我们需要获取一个要扫描的镜像；让我们获取一个旧的镜像，如下所示：

```
$ anchore-cli --u admin --p foobar image add docker.io/russmckendrick/moby-counter:old
```

它将花费一两分钟来运行其初始扫描；您可以通过运行以下命令来检查状态：

```
$ anchore-cli --u admin --p foobar image list
```

一段时间后，状态应该从`analyzing`变为`analyzed`：

```
$ anchore-cli --u admin --p foobar image get docker.io/russmckendrick/moby-counter:old
```

这将显示图像的概述，如下所示：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/ms-dkr-3e/img/85631f1e-3fd3-451f-930d-8f968078e110.png)

然后，您可以通过运行以下命令查看问题列表（如果有的话）：

```
$ anchore-cli --u admin --p foobar image vuln docker.io/russmckendrick/moby-counter:old os
```

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/ms-dkr-3e/img/41239fbd-01ca-4dee-a1f0-caf9d81769f0.png)

正如您所看到的，列出的每个软件包都有当前版本，指向 CVE 问题的链接，以及修复报告问题的版本号的确认。

您可以使用以下命令来删除 Anchore 容器：

```
$ docker-compose stop
$ docker-compose rm
```

# 总结

在本章中，我们涵盖了 Docker 安全的一些方面。首先，我们看了一些在运行容器时（与典型的虚拟机相比）必须考虑的事情，涉及安全性。我们看了看 Docker 主机的优势，然后讨论了镜像信任。然后我们看了看我们可以用于安全目的的 Docker 命令。

我们启动了一个只读容器，以便我们可以最小化入侵者在我们运行的容器中可能造成的任何潜在损害。由于并非所有应用程序都适合在只读容器中运行，因此我们随后研究了如何跟踪自启动以来对镜像所做的更改。在尝试解决任何问题时，能够轻松发现运行时文件系统上所做的任何更改总是很有用。

接下来，我们讨论了 Docker 的互联网安全中心指南。本指南将帮助您设置 Docker 环境的多个方面。最后，我们看了看 Docker Bench Security。我们看了如何启动它，并且我们通过了一个输出示例。然后我们分析了输出，看看它的含义。请记住应用程序涵盖的七个项目：主机配置，Docker 守护程序配置，Docker 守护程序配置文件，容器镜像和构建文件，容器运行时，Docker 安全操作和 Docker Swarm 配置。

在下一章中，我们将看看 Docker 如何适应您现有的工作流程，以及处理容器的一些新方法。

# 问题

1.  启动容器时，如何使其全部或部分为只读？

1.  每个容器应该运行多少个进程？

1.  检查 Docker 安装与 CIS Docker 基准的最佳方法是什么？

1.  运行 Docker Bench Security 应用程序时，应该挂载什么？

1.  正确还是错误：Quay 仅支持私有图像的图像扫描。

# 进一步阅读

更多信息，请访问网站[`www.cisecurity.org/`](https://www.cisecurity.org/)；Docker 基准可以在[`www.cisecurity.org/benchmark/docker/`](https://www.cisecurity.org/benchmark/docker/)找到。


# 第十三章：Docker 工作流程

在本章中，我们将研究 Docker 以及 Docker 的各种工作流程。我们将把所有的部分整合在一起，这样你就可以开始在生产环境中使用 Docker，并且感到舒适。让我们来看看本章将涵盖的内容：

+   用于开发的 Docker

+   监控 Docker

+   扩展到外部平台

+   生产环境是什么样子？

# 技术要求

在本章中，我们将在桌面上使用 Docker。与之前的章节一样，我将使用我偏好的操作系统，即 macOS。我们将运行的 Docker 命令将适用于我们迄今为止安装了 Docker 的三种操作系统。然而，一些支持命令可能只适用于基于 macOS 和 Linux 的操作系统。

本章中使用的代码的完整副本可以在 GitHub 存储库中找到：[`github.com/PacktPublishing/Mastering-Docker-Third-Edition/tree/master/chapter14`](https://github.com/PacktPublishing/Mastering-Docker-Third-Edition/tree/master/chapter14)。

观看以下视频以查看代码的实际操作：

[`bit.ly/2SaG0uP`](http://bit.ly/2SaG0uP)

# 用于开发的 Docker

我们将从讨论 Docker 如何帮助开发人员开始我们对工作流程的研究。在第一章 *Docker 概述*中，我们讨论的第一件事是开发人员和*在我的机器上可以运行*的问题。到目前为止，我们还没有完全解决这个问题，所以现在让我们来解决这个问题。

在本节中，我们将看看开发人员如何在本地机器上使用 Docker for macOS 或 Docker for Windows 以及 Docker Compose 开发他们的 WordPress 项目。

我们的目标是启动 WordPress 安装，以下是您将要执行的步骤：

1.  下载并安装 WordPress。

1.  允许从桌面编辑器（如 Atom、Visual Studio Code 或 Sublime Text）在本地机器上访问 WordPress 文件。

1.  使用 WordPress 命令行工具（`WP-CLI`）配置和管理 WordPress。这使您可以在不丢失工作的情况下停止、启动甚至删除容器。

在启动 WordPress 安装之前，让我们来看看 Docker Compose 文件以及我们正在运行的服务：

```
version: "3"

services:
 web:
 image: nginx:alpine
 ports:
 - "8080:80"
 volumes:
 - "./wordpress/web:/var/www/html"
 - "./wordpress/nginx.conf:/etc/nginx/conf.d/default.conf"
 depends_on:
 - wordpress
 wordpress:
 image: wordpress:php7.2-fpm-alpine
 volumes:
 - "./wordpress/web:/var/www/html"
 depends_on:
 - mysql
 mysql:
 image: mysql:5
 environment:
 MYSQL_ROOT_PASSWORD: "wordpress"
 MYSQL_USER: "wordpress"
 MYSQL_PASSWORD: "wordpress"
 MYSQL_DATABASE: "wordpress"
 volumes:
 - "./wordpress/mysql:/var/lib/mysql"
 wp:
 image: wordpress:cli-2-php7.2
 volumes:
 - "./wordpress/web:/var/www/html"
 - "./wordpress/export:/export"
```

我们可以使用 PMSIpilot 的`docker-compose-viz`工具来可视化 Docker Compose 文件。要做到这一点，在与`docker-compose.yml`文件相同的文件夹中运行以下命令：

```
$ docker container run --rm -it --name dcv -v $(pwd):/input pmsipilot/docker-compose-viz render -m image docker-compose.yml
```

这将输出一个名为`docker-compose.png`的文件，您应该会得到类似于这样的东西：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/ms-dkr-3e/img/7a4d5fa8-68e1-4249-b542-17d059154743.png)

您可以使用`docker-compose-viz`来为任何 Docker Compose 文件提供可视化表示。正如您从我们的文件中看到的，我们定义了四个服务。

第一个被称为`web`。这个服务是四个中唯一暴露给主机网络的服务，并且它充当我们 WordPress 安装的前端。它运行来自[`store.docker.com/images/nginx/`](https://store.docker.com/images/nginx/)的官方 nginx 镜像，并且扮演两个角色。在我们看这些之前，先看一下以下 nginx 配置：

```
server {
 server_name _;
 listen 80 default_server;

 root /var/www/html;
 index index.php index.html;

 access_log /dev/stdout;
 error_log /dev/stdout info;

 location / {
 try_files $uri $uri/ /index.php?$args;
 }

 location ~ .php$ {
 include fastcgi_params;
 fastcgi_pass wordpress:9000;
 fastcgi_index index.php;
 fastcgi_param SCRIPT_FILENAME $document_root$fastcgi_script_name;
 fastcgi_buffers 16 16k;
 fastcgi_buffer_size 32k;
 }
}
```

您可以看到，我们正在使用 nginx 从`/var/www/html/`提供除 PHP 之外的所有内容，我们正在使用 nginx 从我们的主机机器挂载，并且所有 PHP 文件的请求都被代理到我们的第二个名为`wordpress`的服务，端口为`9000`。nginx 配置本身被挂载到我们的主机机器上的`/etc/nginx/conf.d/default.conf`。

这意味着我们的 nginx 容器充当静态内容的 Web 服务器，这是第一个角色，同时也充当代理通过到 WordPress 容器的动态内容，这是容器承担的第二个角色。

第二个服务是`wordpress`；这是来自[`store.docker.com/images/wordpress`](https://store.docker.com/images/wordpress)的官方 WordPress 镜像，我正在使用`php7.2-fpm-alpine`标签。这使我们可以在 Alpine Linux 基础上运行的 PHP 7.2 上使用`PHP-FPM`构建的 WordPress 安装。

**FastCGI 进程管理器**（**PHP-FPM**）是一个具有一些出色功能的 PHP FastCGI 实现。对我们来说，它允许 PHP 作为一个我们可以绑定到端口并传递请求的服务运行；这符合 Docker 在每个容器上运行单个服务的方法。

我们挂载了与 web 服务相同的网站根目录，在主机上是`wordpress/web`，在服务上是`/var/www/html/`。一开始，我们主机上的文件夹将是空的；然而，一旦 WordPress 服务启动，它将检测到没有任何核心 WordPress 安装，并将其复制到该位置，有效地引导我们的 WordPress 安装并将其复制到我们的主机上，准备让我们开始工作。

下一个服务是 MySQL，它使用官方的 MySQL 镜像（[`store.docker.com/images/mysql/`](https://store.docker.com/images/mysql/)），是我们使用的四个镜像中唯一不使用 Alpine Linux 的镜像（来吧 MySQL，动作快点，发布一个基于 Alpine Linux 的镜像！）。相反，它使用`debian:stretch-slim`。我们传递了一些环境变量，以便在容器首次运行时创建数据库、用户名和密码；如果您将来使用这个作为项目的基础，密码是您应该更改的内容。

像`web`和`wordpress`容器一样，我们从主机机器上挂载一个文件夹。在这种情况下，它是`wordpress/mysql`，我们将其挂载到`/var/lib/mysql/`，这是 MySQL 存储其数据库和相关文件的默认文件夹。

您会注意到当容器启动时，`wordpress/mysql`中填充了一些文件。我不建议使用本地 IDE 对其进行编辑。

最终的服务简单地称为`wp`。它与其他三个服务不同：这个服务在执行时会立即退出，因为容器内没有长时间运行的进程。它不提供长时间运行的进程，而是在与我们的主`wordpress`容器完全匹配的环境中提供对 WordPress 命令行工具的访问。

您会注意到我们挂载了网站根目录，就像我们在 web 和 WordPress 上做的那样，还有一个名为`/export`的第二个挂载；一旦我们配置了 WordPress，我们将更详细地看一下这一点。

启动 WordPress，我们只需要运行以下命令来拉取镜像：

```
$ docker-compose pull
```

这将拉取镜像并启动`web`，`wordpress`和`mysql`服务，以及准备`wp`服务。在服务启动之前，我们的`wordpress`文件夹看起来是这样的：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/ms-dkr-3e/img/a43578b3-ae10-48cd-a955-c9ae51cf4a22.png)

正如您所看到的，我们只在其中有`nginx.conf`，这是 Git 存储库的一部分。然后，我们可以使用以下命令启动容器并检查它们的状态：

```
$ docker-compose up -d
$ docker-compose ps
```

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/ms-dkr-3e/img/32a9383e-8a5f-446e-a591-56c5824da777.png)

您应该看到在`wordpress`文件夹中已创建了三个文件夹：`export`，`mysql`和`web`。还要记住，我们期望`dockerwordpress_wp_1`有一个`exit`状态，所以没问题：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/ms-dkr-3e/img/2c39b6fd-5299-4d71-b8ec-e949ab69dfba.png)

打开浏览器并转到`http://localhost:8080/`应该显示标准的 WordPress 预安装欢迎页面，您可以在其中选择要用于安装的语言：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/ms-dkr-3e/img/002b9525-f3e6-4362-82ee-c457ac83674b.png)

不要点击**继续**，因为它会带您到基于 GUI 的安装的下一个屏幕。而是返回到您的终端。

我们将使用 WP-CLI 而不是使用 GUI 来完成安装。这有两个步骤。第一步是创建一个`wp-config.php`文件。要做到这一点，请运行以下命令：

```
$ docker-compose run wp core config \
    --dbname=wordpress \
    --dbuser=wordpress \
    --dbpass=wordpress \
    --dbhost=mysql \
    --dbprefix=wp_
```

如您将在以下终端输出中看到的，在运行命令之前，我只有`wp-config-sample.php`文件，这是 WordPress 核心附带的。然后，在运行命令后，我有了自己的`wp-config.php`文件：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/ms-dkr-3e/img/93ff2e9d-9e0e-4c46-bdc6-438a7e65c5bf.png)

您会注意到在命令中，我们传递了我们在 Docker Compose 文件中定义的数据库详细信息，并告诉 WordPress 它可以连接到地址为`mysql`的数据库服务。

现在我们已经配置了数据库连接详细信息，我们需要配置我们的 WordPress 网站以及创建一个管理员用户并设置密码。要做到这一点，请运行以下命令：

```
$ docker-compose run wp core install \
 --title="Blog Title" \
 --url="http://localhost:8080" \
 --admin_user="admin" \
 --admin_password="password" \
 --admin_email="email@domain.com"
```

运行此命令将产生有关电子邮件服务的错误；不要担心这条消息，因为这只是一个本地开发环境。我们不太担心电子邮件离开我们的 WordPress 安装：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/ms-dkr-3e/img/20b6bd8f-dcf6-4822-a6e0-7ca29deddc65.png)

我们已经使用 WP-CLI 在 WordPress 中配置了以下内容：

+   我们的 URL 是`http://localhost:8080`

+   我们的网站标题应该是`博客标题`

+   我们的管理员用户名是`admin`，密码是`password`，用户的电子邮件是`email@domain.com`

返回到您的浏览器并输入[`localhost:8080/`](http://localhost:8080/)应该呈现给您一个原始的 WordPress 网站：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/ms-dkr-3e/img/8375e8c2-0472-4227-bdfe-5db42c6b12ea.png)

在我们进一步操作之前，让我们先定制一下我们的安装，首先安装并启用 JetPack 插件：

```
$ docker-compose run wp plugin install jetpack --activate
```

该命令的输出如下：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/ms-dkr-3e/img/7eb7c72d-cad0-4837-9df6-5cdd0c6d30b9.png)

然后，安装并启用`sydney`主题：

```
$ docker-compose run wp theme install sydney --activate
```

该命令的输出如下：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/ms-dkr-3e/img/a5063118-333d-47e6-b534-9c7ebadbcabc.png)

刷新我们的 WordPress 页面[`localhost:8080/`](http://localhost:8080/)应该显示类似以下内容：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/ms-dkr-3e/img/8957b6fe-d698-4b21-9f37-292acb3742a5.png)

在打开 IDE 之前，让我们使用以下命令销毁运行我们 WordPress 安装的容器：

```
$ docker-compose down 
```

该命令的输出如下：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/ms-dkr-3e/img/d4e8f2f0-b75d-4f41-a203-be965f441683.png)

由于我们整个 WordPress 安装，包括所有文件和数据库，都存储在我们的本地机器上，我们应该能够运行以下命令返回到我们离开的 WordPress 网站：

```
$ docker-compose up -d
```

一旦确认它按预期运行并正在运行，打开桌面编辑器中的`docker-wordpress`文件夹。我使用 Sublime Text。在编辑器中，打开`wordpress/web/wp-blog-header.php`文件，并在开头的 PHP 语句中添加以下行并保存：

```
echo "Testing editing in the IDE";
```

文件应该看起来像以下内容：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/ms-dkr-3e/img/522fd0f5-a1e0-4f20-aca7-f5d9f1b45843.png)

保存后，刷新浏览器，你应该在页面底部的 IDE 中看到消息**Testing editing**（以下屏幕是放大的；如果你在跟随，可能更难发现，因为文本非常小）：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/ms-dkr-3e/img/28881359-ecf2-43c1-a05c-91a7904d1bab.png)

我们要看的最后一件事是为什么`wordpress/export`文件夹被挂载到`wp`容器上。

正如本章前面已经提到的，你不应该真的去触碰`wordpress/mysql`文件夹的内容；这也包括共享它。虽然如果你将项目文件夹压缩并传递给同事，它可能会工作，但这并不被认为是最佳实践。因此，我们已经挂载了导出文件夹，以便我们可以使用 WP-CLI 进行数据库转储和导入。

要做到这一点，运行以下命令：

```
$ docker-compose run wp db export --add-drop-table /export/wordpress.sql
```

以下终端输出显示了导出以及`wordpress/export`文件夹的内容，最后是 MySQL 转储的前几行：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/ms-dkr-3e/img/05768ab0-7d48-487d-ab2e-a1e4d693a0f4.png)

如果需要的话，比如说，我在开发过程中犯了一个错误，我可以通过运行以下命令回滚到数据库的那个版本：

```
$ docker-compose run wp db import /export/wordpress.sql
```

命令的输出如下：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/ms-dkr-3e/img/2f5dcc3c-517c-485c-8463-5b12d7aa5fb1.png)

正如您所见，我们已经安装了 WordPress，使用 WP-CLI 和浏览器与其进行了交互，编辑了代码，并备份和恢复了数据库，所有这些都不需要安装或配置 nginx、PHP、MySQL 或 WP-CLI。我们也不需要登录到容器中。通过从主机机器挂载卷，我们的内容在我们关闭 WordPress 容器时是安全的，我们没有丢失任何工作。

此外，如果需要，我们可以轻松地将项目文件夹的副本传递给安装了 Docker 的同事，然后通过一条命令，他们就可以在我们的代码上工作，知道它在与我们自己的安装相同的环境中运行。

最后，由于我们正在使用 Docker Store 的官方镜像，我们知道可以安全地要求将它们部署到生产环境中，因为它们是根据 Docker 的最佳实践构建的。

不要忘记通过运行`docker-compose down`停止和删除您的 WordPress 容器。

# 监控

接下来，我们将看一下监视我们的容器和 Docker 主机。在第四章*，管理容器*中，我们讨论了`docker container top`和`docker container stats`命令。您可能还记得，这两个命令只显示实时信息；没有保留历史数据。

如果您正在尝试调试问题或者想快速了解容器内部发生了什么，这很棒，但如果您需要回顾问题，那就不太有帮助：也许您已经配置了容器，使其在变得无响应时重新启动。虽然这对应用程序的可用性有所帮助，但如果您需要查看容器为何变得无响应，那就没有太多帮助了。

在 GitHub 存储库的`/chapter14`文件夹中，有一个名为`prometheus`的文件夹，其中有一个 Docker Compose 文件，可以在两个网络上启动三个不同的容器。而不是查看 Docker Compose 文件本身，让我们来看一下可视化：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/ms-dkr-3e/img/3efc549a-54a8-4083-8edc-b1679455d5af.png)

如您所见，有很多事情正在进行。我们正在运行的三个服务是：

+   **Cadvisor**

+   **Prometheus**

+   **Grafana**

在启动和配置 Docker Compose 服务之前，我们应该讨论每个服务为什么需要，从`cadvisor`开始。

`cadvisor`是 Google 发布的一个项目。正如您从我们使用的 Docker Hub 用户名在图像中看到的那样，Docker Compose 文件中的服务部分如下所示：

```
 cadvisor:
 image: google/cadvisor:latest
 container_name: cadvisor
 volumes:
 - /:/rootfs:ro
 - /var/run:/var/run:rw
 - /sys:/sys:ro
 - /var/lib/docker/:/var/lib/docker:ro
 restart: unless-stopped
 expose:
 - 8080
 networks:
 - back
```

我们正在挂载我们主机文件系统的各个部分，以便让`cadvisor`访问我们的 Docker 安装，方式与我们在第十一章*，Portainer – A GUI for Docker*中所做的方式相同。这样做的原因是，在我们的情况下，我们将使用`cadvisor`来收集容器的统计信息。虽然它可以作为独立的容器监控服务使用，但我们不希望公开暴露`cadvisor`容器。相反，我们只是让它在后端网络的 Docker Compose 堆栈中对其他容器可用。

`cadvisor`是 Docker 容器`stat`命令的自包含 Web 前端，显示图形并允许您从 Docker 主机轻松进入容器的易于使用的界面。但是，它不会保留超过 5 分钟的指标。

由于我们试图记录可能在几个小时甚至几天后可用的指标，所以最多只有 5 分钟的指标意味着我们将不得不使用其他工具来记录它处理的指标。`cadvisor`将我们想要记录的信息作为结构化数据暴露在以下端点：`http://cadvisor:8080/metrics/`。

我们将在一会儿看到这为什么很重要。`cadvisor`端点正在被我们接下来的服务`prometheus`自动抓取。这是大部分繁重工作发生的地方。`prometheus`是由 SoundCloud 编写并开源的监控工具：

```
 prometheus:
 image: prom/prometheus
 container_name: prometheus
 volumes:
 - ./prometheus/prometheus.yml:/etc/prometheus/prometheus.yml
 - prometheus_data:/prometheus
 restart: unless-stopped
 expose:
 - 9090
 depends_on:
 - cadvisor
 networks:
 - back
```

正如您从前面的服务定义中看到的，我们正在挂载一个名为`./prometheus/prometheus.yml`的配置文件，还有一个名为`prometheus_data`的卷。配置文件包含有关我们要抓取的源的信息，正如您从以下配置中看到的那样：

```
global:
 scrape_interval: 15s 
 evaluation_interval: 15s
 external_labels:
 monitor: 'monitoring'

rule_files:

scrape_configs:

 - job_name: 'prometheus'
 static_configs:
 - targets: ['localhost:9090']

 - job_name: 'cadvisor'
 static_configs:
 - targets: ['cadvisor:8080']
```

我们指示 Prometheus 每`15`秒从我们的端点抓取数据。端点在`scrape_configs`部分中定义，正如你所看到的，我们在其中定义了`cadvisor`以及 Prometheus 本身。我们创建和挂载`prometheus_data`卷的原因是，Prometheus 将存储我们所有的指标，因此我们需要确保它的安全。

在其核心，Prometheus 是一个时间序列数据库。它获取已经抓取的数据，处理数据以找到指标名称和数值，然后将其与时间戳一起存储。

Prometheus 还配备了强大的查询引擎和 API，使其成为这种数据的完美数据库。虽然它具有基本的图形能力，但建议您使用 Grafana，这是我们的最终服务，也是唯一一个公开暴露的服务。

**Grafana**是一个用于显示监控图形和指标分析的开源工具，它允许您使用时间序列数据库（如 Graphite、InfluxDB 和 Prometheus）创建仪表板。还有其他后端数据库选项可用作插件。

Grafana 的 Docker Compose 定义遵循与我们其他服务类似的模式：

```
 grafana:
 image: grafana/grafana
 container_name: grafana
 volumes:
 - grafana_data:/var/lib/grafana
 - ./grafana/provisioning/:/etc/grafana/provisioning/
 env_file:
 - ./grafana/grafana.config
 restart: unless-stopped
 ports:
 - 3000:3000
 depends_on:
 - prometheus
 networks:
 - front
 - back
```

我们使用`grafana_data`卷来存储 Grafana 自己的内部配置数据库，而不是将环境变量存储在 Docker Compose 文件中，我们是从名为`./grafana/grafana.config`的外部文件中加载它们。

变量如下：

```
GF_SECURITY_ADMIN_USER=admin
GF_SECURITY_ADMIN_PASSWORD=password
GF_USERS_ALLOW_SIGN_UP=false
```

正如你所看到的，我们在这里设置了用户名和密码，因此将它们放在外部文件中意味着你可以在不编辑核心 Docker Compose 文件的情况下更改这些值。

现在我们知道了这四个服务各自的角色，让我们启动它们。要做到这一点，只需从`prometheus`文件夹运行以下命令：

```
$ docker-compose pull
$ docker-compose up -d 
```

这将创建一个网络和卷，并从 Docker Hub 拉取镜像。然后它将启动这四个服务：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/ms-dkr-3e/img/9f337042-8244-4838-bff2-40c8d518ba0c.png)

你可能会立刻转到 Grafana 仪表板。如果你这样做，你将看不到任何东西，因为 Grafana 需要几分钟来初始化自己。你可以通过查看日志来跟踪它的进度：

```
$ docker-compose logs -f grafana
```

命令的输出如下：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/ms-dkr-3e/img/385e8580-5b68-48c3-b69e-abd387fb61b6.png)

一旦您看到`HTTP 服务器监听`的消息，Grafana 将可用。使用 Grafana 5，您现在可以导入数据源和仪表板，这就是为什么我们将`./grafana/provisioning/`挂载到`/etc/grafana/provisioning/`的原因。这个文件夹包含配置，自动配置 Grafana 与我们的 Prometheus 服务通信，并导入仪表板，显示 Prometheus 从 cadvisor 中抓取的数据。

打开您的浏览器，输入`http://localhost:3000/`，您应该会看到一个登录界面：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/ms-dkr-3e/img/649978eb-8e40-4a14-9f29-58f31272ae83.png)

输入**用户**为`admin`，**密码**为`password`。一旦登录，如果您已配置数据源，您应该会看到以下页面：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/ms-dkr-3e/img/ddac6a6f-0e09-439a-a2cb-9cf553af9050.png)

正如您所看到的，安装 Grafana 的初始步骤|创建您的第一个数据源|创建您的第一个仪表板都已经执行完毕，只剩下最后两个步骤。现在，我们将忽略这些。点击左上角的主页按钮将会弹出一个菜单，列出可用的仪表板：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/ms-dkr-3e/img/ed39f3be-0f1b-4fd7-9dac-6a257b5ff551.png)

如您所见，我们有一个名为 Docker Monitoring 的数据源。点击它将会带您到以下页面：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/ms-dkr-3e/img/e4442959-0f79-4cf4-a8c0-7a057e461f22.png)

如您从屏幕右上角的时间信息中所见，默认情况下显示最近五分钟的数据。点击它将允许您更改时间范围的显示。例如，以下屏幕显示了最近 15 分钟的数据，显然比 cadvisor 记录的五分钟要多：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/ms-dkr-3e/img/461543ed-904b-47f9-a747-8fcd743f3e3f.png)

我已经提到这是一个复杂的解决方案；最终，Docker 将扩展最近发布的内置端点，目前只公开有关 Docker 引擎而不是容器本身的信息。有关内置端点的更多信息，请查看官方 Docker 文档，网址为[`docs.docker.com/config/thirdparty/prometheus/`](https://docs.docker.com/config/thirdparty/prometheus/)。

还有其他监控解决方案；其中大多数采用第三方**软件即服务**（**SaaS**）的形式。从*进一步阅读*部分的服务列表中可以看出，列出了一些成熟的监控解决方案。实际上，您可能已经在使用它们，因此在扩展配置时，考虑监视容器时会很容易。

一旦您完成了对 Prometheus 安装的探索，请不要忘记通过运行以下命令来删除它：

```
$ docker-compose down --volumes --rmi all
```

这将删除所有容器、卷、镜像和网络。

# 扩展到外部平台

我们已经看过如何使用诸如 Docker Machine、Docker Swarm、Docker for Amazon Web Services 和 Rancher 等工具来扩展到其他外部平台，并启动集群以及来自公共云服务的集群和容器服务，如 Amazon Web Services、Microsoft Azure 和 DigitalOcean。

# Heroku

**Heroku**与其他云服务有些不同，因为它被认为是**平台即服务**（**PaaS**）。您不是在其上部署容器，而是将您的容器链接到 Heroku 平台，从中它将运行服务，如 PHP、Java、Node.js 或 Python。因此，您可以在 Heroku 上运行您的 Rails 应用程序，然后将您的 Docker 容器附加到该平台。

我们不会在这里涵盖安装 Heroku，因为这有点离题。有关 Heroku 的更多详细信息，请参阅本章的*进一步阅读*部分。

您可以将 Docker 和 Heroku 结合使用的方法是在 Heroku 平台上创建您的应用程序，然后在您的代码中，您将有类似以下内容的东西：

```
{
 "name": “Application Name",
 "description": “Application to run code in a Docker container",
 "image": “<docker_image>:<tag>”,
 "addons": [ "heroku-postgresql" ]
}
```

要退一步，我们首先需要安装插件才能使此功能正常工作。只需运行以下命令：

```
$ heroku plugins:install heroku-docker
```

现在，如果您想知道您可以或应该从 Docker Hub 使用哪个镜像，Heroku 维护了许多您可以在上述代码中使用的镜像：

+   `heroku/nodejs`

+   `heroku/ruby`

+   `heroku/jruby`

+   `heroku/python`

+   `heroku/scala`

+   `heroku/clojure`

+   `heroku/gradle`

+   `heroku/java`

+   `heroku/go`

+   `heroku/go-gb`

# 生产环境是什么样子的？

在本章的最后一节，我们将讨论生产环境应该是什么样子。这一节不会像你想象的那么长。这是因为有大量可用的选项，所以不可能覆盖它们所有。此外，根据前面的章节，你应该已经对什么对你最好有了一个很好的想法。

相反，我们将看一些在规划环境时应该问自己的问题。

# Docker 主机

Docker 主机是你的环境的关键组件。没有这些，你就没有地方运行你的容器。正如我们在之前的章节中已经看到的，当涉及到运行 Docker 主机时有一些考虑因素。你需要考虑的第一件事是，如果你的主机正在运行 Docker，它们不应该运行任何其他服务。

# 进程混合

你应该抵制迅速在现有主机上安装 Docker 并启动容器的诱惑。这不仅可能会导致安全问题，因为你在单个主机上同时运行了隔离和非隔离的进程，而且还可能会导致性能问题，因为你无法为非容器化的应用添加资源限制，这意味着它们可能也会对正在运行的容器产生负面影响。

# 多个隔离的 Docker 主机

如果你有多个 Docker 主机，你将如何管理它们？运行像 Portainer 这样的工具很好，但当尝试管理多个主机时可能会麻烦。此外，如果你运行多个隔离的 Docker 主机，你就没有将容器在主机之间移动的选项。

当然，你可以使用诸如 Weave Net 之类的工具来跨多个独立的 Docker 主机扩展容器网络。根据你的托管环境，你可能还可以选择在外部存储上创建卷，并根据需要将它们呈现给 Docker 主机，但你很可能正在创建一个手动过程来管理容器在主机之间的迁移。

# 路由到你的容器

如果你有多个主机，你需要考虑如何在你的容器之间路由请求。

例如，如果您有外部负载均衡器，例如 AWS 中的 ELB，或者在本地集群前面有一个专用设备，您是否有能力动态添加路由，将命中`端口 x`的流量添加到您的 Docker 主机上的`端口 y`，然后将流量路由到您的容器？

如果您有多个容器都需要在同一个外部端口上访问，您将如何处理？

您是否需要安装代理，如 Traefik、HAProxy 或 nginx，以接受并根据基于域或子域的虚拟主机路由请求，而不仅仅是使用基于端口的路由？

例如，您可以仅使用网站的端口，将所有内容都配置到由 Docker 配置的容器上的端口`80`和`443`，以接受这些端口上的流量。使用虚拟主机路由意味着您可以将`domain-a.com`路由到`容器 a`，然后将[domainb.com](https://www.domain-b.com/)路由到`容器 b`。`domain-a.com`和`domain-b.com`都可以指向相同的 IP 地址和端口。

# 聚类

我们在前一节讨论的许多问题都可以通过引入集群工具来解决，例如 Docker Swarm 和 Kubernetes

# 兼容性

即使应用程序在开发人员的本地 Docker 安装上运行良好，您也需要能够保证，如果将应用程序部署到例如 Kubernetes 集群，它也能以相同的方式工作。

十次中有九次，您不会遇到问题，但您确实需要考虑应用程序如何在同一应用程序集内部与其他容器进行通信。

# 参考架构

您选择的集群技术是否有参考架构？在部署集群时最好检查一下。有最佳实践指南与您提出的环境接近或匹配。毕竟，没有人想要创建一个巨大的单点故障。

此外，推荐的资源是什么？部署具有五个管理节点和单个 Docker 主机的集群没有意义，就像部署五个 Docker 主机和单个管理服务器一样，因为您有一个相当大的单点故障。

您的集群技术支持哪些支持技术（例如，远程存储、负载均衡器和防火墙）？

# 集群通信

当集群与管理或 Docker 主机通信时，有哪些要求？您是否需要内部或单独的网络来隔离集群流量？

您是否可以轻松地将集群成员限制在您的集群中？集群通信是否加密？您的集群可能会泄露哪些信息？这是否使其成为黑客的目标？

集群需要对 API 进行什么样的外部访问，比如您的公共云提供商？任何 API/访问凭据存储得有多安全？

# 镜像注册表

您的应用程序是如何打包的？您是否已经将代码嵌入到镜像中？如果是，您是否需要托管一个私有的本地镜像注册表，还是可以使用外部服务，比如 Docker Hub、Docker Trusted Registry (DTR)或 Quay？

如果您需要托管自己的私有注册表，在您的环境中应该放在哪里？谁有或需要访问权限？它是否可以连接到您的目录提供者，比如 Active Directory 安装？

# 总结

在本章中，我们看了一些关于 Docker 的不同工作流程，以及如何为您的容器和 Docker 主机启动一些监控。

当涉及到您自己的环境时，最好的做法是构建一个概念验证，并尽力覆盖您能想到的每一种灾难情景。您可以通过使用云提供商提供的容器服务或寻找一个良好的参考架构来提前开始，这些都应该限制您的试错。

在下一章中，我们将看一看容器世界中您的下一步是什么。

# 问题

1.  哪个容器为我们的 WordPress 网站提供服务？

1.  为什么`wp`容器不能保持运行状态？

1.  cAdvisor 会保留多长时间的指标？

1.  什么 Docker Compose 命令可以用来删除与应用程序有关的所有内容？

# 进一步阅读

您可以在本章中找到我们使用的软件的详细信息，网址如下：

+   WordPress: [`wordpress.org/`](http://wordpress.org/)

+   WP-CLI: [`wp-cli.org/`](https://wp-cli.org/)

+   PHP-FPM: [`php-fpm.org/`](https://php-fpm.org/)

+   cAdvisor: [`github.com/google/cadvisor/`](https://github.com/google/cadvisor/)

+   Prometheus: [`prometheus.io/`](https://prometheus.io/)

+   Grafana: [`grafana.com/`](https://grafana.com/)

+   Prometheus 数据模型: [`prometheus.io/docs/concepts/data_model/`](https://prometheus.io/docs/concepts/data_model/)

+   Traefik: [`traefik.io/`](https://traefik.io/)

+   HAProxy: [`www.haproxy.org/`](https://www.haproxy.org/)

+   NGINX: [`nginx.org/`](https://nginx.org/)

+   Heroku: [`www.heroku.com`](https://www.heroku.com)

其他外部托管的 Docker 监控平台包括以下内容：

+   Sysdig Cloud: [`sysdig.com/`](https://sysdig.com/)

+   Datadog: [`docs.datadoghq.com/integrations/docker/`](http://docs.datadoghq.com/integrations/docker/)

+   CoScale: [`www.coscale.com/docker-monitoring`](http://www.coscale.com/docker-monitoring)

+   Dynatrace: [`www.dynatrace.com/capabilities/microservices-and-container-monitoring/`](https://www.dynatrace.com/capabilities/microservices-and-container-monitoring/)

+   SignalFx: [`signalfx.com/docker-monitoring/`](https://signalfx.com/docker-monitoring/)

+   New Relic: [`newrelic.com/partner/docker`](https://newrelic.com/partner/docker)

+   Sematext: [`sematext.com/docker/`](https://sematext.com/docker/)

还有其他自托管选项，例如：

+   Elastic Beats: [`www.elastic.co/products/beats`](https://www.elastic.co/products/beats)

+   Sysdig: [`www.sysdig.org`](https://www.sysdig.org)

+   Zabbix: [`github.com/monitoringartist/zabbix-docker-monitoring`](https://github.com/monitoringartist/zabbix-docker-monitoring)


# 第十四章：下一步与 Docker

你已经读到了这本书的最后一章，并且一直坚持到了最后！在这一章中，我们将看看 Moby 项目以及你如何为 Docker 以及社区做出贡献。然后我们将以快速概述云原生计算基金会结束这一章。让我们从讨论 Moby 项目开始。

# Moby 项目

在 DockerCon 2017 上宣布的消息之一是 Moby 项目。当这个项目被宣布时，我从同事那里得到了一些关于这个项目是什么的问题，因为乍一看，Docker 似乎发布了另一个容器系统。

那么，我是如何回答的呢？在几天内被困惑的表情困扰之后，我找到了以下答案：

“Moby 项目是一个开源项目的集合名称，它收集了用于构建基于容器的系统的几个库。该项目配备了自己的框架，用于将这些库组合成一个可用的系统，还有一个名为 Moby Origin 的参考系统；可以将其视为一个允许您构建甚至自定义自己的 Docker 的“Hello World”。”

在我给出这个答案后，通常会发生两件事中的一件；典型的反应是“但那实际上是什么意思？”我回答说：

“Moby 项目是 Docker（公司）和任何希望为项目做出贡献的人的开源游乐场，用于在公共论坛中开发新的并扩展现有特性到构成基于容器的系统的库和框架。其中一个产出是名为 Moby Origin 的尖端容器系统，另一个是 Docker（产品），它以开源社区版或商业支持的企业版形式提供。”

对于任何要求类似项目的例子，结合了尖端版本、稳定的开源版本和企业支持版本的人，我解释了 Red Hat 在 Red Hat Enterprise Linux 上的做法：

<q>可以把它看作是 Red Hat 企业版 Linux 采用的方法。你有 Fedora，它是 Red Hat 操作系统开发者引入新软件包、功能以及移除旧的过时组件的前沿版本开发平台。通常，Fedora 的功能比 Red Hat 企业版 Linux 领先一两年，后者是基于 Fedora 项目工作成果的商业支持的长期版本；除了这个版本，你还可以在 CentOS 中找到社区支持版本。</q>

你可能会想，*为什么这本书的最后才提到这个？* 嗯，在我写这本书的时候，这个项目仍处于起步阶段。事实上，工作仍在进行中，以将 Moby 项目所需的所有组件从主要的 Docker 项目中转移过来。

在我写这篇文章时，这个项目唯一真正可用的组件是*LinuxKit*，它是将所有库汇集在一起并输出可运行容器的可引导系统的框架。

由于这个项目发展速度极快，我不会提供如何使用 LinuxKit 或更多关于 Moby 项目的细节，因为在你阅读时可能已经发生了变化；相反，我建议收藏以下页面以保持最新：

+   项目的主要网站，网址是：[`mobyproject.org/`](https://mobyproject.org/)

+   Moby 项目的 GitHub 页面，网址是：[`github.com/moby/`](https://github.com/moby/)

+   Moby 项目的 Twitter 账号是一个获取新闻和教程链接的好来源，网址是：[`twitter.com/moby/`](https://twitter.com/moby/)

+   LinuxKit 的主页包含了如何入门的示例和说明，网址是：[`github.com/linuxkit/`](https://github.com/linuxkit/)

# 贡献 Docker

所以，你想要帮助贡献 Docker 吗？你有一个想在 Docker 或其组件中看到的好主意吗？让我们为你提供所需的信息和工具。如果你不是程序员类型的人，你也可以通过其他方式进行贡献。Docker 拥有庞大的用户群，你可以通过帮助支持其他用户的服务来进行贡献。让我们学习如何做到这一点。

# 贡献代码

你可以通过帮助 Docker 代码来做出贡献。由于 Docker 是开源的，你可以下载代码到本地机器上，开发新功能，并将其作为拉取请求提交给 Docker。然后，它们将定期进行审查，如果他们认为你的贡献应该被接受，他们将批准拉取请求。当你知道自己的作品被接受时，这可能会让你感到非常谦卑。

首先，你需要知道如何设置贡献：这几乎是 Docker ([`github.com/docker/`](https://github.com/docker/)) 和 Moby Project ([`github.com/moby/`](https://github.com/moby/)) 的所有内容，我们在前一节已经讨论过。但是我们如何开始帮助贡献呢？最好的开始地方是遵循官方 Docker 文档中的指南，网址为[`docs.docker.com/project/who-written-for/`](https://docs.docker.com/project/who-written-for/)。

你可能已经猜到，为了建立开发环境，你不需要太多，因为很多开发都是在容器内完成的。例如，除了拥有 GitHub 账户外，Docker 列出了以下三个软件作为最低要求：

+   Git：[`git-scm.com/`](https://git-scm.com/)

+   Make：[`www.gnu.org/software/make/`](https://www.gnu.org/software/make/)

+   Docker：如果你已经走到这一步，你应该不需要链接

你可以在以下网址找到有关如何准备 Mac 和 Linux 的 Docker 开发的更多细节：[`docs.docker.com/opensource/project/software-required/`](https://docs.docker.com/opensource/project/software-required/)，以及 Windows 用户的更多信息：[`docs.docker.com/opensource/project/software-req-win/`](https://docs.docker.com/opensource/project/software-req-win/)。

要成为一个成功的开源项目，必须有一些社区准则。我建议阅读这个优秀的快速入门指南，网址为：[`docs.docker.com/opensource/code/`](https://docs.docker.com/opensource/code/)，以及更详细的贡献工作流程文档，网址为：[`docs.docker.com/opensource/workflow/make-a-contribution/`](https://docs.docker.com/opensource/workflow/make-a-contribution/)。

Docker 有一套行为准则，涵盖了他们的员工和整个社区应该如何行事。它是开源的，根据知识共享署名 3.0 许可，规定如下：

<q>![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/ms-dkr-3e/img/9c145a15-4ca2-48f0-a6c4-f4a53e17d612.png)</q>

行为准则的完整代码可以在以下网址找到：[`github.com/docker/code-of-conduct/`](https://github.com/docker/code-of-conduct/)。

# 提供 Docker 支持

您也可以通过其他方式为 Docker 做出贡献，而不仅仅是贡献 Docker 的代码或功能集。您可以利用自己所获得的知识来帮助其他人解决他们的支持问题。社区非常开放，总有人愿意帮助。当我遇到问题时，得到帮助对我非常有帮助。得到帮助也很好，但也要回馈给他人；这是一种很好的互惠互利。这也是一个收集你可以使用的想法的好地方。您可以根据他们的设置看到其他人提出的问题，这可能会激发您想要在您的环境中使用的想法。

您还可以关注有关服务的 GitHub 问题。这些可能是功能请求以及 Docker 如何实现它们，或者它们可能是通过使用服务而出现的问题。您可以帮助测试其他人遇到的问题，以查看您是否可以复制该问题，或者您是否找到了可能的解决方案。

Docker 拥有一个非常活跃的社区，网址为：[`community.docker.com/`](https://community.docker.com/)；在这里，您不仅可以看到最新的社区新闻和活动，还可以在他们的 Slack 频道中与 Docker 用户和开发人员交谈。在撰写本书时，有超过 80 个频道涵盖各种主题，如 Docker for Mac，Docker for Windows，Alpine Linux，Swarm，Storage 和 Network 等，每时每刻都有数百名活跃用户。

最后，还有 Docker 论坛，网址为：[`forums.docker.com/`](https://forums.docker.com/)。如果您想搜索主题/问题或关键字，这是一个很好的来源。

# 其他贡献

还有其他方式可以为 Docker 做出贡献。您可以做一些事情，比如在您的机构推广服务并吸引兴趣。您可以通过您自己组织的通信方式开始这种沟通，无论是通过电子邮件分发列表、小组讨论、IT 圆桌会议还是定期安排的会议。

您还可以在您的组织内安排聚会，让人们开始交流。这些聚会旨在不仅包括您的组织，还包括您所在的城市或镇的成员，以便更广泛地传播和推广服务。

您可以通过访问以下网址搜索您所在地区是否已经有聚会：[`www.docker.com/community/meetup-groups/`](https://www.docker.com/community/meetup-groups/)。

# 云原生计算基金会

我们在第九章“Docker 和 Kubernetes”中简要讨论了云原生计算基金会。云原生计算基金会，简称 CNCF，旨在为允许您管理容器和微服务架构的项目提供一个供应商中立的家园。

其成员包括 Docker、亚马逊网络服务、谷歌云、微软 Azure、红帽、甲骨文、VMWare 和 Digital Ocean 等。2018 年 6 月，Linux 基金会报告称 CNCF 有 238 名成员。这些成员不仅贡献项目，还贡献工程时间、代码和资源。

# 毕业项目

在撰写本书时，有两个毕业项目，这两个项目我们在之前的章节中已经讨论过。这两个项目可以说也是基金会维护的项目中最知名的两个，它们分别是：

+   **Kubernetes** ([`kubernetes.io`](https://kubernetes.io))：这是第一个捐赠给基金会的项目。正如我们已经提到的，它最初是由 Google 开发的，现在在基金会成员和开源社区中拥有超过 2300 名贡献者。

+   **Prometheus** ([`prometheus.io`](https://prometheus.io))：这个项目是由 SoundCloud 捐赠给基金会的。正如我们在第十三章“Docker 工作流”中所看到的，它是一个实时监控和警报系统，由强大的时间序列数据库引擎支持。

要毕业，一个项目必须完成以下工作：

+   采用了类似于 Docker 发布的 CNCF 行为准则。完整的行为准则可以在以下网址找到：[`github.com/cncf/foundation/blob/master/code-of-conduct.md`](https://github.com/cncf/foundation/blob/master/code-of-conduct.md)。

+   获得了**Linux 基金会**（**LF**）**核心基础设施倡议**（**CII**）最佳实践徽章，证明该项目正在使用一套成熟的最佳实践进行开发 - 完整的标准可以在以下网址找到：[`github.com/coreinfrastructure/best-practices-badge/blob/master/doc/criteria.md`](https://github.com/coreinfrastructure/best-practices-badge/blob/master/doc/criteria.md)。

+   至少收购了两家有项目提交者的组织。

+   通过`GOVERNANCE.md`和`OWNERS.md`文件公开定义了提交者流程和项目治理。

+   在`ADOPTERS.md`文件中公开列出项目的采用者，或者在项目网站上使用标志。

+   获得了**技术监督委员会**（**TOC**）的超级多数票。您可以在以下网址了解更多关于该委员会的信息：[`github.com/cncf/toc`](https://github.com/cncf/toc)。

还有另一种项目状态，目前大多数项目都处于这种状态。

# 项目孵化

处于孵化阶段的项目最终应该具有毕业生的地位。以下项目都做到了以下几点：

+   证明该项目至少被三个独立的最终用户使用（不是项目发起者）。

+   获得了大量的贡献者，包括内部和外部。

+   展示了成长和良好的成熟水平。

技术指导委员会（TOC）积极参与与项目合作，以确保活动水平足以满足前述标准，因为指标可能因项目而异。

当前的项目列表如下：

+   **OpenTracing** ([`opentracing.io/`](https://opentracing.io/))：这是两个跟踪项目中的第一个，现在都属于 CNCF。与其说是一个应用程序，不如说你可以下载并使用它作为一组库和 API，让你在基于微服务的应用程序中构建行为跟踪和监控。

+   Fluentd（[`www.fluentd.org`](https://www.fluentd.org)）：这个工具允许您从大量来源收集日志数据，然后将日志数据路由到多个日志管理、数据库、归档和警报系统，如 Elastic Search、AWS S3、MySQL、SQL Server、Hadoop、Zabbix 和 DataDog 等。

+   gRPC（[`grpc.io`](https://grpc.io)）：与 Kubernetes 一样，gRPC 是由谷歌捐赠给 CNCF 的。它是一个开源、可扩展和性能优化的 RPC 框架，已经在 Netflix、思科和 Juniper Networks 等公司投入使用。

+   Containerd（[`containerd.io`](https://containerd.io)）：我们在第一章《Docker 概述》中简要提到了 Containerd，作为 Docker 正在开发的开源项目之一。它是一个标准的容器运行时，允许开发人员在其平台或应用程序中嵌入一个可以管理 Docker 和 OCI 兼容镜像的运行时。

+   Rkt（[`github.com/rkt/rkt`](https://github.com/rkt/rkt)）：Rkt 是 Docker 容器引擎的替代品。它不是使用守护程序来管理主机系统上的容器，而是使用命令行来启动和管理容器。它是由 CoreOS 捐赠给 CNCF 的，现在由 Red Hat 拥有。

+   CNI（[`github.com/containernetworking`](https://github.com/containernetworking)）：CNI 是 Container Networking Interface 的缩写，再次强调它不是您下载和使用的东西。相反，它是一种网络接口标准，旨在嵌入到容器运行时中，如 Kubernetes、Rkt 和 Mesos。拥有一个共同的接口和一组 API 允许通过第三方插件和扩展在这些运行时中更一致地支持高级网络功能。

+   Envoy（[`www.envoyproxy.io`](https://www.envoyproxy.io)）：最初在 Lyft 内部创建，并被苹果、Netflix 和谷歌等公司使用，Envoy 是一个高度优化的服务网格，提供负载均衡、跟踪和可观察数据库和网络活动的环境。

+   Jaeger（[`jaegertracing.io`](https://jaegertracing.io)）：这是列表中的第二个跟踪系统。与 OpenTracing 不同，它是一个完全分布式的跟踪系统，最初由 Uber 开发，用于监视其庞大的微服务环境。现在被 Red Hat 等公司使用，具有现代化的用户界面和对 OpenTracing 和各种后端存储引擎的本地支持。它旨在与其他 CNCF 项目（如 Kubernetes 和 Prometheus）集成。

+   Notary（[`github.com/theupdateframework/notary`](https://github.com/theupdateframework/notary)）：该项目最初由 Docker 编写，是 TUF 的实现，接下来我们将介绍 TUF。它旨在允许开发人员通过提供一种机制来验证其容器映像和内容的来源，签署其容器映像。

+   TUF（[`theupdateframework.github.io`](https://theupdateframework.github.io)）：**The Update Framework**（TUF）是一种标准，允许软件产品通过使用加密密钥在安装和更新过程中保护自己。它是由纽约大学工程学院开发的。

+   Vitess（[`vitess.io`](https://vitess.io)）：自 2011 年以来，Vitess 一直是 YouTube 的 MySQL 数据库基础设施的核心组件。它是一个通过分片水平扩展 MySQL 的集群系统。

+   CoreDNS（[`coredns.io`](https://coredns.io)）：这是一个小巧、灵活、可扩展且高度优化的 DNS 服务器，使用 Go 语言编写，并从头开始设计，可以在运行数千个容器的基础设施中运行。

+   NATS（[`nats.io`](https://nats.io)）：这里有一个为运行微服务或支持物联网设备的架构设计的消息传递系统。

+   Linkerd（[`linkerd.io`](https://linkerd.io)）：由 Twitter 开发，Linkerd 是一个服务网格，旨在扩展并处理每秒数万个安全请求。

+   Helm（[`www.helm.sh`](https://www.helm.sh)）：针对 Kubernetes 构建，Helm 是一个软件包管理器，允许用户将其 Kubernetes 应用程序打包成易于分发的格式，并迅速成为标准。

+   **Rook** ([`rook.io`](https://rook.io))：目前，Rook 正处于早期开发阶段，专注于为 Kubernetes 上的 Ceph（Red Hat 的分布式存储系统）提供编排层。最终，它将扩展以支持其他分布式块和对象存储系统。

我们在本书的各个章节中使用了其中一些项目，我相信其他项目也会引起您的兴趣，因为您正在寻找解决诸如路由到您的容器和监视您的应用程序在您的环境中的问题。

# CNCF 景观

CNCF 提供了一个交互式地图，显示了他们和他们成员管理的所有项目，网址为[`landscape.cncf.io/`](https://landscape.cncf.io)。以下是其中一个关键要点：

<q>您正在查看 590 张卡片，总共有 1,227,036 颗星星，市值为 6.52 万亿美元，融资为 16.3 亿美元。</q>

虽然我相信您会同意这些数字非常令人印象深刻，但这有什么意义呢？多亏了 CNCF 的工作，我们有了一些项目，比如 Kubernetes，它们为跨多个云基础设施提供了一套标准化的工具、API 和方法，还可以在本地和裸金属服务上提供构建块，让您创建和部署自己的高可用、可扩展和高性能的容器和微服务应用程序。

# 摘要

我希望本章让您对您的容器之旅中可以采取的下一步有所了解。我发现，虽然简单地使用这些服务很容易，但通过成为围绕各种软件和项目形成的大型、友好和热情的开发人员和其他用户社区的一部分，您可以获得更多收益，这些人和您一样。

这种社区和合作的意识得到了云原生计算基金会的进一步加强。这将大型企业聚集在一起，直到几年前，他们不会考虑与其他被视为竞争对手的企业在大型项目上进行公开合作。
