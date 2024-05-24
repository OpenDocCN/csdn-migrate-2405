# Docker 秘籍（二）

> 原文：[`zh.annas-archive.org/md5/3BDF7E02FD45D3E3DF6846ABA9F12FB8`](https://zh.annas-archive.org/md5/3BDF7E02FD45D3E3DF6846ABA9F12FB8)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第四章：容器的网络和数据管理

在本章中，我们将涵盖以下内容：

+   从外部访问容器

+   管理容器中的数据

+   连接两个或多个容器

+   通过链接容器开发 LAMP 应用程序

+   使用 Flannel 进行多主机容器的网络

+   为容器分配 IPv6 地址

# 介绍

到目前为止，我们已经使用单个容器并在本地访问它。但是随着我们转向更多的真实用例，我们将需要从外部世界访问容器，在容器内共享外部存储，与在其他主机上运行的容器通信等。在本章中，我们将看到如何满足其中一些要求。让我们首先了解 Docker 的默认网络设置，然后转向高级用例。

当 Docker 守护程序启动时，它会创建一个名为`docker0`的虚拟以太网桥。例如，我们将在运行 Docker 守护程序的系统上使用`ip addr`命令看到以下内容：

![介绍](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-cb/img/image00314.jpeg)

正如我们所看到的，`docker0`的 IP 地址为 172.17.42.1/16。Docker 随机选择一个地址和子网，来自 RFC 1918（[`tools.ietf.org/html/rfc1918`](https://tools.ietf.org/html/rfc1918)）中定义的私有范围。使用这个桥接接口，容器可以彼此通信，也可以与主机系统通信。

默认情况下，每次 Docker 启动一个容器，它都会创建一对虚拟接口，其中一端连接到主机系统，另一端连接到创建的容器。让我们启动一个容器，看看会发生什么：

![介绍](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-cb/img/image00315.jpeg)

连接到容器的`eth0`接口的一端获得了 172.17.0.1/16 的 IP 地址。我们还在主机系统上的接口的另一端看到了以下条目：

![介绍](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-cb/img/image00316.jpeg)

现在，让我们创建更多的容器，并使用管理以太网桥的`brctl`命令查看`docker0`桥接：

![介绍](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-cb/img/image00317.jpeg)

每个 veth*都绑定到`docker0`桥接，这样就在主机和每个 Docker 容器之间创建了一个虚拟子网。除了设置`docker0`桥接之外，Docker 还创建了 IPtables NAT 规则，以便所有容器默认可以与外部世界通信，但反之则不行。让我们看看 Docker 主机上的 NAT 规则：

![介绍](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-cb/img/image00318.jpeg)

如果我们尝试从容器连接到外部世界，我们将不得不通过默认创建的 Docker 桥：

![介绍](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-cb/img/image00319.jpeg)

在本章的后面，我们将看到外部世界如何连接到容器。

在启动容器时，我们有几种模式可以选择其网络：

+   `--net=bridge`：这是我们刚刚看到的默认模式。因此，我们用来启动容器的前面的命令可以写成如下形式：

```
$ docker run -i -t --net=bridge centos /bin/bash 

```

+   `--net=host`：使用此选项，Docker 不会为容器创建网络命名空间；相反，容器将与主机进行网络堆栈。因此，我们可以使用以下选项启动容器：

```
 $ docker run -i -t  --net=host centos bash 

```

然后我们可以在容器内运行`ip addr`命令，如下所示：

![介绍](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-cb/img/image00320.jpeg)

我们可以看到所有连接到主机的网络设备。使用这种配置的一个例子是在容器中运行`nginx`反向代理，以提供在主机上运行的 Web 应用程序。

+   `--net=container:NAME_or_ID`：使用此选项，Docker 在启动容器时不会创建新的网络命名空间，而是从另一个容器中共享它。让我们启动第一个容器并查找其 IP 地址：

```
$ docker run -i -t --name=centos centos bash 

```

![介绍](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-cb/img/image00321.jpeg)

现在开始另一个如下：

```
$ docker run -i -t --net=container:centos ubuntu bash 

```

![介绍](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-cb/img/image00322.jpeg)

正如我们所看到的，两个容器包含相同的 IP 地址。

Kubernetes（[`kubernetes.io/`](http://kubernetes.io/)）Pod 中的容器使用此技巧来相互连接。我们将在第八章中重新讨论这个问题，*Docker 编排和托管平台*。

+   `--net=none`：使用此选项，Docker 在容器内创建网络命名空间，但不配置网络。

### 注意

有关我们在前面部分讨论的不同网络的更多信息，请访问[`docs.docker.com/articles/networking/#how-docker-networks-a-container`](https://docs.docker.com/articles/networking/#how-docker-networks-a-container)。

从 Docker 1.2 版本开始，还可以在运行的容器上更改`/etc/host`、`/etc/hostname`和`/etc/resolv.conf`。但是，请注意，这些只是用于运行容器。如果重新启动，我们将不得不再次进行更改。

到目前为止，我们已经在单个主机上查看了网络，但在现实世界中，我们希望连接多个主机，并且让一个主机上的容器与另一个主机上的容器进行通信。Flannel ([`github.com/coreos/flannel`](https://github.com/coreos/flannel))，Weave ([`github.com/weaveworks/weave`](https://github.com/weaveworks/weave))，Calio ([`www.projectcalico.org/getting-started/docker/`](http://www.projectcalico.org/getting-started/docker/))和 Socketplane ([`socketplane.io/`](http://socketplane.io/))是一些提供此功能的解决方案。在本章的后面，我们将看到如何配置 Flannel 进行多主机网络。Socketplane 于'15 年 3 月加入了 Docker Inc。

社区和 Docker 正在构建一个**容器网络模型**（**CNM**）与 libnetwork ([`github.com/docker/libnetwork`](https://github.com/docker/libnetwork))，它提供了一个原生的 Go 实现来连接容器。有关此开发的更多信息，请访问[`blog.docker.com/2015/04/docker-networking-takes-a-step-in-the-right-direction-2/`](http://blog.docker.com/2015/04/docker-networking-takes-a-step-in-the-right-direction-2/)。

# 从外部访问容器

一旦容器启动，我们希望从外部访问它。如果您使用`--net=host`选项启动容器，则可以通过 Docker 主机 IP 访问它。使用`--net=none`，您可以通过公共端口或其他复杂的设置附加网络接口。让我们看看默认情况下会发生什么——从主机网络接口转发数据包到容器。

## 准备工作

确保 Docker 守护程序在主机上运行，并且您可以通过 Docker 客户端进行连接。

## 如何做…

1.  让我们使用`-P`选项启动一个容器：

```
$ docker run --expose 80 -i -d -P --name f20 fedora /bin/bash 

```

![如何做…](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-cb/img/image00323.jpeg)

这会自动将容器的任何网络端口映射到 Docker 主机的 49000 到 49900 之间的随机高端口。

在`PORTS`部分，我们看到`0.0.0.0:49159->80/tcp`，格式如下：

```
<Host Interface>:<Host Port> -> <Container Interface>/<protocol> 

```

因此，如果来自 Docker 主机上任何接口的端口`49159`的任何请求，请求将被转发到`centos1`容器的端口`80`。

我们还可以使用`-p`选项将容器的特定端口映射到主机的特定端口：

```
$  docker run -i -d -p 5000:22 --name centos2 centos /bin/bash 

```

![如何做…](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-cb/img/image00324.jpeg)

在这种情况下，来自 Docker 主机上任何接口的端口`5000`的所有请求都将被转发到`centos2`容器的端口`22`。

## 工作原理…

使用默认配置，Docker 设置防火墙规则，将连接从主机转发到容器，并在 Docker 主机上启用 IP 转发：

![工作原理…](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-cb/img/image00325.jpeg)

如前面的例子所示，已经设置了一个`DNAT`规则，将主机上端口`5000`的所有流量转发到容器的端口`22`。

## 还有更多…

默认情况下，使用`-p`选项，Docker 将所有请求转发到主机的任何接口。要绑定到特定接口，可以指定如下内容：

```
$ docker run -i -d -p 192.168.1.10:5000:22 --name f20 fedora /bin/bash 

```

在这种情况下，只有来自 Docker 主机上 IP 为`192.168.1.10`的接口的端口`5000`的所有请求都将被转发到`f20`容器的端口`22`。要将容器的端口`22`映射到主机的动态端口，可以运行以下命令：

```
$ docker run -i -d -p 192.168.1.10::22 --name f20 fedora /bin/bash 

```

我们可以将容器上的多个端口绑定到主机上的端口，如下所示：

```
$  docker run -d -i -p 5000:22 -p 8080:80 --name f20 fedora /bin/bash 

```

我们可以查找映射到容器端口的公共端口，如下所示：

```
$ docker port f20 80 
0.0.0.0:8080 

```

要查看容器的所有网络设置，可以运行以下命令：

```
$ docker inspect   -f "{{ .NetworkSettings }}" f20 

```

## 另请参阅

+   Docker 网站上的网络文档：[`docs.docker.com/articles/networking/`](https://docs.docker.com/articles/networking/)。

# 在容器中管理数据

当容器被删除时，任何未提交的数据或容器中的更改都会丢失。例如，如果您在容器中配置了 Docker 注册表并推送了一些镜像，那么一旦注册表容器被删除，所有这些镜像都会丢失，如果您没有提交它们。即使您提交了，也不是最佳做法。我们应该尽量保持容器的轻量化。以下是两种主要的管理 Docker 数据的方法：

+   **数据卷**：来自 Docker 文档([`docs.docker.com/userguide/dockervolumes/`](https://docs.docker.com/userguide/dockervolumes/))，数据卷是一个专门指定的目录，位于一个或多个容器中，绕过联合文件系统，提供了几个有用的特性，用于持久或共享数据：

+   在创建容器时初始化卷。如果容器的基本镜像包含指定挂载点的数据，则该数据将被复制到新卷中。

+   数据卷可以在容器之间共享和重复使用。

+   对数据卷的更改是直接进行的。

+   对数据卷的更改不会在更新镜像时包含在内。

+   数据卷会持久存在，直到没有容器在使用它们。

+   **数据卷容器**：由于卷会持久存在，直到没有容器在使用它，我们可以使用卷在容器之间共享持久数据。因此，我们可以创建一个命名的数据卷容器，并将数据挂载到另一个容器中。

## 准备工作

确保 Docker 守护程序在主机上运行，并且可以通过 Docker 客户端进行连接。

## 如何做...

1.  添加数据卷。使用`docker run`命令的`-v`选项，我们向容器添加数据卷：

```
$ docker run -t -d -P -v /data --name f20 fedora /bin/bash 

```

我们可以在容器中拥有多个数据卷，可以通过多次添加`-v`来创建：

```
$ docker run -t -d -P -v /data -v /logs --name f20 fedora /bin/bash 

```

### 提示

`VOLUME`指令可以在 Dockerfile 中使用，通过添加类似于`VOLUME ["/data"]`的内容来添加数据卷。

我们可以使用`inspect`命令查看容器的数据卷详细信息：

```
$ docker inspect -f "{{ .Config.Volumes }}" f20 
$ docker inspect -f "{{ .Volumes }}" f20 

```

![如何做...](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-cb/img/image00326.jpeg)

如果容器中不存在目标目录，它将被创建。

1.  接下来，我们将主机目录挂载为数据卷。我们还可以使用`-v`选项将主机目录映射到数据卷：

```
$ docker run -i -t -v /source_on_host:/destination_on_container fedora /bin/bash 

```

考虑以下示例：

```
$ docker run -i -t -v /srv:/mnt/code fedora /bin/bash 

```

在不同环境中测试代码、在中央位置收集日志等情况下，这可能非常有用。我们还可以按照以下方式将主机目录映射为只读模式：

```
$ docker run -i -t -v /srv:/mnt/code:ro fedora /bin/bash 

```

我们还可以使用以下命令将主机的整个根文件系统挂载到容器中：

```
$ docker run -i -t -v /:/host:ro fedora /bin/bash 

```

如果主机上的目录（`/srv`）不存在，则将创建它，前提是您有权限创建。此外，在启用 SELinux 的 Docker 主机上，如果 Docker 守护程序配置为使用 SELinux（`docker -d --selinux-enabled`），则在尝试访问挂载卷上的文件之前，如果您尝试访问挂载卷上的文件，您将看到`permission denied`错误。要重新标记它们，请使用以下命令之一：

```
$ docker run -i -t -v /srv:/mnt/code:z fedora /bin/bash 
$ docker run -i -t -v /srv:/mnt/code:Z fedora /bin/bash 

```

请访问第九章，*Docker 安全性*，以获取更多详细信息。

1.  现在，创建一个数据卷容器。通过卷共享主机目录到容器时，我们将容器绑定到给定的主机，这是不好的。此外，在这种情况下，存储不受 Docker 控制。因此，在我们希望数据持久化即使更新容器时，我们可以从数据卷容器获得帮助。数据卷容器用于创建卷，仅此而已；它们甚至不运行。由于创建的卷附加到容器（未运行），因此无法删除。例如，这是一个命名的数据容器：

```
$ docker run -d -v /data --name data fedora echo "data volume container" 

```

这将只创建一个将映射到 Docker 管理的目录的卷。现在，其他容器可以使用`--volumes-from`选项从数据容器中挂载卷，如下所示：

```
$ docker run  -d -i -t --volumes-from data --name client1 fedora /bin/bash 

```

我们可以从数据卷容器挂载卷到多个容器：

```
$ docker run  -d -i -t --volumes-from data --name client2 fedora /bin/bash 

```

![如何做...](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-cb/img/image00327.jpeg)

我们还可以多次使用`--volumes-from`来从多个容器获取数据卷。我们还可以通过从某个其他容器挂载卷的容器来创建链。

## 它是如何工作的...

在数据卷的情况下，当主机目录未共享时，Docker 在`/var/lib/docker/`中创建一个目录，然后与其他容器共享。

## 还有更多...

+   使用`-v`标志删除卷以`docker rm`，只有当没有其他容器在使用它时。如果其他容器正在使用卷，则容器将被删除（使用`docker rm`），但卷将不会被删除。

+   在上一章中，我们看到了如何配置 Docker 注册表，默认情况下以`dev` flavor 启动。在此注册表中，上传的图像保存在我们启动的容器中的`/tmp/registry`文件夹中。我们可以在注册表容器中挂载主机上的`/tmp/registry`目录，因此每当我们上传图像时，它将保存在运行 Docker 注册表的主机上。因此，要启动容器，我们运行以下命令：

```
$ docker run -v /srv:/tmp/registry -p 5000:5000 registry 

```

要推送图像，我们运行以下命令：

```
$ docker push registry-host:5000/nkhare/f20 

```

成功推送图像后，我们可以查看我们在 Docker 注册表中挂载的目录的内容。在我们的情况下，我们应该看到以下目录结构：

```
/srv/
├── images 
│   ├── 3f2fed40e4b0941403cd928b6b94e0fd236dfc54656c00e456747093d10157ac 
│   │   ├── ancestry 
│   │   ├── _checksum 
│   │   ├── json 
│   │   └── layer 
│   ├── 511136ea3c5a64f264b78b5433614aec563103b4d4702f3ba7d4d2698e22c158 
│   │   ├── ancestry 
│   │   ├── _checksum 
│   │   ├── json 
│   │   └── layer 
│   ├── 53263a18c28e1e54a8d7666cb835e9fa6a4b7b17385d46a7afe55bc5a7c1994c 
│   │   ├── ancestry 
│   │   ├── _checksum 
│   │   ├── json 
│   │   └── layer 
│   └── fd241224e9cf32f33a7332346a4f2ea39c4d5087b76392c1ac5490bf2ec55b68 
│       ├── ancestry 
│       ├── _checksum 
│       ├── json 
│       └── layer 
├── repositories 
│   └── nkhare 
│       └── f20 
│           ├── _index_images 
│           ├── json 
│           ├── tag_latest 
│           └── taglatest_json 
```

## 另请参阅

+   Docker 网站上的文档位于[`docs.docker.com/userguide/dockervolumes/`](https://docs.docker.com/userguide/dockervolumes/)

+   [`container42.com/2013/12/16/persistent-volumes-with-docker-container-as-volume-pattern/`](http://container42.com/2013/12/16/persistent-volumes-with-docker-container-as-volume-pattern/)

+   [`container42.com/2014/11/03/docker-indepth-volumes/`](http://container42.com/2014/11/03/docker-indepth-volumes/)

# 链接两个或更多个容器

通过容器化，我们希望通过在不同的容器上运行服务，然后将它们链接在一起来创建我们的堆栈。在上一章中，我们通过将 Web 服务器和数据库放在同一个容器中来创建了一个 WordPress 容器。但是，我们也可以将它们放在不同的容器中并将它们链接在一起。容器链接在它们之间创建了一个父子关系，其中父容器可以看到其子容器的选定信息。链接依赖于容器的命名。

## 准备工作

确保 Docker 守护程序在主机上运行，并且您可以通过 Docker 客户端进行连接。

## 如何操作…

1.  创建一个名为`centos_server`的命名容器：

```
$ docker run  -d -i -t --name centos_server centos /bin/bash 

```

如何操作…

1.  现在，让我们使用`--link`选项启动另一个名为 client 的容器，并将其与`centos_server`容器进行链接，该选项接受`name:alias`参数。然后查看`/etc/hosts`文件：

```
$ docker run  -i -t --link centos_server:server --name client fedora /bin/bash 

```

如何操作…

## 工作原理…

在上面的例子中，我们使用别名 server 将`centos_server`容器链接到客户端容器。通过链接这两个容器，第一个容器（在本例中为`centos_server`）的条目将被添加到客户端容器的`/etc/hosts`文件中。此外，在客户端中设置了一个名为`SERVER_NAME`的环境变量来引用服务器。

工作原理…

## 还有更多…

现在，让我们创建一个`mysql`容器：

```
$ docker run --name mysql -e MYSQL_ROOT_PASSWORD=mysecretpassword -d mysql 

```

然后，让我们从客户端链接它并检查环境变量：

```
$ docker run  -i -t --link mysql:mysql-server --name client fedora /bin/bash 

```

还有更多…

还让我们看一下`docker ps`的输出：

还有更多…

如果仔细观察，我们在启动`client`容器时没有指定`-P`或`-p`选项来映射两个容器之间的端口。根据容器暴露的端口，Docker 在链接到它的容器之间创建了一个内部安全隧道。为此，Docker 在链接器容器内设置环境变量。在前面的情况下，`mysql`是链接的容器，client 是链接器容器。由于`mysql`容器暴露端口`3306`，我们在客户端容器内看到相应的环境变量（`MYSQL_SERVER_*`）。

### 提示

由于链接取决于容器的名称，如果要重用名称，必须删除旧容器。

## 另请参阅

+   在 Docker 网站上的文档，请访问[`docs.docker.com/userguide/dockerlinks/`](https://docs.docker.com/userguide/dockerlinks/)

# 通过链接容器开发 LAMP 应用程序

让我们通过链接容器来扩展先前的食谱，创建一个 LAMP 应用程序（WordPress）。

## 准备工作

从 Docker 注册表中拉取 MySQL 和 WordPress 镜像：

+   对于 MySQL：

+   有关镜像，请访问[`registry.hub.docker.com/_/mysql/`](https://registry.hub.docker.com/_/mysql/)

+   对于 Dockerfile，请访问[`github.com/docker-library/docker-mysql`](https://github.com/docker-library/docker-mysql)

+   对于 WordPress：

+   有关镜像，请访问[`registry.hub.docker.com/_/wordpress/`](https://registry.hub.docker.com/_/wordpress/)

+   对于 Dockerfile，请访问[`github.com/docker-library/wordpress`](https://github.com/docker-library/wordpress)

## 如何做...

1.  首先，启动一个`mysql`容器：

```
$ docker run --name mysql -e MYSQL_ROOT_PASSWORD=mysecretpassword -d mysql 

```

1.  然后，启动`wordpress`容器并将其与`mysql`容器链接起来：

```
$ docker run -d --name wordpress --link mysql:mysql -p 8080:80 wordpress 

```

![如何做...](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-cb/img/image00333.jpeg)

我们将 Docker 主机的`8080`端口映射到容器的`80`端口，因此我们可以通过访问 Docker 主机上的`8080`端口和`http://<DockerHost>:8080` URL 来连接 WordPress。

## 它是如何工作的...

在`wordpress`和`mysql`容器之间创建了一个链接。每当`wordpress`容器收到一个数据库请求时，它将其传递给`mysql`容器并获取结果。查看前面的食谱以获取更多详细信息。

# 使用 Flannel 进行多主机容器的网络连接

在这个教程中，我们将使用 Flannel ([`github.com/coreos/flannel`](https://github.com/coreos/flannel)) 来设置多主机容器网络。Flannel 是一个通用的覆盖网络，可以作为**软件定义网络**（**SDN**）的替代方案。它是一个基于 IP 的解决方案，使用**虚拟可扩展局域网**（**VXLAN**），为运行该容器的主机分配唯一的 IP 地址。因此，在这种解决方案中，每个主机在集群中使用覆盖网络内的不同子网进行通信。Flannel 使用`etcd`服务 ([`github.com/coreos/etcd`](https://github.com/coreos/etcd)) 作为键值存储。

## 准备工作

对于这个教程，我们将需要安装了 Fedora 21 的三个虚拟机或物理机。

## 如何做…

1.  让我们称一台机器/虚拟机为`master`，另外两台为`minion1`和`minion2`。根据您系统的 IP 地址，更新`/etc/hosts`文件如下：![如何做…](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-cb/img/image00334.jpeg)

1.  在我们设置的所有系统上安装`etcd`、`Flannel`和`Docker`：

```
$ yum install -y etcd flannel docker 

```

1.  在`/etc/etcd/etcd.conf`文件中将`ETCD_LISTEN_CLIENT_URLS`的值修改为`http://master.example.com:4001`如下：

```
ETCD_LISTEN_CLIENT_URLS="http://master.example.com:4001"
```

1.  在 master 中，启动`etcd`服务并检查其状态：

```
$ systemctl start etcd 
$ systemctl enable etcd 
$ systemctl status etcd 

```

1.  在 master 中，创建一个名为`flannel-config.json`的文件，内容如下：

```
{
"Network": "10.0.0.0/16",
"SubnetLen": 24,
"Backend": {
"Type": "vxlan",
"VNI": 1
   }
}
```

1.  使用`config`作为键将上述配置文件上传到`etcd`：

```
$ curl -L http://master.example.com:4001/v2/keys/coreos.com/network/config -XPUT --data-urlencode value@flannel-config.json 

```

![如何做…](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-cb/img/image00335.jpeg)

1.  在 master 中，更新`/etc/sysconfig/flanneld`文件中的`FLANNEL_OPTIONS`以反映系统的接口。同时，更新`FLANNEL_ETCD`以使用主机名而不是 127.0.0.1:4001 地址。![如何做…](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-cb/img/image00336.jpeg)

1.  在 master 中，启用和启动`flanneld`服务：

```
$ systemctl enable flanneld 
$ systemctl start flanneld 
$ systemctl status flanneld 

```

![如何做…](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-cb/img/image00337.jpeg)

1.  从 minion 系统中，检查对`etcd`的与 master 的连接：

```
[root@minion1 ~]#  curl -L http://master.example.com:4001/v2/keys/coreos.com/network/config 

```

1.  更新两个 minion 中的`/etc/sysconfig/flanneld`文件，指向 master 中运行的`etcd`服务器，并更新`FLANNEL_OPTIONS`以反映 minion 主机的接口：![如何做…](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-cb/img/image00338.jpeg)

1.  在两个 minion 中启用和启动`flanneld`服务：

```
$ systemctl enable flanneld 
$ systemctl start flanneld 
$ systemctl status flanneld 

```

1.  在集群中的任何一台主机上运行以下命令：

```
$ curl -L http://master.example.com:4001/v2/keys/coreos.com/network/subnets | python -mjson.tool 

```

![如何做…](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-cb/img/image00339.jpeg)

这告诉我们网络中主机的数量以及与它们关联的子网（查看每个节点的密钥）。我们可以将子网与主机上的 MAC 地址关联起来。在每个主机上，`/run/flannel/docker`和`/run/flannel/subnet.env`文件中填充了子网信息。例如，在`minion2`中，你会看到类似以下内容：

![如何做…](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-cb/img/image00340.jpeg)

1.  要在所有主机中重新启动 Docker 守护程序：

```
$ systemctl restart docker 

```

然后，查看`docker0`和`flannel.1`接口的 IP 地址。在`minion2`中，看起来像下面这样：

![如何做…](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-cb/img/image00341.jpeg)

我们可以看到`docker0`接口从与`flannel.1`接口相同的子网中获取了 IP，该子网用于路由所有流量。

1.  我们已经准备好在任何主机中生成两个容器，并且它们应该能够进行通信。让我们在`minion1`中创建一个容器并获取其 IP 地址：![如何做…](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-cb/img/image00342.jpeg)

1.  现在在`minion2`中创建另一个容器，并像下面这样 ping`minion1`中运行的容器：![如何做…](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-cb/img/image00343.jpeg)

## 工作原理…

使用 Flannel，我们首先使用`10.0.0.0/16`网络配置覆盖。然后，每个主机选择一个随机的`/24`网络；例如，在我们的情况下，`minion2`获取`10.0.62.0/24`子网等等。配置完成后，主机中的容器将从所选的子网中获取 IP 地址。Flannel 封装数据包并使用 UDP 将其发送到远程主机。

此外，在安装过程中，Flannel 会在`/usr/lib/systemd/system/docker.service.d/`中复制一个配置文件（`flannel.conf`），Docker 使用该文件进行配置。

## 另请参阅

+   Flannel GitHub 上的图表可帮助您了解操作理论，网址为[`github.com/coreos/flannel/blob/master/packet-01.png`](https://github.com/coreos/flannel/blob/master/packet-01.png)

+   CoreOS 网站上的文档位于[`coreos.com/blog/introducing-rudder/`](https://coreos.com/blog/introducing-rudder/)

+   Scott Collier 在 Fedora 上设置 Flannel 的博客文章位于[`www.colliernotes.com/2015/01/flannel-and-docker-on-fedora-getting.html`](http://www.colliernotes.com/2015/01/flannel-and-docker-on-fedora-getting.html)

# 为容器分配 IPv6 地址

默认情况下，Docker 为容器分配 IPv4 地址。Docker 1.5 添加了一个功能来支持 IPv6 地址。

## 准备工作

确保 Docker 守护进程（1.5 版本及以上）正在主机上运行，并且您可以通过 Docker 客户端进行连接。

## 如何操作...

1.  使用`--ipv6`选项启动 Docker 守护进程，我们可以在守护进程的配置文件（在 Fedora 上为`/etc/sysconfig/docker`）中添加以下选项：

```
OPTIONS='--selinux-enabled --ipv6' 

```

或者，如果我们以守护进程模式启动 Docker，那么可以按以下方式启动：

```
$ docker -d --ipv6 

```

通过运行这些命令之一，Docker 将使用 IPv6 本地链路地址`fe80::1`设置`docker0`桥。

![如何操作...](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-cb/img/image00344.jpeg)

1.  让我们启动容器并查找分配给它的 IP 地址：![如何操作...](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-cb/img/image00345.jpeg)

正如我们所看到的，容器可以获得 IPv4 和本地链路 IPv6 地址。要从主机机器上 ping 容器的 IPv6 地址，请运行以下命令：

```
$ ping6 -I docker0 fe80::42:acff:fe11:3 

```

要从容器中 ping`docker0`桥，请运行以下命令：

```
[root@c7562c38bd0f /]# ping6 -I eth0 fe80::1 

```

## 工作原理...

Docker 配置`docker0`桥以向容器分配 IPv6 地址，这使我们能够使用容器的 IPv6 地址。

## 更多信息...

默认情况下，容器将获得链路本地地址。要为它们分配全局可路由地址，可以通过`--fixed-cidr-v6`选项传递 IPv6 子网选择地址，如下所示：

```
$ docker -d --ipv6 --fixed-cidr-v6="2001:db8:1::/64" 

```

![更多信息...](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-cb/img/image00346.jpeg)

从这里，我们可以看到全局可路由地址（GlobalIPv6Address）现在已经设置。

## 另请参阅

+   有关 Docker 1.5 版本的发布说明，请访问[`blog.docker.com/2015/02/docker-1-5-ipv6-support-read-only-containers-stats-named-dockerfiles-and-more/`](https://blog.docker.com/2015/02/docker-1-5-ipv6-support-read-only-containers-stats-named-dockerfiles-and-more/)。

+   有关 Docker 网站上的文档，请访问[`docs.docker.com/v1.5/articles/networking/#ipv6`](http://docs.docker.com/v1.5/articles/networking/#ipv6)。

+   在设置 IPv6 选项之前，您可能需要删除主机上现有的`docker0`桥接。要了解如何操作，请访问[`docs.docker.com/v1.5/articles/networking/#customizing-docker0`](http://docs.docker.com/v1.5/articles/networking/#customizing-docker0)。


# 第五章：Docker 使用案例

在本章中，我们将涵盖以下配方：

+   使用 Docker 进行测试

+   使用 Shippable 和 Red Hat OpenShift 进行 CI/CD

+   使用 Drone 进行 CI/CD

+   使用 OpenShift Origin 设置 PaaS

+   在 OpenShift v3 上构建和部署应用程序的源代码

+   将 Docker 配置为 Openstack 的 hypervisor 驱动程序

# 介绍

现在我们知道如何使用容器和镜像。在上一章中，我们还看到了如何链接容器并在主机和其他容器之间共享数据。我们还看到了来自一个主机的容器如何与其他主机的容器进行通信。

现在让我们看看 Docker 的不同用例。这里列举了其中的一些：

+   **快速原型设计**：这是我最喜欢的用例之一。一旦我们有了一个想法，使用 Docker 很容易进行原型设计。我们所需要做的就是设置容器来提供我们需要的所有后端服务，并将它们连接在一起。例如，要设置一个 LAMP 应用程序，获取 Web 和 DB 服务器并将它们链接在一起，就像我们在上一章中看到的那样。

+   **协作和分发**：GitHub 是协作和分发代码的最佳示例之一。同样，Docker 提供了 Dockerfile、注册表和导入/导出等功能，以与他人共享和协作。我们在之前的章节中已经涵盖了所有这些内容。

+   **持续集成**（**CI**）：Martin Fowler 网站上的以下定义（[`www.martinfowler.com/articles/continuousIntegration.html`](http://www.martinfowler.com/articles/continuousIntegration.html)）涵盖了所有内容：

> *"持续集成是一个软件开发实践，团队成员经常集成他们的工作，通常每个人至少每天集成一次 - 导致每天多次集成。每次集成都由自动构建（包括测试）进行验证，以尽快检测集成错误。许多团队发现这种方法大大减少了集成问题，并允许团队更快地开发一致的软件。本文是持续集成的快速概述，总结了该技术及其当前用法。"*

使用其他章节的示例，我们可以使用 Docker 构建一个 CI 环境。您可以创建自己的 CI 环境，也可以从 Shippable 和 Drone 等公司获取服务。我们将在本章后面看到如何使用 Shippable 和 Drone 进行 CI 工作。Shippable 不是托管解决方案，但 Drone 是，它可以给您更好的控制。我认为在这里谈论它们两个会很有帮助：

+   持续交付（CD）：CI 之后的下一步是持续交付，通过这一步，我们可以将我们的代码快速可靠地部署到我们的客户、云和其他环境中，而无需任何手动工作。在本章中，我们将看到如何通过 Shippable CI 自动部署 Red Hat OpenShift 上的应用程序。

+   平台即服务（PaaS）：Docker 可以用于构建您自己的 PaaS。它可以使用 OpenShift、CoreOS、Atomic、Tsuru 等工具/平台进行部署。在本章后面，我们将看到如何使用 OpenShift Origin（[`www.openshift.com/products/origin`](https://www.openshift.com/products/origin)）设置 PaaS。

# 使用 Docker 进行测试

在开发或 QA 期间，如果我们可以针对不同的环境检查我们的代码，将会很有帮助。例如，我们可能希望在不同版本的 Python 或不同发行版（如 Fedora、Ubuntu、CentOS 等）之间检查我们的 Python 代码。对于这个配方，我们将从 Flask 的 GitHub 存储库中挑选示例代码，这是一个用于 Python 的微框架（[`flask.pocoo.org/`](http://flask.pocoo.org/)）。我选择这个是为了保持简单，并且它也更容易用于其他配方。

对于这个配方，我们将创建图像，其中一个容器带有 Python 2.7，另一个带有 Python 3.3。然后，我们将使用一个示例 Python 测试代码来针对每个容器运行。

## 准备就绪

+   由于我们将使用 Flask 的 GitHub 存储库中的示例代码，让我们克隆它：

```
$ git clone https://github.com/mitsuhiko/flask

```

+   创建一个名为`Dockerfile_2.7`的文件，然后从中构建一个图像：

```
$ cat /tmp/ Dockerfile_2.7
FROM python:2.7
RUN pip install flask
RUN pip install pytest
WORKDIR /test
CMD ["/usr/local/bin/py.test"]

```

+   要构建`python2.7test`图像，请运行以下命令：

```
$ docker build -t python2.7test - < /tmp/Dockerfile_2.7

```

+   类似地，创建一个以`python:3.3`为基础图像的 Dockerfile，并构建`python3.3test`图像：

```
$ cat /tmp/Dockerfile_3.3
FROM python:3.3
RUN pip install flask
RUN pip install pytest
WORKDIR /test
CMD ["/usr/local/bin/py.test"]

```

+   要构建图像，请运行以下命令：

```
$ docker build -t python3.3test  - < /tmp/Dockerfile_3.3

```

确保两个图像都已创建。

![准备就绪](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-cb/img/image00347.jpeg)

## 如何做…

现在，使用 Docker 的卷功能，我们将挂载包含源代码和测试用例的外部目录。要使用 Python 2.7 进行测试，请执行以下操作：

1.  转到包含 Flask 示例的目录：

```
$ cd /tmp/flask/examples/

```

1.  启动一个带有`python2.7`测试镜像并在`/test`下挂载`blueprintexample`的容器：

```
$ docker run -d -v `pwd`/blueprintexample:/test python2.7test

```

![操作方法...](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-cb/img/image00348.jpeg)

1.  类似地，要使用 Python 3.3 进行测试，请运行以下命令：

```
 $ docker run -d -v `pwd`/blueprintexample:/test python3.3test

```

1.  在启用 SELinux 的 Fedora/RHEL/CentOS 上运行上述测试时，您将收到“权限被拒绝”的错误。要解决此问题，请在容器内挂载主机目录时重新标记主机目录，如下所示：

```
$ docker run -d -v `pwd`/blueprintexample:/test:z python2.7test

```

### 注意

有关 SELinux 的更多详细信息，请参阅第九章，“Docker 安全性”。

## 工作原理...

从 Dockerfile 中可以看出，在运行`py.test`二进制文件的 CMD 之前，我们将工作目录更改为`/test`。在启动容器时，我们将源代码挂载到`/test`。因此，一旦容器启动，它将运行`py.test`二进制文件并运行测试。

## 还有更多...

+   在这个示例中，我们已经看到了如何使用不同版本的 Python 来测试我们的代码。同样，您可以从 Fedora、CentOS、Ubuntu 中选择不同的基本镜像，并在不同的 Linux 发行版上进行测试。

+   如果您在环境中使用 Jenkins，则可以使用其 Docker 插件动态提供从机器，运行构建并在 Docker 主机上关闭它。有关此的更多详细信息，请访问[`wiki.jenkins-ci.org/display/JENKINS/Docker+Plugin`](https://wiki.jenkins-ci.org/display/JENKINS/Docker+Plugin)。

# 使用 Shippable 和 Red Hat OpenShift 进行 CI/CD

在前面的示例中，我们看到了 Docker 如何在本地开发和 QA 环境中用于测试的示例。让我们看一个端到端的示例，看看 Docker 现在如何在 CI/CD 环境中使用。在这个示例中，我们将看到如何使用 Shippable ([`www.shippable.com/`](http://www.shippable.com/)) 进行 CI/CD 并将其部署在 Red Hat 的 OpenShift 环境 ([`openshift.redhat.com`](https://openshift.redhat.com))。

Shippable 是一个 SaaS 平台，可以让您轻松地将持续集成/部署添加到您的 GitHub 和 Bitbucket(Git)存储库中，它完全建立在 Docker 上。Shippable 使用构建 minions，这些是基于 Docker 的容器，用于运行工作负载。Shippable 支持许多语言，如 Ruby、Python、Node.js、Java、Scala、PHP、Go 和 Clojure。默认的构建 minions 是 Ubuntu 12.04 LTS 和 Ubuntu 14.04。他们还添加了支持使用来自 Docker Hub 的自定义镜像作为 minions。Shippable CI 需要关于项目和构建指令的信息，这些信息存储在名为`shippable.yml`的`yml`文件中，您必须在源代码存储库中提供。`yml`文件包含以下指令：

+   `build_image`：这是用于构建的 Docker 镜像

+   `language`：这将显示编程语言

+   `versions`：您可以指定不同版本的语言以在单个构建指令中进行测试。

+   `before_install`：这些是在运行构建之前的指令

+   `script`：这是一个用于运行测试的二进制/脚本

+   `after_success`：这些是构建成功后的指令；这用于在 PaaS 上执行部署，如 Heroku、Amazon Elastic Beanstalk、AWS OpsWorks、Google App Engine、Red Hat OpenShift 等。

Red Hat 的 OpenShift 是一个用于托管应用程序的 PaaS 平台。目前，它使用非基于 Docker 的容器技术来托管应用程序，但下一个版本的 OpenShift([`github.com/openshift/origin`](https://github.com/openshift/origin))正在基于 Kubernetes 和 Docker 构建。这告诉我们 Docker 在企业世界中被采用的速度。我们将在本章后面看到如何设置 OpenShift v3。

对于这个食谱，我们将使用在上一个食谱中使用的相同示例代码，首先在 Shippable 上进行测试，然后在 OpenShift 上部署它。

## 准备工作

1.  在 Shippable 上创建一个帐户([`www.shippable.com/`](https://www.shippable.com/))。

1.  从[`github.com/openshift/flask-example`](https://github.com/openshift/flask-example)派生 flask 示例。

1.  在 OpenShift 上为派生存储库创建一个应用程序，具体步骤如下：

1.  在 OpenShift 上创建一个帐户([`www.openshift.com/app/account/new`](https://www.openshift.com/app/account/new))并登录。

1.  为应用程序选择**Python 2.7 Cartridge**。

1.  更新您想要的**Public URL**部分。在**Source Code**部分，提供我们分叉存储库的 URL。对于本示例，我分别放下了`blueprint`和`https://github.com/nkhare/flask-example`：![准备就绪](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-cb/img/image00349.jpeg)

1.  单击**Create Application**创建新应用程序。创建后，您应该能够访问我们在上一步中提到的公共 URL。

创建应用程序后，OpenShift 提供了一种在`进行代码更改`部分管理/更新此应用程序的源代码的方法。由于我们希望使用 Shippable 部署应用程序，因此无需遵循这些说明。

1.  在本地系统上克隆分叉存储库：

```
$ git clone git@github.com:nkhare/flask-example.git

```

1.  让我们使用之前使用过的相同蓝图示例。要这样做，请按照以下说明进行操作：

1.  克隆 flask 存储库：

```
$ git clone https://github.com/mitsuhiko/flask.git

```

1.  复制蓝图示例：

```
$ cp -Rv flask/examples/blueprintexample/* flask-example/wsgi/

```

1.  更新`flask-example/wsgi/application`文件，从`blueprintexample`模块导入`app`模块。因此，`flask-example/wsgi/application`文件中的最后一行看起来像下面这样：

```
from blueprintexample import app as application
```

1.  在 flask-example 存储库的顶层添加带有以下内容的`requirements.txt`文件：

```
flask 
pytest
```

1.  添加带有以下内容的`shippable.yml`文件：

```
language: python 

python: 
  - 2.6 
  - 2.7 

install: 
  - pip install -r requirements.txt 

# Make folders for the reports 
before_script: 
  - mkdir -p shippable/testresults 
  - mkdir -p shippable/codecoverage 

script: 
  - py.test 

archive: true 
```

1.  提交代码并将其推送到您的分叉存储库中。

## 如何操作...

1.  登录到 Shippable。

1.  登录后，单击**SYNC ACCOUNT**以获取列出您的分叉存储库，如果尚未列出。查找并启用要构建和运行测试的存储库。在本例中，我选择了我的 GitHub 存储库中的`flask-example`。启用后，您应该看到类似以下内容：![如何操作...](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-cb/img/image00350.jpeg)

1.  单击播放按钮并选择要构建的分支。对于本示例，我选择了 master：

如果构建成功，您将看到成功的图标。

下次在存储库中提交代码时，Shippable 将触发构建并测试代码。现在，要在 OpenShift 上执行持续部署，请按照 Shippable 网站提供的说明进行操作（[`docs.shippable.com/deployment/openshift/`](http://docs.shippable.com/deployment/openshift/)）：

1.  从 Shippable 仪表板获取部署密钥（位于右侧，**Repos**下方）：![如何操作...](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-cb/img/image00351.jpeg)

1.  将其复制到 OpenShift 的([`openshift.redhat.com/app/console/settings`](https://openshift.redhat.com/app/console/settings)) **Settings** | **Public** **Keys**部分如下所示：![如何操作...](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-cb/img/image00352.jpeg)

1.  从 OpenShift 应用程序页面获取**源代码**存储库链接，它将在下一步中用作`OPNESHIFT_REPO`：![如何操作...](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-cb/img/image00353.jpeg)

1.  安装部署密钥后，更新`shippable.yml`文件如下：

```
env: 
  global: 
    - **OPENSHIFT_REPO**=ssh://545ea4964382ec337f000009@blueprint-neependra.rhcloud.com/~/git/blueprint.git 

language: python 

python: 
  - 2.6 
  - 2.7 

install: 
  - pip install -r requirements.txt 

# Make folders for the reports 
before_script: 
  - mkdir -p shippable/testresults 
  - mkdir -p shippable/codecoverage 
  - git remote -v | grep ^openshift || git remote add openshift $OPENSHIFT_REPO 
  - cd wsgi 

script: 
  - py.test 

after_success: 
  - git push -f openshift $BRANCH:master 

archive: true 
```

`OPENSHIFT_REPO`应该反映您使用 OpenShift 部署的应用程序。它将与此示例中显示的内容不同。

1.  现在提交这些更改并将其推送到 GitHub。您将看到 Shippable 触发的构建以及在 OpenShift 上部署的新应用程序。

1.  访问您的应用主页，您应该看到其更新的内容。

## 工作原理…

在每个构建指令中，Shippable 会根据`shippable.yml`文件中指定的镜像和语言类型，启动新的容器并运行构建以执行测试。在我们的情况下，Shippable 将启动两个容器，一个用于 Python 2.6，另一个用于 Python 2.7。当您在 GitHub 上注册时，Shippable 会向您的存储库添加一个 webhook，如下所示：

![工作原理…](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-cb/img/image00354.jpeg)

因此，每次对 GitHub 进行提交更改时，Shippable 上的构建都会被触发，并在成功后部署到 OpenShift 上。

## 另请参阅

+   Shippable 网站上提供了详细的文档，网址为[`docs.shippable.com/`](http://docs.shippable.com/)。

# 使用 Drone 进行 CI/CD

如 Drone 网站（[`drone.io/`](https://drone.io/)）上所述，Drone 是一个托管的持续集成服务。它使您能够方便地设置项目，以便在对代码进行更改时自动构建、测试和部署。他们提供了他们平台的开源版本，您可以在您的环境或云上进行托管。截至目前，他们支持诸如 C/C++、Dart、Go、Haskell、Groovy、Java、Node.js、PHP、Python、Ruby 和 Scala 等语言。使用 Drone，您可以将应用程序部署到 Heroku、Dotcloud、Google App Engine 和 S3 等平台。您还可以通过 SSH（rsync）将代码同步到远程服务器进行部署。

对于这个示例，让我们使用之前示例中使用的相同示例。

## 准备工作

1.  登录到 Drone（[`drone.io/`](https://drone.io/)）。

1.  单击**新项目**并设置存储库。在我们的情况下，我们将选择在之前的示例中使用的 GitHub 上的相同存储库（[`github.com/nkhare/flask-example`](https://github.com/nkhare/flask-example)）：![准备工作](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-cb/img/image00355.jpeg)

1.  一旦选择了，它会要求您为所选的存储库选择编程语言。在这种情况下，我选择了 Python。

1.  然后它会提示您设置构建脚本。对于这个教程，我们将输入以下内容并保存：

```
pip install -r requirements.txt --use-mirrors
cd wsgi
py.test

```

## 操作步骤如下…

1.  通过单击**立即构建**来触发手动构建，如下面的屏幕截图所示：![操作步骤如下…](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-cb/img/image00356.jpeg)

## 它是如何工作的…

构建过程启动一个新的容器，克隆源代码存储库，并在其中运行我们在**命令**部分中指定的命令（运行测试用例）。

## 还有更多…

+   构建完成后，您可以查看控制台输出。

+   Drone 还在 GitHub 中添加了一个 Webhook；因此，下次您提交存储库中的更改时，将触发构建。

+   Drone 还支持将应用程序持续部署到不同的云环境，就像我们在之前的教程中看到的那样。要设置这个，转到**设置**选项卡，选择**部署**，然后选择**添加新的部署**。选择您的云提供商并设置它：![还有更多…](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-cb/img/image00357.jpeg)

## 另请参阅

+   Drone 的文档网址为[`docs.drone.io/`](http://docs.drone.io/)

+   配置自托管的 Drone 环境的步骤，目前处于 alpha 阶段，网址为[`github.com/drone/drone`](https://github.com/drone/drone)

# 使用 OpenShift Origin 设置 PaaS

平台即服务是一种云服务类型，其中消费者控制应用程序（主要是 Web 应用程序）的软件部署和配置设置，提供者提供服务器、网络和其他服务来管理这些部署。提供者可以是外部的（公共提供者）或内部的（组织中的 IT 部门）。有许多 PaaS 提供者，例如 Amazon ([`aws.amazon.com/`](http://aws.amazon.com/))、Heroku ([`www.heroku.com/`](https://www.heroku.com/))、OpenShift ([`www.openshift.com/`](https://www.openshift.com/))等。最近，容器似乎已成为应用程序部署的自然选择。

在本章的前面，我们看了如何使用 Shippable 和 OpenShift 构建 CI/CD 解决方案，我们将我们的应用程序部署到 OpenShift PaaS。我们在 Openshift Online 上部署了我们的应用程序，这是公共云服务。在撰写本书时，OpenShift 公共云服务使用非 Docker 容器技术将应用程序部署到公共云服务。OpenShift 团队一直在开发 OpenShift v3 ([`github.com/openshift/origin`](https://github.com/openshift/origin))，这是一个利用 Docker 和 Kubernetes ([`kubernetes.io`](http://kubernetes.io))等技术的 PaaS，为您的云启用应用程序提供了一个完整的生态系统。他们计划在今年晚些时候将其移至公共云服务。正如我们在第八章，“Docker 编排和托管平台”中所讨论的，强烈建议在继续本教程之前先阅读该章节。我将借用该章节中的一些概念。

![使用 OpenShift Origin 设置 PaaS](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-cb/img/image00358.jpeg)

[`blog.openshift.com/openshift-v3-deep-dive-docker-kubernetes/`](https://blog.openshift.com/openshift-v3-deep-dive-docker-kubernetes/)

Kubernetes 提供了容器集群管理的功能，如调度 pod 和服务发现，但它没有完整应用程序的概念，也没有从源代码构建和部署 Docker 镜像的能力。OpenShift v3 扩展了基本的 Kubernetes 模型，并填补了这些空白。如果我们快进并查看第八章，“Docker 编排和托管平台”，对于 Kubernetes 部分，您会注意到要部署一个应用程序，我们需要定义 Pods、Services 和 Replication-Controllers。OpenShift v3 试图将所有这些信息抽象出来，并让您定义一个配置文件，该文件负责处理所有内部连接。此外，OpenShift v3 还提供其他功能，如通过源代码推送进行自动部署，集中管理和管理应用程序，身份验证，团队和项目隔离，以及资源跟踪和限制，所有这些都是企业部署所需的。

在这个示例中，我们将在 VM 上设置全功能的 OpenShift v3 Origin 并启动一个 pod。在下一个示例中，我们将看到如何使用**源到镜像**（**STI**）构建功能通过源代码构建和部署应用程序。由于 OpenShift v3 Origin 正在进行积极的开发，我从源代码中选择了一个标签，并在这个示例和下一个示例中使用了该代码库。在更新的版本中，命令行选项可能会发生变化。有了这些信息，您应该能够适应最新的发布版本。最新的示例可以在[`github.com/openshift/origin/tree/master/examples/hello-openshift`](https://github.com/openshift/origin/tree/master/examples/hello-openshift)找到。

## 准备就绪

设置 Vagrant ([`www.vagrantup.com/`](https://www.vagrantup.com/))并安装 VirtualBox 提供程序([`www.virtualbox.org/`](https://www.virtualbox.org/))。如何设置这些内容的说明超出了本书的范围。

1.  克隆 OpenShift Origin 存储库：

```
$ git clone https://github.com/openshift/origin.git

```

1.  检出`v0.4.3`标签：

```
$ cd origin
$ git checkout tags/v0.4.3

```

1.  启动虚拟机：

```
$ vagrant up --provider=virtualbox

```

1.  登录到容器：

```
$ vagrant ssh

```

## 如何做...

1.  构建 OpenShift 二进制文件：

```
$ cd /data/src/github.com/openshift/origin
$ make clean build

```

1.  转到`hello-openshift`示例：

```
$  cd /data/src/github.com/openshift/origin/examples/hello-openshift

```

1.  在一个守护进程中启动所有 OpenShift 服务：

```
$ mkdir logs
$ sudo /data/src/github.com/openshift/origin/_output/local/go/bin/openshift start --public-master=localhost &> logs/openshift.log &

```

1.  OpenShift 服务由 TLS 保护。我们的客户端需要接受服务器证书并呈现自己的客户端证书。这些证书是作为 Openshift 启动的一部分在当前工作目录中生成的。

```
$ export OPENSHIFTCONFIG=`pwd`/openshift.local.certificates/admin/.kubeconfig
$ export CURL_CA_BUNDLE=`pwd`/openshift.local.certificates/ca/cert.crt
$ sudo chmod a+rwX "$OPENSHIFTCONFIG"

```

1.  根据`hello-pod.json`定义创建 pod：

```
$ osc create -f hello-pod.json

```

![如何做...](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-cb/img/image00359.jpeg)

1.  连接到 pod：

```
$ curl localhost:6061

```

## 它是如何工作的...

当 OpenShift 启动时，所有 Kubernetes 服务也会启动。然后，我们通过 CLI 连接到 OpenShift 主服务器，并请求它启动一个 pod。该请求然后转发到 Kubernetes，Kubernetes 启动了 pod。在 pod 配置文件中，我们提到将主机机器的端口`6061`映射到 pod 的端口`8080`。因此，当我们在端口`6061`上查询主机时，我们从 pod 得到了回复。

## 还有更多...

如果运行`docker ps`命令，将看到相应的容器正在运行。

## 另请参阅

+   在[`github.com/openshift/origin`](https://github.com/openshift/origin)上的*了解更多*部分

+   在[`blog.openshift.com/openshift-3-beta-3-training-commons-briefing-12/`](https://blog.openshift.com/openshift-3-beta-3-training-commons-briefing-12/)上查看 OpenShift 3 beta 3 视频教程

+   最新的 OpenShift 培训在[`github.com/openshift/training`](https://github.com/openshift/training)

+   OpenShift v3 文档位于[`docs.openshift.org/latest/welcome/index.html`](http://docs.openshift.org/latest/welcome/index.html)

# 从源代码构建和部署应用程序到 OpenShift v3

OpenShift v3 提供了从源代码构建镜像的构建过程。以下是可以遵循的构建策略：

+   **Docker 构建**：在这种情况下，用户将提供 Docker 上下文（Dockerfiles 和支持文件），用于构建镜像。OpenShift 只需触发`docker build`命令来创建镜像。

+   **源到镜像（STI）构建**：在这种情况下，开发人员定义源代码仓库和构建器镜像，后者定义了用于创建应用程序的环境。然后 STI 使用给定的源代码和构建器镜像为应用程序创建一个新的镜像。有关 STI 的更多详细信息，请参见[`github.com/openshift/source-to-image`](https://github.com/openshift/source-to-image)。

+   **自定义构建**：这类似于 Docker 构建策略，但用户可以自定义将用于构建执行的构建器镜像。

在这个教程中，我们将看一下 STI 构建过程。我们将查看 OpenShift v3 Origin 仓库中的 sample-app（[`github.com/openshift/origin/tree/v0.4.3/examples/sample-app`](https://github.com/openshift/origin/tree/v0.4.3/examples/sample-app)）。相应的 STI 构建文件位于[`github.com/openshift/origin/blob/v0.4.3/examples/sample-app/application-template-stibuild.json`](https://github.com/openshift/origin/blob/v0.4.3/examples/sample-app/application-template-stibuild.json)。

在`BuildConfig`部分，我们可以看到源指向 GitHub 仓库（`git://github.com/openshift/ruby-hello-world.git`），而`strategy`部分下的镜像指向`openshift/ruby-20-centos7`镜像。因此，我们将使用`openshift/ruby-20-centos7`镜像，并使用来自 GitHub 仓库的源代码构建一个新的镜像。构建后的新镜像将根据设置被推送到本地或第三方 Docker 注册表。`BuildConfig`部分还定义了何时触发新构建的触发器，例如，当构建镜像发生变化时。

在同一个 STI 构建文件（`application-template-stibuild.json`）中，您会找到多个`DeploymentConfig`部分，每个 pod 一个。`DeploymentConfig`部分包含诸如导出端口、副本、pod 的环境变量和其他信息等信息。简单来说，您可以将`DeploymentConfig`视为 Kubernetes 的扩展复制控制器。它还有触发器来触发新的部署。每次创建新的部署时，`DeploymentConfig`的`latestVersion`字段会递增。还会向`DeploymentConfig`添加`deploymentCause`，描述导致最新部署的更改。

`ImageRepository`，最近更名为`ImageStream`，是一组相关图像。`BuildConfig`和`DeploymentConfig`监视`ImageStream`以查找图像更改并根据各自的触发器做出相应反应。

在 STI 构建文件中，您还会找到用于 pod 的服务（数据库和前端）、用于前端服务的路由，通过该路由可以访问应用程序，以及一个模板。模板描述了一组预期一起使用的资源，可以进行自定义和处理以生成配置。每个模板可以定义一组参数，这些参数可以被容器修改后使用。

与 STI 构建类似，在同一个 sample-app 示例文件夹中有 Docker 和自定义构建的示例。我假设您已经有了之前的配方，所以我们将从那里继续。

## 准备工作

您应该已经完成了之前的配方，*使用 OpenShift Origin 设置 PaaS*。

您当前的工作目录应该是 Vagrant 启动的 VM 内的`/data/src/github.com/openshift/origin /examples/hello-openshift`。

## 如何操作...

1.  部署一个私有的 Docker 注册表来托管 STI 构建过程中创建的镜像：

```
$ sudo openshift ex registry --create --credentials=./openshift.local.certificates/openshift-registry/.kubeconfig

```

1.  确认注册表已启动（这可能需要几分钟）：

```
$ osc describe service docker-registry

```

![如何操作...](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-cb/img/image00360.jpeg)

1.  在 OpenShift 中创建一个新项目。这将创建一个命名空间`test`来包含构建和稍后我们将生成的应用程序：

```
$ openshift ex new-project test --display-name="OpenShift 3 Sample" --description="This is an example project to demonstrate OpenShift v3" --admin=test-admin

```

1.  使用`test-admin`用户登录并切换到`test`项目，从现在开始每个命令都将使用该项目：

```
$ osc login -u test-admin -p pass
$ osc project test

```

1.  提交应用程序模板进行处理（生成模板中请求的共享参数），然后请求创建处理后的模板：

```
$ osc process -f application-template-stibuild.json | osc create -f -

```

1.  这不会触发构建。要启动应用程序的构建，请运行以下命令：

```
$ osc start-build ruby-sample-build

```

1.  监视构建并等待状态变为`complete`（这可能需要几分钟）：

```
$ osc get builds

```

1.  获取服务列表：

```
$ osc get services

```

![如何做...](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-cb/img/image00361.jpeg)

## 它是如何工作的...

在`BuildConfig`（`ruby-sample-build`）部分，我们将源指定为`ruby-hello-world` Git 存储库（`git://github.com/openshift/ruby-hello-world.git`），我们的镜像为`openshift/ruby-20-centos7`。因此，构建过程将使用该镜像，并使用 STI 构建器，在`openshift/ruby-20-centos7`上构建我们的源后创建一个名为`origin-ruby-sample`的新镜像。然后将新镜像推送到我们之前创建的 Docker 注册表中。

使用`DeploymentConfig`，前端和后端 pod 也被部署并链接到相应的服务。

## 还有更多...

+   前面的前端服务可以通过服务 IP 和相应的端口访问，但无法从外部访问。为了使其可访问，我们给我们的应用程序一个 FQDN；例如，在以下示例中，它被定义为`www.example.com`：![还有更多...](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-cb/img/image00361.jpeg)

OpenShift v3 提供了一个 HAProxy 路由器，可以将 FQDN 映射到相应的 pod。有关更多信息，请访问[`docs.openshift.org/latest/architecture/core_objects/routing.html`](http://docs.openshift.org/latest/architecture/core_objects/routing.html)。您还需要在外部 DNS 中添加一个条目来解析此处提供的 FQDN。

+   OpenShift v3 Origin 也是一个管理 GUI。要在 GUI 上查看我们部署的应用程序，请将用户名`test-admin`绑定到默认命名空间中的查看角色，以便您可以在 Web 控制台中观察进展：

```
$ openshift ex policy add-role-to-user view test-admin

```

然后，通过浏览器，连接到`https://<host>:8443/console`，并通过`test-admin`用户登录，输入任何密码。由于 Vagrant 将主机机器上端口`8443`的流量转发到 VM，您应该能够通过运行 VM 的主机连接。然后选择**OpenShift 3 Sample**作为项目并进行探索。

![还有更多...](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-cb/img/image00362.jpeg)

+   在多节点设置中，您的 pod 可以安排在不同的系统上。OpenShift v3 通过覆盖网络 pod 连接 pod，运行在一个节点上的 pod 可以访问另一个节点上的 pod。它被称为`openshift-sdn`。有关更多详细信息，请访问[`github.com/openshift/openshift-sdn`](https://github.com/openshift/openshift-sdn)。

## 另请参阅

+   在[`github.com/openshift/origin`](https://github.com/openshift/origin)的*了解更多*部分

+   在[`blog.openshift.com/openshift-3-beta-3-training-commons-briefing-12/`](https://blog.openshift.com/openshift-3-beta-3-training-commons-briefing-12/)上有 OpenShift 3 beta 3 视频教程

+   最新的 OpenShift 培训在[`github.com/openshift/training`](https://github.com/openshift/training)

+   在[`docs.openshift.org/latest/welcome/index.html`](http://docs.openshift.org/latest/welcome/index.html)上有 OpenShift v3 文档

# 将 Docker 配置为 OpenStack 的虚拟化程序驱动程序

我假设读者对 OpenStack 有一定了解，因为本书不涵盖这方面的内容。有关 OpenStack 及其组件的更多信息，请访问[`www.openstack.org/software/`](http://www.openstack.org/software/)。

在 OpenStack 中，Nova 支持不同的计算虚拟化程序，如 KVM、XEN、VMware、HyperV 等。我们可以使用这些驱动程序来创建虚拟机。使用 Ironic（[`wiki.openstack.org/wiki/Ironic`](https://wiki.openstack.org/wiki/Ironic)），您也可以创建裸金属服务器。Nova 在 Havana（[`www.openstack.org/software/havana/`](https://www.openstack.org/software/havana/)）版本中添加了对 Docker 的容器创建支持，但目前它不在主线中，以加快开发周期。未来计划将其合并到主线中。在底层，它看起来像这样：

![为 OpenStack 配置 Docker 作为虚拟化程序驱动程序](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-cb/img/image00363.jpeg)

[`wiki.openstack.org/wiki/File:Docker-under-the-hood.png`](https://wiki.openstack.org/wiki/File:Docker-under-the-hood.png)

DevStack（[`docs.openstack.org/developer/devstack/overview.html`](http://docs.openstack.org/developer/devstack/overview.html)）是一组脚本，用于快速创建 OpenStack 开发环境。它不是通用安装程序，但是非常容易开始使用 OpenStack 的方法。在本教程中，我们将在 Fedora21 上将 DevStack 的环境配置为使用 Docker 作为 Nova 驱动程序。

## 准备工作

1.  在系统上安装 Docker。

1.  克隆`nova-docker`和`devstack`：

```
$ git clone https://git.openstack.org/stackforge/nova-docker /opt/stack/nova-docker
$ git clone https://git.openstack.org/openstack-dev/devstack /opt/stack/devstack

```

1.  在我们可以使用`configure_nova_hypervisor_rootwrap`之前需要以下步骤：

```
$ git clone https://git.openstack.org/openstack/nova /opt/stack/nova

```

1.  准备安装 Devstack：

```
$ cd /opt/stack/nova-docker
$ ./contrib/devstack/prepare_devstack.sh

```

1.  创建 stack 用户并将其添加到`sudo`：

```
$ /opt/stack/devstack/tools/create-stack-user.sh

```

1.  使用 Python 安装`docker-py`以与 docker 进行通信：

```
$ yum install python-pip
$ pip install docker-py

```

## 如何做…

1.  完成先决条件步骤后，运行以下命令安装 Devstack：

```
$ cd /opt/stack/devstack
$ ./stack.sh

```

## 它是如何工作的...

+   `prepare_devstack.sh`驱动程序在`localrc`文件中进行以下条目的设置，以设置 Nova 驱动程序的正确环境：

```
export VIRT_DRIVER=docker 
export DEFAULT_IMAGE_NAME=cirros 
export NON_STANDARD_REQS=1 
export IMAGE_URLS=" " 
```

+   运行`stackrc`文件后，我们可以看到关于 Nova 和 Glance 的以下更改：

+   `/etc/nova/nova.conf`文件更改了计算驱动程序：

```
 [DEFAULT] 
 compute_driver = novadocker.virt.docker.DockerDriver 
```

+   `/etc/nova/rootwrap.d/docker.filters`文件更新为以下内容：

```
[Filters] 
# nova/virt/docker/driver.py: 'ln', '-sf', '/var/run/netns/.*' 
ln: CommandFilter, /bin/ln, root 
```

+   在`/etc/glance/glance-api.conf`中，在容器/镜像格式中添加`docker`：

```
[DEFAULT] 
container_formats = ami,ari,aki,bare,ovf,docker 
```

## 还有更多...

+   在`localrc`中，我们将`cirros`作为默认镜像，因此一旦设置完成，我们可以看到已下载`cirros`的 Docker 镜像：![更多内容...](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-cb/img/image00364.jpeg)

这将自动导入到 Glance 中。

![更多内容...](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-cb/img/image00365.jpeg)

从前面的截图中，我们可以看到容器格式是 Docker。

+   现在您可以使用 Horizon 创建一个使用`cirros`镜像的实例，或者从命令行创建一个实例，并查看使用 Docker 命令行启动的容器。

+   要将任何镜像导入 Glance，可以执行以下操作：

+   从 Docker Hub 拉取所需的镜像：

```
$ docker pull fedora

```

+   导入镜像（目前只有管理员可以导入镜像）：

```
$ source openrc
$ export OS_USERNAME=admin
$ sudo docker save fedora | glance image-create --is-public=True --container-format=docker --disk-format=raw --name fedora

```

![更多内容...](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-cb/img/image00366.jpeg)

+   Cinder 和 Neutron 的集成不足，但情况正在迅速改善。

+   在安装过程中，如果出现`AttributeError: 'module' object has no attribute 'PY2'`错误，则运行以下命令进行修复：

```
$ pip uninstall  six
$ pip install --upgrade   six

```

## 另请参阅

+   在 OpenStack 网站上的文档[`wiki.openstack.org/wiki/Docker`](https://wiki.openstack.org/wiki/Docker)。

+   Docker 也是 OpenStack Heat 的资源类型之一。在[`docs.openstack.org/developer/heat/template_guide/contrib.html#dockerinc-resource`](http://docs.openstack.org/developer/heat/template_guide/contrib.html#dockerinc-resource)了解更多信息。

+   OpenStack 中有一个有趣的项目叫做 Kolla，它专注于通过 Docker 容器部署 OpenStack 服务。在[`github.com/stackforge/kolla/`](https://github.com/stackforge/kolla/)了解更多信息。


# 第六章：Docker API 和语言绑定

在本章中，我们将涵盖以下内容：

+   配置 Docker 守护程序远程 API

+   使用远程 API 执行图像操作

+   使用远程 API 执行容器操作

+   探索 Docker 远程 API 客户端库

+   保护 Docker 守护程序远程 API

# 介绍

在之前的章节中，我们学习了不同的命令来管理图像、容器等。尽管我们通过命令行运行所有命令，但 Docker 客户端（CLI）与 Docker 守护程序之间的通信是通过 API 进行的，这被称为 Docker 守护程序远程 API。

Docker 还提供了用于与 Docker Hub 和 Docker 注册表通信的 API，Docker 客户端也使用这些 API。除了这些 API 之外，我们还有不同编程语言的 Docker 绑定。因此，如果您想为 Docker 图像、容器管理等构建一个漂亮的 GUI，了解前面提到的 API 将是一个很好的起点。

在本章中，我们将研究 Docker 守护程序远程 API，并使用`curl`命令（[`curl.haxx.se/docs/manpage.html`](http://curl.haxx.se/docs/manpage.html)）与不同 API 的端点进行通信，这将类似于以下命令：

```
$ curl -X <REQUEST> -H <HEADER> <OPTION> <ENDPOINT>

```

前面的请求将返回一个返回代码和与我们选择的端点和请求相对应的输出。`GET`、`PUT`和`DELETE`是不同类型的请求，如果没有指定，默认请求是 GET。每个 API 端点对于返回代码都有自己的解释。

# 配置 Docker 守护程序远程 API

正如我们所知，Docker 具有客户端-服务器架构。当我们安装 Docker 时，用户空间程序和守护程序从同一个二进制文件启动。守护程序默认绑定到同一主机上的`unix://var/run/docker.sock`。这将不允许我们远程访问守护程序。为了允许远程访问，我们需要以允许远程访问的方式启动 Docker，这可以通过适当地更改`-H`标志来实现。

## 准备工作

根据您正在运行的 Linux 发行版，找出需要更改的 Docker 守护程序配置文件。对于 Fedora、Red Hat 发行版，它可能是`/etc/sysconfig/docker`，对于 Ubuntu/Debian 发行版，它可能是`/etc/default/docker`。

## 操作步骤…

1.  在 Fedora 20 系统上，在配置文件（/etc/sysconfig/docker）中添加`-H tcp://0.0.0.0:2375`选项，如下所示：

```
OPTIONS=--selinux-enabled -H tcp://0.0.0.0:2375

```

1.  重新启动 Docker 服务。在 Fedora 上，运行以下命令：

```
$ sudo systemctl restart docker

```

1.  从远程客户端连接到 Docker 主机：

```
$ docker -H <Docker Host>:2375 info

```

![如何做…](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-cb/img/image00367.jpeg)

确保防火墙允许在安装了 Docker 守护程序的系统上访问端口`2375`。

## 它是如何工作的…

通过前述命令，我们允许 Docker 守护程序通过 TCP 在所有网络接口上监听端口`2375`。

## 还有更多…

+   在前面提到的客户端和 Docker 之间的通信中，主机是不安全的。在本章的后面，我们将看到如何在它们之间启用 TLS。

+   Docker CLI 查找环境变量；如果被设置了，那么 CLI 将使用该端点进行连接，例如，如果我们设置如下：

```
$ export DOCKER_HOST=tcp://dockerhost.example.com:2375

```

然后，在该会话中，未来的 docker 命令默认连接到远程 Docker 主机并运行此命令：

```
$ docker info

```

## 另请参阅

+   Docker 网站上的文档[`docs.docker.com/reference/api/docker_remote_api/`](https://docs.docker.com/reference/api/docker_remote_api/)

# 使用远程 API 执行图像操作

在启用了 Docker 守护程序远程 API 之后，我们可以通过客户端进行所有与图像相关的操作。为了更好地理解 API，让我们使用`curl`连接到远程守护程序并进行一些与图像相关的操作。

## 准备工作

配置 Docker 守护程序并允许远程访问，如前面的配方中所解释的。

## 如何做…

在这个配方中，我们将看一下一些图像操作，如下所示：

1.  要列出图像，请使用以下 API：

```
GET /images/json

```

以下是前述语法的一个例子：

```
$ curl http://dockerhost.example.com:2375/images/json

```

![如何做…](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-cb/img/image00368.jpeg)

1.  要创建图像，请使用以下 API：

```
POST /images/create

```

以下是一些示例：

+   从 Docker Hub 获取 Fedora 图像：

```
 $ curl -X POST 
http://dockerhost.example.com:2375/images/create?fromImage=fedora

```

+   获取带有`latest`标签的 WordPress 图像：

```
 $  curl -X POST 
http://dockerhost.example.com:2375/images/create?fromImage=wordpress&tag=latest

```

+   从可访问的 Web 服务器上的`tar`文件创建图像：

```
 $ curl -X POST 
http://dockerhost.example.com:2375/images/create?fromSrc=http://localhost/image.tar

```

1.  要构建图像，请使用以下 API：

```
POST  /commit

```

以下是一些示例：

+   从容器（`container id = 704a7c71f77d`）构建图像

```
 $ curl -X POST 
http://dockerhost.example.com:2375/commit?container=704a7c71f77d

```

+   从 Docker 文件构建图像：

```
 $  curl -X POST  -H "Content-type:application/tar" --data-binary '@/tmp/Dockerfile.tar.gz'  
http://dockerhost.example.com:2375/build?t=apache

```

由于 API 期望内容为`tar`文件，我们需要将 Docker 文件放入 tar 中并调用 API。

1.  要删除图像，请使用以下 API：

```
DELETE  /images/<name>

```

以下是前述语法的一个例子：

```
$ curl -X DELETE
http://dockerhost.example.com:2375/images/wordpress:3.9.1

```

## 它是如何工作的…

在前面提到的所有情况下，API 将连接到 Docker 守护程序并执行请求的操作。

## 还有更多…

我们还没有涵盖之前讨论的 API 的所有选项，Docker 为其他与镜像相关的操作提供了 API。访问 API 文档以获取更多详细信息。

## 另请参阅

+   每个 API 端点可以有不同的输入来控制操作。更多详细信息，请访问 Docker 网站上的文档[`docs.docker.com/reference/api/docker_remote_api_v1.18/#22-images`](https://docs.docker.com/reference/api/docker_remote_api_v1.18/#22-images)。

# 使用远程 API 执行容器操作

与我们使用 API 执行镜像操作类似，我们也可以使用 API 执行所有与容器相关的操作。

## 准备工作

配置 Docker 守护程序并允许远程访问，如前面的示例所述。

## 如何做…

在这个示例中，我们将看一些容器操作：

1.  要列出容器，请使用以下 API：

```
GET  /containers/json

```

以下是一些示例：

+   获取所有正在运行的容器：

```
 $ curl -X GET http://shadowfax.example.com:2375/containers/json

```

+   获取所有正在运行的容器，包括已停止的容器

```
 $ curl -X GET http://shadowfax.example.com:2375/containers/json?all=True

```

1.  要创建一个新的容器，请使用以下 API：

```
POST  /containers/create

```

以下是一些示例

+   从`fedora`镜像创建一个容器：

```
 $ curl -X POST  -H "Content-type:application/json" -d '{"Image": "fedora", "Cmd": ["ls"] }' http://dockerhost.example.com:2375/containers/create

```

+   从`fedora`镜像创建一个名为`f21`的容器：

```
 $ curl -X POST  -H "Content-type:application/json" -d '{"Image": "fedora", "Cmd": ["ls"] }' http://dockerhost.example.com:2375/containers/create?name=f21

```

1.  要启动一个容器，请使用以下 API：

```
POST /containers/<id>/start

```

例如，启动 ID 为`591ab8ac2650`的容器：

```
$ curl -X POST  -H "Content-type:application/json" -d '{"Dns":  ["4.2.2.1"] }' http://dockerhost.example.com:2375/containers/591ab8ac2650/start

```

请注意，当启动已停止的容器时，我们还传递了 DNS 选项，这将改变容器的 DNS 配置。

1.  要检查一个容器，请使用以下 API：

```
GET  /containers/<id>/json

```

例如，检查 ID 为`591ab8ac2650`的容器：

```
$ curl -X GET http://dockerhost.example.com:2375/containers/591ab8ac2650/json

```

1.  要获取正在容器内运行的进程列表，请使用以下 API：

```
GET /containers/<id>/top

```

例如，获取 ID 为`591ab8ac2650`的容器中正在运行的进程：

```
$ curl -X GET http://dockerhost.example.com:2375/containers/591ab8ac2650/top

```

1.  要停止一个容器，请使用以下 API：

```
POST /containers/<id>/stop

```

例如，停止 ID 为`591ab8ac2650`的容器：

```
$ curl -X POST http://dockerhost.example.com:2375/containers/591ab8ac2650/stop

```

## 它是如何工作的…

我们还没有涵盖之前讨论的 API 的所有选项，Docker 为其他与容器相关的操作提供了 API。访问 API 文档以获取更多详细信息。

## 另请参阅

+   Docker 网站上的文档[`docs.docker.com/reference/api/docker_remote_api_v1.18/#21-containers`](https://docs.docker.com/reference/api/docker_remote_api_v1.18/#21-containers)

# 探索 Docker 远程 API 客户端库

在最近的几个示例中，我们探索了 Docker 提供的 API，以连接并对远程 Docker 守护程序执行操作。Docker 社区已经为不同的编程语言添加了绑定，以访问这些 API。其中一些列在[`docs.docker.com/reference/api/remote_api_client_libraries/`](https://docs.docker.com/reference/api/remote_api_client_libraries/)上。

请注意，Docker 维护人员不维护这些库。让我们通过一些示例来探索 Python 绑定，并看看它如何使用 Docker 远程 API。

## 准备就绪

+   在 Fedora 上安装`docker-py`：

```
$ sudo yum install python-docker-py

```

或者，使用`pip`来安装该软件包：

```
$ sudo pip install docker-py

```

+   导入模块：

```
$ python
>>> import docker

```

## 如何做…

1.  创建客户端，使用以下步骤：

1.  通过 Unix 套接字连接：

```
 >>> client = docker.Client(base_url='unix://var/run/docker.sock', version='1.18',  timeout=10)

```

1.  通过 HTTP 连接：

```
 >>> client = docker.Client(base_url='http://dockerhost.example.com:2375', version='1.18',  timeout=10)

```

在这里，`base_url`是要连接的端点，`version`是客户端将使用的 API 版本，`timeout`是以秒为单位的超时值。

1.  使用以下代码搜索图像：

```
>>> client.search ("fedora")

```

1.  使用以下代码拉取图像：

```
>>> client.pull("fedora", tag="latest")

```

1.  使用以下代码启动容器：

```
>>> client.create_container("fedora", command="ls", hostname=None, user=None, detach=False, stdin_open=False, tty=False, mem_limit=0, ports=None, environment=None, dns=None, volumes=None, volumes_from=None,network_disabled=False, name=None, entrypoint=None, cpu_shares=None, working_dir=None,memswap_limit=0)

```

## 它是如何工作的…

在所有前面的情况下，Docker Python 模块将使用 Docker 提供的 API 向端点发送 RESTful 请求。查看`docker-py`中提供的`search`、`pull`和`start`等方法的以下代码，该代码位于[`github.com/docker/docker-py/blob/master/docker/client.py`](https://github.com/docker/docker-py/blob/master/docker/client.py)。

## 还有更多…

您可以探索为 Docker 编写的不同用户界面。其中一些如下所示：

+   Shipyard（[`shipyard-project.com/`](http://shipyard-project.com/)）—使用 Python 编写

+   DockerUI（[`github.com/crosbymichael/dockerui`](https://github.com/crosbymichael/dockerui)）—使用 AngularJS 编写的 JavaScript

# 保护 Docker 守护程序远程 API

在本章的前面，我们看到了如何配置 Docker 守护程序以接受远程连接。但是，使用我们遵循的方法，任何人都可以连接到我们的 Docker 守护程序。我们可以使用传输层安全性（[`en.wikipedia.org/wiki/Transport_Layer_Security`](http://en.wikipedia.org/wiki/Transport_Layer_Security)）来保护我们的连接。

我们可以通过使用现有的**证书颁发机构**（**CA**）或创建我们自己来配置 TLS。为简单起见，我们将创建自己的证书颁发机构，这在生产中不推荐。在本例中，我们假设运行 Docker 守护程序的主机是`dockerhost.example.com`。

## 准备就绪

确保您已安装`openssl`库。

## 操作步骤...

1.  在您的主机上创建一个目录，放置我们的 CA 和其他相关文件：

```
$ mkdirc-p /etc/docker
$ cd  /etc/docker

```

1.  创建 CA 私钥和公钥：

```
$ openssl genrsa -aes256 -out ca-key.pem 2048
$ openssl req -new -x509 -days 365 -key ca-key.pem -sha256 -out ca.pem

```

![操作步骤...](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-cb/img/image00369.jpeg)

1.  现在，让我们创建服务器密钥和证书签名请求。确保`通用名称`与 Docker 守护程序系统的主机名匹配。在我们的情况下，它是`dockerhost.example.com`。

```
$ openssl genrsa -out server-key.pem 2048
$ openssl req -subj "/CN=dockerhost.example.com" -new -key server-key.pem -out server.csr

```

![操作步骤...](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-cb/img/image00370.jpeg)

1.  为了允许来自 127.0.0.1 和特定主机（例如 10.70.1.67）的连接，创建一个扩展配置文件并使用我们的 CA 签署公钥：

```
$ echo subjectAltName = IP:10.70.1.67,IP:127.0.0.1 > extfile.cnf
$ openssl x509 -req -days 365 -in server.csr -CA ca.pem -CAkey ca-key.pem    -CAcreateserial -out server-cert.pem -extfile extfile.cnf

```

![操作步骤...](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-cb/img/image00371.jpeg)

1.  对于客户端认证，创建一个客户端密钥和证书签名请求：

```
$ openssl genrsa -out key.pem 2048
$ openssl req -subj '/CN=client' -new -key key.pem -out client.csr

```

![操作步骤...](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-cb/img/image00372.jpeg)

1.  为了使密钥适用于客户端认证，创建一个扩展配置文件并签署公钥：

```
$ echo extendedKeyUsage = clientAuth > extfile_client.cnf
$ openssl x509 -req -days 365 -in client.csr -CA ca.pem -CAkey ca-key.pem  -CAcreateserial -out cert.pem -extfile_client.cnf

```

![操作步骤...](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-cb/img/image00373.jpeg)

1.  生成`cert.pem`和`server-cert.pem`后，我们可以安全地删除证书签名请求：

```
$ rm -rf client.csr server.csr

```

1.  为了加强安全性并保护密钥免受意外损坏，让我们更改权限：

```
$ chmod -v 0600 ca-key.pem key.pem server-key.pem ca.pem server-cert.pem cert.pem

```

1.  如果守护程序正在`dockerhost.example.com`上运行，请停止它。然后，从`/etc/docker`手动启动 Docker 守护程序：

```
 $ pwd
 /etc/docker
 $ docker -d --tlsverify --tlscacert=ca.pem --tlscert=server-cert.pem    --tlskey=server-key.pem   -H=0.0.0.0:2376

```

1.  从另一个终端，转到`/etc/docker`。运行以下命令连接到 Docker 守护程序：

```
$ cd /etc/docker
$ docker --tlsverify --tlscacert=ca.pem --tlscert=cert.pem --tlskey=key.pem -H=127.0.0.1:2376 version

```

您将看到建立了 TLS 连接，并且可以在其上运行命令。您还可以将 CA 公钥和客户端的 TLS 证书和密钥放在用户的主目录中的`.docker`文件夹中，并使用`DOCKER_HOST`和`DOCKER_TLS_VERIFY`环境变量来默认进行安全连接。

![操作步骤...](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-cb/img/image00374.jpeg)

1.  要从我们在签署服务器密钥时提到的远程主机连接，我们需要将 CA 公钥和客户端的 TLS 证书和密钥复制到远程机器，然后按照前面的截图连接到 Docker 主机。

## 工作原理…

我们为 Docker 守护程序和客户端建立了 TLS 连接，以进行安全通信。

## 还有更多…

+   要设置 Docker 守护程序默认启动 TLS 配置，我们需要更新 Docker 配置文件。例如，在 Fedora 上，您可以在`/etc/sysconfig/docker`中更新`OPTIONS`参数如下：

```
OPTIONS='--selinux-enabled -H tcp://0.0.0.0:2376 --tlsverify     --tlscacert=/etc/docker/ca.pem --tlscert=/etc/docker/server-cert.pem --tlskey=/etc/docker/server-key.pem'

```

+   如果你还记得，在第一章中，*介绍和安装*，我们看到了如何使用 Docker Machine（[`docs.docker.com/machine/`](http://docs.docker.com/machine/)）来设置 Docker 主机，并且在这个设置过程中，TLS 设置发生在运行 Docker 守护程序的主机和客户端之间。在使用 Docker Machine 配置 Docker 主机后，检查客户端系统上的`.docker/machine`用户。


# 第七章：Docker 性能

在本章中，我们将涵盖以下配方：

+   基准测试 CPU 性能

+   基准测试磁盘性能

+   基准测试网络性能

+   使用统计功能获取容器资源使用情况

+   设置性能监控

# 介绍

在第三章中，*使用 Docker 镜像*，我们看到了 Dockerfile 如何用于创建由不同服务/软件组成的镜像，稍后在第四章中，*容器的网络和数据管理*，我们看到了一个 Docker 容器如何与外部世界进行数据和网络交流。在第五章中，*Docker 使用案例*，我们研究了 Docker 的不同使用案例，在第六章中，*Docker API 和语言绑定*，我们看到了如何使用远程 API 连接到远程 Docker 主机。

易用性都很好，但在投入生产之前，性能是考虑的关键因素之一。在本章中，我们将看到 Docker 的性能影响特性以及我们可以遵循的基准测试不同子系统的方法。在进行性能评估时，我们需要将 Docker 性能与以下进行比较：

+   裸金属

+   虚拟机

+   Docker 在虚拟机内运行

在本章中，我们将探讨进行性能评估的方法，而不是从运行中收集的性能数据进行比较。但是，我会指出不同公司进行的性能比较，供您参考。

让我们首先看一些影响 Docker 性能的特性：

+   **卷**：在放置任何企业级工作负载时，您希望相应地调整底层存储。您不应该使用容器使用的主/根文件系统来存储数据。Docker 提供了通过卷附加/挂载外部存储的功能。正如我们在第四章中所看到的，*容器的网络和数据管理*，有两种类型的卷，如下所示：

+   通过`--volume`选项通过主机机器挂载的卷

+   通过`--volumes-from`选项通过另一个容器挂载的卷

+   **存储驱动程序**：我们在第一章中查看了不同的存储驱动程序，即 vfs、aufs、btrfs、devicemapper 和 overlayFS。最近还合并了对 ZFS 的支持。您可以在[`github.com/docker/docker/blob/master/daemon/graphdriver/driver.go`](https://github.com/docker/docker/blob/master/daemon/graphdriver/driver.go)上检查当前支持的存储驱动程序及其选择优先级，如果没有选择 Docker 启动时间。

如果您正在运行 Fedora、CentOS 或 RHEL，则设备映射器将是默认的存储驱动程序。您可以在[`github.com/docker/docker/tree/master/daemon/graphdriver/devmapper`](https://github.com/docker/docker/tree/master/daemon/graphdriver/devmapper)找到一些特定于设备映射器的调整。

您可以使用`-s`选项更改 Docker 守护程序的默认存储驱动程序。您可以更新特定于发行版的配置/系统文件，以在服务重新启动时进行更改。对于 Fedora/RHEL/CentOS，您需要在`/etc/sysconfig/docker`中更新`OPTIONS`字段。类似以下内容可用于使用`btrfs`后端：

```
OPTIONS=-s btrfs

```

以下图表显示了使用不同存储驱动程序配置启动和停止 1,000 个容器所需的时间：

![Introduction](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-cb/img/image00375.jpeg)

[`developerblog.redhat.com/2014/09/30/overview-storage-scalability-docker/`](http://developerblog.redhat.com/2014/09/30/overview-storage-scalability-docker/)

正如您所看到的，overlayFS 的性能优于其他存储驱动程序。

+   **--net=host**：我们知道，默认情况下，Docker 会创建一个桥接，并将 IP 分配给容器。使用`--net=host`将主机网络堆栈暴露给容器，跳过为容器创建网络命名空间。由此可见，与桥接方式相比，此选项始终提供更好的性能。

这有一些限制，比如不能让两个容器或主机应用程序监听相同的端口。

+   **Cgroups**：Docker 的默认执行驱动程序`libcontainer`公开了不同的 Cgroups 旋钮，可用于微调容器性能。其中一些如下：

+   **CPU 份额**：通过这个，我们可以为容器分配比例权重，并相应地共享资源。考虑以下示例：

```
$ docker run -it -c 100 fedora bash

```

+   CPUsets：这允许您创建 CPU 掩码，使用它可以控制容器内线程在主机 CPU 上的执行。例如，以下代码将在容器内的第 0 和第 3 个核心上运行线程：

```
$ docker run -it  --cpuset=0,3 fedora bash

```

+   内存限制：我们可以为容器设置内存限制。例如，以下命令将限制容器的内存使用量为 512 MB：

```
$ docker run -it -m 512M fedora bash

```

+   Sysctl 和 ulimit 设置：在某些情况下，您可能需要根据用例更改一些`sysclt`值以获得最佳性能，例如更改打开文件的数量。使用 Docker 1.6（[`docs.docker.com/v1.6/release-notes/`](https://docs.docker.com/v1.6/release-notes/)）及以上版本，我们可以使用以下命令更改`ulimit`设置：

```
$ docker run -it --ulimit data=8192 fedora bash

```

前面的命令将仅更改给定容器的设置，这是一个每个容器的调整变量。我们还可以通过 Docker 守护程序的 systemd 配置文件设置其中一些设置，默认情况下将适用于所有容器。例如，在 Fedora 上查看 Docker 的 systemd 配置文件，您将在服务部分看到类似以下内容：

```
LimitNOFILE=1048576  # Open file descriptor setting
LimitNPROC=1048576   # Number of processes settings
LimitCORE=infinity   # Core size settings

```

您可以根据需要进行更新。

您可以通过研究他人的工作来了解 Docker 的性能。在过去一年中，一些公司已经发表了一些与 Docker 性能相关的研究：

+   来自 Red Hat：

+   在 Red Hat Enterprise Linux 上对 Docker 的性能分析：

[`developerblog.redhat.com/2014/08/19/performance-analysis-docker-red-hat-enterprise-linux-7/`](http://developerblog.redhat.com/2014/08/19/performance-analysis-docker-red-hat-enterprise-linux-7/)

[`github.com/jeremyeder/docker-performance`](https://github.com/jeremyeder/docker-performance)

+   Docker 中存储可扩展性的综合概述：

[`developerblog.redhat.com/2014/09/30/overview-storage-scalability-docker/`](http://developerblog.redhat.com/2014/09/30/overview-storage-scalability-docker/)

+   超越微基准-以特斯拉效率突破容器性能：

[`developerblog.redhat.com/2014/10/21/beyond-microbenchmarks-breakthrough-container-performance-with-tesla-efficiency/`](http://developerblog.redhat.com/2014/10/21/beyond-microbenchmarks-breakthrough-container-performance-with-tesla-efficiency/)

+   使用 Red Hat Enterprise Linux 容器化数据库：

[`rhelblog.redhat.com/2014/10/29/containerizing-databases-with-red-hat-enterprise-linux/`](http://rhelblog.redhat.com/2014/10/29/containerizing-databases-with-red-hat-enterprise-linux/)

+   来自 IBM

+   虚拟机和 Linux 容器的性能比较的更新版本：

[`domino.research.ibm.com/library/cyberdig.nsf/papers/0929052195DD819C85257D2300681E7B/$File/rc25482.pdf`](http://domino.research.ibm.com/library/cyberdig.nsf/papers/0929052195DD819C85257D2300681E7B/%24File/rc25482.pdf)

[`github.com/thewmf/kvm-docker-comparison`](https://github.com/thewmf/kvm-docker-comparison)

+   来自 VMware

+   VMware vSphere 中的 Docker 容器性能

[`blogs.vmware.com/performance/2014/10/docker-containers-performance-vmware-vsphere.html`](http://blogs.vmware.com/performance/2014/10/docker-containers-performance-vmware-vsphere.html)

为了进行基准测试，我们需要在不同的环境（裸机/虚拟机/Docker）上运行类似的工作负载，然后借助不同的性能统计数据收集结果。为了简化事情，我们可以编写通用的基准测试脚本，这些脚本可以用于不同的环境。我们还可以创建 Dockerfiles 来生成带有工作负载生成脚本的容器。例如，在*Red Hat 企业 Linux 上 Docker 性能分析*文章中，作者使用了一个 Dockerfile 来创建一个 CentOS 镜像，并使用`container`环境变量来选择 Docker 和非 Docker 环境的基准测试脚本`run-sysbench.sh`。

同样，IBM 发布了用于其研究的 Dockerfiles 和相关脚本，可在[`github.com/thewmf/kvm-docker-comparison`](https://github.com/thewmf/kvm-docker-comparison)上找到。

我们将在本章的示例中使用一些之前提到的 Docker 文件和脚本。

# 基准测试 CPU 性能

我们可以使用诸如 Linpack（[`www.netlib.org/linpack/`](http://www.netlib.org/linpack/)）和 sysbench（[`github.com/nuodb/sysbench`](https://github.com/nuodb/sysbench)）之类的基准测试来测试 CPU 性能。对于这个示例，我们将使用 sysbench。我们将看到如何在裸机和容器内运行基准测试。如前所述，类似的步骤可以在其他环境中执行。

## 准备工作

我们将使用 CentOS 7 容器在容器内运行基准测试。理想情况下，我们应该有一个安装了 CentOS 7 的系统，以便在裸机上获得基准测试结果。对于容器测试，让我们从之前提到的 GitHub 存储库构建镜像：

```
$ git clone https://github.com/jeremyeder/docker-performance.git
$ cd docker-performance/Dockerfiles/
$ docker build -t c7perf --rm=true - < Dockerfile
$ docker images
REPOSITORY           TAG            IMAGE ID          CREATED              VIRTUAL SIZE
c7perf              latest         59a10df39a82    About a minute ago         678.3 MB

```

## 如何做…

在同一个 GitHub 存储库中，我们有一个用于运行 sysbench 的脚本，`docker-performance/bench/sysbench/run-sysbench.sh`。它有一些配置，您可以根据需要进行修改。

1.  作为 root 用户，在主机上创建`/results`目录：

```
$ mkdir -p /results

```

现在，在将容器环境变量设置为与 Docker 不同的值后运行基准测试，我们在主机上使用该值构建`c7perf`镜像，运行以下命令：

```
$ cd docker-performance/bench/sysbench
$ export container=no
$ sh ./run-sysbench.sh  cpu test1

```

默认情况下，结果会收集在`/results`中。确保您对其具有写访问权限，或者在基准测试脚本中更改`OUTDIR`参数。

1.  要在容器内运行基准测试，我们需要先启动容器，然后运行基准测试脚本：

```
$ mkdir /results_container
$ docker run -it -v /results_container:/results c7perf bash
$ docker-performance/bench/sysbench/run-sysbench.sh cpu test1

```

由于我们挂载了主机目录`/results_container`到容器内的`/results`，因此结果将在主机上收集。

1.  在 Fedora/RHEL/CentOS 上运行上述测试时，如果启用了 SELinux，您将收到`Permission denied`错误。要解决此问题，请在将其挂载到容器内时重新标记主机目录，如下所示：

```
$ docker run -it -v /results_container:/results:z c7perf bash

```

或者，暂时将 SELinux 设置为宽松模式：

```
$  setenforce 0

```

然后，在测试之后，将其恢复为宽松模式：

```
$  setenforce 1

```

### 注意

有关 SELinux 的更多详细信息，请参阅第九章，“Docker 安全性”。

## 它是如何工作的…

基准测试脚本在内部调用 sysbench 的 CPU 基准测试，用于给定输入。CPU 是通过使用 Euklid 算法进行 64 位整数操作来进行基准测试，用于计算素数。每次运行的结果都会收集在相应的结果目录中，可用于比较。

## 还有更多…

裸机和 Docker CPU 性能报告几乎没有差异。

## 另请参阅

+   查看 IBM 和 VMware 在本章前面引用的链接中使用 Linpack 发布的 CPU 基准测试结果。

# 基准测试磁盘性能

有一些工具可用于基准测试磁盘性能，例如 Iozone ([`www.iozone.org/`](http://www.iozone.org/))，smallfile ([`github.com/bengland2/smallfile`](https://github.com/bengland2/smallfile))和 Flexible IO ([`github.com/axboe/fio`](https://github.com/axboe/fio))。对于本教程，我们将使用 FIO。为此，我们需要编写一个作业文件，模拟您想要运行的工作负载。使用此作业文件，我们可以在目标上模拟工作负载。对于本教程，让我们使用 IBM 发布的基准测试结果中的 FIO 示例（[`github.com/thewmf/kvm-docker-comparison/tree/master/fio`](https://github.com/thewmf/kvm-docker-comparison/tree/master/fio)）。

## 准备就绪

在裸机/虚拟机/Docker 容器上，安装 FIO 并挂载包含文件系统的磁盘以进行每个测试，挂载在`/ferrari`下或在 FIO 作业文件中提到的任何位置。在裸机上，您可以进行本地挂载，在虚拟机上，可以使用虚拟磁盘驱动程序进行挂载，或者可以进行设备透传。在 Docker 上，我们可以使用 Docker 卷从主机机器附加文件系统。

准备工作负载文件。我们可以选择[`github.com/thewmf/kvm-docker-comparison/blob/master/fio/mixed.fio`](https://github.com/thewmf/kvm-docker-comparison/blob/master/fio/mixed.fio)：

```
[global]
ioengine=libaio
direct=1
size=16g
group_reporting
thread
filename=/ferrari/fio-test-file

[mixed-random-rw-32x8]
stonewall
rw=randrw
rwmixread=70
bs=4K
iodepth=32
numjobs=8
runtime=60
```

使用上述作业文件，我们可以在`/ferrari/fio-test-file`上进行 4K 块大小的随机直接 I/O，使用 16GB 文件上的`libaio`驱动程序。I/O 深度为 32，并行作业数为 8。这是一个混合工作负载，其中 70％为读取，30％为写入。

## 如何做...

1.  对于裸机和虚拟机测试，您只需运行 FIO 作业文件并收集结果：

```
$ fio mixed.fio

```

1.  对于 Docker 测试，您可以按以下方式准备 Docker 文件：

```
FROM ubuntu
MAINTAINER nkhare@example.com
RUN apt-get update
RUN apt-get -qq install -y fio
ADD mixed.fio /
VOLUME ["/ferrari"]
ENTRYPOINT ["fio"]
```

1.  现在，使用以下命令创建一个镜像：

```
$ docker build -t docker_fio_perf .

```

1.  按照以下方式启动容器以运行基准测试并收集结果：

```
$ docker run --rm -v /ferrari:/ferrari docker_fio_perf mixed.fio

```

1.  在 Fedora/RHEL/CentOS 上运行上述测试时，启用 SELinux，您将收到“权限被拒绝”的错误。要解决此问题，请在容器内部挂载主机目录时重新标记主机目录，如下所示：

```
$ docker run --rm -v /ferrari:/ferrari:z docker_fio_perf mixed.fio

```

## 它是如何工作的...

FIO 将运行作业文件中给定的工作负载并输出结果。

## 还有更多...

收集结果后，您可以进行结果比较。您甚至可以尝试使用作业文件进行不同类型的 I/O 模式，并获得所需的结果。

## 另请参阅

+   查看 IBM 和 VMware 使用 FIO 在本章前面引用的链接中发布的磁盘基准测试结果

# 基准测试网络性能

网络是在容器环境中部署应用程序时需要考虑的关键因素之一。为了与裸机、虚拟机和容器进行性能比较，我们必须考虑以下不同的场景：

+   裸机到裸机

+   虚拟机到虚拟机

+   使用默认网络模式（桥接）的 Docker 容器到容器

+   使用主机网络（`--net=host`）的 Docker 容器到容器

+   Docker 容器在虚拟机中运行，与外部世界连接

在前述任何情况下，我们可以选择两个端点进行基准测试。我们可以使用工具如`nuttcp` ([`www.nuttcp.net/`](http://www.nuttcp.net/))和`netperf` ([`netperf.org/netperf/`](http://netperf.org/netperf/))来分别测量网络带宽和请求/响应。

## 准备就绪

确保两个端点可以相互到达并安装了必要的软件包/软件。在 Fedora 21 上，您可以使用以下命令安装`nuttcp`：

```
$ yum install -y nuttcp

```

然后，从其网站获取`netperf`。

## 如何做…

使用`nuttcp`测量网络带宽，执行以下步骤：

1.  在一个端点上启动`nuttcp`服务器：

```
$ nuttcp -S

```

1.  使用以下命令从客户端测量传输吞吐量（客户端到服务器）：

```
$ nuttcp -t <SERVER_IP>

```

1.  使用以下命令在客户端上测量接收吞吐量（服务器到客户端）：

```
$ nuttcp -r <SERVER_IP>

```

1.  使用`netperf`运行请求/响应基准测试，执行以下步骤：

1.  在一个端点上启动`netserver`：

```
$ netserver

```

1.  从另一个端点连接到服务器并运行请求/响应测试：

+   对于 TCP：

```
$ netperf  -H 172.17.0.6 -t TCP_RR

```

+   对于 UDP：

```
$ netperf  -H 172.17.0.6 -t UDP_RR

```

## 它是如何工作的…

在前面提到的两种情况中，一个端点成为客户端，向另一个端点上的服务器发送请求。

## 还有更多…

我们可以收集不同场景的基准测试结果并进行比较。`netperf`也可以用于吞吐量测试。

## 另请参阅

+   查看 IBM 和 VMware 在本章前面引用的链接中发布的网络基准测试结果。

# 使用统计功能获取容器资源使用情况

随着 1.5 版本的发布，Docker 增加了一个功能，可以从内置命令中获取容器资源使用情况。

## 准备就绪

安装了 1.5 或更高版本的 Docker 主机，可以通过 Docker 客户端访问。同时，启动一些容器以获取统计信息。

## 如何做…

1.  运行以下命令从一个或多个容器获取统计信息：

```
$ docker stats [CONTAINERS]

```

例如，如果我们有两个名为`some-mysql`和`backstabbing_turing`的容器，然后运行以下命令以获取统计信息：

```
$ docker stats some-mysql backstabbing_turing

```

![操作方法…](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-cb/img/image00376.jpeg)

## 它是如何工作的…

Docker 守护程序从 Cgroups 获取资源信息，并通过 API 提供它。

## 参见

+   参考 Docker 1.5 的发布说明[`docs.docker.com/v1.5/release-notes/`](https://docs.docker.com/v1.5/release-notes/)

# 设置性能监控

我们有诸如 SNMP、Nagios 等工具来监视裸机和虚拟机的性能。同样，有一些可用于监视容器性能的工具/插件，如 cAdvisor（[`github.com/google/cadvisor`](https://github.com/google/cadvisor)）和 sFlow（[`blog.sflow.com/2014/06/docker-performance-monitoring.html`](http://blog.sflow.com/2014/06/docker-performance-monitoring.html)）。在本教程中，让我们看看如何配置 cAdvisor。

## 准备就绪

设置 cAdvisor。

+   运行 cAdvisor 的最简单方法是运行其 Docker 容器，可以使用以下命令完成：

```
sudo docker run \
 --volume=/:/rootfs:ro \
 --volume=/var/run:/var/run:rw \
 --volume=/sys:/sys:ro \
 --volume=/var/lib/docker/:/var/lib/docker:ro \
 --publish=8080:8080 \
 --detach=true \
 --name=cadvisor \
 google/cadvisor:latest

```

+   如果您想在 Docker 之外运行 cAdvisor，请按照 cAdvisor 主页上给出的说明进行操作[`github.com/google/cadvisor/blob/master/docs/running.md#standalone`](https://github.com/google/cadvisor/blob/master/docs/running.md#standalone)

## 操作方法…

容器启动后，将浏览器指向`http://localhost:8080`。您将首先获得有关主机机器的 CPU、内存使用情况和其他信息的图表。然后，通过单击 Docker 容器链接，您将在**子容器**部分下获得运行在机器上的容器的 URL。如果单击其中任何一个，您将看到相应容器的资源使用信息。

以下是一个这样的容器的屏幕截图：

![操作方法…](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-cb/img/image00377.jpeg)

## 它是如何工作的…

使用`docker run`命令，我们已经以只读模式挂载了一些卷，cAdvisor 将从中读取相关信息，比如容器的 Cgroup 详细信息，并以图形方式显示它们。

## 还有更多…

cAdvisor 支持将性能矩阵导出到 influxdb（[`influxdb.com/`](http://influxdb.com/)）。Heapster（[`github.com/GoogleCloudPlatform/heapster`](https://github.com/GoogleCloudPlatform/heapster)）是 Google 的另一个项目，它允许使用 cAdvisor 进行集群范围（Kubernetes）监控。

## 参见

+   您可以在 Docker 网站的文档中查看 cAdvisor 从 Cgroups 中使用的矩阵[https://docs.docker.com/articles/runmetrics/]。
