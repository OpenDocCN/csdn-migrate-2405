# 精通 Docker 第三版（二）

> 原文：[`zh.annas-archive.org/md5/3EE782924E03F9CE768AD8AE784D47E6`](https://zh.annas-archive.org/md5/3EE782924E03F9CE768AD8AE784D47E6)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第四章：管理容器

到目前为止，我们一直在集中讨论如何构建、存储和分发我们的 Docker 镜像。现在我们将看看如何启动容器，以及如何使用 Docker 命令行客户端来管理和与它们交互。

我们将重新访问我们在第一章中使用的命令，并更详细地了解，然后深入了解可用的命令。一旦我们熟悉了容器命令，我们将看看 Docker 网络和 Docker 卷。

我们将涵盖以下主题：

+   Docker 容器命令：

+   基础知识

+   与您的容器交互

+   日志和进程信息

+   资源限制

+   容器状态和其他命令

+   删除容器

+   Docker 网络和卷

# 技术要求

在本章中，我们将继续使用我们的本地 Docker 安装。与之前一样，本章中的截图将来自我首选的操作系统 macOS，但我们将运行的 Docker 命令将在迄今为止安装了 Docker 的三种操作系统上都可以工作；但是，一些支持命令可能只适用于 macOS 和基于 Linux 的操作系统。

观看以下视频以查看代码的实际操作：

[`bit.ly/2yupP3n`](http://bit.ly/2yupP3n)

# Docker 容器命令

在我们深入研究更复杂的 Docker 命令之前，让我们回顾并更详细地了解我们在之前章节中使用的命令。

# 基础知识

在第一章中，*Docker 概述*，我们使用以下命令启动了最基本的容器`hello-world`容器：

```
$ docker container run hello-world
```

如您可能还记得，这个命令从 Docker Hub 拉取了一个 1.84 KB 的镜像。您可以在[`store.docker.com/images/hello-world/`](https://store.docker.com/images/hello-world/)找到该镜像的 Docker Store 页面，并且根据以下 Dockerfile，它运行一个名为`hello`的可执行文件：

```
FROM scratch
COPY hello /
CMD ["/hello"]
```

`hello`可执行文件将`Hello from Docker!`文本打印到终端，然后进程退出。从以下终端输出的完整消息文本中可以看出，`hello`二进制文件还会告诉您刚刚发生了什么步骤：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/ms-dkr-3e/img/60c57d8f-1e69-4387-ae4f-61328267a54a.png)

随着进程退出，我们的容器也会停止；可以通过运行以下命令来查看：

```
$ docker container ls -a
```

命令的输出如下：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/ms-dkr-3e/img/00190aaa-8351-4217-a20a-9a5f46206da2.png)

您可能会注意到在终端输出中，我首先运行了带有和不带有`-a`标志的`docker container ls`命令——这是`--all`的缩写，因为不带标志运行它不会显示任何已退出的容器。

我们不必给我们的容器命名，因为它存在的时间不够长，我们也不在乎它叫什么。Docker 会自动为容器分配名称，而在我的情况下，你可以看到它被称为`pensive_hermann`。

您会注意到，在您使用 Docker 的过程中，如果选择让它为您生成容器，它会为您的容器起一些非常有趣的名字。尽管这有点离题，但生成这些名称的代码可以在`names-generator.go`中找到。在源代码的最后，它有以下的`if`语句：

```
if name == "boring_wozniak" /* Steve Wozniak is not boring */ {
  goto begin
}
```

这意味着永远不会有一个名为`boring_wozniak`的容器（这也是完全正确的）。

Steve Wozniak 是一位发明家、电子工程师、程序员和企业家，他与史蒂夫·乔布斯共同创立了苹果公司。他被誉为 70 年代和 80 年代个人电脑革命的先驱，绝对不是无聊的！

我们可以通过运行以下命令删除状态为`exited`的容器，确保您用您自己的容器名称替换掉命令中的容器名称：

```
$ docker container rm pensive_hermann
```

此外，在第一章 *Docker 概述*的结尾，我们使用官方 nginx 镜像启动了一个容器，使用以下命令： 

```
$ docker container run -d --name nginx-test -p 8080:80 nginx
```

正如您可能记得的那样，这会下载镜像并运行它，将我们主机上的端口`8080`映射到容器上的端口`80`，并将其命名为`nginx-test`：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/ms-dkr-3e/img/796a8134-aa46-4c0a-b133-d47ebca3ad68.png)

正如您从我们的`docker image ls`命令中可以看到的，我们现在已经下载并运行了两个镜像。以下命令显示我们有一个正在运行的容器：

```
$ docker container ls
```

以下终端输出显示，当我运行该命令时，我的容器已经运行了 5 分钟：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/ms-dkr-3e/img/f002c3b3-9feb-4993-8137-95b09982b12c.png)

从我们的`docker container run`命令中可以看到，我们引入了三个标志。其中一个是`-d`，它是`--detach`的缩写。如果我们没有添加这个标志，那么我们的容器将在前台执行，这意味着我们的终端会被冻结，直到我们通过按下*Ctrl* + *C*传递进程的退出命令。

我们可以通过运行以下命令来看到这一点，以启动第二个`nginx`容器与我们已经启动的容器一起运行：

```
$ docker container run --name nginx-foreground -p 9090:80 nginx
```

启动后，打开浏览器并转到`http://localhost:9090/`。当您加载页面时，您会注意到您的页面访问被打印到屏幕上；在浏览器中点击刷新将显示更多的访问量，直到您在终端中按下*Ctrl* + *C*。

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/ms-dkr-3e/img/5f74deb2-6202-486b-b99e-542262ab4569.png)

运行`docker container ls -a`显示您有两个容器，其中一个已退出：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/ms-dkr-3e/img/595d8d02-f115-4928-9bc6-689caa8046a2.png)

发生了什么？当我们移除了分离标志时，Docker 直接将我们连接到容器内的 nginx 进程，这意味着我们可以看到该进程的`stdin`、`stdout`和`stderr`。当我们使用*Ctrl* + *C*时，实际上是向 nginx 进程发送了一个终止指令。由于那是保持容器运行的进程，一旦没有运行的进程，容器立即退出。

标准输入（`stdin`）是我们的进程用来从最终用户那里获取信息的句柄。标准输出（`stdout`）是进程写入正常信息的地方。标准错误（`stderr`）是进程写入错误消息的地方。

当我们启动`nginx-foreground`容器时，您可能还注意到我们使用`--name`标志为其指定了不同的名称。

这是因为您不能使用相同的名称拥有两个容器，因为 Docker 允许您使用`CONTAINER ID`或`NAME`值与容器进行交互。这就是名称生成器函数存在的原因：为您不希望自己命名的容器分配一个随机名称，并确保我们永远不会称史蒂夫·沃兹尼亚克为无聊。

最后要提到的是，当我们启动`nginx-foreground`时，我们要求 Docker 将端口`9090`映射到容器上的端口`80`。这是因为我们不能在主机上的一个端口上分配多个进程，因此如果我们尝试使用与第一个相同的端口启动第二个容器，我们将收到错误消息：

```
docker: Error response from daemon: driver failed programming external connectivity on endpoint nginx-foreground (3f5b355607f24e03f09a60ee688645f223bafe4492f807459e4a2b83571f23f4): Bind for 0.0.0.0:8080 failed: port is already allocated.
```

此外，由于我们在前台运行容器，您可能会收到来自 nginx 进程的错误，因为它未能启动：

```
ERRO[0003] error getting events from daemon: net/http: request cancelled
```

但是，您可能还注意到我们将端口映射到容器上的端口 80——为什么没有错误？

嗯，正如在第一章中解释的那样，*Docker 概述*，容器本身是隔离的资源，这意味着我们可以启动尽可能多的容器，并重新映射端口 80，它们永远不会与其他容器冲突；当我们想要从 Docker 主机路由到暴露的容器端口时，我们只会遇到问题。

让我们保持我们的 nginx 容器在下一节中继续运行。

# 与您的容器进行交互

到目前为止，我们的容器一直在运行单个进程。Docker 为您提供了一些工具，使您能够 fork 额外的进程并与它们交互。

# attach

与正在运行的容器进行交互的第一种方法是`attach`到正在运行的进程。我们仍然有我们的`nginx-test`容器在运行，所以让我们通过运行这个命令来连接到它：

```
$ docker container attach nginx-test
```

打开浏览器并转到`http://localhost:8080/`将会将 nginx 访问日志打印到屏幕上，就像我们启动`nginx-foreground`容器时一样。按下*Ctrl* + *C*将终止进程并将您的终端返回正常；但是，与之前一样，我们将终止保持容器运行的进程：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/ms-dkr-3e/img/1bb4e06d-3b7a-4ff5-a240-277270cfc9f2.png)

我们可以通过运行以下命令重新启动我们的容器：

```
$ docker container start nginx-test
```

这将以分离状态重新启动容器，这意味着它再次在后台运行，因为这是容器最初启动时的状态。转到`http://localhost:8080/`将再次显示 nginx 欢迎页面。

让我们重新连接到我们的进程，但这次附加一个额外的选项：

```
$ docker container attach --sig-proxy=false nginx-test 
```

多次访问容器的 URL，然后按下*Ctrl* + *C*将使我们从 nginx 进程中分离出来，但这次，而不是终止 nginx 进程，它将只是将我们返回到我们的终端，使容器处于分离状态，可以通过运行`docker container ls`来查看：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/ms-dkr-3e/img/a4b9322c-7f40-4ca1-8a24-86b30d727a2b.png)

# exec

`attach`命令在您需要连接到容器正在运行的进程时很有用，但如果您需要更交互式的东西呢？

您可以使用`exec`命令；这会在容器内生成第二个进程，您可以与之交互。例如，要查看`/etc/debian_version`文件的内容，我们可以运行以下命令：

```
$ docker container exec nginx-test cat /etc/debian_version
```

这将产生第二个进程，本例中是 cat 命令，它将打印`/etc/debian_version`的内容到`stdout`。第二个进程然后将终止，使我们的容器在执行 exec 命令之前的状态：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/ms-dkr-3e/img/26de55e0-7fde-47c8-8d5b-304a3fe6da7e.png)

我们可以通过运行以下命令进一步进行：

```
$ docker container exec -i -t nginx-test /bin/bash
```

这次，我们正在派生一个 bash 进程，并使用`-i`和`-t`标志来保持对容器的控制台访问。`-i`标志是`--interactive`的简写，它指示 Docker 保持`stdin`打开，以便我们可以向进程发送命令。`-t`标志是`--tty`的简写，并为会话分配一个伪 TTY。

早期用户终端连接到计算机被称为电传打字机。虽然这些设备今天不再使用，但是 TTY 的缩写在现代计算中继续用来描述纯文本控制台。

这意味着您将能够像远程终端会话（如 SSH）一样与容器进行交互：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/ms-dkr-3e/img/adc82b1e-ce80-447f-ba61-df6187947c28.png)

虽然这非常有用，因为您可以像与虚拟机一样与容器进行交互，但我不建议在使用伪 TTY 运行时对容器进行任何更改。很可能这些更改不会持久保存，并且在删除容器时将丢失。我们将在第十二章中更详细地讨论这背后的思考，*Docker 工作流*。

# 日志和进程信息

到目前为止，我们要么附加到容器中的进程，要么附加到容器本身，以查看信息。Docker 提供了一些命令，允许您查看有关容器的信息，而无需使用`attach`或`exec`命令。

# 日志

`logs`命令相当不言自明；它允许您与 Docker 在后台跟踪的容器的`stdout`流进行交互。例如，要查看我们的`nginx-test`容器的`stdout`的最后条目，只需使用以下命令：

```
$ docker container logs --tail 5 nginx-test
```

命令的输出如下所示：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/ms-dkr-3e/img/f4d55587-638d-40a9-b254-6ea3b7dfd5ca.png)

要实时查看日志，我只需要运行以下命令：

```
$ docker container logs -f nginx-test
```

`-f`标志是`--follow`的简写。我也可以，比如，通过运行以下命令查看自从某个时间以来已经记录的所有内容：

```
$ docker container logs --since 2018-08-25T18:00 nginx-test
```

命令的输出如下所示：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/ms-dkr-3e/img/81472a8d-7d42-47f3-8992-3ef68d28d1f2.png)

你可能会注意到，在前面的输出中，访问日志中的时间戳是 17:12，早于 18:00。为什么会这样？

`logs` 命令显示了 Docker 记录的 `stdout` 的时间戳，而不是容器内部的时间。当我运行以下命令时，你可以看到这一点：

```
$ date
$ docker container exec nginx-test date 
```

输出如下：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/ms-dkr-3e/img/ad0e1a71-4115-41f3-9cf9-ce4611e9c86e.png)

由于我的主机上正在使用**英国夏令时**（**BST**），所以我的主机和容器之间有一个小时的时间差。

幸运的是，为了避免混淆（或者增加混淆，这取决于你的观点），你可以在 `logs` 命令中添加 `-t`：

```
$ docker container logs --since 2018-08-25T18:00 -t nginx-test
```

`-t` 标志是 `--timestamp` 的缩写；这个选项会在输出之前添加 Docker 捕获的时间：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/ms-dkr-3e/img/5adad768-d3f4-48cf-861f-2c2928badd3b.png)

# top

`top` 命令非常简单；它列出了你指定的容器中正在运行的进程，使用方法如下：

```
$ docker container top nginx-test
```

命令的输出如下：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/ms-dkr-3e/img/4a4ecf85-0897-4c4f-ae0a-0d837d554327.png)

如你从下面的终端输出中可以看到，我们有两个正在运行的进程，都是 nginx，这是可以预料到的。

# stats

`stats` 命令提供了关于指定容器的实时信息，或者如果你没有传递 `NAME` 或 `ID` 容器，则提供所有正在运行的容器的信息：

```
$ docker container stats nginx-test
```

如你从下面的终端输出中可以看到，我们得到了指定容器的 `CPU`、`RAM`、`NETWORK`、`DISK IO` 和 `PIDS` 的信息：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/ms-dkr-3e/img/b65c9bb2-62b3-4d50-bfd7-6fc5586a4ad9.png)

我们也可以传递 `-a` 标志；这是 `--all` 的缩写，显示所有容器，无论是否正在运行。例如，尝试运行以下命令：

```
$ docker container stats -a
```

你应该会收到类似以下的输出：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/ms-dkr-3e/img/290518ab-d015-4073-99f4-96ba471a7fd3.png)

然而，如你从前面的输出中可以看到，如果容器没有运行，那么就没有任何资源被利用，所以它实际上并没有增加任何价值，除了让你直观地看到你有多少个容器正在运行以及资源的使用情况。

值得指出的是，`stats` 命令显示的信息只是实时的；Docker 不会记录资源利用情况并以与 `logs` 命令相同的方式提供。我们将在后面的章节中研究更长期的资源利用情况存储。

# 资源限制

我们运行的最后一个命令显示了我们容器的资源利用情况；默认情况下，启动时，容器将被允许消耗主机机器上所有可用的资源。我们可以对容器可以消耗的资源进行限制；让我们首先更新我们的`nginx-test`容器的资源允许量。

通常，我们会在使用`run`命令启动容器时设置限制；例如，要将 CPU 优先级减半并设置内存限制为`128M`，我们将使用以下命令：

```
$ docker container run -d --name nginx-test --cpu-shares 512 --memory 128M -p 8080:80 nginx
```

然而，我们没有使用任何资源限制启动我们的`nginx-test`容器，这意味着我们需要更新我们已经运行的容器；为此，我们可以使用`update`命令。现在，您可能认为这应该只涉及运行以下命令：

```
$ docker container update --cpu-shares 512 --memory 128M nginx-test
```

但实际上，运行上述命令会产生一个错误：

```
Error response from daemon: Cannot update container 3f2ce315a006373c075ba7feb35c1368362356cb5fe6837acf80b77da9ed053b: Memory limit should be smaller than already set memoryswap limit, update the memoryswap at the same time
```

当前设置的`memoryswap`限制是多少？要找出这个，我们可以使用`inspect`命令来显示我们正在运行的容器的所有配置数据；只需运行以下命令：

```
$ docker container inspect nginx-test
```

通过运行上述命令，您可以看到有很多配置数据。当我运行该命令时，返回了一个 199 行的 JSON 数组。让我们使用`grep`命令来过滤只包含单词`memory`的行：

```
$ docker container inspect nginx-test | grep -i memory
```

这返回以下配置数据：

```
 "Memory": 0,
 "KernelMemory": 0, "MemoryReservation": 0,
 "MemorySwap": 0,
 "MemorySwappiness": null,
```

一切都设置为`0`，那么`128M`怎么会小于`0`呢？

在资源配置的上下文中，`0`实际上是默认值，表示没有限制—注意每个数字值后面缺少`M`。这意味着我们的更新命令实际上应该如下所示：

```
$ docker container update --cpu-shares 512 --memory 128M --memory-swap 256M nginx-test
```

分页是一种内存管理方案，其中内核将数据存储和检索，或者交换，从辅助存储器中用于主内存。这允许进程超出可用的物理内存大小。

默认情况下，当您在运行命令中设置`--memory`时，Docker 将设置`--memory-swap`大小为`--memory`的两倍。如果现在运行`docker container stats nginx-test`，您应该看到我们设置的限制：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/ms-dkr-3e/img/77a31bee-f5aa-47fa-bc45-c87ce4e5d593.png)

此外，重新运行`docker container inspect nginx-test | grep -i memory`将显示以下更改：

```
 "Memory": 134217728,
 "KernelMemory": 0,
 "MemoryReservation": 0,
 "MemorySwap": 268435456,
 "MemorySwappiness": null,
```

运行`docker container inspect`时，值都以字节而不是兆字节（MB）显示。

# 容器状态和其他命令

在本节的最后部分，我们将看一下容器可能处于的各种状态，以及作为`docker container`命令的一部分尚未涵盖的几个剩余命令。

运行`docker container ls -a`应该显示类似以下终端输出：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/ms-dkr-3e/img/5772ae4a-e0c4-4b08-9eaa-6736196039a3.png)

如您所见，我们有两个容器；一个状态为`Up`，另一个为`Exited`。在继续之前，让我们启动五个更多的容器。要快速执行此操作，请运行以下命令：

```
$ for i in {1..5}; do docker container run -d --name nginx$(printf "$i") nginx; done
```

运行`docker container ls -a`时，您应该看到您的五个新容器，命名为`nginx1`到`nginx5`：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/ms-dkr-3e/img/93f06e05-03cc-4a87-afa7-405edc4fc671.png)

# 暂停和取消暂停

让我们来看看暂停`nginx1`。要做到这一点，只需运行以下命令：

```
$ docker container pause nginx1
```

运行`docker container ls`将显示容器的状态为`Up`，但也显示为`Paused`：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/ms-dkr-3e/img/1d9542b7-02c5-4c7d-9c9d-2231f3be2885.png)

请注意，我们不必使用`-a`标志来查看有关容器的信息，因为进程尚未终止；相反，它已经被使用`cgroups`冻结器挂起。使用`cgroups`冻结器，进程不知道自己已经被挂起，这意味着它可以被恢复。

你可能已经猜到了，可以使用`unpause`命令恢复暂停的容器，如下所示：

```
$ docker container unpause nginx1
```

如果您需要冻结容器的状态，这个命令非常有用；例如，也许您的一个容器出现了问题，您需要稍后进行一些调查，但不希望它对其他正在运行的容器产生负面影响。

# 停止，启动，重启和杀死

接下来，我们有`stop`，`start`，`restart`和`kill`命令。我们已经使用`start`命令恢复了状态为`Exited`的容器。`stop`命令的工作方式与我们在前台运行容器时使用*Ctrl* + *C*分离的方式完全相同。运行以下命令：

```
$ docker container stop nginx2
```

通过这个，发送一个请求给进程终止，称为`SIGTERM`。如果进程在宽限期内没有自行终止，那么将发送一个终止信号，称为`SIGKILL`。这将立即终止进程，不给它完成导致延迟的任何时间；例如，将数据库查询的结果提交到磁盘。

因为这可能是不好的，Docker 给了你覆盖默认的宽限期的选项，这个默认值是`10`秒，可以使用`-t`标志来覆盖；这是`--time`的缩写。例如，运行以下命令将在发送`SIGKILL`之前等待最多`60`秒，如果需要发送以杀死进程：

```
$ docker container stop -t 60 nginx3
```

`start`命令，正如我们已经看到的，将重新启动进程；然而，与`pause`和`unpause`命令不同，这种情况下，进程将使用最初启动它的标志从头开始，而不是从离开的地方开始：

```
$ docker container start nginx2 nginx3
```

`restart`命令是以下两个命令的组合；它先停止，然后再启动你传递的`ID`或`NAME`容器。与`stop`一样，你也可以传递`-t`标志：

```
$ docker container restart -t 60 nginx4
```

最后，您还可以通过运行`kill`命令立即向容器发送`SIGKILL`命令：

```
$ docker container kill nginx5 
```

# 删除容器

让我们使用`docker container ls -a`命令来检查我们正在运行的容器。当我运行命令时，我可以看到我有两个处于`Exited`状态的容器，其他所有容器都在运行：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/ms-dkr-3e/img/4bcbe8c0-ef73-4ee3-892f-736df9b751ed.png)

要删除两个已退出的容器，我只需运行`prune`命令：

```
$ docker container prune
```

这样做时，会弹出一个警告，询问您是否真的确定，如下面的截图所示：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/ms-dkr-3e/img/6bf28535-d586-446d-90c9-652a5be114b0.png)

您可以使用`rm`命令选择要删除的容器，下面是一个示例：

```
$ docker container rm nginx4
```

另一种选择是将`stop`和`rm`命令串联在一起：

```
$ docker container stop nginx3 && docker container rm nginx3
```

然而，鉴于您现在可以使用`prune`命令，这可能是太费力了，特别是在您试图删除容器并且可能不太关心进程如何优雅地终止的情况下。

随意使用您喜欢的任何方法删除剩余的容器。

# 杂项命令

在本节的最后部分，我们将看一些在日常使用 Docker 时可能不会经常使用的命令。其中之一是`create`。

`create`命令与`run`命令非常相似，只是它不启动容器，而是准备和配置一个：

```
$ docker container create --name nginx-test -p 8080:80 nginx
```

您可以通过运行`docker container ls -a`来检查已创建容器的状态，然后使用`docker container start nginx-test`启动容器，然后再次检查状态：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/ms-dkr-3e/img/0ce749fe-7c8c-4322-8f83-59b00098ab61.png)

我们要快速查看的下一个命令是`port`命令；这将显示容器的端口以及任何端口映射：

```
$ docker container port nginx-test
```

它应该返回以下内容：

```
80/tcp -> 0.0.0.0:8080
```

我们已经知道这一点，因为这是我们配置的内容。此外，端口在`docker container ls`输出中列出。

我们要快速查看的最后一个命令是`diff`命令。该命令打印自容器启动以来已添加（`A`）或更改（`C`）的所有文件的列表——基本上是我们用于启动容器的原始映像和现在存在的文件之间文件系统的差异列表。

在运行命令之前，让我们使用`exec`命令在`nginx-test`容器中创建一个空白文件：

```
$ docker container exec nginx-test touch /tmp/testing
```

现在我们在`/tmp`中有一个名为`testing`的文件，我们可以使用以下命令查看原始映像和运行容器之间的差异：

```
$ docker container diff nginx-test
```

这将返回一个文件列表；从下面的列表中可以看到，我们的测试文件在那里，还有在 nginx 启动时创建的文件：

```
C /run
A /run/nginx.pid
C /tmp
A /tmp/testing
C /var/cache/nginx
A /var/cache/nginx/client_temp A /var/cache/nginx/fastcgi_temp A /var/cache/nginx/proxy_temp
A /var/cache/nginx/scgi_temp
A /var/cache/nginx/uwsgi_temp
```

值得指出的是，一旦停止并删除容器，这些文件将丢失。在本章的下一节中，我们将看看 Docker 卷，并学习如何持久保存数据。

再次强调，如果您在跟着做，应该使用您选择的命令删除在本节启动的任何正在运行的容器。

# Docker 网络和卷

在完成本章之前，我们将首先使用默认驱动程序来了解 Docker 网络和 Docker 卷的基础知识。让我们先看看网络。

# Docker 网络

到目前为止，我们一直在单个共享网络上启动我们的容器。尽管我们还没有讨论过，但这意味着我们一直在启动的容器可以在不使用主机的情况下相互通信

网络。

现在不详细讨论，让我们通过一个例子来工作。我们将运行一个双容器应用程序；第一个容器将运行 Redis，第二个容器将运行我们的应用程序，该应用程序使用 Redis 容器来存储系统状态。

**Redis**是一个内存数据结构存储，可以用作数据库、缓存或消息代理。它支持不同级别的磁盘持久性。

在启动应用程序之前，让我们下载将要使用的容器映像，并创建网络：

```
$ docker image pull redis:alpine
$ docker image pull russmckendrick/moby-counter
$ docker network create moby-counter
```

您应该会看到类似以下终端输出：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/ms-dkr-3e/img/437d8315-2fb0-4b30-919e-de523c2a9d8f.png)

现在我们已经拉取了我们的镜像并创建了我们的网络，我们可以启动我们的容器，从 Redis 开始：

```
$ docker container run -d --name redis --network moby-counter redis:alpine
```

正如您所看到的，我们使用了`--network`标志来定义我们的容器启动的网络。现在 Redis 容器已经启动，我们可以通过运行以下命令来启动应用程序容器：

```
$ docker container run -d --name moby-counter --network moby-counter -p 8080:80 russmckendrick/moby-counter
```

同样，我们将容器启动到`moby-counter`网络中；这一次，我们将端口`8080`映射到容器上的端口`80`。请注意，我们不需要担心暴露 Redis 容器的任何端口。这是因为 Redis 镜像带有一些默认值，暴露默认端口，对我们来说默认端口是`6379`。这可以通过运行`docker container ls`来查看：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/ms-dkr-3e/img/1b81c8f6-2b54-40c8-bccd-b2ba1cd835e8.png)

现在剩下的就是访问应用程序；要做到这一点，打开浏览器，转到`http://localhost:8080/`。您应该会看到一个几乎空白的页面，上面显示着**点击添加标志**的消息：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/ms-dkr-3e/img/d2e7aade-e54d-49a5-8867-cd7fec245ee5.png)

单击页面上的任何位置都会添加 Docker 标志，所以请点击：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/ms-dkr-3e/img/d32f4117-a87d-48e6-a1ac-06550232f498.png)

发生了什么？从 moby-counter 容器提供的应用程序正在连接到`redis`容器，并使用该服务来存储您通过点击放置在屏幕上的每个标志的屏幕坐标。

moby-counter 应用程序是如何连接到`redis`容器的？在`server.js`文件中，设置了以下默认值：

```
var port = opts.redis_port || process.env.USE_REDIS_PORT || 6379
var host = opts.redis_host || process.env.USE_REDIS_HOST || 'redis'
```

这意味着`moby-counter`应用程序正在尝试连接到名为`redis`的主机的端口`6379`。让我们尝试使用 exec 命令从`moby-counter`应用程序中 ping`redis`容器，看看我们得到什么：

```
$ docker container exec moby-counter ping -c 3 redis
```

您应该会看到类似以下输出：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/ms-dkr-3e/img/4b88fe00-2244-44b4-88fe-1bd7efe6ef10.png)

正如您所看到的，`moby-counter`容器将`redis`解析为`redis`容器的 IP 地址，即`172.18.0.2`。您可能会认为应用程序的主机文件包含了`redis`容器的条目；让我们使用以下命令来查看一下：

```
$ docker container exec moby-counter cat /etc/hosts
```

这返回了`/etc/hosts`的内容，在我的情况下，看起来像以下内容：

```
127.0.0.1 localhost
::1 localhost ip6-localhost ip6-loopback
fe00::0 ip6-localnet
ff00::0 ip6-mcastprefix
ff02::1 ip6-allnodes
ff02::2 ip6-allrouters
172.18.0.3 4e7931312ed2
```

除了最后的条目外，实际上是 IP 地址解析为本地容器的主机名，`4e7931312ed2`是容器的 ID；没有`redis`的条目。接下来，让我们通过运行以下命令来检查`/etc/resolv.conf`：

```
$ docker container exec moby-counter cat /etc/resolv.conf
```

这返回了我们正在寻找的内容；如您所见，我们正在使用本地`nameserver`：

```
nameserver 127.0.0.11
options ndots:0
```

让我们使用以下命令对`redis`进行 DNS 查找，针对`127.0.0.11`：

```
$ docker container exec moby-counter nslookup redis 127.0.0.11
```

这返回了`redis`容器的 IP 地址：

```
Server: 127.0.0.11
Address 1: 127.0.0.11

Name: redis
Address 1: 172.18.0.2 redis.moby-counter
```

让我们创建第二个网络并启动另一个应用程序容器：

```
$ docker network create moby-counter2
$ docker run -itd --name moby-counter2 --network moby-counter2 -p 9090:80 russmckendrick/moby-counter
```

现在我们已经启动并运行了第二个应用程序容器，让我们尝试从中 ping`redis`容器：

```
$ docker container exec moby-counter2 ping -c 3 redis
```

在我的情况下，我得到了以下错误：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/ms-dkr-3e/img/fe272858-2c80-4c3d-a694-619b4c7b0046.png)

让我们检查`resolv.conf`文件，看看是否已经在使用相同的域名服务器，如下所示：

```
$ docker container exec moby-counter2 cat /etc/resolv.conf
```

从以下输出中可以看出，域名服务器确实已经在使用中：

```
nameserver 127.0.0.11
options ndots:0
```

由于我们在与名为`redis`的容器运行的不同网络中启动了`moby-counter2`容器，我们无法解析容器的主机名，因此返回了错误的地址错误：

```
$ docker container exec moby-counter2 nslookup redis 127.0.0.11
Server: 127.0.0.11
Address 1: 127.0.0.11

nslookup: can't resolve 'redis': Name does not resolve
```

让我们看看在我们的第二个网络中启动第二个 Redis 服务器；正如我们已经讨论过的，我们不能有两个同名的容器，所以让我们有创意地将其命名为`redis2`。

由于我们的应用程序配置为连接到解析为`redis`的容器，这是否意味着我们将不得不对我们的应用程序容器进行更改？不，但 Docker 已经为您做好了准备。

虽然我们不能有两个同名的容器，正如我们已经发现的那样，我们的第二个网络完全与第一个网络隔离运行，这意味着我们仍然可以使用`redis`的 DNS 名称。为此，我们需要添加`--network-alias`标志，如下所示：

```
$ docker container run -d --name redis2 --network moby-counter2 --network-alias redis redis:alpine
```

如您所见，我们已经将容器命名为`redis2`，但将`--network-alias`设置为`redis`；这意味着当我们执行查找时，我们会看到返回的正确 IP 地址：

```
$ docker container exec moby-counter2 nslookup redis 127.0.0.1
Server: 127.0.0.1
Address 1: 127.0.0.1 localhost

Name: redis
Address 1: 172.19.0.3 redis2.moby-counter2
```

如您所见，`redis`实际上是`redis2.moby-counter2`的别名，然后解析为`172.19.0.3`。

现在我们应该有两个应用程序在本地 Docker 主机上以自己的隔离网络并行运行，可以通过`http://localhost:8080/`和`http://localhost:9090/`访问。运行`docker network ls`将显示在 Docker 主机上配置的所有网络，包括默认网络：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/ms-dkr-3e/img/028c4da4-f1c6-4714-9720-ac7eeed8307d.png)

您可以通过运行以下`inspect`命令来了解有关网络配置的更多信息：

```
$ docker network inspect moby-counter
```

运行上述命令将返回以下 JSON 数组：

```
[
 {
 "Name": "moby-counter",
 "Id": "c8b38a10efbefd701c83203489459d9d5a1c78a79fa055c1c81c18dea3f1883c",
 "Created": "2018-08-26T11:51:09.7958001Z",
 "Scope": "local",
 "Driver": "bridge",
 "EnableIPv6": false,
 "IPAM": {
 "Driver": "default",
 "Options": {},
 "Config": [
 {
 "Subnet": "172.18.0.0/16",
 "Gateway": "172.18.0.1"
 }
 ]
 },
 "Internal": false,
 "Attachable": false,
 "Ingress": false,
 "ConfigFrom": {
 "Network": ""
 },
 "ConfigOnly": false,
 "Containers": {
 "4e7931312ed299ed9132f3553e0518db79b4c36c43d36e88306aed7f6f9749d8": {
 "Name": "moby-counter",
 "EndpointID": "dc83770ae0939c98416ee69d939b30a1da391b11d14012c8188be287baa9c325",
 "MacAddress": "02:42:ac:12:00:03",
 "IPv4Address": "172.18.0.3/16",
 "IPv6Address": ""
 },
 "d760bc59c3ac5f9ba8b7aa8e9f61fd21ce0b8982f3a85db888a5bcf103bedf6e": {
 "Name": "redis",
 "EndpointID": "5af2bfd1ce486e38a9c5cddf9e16878fdb91389cc122cfef62d5e575a91b89b9",
 "MacAddress": "02:42:ac:12:00:02",
 "IPv4Address": "172.18.0.2/16",
 "IPv6Address": ""
 }
 },
 "Options": {},
 "Labels": {}
 }
]
```

如您所见，它包含有关在 IPAM 部分中使用的网络寻址信息，以及网络中运行的两个容器的详细信息。

**IP 地址管理（IPAM）**是规划、跟踪和管理网络内的 IP 地址的一种方法。IPAM 具有 DNS 和 DHCP 服务，因此每个服务都会在另一个服务发生变化时得到通知。例如，DHCP 为`container2`分配一个地址。然后更新 DNS 服务，以便在针对`container2`进行查找时返回 DHCP 分配的 IP 地址。

在我们继续下一节之前，我们应该删除一个应用程序和相关网络。要做到这一点，请运行以下命令：

```
$ docker container stop moby-counter2 redis2
$ docker container prune
$ docker network prune
```

这将删除容器和网络，如下截图所示：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/ms-dkr-3e/img/f90ab3a9-4e23-474b-bb23-6ca5f25a95e3.png)

正如本节开头提到的，这只是默认的网络驱动程序，这意味着我们只能在单个 Docker 主机上使用我们的网络。在后面的章节中，我们将看看如何将我们的 Docker 网络扩展到多个主机甚至多个提供商。

# Docker 卷

如果您一直在按照上一节的网络示例进行操作，您应该有两个正在运行的容器，如下截图所示：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/ms-dkr-3e/img/d8736f3a-5221-4505-8f87-be8f4880a91f.png)

当您在浏览器中访问应用程序（在`http://localhost:8080/`），您可能会看到屏幕上已经有 Docker 标志。让我们停下来，然后移除 Redis 容器，看看会发生什么。要做到这一点，请运行以下命令：

```
$ docker container stop redis
$ docker container rm redis
```

如果您的浏览器打开，您可能会注意到 Docker 图标已经淡出到背景中，屏幕中央有一个动画加载器。这基本上是为了显示应用程序正在等待与 Redis 容器重新建立连接：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/ms-dkr-3e/img/877b5f80-6b36-4d49-be89-2f09a51aea48.png)

使用以下命令重新启动 Redis 容器：

```
$ docker container run -d --name redis --network moby-counter redis:alpine
```

这恢复了连接；但是，当您开始与应用程序交互时，您之前的图标会消失，您将得到一个干净的界面。快速在屏幕上添加一些图标，这次以不同的模式放置，就像我在这里做的一样：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/ms-dkr-3e/img/ae34105f-21e6-4e8e-ad8d-98e7ebebdb46.png)

一旦你有了一个模式，让我们再次通过以下命令移除 Redis 容器：

```
$ docker container stop redis
$ docker container rm redis
```

正如我们在本章前面讨论过的，容器中的数据丢失是可以预料的。然而，由于我们使用了官方的 Redis 镜像，实际上我们并没有丢失任何数据。

我们使用的官方 Redis 镜像的 Dockerfile 如下所示：

```
FROM alpine:3.8

RUN addgroup -S redis && adduser -S -G redis redis
RUN apk add --no-cache 'su-exec>=0.2'

ENV REDIS_VERSION 4.0.11
ENV REDIS_DOWNLOAD_URL http://download.redis.io/releases/redis-4.0.11.tar.gz
ENV REDIS_DOWNLOAD_SHA fc53e73ae7586bcdacb4b63875d1ff04f68c5474c1ddeda78f00e5ae2eed1bbb

RUN set -ex; \
 \
 apk add --no-cache --virtual .build-deps \
 coreutils \
 gcc \
 jemalloc-dev \
 linux-headers \
 make \
 musl-dev \
 ; \
 \
 wget -O redis.tar.gz "$REDIS_DOWNLOAD_URL"; \
 echo "$REDIS_DOWNLOAD_SHA *redis.tar.gz" | sha256sum -c -; \
 mkdir -p /usr/src/redis; \
 tar -xzf redis.tar.gz -C /usr/src/redis --strip-components=1; \
 rm redis.tar.gz; \
 \
 grep -q '^#define CONFIG_DEFAULT_PROTECTED_MODE 1$' /usr/src/redis/src/server.h; \
 sed -ri 's!^(#define CONFIG_DEFAULT_PROTECTED_MODE) 1$!\1 0!' /usr/src/redis/src/server.h; \
 grep -q '^#define CONFIG_DEFAULT_PROTECTED_MODE 0$' /usr/src/redis/src/server.h; \
 \
 make -C /usr/src/redis -j "$(nproc)"; \
 make -C /usr/src/redis install; \
 \
 rm -r /usr/src/redis; \
 \
 runDeps="$( \
 scanelf --needed --nobanner --format '%n#p' --recursive /usr/local \
 | tr ',' '\n' \
 | sort -u \
 | awk 'system("[ -e /usr/local/lib/" $1 " ]") == 0 { next } { print "so:" $1 }' \
 )"; \
 apk add --virtual .redis-rundeps $runDeps; \
 apk del .build-deps; \
 \
 redis-server --version

RUN mkdir /data && chown redis:redis /data
VOLUME /data
WORKDIR /data

COPY docker-entrypoint.sh /usr/local/bin/
ENTRYPOINT ["docker-entrypoint.sh"]

EXPOSE 6379
CMD ["redis-server"]
```

如果你注意到文件末尾有`VOLUME`和`WORKDIR`指令声明；这意味着当我们的容器启动时，Docker 实际上创建了一个卷，然后在卷内部运行了`redis-server`。

通过运行以下命令，我们可以看到这一点：

```
$ docker volume ls
```

这将显示至少两个卷，如下截图所示：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/ms-dkr-3e/img/a53d746d-cbc9-4f6d-8a9c-89758fcc9bb8.png)

正如你所看到的，卷的名称并不友好；实际上，它是卷的唯一 ID。那么当我们启动 Redis 容器时，我们该如何使用这个卷呢？

我们从 Dockerfile 中知道，卷被挂载到容器中的`/data`，所以我们只需要告诉 Docker 在运行时使用哪个卷以及应该挂载到哪里。

为此，请运行以下命令，确保你用自己的卷 ID 替换卷 ID：

```
$ docker container run -d --name redis -v c2e417eab8fa20944582e2de525ab87b749099043b8c487194b7b6415b537e6a:/data --network moby-counter redis:alpine 
```

如果你启动了 Redis 容器后，你的应用页面看起来仍在尝试重新连接到 Redis 容器，那么你可能需要刷新你的浏览器；如果刷新不起作用，可以通过运行`docker container restart moby-counter`来重新启动应用容器，然后再次刷新你的浏览器。

你可以通过运行以下命令来查看卷的内容，以附加到容器并列出`/data`中的文件：

```
$ docker container exec redis ls -lhat /data
```

这将返回类似以下内容：

```
total 12
drwxr-xr-x 1 root root 4.0K Aug 26 13:30 ..
drwxr-xr-x 2 redis redis 4.0K Aug 26 12:44 .
-rw-r--r-- 1 redis redis 392 Aug 26 12:44 dump.rdb
```

你也可以移除正在运行的容器并重新启动它，但这次使用第二个卷的 ID。从你浏览器中的应用程序可以看出，你最初创建的两种不同模式是完好无损的。

最后，你可以用自己的卷来覆盖这个卷。要创建一个卷，我们需要使用`volume`命令：

```
$ docker volume create redis_data
```

一旦创建完成，我们就可以通过运行以下命令来使用`redis_data`卷来存储我们的 Redis，这是在移除 Redis 容器后进行的操作，该容器可能已经在运行：

```
$ docker container run -d --name redis -v redis_data:/data --network moby-counter redis:alpine
```

然后我们可以根据需要重复使用这个卷，下面的屏幕显示了卷的创建，附加到一个容器，然后移除，最后重新附加到一个新的容器：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/ms-dkr-3e/img/587c6e86-e8de-4dca-bf50-f3e35dfe9776.png)

与`network`命令一样，我们可以使用`inspect`命令查看有关卷的更多信息，如下所示：

```
$ docker volume inspect redis_data
```

前面的代码将产生类似以下输出：

```
[
 {
 "CreatedAt": "2018-08-26T13:39:33Z",
 "Driver": "local",
 "Labels": {},
 "Mountpoint": "/var/lib/docker/volumes/redis_data/_data",
 "Name": "redis_data",
 "Options": {},
 "Scope": "local"
 }
]
```

您可以看到使用本地驱动程序时卷并不多；值得注意的一件事是，数据存储在 Docker 主机机器上的路径是`/var/lib/docker/volumes/redis_data/_data`。如果您使用的是 Docker for Mac 或 Docker for Windows，那么这个路径将是您的 Docker 主机虚拟机，而不是您的本地机器，这意味着您无法直接访问卷内的数据。

不过不用担心；我们将在后面的章节中讨论 Docker 卷以及您如何与数据交互。现在，我们应该整理一下。首先，删除这两个容器和网络：

```
$ docker container stop redis moby-counter $ docker container prune
$ docker network prune
```

然后我们可以通过运行以下命令来删除卷：

```
$ docker volume prune
```

您应该看到类似以下终端输出：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/ms-dkr-3e/img/8a083f82-ac74-40d9-ad79-af59bc811b43.png)

现在我们又回到了一个干净的状态，所以我们可以继续下一章了。

# 总结

在本章中，我们看了如何使用 Docker 命令行客户端来管理单个容器并在它们自己的隔离 Docker 网络中启动多容器应用程序。我们还讨论了如何使用 Docker 卷在文件系统上持久化数据。到目前为止，在本章和之前的章节中，我们已经详细介绍了我们将在接下来的章节中使用的大部分可用命令：

```
$ docker container [command]
$ docker network [command]
$ docker volume [command]
$ docker image [command]
```

现在我们已经涵盖了在本地使用 Docker 的四个主要领域，我们可以开始看如何使用 Docker Compose 创建更复杂的应用程序。

在下一章中，我们将看一下另一个核心 Docker 工具，称为 Docker Compose。

# 问题

1.  您必须附加哪个标志到`docker container ls`以查看所有容器，包括运行和停止的容器？

1.  真或假：`-p 8080:80`标志将容器上的端口 80 映射到主机上的端口 8080。

1.  解释使用*Ctrl* + *C*退出您已连接的容器时发生的情况与使用`--sig-proxy=false`命令的附加命令。

1.  真或假：`exec`命令将您连接到正在运行的进程。

1.  您将使用哪个标志为容器添加别名，以便在另一个网络中已经具有相同 DNS 名称的容器运行时响应 DNS 请求？

1.  您将使用哪个命令来查找有关 Docker 卷的详细信息？

# 进一步阅读

您可以在以下链接找到更多关于本章讨论的一些主题的信息：

+   名称生成器代码：[`github.com/moby/moby/blob/master/pkg/namesgenerator/names-generator.go`](https://github.com/moby/moby/blob/master/pkg/namesgenerator/names-generator.go)

+   cgroups 冷冻功能：[`www.kernel.org/doc/Documentation/cgroup-v1/freezer-subsystem.txt`](https://www.kernel.org/doc/Documentation/cgroup-v1/freezer-subsystem.txt)

+   Redis: [`redis.io/`](https://redis.io/)


# 第五章：Docker Compose

在本章中，我们将介绍另一个核心 Docker 工具，称为 Docker Compose，以及目前正在开发中的 Docker App。我们将把本章分解为以下几个部分：

+   Docker Compose 介绍

+   我们的第一个 Docker Compose 应用程序

+   Docker Compose YAML 文件

+   Docker Compose 命令

+   Docker App

# 技术要求

与之前的章节一样，我们将继续使用本地的 Docker 安装。同样，在本章中的截图将来自我首选的操作系统 macOS。

与以前一样，我们将运行的 Docker 命令将适用于我们迄今为止安装了 Docker 的三种操作系统。但是，一些支持命令可能只适用于 macOS 和基于 Linux 的操作系统。 

本章中使用的代码的完整副本可以在以下网址找到：[`github.com/PacktPublishing/Mastering-Docker-Third-Edition/tree/master/chapter05`](https://github.com/PacktPublishing/Mastering-Docker-Third-Edition/tree/master/chapter05)。

观看以下视频以查看代码的实际操作：

[`bit.ly/2q7MJZU`](http://bit.ly/2q7MJZU)

# 介绍 Docker Compose

在第一章*，Docker 概述*中，我们讨论了 Docker 旨在解决的一些问题。我们解释了它如何解决诸如通过将进程隔离到单个容器中来同时运行两个应用程序等挑战，这意味着您可以在同一主机上运行完全不同版本的相同软件堆栈，比如 PHP 5.6 和 PHP 7，就像我们在第二章*，构建容器镜像*中所做的那样。

在第四章*，管理容器*的最后，我们启动了一个由多个容器组成的应用程序，而不是在单个容器中运行所需的软件堆栈。我们启动的示例应用程序 Moby Counter 是用 Node.js 编写的，并使用 Redis 作为后端来存储键值，这里我们的案例是 Docker 标志的位置。

这意味着我们必须启动两个容器，一个用于应用程序，一个用于 Redis。虽然启动应用程序本身相当简单，但手动启动单个容器存在许多缺点。

例如，如果我想让同事部署相同的应用程序，我将不得不传递以下命令：

```
$ docker image pull redis:alpine
$ docker image pull russmckendrick/moby-counter
$ docker network create moby-counter
$ docker container run -d --name redis --network moby-counter redis:alpine
$ docker container run -d --name moby-counter --network moby-counter -p 8080:80 russmckendrick/moby-counter
```

好吧，如果镜像还没有被拉取，我可以不用执行前两个命令，因为在运行时会拉取镜像，但随着应用程序变得更加复杂，我将不得不开始传递一个越来越庞大的命令和指令集。

我还必须明确指出，他们必须考虑命令需要执行的顺序。此外，我的笔记还必须包括任何潜在问题的细节，以帮助他们解决任何问题——这可能意味着我们现在面临的是一个*工作是 DevOps 问题*的场景，我们要尽一切努力避免。

虽然 Docker 的责任应该止步于创建镜像和使用这些镜像启动容器，但他们认为这是技术意味着我们不会陷入的一个场景。多亏了 Docker，人们不再需要担心他们启动应用程序的环境中的不一致性，因为现在可以通过镜像进行部署。

因此，回到 2014 年 7 月，Docker 收购了一家名为 Orchard Laboratories 的小型英国初创公司，他们提供了两种基于容器的产品。

这两个产品中的第一个是基于 Docker 的主机平台：可以将其视为 Docker Machine 和 Docker 本身的混合体。通过一个单一的命令`orchard`，您可以启动一个主机机器，然后将您的 Docker 命令代理到新启动的主机上；例如，您可以使用以下命令：

```
$ orchard hosts create
$ orchard docker run -p 6379:6379 -d orchardup/redis
```

其中一个是在 Orchard 平台上启动 Docker 主机，然后启动一个 Redis 容器。

第二个产品是一个名为 Fig 的开源项目。Fig 允许您使用`YAML`文件来定义您想要如何构建多容器应用程序的结构。然后，它会根据`YAML`文件自动启动容器。这样做的好处是，因为它是一个 YAML 文件，开发人员可以很容易地在他们的代码库中开始使用`fig.yml`文件和 Dockerfiles 一起进行部署。

在这两种产品中，Docker 为 Fig 收购了 Orchard Laboratories。不久之后，Orchard 服务被停止，2015 年 2 月，Fig 成为了 Docker Compose。

作为我们在第一章*Docker 概述*中安装 Docker for Mac、Docker for Windows 和 Linux 上的 Docker 的一部分，我们安装了 Docker Compose，因此不再讨论它的功能，让我们尝试使用 Docker Compose 仅仅启动我们在上一章末尾手动启动的两个容器应用程序。

# 我们的第一个 Docker Compose 应用程序

如前所述，Docker Compose 使用一个 YAML 文件，通常命名为`dockercompose.yml`，来定义您的多容器应用程序应该是什么样子的。我们在第四章*管理容器*中启动的两个容器应用程序的 Docker Compose 表示如下：

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

即使没有逐行分析文件中的每一行，也应该很容易跟踪到正在发生的事情。要启动我们的应用程序，我们只需切换到包含您的`docker-compose.yml`文件的文件夹，并运行以下命令：

```
$ docker-compose up
```

正如您从以下终端输出中所看到的，启动时发生了很多事情：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/ms-dkr-3e/img/4e69ce24-f7a6-4080-a784-5b049cc7c666.png)

正如您从前几行所看到的，Docker Compose 做了以下事情：

+   它创建了一个名为`mobycounter_redis_data`的卷，使用我们在`docker-compose.yml`文件末尾定义的默认驱动程序。

+   它创建了一个名为`mobycounter_default`的网络，使用默认网络驱动程序——在任何时候我们都没有要求 Docker Compose 这样做。稍后再详细讨论。

+   它启动了两个容器，一个叫做`mobycounter_redis_1`，第二个叫做`mobycounter_mobycounter_1`。

您可能还注意到我们的多容器应用程序中的 Docker Compose 命名空间已经用`mobycounter`作为前缀。它从我们存储 Docker Compose 文件的文件夹中获取了这个名称。

一旦启动，Docker Compose 连接到`mobycounter_redis_1`和`mobycounter_mobycounter_1`，并将输出流到我们的终端会话。在终端屏幕上，您可以看到`redis_1`和`mobycounter_1`开始相互交互。

当使用`docker-compose up`运行 Docker Compose 时，它将在前台运行。按下*Ctrl* + *C*将停止容器并返回对终端会话的访问。

# Docker Compose YAML 文件

在我们更深入地使用 Docker Compose 之前，我们应该深入研究`docker-compose.yml`文件，因为这些文件是 Docker Compose 的核心。

YAML 是一个递归缩写，代表**YAML 不是标记语言**。它被许多不同的应用程序用于配置和定义人类可读的结构化数据格式。你在示例中看到的缩进非常重要，因为它有助于定义数据的结构。

# Moby 计数器应用程序

我们用来启动多容器应用程序的`docker-compose.yml`文件分为三个独立的部分。

第一部分简单地指定了我们正在使用的 Docker Compose 定义语言的版本；在我们的情况下，由于我们正在运行最新版本的 Docker 和 Docker Compose，我们使用的是版本 3：

```
version: "3"
```

接下来的部分是我们定义容器的地方；这部分是服务部分。它采用以下格式：

```
services: --> container name: ----> container options --> container name: ----> container options
```

在我们的示例中，我们定义了两个容器。我已经将它们分开以便阅读：

```
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
```

定义服务的语法接近于使用`docker container run`命令启动容器。我说接近是因为虽然在阅读定义时它是完全合理的，但只有在仔细检查时才会意识到 Docker Compose 语法和`docker container run`命令之间实际上存在很多差异。

例如，在运行`docker container run`命令时，以下内容没有标志：

+   `image：`这告诉 Docker Compose 要下载和使用哪个镜像。在命令行上运行`docker container run`时，这不作为选项存在，因为你只能运行一个单独的容器；正如我们在之前的章节中看到的，镜像总是在命令的末尾定义，而不需要传递标志。

+   `volume：`这相当于`--volume`标志，但它可以接受多个卷。它只使用在 Docker Compose YAML 文件中声明的卷；稍后会详细介绍。

+   `depends_on：`这在`docker container run`调用中永远不会起作用，因为该命令只针对单个容器。在 Docker Compose 中，`depends_on`用于帮助构建一些逻辑到启动容器的顺序中。例如，只有在容器 A 成功启动后才启动容器 B。

+   `ports：`这基本上是`--publish`标志，它接受一个端口列表。

我们使用的命令中唯一具有与在运行`docker container run`时等效标志的部分是这个：

+   `restart：`这与使用`--restart`标志相同，并接受相同的输入。

我们的 Docker Compose YAML 文件的最后一部分是我们声明卷的地方：

```
volume:
 redis_data:
```

# 示例投票应用程序

如前所述，Moby 计数器应用程序的 Docker Compose 文件是一个相当简单的示例。让我们看看一个更复杂的 Docker Compose 文件，看看我们如何引入构建容器和多个网络。

在本书的存储库中，您将在`chapter05`目录中找到一个名为`example-voting-app`的文件夹。这是来自官方 Docker 示例存储库的投票应用程序的一个分支。

正如您所看到的，如果您打开`docker-compose.yml`文件，该应用程序由五个容器、两个网络和一个卷组成。暂时忽略其他文件；我们将在以后的章节中查看其中一些。让我们逐步了解`docker-compose.yml`文件，因为其中有很多内容：

```
version: "3"

services:
```

正如您所看到的，它从定义版本开始，然后开始列出服务。我们的第一个容器名为`vote`；它是一个允许用户提交他们的投票的 Python 应用程序。正如您从以下定义中所看到的，我们实际上是通过使用`build`而不是`image`命令从头开始构建一个镜像，而不是下载一个镜像：

```
 vote:
 build: ./vote
 command: python app.py
 volumes:
 - ./vote:/app
 ports:
 - "5000:80"
 networks:
 - front-tier
 - back-tier
```

构建指令在这里告诉 Docker Compose 使用 Dockerfile 构建一个容器，该 Dockerfile 可以在`./vote`文件夹中找到。Dockerfile 本身对于 Python 应用程序来说非常简单。

容器启动后，我们将`./vote`文件夹从主机机器挂载到容器中，这是通过传递我们想要挂载的文件夹的路径以及我们想要在容器中挂载的位置来实现的。

我们告诉容器在启动时运行`python app.py`。我们将主机机器上的端口`5000`映射到容器上的端口`80`，最后，我们将两个网络进一步附加到容器上，一个称为`front-tier`，另一个称为`back-tier`。

`front-tier`网络将包含必须将端口映射到主机机器的容器；`back-tier`网络保留用于不需要暴露其端口的容器，并充当私有的隔离网络。

接下来，我们有另一个连接到`front-tier`网络的容器。该容器显示投票结果。`result`容器包含一个 Node.js 应用程序，它连接到我们马上会提到的 PostgreSQL 数据库，并实时显示投票容器中的投票结果。与`vote`容器一样，该镜像是使用位于`./result`文件夹中的`Dockerfile`本地构建的：

```
 result:
 build: ./result
 command: nodemon server.js
 volumes:
 - ./result:/app
 ports:
 - "5001:80"
 - "5858:5858"
 networks:
 - front-tier
 - back-tier
```

我们正在暴露端口`5001`，这是我们可以连接以查看结果的地方。接下来，也是最后一个应用程序容器被称为`worker`：

```
 worker:
 build:
 context: ./worker
 depends_on:
 - "redis"
 networks:
 - back-tier
```

worker 容器运行一个.NET 应用程序，其唯一工作是连接到 Redis，并通过将每个投票转移到运行在名为`db`的容器上的 PostgreSQL 数据库来注册每个投票。该容器再次使用`Dockerfile`构建，但这一次，我们不是传递存储`Dockerfile`和应用程序的文件夹路径，而是使用上下文。这为 docker 构建设置工作目录，并允许您定义附加选项，如标签和更改`Dockerfile`的名称。

由于该容器除了连接到`redis`和`db`容器外什么也不做，因此它不需要暴露任何端口，因为没有任何东西直接连接到它；它也不需要与运行在`front-tier`网络上的任何容器通信，这意味着我们只需要添加`back-tier`网络。

所以，我们现在有了`vote`应用程序，它注册来自最终用户的投票并将它们发送到`redis`容器，然后由`worker`容器处理。`redis`容器的服务定义如下：

```
 redis:
 image: redis:alpine
 container_name: redis
 ports: ["6379"]
 networks:
 - back-tier
```

该容器使用官方的 Redis 镜像，并不是从 Dockerfile 构建的；我们确保端口`6379`可用，但仅在`back-tier`网络上。我们还指定了容器的名称，将其设置为`redis`，使用`container_name`。这是为了避免我们在代码中对 Docker Compose 生成的默认名称做任何考虑，因为您可能还记得，Docker Compose 使用文件夹名称在其自己的应用程序命名空间中启动容器。

接下来，也是最后一个容器是我们已经提到的 PostgreSQL 容器，名为`db`：

```
 db:
 image: postgres:9.4
 container_name: db
 volumes:
 - "db-data:/var/lib/postgresql/data"
 networks:
 - back-tier
```

正如你所看到的，它看起来与`redis`容器非常相似，因为我们正在使用官方镜像；然而，你可能注意到我们没有暴露端口，因为这是官方镜像中的默认选项。我们还指定了容器的名称。

因为这是我们将存储投票的地方，我们正在创建和挂载一个卷来作为我们的 PostgreSQL 数据库的持久存储：

```
volumes:
 db-data:
```

最后，这是我们一直在谈论的两个网络：

```
networks:
 front-tier:
 back-tier:
```

运行`docker-compose up`会给出很多关于启动过程的反馈；首次启动应用程序大约需要 5 分钟。如果你没有跟着操作并自己启动应用程序，接下来是启动的摘要版本。

你可能会收到一个错误，指出`npm ERR! request to https://registry.npmjs.org/nodemon failed, reason: Hostname/IP doesn't match certificate's altnames`。如果是这样，那么以有写入`/etc/hosts`权限的用户身份运行以下命令`echo "104.16.16.35 registry.npmjs.org" >> /etc/hosts`。

我们首先创建网络并准备好卷供我们的容器使用：

```
Creating network "example-voting-app_front-tier" with the default driver
Creating network "example-voting-app_back-tier" with the default driver
Creating volume "example-voting-app_db-data" with default driver
```

然后我们构建`vote`容器镜像：

```
Building vote
Step 1/7 : FROM python:2.7-alpine
2.7-alpine: Pulling from library/python
8e3ba11ec2a2: Pull complete
ea489525e565: Pull complete
f0d8a8560df7: Pull complete
8971431029b9: Pull complete
Digest: sha256:c9f17d63ea49a186d899cb9856a5cc1c601783f2c9fa9b776b4582a49ceac548
Status: Downloaded newer image for python:2.7-alpine
 ---> 5082b69714da
Step 2/7 : WORKDIR /app
 ---> Running in 663db929990a
Removing intermediate container 663db929990a
 ---> 45fe48ea8e4c
Step 3/7 : ADD requirements.txt /app/requirements.txt
 ---> 2df3b3211688
Step 4/7 : RUN pip install -r requirements.txt
 ---> Running in 23ad90b81e6b
[lots of python build output here]
Step 5/7 : ADD . /app
 ---> cebab4f80850
Step 6/7 : EXPOSE 80
 ---> Running in b28d426e3516
Removing intermediate container b28d426e3516
 ---> bb951ea7dffc
Step 7/7 : CMD ["gunicorn", "app:app", "-b", "0.0.0.0:80", "--log-file", "-", "--access-logfile", "-", "--workers", "4", "--keep-alive", "0"]
 ---> Running in 2e97ca847f8a
Removing intermediate container 2e97ca847f8a
 ---> 638c74fab05e
Successfully built 638c74fab05e
Successfully tagged example-voting-app_vote:latest
WARNING: Image for service vote was built because it did not already exist. To rebuild this image you must use `docker-compose build` or `docker-compose up --build`.
```

一旦`vote`镜像构建完成，`worker`镜像就会被构建：

```
Building worker
Step 1/5 : FROM microsoft/dotnet:2.0.0-sdk
2.0.0-sdk: Pulling from microsoft/dotnet
3e17c6eae66c: Pull complete
74d44b20f851: Pull complete
a156217f3fa4: Pull complete
4a1ed13b6faa: Pull complete
18842ff6b0bf: Pull complete
e857bd06f538: Pull complete
b800e4c6f9e9: Pull complete
Digest: sha256:f4ea9cdf980bb9512523a3fb88e30f2b83cce4b0cddd2972bc36685461081e2f
Status: Downloaded newer image for microsoft/dotnet:2.0.0-sdk
 ---> fde8197d13f4
Step 2/5 : WORKDIR /code
 ---> Running in 1ca2374cff99
Removing intermediate container 1ca2374cff99
 ---> 37f9b05325f9
Step 3/5 : ADD src/Worker /code/src/Worker
 ---> 9d393c6bd48c
Step 4/5 : RUN dotnet restore -v minimal src/Worker && dotnet publish -c Release -o "./" "src/Worker/"
 ---> Running in ab9fe7820062
 Restoring packages for /code/src/Worker/Worker.csproj...
 [lots of .net build output here]
 Restore completed in 8.86 sec for /code/src/Worker/Worker.csproj.
Microsoft (R) Build Engine version 15.3.409.57025 for .NET Core
Copyright (C) Microsoft Corporation. All rights reserved.
 Worker -> /code/src/Worker/bin/Release/netcoreapp2.0/Worker.dll
 Worker -> /code/src/Worker/
Removing intermediate container ab9fe7820062
 ---> cf369fbb11dd
Step 5/5 : CMD dotnet src/Worker/Worker.dll
 ---> Running in 232416405e3a
Removing intermediate container 232416405e3a
 ---> d355a73a45c9
Successfully built d355a73a45c9
Successfully tagged example-voting-app_worker:latest
WARNING: Image for service worker was built because it did not already exist. To rebuild this image you must use `docker-compose build` or `docker-compose up --build`.
```

然后拉取`redis`镜像：

```
Pulling redis (redis:alpine)...
alpine: Pulling from library/redis
8e3ba11ec2a2: Already exists
1f20bd2a5c23: Pull complete
782ff7702b5c: Pull complete
82d1d664c6a7: Pull complete
69f8979cc310: Pull complete
3ff30b3bc148: Pull complete
Digest: sha256:43e4d14fcffa05a5967c353dd7061564f130d6021725dd219f0c6fcbcc6b5076
Status: Downloaded newer image for redis:alpine
```

接下来是为`db`容器准备的 PostgreSQL 镜像：

```
Pulling db (postgres:9.4)...
9.4: Pulling from library/postgres
be8881be8156: Pull complete
01d7a10e8228: Pull complete
f8968e0fd5ca: Pull complete
69add08e7e51: Pull complete
954fe1f9e4e8: Pull complete
9ace39987bb3: Pull complete
9020931bcc5d: Pull complete
71f421dd7dcd: Pull complete
a909f41228ab: Pull complete
cb62befcd007: Pull complete
4fea257fde1a: Pull complete
f00651fb0fbf: Pull complete
0ace3ceac779: Pull complete
b64ee32577de: Pull complete
Digest: sha256:7430585790921d82a56c4cbe62fdf50f03e00b89d39cbf881afa1ef82eefd61c
Status: Downloaded newer image for postgres:9.4
```

现在是大事将要发生的时候了；构建`result`镜像。Node.js 非常冗长，所以在执行`Dockerfile`的`npm`部分时，屏幕上会打印出相当多的输出；事实上，有超过 250 行的输出：

```
Building result
Step 1/11 : FROM node:8.9-alpine
8.9-alpine: Pulling from library/node
605ce1bd3f31: Pull complete
79b85b1676b5: Pull complete
20865485d0c2: Pull complete
Digest: sha256:6bb963d58da845cf66a22bc5a48bb8c686f91d30240f0798feb0d61a2832fc46
Status: Downloaded newer image for node:8.9-alpine
 ---> 406f227b21f5
Step 2/11 : RUN mkdir -p /app
 ---> Running in 4af9c85c67ee
Removing intermediate container 4af9c85c67ee
 ---> f722dde47fcf
Step 3/11 : WORKDIR /app
 ---> Running in 8ad29a42f32f
Removing intermediate container 8ad29a42f32f
 ---> 32a05580f2ec
Step 4/11 : RUN npm install -g nodemon
[lots and lots of nodejs output]
Step 8/11 : COPY . /app
 ---> 725966c2314f
Step 9/11 : ENV PORT 80
 ---> Running in 6f402a073bf4
Removing intermediate container 6f402a073bf4
 ---> e3c426b5a6c8
Step 10/11 : EXPOSE 80
 ---> Running in 13db57b3c5ca
Removing intermediate container 13db57b3c5ca
 ---> 1305ea7102cf
Step 11/11 : CMD ["node", "server.js"]
 ---> Running in a27700087403
Removing intermediate container a27700087403
 ---> 679c16721a7f
Successfully built 679c16721a7f
Successfully tagged example-voting-app_result:latest
WARNING: Image for service result was built because it did not already exist. To rebuild this image you must use `docker-compose build` or `docker-compose up --build`.
```

应用程序的`result`部分可以在`http://localhost:5001`访问。默认情况下没有投票，它是 50/50 的分割：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/ms-dkr-3e/img/4a22ffa8-8c43-4c3b-a426-6219b0ee85a0.png)

应用程序的`vote`部分可以在`http://localhost:5000`找到：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/ms-dkr-3e/img/f8de0f3e-20dd-45db-ae5f-7488b207f103.png)

点击**CATS**或**DOGS**将注册一票；你应该能在终端的 Docker Compose 输出中看到这一点：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/ms-dkr-3e/img/b3a3eb0d-f32c-46be-8b36-0257af71fc63.png)

有一些错误，因为只有当投票应用程序注册第一张选票时，Redis 表结构才会被创建；一旦投票被投出，Redis 表结构将被创建，并且工作容器将接收该投票并通过写入`db`容器来处理它。一旦投票被投出，`result`容器将实时更新：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/ms-dkr-3e/img/bbd70927-10dc-48ab-ae1a-cada61daea24.png)

在接下来的章节中，当我们查看如何启动 Docker Swarm 堆栈和 Kubenetes 集群时，我们将再次查看 Docker Compose YAML 文件。现在，让我们回到 Docker Compose，并查看一些我们可以运行的命令。

# Docker Compose 命令

我们已经过了本章的一半，我们运行的唯一 Docker Compose 命令是`docker-compose up`。如果您一直在跟着做，并且运行`docker container ls -a`，您将看到类似以下终端屏幕的内容：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/ms-dkr-3e/img/5d363680-67d7-437f-bd51-5dbf01bffb15.png)

正如您所看到的，我们有很多容器的状态是“退出”。这是因为当我们使用*Ctrl* + *C*返回到我们的终端时，Docker Compose 容器被停止了。

选择一个 Docker Compose 应用程序，并切换到包含`docker-compose.yml`文件的文件夹，我们将通过一些更多的 Docker Compose 命令进行工作。我将使用**示例投票**应用程序。

# 上升和 PS

第一个是`docker-compose up`，但这次，我们将添加一个标志。在您选择的应用程序文件夹中，运行以下命令：

```
$ docker-compose up -d
```

这将重新启动您的应用程序，这次是在分离模式下：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/ms-dkr-3e/img/0b96c910-8548-4bf7-ac18-d2d5daf3b40f.png)

一旦控制台返回，您应该能够使用以下命令检查容器是否正在运行：

```
$ docker-compose ps
```

正如您从以下终端输出中所看到的，所有容器的状态都是“上升”的：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/ms-dkr-3e/img/bb818478-bc68-4381-84be-11090fbd2b00.png)

运行这些命令时，Docker Compose 只会知道在`docker-compose.yml`文件的服务部分中定义的容器；所有其他容器将被忽略，因为它们不属于我们的服务堆栈。

# 配置

运行以下命令将验证我们的`docker-compose.yml`文件：

```
$ docker-compose config
```

如果没有问题，它将在屏幕上打印出您的 Docker Compose YAML 文件的渲染副本；这是 Docker Compose 将解释您的文件的方式。如果您不想看到这个输出，只想检查错误，那么您可以运行以下命令：

```
$ docker-compose config -q
```

这是`--quiet`的简写。如果有任何错误，我们到目前为止所做的示例中不应该有错误，它们将显示如下：

```
ERROR: yaml.parser.ParserError: while parsing a block mapping in "./docker-compose.yml", line 1, column 1 expected <block end>, but found '<block mapping start>' in "./docker-compose.yml", line 27, column 3
```

# Pull，build 和 create

接下来的两个命令将帮助您准备启动 Docker Compose 应用程序。以下命令将读取您的 Docker Compose YAML 文件并拉取它找到的任何镜像：

```
$ docker-compose pull
```

以下命令将执行在您的文件中找到的任何构建指令：

```
$ docker-compose build
```

当您首次定义 Docker Compose 应用程序并希望在启动应用程序之前进行测试时，这些命令非常有用。如果 Dockerfile 有更新，`docker-compose build`命令也可以用来触发构建。

`pull`和`build`命令只生成/拉取我们应用程序所需的镜像；它们不配置容器本身。为此，我们需要使用以下命令：

```
$ docker-compose create
```

这将创建但不启动容器。与`docker container create`命令一样，它们将处于退出状态，直到您启动它们。`create`命令有一些有用的标志可以传递：

+   `--force-recreate`：即使配置没有更改，也会重新创建容器

+   `--no-recreate`：如果容器已经存在，则不重新创建；此标志不能与前一个标志一起使用

+   `--no-build`：即使缺少需要构建的镜像，也不会构建镜像

+   `--build`：在创建容器之前构建镜像

# 开始，停止，重新启动，暂停和取消暂停

以下命令的工作方式与它们的 docker 容器对应物完全相同，唯一的区别是它们会对所有容器产生影响：

```
$ docker-compose start
$ docker-compose stop
$ docker-compose restart
$ docker-compose pause
$ docker-compose unpause
```

可以通过传递服务名称来针对单个服务；例如，要`暂停`和`取消暂停` `db` 服务，我们可以运行以下命令：

```
$ docker-compose pause db
$ docker-compose unpause db
```

# Top，logs 和 events

接下来的三个命令都会向我们提供有关正在运行的容器和 Docker Compose 中发生的情况的反馈。

与其 docker 容器对应物一样，以下命令显示了在我们的 Docker Compose 启动的每个容器中运行的进程的信息：

```
$ docker-compose top
```

从以下终端输出可以看到，每个容器都分成了自己的部分：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/ms-dkr-3e/img/47672e5f-ef23-41ba-96ac-f09431f5030f.png)

如果您只想看到其中一个服务，只需在运行命令时传递其名称：

```
$ docker-compose top db
```

下一个命令会将每个正在运行的容器的`logs`流式传输到屏幕上：

```
$ docker-compose logs
```

与`docker container`命令一样，您可以传递标志，如`-f`或`--follow`，以保持流式传输，直到按下*Ctrl* + *C*。此外，您可以通过在命令末尾附加其名称来为单个服务流式传输日志：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/ms-dkr-3e/img/ce0c8f42-1208-4a13-b767-c02b3bb462ef.png)

`events`命令再次像 docker 容器版本一样工作；它实时流式传输事件，例如我们一直在讨论的其他命令触发的事件。例如，运行此命令：

```
$ docker-compose events
```

在第二个终端窗口中运行`docker-compose pause`会得到以下输出：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/ms-dkr-3e/img/332e23d6-bc34-4a7e-8e48-c1b910707a23.png)

这两个命令类似于它们的 docker 容器等效命令。运行以下命令：

```
$ docker-compose exec worker ping -c 3 db
```

这将在已经运行的`worker`容器中启动一个新进程，并对`db`容器进行三次 ping，如下所示：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/ms-dkr-3e/img/0647960c-03ed-4c9d-9e24-259c4e0ab85f.png)

`run`命令在应用程序中需要以容器化命令运行一次时非常有用。例如，如果您使用诸如 composer 之类的软件包管理器来更新存储在卷上的项目的依赖关系，可以运行类似以下命令：

```
$ docker-compose run --volume data_volume:/app composer install
```

这将使用`install`命令在`composer`容器中运行，并将`data_volume`挂载到容器内的`/app`。

# 规模

`scale`命令将接受您传递给命令的服务，并将其扩展到您定义的数量；例如，要添加更多的 worker 容器，我只需要运行以下命令：

```
$ docker-compose scale worker=3
```

然而，这实际上会给出以下警告：

```
WARNING: The scale command is deprecated. Use the up command with the -scale flag instead.
```

我们现在应该使用以下命令：

```
$ docker-compose up -d --scale worker=3
```

虽然`scale`命令在当前版本的 Docker Compose 中存在，但它将在将来的软件版本中被移除。

您会注意到我选择了扩展 worker 容器的数量。这是有充分理由的，如果您尝试运行以下命令，您将自己看到：

```
$ docker-compose up -d --scale vote=3
```

您会注意到，虽然 Docker Compose 创建了额外的两个容器，但它们未能启动，并显示以下错误：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/ms-dkr-3e/img/4a6ae0cb-5db8-4bf8-99cc-2cc1c667be78.png)

这是因为我们不能有三个单独的容器都试图映射到相同的端口。对此有一个解决方法，我们将在后面的章节中更详细地讨论。

# Kill、rm 和 down

我们最终要看的三个 Docker Compose 命令是用来移除/终止我们的 Docker Compose 应用程序的命令。第一个命令通过立即停止运行的容器进程来停止我们正在运行的容器。这就是`kill`命令：

```
$ docker-compose kill
```

运行此命令时要小心，因为它不会等待容器优雅地停止，比如运行`docker-compose stop`时，使用`docker-compose kill`命令可能会导致数据丢失。

接下来是`rm`命令；这将删除任何状态为`exited`的容器：

```
$ docker-compose rm
```

最后，我们有`down`命令。你可能已经猜到了，它的效果与运行`docker-compose up`相反：

```
$ docker-compose down
```

这将删除运行`docker-compose up`时创建的容器和网络。如果要删除所有内容，可以通过运行以下命令来实现：

```
$ docker-compose down --rmi all --volumes
```

当你运行`docker-compose up`命令时，这将删除所有容器、网络、卷和镜像（包括拉取和构建的镜像）；这包括可能在 Docker Compose 应用程序之外使用的镜像。但是，如果镜像正在使用中，将会出现错误，并且它们将不会被移除：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/ms-dkr-3e/img/08087e2a-53d9-4ff6-829c-6133c8470532.png)

从前面的输出中可以看到，有一个使用`redis`镜像的容器，Moby 计数器应用程序，因此它没有被移除。然而，Example Vote 应用程序使用的所有其他镜像都被移除了，包括作为初始`docker-compose up`的一部分构建的镜像，以及从 Docker Hub 下载的镜像。

# Docker App

在开始本节之前，我应该发出以下警告：

*我们将要讨论的功能非常实验性。它还处于早期开发阶段，不应被视为即将推出的功能的预览以外的东西。*

因此，我只会介绍 macOS 版本的安装。然而，在安装之前，让我们讨论一下 Docker App 到底是什么意思。

虽然 Docker Compose 文件在与他人共享环境时非常有用，但您可能已经注意到，在本章中到目前为止，我们一直缺少一个非常关键的元素，那就是实际上分发您的 Docker Compose 文件的能力，类似于您如何分发 Docker 镜像。

Docker 已经承认了这一点，并且目前正在开发一个名为 Docker App 的新功能，希望能填补这一空白。

**Docker App**是一个自包含的二进制文件，可帮助您创建一个可以通过 Docker Hub 或 Docker 企业注册表共享的应用程序包。

我建议检查 GitHub 项目的**R****eleases**页面（您可以在*Further reading*部分找到链接），以确保您使用的是最新版本。如果版本晚于 0.4.1，您将需要在以下命令中替换版本号。

要在 macOS 上安装 Docker App，您可以运行以下命令，首先设置要下载的版本：

```
$ VERSION=v0.4.1
```

现在您已经有了正确的版本，可以使用以下命令下载并放置它：

```
$ curl -SL https://github.com/docker/app/releases/download/$VERSION/docker-app-darwin.tar.gz | tar xJ -C /usr/local/bin/
$ mv /usr/local/bin/docker-app-darwin /usr/local/bin/docker-app
$ chmod +x /usr/local/bin/docker-app
```

一旦就位，您应该能够运行以下命令，在屏幕上打印一些关于二进制的基本信息：

```
$ docker-app version
```

可以在此处查看前述命令的完整输出，供不跟随的人参考：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/ms-dkr-3e/img/9c5da96b-a744-4c5f-9cb5-3e853db7aa53.png)

我们将使用的`docker-compose.yml`文件有一个轻微的更改。版本需要更新为`3.6`而不仅仅是`3`。不这样做将导致以下错误：

```
Error: unsupported Compose file version: 3
```

我们需要运行的命令，也是生成前述错误的命令，如下所示：

```
$ docker-app init --single-file mobycounter
```

此命令将我们的`docker-compose.yml`文件嵌入`.dockerapp`文件中。最初，文件中将有相当多的注释，详细说明您需要在进行下一步之前进行的更改。我在存储库中留下了一个未更改的文件版本，在`chapter5/mobycounter-app`文件夹中名为`mobycounter.dockerapp.original`。

可以在此处找到`mobycounter.dockerapp`文件的编辑版本：

```
version: latest
name: mobycounter
description: An example Docker App file which packages up the Moby Counter application
namespace: masteringdockerthirdedition
maintainers:
 - name: Russ McKendrick
 email: russ@mckendrick.io

---
version: "3.6"

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
 - "${port}:80"
 restart: always

volumes:
 redis_data:

---

{ "port":"8080" }
```

如您所见，它分为三个部分；第一部分包含有关应用程序的元数据，如下所示：

+   `Version`：这是将在 Docker Hub 上发布的应用程序的版本

+   `Name`：应用程序的名称，将显示在 Docker Hub 上

+   `Description`：应用程序的简短描述

+   名称空间：这通常是您的 Docker Hub 用户名或您可以访问的组织

+   维护者：应用程序的维护者列表

第二部分包含我们的 Docker Compose 文件。您可能会注意到一些选项已被替换为变量。在我们的示例中，我已经用`${port}`替换了端口`8080`。`port`变量的默认值在最后一部分中定义。

一旦`.dockerapp`文件完成，您可以运行以下命令将 Docker 应用程序保存为镜像：

```
$ docker-app save
```

您可以通过运行以下命令仅查看您在主机上激活的 Docker 应用程序：

```
$ docker-app ls
```

由于 Docker 应用程序主要只是包装在标准 Docker 镜像中的一堆元数据，您也可以通过运行以下命令来查看它：

```
$ docker image ls
```

如果您没有跟随这部分，您可以在此处查看终端输出的结果：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/ms-dkr-3e/img/b63c6b9b-a8dd-40fa-9651-068f329248e4.png)

运行以下命令可以概述 Docker 应用程序，就像您可以使用`docker image inspect`来查找有关镜像构建方式的详细信息一样：

```
$ docker-app inspect masteringdockerthirdedition/mobycounter.dockerapp:latest
```

如您从以下终端输出中所见，使用`docker-app inspect`而不是`docker image inspect`运行命令会得到更友好的输出：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/ms-dkr-3e/img/81756d0f-6074-4664-8738-faf34d524d47.png)

现在我们已经完成了我们的应用程序，我们需要将其推送到 Docker Hub。要做到这一点，只需运行以下命令：

```
$ docker-app push
```

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/ms-dkr-3e/img/eced72f8-ac1c-4291-a9a1-ff80917c217c.png)

这意味着我们的应用程序现在已发布在 Docker Hub 上：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/ms-dkr-3e/img/449dc815-8dcf-408d-a7b7-fad918ab0dd0.png)

那么如何获取 Docker 应用程序呢？首先，我们需要删除本地镜像。要做到这一点，请运行以下命令：

```
$ docker image rm masteringdockerthirdedition/mobycounter.dockerapp:latest
```

一旦删除，移动到另一个目录：

```
$ cd ~/
```

现在，让我们下载 Docker 应用程序，更改端口并启动它：

```
$ docker-app render masteringdockerthirdedition/mobycounter:latest --set port="9090" | docker-compose -f - up
```

同样，对于那些没有跟随的人，可以在此找到前述命令的终端输出：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/ms-dkr-3e/img/5d14eae8-47a2-4f33-92d7-e7ad8427c401.png)

如您所见，甚至无需手动下载 Docker 应用程序镜像，我们的应用程序就已经运行起来了。转到`http://localhost:9090/`应该会显示一个邀请您点击添加标志的屏幕。

与正常的前台 Docker Compose 应用程序一样，按下*Ctrl* + *C*返回到您的终端。

您可以运行以下命令来交互和终止您的应用程序：

```
$ docker-app render masteringdockerthirdedition/mobycounter:latest --set port="9090" | docker-compose -f - ps $ docker-app render masteringdockerthirdedition/mobycounter:latest --set port="9090" | docker-compose -f - down --rmi all --volumes
```

Docker App 中还有更多功能。但我们还没有准备好进一步详细讨论。我们将在第八章，Docker Swarm 和第九章，Docker 和 Kubernetes 中回到 Docker App。

如本节顶部所述，此功能处于早期开发阶段，我们讨论的命令和功能可能会在未来发生变化。但即使在这个早期阶段，我希望您能看到 Docker App 的优势，以及它是如何在 Docker Compose 奠定的坚实基础上构建的。

# 摘要

希望您喜欢这一章关于 Docker Compose 的内容，我希望您能像我一样看到它已经从一个非常有用的第三方工具发展成为核心 Docker 体验中非常重要的一部分。

Docker Compose 引入了一些关键概念，指导您如何运行和管理容器。我们将在第八章，Docker Swarm 和第九章，Docker 和 Kubernetes 中进一步探讨这些概念。

在下一章中，我们将远离基于 Linux 的容器，快速了解 Windows 容器。

# 问题

1.  Docker Compose 文件使用哪种开源格式？

1.  在我们最初的 Moby 计数器 Docker Compose 文件中，哪个标志与其 Docker CLI 对应物完全相同？

1.  真或假：您只能在 Docker Compose 文件中使用 Docker Hub 的镜像？

1.  默认情况下，Docker Compose 如何决定要使用的命名空间？

1.  在 docker-compose up 中添加哪个标志以在后台启动容器？

1.  运行 Docker Compose 文件的语法检查的最佳方法是什么？

1.  解释 Docker App 工作的基本原理。

# 进一步阅读

有关 Orchard Laboratories 的详细信息，请参阅以下内容：

+   Orchard Laboratories 网站：[`www.orchardup.com/`](https://www.orchardup.com/)

+   Orchard Laboratories 加入 Docker：[`blog.docker.com/2014/07/welcoming-the-orchard-and-fig-team`](https://blog.docker.com/2014/07/welcoming-the-orchard-and-fig-team)

有关 Docker App 项目的更多信息，请参阅以下内容：

+   GitHub 存储库：[`github.com/docker/app/`](http://github.com/docker/app/)

+   发布页面 - [`github.com/docker/app/releases`](https://github.com/docker/app/releases)

最后，这里有一些我们涵盖的其他主题的进一步链接：

+   YAML 项目主页：[`www.yaml.org/`](http://www.yaml.org/)

+   Docker 示例仓库：[`github.com/dockersamples/`](https://github.com/dockersamples/)


# 第六章：Windows 容器

在这一章中，我们将讨论并了解 Windows 容器。微软已经接受容器作为在新硬件上部署旧应用程序的一种方式。与 Linux 容器不同，Windows 容器仅在基于 Windows 的 Docker 主机上可用。

在本章中，我们将涵盖以下主题：

+   Windows 容器简介

+   为 Windows 容器设置 Docker 主机

+   运行 Windows 容器

+   Windows 容器 Dockerfile

+   Windows 容器和 Docker Compose

# 技术要求

与之前的章节一样，我们将继续使用我们的本地 Docker 安装。同样，在本章中的屏幕截图将来自我首选的操作系统 macOS——是的，即使我们将要运行 Windows 容器，你仍然可以使用你的 macOS 客户端。稍后会详细介绍。

我们将运行的 Docker 命令将在我们迄今为止安装了 Docker 的三种操作系统上运行。然而，在本章中，我们将启动的容器只能在 Windows Docker 主机上运行。我们将在 macOS 和基于 Linux 的机器上使用 VirtualBox 和 Vagrant 来帮助启动和运行 Windows Docker 主机。

本章中使用的代码的完整副本可以在[`github.com/PacktPublishing/Mastering-Docker-Third-Edition/tree/master/chapter06/`](https://github.com/PacktPublishing/Mastering-Docker-Third-Edition/tree/master/chapter06/)找到。

查看以下视频以查看代码的实际操作：

[`bit.ly/2PfjuSR`](http://bit.ly/2PfjuSR)

# Windows 容器简介

作为一个在过去 20 年里几乎每天都在使用 macOS 和 Linux 计算机和笔记本电脑以及 Linux 服务器的人，再加上我唯一的微软 Windows 的经验是我拥有的 Windows XP 和 Windows 10 游戏 PC，以及我在工作中无法避免的偶尔的 Windows 服务器，Windows 容器的出现是一个有趣的发展。

现在，我从来没有认为自己是 Linux/UNIX 的粉丝。然而，微软在过去几年的行动甚至让我感到惊讶。在 2014 年的 Azure 活动中，微软宣布"Microsoft![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/ms-dkr-3e/img/ef26c732-b5bc-41ad-a5e7-e32524861a68.png)Linux"，自那以后就一发不可收拾：

+   Linux 在 Microsoft Azure 中是一等公民

+   .NET Core 是跨平台的，这意味着你可以在 Linux 和 Windows 上运行你的.NET 应用程序。

+   SQL Server 现在可以在 Linux 上使用

+   你可以在 Windows 10 专业版机器上运行 Linux shell，比如 Ubuntu。

+   PowerShell 已经移植到 Linux。

+   微软开发了跨平台工具，比如 Visual Studio Code，并将其开源。

+   微软以 75 亿美元收购 GitHub！

很明显，昔日的微软已经不复存在，前任 CEO 史蒂夫·鲍尔默曾经公开嘲讽开源和 Linux 社区，称他们的话不适合在这里重复。

因此，这一宣布并不令人意外。在微软公开宣布对 Linux 的喜爱后的几个月，即 2014 年 10 月，微软和 Docker 宣布合作，推动在基于 Windows 的操作系统上，如 Windows 10 专业版和 Windows Server 2016 上采用容器技术。

那么 Windows 容器是什么？

从表面上看，它们与 Linux 容器没有什么不同。微软在 Windows 内核上的工作引入了与 Linux 上发现的相同的进程隔离。而且，与 Linux 容器一样，这种隔离还延伸到一个沙盒文件系统，甚至是 Windows 注册表。

由于每个容器实际上都是一个全新的 Windows Core 或 Windows Nano，这些又是精简的 Windows 服务器镜像（可以想象成 Windows 版的 Alpine Linux），安装管理员可以在同一台主机上运行多个 Docker 化的应用程序，而无需担心任何自定义注册表更改或需求冲突和引起问题。

再加上 Docker 命令行客户端提供的同样易用性，管理员们可以将传统应用迁移到更现代的硬件和主机操作系统，而无需担心管理多个运行旧不受支持版本 Windows 的虚拟机所带来的问题和开销。

Windows 容器还提供了另一层隔离。当容器启动时，Hyper-V 隔离在最小的虚拟机监视器内运行容器进程。这进一步将容器进程与主机机器隔离开来。然而，使用 Hyper-V 隔离的每个容器需要额外的资源，而且启动时间也会增加，因为需要在容器启动之前启动虚拟机监视器。

虽然 Hyper-V 隔离确实使用了微软的虚拟化技术，可以在 Windows 服务器和桌面版以及 Xbox One 系统软件中找到，但你不能使用标准的 Hyper-V 管理工具来管理 Hyper-V 隔离的容器。你必须使用 Docker。

在微软不得不投入大量工作和努力来启用 Windows 内核中的容器之后，为什么他们选择了 Docker 而不是创建自己的管理工具呢？

Docker 已经成为管理容器的首选工具，具有一组经过验证的 API 和庞大的社区。而且，它是开源的，这意味着微软不仅可以适应其在 Windows 上的使用，还可以为其发展做出贡献。

以下图表概述了 Windows 上的 Docker 的工作原理：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/ms-dkr-3e/img/0021ddf3-befc-4ebf-ab5a-f0d066aa5463.png)

请注意，我说的是 Windows 上的 Docker，而不是 Docker for Windows；它们是非常不同的产品。Windows 上的 Docker 是与 Windows 内核交互的 Docker 引擎和客户端的本机版本，以提供 Windows 容器。Docker for Windows 是开发人员在其桌面上运行 Linux 和 Windows 容器的尽可能本机的体验。

# 为 Windows 容器设置 Docker 主机

正如你可能已经猜到的，你需要访问一个运行 Docker 的 Windows 主机。如果你没有运行 Windows 10 专业版的机器，也不用太担心——你可以在 macOS 和 Linux 上实现这一点。在我们讨论这些方法之前，让我们看看如何在 Windows 10 专业版上使用 Docker for Windows 安装运行 Windows 容器。

# Windows 10 专业版

**Windows 10 专业版**原生支持 Windows 容器。但默认情况下，它配置为运行 Linux 容器。要从运行 Linux 容器切换到 Windows 容器，右键单击系统托盘中的 Docker 图标，然后从菜单中选择**切换到 Windows 容器...**：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/ms-dkr-3e/img/fe51cd8e-9f4c-455d-b29e-35619f7b1e3f.png)

这将弹出以下提示：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/ms-dkr-3e/img/e278b88e-0e03-4cb2-b98b-40babb3dce46.png)

点击**切换**按钮，几秒钟后，你现在将管理 Windows 容器。你可以通过打开提示符并运行以下命令来查看：

```
$ docker version
```

可以从以下输出中看到这一点：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/ms-dkr-3e/img/12ba843c-1fe8-4489-b1de-4469687e8470.png)

Docker 引擎的`OS/Arch`为`windows/amd64`，而不是我们到目前为止一直看到的`linux/amd64`。那就涵盖了 Windows 10 专业版。但是像我这样更喜欢 macOS 和 Linux 的人呢？

# macOS 和 Linux

为了在 macOS 和 Linux 机器上访问 Windows 容器，我们将使用 Stefan Scherer 整理的优秀资源。在本书附带的存储库的`chapter06`文件夹中，有 Stefan 的 Windows - `docker-machine repo`的分支版本，其中包含您在 macOS 上运行 Windows 容器所需的所有文件。

在我们开始之前，您将需要以下工具 - Hashicorp 的 Vagrant 和 Oracle 的 Virtualbox。您可以从以下位置下载这些工具：

+   [`www.vagrantup.com/downloads.html`](https://www.vagrantup.com/downloads.html)

+   [`www.virtualbox.org/wiki/Downloads`](https://www.virtualbox.org/wiki/Downloads)

下载并安装后，打开终端，转到`chapter06/docker-machine`存储库文件夹，并运行以下命令：

```
$ vagrant up --provider virtualbox 2016-box
```

这将下载一个包含运行 Windows 容器所需的所有内容的 VirtualBox Windows Server 2016 核心评估映像。下载文件大小略大于 10 GB，因此请确保您具有足够的带宽和磁盘空间来运行该映像。

Vagrant 将启动映像，配置 VM 上的 Docker，并将所需的证书文件复制到您的本地 Docker 客户端以与主机进行交互。要切换到使用新启动的 Docker Windows 主机，只需运行以下命令：

```
$ eval $(docker-machine env 2016-box)
```

我们将在下一章节中更详细地介绍 Docker Machine。然而，前面的命令已重新配置了您的本地 Docker 客户端，以便与 Docker Windows 主机通信。您可以通过运行以下命令来查看：

```
$ docker version
```

如果您不跟着操作，可以查看下面的预期输出：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/ms-dkr-3e/img/064755f6-ee49-4fe6-b71b-0973b323a80f.png)

如您所见，我们现在连接到运行`windows/amd64`的 Docker 引擎。要切换回，您可以重新启动终端会话，或者运行以下命令：

```
$ eval $(docker-machine env -unset)
```

完成 Docker Windows 主机后，可以运行以下命令来停止它：

```
$ vagrant halt
```

或者，要完全删除它，请运行以下命令：

```
$ vagrant destroy
```

前面的命令必须在`chapter06/docker-machine`存储库文件夹中运行。

# 运行 Windows 容器

正如本章的第一部分所暗示的，使用 Docker 命令行客户端启动和与 Windows 容器交互与我们迄今为止运行的方式没有任何不同。让我们通过运行`hello-world`容器来测试一下：

```
$ docker container run hello-world
```

就像以前一样，这将下载`hello-world`容器并返回一条消息：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/ms-dkr-3e/img/b1f3e83b-2a2f-4089-b125-d13066170b11.png)

这一次唯一的区别是，Docker 不是拉取 Linux 镜像，而是拉取了基于`nanoserver-sac2016`镜像的`windows-amd64`版本的镜像。

现在，让我们来看看在前台运行容器，这次运行 PowerShell：

```
$ docker container run -it microsoft/windowsservercore  powershell
```

一旦您的 shell 处于活动状态，运行以下命令将为您提供计算机名称，即容器 ID：

```
$ Get-CimInstance -ClassName Win32_Desktop -ComputerName . 
```

您可以在下面的终端输出中看到上述命令的完整输出：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/ms-dkr-3e/img/9dce60a5-07b2-411d-9cae-7eb02d587ff7.png)

一旦您通过运行`exit`退出了 PowerShell，您可以通过运行以下命令查看容器 ID：

```
$ docker container ls -a
```

您可以在下面的屏幕中看到预期的输出：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/ms-dkr-3e/img/48cc683a-524b-44f7-b0a2-e1382991fd5f.png)

现在，让我们来看看构建一个执行某些操作的镜像。

# 一个 Windows 容器 Dockerfile

Windows 容器镜像使用与 Linux 容器相同的 Dockerfile 命令格式。以下 Dockerfile 将在容器上下载、安装和启用 IIS Web 服务器：

```
# escape=`
FROM microsoft/nanoserver:sac2016

RUN powershell -NoProfile -Command `
    New-Item -Type Directory C:\install; `
    Invoke-WebRequest https://az880830.vo.msecnd.net/nanoserver-ga-2016/Microsoft-NanoServer-IIS-Package_base_10-0-14393-0.cab -OutFile C:\install\Microsoft-NanoServer-IIS-Package_base_10-0-14393-0.cab; `
    Invoke-WebRequest https://az880830.vo.msecnd.net/nanoserver-ga-2016/Microsoft-NanoServer-IIS-Package_English_10-0-14393-0.cab -OutFile C:\install\Microsoft-NanoServer-IIS-Package_English_10-0-14393-0.cab; `
    dism.exe /online /add-package /packagepath:c:\install\Microsoft-NanoServer-IIS-Package_base_10-0-14393-0.cab & `
    dism.exe /online /add-package /packagepath:c:\install\Microsoft-NanoServer-IIS-Package_English_10-0-14393-0.cab & `
    dism.exe /online /add-package /packagepath:c:\install\Microsoft-NanoServer-IIS-Package_base_10-0-14393-0.cab & ;`
    powershell -NoProfile -Command `
    Remove-Item -Recurse C:\install\ ; `
    Invoke-WebRequest https://dotnetbinaries.blob.core.windows.net/servicemonitor/2.0.1.3/ServiceMonitor.exe -OutFile C:\ServiceMonitor.exe; `
    Start-Service Was; `
    While ((Get-ItemProperty HKLM:\SYSTEM\CurrentControlSet\Services\WAS\Parameters\ -Name NanoSetup -ErrorAction Ignore) -ne $null) {Start-Sleep 1}

EXPOSE 80

ENTRYPOINT ["C:\\ServiceMonitor.exe", "w3svc"]
```

您可以使用以下命令构建镜像：

```
$ docker image build --tag local:dockerfile-iis .
```

构建后，运行`docker image ls`应该显示以下内容：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/ms-dkr-3e/img/57a6cc54-4042-4683-a586-a74f8c423a3b.png)

关于 Windows 容器镜像，您会立即注意到它们很大。这是在 Server 2019 发布时正在解决的问题。

使用以下命令运行容器将启动 IIS 镜像：

```
$ docker container run -d --name dockerfile-iis -p 8080:80 local:dockerfile-iis
```

您可以通过打开浏览器来看到您新启动的容器在运行。但是，您需要通过容器的 NAT IP 访问它，而不是转到`http://localhost``:8080/`。如果您使用的是 Windows 10 专业版，可以通过运行以下命令找到 NAT IP：

```
$ docker inspect --format="{{.NetworkSettings.Networks.nat.IPAddress}}" dockerfile-iis
```

这将为您提供一个 IP 地址，只需在末尾添加`8080/`；例如，`http://172.31.20.180:8080/`。

macOS 用户可以运行以下命令，使用我们启动的 Vagrant VM 的 IP 地址来打开他们的浏览器：

```
$ open http://$(docker-machine ip 2016-box):8080/
```

无论您在哪个操作系统上启动了 IIS 容器，您都应该看到以下默认的临时页面：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/ms-dkr-3e/img/13e49dd0-5f66-4d63-aaa7-a98ea2e989af.png)

要停止和删除我们迄今为止启动的容器，请运行以下命令：

```
$ docker container stop dockerfile-iis
$ docker container prune
```

到目前为止，我相信您会同意，这种体验与使用基于 Linux 的容器的 Docker 没有任何不同。

# Windows 容器和 Docker Compose

在本章的最后一节中，我们将看看如何在 Windows Docker 主机上使用 Docker Compose。正如您已经猜到的那样，与我们在上一章中运行的命令相比，几乎没有什么变化。在存储库的`chapter06`文件夹中，有一个来自 Docker 示例存储库的`dotnet-album-viewer`应用程序的分支，因为它附带了一个`docker-compose.yml`文件。

Docker Compose 文件如下所示：

```
version: '2.1'

services:
 db:
 image: microsoft/mssql-server-windows-express
 environment:
 sa_password: "DockerCon!!!"
 ACCEPT_EULA: "Y"
 healthcheck:
 test: [ "CMD", "sqlcmd", "-U", "sa", "-P", "DockerCon!!!", "-Q", "select 1" ]
 interval: 2s
 retries: 10

 app:
 image: dockersamples/dotnet-album-viewer
 build:
 context: .
 dockerfile: docker/app/Dockerfile
 environment:
 - "Data:useSqLite=false"
 - "Data:SqlServerConnectionString=Server=db;Database=AlbumViewer;User Id=sa;Password=DockerCon!!!;MultipleActiveResultSets=true;App=AlbumViewer"
 depends_on:
 db:
 condition: service_healthy
 ports:
 - "80:80"

networks:
 default:
 external:
 name: nat
```

正如您所看到的，它使用与我们之前查看的 Docker Compose 文件相同的结构、标志和命令，唯一的区别是我们使用了专为 Windows 容器设计的 Docker Hub 中的镜像。

要构建所需的镜像，只需运行以下命令：

```
$ docker-compose build
```

然后，一旦构建完成，使用以下命令启动：

```
$ docker-compose up -d
```

与之前一样，然后您可以使用此命令查找 Windows 上的 IP 地址：

```
$ docker inspect -f "{{ .NetworkSettings.Networks.nat.IPAddress }}" musicstore_web_1
```

要打开应用程序，您只需要在浏览器中输入您的 Docker 主机的 IP 地址。如果您正在使用 macOS，运行以下命令：

```
$ open http://$(docker-machine ip 2016-box)/
```

您应该看到以下页面：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/ms-dkr-3e/img/8fe03330-f09d-4274-96c9-8bdbc5e641e9.png)

完成应用程序后，您可以运行以下命令来删除它：

```
$ docker-compose down --rmi all --volumes
```

# 总结

在本章中，我们简要介绍了 Windows 容器。正如您所见，由于微软采用了 Docker 作为 Windows 容器的管理工具，这种体验对于任何已经使用 Docker 来管理 Linux 容器的人来说都是熟悉的。

在下一章中，我们将更详细地了解 Docker Machine。

# 问题

1.  Windows 上的 Docker 引入了哪种额外的隔离层？

1.  您将使用哪个命令来查找 Windows 容器的 NAT IP 地址？

1.  真或假：Windows 上的 Docker 引入了一组额外的命令，您需要使用这些命令来管理 Windows 容器？

# 进一步阅读

您可以在本章提到的主题中找到更多信息如下：

+   Docker 和微软合作公告：[`blog.docker.com/2014/10/docker-microsoft-partner-distributed-applications/`](https://blog.docker.com/2014/10/docker-microsoft-partner-distributed-applications/)

+   Windows Server 和 Docker-将 Docker 和容器引入 Windows 背后的内部机制：[`www.youtube.com/watch?v=85nCF5S8Qok`](https://www.youtube.com/watch?v=85nCF5S8Qok)

+   Stefan Scherer 在 GitHub 上：[`github.com/stefanScherer/`](https://github.com/stefanScherer/)

+   `dotnet-album-viewer`存储库：[`github.com/dockersamples/dotnet-album-viewer`](https://github.com/dockersamples/dotnet-album-viewer)
