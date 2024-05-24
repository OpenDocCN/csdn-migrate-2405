# SpringBoot 和 SpringCloud 微服务实用指南（二）

> 原文：[`zh.annas-archive.org/md5/328F7FCE73118A0BA71B389914A67B52`](https://zh.annas-archive.org/md5/328F7FCE73118A0BA71B389914A67B52)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第四章：使用 Docker 部署我们的微服务。

在本章中，我们将开始使用 Docker 并将我们的微服务放入容器中！

到本章末尾，我们将运行完全自动化的微服务架构测试，以 Docker 容器的形式启动我们的所有微服务，除了 Docker 引擎之外不需要其他基础架构。我们还将运行一系列测试，以验证微服务按预期一起工作，并在最后关闭所有微服务，不留下我们执行的测试的任何痕迹。

能够以这种方式测试多个协作的微服务非常有用。作为开发者，我们可以在本地开发机上验证其工作效果。我们还可以在构建服务器上运行完全相同的测试，以自动验证源代码的更改不会在系统层面破坏测试。此外，我们不需要为运行这些类型的测试分配专用的基础架构。在接下来的章节中，我们将了解如何将数据库和队列管理器添加到我们的测试架构中，所有这些都将作为 Docker 容器运行。

然而，这并不取代自动化单元和集成测试的需要，这些测试孤立地测试单个微服务。它们的重要性与日俱增。

对于生产使用，如本书前面提到的，我们需要一个容器编排器，如 Kubernetes。我们将在本书后面回到容器编排器和 Kubernetes。

本章将涵盖以下主题：

+   容器简介。

+   Docker 和 Java。Java 在历史上对容器并不友好，但随着 Java 10 的发布，这一切都改变了。让我们看看 Docker 和 Java 在这个话题上是如何结合在一起的！

+   使用 Docker 和一个微服务。

+   使用 Docker Compose 管理微服务架构。

+   自动测试它们全部。

# 技术要求

本书中描述的所有命令都是在 MacBook Pro 上使用 macOS Mojave 运行的，但如果你想在其他平台（如 Linux 或 Windows）上运行它们，应该很容易进行修改。

除了前章的技术要求之外，我们还需要安装 Docker。Docker 社区版可以从 [`store.docker.com/search?type=edition&offering=community`](https://store.docker.com/search?type=edition&offering=community)[下载](https://store.docker.com/search?type=edition&offering=community)。

为了能够运行本书中的示例，建议您配置 Docker，使其可以使用除一个以外的所有 CPU（将所有 CPU 分配给 Docker 可能会在测试运行时使计算机失去响应）以及至少 6 GB 的内存。这可以在 Docker 的“偏好设置”的“高级”选项卡中配置，如下面的屏幕截图所示：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/hsn-msvc-sprbt-sprcld/img/5fe1ee81-076f-4652-b550-bd63ba45cc3e.png)

本章的源代码可以在本书的 GitHub 仓库中找到：[`github.com/PacktPublishing/Hands-On-Microservices-with-Spring-Boot-and-Spring-Cloud/tree/master/Chapter04`](https://github.com/PacktPublishing/Hands-On-Microservices-with-Spring-Boot-and-Spring-Cloud/tree/master/Chapter04)。

为了能够运行本书中描述的命令，将源代码下载到一个文件夹中，并设置一个环境变量`$BOOK_HOME`，该变量指向该文件夹。一些示例命令如下：

```java
export BOOK_HOME=~/Documents/Hands-On-Microservices-with-Spring-Boot-and-Spring-Cloud
git clone https://github.com/PacktPublishing/Hands-On-Microservices-with-Spring-Boot-and-Spring-Cloud $BOOK_HOME
cd $BOOK_HOME/Chapter04
```

本章所用的 Java 源代码是为 Java 8 编写的，并在 Java 12 上进行了测试运行。在本章写作时，Spring Boot 的最新版本是 2.1.0（以及 Spring 5.1.2）。

本章中的代码示例都来自`$BOOK_HOME/Chapter04`的源代码，但在许多情况下，已经编辑了源代码中不相关部分，例如注释、导入和日志声明。

如果你想查看本章应用于源代码中的更改，即了解为 Docker 添加支持所做的工作，你可以将第三章创建一组协作的微服务的源代码进行比较，*创建一组协作的微服务*。你可以使用你喜欢的`diff`工具，比较两个文件夹`$BOOK_HOME/Chapter03/2-basic-rest-services`和`$BOOK_HOME/Chapter04`。

# 容器入门

正如我们在第二章 Spring Boot 入门中提到的，Docker 在 2013 年使容器作为轻量级虚拟机替代品的概念变得非常流行。容器实际上是在使用 Linux 命名空间的 Linux 主机上处理的，以提供隔离容器之间全局系统资源的隔离，例如用户、进程、文件系统和网络。**Linux 控制组**（也称为**cgroups**）用于限制容器可以消耗的 CPU 和内存量。与在每台虚拟机中使用虚拟化器运行操作系统完整副本相比，容器的开销只是虚拟机开销的一小部分。这导致了更快的启动时间以及 CPU 和内存使用上的显著降低。然而，容器提供的隔离被认为不如虚拟机提供的隔离安全。随着 Windows Server 2016 和 Windows 10 Pro（1607 周年更新）的发布，微软也开始支持在 Windows 上使用 Docker。请看下面的图表：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/hsn-msvc-sprbt-sprcld/img/caee1a35-71e9-4b6c-953f-b00a2d6eaca3.png)

前一个图表说明了虚拟机和容器的资源使用差异，可视化同一类型的服务器可以运行远比虚拟机更多的容器。

# 运行我们的第一个 Docker 命令

-   让我们尝试通过使用 Docker 的`run`命令在 Docker 中启动一个 Ubuntu 服务器：

```java
docker run -it --rm ubuntu
```

-   使用前面的命令，我们要求 Docker 创建一个运行 Ubuntu 的容器，基于官方 Docker 镜像中可用的最新版本的 Ubuntu。`-it`选项用于使我们能够使用终端与容器交互，`--rm`选项告诉 Docker，一旦我们退出终端会话，就删除容器；否则，容器将保留在 Docker 引擎中，状态为`Exited`。

-   第一次使用我们没有自己构建的 Docker 镜像时，Docker 将从 Docker 注册表中下载它，默认是 Docker Hub ([`hub.docker.com`](https://hub.docker.com))。这需要一些时间，但对于该 Docker 镜像的后续使用，容器将在几秒钟内启动！

-   一旦 Docker 镜像下载完毕并启动容器，Ubuntu 服务器应该会以如下提示响应：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/hsn-msvc-sprbt-sprcld/img/39044aaf-927e-4210-9731-1a3f10fedd10.png)

-   我们可以尝试通过询问它运行的是哪个版本的 Ubuntu 来测试容器：

```java
cat /etc/os-release | grep 'VERSION='
```

-   它应该会像下面这样响应：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/hsn-msvc-sprbt-sprcld/img/60a69639-0969-4d0f-ab2c-f8a2582d51eb.png)

-   我们可以使用`exit`命令离开容器，并验证使用`docker ps -a`命令 Ubuntu 容器是否不再退出。我们需要使用`-a`选项来查看停止的容器；否则，只显示运行中的容器。

-   如果你更喜欢 CentOS 而不是 Ubuntu，可以尝试使用`docker run --rm -it centos`命令。一旦 CoreOS 服务器在其容器中启动运行，你可以，例如，使用`cat /etc/redhat-release`命令询问它运行的是哪个版本的 CoreOS。它应该会像下面这样响应：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/hsn-msvc-sprbt-sprcld/img/0bc608f2-03e6-40ec-a0b4-d343d9eff2b3.png)

-   使用`exit`命令离开容器以删除它。

-   如果你发现 Docker 引擎中有许多不想要的容器，并且你想获得一个干净的起点，即摆脱它们全部，你可以运行以下命令：

```java
docker rm -f $(docker ps -aq)
```

-   `docker rm -f`命令停止并删除指定容器 ID 的容器。`docker ps -aq`命令列出 Docker 引擎中所有运行和停止容器的容器 ID。`-q`选项减少`docker ps`命令的输出，使其只列出容器 ID。

-   在了解 Docker 是什么之后，接下来我们可以理解在 Docker 中运行 Java 时可能遇到的问题。

# -   在 Docker 中运行 Java 的挑战

-   当谈到 Java 时，过去几年里，有很多尝试让 Java 在 Docker 中良好地运行。目前，Java 的官方 Docker 镜像基于 OpenJDK: [`hub.docker.com/_/openjdk/`](https://hub.docker.com/_/openjdk/)。我们将使用带有 Docker 标签`openjdk:12.0.2`的 Java SE 12，即 Java SE v12.0.2。

历史上，Java 在尊重 Docker 容器中 Linux cgroups 指定的配额方面做得并不好；它只是简单地忽略了这些设置。因此，Java 并不是在 JVM 内部根据容器中可用的内存来分配内存，而是好像它能够访问 Docker 主机的所有内存，这显然是不好的！同样，Java 分配与 Docker 主机的总 CPU 核心数相关的资源，如线程池，而不是为运行的 JVM 分配的 CPU 核心数。在 Java SE 9 中，提供了一些初始支持，这也被反向移植到了 Java SE 8 的后续版本中。然而，在 Java 10 中，对 CPU 和内存约束提供了大幅改进的支持。

让我们试一试！

首先，我们将尝试在本地下执行 Java 命令，不使用 Docker，因为这将告诉我们 JVM 看到多少内存和 CPU 核心数。接下来，我们将使用 Java SE 12 在 Docker 中尝试这些命令，以验证它是否尊重我们在其中运行的 Docker 容器上设置的约束。最后，我们还将尝试一个 Java SE 9 容器，并看看它如何不尊重约束以及可能造成什么问题。

# 没有 Docker 的 Java

在我们将自己投入到 Docker 之前，让我们不使用 Docker 尝试 Java 命令，以熟悉 Java 命令！

让我们先找出 Java 在 Docker 外部运行时看到的有多少可用处理器，即 CPU 核心数。我们可以通过将 `Runtime.getRuntime().availableprocessors()` Java 语句发送到 Java CLI 工具 `jshell` 来完成这个操作：

```java
echo 'Runtime.getRuntime().availableProcessors()' | jshell -q
```

`jshell` 需要 Java SE 9 或更高版本！

在我的机器上，我得到以下响应：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/hsn-msvc-sprbt-sprcld/img/47ae0858-fb1f-43ec-988a-303e04880a4d.png)

好吧，`12` 个核心是符合预期的，因为我的笔记本电脑的处理器是六核心的英特尔 Core i9 CPU，具有超线程技术（操作系统为每个物理核心看到两个虚拟核心）。

关于可用的内存量，让我们询问 JVM 它认为可以为其堆分配的最大大小。我们可以通过使用 `-XX:+PrintFlagsFinal` Java 选项向 JVM 请求额外的运行时信息，然后使用 `grep` 命令过滤出 `MaxHeapSize` 参数来实现这一点：

```java
java -XX:+PrintFlagsFinal -version | grep MaxHeapSize 
```

在我的机器上，我得到以下响应：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/hsn-msvc-sprbt-sprcld/img/98ea076e-f964-4885-b262-e8020b7b702c.png)

`8589934592` 字节碰巧正好是 8 GB，即 *8 * 1,024³*。由于我们没有为 JVM 使用 `-Xmx` 参数指定任何最大堆大小，JVM 将最大值设置为可用内存的四分之一。由于我的笔记本电脑有 32 GB 的内存，*32/4=8*，这也是符合预期的！

让我们通过验证能够将最大堆内存大小通过 `-Xmx` 参数降低到例如 200 MB 来总结一下：

```java
java -Xmx200m -XX:+PrintFlagsFinal -version | grep MaxHeapSize
```

JVM 将响应为 *209,715,200* 字节，即 *200 * 1,024³* 字节 = 200 MB，符合预期！

既然我们已经了解了在没有 Docker 的情况下 Java 命令是如何工作的，那么让我们试着用 Docker 来执行这个命令！

# Docker 中的 Java

让我们看看 Java SE 12 如何响应我们在其运行的容器中设置的限制！

由于我使用的是 Docker for macOS，实际上我是在我的 MacBook Pro 上的虚拟机上运行 Docker 引擎作为 Docker 宿主。我已经为 macOS 配置了 Docker，使其允许 Docker 宿主使用我 macOS 中的所有 12 个核心，但只使用最多 16GB 内存。总的来说，Docker 宿主有 12 个核心和 16GB 内存。

# CPU

首先，我们不施加任何限制，也就是说，我们用同样的测试方法，但是不使用 Docker：

```java
echo 'Runtime.getRuntime().availableProcessors()' | docker run --rm -i openjdk:12.0.2 jshell -q
```

这个命令会将`Runtime.getRuntime().availableProcessors()`字符串发送到 Docker 容器，该容器将使用`jshell`处理这个字符串。

它将响应同样的结果，即在我的情况下为`$1 ==> 12`。让我们继续限制 Docker 容器只能使用三个 CPU 核心，使用`--cpus 3` Docker 选项，并询问 JVM 它看到了多少可用的处理器：

```java
echo 'Runtime.getRuntime().availableProcessors()' | docker run --rm -i --cpus 3 openjdk:12.0.2 jshell -q
```

JVM 现在响应为`$1 ==> 3`，即 Java SE 12 尊重容器中的设置，因此，它能够正确配置与 CPU 相关的资源，比如线程池！

让我们试着指定可用的 CPU 的相对份额，而不是 CPU 的确切数量。1024 个份额默认对应一个核心，所以如果我们想要将容器限制为两个核心，我们将`--cpu-shares` Docker 选项设置为 2048，像这样：

```java
echo 'Runtime.getRuntime().availableProcessors()' | docker run --rm -i --cpu-shares 2048 openjdk:12.0.2 jshell -q
```

JVM 将响应`$1 ==> 2`，即 Java SE 12 也尊重相对`share`选项！

尽管`--cpus`选项是一个硬性限制，但`--cpu-shares`选项只有在 Docker 宿主承受高负载时才会生效。这意味着，如果 CPU 资源可用，容器可以消耗比`share`选项显示的更多的 CPU。

接下来，让我们尝试限制内存量。

# 内存

如果没有内存限制，Docker 将把内存的四分之一分配给容器：

```java
docker run -it --rm openjdk:12.0.2 java -XX:+PrintFlagsFinal -version | grep MaxHeapSize
```

它将响应 4,202,692,608 字节，等于 4GB，即*8 * 1024³*。由于我的 Docker 宿主有 16GB 内存，这是正确的，即*16/4 = 4*。

然而，如果我们限制 Docker 容器只能使用最多 1GB 内存，使用`-m=1024M` Docker 选项，我们会看到较低的内存分配：

```java
docker run -it --rm -m=1024M openjdk:12.0.2 java -XX:+PrintFlagsFinal -version | grep MaxHeapSize
```

JVM 将响应 268,435,456 字节，即 256MB，也就是*2 * 1024²*字节。256MB 是 1GB 的四分之一，所以这也在意料之中。

我们可以像往常一样，自己设置最大堆大小。例如，如果我们想要允许堆内存使用 1GB 中的 800MB，我们可以使用`-Xmx800m` Java 选项指定：

```java
docker run -it --rm -m=1024M openjdk:12.0.2 java -Xmx800m -XX:+PrintFlagsFinal -version | grep MaxHeapSize
```

JVM 将响应 838,860,800 字节= *800 * 1024²*字节= 800MB，如预期一样。

最后，让我们通过一些内存溢出测试来确保这真的有效。

让我们使用`jshell`在分配了 1GB 内存的 JVM 中尝试，也就是说，它的最大堆大小为 256MB。

首先，尝试分配一个 100 MB 的字节数组：

```java
echo 'new byte[100_000_000]' | docker run -i --rm -m=1024M openjdk:12.0.2 jshell -q
```

命令将会回应`$1 ==>`，意味着它工作得很好！

通常，`jshell`将打印出命令的结果值，但是 100 MB 的字节数组全部设置为零输出太多，所以我们什么也没有。

现在，让我们尝试分配一个大于最大堆大小的字节数组，例如 500 MB：

```java
echo 'new byte[500_000_000]' | docker run -i --rm -m=1024M openjdk:12.0.2 jshell -q
```

JVM 看到它不能执行该操作，因为它尊重容器的最大内存设置，并立即回应`Exception java.lang.OutOfMemoryError: Java heap space`。太好了！

如果我们使用一个不尊重容器设置的最大内存的 JVM 会怎样？

让我们用 Java SE 9 来找出答案！

# Docker 和 Java SE 9（或更早版本）的问题

首先，尝试使用`openjdk:9-jdk`镜像将 Java SE 9 JVM 限制在三个 CPU 核心。

Java 9 无法遵守三个 CPU 的限制：

```java
echo 'Runtime.getRuntime().availableProcessors()' | docker run --rm -i --cpus 3 openjdk:9-jdk jshell -q
```

在我的机器上，它回应为`$1 ==> 12`，也就是说，它忽略了三个 CPU 核心的限制。

如果我们尝试`--cpu-shares`选项，我们也会得到同样的结果，即`$1 ==> 12`：

```java
echo 'Runtime.getRuntime().availableProcessors()' | docker run --rm -i --cpu-shares 2048 openjdk:9-jdk jshell -q
```

现在，尝试将内存限制为 1 GB：

```java
docker run -it --rm -m=1024M openjdk:9-jdk java -XX:+PrintFlagsFinal -version | grep MaxHeapSize
```

如预期那样，Java SE 9 不尊重我们在 Docker 中设置的内存约束；也就是说，它报告最大堆大小为 4,202,692,608 字节= *4 GB – 4 * 1024³*字节。在这里，Java 9 在给定 Docker 主机的内存时计算了可用的内存，而不是在实际的容器中！

那么，如果我们重复对 Java SE 12 进行的内存分配测试呢？

让我们尝试第一个测试，即分配一个 100 MB 数组：

```java
echo 'new byte[100_000_000]' | docker run -i --rm -m=1024M openjdk:9-jdk jshell -q
```

命令回应为`$1 ==> byte[100000000] { 0, 0, 0, ...`，所以这工作得很好！

现在，让我们进行一个真正有趣的测试：如果我们为 Docker 分配给容器的内存中分配一个 500 MB 的字节数组，会发生什么？

```java
echo 'new byte[500_000_000]' | docker run -i --rm -m=1024M openjdk:9-jdk jshell -q
```

从 Java 的角度来看，这应该可以工作。由于 Java 认为总内存为 16 GB，它已将最大堆大小设置为 4 GB，因此它开始为字节数组分配 500 MB。但是过了一会儿，JVM 的总大小超过 1 GB，Docker 将无情地杀死容器，导致诸如`State engine terminated`的混淆异常。我们基本上不知道出了什么问题，尽管我们可以猜测我们耗尽了内存。

所以，总结一下，如果你计划在 Docker 和 Java 上做任何严肃的工作，确保你使用 Java SE 10 或更高版本！

公平地说，应该提到 Java SE 9 包含对 cgroups 的一些初步支持。如果你指定了 Java 选项`-XX:+UnlockExperimentalVMOptions`和`-XX:+UseCGroupMemoryLimitForHeap`，它将尊重 cgroup 约束的一部分，但不是全部，并且应该注意的是这仅是实验性的。由于这一点，应该避免在生产环境中使用。简单地在 Docker 中使用 Java SE 10 或更高版本！

# 使用单个微服务的 Docker

既然我们理解了 Java 的工作原理，我们就可以开始使用 Docker 与我们其中一个微服务一起工作了。在我们能够将微服务作为 Docker 容器运行之前，我们需要将其打包到 Docker 镜像中。要构建 Docker 镜像，我们需要一个 Dockerfile，所以我们从那个开始。接下来，我们需要为我们的微服务创建一个 Docker 特定的配置。由于在容器中运行的微服务与其他微服务隔离，例如，它有自己的 IP 地址、主机名和端口，因此它需要与在同一主机上与其他微服务一起运行时的配置不同。例如，由于其他微服务不再在同一主机上运行，所以不会发生端口冲突。当在 Docker 中运行时，我们可以为所有微服务使用默认端口 `8080`，而无需担心端口冲突的风险。另一方面，如果我们需要与其他微服务通信，我们不能再像在同一主机上运行它们时那样使用 localhost。微服务的源代码不会受到将微服务以容器形式运行的影响，只有它们的配置会受到影响。

为了处理在没有 Docker 的情况下本地运行和作为 Docker 容器运行微服务时所需的不同配置，我们将使用 Spring 配置文件。自从第三章 *创建一组协作的微服务* 以来，我们就一直在使用默认的 Spring 配置文件来本地运行而不使用 Docker，因此我们将创建一个名为 `docker` 的 Spring 配置文件，用于在 Docker 中作为容器运行我们的微服务。

# 源代码中的更改

我们将使用 `product` 微服务，该微服务可以在源代码中的 `$BOOK_HOME/Chapter04/microservices/product-service/` 找到。在下一节中，我们将也将这个应用到其他微服务上。

首先，我们在属性文件 `$BOOK_HOME/Chapter04/microservices/product-service/src/main/resources/application.yml` 的末尾添加 Docker 的 Spring 配置文件：

```java
---
spring.profiles: docker

server.port: 8080
```

Spring 配置文件可以用来指定特定环境的配置，这里的情况是指当微服务在 Docker 容器中运行时才使用该配置。其他例子是那些特定于 `dev`、`test` 和生产环境的配置。配置文件中的值会覆盖默认值，即默认配置文件中的值。使用 `.yaml` 文件，可以在同一个文件中放置多个 Spring 配置文件，它们之间用 `---` 分隔。

我们唯一要更改的参数是正在使用的端口；也就是说，当微服务在容器中运行时，我们将使用默认端口 `8080`。

接下来，我们将创建一个 `Dockerfile`，用于构建 Docker 镜像，`$BOOK_HOME/Chapter04/microservices/product-service/Dockerfile`。它看起来像这样：

```java
FROM openjdk:12.0.2

EXPOSE 8080

ADD ./build/libs/*.jar app.jar

ENTRYPOINT ["java","-jar","/app.jar"]
```

需要注意的一些事情如下：

+   我们将基于 OpenJDK 的官方 Docker 镜像，并使用 Java SE v12.0.2。

+   我们将向其他 Docker 容器暴露端口 `8080`。

+   我们从 Gradle 构建库`build/libs`中添加我们的`fat-jar`文件到 Docker 镜像中：

+   我们将指定 Docker 在容器启动时使用的命令，即`java -jar /app.jar`。

在考虑源代码中的这些更改之后

# 构建 Docker 镜像

要构建 Docker 镜像，我们需要为`product-service`构建部署工件，即脂肪文件：

```java
cd $BOOK_HOME/Chapter04
./gradlew :microservices:product-service:build
```

由于我们只想构建`product-service`及其依赖项`api`和`util`，所以我们不使用正常的`build`命令（它会构建所有微服务），而是使用一个告诉 Gradle 只构建`product-service`的变体：`:microservices:product-service:build`。

我们可以在 Gradle 构建库`build/libs`中找到`fat-jar`文件。例如，`ls -l microservices/product-service/build/libs`命令将会报告如下内容：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/hsn-msvc-sprbt-sprcld/img/2af54aa7-9e16-41b1-964a-021bda81ebd5.png)

正如你所看到的，JAR 文件的大小接近 20 MB——难怪它们被称为`fat-jar`文件！

如果你好奇它的实际内容，可以使用`unzip -l microservices/product-service/build/libs/product-service-1.0.0-SNAPSHOT.jar`命令查看。

接下来，我们将构建 Docker 镜像并将其命名为`product-service`，如下所示：

```java
cd microservices/product-service
docker build -t product-service .
```

Docker 将使用当前目录中的 Dockerfile 来构建 Docker 镜像。该镜像将被命名为`product-service`并存储在 Docker 引擎内部。

验证我们是否获取了 Docker 镜像，使用以下命令：

```java
docker images | grep product-service
```

预期的输出如下：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/hsn-msvc-sprbt-sprcld/img/81cd92d2-7f8a-42a7-8e75-bfd20c69a1a6.png)

既然我们已经构建了镜像，那么让我们看看如何启动服务。

# 启动服务

使用以下命令以容器形式启动`product`微服务：

```java
docker run --rm -p8080:8080 -e "SPRING_PROFILES_ACTIVE=docker" product-service
```

这是我们从前面的代码可以推断出的事情：

1.  `docker run`：Docker 运行命令将启动容器并在终端中显示日志输出。只要容器运行，终端就会被锁定。

1.  我们已经看到了`--rm`选项；它将告诉 Docker 我们在使用*Ctrl + C*从终端停止执行时清理容器。

1.  `-p8080:8080`选项将容器中的端口`8080`映射到 Docker 主机的端口`8080`，这使得它可以从外部调用。在 macOS 上的 Docker 中，Docker 在本地 Linux 虚拟机中运行，端口也将被映射到 macOS 上，在本地主机上可用。我们只能在 Docker 主机上有一个特定端口的容器映射！

1.  使用`-e`选项，我们可以为容器指定环境变量，这个例子中是`SPRING_PROFILES_ACTIVE=docker`。`SPRING_PROFILES_ACTIVE`环境变量用于告诉 Spring 使用哪个配置文件。在我们的例子中，我们希望 Spring 使用`docker`配置文件。

1.  最后，我们有了`product-service`，这是 Docker 将用来启动容器的 Docker 镜像的名称。

预期的输出如下：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/hsn-msvc-sprbt-sprcld/img/6418f725-7182-4415-a87c-283962b36cad.png)

这是我们从上述输出中推断出的：

+   Spring 使用的配置文件是`docker`。在输出中查找`以下配置文件处于活动状态: docker`来验证这一点。

+   容器分配的端口是`8080`。在输出中查找`Netty started on port(s): 8080`来验证这一点。

+   当日志消息`Started ProductServiceApplication`被写入时，微服务就准备好接受请求了！

在另一个终端窗口尝试以下代码：

```java
curl localhost:8080/product/3
```

注意我们可以使用 localhost 上的端口`8080`，如前所述！

以下是预期输出：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/hsn-msvc-sprbt-sprcld/img/da91fca5-5223-4ded-b277-26ef0ea17866.png)

这与我们从上一章获得的输出类似，但有一个主要区别；我们有`"service Address":"aebb42b32fef/172.17.0.2:8080"`的内容，端口是`8080`，如预期那样，IP 地址`172.17.0.2`是一个从 Docker 内部网络分配给容器的 IP 地址——但是主机名`aebb42b32fef`是从哪里来的？

询问 Docker 所有正在运行的容器：

```java
docker ps
```

我们会看到类似以下内容：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/hsn-msvc-sprbt-sprcld/img/ab9eb9ee-8dc6-4e0c-bcd2-14269175f84c.png)

从上述输出中我们可以看到，主机名相当于容器的 ID，如果你想要了解哪个容器实际响应了你的请求，这一点是很有帮助的！

用*Ctrl + C*命令停止终端中的容器。完成这一步后，我们可以继续运行分离的容器。

# 分离运行容器

好的，这很好，但如果我们不想挂起我们从哪里开始容器的终端窗口怎么办？

是时候开始作为分离容器运行了，也就是说，运行容器而不锁定终端！

我们可以通过添加`-d`选项并同时使用`--name`选项为其命名来实现。由于我们将在使用完毕时明确停止和删除容器，所以不再需要`--rm`选项：

```java
docker run -d -p8080:8080 -e "SPRING_PROFILES_ACTIVE=docker" --name my-prd-srv product-service
```

如果我们再次运行`docker ps`命令，我们将看到我们新创建的容器，名为`my-prd-srv`：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/hsn-msvc-sprbt-sprcld/img/a683c0b3-0d98-4e01-afad-b521ee76cd42.png)

但是，我们如何获取容器的日志输出呢？

介绍 Docker 的`logs`命令：

```java
docker logs my-prd-srv -f
```

`-f`选项告诉命令跟随日志输出，即，当所有当前日志输出被写入终端时，不要结束命令，但也要等待更多输出。如果你预期有很多不想看到的旧日志消息，你还可以添加`--tail 0`选项，这样你只看到新的日志消息。或者，你可以使用`--since`选项，并使用绝对时间戳或相对时间，例如`--since 5m`，来看最多五分钟内的日志消息。

用一个新的`curl`请求尝试这个。你应该看到一个新的日志消息已经被写入终端的日志输出！

通过停止和删除容器来结束：

```java
docker rm -f my-prd-srv
```

`-f`选项强制 Docker 删除容器，即使它正在运行。Docker 会在删除之前自动停止容器。

现在我们已经知道如何使用 Docker 与微服务，我们可以进一步了解如何使用 Docker Compose 管理微服务架构，并查看其变化。

# 使用 Docker Compose 管理微服务架构

我们已经看到如何运行单个微服务作为 Docker 容器，但是管理整个系统架构的微服务呢？

如我们之前提到的，这就是`docker-compose`的目的。通过使用单一命令，我们可以构建、启动、记录和停止作为 Docker 容器运行的一组协作微服务！

# 源代码的变化

为了能够使用 Docker Compose，我们需要创建一个配置文件`docker-compose.yml`，描述 Docker Compose 将为我们管理的微服务。我们还需要为剩余的微服务设置 Dockerfile，并为每个微服务添加一个特定的 Spring 配置文件。

所有四个微服务都有自己的 Dockerfile，但它们都与前一个相同。您可以在以下位置找到它们：

+   `$BOOK_HOME/Chapter04/microservices/product-service/Dockerfile`

+   `$BOOK_HOME/Chapter04/microservices/recommendation-service/Dockerfile`

+   `$BOOK_HOME/Chapter04/microservices/review-service/Dockerfile`

+   `$BOOK_HOME/Chapter04/microservices/product-composite-service/Dockerfile`

当涉及到 Spring 配置文件时，三个核心服务`product`、`recommendation`和`review-service`具有相同的`docker`配置文件，它只指定当作为容器运行时应使用默认端口`8080`。

对于`product-composite-service`，事情变得有些复杂，因为它需要知道如何找到核心服务。当我们所有服务都运行在 localhost 上时，它被配置为使用 localhost 和每个核心服务的个别端口号`7001`-`7003`。当在 Docker 中运行时，每个服务将有自己的主机名，但可以在相同的端口号`8080`上访问。在此处，`product-composite-service`的`docker`配置文件如下所示：

```java
---
spring.profiles: docker

server.port: 8080

app:
  product-service:
    host: product
    port: 8080
  recommendation-service:
    host: recommendation
    port: 8080
  review-service:
    host: review
    port: 8080
```

详细信息请参阅`$BOOK_HOME/Chapter04/microservices/product-composite-service/src/main/resources/application.yml`。

主机名、产品、推荐和评论从何而来？

这些在`docker-compose.yml`文件中指定，该文件位于`$BOOK_HOME/Chapter04`文件夹中。它看起来像这样：

```java
version: '2.1'

services:
  product:
    build: microservices/product-service
    mem_limit: 350m
    environment:
      - SPRING_PROFILES_ACTIVE=docker

  recommendation:
    build: microservices/recommendation-service
    mem_limit: 350m
    environment:
      - SPRING_PROFILES_ACTIVE=docker

  review:
    build: microservices/review-service
    mem_limit: 350m
    environment:
      - SPRING_PROFILES_ACTIVE=docker

  product-composite:
    build: microservices/product-composite-service
    mem_limit: 350m
    ports:
      - "8080:8080"
    environment:
      - SPRING_PROFILES_ACTIVE=docker
```

对于每个微服务，我们指定如下内容：

+   微服务名称。这也将是内部 Docker 网络中容器的的主机名。

+   构建指令指定了查找用于构建 Docker 镜像的 Dockerfile 的位置。

+   内存限制为 350 MB。这确保了本章及接下来的章节中所有的容器都能 fits in the 6 GB of memory that we allocated to the Docker engine in the *Technical requirements* section。

+   为容器设置的环境变量。在我们的案例中，我们使用这些来指定要使用的 Spring 配置文件。

对于`product-composite`服务，我们还将指定端口映射，即，我们将将其端口暴露给 Docker 外部。其他微服务将无法从外部访问。接下来，我们将了解如何启动微服务架构。

# 启动微服务架构

有了所有必要的代码更改，我们可以构建 Docker 镜像，启动微服务架构，并运行一些测试来验证它是否按预期工作。为此，我们需要做以下工作：

1.  首先，我们使用 Gradle 构建我们的部署工件，然后使用 Docker Compose 构建 Docker 镜像：

```java
cd $BOOK_HOME/Chapter04
./gradlew build
docker-compose build
```

1.  然后，我们需要验证我们是否可以看到我们的 Docker 镜像，如下所示：

```java
docker images | grep chapter04
```

1.  我们应该看到以下输出：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/hsn-msvc-sprbt-sprcld/img/75213781-b3ea-4f66-84b9-62727717d4c5.png)

1.  使用以下命令启动微服务架构：

```java
docker-compose up -d
```

`-d`选项的意义与 Docker 之前描述的意义相同。

我们可以使用以下命令监控每个容器日志中写入的输出，以跟踪启动过程：

```java
docker-compose logs -f
```

`docker compose logs`命令支持与`docker logs`相同的`-f`和`--tail`选项，如前所述。

Docker Compose `logs`命令也支持将日志输出限制为一组容器。只需在`logs`命令之后添加您想要查看日志输出的容器的名称。例如，要只查看`product`和`review`服务的日志输出，请使用`docker-compose logs -f product review`。

当四个微服务都报告它们已经启动时，我们就可以尝试使用微服务架构了。寻找以下内容：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/hsn-msvc-sprbt-sprcld/img/760e3b57-8782-48c5-90ef-7ec483ef7f0e.png)

请注意，每个日志消息都以前缀的方式加上了产生输出的容器的名称！

现在，我们准备运行一些测试来验证这是否如预期工作。当我们从前一章直接在 localhost 上运行复合服务时，调用 Docker 中的复合服务所需做的唯一更改是端口号。现在我们使用端口`8080`：

```java
curl localhost:8080/product-composite/123 -s | jq .
```

我们将得到相同的响应：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/hsn-msvc-sprbt-sprcld/img/ea65b614-de1e-426a-83dc-b750d6cef6be.png)

然而，有一个很大的区别——`serviceAddresses`中报告的主机名和端口：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/hsn-msvc-sprbt-sprcld/img/60a1a060-0f7d-4bb9-9088-89a1c926ae2b.png)

在这里，我们可以看到分配给每个 Docker 容器的主机名和 IP 地址。

我们完成了；现在只剩下一步：

```java
docker-compose down 
```

前面命令将关闭微服务架构。

# 一起自动测试它们

当手动管理一组微服务时，Docker Compose 非常有帮助！在本节中，我们将更进一步地将 Docker Compose 集成到我们的测试脚本`test-em-all.bash`中。测试脚本将自动启动微服务景观，运行所有必要的测试以验证微服务景观按预期工作，并最终拆除它，不留下任何痕迹。

测试脚本可以在`$BOOK_HOME/Chapter04/test-em-all.bash`找到。

在测试脚本运行测试套件之前，它会检查测试脚本的调用中是否存在`start`参数。如果找到，它将使用以下代码重新启动容器：

```java
if [[ $@ == *"start"* ]]
then
    echo "Restarting the test environment..."
    echo "$ docker-compose down"
    docker-compose down
    echo "$ docker-compose up -d"
    docker-compose up -d
fi

```

之后，测试脚本将等待`product-composite`服务响应 OK：

```java
waitForService http://$HOST:${PORT}/product-composite/1
```

`waitForService`bash 函数可以如此实现：

```java
function testUrl() {
    url=$@
    if curl $url -ks -f -o /dev/null
    then
          echo "Ok"
          return 0
    else
          echo -n "not yet"
          return 1
    fi;
}

function waitForService() {
    url=$@
    echo -n "Wait for: $url... "
    n=0
    until testUrl $url
    do
        n=$((n + 1))
        if [[ $n == 100 ]]
        then
            echo " Give up"
            exit 1
        else
            sleep 6
            echo -n ", retry #$n "
        fi
    done
}
```

接下来，像之前一样执行所有测试。之后，如果发现测试脚本的调用中存在`stop`参数，它将拆除景观：

```java
if [[ $@ == *"stop"* ]]
then
    echo "We are done, stopping the test environment..."
    echo "$ docker-compose down"
    docker-compose down
fi
```

请注意，如果某些测试失败，测试脚本将不会拆除景观；它只会停止，留下景观用于错误分析！

测试脚本还将将默认端口从`7000`更改为`8080`，我们在没有 Docker 的情况下运行微服务时使用`7000`，而`8080`被我们的 Docker 容器使用。

让我们试试吧！要启动景观，运行测试并在之后拆除它，像这样：

```java
./test-em-all.bash start stop
```

以下是从一次测试运行中获取的一些示例输出（包括被删除的特定测试的输出）：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/hsn-msvc-sprbt-sprcld/img/16df5488-1e1d-45e3-850e-fad5f66cdbaf.png)

测试这些之后，我们可以继续了解如何解决失败的测试问题。

# 测试运行故障排除

如果运行`./test-em-all.bash start stop`的测试失败，按照这些步骤可以帮助您识别问题并修复问题后继续测试：

1.  首先，使用以下命令检查运行中的微服务的状态：

```java
docker-compose ps
```

1.  如果所有微服务都运行正常且健康，您将收到以下输出：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/hsn-msvc-sprbt-sprcld/img/8cdb0618-6760-4126-a3f5-abb60989b739.png)

1.  如果有任何微服务的状态不是`Up`，使用`docker-compose logs`命令检查其日志输出是否有任何错误。例如，如果您想检查`product`服务的日志输出，可以使用以下代码：

```java
docker-compose logs product
```

1.  如果错误日志输出显示 Docker 磁盘空间不足，可以使用以下命令回收部分空间：

```java
docker system prune -f --volumes
```

1.  如有需要，您可以使用`docker-compose up -d --scale`命令重新启动失败的微服务。例如，如果您想重新启动`product`服务，可以使用以下代码：

```java
docker-compose up -d --scale product=0
docker-compose up -d --scale product=1
```

1.  如果一个微服务丢失，例如，由于崩溃，您可以使用`docker-compose up -d --scale`命令启动它。例如，您会使用以下代码为`product`服务：

```java
docker-compose up -d --scale product=1
```

1.  一旦所有微服务都运行并保持健康状态，再次运行测试脚本，但这次不启动微服务：

```java
./test-em-all.bash
```

测试应该运行得很好！

最后，关于一个组合命令的提示，该命令从源代码构建运行时工件和 Docker 镜像，然后在每个 Docker 容器中运行所有测试：

`./gradlew clean build && docker-compose build && ./test-em-all.bash start stop`

如果你想在将新代码推送到你的 Git 仓库之前或作为你构建服务器中构建管道的部分来检查一切是否正常，这太完美了！

# 总结

在本章中，我们看到了 Docker 如何被用来简化对一组协同工作的微服务的测试。

我们了解到，从 Java SE v10 开始，它尊重我们对容器施加的约束，关于容器可以使用多少 CPU 和内存。

我们也看到了，要让一个基于 Java 的微服务作为 Docker 容器运行，需要多么小的改动。多亏了 Spring 配置文件，我们可以在不进行任何代码更改的情况下在 Docker 中运行微服务。

最后，我们看到了 Docker Compose 如何帮助我们用单一命令管理一组协同工作的微服务，无论是手动还是更好的自动方式，当与像`test-em-all.bash`这样的测试脚本集成时。

在下一章中，我们将学习如何使用 OpenAPI/Swagger 描述来添加 API 文档。

# 问题

1.  虚拟机和 Docker 容器之间有哪些主要区别？

1.  命名空间和 Docker 中的 cgroups 有什么作用？

1.  一个 Java 应用程序如果不尊重容器中的最大内存设置并且分配了比允许更多的内存，会发生什么？

1.  我们如何让一个基于 Spring 的应用程序在不修改其源代码的情况下作为 Docker 容器运行？

1.  为什么下面的 Docker Compose 代码段不会工作？

```java
  review:
    build: microservices/review-service
    ports:
      - "8080:8080"
    environment:
      - SPRING_PROFILES_ACTIVE=docker

  product-composite:
    build: microservices/product-composite-service
    ports:
      - "8080:8080"
    environment:
      - SPRING_PROFILES_ACTIVE=docker
```


# 第五章：使用 OpenAPI/Swagger 添加 API 描述

一个 API（如 RESTful 服务）的价值在很大程度上取决于它是多么容易消费！良好且易于访问的文档是 API 是否有用的一个重要因素。在本章中，我们将学习如何使用 OpenAPI/Swagger 来文档化我们可以从微服务架构中外部访问的 API。

正如我们在第二章，《Spring Boot 简介》中提到的，Swagger 是文档 RESTful 服务时最常用的规范之一，许多领先的 API 网关都有对 Swagger 的本地支持。我们将学习如何使用 SpringFox 生成此类文档，以及使用 SpringFox 文档永恒 API 所需的源代码更改。我们将尝试使用内嵌的 Swagger 查看器来查看文档和测试 API。

到本章结束时，我们将拥有一个基于 Swagger 的外部 API 文档，该 API 是由`product-composite-service`微服务暴露的。我们将能够使用内嵌的 Swagger 查看器来可视化和测试 API。

本章将涵盖以下主题：

+   使用 SpringFox 简介

+   源代码的更改

+   构建和启动微服务

+   尝试 Swagger 文档

# 技术要求

本书中描述的所有命令都是在使用 macOS Mojave 的 MacBook Pro 上运行的，但如果您想在其他平台（如 Linux 或 Windows）上运行它们，应该很容易进行修改。

在你通过本章的学习之前，不需要安装任何新工具。

本章的源代码可以在本书的 GitHub 仓库中找到：[`github.com/PacktPublishing/Hands-On-Microservices-with-Spring-Boot-and-Spring-Cloud/tree/master/Chapter05`](https://github.com/PacktPublishing/Hands-On-Microservices-with-Spring-Boot-and-Spring-Cloud/tree/master/Chapter05)。

为了能够运行本书中描述的命令，请将源代码下载到文件夹中，并设置一个环境变量`$BOOK_HOME`，使其指向该文件夹。一些示例命令如下：

```java
export BOOK_HOME=~/Documents/Hands-On-Microservices-with-Spring-Boot-and-Spring-Cloud
git clone https://github.com/PacktPublishing/Hands-On-Microservices-with-Spring-Boot-and-Spring-Cloud $BOOK_HOME
cd $BOOK_HOME/Chapter05
```

本章中提到的 Java 源代码是为 Java 8 编写的，并在 Java 12 上进行了测试。本章使用了 Spring Boot 2.1.0（以及 Spring 5.1.2），这是在撰写本章时可用的最新 Spring Boot 版本。

本章中的代码示例都来自`$BOOK_HOME/Chapter05`的源代码，但在许多情况下，已经编辑了这些示例，以删除源代码中的无关部分，例如注释、导入和日志语句。

如果你想要查看本章应用于源代码的变化，即查看使用 SpringFox 创建基于 Swagger 的 API 文档所采取的措施，你可以与第四章，*使用 Docker 部署我们的微服务*的源代码进行比较。你可以使用你喜欢的`diff`工具，比较两个文件夹，即`$BOOK_HOME/Chapter04`和`$BOOK_HOME/Chapter05`。

# 使用 SpringFox 的介绍

SpringFox 使得可以将与实现 API 的源代码一起保持 API 文档。对我来说，这是一个重要的特性。如果 API 文档与 Java 源代码在不同的生命周期中维护，它们将随着时间的推移而相互偏离。根据我的经验，在很多情况下，这种情况比预期的要早。像往常一样，将组件的接口与实现分离是很重要的。在记录 RESTful API 方面，我们应该将 API 文档添加到描述 API 的 Java 接口中，而不是添加到实现 API 的 Java 类中。为了简化 API 文档的更新，我们可以将文档的部分内容放在属性文件中，而不是直接放在 Java 代码中。

2015 年，SmartBear Software 将 Swagger 规范捐赠给 Linux Foundation 的 OpenAPI Initiative，并创建了 OpenAPI 规范。为了创建 API 文档，我们将使用**SpringFox**，它可以在运行时创建基于 Swagger 的 API 文档。

它基于我们提供的配置以及通过检查由 Spring WebFlux 和 Swagger 提供的注释来实现：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/hsn-msvc-sprbt-sprcld/img/4b24888c-15c8-42ed-8f85-99bff144857c.png)

计划支持 OpenAPI 的 SpringFox 版本为 v3。在撰写本章时，SpringFox V3 仍在开发中，因此我们将使用 SpringFox V3 的快照版本，并根据 Swagger V2 创建 API 文档。一旦 SpringFox V3 发布，本书的源代码将会更新。

为了启用 SpringFox 以便我们可以创建 API 文档，我们将为 SpringFox 设置一个基本配置，并向定义 RESTful 服务的 Java 接口添加注解。

如果文档的某些部分被放置在属性文件中以简化 API 文档的更新，那么这些属性文件必须与源代码在相同的生命周期和版本控制下处理，否则它们可能会开始与实现偏离，也就是说，变得过时。

# 源代码的变化

为了添加`product-composite-service`微服务暴露的外部 API 的基于 Swagger 的文档，我们需要改变两个模块的源代码：

+   `product-composite-services`：在这里，我们将在 Java 应用程序类`ProductCompositeServiceApplication`中设置 SpringFox 配置，并描述 API 的一般信息。

+   `api`：在这里，我们将向 Java 接口`ProductCompositeService`添加 Swagger 注解，描述每个 RESTful 服务。在这个阶段，我们只有一个 RESTful 服务，即`/product-composite/{productId}`，用于请求关于特定产品的复合信息。

实际用于描述 API 操作的文本将被放置在默认的属性文件`application.yml`中。

在我们可以使用 SpringFox 之前，我们需要将其作为依赖项添加到 Gradle 构建文件中。所以，让我们从这一点开始！

# 向 Gradle 构建文件添加依赖项

如我们之前提到的，我们将使用 SpringFox V3 的快照版本。SpringFox 产品分为多个模块。我们需要指定依赖关系的模块如下：

+   `springfox-swagger2`，这样我们就可以创建基于 Swagger 2 的文档

+   `springfox-spring-webflux`，这样我们就可以支持基于 Spring WebFlux 的 RESTful 操作

+   `springfox-swagger-ui`，这样我们可以在微服务中嵌入 Swagger 查看器

我们可以将这些添加到`product-composite-service`模块的 Gradle 构建文件`build.gradle`中，如下所示：

```java
implementation('io.springfox:springfox-swagger2:3.0.0-SNAPSHOT')
implementation('io.springfox:springfox-swagger-ui:3.0.0-SNAPSHOT')
implementation('io.springfox:springfox-spring-webflux:3.0.0-SNAPSHOT')
```

`api`项目只需要`springfox-swagger2`模块的一个依赖项，因此只需要在其`build.gradle`文件中添加以下依赖项：

```java
implementation('io.springfox:springfox-swagger2:3.0.0-SNAPSHOT')
```

SpringFox 项目在 Maven 仓库发布快照构建（[`oss.jfrog.org/artifactory/oss-snapshot-local/`](http://oss.jfrog.org/artifactory/oss-snapshot-local/)），所以我们还需要添加这个：

```java
repositories {
   mavenCentral()
   maven { url 'http://oss.jfrog.org/artifactory/oss-snapshot-local/' }
}
```

为了能够构建核心模块，即`product-service`、`recommendation-service`和`review-service`，我们需要将 Maven 仓库添加到它们的 Gradle 构建文件`build.gradle`中。

# 向产品组合服务应用程序添加配置和一般 API 文档

为了在`product-composite-service`微服务中启用 SpringFox，我们必须添加一个配置。为了保持源代码紧凑，我们将直接将其添加到`ProductCompositeServiceApplication`应用程序类中。

如果你喜欢，你可以将 SpringFox 的配置放在一个单独的 Spring 配置类中。

首先，我们需要添加`@EnableSwagger2WebFlux`注解，以便让 SpringFox 为我们的使用 Spring WebFlux 实现的 RESTful 服务生成 Swagger V2 文档。然后，我们需要定义一个返回 SpringFox `Docket`bean 的 Spring Bean，用于配置 SpringFox。

我们将要添加到`$BOOK_HOME/Chapter05/microservices/product-composite-service/src/main/java/se/magnus/microservices/composite/product/ProductCompositeServiceApplication.java`的源代码如下所示：

```java
@EnableSwagger2WebFlux
public class ProductCompositeServiceApplication {

   @Bean
   public Docket apiDocumentation() {
      return new Docket(SWAGGER_2)
         .select()
         .apis(basePackage("se.magnus.microservices.composite.product"))
         .paths(PathSelectors.any())
         .build()
            .globalResponseMessage(GET, emptyList())
            .apiInfo(new ApiInfo(
                   apiTitle,
                   apiDescription,
                   apiVersion,
                   apiTermsOfServiceUrl,
                   new Contact(apiContactName, apiContactUrl, 
                    apiContactEmail),
                   apiLicense,
                   apiLicenseUrl,
                   emptyList()
                                  ));
    }
```

从前面的代码，我们可以理解如下：

+   `@EnableSwagger2WebFlux`注解是启动 SpringFox 的起点。

+   `Docket`bean 被初始化以创建 Swagger V2 文档。

+   使用 `apis()` 和 `paths()` 方法，我们可以指定 SpringFox 应在哪里查找 API 文档。

+   使用 `globalResponseMessage()` 方法，我们要求 SpringFox 不要向 API 文档中添加任何默认 HTTP 响应代码，如 `401` 和 `403`，这些我们目前不使用。

+   用于配置 `Docket` bean 的一般 API 信息的 `api*` 变量是从属性文件中使用 Spring `@Value` 注解初始化的。这些如下：

```java
    @Value("${api.common.version}")           String apiVersion;
    @Value("${api.common.title}")             String apiTitle;
    @Value("${api.common.description}")       String apiDescription;
    @Value("${api.common.termsOfServiceUrl}") String 
                                              apiTermsOfServiceUrl;
    @Value("${api.common.license}")           String apiLicense;
    @Value("${api.common.licenseUrl}")        String apiLicenseUrl;
    @Value("${api.common.contact.name}")      String apiContactName;
    @Value("${api.common.contact.url}")       String apiContactUrl;
    @Value("${api.common.contact.email}")     String apiContactEmail;
```

添加配置和 API 文档后，我们可以继续了解如何向 ProductCompositeService 添加 API 特定的文档。

# 向 ProductCompositeService 添加 API 特定的文档

为了文档化实际的 API `ProductCompositeService` 及其 RESTful 操作，我们将向 Java 接口声明中添加 `@Api` 注解，以便我们可以提供 API 的通用描述。对于 API 中的每个 RESTful 操作，我们将添加一个 `@ApiOperation` 注解，并在相应的 Java 方法上添加 `@ApiResponse` 注解，以描述操作及其预期的错误响应。

SpringFox 将检查 `@GetMapping` Spring 注解，以了解操作接受什么输入参数，如果产生成功响应，响应将是什么样子。

在以下示例中，我们从 `@ApiOperation` 注解中提取了实际文本到一个属性文件中。注解包含属性占位符，SpringFox 将使用它们在运行时从属性文件中查找实际文本。

资源级别的 API 文档如下所示：

```java
@Api(description = "REST API for composite product information.")
public interface ProductCompositeService {
```

单个 API 操作如下所示：

```java
    @ApiOperation(
        value = "${api.product-composite.get-composite-
         product.description}",
        notes = "${api.product-composite.get-composite-product.notes}")
    @ApiResponses(value = {
        @ApiResponse(code = 400, message = "Bad Request, invalid format 
        of the request. See response message for more information."),
        @ApiResponse(code = 404, message = "Not found, the specified id 
         does not exist."),
        @ApiResponse(code = 422, message = "Unprocessable entity, input 
         parameters caused the processing to fails. See response 
         message for more information.")
    })
    @GetMapping(
        value    = "/product-composite/{productId}",
        produces = "application/json")
    ProductAggregate getProduct(@PathVariable int productId);
```

对于 `@ApiOperation` Swagger 注解中指定的值，我们可以直接使用属性占位符，而不用 Spring `@Value` 注解。对于预期 `ApiResponses` 的描述，即预期的错误代码，SpringFox 目前不支持使用属性占位符，因此在这种情况下，每个错误代码的实际文本直接放在 Java 源代码中。

详细信息，请参阅 `$BOOK_HOME/Chapter05/api/src/main/java/se/magnus/api/composite/product/ProductCompositeService.java`。

# 将 API 的文本描述添加到属性文件

最后，我们需要将 API 的文本描述添加到属性文件 `application.yml` 中。在此处，我们有如下 `@Value` 注解：

```java
@Value("${api.common.version}") String apiVersion;
```

对于每个 `@Value` 注解，我们需要在 YAML 文件中指定一个相应的属性；例如：

```java
api:
  common:
    version: 1.0.0
```

同样，我们有 Swagger 注解，其外观如下：

```java
@ApiOperation(value = "${api.product-composite.get-composite-product.description}")
```

这些期待 YAML 文件中有相应的属性；例如：

```java
api:
  product-composite:
    get-composite-product:
      description: Returns a composite view of the specified product id
```

如果您想了解更多关于如何构建 YAML 文件的信息，请查看规范：[`yaml.org/spec/1.2/spec.html`](https://yaml.org/spec/1.2/spec.html)。

首先，API 的通用描述，它是在 SpringFox `Docket` bean 中配置的，如下所示：

```java
api:
  common:
    version: 1.0.0
    title: Sample API
    description: Description of the API...
    termsOfServiceUrl: MINE TERMS OF SERVICE URL
    license: License
    licenseUrl: MY LICENSE URL
    contact:
      name: Contact
      url: My
      email: me@mail.com
```

接下来，给出了实际 API 操作的详细描述：

```java
product-composite:
  get-composite-product:
    description: Returns a composite view of the specified product id
    notes: |
      # Normal response
      If the requested product id is found the method will return 
      information regarding:
      1\. Base product information
      1\. Reviews
      1\. Recommendations
      1\. Service Addresses\n(technical information regarding the 
      addresses of the microservices that created the response)

      # Expected partial and error responses
      In the following cases, only a partial response be created (used 
      to simplify testing of error conditions)

      ## Product id 113
      200 - Ok, but no recommendations will be returned

      ## Product id 213
      200 - Ok, but no reviews will be returned

      ## Non numerical product id
      400 - A <b>Bad Request</b> error will be returned

      ## Product id 13
      404 - A <b>Not Found</b> error will be returned

      ## Negative product ids
      422 - An <b>Unprocessable Entity</b> error will be returned
```

请注意，SpringFox 支持使用 markdown 语法提供 API 操作的多行描述。

有关详细信息，请参阅`$BOOK_HOME/Chapter05/microservices/product-composite-service/src/main/resources/application.yml`。

# 构建和启动微服务架构

在我们尝试 Swagger 文档之前，我们需要构建和启动微服务架构！

这可以通过以下命令完成：

```java
cd $BOOK_HOME/Chapter05
./gradlew build && docker-compose build && docker-compose up -d
```

你可能会遇到一个关于端口`8080`已经被分配的错误信息。这将会是这样的：

```java
ERROR: for product-composite Cannot start service product-composite: driver failed programming external connectivity on endpoint chapter05_product-composite_1 (0138d46f2a3055ed1b90b3b3daca92330919a1e7fec20351728633222db5e737): Bind for 0.0.0.0:8080 failed: port is already allocated
```

如果是这种情况，你可能忘记从上一章关闭微服务架构。要找出正在运行的容器的名称，请运行以下命令：

```java
 docker ps --format {{.Names}}
```

当上一章的微服务架构仍在运行时，示例响应如下：

```java
chapter05_review_1
chapter05_product_1
chapter05_recommendation_1
chapter04_review_1
chapter04_product-composite_1
chapter04_product_1
chapter04_recommendation_1
```

如果在命令的输出中找到了其他章节的容器，例如，来自第四章，*使用 Docker 部署我们的微服务*，如前一个示例所示，你需要跳到那一章并关闭那个章节的容器：

```java
cd ../Chapter04
docker-compose down
```

现在，你可以启动本章缺失的容器了：

```java
cd ../Chapter05
docker-compose up -d
```

请注意，由于其他容器已经成功启动，该命令只启动了缺失的容器`product-composite`：

```java
Starting chapter05_product-composite_1 ... done
```

为了等待微服务架构启动并验证它是否正常工作，你可以运行以下命令：

```java
./test-em-all.bash 
```

这个微服务的成功启动有助于我们更好地理解其架构，也有助于理解我们将在下一节学习的 Swagger 文档。

# 尝试 Swagger 文档

为了浏览 Swagger 文档，我们将使用内嵌的 Swagger 查看器。如果我们打开`http://localhost:8080/swagger-ui.html` URL 在网页浏览器中，我们将看到一个类似于以下屏幕截图的网页：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/hsn-msvc-sprbt-sprcld/img/eb92fdb1-5db9-4a87-92d4-7c71147b6608.png)

这里，我们可以找到以下内容：

+   我们在 SpringFox `Docket` bean 中指定的通用信息，以及实际 Swagger 文档的链接，`http://localhost:8080/v2/api-docs`

+   API 资源的列表；在我们这个案例中，是`product-composite-service` API

+   页面底部有一个部分，我们可以查看 API 中使用的模型

它的工作原理如下：

1.  点击`product-composite-service` API 资源来展开它。你会得到一个资源上可用的操作列表。

1.  你只能看到一个操作，`/product-composite/{productId}`。点击它来展开它。你会看到我们在`ProductCompositeService` Java 接口中指定的操作的文档：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/hsn-msvc-sprbt-sprcld/img/8cfce8b6-7453-449a-a9ef-2e09eaa283fa.png)

这里，我们可以看到以下内容：

+   操作的一行描述。

+   一个包含操作详细信息的章节，包括它支持的输入参数。请注意`@ApiOperation`注解中的`notes`字段是如何漂亮地渲染出来的 markdown 语法！

如果你滚动网页向下，你还会找到有关预期响应的文档，包括正常的 200 响应和我们定义的各种 4xx 错误响应，如下面的截图所示：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/hsn-msvc-sprbt-sprcld/img/552a2eb1-0907-4982-9bea-1c27987a129f.png)

如果我们滚动回参数描述，我们会找到“尝试一下！”按钮。如果我们点击该按钮，我们可以输入实际的参数值，并通过点击“执行”按钮向 API 发送请求。例如，如果我们输入 `productId 123`，我们将得到以下响应：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/hsn-msvc-sprbt-sprcld/img/25e34f7c-852a-407f-a9ad-c7963c7808bb.png)

我们将得到一个预期的 200（OK）作为响应代码，以及一个我们已熟悉的 JSON 结构作为响应体！

如果我们输入一个错误的输入，比如 `-1`，我们将得到一个正确的错误代码作为响应代码，以及一个相应的基于 JSON 的错误描述作为响应体：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/hsn-msvc-sprbt-sprcld/img/3361c3ba-305c-4950-8454-afea6db7d2e4.png)

如果你想尝试调用 API 而不用 Swagger UI，你可以从响应部分复制相应的 `curl` 命令，并在终端窗口中运行它！以下是一个例子：

```java
curl -X GET "http://localhost:8080/product-composite/123" -H "accept: application/json"
```

很棒，不是吗？

# 摘要

API 的良好文档化对其接受度至关重要，而 Swagger 是最常用于文档化 RESTful 服务的规范之一。SpringFox 是一个开源项目，它使得通过检查 Spring WebFlux 和 Swagger 注解，在运行时动态创建基于 Swagger 的 API 文档变得可能。API 的文本描述可以从 Java 源代码中的注解中提取，并放置在属性文件中以便于编辑。SpringFox 可以配置为将内嵌的 Swagger 查看器带入微服务，这使得阅读微服务公开的 API 以及从查看器中尝试它们变得非常容易。

现在，那么通过向我们的微服务中添加持久性（即保存数据库中数据的能力）来为我们的微服务带来一些生机呢？为此，我们需要添加一些更多 API，这样我们才能创建和删除微服务处理的信息。翻到下一章了解更多信息！

# 问题

1.  SpringFox 是如何帮助我们为 RESTful 服务创建 API 文档的？

1.  SpringFox 支持哪些 API 文档化规范？

1.  SpringFox 中的 `Docket` bean 的目的是什么？

1.  说出一些 SpringFox 在运行时读取的注解，以创建 API 文档！

1.  `: |` 在 YAML 文件中是什么意思？

1.  如何在不使用嵌入式 Swagger 查看器的情况下重复对 API 的调用？


# 第六章：添加持久化

在本章中，我们将学习如何将微服务正在使用数据进行持久化。正如在第二章《Spring Boot 简介》中提到的，我们将使用 Spring Data 项目将数据持久化到 MongoDB 和 MySQL 数据库中。`project`和`recommendation`微服务将使用 Spring Data 进行 MongoDB 操作，而`review`微服务将使用 Spring Data 的**JPA**（Java Persistence API 的缩写）访问 MySQL 数据库。我们将向 RESTful API 添加操作，以能够创建和删除数据库中的数据。现有的用于读取数据的 API 将更新以访问数据库。我们将以 Docker 容器的形式运行数据库，由 Docker Compose 管理，也就是我们运行微服务的方式。

本章将涵盖以下主题：

+   向核心微服务添加持久化层

+   编写专注于持久化的自动化测试

+   在服务层中使用持久化层

+   扩展组合服务 API

+   向 Docker Compose 环境中添加数据库

+   手动测试新 API 和持久化层

+   更新微服务环境中的自动化测试

# 技术要求

本书中描述的所有命令都是在 MacBook Pro 上使用 macOS Mojave 运行的，但应该很容易修改以在另一个平台，如 Linux 或 Windows 上运行。

在本章中不需要安装任何新工具。

为了能够手动访问数据库，我们将使用用于运行数据库的 Docker 镜像中提供的 CLI 工具。不过，我们将在 Docker Compose 中暴露每个数据库所使用的标准端口——MySQL 的`3306`和 MongoDB 的`27017`。这将允许你使用你最喜欢的数据库工具以与它们在本机运行相同的方式访问数据库。

本章的源代码可以在 GitHub 上找到：[`github.com/PacktPublishing/Hands-On-Microservices-with-Spring-Boot-and-Spring-Cloud/tree/master/Chapter06`](https://github.com/PacktPublishing/Hands-On-Microservices-with-Spring-Boot-and-Spring-Cloud/tree/master/Chapter06)。

为了能够按照书中描述运行命令，请将源代码下载到一个文件夹中，并设置一个环境变量`$BOOK_HOME`，使其指向该文件夹。以下是一些示例命令：

```java
export BOOK_HOME=~/Documents/Hands-On-Microservices-with-Spring-Boot-and-Spring-Cloud
git clone https://github.com/PacktPublishing/Hands-On-Microservices-with-Spring-Boot-and-Spring-Cloud $BOOK_HOME
cd $BOOK_HOME/Chapter06
```

本章所用的 Java 源代码是为 Java 8 编写的，并在 Java 12 上进行了测试。本章使用的是 Spring Boot 2.1.0（以及 Spring 5.1.2）——这是在撰写本章时 Spring Boot 可用的最新版本。

源代码包含以下 Gradle 项目：

+   `api`

+   `util`

+   `microservices/product-service`

+   `microservices/review-service`

+   `microservices/recommendation-service`

+   `microservices/product-composite-service`

本章中的所有代码示例都来自`$BOOK_HOME/Chapter06`的源代码，但在许多情况下，为了删除源代码中不相关部分，例如注释和导入以及日志语句，都进行了编辑。

如果你想要查看在第六章，*添加持久化*中应用到源代码的变化，可以看到添加了持久化到微服务中使用 Spring Data 所需要的一切，你可以与第五章，*使用 OpenAPI/Swagger 添加 API 描述*的源代码进行比较。你可以使用你喜欢的 diff 工具，比较两个文件夹，`$BOOK_HOME/Chapter05`和`$BOOK_HOME/Chapter06`。

# 但首先，让我们看看我们的目标在哪里

到本章结束时，我们的微服务内部将会有如下的层次结构：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/hsn-msvc-sprbt-sprcld/img/148fd8fc-30e4-4039-986a-554a4237bb7c.png)

**协议层**非常薄，仅包含`RestController`注解和公共`GlobalControllerExceptionHandler`。每个微服务的主要功能都存在于服务层中。`product-composite`服务包含一个集成层，用于与三个核心微服务进行通信。核心微服务都将有一个用于与它们数据库通信的**持久化层**。

我们可以使用如下命令查看存储在 MongoDB 中的数据：

```java
docker-compose exec mongodb mongo product-db --quiet --eval "db.products.find()"
```

命令的结果应该像以下这样：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/hsn-msvc-sprbt-sprcld/img/396be685-3e82-4fc9-b871-3b6e72c7f6d8.png)

关于存储在 MySQL 中的数据，我们可以使用如下命令查看：

```java
docker-compose exec mysql mysql -uuser -p review-db -e "select * from reviews"
```

命令的结果应该如下所示：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/hsn-msvc-sprbt-sprcld/img/05445cec-486e-426e-8b16-b611e61649e5.png)

**注意：** `mongo`和`mysql`命令的输出已经被缩短以提高可读性。

让我们看看如何进行操作。

# 为核心微服务添加持久化层

让我们先为核心微服务添加一个持久化层。除了使用 Spring Data，我们还将使用一个 Java bean 映射工具 MapStruct，它使得在 Spring Data 实体对象和 API 模型类之间转换变得容易。有关详细信息，请参阅[`mapstruct.org/`](http://mapstruct.org/)。

首先，我们需要添加对 MapStruct、Spring Data 以及我们打算使用的数据库的 JDBC 驱动的依赖。之后，我们可以定义我们的 Spring Data 实体类和仓库。Spring Data 实体类和仓库将被放置在它们自己的 Java 包中，`persistence`。例如，对于产品微服务，它们将被放置在 Java 包`se.magnus.microservices.core.product.persistence`中。

# 添加依赖

我们将使用 MapStruct V1.3.0-Beta 2，所以我们首先在每一个核心微服务的构建文件中定义一个变量，以保存版本信息，`build.gradle`：

```java
ext {
 mapstructVersion = "1.3.0.Beta2"
}
```

接下来，我们声明对 MapStruct 的依赖：

```java
implementation("org.mapstruct:mapstruct:${mapstructVersion}")
```

由于 MapStruct 在编译时通过处理 MapStruct 注解来生成 bean 映射的实现，我们需要添加一个`annotationProcessor`和一个`testAnnotationProcessor`依赖：

```java
iannotationProcessor "org.mapstruct:mapstruct-processor:${mapstructVersion}"
testAnnotationProcessor "org.mapstruct:mapstruct-processor:${mapstructVersion}"
```

为了使在流行的 IDE 如 IntelliJ IDEA 中的编译时生成工作，我们还需要添加以下依赖：

```java
compileOnly "org.mapstruct:mapstruct-processor:${mapstructVersion}"
```

如果你使用的是 IntelliJ IDEA，你还需要确保启用了注解处理支持。打开首选项，导航到构建、执行、部署 | 编译器 | 注解处理器。验证名为“启用注解处理”的复选框是否被选中！

对于`project`和`recommendation`微服务，我们在 Spring Data for MongoDB 中声明了以下依赖：

```java
implementation('org.springframework.boot:spring-boot-starter-data-mongodb')
testImplementation('de.flapdoodle.embed:de.flapdoodle.embed.mongo')
```

对`de.flapdoodle.embed.mongo`的测试依赖使我们能够在运行 JUnit 基础测试时运行 MongoDB 嵌入式。

`review`微服务将使用 Spring Data for JPA，并搭配 MySQL 作为其数据库在运行时使用，在测试时会使用嵌入式数据库 H2。因此，在它的构建文件`build.gradle`中声明了以下依赖：

```java
implementation('org.springframework.boot:spring-boot-starter-data-jpa')
implementation('mysql:mysql-connector-java')
testImplementation('com.h2database:h2')
```

# 使用实体类存储数据

实体类在包含字段方面与相应的 API 模型类相似——查看`api`项目中的 Java 包`se.magnus.api.core`。我们将在与 API 模型类字段相比在实体类中添加两个字段`id`和`version`。

`id`字段用于持有每个存储实体的数据库身份——在使用关系数据库时是主键。我们将负责生成身份字段唯一值的职责委托给 Spring Data。根据所使用的数据库，Spring Data 可以将这个职责委托给数据库引擎。无论哪种情况，应用程序代码都不需要考虑如何设置数据库`id`的唯一值。`id`字段在 API 中不暴露，这是从安全角度出发的最佳实践。模型类中的字段，用于标识实体，将在相应的实体类中分配一个唯一索引，以确保从业务角度保持数据库的一致性。

`version`字段用于实现乐观锁，即允许 Spring Data 验证数据库中实体的更新是否覆盖了并发更新。如果存储在数据库中的版本字段值高于更新请求中的版本字段值，这表明更新是基于过时数据进行的——即自从从数据库中读取数据以来，要更新的信息已被其他人更新。Spring Data 将防止基于过时数据执行更新。在编写持久性测试的部分，我们将看到测试验证 Spring Data 中的乐观锁机制防止对过时数据执行更新。由于我们只实现创建、读取和删除操作的 API，因此我们不会在 API 中暴露版本字段。

产品实体类最有趣的部分看起来像这样：

```java
@Document(collection="products")
public class ProductEntity {

 @Id
 private String id;

 @Version
 private Integer version;

 @Indexed(unique = true)
 private int productId;

 private String name;
 private int weight;
```

以下是从前面代码得出的观察结果：

+   `@Document(collection="products")`注解用于标记用作 MongoDB 实体的类，即映射到名为`products`的 MongoDB 集合。

+   `@Id` 和 `@Version` 注解用于标记由 Spring Data 使用的 `id` 和 `version` 字段，如前所述。

+   `@Indexed(unique = true)` 注解用于为业务键 `productId` 创建一个唯一的索引。

`Recommendation` 实体类最有趣的部分看起来是这样的：

```java
@Document(collection="recommendations")
@CompoundIndex(name = "prod-rec-id", unique = true, def = "{'productId': 1, 'recommendationId' : 1}")
public class RecommendationEntity {

    @Id
    private String id;

    @Version
    private Integer version;

    private int productId;
    private int recommendationId;
    private String author;
    private int rating;
    private String content;
```

在前面产品实体的解释基础上，我们可以看到如何使用 `@CompoundIndex` 注解为基于字段 `productId` 和 `recommendationId` 的复合业务键创建唯一的复合索引。

最后，`Review` 实体类最有趣的部分看起来是这样的：

```java
@Entity
@Table(name = "reviews", indexes = { @Index(name = "reviews_unique_idx", unique = true, columnList = "productId,reviewId") })
public class ReviewEntity {

    @Id @GeneratedValue
    private int id;

    @Version
    private int version;

    private int productId;
    private int reviewId;
    private String author;
    private String subject;
    private String content;
```

以下是对前面代码的观察：

+   `@Entity` 和 `@Table` 注解用于标记一个类作为一个用于 JPA 的实体类——映射到 SQL 数据库中的一个名为 `products` 的表。

+   `@Table` 注解也用于指定基于字段 `productId` 和 `reviewId` 的复合业务键应创建一个唯一的复合索引。

+   `@Id` 和 `@Version` 注解用于标记 `id` 和 `version` 字段，如前所述，由 Spring Data 使用。为了指导 Spring Data for JPA 自动为 `id` 字段生成唯一的 `id` 值，我们使用了 `@GeneratedValue` 注解。

实体类的完整源代码可以在以下链接中找到：

+   `se.magnus.microservices.core.product.persistence.ProductEntity` 在 `product` 项目中

+   `se.magnus.microservices.core.recommendation.persistence.RecommendationEntity` 在 `recommendation` 项目中

+   `se.magnus.microservices.core.review.persistence.ReviewEntity` 在 `review` 项目中

# 在 Spring Data 中定义仓库

Spring Data 带有一组用于定义仓库的基础类。我们将使用基础类 `CrudRepository` 和 `PagingAndSortingRepository`。`CrudRepository` 基础类提供了执行基本的数据库创建、读取、更新和删除操作的标准方法。`PagingAndSortingRepository` 基础类在 `CrudRepository` 基础类中增加了分页和排序的支持。

我们将使用 `CrudRepository` 类作为 `Recommendation` 和 `Review` 仓库的基础类，以及 `PagingAndSortingRepository` 类作为 `Product` 仓库的基础类。

我们还将向我们的仓库中添加几个额外的查询方法，用于使用业务键 `productId` 查找实体。

Spring Data 支持基于方法签名的命名约定定义额外的查询方法。例如，`findByProductId(int productId)` 方法签名可以用来指导 Spring Data 自动创建一个查询，当调用查询方法时，返回底层集合或表中`productId`字段设置为`productId`参数中指定值的实体。有关如何声明额外查询的详细信息，请参阅[`docs.spring.io/spring-data/data-commons/docs/current/reference/html/#repositories.query-methods.query-creation`](https://docs.spring.io/spring-data/data-commons/docs/current/reference/html/#repositories.query-methods.query-creation)。

`Product` 仓库类看起来是这样的：

```java
public interface ProductRepository extends PagingAndSortingRepository<ProductEntity, String> {
    Optional<ProductEntity> findByProductId(int productId);
}
```

因为`findByProductId`方法可能返回零个或一个产品实体，所以通过将其包裹在`Optional`对象中来标记返回值为可选的。

`Recommendation` 仓库类看起来是这样的：

```java
public interface RecommendationRepository extends CrudRepository<RecommendationEntity, String> {
    List<RecommendationEntity> findByProductId(int productId);
}
```

在这个案例中，`findByProductId`方法将返回零到多个推荐实体，所以返回值被定义为一个列表。

最后，`Review` 仓库类的样子是这样的：

```java
public interface ReviewRepository extends CrudRepository<ReviewEntity, Integer> {
    @Transactional(readOnly = true)
    List<ReviewEntity> findByProductId(int productId);
}
```

由于 SQL 数据库是事务性的，我们必须为查询方法`findByProductId()`指定默认的事务类型——在我们的案例中是只读的。

就这样——这就是为我们的核心微服务建立持久化层所需的所有步骤。

要在以下位置查看仓库类的完整源代码：

+   `se.magnus.microservices.core.product.persistence.ProductRepository` 在 `product` 项目中

+   `se.magnus.microservices.core.recommendation.persistence.RecommendationRepository` 在 `recommendation` 项目中

+   `se.magnus.microservices.core.review.persistence.ReviewRepository` 在 `review` 项目中

让我们通过编写一些持久化测试来验证它们是否如预期般工作。

# 编写关注持久化的自动化测试

在编写持久化测试时，我们希望当测试开始时启动一个嵌入式数据库，当测试完成时将其销毁。然而，我们不希望测试等待其他资源启动，例如，Netty 之类的 Web 服务器（在运行时是必需的）。

Spring Boot 带有两个针对此特定要求定制的类级注解：

+   `@DataMongoTest`：当测试开始时启动一个嵌入式 MongoDB 数据库。

+   `@DataJpaTest`：当测试开始时启动一个嵌入式 SQL 数据库：

    +   自从我们在构建文件中向评论微服务的 H2 数据库添加了测试依赖后，它将被用作嵌入式 SQL 数据库。

    +   默认情况下，Spring Boot 配置测试以回滚 SQL 数据库的更新，以最小化对其他测试的负面副作用风险。在我们的情况下，这种行为将导致一些测试失败。因此，通过类级注解禁用了自动回滚：`@Transactional(propagation = NOT_SUPPORTED)`。

三个核心微服务的持久化测试彼此相似，因此我们只需查看`Product`微服务的持久化测试。

测试类声明了一个方法`setupDb()`，用`@Before`注解标记，在每种测试方法之前执行。设置方法从数据库中删除以前测试的任何实体，并插入一个测试方法可以作为其测试基础的实体：

```java
@RunWith(SpringRunner.class)
@DataMongoTest
public class PersistenceTests {

    @Autowired
    private ProductRepository repository;
    private ProductEntity savedEntity;

    @Before
    public void setupDb() {
        repository.deleteAll();
        ProductEntity entity = new ProductEntity(1, "n", 1);
        savedEntity = repository.save(entity);
        assertEqualsProduct(entity, savedEntity);
    }
```

接下来是各种测试方法。首先是`create`测试：

```java
@Test
public void create() {
    ProductEntity newEntity = new ProductEntity(2, "n", 2);
    savedEntity = repository.save(newEntity);

    ProductEntity foundEntity = 
    repository.findById(newEntity.getId()).get();
    assertEqualsProduct(newEntity, foundEntity);

    assertEquals(2, repository.count());
}
```

此测试创建了一个新实体，并验证它可以通过`findByProductId()`方法找到，并以断言数据库中存储了两个实体结束，一个是通过`setup`方法创建的，另一个是测试本身创建的。

`update`测试看起来像这样：

```java
@Test
public void update() {
    savedEntity.setName("n2");
    repository.save(savedEntity);

    ProductEntity foundEntity = 
    repository.findById(savedEntity.getId()).get();
    assertEquals(1, (long)foundEntity.getVersion());
    assertEquals("n2", foundEntity.getName());
}
```

此测试更新了由设置方法创建的实体，再次使用标准的`findById()`方法从数据库中读取它，并断言它的一些字段包含期望的值。注意，当实体被创建时，其`version`字段由 Spring Data 设置为`0`。

`delete`测试看起来像这样：

```java
@Test
public void delete() {
    repository.delete(savedEntity);
    assertFalse(repository.existsById(savedEntity.getId()));
}
```

此测试删除由`setup`方法创建的实体，并验证它不再存在于数据库中。

`read`测试看起来像这样：

```java
@Test
public void getByProductId() {
    Optional<ProductEntity> entity = 
    repository.findByProductId(savedEntity.getProductId());
    assertTrue(entity.isPresent());
    assertEqualsProduct(savedEntity, entity.get());
}
```

此测试使用了`findByProductId()`方法来获取由`setup`方法创建的实体，验证它是否被找到，然后使用本地助手方法`assertEqualsProduct()`来验证`findByProductId()`返回的实体是否与`setup`方法存储的实体相同。

接下来，它跟随两个测试方法，验证替代流程——错误条件的处理。首先是验证重复正确处理的测试：

```java
@Test(expected = DuplicateKeyException.class)
public void duplicateError() {
    ProductEntity entity = new 
    ProductEntity(savedEntity.getProductId(), "n", 1);
    repository.save(entity);
}
```

测试尝试存储一个与`setup`方法保存的实体具有相同业务键的实体。如果保存操作成功，或者保存失败并抛出预期之外的异常，`DuplicateKeyException`，则测试将失败。

在我看来，另一个负向测试是测试类中最有趣的测试。这是一个测试，用于验证在更新陈旧数据时的正确错误处理——它验证乐观锁定机制是否工作。它看起来像这样：

```java
@Test
public void optimisticLockError() {

    // Store the saved entity in two separate entity objects
    ProductEntity entity1 = 
    repository.findById(savedEntity.getId()).get();
    ProductEntity entity2 = 
    repository.findById(savedEntity.getId()).get();

    // Update the entity using the first entity object
    entity1.setName("n1");
    repository.save(entity1);

    //  Update the entity using the second entity object.
    // This should fail since the second entity now holds a old version 
    // number, that is, a Optimistic Lock Error
    try {
        entity2.setName("n2");
        repository.save(entity2);

        fail("Expected an OptimisticLockingFailureException");
    } catch (OptimisticLockingFailureException e) {}

    // Get the updated entity from the database and verify its new 
    // state
    ProductEntity updatedEntity = 
    repository.findById(savedEntity.getId()).get();
    assertEquals(1, (int)updatedEntity.getVersion());
    assertEquals("n1", updatedEntity.getName());
}
```

从前面的代码中观察到以下情况：

1.  首先，测试两次读取同一个实体，并将其存储在两个不同的变量`entity1`和`entity2`中。

1.  接下来，它使用其中一个变量`entity1`来更新实体。在数据库中更新实体将导致 Spring Data 自动增加实体的版本字段。另一个变量`entity2`现在包含陈旧数据，体现在其版本字段持有的值低于数据库中对应值。

1.  当测试尝试使用包含陈旧数据的变量`entity2`更新实体时，预计会通过抛出`OptimisticLockingFailureException`异常来失败。

1.  测试通过断言数据库中的实体反映了第一次更新，即包含名称`"n1"`，并且版本字段具有值`1`，即只在数据库中更新了实体的一次。

最后，`product`服务包含一个测试，演示了 Spring Data 中内置的排序和分页支持的用法：

```java
@Test
public void paging() {
    repository.deleteAll();
    List<ProductEntity> newProducts = rangeClosed(1001, 1010)
        .mapToObj(i -> new ProductEntity(i, "name " + i, i))
        .collect(Collectors.toList());
    repository.saveAll(newProducts);

    Pageable nextPage = PageRequest.of(0, 4, ASC, "productId");
    nextPage = testNextPage(nextPage, "[1001, 1002, 1003, 1004]", 
    true);
    nextPage = testNextPage(nextPage, "[1005, 1006, 1007, 1008]", 
    true);
    nextPage = testNextPage(nextPage, "[1009, 1010]", false);
}
```

从前面的代码中观察到以下内容：

1.  测试从删除任何现有数据开始，然后插入具有`productId`字段从`1001`到`1010`的 10 个实体。

1.  接下来，它创建了`PageRequest`，请求每页 4 个实体的分页计数，并根据`ProductId`升序排序。

1.  最后，它使用一个助手方法`testNextPage`来读取预期的三页内容，验证每页中预期的产品 ID，并验证 Spring Data 正确报告是否存在更多页面。

助手方法`testNextPage`看起来像这样：

```java
private Pageable testNextPage(Pageable nextPage, String expectedProductIds, boolean expectsNextPage) {
    Page<ProductEntity> productPage = repository.findAll(nextPage);
    assertEquals(expectedProductIds, productPage.getContent()
    .stream().map(p -> p.getProductId()).collect(Collectors.
    toList()).toString());
    assertEquals(expectsNextPage, productPage.hasNext());
    return productPage.nextPageable();
}
```

助手方法使用分页请求对象`nextPage`从仓库方法的`findAll()`获取下一页。根据结果，它从返回的实体中提取产品 ID，将其转换为字符串，并与期望的产品 ID 列表进行比较。最后，它返回一个布尔值，指示是否可以检索更多页面。

三篇持久化测试类的完整源代码，请参见以下内容：

+   `se.magnus.microservices.core.product.PersistenceTests`在`product`项目中

+   `se.magnus.microservices.core.recommendation.PersistenceTests`在`recommendation`项目中

+   `se.magnus.microservices.core.review.PersistenceTests`在`review`项目中

`product`微服务中的持久化测试可以通过使用 Gradle 执行以下命令来执行：

```java
cd $BOOK_HOME/Chapter06
./gradlew microservices:product-service:test --tests PersistenceTests
```

运行测试后，它应该响应以下内容：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/hsn-msvc-sprbt-sprcld/img/cf9108ce-73db-41ea-ab82-0bf1eb098921.png)

在持久化层就位后，我们可以将核心微服务中的服务层更新为使用持久化层。

# 在服务层使用持久化层

在本节中，我们将学习如何在服务层使用持久化层来存储和从数据库中检索数据。我们将按照以下步骤进行：

1.  日志记录数据库连接 URL。

1.  添加新的 API。

1.  使用持久化层。

1.  声明一个 Java bean mapper。

1.  更新服务测试。

# 日志记录数据库连接 URL

当扩展微服务的数量时，每个微服务连接到自己的数据库，我发现自己有时不确定每个微服务实际上使用的是哪个数据库。因此，我通常在微服务启动后直接添加一个日志语句，记录用于连接数据库的连接 URL。

例如，`Product`服务的启动代码看起来像这样：

```java
public class ProductServiceApplication {
  private static final Logger LOG = 
  LoggerFactory.getLogger(ProductServiceApplication.class);

  public static void main(String[] args) {
    ConfigurableApplicationContext ctx = 
    SpringApplication.run(ProductServiceApplication.class, args);
    String mongodDbHost = 
    ctx.getEnvironment().getProperty("spring.data.mongodb.host");
    String mongodDbPort = 
    ctx.getEnvironment().getProperty("spring.data.mongodb.port");
    LOG.info("Connected to MongoDb: " + mongodDbHost + ":" + 
    mongodDbPort);
  }
}
```

在日志中，应期望以下类型的输出：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/hsn-msvc-sprbt-sprcld/img/96ba31d3-159d-4cca-a6b9-b3000522b943.png)

要查看完整的源代码，请参阅`product`项目中的`se.magnus.microservices.core.product.ProductServiceApplication`类。

# 添加新 API

在我们能够使用持久化层在数据库中创建和删除信息之前，我们需要在我们的核心服务 API 中创建相应的 API 操作。

创建和删除产品实体的 API 操作看起来像这样：

```java
@PostMapping(
    value    = "/product",
    consumes = "application/json",
    produces = "application/json")
Product createProduct(@RequestBody Product body);

@DeleteMapping(value = "/product/{productId}")
void deleteProduct(@PathVariable int productId);
```

删除操作的实现将是幂等的，也就是说，如果多次调用，它将返回相同的结果。这在故障场景中是一个宝贵的特性。例如，如果客户端在调用删除操作时遇到网络超时，它可以简单地再次调用删除操作，而不用担心不同的响应，例如，第一次响应为 OK (200) 和连续调用响应为 Not Found (404)，或者任何意外的副作用。这暗示了即使实体在数据库中不再存在，操作也应该返回 OK (200)的状态码。

`recommendation` 和 `review` 实体的 API 操作看起来很相似；然而，注意，当涉及到`recommendation` 和 `review` 实体的删除操作时，它将删除指定`productId`的所有`recommendations`和`reviews`。

要查看完整的源代码，请查看`api`项目中的以下类：

+   `se.magnus.api.core.product.ProductService`

+   `se.magnus.api.core.recommendation.RecommendationService`

+   `se.magnus.api.core.review.ReviewService`

# 使用持久化层

在服务层中使用持久化层的源代码对于所有核心微服务都是结构相同的。因此，我们只查看`Product`微服务的源代码。

首先，我们需要从持久化层注入仓库类和一个 Java bean 映射器类到构造函数中：

```java
private final ServiceUtil serviceUtil;
private final ProductRepository repository;
private final ProductMapper mapper;

@Autowired
public ProductServiceImpl(ProductRepository repository, ProductMapper mapper, ServiceUtil serviceUtil) {
    this.repository = repository;
    this.mapper = mapper;
    this.serviceUtil = serviceUtil;
}
```

在下一节中，我们将看到 Java 映射器类是如何定义的。

接下来，按照以下方式实现`createProduct`方法：

```java
public Product createProduct(Product body) {
    try {
        ProductEntity entity = mapper.apiToEntity(body);
        ProductEntity newEntity = repository.save(entity);
        return mapper.entityToApi(newEntity);
    } catch (DuplicateKeyException dke) {
        throw new InvalidInputException("Duplicate key, Product Id: " + 
        body.getProductId());
    }
}
```

`create`方法使用了仓库中的`save`方法来存储一个新的实体。应注意映射器类是如何使用两个映射器方法`apiToEntity()`和`entityToApi()`，在 API 模型类和实体类之间转换 Java bean 的。我们为`create`方法处理的唯一错误是`DuplicateKeyException`异常，我们将它转换为`InvalidInputException`异常。

`getProduct`方法看起来像这样：

```java
public Product getProduct(int productId) {
    if (productId < 1) throw new InvalidInputException("Invalid 
    productId: " + productId);
    ProductEntity entity = repository.findByProductId(productId)
        .orElseThrow(() -> new NotFoundException("No product found for 
         productId: " + productId));
    Product response = mapper.entityToApi(entity);
    response.setServiceAddress(serviceUtil.getServiceAddress());
    return response;
}
```

在进行了基本输入验证（即确保`productId`不是负数）之后，仓库中的`findByProductId()`方法用于查找产品实体。由于仓库方法返回一个`Optional`产品，我们可以使用`Optional`类中的`orElseThrow()`方法方便地抛出如果没有找到产品实体就抛出`NotFoundException`异常。在返回产品信息之前，使用`serviceUtil`对象填充微服务当前使用的地址。

最后，让我们看看`deleteProduct`方法：

```java
public void deleteProduct(int productId) {
    repository.findByProductId(productId).ifPresent(e -> 
    repository.delete(e));
}
```

`delete` 方法还使用了仓库中的`findByProductId()`方法，并使用了`Optional`类中的`ifPresent()`方法，方便地仅在实体存在时删除实体。注意，该实现是幂等的，即，如果找不到实体，它不会报告任何故障。

三个服务实现类的源代码可以在以下位置找到：

+   `se.magnus.microservices.core.product.services.ProductServiceImpl` 在 `product` 项目中

+   `se.magnus.microservices.core.recommendation.services.RecommendationServiceImpl` 在 `recommendation` 项目中

+   `se.magnus.microservices.core.review.services.ReviewServiceImpl` 在 `review` 项目中

# 声明一个 Java bean 映射器

那么，魔法的 Java bean 映射器又如何呢？

正如前面提到的，我们使用 MapStruct 来声明我们的映射器类。MapStruct 在三个核心微服务中的使用是相似的，所以我们只查看`Product`微服务中的映射器对象源代码。

`product` 服务的映射器类看起来像这样：

```java
@Mapper(componentModel = "spring")
public interface ProductMapper {

    @Mappings({
        @Mapping(target = "serviceAddress", ignore = true)
    })
    Product entityToApi(ProductEntity entity);

    @Mappings({
        @Mapping(target = "id", ignore = true),
        @Mapping(target = "version", ignore = true)
    })
    ProductEntity apiToEntity(Product api);
}
```

从前面的代码中观察到以下内容：

+   `entityToApi()`方法将实体对象映射到 API 模型对象。由于实体类没有`serviceAddress`字段，`entityToApi()`方法被注解忽略`serviceAddress`。

+   `apiToEntity()`方法将 API 模型对象映射到实体对象。同样，`apiToEntity()`方法被注解忽略在 API 模型类中缺失的`id`和`version`字段。

MapStruct 不仅支持按名称映射字段，还可以指定它映射具有不同名称的字段。在`Recommendation`服务的映射器类中，使用以下注解将`rating`实体字段映射到 API 模型字段`rate`：

```java
    @Mapping(target = "rate", source="entity.rating"),
    Recommendation entityToApi(RecommendationEntity entity);

    @Mapping(target = "rating", source="api.rate"),
    RecommendationEntity apiToEntity(Recommendation api);
```

成功构建 Gradle 后，生成的映射实现可以在`build/classes` 文件夹中找到，例如，`Product`服务：`$BOOK_HOME/Chapter06/microservices/product-service/build/classes/java/main/se/magnus/microservices/core/product/services/ProductMapperImpl.java`。

三个映射器类的源代码可以在以下位置找到：

+   `se.magnus.microservices.core.product.services.ProductMapper` 在 `product` 项目中

+   `se.magnus.microservices.core.recommendation.services.RecommendationMapper` 在 `recommendation` 项目中

+   `se.magnus.microservices.core.review.services.ReviewMapper` 在 `review` 项目中

# 更新服务测试

自上一章以来，核心微服务暴露的 API 的测试已经更新，增加了对创建和删除 API 操作的测试。

新增的测试在三个核心微服务中都是相似的，所以我们只查看`Product`微服务中的服务测试源代码。

为了确保每个测试都有一个已知的状态，声明了一个设置方法，`setupDb()`，并用 `@Before` 注解，这样它会在每个测试运行之前运行。设置方法移除了之前创建的任何实体：

```java
@Autowired
private ProductRepository repository;

@Before
public void setupDb() {
   repository.deleteAll();
}
```

创建 API 的测试方法验证了一个产品实体在创建后可以被检索到，并且使用相同的 `productId` 创建另一个产品实体会导致预期的错误，`UNPROCESSABLE_ENTITY`，在 API 请求的响应中：

```java
@Test
public void duplicateError() {
   int productId = 1;
   postAndVerifyProduct(productId, OK);
   assertTrue(repository.findByProductId(productId).isPresent());

   postAndVerifyProduct(productId, UNPROCESSABLE_ENTITY)
      .jsonPath("$.path").isEqualTo("/product")
      .jsonPath("$.message").isEqualTo("Duplicate key, Product Id: " + 
       productId);
}
```

删除 API 的测试方法验证了一个产品实体可以被删除，并且第二个删除请求是幂等的——它还返回了状态码 OK，即使实体在数据库中已不再存在：

```java
@Test
public void deleteProduct() {
   int productId = 1;
   postAndVerifyProduct(productId, OK);
   assertTrue(repository.findByProductId(productId).isPresent());

   deleteAndVerifyProduct(productId, OK);
   assertFalse(repository.findByProductId(productId).isPresent());

   deleteAndVerifyProduct(productId, OK);
}
```

为了简化向 API 发送创建、读取和删除请求并验证响应状态，已经创建了三个辅助方法：

+   `postAndVerifyProduct()`

+   `getAndVerifyProduct()`

+   `deleteAndVerifyProduct()`

`postAndVerifyProduct()` 方法看起来是这样的：

```java
private WebTestClient.BodyContentSpec postAndVerifyProduct(int productId, HttpStatus expectedStatus) {
   Product product = new Product(productId, "Name " + productId, 
   productId, "SA");
   return client.post()
      .uri("/product")
      .body(just(product), Product.class)
      .accept(APPLICATION_JSON_UTF8)
      .exchange()
      .expectStatus().isEqualTo(expectedStatus)
      .expectHeader().contentType(APPLICATION_JSON_UTF8)
      .expectBody();
}
```

除了执行实际的 HTTP 请求并验证其响应码外，辅助方法还将响应的正文返回给调用者进行进一步调查，如果需要的话。另外两个用于读取和删除请求的辅助方法类似，可以在本节开头指出的源代码中找到。

三个服务测试类的源代码可以在以下位置找到：

+   `se.magnus.microservices.core.product.ProductServiceApplicationTests` 在 `product` 项目中

+   `se.magnus.microservices.core.recommendation.RecommendationServiceApplicationTests` 在 `recommendation` 项目中

+   `se.magnus.microservices.core.review.ReviewServiceApplicationTests` 在 `review` 项目中

现在，让我们来看看如何扩展复合服务 API。

# 扩展复合服务 API

在本节中，我们将了解如何扩展复合 API 以创建和删除复合实体。我们将按照以下步骤进行：

1.  在复合服务 API 中添加新操作

1.  在集成层中添加方法

1.  实现新的复合 API 操作

1.  更新复合服务测试

# 在复合服务 API 中添加新操作

创建和删除实体的复合版本以及处理聚合实体的方法与核心服务 API 中的创建和删除操作相似。主要区别在于，它们添加了用于基于 Swagger 的文档的注解。有关 Swagger 注解的使用说明，请参阅 第五章，*使用 OpenAPI/Swagger 添加 API 描述* 节，*在 ProductCompositeService 中添加 API 特定文档*。创建复合产品实体的 API 操作声明如下：

```java
@ApiOperation(
    value = "${api.product-composite.create-composite-
    product.description}",
    notes = "${api.product-composite.create-composite-product.notes}")
@ApiResponses(value = {
    @ApiResponse(code = 400, message = "Bad Request, invalid format of 
    the request. See response message for more information."),
    @ApiResponse(code = 422, message = "Unprocessable entity, input 
    parameters caused the processing to fail. See response message for 
    more information.")
})
@PostMapping(
    value    = "/product-composite",
    consumes = "application/json")
void createCompositeProduct(@RequestBody ProductAggregate body);
```

删除复合产品实体的 API 操作声明如下：

```java
@ApiOperation(
    value = "${api.product-composite.delete-composite-
    product.description}",
    notes = "${api.product-composite.delete-composite-product.notes}")
@ApiResponses(value = {
    @ApiResponse(code = 400, message = "Bad Request, invalid format of 
    the request. See response message for more information."),
    @ApiResponse(code = 422, message = "Unprocessable entity, input 
    parameters caused the processing to fail. See response message for 
    more information.")
})
@DeleteMapping(value = "/product-composite/{productId}")
void deleteCompositeProduct(@PathVariable int productId);
```

完整的源代码，请参阅`api`项目中的 Java 接口`se.magnus.api.composite.product.ProductCompositeService`。

我们还需要像以前一样，将 API 文档的描述性文本添加到属性文件`application.yml`中：

```java
create-composite-product:
  description: Creates a composite product
  notes: |
    # Normal response
    The composite product information posted to the API will be 
    splitted up and stored as separate product-info, recommendation and 
    review entities.

    # Expected error responses
    1\. If a product with the same productId as specified in the posted 
    information already exists, an <b>422 - Unprocessable Entity</b> 
    error with a "duplicate key" error message will be returned

delete-composite-product:
  description: Deletes a product composite
  notes: |
    # Normal response
    Entities for product information, recommendations and reviews 
    related to the specificed productId will be deleted.
    The implementation of the delete method is idempotent, that is, it 
    can be called several times with the same response.
    This means that a delete request of a non existing product will 
    return <b>200 Ok</b>.
```

具体细节，请查看`product-composite`项目中的`src/main/resources/application.yml`配置文件。

更新后的 Swagger 文档将如下所示：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/hsn-msvc-sprbt-sprcld/img/52f270b1-6039-4d6e-ad95-f4a9a7029063.png)

在本章后面，我们将使用 Swagger UI 来尝试新的组合 API 操作。

# 在集成层中添加方法

在我们能够实现组合服务中的新创建和删除 API 之前，我们需要扩展集成层，使其能够调用核心微服务 API 中的底层创建和删除操作。

调用三个核心微服务中的创建和删除操作的集成层方法简单且彼此相似，所以我们只查看调用`Product`微服务的方法的源代码。

`createProduct()`方法看起来像这样：

```java
@Override
public Product createProduct(Product body) {
    try {
        return restTemplate.postForObject(productServiceUrl, body, 
        Product.class);
    } catch (HttpClientErrorException ex) {
        throw handleHttpClientException(ex);
    }
}
```

它简单地将发送 HTTP 请求的责任委托给`RestTemplate`对象，并将错误处理委托给助手方法`handleHttpClientException`。

`deleteProduct()`方法看起来像这样：

```java
@Override
public void deleteProduct(int productId) {
    try {
        restTemplate.delete(productServiceUrl + "/" + productId);
    } catch (HttpClientErrorException ex) {
        throw handleHttpClientException(ex);
    }
}
```

它的实现方式与创建方法相同，但执行的是 HTTP 删除请求。

集成层完整的源代码可以在`product-composite`项目中的`se.magnus.microservices.composite.product.services.ProductCompositeIntegration`类中找到。

# 实现新的组合 API 操作

现在，我们可以实现组合的创建和删除方法！

组合的创建方法会将聚合产品对象拆分为`product`、`recommendation`和`review`的独立对象，并在集成层中调用相应的创建方法：

```java
@Override
public void createCompositeProduct(ProductAggregate body) {
    try {
        Product product = new Product(body.getProductId(), 
        body.getName(), body.getWeight(), null);
        integration.createProduct(product);

        if (body.getRecommendations() != null) {
            body.getRecommendations().forEach(r -> {
                Recommendation recommendation = new 
                Recommendation(body.getProductId(), 
                r.getRecommendationId(), r.getAuthor(), r.getRate(), 
                r.getContent(), null);
                integration.createRecommendation(recommendation);
            });
        }

        if (body.getReviews() != null) {
            body.getReviews().forEach(r -> {
                Review review = new Review(body.getProductId(), 
                r.getReviewId(), r.getAuthor(), r.getSubject(), 
                r.getContent(), null);
                integration.createReview(review);
            });
        }
    } catch (RuntimeException re) {
        LOG.warn("createCompositeProduct failed", re);
        throw re;
    }
}
```

组合的删除方法 simply calls the three delete methods in the integration layer to delete the corresponding entities in the underlying databases:

```java
@Override
public void deleteCompositeProduct(int productId) {
    integration.deleteProduct(productId);
    integration.deleteRecommendations(productId);
    integration.deleteReviews(productId);
}
```

完整的源代码，请参阅`product-composite`项目中的`se.magnus.microservices.composite.product.services.ProductCompositeServiceImpl`类。

对于快乐路径场景，这个实现会很好，但如果我们考虑各种错误场景，这个实现将会带来麻烦！

例如，如果底层的核心微服务之一暂时不可用，可能是由于内部、网络或数据库问题，那该怎么办？

这可能导致部分创建或删除的组合产品。对于删除操作，如果请求者简单地调用组合的删除方法直到成功，这可以得到修复。然而，如果底层问题持续一段时间，请求者可能会放弃，导致组合产品的不一致状态——在大多数情况下这是不可接受的！

在下一章第七章中，*开发反应式微服务*，我们将了解如何使用同步 API（如 RESTful API）来解决这些问题！

现在，让我们带着这个脆弱的设计继续前进。

# 更新组合服务测试：

正如在第三章中提到的*创建一组协作微服务*（参考*隔离微服务的自动化测试*部分），测试组合服务限于使用简单的模拟组件而不是实际的核心服务。这限制了我们测试更复杂场景的能力，例如，在尝试在底层数据库中创建重复项时的错误处理。组合的创建和删除 API 操作的测试相对简单：

```java
@Test
public void createCompositeProduct1() {
   ProductAggregate compositeProduct = new ProductAggregate(1, "name", 
   1, null, null, null);
   postAndVerifyProduct(compositeProduct, OK);
}

@Test
public void createCompositeProduct2() {
    ProductAggregate compositeProduct = new ProductAggregate(1, "name", 
        1, singletonList(new RecommendationSummary(1, "a", 1, "c")),
        singletonList(new ReviewSummary(1, "a", "s", "c")), null);
    postAndVerifyProduct(compositeProduct, OK);
}

@Test
public void deleteCompositeProduct() {
    ProductAggregate compositeProduct = new ProductAggregate(1, "name", 
        1,singletonList(new RecommendationSummary(1, "a", 1, "c")),
        singletonList(new ReviewSummary(1, "a", "s", "c")), null);
    postAndVerifyProduct(compositeProduct, OK);
    deleteAndVerifyProduct(compositeProduct.getProductId(), OK);
    deleteAndVerifyProduct(compositeProduct.getProductId(), OK);
}
```

完整的源代码，请参阅`product-composite`项目中的测试类，`se.magnus.microservices.composite.product.ProductCompositeServiceApplicationTests`。

接下来，我们将了解如何将数据库添加到 Docker Compose 的景观中。

# 向 Docker Compose 景观添加数据库：

现在，我们已经将所有源代码放到位。在我们能够启动微服务景观并尝试新的 API 以及新的持久层之前，我们必须启动一些数据库。

我们将把 MongoDB 和 MySQL 带入由 Docker Compose 控制的系统景观，并向我们的微服务添加配置，以便它们在运行时能够找到它们的数据库，无论是否作为 Docker 容器运行。

# Docker Compose 配置：

MongoDB 和 MySQL 在 Docker Compose 配置文件`docker-compose.yml`中声明如下：

```java
mongodb:
  image: mongo:3.6.9
  mem_limit: 350m
  ports:
    - "27017:27017"
  command: mongod --smallfiles

mysql:
  image: mysql:5.7
  mem_limit: 350m
  ports:
    - "3306:3306"
  environment:
    - MYSQL_ROOT_PASSWORD=rootpwd
    - MYSQL_DATABASE=review-db
    - MYSQL_USER=user
    - MYSQL_PASSWORD=pwd
  healthcheck:
    test: ["CMD", "mysqladmin" ,"ping", "-uuser", "-ppwd", "-h", "localhost"]
    interval: 10s
    timeout: 5s
    retries: 10
```

以下是从前面代码中观察到的：

1.  我们将使用官方的 MongoDB V3.6.9 和 MySQL 5.7 Docker 镜像，并将它们的默认端口`27017`和`3306`转发到 Docker 主机，在 Mac 上使用 Docker 时也可在`localhost`上访问。

1.  对于 MySQL，我们还声明了一些环境变量，定义如下：

    +   root 密码：

    +   将在图像启动时创建的数据库的名称：

    +   为在图像启动时为数据库设置的用户设置用户名和密码：

1.  对于 MySQL，我们还声明了一个健康检查，Docker 将运行该检查以确定 MySQL 数据库的状态。

为了避免微服务在数据库启动之前尝试连接到它们的数据库的问题，`product`和`recommendation`服务被声明为依赖于`mongodb`数据库，如下所示：

```java
product/recommendation:
 depends_on:
 - mongodb
```

这意味着 Docker Compose 将在启动`mongodb`容器后启动`product`和`recommendation`容器。

出于同样的原因，`review`服务被声明为依赖于`mysql`数据库：

```java
review:
  depends_on:
    mysql:
      condition: service_healthy
```

在这种情况下，`review`服务依赖于不仅启动了`mysql`容器，而且`mysql`容器的健康检查报告也正常。之所以采取这一额外步骤，是因为`mysql`容器的初始化包括设置数据库并创建数据库超级用户。这需要几秒钟，为了在完成此操作之前阻止`review`服务启动，我们指示 Docker Compose 在`mysql`容器通过其健康检查报告正常之前，不要启动`review`容器。

# 数据库连接配置

有了数据库之后，我们现在需要为核心微服务设置配置，以便它们知道如何连接到其数据库。这在每个核心微服务的配置文件`src/main/resources/application.yml`中进行设置，位于`product`，`recommendation`和`review`项目中。

`product`和`recommendation`服务的配置类似，所以我们只查看`product`服务的配置。以下配置部分值得关注：

```java
spring.data.mongodb:
  host: localhost
  port: 27017
  database: product-db

logging:
 level:
 org.springframework.data.mongodb.core.MongoTemplate: DEBUG

---
spring.profiles: docker

spring.data.mongodb.host: mongodb
```

以下是从前面代码中观察到的：

1.  在没有 Docker 的情况下运行，使用默认的 Spring 配置文件，期望数据库可以在`localhost:27017`上访问。

1.  将`MongoTemplate`的日志级别设置为`DEBUG`将允许我们查看在日志中执行了哪些 MongoDB 语句。

1.  在使用 Spring 配置文件运行 Docker 内部时，`Docker`，数据库期望可以在`mongodb:27017`上访问。

影响`review`服务如何连接其 SQL 数据库的配置如下所示：

```java
spring.jpa.hibernate.ddl-auto: update

spring.datasource:
  url: jdbc:mysql://localhost/review-db
  username: user
  password: pwd

spring.datasource.hikari.initializationFailTimeout: 60000

logging:
 level:
 org.hibernate.SQL: DEBUG
 org.hibernate.type.descriptor.sql.BasicBinder: TRACE

---
spring.profiles: docker

spring.datasource:
 url: jdbc:mysql://mysql/review-db
```

以下是从前面代码中观察到的：

1.  默认情况下，Spring Data JPA 将使用 Hibernate 作为 JPA 实体管理器。

1.  `spring.jpa.hibernate.ddl-auto`属性用于告诉 Spring Data JPA 在启动期间创建新的或更新现有的 SQL 表。

    **注意：**强烈建议在生产环境中将`spring.jpa.hibernate.ddl-auto`属性设置为`none`——这防止 Spring Data JPA 操作 SQL 表的结构。

1.  在没有 Docker 的情况下运行，使用默认的 Spring 配置文件，期望数据库可以在`localhost`上使用默认端口`3306`访问。

1.  默认情况下，Spring Data JPA 使用 HikariCP 作为 JDBC 连接池。为了在硬件资源有限的计算机上最小化启动问题，将`initializationFailTimeout`参数设置为 60 秒。这意味着 Spring Boot 应用程序在启动期间会等待最多 60 秒以建立数据库连接。

1.  Hibernate 的日志级别设置会导致 Hibernate 打印使用的 SQL 语句和实际值。请注意，在生产环境中，出于隐私原因，应避免将实际值写入日志。

1.  当使用 Spring 配置文件`Docker`在 Docker 内运行时，数据库预期可以通过`mysql`主机名使用默认端口`3306`可达。

# MongoDB 和 MySQL CLI 工具

为了能够运行数据库 CLI 工具，可以使用 Docker Compose `exec`命令。

本节描述的命令将在下一节的手动测试中使用。现在不要尝试运行它们；因为我们现在还没有运行数据库，所以它们会失败！

要启动 MongoDB CLI 工具`mongo`，在`mongodb`容器内运行以下命令：

```java
docker-compose exec mongodb mongo --quiet
>
```

输入`exit`以离开`mongo` CLI。

要启动 MySQL CLI 工具`mysql`，在`mysql`容器内并使用启动时创建的用户登录到`review-db`，请运行以下命令：

```java
docker-compose exec mysql mysql -uuser -p review-db
mysql>
```

`mysql` CLI 工具将提示您输入密码；您可以在`docker-compose.yml`文件中找到它。查找环境变量的值`MYSQL_PASSWORD`。

输入`exit`以离开`mysql` CLI。

我们将在下一节看到这些工具的使用。

如果您更喜欢图形数据库工具，您也可以本地运行它们，因为 MongoDB 和 MySQL 容器都将在本地主机上暴露它们的标准端口。

# 对新 API 和持久化层进行手动测试。

现在，终于可以启动一切并使用 Swagger UI 进行手动测试了。

使用以下命令构建并启动系统架构：

```java
cd $BOOK_HOME/Chapter06
./gradlew build && docker-compose build && docker-compose up
```

在网络浏览器中打开 Swagger UI，`http://localhost:8080/swagger-ui.html`，并在网页上执行以下步骤：

1.  点击产品组合服务实现（product-composite-service-impl）和 POST 方法以展开它们。

1.  点击尝试一下（Try it out）按钮并下移到正文字段。

1.  将`productId`字段的默认值`0`替换为`123456`。

1.  滚动到底部的执行按钮并点击它。

1.  验证返回的响应码是`200`。

点击执行按钮后的示例屏幕截图如下：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/hsn-msvc-sprbt-sprcld/img/eb728f85-f6b7-42e9-89a2-41ed11559551.png)

从`docker-compose up`命令的日志输出中，我们应该能够看到如下输出（为了提高可读性而简化）：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/hsn-msvc-sprbt-sprcld/img/1b2a26c1-fe45-49c0-95e9-9a8d4384351e.png)

我们还可以使用数据库 CLI 工具来查看不同数据库中的实际内容。

在`product`服务中查找内容，即 MongoDB 中的`products`集合，使用以下命令：

```java
docker-compose exec mongodb mongo product-db --quiet --eval "db.products.find()"
```

期望得到如下响应：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/hsn-msvc-sprbt-sprcld/img/0b57bb76-075c-4cfd-9d65-43d2760a8200.png)

在`recommendation`服务中查找内容，即 MongoDB 中的`recommendations`集合，使用以下命令：

```java
docker-compose exec mongodb mongo recommendation-db --quiet --eval "db.recommendations.find()"
```

期望得到如下响应：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/hsn-msvc-sprbt-sprcld/img/12d6b674-b3ac-4819-9fc8-5423d00c17af.png)10

在`review`服务中查找内容，即 MySQL 中的`reviews`表，使用以下命令：

```java
docker-compose exec mysql mysql -uuser -p review-db -e "select * from reviews"
```

`mysql` CLI 工具将提示您输入密码；您可以在`docker-compose.yml`文件中找到它。查找环境变量的值`MYSQL_PASSWORD`。预期得到如下响应：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/hsn-msvc-sprbt-sprcld/img/b408949c-fb6d-4b76-8976-556538b135d2.png)

通过按下*Ctrl + C*中断`docker-compose up`命令，然后执行`docker-compose down`命令，可以关闭系统环境。之后，我们将看看如何在微服务环境中更新自动化测试。

# 更新微服务环境的自动化测试

微服务环境的自动化测试`test-em-all.bash`需要更新，以确保在运行测试之前，每个微服务数据库都处于已知状态。

脚本增加了一个设置函数`setupTestdata()`，该函数使用组合实体的创建和删除 API 将测试使用的产品重新创建到已知状态。

`setupTestdata`函数如下所示：

```java
function setupTestdata() {

    body=\
    '{"productId":1,"name":"product 1","weight":1, "recommendations":[
        {"recommendationId":1,"author":"author 
         1","rate":1,"content":"content 1"},
        {"recommendationId":2,"author":"author 
         2","rate":2,"content":"content 2"},
        {"recommendationId":3,"author":"author 
         3","rate":3,"content":"content 3"}
    ], "reviews":[
        {"reviewId":1,"author":"author 1","subject":"subject 
         1","content":"content 1"},
        {"reviewId":2,"author":"author 2","subject":"subject 
         2","content":"content 2"},
        {"reviewId":3,"author":"author 3","subject":"subject 
         3","content":"content 3"}
    ]}'
    recreateComposite 1 "$body"

    body=\
    '{"productId":113,"name":"product 113","weight":113, "reviews":[
    {"reviewId":1,"author":"author 1","subject":"subject 
     1","content":"content 1"},
    {"reviewId":2,"author":"author 2","subject":"subject 
     2","content":"content 2"},
    {"reviewId":3,"author":"author 3","subject":"subject 
     3","content":"content 3"}
]}'
    recreateComposite 113 "$body"

    body=\
    '{"productId":213,"name":"product 213","weight":213, 
    "recommendations":[
       {"recommendationId":1,"author":"author 
         1","rate":1,"content":"content 1"},
       {"recommendationId":2,"author":"author 
        2","rate":2,"content":"content 2"},
       {"recommendationId":3,"author":"author 
        3","rate":3,"content":"content 3"}
]}'
    recreateComposite 213 "$body"

}
```

它使用一个辅助函数`recreateComposite()`来对创建和删除 API 执行实际的请求：

```java
function recreateComposite() {
    local productId=$1
    local composite=$2

    assertCurl 200 "curl -X DELETE http://$HOST:$PORT/product-
    composite/${productId} -s"
    curl -X POST http://$HOST:$PORT/product-composite -H "Content-Type: 
    application/json" --data "$composite"
}
```

`setupTestdata`函数在`waitForService`函数之后直接调用：

```java
waitForService curl -X DELETE http://$HOST:$PORT/product-composite/13

setupTestdata
```

`waitForService`函数的主要目的是验证所有微服务是否都已启动并运行。在前一章节中，使用了组合产品服务的 get API。在本章节中，我们使用的是 delete API。使用 get API 时，如果找不到实体，只会调用产品核心微服务；推荐和`review`服务不会被调用以验证它们是否启动并运行。调用 delete API 也将确保`productId 13`的*未找到*测试成功。在本书的后面部分，我们将了解如何为检查微服务环境的运行状态定义特定的 API。

以下命令可执行更新后的测试脚本：

```java
cd $BOOK_HOME/Chapter06
./test-em-all.bash start stop
```

执行应该以编写如下日志消息结束：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/hsn-msvc-sprbt-sprcld/img/bcd02c04-4291-440a-96e4-0660e2792679.png)

这结束了微服务环境的自动化测试的更新。

# 总结

在本章节中，我们看到了如何使用 Spring Data 为核心微服务添加一个持久层。我们使用了 Spring Data 的核心概念，存储库和实体，在 MongoDB 和 MySQL 中以一种类似的编程模型存储数据，即使不是完全可移植的。我们还看到了 Spring Boot 的注解`@DataMongoTest`和`@DataJpaTest`如何用于方便地设置针对持久层的测试；在这种情况下，在测试运行之前自动启动嵌入式数据库，但不会启动微服务在运行时需要的其他基础架构，例如 Netty 这样的 web 服务器。这导致持久层测试易于设置，并且启动开销最小。

我们也看到了持久层如何被服务层使用，以及我们如何为创建和删除实体（包括核心和组合实体）添加 API。

最后，我们学习了使用 Docker Compose 在运行时启动 MongoDB 和 MySQL 等数据库是多么方便，以及如何使用新的创建和删除 API 在运行微服务基础系统景观的自动化测试之前设置测试数据。

然而，在本章中识别出了一个主要问题。使用同步 API 更新（创建或删除）复合实体——一个其部分存储在多个微服务中的实体——如果不成功更新所有涉及的微服务，可能会导致不一致。这通常是不可接受的。这引导我们进入下一章，我们将探讨为什么以及如何构建响应式微服务，即可扩展和健壮的微服务。

# 问题

1.  Spring Data 是一种基于实体和仓库的常见编程模型，可以用于不同类型的数据库引擎。从本章的源代码示例中，MySQL 和 MongoDB 的持久化代码最重要的区别是什么？

1.  实现乐观锁需要 Spring Data 提供什么？

1.  MapStruct 是用来做什么的？

1.  什么是幂等操作，为什么这很有用？

1.  我们如何在不使用 API 的情况下访问存储在 MySQL 和 MongoDB 数据库中的数据？
