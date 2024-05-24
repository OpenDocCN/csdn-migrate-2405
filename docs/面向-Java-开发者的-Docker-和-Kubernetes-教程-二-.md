# 面向 Java 开发者的 Docker 和 Kubernetes 教程（二）

> 原文：[`zh.annas-archive.org/md5/232C7A0FCE93C7B650611F281F88F33B`](https://zh.annas-archive.org/md5/232C7A0FCE93C7B650611F281F88F33B)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第五章：使用 Java 应用程序创建镜像

现在我们有一个简单但功能齐全的基于 Spring Bootstrap 的 Java 微服务，我们可以进一步进行。在使用 Kubernetes 部署之前，让我们将其打包为 Docker 镜像。在本章中，我们将创建一个包含我们应用程序的 Docker 镜像，并将 Spring Boot 应用程序 docker 化以在隔离环境中运行，即容器中。

本章涵盖的主题将是：

+   创建 Dockerfile

+   Dockerfile 指令

+   构建镜像

+   创建和删除镜像

让我们从定义一个`Dockerfile`开始，这将是我们容器的定义。

# Dockerfile

正如您在第一章中所记得的，*Docker 简介*，`Dockerfile`是一种构建镜像的配方。它是一个纯文本文件，包含按顺序由 Docker 执行的指令。每个`Dockerfile`都有一个基础镜像，Docker 引擎将用它来构建。生成的镜像将是文件系统的特定状态：一个只读的、冻结的不可变的快照，由代表文件系统在不同时间点上的更改的层组成。

Docker 中的镜像创建流程非常简单，基本上包括两个步骤：

1.  首先，您准备一个名为`Dockerfile`的文本文件，其中包含一系列关于如何构建镜像的指令。您可以在`Dockerfile`中使用的指令集并不是很广泛，但足以充分指导 Docker 如何创建镜像。

1.  接下来，您执行`docker build`命令，基于您刚刚创建的`Dockerfile`创建一个 Docker 镜像。`docker build`命令在上下文中运行。构建的上下文是指定位置的文件，可以是`PATH`或 URL。`PATH`是本地文件系统上的目录，URL 是 Git 存储库位置。上下文会递归处理。`PATH`将包括任何子目录。URL 将包括存储库及其子模块。

如果您创建一个包含 Java 应用程序的镜像，您也可以跳过第二步，并利用其中一个可用的 Docker Maven 插件。在学习如何使用`docker build`命令构建镜像之后，我们还将使用 Maven 创建我们的镜像。在使用 Maven 构建时，上下文将由 Maven 自动提供给`docker build`命令（或者在这种情况下是一个构建过程）。实际上，根本不需要`Dockerfile`，它将在构建过程中自动创建。我们将在短时间内了解这一点。

`Dockerfile`的标准名称就是`Dockerfile`。它只是一个纯文本文件。根据您使用的 IDE，有插件可以提供 Dockerfile 语法高亮和自动补全，这使得编辑它们变得轻而易举。Dockerfile 指令使用简单明了的语法，使它们非常容易理解、创建和使用。它们被设计为自解释的，特别是因为它们允许像正确编写的应用程序源代码一样进行注释。现在让我们来了解一下`Dockerfile`指令。

# Dockerfile 指令

我们将从每个 Dockerfile 顶部必须具有的指令`FROM`开始。

# FROM

这是 Dockerfile 中的第一条指令。它为文件中接下来的每个后续指令设置基础镜像。`FROM`指令的语法很简单。就是：

`FROM <image>`，或`FROM <image>:<tag>`，或`FROM <image>@<digest>`

`FROM`指令以`tag`或`digest`作为参数。如果您决定跳过它们，Docker 将假定您想要从`latest`标签构建您的镜像。请注意，`latest`并不总是您想要构建的镜像的最新版本。`latest`标签有点特殊。而且它可能不会像您期望的那样工作。总之，除非镜像创建者（例如`openjdk`或`fabric8`）有特定的`build`、`tag`和`push`模式，否则`latest`标签并不意味着任何特殊含义。分配给镜像的`latest`标签只是意味着它是最后构建并执行的镜像，没有提供特定标签。很容易理解，这可能会令人困惑，拉取标记为`latest`的镜像将不会获取软件的最新版本。

当拉取标记为`latest`的镜像时，Docker 不会检查您是否获取了软件的最新版本。

如果 Docker 在构建过程中找不到你提供的标签或摘要，将会抛出错误。你应该明智地选择基础镜像。我的建议是始终优先选择在 Docker Hub 上找到的官方仓库。通过选择官方镜像，你可以相当确信它的质量高，经过测试，得到支持和维护。

对于容器化 Java 应用程序，我们有两个选项。第一个是使用基础 Linux 镜像，并使用`RUN`指令安装 Java（我们将在稍后介绍`RUN`）。第二个选项是拉取已经安装了 Java 运行时的镜像。在这里，你有更多选择。例如：

+   `openjdk`：一个官方仓库，包含了 Java 平台标准版的开源实现。标签`latest`指向了`8u121-alpine` OpenJDK 版本，这是在撰写本书时的最新版本。

+   `fabric8/java-alpine-openjdk8-jdk`：这个基础镜像实际上也被 fabric8 Maven 插件使用。

+   `frolvlad/alpine-oraclejdk8`：有三个标签可供选择：full（只删除源代码 tarballs），cleaned（清理桌面部分），slim（删除除编译器和 JVM 之外的所有内容）。标签 latest 指向了 cleaned 版本。

+   `jeanblanchard/java`：一个包含基于 Alpine Linux 的镜像的仓库，以保持尺寸最小（大约是基于 Ubuntu 的镜像的 25%）。标签`latest`指向了 Oracle Java 8（Server JRE）。

通过在 Docker Hub 上注册并创建账户，你将获得访问 Docker Store 的权限。它可以在[`store.docker.com`](https://store.docker.com)找到。尝试在 Docker Store 中搜索与 Java 相关的镜像。你会找到许多有用的镜像可供选择，其中之一就是官方的 Oracle Java 8 SE（Server JRE）镜像。这个 Docker 镜像提供了 Server JRE，这是专门针对在服务器环境中部署 Java 的运行时环境。Server JRE 包括用于 JVM 监控和服务器应用程序常用的工具。你可以通过在 Docker Store 购买官方 Java Docker 镜像来获取这个官方 Java Docker 镜像。点击获取内容，价格为$0.00，因此可以免费用于开发目的。

请注意，来自 Docker Store 的镜像与您的 Docker Hub 帐户绑定。在拉取它们或构建以它们为基础镜像的自己的镜像之前，您需要使用 `docker login` 命令和您的 Docker Hub 凭据对 Docker Store 进行身份验证。

为了我们的目的，让我们选择 `jeanblanchard/java`。这是官方的 Oracle Java 运行在 Alpine Linux 发行版之上。基础镜像小巧且下载速度快。我们的 `FROM` 指令将与此相同：

```
FROM jeanblanchard/java:8

```

如果在您的 Docker 主机上（例如在您的本地计算机上）找不到 `FROM` 镜像，Docker 将尝试从 Docker Hub（或者如果您已经设置了私有仓库，则从私有仓库）中找到并拉取它。`Dockerfile` 中的所有后续指令将使用 `FROM` 中指定的镜像作为基础起点。这就是为什么它是强制性的；一个有效的 `Dockerfile` 必须在顶部有它。

# MAINTAINER

通过使用 `MAINTAINER` 指令，您可以设置生成的镜像的 `Author` 字段。这可以是您的姓名、用户名，或者您希望作为您正在编写的 `Dockerfile` 创建的镜像的作者。这个命令可以放在 `Dockerfile` 的任何位置，但最好的做法是将其放在文件顶部，在 `FROM` 指令之后。这是一个所谓的非执行命令，意味着它不会对生成的镜像进行任何更改。语法非常简单：

```
MAINTAINER authors_name

```

# WORKDIR

`WORKDIR` 指令为 Dockerfile 中在它之后出现的任何 `CMD` 、`RUN` 、`ENTRYPOINT` 、`COPY` 和 `ADD` 指令添加一个工作目录。该指令的语法是 `WORKDIR /PATH`。如果提供了相对路径，可以在一个 Dockerfile 中有多个 `WORKDIR` 指令；它将相对于前一个 `WORKDIR` 指令的路径。

# ADD

`ADD` 的基本作用是将文件从源复制到容器自己的文件系统中的所需目的地。它接受两个参数：源（`<source path or URL>`）和目的地（`<destination path>`）：

```
ADD <source path or URL> <destination path >

```

源可以有两种形式：它可以是文件、目录或 URL 的路径。路径是相对于构建过程将要启动的目录（我们之前提到的构建上下文）的。这意味着您不能将例如 `"../../config.json"` 放置为 `ADD` 指令的源路径参数。

源路径和目标路径可以包含通配符。这些与常规文件系统中的通配符相同：`*`表示任何文本字符串，`?`表示任何单个字符。

例如，`ADD target/*.jar /`将所有以`.jar`结尾的文件添加到镜像文件系统的根目录中。

如果需要，可以指定多个源路径，并用逗号分隔。它们都必须相对于构建上下文，就像只有一个源路径一样。如果您的源路径或目标路径包含空格，您需要使用特殊的语法，添加方括号：

`ADD ["<source path or URL>" "<destination path>"]`

如果源路径不以斜杠结尾，它将被视为单个文件，并且只会被复制到目标路径中。如果源路径以斜杠结尾，它将被视为目录：然后将其整个内容复制到目标路径中，但目录本身不会在目标路径中创建。因此，可以看到，当向镜像添加文件或目录时，斜杠`/`非常重要。如果源路径指向常见格式（如 ZIP、TAR 等）的压缩存档，它将被解压缩到目标路径中。Docker 不是通过文件名来识别存档，而是检查文件的内容。

如果存档损坏或者以其他方式无法被 Docker 读取，它将不会被解压缩，也不会给出错误消息。文件将被复制到目标路径中。

相同的尾部斜杠规则适用于目标路径；如果以斜杠结尾，表示它是一个目录。否则，它将被视为单个文件。这在构建镜像的文件系统内容时为您提供了很大的灵活性；您可以将文件添加到目录中，将文件添加为单个文件（使用相同或不同的名称），或者只添加整个目录。

`ADD` 命令不仅仅是从本地文件系统复制文件，您还可以使用它从网络获取文件。如果源是一个 URL，那么 URL 的内容将自动下载并放置在目标位置。请注意，从网络下载的文件存档将不会被解压缩。再次强调，当下载文件时，尾部的斜杠很重要；如果目标路径以斜杠结尾，文件将被下载到该目录中。否则，下载的文件将只是保存在您提供的目标路径下的名称。

`<destination directory>` 可以是绝对路径，也可以是相对于 `WORKDIR` 指令指定的目录的路径（我们将在稍后介绍）。源（或多个源）将被复制到指定的目标位置。例如：

+   `ADD config.json projectRoot/` 将把 `config.json` 文件添加到 `<WORKDIR>/projectRoot/` 中

+   `ADD config.json /absoluteDirectory/` 将把 `config.json` 文件添加到 `/absoluteDirectory/` 中

关于镜像中创建的文件的所有权，它们将始终以用户 ID（`UID`）`0` 和组 ID（`GID`）`0` 创建。权限将与源文件相同，除非它是从远程 URL 下载的文件：在这种情况下，它将获得权限值 `600`（只有所有者可以读写该文件）。如果您需要更改这些值（所有权或权限），您需要在 `ADD` 指令之后在您的 Dockerfile 中提供更多的指令。

如果您需要添加到镜像的文件位于需要身份验证的 URL 上，`ADD` 指令将无法工作。您需要使用 shell 命令来下载文件，比如 `wget` 或 `curl`。

请注意，如果您不需要其特殊功能，比如解压缩存档，就不应该使用 `ADD`，而应该使用 `COPY`。

# COPY

`COPY` 指令将从 `<source path>` 复制新文件或目录，并将它们添加到容器的文件系统中的路径 `<destination path>`。

它与 `ADD` 指令非常相似，甚至语法也没有区别：

```
COPY <source path or URL> <destination path >

```

`COPY` 也适用于 `ADD` 的所有规则：所有源路径必须相对于构建的上下文。再次强调，源路径和目标路径末尾的斜杠的存在很重要：如果存在，路径将被视为文件；否则，它将被视为目录。

当然，就像`ADD`一样，你可以有多个源路径。如果源路径或目标路径包含空格，你需要用方括号括起来：

```
COPY ["<source path or URL>" "<destination path>"]

```

`<destination path>`是一个绝对路径（如果以斜杠开头），或者是相对于`WORKDIR`指令指定的路径的路径。

正如你所看到的，`COPY`的功能与`ADD`指令几乎相同，只有一个区别。`COPY`仅支持将本地文件基本复制到容器中。另一方面，`ADD`提供了一些更多的功能，比如归档解压、通过 URL 下载文件等。Docker 的最佳实践建议，如果你不需要`ADD`的这些附加功能，应该优先使用`COPY`。由于`COPY`命令的透明性，`Dockerfile`将更清洁、更易于理解。

`ADD`和`COPY`指令有一个共同的重要方面，即缓存。基本上，Docker 在构建过程中缓存进入镜像的文件。镜像中文件或文件的内容被检查，并为每个文件计算校验和。在缓存查找期间，校验和与现有镜像中的校验和进行比较。如果文件的内容和元数据发生了变化，缓存就会失效。否则，如果源文件没有发生变化，现有的镜像层就会被重用。

如果你有多个 Dockerfile 步骤使用来自你的上下文的不同文件，单独`COPY`它们，而不是一次性全部复制。这将确保每个步骤的构建缓存只有在特定所需文件发生变化时才会失效（强制步骤重新运行）。

正如你所看到的，`COPY`指令的语法和行为几乎与`ADD`指令相同，但它们的功能集有些不同。对于不需要`ADD`功能的归档解压或从 URL 获取文件的文件和目录，你应该始终使用`COPY`。

# 运行

`RUN`指令是`Dockerfile`的中心执行指令。实质上，`RUN`指令将在当前镜像的新层上执行一个命令（或多个命令），然后提交结果。生成的提交镜像将作为`Dockerfile`中下一条指令的基础。正如你从第一章中记得的，*Docker 简介*，分层是 Docker 的核心概念。`RUN`以命令作为其参数，并运行它以创建新的层。

这也意味着`COPY`和`ENTRYPOINT`设置的参数可以在运行时被覆盖，所以如果你在启动容器后没有改变任何东西，结果将始终相同。然而，`RUN`将在构建时执行，无论你在运行时做什么，其效果都会存在。

为了使你的 Dockerfile 更易读和更易维护，你可以将长或复杂的`RUN`语句拆分成多行，用反斜杠分隔它们。

`Dockerfile`中的`RUN`命令将按照它们在其中出现的顺序执行。

每个`RUN`指令在镜像中创建一个新的层。

正如你已经从第一章中了解的那样，*Docker 简介*，层被 Docker 缓存和重用。在下一次构建期间，`RUN`指令的缓存不会自动失效。例如，`RUN apt-get upgrade -y`的指令的缓存将在下一次构建中被重用。缓存为什么重要？在大多数情况下，缓存非常有用，可以节省大量构建镜像的时间。它使构建新容器变得非常快速。然而，需要警惕。有时缓存可能会带来意外的结果。在构建过程中，缓存被大量使用，当你希望`RUN`命令的更新输出进入新容器时，可能会出现问题。如果`RUN`命令在两次构建之间没有改变，Docker 的缓存将不会失效。实际上，Docker 将重用缓存中的先前结果。这显然是有害的。想象一种情况，当你使用`RUN`命令从 Git 仓库中拉取源代码时，通过使用`git clone`作为构建镜像的第一步。

当 Docker 缓存需要失效时要注意，否则你将在镜像构建中得到意外的结果。

这就是为什么知道如何选择性地使缓存失效很重要。在 Docker 世界中，这被称为缓存破坏。

考虑以下示例。`RUN`最常见的用例可能是`apt-get`的应用，它是 Ubuntu 上用于下载软件包的包管理器命令。假设我们有以下 Dockerfile，安装 Java 运行时：

```
FROM ubuntu 
RUN apt-get update 
RUN apt-get install -y openjdk-8-jre 

```

如果我们从这个`Dockerfile`构建一个镜像，两个`RUN`指令的所有层将被放入层缓存中。但是，过了一会儿，您决定在镜像中加入`node.js`包，所以现在`Dockerfile`看起来和这样一样：

```
FROM ubuntu 
RUN apt-get update 
RUN apt-get install -y openjdk-8-jre 
RUN apt-get install -y nodejs 

```

如果您第二次运行`docker build`，Docker 将通过从缓存中获取它们来重用层。因此，`apt-get update`将不会被执行，因为将使用缓存的版本。实际上，您新创建的镜像可能会有`java`和`node.js`包的过时版本。在创建`RUN`指令时，您应该始终牢记缓存的概念。在我们的例子中，我们应该始终将`RUN apt-get update`与`apt-get install`结合在同一个`RUN`语句中，这将创建一个单独的层；例如：

```
RUN apt-get update \

&& apt-get install -y openjdk-8-jre \

&& apt-get install -y nodejs \

&& apt-get clean

```

比这更好的是，您还可以使用一种称为“版本固定”的技术来避免缓存问题。这只是为要安装的包提供一个具体的版本。

# CMD

`CMD`指令的目的是为执行容器提供默认值。您可以将`CMD`指令视为镜像的起点，当容器稍后运行时。这可以是一个可执行文件，或者，如果您指定了`ENTRYPOINT`指令（我们将在下面解释），您可以省略可执行文件，只提供默认参数。`CMD`指令的语法可以有两种形式：

+   `CMD ["executable","parameter1","parameter2"]`：这是所谓的`exec`形式。这也是首选和推荐的形式。参数是 JSON 数组，它们需要用方括号括起来。重要的一点是，当容器运行时，`exec`形式不会调用命令 shell。它只是运行提供的可执行文件作为第一个参数。如果`Dockerfile`中存在`ENTRYPOINT`指令，`CMD`为`ENTRYPOINT`指令提供了一组默认参数。

+   `CMD command parameter1 parameter2`：这是指令的 shell 形式。这次，shell（如果存在于镜像中）将处理提供的命令。指定的二进制文件将使用`/bin/sh -c`调用 shell 来执行。这意味着，如果您使用`CMD echo $HOSTNAME`来显示容器的主机名，您应该使用指令的 shell 形式。

我们之前说过，`CMD`指令的推荐形式是`exec`形式。原因在于：通过 shell 启动的所有内容都将作为`/bin/sh -c`的子命令启动，这不会传递信号。这意味着可执行文件不会成为容器的 PID 1，并且不会接收 Unix 信号，因此您的可执行文件将无法接收来自`docker stop <container>`的`SIGTERM`。还有另一个缺点：您将需要在容器中使用 shell。如果您正在构建一个最小的镜像，它不需要包含 shell 二进制文件。使用 shell 形式的`CMD`指令将会简单失败。

当 Docker 执行命令时，它不会检查容器内是否有 shell 可用。如果镜像中没有`/bin/sh`，容器将无法启动。

另一方面，如果我们将`CMD`更改为`exec`形式，Docker 将寻找一个名为`echo`的可执行文件，这当然会失败，因为`echo`是一个 shell 命令。

因为`CMD`在运行容器时与 Docker 引擎的起点相同，Dockerfile 中只能有一个单独的`CMD`指令。

如果在 Dockerfile 中有多个`CMD`指令，只有最后一个会生效。

您可能会注意到`CMD`指令与`RUN`非常相似。它们都可以运行任何命令（或应用程序）。但有一个重要的区别：执行时间。通过`RUN`指令提供的命令在构建时执行，而通过`CMD`指令指定的命令在通过`docker run`在新创建的镜像上启动容器时执行。与`CMD`不同，`RUN`指令实际上用于构建镜像，通过在之前的层上创建一个新的层来提交。

`RUN`是一个构建时指令，`CMD`是一个运行时指令。

信不信由你，我们现在可以将我们的 REST 示例微服务容器化。让我们通过在第四章中创建的`pom.xml`文件上执行`mvn clean install`来检查它是否构建成功，*创建 Java 微服务*。构建成功后，我们应该有一个包含`rest-example-0.1.0.jar`文件的`target`目录。`target`目录中的 Spring Boot 应用程序 JAR 是一个可执行的、厚重的 JAR。我们将从 Docker 容器内运行它。让我们编写基本的`Dockerfile`，使用我们已经知道的命令，并将其放在我们项目的根目录（这将是我们`docker build`命令的上下文）：

```
FROM jeanblanchard/java:8

COPY target/rest-example-0.1.0.jar rest-example-0.1.0.jar

CMD java -jar rest-example-0.1.0.jar

```

现在我们可以运行`docker build`命令，使用`rest-example`作为镜像名称，省略标签（你会记得，在构建镜像时省略标签会导致创建`latest`标签）：

```
$ docker build . -t rest-example

```

作为第一个参数的点指定了`docker build`命令的上下文。在我们的情况下，它将只是我们小微服务的根目录。在构建过程中，Docker 将输出所有的步骤和层 ID。请注意，几乎每个`Dockerfile`指令都会创建一个新的层。如果你还记得第一章，*Docker 简介*，Docker 利用了层缓存。如果特定的层可以被重用，它将从缓存中取出。这极大地提高了构建过程的性能。最后，Docker 将输出新创建的镜像的 ID，如下截图所示：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-k8s-java-dev/img/Image00068.jpg)

镜像已经创建，所以应该可以运行。要列出镜像，执行以下 Docker 命令：

```
$ docker image ls

```

如下截图所示，我们的`rest-example`镜像已经准备好可以运行了：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-k8s-java-dev/img/Image00069.jpg)

到目前为止，一切都很顺利。我们已经构建了我们的镜像的基本形式。虽然运行镜像的过程是第六章的主题，*使用 Java 应用程序运行容器*，让我们现在快速运行它来证明它正在工作。要运行镜像，执行以下命令：

```
$ docker run -it rest-example

```

过一会儿，你应该会看到熟悉的 Spring Boot 横幅，这表明我们的服务是从 Docker 容器内部运行的：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-k8s-java-dev/img/Image00070.jpg)

这并不是很复杂，对吧？基本的`Dockerfile`只包含三行，使用`FROM`定义基础镜像，使用`COPY`将可执行的 jar 传输到镜像的文件系统中，以及使用`CMD`指令来运行服务。

使用 Maven 构建应用程序 jar 存档，然后使用 Dockerfile 的`COPY`指令进行复制就可以了。那么，将构建过程委托给 Docker 守护进程本身呢？嗯，我们可以使用我们已经知道的`Dockerfile`指令来做到这一点。使用 Docker 守护进程构建 Java 应用程序的缺点是镜像将包含所有的 JDK（包括 Java 编译器）、Maven 二进制文件和我们的应用程序源代码。我建议构建一个单一的构件（JAR 或 WAR 文件），进行彻底的测试（使用面向发布的 QA 周期），并将唯一的构件（当然还有它的依赖项）部署到目标机器上。然而，为了了解`Dockerfile`可能实现的功能，让我们看看以下示例，假设我们的应用程序代码在本地磁盘上的`/app`文件夹中：

```
FROM java:8 

RUN apt-get update

RUN apt-get install -y maven

WORKDIR /app

COPY pom.xml /app/pom.xml

COPY src /app/src

RUN ["mvn", "package"]

CMD ["/usr/lib/jvm/java-8-openjdk-amd64/bin/java", 

"-jar", "target/ rest-example-0.1.0.jar"]

```

在前面的例子中，Maven 构建过程将由 Docker 执行。我们只需运行`apt-get`命令来安装 Maven，将我们的应用程序源代码添加到镜像中，执行 Maven 的`package`命令，然后运行我们的服务。它的行为将与我们将已构建的构件复制到镜像文件系统中完全相同。

有一个 Dockerfile 指令与`CMD`指令有点相关：`ENTRYPOINT`。现在让我们来看看它。

# ENTRYPOINT

官方的 Docker 文档说`ENTRYPOINT`指令允许您配置一个将作为可执行文件运行的容器。至少在第一次使用时，这并不是很清楚。`ENTRYPOINT`指令与`CMD`指令有关。实际上，起初可能会有些混淆。其原因很简单：`CMD`首先开发，然后为了更多的定制开发了`ENTRYPOINT`，这两个指令之间的一些功能重叠。让我们解释一下。`ENTRYPOINT`指定容器启动时将始终执行的命令。另一方面，`CMD`指定将传递给`ENTRYPOINT`的参数。Docker 有一个默认的`ENTRYPOINT`，即`/bin/sh -c`，但没有默认的`CMD`。例如，考虑这个 Docker 命令：

```
docker run ubuntu "echo" "hello world"

```

在这种情况下，镜像将是最新的`ubuntu`，`ENTRYPOINT`将是默认的`/bin/sh -c`，传递给`ENTRYPOINT`的命令将是`echo "hello world"`。

`ENTRYPOINT`指令的语法可以有两种形式，类似于`CMD`。

`ENTRYPOINT ["executable", "parameter1", "parameter2"]`是`exec`形式，首选和推荐。与`CMD`指令的`exec`形式一样，这不会调用命令 shell。这意味着不会发生正常的 shell 处理。例如，`ENTRYPOINT [ "echo", "$HOSTNAME" ]`将不会对`$HOSTNAME`变量进行变量替换。如果您需要 shell 处理，那么您需要使用 shell 形式或直接执行 shell。例如：

```
ENTRYPOINT [ "sh", "-c", "echo $HOSTNAME" ]

```

在 Dockerfile 中使用`ENV`定义的变量（我们稍后会介绍），将被 Dockerfile 解析器替换。

`ENTRYPOINT command parameter1 parameter2`是一个 shell 形式。将发生正常的 shell 处理。这种形式还将忽略任何`CMD`或`docker run`命令行参数。此外，您的命令将不会成为 PID 1，因为它将由 shell 执行。因此，如果您然后运行`docker stop <container>`，容器将无法干净地退出，并且在超时后停止命令将被迫发送`SIGKILL`。

与`CMD`指令一样，Dockerfile 中的最后一个`ENTRYPOINT`指令才会生效。在 Dockerfile 中覆盖`ENTRYPOINT`允许您在运行容器时有不同的命令处理您的参数。如果您需要更改图像中的默认 shell，可以通过更改`ENTRYPOINT`来实现：

```
FROM ubuntu 

ENTRYPOINT ["/bin/bash"]

```

从现在开始，所有来自`CMD`的参数，或者在使用`docker run`启动容器时提供的参数，将由 Bash shell 处理，而不是默认的`/bin/sh -c`。

考虑这个基于 BusyBox 的简单`Dockerfile`。BusyBox 是一个软件，它在一个可执行文件中提供了几个精简的 Unix 工具。为了演示`ENTRYPOINT`，我们将使用 BusyBox 中的`ping`命令：

```
FROM busybox 

ENTRYPOINT ["/bin/ping"] 

CMD ["localhost"]

```

让我们使用先前的 Dockerfile 构建镜像，执行以下命令：

```
$ docker build -t ping-example .

```

如果现在使用`ping`镜像运行容器，`ENTRYPOINT`指令将处理提供的`CMD`参数：在我们的情况下，默认情况下将是`localhost`。让我们运行它，使用以下命令：

```
$ docker run ping-example

```

因此，您将得到一个`/bin/ping localhost`的命令行响应，如您在以下截图中所见：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-k8s-java-dev/img/Image00071.jpg)

`CMD`指令，正如你从描述中记得的那样，设置了默认命令和/或参数，当你运行容器时，可以从命令行覆盖它们。`ENTRYPOINT`不同，它的命令和参数不能被命令行覆盖。相反，所有命令行参数将被附加到`ENTRYPOINT`参数之后。这样你可以锁定在容器启动时始终执行的命令。

与`CMD`参数不同，当 Docker 容器使用命令行参数运行时，`ENTRYPOINT`命令和参数不会被忽略。

因为命令行参数将被附加到`ENTRYPOINT`参数，我们可以通过传递给`ENTRYPOINT`的不同参数来运行我们的`ping`镜像。让我们尝试一下，通过使用不同的输入来运行我们的 ping 示例：

```
$ docker run ping-example www.google.com

```

这次它的行为会有所不同。提供的参数值`www.google.com`将被附加到`ENTRYPOINT`，而不是 Dockerfile 中提供的默认`CMD`值。将执行的总命令行将是`/bin/ping www.google.com`，如你在下面的截图中所见：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-k8s-java-dev/img/Image00072.jpg)您可以使用`exec`形式的`ENTRYPOINT`来设置相当稳定的默认命令和参数，然后使用`CMD`的任一形式来设置更有可能被更改的附加默认值。

有了`ENTRYPOINT`指令，我们就有了很多的灵活性。最后但并非最不重要的是，当使用`docker run`命令的`--entrypoint`参数启动容器时，`ENTRYPOINT`也可以被覆盖。请注意，你可以使用`--entrypoint`来覆盖`ENTRYPOINT`设置，但这只能设置要执行的二进制文件（不会使用`sh -c`）。正如你所见，`CMD`和`ENTRYPOINT`指令都定义了在运行容器时执行的命令。让我们总结一下我们对它们之间的区别和合作所学到的内容：

+   一个 Dockerfile 应该指定至少一个`CMD`或`ENTRYPOINT`指令

+   Dockerfile 中只有最后一个`CMD`和`ENTRYPOINT`将被使用

+   在使用容器作为可执行文件时，应该定义`ENTRYPOINT`

+   你应该使用`CMD`指令来定义作为`ENTRYPOINT`定义的命令的默认参数，或者在容器中执行`ad-hoc`命令的方式

+   当使用替代参数运行容器时，`CMD`将被覆盖

+   `ENTRYPOINT`设置了每次使用该镜像创建容器时使用的具体默认应用程序。

+   如果你将`ENTRYPOINT`与`CMD`配对，你可以从`CMD`中删除一个可执行文件，只留下它的参数，这些参数将传递给`ENTRYPOINT`。

+   `ENTRYPOINT`的最佳用法是设置镜像的主要命令，允许该镜像像执行该命令一样运行（然后使用`CMD`作为默认标志）。

我们的服务运行正常，但并不是很有用。首先，启动它涉及许多手动步骤，这就是为什么我们将在本章后面使用 Maven 自动化它。其次，正如你会记得的，我们的服务监听着端口号为 8080 的 HTTP 请求。我们的基本镜像运行了，但没有暴露任何网络端口，因此没有人和没有东西可以访问该服务。让我们继续学习有关剩余的 Dockerfile 指令来修复它。

# EXPOSE

`EXPOSE`指令通知 Docker 容器在运行时监听指定的网络端口。我们已经在第二章中提到了`EXPOSE`指令，*网络和持久存储*。正如你会记得的，Dockerfile 中的`EXPOSE`相当于`--expose`命令行选项。Docker 使用`EXPOSE`命令后跟端口号来允许流入的流量到达容器。我们已经知道`EXPOSE`不会自动使容器的端口在主机上可访问。要做到这一点，你必须使用`-p`标志来发布一系列端口，或者使用`-P`标志一次发布所有暴露的端口。

让我们回到我们的`Dockerfile`并暴露一个端口：

```
FROM jeanblanchard/java:8

COPY target/rest-example-0.1.0.jar rest-example-0.1.0.jar

CMD java -jar rest-example-0.1.0.jar

EXPOSE 8080

```

如果你现在使用相同的命令重新构建镜像，`docker build . -t rest-example`，你会注意到 Docker 输出了第四层，表示端口 8080 已经被暴露。暴露的端口将对此 Docker 主机上的其他容器可用，并且如果在运行时映射它们，也对外部世界可用。好吧，让我们尝试一下，使用以下`docker run`命令：

```
$ docker run -p 8080:8080 -it rest-example

```

如果您现在使用`HTTP`请求调用本地主机，比如`POST`（用于保存我们的图书实体）或`GET`（用于获取图书列表或单本图书），就像我们在第四章中所做的那样，*创建 Java 微服务*，使用任何 HTTP 工具，比如 HTTPie 或 Postman，它将像以前一样做出响应。但是，这一次是来自 Docker 容器。现在，这是一件了不起的事情。让我们了解剩下的重要的 Dockerfile 指令。

# VOLUME

正如您在第一章中所记得的，*Docker 简介*，容器文件系统默认是临时的。如果您启动 Docker 镜像（即运行容器），您将得到一个读写层，该层位于堆栈的顶部。您可以随意创建，修改和删除文件，然后提交该层以保留更改。在第二章中，*网络和持久存储*，我们已经学会了如何创建卷，这是一种很好的存储和检索数据的方法。我们可以在`Dockerfile`中使用`VOLUME`指令做同样的事情。

语法再简单不过了：就是`VOLUME ["/volumeName"]`。

`VOLUME`的参数可以是 JSON 数组，也可以是一个带有一个或多个参数的普通字符串。例如：

```
VOLUME ["/var/lib/tomcat8/webapps/"]

VOLUME /var/log/mongodb /var/log/tomcat

```

`VOLUME`指令创建一个具有指定名称的挂载点，并将其标记为包含来自本机主机或其他容器的外部挂载卷。

`VOLUME`命令将在容器内部挂载一个目录，并将在该目录内创建或编辑的任何文件存储在容器文件结构之外的主机磁盘上。在`Dockerfile`中使用`VOLUME`让 Docker 知道某个目录包含永久数据。Docker 将为该数据创建一个卷，并且即使删除使用它的所有容器，也不会删除它。它还绕过了联合文件系统，因此该卷实际上是一个实际的目录，它会在所有共享它的容器中（例如，如果它们使用`--volumes-from`选项启动）以正确的方式挂载，无论是读写还是只读。要理解`VOLUME`，让我们看一个简单的 Dockerfile：

```
FROM ubuntu 

VOLUME /var/myVolume

```

如果您现在运行容器并在`/var/myVolume`中保存一些文件，它们将可供其他容器共享。

基本上，`VOLUME`和`-v`几乎是相等的。`VOLUME`和`-v`之间的区别在于，您可以在执行`docker run`启动容器时动态使用`-v`并将您的`host`目录挂载到容器上。这样做的原因是 Dockerfile 旨在具有可移植性和共享性。主机目录卷是 100%依赖于主机的，并且在任何其他机器上都会出现问题，这与 Docker 的理念有些不符。因此，在 Dockerfile 中只能使用可移植指令。

`VOLUME`和`-v`之间的根本区别在于：`-v`会将操作系统中现有的文件挂载到 Docker 容器内，而`VOLUME`会在主机上创建一个新的空卷，并将其挂载到容器内。

# LABEL

为了向我们的镜像添加元数据，我们使用`LABEL`指令。单个标签是一个键值对。如果标签值中需要有空格，您需要用引号将其包裹起来。标签是可累加的，它们包括从作为您自己镜像基础的镜像（`FROM`指令中的镜像）中获取的所有标签。如果 Docker 遇到已经存在的标签，它将用新值覆盖具有相同键的标签。在定义标签时，有一些规则必须遵守：键只能由小写字母数字字符、点和破折号组成，并且必须以字母数字字符开头和结尾。为了防止命名冲突，Docker 建议使用反向域表示法为标签键使用命名空间。另一方面，没有命名空间（点）的键保留供命令行使用。

`LABEL`指令的语法很简单：

```
LABEL "key"="value"

```

要使用多行值，请使用反斜杠将行分隔开；例如：

```
LABEL description="This is my \

multiline description of the software."

```

您可以在单个镜像中拥有多个标签。用空格或反斜杠分隔它们；例如：

```
LABEL key1="value1" key2="value2" key3="value3"

LABEL key1="value1" \

key2="value2" \

key3="value3"

```

实际上，如果您的镜像中需要有多个标签，建议使用`LABEL`指令的多标签形式，因为这样会在镜像中只产生一个额外的层。

每个`LABEL`指令都会创建一个新的层。如果您的镜像有很多标签，请使用单个`LABEL`指令的多重形式。

如果您想要查看镜像具有哪些标签，可以使用您已经在之前章节中了解过的`docker inspect`命令。

# ENV

`ENV`是一个`Dockerfile`指令，它将环境变量`<key>`设置为值`<value>`。您可以有两种选项来使用`ENV`：

+   第一个，`ENV <key> <value>` ，将一个单一变量设置为一个值。第一个空格后的整个字符串将被视为 `<value>` 。这将包括任何字符，还有空格和引号。例如：

```
ENV JAVA_HOME /var/lib/java8

```

+   第二个，带有等号的是 `ENV <key>=<value>` 。这种形式允许一次设置多个环境变量。如果需要在值中提供空格，您需要使用引号。如果需要在值中使用引号，使用反斜杠：

```
ENV CONFIG_TYPE=file CONFIG_LOCATION="home/Jarek/my \app/config.json"

```

请注意，您可以使用 `ENV` 更新 `PATH` 环境变量，然后 `CMD` 参数将意识到该设置。这将导致 `Dockerfile` 中 `CMD` 参数的更清晰形式。例如，设置如下：

```
ENV PATH /var/lib/tomcat8/bin:$PATH

```

这将确保 `CMD ["startup.sh"]` 起作用，因为它将在系统 `PATH` 中找到 `startup.sh` 文件。您还可以使用 `ENV` 设置经常修改的版本号，以便更容易处理升级，如下例所示：

```
ENV TOMCAT_VERSION_MAJOR 8

ENV TOMCAT_VERSION 8.5.4

RUN curl -SL http://apache.uib.no/tomcat/tomcat-$TOMCAT_VERSION_MAJOR/v$TOMCAT_VERSION/bin/apache-tomcat-$TOMCAT_VERSION.tar.gz | tar zxvf apache-tomcat-$TOMCAT_VERSION.tar.gz -c /usr/Jarek/apache-tomcat-$TOMCAT_VERSION

ENV PATH /usr/Jarek/apache-tomcat-$TOMCAT_VERSION/bin:$PATH

```

在上一个示例中，Docker 将下载 `ENV` 变量中指定的 Tomcat 版本，将其提取到具有该版本名称的新目录中，并设置系统 `PATH` 以使其可用于运行。

使用 `ENV` 设置的环境变量将在从生成的镜像运行容器时持续存在。与使用 `LABEL` 创建的标签一样，您可以使用 `docker inspect` 命令查看 `ENV` 值。`ENV` 值也可以在容器启动之前使用 `docker run --env <key>=<value>` 覆盖。

# USER

`USER` 指令设置运行镜像时要使用的用户名或 UID。它将影响 `Dockerfile` 中接下来的任何 `RUN` 、`CMD` 和 `ENTRYPOINT` 指令的用户。

指令的语法只是 `USER <用户名或 UID>` ；例如：

```
USER tomcat

```

如果可执行文件可以在没有特权的情况下运行，可以使用 `USER` 命令。Dockerfile 可以包含与此相同的用户和组创建指令：

```
RUN groupadd -r tomcat && useradd -r -g tomcat tomcat

```

频繁切换用户将增加生成镜像中的层数，并使 Dockerfile 更加复杂。

# ARG

`ARG` 指令用于在 `docker build` 命令期间向 Docker 守护程序传递参数。`ARG` 变量定义从 `Dockerfile` 中定义的行开始生效。通过使用 `--build-arg` 开关，您可以为已定义的变量分配一个值：

```
$ docker build --build-arg <variable name>=<value> .

```

从`--build-arg`中的值将传递给构建图像的守护程序。您可以使用多个`ARG`指令指定多个参数。如果您指定了未使用`ARG`定义的构建时间参数，构建将失败并显示错误，但可以在`Dockerfile`中指定默认值。您可以通过以下方式指定默认参数值：

```
FROM ubuntu 

ARG user=jarek

```

如果在开始构建之前未指定任何参数，则将使用默认值：

不建议使用`ARG`传递秘密，如 GitHub 密钥、用户凭据、密码等，因为所有这些都将通过使用`docker history`命令对图像的任何用户可见！

# ONBUILD

`ONBUILD`指令指定了另一个指令，当使用此图像作为其基础图像构建其他图像时将触发该指令。换句话说，`ONBUILD`指令是父`Dockerfile`给子`Dockerfile`（下游构建）的指令。任何构建指令都可以注册为触发器，并且这些指令将在`Dockerfile`中的`FROM`指令之后立即触发。

`ONBUILD`指令的语法如下：

```
ONBUILD <INSTRUCTION>

```

在其中，`<INSTRUCTION>`是另一个 Dockerfile 构建指令，稍后将在构建子图像时触发。有一些限制：`ONBUILD`指令不允许链接另一个`ONBUILD`指令，也不允许`FROM`和`MAINTAINER`指令作为`ONBUILD`触发器。

这在构建将用作基础构建其他图像的图像时非常有用。例如，应用程序构建环境或可能使用用户特定配置进行定制的守护程序。`ONBUILD`指令非常有用（[`docs.docker.com/engine/reference/builder/#onbuild`](https://docs.docker.com/engine/reference/builder/#onbuild)和[`docs.docker.com/engine/reference/builder/#maintainer-deprecated`](https://docs.docker.com/engine/reference/builder/#maintainer-deprecated)），用于自动构建所选软件堆栈。考虑以下使用 Maven 构建 Java 应用程序的示例（是的，Maven 也可以作为 Docker 容器使用）。基本上，您项目的 Dockerfile 只需要引用包含`ONBUILD`指令的基础容器即可：

```
 FROM maven:3.3-jdk-8-onbuild 

 CMD ["java","-jar","/usr/src/app/target/app-1.0-SNAPSHOT-jar-with-dependencies.jar"] 

```

没有魔法，如果您查看父级的 Dockerfile，一切都会变得清晰。在我们的情况下，它将是 GitHub 上可用的`docker-maven` Dockerfile：

```
 FROM maven:3-jdk-8

RUN mkdir -p /usr/src/app

WORKDIR /usr/src/app

ONBUILD ADD . /usr/src/app

ONBUILD RUN mvn install 

```

有一个基础镜像，其中安装了 Java 和 Maven，并有一系列指令来复制文件和运行 Maven。

`ONBUILD`指令会向镜像添加一个触发指令，以便在将来作为另一个构建的基础时执行。触发器将在子构建的上下文中执行，就好像它被立即插入到子`Dockerfile`中的`FROM`指令之后一样。

当 Docker 在构建过程中遇到`ONBUILD`指令时，构建器会向正在构建的镜像的元数据中添加一种触发器。但这是影响到该镜像的唯一方式。在构建结束时，所有触发器的列表将存储在镜像清单中，键为`OnBuild`。您可以使用我们已经知道的`docker inspect`命令来查看它们。

稍后，该镜像可以作为新构建的基础，使用`FROM`指令。在处理`FROM`指令时，Docker 构建器会寻找`ONBUILD`触发器，并按照它们注册的顺序执行它们。如果任何触发器失败，`FROM`指令将被中止，这将导致构建失败。如果所有触发器成功，`FROM`指令完成，构建继续进行。

# STOPSIGNAL

要指定应发送哪个系统调用信号以退出容器，请使用`STOPSIGNAL`指令。该信号可以是与内核的`syscall`表中的位置匹配的有效无符号数字，例如`9`，或者是格式为`SIGNAME`的信号名称，例如`SIGKILL`。

# HEALTHCHECK

`HEALTHCHECK`指令可用于通知 Docker 如何测试容器以检查其是否仍在工作。这可以是检查我们的 REST 服务是否响应`HTTP`调用，或者只是监听指定的端口。

容器可以有几种状态，可以使用`docker ps`命令列出。这些可以是`created`，`restarting`，`running`，`paused`，`exited`或`dead`。但有时这还不够；从 Docker 的角度来看，容器可能仍然存活，但应用程序可能会挂起或以其他方式失败。对应用程序状态的额外检查可能很有用，`HEALTHCHECK`非常方便。

`HEALTHCHECK`状态最初为 starting。每当健康检查通过时，它就变为`healthy`（无论之前处于什么状态）。在连续失败一定次数后，它就会变为`unhealthy`。

`HEALTHCHECK`指令的语法如下：

```
HEALTHCHECK --interval=<interval> --timeout=<timeout> CMD <command>

```

`<interval>`（默认值为 30 秒）和`<timeout>`（同样，默认值为 30 秒）是时间值，分别指定检查间隔和超时时间。`<command>`是实际用于检查应用程序是否仍在运行的命令。`<command>`的退出代码被 Docker 用来确定健康检查是失败还是成功。值可以是`0`，表示容器健康并且可以使用，也可以是`1`，表示出现了问题，容器无法正常工作。Java 微服务的`healthcheck`实现可以是一个简单的`/ping` REST 端点，返回任何内容（如时间戳），甚至可以返回一个空响应和`HTTP 200`状态码，证明它还活着。我们的`HEALTHCHECK`可以执行对这个端点的`GET`方法，检查服务是否响应。

```
HEALTHCHECK --interval=5m --timeout=2s --retries=3 CMD curl -f http://localhost/ping || exit 1

```

在上一个示例中，命令`curl -f http://localhost/ping`将每 5 分钟执行一次，最长超时时间为 2 秒。如果检查的单次运行时间超过 2 秒，则认为检查失败。如果连续三次重试失败，容器将获得`unhealthy`状态。

Dockerfile 中只能有一个`HEALTHCHECK`指令。如果列出多个，则只有最后一个`HEALTHCHECK`会生效。

`HEALTHCHECK`指令使您有可能微调容器监控，从而确保容器正常工作。这比仅有`running`、`exited`或`dead`标准 Docker 状态要好。

现在我们已经了解了`Dockerfile`指令，我们准备好准备我们的图像。让我们自动化一些事情。我们将使用 Maven 创建和运行我们的图像。

# 使用 Maven 创建图像

当然，我们可以使用 Docker 本身来构建我们的 Docker 镜像。但这不是 Spring 开发人员的典型用例。对我们来说，典型的用例是使用 Maven。如果你已经设置了持续集成流程，例如使用 Jenkins，这将特别有用。将镜像构建过程委托给 Maven 可以给你很大的灵活性，也可以节省大量时间。目前在 GitHub 上至少有几个免费的 Docker Maven 插件可用，例如：

+   [`github.com/spotify/docker-maven-plugin`](https://github.com/spotify/docker-maven-plugin)：Spotify 提供的用于构建和推送 Docker 镜像的 Maven 插件。

+   [`github.com/alexec/docker-maven-plugin`](https://github.com/alexec/docker-maven-plugin)。

+   [`github.com/fabric8io/docker-maven-plugin`](https://github.com/fabric8io/docker-maven-plugin)：这是我发现最有用和可配置的插件。在撰写本文时，Fabric8 似乎是最健壮的 Maven Docker 插件。Fabric8 是一个集成的开源 DevOps 和集成平台，可以在任何 Kubernetes 或 OpenShift 环境上即插即用，并提供持续交付、管理、ChatOps 和 Chaos Monkey。我们将在本章的其余部分使用这个插件。

我们的用例将使用 Maven 打包 Spring Boot 可执行 JAR 文件，然后将构建产物复制到 Docker 镜像中。使用 Maven 插件来构建 Docker 主要关注两个方面：

+   构建和推送包含构建产物的 Docker 镜像

+   启动和停止 Docker 容器进行集成测试和开发。这是我们将在第六章中专注的内容，*使用 Java 应用程序运行容器*

让我们现在专注于创建一个镜像，从插件目标和可能的配置选项开始。

fabric8 Docker 插件提供了一些 Maven 目标：

+   `docker:build`：这使用 maven-assembly-plugin 的装配描述符格式来指定将从子目录（默认为`/maven`）添加到镜像中的内容

+   `docker:push`：使用此插件构建的镜像可以推送到公共或私有的 Docker 注册表

+   `docker:start`和`docker:stop`：用于启动和停止容器

+   `docker:watch`：这将依次执行`docker:build`和`docker:run`。它可以在后台永远运行（单独的控制台），除非您使用 CTRL+C 停止它。它可以监视装配文件的更改并重新运行构建。这样可以节省很多时间。

+   `docker:remove`：用于清理镜像和容器

+   `docker:logs`：这会打印出正在运行的容器的输出

+   `docker:volume-create`和`docker:volume-remove`：分别用于创建和删除卷。我们将在本章后面再回到这些内容

在我们运行这些目标之前，我们需要告诉插件它应该如何行为。我们在项目的`pom.xml`文件中的插件配置中进行配置：

+   Maven Docker 插件配置

插件定义中的重要部分是`<configuration>`元素。这是您设置插件行为的地方。`<configuration>`中有两个主要元素：

+   指定如何构建镜像的`<build>`配置

+   描述如何创建和启动容器的`<run>`配置

这是`fabric8` Maven 插件的 Docker 的配置的最简单的示例：

```
<plugin>

 <groupId>io.fabric8</groupId>

 <artifactId>docker-maven-plugin</artifactId>

 <version>0.20.1</version>

 <configuration>

 <dockerHost>http://127.0.0.1:2375</dockerHost>

 <verbose>true</verbose>

 <images>

 <image>

 <name>rest-example:${project.version}</name>

 <build>

 <dockerFile>Dockerfile</dockerFile>

 <assembly>

 <descriptorRef>artifact</descriptorRef>

 </assembly>

 </build>

 </image>

 </images>

 </configuration>

</plugin>

```

`<dockerHost>`指定正在运行的 Docker 引擎的 IP 地址和端口，因此，当然，要使其构建，您首先需要运行 Docker。在前面的情况下，如果您从 shell 运行`mvn clean package docker:build`命令，Fabric8 Docker 插件将使用您提供的`Dockerfile`构建镜像。但是还有另一种构建图像的方法，根本不使用`Dockerfile`，至少不是显式定义的。要做到这一点，我们需要稍微更改插件配置。看一下修改后的配置：

```
<configuration>

 <images>

 <image>

 <name>rest-example:${project.version}</name>

 <alias>rest-example</alias>

 <build>

 <from>jeanblanchard/java:8</from>

 <assembly>

 <descriptorRef>artifact</descriptorRef>

 </assembly>

 <cmd>java -jar 

 maven/${project.name}-${project.version}.jar</cmd>

 </build>

 </image>

 </images>

</configuration>

```

正如您所看到的，我们不再提供`Dockerfile`。相反，我们只提供`Dockerfile`指令作为插件配置元素。这非常方便，因为我们不再需要硬编码可执行 jar 名称、版本等。它将从 Maven 构建范围中获取。例如，jar 的名称将被提供给`<cmd>`元素。这将自动导致在`Dockerfile`中生成有效的`CMD`指令。如果我们现在使用`mvn clean package docker:build`命令构建项目，Docker 将使用我们的应用程序构建一个镜像。让我们按字母顺序列出我们可用的配置元素：

| **元素** | **描述** |
| --- | --- |

| `assembly` | `<assembly>` 元素定义了如何构建进入 Docker 镜像的构件和其他文件。您可以使用 `targetDir` 元素提供一个目录，其中包含装配中包含的文件和构件将被复制到镜像中。这个元素的默认值是 `/maven`。在我们的示例中，我们将使用 `<descriptorRef>` 提供预定义装配描述符之一。`<descriptorRef>` 是一种方便的快捷方式，可以取以下值：

+   `artifact-with-dependencies` : 附加项目的构件和所有依赖项。此外，当类路径文件存在于目标目录中时，它将被添加进去。

+   `artifact` : 仅附加项目的构件，而不包括依赖项。

+   `project` : 附加整个 Maven 项目，但不包括 `target/` 目录。

+   `rootWar` : 将构件复制为 `ROOT.war` 到 `exposed` 目录。例如，Tomcat 可以在 `root` 上下文中部署 war 文件。

|

| `buildArgs` | 允许提供一个映射，指定 Docker `buildArgs` 的值，在使用构建参数的外部 Dockerfile 构建镜像时使用。键值语法与定义 Maven 属性（或 `labels` 或 `env`）时相同。 |
| --- | --- |
| `buildOptions` | 一个映射，用于指定构建选项，提供给 Docker 守护程序在构建镜像时使用。 |
| `cleanup` | 这对于在每次构建后清理未标记的镜像很有用（包括从中创建的任何容器）。默认值是 `try`，它尝试删除旧镜像，但如果不可能，例如，镜像仍然被运行中的容器使用，则不会使构建失败。 |
| `cmd` | 这相当于我们已经了解的 `CMD` 指令，用于提供默认执行的命令。 |
| `compression` | 可以取 `none`（默认值）、`gzip` 或 `bzip2` 值。它允许我们指定压缩模式以及构建存档如何传输到 Docker 守护程序（`docker:build`）。 |
| `entryPoint` | 等同于 Dockerfile 中的 `ENTRYPOINT`。 |
| `env` | 等同于 Dockerfile 中的 `ENV`。 |
| `from` | 等同于 Dockerfile 中的 `FROM`，用于指定基础镜像。 |
| `healthCheck` | 等同于 Dockerfile 中的 `HEALTHCHECK`。 |
| `labels` | 用于定义标签，与 Dockerfile 中的 `LABEL` 相同。 |
| `maintainer` | 等同于 Dockerfile 中的 `MAINTAINER`。 |
| `nocache` | 用于禁用 Docker 的构建层缓存。可以通过设置系统属性 `docker.nocache` 来覆盖，当运行 Maven 命令时。 |
| `optimize` | 如果设置为 true，则会将所有 `runCmds` 压缩成单个 `RUN` 指令。强烈建议最小化创建的镜像层的数量。 |
| `ports` | 在 Dockerfile 中的 `EXPOSE` 的等效。这是一个 `<port>` 元素的列表，每个元素表示要暴露的一个端口。格式可以是纯数字，如 `"8080"`，也可以附加协议，如 `"8080/tcp"`。 |
| `runCmds` | 等效于 `RUN`，在构建过程中要运行的命令。它包含要传递给 shell 的 `<run>` 元素。 |
| `tags` | 可以包含一系列 `<tag>` 元素，提供构建后要标记的额外标签。 |
| `user` | 等效于 Dockerfile 中的 `USER`，指定 Dockerfile 应切换到的用户。 |
| `volumes` | 包含一系列 `VOLUME` 等效，一个 `<volume>` 元素的列表，用于创建容器卷。 |
| `workdir` | 与 Dockerfile 中的 `WORKDIR` 等效，表示启动容器时要切换到的目录。 |

如您所见，插件配置非常灵活，包含了 Dockerfile 指令的完整等效集。让我们看看我们的 `pom.xml` 在正确配置下是什么样子。

完整的 `pom.xml`。

如果您从头开始关注我们的项目，完整的 Maven POM 与以下内容相同：

```
 <?xml version="1.0" encoding="UTF-8"?>

    <project   xsi:schemaLocation="http://maven.apache.org/POM/4.0.0 http://maven.apache.org/xsd/maven-4.0.0.xsd">

      <modelVersion>4.0.0</modelVersion>

      <groupId>pl.finsys</groupId>

      <artifactId>rest-example</artifactId>

      <version>0.1.0</version>

      <parent>

        <groupId>org.springframework.boot</groupId>

        <artifactId>spring-boot-starter-

         parent</artifactId>

        <version>1.5.2.RELEASE</version>

      </parent>

      <dependencies>

        <dependency>

          <groupId>org.springframework.boot</groupId>

          <artifactId>spring-boot-starter-web</artifactId>

        </dependency>

        <dependency>

          <groupId>org.springframework.boot</groupId>

          <artifactId>spring-boot-starter-data-

           jpa</artifactId>

        </dependency>

        <dependency>

          <groupId>org.hibernate</groupId>

          <artifactId>hibernate-validator</artifactId>

        </dependency>

        <dependency>

          <groupId>org.hsqldb</groupId>

          <artifactId>hsqldb</artifactId>

          <scope>runtime</scope>

        </dependency>

        <dependency>

          <groupId>io.springfox</groupId>

          <artifactId>springfox-swagger2</artifactId>

          <version>2.6.1</version>

        </dependency>

        <dependency>

          <groupId>io.springfox</groupId>

          <artifactId>springfox-swagger-ui</artifactId>

          <version>2.5.0</version>

        </dependency>

        <!--test dependencies-->

        <dependency>

          <groupId>org.springframework.boot</groupId>

          <artifactId>spring-boot-starter-

           test</artifactId>

          <scope>test</scope>

        </dependency>

        <dependency>

          <groupId>org.springframework.boot</groupId>

          <artifactId>spring-boot-starter-

           test</artifactId>

          <scope>test</scope>

        </dependency>

        <dependency>

          <groupId>com.jayway.jsonpath</groupId>

          <artifactId>json-path</artifactId>

          <scope>test</scope>

        </dependency>

      </dependencies>

      <properties>

        <java.version>1.8</java.version>

      </properties>

      <build>

        <plugins>

          <plugin>

            <groupId>org.springframework.boot</groupId>

            <artifactId>spring-boot-maven-

             plugin</artifactId>

          </plugin>

          <plugin>

            <groupId>org.springframework.boot</groupId>

            <artifactId>spring-boot-maven-

            plugin</artifactId>

          </plugin>

          <plugin>

            <groupId>io.fabric8</groupId>

            <artifactId>docker-maven-plugin</artifactId>

            <version>0.20.1</version>

            <configuration>

              <images>

                <image>

                  <name>rest-example:${project.version}

                  </name>

                  <alias>rest-example</alias>

                  <build>

                    <from>openjdk:latest</from>

                    <assembly>

                      <descriptorRef>artifact</descriptorRef>

                    </assembly>

                    <cmd>java -jar maven/${project.name}-${project.version}.jar</cmd>

                  </build>

                  <run>

                    <wait>

                      <log>Hello World!</log>

                    </wait>

                  </run>

                </image>

              </images>

            </configuration>

          </plugin>

        </plugins>

      </build>

      <repositories>

        <repository>

          <id>spring-releases</id>

          <url>https://repo.spring.io/libs-release</url>

        </repository>

      </repositories>

      <pluginRepositories>

        <pluginRepository>

          <id>spring-releases</id>

          <url>https://repo.spring.io/libs-release</url>

        </pluginRepository>

      </pluginRepositories>

    </project> 

```

# 构建镜像

要使用我们的 Spring Boot 构件构建 Docker 镜像，请运行以下命令：

```
$ mvn clean package docker:build

```

`clean` 告诉 Maven 删除 `target` 目录。Maven 将始终使用 `package` 命令编译您的类。使用 `docker:build` 命令运行 `package` 命令非常重要。如果尝试在两个单独的步骤中运行这些命令，将会遇到错误。在构建 Docker 镜像时，您将在控制台中看到以下输出：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-k8s-java-dev/img/Image00073.jpg)

新镜像的 ID 将显示在控制台输出中。如果您想知道自动生成的 Dockerfile 看起来和什么一样，您可以在项目的 `target/docker/rest-example/0.1.0/build` 目录中找到它。第一次构建此 Docker 镜像时，由于正在下载所有层，所以会花费更长时间。但由于层缓存的原因，每次构建都会快得多。

# 创建和删除卷

Fabric8 Maven Docker 插件如果没有管理卷的可能性，就不可能成为一个完整的解决方案。实际上，它提供了两种处理卷的方式：`docker:volume-create`和`docker:volume-remove`。正如你可能还记得的那样，来自第二章的*网络和持久存储*，Docker 在处理卷和它们的驱动程序时使用了类似插件的架构。`fabric8`插件可以配置为将特定的卷驱动程序及其参数传递给 Docker 守护程序。考虑一下插件配置的以下片段：

```
 <plugin> 

 <configuration> 

    [...] 

    <volumes> 

    <volume> 

    <name>myVolume</name> 

    <driver>local</driver> 

    <opts> 

    <type>tmpfs</type> 

    <device>tmpfs</device> 

    <o>size=100m,uid=1000</o> 

    </opts> 

    <labels> 

    <volatileData>true</volatileData> 

    </labels> 

    </volume> 

    </volumes> 

    </configuration> 

  </plugin> 

```

在上一个例子中，我们使用本地文件系统驱动程序创建了一个命名卷。它可以在容器启动期间挂载，如`pom.xml`文件的`<run>`部分中指定的那样。

# 总结

在本章中，我们看了如何开始使用 Docker 容器和打包 Java 应用程序。我们可以通过手动使用`docker build`命令和`Dockerfile`来手动完成，也可以使用 Maven 来自动化。对于 Java 开发人员，Docker 有助于将我们的应用程序隔离在一个干净的环境中。隔离很重要，因为它减少了我们使用的软件环境的复杂性。Fabric8 Maven Docker 插件是一个很好的工具，我们可以使用它来使用 Maven 自动构建我们的镜像，特别是在处理 Java 应用程序时。不再需要手动编写 Dockerfile，我们只需使用广泛的选项配置插件，就可以完成。此外，使用 Maven 使我们可以轻松地将 Docker 构建纳入我们现有的开发流程中，例如使用 Jenkins 进行持续交付。在第六章中，*使用 Java 应用程序运行容器*，我们将更详细地讨论如何从容器内部运行我们的 Java 应用程序。当然，我们也会使用 Maven 来完成这个过程。


# 第六章：使用 Java 应用程序运行容器

在第五章 *使用 Java 应用程序创建镜像*中，我们学习了 Dockerfile 的结构以及如何构建我们的镜像。在这一点上，您应该能够创建自己的 Docker 镜像并开始使用它。实际上，我们已经多次运行了容器，但没有深入细节。我们手动构建了镜像，使用 Dockerfile，然后发出了`docker build`命令。我们还使用 Maven 来自动化构建过程。我们创建的镜像包含了我们简单的 REST Java 服务。我们已经运行它来检查它是否真的有效。然而，这一次，我们将更详细地讨论从我们的镜像运行容器的一些细节。本章将包括以下概念：

+   启动和停止容器

+   容器运行模式

+   监控容器

+   容器重启策略

+   资源的运行时约束

+   使用 Maven 运行容器

# 启动和停止容器

让我们回到一点，从基础知识开始：如何手动从 shell 或命令行运行和停止 Docker 容器。

# 开始

正如您在前几章中看到的那样，要从镜像中启动容器，我们使用`docker run`命令。运行的容器将有自己的文件系统、网络堆栈和与主机分开的隔离进程树。正如您在第五章 *使用 Java 应用程序创建镜像*中所记得的，每个`docker run`命令都会创建一个新的容器，并执行 Dockerfile、`CMD`或`ENTRYPOINT`中指定的命令。

`docker run`命令的语法如下：

```
$ docker run [OPTIONS] IMAGE[:TAG|@DIGEST] [COMMAND] [ARG...]

```

该命令使用镜像名称，可选的`TAG`或`DIGEST`。如果跳过`TAG`和`DIGEST`命令参数，Docker 将基于标记为`latest`的镜像运行容器。`docker run`命令还接受一组可能有用的选项，例如运行时模式、分离或前台、网络设置或 CPU 和内存的运行时限制。我们将在本章后面介绍这些内容。当然，您可以执行`docker run`命令，几乎没有任何参数，除了镜像名称。它将运行并采用镜像中定义的默认选项。指定选项可以让您覆盖图像作者指定的选项以及 Docker 引擎的运行时默认值。

`COMMAND`参数不是必需的，镜像的作者可能已经在`Dockerfile`中使用`CMD`指令提供了默认的`COMMAND`。`CMD`在 Dockerfile 中只出现一次，通常是最后一条指令。从镜像启动容器时，我们可以通过提供自己的命令或参数作为`docker run`的`COMMAND`参数来覆盖`CMD`指令。在`docker run`命令中出现在镜像名称之后的任何内容都将传递给容器，并被视为`CMD`参数。如果镜像还指定了`ENTRYPOINT`，那么`CMD`或`COMMAND`将作为参数附加到`ENTRYPOINT`。但是猜猜，我们也可以使用`docker run`命令的`--entrypoint`选项来覆盖`ENTRYPOINT`。

# 停止

要停止一个或多个正在运行的 Docker 容器，我们使用`docker stop`命令。语法很简单：

```
$ docker stop [OPTIONS] CONTAINER [CONTAINER...]

```

您可以指定一个或多个要停止的容器。`docker stop`的唯一选项是`-t`（`--time`），它允许我们指定在停止容器之前等待的时间。默认值为 10 秒，应该足够容器优雅地停止。要以更加残酷的方式停止容器，可以执行以下命令：

```
$ docker kill  CONTAINER [CONTAINER...]

```

`docker stop`和`docker kill`之间有什么区别？它们都会停止正在运行的容器。但有一个重要的区别：

+   `docker stop`：容器内的主进程首先会收到`SIGTERM`，然后经过一个宽限期，会收到`SIGKILL`

+   `docker kill`：容器内的主进程将被发送`SIGKILL`（默认）或使用`--signal`选项指定的任何信号

换句话说，`docker stop`尝试通过发送标准的 POSIX 信号`SIGTERM`来触发优雅的关闭，而`docker kill`只是残酷地杀死进程，因此关闭容器。

# 列出正在运行的容器

要列出正在运行的容器，只需执行`docker ps`命令：

```
$ docker ps

```

要包括 Docker 主机上存在的所有容器，请包括`-a`选项：

```
$ docker ps -a

```

您还可以使用`-f`选项过滤列表以指定过滤器。过滤器需要以`key=value`格式提供。当前可用的过滤器包括：

+   `id`：按容器的 id 筛选

+   `标签`：按标签筛选

+   `名称`：按容器的名称筛选

+   `退出`：按容器的退出代码筛选

+   `状态`：按状态筛选，可以是 created、restarting、running、removing、paused、exited 或 dead

+   `volume`：当指定卷名称或挂载点时，将包括挂载指定卷的容器

+   `network`：当指定网络 ID 或名称时，将包括连接到指定网络的容器

考虑以下示例，它将获取 Docker 主机上的所有容器，并通过运行状态进行筛选：

```
$ docker ps -a -f status=running

```

# 删除容器

要从主机中删除容器，我们使用`docker rm`命令。语法如下：

```
$ docker rm [OPTIONS] CONTAINER [CONTAINER...]

```

您可以一次指定一个或多个容器。如果您一遍又一遍地运行短期前台进程，这些文件系统的大小可能会迅速增长。有一个解决方案：不要手动清理，告诉 Docker 在容器退出时自动清理容器并删除文件系统。您可以通过添加`--rm`标志来实现这一点，这样在进程完成后容器数据会被自动删除。

`--rm`标志将使 Docker 在容器关闭后删除容器。

例如，使用以下示例中的`run`命令：

```
$ docker run --rm -it Ubuntu /bin/bash

```

上述命令告诉 Docker 在关闭容器时将其删除。

在启动 Docker 容器时，您可以决定是以默认模式、前台模式还是后台模式（即分离模式）运行容器。让我们解释一下它们之间的区别。

# 容器运行模式

Docker 有两种容器运行模式，前台和分离。让我们从默认模式，即前台模式开始。

# 前台

在前台模式下，您用来执行`docker run`的控制台将附加到标准输入、输出和错误流。这是默认行为；Docker 将`STDIN`、`STDOUT`和`STDERR`流附加到您的 shell 控制台。如果需要，您可以更改此行为，并为`docker run`命令使用`-a`开关。作为`-a`开关的参数，您使用要附加到控制台的流的名称。例如：

```
$ docker run -a stdin -a stdout -i -t centos /bin/bash

```

上述命令将把`stdin`和`stdout`流附加到您的控制台。

有用的`docker run`选项是`-i`或`--interactive`（用于保持`STDIN`流开放，即使未附加）和`-t`或`-tty`（用于附加`伪 tty`）开关，通常一起使用为`-it`，您需要使用它为在容器中运行的进程分配`伪 tty`控制台。实际上，我们在第五章中使用了这个选项，*使用 Java 应用程序创建镜像*，当我们运行我们的 REST 服务时。

```
$ docker run -it rest-example

```

简单地说，`-it`用于在容器启动后将命令行附加到容器。这样，您可以在 shell 控制台中查看正在运行的容器的情况，并在需要时与容器交互。

# 分离

您可以使用`-d`选项以分离模式启动 Docker 容器。这是前台模式的相反。容器启动并在后台运行，就像守护进程或服务一样。让我们尝试在后台运行我们的 rest-example，执行以下命令：

```
$ docker run -d -p 8080:8080 rest-example

```

容器启动后，您将获得控制权，并可以使用 shell 或命令行执行其他命令。Docker 将只输出容器 ID，如下面的屏幕截图所示：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-k8s-java-dev/img/Image00074.jpg)

您可以使用容器 ID 在其他 docker 命令中引用容器，例如，如果您需要停止容器或附加到容器。我们的服务虽然在后台运行，但仍在工作：Spring Boot 应用程序在端口`8080`上监听`HTTP` `GET`或`POST`请求。请注意，以分离模式启动的容器会在用于运行容器的根进程退出时停止。了解这一点很重要，即使您有一些在后台运行的进程（从 Dockerfile 中的指令启动），Docker 也会在启动容器的命令完成时停止容器。在我们的情况下，Spring Boot 应用程序正在运行和监听，并且同时防止 Docker 关闭容器。要将容器从后台带回到控制台的前台，您需要附加到它。

# 附加到运行的容器

要保持对分离容器的控制，请使用`docker attach`命令。`docker attach`的语法非常简单：

```
$ docker attach [OPTIONS] <container ID or name>

```

在我们的情况下，这将是在启动容器时给我们的 ID：

```
$ docker attach 5687bd611f84b53716424fd826984f551251bc95f3db49715fc7211a6bb23840

```

此时，如果有什么东西被打印出来，比如我们运行的 REST 服务的另一条日志行，您将在控制台上看到它。正如您所看到的，如果您需要实时查看写入`stdout`流的内容，`docker attach`命令会很有用。它基本上会*重新附加*您的控制台到容器中运行的进程。换句话说，它将`stdout`流传输到您的屏幕，并将`stdin`映射到您的键盘，允许您输入命令并查看它们的输出。请注意，当附加到容器时按下*CTRL + C*键序列会终止容器的运行进程，而不是从控制台中分离。要从进程中分离，请使用默认的*CTRL+P*和*CTRL+Q*键序列。如果*CTRL + P*和*CTRL + Q*序列与您现有的键盘快捷键冲突，您可以通过为`docker attach`命令设置`--detach-keys`选项来提供自己的分离序列。如果您希望能够使用*CTRL + C*分离，您可以通过将`sig-proxy`参数设置为`false`来告诉 Docker 不要向容器中运行的进程发送`sig-term`：

```
$ docker attach --sig-proxy=false [container-name or ID]

```

如果容器在后台运行，监视其行为将是很好的。Docker 提供了一套功能来实现这一点。让我们看看如何监视运行中的容器。

# 监视容器

监视运行中的 Docker 容器有一些方法。可以查看日志文件，查看容器事件和统计信息，还可以检查容器属性。让我们从 Docker 具有的强大日志记录功能开始。访问日志条目至关重要，特别是如果您的容器在分离的运行时模式下运行。让我们看看在日志记录机制方面 Docker 能提供什么。

# 查看日志

大多数应用程序将它们的日志条目输出到标准的`stdout`流。如果容器在前台模式下运行，您将在控制台上看到它。但是，当以分离模式运行容器时，您在控制台上将什么也看不到，只会看到容器 ID。但是，Docker 引擎会在主机上的历史文件中收集运行容器的所有`stdout`输出。您可以使用`docker logs`命令来显示它。命令的语法如下：

```
$ docker logs -f <container name or ID>

```

`docker logs`命令将仅将日志的最后几行输出到控制台。由于容器仍在后台运行（以分离模式），您将立即收到提示，如下面的屏幕截图所示，显示了我们的 REST 服务日志文件的片段：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-k8s-java-dev/img/Image00075.jpg)

`-f`标志在 Linux `tail`命令中起着相同的作用，它会在控制台上持续显示新的日志条目。当你完成后，按下*CTRL + C*停止在控制台上显示日志文件。请注意，这与在容器中按下*CTRL + C*不同，那里*CTRL + C*会终止容器内运行的进程。这次，它只会停止显示日志文件，很安全。

日志文件是永久的，即使容器停止，只要其文件系统仍然存在于磁盘上（直到使用`docker rm`命令删除为止）。默认情况下，日志条目存储在位于`/var/lib/docker`目录中的 JSON 文件中。您可以使用`docker inspect`命令查看日志文件的完整路径，并使用模板提取`LogPath`（我们将在稍后介绍`inspect`和模板）。

我们已经说过，默认情况下，日志条目将进入 JSON 文件。但这可以很容易地改变，因为 Docker 利用了日志驱动程序的概念。通过使用不同的驱动程序，您可以选择其他存储容器日志的方式。默认驱动程序是`json-file`驱动程序，它只是将条目写入 JSON 文件。每个驱动程序都可以接受附加参数。例如，JSON 驱动程序接受：

```
--log-opt max-size=[0-9+][k|m|g]

--log-opt max-file=[0-9+]

```

您可能已经猜到，这类似于我们 Java 应用程序中的滚动文件。`max-size`指定可以创建的最大文件大小；达到指定大小后，Docker 将创建一个新文件。您可以使用大小后缀`k`，`m`或`g`，其中 k 代表千字节，`m`代表兆字节，`g`代表千兆字节。将日志拆分为单独的文件使得传输、存档等变得更加容易。此外，如果文件更小，搜索日志文件会更加方便。

`docker log`命令只显示最新日志文件中的日志条目。

还有一些其他可用的日志驱动程序。列表包括：

+   `none`：它将完全关闭日志记录

+   `syslog`：这是 Docker 的`syslog`日志驱动程序。它将日志消息写入系统`syslog`

+   `journald`：将日志消息记录到`journald`。`systemd-journald`是负责事件记录的守护程序，其追加日志文件作为其日志文件

+   `splunk`：提供使用`Event Http` Collector 将日志消息写入 Splunk。Splunk 可用作企业级日志分析工具。您可以在[`www.splunk.com`](https://www.splunk.com)了解更多信息

+   `gelf`：将日志条目写入 GELF 端点，如 Graylog 或 Logstash。 Graylog 可在[`www.graylog.org`](https://www.graylog.org)找到，是一个开源日志管理工具，支持对所有日志文件进行搜索、分析和警报。您可以在[`www.elastic.co/products/logstash`](https://www.elastic.co/products/logstash)找到 Logstash，它是用于处理任何数据（包括日志数据）的管道。

+   `fluentd`：将日志消息写入`fluentd`。Fluentd 是一个用于统一日志层的开源数据收集器。Fluentd 的主要特点是通过提供统一的日志层来将数据源与后端系统分离。它体积小，速度快，并且具有数百个插件，使其成为非常灵活的解决方案。您可以在其网站[`www.fluentd.org`](https://www.fluentd.org)上了解更多关于`fluentd`的信息

+   `gcplogs`：将日志条目发送到 Google Cloud 日志记录

+   `awslogs`：此驱动程序将日志消息写入 Amazon CloudWatch 日志。

正如您所看到的，Docker 的可插拔架构在运行容器时提供了几乎无限的灵活性。要切换到其他日志驱动程序，请使用`docker run`命令的`--log-driver`选项。例如，要将日志条目存储在`syslog`中，请执行以下操作：

```
$ docker run --log-driver=syslog rest-example

```

请注意，`docker logs`命令仅适用于`json-file`和`journald`驱动程序。要访问写入其他日志引擎的日志，您将需要使用与您选择的驱动程序匹配的工具。使用专门的工具浏览日志条目通常更方便；实际上，这通常是您选择另一个日志驱动程序的原因。例如，在 Logstash 或 Splunk 中搜索和浏览日志比在充满 JSON 条目的文本文件中查找要快得多。

查看日志条目是监视我们的应用程序在主机上的行为的便捷方式。有时，看到运行容器的属性也是很好的，比如映射的网络端口或映射的卷等等。为了显示容器的属性，我们使用`docker inspect`命令，这非常有用。

# 检查容器

我们一直在使用的`docker ps`命令用于列出运行的容器，它给我们提供了很多关于容器的信息，比如它们的 ID、运行时间、映射端口等等。为了显示关于运行容器的更多细节，我们可以使用`docker inspect`。命令的语法如下：

```
$ docker inspect [OPTIONS] CONTAINER|IMAGE|TASK [CONTAINER|IMAGE|TASK...]

```

默认情况下，`docker inspect`命令将以 JSON 数组格式输出有关容器或镜像的信息。由于有许多属性，这可能不太可读。如果我们知道我们要找的是什么，我们可以提供一个模板来处理输出，使用`-f`（或`--format`）选项。模板使用来自 Go 语言的模板格式（顺便说一句，Docker 本身是用 Go 语言编写的）。`docker inspect`命令最简单和最常用的模板只是一个简短的模板，用于提取你需要的信息，例如：

```
$ docker inspect -f '{{.State.ExitCode}}' jboss/wildfly

```

由于`inspect`命令接受 Go 模板来形成容器或镜像元数据的输出，这个特性为处理和转换结果提供了几乎无限的可能性。Go 模板引擎非常强大，所以，我们可以使用模板引擎来进一步处理结果，而不是通过 grep 来处理输出，这样虽然快速但混乱。

`--format`的参数只是我们要应用于容器元数据的模板。在这个模板中，我们可以使用条件语句、循环和其他 Go 语言特性。例如，以下内容将找到所有具有非零退出代码的容器的名称：

```
$ docker inspect -f '{{if ne 0.0 .State.ExitCode }}{{.Name}} {{.State.ExitCode}}{{ end }}' $(docker ps -aq)

```

请注意，我们提供了`$(docker ps -aq)`，而不是容器 ID 或名称。因此，所有正在运行的容器的 ID 将被传递给`docker inspect`命令，这可能是一个很方便的快捷方式。花括号`{{}}`表示 Go 模板指令，它们之外的任何内容都将被直接打印出来。在 Go 模板中，`.`表示上下文。大多数情况下，当前上下文将是元数据的整个数据结构，但在需要时可以重新绑定，包括使用`with`操作。例如，这两个`inspect`命令将打印出完全相同的结果：

```
$ docker inspect -f '{{.State.ExitCode}}' wildfly

$ docker inspect -f '{{with .State}} {{.ExitCode}} {{end}}' wildfly

```

如果您在绑定的上下文中，美元符号（`$`）将始终让您进入`root`上下文。我们可以执行这个命令：

```
$ docker inspect -f '{{with .State}} {{$.Name}} exited with {{.ExitCode}} exit code \ {{end}}' wildfly

```

然后将输出：

```
/wildfly exited with 0 exit code.

```

模板引擎支持逻辑函数，如`and`、`or`和`not`；它们将返回布尔结果。还支持比较函数，如`eq`（相等）、`ne`（不相等）、`lt`（小于）、`le`（小于或等于）、`gt`（大于）和`ge`（大于或等于）。比较函数可以比较字符串、浮点数或整数。与条件函数一起使用，如`if`，所有这些在从`inspect`命令创建更复杂的输出时都非常有用：

```
$ docker inspect -f '{{if eq .State.ExitCode 0.0}} \

Normal Exit \

{{else if eq .State.ExitCode 1.0}} \

Not a Normal Exit \

{{else}} \

Still Not a Normal Exit \

{{end}}' wildfly

```

有时，`docker inspect`命令的大量输出可能会令人困惑。由于输出以 JSON 格式呈现，可以使用`jq`工具来获取输出的概述并挑选出有趣的部分。

`jq`工具可以免费获取，网址为[`stedolan.github.io/jq/`](https://stedolan.github.io/jq/)。它是一个轻量灵活的命令行 JSON 处理器，类似于 JSON 数据的`sed`命令。例如，让我们从元数据中提取容器的 IP 地址：

```
$ docker inspect <containerID> | jq -r '.[0].NetworkSettings.IPAddress'

```

正如您所看到的，`docker inspect`命令提供了有关 Docker 容器的有用信息。结合 Go 模板功能，以及可选的`jq`工具，它为您提供了一个强大的工具，可以获取有关您的容器的信息，并可以在脚本中进一步使用。但除了元数据之外，还有另一个有价值的信息来源。这就是运行时统计信息，现在我们将重点关注这一点。

# 统计信息

要查看容器的 CPU、内存、磁盘 I/O 和网络 I/O 统计信息，请使用`docker stats`命令。该命令的语法如下：

```
docker stats [OPTIONS] [CONTAINER...]

```

您可以通过指定由空格分隔的容器 ID 或名称列表来将统计量限制为一个或多个特定容器。默认情况下，如果未指定容器，则该命令将显示所有运行中容器的统计信息，如下面的屏幕截图所示：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-k8s-java-dev/img/Image00076.jpg)

`docker stats`命令接受选项，其中可以包括：

+   `--no-stream`：这将禁用流式统计信息，并且只拉取第一个结果

+   `-a`（`--all`）：这将显示所有（不仅仅是运行中的）容器的统计信息

统计信息可用于查看我们的容器在运行时的行为是否良好。这些信息可以用来检查是否需要对容器应用一些资源约束，我们将在本章稍后讨论运行时约束。

查看日志、容器元数据和运行时统计信息，可以在监视运行中的容器时给您几乎无限的可能性。除此之外，我们还可以全局查看 docker 主机上发生的情况。当主机上的 docker 引擎接收到命令时，它将发出我们可以观察到的事件。现在让我们来看看这个机制。

# 容器事件

为了实时观察到 docker 引擎接收的事件，我们使用`docker events`命令。如果容器已启动、停止、暂停等，事件将被发布。如果您想知道容器运行时发生了什么，这将非常有用。这是一个强大的监控功能。Docker 容器报告了大量的事件，您可以使用`docker events`命令列出。列表包括：

```
attach, commit, copy, create, destroy, detach, die, exec_create, exec_detach, exec_start, export, health_status, kill, oom, pause, rename, resize, restart, start, stop, top, unpause, update

```

`docker events`命令可以使用`-f`开关，如果您正在寻找特定内容，它将过滤输出。如果未提供过滤器，则将报告所有事件。目前可能的过滤器列表包括：

+   容器（`container=<名称或 ID>`）

+   事件（`event=<事件操作>`）

+   镜像（`image=<标签或 ID>`）

+   插件（实验性）（`plugin=<名称或 ID>`）

+   标签（`label=<键>`或`label=<键>=<值>`）

+   类型（`type=<容器或镜像或卷或网络或守护程序>`）

+   卷（`volume=<名称或 ID>`）

+   网络（`network=<名称或 ID>`）

+   守护程序（`daemon=<名称或 ID>`）

看看以下示例。在一个控制台窗口中运行了`docker events`命令，而在另一个控制台中发出了`docker run rest-example`命令。如您在以下截图中所见，`docker events`将报告我们的 rest-example 容器的创建、附加、连接和启动事件：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-k8s-java-dev/img/Image00077.jpg)

因此，您将获得一个时间戳和事件的名称，以及导致事件的容器的 ID。`docker events`命令可以接受其他选项，例如`--since`和`--until`，用于指定要获取事件的时间范围。监视容器事件是一个很好的工具，可以看到 Docker 主机上发生了什么。但这还不是全部。您还可以影响容器在崩溃时的行为，例如。我们使用容器重启策略来实现这一点。

# 重启策略

通过在`docker run`命令中使用`--restart`选项，您可以指定重启策略。这告诉 Docker 在容器关闭时如何反应。然后可以重新启动容器以最小化停机时间，例如在生产服务器上运行时。然而，在我们解释 Docker 重启策略之前，让我们先专注一会儿退出代码。退出代码是关键信息，它告诉我们容器无法运行或退出的原因。有时它与您将作为参数提供给`docker run`的命令有关。当`docker run`命令以非零代码结束时，退出代码遵循`chroot`标准，如您在这里所见：

+   退出代码`125`：`docker run`命令本身失败

+   退出代码`126`：提供的命令无法调用

+   退出代码`127`：提供的命令找不到

+   其他非零的、应用程序相关的退出代码

您可能还记得，在之前的章节中，我们一直在使用`docker ps`命令列出运行中的容器。要列出非运行中的容器，我们可以为`docker ps`命令添加`-a`开关。当容器完成时，退出代码可以在`docker ps -a`命令的输出中的状态列中找到。可以通过在启动容器时指定重启策略来自动重新启动崩溃的容器。通过`docker run`命令的-restart 开关来指定所需的重启策略，就像这个例子中一样：

```
$ docker run --restart=always rest-example

```

目前 Docker 有四种重启策略。让我们逐一了解它们，从最简单的开始：`no`。

# 没有

`no`策略是默认的重启策略，简单地不会在任何情况下重新启动容器。实际上，您不必指定此策略，因为这是默认行为。除非您有一些可配置的设置来运行 Docker 容器，否则`no`策略可以用作关闭开关。

# 始终

如果我们希望无论命令的退出代码是什么，容器都会重新启动，我们可以使用`always`重启策略。基本上，它就是字面意思；Docker 将在任何情况下重新启动容器。重启策略将始终重新启动容器。即使容器在重新启动之前已停止，也是如此。每当 Docker 服务重新启动时，使用 always 策略的容器也将被重新启动，无论它们是否正在执行。

使用`always`重启策略，Docker 守护程序将尝试无限次重新启动容器。

# 在失败时

这是一种特殊的重启策略，可能是最常用的。通过使用`on-failure`重启策略，您指示 Docker 在容器以非零退出状态退出时重新启动容器，否则不重新启动。这就是我们从退出代码开始解释重启策略的原因。您还可以选择为 Docker 尝试重新启动容器的次数提供一个数字。此重启策略的语法也略有不同，因为使用此策略，您还可以指定 Docker 将尝试自动重新启动容器的最大次数。

考虑这个例子：

```
$ docker run --restart=on-failure:5 rest-example

```

在失败的情况下，上述命令将运行具有我们的 REST 服务的容器，并在放弃之前尝试重新启动五次。 `on-failures`重启策略的主要好处是，当应用程序以成功的退出代码退出时（这意味着应用程序没有错误，只是执行完毕），容器将不会重新启动。可以通过我们已经知道的`docker inspect`命令获取容器的重新启动尝试次数。例如，要获取具有特定 ID 或名称的容器的重新启动次数：

```
$ docker inspect -f "{{ .RestartCount }}" <ContainerID>

```

您还可以发现容器上次启动的时间：

```
$ docker inspect -f "{{ .State.StartedAt }}" <ContainerID>

```

您应该知道，Docker 在重新启动容器之间使用延迟，以防止洪水般的保护。这是一个递增的延迟；它从 100 毫秒的值开始，然后 Docker 将加倍上一个延迟。实际上，守护程序将等待 100 毫秒，然后是 200 毫秒，400，800 等，直到达到`on-failure`限制，或者当您使用`docker stop`停止容器，或者通过执行`docker rm -f`命令强制删除容器。

如果容器成功重新启动，则延迟将重置为默认值 100 毫秒。

# unless-stopped

与`always`类似，如果我们希望容器无论退出代码如何都重新启动，我们可以使用`unless-stopped`。`unless-stopped`重启策略与`always`相同，唯一的例外是，它将重新启动容器，而不管退出状态如何，但如果容器在停止状态之前已被停止，则不会在守护程序启动时启动它。这意味着使用`unless-stopped`重启策略，如果容器在重新启动前正在运行，则系统重新启动后容器将被重新启动。当 Docker 容器中的应用程序退出时，该容器也将被停止。如果容器中运行的应用程序崩溃，容器将停止，并且该容器将保持停止状态，直到有人或某物重新启动它。

在将重启策略应用于容器之前，最好先考虑容器将用于做什么样的工作。这也取决于将在容器上运行的软件的类型。例如，数据库可能应该应用`always`或`unless-stopped`策略。如果您的容器应用了某种重启策略，当您使用`docker ps`命令列出容器时，它将显示为`Restarting`或`Up`状态。

# 更新正在运行的容器的重启策略

有时，在容器已经启动后，有必要*即时*更新 Docker 运行时参数。一个例子是，如果您想要防止容器在 Docker 主机上消耗过多资源。为了在运行时设置策略，我们可以使用`docker update`命令。除了其他运行时参数（例如内存或 CPU 约束，我们将在本章后面讨论），`docker update`命令还提供了更新运行中容器的重启策略的选项。语法非常简单，您只需要提供您希望容器具有的新重启策略以及容器的 ID 或名称：

```
$ docker update --restart=always <CONTAINER_ID or NAME>

```

运行`docker update`命令后，新的重启策略将立即生效。另一方面，如果您在已停止的容器上执行`update`命令，该策略将在以后启动容器时使用。可能的选项与您启动容器时可以指定的选项完全相同：

+   `no`（默认值）

+   `always`

+   失败时

+   `unless-stopped`

如果在 Docker 主机上运行多个容器，并且想要一次性为它们指定新的重启策略，只需提供它们所有的 ID 或名称，用空格分隔。

您还可以使用`docker events`命令查看应用了哪种重启策略，这是您已经在上一节中了解过的。`docker events`可以用来观察容器报告的运行时事件的历史记录，还会报告`docker update`事件，提供有关已更改的详细信息。如果容器已应用重启策略，事件将被发布。如果要检查运行中容器的重启策略，请使用`docker inspect`与容器 ID 或名称以及设置`--format`参数的路径：

```
$ docker inspect --format '{{ .HostConfig.RestartPolicy.Name }}' <ContainerID>

```

根据容器设置重启策略的能力非常适用于那些图像是自包含的，不需要进行更复杂的编排任务的情况。重启策略不是您可以在运行中容器上更改的唯一参数。

# 资源的运行时约束

在运行时限制 Docker 容器使用资源可能是有用的。Docker 为您提供了许多设置内存、CPU 使用或磁盘访问使用的约束的可能性。让我们从设置内存约束开始。

# 内存

值得知道，默认情况下，即如果您在没有任何约束的情况下使用默认设置，则运行的容器可以使用所有主机内存。要更改此行为，我们可以使用`docker run`命令的`--memory`（或`-m`简称）开关。它分别采用`k`，`m`或`g`后缀，表示千字节，兆字节和千兆字节。

具有设置内存约束的`docker run`命令的语法将如下所示：

```
$ docker run -it -m 512m ubuntu

```

上述命令将执行 Ubuntu 镜像，容器可以使用的最大内存为半个千兆字节。

如果您没有设置容器可以分配的内存限制，这可能会导致随机问题，其中单个容器可以轻松使整个主机系统变得不稳定和/或无法使用。因此，始终在容器上使用内存约束是明智的决定。

除了用户内存限制外，还有内存预留和内核内存约束。让我们解释一下内存预留限制是什么。在正常工作条件下，运行的容器可以并且可能会使用所需的内存，直到您使用`docker run`命令的`--memory`（`-m`）开关设置的限制。当应用内存预留时，Docker 将检测到低内存情况，并尝试强制容器将其消耗限制到预留限制。如果您没有设置内存预留限制，它将与使用`-m`开关设置的硬内存限制完全相同。

内存预留不是硬限制功能。不能保证不会超出限制。内存预留功能将尝试确保根据预留设置分配内存。

考虑以下示例：

```
$ docker run -it -m 1G --memory-reservation 500M ubuntu /bin/bash

```

上述命令将将硬内存限制设置为`1g`，然后将内存预留设置为半个千兆字节。设置这些约束后，当容器消耗的内存超过`500M`但少于`1G`时，Docker 将尝试将容器内存缩小到少于`500M`。

在下一个示例中，我们将设置内存预留而不设置硬内存限制：

```
$ docker run -it --memory-reservation 1G ubuntu /bin/bash

```

在前面的示例中，当容器启动时，它可以使用其进程所需的内存。`--memory-reservation`开关设置将阻止容器长时间消耗过多的内存，因为每次内存回收都会将容器的内存使用量缩小到预留中指定的大小。

内核内存与用户内存完全不同，主要区别在于内核内存无法交换到磁盘。它包括堆栈页面、slab 页面、套接字内存压力和 TCP 内存压力。您可以使用`--kernel-memory`开关来设置内核内存限制以约束这些类型的内存。与设置用户内存限制一样，只需提供一个带有后缀的数字，例如`k`、`b`和`g`，分别表示千字节、兆字节或千兆字节，尽管以千字节设置它可能是一个非常罕见的情况。

例如，每个进程都会占用一些堆栈页面。通过限制内核内存，您可以防止在内核内存使用过高时启动新进程。此外，由于主机无法将内核内存交换到磁盘，容器可能会通过消耗过多的内核内存来阻塞整个主机服务。

设置内核内存限制很简单。我们可以单独设置`--kernel-memory`，而不限制总内存使用量，就像下面的例子一样：

```
$ docker run -it --kernel-memory 100M ubuntu  /bin/bash

```

在上面的例子中，容器中的进程可以根据需要使用内存，但只能消耗`100M`的内核内存。我们还可以设置硬内存限制，如下面的命令所示：

```
$ docker run -it -m 1G --kernel-memory 100M ubuntu /bin/bash

```

在上述命令中，我们同时设置了内存和内核内存，因此容器中的进程可以总共使用`1G`内存，其中包括`100M`的内核内存。

与内存相关的另一个约束条件在运行容器时可能会有用，这是 swappines 约束。我们可以使用`--memory-swappiness`开关来应用约束到`docker run`命令。当你想要避免与内存交换相关的性能下降时，这可能会有所帮助。`--memory-swappiness`开关的参数是可以交换的匿名内存页面的百分比，因此它的值范围是从`0`到`100`。将值设置为零，将根据您的内核版本禁用交换或使用最小交换。相反，值为`100`会将所有匿名页面设置为可以交换出去的候选项。例如：

```
$ docker run -it --memory-swappiness=0 ubuntu /bin/bash

```

在上述命令中，我们完全关闭了`ubuntu`容器的交换。

除了设置内存使用约束外，您还可以指示 Docker 如何分配处理器能力给它将要运行的容器。

# 处理器

使用`-c`（或`--cpu-shares`作为等效项）来为`docker run`命令开关指定 CPU 份额的值是可能的。默认情况下，每个新容器都有 1024 份 CPU 份额，并且所有容器获得相同的 CPU 周期。这个百分比可以通过改变容器的 CPU 份额权重相对于所有其他正在运行的容器的权重来改变。但请注意，您不能设置容器可以使用的精确处理器速度。这是一个**相对权重**，与实际处理器速度无关。事实上，没有办法准确地说一个容器应该有权利只使用主机处理器的 2 GHz。

CPU 份额只是一个数字，与 CPU 速度没有任何关系。

如果我们启动两个容器，两者都将使用 100%的 CPU，处理器时间将在两个容器之间平均分配。原因是两个容器将拥有相同数量的处理器份额。但是如果您将一个容器的处理器份额限制为 512，它将只获得 CPU 时间的一半。这并不意味着它只能使用 CPU 的一半；这个比例只在运行 CPU 密集型进程时适用。如果另一个容器（具有`1024`份份额）处于空闲状态，我们的容器将被允许使用 100%的处理器时间。实际的 CPU 时间将取决于系统上运行的容器数量。这在一个具体的例子中更容易理解。

考虑三个容器，一个（我们称之为`Container1`）设置了`--cpu-shares`为`1024`，另外两个（`Container2`和`Container3`）设置了`--cpu-shares`为`512`。当所有三个容器中的进程尝试使用所有的 CPU 功率时，`Container1`将获得总 CPU 时间的 50%，因为它相对于其他正在运行的容器（`Container2`和`Container3`的总和）有一半的 CPU 使用量。如果我们添加一个`--cpu-share`为 1024 的第四个容器（`Container4`），我们的第一个`Container1`只会获得 CPU 的 33%，因为它现在相对于总 CPU 功率的三分之一。`Container2`将获得 16.5%，`Container3`也是 16.5%，最后一个`Container4`再次被允许使用 CPU 的 33%。

虽然`docker run`命令的`-c`或`--cpu_shares`标志修改了容器相对于所有其他运行容器的 CPU 份额权重，但它不限制容器对主机机器 CPU 的使用。但是还有另一个标志可以限制容器的 CPU 使用：`--cpu-quota`。其默认值为`100000`，表示允许使用 100%的 CPU 使用率。我们可以使用`--cpu-quota`来限制 CPU 使用，例如：

```
$ docker run -it  --cpu-quota=50000 ubuntu /bin/bash

```

在前面的命令中，容器的限制将是 CPU 资源的 50%。`--cpu-quota`通常与`docker run`的`--cpu-period`标志一起使用。这是 CPU CFS（Completely Fair Scheduler）周期的设置。默认周期值为 100000，即 100 毫秒。看一个例子：

```
$ docker run -it --cpu-quota=25000 --cpu-period=50000  ubuntu /bin/bash

```

这意味着容器可以每 50 毫秒获得 50%的 CPU 使用率。

限制 CPU 份额和使用率并不是我们可以在容器上设置的唯一与处理器相关的约束。当我们想要执行此操作时，`docker run`命令的`--cpuset`开关非常方便。考虑以下例子：

```
$ docker run -it --cpuset 4 ubuntu

```

上述命令将运行`ubuntu`镜像，并允许容器使用所有四个处理器核心。要启动容器并只允许使用一个处理器核心，可以将`--cpuset`值更改为`1`：

```
$ docker run -it --cpuset 1 ubuntu

```

当然，您可以将`--cpuset`选项与`--cpu_shares`混合在一起，以调整容器的 CPU 约束。

# 更新正在运行的容器的约束

与重启策略一样，当容器已经在运行时也可以更新约束。如果您发现您的容器占用了太多的 Docker 主机系统资源，并希望限制此使用，这可能会有所帮助。同样，我们使用`docker update`命令来执行此操作。

与重启策略一样，`docker update`命令的语法与启动容器时相同，您将所需的约束作为 docker update 命令的参数指定，然后提供容器 ID（例如从`docker ps`命令输出中获取）或其名称。同样，如果您想一次更改多个容器的约束，只需提供它们的 ID 或名称，用空格分隔。让我们看一些在运行时如何更新约束的示例：

```
$ docker update --cpu-shares 512 abbdef1231677

```

上述命令将限制 CPU 份额的值为 512。当然，您也可以同时对多个容器应用 CPU 和内存约束：

```
docker update --cpu-shares 512 -m 500M abbdef1231677 dabdff1231678

```

上述命令将更新 CPU 份额和内存限制到两个容器，标识为`abbdef1231677`和`dabdff1231678`。

当更新运行时约束时，当然也可以在一个命令中应用所需的重启策略，就像下面的例子一样：

```
$ docker update --restart=always -m 300M aabef1234716

```

正如您所看到的，设置约束的能力在运行 Docker 容器时给了您很大的灵活性。但值得注意的是，应用约束并不总是可能的。原因是约束设置功能严重依赖于 Docker 主机的内部情况，特别是其内核。例如，设置内核内存限制或`内存 swappiness`并不总是可能的，有时您会收到`您的内核不支持内核内存限制或内核不支持内存 swappiness 功能`的消息。有时这些限制是可配置的，有时不是。例如，如果您收到`警告：您的内核不支持 Ubuntu 上的 cgroup 交换限制`，您可以在 Grub 配置文件中使用`cgroup_enable=memory swapaccount=1`设置来调整 Grub 引导加载程序，例如在 Ubuntu 中，这将是`/etc/default/grub`。重要的是要阅读 Docker 打印出的日志，以确保您的约束已经生效。

在容器启动或在动态更新约束后，始终注意 Docker 输出的警告，可能会导致您的约束不起作用！

我们已经知道如何使用命令行中可用的命令来运行和观察容器。然而，如果您需要在开发流程中启动容器，例如进行集成测试，这并不是很方便。我们在第五章中使用的 Fabric8 Docker Maven 插件，用于构建镜像，如果我们需要运行容器，也会很方便。现在让我们来做吧。

# 使用 Maven 运行

该插件提供了两个与启动和停止容器相关的 Maven 目标。这将是 `docker:start` 和 `docker:stop` 。使用 `docker:start` 创建和启动容器，使用 `docker:stop` 停止和销毁容器。如果需要在集成测试期间运行容器，典型用例将是在 Maven 构建阶段中包含这些目标：`docker:start` 将绑定到 `pre-integration-test`，`docker:stop` 绑定到 `post-integration-test` 阶段。

# 插件配置

该插件使用 `pom.xml` 文件中 `<configuration>` 的 `<run>` 子元素中的配置。最重要的配置元素列表如下：

| `cmd` | 应在容器启动结束时执行的命令。如果未给出，则使用图像的默认命令。 |
| --- | --- |
| `entrypoint` | 容器的入口点。 |
| `log` | 日志配置，用于控制是否以及如何打印运行容器的日志消息。这也可以配置要使用的日志驱动程序。 |
| `memory` | 内存限制（以字节为单位） |

| n`amingStrategy` | 容器名称创建的命名策略：

+   `none`：使用来自 Docker 的随机分配的名称（默认）

+   `alias`：使用图像配置中指定的别名。如果已经存在具有此名称的容器，则会抛出错误。

|

| `network` | `<network>` 元素可用于配置容器的网络模式。它知道以下子元素：

+   `<mode>`：网络模式，可以是以下值之一：

+   `bridge`：使用默认的 Docker 桥接模式（默认）

+   `host`：共享 Docker 主机网络接口

+   `container`：连接到指定容器的网络

容器的名称取自 `<name>` 元素：

+   `custom`：使用自定义网络，必须在使用 Docker 网络创建之前创建

+   `none`：不会设置网络

|

| `ports` | `<ports>` 配置包含端口映射的列表。每个映射有多个部分，每个部分由冒号分隔。这相当于使用 `docker run` 命令和 `-p` 选项时的端口映射。一个示例条目可以看起来像这样：

```
<ports>   
<port>8080:8080</port>   
</ports>   
```

|

| `restartPolicy` | 提供了我们在本章前面讨论过的重启策略。一个示例条目可以看起来像下面这样：

```
<restartPolicy>   
<name> on-failure</name>   
<retry>5</retry>   
</restartPolicy>   
```

|

| `volumes` | 用于绑定到主机目录和其他容器的卷配置。示例配置可以看起来像下面这样：

```
<volumes>   
<bind>   
<volume>/logs</volume><volume>/opt/host_export:/opt/container_import</volume> </bind>   
</volumes>   
```

|

我们的 Java REST 服务的完整`<configuration>`元素可以看起来和以下一样。这是一个非常基本的例子，我们只在这里配置了运行时端口映射：

```
<configuration> 
<images> 
<image> 
<name>rest-example:${project.version}</name> 
<alias>rest-example</alias> 
<build> 
<from>openjdk:latest</from> 
<assembly> 
<descriptorRef>artifact</descriptorRef> 
</assembly> 
<cmd>java -jar maven/${project.name}-${project.version}.jar</cmd> 
</build> 
<run> 
<ports> 
<port>8080:8080</port> 
</ports> 
</run> 
</image> 
</images> 
</configuration>

```

配置了我们的容器后，让我们尝试运行它，使用 Maven。

# 启动和停止容器

要启动容器，请执行以下操作：

```
$ mvn clean package docker:start

```

Maven 将从源代码构建我们的 REST 服务，构建镜像，并在后台启动容器。作为输出，我们将得到容器的 ID，如你可以在以下截图中看到的那样：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-k8s-java-dev/img/Image00078.jpg)

容器现在在后台运行。要测试它是否在运行，我们可以发出`docker ps`命令来列出所有正在运行的容器，或者通过在映射的`8080`端口上执行一些`HTTP`方法，如`GET`或`POST`来调用服务。端口已在`<build>`配置元素中公开，并在`<run>`配置元素中公开。这很方便，不是吗？但是，如果我们想要看到容器的输出而不是在后台运行它怎么办？这也很容易；让我们首先通过发出以下命令来停止它：

```
$ mvn docker:stop

```

10 秒后（你会记得，这是在停止容器之前的默认超时时间），Maven 将输出一个声明，表示容器已经停止：

```
[INFO] DOCKER> [rest-example:0.1.0] "rest-example": Stop and removed container 51660084f0d8 after 0 ms

```

让我们再次运行容器，这次使用 Maven 的`docker:run`目标，而不是`docker:start`。执行以下操作：

```
$ mvn clean package docker:run

```

这次，Maven Docker 插件将运行容器，我们将在控制台上看到 Spring Boot 横幅，如你可以在以下截图中看到的那样：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-k8s-java-dev/img/Image00079.jpg)

我猜你现在可以辨别`docker:start`和`docker:run`之间的区别了。正确，`docker:run`相当于`docker run`命令的`-i`选项。`docker:run`还会自动打开`showLogs`选项，这样你就可以看到容器内发生了什么。作为替代，你可以提供`docker.follow`作为系统属性，这样`docker:start`将永远不会返回，而是阻塞，直到按下*CTRL + C*，就像当你执行`docker:run` Maven 目标时一样。

正如你所看到的，Fabric8 Docker Maven 插件给了你与从 shell 或命令行运行和停止容器时一样的控制。但这里是 Maven 构建过程本身的优势：你可以自动化事情。Docker 容器现在可以在构建过程中使用，集成测试和持续交付流程中使用；你说了算。

# 摘要

在本章中，我们已经学会了如何管理容器的生命周期，使用不同的运行模式（前台和后台）启动它，停止或删除它。我们还知道如何创建约束，使我们的容器按照我们想要的方式运行，通过使用运行时约束来限制 CPU 和 RAM 的使用。当我们的容器运行时，我们现在能够以多种方式检查容器的行为，比如读取日志输出，查看事件或浏览统计数据。如果你正在使用 Maven，作为 Java 开发人员，你可能会配置 Docker Maven 插件，以便自动启动或停止容器。

我们已经对 Docker 有了很多了解，我们可以构建和运行镜像。现在是时候更进一步了。我们将使用 Kubernetes 自动化部署、扩展和管理容器化应用程序。这是真正有趣的时刻。


# 第七章：Kubernetes 简介

阅读完第六章，*使用 Java 应用程序运行容器*，现在您对使用 Docker 打包 Java 应用程序有了很多知识。现在是时候更进一步，专注于我们所缺少的内容--容器管理和编排。市场上有一些合适的工具，例如 Nomad、Docker Swarm、Apache Mesos 或 AZK 等。在本章中，我们将重点介绍可能是最受欢迎的工具之一，Kubernetes。Kubernetes（有时简称为 k8s）是由 Google 于 2015 年创建的用于 Docker 容器的开源编排系统。Google 开发的第一个统一容器管理系统是内部称为 Borg 的系统；Kubernetes 是它的后代。本章涵盖的主题列表将是：

+   为什么以及何时需要容器管理

+   Kubernetes 简介

+   基本的 Kubernetes 概念

让我们从回答为什么我们需要 Kubernetes 这个问题开始。我们将探讨容器管理和编排背后的原因。

# 我们为什么需要 Kubernetes？

正如您已经知道的那样，Docker 容器为运行打包成小型独立软件的 Java 服务提供了极大的灵活性。Docker 容器使应用程序的组件可移植--您可以在不需要担心依赖项或底层操作系统的情况下，在不同的环境中移动单个服务。只要操作系统能够运行 Docker 引擎，您的 Java 容器就可以在该系统上运行。

另外，正如你在第一章中所记得的，*Docker 简介*，Docker 隔离容器的概念远非传统虚拟化。区别在于 Docker 容器利用主机操作系统的资源--它们轻便、快速且易于启动。这一切都很好，但也存在一些风险。你的应用由多个独立的微服务组成。服务的数量可能会随着时间增长。此外，如果你的应用开始承受更大的负载，增加相同服务的容器数量以分担负载会很好。这并不意味着你只需要使用自己的服务器基础设施--你的容器可以部署到云端。今天我们有很多云服务提供商，比如谷歌或亚马逊。在云端运行你的容器，会给你带来很多优势。首先，你不需要管理自己的服务器。其次，在大多数云端，你只需为实际使用付费。如果负载增加，云服务的成本当然会增加，因为你将使用更多的计算能力。但如果没有负载，你将付出零成本。这说起来容易，但监控服务器使用情况，尤其是在应用或应用程序运行的组件数量庞大时，可能会有些棘手。你需要仔细查看云公司的账单，并确保你没有一个容器在云端空转。如果特定服务对你的应用不那么重要，也不需要快速响应，你可以将其迁移到最便宜的机器上。另一方面，如果另一个服务承受更大的负载并且至关重要，你可能会希望将其迁移到更强大的机器上或增加更多实例。最重要的是，通过使用 Kubernetes，这可以自动化。通过拥有管理 Docker 容器的正确工具，这可以实时完成。你的应用可以以非常灵活的方式自适应--最终用户可能甚至不会意识到他们使用的应用程序位于何处。容器管理和监控软件可以通过更好地利用你支付的硬件大大降低硬件成本。Kubernetes 处理在计算集群中的节点上进行调度，并积极管理工作负载，以确保它们的状态与用户声明的意图相匹配。使用标签和 Pods 的概念（我们将在本章后面介绍），Kubernetes 将组成应用程序的容器分组为逻辑单元，以便进行简单的管理和发现。

将应用程序以一组容器的形式运行在受管理的环境中，也改变了对软件开发的视角。你可以在服务的新版本上进行工作，当准备好时，可以实现动态滚动更新。这也意味着专注于应用程序而不是运行在其上的机器，这结果允许开发团队以更加灵活、更小、更模块化的方式运作。它使得软件开发真正地变得敏捷，这正是我们一直想要的。微服务是小型且独立的，构建和部署时间大大缩短。此外，发布的风险也更小，因此你可以更频繁地发布较小的更改，最大程度地减少一次性发布所有内容可能导致的巨大失败的可能性。

在我们开始介绍基本的 Kubernetes 概念之前，让我们总结一下 Kubernetes 给我们带来了什么：

+   快速、可预测地部署应用程序

+   动态扩展

+   无缝发布新功能

+   防故障

+   将硬件使用限制在所需的资源上

+   敏捷的应用程序开发

+   操作系统、主机和云提供商之间的可移植性

这是一系列无法轻易超越的功能。要理解如何实现这一点，我们需要了解核心的 Kubernetes 概念。到目前为止，我们只知道来自 Docker 的一个概念--容器--它是一个可移植的、独立的软件单元。容器可以包含任何我们想要的东西，无论是数据库还是 Java REST 微服务。让我们来了解剩下的部分。

# 基本的 Kubernetes 概念

集群是一组节点；它们可以是安装了 Kubernetes 平台的物理服务器或虚拟机。基本的 Kubernetes 架构如下图所示：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-k8s-java-dev/img/Image00080.jpg)

正如你所看到的，Kubernetes 集群由一个主节点和若干个工作节点以及一些组件组成。虽然乍一看可能会让人感到害怕和复杂，但如果我们逐个描述这些概念，从 Pod 开始，就会更容易理解。

# Pods

Pod 由一个或多个 Docker 容器组成。这是 Kubernetes 平台的基本单元，也是 Kubernetes 处理的基本执行单元。Pod 的图示如下：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-k8s-java-dev/img/Image00081.jpg)

在同一 Pod 中运行的容器共享相同的网络命名空间、磁盘和安全上下文。事实上，建议在同一 Pod 中运行的容器之间使用 localhost 进行通信。每个容器还可以与集群中的任何其他 Pod 或服务进行通信。

正如您从第二章中记得的，*网络和持久存储*，您可以在 Docker 容器中挂载卷。Kubernetes 还支持卷的概念。附加到 Pod 的卷可以在此 Pod 上运行的一个或多个容器内挂载。Kubernetes 支持许多不同类型的卷，作为原生支持挂载 GitHub 存储库、网络磁盘、本地硬盘等。

如果您的应用程序需要分布式存储并且需要处理大量数据，您不仅仅局限于本地硬盘。Kubernetes 还支持卷提供程序。目前，可用的持久卷提供程序列表包括：

+   GCE：谷歌云平台

+   AWS：亚马逊网络服务

+   GlusterFS：可扩展的网络文件系统。使用免费的开源软件 GlusterFS，您可以利用现有的存储硬件创建大型分布式存储解决方案

+   OpenStack Cinder：用于 OpenStack Nova 计算平台用户的块存储服务

+   CephRBD：可靠的自主分布式对象存储（RADOS），为您的应用程序提供单一统一存储集群中的对象、块和文件系统存储

+   QuoByte

+   Kube-Aliyun

网络命名空间和卷不是 Pod 的唯一属性。正如您在 Pod 的图表中所看到的，Pod 可以附加标签和注释。标签在 Kubernetes 中非常重要。它们是附加到对象（在本例中是 Pod）的键/值对。标签的理念是它们可以用于标识对象--标签对用户来说是有意义和相关的。标签的一个示例可能是：

```
app=my-rest-service 

layer=backend

```

稍后，我们将使用标签选择器来选择具有指定标签的对象（如 Pods）。通过标签选择器，在 Kubernetes 中是核心分组原语，客户端或用户可以识别对象或一组对象。选择器类似于标签，也是用于使用匹配标签识别资源的键值表达式。例如，选择器表达式`app = my-rest-service`将选择所有具有标签`app = my-rest-service`的 Pods。另一方面，注释是一种可以附加到 Pods 的元数据。它们不是用于识别属性；它们是可以被工具或库读取的属性。关于注释应包含什么的规则没有规定--这取决于您。注释可以包含诸如构建或发布版本、时间戳、Git 分支名称、Git`pull`请求编号或任何其他内容，如手机号码。

标签用于识别有关 Kubernetes 对象（如 Pods）的信息。注释只是附加到对象的元数据。

我们之前说过，Pod 是 Kubernetes 中的执行的基本单位。它可以包含多个容器。具有多个 Docker 容器的 Pod 的现实生活示例可能是我们的 Java REST 微服务 Pod。例如，在之前的章节中，我们的微服务一直将其数据库数据存储在内存中。在现实生活中，数据可能应该存储在真正的数据库中。我们的 Pod 可能会有一个包含 Java JRE 和 Spring Boot 应用程序本身的容器，以及第二个包含 PostgreSQL 数据库的容器，微服务使用它来存储数据。这两个容器组成一个 Pod--一个单一的、解耦的执行单元，包含我们的 REST 服务运行所需的一切。

Pod 的定义是一个名为`Pod`清单的 JSON 或 YAML 文件。看一个包含一个容器的简单示例：

```
apiVersion: v1

kind: Pod

metadata:

 name: rest_service

spec:

 containers:

 name: rest_service

 image: rest_service

 ports:

 - containerPort: 8080

```

在 JSON 文件中相同的`pod`清单看起来与以下内容相同：

```
{

 "apiVersion": "v1", 

 "kind": "Pod",

 "metadata":{

 "name": ”rest_service”,

 "labels": {

 "name": "rest_service"

 }

 },

 "spec": {

 "containers": [{

 "name": "rest_service",

 "image": "rest_service",

 "ports": [{"containerPort": 8080}],

 }]

 }

}

```

容器的`image`是 Docker 镜像名称。`containerPort`公开来自 REST 服务容器的端口，因此我们可以连接到 Pod 的 IP 上的服务。默认情况下，正如您从第一章中记得的那样，*Docker 简介*中定义的`image`中的入口点将运行。

非常重要的是要意识到 Pod 的生命周期是脆弱的。因为 Pod 被视为无状态、独立的单元，如果其中一个不健康或者只是被新版本替换，Kubernetes Master 不会对其手下留情--它只会将其杀死并处理掉。

事实上，Pod 有一个严格定义的生命周期。以下列表描述了 Pod 生命周期的各个阶段：

+   `挂起`：这个阶段意味着 Pod 已经被 Kubernetes 系统接受，但一个或多个 Docker 容器镜像尚未被创建。Pod 可能会在这个阶段停留一段时间--例如，如果需要从互联网下载镜像。

+   `运行中`：Pod 已经放置到一个节点上，并且 Pod 的所有 Docker 容器都已经被创建。

+   `成功`：Pod 中的所有 Docker 容器都已成功终止。

+   `失败`：Pod 中的所有 Docker 容器都已终止，但至少一个容器以失败状态终止或被系统终止。

+   `未知`：这通常表示与 Pod 主机的通信出现问题；由于某种原因，无法检索 Pod 的状态。

当一个 Pod 被关闭时，不仅仅是因为它失败了。更常见的情况是，如果我们的应用程序需要处理增加的负载，我们需要运行更多的 Pod。另一方面，如果负载减少或根本没有负载，那么运行大量 Pod 就没有意义--我们可以处理掉它们。当然，我们可以手动启动和停止 Pod，但自动化总是更好。这就引出了 ReplicaSets 的概念。

# ReplicaSets

ReplicaSets 是使用复制来扩展应用程序的概念。Kubernetes 复制有什么用处？通常情况下，您会希望复制您的容器（实际上就是您的应用程序）出于几个原因，包括：

+   **扩展**：当负载增加并对现有实例的数量造成过重负荷时，Kubernetes 使您能够轻松地扩展应用程序，根据需要创建额外的实例。

+   **负载均衡**：我们可以轻松地将流量分发到不同的实例，以防止单个实例或节点过载。负载均衡是因为 Kubernetes 的架构而自带的，非常方便。

+   **可靠性和容错性**：通过拥有应用程序的多个版本，可以防止一个或多个失败时出现问题。如果系统替换任何失败的容器，这一点尤为重要。

复制适用于许多用例，包括基于微服务的应用程序，其中多个独立的小型服务提供非常具体的功能，或者基于云原生应用程序，该应用程序基于任何组件随时可能失败的理论。 复制是实现它们的完美解决方案，因为多个实例自然适合于架构。

ReplicaSet 确保在任何给定时间运行指定数量的 Pod 克隆，称为副本。 如果有太多，它们将被关闭。 如果需要更多，例如由于错误或崩溃而死亡了一些，或者可能有更高的负载，将会启动一些更多的 Pod。 ReplicaSets 由部署使用。 让我们看看部署是什么。

# 部署

部署负责创建和更新应用程序的实例。 一旦部署已创建，Kubernetes Master 将应用程序实例调度到集群中的各个节点。 部署是一个更高级别的抽象层； 在进行 Pod 编排、创建、删除和更新时，它管理 ReplicaSets。 部署为 Pod 和 ReplicaSets 提供声明性更新。 部署允许轻松更新 Replica Set，以及能够回滚到先前的部署。

您只需指定所需的副本数量和每个 Pod 中要运行的容器，部署控制器将启动它们。 YAML 文件中的示例部署清单定义看起来与以下内容相同：

```
apiVersion: 1.0

kind: Deployment

metadata:

 name: rest_service-deployment

spec:

 replicas: 3

 template:

 metadata:

 labels:

 app: rest_service

 spec:

 containers:

 - name: rest_service

 image: rest_service

 ports:

 - containerPort: 8080

```

在前面的示例中，部署控制器将创建一个包含三个运行我们的 Java REST 服务的 Pod 的 ReplicaSet。

部署是一种控制结构，负责启动或关闭 Pod。 部署通过创建或关闭副本来管理 Pod 或一组 Pod 的状态。 部署还管理对 Pod 的更新。 部署是一个更高的抽象层，它创建 ReplicaSets 资源。 ReplicaSets 监视 Pod，并确保始终运行正确数量的副本。 当您想要更新 Pod 时，您需要修改部署清单。 此修改将创建一个新的 ReplicaSet，该 ReplicaSet 将扩展，而先前的 ReplicaSet 将缩减，从而实现应用程序的无停机部署。

部署的主要目的是进行滚动更新和回滚。滚动更新是以串行、逐个更新应用程序到新版本的过程。通过逐个更新实例，您可以保持应用程序的运行。如果您一次性更新所有实例，您的应用程序很可能会出现停机时间。此外，执行滚动更新允许您在过程中捕获错误，以便在影响所有用户之前进行回滚。

部署还允许我们轻松回滚。要执行回滚，我们只需设置要回滚到的修订版本。Kubernetes 将扩展相应的副本集并缩减当前的副本集，这将导致服务回滚到指定的修订版本。实际上，在《第八章》*使用 Java 与 Kubernetes*中，我们将大量使用部署来向集群推出服务的更新。

复制是 Kubernetes 功能的重要部分。正如您所看到的，Pod 的生命周期是脆弱且短暂的。因为 Pod 及其克隆品一直在出现和消失，我们需要一些永久和有形的东西，一些将永远存在，这样我们的应用程序用户（或其他 Pod）可以发现并调用。这就引出了 Kubernetes 服务的概念。让我们现在专注于它们。

# 服务

Kubernetes 服务将一个或多个 Pod 组合成一个内部或外部进程，需要长时间运行并且可以外部访问，例如我们的 Java REST API 端点或数据库主机。这就是我们为 Pods 分配标签非常重要的地方；服务通过寻找特定标签来查找要分组的 Pods。我们使用标签选择器来选择具有特定标签的 Pods，并将服务或副本集应用于它们。其他应用程序可以通过 Kubernetes 服务发现找到我们的服务。

服务是 Kubernetes 提供网络连接到一个或多个 Pod 的抽象。正如你从关于 Docker 网络的章节中记得的那样，默认情况下，Docker 使用主机私有网络，容器只能在它们位于同一主机上时才能相互通信。在 Kubernetes 中，集群 Pod 可以与其他 Pod 通信，无论它们降落在哪个主机上。这是可能的，因为有了服务。每个服务都有自己的 IP 地址和端口，其在服务的生命周期内保持不变。服务具有集成的负载均衡器，将网络流量分发到所有 Pod。虽然 Pod 的生命周期可能很脆弱，因为它们根据应用程序的需要被启动或关闭，但服务是一个更为持续的概念。每个 Pod 都有自己的 IP 地址，但当它死亡并且另一个被带到生活时，IP 地址可能会不同。这可能会成为一个问题--如果一组 Pod 在 Kubernetes 集群内为其他 Pod 提供功能，一个可能会丢失另一个的 IP 地址。通过分配寿命的 IP 地址，服务解决了这个问题。服务抽象实现了解耦。假设我们的 Java REST 服务运行在 Spring Boot 应用程序之上。我们需要一种方式将来自互联网的 HTTP 请求，比如`GET`或`POST`，路由到我们的 Docker 容器。我们将通过设置一个使用负载均衡器将来自公共 IP 地址的请求路由到其中一个容器的 Kubernetes 服务来实现。我们将把包含 REST 服务的容器分组到一个 Pod 中，并命名为，比如，我们的小 REST 服务。然后我们将定义一个 Kubernetes 服务，它将为我们的小 REST 服务 Pod 中的任何容器提供端口`8080`。Kubernetes 将使用负载均衡器在指定的容器之间分配流量。让我们总结一下 Kubernetes 服务的特点：

+   服务是持久和永久的

+   它们提供发现

+   它们提供负载均衡

+   它们暴露了一个稳定的网络 IP 地址

+   它们通过标签的使用来查找要分组的 Pod

我们已经说过有一个内置的服务发现机制。Kubernetes 支持两种主要的查找服务的模式：环境变量和 DNS。服务发现是找出如何连接到服务的过程。Kubernetes 包含一个专门用于此目的的内置 DNS 服务器：kube-dns。

# kube-dns

Kubernetes 提供了一个 DNS 集群附加组件，每次集群启动时都会自动启动。DNS 服务本身作为一个集群服务运行--它的 SkyDNS--一个建立在`etcd`之上的服务的公告和发现的分布式服务（您将在本章后面了解到 etcd 是什么）。它利用 DNS 查询来发现可用的服务。它支持前向查找（A 记录）、服务查找（SRV 记录）和反向 IP 地址查找（PTR 记录）。实际上，服务是 Kubernetes 分配 DNS 名称的唯一类型对象；Kubernetes 生成一个解析为服务 IP 地址的内部 DNS 条目。服务被分配一个 DNS A 记录，格式为`service-name.namespace-name.svc.cluster.local`。这将解析为服务的集群 IP。例如，对于一个名为`my-rest-service`的服务，DNS 附加组件将确保该服务通过`my-rest-service.default.svc.cluster.local`主机名对集群中的其他 Pod（和其他服务）可用。基于 DNS 的服务发现提供了一种灵活和通用的方式来连接整个集群中的服务。

请注意，当使用`hostNetwork=true`选项时，Kubernetes 将使用主机的 DNS 服务器，而不使用集群的 DNS 服务器。

在我们的 Kubernetes 之旅中，还有一个概念会不时出现--命名空间。让我们找出它的用途。

# 命名空间

命名空间在 Kubernetes 内部作为一个分组机制。Pods、卷、ReplicaSets 和服务可以在命名空间内轻松合作，但命名空间提供了与集群其他部分的隔离。这种隔离的可能用例是什么？好吧，命名空间让您在同一组机器的集群中管理不同的环境。例如，您可以在同一组机器的集群中拥有不同的测试和暂存环境。

这可能会节省一些资源在您的基础设施中，但它可能是危险的；没有命名空间，将在同一集群上运行预发布版本的软件的新版本可能会有风险。有了可用的命名空间，您可以在同一集群中对不同的环境进行操作，而不必担心影响其他环境。

因为 Kubernetes 使用`default`命名空间，所以使用命名空间是可选的，但建议使用。

我们已经解释了所有 Kubernetes 的抽象概念--我们知道有 Pods、ReplicaSets、部署和服务。现在是时候转向 Kubernetes 架构的物理执行层了。所有这些小而脆弱的 Pod 都需要存在的地方。它们存在于我们现在要了解的节点中。

# 节点

节点是 Kubernetes 架构中的工作马。它可以是虚拟机器或物理机器，这取决于您的基础设施。工作节点按照主节点的指示运行任务，我们很快会解释主节点是什么。节点（在早期的 Kubernetes 生命周期中，它们被称为 Minions）可以运行一个或多个 Pod。它们在容器化环境中提供特定于应用程序的虚拟主机。

当工作节点死机时，运行在该节点上的 Pod 也会死机。

以下图表显示了节点的内容：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-k8s-java-dev/img/Image00082.jpg)

正如您在前面的图表中所看到的，Kubernetes 中的节点内部运行着一些非常重要的进程。让我们逐一解释它们的目的。

# Kubelet

Kubelet 可能是 Kubernetes 中最重要的控制器。它是一个进程，响应来自主节点的命令（我们将在一秒钟内解释主节点是什么）。每个节点都有这个进程在监听。主节点调用它来管理 Pod 及其容器。Kubelet 运行 Pod（正如您已经知道的，它们是共享 IP 和卷的容器集合）。Kubelet（[`kubernetes.io/v1.0/docs/admin/kubelet/`](https://kubernetes.io/v1.0/docs/admin/kubelet/)）负责在单个机器上运行的内容，它有一个任务：确保所有容器都在运行。换句话说，Kubelet 是代理的名称，节点是代理运行的机器的名称。值得知道的是，每个 Kubelet 还有一个内部的`HTTP`服务器，它监听 HTTP 请求并响应简单的 API 调用以提交新的清单。

# 代理

代理是一个创建虚拟 IP 地址的网络代理，客户端可以访问该地址。网络调用将被透明地代理到 Kubernetes 服务中的 Pod。正如您已经知道的那样，服务提供了一种将 Pod 分组成单一业务流程的方式，可以在共同的访问策略下访问。通过在节点上运行代理，我们可以调用服务 IP 地址。从技术上讲，节点的代理是一个`kube-proxy` ([`kubernetes.io/docs/admin/kube-proxy/`](https://kubernetes.io/docs/admin/kube-proxy/)) 进程，它编程`iptables`规则来捕获对服务 IP 地址的访问。Kubernetes 网络代理在每个节点上运行。没有它，我们将无法访问服务。

`kube-proxy`只知道 UDP 和 TCP，不理解 HTTP，提供负载平衡，只用于访问服务。

# Docker

最后，每个节点都需要运行一些东西。这将是一个 Docker 容器运行时，负责拉取镜像并运行容器。

所有这些节点，就像现实世界中的任何其他工作人员组一样，都需要一个管理者。在 Kubernetes 中，节点管理器的角色由一个特殊的节点执行：主节点。

# 主节点

主节点不运行任何容器--它只处理和管理集群。主节点是提供集群统一视图的中央控制点。有一个单独的主节点控制多个工作节点，实际上运行我们的容器。主节点自动处理跨集群工作节点的 Pod 调度-考虑到每个节点上的可用资源。主节点的结构如下图所示：

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-k8s-java-dev/img/Image00083.jpg)

让我们逐个解析主节点，从`etcd`开始。

# etcd

Kubernetes 将其所有集群状态存储在[`etcd`](https://github.com/coreos/etcd)，这是一个具有强一致性模型的分布式数据存储。`etcd`是一个分布式、可靠的关键值存储，用于分布式系统的最关键数据，重点是：

+   **简单**：定义明确的面向用户的 API

+   **安全**：自动 TLS，可选客户端证书认证

+   **快速**：经过基准测试，每秒 10,000 次写入

+   **可靠**：使用 Raft 正确分布

这个状态包括集群中存在哪些节点，应该运行哪些 Pod，它们运行在哪些节点上，以及更多其他信息。整个集群状态存储在一个`etcd`实例中。这提供了一种可靠地存储配置数据的方式。另一个在主节点上运行的关键组件是 API 服务器。

# API 服务器

主节点上驻留的主要组件之一是 API 服务器。它非常重要，以至于有时候，您可能会发现主节点通常被称为 API 服务器。从技术上讲，它是一个名为`kube-apiserver`的进程，它接受并响应使用 JSON 的`HTTP` `REST`请求。它的主要目的是验证和配置 API 对象的数据，这些对象包括 Pod、服务、ReplicaSets 等。API 服务器通过提供集群的共享状态的前端，使所有其他组件进行交互。API 服务器是中央管理实体，是唯一连接到 etcd 的 Kubernetes 组件。所有其他组件必须通过 API 服务器来处理集群状态。我们将在第九章中详细介绍 Kubernetes API，*使用 Kubernetes API*。

主节点不运行任何容器--它只处理和管理整个集群。实际运行容器的节点是工作节点。

# 调度器

正如我们之前所说，如果您创建一个部署，主节点将安排将应用实例分布到集群中的各个节点上。一旦应用实例启动并运行，部署控制器将持续监视这些实例。这是一种自我修复机制--如果一个节点宕机或被删除，部署控制器将替换它。

现在我们知道了构成 Kubernetes 架构的特定组件是什么，让我们看看有哪些工具可供我们使用。

# 可用工具

在本书的其余部分，我们将使用一些工具。让我们从最重要的工具`kubectl`开始。

# kubectl

`kubectl`是针对 Kubernetes 集群运行命令的命令行界面。事实上，这是在使用 Kubernetes 时最常用的命令。在第八章，*使用 Java 与 Kubernetes*中，我们将介绍命令的语法和可能的用法。使用`kubectl`，您将与您的集群进行交互。当然，通过主节点和 API 服务器公开的 API，我们可以使用我们选择的`HTTP`客户端来执行，但使用`kubectl`更快速和更方便。`kubectl`提供了许多功能，例如列出资源、显示有关资源的详细信息、打印日志、管理集群以及在 Pod 中执行容器上的命令。

# 仪表板

Kubernetes 仪表板是一个漂亮、干净的基于 Web 的 UI，用于 Kubernetes 集群。使用仪表板，您可以管理和排除集群本身以及其中运行的应用程序。你可以说它是 Kubernetes 的用户界面。对于那些喜欢使用图形界面的人来说，仪表板可以是一个方便的工具，用于部署容器化应用程序并概览集群中运行的应用程序，以及创建或修改诸如部署、Pod 和服务等个别资源。例如，您可以扩展部署，启动滚动更新，重新启动 Pod，或使用部署向导部署新应用程序。我们还将在第八章，*使用 Java 与 Kubernetes*中使用仪表板。

# Minikube

运行集群似乎是一个需要大量设置的复杂过程。这并不一定是事实。实际上，在本地机器上轻松运行 Kubernetes 集群以进行学习、测试和开发是相当容易的。在 GitHub 上提供的`minikube`工具[`github.com/kubernetes/minikube`](https://github.com/kubernetes/minikube)允许您在自己的机器上设置本地集群。它适用于所有主要平台，包括 Linux、macOS 和 Windows。启动的集群当然将是单节点集群，但这已经足够开始进行实际的 Kubernetes 示例。实际上，在第八章，*使用 Java 与 Kubernetes*中，在我们开始将我们的`REST`服务部署到集群之前，我们将在本地运行 Kubernetes。

除了前面提到的之外，您可能会在互联网上找到许多其他与 Kubernetes 非常配合的工具和实用程序。

# 摘要

本章介绍了许多新概念。让我们简要总结一下我们对 Kubernetes 架构的了解。

Kubernetes（k8s）是一个用于自动化容器操作的开源平台，如部署、调度和在节点集群中扩展。使用 Kubernetes，您可以：

+   自动化部署和复制容器

+   在飞行中扩展和缩小容器

+   将容器组织成组，并在它们之间提供负载平衡

+   轻松推出应用程序容器的新版本

+   为您的应用程序提供容错机制——如果一个容器死了，它会被替换

+   Kubernetes 包括：

+   **集群**：一组节点。

+   **节点**：作为工作者的物理或虚拟机。每个节点运行 kubelet、代理和 Docker 引擎进程。

+   **主节点**：提供对集群的统一视图。它提供了 Kubernetes API 服务器。API 服务器提供了一个`REST`端点，可用于与集群交互。主节点还包括用于创建和复制 Pods 的控制器。

+   **Pods**：被调度到节点。每个 Pod 运行一个单独的容器或一组容器和卷。同一 Pod 中的容器共享相同的网络命名空间和卷，并可以使用本地主机相互通信。它们的生命是脆弱的；它们会不断诞生和死亡。

+   **标签**：Pods 具有附加的键/值对标签。标签用于精确选择 Pods。

+   **服务**：定义一组 Pods 和访问它们的策略的抽象。服务通过使用标签选择器来找到它们的 Pod 组。因为单个 Pod 的 IP 可能会改变，所以服务为其客户端提供了一个永久的 IP 地址。

这可能有点令人不知所措的理论。别担心，在第八章，*使用 Java 与 Kubernetes*中，我们将运行本地 Kubernetes 集群。我们的计划将包括使用`minikube`创建本地 Kubernetes 集群。然后，我们将使用我们的 Java REST 微服务部署和管理 Docker 容器。通过一些实际的、动手操作，Kubernetes 架构将会更加清晰。运行本地 Kubernetes 并不是我们要做的唯一的事情。稍后，在第十章，*在云中部署 Java 到 Kubernetes*中，我们将把我们的应用程序放在真正的云端——那是 Kubernetes 真正发光的地方。
