# Docker 安全手册（二）

> 原文：[`zh.annas-archive.org/md5/DF5BC22123D44CC1CDE476D1F2E35514`](https://zh.annas-archive.org/md5/DF5BC22123D44CC1CDE476D1F2E35514)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第七章：使用第三方工具保护 Docker

在本章中，让我们看看如何使用第三方工具来保护 Docker。这些工具不是 Docker 生态系统的一部分，您可以使用它们来帮助保护您的系统。我们将看看以下三个项目：

+   **流量授权**：这允许入站和出站流量由令牌代理进行验证，以确保服务之间的流量是安全的。

+   **Summon**：Summon 是一个命令行工具，它读取`secrets.yml`格式的文件，并将秘密作为环境变量注入到任何进程中。一旦进程退出，秘密就消失了。

+   **sVirt 和 SELinux**：sVirt 是一个集成**强制访问控制**（**MAC**）安全和基于 Linux 的虚拟化（**基于内核的虚拟机**（**KVM**），lguest 等）的社区项目。

然后，我们将添加一些额外的第三方工具，这些工具非常有用且功能强大，值得得到一些有用的第三方工具的认可。这些工具包括**dockersh**，**DockerUI**，**Shipyard**和**Logspout**。话不多说，让我们开始我们的道路，走向我们可以获得的最安全的环境。

# 第三方工具

那么，我们将关注哪些第三方工具？嗯，从前面的介绍中，您了解到我们将特别关注三种工具。这些将是流量授权、Summon 和带有 SELinux 的 sVirt。所有这三种工具在不同方面都有帮助，并且可以用于执行不同的任务。我们将学习它们之间的区别，并帮助您确定要实施哪些工具。您可以决定是否要全部实施它们，只实施其中一两个，或者也许您觉得这些都与您当前的环境无关。然而，了解外部工具的存在是很好的，以防您的需求发生变化，您的 Docker 环境的整体架构随时间发生变化。

## 流量授权

流量授权可用于调节服务之间的 HTTP/HTTPS 流量。这涉及到一个转发器、守门人和令牌经纪人。这允许令牌经纪人验证服务之间的流量，以确保流量的安全性。每个容器都运行一个守门人，用于拦截所有的 HTTP/HTTPS 入站流量，并从授权标头中找到的令牌验证其真实性。转发器也在每个容器上运行，与守门人一样，它也拦截流量；然而，它不是拦截入站流量，而是拦截出站流量，并将令牌放置在授权标头上。这些令牌是由令牌经纪人发出的。这些令牌也可以被缓存以节省时间并最小化延迟的影响。让我们将其分解为一系列步骤，如下所示：

1.  服务 A 发起对服务 B 的请求。

1.  服务 A 上的转发器将与令牌经纪人进行身份验证。

1.  令牌经纪人将发出一个令牌，服务 A 将应用于授权标头并将请求转发给服务 B。

1.  服务 B 的守门人将拦截请求，并将授权标头与令牌经纪人进行验证。

1.  一旦授权标头被验证，它就会被转发到服务 B。

正如您所看到的，这对入站和出站请求都应用了额外的授权。正如我们将在下一节中看到的，您还可以使用 Summon 与流量授权一起使用共享的秘密，一旦使用，这些秘密就可用，但一旦应用程序完成其操作，它们就会消失。

有关流量授权和 Docker 的更多信息，请访问[`blog.conjur.net/securing-docker-with-secrets-and-dynamic-traffic-authorization`](https://blog.conjur.net/securing-docker-with-secrets-and-dynamic-traffic-authorization)。

## Summon

Summon 是一个命令行工具，用于帮助传递秘密或不想暴露的东西，比如密码或环境变量，然后这些秘密在进程退出时被销毁。这很棒，因为一旦秘密被使用并且进程退出，秘密就不再存在了。这意味着秘密不会一直存在，直到它被手动移除或被攻击者发现并用于恶意目的。让我们看看如何利用 Summon。

Summon 通常使用三个文件：一个`secrets.yml`文件，用于执行操作或任务的脚本，以及 Dockerfile。正如您之前学到的，或者根据您当前的 Docker 经验，Dockerfile 是构建容器的基础，其中包含了如何设置容器、安装什么、配置什么等指令。

一个很好的例子是使用 Summon 来部署 AWS 凭证到一个容器中。为了使用 AWS CLI，你需要一些关键的信息，这些信息应该保密。这两个信息是你的 AWS 访问密钥 ID 和 AWS 秘密访问密钥。有了这两个信息，你就可以操纵某人的 AWS 账户并在该账户内执行操作。让我们来看看其中一个文件`secrets.yml`文件的内容：

```
secrets.yml
AWS_ACCESS_KEY_ID: !var $env/aws_access_key_id
AWS_SECRET_ACCESS_KEY: !var $env/aws_secret_access_key
```

`-D`选项用于替换值，而`$env`是一个替换变量的例子，因此，选项可以互换使用。

在前面的内容中，我们可以看到我们想要将这两个值传递给我们的应用程序。有了这个文件、您想要部署的脚本文件和 Dockerfile，您现在可以构建您的应用程序了。

我们只需在包含这三个文件的文件夹中使用`docker build`命令：

```
$ docker build -t scottpgallagher/aws-deploy .

```

接下来，我们需要安装 Summon，可以通过一个简单的`curl`命令来完成：

```
$ curl -sSL https://raw.githubusercontent.com/conjurinc/summon/master/install.sh | bash

```

现在我们安装了 Summon，我们需要使用 Summon 运行容器，并传递我们的秘密值（请注意，这只适用于 OS X）：

```
$ security add-generic-password -s "summon" -a "aws_access_key_id" -w "ACESS_KEY_ID"
$ security add-generic-password -s "summon" -a "aws_secret_access_key" -w "SECRET_ACCESS_KEY"

```

现在我们准备使用 Summon 运行 Docker，以便将这些凭证传递给容器：

```
$ summon -p ring.py docker run —env-file @ENVFILE aws-deploy

```

您还可以使用以下`cat`命令查看您传递的值：

```
$ summon -p ring.py cat @SUMMONENVFILE
aws_access_key_id=ACESS_KEY_ID
aws_secret_access_key=SECRET_ACCESS_KEY

```

`@SUMMONENVFILE`是一个内存映射文件，其中包含了`secrets.yml`文件中的值。

有关更多信息和其他使用 Summon 的选项，请访问[`conjurinc.github.io/summon/#examples`](https://conjurinc.github.io/summon/#examples)。

## sVirt 和 SELinux

sVirt 是 SELinux 实现的一部分，但通常被关闭，因为大多数人认为它是一个障碍。唯一的障碍应该是学习 sVirt 和 SELinux。

sVirt 是一个实现 Linux 基于虚拟化的 MAC 安全性的开源社区项目。您希望实现 sVirt 的一个原因是为了提高安全性，以及加固系统防止可能存在于 hypervisor 中的任何错误。这将有助于消除可能针对虚拟机或主机的任何攻击向量。

请记住，Docker 主机上的所有容器共享运行在 Docker 主机上的 Linux 内核的使用权。如果主机上的 Linux 内核存在漏洞，那么在该 Docker 主机上运行的所有容器都有可能很容易地受到威胁。如果您实施了 sVirt 并且容器受到了威胁，那么威胁无法传播到您的 Docker 主机，然后传播到其他 Docker 容器。

sVirt 与 SELinux 一样利用标签。以下表格列出了这些标签及其描述：

| 类型 | SELinux 上下文 | 描述 |
| --- | --- | --- |
| 虚拟机进程 | `system_u:system_r:svirt_t:MCS1` | `MCS1`是一个随机选择的 MCS 字段。目前，大约支持 50 万个标签。 |
| 虚拟机镜像 | `system_u:object_r:svirt_image_t:MCS1` | 只有具有相同 MCS 字段的标记为`svirt_t`的进程才能读/写这些镜像文件和设备。 |
| 虚拟机共享读/写内容 | `system_u:object_r:svirt_image_t:s0` | 所有标记为`svirt_t`的进程都被允许写入`svirt_image_t:s0`文件和设备。 |
| 虚拟机镜像 | `system_u:object_r:virt_content_t:s0` | 这是镜像退出时使用的系统默认标签。不允许`svirt_t`虚拟进程读取带有此标签的文件/设备。 |

# 其他第三方工具

本章还有一些其他值得一提的第三方工具，值得探索，看看它们对您能够增加的价值。似乎如今，很多关注点都放在了用于帮助保护应用程序和基础设施的图形界面应用程序上。以下实用程序将为您提供一些可能与您正在使用 Docker 工具的环境相关的选项。

### 注意

请注意，在实施以下某些项目时应谨慎，因为可能会产生意想不到的后果。在生产实施之前，请务必在测试环境中使用。

## dockersh

dockersh 旨在用作支持多个交互式用户的机器上的登录 shell 替代品。为什么这很重要？如果您记得在处理 Docker 主机上的 Docker 容器时遇到的一些一般安全警告，您将知道谁可以访问 Docker 主机就可以访问该 Docker 主机上运行的所有容器。使用 dockersh，您可以按容器隔离用户，并且只允许用户访问您希望他们访问的容器，同时保持对 Docker 主机的管理控制，并将安全门槛降至最低。

这是一种理想的方法，可以在每个容器的基础上帮助隔离用户，同时容器有助于通过使用 dockersh 消除对 SSH 的需求，您可以消除一些关于提供所有需要容器访问权限的人访问 Docker 主机的担忧。设置和调用 dockersh 需要大量信息，因此，如果您感兴趣，建议访问以下网址，了解有关 dockersh 的更多信息，包括如何设置和使用它：

[`github.com/Yelp/dockersh`](https://github.com/Yelp/dockersh)

## DockerUI

DockerUI 是查看 Docker 主机内部情况的简单方法。安装 DockerUI 非常简单，只需运行一个简单的`docker run`命令即可开始：

```
$ docker run -d -p 9000:9000 --privileged -v /var/run/docker.sock:/var/run/docker.sock dockerui/dockerui

```

要访问 DockerUI，只需打开浏览器并导航到以下链接：

`http://<docker_host_ip>:9000`

这将在端口`9000`上打开您的 DockerUI，如下面的截图所示：

![DockerUI](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/sec-dkr/img/00010.jpeg)

您可以获得有关 Docker 主机及其生态系统的一般高级视图，并可以执行诸如从停止状态重新启动、停止或启动 Docker 主机上的容器等操作。DockerUI 将运行命令行项的陡峭学习曲线转化为您在 Web 浏览器中使用点和点击执行的操作。

有关 DockerUI 的更多信息，请访问[`github.com/crosbymichael/dockerui`](https://github.com/crosbymichael/dockerui)。

## Shipyard

Shipyard，就像 DockerUI 一样，允许您使用 GUI Web 界面来管理各种方面——主要是在您的容器中——并对其进行操作。Shipyard 是建立在 Docker Swarm 之上的，因此您可以利用 Docker Swarm 的功能集，从而可以管理多个主机和容器，而不仅仅是专注于一台主机及其容器。

使用 Shipyard 非常简单，以下`curl`命令再次出现：

```
$ curl -sSL https://shipyard-project.com/deploy | bash -s

```

一旦设置完成，要访问 Shipyard，您只需打开浏览器并导航到以下链接：

`http://<docker_host_ip>:8080`

正如我们在下面的屏幕截图中所看到的，我们可以查看我们的 Docker 主机上的所有容器：

![Shipyard](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/sec-dkr/img/00011.jpeg)

我们还可以查看位于我们的 Docker 主机上的所有图像，如下面的屏幕截图所示：

![Shipyard](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/sec-dkr/img/00012.jpeg)

我们还可以控制我们的容器，如下面的屏幕截图所示：

![Shipyard](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/sec-dkr/img/00013.jpeg)

Shipyard，就像 DockerUI 一样，允许您操作 Docker 主机和容器，重新启动它们，停止它们，从失败状态启动它们，或者部署新容器并使其加入 Swarm 集群。Shipyard 还允许您查看诸如端口映射信息之类的信息，即主机的哪个端口映射到容器。这使您能够在需要时快速获取重要信息，以解决任何安全相关问题。Shipyard 还具有用户管理功能，而 DockerUI 则缺乏此功能。

有关 Shipyard 的更多信息，请访问以下网址：

+   [`github.com/shipyard/shipyard`](https://github.com/shipyard/shipyard)

+   [`shipyard-project.com`](http://shipyard-project.com)

## Logspout

当出现需要解决的问题时，您会去哪里？大多数人首先会查看该应用程序的日志，以查看是否输出了任何错误。有了 Logspout，对于许多运行中的容器，这将成为一个更易管理的任务。使用 Logspout，您可以将每个容器的所有日志路由到您选择的位置。然后，您可以在一个地方解析这些日志。您可以让 Logspout 为您完成这项工作，而不必从每个容器中提取日志并逐个审查它们。

Logspout 的设置与我们在其他第三方解决方案中看到的一样简单。只需在每个 Docker 主机上运行以下命令即可开始收集日志：

```
$ docker run --name="logspout" \
--volume=/var/run/docker.sock:/tmp/docker.sock \
--publish=127.0.0.1:8000:8080 \
gliderlabs/logspout

```

现在我们已经将所有容器日志收集到一个区域，我们需要解析这些日志，但是该如何做呢？

```
$ curl http://127.0.0.1:8000/logs

```

这里又是`curl`命令拯救的时候了！日志以容器名称为前缀，并以一种方式进行着色，以区分日志。您可以将`docker run`调用中的回环（`127.0.0.1`）地址替换为 Docker 主机的 IP 地址，以便更容易连接，以便能够获取日志，并将端口从`8000`更改为您选择的端口。还有不同的模块可以用来获取和收集日志。

有关 Logspout 的更多信息，请访问[`github.com/gliderlabs/logspout`](https://github.com/gliderlabs/logspout)。

# 总结

在本章中，我们看了一些第三方工具，以帮助确保 Docker 环境的安全。主要是我们看了三个工具：Traffic Authorization、Summon 和带有 SELinux 的 sVirt。这三个工具可以以不同的方式被利用，以帮助确保您的 Docker 环境，让您在一天结束时放心地在 Docker 容器中运行应用程序。我们了解了除 Docker 提供的工具之外，还有哪些第三方工具可以帮助确保您的环境，在 Docker 上运行应用程序时保持安全。

然后，我们看了一些其他第三方工具。鉴于您的 Docker 环境设置，这些额外的工具对一些人来说是值得的。其中一些工具包括 dockersh、DockerUI、Shipyard 和 Logsprout。这些工具在小心应用时，可以为 Docker 配置的整体安全性增加额外的增强。

在下一章中，我们将讨论如何保持安全。在当今安全问题如此严峻的情况下，有时很难知道在哪里寻找更新的信息并能够快速应用修复措施。

您将学会帮助强化将安全性放在首要位置的想法，并订阅诸如电子邮件列表之类的内容，这些内容不仅包括 Docker，还包括与您在 Linux 上运行的环境相关的内容。其他内容包括跟踪与 Docker 安全相关的 GitHub 问题，参与 IRC 聊天室的讨论，并关注 CVE 等网站。


# 第八章：保持安全

在本章中，我们将看一下与 Docker 相关的安全问题。您可以通过哪些方式帮助自己及时了解您目前正在运行的 Docker 工具版本的安全问题？如何在任何安全问题出现时保持领先，并确保您的环境安全？在本章中，我们将看一下多种方式，您可以及时了解任何出现的安全问题，以及尽快获取信息的最佳方式。您将学习如何帮助强化将安全放在首要位置的想法，并订阅诸如电子邮件列表之类的内容，其中不仅包括 Docker，还包括与您正在运行的 Linux 环境相关的项目。其他项目包括跟进与 Docker 安全相关的 GitHub 问题，关注**Internet Relay Chat** (**IRC**)聊天室，以及观察 CVE 等网站。

在本章中，我们将涵盖以下主题：

+   跟上安全问题

+   电子邮件列表选项

+   GitHub 问题

+   IRC 聊天室

+   CVE 网站

+   其他感兴趣的领域

# 跟上安全问题

在这一部分，我们将看一下您可以获取或了解与 Docker 产品可能出现的安全问题相关的信息的多种方式。虽然这并不是您可以用来跟进问题的工具的完整列表，但这是一个很好的开始，包括最常用的项目。这些项目包括电子邮件分发列表，关注 Docker 的 GitHub 问题，多个 Docker 产品的 IRC 聊天室，CVE 网站等等，以及其他感兴趣的领域，可以关注与 Docker 产品相关的事项，比如 Linux 内核漏洞和其他可以用来减轻风险的项目。

## 电子邮件列表选项

Docker 运营两个邮件列表，用户可以注册加入。这些邮件列表提供了收集有关问题或其他人正在处理的项目的信息的方式，并激发您的想法，让您在自己的环境中做同样的事情。您还可以使用它们来帮助 Docker 社区提出您在使用各种 Docker 产品或与 Docker 产品相关的其他产品时遇到的问题或问题。

### 这两个电子邮件列表如下：

+   Docker-dev

+   Docker-user

Docker-dev 邮件列表主要面向什么？你猜对了，它主要面向开发人员！这些人要么对开发人员类型的角色感兴趣，想了解其他人正在开发什么，要么他们自己正在为可能集成到各种 Docker 产品中的某些东西开发代码。这可能是创建一个围绕 Docker Swarm 的 Web 界面之类的东西。这个列表将是你想要发布问题的地方。该列表包括其他开发人员，甚至可能包括在 Docker 工作的人，他们可能能够帮助您解决任何问题或困难。

另一个列表，Docker-user 列表，面向各种 Docker 产品或服务的用户，并对如何使用产品/服务或如何将第三方产品与 Docker 集成等问题提出疑问。这可能包括如何将 Heroku 与 Docker 集成或在云中使用 Docker。如果你是 Docker 的用户，那么这个列表就是适合你的。如果你有高级经验，或者列表上出现了你有经验或之前处理过的问题，你也可以为列表做出贡献。

没有规定你不能同时加入两个列表。如果你想兼得两全，你可以同时注册两个列表，评估每个列表的流量，然后根据你的兴趣决定只加入一个。你也可以选择不加入列表，只在 Google Groups 页面上关注它们。

Docker-dev 列表的 Google Groups 页面是[`groups.google.com/forum/#!forum/docker-dev`](https://groups.google.com/forum/#!forum/docker-dev)，而 Docker-user 列表的 Google Groups 页面是[`groups.google.com/forum/#!forum/docker-user`](https://groups.google.com/forum/#!forum/docker-user)。

不要忘记你也可以通过这些列表搜索，看看你的问题或疑问是否已经得到解答。由于本书是关于安全性的，不要忘记你可以使用这两个邮件列表讨论与安全相关的问题，无论是开发还是用户相关的。

## GitHub 问题

跟踪与安全相关问题的另一种方法是关注 GitHub 的问题。由于 Docker 核心和其他各种 Docker 部分（如 Machine、Swarm、Compose 等）的所有代码都存储在 GitHub 上，它提供了一个区域。您现在可能正在问自己 GitHub 问题到底是什么，为什么我要关心它们。GitHub Issues 是 GitHub 使用的缺陷跟踪系统。通过跟踪这些问题，您可以查看其他人正在经历的问题，并在自己的环境中超前解决它们，或者可以解决您的环境中的问题，知道其他人也遇到了同样的问题，而不仅仅是您的问题。您可以停止拔剩下的头发了。

由于每个 GitHub 存储库都有自己的问题部分，我们不需要查看每个问题部分，但我认为值得查看一个存储库的问题部分，以便了解您正在查看的内容，以帮助解释所有这些。

以下截图（可在[`github.com/docker/docker/issues`](https://github.com/docker/docker/issues)找到）显示了 Docker 核心软件代码中存在的所有当前问题：

![GitHub issues](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/sec-dkr/img/00014.jpeg)

从这个屏幕上，我们不仅可以看到有多少问题是开放的，还可以知道有多少已经关闭。这些问题曾经是问题，为它们找到了解决方案，现在它们已经关闭了。关闭的问题是为了历史目的而存在，以便能够回到过去，看看可能已经提供了什么解决方案来解决问题。

在下面的截图中，我们可以根据作者对问题进行过滤，即提交问题的人：

![GitHub issues](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/sec-dkr/img/00015.jpeg)

在下面的截图中，我们还可以根据标签对问题进行过滤，这些标签可能包括**api**、**kernel**、**apparmor**、**selinux**、**aufs**等等：

![GitHub issues](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/sec-dkr/img/00016.jpeg)

在下面的截图中，我们可以看到我们还可以按里程碑进行过滤：

![GitHub issues](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/sec-dkr/img/00017.jpeg)

里程碑本质上是标签，用于根据特定目的解决问题。它们也可以用于计划即将发布的版本。正如我们在这里看到的，其中一些包括**Windows TP4**和**Windows TP5**。

最后，我们可以根据受让人对问题进行过滤，即被指定解决或处理问题的人，如下面的截图所示：

![GitHub issues](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/sec-dkr/img/00018.jpeg)

正如我们所看到的，有很多方法可以过滤问题，但问题实际上是什么样子的，它包含了什么？让我们在下一节中看看。

在接下来的截图中，我们可以看到一个实际问题是什么样子的：

![GitHub issues](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/sec-dkr/img/00019.jpeg)

我们可以看到的一些信息是问题的标题和唯一的问题编号。然后我们可以看到这个特定问题是开放的，报告问题的人，以及它已经开放了多长时间。然后我们可以看到问题上有多少评论，然后是问题本身的详细解释。在右侧，我们可以看到问题有哪些标签，它的里程碑是什么，它分配给谁，以及有多少参与者参与了这个问题。参与的人是以某种方式对问题进行了评论的人。

在上一张图片中，也就是在前一张图片的底部，我们可以看到问题的时间轴，比如它被分配给谁以及何时，以及何时为其分配了标签和任何额外的评论。

![GitHub issues](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/sec-dkr/img/00020.jpeg)

## IRC 房间

首先要理解的是 IRC 究竟是什么。如果你回想一下旧日子，我们可能都有一些形式的 IRC 房间，当我们使用 AOL 时，有聊天室，你可以根据你的位置或主题加入。IRC 的运作方式与此类似，有一个服务器，客户端（比如你自己）连接到这个服务器。这些房间通常基于一个主题、产品或服务，人们可以共同讨论。你可以作为一个团体进行聊天，但也可以与同一房间或频道中的其他人进行私人聊天。

Docker 利用 IRC 讨论其产品。这不仅允许产品的最终用户参与讨论，而且在 Docker 的情况下，大多数实际上为 Docker 工作并且在这些产品上工作的人通常每天都会在这些房间中，并且会与您讨论您可能遇到的问题或您可能有的问题。

使用 IRC，有多个服务器可以用来连接到托管的频道。Docker 使用[`freenode.net`](http://freenode.net)服务器（如果您要使用第三方客户端连接到 IRC，这是您将使用的服务器；但是，您也可以使用[`webchat.freenode.net`](http://webchat.freenode.net)），然后他们所有产品的频道都是**#docker**、**#docker-dev**、**#docker-swarm**、**#docker-compose**和**#docker-machine**等。所有频道都以井号（#）开头，后面跟着频道名称。在这些频道中，每个产品都有讨论。除了这些频道，还有其他频道可以讨论与 Docker 相关的主题。在上一章中，我们讨论了 Shipyard 项目，它允许您在 Docker Swarm 环境的顶部叠加 GUI 界面。如果您对这个特定产品有疑问，您可以加入该产品的频道，即**#shipyard**。您也可以加入其他频道，每天都会有更多的频道被创建。要获取频道列表，您需要连接到 IRC 客户端并发出命令。请按照给定的链接查看如何执行此操作：

[`irc.netsplit.de/channels/?net=freenode`](http://irc.netsplit.de/channels/?net=freenode)

每个频道也保留了聊天存档，因此，您也可以搜索其中的内容，以了解是否正在围绕您可能遇到的问题或问题进行讨论。例如，如果您想查看**#docker**频道的日志，您可以在这里找到：

[`botbot.me/freenode/docker/`](https://botbot.me/freenode/docker/)

您可以在以下网站上搜索其他频道存档：

[`botbot.me`](https://botbot.me)

## CVE 网站

在第五章中，*监控和报告 Docker 安全事件*，我们介绍了 CVE 和 Docker CVE。关于它们的一些要记住的事情列在以下内容中：

+   CVE 可以在[`cve.mitre.org/index.html`](https://cve.mitre.org/index.html)找到

+   与 Docker 相关的 CVE 可以在[`www.docker.com/docker-cve-database`](https://www.docker.com/docker-cve-database)找到

+   要搜索 CVE，请使用以下 URL：[`cve.mitre.org/index.html`](https://cve.mitre.org/index.html)

+   如果您从上述链接打开此 CVE，您将看到它汇集了一些信息，如下所示：

+   CVE ID

+   描述

+   参考资料

+   日期输入创建

+   阶段

+   投票

+   评论

+   建议

# 其他感兴趣的领域

在安全方面，有一些您应该牢记的领域。Linux 内核，正如我们在本书中经常谈到的那样，是 Docker 生态系统的关键部分。因此，尽可能保持内核最新是非常重要的。关于更新，同样重要的是保持您使用的 Docker 产品也是最新的。大多数更新包括安全更新，因此在发布新产品更新时应该进行更新。

Twitter 已经成为社交热点，当您想要推广您的产品时，Docker 也是如此。Docker 有一些用于不同目的的账户，它们列在以下。根据您使用的 Docker 的部分，最好关注其中一个或全部，如下列表所示：

+   **@docker**

+   **@dockerstatus**

+   **@dockerswarm**

+   **@dockermachine**

Twitter 还利用标签将推文分组在一起，基于它们的标签。对于 Docker，情况也是如此，它们使用#docker 标签，您可以在 Twitter 上搜索这个标签，以汇集所有关于 Docker 的推文。

最后我们要讨论的是 Stack Overflow。Stack Overflow 是一个问答网站，使用投票来推广提供帮助的答案，以帮助您以最快的方式获得最佳答案。Stack Overflow 利用类似 Twitter 的方法对问题进行标记，这样您就可以搜索特定主题的所有问题。以下是一个链接，您可以使用它来汇集所有 Docker 问题进行搜索：

[`stackoverflow.com/questions/tagged/docker`](http://stackoverflow.com/questions/tagged/docker)

当您访问 URL 时，您将看到一系列问题，以及每个问题的投票数、回答数、浏览数，以及其中一些问题上的绿色勾号。被勾选的答案是提问者标记为被接受的答案，意味着它是最佳答案。一些监控 Docker 问题的人是为 Docker 工作的人，他们在幕后工作并提供最佳答案，因此，这是一个提出任何可能问题的好地方。

# 总结

在本章中，我们看了如何跟上与安全相关的问题，这些问题不仅涉及到您现在或将来可能运行的 Docker 产品，还涉及到诸如内核问题之类的安全问题。由于 Docker 依赖于主机上的内核来运行所有的 Docker 容器，因此内核非常重要。我们看了多个您可以注册的邮件列表，以此方式获取通知。加入 IRC 聊天室并关注 GitHub 上与安全相关或当前不起作用的问题，可能会影响您的环境。在部署任何东西时，始终将安全放在首位非常重要，虽然 Docker 本身是安全的，但总会有人利用任何漏洞，因此，请尽量保持所有环境的安全和最新状态。
