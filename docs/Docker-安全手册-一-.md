# Docker 安全手册（一）

> 原文：[`zh.annas-archive.org/md5/DF5BC22123D44CC1CDE476D1F2E35514`](https://zh.annas-archive.org/md5/DF5BC22123D44CC1CDE476D1F2E35514)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 前言

Docker 是当今技术中最热门的词汇！本书帮助您确保您在 Docker 工具生态系统中保护所有部分。如今，保持数据和系统的安全性至关重要，而使用 Docker 也不例外。了解 Docker 如何固有地安全，并如何进一步保护其周围的部分，并密切关注潜在的漏洞。

# 本书涵盖内容

第一章, *保护 Docker 主机*, 通过讨论如何保护您的 Docker 环境的第一部分来开始本书，即通过关注您的 Docker 主机。 Docker 主机是您的容器将在其上运行的平台。如果不先保护这些，就像把家门大开一样。

第二章, *保护 Docker 组件*, 侧重于保护 Docker 的组件，例如您可以使用的注册表，运行在您的主机上的容器，以及如何签署您的镜像。

第三章, *保护和加固 Linux 内核*, 解释了现有的加固指南以及您可以使用的不同安全措施/方法，以帮助保护用于运行容器的内核，因为保护它很重要。

第四章, *Docker 安全基准*, 告诉您您已经如何设置了 Docker 环境与 Docker 安全基准应用程序，获得建议，告诉您应该立即解决的问题，以及您现在不必解决的问题，但应该保持警惕。

第五章，“监控和报告 Docker 安全事件”，介绍了如何及时了解 Docker 发布的安全发现，以帮助您了解您的环境。此外，我们还将介绍如何安全地报告您发现的任何安全问题，以确保 Docker 有机会在问题公开和普遍化之前缓解这些问题。

第六章，“使用 Docker 内置安全功能”，介绍了使用 Docker 工具来帮助保护您的环境。我们将全面介绍这些工具，为您提供 Docker 本身提供的基线。您可以了解可以用于安全需求的命令行和图形界面工具。

第七章，“使用第三方工具保护 Docker”，介绍了可用于帮助您保护 Docker 环境的第三方工具。您将了解命令行，但我们将重点关注第三方工具。我们将介绍流量授权、召唤和 SELinux 中的 sVirt。

第八章，“保持安全”，解释了您可以使用的手段，以及如何及时了解与您目前正在运行的 Docker 工具版本相关的安全问题，如何在安全问题出现之前保持领先，并确保您的环境安全。

# 本书所需的内容

本书将指导您安装所需的任何工具。您需要安装 Windows、Mac OS 或 Linux 系统；最好是后者，并且需要互联网连接。

# 本书适合对象

本书适用于将使用 Docker 作为测试平台的开发人员，以及对保护 Docker 容器感兴趣的安全专业人员。读者必须熟悉 Docker 的基础知识。

# 惯例

在本书中，您将找到许多文本样式，用于区分不同类型的信息。以下是这些样式的一些示例及其含义的解释。

文本中的代码词、数据库表名、文件夹名、文件名、文件扩展名、路径名、虚拟 URL、用户输入和 Twitter 用户名显示如下："您将需要`之前输入的密码短语`来获取`ca-key.pem`。"

任何命令行输入或输出都会以以下方式书写：

```
$ docker run -it scottpgallagher/chef-server /bin/bash

```

新术语和重要单词以粗体显示。您在屏幕上看到的单词，例如在菜单或对话框中，会以这种方式出现在文本中："下一节，**安全**设置，可能是最重要的之一。"

### 注意

警告或重要说明会出现在这样的框中。

### 提示

提示和技巧会以这种方式出现。


# 第一章：保护 Docker 主机

欢迎来到*Securing Docker*书籍！我们很高兴您决定阅读这本书，我们希望确保您使用的资源得到适当的保护，以确保系统完整性和数据丢失预防。了解为什么您应该关心安全性也很重要。如果数据丢失预防还没有吓到您，那么考虑最坏的情况——整个系统被攻破，您的机密设计可能被泄露或被他人窃取——可能有助于加强安全性。在本书中，我们将涵盖许多主题，以帮助您安全地设置环境，以便您可以放心地开始部署容器，知道您在开始时采取了正确的步骤来加强您的环境。在本章中，我们将着眼于保护 Docker 主机，并将涵盖以下主题：

+   Docker 主机概述

+   讨论 Docker 主机

+   虚拟化和隔离

+   Docker 守护程序的攻击面

+   保护 Docker 主机

+   Docker Machine

+   SELinux 和 AppArmor

+   自动修补主机

# Docker 主机概述

在我们深入研究之前，让我们先退一步，确切地了解 Docker 主机是什么。在本节中，我们将查看 Docker 主机本身，以了解我们在谈论 Docker 主机时指的是什么。我们还将研究 Docker 使用的虚拟化和隔离技术，以确保安全性。

# 讨论 Docker 主机

当我们想到 Docker 主机时，我们会想到什么？如果用我们几乎都熟悉的虚拟机来说，让我们看看典型的 VM 主机与 Docker 主机有何不同。**VM 主机**是虚拟机实际运行在其上的地方。通常情况下，如果您使用 VMware，则是**VMware ESXi**，如果您使用**Hyper-V**，则是**Windows Server**。让我们来看看它们的比较，以便您可以对两者有一个视觉上的表示，如下图所示：

![讨论 Docker 主机](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/sec-dkr/img/00002.jpeg)

上图描述了 VM 主机和 Docker 主机之间的相似之处。如前所述，任何服务的主机只是底层虚拟机或 Docker 容器运行的系统。因此，主机是包含和操作您安装和设置服务的底层系统的操作系统或服务，例如 Web 服务器、数据库等。

# 虚拟化和隔离

了解如何保护 Docker 主机之前，我们必须首先了解 Docker 主机是如何设置以及 Docker 主机中包含哪些项目。与 VM 主机一样，它们包含底层服务运行的操作系统。对于 VM，您正在在 VM 主机操作系统之上创建一个全新的操作系统。然而，在 Docker 上，您并没有这样做，而是共享 Docker 主机正在使用的 Linux 内核。让我们看一下以下图表，以帮助我们表示这一点：

![虚拟化和隔离](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/sec-dkr/img/00003.jpeg)

从上图中可以看出，VM 主机和 Docker 主机上的项目设置方式有明显的区别。在 VM 主机上，每个虚拟机都有其自己的项目。每个容器化应用程序都带有自己的一套库，无论是 Windows 还是 Linux。现在，在 Docker 主机上，我们看不到这一点。我们看到它们共享 Docker 主机上正在使用的 Linux 内核版本。也就是说，Docker 主机方面需要解决一些安全方面的问题。现在，在 VM 主机方面，如果某个虚拟机受到了损害，操作系统只是隔离在那一个虚拟机中。回到 Docker 主机方面，如果 Docker 主机上的内核受到了损害，那么运行在该主机上的所有容器也会面临很高的风险。

因此，现在您应该明白了，当涉及到 Docker 主机时，我们专注于安全是多么重要。Docker 主机确实使用了一些隔离技术，可以在一定程度上保护免受内核或容器受损。其中两种方式是通过实施命名空间和 cgroups。在讨论它们如何帮助之前，让我们先给出它们的定义。

内核命名空间，通常被称为，为在主机上运行的容器提供一种隔离形式。这意味着什么？这意味着你在 Docker 主机上运行的每个容器都将被赋予自己的网络堆栈，以便它不会特权访问另一个容器的套接字或接口。然而，默认情况下，所有 Docker 容器都位于桥接接口上，以便它们可以轻松地相互通信。将桥接接口视为所有容器连接到的网络交换机。

命名空间还为进程和挂载点提供隔离。在一个容器中运行的进程不能影响或甚至看到在另一个 Docker 容器中运行的进程。挂载点的隔离也是基于每个容器的。这意味着一个容器上的挂载点不能看到或与另一个容器上的挂载点进行交互。

另一方面，控制组是控制和限制将在 Docker 主机上运行的容器资源的工具。这归结为什么，意味着它将如何使你受益？这意味着 cgroups，它们将被称为，帮助每个容器获得其公平份额的内存磁盘 I/O，CPU 等等。因此，一个容器不能通过耗尽其上可用的所有资源来使整个主机崩溃。这将有助于确保即使一个应用程序表现不佳，其他容器也不会受到这个应用程序的影响，你的其他应用程序可以保证正常运行时间。

# Docker 守护程序的攻击面

虽然 Docker 确实简化了虚拟化领域的一些复杂工作，但很容易忘记考虑在 Docker 主机上运行容器的安全影响。您需要注意的最大问题是 Docker 需要 root 权限才能运行。因此，您需要知道谁可以访问您的 Docker 主机和 Docker 守护程序，因为他们将完全管理您 Docker 主机上的所有 Docker 容器和镜像。他们可以启动新容器，停止现有容器，删除镜像，拉取新镜像，甚至通过向其中注入命令来重新配置正在运行的容器。他们还可以从容器中提取密码和证书等敏感信息。因此，如果确实需要对谁可以访问您的 Docker 守护程序进行分开控制，还需要确保分开重要的容器。这适用于需要访问运行容器的 Docker 主机的人。如果用户需要 API 访问，则情况就不同了，可能不需要分开。例如，将敏感的容器保留在一个 Docker 主机上，而将正常运行的容器保留在另一个 Docker 主机上，并授予其他员工对非特权主机上的 Docker 守护程序的访问权限。如果可能的话，还建议取消将在主机上运行的容器的 setuid 和 setgid 功能。如果要运行 Docker，建议只在此服务器上使用 Docker 而不是其他应用程序。Docker 还以非常受限的功能集启动容器，这有利于解决安全问题。

### 注意

要在启动 Docker 容器时取消 setuid 或 setgid 功能，您需要做类似以下操作：

```
$ docker run -d --cap-drop SETGID --cap-drop SETUID nginx

```

这将启动`nginx`容器，并且会为容器取消`SETGID`和`SETUID`的功能。

Docker 的最终目标是将根用户映射到 Docker 主机上存在的非根用户。他们还致力于使 Docker 守护程序能够在不需要 root 权限的情况下运行。这些未来的改进将有助于简化 Docker 在实施其功能集时所需的关注度。

## 保护 Docker 守护程序

为了进一步保护 Docker 守护程序，我们可以保护 Docker 守护程序正在使用的通信。我们可以通过生成证书和密钥来实现这一点。在我们深入创建证书和密钥之前，有一些术语需要理解。**证书颁发机构**（**CA**）是颁发证书的实体。该证书证明了主体对公钥的所有权。通过这样做，我们可以确保您的 Docker 守护程序只接受由相同 CA 签署的证书的其他守护程序的通信。

现在，我们将看一下如何确保您在 Docker 主机上运行的容器将在接下来的几页中是安全的；然而，首先，您需要确保 Docker 守护程序在安全运行。为此，您需要在守护程序启动时启用一些参数。您需要预先准备一些东西，如下所示：

1.  创建 CA。

```
$ openssl genrsa -aes256 -out ca-key.pem 4096
Generating RSA private key, 4096 bit long modulus
......................................................................................................................................................................................................................++
....................................................................++
e is 65537 (0x10001)
Enter pass phrase for ca-key.pem:
Verifying - Enter pass phrase for ca-key.pem:

```

您需要指定两个值，`密码短语`和`密码短语`。这需要在`4`和`1023`个字符之间。少于`4`或多于`1023`的字符将不被接受。

```
$ openssl req -new -x509 -days <number_of_days> -key ca-key.pem -sha256 -out ca.pem
Enter pass phrase for ca-key.pem:
You are about to be asked to enter information that will be incorporated
into your certificate request.
What you are about to enter is what is called a Distinguished Name or a DN.
There are quite a few fields but you can leave some blank
For some fields there will be a default value,
If you enter '.', the field will be left blank.
-----
Country Name (2 letter code) [AU]:US
State or Province Name (full name) [Some-State]:Pennsylvania
Locality Name (eg, city) []:
Organization Name (eg, company) [Internet Widgits Pty Ltd]:
Organizational Unit Name (eg, section) []:
Common Name (e.g. server FQDN or YOUR name) []:
Email Address []:

```

您将需要一些项目。您需要之前输入的`密码短语`用于`ca-key.pem`。您还需要`国家`、`州`、`城市`、`组织名称`、`组织单位名称`、**完全限定域名**（**FQDN**）和`电子邮件地址`以完成证书。

1.  创建客户端密钥和签名证书。

```
$ openssl genrsa -out key.pem 4096
$ openssl req -subj '/CN=<client_DNS_name>' -new -key key.pem -out client.csr

```

1.  签署公钥。

```
$ openssl x509 -req -days <number_of_days> -sha256 -in client.csr -CA ca.pem -CAkey ca-key.pem -CAcreateserial -out cert.em

```

1.  更改权限。

```
$ chmod -v 0400 ca-key.pem key.pem server-key.em
$ chmod -v 0444 ca.pem server-cert.pem cert.em
```

现在，您可以确保您的 Docker 守护程序只接受来自您提供签署证书的其他 Docker 主机的连接：

```
$ docker daemon --tlsverify --tlscacert=ca.pem --tlscert=server-certificate.pem --tlskey=server-key.pem -H=0.0.0.0:2376
```

确保证书文件位于您运行命令的目录中，否则您需要指定证书文件的完整路径。

在每个客户端上，您需要运行以下命令：

```
$ docker --tlsverify --tlscacert=ca.pem --tlscert=cert.pem --tlskey=key.pem -H=<$DOCKER_HOST>:2376 version

```

再次强调，证书的位置很重要。确保它们位于您计划运行前述命令的目录中，或者指定证书和密钥文件位置的完整路径。

您可以通过访问以下链接了解如何默认情况下在 Docker 守护程序中使用**传输层安全**（**TLS**）：

[`docs.docker.com/engine/articles/https/`](http://docs.docker.com/engine/articles/https/)

有关**Docker 安全部署指南**的更多阅读，以下链接提供了一个表格，可以用来深入了解您还可以利用的其他一些项目：

[`github.com/GDSSecurity/Docker-Secure-Deployment-Guidelines`](https://github.com/GDSSecurity/Docker-Secure-Deployment-Guidelines)

该网站的一些亮点包括：

+   收集安全和审计日志

+   在运行 Docker 容器时使用特权开关

+   设备控制组

+   挂载点

+   安全审计

# 保护 Docker 主机

我们从哪里开始保护我们的主机？我们需要从哪些工具开始？我们将在本节中使用 Docker Machine，以及如何确保我们创建的主机是以安全的方式创建的。Docker 主机就像您房子的前门，如果您没有适当地保护它们，任何人都可以随意进入。我们还将看看**安全增强型 Linux**（**SELinux**）和**AppArmor**，以确保您在创建的主机上有额外的安全层。最后，我们将看看一些支持并在发现安全漏洞时自动修补其操作系统的操作系统。

# Docker Machine

Docker Machine 是一种工具，允许您将 Docker 守护程序安装到您的虚拟主机上。然后，您可以使用 Docker Machine 管理这些 Docker 主机。Docker Machine 可以通过 Windows 和 Mac 上的**Docker 工具箱**安装。如果您使用 Linux，则可以通过简单的 `curl` 命令安装 Docker Machine：

```
$ curl -L https://github.com/docker/machine/releases/download/v0.6.0/docker-machine-`uname -s`-`uname -m` > /usr/local/bin/docker-machine && \
$ chmod +x /usr/local/bin/docker-machine

```

第一条命令将 Docker Machine 安装到 `/usr/local/bin` 目录中，第二条命令更改文件的权限并将其设置为可执行文件。

我们将在以下演练中使用 Docker Machine 来设置新的 Docker 主机。

Docker Machine 是您应该或将要使用来设置您的主机的工具。因此，我们将从它开始，以确保您的主机以安全的方式设置。我们将看看您如何在使用 Docker Machine 工具创建主机时，如何判断您的主机是否安全。让我们看看使用 Docker Machine 创建 Docker 主机时的情况，如下：

```
$ docker-machine create --driver virtualbox host1

Running pre-create checks...
Creating machine...
Waiting for machine to be running, this may take a few minutes...
Machine is running, waiting for SSH to be available...
Detecting operating system of created instance...
Provisioning created instance...
Copying certs to the local machine directory...
Copying certs to the remote machine...

Setting Docker configuration on the remote daemon...

```

从前面的输出中，随着创建的运行，Docker Machine 正在执行诸如创建机器、等待 SSH 可用、执行操作、将证书复制到正确位置以及设置 Docker 配置等操作，我们将看到如何连接 Docker 到这台机器，如下所示：

```
$ docker-machine env host1

export DOCKER_TLS_VERIFY="1"
export DOCKER_HOST="tcp://192.168.99.100:2376"
export DOCKER_CERT_PATH="/Users/scottpgallagher/.docker/machine/machines/host1"
export DOCKER_MACHINE_NAME="host1"
# Run this command to configure your shell:
# eval "$(docker-machine env host1)"

```

前面的命令输出显示了设置此机器为 Docker 命令将要运行的机器所需运行的命令：

```
eval "$(docker-machine env host1)"

```

现在我们可以运行常规的 Docker 命令，比如`docker info`，它将从`host1`返回信息，现在我们已经将其设置为我们的环境。

我们可以从前面突出显示的输出中看到，主机从两个导出行开始就被安全地设置了。以下是第一个突出显示的行：

```
export DOCKER_TLS_VERIFY="1"

```

从其他突出显示的输出中，`DOCKER_TLS_VERIFY`被设置为`1`或`true`。以下是第二个突出显示的行：

```
export DOCKER_HOST="tcp://192.168.99.100:2376"

```

我们将主机设置为在安全端口`2376`上运行，而不是在不安全端口`2375`上运行。

我们还可以通过运行以下命令来获取这些信息：

```
$ docker-machine ls
NAME      ACTIVE   DRIVER       STATE     URL                         SWARM
host1              *        virtualbox     Running   tcp://192.168.99.100:2376

```

如果您已经使用先前的说明来设置 Docker 主机和 Docker 容器使用 TLS，请确保检查可以与 Docker Machine 一起使用的 TLS 开关选项。如果您有现有的证书要使用，这些开关将非常有用。通过运行以下命令，可以在突出显示的部分找到这些开关：

```
$ docker-machine --help

Options:
--debug, -D      Enable debug mode
-s, --storage-path "/Users/scottpgallagher/.docker/machine"
Configures storage path [$MACHINE_STORAGE_PATH]
--tls-ca-cert      CA to verify remotes against [$MACHINE_TLS_CA_CERT]
--tls-ca-key      Private key to generate certificates [$MACHINE_TLS_CA_KEY]
--tls-client-cert     Client cert to use for TLS [$MACHINE_TLS_CLIENT_CERT]
--tls-client-key       Private key used in client TLS auth [$MACHINE_TLS_CLIENT_KEY]
--github-api-token     Token to use for requests to the Github API [$MACHINE_GITHUB_API_TOKEN]
--native-ssh      Use the native (Go-based) SSH implementation. [$MACHINE_NATIVE_SSH]
--help, -h      show help
--version, -v      print the version

```

如果您想要安心，或者您的密钥确实被 compromise，您也可以使用`regenerate-certs`子命令重新生成机器的 TLS 证书。一个示例命令看起来类似于以下命令：

```
$ docker-machine regenerate-certs host1

Regenerate TLS machine certs?  Warning: this is irreversible. (y/n): y
Regenerating TLS certificates
Copying certs to the local machine directory...
Copying certs to the remote machine...
Setting Docker configuration on the remote daemon...

```

# SELinux 和 AppArmor

大多数 Linux 操作系统都基于它们可以利用 SELinux 或 AppArmor 来实现对操作系统上的文件或位置的更高级访问控制。使用这些组件，您可以限制容器以 root 用户的权限执行程序的能力。

Docker 确实提供了一个安全模型模板，其中包括 AppArmor，Red Hat 也为 Docker 提供了 SELinux 策略。您可以利用这些提供的模板在您的环境中添加额外的安全层。

有关 SELinux 和 Docker 的更多信息，我建议访问以下网站：

[`www.mankier.com/8/docker_selinux`](https://www.mankier.com/8/docker_selinux)

另一方面，如果你正在寻找关于 AppArmor 和 Docker 的更多阅读材料，我建议访问以下网站：

[`github.com/docker/docker/tree/master/contrib/apparmor`](https://github.com/docker/docker/tree/master/contrib/apparmor)

在这里，您将找到一个`template.go`文件，这是 Docker 随其应用程序一起提供的 AppArmor 模板。

# 自动修补主机

如果您真的想深入了解高级 Docker 主机，那么您可以使用 CoreOS 和 Amazon Linux AMI，它们都以不同的方式进行自动修补。CoreOS 将在安全更新发布时对您的操作系统进行修补并重新启动您的操作系统，而 Amazon Linux AMI 将在您重新启动时完成更新。因此，在设置 Docker 主机时选择要使用的操作系统时，请确保考虑到这两种操作系统都以不同的方式实现了某种形式的自动修补。您将希望确保实施某种类型的扩展或故障转移来满足在 CoreOS 上运行时的需求，以便在重新启动以修补操作系统时不会出现停机时间。

# 总结

在本章中，我们看了如何保护我们的 Docker 主机。Docker 主机是第一道防线，因为它们是您的容器将运行和相互通信以及最终用户的起点。如果这些不安全，那么继续进行其他任何事情就没有意义。您学会了如何设置 Docker 守护程序以通过为主机和客户端生成适当的证书来安全运行 TLS。我们还看了使用 Docker 容器的虚拟化和隔离优势，但请记住 Docker 守护程序的攻击面。

其他内容包括如何使用 Docker Machine 在安全操作系统上轻松创建 Docker 主机，并确保在设置容器时使用安全方法。使用 SELinux 和 AppArmor 等项目也有助于改善您的安全性。最后，我们还介绍了一些 Docker 主机操作系统，您也可以使用自动修补，例如 CoreOS 和 Amazon Linux AMI。

在下一章中，我们将研究如何保护 Docker 的组件。我们将重点关注保护 Docker 的组件，比如您可以使用的注册表、运行在您主机上的容器，以及如何对您的镜像进行签名。


# 第二章：保护 Docker 组件

在本章中，我们将研究如何使用诸如图像签名工具之类的工具来保护一些 Docker 组件。有一些工具可以帮助保护我们存储图像的环境，无论它们是否被签名。我们还将研究使用商业级支持的工具。我们将要研究的一些工具（图像签名和商业级支持工具）包括：

+   **Docker 内容信任**：可用于签署您的图像的软件。我们将研究所有组件，并通过一个签署图像的示例进行讲解。

+   **Docker 订阅**：订阅是一个全包套餐，包括一个存储图像的位置，以及 Docker 引擎来运行您的容器，同时为所有这些部分提供商业级支持，还包括您计划使用的应用程序及其生命周期的商业级支持。

+   **Docker 受信任的注册表**（**DTR**）：受信任的注册表为您提供了一个安全的位置，用于存储和管理您的图像，无论是在本地还是在云中。它还与您当前的基础设施有很多集成。我们将研究所有可用的部分。

# Docker 内容信任

Docker 内容信任是一种方法，您可以安全地签署您创建的 Docker 图像，以确保它们来自于它们所说的那个人，也就是您！在本节中，我们将研究**Notary**的组件以及签署图像的示例。最后，我们将一睹使用 Notary 的最新方法，以及现在可用的硬件签名能力。这是一个非常令人兴奋的话题，所以让我们毫不犹豫地深入研究吧！

## Docker 内容信任组件

要理解 Docker 内容信任的工作原理，熟悉构成其生态系统的所有组件是有益的。

该生态系统的第一部分是**更新框架**（**TUF**）部分。从现在开始，我们将称之为 TUF，它是 Notary 构建的框架。TUF 解决了软件更新系统的问题，因为它们通常很难管理。它使用户能够确保所有应用程序都是安全的，并且可以经受任何密钥妥协。但是，如果一个应用程序默认不安全，直到它达到安全合规性之前，它将无法帮助保护该应用程序。它还可以在不受信任的来源上进行可信任的更新等等。要了解更多关于 TUF 的信息，请访问网站：

[`theupdateframework.com/`](http://theupdateframework.com/)

内容信任生态系统的下一个部分是公证。公证是实际使用您的密钥进行签名的关键基础部分。公证是开源软件，可以在这里找到：

[`github.com/docker/notary`](https://github.com/docker/notary)

这是由 Docker 的人员制作的，用于发布和验证内容。公证包括服务器部分和客户端部分。客户端部分驻留在您的本地计算机上，并处理本地密钥的存储以及与公证服务器的时间戳匹配的通信。

基本上，公证服务器有三个步骤。

1.  编译服务器

1.  配置服务器

1.  运行服务器

由于步骤可能会在将来更改，最佳位置获取信息的地方将在 Docker Notary 的 GitHub 页面上。有关编译和设置公证服务器端的更多信息，请访问：

[`github.com/docker/notary#compiling-notary-server`](https://github.com/docker/notary#compiling-notary-server)

Docker 内容信任利用两个不同的密钥。第一个是标记密钥。标记密钥为您发布的每个新存储库生成。这些密钥可以与其他人共享，并导出给那些需要代表注册表签署内容的人。另一个密钥，脱机密钥，是重要的密钥。这是您想要锁在保险库中并且永远不与任何人分享的密钥*...永远*！正如名称所暗示的，这个密钥应该保持脱机状态，不要存储在您的计算机上或任何网络或云存储上。您需要脱机密钥的唯一时候是如果您要将其更换为新密钥或者创建新存储库。

那么，所有这些意味着什么，它真正对您有什么好处？这有助于保护针对三个关键场景，没有双关语。

+   防止图像伪造，例如，如果有人决定假装您的图像来自您。如果没有那个人能够用存储库特定密钥签署该图像，记住您要将其保持*脱机*！，他们将无法将其冒充为实际来自您的。

+   防止重放攻击；重放攻击是指恶意用户试图将一个旧版本的应用程序（已被破坏）冒充为最新的合法版本。由于 Docker 内容信任使用时间戳的方式，这将最终失败，并保护您和您的用户的安全。

+   防止密钥被泄露。如果密钥被泄露，您可以利用离线密钥进行密钥轮换。只有拥有离线密钥的人才能进行密钥轮换。在这种情况下，您需要创建一个新密钥，并使用您的离线密钥对其进行签名。

所有这些的主要要点是，离线密钥是用来离线保存的。永远不要将其存储在云存储、GitHub 上，甚至是始终连接到互联网的系统上，比如您的本地计算机。最佳做法是将其存储在加密的 U 盘上，并将该 U 盘存储在安全的位置。

要了解有关 Docker 内容信任的更多信息，请访问以下博客文章：

[`blog.docker.com/2015/08/content-trust-docker-1-8/`](http://blog.docker.com/2015/08/content-trust-docker-1-8/)

## 签名图像

现在我们已经介绍了 Docker 内容信任的所有组件，让我们看看如何对图像进行签名以及涉及的所有步骤。这些说明仅供开发目的。如果您要在生产环境中运行 Notary 服务器，您将需要使用自己的数据库，并按照其网站上的说明自己编译 Notary：

[`github.com/docker/notary#compiling-notary-server`](https://github.com/docker/notary#compiling-notary-server)

这将允许您在您自己的后端注册表中使用自己的密钥。如果您正在使用 Docker Hub，使用 Docker 内容信任非常简单。

```
$ export DOCKER_CONTENT_TRUST=1

```

最重要的一点是，您需要给您推送的所有图像打上标签，这是在下一个命令中看到的：

```
$ docker push scottpgallagher/ubuntu:latest

The push refers to a repository [docker.io/scottpgallagher/ubuntu] (len: 1)
f50e4a66df18: Image already exists
a6785352b25c: Image already exists
0998bf8fb9e9: Image already exists
0a85502c06c9: Image already exists
latest: digest: sha256:98002698c8d868b03708880ad2e1d36034c79a6698044b495ac34c4c16eacd57 size: 8008
Signing and pushing trust metadata
You are about to create a new root signing key passphrase. This passphrase
will be used to protect the most sensitive key in your signing system. Please
choose a long, complex passphrase and be careful to keep the password and the
key file itself secure and backed up. It is highly recommended that you use a
password manager to generate the passphrase and keep it safe. There will be no
way to recover this key. You can find the key in your config directory.
Enter passphrase for new root key with id d792b7a:
Repeat passphrase for new root key with id d792b7a:
Enter passphrase for new repository key with id docker.io/scottpgallagher/ubuntu (46a967e):
Repeat passphrase for new repository key with id docker.io/scottpgallagher/ubuntu (46a967e):
Finished initializing "docker.io/scottpgallagher/ubuntu"

```

以上代码中最重要的一行是：

```
latest: digest: sha256:98002698c8d868b03708880ad2e1d36034c79a6698044b495ac34c4c16eacd57 size: 8008

```

这将为您提供用于验证图像的 SHA 哈希值，以及其大小。当有人要运行该`image/container`时，将在以后使用这些信息。

如果您从没有这个图像的机器上执行`docker pull`，您可以看到它已经用该哈希签名。

```
$ docker pull scottpgallagher/ubuntu

Using default tag: latest
latest: Pulling from scottpgallagher/ubuntu
Digest: sha256:98002698c8d868b03708880ad2e1d36034c79a6698044b495ac34c4c16eacd57
Status: Downloaded newer image for scottpgallagher/ubuntu:latest

```

再次，当我们执行`pull`命令时，我们看到了 SHA 值的呈现。

因此，这意味着当您要运行此容器时，它不会在本地运行，而是首先将本地哈希与注册表服务器上的哈希进行比较，以确保它没有更改。如果它们匹配，它将运行，如果它们不匹配，它将不运行，并且会给您一个关于哈希不匹配的错误消息。

使用 Docker Hub，您基本上不会使用自己的密钥签署镜像，除非您操作位于`~/.docker/trust/trusted-certificates/`目录中的密钥。请记住，默认情况下，安装 Docker 时会提供一组可用的证书。

## 硬件签名

现在我们已经看过了如何签署镜像，还有哪些其他安全措施可以帮助使该过程更加安全？YubiKeys 登场！YubiKeys 是一种可以利用的双因素身份验证。YubiKey 的工作方式是，它在硬件中内置了根密钥。您启用 Docker 内容信任，然后推送您的镜像。在使用您的镜像时，Docker 会注意到您已启用内容信任，并要求您触摸 YubiKey，是的，物理触摸它。这是为了确保您是一个人，而不是一个机器人或只是一个脚本。然后，您需要提供一个密码来使用，然后再次触摸 YubiKey。一旦您这样做了，您就不再需要 YubiKey，但您需要之前分配的密码。

我对此的描述实在是不够好。在 DockerCon Europe 2015（[`europe-2015.dockercon.com`](http://europe-2015.dockercon.com)）上，两名 Docker 员工 Aanand Prasad 和 Diogo Mónica 之间的操作非常精彩。

要观看视频，请访问以下网址：

[`youtu.be/fLfFFtOHRZQ?t=1h21m33s`](https://youtu.be/fLfFFtOHRZQ?t=1h21m33s)

# Docker 订阅

Docker 订阅是一个为您的分布式应用程序提供支持和部署的服务。Docker 订阅包括两个关键的软件部分和一个支持部分：

+   Docker 注册表-在其中存储和管理您的镜像（本地托管或托管在云中）

+   Docker 引擎-运行这些镜像

+   Docker 通用控制平面（UCP）

+   商业支持-打电话或发送电子邮件寻求帮助

如果您是开发人员，有时操作方面的事情可能有点难以设置和管理，或者需要一些培训才能开始。通过 Docker 订阅，您可以利用商业级支持的专业知识来减轻一些担忧。有了这种支持，您将得到对您问题的快速响应。您将收到任何可用的热修复程序，或者已经提供的修补程序来修复您的解决方案。协助未来升级也是选择 Docker 订阅计划的附加好处之一。您将获得升级您的环境到最新和最安全的 Docker 环境的帮助。

定价是根据您想要运行环境的位置来分解的，无论是在您选择的服务器上还是在云环境中。它还取决于您希望拥有多少 Docker 可信注册表和/或多少商业支持的 Docker 引擎。所有这些解决方案都为您提供了与现有的**LDAP**或**Active Directory**环境集成的功能。有了这个附加好处，您可以使用诸如组策略之类的项目来管理对这些资源的访问。您还需要决定您希望从支持端获得多快的响应时间。所有这些都将影响您为订阅服务支付的价格。无论您支付多少，花费的钱都是值得的，不仅仅是因为您将获得的安心，还因为您将获得的知识是无价的。

您还可以根据月度或年度基础更改计划，以及以十个为增量升级您的 Docker 引擎实例。您还可以以十个为单位升级**Docker** **Hub 企业版**实例的数量。在本地服务器和云之间进行切换也是可能的。

为了不让人困惑，我们来分解一些东西。Docker 引擎是 Docker 生态系统的核心。它是您用来运行、构建和管理容器或镜像的命令行工具。Docker Hub 企业版是您存储和管理镜像的位置。这些镜像可以是公开的，也可以是私有的。我们将在本章的下一节中了解更多关于 DTR 的信息。

有关 Docker Subscription 的更多信息，请访问下面的链接。您可以注册免费的 30 天试用，查看订阅计划，并联系销售以获取额外的帮助或提问。订阅计划足够灵活，可以符合您的操作环境，无论是您想要全天候支持还是只需要一半时间的支持：

[`www.docker.com/docker-subscription`](https://www.docker.com/docker-subscription)

您还可以在这里查看商业支持的详细信息：

[`www.docker.com/support`](https://www.docker.com/support)

将所有这些都带回到本书的主题，即保护 Docker，这绝对是您可以获得的最安全的 Docker 环境，您将使用它来管理图像和容器，以及管理它们存储和运行的位置。多一点帮助从来都不会有坏处，有了这个选项，一点帮助肯定会走得更远。

最新添加的部分是 Docker Universal Control Plane。Docker UCP 提供了一个解决方案，用于管理 Docker 化的应用程序和基础设施，无论它们在何处运行。这可以在本地或云中运行。您可以在以下链接找到有关 Docker UCP 的更多信息：

[`www.docker.com/products/docker-universal-control-plane`](https://www.docker.com/products/docker-universal-control-plane)

您还可以使用上述网址获得产品演示。Docker UCP 是可扩展的，易于设置，并且可以通过集成到现有的 LDAP 或 Active Directory 环境中管理用户和访问控制。

# Docker Trusted Registry

DTR 是一个解决方案，提供了一个安全的位置，您可以在本地或云中存储和管理 Docker 镜像。它还提供了一些监控功能，让您了解使用情况，以便了解传递给它的负载类型。DTR 与 Docker Registry 不同，不是免费的，并且有定价模型。就像我们之前在 Docker Subscription 中看到的那样，DTR 的定价计划是相同的。不要担心，因为我们将在本书的下一部分介绍 Docker Registry，这样您就可以了解它，并为图像存储提供所有可用的选项。

我们将其分成自己的部分的原因是，涉及许多移动部件，了解它们如何作为整体对 Docker 订阅部分至关重要，但作为独立的 DTR 部分，其中维护和存储所有图像的地方也很重要。

## 安装

安装 DTR 有两种方式，或者说有两个位置可以安装 DTR。第一种是在您管理的服务器上部署它。另一种是将其部署到像**Digital Ocean**，**Amazon Web Services**（**AWS**）或**Microsoft Azure**这样的云提供商环境中。

您首先需要的是 DTR 的许可证。目前，他们提供了一个试用许可证，您可以使用，我强烈建议您这样做。这将允许您在所选环境中评估软件，而无需完全承诺该环境。如果您发现在特定环境中有些功能不起作用，或者您觉得另一个位置可能更适合您，那么您可以在不必被绑定到特定位置或不必将现有环境移动到不同的提供商或位置的情况下进行切换。如果您选择使用 AWS，他们有一个预先制作的**Amazon Machine Image**（**AMI**），您可以利用它更快地设置您的受信任的注册表。这样可以避免手动完成所有操作。

在安装受信任的注册表之前，您首先需要安装 Docker Engine。如果您尚未安装，请参阅下面链接中的文档以获取更多信息。

[`docs.docker.com/docker-trusted-registry/install/install-csengine/`](https://docs.docker.com/docker-trusted-registry/install/install-csengine/)

您会注意到在安装普通的 Docker Engine 和**Docker CS Engine**之间存在差异。Docker CS Engine 代表商业支持的 Docker Engine。请务必查看文档，因为推荐或支持的 Linux 版本列表比 Docker Engine 的常规列表要短。

如果您使用 AMI 进行安装，请按照此处的说明进行：

[`docs.docker.com/docker-trusted-registry/install/dtr-ami-byol-launch/`](https://docs.docker.com/docker-trusted-registry/install/dtr-ami-byol-launch/)

如果您要在 Microsoft Azure 上安装，请按照此处的说明进行：

[`docs.docker.com/docker-trusted-registry/install/dtr-vhd-azure/`](https://docs.docker.com/docker-trusted-registry/install/dtr-vhd-azure/)

一旦您安装了 Docker Engine，就该安装 DTR 组件了。如果您读到这一点，我们将假设您不是在 AWS 或 Microsoft Azure 上安装。如果您使用这两种方法之一，请参阅上面的链接。安装非常简单：

```
$ sudo bash -c '$(sudo docker run docker/trusted-registry install)'

```

### 注意

注意：在 Mac OS 上运行时，您可能需要从上述命令中删除`sudo`选项。

运行完这个命令后，您可以在浏览器中导航到 Docker 主机的 IP 地址。然后，您将设置受信任的注册表的域名，并应用许可证。Web 门户将引导您完成其余的设置过程。

在访问门户时，您还可以通过现有的 LDAP 或 Active Directory 环境设置身份验证，但这可以随时完成。

完成后，是时候进行*保护 Docker 受信任的注册表*，我们将在下一节中介绍。

## 保护 Docker 受信任的注册表

现在我们已经设置好了受信任的注册表，我们需要使其安全。在使其安全之前，您需要创建一个管理员帐户以执行操作。一旦您的受信任的注册表已经运行，并且已登录，您将能够在**设置**下看到六个区域。这些是：

+   **常规**设置

+   **安全**设置

+   **存储**设置

+   **许可证**

+   **认证**设置

+   **更新**

**常规**设置主要集中在诸如**HTTP 端口**或**HTTPS 端口**、用于您的受信任注册表的**域名**和代理设置等设置上。

![保护 Docker 受信任的注册表](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/sec-dkr/img/00004.jpeg)

接下来的部分，**安全**设置，可能是最重要的部分之一。在这个**仪表板**窗格中，您可以利用您的**SSL 证书**和**SSL 私钥**。这些是使您的 Docker 客户端和受信任的注册表之间的通信安全的要素。现在，这些证书有一些选项。您可以使用在安装受信任的注册表时创建的自签名证书。您也可以使用自己的自签名证书，使用诸如**OpenSSL**之类的命令行工具。如果您在企业组织中，他们很可能有一个地方，您可以请求像注册表一样使用的证书。您需要确保您受信任的注册表上的证书与您的客户端上使用的证书相同，以确保在执行`docker pull`或`docker push`命令时进行安全通信。

![保护 Docker Trusted Registry](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/sec-dkr/img/00005.jpeg)

接下来的部分涉及图像存储设置。在这个**仪表板**窗格中，您可以设置图像在后端存储上的存储位置。这可能包括您正在使用的 NFS 共享、受信任的注册表服务器的本地磁盘存储、来自 AWS 的 S3 存储桶或其他云存储解决方案。一旦您选择了**存储后端**选项，您就可以设置从该**存储**中存储图像的路径：

![保护 Docker Trusted Registry](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/sec-dkr/img/00006.jpeg)

**许可证**部分非常简单，这是您更新许可证的地方，当需要更新新的许可证或升级可能包括更多选项的许可证时：

![保护 Docker Trusted Registry](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/sec-dkr/img/00007.jpeg)

身份验证设置允许您将登录到受信任的注册表与现有的身份验证环境联系起来。您的选项是：**无**或**托管**选项。**无**除了测试目的外不建议使用。**托管**选项是您可以设置用户名和密码并从那里管理它们的地方。另一个选项是使用**LDAP**服务，您可能已经在运行，这样用户就可以在其他工作设备上使用相同的登录凭据，比如电子邮件或网页登录。

![保护 Docker Trusted Registry](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/sec-dkr/img/00008.jpeg)

最后一个部分，**更新**，涉及您如何管理 DTR 的更新。这些设置完全取决于您如何处理更新，但是请确保如果您正在进行自动化形式的更新，您也在事件发生更新过程中出现问题时利用备份进行恢复。

![Securing Docker Trusted Registry](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/sec-dkr/img/00009.jpeg)

## 管理

现在我们已经介绍了帮助您保护您的受信任注册表的项目，我们不妨花几分钟来介绍控制台中的其他项目，以帮助您管理它。除了注册表中的**设置**选项卡之外，还有其他四个选项卡，您可以浏览并收集有关您的注册表的信息。它们是：

+   **仪表板**

+   **存储库**

+   **组织**

+   **日志**

**仪表板**是您通过浏览器登录到控制台时带您到的主要页面。这将在一个中央位置显示有关您的注册表的信息。您将看到的信息更多地与注册表服务器本身以及注册表服务器正在运行的 Docker 主机相关的硬件信息。**存储库**部分将允许您控制用户能够从中拉取镜像的存储库，无论是**公共**还是**私有**。**组织**部分允许您控制访问权限，也就是说，系统上谁可以对您选择配置的存储库执行推送、拉取或其他 Docker 相关命令。最后一个部分，**日志**部分，将允许您查看基于您的注册表使用的容器的日志。日志每两周轮换一次，最大大小为*64 mb*。您还可以根据容器过滤日志，以及根据日期和/或时间搜索。

## 工作流

在这一部分，让我们拉取一张图片，对其进行操作，然后将其放在我们的 DTR 上，以便组织内的其他人可以访问。

首先，我们需要从**Docker Hub**拉取一个镜像。现在，你可以从头开始使用**Dockerfile**，然后进行 Docker 构建，然后推送，但是，为了演示，我们假设我们有`mysql`镜像，并且我们想以某种方式对其进行定制。

```
$ docker pull mysql

Using default tag: latest
latest: Pulling from library/mysql

1565e86129b8: Pull complete
a604b236bcde: Pull complete
2a1fefc8d587: Pull complete
f9519f46a2bf: Pull complete
b03fa53728a0: Pull complete
ac2f3cdeb1c6: Pull complete
b61ef27b0115: Pull complete
9ff29f750be3: Pull complete
ece4ebeae179: Pull complete
95255626f143: Pull complete
0c7947afc43f: Pull complete
b3a598670425: Pull complete
e287fa347325: Pull complete
40f595e5339f: Pull complete
0ab12a4dd3c8: Pull complete
89fa423a616b: Pull complete
Digest: sha256:72e383e001789562e943bee14728e3a93f2c3823182d14e3e01b3fd877976265
Status: Downloaded newer image for mysql:latest

$ docker images

REPOSITORY          TAG                 IMAGE ID            CREATED             VIRTUAL SIZE
mysql               latest              89fa423a616b        20 hours ago        359.9 MB

```

现在，让我们假设我们对图像进行了定制。假设我们设置了容器，将其日志发送到一个日志聚合服务器，我们正在使用该服务器从我们运行的所有容器中收集日志。现在我们需要保存这些更改。

```
$ docker commit be4ea9a7734e <dns.name>/mysql

```

当我们进行提交时，我们需要一些信息。首先是容器 ID，我们可以通过运行`docker ps`命令来获取。我们还需要我们之前设置的注册表服务器的 DNS 名称，最后是一个唯一的镜像名称。在我们的情况下，我们将其保留为`mysql`。

现在我们准备将更新后的镜像推送到我们的注册表服务器。我们唯一需要的信息是我们要推送的镜像名称，即`<dns.name>/mysql`。

```
$ docker push <dns.name>/mysql

```

现在，该镜像已准备好供我们组织中的其他用户使用。由于镜像位于我们的受信任的注册表中，我们可以控制客户对该镜像的访问。这可能意味着我们的客户需要我们的证书和密钥才能推送和拉取该镜像，以及在我们之前在上一节中介绍的组织设置中设置的权限。

```
$ docker pull <dns.name>/mysql

```

然后我们可以运行镜像，如果需要的话进行更改，并将新创建的镜像推送回受信任的注册服务器。

# Docker Registry

Docker Registry 是一个开源选项，如果您想完全自己操作的话。如果您完全不想操心，您可以随时使用 Docker Hub，并依赖公共和私有存储库，在 Docker Hub 上会收取费用。这可以在您选择的服务器上或云服务上进行托管。

## 安装

Docker Registry 的安装非常简单，因为它运行在一个 Docker 容器中。这使您可以在几乎任何地方运行它，在您自己的服务器环境中的虚拟机中或在云环境中。通常使用的端口是端口`5000`，但您可以根据需要进行更改：

```
$ docker run -d -p 5000:5000 --restart=always  --name registry registry:2.2

```

您还会注意到我们上面的另一个项目是，我们正在指定要使用的版本，而不是留空并拉取最新版本。这是因为在撰写本书时，该注册表标签的最新版本仍为 0.9.1。现在，虽然这对一些人来说可能合适，但版本 2 已经足够稳定，可以考虑在生产环境中运行。我们还引入了`--restart=always`标志，以便在容器发生故障时，它将重新启动并可用于提供或接受镜像。

一旦您运行了上述命令，您将在 Docker 主机的 IP 地址上拥有一个运行的容器注册表，以及您在上面的`docker run`命令中使用的端口选择。

现在是时候在您的新注册表上放一些图像了。我们首先需要一个要推送到注册表的图像，我们可以通过两种方式来实现。我们可以基于我们创建的 Docker 文件构建图像，或者我们可以从另一个注册表中拉取图像，在我们的情况下，我们将使用 Docker Hub，然后将该图像推送到我们的新注册表服务器。首先，我们需要选择一个图像，再次，我们将默认回到`mysql`图像，因为它是一个更受欢迎的图像，大多数人在某个时候可能会在其环境中使用。

```
$ docker pull mysql
Using default tag: latest
latest: Pulling from library/mysql

1565e86129b8: Pull complete
a604b236bcde: Pull complete
2a1fefc8d587: Pull complete
f9519f46a2bf: Pull complete
b03fa53728a0: Pull complete
ac2f3cdeb1c6: Pull complete
b61ef27b0115: Pull complete
9ff29f750be3: Pull complete
ece4ebeae179: Pull complete
95255626f143: Pull complete
0c7947afc43f: Pull complete
b3a598670425: Pull complete
e287fa347325: Pull complete
40f595e5339f: Pull complete
0ab12a4dd3c8: Pull complete
89fa423a616b: Pull complete
Digest: sha256:72e383e001789562e943bee14728e3a93f2c3823182d14e3e01b3fd877976265
Status: Downloaded newer image for mysql:latest

```

接下来，您需要标记图像，以便它现在指向您的新注册表，这样您就可以将其推送到新位置：

```
$ docker tag mysql <IP_address>:5000/mysql

```

让我们来分解上面的命令。我们正在做的是将`mysql`图像从 Docker Hub 中拉取，并将标签`<IP_address>:5000/mysql`应用于该图像。现在，`<IP_address>`部分将被 Docker 主机的 IP 地址替换，该主机正在运行注册表容器。这也可以是一个 DNS 名称，只要 DNS 指向正确的 IP 地址即可。我们还需要指定我们的注册表服务器的端口号，在我们的情况下，我们将其保留为端口`5000`，因此我们在标签中包括：`5000`。然后，我们将在命令的末尾给它相同的名称`mysql`。现在，我们准备将此图像推送到我们的新注册表。

```
$ docker push <IP_address>:5000/mysql

```

推送完成后，您现在可以从另一台配置有 Docker 并且可以访问注册表服务器的机器上将其拉取下来。

```
$ docker pull <IP_address>:5000/mysql

```

我们在这里看到的是默认设置，虽然如果您想使用防火墙等来保护环境，甚至是内部 IP 地址，它可能会起作用，但您可能仍然希望将安全性提升到下一个级别，这就是我们将在下一节中讨论的内容。我们如何使这更加安全？

## 配置和安全性

是时候用一些额外的功能来加强我们的运行注册表了。第一种方法是使用 TLS 运行您的注册表。使用 TLS 允许您向系统应用证书，以便从中提取的人知道它是您所说的那样，因为他们知道没有人侵犯了服务器，也没有人通过提供受损的图像进行中间人攻击。

为此，我们需要重新调整上一节中运行的 Docker `run`命令。这将假定您已经完成了从企业环境获取证书和密钥的过程，或者您已经使用其他软件自签了一个。

我们的新命令将如下所示：

```
$ docker run -d -p 5000:5000 --restart=always --name registry \
-e REGISTRY_HTTP_TLS_CERTIFICATE=server.crt \
-e REGISTRY_HTTP_TLS_KEY=server.key \
-v <certificate folder>/<path_on_container> \
registry:2.2.0

```

您需要在证书所在的目录中，或在上述命令中指定完整路径。同样，我们保持标准端口`5000`，以及注册表的名称。您也可以将其更改为更适合您的内容。出于本书的目的，我们将保持接近官方文档中的内容，以便您在那里查找更多参考资料。接下来，我们在`run`命令中添加了两行额外的内容：

```
-e REGISTRY_HTTP_TLS_CERTIFICATE=server.crt \
-e REGISTRY_HTTP_TLS_KEY=server.key \

```

这将允许您指定要使用的证书和密钥文件。这两个文件需要在您运行`run`命令的同一目录中，因为环境变量将在运行时寻找它们。现在，如果您喜欢，您还可以在运行命令中添加一个卷开关，使其更加清晰，并将证书和密钥放在那个文件夹中以这种方式运行注册表服务器。

您还可以通过在注册表服务器上设置用户名和密码来帮助提高安全性。当用户想要推送或拉取一个项目时，他们将需要用户名和密码信息。但这种方法的问题是，您必须与 TLS 一起使用。用户名和密码的这种方法不是一个独立的选项。

首先，您需要创建一个密码文件，该文件将在您的`run`命令中使用：

```
$ docker run --entrypoint htpasswd registry:2.2.0 -bn <username> <password> > htpasswd

```

现在，要理解这里发生了什么可能有点困惑，所以在我们跳转到`run`命令之前，让我们澄清一下。首先，我们发出了一个`run`命令。这个命令将运行`registry:2.2.0`容器，并且指定的入口点意味着运行`htpasswd`命令以及`-bn`开关，这将以加密方式将`username`和`password`注入到一个名为`htpasswd`的文件中，您将在注册表服务器上用于身份验证目的。`-b`表示批处理模式运行，而`-n`表示显示结果，`>`表示将这些项目放入文件而不是实际输出屏幕。

现在，让我们来看看我们新增强的、完全安全的 Docker `run`命令：

```
$ docker run -d -p 5000:5000 --restart=always --name registry \
-e "REGISTRY_AUTH=htpasswd" \
-e "REGISTRY_AUTH_HTPASSWD_REALM=Registry Name" \
-e REGISTRY_AUTH_HTPASSWD_PATH=htpasswd \
-e REGISTRY_HTTP_TLS_CERTIFICATE=server.crt \
-e REGISTRY_HTTP_TLS_KEY=server.key \
registry:2.20

```

再次，这是很多内容需要消化，但让我们一起来看一下。我们之前在一些地方已经看到了这些内容：

```
-e REGISTRY_HTTP_TLS_CERTIFICATE=server.crt \
-e REGISTRY_HTTP_TLS_KEY=server.key \

```

新的内容包括：…（未完待续）

```
-e "REGISTRY_AUTH=htpasswd" \
-e "REGISTRY_AUTH_HTPASSWD_REALM=Registry Name" \
-e REGISTRY_AUTH_HTPASSWD_PATH=htpasswd \

```

第一个告诉注册服务器使用`htpasswd`作为其验证客户端的身份验证方法。第二个为您的注册表提供一个名称，并且可以根据您自己的意愿进行更改。最后一个告诉注册服务器要使用的文件的位置，该文件将用于`htpasswd`身份验证。同样，您需要使用卷，并将`htpasswd`文件放在容器内的自己的卷中，以便日后更容易更新。您还需要记住，在执行 Docker `run`命令时，`htpasswd`文件需要放在与证书和密钥文件相同的目录中。

# 总结

在本章中，我们已经学习了如何使用 Docker 内容信任的组件以及使用 Docker 内容信任进行硬件签名，以及第三方实用程序，如 YubiKeys。我们还了解了 Docker 订阅，您可以利用它来帮助建立不仅安全的 Docker 环境，而且还得到 Docker 官方支持的环境。然后，我们看了 DTR 作为您可以用来存储 Docker 镜像的解决方案。最后，我们看了 Docker 注册表，这是一个自托管的注册表，您可以用来存储和管理您的镜像。本章应该为您提供了足够的配置项，以帮助您做出正确的决定，确定在哪里存储您的镜像。

在下一章中，我们将研究如何保护/加固 Linux 内核。由于内核是用于运行所有容器的，因此很重要对其进行适当的保护，以帮助减轻任何安全相关的问题。我们将介绍一些加固指南，您可以使用这些指南来实现这一目标。


# 第三章：保护和加固 Linux 内核

在本章中，我们将把注意力转向保护和加固每个在您的 Docker 主机上运行的容器所依赖的关键组件：Linux 内核。我们将专注于两个主题：您可以遵循的加固 Linux 内核的指南和您可以添加到您的工具库中以帮助加固 Linux 内核的工具。在深入讨论之前，让我们简要地看一下本章将涵盖的内容：

+   Linux 内核加固指南

+   Linux 内核加固工具

+   **Grsecurity**

+   **Lynis**

# Linux 内核加固指南

在本节中，我们将看一下 SANS 研究所关于 Linux 内核的加固指南。虽然很多信息已经过时，但我认为了解 Linux 内核如何发展并成为一个安全实体是很重要的。如果你能够进入时光机，回到 2003 年并尝试做今天想做的事情，这就是你必须做的一切。

首先，关于 SANS 研究所的一些背景信息。这是一家总部位于美国的私人公司，专门从事网络安全和信息技术相关的培训和教育。这些培训使专业人员能够防御其环境免受攻击者的侵害。SANS 还通过其 SANS 技术学院领导实验室提供各种免费的安全相关内容。有关更多信息，请访问[`www.sans.edu/research/leadership-laboratory`](http://www.sans.edu/research/leadership-laboratory)。

为了帮助减轻这种广泛的攻击基础，需要在 IT 基础设施和软件的每个方面都有安全关注。基于此，开始的第一步应该是在 Linux 内核上。

## SANS 加固指南深入研究

由于我们已经介绍了 SANS 研究所的背景，让我们继续并开始遵循我们将用来保护我们的 Linux 内核的指南。

作为参考，我们将使用以下 URL，并重点介绍您应该关注和在您的环境中实施以保护 Linux 内核的关键点：

[`www.sans.org/reading-room/whitepapers/linux/linux-kernel-hardening-1294`](https://www.sans.org/reading-room/whitepapers/linux/linux-kernel-hardening-1294)

Linux 内核是 Linux 生态系统中不断发展和成熟的一部分，因此，重要的是要对当前的 Linux 内核有一个牢固的掌握，这将有助于在未来的发布中锁定新的功能集。

Linux 内核允许加载模块，而无需重新编译或重新启动，这在您希望消除停机时间时非常有用。一些不同的操作系统在尝试将更新应用到特定的操作系统/应用程序标准时需要重新启动。这也可能是 Linux 内核的一个坏处，因为攻击者可以向内核注入有害材料，并且不需要重新启动机器，这可能会被注意到系统的重新启动。因此，建议禁用带有加载选项的静态编译内核，以帮助防止攻击向量。

缓冲区溢出是攻击者入侵内核并获取权限的另一种方式。应用程序在内存中存储用户数据的限制或缓冲区。攻击者使用特制的代码溢出这个缓冲区，这可能让攻击者控制系统，从而赋予他们在那一点上做任何他们想做的事情的权力。他们可以向系统添加后门，将日志发送到一个邪恶的地方，向系统添加额外的用户，甚至将您锁在系统外。为了防止这些类型的攻击，指南专注于三个重点领域。

第一个是**Openwall** Linux 内核补丁，这是一个用来解决这个问题的补丁。这个补丁还包括一些其他安全增强功能，可能归因于您的运行环境。其中一些项目包括在`/tmp`文件夹位置限制链接和文件读取/写入，以及对文件系统上`/proc`位置的访问限制。它还包括对一些用户进程的增强执行力，您也可以控制，以及能够销毁未使用的共享内存段，最后，对于那些运行内核版本旧于 2.4 版本的用户，还有一些其他增强功能。

如果您正在运行较旧版本的 Linux 内核，您将希望查看[`www.openwall.com/Owl/`](http://www.openwall.com/Owl/)上的 Openwall 强化 Linux 和[`www.openwall.com/linux/`](http://www.openwall.com/linux/)上的 Openwall Linux。

下一个软件叫做**Exec** **Shield**，它采用了类似于 Openwall Linux 内核补丁的方法，实现了一个不可执行的堆栈，但是 Exec Shield 通过尝试保护任何和所有的虚拟内存段来扩展了这一点。这个补丁仅限于防止针对 Linux 内核地址空间的攻击。这些地址空间包括堆栈、缓冲区或函数指针溢出空间。

关于这个补丁的更多信息可以在[`en.wikipedia.org/wiki/Exec_Shield`](https://en.wikipedia.org/wiki/Exec_Shield)找到。

最后一个是**PaX**，它是一个为 Linux 内核创建补丁以防止各种软件漏洞的团队。由于这是我们将在下一节深入讨论的内容，我们将只讨论一些它的特点。这个补丁关注以下三个地址空间：

+   **PAGEEXEC**：这些是基于分页的、不可执行的页面

+   **SEGMEXEC**：这些是基于分段的、不可执行的页面

+   **MPROTECT**：这些是`mmap()`和`mprotect()`的限制

要了解有关 PaX 的更多信息，请访问[`pax.grsecurity.net`](https://pax.grsecurity.net)。

现在你已经看到了你需要付出多少努力，你应该高兴安全现在对每个人都是至关重要的，特别是 Linux 内核。在后面的一些章节中，我们将看一些正在用于帮助保护环境的新技术：

+   命名空间

+   cgroups

+   sVirt

+   Summon

通过`docker run`命令上的`--cap-ad`和`--cap-drop`开关也可以实现许多功能。

即使像以前一样，你仍然需要意识到内核在主机上的所有容器中是共享的，因此，你需要保护这个内核，并在必要时注意漏洞。以下链接允许您查看 Linux 内核中的**常见** **漏洞和** **曝光**（**CVE**）：

[`www.cvedetails.com/vulnerability-list/vendor_id-33/product_id-47/cvssscoremin-7/cvssscoremax-7.99/Linux-Linux-Kernel.html`](https://www.cvedetails.com/vulnerability-list/vendor_id-33/product_id-47/cvssscoremin-7/cvssscoremax-7.99/Linux-Linux-Kernel.html)

## 访问控制

您可以在 Linux 上叠加各种级别的访问控制，以及应该遵循的特定用户的建议，这些用户将是您系统上的超级用户。只是为了给超级用户一些定义，他们是系统上具有无限制访问权限的帐户。在叠加这些访问控制时，应包括 root 用户。

这些访问控制建议将是以下内容：

+   限制 root 用户的使用

+   限制其 SSH 的能力

默认情况下，在某些系统上，如果启用了 SSH，root 用户有能力 SSH 到机器上，我们可以从一些 Linux 系统的`/etc/ssh/sshd_config`文件的部分中看到如下内容：

```
# Authentication:

#LoginGraceTime 2m
#PermitRootLogin no
#StrictModes yes
#MaxAuthTries 6
#MaxSessions 10
```

从这里你可以看到，`PermitRootLogin no`部分被用`#`符号注释掉，这意味着这行不会被解释。要更改这个，只需删除`#`符号，保存文件并重新启动服务。该文件的部分现在应该类似于以下代码：

```
# Authentication:

#LoginGraceTime 2m
PermitRootLogin no
#StrictModes yes
#MaxAuthTries 6
#MaxSessions 10
```

现在，您可能希望重新启动 SSH 服务以使这些更改生效，如下所示：

```
$ sudo service sshd restart

```

+   限制其在控制台之外的登录能力。在大多数 Linux 系统上，有一个文件在`/etc/default/login`中，在该文件中，有一行类似以下的内容：

```
#CONSOLE=/dev/console
```

类似于前面的例子，我们需要通过删除`#`来取消注释此行，以使其生效。这将只允许 root 用户在`console`上登录，而不是通过 SSH 或其他方法。

+   限制`su`命令

`su`命令允许您以 root 用户身份登录并能够发出 root 级别的命令，从而完全访问整个系统。为了限制谁可以使用此命令，有一个文件位于`/etc/pam.d/su`，在这个文件中，您会看到类似以下的一行：

```
auth required /lib/security/pam_wheel.so use_uid
```

您还可以选择这里的以下代码行，具体取决于您的 Linux 版本：

```
auth required pam_wheel.so use_uid
```

检查 wheel 成员资格将根据当前用户 ID 来执行对`su`命令的使用能力。

+   要求使用`sudo`来运行命令

+   其他一些推荐使用的访问控制包括以下控制：

+   强制访问控制（MAC）：限制用户在系统上的操作

+   基于角色的访问控制：使用组分配这些组可以执行的角色

+   基于规则集的访问控制（RSBAC）：按请求类型分组的规则集，并根据设置的规则执行操作

+   **领域和类型强制执行**（DTE）：允许或限制某些领域执行特定操作，或防止领域相互交互

您还可以利用以下内容：

+   SELinux（基于 RPM 的系统（如 Red Hat、CentOS 和 Fedora）

+   AppArmor（基于 apt-get 的系统（如 Ubuntu 和 Debian）

RSBAC，正如我们之前讨论的那样，允许您选择适合系统运行的控制方法。您还可以创建自己的访问控制模块，以帮助执行。在大多数 Linux 系统上，默认情况下，这些类型的环境是启用或强制执行模式的。大多数人在创建新系统时会关闭这些功能，但这会带来安全缺陷，因此，重要的是要学习这些系统的工作原理，并在启用或强制执行模式下使用它们以帮助减轻进一步的风险。

有关每个的更多信息可以在以下找到：

+   SELinux：[`en.wikipedia.org/wiki/Security-Enhanced_Linux`](https://en.wikipedia.org/wiki/Security-Enhanced_Linux)

+   **AppArmor**：[`en.wikipedia.org/wiki/AppArmor`](https://en.wikipedia.org/wiki/AppArmor)

## 面向发行版

在 Linux 社区中有许多 Linux 发行版，或者他们称之为“风味”，已经被*预先烘烤*以进行硬化。我们之前提到过一个，即 Linux 的**Owlwall**风味，但还有其他一些。在其他两个中，一个已经不复存在，即**Adamantix**，另一个是**Gentoo Linux**。这些 Linux 风味作为其操作系统构建的标准，具有一些内置的 Linux 内核加固功能。

# Linux 内核加固工具

有一些 Linux 内核加固工具，但在本节中我们将只关注其中两个。第一个是 Grsecurity，第二个是 Lynis。这些工具可以增加您的武器库，帮助增强您将在其中运行 Docker 容器的环境的安全性。

## Grsecurity

那么，Grsecurity 到底是什么？根据他们的网站，Grsecurity 是 Linux 内核的广泛安全增强。这个增强包含了一系列项目，有助于抵御各种威胁。这些威胁可能包括以下组件：

+   零日漏洞利用：这可以减轻并保护您的环境，直到供应商提供长期解决方案。

+   **共享主机或容器的弱点**：这可以保护您免受各种技术以及容器使用的针对主机上每个容器的内核妥协。

+   **它超越了基本的访问控制**：Grsecurity 与 PaX 团队合作，引入复杂性和不可预测性，以防止攻击者，并拒绝攻击者再有机会。

+   **与现有的 Linux 发行版集成**：由于 Grsecurity 是基于内核的，因此可以与 Red Hat、Ubuntu、Debian 和 Gentoo 等任何 Linux 发行版一起使用。无论您使用的是哪种 Linux 发行版，都没有关系，因为重点是底层的 Linux 内核。

更多信息请访问[`grsecurity.net/`](https://grsecurity.net/)。

要直接了解有关使用类似 Grsecurity 的工具提供的功能集，请访问以下链接：

[`grsecurity.net/features.php`](http://grsecurity.net/features.php)

在此页面，项目将被分为以下五个类别：

+   内存损坏防御

+   文件系统加固

+   其他保护

+   RBAC

+   GCC 插件

## Lynis

Lynis 是一个用于审核系统安全性的开源工具。它直接在主机上运行，因此可以访问 Linux 内核本身以及其他各种项目。Lynis 可以在几乎所有 Unix 操作系统上运行，包括以下操作系统：

+   AIS

+   FreeBSD

+   Mac OS

+   Linux

+   Solaris

Lynis 是一个 shell 脚本编写的工具，因此，它与在系统上复制和粘贴以及运行简单命令一样容易：

```
./lynis audit system

```

在运行时，将执行以下操作：

+   确定操作系统

+   执行搜索以获取可用工具和实用程序

+   检查是否有 Lynis 更新

+   从启用的插件运行测试

+   按类别运行安全性测试

+   报告安全扫描状态

更多信息请访问[`rootkit.nl/projects/lynis.html`](https://rootkit.nl/projects/lynis.html)和[`cisofy.com/lynis/`](https://cisofy.com/lynis/)。

# 总结

在本章中，我们研究了加固和保护 Linux 内核。我们首先查看了一些加固指南，然后深入了解了 SANS 研究所加固指南的概述。我们还研究了如何通过各种补丁来防止内核和应用程序中的缓冲区溢出。我们还研究了各种访问控制、SELinux 和 AppArmor。最后，我们还研究了两种加固工具，可以将它们添加到我们的软件工具箱中，即 Grsecurity 和 Lynis。

在下一章中，我们将看一下 Docker Bench 安全应用程序。这是一个可以查看各种 Docker 项目的应用程序，比如主机配置、Docker 守护程序配置、守护程序配置文件、容器镜像和构建文件、容器运行时，最后是 Docker 安全操作。它将包含大量代码输出的实际示例。


# 第四章：安全的 Docker Bench

在本章中，我们将看一下**Docker 安全基准**。这是一个工具，可用于扫描您的 Docker 环境，从主机级别开始检查所有这些主机的各个方面，检查 Docker 守护程序及其配置，检查在 Docker 主机上运行的容器，并审查 Docker 安全操作，并为您提供跨越威胁或关注的建议，您可能希望查看以解决它。在本章中，我们将看以下项目：

+   **Docker 安全** - 最佳实践

+   **Docker** - 最佳实践

+   **互联网安全中心**（**CIS**）指南

+   主机配置

+   Docker 守护程序配置

+   Docker 守护程序配置文件

+   容器镜像/运行时

+   Docker 安全操作

+   Docker Bench 安全应用程序

+   运行工具

+   理解输出

# Docker 安全 - 最佳实践

在本节中，我们将介绍使用 Docker 的最佳实践以及 CIS 指南，以正确保护 Docker 环境的所有方面。当您实际运行扫描（在本章的下一节）并获得需要或应该修复的结果时，您将参考此指南。该指南分为以下几个部分：

+   主机配置

+   Docker 守护程序配置

+   Docker 守护程序配置文件

+   容器镜像/运行时

+   Docker 安全操作

# Docker - 最佳实践

在我们深入研究 CIS 指南之前，让我们回顾一些在使用 Docker 时的最佳实践：

+   **每个容器一个应用程序**：将您的应用程序分布到每个容器中。Docker 就是为此而构建的，这样做会让一切变得更加简单。我们之前谈到的隔离就是关键所在。

+   **审查谁可以访问您的 Docker 主机**：请记住，谁拥有访问您的 Docker 主机的权限，谁就可以操纵主机上的所有镜像和容器。

+   **使用最新版本**：始终使用最新版本的 Docker。这将确保所有安全漏洞都已修补，并且您也拥有最新的功能。

+   **使用资源**：如果需要帮助，请使用可用资源。Docker 社区庞大而乐于助人。充分利用他们的网站、文档和**Internet Relay Chat**（**IRC**）聊天室。

# CIS 指南

CIS 指南是一份文件（[`benchmarks.cisecurity.org/tools2/docker/cis_docker_1.6_benchmark_v1.0.0.pdf`](https://benchmarks.cisecurity.org/tools2/docker/cis_docker_1.6_benchmark_v1.0.0.pdf)），它涵盖了 Docker 部件的各个方面，以帮助您安全地配置 Docker 环境的各个部分。我们将在以下部分进行介绍。

## 主机配置

本指南的这一部分涉及配置您的 Docker 主机。这是 Docker 环境中所有容器运行的部分。因此，保持其安全性至关重要。这是对抗攻击者的第一道防线。

## Docker 守护程序配置

本指南的这一部分建议保护运行中的 Docker 守护程序。您对 Docker 守护程序配置所做的每一项更改都会影响每个容器。这些是您可以附加到 Docker 守护程序的开关，我们之前看到的，以及在我们运行工具时将在以下部分看到的项目。

## Docker 守护程序配置文件

本指南的这一部分涉及 Docker 守护程序使用的文件和目录。这涵盖了从权限到所有权的范围。有时，这些区域可能包含您不希望他人知道的信息，这些信息可能以纯文本格式存在。

## 容器镜像/运行时

本指南的这一部分包含了保护容器镜像以及容器运行时的信息。

第一部分包含镜像，涵盖了基础镜像和使用的构建文件。您需要确保您使用的镜像不仅适用于基础镜像，还适用于 Docker 体验的任何方面。本指南的这一部分涵盖了在创建自己的基础镜像时应遵循的项目，以确保它们是安全的。

第二部分，容器运行时，涵盖了许多与安全相关的项目。您必须注意您提供的运行时变量。在某些情况下，攻击者可以利用它们来获得优势，而您可能认为您正在利用它们来获得自己的优势。在您的容器中暴露太多内容可能会危及不仅该容器的安全性，还会危及 Docker 主机和在该主机上运行的其他容器的安全性。

## Docker 安全操作

本指南的这一部分涵盖了涉及部署的安全领域。这些项目与最佳实践和建议更密切地相关，这些项目应该遵循。

# Docker Bench Security 应用程序

在本节中，我们将介绍 Docker Benchmark Security 应用程序，您可以安装和运行该工具。该工具将检查以下组件：

+   主机配置

+   Docker 守护进程配置

+   Docker 守护进程配置文件

+   容器镜像和构建文件

+   容器运行时

+   Docker 安全操作

看起来很熟悉？应该是的，因为这些是我们在上一节中审查的相同项目，只是内置到一个应用程序中，它将为您做很多繁重的工作。它将向您显示配置中出现的警告，并提供有关其他配置项甚至通过测试的项目的信息。

我们将看看如何运行该工具，一个实时例子，以及进程输出的含义。

## 运行工具

运行该工具很简单。它已经被打包到一个 Docker 容器中。虽然您可以获取源代码并自定义输出或以某种方式操纵它（比如，通过电子邮件输出），但默认情况可能是您所需要的一切。

代码在这里找到：[`github.com/docker/docker-bench-security`](https://github.com/docker/docker-bench-security)

要运行该工具，我们只需将以下内容复制并粘贴到我们的 Docker 主机中：

```
$ docker run -it --net host --pid host --cap-add audit_control \
-v /var/lib:/var/lib \
-v /var/run/docker.sock:/var/run/docker.sock \
-v /usr/lib/systemd:/usr/lib/systemd \
-v /etc:/etc --label docker_bench_security \
docker/docker-bench-security

```

如果您还没有该镜像，它将首先下载该镜像，然后为您启动该进程。现在我们已经看到了安装和运行它有多么简单，让我们看一个 Docker 主机上的例子，看看它实际上做了什么。然后我们将查看输出并深入分析它。

还有一个选项可以克隆 Git 存储库，输入`git clone`命令的目录，并运行提供的 shell 脚本。所以，我们有多个选择！

让我们看一个例子，并分解每个部分，如下命令所示：

```
# ------------------------------------------------------------------------------
# Docker Bench for Security v1.0.0
#
# Docker, Inc. (c) 2015
#
# Checks for dozens of common best-practices around deploying Docker containers in production.
# Inspired by the CIS Docker 1.6 Benchmark:
# https://benchmarks.cisecurity.org/tools2/docker/CIS_Docker_1.6_Benchmark_v1.0.0.pdf
# ------------------------------------------------------------------------------

Initializing Sun Jan 17 19:18:56 UTC 2016

```

### 运行工具 - 主机配置

让我们看看主机配置运行时的输出：

```
[INFO] 1 - Host configuration
[WARN] 1.1  - Create a separate partition for containers
[PASS] 1.2  - Use an updated Linux Kernel
[PASS] 1.5  - Remove all non-essential services from the host - Network
[PASS] 1.6  - Keep Docker up to date
[INFO]       * Using 1.9.1 which is current as of 2015-11-09
[INFO]       * Check with your operating system vendor for support and security maintenance for docker
[INFO] 1.7  - Only allow trusted users to control Docker daemon
[INFO]      * docker:x:100:docker
[WARN] 1.8  - Failed to inspect: auditctl command not found.
[INFO] 1.9  - Audit Docker files and directories - /var/lib/docker
[INFO]      * Directory not found
[WARN] 1.10 - Failed to inspect: auditctl command not found.
[INFO] 1.11 - Audit Docker files and directories - docker-registry.service
[INFO]      * File not found
[INFO] 1.12 - Audit Docker files and directories - docker.service
[INFO]      * File not found
[WARN] 1.13 - Failed to inspect: auditctl command not found.
[INFO] 1.14 - Audit Docker files and directories - /etc/sysconfig/docker
[INFO]      * File not found
[INFO] 1.15 - Audit Docker files and directories - /etc/sysconfig/docker-network
[INFO]      * File not found
[INFO] 1.16 - Audit Docker files and directories - /etc/sysconfig/docker-registry
[INFO]      * File not found
[INFO] 1.17 - Audit Docker files and directories - /etc/sysconfig/docker-storage
[INFO]      * File not found
[INFO] 1.18 - Audit Docker files and directories - /etc/default/docker
[INFO]      * File not found

```

### 运行工具 - Docker 守护进程配置

让我们看看 Docker 守护进程配置运行时的输出，如下命令所示：

```
[INFO] 2 - Docker Daemon Configuration
[PASS] 2.1  - Do not use lxc execution driver
[WARN] 2.2  - Restrict network traffic between containers
[PASS] 2.3  - Set the logging level
[PASS] 2.4  - Allow Docker to make changes to iptables
[PASS] 2.5  - Do not use insecure registries
[INFO] 2.6  - Setup a local registry mirror
[INFO]      * No local registry currently configured
[WARN] 2.7  - Do not use the aufs storage driver
[PASS] 2.8  - Do not bind Docker to another IP/Port or a Unix socket
[INFO] 2.9  - Configure TLS authentication for Docker daemon
[INFO]      * Docker daemon not listening on TCP
[INFO] 2.10 - Set default ulimit as appropriate
[INFO]      * Default ulimit doesn't appear to be set

```

### 运行工具 - Docker 守护进程配置文件

让我们看看 Docker 守护进程配置文件运行时的输出，如下所示：

```
[INFO] 3 - Docker Daemon Configuration Files
[INFO] 3.1  - Verify that docker.service file ownership is set to root:root
[INFO]      * File not found
[INFO] 3.2  - Verify that docker.service file permissions are set to 644
[INFO]      * File not found
[INFO] 3.3  - Verify that docker-registry.service file ownership is set to root:root
[INFO]      * File not found
[INFO] 3.4  - Verify that docker-registry.service file permissions are set to 644
[INFO]      * File not found
[INFO] 3.5  - Verify that docker.socket file ownership is set to root:root
[INFO]      * File not found
[INFO] 3.6  - Verify that docker.socket file permissions are set to 644
[INFO]      * File not found
[INFO] 3.7  - Verify that Docker environment file ownership is set to root:root
[INFO]      * File not found
[INFO] 3.8  - Verify that Docker environment file permissions are set to 644
[INFO]      * File not found
[INFO] 3.9  - Verify that docker-network environment file ownership is set to root:root
[INFO]      * File not found
[INFO] 3.10 - Verify that docker-network environment file permissions are set to 644
[INFO]      * File not found
[INFO] 3.11 - Verify that docker-registry environment file ownership is set to root:root
[INFO]      * File not found
[INFO] 3.12 - Verify that docker-registry environment file permissions are set to 644
[INFO]      * File not found
[INFO] 3.13 - Verify that docker-storage environment file ownership is set to root:root
[INFO]      * File not found
[INFO] 3.14 - Verify that docker-storage environment file permissions are set to 644
[INFO]      * File not found
[PASS] 3.15 - Verify that /etc/docker directory ownership is set to root:root
[PASS] 3.16 - Verify that /etc/docker directory permissions are set to 755
[INFO] 3.17 - Verify that registry certificate file ownership is set to root:root
[INFO]      * Directory not found
[INFO] 3.18 - Verify that registry certificate file permissions are set to 444
[INFO]      * Directory not found
[INFO] 3.19 - Verify that TLS CA certificate file ownership is set to root:root
[INFO]      * No TLS CA certificate found
[INFO] 3.20 - Verify that TLS CA certificate file permissions are set to 444
[INFO]      * No TLS CA certificate found
[INFO] 3.21 - Verify that Docker server certificate file ownership is set to root:root
[INFO]      * No TLS Server certificate found
[INFO] 3.22 - Verify that Docker server certificate file permissions are set to 444
[INFO]      * No TLS Server certificate found
[INFO] 3.23 - Verify that Docker server key file ownership is set to root:root
[INFO]      * No TLS Key found
[INFO] 3.24 - Verify that Docker server key file permissions are set to 400
[INFO]      * No TLS Key found
[PASS] 3.25 - Verify that Docker socket file ownership is set to root:docker
[PASS] 3.26 - Verify that Docker socket file permissions are set to 660

```

### 运行工具 - 容器镜像和构建文件

让我们看看容器镜像和构建文件运行时的输出，如下命令所示：

```
[INFO] 4 - Container Images and Build Files
[INFO] 4.1  - Create a user for the container
[INFO]      * No containers running

```

### 运行工具 - 容器运行时

让我们看看容器运行时的输出，如下所示：

```
[INFO] 5  - Container Runtime
[INFO]      * No containers running, skipping Section 5

```

### 运行工具 - Docker 安全操作

让我们来看一下 Docker 安全操作运行时的输出，如下命令所示：

```
[INFO] 6  - Docker Security Operations
[INFO] 6.5 - Use a centralized and remote log collection service
[INFO]      * No containers running
[INFO] 6.6 - Avoid image sprawl
[INFO]      * There are currently: 23 images
[WARN] 6.7 - Avoid container sprawl
[WARN]      * There are currently a total of 51 containers, with only 1 of them currently running

```

哇！大量的输出和大量的内容需要消化；但这一切意味着什么？让我们来看看并分解每个部分。

## 理解输出

我们将看到三种类型的输出，如下所示：

+   【通过】：这些项目是可靠的，可以直接使用。它们不需要任何关注，但是阅读它们会让您感到温暖。越多越好！

+   【信息】：这些是您应该审查并修复的项目，如果您认为它们与您的设置和安全需求相关。

+   【警告】：这些是需要修复的项目。这些是我们不希望看到的项目。

记住，我们在扫描中涵盖了六个主要主题，如下所示：

+   主机配置

+   Docker 守护程序配置

+   Docker 守护程序配置文件

+   容器镜像和构建文件

+   容器运行时

+   Docker 安全操作

让我们来看看我们在扫描的每个部分中看到的内容。这些扫描结果来自默认的 Ubuntu Docker 主机，在此时没有对系统进行任何调整。我们再次关注每个部分中的`[警告]`项目。当您运行您自己的扫描时，可能会出现其他警告，但这些将是最常见的，如果不是每个人都会首先遇到的。

### 理解输出 - 主机配置

让我们来看一下主机配置运行时输出：

```
[WARN] 1.1 - Create a separate partition for containers

```

对于这一点，您将希望将`/var/lib/docker`映射到一个单独的分区。

```
[WARN] 1.8 - Failed to inspect: auditctl command not found.
[WARN] 1.9 - Failed to inspect: auditctl command not found.
[WARN] 1.10 - Failed to inspect: auditctl command not found.
[WARN] 1.13 - Failed to inspect: auditctl command not found.
[WARN] 1.18 - Failed to inspect: auditctl command not found.

```

### 理解输出 - Docker 守护程序配置

让我们来看一下 Docker 守护程序配置输出：

```
[WARN] 2.2 - Restrict network traffic between containers

```

默认情况下，运行在同一 Docker 主机上的所有容器都可以访问彼此的网络流量。要防止这种情况发生，您需要在 Docker 守护程序的启动过程中添加`--icc=false`标志：

```
[WARN] 2.7 - Do not use the aufs storage driver

```

同样，您可以在 Docker 守护程序启动过程中添加一个标志，以防止 Docker 使用`aufs`存储驱动程序。在 Docker 守护程序启动时使用`-s <storage_driver>`，您可以告诉 Docker 不要使用`aufs`作为存储。建议您使用适合您所使用的 Docker 主机操作系统的最佳存储驱动程序。

### 理解输出 - Docker 守护程序配置文件

如果您使用的是原始的 Docker 守护程序，您不应该看到任何警告。如果您以某种方式定制了代码，可能会在这里收到一些警告。这是您希望永远不会看到任何警告的一个领域。

### 理解输出-容器镜像和构建文件

让我们来看看容器镜像和构建文件运行时输出的输出：

```
[WARN] 4.1 - Create a user for the container
[WARN] * Running as root: suspicious_mccarthy

```

这说明`suspicious_mccarthy`容器正在以 root 用户身份运行，建议创建另一个用户来运行您的容器。

### 理解输出-容器运行时

让我们来看看容器运行时输出的输出，如下所示：

```
[WARN] 5.1: - Verify AppArmor Profile, if applicable
[WARN] * No AppArmorProfile Found: suspicious_mccarthy

```

这说明`suspicious_mccarthy`容器没有`AppArmorProfile`，这是 Ubuntu 中提供的额外安全性。

```
[WARN] 5.3 - Verify that containers are running only a single main process
[WARN] * Too many processes running: suspicious_mccarthy

```

这个错误非常直接。您需要确保每个容器只运行一个进程。如果运行多个进程，您需要将它们分布在多个容器中，并使用容器链接，如下命令所示：

```
[WARN] 5.4 - Restrict Linux Kernel Capabilities within containers
[WARN] * Capabilities added: CapAdd=[audit_control] to suspicious_mccarthy

```

这说明`audit_control`功能已添加到此运行的容器中。您可以使用`--cap-drop={}`从您的`docker run`命令中删除容器的额外功能，如下所示：

```
[WARN] 5.6 - Do not mount sensitive host system directories on containers
[WARN] * Sensitive directory /etc mounted in: suspicious_mccarthy
[WARN] * Sensitive directory /lib mounted in: suspicious_mccarthy
[WARN] 5.7 - Do not run ssh within containers
[WARN] * Container running sshd: suspicious_mccarthy

```

这很直接。不需要在容器内运行 SSH。您可以使用 Docker 提供的工具来对容器进行所有操作。确保任何容器中都没有运行 SSH。您可以使用`docker exec`命令来执行对容器的操作（更多信息请参见：[`docs.docker.com/engine/reference/commandline/exec/`](https://docs.docker.com/engine/reference/commandline/exec/)），如下命令所示：

```
[WARN] 5.10 - Do not use host network mode on container
[WARN] * Container running with networking mode 'host':
suspicious_mccarthy

```

这个问题在于，当容器启动时，传递了`--net=host`开关。不建议使用这个开关，因为它允许容器修改网络配置，并打开低端口号，以及访问 Docker 主机上的网络服务，如下所示：

```
[WARN] 5.11 - Limit memory usage for the container
[WARN] * Container running without memory restrictions:
suspicious_mccarthy

```

默认情况下，容器没有内存限制。如果在 Docker 主机上运行多个容器，这可能很危险。您可以在发出`docker run`命令时使用`-m`开关来限制容器的内存使用量。值以兆字节为单位（即 512 MB 或 1024 MB），如下命令所示：

```
[WARN] 5.12 - Set container CPU priority appropriately
[WARN] * The container running without CPU restrictions:
suspicious_mccarthy

```

与内存选项一样，您还可以在每个容器上设置 CPU 优先级。这可以在发出`docker run`命令时使用`--cpu-shares`开关来完成。CPU 份额基于数字 1,024。因此，一半将是 512，25%将是 256。使用 1,024 作为基本数字来确定 CPU 份额，如下所示：

```
[WARN] 5.13 - Mount container's root filesystem as readonly
[WARN] * Container running with root FS mounted R/W:
suspicious_mccarthy

```

您确实希望将容器用作不可变环境，这意味着它们不会在内部写入任何数据。数据应该写入卷。同样，您可以使用`--read-only`开关，如下所示：

```
[WARN] 5.16 - Do not share the host's process namespace
[WARN] * Host PID namespace being shared with: suspicious_mccarthy

```

当您使用`--pid=host`开关时会出现此错误。不建议使用此开关，因为它会破坏容器和 Docker 主机之间的进程隔离。

### 理解输出- Docker 安全操作

再次，您希望永远不要看到的另一个部分是如果您使用的是标准 Docker，则会看到警告。在这里，您将看到信息，并应该审查以确保一切正常。

# 总结

在本章中，我们看了一下 Docker 的 CIS 指南。这个指南将帮助您设置 Docker 环境的多个方面。最后，我们看了一下 Docker 安全基准。我们看了如何启动它并进行了一个示例，展示了运行后的输出。然后我们看了输出以了解其含义。请记住应用程序涵盖的六个项目：主机配置、Docker 守护程序配置、Docker 守护程序配置文件、容器镜像和构建文件、容器运行时和 Docker 安全操作。

在下一章中，我们将看一下如何监视以及报告您遇到的任何 Docker 安全问题。这将帮助您了解在现有环境中可能与安全有关的任何内容。如果您遇到自己发现的与安全有关的问题，有最佳实践可用于报告这些问题，以便 Docker 有时间修复它们，然后再允许公共社区知道这个问题，这将使黑客能够利用这些漏洞。


# 第五章：监控和报告 Docker 安全事件

在本章中，我们将看看如何及时了解 Docker 发布的安全发现，以便了解您的环境。此外，我们将看看如何安全地报告您发现的任何安全问题，以确保 Docker 有机会在问题变得公开和普遍之前缓解这些问题。在本章中，我们将涵盖以下主题：

+   Docker 安全监控

+   Docker **常见漏洞和暴露** (**CVE**)

+   邮件列表

+   Docker 安全报告

+   负责任的披露

+   安全报告

+   其他 Docker 资源

+   Docker Notary

+   硬件签名

+   阅读材料

# Docker 安全监控

在本节中，我们将看一些监控与您可能使用的任何 Docker 产品相关的安全问题的方法。在使用各种产品时，您需要能够了解是否存在任何安全问题，以便您可以减轻这些风险，保持您的环境和数据安全。

# Docker CVE

要了解 Docker CVE 是什么，您首先需要知道什么是 CVE。CVE 实际上是由 MITRE 公司维护的系统。这些用作以 CVE 编号为基础的公开提供信息的方式，每个漏洞都有一个专用的 CVE 编号以便易于参考。这允许 MITRE 公司为所有获得 CVE 编号的漏洞建立一个国家数据库。要了解更多关于 CVE 的信息，您可以在维基百科文章中找到：

[`en.wikipedia.org/wiki/Common_Vulnerabilities_and_Exposures`](https://en.wikipedia.org/wiki/Common_Vulnerabilities_and_Exposures)

维基百科文章解释了它们如何分配 CVE 编号以及它们遵循的格式。

现在您知道了 CVE 是什么，您可能已经了解了 Docker CVE 是什么。它们是直接与 Docker 安全事件或问题相关的 CVE。要了解更多关于 Docker CVE 的信息或查看当前 Docker CVE 的列表，请访问[`www.docker.com/docker-cve-database`](https://www.docker.com/docker-cve-database)。

此列表将在为 Docker 产品创建 CVE 时随时更新。正如您所见，列表非常小，因此，这可能是一个不会以日常或甚至每月频率增长的列表。

# 邮件列表

在生态系统中跟踪或讨论任何 Docker 产品的安全相关问题的另一种方法是加入他们的邮件列表。目前，他们有两个邮件列表，你可以加入或者跟随。

第一个是开发者列表，你可以加入或者跟随。这个列表是为那些要么帮助贡献 Docker 产品的代码，要么使用 Docker 代码库开发产品的人准备的。链接如下：

[`groups.google.com/forum/#!forum/docker-dev`](https://groups.google.com/forum/#!forum/docker-dev)

第二个列表是用户列表。这个列表是为那些可能有安全相关问题的各种 Docker 产品的用户准备的。你可以搜索已经提交的讨论，加入现有的对话，或者提出新问题，会有其他在邮件列表上的人回答你的问题。论坛链接如下：

[`groups.google.com/forum/#!forum/docker-user`](https://groups.google.com/forum/#!forum/docker-user)

在提出安全相关问题之前，你需要阅读以下部分，以确保你不会暴露任何可能引诱攻击者的现有安全问题。

# Docker 安全报告

报告 Docker 安全问题和监控 Docker 安全问题一样重要。虽然报告这些问题很重要，但是当你发现安全问题并希望报告时，你应该遵循一定的标准。

## 负责披露

在披露与安全相关的问题时，不仅对于 Docker，对于任何产品，都有一个叫做**负责披露**的术语，每个人都应该遵循。负责披露是一项协议，允许开发人员或产品维护者在向公众披露问题之前有充足的时间提供安全问题的修复。

要了解更多关于负责披露的信息，你可以访问[`en.wikipedia.org/wiki/Responsible_disclosure`](https://en.wikipedia.org/wiki/Responsible_disclosure)。

记得要站在负责代码的团队的角度考虑。如果这是你的代码，你不是也希望有人提醒你存在漏洞，这样你就有充足的时间在披露之前修复问题，避免造成普遍恐慌并使收件箱被大量邮件淹没吗？

## 安全报告

目前，报告安全问题的方法是给 Docker 安全团队发送电子邮件，并提供尽可能多的关于安全问题的信息。虽然这些不是 Docker 可能推荐的确切项目，但这些是大多数其他安全专业人员在报告安全问题时喜欢看到的一般准则，例如以下内容：

+   产品和版本，在哪里发现了安全问题

+   重现问题的方法

+   当时使用的操作系统，以及版本

+   您可以提供的任何其他信息

记住，你提供的信息越多，团队就能更快地从他们的角度做出反应，从一开始就更积极地对问题进行攻击。

要报告任何与 Docker 相关产品的安全问题，请确保将任何信息发送到`<security@docker.com>`

# 额外的 Docker 安全资源

如果你正在寻找其他要查看的项目，我们在第一章中涵盖了一些额外的项目，值得进行快速审查。确保回顾第一章，以获取有关接下来的几个项目或每个部分提供的链接的更多详细信息。

## Docker Notary

让我们快速看一下**Docker Notary**，但是要了解有关 Docker Notary 的更多信息，您可以回顾第二章中的信息，*保护 Docker 组件*或以下 URL：

[`github.com/docker/notary`](https://github.com/docker/notary)

Docker Notary 允许您使用推荐的离线保存的私钥对内容进行签名并发布。使用这些密钥对您的内容进行签名有助于确保其他人知道他们正在使用的内容实际上来自于它所说的您，并且可以信任该内容，假设用户信任您。

Docker Notary 有一些关键目标，我认为以下几点很重要：

+   可生存的密钥妥协

+   新鲜度保证

+   可配置的信任阈值

+   签名委托

+   使用现有分发

+   不受信任的镜像和传输

重要的是要知道，Docker Notary 也有服务器和客户端组件。要使用 Notary，您必须熟悉命令行环境。前面的链接将为您解释清楚，并为您提供设置和使用每个组件的演练。

## 硬件签名

与之前的 Docker Notary 部分类似，让我们快速看一下硬件签名，因为这是一个非常重要的功能，必须充分理解。

Docker 还允许硬件签名。这是什么意思？从前面的部分我们看到，您可以使用高度安全的密钥对内容进行签名，使其他人能够验证信息来自于它所说的那个人，这最终为每个人提供了极大的安心。

硬件签名通过允许您添加另一层代码签名，将其提升到一个全新的水平。通过引入一个硬件设备，Yubikey——一个 USB 硬件设备——您可以使用您的私钥（记得将它们安全地离线存放在某个地方），以及一个需要您在签署代码时轻触的硬件设备。这证明了您是一个人类，因为您在签署代码时必须亲自触摸 YubiKey。

有关 Notary 硬件签名部分的更多信息，值得阅读他们发布此功能时的公告，网址如下：

[`blog.docker.com/2015/11/docker-content-trust-yubikey/`](https://blog.docker.com/2015/11/docker-content-trust-yubikey/)

要观看使用 YubiKeys 和 Docker Notary 的视频演示，请访问以下 YouTube 网址：

[`youtu.be/fLfFFtOHRZQ?t=1h21m23s`](https://youtu.be/fLfFFtOHRZQ?t=1h21m23s)

要了解有关 YubiKeys 的更多信息，请访问其网站：

[`www.yubico.com`](https://www.yubico.com)

## 阅读材料

还有一些额外的阅读材料，可以帮助确保您的重点是监控整个 Docker 生态系统的安全方面。

回顾一下第四章，“Docker 安全基准”，我们介绍了 Docker 基准，这是一个用于扫描整个 Docker 环境的应用程序。这对于帮助指出可能存在的任何安全风险非常有用。

我还找到了一本很棒的免费 Docker 安全电子书。这本书将涵盖潜在的安全问题，以及您可以利用的工具和技术来保护您的容器环境。免费的东西不错，对吧？！您可以在以下网址找到这本书：

[`www.openshift.com/promotions/docker-security.html`](https://www.openshift.com/promotions/docker-security.html)

您可以参考以下《容器安全简介》白皮书获取更多信息：

[`d3oypxn00j2a10.cloudfront.net/assets/img/Docker%20Security/WP_Intro_to_container_security_03.20.2015.pdf`](https://d3oypxn00j2a10.cloudfront.net/assets/img/Docker%20Security/WP_Intro_to_container_security_03.20.2015.pdf)

您还可以参考以下《Docker 容器权威指南》白皮书：

[`www.docker.com/sites/default/files/WP-%20Definitive%20Guide%20To%20Containers.pdf`](https://www.docker.com/sites/default/files/WP-%20Definitive%20Guide%20To%20Containers.pdf)

最后两项——《容器安全简介》白皮书和《Docker 容器权威指南》——都是直接由 Docker 创建的，因此它们包含了直接与理解容器结构相关的信息，并且将大量 Docker 信息分解到一个中心位置，您可以随时下载或打印出来并随时使用。它们还可以帮助您了解容器的各个层，并且它们如何帮助保持您的环境和应用程序相互安全。

## Awesome Docker

虽然这不是一个与安全相关的工具，但它是一个非常有用且经常更新的 Docker 工具。Awesome Docker 是一个精选的 Docker 项目列表。它允许其他人通过拉取请求向精选列表贡献。该列表包括了想要开始使用 Docker 的人的主题；有用的文章；深入的文章；网络文章；以及关于使用多服务器 Docker 环境、云基础设施、技巧和新闻通讯的文章，列表还在不断增加。要查看该项目以及其中包含的所有*精彩*内容，请访问以下网址：

[`github.com/veggiemonk/awesome-docker`](https://github.com/veggiemonk/awesome-docker)

# 摘要

在本章中，我们看了一些监视和报告 Docker 安全问题的方法。我们看了一些邮件列表，您可以加入监视 Docker CVE 列表。我们还回顾了如何使用 Docker Notary 对您的图像进行签名，以及如何利用硬件签名来使用硬件设备，比如 YubiKeys。我们还研究了负责任的披露，即在向公众发布之前，给 Docker 修复任何安全相关问题的机会。

在下一章中，我们将研究如何使用一些 Docker 工具。这些工具可以用来保护 Docker 环境。我们将研究命令行工具和图形界面工具，您可以利用它们的优势。我们将研究如何在您的环境中使用 TLS，使用只读容器，利用内核命名空间和控制组，并减轻风险，同时注意 Docker 守护程序的攻击面。


# 第六章：使用 Docker 内置安全功能

在本章中，我们将介绍可以用来保护您的环境的 Docker 工具。我们将介绍命令行工具和 GUI 工具，您可以利用这些工具来帮助您。本章将涵盖以下内容：

+   Docker 工具

+   在您的环境中使用 TLS，以确保各个部分之间的安全通信

+   使用只读容器来帮助保护容器中的数据免受某种形式的操纵

+   Docker 安全基础知识

+   内核命名空间

+   控制组

+   Linux 内核功能

# Docker 工具

在本节中，我们将介绍可以帮助您保护 Docker 环境的工具。这些是内置在您已经使用的 Docker 软件中的选项。现在是时候学习如何启用或利用这些功能，以确保通信安全；在这里，我们将介绍启用 TLS，这是一种确保应用程序之间隐私的协议。它确保没有人在监听通信。可以将其视为观看电影时人们在电话中说“这条线路安全吗？”的情景。当涉及网络通信时，这是同样的想法。然后，我们将看看如何利用只读容器来确保您提供的数据不会被任何人操纵。

## 使用 TLS

强烈建议使用 Docker Machine 来创建和管理 Docker 主机。它将自动设置通信以使用 TLS。以下是您可以验证由`docker-machine`创建的*默认*主机是否确实使用 TLS 的方法。

一个重要因素是知道您是否在使用 TLS，然后根据实际情况调整使用 TLS。重要的是要记住，如今几乎所有的 Docker 工具都启用了 TLS，或者如果它们没有启用，它们似乎正在朝着这个目标努力。您可以使用 Docker Machine `inspect`命令来检查您的 Docker 主机是否使用了 TLS。接下来，我们将查看一个主机，并查看它是否启用了 TLS：

```
docker-machine inspect default

{
"ConfigVersion": 3,
"Driver": {
"IPAddress": "192.168.99.100",
"MachineName": "default",
"SSHUser": "docker",
"SSHPort": 50858,
"SSHKeyPath": "/Users/scottgallagher/.docker/machine/machines/default/id_rsa",
"StorePath": "/Users/scottgallagher/.docker/machine",
"SwarmMaster": false,
"SwarmHost": "tcp://0.0.0.0:3376",
"SwarmDiscovery": "",
"VBoxManager": {},
"CPU": 1,
"Memory": 2048,
"DiskSize": 204800,
"Boot2DockerURL": "",
"Boot2DockerImportVM": "",
"HostDNSResolver": false,
"HostOnlyCIDR": "192.168.99.1/24",
"HostOnlyNicType": "82540EM",
"HostOnlyPromiscMode": "deny",
"NoShare": false,
"DNSProxy": false,
"NoVTXCheck": false
},
"DriverName": "virtualbox",
"HostOptions": {
"Driver": "",
"Memory": 0,
"Disk": 0,
"EngineOptions": {
"ArbitraryFlags": [],
"Dns": null,
"GraphDir": "",
"Env": [],
"Ipv6": false,
"InsecureRegistry": [],
"Labels": [],
"LogLevel": "",
"StorageDriver": "",
"SelinuxEnabled": false,
"TlsVerify": true,
"RegistryMirror": [],
"InstallURL": "https://get.docker.com"
},
"SwarmOptions": {
"IsSwarm": false,
"Address": "",
"Discovery": "",
"Master": false,
"Host": "tcp://0.0.0.0:3376",
"Image": "swarm:latest",
"Strategy": "spread",
"Heartbeat": 0,
"Overcommit": 0,
"ArbitraryFlags": [],
"Env": null
},
"AuthOptions": {
"CertDir": "/Users/scottgallagher/.docker/machine/certs",
"CaCertPath": "/Users/scottgallagher/.docker/machine/certs/ca.pem",
"CaPrivateKeyPath": "/Users/scottgallagher/.docker/machine/certs/ca-key.pem",
"CaCertRemotePath": "",
"ServerCertPath": "/Users/scottgallagher/.docker/machine/machines/default/server.pem",
"ServerKeyPath": "/Users/scottgallagher/.docker/machine/machines/default/server-key.pem",
"ClientKeyPath": "/Users/scottgallagher/.docker/machine/certs/key.pem",
"ServerCertRemotePath": "",
"ServerKeyRemotePath": "",
"ClientCertPath": "/Users/scottgallagher/.docker/machine/certs/cert.pem",
"ServerCertSANs": [],
"StorePath": "/Users/scottgallagher/.docker/machine/machines/default"
}
},
"Name": "default"
}

```

从前面的输出中，我们可以关注以下行：

```
"SwarmHost": "tcp://0.0.0.0:3376",

```

这向我们表明，如果我们正在运行**Swarm**，这个主机将利用安全的`3376`端口。现在，如果你没有使用 Docker Swarm，那么你可以忽略这一行。但是，如果你正在使用 Docker Swarm，那么这一行就很重要。

回过头来，让我们先确定一下 Docker Swarm 是什么。Docker Swarm 是 Docker 内部的原生集群。它有助于将多个 Docker 主机转变为易于管理的单个虚拟主机：

```
"AuthOptions": {
"CertDir": "/Users/scottgallagher/.docker/machine/certs",
"CaCertPath": "/Users/scottgallagher/.docker/machine/certs/ca.pem",
"CaPrivateKeyPath": "/Users/scottgallagher/.docker/machine/certs/ca-key.pem",
"CaCertRemotePath": "",
"ServerCertPath": "/Users/scottgallagher/.docker/machine/machines/default/server.pem",
"ServerKeyPath": "/Users/scottgallagher/.docker/machine/machines/default/server-key.pem",
"ClientKeyPath": "/Users/scottgallagher/.docker/machine/certs/key.pem",
"ServerCertRemotePath": "",
"ServerKeyRemotePath": "",
"ClientCertPath": "/Users/scottgallagher/.docker/machine/certs/cert.pem",
"ServerCertSANs": [],
"StorePath": "/Users/scottgallagher/.docker/machine/machines/default"
}

```

这向我们表明这个主机实际上正在使用证书，所以我们知道它正在使用 TLS，但仅凭此如何知道呢？在接下来的部分，我们将看看如何确切地知道它是否正在使用 TLS。

Docker Machine 还有一个选项，可以通过 TLS 运行所有内容。这是使用 Docker Machine 管理 Docker 主机的最安全方式。如果你开始使用自己的证书，这种设置可能会有些棘手。默认情况下，Docker Machine 会将它使用的证书存储在`/Users/<user_id>/.docker/machine/certs/`目录下。你可以从前面的输出中看到证书存储在你的机器上的位置。

让我们看看如何实现查看我们的 Docker 主机是否使用 TLS 的目标：

```
docker-machine ls
NAME      ACTIVE   URL          STATE     URL SWARM   DOCKER   ERRORS
default   *        virtualbox   Running   tcp://192.168.99.100:2376  v1.9.1

```

这就是我们可以知道它正在使用 TLS 的地方。Docker Machine 主机的不安全端口是`2375`端口，而这个主机使用的是`2376`，这是 Docker Machine 的安全 TLS 端口。因此，这个主机实际上正在使用 TLS 进行通信，这让你放心知道通信是安全的。

## 只读容器

关于`docker run`命令，我们主要关注的是允许我们将容器内的所有内容设置为只读的选项。让我们看一个例子，并分解它到底是做什么的：

```
$ docker run --name mysql --read-only -v /var/lib/mysql v /tmp --e MYSQL_ROOT_PASSWORD=password -d mysql

```

在这里，我们正在运行一个`mysql`容器，并将整个容器设置为只读，除了`/var/lib/mysql`目录。这意味着容器内唯一可以写入数据的位置是`/var/lib/mysql`目录。容器内的任何其他位置都不允许你在其中写入任何内容。如果你尝试运行以下命令，它会失败：

```
$ docker exec mysql touch /opt/filename

```

如果你想控制容器可以写入或不写入的位置，这将非常有帮助。一定要明智地使用它。进行彻底测试，因为当应用程序无法写入某些位置时可能会产生后果。

还记得我们在之前章节中看到的 Docker 卷吗？我们能够将卷设置为只读。类似于之前的`docker run`命令，我们将所有内容设置为只读，除了指定的卷，现在我们可以做相反的操作，将单个卷（或者如果你使用更多的`-v`开关，可以是多个卷）设置为只读。关于卷需要记住的一点是，当你使用一个卷并将其挂载到容器中时，它将作为空卷挂载到容器内的目录顶部，除非你使用`--volumes-from`开关或在事后以其他方式向容器添加数据：

```
$ docker run -d -v /opt/uploads:/opt/uploads:/opt/uploads:ro nginx

```

这将在`/opt/uploads`中挂载一个卷，并将其设置为只读。如果你不希望运行的容器写入卷以保持数据或配置文件的完整性，这可能会很有用。

关于`docker run`命令，我们要看的最后一个选项是`--device=`开关。这个开关允许我们将 Docker 主机上的设备挂载到容器内的指定位置。在这样做时，我们需要意识到一些安全风险。默认情况下，当你这样做时，容器将获得对设备位置的完全访问权限：读、写和`mknod`访问。现在，你可以通过在开关命令的末尾操纵`rwm`来控制这些权限。

让我们来看看其中一些，并了解它们是如何工作的：

```
$ docker run --device=/dev/sdb:/dev/sdc2 -it ubuntu:latest /bin/bash

```

之前的命令将运行最新的 Ubuntu 镜像，并将`/dev/sdb`设备挂载到容器内的`/dev/sdc2`位置：

```
$ docker run --device=/dev/sdb:/dev/sdc2:r -it ubuntu:latest /bin/bash

```

这个命令将运行最新的 Ubuntu 镜像，并将`/dev/sdb1`设备挂载到容器内的`/dev/sdc2`位置。然而，这个命令的末尾有一个`:r`标签，指定它是只读的，不能被写入。

# Docker 安全基础知识

在前面的章节中，我们研究了一些你可以使用的 Docker 工具，比如用于通信的 TLS，以及使用只读容器来确保数据不被更改或操纵。在本节中，我们将重点介绍 Docker 生态系统中提供的一些更多选项，可以用来帮助加强你的环境安全性。我们将看一下内核命名空间，它提供了另一层抽象，通过为运行的进程提供自己的资源，这些资源只对进程本身可见，而对其他可能正在运行的进程不可见。我们将在本节中更多地了解内核命名空间。然后我们将看一下控制组。控制组，更常被称为 cgroups，让你能够限制特定进程所拥有的资源。然后我们将介绍 Linux 内核功能。通过这个，我们将看一下在使用 Docker 运行时，默认情况下对容器施加的限制。最后，我们将看一下 Docker 守护程序的攻击面，需要注意的 Docker 守护程序存在的风险，以及如何减轻这些风险。

## 内核命名空间

内核命名空间为容器提供了一种隔离形式。可以把它们看作是一个容器包裹在另一个容器中。在一个容器中运行的进程不能干扰另一个容器内运行的进程，更不用说在容器所在的 Docker 主机上运行了。它的工作方式是，每个容器都有自己的网络堆栈来操作。然而，有办法将这些容器链接在一起，以便能够相互交互；然而，默认情况下，它们是相互隔离的。内核命名空间已经存在了相当长的时间，所以它们是一种经过验证的隔离保护方法。它们在 2008 年被引入，而在撰写本书时，已经是 2016 年了。你可以看到，到了今年 7 月，它们将满八岁。因此，当你发出`docker run`命令时，你正在受益于后台进行的大量工作。这些工作正在创建自己的网络堆栈来操作。这也使得容器免受其他容器能够操纵容器的运行进程或数据的影响。

## 控制组

控制组，或更常见的称为 cgroups，是 Linux 内核的一个功能，允许您限制容器可以使用的资源。虽然它们限制资源，但它们也确保每个容器获得它所需的资源，以及没有单个容器可以使整个 Docker 主机崩溃。

使用控制组，您可以限制特定容器获得的 CPU、内存或磁盘 I/O 的数量。如果我们查看`docker run`命令的帮助，让我们突出显示我们可以控制的项目。我们只会突出显示一些对大多数用户特别有用的项目，但请查看它们，看看是否有其他项目适合您的环境，如下所示：

```
$ docker run --help

Usage: docker run [OPTIONS] IMAGE [COMMAND] [ARG...]

Run a command in a new container

-a, --attach=[]                 Attach to STDIN, STDOUT or STDERR
--add-host=[]                   Add a custom host-to-IP mapping (host:ip)
--blkio-weight=0                Block IO (relative weight), between 10 and 1000
--cpu-shares=0                  CPU shares (relative weight)
--cap-add=[]                    Add Linux capabilities
--cap-drop=[]                   Drop Linux capabilities
--cgroup-parent=                Optional parent cgroup for the container
--cidfile=                      Write the container ID to the file
--cpu-period=0                  Limit CPU CFS (Completely Fair Scheduler) period
--cpu-quota=0                   Limit CPU CFS (Completely Fair Scheduler) quota
--cpuset-cpus=                  CPUs in which to allow execution (0-3, 0,1)
--cpuset-mems=                  MEMs in which to allow execution (0-3, 0,1)
-d, --detach=false              Run container in background and print container ID
--device=[]                     Add a host device to the container
--disable-content-trust=true    Skip image verification
--dns=[]                        Set custom DNS servers
--dns-opt=[]                    Set DNS options
--dns-search=[]                 Set custom DNS search domains
-e, --env=[]                    Set environment variables
--entrypoint=                   Overwrite the default ENTRYPOINT of the image
--env-file=[]                   Read in a file of environment variables
--expose=[]                     Expose a port or a range of ports
--group-add=[]                  Add additional groups to join
-h, --hostname=                 Container host name
--help=false                    Print usage
-i, --interactive=false         Keep STDIN open even if not attached
--ipc=                          IPC namespace to use
--kernel-memory=                Kernel memory limit
-l, --label=[]                  Set meta data on a container
--label-file=[]                 Read in a line delimited file of labels
--link=[]                       Add link to another container
--log-driver=                   Logging driver for container
--log-opt=[]                    Log driver options
--lxc-conf=[]                   Add custom lxc options
-m, --memory=                   Memory limit
--mac-address=                  Container MAC address (e.g. 92:d0:c6:0a:29:33)
--memory-reservation=           Memory soft limit
--memory-swap=                  Total memory (memory + swap), '-1' to disable swap
--memory-swappiness=-1          Tuning container memory swappiness (0 to 100)
--name=                         Assign a name to the container
--net=default                   Set the Network for the container
--oom-kill-disable=false        Disable OOM Killer
-P, --publish-all=false         Publish all exposed ports to random ports
-p, --publish=[]                Publish a container's port(s) to the host
--pid=                          PID namespace to use
--privileged=false              Give extended privileges to this container
--read-only=false               Mount the container's root filesystem as read only
--restart=no                    Restart policy to apply when a container exits
--rm=false                      Automatically remove the container when it exits
--security-opt=[]               Security Options
--sig-proxy=true                Proxy received signals to the process
--stop-signal=SIGTERM           Signal to stop a container, SIGTERM by default
-t, --tty=false                 Allocate a pseudo-TTY
-u, --user=                     Username or UID (format: <name|uid>[:<group|gid>])
--ulimit=[]                     Ulimit options
--uts=                          UTS namespace to use
-v, --volume=[]                 Bind mount a volume
--volume-driver=                Optional volume driver for the container
--volumes-from=[]               Mount volumes from the specified container(s)
-w, --workdir=                  Working directory inside the container

```

正如您可以从前面突出显示的部分看到的，这些只是您可以在每个容器基础上控制的一些项目。

## Linux 内核功能

Docker 使用内核功能来放置 Docker 在启动或启动容器时放置的限制。限制根访问是这些内核功能的最终目标。有一些通常以 root 身份运行的服务，但现在可以在没有这些权限的情况下运行。其中一些包括`SSH`、`cron`和`syslogd`。

总的来说，这意味着您不需要像通常想的那样在服务器上拥有 root 权限。您可以以降低的容量集运行。这意味着您的 root 用户不需要通常需要的特权。

您可能不再需要启用的一些项目如下所示：

+   执行挂载操作

+   使用原始套接字，这将有助于防止数据包欺骗

+   创建新设备

+   更改文件的所有者

+   更改属性

这有助于防止如果有人破坏了一个容器，那么他们无法提升到您提供的更高权限。要从运行的容器提升到运行的 Docker 主机，将会更加困难，甚至不可能。由于这种复杂性，攻击者可能会选择其他地方而不是您的 Docker 环境来尝试攻击。Docker 还支持添加和删除功能，因此建议删除所有功能，除了您打算使用的功能。例如，可以在`docker run`命令上使用`-cap-add net_bind_service`开关。

# 容器与虚拟机

希望您信任您的组织和所有可以访问这些系统的人。您很可能会从头开始设置虚拟机。由于其庞大的体积，很可能无法从他人那里获取虚拟机。因此，您将了解虚拟机内部的情况。也就是说，对于 Docker 容器，您可能不知道您可能在容器中使用的镜像中有什么。

# 总结

在本章中，我们研究了将 TLS 部署到我们 Docker 环境的所有部分，以便确保所有通信都是安全的，流量不能被拦截和解释。我们还了解了如何利用只读容器来确保提供的数据不能被篡改。然后，我们看了如何为进程提供它们自己的抽象，比如网络、挂载、用户等。接着，我们深入了解了控制组，或者更常见的称为 cgroups，作为限制进程或容器资源的一种方式。我们还研究了 Linux 内核的功能，即在启动或启动容器时施加的限制。最后，我们深入了解了如何减轻针对 Docker 守护程序攻击面的风险。

在下一章中，我们将研究使用第三方工具保护 Docker，并了解除 Docker 提供的工具之外，还有哪些第三方工具可以帮助您保护环境，以确保在 Docker 上运行时保持应用程序的安全。
