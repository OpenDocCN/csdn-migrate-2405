# GPT3 探索指南（六）

> 原文：[`zh.annas-archive.org/md5/e19ec4b9c1d08c12abd2983dace7ff20`](https://zh.annas-archive.org/md5/e19ec4b9c1d08c12abd2983dace7ff20)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第十一章：Docker 安全性

概述

在本章中，我们将为您提供所需的信息，以确保您的容器是安全的，并且不会对使用其上运行的应用程序的人员构成安全风险。您将使用特权和非特权容器，并了解为什么不应该以 root 用户身份运行容器。本章将帮助您验证镜像是否来自可信的来源，使用签名密钥。您还将为 Docker 镜像设置安全扫描，确保您的镜像可以安全使用和分发。您将使用 AppArmor 进一步保护您的容器，并使用 Linux 的安全计算模式（`seccomp`）来创建和使用`seccomp`配置文件与您的 Docker 镜像。

# 介绍

本章试图解决一个可以专门写一本书的主题。我们试图在教育您如何使用 Docker 来处理安全性方面走一部分路。之前的章节已经为您提供了使用 Docker 构建应用程序的坚实基础，本章希望利用这些信息为它们提供安全稳定的容器来运行。

Docker 和微服务架构使我们能够从更安全和健壮的环境开始管理我们的服务，但这并不意味着我们需要完全忘记安全性。本章详细介绍了在创建和维护跨环境服务时需要考虑的一些方面，以及您可以开始在工作系统中实施这些程序的方式。

Docker 安全性不应该与您的常规 IT 安全流程分开，因为概念是相同的。Docker 有不同的处理这些概念的方法，但总的来说，开始使用 Docker 安全性的好地方包括以下内容：

+   **访问控制**：确保运行的容器无法被攻击者访问，并且权限也受到限制。

+   **更新和修补操作系统**：我们需要确保我们使用的镜像来自可信的来源。我们还需要能够扫描我们的镜像，以确保引入的任何应用程序也不会引入额外的漏洞。

+   **数据敏感性**：所有敏感信息都应该保持不可访问。这可能是密码、个人信息，或者任何您不希望被任何人获取的数据。

在本章中，我们将涵盖许多信息，包括前述的内容以及更多。我们将首先考虑在运行时您的 Docker 容器可能具有的不同访问权限，以及您如何开始限制它们可以执行的操作。然后，我们将更仔细地研究如何保护镜像，使用签名密钥，以及如何验证它们来自可信任的来源。我们还将练习扫描您的镜像以确保它们可以安全使用的已知漏洞。本章的最后两节将重点介绍使用 AppArmor 和`seccomp`安全配置文件来进一步限制正在运行的容器的功能和访问权限。

注意

在 Docker 镜像中使用密码和秘钥时，编排方法如 Swarm 和 Kubernetes 提供了安全的存储秘钥的方式，无需将它们存储为明文配置供所有人访问。如果您没有使用这些编排方法，我们也将在下一章提供一些关于如何在镜像中使用秘钥的想法。

# 容器中的特权和 root 用户访问权限

提高容器安全性的一个重要方法是减少攻击者在获得访问权限后可以做的事情。攻击者在容器上可以运行的命令类型受限于运行容器进程的用户的访问权限级别。因此，如果运行容器的用户没有 root 或提升的特权，这将限制攻击者可以做的事情。另一个需要记住的事情是，如果容器被攻破并以 root 用户身份运行，这也可能允许攻击者逃离容器并访问运行 Docker 的主机系统。

容器上运行的大多数进程都是不需要 root 访问权限的应用程序，这与在服务器上运行进程是一样的，您也不会将它们作为 root 运行。在容器上运行的应用程序应该只能访问它们所需的内容。提供 root 访问权限的原因，特别是在基础镜像中，是因为应用程序需要安装在容器上，但这应该只是一个临时措施，您的完整镜像应该以另一个用户身份运行。

为了做到这一点，在创建我们的镜像时，我们可以设置一个 Dockerfile 并创建一个将在容器上运行进程的用户。下面这行与在 Linux 命令行上设置用户相同，我们首先设置组，然后将用户分配到这个组中：

```
RUN addgroup --gid <GID> <UID> && adduser <UID> -h <home_directory> --disabled-password --uid <UID> --ingroup <UID> <user_name>
```

在上述命令中，我们还使用`adduser`选项来设置`home`目录并禁用登录密码。

注意

`addgroup`和`adduser`是特定于基于 Alpine 的镜像的命令，这些镜像是基于 Linux 的镜像，但使用不同的软件包和实用程序来自基于 Debian 的镜像。Alpine 镜像使用这些软件包的原因是它们选择更轻量级的实用程序和应用程序。如果您使用的是基于 Ubuntu/Debian 或 Red Hat 的镜像，您需要改用`useradd`和`groupadd`命令，并使用这些命令的相关选项。

正如您将在即将进行的练习中看到的，我们将切换到我们专门创建的用户以创建我们将要运行的进程。您可以自行决定组和用户的名称，但许多用户更喜欢使用四位或五位数字作为这将不会向潜在攻击者突出显示该用户的任何更多特权，并且通常是创建用户和组的标准做法。在我们的 Dockerfile 中，在创建进程之前，我们包括`USER`指令，并包括我们先前创建的用户的用户 ID：

```
USER <UID>
```

在本章的这一部分，我们将介绍一个新的镜像，并展示如果容器上的进程由 root 用户运行可能会出现的问题。我们还将向您展示容器中的 root 用户与底层主机上的 root 用户是相同的。然后，我们将更改我们的镜像，以展示删除容器上运行的进程的 root 访问权限的好处。

注意

请使用`touch`命令创建文件，并使用`vim`命令在文件上使用 vim 编辑器进行操作。

## 练习 11.01：以 root 用户身份运行容器

当我们以 root 用户身份运行容器进程时，可能会出现许多问题。本练习将演示特定的安全问题，例如更改访问权限、终止进程、对 DNS 进行更改，以及您的镜像和底层操作系统可能会变得脆弱。您将注意到，作为 root 用户，攻击者还可以使用诸如`nmap`之类的工具来扫描网络以查找开放的端口和网络目标。

您还将纠正这些问题，从而限制攻击者在运行容器上的操作：

1.  使用您喜欢的文本编辑器创建一个名为`Dockerfile_original`的新 Dockerfile，并将以下代码输入文件。在此步骤中，所有命令都是以 root 用户身份运行的：

```
1 FROM alpine
2
3 RUN apk update
4 RUN apk add wget curl nmap libcap
5
6 RUN echo "#!/sh\n" > test_memory.sh
7 RUN echo "cat /proc/meminfo; mpstat; pmap -x 1"     >> test_memory.sh
8 RUN chmod 755 test_memory.sh
9
10 CMD ["sh", "test_memory.sh"]
```

这将创建一个基本的应用程序，将运行一个名为`test_memory.sh`的小脚本，该脚本使用`meminfo`，`mpstat`和`pmap`命令来提供有关容器内存状态的详细信息。您还会注意到在*第 4 行*上，我们正在安装一些额外的应用程序，以使用`nmap`查看网络进程，并使用`libcap`库查看用户容器的功能。

1.  构建`security-app`镜像并在同一步骤中运行该镜像：

```
docker build -t security-app . ; docker run –rm security-app
```

输出已经大大减少，您应该看到镜像构建，然后运行内存报告：

```
MemTotal:        2036900 kB
MemFree:         1243248 kB
MemAvailable:    1576432 kB
Buffers:          73240 kB
…
```

1.  使用`whoami`命令查看容器上的运行用户：

```
docker run --rm security-app whoami
```

不应该让人感到惊讶的是运行用户是 root 用户：

```
root
```

1.  使用`capsh –print`命令查看用户在容器上能够运行的进程。作为 root 用户，您应该拥有大量的功能：

```
docker run --rm -it security-app capsh –print
```

您会注意到用户可以访问更改文件所有权（`cap_chown`），杀死进程（`cap_kill`）和对 DNS 进行更改（`cap_net_bind_service`）等功能。这些都是可以在运行环境中引起许多问题的高级进程，不应该对容器可用：

```
Current: = cap_chown,cap_dac_override,cap_fowner,cap_fsetid,
cap_kill,cap_setgid,cap_setuid,cap_setpcap,cap_net_bind_service,
cap_net_raw,cap_sys_chroot,cap_mknod,cap_audit_write,
cap_setfcap+eip
groups=0(root),1(bin),2(daemon),3(sys),4(adm),6(disk),10(wheel),
11(floppy),20(dialout),26(tape),27(video)
```

1.  作为 root 用户，攻击者还可以使用我们之前安装的`nmap`等工具来扫描网络以查找开放的端口和网络目标。通过传递`nmap`命令再次运行您的容器镜像，查找`localhost`下已打开的`443`端口：

```
docker run --rm -it security-app sh -c 'nmap -sS -p 443 localhost'
```

命令的输出如下：

```
Starting Nmap 7.70 ( https://nmap.org ) at 2019-11-13 02:40 UTC
Nmap scan report for localhost (127.0.0.1)
Host is up (0.000062s latency).
Other addresses for localhost (not scanned): ::1
PORT    STATE  SERVICE
443/tcp closed https
Nmap done: 1 IP address (1 host up) scanned in 0.27 seconds
```

注意

前面的`nmap`扫描没有找到任何开放的网络，但这是一个不应该能够由任何用户运行的提升命令。我们将在本练习的后面演示非 root 用户无法运行此命令。

1.  如前所述，在容器上作为 root 用户与在底层主机上作为 root 用户是相同的。这可以通过将一个由 root 拥有的文件挂载到容器上来证明。为此，创建一个秘密文件。将您的秘密密码回显到`/tmp/secret.txt`文件中：

```
echo "secret password" > /tmp/secret.txt
```

更改所有权以确保 root 用户拥有它：

```
sudo chown root /tmp/secret.txt
```

1.  使用`docker run`命令将文件挂载到运行的容器上，并检查是否能够访问并查看文件中的数据。容器上的用户可以访问只有主机系统上的 root 用户才能访问的文件：

```
docker run -v /tmp/secret.txt:/tmp/secret.txt security-app sh -c 'cat /tmp/secret.txt'
```

来自 docker run 命令的输出将是“`secret password`”

```
secret password
```

然而，Docker 容器不应该能够暴露这些信息。

1.  要开始对容器进行一些简单的更改，以阻止再次发生这种访问，再次打开 Dockerfile 并添加突出显示的代码（*行 6*，*7*，*8*和*9*），保持先前的代码不变。这些代码将创建一个名为`10001`的组和一个名为`20002`的用户。然后将设置一个带有`home`目录的用户，然后您将进入该目录并开始使用*行 9*中的`USER`指令进行操作：

```
1 FROM alpine
2
3 RUN apk update
4 RUN apk add wget curl nmap libcap
5
6 RUN addgroup --gid 10001 20002 && adduser 20002 -h     /home/security_apps --disabled-password --uid 20002     --ingroup 20002
7 WORKDIR /home/security_apps
8
9 USER 20002
```

1.  对*行 15*进行更改，以确保脚本是从新的`security_app`目录运行的，然后保存 Dockerfile：

```
11 RUN echo "#!/sh\n" > test_memory.sh
12 RUN echo "cat /proc/meminfo; mpstat; pmap -x 1" >>     test_memory.sh
13 RUN chmod 755 test_memory.sh
14
15 CMD ["sh", "/home/security_apps/test_memory.sh"]
```

完整的 Dockerfile 应该如下所示：

```
FROM alpine
RUN apk update
RUN apk add wget curl nmap libcap
RUN addgroup --gid 10001 20002 && adduser 20002 -h   /home/security_apps --disabled-password --uid 20002     --ingroup 20002
WORKDIR /home/security_apps
USER 20002
RUN echo "#!/sh\n" > test_memory.sh
RUN echo "cat /proc/meminfo; mpstat; pmap -x 1" >>   test_memory.sh
RUN chmod 755 test_memory.sh
CMD ["sh", "/home/security_apps/test_memory.sh"]
```

1.  再次构建图像并使用`whoami`命令运行它：

```
docker build -t security-app . ; docker run --rm security-app whoami
```

您将看到一个新用户为`20002`而不是 root 用户：

```
20002
```

1.  以前，您可以从容器中运行`nmap`。验证新用户是否被阻止访问`nmap`命令以扫描网络漏洞：

```
docker run --rm -it security-app sh -c 'nmap -sS -p 443 localhost'
```

通过使用`nmap -sS`命令再次运行您的镜像，您现在应该无法运行该命令，因为容器正在以`20002`用户身份运行，没有足够的权限来运行该命令：

```
You requested a scan type which requires root privileges.
QUITTING!
```

1.  您现在已经大大限制了运行容器的功能，但是由主机 root 用户拥有的文件是否仍然可以被运行的`security-app`容器访问？再次挂载文件，看看是否可以输出文件的信息：

```
docker run -v /tmp/secret.txt:/tmp/secret.txt security-app sh -c 'cat /tmp/secret.txt'
```

您应该在结果中看到`Permission denied`，确保容器不再可以访问`secret.txt`文件：

```
cat: can't open '/tmp/secret.txt': Permission denied
```

正如我们在本练习中所演示的，删除正在运行的容器对 root 用户的访问权限是减少攻击者可以实现的目标的一个良好的第一步。下一节将快速查看运行容器的特权和能力以及如何使用`docker run`命令进行操作。

## 运行时特权和 Linux 能力

在运行容器时，Docker 提供了一个标志，可以覆盖所有安全和用户选项。这是通过使用`––privileged`选项来运行容器来实现的。尽管您已经看到了当容器以 root 用户身份运行时用户可以实现什么，但我们正在以非特权状态运行容器。尽管提供了`––privileged`选项，但应该谨慎使用，如果有人请求以此模式运行您的容器，我们应该谨慎对待。有一些特定情况，例如，如果您需要在树莓派上运行 Docker 并需要访问底层架构，那么您可能希望为用户添加功能。

如果您需要为容器提供额外的特权以运行特定命令和功能，Docker 提供了一种更简单的方法，即使用`––cap–add`和`––cap–drop`选项。这意味着，与使用`––privileged`选项提供完全控制不同，您可以使用`––cap–add`和`––cap–drop`来限制用户可以实现的内容。

在运行容器时，`––cap–add`和`––cap–drop`可以同时使用。例如，您可能希望包括`––cap–add=all`和`––cap–drop=chown`。

以下是一些可用于`––cap``–add`和`––cap–drop`的功能的简短列表：

+   `setcap`：修改正在运行系统的进程功能。

+   `mknod`：使用`mknod`命令在运行系统上创建特殊文件。

+   `chown`：对文件的 UID 和 GID 值执行文件所有权更改。

+   `kill`：绕过发送信号以停止进程的权限。

+   `setgid/setuid`：更改进程的 UID 和 GID 值。

+   `net_bind_service`：将套接字绑定到域端口。

+   `sys_chroot`：更改运行系统上的`root`目录。

+   `setfcap`：设置文件的功能。

+   `sys_module`：在运行系统上加载和卸载内核模块。

+   `sys_admin`：执行一系列管理操作。

+   `sys_time`：对系统时钟进行更改和设置时间。

+   `net_admin`：执行与网络相关的一系列管理操作。

+   `sys_boot`：重新启动系统并在系统上加载新内核以供以后执行。

要添加额外的功能，您只需包括该功能，如果您在执行`docker run`命令时添加或删除功能，您的命令将如下所示：

```
docker run –-cap-add|--cap-drop <capability_name> <image_name>
```

正如您所看到的，语法使用`––cap–add`来添加功能，`––cap–drop`来移除功能。

注意

如果您有兴趣查看在运行容器时可以添加和删除的全部功能列表，请访问[`man7.org/linux/man-pages/man7/capabilities.7.html`](http://man7.org/linux/man-pages/man7/capabilities.7.html)。

我们已经简要介绍了使用特权和功能。在本章的后面，我们将有机会在测试安全配置文件时使用这些功能。不过，现在我们将看看如何使用数字签名来验证我们的 Docker 镜像的真实性。

# 签署和验证 Docker 镜像

就像我们可以确保我们购买和安装在系统上的应用程序来自可信任的来源一样，我们也可以对我们使用的 Docker 镜像进行同样的操作。运行一个不受信任的 Docker 镜像可能会带来巨大的风险，并可能导致系统出现重大问题。这就是为什么我们应该寻求对我们使用的镜像进行特定的验证。不受信任的来源可能会向正在运行的镜像添加代码，这可能会将整个网络暴露给攻击者。

幸运的是，Docker 有一种方式可以对我们的镜像进行数字签名，以确保我们使用的是来自经过验证的供应商或提供者的镜像。这也将确保自签名之初镜像未被更改或损坏，从而确保其真实性。这不应该是我们信任镜像的唯一方式。正如您将在本章后面看到的那样，一旦我们有了镜像，我们可以扫描它以确保避免安装可能存在安全问题的镜像。

Docker 允许我们签署和验证镜像的方式是使用**Docker 内容信任**（**DCT**）。DCT 作为 Docker Hub 的一部分提供，并允许您对从您的注册表发送和接收的所有数据使用数字签名。DCT 与镜像标签相关联，因此并非所有镜像都需要标记，因此并非所有镜像都会有与之相关的 DCT。这意味着任何想要发布镜像的人都可以这样做，但可以确保在需要签署之前镜像是否正常工作。

DCT 并不仅限于 Docker Hub。如果用户在其环境中启用了 DCT，他们只能拉取、运行或构建受信任的镜像，因为 DCT 确保用户只能看到已签名的镜像。DCT 信任是通过使用签名密钥来管理的，这些密钥是在首次运行 DCT 时创建的。当密钥集创建时，它包括三种不同类型的密钥：

+   **离线密钥**：用于创建标记密钥。它们应该被小心存放，并由创建图像的用户拥有。如果这些密钥丢失或被 compromise，可能会给发布者带来很多问题。

+   **存储库或标记密钥**：这些与发布者相关，并与图像存储库相关联。当您签署准备推送到存储库的受信任图像时使用。

+   **服务器管理的密钥**：这些也与图像存储库相关联，并存储在服务器上。

注意

确保您保管好您的离线密钥，因为如果您丢失了离线密钥，它将会导致很多问题，因为 Docker 支持很可能需要介入来重置存储库状态。这还需要所有使用过存储库中签名图像的消费者进行手动干预。

就像我们在前面的章节中看到的那样，Docker 提供了易于使用的命令行选项来生成、加载和使用签名密钥。如果您启用了 DCT，Docker 将使用您的密钥直接对图像进行签名。如果您想进一步控制事情，您可以使用`docker trust key generate`命令来创建您的离线密钥，并为它们分配名称：

```
docker trust key generate <name>
```

您的密钥将存储在您的`home`目录的`.docker/trust`目录中。如果您有一组离线密钥，您可以使用`docker trust key load`命令和您创建它们的名称来使用这些密钥，如下所示：

```
docker trust key load <pem_key_file> –name <name>
```

一旦您拥有您的密钥，或者加载了您的原始密钥，您就可以开始对图像进行签名。您需要使用`docker trust sign`命令包括图像的完整注册表名称和标签：

```
docker trust sign <registry>/<repo>:<tag>
```

一旦您签署了您的图像，或者您有一个需要验证签名的图像，您可以使用`docker trust inspect`命令来显示签名密钥和签发者的详细信息：

```
docker trust inspect –pretty <registry>/<repo>:<tag>
```

在开发过程中使用 DCT 可以防止用户使用来自不受信任和未知来源的容器图像。我们将使用本章前几节中我们一直在开发的安全应用程序来创建和实施 DCT 签名密钥。

## 练习 11.02：签署 Docker 图像并在您的系统上利用 DCT

在接下来的练习中，您将学习如何在您的环境中使用 DCT 并实施使用签名图像的流程。您将首先导出`DOCKER_CONTENT_TRUST`环境变量以在您的系统上启用 DCT。接下来，您将学习如何对图像进行签名和验证签名的图像：

1.  将`DOCKER_CONTENT_TRUST`环境变量导出到您的系统，以在您的系统上启用 DCT。还要确保将变量设置为`1`：

```
export DOCKER_CONTENT_TRUST=1
```

1.  现在启用了 DCT，您将无法拉取或处理任何没有与其关联签名密钥的 Docker 图像。我们可以通过从 Docker Hub 存储库中拉取`security-app`图像来测试：

```
docker pull vincesestodocker/security-app
```

从错误消息中可以看出，我们无法拉取最新的图像，这是个好消息，因为我们最初没有使用签名密钥进行推送：

```
Using default tag: latest
Error: remote trust data does not exist for docker.io/vincesestodocker/security-app: notary.docker.io does 
not have trust data for docker.io/vincesestodocker/security-app
```

1.  将图像推送到您的图像存储库：

```
docker push vincesestodocker/security-app
```

您不应该能够这样做，因为本地图像也没有关联签名密钥：

```
The push refers to repository 
[docker.io/vincesestodocker/security-app]
No tag specified, skipping trust metadata push
```

1.  将新图像标记为`trust1`，准备推送到 Docker Hub：

```
docker tag security-app:latest vincesestodocker/security-app:trust1
```

1.  如前所述，当我们第一次将图像推送到存储库时，签名密钥将自动与图像关联。确保给你的图像打上标签，因为这将阻止 DCT 识别需要签名。再次将图像推送到存储库：

```
docker push vincesestodocker/security-app:trust1
```

在运行上述命令后，将打印以下行：

```
The push refers to repository 
[docker.io/vincesestodocker/security-app]
eff6491f0d45: Layer already exists 
307b7a157b2e: Layer already exists 
03901b4a2ea8: Layer already exists 
ver2: digest: sha256:7fab55c47c91d7e56f093314ff463b7f97968e
e0f80f5ee927430fc39f525f66 size: 949
Signing and pushing trust metadata
You are about to create a new root signing key passphrase. 
This passphrase will be used to protect the most sensitive key 
in your signing system. Please choose a long, complex passphrase 
and be careful to keep the password and the key file itself 
secure and backed up. It is highly recommended that you use a 
password manager to generate the passphrase and keep it safe. 
There will be no way to recover this key. You can find the key 
in your config directory.
Enter passphrase for new root key with ID 66347fd: 
Repeat passphrase for new root key with ID 66347fd: 
Enter passphrase for new repository key with ID cf2042d: 
Repeat passphrase for new repository key with ID cf2042d: 
Finished initializing "docker.io/vincesestodocker/security-app"
Successfully signed docker.io/vincesestodocker/security-app:
trust1
```

以下输出显示，当图像被推送到注册表时，作为该过程的一部分创建了一个新的签名密钥，要求用户在过程中创建新的根密钥和存储库密钥。

1.  现在更加安全了。不过，在您的系统上运行图像呢？现在我们的系统上启用了 DCT，运行容器图像会有任何问题吗？使用`docker run`命令在您的系统上运行`security-app`图像：

```
docker run -it vincesestodocker/security-app sh
```

该命令应返回以下输出：

```
docker: No valid trust data for latest.
See 'docker run --help'.
```

在上面的输出中，我们故意没有使用`trust1`标签。与前几章一样，Docker 将尝试使用`latest`标签运行图像。由于这也没有与之关联的签名密钥，因此无法运行它。

1.  您可以直接从工作系统对图像进行签名，并且可以使用之前创建的密钥对后续标记的图像进行签名。使用`trust2`标签对图像进行标记：

```
docker tag vincesestodocker/security-app:trust1 vincesestodocker/security-app:trust2
```

1.  使用在此练习中创建的签名密钥对新标记的图像进行签名。使用`docker trust sign`命令对图像和图像的层进行签名：

```
docker trust sign vincesestodocker/security-app:trust2
```

该命令将自动将已签名的图像推送到我们的 Docker Hub 存储库：

```
Signing and pushing trust data for local image 
vincesestodocker/security-app:trust2, may overwrite remote 
trust data
The push refers to repository 
[docker.io/vincesestodocker/security-app]
015825f3a965: Layer already exists 
2c32d3f8446b: Layer already exists 
1bbb374ec935: Layer already exists 
bcc0069f86e9: Layer already exists 
e239574b2855: Layer already exists 
f5e66f43d583: Layer already exists 
77cae8ab23bf: Layer already exists 
trust2: digest: sha256:a61f528324d8b63643f94465511132a38ff945083c
3a2302fa5a9774ea366c49 size: 1779
Signing and pushing trust metadataEnter passphrase for 
vincesestodocker key with ID f4b834e: 
Successfully signed docker.io/vincesestodocker/security-app:
trust2
```

1.  使用`docker trust`命令和`inspect`选项查看签名信息：

```
docker trust inspect --pretty vincesestodocker/security-app:trust2
```

输出将为您提供签名者的详细信息，已签名的标记图像以及有关图像的其他信息：

```
Signatures for vincesestodocker/security-app:trust2
SIGNED TAG      DIGEST                     SIGNERS
trust2          d848a63170f405ad3…         vincesestodocker
List of signers and their keys for vincesestodocker/security-app:
trust2
SIGNER              KEYS
vincesestodocker    f4b834e54c71
Administrative keys for vincesestodocker/security-app:trust2
  Repository Key:
    26866c7eba348164f7c9c4f4e53f04d7072fefa9b52d254c573e8b082
    f77c966
  Root Key:
    69bef52a24226ad6f5505fd3159f778d6761ac9ad37483f6bc88b1cb4
    7dda334
```

1.  使用`docker trust revoke`命令来移除相关密钥的签名：

```
docker trust revoke vincesestodocker/security-app:trust2
Enter passphrase for vincesestodocker key with ID f4b834e: 
Successfully deleted signature for vincesestodocker/security-app:
trust2
```

注意

如果您正在使用自己的 Docker 注册表，您可能需要设置一个公证服务器，以允许 DCT 与您的 Docker 注册表一起工作。亚马逊的弹性容器注册表和 Docker 可信注册表等产品已经内置了公证功能。

正如您所看到的，使用 DCT 对 Docker 映像进行签名和验证可以轻松地控制您作为应用程序一部分使用的映像。从可信源使用已签名的映像只是方程式的一部分。在下一节中，我们将使用 Anchore 和 Snyk 来开始扫描我们的映像以查找漏洞。

# Docker 映像安全扫描

安全扫描在不仅确保应用程序的正常运行时间方面发挥着重要作用，而且还确保您不会运行过时、未打补丁或容器映像存在漏洞。应该对团队使用的所有映像以及您的环境中使用的所有映像进行安全扫描。无论您是从头开始创建它们并且信任它们与否，这都是减少环境中潜在风险的重要步骤。本章的这一部分将介绍两种扫描映像的选项，这些选项可以轻松地被您的开发团队采用。

通过对我们的 Docker 映像实施安全扫描，我们希望实现以下目标：

+   我们需要保持一个已知且最新的漏洞数据库，或者使用一个将代表我们保持这个数据库的应用程序。

+   我们将我们的 Docker 映像与漏洞数据库进行扫描，不仅验证底层操作系统是否安全和打了补丁，还验证容器使用的开源应用程序和我们软件实现所使用的语言是否安全。

+   安全扫描完成后，我们需要得到一个完整的报告，报告和警报任何在扫描过程中可能被突出显示的问题。

+   最后，安全扫描可以提供任何发现的问题的修复，并通过更新 Dockerfile 中使用的基础镜像或支持的应用程序来发出警报。

市场上有很多可以为您执行安全扫描的产品，包括付费和开源产品。在本章中，由于篇幅有限，我们选择了两项我们发现易于使用并提供良好功能的服务。首先是 Anchore，这是一个开源的容器分析工具，我们将安装到我们的系统上，并作为本地工具来测试我们的图像。然后我们将看看 Snyk，这是一个在线 SaaS 产品。Snyk 有免费版本可用，这也是我们在本章中将使用的版本，以演示其工作原理。它提供了不错的功能，而无需支付月费。

# 使用 Anchore 安全扫描本地扫描图像

Anchore 容器分析是一个开源的静态分析工具，允许您扫描您的 Docker 图像，并根据用户定义的策略提供通过或失败的结果。Anchore Engine 允许用户拉取图像，并在不运行图像的情况下分析图像的内容，并评估图像是否适合使用。Anchore 使用 PostgreSQL 数据库存储已知漏洞的详细信息。然后，您可以使用命令行界面针对数据库扫描图像。Anchore 还非常容易上手，正如我们将在接下来的练习中看到的那样，它提供了一个易于使用的`docker-compose`文件，以自动安装并尽快让您开始使用。

注意

如果您对 Anchore 想了解更多信息，可以在[`docs.anchore.com/current/`](https://docs.anchore.com/current/)找到大量的文档和信息。

在即将进行的练习中，一旦我们的环境正常运行，您将使用 Anchore 的 API 进行交互。`anchore-cli`命令带有许多易于使用的命令，用于检查系统状态并开始评估我们图像的漏洞。

一旦我们的系统正常运行，我们可以使用`system status`命令来提供所有服务的列表，并确保它们正常运行：

```
anchore-cli system status
```

一旦系统正常运行，您需要做的第一件事情之一就是验证 feeds 列表是否是最新的。这将确保您的数据库已经填充了漏洞 feeds。这可以通过以下`system feeds list`命令来实现：

```
anchore-cli system feeds list
```

默认情况下，`anchore-cli`将使用 Docker Hub 作为您的图像注册表。如果您的图像存储在不同的注册表上，您将需要使用`anchore-cli registry add`命令添加注册表，并指定注册表名称，以及包括 Anchore 可以使用的用户名和密码：

```
anchore-cli registry add <registry> <user> <password>
```

要将图像添加到 Anchore，您可以使用`image add`命令行选项，包括 Docker Hub 位置和图像名称：

```
anchore-cli image add <repository_name>/<image_name>
```

如果您希望扫描图像以查找漏洞，可以使用`image vuln`选项，包括您最初扫描的图像名称。我们还可以使用`os`选项来查找特定于操作系统的漏洞，以及`non-os`来查找与语言相关的漏洞。在以下示例中，我们使用了`all`来包括`os`和`non-os`选项：

```
anchore-cli image vuln <repository_name>/<image_name> all
```

然后，要查看图像的完成评估，并根据图像是否安全可用提供通过或失败，您可以使用`anchore-cli`命令的`evaluate check`选项：

```
anchore-cli evaluate check <repository_name>/<image_name>
```

考虑到所有这些，Anchore 确实提供了一个支持和付费版本，带有易于使用的 Web 界面，但正如您将在以下练习中看到的，需要很少的工作即可让 Anchore 应用程序在您的系统上运行和扫描。

注意

上一个练习在创建和签署容器时使用了 DCT。在以下练习中，用于练习的 Anchore 图像使用了`latest`标签，因此如果您仍在运行 DCT，则需要在进行下一个练习之前停止它：

`export DOCKER_CONTENT_TRUST=0`

## 练习 11.03：开始使用 Anchore 图像扫描

在以下练习中，您将使用`docker-compose`在本地系统上安装 Anchore，并开始分析您在本章中使用的图像：

1.  创建并标记您一直在使用的`security-app`图像的新版本。使用`scan1`标记图像：

```
docker tag security-app:latest vincesestodocker/security-app:scan1 ;
```

将其推送到 Docker Hub 存储库：

```
docker push vincesestodocker/security-app:scan1
```

1.  创建一个名为`aevolume`的新目录，并使用以下命令进入该目录。这是我们将执行工作的地方：

```
mkdir aevolume; cd aevolume
```

1.  Anchore 为您提供了一切您需要开始使用的东西，一个易于使用的`docker-compose.yaml`文件来设置和运行 Anchore API。使用以下命令拉取最新的`anchore-engine` Docker Compose 文件：

```
curl -O https://docs.anchore.com/current/docs/engine/quickstart/docker-compose.yaml
```

1.  查看`docker-compose.yml`文件。虽然文件包含超过 130 行，但文件中没有太复杂的内容。`Compose`文件正在设置 Anchore 的功能，包括 PostgreSQL 数据库、目录和分析器进行查询；一个简单的队列和策略引擎；以及一个 API 来运行命令和查询。

1.  使用`docker-compose pull`命令拉取`docker-compose.yml`文件所需的镜像，确保您在与`Compose`文件相同的目录中：

```
docker-compose pull
```

该命令将开始拉取数据库、目录、分析器、简单队列、策略引擎和 API：

```
Pulling anchore-db           ... done
Pulling engine-catalog       ... done
Pulling engine-analyzer      ... done
Pulling engine-policy-engine ... done
Pulling engine-simpleq       ... done
Pulling engine-api           ... done
```

1.  如果我们的所有镜像现在都可用，如前面的输出所示，除了使用`docker-compose up`命令运行`Compose`文件之外，没有其他事情要做。使用`-d`选项使所有容器作为守护进程在后台运行：

```
docker-compose up -d
```

该命令应该输出以下内容：

```
Creating network "aevolume_default" with the default driver
Creating volume "aevolume_anchore-db-volume" with default driver
Creating volume "aevolume_anchore-scratch" with default driver
Creating aevolume_anchore-db_1 ... done
Creating aevolume_engine-catalog_1 ... done
Creating aevolume_engine-analyzer_1      ... done
Creating aevolume_engine-simpleq_1       ... done
Creating aevolume_engine-api_1           ... done
Creating aevolume_engine-policy-engine_1 ... done
```

1.  运行`docker ps`命令，以查看系统上正在运行的包含 Anchore 的容器，准备开始扫描我们的镜像。表格中的`IMAGE`、`COMMAND`和`CREATED`列已被删除以方便查看：

```
docker-compose ps
```

输出中的所有值应该显示每个 Anchore Engine 容器的`healthy`状态：

```
CONTAINER ID       STATUS         PORTS
    NAMES
d48658f6aa77       (healthy)      8228/tcp
    aevolume_engine-analyzer_1
e4aec4e0b463   (healthy)          8228/tcp
    aevolume_engine-policy-engine_1
afb59721d890   (healthy)          8228->8228/tcp
    aevolume_engine-api_1
d61ff12e2376   (healthy)          8228/tcp
    aevolume_engine-simpleq_1
f5c29716aa40   (healthy)          8228/tcp
    aevolume_engine-catalog_1
398fef820252   (healthy)          5432/tcp
    aevolume_anchore-db_1
```

1.  现在环境已部署到您的系统上，使用`docker-compose exec`命令来运行前面提到的`anchor-cli`命令。使用`pip3`命令将`anchorecli`包安装到您的运行系统上。使用`--version`命令来验证`anchore-cli`是否已成功安装：

```
pip3 install anchorecli; anchore-cli --version
```

该命令返回`anchor-cli`的版本：

```
anchore-cli, version 0.5.0
```

注意

版本可能会因系统而异。

1.  现在您可以运行您的`anchore-cli`命令，但您需要指定 API 的 URL（使用`--url`）以及用户名和密码（使用`--u`和`--p`）。相反，使用以下命令将值导出到您的环境中，这样您就不需要使用额外的命令行选项：

```
export ANCHORE_CLI_URL=http://localhost:8228/v1
export ANCHORE_CLI_USER=admin
export ANCHORE_CLI_PASS=foobar
```

注意

上述变量是 Anchore 提供的`Compose`文件的默认值。如果您决定在部署环境中设置运行环境，您很可能会更改这些值以提高安全性。

1.  现在`anchore-cli`已安装和配置好，使用`anchore-cli system status`命令来验证分析器、队列、策略引擎、目录和 API 是否都正常运行：

```
anchore-cli system status
```

可能会出现一两个服务宕机的情况，这意味着您很可能需要重新启动容器：

```
Service analyzer (anchore-quickstart, http://engine-analyzer:
8228): up
Service simplequeue (anchore-quickstart, http://engine-simpleq:
8228): up
Service policy_engine (anchore-quickstart, http://engine-policy-engine:8228): up
Service catalog (anchore-quickstart, http://engine-catalog:
8228): up
Service apiext (anchore-quickstart, http://engine-api:8228): 
up
Engine DB Version: 0.0.11
Engine Code Version: 0.5.1
```

注意

`Engine DB Version`和`Engine Code Version`可能会因系统而异。

1.  使用`anchore-cli system feeds list`命令查看数据库中的所有漏洞：

```
anchore-cli system feeds list
```

由于提供给数据库的漏洞数量很大，以下输出已经被缩减：

```
Feed                Group          LastSync
    RecordCount
nvdv2               nvdv2:cves     None
    0
vulnerabilities     alpine:3\.      2019-10-24T03:47:28.504381
    1485
vulnerabilities     alpine:3.3     2019-10-24T03:47:36.658242
    457
vulnerabilities     alpine:3.4     2019-10-24T03:47:51.594635
    681
vulnerabilities     alpine:3.5     2019-10-24T03:48:03.442695
    875
vulnerabilities     alpine:3.6     2019-10-24T03:48:19.384824
    1051
vulnerabilities     alpine:3.7     2019-10-24T03:48:36.626534
    1253
vulnerabilities     alpine:3.8     None
    0
vulnerabilities     alpine:3.9     None
    0
vulnerabilities     amzn:2         None
    0
```

在前面的输出中，您会注意到一些漏洞 feed 显示为`None`。这是因为数据库是最近设置的，并且尚未更新所有漏洞。继续显示 feed 列表，就像在上一步中所做的那样，一旦所有条目在`LastSync`列中显示日期，您就可以开始扫描镜像了。

1.  一旦 feed 完全更新，使用`anchore-cli image add`命令添加镜像。记得使用完整路径，包括镜像仓库标签，因为 Anchore 将使用位于 Docker Hub 上的镜像：

```
anchore-cli image add vincesestodocker/security-app:scan1
```

该命令将镜像添加到 Anchore 数据库，准备进行扫描：

```
Image Digest: sha256:7fab55c47c91d7e56f093314ff463b7f97968ee0
f80f5ee927430
fc39f525f66
Parent Digest: sha256:7fab55c47c91d7e56f093314ff463b7f97968ee
0f80f5ee927430fc39f525f66
Analysis Status: not_analyzed
Image Type: docker
Analyzed At: None
Image ID: 8718859775e5d5057dd7a15d8236a1e983a9748b16443c99f8a
40a39a1e7e7e5
Dockerfile Mode: None
Distro: None
Distro Version: None
Size: None
Architecture: None
Layer Count: None
Full Tag: docker.io/vincesestodocker/security-app:scan1
Tag Detected At: 2019-10-24T03:51:18Z 
```

当您添加镜像时，您会注意到我们已经强调输出显示为`not_analyzed`。这将被排队等待分析，对于较小的镜像，这将是一个快速的过程。

1.  监控您的镜像，查看是否已使用`anchore-cli image list`命令进行分析：

```
anchore-cli image list
```

这将提供我们当前添加的所有镜像列表，并显示它们是否已经被分析的状态：

```
Full Tag               Image Digest            Analysis Status
security-app:scan1     sha256:a1bd1f6fec31…    analyzed
```

1.  现在镜像已经添加并分析完成，您可以开始查看镜像，并查看基础镜像和安装的应用程序，包括版本和许可证号。使用`anchore-cli`的`image content os`命令。您还可以使用其他内容类型，包括`file`用于镜像上的所有文件，`npm`用于所有 Node.js 模块，`gem`用于 Ruby gems，`java`用于 Java 存档，以及`python`用于 Python 工件。

```
anchore-cli image content vincesestodocker/security-app:scan1 os
```

该命令将返回以下输出：

```
Package                   Version        License
alpine-baselayout         3.1.2          GPL-2.0-only
alpine-keys               2.1            MIT
apk-tools                 2.10.4         GPL2 
busybox                   1.30.1         GPL-2.0
ca-certificates           20190108       MPL-2.0 GPL-2.0-or-later
ca-certificates-cacert    20190108       MPL-2.0 GPL-2.0-or-later
curl                      7.66.0         MIT
libc-utils                0.7.1          BSD
libcrypto1.1              1.1.1c         OpenSSL
libcurl                   7.66.0         MIT
libssl1.1                 1.1.1c         OpenSSL
libtls-standalone         2.9.1          ISC
musl                      1.1.22         MIT
musl-utils                1.1.22         MIT BSD GPL2+
nghttp2-libs              1.39.2         MIT
scanelf                   1.2.3          GPL-2.0
ssl_client                1.30.1         GPL-2.0
wget                      1.20.3         GPL-3.0-or-later
zlib                      1.2.11         zlib
```

1.  使用`anchore-cli image vuln`命令，并包括您要扫描的图像以检查漏洞。如果没有漏洞存在，您将不会看到任何输出。我们在下面的命令行中使用了`all`来提供关于操作系统和非操作系统漏洞的报告。我们也可以使用`os`来获取特定于操作系统的漏洞，使用`non-os`来获取与语言相关的漏洞：

```
anchore-cli image vuln vincesestodocker/security-app:scan1 all
```

1.  对图像进行评估检查，为我们提供图像扫描的“通过”或“失败”结果。使用`anchore-cli evaluate check`命令来查看图像是否安全可用：

```
anchore-cli evaluate check vincesestodocker/security-app:scan1
From the output of the above command, it looks like our image 
is safe with a pass result.Image Digest: sha256:7fab55c47c91d7e56f093314ff463b7f97968ee0f80f5ee927430fc
39f525f66
Full Tag: docker.io/vincesestodocker/security-app:scan1
Status: pass
Last Eval: 2019-10-24T03:54:40Z
Policy ID: 2c53a13c-1765-11e8-82ef-23527761d060
```

所有前面的练习都已经很好地确定了我们的图像是否存在漏洞并且是否安全可用。接下来的部分将向您展示 Anchore 的替代方案，尽管它有付费组件，但仍然通过访问免费版本提供了大量的功能。

# 使用 Snyk 进行 SaaS 安全扫描

Snyk 是一个在线 SaaS 应用程序，提供易于使用的界面，允许您扫描 Docker 图像以查找漏洞。虽然 Snyk 是一个付费应用程序，但它提供了一个免费的功能大量的免费版本。它为开源项目提供无限的测试，并允许 GitHub 和 GitLab 集成，提供对开源项目的修复和持续监控。您所能进行的容器漏洞测试受到限制。

下面的练习将通过使用 Web 界面来指导您如何注册帐户，然后添加要扫描安全漏洞的容器。

## 练习 11.04：设置 Snyk 安全扫描

在这个练习中，您将使用您的网络浏览器与 Snyk 合作，开始对我们的`security-app`图像实施安全扫描。

1.  如果您以前没有使用过 Snyk 或没有帐户，请在 Snyk 上创建一个帐户。除非您想将帐户升级到付费版本，否则您不需要提供任何信用卡详细信息，但在这个练习中，您只需要免费选项。因此，请登录 Snyk 或在[`app.snyk.io/signup`](https://app.snyk.io/signup)上创建一个帐户。

1.  您将看到一个网页，如下面的屏幕截图所示。选择您希望创建帐户的方法，并按照提示继续：![图 11.1：使用 Snyk 创建帐户](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-ws/img/B15021_11_01.jpg)

图 11.1：使用 Snyk 创建帐户

1.  登录后，您将看到一个类似于*图 11.2*的页面，询问`您想要测试的代码在哪里？`。Snyk 不仅扫描 Docker 图像，还扫描您的代码以查找漏洞。您已经在 Docker Hub 中有了您的`security-app`图像，所以点击`Docker Hub`按钮开始这个过程：![图 11.2：使用 Snyk 开始安全扫描](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-ws/img/B15021_11_02.jpg)

图 11.2：使用 Snyk 开始安全扫描

注意

如果您没有看到上述的网页，您可以转到以下网址添加一个新的存储库。请记住，将以下网址中的`<your_account_name>`更改为您创建 Snyk 帐户时分配给您的帐户名称：

`https://app.snyk.io/org/<your_account_name>/add`。

1.  通过 Docker Hub 进行身份验证，以允许其查看您可用的存储库。当出现以下页面时，输入您的 Docker Hub 详细信息，然后点击`Continue`：![图 11.3：在 Snyk 中与 Docker Hub 进行身份验证](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-ws/img/B15021_11_03.jpg)

图 11.3：在 Snyk 中与 Docker Hub 进行身份验证

1.  验证后，您将看到 Docker Hub 上所有存储库的列表，包括每个存储库存储的标签。在本练习中，您只需要选择一个图像，并使用本节中创建的`scan1`标签。选择带有`scan1`标签的`security-app`图像。一旦您对选择满意，点击屏幕右上角的`Add selected repositories`按钮：![图 11.4：选择要由 Snyk 扫描的 Docker Hub 存储库](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-ws/img/B15021_11_04.jpg)

图 11.4：选择要由 Snyk 扫描的 Docker Hub 存储库

1.  一旦您添加了图像，Snyk 将立即对其进行扫描，根据图像的大小，这应该在几秒钟内完成。点击屏幕顶部的`Projects`选项卡，查看扫描结果，并点击选择您想要查看的存储库和标签：![图 11.5：在 Snyk 中查看您的项目报告](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-ws/img/B15021_11_05.jpg)

图 11.5：在 Snyk 中查看您的项目报告

单击存储库名称后，您将看到图像扫描报告，概述图像的详细信息，使用了哪些基本图像，以及在扫描过程中是否发现了任何高、中或低级问题：

![图 11.6：Snyk 中的图像扫描报告页面](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-ws/img/B15021_11_06.jpg)

图 11.6：Snyk 中的图像扫描报告页面

Snyk 将每天扫描您的镜像，如果发现任何问题，将会通知您。除非发现任何漏洞，否则每周都会给您发送一份报告。如果有漏洞被发现，您将尽快收到通知。

使用 Snyk，您可以使用易于遵循的界面扫描您的镜像中的漏洞。作为一种 SaaS 基于 Web 的应用程序，这也意味着无需管理应用程序和服务器进行安全扫描。这是关于安全扫描我们的镜像的部分的结束，我们现在将转向使用安全配置文件来帮助阻止攻击者利用他们可能能够访问的任何镜像。

# 使用容器安全配置文件

安全配置文件允许您利用 Linux 中现有的安全工具，并在您的 Docker 镜像上实施它们。在接下来的部分中，我们将涵盖 AppArmor 和`seccomp`。这些都是您可以在 Docker 环境中运行时减少进程获取访问权限的方式。它们都很容易使用，您很可能已经在您的镜像中使用它们。我们将分别查看它们，但请注意，AppArmor 和 Linux 的安全计算在功能上有重叠。目前，您需要记住的是，AppArmor 可以阻止应用程序访问它们不应该访问的文件，而 Linux 的安全计算将帮助阻止利用任何 Linux 内核漏洞。

默认情况下，特别是如果您正在运行最新版本的 Docker，您可能已经同时运行了两者。您可以通过运行`docker info`命令并查找`Security Options`来验证这一点。以下是一个显示两个功能都可用的系统的输出：

```
docker info
Security Options:
  apparmor
  seccomp
   Profile: default
```

以下部分将涵盖 Linux 的 AppArmor 和安全计算，并清楚地介绍如何在系统上实施和使用两者。

## 在您的镜像上实施 AppArmor 安全配置文件

AppArmor 代表应用程序装甲，是一个 Linux 安全模块。AppArmor 的目标是保护操作系统免受安全威胁，并作为 Docker 版本 1.13.0 的一部分实施。它允许用户向其运行的容器加载安全配置文件，并可以创建以锁定容器上服务可用的进程。Docker 默认包含的提供了中等保护，同时仍允许访问大量应用程序。

为了帮助用户编写安全配置文件，AppArmor 提供了**complain 模式**，允许几乎任何任务在没有受限制的情况下运行，但任何违规行为都将被记录到审计日志中。它还有一个**unconfined 模式**，与 complain 模式相同，但不会记录任何事件。

注意

有关 AppArmor 的更多详细信息，包括文档，请使用以下链接，它将带您到 GitLab 上 AppArmor 主页：

[`gitlab.com/apparmor/apparmor/wikis/home`](https://gitlab.com/apparmor/apparmor/wikis/home)。

AppArmor 还配备了一套命令，帮助用户管理应用程序，包括将策略编译和加载到内核中。默认配置文件对新用户来说可能有点令人困惑。您需要记住的主要规则是，拒绝规则优先于允许和所有者规则，这意味着如果它们都在同一个应用程序上，则允许规则将被随后的拒绝规则覆盖。文件操作使用`'r'`表示读取，`'w'`表示写入，`'k'`表示锁定，`'l'`表示链接，`'x'`表示执行。

我们可以开始使用 AppArmor，因为它提供了一些易于使用的命令行工具。您将使用的第一个是`aa-status`命令，它提供了系统上所有正在运行的配置文件的状态。这些配置文件位于系统的`/etc/apparmor.d`目录中：

```
aa-status
```

如果我们的系统上安装了配置文件，我们至少应该有`docker-default`配置文件；它可以通过`docker run`命令的`--security-opt`选项应用于我们的 Docker 容器。在下面的示例中，您可以看到我们将`--security-opt`值设置为`apparmor`配置文件，或者您可以使用`unconfined`配置文件，这意味着没有配置文件与该镜像一起运行：

```
docker run --security-opt apparmor=<profile> <image_name>
```

要生成我们的配置文件，我们可以使用`aa-genprof`命令来进一步了解需要设置为配置文件的内容。AppArmor 将在您执行一些示例命令时扫描日志，然后为您在系统上创建一个配置文件，并将其放在默认配置文件目录中：

```
aa-genprof <application>
```

一旦您满意您的配置文件，它们需要加载到您的系统中，然后您才能开始使用它们与您的镜像。您可以使用`apparmor_parser`命令，带有`-r`（如果已经设置，则替换）和`-W`（写入缓存）选项。然后可以将配置文件与正在运行的容器一起使用：

```
apparmor_parser -r -W <path_to_profile>
```

最后，如果您希望从 AppArmor 中删除配置文件，可以使用`apparmor_parser`命令和`-R`选项来执行此操作：

```
apparmor_parser -R <path_to_profile>
```

AppArmor 看起来很复杂，但希望通过以下练习，您应该能够熟悉该应用程序，并对生成自定义配置文件增加额外的信心。

## 练习 11.05：开始使用 AppArmor 安全配置文件

以下练习将向您介绍 AppArmor 安全配置文件，并帮助您在运行的 Docker 容器中实施新规则：

1.  如果您正在运行 Docker Engine 版本 19 或更高版本，则 AppArmor 应已作为应用程序的一部分设置好。运行`docker info`命令来验证它是否正在运行：

```
docker info
…
Security Options:
  apparmor
…
```

1.  在本章中，我们通过创建用户`20002`更改了容器的运行用户。我们将暂停此操作，以演示 AppArmor 在此情况下的工作原理。使用文本编辑器打开`Dockerfile`，这次将*第 9 行*注释掉，就像我们在下面的代码中所做的那样：

```
  8 
  9 #USER 20002
```

1.  再次构建`Dockerfile`并验证镜像一旦再次作为 root 用户运行：

```
docker build -t security-app . ; docker run --rm security-app whoami
```

上述命令将构建`Dockerfile`，然后返回以下输出：

```
root
```

1.  通过在命令行中运行`aa-status`使用 AppArmor`status`命令：

```
aa-status
```

注意

如果您被拒绝运行`aa-status`命令，请使用`sudo`。

这将显示类似于以下内容的输出，并提供加载的配置文件和加载的配置文件类型。您会注意到输出包括在 Linux 系统上运行的所有 AppArmor 配置文件：

```
apparmor module is loaded.
15 profiles are loaded.
15 profiles are in enforce mode.
    /home/vinces/DockerWork/example.sh
    /sbin/dhclient
    /usr/bin/lxc-start
    /usr/lib/NetworkManager/nm-dhcp-client.action
    /usr/lib/NetworkManager/nm-dhcp-helper
    /usr/lib/connman/scripts/dhclient-script
    /usr/lib/lxd/lxd-bridge-proxy
    /usr/lib/snapd/snap-confine
    /usr/lib/snapd/snap-confine//mount-namespace-capture-helper
    /usr/sbin/tcpdump
    docker-default
    lxc-container-default
    lxc-container-default-cgns
    lxc-container-default-with-mounting
    lxc-container-default-with-nesting
0 profiles are in complain mode.
1 processes have profiles defined.
1 processes are in enforce mode.
    /sbin/dhclient (920) 
0 processes are in complain mode.
0 processes are unconfined but have a profile defined.
```

1.  在后台运行`security-app`容器，以帮助我们测试 AppArmor：

```
docker run -dit security-app sh
```

1.  由于我们没有指定要使用的配置文件，AppArmor 使用`docker-default`配置文件。通过再次运行`aa-status`来验证这一点：

```
aa-status
```

您将看到，在输出的底部，现在显示有两个进程处于`强制模式`，一个显示为`docker-default`：

```
apparmor module is loaded.
…
2 processes are in enforce mode.
    /sbin/dhclient (920) 
    docker-default (9768)
0 processes are in complain mode.
0 processes are unconfined but have a profile defined.
```

1.  删除我们当前正在运行的容器，以便在本练习中稍后不会混淆：

```
docker kill $(docker ps -a -q)
```

1.  在不使用 AppArmor 配置文件的情况下启动容器，使用`-–security-opt` Docker 选项指定`apparmor=unconfined`。还使用`–-cap-add SYS_ADMIN`功能，以确保您对运行的容器具有完全访问权限：

```
docker run -dit --security-opt apparmor=unconfined --cap-add SYS_ADMIN security-app sh
```

1.  访问容器并查看您可以运行哪些类型的命令。使用`docker exec`命令和`CONTAINER ID`访问容器，但请注意，您的`CONTAINER ID`值将与以下不同：

```
docker exec -it db04693ddf1f sh
```

1.  通过创建两个目录并使用以下命令将它们挂载为绑定挂载来测试你所拥有的权限：

```
mkdir 1; mkdir 2; mount --bind 1 2
ls -l
```

能够在容器上挂载目录是一种提升的权限，所以如果你能够做到这一点，那么很明显没有配置文件在阻止我们，并且我们可以像这样访问挂载文件系统：

```
total 8
drwxr-xr-x    2 root     root          4096 Nov  4 04:08 1
drwxr-xr-x    2 root     root          4096 Nov  4 04:08 2
```

1.  使用`docker kill`命令退出容器。你应该看到默认的 AppArmor 配置文件是否会限制对这些命令的访问：

```
docker kill $(docker ps -a -q)
```

1.  创建`security-app`镜像的一个新实例。在这个实例中，也使用`--cap-add SYS_ADMIN`能力，以允许加载默认的 AppArmor 配置文件：

```
docker run -dit --cap-add SYS_ADMIN security-app sh
```

当创建一个新的容器时，该命令将返回提供给用户的随机哈希。

1.  通过使用`exec`命令访问新的运行容器来测试更改，并查看是否可以执行绑定挂载，就像之前的步骤一样：

```
docker exec -it <new_container_ID> sh 
mkdir 1; mkdir 2; mount --bind 1 2
```

你应该会看到`Permission denied`：

```
mount: mounting 1 on 2 failed: Permission denied
```

1.  再次退出容器。使用`docker kill`命令删除原始容器：

```
docker kill $(docker ps -a -q)
```

在这个练习的下一部分，你将看到是否可以为我们的 Docker 容器实现自定义配置文件。

1.  使用 AppArmor 工具收集需要跟踪的资源信息。使用`aa-genprof`命令跟踪`nmap`命令的详细信息：

```
aa-genprof nmap
```

注意

如果你没有安装`aa-genprof`命令，使用以下命令安装它，然后再次运行`aa-genprof nmap`命令：

`sudo apt install apparmor-utils`

我们已经减少了命令的输出，但如果成功的话，你应该会看到一个输出，显示正在对`/usr/bin/nmap`命令进行分析：

```
…
Profiling: /usr/bin/nmap
[(S)can system log for AppArmor events] / (F)inish
```

注意

如果你的系统中没有安装`nmap`，运行以下命令：

`sudo apt-get update`

`sudo apt-get install nmap`

1.  在一个单独的终端窗口中运行`nmap`命令，以向`aa-genprof`提供应用程序的详细信息。在`docker run`命令中使用`-u root`选项，以 root 用户身份运行`security-app`容器，这样它就能够运行`nmap`命令：

```
docker run -it -u root security-app sh -c 'nmap -sS -p 443 localhost'
```

1.  返回到你一直在运行`aa-genprof`命令的终端。按下*S*来扫描系统日志以查找事件。扫描完成后，按下*F*来完成生成：

```
Reading log entries from /var/log/syslog.
Updating AppArmor profiles in /etc/apparmor.d.
```

所有配置文件都放在`/etc/apparmor.d/`目录中。如果一切正常，你现在应该在`/etc/apparmor.d/usr.bin.nmap`文件中看到类似以下输出的文件：

```
1 # Last Modified: Mon Nov 18 01:03:31 2019
2 #include <tunables/global>
3 
4 /usr/bin/nmap {
5   #include <abstractions/base>
6 
7   /usr/bin/nmap mr,
8 
9 }
```

1.  使用`apparmor_parser`命令将新文件加载到系统上。使用`-r`选项来替换已存在的配置文件，使用`-W`选项将其写入缓存：

```
apparmor_parser -r -W /etc/apparmor.d/usr.bin.nmap
```

1.  运行`aa-status`命令来验证配置文件现在是否可用，并查看是否有一个新的配置文件指定了`nmap`：

```
aa-status | grep nmap
```

请注意，配置文件的名称与应用程序的名称相同，即`/usr/bin/nmap`，这是在运行容器时需要使用的名称：

```
/usr/bin/nmap
```

1.  现在，测试您的更改。以`-u root`用户运行容器。还使用`--security-opt apparmor=/usr/bin/nmap`选项以使用新创建的配置文件运行容器：

```
docker run -it -u root --security-opt apparmor=/usr/bin/nmap security-app sh -c 'nmap -sS -p 443 localhost'
```

您还应该看到`Permission denied`的结果，以显示我们创建的 AppArmor 配置文件正在限制使用，这正是我们希望看到的：

```
sh: nmap: Permission denied
```

在这个练习中，我们演示了如何在您的系统上开始使用 AppArmor，并向您展示了如何创建您自己的配置文件。在下一节中，我们将继续介绍类似的应用程序，即 Linux 的*seccomp*。

## Linux 容器的 seccomp

Linux 的`seccomp`是从 3.17 版本开始添加到 Linux 内核中的，它提供了一种限制 Linux 进程可以发出的系统调用的方法。这个功能也可以在我们运行的 Docker 镜像中使用，以帮助减少运行容器的进程，确保如果容器被攻击者访问或感染了恶意代码，攻击者可用的命令和进程将受到限制。

`seccomp`使用配置文件来建立可以执行的系统调用的白名单，默认配置文件提供了一个可以执行的系统调用的长列表，并且还禁用了大约 44 个系统调用在您的 Docker 容器上运行。在阅读本书的章节时，您很可能一直在使用默认的`seccomp`配置文件。

Docker 将使用主机系统的`seccomp`配置，可以通过搜索`/boot/config`文件并检查`CONFIG_SECCOMP`选项是否设置为`y`来找到它：

```
cat /boot/config-'uname -r' | grep CONFIG_SECCOMP=
```

在运行我们的容器时，如果我们需要以无`seccomp`配置文件的方式运行容器，我们可以使用`--security-opt`选项，然后指定`seccomp`配置文件未确认。以下示例提供了此语法的示例：

```
docker run --security-opt seccomp=unconfined <image_name>
```

我们也可以创建我们自定义的配置文件。在这些情况下，我们将自定义配置文件的位置指定为`seccomp`的值，如下所示：

```
docker run --security-opt seccomp=new_default.json <image_name>
```

## 练习 11.06：开始使用 seccomp

在这个练习中，您将在当前环境中使用`seccomp`配置文件。您还将创建一个自定义配置文件，以阻止您的 Docker 镜像对文件执行更改所有权命令：

1.  检查您运行的 Linux 系统是否已启用`seccomp`。然后可以确保它也在 Docker 上运行：

```
cat /boot/config-'uname -r' | grep CONFIG_SECCOMP=
```

在引导配置目录中搜索`CONFIG_SECCOMP`，它的值应为`y`：

```
CONFIG_SECCOMP=y
```

1.  使用`docker info`命令确保 Docker 正在使用配置文件：

```
docker info
```

在大多数情况下，您会注意到它正在运行默认配置文件：

```
…
Security Options:
  seccomp
   Profile: default
…
```

我们已经减少了`docker info`命令的输出，但是如果您查找`Security Options`标题，您应该会在系统上看到`seccomp`。如果您希望关闭此功能，您需要将`CONFIG_SECCOMP`的值更改为`n`。

1.  运行`security-app`，看看它是否也在运行时使用了`seccomp`配置文件。还要在`/proc/1/status`文件中搜索单词`Seccomp`：

```
docker run -it security-app grep Seccomp /proc/1/status
```

值为`2`将显示容器一直在使用`Seccomp`配置文件运行：

```
Seccomp:    2
```

1.  可能会有一些情况，您希望在不使用`seccomp`配置文件的情况下运行容器。您可能需要调试容器或运行在其上的应用程序。要在不使用任何`seccomp`配置文件的情况下运行容器，请使用`docker run`命令的`--security-opt`选项，并指定`seccomp`将不受限制。现在对您的`security-app`容器执行此操作，以查看结果：

```
docker run -it --security-opt seccomp=unconfined security-app grep Seccomp /proc/1/status
```

值为`0`将显示我们已成功关闭`Seccomp`：

```
Seccomp:    0
```

1.  创建自定义配置文件也并不是很困难，但可能需要一些额外的故障排除来完全理解语法。首先，测试`security-app`容器，看看我们是否可以在命令行中使用`chown`命令。然后，您的自定义配置文件将尝试阻止此命令的可用性：

```
docker run -it security-app sh
```

1.  当前作为默认值运行的`seccomp`配置文件应该允许我们运行`chown`命令，因此在您可以访问运行的容器时，测试一下是否可以创建新文件并使用`chown`命令更改所有权。最后运行目录的长列表以验证更改是否已生效：

```
/# touch test.txt
/# chown 1001 test.txt
/# ls -l test.txt
```

这些命令应该提供类似以下的输出：

```
-rw-r--r--    1 1001      users        0 Oct 22 02:44 test.txt
```

1.  通过修改默认配置文件来创建您的自定义配置文件。使用`wget`命令从本书的官方 GitHub 帐户下载自定义配置文件到您的系统上。使用以下命令将下载的自定义配置文件重命名为`new_default.json`：

```
wget https://raw.githubusercontent.com/docker/docker/v1.12.3/profiles/seccomp/default.json -O new_default.json
```

1.  使用文本编辑器打开`new_default.json`文件，尽管会有大量的配置列表，但要搜索控制`chown`的特定配置。在撰写本文时，这位于默认`seccomp`配置文件的*第 59 行*：

```
59                 {  
60                         "name": "chown",
61                         "action": "SCMP_ACT_ALLOW",
62                         "args": []
63                 },
```

`SCMP_ACT_ALLOW`操作允许运行命令，但如果从`new_default.json`文件中删除*第 59*至*63 行*，这应该会阻止我们的配置文件允许运行此命令。删除这些行并保存文件以供我们使用。

1.  与此练习中*步骤 4*一样，使用`--security-opt`选项并指定使用我们编辑过的`new_default.json`文件来运行镜像：

```
docker run -it --security-opt seccomp=new_default.json security-app sh
```

1.  执行与此练习中*步骤 6*相同的测试，如果我们的更改起作用，`seccomp`配置文件现在应该阻止我们运行`chown`命令：

```
/# touch test.txt
/# chown 1001 test.txt
chown: test.txt: Operation not permitted
```

只需进行最少量的工作，我们就成功创建了一个策略，以阻止恶意代码或攻击者更改容器中文件的所有权。虽然这只是一个非常基本的例子，但它让您了解了如何开始配置`seccomp`配置文件，以便根据您的需求进行特定的微调。

## 活动 11.01：为全景徒步应用程序设置 seccomp 配置文件

全景徒步应用程序正在顺利进行，但本章表明您需要确保用户在容器上可以执行的操作受到限制。如果容器可以被攻击者访问，您需要设置一些防范措施。在此活动中，您将创建一个`seccomp`配置文件，可用于应用程序中的服务，以阻止用户能够创建新目录，终止运行在容器上的进程，并最后，通过运行`uname`命令了解有关运行容器的更多详细信息。

完成此活动所需的步骤如下：

1.  获取默认的`seccomp`配置文件的副本。

1.  查找配置文件中将禁用`mkdir`、`kill`和`uname`命令的特定控件。

1.  运行全景徒步应用程序的服务，并确保新配置文件应用于容器。

1.  访问容器并验证您是否不再能够执行在`seccomp`配置文件中被阻止的`mkdir`、`kill`和`uname`命令。例如，如果我们在添加了新配置文件的新图像上执行`mkdir`命令，我们应该看到类似以下的输出：

```
$ mkdir test
mkdir: can't create directory 'test': Operation not permitted
```

注意

可以通过此链接找到此活动的解决方案。

## 活动 11.02：扫描全景徒步应用图像以查找漏洞

我们一直在使用其他用户或开发人员提供的全景徒步应用的基本图像。在这个活动中，您需要扫描图像以查找漏洞，并查看它们是否安全可用。

完成此活动需要采取的步骤如下：

1.  决定使用哪种服务来扫描您的图像。

1.  将图像加载到准备好进行扫描的服务中。

1.  扫描图像并查看图像上是否存在任何漏洞。

1.  验证图像是否安全可用。您应该能够在 Anchore 中执行评估检查，并看到类似以下输出的通过状态：

```
Image Digest: sha256:57d8817bac132c2fded9127673dd5bc7c3a976546
36ce35d8f7a05cad37d37b7
Full Tag: docker.io/dockerrepo/postgres-app:sample_tag
Status: pass
Last Eval: 2019-11-23T06:15:32Z
Policy ID: 2c53a13c-1765-11e8-82ef-23527761d060
```

注意

可以通过此链接找到此活动的解决方案。

# 总结

本章主要讨论了安全性，限制在使用 Docker 和我们的容器图像时的风险，以及我们如何在 Docker 安全方面迈出第一步。我们看到了以 root 用户身份运行容器进程的潜在风险，并了解了如何通过进行一些微小的更改来防止这些问题的出现，如果攻击者能够访问正在运行的容器。然后，我们更仔细地研究了如何通过使用图像签名证书来信任我们正在使用的图像，然后在我们的 Docker 图像上实施安全扫描。

在本章结束时，我们开始使用安全配置文件。我们使用了两种最常见的安全配置文件 - AppArmor 和`seccomp` - 在我们的 Docker 图像上实施了两种配置文件，并查看了减少容器特定访问权限的结果。下一章将探讨在运行和创建我们的 Docker 图像时实施最佳实践。


# 第十二章：最佳实践

概述

在本章中，您将学习一些在使用 Docker 和容器镜像时的最佳实践，这将使您能够监视和管理容器使用的资源，并限制其对主机系统的影响。您将分析 Docker 的最佳实践，并了解为什么重要的是只在一个容器中运行一个服务，确保您的容器是可扩展的和不可变的，并确保您的基础应用程序在短时间内启动。本章将通过使用 `hadolint` 的 `FROM:latest` 命令和 `dcvalidator` 在应用程序和容器运行之前对您的 `Dockerfiles` 和 `docker-compose.yml` 文件进行检查，以帮助您强制执行这些最佳实践。

# 介绍

安全的前一章涵盖了一些 Docker 镜像和服务的最佳实践，这些实践已经遵循了这些最佳实践。我们确保我们的镜像和服务是安全的，并且限制了如果攻击者能够访问镜像时可以实现的内容。本章不仅将带您了解创建和运行 Docker 镜像的最佳实践，还将关注容器性能、配置我们的服务，并确保运行在其中的服务尽可能高效地运行。

我们将从深入了解如何监视和配置服务使用的资源开始，比如内存和 CPU 使用情况。然后，我们将带您了解一些您可以在项目中实施的重要实践，看看您如何创建 Docker 镜像以及在其上运行的应用程序。最后，本章将为您提供一些实用工具，用于测试您的 `Dockerfiles` 和 `docker-compose.yml` 文件，这将作为一种确保您遵循所述实践的方式。

本章展示了如何确保尽可能优化您的服务和容器，以确保它们从开发环境到生产环境都能无故障地运行。本章的目标是确保您的服务尽快启动，并尽可能高效地处理。本章提到的实践还确保了可重用性（也就是说，他们确保任何想要重用您的镜像或代码的人都可以这样做，并且可以随时了解具体发生了什么）。首先，以下部分讨论了如何使用容器资源。

# 使用容器资源

从传统服务器环境迁移到 Docker 的主要好处之一是，即使在转移到生产环境时，它使我们能够大大减少服务和应用程序的占用空间。然而，这并不意味着我们可以简单地在容器上运行任何东西，期望所有进程都能顺利完成执行。就像在独立服务器上运行服务时一样，我们需要确保我们的容器使用的资源（如 CPU、内存和磁盘输入输出）不会导致我们的生产环境或任何其他容器崩溃。通过监控开发系统中使用的资源，我们可以帮助优化流程，并确保最终用户在将其移入生产环境时体验到无缝操作。

通过测试我们的服务并监控资源使用情况，我们将能够了解运行应用程序所需的资源，并确保运行我们 Docker 镜像的主机具有足够的资源来运行我们的服务。最后，正如您将在接下来的章节中看到的，我们还可以限制容器可以访问的 CPU 和内存资源的数量。在开发运行在 Docker 上的服务时，我们需要在开发系统上测试这些服务，以确切了解它们在移入测试和生产环境时会发生什么。

当我们将多种不同的服务（如数据库、Web 服务器和 API 网关）组合在一起创建一个应用程序时，有些服务比其他服务更重要，在某些情况下，这些服务可能需要分配更多资源。然而，在 Docker 中，运行的容器默认情况下并没有真正的资源限制。

在之前的章节中，我们学习了使用 Swarm 和 Kubernetes 进行编排，这有助于在系统中分配资源，但本章的这一部分将教您一些基本工具来测试和监视您的资源。我们还将看看您可以如何配置您的容器，以不再使用默认可用的资源。

为了帮助我们在本章的这一部分，我们将创建一个新的镜像，该镜像将仅用于演示我们系统中的资源使用情况。在本节的第一部分中，我们将创建一个将添加一个名为 stress 的应用程序的镜像。stress 应用程序的主要功能是对我们的系统施加重负载。该镜像将允许我们查看在我们的主机系统上使用的资源，然后允许我们在运行 Docker 镜像时使用不同的选项来限制使用的资源。

注意

本章的这一部分将为您提供有关监视我们正在运行的 Docker 容器资源的简要指南。本章将仅涵盖一些简单的概念，因为我们将在本书的另一章节中专门提供有关监视容器指标的深入细节。

为了帮助我们查看正在运行的容器消耗的资源，Docker 提供了`stats`命令，作为我们正在运行的容器消耗资源的实时流。如果您希望限制流所呈现的数据，特别是如果您有大量正在运行的容器，您可以通过指定容器的名称或其 ID 来指定只提供某些容器：

```
docker stats <container_name|container_id>
```

`docker` `stats`命令的默认输出将为您提供容器的名称和 ID，容器正在使用的主机 CPU 和内存的百分比，容器正在发送和接收的数据，以及从主机存储中读取和写入的数据量：

```
NAME                CONTAINER           CPU %
docker-stress       c8cf5ad9b6eb        400.43%
```

以下部分将重点介绍如何使用`docker stats`命令来监视我们的资源。我们还将向`stats`命令提供格式控制，以提供我们需要的信息。

# 管理容器 CPU 资源

本章的这一部分将向您展示如何设置容器使用的 CPU 数量限制，因为没有限制的容器可能会占用主机服务器上所有可用的 CPU 资源。我们将着眼于优化我们正在运行的 Docker 容器，但实际上大量使用 CPU 的问题通常出现在基础设施或容器中运行的应用程序上。

当我们讨论 CPU 资源时，通常是指单个物理计算机芯片。如今，CPU 很可能有多个核心，更多的核心意味着更多的进程。但这并不意味着我们拥有无限的资源。当我们显示正在使用的 CPU 百分比时，除非您的系统只有一个 CPU 和一个核心，否则您很可能会看到超过 100%的 CPU 使用率。例如，如果您的系统的 CPU 中有四个核心，而您的容器正在利用所有的 CPU，您将看到 400%的值。

我们可以修改在我们的系统上运行的`docker stats`命令，通过提供`--format`选项来仅提供 CPU 使用情况的详细信息。这个选项允许我们指定我们需要的输出格式，因为我们可能只需要`stats`命令提供的一两个指标。以下示例配置了`stats`命令的输出以以`table`格式显示，只呈现容器的名称、ID 和正在使用的 CPU 百分比：

```
docker stats --format "table {{.Name}}\t{{.Container}}\t{{.CPUPerc}}"
```

如果我们没有运行 Docker 镜像，这个命令将提供一个包含以下三列的表格：

```
NAME                CONTAINER           CPU %
```

为了控制我们正在运行的容器使用的 CPU 核心数量，我们可以在`docker run`命令中使用`--cpus`选项。以下语法向我们展示了运行镜像，但通过使用`--cpus`选项限制了镜像可以访问的核心数量：

```
docker run --cpus 2 <docker-image>
```

更好的选择不是设置容器可以使用的核心数量，而是设置它可以共享的总量。Docker 提供了`--cpushares`或`-c`选项来设置容器可以使用的处理能力的优先级。通过使用这个选项，这意味着在运行容器之前我们不需要知道主机机器有多少个核心。这也意味着我们可以将正在运行的容器转移到不同的主机系统，而不需要更改运行镜像的命令。

默认情况下，Docker 将为每个运行的容器分配 1,024 份份额。如果您将`--cpushares`值设置为`256`，它将拥有其他运行容器的四分之一的处理份额：

```
docker run --cpushares 256 <docker-image>
```

注意

如果系统上没有运行其他容器，即使您已将`--cpushares`值设置为`256`，容器也将被允许使用剩余的处理能力。

即使您的应用程序可能正在正常运行，查看减少其可用 CPU 量以及在正常运行时消耗多少的做法总是一个好习惯。

在下一个练习中，我们将使用`stress`应用程序来监视系统上的资源使用情况。

注意

请使用`touch`命令创建文件，并使用`vim`命令使用 vim 编辑器处理文件。

## 练习 12.01：了解 Docker 镜像上的 CPU 资源

在这个练习中，您将首先创建一个新的 Docker 镜像，这将帮助您在系统上生成一些资源。我们将演示如何在镜像上使用已安装的`stress`应用程序。该应用程序将允许您开始监视系统上的资源使用情况，以及允许您更改镜像使用的 CPU 资源数量：

1.  创建一个新的`Dockerfile`并打开您喜欢的文本编辑器输入以下细节。您将使用 Ubuntu 作为基础来创建镜像，因为`stress`应用程序尚未作为易于在 Alpine 基础镜像上安装的软件包提供：

```
FROM ubuntu
RUN apt-get update && apt-get install stress
CMD stress $var
```

1.  使用`docker build`命令的`-t`选项构建新镜像并将其标记为`docker-stress`：

```
docker build -t docker-stress .
```

1.  在运行新的`docker-stress`镜像之前，请先停止并删除所有其他容器，以确保结果不会被系统上运行的其他容器混淆：

```
docker rm -f $(docker -a -q)
```

1.  在`Dockerfile`的*第 3 行*上，您会注意到`CMD`指令正在运行 stress 应用程序，后面跟着`$var`变量。这将允许您通过环境变量直接向容器上运行的 stress 应用程序添加命令行选项，而无需每次想要更改功能时都构建新镜像。通过运行您的镜像并使用`-e`选项添加环境变量来测试这一点。将`var="--cpu 4 --timeout 20"`作为`stress`命令的命令行选项添加：

```
docker run --rm -it -e var="--cpu 4 --timeout 20" docker-stress
```

`docker run`命令已添加了`var="--cpu 4 --timeout 20"`变量，这将特别使用这些命令行选项运行`stress`命令。`--cpu`选项表示将使用系统的四个 CPU 或核心，`--timeout`选项将允许压力测试运行指定的秒数 - 在本例中为`20`：

```
stress: info: [6] dispatching hogs: 4 cpu, 0 io, 0 vm, 0 hdd
stress: info: [6] successful run completed in 20s
```

注意

如果我们需要连续运行`stress`命令而不停止，我们将简单地不包括`--timeout`选项。我们的示例都包括`timeout`选项，因为我们不想忘记并持续使用运行主机系统的资源。

1.  运行`docker stats`命令，查看这对主机系统的影响。使用`--format`选项限制所提供的输出，只提供 CPU 使用情况：

```
docker stats --format "table {{.Name}}\t{{.Container}}\t{{.CPUPerc}}"
```

除非您的系统上运行着一个容器，否则您应该只看到表头，类似于此处提供的输出：

```
NAME                CONTAINER           CPU %
```

1.  在运行`stats`命令的同时，进入一个新的终端窗口，并再次运行`docker-stress`容器，就像本练习的*步骤 4*中一样。使用`--name`选项确保在使用`docker stress`命令时查看正确的镜像：

```
docker run --rm -it -e var="--cpu 4 --timeout 20" --name docker-stress docker-stress
```

1.  返回到运行`docker stats`的终端。现在您应该看到一些输出呈现在您的表上。您的输出将与以下内容不同，因为您的系统上可能运行着不同数量的核心。以下输出显示我们的 CPU 百分比使用了 400%。运行该命令的系统有六个核心。它显示 stress 应用程序正在使用四个可用核心中的 100%：

```
NAME                CONTAINER           CPU %
docker-stress       c8cf5ad9b6eb        400.43%
```

1.  再次运行`docker-stress`容器，这次将`--cpu`选项设置为`8`：

```
docker run --rm -it -e var="--cpu 8 --timeout 20" --name docker-stress docker-stress
```

如您在以下统计输出中所见，我们已经达到了 Docker 容器几乎使用系统上所有六个核心的极限，为我们的系统上的次要进程留下了一小部分处理能力：

```
NAME                CONTAINER           CPU %
docker-stress       8946da6ffa90        599.44%
```

1.  通过使用`--cpus`选项并指定要允许镜像使用的核心数量，来管理您的`docker-stress`镜像可以访问的核心数量。在以下命令中，将`2`设置为我们的容器被允许使用的核心数量：

```
docker run --rm -it -e var="--cpu 8 --timeout 20" --cpus 2 --name docker-stress docker-stress
```

1.  返回到运行`docker stats`的终端。您将看到正在使用的 CPU 百分比不会超过 200%，显示 Docker 将资源使用限制在我们系统上仅有的两个核心：

```
NAME                CONTAINER           CPU %
docker-stress       79b32c67cbe3        208.91%
```

到目前为止，您只能一次在我们的系统上运行一个容器。这个练习的下一部分将允许您以分离模式运行两个容器。在这里，您将测试在运行的一个容器上使用`--cpu-shares`选项来限制它可以使用的核心数量。

1.  如果您没有在终端窗口中运行`docker stats`，请像之前一样启动它，以便我们监视正在运行的进程：

```
docker stats --format "table {{.Name}}\t{{.Container}}\t{{.CPUPerc}}"
```

1.  访问另一个终端窗口，并启动两个`docker-stress`容器 - `docker-stress1`和`docker-stress2`。第一个将使用`--timeout`值为`60`，让压力应用程序运行 60 秒，但在这里，将`--cpu-shares`值限制为`512`：

```
docker run --rm -dit -e var="--cpu 8 --timeout 60" --cpu-shares 512 --name docker-stress1 docker-stress
```

容器的 ID 将返回如下：

```
5f617e5abebabcbc4250380b2591c692a30b3daf481b6c8d7ab8a0d1840d395f
```

第二个容器将不受限制，但`--timeout`值只有`30`，所以它应该先完成：

```
docker run --rm -dit -e var="--cpu 8 --timeout 30" --name docker-stress2 docker-stress2
```

容器的 ID 将返回如下：

```
83712c28866dd289937a9c5fe4ea6c48a6863a7930ff663f3c251145e2fbb97a
```

1.  回到运行`docker stats`的终端。您会看到两个容器正在运行。在以下输出中，我们可以看到名为`docker-stress1`和`docker-stress2`的容器。`docker-stress1`容器被设置为只有`512` CPU 份额，而其他容器正在运行。还可以观察到它只使用了第二个名为`docker-stress2`的容器的一半 CPU 资源：

```
NAME                CONTAINER           CPU %
docker-stress1      5f617e5abeba        190.25%
docker-stress2      83712c28866d        401.49%
```

1.  当第二个容器完成后，`docker-stress1`容器的 CPU 百分比将被允许使用运行系统上几乎所有六个可用的核心：

```
NAME                CONTAINER           CPU %
stoic_keldysh       5f617e5abeba        598.66%
```

CPU 资源在确保应用程序以最佳状态运行方面起着重要作用。这个练习向您展示了在将容器部署到生产环境之前，监视和配置容器的处理能力有多么容易。接下来的部分将继续对容器的内存执行类似的监视和配置更改。

# 管理容器内存资源

就像我们可以监视和控制容器在系统上使用的 CPU 资源一样，我们也可以对内存的使用情况进行相同的操作。与 CPU 一样，默认情况下，运行的容器可以使用主机的所有内存，并且在某些情况下，如果没有限制，可能会导致系统变得不稳定。如果主机系统内核检测到没有足够的内存可用，它将显示**内存不足异常**并开始终止系统上的进程以释放内存。

好消息是，Docker 守护程序在您的系统上具有高优先级，因此内核将首先终止运行的容器，然后才会停止 Docker 守护程序的运行。这意味着如果高内存使用是由容器应用程序引起的，您的系统应该能够恢复。

注意

如果您的运行容器正在被关闭，您还需要确保已经测试了您的应用程序，以确保它对正在运行的进程的影响是有限的。

再次强调，`docker stats`命令为我们提供了关于内存使用情况的大量信息。它将输出容器正在使用的内存百分比，以及当前内存使用量与其能够使用的总内存量的比较。与之前一样，我们可以通过`--format`选项限制所呈现的输出。在以下命令中，我们通过`.Name`、`.Container`、`.MemPerc`和`.MemUsage`属性，仅显示容器名称和 ID，以及内存百分比和内存使用量：

```
docker stats --format "table {{.Name}}\t{{.Container}}\t{{.MemPerc}}\t{{.MemUsage}}"
```

没有运行的容器，上述命令将显示以下输出：

```
NAME         CONTAINER          MEM %         MEM USAGE / LIMIT
```

如果我们想要限制或控制运行容器使用的内存量，我们有一些选项可供选择。其中一个可用的选项是`--memory`或`-m`选项，它将设置运行容器可以使用的内存量的限制。在以下示例中，我们使用了`--memory 512MB`的语法来限制可用于镜像的内存量为`512MB`：

```
docker run --memory 512MB <docker-image>
```

如果容器正在运行的主机系统也在使用交换空间作为可用内存的一部分，您还可以将内存从该容器分配为交换空间。这只需使用`--memory-swap`选项即可。这只能与`--memory`选项一起使用，正如我们在以下示例中所演示的。我们已将`--memory-swap`选项设置为`1024MB`，这是容器可用内存的总量，包括内存和交换内存。因此，在我们的示例中，交换空间中将有额外的`512MB`可用：

```
docker run --memory 512MB --memory-swap 1024MB <docker-image>
```

但需要记住，交换内存将被分配到磁盘，因此会比 RAM 更慢、响应更慢。

注意

`--memory-swap`选项需要设置为高于`--memory`选项的数字。如果设置为相同的数字，您将无法为运行的容器分配任何内存到交换空间。

另一个可用的选项，只有在需要确保运行容器始终可用时才能使用的是`--oom-kill-disable`选项。此选项会阻止内核在主机系统内存过低时杀死运行的容器。这应该只与`--memory`选项一起使用，以确保您设置了容器可用内存的限制。如果没有限制，`--oom-kill-disable`选项很容易使用主机系统上的所有内存：

```
docker run --memory 512MB --oom-kill-disable <docker-image>
```

尽管您的应用程序设计良好，但前面的配置为您提供了一些选项来控制运行容器使用的内存量。

下一节将为您提供在分析 Docker 镜像上的内存资源方面的实践经验。

## 练习 12.02：分析 Docker 镜像上的内存资源

这项练习将帮助您分析在主机系统上运行时活动容器如何使用内存。再次使用之前创建的`docker-stress`镜像，但这次使用选项仅在运行容器上使用内存。这个命令将允许我们实现一些可用的内存限制选项，以确保我们运行的容器不会使主机系统崩溃：

1.  运行`docker stats`命令以显示所需的百分比内存和内存使用值的相关信息：

```
docker stats --format "table {{.Name}}\t{{.Container}}\t{{.MemPerc}}\t{{.MemUsage}}"
```

这个命令将提供以下类似的输出：

```
NAME        CONTAINER       MEM %         MEM USAGE / LIMIT
```

1.  打开一个新的终端窗口再次运行`stress`命令。你的`docker-stress`镜像只有在使用`--cpu`选项时才会利用 CPU。使用以下命令中的`--vm`选项来启动你希望产生的工作进程数量以消耗内存。默认情况下，每个工作进程将消耗`256MB`：

```
docker run --rm -it -e var="--vm 2 --timeout 20" --name docker-stress docker-stress
```

当你返回监视正在运行的容器时，内存使用量只达到了限制的 20%左右。这可能因不同系统而异。由于只有两个工作进程在运行，每个消耗 256MB，你应该只会看到内存使用量达到大约 500MB：

```
NAME            CONTAINER      MEM %      MEM USAGE / LIMIT
docker-stress   b8af08e4d79d   20.89%     415.4MiB / 1.943GiB
```

1.  压力应用程序还有`--vm-bytes`选项来控制每个被产生的工作进程将消耗的字节数。输入以下命令，将每个工作进程设置为`128MB`。当你监视它时，它应该显示较低的使用量：

```
docker run --rm -it -e var="--vm 2 --vm-bytes 128MB --timeout 20" --name stocker-stress docker-stress
```

正如你所看到的，压力应用程序在推动内存使用量时并没有取得很大的进展。如果你想要使用系统上可用的全部 8GB RAM，你可以使用`--vm 8 --vm-bytes` 1,024 MB：

```
NAME            CONTAINER      MEM %    MEM USAGE / LIMIT
docker-stress   ad7630ed97b0   0.04%    904KiB / 1.943GiB
```

1.  使用`--memory`选项减少`docker-stress`镜像可用的内存。在以下命令中，你会看到我们将正在运行的容器的可用内存限制为`512MB`：

```
docker run --rm -it -e var="--vm 2 --timeout 20" --memory 512MB --name docker-stress docker-stress
```

1.  返回到运行`docker stats`的终端，你会看到内存使用率飙升到了接近 100%。这并不是一件坏事，因为它只是你正在运行的容器分配的一小部分内存。在这种情况下，它是 512MB，仅为之前的四分之一：

```
NAME            CONTAINER      MEM %     MEM USAGE / LIMIT
docker-stress   bd84cf27e480   88.11%    451.1MiB / 512MiB
```

1.  同时运行多个容器，看看我们的`stats`命令如何响应。在`docker run`命令中使用`-d`选项将容器作为守护进程在主机系统的后台运行。现在，两个`docker-stress`容器都将使用六个工作进程，但我们的第一个镜像，我们将其命名为`docker-stress1`，被限制在`512MB`的内存上，而我们的第二个镜像，名为`docker-stress2`，只运行 20 秒，将拥有无限的内存：

```
docker run --rm -dit -e var="--vm 6 --timeout 60" --memory 512MB --name docker-stress1 docker-stress
ca05e244d03009531a6a67045a5b1edbef09778737cab2aec7fa92eeaaa0c487
docker run --rm -dit -e var="--vm 6 --timeout 20" --name docker-stress2 docker-stress
6d9cbb966b776bb162a47f5e5ff3d88daee9b0304daa668fca5ff7ae1ee887ea
```

1.  返回到运行`docker stats`的终端。你会看到只有一个容器，即`docker-stress1`容器，被限制在 512MB，而`docker-stress2`镜像被允许在更多的内存上运行：

```
NAME             CONTAINER       MEM %    MEM USAGE / LIMIT
docker-stress1   ca05e244d030    37.10%   190MiB / 512MiB
docker-stress2   6d9cbb966b77    31.03%   617.3MiB / 1.943GiB
```

如果你等待一会儿，`docker-stress1`镜像将被留下来独自运行：

```
NAME             CONTAINER      MEM %    MEM USAGE / LIMIT
docker-stress1   ca05e244d030   16.17%   82.77MiB / 512MiB
```

注意

我们在这里没有涵盖的一个选项是`--memory-reservation`选项。这也与`--memory`选项一起使用，并且需要设置为低于内存选项。这是一个软限制，当主机系统的内存不足时激活，但不能保证限制将被执行。

本章的这一部分帮助我们确定如何运行容器并监视使用情况，以便在将它们投入生产时，它们不会通过使用所有可用内存来停止主机系统。现在，您应该能够确定您的镜像正在使用多少内存，并在长时间运行或内存密集型进程出现问题时限制可用内存量。在下一节中，我们将看看我们的容器如何在主机系统磁盘上消耗设备的读写资源。

# 管理容器磁盘的读写资源

运行容器消耗的 CPU 和内存通常是环境运行不佳的最大罪魁祸首，但您的运行容器也可能存在问题，尝试读取或写入主机的磁盘驱动器过多。这很可能对 CPU 或内存问题影响较小，但如果大量数据被传输到主机系统的驱动器上，仍可能引起争用并减慢服务速度。

幸运的是，Docker 还为我们提供了一种控制运行容器执行读取和写入操作的方法。就像我们之前看到的那样，我们可以在`docker run`命令中使用多个选项来限制我们要读取或写入设备磁盘的数据量。

`docker stats`命令还允许我们查看传输到和从我们的运行容器的数据。它有一个专用列，可以使用`docker stats`命令中的`BlockIO`值将其添加到我们的表中，该值代表对我们的主机磁盘驱动器或目录的读写操作：

```
docker stats --format "table {{.Name}}\t{{.Container}}\t{{.BlockIO}}"
```

如果我们的系统上没有任何运行的容器，上述命令应该为我们提供以下输出：

```
NAME                CONTAINER           BLOCK I/O
```

如果我们需要限制正在运行的容器可以移动到主机系统磁盘存储的数据量，我们可以从使用`--blkio-weight`选项开始，该选项与我们的`docker run`命令一起使用。此选项代表**块输入输出权重**，允许我们为容器设置一个相对权重，介于`10`和`1000`之间，并且相对于系统上运行的所有其他容器。所有容器将被设置为相同比例的带宽，即 500。如果为任何容器提供值 0，则此选项将被关闭。

```
docker run --blkio-weight <value> <docker-image>
```

我们可以使用的下一个选项是`--device-write-bps`，它将限制指定的设备可用的特定写入带宽，以字节每秒的值为单位。特定设备是相对于容器在主机系统上使用的设备。此选项还有一个“每秒输入/输出（IOPS）”选项，也可以使用。以下语法提供了该选项的基本用法，其中限制值设置为 MB 的数值：

```
docker run --device-write-bps <device>:<limit> <docker-image>
```

就像有一种方法可以限制写入进程到主机系统的磁盘一样，也有一种选项可以限制可用的读取吞吐量。同样，它还有一个“每秒输入/输出（IOPS）”选项，可以用来限制可以从正在运行的容器中读取的数据量。以下示例使用`--device-read-bps`选项作为`docker run`命令的一部分：

```
docker run --device-read-bps <device>:<limit> <docker-image>
```

如果您遵守容器最佳实践，磁盘输入或输出的过度消耗不应该是太大的问题。尽管如此，没有理由认为这不会给您造成任何问题。就像您已经处理过 CPU 和内存一样，您的磁盘输入和输出应该在将服务实施到生产环境之前在运行的容器上进行测试。

## 练习 12.03：理解磁盘读写

这个练习将使您熟悉查看正在运行的容器的磁盘读写。它将允许您通过在运行时使用可用的选项来配置磁盘使用速度的限制来开始运行您的容器：

1.  打开一个新的终端窗口并运行以下命令：

```
docker stats --format "table {{.Name}}\t{{.Container}}\t{{.BlockIO}}" 
```

`docker stats`命令与`BlockIO`选项帮助我们监视从我们的容器到主机系统磁盘的输入和输出级别。

1.  启动容器以从 bash 命令行访问它。在运行的`docker-stress`镜像上直接执行一些测试。stress 应用程序确实为您提供了一些选项，以操纵容器和主机系统上的磁盘利用率，但它仅限于磁盘写入：

```
docker run -it --rm --name docker-stress docker-stress /bin/bash
```

1.  与 CPU 和内存使用情况不同，块输入和输出显示容器使用的总量，因此它不会随着运行容器执行更多更改而动态变化。回到运行`docker stats`的终端。您应该看到输入和输出都为`0B`：

```
NAME                CONTAINER           BLOCK I/O
docker-stress       0b52a034f814        0B / 0B
```

1.  在这种情况下，您将使用 bash shell，因为它可以访问`time`命令以查看每个进程需要多长时间。使用`dd`命令，这是一个用于复制文件系统和备份的 Unix 命令。在以下选项中，使用`if`（输入文件）选项创建我们的`/dev/zero`目录的副本，并使用`of`（输出文件）选项将其输出到`disk.out`文件。`bs`选项是块大小或应该一次读取的数据量，`count`是要读取的总块数。最后，将`oflag`值设置为`direct`，这意味着复制将避免缓冲区缓存，因此您将看到磁盘读取和写入的真实值：

```
time dd if=/dev/zero of=disk.out bs=1M count=10 oflag=direct
10+0 records in
10+0 records out
10485760 bytes (10 MB, 10 MiB) copied, 0.0087094 s, 1.2 GB/s
real    0m0.010s
user    0m0.000s
sys     0m0.007s
```

1.  回到运行`docker stats`命令的终端。您将看到超过 10MB 的数据发送到主机系统的磁盘。与 CPU 和内存不同，传输完成后，您不会看到此数据值下降：

```
NAME                CONTAINER           BLOCK I/O
docker-stress       0b52a034f814        0B / 10.5MB
```

您还会注意到*步骤 4*中的命令几乎立即完成，`time`命令显示实际只需`0.01s`即可完成。您将看到如果限制可以写入磁盘的数据量会发生什么，但首先退出运行的容器，以便它不再存在于我们的系统中。

1.  要再次启动我们的`docker-stress`容器，请将`--device-write-bps`选项设置为每秒`1MB`在`/dev/sda`设备驱动器上：

```
docker run -it --rm --device-write-bps /dev/sda:1mb --name docker-stress docker-stress /bin/bash
```

1.  再次运行`dd`命令，之前加上`time`命令，以测试需要多长时间。您会看到该命令花费的时间比*步骤 4*中的时间长得多。`dd`命令再次设置为复制`1MB`块，`10`次：

```
time dd if=/dev/zero of=test.out bs=1M count=10 oflag=direct
```

因为容器限制为每秒只能写入 1MB，所以该命令需要 10 秒，如下面的输出所示：

```
10+0 records in
10+0 records out
10485760 bytes (10 MB, 10 MiB) copied, 10.0043 s, 1.0 MB/s
real    0m10.006s
user    0m0.000s
sys     0m0.004s
```

我们已经能够很容易地看到我们的运行容器如何影响底层主机系统，特别是在使用磁盘读写时。我们还能够看到我们如何轻松地限制可以写入设备的数据量，以便在运行容器之间减少争用。在下一节中，我们将快速回答一个问题，即如果您正在使用`docker-compose`，您需要做什么，并且限制容器使用的资源数量。

# 容器资源和 Docker Compose

诸如 Kubernetes 和 Swarm 之类的编排器在控制和运行资源以及在需要额外资源时启动新主机方面发挥了重要作用。但是，如果您在系统或测试环境中运行`docker-compose`，您该怎么办呢？幸运的是，前面提到的资源配置也适用于`docker-compose`。

在我们的`docker-compose.yml`文件中，在我们的服务下，我们可以在`deploy`配置下使用`resources`选项，并为我们的服务指定资源限制。就像我们一直在使用`--cpus`、`--cpu_shares`和`--memory`等选项一样，我们在我们的`docker-compose.yml`文件中也会使用相同的选项，如`cpus`、`cpu_shares`和`memory`。

以下代码块中的示例`compose`文件部署了我们在本章中一直在使用的`docker-stress`镜像。如果我们看*第 8 行*，我们可以看到`deploy`语句，后面是`resources`语句。这是我们可以为我们的容器设置限制的地方。就像我们在前面的部分中所做的那样，我们在*第 11 行*上将`cpus`设置为`2`，在*第 12 行*上将`memory`设置为`256MB`。 

```
1 version: '3'
2 services:
3   app:
4     container_name: docker-stress
5     build: .
6     environment:
7       var: "--cpu 2 --vm 6 --timeout 20"
8     deploy:
9       resources:
10         limits:
11           cpus: '2'
12           memory: 256M
```

尽管我们只是简单地涉及了这个主题，但前面涵盖资源使用的部分应该指导您如何在`docker-compose.yml`文件中分配资源。这就是我们关于 Docker 容器资源使用的部分的结束。从这里开始，我们将继续研究创建我们的`Dockerfiles`的最佳实践，以及如何开始使用不同的应用程序来确保我们遵守这些最佳实践。

# Docker 最佳实践

随着我们的容器和服务规模和复杂性的增长，重要的是要确保在创建 Docker 镜像时我们遵循最佳实践。对于我们在 Docker 镜像上运行的应用程序也是如此。在本章的后面，我们将查看我们的`Dockerfiles`和`docker-compose.yml`文件，这将分析我们的文件中的错误和最佳实践，从而让您更清楚地了解。与此同时，让我们来看看在创建 Docker 镜像和应用程序与之配合工作时需要牢记的一些更重要的最佳实践。

注意

本章可能涵盖了一些之前章节的内容，但我们将能够为您提供更多信息和清晰解释为什么我们要使用这些实践。

在接下来的部分，我们将介绍一些在创建服务和容器时应该遵循的常见最佳实践。

## 每个容器只运行一个服务

在现代微服务架构中，我们需要记住每个容器只应安装一个服务。容器的主要进程由`Dockerfile`末尾的`ENTRYPOINT`或`CMD`指令设置。

您在容器中安装的服务很容易运行多个进程，但为了充分利用 Docker 和微服务的优势，您应该每个容器只运行一个服务。更进一步地说，您的容器应该只负责一个单一的功能，如果它负责的事情超过一个，那么它应该拆分成不同的服务。

通过限制每个容器的功能，我们有效地减少了镜像使用的资源，并可能减小了镜像的大小。正如我们在上一章中看到的，这也将减少攻击者在获得运行中的容器访问权限时能够执行任何不应该执行的操作的机会。这也意味着，如果容器因某种原因停止工作，对环境中运行的其他应用程序的影响有限，服务将更容易恢复。

## 基础镜像

当我们为我们的容器选择基础镜像时，我们需要做的第一件事之一是确保我们使用的是最新的镜像。还要做一些研究，确保您不使用安装了许多不需要的额外应用程序的镜像。您可能会发现，受特定语言支持的基础镜像或特定焦点将限制所需的镜像大小，从而限制您在创建镜像时需要安装的内容。

这就是为什么我们使用受 PostgreSQL 支持的 Docker 镜像，而不是在构建时在镜像上安装应用程序。受 PostgreSQL 支持的镜像确保它是安全的，并且运行在最新版本，并确保我们不在镜像上运行不需要的应用程序。

在为我们的`Dockerfile`指定基础镜像时，我们需要确保还指定了特定版本，而不是让 Docker 简单地使用`latest`镜像。另外，确保您不是从不是来自值得信赖的提供者的存储库或注册表中拉取镜像。

如果您已经使用 Docker 一段时间，可能已经遇到了`MAINTAINER`指令，您可以在其中指定生成图像的作者。现在这已经被弃用，但您仍然可以使用`LABEL`指令来提供这些细节，就像我们在以下语法中所做的那样：

```
LABEL maintainer="myemailaddress@emaildomain.com"
```

## 安装应用程序和语言

当您在镜像上安装应用程序时，永远记住不需要执行`apt-get update`或`dist-upgrade`。如果您需要以这种方式升级镜像版本，应该考虑使用不同的镜像。如果您使用`apt-get`或`apk`安装应用程序，请确保指定您需要的特定版本，因为您不希望安装新的或未经测试的版本。

在安装软件包时，确保使用`-y`开关，以确保构建不会停止并要求用户提示。另外，您还应该使用`--no-install-recommends`，因为您不希望安装大量您的软件包管理器建议的不需要的应用程序。此外，如果您使用基于 Debian 的容器，请确保使用`apt-get`或`apt-cache`，因为`apt`命令专门用于用户交互，而不是用于脚本化安装。

如果您正在从其他形式安装应用程序，比如从代码构建应用程序，请确保清理安装文件，以再次减小您创建的镜像的大小。同样，如果您正在使用`apt-get`，您还应该删除`/var/lib/apt/lists/`中的列表，以清理安装文件并减小容器镜像的大小。

## 运行命令和执行任务

当我们的镜像正在创建时，通常需要在我们的`Dockerfile`中执行一些任务，以准备好我们的服务运行的环境。始终确保您不使用`sudo`命令，因为这可能会导致一些意外的结果。如果需要以 root 身份运行命令，您的基础镜像很可能正在以 root 用户身份运行；只需确保您创建一个单独的用户来运行您的应用程序和服务，并且在构建完成之前容器已经切换到所需的用户。

确保您使用`WORKDIR`切换到不同的目录，而不是运行指定长路径的指令，因为这可能会让用户难以阅读。对于`CMD`和`ENTRYPOINT`参数，请使用`JSON`表示法，并始终确保只有一个`CMD`或`ENTRYPOINT`指令。

## 容器需要是不可变的和无状态的

我们需要确保我们的容器和运行在其中的服务是不可变的。我们不能像传统服务器那样对待容器，特别是在运行容器上更新应用程序的服务器。您应该能够从代码更新容器并部署它，而无需访问它。

当我们说不可变时，我们指的是容器在其生命周期内不会被修改，不会进行更新、补丁或配置更改。您的代码或更新的任何更改都应该通过构建新镜像然后部署到您的环境中来实现。这样做可以使部署更安全，如果升级出现任何问题，您只需重新部署旧版本的镜像。这也意味着您在所有环境中运行相同的镜像，确保您的环境尽可能相同。

当我们谈论容器需要是无状态的时候，这意味着运行容器所需的任何数据都应该在容器外部运行。文件存储也应该在容器外部，可能在云存储上或者使用挂载卷。将数据从容器中移除意味着容器可以在任何时候被干净地关闭和销毁，而不必担心数据丢失。当创建一个新的容器来替换旧的容器时，它只需连接到原始数据存储。

## 设计应用程序以实现高可用性和可扩展性

在微服务架构中使用容器旨在使您的应用程序能够扩展到多个实例。因此，在开发您的应用程序时，您应该预期可能会出现许多实例同时部署的情况，需要在需要时进行上下扩展。当容器负载较重时，您的服务运行和完成也不应该有问题。

当您的服务需要因为增加的请求而扩展时，应用程序需要启动的时间就成为一个重要问题。在将您的服务部署到生产环境之前，您需要确保启动时间很快，以确保系统能够更有效地扩展而不会给用户的服务造成任何延迟。为了确保您的服务符合行业最佳实践，您的服务应该在不到 10 秒内启动，但不到 20 秒也是可以接受的。

正如我们在前一节中所看到的，改善应用程序的启动时间不仅仅是提供更多的 CPU 和内存资源的问题。我们需要确保我们容器中的应用程序能够高效运行，如果它们启动和运行特定进程的时间太长，可能是因为一个应用程序执行了太多的任务。

## 图像和容器需要适当地打标签

我们在《第三章》《管理您的 Docker 镜像》中详细介绍了这个主题，并明确指出，我们需要考虑如何命名和标记我们的图像，特别是当我们开始与更大的开发团队合作时。为了让所有用户能够理解图像的功能，并了解部署到环境中的版本，需要在团队开始大部分工作之前决定并达成一致的相关标记和命名策略。

图像和容器名称需要与它们运行的应用程序相关，因为模糊的名称可能会引起混淆。还必须制定一个版本的约定标准，以确保任何用户都可以确定在特定环境中运行的版本以及最新稳定版本是什么版本。正如我们在*第三章*中提到的*管理您的 Docker 镜像*中所提到的，尽量不要使用`latest`，而是选择语义版本控制系统或 Git 存储库`commit`哈希，用户可以参考文档或构建环境，以确保他们拥有最新版本的镜像。

## 配置和秘密

环境变量和秘密不应该内置到您的 Docker 镜像中。通过这样做，您违反了可重用图像的规则。使用您的秘密凭据构建图像也是一种安全风险，因为它们将存储在图像层中，因此任何能够拉取图像的人都将能够看到凭据。

在为应用程序设置配置时，可能需要根据环境的不同进行更改，因此重要的是要记住，当需要时，您需要能够动态更改这些配置。这可能包括应用程序所编写的语言的特定配置，甚至是应用程序需要连接到的数据库。我们之前提到过，如果您正在配置应用程序作为您的`Dockerfile`的一部分，这将使其难以更改，您可能需要为您希望部署图像的每个环境创建一个特定的`Dockerfile`。

配置图像的一种方法，就像我们在`docker-stress`图像中看到的那样，是使用在运行图像时在命令行上设置的环境变量。如果未提供变量，则入口点或命令应包含默认值。这意味着即使未提供额外的变量，容器仍将启动和运行：

```
docker run -e var="<variable_name>" <image_name>
```

通过这样做，我们使我们的配置更加动态，但是当您有一个更大或更复杂的配置时，这可能会限制您的配置。环境变量可以很容易地从您的`docker run`命令转移到`docker-compose`，然后在 Swarm 或 Kubernetes 中使用。

对于较大的配置，您可能希望通过 Docker 卷挂载配置文件。这意味着您可以设置一个配置文件并在系统上轻松测试运行，然后如果需要转移到诸如 Kubernetes 或 Swarm 之类的编排系统，或者外部配置管理解决方案，您可以轻松将其转换为配置映射。

如果我们想要在本章中使用的`docker-stress`镜像中实现这一点，可以修改为使用配置文件来挂载我们想要运行的值。在以下示例中，我们修改了`Dockerfile`以设置*第 3 行*运行一个脚本，该脚本将代替我们运行`stress`命令：

```
1 FROM ubuntu
2 RUN apt-get update && apt-get install stress
3 CMD ["sh","/tmp/stress_test.sh"]
```

这意味着我们可以构建 Docker 镜像，并使其随时准备好供我们使用。我们只需要一个脚本，我们会挂载在`/tmp`目录中运行。我们可以使用以下示例：

```
1 #!/bin/bash
2 
3 /usr/bin/stress --cpu 8 --timeout 20 --vm 6 --timeout 60
```

这说明了将我们的值从环境变量移动到文件的想法。然后，我们将执行以下操作来运行容器和 stress 应用程序，知道如果我们想要更改`stress`命令使用的变量，我们只需要对我们挂载的文件进行微小的更改：

```
docker run --rm -it -v ${PWD}/stress_test.sh:/tmp/stress_test.sh docker-stress
```

注意

阅读完这些最佳实践清单时，你可能会认为我们违背了很多内容，但请记住，我们在很多情况下都这样做是为了演示一个流程或想法。

## 使您的镜像尽可能精简和小

*第三章*，*管理您的 Docker 镜像*，还让我们尽可能地减小了镜像的大小。我们发现通过减小镜像的大小，可以更快地构建镜像。它们也可以更快地被拉取并在我们的系统上运行。在我们的容器上安装的任何不必要的软件或应用程序都会占用额外的空间和资源，并可能因此减慢我们的服务速度。

正如我们在*第十一章*，*Docker 安全*中所做的那样，使用 Anchore Engine 这样的应用程序显示了我们可以审计我们的镜像以查看其内容，以及安装在其中的应用程序。这是一种简单的方法，可以确保我们减小镜像的大小，使其尽可能精简。

您现在已经了解了您应该在容器镜像和服务中使用的最佳实践。本章的以下部分将帮助您通过使用应用程序来验证您的`Dockerfiles`和`docker-compose.yml`是否按照应有的方式创建来强制执行其中的一些最佳实践。

# 在您的代码中强制执行 Docker 最佳实践

就像我们在开发应用程序时寻求使我们的编码更加简单一样，我们可以使用外部服务和测试来确保我们的 Docker 镜像遵守最佳实践。在本章的以下部分，我们将使用三种工具来确保我们的`Dockerfiles`和`docker-compose.yml`文件遵守最佳实践，并确保我们在构建 Docker 镜像时不会引入潜在问题。

这些工具将使用起来非常简单，并提供强大的功能。我们将首先使用`hadolint`在我们的系统上直接对我们的`Dockerfiles`进行代码检查，它将作为一个独立的 Docker 镜像运行，我们将把我们的`Dockerfiles`输入到其中。然后我们将看一下`FROM:latest`，这是一个在线服务，提供一些基本功能来帮助我们找出`Dockerfiles`中的问题。最后，我们将看一下**Docker Compose Validator**（**DCValidator**），它将执行类似的功能，但在这种情况下，我们将对我们的`docker-compose.yml`文件进行代码检查，以帮助找出潜在问题。

通过在构建和部署我们的镜像之前使用这些工具，我们希望减少我们的 Docker 镜像的构建时间，减少我们引入的错误数量，可能减少我们的 Docker 镜像的大小，并帮助我们更多地了解和执行 Docker 最佳实践。

## 使用 Docker Linter 检查您的镜像

包含本书所有代码的 GitHub 存储库还包括将与构建的 Docker 镜像进行比较的测试。另一方面，代码检查器将分析您的代码，并在构建镜像之前寻找潜在错误。在本章的这一部分，我们正在寻找我们的`Dockerfiles`中的潜在问题，特别是使用一个名为`hadolint`的应用程序。

名称`hadolint`是**Haskell Dockerfile Linter**的缩写，并带有自己的 Docker 镜像，允许您拉取该镜像，然后将您的`Dockerfile`发送到正在运行的镜像以进行测试。即使您的`Dockerfile`相对较小，并且构建和运行没有任何问题，`hadolint`通常会提供许多建议，并指出`Dockerfile`中的缺陷，以及可能在将来出现问题的潜在问题。

要在您的`Dockerfiles`上运行`hadolint`，您需要在您的系统上有`hadolint` Docker 镜像。正如您现在所知，这只是运行`docker pull`命令并使用所需镜像的名称和存储库的问题。在这种情况下，存储库和镜像都称为`hadolint`：

```
docker pull hadolint/hadolint
```

然后，您可以简单地运行`hadolint`镜像，并使用小于(`<`)符号将您的`Dockerfile`指向它，就像我们在以下示例中所做的那样：

```
docker run hadolint/hadolint < Dockerfile
```

如果您足够幸运，没有任何问题与您的`Dockerfile`，您不应该看到前面命令的任何输出。如果有需要忽略特定警告的情况，您可以使用`--ignore`选项，后跟触发警告的特定规则 ID：

```
docker run hadolint/hadolint hadolint --ignore <hadolint_rule_id> - < Dockerfile
```

如果您需要忽略一些警告，尝试在命令行中实现可能会有点复杂，因此`hadolint`还有设置配置文件的选项。`hadolint`配置文件仅限于忽略警告并提供受信任存储库的列表。您还可以使用 YAML 格式设置包含您忽略警告列表的配置文件。然后，`hadolint`将需要在运行的镜像上挂载此文件，以便应用程序使用它，因为它将在应用程序的主目录中查找`.hadolint.yml`配置文件位置：

```
docker run --rm -i -v ${PWD}/.hadolint.yml:/.hadolint.yaml hadolint/hadolint < Dockerfile
```

`hadolint`是用于清理您的`Dockerfiles`的更好的应用程序之一，并且可以轻松地作为构建和部署流水线的一部分进行自动化。作为替代方案，我们还将看一下名为`FROM:latest`的在线应用程序。这个应用程序是一个基于 Web 的服务，不提供与`hadolint`相同的功能，但允许您轻松地将您的`Dockerfile`代码复制粘贴到在线编辑器中，并获得有关`Dockerfile`是否符合最佳实践的反馈。

## 练习 12.04：清理您的 Dockerfile

此练习将帮助您了解如何在系统上访问和运行`hadolint`，以帮助您强制执行`Dockerfiles`的最佳实践。我们还将使用一个名为`FROM:latest`的在线`Dockerfile` linter 来比较我们收到的警告：

1.  使用以下`docker pull`命令从`hadolint`存储库中拉取镜像：

```
docker pull hadolint/hadolint
```

1.  您已经准备好一个`Dockerfile`，其中包含您在本章早些时候用来测试和管理资源的`docker-stress`镜像。运行`hadolint`镜像以对此`Dockerfile`进行检查，或者对任何其他`Dockerfile`进行检查，并使用小于（`<`）符号发送到`Dockerfile`，如以下命令所示：

```
docker run --rm -i hadolint/hadolint < Dockerfile
```

从以下输出中可以看出，即使我们的`docker-stress`镜像相对较小，`hadolint`也提供了许多不同的方式，可以改善性能并帮助我们的镜像遵守最佳实践：

```
/dev/stdin:1 DL3006 Always tag the version of an image explicitly
/dev/stdin:2 DL3008 Pin versions in apt get install. Instead of 
'apt-get install <package>' use 'apt-get install 
<package>=<version>'
/dev/stdin:2 DL3009 Delete the apt-get lists after installing 
something
/dev/stdin:2 DL3015 Avoid additional packages by specifying 
'--no-install-recommends'
/dev/stdin:2 DL3014 Use the '-y' switch to avoid manual input 
'apt-get -y install <package>'
/dev/stdin:3 DL3025 Use arguments JSON notation for CMD 
and ENTRYPOINT arguments
```

注意

如果您的`Dockerfile`通过`hadolint`成功运行，并且没有发现任何问题，则在命令行上不会向用户呈现任何输出。

1.  `hadolint`还为您提供了使用`--ignore`选项来抑制不同检查的选项。在以下命令中，我们选择忽略`DL3008`警告，该警告建议您将安装的应用程序固定到特定版本号。执行`docker run`命令以抑制`DL3008`警告。请注意，在指定运行的镜像名称之后，您需要提供完整的`hadolint`命令，以及在提供`Dockerfile`之前提供额外的破折号（`-`）：

```
docker run --rm -i hadolint/hadolint hadolint --ignore DL3008 - < Dockerfile
```

您应该获得以下类似的输出：

```
/dev/stdin:1 DL3006 Always tag the version of an image explicitly
/dev/stdin:2 DL3009 Delete the apt-get lists after installing 
something
/dev/stdin:2 DL3015 Avoid additional packages by specifying 
'--no-install-recommends'
/dev/stdin:2 DL3014 Use the '-y' switch to avoid manual input 
'apt-get -y install <package>'
/dev/stdin:3 DL3025 Use arguments JSON notation for CMD and 
ENTRYPOINT arguments
```

1.  `hadolint`还允许您创建一个配置文件，以添加要忽略的任何警告，并在命令行上指定它们。使用`touch`命令创建一个名为`.hadolint.yml`的文件：

```
touch .hadolint.yml
```

1.  使用文本编辑器打开配置文件，并在`ignored`字段下输入您希望忽略的任何警告。如您所见，您还可以添加一个`trustedRegistries`字段，在其中列出您将从中拉取镜像的所有注册表。请注意，如果您的镜像不来自配置文件中列出的注册表之一，`hadolint`将提供额外的警告：

```
ignored:
  - DL3006
  - DL3008
  - DL3009
  - DL3015
  - DL3014
trustedRegistries:
  - docker.io
```

1.  `hadolint`将在用户的主目录中查找您的配置文件。由于您正在作为 Docker 镜像运行`hadolint`，因此在执行`docker run`命令时，使用`-v`选项将文件从当前位置挂载到运行镜像的主目录上：

```
docker run --rm -i -v ${PWD}/.hadolint.yml:/.hadolint.yaml hadolint/hadolint < Dockerfile
```

该命令将输出如下：

```
/dev/stdin:3 DL3025 Use arguments JSON notation for CMD and ENTRYPOINT arguments
```

注意

`hadolint`的源代码存储库提供了所有警告的列表，以及如何在您的`Dockerfile`中解决这些问题的详细信息。如果您还没有这样做，可以随意查看 Hadolint 维基页面[`github.com/hadolint/hadolint/wiki`](https://github.com/hadolint/hadolint/wiki)。

1.  最后，`hadolint`还允许您选择以 JSON 格式输出检查结果。再次，我们需要在命令行中添加一些额外的值。在命令行中，在将您的`Dockerfile`添加和解析到`hadolint`之前，添加额外的命令行选项`hadolint -f json`。在以下命令中，您还需要安装`jq`软件包：

```
docker run --rm -i -v ${PWD}/.hadolint.yml:/.hadolint.yaml hadolint/hadolint hadolint -f json - < Dockerfile | jq
```

您应该得到以下输出：

```
[
  {
    "line": 3,
    "code": "DL3025",
    "message": "Use arguments JSON notation for CMD and ENTRYPOINT arguments",
    "column": 1,
    "file": "/dev/stdin",
    "level": "warning"
  }
]
```

注意

`hadolint`可以轻松集成到您的构建流水线中，在构建之前对您的`Dockerfiles`进行检查。如果您有兴趣直接将`hadolint`应用程序安装到您的系统上，而不是使用 Docker 镜像，您可以通过克隆以下 GitHub 存储库来实现[`github.com/hadolint/hadolint`](https://github.com/hadolint/hadolint)。

`hadolint`并不是您可以用来确保您的`Dockerfiles`遵守最佳实践的唯一应用程序。这个练习的下一步将介绍一个名为`FROM:latest`的在线服务，也可以帮助强制执行`Dockerfiles`的最佳实践。

1.  要使用`FROM:latest`，打开您喜欢的网络浏览器，输入以下 URL：

```
https://www.fromlatest.io
```

当网页加载时，您应该看到类似以下截图的页面。在网页的左侧，您应该看到输入了一个示例`Dockerfile`，在网页的右侧，您应该看到一个潜在问题或优化`Dockerfile`的方法列表。右侧列出的每个项目都有一个下拉菜单，以向用户提供更多详细信息：

![图 12.1：FROM:latest 网站的截图，显示输入了一个示例 Dockerfile](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-ws/img/B15021_12_01.jpg)

图 12.1：FROM:latest 网站的截图，显示输入了一个示例 Dockerfile

1.  在这个练习的前一部分中，我们将使用`docker-stress`镜像的`Dockerfile`。要将其与`FROM:latest`一起使用，请将以下代码行复制到网页左侧，覆盖网站提供的示例`Dockerfile`：

```
FROM ubuntu
RUN apt-get update && apt-get install stress
CMD stress $var
```

一旦您将`Dockerfile`代码发布到网页上，页面将开始分析命令。正如您从以下截图中所看到的，它将提供有关如何解决潜在问题并优化`Dockerfile`以使镜像构建更快的详细信息：

![图 12.2：我们的 docker-stress 镜像输入的 Dockerfile](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-ws/img/B15021_12_02.jpg)

图 12.2：我们的 docker-stress 镜像输入的 Dockerfile

`hadolint`和`FROM latest`都提供了易于使用的选项，以帮助您确保您的`Dockerfiles`遵守最佳实践。下一个练习将介绍一种类似的方法，用于检查您的`docker-compose.yml`文件，以确保它们也可以无故障运行，并且不会引入任何不良实践。

## 练习 12.05：验证您的 docker-compose.yml 文件

Docker 已经有一个工具来验证您的`docker-compose.yml`文件，但是内置的验证器无法捕捉到`docker-compose`文件中的所有问题，包括拼写错误、相同的端口分配给不同的服务或重复的键。我们可以使用`dcvalidator`来查找诸如拼写错误、重复的键和分配给数字服务的端口等问题。

要执行以下练习，您需要在系统上安装 Git 和最新版本的 Python 3。在开始之前，您不会被引导如何执行安装，但在开始之前需要这些项目。

1.  要开始使用`dcvalidator`，请克隆该项目的 GitHub 存储库。如果您还没有这样做，您需要运行以下命令来克隆存储库：

```
git clone https://github.com/serviceprototypinglab/dcvalidator.git
```

1.  命令行应用程序只需要 Python 3 来运行，但是您需要确保首先安装了所有的依赖项，因此请切换到您刚刚克隆的存储库的`dcvalidator`目录：

```
cd dcvalidator
```

1.  安装`dcvalidator`的依赖项很容易，您的系统很可能已经安装了大部分依赖项。要安装依赖项，请在`dcvalidator`目录中使用`pip3 install`命令，并使用`-r`选项来使用服务器目录中的`requirments.txt`文件：

```
pip3 install -r server/requirments.txt
```

1.  从头开始创建一个`docker-compose`文件，该文件将使用本章中已经创建的一些镜像。使用`touch`命令创建一个`docker-compose.yml`文件：

```
touch docker-compose.yml
```

1.  打开您喜欢的文本编辑器来编辑`docker-compose`文件。确保您还包括我们故意添加到文件中的错误，以确保`dcvalidator`能够发现这些错误，并且我们将使用本章前面创建的`docker-stress`镜像。确保您逐字复制此文件，因为我们正在努力确保在我们的`docker-compose.yml`文件中强制出现一些错误：

```
version: '3'
services:
  app:
    container_name: docker-stress-20
    build: .
    environment:
      var: "--cpu 2 --vm 6 --timeout 20"
    ports:
      - 80:8080
      - 80:8080
    dns: 8.8.8
    deploy:
      resources:
        limits:
          cpus: '0.50'
          memory: 50M
  app2:
    container_name: docker-stress-30
    build: .
    environment:
      var: "--cpu 2 --vm 6 --timeout 30"
    dxeploy:
      resources:
        limits:
          cpus: '0.50'
          memory: 50M
```

1.  使用`-f`选项运行`validator-cli.py`脚本来解析我们想要验证的特定文件——在以下命令行中，即`docker-compose.yml`文件。然后，`-fi`选项允许您指定可用于验证我们的`compose`文件的过滤器。在以下代码中，我们正在使用`validator-cli`目前可用的所有过滤器：

```
python3 validator-cli.py -f docker-compose.yml -fi 'Duplicate Keys,Duplicate ports,Typing mistakes,DNS,Duplicate expose'
```

您应该获得以下类似的输出：

```
Warning: no kafka support
loading compose files....
checking consistency...
syntax is ok
= type: docker-compose
- service:app
Duplicate ports in service app port 80
=================== ERROR ===================
Under service: app
The DNS is not appropriate!
=============================================
- service:app2
=================== ERROR ===================
I can not find 'dxeploy' tag under 'app2' service. 
Maybe you can use: 
deploy
=============================================
services: 2
labels:
time: 0.0s
```

正如预期的那样，`validator-cli.py`已经能够找到相当多的错误。它显示您在应用服务中分配了重复的端口，并且您设置的 DNS 也是不正确的。`App2`显示了一些拼写错误，并建议我们可以使用不同的值。

注意

在这一点上，您需要指定您希望您的`docker-compose.yml`文件针对哪些过滤器进行验证，但这将随着即将发布的版本而改变。

1.  您会记得，我们使用了一个`docker-compose`文件来安装 Anchore 镜像扫描程序。当您有`compose`文件的 URL 位置时，使用`-u`选项传递文件的 URL 以进行验证。在这种情况下，它位于 Packt GitHub 账户上：

```
python3 validator-cli.py -u https://github.com/PacktWorkshops/The-Docker-Workshop/blob/master/Chapter11/Exercise11.03/docker-compose.yaml -fi 'Duplicate Keys,Duplicate ports,Typing mistakes,DNS,Duplicate expose'
```

如您在以下代码块中所见，`dcvalidator`没有在`docker-compose.yml`文件中发现任何错误：

```
Warning: no kafka support
discard cache...
loading compose files....
checking consistency...
syntax is ok
= type: docker-compose=
- service:engine-api
- service:engine-catalog
- service:engine-simpleq
- service:engine-policy-engine
- service:engine-analyzer
- service:anchore-db
services: 6
labels:
time: 0.6s
```

如您所见，Docker Compose 验证器相当基本，但它可以发现我们可能错过的`docker-compose.yml`文件中的一些错误。特别是在我们有一个较大的文件时，如果我们在尝试部署环境之前可能错过了一些较小的错误，这可能是可能的。这已经将我们带到了本章的这一部分的结束，我们一直在使用一些自动化流程和应用程序来验证和清理我们的`Dockerfiles`和`docker-compose.yml`文件。

现在，让我们继续进行活动，这将帮助您测试对本章的理解。在接下来的活动中，您将查看 Panoramic Trekking App 上运行的一个服务使用的资源。

## 活动 12.01：查看 Panoramic Trekking App 使用的资源

在本章的前面，我们看了一下我们正在运行的容器在我们的主机系统上消耗了多少资源。在这个活动中，您将选择全景徒步应用程序上运行的服务之一，使用其默认配置运行容器，并查看它使用了什么 CPU 和内存资源。然后，再次运行容器，更改 CPU 和内存配置，以查看这如何影响资源使用情况：

您需要完成此活动的一般步骤如下：

1.  决定在全景徒步应用程序中选择一个您想要测试的服务。

1.  创建一组测试，然后用它们来测量服务的资源使用情况。

1.  启动您的服务，并使用您在上一步中创建的测试来监视资源使用情况。

1.  停止您的服务运行，并再次运行它，这次更改 CPU 和内存配置。

1.  再次使用您在*步骤 2*中创建的测试监视资源使用情况，并比较资源使用情况的变化。

注意

此活动的解决方案可以通过此链接找到。

下一个活动将帮助您在您的`Dockerfiles`上使用`hadolint`来改进最佳实践。

## 活动 12.02：使用 hadolint 改进 Dockerfiles 上的最佳实践

`hadolint`提供了一个很好的方式来强制执行最佳实践，当您创建您的 Docker 镜像时。在这个活动中，您将再次使用`docker-stress`镜像的`Dockerfile`，以查看您是否可以使用`hadolint`的建议来改进`Dockerfile`，使其尽可能地符合最佳实践。

您需要完成此活动的步骤如下：

1.  确保您的系统上有`hadolint`镜像可用并正在运行。

1.  对`docker-stress`镜像的`Dockerfile`运行`hadolint`镜像，并记录结果。

1.  对上一步中的`Dockerfile`进行推荐的更改。

1.  再次测试`Dockerfile`。

完成活动后，您应该获得以下输出：

![图 12.3：活动 12.02 的预期输出](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-ws/img/B15021_12_03.jpg)

图 12.3：活动 12.02 的预期输出

注意

此活动的解决方案可以通过此链接找到。

# 总结

本章我们深入研究了许多理论知识，以及对练习进行了深入的工作。我们从查看我们的运行 Docker 容器如何利用主机系统的 CPU、内存和磁盘资源开始了本章。我们研究了监视这些资源如何被我们的容器消耗，并配置我们的运行容器以减少使用的资源数量。

然后，我们研究了 Docker 的最佳实践，涉及了许多不同的主题，包括利用基础镜像、安装程序和清理、为可扩展性开发底层应用程序，以及配置应用程序和镜像。然后，我们介绍了一些工具，帮助您执行这些最佳实践，包括`hadolint`和`FROM:latest`，帮助您对`Dockerfiles`进行代码检查，以及`dcvalidator`来检查您的`docker-compose.yml`文件。

下一章将进一步提升我们的监控技能，介绍使用 Prometheus 来监控我们的容器指标和资源。
