# 深入理解 Docker（五）

> 原文：[`zh.annas-archive.org/md5/8474E71CF7E3D29A70BB0D1BE42B1C22`](https://zh.annas-archive.org/md5/8474E71CF7E3D29A70BB0D1BE42B1C22)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

## 附录 A：保护客户端和守护程序通信

这最初是要成为“安装 Docker”章节或“Docker 安全性”章节的一部分。但它变得太长了，所以我把它添加到这里作为附录。

Docker 实现了客户端-服务器模型。客户端实现了 CLI，服务器（守护程序）实现了功能，包括面向公众的 REST API。

客户端称为`docker`（在 Windows 上为`docker.exe`），守护程序称为`dockerd`（在 Windows 上为`dockerd.exe`）。默认安装将它们放在同一主机上，并配置它们通过安全的本地 PIC 套接字进行通信：

+   在 Linux 上为`/var/run/docker.sock`

+   在 Windows 上为`//./pipe/docker_engine`

但是，也可以配置它们通过网络进行通信。但默认的守护程序网络配置使用了在 2375/tcp 端口上的未加密 HTTP 套接字。

![图 A1.1](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-dpdv/img/figurea1-1.png)

图 A1.1

> **注意：**惯例是在客户端和守护程序之间使用`2375`进行未加密通信，使用`2376`进行加密流量。

这对实验室可能没问题，但对于生产环境是不可接受的。

TLS 来拯救！

Docker 允许您配置客户端和守护程序只接受通过 TLS 保护的网络连接。即使在使用受信任的内部网络时，这在生产环境中也是推荐的！

Docker 提供了两种模式来保护客户端和守护程序之间的 TLS 通信：

+   **守护程序模式：** Docker 守护程序只接受来自经过身份验证的客户端的连接。

+   **客户端模式：** Docker 客户端只会连接由受信任 CA 签名的 Docker 守护程序。

两者的结合提供了最高的安全性。

我们将使用一个简单的实验室环境来演示配置 Docker 的**守护程序模式**和**客户端模式**的过程。

### 实验室设置

在本章的其余部分，我们将使用一个简单的实验室设置。这是一个具有 CA、Docker 客户端和 Docker 守护程序的三节点 Linux 实验室。所有主机都必须能够通过名称解析彼此。

我们将配置`node1`作为安全的 Docker 客户端，`node3`作为安全的 Docker 守护程序。`node2`将作为 CA。

您可以在自己的环境中跟随操作，但所有示例都将使用图 A1.2 中实验室图表中的名称和 IP。

![图 A1.2 示例实验室设置](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-dpdv/img/figurea1-2.png)

图 A1.2 示例实验室设置

高级流程将如下：

1.  **配置 CA 和证书**

1.  创建 CA（自签名证书）

1.  为守护程序创建并签署密钥

1.  为客户端创建并签署密钥

1.  分发密钥

1.  **配置 Docker 使用 TLS**

1.  配置守护程序模式

1.  配置客户端模式

### 创建 CA（自签名证书）

只有在您在实验室中跟随并需要构建 CA 来签署证书时，您才需要完成此步骤。此外，我们正在构建一个简单的 CA 来帮助演示如何配置 Docker，我们**不**试图构建一个生产级 PKI。

在实验室中从`CA`节点运行以下命令。

1.  为 CA 创建一个新的私钥。

您将在操作中设置一个密码。不要忘记它！

```
 $ openssl genrsa -aes256 -out ca-key.pem 4096

 Generating RSA private key, 4096 bit long modulus
 ...............................................++
 ..++
 e is 65537 (0x10001)
 Enter pass phrase for ca-key.pem:
 Verifying - Enter pass phrase for ca-key.pem: 
```

您现在在当前目录中有一个名为`ca-key.pem`的新文件。这是 CA 的私钥。

*使用 CA 的私钥生成公钥（证书）。

您需要输入上一步的密码。希望您还没有忘记它:-D

```
 $ openssl req -new -x509 -days 730 -key ca-key.pem -sha256 -out ca.pem 
```

这已经在您的工作目录中添加了第二个文件，名为`ca.pem`。这是 CA 的公钥，也称为“证书”。

您现在在当前目录中有两个文件：`ca-key.pem`和`ca.pem`。这些是 CA 的私钥和公钥，并形成了 CA 的*身份*。

#### 为守护程序创建密钥对

在这一步中，我们将为`node3`生成一个新的密钥对。这是将运行安全 Docker 守护程序的节点。这是一个四步过程：

1.  创建私钥

1.  创建签名请求

1.  添加 IP 地址并使其有效用于*服务器授权*

1.  生成证书

让我们开始吧。

从 CA 节点（node2）运行所有命令。

1.  为守护程序创建私钥。

```
 $ openssl genrsa -out daemon-key.pem 4096
 <Snip> 
```

这已在您的工作目录中创建了一个名为`daemon-key.pem`的新文件。这是守护节点的私钥。

*为 CA 创建证书签名请求（CSR），以创建并签署守护程序的证书。确保使用您打算在其上运行安全 Docker 守护程序的节点的正确 DNS 名称。示例使用`node3`。

```
 $ openssl req -subj "/CN=node3" \
   -sha256 -new -key daemon-key.pem -out daemon.csr 
```

您现在在工作目录中有第四个文件。这个文件是 CSR，名为`daemon.csr`。*向证书添加所需属性。

我们需要创建一个文件，当它被 CA 签名时，将向守护程序的证书添加一些扩展属性。这些属性将添加守护程序的 DNS 名称和 IP 地址，并配置证书用于*服务器认证*。

创建一个名为`extfile.cnf`的新文件，并填入以下值。示例中使用了实验室中守护节点的 DNS 名称和 IP。您的环境中的值可能不同。

```
 subjectAltName = DNS:node3,IP:10.0.0.12
 extendedKeyUsage = serverAuth 
```

*生成证书。

此步骤使用 CSR 文件、CA 密钥和`extfile.cnf`文件来签署和配置守护程序的证书。它将输出守护程序的公钥（证书）作为一个名为`daemon-cert.pem`的新文件。

此时，您已经拥有一个可用的 CA，以及将运行安全 Docker 守护程序的`node3`的密钥对。

在继续之前，删除 CSR 和`extfile.cnf`。

```
$ rm daemon.csr extfile.cnf 
```

#### 为客户端创建密钥对

在这一部分，我们将重复刚才为`node3`所做的操作，但这次我们将为将运行我们的 Docker 客户端的`node1`做同样的操作。

从 CA（`node2`）运行所有命令。

1.  为`node1`创建一个私钥。

这将在您的工作目录中生成一个名为`client-key.pem`的新文件。

```
 $ openssl genrsa -out client-key.pem 4096 
```

*创建一个 CSR。确保使用将成为您安全 Docker 客户端的节点的正确 DNS 名称。示例中使用了`node1`。

```
 $ openssl req -subj '/CN=node1' -new -key client-key.pem -out client.csr 
```

这将在当前目录中创建一个名为`client.csr`的新文件。*创建一个名为`extfile.cnf`的文件，并填入以下值。这将使证书对客户端身份验证有效。

```
 extendedKeyUsage = clientAuth 
```

*使用 CSR、CA 的公钥和私钥以及`extfile.cnf`文件为`node1`创建证书。这将在当前目录中创建一个名为`client-cert.pem`的新文件，其中包含客户端的签名公钥。

删除 CSR 和`extfile.cnf`文件，因为它们不再需要。

```
$ rm client.csr extfile.cnf 
```

此时，您的工作目录中应该有以下 7 个文件：

```
ca-key.pem          << CA private key
ca.pem              << CA public key (cert)
ca.srl              << Tracks serial numbers
client-cert.pem     << client public key (Cert)
client-key.pem      << client private key
daemon-cert.pem     << daemon public key (cert)
daemon-key.pem      << daemon private key 
```

在继续之前，您应该从密钥中删除写权限，并将它们设置为只有您和其他属于您组的账户可以读取。

```
$ chmod `0400` ca-key.pem client-key.pem daemon-key.pem 
```

#### 分发密钥

现在您已经拥有所有的密钥和证书，是时候将它们分发给客户端和守护节点了。我们将复制以下文件：

+   将 CA 的`ca.pem`、`daemon-cert.pem`和`daemon-key.pem`复制到`node3`（守护节点）。

+   将 CA 的`ca.pem`、`client-cert.pem`和`client-key.pem`复制到`node1`（客户端节点）。

我们将向您展示如何使用`scp`进行操作，但请随意使用其他工具。

从包含`node2`（CA 节点）上的密钥的目录中运行以下命令。

```
// Daemon files
$ scp ./ca.pem ubuntu@daemon:/home/ubuntu/.docker/ca.pem
$ scp ./daemon-cert.pem ubuntu@daemon:/home/ubuntu/.docker/cert.pem
$ scp ./daemon-key.pem ubuntu@daemon:/home/ubuntu/.docker/key.pem

//Client files
$ scp ./ca.pem ubuntu@client:/home/ubuntu/.docker/ca.pem
$ scp ./client-cert.pem ubuntu@client:/home/ubuntu/.docker/cert.pem
$ scp ./client-key.pem ubuntu@client:/home/ubuntu/.docker/key.pem 
```

关于这些命令有几点需要注意：

1.  第 2、3、5 和 6 个命令是作为复制操作的一部分重命名文件。这很重要，因为 Docker 希望文件具有这些名称。

1.  这些命令适用于 Ubuntu Linux，并且假定您正在使用`ubuntu`用户帐户。

1.  在执行命令之前，您可能需要在守护程序和客户端节点上预先创建`/home/ubuntu/.docker`隐藏目录。您可能还需要更改`.docker`目录的权限以启用复制——`chmod 777 .docker`将起作用，但不安全。**记住，我们正在构建一个快速的 CA 和证书，以便您可以跟着做。我们并不打算构建一个安全的 PKI**。

1.  如果您在类似 AWS 的环境中工作，您需要为每个复制命令使用`-i <key>`标志指定实例的私钥。例如：

实验现在看起来像 A1.3 图

![图 A1.3 更新的实验与密钥](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-dpdv/img/figurea1-3.png)

图 A1.3 更新的实验与密钥

在`node1`和`node3`上存在 CA 的公钥（`ca.pem`）将告诉它们信任 CA 和由其签署的所有证书。

有了证书，**最终可以配置 Docker，以便客户端和守护程序使用 TLS！**

### 为 TLS 配置 Docker

正如我们之前提到的，Docker 有两种 TLS 模式：

+   **守护模式**

+   **客户端模式**

守护模式告诉守护进程只允许来自具有有效证书的客户端的连接。客户端模式告诉客户端只连接到具有有效证书的守护进程。

我们将为`node1`上的守护进程配置*守护模式*，并进行测试。之后，我们将为`node2`上的客户端进程配置*客户端模式*，并进行测试。

#### 为 TLS 配置 Docker 守护程序

通过在`daemon.json`配置文件中设置一些守护标志来保护守护程序就可以了。

+   `tlsverify`启用 TLS 验证

+   `tlscacert`告诉守护程序信任哪个 CA

+   `tlscert`告诉 Docker 守护程序的证书在哪里

+   `tlskey`告诉 Docker 守护程序的私钥在哪里

+   `hosts`告诉 Docker 在哪些套接字上绑定守护程序

我们将在平台无关的`daemon.json`配置文件中配置这些。在 Linux 上，它位于`/etc/docker/`，在 Windows 上位于`C:\ProgramData\Docker\config\`。

在将运行安全 Docker 守护程序的节点（例如实验中的`node3`）上执行所有以下操作。

编辑`daemon.json`文件并添加以下行。

```
{
    "hosts": ["tcp://node3:2376"],
    "tls": true,
    "tlsverify": true,
    "tlscacert": "/home/ubuntu/.docker/ca.pem",
    "tlscert": "/home/ubuntu/.docker/cert.pem",
    "tlskey": "/home/ubuntu/.docker/key.pem"
} 
```

**警告！**运行`systemd`的 Linux 系统不允许您在`daemon.json`中使用“hosts”选项。相反，您必须在 systemd 覆盖文件中指定它。最简单的方法是使用`sudo systemctl edit docker`命令。这将在编辑器中打开一个名为`/etc/systemd/system/docker.service.d/override.conf`的新文件。添加以下三行并保存文件。

```
`[Service]`
`ExecStart``=`
`ExecStart``=``/usr/bin/dockerd -H tcp://node3:2376` 
```

现在 TLS 和主机选项已设置，是时候重新启动 Docker 了。

一旦 Docker 重新启动，您可以通过检查`ps`命令的输出来验证新的`hosts`值是否生效。

```
$ ps -elf `|` grep dockerd
`4` S root  ... /usr/bin/dockerd -H tcp://node3:2376 
```

命令输出中的“`-H tcp://node3:2376`”的存在证明了守护程序正在监听网络。端口`2376`是使用 TLS 的 Docker 的标准端口。`2375`是默认的不安全端口。

如果运行普通命令，例如`docker version`，它将无法工作。这是因为我们刚刚配置了**守护程序**在网络上监听，但**Docker 客户端**仍然尝试使用本地 IPC 套接字。再次尝试命令，但这次指定`-H tcp://node3:2376`标志。

```
$ docker -H tcp://node3:2376 version
Client:
 Version:       `18`.01.0-ce
 API version:   `1`.35
 <Snip>
Get http://daemon:2376/v1.35/version: net/http: HTTP/1.x transport connectio`\`
n broken: malformed HTTP response `"\x15\x03\x01\x00\x02\x02"`.
* Are you trying to connect to a TLS-enabled daemon without TLS? 
```

命令看起来更好了，但仍然无法工作。这是因为守护程序正在拒绝来自未经身份验证的客户端的所有连接。

恭喜。 Docker 守护程序已配置为在网络上监听，并拒绝来自未经身份验证的客户端的连接。

让我们在`node1`上配置 Docker 客户端以使用 TLS。

#### 为 TLS 配置 Docker 客户端

在本节中，我们将在`node1`上为 Docker 客户端配置两件事：

+   连接到网络上的远程守护程序

+   对所有`docker`命令进行签名

从将运行您的安全 Docker 客户端的节点（例如实验中的`node1`）执行以下所有操作。

导出以下环境变量以配置客户端通过网络连接到远程守护程序。

```
export DOCKER_HOST=tcp://node3:2376 
```

尝试以下命令。

```
$ docker version
Client:
 Version:       `18`.01.0-ce
<Snip>
Get http://daemon:2376/v1.35/version: net/http: HTTP/1.x transport connectio`\`
n broken: malformed HTTP response `"\x15\x03\x01\x00\x02\x02"`.
* Are you trying to connect to a TLS-enabled daemon without TLS? 
```

Docker 客户端现在正在通过网络向远程守护程序发送命令，但远程守护程序将仅接受经过身份验证的连接。

导出另一个环境变量，告诉 Docker 客户端使用其证书对所有命令进行签名。

```
export DOCKER_TLS_VERIFY=1 
```

再次运行`docker version`命令。

```
$ docker version
Client:
 Version:       `18`.01.0-ce
<Snip>
Server:
 Engine:
  Version:      `18`.01.0-ce
  API version:  `1`.35 `(`minimum version `1`.12`)`
  Go version:   go1.9.2
  Git commit:   03596f5
  Built:        Wed Jan `10` `20`:09:37 `2018`
  OS/Arch:      linux/amd64
  Experimental: `false` 
```

恭喜。客户端已成功通过安全连接与远程守护程序通信。实验的最终配置如图 A1.4 所示。

![图 A1.4](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-dpdv/img/figurea1-4.png)

图 A1.4

在我们进行快速回顾之前，还有几点要注意。

1.  这个最后的例子有效是因为我们将客户端的 TLS 密钥复制到了 Docker 期望它们在的文件夹中。这是一个隐藏文件夹，位于用户的主目录中，名为`.docker`。我们还给了密钥默认的文件名，Docker 期望的是(`ca.pem`, `cert.pem`, and `key.pem`)。您可以通过导出`DOCKER_CERT_PATH`来指定不同的文件夹。

1.  您可能希望将环境变量（`DOCKER_HOST`和`DOCKER_TLS_VERIFY`）变成您环境中更加永久的设置。

### Docker TLS 总结

Docker 支持两种 TLS 模式：

+   `守护进程模式`

+   `客户端模式`

守护进程模式将拒绝来自未使用有效证书签署命令的客户端的连接。客户端模式将不会连接到没有有效证书的远程守护进程。

通过 Docker 守护进程配置文件来配置 TLS。该文件名为`daemon.json`，它是平台无关的。

以下的`daemon.json`应该适用于大多数系统：

```
{
    "hosts": ["tcp://node3:2376"],
    "tls": true,
    "tlsverify": true,
    "tlscacert": "/home/ubuntu/.docker/ca.pem",
    "tlscert": "/home/ubuntu/.docker/cert.pem",
    "tlskey": "/home/ubuntu/.docker/key.pem"
} 
```

`*   `hosts`告诉 Docker 在哪个套接字上绑定守护进程。该示例将其绑定到端口`2376`上的网络套接字。您可以使用任何空闲端口，但惯例是在安全的 Docker 连接中使用`2376`。运行`systemd`的 Linux 系统无法使用此标志，需要使用`systemd`覆盖文件。

+   `tls`和`tlsverify`强制守护进程只使用加密和认证的连接。

+   `tlscacert`告诉 Docker 信任哪个 CA。这会导致 Docker 信任该 CA 签发的所有证书。

+   `tlscert`告诉 Docker 守护进程的证书位于哪里。

+   `tlskey`告诉 Docker 守护进程的私钥位于哪里。

对这些值进行任何更改都需要重新启动 Docker 才能生效。

为 TLS 配置**Docker 客户端**就是设置两个环境变量：

+   `DOCKER_HOST`

+   `DOCKER_TLS_VERIFY`

`DOCKER_HOST`告诉客户端在哪里找到守护进程。`export DOCKER_HOST=tcp://node3:2376`将告诉 Docker 客户端连接到远程主机`node3`上的端口`2376`上的守护进程。

`export DOCKER_TLS_VERIFY=1`将告诉 Docker 客户端签署其发出的所有命令。```````````````````````


## 附录 B：DCA 考试

这个附录将随着时间的推移而更新，提供参加 DCA 考试的技巧和建议。

我还开设了一个新的网站和 LinkedIn 小组，供您分享考试经验和技巧。

+   该网站是 www.dockercerts.com，目前正在开发中

+   [LinkedIn 小组](https://www.linkedin.com/groups/13578221)名为**Docker 认证协会（DCA）**

### 其他帮助考试的资源

在撰写本文时，**这是唯一涵盖所有 DCA 考试目标的资源**。

我还有一个[优秀的视频培训课程](https://app.pluralsight.com/library/courses/docker-deep-dive-update/table-of-contents)，涵盖了大部分考试目标，是帮助您记住本书所学内容的好方法。

视频课程节奏快，有趣，并且评价很高！

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-dpdv/img/figureab-1.png)

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-dpdv/img/figureab-2.png)

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-dpdv/img/figureab-3.png)

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-dpdv/img/figureab-4.png)

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-dpdv/img/figureab-5.png)

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-dpdv/img/figureab-6.png)

如果您对花钱购买视频课程感到不确定，让我说两件事：

1.  如果它能帮助您通过 DCA 考试，那就是值得的！

1.  Pluralsight 总是有免费试用。注册试用并看看您是否喜欢它 — 我认为您会喜欢的！

### 将考试目标映射到章节

以下是考试目标列表以及它们所涵盖的章节。几乎所有目标都将在比这里显示的更多的章节中涵盖，但这些是它们在最详细涵盖的主要章节。

### 领域 1：编排（占考试的 25%）

+   完成 swarm 模式集群的设置，包括管理节点和工作节点：**第十章**

+   说明运行容器与运行服务之间的差异：**第十章和第十四章**

+   演示锁定 swarm 集群的步骤：**第十章**

+   将单个容器的运行指令扩展到在 swarm 下运行服务：**第十章和第十四章**

+   解释“docker inspect”命令的输出：**多个章节**

+   使用 YAML 组合文件将应用程序部署转换为堆栈文件，并使用 docker stack deploy：**第十四章**

+   增加副本数量：**第十章和第十四章**

+   添加网络，发布端口：**第 9、11、12 和 14 章**

+   挂载卷：**第九章和第十三章**

+   说明复制与全局服务的运行：**第十章**

+   识别部署失败的服务所需的故障排除步骤：**第十四章**

+   应用节点标签以演示任务的放置：**第十四章**

+   草绘 Docker 化应用程序与传统系统通信的方式：**第十一章**

+   解释 swarm 集群中仲裁的重要性：**第十章和第十六章**

+   演示使用“docker service create”模板的用法：**第十章**

### 领域 2：图像创建、管理和注册表（考试的 20%）

+   描述 Dockerfile 选项[add、copy、volumes、expose、entrypoint 等]：**第八章和第九章**

+   展示 Dockerfile 的主要部分：**第八章和第九章**

+   举例说明如何通过 Dockerfile 创建高效的图像：**第八章**

+   使用 CLI 命令如 list、delete、prune、rmi 等来管理图像：**第六章**

+   检查图像并使用过滤器和格式报告特定属性：**第六章**

+   演示给图像打标签的能力：**第六章和第十七章**

+   利用注册表存储图像：**第十七章**

+   显示 Docker 图像的层：**第六章**

+   应用文件创建 Docker 图像：**第八章**

+   将图像修改为单层：**第八章**

+   描述图像层的工作原理：**第八章**

+   部署注册表（非架构）：**第十六章**

+   配置注册表：**第十六章和第十七章**

+   登录到注册表：**第六章和第十七章**

+   利用注册表中的搜索功能：**第六章**

+   给图像打标签：**第六章和第十七章**

+   将图像推送到注册表：**第八章和第十七章**

+   在注册表中签署图像：**第十七章**

+   从注册表中拉取图像：**第六章**

+   描述图像删除的工作原理：**第六章和第十七章**

+   从注册表中删除图像：**第十七章**

### 领域 3：安装和配置（考试的 15%）

+   演示升级 Docker 引擎的能力：**第三章**

+   完成对仓库的设置，选择存储驱动程序，并在多个平台上完成 Docker 引擎的安装：**第三章**

+   设置 swarm，配置管理器，添加节点，并设置备份计划：**第十章和第十六章**

+   创建和管理用户和团队：**第十六章和第十七章**

+   概述安装前的大小要求：**第十六章**

+   了解命名空间、cgroups 和证书配置：**第五章、第十五章、第十六章和附录 A**

+   使用基于证书的客户端-服务器身份验证来确保 Docker 守护程序有权访问注册表上的图像：**第十七章**

+   持续重复部署 Docker 引擎、UCP 和 DTR 在 AWS 和本地的高可用配置的步骤：**第十六章和第十七章**

+   完成对 UCP 和 DTR 的备份配置：**第十六章**

+   配置 Docker 守护程序在启动时启动：**第三章**

### 领域 4：网络（考试的 15%）

+   为开发人员创建一个 Docker 桥接网络供其容器使用：**第十一章**

+   排除容器和引擎日志以了解容器之间的连接问题：**第十一章**

+   发布一个端口，以便应用程序可以在外部访问：**第 7、9、10、11、14 和 17 章**

+   确定容器在外部可访问的 IP 和端口：**第 7、9、11 和 17 章**

+   描述内置网络驱动程序的不同类型和用例：**第十一章**

+   了解容器网络模型以及它如何与 Docker 引擎和网络和 IPAM 驱动程序进行交互：**第十一章**

+   配置 Docker 使用外部 DNS：**第十一章**

+   使用 Docker 进行 HTTP/HTTPs 流量负载均衡到一个应用程序（使用 Docker EE 配置 L7 负载均衡）：**第十七章**

+   了解并描述在 Docker 引擎、注册表和 UCP 控制器之间流动的流量类型：**第 6、17 章和附录 A**

+   在 Docker 叠加网络上部署服务：**第 10、12 和 14 章**

+   描述“主机”和“入口”端口发布模式之间的区别：**第 11 和 14 章**

### 领域 5：安全（考试的 15%）

+   描述签署图像的过程：**第 6、15 和 17 章**

+   演示图像通过安全扫描：**第 15 和 17 章**

+   启用 Docker 内容信任：**第 15 和 17 章**

+   在 UCP 中配置 RBAC：**第十七章**

+   将 UCP 与 LDAP/AD 集成：**第十七章**

+   演示创建 UCP 客户端捆绑包：**第 16 和 17 章**

+   演示创建 UCP 客户端捆绑包：**第十五章**

+   描述集群默认安全性：**第 10 和 15 章**

+   描述 MTLS：**第 15 和 17 章**

+   身份角色：**第十七章**

+   描述 UCP 工作者和管理者之间的区别：**第 16 和 17 章**

+   描述使用外部证书与 UCP 和 DTR 的过程：**第 16 和 17 章**

### 领域 6：存储和卷（考试的 10%）

+   说明应在哪个操作系统上使用哪个图形驱动程序：**第 3 和 13 章**

+   演示如何配置 devicemapper：**第三章**

+   比较对象存储和块存储，并解释在可用时哪种更可取：**第十三章**

+   总结应用程序由哪些层组成以及这些层位于文件系统上的位置：**第 6 和 13 章**

+   描述卷在 Docker 中用于持久存储的使用方式：**第 13 和 14 章**

+   识别您将采取的步骤来清理文件系统上未使用的镜像，也在 DTR 上：**第 13 和 17 章**

+   演示存储如何在集群节点之间使用：**第十三章和第十七章**


## 附录 C：接下来做什么

希望你对 Docker 感到自信，并准备好参加 DCA 考试！

幸运的是，将你的容器之旅迈向下一步从未如此简单！

### 练习

现在搭建基础架构和工作负载变得更加容易了。Docker for Mac 和 Docker for Windows 让你可以在笔记本电脑上轻松玩耍和开发 Docker。[Play with Docker](https://play-with-docker.com/)是一个免费的在线游乐场，你可以在那里练习 Docker，直到成为世界权威！

### 视频培训

我在[Pluralsight](http://app.pluralsight.com/author/nigel-poulton)上创建了大量备受好评的视频培训课程。如果你还不是 Pluralsight 的会员，那就加入吧！是的，这需要花钱，但是非常值得！如果你不确定的话……他们总是有免费试用，你可以在有限的时间内免费访问我的课程。

### 认证

现在有一个官方的方式来证明你的 Docker 专业知识！我做了，我也建议你这样做。

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-dpdv/img/figureac-1.png)

### 社区活动

我强烈建议你参加[Dockercon](https://www.dockercon.com)等活动以及你当地的[Docker 聚会](https://www.docker.com/community/meetup-groups)。如果你在那里看到我，请务必过来打个招呼！

### 反馈

非常感谢阅读我的书。我真的希望它对你有所帮助！

现在让我提一个请求…

写一本书需要非常多的努力！我写这本书的希望是能激励你，为你打开新的机会。如果你喜欢这本书，在亚马逊上给它一些爱，打几颗星并写一篇评论！

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-dpdv/img/figureac-2.png)

引用威廉·莎士比亚的话：“*不表达爱意的人，是不会被爱的*”。所以，如果你喜欢这本书，就用一些星星来表达吧！

也可以随时在[Twitter](https://twitter.com/nigelpoulton)上找我，但星星和汽车是我的梦想 :-D

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-dpdv/img/figureac-3.png)

![](https://github.com/OpenDocCN/freelearn-devops-zh/raw/master/docs/dkr-dpdv/img/figureac-4.png)
